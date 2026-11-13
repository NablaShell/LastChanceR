// src/network/listener.rs
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, SigningKey};
use reqwest::header::CONTENT_TYPE;
use reqwest::Client;
use std::time::Duration;
use crate::network::Config;

/// Один из допустимых размеров пакета (см. API.md §4.1).
const ALLOWED_PACKET_SIZES: [usize; 4] = [256, 1024, 4096, 65536];

pub struct Listener {
    client: Client,
    config: Config,
}

impl Listener {
    pub fn new(config: &Config) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_default();

        Self {
            client,
            config: config.clone(),
        }
    }

    pub async fn pull_messages_with_auth(
        &self,
        identity_hash: &str,
        pub_key_hex: &str,          // hex(ed25519_public_key) — НЕ хеш!
        signing_key: &SigningKey,
    ) -> Result<Vec<Vec<u8>>> {
        let now = chrono::Utc::now().timestamp().to_string();
        // message = timestamp + target_hash (без разделителя, API.md §4.2)
        let message = format!("{}{}", now, identity_hash);
        let signature = signing_key.sign(message.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());

        let url = format!("{}/pull/{}", self.config.server_url, identity_hash);

        let response = self.client
            .get(&url)
            .header("X-Identity-Key", pub_key_hex)
            .header("X-Timestamp", &now)
            .header("X-Signature", &sig_hex)
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Accept", "multipart/form-data")
            .header("User-Agent", "Mozilla/5.0 (X11; Arch Linux; rv:130.0) Gecko/20100101 Firefox/130.0")
            .header(&self.config.mask_header_name, &self.config.mask_header_value)
            .send()
            .await
            .map_err(|e| anyhow!("pull request failed: {}", e))?;

        let status = response.status();

        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(Vec::new());
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(anyhow!("rate limited (429)"));
        }

        if status == reqwest::StatusCode::UNAUTHORIZED {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("unauthorized (401): {}", body));
        }

        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("server returned {}: {}", status, body));
        }

        // Content-Type должен быть multipart/form-data; boundary=...
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        let bytes = response
            .bytes()
            .await
            .map_err(|e| anyhow!("read body: {}", e))?;

        if !content_type.starts_with("multipart/") {
            // API.md гарантирует multipart на 200, но если сервер вернул
            // что-то иное — не молча делаем вид, что это один пакет.
            return Err(anyhow!(
                "unexpected Content-Type on /pull: {:?}",
                content_type
            ));
        }

        let messages = parse_multipart(&content_type, &bytes)?;

        // Валидация размеров (API.md §4.1: ровно 256/1024/4096/65536)
        for m in &messages {
            if !ALLOWED_PACKET_SIZES.contains(&m.len()) {
                log::warn!(
                    "[LISTENER] packet size {} is not in allowed grid {:?}",
                    m.len(),
                    ALLOWED_PACKET_SIZES
                );
            }
        }

        Ok(messages)
    }

    pub async fn download_file(&self, file_hash: &str) -> Result<Vec<u8>> {
        if file_hash.is_empty() {
            return Err(anyhow!("empty file_hash"));
        }

        let url = format!("{}/download/{}", self.config.file_server_url, file_hash);

        let response = self.client
            .get(&url)
            .header("X-Requested-With", "XMLHttpRequest")
            .header("User-Agent", "Mozilla/5.0 (X11; Arch Linux; rv:130.0) Gecko/20100101 Firefox/130.0")
            .header(&self.config.mask_header_name, &self.config.mask_header_value)
            .send()
            .await
            .map_err(|e| anyhow!("download request failed: {}", e))?;

        match response.status().as_u16() {
            200 => {
                let data = response
                    .bytes()
                    .await
                    .map_err(|e| anyhow!("read file data: {}", e))?;
                Ok(data.to_vec())
            }
            404 => Err(anyhow!(
                "file not found (already downloaded or expired)"
            )),
            400 => Err(anyhow!("bad request (missing file hash)")),
            429 => Err(anyhow!("rate limited (429)")),
            code => {
                let body = response.text().await.unwrap_or_default();
                Err(anyhow!("download failed: {} - {}", code, body))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Multipart parsing
// ---------------------------------------------------------------------------

/// Извлекает `boundary` из `Content-Type: multipart/form-data; boundary=...`.
fn extract_boundary(content_type: &str) -> Result<Vec<u8>> {
    // boundary может быть в кавычках: boundary="abc"
    for part in content_type.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("boundary=") {
            let b = rest.trim().trim_matches('"');
            if b.is_empty() {
                return Err(anyhow!("empty multipart boundary"));
            }
            return Ok(b.as_bytes().to_vec());
        }
    }
    Err(anyhow!("no boundary in Content-Type: {:?}", content_type))
}

/// Разбирает multipart-тело ответа `/pull`.
///
/// Формат (RFC 7578):
///   --boundary\r\n
///   headers...\r\n
///   \r\n
///   <payload>\r\n
///   --boundary\r\n
///   ...
///   --boundary--\r\n
fn parse_multipart(content_type: &str, body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let boundary = extract_boundary(content_type)?;

    // Разделители: "\r\n--boundary" — между частями,
    //             "--boundary"     — в начале тела.
    let mut delimiter = Vec::with_capacity(boundary.len() + 4);
    delimiter.extend_from_slice(b"\r\n--");
    delimiter.extend_from_slice(&boundary);

    // В начале тела delimiter идёт без ведущего \r\n.
    let mut leading = Vec::with_capacity(boundary.len() + 2);
    leading.extend_from_slice(b"--");
    leading.extend_from_slice(&boundary);

    let mut messages = Vec::new();
    let mut pos;

    // Первый boundary
    if body.starts_with(&leading) {
        pos = leading.len();
    } else if let Some(idx) = find_subsequence(body, &delimiter) {
        pos = idx + delimiter.len();
    } else {
        return Err(anyhow!("multipart body has no boundary"));
    }

    loop {
        // После boundary: либо "--" (конец), либо "\r\n" (заголовки части)
        if body.get(pos..pos + 2) == Some(b"--") {
            break;
        }
        if body.get(pos..pos + 2) != Some(b"\r\n") {
            return Err(anyhow!("malformed multipart: expected CRLF after boundary"));
        }
        pos += 2;

        // Ищем конец заголовков части (пустая строка)
        let headers_end = find_subsequence(&body[pos..], b"\r\n\r\n")
            .ok_or_else(|| anyhow!("multipart part has no header terminator"))?;
        let payload_start = pos + headers_end + 4;

        // Ищем следующий delimiter
        let next = find_subsequence(&body[payload_start..], &delimiter)
            .ok_or_else(|| anyhow!("multipart body ended without closing boundary"))?;

        let payload_end = payload_start + next;
        if payload_end > payload_start {
            messages.push(body[payload_start..payload_end].to_vec());
        }

        pos = payload_end + delimiter.len();
    }

    Ok(messages)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_parts() {
        let body = b"--XyZ\r\nContent-Type: application/octet-stream\r\n\r\nPART1\r\n--XyZ\r\nContent-Type: application/octet-stream\r\n\r\nPART2\r\n--XyZ--\r\n";
        let ct = "multipart/form-data; boundary=XyZ";
        let parts = parse_multipart(ct, body).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], b"PART1");
        assert_eq!(parts[1], b"PART2");
    }

    #[test]
    fn parses_empty_multipart() {
        let body = b"--XyZ--\r\n";
        let ct = "multipart/form-data; boundary=XyZ";
        let parts = parse_multipart(ct, body).unwrap();
        assert!(parts.is_empty());
    }

    #[test]
    fn quoted_boundary() {
        let body = b"--abc\r\n\r\nX\r\n--abc--\r\n";
        let ct = r#"multipart/form-data; boundary="abc""#;
        let parts = parse_multipart(ct, body).unwrap();
        assert_eq!(parts, vec![b"X".to_vec()]);
    }
}
