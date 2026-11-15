// src/network/sender.rs
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::sync::RwLock;
use std::time::Duration;
use crate::network::{build_http_client, Config};
use crate::types::{truncate_display, FileHash};

const MAX_UPLOAD_SIZE: usize = crate::crypto::FILE_MAX_ENVELOPE;
// Один клиент на всё; таймаут 120s покрывает upload до 128 MiB.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Sender {
    client: RwLock<Client>,
    config: RwLock<Config>,
}

impl Sender {
    pub fn new(config: &Config) -> Result<Self> {
        let client = build_http_client(CLIENT_TIMEOUT, config.proxy_url.as_deref())?;

        Ok(Self {
            client: RwLock::new(client),
            config: RwLock::new(config.clone()),
        })
    }

    /// Применяет новые сетевые параметры и пересобирает клиент под новый прокси.
    pub fn update_config(&self, config: &Config) -> Result<()> {
        let client = build_http_client(CLIENT_TIMEOUT, config.proxy_url.as_deref())?;

        let mut config_guard = self
            .config
            .write()
            .map_err(|_| anyhow!("конфигурация отправителя недоступна: блокировка повреждена"))?;
        let mut client_guard = self
            .client
            .write()
            .map_err(|_| anyhow!("HTTP-клиент отправителя недоступен: блокировка повреждена"))?;

        *config_guard = config.clone();
        *client_guard = client;
        Ok(())
    }

    fn current_config(&self) -> Result<Config> {
        self.config
            .read()
            .map(|config| config.clone())
            .map_err(|_| anyhow!("конфигурация отправителя недоступна: блокировка повреждена"))
    }

    fn current_client(&self) -> Result<Client> {
        self.client
            .read()
            .map(|client| client.clone())
            .map_err(|_| anyhow!("HTTP-клиент отправителя недоступен: блокировка повреждена"))
    }

    pub async fn send_message(&self, target_hash: &str, packet: &[u8]) -> Result<()> {
        if !crate::crypto::ratchet::is_valid_packet_len(packet.len()) {
            return Err(anyhow!(
                "invalid packet size {} (expected a v3 bucket with randomized padding)",
                packet.len()
            ));
        }

        let config = self.current_config()?;
        let client = self.current_client()?;
        let url = format!("{}/push/{}", config.server_url, target_hash);

        let max_retries = 3;
        let base_delay = Duration::from_secs(1);
        let mut last_err: Option<String> = None;

        for attempt in 0..=max_retries {
            let result = client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", packet.len().to_string())
                .header("X-Requested-With", "XMLHttpRequest")
                .header("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0")
                .header(&config.mask_header_name, &config.mask_header_value)
                // bytes::Bytes — без лишней копии Vec
                .body(bytes::Bytes::copy_from_slice(packet))
                .send()
                .await;

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(());
                    }
                    if status.as_u16() == 429 {
                        // rate limit — единственный статус, на который ретраим по API.md
                        let body = resp.text().await.unwrap_or_default();
                        last_err = Some(format!("rate limited: {}", body));
                        if attempt < max_retries {
                            let delay = base_delay * 2u32.pow(attempt as u32);
                            log::info!(
                                "[SENDER] 429, retry in {:?} (attempt {}/{})",
                                delay,
                                attempt + 1,
                                max_retries + 1
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                    } else {
                        // прочие 4xx/5xx — не ретраим
                        let body = resp.text().await.unwrap_or_default();
                        return Err(anyhow!("server returned {}: {}", status, body));
                    }
                }
                Err(e) => {
                    last_err = Some(format!("request failed: {}", e));
                    if attempt < max_retries {
                        let delay = base_delay * 2u32.pow(attempt as u32);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
            }
        }

        Err(anyhow!(
            "push failed after {} attempts: {}",
            max_retries + 1,
            last_err.unwrap_or_else(|| "unknown".into())
        ))
    }

    pub async fn upload_file(&self, payload: &[u8]) -> Result<String> {
        if payload.is_empty() {
            return Err(anyhow!("empty payload"));
        }
        if payload.len() > MAX_UPLOAD_SIZE {
            return Err(anyhow!(
                "file too large: {} bytes (max {} bytes)",
                payload.len(),
                MAX_UPLOAD_SIZE
            ));
        }

        let config = self.current_config()?;
        let client = self.current_client()?;
        let url = format!("{}/upload", config.file_server_url);

        let response = client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            // Content-Length обязателен (API.md §5.1). body(Bytes) его ставит сам,
            // но явный заголовок защищает от регрессий.
            .header("Content-Length", payload.len().to_string())
            // Имя файла больше не передаётся открытым заголовком (M-4):
            // оно лежит внутри AEAD-конверта v3.
            .header("X-Requested-With", "XMLHttpRequest")
            .header("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0")
            .header(&config.mask_header_name, &config.mask_header_value)
            .body(bytes::Bytes::copy_from_slice(payload))
            .send()
            .await
            .map_err(|e| anyhow!("upload request failed: {}", e))?;

        match response.status().as_u16() {
            200 => {
                let file_hash = response
                    .text()
                    .await
                    .map_err(|e| anyhow!("read response: {}", e))?;
                let file_hash = file_hash.trim();
                if file_hash.is_empty() {
                    return Err(anyhow!("server returned empty file hash"));
                }
                // Хеш от сервера — недоверенный ввод. Приводим к
                // каноническому lower-case hex до использования в UI/URL.
                let file_hash = FileHash::from_hex(file_hash).map_err(|e| {
                    anyhow!(
                        "server returned invalid file hash ({}…, {} chars): {}",
                        truncate_display(file_hash, 16),
                        file_hash.chars().count(),
                        e
                    )
                })?;
                Ok(file_hash.to_string())
            }
            411 => Err(anyhow!("missing Content-Length")),
            413 => Err(anyhow!("file too large (413)")),
            429 => Err(anyhow!("rate limited (429)")),
            code => {
                let body = response.text().await.unwrap_or_default();
                Err(anyhow!("upload failed: {} - {}", code, body))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn upload_file_does_not_send_file_name_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("server address");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];

            loop {
                let read = stream.read(&mut chunk).await.expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let headers_end = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
                .unwrap_or(request.len());
            let headers = String::from_utf8_lossy(&request[..headers_end]).to_ascii_lowercase();

            let declared = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while request.len() < headers_end + declared {
                let read = stream.read(&mut chunk).await.expect("read body");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }

            let body = "a".repeat(64);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write response");
            stream.flush().await.ok();
            headers
        });

        let config = Config {
            file_server_url: format!("http://{}", addr),
            ..Config::default()
        };
        let sender = Sender::new(&config).expect("sender");
        let hash = sender.upload_file(b"encrypted envelope").await.expect("upload");
        assert_eq!(hash.len(), 64);

        let headers = server.await.expect("server task");
        let forbidden = format!("x-{}-name", "file");
        assert!(!headers.contains(&forbidden), "headers: {}", headers);
    }
}
