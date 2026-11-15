// src/network/listener.rs
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use reqwest::header::CONTENT_TYPE;
use reqwest::Client;
use std::sync::RwLock;
use std::time::Duration;
use crate::network::{
    auth, build_http_client, Config, BODY_READ_TIMEOUT, MAX_ERROR_BODY, MAX_FILE_BODY,
    MAX_MESSAGE_BODY, MAX_MULTIPART_BOUNDARY, MAX_MULTIPART_HEADERS,
    MAX_MULTIPART_HEADER_BYTES, MAX_MULTIPART_PARTS,
};
use crate::types::{truncate_display, FileHash};

/// Сколько секунд сервер держит входящий long-poll запрос.
const LONG_POLL_WAIT_SECS: u64 = 25;
/// Таймаут клиента должен быть больше `wait` с запасом на анонимные сети.
const PULL_TIMEOUT: Duration = Duration::from_secs(45);
/// Скачивание файла может идти дольше обычного запроса.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Ошибка long-poll запроса, от которой зависит стратегия повторов.
#[derive(Debug)]
pub enum PullError {
    /// Транспортная ошибка: обрыв, таймаут, недоступный прокси.
    Network(String),
    /// Сервер ответил 429.
    RateLimited,
    /// Сервер ответил 401.
    Unauthorized(String),
    /// Сервер ответил 4xx/5xx.
    Server(u16, String),
    /// Нарушение протокола: неожиданный Content-Type, битый multipart.
    Protocol(String),
    /// Тело ответа нарушило лимиты/целостность или не дочиталось.
    Body(BodyError),
}

/// Тело ответа превысило жёсткий лимит.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadTooLarge {
    pub limit: usize,
    pub declared: Option<u64>,
}

impl std::fmt::Display for PayloadTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.declared {
            Some(declared) => write!(
                f,
                "payload too large: declared {} bytes, limit {} bytes",
                declared, self.limit
            ),
            None => write!(f, "payload too large: limit {} bytes", self.limit),
        }
    }
}

impl std::error::Error for PayloadTooLarge {}

/// Multipart-часть превысила один из лимитов парсера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartLimitExceeded {
    pub what: &'static str,
    pub limit: usize,
}

impl std::fmt::Display for MultipartLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "multipart {} limit exceeded ({})", self.what, self.limit)
    }
}

impl std::error::Error for MultipartLimitExceeded {}

/// Ошибка потокового чтения тела ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyError {
    PayloadTooLarge(PayloadTooLarge),
    /// Фактическое тело не совпало с `Content-Length` (fail-closed).
    ContentLengthMismatch { declared: u64, actual: u64 },
    Timeout { seconds: u64 },
    Network(String),
    Multipart(MultipartError),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BodyError::PayloadTooLarge(error) => write!(f, "{}", error),
            BodyError::ContentLengthMismatch { declared, actual } => write!(
                f,
                "Content-Length mismatch: declared {}, received {}",
                declared, actual
            ),
            BodyError::Timeout { seconds } => {
                write!(f, "body read timed out after {} seconds", seconds)
            }
            BodyError::Network(message) => write!(f, "body read failed: {}", message),
            BodyError::Multipart(error) => write!(f, "{}", error),
        }
    }
}

impl std::error::Error for BodyError {}

/// Ошибка разбора multipart-ответа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultipartError {
    Limit(MultipartLimitExceeded),
    Malformed(String),
}

impl std::fmt::Display for MultipartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultipartError::Limit(error) => write!(f, "{}", error),
            MultipartError::Malformed(message) => write!(f, "malformed multipart: {}", message),
        }
    }
}

impl std::error::Error for MultipartError {}

impl std::fmt::Display for PullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PullError::Network(message) => write!(f, "pull request failed: {}", message),
            PullError::RateLimited => write!(f, "rate limited (429)"),
            PullError::Unauthorized(body) => write!(f, "unauthorized (401): {}", body),
            PullError::Server(code, body) => write!(f, "server returned {}: {}", code, body),
            PullError::Protocol(message) => write!(f, "{}", message),
            PullError::Body(error) => write!(f, "{}", error),
        }
    }
}

impl std::error::Error for PullError {}

impl PullError {
    /// Повторять запрос после паузы имеет смысл при сетевых сбоях,
    /// ответах 5xx и 429.
    pub fn is_retryable(&self) -> bool {
        match self {
            PullError::Network(_) | PullError::RateLimited => true,
            PullError::Server(code, _) => *code >= 500,
            PullError::Body(BodyError::Network(_)) | PullError::Body(BodyError::Timeout { .. }) => {
                true
            }
            PullError::Unauthorized(_)
            | PullError::Protocol(_)
            | PullError::Body(_) => false,
        }
    }
}

/// Потоково читает тело ответа, не позволяя серверу исчерпать память.
///
/// Политика:
/// - `Content-Length` больше лимита → ошибка до чтения тела;
/// - суммарный размер ровно `limit` включительно разрешён;
/// - превышение в chunked-ответе или несовпадение с `Content-Length`
///   (в любую сторону) → ошибка, остаток тела не дочитывается;
/// - таймаут покрывает всё чтение, а не отдельный chunk.
///
/// Общая для `listener` и `sender`: ответ `/upload` тоже недоверенный.
pub(crate) async fn read_body_limited(
    mut response: reqwest::Response,
    limit: usize,
    timeout: Duration,
) -> std::result::Result<Vec<u8>, BodyError> {
    let declared = response.content_length();
    if let Some(declared) = declared {
        if declared > limit as u64 {
            return Err(BodyError::PayloadTooLarge(PayloadTooLarge {
                limit,
                declared: Some(declared),
            }));
        }
    }

    // Не аллоцируем по заявленному размеру: даже легитимные 256 MiB
    // растут постепенно, а вредоносный Content-Length не резервирует память.
    const INITIAL_CAPACITY: usize = 64 * 1024;
    let initial_capacity = declared
        .map(|value| value.min(INITIAL_CAPACITY as u64) as usize)
        .unwrap_or(0);

    let read = async move {
        let mut body = Vec::with_capacity(initial_capacity);
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|e| BodyError::Network(e.to_string()))?;
            let Some(chunk) = chunk else {
                break;
            };

            let actual = body
                .len()
                .checked_add(chunk.len())
                .ok_or(BodyError::PayloadTooLarge(PayloadTooLarge {
                    limit,
                    declared,
                }))?;

            if actual > limit {
                return Err(BodyError::PayloadTooLarge(PayloadTooLarge {
                    limit,
                    declared,
                }));
            }

            if let Some(declared) = declared {
                if actual as u64 > declared {
                    return Err(BodyError::ContentLengthMismatch {
                        declared,
                        actual: actual as u64,
                    });
                }
            }

            body.extend_from_slice(&chunk);
        }

        if let Some(declared) = declared {
            if body.len() as u64 != declared {
                return Err(BodyError::ContentLengthMismatch {
                    declared,
                    actual: body.len() as u64,
                });
            }
        }

        Ok(body)
    };

    match tokio::time::timeout(timeout, read).await {
        Err(_) => Err(BodyError::Timeout {
            seconds: timeout.as_secs(),
        }),
        Ok(result) => result,
    }
}

pub struct Listener {
    client: RwLock<Client>,
    config: RwLock<Config>,
}

impl Listener {
    pub fn new(config: &Config) -> Result<Self> {
        let client = build_http_client(PULL_TIMEOUT, config.proxy_url.as_deref())?;

        Ok(Self {
            client: RwLock::new(client),
            config: RwLock::new(config.clone()),
        })
    }

    /// Применяет новые сетевые параметры и пересобирает клиент под новый прокси.
    pub fn update_config(&self, config: &Config) -> Result<()> {
        let client = build_http_client(PULL_TIMEOUT, config.proxy_url.as_deref())?;

        let mut config_guard = self
            .config
            .write()
            .map_err(|_| anyhow!("конфигурация слушателя недоступна: блокировка повреждена"))?;
        let mut client_guard = self
            .client
            .write()
            .map_err(|_| anyhow!("HTTP-клиент слушателя недоступен: блокировка повреждена"))?;

        *config_guard = config.clone();
        *client_guard = client;
        Ok(())
    }

    fn current_config(&self) -> Result<Config> {
        self.config
            .read()
            .map(|config| config.clone())
            .map_err(|_| anyhow!("конфигурация слушателя недоступна: блокировка повреждена"))
    }

    fn current_client(&self) -> Result<Client> {
        self.client
            .read()
            .map(|client| client.clone())
            .map_err(|_| anyhow!("HTTP-клиент слушателя недоступен: блокировка повреждена"))
    }

    pub async fn pull_messages_with_auth(
        &self,
        identity_hash: &str,
        pub_key_hex: &str,          // hex(ed25519_public_key) — НЕ хеш!
        signing_key: &SigningKey,
    ) -> std::result::Result<Vec<Vec<u8>>, PullError> {
        let config = self
            .current_config()
            .map_err(|e| PullError::Protocol(e.to_string()))?;
        let client = self
            .current_client()
            .map_err(|e| PullError::Protocol(e.to_string()))?;
        // Подпись покрывает метод, путь, query, timestamp, одноразовый nonce
        // и SHA256(body) — см. src/network/auth.rs (H-4).
        let timestamp = chrono::Utc::now().timestamp();
        let nonce = auth::generate_nonce();
        let path = format!("/pull/{}", identity_hash);
        let query = format!("wait={}", LONG_POLL_WAIT_SECS);
        let signature = auth::sign_request(
            signing_key,
            "GET",
            &path,
            &query,
            timestamp,
            &nonce,
            &[],
        );

        // ?wait=25 включает серверный HTTP long-poll: пустая очередь держит
        // соединение до появления сообщения или истечения wait.
        let url = format!("{}{}?{}", config.server_url, path, query);

        let response = client
            .get(&url)
            .header("X-Identity-Key", pub_key_hex)
            .header(auth::HEADER_IDENTITY, identity_hash)
            .header(auth::HEADER_TIMESTAMP, timestamp.to_string())
            .header(auth::HEADER_NONCE, &nonce)
            .header(auth::HEADER_SIGNATURE, &signature)
            .header("X-Requested-With", "XMLHttpRequest")
            .header("Accept", "multipart/form-data")
            .header("User-Agent", "Mozilla/5.0 (X11; Arch Linux; rv:130.0) Gecko/20100101 Firefox/130.0")
            .header(&config.mask_header_name, &config.mask_header_value)
            .send()
            .await
            .map_err(|e| PullError::Network(e.to_string()))?;

        let status = response.status();

        if status == reqwest::StatusCode::NO_CONTENT {
            return Ok(Vec::new());
        }

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(PullError::RateLimited);
        }

        if status == reqwest::StatusCode::UNAUTHORIZED {
            let body = read_body_limited(response, MAX_ERROR_BODY, BODY_READ_TIMEOUT)
                .await
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            return Err(PullError::Unauthorized(body));
        }

        if !status.is_success() {
            let body = read_body_limited(response, MAX_ERROR_BODY, BODY_READ_TIMEOUT)
                .await
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            return Err(PullError::Server(status.as_u16(), body));
        }

        // Content-Type должен быть multipart/form-data; boundary=...
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();

        if !content_type.starts_with("multipart/") {
            // API.md гарантирует multipart на 200, но если сервер вернул
            // что-то иное — не молча делаем вид, что это один пакет.
            return Err(PullError::Protocol(format!(
                "unexpected Content-Type on /pull: {:?}",
                truncate_display(&content_type, 64)
            )));
        }

        let bytes = read_body_limited(response, MAX_MESSAGE_BODY, BODY_READ_TIMEOUT)
            .await
            .map_err(PullError::Body)?;

        let messages = parse_multipart(&content_type, &bytes)
            .map_err(|e| PullError::Body(BodyError::Multipart(e)))?;

        // Валидация размеров: v3 использует bucket + рандомизацию внутри
        // bucket, поэтому проверяем диапазон, а не точное значение.
        for m in &messages {
            if !crate::crypto::ratchet::is_valid_packet_len(m.len()) {
                log::warn!(
                    "[LISTENER] packet size {} is outside the v3 padding grid",
                    m.len()
                );
            }
        }

        Ok(messages)
    }

    pub async fn download_file(&self, file_hash: &str) -> Result<Vec<u8>> {
        if file_hash.is_empty() {
            return Err(anyhow!("empty file_hash"));
        }
        // Идентификатор уходит в URL: принимаем только 64 hex-символа.
        let bare_hash = file_hash.strip_prefix("sha256:").unwrap_or(file_hash);
        let file_hash = FileHash::from_hex(bare_hash).map_err(|e| {
            anyhow!(
                "invalid file hash ({}…, {} chars): {}",
                truncate_display(file_hash, 16),
                file_hash.chars().count(),
                e
            )
        })?;

        let config = self.current_config()?;
        let client = self.current_client()?;
        let url = format!("{}/download/{}", config.file_server_url, file_hash);

        let response = client
            .get(&url)
            // Общий таймаут клиента рассчитан на long-poll; файл может
            // качаться дольше, поэтому для download задаём свой лимит.
            .timeout(DOWNLOAD_TIMEOUT)
            .header("X-Requested-With", "XMLHttpRequest")
            .header("User-Agent", "Mozilla/5.0 (X11; Arch Linux; rv:130.0) Gecko/20100101 Firefox/130.0")
            .header(&config.mask_header_name, &config.mask_header_value)
            .send()
            .await
            .map_err(|e| anyhow!("download request failed: {}", e))?;

        match response.status().as_u16() {
            200 => {
                let data = read_body_limited(response, MAX_FILE_BODY, BODY_READ_TIMEOUT)
                    .await
                    .map_err(|e| anyhow!("download body rejected: {}", e))?;
                Ok(data)
            }
            404 => Err(anyhow!(
                "file not found (already downloaded or expired)"
            )),
            400 => Err(anyhow!("bad request (missing file hash)")),
            429 => Err(anyhow!("rate limited (429)")),
            code => {
                let body = read_body_limited(response, MAX_ERROR_BODY, BODY_READ_TIMEOUT)
                    .await
                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                    .unwrap_or_default();
                Err(anyhow!("download failed: {} - {}", code, body))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Multipart parsing
// ---------------------------------------------------------------------------

/// Извлекает `boundary` из `Content-Type: multipart/form-data; boundary=...`.
fn extract_boundary(content_type: &str) -> Result<Vec<u8>, MultipartError> {
    // boundary может быть в кавычках: boundary="abc"
    for part in content_type.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("boundary=") {
            let boundary = rest.trim().trim_matches('"');
            if boundary.is_empty() {
                return Err(MultipartError::Malformed("empty boundary".to_string()));
            }
            if boundary.len() > MAX_MULTIPART_BOUNDARY {
                return Err(MultipartError::Limit(MultipartLimitExceeded {
                    what: "boundary bytes",
                    limit: MAX_MULTIPART_BOUNDARY,
                }));
            }
            if boundary.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
                return Err(MultipartError::Malformed(
                    "boundary contains CR/LF".to_string(),
                ));
            }
            return Ok(boundary.as_bytes().to_vec());
        }
    }
    Err(MultipartError::Malformed(format!(
        "no boundary in Content-Type: {:?}",
        truncate_display(content_type, 64)
    )))
}

/// Разбирает multipart-тело ответа `/pull` с лимитами на части и заголовки.
///
/// Формат (RFC 7578):
///   --boundary\r\n
///   headers...\r\n
///   \r\n
///   <payload>\r\n
///   --boundary\r\n
///   ...
///   --boundary--\r\n
fn parse_multipart(content_type: &str, body: &[u8]) -> Result<Vec<Vec<u8>>, MultipartError> {
    parse_multipart_with_limit(content_type, body, MAX_MESSAGE_BODY)
}

fn parse_multipart_with_limit(
    content_type: &str,
    body: &[u8],
    max_body: usize,
) -> Result<Vec<Vec<u8>>, MultipartError> {
    if body.len() > max_body {
        return Err(MultipartError::Limit(MultipartLimitExceeded {
            what: "body bytes",
            limit: max_body,
        }));
    }

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
    let mut parts_seen = 0usize;
    let mut payload_total = 0usize;
    let mut pos;

    // Первый boundary
    if body.starts_with(&leading) {
        pos = leading.len();
    } else if let Some(idx) = find_subsequence(body, &delimiter) {
        pos = idx + delimiter.len();
    } else {
        return Err(MultipartError::Malformed(
            "body has no boundary".to_string(),
        ));
    }

    loop {
        // После boundary: либо "--" (конец), либо "\r\n" (заголовки части)
        if body.get(pos..pos + 2) == Some(b"--") {
            break;
        }
        if body.get(pos..pos + 2) != Some(b"\r\n") {
            return Err(MultipartError::Malformed(
                "expected CRLF after boundary".to_string(),
            ));
        }

        // Закрывающий boundary не считается частью, поэтому лимит
        // проверяется только для реальных секций.
        parts_seen += 1;
        if parts_seen > MAX_MULTIPART_PARTS {
            return Err(MultipartError::Limit(MultipartLimitExceeded {
                what: "parts",
                limit: MAX_MULTIPART_PARTS,
            }));
        }
        pos += 2;

        // Ищем конец заголовков части (пустая строка).
        // Отсчёт начинаем на два байта раньше: у части без заголовков
        // терминатор `\r\n\r\n` состоит из CRLF после boundary и пустой
        // строки заголовков. Иначе такой (валидный) multipart не разобрать.
        let headers_start = pos.saturating_sub(2);
        let headers_end = find_subsequence(&body[headers_start..], b"\r\n\r\n").ok_or_else(|| {
            MultipartError::Malformed("part has no header terminator".to_string())
        })?;

        if headers_end > MAX_MULTIPART_HEADER_BYTES {
            return Err(MultipartError::Limit(MultipartLimitExceeded {
                what: "header bytes per part",
                limit: MAX_MULTIPART_HEADER_BYTES,
            }));
        }

        let header_block = &body[headers_start..headers_start + headers_end];
        let header_count = header_block
            .windows(2)
            .filter(|window| window == b"\r\n")
            .count();
        if header_count > MAX_MULTIPART_HEADERS {
            return Err(MultipartError::Limit(MultipartLimitExceeded {
                what: "headers per part",
                limit: MAX_MULTIPART_HEADERS,
            }));
        }

        let payload_start = headers_start + headers_end + 4;

        // Ищем следующий delimiter
        let next = find_subsequence(&body[payload_start..], &delimiter).ok_or_else(|| {
            MultipartError::Malformed("body ended without closing boundary".to_string())
        })?;

        let payload_end = payload_start + next;
        let payload_len = payload_end - payload_start;
        payload_total = payload_total.checked_add(payload_len).ok_or(
            MultipartError::Limit(MultipartLimitExceeded {
                what: "payload bytes",
                limit: max_body,
            }),
        )?;
        if payload_total > max_body {
            return Err(MultipartError::Limit(MultipartLimitExceeded {
                what: "payload bytes",
                limit: max_body,
            }));
        }

        if payload_len > 0 {
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

    // Пропускаем несовпавшие позиции по первому байту boundary, а не
    // запускаем `windows()`-сравнение на каждом смещении.
    let first = needle[0];
    let mut start = 0usize;
    while start + needle.len() <= haystack.len() {
        let offset = haystack[start..].iter().position(|&byte| byte == first)?;
        let candidate = start + offset;
        if candidate + needle.len() > haystack.len() {
            return None;
        }
        if &haystack[candidate..candidate + needle.len()] == needle {
            return Some(candidate);
        }
        start = candidate + 1;
    }
    None
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

    #[tokio::test]
    async fn pull_request_carries_canonical_signature_headers() {
        use crate::identity::hash_ed25519_public;
        use crate::network::auth::{AuthFailure, AuthRequest, AuthVerifier};
        use std::collections::HashMap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::sync::oneshot;

        let server = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        let (request_sender, request_receiver) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut raw = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = stream.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..read]);
                if raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = request_sender.send(String::from_utf8_lossy(&raw).into_owned());
            let _ = stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            let _ = stream.shutdown().await;
        });

        let config = Config {
            server_url: format!("http://{}", addr),
            ..Config::default()
        };
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let identity_hash =
            hash_ed25519_public(signing_key.verifying_key().as_bytes());
        let listener = Listener::new(&config).unwrap();

        let messages = listener
            .pull_messages_with_auth(
                &identity_hash,
                &hex::encode(signing_key.verifying_key().as_bytes()),
                &signing_key,
            )
            .await
            .unwrap();
        assert!(messages.is_empty());

        let raw = request_receiver.await.unwrap();
        let mut lines = raw.split("\r\n");
        let request_line = lines.next().unwrap();
        let mut parts = request_line.split(' ');
        assert_eq!(parts.next(), Some("GET"));
        let target = parts.next().unwrap();
        let (path, query) = target.split_once('?').unwrap();
        assert_eq!(path, format!("/pull/{}", identity_hash));
        assert_eq!(query, "wait=25");

        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        let nonce = headers.get("x-auth-nonce").unwrap();
        let signature = headers.get("x-auth-signature").unwrap();
        let timestamp: i64 = headers.get("x-auth-timestamp").unwrap().parse().unwrap();
        assert_eq!(headers.get("x-auth-identity").unwrap(), &identity_hash);

        let request = AuthRequest {
            method: "GET",
            path,
            query,
            timestamp,
            nonce: nonce.as_str(),
            signature: signature.as_str(),
            body: b"",
        };
        let now = chrono::Utc::now().timestamp();
        let verifying_key = signing_key.verifying_key();
        let mut verifier = AuthVerifier::new();
        assert_eq!(
            verifier.verify(&verifying_key, &identity_hash, &request, now),
            Ok(())
        );
        assert_eq!(
            verifier.verify(&verifying_key, &identity_hash, &request, now),
            Err(AuthFailure::ReplayedNonce)
        );
    }

    async fn spawn_raw_response(
        response: Vec<u8>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            let _ = stream.write_all(&response).await;
            let _ = stream.shutdown().await;
        });
        (format!("http://{}", addr), handle)
    }

    #[tokio::test]
    async fn content_length_above_limit_is_rejected_before_body() {
        let (url, server) = spawn_raw_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 999999\r\nConnection: close\r\n\r\n".to_vec(),
        )
        .await;
        let response = reqwest::Client::new().get(&url).send().await.unwrap();

        let error = read_body_limited(response, 32, BODY_READ_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BodyError::PayloadTooLarge(PayloadTooLarge {
                limit: 32,
                declared: Some(999999)
            })
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn chunked_body_over_limit_is_aborted() {
        let (url, server) = spawn_raw_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n".to_vec(),
        )
        .await;
        let response = reqwest::Client::new().get(&url).send().await.unwrap();

        let error = read_body_limited(response, 8, BODY_READ_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BodyError::PayloadTooLarge(PayloadTooLarge { limit: 8, .. })
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn body_limit_is_inclusive() {
        let (url, server) = spawn_raw_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n".to_vec(),
        )
        .await;
        let response = reqwest::Client::new().get(&url).send().await.unwrap();
        let body = read_body_limited(response, 10, BODY_READ_TIMEOUT)
            .await
            .unwrap();
        assert_eq!(body, b"helloworld");
        server.await.unwrap();

        let (url, server) = spawn_raw_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n".to_vec(),
        )
        .await;
        let response = reqwest::Client::new().get(&url).send().await.unwrap();
        assert!(read_body_limited(response, 9, BODY_READ_TIMEOUT)
            .await
            .is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn truncated_body_is_rejected() {
        let (url, server) = spawn_raw_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nhello"
                .to_vec(),
        )
        .await;
        let response = reqwest::Client::new().get(&url).send().await.unwrap();

        assert!(read_body_limited(response, 64, BODY_READ_TIMEOUT)
            .await
            .is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn slow_body_hits_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 2048];
            let _ = stream.read(&mut request).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n")
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let response = reqwest::Client::new()
            .get(format!("http://{}", addr))
            .send()
            .await
            .unwrap();
        let error = read_body_limited(response, 64, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(matches!(error, BodyError::Timeout { .. }));
        server.abort();
    }

    #[test]
    fn multipart_rejects_too_many_parts() {
        let mut body = String::new();
        for index in 0..=MAX_MULTIPART_PARTS {
            body.push_str(&format!("--X\r\n\r\npart-{}\r\n", index));
        }
        body.push_str("--X--\r\n");

        match parse_multipart("multipart/form-data; boundary=X", body.as_bytes()) {
            Err(MultipartError::Limit(error)) => assert_eq!(error.what, "parts"),
            other => panic!("expected parts limit, got {:?}", other),
        }
    }

    #[test]
    fn multipart_accepts_exactly_max_parts() {
        let mut body = String::new();
        for index in 0..MAX_MULTIPART_PARTS {
            body.push_str(&format!("--X\r\n\r\npart-{}\r\n", index));
        }
        body.push_str("--X--\r\n");

        let parts = parse_multipart("multipart/form-data; boundary=X", body.as_bytes()).unwrap();
        assert_eq!(parts.len(), MAX_MULTIPART_PARTS);
    }

    #[test]
    fn multipart_rejects_oversized_headers() {
        let body = format!(
            "--X\r\nX-Big: {}\r\n\r\npayload\r\n--X--\r\n",
            "a".repeat(MAX_MULTIPART_HEADER_BYTES)
        );
        match parse_multipart("multipart/form-data; boundary=X", body.as_bytes()) {
            Err(MultipartError::Limit(error)) => {
                assert_eq!(error.what, "header bytes per part")
            }
            other => panic!("expected header bytes limit, got {:?}", other),
        }
    }

    #[test]
    fn multipart_rejects_too_many_headers() {
        let mut body = String::from("--X\r\n");
        for index in 0..=MAX_MULTIPART_HEADERS {
            body.push_str(&format!("X-Header-{}: v\r\n", index));
        }
        body.push_str("\r\npayload\r\n--X--\r\n");

        match parse_multipart("multipart/form-data; boundary=X", body.as_bytes()) {
            Err(MultipartError::Limit(error)) => assert_eq!(error.what, "headers per part"),
            other => panic!("expected headers limit, got {:?}", other),
        }
    }

    #[test]
    fn multipart_rejects_body_over_limit() {
        let body = b"--X\r\n\r\npayload\r\n--X--\r\n";
        match parse_multipart_with_limit("multipart/form-data; boundary=X", body, 8) {
            Err(MultipartError::Limit(error)) => assert_eq!(error.what, "body bytes"),
            other => panic!("expected body limit, got {:?}", other),
        }
    }

    #[test]
    fn multipart_rejects_oversized_boundary() {
        let boundary = "b".repeat(MAX_MULTIPART_BOUNDARY + 1);
        let content_type = format!("multipart/form-data; boundary={}", boundary);
        match parse_multipart(&content_type, b"--x--\r\n") {
            Err(MultipartError::Limit(error)) => assert_eq!(error.what, "boundary bytes"),
            other => panic!("expected boundary limit, got {:?}", other),
        }
    }

    #[test]
    fn multipart_rejects_garbage_without_panicking() {
        for (content_type, body) in [
            ("multipart/form-data", &b"garbage"[..]),
            ("multipart/form-data; boundary=", &b"garbage"[..]),
            (
                "multipart/form-data; boundary=X",
                &b"--X\r\nno terminator"[..],
            ),
            ("multipart/form-data; boundary=X", &b"--X\r\n\r\npayload"[..]),
        ] {
            assert!(matches!(
                parse_multipart(content_type, body),
                Err(MultipartError::Malformed(_))
            ));
        }
    }
}
