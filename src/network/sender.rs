// src/network/sender.rs
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use reqwest::Client;
use std::collections::HashMap;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use crate::identity::hash_ed25519_public;
use crate::network::listener::read_body_limited;
use crate::network::{auth, build_http_client, Config, BODY_READ_TIMEOUT, MAX_ERROR_BODY};
use crate::types::{truncate_display, FileHash};

const MAX_UPLOAD_SIZE: usize = crate::crypto::FILE_MAX_ENVELOPE;
/// Успешный `/upload` возвращает один hex-хеш (64 символа). Лимит с запасом
/// на whitespace, но жёсткий: тело 200 — такой же недоверенный ввод, как и
/// тело ошибки, и не должно читаться без границ (M-A).
const MAX_UPLOAD_HASH_BODY: usize = 1024;
// Один клиент на всё; таймаут 120s покрывает upload до 128 MiB.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(120);

/// Локальный лимит `/push` на комнату. Подпись можно получить легитимно,
/// поэтому клиент не должен превращаться в источник флуда (M-8).
pub const PUSH_REQUESTS_PER_SECOND: u32 = 8;
/// Максимум повторов `/push` после 429/503/сетевой ошибки.
pub const MAX_PUSH_RETRIES: u32 = 3;
/// Базовая пауза экспоненциального backoff.
pub const PUSH_BASE_DELAY: Duration = Duration::from_secs(1);

/// Типизированная ошибка `/push`: позволяет не ретраить 401 и различать
/// rate-limit/серверные отказы без разбора строк.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushError {
    /// Сервер ответил 429 после исчерпания повторов.
    RateLimited { body: String },
    /// Подпись/identity/nonce не приняты сервером. Повтор не поможет.
    Unauthorized { body: String },
    /// Прочий 4xx/5xx (5xx повторяется до лимита).
    Server { status: u16, body: String },
    /// Транспортная ошибка после исчерпания повторов.
    Network(String),
    /// Пакет не соответствует v3-сетке или локальному контракту.
    Protocol(String),
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushError::RateLimited { body } => write!(f, "rate limited (429): {}", body),
            PushError::Unauthorized { body } => write!(f, "unauthorized (401): {}", body),
            PushError::Server { status, body } => {
                write!(f, "server returned {}: {}", status, body)
            }
            PushError::Network(message) => write!(f, "push request failed: {}", message),
            PushError::Protocol(message) => write!(f, "push rejected: {}", message),
        }
    }
}

impl std::error::Error for PushError {}

/// Token bucket на комнату: `per_second` токенов в секунду, burst — тот же
/// размер. Детерминирован по переданному `Instant`, поэтому тестируется без
/// реального сна.
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

struct PushRateLimiter {
    per_second: u32,
    burst: f64,
    buckets: HashMap<String, TokenBucket>,
}

impl PushRateLimiter {
    fn new(per_second: u32) -> Self {
        let per_second = per_second.max(1);
        Self {
            per_second,
            burst: f64::from(per_second),
            buckets: HashMap::new(),
        }
    }

    fn delay_until_allowed(&mut self, key: &str, now: Instant) -> Duration {
        let per_second = f64::from(self.per_second);
        let burst = self.burst;
        let bucket = self
            .buckets
            .entry(key.to_string())
            .or_insert(TokenBucket {
                tokens: burst,
                last_refill: now,
            });

        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_second).min(burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Duration::ZERO
        } else {
            Duration::from_secs_f64((1.0 - bucket.tokens) / per_second)
        }
    }
}

pub struct Sender {
    client: RwLock<Client>,
    config: RwLock<Config>,
    rate_limiter: Mutex<PushRateLimiter>,
    retry_base_delay: Duration,
}

impl Sender {
    pub fn new(config: &Config) -> Result<Self> {
        Self::with_limits(config, PUSH_REQUESTS_PER_SECOND, PUSH_BASE_DELAY)
    }

    fn with_limits(
        config: &Config,
        requests_per_second: u32,
        retry_base_delay: Duration,
    ) -> Result<Self> {
        let client = build_http_client(CLIENT_TIMEOUT, config.proxy_url.as_deref())?;

        Ok(Self {
            client: RwLock::new(client),
            config: RwLock::new(config.clone()),
            rate_limiter: Mutex::new(PushRateLimiter::new(requests_per_second)),
            retry_base_delay,
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

    /// Ждёт свободный слот локального rate-limit для комнаты.
    async fn wait_for_push_slot(&self, room: &str) -> std::result::Result<(), PushError> {
        loop {
            let delay = {
                let mut limiter = self.rate_limiter.lock().map_err(|_| {
                    PushError::Protocol("push rate limiter lock poisoned".to_string())
                })?;
                limiter.delay_until_allowed(room, Instant::now())
            };

            if delay.is_zero() {
                return Ok(());
            }

            log::debug!(
                "[SENDER] push rate limit for {}: waiting {:?}",
                truncate_display(room, 16),
                delay
            );
            tokio::time::sleep(delay).await;
        }
    }

    fn backoff(&self, attempt: u32) -> Duration {
        let multiplier = 2u32.saturating_pow(attempt.min(5));
        self.retry_base_delay.saturating_mul(multiplier)
    }

    /// Отправляет v3-пакет и подписывает `/push` тем же каноническим
    /// конвертом, что `/pull` (H-4/M-8).
    ///
    /// Каждая попытка получает свежие `timestamp` и `nonce`; `body_hash`
    /// привязан к точному v3-конверту. `401` не повторяется.
    pub async fn send_message(
        &self,
        target_hash: &str,
        packet: &[u8],
        signing_key: &SigningKey,
    ) -> std::result::Result<(), PushError> {
        if !crate::crypto::ratchet::is_valid_packet_len(packet.len()) {
            return Err(PushError::Protocol(format!(
                "invalid packet size {} (expected a v3 bucket with randomized padding)",
                packet.len()
            )));
        }

        let config = self
            .current_config()
            .map_err(|e| PushError::Protocol(e.to_string()))?;
        let client = self
            .current_client()
            .map_err(|e| PushError::Protocol(e.to_string()))?;

        let identity_hash = hash_ed25519_public(signing_key.verifying_key().as_bytes());
        let identity_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let path = format!("/push/{}", target_hash);
        let url = format!("{}{}", config.server_url, path);

        let mut last_error: Option<String> = None;

        for attempt in 0..=MAX_PUSH_RETRIES {
            self.wait_for_push_slot(target_hash).await?;

            let timestamp = chrono::Utc::now().timestamp();
            let nonce = auth::generate_nonce();
            let signature = auth::sign_request(
                signing_key,
                "POST",
                &path,
                "",
                timestamp,
                &nonce,
                packet,
            );

            let result = client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Length", packet.len().to_string())
                .header("X-Identity-Key", &identity_key_hex)
                .header(auth::HEADER_IDENTITY, &identity_hash)
                .header(auth::HEADER_TIMESTAMP, timestamp.to_string())
                .header(auth::HEADER_NONCE, &nonce)
                .header(auth::HEADER_SIGNATURE, &signature)
                .header("X-Requested-With", "XMLHttpRequest")
                .header("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0")
                .header(&config.mask_header_name, &config.mask_header_value)
                // bytes::Bytes — без лишней копии Vec
                .body(bytes::Bytes::copy_from_slice(packet))
                .send()
                .await;

            match result {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        return Ok(());
                    }

                    let code = status.as_u16();
                    let body = read_error_body(response, MAX_ERROR_BODY).await;

                    if code == 401 {
                        // Подпись/nonce/identity отклонены: слепой повтор
                        // только усилит нагрузку и не изменит результат.
                        log::warn!(
                            "[SENDER] push rejected by auth (401) for {}",
                            truncate_display(target_hash, 16)
                        );
                        return Err(PushError::Unauthorized { body });
                    }

                    // 429/503 и прочие 5xx — временные; повторяем с backoff.
                    if code == 429 || code == 503 || code >= 500 {
                        last_error = Some(format!("server returned {}: {}", code, body));
                        if attempt < MAX_PUSH_RETRIES {
                            let delay = self.backoff(attempt);
                            log::info!(
                                "[SENDER] {} for {}, retry in {:?} (attempt {}/{})",
                                code,
                                truncate_display(target_hash, 16),
                                delay,
                                attempt + 1,
                                MAX_PUSH_RETRIES + 1
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        return Err(if code == 429 {
                            PushError::RateLimited { body }
                        } else {
                            PushError::Server { status: code, body }
                        });
                    }

                    // Прочие 4xx — постоянная ошибка запроса.
                    return Err(PushError::Server { status: code, body });
                }
                Err(error) => {
                    last_error = Some(format!("request failed: {}", error));
                    if attempt < MAX_PUSH_RETRIES {
                        let delay = self.backoff(attempt);
                        log::info!(
                            "[SENDER] transport error for {}, retry in {:?} (attempt {}/{})",
                            truncate_display(target_hash, 16),
                            delay,
                            attempt + 1,
                            MAX_PUSH_RETRIES + 1
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
            }
        }

        Err(PushError::Network(
            last_error.unwrap_or_else(|| "unknown".to_string()),
        ))
    }

    /// Загружает файловый конверт на файловый сервер.
    ///
    /// `/upload` подписывается тем же каноническим конвертом, что `/push` и
    /// `/pull` (L-6): подпись покрывает метод, путь, timestamp, одноразовый
    /// nonce и `SHA256(payload)`, поэтому ни тело, ни endpoint нельзя
    /// подменить по дороге.
    pub async fn upload_file(
        &self,
        payload: &[u8],
        signing_key: &SigningKey,
    ) -> Result<String> {
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
        let path = "/upload";
        let url = format!("{}{}", config.file_server_url, path);
        let signed = auth::RequestSignature::sign(signing_key, "POST", path, "", payload);

        let mut request = client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            // Content-Length обязателен (API.md §5.1). body(Bytes) его ставит сам,
            // но явный заголовок защищает от регрессий.
            .header("Content-Length", payload.len().to_string());

        for (name, value) in signed.headers() {
            request = request.header(name, value);
        }

        let response = request
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
            200 => read_upload_hash(response).await,
            401 => {
                let body = read_error_body(response, MAX_ERROR_BODY).await;
                Err(anyhow!("unauthorized (401): {}", body))
            }
            411 => Err(anyhow!("missing Content-Length")),
            413 => Err(anyhow!(
                "file too large (413, max {} bytes)",
                MAX_UPLOAD_SIZE
            )),
            429 => Err(anyhow!("rate limited (429)")),
            code => {
                let body = read_error_body(response, MAX_ERROR_BODY).await;
                Err(anyhow!("upload failed: {} - {}", code, body))
            }
        }
    }
}

/// Разбирает тело успешного `/upload`: ограниченное чтение, затем строгая
/// проверка hex-хеша. Ошибки чтения (в т.ч. превышение лимита) фатальны —
/// тело 200 не должно читаться до EOF.
async fn read_upload_hash(response: reqwest::Response) -> Result<String> {
    let body = read_body_limited(response, MAX_UPLOAD_HASH_BODY, BODY_READ_TIMEOUT)
        .await
        .map_err(|e| anyhow!("read response: {}", e))?;

    // Валидный хеш — только ASCII hex; произвольные байты в сообщение об
    // ошибке не попадают.
    let body = std::str::from_utf8(&body)
        .map_err(|_| anyhow!("server returned non-UTF-8 file hash"))?;
    let file_hash = body.trim();
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

/// Читает тело ошибки с жёстким лимитом (M-2), не доверяя Content-Length.
async fn read_error_body(response: reqwest::Response, limit: usize) -> String {
    if response
        .content_length()
        .is_some_and(|declared| declared > limit as u64)
    {
        return String::new();
    }

    let read = async move {
        let mut response = response;
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len().saturating_add(chunk.len()) > limit {
                        break;
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        body
    };

    match tokio::time::timeout(BODY_READ_TIMEOUT, read).await {
        Ok(body) => String::from_utf8_lossy(&body).into_owned(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TARGET: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn test_packet() -> Vec<u8> {
        crate::crypto::ratchet::RatchetState::new(&[7u8; 32], crate::crypto::ratchet::Role::Initiator)
            .expect("ratchet state")
            .encrypt(b"signed push")
            .expect("encrypt")
    }

    fn test_config(url: String) -> Config {
        Config {
            server_url: url,
            ..Config::default()
        }
    }

    /// Читает один HTTP-запрос целиком (заголовки + тело по Content-Length).
    async fn read_request(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut chunk).await.expect("read request");
            if read == 0 {
                break request.len();
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(position) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break position + 4;
            }
        };

        let headers = String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
        let declared = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0);

        while request.len() < header_end + declared {
            let read = stream.read(&mut chunk).await.expect("read body");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
        }
        request
    }

    fn split_request(raw: &[u8]) -> (String, String, String, std::collections::HashMap<String, String>, Vec<u8>) {
        let header_end = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
            .expect("header terminator");
        let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
        let mut lines = head.split("\r\n");
        let request_line = lines.next().expect("request line");
        let mut parts = request_line.split(' ');
        let method = parts.next().unwrap_or_default().to_string();
        let target = parts.next().unwrap_or_default().to_string();
        let (path, query) = target.split_once('?').unwrap_or((&target, ""));
        let (path, query) = (path.to_string(), query.to_string());

        let mut headers = std::collections::HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        (method, path, query, headers, raw[header_end..].to_vec())
    }

    #[tokio::test]
    async fn push_request_carries_canonical_signature() {
        use crate::crypto::ratchet::{Role, RatchetState};
        use crate::network::auth::{AuthFailure, AuthRequest, AuthVerifier};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("server address");
        let (request_sender, request_receiver) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let raw = read_request(&mut stream).await;
            let _ = request_sender.send(raw);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = stream.shutdown().await;
        });

        let sender = Sender::new(&test_config(format!("http://{}", addr))).expect("sender");
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let packet = RatchetState::new(&[1u8; 32], Role::Initiator)
            .expect("state")
            .encrypt(b"hello")
            .expect("packet");
        sender
            .send_message(TARGET, &packet, &signing_key)
            .await
            .expect("push");

        let raw = request_receiver.await.expect("captured request");
        let (method, path, query, headers, body) = split_request(&raw);
        assert_eq!(method, "POST");
        assert_eq!(path, format!("/push/{}", TARGET));
        assert!(query.is_empty());
        assert_eq!(body, packet);

        let identity_hash = hash_ed25519_public(signing_key.verifying_key().as_bytes());
        assert_eq!(
            headers.get("x-auth-identity").map(String::as_str),
            Some(identity_hash.as_str())
        );
        assert_eq!(
            headers.get("x-identity-key").map(String::as_str),
            Some(hex::encode(signing_key.verifying_key().as_bytes()).as_str())
        );

        let timestamp: i64 = headers
            .get("x-auth-timestamp")
            .expect("timestamp")
            .parse()
            .expect("timestamp number");
        let nonce = headers.get("x-auth-nonce").expect("nonce").clone();
        let signature = headers.get("x-auth-signature").expect("signature").clone();
        let now = chrono::Utc::now().timestamp();

        let verifying_key = signing_key.verifying_key();
        let path_owned = path.clone();
        let mut verifier = AuthVerifier::new();
        let request = AuthRequest {
            method: "POST",
            path: &path_owned,
            query: "",
            timestamp,
            nonce: &nonce,
            signature: &signature,
            body: &packet,
        };
        assert_eq!(
            verifier.verify(&verifying_key, &identity_hash, &request, now),
            Ok(())
        );
        assert_eq!(
            verifier.verify(&verifying_key, &identity_hash, &request, now),
            Err(AuthFailure::ReplayedNonce)
        );

        // Подмена endpoint/метода/тела ломает подпись; /pull-подпись на
        // /push не подходит.
        for (method, path, body) in [
            ("GET", path_owned.as_str(), packet.as_slice()),
            ("POST", "/pull/abc", packet.as_slice()),
            ("POST", path_owned.as_str(), b"other".as_slice()),
        ] {
            let request = AuthRequest {
                method,
                path,
                query: "",
                timestamp,
                nonce: &nonce,
                signature: &signature,
                body,
            };
            let mut verifier = AuthVerifier::new();
            assert_eq!(
                verifier.verify(&verifying_key, &identity_hash, &request, now),
                Err(AuthFailure::InvalidSignature)
            );
        }

        // Изменение query (сюда же относится ?wait=) инвалидирует подпись.
        let request = AuthRequest {
            method: "POST",
            path: &path_owned,
            query: "wait=25",
            timestamp,
            nonce: &nonce,
            signature: &signature,
            body: &packet,
        };
        let mut verifier = AuthVerifier::new();
        assert_eq!(
            verifier.verify(&verifying_key, &identity_hash, &request, now),
            Err(AuthFailure::InvalidSignature)
        );
    }

    #[tokio::test]
    async fn push_401_is_not_retried() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let connections = Arc::new(AtomicUsize::new(0));
        let counter = connections.clone();

        tokio::spawn(async move {
            loop {
                let accept = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
                let Ok(Ok((mut stream, _))) = accept else {
                    break;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = read_request(&mut stream).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\nConnection: close\r\n\r\nunauthorized",
                    )
                    .await;
                let _ = stream.shutdown().await;
            }
        });

        let sender = Sender::with_limits(
            &test_config(format!("http://{}", addr)),
            100,
            Duration::from_millis(10),
        )
        .expect("sender");
        let signing_key = SigningKey::from_bytes(&[43u8; 32]);
        let error = sender
            .send_message(TARGET, &test_packet(), &signing_key)
            .await
            .expect_err("401 must fail");
        assert!(matches!(error, PushError::Unauthorized { .. }));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 1, "401 must not be retried");
    }

    #[tokio::test]
    async fn push_429_backs_off_and_retries() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();

        tokio::spawn(async move {
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let _ = read_request(&mut stream).await;
                let index = counter.fetch_add(1, Ordering::SeqCst);
                let response = if index == 0 {
                    "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 11\r\nConnection: close\r\n\r\nrate limited"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let sender = Sender::with_limits(
            &test_config(format!("http://{}", addr)),
            100,
            Duration::from_millis(10),
        )
        .expect("sender");
        let signing_key = SigningKey::from_bytes(&[44u8; 32]);
        sender
            .send_message(TARGET, &test_packet(), &signing_key)
            .await
            .expect("retry after 429 must succeed");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn push_rate_limit_throttles_per_room() {
        let start = Instant::now();
        let mut limiter = PushRateLimiter::new(2);

        assert_eq!(limiter.delay_until_allowed("room-a", start), Duration::ZERO);
        assert_eq!(limiter.delay_until_allowed("room-a", start), Duration::ZERO);
        assert!(
            limiter.delay_until_allowed("room-a", start) > Duration::ZERO,
            "third push in the same instant must be delayed"
        );
        // Другая комната имеет собственный bucket.
        assert_eq!(limiter.delay_until_allowed("room-b", start), Duration::ZERO);
        // После паузы токен восстанавливается.
        assert_eq!(
            limiter.delay_until_allowed("room-a", start + Duration::from_millis(600)),
            Duration::ZERO
        );
    }

    #[tokio::test]
    async fn invalid_packet_is_rejected_before_any_network() {
        let sender = Sender::new(&test_config("http://127.0.0.1:1".to_string())).expect("sender");
        let signing_key = SigningKey::from_bytes(&[45u8; 32]);
        let error = sender
            .send_message(TARGET, b"short", &signing_key)
            .await
            .expect_err("short packet");
        assert!(matches!(error, PushError::Protocol(_)));
    }

    #[tokio::test]
    async fn upload_file_does_not_send_file_name_header() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test server");
        let addr = listener.local_addr().expect("server address");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let request = read_request(&mut stream).await;

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
            String::from_utf8_lossy(&request).to_ascii_lowercase()
        });

        let config = Config {
            file_server_url: format!("http://{}", addr),
            ..Config::default()
        };
        let sender = Sender::new(&config).expect("sender");
        let signing_key = SigningKey::from_bytes(&[46u8; 32]);
        let hash = sender
            .upload_file(b"encrypted envelope", &signing_key)
            .await
            .expect("upload");
        assert_eq!(hash.len(), 64);

        let headers = server.await.expect("server task");
        let forbidden = format!("x-{}-name", "file");
        assert!(!headers.contains(&forbidden), "headers: {}", headers);
    }

    const UPLOAD_HASH: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn upload_config(addr: std::net::SocketAddr) -> Config {
        Config {
            file_server_url: format!("http://{}", addr),
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn upload_success_body_at_limit_is_accepted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        // Хеш + whitespace ровно до MAX_UPLOAD_HASH_BODY байт.
        let body = format!(
            "{}{}",
            UPLOAD_HASH,
            " ".repeat(MAX_UPLOAD_HASH_BODY - UPLOAD_HASH.len())
        );
        assert_eq!(body.len(), MAX_UPLOAD_HASH_BODY);

        let payload = body.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = read_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        let sender = Sender::new(&upload_config(addr)).expect("sender");
        let signing_key = SigningKey::from_bytes(&[47u8; 32]);
        let hash = sender
            .upload_file(b"encrypted envelope", &signing_key)
            .await
            .expect("body of exactly the limit is allowed");
        assert_eq!(hash, UPLOAD_HASH);
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn upload_success_body_over_limit_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let body = format!(
            "{}{}",
            UPLOAD_HASH,
            " ".repeat(MAX_UPLOAD_HASH_BODY + 1 - UPLOAD_HASH.len())
        );
        assert_eq!(body.len(), MAX_UPLOAD_HASH_BODY + 1);

        let payload = body.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = read_request(&mut stream).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        let sender = Sender::new(&upload_config(addr)).expect("sender");
        let signing_key = SigningKey::from_bytes(&[48u8; 32]);
        let error = sender
            .upload_file(b"encrypted envelope", &signing_key)
            .await
            .expect_err("body over the limit must be rejected");
        assert!(
            format!("{}", error).contains("payload too large"),
            "unexpected error: {}",
            error
        );
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn upload_chunked_endless_body_is_rejected() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let written = Arc::new(AtomicUsize::new(0));
        let counter = written.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _ = read_request(&mut stream).await;
            if stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await
                .is_err()
            {
                return;
            }

            let chunk = vec![b'a'; 64 * 1024];
            let mut frame = Vec::with_capacity(chunk.len() + 16);
            frame.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            frame.extend_from_slice(&chunk);
            frame.extend_from_slice(b"\r\n");

            // Никогда не завершаем поток: клиент обязан оборвать чтение по
            // лимиту, а не накапливать тело до OOM.
            for _ in 0..4096 {
                if stream.write_all(&frame).await.is_err() {
                    break;
                }
                counter.fetch_add(frame.len(), Ordering::SeqCst);
            }
            let _ = stream.shutdown().await;
        });

        let sender = Sender::new(&upload_config(addr)).expect("sender");
        let signing_key = SigningKey::from_bytes(&[49u8; 32]);
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            sender.upload_file(b"encrypted envelope", &signing_key),
        )
        .await
        .expect("endless body must not hang")
        .expect_err("endless body must be rejected");
        assert!(
            format!("{}", error).contains("payload too large"),
            "unexpected error: {}",
            error
        );

        server.await.expect("server task");
        assert!(
            written.load(Ordering::SeqCst) < 4 * 1024 * 1024,
            "client kept reading past the limit instead of closing: {} bytes written",
            written.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn upload_request_carries_canonical_signature() {
        use crate::network::auth::{AuthFailure, AuthRequest, AuthVerifier};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (request_sender, request_receiver) = tokio::sync::oneshot::channel();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let raw = read_request(&mut stream).await;
            let _ = request_sender.send(raw);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                UPLOAD_HASH.len(),
                UPLOAD_HASH
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        let sender = Sender::new(&upload_config(addr)).expect("sender");
        let signing_key = SigningKey::from_bytes(&[50u8; 32]);
        let payload = b"encrypted envelope";
        let hash = sender
            .upload_file(payload, &signing_key)
            .await
            .expect("upload");
        assert_eq!(hash, UPLOAD_HASH);

        let raw = request_receiver.await.expect("captured request");
        let (method, path, query, headers, body) = split_request(&raw);
        assert_eq!(method, "POST");
        assert_eq!(path, "/upload");
        assert!(query.is_empty());
        assert_eq!(body.as_slice(), payload.as_slice());

        let identity_hash = hash_ed25519_public(signing_key.verifying_key().as_bytes());
        assert_eq!(
            headers.get("x-auth-identity").map(String::as_str),
            Some(identity_hash.as_str())
        );
        assert_eq!(
            headers.get("x-identity-key").map(String::as_str),
            Some(hex::encode(signing_key.verifying_key().as_bytes()).as_str())
        );

        let timestamp: i64 = headers
            .get("x-auth-timestamp")
            .expect("timestamp")
            .parse()
            .expect("timestamp number");
        let nonce = headers.get("x-auth-nonce").expect("nonce").clone();
        let signature = headers.get("x-auth-signature").expect("signature").clone();
        let now = chrono::Utc::now().timestamp();
        let verifying_key = signing_key.verifying_key();

        let mut verifier = AuthVerifier::new();
        let request = AuthRequest {
            method: "POST",
            path: "/upload",
            query: "",
            timestamp,
            nonce: &nonce,
            signature: &signature,
            body: payload,
        };
        assert_eq!(
            verifier.verify(&verifying_key, &identity_hash, &request, now),
            Ok(())
        );
        assert_eq!(
            verifier.verify(&verifying_key, &identity_hash, &request, now),
            Err(AuthFailure::ReplayedNonce)
        );

        // Подпись привязана к endpoint и телу: /upload-подпись нельзя
        // переиспользовать для скачивания или подменить байты конверта.
        for (path, body) in [
            ("/download/abc", payload.as_slice()),
            ("/upload", b"other".as_slice()),
        ] {
            let mut verifier = AuthVerifier::new();
            let request = AuthRequest {
                method: "POST",
                path,
                query: "",
                timestamp,
                nonce: &nonce,
                signature: &signature,
                body,
            };
            assert_eq!(
                verifier.verify(&verifying_key, &identity_hash, &request, now),
                Err(AuthFailure::InvalidSignature)
            );
        }

        server.await.expect("server task");
    }

    /// Серверной части нет в репозитории, поэтому здесь эталонная проверка
    /// тем же [`AuthVerifier`]: подписанный `/upload` принимается, а запрос
    /// без подписи получает `401` (L-6). Сам клиент неподписанных запросов
    /// файлового API не отправляет.
    #[tokio::test]
    async fn unsigned_upload_is_rejected_with_401_by_reference_verifier() {
        use crate::network::auth::{AuthRequest, AuthVerifier};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let signing_key = SigningKey::from_bytes(&[51u8; 32]);
        let verifying_key = signing_key.verifying_key();

        let server = tokio::spawn(async move {
            let mut verifier = AuthVerifier::new();
            for request_index in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let raw = read_request(&mut stream).await;
                let (method, path, query, headers, body) = split_request(&raw);

                let identity = headers
                    .get("x-auth-identity")
                    .cloned()
                    .unwrap_or_default();
                let timestamp = headers
                    .get("x-auth-timestamp")
                    .and_then(|value| value.parse::<i64>().ok());
                let nonce = headers.get("x-auth-nonce").cloned().unwrap_or_default();
                let signature = headers.get("x-auth-signature").cloned().unwrap_or_default();

                let accepted = timestamp.is_some_and(|timestamp| {
                    let request = AuthRequest {
                        method: &method,
                        path: &path,
                        query: &query,
                        timestamp,
                        nonce: &nonce,
                        signature: &signature,
                        body: &body,
                    };
                    verifier
                        .verify(&verifying_key, &identity, &request, chrono::Utc::now().timestamp())
                        .is_ok()
                });

                let response = if accepted {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        UPLOAD_HASH.len(),
                        UPLOAD_HASH
                    )
                } else {
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\nConnection: close\r\n\r\nunauthorized".to_string()
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;

                assert_eq!(request_index == 0, accepted);
            }
        });

        let sender = Sender::new(&upload_config(addr)).expect("sender");
        let hash = sender
            .upload_file(b"encrypted envelope", &signing_key)
            .await
            .expect("signed upload must be accepted");
        assert_eq!(hash, UPLOAD_HASH);

        let unsigned = reqwest::Client::new()
            .post(format!("http://{}/upload", addr))
            .body("unsigned envelope")
            .send()
            .await
            .expect("unsigned upload");
        assert_eq!(unsigned.status().as_u16(), 401);
        assert!(
            unsigned.text().await.unwrap_or_default().contains("unauthorized"),
            "401 body must stay opaque"
        );

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn oversize_upload_is_rejected_before_any_network() {
        // Порт 1 заведомо недоступен: если бы проверка размера стояла после
        // отправки, ошибка была бы транспортной, а не «file too large».
        let config = Config {
            file_server_url: "http://127.0.0.1:1".to_string(),
            ..Config::default()
        };
        let sender = Sender::new(&config).expect("sender");
        let signing_key = SigningKey::from_bytes(&[52u8; 32]);
        let payload = vec![0u8; MAX_UPLOAD_SIZE + 1];

        let error = sender
            .upload_file(&payload, &signing_key)
            .await
            .expect_err("oversize upload must be rejected locally");
        assert!(
            format!("{}", error).contains("file too large"),
            "unexpected error: {}",
            error
        );
    }
}
