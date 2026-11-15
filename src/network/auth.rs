// src/network/auth.rs
//!
//! Каноническая подпись HTTP-запроса (H-4).
//!
//! Подписывается не пара `timestamp + identity_hash`, а весь запрос:
//!
//! ```text
//! METHOD \n PATH \n CANONICAL_QUERY \n TIMESTAMP \n NONCE \n SHA256(body)
//! ```
//!
//! Это привязывает подпись к конкретному endpoint, query, телу и одноразовому
//! nonce. Серверная часть в комплект не входит, поэтому здесь же лежит
//! переиспользуемый [`AuthVerifier`] с nonce-кэшем и аудитом отказов.

use crate::identity::hash_ed25519_public;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

/// Заголовки аутентифицированного запроса.
pub const HEADER_IDENTITY: &str = "X-Auth-Identity";
pub const HEADER_TIMESTAMP: &str = "X-Auth-Timestamp";
pub const HEADER_NONCE: &str = "X-Auth-Nonce";
pub const HEADER_SIGNATURE: &str = "X-Auth-Signature";

/// Допустимое опоздание запроса (timestamp в прошлом).
pub const TIMESTAMP_WINDOW_SECS: i64 = 60;
/// Допустимое опережение запроса (расхождение часов в другую сторону).
pub const TIMESTAMP_SKEW_SECS: i64 = 30;
/// TTL nonce-записи: окно + запас, чтобы nonce не освободился раньше окна.
pub const NONCE_TTL_SECS: u64 = (TIMESTAMP_WINDOW_SECS + TIMESTAMP_SKEW_SECS) as u64 + 60;
/// Ёмкость nonce-кэша на одну identity.
pub const MAX_NONCES_PER_IDENTITY: usize = 1024;

/// Длина nonce в байтах CSPRNG-энтропии.
pub const NONCE_BYTES: usize = 24;
/// Минимальная допустимая длина nonce после base64url-декодирования.
pub const MIN_NONCE_BYTES: usize = 16;
/// Максимальная допустимая длина nonce после base64url-декодирования.
pub const MAX_NONCE_BYTES: usize = 32;

/// Одинаковое тело ответа для всех отказов аутентификации.
pub const AUTH_REJECTED_BODY: &str = "unauthorized";

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// `SHA256(body)` в нижнем hex.
pub fn body_hash(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Строит канонический конверт запроса в UTF-8.
pub fn canonical_request(
    method: &str,
    path: &str,
    query: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let method = method.to_ascii_uppercase();
    let path = canonical_path(path);
    let query = canonical_query(query);
    let envelope = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        path,
        query,
        timestamp,
        nonce,
        body_hash(body)
    );
    envelope.into_bytes()
}

/// Путь без query, с ведущим `/` и без завершающего `/` (кроме корня).
fn canonical_path(path: &str) -> String {
    let path = path.split('?').next().unwrap_or("");
    let mut path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    while path.len() > 1 && path.ends_with('/') {
        path.pop();
    }
    path
}

/// Query-пары сортируются по ключу, затем по значению. Percent-encoding
/// сохраняется ровно в том виде, в котором пришёл в запросе.
fn canonical_query(query: &str) -> String {
    let query = query.strip_prefix('?').unwrap_or(query);
    if query.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<(&str, &str)> = query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| part.split_once('=').unwrap_or((part, "")))
        .collect();
    pairs.sort_by(|left, right| left.0.cmp(right.0).then_with(|| left.1.cmp(right.1)));

    pairs
        .into_iter()
        .map(|(key, value)| format!("{}={}", key, value))
        .collect::<Vec<_>>()
        .join("&")
}

/// Генерирует nonce: 24 случайных байта в base64url без padding.
pub fn generate_nonce() -> String {
    let mut bytes = [0u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut bytes);
    base64url_encode(&bytes)
}

/// Подписывает канонический конверт и возвращает `base64url(sig)`.
pub fn sign_request(
    signing_key: &SigningKey,
    method: &str,
    path: &str,
    query: &str,
    timestamp: i64,
    nonce: &str,
    body: &[u8],
) -> String {
    let canonical = canonical_request(method, path, query, timestamp, nonce, body);
    let signature = signing_key.sign(&canonical);
    base64url_encode(&signature.to_bytes())
}

/// Параметры проверяемого HTTP-запроса.
///
/// `path` и `query` передаются отдельно: сервер должен брать их из
/// фактического запроса, а не из заголовков.
pub struct AuthRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a str,
    pub timestamp: i64,
    pub nonce: &'a str,
    pub signature: &'a str,
    pub body: &'a [u8],
}

/// Причина отказа. Наружу отдаётся одинаковое тело, причина идёт в аудит.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    /// `identity_hash` не соответствует предъявленному ключу.
    InvalidIdentity,
    /// Nonce не base64url или его длина вне 16..=32 байт.
    MalformedNonce,
    /// Timestamp вне окна `[now - WINDOW, now + SKEW]`.
    TimestampOutOfWindow,
    /// Подпись не сходится с каноническим конвертом.
    InvalidSignature,
    /// Nonce уже использован этой identity.
    ReplayedNonce,
    /// Кэш identity заполнен: fail-closed.
    NonceCacheFull,
}

impl AuthFailure {
    /// Внутренняя причина для аудита (никогда не уходит клиенту).
    pub fn reason(self) -> &'static str {
        match self {
            AuthFailure::InvalidIdentity => "invalid_identity",
            AuthFailure::MalformedNonce => "malformed_nonce",
            AuthFailure::TimestampOutOfWindow => "timestamp_out_of_window",
            AuthFailure::InvalidSignature => "invalid_signature",
            AuthFailure::ReplayedNonce => "replayed_nonce",
            AuthFailure::NonceCacheFull => "nonce_cache_full",
        }
    }

    /// HTTP-статус: переполнение кэша — это отказ доступности, остальное 401.
    pub fn status(self) -> u16 {
        match self {
            AuthFailure::NonceCacheFull => 503,
            _ => 401,
        }
    }
}

/// Ошибка вставки в nonce-кэш.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceCacheError {
    Replayed,
    Full,
}

struct NonceEntry {
    nonce: String,
    expires_at: Instant,
}

/// In-memory nonce-кэш: `identity_hash -> FIFO записей с TTL`.
///
/// Запись добавляется только после успешной проверки подписи. Истёкшие
/// записи удаляются лениво при вставке; [`NonceCache::purge_expired`] можно
/// вызывать и из фонового цикла сервера.
pub struct NonceCache {
    entries: HashMap<String, VecDeque<NonceEntry>>,
    capacity_per_identity: usize,
    ttl: Duration,
}

impl NonceCache {
    pub fn new(capacity_per_identity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity_per_identity,
            ttl,
        }
    }

    /// Регистрирует nonce. При переполнении возвращает [`NonceCacheError::Full`]
    /// (fail-closed), не вытесняя старые записи.
    pub fn insert(
        &mut self,
        identity_hash: &str,
        nonce: &str,
        now: Instant,
    ) -> Result<(), NonceCacheError> {
        let entries = self.entries.entry(identity_hash.to_string()).or_default();
        while entries
            .front()
            .map(|entry| entry.expires_at <= now)
            .unwrap_or(false)
        {
            entries.pop_front();
        }

        // Replay важнее переполнения: существующий nonce не должен
        // превращаться в 503 только потому, что кэш уже полон.
        if entries.iter().any(|entry| entry.nonce == nonce) {
            return Err(NonceCacheError::Replayed);
        }
        if entries.len() >= self.capacity_per_identity {
            return Err(NonceCacheError::Full);
        }

        entries.push_back(NonceEntry {
            nonce: nonce.to_string(),
            expires_at: now + self.ttl,
        });
        Ok(())
    }

    pub fn nonce_count(&self, identity_hash: &str) -> usize {
        self.entries
            .get(identity_hash)
            .map(VecDeque::len)
            .unwrap_or(0)
    }

    pub fn total_nonce_count(&self) -> usize {
        self.entries.values().map(VecDeque::len).sum()
    }

    /// Удаляет все истёкшие записи. Вызывать можно периодически.
    pub fn purge_expired(&mut self, now: Instant) {
        for entries in self.entries.values_mut() {
            while entries
                .front()
                .map(|entry| entry.expires_at <= now)
                .unwrap_or(false)
            {
                entries.pop_front();
            }
        }
        self.entries.retain(|_, entries| !entries.is_empty());
    }
}

/// Серверный верификатор запросов.
///
/// Сервер сам находит [`VerifyingKey`] по `identity_hash` из списка известных
/// контактов, затем вызывает [`AuthVerifier::verify`]. Одинаковое тело ответа
/// для всех отказов: [`AUTH_REJECTED_BODY`].
pub struct AuthVerifier {
    cache: NonceCache,
    rejected: u64,
}

impl Default for AuthVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthVerifier {
    pub fn new() -> Self {
        Self::with_cache(NonceCache::new(
            MAX_NONCES_PER_IDENTITY,
            Duration::from_secs(NONCE_TTL_SECS),
        ))
    }

    pub fn with_cache(cache: NonceCache) -> Self {
        Self {
            cache,
            rejected: 0,
        }
    }

    /// Проверяет запрос, используя текущее время.
    pub fn verify(
        &mut self,
        verifying_key: &VerifyingKey,
        identity_hash: &str,
        request: &AuthRequest<'_>,
        now_unix: i64,
    ) -> Result<(), AuthFailure> {
        self.verify_at(verifying_key, identity_hash, request, now_unix, Instant::now())
    }

    /// То же самое с явным `Instant` для тестов TTL.
    pub fn verify_at(
        &mut self,
        verifying_key: &VerifyingKey,
        identity_hash: &str,
        request: &AuthRequest<'_>,
        now_unix: i64,
        now: Instant,
    ) -> Result<(), AuthFailure> {
        match self.check(verifying_key, identity_hash, request, now_unix, now) {
            Ok(()) => {
                log::debug!(
                    "[AUTH] accept identity={} method={} path={}",
                    identity_hash,
                    request.method,
                    request.path
                );
                Ok(())
            }
            Err(failure) => {
                self.rejected += 1;
                // Сигнатура и тело в лог не попадают.
                log::warn!(
                    "[AUTH] reject identity={} nonce={} method={} path={} reason={}",
                    identity_hash,
                    request.nonce,
                    request.method,
                    request.path,
                    failure.reason()
                );
                Err(failure)
            }
        }
    }

    fn check(
        &mut self,
        verifying_key: &VerifyingKey,
        identity_hash: &str,
        request: &AuthRequest<'_>,
        now_unix: i64,
        now: Instant,
    ) -> Result<(), AuthFailure> {
        let expected_hash = hash_ed25519_public(verifying_key.as_bytes());
        if !identity_hash.eq_ignore_ascii_case(&expected_hash) {
            return Err(AuthFailure::InvalidIdentity);
        }

        let nonce_len = base64url_decode(request.nonce)
            .map(|bytes| bytes.len())
            .ok_or(AuthFailure::MalformedNonce)?;
        if !(MIN_NONCE_BYTES..=MAX_NONCE_BYTES).contains(&nonce_len) {
            return Err(AuthFailure::MalformedNonce);
        }

        let earliest = now_unix.saturating_sub(TIMESTAMP_WINDOW_SECS);
        let latest = now_unix.saturating_add(TIMESTAMP_SKEW_SECS);
        if request.timestamp < earliest || request.timestamp > latest {
            return Err(AuthFailure::TimestampOutOfWindow);
        }

        let signature_bytes =
            base64url_decode(request.signature).ok_or(AuthFailure::InvalidSignature)?;
        let signature_bytes: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthFailure::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);

        let canonical = canonical_request(
            request.method,
            request.path,
            request.query,
            request.timestamp,
            request.nonce,
            request.body,
        );
        verifying_key
            .verify(&canonical, &signature)
            .map_err(|_| AuthFailure::InvalidSignature)?;

        // Вставка только после всех проверок: мусорные nonce не забивают кэш.
        self.cache
            .insert(identity_hash, request.nonce, now)
            .map_err(|error| match error {
                NonceCacheError::Replayed => AuthFailure::ReplayedNonce,
                NonceCacheError::Full => AuthFailure::NonceCacheFull,
            })
    }

    pub fn nonce_count(&self, identity_hash: &str) -> usize {
        self.cache.nonce_count(identity_hash)
    }

    pub fn total_nonce_count(&self) -> usize {
        self.cache.total_nonce_count()
    }

    /// Сколько отказов уже записано в аудит (метрика для тестов и мониторинга).
    pub fn rejection_count(&self) -> u64 {
        self.rejected
    }
}

/// base64url без padding.
fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as u32;
        let second = chunk.get(1).copied().unwrap_or(0) as u32;
        let third = chunk.get(2).copied().unwrap_or(0) as u32;
        let combined = (first << 16) | (second << 8) | third;

        out.push(BASE64URL_ALPHABET[((combined >> 18) & 0x3f) as usize] as char);
        out.push(BASE64URL_ALPHABET[((combined >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(BASE64URL_ALPHABET[((combined >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL_ALPHABET[(combined & 0x3f) as usize] as char);
        }
    }
    out
}

/// base64url без padding. `None` для недопустимого алфавита/length%4 == 1.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    if input.len() % 4 == 1 {
        return None;
    }

    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32;

        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    // Неиспользованные хвостовые биты канонической строки обязаны быть нулями.
    if buffer != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: i64 = 1_700_000_000;

    fn test_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn identity_hash(signing_key: &SigningKey) -> String {
        hash_ed25519_public(signing_key.verifying_key().as_bytes())
    }

    fn request<'a>(
        method: &'a str,
        path: &'a str,
        query: &'a str,
        timestamp: i64,
        nonce: &'a str,
        signature: &'a str,
        body: &'a [u8],
    ) -> AuthRequest<'a> {
        AuthRequest {
            method,
            path,
            query,
            timestamp,
            nonce,
            signature,
            body,
        }
    }

    fn signed_request(
        signing_key: &SigningKey,
        method: &str,
        path: &str,
        query: &str,
        timestamp: i64,
        nonce: &str,
        body: &[u8],
    ) -> String {
        sign_request(
            signing_key,
            method,
            path,
            query,
            timestamp,
            nonce,
            body,
        )
    }

    #[test]
    fn canonical_request_is_stable_and_binds_every_field() {
        let base = canonical_request("get", "/pull/abc/", "b=2&a=1", TS, "nonce", b"");
        let reordered = canonical_request("GET", "/pull/abc", "a=1&b=2", TS, "nonce", b"");
        assert_eq!(base, reordered);

        let expected = format!(
            "GET\n/pull/abc\na=1&b=2\n{}\nnonce\n{}",
            TS,
            body_hash(b"")
        );
        assert_eq!(String::from_utf8(base.clone()).unwrap(), expected);

        for different in [
            canonical_request("POST", "/pull/abc", "a=1&b=2", TS, "nonce", b""),
            canonical_request("GET", "/send/abc", "a=1&b=2", TS, "nonce", b""),
            canonical_request("GET", "/pull/abc", "a=2&b=2", TS, "nonce", b""),
            canonical_request("GET", "/pull/abc", "a=1&b=2", TS + 1, "nonce", b""),
            canonical_request("GET", "/pull/abc", "a=1&b=2", TS, "nonce2", b""),
            canonical_request("GET", "/pull/abc", "a=1&b=2", TS, "nonce", b"x"),
        ] {
            assert_ne!(base, different);
        }
    }

    #[test]
    fn canonical_query_preserves_encoding_and_handles_empty_query() {
        let encoded = canonical_request("GET", "/pull/x", "b=%2F&a=%20", TS, "n", b"");
        let text = String::from_utf8(encoded).unwrap();
        assert!(text.contains("\na=%20&b=%2F\n"));

        let empty = canonical_request("GET", "/pull/x", "", TS, "n", b"");
        let text = String::from_utf8(empty).unwrap();
        assert_eq!(text, format!("GET\n/pull/x\n\n{}\nn\n{}", TS, body_hash(b"")));
    }

    #[test]
    fn base64url_round_trips_and_rejects_bad_input() {
        for len in 0..12 {
            let bytes: Vec<u8> = (0..len).map(|value| value as u8 * 7).collect();
            let encoded = base64url_encode(&bytes);
            assert!(!encoded.contains('='));
            assert_eq!(base64url_decode(&encoded).unwrap(), bytes);
        }
        assert!(base64url_decode("abc=").is_none());
        assert!(base64url_decode("a").is_none());
        assert!(base64url_decode("ab cd").is_none());
    }

    #[test]
    fn generated_nonces_are_24_random_base64url_bytes() {
        let first = generate_nonce();
        let second = generate_nonce();
        assert_ne!(first, second);
        assert!(!first.contains('='));
        assert_eq!(base64url_decode(&first).unwrap().len(), NONCE_BYTES);
    }

    #[test]
    fn valid_get_is_accepted_and_nonce_is_cached() {
        let signing_key = test_key(1);
        let hash = identity_hash(&signing_key);
        let nonce = generate_nonce();
        let signature = signed_request(&signing_key, "GET", "/pull/abc", "wait=25", TS, &nonce, b"");

        let mut verifier = AuthVerifier::new();
        let request = request("GET", "/pull/abc", "wait=25", TS, &nonce, &signature, b"");
        assert_eq!(
            verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
            Ok(())
        );
        assert_eq!(verifier.nonce_count(&hash), 1);
        assert_eq!(verifier.rejection_count(), 0);
    }

    #[test]
    fn replay_is_rejected_and_audited() {
        let signing_key = test_key(2);
        let hash = identity_hash(&signing_key);
        let nonce = generate_nonce();
        let signature = signed_request(&signing_key, "GET", "/pull/abc", "wait=25", TS, &nonce, b"");
        let request = request("GET", "/pull/abc", "wait=25", TS, &nonce, &signature, b"");

        let mut verifier = AuthVerifier::new();
        verifier
            .verify(&signing_key.verifying_key(), &hash, &request, TS)
            .unwrap();
        assert_eq!(
            verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
            Err(AuthFailure::ReplayedNonce)
        );
        assert_eq!(verifier.nonce_count(&hash), 1);
        assert_eq!(verifier.rejection_count(), 1);
    }

    #[test]
    fn timestamp_outside_window_is_rejected() {
        let signing_key = test_key(3);
        let hash = identity_hash(&signing_key);
        let mut verifier = AuthVerifier::new();

        for timestamp in [TS - TIMESTAMP_WINDOW_SECS - 1, TS + TIMESTAMP_SKEW_SECS + 1] {
            let nonce = generate_nonce();
            let signature =
                signed_request(&signing_key, "GET", "/pull/abc", "", timestamp, &nonce, b"");
            let request = request("GET", "/pull/abc", "", timestamp, &nonce, &signature, b"");
            assert_eq!(
                verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
                Err(AuthFailure::TimestampOutOfWindow)
            );
        }
        assert_eq!(verifier.total_nonce_count(), 0);
    }

    #[test]
    fn timestamp_window_boundaries_are_inclusive() {
        let signing_key = test_key(4);
        let hash = identity_hash(&signing_key);
        let mut verifier = AuthVerifier::new();

        for timestamp in [TS - TIMESTAMP_WINDOW_SECS, TS + TIMESTAMP_SKEW_SECS] {
            let nonce = generate_nonce();
            let signature =
                signed_request(&signing_key, "GET", "/pull/abc", "", timestamp, &nonce, b"");
            let request = request("GET", "/pull/abc", "", timestamp, &nonce, &signature, b"");
            assert_eq!(
                verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
                Ok(())
            );
        }
    }

    #[test]
    fn tampered_method_path_query_or_body_is_rejected() {
        let signing_key = test_key(5);
        let hash = identity_hash(&signing_key);
        let nonce = generate_nonce();
        let body = b"payload";
        let signature =
            signed_request(&signing_key, "POST", "/send/abc", "wait=25", TS, &nonce, body);
        let mut verifier = AuthVerifier::new();

        for request in [
            request("GET", "/send/abc", "wait=25", TS, &nonce, &signature, body),
            request("POST", "/pull/abc", "wait=25", TS, &nonce, &signature, body),
            request("POST", "/send/abc", "wait=10", TS, &nonce, &signature, body),
            request("POST", "/send/abc", "wait=25", TS, &nonce, &signature, b"other"),
        ] {
            assert_eq!(
                verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
                Err(AuthFailure::InvalidSignature)
            );
        }
        assert_eq!(verifier.total_nonce_count(), 0);
    }

    #[test]
    fn wait_parameter_change_invalidates_pull_signature() {
        let signing_key = test_key(6);
        let hash = identity_hash(&signing_key);
        let nonce = generate_nonce();
        let signature = signed_request(&signing_key, "GET", "/pull/abc", "wait=25", TS, &nonce, b"");
        let request = request("GET", "/pull/abc", "wait=10", TS, &nonce, &signature, b"");

        let mut verifier = AuthVerifier::new();
        assert_eq!(
            verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
            Err(AuthFailure::InvalidSignature)
        );
    }

    #[test]
    fn signature_for_pull_does_not_work_on_send() {
        let signing_key = test_key(7);
        let hash = identity_hash(&signing_key);
        let nonce = generate_nonce();
        let signature = signed_request(&signing_key, "GET", "/pull/abc", "wait=25", TS, &nonce, b"");
        let request = request("POST", "/send/abc", "wait=25", TS, &nonce, &signature, b"");

        let mut verifier = AuthVerifier::new();
        assert_eq!(
            verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
            Err(AuthFailure::InvalidSignature)
        );
    }

    #[test]
    fn wrong_identity_hash_or_signing_key_is_rejected() {
        let signing_key = test_key(8);
        let other_key = test_key(9);
        let nonce = generate_nonce();
        let signature = signed_request(&signing_key, "GET", "/pull/abc", "", TS, &nonce, b"");
        let request = request("GET", "/pull/abc", "", TS, &nonce, &signature, b"");
        let mut verifier = AuthVerifier::new();

        assert_eq!(
            verifier.verify(
                &signing_key.verifying_key(),
                &identity_hash(&other_key),
                &request,
                TS
            ),
            Err(AuthFailure::InvalidIdentity)
        );
        assert_eq!(
            verifier.verify(
                &other_key.verifying_key(),
                &identity_hash(&signing_key),
                &request,
                TS
            ),
            Err(AuthFailure::InvalidIdentity)
        );
    }

    #[test]
    fn invalid_signatures_do_not_pollute_the_nonce_cache() {
        let signing_key = test_key(10);
        let hash = identity_hash(&signing_key);
        let bogus_signature = base64url_encode(&[0u8; 64]);
        let mut verifier = AuthVerifier::new();

        for _ in 0..10 {
            let nonce = generate_nonce();
            let request = request("GET", "/pull/abc", "", TS, &nonce, &bogus_signature, b"");
            assert_eq!(
                verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
                Err(AuthFailure::InvalidSignature)
            );
        }
        assert_eq!(verifier.total_nonce_count(), 0);
        assert_eq!(verifier.rejection_count(), 10);
    }

    #[test]
    fn malformed_nonces_are_rejected_before_caching() {
        let signing_key = test_key(11);
        let hash = identity_hash(&signing_key);
        let signature = base64url_encode(&[0u8; 64]);
        let mut verifier = AuthVerifier::new();

        for nonce in ["AAAA", "abc=", &base64url_encode(&[1u8; 33])] {
            let request = request("GET", "/pull/abc", "", TS, nonce, &signature, b"");
            assert_eq!(
                verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
                Err(AuthFailure::MalformedNonce)
            );
        }
        assert_eq!(verifier.total_nonce_count(), 0);
    }

    #[test]
    fn nonce_cache_overflow_fails_closed_and_replay_wins() {
        let start = Instant::now();
        let ttl = Duration::from_secs(NONCE_TTL_SECS);
        let mut cache = NonceCache::new(2, ttl);

        cache.insert("alice", "n1", start).unwrap();
        cache.insert("alice", "n2", start).unwrap();
        assert_eq!(
            cache.insert("alice", "n3", start),
            Err(NonceCacheError::Full)
        );
        assert_eq!(cache.nonce_count("alice"), 2);

        let mut one_slot = NonceCache::new(1, ttl);
        one_slot.insert("bob", "n1", start).unwrap();
        assert_eq!(
            one_slot.insert("bob", "n1", start),
            Err(NonceCacheError::Replayed)
        );
    }

    #[test]
    fn expired_nonce_is_purged_after_ttl() {
        let start = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut cache = NonceCache::new(4, ttl);

        cache.insert("alice", "n1", start).unwrap();
        assert_eq!(
            cache.insert("alice", "n1", start + ttl - Duration::from_millis(1)),
            Err(NonceCacheError::Replayed)
        );
        assert_eq!(cache.insert("alice", "n1", start + ttl), Ok(()));
        assert_eq!(cache.nonce_count("alice"), 1);
    }

    #[test]
    fn purge_expired_drops_empty_identities() {
        let start = Instant::now();
        let ttl = Duration::from_secs(10);
        let mut cache = NonceCache::new(4, ttl);
        cache.insert("alice", "n1", start).unwrap();
        cache.insert("bob", "n2", start).unwrap();

        cache.purge_expired(start + ttl);
        assert_eq!(cache.total_nonce_count(), 0);
    }

    #[test]
    fn expired_nonce_with_stale_timestamp_is_still_rejected() {
        let signing_key = test_key(12);
        let hash = identity_hash(&signing_key);
        let nonce = generate_nonce();
        let signature = signed_request(&signing_key, "GET", "/pull/abc", "", TS, &nonce, b"");
        let request = request("GET", "/pull/abc", "", TS, &nonce, &signature, b"");

        let ttl = Duration::from_secs(10);
        let mut verifier = AuthVerifier::with_cache(NonceCache::new(4, ttl));
        let start = Instant::now();
        verifier
            .verify_at(&signing_key.verifying_key(), &hash, &request, TS, start)
            .unwrap();

        // Nonce уже истёк, но timestamp тоже вне окна: отказ по timestamp,
        // кэш не должен «освободить» запись раньше окна.
        assert_eq!(
            verifier.verify_at(
                &signing_key.verifying_key(),
                &hash,
                &request,
                TS + TIMESTAMP_WINDOW_SECS + TIMESTAMP_SKEW_SECS + 1,
                start + ttl + Duration::from_secs(1)
            ),
            Err(AuthFailure::TimestampOutOfWindow)
        );
    }

    #[test]
    fn empty_body_get_happy_path_and_replay() {
        let signing_key = test_key(13);
        let hash = identity_hash(&signing_key);
        let nonce = generate_nonce();
        let signature = signed_request(&signing_key, "get", "/pull/abc/", "", TS, &nonce, b"");
        let request = request("GET", "/pull/abc", "", TS, &nonce, &signature, b"");

        let mut verifier = AuthVerifier::new();
        assert_eq!(
            verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
            Ok(())
        );
        assert_eq!(
            verifier.verify(&signing_key.verifying_key(), &hash, &request, TS),
            Err(AuthFailure::ReplayedNonce)
        );
    }
}
