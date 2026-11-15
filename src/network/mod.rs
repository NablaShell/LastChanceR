// src/network/mod.rs
pub mod auth;
pub mod config;
pub mod listener;
pub mod routing;
pub mod sender;

pub use config::Config;
pub use listener::Listener;
pub use routing::{InboundRouter, Route, RoutingError, RoutingStats};
pub use sender::Sender;

use anyhow::{anyhow, Result};
use reqwest::Client;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Лимиты недоверенных ответов (M-2).
//
// Значения — стартовые и зафиксированы здесь, чтобы клиент, парсер и тесты
// использовали одну политику. Границы включительные: тело ровно `MAX_*`
// байт допустимо, `MAX_* + 1` — уже ошибка.
// ---------------------------------------------------------------------------

/// Максимальный размер multipart-ответа `/pull` (сообщения).
pub const MAX_MESSAGE_BODY: usize = 8 * 1024 * 1024; // 8 MiB
/// Максимальный размер скачиваемого файла (до расшифровки).
///
/// Равен максимальному размеру файлового конверта: скачивать больше, чем
/// клиент способен принять и расшифровать, бессмысленно (L-6). Лимит
/// применяется к телу ответа; HTTP-заголовки в него не входят.
pub const MAX_FILE_BODY: usize = crate::crypto::FILE_MAX_ENVELOPE;
/// Максимум частей в одном multipart-ответе.
pub const MAX_MULTIPART_PARTS: usize = 16;
/// Максимум заголовков одной части.
pub const MAX_MULTIPART_HEADERS: usize = 32;
/// Максимум байт заголовков одной части (включая CRLF).
pub const MAX_MULTIPART_HEADER_BYTES: usize = 8 * 1024;
/// Максимум длины boundary (RFC 2046 рекомендует не более 70).
pub const MAX_MULTIPART_BOUNDARY: usize = 200;
/// Тело ошибки (401/4xx/5xx) читаем с маленьким лимитом.
pub const MAX_ERROR_BODY: usize = 64 * 1024;
/// Таймаут на всё тело ответа, а не на отдельный chunk.
pub const BODY_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Создаёт HTTP-клиент с общим таймаутом и (опционально) внешним прокси.
///
/// Адрес прокси нормализуется здесь же, поэтому клиент всегда получает
/// `socks5h://` вместо `socks5://` и не резолвит DNS мимо прокси.
pub(crate) fn build_http_client(timeout: Duration, proxy_url: Option<&str>) -> Result<Client> {
    let mut builder = Client::builder()
        .timeout(timeout)
        .pool_max_idle_per_host(10);

    if let Some(url) = proxy_url.and_then(config::normalize_proxy_url) {
        let proxy = reqwest::Proxy::all(&url)
            .map_err(|e| anyhow!("invalid proxy URL {:?}: {}", url, e))?;
        builder = builder.proxy(proxy);
    }

    builder
        .build()
        .map_err(|e| anyhow!("failed to create HTTP client: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L-6: клиент не должен принимать по `/download` больше, чем способен
    /// расшифровать. Верхняя граница тела совпадает с размером конверта.
    #[test]
    fn file_body_limit_matches_file_envelope_limit() {
        assert_eq!(MAX_FILE_BODY, crate::crypto::FILE_MAX_ENVELOPE);
        const {
            assert!(
                MAX_FILE_BODY < 256 * 1024 * 1024,
                "the old 256 MiB limit would download envelopes the client cannot accept"
            );
        }
    }
}
