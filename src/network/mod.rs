// src/network/mod.rs
pub mod config;
pub mod listener;
pub mod sender;

pub use config::Config;
pub use listener::Listener;
pub use sender::Sender;

use anyhow::{anyhow, Result};
use reqwest::Client;
use std::time::Duration;

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
