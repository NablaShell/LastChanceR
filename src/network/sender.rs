// src/network/sender.rs
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::sync::RwLock;
use std::time::Duration;
use crate::network::Config;

const MAX_UPLOAD_SIZE: usize = 100 * 1024 * 1024; // 100 MB
const ALLOWED_PACKET_SIZES: [usize; 4] = [256, 1024, 4096, 65536];

pub struct Sender {
    client: Client,
    config: RwLock<Config>,
}

impl Sender {
    pub fn new(config: &Config) -> Self {
        // Один клиент на всё; таймаут 120s покрывает upload до 100 MB.
        let client = Client::builder()
            .timeout(Duration::from_secs(120))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_default();

        Self {
            client,
            config: RwLock::new(config.clone()),
        }
    }

    /// Применяет новые сетевые параметры без перезапуска клиента.
    pub fn update_config(&self, config: &Config) -> Result<()> {
        let mut guard = self
            .config
            .write()
            .map_err(|_| anyhow!("конфигурация отправителя недоступна: блокировка повреждена"))?;
        *guard = config.clone();
        Ok(())
    }

    fn current_config(&self) -> Result<Config> {
        self.config
            .read()
            .map(|config| config.clone())
            .map_err(|_| anyhow!("конфигурация отправителя недоступна: блокировка повреждена"))
    }

    pub async fn send_message(&self, target_hash: &str, packet: &[u8]) -> Result<()> {
        if !ALLOWED_PACKET_SIZES.contains(&packet.len()) {
            return Err(anyhow!(
                "invalid packet size {} (allowed: {:?})",
                packet.len(),
                ALLOWED_PACKET_SIZES
            ));
        }

        let config = self.current_config()?;
        let url = format!("{}/push/{}", config.server_url, target_hash);

        let max_retries = 3;
        let base_delay = Duration::from_secs(1);
        let mut last_err: Option<String> = None;

        for attempt in 0..=max_retries {
            let result = self
                .client
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

    pub async fn upload_file(&self, payload: &[u8], file_name: &str) -> Result<String> {
        if payload.is_empty() {
            return Err(anyhow!("empty payload"));
        }
        if payload.len() > MAX_UPLOAD_SIZE {
            return Err(anyhow!(
                "file too large: {} bytes (max 100MB)",
                payload.len()
            ));
        }

        let config = self.current_config()?;
        let url = format!("{}/upload", config.file_server_url);

        let response = self.client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            // Content-Length обязателен (API.md §5.1). body(Bytes) его ставит сам,
            // но явный заголовок защищает от регрессий.
            .header("Content-Length", payload.len().to_string())
            .header("X-File-Name", file_name)
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
                let file_hash = file_hash.trim().to_string();
                if file_hash.is_empty() {
                    return Err(anyhow!("server returned empty file hash"));
                }
                Ok(file_hash)
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
