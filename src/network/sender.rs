// src/network/sender.rs
use anyhow::{anyhow, Result};
use reqwest::Client;
use std::time::Duration;
use crate::network::Config;

pub struct Sender {
    client: Client,
    config: Config,
}

impl Sender {
    pub fn new(config: &Config) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(10)
            .build()
            .unwrap_or_default();
        
        Self {
            client,
            config: config.clone(),
        }
    }
    
    pub async fn send_message(&self, target_hash: &str, packet: &[u8]) -> Result<()> {
        let url = format!("{}/push/{}", self.config.server_url, target_hash);
        
        let max_retries = 3;
        let base_delay = Duration::from_secs(1);
        
        for attempt in 0..=max_retries {
            let response = self.client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header(&self.config.mask_header_name, &self.config.mask_header_value)
                .header("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0")
                .body(packet.to_vec())
                .send()
                .await;
            
            match response {
                Ok(resp) => {
                    let status = resp.status();
                    
                    if status.is_success() {
                        return Ok(());
                    }
                    
                    if status.as_u16() == 429 {
                        // Rate limited
                        if attempt == max_retries {
                            let body = resp.text().await.unwrap_or_default();
                            return Err(anyhow!("rate limited after {} retries: {}", max_retries + 1, body));
                        }
                        
                        let retry_delay = base_delay * 2u32.pow(attempt as u32);
                        log::info!("[SENDER] Rate limited, retrying in {:?} (attempt {}/{})", 
                            retry_delay, attempt + 1, max_retries + 1);
                        
                        tokio::time::sleep(retry_delay).await;
                        continue;
                    }
                    
                    let body = resp.text().await.unwrap_or_default();
                    return Err(anyhow!("server returned {}: {}", status, body));
                }
                Err(e) => {
                    if attempt == max_retries {
                        return Err(anyhow!("request failed after {} retries: {}", max_retries + 1, e));
                    }
                    let delay = base_delay * 2u32.pow(attempt as u32);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        
        Err(anyhow!("unexpected loop exit"))
    }
    
    pub async fn upload_file(&self, payload: &[u8], file_name: &str) -> Result<String> {
        if payload.len() > 100 * 1024 * 1024 {
            return Err(anyhow!("file too large: {} bytes (max 100MB)", payload.len()));
        }
        
        let url = format!("{}/upload", self.config.file_server_url);
        
        let upload_client = Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_default();
        
        let response = upload_client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .header("X-File-Name", file_name)
            .header(&self.config.mask_header_name, &self.config.mask_header_value)
            .header("User-Agent", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:149.0) Gecko/20100101 Firefox/149.0")
            .body(payload.to_vec())
            .send()
            .await
            .map_err(|e| anyhow!("upload request failed: {}", e))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("upload failed: {} - {}", status, body));
        }
        
        let file_hash = response.text()
            .await
            .map_err(|e| anyhow!("read response: {}", e))?;
        
        Ok(file_hash.trim().to_string())
    }
}
