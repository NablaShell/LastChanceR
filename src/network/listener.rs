// src/network/listener.rs
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use reqwest::Client;
use std::time::Duration;
use crate::network::Config;

pub struct Listener {
    client: Client,
    config: Config,
}

impl Listener {
    pub fn new(config: &Config) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(60))
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
        pub_key_hex: &str,
        signing_key: &SigningKey,
    ) -> Result<Vec<Vec<u8>>> {
        use ed25519_dalek::Signer;
        
        let now = chrono::Utc::now().timestamp();
        let message = format!("{}{}", now, identity_hash);
        let signature = signing_key.sign(message.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());
        
        let url = format!("{}/pull/{}", self.config.server_url, identity_hash);
        
        let response = self.client
            .get(&url)
            .header("X-Identity-Key", pub_key_hex)
            .header("X-Timestamp", now.to_string())
            .header("X-Signature", &sig_hex)
            .header(&self.config.mask_header_name, &self.config.mask_header_value)
            .header("Accept", "multipart/form-data")
            .header("User-Agent", "Mozilla/5.0 (X11; Arch Linux; rv:130.0) Gecko/20100101 Firefox/130.0")
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
        
        // Parse multipart response
        let content_type = response.headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        
        if content_type.starts_with("multipart/") {
            // Parse multipart
            let bytes = response.bytes()
                .await
                .map_err(|e| anyhow!("read body: {}", e))?;
            
            // Simple multipart parsing (you might want to use a proper multipart crate)
            self.parse_multipart_response(&bytes)
        } else {
            // Fallback: read as plain binary
            let data = response.bytes()
                .await
                .map_err(|e| anyhow!("read body: {}", e))?;
            
            if data.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![data.to_vec()])
            }
        }
    }
    
    fn parse_multipart_response(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        // Extract boundary from content-type
        let data_str = String::from_utf8_lossy(&data[..data.len().min(1024)]);
        let boundary_marker = "boundary=";
        let boundary = data_str
            .find(boundary_marker)
            .map(|i| &data_str[i + boundary_marker.len()..])
            .and_then(|s| s.split(';').next())
            .and_then(|s| s.split('\r').next())
            .and_then(|s| s.split('\n').next())
            .unwrap_or("");
        
        if boundary.is_empty() {
            return Ok(vec![data.to_vec()]);
        }
        
        let boundary_bytes = format!("--{}", boundary).into_bytes();
        let mut messages = Vec::new();
        let mut pos = 0;
        
        while pos < data.len() {
            // Find boundary
            if let Some(idx) = find_subsequence(&data[pos..], &boundary_bytes) {
                let content_start = pos + idx + boundary_bytes.len();
                
                // Check if this is the end boundary
                if content_start + 2 <= data.len() && &data[content_start..content_start + 2] == b"--" {
                    break;
                }
                
                // Skip headers (until empty line)
                if let Some(header_end) = find_subsequence(&data[content_start..], b"\r\n\r\n") {
                    let content = content_start + header_end + 4;
                    
                    // Find next boundary
                    if let Some(next_boundary) = find_subsequence(&data[content..], &boundary_bytes) {
                        let message_end = content + next_boundary - 2; // -2 for \r\n before boundary
                        if message_end > content {
                            messages.push(data[content..message_end].to_vec());
                        }
                        pos = content + next_boundary;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        Ok(messages)
    }
    
    pub async fn download_file(&self, file_hash: &str) -> Result<Vec<u8>> {
        let url = format!("{}/download/{}", self.config.file_server_url, file_hash);
        
        let response = self.client
            .get(&url)
            .header(&self.config.mask_header_name, &self.config.mask_header_value)
            .header("User-Agent", "Mozilla/5.0 (X11; Arch Linux; rv:130.0) Gecko/20100101 Firefox/130.0")
            .send()
            .await
            .map_err(|e| anyhow!("download request failed: {}", e))?;
        
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("download failed: {} - {}", status, body));
        }
        
        let data = response.bytes()
            .await
            .map_err(|e| anyhow!("read file data: {}", e))?;
        
        Ok(data.to_vec())
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    
    for i in 0..=haystack.len() - needle.len() {
        if &haystack[i..i + needle.len()] == needle {
            return Some(i);
        }
    }
    
    None
}
