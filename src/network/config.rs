// src/network/config.rs
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use crate::storage::SafeFSOps;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub file_server_url: String,
    pub mask_header_name: String,
    pub mask_header_value: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: "https://msg.example.com".to_string(),
            file_server_url: "https://files.example.com".to_string(),
            mask_header_name: "X-DNS-Connect".to_string(),
            mask_header_value: "We_Are_Not_Legion".to_string(),
        }
    }
}

impl Config {
    pub fn load(base_dir: &str) -> Result<Self> {
        let safe_fs = SafeFSOps::new(base_dir)?;
        let config_path = "global.conf";
        
        match safe_fs.safe_read_file(config_path) {
            Ok(data) => {
                let mut cfg: Config = serde_json::from_slice(&data)
                    .map_err(|e| anyhow!("invalid config file: {}", e))?;
                
                // Fill empty fields with defaults
                let defaults = Config::default();
                if cfg.server_url.is_empty() {
                    cfg.server_url = defaults.server_url;
                }
                if cfg.file_server_url.is_empty() {
                    cfg.file_server_url = defaults.file_server_url;
                }
                if cfg.mask_header_name.is_empty() {
                    cfg.mask_header_name = defaults.mask_header_name;
                }
                if cfg.mask_header_value.is_empty() {
                    cfg.mask_header_value = defaults.mask_header_value;
                }
                
                Ok(cfg)
            }
            Err(_) => {
                // File doesn't exist, create with defaults
                let default_cfg = Config::default();
                let json_data = serde_json::to_string_pretty(&default_cfg)
                    .map_err(|e| anyhow!("failed to marshal default config: {}", e))?;
                
                safe_fs.safe_write_file(config_path, json_data.as_bytes(), 0o600)?;
                
                Ok(default_cfg)
            }
        }
    }
}
