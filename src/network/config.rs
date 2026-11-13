// src/network/config.rs
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use crate::storage::SafeFSOps;
use crate::vault::{self, MasterKey, Vault};

const CONFIG_FILE_NAME: &str = "global.conf";
const CONFIG_AAD: &[u8] = b"lastchance:global.conf";

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
    /// Загружает конфигурацию, расшифровывая её мастер-ключом.
    ///
    /// Если найден файл старого формата (открытый JSON), он сразу
    /// перезаписывается зашифрованным.
    pub fn load(base_dir: &str, vault: &Vault) -> Result<Self> {
        let safe_fs = SafeFSOps::new(base_dir)?;

        match safe_fs.safe_read_file(CONFIG_FILE_NAME) {
            Ok(data) => {
                let legacy = !vault::is_sealed(&data);
                let plaintext = if legacy {
                    data
                } else {
                    vault.open_file(CONFIG_AAD, &data)?
                };

                let mut cfg: Config = serde_json::from_slice(&plaintext)
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

                if legacy {
                    save_encrypted(&safe_fs, vault, &cfg)?;
                }

                Ok(cfg)
            }
            Err(_) => {
                // File doesn't exist, create with defaults
                let default_cfg = Config::default();
                save_encrypted(&safe_fs, vault, &default_cfg)?;

                Ok(default_cfg)
            }
        }
    }

    /// Сохраняет конфигурацию в зашифрованный `global.conf`.
    pub fn save(&self, base_dir: &str, vault: &Vault) -> Result<()> {
        let safe_fs = SafeFSOps::new(base_dir)?;
        save_encrypted(&safe_fs, vault, self)
    }

    /// Перешифровывает `global.conf` со старого ключа на новый (`/passwd`).
    pub fn reencrypt(base_dir: &str, old_key: &MasterKey, new_key: &MasterKey) -> Result<()> {
        let safe_fs = SafeFSOps::new(base_dir)?;

        // Конфиг мог быть ещё не создан — тогда перешифровывать нечего.
        if safe_fs.safe_stat(CONFIG_FILE_NAME).is_err() {
            return Ok(());
        }

        let data = safe_fs.safe_read_file(CONFIG_FILE_NAME)?;

        let plaintext = if vault::is_sealed(&data) {
            vault::open_file(old_key, CONFIG_AAD, &data)?
        } else {
            data
        };

        let sealed = vault::seal_file(new_key, CONFIG_AAD, &plaintext)?;
        safe_fs.safe_write_file(CONFIG_FILE_NAME, &sealed, 0o600)
    }
}

fn save_encrypted(safe_fs: &SafeFSOps, vault: &Vault, cfg: &Config) -> Result<()> {
    let json_data = serde_json::to_string_pretty(cfg)
        .map_err(|e| anyhow!("failed to marshal config: {}", e))?;
    let sealed = vault.seal_file(CONFIG_AAD, json_data.as_bytes())?;

    safe_fs.safe_write_file(CONFIG_FILE_NAME, &sealed, 0o600)
}
