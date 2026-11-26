// src/network/config.rs
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use crate::i18n::Lang;
use crate::storage::SafeFSOps;
use crate::vault::{self, MasterKey, Vault};

const CONFIG_FILE_NAME: &str = "global.conf";
const CONFIG_AAD: &[u8] = b"lastchance:global.conf";

pub const DEFAULT_TOR_CONTROL_ADDR: &str = "127.0.0.1:9051";
pub const DEFAULT_TOR_SOCKS_ADDR: &str = "127.0.0.1:9050";
pub const DEFAULT_P2P_LOCAL_PORT: u16 = 0;
pub const DEFAULT_P2P_ONION_PORT: u16 = 9878;

pub const DEFAULT_NOTIFY_LEVEL: u8 = 2;
pub const DEFAULT_STEALTH_TITLE: &str = "Eye break";
pub const DEFAULT_STEALTH_BODY: &str =
    "Time to rest. Take an eye break for {sec} seconds";
pub const DEFAULT_STEALTH_SECONDS: &str = "10";

fn default_tor_control_addr() -> String {
    DEFAULT_TOR_CONTROL_ADDR.to_string()
}

fn default_tor_socks_addr() -> String {
    DEFAULT_TOR_SOCKS_ADDR.to_string()
}

fn default_p2p_local_port() -> u16 {
    DEFAULT_P2P_LOCAL_PORT
}

fn default_p2p_onion_port() -> u16 {
    DEFAULT_P2P_ONION_PORT
}

fn default_notify_level() -> u8 {
    DEFAULT_NOTIFY_LEVEL
}

fn default_stealth_title() -> String {
    DEFAULT_STEALTH_TITLE.to_string()
}

fn default_stealth_body() -> String {
    DEFAULT_STEALTH_BODY.to_string()
}

fn default_stealth_seconds() -> String {
    DEFAULT_STEALTH_SECONDS.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Адрес Tor ControlPort, например `127.0.0.1:9051`.
    #[serde(default = "default_tor_control_addr")]
    pub tor_control_addr: String,
    /// Адрес Tor SOCKS5h-прокси, например `127.0.0.1:9050`.
    #[serde(default = "default_tor_socks_addr")]
    pub tor_socks_addr: String,
    /// Необязательный путь к Tor control cookie-файлу.
    /// `None` означает автопоиск через `PROTOCOLINFO` (`COOKIEFILE`).
    #[serde(default)]
    pub tor_cookie_path: Option<String>,
    /// Локальный TCP-порт на `127.0.0.1`, который принимает трафик скрытого сервиса.
    /// `0` — автоматический выбор свободного порта при запуске.
    #[serde(default = "default_p2p_local_port")]
    pub p2p_local_port: u16,
    /// Виртуальный порт `.onion`-сервиса для входящих и исходящих P2P-соединений.
    #[serde(default = "default_p2p_onion_port")]
    pub p2p_onion_port: u16,
    /// Режим системных уведомлений:
    /// 0 — выключены, 1 — stealth, 2 — только отправитель, 3 — полный предпросмотр.
    #[serde(default = "default_notify_level")]
    pub notify_level: u8,
    /// Заголовок уведомления в режиме stealth.
    #[serde(default = "default_stealth_title")]
    pub stealth_title: String,
    /// Тело уведомления в режиме stealth. Поддерживает `{sec}` и `{count}`.
    #[serde(default = "default_stealth_body")]
    pub stealth_body: String,
    /// Строка для `{sec}`: например `10` или диапазон `10-15`.
    #[serde(default = "default_stealth_seconds")]
    pub stealth_seconds: String,
    /// Язык интерфейса. Старые конфиги без этого поля получают английский.
    #[serde(default)]
    pub lang: Lang,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            tor_control_addr: default_tor_control_addr(),
            tor_socks_addr: default_tor_socks_addr(),
            tor_cookie_path: None,
            p2p_local_port: DEFAULT_P2P_LOCAL_PORT,
            p2p_onion_port: DEFAULT_P2P_ONION_PORT,
            notify_level: DEFAULT_NOTIFY_LEVEL,
            stealth_title: default_stealth_title(),
            stealth_body: default_stealth_body(),
            stealth_seconds: default_stealth_seconds(),
            lang: Lang::En,
        }
    }
}

/// Человекочитаемая подпись режима уведомлений для меню `/set`.
pub fn notify_level_label(lang: Lang, level: u8) -> &'static str {
    lang.notify_level_label(level)
}

/// Нормализует опциональный путь к cookie-файлу Tor.
/// Пустая строка, `-` и `auto` сбрасывают значение в `None`.
pub fn normalize_optional_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "-" || trimmed.eq_ignore_ascii_case("auto") {
        return None;
    }
    Some(trimmed.to_string())
}

fn validate_endpoint_addr(label: &str, addr: &str) -> Result<()> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("{} must not be empty", label));
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(anyhow!("{} contains invalid whitespace or control characters", label));
    }
    if let Ok(socket_addr) = trimmed.parse::<SocketAddr>() {
        if socket_addr.port() == 0 {
            return Err(anyhow!("{} port must be non-zero", label));
        }
        return Ok(());
    }
    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return Err(anyhow!("{} must be in host:port format", label));
    };
    if host.is_empty() {
        return Err(anyhow!("{} is missing host", label));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("{} has invalid port", label))?;
    if port == 0 {
        return Err(anyhow!("{} port must be non-zero", label));
    }
    Ok(())
}

fn env_nonempty(keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| std::env::var(key).ok())
        .map(|val| val.trim().to_string())
        .filter(|val| !val.is_empty())
}

impl Config {
    /// Нормализует значения, которые допускают несколько форм записи.
    pub fn normalize(&mut self) {
        self.tor_control_addr = self.tor_control_addr.trim().to_string();
        if self.tor_control_addr.is_empty() {
            self.tor_control_addr = default_tor_control_addr();
        }
        self.tor_socks_addr = self.tor_socks_addr.trim().to_string();
        if self.tor_socks_addr.is_empty() {
            self.tor_socks_addr = default_tor_socks_addr();
        }
        self.tor_cookie_path = normalize_optional_path(
            self.tor_cookie_path.as_deref().unwrap_or_default(),
        );
        if self.p2p_onion_port == 0 {
            self.p2p_onion_port = DEFAULT_P2P_ONION_PORT;
        }
        self.notify_level = self.notify_level.min(3);
    }

    /// Адрес Tor ControlPort с учётом env (`LASTCHANCE_TOR_CONTROL`, `TOR_CONTROL_ADDR`).
    pub fn effective_tor_control_addr(&self) -> String {
        env_nonempty(&["LASTCHANCE_TOR_CONTROL", "TOR_CONTROL_ADDR"])
            .unwrap_or_else(|| self.tor_control_addr.clone())
    }

    /// Адрес Tor SOCKS5h-прокси с учётом env (`LASTCHANCE_TOR_SOCKS`, `TOR_SOCKS_ADDR`).
    pub fn effective_tor_socks_addr(&self) -> String {
        env_nonempty(&["LASTCHANCE_TOR_SOCKS", "TOR_SOCKS_ADDR"])
            .unwrap_or_else(|| self.tor_socks_addr.clone())
    }

    /// Путь к Tor control cookie с учётом env (`LASTCHANCE_TOR_COOKIE`, `TOR_COOKIE_PATH`).
    pub fn effective_tor_cookie_path(&self) -> Option<String> {
        if let Some(raw) = env_nonempty(&["LASTCHANCE_TOR_COOKIE", "TOR_COOKIE_PATH"]) {
            return normalize_optional_path(&raw);
        }
        self.tor_cookie_path.clone()
    }

    /// Локальный порт привязки с учётом env (`LASTCHANCE_P2P_LOCAL_PORT`, `P2P_LOCAL_PORT`).
    pub fn effective_p2p_local_port(&self) -> u16 {
        env_nonempty(&["LASTCHANCE_P2P_LOCAL_PORT", "P2P_LOCAL_PORT"])
            .and_then(|val| val.parse::<u16>().ok())
            .unwrap_or(self.p2p_local_port)
    }

    /// Виртуальный порт `.onion` с учётом env (`LASTCHANCE_P2P_ONION_PORT`, `P2P_ONION_PORT`).
    pub fn effective_p2p_onion_port(&self) -> u16 {
        env_nonempty(&["LASTCHANCE_P2P_ONION_PORT", "P2P_ONION_PORT"])
            .and_then(|val| val.parse::<u16>().ok())
            .filter(|port| *port > 0)
            .unwrap_or(self.p2p_onion_port)
    }

    /// Переключает язык и, если stealth-шаблоны не менялись вручную,
    /// заменяет их стандартными строками новой локали.
    pub fn apply_lang(&mut self, lang: Lang) {
        let untouched_title = [Lang::En, Lang::Ru]
            .iter()
            .any(|l| self.stealth_title == l.default_stealth_title());
        let untouched_body = [Lang::En, Lang::Ru]
            .iter()
            .any(|l| self.stealth_body == l.default_stealth_body());
        if untouched_title {
            self.stealth_title = lang.default_stealth_title().to_string();
        }
        if untouched_body {
            self.stealth_body = lang.default_stealth_body().to_string();
        }
        self.lang = lang;
    }

    /// Формирует заголовок и тело системного уведомления по текущему режиму.
    ///
    /// Возвращает `None`, если уведомления отключены.
    pub fn notification_content(
        &self,
        sender: &str,
        text: &str,
        unread: usize,
    ) -> Option<(String, String)> {
        let texts = self.lang.texts();
        match self.notify_level {
            0 => None,
            1 => {
                let seconds = {
                    let value = self.stealth_seconds.trim();
                    if value.is_empty() {
                        DEFAULT_STEALTH_SECONDS
                    } else {
                        value
                    }
                };
                let count = unread.max(1).to_string();
                let title = substitute_stealth(&self.stealth_title, seconds, &count);
                let body = substitute_stealth(&self.stealth_body, seconds, &count);
                Some((
                    if title.trim().is_empty() {
                        self.lang.default_stealth_title().to_string()
                    } else {
                        title
                    },
                    if body.trim().is_empty() {
                        self.lang.default_stealth_body().to_string()
                    } else {
                        body
                    },
                ))
            }
            2 => Some((
                "LastChance".to_string(),
                texts.notify_new_message.replace("{}", sender),
            )),
            3 => Some((
                sender.to_string(),
                preview_body(text)
                    .unwrap_or_else(|| texts.notify_new_message_default.to_string()),
            )),
            _ => None,
        }
    }

    /// Проверяет корректность сетевых адресов Tor до сохранения конфига.
    pub fn validate(&self) -> Result<()> {
        validate_endpoint_addr("Tor ControlPort", &self.tor_control_addr)?;
        validate_endpoint_addr("Tor SOCKS5h", &self.tor_socks_addr)?;
        if self.p2p_onion_port == 0 {
            return Err(anyhow!("P2P onion port must be non-zero"));
        }
        if let Some(path) = self.tor_cookie_path.as_deref() {
            if path.chars().any(|c| c.is_control()) {
                return Err(anyhow!("Tor cookie path contains control characters"));
            }
        }
        Ok(())
    }

    /// Загружает конфигурацию, расшифровывая её мастер-ключом.
    ///
    /// Если найден файл старого формата (открытый JSON), он сразу
    /// перезаписывается зашифрованным.
    pub fn load(base_dir: &str, vault: &Vault) -> Result<Self> {
        Ok(Self::load_with_language_flag(base_dir, vault)?.0)
    }

    /// Загружает конфигурацию и сообщает, нужно ли показать выбор языка.
    ///
    /// Флаг `true` означает, что `global.conf` ещё не существовал или в нём
    /// нет поля `lang` (конфиг старой версии).
    pub fn load_with_language_flag(base_dir: &str, vault: &Vault) -> Result<(Self, bool)> {
        let safe_fs = SafeFSOps::new(base_dir)?;

        match safe_fs.safe_read_file(CONFIG_FILE_NAME) {
            Ok(data) => {
                let legacy = !vault::is_sealed(&data);
                let plaintext = if legacy {
                    data
                } else {
                    vault.open_file(CONFIG_AAD, &data)?
                };

                let value: serde_json::Value = serde_json::from_slice(&plaintext)
                    .map_err(|e| anyhow!("invalid config file: {}", e))?;
                let language_missing = value.get("lang").is_none();

                let mut cfg: Config = serde_json::from_value(value)
                    .map_err(|e| anyhow!("invalid config file: {}", e))?;

                let defaults = Config::default();
                if cfg.tor_control_addr.trim().is_empty() {
                    cfg.tor_control_addr = defaults.tor_control_addr;
                }
                if cfg.tor_socks_addr.trim().is_empty() {
                    cfg.tor_socks_addr = defaults.tor_socks_addr;
                }
                if cfg.p2p_onion_port == 0 {
                    cfg.p2p_onion_port = defaults.p2p_onion_port;
                }
                if cfg.stealth_title.trim().is_empty() {
                    cfg.stealth_title = cfg.lang.default_stealth_title().to_string();
                }
                if cfg.stealth_body.trim().is_empty() {
                    cfg.stealth_body = cfg.lang.default_stealth_body().to_string();
                }
                if cfg.stealth_seconds.trim().is_empty() {
                    cfg.stealth_seconds = defaults.stealth_seconds;
                }
                if cfg.lang != Lang::En {
                    if cfg.stealth_title == DEFAULT_STEALTH_TITLE {
                        cfg.stealth_title = cfg.lang.default_stealth_title().to_string();
                    }
                    if cfg.stealth_body == DEFAULT_STEALTH_BODY {
                        cfg.stealth_body = cfg.lang.default_stealth_body().to_string();
                    }
                }
                cfg.normalize();

                if legacy {
                    save_encrypted(&safe_fs, vault, &cfg)?;
                }

                Ok((cfg, language_missing))
            }
            Err(_) => {
                let default_cfg = Config::default();
                save_encrypted(&safe_fs, vault, &default_cfg)?;

                Ok((default_cfg, true))
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

fn substitute_stealth(template: &str, seconds: &str, count: &str) -> String {
    template
        .replace("{sec}", seconds)
        .replace("{count}", count)
        .trim()
        .to_string()
}

/// Готовит текст сообщения для полного предпросмотра.
///
/// Управляющие символы превращаются в пробелы, пробельные серии
/// схлопываются, а длина ограничивается 120 символами.
fn preview_body(text: &str) -> Option<String> {
    let cleaned: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }

    let mut chars = collapsed.chars();
    let mut preview: String = chars.by_ref().take(120).collect();
    if chars.next().is_some() {
        preview = preview.chars().take(117).collect();
        preview.push_str("...");
    }
    Some(preview)
}

fn save_encrypted(safe_fs: &SafeFSOps, vault: &Vault, cfg: &Config) -> Result<()> {
    let mut cfg = cfg.clone();
    cfg.normalize();
    let json_data = serde_json::to_string_pretty(&cfg)
        .map_err(|e| anyhow!("failed to marshal config: {}", e))?;
    let sealed = vault.seal_file(CONFIG_AAD, json_data.as_bytes())?;

    safe_fs.safe_write_file(CONFIG_FILE_NAME, &sealed, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_optional_cookie_paths() {
        assert_eq!(normalize_optional_path(""), None);
        assert_eq!(normalize_optional_path("   "), None);
        assert_eq!(normalize_optional_path("-"), None);
        assert_eq!(normalize_optional_path("auto"), None);
        assert_eq!(normalize_optional_path("AUTO"), None);
        assert_eq!(
            normalize_optional_path(" /run/tor/control.authcookie ").as_deref(),
            Some("/run/tor/control.authcookie")
        );
    }

    #[test]
    fn validates_tor_endpoints() {
        let mut cfg = Config::default();
        assert!(cfg.validate().is_ok());

        cfg.tor_control_addr = "localhost:9051".to_string();
        assert!(cfg.validate().is_ok());

        cfg.tor_socks_addr = "not-an-endpoint".to_string();
        assert!(cfg.validate().is_err());

        cfg.tor_socks_addr = "127.0.0.1:0".to_string();
        assert!(cfg.validate().is_err());

        cfg.tor_socks_addr = DEFAULT_TOR_SOCKS_ADDR.to_string();
        cfg.p2p_onion_port = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn notification_defaults_and_levels() {
        let mut config = Config::default();
        assert_eq!(config.notify_level, 2);
        assert_eq!(
            config.notification_content("Alice", "hello", 1),
            Some((
                "LastChance".to_string(),
                "New message from Alice".to_string()
            ))
        );

        config.lang = Lang::Ru;
        assert_eq!(
            config.notification_content("Алиса", "привет", 1),
            Some((
                "LastChance".to_string(),
                "Новое сообщение от Алиса".to_string()
            ))
        );
        config.lang = Lang::En;

        config.notify_level = 3;
        assert_eq!(
            config.notification_content("Alice", "hello", 1),
            Some(("Alice".to_string(), "hello".to_string()))
        );

        config.notify_level = 0;
        assert_eq!(config.notification_content("Alice", "hello", 1), None);
    }

    #[test]
    fn stealth_notification_substitutes_template_values() {
        let config = Config {
            notify_level: 1,
            stealth_title: "Пауза {count}".to_string(),
            stealth_body: "Отдых {sec}, писем: {count}".to_string(),
            stealth_seconds: "10-15".to_string(),
            ..Config::default()
        };

        assert_eq!(
            config.notification_content("Alice", "secret", 3),
            Some((
                "Пауза 3".to_string(),
                "Отдых 10-15, писем: 3".to_string()
            ))
        );
    }

    #[test]
    fn preview_is_clean_and_truncated() {
        let config = Config {
            notify_level: 3,
            ..Config::default()
        };

        let long = "а".repeat(200);
        let (_, body) = config.notification_content("Alice", &long, 1).unwrap();
        assert_eq!(body.chars().count(), 120);
        assert!(body.ends_with("..."));

        let (_, body) = config
            .notification_content("Alice", "строка\nс\tуправляющими  символами", 1)
            .unwrap();
        assert_eq!(body, "строка с управляющими символами");
    }

    #[test]
    fn old_server_config_json_upgrades_with_tor_defaults() {
        let json = r#"{
            "server_url": "https://msg.example.com",
            "file_server_url": "https://files.example.com",
            "mask_header_name": "X-DNS-Connect",
            "mask_header_value": "We_Are_Not_Legion"
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
        assert_eq!(config.tor_control_addr, DEFAULT_TOR_CONTROL_ADDR);
        assert_eq!(config.tor_socks_addr, DEFAULT_TOR_SOCKS_ADDR);
        assert_eq!(config.p2p_local_port, DEFAULT_P2P_LOCAL_PORT);
        assert_eq!(config.p2p_onion_port, DEFAULT_P2P_ONION_PORT);
        assert_eq!(config.notify_level, DEFAULT_NOTIFY_LEVEL);
        assert_eq!(config.stealth_title, DEFAULT_STEALTH_TITLE);
        assert_eq!(config.stealth_body, DEFAULT_STEALTH_BODY);
        assert_eq!(config.stealth_seconds, DEFAULT_STEALTH_SECONDS);
    }

    #[test]
    fn notify_level_is_clamped() {
        let mut config = Config {
            notify_level: 99,
            ..Config::default()
        };
        config.normalize();
        assert_eq!(config.notify_level, 3);
    }
}
