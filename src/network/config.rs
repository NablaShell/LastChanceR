// src/network/config.rs
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use crate::i18n::Lang;
use crate::storage::SafeFSOps;
use crate::vault::{self, MasterKey, Vault};

const CONFIG_FILE_NAME: &str = "global.conf";
const CONFIG_AAD: &[u8] = b"lastchance:global.conf";

pub const DEFAULT_NOTIFY_LEVEL: u8 = 2;
pub const DEFAULT_STEALTH_TITLE: &str = "Eye break";
pub const DEFAULT_STEALTH_BODY: &str =
    "Time to rest. Take an eye break for {sec} seconds";
pub const DEFAULT_STEALTH_SECONDS: &str = "10";

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
    pub server_url: String,
    pub file_server_url: String,
    pub mask_header_name: String,
    pub mask_header_value: String,
    /// Внешний прокси (Tor/I2P), например `socks5h://127.0.0.1:9050`.
    #[serde(default)]
    pub proxy_url: Option<String>,
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
            server_url: "https://msg.example.com".to_string(),
            file_server_url: "https://files.example.com".to_string(),
            mask_header_name: "X-DNS-Connect".to_string(),
            mask_header_value: "We_Are_Not_Legion".to_string(),
            proxy_url: None,
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

/// Приводит пользовательский адрес прокси к каноническому виду.
///
/// Пустая строка, `-` и `none` означают «без прокси». `socks5://` заменяется
/// на `socks5h://`: в этом режиме DNS-резолвинг выполняет прокси, и домен
/// сервера не уходит провайдеру.
pub fn normalize_proxy_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed == "-" || trimmed.eq_ignore_ascii_case("none") {
        return None;
    }

    const SOCKS5_SCHEME: &str = "socks5://";
    if trimmed
        .get(..SOCKS5_SCHEME.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(SOCKS5_SCHEME))
    {
        return Some(format!("socks5h://{}", &trimmed[SOCKS5_SCHEME.len()..]));
    }

    Some(trimmed.to_string())
}

impl Config {
    /// Нормализует значения, которые допускают несколько форм записи.
    pub fn normalize(&mut self) {
        self.proxy_url = normalize_proxy_url(self.proxy_url.as_deref().unwrap_or_default());
        self.notify_level = self.notify_level.min(3);
    }

    /// Переключает язык и, если stealth-шаблоны не менялись вручную,
    /// заменяет их стандартными строками новой локали.
    pub fn apply_lang(&mut self, lang: Lang) {
        // Стандартный шаблон любой локали считаем «нетронутым»: так старые
        // конфиги с русскими значениями корректно переводятся на English.
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
    /// Возвращает `None`, если уведомления отключены. Текст намеренно не
    /// содержит эмодзи: для файлов используется строка `Файл: <имя>`.
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
                preview_body(text, self.lang)
                    .unwrap_or_else(|| texts.notify_new_message_default.to_string()),
            )),
            _ => None,
        }
    }

    /// Проверяет, что прокси-URL корректен, до сохранения конфига.
    pub fn validate(&self) -> Result<()> {
        if let Some(url) = self.proxy_url.as_deref() {
            reqwest::Proxy::all(url)
                .map_err(|e| anyhow!("invalid proxy URL {:?}: {}", url, e))?;
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
                if cfg.stealth_title.trim().is_empty() {
                    cfg.stealth_title = cfg.lang.default_stealth_title().to_string();
                }
                if cfg.stealth_body.trim().is_empty() {
                    cfg.stealth_body = cfg.lang.default_stealth_body().to_string();
                }
                if cfg.stealth_seconds.trim().is_empty() {
                    cfg.stealth_seconds = defaults.stealth_seconds;
                }
                // Старые конфиги получали английские шаблоны из serde-default;
                // для русской локали заменяем их на русские стандартные.
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
                // File doesn't exist, create with defaults
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
fn preview_body(text: &str, lang: Lang) -> Option<String> {
    if let Some(file_name) = file_name_from_notification(text) {
        return Some(lang.texts().notify_file.replace("{}", &file_name));
    }

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

/// Достаёт имя файла из служебного сообщения вида `Файл: <имя>`.
fn file_name_from_notification(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("📎 ").unwrap_or(line);
        let Some(name) = line
            .strip_prefix("Файл: ")
            .or_else(|| line.strip_prefix("File: "))
        else {
            continue;
        };
        let name = name.trim();
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }
    None
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
    fn normalizes_socks5_to_remote_dns() {
        assert_eq!(
            normalize_proxy_url("socks5://127.0.0.1:9050").as_deref(),
            Some("socks5h://127.0.0.1:9050")
        );
        assert_eq!(
            normalize_proxy_url("  socks5h://127.0.0.1:9050  ").as_deref(),
            Some("socks5h://127.0.0.1:9050")
        );
        assert_eq!(
            normalize_proxy_url("http://127.0.0.1:4444").as_deref(),
            Some("http://127.0.0.1:4444")
        );
    }

    #[test]
    fn empty_or_none_disables_proxy() {
        assert_eq!(normalize_proxy_url(""), None);
        assert_eq!(normalize_proxy_url("   "), None);
        assert_eq!(normalize_proxy_url("-"), None);
        assert_eq!(normalize_proxy_url("none"), None);
        assert_eq!(normalize_proxy_url("NONE"), None);
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

        let (_, body) = config
            .notification_content("Alice", "📎 Файл: secret.pdf\nРазмер: 10 B", 1)
            .unwrap();
        assert_eq!(body, "File: secret.pdf");
    }

    #[test]
    fn old_config_json_gets_notification_defaults() {
        let json = r#"{
            "server_url": "https://msg.example.com",
            "file_server_url": "https://files.example.com",
            "mask_header_name": "X-DNS-Connect",
            "mask_header_value": "We_Are_Not_Legion"
        }"#;

        let config: Config = serde_json::from_str(json).unwrap();
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
