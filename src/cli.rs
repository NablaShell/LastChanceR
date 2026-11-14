//! Разбор аргументов командной строки.
//!
//! Модуль не зависит от ratatui/crossterm, поэтому одинаково используется
//! и обычным TUI-клиентом, и headless-режимом отправки сообщений. Юнит-тесты
//! живут здесь же и запускаются через `cargo test --lib`.

use anyhow::{anyhow, Result};

/// Аргументы headless-отправки без запуска TUI.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HeadlessArgs {
    /// Получатель: имя контакта, identity_hash или `lastchance://contact?...`.
    pub to: Option<String>,
    /// Текст сообщения; `-` означает чтение из stdin.
    pub send: Option<String>,
    /// Необязательный путь к файлу для зашифрованной отправки.
    pub file: Option<String>,
}

impl HeadlessArgs {
    /// Включён ли headless-режим (передан хотя бы один из его флагов).
    pub fn is_active(&self) -> bool {
        self.to.is_some() || self.send.is_some() || self.file.is_some()
    }

    /// Читать ли текст сообщения из stdin.
    pub fn reads_stdin(&self) -> bool {
        self.send.as_deref() == Some("-")
    }

    /// Проверяет, что получатель и полезная нагрузка заданы вместе.
    pub fn validate(&self) -> Result<()> {
        if !self.is_active() {
            return Ok(());
        }

        if self.to.as_deref().map(str::trim).unwrap_or_default().is_empty() {
            return Err(anyhow!("--to is required together with --send/--file"));
        }

        if self.send.is_none() && self.file.is_none() {
            return Err(anyhow!("--to requires --send <text|-> or --file <path>"));
        }

        Ok(())
    }
}

/// Возвращает значение флага `--name value` или `--name=value`.
///
/// `None` означает, что флаг не передан. Пустое значение считается ошибкой:
/// так опечатка вроде `--send ""` не превращается в пустое сообщение.
pub fn parse_flag_value(args: &[String], name: &str) -> Result<Option<String>> {
    let prefix = format!("{}=", name);
    let mut iter = args.iter().skip(1);

    while let Some(arg) = iter.next() {
        if arg == name {
            return match iter.next() {
                Some(value) if !value.trim().is_empty() => Ok(Some(value.clone())),
                _ => Err(anyhow!("{}: missing value", name)),
            };
        }

        if let Some(value) = arg.strip_prefix(&prefix) {
            if value.trim().is_empty() {
                return Err(anyhow!("{}: missing value", name));
            }
            return Ok(Some(value.to_string()));
        }
    }

    Ok(None)
}

/// Разбирает каталог профиля. `--profile-dir` имеет приоритет над
/// устаревшим `--data-dir`; переменная окружения учитывается позже,
/// в `storage::paths`.
pub fn parse_profile_dir(args: &[String]) -> Result<Option<String>> {
    if let Some(path) = parse_flag_value(args, "--profile-dir")? {
        return Ok(Some(path));
    }
    parse_flag_value(args, "--data-dir")
}

/// Разбирает headless-аргументы и сразу проверяет их сочетание.
pub fn parse_headless_args(args: &[String]) -> Result<HeadlessArgs> {
    let parsed = HeadlessArgs {
        to: parse_flag_value(args, "--to")?,
        send: parse_flag_value(args, "--send")?,
        file: parse_flag_value(args, "--file")?,
    };
    parsed.validate()?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        std::iter::once("lastchance".to_string())
            .chain(items.iter().map(|item| item.to_string()))
            .collect()
    }

    #[test]
    fn parses_headless_to_and_send() {
        let parsed = parse_headless_args(&args(&[
            "--to", "alice", "--send", "hello world",
        ]))
        .unwrap();

        assert!(parsed.is_active());
        assert_eq!(parsed.to.as_deref(), Some("alice"));
        assert_eq!(parsed.send.as_deref(), Some("hello world"));
        assert_eq!(parsed.file, None);
        assert!(!parsed.reads_stdin());
    }

    #[test]
    fn parses_send_dash_as_stdin() {
        let parsed =
            parse_headless_args(&args(&["--to", "alice", "--send", "-"])).unwrap();

        assert!(parsed.reads_stdin());
        assert_eq!(parsed.send.as_deref(), Some("-"));
    }

    #[test]
    fn parses_equals_form_and_file() {
        let parsed = parse_headless_args(&args(&[
            "--to=lastchance://contact?hash=x",
            "--send=hi",
            "--file=/tmp/report.pdf",
        ]))
        .unwrap();

        assert_eq!(
            parsed.to.as_deref(),
            Some("lastchance://contact?hash=x")
        );
        assert_eq!(parsed.send.as_deref(), Some("hi"));
        assert_eq!(parsed.file.as_deref(), Some("/tmp/report.pdf"));
    }

    #[test]
    fn headless_requires_recipient_and_payload() {
        assert!(parse_headless_args(&args(&["--send", "hi"])).is_err());
        assert!(parse_headless_args(&args(&["--to", "alice"])).is_err());
        assert!(parse_headless_args(&args(&["--to", "alice", "--file", ""])).is_err());
    }

    #[test]
    fn profile_dir_flag_wins_over_legacy_data_dir() {
        let parsed = parse_profile_dir(&args(&[
            "--data-dir",
            "/tmp/legacy",
            "--profile-dir",
            "/tmp/bot",
        ]))
        .unwrap();
        assert_eq!(parsed.as_deref(), Some("/tmp/bot"));

        let parsed =
            parse_profile_dir(&args(&["--data-dir", "/tmp/legacy"])).unwrap();
        assert_eq!(parsed.as_deref(), Some("/tmp/legacy"));

        assert_eq!(parse_profile_dir(&args(&[])).unwrap(), None);
    }
}
