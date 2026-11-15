//! Общие типы и безопасные утилиты для недоверенных данных.

pub mod ids;

pub use ids::{FileHash, IdError, IdentityHash, RoomId, HEX_ID_BYTES, HEX_ID_LEN};

/// Обрезает строку до `max_chars` символов (не байт).
///
/// Если строка длиннее, последний символ заменяется многоточием, поэтому
/// результат всегда содержит не более `max_chars` символов. Функция
/// безопасна для любого UTF-8 и никогда не режет символ пополам.
pub fn truncate_display(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    let mut chars = value.chars();
    let mut out: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        out.pop();
        out.push('…');
    }
    out
}

/// Короткое представление идентификатора для UI и логов: 6 символов + `…`.
///
/// Работает по `char`, а не по байтам, поэтому не паникует на кириллице,
/// эмодзи и любом другом UTF-8.
pub fn short_hash(value: &str) -> String {
    let mut chars = value.chars();
    let mut out: String = chars.by_ref().take(6).collect();
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// Разбирает служебное сообщение о файле, отклоняя невалидный hash.
///
/// Возвращает `Ok(None)`, если текст не является уведомлением о файле
/// (нет маркера `📎` или строки с hash). Если hash присутствует, но не
/// является 64-символьным hex, возвращается `Err` — вызывающая сторона
/// обязана отбросить сообщение до записи в БД.
pub fn parse_file_notification_checked(text: &str) -> Result<Option<(String, String)>, IdError> {
    if !text.contains('📎') {
        return Ok(None);
    }

    let mut file_name = None;
    let mut file_hash = None;

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line
            .strip_prefix("📎 Файл:")
            .or_else(|| line.strip_prefix("📎 File:"))
        {
            file_name = Some(rest.trim().to_string());
        } else if let Some(rest) = line
            .strip_prefix("Хеш:")
            .or_else(|| line.strip_prefix("Hash:"))
        {
            file_hash = Some(rest.trim().to_string());
        }
    }

    let file_hash = match file_hash.filter(|hash| !hash.is_empty()) {
        Some(hash) => hash,
        None => return Ok(None),
    };

    // Wire-format допускает необязательный префикс `sha256:`, но сам hash
    // обязан быть 64 hex-символами.
    let bare_hash = file_hash.strip_prefix("sha256:").unwrap_or(&file_hash);
    FileHash::from_hex(bare_hash)?;

    let file_name = file_name.filter(|name| !name.is_empty()).unwrap_or_else(|| {
        format!(
            "file_{}",
            bare_hash.chars().take(8).collect::<String>()
        )
    });

    Ok(Some((file_name, file_hash)))
}

/// Как [`parse_file_notification_checked`], но невалидный hash превращается
/// в `None` для UI-путей, где ошибка уже обработана на границе.
pub fn parse_file_notification(text: &str) -> Option<(String, String)> {
    parse_file_notification_checked(text).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_notification_accepts_valid_hash() {
        let hash = "a".repeat(64);
        let text = format!("📎 Файл: report.pdf\nХеш: {}", hash);
        let parsed = parse_file_notification_checked(&text)
            .unwrap()
            .expect("file notification");
        assert_eq!(parsed.0, "report.pdf");
        assert_eq!(parsed.1, hash);
    }

    #[test]
    fn file_notification_rejects_invalid_hash() {
        let text = "📎 File: report.pdf\nHash: not-a-hash";
        assert!(parse_file_notification_checked(text).is_err());
        assert!(parse_file_notification(text).is_none());
    }

    #[test]
    fn file_notification_ignores_regular_text() {
        assert!(parse_file_notification_checked("hello 📎 world")
            .unwrap()
            .is_none());
    }
}
