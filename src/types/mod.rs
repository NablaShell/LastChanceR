//! Общие типы и безопасные утилиты для недоверенных данных.

pub mod ids;

pub use ids::{
    normalize_file_id, FileHash, IdError, IdentityHash, RoomId, FILE_ID_HEX_LEN, HEX_ID_BYTES,
    HEX_ID_LEN,
};

/// Разобранное E2E-уведомление о файле.
///
/// Текст уведомления приходит внутри расшифрованного сообщения, поэтому
/// `file_hash` и `file_id` аутентичны. `file_id` — случайный идентификатор
/// из заголовка v3-конверта; он позволяет отличить два валидных конверта
/// одной пары/комнаты. Уведомления старого формата его не содержат:
/// для них остаётся проверка `sha256(конверт) == file_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNotification {
    pub file_name: String,
    pub file_hash: String,
    /// Канонический lower-case hex (32 символа), если он был в уведомлении.
    pub file_id: Option<String>,
}

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

/// Убирает символы, которыми можно управлять терминалом или подменить
/// направление текста.
///
/// Управляющие `C0`/`C1`-символы (включая `ESC`) отбрасываются, поэтому
/// ANSI-последовательности не переживают санитизацию. Из bidi-разметки
/// удаляются только явные embedding/override/isolate-маркеры: обычный
/// Unicode (кириллица, эмодзи, RTL-буквы) сохраняется как есть.
pub fn sanitize_display_text(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control() && !is_bidi_control(*c))
        .collect()
}

fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{202A}'..='\u{202E}' // LRE, RLE, PDF, LRO, RLO
            | '\u{2066}'..='\u{2069}' // LRI, RLI, FSI, PDI
    )
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

/// Разбирает служебное сообщение о файле, отклоняя невалидные hash/file_id.
///
/// Возвращает `Ok(None)`, если текст не является уведомлением о файле
/// (нет маркера `📎` или строки с hash). Если hash присутствует, но не
/// является 64-символьным hex, возвращается `Err` — вызывающая сторона
/// обязана отбросить сообщение до записи в БД. То же для `file_id`: если
/// строка есть, она обязана быть 32 hex-символами.
pub fn parse_file_notification_checked(text: &str) -> Result<Option<FileNotification>, IdError> {
    if !text.contains('📎') {
        return Ok(None);
    }

    let mut file_name = None;
    let mut file_hash = None;
    let mut file_id = None;

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
        } else if let Some(rest) = line
            .strip_prefix("File ID:")
            .or_else(|| line.strip_prefix("ID файла:"))
        {
            file_id = Some(rest.trim().to_string());
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

    // `file_id` необязателен для совместимости со старыми уведомлениями.
    let file_id = match file_id.filter(|id| !id.is_empty()) {
        Some(id) => Some(normalize_file_id(&id)?),
        None => None,
    };

    let file_name = file_name
        .map(|name| sanitize_display_text(&name))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| format!("file_{}", bare_hash.chars().take(8).collect::<String>()));

    Ok(Some(FileNotification {
        file_name,
        file_hash,
        file_id,
    }))
}

/// Как [`parse_file_notification_checked`], но невалидный hash/file_id
/// превращается в `None` для UI-путей, где ошибка уже обработана на границе.
pub fn parse_file_notification(text: &str) -> Option<FileNotification> {
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
        assert_eq!(parsed.file_name, "report.pdf");
        assert_eq!(parsed.file_hash, hash);
        // Старый формат без file_id остаётся читаемым.
        assert_eq!(parsed.file_id, None);
    }

    #[test]
    fn file_notification_accepts_and_normalizes_file_id() {
        let hash = "a".repeat(64);
        let file_id = "0123456789ABCDEF0123456789ABCDEF";
        let text = format!(
            "📎 File: report.pdf\nSize: 1 KiB\nHash: {}\nFile ID: {}",
            hash, file_id
        );
        let parsed = parse_file_notification_checked(&text)
            .unwrap()
            .expect("file notification");
        assert_eq!(parsed.file_name, "report.pdf");
        assert_eq!(parsed.file_hash, hash);
        assert_eq!(
            parsed.file_id.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn file_notification_rejects_invalid_hash() {
        let text = "📎 File: report.pdf\nHash: not-a-hash";
        assert!(parse_file_notification_checked(text).is_err());
        assert!(parse_file_notification(text).is_none());
    }

    #[test]
    fn file_notification_rejects_invalid_file_id() {
        let hash = "a".repeat(64);
        for file_id in ["not-a-file-id", &"a".repeat(31), &"a".repeat(33)] {
            let text = format!("📎 File: report.pdf\nHash: {}\nFile ID: {}", hash, file_id);
            assert!(
                parse_file_notification_checked(&text).is_err(),
                "file_id {:?} must be rejected",
                file_id
            );
            assert!(parse_file_notification(&text).is_none());
        }
    }

    #[test]
    fn display_text_drops_controls_and_bidi_overrides() {
        assert_eq!(
            sanitize_display_text("Alice\x1b[31m\u{202E}Bob\u{2066}!"),
            "Alice[31mBob!"
        );
        assert_eq!(sanitize_display_text("a\nb\tc\u{7f}d"), "abcd");
    }

    #[test]
    fn display_text_keeps_legitimate_unicode() {
        assert_eq!(sanitize_display_text("🙂 שלום مرحبا"), "🙂 שלום مرحبا");
        assert_eq!(sanitize_display_text("Иван 🙂"), "Иван 🙂");
    }

    #[test]
    fn file_notification_sanitizes_name() {
        let hash = "a".repeat(64);
        let text = format!("📎 Файл: report\x1b[31m\u{202E}.pdf\nХеш: {}", hash);
        let parsed = parse_file_notification_checked(&text)
            .unwrap()
            .expect("file notification");
        assert_eq!(parsed.file_name, "report[31m.pdf");
    }

    #[test]
    fn file_notification_ignores_regular_text() {
        assert!(parse_file_notification_checked("hello 📎 world")
            .unwrap()
            .is_none());
    }
}
