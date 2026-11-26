//! Общие типы и безопасные утилиты для недоверенных данных.

pub mod ids;

pub use ids::{IdError, IdentityHash, OnionAddress, OnionError, RoomId, HEX_ID_BYTES, HEX_ID_LEN};

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
