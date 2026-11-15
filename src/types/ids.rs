//! Строго типизированные hex-идентификаторы.
//!
//! Идентификаторы приходят из недоверенных источников (invite-ссылки,
//! ответы сервера, тексты сообщений). Все они имеют одинаковый wire-формат:
//! 64 ASCII hex-символа, кодирующие 32 байта. Разбор выполняется до любых
//! срезов и до попадания значения в БД, поэтому не-ASCII или короткая
//! строка не может вызвать панику на байтовом индексе.

use std::fmt;
use std::str::FromStr;

/// Длина идентификатора в байтах.
pub const HEX_ID_BYTES: usize = 32;
/// Длина hex-представления идентификатора.
pub const HEX_ID_LEN: usize = HEX_ID_BYTES * 2;

/// Ошибка разбора идентификатора.
///
/// Намеренно не содержит исходную строку целиком: недоверенный ввод
/// нельзя бездумно печатать в логи.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdError {
    /// Длина не равна 64 символам.
    InvalidLength { expected: usize, actual: usize },
    /// В позиции `index` находится не hex-символ.
    InvalidHex { index: usize },
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdError::InvalidLength { expected, actual } => {
                write!(f, "expected {} hex characters, got {}", expected, actual)
            }
            IdError::InvalidHex { index } => {
                write!(f, "invalid hex character at byte {}", index)
            }
        }
    }
}

impl std::error::Error for IdError {}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_id(bytes: &[u8]) -> Result<[u8; HEX_ID_BYTES], IdError> {
    if bytes.len() != HEX_ID_LEN {
        return Err(IdError::InvalidLength {
            expected: HEX_ID_LEN,
            actual: bytes.len(),
        });
    }

    let mut out = [0u8; HEX_ID_BYTES];
    for index in 0..HEX_ID_BYTES {
        let high = hex_value(bytes[index * 2]).ok_or(IdError::InvalidHex { index: index * 2 })?;
        let low =
            hex_value(bytes[index * 2 + 1]).ok_or(IdError::InvalidHex { index: index * 2 + 1 })?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

macro_rules! hex_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; HEX_ID_BYTES]);

        impl $name {
            /// Разбирает ровно 64 hex-символа (верхний или нижний регистр).
            pub fn from_hex(value: &str) -> Result<Self, IdError> {
                Self::from_hex_bytes(value.as_bytes())
            }

            /// Разбирает идентификатор из сырых байт.
            ///
            /// Не выполняет `String::from_utf8`: не-ASCII байт просто
            /// становится `InvalidHex`, без паники и потери диагностики.
            pub fn from_hex_bytes(value: &[u8]) -> Result<Self, IdError> {
                decode_hex_id(value).map(Self)
            }

            /// Создаёт идентификатор из уже проверенных байт.
            pub const fn from_bytes(bytes: [u8; HEX_ID_BYTES]) -> Self {
                Self(bytes)
            }

            /// Возвращает сырые байты идентификатора.
            pub const fn as_bytes(&self) -> &[u8; HEX_ID_BYTES] {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        // Идентификаторы не являются секретами; Debug печатает тот же
        // lower-case hex, что и Display, но без двойных кавычек.
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(self.0))
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::from_hex(value)
            }
        }
    };
}

hex_id! {
    /// SHA-256 от Ed25519-публичного ключа (identity/contact/room hash).
    IdentityHash
}

hex_id! {
    /// SHA-256 зашифрованного файла, который возвращает файловый сервер.
    FileHash
}

hex_id! {
    /// Идентификатор комнаты. Сейчас совпадает по формату с identity hash.
    RoomId
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_LOWER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const VALID_UPPER: &str = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn accepts_lower_and_upper_hex_and_round_trips() {
        let lower = IdentityHash::from_hex(VALID_LOWER).unwrap();
        let upper = IdentityHash::from_hex(VALID_UPPER).unwrap();
        assert_eq!(lower, upper);
        assert_eq!(lower.to_string(), VALID_LOWER);
        assert_eq!(format!("{:?}", lower), VALID_LOWER);
        assert_eq!(lower.as_bytes().len(), HEX_ID_BYTES);
    }

    #[test]
    fn rejects_non_ascii_without_panicking() {
        let cyrillic = "я".repeat(64);
        let emoji = "😀".repeat(32);
        assert!(IdentityHash::from_hex(&cyrillic).is_err());
        assert!(IdentityHash::from_hex(&emoji).is_err());

        // Невалидный UTF-8 на байтовой границе тоже не должен паниковать.
        let raw = [0xff_u8; HEX_ID_LEN];
        assert!(FileHash::from_hex_bytes(&raw).is_err());
    }

    #[test]
    fn rejects_wrong_lengths() {
        for value in ["", "a", &"a".repeat(63), &"a".repeat(65)] {
            assert!(matches!(
                RoomId::from_hex(value),
                Err(IdError::InvalidLength { .. })
            ));
        }
    }

    #[test]
    fn rejects_non_hex_ascii() {
        for value in [
            format!("{}g", "a".repeat(63)),
            format!("{} ", "a".repeat(63)),
            format!("0x{}", "a".repeat(62)),
        ] {
            assert!(matches!(
                FileHash::from_hex(&value),
                Err(IdError::InvalidHex { .. })
            ));
        }
    }

    #[test]
    fn short_hash_is_char_safe() {
        assert_eq!(super::super::short_hash("abcdef"), "abcdef");
        assert_eq!(super::super::short_hash("abcdefg"), "abcdef…");
        // Каждый символ — многобайтовый UTF-8; байтовый срез здесь паниковал бы.
        assert_eq!(super::super::short_hash("кириллица"), "кирилл…");
        assert_eq!(super::super::short_hash("😀😀😀😀😀😀😀"), "😀😀😀😀😀😀…");
    }

    #[test]
    fn truncate_display_is_char_safe() {
        assert_eq!(super::super::truncate_display("abcdef", 6), "abcdef");
        assert_eq!(super::super::truncate_display("abcdefg", 6), "abcde…");
        assert_eq!(super::super::truncate_display("кириллица", 4), "кир…");
        assert_eq!(super::super::truncate_display("😀😀😀", 2), "😀…");
        assert_eq!(super::super::truncate_display("abc", 0), "");
        assert_eq!(
            super::super::truncate_display("кириллица", 100)
                .chars()
                .count(),
            9
        );
        assert_eq!(
            super::super::truncate_display("abcdefg", 6)
                .chars()
                .count(),
            6
        );
    }
}
