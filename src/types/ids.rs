//! Строго типизированные идентификаторы и Tor v3 `.onion`-адреса.
//!
//! Идентификаторы приходят из недоверенных источников (invite-ссылки,
//! ответы Tor ControlPort, входящие данные). Все hex-идентификаторы имеют
//! формат 64 ASCII hex-символа (32 байта), а `.onion`-адреса проверяются
//! на строгий формат Tor v3 (56 base32-символов + `.onion`, версия `0x03`).

use std::fmt;
use std::str::FromStr;

/// Длина идентификатора в байтах.
pub const HEX_ID_BYTES: usize = 32;
/// Длина hex-представления идентификатора.
pub const HEX_ID_LEN: usize = HEX_ID_BYTES * 2;
/// Длина Tor v3 ServiceID в символах base32 (без `.onion`).
pub const ONION_V3_SERVICE_ID_LEN: usize = 56;
/// Полная длина Tor v3 `.onion`-хоста (56 + `.onion`).
pub const ONION_V3_HOST_LEN: usize = ONION_V3_SERVICE_ID_LEN + 6;
/// Версия адреса Tor v3 hidden service (`0x03`).
pub const ONION_V3_VERSION: u8 = 0x03;

#[cfg(test)]
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

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

/// Ошибка валидации Tor v3 `.onion`-адреса.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionError {
    MissingSuffix,
    InvalidLength(usize),
    InvalidBase32(usize),
    UnsupportedVersion(u8),
    ZeroPublicKey,
}

impl fmt::Display for OnionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSuffix => write!(f, "onion address must end with .onion"),
            Self::InvalidLength(len) => write!(
                f,
                "invalid v3 onion service id length: expected {}, got {}",
                ONION_V3_SERVICE_ID_LEN, len
            ),
            Self::InvalidBase32(idx) => write!(f, "invalid base32 character at index {}", idx),
            Self::UnsupportedVersion(ver) => {
                write!(f, "unsupported onion address version: {} (expected v3)", ver)
            }
            Self::ZeroPublicKey => write!(f, "onion address has all-zero public key"),
        }
    }
}

impl std::error::Error for OnionError {}

/// Валидированный Tor v3 адрес вида `<56-char-base32>.onion`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OnionAddress(String);

impl OnionAddress {
    /// Разбирает и нормализует Tor v3 `.onion`-адрес в нижний регистр.
    ///
    /// Не допускает схему, порт, путь или пробельные символы: ожидается
    /// исключительно `<service_id>.onion`.
    pub fn parse(raw: &str) -> Result<Self, OnionError> {
        if !raw.is_ascii() {
            return Err(OnionError::MissingSuffix);
        }
        let lower = raw.to_ascii_lowercase();
        let service_id = lower
            .strip_suffix(".onion")
            .ok_or(OnionError::MissingSuffix)?;
        if service_id.len() != ONION_V3_SERVICE_ID_LEN {
            return Err(OnionError::InvalidLength(service_id.len()));
        }

        let decoded = decode_base32_v3(service_id.as_bytes())?;
        if decoded[34] != ONION_V3_VERSION {
            return Err(OnionError::UnsupportedVersion(decoded[34]));
        }
        if decoded[..32].iter().all(|b| *b == 0) {
            return Err(OnionError::ZeroPublicKey);
        }

        Ok(Self(lower))
    }

    /// Строит `.onion` из 56-символьного Tor `ServiceID` (без `.onion`).
    pub fn from_service_id(service_id: &str) -> Result<Self, OnionError> {
        Self::parse(&format!("{}.onion", service_id))
    }

    /// Полный адрес `<service_id>.onion`.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 56-символьный `ServiceID` без `.onion`.
    pub fn service_id(&self) -> &str {
        &self.0[..ONION_V3_SERVICE_ID_LEN]
    }

    /// Собирает синтетический валидный по структуре Tor v3 адрес (для тестов).
    #[cfg(test)]
    pub fn test_v3_from_seed(seed: u8) -> Self {
        let mut raw = [0u8; 35];
        raw[..32].fill(seed.max(1));
        raw[32] = seed;
        raw[33] = seed.wrapping_add(1);
        raw[34] = ONION_V3_VERSION;
        let service_id = encode_base32(&raw);
        Self(format!("{}.onion", service_id))
    }
}

impl fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for OnionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for OnionAddress {
    type Err = OnionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

fn decode_base32_v3(input: &[u8]) -> Result<[u8; 35], OnionError> {
    if input.len() != ONION_V3_SERVICE_ID_LEN {
        return Err(OnionError::InvalidLength(input.len()));
    }

    let mut out = [0u8; 35];
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out_idx = 0usize;

    for (index, byte) in input.iter().enumerate() {
        let val = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(OnionError::InvalidBase32(index)),
        } as u32;

        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if out_idx >= out.len() {
                return Err(OnionError::InvalidLength(input.len()));
            }
            out[out_idx] = (buffer >> bits) as u8;
            out_idx += 1;
            buffer &= (1 << bits) - 1;
        }
    }

    if out_idx != 35 || bits != 0 {
        return Err(OnionError::InvalidLength(input.len()));
    }
    Ok(out)
}

#[cfg(test)]
fn encode_base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(BASE32_ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(BASE32_ALPHABET[idx] as char);
    }
    out
}

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
        assert!(RoomId::from_hex_bytes(&raw).is_err());
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
                IdentityHash::from_hex(&value),
                Err(IdError::InvalidHex { .. })
            ));
        }
    }

    #[test]
    fn onion_v3_validates_and_normalizes() {
        let generated = OnionAddress::test_v3_from_seed(7);
        let upper = generated.as_str().to_ascii_uppercase();
        let parsed = OnionAddress::parse(&upper).unwrap();
        assert_eq!(parsed, generated);
        assert_eq!(parsed.service_id().len(), ONION_V3_SERVICE_ID_LEN);

        // Реальный публичный пример Tor v3 адреса.
        let real = "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion";
        assert!(OnionAddress::parse(real).is_ok());
    }

    #[test]
    fn onion_v3_rejects_v2_invalid_chars_and_ports() {
        // v2 (16 символов)
        assert!(OnionAddress::parse("expyuzz4wqqyqhjn.onion").is_err());
        // неверный суффикс или порт
        let valid = OnionAddress::test_v3_from_seed(3);
        assert!(OnionAddress::parse(valid.service_id()).is_err());
        assert!(OnionAddress::parse(&format!("{}:9878", valid)).is_err());
        assert!(OnionAddress::parse(&format!(" {}", valid)).is_err());
        // неверная версия (не 0x03)
        let mut wrong_ver = [1u8; 35];
        wrong_ver[34] = 0x02;
        assert!(matches!(
            OnionAddress::from_service_id(&encode_base32(&wrong_ver)),
            Err(OnionError::UnsupportedVersion(2))
        ));
        // нулевой ключ
        let mut zero_pk = [0u8; 35];
        zero_pk[34] = ONION_V3_VERSION;
        assert!(matches!(
            OnionAddress::from_service_id(&encode_base32(&zero_pk)),
            Err(OnionError::ZeroPublicKey)
        ));
    }
}
