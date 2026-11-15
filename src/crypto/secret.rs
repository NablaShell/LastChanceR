//! Обёртки для секретов в памяти (M-5).
//!
//! Секреты (seed-фраза, приватные ключи, корневые ключи храповика) не должны
//! оставаться в куче после `drop`, попадать в логи через `Debug`/`Display`
//! или размножаться неявными `Clone`/`to_vec()`. Типы ниже:
//!
//! * затирают содержимое при освобождении (`ZeroizeOnDrop` из `zeroize`,
//!   который использует volatile-запись и compiler fence);
//! * не реализуют `Clone` — копирование возможно только явным
//!   [`SecretBytes::duplicate`]/[`SecretString::duplicate`] с аудитом;
//! * печатают в `Debug` только `<secret>`/`<redacted>`, без содержимого.
//!
//! Доступ к материалу — только через `expose()`, поэтому все места чтения
//! секрета видны при аудите.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Секретный байтовый буфер произвольной длины.
///
/// Затирается при `drop`; `Debug` не печатает содержимое. `Clone` намеренно
/// не реализован: если копия действительно нужна, используйте
/// [`SecretBytes::duplicate`] и объясните это в ревью.
///
/// ```compile_fail
/// use lastchance::crypto::SecretBytes;
///
/// let secret = SecretBytes::from_slice(b"top-secret");
/// let copy = secret.clone(); // Clone намеренно не реализован
/// ```
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Забирает владение буфером.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Копирует срез в затираемый буфер.
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    /// Явный доступ к секрету. Единственный способ прочитать материал.
    pub fn expose(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Изменяемый доступ для заполнения буфера на месте (например, HKDF).
    pub fn expose_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Явная, аудируемая копия секрета.
    ///
    /// В отличие от `Clone`, вызов невозможно случайно пропустить при
    /// чтении кода: он виден как `duplicate()` и должен быть обоснован.
    pub fn duplicate(&self) -> Self {
        Self::from_slice(self.expose())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

// Формат JSON не меняется: `Vec<u8>` и `serialize_bytes` в serde_json дают
// одинаковый массив чисел, поэтому `identity.json` остаётся совместимым.
impl Serialize for SecretBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.expose())
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(Self::new(bytes))
    }
}

/// Секретная строка (seed-фраза, парольная фраза).
///
/// Как и [`SecretBytes`], затирается при `drop` и не печатает содержимое.
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Явный доступ к секрету.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Явная, аудируемая копия секретной строки.
    pub fn duplicate(&self) -> Self {
        Self::new(self.expose().to_string())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<secret>")
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.expose())
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Self::new(value))
    }
}

macro_rules! fixed_secret {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        ///
        /// Затирается при `drop`, `Debug` печатает только `<redacted>`,
        /// `Clone` намеренно не реализован.
        #[derive(Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; 32]);

        impl $name {
            pub const SIZE: usize = 32;

            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Явный доступ к секрету.
            pub fn expose(&self) -> &[u8; 32] {
                &self.0
            }

            /// Изменяемый доступ для заполнения на месте.
            pub fn expose_mut(&mut self) -> &mut [u8; 32] {
                &mut self.0
            }

            /// Явная, аудируемая копия секрета.
            pub fn duplicate(&self) -> Self {
                Self(self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("<redacted>")
            }
        }
    };
}

fixed_secret! {
    /// Seed для вывода Ed25519-ключа.
    Ed25519Seed
}

fixed_secret! {
    /// Приватный X25519-ключ.
    X25519Priv
}

fixed_secret! {
    /// Корневой ключ эпохи Double Ratchet.
    RootKey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let secret = SecretBytes::from_slice(b"top-secret-material");
        assert_eq!(format!("{:?}", secret), "<secret>");
        assert!(!format!("{:?}", secret).contains("top-secret"));
        assert_eq!(secret.expose(), b"top-secret-material");
    }

    #[test]
    fn secret_string_debug_is_redacted() {
        let secret = SecretString::new("abandon abandon about".to_string());
        assert_eq!(format!("{:?}", secret), "<secret>");
        assert!(!format!("{:?}", secret).contains("abandon"));
        assert_eq!(secret.expose(), "abandon abandon about");
    }

    #[test]
    fn fixed_secret_debug_is_redacted() {
        let seed = Ed25519Seed::from_bytes([0xAB; 32]);
        assert_eq!(format!("{:?}", seed), "<redacted>");

        let private = X25519Priv::from_bytes([0xCD; 32]);
        assert_eq!(format!("{:?}", private), "<redacted>");

        let root = RootKey::from_bytes([0xEF; 32]);
        assert_eq!(format!("{:?}", root), "<redacted>");
    }

    /// Проверяет Drop-хук на стековом буфере фиксированной длины.
    ///
    /// `SecretBytes` использует тот же `Zeroizing`, но его буфер живёт в
    /// куче и после `drop` освобождается, поэтому читать его напрямую
    /// нельзя. Здесь достаточно доказать, что `ZeroizeOnDrop` действительно
    /// обнуляет память.
    #[test]
    fn fixed_secret_is_wiped_on_drop() {
        let mut root = std::mem::ManuallyDrop::new(RootKey::from_bytes([0xAB; 32]));
        let ptr = root.expose().as_ptr();

        // SAFETY: `ManuallyDrop::drop` выполняет `ZeroizeOnDrop`, но не
        // освобождает память; указатель остаётся валидным для чтения
        // внутри текущей области видимости.
        unsafe {
            std::mem::ManuallyDrop::drop(&mut root);
            for index in 0..RootKey::SIZE {
                assert_eq!(ptr.add(index).read(), 0, "byte {index} was not wiped");
            }
        }
    }

    #[test]
    fn arc_secret_is_shared_without_deep_copy() {
        use std::sync::Arc;

        // Так listener получает ключ: один буфер, разделяемый через Arc.
        let secret = Arc::new(SecretBytes::from_slice(b"listener-key"));
        let shared = Arc::clone(&secret);

        assert_eq!(Arc::strong_count(&secret), 2);
        assert_eq!(shared.expose(), b"listener-key");

        drop(shared);
        assert_eq!(Arc::strong_count(&secret), 1);

        // Последний Arc передаёт владение SecretBytes, который затирает
        // буфер через Zeroizing при drop.
        drop(secret);
    }

    #[test]
    fn duplicate_creates_independent_secret_copy() {
        let mut original = SecretBytes::from_slice(&[1, 2, 3, 4]);
        let copy = original.duplicate();
        original.expose_mut()[0] = 9;

        assert_eq!(copy.expose(), &[1, 2, 3, 4]);
        assert_eq!(original.expose(), &[9, 2, 3, 4]);
    }

    #[test]
    fn secret_bytes_json_format_matches_vec() {
        let bytes = SecretBytes::new(vec![1, 2, 3, 4]);
        let encoded = serde_json::to_string(&bytes).unwrap();
        assert_eq!(encoded, serde_json::to_string(&vec![1u8, 2, 3, 4]).unwrap());

        let decoded: SecretBytes = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.expose(), &[1, 2, 3, 4]);
    }

    #[test]
    fn secret_string_json_round_trips() {
        let value = SecretString::new("abandon abandon about".to_string());
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(encoded, "\"abandon abandon about\"");

        let decoded: SecretString = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.expose(), "abandon abandon about");
    }
}
