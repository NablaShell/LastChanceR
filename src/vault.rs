// src/vault.rs
//! Защита локальных данных мастер-паролем.
//!
//! Мастер-ключ выводится из пароля через Argon2id и хранится в памяти только
//! внутри [`zeroize::Zeroizing`]. Файлы (`identity.json`, `global.conf`)
//! шифруются XChaCha20-Poly1305 целиком, а чувствительные поля SQLite — по
//! значению (формат `lc1:<hex(nonce || ciphertext)>`).

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::OsRng, RngCore};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

use crate::storage::SafeFSOps;

/// Файл со случайной солью Argon2 (рядом с остальными данными профиля).
pub const SALT_FILE_NAME: &str = "vault.salt";
/// Файл-проверка: зашифрованный маркер, позволяющий отличить неверный пароль.
pub const CHECK_FILE_NAME: &str = "vault.check";
/// Минимальная длина мастер-пароля.
pub const MIN_PASSWORD_LEN: usize = 8;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const FILE_MAGIC: &[u8] = b"LCVAULT1";
const CHECK_FILE_AAD: &[u8] = b"lastchance:vault.check";
const CHECK_VALUE: &[u8] = b"LASTCHANCE-VAULT-V1";
const DB_AAD: &[u8] = b"lastchance:db";
const STR_PREFIX: &str = "lc1:";

/// 32-байтный мастер-ключ. Копии автоматически затираются при освобождении.
#[derive(Clone)]
pub struct MasterKey(Zeroizing<[u8; 32]>);

impl MasterKey {
    /// Шифрует произвольные байты: `nonce || ciphertext || tag`.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*self.0));

        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);

        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("не удалось зашифровать данные"))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Расшифровывает `nonce || ciphertext || tag`.
    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN {
            return Err(anyhow!("зашифрованные данные слишком короткие"));
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&*self.0));
        let (nonce, ciphertext) = data.split_at(NONCE_LEN);

        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("неверный пароль или повреждённые данные"))
    }

    /// Шифрует строку для хранения в SQLite.
    pub fn encrypt_str(&self, value: &str) -> Result<String> {
        let sealed = self.encrypt(value.as_bytes(), DB_AAD)?;
        Ok(format!("{}{}", STR_PREFIX, hex::encode(sealed)))
    }

    /// Расшифровывает строку из SQLite. Значения без префикса считаются
    /// наследием старой версии и возвращаются как есть (миграция выполняется
    /// при открытии базы).
    pub fn decrypt_str(&self, value: &str) -> Result<String> {
        if !is_encrypted_str(value) {
            return Ok(value.to_string());
        }

        let raw = hex::decode(&value[STR_PREFIX.len()..])
            .map_err(|e| anyhow!("повреждённое поле базы: {}", e))?;
        let plaintext = self.decrypt(&raw, DB_AAD)?;
        String::from_utf8(plaintext).map_err(|e| anyhow!("поле базы не является UTF-8: {}", e))
    }
}

/// Выводит мастер-ключ из пароля через Argon2id.
pub fn derive_key(password: &str, salt: &[u8]) -> Result<MasterKey> {
    if password.is_empty() {
        return Err(anyhow!("мастер-пароль не должен быть пустым"));
    }
    if salt.len() < 8 {
        return Err(anyhow!("соль должна быть не короче 8 байт"));
    }

    // Параметры Argon2id: 19 MiB памяти, 2 прохода, 1 поток.
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| anyhow!("некорректные параметры Argon2: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut raw = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *raw)
        .map_err(|e| anyhow!("не удалось вывести мастер-ключ: {}", e))?;

    Ok(MasterKey(raw))
}

/// Генерирует новую случайную соль и ключ (для первого запуска и `/passwd`).
pub fn derive_new(password: &str) -> Result<(Vec<u8>, MasterKey)> {
    let salt = random_salt().to_vec();
    let key = derive_key(password, &salt)?;
    Ok((salt, key))
}

/// Шифрует файл целиком: `LCVAULT1 || nonce || ciphertext || tag`.
pub fn seal_file(key: &MasterKey, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let sealed = key.encrypt(plaintext, aad)?;
    let mut out = Vec::with_capacity(FILE_MAGIC.len() + sealed.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Расшифровывает файл, созданный [`seal_file`].
pub fn open_file(key: &MasterKey, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let sealed = data
        .strip_prefix(FILE_MAGIC)
        .ok_or_else(|| anyhow!("файл не зашифрован или повреждён"))?;
    key.decrypt(sealed, aad)
}

/// Проверяет, что файл зашифрован нашим форматом.
pub fn is_sealed(data: &[u8]) -> bool {
    data.starts_with(FILE_MAGIC)
}

/// Проверяет, что значение колонки SQLite уже зашифровано.
pub fn is_encrypted_str(value: &str) -> bool {
    value.starts_with(STR_PREFIX)
}

/// Записывает соль и проверочный файл для нового ключа.
pub fn write_meta(base_dir: &str, salt: &[u8], key: &MasterKey) -> Result<()> {
    let safe_fs = SafeFSOps::new(base_dir)?;

    let check = seal_file(key, CHECK_FILE_AAD, CHECK_VALUE)?;

    // Сначала соль, потом проверка: оба файла нужны для `is_initialized`.
    safe_fs.safe_write_file(SALT_FILE_NAME, salt, 0o600)?;
    safe_fs.safe_write_file(CHECK_FILE_NAME, &check, 0o600)?;
    Ok(())
}

/// Разделяемая обёртка над мастер-ключом.
///
/// Клоны `Vault` указывают на один и тот же ключ, поэтому после смены пароля
/// достаточно заменить его один раз — все компоненты (`App`, `Storage`,
/// `IdentityManager`) сразу увидят новый ключ.
#[derive(Clone)]
pub struct Vault {
    key: Arc<Mutex<MasterKey>>,
}

impl Vault {
    /// Создаёт новое хранилище с указанным мастер-паролем.
    pub fn create(base_dir: &str, password: &str) -> Result<Self> {
        if password.chars().count() < MIN_PASSWORD_LEN {
            return Err(anyhow!(
                "мастер-пароль должен быть не короче {} символов",
                MIN_PASSWORD_LEN
            ));
        }

        let salt = random_salt();
        let key = derive_key(password, &salt)?;
        write_meta(base_dir, &salt, &key)?;

        Ok(Self {
            key: Arc::new(Mutex::new(key)),
        })
    }

    /// Разблокирует существующее хранилище.
    pub fn unlock(base_dir: &str, password: &str) -> Result<Self> {
        let salt = read_salt(base_dir)?;
        let key = derive_key(password, &salt)?;
        verify_check(base_dir, &key)?;

        Ok(Self {
            key: Arc::new(Mutex::new(key)),
        })
    }

    /// Проверяет, создано ли хранилище в этой директории.
    pub fn is_initialized(base_dir: &str) -> Result<bool> {
        let safe_fs = SafeFSOps::new(base_dir)?;
        Ok(safe_fs.safe_stat(SALT_FILE_NAME).is_ok()
            && safe_fs.safe_stat(CHECK_FILE_NAME).is_ok())
    }

    /// Проверяет пароль без изменения состояния хранилища.
    pub fn verify_password(base_dir: &str, password: &str) -> Result<()> {
        let salt = read_salt(base_dir)?;
        let key = derive_key(password, &salt)?;
        verify_check(base_dir, &key)
    }

    /// Возвращает копию ключа (затирается при освобождении).
    pub fn key(&self) -> Result<MasterKey> {
        self.key
            .lock()
            .map(|key| key.clone())
            .map_err(|_| anyhow!("мастер-ключ недоступен: блокировка повреждена"))
    }

    /// Заменяет ключ во всех клонах `Vault`.
    pub fn replace_key(&self, key: MasterKey) -> Result<()> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| anyhow!("мастер-ключ недоступен: блокировка повреждена"))?;
        *guard = key;
        Ok(())
    }

    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.key()?.encrypt(plaintext, aad)
    }

    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.key()?.decrypt(data, aad)
    }

    pub fn encrypt_str(&self, value: &str) -> Result<String> {
        self.key()?.encrypt_str(value)
    }

    pub fn decrypt_str(&self, value: &str) -> Result<String> {
        self.key()?.decrypt_str(value)
    }

    pub fn seal_file(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        seal_file(&self.key()?, aad, plaintext)
    }

    pub fn open_file(&self, aad: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        open_file(&self.key()?, aad, data)
    }
}

fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn read_salt(base_dir: &str) -> Result<Vec<u8>> {
    let safe_fs = SafeFSOps::new(base_dir)?;
    let salt = safe_fs.safe_read_file(SALT_FILE_NAME)?;
    if salt.len() < 8 {
        return Err(anyhow!("файл соли повреждён: {}", SALT_FILE_NAME));
    }
    Ok(salt)
}

fn verify_check(base_dir: &str, key: &MasterKey) -> Result<()> {
    let safe_fs = SafeFSOps::new(base_dir)?;
    let data = safe_fs.safe_read_file(CHECK_FILE_NAME)?;

    let plaintext =
        open_file(key, CHECK_FILE_AAD, &data).map_err(|_| anyhow!("неверный мастер-пароль"))?;
    if plaintext != CHECK_VALUE {
        return Err(anyhow!("файл проверки мастер-пароля повреждён"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_and_encrypt_roundtrip() {
        let salt = [7u8; SALT_LEN];
        let key = derive_key("correct horse battery staple", &salt).unwrap();
        let another = derive_key("correct horse battery staple", &salt).unwrap();

        let sealed = key.encrypt(b"secret", b"test").unwrap();
        assert_eq!(another.decrypt(&sealed, b"test").unwrap(), b"secret");
        assert!(another.decrypt(&sealed, b"other-aad").is_err());
    }

    #[test]
    fn test_string_fields() {
        let key = derive_key("password-123", &[1u8; SALT_LEN]).unwrap();
        let encrypted = key.encrypt_str("Привет").unwrap();

        assert!(is_encrypted_str(&encrypted));
        assert!(!encrypted.contains("Привет"));
        assert_eq!(key.decrypt_str(&encrypted).unwrap(), "Привет");
        // Наследие старой версии.
        assert_eq!(key.decrypt_str("plain").unwrap(), "plain");
    }

    #[test]
    fn test_file_format() {
        let key = derive_key("password-123", &[2u8; SALT_LEN]).unwrap();
        let sealed = seal_file(&key, b"file", b"payload").unwrap();

        assert!(is_sealed(&sealed));
        assert_eq!(open_file(&key, b"file", &sealed).unwrap(), b"payload");
        assert!(open_file(&key, b"other", &sealed).is_err());
    }

    #[test]
    fn test_vault_create_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();

        let vault = Vault::create(base, "strong-password").unwrap();
        assert!(Vault::is_initialized(base).unwrap());
        let sealed = vault.seal_file(b"aad", b"data").unwrap();

        assert!(Vault::unlock(base, "wrong-password").is_err());
        let reopened = Vault::unlock(base, "strong-password").unwrap();
        assert_eq!(reopened.open_file(b"aad", &sealed).unwrap(), b"data");
    }
}
