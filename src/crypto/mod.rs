// src/crypto/mod.rs
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
use anyhow::{anyhow, Result};

pub mod ratchet;
pub mod secret;

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

pub const SIZE_TINY: usize = 256;
pub const SIZE_SMALL: usize = 1024;
pub const SIZE_MEDIUM: usize = 4096;
pub const SIZE_MAX: usize = 65536;

pub const ALLOWED_TOTAL_SIZES: [usize; 4] = [SIZE_TINY, SIZE_SMALL, SIZE_MEDIUM, SIZE_MAX];

// ECDH Key Exchange
pub fn generate_shared_key(my_private_key: &[u8], their_public_key: &[u8]) -> Result<[u8; 32]> {
    if my_private_key.len() != 32 {
        return Err(anyhow!("private key must be 32 bytes, got {}", my_private_key.len()));
    }
    if their_public_key.len() != 32 {
        return Err(anyhow!("public key must be 32 bytes, got {}", their_public_key.len()));
    }

    let mut private_bytes = [0u8; 32];
    private_bytes.copy_from_slice(my_private_key);
    let private_key = StaticSecret::from(private_bytes);

    let mut public_bytes = [0u8; 32];
    public_bytes.copy_from_slice(their_public_key);
    let public_key = PublicKey::from(public_bytes);

    let shared_secret = private_key.diffie_hellman(&public_key);

    // X25519 не кодирует валидность точки в public key. Низкопорядковые
    // точки дают all-zero shared secret, который нельзя использовать как
    // ключ (это классический invalid-curve/small-subgroup вектор).
    if !shared_secret.was_contributory() {
        return Err(anyhow!(
            "invalid X25519 public key: shared secret is all-zero (low-order point)"
        ));
    }

    // HKDF derivation
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut final_key = [0u8; 32];
    hkdf.expand(b"ECDH_v1", &mut final_key)
        .map_err(|e| anyhow!("HKDF derivation failed: {}", e))?;

    Ok(final_key)
}

// ---------------------------------------------------------------------------
// E2E application envelope (внутри уже зашифрованного кадра)
// ---------------------------------------------------------------------------

/// Магия внутреннего конверта. Она зашифрована вместе с кадром и на диск
/// никогда не попадает.
pub const E2E_MAGIC: &[u8; 4] = b"LCE1";

const E2E_KIND_TEXT: u8 = 1;
const E2E_KIND_SET_TTL: u8 = 2;
const E2E_KIND_RATCHET_RESET: u8 = 3;
const E2E_HEADER_MIN: usize = 6; // magic + kind + optional-flag

/// Расшифрованная полезная нагрузка E2E-сообщения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum E2ePayload {
    /// Обычный текст. `ttl_seconds` приходит только от клиентов,
    /// поддерживающих синхронизированный RAM-TTL.
    Text {
        text: String,
        ttl_seconds: Option<u64>,
    },
    /// Управляющий сигнал двустороннего TTL.
    SetTtl { seconds: Option<u64> },
    /// Собеседник сбросил сессию Double Ratchet: локальное состояние
    /// нужно заново инициализировать из общего секрета.
    RatchetReset,
}

fn write_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn read_optional_u64(payload: &[u8], pos: &mut usize) -> Result<Option<u64>> {
    let flag = *payload
        .get(*pos)
        .ok_or_else(|| anyhow!("truncated e2e payload"))?;
    *pos += 1;

    match flag {
        0 => Ok(None),
        1 => {
            let end = pos
                .checked_add(8)
                .ok_or_else(|| anyhow!("e2e payload length overflow"))?;
            let bytes = payload
                .get(*pos..end)
                .ok_or_else(|| anyhow!("truncated e2e payload"))?;
            *pos = end;
            let value = u64::from_le_bytes(
                bytes
                    .try_into()
                    .map_err(|_| anyhow!("invalid e2e ttl field"))?,
            );
            Ok(Some(value))
        }
        other => Err(anyhow!("invalid e2e optional flag: {}", other)),
    }
}

/// Собирает текстовый конверт с необязательным TTL.
pub fn encode_text_payload(text: &str, ttl_seconds: Option<u64>) -> Vec<u8> {
    let mut out = Vec::with_capacity(E2E_HEADER_MIN + 8 + text.len());
    out.extend_from_slice(E2E_MAGIC);
    out.push(E2E_KIND_TEXT);
    write_optional_u64(&mut out, ttl_seconds);
    out.extend_from_slice(text.as_bytes());
    out
}

/// Собирает управляющий пакет `SetTtl { seconds }`.
pub fn encode_set_ttl(seconds: Option<u64>) -> Vec<u8> {
    let mut out = Vec::with_capacity(E2E_HEADER_MIN + 8);
    out.extend_from_slice(E2E_MAGIC);
    out.push(E2E_KIND_SET_TTL);
    write_optional_u64(&mut out, seconds);
    out
}

/// Собирает управляющий пакет сброса храповика.
pub fn encode_ratchet_reset() -> Vec<u8> {
    let mut out = Vec::with_capacity(E2E_HEADER_MIN);
    out.extend_from_slice(E2E_MAGIC);
    out.push(E2E_KIND_RATCHET_RESET);
    out
}

/// Разбирает полезную нагрузку. Сообщения без магии считаются обычным
/// текстом: это сохраняет совместимость со старыми клиентами.
pub fn decode_payload(payload: &[u8]) -> Result<E2ePayload> {
    if payload.len() < E2E_MAGIC.len() + 1 || &payload[..E2E_MAGIC.len()] != E2E_MAGIC {
        return Ok(E2ePayload::Text {
            text: String::from_utf8_lossy(payload).to_string(),
            ttl_seconds: None,
        });
    }

    let kind = payload[E2E_MAGIC.len()];
    let mut pos = E2E_MAGIC.len() + 1;

    match kind {
        E2E_KIND_TEXT => {
            let ttl_seconds = read_optional_u64(payload, &mut pos)?;
            Ok(E2ePayload::Text {
                text: String::from_utf8_lossy(&payload[pos..]).to_string(),
                ttl_seconds,
            })
        }
        E2E_KIND_SET_TTL => {
            let seconds = read_optional_u64(payload, &mut pos)?;
            if pos != payload.len() {
                return Err(anyhow!("trailing bytes in SetTtl payload"));
            }
            Ok(E2ePayload::SetTtl { seconds })
        }
        E2E_KIND_RATCHET_RESET => {
            if pos != payload.len() {
                return Err(anyhow!("trailing bytes in RatchetReset payload"));
            }
            Ok(E2ePayload::RatchetReset)
        }
        other => Err(anyhow!("unknown e2e payload kind: {}", other)),
    }
}

// ---------------------------------------------------------------------------
// File envelope v3 (M-4)
// ---------------------------------------------------------------------------
//
// Формат:
//
//   [ ver u8 = 3 ][ file_id 16 ][ nonce 24 ][ AEAD(inner) ][ tag 16 ]
//
// `inner` целиком лежит внутри AEAD:
//
//   [ name_len u16 ][ name ][ size u64 ][ padded_size u64 ][ payload ][ zero padding ]
//
// AAD привязывает версию, `file_id`, комнату и пару личностей. Имя и размеры
// не видны серверу; `padded_size` выбирается по bucket-сетке с рандомизацией
// внутри bucket, поэтому точный размер файла не коррелирует с объёмом.

/// Версия файлового конверта. v2 (nonce || ciphertext без AAD) не читается.
pub const FILE_VERSION_V3: u8 = 3;
/// Размер случайного `file_id`.
pub const FILE_ID_SIZE: usize = 16;
/// Максимальный реальный размер файла (100 MiB).
pub const FILE_MAX_PLAINTEXT: usize = 100 * 1024 * 1024;
/// Максимальный размер файлового конверта на проводе (128 MiB).
pub const FILE_MAX_ENVELOPE: usize = 128 * 1024 * 1024;
/// Максимальная длина имени файла внутри конверта.
pub const FILE_NAME_MAX: usize = 1024;
/// `version (1) + file_id (16) + nonce (24)`.
pub const FILE_HEADER_SIZE: usize = 1 + FILE_ID_SIZE + NONCE_SIZE;

const FILE_INNER_FIXED: usize = 2 + 8 + 8;
const FILE_KEY_INFO: &[u8] = b"file-v3";
const FILE_AAD_LABEL: &[u8] = b"lastchance-file-v3";

/// Сетка паддинга файла. Последний bucket покрывает [`FILE_MAX_PLAINTEXT`].
pub const FILE_PADDING_BUCKETS: [usize; 10] = [
    1024,
    4096,
    16 * 1024,
    64 * 1024,
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
    16 * 1024 * 1024,
    64 * 1024 * 1024,
    112 * 1024 * 1024,
];

/// Типизированные ошибки файлового конверта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    /// Конверт собран по несовместимой версии (старый файл или подделка).
    UnsupportedVersion(u8),
    /// AEAD-тег не сошёлся: подмена AAD, заголовка или шифротекста.
    AadMismatch,
    /// Паддинг/размеры не соответствуют политике конверта.
    PaddingInvalid(&'static str),
    /// Конверт или открытый текст превышает лимит.
    TooLarge { size: usize, limit: usize },
    /// Имя файла внутри конверта некорректно.
    NameInvalid(&'static str),
    /// Структура конверта повреждена.
    Malformed(&'static str),
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported file envelope version: {}", version)
            }
            Self::AadMismatch => write!(f, "file envelope authentication failed"),
            Self::PaddingInvalid(reason) => write!(f, "invalid file padding: {}", reason),
            Self::TooLarge { size, limit } => {
                write!(f, "file envelope too large: {} > {} bytes", size, limit)
            }
            Self::NameInvalid(reason) => write!(f, "invalid file name: {}", reason),
            Self::Malformed(reason) => write!(f, "malformed file envelope: {}", reason),
        }
    }
}

impl std::error::Error for FileError {}

/// Открытый файл, полученный из v3-конверта.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedFile {
    pub file_id: [u8; FILE_ID_SIZE],
    pub name: String,
    pub size: u64,
    /// Размер payload вместе с паддингом (по bucket-сетке).
    pub padded_size: u64,
    pub data: Vec<u8>,
}

fn file_key(shared_secret: &[u8; 32], file_id: &[u8; FILE_ID_SIZE]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(file_id), shared_secret);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(FILE_KEY_INFO, key.as_mut())
        .map_err(|e| anyhow!("file HKDF expansion failed: {}", e))?;
    Ok(key)
}

/// AAD файлового конверта.
///
/// Пара личностей канонизируется лексикографически. Это сохраняет
/// привязку к обоим участникам и не зависит от того, кто скачивает файл
/// (отправитель или получатель), при этом файл из другой пары/комнаты
/// расшифровать нельзя.
pub fn file_aad(
    file_id: &[u8; FILE_ID_SIZE],
    room_id: &str,
    sender: &str,
    recipient: &str,
) -> Vec<u8> {
    let (low, high) = if sender <= recipient {
        (sender, recipient)
    } else {
        (recipient, sender)
    };

    let mut aad = Vec::with_capacity(
        FILE_AAD_LABEL.len() + 1 + FILE_ID_SIZE + 12 + room_id.len() + low.len() + high.len(),
    );
    aad.extend_from_slice(FILE_AAD_LABEL);
    aad.push(FILE_VERSION_V3);
    aad.extend_from_slice(file_id);
    for part in [room_id, low, high] {
        aad.extend_from_slice(&(part.len() as u32).to_le_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    aad
}

/// Выбирает `padded_size` по bucket-сетке с рандомизацией внутри bucket.
///
/// `padded_size >= plaintext_len`, но не больше `bucket + bucket / 8`.
fn padded_file_size(plaintext_len: usize) -> Result<usize> {
    if plaintext_len > FILE_MAX_PLAINTEXT {
        return Err(FileError::TooLarge {
            size: plaintext_len,
            limit: FILE_MAX_PLAINTEXT,
        }
        .into());
    }
    let bucket = FILE_PADDING_BUCKETS
        .iter()
        .copied()
        .find(|bucket| *bucket >= plaintext_len)
        .ok_or(FileError::TooLarge {
            size: plaintext_len,
            limit: FILE_MAX_PLAINTEXT,
        })?;

    let extra_max = bucket / 8;
    let extra = if extra_max == 0 {
        0
    } else {
        (OsRng.next_u64() % (extra_max as u64 + 1)) as usize
    };

    Ok(bucket + extra)
}

/// Шифрует файл в конверт v3.
///
/// `name` и реальный размер попадают только внутрь AEAD. Ключ файла
/// выводится как `HKDF(shared_secret, salt = file_id, info = "file-v3")`,
/// поэтому один и тот же контактный секрет не используется напрямую.
pub fn encrypt_file_v3(
    plaintext: &[u8],
    name: &str,
    shared_secret: &[u8; 32],
    room_id: &str,
    sender: &str,
    recipient: &str,
) -> Result<Vec<u8>> {
    if plaintext.len() > FILE_MAX_PLAINTEXT {
        return Err(FileError::TooLarge {
            size: plaintext.len(),
            limit: FILE_MAX_PLAINTEXT,
        }
        .into());
    }
    if name.is_empty() {
        return Err(FileError::NameInvalid("empty").into());
    }
    if name.len() > FILE_NAME_MAX {
        return Err(FileError::NameInvalid("too long").into());
    }
    let name_len = u16::try_from(name.len())
        .map_err(|_| FileError::NameInvalid("does not fit into u16"))?;
    let size = u64::try_from(plaintext.len())
        .map_err(|_| FileError::TooLarge {
            size: plaintext.len(),
            limit: FILE_MAX_PLAINTEXT,
        })?;

    let padded_size = padded_file_size(plaintext.len())?;
    let inner_len = FILE_INNER_FIXED
        .checked_add(name.len())
        .and_then(|value| value.checked_add(padded_size))
        .ok_or(FileError::TooLarge {
            size: padded_size,
            limit: FILE_MAX_PLAINTEXT,
        })?;

    let envelope_len = FILE_HEADER_SIZE
        .checked_add(inner_len)
        .and_then(|value| value.checked_add(TAG_SIZE))
        .ok_or(FileError::TooLarge {
            size: inner_len,
            limit: FILE_MAX_ENVELOPE,
        })?;
    if envelope_len > FILE_MAX_ENVELOPE {
        return Err(FileError::TooLarge {
            size: envelope_len,
            limit: FILE_MAX_ENVELOPE,
        }
        .into());
    }

    let mut file_id = [0u8; FILE_ID_SIZE];
    OsRng.fill_bytes(&mut file_id);
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut inner = Zeroizing::new(vec![0u8; inner_len]);
    inner[..2].copy_from_slice(&name_len.to_le_bytes());
    let name_end = 2 + name.len();
    inner[2..name_end].copy_from_slice(name.as_bytes());
    inner[name_end..name_end + 8].copy_from_slice(&size.to_le_bytes());
    let padded_end = name_end + 16;
    inner[name_end + 8..padded_end].copy_from_slice(&(padded_size as u64).to_le_bytes());

    let data_end = padded_end + plaintext.len();
    inner[padded_end..data_end].copy_from_slice(plaintext);
    // Хвост остаётся нулевым: конверт проверяет это при расшифровке.

    let key = file_key(shared_secret, &file_id)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow!("invalid file key"))?;
    let aad = file_aad(&file_id, room_id, sender, recipient);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: inner.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow!("file encryption failed"))?;

    let mut envelope = Vec::with_capacity(FILE_HEADER_SIZE + ciphertext.len());
    envelope.push(FILE_VERSION_V3);
    envelope.extend_from_slice(&file_id);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    if envelope.len() != envelope_len {
        return Err(anyhow!("file envelope size mismatch"));
    }
    Ok(envelope)
}

/// Расшифровывает конверт v3 и проверяет AAD, имя и паддинг.
///
/// Лимит проверяется по длине конверта до AEAD-аллокации. Старый
/// nonce||ciphertext-формат отклоняется как `UnsupportedVersion` (fail-closed).
pub fn decrypt_file_v3(
    envelope: &[u8],
    shared_secret: &[u8; 32],
    room_id: &str,
    sender: &str,
    recipient: &str,
) -> Result<DecryptedFile> {
    if envelope.len() < FILE_HEADER_SIZE + TAG_SIZE + FILE_INNER_FIXED {
        return Err(FileError::Malformed("too short").into());
    }
    if envelope.len() > FILE_MAX_ENVELOPE {
        return Err(FileError::TooLarge {
            size: envelope.len(),
            limit: FILE_MAX_ENVELOPE,
        }
        .into());
    }
    if envelope[0] != FILE_VERSION_V3 {
        return Err(FileError::UnsupportedVersion(envelope[0]).into());
    }

    let mut file_id = [0u8; FILE_ID_SIZE];
    file_id.copy_from_slice(&envelope[1..1 + FILE_ID_SIZE]);
    let nonce_start = 1 + FILE_ID_SIZE;
    let nonce = XNonce::from_slice(&envelope[nonce_start..nonce_start + NONCE_SIZE]);
    let ciphertext = &envelope[FILE_HEADER_SIZE..];

    let key = file_key(shared_secret, &file_id)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow!("invalid file key"))?;
    let aad = file_aad(&file_id, room_id, sender, recipient);
    let inner = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| FileError::AadMismatch)?,
    );

    if inner.len() < FILE_INNER_FIXED {
        return Err(FileError::Malformed("inner too short").into());
    }

    let name_len = u16::from_le_bytes(
        inner[..2]
            .try_into()
            .map_err(|_| FileError::Malformed("name length"))?,
    ) as usize;
    if name_len == 0 || name_len > FILE_NAME_MAX {
        return Err(FileError::NameInvalid("length out of range").into());
    }
    let name_end = 2usize
        .checked_add(name_len)
        .ok_or(FileError::Malformed("name length overflow"))?;
    if name_end + 16 > inner.len() {
        return Err(FileError::Malformed("truncated name/header").into());
    }

    let name = std::str::from_utf8(&inner[2..name_end])
        .map_err(|_| FileError::NameInvalid("not UTF-8"))?
        .to_string();
    let size = u64::from_le_bytes(
        inner[name_end..name_end + 8]
            .try_into()
            .map_err(|_| FileError::Malformed("size"))?,
    );
    let padded_size = u64::from_le_bytes(
        inner[name_end + 8..name_end + 16]
            .try_into()
            .map_err(|_| FileError::Malformed("padded size"))?,
    );

    let payload_start = name_end + 16;
    let payload_len = inner
        .len()
        .checked_sub(payload_start)
        .ok_or(FileError::Malformed("payload start"))?;
    if padded_size != payload_len as u64 {
        return Err(FileError::PaddingInvalid("padded_size does not match payload").into());
    }
    if size > padded_size {
        return Err(FileError::PaddingInvalid("size exceeds padded_size").into());
    }
    if padded_size > FILE_MAX_ENVELOPE as u64 {
        return Err(FileError::PaddingInvalid("padded_size exceeds limit").into());
    }
    let size_usize = usize::try_from(size)
        .map_err(|_| FileError::PaddingInvalid("size does not fit usize"))?;
    if inner[payload_start + size_usize..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(FileError::PaddingInvalid("non-zero tail").into());
    }

    Ok(DecryptedFile {
        file_id,
        name,
        size,
        padded_size,
        data: inner[payload_start..payload_start + size_usize].to_vec(),
    })
}

// Ed25519 functions
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};
use hex;

pub fn generate_ed25519_key_from_seed(seed: &[u8]) -> Result<SigningKey> {
    if seed.len() != 32 {
        return Err(anyhow!("seed must be exactly 32 bytes, got {}", seed.len()));
    }
    let mut seed_array = [0u8; 32];
    seed_array.copy_from_slice(seed);
    Ok(SigningKey::from_bytes(&seed_array))
}

pub fn sign_ed25519(private_key: &SigningKey, message: &[u8]) -> String {
    let signature = private_key.sign(message);
    hex::encode(signature.to_bytes())
}

pub fn verify_ed25519(
    public_key: &VerifyingKey,
    message: &[u8],
    signature_hex: &str,
) -> Result<bool> {
    let signature_bytes = hex::decode(signature_hex)
        .map_err(|e| anyhow!("invalid signature hex: {}", e))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|e| anyhow!("invalid signature: {}", e))?;
    
    Ok(public_key.verify(message, &signature).is_ok())
}

pub fn compute_identity_hash(public_key: &VerifyingKey) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(public_key.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::{PublicKey, StaticSecret};

    #[test]
    fn test_generate_shared_key() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let bob_secret = StaticSecret::random_from_rng(OsRng);
        
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);
        
        let alice_shared = generate_shared_key(
            alice_secret.as_bytes(),
            bob_public.as_bytes(),
        ).unwrap();
        
        let bob_shared = generate_shared_key(
            bob_secret.as_bytes(),
            alice_public.as_bytes(),
        ).unwrap();
        
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn ecdh_rejects_low_order_public_keys() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        let zero = [0u8; 32];
        assert!(generate_shared_key(alice_secret.as_bytes(), &zero).is_err());

        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(generate_shared_key(alice_secret.as_bytes(), &one).is_err());
    }

    #[test]
    fn e2e_text_envelope_round_trips_ttl() {
        let payload = encode_text_payload("исчезающее сообщение", Some(30));
        assert_eq!(
            decode_payload(&payload).unwrap(),
            E2ePayload::Text {
                text: "исчезающее сообщение".to_string(),
                ttl_seconds: Some(30),
            }
        );
    }

    #[test]
    fn e2e_set_ttl_envelope_round_trips() {
        assert_eq!(
            decode_payload(&encode_set_ttl(Some(5 * 60))).unwrap(),
            E2ePayload::SetTtl { seconds: Some(300) }
        );
        assert_eq!(
            decode_payload(&encode_set_ttl(None)).unwrap(),
            E2ePayload::SetTtl { seconds: None }
        );
    }

    #[test]
    fn e2e_ratchet_reset_envelope_round_trips() {
        assert_eq!(
            decode_payload(&encode_ratchet_reset()).unwrap(),
            E2ePayload::RatchetReset
        );
    }

    #[test]
    fn legacy_plaintext_is_still_text() {
        assert_eq!(
            decode_payload(b"hello old client").unwrap(),
            E2ePayload::Text {
                text: "hello old client".to_string(),
                ttl_seconds: None,
            }
        );
    }

    // -----------------------------------------------------------------
    // File envelope v3 (M-4)
    // -----------------------------------------------------------------

    const FILE_ROOM: &str = "room-a";
    const FILE_SENDER: &str = "sender-a";
    const FILE_RECIPIENT: &str = "recipient-b";

    fn seal_inner(inner: &[u8], file_id: [u8; FILE_ID_SIZE]) -> Vec<u8> {
        let shared = [9u8; 32];
        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let key = file_key(&shared, &file_id).unwrap();
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let aad = file_aad(&file_id, FILE_ROOM, FILE_SENDER, FILE_RECIPIENT);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: inner,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut envelope = Vec::new();
        envelope.push(FILE_VERSION_V3);
        envelope.extend_from_slice(&file_id);
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        envelope
    }

    fn name_size_offset(name: &str) -> usize {
        2 + name.len()
    }

    fn inner_frame(name: &str, size: u64, padded_size: u64, data: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&(name.len() as u16).to_le_bytes());
        inner.extend_from_slice(name.as_bytes());
        inner.extend_from_slice(&size.to_le_bytes());
        inner.extend_from_slice(&padded_size.to_le_bytes());
        inner.extend_from_slice(data);
        inner.resize(inner.len() + (padded_size as usize).saturating_sub(data.len()), 0);
        inner
    }

    fn decrypt_with_shared(envelope: &[u8], shared: &[u8; 32]) -> Result<DecryptedFile> {
        decrypt_file_v3(
            envelope,
            shared,
            FILE_ROOM,
            FILE_SENDER,
            FILE_RECIPIENT,
        )
    }

    #[test]
    fn file_v3_round_trips_name_size_and_content() {
        let shared = [9u8; 32];
        let data = b"secret file bytes";
        let envelope = encrypt_file_v3(
            data,
            "report.txt",
            &shared,
            FILE_ROOM,
            FILE_SENDER,
            FILE_RECIPIENT,
        )
        .unwrap();

        assert_eq!(envelope[0], FILE_VERSION_V3);
        assert!(
            !envelope.windows(10).any(|window| window == b"report.txt"),
            "file name must not appear in plaintext"
        );

        let file = decrypt_with_shared(&envelope, &shared).unwrap();
        assert_eq!(file.name, "report.txt");
        assert_eq!(file.size, data.len() as u64);
        assert_eq!(file.data, data);
        assert_eq!(file.file_id, envelope[1..1 + FILE_ID_SIZE]);
        assert!(file.padded_size >= file.size);
    }

    #[test]
    fn file_v3_tampered_name_and_sizes_fail_aead() {
        let shared = [9u8; 32];
        let envelope = encrypt_file_v3(
            b"payload",
            "name.txt",
            &shared,
            FILE_ROOM,
            FILE_SENDER,
            FILE_RECIPIENT,
        )
        .unwrap();

        // Имя лежит в начале inner: 2 байта длины, затем байты имени.
        for offset in [0usize, 2, FILE_HEADER_SIZE + 2 + 5 + 2] {
            let mut tampered = envelope.clone();
            tampered[FILE_HEADER_SIZE + offset] ^= 0x01;
            let error = decrypt_with_shared(&tampered, &shared).unwrap_err();
            assert!(
                matches!(error.downcast_ref::<FileError>(), Some(FileError::AadMismatch)),
                "offset {}: {:#}",
                offset,
                error
            );
        }
    }

    #[test]
    fn file_v3_rejects_wrong_room_and_identity_pair() {
        let shared = [9u8; 32];
        let envelope = encrypt_file_v3(
            b"payload",
            "name.txt",
            &shared,
            FILE_ROOM,
            FILE_SENDER,
            FILE_RECIPIENT,
        )
        .unwrap();

        assert!(matches!(
            decrypt_file_v3(&envelope, &shared, "room-b", FILE_SENDER, FILE_RECIPIENT)
                .unwrap_err()
                .downcast_ref::<FileError>(),
            Some(FileError::AadMismatch)
        ));
        assert!(matches!(
            decrypt_file_v3(&envelope, &shared, FILE_ROOM, "sender-x", "recipient-y")
                .unwrap_err()
                .downcast_ref::<FileError>(),
            Some(FileError::AadMismatch)
        ));
        assert!(matches!(
            decrypt_file_v3(&envelope, &shared, FILE_ROOM, "sender-x", FILE_RECIPIENT)
                .unwrap_err()
                .downcast_ref::<FileError>(),
            Some(FileError::AadMismatch)
        ));
    }

    #[test]
    fn file_v3_padding_policy_is_enforced() {
        let shared = [9u8; 32];
        let file_id = [3u8; FILE_ID_SIZE];

        // padded_size == size допустим.
        let inner = inner_frame("a.txt", 3, 3, b"abc");
        let file = decrypt_with_shared(&seal_inner(&inner, file_id), &shared).unwrap();
        assert_eq!(file.data, b"abc");

        // padded_size < size отклоняется.
        let inner = inner_frame("a.txt", 4, 3, b"abc");
        let error = decrypt_with_shared(&seal_inner(&inner, file_id), &shared).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<FileError>(),
            Some(FileError::PaddingInvalid("size exceeds padded_size"))
        ));

        // Ненулевой хвост отклоняется.
        let mut inner = inner_frame("a.txt", 3, 8, b"abc");
        *inner.last_mut().unwrap() = 1;
        let error = decrypt_with_shared(&seal_inner(&inner, file_id), &shared).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<FileError>(),
            Some(FileError::PaddingInvalid("non-zero tail"))
        ));

        // padded_size не совпадает с фактическим payload.
        let mut inner = inner_frame("a.txt", 3, 8, b"abc");
        inner[name_size_offset("a.txt") + 8..name_size_offset("a.txt") + 16]
            .copy_from_slice(&9u64.to_le_bytes());
        let error = decrypt_with_shared(&seal_inner(&inner, file_id), &shared).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<FileError>(),
            Some(FileError::PaddingInvalid(
                "padded_size does not match payload"
            ))
        ));
    }

    #[test]
    fn file_v3_padding_is_randomized_within_bucket() {
        let shared = [9u8; 32];
        let mut sizes = Vec::new();
        for _ in 0..8 {
            let envelope =
                encrypt_file_v3(b"same size", "x.bin", &shared, FILE_ROOM, FILE_SENDER, FILE_RECIPIENT)
                    .unwrap();
            let file = decrypt_with_shared(&envelope, &shared).unwrap();
            assert!(file.padded_size >= 1024 && file.padded_size <= 1024 + 1024 / 8);
            sizes.push(file.padded_size);
        }
        assert!(
            sizes.windows(2).any(|pair| pair[0] != pair[1]),
            "randomized padding must vary within the bucket: {:?}",
            sizes
        );
    }

    #[test]
    fn file_v3_rejects_oversize_before_allocation() {
        assert!(matches!(
            padded_file_size(FILE_MAX_PLAINTEXT + 1).unwrap_err().downcast_ref::<FileError>(),
            Some(FileError::TooLarge { .. })
        ));
    }

    #[test]
    fn legacy_file_envelope_is_rejected() {
        let shared = [9u8; 32];
        let mut legacy = vec![2u8];
        legacy.resize(FILE_HEADER_SIZE + TAG_SIZE + FILE_INNER_FIXED, 0);
        let error = decrypt_with_shared(&legacy, &shared).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<FileError>(),
            Some(FileError::UnsupportedVersion(2))
        ));
    }

}
