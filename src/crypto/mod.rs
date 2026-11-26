// src/crypto/mod.rs
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
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

/// Канонические u-координаты X25519-точек малого порядка (1, 2, 4 и 8).
///
/// DH с любой из них даёт нулевой общий секрет. [`generate_shared_key`] и
/// ratchet дополнительно проверяют `was_contributory()`, поэтому этот список
/// — дешёвый fail-closed фильтр до скалярного умножения и KDF.
const LOW_ORDER_X25519_POINTS: [[u8; 32]; 7] = [
    // 0 (порядок 4)
    [0; 32],
    // 1 (порядок 1)
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // 325606250916557431795983626356110631294008115727848805560023387167927233504 (порядок 8)
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (порядок 8)
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    // p - 1 (порядок 2)
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p (порядок 4)
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // p + 1 (порядок 1)
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Проверяет публичный X25519-ключ собеседника до ECDH.
///
/// Единая точка проверки для всех ECDH-путей (L-7, покрыто C-1).
/// Отклоняет all-zero и low-order точки, включая кодировки, которые
/// отличаются только игнорируемым старшим битом (RFC 7748 маскирует бит 255).
/// Проверка не паникует на произвольных 32 байтах и возвращает ошибку вместо
/// невалидного общего секрета.
pub fn validate_x25519_peer(their_public_key: &[u8]) -> Result<()> {
    let mut key: [u8; 32] = their_public_key.try_into().map_err(|_| {
        anyhow!(
            "public key must be 32 bytes, got {}",
            their_public_key.len()
        )
    })?;
    key[31] &= 0x7f;

    if LOW_ORDER_X25519_POINTS.contains(&key) {
        return Err(anyhow!(
            "invalid X25519 public key: all-zero or low-order point"
        ));
    }
    Ok(())
}

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
    validate_x25519_peer(&public_bytes)?;
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
// Padding helpers (used by ratchet and vault.dat)
// ---------------------------------------------------------------------------

/// Подбирает размер по bucket-сетке с рандомизацией внутри bucket.
///
/// Возвращает `bucket + jitter`, где `bucket` — первый элемент сетки
/// `>= len`, а `jitter` равномерно распределён в `[0, bucket / 8]`.
/// Возвращает `None`, если `len` больше последнего bucket’а.
pub(crate) fn padded_bucket_len(len: usize, buckets: &[usize]) -> Option<usize> {
    let bucket = buckets.iter().copied().find(|bucket| *bucket >= len)?;
    let extra_max = bucket / 8;
    let extra = if extra_max == 0 {
        0
    } else {
        (OsRng.next_u64() % (extra_max as u64 + 1)) as usize
    };

    Some(bucket + extra)
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
    fn ecdh_rejects_all_low_order_public_keys() {
        let alice_secret = StaticSecret::random_from_rng(OsRng);
        for point in LOW_ORDER_X25519_POINTS {
            assert!(
                generate_shared_key(alice_secret.as_bytes(), &point).is_err(),
                "low-order point must be rejected: {:02x?}",
                point
            );
        }
    }

    #[test]
    fn validate_x25519_peer_rejects_low_order_without_panicking() {
        let probe = StaticSecret::random_from_rng(OsRng);
        for point in LOW_ORDER_X25519_POINTS {
            // Список должен содержать именно низкопорядковые точки: DH с
            // любой из них даёт невкладной (all-zero) секрет.
            assert!(!probe
                .diffie_hellman(&PublicKey::from(point))
                .was_contributory());
            assert!(validate_x25519_peer(&point).is_err());

            // Тот же ключ с выставленным игнорируемым старшим битом.
            let mut non_canonical = point;
            non_canonical[31] |= 0x80;
            assert!(validate_x25519_peer(&non_canonical).is_err());
        }

        assert!(validate_x25519_peer(&[0u8; 31]).is_err());

        let valid_secret = StaticSecret::random_from_rng(OsRng);
        let valid_public = PublicKey::from(&valid_secret);
        assert!(validate_x25519_peer(valid_public.as_bytes()).is_ok());
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

    #[test]
    fn shared_bucket_helper_randomizes_within_bucket() {
        const TEST_BUCKETS: [usize; 3] = [1024, 4096, 16 * 1024];
        let mut sizes = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let padded = padded_bucket_len(3000, &TEST_BUCKETS).unwrap();
            assert!((4096..=4096 + 4096 / 8).contains(&padded));
            sizes.insert(padded);
        }
        assert!(
            sizes.len() > 1,
            "bucket padding must be randomized: {:?}",
            sizes
        );

        // Значение больше последнего bucket’а не должно молча обрезаться.
        assert!(padded_bucket_len(usize::MAX, &TEST_BUCKETS).is_none());
    }
}
