// src/crypto/mod.rs
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use anyhow::{anyhow, Result};

pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;
pub const FRAME_HEADER_SIZE: usize = 14;
pub const MAGIC_BYTES_VALUE: u16 = 0x4E53;

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

    // HKDF derivation
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
    let mut final_key = [0u8; 32];
    hkdf.expand(b"ECDH_v1", &mut final_key)
        .map_err(|e| anyhow!("HKDF derivation failed: {}", e))?;

    Ok(final_key)
}

fn find_min_allowed_total_size(min_data_len: usize) -> Result<usize> {
    for &size in ALLOWED_TOTAL_SIZES.iter() {
        if size >= min_data_len {
            return Ok(size);
        }
    }
    Err(anyhow!("data too large: {} bytes exceeds max allowed {}", min_data_len, SIZE_MAX))
}

// Message Encryption
pub fn encrypt_message(plaintext: &[u8], shared_secret: &[u8; 32], session_id: u64) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(shared_secret.into());
    
    // Create base frame
    let mut base_frame = vec![0u8; FRAME_HEADER_SIZE + plaintext.len()];
    
    // Magic bytes
    base_frame[0..2].copy_from_slice(&MAGIC_BYTES_VALUE.to_le_bytes());
    
    // Session ID
    base_frame[2..10].copy_from_slice(&session_id.to_le_bytes());
    
    // Payload length
    if plaintext.len() > u32::MAX as usize {
        return Err(anyhow!("plaintext too large: {} bytes exceeds max uint32", plaintext.len()));
    }
    base_frame[10..14].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    
    // Copy plaintext
    base_frame[14..].copy_from_slice(plaintext);
    
    // Calculate total size
    let min_total_size = NONCE_SIZE + base_frame.len() + TAG_SIZE;
    let total_size = find_min_allowed_total_size(min_total_size)?;
    let encrypted_block_size = total_size - NONCE_SIZE;
    let frame_with_padding_size = encrypted_block_size - TAG_SIZE;
    
    // Create frame with padding
    let mut frame_with_padding = vec![0u8; frame_with_padding_size];
    frame_with_padding[..base_frame.len()].copy_from_slice(&base_frame);
    
    // Fill random padding
    if base_frame.len() < frame_with_padding_size {
        OsRng.fill_bytes(&mut frame_with_padding[base_frame.len()..]);
    }
    
    // Generate nonce
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, frame_with_padding.as_slice())
        .map_err(|e| anyhow!("encryption failed: {}", e))?;
    
    // Combine packet
    let mut packet = Vec::with_capacity(total_size);
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&ciphertext);
    
    Ok(packet)
}

// Message Decryption
pub fn decrypt_message(packet: &[u8], shared_secret: &[u8; 32]) -> Result<(Vec<u8>, u64)> {
    // Validate packet size
    if !ALLOWED_TOTAL_SIZES.contains(&packet.len()) {
        return Err(anyhow!(
            "invalid packet size {}: must be one of {:?}",
            packet.len(),
            ALLOWED_TOTAL_SIZES
        ));
    }
    
    let cipher = XChaCha20Poly1305::new(shared_secret.into());
    
    if packet.len() < NONCE_SIZE + TAG_SIZE {
        return Err(anyhow!(
            "packet too short: {} bytes, need at least {}",
            packet.len(),
            NONCE_SIZE + TAG_SIZE
        ));
    }
    
    let nonce = XNonce::from_slice(&packet[..NONCE_SIZE]);
    let encrypted_block = &packet[NONCE_SIZE..];
    
    let frame_with_padding = cipher
        .decrypt(nonce, encrypted_block)
        .map_err(|e| anyhow!("decryption failed (wrong key or corrupted data): {}", e))?;
    
    if frame_with_padding.len() < FRAME_HEADER_SIZE {
        return Err(anyhow!("decrypted frame too short: {} bytes", frame_with_padding.len()));
    }
    
    // Check magic bytes
    let magic = u16::from_le_bytes([frame_with_padding[0], frame_with_padding[1]]);
    if magic != MAGIC_BYTES_VALUE {
        return Err(anyhow!(
            "invalid magic bytes: expected 0x{:04X}, got 0x{:04X}",
            MAGIC_BYTES_VALUE,
            magic
        ));
    }
    
    // Extract session ID
    let session_id = u64::from_le_bytes(frame_with_padding[2..10].try_into()?);
    
    // Get data length
    let data_len = u32::from_le_bytes(frame_with_padding[10..14].try_into()?) as usize;
    
    if data_len > frame_with_padding.len() - FRAME_HEADER_SIZE {
        return Err(anyhow!(
            "declared data length {} exceeds frame bounds {}",
            data_len,
            frame_with_padding.len() - FRAME_HEADER_SIZE
        ));
    }
    
    let message = frame_with_padding[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + data_len].to_vec();
    
    Ok((message, session_id))
}

// ---------------------------------------------------------------------------
// E2E application envelope (внутри уже зашифрованного кадра)
// ---------------------------------------------------------------------------

/// Магия внутреннего конверта. Она зашифрована вместе с кадром и на диск
/// никогда не попадает.
pub const E2E_MAGIC: &[u8; 4] = b"LCE1";

const E2E_KIND_TEXT: u8 = 1;
const E2E_KIND_SET_TTL: u8 = 2;
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

/// Разбирает полезную нагрузку. Сообщения без магии считаются обычным
/// текстом: это сохраняет совместимость со старыми клиентами.
pub fn decode_payload(payload: &[u8]) -> Result<E2ePayload> {
    if payload.len() < E2E_HEADER_MIN || &payload[..E2E_MAGIC.len()] != E2E_MAGIC {
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
        other => Err(anyhow!("unknown e2e payload kind: {}", other)),
    }
}

// File Encryption
pub fn encrypt_file(plaintext: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(shared_secret.into());
    
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    
    let mut ciphertext = nonce_bytes.to_vec();
    let encrypted = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("file encryption failed: {}", e))?;
    ciphertext.extend_from_slice(&encrypted);
    
    Ok(ciphertext)
}

// File Decryption
pub fn decrypt_file(ciphertext: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(shared_secret.into());
    
    if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
        return Err(anyhow!("ciphertext too short: {} bytes", ciphertext.len()));
    }
    
    let nonce = XNonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let encrypted_data = &ciphertext[NONCE_SIZE..];
    
    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|e| anyhow!("file decryption failed: {}", e))?;
    
    Ok(plaintext)
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
    fn test_message_encryption_decryption() {
        let shared_secret = [42u8; 32];
        let plaintext = b"Hello, World!";
        let session_id = 12345;
        
        let packet = encrypt_message(plaintext, &shared_secret, session_id).unwrap();
        let (decrypted, decrypted_session_id) = decrypt_message(&packet, &shared_secret).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
        assert_eq!(session_id, decrypted_session_id);
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
    fn legacy_plaintext_is_still_text() {
        assert_eq!(
            decode_payload(b"hello old client").unwrap(),
            E2ePayload::Text {
                text: "hello old client".to_string(),
                ttl_seconds: None,
            }
        );
    }
}
