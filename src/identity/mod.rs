// src/identity/mod.rs
use crate::crypto::secret::{Ed25519Seed, SecretBytes, SecretString, X25519Priv};
use crate::storage::SafeFSOps;
use crate::types::{sanitize_display_text, truncate_display, IdentityHash};
use crate::vault::{self, MasterKey, Vault};
use anyhow::{anyhow, Result};
use bip39::Mnemonic;
use ciborium::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub const IDENTITY_FILE_NAME: &str = "identity.json";

const IDENTITY_AAD: &[u8] = b"lastchance:identity.json";

/// Версия подписываемого identity-документа.
pub const IDENTITY_DOC_VERSION: u64 = 1;
/// Максимальная длина ника в identity-документе (UTF-8 байты).
pub const MAX_NICKNAME_BYTES: usize = 64;
/// Максимальный размер CBOR-документа в URL (hex-строка).
const MAX_DOC_HEX_LEN: usize = 8 * 1024;

const INVITE_PREFIX: &str = "lastchance://contact?";
const FINGERPRINT_CONTEXT: &[u8] = b"lastchance:identity-fingerprint:v1";

/// Подписываемый документ личности.
///
/// В документ входят оба публичных ключа, поэтому Ed25519-подпись
/// криптографически связывает X25519-ключ с владельцем Ed25519-ключа.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityDoc {
    pub version: u64,
    pub ed25519_pub: [u8; 32],
    pub x25519_pub: [u8; 32],
    pub nickname: Option<String>,
    pub created_at: u64,
}

impl IdentityDoc {
    pub fn new(
        version: u64,
        ed25519_pub: [u8; 32],
        x25519_pub: [u8; 32],
        nickname: Option<String>,
        created_at: u64,
    ) -> Result<Self> {
        if version != IDENTITY_DOC_VERSION {
            return Err(anyhow!(
                "unsupported identity document version: {}",
                version
            ));
        }
        if let Some(name) = nickname.as_deref() {
            if name.len() > MAX_NICKNAME_BYTES {
                return Err(anyhow!(
                    "nickname is too long: {} bytes (max {})",
                    name.len(),
                    MAX_NICKNAME_BYTES
                ));
            }
        }
        // Сам ник не меняем: он входит в подписанный CBOR. Управляющие
        // символы отбрасываются на границе отображения/импорта
        // (см. `display_nickname`).

        Ok(Self {
            version,
            ed25519_pub,
            x25519_pub,
            nickname,
            created_at,
        })
    }

    /// Создаёт документ из срезов ключей (используется `App`).
    pub fn from_slices(
        ed25519_pub: &[u8],
        x25519_pub: &[u8],
        nickname: Option<String>,
        created_at: u64,
    ) -> Result<Self> {
        let ed25519_pub = ed25519_pub
            .try_into()
            .map_err(|_| anyhow!("ed25519 public key must be 32 bytes"))?;
        let x25519_pub = x25519_pub
            .try_into()
            .map_err(|_| anyhow!("x25519 public key must be 32 bytes"))?;
        Self::new(
            IDENTITY_DOC_VERSION,
            ed25519_pub,
            x25519_pub,
            nickname,
            created_at,
        )
    }

    /// RFC 8949 deterministic encoding: минимальные целые, definite-length
    /// строки и ключи map, отсортированные по байтам их CBOR-кодирования.
    pub fn canonical_cbor(&self) -> Result<Vec<u8>> {
        let mut fields: Vec<(&str, Value)> = vec![
            ("version", Value::Integer(self.version.into())),
            ("ed25519_pub", Value::Bytes(self.ed25519_pub.to_vec())),
            ("x25519_pub", Value::Bytes(self.x25519_pub.to_vec())),
            ("created_at", Value::Integer(self.created_at.into())),
        ];
        if let Some(nickname) = self.nickname.as_deref() {
            fields.push(("nickname", Value::Text(nickname.to_string())));
        }

        // Для коротких tstr ключей порядок encoded-key совпадает с
        // порядком (длина, байты): заголовок major type 3 кодирует длину.
        fields.sort_by(|(left, _), (right, _)| {
            left.len()
                .cmp(&right.len())
                .then_with(|| left.as_bytes().cmp(right.as_bytes()))
        });

        let value = Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (Value::Text(key.to_string()), value))
                .collect(),
        );

        let mut out = Vec::new();
        ciborium::ser::into_writer(&value, &mut out)
            .map_err(|e| anyhow!("failed to encode identity document: {}", e))?;
        Ok(out)
    }

    /// Разбирает документ и требует, чтобы вход был именно каноническим CBOR.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DOC_HEX_LEN / 2 {
            return Err(anyhow!("identity document is too large"));
        }

        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| anyhow!("invalid identity CBOR: {}", e))?;
        let map = value
            .as_map()
            .ok_or_else(|| anyhow!("identity document must be a CBOR map"))?;

        let mut seen = HashSet::new();
        let mut version = None;
        let mut ed25519_pub = None;
        let mut x25519_pub = None;
        let mut nickname = None;
        let mut created_at = None;

        for (key, value) in map {
            let key = key
                .as_text()
                .ok_or_else(|| anyhow!("identity document keys must be text"))?;
            if !seen.insert(key.to_string()) {
                return Err(anyhow!("duplicate identity document key: {}", key));
            }

            match key {
                "version" => version = Some(cbor_u64(value, key)?),
                "ed25519_pub" => ed25519_pub = Some(cbor_bytes32(value, key)?),
                "x25519_pub" => x25519_pub = Some(cbor_bytes32(value, key)?),
                "nickname" => {
                    let text = value
                        .as_text()
                        .ok_or_else(|| anyhow!("nickname must be a text string"))?;
                    nickname = Some(text.to_string());
                }
                "created_at" => created_at = Some(cbor_u64(value, key)?),
                other => return Err(anyhow!("unknown identity document key: {}", other)),
            }
        }

        let doc = Self::new(
            version.ok_or_else(|| anyhow!("identity document is missing version"))?,
            ed25519_pub.ok_or_else(|| anyhow!("identity document is missing ed25519_pub"))?,
            x25519_pub.ok_or_else(|| anyhow!("identity document is missing x25519_pub"))?,
            nickname,
            created_at.ok_or_else(|| anyhow!("identity document is missing created_at"))?,
        )?;

        if doc.canonical_cbor()? != bytes {
            return Err(anyhow!(
                "identity document is not canonical CBOR (RFC 8949 deterministic encoding required)"
            ));
        }

        Ok(doc)
    }

    /// `sha256(ed25519_pub)`, hex. Единственный источник identity hash.
    pub fn hash_hex(&self) -> String {
        hash_ed25519_public(&self.ed25519_pub)
    }

    /// Отпечаток связки обоих ключей для сверки вне канала.
    pub fn fingerprint_hex(&self) -> String {
        fingerprint_hex(&self.ed25519_pub, &self.x25519_pub)
    }
}

/// Подписанный identity-документ из invite-ссылки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityInvite {
    pub doc: IdentityDoc,
    pub signature: [u8; 64],
}

impl IdentityInvite {
    /// Подписывает канонический CBOR-блок целиком.
    pub fn sign(doc: IdentityDoc, signing_key: &SigningKey) -> Result<Self> {
        let bytes = doc.canonical_cbor()?;
        let signature = signing_key.sign(&bytes);
        Ok(Self {
            doc,
            signature: signature.to_bytes(),
        })
    }

    /// Проверяет Ed25519-подпись документа.
    pub fn verify(&self) -> Result<()> {
        let bytes = self.doc.canonical_cbor()?;
        let verifying_key = VerifyingKey::from_bytes(&self.doc.ed25519_pub)
            .map_err(|e| anyhow!("invalid ed25519 public key: {}", e))?;
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| anyhow!("invalid identity document signature"))
    }

    pub fn hash_hex(&self) -> String {
        self.doc.hash_hex()
    }

    pub fn fingerprint_hex(&self) -> String {
        self.doc.fingerprint_hex()
    }

    pub fn display_nickname(&self) -> String {
        self.doc
            .nickname
            .as_deref()
            .map(sanitize_display_text)
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("user_{}", &self.hash_hex()[..8]))
    }

    /// Сериализует подписанный документ в invite-ссылку.
    pub fn to_link(&self) -> Result<String> {
        let doc_hex = hex::encode(self.doc.canonical_cbor()?);
        let sig_hex = hex::encode(self.signature);
        let hash = self.hash_hex();
        let x25519 = hex::encode(self.doc.x25519_pub);
        let ed25519 = hex::encode(self.doc.ed25519_pub);

        let mut params = vec![
            ("hash", hash.as_str()),
            ("doc", doc_hex.as_str()),
            ("sig", sig_hex.as_str()),
            ("x25519", x25519.as_str()),
            ("ed25519", ed25519.as_str()),
        ];
        if let Some(nickname) = self.doc.nickname.as_deref() {
            params.push(("nickname", nickname));
        }

        let encoded: String = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(params.iter())
            .finish();

        Ok(format!("{}{}", INVITE_PREFIX, encoded))
    }

    /// Разбирает и полностью проверяет invite-ссылку.
    ///
    /// Ссылка без `doc`/`sig` (старый формат) отклоняется: иначе подмена
    /// X25519-ключа в URL оставалась бы незамеченной.
    pub fn from_link(raw: &str) -> Result<Self> {
        let params_str = raw
            .strip_prefix(INVITE_PREFIX)
            .ok_or_else(|| anyhow!("this is not a lastchance://contact?... link"))?;

        let mut params = HashMap::new();
        for (key, value) in url::form_urlencoded::parse(params_str.as_bytes()) {
            if params.contains_key(key.as_ref()) {
                return Err(anyhow!("duplicate invite parameter: {}", key));
            }
            params.insert(key.into_owned(), value.into_owned());
        }

        let hash = params
            .get("hash")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("invite is missing identity hash"))?;
        // Валидация до сравнения и любых срезов: не-ASCII/короткая строка
        // не должна доходить до бизнес-логики.
        let hash_id = IdentityHash::from_hex(hash).map_err(|e| {
            anyhow!(
                "invalid identity hash in invite ({}…, {} chars): {}",
                truncate_display(hash, 16),
                hash.chars().count(),
                e
            )
        })?;
        let doc_hex = params
            .get("doc")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow!("unsigned/legacy invite rejected: missing identity document")
            })?;
        if doc_hex.len() > MAX_DOC_HEX_LEN {
            return Err(anyhow!("identity document in invite is too large"));
        }
        let sig_hex = params
            .get("sig")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("unsigned/legacy invite rejected: missing signature"))?;

        let doc_bytes =
            hex::decode(doc_hex).map_err(|e| anyhow!("invalid identity document hex: {}", e))?;
        let doc = IdentityDoc::from_canonical_cbor(&doc_bytes)?;

        let sig_bytes = hex::decode(sig_hex).map_err(|e| anyhow!("invalid signature hex: {}", e))?;
        let signature: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| anyhow!("identity signature must be 64 bytes"))?;

        let invite = Self { doc, signature };
        invite.verify()?;

        let computed_hash = invite.hash_hex();
        if hash_id.to_string() != computed_hash {
            return Err(anyhow!(
                "identity hash mismatch: link has {}, but sha256(ed25519_pub) is {}",
                hash_id,
                computed_hash
            ));
        }

        if let Some(value) = params.get("x25519").filter(|value| !value.is_empty()) {
            let bytes =
                hex::decode(value).map_err(|e| anyhow!("invalid x25519 hex in link: {}", e))?;
            if bytes != invite.doc.x25519_pub {
                return Err(anyhow!(
                    "x25519 key in link does not match the signed identity document"
                ));
            }
        }

        if let Some(value) = params.get("ed25519").filter(|value| !value.is_empty()) {
            let bytes =
                hex::decode(value).map_err(|e| anyhow!("invalid ed25519 hex in link: {}", e))?;
            if bytes != invite.doc.ed25519_pub {
                return Err(anyhow!(
                    "ed25519 key in link does not match the signed identity document"
                ));
            }
        }

        if let Some(value) = params.get("nickname").filter(|value| !value.is_empty()) {
            match invite.doc.nickname.as_deref() {
                Some(signed) if signed == value => {}
                Some(_) => {
                    return Err(anyhow!(
                        "nickname in link does not match the signed identity document"
                    ));
                }
                None => {
                    return Err(anyhow!(
                        "unsigned nickname is not allowed without a signed nickname"
                    ));
                }
            }
        }

        Ok(invite)
    }
}

fn cbor_u64(value: &Value, field: &str) -> Result<u64> {
    let integer = value
        .as_integer()
        .ok_or_else(|| anyhow!("{} must be an unsigned integer", field))?;
    u64::try_from(integer).map_err(|_| anyhow!("{} is out of range", field))
}

fn cbor_bytes32(value: &Value, field: &str) -> Result<[u8; 32]> {
    let bytes = value
        .as_bytes()
        .ok_or_else(|| anyhow!("{} must be a byte string", field))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{} must be exactly 32 bytes", field))
}

pub fn hash_ed25519_public(ed25519_pub: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ed25519_pub);
    hex::encode(hasher.finalize())
}

/// Отпечаток связки `ed25519_pub || x25519_pub`, hex.
pub fn fingerprint_hex(ed25519_pub: &[u8; 32], x25519_pub: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_CONTEXT);
    hasher.update(ed25519_pub);
    hasher.update(x25519_pub);
    hex::encode(hasher.finalize())
}

/// Личность пользователя.
///
/// Секретные поля (`seed_phrase`, `private_key`, `ed25519_private_key`)
/// хранятся в затираемых обёртках и никогда не печатаются через `Debug`.
/// `Clone` реализован вручную: единственное место, где секреты
/// дублируются, — [`Clone::clone`] менеджера личности (кэш и возврат
/// владельцу), и это явно помечено.
#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub nickname: String,
    pub seed_phrase: SecretString,
    pub public_key: Vec<u8>,
    pub private_key: SecretBytes,
    pub ed25519_public_key: Vec<u8>,
    pub ed25519_private_key: SecretBytes,
    pub hash: String,
    pub created_at: i64,
    pub updated_at: i64,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Печатаем только публичные части и координаты. Секреты остаются
        // скрытыми даже при `{:?}`/`{:#?}` в логах и panic-сообщениях.
        f.debug_struct("Identity")
            .field("nickname", &self.nickname)
            .field("public_key", &hex::encode(&self.public_key))
            .field("ed25519_public_key", &hex::encode(&self.ed25519_public_key))
            .field("hash", &self.hash)
            .field("seed_phrase", &self.seed_phrase)
            .field("private_key", &self.private_key)
            .field("ed25519_private_key", &self.ed25519_private_key)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        // SECURITY(M-5): единственная точка копирования секретов Identity.
        // Вызывается при кэшировании в IdentityManager. Новые вызовы
        // `Identity::clone()` должны быть обоснованы при ревью.
        Self {
            nickname: self.nickname.clone(),
            seed_phrase: self.seed_phrase.duplicate(),
            public_key: self.public_key.clone(),
            private_key: self.private_key.duplicate(),
            ed25519_public_key: self.ed25519_public_key.clone(),
            ed25519_private_key: self.ed25519_private_key.duplicate(),
            hash: self.hash.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

pub struct IdentityManager {
    storage_path: String,
    safe_fs: Option<SafeFSOps>,
    cached_id: Option<Identity>,
    vault: Vault,
}

impl IdentityManager {
    pub fn new(storage_path: String, vault: Vault) -> Self {
        Self {
            storage_path,
            safe_fs: None,
            cached_id: None,
            vault,
        }
    }

    fn init_safe_fs(&mut self) -> Result<()> {
        if self.safe_fs.is_none() {
            self.safe_fs = Some(SafeFSOps::new(&self.storage_path)?);
        }
        Ok(())
    }

    pub fn generate_new_identity(&mut self, nickname: &str) -> Result<Identity> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(entropy.as_mut());

        let mnemonic = Mnemonic::from_entropy(entropy.as_ref())
            .map_err(|e| anyhow!("failed to generate mnemonic: {}", e))?;
        let seed_phrase = SecretString::new(mnemonic.to_string());

        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let keys = derive_keys_from_seed(seed.as_ref())?;

        let nickname = if nickname.is_empty() {
            format!("user_{}", &keys.identity_hash[..8])
        } else {
            nickname.to_string()
        };

        let now = chrono::Utc::now().timestamp();

        let identity = Identity {
            nickname,
            seed_phrase,
            public_key: keys.x25519_public,
            private_key: keys.x25519_private,
            ed25519_public_key: keys.ed25519_public,
            ed25519_private_key: keys.ed25519_private,
            hash: keys.identity_hash,
            created_at: now,
            updated_at: now,
        };

        self.cached_id = Some(identity.clone());
        Ok(identity)
    }

    /// Восстанавливает личность из существующей BIP-39 фразы.
    ///
    /// Фраза нормализуется (регистр и лишние пробелы), после чего из неё
    /// детерминированно выводятся те же ключи, что были созданы при
    /// первоначальной генерации. Файл на диск не пишется — для этого
    /// нужно отдельно вызвать [`IdentityManager::save`].
    pub fn restore_from_mnemonic(&mut self, seed_phrase: &str, nickname: &str) -> Result<Identity> {
        let identity = Identity::from_mnemonic(seed_phrase, nickname)?;
        self.cached_id = Some(identity.clone());
        Ok(identity)
    }

    pub fn load_or_create(&mut self, nickname: &str) -> Result<Identity> {
        self.init_safe_fs()?;

        let exists = match self.safe_fs.as_ref() {
            Some(safe_fs) => safe_fs.safe_stat(IDENTITY_FILE_NAME).is_ok(),
            None => false,
        };

        if exists {
            self.load()
        } else {
            let identity = self.generate_new_identity(nickname)?;
            self.save(&identity)?;
            Ok(identity)
        }
    }

    pub fn save(&mut self, identity: &Identity) -> Result<()> {
        self.init_safe_fs()?;

        let data = serde_json::to_string_pretty(identity)
            .map_err(|e| anyhow!("failed to marshal identity: {}", e))?;
        let sealed = self.vault.seal_file(IDENTITY_AAD, data.as_bytes())?;

        let safe_fs = self
            .safe_fs
            .as_ref()
            .ok_or_else(|| anyhow!("safe fs is not initialized"))?;
        safe_fs.safe_write_file(IDENTITY_FILE_NAME, &sealed, 0o600)?;

        self.cached_id = Some(identity.clone());
        Ok(())
    }

    pub fn load(&mut self) -> Result<Identity> {
        self.init_safe_fs()?;

        let data = self
            .safe_fs
            .as_ref()
            .ok_or_else(|| anyhow!("safe fs is not initialized"))?
            .safe_read_file(IDENTITY_FILE_NAME)?;

        let legacy = !vault::is_sealed(&data);
        let plaintext = if legacy {
            data
        } else {
            self.vault.open_file(IDENTITY_AAD, &data)?
        };

        let identity: Identity = serde_json::from_slice(&plaintext)
            .map_err(|e| anyhow!("failed to unmarshal identity: {}", e))?;
        identity.validate()?;

        // Файл старого формата сразу перезаписываем зашифрованным.
        if legacy {
            self.save(&identity)?;
        }

        self.cached_id = Some(identity.clone());
        Ok(identity)
    }

    /// Перешифровывает файл личности со старого ключа на новый (`/passwd`).
    pub fn reencrypt(&mut self, old_key: &MasterKey, new_key: &MasterKey) -> Result<()> {
        self.init_safe_fs()?;

        let data = self
            .safe_fs
            .as_ref()
            .ok_or_else(|| anyhow!("safe fs is not initialized"))?
            .safe_read_file(IDENTITY_FILE_NAME)?;

        let plaintext = if vault::is_sealed(&data) {
            vault::open_file(old_key, IDENTITY_AAD, &data)?
        } else {
            data
        };

        let sealed = vault::seal_file(new_key, IDENTITY_AAD, &plaintext)?;
        self.safe_fs
            .as_ref()
            .ok_or_else(|| anyhow!("safe fs is not initialized"))?
            .safe_write_file(IDENTITY_FILE_NAME, &sealed, 0o600)?;

        Ok(())
    }

    pub fn current(&self) -> Option<&Identity> {
        self.cached_id.as_ref()
    }

    pub fn update_nickname(&mut self, nickname: &str) -> Result<()> {
        if self.cached_id.is_none() {
            self.load_or_create(nickname)?;
        }

        // Забираем личность из кэша, чтобы не дублировать секреты ради
        // изменения одного ника. `save` вернёт копию в кэш.
        if let Some(mut identity) = self.cached_id.take() {
            identity.nickname = nickname.to_string();
            identity.updated_at = chrono::Utc::now().timestamp();
            if let Err(e) = self.save(&identity) {
                self.cached_id = Some(identity);
                return Err(e);
            }
        }

        Ok(())
    }
}

impl Identity {
    /// Строит личность из мнемонической фразы без обращения к хранилищу.
    ///
    /// BIP-39 не чувствителен к регистру и лишним пробелам, поэтому ввод
    /// пользователя приводится к каноническому виду до проверки контрольной
    /// суммы. Невалидная фраза возвращает ошибку.
    pub fn from_mnemonic(seed_phrase: &str, nickname: &str) -> Result<Identity> {
        let normalized = SecretString::new(normalize_seed_phrase(seed_phrase));
        let mnemonic = Mnemonic::parse(normalized.expose())
            .map_err(|e| anyhow!("некорректная мнемоническая фраза: {}", e))?;

        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let keys = derive_keys_from_seed(seed.as_ref())?;

        let nickname = if nickname.trim().is_empty() {
            format!("user_{}", &keys.identity_hash[..8])
        } else {
            nickname.trim().to_string()
        };

        let now = chrono::Utc::now().timestamp();

        Ok(Identity {
            nickname,
            seed_phrase: normalized,
            public_key: keys.x25519_public,
            private_key: keys.x25519_private,
            ed25519_public_key: keys.ed25519_public,
            ed25519_private_key: keys.ed25519_private,
            hash: keys.identity_hash,
            created_at: now,
            updated_at: now,
        })
    }
}

/// Приводит ввод к каноническому виду BIP-39: один пробел между словами,
/// нижний регистр.
fn normalize_seed_phrase(raw: &str) -> String {
    raw.split_whitespace()
        .map(|word| word.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

struct DerivedKeys {
    x25519_public: Vec<u8>,
    x25519_private: SecretBytes,
    ed25519_public: Vec<u8>,
    ed25519_private: SecretBytes,
    identity_hash: String,
}

/// Выводит ключи личности из BIP-39 seed.
///
/// Промежуточные значения (`x_priv_raw`, `ed_seed`) живут в обёртках с
/// `ZeroizeOnDrop`, а `SigningKey`/`StaticSecret` затираются самими
/// библиотеками. Входной seed не копируется: вызывающий хранит его в
/// `Zeroizing` и затирает сразу после вызова (см. [`Zeroizing`]).
fn derive_keys_from_seed(seed: &[u8]) -> Result<DerivedKeys> {
    // X25519 via HKDF
    let hkdf_x = Hkdf::<Sha256>::new(None, seed);
    let mut x_priv_raw = X25519Priv::from_bytes([0u8; 32]);
    hkdf_x
        .expand(b"X25519_E2EE_Key_v1", x_priv_raw.expose_mut())
        .map_err(|e| anyhow!("hkdf x25519: {}", e))?;

    let private_key = StaticSecret::from(*x_priv_raw.expose());
    let public_key = PublicKey::from(&private_key);

    let x25519_private = SecretBytes::from_slice(private_key.as_bytes());
    let x25519_pub = public_key.as_bytes().to_vec();

    // Ed25519 via HKDF
    let hkdf_e = Hkdf::<Sha256>::new(None, seed);
    let mut ed_seed = Ed25519Seed::from_bytes([0u8; 32]);
    hkdf_e
        .expand(b"Ed25519_Auth_Key_v1", ed_seed.expose_mut())
        .map_err(|e| anyhow!("hkdf ed25519: {}", e))?;

    let signing_key = SigningKey::from_bytes(ed_seed.expose());
    let verifying_key = signing_key.verifying_key();

    let ed25519_pub = verifying_key.as_bytes().to_vec();
    let ed25519_private = {
        let bytes = Zeroizing::new(signing_key.to_bytes());
        SecretBytes::from_slice(bytes.as_ref())
    };

    // Промежуточные буферы не должны доживать до выхода из функции.
    drop(x_priv_raw);
    drop(ed_seed);

    // Hash = SHA256(Ed25519PublicKey) — публичное значение, не секрет.
    let mut hasher = Sha256::new();
    hasher.update(&ed25519_pub);
    let hash = hex::encode(hasher.finalize());

    Ok(DerivedKeys {
        x25519_public: x25519_pub,
        x25519_private,
        ed25519_public: ed25519_pub,
        ed25519_private,
        identity_hash: hash,
    })
}

impl Identity {
    /// Проверяет, что сохранённые ключи и `hash` согласованы.
    ///
    /// Это защищает от повреждённого/подменённого `identity.json`:
    /// `hash` обязан быть `sha256(ed25519_pub)`, а X25519-ключ — парой
    /// к сохранённому приватному ключу.
    pub fn validate(&self) -> Result<()> {
        let ed25519_private: [u8; 32] = self
            .ed25519_private_key
            .expose()
            .try_into()
            .map_err(|_| anyhow!("identity has invalid ed25519 private key length"))?;
        let ed25519_public: [u8; 32] = self
            .ed25519_public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("identity has invalid ed25519 public key length"))?;
        let x25519_private: [u8; 32] = self
            .private_key
            .expose()
            .try_into()
            .map_err(|_| anyhow!("identity has invalid x25519 private key length"))?;
        let x25519_public: [u8; 32] = self
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("identity has invalid x25519 public key length"))?;

        let signing_key = SigningKey::from_bytes(&ed25519_private);
        if signing_key.verifying_key().as_bytes() != &ed25519_public {
            return Err(anyhow!(
                "identity ed25519 public key does not match its private key"
            ));
        }

        let x_secret = StaticSecret::from(x25519_private);
        if PublicKey::from(&x_secret).as_bytes() != &x25519_public {
            return Err(anyhow!(
                "identity x25519 public key does not match its private key"
            ));
        }

        if !self.hash.eq_ignore_ascii_case(&hash_ed25519_public(&ed25519_public)) {
            return Err(anyhow!(
                "identity hash does not match sha256(ed25519_pub)"
            ));
        }

        Ok(())
    }

    pub fn get_public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    pub fn get_ed25519_public_key_hex(&self) -> String {
        hex::encode(&self.ed25519_public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Стандартный тестовый вектор BIP-39: 128 нулевых бит энтропии.
    const VALID_PHRASE: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn restore_from_same_mnemonic_is_deterministic() {
        let first = Identity::from_mnemonic(VALID_PHRASE, "").unwrap();
        let second = Identity::from_mnemonic(VALID_PHRASE, "").unwrap();

        assert_eq!(first.seed_phrase.expose(), VALID_PHRASE);
        assert_eq!(first.hash, second.hash);
        assert_eq!(first.public_key, second.public_key);
        assert_eq!(first.private_key.expose(), second.private_key.expose());
        assert_eq!(first.ed25519_public_key, second.ed25519_public_key);
        assert_eq!(
            first.ed25519_private_key.expose(),
            second.ed25519_private_key.expose()
        );
        assert_eq!(first.nickname, second.nickname);
        assert!(first.nickname.starts_with("user_"));
    }

    #[test]
    fn restore_normalizes_case_and_extra_whitespace() {
        let messy = format!("  {}  ", VALID_PHRASE.to_uppercase().replace(' ', " \t\n "));
        let identity = Identity::from_mnemonic(&messy, "alice").unwrap();

        assert_eq!(identity.seed_phrase.expose(), VALID_PHRASE);
        assert_eq!(identity.nickname, "alice");
        assert_eq!(identity.hash, Identity::from_mnemonic(VALID_PHRASE, "bob").unwrap().hash);
    }

    #[test]
    fn restore_rejects_invalid_checksum() {
        let invalid =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let error = Identity::from_mnemonic(invalid, "").unwrap_err().to_string();

        assert!(error.contains("некорректная мнемоническая фраза"), "{error}");
    }

    #[test]
    fn restore_rejects_unknown_word() {
        let invalid =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword";
        assert!(Identity::from_mnemonic(invalid, "").is_err());
    }

    fn test_doc(x25519_byte: u8) -> IdentityDoc {
        IdentityDoc::new(
            1,
            [7u8; 32],
            [x25519_byte; 32],
            Some("alice".to_string()),
            1_700_000_000,
        )
        .unwrap()
    }

    #[test]
    fn identity_doc_uses_canonical_sorted_cbor() {
        let doc = test_doc(9);
        let cbor = doc.canonical_cbor().unwrap();

        // 5 entries; the first key is "version" (shortest encoded key).
        assert_eq!(cbor[0], 0xa5);
        assert_eq!(&cbor[1..2], &[0x67]);
        assert_eq!(&cbor[2..9], b"version");

        assert_eq!(IdentityDoc::from_canonical_cbor(&cbor).unwrap(), doc);
    }

    #[test]
    fn identity_doc_rejects_non_canonical_cbor() {
        let doc = test_doc(9);
        let unordered = Value::Map(vec![
            (
                Value::Text("ed25519_pub".to_string()),
                Value::Bytes(doc.ed25519_pub.to_vec()),
            ),
            (
                Value::Text("x25519_pub".to_string()),
                Value::Bytes(doc.x25519_pub.to_vec()),
            ),
            (
                Value::Text("version".to_string()),
                Value::Integer(doc.version.into()),
            ),
            (
                Value::Text("created_at".to_string()),
                Value::Integer(doc.created_at.into()),
            ),
            (
                Value::Text("nickname".to_string()),
                Value::Text("alice".to_string()),
            ),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&unordered, &mut encoded).unwrap();

        assert!(IdentityDoc::from_canonical_cbor(&encoded).is_err());
    }

    #[test]
    fn signed_invite_round_trips_and_binds_both_keys() {
        let signing_key = SigningKey::from_bytes(&[3u8; 32]);
        let mut doc = test_doc(11);
        doc.ed25519_pub = *signing_key.verifying_key().as_bytes();

        let invite = IdentityInvite::sign(doc.clone(), &signing_key).unwrap();
        invite.verify().unwrap();

        let link = invite.to_link().unwrap();
        let parsed = IdentityInvite::from_link(&link).unwrap();
        assert_eq!(parsed, invite);
        assert_eq!(parsed.hash_hex(), doc.hash_hex());
        assert_eq!(parsed.fingerprint_hex(), doc.fingerprint_hex());
    }

    #[test]
    fn signed_invite_without_nickname_round_trips() {
        let signing_key = SigningKey::from_bytes(&[8u8; 32]);
        let doc = IdentityDoc::new(
            1,
            *signing_key.verifying_key().as_bytes(),
            [9u8; 32],
            None,
            7,
        )
        .unwrap();
        let invite = IdentityInvite::sign(doc, &signing_key).unwrap();
        let link = invite.to_link().unwrap();

        assert!(!link.contains("nickname="));
        let parsed = IdentityInvite::from_link(&link).unwrap();
        assert_eq!(parsed.doc.nickname, None);
        assert!(parsed.display_nickname().starts_with("user_"));
    }

    #[test]
    fn display_nickname_sanitizes_terminal_and_bidi_controls() {
        let mut doc = test_doc(10);
        doc.nickname = Some("evil\x1b[2J\u{202E}name".to_string());
        let invite = IdentityInvite {
            doc,
            signature: [0u8; 64],
        };
        assert_eq!(invite.display_nickname(), "evil[2Jname");

        let mut doc = test_doc(10);
        doc.nickname = Some("🙂 שלום".to_string());
        let invite = IdentityInvite {
            doc,
            signature: [0u8; 64],
        };
        assert_eq!(invite.display_nickname(), "🙂 שלום");
    }

    #[test]
    fn changed_x25519_invalidates_signature() {
        let signing_key = SigningKey::from_bytes(&[4u8; 32]);
        let mut doc = test_doc(12);
        doc.ed25519_pub = *signing_key.verifying_key().as_bytes();
        let mut invite = IdentityInvite::sign(doc, &signing_key).unwrap();

        invite.doc.x25519_pub = [13u8; 32];
        assert!(invite.verify().is_err());
    }

    #[test]
    fn invite_rejects_hash_mismatch_and_tampered_fields() {
        let signing_key = SigningKey::from_bytes(&[5u8; 32]);
        let mut doc = test_doc(14);
        doc.ed25519_pub = *signing_key.verifying_key().as_bytes();
        let invite = IdentityInvite::sign(doc, &signing_key).unwrap();
        let link = invite.to_link().unwrap();

        let bad_hash = link.replacen(&invite.hash_hex(), &"0".repeat(64), 1);
        assert!(IdentityInvite::from_link(&bad_hash).is_err());

        let bad_x25519 = link.replacen(&hex::encode(invite.doc.x25519_pub), &hex::encode([15u8; 32]), 1);
        assert!(IdentityInvite::from_link(&bad_x25519).is_err());
    }

    #[test]
    fn invite_rejects_invalid_hash_at_boundary() {
        let signing_key = SigningKey::from_bytes(&[6u8; 32]);
        let mut doc = test_doc(16);
        doc.ed25519_pub = *signing_key.verifying_key().as_bytes();
        let invite = IdentityInvite::sign(doc, &signing_key).unwrap();
        let link = invite.to_link().unwrap();

        for bad_hash in ["", "abc", &"я".repeat(64), &"😀".repeat(32)] {
            let bad_link = link.replacen(&invite.hash_hex(), bad_hash, 1);
            assert!(
                IdentityInvite::from_link(&bad_link).is_err(),
                "invalid hash must be rejected before parsing the document"
            );
        }
    }

    #[test]
    fn identity_validation_rejects_hash_mismatch() {
        let mut identity = Identity::from_mnemonic(VALID_PHRASE, "alice").unwrap();
        identity.validate().unwrap();
        identity.hash = "00".repeat(32);
        assert!(identity.validate().is_err());
    }

    #[test]
    fn identity_debug_redacts_all_secret_material() {
        let identity = Identity::from_mnemonic(VALID_PHRASE, "alice").unwrap();

        let x_private = hex::encode(identity.private_key.expose());
        let ed_private = hex::encode(identity.ed25519_private_key.expose());
        let debug = format!("{:#?}", identity);

        assert!(!debug.contains(&x_private), "x25519 private key leaked");
        assert!(!debug.contains(&ed_private), "ed25519 private key leaked");
        assert!(!debug.contains("abandon"), "seed phrase leaked");
        assert!(debug.contains("<secret>"));
        assert_eq!(format!("{:?}", identity.private_key), "<secret>");
        assert_eq!(format!("{:?}", identity.seed_phrase), "<secret>");
    }

    #[test]
    fn identity_json_format_is_unchanged_by_secret_wrappers() {
        let identity = Identity::from_mnemonic(VALID_PHRASE, "alice").unwrap();
        let json = serde_json::to_string(&identity).unwrap();

        // Секреты по-прежнему сериализуются как строка/массив чисел:
        // этот формат читают существующие `identity.json`.
        assert!(json.contains("\"seed_phrase\":\"abandon abandon"));
        assert!(json.contains("\"private_key\":["));

        let restored: Identity = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.seed_phrase.expose(), identity.seed_phrase.expose());
        assert_eq!(
            restored.private_key.expose(),
            identity.private_key.expose()
        );
        restored.validate().unwrap();
    }

    #[test]
    fn derive_keys_from_seed_leaves_no_seed_in_results() {
        let mut seed = Zeroizing::new([0x42u8; 64]);
        let keys = derive_keys_from_seed(seed.as_ref()).unwrap();

        // Промежуточные буферы живут в ZeroizeOnDrop-обёртках. Исходный
        // seed вызывающий может затереть сразу после вывода ключей.
        zeroize::Zeroize::zeroize(&mut *seed);
        assert!(seed.iter().all(|byte| *byte == 0));

        assert_eq!(keys.x25519_private.expose().len(), 32);
        assert_eq!(keys.ed25519_private.expose().len(), 32);
        assert_eq!(keys.x25519_public.len(), 32);
        assert_eq!(keys.ed25519_public.len(), 32);
    }

    #[test]
    fn cloned_identity_keeps_independent_secret_copies() {
        // Копия нужна кэшу менеджера; проверяем, что она не разделяет
        // изменяемый буфер с оригиналом.
        let identity = Identity::from_mnemonic(VALID_PHRASE, "alice").unwrap();
        let mut cloned = identity.clone();
        cloned.private_key.expose_mut()[0] ^= 0xFF;

        assert_ne!(cloned.private_key.expose(), identity.private_key.expose());
        assert_eq!(cloned.hash, identity.hash);
    }

    #[test]
    fn legacy_unsigned_invite_is_rejected() {
        let legacy = format!(
            "lastchance://contact?hash={}&x25519={}&ed25519={}&nickname=alice",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64)
        );
        assert!(IdentityInvite::from_link(&legacy).is_err());
    }
}
