// src/storage/db.rs
//! Локальное хранилище контактов, комнат, сообщений и файлов.
//!
//! Рабочая база SQLite живёт исключительно в оперативной памяти
//! (`Connection::open_in_memory`). На диск пишется один файл `vault.dat`
//! в формате `[nonce 24] || [ciphertext] || [tag 16]` (XChaCha20-Poly1305)
//! без магических байтов и открытых заголовков: ни имена контактов, ни
//! тексты сообщений, ни служебные подписи SQLite на диск не попадают.
//!
//! Перед шифрованием дамп базы дополняется случайным паддингом по
//! bucket-сетке (с джиттером внутри bucket). Внутренний заголовок (версия
//! схемы и длина полезной нагрузки) хранится строго внутри зашифрованного
//! блока, поэтому точное число сообщений по размеру файла не определяется:
//! наблюдатель видит только bucket. Это mitigation, а не устранение утечки:
//! рост числа bucket’ов всё ещё коррелирует с объёмом данных.
//!
//! При каждом изменении данных состояние базы сериализуется, шифруется
//! мастер-ключом и атомарно перезаписывается через [`SafeFSOps`] с правами
//! 0600 на Unix.

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroizing;

use crate::crypto::secret::{SecretBytes, SecretString};
use crate::storage::SafeFSOps;
use crate::types::{truncate_display, IdentityHash, OnionAddress};
use crate::vault::{MasterKey, Vault};

/// Новый зашифрованный контейнер локальной базы.
pub const VAULT_FILE_NAME: &str = "vault.dat";

/// Старая открытая база SQLite. Оставлена только для автомиграции.
pub const LEGACY_DB_FILE_NAME: &str = "user.db";

/// `nonce (24) + Poly1305 tag (16)`.
const CONTAINER_OVERHEAD: usize = 40;
/// Bucket-сетка контейнера `vault.dat`. Последний bucket покрывает
/// [`MAX_PAYLOAD_LEN`]. Та же политика джиттера, что у файловых конвертов
/// (общий [`crate::crypto::padded_bucket_len`]).
const VAULT_PADDING_BUCKETS: [usize; 11] = [
    4 * 1024,
    16 * 1024,
    64 * 1024,
    256 * 1024,
    1024 * 1024,
    4 * 1024 * 1024,
    16 * 1024 * 1024,
    64 * 1024 * 1024,
    128 * 1024 * 1024,
    256 * 1024 * 1024,
    512 * 1024 * 1024,
];
/// Открытый заголовок внутри шифротекста: `LCDB` + версия + длина JSON.
const INNER_MAGIC: &[u8; 4] = b"LCDB";
const INNER_VERSION: u8 = 1;
const INNER_HEADER_LEN: usize = 9;
/// AAD привязывает контейнер к назначению файла.
const VAULT_AAD: &[u8] = b"lastchance:vault.dat";
/// Верхняя граница дампа, чтобы повреждённый заголовок не вызвал OOM.
const MAX_PAYLOAD_LEN: usize = 512 * 1024 * 1024;
/// Как часто mtime можно «переставлять» на новое случайное значение.
/// Между обновлениями все записи получают один и тот же mtime, поэтому
/// отдельная отправка сообщения не оставляет свежего следа.
const MTIME_REFRESH_MIN_SECS: u64 = 5 * 60;
const MTIME_REFRESH_MAX_SECS: u64 = 15 * 60;
/// Насколько назад сдвигается mtime: файл выглядит старше реальной записи.
const MTIME_MAX_AGE_SECS: u64 = 6 * 60 * 60;

// ============================================================
// DATA MODELS
// ============================================================

/// Контакт ещё не сверен пользователем (обычное состояние TOFU).
pub const TOFU_PENDING: &str = "pending";
/// Пользователь сверил отпечаток вне канала.
pub const TOFU_VERIFIED: &str = "verified";
/// X25519-ключ изменился после первой встречи.
pub const TOFU_CHANGED: &str = "changed";

fn default_tofu_state() -> String {
    TOFU_PENDING.to_string()
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub hash: String,
    pub public_key: Vec<u8>,
    /// Ed25519 public key в hex, если он был в ссылке-приглашении.
    pub ed25519: Option<String>,
    /// Подписанный Tor v3 `.onion`-адрес собеседника.
    pub onion_addr: Option<String>,
    /// Отпечаток связки Ed25519 + X25519, hex.
    pub fingerprint: Option<String>,
    /// Состояние TOFU: `pending`, `verified` или `changed`.
    pub tofu_state: String,
    pub nickname: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub id: i64,
    pub contact_hash: String,
    pub room_hash: String,
    pub direction: String, // "in" or "out"
    pub text: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
    /// Исчезающее сообщение живёт только в оперативной памяти и
    /// никогда не попадает в `vault.dat`.
    pub is_ephemeral: bool,
    /// Unix timestamp, после которого сообщение затирается из RAM.
    pub expires_at: Option<u64>,
}

/// Учётные данные Tor v3 hidden service, хранящиеся внутри зашифрованного `vault.dat`.
pub struct TorServiceCredentials {
    pub service_id: String,
    pub private_key: SecretString,
}

impl std::fmt::Debug for TorServiceCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorServiceCredentials")
            .field("service_id", &self.service_id)
            .field("private_key", &self.private_key)
            .finish()
    }
}

/// Запись зашифрованной исходящей очереди (`outbox`) в `vault.dat`.
#[derive(Debug, Clone)]
pub struct OutboxItem {
    pub id: i64,
    pub room_hash: String,
    pub recipient_onion: String,
    pub packet: Vec<u8>,
    pub created_at: i64,
    pub attempts: u32,
    pub next_retry_at: i64,
    pub last_error: Option<String>,
}

/// M-C: tombstone уничтоженной сессии TTL-комнаты.
///
/// В зашифрованный `vault.dat` попадают только alias сессии (он и так
/// передаётся в открытом заголовке), `SHA256(session_id)` и время ретирации.
/// Сам `session_id`, `bootstrap_nonce`, DH/ratchet-ключи и содержимое
/// сообщений здесь не хранятся.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlTombstone {
    /// `HKDF(session_id, "route-v3")` — адрес retired-сессии.
    pub session_alias: [u8; 16],
    /// `SHA256(session_id)`.
    pub session_id_hash: [u8; 32],
    /// Unix seconds; используется для очистки по `TOMBSTONE_TTL`.
    pub retired_at: u64,
}

// ============================================================
// SNAPSHOT (то, что попадает внутрь шифротекста)
// ============================================================

/// Строки базы в сериализуемом виде.
///
/// Все значения хранятся как строки: `public_key` — hex, время — в том же
/// виде, в котором его вернул SQLite. Это упрощает миграцию и не создаёт
/// зависимостей от конкретного SQLite-дампа.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Snapshot {
    #[serde(default)]
    contacts: Vec<ContactRow>,
    #[serde(default)]
    rooms: Vec<RoomRow>,
    #[serde(default)]
    messages: Vec<MessageRow>,
    /// Сериализованные состояния Double Ratchet.
    #[serde(default)]
    ratchet_states: Vec<RatchetRow>,
    /// `session_id`, которые нельзя принимать после reset/вытеснения.
    #[serde(default)]
    retired_ratchet_sessions: Vec<RetiredSessionRow>,
    /// M-C: tombstone-хеши retired-сессий TTL-комнат.
    #[serde(default)]
    ttl_tombstones: Vec<TtlTombstoneRow>,
    /// Постоянный Tor v3 hidden service ключ (`ED25519-V3:...`).
    #[serde(default)]
    tor_service: Option<TorServiceRow>,
    /// Зашифрованная очередь исходящих пакетов на случай оффлайна пира.
    #[serde(default)]
    outbox: Vec<OutboxRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ContactRow {
    hash: String,
    /// hex-кодированный публичный ключ.
    public_key: String,
    ed25519: Option<String>,
    #[serde(default)]
    onion_addr: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    #[serde(default = "default_tofu_state")]
    tofu_state: String,
    nickname: String,
    created_at: String,
}

/// Сырые поля контакта из SQLite (см. `Storage::get_contact`).
type ContactDbRow = (
    String,
    Vec<u8>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
);

#[derive(Debug, Serialize, Deserialize)]
struct RoomRow {
    id: i64,
    name: String,
    contact_hash: String,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct MessageRow {
    id: i64,
    contact_hash: String,
    room_hash: String,
    direction: String,
    text: String,
    timestamp: String,
    status: String,
    /// Поля появились позже: старые снимки читаются с значениями по умолчанию.
    #[serde(default)]
    is_ephemeral: bool,
    #[serde(default)]
    expires_at: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TorServiceRow {
    service_id: String,
    private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct OutboxRow {
    id: i64,
    room_hash: String,
    recipient_onion: String,
    /// hex-кодированный Double Ratchet v3 пакет.
    packet: String,
    created_at: i64,
    attempts: u32,
    next_retry_at: i64,
    #[serde(default)]
    last_error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RatchetRow {
    room_hash: String,
    /// hex-кодированное состояние; контейнер `vault.dat` уже зашифрован.
    state: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct RetiredSessionRow {
    room_hash: String,
    /// hex-кодированный `session_id` (16 байт).
    session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct TtlTombstoneRow {
    /// hex-кодированный alias сессии (16 байт).
    session_alias: String,
    /// hex-кодированный `SHA256(session_id)` (32 байта).
    session_id_hash: String,
    #[serde(default)]
    retired_at: u64,
}

// ============================================================
// STORAGE
// ============================================================

/// Состояние рандомизированного mtime `vault.dat`.
///
/// `anchor` — значение, которое выставляется при каждой записи, пока не
/// истёк `next_refresh`. Это не секрет и не влияет на целостность данных,
/// поэтому poison блокировки восстанавливается через `into_inner`.
#[derive(Default)]
struct VaultMtime {
    anchor: Option<SystemTime>,
    next_refresh: Option<Instant>,
}

pub struct Storage {
    db: Arc<Mutex<Connection>>,
    vault: Vault,
    safe_fs: SafeFSOps,
    mtime: Mutex<VaultMtime>,
}

impl Storage {
    /// Открывает хранилище: расшифровывает `vault.dat` либо выполняет
    /// бесшовную миграцию со старой открытой `user.db`.
    pub fn new(base_dir: &str, vault: Vault) -> Result<Self> {
        let safe_fs = SafeFSOps::new(base_dir)?;
        let conn = Connection::open_in_memory()
            .map_err(|e| anyhow!("failed to open in-memory database: {}", e))?;

        let storage = Self {
            db: Arc::new(Mutex::new(conn)),
            vault,
            safe_fs,
            mtime: Mutex::new(VaultMtime::default()),
        };

        storage.init_tables()?;
        storage.configure_connection()?;

        let vault_path = Path::new(base_dir).join(VAULT_FILE_NAME);
        let legacy_path = Path::new(base_dir).join(LEGACY_DB_FILE_NAME);

        if vault_path.exists() {
            let data = storage.safe_fs.safe_read_file(VAULT_FILE_NAME)?;
            let key = storage.vault.key()?;
            let snapshot = Self::decode_container(&key, &data)?;
            storage.load_snapshot(&snapshot)?;

            // Остатки старой открытой базы (например, после прерванной
            // миграции) больше не нужны и не должны лежать на диске.
            if legacy_path.exists() {
                Self::purge_legacy_files(&legacy_path);
            }
        } else if legacy_path.exists() {
            let snapshot = storage.read_legacy_snapshot(&legacy_path)?;
            storage.load_snapshot(&snapshot)?;

            // Сначала фиксируем данные в зашифрованном виде, и только потом
            // затираем открытую базу: сбой на любом шаге не теряет данные.
            storage.persist()?;
            Self::purge_legacy_files(&legacy_path);
        } else {
            // Создаём пустой контейнер сразу, чтобы формат на диске был
            // предсказуемым и не зависел от первой записи.
            storage.persist()?;
        }

        Ok(storage)
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| anyhow!("database lock poisoned"))
    }

    fn configure_connection(&self) -> Result<()> {
        let conn = self.conn()?;
        // База в памяти: журнал WAL не нужен, временные файлы не создаём.
        conn.execute_batch(
            "
            PRAGMA foreign_keys=ON;
            PRAGMA temp_store=MEMORY;
            PRAGMA secure_delete=ON;
        ",
        )
        .map_err(|e| anyhow!("failed to configure database: {}", e))
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn()?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS contacts (
                hash TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                ed25519 TEXT,
                onion_addr TEXT,
                fingerprint TEXT,
                tofu_state TEXT NOT NULL DEFAULT 'pending',
                nickname TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS rooms (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                contact_hash TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(contact_hash) REFERENCES contacts(hash)
            );

            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_hash TEXT NOT NULL,
                room_hash TEXT NOT NULL,
                direction TEXT NOT NULL,
                text TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'delivered',
                is_ephemeral INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER,
                FOREIGN KEY(contact_hash) REFERENCES contacts(hash),
                FOREIGN KEY(room_hash) REFERENCES contacts(hash)
            );

            CREATE TABLE IF NOT EXISTS tor_service (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                service_id TEXT NOT NULL,
                private_key TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                room_hash TEXT NOT NULL,
                recipient_onion TEXT NOT NULL,
                packet BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_retry_at INTEGER NOT NULL,
                last_error TEXT
            );

            CREATE TABLE IF NOT EXISTS ratchet_states (
                room_hash TEXT PRIMARY KEY,
                state BLOB NOT NULL,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS retired_ratchet_sessions (
                room_hash TEXT NOT NULL,
                session_id BLOB NOT NULL,
                retired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (room_hash, session_id)
            );

            -- M-C: для TTL-комнат на диск пишутся только alias сессии и
            -- SHA256(session_id). Сам session_id/ratchet здесь отсутствуют.
            CREATE TABLE IF NOT EXISTS ttl_tombstones (
                session_alias BLOB PRIMARY KEY,
                session_id_hash BLOB NOT NULL,
                retired_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_hash);
            CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_hash);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
            CREATE INDEX IF NOT EXISTS idx_outbox_due ON outbox(next_retry_at, id);
            CREATE INDEX IF NOT EXISTS idx_outbox_room ON outbox(room_hash);
            CREATE INDEX IF NOT EXISTS idx_ttl_tombstones_retired ON ttl_tombstones(retired_at);
        ",
        )
        .map_err(|e| anyhow!("failed to create tables: {}", e))?;

        Ok(())
    }

    // ============================================================
    // ENCRYPTED CONTAINER
    // ============================================================

    /// Дополняет открытый блок так, чтобы итоговый контейнер
    /// (`plaintext + nonce + tag`) попал в bucket-сетку с джиттером.
    fn padded_plaintext_len(payload_len: usize) -> Result<usize> {
        let with_overhead = INNER_HEADER_LEN
            .checked_add(payload_len)
            .and_then(|len| len.checked_add(CONTAINER_OVERHEAD))
            .ok_or_else(|| anyhow!("database dump is too large"))?;

        let padded_total = crate::crypto::padded_bucket_len(with_overhead, &VAULT_PADDING_BUCKETS)
            .ok_or_else(|| anyhow!("database dump is too large"))?;

        padded_total
            .checked_sub(CONTAINER_OVERHEAD)
            .ok_or_else(|| anyhow!("database dump is too large"))
    }

    /// Переставляет mtime `vault.dat` на случайное значение.
    ///
    /// Значение обновляется не на каждую запись, а раз в 5–15 минут и
    /// сдвигается на случайные 1 секунду … 6 часов назад. Так mtime не
    /// показывает точное время активности, хотя полностью утечку не
    /// устраняет. Ошибка метаданных не должна терять уже записанные данные:
    /// она только логируется.
    fn randomize_vault_mtime(&self) {
        let now = SystemTime::now();
        let anchor = {
            // Простая RAM-структура: poison не означает потерю данных.
            let mut state = self
                .mtime
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let refresh = state
                .next_refresh
                .map(|deadline| Instant::now() >= deadline)
                .unwrap_or(true);

            if refresh {
                let age = 1 + OsRng.next_u64() % MTIME_MAX_AGE_SECS;
                state.anchor = Some(now.checked_sub(Duration::from_secs(age)).unwrap_or(now));
                let interval = MTIME_REFRESH_MIN_SECS
                    + OsRng.next_u64() % (MTIME_REFRESH_MAX_SECS - MTIME_REFRESH_MIN_SECS + 1);
                state.next_refresh = Some(Instant::now() + Duration::from_secs(interval));
            }

            state.anchor.unwrap_or(now)
        };

        if let Err(e) = self.safe_fs.set_mtime(VAULT_FILE_NAME, anchor) {
            log::warn!("failed to randomize vault.dat mtime: {:#}", e);
        }
    }

    /// Сериализует снимок и шифрует его: `nonce || ciphertext || tag`.
    ///
    /// Внутренний заголовок (`LCDB`, версия, длина JSON) находится внутри
    /// шифротекста, хвост добивается случайными байтами.
    fn encode_container(key: &MasterKey, snapshot: &Snapshot) -> Result<Vec<u8>> {
        let payload = Zeroizing::new(
            serde_json::to_vec(snapshot)
                .map_err(|e| anyhow!("failed to serialize database: {}", e))?,
        );
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| anyhow!("database dump is too large"))?;
        let plain_len = Self::padded_plaintext_len(payload.len())?;

        let mut plain = Zeroizing::new(vec![0u8; plain_len]);
        plain[..INNER_MAGIC.len()].copy_from_slice(INNER_MAGIC);
        plain[INNER_MAGIC.len()] = INNER_VERSION;
        plain[5..INNER_HEADER_LEN].copy_from_slice(&payload_len.to_le_bytes());
        plain[INNER_HEADER_LEN..INNER_HEADER_LEN + payload.len()].copy_from_slice(&payload);

        // Случайный паддинг: содержимое зашифровано, но хвост не должен
        // быть детерминированным даже при одинаковом наборе строк.
        OsRng.fill_bytes(&mut plain[INNER_HEADER_LEN + payload.len()..]);

        key.encrypt(plain.as_slice(), VAULT_AAD)
    }

    /// Расшифровывает и разбирает контейнер `vault.dat`.
    fn decode_container(key: &MasterKey, data: &[u8]) -> Result<Snapshot> {
        if data.len() <= CONTAINER_OVERHEAD {
            return Err(anyhow!("vault.dat is truncated"));
        }

        let plain = Zeroizing::new(key.decrypt(data, VAULT_AAD)?);

        if plain.len() < INNER_HEADER_LEN || &plain[..INNER_MAGIC.len()] != INNER_MAGIC {
            return Err(anyhow!("corrupted storage container header"));
        }
        if plain[INNER_MAGIC.len()] != INNER_VERSION {
            return Err(anyhow!(
                "unsupported storage schema version: {}",
                plain[INNER_MAGIC.len()]
            ));
        }

        let payload_len = u32::from_le_bytes([plain[5], plain[6], plain[7], plain[8]]) as usize;

        if payload_len > MAX_PAYLOAD_LEN {
            return Err(anyhow!("storage payload length is out of range"));
        }
        let end = INNER_HEADER_LEN
            .checked_add(payload_len)
            .ok_or_else(|| anyhow!("storage payload length is out of range"))?;
        if end > plain.len() {
            return Err(anyhow!("storage payload exceeds container size"));
        }

        serde_json::from_slice(&plain[INNER_HEADER_LEN..end])
            .map_err(|e| anyhow!("failed to parse storage payload: {}", e))
    }

    /// Атомарно записывает зашифрованный снимок под текущим ключом.
    fn persist(&self) -> Result<()> {
        let conn = self.conn()?;
        self.persist_locked(&conn)
    }

    /// Вариант [`Self::persist`] для вызывающих, которые уже держат
    /// блокировку базы (иначе был бы deadlock).
    fn persist_locked(&self, conn: &Connection) -> Result<()> {
        let key = self.vault.key()?;
        let snapshot = Self::dump_snapshot(conn)?;
        let sealed = Self::encode_container(&key, &snapshot)?;
        self.safe_fs
            .safe_write_file(VAULT_FILE_NAME, &sealed, 0o600)?;
        self.randomize_vault_mtime();
        Ok(())
    }

    /// Перешифровывает контейнер новым ключом, не отпуская блокировку базы.
    fn rekey(&self, new_key: &MasterKey) -> Result<()> {
        let conn = self.conn()?;
        let snapshot = Self::dump_snapshot(&conn)?;
        let sealed = Self::encode_container(new_key, &snapshot)?;
        self.safe_fs
            .safe_write_file(VAULT_FILE_NAME, &sealed, 0o600)?;
        self.randomize_vault_mtime();

        // Ключ меняем только после успешной записи: при ошибке профиль
        // остаётся доступным старым ключом.
        self.vault.replace_key(new_key.clone())?;
        Ok(())
    }

    /// Совместимость с прежним API смены пароля.
    ///
    /// Отдельных зашифрованных полей больше нет — весь контейнер
    /// перешифровывается новым ключом.
    pub fn reencrypt_fields(&self, _old_key: &MasterKey, new_key: &MasterKey) -> Result<()> {
        self.rekey(new_key)
    }

    /// Перешифровывает контейнер и переключает `Vault` на новый ключ.
    pub fn reencrypt_fields_and_replace_key(
        &self,
        _old_key: &MasterKey,
        new_key: &MasterKey,
    ) -> Result<()> {
        self.rekey(new_key)
    }

    // ============================================================
    // SNAPSHOT I/O
    // ============================================================

    fn dump_snapshot(conn: &Connection) -> Result<Snapshot> {
        let contacts = {
            let mut stmt = conn
                .prepare(
                    "SELECT hash, public_key, ed25519, onion_addr, fingerprint, tofu_state, nickname, created_at
                     FROM contacts ORDER BY created_at ASC",
                )
                .map_err(|e| anyhow!("failed to prepare contacts dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(ContactRow {
                        hash: row.get(0)?,
                        public_key: hex::encode(row.get::<_, Vec<u8>>(1)?),
                        ed25519: row.get(2)?,
                        onion_addr: row.get(3)?,
                        fingerprint: row.get(4)?,
                        tofu_state: row
                            .get::<_, Option<String>>(5)?
                            .unwrap_or_else(default_tofu_state),
                        nickname: row.get(6)?,
                        created_at: row.get::<_, Option<String>>(7)?.unwrap_or_default(),
                    })
                })
                .map_err(|e| anyhow!("failed to dump contacts: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read contacts: {}", e))?;
            rows
        };

        let rooms = {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, contact_hash, created_at
                     FROM rooms ORDER BY id ASC",
                )
                .map_err(|e| anyhow!("failed to prepare rooms dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(RoomRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        contact_hash: row.get(2)?,
                        created_at: row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    })
                })
                .map_err(|e| anyhow!("failed to dump rooms: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read rooms: {}", e))?;
            rows
        };

        let messages = {
            let mut stmt = conn
                .prepare(
                    "SELECT id, contact_hash, room_hash, direction, text, timestamp, status,
                            is_ephemeral, expires_at
                     FROM messages
                     WHERE is_ephemeral = 0
                     ORDER BY id ASC",
                )
                .map_err(|e| anyhow!("failed to prepare messages dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(MessageRow {
                        id: row.get(0)?,
                        contact_hash: row.get(1)?,
                        room_hash: row.get(2)?,
                        direction: row.get(3)?,
                        text: row.get(4)?,
                        timestamp: row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                        status: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                        is_ephemeral: row.get::<_, i64>(7)? != 0,
                        expires_at: row
                            .get::<_, Option<i64>>(8)?
                            .map(|value| value.max(0) as u64),
                    })
                })
                .map_err(|e| anyhow!("failed to dump messages: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read messages: {}", e))?;
            rows
        };

        let tor_service = conn
            .query_row(
                "SELECT service_id, private_key FROM tor_service WHERE id = 1",
                [],
                |row| {
                    Ok(TorServiceRow {
                        service_id: row.get(0)?,
                        private_key: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(|e| anyhow!("failed to dump tor service: {}", e))?;

        let outbox = {
            let mut stmt = conn
                .prepare(
                    "SELECT id, room_hash, recipient_onion, packet, created_at,
                            attempts, next_retry_at, last_error
                     FROM outbox ORDER BY id ASC",
                )
                .map_err(|e| anyhow!("failed to prepare outbox dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(OutboxRow {
                        id: row.get(0)?,
                        room_hash: row.get(1)?,
                        recipient_onion: row.get(2)?,
                        packet: hex::encode(row.get::<_, Vec<u8>>(3)?),
                        created_at: row.get(4)?,
                        attempts: row.get::<_, i64>(5)?.max(0) as u32,
                        next_retry_at: row.get(6)?,
                        last_error: row.get(7)?,
                    })
                })
                .map_err(|e| anyhow!("failed to dump outbox: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read outbox: {}", e))?;
            rows
        };

        let ratchet_states = {
            let mut stmt = conn
                .prepare("SELECT room_hash, state FROM ratchet_states ORDER BY room_hash ASC")
                .map_err(|e| anyhow!("failed to prepare ratchet dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(RatchetRow {
                        room_hash: row.get(0)?,
                        state: hex::encode(row.get::<_, Vec<u8>>(1)?),
                    })
                })
                .map_err(|e| anyhow!("failed to dump ratchet states: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read ratchet states: {}", e))?;
            rows
        };

        let retired_ratchet_sessions = {
            let mut stmt = conn
                .prepare(
                    "SELECT room_hash, session_id FROM retired_ratchet_sessions
                     ORDER BY rowid ASC",
                )
                .map_err(|e| anyhow!("failed to prepare retired session dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(RetiredSessionRow {
                        room_hash: row.get(0)?,
                        session_id: hex::encode(row.get::<_, Vec<u8>>(1)?),
                    })
                })
                .map_err(|e| anyhow!("failed to dump retired sessions: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read retired sessions: {}", e))?;
            rows
        };

        let ttl_tombstones = {
            let mut stmt = conn
                .prepare(
                    "SELECT session_alias, session_id_hash, retired_at
                     FROM ttl_tombstones ORDER BY retired_at ASC, rowid ASC",
                )
                .map_err(|e| anyhow!("failed to prepare ttl tombstone dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(TtlTombstoneRow {
                        session_alias: hex::encode(row.get::<_, Vec<u8>>(0)?),
                        session_id_hash: hex::encode(row.get::<_, Vec<u8>>(1)?),
                        retired_at: row.get::<_, i64>(2)?.max(0) as u64,
                    })
                })
                .map_err(|e| anyhow!("failed to dump ttl tombstones: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read ttl tombstones: {}", e))?;
            rows
        };

        Ok(Snapshot {
            contacts,
            rooms,
            messages,
            ratchet_states,
            retired_ratchet_sessions,
            ttl_tombstones,
            tor_service,
            outbox,
        })
    }

    fn load_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let mut conn = self.conn()?;

        // Внешние ключи на время импорта отключены: переносим строки как
        // есть, включая возможные неконсистентности старой базы.
        conn.execute_batch("PRAGMA foreign_keys=OFF;")
            .map_err(|e| anyhow!("failed to disable foreign keys: {}", e))?;

        let result = (|| -> Result<()> {
            let tx = conn
                .transaction()
                .map_err(|e| anyhow!("failed to start transaction: {}", e))?;

            for contact in &snapshot.contacts {
                let public_key = hex::decode(&contact.public_key)
                    .map_err(|e| anyhow!("corrupted public key for contact in storage: {}", e))?;
                tx.execute(
                    "INSERT OR REPLACE INTO contacts
                        (hash, public_key, ed25519, onion_addr, fingerprint, tofu_state, nickname, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        contact.hash,
                        public_key,
                        contact.ed25519,
                        contact.onion_addr,
                        contact.fingerprint,
                        contact.tofu_state,
                        contact.nickname,
                        contact.created_at
                    ],
                )
                .map_err(|e| anyhow!("failed to restore contact: {}", e))?;
            }

            for room in &snapshot.rooms {
                tx.execute(
                    "INSERT OR REPLACE INTO rooms (id, name, contact_hash, created_at)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![room.id, room.name, room.contact_hash, room.created_at],
                )
                .map_err(|e| anyhow!("failed to restore room: {}", e))?;
            }

            for message in &snapshot.messages {
                tx.execute(
                    "INSERT OR REPLACE INTO messages
                        (id, contact_hash, room_hash, direction, text, timestamp, status,
                         is_ephemeral, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        message.id,
                        message.contact_hash,
                        message.room_hash,
                        message.direction,
                        message.text,
                        message.timestamp,
                        message.status,
                        message.is_ephemeral,
                        message.expires_at.map(|value| value as i64)
                    ],
                )
                .map_err(|e| anyhow!("failed to restore message: {}", e))?;
            }

            if let Some(service) = &snapshot.tor_service {
                tx.execute(
                    "INSERT OR REPLACE INTO tor_service (id, service_id, private_key)
                     VALUES (1, ?1, ?2)",
                    params![service.service_id, service.private_key],
                )
                .map_err(|e| anyhow!("failed to restore tor service: {}", e))?;
            }

            for item in &snapshot.outbox {
                let packet = hex::decode(&item.packet)
                    .map_err(|e| anyhow!("corrupted outbox packet in storage: {}", e))?;
                tx.execute(
                    "INSERT OR REPLACE INTO outbox
                        (id, room_hash, recipient_onion, packet, created_at, attempts, next_retry_at, last_error)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        item.id,
                        item.room_hash,
                        item.recipient_onion,
                        packet,
                        item.created_at,
                        item.attempts as i64,
                        item.next_retry_at,
                        item.last_error
                    ],
                )
                .map_err(|e| anyhow!("failed to restore outbox item: {}", e))?;
            }

            for ratchet in &snapshot.ratchet_states {
                let state = hex::decode(&ratchet.state)
                    .map_err(|e| anyhow!("corrupted ratchet state in storage: {}", e))?;
                tx.execute(
                    "INSERT OR REPLACE INTO ratchet_states (room_hash, state)
                     VALUES (?1, ?2)",
                    params![ratchet.room_hash, state],
                )
                .map_err(|e| anyhow!("failed to restore ratchet state: {}", e))?;
            }

            for retired in &snapshot.retired_ratchet_sessions {
                let session_id = hex::decode(&retired.session_id)
                    .map_err(|e| anyhow!("corrupted retired session in storage: {}", e))?;
                if session_id.len() != 16 {
                    return Err(anyhow!("retired session id must be 16 bytes"));
                }
                tx.execute(
                    "INSERT OR REPLACE INTO retired_ratchet_sessions (room_hash, session_id)
                     VALUES (?1, ?2)",
                    params![retired.room_hash, session_id],
                )
                .map_err(|e| anyhow!("failed to restore retired session: {}", e))?;
            }

            for tombstone in &snapshot.ttl_tombstones {
                let alias = hex::decode(&tombstone.session_alias)
                    .map_err(|e| anyhow!("corrupted ttl tombstone alias: {}", e))?;
                let hash = hex::decode(&tombstone.session_id_hash)
                    .map_err(|e| anyhow!("corrupted ttl tombstone hash: {}", e))?;
                if alias.len() != 16 || hash.len() != 32 {
                    return Err(anyhow!("ttl tombstone fields have invalid lengths"));
                }
                tx.execute(
                    "INSERT OR REPLACE INTO ttl_tombstones
                        (session_alias, session_id_hash, retired_at)
                     VALUES (?1, ?2, ?3)",
                    params![alias, hash, tombstone.retired_at as i64],
                )
                .map_err(|e| anyhow!("failed to restore ttl tombstone: {}", e))?;
            }

            tx.commit()
                .map_err(|e| anyhow!("failed to commit snapshot restore: {}", e))?;
            Ok(())
        })();

        let _ = conn.execute_batch("PRAGMA foreign_keys=ON;");
        result
    }

    // ============================================================
    // LEGACY MIGRATION
    // ============================================================

    /// Читает контакты, комнаты, сообщения и файлы из старой открытой
    /// `user.db`. Чувствительные поля, зашифрованные прежней версией
    /// (`lc1:...`), расшифровываются мастер-ключом.
    fn read_legacy_snapshot(&self, path: &Path) -> Result<Snapshot> {
        let conn =
            Connection::open(path).map_err(|e| anyhow!("failed to open legacy database: {}", e))?;

        let mut snapshot = Snapshot::default();

        if table_exists(&conn, "contacts")? {
            let ed25519_col = if has_column(&conn, "contacts", "ed25519")? {
                "ed25519"
            } else {
                "NULL"
            };
            let fingerprint_col = if has_column(&conn, "contacts", "fingerprint")? {
                "fingerprint"
            } else {
                "NULL"
            };
            let tofu_col = if has_column(&conn, "contacts", "tofu_state")? {
                "tofu_state"
            } else {
                "NULL"
            };
            let sql = format!(
                "SELECT hash, public_key, {}, nickname, created_at, {}, {} FROM contacts",
                ed25519_col, fingerprint_col, tofu_col
            );
            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| anyhow!("failed to read legacy contacts: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                })
                .map_err(|e| anyhow!("failed to query legacy contacts: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read legacy contacts: {}", e))?;

            for (hash, public_key, ed25519, nickname, created_at, fingerprint, tofu_state) in rows
            {
                snapshot.contacts.push(ContactRow {
                    hash,
                    public_key: hex::encode(public_key),
                    ed25519,
                    onion_addr: None,
                    fingerprint,
                    tofu_state: tofu_state
                        .filter(|state| !state.is_empty())
                        .unwrap_or_else(default_tofu_state),
                    nickname: self.vault.decrypt_str(&nickname)?,
                    created_at,
                });
            }
        }

        if table_exists(&conn, "rooms")? {
            let mut stmt = conn
                .prepare("SELECT id, name, contact_hash, created_at FROM rooms")
                .map_err(|e| anyhow!("failed to read legacy rooms: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?.unwrap_or_default(),
                    ))
                })
                .map_err(|e| anyhow!("failed to query legacy rooms: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read legacy rooms: {}", e))?;

            for (id, name, contact_hash, created_at) in rows {
                snapshot.rooms.push(RoomRow {
                    id,
                    name: self.vault.decrypt_str(&name)?,
                    contact_hash,
                    created_at,
                });
            }
        }

        if table_exists(&conn, "messages")? {
            let mut stmt = conn
                .prepare(
                    "SELECT id, contact_hash, room_hash, direction, text, timestamp, status
                     FROM messages",
                )
                .map_err(|e| anyhow!("failed to read legacy messages: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                        row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                    ))
                })
                .map_err(|e| anyhow!("failed to query legacy messages: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read legacy messages: {}", e))?;

            for (id, contact_hash, room_hash, direction, text, timestamp, status) in rows {
                snapshot.messages.push(MessageRow {
                    id,
                    contact_hash,
                    room_hash,
                    direction,
                    text: self.vault.decrypt_str(&text)?,
                    timestamp,
                    status,
                    is_ephemeral: false,
                    expires_at: None,
                });
            }
        }

        Ok(snapshot)
    }

    /// Затирает `user.db` вместе с `-journal`, `-wal` и `-shm` нулями и
    /// удаляет их.
    fn purge_legacy_files(db_path: &Path) {
        if let Err(e) = secure_remove_file(db_path) {
            log::warn!(
                "failed to securely remove legacy database file {:?}: {:#}",
                db_path,
                e
            );
        }
    }

    // ============================================================
    // CONTACTS
    // ============================================================

    pub fn add_contact(&self, hash: &str, public_key: &[u8], nickname: &str) -> Result<()> {
        self.add_contact_with_ed25519(hash, public_key, None, nickname)
    }

    /// Сохраняет контакт вместе с Ed25519-ключом (тестовый/упрощённый путь).
    pub fn add_contact_with_ed25519(
        &self,
        hash: &str,
        public_key: &[u8],
        ed25519: Option<&str>,
        nickname: &str,
    ) -> Result<()> {
        self.upsert_contact(
            hash,
            public_key,
            ed25519,
            None,
            nickname,
            None,
            None,
        )
    }

    /// Сохраняет криптографически проверенный контакт с отпечатком и TOFU (без `.onion`).
    pub fn upsert_verified_contact(
        &self,
        hash: &str,
        public_key: &[u8],
        ed25519: &str,
        fingerprint: &str,
        tofu_state: &str,
        nickname: &str,
    ) -> Result<()> {
        self.upsert_contact(
            hash,
            public_key,
            Some(ed25519),
            None,
            nickname,
            Some(fingerprint),
            Some(tofu_state),
        )
    }

    /// Сохраняет проверенный P2P-контакт вместе с подписанным Tor v3 `.onion`-адресом.
    #[allow(clippy::too_many_arguments)]
    pub fn upsert_p2p_contact(
        &self,
        hash: &str,
        public_key: &[u8],
        ed25519: &str,
        onion_addr: &str,
        fingerprint: &str,
        tofu_state: &str,
        nickname: &str,
    ) -> Result<()> {
        let normalized_onion = OnionAddress::parse(onion_addr)
            .map_err(|e| anyhow!("invalid peer .onion address: {}", e))?;
        self.upsert_contact(
            hash,
            public_key,
            Some(ed25519),
            Some(normalized_onion.as_str()),
            nickname,
            Some(fingerprint),
            Some(tofu_state),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_contact(
        &self,
        hash: &str,
        public_key: &[u8],
        ed25519: Option<&str>,
        onion_addr: Option<&str>,
        nickname: &str,
        fingerprint: Option<&str>,
        tofu_state: Option<&str>,
    ) -> Result<()> {
        IdentityHash::from_hex(hash).map_err(|e| {
            anyhow!(
                "invalid contact hash ({}…, {} chars): {}",
                truncate_display(hash, 16),
                hash.chars().count(),
                e
            )
        })?;
        if let Some(addr) = onion_addr {
            OnionAddress::parse(addr)
                .map_err(|e| anyhow!("invalid peer .onion address: {}", e))?;
        }

        let tofu_state = tofu_state.unwrap_or(TOFU_PENDING);
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO contacts
                (hash, public_key, ed25519, onion_addr, fingerprint, tofu_state, nickname)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(hash) DO UPDATE SET
                 public_key = excluded.public_key,
                 nickname = excluded.nickname,
                 ed25519 = COALESCE(excluded.ed25519, contacts.ed25519),
                 onion_addr = COALESCE(excluded.onion_addr, contacts.onion_addr),
                 fingerprint = COALESCE(excluded.fingerprint, contacts.fingerprint),
                 tofu_state = CASE
                     WHEN ?5 IS NULL THEN contacts.tofu_state
                     ELSE excluded.tofu_state
                 END",
            params![
                hash,
                public_key,
                ed25519,
                onion_addr,
                fingerprint,
                tofu_state,
                nickname
            ],
        )
        .map_err(|e| anyhow!("failed to add contact: {}", e))?;

        self.persist_locked(&conn)
    }

    /// Меняет TOFU-состояние контакта после сверки отпечатка.
    pub fn set_contact_tofu_state(&self, hash: &str, tofu_state: &str) -> Result<()> {
        let conn = self.conn()?;
        let affected = conn
            .execute(
                "UPDATE contacts SET tofu_state = ?1 WHERE hash = ?2",
                params![tofu_state, hash],
            )
            .map_err(|e| anyhow!("failed to update contact TOFU state: {}", e))?;

        if affected == 0 {
            return Err(anyhow!(
                "contact not found: {}",
                truncate_display(hash, 16)
            ));
        }

        self.persist_locked(&conn)
    }

    pub fn get_contact(&self, hash: &str) -> Result<Contact> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT hash, public_key, ed25519, onion_addr, fingerprint, tofu_state, nickname, created_at
                 FROM contacts WHERE hash = ?1",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let (hash_value, public_key, ed25519, onion_addr, fingerprint, tofu_state, nickname, created_at): ContactDbRow =
            stmt
            .query_row(params![hash], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            })
            .map_err(|_e| anyhow!("contact not found: {}", truncate_display(hash, 16)))?;

        Ok(Contact {
            hash: hash_value,
            public_key,
            ed25519,
            onion_addr,
            fingerprint,
            tofu_state: tofu_state
                .filter(|state| !state.is_empty())
                .unwrap_or_else(default_tofu_state),
            nickname,
            created_at: parse_timestamp(&created_at),
        })
    }

    pub fn get_all_contacts(&self) -> Result<Vec<Contact>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT hash, public_key, ed25519, onion_addr, fingerprint, tofu_state, nickname, created_at
                 FROM contacts ORDER BY created_at DESC",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(|e| anyhow!("failed to query contacts: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read contacts: {}", e))?;

        let mut contacts = Vec::with_capacity(rows.len());
        for (hash, public_key, ed25519, onion_addr, fingerprint, tofu_state, nickname, created_at) in rows {
            contacts.push(Contact {
                hash,
                public_key,
                ed25519,
                onion_addr,
                fingerprint,
                tofu_state: tofu_state
                    .filter(|state| !state.is_empty())
                    .unwrap_or_else(default_tofu_state),
                nickname,
                created_at: parse_timestamp(&created_at),
            });
        }

        Ok(contacts)
    }

    pub fn get_contact_hash_by_nickname(&self, nickname: &str) -> Result<String> {
        {
            let conn = self.conn()?;
            let mut stmt = conn
                .prepare("SELECT contact_hash, name FROM rooms")
                .map_err(|e| anyhow!("failed to prepare query: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| anyhow!("failed to query rooms: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read rooms: {}", e))?;

            for (hash, name) in rows {
                if name == nickname {
                    return Ok(hash);
                }
            }
        }

        let contacts = self.get_all_contacts()?;
        let contact = contacts
            .iter()
            .find(|contact| contact.nickname == nickname)
            .ok_or_else(|| anyhow!("contact not found: {}", nickname))?;

        let hash = contact.hash.clone();
        self.ensure_room(nickname, &hash)?;
        Ok(hash)
    }

    pub fn ensure_room(&self, nickname: &str, hash: &str) -> Result<()> {
        let conn = self.conn()?;

        let exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM rooms WHERE contact_hash = ?1 LIMIT 1",
                params![hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| anyhow!("failed to query room: {}", e))?;

        if exists.is_some() {
            return Ok(());
        }

        conn.execute(
            "INSERT OR IGNORE INTO rooms (name, contact_hash) VALUES (?1, ?2)",
            params![nickname, hash],
        )
        .map_err(|e| anyhow!("failed to ensure room: {}", e))?;

        self.persist_locked(&conn)
    }

    pub fn update_contact_nickname(&self, contact_hash: &str, new_nickname: &str) -> Result<()> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| anyhow!("failed to start transaction: {}", e))?;

        let affected = tx
            .execute(
                "UPDATE contacts SET nickname = ?1 WHERE hash = ?2",
                params![new_nickname, contact_hash],
            )
            .map_err(|e| anyhow!("failed to update contact nickname: {}", e))?;

        if affected == 0 {
            return Err(anyhow!(
                "contact not found: {}",
                truncate_display(contact_hash, 16)
            ));
        }

        // Имя комнаты хранится отдельно и используется для поиска по нику,
        // поэтому переименование должно менять и его.
        tx.execute(
            "UPDATE rooms SET name = ?1 WHERE contact_hash = ?2",
            params![new_nickname, contact_hash],
        )
        .map_err(|e| anyhow!("failed to update room name: {}", e))?;

        tx.commit()
            .map_err(|e| anyhow!("failed to commit rename: {}", e))?;

        self.persist_locked(&conn)
    }

    /// Количество сообщений, связанных с контактом (входящих и исходящих).
    pub fn count_messages(&self, contact_hash: &str) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE contact_hash = ?1 OR room_hash = ?1",
                params![contact_hash],
                |row| row.get(0),
            )
            .map_err(|e| anyhow!("failed to count messages: {}", e))?;
        Ok(count.max(0) as usize)
    }

    /// Удаляет контакт и всю связанную историю: сообщения, файлы и комнату.
    ///
    /// Внешние ключи объявлены без `ON DELETE CASCADE`, поэтому очистка
    /// выполняется явно и в одной транзакции.
    pub fn delete_contact(&self, contact_hash: &str) -> Result<()> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| anyhow!("failed to start transaction: {}", e))?;

        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM contacts WHERE hash = ?1",
                params![contact_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| anyhow!("failed to query contact: {}", e))?;

        if exists.is_none() {
            return Err(anyhow!(
                "contact not found: {}",
                truncate_display(contact_hash, 16)
            ));
        }

        tx.execute(
            "DELETE FROM messages WHERE contact_hash = ?1 OR room_hash = ?1",
            params![contact_hash],
        )
        .map_err(|e| anyhow!("failed to delete messages: {}", e))?;
        tx.execute(
            "DELETE FROM outbox WHERE room_hash = ?1",
            params![contact_hash],
        )
        .map_err(|e| anyhow!("failed to delete outbox items: {}", e))?;
        tx.execute(
            "DELETE FROM ratchet_states WHERE room_hash = ?1",
            params![contact_hash],
        )
        .map_err(|e| anyhow!("failed to delete ratchet state: {}", e))?;
        tx.execute(
            "DELETE FROM rooms WHERE contact_hash = ?1",
            params![contact_hash],
        )
        .map_err(|e| anyhow!("failed to delete room: {}", e))?;
        tx.execute(
            "DELETE FROM contacts WHERE hash = ?1",
            params![contact_hash],
        )
        .map_err(|e| anyhow!("failed to delete contact: {}", e))?;

        tx.commit()
            .map_err(|e| anyhow!("failed to commit contact deletion: {}", e))?;

        self.persist_locked(&conn)
    }

    // ============================================================
    // MESSAGES
    // ============================================================

    pub fn save_message_with_room(
        &self,
        contact_hash: &str,
        direction: &str,
        room_hash: &str,
        text: &str,
    ) -> Result<()> {
        self.save_message_with_room_meta(contact_hash, direction, room_hash, text, false, None)
    }

    /// Сохраняет сообщение и его TTL-метаданные.
    ///
    /// Исчезающие сообщения остаются только в in-memory SQLite: запись
    /// `vault.dat` для них пропускается, а дамп снимка их всегда исключает.
    #[allow(clippy::too_many_arguments)]
    pub fn save_message_with_room_meta(
        &self,
        contact_hash: &str,
        direction: &str,
        room_hash: &str,
        text: &str,
        is_ephemeral: bool,
        expires_at: Option<u64>,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO messages
                (contact_hash, direction, room_hash, text, status, is_ephemeral, expires_at)
             VALUES (?1, ?2, ?3, ?4, 'delivered', ?5, ?6)",
            params![
                contact_hash,
                direction,
                room_hash,
                text,
                is_ephemeral,
                expires_at.map(|value| value as i64)
            ],
        )
        .map_err(|e| anyhow!("failed to save message: {}", e))?;

        if is_ephemeral {
            Ok(())
        } else {
            self.persist_locked(&conn)
        }
    }

    pub fn save_message(&self, contact_hash: &str, direction: &str, text: &str) -> Result<()> {
        self.save_message_with_room(contact_hash, direction, contact_hash, text)
    }

    pub fn get_room_messages(&self, room_hash: &str, limit: i64) -> Result<Vec<Message>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, contact_hash, direction, text, timestamp, status,
                        is_ephemeral, expires_at
                 FROM messages
                 WHERE room_hash = ?1
                 ORDER BY timestamp DESC, id DESC
                 LIMIT ?2",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map(params![room_hash, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    row.get::<_, Option<String>>(5)?.unwrap_or_default(),
                    row.get::<_, i64>(6)? != 0,
                    row.get::<_, Option<i64>>(7)?,
                ))
            })
            .map_err(|e| anyhow!("failed to query messages: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read messages: {}", e))?;

        let mut messages = Vec::with_capacity(rows.len());
        for (id, contact_hash, direction, text, timestamp, status, is_ephemeral, expires_at) in rows
        {
            messages.push(Message {
                id,
                contact_hash,
                room_hash: room_hash.to_string(),
                direction,
                text,
                timestamp: parse_timestamp(&timestamp),
                status,
                is_ephemeral,
                expires_at: expires_at.map(|value| value.max(0) as u64),
            });
        }

        Ok(messages)
    }

    pub fn get_messages(&self, contact_hash: &str, limit: i64) -> Result<Vec<Message>> {
        self.get_room_messages(contact_hash, limit)
    }

    /// Затирает и удаляет из оперативной памяти истёкшие сообщения.
    ///
    /// `vault.dat` не перезаписывается: эфемерные сообщения и так не
    /// попадают в снимок. Тексты сначала перезаписываются пустой строкой
    /// в SQLite, а их Rust-буферы оборачиваются в [`Zeroizing`].
    pub fn purge_expired_messages(&self, now: u64) -> Result<Vec<i64>> {
        let mut conn = self.conn()?;

        let expired: Vec<(i64, String)> = {
            let mut stmt = conn
                .prepare(
                    "SELECT id, text FROM messages
                     WHERE is_ephemeral = 1
                       AND expires_at IS NOT NULL
                       AND expires_at <= ?1
                     ORDER BY id ASC",
                )
                .map_err(|e| anyhow!("failed to prepare expiry query: {}", e))?;
            let rows = stmt
                .query_map(params![now as i64], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(|e| anyhow!("failed to query expired messages: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read expired messages: {}", e))?;
            rows
        };

        if expired.is_empty() {
            return Ok(Vec::new());
        }

        let tx = conn
            .transaction()
            .map_err(|e| anyhow!("failed to start expiry transaction: {}", e))?;

        for (id, _) in &expired {
            tx.execute("UPDATE messages SET text = '' WHERE id = ?1", params![id])
                .map_err(|e| anyhow!("failed to wipe expired message: {}", e))?;
        }
        tx.execute(
            "DELETE FROM messages
             WHERE is_ephemeral = 1
               AND expires_at IS NOT NULL
               AND expires_at <= ?1",
            params![now as i64],
        )
        .map_err(|e| anyhow!("failed to delete expired messages: {}", e))?;
        tx.commit()
            .map_err(|e| anyhow!("failed to commit expiry transaction: {}", e))?;

        let ids: Vec<i64> = expired.iter().map(|(id, _)| *id).collect();
        // Строковые буферы затираются при drop.
        let buffers: Vec<Zeroizing<String>> = expired
            .into_iter()
            .map(|(_, text)| Zeroizing::new(text))
            .collect();
        drop(buffers);

        Ok(ids)
    }

    /// Снимок сообщений, реально записанных в `vault.dat` (только для тестов).
    #[cfg(test)]
    pub(crate) fn persisted_messages_for_test(&self) -> Result<Vec<Message>> {
        let key = self.vault.key()?;
        let data = self.safe_fs.safe_read_file(VAULT_FILE_NAME)?;
        let snapshot = Self::decode_container(&key, &data)?;

        Ok(snapshot
            .messages
            .into_iter()
            .map(|row| Message {
                id: row.id,
                contact_hash: row.contact_hash,
                room_hash: row.room_hash,
                direction: row.direction,
                text: row.text,
                timestamp: parse_timestamp(&row.timestamp),
                status: row.status,
                is_ephemeral: row.is_ephemeral,
                expires_at: row.expires_at,
            })
            .collect())
    }

    // ============================================================
    // DOUBLE RATCHET STATE
    // ============================================================

    /// Сохраняет состояние храповика комнаты в зашифрованный `vault.dat`.
    ///
    /// Для комнат с активным RAM-TTL этот метод не вызывается: состояние
    /// живёт только в памяти `App`.
    pub fn save_ratchet_state(&self, room_hash: &str, state: &[u8]) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO ratchet_states (room_hash, state, updated_at)
             VALUES (?1, ?2, CURRENT_TIMESTAMP)",
            params![room_hash, state],
        )
        .map_err(|e| anyhow!("failed to save ratchet state: {}", e))?;

        self.persist_locked(&conn)
    }

    /// Загружает состояние храповика комнаты, если оно есть в `vault.dat`.
    ///
    /// Возвращает `SecretBytes`: снапшот содержит корневые/цепные ключи и
    /// приватные DH-ключи, поэтому он затирается при `drop` и не может
    /// случайно утечь как обычный `Vec<u8>`.
    pub fn load_ratchet_state(&self, room_hash: &str) -> Result<Option<SecretBytes>> {
        let conn = self.conn()?;
        conn.query_row(
            "SELECT state FROM ratchet_states WHERE room_hash = ?1",
            params![room_hash],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map(|state| state.map(SecretBytes::new))
        .map_err(|e| anyhow!("failed to load ratchet state: {}", e))
    }

    /// Удаляет состояние храповика комнаты из памяти и `vault.dat`.
    pub fn delete_ratchet_state(&self, room_hash: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM ratchet_states WHERE room_hash = ?1",
            params![room_hash],
        )
        .map_err(|e| anyhow!("failed to delete ratchet state: {}", e))?;

        self.persist_locked(&conn)
    }

    /// Сохраняет tombstone-и `session_id` комнаты в `vault.dat`.
    ///
    /// Вызывается только для обычных комнат: при активном RAM-TTL
    /// `session_id` на диск не попадают (H-3).
    pub fn save_retired_ratchet_sessions(
        &self,
        room_hash: &str,
        session_ids: &[[u8; 16]],
    ) -> Result<()> {
        let mut conn = self.conn()?;
        {
            let tx = conn
                .transaction()
                .map_err(|e| anyhow!("failed to start retired session update: {}", e))?;
            tx.execute(
                "DELETE FROM retired_ratchet_sessions WHERE room_hash = ?1",
                params![room_hash],
            )
            .map_err(|e| anyhow!("failed to clear retired sessions: {}", e))?;

            for session_id in session_ids {
                tx.execute(
                    "INSERT OR IGNORE INTO retired_ratchet_sessions (room_hash, session_id)
                     VALUES (?1, ?2)",
                    params![room_hash, session_id.as_slice()],
                )
                .map_err(|e| anyhow!("failed to save retired session: {}", e))?;
            }

            tx.commit()
                .map_err(|e| anyhow!("failed to commit retired sessions: {}", e))?;
        }

        self.persist_locked(&conn)
    }

    /// Загружает все tombstone-и `session_id` из `vault.dat`.
    ///
    /// Порядок строк — порядок вставки, чтобы при переполнении реестра
    /// вытеснялись самые старые записи.
    pub fn load_retired_ratchet_sessions(&self) -> Result<Vec<(String, [u8; 16])>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT room_hash, session_id FROM retired_ratchet_sessions
                 ORDER BY rowid ASC",
            )
            .map_err(|e| anyhow!("failed to prepare retired session load: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(|e| anyhow!("failed to load retired sessions: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read retired sessions: {}", e))?;

        rows.into_iter()
            .map(|(room_hash, raw)| {
                let session_id: [u8; 16] = raw
                    .try_into()
                    .map_err(|_| anyhow!("retired session id must be 16 bytes"))?;
                Ok((room_hash, session_id))
            })
            .collect()
    }

    /// Удаляет tombstone-и комнаты (включение RAM-TTL или удаление контакта).
    pub fn delete_retired_ratchet_sessions(&self, room_hash: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM retired_ratchet_sessions WHERE room_hash = ?1",
            params![room_hash],
        )
        .map_err(|e| anyhow!("failed to delete retired sessions: {}", e))?;

        self.persist_locked(&conn)
    }

    /// M-C: сохраняет tombstone-хеши retired-сессий TTL-комнат.
    ///
    /// Таблица заменяется целиком: вызывающий уже применил
    /// `TOMBSTONE_TTL`/`MAX_TTL_TOMBSTONES`. Внутри зашифрованного
    /// `vault.dat` лежат только alias сессии и `SHA256(session_id)`.
    pub fn save_ttl_tombstones(&self, tombstones: &[TtlTombstone]) -> Result<()> {
        let mut conn = self.conn()?;
        {
            let tx = conn
                .transaction()
                .map_err(|e| anyhow!("failed to start ttl tombstone update: {}", e))?;
            tx.execute("DELETE FROM ttl_tombstones", [])
                .map_err(|e| anyhow!("failed to clear ttl tombstones: {}", e))?;

            for tombstone in tombstones {
                tx.execute(
                    "INSERT OR REPLACE INTO ttl_tombstones
                        (session_alias, session_id_hash, retired_at)
                     VALUES (?1, ?2, ?3)",
                    params![
                        tombstone.session_alias.as_slice(),
                        tombstone.session_id_hash.as_slice(),
                        tombstone.retired_at as i64
                    ],
                )
                .map_err(|e| anyhow!("failed to save ttl tombstone: {}", e))?;
            }

            tx.commit()
                .map_err(|e| anyhow!("failed to commit ttl tombstones: {}", e))?;
        }

        self.persist_locked(&conn)
    }

    /// M-C: загружает tombstone-хеши TTL-сессий из `vault.dat`.
    ///
    /// Порядок — от старых к новым, чтобы вызывающий мог вытеснить
    /// старейшие записи при переполнении.
    pub fn load_ttl_tombstones(&self) -> Result<Vec<TtlTombstone>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT session_alias, session_id_hash, retired_at
                 FROM ttl_tombstones ORDER BY retired_at ASC, rowid ASC",
            )
            .map_err(|e| anyhow!("failed to prepare ttl tombstone load: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|e| anyhow!("failed to load ttl tombstones: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read ttl tombstones: {}", e))?;

        rows.into_iter()
            .map(|(alias, hash, retired_at)| {
                let session_alias: [u8; 16] = alias
                    .try_into()
                    .map_err(|_| anyhow!("ttl tombstone alias must be 16 bytes"))?;
                let session_id_hash: [u8; 32] = hash
                    .try_into()
                    .map_err(|_| anyhow!("ttl tombstone hash must be 32 bytes"))?;
                Ok(TtlTombstone {
                    session_alias,
                    session_id_hash,
                    retired_at: retired_at.max(0) as u64,
                })
            })
            .collect()
    }

    /// Снимок состояния храповика из `vault.dat` (только для тестов).
    #[cfg(test)]
    pub(crate) fn persisted_ratchet_state_for_test(
        &self,
        room_hash: &str,
    ) -> Result<Option<Vec<u8>>> {
        let key = self.vault.key()?;
        let data = self.safe_fs.safe_read_file(VAULT_FILE_NAME)?;
        let snapshot = Self::decode_container(&key, &data)?;
        snapshot
            .ratchet_states
            .iter()
            .find(|row| row.room_hash == room_hash)
            .map(|row| {
                hex::decode(&row.state)
                    .map_err(|e| anyhow!("corrupted ratchet state in snapshot: {}", e))
            })
            .transpose()
    }

    /// Расшифрованный снимок vault в JSON (только для тестов M-C).
    #[cfg(test)]
    pub(crate) fn persisted_snapshot_json_for_test(&self) -> Result<String> {
        let key = self.vault.key()?;
        let data = self.safe_fs.safe_read_file(VAULT_FILE_NAME)?;
        let snapshot = Self::decode_container(&key, &data)?;
        serde_json::to_string(&snapshot)
            .map_err(|e| anyhow!("failed to serialize decrypted snapshot: {}", e))
    }

    // ============================================================
    // TOR HIDDEN SERVICE & P2P OUTBOX
    // ============================================================

    /// Сохраняет постоянный ключ Tor v3 hidden service (`ED25519-V3:...`)
    /// и его `ServiceID` внутри зашифрованного `vault.dat`.
    pub fn save_tor_service(&self, service_id: &str, private_key: &str) -> Result<()> {
        let addr = OnionAddress::from_service_id(service_id)
            .map_err(|e| anyhow!("invalid Tor ServiceID: {}", e))?;
        if private_key.trim().is_empty() {
            return Err(anyhow!("Tor private key cannot be empty"));
        }

        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO tor_service (id, service_id, private_key)
             VALUES (1, ?1, ?2)",
            params![addr.service_id(), private_key],
        )
        .map_err(|e| anyhow!("failed to save tor service credentials: {}", e))?;

        self.persist_locked(&conn)
    }

    /// Загружает сохранённый ключ Tor v3 hidden service из `vault.dat`.
    pub fn load_tor_service(&self) -> Result<Option<TorServiceCredentials>> {
        let conn = self.conn()?;
        let row = conn
            .query_row(
                "SELECT service_id, private_key FROM tor_service WHERE id = 1",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()
            .map_err(|e| anyhow!("failed to load tor service credentials: {}", e))?;

        match row {
            Some((service_id, private_key)) => {
                let addr = OnionAddress::from_service_id(&service_id)
                    .map_err(|e| anyhow!("corrupted Tor ServiceID in storage: {}", e))?;
                Ok(Some(TorServiceCredentials {
                    service_id: addr.service_id().to_string(),
                    private_key: SecretString::new(private_key),
                }))
            }
            None => Ok(None),
        }
    }

    /// Ставит уже зашифрованный Double Ratchet v3 пакет в исходящую очередь.
    ///
    /// Для комнат с активным RAM-TTL этот метод НЕ должен вызываться (H-3).
    pub fn enqueue_outbox(
        &self,
        room_hash: &str,
        recipient_onion: &str,
        packet: &[u8],
        now_unix: i64,
    ) -> Result<i64> {
        IdentityHash::from_hex(room_hash).map_err(|e| {
            anyhow!(
                "invalid room hash ({}…, {} chars): {}",
                truncate_display(room_hash, 16),
                room_hash.chars().count(),
                e
            )
        })?;
        let normalized_onion = OnionAddress::parse(recipient_onion)
            .map_err(|e| anyhow!("invalid recipient .onion address: {}", e))?;
        if packet.is_empty() {
            return Err(anyhow!("cannot enqueue empty packet"));
        }

        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO outbox
                (room_hash, recipient_onion, packet, created_at, attempts, next_retry_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?4)",
            params![room_hash, normalized_onion.as_str(), packet, now_unix],
        )
        .map_err(|e| anyhow!("failed to enqueue outbox packet: {}", e))?;
        let id = conn.last_insert_rowid();

        self.persist_locked(&conn)?;
        Ok(id)
    }

    /// Возвращает элементы outbox, готовые к отправке (FIFO по `id`).
    pub fn due_outbox_items(&self, now_unix: i64) -> Result<Vec<OutboxItem>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, room_hash, recipient_onion, packet, created_at,
                        attempts, next_retry_at, last_error
                 FROM outbox
                 WHERE next_retry_at <= ?1
                 ORDER BY id ASC",
            )
            .map_err(|e| anyhow!("failed to prepare due outbox query: {}", e))?;

        let rows = stmt
            .query_map(params![now_unix], |row| {
                Ok(OutboxItem {
                    id: row.get(0)?,
                    room_hash: row.get(1)?,
                    recipient_onion: row.get(2)?,
                    packet: row.get(3)?,
                    created_at: row.get(4)?,
                    attempts: row.get::<_, i64>(5)?.max(0) as u32,
                    next_retry_at: row.get(6)?,
                    last_error: row.get(7)?,
                })
            })
            .map_err(|e| anyhow!("failed to query due outbox: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read due outbox: {}", e))?;

        Ok(rows)
    }

    /// Обновляет счётчик попыток и время следующей попытки после сбоя доставки.
    pub fn mark_outbox_retry(
        &self,
        id: i64,
        attempts: u32,
        next_retry_at: i64,
        last_error: &str,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE outbox
             SET attempts = ?1, next_retry_at = ?2, last_error = ?3
             WHERE id = ?4",
            params![attempts as i64, next_retry_at, last_error, id],
        )
        .map_err(|e| anyhow!("failed to update outbox retry: {}", e))?;

        self.persist_locked(&conn)
    }

    /// Удаляет успешно доставленный пакет из outbox.
    pub fn delete_outbox_item(&self, id: i64) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM outbox WHERE id = ?1", params![id])
            .map_err(|e| anyhow!("failed to delete outbox item: {}", e))?;

        self.persist_locked(&conn)
    }

    /// Удаляет все отложенные пакеты комнаты (reset храповика или удаление контакта).
    pub fn clear_room_outbox(&self, room_hash: &str) -> Result<usize> {
        let conn = self.conn()?;
        let removed = conn
            .execute("DELETE FROM outbox WHERE room_hash = ?1", params![room_hash])
            .map_err(|e| anyhow!("failed to clear room outbox: {}", e))?;
        if removed > 0 {
            self.persist_locked(&conn)?;
        }
        Ok(removed)
    }

    /// Количество пакетов, ожидающих отправки в outbox.
    pub fn count_outbox(&self) -> Result<usize> {
        let conn = self.conn()?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))
            .map_err(|e| anyhow!("failed to count outbox items: {}", e))?;
        Ok(count.max(0) as usize)
    }

    /// Возвращает `true`, если для комнаты уже есть ожидающие пакеты в outbox.
    pub fn has_pending_outbox_for_room(&self, room_hash: &str) -> Result<bool> {
        let conn = self.conn()?;
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM outbox WHERE room_hash = ?1 LIMIT 1",
                params![room_hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| anyhow!("failed to check room outbox: {}", e))?;
        Ok(found.is_some())
    }

    pub fn close(&self) -> Result<()> {
        // Соединение закроется вместе с Arc<Mutex<Connection>>. Здесь же
        // оставляем последнюю согласованную зашифрованную копию на диске.
        self.persist()
    }
}

/// SQLite `CURRENT_TIMESTAMP` не всегда RFC3339, поэтому при ошибке парсинга
/// подставляем текущее время (как и раньше).
fn parse_timestamp(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

/// Есть ли таблица в базе (для миграции очень старых профилей).
fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let found: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| anyhow!("failed to inspect legacy schema: {}", e))?;
    Ok(found.is_some())
}

/// Есть ли колонка у таблицы (для баз до появления `contacts.ed25519`).
fn has_column(conn: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({})", table))
        .map_err(|e| anyhow!("failed to inspect legacy schema: {}", e))?;
    let columns = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| anyhow!("failed to read legacy schema: {}", e))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("failed to read legacy schema: {}", e))?;
    Ok(columns.iter().any(|name| name == column))
}

/// Перезаписывает файл нулями и удаляет его.
///
/// Для основного файла также удаляются SQLite-сателлиты `-journal`, `-wal`
/// и `-shm`: они могут содержать данные и переживают удаление основного
/// файла. Отсутствие сателлита считается нормой, остальные ошибки
/// накапливаются и возвращаются как ошибка.
fn secure_remove_file(path: &Path) -> Result<()> {
    let mut targets = Vec::with_capacity(4);
    targets.push(path.to_path_buf());

    for suffix in ["-journal", "-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        targets.push(std::path::PathBuf::from(sidecar));
    }

    let mut first_error = None;
    for target in targets {
        if let Err(e) = secure_remove_one(&target) {
            if first_error.is_none() {
                first_error = Some(e);
            }
        }
    }

    match first_error {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn secure_remove_one(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(anyhow!("cannot inspect {:?}: {}", path, e)),
    };

    if metadata.is_file() {
        // Ошибки затирания не должны мешать удалению файла.
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            let zeros = [0u8; 8192];
            let mut remaining = metadata.len();
            while remaining > 0 {
                let chunk = remaining.min(zeros.len() as u64) as usize;
                if file.write_all(&zeros[..chunk]).is_err() {
                    break;
                }
                remaining -= chunk as u64;
            }
            let _ = file.sync_all();
        }
    }

    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("cannot remove {:?}: {}", path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const TEST_PASSWORD: &str = "test-password-123";

    struct TestStorage {
        storage: Storage,
        dir: tempfile::TempDir,
    }

    impl TestStorage {
        fn path(&self) -> &Path {
            self.dir.path()
        }
    }

    fn setup() -> TestStorage {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().to_str().expect("utf-8 temp path");
        let vault = Vault::create(base, TEST_PASSWORD).expect("create vault");
        let storage = Storage::new(base, vault).expect("open storage");
        TestStorage { storage, dir }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn read_vault(path: &Path) -> Vec<u8> {
        fs::read(path.join(VAULT_FILE_NAME)).expect("read vault.dat")
    }

    fn vault_mtime(path: &Path) -> SystemTime {
        fs::metadata(path.join(VAULT_FILE_NAME))
            .expect("stat vault.dat")
            .modified()
            .expect("vault.dat mtime")
    }

    fn assert_bucket_padded(len: usize) {
        assert!(
            VAULT_PADDING_BUCKETS
                .iter()
                .any(|bucket| len >= *bucket && len <= bucket + bucket / 8),
            "vault.dat size {} is outside the padding grid",
            len
        );
    }

    #[test]
    fn test_add_and_get_contact() {
        let t = setup();

        let hash = "a".repeat(64);
        let public_key = vec![1u8; 32];
        let nickname = "Test User";

        t.storage.add_contact(&hash, &public_key, nickname).unwrap();

        let contact = t.storage.get_contact(&hash).unwrap();
        assert_eq!(contact.hash, hash);
        assert_eq!(contact.public_key, public_key);
        assert_eq!(contact.nickname, nickname);
    }

    #[test]
    fn test_save_and_get_messages() {
        let t = setup();

        let hash = "b".repeat(64);
        t.storage.add_contact(&hash, &[2u8; 32], "Test").unwrap();

        t.storage.save_message(&hash, "in", "Hello").unwrap();
        t.storage.save_message(&hash, "out", "Hi!").unwrap();

        let messages = t.storage.get_room_messages(&hash, 10).unwrap();
        assert_eq!(messages.len(), 2);

        // Messages should be in descending order (newest first)
        assert_eq!(messages[0].text, "Hi!");
        assert_eq!(messages[1].text, "Hello");
    }

    #[test]
    fn ephemeral_messages_are_ram_only_and_expire() {
        let t = setup();

        let hash = "8".repeat(64);
        t.storage.add_contact(&hash, &[8u8; 32], "Ephemeral").unwrap();
        t.storage.ensure_room("Ephemeral", &hash).unwrap();

        let now = Utc::now().timestamp().max(0) as u64;
        let expires_at = now + 60;
        t.storage
            .save_message_with_room_meta(&hash, "out", &hash, "RAM-only secret", true, Some(expires_at))
            .unwrap();

        // Сообщение доступно в памяти...
        let messages = t.storage.get_room_messages(&hash, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].is_ephemeral);
        assert_eq!(messages[0].expires_at, Some(expires_at));

        // ...но его нет в зашифрованном снимке на диске.
        let key = t.storage.vault.key().unwrap();
        let snapshot = Storage::decode_container(&key, &read_vault(t.path())).unwrap();
        assert!(snapshot.messages.is_empty());
        assert!(t
            .storage
            .persisted_messages_for_test()
            .unwrap()
            .iter()
            .all(|message| message.text != "RAM-only secret"));

        // Обычное сообщение снова попадает в vault.dat.
        t.storage
            .save_message_with_room_meta(&hash, "out", &hash, "persistent", false, None)
            .unwrap();
        let persisted = t.storage.persisted_messages_for_test().unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].text, "persistent");

        // Истёкшее эфемерное сообщение удаляется из памяти.
        let removed = t.storage.purge_expired_messages(expires_at + 1).unwrap();
        assert_eq!(removed.len(), 1);
        let messages = t.storage.get_room_messages(&hash, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "persistent");
    }

    #[test]
    fn vault_file_hides_metadata_and_uses_padded_buckets() {
        let t = setup();

        let hash = "c".repeat(64);
        let onion = OnionAddress::test_v3_from_seed(5).to_string();
        let nickname = "HiddenContactName";
        let secret_text = "Very secret message body";

        t.storage
            .upsert_p2p_contact(
                &hash,
                &[3u8; 32],
                &"ab".repeat(32),
                &onion,
                &"cd".repeat(32),
                TOFU_PENDING,
                nickname,
            )
            .unwrap();
        t.storage.ensure_room(nickname, &hash).unwrap();
        t.storage.save_message(&hash, "in", secret_text).unwrap();

        let bytes = read_vault(t.path());

        // Никаких открытых заголовков и метаданных.
        assert!(!contains(&bytes, b"SQLite"));
        assert!(!contains(&bytes, b"SQLite format 3"));
        assert!(!contains(&bytes, nickname.as_bytes()));
        assert!(!contains(&bytes, secret_text.as_bytes()));
        assert!(!contains(&bytes, onion.as_bytes()));

        // Размер лежит в первом bucket’е с джиттером (а не ровно на границе).
        assert_bucket_padded(bytes.len());
        assert!(bytes.len() >= VAULT_PADDING_BUCKETS[0]);
        assert!(bytes.len() <= VAULT_PADDING_BUCKETS[0] + VAULT_PADDING_BUCKETS[0] / 8);

        // Контейнер расшифровывается обратно и содержит исходные данные.
        let key = t.storage.vault.key().unwrap();
        let snapshot = Storage::decode_container(&key, &bytes).unwrap();
        assert_eq!(snapshot.contacts.len(), 1);
        assert_eq!(snapshot.contacts[0].nickname, nickname);
        assert_eq!(snapshot.contacts[0].onion_addr.as_deref(), Some(onion.as_str()));
        assert_eq!(snapshot.messages.len(), 1);
        assert_eq!(snapshot.messages[0].text, secret_text);
    }

    #[test]
    fn vault_size_stays_within_one_bucket_as_messages_grow() {
        let t = setup();

        let hash = "9".repeat(64);
        t.storage.add_contact(&hash, &[9u8; 32], "Bucket").unwrap();
        t.storage.ensure_room("Bucket", &hash).unwrap();

        let mut sizes = Vec::new();
        for index in 0..5 {
            t.storage
                .save_message(&hash, "out", &format!("message-{}", index))
                .unwrap();
            let size = read_vault(t.path()).len();
            assert_bucket_padded(size);
            sizes.push(size);
        }

        let min = *sizes.iter().min().unwrap();
        let max = *sizes.iter().max().unwrap();
        assert!(min >= VAULT_PADDING_BUCKETS[0]);
        // Все пять записей остаются в первом bucket’е: размер не растёт
        // линейно с числом сообщений, виден только bucket + джиттер.
        assert!(
            max - min <= VAULT_PADDING_BUCKETS[0] / 8,
            "sizes leaked message growth: {:?}",
            sizes
        );
    }

    #[test]
    fn vault_mtime_does_not_change_on_every_write() {
        let t = setup();

        let hash = "7".repeat(64);
        t.storage.add_contact(&hash, &[7u8; 32], "Mtime").unwrap();
        let before = vault_mtime(t.path());

        t.storage.save_message(&hash, "out", "first").unwrap();
        let after_first = vault_mtime(t.path());
        t.storage.save_message(&hash, "out", "second").unwrap();
        let after_second = vault_mtime(t.path());

        // Между обновлениями mtime (5–15 минут) записи не оставляют
        // свежего временного следа.
        assert_eq!(before, after_first);
        assert_eq!(after_first, after_second);
    }

    #[test]
    fn vault_mtime_is_shifted_back_from_wall_clock() {
        let t = setup();
        let mtime = vault_mtime(t.path());

        let age = SystemTime::now().duration_since(mtime).unwrap_or_default();
        assert!(
            age >= Duration::from_secs(1),
            "mtime must be randomized backwards, age: {:?}",
            age
        );
    }

    #[test]
    fn ttl_message_does_not_rewrite_vault() {
        let t = setup();

        let hash = "6".repeat(64);
        t.storage.add_contact(&hash, &[6u8; 32], "Ttl").unwrap();
        t.storage.ensure_room("Ttl", &hash).unwrap();

        let before_bytes = read_vault(t.path());
        let before_mtime = vault_mtime(t.path());

        let expires_at = Utc::now().timestamp().max(0) as u64 + 60;
        t.storage
            .save_message_with_room_meta(
                &hash,
                "out",
                &hash,
                "RAM-only TTL",
                true,
                Some(expires_at),
            )
            .unwrap();

        // H-3: TTL-сообщение не должно трогать vault.dat вообще — ни размер,
        // ни mtime.
        assert_eq!(read_vault(t.path()), before_bytes);
        assert_eq!(vault_mtime(t.path()), before_mtime);
    }

    #[test]
    fn reopened_vault_restores_state() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let hash = "e".repeat(64);

        let fingerprint = "ef".repeat(32);
        {
            let vault = Vault::create(base, TEST_PASSWORD).unwrap();
            let storage = Storage::new(base, vault).unwrap();
            storage
                .upsert_verified_contact(
                    &hash,
                    &[4u8; 32],
                    &"ab".repeat(32),
                    &fingerprint,
                    TOFU_VERIFIED,
                    "Persisted",
                )
                .unwrap();
            storage.save_message(&hash, "out", "still here").unwrap();
        }

        let vault = Vault::unlock(base, TEST_PASSWORD).unwrap();
        let storage = Storage::new(base, vault).unwrap();

        let contact = storage.get_contact(&hash).unwrap();
        assert_eq!(contact.nickname, "Persisted");
        assert_eq!(contact.tofu_state, TOFU_VERIFIED);
        assert_eq!(contact.fingerprint.as_deref(), Some(fingerprint.as_str()));
        assert_eq!(
            storage.get_room_messages(&hash, 10).unwrap()[0].text,
            "still here"
        );

        // Открытых файлов SQLite не осталось.
        assert!(!dir.path().join(LEGACY_DB_FILE_NAME).exists());
        assert!(!dir
            .path()
            .join(format!("{}-wal", LEGACY_DB_FILE_NAME))
            .exists());
        assert!(!dir
            .path()
            .join(format!("{}-shm", LEGACY_DB_FILE_NAME))
            .exists());
    }

    #[test]
    fn migrates_legacy_plaintext_db_and_removes_it() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let hash = "f".repeat(64);

        let vault = Vault::create(base, TEST_PASSWORD).unwrap();

        {
            let legacy = Connection::open(dir.path().join(LEGACY_DB_FILE_NAME)).unwrap();
            legacy
                .execute_batch(
                    "
                    CREATE TABLE contacts (
                        hash TEXT PRIMARY KEY,
                        public_key BLOB NOT NULL,
                        ed25519 TEXT,
                        nickname TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE rooms (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL UNIQUE,
                        contact_hash TEXT NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    CREATE TABLE messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        contact_hash TEXT NOT NULL,
                        room_hash TEXT NOT NULL,
                        direction TEXT NOT NULL,
                        text TEXT NOT NULL,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        status TEXT DEFAULT 'delivered'
                    );
                ",
                )
                .unwrap();
            legacy
                .execute(
                    "INSERT INTO contacts (hash, public_key, nickname)
                     VALUES (?1, ?2, 'Legacy Name')",
                    params![hash, vec![9u8; 32]],
                )
                .unwrap();
            legacy
                .execute(
                    "INSERT INTO rooms (name, contact_hash) VALUES ('Legacy Name', ?1)",
                    params![hash],
                )
                .unwrap();
            legacy
                .execute(
                    "INSERT INTO messages (contact_hash, room_hash, direction, text)
                     VALUES (?1, ?1, 'in', 'Legacy message')",
                    params![hash],
                )
                .unwrap();
        }

        let storage = Storage::new(base, vault).unwrap();

        assert_eq!(storage.get_contact(&hash).unwrap().nickname, "Legacy Name");
        assert_eq!(
            storage.get_room_messages(&hash, 10).unwrap()[0].text,
            "Legacy message"
        );

        // Старая открытая база затерта и удалена, остался только vault.dat.
        for suffix in ["", "-wal", "-shm"] {
            let path = dir
                .path()
                .join(format!("{}{}", LEGACY_DB_FILE_NAME, suffix));
            assert!(!path.exists(), "legacy file still exists: {:?}", path);
        }
        let bytes = read_vault(dir.path());
        assert!(!contains(&bytes, b"Legacy Name"));
        assert!(!contains(&bytes, b"Legacy message"));
        assert_bucket_padded(bytes.len());
    }

    #[test]
    fn rekeying_rewrites_vault_with_new_key() {
        let t = setup();

        let hash = "1".repeat(64);
        t.storage.add_contact(&hash, &[4u8; 32], "Name").unwrap();
        t.storage.save_message(&hash, "out", "Text").unwrap();

        let old_key = t.storage.vault.key().unwrap();
        let (_, new_key) = crate::vault::derive_new("new-password-123").unwrap();
        t.storage
            .reencrypt_fields_and_replace_key(&old_key, &new_key)
            .unwrap();

        let bytes = read_vault(t.path());
        assert!(old_key.decrypt(&bytes, VAULT_AAD).is_err());
        let snapshot = Storage::decode_container(&new_key, &bytes).unwrap();
        assert_eq!(snapshot.contacts[0].nickname, "Name");
        assert_eq!(snapshot.messages[0].text, "Text");

        // В оперативной памяти данные остаются доступны.
        assert_eq!(t.storage.get_contact(&hash).unwrap().nickname, "Name");
    }

    #[test]
    fn rename_contact_updates_room_lookup() {
        let t = setup();

        let hash = "2".repeat(64);
        t.storage
            .add_contact(&hash, &[5u8; 32], "Old Name")
            .unwrap();
        t.storage.ensure_room("Old Name", &hash).unwrap();

        t.storage
            .update_contact_nickname(&hash, "New Name")
            .unwrap();

        assert_eq!(t.storage.get_contact(&hash).unwrap().nickname, "New Name");
        assert_eq!(
            t.storage.get_contact_hash_by_nickname("New Name").unwrap(),
            hash
        );
        assert!(t.storage.get_contact_hash_by_nickname("Old Name").is_err());
    }

    #[test]
    fn add_contact_keeps_ed25519_key() {
        let t = setup();

        let hash = "3".repeat(64);
        let ed25519 = "ab".repeat(32);
        t.storage
            .add_contact_with_ed25519(&hash, &[6u8; 32], Some(&ed25519), "Alice")
            .unwrap();

        assert_eq!(
            t.storage.get_contact(&hash).unwrap().ed25519.as_deref(),
            Some(ed25519.as_str())
        );

        // Повторный импорт без ключа не должен его затирать.
        t.storage.add_contact(&hash, &[6u8; 32], "Alice").unwrap();
        assert_eq!(
            t.storage.get_contact(&hash).unwrap().ed25519.as_deref(),
            Some(ed25519.as_str())
        );
    }

    #[test]
    fn verified_contact_persists_fingerprint_and_tofu_state() {
        let t = setup();

        let hash = "4".repeat(64);
        let fingerprint = "cd".repeat(32);
        t.storage
            .upsert_verified_contact(
                &hash,
                &[7u8; 32],
                &"ab".repeat(32),
                &fingerprint,
                TOFU_PENDING,
                "Alice",
            )
            .unwrap();

        let contact = t.storage.get_contact(&hash).unwrap();
        assert_eq!(contact.fingerprint.as_deref(), Some(fingerprint.as_str()));
        assert_eq!(contact.tofu_state, TOFU_PENDING);

        t.storage
            .set_contact_tofu_state(&hash, TOFU_VERIFIED)
            .unwrap();
        let contact = t.storage.get_contact(&hash).unwrap();
        assert_eq!(contact.tofu_state, TOFU_VERIFIED);
        assert_eq!(contact.fingerprint.as_deref(), Some(fingerprint.as_str()));

        // Повторный legacy-upsert без отпечатка не должен стирать TOFU.
        t.storage.add_contact(&hash, &[7u8; 32], "Alice").unwrap();
        let contact = t.storage.get_contact(&hash).unwrap();
        assert_eq!(contact.tofu_state, TOFU_VERIFIED);
        assert_eq!(contact.fingerprint.as_deref(), Some(fingerprint.as_str()));
    }

    #[test]
    fn delete_contact_removes_messages_outbox_and_room() {
        let t = setup();

        let hash = "4".repeat(64);
        let other = "5".repeat(64);
        let onion = OnionAddress::test_v3_from_seed(7).to_string();

        t.storage
            .add_contact(&hash, &[7u8; 32], "Delete Me")
            .unwrap();
        t.storage.ensure_room("Delete Me", &hash).unwrap();
        t.storage.save_message(&hash, "in", "secret one").unwrap();
        t.storage.save_message(&hash, "out", "secret two").unwrap();
        t.storage
            .enqueue_outbox(&hash, &onion, b"queued-packet", 100)
            .unwrap();

        t.storage
            .add_contact(&other, &[8u8; 32], "Keep Me")
            .unwrap();
        t.storage.ensure_room("Keep Me", &other).unwrap();
        t.storage.save_message(&other, "in", "keep this").unwrap();

        assert_eq!(t.storage.count_messages(&hash).unwrap(), 2);
        assert_eq!(t.storage.count_outbox().unwrap(), 1);

        t.storage.delete_contact(&hash).unwrap();

        assert!(t.storage.get_contact(&hash).is_err());
        assert!(t.storage.get_room_messages(&hash, 10).unwrap().is_empty());
        assert_eq!(t.storage.count_outbox().unwrap(), 0);
        assert_eq!(t.storage.count_messages(&hash).unwrap(), 0);

        // Второй контакт и его история не затронуты.
        assert_eq!(t.storage.get_contact(&other).unwrap().nickname, "Keep Me");
        assert_eq!(t.storage.get_room_messages(&other, 10).unwrap().len(), 1);

        // После удаления на диске не осталось открытых строк.
        let bytes = read_vault(t.path());
        assert!(!contains(&bytes, b"Delete Me"));
        assert!(!contains(&bytes, b"secret one"));
        assert!(!contains(&bytes, b"queued-packet"));
    }

    #[cfg(unix)]
    #[test]
    fn vault_file_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let t = setup();
        t.storage
            .add_contact(&"7".repeat(64), &[1u8; 32], "Private")
            .unwrap();

        let mode = fs::metadata(t.path().join(VAULT_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn secure_remove_file_removes_sqlite_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join(LEGACY_DB_FILE_NAME);

        for suffix in ["", "-journal", "-wal", "-shm"] {
            let path = dir
                .path()
                .join(format!("{}{}", LEGACY_DB_FILE_NAME, suffix));
            fs::write(&path, b"secret").unwrap();
        }

        secure_remove_file(&db_path).unwrap();

        for suffix in ["", "-journal", "-wal", "-shm"] {
            let path = dir
                .path()
                .join(format!("{}{}", LEGACY_DB_FILE_NAME, suffix));
            assert!(!path.exists(), "file still exists: {:?}", path);
        }

        // Повторный вызов на отсутствующих файлах — не ошибка.
        secure_remove_file(&db_path).unwrap();
    }

    #[test]
    fn secure_remove_file_reports_non_notfound_errors() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join(LEGACY_DB_FILE_NAME);
        fs::write(&db_path, b"main").unwrap();

        // Каталог на месте `-journal`: remove_file вернёт ошибку, которую
        // нельзя молча игнорировать.
        let journal = dir
            .path()
            .join(format!("{}-journal", LEGACY_DB_FILE_NAME));
        fs::create_dir(&journal).unwrap();
        fs::write(journal.join("keep"), b"x").unwrap();

        assert!(secure_remove_file(&db_path).is_err());
        // Основной файл всё равно удалён: ошибка сателлита не блокирует wipe.
        assert!(!db_path.exists());
    }

    #[test]
    fn tor_service_credentials_persist_encrypted_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let addr = OnionAddress::test_v3_from_seed(11);
        let secret_blob = "ED25519-V3:super-secret-onion-key-material";

        {
            let vault = Vault::create(base, TEST_PASSWORD).unwrap();
            let storage = Storage::new(base, vault).unwrap();
            assert!(storage.load_tor_service().unwrap().is_none());
            storage
                .save_tor_service(addr.service_id(), secret_blob)
                .unwrap();
        }

        let disk = read_vault(dir.path());
        assert!(!contains(&disk, secret_blob.as_bytes()));
        assert!(!contains(&disk, addr.service_id().as_bytes()));

        let vault = Vault::unlock(base, TEST_PASSWORD).unwrap();
        let reopened = Storage::new(base, vault).unwrap();
        let loaded = reopened.load_tor_service().unwrap().expect("tor service");
        assert_eq!(loaded.service_id, addr.service_id());
        assert_eq!(loaded.private_key.expose(), secret_blob);
        assert_eq!(format!("{:?}", loaded).contains("super-secret"), false);
    }

    #[test]
    fn outbox_items_persist_backoff_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let room = "a".repeat(64);
        let onion = OnionAddress::test_v3_from_seed(4).to_string();

        let id1 = {
            let vault = Vault::create(base, TEST_PASSWORD).unwrap();
            let storage = Storage::new(base, vault).unwrap();
            let id1 = storage.enqueue_outbox(&room, &onion, b"pkt-1", 100).unwrap();
            let _id2 = storage.enqueue_outbox(&room, &onion, b"pkt-2", 100).unwrap();
            assert_eq!(storage.count_outbox().unwrap(), 2);
            assert!(storage.has_pending_outbox_for_room(&room).unwrap());
            storage.mark_outbox_retry(id1, 1, 130, "peer offline").unwrap();
            id1
        };

        let vault = Vault::unlock(base, TEST_PASSWORD).unwrap();
        let storage = Storage::new(base, vault).unwrap();
        assert_eq!(storage.count_outbox().unwrap(), 2);

        let due_at_110 = storage.due_outbox_items(110).unwrap();
        assert_eq!(due_at_110.len(), 1);
        assert_eq!(due_at_110[0].packet, b"pkt-2");

        let due_at_130 = storage.due_outbox_items(130).unwrap();
        assert_eq!(due_at_130.len(), 2);
        assert_eq!(due_at_130[0].id, id1);
        assert_eq!(due_at_130[0].attempts, 1);
        assert_eq!(due_at_130[0].last_error.as_deref(), Some("peer offline"));

        storage.delete_outbox_item(id1).unwrap();
        assert_eq!(storage.count_outbox().unwrap(), 1);

        assert_eq!(storage.clear_room_outbox(&room).unwrap(), 1);
        assert_eq!(storage.count_outbox().unwrap(), 0);
        assert!(!storage.has_pending_outbox_for_room(&room).unwrap());
    }

    #[test]
    fn retired_ratchet_sessions_survive_reopen() {
        // H-2: tombstone-и сброшенной сессии должны пережить перезапуск,
        // иначе её запоздавший bootstrap-пакет снова выглядит новым.
        let TestStorage { storage, dir } = setup();
        let room = "d".repeat(64);
        let first = [1u8; 16];
        let second = [2u8; 16];

        storage
            .save_retired_ratchet_sessions(&room, &[first, second])
            .unwrap();

        let key = storage.vault.key().unwrap();
        let snapshot = Storage::decode_container(&key, &read_vault(dir.path())).unwrap();
        assert_eq!(snapshot.retired_ratchet_sessions.len(), 2);

        let base = dir.path().to_str().unwrap().to_string();
        drop(storage);

        let vault = Vault::unlock(&base, TEST_PASSWORD).unwrap();
        let reopened = Storage::new(&base, vault).unwrap();
        assert_eq!(
            reopened.load_retired_ratchet_sessions().unwrap(),
            vec![(room.clone(), first), (room.clone(), second)]
        );

        reopened
            .delete_retired_ratchet_sessions(&room)
            .unwrap();
        assert!(reopened
            .load_retired_ratchet_sessions()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn ttl_tombstones_survive_reopen_without_session_secrets() {
        // M-C: на диск попадают только alias и SHA256(session_id), не
        // session_id/ratchet/bootstrap_nonce.
        let TestStorage { storage, dir } = setup();
        let session_id = [0x42u8; 16];
        let session_alias = crate::crypto::ratchet::session_alias(&session_id).unwrap();
        let session_id_hash = crate::crypto::ratchet::session_id_hash(&session_id);
        let tombstone = TtlTombstone {
            session_alias,
            session_id_hash,
            retired_at: 1_700_000_000,
        };

        storage.save_ttl_tombstones(&[tombstone]).unwrap();

        let key = storage.vault.key().unwrap();
        let snapshot = Storage::decode_container(&key, &read_vault(dir.path())).unwrap();
        assert_eq!(snapshot.ttl_tombstones.len(), 1);
        assert_eq!(
            snapshot.ttl_tombstones[0].session_alias,
            hex::encode(session_alias)
        );
        assert_eq!(
            snapshot.ttl_tombstones[0].session_id_hash,
            hex::encode(session_id_hash)
        );
        assert!(snapshot.ratchet_states.is_empty());
        assert!(snapshot.retired_ratchet_sessions.is_empty());

        let base = dir.path().to_str().unwrap().to_string();
        drop(storage);

        let vault = Vault::unlock(&base, TEST_PASSWORD).unwrap();
        let reopened = Storage::new(&base, vault).unwrap();
        assert_eq!(reopened.load_ttl_tombstones().unwrap(), vec![tombstone]);

        let decrypted = reopened.persisted_snapshot_json_for_test().unwrap();
        assert!(decrypted.contains(&hex::encode(session_id_hash)));
        assert!(
            !decrypted.contains(&hex::encode(session_id)),
            "raw session_id must never be persisted for TTL rooms"
        );
    }

    #[test]
    fn secure_remove_file_wipes_ttl_tombstones() {
        // M-C/D-M-6: wipe удаляет vault.dat вместе с ttl_tombstones.
        let TestStorage { storage, dir } = setup();
        let tombstone = TtlTombstone {
            session_alias: [1u8; 16],
            session_id_hash: [2u8; 32],
            retired_at: 1_700_000_000,
        };
        storage.save_ttl_tombstones(&[tombstone]).unwrap();
        assert_eq!(storage.load_ttl_tombstones().unwrap().len(), 1);

        let base = dir.path().to_str().unwrap().to_string();
        let vault_path = dir.path().join(VAULT_FILE_NAME);
        drop(storage);

        secure_remove_file(&vault_path).unwrap();
        assert!(!vault_path.exists());

        let vault = Vault::unlock(&base, TEST_PASSWORD).unwrap();
        let reopened = Storage::new(&base, vault).unwrap();
        assert!(
            reopened.load_ttl_tombstones().unwrap().is_empty(),
            "wipe must remove persisted TTL tombstones"
        );
    }

    #[test]
    fn invalid_identifiers_are_rejected_before_db_write() {
        let t = setup();
        let room = "a".repeat(64);
        let valid_onion = OnionAddress::test_v3_from_seed(9).to_string();

        for bad_hash in ["", "abc", &"я".repeat(64), &"😀".repeat(32)] {
            assert!(
                t.storage.add_contact(bad_hash, &[1u8; 32], "Bad").is_err(),
                "invalid contact hash must be rejected"
            );
            assert!(t
                .storage
                .enqueue_outbox(bad_hash, &valid_onion, b"pkt", 100)
                .is_err());
        }
        assert!(t.storage.get_all_contacts().unwrap().is_empty());
        assert_eq!(t.storage.count_outbox().unwrap(), 0);

        assert!(t
            .storage
            .enqueue_outbox(&room, "not-an-onion.com", b"pkt", 100)
            .is_err());
        assert!(t.storage.save_tor_service("short", "ED25519-V3:x").is_err());
        assert_eq!(t.storage.count_outbox().unwrap(), 0);
    }
}
