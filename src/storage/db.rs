// src/storage/db.rs
//! Локальное хранилище контактов, комнат, сообщений и файлов.
//!
//! Рабочая база SQLite живёт исключительно в оперативной памяти
//! (`Connection::open_in_memory`). На диск пишется один файл `vault.dat`
//! в формате `[nonce 24] || [ciphertext] || [tag 16]` (XChaCha20-Poly1305)
//! без магических байтов и открытых заголовков: ни имена контактов, ни
//! тексты сообщений, ни служебные подписи SQLite на диск не попадают.
//!
//! Перед шифрованием дамп базы дополняется случайным паддингом так, чтобы
//! размер контейнера был кратен 4096 байтам. Внутренний заголовок (версия
//! схемы и длина полезной нагрузки) хранится строго внутри зашифрованного
//! блока, поэтому по размеру файла нельзя судить о количестве сообщений.
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
use zeroize::Zeroizing;

use crate::storage::SafeFSOps;
use crate::vault::{MasterKey, Vault};

/// Новый зашифрованный контейнер локальной базы.
pub const VAULT_FILE_NAME: &str = "vault.dat";

/// Старая открытая база SQLite. Оставлена только для автомиграции.
pub const LEGACY_DB_FILE_NAME: &str = "user.db";

/// `nonce (24) + Poly1305 tag (16)`.
const CONTAINER_OVERHEAD: usize = 40;
/// Размер блока, к которому выравнивается контейнер.
const BLOCK_SIZE: usize = 4096;
/// Открытый заголовок внутри шифротекста: `LCDB` + версия + длина JSON.
const INNER_MAGIC: &[u8; 4] = b"LCDB";
const INNER_VERSION: u8 = 1;
const INNER_HEADER_LEN: usize = 9;
/// AAD привязывает контейнер к назначению файла.
const VAULT_AAD: &[u8] = b"lastchance:vault.dat";
/// Верхняя граница дампа, чтобы повреждённый заголовок не вызвал OOM.
const MAX_PAYLOAD_LEN: usize = 512 * 1024 * 1024;

// ============================================================
// DATA MODELS
// ============================================================

#[derive(Debug, Clone)]
pub struct Contact {
    pub hash: String,
    pub public_key: Vec<u8>,
    /// Ed25519 public key в hex, если он был в ссылке-приглашении.
    /// Старые контакты могут не иметь его: колонка появилась позже.
    pub ed25519: Option<String>,
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

#[derive(Debug, Clone)]
pub struct FileRecord {
    pub file_hash: String,
    pub room_hash: String,
    pub file_name: String,
    pub file_size: i64,
    pub uploaded_at: DateTime<Utc>,
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
    #[serde(default)]
    files: Vec<FileRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ContactRow {
    hash: String,
    /// hex-кодированный публичный ключ.
    public_key: String,
    ed25519: Option<String>,
    nickname: String,
    created_at: String,
}

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
struct FileRow {
    file_hash: String,
    room_hash: String,
    file_name: String,
    file_size: i64,
    uploaded_at: String,
}

// ============================================================
// STORAGE
// ============================================================

pub struct Storage {
    db: Arc<Mutex<Connection>>,
    vault: Vault,
    safe_fs: SafeFSOps,
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

            CREATE TABLE IF NOT EXISTS files (
                file_hash TEXT PRIMARY KEY,
                room_hash TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(room_hash) REFERENCES contacts(hash)
            );

            CREATE INDEX IF NOT EXISTS idx_messages_contact ON messages(contact_hash);
            CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_hash);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
            CREATE INDEX IF NOT EXISTS idx_files_room ON files(room_hash);
            CREATE INDEX IF NOT EXISTS idx_files_uploaded ON files(uploaded_at);
        ",
        )
        .map_err(|e| anyhow!("failed to create tables: {}", e))?;

        Ok(())
    }

    // ============================================================
    // ENCRYPTED CONTAINER
    // ============================================================

    /// Дополняет открытый блок до размера, при котором итоговый контейнер
    /// (`plaintext + nonce + tag`) кратен [`BLOCK_SIZE`].
    fn padded_plaintext_len(payload_len: usize) -> Result<usize> {
        let unpadded = INNER_HEADER_LEN
            .checked_add(payload_len)
            .ok_or_else(|| anyhow!("database dump is too large"))?;
        let with_overhead = unpadded
            .checked_add(CONTAINER_OVERHEAD)
            .ok_or_else(|| anyhow!("database dump is too large"))?;

        let blocks = with_overhead.div_ceil(BLOCK_SIZE).max(1);
        blocks
            .checked_mul(BLOCK_SIZE)
            .and_then(|total| total.checked_sub(CONTAINER_OVERHEAD))
            .ok_or_else(|| anyhow!("database dump is too large"))
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
            .safe_write_file(VAULT_FILE_NAME, &sealed, 0o600)
    }

    /// Перешифровывает контейнер новым ключом, не отпуская блокировку базы.
    fn rekey(&self, new_key: &MasterKey) -> Result<()> {
        let conn = self.conn()?;
        let snapshot = Self::dump_snapshot(&conn)?;
        let sealed = Self::encode_container(new_key, &snapshot)?;
        self.safe_fs
            .safe_write_file(VAULT_FILE_NAME, &sealed, 0o600)?;

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
                    "SELECT hash, public_key, ed25519, nickname, created_at
                     FROM contacts ORDER BY created_at ASC",
                )
                .map_err(|e| anyhow!("failed to prepare contacts dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(ContactRow {
                        hash: row.get(0)?,
                        public_key: hex::encode(row.get::<_, Vec<u8>>(1)?),
                        ed25519: row.get(2)?,
                        nickname: row.get(3)?,
                        created_at: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
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

        let files = {
            let mut stmt = conn
                .prepare(
                    "SELECT file_hash, room_hash, file_name, file_size, uploaded_at
                     FROM files ORDER BY uploaded_at ASC",
                )
                .map_err(|e| anyhow!("failed to prepare files dump: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok(FileRow {
                        file_hash: row.get(0)?,
                        room_hash: row.get(1)?,
                        file_name: row.get(2)?,
                        file_size: row.get(3)?,
                        uploaded_at: row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    })
                })
                .map_err(|e| anyhow!("failed to dump files: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read files: {}", e))?;
            rows
        };

        Ok(Snapshot {
            contacts,
            rooms,
            messages,
            files,
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
                        (hash, public_key, ed25519, nickname, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        contact.hash,
                        public_key,
                        contact.ed25519,
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

            for file in &snapshot.files {
                tx.execute(
                    "INSERT OR REPLACE INTO files
                        (file_hash, room_hash, file_name, file_size, uploaded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        file.file_hash,
                        file.room_hash,
                        file.file_name,
                        file.file_size,
                        file.uploaded_at
                    ],
                )
                .map_err(|e| anyhow!("failed to restore file record: {}", e))?;
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
            let has_ed25519 = has_column(&conn, "contacts", "ed25519")?;
            let sql = if has_ed25519 {
                "SELECT hash, public_key, ed25519, nickname, created_at FROM contacts"
            } else {
                "SELECT hash, public_key, NULL, nickname, created_at FROM contacts"
            };
            let mut stmt = conn
                .prepare(sql)
                .map_err(|e| anyhow!("failed to read legacy contacts: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    ))
                })
                .map_err(|e| anyhow!("failed to query legacy contacts: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read legacy contacts: {}", e))?;

            for (hash, public_key, ed25519, nickname, created_at) in rows {
                snapshot.contacts.push(ContactRow {
                    hash,
                    public_key: hex::encode(public_key),
                    ed25519,
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

        if table_exists(&conn, "files")? {
            let mut stmt = conn
                .prepare(
                    "SELECT file_hash, room_hash, file_name, file_size, uploaded_at FROM files",
                )
                .map_err(|e| anyhow!("failed to read legacy files: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        legacy_value_as_string(row, 3)?,
                        row.get::<_, Option<String>>(4)?.unwrap_or_default(),
                    ))
                })
                .map_err(|e| anyhow!("failed to query legacy files: {}", e))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read legacy files: {}", e))?;

            for (file_hash, room_hash, file_name, raw_size, uploaded_at) in rows {
                let decrypted_size = self.vault.decrypt_str(&raw_size)?;
                let file_size = decrypted_size
                    .trim()
                    .parse::<i64>()
                    .map_err(|e| anyhow!("corrupted file size in legacy database: {}", e))?;
                snapshot.files.push(FileRow {
                    file_hash,
                    room_hash,
                    file_name: self.vault.decrypt_str(&file_name)?,
                    file_size,
                    uploaded_at,
                });
            }
        }

        Ok(snapshot)
    }

    /// Затирает `user.db`, `user.db-wal` и `user.db-shm` нулями и удаляет их.
    fn purge_legacy_files(db_path: &Path) {
        let file_name = db_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(LEGACY_DB_FILE_NAME);

        for suffix in ["", "-wal", "-shm"] {
            let path = db_path.with_file_name(format!("{}{}", file_name, suffix));
            if let Err(e) = secure_remove_file(&path) {
                log::warn!(
                    "failed to securely remove legacy database file {:?}: {:#}",
                    path,
                    e
                );
            }
        }
    }

    // ============================================================
    // CONTACTS
    // ============================================================

    pub fn add_contact(&self, hash: &str, public_key: &[u8], nickname: &str) -> Result<()> {
        self.add_contact_with_ed25519(hash, public_key, None, nickname)
    }

    /// Сохраняет контакт вместе с Ed25519-ключом (если он был в ссылке).
    ///
    /// Повторный импорт без Ed25519 не должен затирать уже известный ключ,
    /// поэтому используется `COALESCE` в UPSERT-ветке.
    pub fn add_contact_with_ed25519(
        &self,
        hash: &str,
        public_key: &[u8],
        ed25519: Option<&str>,
        nickname: &str,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO contacts (hash, public_key, ed25519, nickname) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(hash) DO UPDATE SET
                 public_key = excluded.public_key,
                 nickname = excluded.nickname,
                 ed25519 = COALESCE(excluded.ed25519, contacts.ed25519)",
            params![hash, public_key, ed25519, nickname],
        )
        .map_err(|e| anyhow!("failed to add contact: {}", e))?;

        self.persist_locked(&conn)
    }

    pub fn get_contact(&self, hash: &str) -> Result<Contact> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT hash, public_key, ed25519, nickname, created_at
                 FROM contacts WHERE hash = ?1",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let (hash_value, public_key, ed25519, nickname, created_at): (
            String,
            Vec<u8>,
            Option<String>,
            String,
            String,
        ) = stmt
            .query_row(params![hash], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .map_err(|_e| anyhow!("contact not found: {}", &hash[..hash.len().min(16)]))?;

        Ok(Contact {
            hash: hash_value,
            public_key,
            ed25519,
            nickname,
            created_at: parse_timestamp(&created_at),
        })
    }

    pub fn get_all_contacts(&self) -> Result<Vec<Contact>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT hash, public_key, ed25519, nickname, created_at
                 FROM contacts ORDER BY created_at DESC",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| anyhow!("failed to query contacts: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read contacts: {}", e))?;

        let mut contacts = Vec::with_capacity(rows.len());
        for (hash, public_key, ed25519, nickname, created_at) in rows {
            contacts.push(Contact {
                hash,
                public_key,
                ed25519,
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
                &contact_hash[..contact_hash.len().min(16)]
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
                &contact_hash[..contact_hash.len().min(16)]
            ));
        }

        tx.execute(
            "DELETE FROM messages WHERE contact_hash = ?1 OR room_hash = ?1",
            params![contact_hash],
        )
        .map_err(|e| anyhow!("failed to delete messages: {}", e))?;
        tx.execute(
            "DELETE FROM files WHERE room_hash = ?1",
            params![contact_hash],
        )
        .map_err(|e| anyhow!("failed to delete files: {}", e))?;
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
    // FILES
    // ============================================================

    pub fn save_file_record(
        &self,
        file_hash: &str,
        room_hash: &str,
        file_name: &str,
        file_size: i64,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO files (file_hash, room_hash, file_name, file_size, uploaded_at)
             VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)",
            params![file_hash, room_hash, file_name, file_size],
        )
        .map_err(|e| anyhow!("failed to save file record: {}", e))?;

        self.persist_locked(&conn)
    }

    pub fn get_file_record(&self, file_hash: &str) -> Result<FileRecord> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT file_hash, room_hash, file_name, file_size, uploaded_at
                 FROM files WHERE file_hash = ?1",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let (hash_value, room_hash, file_name, file_size, uploaded_at): (
            String,
            String,
            String,
            i64,
            String,
        ) = stmt
            .query_row(params![file_hash], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .map_err(|_e| {
                anyhow!(
                    "file record not found: {}",
                    &file_hash[..file_hash.len().min(16)]
                )
            })?;

        Ok(FileRecord {
            file_hash: hash_value,
            room_hash,
            file_name,
            file_size,
            uploaded_at: parse_timestamp(&uploaded_at),
        })
    }

    pub fn get_room_files(&self, room_hash: &str) -> Result<Vec<FileRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT file_hash, room_hash, file_name, file_size, uploaded_at
                 FROM files WHERE room_hash = ?1
                 ORDER BY uploaded_at DESC",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map(params![room_hash], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| anyhow!("failed to query room files: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read files: {}", e))?;

        let mut files = Vec::with_capacity(rows.len());
        for (file_hash, room_hash, file_name, file_size, uploaded_at) in rows {
            files.push(FileRecord {
                file_hash,
                room_hash,
                file_name,
                file_size,
                uploaded_at: parse_timestamp(&uploaded_at),
            });
        }

        Ok(files)
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

/// Читает значение старой колонки как строку. Нужен для `file_size`:
/// в древних базах это INTEGER, позже — зашифрованный TEXT.
fn legacy_value_as_string(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<String> {
    use rusqlite::types::ValueRef;

    match row.get_ref(index)? {
        ValueRef::Null => Ok(String::new()),
        ValueRef::Integer(value) => Ok(value.to_string()),
        ValueRef::Real(value) => Ok(value.to_string()),
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            String::from_utf8(bytes.to_vec()).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    index,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })
        }
    }
}

/// Перезаписывает файл нулями и удаляет его.
fn secure_remove_file(path: &Path) -> Result<()> {
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
    fn vault_file_hides_metadata_and_is_block_aligned() {
        let t = setup();

        let hash = "c".repeat(64);
        let file_hash = "d".repeat(64);
        let nickname = "HiddenContactName";
        let secret_text = "Very secret message body";

        t.storage.add_contact(&hash, &[3u8; 32], nickname).unwrap();
        t.storage.ensure_room(nickname, &hash).unwrap();
        t.storage.save_message(&hash, "in", secret_text).unwrap();
        t.storage
            .save_file_record(&file_hash, &hash, "hidden-file.txt", 42)
            .unwrap();

        let bytes = read_vault(t.path());

        // Никаких открытых заголовков и метаданных.
        assert!(!contains(&bytes, b"SQLite"));
        assert!(!contains(&bytes, b"SQLite format 3"));
        assert!(!contains(&bytes, nickname.as_bytes()));
        assert!(!contains(&bytes, secret_text.as_bytes()));
        assert!(!contains(&bytes, b"hidden-file.txt"));

        // Размер кратен 4096 с учётом 40 байт nonce+tag.
        assert!(bytes.len() >= BLOCK_SIZE);
        assert_eq!(bytes.len() % BLOCK_SIZE, 0);

        // Контейнер расшифровывается обратно и содержит исходные данные.
        let key = t.storage.vault.key().unwrap();
        let snapshot = Storage::decode_container(&key, &bytes).unwrap();
        assert_eq!(snapshot.contacts.len(), 1);
        assert_eq!(snapshot.contacts[0].nickname, nickname);
        assert_eq!(snapshot.messages.len(), 1);
        assert_eq!(snapshot.messages[0].text, secret_text);
        assert_eq!(snapshot.files.len(), 1);
        assert_eq!(snapshot.files[0].file_size, 42);
    }

    #[test]
    fn reopened_vault_restores_state() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().to_str().unwrap();
        let hash = "e".repeat(64);

        {
            let vault = Vault::create(base, TEST_PASSWORD).unwrap();
            let storage = Storage::new(base, vault).unwrap();
            storage.add_contact(&hash, &[4u8; 32], "Persisted").unwrap();
            storage.save_message(&hash, "out", "still here").unwrap();
        }

        let vault = Vault::unlock(base, TEST_PASSWORD).unwrap();
        let storage = Storage::new(base, vault).unwrap();

        assert_eq!(storage.get_contact(&hash).unwrap().nickname, "Persisted");
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
        let file_hash = "0".repeat(64);

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
                    CREATE TABLE files (
                        file_hash TEXT PRIMARY KEY,
                        room_hash TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
            legacy
                .execute(
                    "INSERT INTO files (file_hash, room_hash, file_name, file_size)
                     VALUES (?1, ?2, 'legacy.txt', 42)",
                    params![file_hash, hash],
                )
                .unwrap();
        }

        let storage = Storage::new(base, vault).unwrap();

        assert_eq!(storage.get_contact(&hash).unwrap().nickname, "Legacy Name");
        assert_eq!(
            storage.get_room_messages(&hash, 10).unwrap()[0].text,
            "Legacy message"
        );
        assert_eq!(storage.get_file_record(&file_hash).unwrap().file_size, 42);

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
        assert_eq!(bytes.len() % BLOCK_SIZE, 0);
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
    fn delete_contact_removes_messages_files_and_room() {
        let t = setup();

        let hash = "4".repeat(64);
        let other = "5".repeat(64);
        let file_hash = "6".repeat(64);

        t.storage
            .add_contact(&hash, &[7u8; 32], "Delete Me")
            .unwrap();
        t.storage.ensure_room("Delete Me", &hash).unwrap();
        t.storage.save_message(&hash, "in", "secret one").unwrap();
        t.storage.save_message(&hash, "out", "secret two").unwrap();
        t.storage
            .save_file_record(&file_hash, &hash, "secret.txt", 10)
            .unwrap();

        t.storage
            .add_contact(&other, &[8u8; 32], "Keep Me")
            .unwrap();
        t.storage.ensure_room("Keep Me", &other).unwrap();
        t.storage.save_message(&other, "in", "keep this").unwrap();

        assert_eq!(t.storage.count_messages(&hash).unwrap(), 2);

        t.storage.delete_contact(&hash).unwrap();

        assert!(t.storage.get_contact(&hash).is_err());
        assert!(t.storage.get_room_messages(&hash, 10).unwrap().is_empty());
        assert!(t.storage.get_room_files(&hash).unwrap().is_empty());
        assert_eq!(t.storage.count_messages(&hash).unwrap(), 0);

        // Второй контакт и его история не затронуты.
        assert_eq!(t.storage.get_contact(&other).unwrap().nickname, "Keep Me");
        assert_eq!(t.storage.get_room_messages(&other, 10).unwrap().len(), 1);

        // После удаления на диске не осталось открытых строк.
        let bytes = read_vault(t.path());
        assert!(!contains(&bytes, b"Delete Me"));
        assert!(!contains(&bytes, b"secret one"));
        assert!(!contains(&bytes, b"secret.txt"));
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
}
