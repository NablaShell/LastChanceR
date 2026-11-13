// src/storage/db.rs
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::vault::{self, MasterKey, Vault};

pub const DB_FILE_NAME: &str = "user.db";

// ============================================================
// DATA MODELS
// ============================================================

#[derive(Debug, Clone)]
pub struct Contact {
    pub hash: String,
    pub public_key: Vec<u8>,
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
// STORAGE
// ============================================================

pub struct Storage {
    db: Arc<Mutex<Connection>>,
    vault: Vault,
}

impl Storage {
    pub fn new(storage_path: &str, vault: Vault) -> Result<Self> {
        let db_path = Path::new(storage_path).join(DB_FILE_NAME);
        let conn =
            Connection::open(&db_path).map_err(|e| anyhow!("failed to open database: {}", e))?;

        // Enable WAL mode for concurrent access
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA busy_timeout=5000;
            PRAGMA foreign_keys=ON;
            PRAGMA secure_delete=ON;
        ",
        )
        .map_err(|e| anyhow!("failed to configure database: {}", e))?;

        let storage = Self {
            db: Arc::new(Mutex::new(conn)),
            vault,
        };

        storage.init_tables()?;
        storage.migrate_plaintext_fields()?;

        // После миграции открытые значения могли остаться в WAL — усекаем журнал.
        if let Ok(conn) = storage.conn() {
            let _ = conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
        }

        Ok(storage)
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>> {
        self.db
            .lock()
            .map_err(|_| anyhow!("database lock poisoned"))
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn()?;

        // Contacts table
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS contacts (
                hash TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
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

    /// Перешифровывает чувствительные поля, оставшиеся от старой версии
    /// в открытом виде. Выполняется при каждом открытии базы.
    fn migrate_plaintext_fields(&self) -> Result<()> {
        self.rewrite_sensitive_fields(|value| {
            if vault::is_encrypted_str(value) {
                Ok(None)
            } else {
                Ok(Some(self.vault.encrypt_str(value)?))
            }
        })
    }

    /// Перешифровывает все чувствительные поля со старого ключа на новый.
    pub fn reencrypt_fields(&self, old_key: &MasterKey, new_key: &MasterKey) -> Result<()> {
        self.rewrite_sensitive_fields(|value| {
            let plaintext = old_key.decrypt_str(value)?;
            Ok(Some(new_key.encrypt_str(&plaintext)?))
        })
    }

    /// Перешифровывает поля и заменяет ключ, не отпуская блокировку базы.
    ///
    /// Блокировка удерживается до замены ключа, поэтому фоновый listener не
    /// успеет записать сообщение, зашифрованное старым ключом, уже после
    /// перешифрования.
    pub fn reencrypt_fields_and_replace_key(
        &self,
        old_key: &MasterKey,
        new_key: &MasterKey,
    ) -> Result<()> {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| anyhow!("failed to start transaction: {}", e))?;

        Self::rewrite_sensitive_tx(&tx, &mut |value| {
            let plaintext = old_key.decrypt_str(value)?;
            Ok(Some(new_key.encrypt_str(&plaintext)?))
        })?;

        tx.commit()
            .map_err(|e| anyhow!("failed to commit re-encryption: {}", e))?;
        self.vault.replace_key(new_key.clone())?;
        drop(conn);

        Ok(())
    }

    /// Общий обход чувствительных колонок в одной транзакции.
    ///
    /// `rewrite` возвращает `Some(new_value)`, если строку нужно обновить.
    fn rewrite_sensitive_fields<F>(&self, mut rewrite: F) -> Result<()>
    where
        F: FnMut(&str) -> Result<Option<String>>,
    {
        let mut conn = self.conn()?;
        let tx = conn
            .transaction()
            .map_err(|e| anyhow!("failed to start transaction: {}", e))?;

        Self::rewrite_sensitive_tx(&tx, &mut rewrite)?;

        tx.commit()
            .map_err(|e| anyhow!("failed to commit re-encryption: {}", e))?;
        Ok(())
    }

    fn rewrite_sensitive_tx<F>(
        tx: &rusqlite::Transaction<'_>,
        rewrite: &mut F,
    ) -> Result<()>
    where
        F: FnMut(&str) -> Result<Option<String>>,
    {
        let contacts: Vec<(String, String)> = {
            let mut stmt = tx
                .prepare("SELECT hash, nickname FROM contacts")
                .map_err(|e| anyhow!("failed to prepare contacts query: {}", e))?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|e| anyhow!("failed to query contacts: {}", e))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read contacts: {}", e))?
        };
        for (hash, value) in contacts {
            if let Some(encrypted) = rewrite(&value)? {
                tx.execute(
                    "UPDATE contacts SET nickname = ?1 WHERE hash = ?2",
                    params![encrypted, hash],
                )
                .map_err(|e| anyhow!("failed to re-encrypt contact: {}", e))?;
            }
        }

        let rooms: Vec<(i64, String)> = {
            let mut stmt = tx
                .prepare("SELECT id, name FROM rooms")
                .map_err(|e| anyhow!("failed to prepare rooms query: {}", e))?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|e| anyhow!("failed to query rooms: {}", e))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read rooms: {}", e))?
        };
        for (id, value) in rooms {
            if let Some(encrypted) = rewrite(&value)? {
                tx.execute(
                    "UPDATE rooms SET name = ?1 WHERE id = ?2",
                    params![encrypted, id],
                )
                .map_err(|e| anyhow!("failed to re-encrypt room: {}", e))?;
            }
        }

        let messages: Vec<(i64, String)> = {
            let mut stmt = tx
                .prepare("SELECT id, text FROM messages")
                .map_err(|e| anyhow!("failed to prepare messages query: {}", e))?;
            let rows = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .map_err(|e| anyhow!("failed to query messages: {}", e))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read messages: {}", e))?
        };
        for (id, value) in messages {
            if let Some(encrypted) = rewrite(&value)? {
                tx.execute(
                    "UPDATE messages SET text = ?1 WHERE id = ?2",
                    params![encrypted, id],
                )
                .map_err(|e| anyhow!("failed to re-encrypt message: {}", e))?;
            }
        }

        let files: Vec<(String, String, String)> = {
            let mut stmt = tx
                .prepare("SELECT file_hash, file_name, file_size FROM files")
                .map_err(|e| anyhow!("failed to prepare files query: {}", e))?;
            let rows = stmt
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, value_as_string(row, 2)?))
                })
                .map_err(|e| anyhow!("failed to query files: {}", e))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|e| anyhow!("failed to read files: {}", e))?
        };
        for (file_hash, file_name, file_size) in files {
            let encrypted_name = rewrite(&file_name)?;
            let encrypted_size = rewrite(&file_size)?;

            if encrypted_name.is_some() || encrypted_size.is_some() {
                tx.execute(
                    "UPDATE files SET file_name = ?1, file_size = ?2 WHERE file_hash = ?3",
                    params![
                        encrypted_name.unwrap_or(file_name),
                        encrypted_size.unwrap_or(file_size),
                        file_hash
                    ],
                )
                .map_err(|e| anyhow!("failed to re-encrypt file record: {}", e))?;
            }
        }

        Ok(())
    }

    // ============================================================
    // CONTACTS
    // ============================================================

    pub fn add_contact(&self, hash: &str, public_key: &[u8], nickname: &str) -> Result<()> {
        let nickname = self.vault.encrypt_str(nickname)?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO contacts (hash, public_key, nickname) VALUES (?1, ?2, ?3)",
            params![hash, public_key, nickname],
        )
        .map_err(|e| anyhow!("failed to add contact: {}", e))?;
        Ok(())
    }

    pub fn get_contact(&self, hash: &str) -> Result<Contact> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare("SELECT hash, public_key, nickname, created_at FROM contacts WHERE hash = ?1")
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let (hash_value, public_key, nickname, created_at): (String, Vec<u8>, String, String) =
            stmt.query_row(params![hash], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|_e| anyhow!("contact not found: {}", &hash[..hash.len().min(16)]))?;

        Ok(Contact {
            hash: hash_value,
            public_key,
            nickname: self.vault.decrypt_str(&nickname)?,
            created_at: parse_timestamp(&created_at),
        })
    }

    pub fn get_all_contacts(&self) -> Result<Vec<Contact>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT hash, public_key, nickname, created_at FROM contacts ORDER BY created_at DESC"
        ).map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| anyhow!("failed to query contacts: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read contacts: {}", e))?;

        let mut contacts = Vec::with_capacity(rows.len());
        for (hash, public_key, nickname, created_at) in rows {
            contacts.push(Contact {
                hash,
                public_key,
                nickname: self.vault.decrypt_str(&nickname)?,
                created_at: parse_timestamp(&created_at),
            });
        }

        Ok(contacts)
    }

    pub fn get_contact_hash_by_nickname(&self, nickname: &str) -> Result<String> {
        // Имена комнат и контактов зашифрованы случайным nonce, поэтому поиск
        // по равенству в SQL невозможен — сравниваем расшифрованные значения.
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
                if self.vault.decrypt_str(&name)? == nickname {
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

        let nickname = self.vault.encrypt_str(nickname)?;
        conn.execute(
            "INSERT OR IGNORE INTO rooms (name, contact_hash) VALUES (?1, ?2)",
            params![nickname, hash],
        )
        .map_err(|e| anyhow!("failed to ensure room: {}", e))?;
        Ok(())
    }

    pub fn update_contact_nickname(&self, contact_hash: &str, new_nickname: &str) -> Result<()> {
        let new_nickname = self.vault.encrypt_str(new_nickname)?;
        let conn = self.conn()?;
        let affected = conn
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

        Ok(())
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
        let text = self.vault.encrypt_str(text)?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO messages (contact_hash, direction, room_hash, text, status) VALUES (?1, ?2, ?3, ?4, 'delivered')",
            params![contact_hash, direction, room_hash, text],
        ).map_err(|e| anyhow!("failed to save message: {}", e))?;
        Ok(())
    }

    pub fn save_message(&self, contact_hash: &str, direction: &str, text: &str) -> Result<()> {
        self.save_message_with_room(contact_hash, direction, contact_hash, text)
    }

    pub fn get_room_messages(&self, room_hash: &str, limit: i64) -> Result<Vec<Message>> {
        let conn = self.conn()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, contact_hash, direction, text, timestamp, status
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
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(|e| anyhow!("failed to query messages: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read messages: {}", e))?;

        let mut messages = Vec::with_capacity(rows.len());
        for (id, contact_hash, direction, text, timestamp, status) in rows {
            messages.push(Message {
                id,
                contact_hash,
                room_hash: room_hash.to_string(),
                direction,
                text: self.vault.decrypt_str(&text)?,
                timestamp: parse_timestamp(&timestamp),
                status,
            });
        }

        Ok(messages)
    }

    pub fn get_messages(&self, contact_hash: &str, limit: i64) -> Result<Vec<Message>> {
        self.get_room_messages(contact_hash, limit)
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
        let file_name = self.vault.encrypt_str(file_name)?;
        let file_size = self.vault.encrypt_str(&file_size.to_string())?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT OR REPLACE INTO files (file_hash, room_hash, file_name, file_size, uploaded_at)
             VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)",
            params![file_hash, room_hash, file_name, file_size],
        )
        .map_err(|e| anyhow!("failed to save file record: {}", e))?;
        Ok(())
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
            String,
            String,
        ) = stmt
            .query_row(params![file_hash], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    value_as_string(row, 3)?,
                    row.get(4)?,
                ))
            })
            .map_err(|_e| {
                anyhow!(
                    "file record not found: {}",
                    &file_hash[..file_hash.len().min(16)]
                )
            })?;

        let file_size = self
            .vault
            .decrypt_str(&file_size)?
            .parse::<i64>()
            .map_err(|e| anyhow!("повреждённый размер файла: {}", e))?;

        Ok(FileRecord {
            file_hash: hash_value,
            room_hash,
            file_name: self.vault.decrypt_str(&file_name)?,
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
                    value_as_string(row, 3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| anyhow!("failed to query room files: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read files: {}", e))?;

        let mut files = Vec::with_capacity(rows.len());
        for (file_hash, room_hash, file_name, file_size, uploaded_at) in rows {
            let file_size = self
                .vault
                .decrypt_str(&file_size)?
                .parse::<i64>()
                .map_err(|e| anyhow!("повреждённый размер файла: {}", e))?;

            files.push(FileRecord {
                file_hash,
                room_hash,
                file_name: self.vault.decrypt_str(&file_name)?,
                file_size,
                uploaded_at: parse_timestamp(&uploaded_at),
            });
        }

        Ok(files)
    }

    pub fn close(&self) -> Result<()> {
        // The connection will be closed when the Arc<Mutex<Connection>> is dropped
        Ok(())
    }
}

/// SQLite `CURRENT_TIMESTAMP` не всегда RFC3339, поэтому при ошибке парсинга
/// подставляем текущее время (как и раньше).
fn parse_timestamp(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

/// Читает значение колонки как строку. Нужен для `file_size`: в старых базах
/// это INTEGER, в новых — зашифрованный TEXT.
fn value_as_string(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_db() -> (Storage, String) {
        let temp_dir =
            std::env::temp_dir().join(format!("test_db_{}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        fs::create_dir_all(&temp_dir).unwrap();

        let base = temp_dir.to_str().unwrap();
        let vault = Vault::create(base, "test-password").unwrap();
        let storage = Storage::new(base, vault).unwrap();
        (storage, temp_dir.to_string_lossy().to_string())
    }

    fn cleanup_test_db(path: &str) {
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn test_add_and_get_contact() {
        let (storage, path) = setup_test_db();

        let hash = "a".repeat(64);
        let public_key = vec![1u8; 32];
        let nickname = "Test User";

        storage.add_contact(&hash, &public_key, nickname).unwrap();

        let contact = storage.get_contact(&hash).unwrap();
        assert_eq!(contact.hash, hash);
        assert_eq!(contact.public_key, public_key);
        assert_eq!(contact.nickname, nickname);

        cleanup_test_db(&path);
    }

    #[test]
    fn test_save_and_get_messages() {
        let (storage, path) = setup_test_db();

        let hash = "b".repeat(64);
        storage.add_contact(&hash, &[2u8; 32], "Test").unwrap();

        storage.save_message(&hash, "in", "Hello").unwrap();
        storage.save_message(&hash, "out", "Hi!").unwrap();

        let messages = storage.get_room_messages(&hash, 10).unwrap();
        assert_eq!(messages.len(), 2);

        // Messages should be in descending order (newest first)
        assert_eq!(messages[0].text, "Hi!");
        assert_eq!(messages[1].text, "Hello");

        cleanup_test_db(&path);
    }

    #[test]
    fn test_sensitive_fields_are_encrypted_at_rest() {
        let (storage, path) = setup_test_db();

        let hash = "c".repeat(64);
        let file_hash = "d".repeat(64);
        storage.add_contact(&hash, &[3u8; 32], "SecretName").unwrap();
        storage.ensure_room("SecretName", &hash).unwrap();
        storage.save_message(&hash, "in", "SecretMessage").unwrap();
        storage
            .save_file_record(&file_hash, &hash, "SecretFile.txt", 42)
            .unwrap();

        let record = storage.get_file_record(&file_hash).unwrap();
        assert_eq!(record.file_name, "SecretFile.txt");
        assert_eq!(record.file_size, 42);

        drop(storage);

        let conn = Connection::open(Path::new(&path).join(DB_FILE_NAME)).unwrap();

        let nickname: String = conn
            .query_row(
                "SELECT nickname FROM contacts WHERE hash = ?1",
                params![hash],
                |row| row.get(0),
            )
            .unwrap();
        let message: String = conn
            .query_row("SELECT text FROM messages LIMIT 1", [], |row| row.get(0))
            .unwrap();
        let file_name: String = conn
            .query_row("SELECT file_name FROM files LIMIT 1", [], |row| row.get(0))
            .unwrap();
        let room_name: String = conn
            .query_row("SELECT name FROM rooms LIMIT 1", [], |row| row.get(0))
            .unwrap();
        let file_size: String = conn
            .query_row("SELECT file_size FROM files LIMIT 1", [], |row| row.get(0))
            .unwrap();

        for value in [&nickname, &message, &file_name, &room_name, &file_size] {
            assert!(vault::is_encrypted_str(value));
        }
        assert!(!nickname.contains("SecretName"));
        assert!(!message.contains("SecretMessage"));
        assert!(!file_name.contains("SecretFile"));
        assert_ne!(file_size, "42");

        drop(conn);
        cleanup_test_db(&path);
    }

    #[test]
    fn test_reencrypt_fields_with_new_key() {
        let (storage, path) = setup_test_db();

        let hash = "e".repeat(64);
        storage.add_contact(&hash, &[4u8; 32], "Name").unwrap();
        storage.save_message(&hash, "out", "Text").unwrap();

        let old_key = storage.vault.key().unwrap();
        let (_, new_key) = vault::derive_new("new-password").unwrap();
        storage.reencrypt_fields(&old_key, &new_key).unwrap();

        // Старый ключ больше не подходит, новый — подходит.
        assert!(storage.get_contact(&hash).is_err());
        storage.vault.replace_key(new_key).unwrap();
        assert_eq!(storage.get_contact(&hash).unwrap().nickname, "Name");
        assert_eq!(storage.get_room_messages(&hash, 10).unwrap()[0].text, "Text");

        cleanup_test_db(&path);
    }
}
