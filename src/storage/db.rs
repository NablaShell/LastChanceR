// src/storage/db.rs
use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex};

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
}

impl Storage {
    pub fn new(storage_path: &str) -> Result<Self> {
        let db_path = Path::new(storage_path).join(DB_FILE_NAME);
        let conn =
            Connection::open(&db_path).map_err(|e| anyhow!("failed to open database: {}", e))?;

        // Enable WAL mode for concurrent access
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA busy_timeout=5000;
            PRAGMA foreign_keys=ON;
        ",
        )
        .map_err(|e| anyhow!("failed to configure database: {}", e))?;

        let storage = Self {
            db: Arc::new(Mutex::new(conn)),
        };

        storage.init_tables()?;

        Ok(storage)
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.db.lock().unwrap();

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

    // ============================================================
    // CONTACTS
    // ============================================================

    pub fn add_contact(&self, hash: &str, public_key: &[u8], nickname: &str) -> Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO contacts (hash, public_key, nickname) VALUES (?1, ?2, ?3)",
            params![hash, public_key, nickname],
        )
        .map_err(|e| anyhow!("failed to add contact: {}", e))?;
        Ok(())
    }

    pub fn get_contact(&self, hash: &str) -> Result<Contact> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT hash, public_key, nickname, created_at FROM contacts WHERE hash = ?1")
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let contact = stmt
            .query_row(params![hash], |row| {
                let created_at: String = row.get(3)?;
                Ok(Contact {
                    hash: row.get(0)?,
                    public_key: row.get(1)?,
                    nickname: row.get(2)?,
                    created_at: DateTime::parse_from_rfc3339(&created_at)
                        .unwrap_or_else(|_| Utc::now().into())
                        .with_timezone(&Utc),
                })
            })
            .map_err(|_e| anyhow!("contact not found: {}", &hash[..hash.len().min(16)]))?;

        Ok(contact)
    }

    pub fn get_all_contacts(&self) -> Result<Vec<Contact>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT hash, public_key, nickname, created_at FROM contacts ORDER BY created_at DESC"
        ).map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let contacts = stmt
            .query_map([], |row| {
                let created_at: String = row.get(3)?;
                Ok(Contact {
                    hash: row.get(0)?,
                    public_key: row.get(1)?,
                    nickname: row.get(2)?,
                    created_at: DateTime::parse_from_rfc3339(&created_at)
                        .unwrap_or_else(|_| Utc::now().into())
                        .with_timezone(&Utc),
                })
            })
            .map_err(|e| anyhow!("failed to query contacts: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read contacts: {}", e))?;

        Ok(contacts)
    }

    pub fn get_contact_hash_by_nickname(&self, nickname: &str) -> Result<String> {
        let conn = self.db.lock().unwrap();

        // First try rooms table
        let mut stmt = conn
            .prepare("SELECT contact_hash FROM rooms WHERE name = ?1")
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        if let Ok(hash) = stmt.query_row(params![nickname], |row| row.get::<_, String>(0)) {
            return Ok(hash);
        }

        // Fallback: search in contacts
        let mut stmt = conn
            .prepare("SELECT hash FROM contacts WHERE nickname = ?1")
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let hash = stmt
            .query_row(params![nickname], |row| row.get::<_, String>(0))
            .map_err(|_e| anyhow!("contact not found: {}", nickname))?;
        // Auto-create room entry
        conn.execute(
            "INSERT OR IGNORE INTO rooms (name, contact_hash) VALUES (?1, ?2)",
            params![nickname, hash],
        )
        .map_err(|e| anyhow!("failed to create room: {}", e))?;

        Ok(hash)
    }

    pub fn ensure_room(&self, nickname: &str, hash: &str) -> Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO rooms (name, contact_hash) VALUES (?1, ?2)",
            params![nickname, hash],
        )
        .map_err(|e| anyhow!("failed to ensure room: {}", e))?;
        Ok(())
    }

    pub fn update_contact_nickname(&self, contact_hash: &str, new_nickname: &str) -> Result<()> {
        let conn = self.db.lock().unwrap();
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
        let conn = self.db.lock().unwrap();
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
        let conn = self.db.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, contact_hash, direction, text, timestamp, status
             FROM messages
             WHERE room_hash = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let messages = stmt
            .query_map(params![room_hash, limit], |row| {
                let timestamp: String = row.get(4)?;
                Ok(Message {
                    id: row.get(0)?,
                    contact_hash: row.get(1)?,
                    room_hash: room_hash.to_string(),
                    direction: row.get(2)?,
                    text: row.get(3)?,
                    timestamp: DateTime::parse_from_rfc3339(&timestamp)
                        .unwrap_or_else(|_| Utc::now().into())
                        .with_timezone(&Utc),
                    status: row.get(5)?,
                })
            })
            .map_err(|e| anyhow!("failed to query messages: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read messages: {}", e))?;

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
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO files (file_hash, room_hash, file_name, file_size, uploaded_at)
             VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)",
            params![file_hash, room_hash, file_name, file_size],
        )
        .map_err(|e| anyhow!("failed to save file record: {}", e))?;
        Ok(())
    }

    pub fn get_file_record(&self, file_hash: &str) -> Result<FileRecord> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT file_hash, room_hash, file_name, file_size, uploaded_at
             FROM files WHERE file_hash = ?1",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let file = stmt
            .query_row(params![file_hash], |row| {
                let uploaded_at: String = row.get(4)?;
                Ok(FileRecord {
                    file_hash: row.get(0)?,
                    room_hash: row.get(1)?,
                    file_name: row.get(2)?,
                    file_size: row.get(3)?,
                    uploaded_at: DateTime::parse_from_rfc3339(&uploaded_at)
                        .unwrap_or_else(|_| Utc::now().into())
                        .with_timezone(&Utc),
                })
            })
            .map_err(|_e| {
                anyhow!(
                    "file record not found: {}",
                    &file_hash[..file_hash.len().min(16)]
                )
            })?;

        Ok(file)
    }

    pub fn get_room_files(&self, room_hash: &str) -> Result<Vec<FileRecord>> {
        let conn = self.db.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT file_hash, room_hash, file_name, file_size, uploaded_at
             FROM files WHERE room_hash = ?1
             ORDER BY uploaded_at DESC",
            )
            .map_err(|e| anyhow!("failed to prepare query: {}", e))?;

        let files = stmt
            .query_map(params![room_hash], |row| {
                let uploaded_at: String = row.get(4)?;
                Ok(FileRecord {
                    file_hash: row.get(0)?,
                    room_hash: row.get(1)?,
                    file_name: row.get(2)?,
                    file_size: row.get(3)?,
                    uploaded_at: DateTime::parse_from_rfc3339(&uploaded_at)
                        .unwrap_or_else(|_| Utc::now().into())
                        .with_timezone(&Utc),
                })
            })
            .map_err(|e| anyhow!("failed to query room files: {}", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| anyhow!("failed to read files: {}", e))?;

        Ok(files)
    }

    pub fn close(&self) -> Result<()> {
        // The connection will be closed when the Arc<Mutex<Connection>> is dropped
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_test_db() -> (Storage, String) {
        let temp_dir =
            std::env::temp_dir().join(format!("test_db_{}", chrono::Utc::now().timestamp()));
        fs::create_dir_all(&temp_dir).unwrap();

        let storage = Storage::new(temp_dir.to_str().unwrap()).unwrap();
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
}
