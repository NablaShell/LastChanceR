// src/app.rs
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use log::{info, warn};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::crypto;
use crate::identity::{Identity, IdentityManager};
use crate::network::{Config, Listener, Sender};
use crate::storage::{Contact, Message, SafeFSOps, Storage};

// ============================================================
// EVENT SYSTEM
// ============================================================

#[derive(Debug, Clone)]
pub enum AppEvent {
    NewMessage {
        room_hash: String,
        text: String,
        timestamp: i64,
        sender: String,
    },
    ContactImport {
        hash: String,
        x25519: String,
        ed25519: Option<String>,
        nickname: String,
    },
    ContactImportError {
        error: String,
    },
    UploadStarted {
        file_name: String,
    },
    UploadProgress {
        status: String,
        progress: i32,
    },
    UploadCompleted {
        file_name: String,
        file_hash: String,
        file_size: Option<i64>,
    },
    UploadError {
        error: String,
    },
    DownloadStarted,
    DownloadCompleted {
        file_path: String,
    },
    DownloadError {
        error: String,
    },
}

// ============================================================
// MAIN APP STRUCTURE
// ============================================================

pub struct App {
    config: Config,
    base_dir: String,

    storage: Arc<Storage>,
    identity_manager: Arc<Mutex<IdentityManager>>,
    pub identity: Identity,

    shared_secrets: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    session_id: Arc<Mutex<u64>>,

    sender: Arc<Sender>,
    listener: Arc<Listener>,

    signing_key: SigningKey,
    ed25519_pub_key_hex: String,

    current_room_hash: Arc<Mutex<String>>,

    safe_fs: Arc<SafeFSOps>,

    event_sender: mpsc::UnboundedSender<AppEvent>,
}

impl App {
    pub fn new(
        config: Config,
        base_dir: String,
        event_sender: mpsc::UnboundedSender<AppEvent>,
    ) -> Result<Self> {
        let safe_fs = Arc::new(SafeFSOps::new(&base_dir)?);

        // Ensure base directory exists
        safe_fs.ensure_dir(".")?;

        // Initialize storage
        let storage = Arc::new(Storage::new(&base_dir)?);

        // Initialize identity
        let identity_manager = Arc::new(Mutex::new(IdentityManager::new(base_dir.clone())));
        let identity = {
            let mut manager = identity_manager.lock().unwrap();
            manager.load_or_create("")?
        };

        // Setup Ed25519 signing key
        if identity.ed25519_private_key.len() != 32 {
            return Err(anyhow!(
                "Invalid Ed25519 private key size — identity may be corrupted"
            ));
        }

        let mut signing_key_bytes = [0u8; 32];
        signing_key_bytes.copy_from_slice(&identity.ed25519_private_key);
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let ed25519_pub_key_hex = identity.get_ed25519_public_key_hex();

        // Initialize network
        let sender = Arc::new(Sender::new(&config));
        let listener = Arc::new(Listener::new(&config));

        // Load shared secrets
        let shared_secrets = Arc::new(Mutex::new(HashMap::new()));
        let current_room_hash = Arc::new(Mutex::new(String::new()));

        {
            let contacts = storage.get_all_contacts()?;
            let mut secrets = shared_secrets.lock().unwrap();

            for contact in &contacts {
                match crypto::generate_shared_key(&identity.private_key, &contact.public_key) {
                    Ok(secret) => {
                        secrets.insert(contact.hash.clone(), secret);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to generate shared secret for {}: {}",
                            &contact.hash[..16.min(contact.hash.len())],
                            e
                        );
                    }
                }
            }

            // Set current room
            if !contacts.is_empty() {
                let mut current = current_room_hash.lock().unwrap();
                *current = contacts[0].hash.clone();
                drop(current);

                let _ = storage.ensure_room(&contacts[0].nickname, &contacts[0].hash);
            }
        }

        info!(
            "App initialized: nickname={}, hash={}...",
            identity.nickname,
            &identity.hash[..16.min(identity.hash.len())]
        );

        Ok(Self {
            config,
            base_dir,
            storage,
            identity_manager,
            identity,
            shared_secrets,
            session_id: Arc::new(Mutex::new(0)),
            sender,
            listener,
            signing_key,
            ed25519_pub_key_hex,
            current_room_hash,
            safe_fs,
            event_sender,
        })
    }

    pub fn emit_event(&self, event: AppEvent) {
        let _ = self.event_sender.send(event);
    }

    pub async fn start(&self) -> Result<()> {
        info!("App started");

        // Start message listener
        let listener = self.listener.clone();
        let identity_hash = self.identity.hash.clone();
        let identity_pub_key = self.identity.get_public_key_hex();
        let identity_priv_key = self.identity.private_key.clone();
        // X-Identity-Key должен содержать hex(ed25519 public key), а не hash:
        // сервер сам считает SHA256(decoded_key) и сравнивает с target_hash.
        let ed25519_pub_key_hex = self.ed25519_pub_key_hex.clone();
        let signing_key = self.signing_key.clone();
        let shared_secrets = self.shared_secrets.clone();
        let storage = self.storage.clone();
        let event_sender = self.event_sender.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            let base_interval = Duration::from_secs(5);
            let mut current_interval = base_interval;

            loop {
                interval.tick().await;

                match listener
                    .pull_messages_with_auth(
                        &identity_hash,
                        &ed25519_pub_key_hex,
                        &signing_key,
                    )
                    .await
                {
                    Ok(messages) => {
                        if current_interval != base_interval {
                            current_interval = base_interval;
                            interval = tokio::time::interval(current_interval);
                        }

                        for packet in messages {
                            Self::handle_incoming_packet(
                                packet,
                                &shared_secrets,
                                &storage,
                                &identity_hash,
                                &identity_pub_key,
                                &identity_priv_key,
                                &event_sender,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        warn!("Pull error: {}", e);

                        // Implement backoff for rate limiting
                        if e.to_string().contains("rate limited") {
                            current_interval =
                                std::cmp::min(current_interval * 2, Duration::from_secs(60));
                            interval = tokio::time::interval(current_interval);
                            info!(
                                "Rate limited, increasing interval to {:?}",
                                current_interval
                            );
                        }
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_incoming_packet(
        packet: Vec<u8>,
        shared_secrets: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
        storage: &Arc<Storage>,
        identity_hash: &str,
        identity_pub_key: &str,
        identity_priv_key: &[u8],
        event_sender: &mpsc::UnboundedSender<AppEvent>,
    ) {
        let secrets = shared_secrets.lock().unwrap();

        let mut decrypted_message = None;
        let mut from_hash = String::new();

        // Try all known keys
        for (hash, secret) in secrets.iter() {
            if let Ok((decrypted, _)) = crypto::decrypt_message(&packet, secret) {
                decrypted_message = Some(decrypted);
                from_hash = hash.clone();
                break;
            }
        }

        // If not decrypted, try as self-message
        if decrypted_message.is_none() {
            drop(secrets);

            // Generate self shared key
            if let Ok(public_key) = hex::decode(identity_pub_key) {
                if let Ok(self_secret) = crypto::generate_shared_key(identity_priv_key, &public_key)
                {
                    if let Ok((decrypted, _)) = crypto::decrypt_message(&packet, &self_secret) {
                        decrypted_message = Some(decrypted);
                        from_hash = identity_hash.to_string();
                    }
                }
            }
        } else {
            drop(secrets);
        }

        let message = match decrypted_message {
            Some(m) => m,
            None => {
                warn!("Failed to decrypt incoming packet");
                return;
            }
        };

        // Get sender name
        let from_name = if from_hash == identity_hash {
            format!("{} (self)", &identity_hash[..8.min(identity_hash.len())])
        } else {
            match storage.get_contact(&from_hash) {
                Ok(contact) => contact.nickname,
                Err(_) => from_hash[..8.min(from_hash.len())].to_string(),
            }
        };

        // Save to DB
        let message_text = String::from_utf8_lossy(&message).to_string();
        let _ = storage.save_message_with_room(&from_hash, "in", &from_hash, &message_text);

        // Send event to UI
        let _ = event_sender.send(AppEvent::NewMessage {
            room_hash: from_hash.clone(),
            text: message_text.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            sender: from_name.clone(),
        });
    }

    // ============================================================
    // API METHODS FOR CLI
    // ============================================================

    pub fn get_profile(&self) -> serde_json::Value {
        serde_json::json!({
            "nickname": self.current_nickname(),
            "hash": self.identity.hash,
            "publicKey": self.identity.get_public_key_hex(),
            "ed25519PublicKey": self.ed25519_pub_key_hex,
        })
    }

    /// Seed-фраза вынесена из `/profile` в отдельную команду `/seed`.
    pub fn get_seed_phrase(&self) -> String {
        self.identity_manager
            .lock()
            .ok()
            .and_then(|manager| {
                manager
                    .current()
                    .map(|identity| identity.seed_phrase.clone())
            })
            .unwrap_or_else(|| self.identity.seed_phrase.clone())
    }

    /// Публичный геттер актуального ника (используется TUI-статус-баром).
    pub fn get_nickname(&self) -> String {
        self.current_nickname()
    }

    /// Источник истины для ника — `IdentityManager`, а не копия в `App`.
    /// После `/nick` копия `self.identity` намеренно не обновляется, поэтому
    /// читаем актуальное значение из менеджера.
    fn current_nickname(&self) -> String {
        self.identity_manager
            .lock()
            .ok()
            .and_then(|manager| manager.current().map(|identity| identity.nickname.clone()))
            .unwrap_or_else(|| self.identity.nickname.clone())
    }

    pub fn get_my_contact_link(&self) -> String {
        use url::form_urlencoded;

        let public_key_hex = self.identity.get_public_key_hex();
        let nickname = self.current_nickname();
        let params = [
            ("hash", self.identity.hash.as_str()),
            ("x25519", public_key_hex.as_str()),
            ("ed25519", self.ed25519_pub_key_hex.as_str()),
            ("nickname", nickname.as_str()),
        ];

        let encoded: String = form_urlencoded::Serializer::new(String::new())
            .extend_pairs(params.iter())
            .finish();

        format!("lastchance://contact?{}", encoded)
    }

    pub fn get_my_contact_json(&self) -> String {
        let data = serde_json::json!({
            "hash": self.identity.hash,
            "x25519": self.identity.get_public_key_hex(),
            "ed25519": self.ed25519_pub_key_hex,
            "nickname": self.current_nickname(),
        });

        serde_json::to_string_pretty(&data).unwrap_or_default()
    }

    pub fn get_contacts(&self) -> Result<Vec<Contact>> {
        self.storage.get_all_contacts()
    }

    pub fn add_contact(&self, hash: &str, pub_key_hex: &str, nickname: &str) -> Result<()> {
        let pub_key =
            hex::decode(pub_key_hex).map_err(|e| anyhow!("invalid public key hex: {}", e))?;

        if pub_key.len() != 32 {
            return Err(anyhow!(
                "public key must be 32 bytes, got {}",
                pub_key.len()
            ));
        }

        let shared_secret = crypto::generate_shared_key(&self.identity.private_key, &pub_key)?;

        self.storage.add_contact(hash, &pub_key, nickname)?;

        {
            let mut secrets = self.shared_secrets.lock().unwrap();
            secrets.insert(hash.to_string(), shared_secret);
        }

        let _ = self.storage.ensure_room(nickname, hash);

        let mut current = self.current_room_hash.lock().unwrap();
        if current.is_empty() {
            *current = hash.to_string();
        }

        Ok(())
    }

    pub fn update_nickname(&self, new_nickname: &str) -> Result<()> {
        let mut manager = self.identity_manager.lock().unwrap();
        manager.update_nickname(new_nickname)?;
        Ok(())
    }

    pub fn update_contact_nickname(&self, contact_hash: &str, new_nickname: &str) -> Result<()> {
        if contact_hash == self.identity.hash {
            return Err(anyhow!(
                "cannot rename your own identity this way; use UpdateNickname()"
            ));
        }
        if new_nickname.is_empty() {
            return Err(anyhow!("nickname cannot be empty"));
        }
        self.storage
            .update_contact_nickname(contact_hash, new_nickname)
    }

    pub async fn send_message(&self, room_hash: &str, text: &str) -> Result<()> {
        let shared_secret = self.get_shared_secret(room_hash)?;

        let session_id = {
            let mut id = self.session_id.lock().unwrap();
            *id += 1;
            *id
        };

        let packet = crypto::encrypt_message(text.as_bytes(), &shared_secret, session_id)?;

        self.sender.send_message(room_hash, &packet).await?;

        self.storage
            .save_message_with_room(room_hash, "out", room_hash, text)?;

        Ok(())
    }

    pub async fn send_file_native(&self, room_hash: &str, file_path: &str) -> Result<()> {
        use std::io::Read;

        let file_name = std::path::Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("invalid file path"))?;

        // Emit upload started event
        self.emit_event(AppEvent::UploadStarted {
            file_name: file_name.to_string(),
        });

        // Open file
        let mut file = self.safe_fs.safe_open_file(file_path)?;
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)
            .map_err(|e| anyhow!("failed to read file: {}", e))?;

        let file_size = file_data.len() as i64;

        // Emit progress event
        self.emit_event(AppEvent::UploadProgress {
            status: "Шифрование...".to_string(),
            progress: 30,
        });

        // Get shared secret
        let shared_secret = self.get_shared_secret(room_hash)?;

        // Encrypt file
        let encrypted_data = crypto::encrypt_file(&file_data, &shared_secret)?;

        // Emit progress event
        self.emit_event(AppEvent::UploadProgress {
            status: "Отправка на сервер...".to_string(),
            progress: 60,
        });

        // Upload file
        let file_hash = match self.sender.upload_file(&encrypted_data, file_name).await {
            Ok(hash) => hash,
            Err(e) => {
                self.emit_event(AppEvent::UploadError {
                    error: e.to_string(),
                });
                return Err(anyhow!("upload failed: {}", e));
            }
        };

        // Save file record
        self.storage
            .save_file_record(&file_hash, room_hash, file_name, file_size)?;

        // Emit progress event
        self.emit_event(AppEvent::UploadProgress {
            status: "Завершено".to_string(),
            progress: 100,
        });

        // Emit upload completed event
        self.emit_event(AppEvent::UploadCompleted {
            file_name: file_name.to_string(),
            file_hash: file_hash.clone(),
            file_size: Some(file_size),
        });

        // Send file notification message
        let message_text = format!(
            "📎 Файл: {}\nРазмер: {}\nХеш: {}",
            file_name,
            humanize_bytes(file_size as u64),
            file_hash
        );

        self.send_message(room_hash, &message_text).await?;

        Ok(())
    }

    pub async fn download_and_save_file(
        &self,
        room_hash: &str,
        file_hash: &str,
        save_path: &str,
    ) -> Result<()> {
        // Emit download started event
        self.emit_event(AppEvent::DownloadStarted);

        // Download encrypted file
        let encrypted_data = match self.listener.download_file(file_hash).await {
            Ok(data) => data,
            Err(e) => {
                self.emit_event(AppEvent::DownloadError {
                    error: e.to_string(),
                });
                return Err(anyhow!("download failed: {}", e));
            }
        };

        // Shared secret берём именно у комнаты файла: /dl может найти файл
        // среди полученных за сессию, не переключая активную комнату.
        let shared_secret = self.get_shared_secret(room_hash)?;

        // Decrypt file
        let file_data = match crypto::decrypt_file(&encrypted_data, &shared_secret) {
            Ok(data) => data,
            Err(e) => {
                self.emit_event(AppEvent::DownloadError {
                    error: e.to_string(),
                });
                return Err(anyhow!("decryption failed: {}", e));
            }
        };

        // Save file. Путь выбирает пользователь (например, ./downloads/...),
        // поэтому пишем напрямую: SafeFSOps ограничивает запись каталогом данных.
        if let Some(parent) = std::path::Path::new(save_path).parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    self.emit_event(AppEvent::DownloadError {
                        error: e.to_string(),
                    });
                    return Err(anyhow!("create directory failed: {}", e));
                }
            }
        }
        if let Err(e) = std::fs::write(save_path, &file_data) {
            self.emit_event(AppEvent::DownloadError {
                error: e.to_string(),
            });
            return Err(anyhow!("save failed: {}", e));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(save_path, std::fs::Permissions::from_mode(0o600));
        }

        // Emit download completed event
        self.emit_event(AppEvent::DownloadCompleted {
            file_path: save_path.to_string(),
        });

        Ok(())
    }

    fn get_shared_secret(&self, room_hash: &str) -> Result<[u8; 32]> {
        {
            let secrets = self.shared_secrets.lock().unwrap();
            if let Some(secret) = secrets.get(room_hash) {
                return Ok(*secret);
            }
        }

        // Check if self
        if room_hash == self.identity.hash {
            let secret =
                crypto::generate_shared_key(&self.identity.private_key, &self.identity.public_key)?;

            let mut secrets = self.shared_secrets.lock().unwrap();
            secrets.insert(room_hash.to_string(), secret);
            return Ok(secret);
        }

        // Load from storage
        let contact = self.storage.get_contact(room_hash)?;
        let secret = crypto::generate_shared_key(&self.identity.private_key, &contact.public_key)?;

        let mut secrets = self.shared_secrets.lock().unwrap();
        secrets.insert(room_hash.to_string(), secret);

        Ok(secret)
    }

    pub fn get_messages(&self, room_hash: &str, limit: i64) -> Result<Vec<Message>> {
        let mut messages = self.storage.get_room_messages(room_hash, limit)?;
        messages.reverse(); // Return in chronological order
        Ok(messages)
    }

    pub fn switch_room(&self, room_hash: &str) {
        let mut current = self.current_room_hash.lock().unwrap();
        *current = room_hash.to_string();
    }

    pub fn get_current_room(&self) -> String {
        self.current_room_hash.lock().unwrap().clone()
    }

    pub fn handle_scheme_url(&self, raw_url: &str) {
        info!("Scheme URL received: {}", raw_url);

        if !raw_url.starts_with("lastchance://contact?") {
            warn!("Unknown scheme URL");
            self.emit_event(AppEvent::ContactImportError {
                error: "Invalid contact link format".to_string(),
            });
            return;
        }

        let params_str = raw_url.trim_start_matches("lastchance://contact?");
        let params: HashMap<String, String> = url::form_urlencoded::parse(params_str.as_bytes())
            .into_owned()
            .collect();

        let hash = params.get("hash").map(|s| s.clone()).unwrap_or_default();
        let x25519 = params.get("x25519").map(|s| s.clone()).unwrap_or_default();
        let ed25519 = params.get("ed25519").map(|s| s.clone());
        let nickname = params
            .get("nickname")
            .map(|s| s.clone())
            .unwrap_or_default();

        if hash.is_empty() || x25519.is_empty() || nickname.is_empty() {
            self.emit_event(AppEvent::ContactImportError {
                error: "Missing required contact parameters".to_string(),
            });
            return;
        }

        self.emit_event(AppEvent::ContactImport {
            hash,
            x25519,
            ed25519,
            nickname,
        });
    }

    pub fn get_base_dir(&self) -> &str {
        &self.base_dir
    }

    pub fn get_config(&self) -> &Config {
        &self.config
    }

    pub fn get_storage(&self) -> &Arc<Storage> {
        &self.storage
    }

    pub fn get_safe_fs(&self) -> &Arc<SafeFSOps> {
        &self.safe_fs
    }
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

fn humanize_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{} B", bytes);
    } else if bytes < 1024 * 1024 {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    } else if bytes < 1024 * 1024 * 1024 {
        return format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0));
    } else {
        return format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn setup_test_app() -> (App, tempfile::TempDir, mpsc::UnboundedReceiver<AppEvent>) {
        let temp_dir = tempdir().unwrap();
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        let config = Config::default();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let app = App::new(config, base_dir, event_sender).unwrap();
        (app, temp_dir, event_receiver)
    }

    #[test]
    fn test_add_contact() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        let hash = "a".repeat(64);
        let pub_key_hex = "b".repeat(64);
        let nickname = "Test User";

        app.add_contact(&hash, &pub_key_hex, nickname).unwrap();

        let contacts = app.get_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].hash, hash);
        assert_eq!(contacts[0].nickname, nickname);
    }

    #[test]
    fn test_humanize_bytes() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1024), "1.0 KB");
        assert_eq!(humanize_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(humanize_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_get_profile() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        let profile = app.get_profile();
        assert!(profile["nickname"].is_string());
        assert!(profile["hash"].is_string());
        assert!(profile["publicKey"].is_string());
        assert!(profile["ed25519PublicKey"].is_string());
        // seed-фраза больше не выводится в /profile
        assert!(profile.get("seedPhrase").is_none());
        assert!(!app.get_seed_phrase().is_empty());
    }

    #[test]
    fn test_contact_link() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        let link = app.get_my_contact_link();
        assert!(link.starts_with("lastchance://contact?"));
        assert!(link.contains("hash="));
        assert!(link.contains("x25519="));
        assert!(link.contains("ed25519="));
        assert!(link.contains("nickname="));
    }
}
