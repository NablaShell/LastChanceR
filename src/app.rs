// src/app.rs
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use log::{info, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::crypto;
use crate::identity::{Identity, IdentityManager};
use crate::network::{Config, Listener, Sender};
use crate::storage::{Contact, Message, SafeFSOps, Storage};
use crate::vault::{self, MasterKey, Vault};

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
    config: RwLock<Config>,
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

    vault: Vault,

    event_sender: mpsc::UnboundedSender<AppEvent>,
}

/// Разворачивает `~` и `~/...` в домашнюю директорию пользователя.
fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    } else if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(raw)
}

/// Запрещённые для отправки системные директории.
fn is_protected_system_path(path: &Path) -> bool {
    #[cfg(unix)]
    {
        const BLOCKED: &[&str] = &["/etc", "/proc", "/sys", "/dev", "/boot", "/run"];
        if BLOCKED.iter().any(|dir| path.starts_with(dir)) {
            return true;
        }
    }

    #[cfg(windows)]
    {
        let windows = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Windows"));
        let windows = std::fs::canonicalize(&windows).unwrap_or(windows);
        if path.starts_with(&windows) {
            return true;
        }
    }

    false
}

/// Разрешает путь отправки относительно PWD, а не каталога данных.
///
/// Поддерживает абсолютные пути и `~/`. Возвращает канонизированный путь,
/// проверяет, что это обычный файл, и (без `force`) блокирует системные папки.
fn resolve_upload_path(raw: &str, force: bool) -> Result<PathBuf> {
    let expanded = expand_tilde(raw);
    let path = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()
            .map_err(|e| anyhow!("не удалось определить текущую директорию: {}", e))?
            .join(expanded)
    };

    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(anyhow!("файл не найден: {}", path.display()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(anyhow!("нет прав на чтение: {}", path.display()));
        }
        Err(e) => {
            return Err(anyhow!(
                "не удалось получить информацию о {}: {}",
                path.display(),
                e
            ));
        }
    };

    if !metadata.is_file() {
        return Err(anyhow!(
            "это не обычный файл (возможно, директория): {}",
            path.display()
        ));
    }

    let canonical = std::fs::canonicalize(&path)
        .map_err(|e| anyhow!("не удалось разрешить путь {}: {}", path.display(), e))?;

    if !force && is_protected_system_path(&canonical) {
        return Err(anyhow!(
            "отправка из системной директории запрещена: {} (используйте /sf --force {})",
            canonical.display(),
            raw
        ));
    }

    // Возвращаем исходный (но уже абсолютный) путь: имя файла и открытие
    // должны соответствовать тому, что ввёл пользователь; canonical нужен
    // только для проверки системных директорий.
    Ok(path)
}

impl App {
    pub fn new(
        config: Config,
        base_dir: String,
        vault: Vault,
        event_sender: mpsc::UnboundedSender<AppEvent>,
    ) -> Result<Self> {
        let safe_fs = Arc::new(SafeFSOps::new(&base_dir)?);

        // Ensure base directory exists
        safe_fs.ensure_dir(".")?;

        // Initialize storage
        let storage = Arc::new(Storage::new(&base_dir, vault.clone())?);

        // Initialize identity
        let identity_manager = Arc::new(Mutex::new(IdentityManager::new(
            base_dir.clone(),
            vault.clone(),
        )));
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
        let sender = Arc::new(Sender::new(&config)?);
        let listener = Arc::new(Listener::new(&config)?);

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
            config: RwLock::new(config),
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
            vault,
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
            // Пауза только перед повтором после ошибки: 1s -> 2s -> 5s -> 15s.
            const BACKOFF: [Duration; 4] = [
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(5),
                Duration::from_secs(15),
            ];
            // Не-ретраибельные ошибки (401, протокол) не должны вызывать
            // busy-loop, поэтому повторяем их с максимальной паузой.
            const NON_RETRYABLE_DELAY: Duration = Duration::from_secs(15);

            let mut backoff_index = 0usize;

            loop {
                match listener
                    .pull_messages_with_auth(
                        &identity_hash,
                        &ed25519_pub_key_hex,
                        &signing_key,
                    )
                    .await
                {
                    Ok(messages) => {
                        backoff_index = 0;

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

                        // 200 OK и 204 No Content не требуют паузы: следующий
                        // long-poll запрос уходит сразу же.
                    }
                    Err(e) => {
                        warn!("Pull error: {}", e);

                        let delay = if e.is_retryable() {
                            let delay = BACKOFF[backoff_index.min(BACKOFF.len() - 1)];
                            backoff_index = (backoff_index + 1).min(BACKOFF.len() - 1);
                            delay
                        } else {
                            NON_RETRYABLE_DELAY
                        };

                        info!("Pull retry in {:?}", delay);
                        tokio::time::sleep(delay).await;
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

    /// Проверяет мастер-пароль без изменения хранилища (команда `/passwd`).
    pub fn verify_master_password(&self, password: &str) -> Result<()> {
        Vault::verify_password(&self.base_dir, password)
    }

    /// Меняет мастер-пароль и перешифровывает файлы профиля и базу.
    pub fn change_master_password(&self, old_password: &str, new_password: &str) -> Result<()> {
        if new_password.chars().count() < vault::MIN_PASSWORD_LEN {
            return Err(anyhow!(
                "новый пароль должен быть не короче {} символов",
                vault::MIN_PASSWORD_LEN
            ));
        }

        Vault::verify_password(&self.base_dir, old_password)?;

        let old_key = self.vault.key()?;
        let (new_salt, new_key) = vault::derive_new(new_password)?;

        let rewrite_files =
            |from: &MasterKey, to: &MasterKey| -> Result<()> {
                {
                    let mut manager = self
                        .identity_manager
                        .lock()
                        .map_err(|_| anyhow!("identity lock poisoned"))?;
                    manager.reencrypt(from, to)?;
                }
                Config::reencrypt(&self.base_dir, from, to)?;
                Ok(())
            };

        if let Err(e) = rewrite_files(&old_key, &new_key) {
            // Без отдельного журнала транзакций делаем best-effort откат,
            // чтобы данные остались доступны старым паролем.
            let _ = rewrite_files(&new_key, &old_key);
            return Err(e);
        }

        // База перешифровывается и переключается на новый ключ под своей
        // блокировкой, поэтому фоновые записи не потеряются.
        if let Err(e) = self
            .storage
            .reencrypt_fields_and_replace_key(&old_key, &new_key)
        {
            let _ = self.storage.reencrypt_fields(&new_key, &old_key);
            let _ = rewrite_files(&new_key, &old_key);
            return Err(e);
        }

        // Метаданные пишем последними: до этого момента профиль ещё
        // открывается старым паролем.
        vault::write_meta(&self.base_dir, &new_salt, &new_key)?;

        Ok(())
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

    pub async fn send_file_native(
        &self,
        room_hash: &str,
        file_path: &str,
        force: bool,
    ) -> Result<()> {
        use std::io::Read;

        // Путь читается из PWD (или абсолютный/~/), а не из каталога данных.
        let path = resolve_upload_path(file_path, force)?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("invalid file path"))?;

        // Emit upload started event
        self.emit_event(AppEvent::UploadStarted {
            file_name: file_name.to_string(),
        });

        // Open file
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(anyhow!("нет прав на чтение: {}", path.display()));
            }
            Err(e) => {
                return Err(anyhow!("не удалось открыть {}: {}", path.display(), e));
            }
        };
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

        let hash = params.get("hash").cloned().unwrap_or_default();
        let x25519 = params.get("x25519").cloned().unwrap_or_default();
        let ed25519 = params.get("ed25519").cloned();
        let nickname = params
            .get("nickname").cloned()
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

    pub fn get_config(&self) -> Config {
        match self.config.read() {
            Ok(config) => config.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Сохраняет новые сетевые параметры и сразу применяет их в работающих
    /// `Sender`/`Listener`, не требуя перезапуска клиента.
    pub fn update_config(&self, mut config: Config) -> Result<()> {
        config.normalize();
        config.validate()?;
        config.save(&self.base_dir, &self.vault)?;

        self.sender.update_config(&config)?;
        self.listener.update_config(&config)?;

        let mut guard = self
            .config
            .write()
            .map_err(|_| anyhow!("конфигурация недоступна: блокировка повреждена"))?;
        *guard = config;

        Ok(())
    }

    pub fn get_storage(&self) -> &Arc<Storage> {
        &self.storage
    }

    /// Показывает системное уведомление о входящем сообщении.
    ///
    /// Ошибки демона уведомлений (например, при работе по SSH без D-Bus)
    /// возвращаются вызывающему, который для входящих сообщений их игнорирует.
    pub fn send_notification(&self, sender: &str, text: &str, unread: usize) -> Result<()> {
        let config = self.get_config();
        match config.notification_content(sender, text, unread) {
            Some((title, body)) => show_system_notification(&title, &body),
            None => Ok(()),
        }
    }

    /// Отправляет тестовое уведомление с текущими настройками (`/set test`).
    pub fn send_test_notification(&self) -> Result<()> {
        let config = self.get_config();
        let (title, body) = config
            .notification_content(
                "LastChance",
                "Тестовое сообщение: уведомления настроены.",
                1,
            )
            .ok_or_else(|| anyhow!("уведомления отключены (Notify Level: 0)"))?;

        show_system_notification(&title, &body)
    }

    pub fn get_safe_fs(&self) -> &Arc<SafeFSOps> {
        &self.safe_fs
    }
}

fn show_system_notification(title: &str, body: &str) -> Result<()> {
    notify_rust::Notification::new()
        .appname("LastChance")
        .summary(title)
        .body(body)
        .show()
        .map(|_| ())
        .map_err(|e| anyhow!("notification daemon error: {}", e))
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================

fn humanize_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
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

        let vault = Vault::create(&base_dir, "test-password").unwrap();
        let app = App::new(config, base_dir, vault, event_sender).unwrap();
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
    fn test_update_config_is_encrypted_and_applied() {
        let (app, temp_dir, _receiver) = setup_test_app();

        let mut config = app.get_config();
        config.server_url = "https://new-text.example".to_string();
        config.file_server_url = "https://new-files.example".to_string();
        config.mask_header_name = "X-Custom-Guard".to_string();
        config.mask_header_value = "new-secret".to_string();
        config.proxy_url = Some("socks5://127.0.0.1:9050".to_string());
        config.notify_level = 1;
        config.stealth_title = "Перерыв".to_string();
        config.stealth_body = "Отдых {sec}, писем: {count}".to_string();
        config.stealth_seconds = "10-15".to_string();

        app.update_config(config.clone()).unwrap();

        let applied = app.get_config();
        assert_eq!(applied.server_url, config.server_url);
        assert_eq!(applied.file_server_url, config.file_server_url);
        assert_eq!(applied.mask_header_name, config.mask_header_name);
        assert_eq!(applied.mask_header_value, config.mask_header_value);
        assert_eq!(
            applied.proxy_url.as_deref(),
            Some("socks5h://127.0.0.1:9050")
        );
        assert_eq!(applied.notify_level, 1);
        assert_eq!(applied.stealth_title, "Перерыв");
        assert_eq!(applied.stealth_body, "Отдых {sec}, писем: {count}");
        assert_eq!(applied.stealth_seconds, "10-15");

        let config_path = temp_dir.path().join("global.conf");
        let raw = std::fs::read(&config_path).unwrap();
        assert!(vault::is_sealed(&raw));
        assert!(!String::from_utf8_lossy(&raw).contains("new-secret"));

        let base_dir = temp_dir.path().to_str().unwrap();
        let reopened_vault = Vault::unlock(base_dir, "test-password").unwrap();
        let saved = Config::load(base_dir, &reopened_vault).unwrap();
        assert_eq!(saved.mask_header_value, "new-secret");
        assert_eq!(
            saved.proxy_url.as_deref(),
            Some("socks5h://127.0.0.1:9050")
        );
        assert_eq!(saved.notify_level, 1);
        assert_eq!(saved.stealth_title, "Перерыв");
        assert_eq!(saved.stealth_body, "Отдых {sec}, писем: {count}");
        assert_eq!(saved.stealth_seconds, "10-15");
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

    #[test]
    fn test_change_master_password_reencrypts_all_data() {
        let temp_dir = tempdir().unwrap();
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        let (event_sender, _event_receiver) = mpsc::unbounded_channel();

        let vault = Vault::create(&base_dir, "old-password-123").unwrap();
        // Создаём зашифрованный global.conf, как это делает main().
        Config::load(&base_dir, &vault).unwrap();
        let app = App::new(
            Config::default(),
            base_dir.clone(),
            vault,
            event_sender,
        )
        .unwrap();

        let hash = "f".repeat(64);
        app.add_contact(&hash, &"a".repeat(64), "Alice").unwrap();
        app.get_storage()
            .save_message(&hash, "out", "secret message")
            .unwrap();
        let identity_hash = app.identity.hash.clone();

        app.change_master_password("old-password-123", "new-password-456")
            .unwrap();

        // Старый пароль больше не открывает хранилище.
        assert!(Vault::unlock(&base_dir, "old-password-123").is_err());

        let new_vault = Vault::unlock(&base_dir, "new-password-456").unwrap();
        Config::load(&base_dir, &new_vault).unwrap();

        let (event_sender, _event_receiver) = mpsc::unbounded_channel();
        let reopened = App::new(
            Config::default(),
            base_dir,
            new_vault,
            event_sender,
        )
        .unwrap();

        assert_eq!(reopened.identity.hash, identity_hash);
        let contacts = reopened.get_contacts().unwrap();
        assert_eq!(contacts[0].nickname, "Alice");
        let messages = reopened.get_messages(&hash, 10).unwrap();
        assert_eq!(messages[0].text, "secret message");
    }
}
