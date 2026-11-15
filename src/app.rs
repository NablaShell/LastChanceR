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
use crate::crypto::ratchet::{self, RatchetState, Role as RatchetRole};
use crate::crypto::secret::SecretBytes;
use crate::i18n::{tr, Lang};
use crate::identity::{
    hash_ed25519_public, Identity, IdentityDoc, IdentityInvite, IdentityManager,
};
use crate::network::{Config, InboundRouter, Listener, Route, RoutingError, Sender};
use crate::storage::{
    Contact, Message, SafeFSOps, Storage, TOFU_CHANGED, TOFU_PENDING, TOFU_VERIFIED,
};
use crate::storage::paths::create_private_file;
use crate::types::{parse_file_notification_checked, truncate_display, FileHash};
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
        /// Сообщение существует только в RAM.
        is_ephemeral: bool,
        /// Unix timestamp, когда сообщение исчезнет.
        expires_at: Option<u64>,
    },
    /// Собеседник изменил синхронизированный RAM-TTL.
    TtlChanged {
        room_hash: String,
        seconds: Option<u64>,
        from_peer: bool,
    },
    ContactImport {
        invite: IdentityInvite,
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

/// Сессионный TTL комнаты. Хранится только в оперативной памяти и
/// намеренно не попадает в `vault.dat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomTtl {
    pub seconds: Option<u64>,
    pub synced: bool,
}

/// Результат импорта подписанного invite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactImportOutcome {
    pub hash: String,
    pub nickname: String,
    pub fingerprint: String,
    pub tofu_state: String,
    /// X25519-ключ отличается от сохранённого (TOFU `changed`).
    pub x25519_changed: bool,
}

/// `session_id` уничтоженных храповиков по hash комнаты. Держится только
/// в оперативной памяти и не сериализуется.
type RetiredRatchetSessions = Arc<Mutex<HashMap<String, Vec<[u8; 16]>>>>;

pub struct App {
    config: RwLock<Config>,
    base_dir: String,

    storage: Arc<Storage>,
    identity_manager: Arc<Mutex<IdentityManager>>,
    pub identity: Identity,

    shared_secrets: Arc<Mutex<HashMap<String, [u8; 32]>>>,
    /// Состояния Double Ratchet. Для обычных комнат они сохраняются в
    /// `vault.dat`, для комнат с RAM-TTL остаются только здесь.
    ratchets: Arc<Mutex<HashMap<String, RatchetState>>>,

    /// `session_id` уничтоженных храповиков (reset, выключение TTL).
    /// RAM-кэш; для обычных комнат дублируется в `vault.dat` и
    /// восстанавливается при старте. Запоздавший bootstrap-пакет старой
    /// сессии не должен приниматься как новая сессия (H-1/H-2).
    retired_ratchet_sessions: RetiredRatchetSessions,

    /// M-8: адресная таблица `alias -> room` и окно дедупликации доставки.
    /// Строится из ratchet-состояний; входящий пакет выбирает комнату по
    /// alias без перебора контактов.
    inbound_router: Arc<Mutex<InboundRouter>>,

    sender: Arc<Sender>,
    listener: Arc<Listener>,

    signing_key: SigningKey,
    ed25519_pub_key_hex: String,

    current_room_hash: Arc<Mutex<String>>,

    safe_fs: Arc<SafeFSOps>,

    vault: Vault,

    /// RAM-only TTL по hash комнаты. Не сериализуется и не сохраняется.
    room_ttls: Arc<Mutex<HashMap<String, RoomTtl>>>,

    event_sender: mpsc::UnboundedSender<AppEvent>,
}

/// Текущее Unix-время в секундах, безопасно приведённое к `u64`.
fn now_timestamp() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// Обрезает UTF-8 строку до `max` байт, не разрывая символ.
fn truncate_utf8(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }

    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// Пишет файл через временный файл в том же каталоге.
///
/// На Unix временный файл создаётся с правами 0600; при ошибке он удаляется,
/// а итоговый путь появляется только после успешного `rename` (M-6-friendly).
fn write_file_atomically(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("download");
    let temp_path = parent.join(format!(
        ".{}.part-{}-{:016x}",
        name,
        std::process::id(),
        rand::random::<u64>()
    ));

    let mut file = create_private_file(&temp_path, 0o600)
        .map_err(|e| anyhow!("create temporary file {}: {}", temp_path.display(), e))?;

    let write_result = (|| -> Result<()> {
        file.write_all(data)
            .map_err(|e| anyhow!("write temporary file {}: {}", temp_path.display(), e))?;
        file.sync_all()
            .map_err(|e| anyhow!("sync temporary file {}: {}", temp_path.display(), e))
    })();
    drop(file);

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    if let Err(first_error) = std::fs::rename(&temp_path, path) {
        // Windows не перезаписывает существующий файл через rename.
        if path.exists() {
            let _ = std::fs::remove_file(path);
            if std::fs::rename(&temp_path, path).is_err() {
                let _ = std::fs::remove_file(&temp_path);
                return Err(anyhow!(
                    "replace {}: {}",
                    path.display(),
                    first_error
                ));
            }
        } else {
            let _ = std::fs::remove_file(&temp_path);
            return Err(anyhow!("rename to {}: {}", path.display(), first_error));
        }
    }

    // Права 0600 уже выставлены на временном файле до записи данных и
    // сохраняются при rename.

    Ok(())
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
fn resolve_upload_path(raw: &str, force: bool, lang: Lang) -> Result<PathBuf> {
    let texts = lang.texts();
    let expanded = expand_tilde(raw);
    let path = if expanded.is_absolute() {
        expanded
    } else {
        std::env::current_dir()
            .map_err(|e| anyhow!("{}", tr(texts.cwd_failed, &[&e.to_string()])))?
            .join(expanded)
    };

    let metadata = match std::fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(anyhow!(
                "{}",
                tr(texts.file_not_found, &[&path.display().to_string()])
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(anyhow!(
                "{}",
                tr(texts.permission_denied, &[&path.display().to_string()])
            ));
        }
        Err(e) => {
            return Err(anyhow!(
                "{}",
                tr(
                    texts.stat_failed,
                    &[&path.display().to_string(), &e.to_string()]
                )
            ));
        }
    };

    if !metadata.is_file() {
        return Err(anyhow!(
            "{}",
            tr(texts.not_regular_file, &[&path.display().to_string()])
        ));
    }

    let canonical = std::fs::canonicalize(&path).map_err(|e| {
        anyhow!(
            "{}",
            tr(
                texts.resolve_path_failed,
                &[&path.display().to_string(), &e.to_string()]
            )
        )
    })?;

    if !force && is_protected_system_path(&canonical) {
        return Err(anyhow!(
            "{}",
            tr(
                texts.system_path_forbidden,
                &[&canonical.display().to_string(), raw]
            )
        ));
    }

    // Возвращаем исходный (но уже абсолютный) путь: имя файла и открытие
    // должны соответствовать тому, что ввёл пользователь; canonical нужен
    // только для проверки системных директорий.
    Ok(path)
}

/// Роль стороны в Double Ratchet. Обе стороны сравнивают одинаковые hash,
/// поэтому выбирают согласованные bootstrap-ключи.
fn ratchet_role_for(identity_hash: &str, room_hash: &str) -> RatchetRole {
    if room_hash == identity_hash {
        RatchetRole::SelfChat
    } else if identity_hash < room_hash {
        RatchetRole::Initiator
    } else {
        RatchetRole::Responder
    }
}

fn room_has_ttl(
    room_ttls: &Arc<Mutex<HashMap<String, RoomTtl>>>,
    room_hash: &str,
) -> bool {
    // TTL-кэш — простое RAM-состояние: после poison карта остаётся
    // логически целой, поэтому продолжаем с inner. Возвращать `false`
    // при poison нельзя: это позволило бы записать ratchet на диск (H-3).
    let ttls = room_ttls
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ttls.get(room_hash).and_then(|ttl| ttl.seconds).is_some()
}

/// Возвращает `session_id`, которые уже уничтожены для комнаты.
fn retired_sessions_for(
    retired: &RetiredRatchetSessions,
    room_hash: &str,
) -> Result<Vec<[u8; 16]>> {
    // Tombstone-и — часть replay-защиты (H-1/H-2). Poison означает, что
    // список неизвестен; нельзя притворяться, что сессий не было.
    let sessions = retired
        .lock()
        .map_err(|_| anyhow!("retired session lock poisoned"))?;
    Ok(sessions.get(room_hash).cloned().unwrap_or_default())
}

/// Переносит tombstone-и комнаты в `vault.dat` либо удаляет их.
///
/// Для комнаты с активным RAM-TTL `session_id` на диск не пишутся (H-3):
/// такие комнаты теряют replay-защиту сессий после перезапуска, что
/// зафиксировано в threat model.
fn persist_retired_sessions(
    storage: &Storage,
    retired: &RetiredRatchetSessions,
    ttl_active: bool,
    room_hash: &str,
) -> Result<()> {
    let session_ids = retired_sessions_for(retired, room_hash)?;
    if ttl_active {
        storage.delete_retired_ratchet_sessions(room_hash)
    } else {
        storage.save_retired_ratchet_sessions(room_hash, &session_ids)
    }
}

/// Запоминает уничтоженные `session_id` комнаты.
fn remember_retired_sessions(
    retired: &RetiredRatchetSessions,
    room_hash: &str,
    session_ids: impl IntoIterator<Item = [u8; 16]>,
) -> Result<()> {
    // Poison не позволяет безопасно дополнить список: сообщаем об ошибке,
    // чтобы вызывающий не удалял ratchet без записанного tombstone.
    let mut sessions = retired
        .lock()
        .map_err(|_| anyhow!("retired session lock poisoned"))?;
    let entry = sessions.entry(room_hash.to_string()).or_default();
    for session_id in session_ids {
        if entry.contains(&session_id) {
            continue;
        }
        entry.push(session_id);
        if entry.len() > ratchet::MAX_RETIRED_SESSIONS {
            entry.remove(0);
        }
    }
    Ok(())
}

/// Загружает состояние из `vault.dat` либо создаёт новую сессию.
///
/// Для комнат с активным RAM-TTL диск не читается и не пишется.
#[allow(clippy::too_many_arguments)]
fn ensure_ratchet_state(
    states: &mut HashMap<String, RatchetState>,
    room_hash: &str,
    shared_secret: &[u8; 32],
    identity_hash: &str,
    storage: &Storage,
    ttl_active: bool,
    retired: &[[u8; 16]],
) -> Result<()> {
    if states.contains_key(room_hash) {
        return Ok(());
    }

    let restored = if ttl_active {
        None
    } else {
        match storage.load_ratchet_state(room_hash) {
            Ok(state) => state,
            Err(e) => {
                warn!("Failed to load ratchet state: {:#}", e);
                None
            }
        }
    };

    let role = ratchet_role_for(identity_hash, room_hash);
    let state = match restored {
        Some(bytes) => match RatchetState::from_bytes(bytes) {
            Ok(mut state) => {
                state.retire_sessions(retired.iter().copied());
                state
            }
            Err(e) => {
                warn!("Ignoring unreadable ratchet state: {:#}", e);
                RatchetState::new_with_retired(shared_secret, role, retired.to_vec())?
            }
        },
        None => RatchetState::new_with_retired(shared_secret, role, retired.to_vec())?,
    };

    states.insert(room_hash.to_string(), state);
    Ok(())
}

/// H-3: единая точка записи состояния храповика.
///
/// При `ttl_active == true` снапшот не пишется никогда, независимо от
/// того, какой путь вызвал сохранение. TTL-комната держит ratchet в RAM.
fn persist_ratchet(
    ttl_active: bool,
    storage: &Storage,
    room_hash: &str,
    state: &[u8],
) -> Result<()> {
    if ttl_active {
        return Ok(());
    }
    storage.save_ratchet_state(room_hash, state)
}

/// Открытый текст, обновлённое состояние храповика (если оно подлежит
/// сохранению) и живые alias сессии для адресной таблицы M-8.
struct DecryptedRatchet {
    plaintext: Vec<u8>,
    serialized: Option<SecretBytes>,
    aliases: Vec<[u8; ratchet::SESSION_ALIAS_SIZE]>,
}

/// Расшифровывает пакет и возвращает открытый текст вместе с обновлённым
/// состоянием храповика (если оно подлежит сохранению).
///
/// Состояние намеренно не пишется здесь: вызывающий сначала обрабатывает
/// полезную нагрузку (например, `SetTtl`), затем решает, нужен ли снапшот.
#[allow(clippy::too_many_arguments)]
fn try_ratchet_decrypt(
    packet: &[u8],
    room_hash: &str,
    shared_secret: &[u8; 32],
    identity_hash: &str,
    storage: &Arc<Storage>,
    ratchets: &Arc<Mutex<HashMap<String, RatchetState>>>,
    retired_sessions: &RetiredRatchetSessions,
    ttl_active: bool,
) -> Option<DecryptedRatchet> {
    let retired = match retired_sessions_for(retired_sessions, room_hash) {
        Ok(retired) => retired,
        Err(_) => {
            warn!(
                "Incoming packet dropped for {}: retired session lock poisoned",
                truncate_display(room_hash, 16)
            );
            return None;
        }
    };

    let (plaintext, serialized, aliases) = {
        let mut states = match ratchets.lock() {
            Ok(states) => states,
            Err(_) => {
                warn!(
                    "Incoming packet dropped for {}: ratchet lock poisoned",
                    truncate_display(room_hash, 16)
                );
                return None;
            }
        };
        ensure_ratchet_state(
            &mut states,
            room_hash,
            shared_secret,
            identity_hash,
            storage,
            ttl_active,
            &retired,
        )
        .ok()?;

        let state = states.get_mut(room_hash)?;
        match state.decrypt(packet, shared_secret) {
            Ok(plaintext) => {
                let serialized = if ttl_active {
                    None
                } else {
                    state.to_bytes().ok()
                };
                let aliases = state.session_aliases().unwrap_or_default();
                (plaintext, serialized, aliases)
            }
            Err(error) => {
                if let Some(typed) = error.downcast_ref::<ratchet::RatchetError>() {
                    warn!(
                        "Incoming packet rejected for {}: {}",
                        truncate_display(room_hash, 16),
                        typed
                    );
                }
                return None;
            }
        }
    };

    Some(DecryptedRatchet {
        plaintext,
        serialized,
        aliases,
    })
}

/// Достаёт общий секрет комнаты из уже загруженной карты.
fn shared_secret_for_room(
    room: &str,
    shared_secrets: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
) -> Option<[u8; 32]> {
    match shared_secrets.lock() {
        Ok(secrets) => secrets.get(room).copied(),
        Err(_) => {
            // Ключевой кэш повреждён: не подставляем «пустой» секрет.
            warn!("Incoming packet dropped: shared secret lock poisoned");
            None
        }
    }
}

/// Единственный fallback для первого пакета сессии (M-8).
///
/// Bootstrap-пакет несёт `bootstrap_nonce`, но alias новой сессии ещё не
/// известен. Здесь перебираются только HKDF-производные alias по контактам;
/// AEAD не запускается ни для одного несовпавшего контакта. Обычные пакеты
/// этот путь не используют.
fn resolve_bootstrap_room(
    alias: &[u8; ratchet::SESSION_ALIAS_SIZE],
    nonce: &[u8; ratchet::BOOTSTRAP_NONCE_SIZE],
    shared_secrets: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
) -> Option<(String, [u8; 32])> {
    let secrets = match shared_secrets.lock() {
        Ok(secrets) => secrets,
        Err(_) => {
            warn!("Incoming packet dropped: shared secret lock poisoned");
            return None;
        }
    };
    for (room, secret) in secrets.iter() {
        if ratchet::bootstrap_session_alias(secret, nonce)
            .ok()
            .is_some_and(|candidate| &candidate == alias)
        {
            return Some((room.clone(), *secret));
        }
    }
    None
}

fn clear_ratchet_state(
    ratchets: &Arc<Mutex<HashMap<String, RatchetState>>>,
    storage: &Arc<Storage>,
    retired_sessions: &RetiredRatchetSessions,
    inbound_router: &Arc<Mutex<InboundRouter>>,
    room_ttls: &Arc<Mutex<HashMap<String, RoomTtl>>>,
    room_hash: &str,
) {
    // Удаление из HashMap запускает Drop для Zeroizing-ключей. Перед этим
    // запоминаем id сессий, чтобы запоздавший пакет не был принят снова,
    // и alias живых сессий для адресной таблицы (M-8).
    let (session_ids, aliases) = match ratchets.lock() {
        Ok(mut states) => match states.remove(room_hash) {
            Some(state) => {
                let ids = state.session_ids();
                let mut aliases = state.session_aliases().unwrap_or_default();
                aliases.extend(state.retired_aliases().unwrap_or_default());
                (ids, aliases)
            }
            None => (Vec::new(), Vec::new()),
        },
        Err(_) => {
            // Состояние храповика неизвестно: не трогаем ни tombstone-и,
            // ни диск, иначе можно потерять replay-защиту (H-1/H-2).
            warn!(
                "Ratchet reset aborted for {}: ratchet lock poisoned",
                truncate_display(room_hash, 16)
            );
            return;
        }
    };

    if let Err(e) = remember_retired_sessions(retired_sessions, room_hash, session_ids) {
        warn!(
            "Ratchet reset aborted for {}: {:#}",
            truncate_display(room_hash, 16),
            e
        );
        return;
    }

    let mut router = match inbound_router.lock() {
        Ok(router) => router,
        Err(_) => {
            warn!(
                "Ratchet reset aborted for {}: routing lock poisoned",
                truncate_display(room_hash, 16)
            );
            return;
        }
    };
    router.retire_room(room_hash, &aliases);

    // Сначала фиксируем tombstone-и, затем удаляем состояние: сбой записи
    // оставляет старую сессию на диске, а не теряет защиту от replay.
    let ttl_active = room_has_ttl(room_ttls, room_hash);
    if let Err(e) = persist_retired_sessions(storage, retired_sessions, ttl_active, room_hash) {
        warn!("Failed to persist retired ratchet sessions: {:#}", e);
        return;
    }

    if let Err(e) = storage.delete_ratchet_state(room_hash) {
        warn!("Failed to delete ratchet state: {:#}", e);
    }
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

        // Tombstone-и переживают перезапуск: без них запоздавший пакет
        // сброшенной сессии снова выглядел бы как первый контакт (H-2).
        let retired_ratchet_sessions = {
            let mut sessions: HashMap<String, Vec<[u8; 16]>> = HashMap::new();
            match storage.load_retired_ratchet_sessions() {
                Ok(entries) => {
                    for (room_hash, session_id) in entries {
                        let entry = sessions.entry(room_hash).or_default();
                        if entry.contains(&session_id) {
                            continue;
                        }
                        entry.push(session_id);
                        if entry.len() > ratchet::MAX_RETIRED_SESSIONS {
                            entry.remove(0);
                        }
                    }
                }
                Err(e) => warn!("Failed to load retired ratchet sessions: {:#}", e),
            }
            Arc::new(Mutex::new(sessions))
        };

        // Initialize identity
        let identity_manager = Arc::new(Mutex::new(IdentityManager::new(
            base_dir.clone(),
            vault.clone(),
        )));
        let identity = {
            // Личность содержит приватные ключи: poison = состояние
            // неизвестно, поэтому инициализация завершается ошибкой.
            let mut manager = identity_manager
                .lock()
                .map_err(|_| anyhow!("identity lock poisoned"))?;
            manager.load_or_create("")?
        };

        // Setup Ed25519 signing key
        if identity.ed25519_private_key.len() != 32 {
            return Err(anyhow!(
                "Invalid Ed25519 private key size — identity may be corrupted"
            ));
        }

        let mut signing_key_bytes = [0u8; 32];
        signing_key_bytes.copy_from_slice(identity.ed25519_private_key.expose());
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
            // Кэш общих секретов чувствителен к poison: не продолжаем с
            // частично заполненной картой.
            let mut secrets = shared_secrets
                .lock()
                .map_err(|_| anyhow!("shared secret lock poisoned"))?;

            for contact in &contacts {
                if let Some(ed25519_hex) = contact.ed25519.as_deref() {
                    let valid_hash = hex::decode(ed25519_hex)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                        .map(|ed25519| hash_ed25519_public(&ed25519))
                        .map(|hash| hash.eq_ignore_ascii_case(&contact.hash))
                        .unwrap_or(false);

                    if !valid_hash {
                        warn!(
                            "Skipping contact {}: stored ed25519 key contradicts identity hash",
                            truncate_display(&contact.hash, 16)
                        );
                        continue;
                    }
                }

                match crypto::generate_shared_key(
                    identity.private_key.expose(),
                    &contact.public_key,
                ) {
                    Ok(secret) => {
                        secrets.insert(contact.hash.clone(), secret);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to generate shared secret for {}: {}",
                            truncate_display(&contact.hash, 16),
                            e
                        );
                    }
                }
            }

            // Self-chat uses the same X25519 static secret; keep it in the
            // map so M-8 routing and send paths never special-case the room.
            match crypto::generate_shared_key(
                identity.private_key.expose(),
                &identity.public_key,
            ) {
                Ok(secret) => {
                    secrets.insert(identity.hash.clone(), secret);
                }
                Err(e) => warn!("Failed to derive self shared secret: {}", e),
            }

            // Set current room to the first contact whose keys validated.
            if let Some(contact) = contacts
                .iter()
                .find(|contact| secrets.contains_key(&contact.hash))
            {
                // Курсор текущей комнаты — простое UI-состояние: после
                // poison безопасно продолжаем с inner.
                let mut current = current_room_hash
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *current = contact.hash.clone();
                drop(current);

                let _ = storage.ensure_room(&contact.nickname, &contact.hash);
            }
        }

        // M-8: восстанавливаем ratchet-состояния до запуска listener-а и
        // строим таблицу alias -> room. Без этого первый не-bootstrap пакет
        // после перезапуска выглядел бы как UnknownRoom.
        let ratchets = Arc::new(Mutex::new(HashMap::new()));
        let inbound_router = Arc::new(Mutex::new(InboundRouter::new()));
        {
            let rooms: Vec<String> = shared_secrets
                .lock()
                .map_err(|_| anyhow!("shared secret lock poisoned"))?
                .keys()
                .cloned()
                .collect();

            let mut states = ratchets
                .lock()
                .map_err(|_| anyhow!("ratchet lock poisoned"))?;

            for room in &rooms {
                let retired = retired_sessions_for(&retired_ratchet_sessions, room)?;
                match storage.load_ratchet_state(room) {
                    Ok(Some(bytes)) => match RatchetState::from_bytes(bytes) {
                        Ok(mut state) => {
                            state.retire_sessions(retired);
                            states.insert(room.clone(), state);
                        }
                        Err(e) => warn!(
                            "Ignoring unreadable ratchet state for {}: {:#}",
                            truncate_display(room, 16),
                            e
                        ),
                    },
                    Ok(None) => {}
                    Err(e) => warn!(
                        "Failed to load ratchet state for {}: {:#}",
                        truncate_display(room, 16),
                        e
                    ),
                }
            }

            let routes: Vec<_> = states
                .iter()
                .map(|(room, state)| {
                    (
                        room.clone(),
                        state.session_aliases().unwrap_or_default(),
                        state.retired_aliases().unwrap_or_default(),
                    )
                })
                .collect();
            drop(states);

            let mut router = inbound_router
                .lock()
                .map_err(|_| anyhow!("routing lock poisoned"))?;
            for (room, active, retired) in routes {
                router.register_state(&room, &active);
                router.register_retired(&room, &retired);
            }

            // Tombstone-и очищенных сессий тоже должны отклоняться адресно.
            let retired = retired_ratchet_sessions
                .lock()
                .map_err(|_| anyhow!("retired session lock poisoned"))?;
            for (room, session_ids) in retired.iter() {
                let aliases: Vec<_> = session_ids
                    .iter()
                    .filter_map(|id| ratchet::session_alias(id).ok())
                    .collect();
                router.register_retired(room, &aliases);
            }
        }

        info!(
            "App initialized: nickname={}, hash={}...",
            identity.nickname,
            truncate_display(&identity.hash, 16)
        );

        Ok(Self {
            config: RwLock::new(config),
            base_dir,
            storage,
            identity_manager,
            identity,
            shared_secrets,
            ratchets,
            retired_ratchet_sessions,
            inbound_router,
            sender,
            listener,
            signing_key,
            ed25519_pub_key_hex,
            current_room_hash,
            safe_fs,
            vault,
            room_ttls: Arc::new(Mutex::new(HashMap::new())),
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
        // X-Identity-Key должен содержать hex(ed25519 public key), а не hash:
        // сервер сам считает SHA256(decoded_key) и сравнивает с target_hash.
        let ed25519_pub_key_hex = self.ed25519_pub_key_hex.clone();
        let signing_key = self.signing_key.clone();
        let shared_secrets = self.shared_secrets.clone();
        let storage = self.storage.clone();
        let room_ttls = self.room_ttls.clone();
        let ratchets = self.ratchets.clone();
        let retired_ratchet_sessions = self.retired_ratchet_sessions.clone();
        let inbound_router = self.inbound_router.clone();
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
                                &room_ttls,
                                &ratchets,
                                &retired_ratchet_sessions,
                                &inbound_router,
                                &identity_hash,
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

    #[allow(clippy::too_many_arguments)]
    async fn handle_incoming_packet(
        packet: Vec<u8>,
        shared_secrets: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
        storage: &Arc<Storage>,
        room_ttls: &Arc<Mutex<HashMap<String, RoomTtl>>>,
        ratchets: &Arc<Mutex<HashMap<String, RatchetState>>>,
        retired_ratchet_sessions: &RetiredRatchetSessions,
        inbound_router: &Arc<Mutex<InboundRouter>>,
        identity_hash: &str,
        event_sender: &mpsc::UnboundedSender<AppEvent>,
    ) {
        // M-8: порядок проверок до криптографии —
        // version/размер → alias lookup → retired → dedup → AEAD → ratchet.
        let (info, route) = {
            let mut router = match inbound_router.lock() {
                Ok(router) => router,
                Err(_) => {
                    warn!("Incoming packet dropped: routing lock poisoned");
                    return;
                }
            };
            match router.resolve(&packet) {
                Ok(resolved) => resolved,
                Err(error) => {
                    warn!("Incoming packet rejected: {}", error);
                    return;
                }
            }
        };

        let (from_hash, shared_secret) = match route {
            Route::Active(room) => match shared_secret_for_room(&room, shared_secrets) {
                Some(secret) => (room, secret),
                None => {
                    warn!(
                        "Incoming packet for {} has no shared secret",
                        truncate_display(&room, 16)
                    );
                    return;
                }
            },
            Route::Retired(room) => {
                warn!(
                    "Incoming packet rejected: {} ({})",
                    RoutingError::StaleSession,
                    truncate_display(&room, 16)
                );
                return;
            }
            Route::Unknown => {
                // Первый пакет сессии: alias ещё никому не известен.
                // Сравниваем только дешёвые HKDF-alias, без AEAD-перебора.
                let resolved = info.bootstrap_nonce.and_then(|nonce| {
                    resolve_bootstrap_room(&info.alias, &nonce, shared_secrets)
                });
                match resolved {
                    Some(room) => room,
                    None => {
                        warn!("Incoming packet rejected: {}", RoutingError::UnknownRoom);
                        return;
                    }
                }
            }
        };

        let now = std::time::Instant::now();
        {
            let mut router = match inbound_router.lock() {
                Ok(router) => router,
                Err(_) => {
                    // Без проверки nonce пакет может оказаться replay.
                    warn!("Incoming packet dropped: routing lock poisoned");
                    return;
                }
            };
            if router.is_duplicate(info.alias, &info.nonce, now) {
                warn!(
                    "Incoming packet rejected: {} ({})",
                    RoutingError::ReplayNonce,
                    truncate_display(&from_hash, 16)
                );
                return;
            }
        }

        let ttl_active = room_has_ttl(room_ttls, &from_hash);
        {
            let mut router = match inbound_router.lock() {
                Ok(router) => router,
                Err(_) => {
                    warn!("Incoming packet dropped: routing lock poisoned");
                    return;
                }
            };
            router.note_decrypt_attempt();
        }
        let decrypted = match try_ratchet_decrypt(
            &packet,
            &from_hash,
            &shared_secret,
            identity_hash,
            storage,
            ratchets,
            retired_ratchet_sessions,
            ttl_active,
        ) {
            Some(decrypted) => decrypted,
            None => {
                warn!(
                    "Failed to decrypt incoming packet for {}",
                    truncate_display(&from_hash, 16)
                );
                return;
            }
        };

        let DecryptedRatchet {
            plaintext: message,
            serialized: mut ratchet_update,
            aliases,
        } = decrypted;

        // Индекс обновляется после успешной расшифровки: bootstrap-сессия
        // получает адрес, а мусорные пакеты не занимают таблицу.
        {
            let mut router = match inbound_router.lock() {
                Ok(router) => router,
                Err(_) => {
                    warn!(
                        "Incoming packet dropped for {}: routing lock poisoned",
                        truncate_display(&from_hash, 16)
                    );
                    return;
                }
            };
            router.register_state(&from_hash, &aliases);
            router.mark_delivered(info.alias, &info.nonce, now);
        }

        // Внутренний конверт: текст с TTL-метаданными или служебные пакеты.
        let (message_text, ttl_seconds) = match crypto::decode_payload(&message) {
            Ok(crypto::E2ePayload::SetTtl { seconds }) => {
                // TTL-кэш — простое RAM-состояние: poison не должен
                // превращаться в «TTL выключен» (H-3).
                {
                    let mut ttls = room_ttls
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    match seconds {
                        Some(value) => {
                            ttls.insert(
                                from_hash.clone(),
                                RoomTtl {
                                    seconds: Some(value),
                                    synced: true,
                                },
                            );
                        }
                        None => {
                            ttls.remove(&from_hash);
                        }
                    }
                }

                // Смена режима TTL сбрасывает сессию храповика с обеих
                // сторон: дальше состояние живёт только в RAM.
                clear_ratchet_state(
                    ratchets,
                    storage,
                    retired_ratchet_sessions,
                    inbound_router,
                    room_ttls,
                    &from_hash,
                );

                let _ = event_sender.send(AppEvent::TtlChanged {
                    room_hash: from_hash.clone(),
                    seconds,
                    from_peer: from_hash != identity_hash,
                });
                return;
            }
            Ok(crypto::E2ePayload::RatchetReset) => {
                clear_ratchet_state(
                    ratchets,
                    storage,
                    retired_ratchet_sessions,
                    inbound_router,
                    room_ttls,
                    &from_hash,
                );
                info!(
                    "Ratchet session reset by peer for {}",
                    truncate_display(&from_hash, 16)
                );
                return;
            }
            Ok(crypto::E2ePayload::Text { text, ttl_seconds }) => {
                // Файловое уведомление приходит внутри расшифрованного
                // текста, но hash всё равно недоверенный. Проверяем до
                // сохранения ratchet/message, чтобы отбросить пакет целиком.
                if let Err(e) = parse_file_notification_checked(&text) {
                    warn!(
                        "Rejected file notification from {}: invalid file hash: {}",
                        truncate_display(&from_hash, 16),
                        e
                    );
                    return;
                }
                if let Some(bytes) = ratchet_update.take() {
                    if let Err(e) = persist_ratchet(
                        room_has_ttl(room_ttls, &from_hash),
                        storage.as_ref(),
                        &from_hash,
                        bytes.expose(),
                    ) {
                        warn!("Failed to persist ratchet state: {:#}", e);
                    }
                }
                (text, ttl_seconds)
            }
            Err(e) => {
                warn!(
                    "Malformed E2E payload from {}: {:#}",
                    truncate_display(&from_hash, 16),
                    e
                );
                return;
            }
        };

        // Get sender name
        let from_name = if from_hash == identity_hash {
            format!("{} (self)", truncate_display(identity_hash, 8))
        } else {
            match storage.get_contact(&from_hash) {
                Ok(contact) => contact.nickname,
                Err(_) => truncate_display(&from_hash, 8),
            }
        };

        // Входящее сообщение становится эфемерным, если TTL пришёл в
        // метаданных или включён локальный режим этой комнаты.
        // Простое RAM-состояние: после poison продолжаем с inner.
        let local_ttl = room_ttls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&from_hash)
            .and_then(|ttl| ttl.seconds);
        let effective_ttl = ttl_seconds.or(local_ttl);
        let expires_at = effective_ttl.map(|seconds| now_timestamp().saturating_add(seconds));

        // Save to DB (ephemeral rows never reach vault.dat).
        let _ = storage.save_message_with_room_meta(
            &from_hash,
            "in",
            &from_hash,
            &message_text,
            expires_at.is_some(),
            expires_at,
        );

        // Send event to UI
        let _ = event_sender.send(AppEvent::NewMessage {
            room_hash: from_hash.clone(),
            text: message_text.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            sender: from_name.clone(),
            is_ephemeral: expires_at.is_some(),
            expires_at,
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

    /// Seed-фраза вынесена из `/profile` в модальное окно `/recovery`,
    /// которое требует текущий мастер-пароль.
    ///
    /// Возвращается обычная `String` только для отображения в UI; хранимый
    /// оригинал остаётся в `SecretString` и затирается при `drop`.
    pub fn get_seed_phrase(&self) -> String {
        self.identity_manager
            .lock()
            .ok()
            .and_then(|manager| {
                manager
                    .current()
                    .map(|identity| identity.seed_phrase.expose().to_string())
            })
            .unwrap_or_else(|| self.identity.seed_phrase.expose().to_string())
    }

    /// Публичный геттер актуального ника (используется TUI-статус-баром).
    pub fn get_nickname(&self) -> String {
        self.current_nickname()
    }

    /// Перезаписывает `identity.json` личностью, восстановленной из BIP-39.
    ///
    /// Текущий ник сохраняется. Запущенный `App` продолжает работать со
    /// старыми ключами до перезапуска — вызывающая сторона должна об этом
    /// предупредить пользователя.
    pub fn restore_identity_from_mnemonic(&self, seed_phrase: &str) -> Result<String> {
        let mut manager = self
            .identity_manager
            .lock()
            .map_err(|_| anyhow!("identity lock poisoned"))?;

        let nickname = manager
            .current()
            .map(|identity| identity.nickname.clone())
            .unwrap_or_default();
        let identity = manager.restore_from_mnemonic(seed_phrase, &nickname)?;
        manager.save(&identity)?;

        Ok(identity.hash)
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

    /// Текущий подписываемый документ личности. Ник берётся из менеджера,
    /// чтобы `/nick` сразу попадал в новые invite-ссылки.
    fn current_identity_doc(&self) -> Result<IdentityDoc> {
        let nickname = self.current_nickname();
        let nickname = truncate_utf8(&nickname, crate::identity::MAX_NICKNAME_BYTES);

        IdentityDoc::from_slices(
            &self.identity.ed25519_public_key,
            &self.identity.public_key,
            Some(nickname),
            self.identity.created_at.max(0) as u64,
        )
    }

    fn current_identity_invite(&self) -> Result<IdentityInvite> {
        IdentityInvite::sign(self.current_identity_doc()?, &self.signing_key)
    }

    pub fn get_my_contact_link(&self) -> Result<String> {
        self.current_identity_invite()?.to_link()
    }

    pub fn get_my_contact_json(&self) -> Result<String> {
        let invite = self.current_identity_invite()?;
        let doc_hex = hex::encode(invite.doc.canonical_cbor()?);
        let data = serde_json::json!({
            "hash": invite.hash_hex(),
            "x25519": hex::encode(invite.doc.x25519_pub),
            "ed25519": hex::encode(invite.doc.ed25519_pub),
            "nickname": invite.display_nickname(),
            "fingerprint": invite.fingerprint_hex(),
            "identityDoc": doc_hex,
            "identitySig": hex::encode(invite.signature),
        });

        serde_json::to_string_pretty(&data)
            .map_err(|e| anyhow!("failed to serialize contact JSON: {}", e))
    }

    pub fn get_contacts(&self) -> Result<Vec<Contact>> {
        self.storage.get_all_contacts()
    }

    /// Добавляет контакт только из криптографически проверенного invite.
    ///
    /// Подпись Ed25519 над CBOR-документом подтверждает, что владелец
    /// Ed25519-ключа действительно выдал этот X25519-ключ. Hash пересчитан
    /// из документа и сверен с ссылкой, поэтому подмена полей невозможна.
    pub fn add_contact_with_ed25519(
        &self,
        invite: &IdentityInvite,
    ) -> Result<ContactImportOutcome> {
        invite.verify()?;

        let doc = &invite.doc;
        let hash = invite.hash_hex();
        let ed25519 = hex::encode(doc.ed25519_pub);
        let fingerprint = invite.fingerprint_hex();
        let pub_key = doc.x25519_pub.to_vec();

        let existing = self.storage.get_contact(&hash).ok();
        let (tofu_state, x25519_changed) = match existing.as_ref() {
            None => (TOFU_PENDING.to_string(), false),
            Some(contact) => {
                if let Some(stored_ed25519) = contact.ed25519.as_deref() {
                    if !stored_ed25519.eq_ignore_ascii_case(&ed25519) {
                        return Err(anyhow!(
                            "stored ed25519 key contradicts sha256-derived identity hash"
                        ));
                    }
                }

                if contact.public_key != pub_key {
                    (TOFU_CHANGED.to_string(), true)
                } else if contact.tofu_state.is_empty() {
                    (TOFU_PENDING.to_string(), false)
                } else {
                    (contact.tofu_state.clone(), false)
                }
            }
        };

        let shared_secret =
            crypto::generate_shared_key(self.identity.private_key.expose(), &pub_key)?;

        let nickname = invite.display_nickname();
        self.storage.upsert_verified_contact(
            &hash,
            &pub_key,
            &ed25519,
            &fingerprint,
            &tofu_state,
            &nickname,
        )?;

        {
            let mut secrets = self
                .shared_secrets
                .lock()
                .map_err(|_| anyhow!("shared secrets lock poisoned"))?;
            secrets.insert(hash.clone(), shared_secret);
        }

        let _ = self.storage.ensure_room(&nickname, &hash);

        // Курсор комнаты — простое UI-состояние: poison безопасен.
        let mut current = self
            .current_room_hash
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.is_empty() {
            *current = hash.clone();
        }

        Ok(ContactImportOutcome {
            hash,
            nickname,
            fingerprint,
            tofu_state: tofu_state.to_string(),
            x25519_changed,
        })
    }

    /// Пользователь сверил отпечаток вне канала и подтверждает контакт.
    pub fn verify_contact_fingerprint(&self, contact_hash: &str) -> Result<()> {
        self.storage
            .set_contact_tofu_state(contact_hash, TOFU_VERIFIED)
    }

    /// Удаляет контакт и всю его историю сообщений/файлов.
    pub fn delete_contact(&self, contact_hash: &str) -> Result<()> {
        if contact_hash == self.identity.hash {
            return Err(anyhow!("cannot delete your own identity"));
        }

        self.storage.delete_contact(contact_hash)?;

        // Кэш секретов удаляем только при исправной блокировке: иначе
        // состояние карты неизвестно.
        let mut secrets = self
            .shared_secrets
            .lock()
            .map_err(|_| anyhow!("shared secret lock poisoned"))?;
        secrets.remove(contact_hash);
        drop(secrets);

        // TTL и курсор комнаты — простое RAM-состояние, poison безопасен.
        self.room_ttls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(contact_hash);

        // Ratchet — fail-closed: при poison не притворяемся, что сессии нет.
        let mut ratchets = self
            .ratchets
            .lock()
            .map_err(|_| anyhow!("ratchet lock poisoned"))?;
        ratchets.remove(contact_hash);
        drop(ratchets);

        let mut router = self
            .inbound_router
            .lock()
            .map_err(|_| anyhow!("routing lock poisoned"))?;
        router.remove_room(contact_hash);
        drop(router);

        let mut current = self
            .current_room_hash
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.as_str() == contact_hash {
            current.clear();
        }

        Ok(())
    }

    /// Количество сообщений контакта для карточки `/contacts`.
    pub fn count_contact_messages(&self, contact_hash: &str) -> Result<usize> {
        self.storage.count_messages(contact_hash)
    }

    pub fn update_nickname(&self, new_nickname: &str) -> Result<()> {
        // Личность/ключи — fail-closed: poison означает неизвестное
        // состояние, запись не выполняется.
        let mut manager = self
            .identity_manager
            .lock()
            .map_err(|_| anyhow!("identity lock poisoned"))?;
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
            let texts = self.get_config().lang.texts();
            return Err(anyhow!(
                "{}",
                tr(
                    texts.password_min_app,
                    &[&vault::MIN_PASSWORD_LEN.to_string()]
                )
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
        let ttl = self.get_room_ttl(room_hash);

        // Односторонний `/ttl` остаётся локальным: TTL не передаётся
        // собеседнику. Двусторонний `/ttl-syn` едет в метаданных текста.
        let wire_ttl = ttl.filter(|value| value.synced).and_then(|value| value.seconds);
        let payload = crypto::encode_text_payload(text, wire_ttl);

        let packet = self.encrypt_with_ratchet(room_hash, &payload)?;

        self.sender
            .send_message(room_hash, &packet, &self.signing_key)
            .await?;

        self.store_outgoing_message(room_hash, text)
    }

    /// Шифрует полезную нагрузку текущей эпохой Double Ratchet.
    ///
    /// Для обычной комнаты обновлённое состояние сразу сохраняется в
    /// `vault.dat`. Для комнаты с RAM-TTL состояние остаётся в памяти.
    fn encrypt_with_ratchet(&self, room_hash: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let ttl_active = self.get_room_ttl(room_hash).is_some();
        let shared_secret = self.get_shared_secret(room_hash)?;
        let identity_hash = self.identity.hash.clone();
        let retired = retired_sessions_for(&self.retired_ratchet_sessions, room_hash)?;

        let (packet, serialized, aliases) = {
            let mut states = self
                .ratchets
                .lock()
                .map_err(|_| anyhow!("ratchet lock poisoned"))?;

            ensure_ratchet_state(
                &mut states,
                room_hash,
                &shared_secret,
                &identity_hash,
                self.storage.as_ref(),
                ttl_active,
                &retired,
            )?;

            let state = states
                .get_mut(room_hash)
                .ok_or_else(|| anyhow!("ratchet state is missing"))?;
            let packet = state.encrypt(payload)?;
            let serialized = if ttl_active {
                None
            } else {
                Some(state.to_bytes()?)
            };
            let aliases = state.session_aliases().unwrap_or_default();
            (packet, serialized, aliases)
        };

        match self.inbound_router.lock() {
            Ok(mut router) => router.register_state(room_hash, &aliases),
            Err(_) => warn!(
                "Failed to register ratchet aliases for {}: routing lock poisoned",
                truncate_display(room_hash, 16)
            ),
        }

        if let Some(bytes) = serialized {
            self.persist_ratchet_if_needed(room_hash, bytes.expose())?;
        }

        Ok(packet)
    }

    /// H-3: для TTL-комнаты состояние храповика не пишется в `vault.dat`.
    fn persist_ratchet_if_needed(&self, room_hash: &str, state: &[u8]) -> Result<()> {
        persist_ratchet(
            self.get_room_ttl(room_hash).is_some(),
            self.storage.as_ref(),
            room_hash,
            state,
        )
    }

    /// Принудительно сбрасывает сессию храповика и уведомляет собеседника.
    pub async fn reset_ratchet_with_peer(&self, room_hash: &str) -> Result<()> {
        let payload = crypto::encode_ratchet_reset();
        let packet = self.encrypt_with_ratchet(room_hash, &payload)?;
        self.sender
            .send_message(room_hash, &packet, &self.signing_key)
            .await?;
        self.clear_ratchet(room_hash)
    }

    /// Удаляет состояние храповика из RAM и `vault.dat`.
    ///
    /// `session_id` уничтоженных сессий остаются в RAM-реестре и (для
    /// обычных комнат) в `vault.dat`, чтобы запоздавший пакет старой
    /// сессии не был принят как новая сессия даже после перезапуска.
    pub fn clear_ratchet(&self, room_hash: &str) -> Result<()> {
        let ttl_active = self.get_room_ttl(room_hash).is_some();
        let (session_ids, aliases) = {
            // Fail-closed: при poison состояние неизвестно, поэтому не
            // удаляем ни диск, ни tombstone-и (H-1/H-2).
            let mut states = self
                .ratchets
                .lock()
                .map_err(|_| anyhow!("ratchet lock poisoned"))?;
            match states.remove(room_hash) {
                Some(state) => {
                    let ids = state.session_ids();
                    let mut aliases = state.session_aliases().unwrap_or_default();
                    aliases.extend(state.retired_aliases().unwrap_or_default());
                    (ids, aliases)
                }
                None => (Vec::new(), Vec::new()),
            }
        };
        remember_retired_sessions(&self.retired_ratchet_sessions, room_hash, session_ids)?;

        // M-8: старый alias больше не маршрутизируется ни в какую сессию,
        // а отклоняется как StaleSession до AEAD.
        let mut router = self
            .inbound_router
            .lock()
            .map_err(|_| anyhow!("routing lock poisoned"))?;
        router.retire_room(room_hash, &aliases);
        drop(router);

        // Сначала tombstone-и, затем удаление состояния: при ошибке записи
        // старая сессия остаётся на диске, а не теряет replay-защиту.
        persist_retired_sessions(
            self.storage.as_ref(),
            &self.retired_ratchet_sessions,
            ttl_active,
            room_hash,
        )?;
        self.storage.delete_ratchet_state(room_hash)
    }

    /// Переносит текущую сессию храповика в RAM и удаляет её с диска.
    ///
    /// Используется при включении `/ttl` или `/ttl-syn`: собеседник
    /// сохраняет прежнюю сессию, поэтому локальная копия должна остаться
    /// доступной, но только в оперативной памяти.
    fn enter_ram_ttl(&self, room_hash: &str) -> Result<()> {
        let retired = retired_sessions_for(&self.retired_ratchet_sessions, room_hash)?;
        {
            let mut states = self
                .ratchets
                .lock()
                .map_err(|_| anyhow!("ratchet lock poisoned"))?;

            if !states.contains_key(room_hash) {
                if let Some(bytes) = self.storage.load_ratchet_state(room_hash)? {
                    match RatchetState::from_bytes(bytes) {
                        Ok(mut state) => {
                            state.retire_sessions(retired);
                            states.insert(room_hash.to_string(), state);
                        }
                        Err(e) => {
                            warn!("Ignoring unreadable ratchet state: {:#}", e);
                        }
                    }
                }
            }
        }

        // M-8: загруженная в RAM сессия должна остаться адресуемой.
        // Fail-closed: не удаляем диск, если не смогли прочитать состояние
        // или обновить маршрутизацию.
        let aliases = {
            let states = self
                .ratchets
                .lock()
                .map_err(|_| anyhow!("ratchet lock poisoned"))?;
            states
                .get(room_hash)
                .map(|state| state.session_aliases().unwrap_or_default())
        };
        if let Some(aliases) = aliases {
            let mut router = self
                .inbound_router
                .lock()
                .map_err(|_| anyhow!("routing lock poisoned"))?;
            router.register_state(room_hash, &aliases);
        }

        // H-3: вместе с ключами с диска уходят и tombstone-и сессий.
        if let Err(e) = self.storage.delete_retired_ratchet_sessions(room_hash) {
            warn!("Failed to delete retired ratchet sessions: {:#}", e);
        }

        self.storage.delete_ratchet_state(room_hash)
    }

    /// Возвращает активный RAM-TTL комнаты. `None`, если таймер выключен.
    pub fn get_room_ttl(&self, room_hash: &str) -> Option<RoomTtl> {
        // Простое RAM-состояние: после poison читаем inner, чтобы не
        // принять активный TTL за выключенный и не записать ratchet (H-3).
        self.room_ttls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(room_hash)
            .copied()
            .filter(|ttl| ttl.seconds.is_some())
    }

    /// Устанавливает односторонний RAM-TTL комнаты (только локально).
    pub fn set_room_ttl(&self, room_hash: &str, seconds: Option<u64>) -> Result<()> {
        // TTL-кэш — простое RAM-состояние: после poison продолжаем с inner.
        let mut ttls = self
            .room_ttls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match seconds {
            Some(value) => {
                ttls.insert(
                    room_hash.to_string(),
                    RoomTtl {
                        seconds: Some(value),
                        synced: false,
                    },
                );
            }
            None => {
                ttls.remove(room_hash);
            }
        }
        drop(ttls);

        match seconds {
            // Включение TTL: текущая сессия переносится в RAM, а её копия
            // удаляется с диска. Сбрасывать храповик не нужно.
            Some(_) => self.enter_ram_ttl(room_hash),
            // Выключение TTL: состояние затирается, следующая сессия
            // начнётся заново.
            None => self.clear_ratchet(room_hash),
        }
    }

    /// Устанавливает двусторонний RAM-TTL и отправляет `SetTtl` собеседнику.
    ///
    /// При включении TTL флаг выставляется до шифрования: иначе `SetTtl`
    /// создаст/сдвинет храповик, и тот попадёт в `vault.dat` (H-3).
    /// Ошибка отправки не откатывает TTL — снапшот с ratchet всё равно не
    /// записывается, а ошибка возвращается вызывающему.
    pub async fn set_synced_ttl(&self, room_hash: &str, seconds: Option<u64>) -> Result<()> {
        let payload = crypto::encode_set_ttl(seconds);

        if seconds.is_some() {
            // Сначала переносим сессию в RAM и только затем включаем TTL,
            // чтобы `encrypt_with_ratchet` не писал ratchet на диск.
            self.enter_ram_ttl(room_hash)?;
            {
                let mut ttls = self
                    .room_ttls
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                ttls.insert(
                    room_hash.to_string(),
                    RoomTtl {
                        seconds,
                        synced: true,
                    },
                );
            }

            let packet = self.encrypt_with_ratchet(room_hash, &payload)?;
            if let Err(e) = self
                .sender
                .send_message(room_hash, &packet, &self.signing_key)
                .await
            {
                // TTL намеренно не откатываем: сессия уже переключена в RAM,
                // а на диске ratchet-состояния быть не должно (H-3).
                return Err(anyhow!("failed to send TTL update: {}", e));
            }
        } else {
            // Выключение TTL: пакет шифруется в текущей RAM-сессии, затем
            // режим снимается; при ошибке отправки возвращаем прежний TTL.
            let packet = self.encrypt_with_ratchet(room_hash, &payload)?;

            let previous = {
                let mut ttls = self
                    .room_ttls
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let previous = ttls.get(room_hash).copied();
                ttls.remove(room_hash);
                previous
            };

            if let Err(e) = self
                .sender
                .send_message(room_hash, &packet, &self.signing_key)
                .await
            {
                if let Some(value) = previous {
                    self.room_ttls
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(room_hash.to_string(), value);
                }
                return Err(anyhow!("failed to send TTL update: {}", e));
            }
        }

        // Обе стороны начинают храповик заново после смены TTL-режима.
        self.clear_ratchet(room_hash)
    }

    /// Сохраняет исходящее сообщение, делая его эфемерным при активном TTL.
    pub fn store_outgoing_message(&self, room_hash: &str, text: &str) -> Result<()> {
        let expires_at = self
            .get_room_ttl(room_hash)
            .and_then(|ttl| ttl.seconds)
            .map(|seconds| now_timestamp().saturating_add(seconds));

        self.storage.save_message_with_room_meta(
            room_hash,
            "out",
            room_hash,
            text,
            expires_at.is_some(),
            expires_at,
        )
    }

    /// Удаляет из RAM сообщения с истёкшим `expires_at`.
    pub fn purge_expired_messages(&self) -> Result<usize> {
        self.purge_expired_messages_at(now_timestamp())
    }

    /// То же, что [`Self::purge_expired_messages`], но с явным временем
    /// (удобно для детерминированных тестов).
    pub fn purge_expired_messages_at(&self, now: u64) -> Result<usize> {
        Ok(self.storage.purge_expired_messages(now)?.len())
    }

    pub async fn send_file_native(
        &self,
        room_hash: &str,
        file_path: &str,
        force: bool,
    ) -> Result<()> {
        use std::io::Read;

        let lang = self.get_config().lang;
        let texts = lang.texts();

        // Путь читается из PWD (или абсолютный/~/), а не из каталога данных.
        let path = resolve_upload_path(file_path, force, lang)?;
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("{}", texts.invalid_file_path))?;

        // Emit upload started event
        self.emit_event(AppEvent::UploadStarted {
            file_name: file_name.to_string(),
        });

        // Open file
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(anyhow!(
                    "{}",
                    tr(texts.permission_denied, &[&path.display().to_string()])
                ));
            }
            Err(e) => {
                return Err(anyhow!(
                    "{}",
                    tr(
                        texts.open_file_failed,
                        &[&path.display().to_string(), &e.to_string()]
                    )
                ));
            }
        };
        let mut file_data = Vec::new();
        file.read_to_end(&mut file_data)
            .map_err(|e| anyhow!("failed to read file: {}", e))?;

        let file_size = file_data.len() as i64;

        // Emit progress event
        self.emit_event(AppEvent::UploadProgress {
            status: texts.upload_encrypting.to_string(),
            progress: 30,
        });

        // Get shared secret
        let shared_secret = self.get_shared_secret(room_hash)?;

        // Encrypt file in the v3 envelope: name and real size are inside
        // AEAD, and AAD binds file_id/room/sender/recipient.
        let encrypted_data = crypto::encrypt_file_v3(
            &file_data,
            file_name,
            &shared_secret,
            room_hash,
            &self.identity.hash,
            room_hash,
        )?;

        // Emit progress event
        self.emit_event(AppEvent::UploadProgress {
            status: texts.upload_sending.to_string(),
            progress: 60,
        });

        // Upload file
        let file_hash = match self.sender.upload_file(&encrypted_data).await {
            Ok(hash) => hash,
            Err(e) => {
                self.emit_event(AppEvent::UploadError {
                    error: e.to_string(),
                });
                return Err(anyhow!("upload failed: {}", e));
            }
        };

        // Save file record (TTL-комнаты не пишут метаданные на диск, H-3).
        let is_ephemeral = self.get_room_ttl(room_hash).is_some();
        self.storage.save_file_record(
            &file_hash,
            room_hash,
            file_name,
            file_size,
            is_ephemeral,
        )?;

        // Emit progress event
        self.emit_event(AppEvent::UploadProgress {
            status: texts.upload_finished.to_string(),
            progress: 100,
        });

        // Emit upload completed event
        self.emit_event(AppEvent::UploadCompleted {
            file_name: file_name.to_string(),
            file_hash: file_hash.clone(),
            file_size: Some(file_size),
        });

        // Send file notification message
        let message_text = texts
            .file_notification
            .replacen("{}", file_name, 1)
            .replacen("{}", &humanize_bytes(file_size as u64), 1)
            .replacen("{}", &file_hash, 1);

        self.send_message(room_hash, &message_text).await?;

        Ok(())
    }

    pub async fn download_and_save_file(
        &self,
        room_hash: &str,
        file_hash: &str,
        save_path: &str,
    ) -> Result<()> {
        // Хеш приходит из сообщения/UI и уходит в URL: валидируем до сети.
        let bare_hash = file_hash.strip_prefix("sha256:").unwrap_or(file_hash);
        FileHash::from_hex(bare_hash).map_err(|e| {
            anyhow!(
                "invalid file hash ({}…): {}",
                truncate_display(file_hash, 16),
                e
            )
        })?;

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

        // Decrypt file. AAD canonicalises the identity pair, so the same
        // call works for sent and received files in this room.
        let file = match crypto::decrypt_file_v3(
            &encrypted_data,
            &shared_secret,
            room_hash,
            &self.identity.hash,
            room_hash,
        ) {
            Ok(file) => file,
            Err(e) => {
                self.emit_event(AppEvent::DownloadError {
                    error: e.to_string(),
                });
                return Err(anyhow!("decryption failed: {}", e));
            }
        };
        let file_data = file.data;

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
        if let Err(e) = write_file_atomically(std::path::Path::new(save_path), &file_data) {
            self.emit_event(AppEvent::DownloadError {
                error: e.to_string(),
            });
            return Err(anyhow!("save failed: {}", e));
        }

        // Emit download completed event
        self.emit_event(AppEvent::DownloadCompleted {
            file_path: save_path.to_string(),
        });

        Ok(())
    }

    fn get_shared_secret(&self, room_hash: &str) -> Result<[u8; 32]> {
        {
            // Ключевой кэш — fail-closed: poison означает неизвестное
            // состояние, операция не продолжается с частичной картой.
            let secrets = self
                .shared_secrets
                .lock()
                .map_err(|_| anyhow!("shared secret lock poisoned"))?;
            if let Some(secret) = secrets.get(room_hash) {
                return Ok(*secret);
            }
        }

        // Check if self
        if room_hash == self.identity.hash {
            let secret =
                crypto::generate_shared_key(self.identity.private_key.expose(), &self.identity.public_key)?;

            let mut secrets = self
                .shared_secrets
                .lock()
                .map_err(|_| anyhow!("shared secret lock poisoned"))?;
            secrets.insert(room_hash.to_string(), secret);
            return Ok(secret);
        }

        // Load from storage
        let contact = self.storage.get_contact(room_hash)?;
        let secret = crypto::generate_shared_key(
            self.identity.private_key.expose(),
            &contact.public_key,
        )?;

        let mut secrets = self
            .shared_secrets
            .lock()
            .map_err(|_| anyhow!("shared secret lock poisoned"))?;
        secrets.insert(room_hash.to_string(), secret);

        Ok(secret)
    }

    pub fn get_messages(&self, room_hash: &str, limit: i64) -> Result<Vec<Message>> {
        let mut messages = self.storage.get_room_messages(room_hash, limit)?;
        messages.reverse(); // Return in chronological order
        Ok(messages)
    }

    pub fn switch_room(&self, room_hash: &str) {
        // Курсор комнаты — простое UI-состояние: poison безопасен,
        // продолжаем с inner.
        let mut current = self
            .current_room_hash
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *current = room_hash.to_string();
    }

    pub fn get_current_room(&self) -> String {
        self.current_room_hash
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn handle_scheme_url(&self, raw_url: &str) {
        info!("Scheme URL received: {}", raw_url);

        match IdentityInvite::from_link(raw_url) {
            Ok(invite) => self.emit_event(AppEvent::ContactImport { invite }),
            Err(e) => {
                warn!("Rejected invite link: {:#}", e);
                self.emit_event(AppEvent::ContactImportError {
                    error: format!("{:#}", e),
                });
            }
        }
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
            .map_err(|_| anyhow!("{}", config.lang.texts().config_lock_failed))?;
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
        let appname = notification_appname(&config);
        match config.notification_content(sender, text, unread) {
            Some((title, body)) => show_system_notification(&appname, &title, &body),
            None => Ok(()),
        }
    }

    /// Отправляет тестовое уведомление с текущими настройками (`/set test`).
    pub fn send_test_notification(&self) -> Result<()> {
        let config = self.get_config();
        let texts = config.lang.texts();
        let (title, body) = config
            .notification_content("LastChance", texts.notify_test_body, 1)
            .ok_or_else(|| anyhow!("{}", texts.notify_disabled))?;

        show_system_notification(&notification_appname(&config), &title, &body)
    }

    pub fn get_safe_fs(&self) -> &Arc<SafeFSOps> {
        &self.safe_fs
    }
}

/// Имя приложения в шапке системного баннера.
///
/// В stealth-режиме (level 1) не раскрываем название мессенджера:
/// берём `stealth_title`, а если он пуст — нейтральное `System Health`.
fn notification_appname(config: &Config) -> String {
    if config.notify_level == 1 {
        let title = config.stealth_title.trim();
        if title.is_empty() {
            "System Health".to_string()
        } else {
            title.to_string()
        }
    } else {
        "LastChance".to_string()
    }
}

fn show_system_notification(appname: &str, title: &str, body: &str) -> Result<()> {
    notify_rust::Notification::new()
        .appname(appname)
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
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};

    fn setup_test_app() -> (App, tempfile::TempDir, mpsc::UnboundedReceiver<AppEvent>) {
        setup_test_app_with_config(Config::default())
    }

    fn setup_test_app_with_config(
        config: Config,
    ) -> (App, tempfile::TempDir, mpsc::UnboundedReceiver<AppEvent>) {
        let temp_dir = tempdir().unwrap();
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let vault = Vault::create(&base_dir, "test-password").unwrap();
        let app = App::new(config, base_dir, vault, event_sender).unwrap();
        (app, temp_dir, event_receiver)
    }

    /// Минимальный HTTP-stub для проверки успешной/неуспешной отправки
    /// без реальной сети.
    async fn spawn_http_stub(status: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let mut data = Vec::new();
            let header_end = loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break data.len();
                }
                data.extend_from_slice(&buf[..n]);
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };

            let headers = String::from_utf8_lossy(&data[..header_end]).to_ascii_lowercase();
            let content_length = headers
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let mut remaining = content_length.saturating_sub(data.len().saturating_sub(header_end));
            while remaining > 0 {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                remaining = remaining.saturating_sub(n);
            }

            let response =
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        format!("http://{addr}")
    }

    fn test_invite_variant(seed: u8, x_seed: u8, nickname: &str) -> IdentityInvite {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let x_secret = X25519Secret::from([x_seed; 32]);
        let x_public = X25519PublicKey::from(&x_secret);
        let doc = IdentityDoc::from_slices(
            signing_key.verifying_key().as_bytes(),
            x_public.as_bytes(),
            Some(nickname.to_string()),
            u64::from(seed),
        )
        .unwrap();
        IdentityInvite::sign(doc, &signing_key).unwrap()
    }

    fn test_invite(seed: u8, nickname: &str) -> IdentityInvite {
        test_invite_variant(seed, seed.wrapping_add(1), nickname)
    }

    #[test]
    fn test_add_contact() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        let invite = test_invite(1, "Test User");
        let hash = invite.hash_hex();
        let nickname = invite.display_nickname();

        app.add_contact_with_ed25519(&invite).unwrap();

        let contacts = app.get_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].hash, hash);
        assert_eq!(contacts[0].nickname, nickname);
        assert_eq!(contacts[0].tofu_state, TOFU_PENDING);
        assert_eq!(
            contacts[0].fingerprint.as_deref(),
            Some(invite.fingerprint_hex().as_str())
        );
    }

    #[test]
    fn tofu_marks_changed_x25519_and_can_be_verified() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        let first = test_invite_variant(20, 21, "Alice");
        let hash = first.hash_hex();
        let outcome = app.add_contact_with_ed25519(&first).unwrap();
        assert_eq!(outcome.tofu_state, TOFU_PENDING);
        assert!(!outcome.x25519_changed);

        // Тот же Ed25519-ключ подписал новый X25519-ключ: это не MITM,
        // но контакт обязан показать смену ключа до ручной сверки.
        let rotated = test_invite_variant(20, 22, "Alice");
        assert_eq!(rotated.hash_hex(), hash);
        let outcome = app.add_contact_with_ed25519(&rotated).unwrap();
        assert!(outcome.x25519_changed);
        assert_eq!(outcome.tofu_state, TOFU_CHANGED);
        assert_eq!(app.get_contacts().unwrap()[0].tofu_state, TOFU_CHANGED);

        app.verify_contact_fingerprint(&hash).unwrap();
        assert_eq!(app.get_contacts().unwrap()[0].tofu_state, TOFU_VERIFIED);
    }

    #[test]
    fn test_notification_appname_hides_messenger_in_stealth_mode() {
        let mut config = Config {
            notify_level: 1,
            stealth_title: "Перерыв для глаз".to_string(),
            ..Config::default()
        };
        assert_eq!(notification_appname(&config), "Перерыв для глаз");

        config.stealth_title = "  ".to_string();
        assert_eq!(notification_appname(&config), "System Health");

        config.notify_level = 2;
        config.stealth_title = "Перерыв".to_string();
        assert_eq!(notification_appname(&config), "LastChance");
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

        let link = app.get_my_contact_link().unwrap();
        assert!(link.starts_with("lastchance://contact?"));
        assert!(link.contains("hash="));
        assert!(link.contains("doc="));
        assert!(link.contains("sig="));
        assert!(link.contains("x25519="));
        assert!(link.contains("ed25519="));
        assert!(link.contains("nickname="));

        let parsed = IdentityInvite::from_link(&link).unwrap();
        assert_eq!(parsed.hash_hex(), app.identity.hash);
        assert_eq!(parsed.doc.x25519_pub.to_vec(), app.identity.public_key);
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

        let invite = test_invite(2, "Alice");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();
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

    #[test]
    fn ratchet_state_is_persisted_only_without_ram_ttl() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        let invite = test_invite(3, "RatchetPeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();

        // Обычная комната: состояние храповика попадает в vault.dat.
        app.encrypt_with_ratchet(&hash, b"persistent-ratchet")
            .unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_some());

        // Включаем RAM-TTL: старое состояние удаляется с диска, новые
        // сообщения обновляют только память.
        app.set_room_ttl(&hash, Some(30)).unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_none());

        app.encrypt_with_ratchet(&hash, b"ram-only-ratchet")
            .unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_none());

        // Выключение TTL затирает RAM-состояние и не восстанавливает диск.
        app.set_room_ttl(&hash, None).unwrap();
        assert!(!app
            .ratchets
            .lock()
            .map(|states| states.contains_key(&hash))
            .unwrap_or(true));
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_none());
    }

    #[test]
    fn ttl_messages_stay_in_ram_and_expire() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        let invite = test_invite(4, "TtlPeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();

        // Включаем односторонний TTL и сохраняем исходящее сообщение.
        app.set_room_ttl(&hash, Some(30)).unwrap();
        let ttl = app.get_room_ttl(&hash).expect("ttl must be enabled");
        assert_eq!(ttl.seconds, Some(30));
        assert!(!ttl.synced);

        app.store_outgoing_message(&hash, "ephemeral secret")
            .unwrap();

        let messages = app.get_messages(&hash, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].is_ephemeral);
        assert!(messages[0].expires_at.is_some());

        // Эфемерного сообщения нет в зашифрованном снимке на диске.
        let persisted = app
            .get_storage()
            .persisted_messages_for_test()
            .unwrap();
        assert!(persisted
            .iter()
            .all(|message| message.text != "ephemeral secret"));

        // /ttl off: следующее сообщение снова сохраняется в vault.dat.
        app.set_room_ttl(&hash, None).unwrap();
        assert!(app.get_room_ttl(&hash).is_none());
        app.store_outgoing_message(&hash, "persistent secret")
            .unwrap();

        let persisted = app
            .get_storage()
            .persisted_messages_for_test()
            .unwrap();
        assert!(persisted
            .iter()
            .any(|message| message.text == "persistent secret"));
        assert!(persisted
            .iter()
            .all(|message| message.text != "ephemeral secret"));

        // Истёкшее эфемерное сообщение удаляется из памяти.
        let expires_at = messages[0].expires_at.expect("ephemeral must expire");
        let removed = app
            .purge_expired_messages_at(expires_at + 1)
            .unwrap();
        assert_eq!(removed, 1);

        let remaining = app.get_messages(&hash, 10).unwrap();
        assert!(remaining
            .iter()
            .all(|message| message.text != "ephemeral secret"));
        assert!(remaining
            .iter()
            .any(|message| message.text == "persistent secret"));
    }

    #[tokio::test]
    async fn synced_ttl_send_failure_keeps_ttl_and_no_ratchet_on_disk() {
        // H-3: неудачная отправка не должна оставлять ratchet в vault.dat
        // и не должна молча откатывать уже включённый TTL.
        let server = spawn_http_stub("400 Bad Request").await;
        let config = Config {
            server_url: server,
            ..Config::default()
        };
        let (app, _temp_dir, _receiver) = setup_test_app_with_config(config);

        let invite = test_invite(5, "SyncPeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();

        // Обычная комната: ratchet уже записан на диск.
        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_some());

        let result = app.set_synced_ttl(&hash, Some(30)).await;
        assert!(result.is_err(), "send failure must surface");

        assert_eq!(
            app.get_room_ttl(&hash).and_then(|ttl| ttl.seconds),
            Some(30),
            "TTL must not be silently rolled back"
        );
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn synced_ttl_removes_previously_persisted_ratchet() {
        let server = spawn_http_stub("200 OK").await;
        let config = Config {
            server_url: server,
            ..Config::default()
        };
        let (app, _temp_dir, _receiver) = setup_test_app_with_config(config);

        let invite = test_invite(6, "SyncPeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();

        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_some());

        app.set_synced_ttl(&hash, Some(30)).await.unwrap();

        assert_eq!(
            app.get_room_ttl(&hash).and_then(|ttl| ttl.seconds),
            Some(30)
        );
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn incoming_set_ttl_does_not_persist_ratchet_before_processing() {
        // H-3: расшифровка SetTtl не должна писать ratchet до того, как
        // станет известно, включает ли пакет TTL.
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let packet = app
            .encrypt_with_ratchet(&hash, &crypto::encode_set_ttl(Some(60)))
            .unwrap();

        // Стираем предыдущий снимок, чтобы отличить новую запись от старой.
        app.get_storage().delete_ratchet_state(&hash).unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_none());

        let shared_secret = app.get_shared_secret(&hash).unwrap();
        let decrypted = try_ratchet_decrypt(
            &packet,
            &hash,
            &shared_secret,
            &app.identity.hash,
            &app.storage,
            &app.ratchets,
            &app.retired_ratchet_sessions,
            false,
        )
        .expect("self-chat packet must decrypt");

        assert_eq!(
            crypto::decode_payload(&decrypted.plaintext).unwrap(),
            crypto::E2ePayload::SetTtl { seconds: Some(60) }
        );
        assert!(decrypted.serialized.is_some());
        assert!(
            app.get_storage()
                .persisted_ratchet_state_for_test(&hash)
                .unwrap()
                .is_none(),
            "decryption must not persist ratchet before payload handling"
        );
    }

    #[tokio::test]
    async fn incoming_set_ttl_leaves_no_ratchet_on_disk() {
        let (app, _temp_dir, mut receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let packet = app
            .encrypt_with_ratchet(&hash, &crypto::encode_set_ttl(Some(60)))
            .unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_some());

        App::handle_incoming_packet(
            packet,
            &app.shared_secrets,
            &app.storage,
            &app.room_ttls,
            &app.ratchets,
            &app.retired_ratchet_sessions,
            &app.inbound_router,
            &app.identity.hash,
            &app.event_sender,
        )
        .await;

        assert_eq!(
            app.get_room_ttl(&hash).and_then(|ttl| ttl.seconds),
            Some(60)
        );
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_none());
        assert!(matches!(
            receiver.try_recv(),
            Ok(AppEvent::TtlChanged { seconds: Some(60), .. })
        ));
    }

    #[tokio::test]
    async fn bootstrap_packet_from_cleared_ratchet_is_rejected() {
        // H-1: после reset старая bootstrap-сессия не должна приниматься
        // даже как «незнакомая»: приложение помнит её session_id.
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        let bootstrap = app.encrypt_with_ratchet(&hash, b"old-bootstrap").unwrap();
        let old_session = app
            .ratchets
            .lock()
            .unwrap()
            .get(&hash)
            .unwrap()
            .session_id();
        let shared_secret = app.get_shared_secret(&hash).unwrap();

        app.clear_ratchet(&hash).unwrap();

        // Новая сессия получает свежий session_id и принимается.
        let fresh = app.encrypt_with_ratchet(&hash, b"fresh").unwrap();
        let fresh_session = app
            .ratchets
            .lock()
            .unwrap()
            .get(&hash)
            .unwrap()
            .session_id();
        assert_ne!(fresh_session, old_session);
        let decrypted = try_ratchet_decrypt(
            &fresh,
            &hash,
            &shared_secret,
            &app.identity.hash,
            &app.storage,
            &app.ratchets,
            &app.retired_ratchet_sessions,
            false,
        )
        .expect("new bootstrap packet must decrypt");
        assert_eq!(decrypted.plaintext, b"fresh");

        // Старый bootstrap-пакет отклоняется как StaleSession.
        assert!(
            try_ratchet_decrypt(
                &bootstrap,
                &hash,
                &shared_secret,
                &app.identity.hash,
                &app.storage,
                &app.ratchets,
                &app.retired_ratchet_sessions,
                false,
            )
            .is_none(),
            "bootstrap packet from a cleared ratchet must not decrypt"
        );
    }

    #[test]
    fn retired_session_survives_restart_and_blocks_replay() {
        // H-2: после reset tombstone должен попасть в vault.dat, иначе
        // перезапуск снова принимает старый bootstrap-пакет как новый.
        let temp_dir = tempdir().unwrap();
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        let (event_sender, _receiver) = mpsc::unbounded_channel();
        let vault = Vault::create(&base_dir, "test-password").unwrap();
        let app = App::new(
            Config::default(),
            base_dir.clone(),
            vault,
            event_sender,
        )
        .unwrap();

        let invite = test_invite(7, "ReplayPeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();

        let bootstrap = app.encrypt_with_ratchet(&hash, b"old-bootstrap").unwrap();
        let old_session = app
            .ratchets
            .lock()
            .unwrap()
            .get(&hash)
            .unwrap()
            .session_id();
        let shared_secret = app.get_shared_secret(&hash).unwrap();

        app.clear_ratchet(&hash).unwrap();
        drop(app);

        let vault = Vault::unlock(&base_dir, "test-password").unwrap();
        let (event_sender, _receiver) = mpsc::unbounded_channel();
        let reopened = App::new(Config::default(), base_dir, vault, event_sender).unwrap();

        assert!(
            reopened
                .retired_ratchet_sessions
                .lock()
                .unwrap()
                .get(&hash)
                .is_some_and(|ids| ids.contains(&old_session)),
            "retired session id must be restored from vault.dat"
        );
        assert!(
            try_ratchet_decrypt(
                &bootstrap,
                &hash,
                &shared_secret,
                &reopened.identity.hash,
                &reopened.storage,
                &reopened.ratchets,
                &reopened.retired_ratchet_sessions,
                false,
            )
            .is_none(),
            "replayed bootstrap packet must stay rejected after restart"
        );
    }

    #[tokio::test]
    async fn incoming_ratchet_reset_persists_retired_session() {
        // H-2: reset от собеседника проходит через clear_ratchet_state и
        // тоже должен оставить tombstone в vault.dat.
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        let _bootstrap = app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let old_session = app
            .ratchets
            .lock()
            .unwrap()
            .get(&hash)
            .unwrap()
            .session_id();
        let reset = app
            .encrypt_with_ratchet(&hash, &crypto::encode_ratchet_reset())
            .unwrap();

        App::handle_incoming_packet(
            reset,
            &app.shared_secrets,
            &app.storage,
            &app.room_ttls,
            &app.ratchets,
            &app.retired_ratchet_sessions,
            &app.inbound_router,
            &app.identity.hash,
            &app.event_sender,
        )
        .await;

        let persisted = app
            .get_storage()
            .load_retired_ratchet_sessions()
            .unwrap();
        assert!(persisted
            .iter()
            .any(|(room_hash, session_id)| room_hash == &hash && session_id == &old_session));
    }

    #[test]
    fn ttl_room_does_not_persist_retired_sessions() {
        // H-3: включение RAM-TTL убирает с диска не только ключи, но и
        // tombstone-и сессий.
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        app.set_room_ttl(&hash, Some(30)).unwrap();
        app.encrypt_with_ratchet(&hash, b"ttl-only").unwrap();
        app.clear_ratchet(&hash).unwrap();

        let persisted = app
            .get_storage()
            .load_retired_ratchet_sessions()
            .unwrap();
        assert!(persisted.iter().all(|(room_hash, _)| room_hash != &hash));
    }

    #[tokio::test]
    async fn invalid_file_hash_message_is_rejected_before_db_write() {
        let (app, _temp_dir, mut receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        // Инициализируем ratchet-сессию, чтобы пакет прошёл расшифровку.
        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let text = "📎 File: evil.bin\nHash: not-a-valid-hex-hash";
        let packet = app
            .encrypt_with_ratchet(&hash, &crypto::encode_text_payload(text, None))
            .unwrap();

        App::handle_incoming_packet(
            packet,
            &app.shared_secrets,
            &app.storage,
            &app.room_ttls,
            &app.ratchets,
            &app.retired_ratchet_sessions,
            &app.inbound_router,
            &app.identity.hash,
            &app.event_sender,
        )
        .await;

        assert!(
            app.get_messages(&hash, 10).unwrap().is_empty(),
            "invalid file hash must not reach the message table"
        );
        assert!(
            receiver.try_recv().is_err(),
            "rejected packet must not be announced to the UI"
        );
    }

    // -----------------------------------------------------------------
    // M-8: адресация входящих по alias, без перебора контактов.
    // -----------------------------------------------------------------

    async fn deliver_packet(app: &App, packet: Vec<u8>) {
        App::handle_incoming_packet(
            packet,
            &app.shared_secrets,
            &app.storage,
            &app.room_ttls,
            &app.ratchets,
            &app.retired_ratchet_sessions,
            &app.inbound_router,
            &app.identity.hash,
            &app.event_sender,
        )
        .await;
    }

    /// Self-chat проверяет маршрутизацию без второго клиента (`SelfChat`
    /// умеет открывать собственные пакеты). Контактная запись нужна только
    /// ради FK `messages.room_hash -> contacts.hash`.
    fn setup_router_room() -> (
        App,
        tempfile::TempDir,
        mpsc::UnboundedReceiver<AppEvent>,
        String,
    ) {
        let (app, temp_dir, receiver) = setup_test_app();
        let hash = app.identity.hash.clone();
        app.get_storage()
            .add_contact(&hash, &app.identity.public_key, "Self")
            .unwrap();
        (app, temp_dir, receiver, hash)
    }

    #[tokio::test]
    async fn known_alias_delivers_with_exactly_one_decrypt() {
        let (app, _temp_dir, _receiver, hash) = setup_router_room();

        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let packet = app
            .encrypt_with_ratchet(&hash, &crypto::encode_text_payload("routed", None))
            .unwrap();

        deliver_packet(&app, packet).await;

        let messages = app.get_messages(&hash, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "routed");

        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.lookups, 1, "exactly one alias lookup per packet");
        assert_eq!(stats.decrypt_attempts, 1, "exactly one AEAD attempt");
        assert_eq!(stats.unknown_rooms, 0);
    }

    #[tokio::test]
    async fn unknown_alias_is_dropped_before_any_decrypt() {
        let (app, _temp_dir, _receiver, hash) = setup_router_room();

        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let mut packet = app
            .encrypt_with_ratchet(&hash, &crypto::encode_text_payload("nobody", None))
            .unwrap();

        // Alias не принадлежит ни одной комнате и пакет не bootstrap:
        // маршрутизатор не должен запускать AEAD ни для одного контакта.
        packet[2] ^= 0xff;
        packet[1] &= !ratchet::FLAG_BOOTSTRAP;

        deliver_packet(&app, packet).await;

        assert!(app.get_messages(&hash, 10).unwrap().is_empty());
        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.decrypt_attempts, 0);
        assert_eq!(stats.unknown_rooms, 1);
    }

    #[tokio::test]
    async fn retired_alias_is_stale_and_creates_no_session() {
        let (app, _temp_dir, _receiver, hash) = setup_router_room();

        let packet = app.encrypt_with_ratchet(&hash, b"stale").unwrap();
        app.clear_ratchet(&hash).unwrap();
        assert!(
            app.ratchets.lock().unwrap().get(&hash).is_none(),
            "reset must drop the live session"
        );

        deliver_packet(&app, packet).await;

        assert!(app.get_messages(&hash, 10).unwrap().is_empty());
        assert!(
            app.ratchets.lock().unwrap().get(&hash).is_none(),
            "stale packet must not create a new session"
        );
        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.stale_sessions, 1);
        assert_eq!(stats.decrypt_attempts, 0);
    }

    #[tokio::test]
    async fn old_alias_is_rejected_after_reset_and_new_session_works() {
        let (app, _temp_dir, _receiver, hash) = setup_router_room();

        let old = app
            .encrypt_with_ratchet(&hash, &crypto::encode_text_payload("old", None))
            .unwrap();
        app.clear_ratchet(&hash).unwrap();
        let fresh = app
            .encrypt_with_ratchet(&hash, &crypto::encode_text_payload("fresh", None))
            .unwrap();

        deliver_packet(&app, old).await;
        assert!(app.get_messages(&hash, 10).unwrap().is_empty());

        deliver_packet(&app, fresh).await;
        let messages = app.get_messages(&hash, 10).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].text, "fresh");
    }

    #[tokio::test]
    async fn duplicate_delivery_is_stored_once() {
        let (app, _temp_dir, _receiver, hash) = setup_router_room();

        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let packet = app
            .encrypt_with_ratchet(&hash, &crypto::encode_text_payload("once", None))
            .unwrap();

        deliver_packet(&app, packet.clone()).await;
        deliver_packet(&app, packet).await;

        let messages = app.get_messages(&hash, 10).unwrap();
        assert_eq!(messages.len(), 1, "replayed packet must be dropped");
        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.replayed_packets, 1);
        assert_eq!(stats.decrypt_attempts, 1);
    }

    #[tokio::test]
    async fn v2_packet_is_rejected_before_alias_lookup() {
        let (app, _temp_dir, _receiver, hash) = setup_router_room();

        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let mut packet = app
            .encrypt_with_ratchet(&hash, &crypto::encode_text_payload("v2", None))
            .unwrap();
        packet[0] = 2;

        deliver_packet(&app, packet).await;

        assert!(app.get_messages(&hash, 10).unwrap().is_empty());
        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.lookups, 0);
        assert_eq!(stats.decrypt_attempts, 0);
    }

    #[tokio::test]
    async fn oversized_packet_is_rejected_before_decrypt() {
        let (app, _temp_dir, _receiver, hash) = setup_router_room();

        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let mut packet = vec![0u8; crate::crypto::SIZE_MAX + crate::crypto::SIZE_MAX / 8 + 1];
        packet[0] = ratchet::PROTOCOL_VERSION;

        deliver_packet(&app, packet).await;

        assert!(app.get_messages(&hash, 10).unwrap().is_empty());
        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.decrypt_attempts, 0);
    }

    #[test]
    fn atomic_file_write_leaves_no_partial_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("download.bin");
        write_file_atomically(&path, b"payload").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"payload");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".part-"))
            .collect();
        assert!(leftovers.is_empty(), "temporary file must be renamed/removed");
    }

    /// Отравитель мьютекса: паника в отдельном потоке оставляет lock
    /// poisoned, не роняя тестовый поток.
    fn poison_mutex<T: Send + 'static>(mutex: &Arc<Mutex<T>>) {
        let cloned = Arc::clone(mutex);
        let _ = std::thread::spawn(move || {
            let _guard = cloned
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("intentional mutex poisoning for test");
        })
        .join();
    }

    #[test]
    fn poisoned_current_room_mutex_recovers() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        poison_mutex(&app.current_room_hash);

        // Курсор комнаты — простое UI-состояние: poison не должен
        // блокировать переключение или чтение.
        app.switch_room("room-after-poison");
        assert_eq!(app.get_current_room(), "room-after-poison");
    }

    #[test]
    fn poisoned_ttl_mutex_recovers() {
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();
        app.set_room_ttl(&hash, Some(30)).unwrap();

        poison_mutex(&app.room_ttls);

        assert_eq!(
            app.get_room_ttl(&hash).and_then(|ttl| ttl.seconds),
            Some(30)
        );
        assert!(room_has_ttl(&app.room_ttls, &hash));

        // Запись после poison тоже восстанавливается на inner-состоянии.
        app.set_room_ttl(&hash, Some(45)).unwrap();
        assert_eq!(
            app.get_room_ttl(&hash).and_then(|ttl| ttl.seconds),
            Some(45)
        );
    }

    #[test]
    fn poisoned_ratchet_encrypt_fails_closed_without_mutation() {
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();
        app.encrypt_with_ratchet(&hash, b"prime").unwrap();

        let before = app
            .ratchets
            .lock()
            .unwrap()
            .get(&hash)
            .unwrap()
            .to_bytes()
            .unwrap()
            .expose()
            .to_vec();

        poison_mutex(&app.ratchets);

        let error = app
            .encrypt_with_ratchet(&hash, b"after-poison")
            .unwrap_err();
        assert!(
            error.to_string().contains("ratchet lock poisoned"),
            "unexpected error: {error}"
        );

        let after = app
            .ratchets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&hash)
            .unwrap()
            .to_bytes()
            .unwrap()
            .expose()
            .to_vec();
        assert_eq!(before, after, "fail-closed path must not advance state");
    }

    #[test]
    fn poisoned_ratchet_clear_keeps_persisted_state() {
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();
        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_some());

        poison_mutex(&app.ratchets);

        let error = app.clear_ratchet(&hash).unwrap_err();
        assert!(
            error.to_string().contains("ratchet lock poisoned"),
            "unexpected error: {error}"
        );
        assert!(
            app.get_storage()
                .persisted_ratchet_state_for_test(&hash)
                .unwrap()
                .is_some(),
            "fail-closed reset must not delete persisted ratchet state"
        );
    }

    #[test]
    fn poisoned_ratchet_incoming_reset_keeps_persisted_state() {
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();
        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_some());

        poison_mutex(&app.ratchets);

        clear_ratchet_state(
            &app.ratchets,
            &app.storage,
            &app.retired_ratchet_sessions,
            &app.inbound_router,
            &app.room_ttls,
            &hash,
        );

        assert!(
            app.get_storage()
                .persisted_ratchet_state_for_test(&hash)
                .unwrap()
                .is_some(),
            "poisoned incoming reset must not delete persisted state"
        );
    }

    #[test]
    fn poisoned_shared_secrets_rejects_key_lookup() {
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        poison_mutex(&app.shared_secrets);

        let error = app.get_shared_secret(&hash).unwrap_err();
        assert!(
            error.to_string().contains("shared secret lock poisoned"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn poisoned_identity_rejects_nickname_update() {
        let (app, _temp_dir, _receiver) = setup_test_app();
        let before = app.get_nickname();

        poison_mutex(&app.identity_manager);

        let error = app.update_nickname("Mallory").unwrap_err();
        assert!(
            error.to_string().contains("identity lock poisoned"),
            "unexpected error: {error}"
        );
        // Read-only fallback не должен мутировать личность.
        assert_eq!(app.get_nickname(), before);
    }

    #[test]
    fn production_code_has_no_lock_unwrap() {
        fn scan(dir: &std::path::Path, violations: &mut Vec<String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    scan(&path, violations);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    let source = std::fs::read_to_string(&path).unwrap();
                    let production = source
                        .split_once("#[cfg(test)]")
                        .map(|(production, _)| production)
                        .unwrap_or(&source);
                    for needle in [".lock().unwrap()", ".lock().expect("] {
                        if production.contains(needle) {
                            violations.push(format!("{}: contains {}", path.display(), needle));
                        }
                    }
                }
            }
        }

        let mut violations = Vec::new();
        scan(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut violations,
        );
        assert!(
            violations.is_empty(),
            "production code must handle poisoned locks explicitly: {violations:#?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn atomic_file_write_failure_removes_temporary_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        // rename(2) не заменит файлом существующий непустой каталог.
        let target = dir.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), b"keep").unwrap();

        assert!(write_file_atomically(&target, b"payload").is_err());

        assert!(target.is_dir());
        assert_eq!(std::fs::read(target.join("keep")).unwrap(), b"keep");

        for entry in std::fs::read_dir(dir.path()).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            assert!(!name.contains(".part-"), "temporary file left: {}", name);
            if entry.path().is_file() {
                let mode = entry.metadata().unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "unexpected mode for {}", name);
            }
        }
    }
}
