// src/app.rs
use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use log::{info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::crypto;
use crate::crypto::ratchet::{self, RatchetState, Role as RatchetRole};
use crate::crypto::secret::{SecretBytes, SharedSecret};
use crate::i18n::tr;
use crate::identity::{
    hash_ed25519_public, Identity, IdentityDoc, IdentityInvite, IdentityManager,
};
use crate::network::{Config, InboundRouter, Route, RoutingError};
use crate::p2p::{
    bind_inbound_listener, outbox_backoff_secs, serve_inbound, P2pSender, TorControlConnection,
};
use crate::storage::{
    Contact, Message, SafeFSOps, Storage, TtlTombstone, TOFU_CHANGED, TOFU_PENDING, TOFU_VERIFIED,
};
use crate::types::{truncate_display, OnionAddress};
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
    /// Состояние подключения к Tor ControlPort и публикации `.onion`-сервиса.
    TorStatusChanged {
        connected: bool,
        onion_addr: Option<String>,
        error: Option<String>,
    },
    /// Изменилось число сообщений, ожидающих отправки в Outbox.
    OutboxUpdated {
        pending: usize,
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
    /// Двусторонний TTL применён локально, но `SetTtl` не доставлен.
    /// Требует явного ретрая ([`App::resync_ttl`]); до подтверждения
    /// TTL не передаётся в метаданных обычных сообщений.
    pub pending_sync: bool,
}

/// Итог двусторонней смены TTL (`/ttl-syn`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtlSyncOutcome {
    /// `SetTtl` доставлен собеседнику.
    Synced,
    /// TTL применён локально, но уведомление не отправлено.
    LocalOnly { error: String },
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

/// M-C: сколько жить tombstone-хешу retired-сессии TTL-комнаты.
///
/// Должно быть не меньше максимального окна, в котором атакующий может
/// влить старый bootstrap-пакет. По истечении запись удаляется, и древний
/// bootstrap снова становится replay-абельным (задокументированный residual).
pub(crate) const TOMBSTONE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// M-C: глобальный предел tombstone-записей.
///
/// При переполнении вытесняются старейшие записи (fail-open для
/// доступности). Это возвращает residual для самых древних сессий, но не
/// блокирует новые ретирации.
pub(crate) const MAX_TTL_TOMBSTONES: usize = 1024;

/// RAM-реестр tombstone-хешей retired-сессий TTL-комнат.
///
/// На диск (в зашифрованный `vault.dat`) попадают только alias сессии и
/// `SHA256(session_id)`. `session_id`, `bootstrap_nonce` и ratchet-состояние
/// в реестре отсутствуют.
#[derive(Default)]
struct TtlTombstoneRegistry {
    /// От старых к новым, чтобы при переполнении вытеснять начало.
    entries: Vec<TtlTombstone>,
    hashes: HashSet<[u8; 32]>,
    aliases: HashSet<[u8; 16]>,
}

impl TtlTombstoneRegistry {
    /// Создаёт реестр из загруженных записей и применяет TTL/лимит.
    ///
    /// Возвращает `true`, если что-то было удалено (тогда вызывающий может
    /// перезаписать vault очищенным набором).
    fn from_entries(entries: Vec<TtlTombstone>, now: u64) -> (Self, bool) {
        let mut registry = Self::default();
        for entry in entries {
            registry.insert(entry);
        }
        let pruned = registry.prune(now);
        (registry, pruned)
    }

    fn insert(&mut self, entry: TtlTombstone) {
        if self.hashes.insert(entry.session_id_hash) {
            self.entries.push(entry);
        }
        self.aliases.insert(entry.session_alias);
    }

    /// Добавляет tombstone-и для уничтоженных `session_id`.
    fn remember(
        &mut self,
        session_ids: impl IntoIterator<Item = [u8; 16]>,
        now: u64,
    ) -> Result<()> {
        for session_id in session_ids {
            let session_alias = ratchet::session_alias(&session_id)?;
            let session_id_hash = ratchet::session_id_hash(&session_id);
            self.insert(TtlTombstone {
                session_alias,
                session_id_hash,
                retired_at: now,
            });
        }
        self.prune(now);
        Ok(())
    }

    /// Удаляет записи старше [`TOMBSTONE_TTL_SECS`] и вытесняет старейшие
    /// сверх [`MAX_TTL_TOMBSTONES`]. Возвращает `true`, если набор изменился.
    fn prune(&mut self, now: u64) -> bool {
        let cutoff = now.saturating_sub(TOMBSTONE_TTL_SECS);
        let before = self.entries.len();
        self.entries.retain(|entry| entry.retired_at >= cutoff);
        let mut changed = self.entries.len() != before;

        if self.entries.len() > MAX_TTL_TOMBSTONES {
            self.entries.sort_by_key(|entry| entry.retired_at);
            let excess = self.entries.len() - MAX_TTL_TOMBSTONES;
            self.entries.drain(..excess);
            changed = true;
        }

        if changed {
            self.rebuild_indexes();
        }
        changed
    }

    fn rebuild_indexes(&mut self) {
        self.hashes = self
            .entries
            .iter()
            .map(|entry| entry.session_id_hash)
            .collect();
        self.aliases = self
            .entries
            .iter()
            .map(|entry| entry.session_alias)
            .collect();
    }

    /// M-C: проверка при приёме bootstrap-пакета до создания новой сессии.
    fn is_retired_session(&self, session_id_hash: &[u8; 32]) -> bool {
        self.hashes.contains(session_id_hash)
    }

    /// Alias retired-сессии также отклоняется до AEAD: после рестарта
    /// не-bootstrap пакет старой TTL-сессии не должен выглядеть как новый.
    fn has_retired_alias(&self, session_alias: &[u8; 16]) -> bool {
        self.aliases.contains(session_alias)
    }

    fn snapshot(&self) -> Vec<TtlTombstone> {
        self.entries.clone()
    }
}

/// Кэш общих секретов комнат.
///
/// Значение — [`SharedSecret`]: затирается при `drop` и не реализует
/// `Clone`, поэтому наружу его можно отдать только по ссылке
/// (см. [`App::with_shared_secret`]) или явным `duplicate()`.
type SharedSecretMap = HashMap<String, SharedSecret>;

pub struct App {
    config: Arc<RwLock<Config>>,
    base_dir: String,

    storage: Arc<Storage>,
    identity_manager: Arc<Mutex<IdentityManager>>,
    pub identity: Identity,

    shared_secrets: Arc<Mutex<SharedSecretMap>>,
    /// Состояния Double Ratchet. Для обычных комнат они сохраняются в
    /// `vault.dat`, для комнат с RAM-TTL остаются только здесь.
    ratchets: Arc<Mutex<HashMap<String, RatchetState>>>,

    /// `session_id` уничтоженных храповиков (reset, выключение TTL).
    /// RAM-кэш; для обычных комнат дублируется в `vault.dat` и
    /// восстанавливается при старте. Запоздавший bootstrap-пакет старой
    /// сессии не должен приниматься как новая сессия (H-1/H-2).
    retired_ratchet_sessions: RetiredRatchetSessions,

    /// M-C: tombstone-хеши retired-сессий TTL-комнат. Отдельный путь от
    /// ratchet-состояния (H-3): на диск попадает только alias и
    /// `SHA256(session_id)`, что восстанавливает анти-replay после рестарта.
    ttl_tombstones: Arc<Mutex<TtlTombstoneRegistry>>,

    /// M-8: адресная таблица `alias -> room` и окно дедупликации доставки.
    /// Строится из ratchet-состояний; входящий пакет выбирает комнату по
    /// alias без перебора контактов.
    inbound_router: Arc<Mutex<InboundRouter>>,

    p2p_sender: Arc<P2pSender>,
    own_onion: Arc<RwLock<Option<OnionAddress>>>,
    tor_connected: Arc<RwLock<bool>>,
    local_p2p_port: Arc<RwLock<Option<u16>>>,
    outbox_notify: Arc<tokio::sync::Notify>,
    tor_reload_notify: Arc<tokio::sync::Notify>,

    #[cfg(test)]
    test_peer_overrides: Arc<Mutex<HashMap<String, std::net::SocketAddr>>>,

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

/// M-C: добавляет tombstone-хеши уничтоженных сессий TTL-комнаты.
fn remember_ttl_tombstones(
    tombstones: &Arc<Mutex<TtlTombstoneRegistry>>,
    session_ids: impl IntoIterator<Item = [u8; 16]>,
) -> Result<()> {
    let mut registry = tombstones
        .lock()
        .map_err(|_| anyhow!("ttl tombstone lock poisoned"))?;
    registry.remember(session_ids, now_timestamp())
}

/// M-C: сохраняет tombstone-хеши в зашифрованный `vault.dat`.
///
/// Ошибка записи не отменяет tombstone в памяти: следующая TTL-ретирация
/// повторит попытку, иначе residual вернулся бы раньше времени.
fn persist_ttl_tombstones(
    storage: &Storage,
    tombstones: &Arc<Mutex<TtlTombstoneRegistry>>,
) -> Result<()> {
    let entries = tombstones
        .lock()
        .map_err(|_| anyhow!("ttl tombstone lock poisoned"))?
        .snapshot();
    storage.save_ttl_tombstones(&entries)
}

/// M-C: проверяет alias retired-сессии TTL-комнаты.
///
/// Вызывается после alias lookup и до AEAD/создания сессии. Poison
/// считается отказом (fail-closed), иначе старый пакет мог бы пройти.
fn ttl_tombstone_has_alias(
    tombstones: &Arc<Mutex<TtlTombstoneRegistry>>,
    alias: &[u8; ratchet::SESSION_ALIAS_SIZE],
) -> Result<bool> {
    let registry = tombstones
        .lock()
        .map_err(|_| anyhow!("ttl tombstone lock poisoned"))?;
    Ok(registry.has_retired_alias(alias))
}

/// M-C: проверяет `SHA256(session_id)` bootstrap-пакета по tombstone-ам.
fn ttl_tombstone_has_hash(
    tombstones: &Arc<Mutex<TtlTombstoneRegistry>>,
    session_id_hash: &[u8; 32],
) -> Result<bool> {
    let registry = tombstones
        .lock()
        .map_err(|_| anyhow!("ttl tombstone lock poisoned"))?;
    Ok(registry.is_retired_session(session_id_hash))
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
) -> (Option<DecryptedRatchet>, usize) {
    let retired = match retired_sessions_for(retired_sessions, room_hash) {
        Ok(retired) => retired,
        Err(_) => {
            warn!(
                "Incoming packet dropped for {}: retired session lock poisoned",
                truncate_display(room_hash, 16)
            );
            return (None, 0);
        }
    };

    let (plaintext, serialized, aliases, aead_attempts) = {
        let mut states = match ratchets.lock() {
            Ok(states) => states,
            Err(_) => {
                warn!(
                    "Incoming packet dropped for {}: ratchet lock poisoned",
                    truncate_display(room_hash, 16)
                );
                return (None, 0);
            }
        };
        if ensure_ratchet_state(
            &mut states,
            room_hash,
            shared_secret,
            identity_hash,
            storage,
            ttl_active,
            &retired,
        )
        .is_err()
        {
            return (None, 0);
        }

        let Some(state) = states.get_mut(room_hash) else {
            return (None, 0);
        };
        let (decrypted, aead_attempts) = state.decrypt_counted(packet, shared_secret);
        match decrypted {
            Ok(plaintext) => {
                let serialized = if ttl_active {
                    None
                } else {
                    state.to_bytes().ok()
                };
                let aliases = state.session_aliases().unwrap_or_default();
                (plaintext, serialized, aliases, aead_attempts)
            }
            Err(error) => {
                if let Some(typed) = error.downcast_ref::<ratchet::RatchetError>() {
                    warn!(
                        "Incoming packet rejected for {}: {}",
                        truncate_display(room_hash, 16),
                        typed
                    );
                }
                return (None, aead_attempts);
            }
        }
    };

    (
        Some(DecryptedRatchet {
            plaintext,
            serialized,
            aliases,
        }),
        aead_attempts,
    )
}

/// Выполняет `f` с общим секретом комнаты, не копируя его из карты.
///
/// `Err` возвращается и при poison, и при отсутствии секрета: оба случая
/// означают, что продолжать криптографию нельзя.
fn with_room_secret<T>(
    room: &str,
    shared_secrets: &Arc<Mutex<SharedSecretMap>>,
    f: impl FnOnce(&SharedSecret) -> T,
) -> Result<T> {
    let secrets = shared_secrets
        .lock()
        .map_err(|_| anyhow!("shared secret lock poisoned"))?;
    let secret = secrets
        .get(room)
        .ok_or_else(|| anyhow!("no shared secret for room {}", truncate_display(room, 16)))?;
    Ok(f(secret))
}

/// Единственный fallback для первого пакета сессии (M-8).
///
/// Bootstrap-пакет несёт `bootstrap_nonce`, но alias новой сессии ещё не
/// известен. Здесь перебираются только HKDF-производные alias по контактам;
/// AEAD не запускается ни для одного несовпавшего контакта. Обычные пакеты
/// этот путь не используют.
///
/// M-C: вместе с комнатой возвращается `SHA256(session_id)`, чтобы
/// проверить tombstone до создания новой сессии. Сам секрет не копируется:
/// он нужен только для HKDF внутри этой функции.
///
/// L-1: второе значение — число выполненных HKDF-вызовов. Счётчик нужен
/// приложению и флуд-тесту, чтобы проверить верхнюю границу работы.
fn resolve_bootstrap_room(
    alias: &[u8; ratchet::SESSION_ALIAS_SIZE],
    nonce: &[u8; ratchet::BOOTSTRAP_NONCE_SIZE],
    shared_secrets: &Arc<Mutex<SharedSecretMap>>,
) -> (Option<(String, [u8; 32])>, usize) {
    let secrets = match shared_secrets.lock() {
        Ok(secrets) => secrets,
        Err(_) => {
            warn!("Incoming packet dropped: shared secret lock poisoned");
            return (None, 0);
        }
    };
    let mut attempts = 0usize;
    for (room, secret) in secrets.iter() {
        attempts = attempts.saturating_add(1);
        if let Ok((candidate_alias, session_id_hash)) =
            ratchet::bootstrap_session_fingerprint(secret.expose(), nonce)
        {
            if &candidate_alias == alias {
                return (Some((room.clone(), session_id_hash)), attempts);
            }
        }
    }
    (None, attempts)
}

#[allow(clippy::too_many_arguments)]
fn clear_ratchet_state(
    ratchets: &Arc<Mutex<HashMap<String, RatchetState>>>,
    storage: &Arc<Storage>,
    retired_sessions: &RetiredRatchetSessions,
    ttl_tombstones: &Arc<Mutex<TtlTombstoneRegistry>>,
    inbound_router: &Arc<Mutex<InboundRouter>>,
    room_ttls: &Arc<Mutex<HashMap<String, RoomTtl>>>,
    room_hash: &str,
    retire_as_ttl: bool,
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

    if let Err(e) =
        remember_retired_sessions(retired_sessions, room_hash, session_ids.iter().copied())
    {
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
    drop(router);

    // M-C: для TTL-комнаты на диск пишутся только alias и SHA256(session_id).
    // Raw session_id и ratchet-состояние остаются в RAM (H-3).
    let ttl_active = retire_as_ttl || room_has_ttl(room_ttls, room_hash);
    if ttl_active {
        if let Err(e) = remember_ttl_tombstones(ttl_tombstones, session_ids.iter().copied()) {
            warn!(
                "Failed to remember TTL tombstone for {}: {:#}",
                truncate_display(room_hash, 16),
                e
            );
            return;
        }
        if let Err(e) = persist_ttl_tombstones(storage, ttl_tombstones) {
            warn!(
                "Failed to persist TTL tombstones for {}: {:#}",
                truncate_display(room_hash, 16),
                e
            );
        }
        // Raw session_id TTL-комнаты не должны оставаться на диске.
        if let Err(e) = storage.delete_retired_ratchet_sessions(room_hash) {
            warn!("Failed to delete retired ratchet sessions: {:#}", e);
        }
    } else if let Err(e) = persist_retired_sessions(storage, retired_sessions, false, room_hash) {
        // Сначала фиксируем tombstone-и, затем удаляем состояние: сбой записи
        // оставляет старую сессию на диске, а не теряет защиту от replay.
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

        // M-C: tombstone-хеши TTL-сессий. TTL и лимит применяются уже при
        // загрузке; если что-то удалено, очищенный набор сразу пишется назад.
        let ttl_tombstones = {
            let (registry, pruned) = match storage.load_ttl_tombstones() {
                Ok(entries) => TtlTombstoneRegistry::from_entries(entries, now_timestamp()),
                Err(e) => {
                    warn!("Failed to load TTL tombstones: {:#}", e);
                    TtlTombstoneRegistry::from_entries(Vec::new(), now_timestamp())
                }
            };
            if pruned {
                if let Err(e) = storage.save_ttl_tombstones(&registry.snapshot()) {
                    warn!("Failed to persist pruned TTL tombstones: {:#}", e);
                }
            }
            Arc::new(Mutex::new(registry))
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

        // Initialize P2P sender and load persistent .onion address if stored.
        let p2p_sender = Arc::new(P2pSender::new(&config));
        let stored_onion = match storage.load_tor_service() {
            Ok(Some(creds)) => match OnionAddress::from_service_id(&creds.service_id) {
                Ok(addr) => Some(addr),
                Err(e) => {
                    warn!("Ignoring invalid stored Tor ServiceID: {}", e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                warn!("Failed to load Tor hidden service credentials: {:#}", e);
                None
            }
        };
        let own_onion = Arc::new(RwLock::new(stored_onion));
        let tor_connected = Arc::new(RwLock::new(false));
        let local_p2p_port = Arc::new(RwLock::new(None));
        let outbox_notify = Arc::new(tokio::sync::Notify::new());
        let tor_reload_notify = Arc::new(tokio::sync::Notify::new());

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
                        secrets.insert(contact.hash.clone(), SharedSecret::from_bytes(secret));
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
                    secrets.insert(identity.hash.clone(), SharedSecret::from_bytes(secret));
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
            config: Arc::new(RwLock::new(config)),
            base_dir,
            storage,
            identity_manager,
            identity,
            shared_secrets,
            ratchets,
            retired_ratchet_sessions,
            ttl_tombstones,
            inbound_router,
            p2p_sender,
            own_onion,
            tor_connected,
            local_p2p_port,
            outbox_notify,
            tor_reload_notify,
            #[cfg(test)]
            test_peer_overrides: Arc::new(Mutex::new(HashMap::new())),
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
        info!("App started (P2P Tor mode)");

        // 1. Локальный TCP-слушатель для входящих кадров от Tor hidden service.
        let cfg = self.get_config();
        let (listener, local_port) = bind_inbound_listener(cfg.effective_p2p_local_port()).await?;
        if let Ok(mut guard) = self.local_p2p_port.write() {
            *guard = Some(local_port);
        }
        info!("P2P inbound listener bound on 127.0.0.1:{}", local_port);

        let identity_hash = self.identity.hash.clone();
        let shared_secrets = self.shared_secrets.clone();
        let storage = self.storage.clone();
        let room_ttls = self.room_ttls.clone();
        let ratchets = self.ratchets.clone();
        let retired_ratchet_sessions = self.retired_ratchet_sessions.clone();
        let ttl_tombstones = self.ttl_tombstones.clone();
        let inbound_router = self.inbound_router.clone();
        let event_sender = self.event_sender.clone();

        tokio::spawn(serve_inbound(listener, move |packet| {
            let shared_secrets = shared_secrets.clone();
            let storage = storage.clone();
            let room_ttls = room_ttls.clone();
            let ratchets = ratchets.clone();
            let retired_ratchet_sessions = retired_ratchet_sessions.clone();
            let ttl_tombstones = ttl_tombstones.clone();
            let inbound_router = inbound_router.clone();
            let identity_hash = identity_hash.clone();
            let event_sender = event_sender.clone();

            async move {
                Self::handle_incoming_packet(
                    packet,
                    &shared_secrets,
                    &storage,
                    &room_ttls,
                    &ratchets,
                    &retired_ratchet_sessions,
                    &ttl_tombstones,
                    &inbound_router,
                    &identity_hash,
                    &event_sender,
                )
                .await;
            }
        }));

        // 2. Управление Tor ControlPort (`ADD_ONION`) и поддержка живучести скрытого сервиса.
        let tor_storage = self.storage.clone();
        let own_onion = self.own_onion.clone();
        let tor_connected = self.tor_connected.clone();
        let tor_reload = self.tor_reload_notify.clone();
        let tor_outbox_notify = self.outbox_notify.clone();
        let tor_events = self.event_sender.clone();
        tokio::spawn(run_tor_control_loop(
            self.config.clone(),
            local_port,
            tor_storage,
            own_onion,
            tor_connected,
            tor_reload,
            tor_outbox_notify,
            tor_events,
        ));

        // 3. Фоновый воркер зашифрованной очереди Outbox.
        let outbox_storage = self.storage.clone();
        let outbox_sender = self.p2p_sender.clone();
        let outbox_notify = self.outbox_notify.clone();
        let outbox_events = self.event_sender.clone();
        #[cfg(test)]
        let test_overrides = self.test_peer_overrides.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = outbox_notify.notified() => {}
                    _ = interval.tick() => {}
                }

                let _ = flush_outbox_once(
                    &outbox_storage,
                    &outbox_sender,
                    &outbox_events,
                    #[cfg(test)]
                    &test_overrides,
                )
                .await;
            }
        });

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_incoming_packet(
        packet: Vec<u8>,
        shared_secrets: &Arc<Mutex<SharedSecretMap>>,
        storage: &Arc<Storage>,
        room_ttls: &Arc<Mutex<HashMap<String, RoomTtl>>>,
        ratchets: &Arc<Mutex<HashMap<String, RatchetState>>>,
        retired_ratchet_sessions: &RetiredRatchetSessions,
        ttl_tombstones: &Arc<Mutex<TtlTombstoneRegistry>>,
        inbound_router: &Arc<Mutex<InboundRouter>>,
        identity_hash: &str,
        event_sender: &mpsc::UnboundedSender<AppEvent>,
    ) {
        // M-8/M-C/L-1: порядок проверок до криптографии —
        // version/размер → alias lookup → retired в памяти → tombstone
        // TTL-сессии → pre-dedup → bootstrap-резолв (с кэшем и лимитом)
        // → tombstone bootstrap → AEAD → ratchet.
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

        // M-C: retired alias TTL-сессии может быть неизвестен роутеру после
        // рестарта (ratchet-состояние живёт только в RAM). Tombstone-хеш
        // восстанавливает этот адрес и отклоняет пакет до AEAD.
        match ttl_tombstone_has_alias(ttl_tombstones, &info.alias) {
            Ok(true) => {
                warn!(
                    "Incoming packet rejected: {} (ttl tombstone)",
                    RoutingError::StaleSession
                );
                return;
            }
            Ok(false) => {}
            Err(e) => {
                warn!("Incoming packet dropped: {:#}", e);
                return;
            }
        }

        let now = std::time::Instant::now();

        // L-1: dedup до любого bootstrap-резолва. Повтор уже доставленного
        // пакета не должен запускать HKDF даже для неизвестного alias.
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
                warn!("Incoming packet rejected: {}", RoutingError::ReplayNonce);
                return;
            }
        }

        let (from_hash, bootstrap_hash) = match route {
            Route::Active(room) => {
                // Секрет живёт в карте: HKDF получает ссылку, копии нет.
                let hash = match with_room_secret(&room, shared_secrets, |secret| {
                    info.bootstrap_nonce.and_then(|nonce| {
                        ratchet::bootstrap_session_id_hash(secret.expose(), &nonce).ok()
                    })
                }) {
                    Ok(hash) => hash,
                    Err(e) => {
                        warn!("Incoming packet dropped: {:#}", e);
                        return;
                    }
                };
                (room, hash)
            }
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
                let Some(nonce) = info.bootstrap_nonce else {
                    warn!("Incoming packet rejected: {}", RoutingError::UnknownRoom);
                    return;
                };

                // L-1: лимит на неизвестные bootstrap-пакеты. Один токен
                // покрывает и попадание в кэш (1 HKDF), и полный скан.
                let allowed = {
                    let mut router = match inbound_router.lock() {
                        Ok(router) => router,
                        Err(_) => {
                            warn!("Incoming packet dropped: routing lock poisoned");
                            return;
                        }
                    };
                    router.allow_bootstrap_scan(now)
                };
                if !allowed {
                    warn!(
                        "Incoming packet rejected: {} (bootstrap rate limit)",
                        RoutingError::UnknownRoom
                    );
                    return;
                }

                // L-1: положительный кэш alias -> room снимает O(contacts)
                // HKDF для повторных пакетов той же bootstrap-сессии.
                let cached = {
                    let mut router = match inbound_router.lock() {
                        Ok(router) => router,
                        Err(_) => {
                            warn!("Incoming packet dropped: routing lock poisoned");
                            return;
                        }
                    };
                    router.cached_bootstrap_room(info.alias)
                };
                let resolved = match cached {
                    Some(room) => {
                        let hash = match with_room_secret(&room, shared_secrets, |secret| {
                            ratchet::bootstrap_session_id_hash(secret.expose(), &nonce).ok()
                        }) {
                            Ok(hash) => hash,
                            Err(e) => {
                                warn!("Incoming packet dropped: {:#}", e);
                                return;
                            }
                        };
                        let hkdf_attempts = usize::from(hash.is_some());
                        if let Ok(mut router) = inbound_router.lock() {
                            router.note_bootstrap_hkdf(hkdf_attempts);
                        }
                        hash.map(|hash| (room, hash))
                    }
                    None => {
                        let (resolved, hkdf_attempts) =
                            resolve_bootstrap_room(&info.alias, &nonce, shared_secrets);
                        if let Ok(mut router) = inbound_router.lock() {
                            router.note_bootstrap_hkdf(hkdf_attempts);
                        }
                        if let Some((room, _)) = resolved.as_ref() {
                            if let Ok(mut router) = inbound_router.lock() {
                                router.cache_bootstrap_room(info.alias, room.clone());
                            }
                        }
                        resolved
                    }
                };

                match resolved {
                    Some((room, hash)) => (room, Some(hash)),
                    None => {
                        warn!("Incoming packet rejected: {}", RoutingError::UnknownRoom);
                        return;
                    }
                }
            }
        };

        // M-C: tombstone-проверка после alias lookup и до создания сессии.
        // Пакет старой TTL-сессии после рестарта не должен выглядеть как
        // новый bootstrap: session_id_hash уже известен из vault.
        if let Some(hash) = bootstrap_hash {
            match ttl_tombstone_has_hash(ttl_tombstones, &hash) {
                Ok(true) => {
                    warn!(
                        "Incoming packet rejected: {} (ttl tombstone)",
                        RoutingError::StaleSession
                    );
                    return;
                }
                Ok(false) => {}
                Err(e) => {
                    warn!("Incoming packet dropped: {:#}", e);
                    return;
                }
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
        let (decrypted, aead_attempts) =
            match with_room_secret(&from_hash, shared_secrets, |secret| {
                try_ratchet_decrypt(
                    &packet,
                    &from_hash,
                    secret.expose(),
                    identity_hash,
                    storage,
                    ratchets,
                    retired_ratchet_sessions,
                    ttl_active,
                )
            }) {
                Ok(outcome) => outcome,
                Err(e) => {
                    warn!("Incoming packet dropped: {:#}", e);
                    return;
                }
            };
        // L-2: даже отклонённый пакет учитывается в бюджете AEAD.
        if let Ok(mut router) = inbound_router.lock() {
            router.note_aead_attempts(aead_attempts);
        }
        let decrypted = match decrypted {
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
                let was_ttl = room_has_ttl(room_ttls, &from_hash);
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
                                    pending_sync: false,
                                },
                            );
                        }
                        None => {
                            ttls.remove(&from_hash);
                        }
                    }
                }

                // Смена режима TTL сбрасывает сессию храповика с обеих
                // сторон: дальше состояние живёт только в RAM. Даже при
                // выключении TTL retiring-сессия была TTL-сессией, поэтому
                // на диск пишется только её tombstone-хеш (M-C).
                clear_ratchet_state(
                    ratchets,
                    storage,
                    retired_ratchet_sessions,
                    ttl_tombstones,
                    inbound_router,
                    room_ttls,
                    &from_hash,
                    was_ttl || seconds.is_some(),
                );

                let _ = event_sender.send(AppEvent::TtlChanged {
                    room_hash: from_hash.clone(),
                    seconds,
                    from_peer: from_hash != identity_hash,
                });
                return;
            }
            Ok(crypto::E2ePayload::RatchetReset) => {
                let ttl_active = room_has_ttl(room_ttls, &from_hash);
                clear_ratchet_state(
                    ratchets,
                    storage,
                    retired_ratchet_sessions,
                    ttl_tombstones,
                    inbound_router,
                    room_ttls,
                    &from_hash,
                    ttl_active,
                );
                info!(
                    "Ratchet session reset by peer for {}",
                    truncate_display(&from_hash, 16)
                );
                return;
            }
            Ok(crypto::E2ePayload::Text { text, ttl_seconds }) => {
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
            "onion": self.own_onion_addr(),
            "torConnected": self.is_tor_connected(),
            "outboxPending": self.outbox_pending_count(),
        })
    }

    /// Текущий локальный `.onion` v3-адрес (загруженный из `vault.dat` или выданный Tor).
    pub fn own_onion_addr(&self) -> Option<String> {
        let guard = match self.own_onion.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.as_ref().map(|addr| addr.as_str().to_string())
    }

    /// Признак активного подключения к Tor ControlPort и опубликованного сервиса.
    pub fn is_tor_connected(&self) -> bool {
        match self.tor_connected.read() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Число зашифрованных пакетов, ожидающих доставки в очереди Outbox.
    pub fn outbox_pending_count(&self) -> usize {
        self.storage.count_outbox().unwrap_or(0)
    }

    fn local_p2p_port_value(&self) -> Option<u16> {
        match self.local_p2p_port.read() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    #[cfg(test)]
    fn set_own_onion_for_test(&self, addr: OnionAddress) {
        let mut guard = match self.own_onion.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(addr);
    }

    #[cfg(test)]
    fn set_peer_override_for_test(&self, room_hash: &str, addr: std::net::SocketAddr) {
        let mut guard = self
            .test_peer_overrides
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(room_hash.to_string(), addr);
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
        let onion = self.own_onion_addr().ok_or_else(|| {
            anyhow!("own Tor .onion address is not ready yet; wait for Tor ControlPort (ADD_ONION)")
        })?;

        IdentityDoc::from_slices(
            &self.identity.ed25519_public_key,
            &self.identity.public_key,
            &onion,
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
            "onion": invite.onion_addr(),
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
        self.storage.upsert_p2p_contact(
            &hash,
            &pub_key,
            &ed25519,
            invite.onion_addr(),
            &fingerprint,
            &tofu_state,
            &nickname,
        )?;

        {
            let mut secrets = self
                .shared_secrets
                .lock()
                .map_err(|_| anyhow!("shared secrets lock poisoned"))?;
            secrets.insert(hash.clone(), SharedSecret::from_bytes(shared_secret));
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

        self.emit_event(AppEvent::OutboxUpdated {
            pending: self.outbox_pending_count(),
        });

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

    fn resolve_recipient_onion(&self, room_hash: &str) -> Result<String> {
        if room_hash == self.identity.hash {
            if let Some(onion) = self.own_onion_addr() {
                return Ok(onion);
            }
        } else {
            let contact = self.storage.get_contact(room_hash)?;
            if let Some(raw) = contact.onion_addr.as_deref() {
                let normalized = OnionAddress::parse(raw)?;
                return Ok(normalized.as_str().to_string());
            }
        }

        #[cfg(test)]
        {
            let overrides = self
                .test_peer_overrides
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if overrides.contains_key(room_hash) {
                return Ok(OnionAddress::test_v3_from_seed(1).to_string());
            }
        }

        Err(anyhow!(
            "contact {} has no P2P .onion address",
            truncate_display(room_hash, 16)
        ))
    }

    async fn send_packet_to_peer(&self, room_hash: &str, packet: &[u8]) -> Result<()> {
        #[cfg(test)]
        {
            let override_addr = {
                let overrides = self
                    .test_peer_overrides
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                overrides.get(room_hash).copied()
            };
            if let Some(addr) = override_addr {
                return self.p2p_sender.send_packet_direct(addr, packet).await;
            }
        }

        if room_hash == self.identity.hash {
            if let Some(port) = self.local_p2p_port_value() {
                let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
                return self.p2p_sender.send_packet_direct(addr, packet).await;
            }
        }

        let onion_str = self.resolve_recipient_onion(room_hash)?;
        let onion = OnionAddress::parse(&onion_str)?;
        self.p2p_sender.send_packet(&onion, packet).await
    }

    /// Проверяет наличие P2P-назначения для комнаты до сдвига храповика.
    fn ensure_p2p_target_available(&self, room_hash: &str) -> Result<()> {
        if room_hash == self.identity.hash && self.local_p2p_port_value().is_some() {
            return Ok(());
        }
        let _ = self.resolve_recipient_onion(room_hash)?;
        Ok(())
    }

    pub async fn send_message(&self, room_hash: &str, text: &str) -> Result<()> {
        let ttl = self.get_room_ttl(room_hash);
        let ttl_active = ttl.is_some();

        // Односторонний `/ttl` остаётся локальным: TTL не передаётся
        // собеседнику. Двусторонний `/ttl-syn` едет в метаданных текста.
        let wire_ttl = ttl.filter(|value| value.synced).and_then(|value| value.seconds);
        let payload = crypto::encode_text_payload(text, wire_ttl);

        // H-3: для RAM-TTL комнат (и прямого self-chat при отсутствии `.onion`)
        // отправляем напрямую без записи зашифрованного конверта в `vault.dat`.
        if ttl_active || (room_hash == self.identity.hash && self.local_p2p_port_value().is_some())
        {
            self.ensure_p2p_target_available(room_hash)?;
            let packet = self.encrypt_with_ratchet(room_hash, &payload)?;
            self.send_packet_to_peer(room_hash, &packet).await?;
            return self.store_outgoing_message(room_hash, text);
        }

        let recipient_onion = self.resolve_recipient_onion(room_hash)?;
        let packet = self.encrypt_with_ratchet(room_hash, &payload)?;
        let now_unix = i64::try_from(now_timestamp()).unwrap_or(i64::MAX);
        self.storage
            .enqueue_outbox(room_hash, &recipient_onion, &packet, now_unix)?;
        self.store_outgoing_message(room_hash, text)?;
        self.emit_event(AppEvent::OutboxUpdated {
            pending: self.outbox_pending_count(),
        });
        self.outbox_notify.notify_one();

        Ok(())
    }

    /// Немедленная синхронная отправка сообщения (для одноразового headless-режима `--send`).
    pub async fn send_message_direct(&self, room_hash: &str, text: &str) -> Result<()> {
        self.ensure_p2p_target_available(room_hash)?;
        let payload = crypto::encode_text_payload(text, None);
        let packet = self.encrypt_with_ratchet(room_hash, &payload)?;
        self.send_packet_to_peer(room_hash, &packet).await?;
        self.store_outgoing_message(room_hash, text)
    }

    #[cfg(test)]
    async fn flush_outbox_for_test(&self) -> Result<usize> {
        flush_outbox_once(
            &self.storage,
            &self.p2p_sender,
            &self.event_sender,
            &self.test_peer_overrides,
        )
        .await
    }

    /// Шифрует полезную нагрузку текущей эпохой Double Ratchet.
    ///
    /// Для обычной комнаты обновлённое состояние сразу сохраняется в
    /// `vault.dat`. Для комнаты с RAM-TTL состояние остаётся в памяти.
    fn encrypt_with_ratchet(&self, room_hash: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let ttl_active = self.get_room_ttl(room_hash).is_some();
        let identity_hash = self.identity.hash.clone();
        let retired = retired_sessions_for(&self.retired_ratchet_sessions, room_hash)?;

        let (packet, serialized, aliases) =
            self.with_shared_secret(room_hash, |shared_secret| {
                let mut states = self
                    .ratchets
                    .lock()
                    .map_err(|_| anyhow!("ratchet lock poisoned"))?;

                ensure_ratchet_state(
                    &mut states,
                    room_hash,
                    shared_secret.expose(),
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
                Ok((packet, serialized, aliases))
            })?;

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
        self.ensure_p2p_target_available(room_hash)?;
        let payload = crypto::encode_ratchet_reset();
        let packet = self.encrypt_with_ratchet(room_hash, &payload)?;
        self.send_packet_to_peer(room_hash, &packet).await?;
        self.clear_ratchet(room_hash)
    }

    /// Удаляет состояние храповика из RAM и `vault.dat`.
    ///
    /// `session_id` уничтоженных сессий остаются в RAM-реестре и (для
    /// обычных комнат) в `vault.dat`, чтобы запоздавший пакет старой
    /// сессии не был принят как новая сессия даже после перезапуска.
    pub fn clear_ratchet(&self, room_hash: &str) -> Result<()> {
        let ttl_active = self.get_room_ttl(room_hash).is_some();
        self.clear_ratchet_with_mode(room_hash, ttl_active)
    }

    /// [`Self::clear_ratchet`] с явным режимом ретирации.
    ///
    /// `retire_as_ttl` нужен при выключении TTL: к моменту сброса комната
    /// уже не считается TTL-комнатой, но уничтожаемая сессия была TTL-сессией
    /// и на диск должен попасть только её tombstone-хеш (M-C).
    fn clear_ratchet_with_mode(&self, room_hash: &str, retire_as_ttl: bool) -> Result<()> {
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
        remember_retired_sessions(
            &self.retired_ratchet_sessions,
            room_hash,
            session_ids.iter().copied(),
        )?;

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
        let ttl_active = retire_as_ttl || self.get_room_ttl(room_hash).is_some();
        if ttl_active {
            remember_ttl_tombstones(&self.ttl_tombstones, session_ids.iter().copied())?;
            // Ошибка записи не отменяет tombstone в памяти: следующая
            // TTL-ретирация повторит попытку.
            if let Err(e) = persist_ttl_tombstones(self.storage.as_ref(), &self.ttl_tombstones) {
                warn!("Failed to persist TTL tombstones: {:#}", e);
            }
            // Raw session_id TTL-комнаты не должны оставаться на диске.
            if let Err(e) = self.storage.delete_retired_ratchet_sessions(room_hash) {
                warn!("Failed to delete retired ratchet sessions: {:#}", e);
            }
        } else {
            persist_retired_sessions(
                self.storage.as_ref(),
                &self.retired_ratchet_sessions,
                false,
                room_hash,
            )?;
        }
        if self
            .storage
            .has_pending_outbox_for_room(room_hash)
            .unwrap_or(false)
        {
            if let Ok(removed) = self.storage.clear_room_outbox(room_hash) {
                if removed > 0 {
                    self.emit_event(AppEvent::OutboxUpdated {
                        pending: self.outbox_pending_count(),
                    });
                }
            }
        }
        self.storage.delete_ratchet_state(room_hash)
    }

    /// Переносит текущую сессию храповика в RAM и удаляет её с диска.
    ///
    /// Используется при включении `/ttl` или `/ttl-syn`: собеседник
    /// сохраняет прежнюю сессию, поэтому локальная копия должна остаться
    /// доступной, но только в оперативной памяти.
    fn enter_ram_ttl(&self, room_hash: &str) -> Result<()> {
        let retired = retired_sessions_for(&self.retired_ratchet_sessions, room_hash)?;

        // M-C: raw tombstone-и, уже лежавшие в vault.dat, перед удалением
        // конвертируются в хеши. Иначе включение TTL молча потеряло бы
        // анти-replay для ранее сброшенных сессий после рестарта.
        if !retired.is_empty() {
            match remember_ttl_tombstones(&self.ttl_tombstones, retired.iter().copied()) {
                Ok(()) => {
                    if let Err(e) =
                        persist_ttl_tombstones(self.storage.as_ref(), &self.ttl_tombstones)
                    {
                        warn!("Failed to persist TTL tombstones: {:#}", e);
                    }
                }
                Err(e) => warn!("Failed to remember TTL tombstones: {:#}", e),
            }
        }

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

        // H-3: raw session_id уходят с диска, но tombstone-хеши TTL-сессий
        // остаются (M-C): это не ratchet-состояние и не session_id.
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
        let was_ttl = self.get_room_ttl(room_hash).is_some();
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
                        pending_sync: false,
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
            // начнётся заново. Сессия была TTL-сессией, поэтому пишется
            // только tombstone-хеш (M-C).
            None => self.clear_ratchet_with_mode(room_hash, was_ttl),
        }
    }

    /// Устанавливает двусторонний RAM-TTL и отправляет `SetTtl` собеседнику.
    ///
    /// При включении TTL флаг выставляется до шифрования: иначе `SetTtl`
    /// создаст/сдвинет храповик, и тот попадёт в `vault.dat` (H-3).
    /// Ошибка отправки не откатывает TTL: снапшот с ratchet всё равно не
    /// записывается. Вместо отката TTL помечается как применённый локально
    /// (`pending_sync`), а вызывающий получает [`TtlSyncOutcome::LocalOnly`],
    /// чтобы показать статус и предложить ретрай ([`Self::resync_ttl`]).
    pub async fn set_synced_ttl(
        &self,
        room_hash: &str,
        seconds: Option<u64>,
    ) -> Result<TtlSyncOutcome> {
        let payload = crypto::encode_set_ttl(seconds);
        let was_ttl = self.get_room_ttl(room_hash).is_some();

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
                        // Подтверждение появится только после успешной
                        // отправки `SetTtl`.
                        synced: false,
                        pending_sync: false,
                    },
                );
            }

            let packet = self.encrypt_with_ratchet(room_hash, &payload)?;
            if let Err(e) = self.send_packet_to_peer(room_hash, &packet).await
            {
                // TTL намеренно не откатываем: сессия уже переключена в RAM,
                // а на диске ratchet-состояния быть не должно (H-3).
                // Оставляем явный признак для UI и ретрая.
                if let Some(ttl) = self
                    .room_ttls
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get_mut(room_hash)
                {
                    ttl.synced = false;
                    ttl.pending_sync = true;
                }
                return Ok(TtlSyncOutcome::LocalOnly {
                    error: format!("{:#}", e),
                });
            }

            if let Some(ttl) = self
                .room_ttls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_mut(room_hash)
            {
                ttl.synced = true;
                ttl.pending_sync = false;
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

            if let Err(e) = self.send_packet_to_peer(room_hash, &packet).await
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
        // При выключении TTL комната уже не TTL, но retiring-сессия была
        // TTL-сессией: на диск попадает только tombstone-хеш (M-C).
        self.clear_ratchet_with_mode(room_hash, was_ttl || seconds.is_some())?;
        Ok(TtlSyncOutcome::Synced)
    }

    /// Повторно отправляет собеседнику уже применённый локально TTL.
    ///
    /// Вызывается после [`TtlSyncOutcome::LocalOnly`]: длительность не
    /// меняется, поэтому TTL не откатывается и не включается заново. При
    /// повторной ошибке `pending_sync` сохраняется и ретрай можно повторить.
    pub async fn resync_ttl(&self, room_hash: &str) -> Result<TtlSyncOutcome> {
        let ttl = self
            .get_room_ttl(room_hash)
            .ok_or_else(|| anyhow!("RAM TTL is not active for this room"))?;

        // Ретрай имеет смысл только для неподтверждённого обновления:
        // односторонний `/ttl` не должен превращаться в двусторонний.
        if ttl.synced || !ttl.pending_sync {
            return Err(anyhow!("TTL update is not pending confirmation"));
        }

        let payload = crypto::encode_set_ttl(ttl.seconds);
        let packet = self.encrypt_with_ratchet(room_hash, &payload)?;

        if let Err(e) = self.send_packet_to_peer(room_hash, &packet).await
        {
            return Ok(TtlSyncOutcome::LocalOnly {
                error: format!("{:#}", e),
            });
        }

        if let Some(ttl) = self
            .room_ttls
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_mut(room_hash)
        {
            ttl.synced = true;
            ttl.pending_sync = false;
        }

        // Собеседник сбросил храповик по `SetTtl`; локально делаем то же,
        // причём retiring-сессия считается TTL-сессией.
        self.clear_ratchet_with_mode(room_hash, true)?;
        Ok(TtlSyncOutcome::Synced)
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

    /// Выполняет `f` с общим секретом комнаты.
    ///
    /// Секрет не копируется: при попадании в кэш `f` получает ссылку на
    /// значение в `HashMap` (блокировка карты держится на время вызова).
    /// При промахе ключ выводится из X25519 и кладётся в карту.
    ///
    /// Ключевой кэш — fail-closed: poison означает неизвестное состояние,
    /// операция не продолжается с частичной картой.
    fn with_shared_secret<T>(
        &self,
        room_hash: &str,
        f: impl FnOnce(&SharedSecret) -> Result<T>,
    ) -> Result<T> {
        {
            let secrets = self
                .shared_secrets
                .lock()
                .map_err(|_| anyhow!("shared secret lock poisoned"))?;
            if let Some(secret) = secrets.get(room_hash) {
                return f(secret);
            }
        }

        // Check if self
        let derived = if room_hash == self.identity.hash {
            crypto::generate_shared_key(
                self.identity.private_key.expose(),
                &self.identity.public_key,
            )?
        } else {
            // Load from storage
            let contact = self.storage.get_contact(room_hash)?;
            crypto::generate_shared_key(self.identity.private_key.expose(), &contact.public_key)?
        };
        let derived = SharedSecret::from_bytes(derived);

        let mut secrets = self
            .shared_secrets
            .lock()
            .map_err(|_| anyhow!("shared secret lock poisoned"))?;
        let secret = secrets.entry(room_hash.to_string()).or_insert(derived);
        f(secret)
    }

    /// Тестовая копия секрета: явный `duplicate()` вместо возврата из
    /// продакшн-API. `SharedSecret` намеренно не реализует `Clone`.
    #[cfg(test)]
    fn shared_secret_for_test(&self, room_hash: &str) -> SharedSecret {
        self.with_shared_secret(room_hash, |secret| Ok(secret.duplicate()))
            .expect("test shared secret")
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

    /// Сохраняет новые сетевые P2P-параметры и сразу применяет их в
    /// `P2pSender` и фоновом цикле Tor ControlPort.
    pub fn update_config(&self, mut config: Config) -> Result<()> {
        config.normalize();
        config.validate()?;
        config.save(&self.base_dir, &self.vault)?;

        self.p2p_sender.update_config(&config)?;

        let mut guard = self
            .config
            .write()
            .map_err(|_| anyhow!("{}", config.lang.texts().config_lock_failed))?;
        *guard = config;
        drop(guard);

        self.tor_reload_notify.notify_one();

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
// P2P BACKGROUND WORKERS
// ============================================================

fn set_tor_connected_flag(flag: &Arc<RwLock<bool>>, connected: bool) {
    match flag.write() {
        Ok(mut guard) => *guard = connected,
        Err(poisoned) => *poisoned.into_inner() = connected,
    }
}

fn current_onion_string(own_onion: &Arc<RwLock<Option<OnionAddress>>>) -> Option<String> {
    let guard = match own_onion.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.as_ref().map(|addr| addr.as_str().to_string())
}

/// Поддерживает подключение к Tor ControlPort, публикует постоянный `.onion`
/// скрытый сервис через `ADD_ONION` и переподключается при сбое или смене конфига.
#[allow(clippy::too_many_arguments)]
async fn run_tor_control_loop(
    config: Arc<RwLock<Config>>,
    local_port: u16,
    storage: Arc<Storage>,
    own_onion: Arc<RwLock<Option<OnionAddress>>>,
    tor_connected: Arc<RwLock<bool>>,
    tor_reload: Arc<tokio::sync::Notify>,
    outbox_notify: Arc<tokio::sync::Notify>,
    event_sender: mpsc::UnboundedSender<AppEvent>,
) {
    loop {
        let cfg = match config.read() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let control_addr = cfg.effective_tor_control_addr();
        let cookie_path = cfg.effective_tor_cookie_path();
        let onion_port = cfg.effective_p2p_onion_port();

        let connect_result = async {
            let mut conn = TorControlConnection::connect(&control_addr).await?;
            let info = conn.protocol_info().await?;
            conn.authenticate(&info, cookie_path.as_deref()).await?;

            let stored = storage.load_tor_service()?;
            let existing_key = stored.as_ref().map(|creds| &creds.private_key);
            let service = conn
                .add_onion(existing_key, onion_port, local_port)
                .await?;

            if let Some(ref private_key) = service.private_key {
                if let Err(e) = storage.save_tor_service(&service.service_id, private_key.expose())
                {
                    warn!("Failed to persist Tor ED25519-V3 key to vault: {:#}", e);
                }
            }

            Ok::<_, anyhow::Error>((conn, service.onion_address))
        }
        .await;

        match connect_result {
            Ok((mut conn, onion_address)) => {
                let onion_str = onion_address.as_str().to_string();
                match own_onion.write() {
                    Ok(mut guard) => *guard = Some(onion_address),
                    Err(poisoned) => *poisoned.into_inner() = Some(onion_address),
                }
                set_tor_connected_flag(&tor_connected, true);
                let _ = event_sender.send(AppEvent::TorStatusChanged {
                    connected: true,
                    onion_addr: Some(onion_str.clone()),
                    error: None,
                });
                info!(
                    "Tor hidden service ready: {}:{} -> 127.0.0.1:{}",
                    onion_str, onion_port, local_port
                );
                outbox_notify.notify_one();

                let mut keepalive = tokio::time::interval(Duration::from_secs(20));
                keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                keepalive.tick().await;

                loop {
                    tokio::select! {
                        _ = tor_reload.notified() => {
                            info!("Tor config reloaded, re-registering ControlPort session");
                            break;
                        }
                        _ = keepalive.tick() => {
                            if let Err(e) = conn.ping().await {
                                warn!("Tor ControlPort keepalive failed: {:#}", e);
                                set_tor_connected_flag(&tor_connected, false);
                                let _ = event_sender.send(AppEvent::TorStatusChanged {
                                    connected: false,
                                    onion_addr: current_onion_string(&own_onion),
                                    error: Some(format!("{:#}", e)),
                                });
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                set_tor_connected_flag(&tor_connected, false);
                warn!("Tor ControlPort unavailable ({}): {:#}", control_addr, e);
                let _ = event_sender.send(AppEvent::TorStatusChanged {
                    connected: false,
                    onion_addr: current_onion_string(&own_onion),
                    error: Some(format!("{:#}", e)),
                });

                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                    _ = tor_reload.notified() => {}
                }
            }
        }
    }
}

/// Одна попытка доставки созревших зашифрованных конвертов из очереди Outbox.
async fn flush_outbox_once(
    storage: &Arc<Storage>,
    sender: &Arc<P2pSender>,
    event_sender: &mpsc::UnboundedSender<AppEvent>,
    #[cfg(test)] test_overrides: &Arc<Mutex<HashMap<String, std::net::SocketAddr>>>,
) -> Result<usize> {
    let now_unix = i64::try_from(now_timestamp()).unwrap_or(i64::MAX);
    let due = storage.due_outbox_items(now_unix)?;
    if due.is_empty() {
        return Ok(0);
    }

    let mut delivered = 0usize;
    let mut failed_rooms = HashSet::new();

    for item in due {
        if failed_rooms.contains(&item.room_hash) {
            continue;
        }

        #[cfg(test)]
        let override_addr = {
            let guard = test_overrides
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.get(&item.room_hash).copied()
        };

        let send_res = {
            #[cfg(test)]
            if let Some(addr) = override_addr {
                sender.send_packet_direct(addr, &item.packet).await
            } else {
                match OnionAddress::parse(&item.recipient_onion) {
                    Ok(target) => sender.send_packet(&target, &item.packet).await,
                    Err(e) => Err(anyhow!("invalid recipient onion address: {}", e)),
                }
            }
            #[cfg(not(test))]
            match OnionAddress::parse(&item.recipient_onion) {
                Ok(target) => sender.send_packet(&target, &item.packet).await,
                Err(e) => Err(anyhow!("invalid recipient onion address: {}", e)),
            }
        };

        match send_res {
            Ok(()) => {
                storage.delete_outbox_item(item.id)?;
                delivered += 1;
            }
            Err(e) => {
                failed_rooms.insert(item.room_hash.clone());
                let next_attempts = item.attempts.saturating_add(1);
                let delay = outbox_backoff_secs(next_attempts);
                let _ = storage.mark_outbox_retry(
                    item.id,
                    next_attempts,
                    now_unix.saturating_add(delay),
                    &format!("{:#}", e),
                );
            }
        }
    }

    let pending = storage.count_outbox().unwrap_or(0);
    let _ = event_sender.send(AppEvent::OutboxUpdated { pending });

    Ok(delivered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::routing::{BOOTSTRAP_SCAN_BURST, BOOTSTRAP_SCAN_REFILL};
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

    /// Минимальный P2P-stub: принимает один фрейм и возвращает `FRAME_ACK`.
    async fn spawn_p2p_ack_stub() -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let Ok(len) = stream.read_u32().await else {
                        return;
                    };
                    let mut buf = vec![0u8; len as usize];
                    if stream.read_exact(&mut buf).await.is_ok() {
                        let _ = stream.write_all(&crate::p2p::FRAME_ACK).await;
                        let _ = stream.shutdown().await;
                    }
                });
            }
        });

        addr
    }

    /// P2P-stub, обрывающий соединение без `FRAME_ACK` для проверки отказов/очереди.
    async fn spawn_p2p_reject_stub() -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                drop(stream);
            }
        });

        addr
    }

    fn test_invite_variant(seed: u8, x_seed: u8, nickname: &str) -> IdentityInvite {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let x_secret = X25519Secret::from([x_seed; 32]);
        let x_public = X25519PublicKey::from(&x_secret);
        let onion = OnionAddress::test_v3_from_seed(seed);
        let doc = IdentityDoc::from_slices(
            signing_key.verifying_key().as_bytes(),
            x_public.as_bytes(),
            onion.as_str(),
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
    fn test_get_profile() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        let profile = app.get_profile();
        assert!(profile["nickname"].is_string());
        assert!(profile["hash"].is_string());
        assert!(profile["publicKey"].is_string());
        assert!(profile["ed25519PublicKey"].is_string());
        assert_eq!(profile["torConnected"], serde_json::json!(false));
        assert_eq!(profile["outboxPending"], serde_json::json!(0));
        // seed-фраза больше не выводится в /profile
        assert!(profile.get("seedPhrase").is_none());
        assert!(!app.get_seed_phrase().is_empty());
    }

    #[test]
    fn test_update_config_is_encrypted_and_applied() {
        let (app, temp_dir, _receiver) = setup_test_app();

        let mut config = app.get_config();
        config.tor_control_addr = "127.0.0.1:9151".to_string();
        config.tor_socks_addr = "127.0.0.1:9150".to_string();
        config.tor_cookie_path = Some("/var/lib/tor/secret_control_cookie".to_string());
        config.p2p_local_port = 19878;
        config.p2p_onion_port = 9999;
        config.notify_level = 1;
        config.stealth_title = "Перерыв".to_string();
        config.stealth_body = "Отдых {sec}, писем: {count}".to_string();
        config.stealth_seconds = "10-15".to_string();

        app.update_config(config.clone()).unwrap();

        let applied = app.get_config();
        assert_eq!(applied.tor_control_addr, "127.0.0.1:9151");
        assert_eq!(applied.tor_socks_addr, "127.0.0.1:9150");
        assert_eq!(
            applied.tor_cookie_path.as_deref(),
            Some("/var/lib/tor/secret_control_cookie")
        );
        assert_eq!(applied.p2p_local_port, 19878);
        assert_eq!(applied.p2p_onion_port, 9999);
        assert_eq!(applied.notify_level, 1);
        assert_eq!(applied.stealth_title, "Перерыв");
        assert_eq!(applied.stealth_body, "Отдых {sec}, писем: {count}");
        assert_eq!(applied.stealth_seconds, "10-15");

        let config_path = temp_dir.path().join("global.conf");
        let raw = std::fs::read(&config_path).unwrap();
        assert!(vault::is_sealed(&raw));
        assert!(!String::from_utf8_lossy(&raw).contains("secret_control_cookie"));

        let base_dir = temp_dir.path().to_str().unwrap();
        let reopened_vault = Vault::unlock(base_dir, "test-password").unwrap();
        let saved = Config::load(base_dir, &reopened_vault).unwrap();
        assert_eq!(saved.tor_control_addr, "127.0.0.1:9151");
        assert_eq!(saved.tor_socks_addr, "127.0.0.1:9150");
        assert_eq!(
            saved.tor_cookie_path.as_deref(),
            Some("/var/lib/tor/secret_control_cookie")
        );
        assert_eq!(saved.p2p_local_port, 19878);
        assert_eq!(saved.p2p_onion_port, 9999);
        assert_eq!(saved.notify_level, 1);
        assert_eq!(saved.stealth_title, "Перерыв");
        assert_eq!(saved.stealth_body, "Отдых {sec}, писем: {count}");
        assert_eq!(saved.stealth_seconds, "10-15");
    }

    #[test]
    fn test_contact_link() {
        let (app, _temp_dir, _receiver) = setup_test_app();

        // Пока .onion не получен от Tor и не сохранён в vault, генерация ссылки fail-closed.
        assert!(app.get_my_contact_link().is_err());

        let own_onion = OnionAddress::test_v3_from_seed(77);
        app.set_own_onion_for_test(own_onion.clone());

        let link = app.get_my_contact_link().unwrap();
        assert!(link.starts_with("lastchance://contact?"));
        assert!(link.contains("hash="));
        assert!(link.contains("doc="));
        assert!(link.contains("sig="));
        assert!(link.contains("x25519="));
        assert!(link.contains("ed25519="));
        assert!(link.contains("onion="));
        assert!(link.contains("nickname="));

        let parsed = IdentityInvite::from_link(&link).unwrap();
        assert_eq!(parsed.hash_hex(), app.identity.hash);
        assert_eq!(parsed.doc.x25519_pub.to_vec(), app.identity.public_key);
        assert_eq!(parsed.onion_addr(), own_onion.as_str());
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
        let reject_addr = spawn_p2p_reject_stub().await;
        let (app, _temp_dir, _receiver) = setup_test_app();

        let invite = test_invite(5, "SyncPeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();
        app.set_peer_override_for_test(&hash, reject_addr);

        // Обычная комната: ratchet уже записан на диск.
        app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_some());

        let outcome = app.set_synced_ttl(&hash, Some(30)).await.unwrap();
        assert!(
            matches!(outcome, TtlSyncOutcome::LocalOnly { .. }),
            "send failure must be reported as local-only, not confirmed"
        );

        let ttl = app.get_room_ttl(&hash).expect("TTL must stay active");
        assert_eq!(
            ttl.seconds,
            Some(30),
            "TTL must not be silently rolled back"
        );
        assert!(!ttl.synced, "failed delivery is not a peer confirmation");
        assert!(ttl.pending_sync, "UI must be able to offer a retry");
        assert!(app
            .get_storage()
            .persisted_ratchet_state_for_test(&hash)
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn synced_ttl_retry_confirms_pending_sync() {
        // L-8: после ошибки отправки TTL остаётся локальным и явно
        // помеченным, а повторная синхронизация подтверждает его.
        let failing_addr = spawn_p2p_reject_stub().await;
        let (app, _temp_dir, _receiver) = setup_test_app();

        let invite = test_invite(7, "RetryPeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();
        app.set_peer_override_for_test(&hash, failing_addr);

        let outcome = app.set_synced_ttl(&hash, Some(45)).await.unwrap();
        match outcome {
            TtlSyncOutcome::LocalOnly { error } => assert!(!error.is_empty()),
            TtlSyncOutcome::Synced => panic!("send failure must not report synced"),
        }

        let ttl = app.get_room_ttl(&hash).expect("TTL is applied locally");
        assert_eq!(ttl.seconds, Some(45));
        assert!(!ttl.synced);
        assert!(ttl.pending_sync);

        // Повторный ретрай при всё ещё недоступном пире сохраняет статус.
        let still_failing_addr = spawn_p2p_reject_stub().await;
        app.set_peer_override_for_test(&hash, still_failing_addr);
        assert!(matches!(
            app.resync_ttl(&hash).await.unwrap(),
            TtlSyncOutcome::LocalOnly { .. }
        ));
        assert!(app.get_room_ttl(&hash).unwrap().pending_sync);

        // Успешный ретрай снимает pending и подтверждает доставку.
        let ok_addr = spawn_p2p_ack_stub().await;
        app.set_peer_override_for_test(&hash, ok_addr);

        assert_eq!(
            app.resync_ttl(&hash).await.unwrap(),
            TtlSyncOutcome::Synced
        );
        let ttl = app.get_room_ttl(&hash).unwrap();
        assert_eq!(ttl.seconds, Some(45), "retry must not change the duration");
        assert!(ttl.synced);
        assert!(!ttl.pending_sync);
    }

    #[tokio::test]
    async fn synced_ttl_removes_previously_persisted_ratchet() {
        let ok_addr = spawn_p2p_ack_stub().await;
        let (app, _temp_dir, _receiver) = setup_test_app();

        let invite = test_invite(6, "SyncPeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();
        app.set_peer_override_for_test(&hash, ok_addr);

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

        let shared_secret = app.shared_secret_for_test(&hash);
        let decrypted = try_ratchet_decrypt(
            &packet,
            &hash,
            shared_secret.expose(),
            &app.identity.hash,
            &app.storage,
            &app.ratchets,
            &app.retired_ratchet_sessions,
            false,
        )
        .0
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
            &app.ttl_tombstones,
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
        let shared_secret = app.shared_secret_for_test(&hash);

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
            shared_secret.expose(),
            &app.identity.hash,
            &app.storage,
            &app.ratchets,
            &app.retired_ratchet_sessions,
            false,
        )
        .0
        .expect("new bootstrap packet must decrypt");
        assert_eq!(decrypted.plaintext, b"fresh");

        // Старый bootstrap-пакет отклоняется как StaleSession.
        assert!(
            try_ratchet_decrypt(
                &bootstrap,
                &hash,
                shared_secret.expose(),
                &app.identity.hash,
                &app.storage,
                &app.ratchets,
                &app.retired_ratchet_sessions,
                false,
            )
            .0
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
        let shared_secret = app.shared_secret_for_test(&hash);

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
                shared_secret.expose(),
                &reopened.identity.hash,
                &reopened.storage,
                &reopened.ratchets,
                &reopened.retired_ratchet_sessions,
                false,
            )
            .0
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
            &app.ttl_tombstones,
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
    fn ttl_room_persists_only_tombstone_hash() {
        // H-3 + M-C: включение RAM-TTL убирает с диска ratchet и raw
        // session_id, но оставляет tombstone-хеш retired-сессии.
        let (app, temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        app.set_room_ttl(&hash, Some(30)).unwrap();
        let bootstrap = app.encrypt_with_ratchet(&hash, b"ttl-only").unwrap();
        let session_id = app
            .ratchets
            .lock()
            .unwrap()
            .get(&hash)
            .unwrap()
            .session_id();
        let expected_hash = ratchet::session_id_hash(&session_id);
        let expected_alias = ratchet::session_alias(&session_id).unwrap();
        app.clear_ratchet(&hash).unwrap();

        let persisted = app
            .get_storage()
            .load_retired_ratchet_sessions()
            .unwrap();
        assert!(persisted.iter().all(|(room_hash, _)| room_hash != &hash));
        assert!(app
            .get_storage()
            .load_ratchet_state(&hash)
            .unwrap()
            .is_none());

        let tombstones = app.get_storage().load_ttl_tombstones().unwrap();
        assert_eq!(tombstones.len(), 1);
        assert_eq!(tombstones[0].session_id_hash, expected_hash);
        assert_eq!(tombstones[0].session_alias, expected_alias);

        // В расшифрованном vault есть только hash; session_id и
        // bootstrap_nonce не сохраняются.
        let decrypted = app
            .get_storage()
            .persisted_snapshot_json_for_test()
            .unwrap();
        assert!(decrypted.contains(&hex::encode(expected_hash)));
        assert!(!decrypted.contains(&hex::encode(session_id)));
        assert!(decrypted.contains("\"ratchet_states\":[]"));
        assert!(decrypted.contains("\"retired_ratchet_sessions\":[]"));
        let bootstrap_nonce = &bootstrap[18..18 + ratchet::BOOTSTRAP_NONCE_SIZE];
        assert!(!decrypted.contains(&hex::encode(bootstrap_nonce)));

        // Vault остаётся читаемым после перезапуска.
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        drop(app);
        let vault = Vault::unlock(&base_dir, "test-password").unwrap();
        let (event_sender, _receiver) = mpsc::unbounded_channel();
        let reopened = App::new(Config::default(), base_dir, vault, event_sender).unwrap();
        assert_eq!(
            reopened.ttl_tombstones.lock().unwrap().snapshot(),
            vec![TtlTombstone {
                session_alias: expected_alias,
                session_id_hash: expected_hash,
                retired_at: tombstones[0].retired_at,
            }]
        );
    }

    #[tokio::test]
    async fn ttl_bootstrap_replay_is_stale_after_restart() {
        // M-C probe: старый bootstrap TTL-сессии не должен приниматься
        // после перезапуска как новая сессия (на старом коде тест падал:
        // сообщение TOP-SECRET-1 доходило).
        let (app, temp_dir, _receiver, hash) = setup_router_room();

        app.set_room_ttl(&hash, Some(60)).unwrap();
        let bootstrap = app
            .encrypt_with_ratchet(&hash, &crypto::encode_text_payload("TOP-SECRET-1", None))
            .unwrap();
        assert_ne!(bootstrap[1] & ratchet::FLAG_BOOTSTRAP, 0);
        let old_session = app
            .ratchets
            .lock()
            .unwrap()
            .get(&hash)
            .unwrap()
            .session_id();
        let old_hash = ratchet::session_id_hash(&old_session);

        // Рестарт-ретирация: TTL остаётся включённым, ratchet не пишется.
        app.clear_ratchet(&hash).unwrap();
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        drop(app);

        let vault = Vault::unlock(&base_dir, "test-password").unwrap();
        let (event_sender, _receiver) = mpsc::unbounded_channel();
        let reopened = App::new(Config::default(), base_dir, vault, event_sender).unwrap();
        assert!(
            reopened
                .ttl_tombstones
                .lock()
                .unwrap()
                .is_retired_session(&old_hash),
            "tombstone hash must survive restart"
        );

        deliver_packet(&reopened, bootstrap).await;

        assert!(
            reopened.get_messages(&hash, 10).unwrap().is_empty(),
            "replayed TTL bootstrap must not deliver TOP-SECRET-1"
        );
        assert!(
            reopened.ratchets.lock().unwrap().get(&hash).is_none(),
            "stale bootstrap must not create a new session"
        );
        let stats = reopened.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.decrypt_attempts, 0);
    }

    #[test]
    fn non_ttl_retirement_does_not_write_ttl_tombstones() {
        // M-C: единый механизм не включается для обычных комнат; H-2
        // продолжает работать через retired_ratchet_sessions.
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        app.encrypt_with_ratchet(&hash, b"normal").unwrap();
        let session_id = app
            .ratchets
            .lock()
            .unwrap()
            .get(&hash)
            .unwrap()
            .session_id();
        app.clear_ratchet(&hash).unwrap();

        assert!(app.get_storage().load_ttl_tombstones().unwrap().is_empty());
        assert!(app
            .get_storage()
            .load_retired_ratchet_sessions()
            .unwrap()
            .iter()
            .any(|(room, id)| room == &hash && id == &session_id));
    }

    #[test]
    fn ttl_tombstones_are_pruned_by_ttl_on_load() {
        // M-C: запись старше TOMBSTONE_TTL удаляется при загрузке.
        let (app, temp_dir, _receiver) = setup_test_app();
        let now = now_timestamp();
        let old = TtlTombstone {
            session_alias: [1u8; 16],
            session_id_hash: [2u8; 32],
            retired_at: now.saturating_sub(TOMBSTONE_TTL_SECS + 60),
        };
        let fresh = TtlTombstone {
            session_alias: [3u8; 16],
            session_id_hash: [4u8; 32],
            retired_at: now,
        };
        app.get_storage()
            .save_ttl_tombstones(&[old, fresh])
            .unwrap();
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        drop(app);

        let vault = Vault::unlock(&base_dir, "test-password").unwrap();
        let (event_sender, _receiver) = mpsc::unbounded_channel();
        let reopened = App::new(Config::default(), base_dir, vault, event_sender).unwrap();

        let entries = reopened.ttl_tombstones.lock().unwrap().snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].session_id_hash, fresh.session_id_hash);
        assert_eq!(
            reopened.get_storage().load_ttl_tombstones().unwrap(),
            vec![fresh]
        );
    }

    #[test]
    fn ttl_tombstones_evict_oldest_over_limit() {
        // M-C: при переполнении вытесняются старейшие записи (fail-open).
        let now = now_timestamp();
        let total = MAX_TTL_TOMBSTONES + 7;
        let entries: Vec<TtlTombstone> = (0..total)
            .map(|index| {
                let seed = index as u64;
                let mut alias = [0u8; 16];
                alias[..8].copy_from_slice(&seed.to_le_bytes());
                let mut hash = [0u8; 32];
                hash[..8].copy_from_slice(&seed.to_le_bytes());
                TtlTombstone {
                    session_alias: alias,
                    session_id_hash: hash,
                    retired_at: now.saturating_sub((total - index) as u64),
                }
            })
            .collect();

        let (registry, _) = TtlTombstoneRegistry::from_entries(entries.clone(), now);
        assert_eq!(registry.snapshot().len(), MAX_TTL_TOMBSTONES);
        assert!(!registry.is_retired_session(&entries[0].session_id_hash));
        assert!(registry.is_retired_session(&entries[total - 1].session_id_hash));

        // Тот же набор после записи/загрузки сохраняет лимит.
        let (app, temp_dir, _receiver) = setup_test_app();
        app.get_storage().save_ttl_tombstones(&entries).unwrap();
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        drop(app);

        let vault = Vault::unlock(&base_dir, "test-password").unwrap();
        let (event_sender, _receiver) = mpsc::unbounded_channel();
        let reopened = App::new(Config::default(), base_dir, vault, event_sender).unwrap();
        assert_eq!(
            reopened.ttl_tombstones.lock().unwrap().snapshot().len(),
            MAX_TTL_TOMBSTONES
        );
        let persisted = reopened.get_storage().load_ttl_tombstones().unwrap();
        assert_eq!(persisted.len(), MAX_TTL_TOMBSTONES);
        assert!(!persisted
            .iter()
            .any(|entry| entry.session_id_hash == entries[0].session_id_hash));
    }

    #[tokio::test]
    async fn foreign_alias_is_unknown_not_a_tombstone_match() {
        // M-C §3.4: чужой alias отклоняется как UnknownRoom после alias
        // lookup, а не как tombstone, и не доходит до AEAD.
        let (app, _temp_dir, _receiver, hash) = setup_router_room();
        app.ttl_tombstones.lock().unwrap().insert(TtlTombstone {
            session_alias: [9u8; 16],
            session_id_hash: [8u8; 32],
            retired_at: now_timestamp(),
        });

        let mut packet = app.encrypt_with_ratchet(&hash, b"foreign").unwrap();
        packet[2] ^= 0xff;
        packet[1] &= !ratchet::FLAG_BOOTSTRAP;
        deliver_packet(&app, packet).await;

        assert!(app.get_messages(&hash, 10).unwrap().is_empty());
        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.unknown_rooms, 1);
        assert_eq!(stats.decrypt_attempts, 0);
    }

    #[test]
    fn tampered_vault_with_ttl_tombstones_fails_closed() {
        // M-C/L-4: подмена байта в vault ломает AEAD и открытие, без паники.
        let (app, temp_dir, _receiver) = setup_test_app();
        app.get_storage()
            .save_ttl_tombstones(&[TtlTombstone {
                session_alias: [5u8; 16],
                session_id_hash: [6u8; 32],
                retired_at: now_timestamp(),
            }])
            .unwrap();
        let base_dir = temp_dir.path().to_str().unwrap().to_string();
        drop(app);

        let vault_path = temp_dir.path().join(crate::storage::VAULT_FILE_NAME);
        let mut bytes = std::fs::read(&vault_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&vault_path, bytes).unwrap();

        let vault = Vault::unlock(&base_dir, "test-password").unwrap();
        let (event_sender, _receiver) = mpsc::unbounded_channel();
        let result = App::new(Config::default(), base_dir, vault, event_sender);
        assert!(
            result.is_err(),
            "tampered vault must fail authentication instead of loading"
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
            &app.ttl_tombstones,
            &app.inbound_router,
            &app.identity.hash,
            &app.event_sender,
        )
        .await;
    }

    /// Пакет правильной v3-формы, но с мусорным зашифрованным заголовком.
    fn garbage_packet(
        alias: [u8; ratchet::SESSION_ALIAS_SIZE],
        bootstrap_nonce: Option<[u8; ratchet::BOOTSTRAP_NONCE_SIZE]>,
        nonce_seed: u64,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 256];
        packet[0] = ratchet::PROTOCOL_VERSION;
        packet[1] = if bootstrap_nonce.is_some() {
            ratchet::FLAG_BOOTSTRAP
        } else {
            0
        };
        packet[2..2 + ratchet::SESSION_ALIAS_SIZE].copy_from_slice(&alias);

        let mut offset = ratchet::OPEN_HEADER_FIXED;
        if let Some(bootstrap_nonce) = bootstrap_nonce {
            packet[offset..offset + ratchet::BOOTSTRAP_NONCE_SIZE]
                .copy_from_slice(&bootstrap_nonce);
            offset += ratchet::BOOTSTRAP_NONCE_SIZE;
        }
        let mut nonce = [0u8; ratchet::NONCE_SIZE];
        nonce[..8].copy_from_slice(&nonce_seed.to_le_bytes());
        packet[offset..offset + ratchet::NONCE_SIZE].copy_from_slice(&nonce);
        packet
    }

    #[tokio::test]
    async fn garbage_bootstrap_flood_has_bounded_hkdf_work() {
        // L-1: флуд случайными bootstrap-alias не должен вызывать HKDF по
        // всем контактам на каждый пакет. Лимитер режет всплеск, а счётчик
        // сканирований остаётся ограниченным.
        let (app, _temp_dir, _receiver, _hash) = setup_router_room();
        let room_count = app.shared_secrets.lock().unwrap().len() as u64;
        assert!(room_count >= 1);

        const FLOOD: u64 = 256;
        let started = std::time::Instant::now();
        for index in 0..FLOOD {
            let mut alias = [0u8; ratchet::SESSION_ALIAS_SIZE];
            alias[..8].copy_from_slice(&index.to_le_bytes());
            alias[8] = 0xA5;
            deliver_packet(&app, garbage_packet(alias, Some([0x5A; 32]), index)).await;
        }
        let elapsed = started.elapsed();

        let stats = app.inbound_router.lock().unwrap().stats();
        let refills =
            u64::try_from(elapsed.as_millis() / BOOTSTRAP_SCAN_REFILL.as_millis())
                .unwrap_or(u64::MAX);
        let allowed_scans = BOOTSTRAP_SCAN_BURST as u64 + refills + 1;
        assert!(
            stats.bootstrap_hkdf_attempts <= allowed_scans * room_count,
            "HKDF scans must be rate bounded: {} > {}",
            stats.bootstrap_hkdf_attempts,
            allowed_scans * room_count
        );
        assert!(
            stats.bootstrap_hkdf_attempts < FLOOD * room_count,
            "flood must not scan every packet"
        );
        assert!(stats.bootstrap_rate_limited > 0, "limiter must engage");
        assert_eq!(stats.decrypt_attempts, 0, "garbage has no valid room");
    }

    #[tokio::test]
    async fn garbage_for_live_alias_has_bounded_aead_attempts() {
        // L-2: мусорные пакеты с живым alias могут заставить храповик
        // перебирать эпохи, но не больше общего бюджета на пакет.
        let (app, _temp_dir, _receiver, hash) = setup_router_room();
        let live = app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let mut alias = [0u8; ratchet::SESSION_ALIAS_SIZE];
        alias.copy_from_slice(&live[2..2 + ratchet::SESSION_ALIAS_SIZE]);

        const FLOOD: u64 = 8;
        for index in 0..FLOOD {
            let before = app.inbound_router.lock().unwrap().stats().aead_attempts;
            deliver_packet(&app, garbage_packet(alias, None, index)).await;
            let after = app.inbound_router.lock().unwrap().stats().aead_attempts;
            assert!(
                after - before <= ratchet::MAX_AEAD_ATTEMPTS_PER_PACKET as u64,
                "one packet must not exceed the AEAD budget"
            );
        }

        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.decrypt_attempts, FLOOD);
        assert!(stats.aead_attempts > 0);
        assert!(
            stats.aead_attempts <= FLOOD * ratchet::MAX_AEAD_ATTEMPTS_PER_PACKET as u64,
            "AEAD work must stay bounded"
        );
        assert!(app.get_messages(&hash, 10).unwrap().is_empty());
    }

    #[tokio::test]
    async fn bootstrap_resolution_is_cached_per_alias() {
        // L-1: после успешного HKDF-резолва повторный bootstrap-пакет той же
        // сессии не должен снова перебирать контакты.
        let (app, _temp_dir, _receiver, hash) = setup_router_room();
        let live = app.encrypt_with_ratchet(&hash, b"prime").unwrap();
        let mut alias = [0u8; ratchet::SESSION_ALIAS_SIZE];
        alias.copy_from_slice(&live[2..2 + ratchet::SESSION_ALIAS_SIZE]);
        let mut bootstrap_nonce = [0u8; ratchet::BOOTSTRAP_NONCE_SIZE];
        bootstrap_nonce.copy_from_slice(
            &live[ratchet::OPEN_HEADER_FIXED
                ..ratchet::OPEN_HEADER_FIXED + ratchet::BOOTSTRAP_NONCE_SIZE],
        );

        // Снимаем живой маршрут, чтобы оба пакета шли через Unknown-bootstrap.
        app.inbound_router.lock().unwrap().remove_room(&hash);
        let room_count = app.shared_secrets.lock().unwrap().len() as u64;

        deliver_packet(&app, garbage_packet(alias, Some(bootstrap_nonce), 1)).await;
        deliver_packet(&app, garbage_packet(alias, Some(bootstrap_nonce), 2)).await;

        let stats = app.inbound_router.lock().unwrap().stats();
        assert_eq!(stats.bootstrap_cache_hits, 1, "second packet uses cache");
        assert_eq!(stats.decrypt_attempts, 2);
        assert!(stats.bootstrap_hkdf_attempts >= 2);
        assert!(
            stats.bootstrap_hkdf_attempts <= room_count + 1,
            "only one full scan plus one cached lookup are allowed"
        );
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
            &app.ttl_tombstones,
            &app.inbound_router,
            &app.room_ttls,
            &hash,
            false,
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

        let error = app.with_shared_secret(&hash, |_| Ok(())).unwrap_err();
        assert!(
            error.to_string().contains("shared secret lock poisoned"),
            "unexpected error: {error}"
        );
    }

    /// L-4: продакшн-путь отдаёт ссылку на значение в кэше, а не копию.
    /// Если `with_shared_secret` начнёт копировать секрет, указатели
    /// разойдутся и тест упадёт.
    #[test]
    fn with_shared_secret_exposes_cached_value_without_copy() {
        let (app, _temp_dir, _receiver) = setup_test_app();
        let hash = app.identity.hash.clone();

        let cached = {
            let secrets = app.shared_secrets.lock().unwrap();
            secrets
                .get(&hash)
                .expect("self secret is loaded at startup")
                .expose()
                .as_ptr()
        };
        let exposed = app
            .with_shared_secret(&hash, |secret| Ok(secret.expose().as_ptr()))
            .unwrap();

        assert_eq!(
            cached, exposed,
            "with_shared_secret must not copy the cached secret"
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

    #[tokio::test]
    async fn p2p_offline_send_enqueues_outbox_with_backoff() {
        let (app, _temp_dir, _receiver) = setup_test_app();
        let invite = test_invite(31, "OfflinePeer");
        let hash = invite.hash_hex();
        app.add_contact_with_ed25519(&invite).unwrap();

        let reject_addr = spawn_p2p_reject_stub().await;
        app.set_peer_override_for_test(&hash, reject_addr);

        app.send_message(&hash, "queued while offline").await.unwrap();
        assert_eq!(app.outbox_pending_count(), 1);
        assert_eq!(app.get_messages(&hash, 10).unwrap().len(), 1);

        let delivered = app.flush_outbox_for_test().await.unwrap();
        assert_eq!(delivered, 0);
        assert_eq!(app.outbox_pending_count(), 1);

        let future_due = app
            .get_storage()
            .due_outbox_items(i64::MAX)
            .unwrap();
        assert_eq!(future_due.len(), 1);
        assert_eq!(future_due[0].attempts, 1);
        assert!(future_due[0].last_error.is_some());
    }

    #[tokio::test]
    async fn p2p_loopback_end_to_end_delivery_and_ratchet() {
        let (alice, _dir_a, _rx_a) = setup_test_app();
        let (bob, _dir_b, mut rx_b) = setup_test_app();

        alice.set_own_onion_for_test(OnionAddress::test_v3_from_seed(11));
        bob.set_own_onion_for_test(OnionAddress::test_v3_from_seed(22));

        let bob_invite = IdentityInvite::from_link(&bob.get_my_contact_link().unwrap()).unwrap();
        let alice_invite =
            IdentityInvite::from_link(&alice.get_my_contact_link().unwrap()).unwrap();

        alice.add_contact_with_ed25519(&bob_invite).unwrap();
        bob.add_contact_with_ed25519(&alice_invite).unwrap();

        let (listener, bob_port) = bind_inbound_listener(0).await.unwrap();
        let bob_addr = std::net::SocketAddr::from(([127, 0, 0, 1], bob_port));

        let bob_shared = bob.shared_secrets.clone();
        let bob_storage = bob.storage.clone();
        let bob_ttls = bob.room_ttls.clone();
        let bob_ratchets = bob.ratchets.clone();
        let bob_retired = bob.retired_ratchet_sessions.clone();
        let bob_tombstones = bob.ttl_tombstones.clone();
        let bob_router = bob.inbound_router.clone();
        let bob_hash = bob.identity.hash.clone();
        let bob_events = bob.event_sender.clone();
        let server_task = tokio::spawn(serve_inbound(listener, move |packet| {
            let bob_shared = bob_shared.clone();
            let bob_storage = bob_storage.clone();
            let bob_ttls = bob_ttls.clone();
            let bob_ratchets = bob_ratchets.clone();
            let bob_retired = bob_retired.clone();
            let bob_tombstones = bob_tombstones.clone();
            let bob_router = bob_router.clone();
            let bob_hash = bob_hash.clone();
            let bob_events = bob_events.clone();
            async move {
                App::handle_incoming_packet(
                    packet,
                    &bob_shared,
                    &bob_storage,
                    &bob_ttls,
                    &bob_ratchets,
                    &bob_retired,
                    &bob_tombstones,
                    &bob_router,
                    &bob_hash,
                    &bob_events,
                )
                .await;
            }
        }));

        alice.set_peer_override_for_test(&bob.identity.hash, bob_addr);
        alice
            .send_message(&bob.identity.hash, "hello over pure p2p")
            .await
            .unwrap();
        assert_eq!(alice.outbox_pending_count(), 1);

        let delivered = alice.flush_outbox_for_test().await.unwrap();
        assert_eq!(delivered, 1);
        assert_eq!(alice.outbox_pending_count(), 0);

        let evt = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .expect("timed out waiting for inbound packet")
            .expect("event channel closed");
        match evt {
            AppEvent::NewMessage { text, room_hash, .. } => {
                assert_eq!(room_hash, alice.identity.hash);
                assert_eq!(text, "hello over pure p2p");
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let bob_msgs = bob.get_messages(&alice.identity.hash, 10).unwrap();
        assert_eq!(bob_msgs.len(), 1);
        assert_eq!(bob_msgs[0].text, "hello over pure p2p");

        server_task.abort();
    }
}
