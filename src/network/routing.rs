// src/network/routing.rs
//!
//! Адресация входящих пакетов по alias (M-8).
//!
//! В P2P-транспорте внутри входящего зашифрованного кадра открытым остаётся
//! только `session_alias` (см. `crypto::ratchet`, B/M-7).
//! Клиент держит таблицу `alias -> room` и выбирает комнату до любой
//! криптографии. Неизвестный alias — [`RoutingError::UnknownRoom`], а не повод
//! перебирать все контакты: перебор и был CPU-amplification, который убирает
//! этот блок.
//!
//! Alias уничтоженной сессии (H-1/H-2) попадает в отдельную таблицу retired
//! и отклоняется как [`RoutingError::StaleSession`] ещё до AEAD. Повторная
//! доставка отслеживается по `(alias, nonce)` с ограниченным TTL: запись
//! добавляется только после успешной расшифровки, поэтому мусорные пакеты
//! таблицу не заполняют.

use crate::crypto::ratchet::{
    packet_route_info, PacketRouteInfo, RatchetError, NONCE_SIZE, SESSION_ALIAS_SIZE,
};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

/// Alias сессии в открытом заголовке v3.
pub type Alias = [u8; SESSION_ALIAS_SIZE];
/// Ключ дедупликации: alias комнаты + AEAD nonce пакета.
pub type DeliveryKey = (Alias, [u8; NONCE_SIZE]);

/// Сколько помнить доставленный `(alias, nonce)`.
pub const DELIVERY_TTL: Duration = Duration::from_secs(300);
/// Жёсткий предел таблицы дедупликации (fail-closed по памяти, не по трафику).
pub const MAX_DELIVERY_ENTRIES: usize = 8192;

/// L-1: сколько успешных bootstrap-резолвов alias -> room помнить.
///
/// Кэш нужен, чтобы повторный bootstrap-пакет не запускал HKDF по всем
/// контактам. Ключ — alias, выведенный из `session_id`, поэтому подделать
/// запись без знания общего секрета нельзя.
pub const MAX_BOOTSTRAP_CACHE_ENTRIES: usize = 256;
/// L-1: всплеск HKDF-сканирований неизвестных bootstrap-пакетов.
pub const BOOTSTRAP_SCAN_BURST: u32 = 16;
/// L-1: пополнение бюджета сканирований — одно разрешение на интервал.
pub const BOOTSTRAP_SCAN_REFILL: Duration = Duration::from_millis(500);

/// Куда адресован входящий пакет.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Известная живая сессия комнаты.
    Active(String),
    /// Alias уничтоженной/вытесненной сессии: пакет устарел.
    Retired(String),
    /// Alias не принадлежит ни одной известной комнате.
    Unknown,
}

/// Типизированные причины отказа маршрутизации.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingError {
    /// Ни одна комната не заявила этот alias.
    UnknownRoom,
    /// Alias принадлежит retired-сессии (H-1/H-2).
    StaleSession,
    /// Пакет v1/v2: v3-only, fail-closed.
    UnsupportedVersion(u8),
    /// Пакет уже доставлялся (тот же alias + nonce).
    ReplayNonce,
    /// Размер пакета вне сетки bucket + рандомизация (M-2).
    InvalidPacketSize,
    /// Битый открытый заголовок или неизвестные флаги.
    MalformedPacket,
}

impl fmt::Display for RoutingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRoom => write!(f, "unknown room alias"),
            Self::StaleSession => write!(f, "packet belongs to a stale session"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported packet version {}", version)
            }
            Self::ReplayNonce => write!(f, "replayed packet nonce"),
            Self::InvalidPacketSize => write!(f, "packet size is outside the allowed bucket"),
            Self::MalformedPacket => write!(f, "malformed packet header"),
        }
    }
}

impl std::error::Error for RoutingError {}

impl From<RatchetError> for RoutingError {
    fn from(error: RatchetError) -> Self {
        match error {
            RatchetError::UnsupportedVersion(version) => Self::UnsupportedVersion(version),
            RatchetError::InvalidPacketSize => Self::InvalidPacketSize,
            _ => Self::MalformedPacket,
        }
    }
}

/// Счётчики для тестов и метрик. Не содержит идентификаторов.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoutingStats {
    pub lookups: u64,
    pub decrypt_attempts: u64,
    pub unknown_rooms: u64,
    pub stale_sessions: u64,
    pub replayed_packets: u64,
    /// L-1: сколько HKDF-сканований контактов выполнено для неизвестных
    /// bootstrap-пакетов (включая попадания в кэш alias -> room).
    pub bootstrap_hkdf_attempts: u64,
    /// L-1: сколько неизвестных bootstrap-пакетов отброшено лимитером.
    pub bootstrap_rate_limited: u64,
    /// L-1: сколько bootstrap-пакетов разрешено без сканирования контактов.
    pub bootstrap_cache_hits: u64,
    /// L-2: фактическое число AEAD-попыток в храповике.
    pub aead_attempts: u64,
}

/// L-1: token bucket для HKDF-сканирований неизвестных bootstrap-пакетов.
///
/// Один пакет стоит один токен независимо от числа контактов, поэтому
/// флуд случайными alias ограничен сверху `burst * contacts` HKDF-вызовами
/// на всплеск. Легитимный первый контакт может попасть под лимит во время
/// атаки; отказ временный, бюджет пополняется.
#[derive(Debug)]
struct BootstrapScanLimiter {
    tokens: u32,
    last_refill: Instant,
}

impl Default for BootstrapScanLimiter {
    fn default() -> Self {
        Self {
            tokens: BOOTSTRAP_SCAN_BURST,
            last_refill: Instant::now(),
        }
    }
}

impl BootstrapScanLimiter {
    fn allow(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill);
        let refill = u32::try_from(elapsed.as_millis() / BOOTSTRAP_SCAN_REFILL.as_millis())
            .unwrap_or(u32::MAX);
        if refill > 0 {
            self.tokens = self.tokens.saturating_add(refill).min(BOOTSTRAP_SCAN_BURST);
            self.last_refill += BOOTSTRAP_SCAN_REFILL * refill;
        }

        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }
}

/// Таблица alias -> комната и окно дедупликации доставки.
///
/// Таблица обновляется при создании/загрузке сессии, смене активной сессии,
/// reset/TTL и удалении контакта. Она не сериализуется: alias выводится из
/// `session_id`, который живёт в ratchet-состоянии.
#[derive(Default)]
pub struct InboundRouter {
    active: HashMap<Alias, String>,
    retired: HashMap<Alias, String>,
    seen: HashSet<DeliveryKey>,
    order: VecDeque<(Instant, DeliveryKey)>,
    delivery_ttl: Duration,
    /// L-1: положительный кэш bootstrap alias -> room.
    bootstrap_cache: HashMap<Alias, String>,
    bootstrap_cache_order: VecDeque<Alias>,
    bootstrap_limiter: BootstrapScanLimiter,
    stats: RoutingStats,
}

impl InboundRouter {
    pub fn new() -> Self {
        Self {
            delivery_ttl: DELIVERY_TTL,
            ..Self::default()
        }
    }

    /// Заменяет набор живых alias комнаты. Старые alias этой комнаты
    /// удаляются, чтобы reset/смена сессии не оставлял ложный маршрут.
    pub fn register_state(&mut self, room: &str, aliases: &[Alias]) {
        self.active.retain(|_, mapped| mapped != room);
        for alias in aliases {
            self.active.insert(*alias, room.to_string());
        }
    }

    /// Запоминает alias уничтоженных сессий комнаты.
    pub fn register_retired(&mut self, room: &str, aliases: &[Alias]) {
        for alias in aliases {
            self.retired.insert(*alias, room.to_string());
        }
    }

    /// Убирает живые маршруты комнаты и переносит её alias в retired.
    pub fn retire_room(&mut self, room: &str, aliases: &[Alias]) {
        self.active.retain(|_, mapped| mapped != room);
        self.register_retired(room, aliases);
    }

    /// Полностью забывает комнату (удаление контакта).
    pub fn remove_room(&mut self, room: &str) {
        self.active.retain(|_, mapped| mapped != room);
        self.retired.retain(|_, mapped| mapped != room);
        self.bootstrap_cache.retain(|_, mapped| mapped != room);
        let cache = &self.bootstrap_cache;
        self.bootstrap_cache_order
            .retain(|alias| cache.contains_key(alias));
    }

    /// L-1: возвращает закэшированную комнату для bootstrap-alias.
    pub fn cached_bootstrap_room(&mut self, alias: Alias) -> Option<String> {
        let room = self.bootstrap_cache.get(&alias).cloned();
        if room.is_some() {
            self.stats.bootstrap_cache_hits = self.stats.bootstrap_cache_hits.saturating_add(1);
        }
        room
    }

    /// L-1: запоминает успешный bootstrap-резолв alias -> room.
    ///
    /// Кэш ограничен по числу записей: старейший alias вытесняется, поэтому
    /// флуд не может раздувать память.
    pub fn cache_bootstrap_room(&mut self, alias: Alias, room: String) {
        if self.bootstrap_cache.insert(alias, room).is_none() {
            self.bootstrap_cache_order.push_back(alias);
        }

        while self.bootstrap_cache_order.len() > MAX_BOOTSTRAP_CACHE_ENTRIES {
            if let Some(evicted) = self.bootstrap_cache_order.pop_front() {
                self.bootstrap_cache.remove(&evicted);
            }
        }
    }

    /// L-1: разрешает одну попытку HKDF-резолва неизвестного bootstrap.
    pub fn allow_bootstrap_scan(&mut self, now: Instant) -> bool {
        if self.bootstrap_limiter.allow(now) {
            return true;
        }
        self.stats.bootstrap_rate_limited =
            self.stats.bootstrap_rate_limited.saturating_add(1);
        false
    }

    /// L-1: учитывает фактически выполненные HKDF-вызовы.
    pub fn note_bootstrap_hkdf(&mut self, attempts: usize) {
        self.stats.bootstrap_hkdf_attempts = self
            .stats
            .bootstrap_hkdf_attempts
            .saturating_add(attempts as u64);
    }

    /// L-2: учитывает AEAD-попытки, выполненные храповиком.
    pub fn note_aead_attempts(&mut self, attempts: usize) {
        self.stats.aead_attempts = self.stats.aead_attempts.saturating_add(attempts as u64);
    }

    /// Ищет комнату по alias, обновляя счётчики.
    pub fn route(&mut self, alias: Alias) -> Route {
        self.stats.lookups = self.stats.lookups.saturating_add(1);
        if let Some(room) = self.active.get(&alias) {
            return Route::Active(room.clone());
        }
        if let Some(room) = self.retired.get(&alias) {
            self.stats.stale_sessions = self.stats.stale_sessions.saturating_add(1);
            return Route::Retired(room.clone());
        }
        self.stats.unknown_rooms = self.stats.unknown_rooms.saturating_add(1);
        Route::Unknown
    }

    /// Разбирает открытый заголовок и сразу маршрутизирует пакет.
    pub fn resolve(
        &mut self,
        packet: &[u8],
    ) -> Result<(PacketRouteInfo, Route), RoutingError> {
        let info = packet_route_info(packet)?;
        let route = self.route(info.alias);
        Ok((info, route))
    }

    /// Отмечает, что приложение собирается вызвать расшифровку.
    ///
    /// Ровно один вызов на пакет; тесты проверяют, что при неизвестном
    /// alias счётчик не растёт.
    pub fn note_decrypt_attempt(&mut self) {
        self.stats.decrypt_attempts = self.stats.decrypt_attempts.saturating_add(1);
    }

    /// Проверяет, доставлялся ли уже этот пакет. Не вставляет запись.
    pub fn is_duplicate(&mut self, alias: Alias, nonce: &[u8; NONCE_SIZE], now: Instant) -> bool {
        self.purge_expired(now);
        let key = (alias, *nonce);
        if self.seen.contains(&key) {
            self.stats.replayed_packets = self.stats.replayed_packets.saturating_add(1);
            return true;
        }
        false
    }

    /// Запоминает успешно расшифрованный пакет.
    pub fn mark_delivered(&mut self, alias: Alias, nonce: &[u8; NONCE_SIZE], now: Instant) {
        self.purge_expired(now);
        let key = (alias, *nonce);
        if !self.seen.insert(key) {
            return;
        }
        self.order.push_back((now, key));

        while self.order.len() > MAX_DELIVERY_ENTRIES {
            if let Some((_, expired)) = self.order.pop_front() {
                self.seen.remove(&expired);
            }
        }
    }

    fn purge_expired(&mut self, now: Instant) {
        while let Some((at, key)) = self.order.front() {
            if now.saturating_duration_since(*at) < self.delivery_ttl {
                break;
            }
            let key = *key;
            self.order.pop_front();
            self.seen.remove(&key);
        }
    }

    pub fn stats(&self) -> RoutingStats {
        self.stats
    }

    #[cfg(test)]
    fn delivery_count(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ratchet::{RatchetState, Role};

    fn session(seed: u8) -> RatchetState {
        RatchetState::new(&[seed; 32], Role::Initiator).expect("ratchet state")
    }

    #[test]
    fn known_alias_routes_to_room_without_scan() {
        let mut router = InboundRouter::new();
        let mut state = session(1);
        let alias = state.active_alias().unwrap();
        router.register_state("room-a", &[alias]);

        let packet = state.encrypt(b"hello").unwrap();
        let (info, route) = router.resolve(&packet).unwrap();
        assert_eq!(info.alias, alias);
        assert_eq!(route, Route::Active("room-a".to_string()));

        router.note_decrypt_attempt();
        assert_eq!(router.stats().decrypt_attempts, 1);
        assert_eq!(router.stats().unknown_rooms, 0);
    }

    #[test]
    fn unknown_alias_is_rejected_with_zero_lookups_to_decrypt() {
        let mut router = InboundRouter::new();
        let mut state = session(2);
        let alias = state.active_alias().unwrap();
        router.register_state("room-a", &[alias]);

        let mut packet = state.encrypt(b"hello").unwrap();
        packet[2] ^= 0xff;

        let (_, route) = router.resolve(&packet).expect("header is still well formed");
        assert_eq!(route, Route::Unknown);
        assert_eq!(router.stats().decrypt_attempts, 0);
        assert_eq!(router.stats().unknown_rooms, 1);
    }

    #[test]
    fn retired_alias_is_stale_before_any_decrypt() {
        let mut router = InboundRouter::new();
        let state = session(3);
        let alias = state.active_alias().unwrap();

        router.register_state("room-a", &[alias]);
        router.retire_room("room-a", &[alias]);

        assert_eq!(router.route(alias), Route::Retired("room-a".to_string()));
        assert_eq!(router.stats().decrypt_attempts, 0);
        assert_eq!(router.stats().stale_sessions, 1);
    }

    #[test]
    fn v2_packet_is_unsupported_before_alias_lookup() {
        let mut router = InboundRouter::new();
        let mut packet = vec![0u8; 256];
        packet[0] = 2;

        assert_eq!(
            router.resolve(&packet).unwrap_err(),
            RoutingError::UnsupportedVersion(2)
        );
        assert_eq!(router.stats().lookups, 0);
    }

    #[test]
    fn oversized_packet_is_rejected_before_routing() {
        let mut router = InboundRouter::new();
        let mut packet = vec![0u8; crate::crypto::SIZE_MAX + crate::crypto::SIZE_MAX / 8 + 1];
        packet[0] = 3;

        assert_eq!(
            router.resolve(&packet).unwrap_err(),
            RoutingError::InvalidPacketSize
        );
        assert_eq!(router.stats().decrypt_attempts, 0);
    }

    #[test]
    fn delivery_dedup_is_bounded_and_expires() {
        let start = Instant::now();
        let mut router = InboundRouter::new();
        let alias = [9u8; SESSION_ALIAS_SIZE];
        let nonce = [7u8; NONCE_SIZE];

        assert!(!router.is_duplicate(alias, &nonce, start));
        router.mark_delivered(alias, &nonce, start);
        assert!(router.is_duplicate(alias, &nonce, start));
        assert_eq!(router.stats().replayed_packets, 1);

        // Другая комната с тем же nonce не считается повтором.
        assert!(!router.is_duplicate([8u8; SESSION_ALIAS_SIZE], &nonce, start));

        assert!(!router.is_duplicate(alias, &nonce, start + DELIVERY_TTL));
        assert_eq!(router.delivery_count(), 0);
    }

    #[test]
    fn registering_state_replaces_old_alias_for_room() {
        let mut router = InboundRouter::new();
        let old = [1u8; SESSION_ALIAS_SIZE];
        let new = [2u8; SESSION_ALIAS_SIZE];

        router.register_state("room", &[old]);
        router.register_state("room", &[new]);

        assert_eq!(router.route(old), Route::Unknown);
        assert_eq!(router.route(new), Route::Active("room".to_string()));
    }
}
