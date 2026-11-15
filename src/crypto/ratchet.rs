//! Double Ratchet для асинхронной доставки поверх X25519 + HKDF-SHA256.
//!
//! Каждая эпоха — это отдельный DH-шаг: одноразовая пара X25519, корневой
//! ключ эпохи (`RootKey`), цепочка отправки/приёма (`ChainKey`) и сообщения
//! с ключом `MessageKey`. Все секреты оборачиваются в [`Zeroizing`] и
//! затираются при вытеснении эпохи или после использования ключа сообщения.
//!
//! Эпохи хранятся в скользящем окне из [`MAX_EPOCHS`] элементов. Это
//! позволяет расшифровать пакеты, которые пришли не по порядку или были
//! отправлены обеими сторонами до получения обновления партнёра.
//!
//! # Bootstrap-эпоха (v3)
//!
//! Первая эпоха сессии раньше была детерминированной: `shared_secret`
//! полностью определял bootstrap-ключи. После `clear_ratchet()` следующая
//! сессия получала те же ключи, поэтому перехваченный bootstrap-пакет
//! (`n = 0`) можно было проиграть в новую сессию.
//!
//! Теперь `RatchetState::new()` генерирует свежий `bootstrap_nonce`
//! (32 байта) и выводит из него `session_id` и bootstrap-ключи:
//! `HKDF(salt = bootstrap_nonce, ikm = shared_secret, info = label-v3)`.
//! Nonce едет только в первом пакете сессии, `session_id` не передаётся
//! вообще, поэтому получатель восстанавливает контекст из nonce и общего
//! секрета. Каждая новая сессия имеет собственную энтропию.
//!
//! Состояние хранит несколько сессионных контекстов (по `session_id`):
//! это сохраняет корректность, когда обе стороны отправили первое сообщение
//! одновременно. Уничтоженные и вытесненные `session_id` попадают в
//! `retired`, и пакеты с ними отклоняются как [`RatchetError::StaleSession`]
//! даже при валидном теге.
//!
//! # Защита от replay эпох (H-2)
//!
//! Окно из [`MAX_EPOCHS`] эпох конечно, поэтому сам по себе `dh_pub`, однажды
//! принятый, нельзя считать новым после вытеснения: иначе повтор пакета
//! вытесненной эпохи создал бы эпоху заново. Каждая сессия помнит последние
//! [`MAX_SEEN_DH_PUBS`] принятых `dh_pub` (в порядке приёма). Пакет с
//! `dh_pub`, которого уже нет среди живых эпох, но который есть в реестре,
//! отклоняется как [`RatchetError::ReplayedDhPub`] до любой криптографии.
//! Реестр пополняется только после успешной аутентификации, поэтому мусорные
//! ключи от активного атакующего его не отравляют; новая сессия (новый
//! `session_id`) начинает с пустого реестра.
//!
//! `remote_pub` — это DH-ключ собеседника, на котором строится следующая
//! эпоха отправки. Пакет уже известной старой эпохи расшифровывается, но
//! `remote_pub` не откатывает. В v3 `epoch_id` аутентифицирован внутри
//! зашифрованного заголовка, поэтому first-sight старого `dh_pub` больше
//! не выглядит как новая эпоха: заголовок открывается только тем ключом,
//! который соответствует его `epoch_id`.
//!
//! При переполнении окна вытесняется только старейшая неактивная эпоха
//! (не та, на которую указывает `remote_pub`, и не самая новая). Если
//! вытеснять нечего, приём завершается [`RatchetError::EpochOverflow`]
//! с неизменным состоянием, а не молчаливой потерей активной эпохи.
//!
//! Формат пакета v3 (M-7):
//!
//! ```text
//! [ ver 3 ][ flags ][ session_alias 16 ][ bootstrap_nonce 32? ][ nonce 24 ]
//! [ encrypted header: dh_pub 32 | epoch_id 4 | n 4 | pn 4 | tag 16 ]
//! [ ciphertext ][ tag 16 ]
//! ```
//!
//! `bootstrap_nonce` присутствует только в первом пакете сессии
//! (`flags & 1`). `session_id` в открытом виде не передаётся: используется
//! псевдоним `HKDF(ikm = session_id, info = "route-v3")[..16]`. Открытый заголовок
//! и зашифрованный header целиком входят в AAD полезной нагрузки, поэтому
//! подмена `dh_pub`, `n`, `pn` или эпохи ломает AEAD.
//!
//! Ключ заголовка — `HKDF(session_header_secret, info = "hdr-v3" || epoch_id)`.
//! `session_header_secret` выводится из общего секрета и bootstrap-nonce и
//! живёт вместе с сессией; `epoch_id` ротирует ключ на каждой DH-эпохе.
//! Получатель перебирает известные id эпох и небольшое окно новых id, пока
//! заголовок не аутентифицируется.
//!
//! Внутри шифротекста лежит `[len u32][payload][random padding]`. Итоговый
//! размер пакета — `bucket + rand(0..=bucket/8)` для bucket из
//! [`ALLOWED_TOTAL_SIZES`], поэтому точный размер не коррелирует со
//! счётчиком `n` или объёмом сообщения.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use super::secret::SecretBytes;
use super::{validate_x25519_peer, ALLOWED_TOTAL_SIZES};

/// Версия wire-формата пакета. v1/v2 не поддерживаются (fail-closed).
pub const PROTOCOL_VERSION: u8 = 3;
/// Размер идентификатора сессии (в открытом виде не передаётся).
pub const SESSION_ID_SIZE: usize = 16;
/// Размер псевдонима сессии в открытом заголовке.
pub const SESSION_ALIAS_SIZE: usize = 16;
/// Размер bootstrap-nonce.
pub const BOOTSTRAP_NONCE_SIZE: usize = 32;
/// Максимум одновременно хранимых эпох (отправки и приёма по отдельности).
pub const MAX_EPOCHS: usize = 5;
/// Максимум запомненных `dh_pub` на сессию (защита от replay вытесненных
/// эпох). Должно быть заметно больше [`MAX_EPOCHS`], иначе реестр вытеснит
/// ключ раньше, чем окно эпох.
pub const MAX_SEEN_DH_PUBS: usize = 128;
/// Максимум пропущенных ключей внутри одной эпохи.
pub const MAX_SKIPPED_KEYS: usize = 32;
/// Максимум одновременно активных сессионных контекстов.
pub const MAX_SESSIONS: usize = 4;
/// Максимум запомненных `session_id`, которые больше нельзя принимать.
///
/// `session_id` меняется только при reset/TTL-переходе или вытеснении
/// сессии, но не на каждой DH-эпохе: одна живая сессия даёт не больше
/// одного tombstone. 128 записей покрывают 32 полных цикла окна из
/// [`MAX_SESSIONS`] сессий, поэтому легитимный поток не вытеснит нужный
/// tombstone раньше, чем истечёт окно replay-защиты.
pub const MAX_RETIRED_SESSIONS: usize = 128;
/// Флаг «пакет несёт bootstrap-nonce».
pub const FLAG_BOOTSTRAP: u8 = 0x01;
/// `version (1) + flags (1) + alias (16)`.
pub const OPEN_HEADER_FIXED: usize = 1 + 1 + SESSION_ALIAS_SIZE;
/// Открытый заголовок без bootstrap-nonce: fixed + AEAD nonce.
pub const OPEN_HEADER_MIN: usize = OPEN_HEADER_FIXED + NONCE_SIZE;
/// Зашифрованный header: `dh_pub (32) + epoch_id (4) + n (4) + pn (4)` + tag.
pub const ENCRYPTED_HEADER_SIZE: usize = 32 + 4 + 4 + 4 + TAG_SIZE;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

const HEADER_PLAINTEXT_SIZE: usize = 32 + 4 + 4 + 4;
/// Насколько вперёд искать `epoch_id` нового заголовка. Потеря большего
/// числа эпох подряд означает, что сессию нужно переустановить.
const MAX_HEADER_EPOCH_LOOKAHEAD: u32 = 64;

const KDF_SALT: &[u8] = b"lastchance-double-ratchet-v3";
const STATE_VERSION: u8 = 3;

/// Ошибки, которые вызывающий может отличить от прочих сбоев.
///
/// Оборачиваются в `anyhow::Error`; тесты и приложение достают их через
/// `downcast_ref`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetError {
    /// Пакет принадлежит уничтоженной или вытесненной сессии.
    StaleSession,
    /// Пакет собран по несовместимой версии протокола.
    UnsupportedVersion(u8),
    /// У незнакомой сессии отсутствует bootstrap-nonce.
    MissingBootstrapNonce,
    /// `dh_pub` уже принимался в этой сессии, но его эпоха вытеснена окном:
    /// такой пакет не открывает новую эпоху.
    ReplayedDhPub,
    /// Окно эпох заполнено, а вытеснить можно только активную эпоху.
    EpochOverflow,
    /// Длина пакета вне сетки bucket + рандомизация (M-8/M-2).
    InvalidPacketSize,
    /// Открытый заголовок битый или неизвестные флаги.
    MalformedHeader,
}

impl fmt::Display for RatchetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaleSession => write!(f, "ratchet packet belongs to a stale session"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported ratchet packet version: {}", version)
            }
            Self::MissingBootstrapNonce => {
                write!(f, "ratchet bootstrap packet has no bootstrap nonce")
            }
            Self::ReplayedDhPub => {
                write!(f, "ratchet packet reuses a dh_pub of an evicted epoch")
            }
            Self::EpochOverflow => write!(f, "ratchet epoch window is full"),
            Self::InvalidPacketSize => write!(
                f,
                "ratchet packet size is outside the allowed padding bucket"
            ),
            Self::MalformedHeader => write!(f, "malformed ratchet header"),
        }
    }
}

impl std::error::Error for RatchetError {}

/// Роль стороны в сессии. Определяется приложением по hash собеседников,
/// чтобы обе стороны вывели одинаковые bootstrap-ключи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
    /// Чат с самим собой: заголовок и локальные ключи зеркальны.
    SelfChat,
}

impl Role {
    fn byte(self) -> u8 {
        match self {
            Self::Initiator => 0,
            Self::Responder => 1,
            Self::SelfChat => 2,
        }
    }

    fn from_byte(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Initiator),
            1 => Ok(Self::Responder),
            2 => Ok(Self::SelfChat),
            other => Err(anyhow!("invalid ratchet role: {}", other)),
        }
    }

    fn local_label(self) -> &'static [u8] {
        match self {
            Self::Initiator => b"bootstrap-initiator-v3",
            Self::Responder => b"bootstrap-responder-v3",
            Self::SelfChat => b"bootstrap-self-v3",
        }
    }

    fn peer_label(self) -> &'static [u8] {
        match self {
            Self::Initiator => b"bootstrap-responder-v3",
            Self::Responder => b"bootstrap-initiator-v3",
            Self::SelfChat => b"bootstrap-self-v3",
        }
    }
}

/// Публичное описание сессии: идентификатор и bootstrap-nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SessionDescriptor {
    id: [u8; SESSION_ID_SIZE],
    nonce: [u8; BOOTSTRAP_NONCE_SIZE],
}

impl SessionDescriptor {
    /// Генерирует свежий nonce и выводит из него `session_id`.
    ///
    /// `session_id` не передаётся в открытом виде, поэтому получатель должен
    /// уметь восстановить его из bootstrap-nonce и общего секрета.
    fn generate(shared_secret: &[u8; 32]) -> Result<Self> {
        let mut nonce = [0u8; BOOTSTRAP_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        let id = derive_session_id(shared_secret, &nonce)?;
        Ok(Self { id, nonce })
    }

    fn id_from_nonce(
        shared_secret: &[u8; 32],
        nonce: &[u8; BOOTSTRAP_NONCE_SIZE],
    ) -> Result<Self> {
        Ok(Self {
            id: derive_session_id(shared_secret, nonce)?,
            nonce: *nonce,
        })
    }
}

/// Открытая часть заголовка v3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenHeader {
    alias: [u8; SESSION_ALIAS_SIZE],
    bootstrap_nonce: Option<[u8; BOOTSTRAP_NONCE_SIZE]>,
    nonce: [u8; NONCE_SIZE],
    /// Смещение зашифрованного заголовка (совпадает с длиной open-байтов).
    header_offset: usize,
}

impl OpenHeader {
    fn flags(&self) -> u8 {
        let mut flags = 0;
        if self.bootstrap_nonce.is_some() {
            flags |= FLAG_BOOTSTRAP;
        }
        flags
    }

    fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.header_offset);
        out.push(PROTOCOL_VERSION);
        out.push(self.flags());
        out.extend_from_slice(&self.alias);
        if let Some(nonce) = self.bootstrap_nonce {
            out.extend_from_slice(&nonce);
        }
        out.extend_from_slice(&self.nonce);
        debug_assert_eq!(out.len(), self.header_offset);
        out
    }

    /// Разбирает открытую часть и проверяет версию/флаги до криптографии.
    fn parse(packet: &[u8]) -> Result<Self> {
        if packet.len() < OPEN_HEADER_MIN {
            return Err(anyhow!(
                "ratchet packet is too short: {} bytes",
                packet.len()
            ));
        }
        if packet[0] != PROTOCOL_VERSION {
            return Err(RatchetError::UnsupportedVersion(packet[0]).into());
        }
        let flags = packet[1];
        if flags & !FLAG_BOOTSTRAP != 0 {
            return Err(anyhow!("unknown ratchet header flags: 0x{:02x}", flags));
        }

        let mut alias = [0u8; SESSION_ALIAS_SIZE];
        alias.copy_from_slice(&packet[2..2 + SESSION_ALIAS_SIZE]);

        let mut offset = OPEN_HEADER_FIXED;
        let bootstrap_nonce = if flags & FLAG_BOOTSTRAP != 0 {
            let end = offset + BOOTSTRAP_NONCE_SIZE;
            if packet.len() < end + NONCE_SIZE {
                return Err(anyhow!("truncated bootstrap ratchet header"));
            }
            let mut nonce = [0u8; BOOTSTRAP_NONCE_SIZE];
            nonce.copy_from_slice(&packet[offset..end]);
            offset = end;
            Some(nonce)
        } else {
            None
        };

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&packet[offset..offset + NONCE_SIZE]);
        let header_offset = offset + NONCE_SIZE;

        Ok(Self {
            alias,
            bootstrap_nonce,
            nonce,
            header_offset,
        })
    }

    fn aad<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        &packet[..self.header_offset]
    }

    fn payload_aad<'a>(&self, packet: &'a [u8]) -> &'a [u8] {
        &packet[..self.header_offset + ENCRYPTED_HEADER_SIZE]
    }
}

/// Открытая часть входящего пакета, доступная до любой криптографии.
///
/// Используется клиентом для маршрутизации по alias (M-8): версия, размер,
/// alias, AEAD nonce и (только для bootstrap-пакета) bootstrap-nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRouteInfo {
    pub version: u8,
    pub alias: [u8; SESSION_ALIAS_SIZE],
    pub nonce: [u8; NONCE_SIZE],
    pub bootstrap_nonce: Option<[u8; BOOTSTRAP_NONCE_SIZE]>,
}

impl PacketRouteInfo {
    pub fn is_bootstrap(&self) -> bool {
        self.bootstrap_nonce.is_some()
    }
}

/// Разбирает только открытый заголовок v3 и проверяет версию/размер.
///
/// Порядок намеренный (M-8): версия → сетка размеров → флаги/alias.
/// Никаких секретов и AEAD здесь нет, поэтому вызывать можно до выбора
/// комнаты. v1/v2 отклоняются как [`RatchetError::UnsupportedVersion`].
pub fn packet_route_info(packet: &[u8]) -> Result<PacketRouteInfo, RatchetError> {
    if packet.len() < OPEN_HEADER_MIN {
        return Err(RatchetError::MalformedHeader);
    }
    if packet[0] != PROTOCOL_VERSION {
        return Err(RatchetError::UnsupportedVersion(packet[0]));
    }
    if !is_valid_packet_len(packet.len()) {
        return Err(RatchetError::InvalidPacketSize);
    }
    if packet[1] & !FLAG_BOOTSTRAP != 0 {
        return Err(RatchetError::MalformedHeader);
    }

    let mut alias = [0u8; SESSION_ALIAS_SIZE];
    alias.copy_from_slice(&packet[2..2 + SESSION_ALIAS_SIZE]);

    let mut offset = OPEN_HEADER_FIXED;
    let bootstrap_nonce = if packet[1] & FLAG_BOOTSTRAP != 0 {
        let end = offset + BOOTSTRAP_NONCE_SIZE;
        if packet.len() < end + NONCE_SIZE {
            return Err(RatchetError::MalformedHeader);
        }
        let mut nonce = [0u8; BOOTSTRAP_NONCE_SIZE];
        nonce.copy_from_slice(&packet[offset..end]);
        offset = end;
        Some(nonce)
    } else {
        None
    };

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&packet[offset..offset + NONCE_SIZE]);

    Ok(PacketRouteInfo {
        version: packet[0],
        alias,
        nonce,
        bootstrap_nonce,
    })
}

/// Заголовок пакета после аутентифицированной расшифровки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatchetHeader {
    pub session_id: [u8; SESSION_ID_SIZE],
    pub bootstrap_nonce: Option<[u8; BOOTSTRAP_NONCE_SIZE]>,
    pub dh_pub: [u8; 32],
    pub epoch_id: u32,
    pub n: u32,
    pub pn: u32,
}

impl RatchetHeader {
    fn plaintext(&self) -> [u8; HEADER_PLAINTEXT_SIZE] {
        let mut out = [0u8; HEADER_PLAINTEXT_SIZE];
        out[..32].copy_from_slice(&self.dh_pub);
        out[32..36].copy_from_slice(&self.epoch_id.to_le_bytes());
        out[36..40].copy_from_slice(&self.n.to_le_bytes());
        out[40..44].copy_from_slice(&self.pn.to_le_bytes());
        out
    }

    fn from_plaintext(
        session_id: [u8; SESSION_ID_SIZE],
        bootstrap_nonce: Option<[u8; BOOTSTRAP_NONCE_SIZE]>,
        plaintext: &[u8],
    ) -> Result<Self> {
        if plaintext.len() != HEADER_PLAINTEXT_SIZE {
            return Err(anyhow!("invalid encrypted header length"));
        }
        let mut dh_pub = [0u8; 32];
        dh_pub.copy_from_slice(&plaintext[..32]);
        let epoch_id = u32::from_le_bytes(
            plaintext[32..36]
                .try_into()
                .map_err(|_| anyhow!("invalid ratchet epoch id"))?,
        );
        let n = u32::from_le_bytes(
            plaintext[36..40]
                .try_into()
                .map_err(|_| anyhow!("invalid ratchet message number"))?,
        );
        let pn = u32::from_le_bytes(
            plaintext[40..44]
                .try_into()
                .map_err(|_| anyhow!("invalid ratchet previous-chain number"))?,
        );
        Ok(Self {
            session_id,
            bootstrap_nonce,
            dh_pub,
            epoch_id,
            n,
            pn,
        })
    }
}

#[derive(Clone)]
struct KeyPair {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl KeyPair {
    fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret).to_bytes();
        Self {
            private: Zeroizing::new(secret.to_bytes()),
            public,
        }
    }

    fn from_private(private: [u8; 32]) -> Self {
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret).to_bytes();
        Self {
            private: Zeroizing::new(private),
            public,
        }
    }

    fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<[u8; 32]> {
        validate_x25519_peer(peer)?;

        let secret = StaticSecret::from(*self.private);
        let shared = secret.diffie_hellman(&PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(anyhow!(
                "invalid X25519 peer key: shared secret is all-zero (low-order point)"
            ));
        }
        Ok(shared.to_bytes())
    }
}

#[derive(Clone)]
struct SendEpoch {
    keypair: KeyPair,
    peer_pub: [u8; 32],
    root_key: Zeroizing<[u8; 32]>,
    chain_key: Zeroizing<[u8; 32]>,
    epoch_id: u32,
    index: u32,
    previous_chain_len: u32,
}

#[derive(Clone)]
struct RecvEpoch {
    peer_pub: [u8; 32],
    local_pub: [u8; 32],
    root_key: Zeroizing<[u8; 32]>,
    chain_key: Zeroizing<[u8; 32]>,
    epoch_id: u32,
    next_index: u32,
    skipped: BTreeMap<u32, Zeroizing<[u8; 32]>>,
}

/// Один сессионный контекст: собственные bootstrap-ключи, корень сессии
/// и окна эпох отправки/приёма.
struct Session {
    descriptor: SessionDescriptor,
    root: Zeroizing<[u8; 32]>,
    /// Секрет для шифрования заголовков. Ротируется вместе с сессией,
    /// а ключ заголовка — вместе с `epoch_id`.
    header_secret: Zeroizing<[u8; 32]>,
    local: KeyPair,
    peer_bootstrap_pub: [u8; 32],
    remote_pub: Option<[u8; 32]>,
    received_since_send: bool,
    /// Следующий `epoch_id` для исходящей эпохи.
    next_epoch_id: u32,
    /// Первый пакет сессии уже отправлен: bootstrap-nonce больше не нужен.
    bootstrap_sent: bool,
    send_epochs: VecDeque<SendEpoch>,
    recv_epochs: VecDeque<RecvEpoch>,
    /// `epoch_id` вытесненных эпох приёма. Нужны, чтобы открыть заголовок
    /// запоздавшего пакета и вернуть типизированный `ReplayedDhPub`, а не
    /// общую ошибку аутентификации.
    retired_epoch_ids: VecDeque<u32>,
    /// `dh_pub` собеседника, которые уже были приняты аутентифицированным
    /// пакетом. Живёт вместе с сессией и ограничен [`MAX_SEEN_DH_PUBS`].
    seen_dh_pubs: VecDeque<[u8; 32]>,
}

impl Session {
    /// Выводит контекст из `shared_secret` и публичного дескриптора сессии.
    ///
    /// Дескриптор едет в пакете, поэтому получатель может построить тот же
    /// контекст без предварительного обмена. Свежий nonce даёт новую
    /// bootstrap-энтропию после каждого reset.
    fn derive(shared_secret: &[u8; 32], role: Role, descriptor: SessionDescriptor) -> Result<Self> {
        let root = expand_salted(shared_secret, &descriptor.nonce, b"bootstrap-root-v3")?;
        let header_secret =
            expand_salted(shared_secret, &descriptor.nonce, b"header-secret-v3")?;
        let local_private = expand_salted(shared_secret, &descriptor.nonce, role.local_label())?;
        let peer_private = expand_salted(shared_secret, &descriptor.nonce, role.peer_label())?;

        let local = KeyPair::from_private(*local_private);
        let peer_bootstrap_pub = PublicKey::from(&StaticSecret::from(*peer_private)).to_bytes();

        Ok(Self {
            descriptor,
            root,
            header_secret,
            local,
            peer_bootstrap_pub,
            remote_pub: None,
            received_since_send: false,
            next_epoch_id: 0,
            bootstrap_sent: false,
            send_epochs: VecDeque::new(),
            recv_epochs: VecDeque::new(),
            retired_epoch_ids: VecDeque::new(),
            seen_dh_pubs: VecDeque::new(),
        })
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.ensure_send_epoch()?;

        let epoch = self
            .send_epochs
            .back_mut()
            .ok_or_else(|| anyhow!("ratchet has no send epoch"))?;

        let bootstrap_nonce = if self.bootstrap_sent {
            None
        } else {
            Some(self.descriptor.nonce)
        };
        let header = RatchetHeader {
            session_id: self.descriptor.id,
            bootstrap_nonce,
            dh_pub: epoch.keypair.public,
            epoch_id: epoch.epoch_id,
            n: epoch.index,
            pn: epoch.previous_chain_len,
        };

        let message_key = derive_message_key(&epoch.chain_key, epoch.index)?;
        epoch.chain_key = advance_chain(&epoch.chain_key)?;
        epoch.index = epoch
            .index
            .checked_add(1)
            .ok_or_else(|| anyhow!("ratchet message counter overflow"))?;

        // Ключ сообщения затирается при drop сразу после шифрования.
        let packet = seal_packet(
            &header,
            &self.header_secret,
            &message_key,
            plaintext,
        )?;
        drop(message_key);

        self.bootstrap_sent = true;
        self.received_since_send = false;
        Ok(packet)
    }

    /// Расшифровывает зашифрованный заголовок, перебирая известные эпохи и
    /// небольшое окно новых `epoch_id`.
    fn open_header(&self, open: &OpenHeader, packet: &[u8]) -> Result<RatchetHeader> {
        if packet.len()
            < open.header_offset + ENCRYPTED_HEADER_SIZE + TAG_SIZE
        {
            return Err(anyhow!("ratchet packet is too short for v3 header"));
        }

        let mut candidates: Vec<u32> = self
            .recv_epochs
            .iter()
            .map(|epoch| epoch.epoch_id)
            .collect();
        candidates.extend(self.retired_epoch_ids.iter().copied());
        let max_known = candidates.iter().copied().max();
        let start = max_known.map_or(0, |value| value.saturating_add(1));
        for offset in 0..MAX_HEADER_EPOCH_LOOKAHEAD {
            candidates.push(start.saturating_add(offset));
        }
        candidates.sort_unstable();
        candidates.dedup();

        let aad = open.aad(packet);
        let encrypted = &packet
            [open.header_offset..open.header_offset + ENCRYPTED_HEADER_SIZE];

        for epoch_id in candidates {
            let key = derive_header_key(&self.header_secret, epoch_id)?;
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
                .map_err(|_| anyhow!("invalid ratchet header key"))?;
            let plaintext = match cipher.decrypt(
                XNonce::from_slice(&open.nonce),
                Payload {
                    msg: encrypted,
                    aad,
                },
            ) {
                Ok(plaintext) => Zeroizing::new(plaintext),
                Err(_) => continue,
            };

            let header = RatchetHeader::from_plaintext(
                self.descriptor.id,
                open.bootstrap_nonce,
                plaintext.as_slice(),
            )?;
            if header.epoch_id != epoch_id {
                // Аутентифицированный заголовок обязан совпадать с ключом,
                // которым он был открыт.
                return Err(anyhow!("ratchet header epoch id mismatch"));
            }
            return Ok(header);
        }

        Err(anyhow!("ratchet header authentication failed"))
    }

    fn decrypt(&mut self, open: &OpenHeader, packet: &[u8]) -> Result<Vec<u8>> {
        let header = self.open_header(open, packet)?;

        let mut order: Vec<usize> = (0..self.recv_epochs.len()).collect();
        let mut known_peer = false;
        if let Some(pos) = self
            .recv_epochs
            .iter()
            .position(|epoch| epoch.peer_pub == header.dh_pub)
        {
            known_peer = true;
            order.retain(|index| *index != pos);
            order.insert(0, pos);
        }

        for index in order {
            let mut candidate = self.recv_epochs[index].clone();
            if let Ok(plaintext) = decrypt_with_epoch(&mut candidate, open, &header, packet) {
                self.recv_epochs[index] = candidate;
                self.note_accepted_epoch(index);
                return Ok(plaintext);
            }
        }

        // Для уже известной эпохи повторная доставка или пакет из будущего
        // не должны создавать новую цепочку: иначе replay прошёл бы снова.
        if known_peer {
            return Err(anyhow!(
                "ratchet packet does not match the active receiving chain"
            ));
        }

        // Ключ уже принимался, но его эпоха вытеснена окном. Такой пакет
        // не открывает «новую» эпоху: это replay.
        if self.seen_dh_pubs.contains(&header.dh_pub) {
            return Err(RatchetError::ReplayedDhPub.into());
        }

        // Новая эпоха: пробуем все локальные приватные ключи из окна.
        for keypair in self.local_key_candidates() {
            let dh = keypair.diffie_hellman(&header.dh_pub)?;
            let root_key =
                derive_epoch_root(&self.root, dh, &keypair.public, &header.dh_pub)?;
            let chain_key = derive_chain_key(&root_key, &header.dh_pub, &keypair.public)?;

            let mut epoch = RecvEpoch {
                peer_pub: header.dh_pub,
                local_pub: keypair.public,
                root_key,
                chain_key,
                epoch_id: header.epoch_id,
                next_index: 0,
                skipped: BTreeMap::new(),
            };

            if let Ok(plaintext) = decrypt_with_epoch(&mut epoch, open, &header, packet) {
                // Сначала окно (может отказать с EpochOverflow), затем реестр:
                // отклонённый ключ не должен блокировать будущий легитимный.
                self.push_recv_epoch(epoch)?;
                self.remember_dh_pub(header.dh_pub);
                self.note_accepted_epoch(self.recv_epochs.len() - 1);
                return Ok(plaintext);
            }
        }

        Err(anyhow!(
            "ratchet decryption failed: no active epoch matches the packet"
        ))
    }

    /// Фиксирует принятую эпоху: двигает `remote_pub` только вперёд.
    ///
    /// `position` — место эпохи в окне приёма. Новые эпохи добавляются в
    /// конец, поэтому пакет уже известной старой эпохи не откатывает
    /// `remote_pub` к прежнему DH-ключу.
    fn note_accepted_epoch(&mut self, position: usize) {
        let Some(peer_pub) = self.recv_epochs.get(position).map(|epoch| epoch.peer_pub) else {
            return;
        };

        let remote_position = self.remote_pub.and_then(|remote| {
            self.recv_epochs
                .iter()
                .position(|epoch| epoch.peer_pub == remote)
        });

        if remote_position.is_none_or(|current| position >= current) {
            self.remote_pub = Some(peer_pub);
        }
        self.received_since_send = true;
    }

    /// Добавляет принятую эпоху в окно, вытесняя только старейшую
    /// неактивную и никогда — самую новую или эпоху `remote_pub`.
    fn push_recv_epoch(&mut self, epoch: RecvEpoch) -> Result<()> {
        self.recv_epochs.push_back(epoch);
        while self.recv_epochs.len() > MAX_EPOCHS {
            let newest = self.recv_epochs.len() - 1;
            let remote = self.remote_pub;
            let victim = (0..newest)
                .find(|index| Some(self.recv_epochs[*index].peer_pub) != remote);

            match victim {
                Some(index) => {
                    if let Some(removed) = self.recv_epochs.remove(index) {
                        self.remember_retired_epoch(removed.epoch_id);
                    }
                }
                None => {
                    // Откатываем приём: состояние остаётся таким же, каким
                    // было до пакета, вместо молчаливой потери активной эпохи.
                    self.recv_epochs.pop_back();
                    return Err(RatchetError::EpochOverflow.into());
                }
            }
        }
        Ok(())
    }

    /// Запоминает `dh_pub` только после успешной аутентификации, иначе
    /// активный атакующий мог бы отравить реестр случайными ключами.
    fn remember_dh_pub(&mut self, dh_pub: [u8; 32]) {
        if self.seen_dh_pubs.contains(&dh_pub) {
            return;
        }
        self.seen_dh_pubs.push_back(dh_pub);
        while self.seen_dh_pubs.len() > MAX_SEEN_DH_PUBS {
            self.seen_dh_pubs.pop_front();
        }
    }

    fn remember_retired_epoch(&mut self, epoch_id: u32) {
        if self.retired_epoch_ids.contains(&epoch_id) {
            return;
        }
        self.retired_epoch_ids.push_back(epoch_id);
        while self.retired_epoch_ids.len() > MAX_SEEN_DH_PUBS {
            self.retired_epoch_ids.pop_front();
        }
    }

    fn ensure_send_epoch(&mut self) -> Result<()> {
        let target = self.remote_pub.unwrap_or(self.peer_bootstrap_pub);

        let needs_new_epoch = match self.send_epochs.back() {
            None => true,
            Some(epoch) => epoch.peer_pub != target || self.received_since_send,
        };

        if !needs_new_epoch {
            return Ok(());
        }

        let keypair = if self.send_epochs.is_empty() {
            self.local.clone()
        } else {
            KeyPair::generate()
        };

        let previous_chain_len = self.send_epochs.back().map(|epoch| epoch.index).unwrap_or(0);
        let dh = keypair.diffie_hellman(&target)?;
        let root_key = derive_epoch_root(&self.root, dh, &keypair.public, &target)?;
        let chain_key = derive_chain_key(&root_key, &keypair.public, &target)?;

        let epoch_id = self.next_epoch_id;
        self.next_epoch_id = self
            .next_epoch_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("ratchet epoch id overflow"))?;

        self.send_epochs.push_back(SendEpoch {
            keypair,
            peer_pub: target,
            root_key,
            chain_key,
            epoch_id,
            index: 0,
            previous_chain_len,
        });

        while self.send_epochs.len() > MAX_EPOCHS {
            self.send_epochs.pop_front();
        }

        Ok(())
    }

    fn local_key_candidates(&self) -> Vec<KeyPair> {
        if self.send_epochs.is_empty() {
            vec![self.local.clone()]
        } else {
            self.send_epochs
                .iter()
                .rev()
                .map(|epoch| epoch.keypair.clone())
                .collect()
        }
    }
}

/// Состояние Double Ratchet для одной комнаты.
pub struct RatchetState {
    role: Role,
    sessions: VecDeque<Session>,
    active: [u8; SESSION_ID_SIZE],
    /// `session_id` уничтоженных сессий: пакеты с ними не принимаются,
    /// даже если криптографически валидны.
    retired: Vec<[u8; SESSION_ID_SIZE]>,
}

impl RatchetState {
    /// Создаёт сессию из общего долгосрочного секрета контакта со свежей
    /// bootstrap-энтропией.
    pub fn new(shared_secret: &[u8; 32], role: Role) -> Result<Self> {
        Self::new_with_retired(shared_secret, role, Vec::new())
    }

    /// То же самое, но с переносом списка `session_id`, которые были
    /// уничтожены до создания этого состояния (reset, выключение TTL).
    pub fn new_with_retired(
        shared_secret: &[u8; 32],
        role: Role,
        retired: Vec<[u8; SESSION_ID_SIZE]>,
    ) -> Result<Self> {
        let descriptor = SessionDescriptor::generate(shared_secret)?;
        let session = Session::derive(shared_secret, role, descriptor)?;

        let mut sessions = VecDeque::new();
        sessions.push_back(session);

        let mut state = Self {
            role,
            sessions,
            active: descriptor.id,
            retired: Vec::new(),
        };
        state.retire_sessions(retired);
        Ok(state)
    }

    /// Шифрует сообщение в текущей эпохе отправки активной сессии.
    ///
    /// Если с прошлой отправки пришло сообщение партнёра, создаётся новая
    /// эпоха со свежей X25519-парой. Внутри одной эпохи номер сообщения
    /// увеличивается, поэтому несколько сообщений подряд не тратят DH-шаги.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let active = self.active;
        let session = self
            .sessions
            .iter_mut()
            .find(|session| session.descriptor.id == active)
            .ok_or_else(|| anyhow!("active ratchet session is missing"))?;
        session.encrypt(plaintext)
    }

    /// Расшифровывает пакет, подбирая сессию по `session_id`, а эпоху —
    /// по публичному ключу или перебирая активное окно по Poly1305-тегу.
    ///
    /// `shared_secret` нужен только для незнакомой сессии: из её nonce
    /// выводится новый контекст. Пакеты уничтоженных сессий отклоняются
    /// как [`RatchetError::StaleSession`].
    pub fn decrypt(&mut self, packet: &[u8], shared_secret: &[u8; 32]) -> Result<Vec<u8>> {
        if !is_valid_packet_len(packet.len()) {
            return Err(anyhow!(
                "invalid ratchet packet size {}: expected a bucket + randomized padding",
                packet.len()
            ));
        }

        let open = OpenHeader::parse(packet)?;

        for retired in &self.retired {
            if session_alias(retired)? == open.alias {
                return Err(RatchetError::StaleSession.into());
            }
        }

        let mut matched = None;
        for (index, session) in self.sessions.iter().enumerate() {
            if session_alias(&session.descriptor.id)? == open.alias {
                matched = Some(index);
                break;
            }
        }

        if let Some(index) = matched {
            let plaintext = self.sessions[index].decrypt(&open, packet)?;
            self.active = self.sessions[index].descriptor.id;
            return Ok(plaintext);
        }

        // Незнакомая сессия: без bootstrap-nonce её контекст не вывести.
        let bootstrap_nonce = open
            .bootstrap_nonce
            .ok_or(RatchetError::MissingBootstrapNonce)?;
        if bootstrap_nonce == [0u8; BOOTSTRAP_NONCE_SIZE] {
            return Err(RatchetError::MissingBootstrapNonce.into());
        }

        let descriptor =
            SessionDescriptor::id_from_nonce(shared_secret, &bootstrap_nonce)?;
        if session_alias(&descriptor.id)? != open.alias {
            return Err(anyhow!(
                "bootstrap ratchet alias does not match the derived session"
            ));
        }

        let mut session = Session::derive(shared_secret, self.role, descriptor)?;
        let plaintext = session.decrypt(&open, packet)?;

        self.active = descriptor.id;
        self.sessions.push_back(session);
        self.evict_sessions();
        Ok(plaintext)
    }

    /// Тестовый помощник: открывает зашифрованный заголовок пакета.
    ///
    /// В продакшн-коде открытый заголовок доступен только внутри ratchet.
    #[cfg(test)]
    pub(crate) fn header_for_test(&self, packet: &[u8]) -> Result<RatchetHeader> {
        let open = OpenHeader::parse(packet)?;
        for session in &self.sessions {
            if session_alias(&session.descriptor.id)? == open.alias {
                return session.open_header(&open, packet);
            }
        }
        Err(anyhow!("no session matches the packet alias"))
    }

    /// Помечает сессии уничтоженными и убирает их контексты.
    ///
    /// Активная сессия не может быть уничтожена: вызывающий сначала
    /// создаёт новое состояние.
    pub fn retire_sessions(
        &mut self,
        session_ids: impl IntoIterator<Item = [u8; SESSION_ID_SIZE]>,
    ) {
        for session_id in session_ids {
            if session_id == self.active {
                continue;
            }
            self.sessions
                .retain(|session| session.descriptor.id != session_id);
            self.remember_retired(session_id);
        }
    }

    /// `session_id` активной сессии.
    pub fn session_id(&self) -> [u8; SESSION_ID_SIZE] {
        self.active
    }

    /// Alias активной сессии — адрес входящего пакета (M-8).
    pub fn active_alias(&self) -> Result<[u8; SESSION_ALIAS_SIZE]> {
        session_alias(&self.active)
    }

    /// Alias всех живых сессионных контекстов комнаты.
    pub fn session_aliases(&self) -> Result<Vec<[u8; SESSION_ALIAS_SIZE]>> {
        self.sessions
            .iter()
            .map(|session| session_alias(&session.descriptor.id))
            .collect()
    }

    /// Alias уничтоженных/вытесненных сессий: по ним пакет отклоняется
    /// как [`RatchetError::StaleSession`] без попытки расшифровки.
    pub fn retired_aliases(&self) -> Result<Vec<[u8; SESSION_ALIAS_SIZE]>> {
        self.retired
            .iter()
            .map(session_alias)
            .collect()
    }

    /// Все `session_id`, которые уже нельзя принимать: активные контексты
    /// и уничтоженные сессии.
    pub fn session_ids(&self) -> Vec<[u8; SESSION_ID_SIZE]> {
        let mut ids: Vec<[u8; SESSION_ID_SIZE]> = self
            .sessions
            .iter()
            .map(|session| session.descriptor.id)
            .collect();
        ids.extend(self.retired.iter().copied());
        ids
    }

    fn remember_retired(&mut self, session_id: [u8; SESSION_ID_SIZE]) {
        if self.retired.contains(&session_id) {
            return;
        }
        self.retired.push(session_id);
        if self.retired.len() > MAX_RETIRED_SESSIONS {
            self.retired.remove(0);
        }
    }

    /// Оставляет не больше [`MAX_SESSIONS`] контекстов, запоминая
    /// вытесненные `session_id` как уничтоженные.
    fn evict_sessions(&mut self) {
        while self.sessions.len() > MAX_SESSIONS {
            let victim = self
                .sessions
                .iter()
                .position(|session| session.descriptor.id != self.active);
            match victim {
                Some(index) => {
                    if let Some(session) = self.sessions.remove(index) {
                        self.remember_retired(session.descriptor.id);
                    }
                }
                None => break,
            }
        }
    }

    fn active_session(&self) -> Option<&Session> {
        self.sessions
            .iter()
            .find(|session| session.descriptor.id == self.active)
    }

    /// Текущий публичный DH-ключ отправки.
    pub fn current_dh_public(&self) -> Option<[u8; 32]> {
        self.active_session()
            .and_then(|session| session.send_epochs.back())
            .map(|epoch| epoch.keypair.public)
    }

    /// Доступ к корневому ключу текущей эпохи отправки без копирования
    /// наружу.
    ///
    /// Замыкание получает срез живого корневого ключа; скопировать его
    /// вызывающий может только явно (`*root`), что видно при аудите.
    /// Возвращает `None`, если эпохи отправки ещё нет.
    pub fn with_root_key<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Option<R> {
        self.active_session()
            .and_then(|session| session.send_epochs.back())
            .map(|epoch| f(&epoch.root_key))
    }

    pub fn send_epoch_count(&self) -> usize {
        self.sessions
            .iter()
            .map(|session| session.send_epochs.len())
            .sum()
    }

    pub fn recv_epoch_count(&self) -> usize {
        self.sessions
            .iter()
            .map(|session| session.recv_epochs.len())
            .sum()
    }

    pub fn skipped_key_count(&self) -> usize {
        self.sessions
            .iter()
            .flat_map(|session| session.recv_epochs.iter())
            .map(|epoch| epoch.skipped.len())
            .sum()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// Сериализует состояние для зашифрованного `vault.dat`.
    ///
    /// Буфер сериализации и промежуточные hex-строки затираются. Результат
    /// обёрнут в [`SecretBytes`], чтобы вызывающий не мог забыть затереть
    /// снапшот: это делается автоматически при `drop`.
    pub fn to_bytes(&self) -> Result<SecretBytes> {
        let mut raw = RawState {
            version: STATE_VERSION,
            role: self.role.byte(),
            active: hex::encode(self.active),
            retired: self.retired.iter().map(hex::encode).collect(),
            sessions: self
                .sessions
                .iter()
                .map(|session| RawSession {
                    id: hex::encode(session.descriptor.id),
                    nonce: hex::encode(session.descriptor.nonce),
                    root: hex::encode(*session.root),
                    header_secret: hex::encode(*session.header_secret),
                    next_epoch_id: session.next_epoch_id,
                    bootstrap_sent: session.bootstrap_sent,
                    local_private: hex::encode(*session.local.private),
                    local_public: hex::encode(session.local.public),
                    peer_bootstrap_pub: hex::encode(session.peer_bootstrap_pub),
                    remote_pub: session.remote_pub.map(hex::encode),
                    received_since_send: session.received_since_send,
                    retired_epoch_ids: session.retired_epoch_ids.iter().copied().collect(),
                    seen_dh_pubs: session
                        .seen_dh_pubs
                        .iter()
                        .map(hex::encode)
                        .collect(),
                    send_epochs: session
                        .send_epochs
                        .iter()
                        .map(|epoch| RawSendEpoch {
                            private: hex::encode(*epoch.keypair.private),
                            public: hex::encode(epoch.keypair.public),
                            peer_pub: hex::encode(epoch.peer_pub),
                            root_key: hex::encode(*epoch.root_key),
                            chain_key: hex::encode(*epoch.chain_key),
                            epoch_id: epoch.epoch_id,
                            index: epoch.index,
                            previous_chain_len: epoch.previous_chain_len,
                        })
                        .collect(),
                    recv_epochs: session
                        .recv_epochs
                        .iter()
                        .map(|epoch| RawRecvEpoch {
                            peer_pub: hex::encode(epoch.peer_pub),
                            local_pub: hex::encode(epoch.local_pub),
                            root_key: hex::encode(*epoch.root_key),
                            chain_key: hex::encode(*epoch.chain_key),
                            epoch_id: epoch.epoch_id,
                            next_index: epoch.next_index,
                            skipped: epoch
                                .skipped
                                .iter()
                                .map(|(index, key)| RawSkipped {
                                    index: *index,
                                    key: hex::encode(**key),
                                })
                                .collect(),
                        })
                        .collect(),
                })
                .collect(),
        };

        let bytes = serde_json::to_vec(&raw)
            .map_err(|e| anyhow!("failed to serialize ratchet state: {}", e))?;
        raw.wipe();
        Ok(SecretBytes::new(bytes))
    }

    /// Восстанавливает состояние из `vault.dat`.
    ///
    /// Принимает владение секретным буфером: после `from_bytes` он больше
    /// не нужен и затирается при `drop` (в том числе на пути ошибки).
    pub fn from_bytes(bytes: SecretBytes) -> Result<Self> {
        let mut raw: RawState = serde_json::from_slice(bytes.expose())
            .map_err(|e| anyhow!("failed to parse ratchet state: {}", e))?;

        let result = Self::from_raw(&raw);
        raw.wipe();
        result
    }

    fn from_raw(raw: &RawState) -> Result<Self> {
        if raw.version != STATE_VERSION {
            return Err(anyhow!(
                "unsupported ratchet state version: {}",
                raw.version
            ));
        }

        let role = Role::from_byte(raw.role)?;

        let mut sessions = VecDeque::new();
        for session in &raw.sessions {
            let mut send_epochs = VecDeque::new();
            for epoch in &session.send_epochs {
                send_epochs.push_back(SendEpoch {
                    keypair: KeyPair {
                        private: Zeroizing::new(decode32(&epoch.private)?),
                        public: decode32(&epoch.public)?,
                    },
                    peer_pub: decode32(&epoch.peer_pub)?,
                    root_key: Zeroizing::new(decode32(&epoch.root_key)?),
                    chain_key: Zeroizing::new(decode32(&epoch.chain_key)?),
                    epoch_id: epoch.epoch_id,
                    index: epoch.index,
                    previous_chain_len: epoch.previous_chain_len,
                });
            }

            let mut recv_epochs = VecDeque::new();
            for epoch in &session.recv_epochs {
                let mut skipped = BTreeMap::new();
                for item in &epoch.skipped {
                    skipped.insert(item.index, Zeroizing::new(decode32(&item.key)?));
                }
                recv_epochs.push_back(RecvEpoch {
                    peer_pub: decode32(&epoch.peer_pub)?,
                    local_pub: decode32(&epoch.local_pub)?,
                    root_key: Zeroizing::new(decode32(&epoch.root_key)?),
                    chain_key: Zeroizing::new(decode32(&epoch.chain_key)?),
                    epoch_id: epoch.epoch_id,
                    next_index: epoch.next_index,
                    skipped,
                });
            }

            while send_epochs.len() > MAX_EPOCHS {
                send_epochs.pop_front();
            }
            while recv_epochs.len() > MAX_EPOCHS {
                recv_epochs.pop_front();
            }

            // Старые состояния (v2 без реестра) восстанавливаем из живых
            // эпох: ключи, которые уже приняты, не должны считаться новыми.
            let mut seen_dh_pubs = VecDeque::new();
            for value in &session.seen_dh_pubs {
                let dh_pub = decode32(value)?;
                if !seen_dh_pubs.contains(&dh_pub) {
                    seen_dh_pubs.push_back(dh_pub);
                }
            }
            for epoch in &recv_epochs {
                if !seen_dh_pubs.contains(&epoch.peer_pub) {
                    seen_dh_pubs.push_back(epoch.peer_pub);
                }
            }
            while seen_dh_pubs.len() > MAX_SEEN_DH_PUBS {
                seen_dh_pubs.pop_front();
            }

            sessions.push_back(Session {
                descriptor: SessionDescriptor {
                    id: decode16(&session.id)?,
                    nonce: decode32(&session.nonce)?,
                },
                root: Zeroizing::new(decode32(&session.root)?),
                header_secret: Zeroizing::new(decode32(&session.header_secret)?),
                next_epoch_id: session.next_epoch_id,
                bootstrap_sent: session.bootstrap_sent,
                local: KeyPair {
                    private: Zeroizing::new(decode32(&session.local_private)?),
                    public: decode32(&session.local_public)?,
                },
                peer_bootstrap_pub: decode32(&session.peer_bootstrap_pub)?,
                remote_pub: session
                    .remote_pub
                    .as_deref()
                    .map(decode32)
                    .transpose()?,
                received_since_send: session.received_since_send,
                send_epochs,
                recv_epochs,
                retired_epoch_ids: session.retired_epoch_ids.iter().copied().collect(),
                seen_dh_pubs,
            });
        }

        if sessions.is_empty() {
            return Err(anyhow!("ratchet state has no sessions"));
        }

        let active = decode16(&raw.active)?;
        if !sessions
            .iter()
            .any(|session| session.descriptor.id == active)
        {
            return Err(anyhow!("ratchet state has no active session"));
        }

        let mut state = Self {
            role,
            sessions,
            active,
            retired: Vec::new(),
        };
        for session_id in &raw.retired {
            state.remember_retired(decode16(session_id)?);
        }
        state.evict_sessions();
        Ok(state)
    }
}

fn decode16(value: &str) -> Result<[u8; SESSION_ID_SIZE]> {
    let bytes = hex::decode(value).map_err(|e| anyhow!("invalid ratchet hex: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("ratchet session id must be 16 bytes"))
}

fn decode32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|e| anyhow!("invalid ratchet hex: {}", e))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("ratchet key must be 32 bytes"))
}

fn expand(ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    expand_salted(ikm, KDF_SALT, info)
}

fn expand_salted(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, out.as_mut())
        .map_err(|e| anyhow!("HKDF expansion failed: {}", e))?;
    Ok(out)
}

/// `session_id` выводится из bootstrap-nonce: в открытом виде он не едет.
fn derive_session_id(
    shared_secret: &[u8; 32],
    nonce: &[u8; BOOTSTRAP_NONCE_SIZE],
) -> Result<[u8; SESSION_ID_SIZE]> {
    let bytes = expand_salted(shared_secret, nonce, b"session-id-v3")?;
    let mut id = [0u8; SESSION_ID_SIZE];
    id.copy_from_slice(&bytes[..SESSION_ID_SIZE]);
    Ok(id)
}

/// Псевдоним сессии для открытого заголовка: не раскрывает `session_id`.
pub fn session_alias(id: &[u8; SESSION_ID_SIZE]) -> Result<[u8; SESSION_ALIAS_SIZE]> {
    let hkdf = Hkdf::<Sha256>::new(None, id);
    let mut alias = [0u8; SESSION_ALIAS_SIZE];
    hkdf.expand(b"route-v3", &mut alias)
        .map_err(|e| anyhow!("session alias derivation failed: {}", e))?;
    Ok(alias)
}

/// `SHA256(session_id)` — единственное производное от `session_id`, которое
/// M-C разрешает писать на диск для TTL-комнат.
///
/// Хеш не позволяет восстановить `session_id`, bootstrap-nonce или ключи
/// храповика. Он используется только как tombstone: после рестарта старый
/// bootstrap-пакет снова получит тот же хеш и будет отклонён как
/// [`RatchetError::StaleSession`].
pub fn session_id_hash(session_id: &[u8; SESSION_ID_SIZE]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.finalize().into()
}

/// Хеш `session_id`, выведенного из bootstrap-nonce и общего секрета.
pub fn bootstrap_session_id_hash(
    shared_secret: &[u8; 32],
    nonce: &[u8; BOOTSTRAP_NONCE_SIZE],
) -> Result<[u8; 32]> {
    let descriptor = SessionDescriptor::id_from_nonce(shared_secret, nonce)?;
    Ok(session_id_hash(&descriptor.id))
}

/// Alias и `SHA256(session_id)` для bootstrap-пакета.
///
/// Оба значения выводятся за один HKDF-проход, чтобы `resolve_bootstrap_room`
/// мог одновременно выбрать комнату и проверить tombstone-хеш.
pub fn bootstrap_session_fingerprint(
    shared_secret: &[u8; 32],
    nonce: &[u8; BOOTSTRAP_NONCE_SIZE],
) -> Result<([u8; SESSION_ALIAS_SIZE], [u8; 32])> {
    let descriptor = SessionDescriptor::id_from_nonce(shared_secret, nonce)?;
    Ok((
        session_alias(&descriptor.id)?,
        session_id_hash(&descriptor.id),
    ))
}

/// Выводит alias сессии из общего секрета и bootstrap-nonce.
///
/// Нужен клиенту, чтобы адресно распознать первый пакет новой сессии:
/// сравнение alias дешевле, чем пробная AEAD-расшифровка у каждого контакта.
pub fn bootstrap_session_alias(
    shared_secret: &[u8; 32],
    nonce: &[u8; BOOTSTRAP_NONCE_SIZE],
) -> Result<[u8; SESSION_ALIAS_SIZE]> {
    let descriptor = SessionDescriptor::id_from_nonce(shared_secret, nonce)?;
    session_alias(&descriptor.id)
}

/// Ключ заголовка ротируется вместе с `epoch_id`.
fn derive_header_key(
    header_secret: &[u8; 32],
    epoch_id: u32,
) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::with_capacity(6 + 4);
    info.extend_from_slice(b"hdr-v3");
    info.extend_from_slice(&epoch_id.to_le_bytes());
    expand(header_secret, &info)
}

fn derive_epoch_root(
    bootstrap_root: &[u8; 32],
    dh: [u8; 32],
    local_pub: &[u8; 32],
    peer_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    // Порядок публичных ключей канонический: обе стороны вычисляют один
    // и тот же RootKey эпохи независимо от того, кто отправил первым.
    let (first, second) = if local_pub <= peer_pub {
        (local_pub, peer_pub)
    } else {
        (peer_pub, local_pub)
    };

    let mut info = Vec::with_capacity(10 + 32 + 32 + 32);
    info.extend_from_slice(b"epoch-root");
    info.extend_from_slice(&dh);
    info.extend_from_slice(first);
    info.extend_from_slice(second);

    expand(bootstrap_root, &info)
}

fn derive_chain_key(
    epoch_root: &[u8; 32],
    sender_pub: &[u8; 32],
    receiver_pub: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::with_capacity(9 + 32 + 32);
    info.extend_from_slice(b"chain-key");
    info.extend_from_slice(sender_pub);
    info.extend_from_slice(receiver_pub);
    expand(epoch_root, &info)
}

fn derive_message_key(chain_key: &[u8; 32], n: u32) -> Result<Zeroizing<[u8; 32]>> {
    let mut info = Vec::with_capacity(7 + 4);
    info.extend_from_slice(b"message");
    info.extend_from_slice(&n.to_le_bytes());
    expand(chain_key, &info)
}

fn advance_chain(chain_key: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    expand(chain_key, b"chain-advance")
}

fn store_skipped(epoch: &mut RecvEpoch, n: u32, key: Zeroizing<[u8; 32]>) {
    while epoch.skipped.len() >= MAX_SKIPPED_KEYS {
        let oldest = match epoch.skipped.keys().next().copied() {
            Some(index) => index,
            None => break,
        };
        epoch.skipped.remove(&oldest);
    }
    epoch.skipped.insert(n, key);
}

fn decrypt_with_epoch(
    epoch: &mut RecvEpoch,
    open: &OpenHeader,
    header: &RatchetHeader,
    packet: &[u8],
) -> Result<Vec<u8>> {
    if header.n < epoch.next_index {
        let key = epoch
            .skipped
            .remove(&header.n)
            .ok_or_else(|| anyhow!("ratchet message key is no longer available"))?;
        return open_packet(open, packet, &key);
    }

    let distance = header.n - epoch.next_index;
    if distance > MAX_SKIPPED_KEYS as u32 {
        return Err(anyhow!(
            "ratchet message is too far ahead: {} > {}",
            distance,
            MAX_SKIPPED_KEYS
        ));
    }

    let mut message_key = None;
    while epoch.next_index <= header.n {
        let key = derive_message_key(&epoch.chain_key, epoch.next_index)?;
        if epoch.next_index == header.n {
            message_key = Some(key);
        } else {
            store_skipped(epoch, epoch.next_index, key);
        }

        epoch.chain_key = advance_chain(&epoch.chain_key)?;
        epoch.next_index = epoch
            .next_index
            .checked_add(1)
            .ok_or_else(|| anyhow!("ratchet receive counter overflow"))?;
    }

    let key = message_key.ok_or_else(|| anyhow!("ratchet message key was not derived"))?;
    open_packet(open, packet, &key)
}

/// Проверяет, что длина пакета лежит в `bucket + rand(0..=bucket/8)`.
pub fn is_valid_packet_len(len: usize) -> bool {
    ALLOWED_TOTAL_SIZES
        .iter()
        .any(|bucket| len >= *bucket && len <= bucket + bucket / 8)
}

fn seal_packet(
    header: &RatchetHeader,
    header_secret: &[u8; 32],
    message_key: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let plaintext_len = u32::try_from(plaintext.len())
        .map_err(|_| anyhow!("ratchet plaintext is too large"))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let open = OpenHeader {
        alias: session_alias(&header.session_id)?,
        bootstrap_nonce: header.bootstrap_nonce,
        nonce: nonce_bytes,
        header_offset: OPEN_HEADER_MIN
            + if header.bootstrap_nonce.is_some() {
                BOOTSTRAP_NONCE_SIZE
            } else {
                0
            },
    };

    let min_total = open
        .header_offset
        .checked_add(ENCRYPTED_HEADER_SIZE)
        .and_then(|value| value.checked_add(std::mem::size_of::<u32>()))
        .and_then(|value| value.checked_add(plaintext.len()))
        .and_then(|value| value.checked_add(TAG_SIZE))
        .ok_or_else(|| anyhow!("ratchet plaintext is too large"))?;

    let bucket = ALLOWED_TOTAL_SIZES
        .iter()
        .copied()
        .find(|size| *size >= min_total)
        .ok_or_else(|| {
            anyhow!(
                "ratchet payload does not fit into {} bytes",
                super::SIZE_MAX
            )
        })?;
    let extra_max = bucket / 8;
    let extra = if extra_max == 0 {
        0
    } else {
        (OsRng.next_u64() % (extra_max as u64 + 1)) as usize
    };
    let total_size = bucket + extra;

    let inner_len = total_size
        .checked_sub(open.header_offset + ENCRYPTED_HEADER_SIZE + TAG_SIZE)
        .ok_or_else(|| anyhow!("ratchet packet size underflow"))?;
    let mut inner = Zeroizing::new(vec![0u8; inner_len]);
    inner[..4].copy_from_slice(&plaintext_len.to_le_bytes());
    inner[4..4 + plaintext.len()].copy_from_slice(plaintext);
    if inner_len > 4 + plaintext.len() {
        OsRng.fill_bytes(&mut inner[4 + plaintext.len()..]);
    }

    let open_bytes = open.to_bytes();
    let header_key = derive_header_key(header_secret, header.epoch_id)?;
    let header_cipher = XChaCha20Poly1305::new_from_slice(header_key.as_ref())
        .map_err(|_| anyhow!("invalid ratchet header key"))?;
    let header_plaintext = header.plaintext();
    let encrypted_header = header_cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: &header_plaintext,
                aad: &open_bytes,
            },
        )
        .map_err(|_| anyhow!("ratchet header encryption failed"))?;
    if encrypted_header.len() != ENCRYPTED_HEADER_SIZE {
        return Err(anyhow!("ratchet header size mismatch"));
    }

    let mut payload_aad = Vec::with_capacity(open_bytes.len() + encrypted_header.len());
    payload_aad.extend_from_slice(&open_bytes);
    payload_aad.extend_from_slice(&encrypted_header);

    let cipher = XChaCha20Poly1305::new_from_slice(message_key)
        .map_err(|_| anyhow!("invalid ratchet message key"))?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce_bytes),
            Payload {
                msg: inner.as_slice(),
                aad: &payload_aad,
            },
        )
        .map_err(|_| anyhow!("ratchet encryption failed"))?;

    let mut packet = Vec::with_capacity(total_size);
    packet.extend_from_slice(&open_bytes);
    packet.extend_from_slice(&encrypted_header);
    packet.extend_from_slice(&ciphertext);

    if packet.len() != total_size {
        return Err(anyhow!("ratchet packet size mismatch"));
    }
    debug_assert!(is_valid_packet_len(packet.len()));

    Ok(packet)
}

fn open_packet(
    open: &OpenHeader,
    packet: &[u8],
    message_key: &[u8; 32],
) -> Result<Vec<u8>> {
    if packet.len() < open.header_offset + ENCRYPTED_HEADER_SIZE + TAG_SIZE {
        return Err(anyhow!("ratchet packet is too short"));
    }

    let aad = open.payload_aad(packet);
    let nonce = XNonce::from_slice(&open.nonce);
    let ciphertext = &packet[open.header_offset + ENCRYPTED_HEADER_SIZE..];

    let cipher = XChaCha20Poly1305::new_from_slice(message_key)
        .map_err(|_| anyhow!("invalid ratchet message key"))?;
    let inner = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("ratchet authentication failed"))?,
    );

    if inner.len() < 4 {
        return Err(anyhow!("ratchet inner frame is too short"));
    }

    let plaintext_len = u32::from_le_bytes(
        inner[..4]
            .try_into()
            .map_err(|_| anyhow!("invalid ratchet inner length"))?,
    ) as usize;

    if plaintext_len > inner.len() - 4 {
        return Err(anyhow!("ratchet inner length exceeds frame bounds"));
    }

    Ok(inner[4..4 + plaintext_len].to_vec())
}

// ---------------------------------------------------------------------------
// Сериализация
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct RawState {
    version: u8,
    role: u8,
    #[serde(default)]
    active: String,
    #[serde(default)]
    retired: Vec<String>,
    #[serde(default)]
    sessions: Vec<RawSession>,
}

impl RawState {
    fn wipe(&mut self) {
        self.active.zeroize();
        for session_id in &mut self.retired {
            session_id.zeroize();
        }
        for session in &mut self.sessions {
            session.wipe();
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RawSession {
    id: String,
    nonce: String,
    root: String,
    header_secret: String,
    next_epoch_id: u32,
    bootstrap_sent: bool,
    local_private: String,
    local_public: String,
    peer_bootstrap_pub: String,
    remote_pub: Option<String>,
    received_since_send: bool,
    /// `epoch_id` вытесненных эпох приёма.
    #[serde(default)]
    retired_epoch_ids: Vec<u32>,
    /// `dh_pub` собеседника, уже принятые в этой сессии (порядок приёма).
    #[serde(default)]
    seen_dh_pubs: Vec<String>,
    #[serde(default)]
    send_epochs: Vec<RawSendEpoch>,
    #[serde(default)]
    recv_epochs: Vec<RawRecvEpoch>,
}

impl RawSession {
    fn wipe(&mut self) {
        self.id.zeroize();
        self.nonce.zeroize();
        self.root.zeroize();
        self.header_secret.zeroize();
        self.local_private.zeroize();
        self.local_public.zeroize();
        self.peer_bootstrap_pub.zeroize();
        if let Some(remote) = self.remote_pub.as_mut() {
            remote.zeroize();
        }
        for dh_pub in &mut self.seen_dh_pubs {
            dh_pub.zeroize();
        }
        for epoch in &mut self.send_epochs {
            epoch.wipe();
        }
        for epoch in &mut self.recv_epochs {
            epoch.wipe();
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RawSendEpoch {
    private: String,
    public: String,
    peer_pub: String,
    root_key: String,
    chain_key: String,
    epoch_id: u32,
    index: u32,
    previous_chain_len: u32,
}

impl RawSendEpoch {
    fn wipe(&mut self) {
        self.private.zeroize();
        self.public.zeroize();
        self.peer_pub.zeroize();
        self.root_key.zeroize();
        self.chain_key.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
struct RawRecvEpoch {
    peer_pub: String,
    local_pub: String,
    root_key: String,
    chain_key: String,
    epoch_id: u32,
    next_index: u32,
    #[serde(default)]
    skipped: Vec<RawSkipped>,
}

impl RawRecvEpoch {
    fn wipe(&mut self) {
        self.peer_pub.zeroize();
        self.local_pub.zeroize();
        self.root_key.zeroize();
        self.chain_key.zeroize();
        for item in &mut self.skipped {
            item.key.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize)]
struct RawSkipped {
    index: u32,
    key: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHARED: [u8; 32] = [7u8; 32];

    fn pair() -> (RatchetState, RatchetState) {
        (
            RatchetState::new(&SHARED, Role::Initiator).unwrap(),
            RatchetState::new(&SHARED, Role::Responder).unwrap(),
        )
    }

    fn assert_stale(error: &anyhow::Error) {
        assert!(
            matches!(
                error.downcast_ref::<RatchetError>(),
                Some(RatchetError::StaleSession)
            ),
            "expected StaleSession, got: {:#}",
            error
        );
    }

    fn assert_error(error: &anyhow::Error, expected: RatchetError) {
        assert_eq!(error.downcast_ref::<RatchetError>(), Some(&expected), "{:#}", error);
    }

    #[test]
    fn ratchet_dh_rejects_low_order_peer_without_panicking() {
        let keypair = KeyPair::generate();

        assert!(keypair.diffie_hellman(&[0u8; 32]).is_err());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(keypair.diffie_hellman(&one).is_err());

        let peer = KeyPair::generate();
        assert!(keypair.diffie_hellman(&peer.public).is_ok());
    }

    #[test]
    fn ping_pong_changes_epochs_roots_and_dh_keys() {
        let (mut alice, mut bob) = pair();

        let mut previous_root = None;
        let mut previous_dh = None;

        for round in 0..6 {
            let alice_text = format!("alice-{}", round);
            let alice_packet = alice.encrypt(alice_text.as_bytes()).unwrap();
            let alice_header = alice.header_for_test(&alice_packet).unwrap();
            if round == 0 {
                assert_eq!(alice_header.n, 0);
                assert_eq!(alice_header.pn, 0);
            }

            let root = alice.with_root_key(|root| *root).unwrap();
            let dh = alice.current_dh_public().unwrap();
            if let Some(previous) = previous_root {
                assert_ne!(root, previous, "RootKey must change between epochs");
            }
            if let Some(previous) = previous_dh {
                assert_ne!(dh, previous, "DH key must change between epochs");
            }
            previous_root = Some(root);
            previous_dh = Some(dh);

            assert_eq!(
                bob.decrypt(&alice_packet, &SHARED).unwrap(),
                alice_text.as_bytes()
            );

            let bob_text = format!("bob-{}", round);
            let bob_packet = bob.encrypt(bob_text.as_bytes()).unwrap();
            let bob_header = bob.header_for_test(&bob_packet).unwrap();
            if round == 0 {
                assert_eq!(bob_header.pn, 0);
            }
            assert_eq!(
                alice.decrypt(&bob_packet, &SHARED).unwrap(),
                bob_text.as_bytes()
            );
        }

        assert!(alice.send_epoch_count() <= MAX_EPOCHS * MAX_SESSIONS);
        assert!(bob.send_epoch_count() <= MAX_EPOCHS * MAX_SESSIONS);
        assert!(alice.recv_epoch_count() <= MAX_EPOCHS * MAX_SESSIONS);
        assert!(bob.recv_epoch_count() <= MAX_EPOCHS * MAX_SESSIONS);
    }

    #[test]
    fn race_messages_decrypt_through_five_epoch_window() {
        let (mut alice, mut bob) = pair();

        // Обе стороны отправляют до получения сообщения партнёра.
        let alice_first = alice.encrypt(b"alice-first").unwrap();
        let bob_first = bob.encrypt(b"bob-first").unwrap();

        assert_eq!(
            bob.decrypt(&alice_first, &SHARED).unwrap(),
            b"alice-first"
        );
        assert_eq!(alice.decrypt(&bob_first, &SHARED).unwrap(), b"bob-first");

        // Старая эпоха ещё активна у обеих сторон. Оба снова отправляют,
        // не дожидаясь обновления партнёра.
        let alice_race = alice.encrypt(b"alice-race").unwrap();
        let bob_race = bob.encrypt(b"bob-race").unwrap();

        assert_eq!(bob.decrypt(&alice_race, &SHARED).unwrap(), b"alice-race");
        assert_eq!(alice.decrypt(&bob_race, &SHARED).unwrap(), b"bob-race");

        // Запоминаем пакет из эпохи, которая позже выйдет из окна.
        let stale_packet = alice.encrypt(b"stale-message").unwrap();

        // Проворачиваем больше пяти эпох, чтобы старые ключи вытеснились.
        for round in 0..7 {
            let text = format!("after-race-{}", round);
            let packet = alice.encrypt(text.as_bytes()).unwrap();
            assert_eq!(bob.decrypt(&packet, &SHARED).unwrap(), text.as_bytes());

            let reply = format!("reply-{}", round);
            let packet = bob.encrypt(reply.as_bytes()).unwrap();
            assert_eq!(alice.decrypt(&packet, &SHARED).unwrap(), reply.as_bytes());
        }

        assert!(alice.send_epoch_count() <= MAX_EPOCHS * MAX_SESSIONS);
        assert!(bob.send_epoch_count() <= MAX_EPOCHS * MAX_SESSIONS);
        assert!(alice.recv_epoch_count() <= MAX_EPOCHS * MAX_SESSIONS);
        assert!(bob.recv_epoch_count() <= MAX_EPOCHS * MAX_SESSIONS);

        // Старейшая эпоха удалена: отложенный пакет больше не расшифровать.
        assert!(bob.decrypt(&stale_packet, &SHARED).is_err());
    }

    #[test]
    fn forward_secrecy_and_packet_sizes_match_padding_grid() {
        let cases = [
            (10usize, 256usize),
            (500, 1024),
            (2000, 4096),
            (20_000, 65536),
        ];

        for (plaintext_len, expected_size) in cases {
            let (mut alice, mut bob) = pair();
            let mut plaintext = vec![b'S'; plaintext_len];
            plaintext[..6].copy_from_slice(b"SECRET");

            let packet = alice.encrypt(&plaintext).unwrap();
            assert!(
                packet.len() >= expected_size
                    && packet.len() <= expected_size + expected_size / 8,
                "packet must use the {} byte bucket (got {})",
                expected_size,
                packet.len()
            );
            assert!(
                !packet.windows(6).any(|window| window == b"SECRET"),
                "plaintext must not leak into the packet"
            );

            assert_eq!(bob.decrypt(&packet, &SHARED).unwrap(), plaintext);

            // Ключ сообщения и цепочка уже продвинуты: повторная доставка
            // того же пакета не должна проходить.
            assert!(
                bob.decrypt(&packet, &SHARED).is_err(),
                "replayed packet must not decrypt twice"
            );
        }
    }

    #[test]
    fn skipped_keys_are_bounded_per_epoch() {
        let (mut alice, mut bob) = pair();

        let first = alice.encrypt(b"first").unwrap();
        assert_eq!(bob.decrypt(&first, &SHARED).unwrap(), b"first");

        // Alice отправляет ещё максимум 32 сообщения подряд: при приёме
        // только последнего в буфере пропущенных должно остаться не больше 32.
        let mut last = Vec::new();
        for index in 0..33 {
            let packet = alice
                .encrypt(format!("message-{}", index).as_bytes())
                .unwrap();
            last = packet;
        }

        let text = bob.decrypt(&last, &SHARED).unwrap();
        assert_eq!(text, b"message-32");
        assert!(bob.skipped_key_count() <= MAX_SKIPPED_KEYS);
    }

    #[test]
    fn state_round_trips_through_serialization() {
        let (mut alice, mut bob) = pair();
        let packet = alice.encrypt(b"hello").unwrap();
        assert_eq!(bob.decrypt(&packet, &SHARED).unwrap(), b"hello");

        let session_id = bob.session_id();
        let bytes = bob.to_bytes().unwrap();
        let mut restored = RatchetState::from_bytes(bytes).unwrap();
        assert_eq!(restored.role(), Role::Responder);
        assert_eq!(restored.session_id(), session_id);

        let packet = alice.encrypt(b"after-save").unwrap();
        assert_eq!(
            restored.decrypt(&packet, &SHARED).unwrap(),
            b"after-save"
        );
    }

    #[test]
    fn serialized_state_is_wrapped_in_secret_bytes() {
        let (mut alice, mut bob) = pair();
        let packet = alice.encrypt(b"hello").unwrap();
        assert_eq!(bob.decrypt(&packet, &SHARED).unwrap(), b"hello");

        let bytes = bob.to_bytes().unwrap();
        assert!(!bytes.expose().is_empty());
        assert_eq!(format!("{:?}", bytes), "<secret>");
        assert!(
            !format!("{:?}", bytes).contains("root_key"),
            "Debug must not expose the serialized state structure"
        );
    }

    #[test]
    fn with_root_key_scopes_root_key_access() {
        let (mut alice, _bob) = pair();
        alice.encrypt(b"hello").unwrap();

        let root_hex = alice.with_root_key(|root| hex::encode(root)).unwrap();
        assert_eq!(root_hex.len(), 64);

        // Замыкание работает с живым ключом: скопировать его наружу можно
        // только явно, что видно при аудите.
        let all_zero = alice
            .with_root_key(|root| root.iter().all(|byte| *byte == 0))
            .unwrap();
        assert!(!all_zero);
    }

    #[test]
    fn new_states_use_fresh_bootstrap_entropy() {
        let first = RatchetState::new(&SHARED, Role::Initiator).unwrap();
        let second = RatchetState::new(&SHARED, Role::Initiator).unwrap();

        assert_ne!(first.session_id(), second.session_id());

        let first_session = &first.sessions[0];
        let second_session = &second.sessions[0];

        assert_ne!(
            first_session.descriptor.nonce,
            second_session.descriptor.nonce
        );
        assert_ne!(*first_session.root, *second_session.root);
        assert_ne!(
            *first_session.local.private,
            *second_session.local.private
        );
        assert_ne!(
            first_session.peer_bootstrap_pub,
            second_session.peer_bootstrap_pub
        );
    }

    #[test]
    fn old_bootstrap_packet_is_rejected_after_reset() {
        let mut alice = RatchetState::new(&SHARED, Role::Initiator).unwrap();
        let mut bob = RatchetState::new(&SHARED, Role::Responder).unwrap();

        let old_packet = alice.encrypt(b"old-session").unwrap();
        assert_eq!(
            bob.decrypt(&old_packet, &SHARED).unwrap(),
            b"old-session"
        );

        // Reset: обе стороны уничтожают состояние, приложение переносит
        // известные session_id в новый контекст.
        let retired = bob.session_ids();
        let mut alice = RatchetState::new(&SHARED, Role::Initiator).unwrap();
        let mut bob =
            RatchetState::new_with_retired(&SHARED, Role::Responder, retired).unwrap();

        let fresh_packet = alice.encrypt(b"fresh-session").unwrap();
        assert_eq!(
            bob.decrypt(&fresh_packet, &SHARED).unwrap(),
            b"fresh-session"
        );

        let error = bob.decrypt(&old_packet, &SHARED).unwrap_err();
        assert_stale(&error);
    }

    #[test]
    fn packet_from_foreign_session_is_stale() {
        let mut alice = RatchetState::new(&SHARED, Role::Initiator).unwrap();
        let packet = alice.encrypt(b"foreign").unwrap();

        let mut bob = RatchetState::new_with_retired(
            &SHARED,
            Role::Responder,
            vec![alice.session_id()],
        )
        .unwrap();

        let error = bob.decrypt(&packet, &SHARED).unwrap_err();
        assert_stale(&error);
    }

    #[test]
    fn bootstrap_packet_without_nonce_is_rejected() {
        let mut alice = RatchetState::new(&SHARED, Role::Initiator).unwrap();
        let mut packet = alice.encrypt(b"no-nonce").unwrap();

        // Обнуляем bootstrap_nonce в открытом заголовке v3: пакет
        // перестаёт нести bootstrap-энтропию и не должен приниматься.
        let nonce_start = OPEN_HEADER_FIXED;
        packet[nonce_start..nonce_start + BOOTSTRAP_NONCE_SIZE].fill(0);

        let mut bob = RatchetState::new(&SHARED, Role::Responder).unwrap();
        let error = bob.decrypt(&packet, &SHARED).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<RatchetError>(),
            Some(RatchetError::MissingBootstrapNonce)
        ));
    }

    #[test]
    fn legacy_v1_packet_is_rejected() {
        let mut alice = RatchetState::new(&SHARED, Role::Initiator).unwrap();
        let mut packet = alice.encrypt(b"legacy").unwrap();
        packet[0] = 1;

        let mut bob = RatchetState::new(&SHARED, Role::Responder).unwrap();
        let error = bob.decrypt(&packet, &SHARED).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<RatchetError>(),
            Some(RatchetError::UnsupportedVersion(1))
        ));
    }

    #[test]
    fn legacy_state_version_is_rejected() {
        let error = match RatchetState::from_bytes(SecretBytes::from_slice(
            br#"{"version":1,"role":0}"#,
        )) {
            Ok(_) => panic!("v1 state must not be accepted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("unsupported ratchet state version: 1"),
            "unexpected error: {:#}",
            error
        );
    }

    #[test]
    fn simultaneous_first_messages_open_two_sessions() {
        let (mut alice, mut bob) = pair();

        let alice_first = alice.encrypt(b"alice-first").unwrap();
        let bob_first = bob.encrypt(b"bob-first").unwrap();
        let alice_session = alice.header_for_test(&alice_first).unwrap().session_id;
        let bob_session = bob.header_for_test(&bob_first).unwrap().session_id;
        assert_ne!(alice_session, bob_session);

        assert_eq!(
            bob.decrypt(&alice_first, &SHARED).unwrap(),
            b"alice-first"
        );
        assert_eq!(alice.decrypt(&bob_first, &SHARED).unwrap(), b"bob-first");

        // Ответ идёт в сессии собеседника, и обе стороны это переживают.
        let bob_reply = bob.encrypt(b"bob-reply").unwrap();
        assert_eq!(
            bob.header_for_test(&bob_reply).unwrap().session_id,
            alice_session
        );
        assert_eq!(alice.decrypt(&bob_reply, &SHARED).unwrap(), b"bob-reply");
        assert_eq!(alice.session_count(), 2);
        assert_eq!(bob.session_count(), 2);

        // Alice отвечает в сессии только что принятого пакета.
        let alice_reply = alice.encrypt(b"alice-reply").unwrap();
        assert_eq!(
            alice.header_for_test(&alice_reply).unwrap().session_id,
            alice_session
        );
        assert_eq!(bob.decrypt(&alice_reply, &SHARED).unwrap(), b"alice-reply");
    }

    #[test]
    fn replayed_evicted_epoch_is_rejected() {
        let (mut alice, mut bob) = pair();

        // Первая эпоха: её пакет сохраняем для повторной подачи.
        let stale = alice.encrypt(b"stale-epoch").unwrap();
        let stale_dh = alice.header_for_test(&stale).unwrap().dh_pub;
        assert_eq!(bob.decrypt(&stale, &SHARED).unwrap(), b"stale-epoch");

        // Проворачиваем больше окна эпох, чтобы dh_pub вышел из него.
        for round in 0..(MAX_EPOCHS + 2) {
            let text = format!("rotate-{}", round);
            let packet = alice.encrypt(text.as_bytes()).unwrap();
            assert_eq!(bob.decrypt(&packet, &SHARED).unwrap(), text.as_bytes());

            let reply = format!("reply-{}", round);
            let packet = bob.encrypt(reply.as_bytes()).unwrap();
            assert_eq!(alice.decrypt(&packet, &SHARED).unwrap(), reply.as_bytes());
        }

        let session = bob.active_session().unwrap();
        assert!(
            !session
                .recv_epochs
                .iter()
                .any(|epoch| epoch.peer_pub == stale_dh),
            "the stale epoch must have left the window"
        );
        assert!(session.seen_dh_pubs.contains(&stale_dh));

        let remote_before = session.remote_pub;
        let recv_epochs_before = bob.recv_epoch_count();
        let sessions_before = bob.session_count();

        let error = bob.decrypt(&stale, &SHARED).unwrap_err();
        assert_error(&error, RatchetError::ReplayedDhPub);

        // Повтор не создал эпоху, не тронул remote_pub и не вытеснил активную.
        let session = bob.active_session().unwrap();
        assert_eq!(session.remote_pub, remote_before);
        assert_eq!(bob.recv_epoch_count(), recv_epochs_before);
        assert_eq!(bob.session_count(), sessions_before);
        assert!(session.recv_epochs.iter().any(|epoch| epoch.peer_pub != stale_dh));
    }

    #[test]
    fn replayed_active_epoch_packet_is_not_a_replay_error() {
        let (mut alice, mut bob) = pair();
        let packet = alice.encrypt(b"active").unwrap();
        assert_eq!(bob.decrypt(&packet, &SHARED).unwrap(), b"active");

        let remote_before = bob.active_session().unwrap().remote_pub;
        let recv_epochs_before = bob.recv_epoch_count();

        // Дедуп по `n` уже есть в цепочке приёма: повтор не проходит,
        // но это не replay dh_pub и не повод создавать новую эпоху.
        let error = bob.decrypt(&packet, &SHARED).unwrap_err();
        assert!(
            error.downcast_ref::<RatchetError>().is_none(),
            "unexpected typed error: {:#}",
            error
        );
        assert_eq!(bob.active_session().unwrap().remote_pub, remote_before);
        assert_eq!(bob.recv_epoch_count(), recv_epochs_before);
    }

    #[test]
    fn legitimate_new_epoch_is_accepted_and_registered() {
        let (mut alice, mut bob) = pair();

        let first = alice.encrypt(b"first").unwrap();
        let first_dh = alice.header_for_test(&first).unwrap().dh_pub;
        assert_eq!(bob.decrypt(&first, &SHARED).unwrap(), b"first");
        assert!(bob
            .active_session()
            .unwrap()
            .seen_dh_pubs
            .contains(&first_dh));

        let reply = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&reply, &SHARED).unwrap(), b"reply");

        let second = alice.encrypt(b"second").unwrap();
        let second_dh = alice.header_for_test(&second).unwrap().dh_pub;
        assert_ne!(first_dh, second_dh);
        assert_eq!(bob.decrypt(&second, &SHARED).unwrap(), b"second");

        let session = bob.active_session().unwrap();
        assert!(session.seen_dh_pubs.contains(&second_dh));
        assert_eq!(session.remote_pub, Some(second_dh));
        assert_eq!(session.recv_epochs.len(), 2);
    }

    #[test]
    fn late_packet_of_known_epoch_does_not_rewind_remote_pub() {
        let (mut alice, mut bob) = pair();

        let first = alice.encrypt(b"epoch-1-first").unwrap();
        let late = alice.encrypt(b"epoch-1-late").unwrap();
        let first_dh = alice.header_for_test(&first).unwrap().dh_pub;
        assert_eq!(
            alice.header_for_test(&late).unwrap().dh_pub,
            first_dh,
            "both packets must belong to the same epoch"
        );
        assert_eq!(bob.decrypt(&first, &SHARED).unwrap(), b"epoch-1-first");

        let reply = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&reply, &SHARED).unwrap(), b"reply");

        let second = alice.encrypt(b"epoch-2").unwrap();
        let second_dh = alice.header_for_test(&second).unwrap().dh_pub;
        assert_ne!(first_dh, second_dh);

        // Более новая эпоха приходит раньше, чем запоздавший пакет старой.
        assert_eq!(bob.decrypt(&second, &SHARED).unwrap(), b"epoch-2");
        assert_eq!(
            bob.active_session().unwrap().remote_pub,
            Some(second_dh)
        );

        assert_eq!(bob.decrypt(&late, &SHARED).unwrap(), b"epoch-1-late");
        assert_eq!(
            bob.active_session().unwrap().remote_pub,
            Some(second_dh),
            "a late packet of an older epoch must not rewind remote_pub"
        );
        assert_eq!(bob.active_session().unwrap().recv_epochs.len(), 2);
    }

    fn test_recv_epoch(peer_pub: [u8; 32]) -> RecvEpoch {
        RecvEpoch {
            peer_pub,
            local_pub: [1u8; 32],
            root_key: Zeroizing::new([0u8; 32]),
            chain_key: Zeroizing::new([0u8; 32]),
            epoch_id: 0,
            next_index: 0,
            skipped: BTreeMap::new(),
        }
    }

    #[test]
    fn epoch_window_evicts_the_oldest_inactive_epoch() {
        let mut session =
            Session::derive(&SHARED, Role::Responder, SessionDescriptor::generate(&SHARED).unwrap()).unwrap();
        for value in 1..=MAX_EPOCHS as u8 {
            session.recv_epochs.push_back(test_recv_epoch([value; 32]));
        }
        session.remote_pub = Some([1u8; 32]);

        session
            .push_recv_epoch(test_recv_epoch([MAX_EPOCHS as u8 + 1; 32]))
            .unwrap();

        let order: Vec<u8> = session
            .recv_epochs
            .iter()
            .map(|epoch| epoch.peer_pub[0])
            .collect();
        assert_eq!(order.len(), MAX_EPOCHS);
        assert_eq!(order[0], 1, "the epoch referenced by remote_pub is kept");
        assert_eq!(*order.last().unwrap(), MAX_EPOCHS as u8 + 1);
        assert_eq!(session.remote_pub, Some([1u8; 32]));
    }

    #[test]
    fn epoch_overflow_is_reported_without_mutating_state() {
        let mut session =
            Session::derive(&SHARED, Role::Responder, SessionDescriptor::generate(&SHARED).unwrap()).unwrap();
        for _ in 0..MAX_EPOCHS {
            session.recv_epochs.push_back(test_recv_epoch([9u8; 32]));
        }
        session.remote_pub = Some([9u8; 32]);

        let error = session
            .push_recv_epoch(test_recv_epoch([8u8; 32]))
            .unwrap_err();
        assert_error(&error, RatchetError::EpochOverflow);

        assert_eq!(session.recv_epochs.len(), MAX_EPOCHS);
        assert_eq!(session.remote_pub, Some([9u8; 32]));
        assert!(session
            .recv_epochs
            .iter()
            .all(|epoch| epoch.peer_pub == [9u8; 32]));
    }

    #[test]
    fn new_session_starts_with_empty_dh_pub_registry() {
        let (mut alice, mut bob) = pair();
        let packet = alice.encrypt(b"first").unwrap();
        let dh_pub = alice.header_for_test(&packet).unwrap().dh_pub;
        assert_eq!(bob.decrypt(&packet, &SHARED).unwrap(), b"first");
        assert!(bob
            .active_session()
            .unwrap()
            .seen_dh_pubs
            .contains(&dh_pub));

        let mut fresh =
            RatchetState::new_with_retired(&SHARED, Role::Responder, bob.session_ids()).unwrap();
        assert!(fresh.active_session().unwrap().seen_dh_pubs.is_empty());

        // H-1 всё ещё отсекает пакет старой сессии по session_id.
        let error = fresh.decrypt(&packet, &SHARED).unwrap_err();
        assert_stale(&error);
    }

    #[test]
    fn dh_pub_registry_survives_serialization() {
        let (mut alice, mut bob) = pair();
        let packet = alice.encrypt(b"hello").unwrap();
        let dh_pub = alice.header_for_test(&packet).unwrap().dh_pub;
        assert_eq!(bob.decrypt(&packet, &SHARED).unwrap(), b"hello");

        let mut restored = RatchetState::from_bytes(bob.to_bytes().unwrap()).unwrap();
        assert!(restored
            .active_session()
            .unwrap()
            .seen_dh_pubs
            .contains(&dh_pub));

        let replay = bob.decrypt(&packet, &SHARED).unwrap_err();
        assert!(replay.downcast_ref::<RatchetError>().is_none());

        // Тот же повтор через восстановленное состояние — та же реакция.
        let error = restored.decrypt(&packet, &SHARED).unwrap_err();
        assert!(error.downcast_ref::<RatchetError>().is_none());

        let next = alice.encrypt(b"after-save").unwrap();
        assert_eq!(
            restored.decrypt(&next, &SHARED).unwrap(),
            b"after-save"
        );
    }

    #[test]
    fn retired_session_registry_keeps_latest_ids() {
        // Ёмкость рассчитана на 32 полных окна по 4 сессии; старые
        // tombstone-и вытесняются, новые остаются.
        let mut state = RatchetState::new(&SHARED, Role::Initiator).unwrap();
        let ids: Vec<[u8; 16]> = (1..=MAX_RETIRED_SESSIONS + 8)
            .map(|index| {
                let mut id = [0u8; 16];
                id[0] = 0xAA;
                id[8..].copy_from_slice(&(index as u64).to_le_bytes());
                id
            })
            .collect();

        state.retire_sessions(ids.clone());

        assert_eq!(state.retired.len(), MAX_RETIRED_SESSIONS);
        assert!(state.retired.contains(&ids[ids.len() - 1]));
        assert!(!state.retired.contains(&ids[0]));
    }

    // -----------------------------------------------------------------
    // M-7: header encryption, alias and randomized padding
    // -----------------------------------------------------------------

    #[test]
    fn v3_header_hides_dh_pub_counters_and_session_id() {
        let (mut alice, _bob) = pair();
        let mut packet = alice.encrypt(b"hidden header 0").unwrap();
        for index in 1..6 {
            packet = alice
                .encrypt(format!("hidden header {}", index).as_bytes())
                .unwrap();
        }
        let header = alice.header_for_test(&packet).unwrap();
        assert_eq!(header.n, 5);

        let open = OpenHeader::parse(&packet).unwrap();
        let clear = &packet[..open.header_offset];
        assert!(
            !packet.windows(32).any(|window| window == header.dh_pub),
            "dh_pub must not appear in the clear header"
        );
        assert!(
            !packet
                .windows(SESSION_ID_SIZE)
                .any(|window| window == alice.session_id()),
            "session_id must not appear in the clear header"
        );
        assert!(
            !clear.windows(4).any(|window| window == header.n.to_le_bytes()),
            "message counter n must be encrypted"
        );
    }

    #[test]
    fn bootstrap_nonce_is_only_in_the_bootstrap_packet() {
        let (mut alice, mut bob) = pair();
        let first = alice.encrypt(b"first").unwrap();
        let open = OpenHeader::parse(&first).unwrap();
        assert!(
            open.bootstrap_nonce.is_some(),
            "first session packet must carry the bootstrap nonce"
        );
        assert_eq!(bob.decrypt(&first, &SHARED).unwrap(), b"first");

        let reply = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&reply, &SHARED).unwrap(), b"reply");

        let second = alice.encrypt(b"second").unwrap();
        let open = OpenHeader::parse(&second).unwrap();
        assert!(
            open.bootstrap_nonce.is_none(),
            "non-bootstrap packets must not repeat the bootstrap nonce"
        );
        let session_nonce = alice.sessions[0].descriptor.nonce;
        assert!(
            !second
                .windows(BOOTSTRAP_NONCE_SIZE)
                .any(|window| window == session_nonce),
            "bootstrap nonce bytes must be absent from later packets"
        );
    }

    #[test]
    fn tampered_encrypted_header_fails_authentication() {
        let (mut alice, mut bob) = pair();
        let mut packet = alice.encrypt(b"header auth").unwrap();
        let open = OpenHeader::parse(&packet).unwrap();
        packet[open.header_offset] ^= 0x01;

        assert!(bob.decrypt(&packet, &SHARED).is_err());
    }

    #[test]
    fn route_info_exposes_only_the_open_header() {
        let (mut alice, _bob) = pair();
        let packet = alice.encrypt(b"route").unwrap();
        let info = packet_route_info(&packet).unwrap();

        assert_eq!(info.version, PROTOCOL_VERSION);
        assert_eq!(info.alias, alice.active_alias().unwrap());
        assert!(info.is_bootstrap());
        assert!(info.bootstrap_nonce.is_some());

        let second = alice.encrypt(b"route-2").unwrap();
        let info = packet_route_info(&second).unwrap();
        assert!(!info.is_bootstrap(), "later packets omit bootstrap nonce");
    }

    #[test]
    fn route_info_rejects_v2_and_oversized_packets_before_crypto() {
        let (mut alice, _bob) = pair();
        let mut packet = alice.encrypt(b"downgrade").unwrap();
        packet[0] = 2;
        assert_eq!(
            packet_route_info(&packet).unwrap_err(),
            RatchetError::UnsupportedVersion(2)
        );

        let mut oversized = vec![0u8; crate::crypto::SIZE_MAX + crate::crypto::SIZE_MAX / 8 + 1];
        oversized[0] = PROTOCOL_VERSION;
        assert_eq!(
            packet_route_info(&oversized).unwrap_err(),
            RatchetError::InvalidPacketSize
        );
    }

    #[test]
    fn alias_relabelling_breaks_header_authentication() {
        // M-8: alias входит в AAD/заголовок. Пакет нельзя переадресовать
        // в другую комнату, подменив alias в открытом заголовке.
        let (mut alice, mut target) = pair();
        let mut packet = alice.encrypt(b"bound to room").unwrap();
        let front = OpenHeader::parse(&packet).unwrap();

        let target_alias = target.active_alias().unwrap();
        assert_ne!(target_alias, front.alias);
        packet[2..2 + SESSION_ALIAS_SIZE].copy_from_slice(&target_alias);

        // Alias теперь указывает на живую сессию target, но заголовок и
        // payload зашифрованы ключами исходной комнаты: AEAD не сходится.
        assert!(target.decrypt(&packet, &SHARED).is_err());
    }

    #[test]
    fn header_key_rotates_with_epoch() {
        let (mut alice, mut bob) = pair();
        let first = alice.encrypt(b"epoch-0").unwrap();
        assert_eq!(bob.decrypt(&first, &SHARED).unwrap(), b"epoch-0");
        let reply = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&reply, &SHARED).unwrap(), b"reply");

        let second = alice.encrypt(b"epoch-1").unwrap();
        let first_header = alice.header_for_test(&first).unwrap();
        let second_header = alice.header_for_test(&second).unwrap();
        assert_ne!(first_header.epoch_id, second_header.epoch_id);

        let secret = &alice.sessions[0].header_secret;
        let key0 = derive_header_key(secret, first_header.epoch_id).unwrap();
        let key1 = derive_header_key(secret, second_header.epoch_id).unwrap();
        assert_ne!(*key0, *key1, "header key must rotate with the epoch");
    }

    #[test]
    fn randomized_padding_is_not_correlated_with_counter() {
        let (mut alice, _bob) = pair();
        let mut lengths = Vec::new();
        for index in 0..24u32 {
            let packet = alice.encrypt(b"same plaintext").unwrap();
            let header = alice.header_for_test(&packet).unwrap();
            assert_eq!(header.n, index);
            assert!(
                packet.len() >= crate::crypto::SIZE_TINY && packet.len() <= crate::crypto::SIZE_TINY + crate::crypto::SIZE_TINY / 8,
                "unexpected bucket size {}",
                packet.len()
            );
            lengths.push(packet.len());
        }

        assert!(
            lengths.windows(2).any(|pair| pair[0] != pair[1]),
            "randomized padding must vary inside the bucket: {:?}",
            lengths
        );
    }

    #[test]
    fn v2_packet_is_rejected_with_unsupported_version() {
        let (mut alice, mut bob) = pair();
        let mut packet = alice.encrypt(b"v2 downgrade").unwrap();
        packet[0] = 2;

        let error = bob.decrypt(&packet, &SHARED).unwrap_err();
        assert_error(&error, RatchetError::UnsupportedVersion(2));
    }

    #[test]
    fn session_alias_is_stable_hides_session_id_and_is_not_the_nonce() {
        let (mut alice, mut bob) = pair();
        let first = alice.encrypt(b"one").unwrap();
        let alias = OpenHeader::parse(&first).unwrap().alias;
        assert_eq!(alias, session_alias(&alice.session_id()).unwrap());
        assert_ne!(alias, alice.session_id());

        assert_eq!(bob.decrypt(&first, &SHARED).unwrap(), b"one");
        let reply = bob.encrypt(b"reply").unwrap();
        assert_eq!(alice.decrypt(&reply, &SHARED).unwrap(), b"reply");

        // Серия пакетов одной сессии: открытый стабильный идентификатор —
        // только alias, и он не равен session_id.
        for index in 0..5 {
            let packet = alice
                .encrypt(format!("series-{}", index).as_bytes())
                .unwrap();
            let open = OpenHeader::parse(&packet).unwrap();
            assert_eq!(open.alias, alias);
            assert_ne!(open.alias, alice.session_id());
        }
    }

    #[test]
    fn packet_size_validation_accepts_randomized_buckets_only() {
        assert!(is_valid_packet_len(256));
        assert!(is_valid_packet_len(256 + 256 / 8));
        assert!(!is_valid_packet_len(255));
        assert!(!is_valid_packet_len(256 + 256 / 8 + 1));
        assert!(is_valid_packet_len(65536 + 65536 / 8));
    }

}
