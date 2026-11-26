//! Чистый P2P-транспорт поверх скрытых сервисов Tor v3 (`.onion`).

pub mod tor_control;
pub mod transport;

pub use tor_control::{ProtocolInfo, TorAuthMethod, TorControlConnection, TorHiddenService};
pub use transport::{
    bind_inbound_listener, outbox_backoff_secs, read_frame, serve_inbound, write_frame,
    P2pSender, FRAME_ACK, MAX_FRAME_SIZE,
};
