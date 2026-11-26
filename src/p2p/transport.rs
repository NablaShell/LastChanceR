//! P2P-транспорт поверх Tor v3 hidden services.
//!
//! - Входящий поток: `tokio::net::TcpListener` на `127.0.0.1:<local_port>`,
//!   принимающий фреймы `[len: u32 BE][ratchet_v3_packet]` с жёстким лимитом
//!   размера до аллокации и отправляющий транспортный ACK (`b"OK"`).
//! - Исходящий поток: подключение напрямую на `<peer>.onion:<port>` через
//!   SOCKS5h (`ATYP=0x03` DOMAINNAME, без локального DNS) по `tor_socks_addr`.

use crate::crypto::ratchet::is_valid_packet_len;
use crate::network::Config;
use crate::types::OnionAddress;
use anyhow::{anyhow, Result};
use log::{debug, warn};
use std::future::Future;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

/// Максимальный размер фрейма (равен максимальному bucket + jitter v3-храповика: 73 728 Б).
pub const MAX_FRAME_SIZE: usize = crate::crypto::SIZE_MAX + crate::crypto::SIZE_MAX / 8;
/// Ограничение числа одновременных входящих соединений на локальном listener.
pub const MAX_INBOUND_CONNECTIONS: usize = 64;
/// Максимум фреймов в рамках одного входящего TCP-потока.
pub const MAX_FRAMES_PER_CONN: usize = 32;
/// Таймаут на чтение/запись отдельного фрейма и ACK.
pub const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// Таймаут на установку Tor-цепочки через SOCKS5h.
pub const SOCKS_CONNECT_TIMEOUT: Duration = Duration::from_secs(45);
/// Транспортное подтверждение приёма фрейма.
pub const FRAME_ACK: [u8; 2] = *b"OK";
/// Ступени экспоненциального backoff для Outbox (в секундах).
pub const OUTBOX_BACKOFF_SECS: [i64; 6] = [5, 15, 30, 60, 180, 600];

/// Вычисляет задержку следующей попытки Outbox по номеру неудачной попытки.
pub fn outbox_backoff_secs(attempt: u32) -> i64 {
    let idx = (attempt as usize).min(OUTBOX_BACKOFF_SECS.len() - 1);
    OUTBOX_BACKOFF_SECS[idx]
}

/// Читает один length-prefixed фрейм (`u32` big-endian + payload).
///
/// Возвращает `Ok(None)` при чистом закрытии соединения на границе фрейма.
/// Длина проверяется против [`MAX_FRAME_SIZE`] и v3 bucket-сетки *до* аллокации.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    let first_read = tokio::time::timeout(IO_TIMEOUT, reader.read(&mut len_buf[..1]))
        .await
        .map_err(|_| anyhow!("frame header read timed out"))?;
    let n = first_read.map_err(|e| anyhow!("failed to read frame length: {}", e))?;
    if n == 0 {
        return Ok(None);
    }

    tokio::time::timeout(IO_TIMEOUT, reader.read_exact(&mut len_buf[1..]))
        .await
        .map_err(|_| anyhow!("frame header read timed out"))?
        .map_err(|e| anyhow!("truncated frame header: {}", e))?;

    let frame_len = u32::from_be_bytes(len_buf) as usize;
    if frame_len == 0 || frame_len > MAX_FRAME_SIZE {
        return Err(anyhow!(
            "frame size {} is outside allowed bounds (1..={})",
            frame_len,
            MAX_FRAME_SIZE
        ));
    }
    if !is_valid_packet_len(frame_len) {
        return Err(anyhow!(
            "frame size {} is outside Double Ratchet v3 padding grid",
            frame_len
        ));
    }

    let mut payload = vec![0u8; frame_len];
    tokio::time::timeout(IO_TIMEOUT, reader.read_exact(&mut payload))
        .await
        .map_err(|_| anyhow!("frame payload read timed out"))?
        .map_err(|e| anyhow!("truncated frame payload: {}", e))?;

    Ok(Some(payload))
}

/// Записывает один length-prefixed фрейм (`u32` big-endian + payload).
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, payload: &[u8]) -> Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME_SIZE {
        return Err(anyhow!(
            "invalid outgoing frame size {} (limit {})",
            payload.len(),
            MAX_FRAME_SIZE
        ));
    }
    if !is_valid_packet_len(payload.len()) {
        return Err(anyhow!(
            "outgoing packet size {} is outside Double Ratchet v3 padding grid",
            payload.len()
        ));
    }

    let len_bytes = u32::try_from(payload.len())
        .map_err(|_| anyhow!("frame length overflow"))?
        .to_be_bytes();

    tokio::time::timeout(IO_TIMEOUT, async {
        writer.write_all(&len_bytes).await?;
        writer.write_all(payload).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| anyhow!("frame write timed out"))?
    .map_err(|e| anyhow!("failed to write frame: {}", e))
}

/// Привязывает входящий TCP-listener строго к `127.0.0.1:<local_port>`.
pub async fn bind_inbound_listener(local_port: u16) -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(|e| anyhow!("failed to bind P2P listener on 127.0.0.1:{}: {}", local_port, e))?;
    let port = listener
        .local_addr()
        .map_err(|e| anyhow!("failed to read bound P2P local port: {}", e))?
        .port();
    Ok((listener, port))
}

/// Принимает входящие P2P-соединения от локального Tor hidden service.
pub async fn serve_inbound<F, Fut>(listener: TcpListener, handler: F)
where
    F: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    let handler = Arc::new(handler);
    let semaphore = Arc::new(Semaphore::new(MAX_INBOUND_CONNECTIONS));

    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!("[P2P] inbound accept error: {}", e);
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };

        let permit = match semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("[P2P] inbound connection limit reached, dropping peer stream");
                let _ = stream.shutdown().await;
                continue;
            }
        };

        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            for _ in 0..MAX_FRAMES_PER_CONN {
                match read_frame(&mut stream).await {
                    Ok(Some(packet)) => {
                        handler(packet).await;
                        if tokio::time::timeout(IO_TIMEOUT, async {
                            stream.write_all(&FRAME_ACK).await?;
                            stream.flush().await
                        })
                        .await
                        .is_err()
                        {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!("[P2P] inbound frame rejected: {}", e);
                        break;
                    }
                }
            }
            let _ = stream.shutdown().await;
        });
    }
}

/// Устанавливает TCP-туннель через SOCKS5h (`ATYP=0x03` DOMAINNAME).
///
/// Имя `.onion` передаётся прокси-серверу Tor целиком: локальный DNS не
/// вызывается ни при каких условиях.
pub async fn connect_socks5h(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    if target_port == 0 {
        return Err(anyhow!("target port must be non-zero"));
    }
    let host_bytes = target_host.as_bytes();
    if host_bytes.is_empty() || host_bytes.len() > u8::MAX as usize || !target_host.is_ascii() {
        return Err(anyhow!("invalid SOCKS5h target hostname"));
    }

    let mut stream = tokio::time::timeout(SOCKS_CONNECT_TIMEOUT, TcpStream::connect(proxy_addr))
        .await
        .map_err(|_| anyhow!("Tor SOCKS5h proxy connect timed out ({})", proxy_addr))?
        .map_err(|e| anyhow!("failed to connect to Tor SOCKS5h {}: {}", proxy_addr, e))?;

    tokio::time::timeout(SOCKS_CONNECT_TIMEOUT, async {
        // Greeting: VER=5, NMETHODS=1, METHOD=0 (NO AUTH)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        stream.flush().await?;

        let mut choice = [0u8; 2];
        stream.read_exact(&mut choice).await?;
        if choice[0] != 0x05 {
            return Err(anyhow!("unexpected SOCKS version from proxy: {}", choice[0]));
        }
        if choice[1] != 0x00 {
            return Err(anyhow!("Tor SOCKS5h proxy rejected no-auth method: {}", choice[1]));
        }

        // CONNECT request: VER=5, CMD=1, RSV=0, ATYP=3 (DOMAINNAME)
        let mut req = Vec::with_capacity(7 + host_bytes.len());
        req.push(0x05);
        req.push(0x01);
        req.push(0x00);
        req.push(0x03);
        req.push(host_bytes.len() as u8);
        req.extend_from_slice(host_bytes);
        req.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&req).await?;
        stream.flush().await?;

        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await?;
        if header[0] != 0x05 {
            return Err(anyhow!("unexpected SOCKS5 reply version: {}", header[0]));
        }

        // Вычитываем BND.ADDR + BND.PORT согласно ATYP, чтобы поток остался синхронизирован.
        match header[3] {
            0x01 => {
                let mut skip = [0u8; 4 + 2];
                stream.read_exact(&mut skip).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut skip = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut skip).await?;
            }
            0x04 => {
                let mut skip = [0u8; 16 + 2];
                stream.read_exact(&mut skip).await?;
            }
            other => {
                return Err(anyhow!("invalid SOCKS5 BND ATYP: {}", other));
            }
        }

        if header[1] != 0x00 {
            return Err(anyhow!("SOCKS5h connect failed: {}", socks5_error_label(header[1])));
        }

        Ok(())
    })
    .await
    .map_err(|_| anyhow!("Tor SOCKS5h handshake timed out"))??;

    Ok(stream)
}

fn socks5_error_label(code: u8) -> &'static str {
    match code {
        0x01 => "general SOCKS server failure",
        0x02 => "connection not allowed by ruleset",
        0x03 => "network unreachable",
        0x04 => "host unreachable (peer .onion offline or descriptor unavailable)",
        0x05 => "connection refused by peer",
        0x06 => "TTL expired (Tor circuit timeout)",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown SOCKS5 error",
    }
}

/// Исходящий P2P-отправитель поверх Tor SOCKS5h.
pub struct P2pSender {
    config: RwLock<Config>,
}

impl P2pSender {
    pub fn new(config: &Config) -> Self {
        Self {
            config: RwLock::new(config.clone()),
        }
    }

    pub fn update_config(&self, config: &Config) -> Result<()> {
        let mut guard = self
            .config
            .write()
            .map_err(|_| anyhow!("P2P sender config lock poisoned"))?;
        *guard = config.clone();
        Ok(())
    }

    fn current_config(&self) -> Result<Config> {
        self.config
            .read()
            .map(|cfg| cfg.clone())
            .map_err(|_| anyhow!("P2P sender config lock poisoned"))
    }

    /// Отправляет зашифрованный Double Ratchet пакет напрямую на `<peer>.onion:<port>`
    /// через Tor SOCKS5h и дожидается транспортного подтверждения `FRAME_ACK`.
    pub async fn send_packet(&self, target: &OnionAddress, packet: &[u8]) -> Result<()> {
        if !is_valid_packet_len(packet.len()) {
            return Err(anyhow!(
                "invalid packet size {} (expected v3 ratchet bucket)",
                packet.len()
            ));
        }

        let cfg = self.current_config()?;
        let socks_addr = cfg.effective_tor_socks_addr();
        let onion_port = cfg.effective_p2p_onion_port();

        let mut stream = connect_socks5h(&socks_addr, target.as_str(), onion_port).await?;
        send_on_stream(&mut stream, packet).await
    }

    /// Локальная TCP-отправка без SOCKS5h — только на loopback (`127.0.0.1` / `::1`)
    /// для self-chat и интеграционных тестов.
    pub async fn send_packet_direct(
        &self,
        addr: std::net::SocketAddr,
        packet: &[u8],
    ) -> Result<()> {
        if !addr.ip().is_loopback() {
            return Err(anyhow!("direct P2P transport is restricted to loopback addresses"));
        }
        if !is_valid_packet_len(packet.len()) {
            return Err(anyhow!(
                "invalid packet size {} (expected v3 ratchet bucket)",
                packet.len()
            ));
        }
        let mut stream = tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("loopback TCP connect timed out"))?
            .map_err(|e| anyhow!("loopback TCP connect failed: {}", e))?;
        send_on_stream(&mut stream, packet).await
    }
}

async fn send_on_stream(stream: &mut TcpStream, packet: &[u8]) -> Result<()> {
    write_frame(stream, packet).await?;

    let mut ack = [0u8; FRAME_ACK.len()];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut ack))
        .await
        .map_err(|_| anyhow!("timed out waiting for peer frame ACK"))?
        .map_err(|e| anyhow!("failed to read peer frame ACK: {}", e))?;

    if ack != FRAME_ACK {
        return Err(anyhow!("unexpected peer ACK response"));
    }

    let _ = stream.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ratchet::{RatchetState, Role};
    use std::io::Cursor;

    fn sample_packet() -> Vec<u8> {
        RatchetState::new(&[7u8; 32], Role::Initiator)
            .unwrap()
            .encrypt(b"hello over tor")
            .unwrap()
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_and_invalid_bucket_before_allocation() {
        // Превышение MAX_FRAME_SIZE отклоняется сразу по 4-байтовому заголовку.
        let mut raw = Vec::new();
        raw.extend_from_slice(&((MAX_FRAME_SIZE as u32) + 1).to_be_bytes());
        let mut cursor = Cursor::new(raw);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert!(err.to_string().contains("outside allowed bounds"));

        // Размер 0 отклоняется.
        let mut cursor_zero = Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(read_frame(&mut cursor_zero).await.is_err());

        // Произвольный размер вне v3 bucket-сетки (например 500) отклоняется до чтения тела.
        let mut cursor_bad_bucket = Cursor::new(500u32.to_be_bytes().to_vec());
        let err = read_frame(&mut cursor_bad_bucket).await.unwrap_err();
        assert!(err.to_string().contains("padding grid"));
    }

    #[tokio::test]
    async fn inbound_listener_and_direct_sender_round_trip_with_ack() {
        let (listener, port) = bind_inbound_listener(0).await.unwrap();
        let addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(serve_inbound(listener, move |packet| {
            let tx = tx.clone();
            async move {
                let _ = tx.send(packet);
            }
        }));

        let packet = sample_packet();
        let sender = P2pSender::new(&Config::default());
        sender.send_packet_direct(addr, &packet).await.unwrap();

        let received = rx.recv().await.expect("packet delivered");
        assert_eq!(received, packet);
    }

    #[tokio::test]
    async fn socks5h_connect_sends_domain_atyp_and_maps_errors() {
        let target = OnionAddress::test_v3_from_seed(5);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        // 1. Успешное SOCKS5h рукопожатие + проверка ATYP=0x03
        let target_clone = target.clone();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x00]);
            sock.write_all(&[0x05, 0x00]).await.unwrap();

            let mut hdr = [0u8; 5];
            sock.read_exact(&mut hdr).await.unwrap();
            assert_eq!(&hdr[..4], &[0x05, 0x01, 0x00, 0x03]);
            let host_len = hdr[4] as usize;
            let mut host_port = vec![0u8; host_len + 2];
            sock.read_exact(&mut host_port).await.unwrap();
            assert_eq!(
                std::str::from_utf8(&host_port[..host_len]).unwrap(),
                target_clone.as_str()
            );
            assert_eq!(
                u16::from_be_bytes([host_port[host_len], host_port[host_len + 1]]),
                9878
            );

            // Ответ SOCKS5: success, IPv4 0.0.0.0:0
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();

            // Принимаем фрейм и отвечаем OK
            let frame = read_frame(&mut sock).await.unwrap().unwrap();
            assert!(!frame.is_empty());
            sock.write_all(&FRAME_ACK).await.unwrap();
        });

        let cfg = Config {
            tor_socks_addr: proxy_addr.to_string(),
            p2p_onion_port: 9878,
            ..Config::default()
        };
        let sender = P2pSender::new(&cfg);
        sender.send_packet(&target, &sample_packet()).await.unwrap();

        // 2. Ошибка SOCKS5 0x04 (host unreachable) корректно пробрасывается
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr2 = listener2.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener2.accept().await.unwrap();
            let mut greet = [0u8; 3];
            sock.read_exact(&mut greet).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut hdr = [0u8; 5];
            sock.read_exact(&mut hdr).await.unwrap();
            let mut rest = vec![0u8; hdr[4] as usize + 2];
            sock.read_exact(&mut rest).await.unwrap();
            sock.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });

        let cfg2 = Config {
            tor_socks_addr: proxy_addr2.to_string(),
            p2p_onion_port: 9878,
            ..Config::default()
        };
        let sender2 = P2pSender::new(&cfg2);
        let err = sender2
            .send_packet(&target, &sample_packet())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("host unreachable"));
    }
}
