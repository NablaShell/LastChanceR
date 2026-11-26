//! Управление локальным Tor ControlPort (`PROTOCOLINFO`, `AUTHENTICATE`, `ADD_ONION`).
//!
//! Скрытый сервис поднимается без `Flags=Detach` (живёт пока открыто
//! управляющее соединение), а приватный ключ `ED25519-V3:...` хранится
//! исключительно внутри зашифрованного `vault.dat`.

use crate::crypto::secret::SecretString;
use crate::types::OnionAddress;
use anyhow::{anyhow, Result};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use zeroize::Zeroizing;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONTROL_LINE_BYTES: usize = 8 * 1024;
const MAX_CONTROL_REPLY_LINES: usize = 64;
const MAX_COOKIE_FILE_BYTES: usize = 256;

const SAFECOOKIE_SERVER_KEY: &[u8] = b"Tor safe cookie authentication server-to-controller hash";
const SAFECOOKIE_CLIENT_KEY: &[u8] = b"Tor safe cookie authentication controller-to-server hash";

/// Методы аутентификации, поддерживаемые Tor ControlPort.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorAuthMethod {
    SafeCookie,
    Cookie,
    HashedPassword,
    Null,
}

/// Результат команды `PROTOCOLINFO 1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolInfo {
    pub auth_methods: Vec<TorAuthMethod>,
    pub cookie_file: Option<String>,
}

/// Зарегистрированный скрытый сервис Tor v3.
pub struct TorHiddenService {
    pub service_id: String,
    pub onion_address: OnionAddress,
    /// Возвращается Tor только при `ADD_ONION NEW:ED25519-V3`.
    pub private_key: Option<SecretString>,
}

impl std::fmt::Debug for TorHiddenService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TorHiddenService")
            .field("service_id", &self.service_id)
            .field("onion_address", &self.onion_address)
            .field("has_private_key", &self.private_key.is_some())
            .finish()
    }
}

/// Открытое управляющее соединение с Tor ControlPort.
pub struct TorControlConnection {
    reader: BufReader<TcpStream>,
}

impl TorControlConnection {
    /// Подключается к локальному Tor ControlPort по TCP.
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = tokio::time::timeout(CONTROL_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow!("Tor ControlPort connection timed out ({})", addr))?
            .map_err(|e| anyhow!("failed to connect to Tor ControlPort {}: {}", addr, e))?;

        Ok(Self {
            reader: BufReader::new(stream),
        })
    }

    async fn send_raw(&mut self, line: &str) -> Result<()> {
        tokio::time::timeout(CONTROL_TIMEOUT, async {
            self.reader.get_mut().write_all(line.as_bytes()).await?;
            self.reader.get_mut().flush().await
        })
        .await
        .map_err(|_| anyhow!("Tor ControlPort write timed out"))?
        .map_err(|e| anyhow!("Tor ControlPort write failed: {}", e))
    }

    async fn read_reply(&mut self) -> Result<Vec<String>> {
        let mut lines = Vec::new();
        for _ in 0..MAX_CONTROL_REPLY_LINES {
            let line = read_line_limited(&mut self.reader, MAX_CONTROL_LINE_BYTES).await?;
            if line.len() < 4 {
                return Err(anyhow!("malformed Tor ControlPort reply line"));
            }

            let code = &line[..3];
            let sep = line.as_bytes()[3];
            let body = &line[4..];

            if code != "250" {
                return Err(anyhow!("Tor ControlPort error ({}): {}", code, body));
            }

            lines.push(body.to_string());
            match sep {
                b'-' => continue,
                b' ' => return Ok(lines),
                _ => {
                    return Err(anyhow!(
                        "unsupported Tor ControlPort reply separator: {:?}",
                        sep as char
                    ))
                }
            }
        }
        Err(anyhow!("Tor ControlPort reply exceeded maximum line count"))
    }

    /// Запрашивает `PROTOCOLINFO 1` и разбирает допустимые методы аутентификации.
    pub async fn protocol_info(&mut self) -> Result<ProtocolInfo> {
        self.send_raw("PROTOCOLINFO 1\r\n").await?;
        let lines = self.read_reply().await?;
        parse_protocol_info(&lines)
    }

    /// Аутентифицируется перед Tor ControlPort (`SAFECOOKIE` > `COOKIE` > `NULL`).
    pub async fn authenticate(
        &mut self,
        info: &ProtocolInfo,
        cookie_override: Option<&str>,
    ) -> Result<()> {
        let cookie_path = cookie_override
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .or(info.cookie_file.as_deref());

        if info.auth_methods.contains(&TorAuthMethod::SafeCookie) {
            if let Some(path) = cookie_path {
                return self.authenticate_safecookie(path).await;
            }
        }

        if info.auth_methods.contains(&TorAuthMethod::Cookie) {
            if let Some(path) = cookie_path {
                return self.authenticate_cookie(path).await;
            }
        }

        if info.auth_methods.contains(&TorAuthMethod::Null) {
            self.send_raw("AUTHENTICATE\r\n").await?;
            let _ = self.read_reply().await?;
            return Ok(());
        }

        if cookie_path.is_none()
            && (info.auth_methods.contains(&TorAuthMethod::SafeCookie)
                || info.auth_methods.contains(&TorAuthMethod::Cookie))
        {
            return Err(anyhow!(
                "Tor ControlPort requires cookie auth, but COOKIEFILE was not reported and no cookie path is configured"
            ));
        }

        Err(anyhow!(
            "Tor ControlPort offered no supported authentication methods ({:?})",
            info.auth_methods
        ))
    }

    async fn authenticate_cookie(&mut self, cookie_path: &str) -> Result<()> {
        let cookie = read_cookie_file(cookie_path)?;
        let cmd = Zeroizing::new(format!("AUTHENTICATE {}\r\n", hex::encode(cookie.as_slice())));
        self.send_raw(&cmd).await?;
        let _ = self.read_reply().await?;
        Ok(())
    }

    async fn authenticate_safecookie(&mut self, cookie_path: &str) -> Result<()> {
        let cookie = read_cookie_file(cookie_path)?;
        let mut client_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut client_nonce);

        let challenge_cmd = format!("AUTHCHALLENGE SAFECOOKIE {}\r\n", hex::encode(client_nonce));
        self.send_raw(&challenge_cmd).await?;
        let reply = self.read_reply().await?;
        let (server_hash, server_nonce) = parse_authchallenge_reply(&reply)?;

        let mut msg = Zeroizing::new(Vec::with_capacity(cookie.len() + 64));
        msg.extend_from_slice(&cookie);
        msg.extend_from_slice(&client_nonce);
        msg.extend_from_slice(&server_nonce);

        let expected_server_hash = hmac_sha256(SAFECOOKIE_SERVER_KEY, &msg);
        if !constant_time_eq_32(&expected_server_hash, &server_hash) {
            return Err(anyhow!("Tor SAFECOOKIE server challenge verification failed"));
        }

        let client_hash = Zeroizing::new(hmac_sha256(SAFECOOKIE_CLIENT_KEY, &msg));
        let auth_cmd = Zeroizing::new(format!(
            "AUTHENTICATE {}\r\n",
            hex::encode(*client_hash)
        ));
        self.send_raw(&auth_cmd).await?;
        let _ = self.read_reply().await?;
        Ok(())
    }

    /// Регистрирует скрытый сервис Tor v3 (`ADD_ONION`) и пробрасывает виртуальный
    /// `onion_port` на `127.0.0.1:<local_port>`.
    pub async fn add_onion(
        &mut self,
        existing_private_key: Option<&SecretString>,
        onion_port: u16,
        local_port: u16,
    ) -> Result<TorHiddenService> {
        if onion_port == 0 || local_port == 0 {
            return Err(anyhow!("onion and local ports must be non-zero"));
        }

        let key_spec = match existing_private_key {
            Some(key) => {
                let raw = key.expose().trim();
                if !raw.starts_with("ED25519-V3:")
                    || raw.chars().any(|c| c.is_control() || c.is_whitespace())
                {
                    return Err(anyhow!("invalid stored ED25519-V3 Tor key format"));
                }
                raw
            }
            None => "NEW:ED25519-V3",
        };

        let cmd = Zeroizing::new(format!(
            "ADD_ONION {} Port={},127.0.0.1:{}\r\n",
            key_spec, onion_port, local_port
        ));
        self.send_raw(&cmd).await?;
        let lines = self.read_reply().await?;

        let mut service_id: Option<String> = None;
        let mut private_key: Option<SecretString> = None;

        for line in lines {
            if let Some(rest) = line.strip_prefix("ServiceID=") {
                service_id = Some(rest.trim().to_string());
            } else if let Some(rest) = line.strip_prefix("PrivateKey=") {
                private_key = Some(SecretString::new(rest.trim().to_string()));
            }
        }

        let service_id =
            service_id.ok_or_else(|| anyhow!("ADD_ONION reply did not include ServiceID"))?;
        let onion_address = OnionAddress::from_service_id(&service_id)
            .map_err(|e| anyhow!("Tor returned invalid v3 ServiceID: {}", e))?;

        Ok(TorHiddenService {
            service_id: onion_address.service_id().to_string(),
            onion_address,
            private_key,
        })
    }

    /// Проверяет живость управляющего соединения с Tor.
    pub async fn ping(&mut self) -> Result<()> {
        self.send_raw("GETINFO version\r\n").await?;
        let _ = self.read_reply().await?;
        Ok(())
    }
}

async fn read_line_limited<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    max_bytes: usize,
) -> Result<String> {
    let mut buf = Vec::with_capacity(128);
    let read_fut = async {
        loop {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                if buf.is_empty() {
                    return Err(anyhow!("Tor ControlPort closed connection"));
                }
                break;
            }

            if let Some(pos) = available.iter().position(|b| *b == b'\n') {
                let take = pos + 1;
                if buf.len() + take > max_bytes {
                    return Err(anyhow!("Tor ControlPort reply line exceeded {} bytes", max_bytes));
                }
                buf.extend_from_slice(&available[..take]);
                reader.consume(take);
                break;
            } else {
                let len = available.len();
                if buf.len() + len > max_bytes {
                    return Err(anyhow!("Tor ControlPort reply line exceeded {} bytes", max_bytes));
                }
                buf.extend_from_slice(available);
                reader.consume(len);
            }
        }
        Ok::<Vec<u8>, anyhow::Error>(buf)
    };

    let bytes = tokio::time::timeout(CONTROL_TIMEOUT, read_fut)
        .await
        .map_err(|_| anyhow!("Tor ControlPort read timed out"))??;

    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow!("Tor ControlPort returned non-UTF-8 line"))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_string())
}

fn parse_protocol_info(lines: &[String]) -> Result<ProtocolInfo> {
    let mut auth_methods = Vec::new();
    let mut cookie_file = None;

    for line in lines {
        let Some(rest) = line.strip_prefix("AUTH ") else {
            continue;
        };
        if let Some(methods_part) = rest.strip_prefix("METHODS=") {
            let (methods_list, tail) = match methods_part.split_once(' ') {
                Some((m, t)) => (m, Some(t)),
                None => (methods_part, None),
            };
            for method in methods_list.split(',') {
                match method.trim() {
                    "SAFECOOKIE" => auth_methods.push(TorAuthMethod::SafeCookie),
                    "COOKIE" => auth_methods.push(TorAuthMethod::Cookie),
                    "HASHEDPASSWORD" => auth_methods.push(TorAuthMethod::HashedPassword),
                    "NULL" => auth_methods.push(TorAuthMethod::Null),
                    _ => {}
                }
            }
            if let Some(tail) = tail {
                if let Some(cookie_raw) = tail.strip_prefix("COOKIEFILE=") {
                    cookie_file = Some(unquote_tor_string(cookie_raw)?);
                }
            }
        }
    }

    if auth_methods.is_empty() {
        return Err(anyhow!("PROTOCOLINFO did not advertise any AUTH METHODS"));
    }

    Ok(ProtocolInfo {
        auth_methods,
        cookie_file,
    })
}

fn unquote_tor_string(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                let escaped = chars
                    .next()
                    .ok_or_else(|| anyhow!("dangling escape in Tor quoted string"))?;
                out.push(escaped);
            } else {
                out.push(c);
            }
        }
        Ok(out)
    } else {
        Ok(trimmed.to_string())
    }
}

fn parse_authchallenge_reply(lines: &[String]) -> Result<([u8; 32], [u8; 32])> {
    for line in lines {
        if let Some(rest) = line.strip_prefix("AUTHCHALLENGE ") {
            let mut server_hash = None;
            let mut server_nonce = None;
            for part in rest.split_whitespace() {
                if let Some(val) = part.strip_prefix("SERVERHASH=") {
                    let bytes = hex::decode(val)
                        .map_err(|_| anyhow!("invalid SERVERHASH hex in AUTHCHALLENGE"))?;
                    server_hash = Some(
                        <[u8; 32]>::try_from(bytes)
                            .map_err(|_| anyhow!("SERVERHASH must be 32 bytes"))?,
                    );
                } else if let Some(val) = part.strip_prefix("SERVERNONCE=") {
                    let bytes = hex::decode(val)
                        .map_err(|_| anyhow!("invalid SERVERNONCE hex in AUTHCHALLENGE"))?;
                    server_nonce = Some(
                        <[u8; 32]>::try_from(bytes)
                            .map_err(|_| anyhow!("SERVERNONCE must be 32 bytes"))?,
                    );
                }
            }
            if let (Some(hash), Some(nonce)) = (server_hash, server_nonce) {
                return Ok((hash, nonce));
            }
        }
    }
    Err(anyhow!("malformed AUTHCHALLENGE reply from Tor"))
}

fn read_cookie_file(path: &str) -> Result<Zeroizing<Vec<u8>>> {
    let meta = std::fs::metadata(Path::new(path))
        .map_err(|e| anyhow!("cannot stat Tor cookie file {}: {}", path, e))?;
    if !meta.is_file() {
        return Err(anyhow!("Tor cookie path is not a regular file: {}", path));
    }
    if meta.len() == 0 || meta.len() > MAX_COOKIE_FILE_BYTES as u64 {
        return Err(anyhow!(
            "Tor cookie file {} has unexpected size {} bytes",
            path,
            meta.len()
        ));
    }
    let data = Zeroizing::new(
        std::fs::read(path)
            .map_err(|e| anyhow!("cannot read Tor cookie file {}: {}", path, e))?,
    );
    if data.is_empty() || data.len() > MAX_COOKIE_FILE_BYTES {
        return Err(anyhow!("Tor cookie file {} has invalid length", path));
    }
    Ok(data)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = Zeroizing::new([0u8; BLOCK_SIZE]);
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        key_block[..32].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = Zeroizing::new([0x36u8; BLOCK_SIZE]);
    let mut outer_pad = Zeroizing::new([0x5cu8; BLOCK_SIZE]);
    for i in 0..BLOCK_SIZE {
        inner_pad[i] ^= key_block[i];
        outer_pad[i] ^= key_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(&*inner_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&*outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn control_authenticates_with_cookie_and_creates_and_reloads_onion() {
        let dir = tempfile::tempdir().unwrap();
        let cookie_path = dir.path().join("control.authcookie");
        let cookie_bytes = [0x42u8; 32];
        std::fs::write(&cookie_path, cookie_bytes).unwrap();

        let service_addr = OnionAddress::test_v3_from_seed(9);
        let service_id = service_addr.service_id().to_string();
        let priv_key = "ED25519-V3:dGVzdC1wcml2YXRlLWtleQ==";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let expected_cookie_hex = hex::encode(cookie_bytes);
        let sid_clone = service_id.clone();

        tokio::spawn(async move {
            for expected_first_add in [true, false] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();

                // PROTOCOLINFO 1
                reader.read_line(&mut line).await.unwrap();
                assert_eq!(line.trim_end(), "PROTOCOLINFO 1");
                let reply = format!(
                    "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE COOKIEFILE=\"{}\"\r\n250 OK\r\n",
                    cookie_path.display()
                );
                reader.get_mut().write_all(reply.as_bytes()).await.unwrap();

                // AUTHENTICATE
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                assert_eq!(line.trim_end(), format!("AUTHENTICATE {}", expected_cookie_hex));
                reader.get_mut().write_all(b"250 OK\r\n").await.unwrap();

                // ADD_ONION
                line.clear();
                reader.read_line(&mut line).await.unwrap();
                if expected_first_add {
                    assert_eq!(
                        line.trim_end(),
                        "ADD_ONION NEW:ED25519-V3 Port=9878,127.0.0.1:19878"
                    );
                    let resp = format!(
                        "250-ServiceID={}\r\n250-PrivateKey={}\r\n250 OK\r\n",
                        sid_clone, priv_key
                    );
                    reader.get_mut().write_all(resp.as_bytes()).await.unwrap();
                } else {
                    assert_eq!(
                        line.trim_end(),
                        format!("ADD_ONION {} Port=9878,127.0.0.1:19879", priv_key)
                    );
                    let resp = format!("250-ServiceID={}\r\n250 OK\r\n", sid_clone);
                    reader.get_mut().write_all(resp.as_bytes()).await.unwrap();
                }
            }
        });

        // 1. Первое создание NEW:ED25519-V3
        let mut ctl = TorControlConnection::connect(&addr.to_string()).await.unwrap();
        let info = ctl.protocol_info().await.unwrap();
        ctl.authenticate(&info, None).await.unwrap();
        let hs = ctl.add_onion(None, 9878, 19878).await.unwrap();
        assert_eq!(hs.service_id, service_id);
        assert_eq!(hs.onion_address, service_addr);
        let saved_key = hs.private_key.expect("NEW must return PrivateKey");
        assert_eq!(saved_key.expose(), priv_key);
        drop(ctl);

        // 2. Повторный запуск с сохранённым ключом из Vault
        let mut ctl2 = TorControlConnection::connect(&addr.to_string()).await.unwrap();
        let info2 = ctl2.protocol_info().await.unwrap();
        ctl2.authenticate(&info2, None).await.unwrap();
        let hs2 = ctl2.add_onion(Some(&saved_key), 9878, 19879).await.unwrap();
        assert_eq!(hs2.service_id, service_id);
        assert!(hs2.private_key.is_none());
    }

    #[tokio::test]
    async fn control_authenticates_with_safecookie_and_verifies_server_hash() {
        let dir = tempfile::tempdir().unwrap();
        let cookie_path = dir.path().join("control.authcookie");
        let cookie_bytes = [0x77u8; 32];
        std::fs::write(&cookie_path, cookie_bytes).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();

            reader.read_line(&mut line).await.unwrap();
            let reply = format!(
                "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=SAFECOOKIE,COOKIE COOKIEFILE=\"{}\"\r\n250 OK\r\n",
                cookie_path.display()
            );
            reader.get_mut().write_all(reply.as_bytes()).await.unwrap();

            line.clear();
            reader.read_line(&mut line).await.unwrap();
            let client_nonce_hex = line
                .trim_end()
                .strip_prefix("AUTHCHALLENGE SAFECOOKIE ")
                .unwrap();
            let client_nonce = hex::decode(client_nonce_hex).unwrap();
            let server_nonce = [0x33u8; 32];

            let mut msg = Vec::new();
            msg.extend_from_slice(&cookie_bytes);
            msg.extend_from_slice(&client_nonce);
            msg.extend_from_slice(&server_nonce);
            let server_hash = hmac_sha256(SAFECOOKIE_SERVER_KEY, &msg);
            let expected_client_hash = hmac_sha256(SAFECOOKIE_CLIENT_KEY, &msg);

            let resp = format!(
                "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                hex::encode(server_hash),
                hex::encode(server_nonce)
            );
            reader.get_mut().write_all(resp.as_bytes()).await.unwrap();

            line.clear();
            reader.read_line(&mut line).await.unwrap();
            assert_eq!(
                line.trim_end(),
                format!("AUTHENTICATE {}", hex::encode(expected_client_hash))
            );
            reader.get_mut().write_all(b"250 OK\r\n").await.unwrap();
        });

        let mut ctl = TorControlConnection::connect(&addr.to_string()).await.unwrap();
        let info = ctl.protocol_info().await.unwrap();
        ctl.authenticate(&info, None).await.unwrap();
    }

    #[tokio::test]
    async fn control_rejects_injected_newlines_in_stored_key() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut ctl = TorControlConnection::connect(&addr.to_string()).await.unwrap();
        let injected = SecretString::new("ED25519-V3:abc\r\nSIGNAL SHUTDOWN".to_string());
        assert!(ctl.add_onion(Some(&injected), 9878, 19878).await.is_err());
    }
}
