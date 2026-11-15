# LastChance

I didn't feel like writing up the details, so this is a very rough version. I’d appreciate help with security testing and UI improvements. Run at your own risk.

**English** · [Русская версия](#русская-версия)

LastChance is a privacy-focused messenger written in Rust. It has no GUI: the client is a lightweight terminal UI (TUI) built with `ratatui` and `crossterm`. The network core and cryptography are kept separate from the interface, so the same engine can be used by another frontend later.

This is still early software. The code is not audited, the protocol is not final, and you should not rely on it for life-critical secrecy yet.

---

## What it does

- End-to-end encrypted one-to-one text chat over your own HTTP server.
- A separate file-transfer contour: files are encrypted locally, uploaded to a file server, and the chat only carries a file hash.
- Fixed-size padded packets for text messages.
- Identity based on a BIP-39 seed phrase, X25519 for key exchange and Ed25519 for authentication.
- Encrypted local storage protected by a master password (Argon2id + XChaCha20-Poly1305).
- HTTP long-polling for incoming messages.
- Optional SOCKS5/HTTP proxy support, including `socks5h://` with remote DNS (Tor/I2P).
- Stealth system notifications that can hide the name of the messenger.
- Ephemeral messages: a per-room TTL timer (local or synced with the peer) keeps the ratchet state in RAM only.
- English and Russian interface with a language picker on first launch.
- A TUI with a help window, a settings wizard, tab completion, input history, mouse scrolling and a file picker.

There is no server bundled with the client. You need to run your own compatible text and file API servers and set their URLs with `/set`.

---

## Architecture

The crate is split into a reusable core library and a thin TUI binary:

| Path | Responsibility |
| --- | --- |
| `src/crypto/` | X25519 ECDH, HKDF, XChaCha20-Poly1305, Ed25519, identity hash, frame format |
| `src/identity/` | Seed generation, key derivation, encrypted `identity.json` |
| `src/network/config.rs` | Encrypted `global.conf`, proxy/notification settings |
| `src/network/sender.rs` | `POST /push/<hash>`, file upload |
| `src/network/listener.rs` | Long-poll `GET /pull/<hash>`, multipart parsing, file download |
| `src/storage/` | Safe filesystem operations and the encrypted local vault |
| `src/vault.rs` | Master-key derivation and local encryption |
| `src/app.rs` | Core application logic, events, contacts, sending/receiving |
| `src/main.rs` | Terminal UI, commands, modals and startup flow |

Message flow:

```text
keyboard ──> TUI (main.rs)
                │
                ▼
             App (app.rs) ──> Sender ──> text API server
                │
                ├──> Storage (in-memory SQLite, `vault.dat`)
                ├──> Vault (master key, Argon2id)
                └──> Listener <── long-poll <── text API server

files: App ──> encrypt with the room secret ──> file API server
       App <── download by hash ── decrypt with the room secret
```

`src/lib.rs` exposes `App`, `Config`, `Vault` and storage helpers. `src/main.rs` is only the terminal client. The core has no TUI dependencies.

---

## Cryptography and packets

### Identity

- A 32-byte random seed is encoded as a BIP-39 mnemonic. `/recovery` asks for the current master password, shows the current phrase and can overwrite the identity with a phrase of 12/15/18/21/24 words; restart the client after restoring.
- Two key pairs are derived from the seed with HKDF-SHA256:
  - X25519 (`X25519_E2EE_Key_v1`) for message/file encryption;
  - Ed25519 (`Ed25519_Auth_Key_v1`) for authentication.
- The public identity hash is `SHA256(Ed25519 public key)`, hex-encoded.
- A contact invite contains the signed canonical CBOR identity document (`doc`) and its Ed25519 signature (`sig`):

```text
lastchance://contact?hash=...&doc=<cbor-hex>&sig=<signature-hex>&x25519=...&ed25519=...&nickname=...
```

- `doc` encodes `version`, `ed25519_pub`, `x25519_pub`, the optional `nickname` and `created_at` using RFC 8949 deterministic CBOR (sorted keys, minimal integers). `sig` is Ed25519 over the exact `doc` bytes. The `hash`, `x25519`, `ed25519` and `nickname` parameters are unsigned copies and must match the signed document.
- Imports reject legacy/unsigned links, duplicate parameters, invalid signatures and any `Ed25519 ↔ X25519 ↔ hash` mismatch. The invite fingerprint is `SHA256("lastchance:identity-fingerprint:v1" || ed25519_pub || x25519_pub)`; compare it out-of-band before trusting a contact.
- Each contact stores its fingerprint and TOFU state (`pending`, `verified` or `changed`). If the X25519 key changes under the same signed Ed25519 identity, the contact is marked `changed` and must be verified again.
- In the contact manager (`/contacts`, `/cnt`, `/ls`, `/c`), `↑`/`↓` or `j`/`k` select a contact, `Enter` opens the chat, `/` filters, `r` renames, `i` shows the fingerprint and TOFU state, `c` copies the fingerprint, `d` deletes and `q`/`Esc` closes. In the info view, `v` marks the fingerprint as verified after an out-of-band check, while `Esc` or `i` returns to the list.

- `/pull` requests are signed with Ed25519 over `timestamp + identity_hash`; the server receives the public key in `X-Identity-Key`, the timestamp in `X-Timestamp` and the signature in `X-Signature`.

### Message encryption

- Each contact has a static shared secret: `X25519(my_private, their_public)` followed by HKDF-SHA256 with the `ECDH_v1` label. It seeds the Double Ratchet session.
- ECDH rejects invalid curve points: an all-zero X25519 output (low-order point) aborts the key agreement instead of producing a shared secret.
- Messages use a Double Ratchet over X25519 ephemeral DH steps, HKDF-SHA256 (`RootKey`, `ChainKey`, `MessageKey`) and XChaCha20-Poly1305 with a fresh 24-byte nonce.
- The v2 open ratchet header is `version (1) || session_id (16) || bootstrap_nonce (32) || dh_pub (32) || n (u32) || pn (u32)`; the whole header is authenticated as AEAD AAD. Inside the encrypted frame: `payload_len (u32) || payload || random padding`.
- Every ratchet state gets a fresh CSPRNG `session_id` and `bootstrap_nonce`. Bootstrap keys are derived as `HKDF(salt = bootstrap_nonce, ikm = shared_secret, info = role label)`; the peer derives the same context from the nonce carried in the packet. After a TTL change or `/ratchet-reset` the next session uses new entropy, so a captured bootstrap packet from an old session cannot be accepted by a new one.
- Destroyed and evicted `session_id` values are remembered and rejected as `StaleSession` even when the AEAD tag is valid. For normal rooms these tombstones are stored in `vault.dat` and survive a client restart; for RAM-TTL rooms they intentionally live only in RAM (H-3) and are lost on restart. The tombstone registry holds up to 128 ids: a `session_id` changes only on reset, TTL transition or session eviction, not on every DH epoch, so 128 entries cover 32 full windows of 4 concurrent sessions. v1 ratchet packets are rejected outright: there is no downgrade path.
- Received peer `dh_pub` values are remembered per session (last 128). A packet whose `dh_pub` was already accepted but whose epoch has left the 5-epoch window is rejected as `ReplayedDhPub` before any cryptography; the registry is filled only after a successful authentication, and a new session starts with an empty registry. `remote_pub` never rewinds when a packet from an epoch already present in the receive window is accepted. The v2 header has no epoch counter, so a genuine but previously unseen older `dh_pub` is indistinguishable from a new epoch and is accepted as one; it can therefore move `remote_pub` to that authentic older key. Forgery is impossible (AEAD), the effect is bounded by the 5-epoch window, and a complete fix requires an epoch counter in a v3 wire format. The newest epoch is never evicted; when the window is full and nothing but protected epochs remains, decryption fails with `EpochOverflow` and leaves the state untouched.
- The client keeps a sliding window of the last 5 epochs (plus up to 32 skipped message keys per epoch), so messages sent concurrently or delivered out of order still decrypt. Old epochs and used message keys are wiped with `Zeroizing`.
- Total packet sizes remain one of:

```text
256 B   1024 B   4096 B   65536 B
```

- The final ratchet packet is `header || nonce || ciphertext || tag`; only those four exact sizes are accepted. Legacy static-secret frames are still accepted for compatibility with older clients.
- `/ratchet-reset` forces a fresh session with the active contact and notifies the peer. The reset creates a new `session_id`, `bootstrap_nonce` and bootstrap keys.

This hides the exact message length inside one of four size classes. It does not hide the size class itself.

### File encryption

Files use the same per-contact shared secret but a different contour:

- the file is encrypted as a whole with XChaCha20-Poly1305 (`nonce || ciphertext || tag`, no fixed padding);
- the encrypted blob is uploaded to the file server (up to 100 MB);
- the server returns a file hash;
- the chat receives a normal encrypted message containing the file name, size and hash;
- the recipient downloads the blob by hash and decrypts it locally.

The text server and the file server are separate URLs configured independently.

### What the servers can see

The text server sees the recipient hash in the URL, the packet size class, the timing and the masking headers. The file server sees the encrypted blob size and its hash. Message and file contents remain encrypted end to end.

---

## Local vault and storage

On first launch the client asks for a master password (minimum 8 characters). The password is never stored.

- A random 32-byte salt is written to `vault.salt`.
- The master key is derived with Argon2id (19 MiB, 2 passes, 1 lane) and kept in memory inside `Zeroizing`.
- `vault.check` is an encrypted marker used to detect a wrong password.
- `identity.json` and `global.conf` are sealed as `LCVAULT1 || nonce || ciphertext || tag` with XChaCha20-Poly1305 and associated data.
- Contacts, rooms, messages, file records and normal Double Ratchet sessions live in an in-memory SQLite database; nothing is ever written to `user.db`, `user.db-wal` or `user.db-shm`.
- On every change the whole database is serialized, padded with random bytes to a multiple of 4096 and sealed with XChaCha20-Poly1305 into `vault.dat` as `nonce || ciphertext || tag`; no magic bytes or open headers are stored on disk. The schema version and payload length sit inside the encrypted block.
- Rooms with an active `/ttl` or `/ttl-syn` timer keep the ratchet state strictly in RAM: it is never written to `vault.dat` and is wiped when TTL is disabled or the client exits.
- `vault.dat` is replaced atomically through a temporary file and receives mode `0600` on Unix.
- A legacy plaintext `user.db` is imported on first open, after which `user.db`, `user.db-wal` and `user.db-shm` are overwritten with zeros and deleted.
- Files created by the client are written with mode `0600` on Unix; a read-only fallback is used where POSIX permissions are unavailable.

`/passwd` verifies the old password, re-encrypts `identity.json`, `global.conf` and all sensitive database fields, replaces the in-memory key and only then writes the new salt/check files. If a step fails, the client tries to roll the old key back.

Contact hashes, public keys, room hashes, message direction/status and timestamps remain plaintext metadata inside the local database; they are needed for lookups and ordering.

The data directory is chosen in this order:

1. `--profile-dir <path>` or `--profile-dir=<path>` (`--data-dir` is a legacy alias).
2. The `LASTCHANCE_DIR` environment variable.
3. Portable mode: if a `.portable` file exists next to the executable, use `data/` beside it.
4. Default: `dirs::config_dir()/lastchance` — `~/.config/lastchance` on Linux (`$XDG_CONFIG_HOME/lastchance` when set), `~/Library/Application Support/lastchance` on macOS, `%APPDATA%\lastchance` on Windows.

On first start, if the new directory does not exist and the old data directory (`~/.local/share/lastchance` on Linux, `%LOCALAPPDATA%\lastchance` on Windows) is non-empty, the client copies the profile automatically. Directories are set to `0700` and files to `0600`; the old directory is kept intact.

The directory contains `identity.json`, `global.conf`, `vault.dat`, `vault.salt` and `vault.check`.

---

## Transport

### Text API

- Send: `POST /push/<target_hash>` with `application/octet-stream`.
- Receive: `GET /pull/<identity_hash>?wait=25`.
- The server holds an empty long-poll for up to 25 seconds; the client uses a 45-second timeout.
- `204 No Content` means the queue is empty.
- A successful pull returns `multipart/form-data`; the client parses the parts and checks that packet sizes are in the allowed grid.
- `429` means rate limiting. Pull retries use a 1s → 2s → 5s → 15s backoff for retryable failures; `401` and protocol errors are retried slowly to avoid a busy loop.
- Push retries up to four attempts with exponential backoff on `429` and transport errors.

### File API

- Upload: `POST /upload` with `application/octet-stream`, `X-File-Name` and `Content-Length`; the response body is the file hash.
- Download: `GET /download/<file_hash>`.
- The download request has its own 300-second timeout; uploads are limited to 100 MB.

### Response limits and input validation

Untrusted identifiers (identity/contact hash from an invite, file hash from the server or a message) are parsed into `IdentityHash`/`FileHash`/`RoomId` at the boundary. Only exactly 64 ASCII hex characters are accepted; non-ASCII, short/long or non-hex input is rejected with a typed error before any byte slicing, database write or URL construction. UI/log output uses `truncate_display()` / `short_hash()`, which operate on characters and never split UTF-8.

Response bodies are streamed with hard limits. The limits are inclusive: exactly `MAX_*` bytes are accepted, `MAX_* + 1` is rejected.

| Limit | Value | Scope |
| --- | --- | --- |
| `MAX_MESSAGE_BODY` | 8 MiB | `/pull` multipart body |
| `MAX_FILE_BODY` | 256 MiB | `/download` body |
| `MAX_MULTIPART_PARTS` | 16 | parts per response |
| `MAX_MULTIPART_HEADERS` | 32 | headers per part |
| `MAX_MULTIPART_HEADER_BYTES` | 8 KiB | headers per part |
| `MAX_MULTIPART_BOUNDARY` | 200 bytes | `boundary=` value |
| `MAX_ERROR_BODY` | 64 KiB | `401`/`4xx`/`5xx` body |
| `BODY_READ_TIMEOUT` | 60 s | the whole body, not one chunk |

`Content-Length` is not trusted: a declared size above the limit is rejected before reading the body, a body that grows past the declared size is aborted, and a shorter body is an integrity error (fail-closed). Chunked responses are counted while reading and are never fully buffered past the limit. Downloads are decrypted in memory by the current crypto API, so they are bounded by `MAX_FILE_BODY` rather than streamed to disk. The decrypted file is written through a temporary file in the destination directory (mode `0600` on Unix) and atomically renamed on success; on error the temporary file is removed.

### Proxy and traffic masking

`Proxy URL` in `/set` accepts an HTTP or SOCKS proxy. Empty input, `-` or `none` disables the proxy. A `socks5://` URL is automatically rewritten to `socks5h://`, so DNS resolution happens on the proxy side and the server hostname is not leaked to the local resolver.

Typical Tor usage:

```text
socks5h://127.0.0.1:9050
```

An I2P HTTP/SOCKS proxy can be configured the same way. The URL is validated before saving, and new proxy settings are applied to the running sender and listener immediately — no restart is needed.

All text and file requests also send browser-like `User-Agent`/`X-Requested-With` headers and the configurable `Guard Header Name` / `Guard Header Value` pair.

---

## Notifications

System notifications are optional and have four levels:

| Level | Behavior |
| --- | --- |
| `0` | Disabled |
| `1` | Stealth: uses the configured title/body template and hides the messenger name |
| `2` | Default: shows only “New message from …” |
| `3` | Full preview: sender as the title and the message text (up to 120 characters) |

Stealth mode replaces `{sec}` and `{count}` in the title and body. The default is:

```text
Title:  Перерыв для глаз
Body:   Время отдыха. Сделайте разминку для глаз на {sec} секунд
Seconds: 10
```

In stealth mode the notification application name is also taken from `Stealth Title`; if it is empty, the neutral `System Health` is used. File messages are previewed as `Файл: <name>` instead of the full body.

`/set test` sends a test notification with the current settings. On Linux notifications need a running D-Bus notification daemon; on headless/SSH sessions they can fail, and incoming-message notifications ignore that error.

---

## TUI and commands

Type a normal line to send it to the active room. Lines starting with `/` are commands.

### Navigation and chats

| Command | Description |
| --- | --- |
| `/help`, `/h`, `/?` | Open the scrollable help window (same as `F1`) |
| `/contacts`, `/cnt`, `/ls`, `/c` | Contact manager: `↑`/`↓` or `j`/`k` select, `Enter` opens the chat, `/` filters, `r` renames, `i` shows info, `c` copies the fingerprint, `d` deletes, `q`/`Esc` closes |
| `/join`, `/jn <link>` | Verify a signed `lastchance://contact?...` link and open the import confirmation dialog |
| `/join -f <path>` | Verify a signed invite from a file and open the import confirmation dialog |
| `/room`, `/r [hash \| nick]` | Show or switch the active room |
| `/sidebar`, `/sb` | Hide or show the chat sidebar |

### Messages and files

| Command | Description |
| --- | --- |
| `/messages [limit]` | Show recent messages of the active room (default 50) |
| `/ttl [duration\|off]` | One-way TTL for new messages in the active room; without an argument — show the status |
| `/ttl-syn [duration\|off]` | Two-way TTL: the peer receives the same timer in an encrypted `SetTtl` control packet |
| `/ratchet-reset` | Reset the Double Ratchet session with the active contact and notify the peer |
| `/sendfile`, `/sf [--force] <path>` | Encrypt and upload a file |
| `/download`, `/dl [id \| name \| hash] [path]` | Download a file from the active room |
| `/set`, `/settings` | Open the interactive settings window |
| `/set notify <0\|1\|2\|3>` | Set the notification level directly |
| `/set test` | Show a test notification |
| `/passwd` | Change the master password and re-encrypt local data |

TTL durations accept `off`, a number with an `s`, `m` or `h` suffix (`30s`, `5m`, `2h`), or plain seconds; zero is rejected. TTL rooms keep the ratchet state in RAM only, and the timer is wiped when TTL is disabled or the client exits. `/ttl-syn` starts a new ratchet session after any change, and `/ttl off` also resets it with the peer.

### Profile

| Command | Description |
| --- | --- |
| `/profile`, `/p` | Show nickname, hash and public keys as JSON |
| `/recovery` | Show the current BIP-39 phrase after confirming the master password; `Tab`/`r` then starts an overwrite: confirm, enter a new 12/15/18/21/24-word phrase and restart the client |
| `/lang [en\|ru]` | Switch the interface language; without an argument — toggle it |
| `/invite`, `/in [-f [dir \| file]]` | Copy the invite link; with `-f`, also save it to `<nickname>_lastchance.invite` |
| `/export` | Print your contact as JSON |
| `/nick <name>` | Change your nickname |
| `/rename <hash> <name>` | Rename a contact |
| `/quit`, `/q`, `/exit` | Exit |

### Keyboard

| Keys | Action |
| --- | --- |
| `F1` | Open/close the help window |
| `Esc`, `q`, `Enter` | Close the help window |
| `Up`/`Down`, `j`/`k` | Scroll help by one line |
| `PgUp`/`PgDn` | Scroll help by a page |
| `Ctrl+S` | Open settings |
| `Ctrl+V` | Paste from the system clipboard |
| `Ctrl+C` | Copy the input to the clipboard and clear it; on an empty line, exit |
| `Alt+Up`/`Alt+Down`, `Ctrl+P`/`Ctrl+N` | Switch chats |
| `Tab` | Complete commands, contacts, file names or paths |
| `Up`/`Down` | Input history (last 50 lines) |
| `PgUp`/`PgDn`, mouse wheel | Scroll chat history |
| `Ctrl+W`, `Ctrl+Backspace`, `Alt+Backspace` | Delete the word to the left |
| `Ctrl+Delete`, `Alt+D` | Delete the word to the right |
| `Ctrl+U` / `Ctrl+K` | Delete to the start / end of the line |
| `Ctrl+Left`, `Alt+B` / `Ctrl+Right`, `Alt+F` | Move by words |
| `Home`, `Ctrl+A` / `End`, `Ctrl+E` | Start / end of the line |

Word navigation and deletion are Unicode-aware. Pasted text is normalized to a single line: newlines and tabs become spaces, control characters are dropped. Passwords and the masked `Guard Header Value` field are never copied to the clipboard.

### `/set`

The settings window has these fields:

| Field | Meaning |
| --- | --- |
| `Text API` | Base URL of the text server |
| `File API` | Base URL of the file server |
| `Guard Header Name` | Custom masking header name |
| `Guard Header Value` | Custom masking header value (masked on screen) |
| `Proxy URL` | HTTP/SOCKS proxy; `-` or `none` disables it |
| `Notify Level` | `0`–`3` |
| `Stealth Title` | Notification title in stealth mode |
| `Stealth Body` | Notification body in stealth mode |
| `Stealth Seconds` | Value substituted for `{sec}` |
| `Language` | Interface language: `English` or `Русский` |

Controls: `Up`/`Down` or `Tab`/`Shift+Tab` select a field, `Enter` edits it, `Esc` cancels editing. In the editing prompt, `Enter` applies and `Esc` cancels. On the `Notify Level` and `Language` rows, `Left`/`Right` or `Space` cycles the value. `Esc` outside editing saves and closes the window.

On first launch, when the config has no `lang` field yet, a welcome modal asks to choose the interface language (`←`/`→` or `1`/`2`, `Enter` confirms).

The defaults point at `https://msg.example.com` and `https://files.example.com`; set your real server URLs before chatting.

### File paths

- `/sendfile` resolves relative paths from the current working directory and also supports `~/` and absolute paths.
- On Unix, `/etc`, `/proc`, `/sys`, `/dev`, `/boot` and `/run` are blocked unless `--force` is given. Windows system directories are blocked similarly.
- `/download` without arguments picks the newest file of the active room and saves it to `./downloads/<name>`. An id from the feed (`#3`), a file name or a hash can be used instead; the second argument may be a directory or a full file path.
- File names are sanitized so a download cannot escape the chosen directory. Downloaded files get mode `0600` on Unix.

---

## Build and run

Requirements: a stable Rust toolchain (edition 2021). SQLite is compiled in through `rusqlite` with the `bundled` feature.

```bash
git clone <this-repository>
cd LastChance_Rust
cargo build --release
./target/release/lastchance
```

During development:

```bash
cargo check --message-format=short
cargo test
```

The binary is `target/release/lastchance` (`lastchance.exe` on Windows).

Optional arguments:

```bash
lastchance --profile-dir /path/to/profile
lastchance --profile-dir=/path/to/profile
LASTCHANCE_DIR=/path/to/profile lastchance
```

Headless sending (no TUI, no raw mode):

```bash
LASTCHANCE_PASS=secret lastchance --to alice --send "hello"
echo "secret text" | LASTCHANCE_PASS=secret lastchance --to alice --send -
LASTCHANCE_PASS=secret lastchance --to alice --file ./report.pdf
```

`--to` accepts a contact name from the local database, an identity hash or a full `lastchance://contact?...` link. `--send -` reads the message from stdin so the text does not appear in `ps aux`. The master password is taken from `LASTCHANCE_PASS`; without it, an interactive TTY is prompted with hidden input. Headless mode exits with code `0` on success and `1` on error.

A `lastchance://contact?...` link passed as a command-line argument is imported as a contact.

On Linux, desktop notifications require a notification daemon reachable over D-Bus, and clipboard integration requires a working X11/Wayland clipboard. Everything else works in a plain terminal.

---

## Prebuilt releases

GitHub Actions builds release binaries when a tag matching `v*` is pushed. The workflow produces:

| Asset | Platform |
| --- | --- |
| `lastchance-linux-x86_64` | Linux x86_64 |
| `lastchance-windows-x86_64.exe` | Windows x86_64 |
| `lastchance-macos-arm64` | macOS Apple Silicon |

Download the asset from the repository's GitHub Releases page, make it executable on Linux/macOS, and run it:

```bash
chmod +x lastchance-linux-x86_64
./lastchance-linux-x86_64
```

On first launch you will be asked to create a master password. On later launches the same password unlocks the local vault; after three wrong attempts the client exits.

---

## Security notes and limitations

- The shared secret is static per contact and seeds every ratchet session. Each session adds fresh `session_id`/`bootstrap_nonce` entropy and ephemeral DH epochs, so session keys are not reused and captured packets cannot be replayed into a new session. Bootstrap keys are nevertheless derived from the long-term shared secret: an attacker who records a session's first packet and later obtains that secret can recompute its bootstrap root. There is no post-compromise security, and true first-message forward secrecy would require an interactive prekey/response handshake. For normal rooms destroyed session ids are persisted in `vault.dat`, so replay of a reset session stays blocked across restarts. For RAM-TTL rooms the list of destroyed session ids lives only in RAM (for the lifetime of the process), so after a client restart a replayed first packet is indistinguishable from first contact (the same TOFU boundary as the very first session). The per-session `dh_pub` registry is bounded to 128 keys: beyond that horizon an ancient key would again look new, but its local DH private key has already left the 5-epoch send window, so the packet still cannot be decrypted. Finally, the v2 header has no epoch counter: a genuine first-seen `dh_pub` from an older epoch is accepted as a new epoch and may move `remote_pub` back to that authentic key. This is a limited denial-of-progress inside the 5-epoch window, not forgery; a v3 epoch counter would close it.
- The server still learns the recipient identity hash, traffic timing, packet size class and the file blob size. Use Tor/I2P and your own servers if that metadata matters to you.
- Local metadata such as contact hashes, public keys and timestamps is not encrypted; message bodies, nicknames and file names are.
- The seed phrase is the identity. Anyone who obtains it can impersonate you and read your chats. The master password protects local data only; there is no password recovery.
- The code has not been audited. The protocol and the storage format may change.
- When HTTPS URLs are used, TLS is provided by `reqwest` defaults; no certificate pinning is implemented.

Security reports, fuzzing, protocol review and UI improvements are welcome.

---

# Русская версия

Я не стал расписывать всё подробно, поэтому это очень черновая версия. Буду рад помощи с тестированием безопасности и улучшением интерфейса. Запускайте на свой страх и риск.

LastChance — мессенджер на Rust с фокусом на приватность. GUI нет: клиент — лёгкий терминальный интерфейс (TUI) на `ratatui` и `crossterm`. Сетевое ядро и криптография отделены от интерфейса, поэтому тот же движок можно позже подключить к другому фронтенду.

Это ранняя версия. Код не проходил аудит, протокол ещё не финальный, и полагаться на него для критически важной секретности пока не стоит.

## Что умеет

- Сквозное (E2E) шифрование личных текстовых чатов через ваш собственный HTTP-сервер.
- Отдельный файловый контур: файл шифруется локально, загружается на файловый сервер, а в чат уходит только хеш.
- Текстовые пакеты фиксированного размера с паддингом.
- Идентичность на основе BIP-39 seed-фразы, X25519 для обмена ключами и Ed25519 для аутентификации.
- Зашифрованное локальное хранилище с мастер-паролем (Argon2id + XChaCha20-Poly1305).
- HTTP Long-Polling для входящих сообщений.
- Необязательный прокси SOCKS5/HTTP, включая `socks5h://` с удалённым DNS (Tor/I2P).
- Stealth-уведомления, скрывающие название мессенджера.
- Эфемерные сообщения: TTL-таймер для комнаты (локальный или синхронизированный с собеседником) держит состояние храповика только в RAM.
- Интерфейс на английском и русском с выбором языка при первом запуске.
- TUI с окном справки, мастером настроек, автодополнением, историей ввода, прокруткой мышью и выбором файлов.

Сервер в комплект не входит. Нужно поднять совместимые текстовый и файловый API-серверы и указать их адреса через `/set`.

## Архитектура

| Путь | Ответственность |
| --- | --- |
| `src/crypto/` | X25519 ECDH, HKDF, XChaCha20-Poly1305, Ed25519, хеш идентичности, формат кадра |
| `src/identity/` | Генерация seed, вывод ключей, зашифрованный `identity.json` |
| `src/network/config.rs` | Зашифрованный `global.conf`, настройки прокси и уведомлений |
| `src/network/sender.rs` | `POST /push/<hash>`, загрузка файлов |
| `src/network/listener.rs` | Long-poll `GET /pull/<hash>`, разбор multipart, скачивание файлов |
| `src/storage/` | Безопасная работа с ФС и зашифрованное локальное хранилище |
| `src/vault.rs` | Вывод мастер-ключа и локальное шифрование |
| `src/app.rs` | Ядро приложения, события, контакты, отправка и приём |
| `src/main.rs` | Терминальный интерфейс, команды, модальные окна, запуск |

Поток сообщения:

```text
клавиатура ──> TUI (main.rs)
                  │
                  ▼
               App (app.rs) ──> Sender ──> текстовый API-сервер
                  │
                  ├──> Storage (SQLite в памяти, `vault.dat`)
                  ├──> Vault (мастер-ключ, Argon2id)
                  └──> Listener <── long-poll <── текстовый API-сервер

файлы: App ──> шифрование ключом комнаты ──> файловый API-сервер
       App <── скачивание по хешу ── расшифровка ключом комнаты
```

`src/lib.rs` экспортирует `App`, `Config`, `Vault` и помощники хранилища. `src/main.rs` — только терминальный клиент; ядро не зависит от TUI.

## Криптография и пакеты

### Идентичность

- 32 случайных байта кодируются в BIP-39 мнемонику. `/recovery` запрашивает текущий мастер-пароль, показывает текущую фразу и позволяет перезаписать идентичность фразой из 12/15/18/21/24 слов; после восстановления перезапустите клиент.
- Из seed через HKDF-SHA256 выводятся две пары ключей:
  - X25519 (`X25519_E2EE_Key_v1`) — для шифрования сообщений и файлов;
  - Ed25519 (`Ed25519_Auth_Key_v1`) — для аутентификации.
- Публичный хеш идентичности — `SHA256(Ed25519 public key)` в hex.
- Инвайт-ссылка содержит подписанный канонический CBOR-документ идентичности (`doc`) и его Ed25519-подпись (`sig`):

```text
lastchance://contact?hash=...&doc=<cbor-hex>&sig=<signature-hex>&x25519=...&ed25519=...&nickname=...
```

- `doc` кодирует `version`, `ed25519_pub`, `x25519_pub`, необязательный `nickname` и `created_at` в детерминированном CBOR по RFC 8949 (отсортированные ключи, минимальные целые). `sig` — Ed25519-подпись ровно над байтами `doc`. Параметры `hash`, `x25519`, `ed25519` и `nickname` — неподписанные копии и обязаны совпадать с подписанным документом.
- Импорт отклоняет старые/неподписанные ссылки, дублирующиеся параметры, неверную подпись и любое несоответствие `Ed25519 ↔ X25519 ↔ hash`. Отпечаток инвайта — `SHA256("lastchance:identity-fingerprint:v1" || ed25519_pub || x25519_pub)`; сверяйте его по независимому каналу до того, как доверять контакту.
- Для каждого контакта хранятся отпечаток и состояние TOFU (`pending`, `verified` или `changed`). Если X25519-ключ меняется при той же подписанной Ed25519-идентичности, контакт помечается как `changed` и требует повторной проверки.
- В менеджере контактов (`/contacts`, `/cnt`, `/ls`, `/c`) клавиши `↑`/`↓` или `j`/`k` выбирают контакт, `Enter` открывает чат, `/` включает фильтр, `r` переименовывает, `i` показывает отпечаток и состояние TOFU, `c` копирует отпечаток, `d` удаляет, `q`/`Esc` закрывает. В окне информации `v` отмечает отпечаток проверенным после сверки вне канала, а `Esc` или `i` возвращают к списку.

- Запросы `/pull` подписываются Ed25519 над строкой `timestamp + identity_hash`. Сервер получает публичный ключ в `X-Identity-Key`, время в `X-Timestamp`, подпись в `X-Signature`.

### Шифрование сообщений

- Для каждого контакта вычисляется статический общий секрет: `X25519(мой_private, его_public)`, затем HKDF-SHA256 с меткой `ECDH_v1`. Он инициализирует сессию Double Ratchet.
- ECDH отклоняет некорректные точки: полностью нулевой выход X25519 (точка малого порядка) прерывает согласование ключа вместо выдачи общего секрета.
- Сообщения используют Double Ratchet поверх эфемерных X25519 DH-шагов, HKDF-SHA256 (`RootKey`, `ChainKey`, `MessageKey`) и XChaCha20-Poly1305 со свежим 24-байтным nonce.
- Открытый заголовок храповика v2: `version (1) || session_id (16) || bootstrap_nonce (32) || dh_pub (32) || n (u32) || pn (u32)`; заголовок целиком аутентифицируется как AEAD AAD. Внутри шифротекста: `payload_len (u32) || payload || случайный паддинг`.
- Каждое состояние храповика получает свежие `session_id` и `bootstrap_nonce` из CSPRNG. Bootstrap-ключи выводятся как `HKDF(salt = bootstrap_nonce, ikm = shared_secret, info = метка роли)`; собеседник строит тот же контекст из nonce в пакете. После смены TTL или `/ratchet-reset` следующая сессия использует новую энтропию, поэтому перехваченный bootstrap-пакет старой сессии не может быть принят новой.
- Уничтоженные и вытесненные `session_id` запоминаются и отклоняются как `StaleSession`, даже если AEAD-тег валиден. Для обычных комнат tombstone-и пишутся в `vault.dat` и переживают перезапуск клиента; для RAM-TTL комнат они намеренно живут только в RAM (H-3) и теряются при перезапуске. Реестр хранит до 128 id: `session_id` меняется только при reset, TTL-переходе или вытеснении сессии, а не на каждой DH-эпохе, поэтому 128 записей покрывают 32 полных окна из 4 одновременных сессий. Пакеты v1 отклоняются без режима совместимости: downgrade невозможен.
- Принятые `dh_pub` собеседника запоминаются на сессию (последние 128). Пакет, чей `dh_pub` уже принимался, но чья эпоха вышла из окна в 5 эпох, отклоняется как `ReplayedDhPub` ещё до криптографии; реестр пополняется только после успешной аутентификации, а новая сессия начинает с пустого реестра. `remote_pub` не откатывается, когда принимается пакет эпохи, уже присутствующей в окне приёма. В заголовке v2 нет счётчика эпох, поэтому подлинный, но впервые увиденный старый `dh_pub` неотличим от новой эпохи и принимается как новая; он может сдвинуть `remote_pub` на этот подлинный старый ключ. Подделка невозможна (AEAD), эффект ограничен окном в 5 эпох, а полное решение требует счётчика эпох в wire-format v3. Самая новая эпоха не вытесняется никогда; если окно заполнено и защищены все эпохи, приём завершается `EpochOverflow`, не меняя состояние.
- Клиент держит скользящее окно из 5 последних эпох (и до 32 пропущенных ключей на эпоху), поэтому одновременные и пришедшие не по порядку сообщения расшифровываются. Старые эпохи и использованные ключи сообщений затираются через `Zeroizing`.
- Итоговый размер пакета по-прежнему один из:

```text
256 Б   1024 Б   4096 Б   65536 Б
```

- Итоговый пакет — `header || nonce || ciphertext || tag`; принимаются только эти четыре точных размера. Старые кадры со статическим секретом всё ещё принимаются для совместимости.
- `/ratchet-reset` принудительно создаёт новую сессию с активным контактом и уведомляет собеседника. Reset генерирует новые `session_id`, `bootstrap_nonce` и bootstrap-ключи.

Так скрывается точная длина сообщения внутри класса размера, но не сам класс.

### Шифрование файлов

Файлы используют тот же общий секрет, но отдельный контур:

- файл целиком шифруется XChaCha20-Poly1305 (`nonce || ciphertext || tag`, без фиксированного паддинга);
- зашифрованный блок до 100 МБ загружается на файловый сервер;
- сервер возвращает хеш файла;
- в чат уходит обычное зашифрованное сообщение с именем, размером и хешем;
- получатель скачивает блок по хешу и расшифровывает локально.

Текстовый и файловый серверы — разные URL, настраиваются независимо.

### Что видят серверы

Текстовый сервер видит хеш получателя в URL, класс размера пакета, тайминг и маскирующие заголовки. Файловый сервер видит размер зашифрованного блока и его хеш. Содержимое сообщений и файлов остаётся зашифрованным сквозным образом.

## Локальное хранилище

При первом запуске клиент просит мастер-пароль (минимум 8 символов). Пароль нигде не сохраняется.

- Случайная 32-байтная соль пишется в `vault.salt`.
- Мастер-ключ выводится через Argon2id (19 МиБ, 2 прохода, 1 поток) и хранится в памяти внутри `Zeroizing`.
- `vault.check` — зашифрованный маркер для проверки пароля.
- `identity.json` и `global.conf` целиком шифруются как `LCVAULT1 || nonce || ciphertext || tag` с XChaCha20-Poly1305 и associated data.
- Контакты, комнаты, сообщения, файловые записи и обычные сессии Double Ratchet живут в SQLite исключительно в оперативной памяти; на диск никогда не пишутся `user.db`, `user.db-wal` или `user.db-shm`.
- При каждом изменении вся база сериализуется, дополняется случайным паддингом до размера, кратного 4096, и шифруется XChaCha20-Poly1305 в `vault.dat` как `nonce || ciphertext || tag`; магические байты и открытые заголовки на диск не попадают. Версия схемы и длина полезной нагрузки хранятся внутри зашифрованного блока.
- Комнаты с активным `/ttl` или `/ttl-syn` держат состояние храповика строго в RAM: оно не попадает в `vault.dat` и затирается при отключении TTL или выходе из клиента.
- `vault.dat` заменяется атомарно через временный файл и получает права `0600` на Unix.
- Старая открытая `user.db` импортируется при первом открытии, после чего `user.db`, `user.db-wal` и `user.db-shm` перезаписываются нулями и удаляются.
- Созданные клиентом файлы получают права `0600` на Unix; там, где POSIX-права недоступны, используется read-only заглушка.

`/passwd` проверяет старый пароль, перешифровывает `identity.json`, `global.conf`, контейнер базы `vault.dat`, заменяет ключ в памяти и только затем пишет новую соль и check-файл. При сбое клиент пытается откатиться на старый ключ.

Все метаданные локальной базы (хеши контактов, публичные ключи, хеши комнат, направление/статус сообщений и время) находятся внутри зашифрованного контейнера и на диске в открытом виде не хранятся.

Порядок выбора каталога данных:

1. `--profile-dir <path>` или `--profile-dir=<path>` (`--data-dir` — устаревший синоним).
2. Переменная окружения `LASTCHANCE_DIR`.
3. Переносимый режим: если рядом с бинарником есть файл `.portable`, используется `data/` рядом с ним.
4. По умолчанию: `dirs::config_dir()/lastchance` — `~/.config/lastchance` на Linux (`$XDG_CONFIG_HOME/lastchance`, если задан), `~/Library/Application Support/lastchance` на macOS, `%APPDATA%\lastchance` на Windows.

При первом запуске, если новой директории ещё нет, а старая data-директория (`~/.local/share/lastchance` на Linux, `%LOCALAPPDATA%\lastchance` на Windows) не пуста, клиент автоматически копирует профиль. Каталоги получают права `0700`, файлы — `0600`; старая директория сохраняется без изменений.

В каталоге лежат `identity.json`, `global.conf`, `vault.dat`, `vault.salt` и `vault.check`.

## Транспорт

### Текстовый API

- Отправка: `POST /push/<target_hash>` с `application/octet-stream`.
- Приём: `GET /pull/<identity_hash>?wait=25`.
- Сервер держит пустой long-poll до 25 секунд; таймаут клиента — 45 секунд.
- `204 No Content` означает пустую очередь.
- Успешный ответ приходит как `multipart/form-data`; клиент разбирает части и проверяет, что размеры пакетов входят в допустимую сетку.
- `429` — rate limit. Повторы pull идут с задержками 1с → 2с → 5с → 15с; `401` и ошибки протокола повторяются медленно, чтобы не крутить busy-loop.
- Push делает до четырёх попыток с экспоненциальной задержкой при `429` и транспортных ошибках.

### Файловый API

- Загрузка: `POST /upload` с `application/octet-stream`, `X-File-Name` и `Content-Length`; тело ответа — хеш файла.
- Скачивание: `GET /download/<file_hash>`.
- У скачивания отдельный таймаут 300 секунд; загрузка ограничена 100 МБ.

### Лимиты и валидация ввода

Недоверенные идентификаторы (identity/contact hash из invite, file hash от сервера или из сообщения) разбираются на границе в `IdentityHash`/`FileHash`/`RoomId`. Принимаются ровно 64 ASCII hex-символа; не-ASCII, короткая/длинная строка или не-hex отклоняются типизированной ошибкой до любых байтовых срезов, записи в БД и построения URL. Для UI/логов используются `truncate_display()` / `short_hash()`: они работают по символам и не рвут UTF-8.

Тела ответов читаются потоково с жёсткими лимитами. Границы включительные: ровно `MAX_*` байт допустимо, `MAX_* + 1` — ошибка.

| Лимит | Значение | Область |
| --- | --- | --- |
| `MAX_MESSAGE_BODY` | 8 МиБ | multipart-тело `/pull` |
| `MAX_FILE_BODY` | 256 МиБ | тело `/download` |
| `MAX_MULTIPART_PARTS` | 16 | частей на ответ |
| `MAX_MULTIPART_HEADERS` | 32 | заголовков на часть |
| `MAX_MULTIPART_HEADER_BYTES` | 8 КиБ | заголовки одной части |
| `MAX_MULTIPART_BOUNDARY` | 200 байт | значение `boundary=` |
| `MAX_ERROR_BODY` | 64 КиБ | тело `401`/`4xx`/`5xx` |
| `BODY_READ_TIMEOUT` | 60 с | всё тело, а не отдельный chunk |

`Content-Length` не считается доверенным: заявленный размер больше лимита отклоняется до чтения тела, рост тела сверх заявленного размера прерывается, а недобор считается ошибкой целостности (fail-closed). Chunked-ответы считаются по мере чтения и не буферизуются сверх лимита. Скачиваемый файл расшифровывается текущим crypto API целиком в памяти, поэтому ограничен `MAX_FILE_BODY`, а не потоковой записью на диск. Расшифрованный файл пишется через временный файл в каталоге назначения (права `0600` на Unix) и атомарно переименовывается только при успехе; при ошибке временный файл удаляется.

### Прокси и маскировка

Поле `Proxy URL` в `/set` принимает HTTP- или SOCKS-прокси. Пустое значение, `-` или `none` отключают прокси. URL `socks5://` автоматически заменяется на `socks5h://`, поэтому DNS резолвится на стороне прокси и имя сервера не утекает локальному резолверу.

Типичный вариант для Tor:

```text
socks5h://127.0.0.1:9050
```

HTTP/SOCKS-прокси I2P настраивается так же. URL проверяется до сохранения, а новые настройки сразу применяются к работающим sender и listener — перезапуск не нужен.

Все текстовые и файловые запросы также отправляют браузерные `User-Agent`/`X-Requested-With` и настраиваемую пару `Guard Header Name` / `Guard Header Value`.

## Уведомления

Системные уведомления необязательны и имеют четыре режима:

| Уровень | Поведение |
| --- | --- |
| `0` | Выключены |
| `1` | Stealth: использует шаблон заголовка/тела и скрывает название мессенджера |
| `2` | По умолчанию: только «Новое сообщение от …» |
| `3` | Полный предпросмотр: отправитель в заголовке и текст до 120 символов |

В stealth-режиме в заголовке и теле подставляются `{sec}` и `{count}`. По умолчанию:

```text
Title:  Перерыв для глаз
Body:   Время отдыха. Сделайте разминку для глаз на {sec} секунд
Seconds: 10
```

В stealth-режиме имя приложения в уведомлении тоже берётся из `Stealth Title`; если оно пустое, используется нейтральное `System Health`. Для файловых сообщений предпросмотр выглядит как `Файл: <имя>`.

`/set test` отправляет тестовое уведомление с текущими настройками. На Linux нужен работающий демон уведомлений с D-Bus; в SSH/headless-сессиях уведомления могут не работать, и для входящих сообщений эта ошибка игнорируется.

## TUI и команды

Обычная строка отправляется в активную комнату. Строки, начинающиеся с `/`, — команды.

### Навигация и чаты

| Команда | Описание |
| --- | --- |
| `/help`, `/h`, `/?` | Открыть прокручиваемую справку (как `F1`) |
| `/contacts`, `/cnt`, `/ls`, `/c` | Менеджер контактов: `↑`/`↓` или `j`/`k` — выбор, `Enter` — открыть чат, `/` — фильтр, `r` — переименовать, `i` — информация, `c` — копировать отпечаток, `d` — удалить, `q`/`Esc` — закрыть |
| `/join`, `/jn <link>` | Проверить подписанную ссылку `lastchance://contact?...` и открыть диалог подтверждения импорта |
| `/join -f <path>` | Проверить подписанный инвайт из файла и открыть диалог подтверждения импорта |
| `/room`, `/r [hash \| nick]` | Показать или сменить активную комнату |
| `/sidebar`, `/sb` | Скрыть или показать панель чатов |

### Сообщения и файлы

| Команда | Описание |
| --- | --- |
| `/messages [limit]` | Последние сообщения активной комнаты (по умолчанию 50) |
| `/ttl [duration\|off]` | Односторонний TTL для новых сообщений в активной комнате; без аргумента — показать состояние |
| `/ttl-syn [duration\|off]` | Двусторонний TTL: собеседник получает тот же таймер в зашифрованном управляющем пакете `SetTtl` |
| `/ratchet-reset` | Сбросить сессию Double Ratchet с активным контактом и уведомить собеседника |
| `/sendfile`, `/sf [--force] <path>` | Зашифровать и загрузить файл |
| `/download`, `/dl [id \| name \| hash] [path]` | Скачать файл активной комнаты |
| `/set`, `/settings` | Открыть интерактивные настройки |
| `/set notify <0\|1\|2\|3>` | Задать режим уведомлений напрямую |
| `/set test` | Показать тестовое уведомление |
| `/passwd` | Сменить мастер-пароль и перешифровать локальные данные |

Длительность TTL принимает `off`, число с суффиксом `s`, `m` или `h` (`30s`, `5m`, `2h`) либо секунды без суффикса; ноль отклоняется. TTL-комнаты держат состояние храповика только в RAM, а таймер затирается при отключении TTL или выходе из клиента. `/ttl-syn` запускает новую сессию храповика после любого изменения, а `/ttl off` дополнительно сбрасывает её с собеседником.

### Профиль

| Команда | Описание |
| --- | --- |
| `/profile`, `/p` | Ник, хеш и публичные ключи в JSON |
| `/recovery` | Показать текущую BIP-39 фразу после подтверждения мастер-пароля; `Tab`/`r` затем запускает перезапись: подтверждение, ввод новой фразы из 12/15/18/21/24 слов и перезапуск клиента |
| `/lang [en\|ru]` | Переключить язык интерфейса; без аргумента — сменить текущий |
| `/invite`, `/in [-f [dir \| file]]` | Скопировать инвайт-ссылку; с `-f` сохранить в `<ник>_lastchance.invite` |
| `/export` | Вывести свой контакт в JSON |
| `/nick <name>` | Сменить свой ник |
| `/rename <hash> <name>` | Переименовать контакт |
| `/quit`, `/q`, `/exit` | Выход |

### Клавиши

| Клавиши | Действие |
| --- | --- |
| `F1` | Открыть/закрыть справку |
| `Esc`, `q`, `Enter` | Закрыть справку |
| `Up`/`Down`, `j`/`k` | Прокрутка справки построчно |
| `PgUp`/`PgDn` | Прокрутка справки страницами |
| `Ctrl+S` | Открыть настройки |
| `Ctrl+V` | Вставить из системного буфера |
| `Ctrl+C` | Скопировать ввод в буфер и очистить строку; на пустой строке — выход |
| `Alt+Up`/`Alt+Down`, `Ctrl+P`/`Ctrl+N` | Переключение чатов |
| `Tab` | Автодополнение команд, контактов, файлов и путей |
| `Up`/`Down` | История ввода (последние 50 строк) |
| `PgUp`/`PgDn`, колесо мыши | Прокрутка истории чата |
| `Ctrl+W`, `Ctrl+Backspace`, `Alt+Backspace` | Удалить слово слева |
| `Ctrl+Delete`, `Alt+D` | Удалить слово справа |
| `Ctrl+U` / `Ctrl+K` | Удалить до начала / до конца строки |
| `Ctrl+Left`, `Alt+B` / `Ctrl+Right`, `Alt+F` | Перемещение по словам |
| `Home`, `Ctrl+A` / `End`, `Ctrl+E` | В начало / в конец строки |

Навигация и удаление по словам учитывают Unicode. Вставляемый текст приводится к одной строке: переводы строк и табуляции заменяются пробелами, управляющие символы отбрасываются. Пароли и замаскированное поле `Guard Header Value` никогда не копируются в буфер.

### `/set`

В окне настроек десять полей:

| Поле | Значение |
| --- | --- |
| `Text API` | Базовый URL текстового сервера |
| `File API` | Базовый URL файлового сервера |
| `Guard Header Name` | Имя маскирующего заголовка |
| `Guard Header Value` | Значение маскирующего заголовка (скрыто на экране) |
| `Proxy URL` | HTTP/SOCKS-прокси; `-` или `none` отключают |
| `Notify Level` | `0`–`3` |
| `Stealth Title` | Заголовок уведомления в stealth-режиме |
| `Stealth Body` | Тело уведомления в stealth-режиме |
| `Stealth Seconds` | Значение для `{sec}` |
| `Language` | Язык интерфейса: `English` или `Русский` |

Управление: `Up`/`Down` или `Tab`/`Shift+Tab` — выбор поля, `Enter` — редактировать, `Esc` — отменить редактирование. В режиме ввода `Enter` применяет значение, `Esc` отменяет. На строках `Notify Level` и `Language` клавиши `Left`/`Right` или `Space` переключают значение. `Esc` вне редактирования сохраняет и закрывает окно.

При первом запуске, если в конфиге ещё нет поля `lang`, приветственное окно предлагает выбрать язык интерфейса (`←`/`→` или `1`/`2`, `Enter` подтверждает).

По умолчанию указаны `https://msg.example.com` и `https://files.example.com`; перед началом переписки задайте реальные адреса серверов.

### Пути к файлам

- `/sendfile` разрешает относительные пути от текущей рабочей директории, поддерживает `~/` и абсолютные пути.
- На Unix каталоги `/etc`, `/proc`, `/sys`, `/dev`, `/boot` и `/run` блокируются без `--force`. Системные каталоги Windows блокируются аналогично.
- `/download` без аргументов берёт самый новый файл активной комнаты и сохраняет его в `./downloads/<имя>`. Можно указать номер из ленты (`#3`), имя или хеш; второй аргумент — каталог или полный путь к файлу.
- Имена файлов очищаются, чтобы скачивание не вышло за пределы выбранного каталога. На Unix скачанные файлы получают права `0600`.

## Сборка и запуск

Нужен стабильный тулчейн Rust (edition 2021). SQLite собирается внутри через `rusqlite` с фичей `bundled`.

```bash
git clone <этот-репозиторий>
cd LastChance_Rust
cargo build --release
./target/release/lastchance
```

Во время разработки:

```bash
cargo check --message-format=short
cargo test
```

Бинарник — `target/release/lastchance` (`lastchance.exe` на Windows).

Необязательные аргументы:

```bash
lastchance --profile-dir /path/to/profile
lastchance --profile-dir=/path/to/profile
LASTCHANCE_DIR=/path/to/profile lastchance
```

Headless-отправка (без TUI и raw-mode):

```bash
LASTCHANCE_PASS=secret lastchance --to alice --send "привет"
echo "секретный текст" | LASTCHANCE_PASS=secret lastchance --to alice --send -
LASTCHANCE_PASS=secret lastchance --to alice --file ./report.pdf
```

`--to` принимает имя контакта из локальной базы, identity_hash или полную ссылку `lastchance://contact?...`. `--send -` читает сообщение из stdin, чтобы текст не светился в `ps aux`. Мастер-пароль берётся из `LASTCHANCE_PASS`; без него в интерактивном TTY запрашивается скрытый ввод. Headless-режим завершается с кодом `0` при успехе и `1` при ошибке.

Ссылка `lastchance://contact?...`, переданная аргументом командной строки, импортируется как контакт.

На Linux для уведомлений нужен демон уведомлений с D-Bus, для буфера обмена — рабочее окружение X11/Wayland. Всё остальное работает в обычном терминале.

## Готовые релизы

GitHub Actions собирает релизные бинарники при пуше тега `v*`. Workflow создаёт:

| Файл | Платформа |
| --- | --- |
| `lastchance-linux-x86_64` | Linux x86_64 |
| `lastchance-windows-x86_64.exe` | Windows x86_64 |
| `lastchance-macos-arm64` | macOS Apple Silicon |

Скачайте файл со страницы GitHub Releases, на Linux/macOS сделайте его исполняемым и запустите:

```bash
chmod +x lastchance-linux-x86_64
./lastchance-linux-x86_64
```

При первом запуске будет предложено создать мастер-пароль. При следующих запусках тот же пароль разблокирует локальное хранилище; после трёх неверных попыток клиент завершится.

## Безопасность и ограничения

- Общий секрет статический для каждого контакта и инициализирует каждую сессию Double Ratchet. Свежие `session_id`/`bootstrap_nonce` и эфемерные DH-эпохи не дают переиспользовать ключи между сессиями и воспроизводить старые пакеты в новую сессию. Однако bootstrap-ключи по-прежнему выводятся из долговременного общего секрета: перехвативший первый пакет сессии и позже получивший этот секрет сможет восстановить её bootstrap-root. Post-compromise security отсутствует; настоящая forward secrecy на первом сообщении требует интерактивного prekey/ответного хендшейка. Для обычных комнат уничтоженные `session_id` пишутся в `vault.dat`, поэтому replay сброшенной сессии блокируется и после перезапуска. Для RAM-TTL комнат список уничтоженных `session_id` живёт только в RAM (в пределах жизни процесса), поэтому после перезапуска клиента повторно поданный первый пакет неотличим от первого контакта (та же граница TOFU, что и у самой первой сессии). Реестр `dh_pub` ограничен 128 ключами на сессию: за этим горизонтом древний ключ снова выглядит новым, но его локальный DH-приватный ключ уже покинул окно отправки в 5 эпох, поэтому расшифровать пакет всё равно не получится. Наконец, в заголовке v2 нет счётчика эпох: подлинный впервые увиденный `dh_pub` старой эпохи принимается как новая эпоха и может сдвинуть `remote_pub` на этот подлинный ключ. Это ограниченный отказ в продвижении внутри окна из 5 эпох, а не подделка; счётчик эпох в v3 закрыл бы и его.
- Сервер по-прежнему узнаёт хеш получателя, тайминг, класс размера пакета и размер файлового блока. Если это важно, используйте Tor/I2P и собственные серверы.
- Локальные метаданные (хеши контактов, публичные ключи, время) не шифруются; тела сообщений, ники и имена файлов — шифруются.
- Seed-фраза — это идентичность. Тот, кто её получил, может выдать себя за вас и читать ваши чаты. Мастер-пароль защищает только локальные данные; восстановления пароля нет.
- Код не проходил аудит. Протокол и формат хранилища могут меняться.
- Если используются HTTPS-адреса, TLS обеспечивается настройками `reqwest` по умолчанию; certificate pinning не реализован.

Сообщения об уязвимостях, фаззинг, ревью протокола и улучшения интерфейса приветствуются.
