# LastChance

**English** · [Русская версия](#русская-версия)

LastChance is a privacy-focused peer-to-peer messenger written in Rust. It has no GUI and no central servers: the client is a lightweight terminal UI (TUI) built with `ratatui` and `crossterm`, communicating directly peer-to-peer over Tor v3 hidden services (`.onion`). The network core and cryptography are kept separate from the interface, so the same engine can be reused by another frontend later.

This is still early software. The code is not audited, the protocol is not final, and you should not rely on it for life-critical secrecy yet. The current crate version is `1.0.0`; see [`CHANGELOG.md`](CHANGELOG.md) for earlier history.

---

## What it does

- **Direct P2P over Tor v3 (`.onion`)**: no central text or file servers. Each client publishes its own Tor v3 hidden service via Tor ControlPort (`ADD_ONION`) and connects to peers directly through Tor SOCKS5h.
- **End-to-end encryption**: Double Ratchet over X25519 ephemeral DH epochs, HKDF-SHA256, and XChaCha20-Poly1305 (wire format v3).
- **Traffic-analysis mitigations**: bucket-padded packets (`256`, `1024`, `4096`, `65536` bytes) with random per-packet jitter inside the bucket, encrypted ratchet headers, and session aliases.
- **Persistent encrypted Outbox**: messages to offline peers in normal rooms are queued encrypted in `vault.dat` and retried with exponential backoff (`5s → 15s → 30s → 60s → 180s → 600s`).
- **Signed identity invites**: BIP-39 seed phrase, X25519 (E2EE) + Ed25519 (auth/signing), and signed `lastchance://contact?...` invites (deterministic CBOR v2 binding the peer's `.onion` address) with TOFU fingerprint verification.
- **Encrypted local vault**: Argon2id + XChaCha20-Poly1305 protecting `vault.dat` (in-memory SQLite), `identity.json`, and `global.conf`.
- **Ephemeral RAM-only TTL rooms**: `/ttl` and `/ttl-syn` keep ratchet state and messages in RAM only (no `vault.dat` writes, no Outbox persistence), with bounded tombstone retention against bootstrap replay.
- **Stealth notifications**: configurable notification levels (`0`–`3`), including disguised system notifications.
- **Bilingual TUI & headless mode**: English and Russian interface, interactive modals (`/set`, `/contacts`, `/help`, `/recovery`), tab completion, input history, mouse scrolling, and `--to`/`--send` CLI mode.

Requires a running local Tor daemon with `SocksPort` and `ControlPort` enabled.

---

## Architecture

The crate is split into a reusable core library (`src/lib.rs`) with no TUI dependencies and a thin TUI binary (`src/main.rs`):

| Path | Responsibility |
| --- | --- |
| `src/crypto/` | X25519 ECDH (with low-order point validation), HKDF, XChaCha20-Poly1305, Double Ratchet, wire format v3, `LCE1` E2E payload, `SecretBytes`/`SecretString` |
| `src/identity/` | BIP-39 seed generation, key derivation, encrypted `identity.json`, signed v2 `IdentityDoc` & `IdentityInvite` (with `.onion`) |
| `src/network/config.rs` | Encrypted `global.conf` (Tor ControlPort, SOCKS5h, cookie path, P2P ports, notifications, language) + env overrides |
| `src/network/routing.rs` | In-memory `alias -> room` routing table, retired aliases, `(alias, nonce)` deduplication, rate-limited bootstrap scan |
| `src/p2p/tor_control.rs` | Tor ControlPort client (`PROTOCOLINFO`, `AUTHENTICATE` via SafeCookie/Cookie/Null, `ADD_ONION`) |
| `src/p2p/transport.rs` | Local `127.0.0.1` TCP inbound listener (`[u32 BE len][packet]` + `OK` ACK) and outbound SOCKS5h `.onion` sender (`P2pSender`) |
| `src/storage/` | `SafeFSOps` (`0700`/`0600`, atomic writes) and in-memory SQLite serialized into `vault.dat` |
| `src/vault.rs` | Argon2id master-key derivation and `LCVAULT1` local file encryption |
| `src/types/` | Validated `IdentityHash`, `OnionAddress`, `RoomId`, and UTF-8/bidi-safe display helpers |
| `src/app.rs` | Core `App` logic, `AppEvent`, Tor control loop, Outbox worker, Double Ratchet, contacts, TTL |
| `src/cli.rs` | Headless argument parsing (`--profile-dir`, `--to`, `--send`) without TUI dependencies |
| `src/i18n.rs` | English and Russian UI strings |
| `src/main.rs` | Terminal UI (`ratatui`/`crossterm`), commands, modals, and startup flow |

Data flow:

```text
Outbound:
  keyboard ──> TUI (main.rs)
                  │
                  ▼
               App (app.rs) ──> Double Ratchet v3 ──> Outbox (vault.dat)
                                                          │
                                                          ▼
                                                   P2pSender (SOCKS5h) ──> Tor ──> peer.onion:9878
  (RAM-TTL rooms & loopback self-chat bypass Outbox and send directly)

Inbound:
  Tor ──> .onion:9878 ──> 127.0.0.1:<local_port> (serve_inbound) ──> OK ACK
                                 │
                                 ▼
                          InboundRouter ──> App (Double Ratchet) ──> in-memory SQLite / vault.dat
```

---

## Cryptography and packets

### Identity

- A 32-byte random seed is encoded as a BIP-39 mnemonic. `/recovery` asks for the current master password, shows the current phrase, and can overwrite the identity with a 12/15/18/21/24-word phrase (restart the client after restoring).
- Two key pairs are derived from the seed with HKDF-SHA256:
  - X25519 (`X25519_E2EE_Key_v1`) for Double Ratchet key agreement;
  - Ed25519 (`Ed25519_Auth_Key_v1`) for signing identity documents.
- The public identity hash is `SHA256(Ed25519 public key)`, hex-encoded (64 characters).
- A contact invite (`v2`) contains the signed canonical CBOR identity document (`doc`) and its Ed25519 signature (`sig`):

```text
lastchance://contact?hash=...&doc=<cbor-hex>&sig=<signature-hex>&x25519=...&ed25519=...&onion=...&nickname=...
```

- `doc` encodes `version` (`2`), `ed25519_pub`, `x25519_pub`, `onion` (Tor v3 `.onion` address), optional `nickname`, and `created_at` using RFC 8949 deterministic CBOR (sorted keys, minimal integers). `sig` is Ed25519 over the exact `doc` bytes. Unsigned query copies must match `doc`.
- Imports reject legacy `v1` invites (missing signed `.onion`), duplicate parameters, invalid signatures, and any `Ed25519 ↔ X25519 ↔ hash ↔ onion` mismatch.
- The invite fingerprint is `SHA256("lastchance:identity-fingerprint:v1" || ed25519_pub || x25519_pub)`; compare it out-of-band before trusting a contact.
- Each contact stores its fingerprint, `.onion` address, and TOFU state (`pending`, `verified`, or `changed`). If the X25519 key changes under the same signed Ed25519 identity, the contact is marked `changed` and must be verified again.

### Message encryption

- Each contact has a static shared secret: `X25519(my_private, their_public)` followed by HKDF-SHA256 with `ECDH_v1`. It seeds the Double Ratchet session.
- Every ECDH path calls `validate_x25519_peer()`, which masks the ignored high bit (RFC 7748) and rejects all seven canonical low-order X25519 points (`0`, `1`, the two points of order 8, `p - 1`, `p`, and `p + 1`), plus requires `was_contributory()`.
- Messages use a Double Ratchet over X25519 ephemeral DH steps, HKDF-SHA256 (`RootKey`, `ChainKey`, `MessageKey`), and XChaCha20-Poly1305 with a fresh 24-byte nonce.
- Wire format v3 is `version (1) || flags (1) || session_alias (16) || [bootstrap_nonce (32)] || nonce (24) || encrypted_header (60) || ciphertext || tag (16)`. `bootstrap_nonce` is present only in the first session packet (`flags & 1`).
- `session_id` is never transmitted; both sides derive it as `HKDF(ikm = shared_secret, salt = bootstrap_nonce, info = "session-id-v3")`, and the open header carries `session_alias = HKDF(ikm = session_id, info = "route-v3")`.
- The ratchet header `dh_pub (32) || epoch_id (u32) || n (u32) || pn (u32)` is encrypted with `HKDF(session_header_secret, info = "hdr-v3" || epoch_id)`. AEAD AAD binds the open header to the encrypted header and payload.
- Inside the encrypted payload, the `LCE1` application envelope encodes `Text { text, ttl_seconds }`, `SetTtl { seconds }`, or `RatchetReset`.
- Packet size is `bucket + rand(0..=bucket/8)` for a bucket in `256, 1024, 4096, 65536` bytes (maximum `73,728` bytes).
- Sliding window of the last 5 epochs (up to 32 skipped message keys per epoch) and a per-session `dh_pub` registry (last 128 keys) prevent replay and handle out-of-order delivery. Old keys are wiped with `Zeroizing`.
- `v1` and `v2` packets are rejected fail-closed with `UnsupportedVersion`.

### Incoming routing by room alias (M-8)

- The client maintains an in-memory `alias -> room` table (rebuilt at startup from `vault.dat`) and selects the room before touching any ratchet key.
- Check order: version and bucket size → alias lookup → retired alias (`StaleSession`) → TTL tombstone alias (`StaleSession`) → `(alias, nonce)` duplicate check (300s TTL, max 8192 entries) → bootstrap resolution (cached up to 256 entries, unknown scans rate-limited by token bucket: burst 16, refill 1/500ms) → TTL tombstone `SHA256(session_id)` (`StaleSession`) → AEAD (budget 24 attempts per packet) → ratchet epoch.
- Non-bootstrap packets with unknown aliases are dropped as `UnknownRoom` with zero decrypt attempts.

### TTL tombstone retention (M-C)

- RAM-TTL rooms never persist ratchet keys or messages to `vault.dat`.
- To prevent a replayed bootstrap packet from resurrecting a retired TTL session after a restart, the vault stores only a minimal encrypted tombstone: `session_alias (16)`, `SHA256(session_id) (32)`, and `retired_at (u64)`.
- Tombstones expire after 30 days (`TOMBSTONE_TTL_SECS`) and are capped at 1024 entries (`MAX_TTL_TOMBSTONES`, oldest evicted first).

### What Tor and the network can see

There is no central server. An observer on the Tor network or a peer's hidden service circuit cannot see message plaintext, `session_id`, `dh_pub`, ratchet counters, or contact identities. A peer receiving frames on its `.onion` service sees incoming TCP connections over Tor, packet timing, padded bucket size (`256..65536` + jitter), and the per-session `session_alias`.

---

## Local vault and storage

On first launch, the client asks for a master password (minimum 8 characters). The password is never stored.

- A random 32-byte salt is written to `vault.salt`; the master key is derived with Argon2id (19 MiB, 2 passes, 1 lane) and held in `Zeroizing`.
- `vault.check` detects wrong passwords.
- `identity.json` and `global.conf` are sealed as `LCVAULT1 || nonce || ciphertext || tag` with XChaCha20-Poly1305.
- Contacts, rooms, messages, Tor hidden service key (`tor_service`), `outbox`, `ratchet_states`, `retired_ratchet_sessions`, and `ttl_tombstones` live in an in-memory SQLite database.
- On changes, the database is serialized, padded on a bucket grid (`4 KiB` … `512 MiB` with jitter), and sealed into `vault.dat` (`nonce || ciphertext || tag`, no magic bytes on disk). `vault.dat` mtime is re-anchored only every 5–15 minutes and shifted back by 1s–6h.
- Rooms with `/ttl` or `/ttl-syn` keep ratchet state and messages strictly in RAM and bypass the persistent Outbox.
- Legacy plaintext `user.db` (if present) is imported on first open, then overwritten with zeros and deleted.

Data directory resolution order:
1. `--profile-dir <path>` or `--profile-dir=<path>` (`--data-dir` is a legacy alias).
2. `LASTCHANCE_DIR` environment variable.
3. Portable mode: `data/` next to the executable if `.portable` exists beside it.
4. Default: `dirs::config_dir()/lastchance` (`~/.config/lastchance` on Linux, `~/Library/Application Support/lastchance` on macOS, `%APPDATA%\lastchance` on Windows).

### File permissions and atomic writes

- On Unix, profile directories are created/enforced as `0700` and data files as `0600` (failing closed if permissions cannot be enforced).
- Files are written to a temporary file in the same directory and atomically renamed.

### In-memory secret handling

- Seeds, private keys, and ratchet keys use `SecretBytes`, `SecretString`, or `Zeroizing` (`zeroize` on drop, no `Clone` on `SecretBytes`/`SecretString`, redacted `Debug`).
- `tests/secret_hygiene.rs` fails CI if `src/` introduces forbidden secret clones.

---

## P2P Tor transport

- **Tor ControlPort** (default `127.0.0.1:9051`): connects, queries `PROTOCOLINFO 1`, authenticates (`SafeCookie`, `Cookie`, or `Null`; cookie path auto-detected or configured), and registers a Tor v3 hidden service via `ADD_ONION` (without `Flags=Detach`, so the service stays active while the control connection is open). The `ED25519-V3:...` service key is stored encrypted inside `vault.dat` so your `.onion` address remains stable across restarts.
- **Inbound listener**: binds strictly to `127.0.0.1:<p2p_local_port>` (default `0` = OS-assigned port) and accepts frames `[len: u32 BE][ratchet_v3_packet]` from the local Tor daemon, validating `len` against `MAX_FRAME_SIZE` (`73,728` bytes) and the v3 bucket grid *before* allocating. Replies with `OK` (`FRAME_ACK`). Limits: `MAX_INBOUND_CONNECTIONS = 64`, `MAX_FRAMES_PER_CONN = 32`, `IO_TIMEOUT = 30s`.
- **Outbound sender (`P2pSender`)**: connects to `<peer>.onion:<p2p_onion_port>` (default `9878`) through Tor SOCKS5h (`127.0.0.1:9050`, `ATYP=0x03` DOMAINNAME — no local DNS), with `SOCKS_CONNECT_TIMEOUT = 45s`, sends the framed packet, and waits for `OK`. Loopback direct TCP is permitted only for `127.0.0.1`/`::1` (self-chat and tests).
- **Outbox**: failed deliveries for normal rooms remain in `outbox` inside `vault.dat` and retry with exponential backoff (`5s, 15s, 30s, 60s, 180s, 600s`).

---

## Notifications

System notifications have four levels:

| Level | Behavior |
| --- | --- |
| `0` | Disabled |
| `1` | Stealth: uses the configured title/body template and hides the messenger name |
| `2` | Default: shows only “New message from …” |
| `3` | Full preview: sender as title and message text (up to 120 characters) |

Stealth mode replaces `{sec}` and `{count}` in the title and body. `/set test` sends a test notification. On Linux, desktop notifications require a running D-Bus notification daemon.

---

## TUI and commands

Type a normal line to send it to the active room. Lines starting with `/` are commands.

### Navigation and chats

| Command | Description |
| --- | --- |
| `/help`, `/h`, `/?` | Open the scrollable help window (same as `F1`) |
| `/contacts`, `/cnt`, `/ls`, `/c` | Contact manager: `↑`/`↓` or `j`/`k` select, `Enter` opens chat, `/` filters, `r` renames, `i` shows info (including `.onion`, fingerprint, TOFU), `c` copies fingerprint, `v` (in info) marks verified, `d` deletes, `q`/`Esc` closes |
| `/join`, `/jn <link>` | Verify a signed `lastchance://contact?...` v2 link and open the import confirmation dialog |
| `/join -f <path>` | Verify a signed invite from a file and open the import confirmation dialog |
| `/room`, `/r [hash \| nick]` | Show or switch the active room |
| `/sidebar`, `/sb` | Hide or show the chat sidebar |

### Messages and settings

| Command | Description |
| --- | --- |
| `/messages [limit]` | Show recent messages of the active room (default 50) |
| `/ttl [duration\|off]` | One-way RAM-only TTL for new messages in the active room; without an argument — show status |
| `/ttl-syn [duration\|off]` | Two-way TTL: sends an encrypted `SetTtl` control packet to the peer |
| `/ttl-syn-retry` | Resend a two-way TTL whose delivery failed |
| `/ratchet-reset` | Reset the Double Ratchet session with the active contact and notify the peer |
| `/set`, `/settings` | Open the interactive settings window |
| `/set notify <0\|1\|2\|3>` | Set the notification level directly |
| `/set test` | Send a test notification |
| `/passwd` | Change the master password and re-encrypt local data |

TTL durations accept `off`, a number with `s`, `m`, or `h` (`30s`, `5m`, `2h`), or plain seconds.

### Profile

| Command | Description |
| --- | --- |
| `/profile`, `/p` | Show nickname, hash, `.onion` address, and public keys as JSON |
| `/recovery` | Show the current BIP-39 phrase after confirming the master password; `Tab`/`r` starts an overwrite |
| `/lang [en\|ru]` | Switch the interface language; without an argument — toggle it |
| `/invite`, `/in [-f [dir \| file]]` | Copy the signed v2 invite link (requires `.onion` to be ready); with `-f`, save to `<nickname>_lastchance.invite` |
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
| `Tab` | Complete commands, contacts, or paths |
| `Up`/`Down` | Input history (last 50 lines) |
| `PgUp`/`PgDn`, mouse wheel | Scroll chat history |
| `Ctrl+W`, `Ctrl+Backspace`, `Alt+Backspace` | Delete word left |
| `Ctrl+Delete`, `Alt+D` | Delete word right |
| `Ctrl+U` / `Ctrl+K` | Delete to start / end of line |
| `Ctrl+Left`, `Alt+B` / `Ctrl+Right`, `Alt+F` | Move by words |
| `Home`, `Ctrl+A` / `End`, `Ctrl+E` | Start / end of line |

### `/set`

The settings window has these fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `Tor ControlPort` | `127.0.0.1:9051` | Tor ControlPort address (`LASTCHANCE_TOR_CONTROL` / `TOR_CONTROL_ADDR`) |
| `Tor SOCKS5h` | `127.0.0.1:9050` | Tor SOCKS5h proxy address (`LASTCHANCE_TOR_SOCKS` / `TOR_SOCKS_ADDR`) |
| `Tor Cookie Path` | auto (`PROTOCOLINFO`) | Path to Tor control cookie (`LASTCHANCE_TOR_COOKIE` / `TOR_COOKIE_PATH`; `-` or `auto` for auto-detect) |
| `P2P Local Port` | `0` (auto) | Local `127.0.0.1` port for inbound Tor hidden service traffic (`LASTCHANCE_P2P_LOCAL_PORT` / `P2P_LOCAL_PORT`) |
| `Onion Service Port` | `9878` | Virtual `.onion` port (`LASTCHANCE_P2P_ONION_PORT` / `P2P_ONION_PORT`) |
| `Notify Level` | `2` | `0`–`3` |
| `Stealth Title` | `Eye break` | Notification title in stealth mode |
| `Stealth Body` | `Time to rest...` | Notification body in stealth mode (`{sec}`, `{count}`) |
| `Stealth Seconds` | `10` | Value substituted for `{sec}` |
| `Language` | `English` | Interface language: `English` or `Русский` |

Controls: `Up`/`Down` or `Tab`/`Shift+Tab` select a field, `Enter` edits it, `Esc` cancels editing. On `Notify Level` and `Language`, `Left`/`Right` or `Space` cycles the value. `Esc` outside editing saves and closes the window (and reloads Tor/P2P settings).

---

## Build and run

Requirements: a stable Rust toolchain (edition 2021) and a running Tor daemon with `ControlPort` and `SocksPort` enabled (for example, in `torrc`: `SocksPort 9050`, `ControlPort 9051`, `CookieAuthentication 1`). SQLite is compiled in via `rusqlite` (`bundled`).

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
```

`--to` accepts a contact name from the local database, an identity hash, or a full `lastchance://contact?...` link. `--send -` reads the message from stdin. Headless mode exits with `0` on success and `1` on error.

Master password sources (in priority order):
1. `LASTCHANCE_PASS_FILE=/path/to/password` — private file (`0600` or stricter on Unix).
2. `LASTCHANCE_PASS=secret` — environment variable (use only under a dedicated UID/container/VM).
3. Interactive TTY prompt with hidden input.

A `lastchance://contact?...` link passed as a command-line argument is imported as a contact.

---

## Prebuilt releases

GitHub Actions (`.github/workflows/release.yml`) builds release binaries on `v*` tags:

| Asset | Platform |
| --- | --- |
| `lastchance-linux-x86_64` | Linux x86_64 |
| `lastchance-windows-x86_64.exe` | Windows x86_64 |
| `lastchance-macos-arm64` | macOS Apple Silicon |

---

## Security notes and limitations

- The static contact shared secret seeds every ratchet session. Each session adds fresh `bootstrap_nonce` entropy and ephemeral DH epochs, so session keys are not reused, but an attacker who records a session's first packet and later obtains the static shared secret can recompute its bootstrap root.
- For RAM-TTL rooms, tombstone retention is bounded to 30 days / 1024 entries (`MAX_TTL_TOMBSTONES`).
- Outbox packets for offline peers in normal rooms are stored encrypted inside `vault.dat` until delivered. RAM-TTL rooms and loopback self-chat never write packets to Outbox.
- `mlock`/`VirtualLock` is not used: secrets can still be written to swap or core dumps.
- The seed phrase is the identity. Anyone who obtains it can impersonate you and read your chats. The master password protects local data only; there is no password recovery.
- The code has not been audited.

---

# Русская версия

LastChance — защищённый P2P-мессенджер на Rust с фокусом на приватность. У клиента нет GUI и нет центральных серверов: это лёгкий терминальный интерфейс (TUI) на `ratatui` и `crossterm`, который общается напрямую peer-to-peer поверх скрытых сервисов Tor v3 (`.onion`). Сетевое ядро и криптография строго отделены от интерфейса.

Проект находится в ранней стадии: код не проходил внешний аудит, протокол может меняться. Текущая версия — `1.0.0`; история изменений приведена в [`CHANGELOG.md`](CHANGELOG.md).

---

## Что умеет

- **Чистый P2P поверх Tor v3 (`.onion`)**: без центральных серверов сообщений или файлов. Клиент сам поднимает скрытый сервис через Tor ControlPort (`ADD_ONION`) и подключается к собеседникам через Tor SOCKS5h.
- **Сквозное шифрование**: Double Ratchet поверх эфемерных ключей X25519, HKDF-SHA256 и XChaCha20-Poly1305 (формат пакетов v3).
- **Защита от анализа трафика**: выравнивание пакетов по bucket-сетке (`256`, `1024`, `4096`, `65536` байт) со случайным джиттером внутри bucket, шифрование заголовков храповика и сессионные alias.
- **Персистентная зашифрованная очередь Outbox**: сообщения для офлайн-собеседников в обычных комнатах сохраняются в `vault.dat` и переотправляются с экспоненциальным backoff (`5с → 15с → 30с → 60с → 180с → 600с`).
- **Подписанные приглашения**: мнемоника BIP-39, X25519 (E2EE) + Ed25519 (подпись), ссылки `lastchance://contact?...` v2 (детерминированный CBOR с `.onion`-адресом) и проверка отпечатка TOFU.
- **Зашифрованное локальное хранилище**: Argon2id + XChaCha20-Poly1305 для `vault.dat` (SQLite в памяти), `identity.json` и `global.conf`.
- **Эфемерные RAM-only TTL-комнаты**: `/ttl` и `/ttl-syn` держат состояние храповика и сообщения только в оперативной памяти (без записи в `vault.dat` и Outbox), с ограниченными tombstone-записями от повторного воспроизведения bootstrap-пакетов.
- **Маскируемые уведомления**: 4 режима (`0`–`3`), включая stealth-уведомления.
- **Двуязычный TUI и headless-режим**: русский и английский интерфейс, модальные окна (`/set`, `/contacts`, `/help`, `/recovery`), автодополнение по `Tab`, история ввода, прокрутка мышью и отправка из CLI (`--to`/`--send`).

Для работы требуется запущенный локальный демон Tor с включёнными `SocksPort` и `ControlPort`.

---

## Архитектура

Крейт разделён на переиспользуемую библиотеку ядра (`src/lib.rs`) без зависимостей от TUI и тонкий бинарник TUI (`src/main.rs`):

| Путь | Назначение |
| --- | --- |
| `src/crypto/` | X25519 ECDH (с проверкой точек малого порядка), HKDF, XChaCha20-Poly1305, Double Ratchet, wire-формат v3, конверт `LCE1`, `SecretBytes`/`SecretString` |
| `src/identity/` | Генерация BIP-39, вывод ключей, зашифрованный `identity.json`, подписанный `IdentityDoc` / `IdentityInvite` v2 (с `.onion`) |
| `src/network/config.rs` | Зашифрованный `global.conf` (Tor ControlPort, SOCKS5h, путь к cookie, порты P2P, уведомления, язык) и env-переопределения |
| `src/network/routing.rs` | Таблица `alias -> room` в памяти, retired-алиасы, дедупликация `(alias, nonce)`, rate-limit bootstrap-сканирования |
| `src/p2p/tor_control.rs` | Клиент Tor ControlPort (`PROTOCOLINFO`, `AUTHENTICATE` через SafeCookie/Cookie/Null, `ADD_ONION`) |
| `src/p2p/transport.rs` | Локальный TCP-слушатель на `127.0.0.1` (`[u32 BE len][packet]` + подтверждение `OK`) и исходящий `P2pSender` через SOCKS5h |
| `src/storage/` | `SafeFSOps` (`0700`/`0600`, атомарная запись) и SQLite в памяти, сериализуемый в `vault.dat` |
| `src/vault.rs` | Вывод мастер-ключа Argon2id и шифрование `LCVAULT1` |
| `src/types/` | Валидируемые типы `IdentityHash`, `OnionAddress`, `RoomId` и безопасное отображение строк |
| `src/app.rs` | Логика `App`, `AppEvent`, цикл Tor ControlPort, воркер Outbox, Double Ratchet, контакты, TTL |
| `src/cli.rs` | Разбор аргументов командной строки (`--profile-dir`, `--to`, `--send`) без зависимостей от TUI |
| `src/i18n.rs` | Локализация (EN/RU) |
| `src/main.rs` | Терминальный интерфейс (`ratatui`/`crossterm`), команды, модальные окна и запуск |

Поток данных:

```text
Исходящие:
  клавиатура ──> TUI (main.rs)
                    │
                    ▼
                 App (app.rs) ──> Double Ratchet v3 ──> Outbox (vault.dat)
                                                            │
                                                            ▼
                                                     P2pSender (SOCKS5h) ──> Tor ──> peer.onion:9878
  (RAM-TTL комнаты и loopback self-chat отправляются напрямую, минуя Outbox)

Входящие:
  Tor ──> .onion:9878 ──> 127.0.0.1:<local_port> (serve_inbound) ──> OK ACK
                                 │
                                 ▼
                          InboundRouter ──> App (Double Ratchet) ──> SQLite в памяти / vault.dat
```

---

## Криптография и пакеты

### Идентичность

- 32-байтовый случайный seed кодируется в мнемонику BIP-39. Команда `/recovery` запрашивает мастер-пароль, показывает текущую фразу и позволяет перезаписать идентичность новой фразой из 12/15/18/21/24 слов (после восстановления нужен перезапуск).
- Из seed через HKDF-SHA256 выводятся две пары ключей:
  - X25519 (`X25519_E2EE_Key_v1`) для шифрования;
  - Ed25519 (`Ed25519_Auth_Key_v1`) для подписи документа личности.
- Публичный `identity_hash` — это `SHA256(Ed25519 public key)` в hex (64 символа).
- Приглашение контакта (`v2`) содержит подписанный детерминированный CBOR-документ (`doc`) и подпись Ed25519 (`sig`):

```text
lastchance://contact?hash=...&doc=<cbor-hex>&sig=<signature-hex>&x25519=...&ed25519=...&onion=...&nickname=...
```

- `doc` включает `version` (`2`), `ed25519_pub`, `x25519_pub`, `onion` (Tor v3 `.onion`-адрес), опциональный `nickname` и `created_at` в RFC 8949 deterministic CBOR. Импорт отклоняет старые инвайты `v1` (без подписанного `.onion`), дублирующиеся параметры, невалидные подписи и любые расхождения между ключами, хешем и адресом.
- Отпечаток приглашения: `SHA256("lastchance:identity-fingerprint:v1" || ed25519_pub || x25519_pub)`. Сверяйте его по другому каналу до подтверждения контакта (`v` в карточке контакта).

### Шифрование сообщений

- Статический общий секрет с контактом вычисляется как `X25519(my_private, their_public)` + HKDF-SHA256 (`ECDH_v1`) и инициализирует сессию Double Ratchet. Все ECDH-пути вызывают `validate_x25519_peer()` (отклонение 7 канонических low-order точек X25519 и проверка `was_contributory()`).
- Формат пакета v3: `version (1) || flags (1) || session_alias (16) || [bootstrap_nonce (32)] || nonce (24) || encrypted_header (60) || ciphertext || tag (16)`.
- `session_id` не передаётся по сети; обе стороны выводят его через HKDF от `shared_secret` и `bootstrap_nonce`, а в открытом заголовке идёт только `session_alias`.
- Заголовок храповика `dh_pub (32) || epoch_id (u32) || n (u32) || pn (u32)` зашифрован ключом эпохи, а AEAD AAD связывает открытый заголовок, зашифрованный заголовок и полезную нагрузку.
- Внутри шифротекста передаётся конверт `LCE1`: `Text { text, ttl_seconds }`, `SetTtl { seconds }` или `RatchetReset`.
- Размер пакета выравнивается до `bucket + rand(0..=bucket/8)` для `bucket` из `256, 1024, 4096, 65536` байт (максимум `73 728` байт).
- Пакеты `v1` и `v2` отклоняются с `UnsupportedVersion`.

### Адресация входящих по alias комнаты (M-8) и TTL-tombstone (M-C)

- Клиент держит в памяти таблицу `alias -> room` и проверяет пакеты в строгом порядке: версия и размер → поиск alias → retired alias (`StaleSession`) → TTL tombstone alias (`StaleSession`) → дедупликация `(alias, nonce)` (TTL 300 с, лимит 8192) → bootstrap-резолв (кэш до 256, неизвестные ограничены token bucket: burst 16, пополнение 1/500 мс) → TTL tombstone `SHA256(session_id)` → AEAD (бюджет 24 попытки) → эпоха храповика.
- Для RAM-TTL комнат в `vault.dat` не пишутся ни ключи храповика, ни сообщения — сохраняется только минимальный зашифрованный tombstone (`session_alias`, `SHA256(session_id)`, `retired_at`) сроком до 30 дней и с глобальным лимитом 1024 записи.

---

## Локальное хранилище

При первом запуске клиент запрашивает мастер-пароль (от 8 символов); сам пароль нигде не сохраняется.

- Мастер-ключ выводится через Argon2id (19 MiB, 2 прохода, 1 поток) с солью из `vault.salt` и хранится в `Zeroizing`.
- `identity.json` и `global.conf` шифруются в формате `LCVAULT1 || nonce || ciphertext || tag` (XChaCha20-Poly1305).
- Контакты, комнаты, сообщения, ключ скрытого сервиса Tor (`tor_service`), `outbox`, `ratchet_states`, `retired_ratchet_sessions` и `ttl_tombstones` живут в SQLite в памяти и при изменениях сериализуются с bucket-паддингом (`4 KiB` … `512 MiB` + джиттер) в `vault.dat`. `mtime` файла `vault.dat` обновляется не чаще раза в 5–15 минут и сдвигается в прошлое на 1 с – 6 ч.
- На Unix каталоги создаются с правами `0700`, файлы — `0600` (при невозможности обеспечить права операция завершается ошибкой).
- Секреты в памяти обёрнуты в `SecretBytes`/`SecretString`/`Zeroizing` и затираются при удалении; `tests/secret_hygiene.rs` запрещает неаудируемое клонирование секретов в `src/`.

Каталог профиля выбирается по приоритету: `--profile-dir` (`--data-dir`) → `LASTCHANCE_DIR` → `./data` (если рядом с бинарником есть `.portable`) → системный каталог конфигурации (`~/.config/lastchance` на Linux).

---

## P2P-транспорт поверх Tor

- **Tor ControlPort** (`127.0.0.1:9051` по умолчанию): подключение, `PROTOCOLINFO 1`, аутентификация (`SafeCookie`, `Cookie` или `Null`), публикация скрытого сервиса через `ADD_ONION` (без `Flags=Detach`). Приватный ключ `ED25519-V3:...` сохраняется в зашифрованном `vault.dat`, поэтому `.onion`-адрес постоянен между запусками.
- **Входящий слушатель**: привязывается строго к `127.0.0.1:<p2p_local_port>` (`0` — автовыбор свободного порта), читает фреймы `[len: u32 BE][packet]` (лимит `73 728` байт и проверка bucket-сетки *до* аллокации, до 64 одновременных соединений, до 32 фреймов на соединение, таймаут 30 с) и отвечает `OK`.
- **Исходящий отправитель (`P2pSender`)**: подключается к `<peer>.onion:<p2p_onion_port>` (`9878` по умолчанию) через Tor SOCKS5h (`127.0.0.1:9050`, `ATYP=0x03`, без локального DNS, таймаут 45 с) и ждёт `OK`. Прямой TCP разрешён только на loopback (`127.0.0.1`/`::1`) для self-chat и тестов.
- **Outbox**: при ошибке доставки в обычных комнатах пакет остаётся в зашифрованной очереди и повторяется с backoff `5, 15, 30, 60, 180, 600` секунд.

---

## TUI и команды

Обычная строка отправляется в активную комнату. Строки с `/` — команды.

### Навигация и чаты

| Команда | Описание |
| --- | --- |
| `/help`, `/h`, `/?` | Открыть справку (или `F1`) |
| `/contacts`, `/cnt`, `/ls`, `/c` | Менеджер контактов: `↑`/`↓` (`j`/`k`), `Enter` — открыть чат, `/` — фильтр, `r` — переименовать, `i` — карточка контакта (`.onion`, отпечаток, TOFU), `c` — копировать отпечаток, `v` — подтвердить отпечаток, `d` — удалить, `q`/`Esc` — закрыть |
| `/join`, `/jn <link>` | Проверить подписанную ссылку `lastchance://contact?...` v2 и подтвердить импорт |
| `/join -f <path>` | Проверить подписанный инвайт из файла |
| `/room`, `/r [hash \| nick]` | Показать или переключить активную комнату |
| `/sidebar`, `/sb` | Скрыть или показать боковую панель |

### Сообщения и настройки

| Команда | Описание |
| --- | --- |
| `/messages [limit]` | Показать последние сообщения активной комнаты (по умолчанию 50) |
| `/ttl [duration\|off]` | Односторонний RAM-TTL для новых сообщений (`30s`, `5m`, `2h`, `off`) |
| `/ttl-syn [duration\|off]` | Двусторонний TTL: отправляет собеседнику зашифрованный сигнал `SetTtl` |
| `/ttl-syn-retry` | Повторно отправить неподтверждённый сигнал `/ttl-syn` |
| `/ratchet-reset` | Сбросить сессию Double Ratchet и уведомить собеседника |
| `/set`, `/settings` | Открыть окно настроек |
| `/set notify <0\|1\|2\|3>` | Установить уровень уведомлений (`0` — выкл, `1` — stealth, `2` — по умолчанию, `3` — с текстом) |
| `/set test` | Отправить тестовое уведомление |
| `/passwd` | Сменить мастер-пароль и перешифровать локальные данные |

### Профиль

| Команда | Описание |
| --- | --- |
| `/profile`, `/p` | Показать ник, хеш, `.onion`-адрес и публичные ключи в JSON |
| `/recovery` | Показать BIP-39 фразу после ввода мастер-пароля; `Tab`/`r` — перезапись фразы |
| `/lang [en\|ru]` | Переключить язык интерфейса |
| `/invite`, `/in [-f [dir \| file]]` | Скопировать подписанную ссылку-приглашение v2 (когда готов `.onion`); с `-f` — сохранить в `<nickname>_lastchance.invite` |
| `/export` | Вывести свой контакт в JSON |
| `/nick <name>` | Сменить свой ник |
| `/rename <hash> <name>` | Переименовать контакт |
| `/quit`, `/q`, `/exit` | Выйти |

### Настройки `/set`

| Поле | По умолчанию | Назначение |
| --- | --- | --- |
| `Tor ControlPort` | `127.0.0.1:9051` | Адрес Tor ControlPort (`LASTCHANCE_TOR_CONTROL` / `TOR_CONTROL_ADDR`) |
| `Tor SOCKS5h` | `127.0.0.1:9050` | Адрес Tor SOCKS5h (`LASTCHANCE_TOR_SOCKS` / `TOR_SOCKS_ADDR`) |
| `Tor Cookie` | авто (`PROTOCOLINFO`) | Путь к cookie-файлу Tor (`LASTCHANCE_TOR_COOKIE` / `TOR_COOKIE_PATH`; `-` или `auto` — автопоиск) |
| `Локальный порт P2P` | `0` (авто) | Локальный порт `127.0.0.1` для входящего трафика от Tor (`LASTCHANCE_P2P_LOCAL_PORT` / `P2P_LOCAL_PORT`) |
| `Порт .onion-сервиса` | `9878` | Виртуальный порт `.onion` (`LASTCHANCE_P2P_ONION_PORT` / `P2P_ONION_PORT`) |
| `Notify Level` | `2` | Уровень уведомлений (`0`–`3`) |
| `Stealth Title` | `Eye break` | Заголовок в stealth-режиме |
| `Stealth Body` | `Time to rest...` | Текст в stealth-режиме (`{sec}`, `{count}`) |
| `Stealth Seconds` | `10` | Значение для `{sec}` |
| `Язык` | `English` | Язык интерфейса (`English` / `Русский`) |

---

## Сборка и запуск

Требования: стабильный Rust (edition 2021) и запущенный демон Tor с включёнными `SocksPort` и `ControlPort` (например, в `torrc`: `SocksPort 9050`, `ControlPort 9051`, `CookieAuthentication 1`).

```bash
git clone <this-repository>
cd LastChance_Rust
cargo build --release
./target/release/lastchance
```

Для разработки:

```bash
cargo check --message-format=short
cargo test
```

Headless-отправка без TUI:

```bash
LASTCHANCE_PASS=secret lastchance --to alice --send "hello"
echo "secret text" | LASTCHANCE_PASS=secret lastchance --to alice --send -
```

Источники мастер-пароля по приоритету: `LASTCHANCE_PASS_FILE` (файл с правами `0600` или строже на Unix) → `LASTCHANCE_PASS` → интерактивный ввод в TTY.

---

## Безопасность и ограничения

- Статический общий секрет с контактом используется для инициализации каждой сессии храповика. Каждая сессия добавляет свежий `bootstrap_nonce` и эфемерные DH-эпохи, но при компрометации статического секрета и наличии перехваченного первого пакета можно восстановить начальный root-ключ сессии.
- В обычных комнатах недоставленные пакеты хранятся в зашифрованном виде в `outbox` внутри `vault.dat` до доставки. В RAM-TTL комнатах и loopback self-chat пакеты в Outbox не пишутся.
- `mlock`/`VirtualLock` не используется: секреты могут попадать в swap и core dumps.
- Мнемоническая фраза — это ваша идентичность. Мастер-пароль защищает только локальное хранилище; восстановления пароля нет.
- Код не проходил независимый аудит безопасности.
