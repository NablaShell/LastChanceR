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
| `src/network/auth.rs` | Canonical request signatures, nonce cache and server-side verification |
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

- Authenticated requests use one canonical envelope: `METHOD\nPATH\nCANONICAL_QUERY\nTIMESTAMP\nNONCE\nSHA256(body)`. `METHOD` is uppercase, `PATH` has no query and no trailing slash (except `/`), `CANONICAL_QUERY` preserves the original percent-encoding and sorts the raw `key=value` pairs by key and then by value (an empty query stays empty), `TIMESTAMP` is Unix seconds and `NONCE` is 24 CSPRNG bytes in unpadded base64url. Ed25519 signs the UTF-8 envelope; the signature is also unpadded base64url.
- The client sends `X-Auth-Identity`, `X-Auth-Timestamp`, `X-Auth-Nonce` and `X-Auth-Signature` (plus the public key in `X-Identity-Key`). A compatible server must bind the identity hash to a known contact, accept `timestamp` only inside `[now - 60s, now + 30s]`, reject a nonce already seen for that identity, rebuild the envelope from the actual method/path/query/body, and answer every authentication failure with the same `401` body (the reason is written to the internal audit log only). The nonce cache holds at most 1024 entries per identity, expires entries after `60 + 30 + 60 = 150s`, and fails closed with `503` instead of evicting when full.

### Message encryption

- Each contact has a static shared secret: `X25519(my_private, their_public)` followed by HKDF-SHA256 with the `ECDH_v1` label. It seeds the Double Ratchet session.
- ECDH rejects invalid curve points: an all-zero X25519 output (low-order point) aborts the key agreement instead of producing a shared secret.
- Messages use a Double Ratchet over X25519 ephemeral DH steps, HKDF-SHA256 (`RootKey`, `ChainKey`, `MessageKey`) and XChaCha20-Poly1305 with a fresh 24-byte nonce.
- Wire format v3 is `version (1) || flags (1) || session_alias (16) || [bootstrap_nonce (32)] || nonce (24) || encrypted_header (60) || ciphertext || tag (16)`. The `bootstrap_nonce` field is present only in the first session packet (`flags & 1`); later packets omit it.
- `session_id` is not transmitted. Both sides derive it as `HKDF(ikm = shared_secret, salt = bootstrap_nonce, info = "session-id-v3")`; the open header carries `session_alias = HKDF(ikm = session_id, info = "route-v3")`. The alias is stable inside one session and is not the session id.
- The ratchet header `dh_pub (32) || epoch_id (u32) || n (u32) || pn (u32)` is encrypted with `HKDF(session_header_secret, info = "hdr-v3" || epoch_id)`, so `dh_pub`, counters and epoch boundaries are not visible on the wire. The key rotates on every DH epoch; the receiver tries known epochs plus a 64-epoch look-ahead window.
- AEAD AAD binds the open header (version, flags, alias, optional bootstrap nonce, nonce) to the encrypted header and payload. Tampering with any header field, swapping headers between epochs, or downgrading the version fails authentication before any plaintext is produced.
- Every ratchet state gets a fresh CSPRNG `bootstrap_nonce`; bootstrap keys are derived from it. After a TTL change or `/ratchet-reset` the next session uses new entropy, so a captured bootstrap packet from an old session cannot be accepted by a new one.
- Destroyed and evicted `session_id` values are remembered and rejected as `StaleSession` even when the AEAD tag is valid. For normal rooms these tombstones are stored in `vault.dat` and survive a client restart; for RAM-TTL rooms they intentionally live only in RAM (H-3) and are lost on restart. The registry holds up to 128 ids.
- Received peer `dh_pub` values are remembered per session (last 128). A packet whose `dh_pub` was already accepted but whose epoch has left the 5-epoch window is rejected as `ReplayedDhPub` before any cryptography. The registry is filled only after a successful authentication. The v3 header carries an authenticated `epoch_id`, so a genuine older key is no longer indistinguishable from a new epoch.
- The client keeps a sliding window of the last 5 epochs (plus up to 32 skipped message keys per epoch), so messages sent concurrently or delivered out of order still decrypt. Old epochs, evicted epoch ids and used message keys are wiped with `Zeroizing`.
- Packet size is `bucket + rand(0..=bucket/8)` for a bucket in `256, 1024, 4096, 65536` bytes. Randomization happens inside the bucket, so the exact size does not correlate with `n` or the message volume; only the bucket (coarse size class) is visible.
- The final packet is `open_header || encrypted_header || ciphertext || tag`; only lengths inside a valid randomized bucket are accepted.
- v1 and v2 packets are rejected with `UnsupportedVersion` (fail-closed, no panic, no partial decryption). The old unauthenticated static-secret decrypt path was removed in M-3; it had no counter or window and allowed indefinite replay.
- `/ratchet-reset` forces a fresh session with the active contact and notifies the peer. The reset creates a new `session_id`, `bootstrap_nonce` and bootstrap keys.

Losing the header key together with the epoch makes the message undecryptable, as in Signal; the UI reports it as an unavailable message instead of guessing. The alias is stable within a session; if that linkability matters, it can be rotated per epoch in a future version (the current policy is documented and tested).

### Incoming routing by room alias (M-8)

- The client keeps an in-memory `alias -> room` table (rebuilt at startup from persisted ratchet states and tombstones) and selects the room from the open header before touching any key.
- Incoming checks have a fixed order: version and size → alias lookup → retired alias (`StaleSession`) → `(alias, nonce)` duplicate check → AEAD → ratchet epoch.
- A non-bootstrap packet with an unknown alias is dropped as `UnknownRoom` with zero decrypt attempts. No contact list is scanned and no packet is tried against several rooms.
- The only multi-contact path is the first packet of a new session: it carries `bootstrap_nonce`, so the client compares cheap HKDF-derived aliases and runs AEAD for at most the single room that matched. This is bounded alias resolution, not ciphertext fan-out.
- Retired aliases (after `/ratchet-reset`, TTL reset, session eviction or contact deletion) are rejected before dedup and AEAD, so an old packet cannot create a fresh session.
- Duplicate delivery is suppressed by `(alias, nonce)` for 300 seconds with a hard cap of 8192 entries. The entry is recorded only after a successful decryption, so junk cannot grow the table.
- Aliases are deterministic from `session_id`: the same session always maps to the same 16-byte alias. This is a deliberate linkability/retention trade-off. A server or observer that sees the alias can group packets into one session, but cannot recover `session_id`, the ratchet epoch, the contact identity or the plaintext. A new alias appears only when the session is reset; aliases are never derived from the long-term identity and are not persisted outside `vault.dat`.
- No enumeration: the client never asks the server which rooms it has, and `/push` is addressed only by the recipient identity hash. The alias lives inside the authenticated v3 header and is never sent as a routing parameter.

### File encryption

Files use a self-contained v3 envelope:

```text
ver (1) = 3 || file_id (16) || nonce (24) || AEAD(inner) || tag (16)
inner = name_len (u16) || name || size (u64) || padded_size (u64) || payload || zero padding
```

- The file key is `HKDF(ikm = contact_shared_secret, salt = file_id, info = "file-v3")`; the static contact secret is never used directly as an AEAD key. If a session/root key is available it is preferred; the current client uses the contact secret as the documented fallback and the per-file salt still gives every file a unique key.
- `name` and the real `size` live only inside the AEAD. The plaintext `X-File-Name` upload header was removed; the server receives an opaque blob and its hash.
- AAD is `"lastchance-file-v3" || version || file_id || room_id || identity_pair`, where the sender/recipient pair is canonically sorted. Moving a blob to another room, contact pair or file id fails authentication.
- `padded_size` follows a bucket grid (1 KiB … 112 MiB) with randomization inside the bucket; the payload tail is zero-filled. On decrypt the client checks `padded_size` equals the actual payload, `size <= padded_size`, and that the whole tail is zero (`PaddingInvalid` otherwise).
- The client rejects `padded_size`/envelope sizes above 128 MiB before allocating the AEAD output, so padding cannot become an OOM vector. The maximum real file size remains 100 MiB.
- Legacy files (`nonce || ciphertext`, no AAD) are rejected with `UnsupportedVersion`: migration is fail-closed by default. There is no lazy re-encryption path because the old blob format carries no room/identity binding; an explicitly enabled migration reader can be added later without weakening the default.
- The chat message still contains the file name, size and hash, but that message is itself end-to-end encrypted.

The text server and the file server are separate URLs configured independently.

### Wire format v3 release note (breaking)

v3 is intentionally incompatible with v1/v2. After upgrading, old ratchet state is ignored (the client starts a fresh session), v2 packets are rejected with `UnsupportedVersion`, and old file blobs cannot be decrypted. Both peers must upgrade together; there is no downgrade path. The change removes the unauthenticated legacy decrypt path, hides ratchet counters and `dh_pub`, replaces the open `session_id` with an alias, and binds file metadata into AEAD.

### What the servers can see

The text server sees the recipient hash in the URL, the padding bucket, the timing and the masking headers. It no longer sees `dh_pub`, ratchet counters, epoch boundaries or the raw `session_id`. It also cannot enumerate a user's rooms: pulls are addressed by identity hash only, and the room alias travels inside the v3 packet. The alias is stable per session, so packet grouping by alias remains possible (see the M-8 notes above). The file server sees the encrypted blob size bucket and its hash, but not the file name or real size. Message and file contents remain encrypted end to end.

---

## Local vault and storage

On first launch the client asks for a master password (minimum 8 characters). The password is never stored.

- A random 32-byte salt is written to `vault.salt`.
- The master key is derived with Argon2id (19 MiB, 2 passes, 1 lane) and kept in memory inside `Zeroizing`.
- `vault.check` is an encrypted marker used to detect a wrong password.
- `identity.json` and `global.conf` are sealed as `LCVAULT1 || nonce || ciphertext || tag` with XChaCha20-Poly1305 and associated data.
- Contacts, rooms, messages, file records and normal Double Ratchet sessions live in an in-memory SQLite database; nothing is ever written to `user.db`, `user.db-wal` or `user.db-shm`.
- On every change the whole database is serialized, padded with random bytes on a bucket grid (4 KiB … 512 MiB) with jitter inside the bucket, and sealed with XChaCha20-Poly1305 into `vault.dat` as `nonce || ciphertext || tag`; no magic bytes or open headers are stored on disk. The schema version and payload length sit inside the encrypted block, so the exact number of messages is not exposed — an observer sees only the bucket.
- `vault.dat` mtime is not refreshed on every write: it is re-anchored every 5–15 minutes and shifted by a random 1 second … 6 hours into the past. These are mitigations, not elimination: bucket boundaries, file existence and long-term growth still leak coarse activity.
- Rooms with an active `/ttl` or `/ttl-syn` timer keep the ratchet state strictly in RAM: it is never written to `vault.dat` and is wiped when TTL is disabled or the client exits. Ephemeral messages and TTL file records never rewrite `vault.dat` either (H-3), so TTL traffic does not update its size or mtime.
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

### File permissions and atomic writes

On Unix the client never relies on the process umask:

- Profile directories (the vault root, its subdirectories and migration staging) are created with mode `0700`.
- Data files (`vault.dat`, `vault.salt`, `vault.check`, `identity.json`, `global.conf`, downloads) are created with mode `0600`.
- Modes are requested at creation time and then verified. If the umask (or an existing directory) produced wider or narrower bits, the client applies `chmod` explicitly. If the final mode still cannot be enforced, the operation fails closed instead of continuing with weaker permissions. The global umask is never modified.
- Data is written to a private temporary file in the destination directory and atomically renamed on success. On error the temporary file is removed and the target is left untouched.
- Old-profile migration creates and hardens the destination structure while copying, so source modes such as `0755`/`0644` are never inherited. A failed migration removes the staging directory.
- Deleting a database removes its SQLite sidecars `-journal`, `-wal` and `-shm` together with the main file; missing sidecars are ignored, other errors are reported.

On non-Unix platforms POSIX modes are unavailable; the client falls back to the read-only marker where applicable and does not silently claim files are private.

### In-memory secret handling

- The seed phrase, X25519/Ed25519 private keys, ratchet root/chain keys and message keys live in `SecretBytes`/`SecretString` or `Zeroizing` wrappers. They are zeroized on drop by the `zeroize` crate (volatile writes plus a compiler fence), so the optimizer cannot elide the wipe.
- `SecretBytes`/`SecretString` deliberately do not implement `Clone`; a copy requires an explicit, auditable `duplicate()` call. `Debug` prints `<secret>`, and fixed-size wrappers (`Ed25519Seed`, `X25519Priv`, `RootKey`) print `<redacted>`, so secrets never reach logs or panic messages.
- `Identity` has a manual `Debug` that shows only public keys, the identity hash and timestamps. `Identity::clone()` is the single audited place where identity secrets are duplicated (used by the identity cache).
- `RatchetState::to_bytes()` returns `SecretBytes`; `from_bytes()` takes ownership of the secret buffer. State loaded from `vault.dat` is wrapped in `SecretBytes` immediately, and error paths wipe intermediate JSON/hex buffers.
- The listener receives the identity private key as `Arc<SecretBytes>` and holds no bare `Vec<u8>` copy; the buffer is wiped when the last `Arc` is dropped.
- The BIP-39 recovery phrase and the master password are read with terminal echo disabled. The seed phrase is never displayed (not even its length), must be entered twice, and the input buffer is zeroized on drop; a TTY password is masked with `*`.
- `RatchetState::with_root_key()` exposes the current root key only inside a closure instead of returning a copy.
- `mlock`/`VirtualLock` is intentionally not used (no extra platform dependency): secrets can still be written to swap and core dumps. Use encrypted swap or a hardened environment if that threat is in scope. Disabling core dumps via `prctl(PR_SET_DUMPABLE, 0)` is also out of scope here.
- A test (`tests/secret_hygiene.rs`) fails if `src/` reintroduces `private_key.clone()`, `seed_phrase.clone()`, `current_root_key` or similar secret copies.

---

## Transport

### Text API

- Send: `POST /push/<target_hash>` with `application/octet-stream`.
- Receive: `GET /pull/<identity_hash>?wait=25`.
- The server holds an empty long-poll for up to 25 seconds; the client uses a 45-second timeout.
- `204 No Content` means the queue is empty.
- A successful pull returns `multipart/form-data`; the client parses the parts and checks that packet sizes are in the allowed grid.
- `429` means rate limiting. Pull retries use a 1s → 2s → 5s → 15s backoff for retryable failures; `401` and protocol errors are retried slowly to avoid a busy loop.
- Push uses the same canonical envelope as pull: `X-Auth-Identity`, `X-Auth-Timestamp`, `X-Auth-Nonce`, `X-Auth-Signature`, with `body_hash = SHA256(packet)` bound into the signature. Every retry gets a fresh nonce and a fresh timestamp; the nonce is never reused.
- `401` from `/push` is not retried (the server will reject the same identity/signature again). `429`, `503` and transport errors are retried with 1s → 2s → 4s exponential backoff, up to 4 attempts total.
- The client enforces a local token bucket of `PUSH_REQUESTS_PER_SECOND = 8` per contact before signing, so a bug or a malicious UI action cannot turn the client into a push flood; exhausting it is a local error, not a server response.

### File API

- Upload: `POST /upload` with `application/octet-stream` and `Content-Length`; the response body is the file hash. The file name is not sent as a header (it is inside the v3 AEAD envelope).
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

`--to` accepts a contact name from the local database, an identity hash or a full `lastchance://contact?...` link. `--send -` reads the message from stdin so the text does not appear in `ps aux`. Headless mode exits with code `0` on success and `1` on error.

The master password is taken from these sources, in priority order:

1. `LASTCHANCE_PASS_FILE=/path/to/password` — read from a file that must be private. On Unix the client rejects any file with group or other permission bits (`0600` or stricter), strips trailing newline characters and never prints the contents. The path itself is not secret.
2. `LASTCHANCE_PASS=secret` — kept for compatibility. The value is part of the process environment: the same UID (and root) can read it via `/proc/<pid>/environ`, and it may also leak into shell history, process listings, crash dumps or logs of a supervisor. Use it only when the client runs under a dedicated UID, container or VM. With a shared UID prefer `LASTCHANCE_PASS_FILE`, or systemd credentials (`LoadCredentialEncrypted=` and `LASTCHANCE_PASS_FILE=$CREDENTIALS_DIRECTORY/lastchance-pass`).
3. If neither variable is set, an interactive TTY is prompted with hidden input.

When both variables are set, `LASTCHANCE_PASS_FILE` wins; `LASTCHANCE_PASS` is ignored and a warning is printed. Neither warning contains the password value, and the value is never logged.

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

- The shared secret is static per contact and seeds every ratchet session. Each session adds fresh `bootstrap_nonce` entropy and ephemeral DH epochs, so session keys are not reused and captured packets cannot be replayed into a new session. Bootstrap keys are nevertheless derived from the long-term shared secret: an attacker who records a session's first packet and later obtains that secret can recompute its bootstrap root. There is no post-compromise security, and true first-message forward secrecy would require an interactive prekey/response handshake. For normal rooms destroyed session ids are persisted in `vault.dat`, so replay of a reset session stays blocked across restarts. For RAM-TTL rooms the list of destroyed session ids lives only in RAM (for the lifetime of the process), so after a client restart a replayed first packet is indistinguishable from first contact (the same TOFU boundary as the very first session). The per-session `dh_pub` registry is bounded to 128 keys: beyond that horizon an ancient key would again look new, but its local DH private key has already left the 5-epoch send window, so the packet still cannot be decrypted. The old v2 header had no epoch counter, so a genuine first-seen `dh_pub` from an older epoch could be accepted as a new epoch and move `remote_pub` back to that authentic key. In v3 the header carries an authenticated `epoch_id` inside the AEAD, and stale epochs are detected before any key agreement, so this limited denial-of-progress no longer applies; v1/v2 packets are rejected outright.
- The server still learns the recipient identity hash, traffic timing, packet size class and the file blob size. The per-session alias allows grouping packets that belong to the same ratchet session, but not identifying the contact or the `session_id`. Use Tor/I2P and your own servers if that metadata matters to you.
- Alias routing leaves no durable server-side trace beyond delivery: the client keeps the alias table only in RAM, rebuilds it from `vault.dat` on startup and forgets retired aliases on contact deletion. Duplicate-delivery keys are held for 300 seconds (maximum 8192) and are not persisted.
- Local metadata such as contact hashes, public keys and timestamps is not encrypted; message bodies, nicknames and file names are.
- The seed phrase is the identity. Anyone who obtains it can impersonate you and read your chats. The master password protects local data only; there is no password recovery.
- `LASTCHANCE_PASS` is exposed to every process that can read the client's environment (`/proc/<pid>/environ` for the same UID, and root). Prefer `LASTCHANCE_PASS_FILE` with mode `0600` or systemd credentials; use the environment variable only under a dedicated UID, container or VM.
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
| `src/network/auth.rs` | Канонические подписи запросов, nonce-кэш и серверная проверка |
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

- Аутентифицированные запросы используют единый канонический конверт: `METHOD\nPATH\nCANONICAL_QUERY\nTIMESTAMP\nNONCE\nSHA256(body)`. `METHOD` — в верхнем регистре, `PATH` — без query и завершающего `/` (кроме корня), `CANONICAL_QUERY` сохраняет исходный percent-encoding и сортирует необработанные пары `key=value` по ключу, затем по значению (пустой query остаётся пустым), `TIMESTAMP` — Unix-секунды, `NONCE` — 24 байта CSPRNG в base64url без padding. Ed25519 подписывает конверт в UTF-8; подпись также кодируется в base64url без padding.
- Клиент отправляет `X-Auth-Identity`, `X-Auth-Timestamp`, `X-Auth-Nonce` и `X-Auth-Signature` (а публичный ключ — в `X-Identity-Key`). Совместимый сервер обязан связать identity hash с известным контактом, принимать `timestamp` только в окне `[now - 60s, now + 30s]`, отклонять уже использованный этой identity nonce, собирать конверт из фактических method/path/query/body и отвечать на любой отказ аутентификации одинаковым телом `401` (причина пишется только во внутренний аудит-лог). Nonce-кэш хранит не более 1024 записей на identity, истекает через `60 + 30 + 60 = 150s` и при переполнении отвечает `503` (fail-closed), а не вытесняет старые записи.

### Шифрование сообщений

- Для каждого контакта вычисляется статический общий секрет: `X25519(мой_private, его_public)`, затем HKDF-SHA256 с меткой `ECDH_v1`. Он инициализирует сессию Double Ratchet.
- ECDH отклоняет некорректные точки: полностью нулевой выход X25519 (точка малого порядка) прерывает согласование ключа вместо выдачи общего секрета.
- Сообщения используют Double Ratchet поверх эфемерных X25519 DH-шагов, HKDF-SHA256 (`RootKey`, `ChainKey`, `MessageKey`) и XChaCha20-Poly1305 со свежим 24-байтным nonce.
- Wire-format v3: `version (1) || flags (1) || session_alias (16) || [bootstrap_nonce (32)] || nonce (24) || encrypted_header (60) || ciphertext || tag (16)`. Поле `bootstrap_nonce` присутствует только в первом пакете сессии (`flags & 1`), остальные пакеты его не несут.
- `session_id` не передаётся. Обе стороны выводят его как `HKDF(ikm = shared_secret, salt = bootstrap_nonce, info = "session-id-v3")`; в открытом заголовке едет `session_alias = HKDF(ikm = session_id, info = "route-v3")`. Alias стабилен внутри сессии и не равен `session_id`.
- Заголовок храповика `dh_pub (32) || epoch_id (u32) || n (u32) || pn (u32)` шифруется ключом `HKDF(session_header_secret, info = "hdr-v3" || epoch_id)`, поэтому `dh_pub`, счётчики и границы эпох не видны на проводе. Ключ ротируется на каждой DH-эпохе; получатель перебирает известные эпохи и окно до 64 новых `epoch_id`.
- AAD полезной нагрузки связывает открытый заголовок (версия, флаги, alias, необязательный bootstrap-nonce, nonce), зашифрованный заголовок и шифротекст. Подмена любого поля заголовка, перестановка заголовков между эпохами или downgrade версии ломает аутентификацию до выдачи открытого текста.
- Каждое состояние храповика получает свежий `bootstrap_nonce` из CSPRNG; из него выводятся bootstrap-ключи. После смены TTL или `/ratchet-reset` следующая сессия использует новую энтропию, поэтому перехваченный bootstrap-пакет старой сессии не может быть принят новой.
- Уничтоженные и вытесненные `session_id` запоминаются и отклоняются как `StaleSession`, даже если AEAD-тег валиден. Для обычных комнат tombstone-и пишутся в `vault.dat` и переживают перезапуск клиента; для RAM-TTL комнат они намеренно живут только в RAM (H-3) и теряются при перезапуске. Реестр хранит до 128 id.
- Принятые `dh_pub` собеседника запоминаются на сессию (последние 128). Пакет, чей `dh_pub` уже принимался, но чья эпоха вышла из окна в 5 эпох, отклоняется как `ReplayedDhPub` ещё до криптографии; реестр пополняется только после успешной аутентификации. В v3 есть аутентифицированный `epoch_id`, поэтому подлинный старый ключ больше не неотличим от новой эпохи.
- Клиент держит скользящее окно из 5 последних эпох (и до 32 пропущенных ключей на эпоху), поэтому одновременные и пришедшие не по порядку сообщения расшифровываются. Старые эпохи, id вытесненных эпох и использованные ключи сообщений затираются через `Zeroizing`.
- Размер пакета — `bucket + rand(0..=bucket/8)`, где bucket один из `256, 1024, 4096, 65536` байт. Рандомизация идёт внутри bucket, поэтому точный размер не коррелирует с `n` или объёмом сообщения; виден только сам bucket (грубый класс размера).
- Итоговый пакет — `open_header || encrypted_header || ciphertext || tag`; принимаются только длины внутри допустимого рандомизированного bucket.
- Пакеты v1 и v2 отклоняются с `UnsupportedVersion` (fail-closed, без паники и частичной расшифровки). Старый неаутентифицированный путь расшифровки со статическим секретом удалён в M-3: у него не было ни счётчика, ни окна, поэтому он допускал бессрочный replay.
- `/ratchet-reset` принудительно создаёт новую сессию с активным контактом и уведомляет собеседника. Reset генерирует новые `session_id`, `bootstrap_nonce` и bootstrap-ключи.

Потеря ключа заголовка вместе с эпохой делает сообщение нерасшифровываемым (как в Signal); UI показывает его как недоступное, а не угадывает. Alias стабилен внутри сессии; если эта связываемость критична, его можно ротировать по эпохам в следующей версии (текущая политика зафиксирована и покрыта тестами).

### Адресация входящих по alias комнаты (M-8)

- Клиент держит в памяти таблицу `alias -> комната` (собирается при старте из сохранённых ratchet-состояний и tombstone-ов) и выбирает комнату по открытому заголовку до обращения к ключам.
- Порядок проверок входящего пакета фиксирован: версия и размер → поиск alias → retired alias (`StaleSession`) → проверка дубля `(alias, nonce)` → AEAD → эпоха храповика.
- Не-bootstrap пакет с неизвестным alias отбрасывается как `UnknownRoom` без единой попытки расшифровки. Список контактов не перебирается, пакет не пробуется против нескольких комнат.
- Единственный путь с несколькими контактами — первый пакет новой сессии: он несёт `bootstrap_nonce`, поэтому клиент сравнивает дешёвые HKDF-alias и запускает AEAD максимум для одной совпавшей комнаты. Это ограниченное разрешение alias, а не перебор шифротекста.
- Retired alias (после `/ratchet-reset`, сброса TTL, вытеснения сессии или удаления контакта) отклоняется до дедупликации и AEAD, поэтому старый пакет не может создать новую сессию.
- Повторная доставка подавляется по `(alias, nonce)` в течение 300 секунд с жёстким лимитом в 8192 записи. Запись появляется только после успешной расшифровки, поэтому мусор не раздувает таблицу.
- Alias детерминированно выводится из `session_id`: одна сессия всегда даёт один и тот же 16-байтный alias. Это осознанный компромисс по связываемости/хранению. Сервер или наблюдатель, видящий alias, может группировать пакеты одной сессии, но не может восстановить `session_id`, эпоху храповика, личность контакта или открытый текст. Новый alias появляется только при сбросе сессии; alias никогда не выводится из долговременной идентичности и не хранится вне `vault.dat`.
- Перечисления нет: клиент никогда не спрашивает сервер, какие комнаты у него есть, а `/push` адресуется только по identity hash получателя. Alias находится внутри аутентифицированного заголовка v3 и не передаётся как параметр маршрутизации.

### Шифрование файлов

Файлы используют самостоятельный конверт v3:

```text
ver (1) = 3 || file_id (16) || nonce (24) || AEAD(inner) || tag (16)
inner = name_len (u16) || name || size (u64) || padded_size (u64) || payload || нулевой паддинг
```

- Ключ файла — `HKDF(ikm = контактный_shared_secret, salt = file_id, info = "file-v3")`; статический секрет никогда не используется напрямую как AEAD-ключ. Если доступен сессионный/корневой ключ, он предпочтителен; текущий клиент использует контактный секрет как задокументированный fallback, а соль `file_id` всё равно даёт уникальный ключ каждому файлу.
- `name` и реальный `size` лежат только внутри AEAD. Открытый заголовок `X-File-Name` при загрузке удалён; сервер получает непрозрачный блок и его хеш.
- AAD — `"lastchance-file-v3" || version || file_id || room_id || identity_pair`, где пара отправитель/получатель канонически сортируется. Перенос блока в другую комнату, пару контактов или с другим `file_id` ломает аутентификацию.
- `padded_size` выбирается по bucket-сетке (1 КиБ … 112 МиБ) с рандомизацией внутри bucket; хвост payload заполнен нулями. При расшифровке проверяется, что `padded_size` совпадает с фактическим payload, `size <= padded_size`, а весь хвост нулевой (иначе `PaddingInvalid`).
- Клиент отклоняет `padded_size`/конверт больше 128 МиБ до аллокации выхода AEAD, поэтому паддинг не становится вектором OOM. Максимальный реальный размер файла остаётся 100 МиБ.
- Legacy-файлы (`nonce || ciphertext`, без AAD) отклоняются с `UnsupportedVersion`: миграция fail-closed по умолчанию. Ленивого перешифрования нет, потому что старый формат не привязывает блок к комнате/идентичности; явный режим чтения для миграции можно добавить позже, не ослабляя дефолт.
- В сообщении чата по-прежнему есть имя, размер и хеш файла, но само сообщение зашифровано сквозным образом.

Текстовый и файловый серверы — разные URL, настраиваются независимо.

### Release note: wire-format v3 (breaking)

v3 намеренно несовместим с v1/v2. После обновления старое состояние храповика игнорируется (клиент начинает новую сессию), пакеты v2 отклоняются с `UnsupportedVersion`, а старые файловые блоки не расшифровываются. Обе стороны должны обновиться вместе; пути downgrade нет. Изменение удаляет неаутентифицированный legacy-путь расшифровки, скрывает счётчики храповика и `dh_pub`, заменяет открытый `session_id` на alias и привязывает метаданные файлов к AEAD.

### Что видят серверы

Текстовый сервер видит хеш получателя в URL, bucket паддинга, тайминг и маскирующие заголовки. Он больше не видит `dh_pub`, счётчики храповика, границы эпох или сырой `session_id`. Он также не может перечислить комнаты пользователя: pull адресуется только по identity hash, а alias комнаты едет внутри пакета v3. Alias стабилен в пределах сессии, поэтому группировка пакетов по alias остаётся возможной (см. заметки M-8 выше). Файловый сервер видит bucket размера зашифрованного блока и его хеш, но не имя и не реальный размер файла. Содержимое сообщений и файлов остаётся зашифрованным сквозным образом.

## Локальное хранилище

При первом запуске клиент просит мастер-пароль (минимум 8 символов). Пароль нигде не сохраняется.

- Случайная 32-байтная соль пишется в `vault.salt`.
- Мастер-ключ выводится через Argon2id (19 МиБ, 2 прохода, 1 поток) и хранится в памяти внутри `Zeroizing`.
- `vault.check` — зашифрованный маркер для проверки пароля.
- `identity.json` и `global.conf` целиком шифруются как `LCVAULT1 || nonce || ciphertext || tag` с XChaCha20-Poly1305 и associated data.
- Контакты, комнаты, сообщения, файловые записи и обычные сессии Double Ratchet живут в SQLite исключительно в оперативной памяти; на диск никогда не пишутся `user.db`, `user.db-wal` или `user.db-shm`.
- При каждом изменении вся база сериализуется, дополняется случайным паддингом по bucket-сетке (4 КиБ … 512 МиБ) с джиттером внутри bucket и шифруется XChaCha20-Poly1305 в `vault.dat` как `nonce || ciphertext || tag`; магические байты и открытые заголовки на диск не попадают. Версия схемы и длина полезной нагрузки хранятся внутри зашифрованного блока, поэтому точное число сообщений не видно — наблюдатель различает только bucket.
- mtime `vault.dat` не обновляется на каждую запись: значение переставляется раз в 5–15 минут и сдвигается на случайные 1 секунду … 6 часов назад. Это mitigation, а не устранение: границы bucket’ов, факт существования файла и долговременный рост всё равно утекают.
- Комнаты с активным `/ttl` или `/ttl-syn` держат состояние храповика строго в RAM: оно не попадает в `vault.dat` и затирается при отключении TTL или выходе из клиента. Исчезающие сообщения и файловые записи TTL-комнат тоже не перезаписывают `vault.dat` (H-3), поэтому TTL-активность не меняет его размер и mtime.
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

### Права доступа

На Unix клиент не полагается на umask процесса:

- Каталоги профиля (корень vault, подкаталоги, staging миграции) создаются с режимом `0700`.
- Файлы с данными (`vault.dat`, `vault.salt`, `vault.check`, `identity.json`, `global.conf`, скачанные файлы) создаются с режимом `0600`.
- Режим запрашивается уже при создании, а затем проверяется. Если umask (или ранее существовавший каталог) дал более широкие или более узкие биты, клиент явно выставляет `chmod`. Если итоговый режим выставить не удалось, операция завершается ошибкой (fail-closed), а не продолжается с ослабленными правами. Глобальный umask процесса не меняется.
- Данные пишутся в приватный временный файл в каталоге назначения и атомарно переименовываются только при успехе. При ошибке временный файл удаляется, целевой путь не изменяется.
- Миграция старого профиля создаёт и укрепляет целевую структуру по ходу копирования, поэтому исходные права вроде `0755`/`0644` не наследуются. При сбое staging-каталог удаляется.
- При удалении базы вместе с основным файлом удаляются SQLite-сателлиты `-journal`, `-wal` и `-shm`; отсутствие сателлита допустимо, остальные ошибки сообщаются.

На не-Unix платформах POSIX-права недоступны: клиент использует read-only заглушку там, где это применимо, и не выдаёт файлы за приватные молча.

### Обработка секретов в памяти

- Seed-фраза, приватные ключи X25519/Ed25519, корневые и цепные ключи храповика и ключи сообщений хранятся в `SecretBytes`/`SecretString` или в `Zeroizing`. При освобождении они затираются через `zeroize` (volatile-запись и compiler fence), поэтому оптимизатор не может вырезать затирание.
- `SecretBytes`/`SecretString` намеренно не реализуют `Clone`: копия возможна только явным, аудируемым вызовом `duplicate()`. `Debug` печатает `<secret>`, а обёртки фиксированной длины (`Ed25519Seed`, `X25519Priv`, `RootKey`) — `<redacted>`, поэтому секреты не попадают в логи и panic-сообщения.
- У `Identity` ручной `Debug`: выводятся только публичные ключи, identity hash и время. `Identity::clone()` — единственное проверяемое место дублирования секретов личности (используется кэшем менеджера).
- `RatchetState::to_bytes()` возвращает `SecretBytes`, а `from_bytes()` принимает владение секретным буфером. Состояние, загруженное из `vault.dat`, сразу оборачивается в `SecretBytes`, а промежуточные JSON/hex-буферы затираются и на путях ошибки.
- Listener получает приватный ключ личности как `Arc<SecretBytes>` и не держит голую копию `Vec<u8>`; буфер затирается при drop последнего `Arc`.
- Seed-фраза BIP-39 и мастер-пароль читаются с отключённым эхом терминала. Seed-фраза не отображается (даже её длина), вводится дважды, а буфер ввода затирается при drop; пароль в TTY маскируется `*`.
- `RatchetState::with_root_key()` отдаёт текущий корневой ключ только внутри замыкания, а не копией наружу.
- `mlock`/`VirtualLock` намеренно не используется (чтобы не добавлять платформенную зависимость): секреты всё ещё могут попасть в swap и core dump. Если эта угроза входит в модель, используйте шифрованный swap или усиленное окружение. Отключение core dump через `prctl(PR_SET_DUMPABLE, 0)` в этот блок тоже не входит.
- Тест `tests/secret_hygiene.rs` падает, если в `src/` снова появятся `private_key.clone()`, `seed_phrase.clone()`, `current_root_key` или похожие копии секретов.

## Транспорт

### Текстовый API

- Отправка: `POST /push/<target_hash>` с `application/octet-stream`.
- Приём: `GET /pull/<identity_hash>?wait=25`.
- Сервер держит пустой long-poll до 25 секунд; таймаут клиента — 45 секунд.
- `204 No Content` означает пустую очередь.
- Успешный ответ приходит как `multipart/form-data`; клиент разбирает части и проверяет, что размеры пакетов входят в допустимую сетку.
- `429` — rate limit. Повторы pull идут с задержками 1с → 2с → 5с → 15с; `401` и ошибки протокола повторяются медленно, чтобы не крутить busy-loop.
- Push подписывается тем же каноническим конвертом, что и pull: `X-Auth-Identity`, `X-Auth-Timestamp`, `X-Auth-Nonce`, `X-Auth-Signature`, а `body_hash = SHA256(packet)` входит в подпись. Каждый повтор получает свежий nonce и свежий timestamp; nonce не переиспользуется.
- `401` от `/push` не повторяется (сервер отклонит ту же identity/подпись снова). `429`, `503` и транспортные ошибки повторяются с экспоненциальной задержкой 1с → 2с → 4с, максимум 4 попытки.
- Клиент применяет локальный token bucket `PUSH_REQUESTS_PER_SECOND = 8` на контакт до подписи, поэтому баг или вредоносное действие UI не превращает клиент в источник push-флуда; исчерпание лимита — локальная ошибка, а не ответ сервера.

### Файловый API

- Загрузка: `POST /upload` с `application/octet-stream` и `Content-Length`; тело ответа — хеш файла. Имя файла не передаётся заголовком (оно внутри AEAD-конверта v3).
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

`--to` принимает имя контакта из локальной базы, identity_hash или полную ссылку `lastchance://contact?...`. `--send -` читает сообщение из stdin, чтобы текст не светился в `ps aux`. Headless-режим завершается с кодом `0` при успехе и `1` при ошибке.

Мастер-пароль берётся из следующих источников (по приоритету):

1. `LASTCHANCE_PASS_FILE=/path/to/password` — читается из приватного файла. На Unix клиент отвергает файл с любыми битами group/other (`0600` или строже), отбрасывает завершающие переводы строк и никогда не печатает содержимое. Сам путь секретом не является.
2. `LASTCHANCE_PASS=secret` — оставлен для совместимости. Значение находится в окружении процесса: тот же UID (и root) может прочитать его через `/proc/<pid>/environ`; оно также может попасть в историю shell, список процессов, core dump или логи супервизора. Используйте его только когда клиент работает в отдельном UID, контейнере или VM. При общем UID предпочтительны `LASTCHANCE_PASS_FILE` или systemd credentials (`LoadCredentialEncrypted=` и `LASTCHANCE_PASS_FILE=$CREDENTIALS_DIRECTORY/lastchance-pass`).
3. Если не задана ни одна переменная, в интерактивном TTY запрашивается скрытый ввод.

Если заданы обе переменные, побеждает `LASTCHANCE_PASS_FILE`; `LASTCHANCE_PASS` игнорируется с предупреждением. Ни одно предупреждение не содержит значения пароля, и значение никогда не логируется.

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

- Общий секрет статический для каждого контакта и инициализирует каждую сессию Double Ratchet. Свежий `bootstrap_nonce` и эфемерные DH-эпохи не дают переиспользовать ключи между сессиями и воспроизводить старые пакеты в новую сессию. Однако bootstrap-ключи по-прежнему выводятся из долговременного общего секрета: перехвативший первый пакет сессии и позже получивший этот секрет сможет восстановить её bootstrap-root. Post-compromise security отсутствует; настоящая forward secrecy на первом сообщении требует интерактивного prekey/ответного хендшейка. Для обычных комнат уничтоженные `session_id` пишутся в `vault.dat`, поэтому replay сброшенной сессии блокируется и после перезапуска. Для RAM-TTL комнат список уничтоженных `session_id` живёт только в RAM (в пределах жизни процесса), поэтому после перезапуска клиента повторно поданный первый пакет неотличим от первого контакта (та же граница TOFU, что и у самой первой сессии). Реестр `dh_pub` ограничен 128 ключами на сессию: за этим горизонтом древний ключ снова выглядит новым, но его локальный DH-приватный ключ уже покинул окно отправки в 5 эпох, поэтому расшифровать пакет всё равно не получится. В старом заголовке v2 не было счётчика эпох, поэтому подлинный впервые увиденный `dh_pub` старой эпохи мог приниматься как новая эпоха и сдвигать `remote_pub` на этот подлинный ключ. В v3 аутентифицированный `epoch_id` едет внутри AEAD, а устаревшие эпохи отсекаются до любого согласования ключей, поэтому этот ограниченный отказ в продвижении больше не применим; пакеты v1/v2 отклоняются целиком.
- Сервер по-прежнему узнаёт хеш получателя, тайминг, класс размера пакета и размер файлового блока. Alias в пределах сессии позволяет группировать пакеты одной ratchet-сессии, но не идентифицировать контакт или `session_id`. Если это важно, используйте Tor/I2P и собственные серверы.
- Адресация по alias не оставляет долговременного следа на сервере сверх факта доставки: таблица alias живёт только в RAM, пересобирается из `vault.dat` при старте, а retired-alias забываются при удалении контакта. Ключи дедупликации хранятся 300 секунд (максимум 8192) и не персистятся.
- Локальные метаданные (хеши контактов, публичные ключи, время) не шифруются; тела сообщений, ники и имена файлов — шифруются.
- Seed-фраза — это идентичность. Тот, кто её получил, может выдать себя за вас и читать ваши чаты. Мастер-пароль защищает только локальные данные; восстановления пароля нет.
- `LASTCHANCE_PASS` виден любому процессу, который может прочитать окружение клиента (`/proc/<pid>/environ` для того же UID и для root). Предпочитайте `LASTCHANCE_PASS_FILE` с режимом `0600` или systemd credentials; используйте переменную окружения только в отдельном UID, контейнере или VM.
- Код не проходил аудит. Протокол и формат хранилища могут меняться.
- Если используются HTTPS-адреса, TLS обеспечивается настройками `reqwest` по умолчанию; certificate pinning не реализован.

Сообщения об уязвимостях, фаззинг, ревью протокола и улучшения интерфейса приветствуются.
