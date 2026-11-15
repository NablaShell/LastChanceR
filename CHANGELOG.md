# Changelog

All notable changes to LastChance are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-15

First release with the hardened wire format and authenticated network API.

### Added

- Double Ratchet v2: per-epoch ephemeral DH keys, bounded skipped-key handling,
  session reset, and a persistent list of retired session ids.
- Wire format v3: a versioned open header bound to the payload through AEAD AAD
  (`version`, `flags`, `session_alias`, optional `bootstrap_nonce`, `nonce`) plus
  an encrypted header carrying the authenticated `epoch_id`.
- File envelopes v3: file id, room id and canonical sender/recipient pair are
  authenticated as AAD, so blobs cannot be moved between rooms, pairs or ids.
- Incoming routing by room aliases without scanning every contact (M-8).
- Canonical request signing and nonce replay protection for the network API (H-4);
  `/push` requests carry a signed canonical envelope.
- Signed identity invites (Ed25519 over deterministic CBOR) and BIP-39 recovery.
- Encrypted local vault: Argon2id-derived master key, XChaCha20-Poly1305,
  block-aligned padded payloads and atomic private-file writes.
- English/Russian interface, headless send mode, ephemeral message TTL,
  long-polling and SOCKS5/HTTP proxy support.
- TTL rooms persist only an encrypted tombstone tuple (`session_alias`,
  `SHA256(session_id)`, `retired_at`) so a retired bootstrap packet is rejected
  as stale after a restart, without storing ratchet state (M-C). Tombstones
  expire after 30 days and are capped at 1024 entries.
- `SecretBytes` wrapper with zeroization and a hygiene test that forbids leaking
  secret copies in production code.

### Changed

- Incoming packets are addressed by a stable per-session alias; the server no
  longer needs a contact scan to find the recipient.
- Files are referenced by hash only; plaintext file names never leave the client.
- Response bodies and multipart parsing are bounded (M-2).
- Identifier parsing is validated at the boundary and byte slicing is
  char-safe (M-1).
- A two-way `/ttl-syn` whose `SetTtl` packet cannot be delivered stays active
  locally but is shown as unconfirmed, and `/ttl-syn-retry` resends it (L-8).

### Security

- v1 and v2 packets are rejected fail-closed; legacy decrypt paths and plaintext
  file names are removed.
- Duplicate `(alias, nonce)` detection and retired-alias checks happen before
  AEAD and ratchet progression.
- Unknown-bootstrap floods are CPU-bounded (L-1): duplicate delivery is checked
  before room resolution, successful `alias -> room` resolutions are cached, and
  HKDF contact scans run under a token bucket.
- Garbage v3 packets cannot force unbounded ratchet work (L-2): session aliases
  (including retired ones) are cached instead of re-derived per packet, the last
  accepted epoch is tried first, header lookahead and retired-epoch candidates
  are capped, and one shared AEAD-attempt budget covers header and payload.
- File API requests (`/upload`, `/download`) carry the same canonical signature
  and nonce as `/push`/`/pull`, and the download body limit is aligned with
  `FILE_MAX_ENVELOPE` (128 MiB) instead of 256 MiB (L-6). The external file
  server must reject requests without auth headers with `401`, and oversized
  bodies with `413` before reading them; this contract is documented in the
  README.
- Invalid signatures do not pollute the nonce cache.

### Breaking

- The on-the-wire format is v3. Clients running 0.4.x or older cannot exchange
  messages with 1.0.0.

## [0.4.0] - 2026-11-13

- HTTP long-polling transport.
- SOCKS5/HTTP proxy support, including `socks5h://` with remote DNS (Tor/I2P).
- Interactive `/set` modal and stealth notifications.

## [0.3.0] - 2026-11-13

- Encrypted local vault with automatic migration from the plaintext database.
- `/set` configuration wizard.
- Cross-platform release builds for Linux, Windows and macOS.

## [0.2.0] - 2026-11-13

- Smart file downloads, tab completion and path-traversal protection.
