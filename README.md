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
| `src/storage/` | Safe filesystem operations and SQLite persistence |
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
                ├──> Storage (SQLite, encrypted fields)
                ├──> Vault (master key, Argon2id)
                └──> Listener <── long-poll <── text API server

files: App ──> encrypt with the room secret ──> file API server
       App <── download by hash ── decrypt with the room secret
```

`src/lib.rs` exposes `App`, `Config`, `Vault` and storage helpers. `src/main.rs` is only the terminal client. The core has no TUI dependencies.

---

## Cryptography and packets

### Identity

- A 32-byte random seed is encoded as a BIP-39 mnemonic (`/seed`).
- Two key pairs are derived from the seed with HKDF-SHA256:
  - X25519 (`X25519_E2EE_Key_v1`) for message/file encryption;
  - Ed25519 (`Ed25519_Auth_Key_v1`) for authentication.
- The public identity hash is `SHA256(Ed25519 public key)`, hex-encoded.
- A contact invite contains `hash`, `x25519`, `ed25519` and `nickname`:

```text
lastchance://contact?hash=...&x25519=...&ed25519=...&nickname=...
```

- `/pull` requests are signed with Ed25519 over `timestamp + identity_hash`; the server receives the public key in `X-Identity-Key`, the timestamp in `X-Timestamp` and the signature in `X-Signature`.

### Message encryption

- Each contact has a static shared secret: `X25519(my_private, their_public)` followed by HKDF-SHA256 with the `ECDH_v1` label.
- Messages are encrypted with XChaCha20-Poly1305 using a fresh 24-byte nonce.
- The plaintext frame is `magic (0x4E53) || session_id (u64) || payload_len (u32) || payload`.
- The whole frame is padded with random bytes to one of four total packet sizes:

```text
256 B   1024 B   4096 B   65536 B
```

- The final packet is `nonce || ciphertext || tag`; only those four exact sizes are accepted.

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
- Sensitive SQLite fields (message text, nicknames, room names, file names and file sizes) are encrypted individually as `lc1:<hex>`.
- Legacy plaintext files and database fields are migrated to encrypted form on load.
- `PRAGMA secure_delete=ON` and a WAL checkpoint are used for the database.
- Files created by the client are written with mode `0600` on Unix; a read-only fallback is used where POSIX permissions are unavailable.

`/passwd` verifies the old password, re-encrypts `identity.json`, `global.conf` and all sensitive database fields, replaces the in-memory key and only then writes the new salt/check files. If a step fails, the client tries to roll the old key back.

Contact hashes, public keys, room hashes, message direction/status and timestamps remain plaintext metadata inside the local database; they are needed for lookups and ordering.

The data directory is chosen in this order:

1. `--data-dir <path>` or `--data-dir=<path>`.
2. The `LASTCHANCE_DIR` environment variable.
3. Portable mode: if a `.portable` file exists next to the executable, use `data/` beside it.
4. Default: `$XDG_DATA_HOME/lastchance` (or `~/.local/share/lastchance`) on Unix-like systems, `%LOCALAPPDATA%\lastchance` on Windows.

The directory contains `identity.json`, `global.conf`, `user.db`, `vault.salt` and `vault.check`.

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
| `/contacts`, `/ls`, `/c` | List contacts |
| `/join`, `/jn <link>` | Add a contact from a `lastchance://contact?...` link and open the chat |
| `/join <hash> <x25519> <nickname>` | Add a contact manually |
| `/join -f <path>` | Add a contact from an invite file |
| `/room`, `/r [hash \| nick]` | Show or switch the active room |
| `/sidebar`, `/sb` | Hide or show the chat sidebar |

### Messages and files

| Command | Description |
| --- | --- |
| `/messages [limit]` | Show recent messages of the active room (default 50) |
| `/sendfile`, `/sf [--force] <path>` | Encrypt and upload a file |
| `/download`, `/dl [id \| name \| hash] [path]` | Download a file from the active room |
| `/set`, `/settings` | Open the interactive settings window |
| `/set notify <0\|1\|2\|3>` | Set the notification level directly |
| `/set test` | Show a test notification |
| `/passwd` | Change the master password and re-encrypt local data |

### Profile

| Command | Description |
| --- | --- |
| `/profile`, `/p` | Show nickname, hash and public keys as JSON |
| `/seed` | Show the BIP-39 seed phrase (keep it secret) |
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

Controls: `Up`/`Down` or `Tab`/`Shift+Tab` select a field, `Enter` edits it, `Esc` cancels editing. In the editing prompt, `Enter` applies and `Esc` cancels. On the `Notify Level` row, `Left`/`Right` or `Space` cycles the value. `Esc` outside editing saves and closes the window.

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
lastchance --data-dir /path/to/profile
lastchance --data-dir=/path/to/profile
LASTCHANCE_DIR=/path/to/profile lastchance
```

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

- The shared secret is static per contact. There is no Double Ratchet, no per-message forward secrecy and no post-compromise security. If a long-term private key leaks, previously captured traffic for that contact can be decrypted.
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
| `src/storage/` | Безопасная работа с ФС и хранение в SQLite |
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
                  ├──> Storage (SQLite, зашифрованные поля)
                  ├──> Vault (мастер-ключ, Argon2id)
                  └──> Listener <── long-poll <── текстовый API-сервер

файлы: App ──> шифрование ключом комнаты ──> файловый API-сервер
       App <── скачивание по хешу ── расшифровка ключом комнаты
```

`src/lib.rs` экспортирует `App`, `Config`, `Vault` и помощники хранилища. `src/main.rs` — только терминальный клиент; ядро не зависит от TUI.

## Криптография и пакеты

### Идентичность

- 32 случайных байта кодируются в BIP-39 мнемонику (`/seed`).
- Из seed через HKDF-SHA256 выводятся две пары ключей:
  - X25519 (`X25519_E2EE_Key_v1`) — для шифрования сообщений и файлов;
  - Ed25519 (`Ed25519_Auth_Key_v1`) — для аутентификации.
- Публичный хеш идентичности — `SHA256(Ed25519 public key)` в hex.
- Инвайт-ссылка содержит `hash`, `x25519`, `ed25519` и `nickname`:

```text
lastchance://contact?hash=...&x25519=...&ed25519=...&nickname=...
```

- Запросы `/pull` подписываются Ed25519 над строкой `timestamp + identity_hash`. Сервер получает публичный ключ в `X-Identity-Key`, время в `X-Timestamp`, подпись в `X-Signature`.

### Шифрование сообщений

- Для каждого контакта вычисляется статический общий секрет: `X25519(мой_private, его_public)`, затем HKDF-SHA256 с меткой `ECDH_v1`.
- Сообщения шифруются XChaCha20-Poly1305 со свежим 24-байтным nonce.
- Открытый кадр: `magic (0x4E53) || session_id (u64) || payload_len (u32) || payload`.
- Кадр добивается случайными байтами до одного из четырёх размеров:

```text
256 Б   1024 Б   4096 Б   65536 Б
```

- Итоговый пакет — `nonce || ciphertext || tag`; принимаются только эти четыре точных размера.

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
- Чувствительные поля SQLite (текст сообщений, ники, имена комнат, имена и размеры файлов) шифруются по значению в формате `lc1:<hex>`.
- Старые открытые файлы и поля базы мигрируют в зашифрованный вид при загрузке.
- Для базы включены `PRAGMA secure_delete=ON` и checkpoint WAL.
- Созданные клиентом файлы получают права `0600` на Unix; там, где POSIX-права недоступны, используется read-only заглушка.

`/passwd` проверяет старый пароль, перешифровывает `identity.json`, `global.conf` и все чувствительные поля базы, заменяет ключ в памяти и только затем пишет новую соль и check-файл. При сбое клиент пытается откатиться на старый ключ.

Хеши контактов, публичные ключи, хеши комнат, направление/статус сообщений и время остаются открытыми метаданными локальной базы — они нужны для поиска и сортировки.

Порядок выбора каталога данных:

1. `--data-dir <path>` или `--data-dir=<path>`.
2. Переменная окружения `LASTCHANCE_DIR`.
3. Переносимый режим: если рядом с бинарником есть файл `.portable`, используется `data/` рядом с ним.
4. По умолчанию: `$XDG_DATA_HOME/lastchance` (или `~/.local/share/lastchance`) на Unix-подобных системах, `%LOCALAPPDATA%\lastchance` на Windows.

В каталоге лежат `identity.json`, `global.conf`, `user.db`, `vault.salt` и `vault.check`.

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
| `/contacts`, `/ls`, `/c` | Список контактов |
| `/join`, `/jn <link>` | Добавить контакт по ссылке `lastchance://contact?...` и открыть чат |
| `/join <hash> <x25519> <nickname>` | Добавить контакт вручную |
| `/join -f <path>` | Добавить контакт из файла-инвайта |
| `/room`, `/r [hash \| nick]` | Показать или сменить активную комнату |
| `/sidebar`, `/sb` | Скрыть или показать панель чатов |

### Сообщения и файлы

| Команда | Описание |
| --- | --- |
| `/messages [limit]` | Последние сообщения активной комнаты (по умолчанию 50) |
| `/sendfile`, `/sf [--force] <path>` | Зашифровать и загрузить файл |
| `/download`, `/dl [id \| name \| hash] [path]` | Скачать файл активной комнаты |
| `/set`, `/settings` | Открыть интерактивные настройки |
| `/set notify <0\|1\|2\|3>` | Задать режим уведомлений напрямую |
| `/set test` | Показать тестовое уведомление |
| `/passwd` | Сменить мастер-пароль и перешифровать локальные данные |

### Профиль

| Команда | Описание |
| --- | --- |
| `/profile`, `/p` | Ник, хеш и публичные ключи в JSON |
| `/seed` | Показать BIP-39 seed-фразу (никому не показывайте) |
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

В окне настроек девять полей:

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

Управление: `Up`/`Down` или `Tab`/`Shift+Tab` — выбор поля, `Enter` — редактировать, `Esc` — отменить редактирование. В режиме ввода `Enter` применяет значение, `Esc` отменяет. На строке `Notify Level` клавиши `Left`/`Right` или `Space` переключают значение. `Esc` вне редактирования сохраняет и закрывает окно.

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
lastchance --data-dir /path/to/profile
lastchance --data-dir=/path/to/profile
LASTCHANCE_DIR=/path/to/profile lastchance
```

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

- Общий секрет статический для каждого контакта. Здесь нет Double Ratchet, посуточной forward secrecy и post-compromise security. При утечке долговременного приватного ключа ранее перехваченный трафик этого контакта можно расшифровать.
- Сервер по-прежнему узнаёт хеш получателя, тайминг, класс размера пакета и размер файлового блока. Если это важно, используйте Tor/I2P и собственные серверы.
- Локальные метаданные (хеши контактов, публичные ключи, время) не шифруются; тела сообщений, ники и имена файлов — шифруются.
- Seed-фраза — это идентичность. Тот, кто её получил, может выдать себя за вас и читать ваши чаты. Мастер-пароль защищает только локальные данные; восстановления пароля нет.
- Код не проходил аудит. Протокол и формат хранилища могут меняться.
- Если используются HTTPS-адреса, TLS обеспечивается настройками `reqwest` по умолчанию; certificate pinning не реализован.

Сообщения об уязвимостях, фаззинг, ревью протокола и улучшения интерфейса приветствуются.
