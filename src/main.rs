// Полноэкранный TUI-клиент LastChance.
//
// Архитектура:
//   - tokio Runtime живёт весь процесс (ядро: Listener, Sender, события).
//   - crossterm::event::EventStream и канал AppEvent слушаются в одном
//     `tokio::select!`, поэтому интерфейс остаётся отзывчивым.
//   - Вся отрисовка — ratatui: история чата, статус-бар и поле ввода.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossterm::cursor::Show;
use crossterm::event::{
    DisableFocusChange, DisableMouseCapture, EnableFocusChange, EnableMouseCapture, Event,
    EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use lastchance::network::config::notify_level_label;
use lastchance::{get_base_dir_with_override, vault, App, AppEvent, Config, Vault};

const HELP: &str = "\
Команды (алиасы):
  /help, /h, /?               — этот список
  /profile, /p                — профиль (nickname, hash, ключи)
  /seed                       — seed-фраза (никому не показывайте!)
  /invite, /in [ -f [dir|file] ]
                              — скопировать ссылку в буфер обмена;
                                с -f — также сохранить в файл инвайта
  /export                     — контакт в формате JSON
  /contacts, /ls, /c          — список контактов
  /join, /jn <link | hash x25519 nickname>
                              — добавить контакт и открыть чат
  /join, /jn -f <path>        — добавить контакт из файла-инвайта
  /room, /r [hash|nick]       — показать или сменить активную комнату
  /messages [limit]           — последние сообщения комнаты
  /sendfile, /sf [--force] <path>
                              — отправить файл; путь ищется от текущей
                                директории, поддерживает ~/ и абсолютные
                                пути; системные папки — только с --force
  /download, /dl [id|name|hash] [path]
                              — скачать файл: без аргументов — последний
                                файл комнаты; id — номер из ленты (#3);
                                path — файл или папка, иначе ./downloads/<name>
  /nick <name>                — сменить свой ник
  /rename <hash> <name>       — переименовать контакт
  /set, /settings             — интерактивное меню настроек: Text API, File API,
                                Guard Header Name/Value, Proxy URL, Notify Level,
                                Stealth Title/Body/Seconds. Стрелки/Tab — выбор,
                                Enter — редактировать поле, Esc — сохранить
  /set notify <0|1|2|3>       — быстро задать режим уведомлений:
                                0 — выкл., 1 — stealth, 2 — отправитель,
                                3 — полный предпросмотр
  /set test                   — показать тестовое системное уведомление
  /passwd                     — сменить мастер-пароль (файлы и база
                                перешифровываются)
  /sidebar, /sb               — скрыть/показать панель чатов
  /quit, /q, /exit            — выход

Любая строка без ведущего / отправляется в активную комнату.
Alt+Up/Alt+Down или Ctrl+P/Ctrl+N — переключение чатов.
Tab — автодополнение команд и контактов (для /room).
Tab после /dl — перебор файлов активной комнаты.
Tab после /sf — автодополнение путей от текущей директории.
Up/Down — история ввода (последние 50 строк).
PgUp/PgDn или колесо мыши — прокрутка истории.
Ctrl+V — вставка из системного буфера обмена.";

// ============================================================
// МОДЕЛЬ ИНТЕРФЕЙСА
// ============================================================

#[derive(Clone, Copy)]
enum FeedKind {
    Incoming,
    Outgoing,
    System,
    Error,
}

struct FeedEntry {
    kind: FeedKind,
    text: String,
}

/// Элемент боковой панели: контакт или активная комната.
struct ChatEntry {
    hash: String,
    label: String,
}

/// Метаданные файла, полученного (или отправленного) в текущей сессии.
#[derive(Clone, Debug)]
struct FileEntry {
    /// Короткий порядковый номер для `/dl <id>`.
    id: usize,
    room_hash: String,
    file_hash: String,
    file_name: String,
    /// Время сообщения о файле (unix timestamp) — чтобы выбрать последний.
    timestamp: i64,
}

/// Состояние циклического автодополнения аргумента по Tab (`/dl`, `/sf`).
struct CompletionCycle {
    /// Начало дополняемого слова во вводе.
    start: usize,
    /// Индекс текущего кандидата.
    index: usize,
    /// Токены для подстановки (`#1`, `#2`, ... или пути).
    candidates: Vec<String>,
    /// Человекочитаемые подписи для статус-бара.
    labels: Vec<String>,
    /// Токен, который сейчас вставлен в поле ввода.
    last_insert: String,
}

/// Команды, доступные для автодополнения по Tab (канонические имена).
const COMMANDS: &[&str] = &[
    "/help",
    "/profile",
    "/seed",
    "/invite",
    "/export",
    "/contacts",
    "/join",
    "/room",
    "/messages",
    "/sendfile",
    "/download",
    "/nick",
    "/rename",
    "/set",
    "/passwd",
    "/sidebar",
    "/quit",
    "/exit",
];

struct UiState {
    feed: Vec<FeedEntry>,
    input: String,
    cursor: usize,
    scroll: usize,
    follow: bool,
    status: String,
    room: String,
    room_label: String,
    nickname: String,
    view_width: usize,
    view_height: usize,
    /// Список чатов для боковой панели.
    chats: Vec<ChatEntry>,
    /// Непрочитанные сообщения по hash комнаты.
    unread: HashMap<String, usize>,
    sidebar_visible: bool,
    /// История последних отправленных строк (максимум 50).
    history: VecDeque<String>,
    /// Позиция в истории; `None` — редактируется новая строка.
    history_index: Option<usize>,
    /// Черновик, сохранённый при входе в историю.
    history_draft: String,
    /// Файлы, встреченные в этой сессии (для умного `/dl`).
    files: Vec<FileEntry>,
    /// Следующий порядковый номер файла.
    next_file_id: usize,
    /// Циклическое дополнение `/dl` по Tab.
    dl_cycle: Option<CompletionCycle>,
    /// Циклическое дополнение путей `/sf` по Tab.
    sf_cycle: Option<CompletionCycle>,
    /// Долгоживущий объект буфера обмена: на X11 он остаётся владельцем
    /// selection, пока жив процесс, поэтому вставка в других окнах работает.
    clipboard: Option<arboard::Clipboard>,
    /// Требуется очистка экрана перед следующей перерисовкой (после вывода
    /// диагностики библиотек в stderr, чтобы ratatui не «поехал»).
    needs_clear: bool,
    /// Терминал сейчас в фокусе (события FocusGained/FocusLost).
    is_terminal_focused: bool,
    /// Активный диалог смены мастер-пароля.
    passwd: Option<PasswdFlow>,
    /// Активное меню настроек.
    settings: Option<SettingsFlow>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PasswdStage {
    Current,
    New,
    Confirm,
}

/// Пошаговый ввод паролей для `/passwd`.
/// Пароли хранятся в `Zeroizing`, чтобы затираться при отмене/завершении.
struct PasswdFlow {
    stage: PasswdStage,
    old: Zeroizing<String>,
    new: Zeroizing<String>,
}

impl PasswdFlow {
    fn new() -> Self {
        Self {
            stage: PasswdStage::Current,
            old: Zeroizing::new(String::new()),
            new: Zeroizing::new(String::new()),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingField {
    ServerUrl,
    FileServerUrl,
    HeaderName,
    HeaderValue,
    ProxyUrl,
    NotifyLevel,
    StealthTitle,
    StealthBody,
    StealthSeconds,
}

const SETTINGS_FIELDS: [SettingField; 9] = [
    SettingField::ServerUrl,
    SettingField::FileServerUrl,
    SettingField::HeaderName,
    SettingField::HeaderValue,
    SettingField::ProxyUrl,
    SettingField::NotifyLevel,
    SettingField::StealthTitle,
    SettingField::StealthBody,
    SettingField::StealthSeconds,
];

impl SettingField {
    fn label(self) -> &'static str {
        match self {
            SettingField::ServerUrl => "Text API",
            SettingField::FileServerUrl => "File API",
            SettingField::HeaderName => "Guard Header Name",
            SettingField::HeaderValue => "Guard Header Value",
            SettingField::ProxyUrl => "Proxy URL",
            SettingField::NotifyLevel => "Notify Level",
            SettingField::StealthTitle => "Stealth Title",
            SettingField::StealthBody => "Stealth Body",
            SettingField::StealthSeconds => "Stealth Seconds",
        }
    }

    fn is_notify_level(self) -> bool {
        matches!(self, SettingField::NotifyLevel)
    }

    fn is_masked(self) -> bool {
        matches!(self, SettingField::HeaderValue)
    }
}

/// Модальное окно настроек `/set`.
/// Значение защитного заголовка не показывается на экране.
struct SettingsFlow {
    selected: usize,
    editing: bool,
    server_url: String,
    file_server_url: String,
    header_name: String,
    header_value: Zeroizing<String>,
    /// Пустая строка означает «прокси не используется».
    proxy_url: String,
    notify_level: u8,
    stealth_title: String,
    stealth_body: String,
    stealth_seconds: String,
}

impl SettingsFlow {
    fn from_config(config: &Config) -> Self {
        Self {
            selected: 0,
            editing: false,
            server_url: config.server_url.clone(),
            file_server_url: config.file_server_url.clone(),
            header_name: config.mask_header_name.clone(),
            header_value: Zeroizing::new(config.mask_header_value.clone()),
            proxy_url: config.proxy_url.clone().unwrap_or_default(),
            notify_level: config.notify_level,
            stealth_title: config.stealth_title.clone(),
            stealth_body: config.stealth_body.clone(),
            stealth_seconds: config.stealth_seconds.clone(),
        }
    }

    fn field(&self) -> SettingField {
        SETTINGS_FIELDS[self.selected.min(SETTINGS_FIELDS.len() - 1)]
    }

    fn move_selection(&mut self, delta: isize) {
        let len = SETTINGS_FIELDS.len() as isize;
        self.selected = (self.selected as isize + delta).rem_euclid(len) as usize;
    }

    fn cycle_notify(&mut self, delta: isize) {
        self.notify_level = (self.notify_level as isize + delta).rem_euclid(4) as u8;
    }

    fn edit_value(&self, field: SettingField) -> String {
        match field {
            SettingField::ServerUrl => self.server_url.clone(),
            SettingField::FileServerUrl => self.file_server_url.clone(),
            SettingField::HeaderName => self.header_name.clone(),
            SettingField::HeaderValue => self.header_value.to_string(),
            SettingField::ProxyUrl => self.proxy_url.clone(),
            SettingField::NotifyLevel => self.notify_level.to_string(),
            SettingField::StealthTitle => self.stealth_title.clone(),
            SettingField::StealthBody => self.stealth_body.clone(),
            SettingField::StealthSeconds => self.stealth_seconds.clone(),
        }
    }

    fn apply_edit(&mut self, field: SettingField, raw: &str) {
        let value = raw.trim();
        match field {
            SettingField::ServerUrl if !value.is_empty() => {
                self.server_url = value.to_string();
            }
            SettingField::FileServerUrl if !value.is_empty() => {
                self.file_server_url = value.to_string();
            }
            SettingField::HeaderName if !value.is_empty() => {
                self.header_name = value.to_string();
            }
            SettingField::HeaderValue if !value.is_empty() => {
                self.header_value = Zeroizing::new(value.to_string());
            }
            SettingField::ProxyUrl => {
                self.proxy_url = if value == "-" || value.eq_ignore_ascii_case("none") {
                    String::new()
                } else {
                    value.to_string()
                };
            }
            SettingField::StealthTitle if !value.is_empty() => {
                self.stealth_title = value.to_string();
            }
            SettingField::StealthBody if !value.is_empty() => {
                self.stealth_body = value.to_string();
            }
            SettingField::StealthSeconds if !value.is_empty() => {
                self.stealth_seconds = value.to_string();
            }
            _ => {}
        }
    }

    fn display_value(&self, field: SettingField) -> String {
        match field {
            SettingField::ServerUrl => self.server_url.clone(),
            SettingField::FileServerUrl => self.file_server_url.clone(),
            SettingField::HeaderName => self.header_name.clone(),
            SettingField::HeaderValue => "********".to_string(),
            SettingField::ProxyUrl => {
                if self.proxy_url.trim().is_empty() {
                    "— (прямое подключение)".to_string()
                } else {
                    self.proxy_url.clone()
                }
            }
            SettingField::NotifyLevel => notify_level_label(self.notify_level).to_string(),
            SettingField::StealthTitle => self.stealth_title.clone(),
            SettingField::StealthBody => self.stealth_body.clone(),
            SettingField::StealthSeconds => self.stealth_seconds.clone(),
        }
    }

    fn to_config(&self) -> Config {
        let mut config = Config {
            server_url: self.server_url.clone(),
            file_server_url: self.file_server_url.clone(),
            mask_header_name: self.header_name.clone(),
            mask_header_value: self.header_value.to_string(),
            proxy_url: if self.proxy_url.trim().is_empty() {
                None
            } else {
                Some(self.proxy_url.clone())
            },
            notify_level: self.notify_level,
            stealth_title: self.stealth_title.clone(),
            stealth_body: self.stealth_body.clone(),
            stealth_seconds: self.stealth_seconds.clone(),
        };
        config.normalize();
        config
    }
}

enum UiNotice {
    Status(String),
    Error(String),
}

impl UiState {
    fn new(app: &App) -> Self {
        let room = app.get_current_room();
        let room_label = room_label(app, &room);

        // Создаём буфер обмена один раз: пересоздание на каждый вызов
        // приводило к предупреждению arboard «dropped too quickly».
        let (clipboard, status) = match arboard::Clipboard::new() {
            Ok(clipboard) => (Some(clipboard), "готово".to_string()),
            Err(e) => (None, format!("буфер обмена недоступен: {}", e)),
        };

        let mut state = Self {
            feed: Vec::new(),
            input: String::new(),
            cursor: 0,
            scroll: 0,
            follow: true,
            status,
            room,
            room_label,
            nickname: app.get_nickname(),
            view_width: 80,
            view_height: 10,
            chats: Vec::new(),
            unread: HashMap::new(),
            sidebar_visible: true,
            history: VecDeque::new(),
            history_index: None,
            history_draft: String::new(),
            files: Vec::new(),
            next_file_id: 0,
            dl_cycle: None,
            sf_cycle: None,
            clipboard,
            needs_clear: false,
            is_terminal_focused: true,
            passwd: None,
            settings: None,
        };
        refresh_chats(app, &mut state);
        reload_room(app, &mut state);
        state
    }
}

// ============================================================
// ТЕРМИНАЛ И PANIC-HOOK
// ============================================================

struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    fn new() -> Result<Self> {
        enable_raw_mode()?;

        let mut stdout = io::stdout();
        if let Err(e) = execute!(
            stdout,
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableFocusChange
        ) {
            let _ = disable_raw_mode();
            return Err(e.into());
        }

        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(mut terminal) => {
                let _ = terminal.clear();
                Ok(Self { terminal })
            }
            Err(e) => {
                let _ = disable_raw_mode();
                Err(e.into())
            }
        }
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableFocusChange,
            Show
        );
        let _ = self.terminal.show_cursor();
    }
}

fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Гарантированно возвращаем терминал в нормальный режим.
        let _ = disable_raw_mode();
        let mut stdout = io::stdout();
        let _ = execute!(
            stdout,
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableFocusChange,
            Show
        );
        default_hook(info);
    }));
}

// ============================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================

fn short_hash(h: &str) -> String {
    if h.len() > 12 {
        let (head, tail) = h.split_at(6);
        format!("{}…{}", head, &tail[tail.len() - 6..])
    } else {
        h.to_string()
    }
}

fn now_time() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

fn event_time(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_else(|| "??:??:??".to_string())
}

fn room_label(app: &App, room: &str) -> String {
    if room.is_empty() {
        return "—".to_string();
    }
    if room == app.identity.hash {
        return "self".to_string();
    }
    match app.get_contacts() {
        Ok(contacts) => contacts
            .iter()
            .find(|c| c.hash == room)
            .map(|c| c.nickname.clone())
            .unwrap_or_else(|| short_hash(room)),
        Err(_) => short_hash(room),
    }
}

fn load_room_feed(app: &App, state: &mut UiState) -> Vec<FeedEntry> {
    let room = state.room.clone();
    if room.is_empty() {
        return Vec::new();
    }

    let room_title = state.room_label.clone();
    let nickname = state.nickname.clone();

    match app.get_messages(&room, 300) {
        Ok(messages) => messages
            .into_iter()
            .map(|m| {
                let outgoing = m.direction != "in";
                let kind = if outgoing {
                    FeedKind::Outgoing
                } else {
                    FeedKind::Incoming
                };
                let time = m.timestamp.format("%H:%M:%S").to_string();

                let text = match parse_file_notification(&m.text) {
                    Some((file_name, file_hash)) => {
                        let id = register_file(
                            state,
                            &room,
                            &file_name,
                            &file_hash,
                            m.timestamp.timestamp(),
                        );
                        let sender = if outgoing {
                            nickname.as_str()
                        } else {
                            room_title.as_str()
                        };
                        file_feed_line(&time, sender, id, &file_name, outgoing)
                    }
                    None => format!("[{}] {}", time, m.text),
                };

                FeedEntry { kind, text }
            })
            .collect(),
        Err(e) => vec![FeedEntry {
            kind: FeedKind::Error,
            text: format!("Не удалось загрузить историю: {:#}", e),
        }],
    }
}

/// Разбирает служебное сообщение о файле, которое отправляет `send_file_native`.
fn parse_file_notification(text: &str) -> Option<(String, String)> {
    if !text.contains('📎') {
        return None;
    }

    let mut file_name = None;
    let mut file_hash = None;

    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("📎 Файл:") {
            file_name = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("Хеш:") {
            file_hash = Some(rest.trim().to_string());
        }
    }

    let file_hash = file_hash.filter(|hash| !hash.is_empty())?;
    let file_name = file_name.filter(|name| !name.is_empty()).unwrap_or_else(|| {
        let raw = file_hash.strip_prefix("sha256:").unwrap_or(&file_hash);
        format!("file_{}", raw.chars().take(8).collect::<String>())
    });

    Some((file_name, file_hash))
}

/// Регистрирует файл в состоянии сессии и возвращает его короткий номер.
fn register_file(
    state: &mut UiState,
    room_hash: &str,
    file_name: &str,
    file_hash: &str,
    timestamp: i64,
) -> usize {
    if let Some(existing) = state
        .files
        .iter_mut()
        .find(|f| f.room_hash == room_hash && f.file_hash == file_hash)
    {
        existing.timestamp = timestamp;
        return existing.id;
    }

    state.next_file_id += 1;
    let id = state.next_file_id;
    state.files.push(FileEntry {
        id,
        room_hash: room_hash.to_string(),
        file_hash: file_hash.to_string(),
        file_name: file_name.to_string(),
        timestamp,
    });
    id
}

fn file_feed_line(
    time: &str,
    sender: &str,
    id: usize,
    file_name: &str,
    outgoing: bool,
) -> String {
    if outgoing {
        format!(
            "[{}] 📎 вы отправили файл [#{}] {} (введите /dl или /dl {})",
            time, id, file_name, id
        )
    } else {
        format!(
            "[{}] 📎 {} отправил файл [#{}] {} (введите /dl или /dl {})",
            time, sender, id, file_name, id
        )
    }
}

fn file_matches(file: &FileEntry, token: &str) -> bool {
    let token = token.trim();
    if token.is_empty() {
        return true;
    }
    let bare = token.strip_prefix('#').unwrap_or(token);

    if let Ok(id) = bare.parse::<usize>() {
        if file.id == id {
            return true;
        }
    }

    if file.file_name.eq_ignore_ascii_case(bare) || file.file_hash.eq_ignore_ascii_case(bare) {
        return true;
    }

    let lower = bare.to_lowercase();
    file.file_name.to_lowercase().starts_with(&lower)
        || file.file_hash.to_lowercase().starts_with(&lower)
}

/// Ищет файл сначала в текущей комнате, затем среди всех файлов сессии.
fn find_file<'a>(files: &'a [FileEntry], room: &str, token: &str) -> Option<&'a FileEntry> {
    files
        .iter()
        .filter(|f| f.room_hash == room)
        .find(|f| file_matches(f, token))
        .or_else(|| files.iter().find(|f| file_matches(f, token)))
}

/// Не даёт имени файла выйти за пределы папки сохранения.
fn safe_file_name(file_name: &str) -> String {
    let base = file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(file_name)
        .replace('\0', "");
    let base = base.trim();

    if base.is_empty() || base == "." || base == ".." {
        "download".to_string()
    } else {
        base.to_string()
    }
}

/// Выбирает путь сохранения: аргумент-папка, аргумент-файл или ./downloads/<name>.
fn resolve_save_path(target: Option<&str>, file_name: &str) -> Result<PathBuf> {
    let file_name = safe_file_name(file_name);

    let path = match target.map(str::trim).filter(|s| !s.is_empty()) {
        None => {
            let dir = PathBuf::from("./downloads");
            std::fs::create_dir_all(&dir)
                .map_err(|e| anyhow!("не удалось создать {}: {}", dir.display(), e))?;
            dir.join(file_name)
        }
        Some(raw) => {
            let candidate = PathBuf::from(raw);
            let looks_like_dir =
                candidate.is_dir() || raw.ends_with('/') || raw.ends_with('\\');

            if looks_like_dir {
                std::fs::create_dir_all(&candidate).map_err(|e| {
                    anyhow!("не удалось создать {}: {}", candidate.display(), e)
                })?;
                candidate.join(file_name)
            } else {
                if let Some(parent) = candidate.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            anyhow!("не удалось создать {}: {}", parent.display(), e)
                        })?;
                    }
                }
                candidate
            }
        }
    };

    Ok(path)
}

/// Разворачивает `~` и `~/...` в домашнюю директорию.
fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        if let Some(home) = dirs::home_dir() {
            return home;
        }
    } else if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(raw)
}

/// Превращает путь пользователя в абсолютный от текущей рабочей директории.
fn absolute_user_path(raw: &str) -> Result<PathBuf> {
    let expanded = expand_tilde(raw);
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        let cwd = std::env::current_dir()
            .map_err(|e| anyhow!("не удалось определить текущую директорию: {}", e))?;
        Ok(cwd.join(expanded))
    }
}

fn reload_room(app: &App, state: &mut UiState) {
    let feed = load_room_feed(app, state);
    state.feed = feed;
    state.scroll = 0;
    state.follow = true;
}

/// Перечитывает список контактов для боковой панели.
fn refresh_chats(app: &App, state: &mut UiState) {
    let mut chats = Vec::new();

    if let Ok(contacts) = app.get_contacts() {
        for contact in contacts {
            if contact.hash == app.identity.hash {
                continue;
            }
            chats.push(ChatEntry {
                hash: contact.hash,
                label: contact.nickname,
            });
        }
    }

    // Активная комната может быть ещё не в списке контактов.
    if !state.room.is_empty() && !chats.iter().any(|c| c.hash == state.room) {
        chats.push(ChatEntry {
            hash: state.room.clone(),
            label: state.room_label.clone(),
        });
    }

    state.chats = chats;

    // Убираем счётчики для комнат, которых больше нет в списке.
    let known: Vec<String> = state.chats.iter().map(|c| c.hash.clone()).collect();
    state.unread.retain(|hash, _| known.iter().any(|h| h == hash));
}

/// Добавляет чат в боковую панель, если его там ещё нет.
fn ensure_chat_entry(state: &mut UiState, hash: &str, label: &str) {
    if hash.is_empty() || state.chats.iter().any(|c| c.hash == hash) {
        return;
    }

    state.chats.push(ChatEntry {
        hash: hash.to_string(),
        label: if label.is_empty() {
            short_hash(hash)
        } else {
            label.to_string()
        },
    });
}

/// Переключает активную комнату и сбрасывает её счётчик непрочитанных.
fn switch_to_room(app: &App, state: &mut UiState, hash: &str) {
    app.switch_room(hash);
    state.room = hash.to_string();
    state.room_label = room_label(app, hash);
    state.unread.remove(hash);
    let label = state.room_label.clone();
    ensure_chat_entry(state, hash, &label);
    reload_room(app, state);
}

/// Переключает чат на delta позиций по списку боковой панели.
fn cycle_chat(app: &App, state: &mut UiState, delta: isize) {
    if state.chats.is_empty() {
        refresh_chats(app, state);
    }
    if state.chats.is_empty() {
        state.status = "чатов нет".to_string();
        return;
    }

    let len = state.chats.len() as isize;
    let index = match state.chats.iter().position(|c| c.hash == state.room) {
        Some(current) => (current as isize + delta).rem_euclid(len),
        None => {
            if delta > 0 {
                0
            } else {
                len - 1
            }
        }
    } as usize;

    let hash = state.chats[index].hash.clone();
    switch_to_room(app, state, &hash);
    state.status = format!("чат: {}", state.room_label);
}

/// Приводит hash или ник из `/room` к hash контакта.
fn resolve_room(app: &App, token: &str) -> String {
    if let Ok(contacts) = app.get_contacts() {
        if let Some(contact) = contacts.iter().find(|c| c.hash == token) {
            return contact.hash.clone();
        }
        if let Some(contact) = contacts
            .iter()
            .find(|c| c.nickname.eq_ignore_ascii_case(token))
        {
            return contact.hash.clone();
        }
        let prefix_matches: Vec<_> = contacts
            .iter()
            .filter(|c| c.hash.starts_with(token))
            .collect();
        if prefix_matches.len() == 1 {
            return prefix_matches[0].hash.clone();
        }
    }

    token.to_string()
}

/// Приводит короткий алиас к каноническому имени команды.
fn normalize_command(cmd: &str) -> &str {
    match cmd {
        "/q" => "/quit",
        "/jn" => "/join",
        "/in" => "/invite",
        "/ls" | "/c" => "/contacts",
        "/r" => "/room",
        "/sf" => "/sendfile",
        "/dl" => "/download",
        "/p" => "/profile",
        "/h" | "/?" => "/help",
        "/sb" => "/sidebar",
        "/settings" => "/set",
        other => other,
    }
}

fn alias_to_command(cmd: &str) -> Option<&'static str> {
    match cmd {
        "/q" => Some("/quit"),
        "/jn" => Some("/join"),
        "/in" => Some("/invite"),
        "/ls" | "/c" => Some("/contacts"),
        "/r" => Some("/room"),
        "/sf" => Some("/sendfile"),
        "/dl" => Some("/download"),
        "/p" => Some("/profile"),
        "/h" | "/?" => Some("/help"),
        "/sb" => Some("/sidebar"),
        "/settings" => Some("/set"),
        _ => None,
    }
}

fn push_system(state: &mut UiState, text: &str) {
    state.feed.push(FeedEntry {
        kind: FeedKind::System,
        text: text.to_string(),
    });
    state.follow = true;
}

fn push_error(state: &mut UiState, text: &str) {
    state.feed.push(FeedEntry {
        kind: FeedKind::Error,
        text: text.to_string(),
    });
    state.follow = true;
    state.status = text.to_string();
}

fn entry_lines(entry: &FeedEntry) -> Vec<Line<'static>> {
    let (marker, style) = match entry.kind {
        FeedKind::Incoming => ("◀ ", Style::default().fg(Color::Cyan)),
        FeedKind::Outgoing => ("▶ ", Style::default().fg(Color::Green)),
        FeedKind::System => ("· ", Style::default().fg(Color::Gray)),
        FeedKind::Error => ("! ", Style::default().fg(Color::Red)),
    };

    entry
        .text
        .split('\n')
        .enumerate()
        .map(|(i, part)| {
            let prefix = if i == 0 { marker } else { "  " };
            Line::from(vec![
                Span::styled(prefix.to_string(), style),
                Span::styled(part.to_string(), style),
            ])
        })
        .collect()
}

fn entry_line_count(entry: &FeedEntry, width: usize) -> usize {
    let width = width.max(1);
    entry
        .text
        .split('\n')
        .map(|line| {
            let chars = line.chars().count() + 2; // маркер/отступ
            chars.div_ceil(width).max(1)
        })
        .sum::<usize>()
        .max(1)
}

fn total_lines(state: &UiState) -> usize {
    let width = state.view_width.max(1);
    state
        .feed
        .iter()
        .map(|entry| entry_line_count(entry, width))
        .sum()
}

fn bottom_offset(state: &UiState) -> usize {
    total_lines(state).saturating_sub(state.view_height.max(1))
}

fn scroll_up(state: &mut UiState, amount: usize) {
    let bottom = bottom_offset(state);
    let current = if state.follow {
        bottom
    } else {
        state.scroll.min(bottom)
    };
    state.scroll = current.saturating_sub(amount);
    state.follow = state.scroll >= bottom;
}

fn scroll_down(state: &mut UiState, amount: usize) {
    let bottom = bottom_offset(state);
    let current = if state.follow {
        bottom
    } else {
        state.scroll.min(bottom)
    };
    let next = current.saturating_add(amount).min(bottom);
    state.scroll = next;
    state.follow = next >= bottom;
}

fn prev_char_boundary(s: &str, idx: usize) -> usize {
    s[..idx]
        .char_indices()
        .next_back()
        .map(|(i, _)| i)
        .unwrap_or(0)
}

fn next_char_boundary(s: &str, idx: usize) -> usize {
    s[idx..]
        .chars()
        .next()
        .map(|c| idx + c.len_utf8())
        .unwrap_or(idx)
}

// ============================================================
// ИСТОРИЯ ВВОДА И АВТОДОПОЛНЕНИЕ
// ============================================================

const HISTORY_LIMIT: usize = 50;

fn history_remember(state: &mut UiState, line: &str) {
    if line.is_empty() {
        return;
    }
    if state
        .history
        .back()
        .map(|last| last.as_str() == line)
        .unwrap_or(false)
    {
        return;
    }

    if state.history.len() >= HISTORY_LIMIT {
        state.history.pop_front();
    }
    state.history.push_back(line.to_string());
}

fn history_prev(state: &mut UiState) {
    if state.history.is_empty() {
        return;
    }

    let next = match state.history_index {
        None => {
            state.history_draft = state.input.clone();
            state.history.len() - 1
        }
        Some(0) => 0,
        Some(index) => index - 1,
    };

    state.history_index = Some(next);
    if let Some(line) = state.history.get(next) {
        state.input = line.clone();
        state.cursor = state.input.len();
    }
}

fn history_next(state: &mut UiState) {
    let Some(index) = state.history_index else {
        return;
    };

    if index + 1 < state.history.len() {
        let next = index + 1;
        state.history_index = Some(next);
        if let Some(line) = state.history.get(next) {
            state.input = line.clone();
            state.cursor = state.input.len();
        }
    } else {
        state.history_index = None;
        state.input = std::mem::take(&mut state.history_draft);
        state.cursor = state.input.len();
    }
}

/// Заменяет `start..cursor` во вводе и ставит курсор после вставленного текста.
fn replace_input_before_cursor(state: &mut UiState, start: usize, text: &str) {
    let cursor = state.cursor;
    state.input.replace_range(start..cursor, text);
    state.cursor = start + text.len();
    state.history_index = None;
}

fn complete_input(app: &App, state: &mut UiState) {
    if state.cursor > state.input.len() || !state.input.starts_with('/') {
        return;
    }

    let before = state.input[..state.cursor].to_string();
    let word_start = before
        .char_indices()
        .rev()
        .find(|(_, c)| c.is_whitespace())
        .map(|(index, c)| index + c.len_utf8())
        .unwrap_or(0);
    let first = before.split_whitespace().next().unwrap_or("");
    let command = normalize_command(first);
    let words_before = before[..word_start].split_whitespace().count();
    let prefix_parts: Vec<&str> = before[..word_start].split_whitespace().collect();

    // /dl <Tab> или /download <Tab> — перебираем файлы текущей комнаты.
    // Второй и последующие аргументы (путь сохранения) не дополняем.
    if command == "/download" && word_start > 0 && words_before == 1 {
        complete_download(state, word_start);
        return;
    }

    // /sf <Tab> или /sendfile <Tab> — пути от текущей директории.
    if command == "/sendfile" && word_start > 0 {
        let current = &before[word_start..];

        // Первый аргумент может быть флагом --force.
        if words_before == 1 && !current.is_empty() && "--force".starts_with(current) {
            replace_input_before_cursor(state, word_start, "--force ");
            state.sf_cycle = None;
            state.status = "флаг --force: разрешить системные пути".to_string();
            return;
        }

        let path_arg = words_before == 1
            || (words_before == 2 && prefix_parts.get(1) == Some(&"--force"));
        if path_arg {
            complete_sendfile(state, word_start);
            return;
        }
    }

    // /room <Tab> или /r <Tab> — дополняем контакт.
    if command == "/room" && word_start > 0 {
        complete_contact(app, state, word_start);
        return;
    }

    // Иначе дополняем имя команды, пока курсор в первом слове.
    if word_start == 0 {
        complete_command(state);
    }
}

fn complete_command(state: &mut UiState) {
    let before = state.input[..state.cursor].to_string();

    // Точный алиас (/r, /q, /sf...) сразу раскрывается в каноническую команду.
    if let Some(target) = alias_to_command(&before) {
        replace_input_before_cursor(state, 0, target);
        state.status = format!("команда: {}", target);
        return;
    }

    let matches: Vec<&str> = COMMANDS
        .iter()
        .copied()
        .filter(|command| command.starts_with(&before))
        .collect();

    match matches.len() {
        0 => state.status = format!("нет команд по запросу «{}»", before),
        1 => {
            let target = matches[0];
            replace_input_before_cursor(state, 0, target);
            state.status = format!("команда: {}", target);
        }
        _ => {
            push_system(
                state,
                &format!("Подходящие команды:\n{}", matches.join("  ")),
            );
            state.status = format!("{} вариантов — см. чат", matches.len());
        }
    }
}

fn dl_status(index: usize, total: usize, label: &str) -> String {
    if total > 1 {
        format!("файл {}/{}: {} (Tab — далее)", index + 1, total, label)
    } else {
        format!("файл: {}", label)
    }
}

fn complete_download(state: &mut UiState, word_start: usize) {
    let before = state.input[..state.cursor].to_string();
    let current = before[word_start..].to_string();

    // Повторный Tab по уже подставленному токену листает кандидатов.
    if let Some(cycle) = state.dl_cycle.take() {
        if cycle.start == word_start
            && cycle.last_insert == current
            && !cycle.candidates.is_empty()
        {
            let index = (cycle.index + 1) % cycle.candidates.len();
            let token = cycle.candidates[index].clone();
            let label = cycle
                .labels
                .get(index)
                .cloned()
                .unwrap_or_else(|| token.clone());
            let total = cycle.candidates.len();

            replace_input_before_cursor(state, word_start, &token);
            state.status = dl_status(index, total, &label);
            state.dl_cycle = Some(CompletionCycle {
                start: word_start,
                index,
                candidates: cycle.candidates,
                labels: cycle.labels,
                last_insert: token,
            });
            return;
        }
    }

    let files: Vec<FileEntry> = state
        .files
        .iter()
        .filter(|f| f.room_hash == state.room)
        .cloned()
        .collect();

    if files.is_empty() {
        state.status = "в этой комнате нет файлов".to_string();
        return;
    }

    let matching: Vec<&FileEntry> = if current.trim().is_empty() {
        files.iter().collect()
    } else {
        files.iter().filter(|f| file_matches(f, &current)).collect()
    };

    if matching.is_empty() {
        state.status = format!("нет файлов по запросу «{}»", current);
        return;
    }

    let candidates: Vec<String> = matching.iter().map(|f| format!("#{}", f.id)).collect();
    let labels: Vec<String> = matching
        .iter()
        .map(|f| format!("#{} {}", f.id, f.file_name))
        .collect();

    let token = candidates[0].clone();
    let label = labels[0].clone();
    let total = candidates.len();

    replace_input_before_cursor(state, word_start, &token);
    state.status = dl_status(0, total, &label);
    state.dl_cycle = Some(CompletionCycle {
        start: word_start,
        index: 0,
        candidates,
        labels,
        last_insert: token,
    });
}

fn path_status(index: usize, total: usize, label: &str) -> String {
    if total > 1 {
        format!("путь {}/{}: {} (Tab — далее)", index + 1, total, label)
    } else {
        format!("файл: {}", label)
    }
}

fn complete_sendfile(state: &mut UiState, word_start: usize) {
    let before = state.input[..state.cursor].to_string();
    let current = before[word_start..].to_string();

    // Повторный Tab листает файлы. Папки не листаем: Tab по папке входит внутрь.
    if let Some(cycle) = state.sf_cycle.take() {
        if cycle.start == word_start
            && cycle.last_insert == current
            && !cycle.candidates.is_empty()
        {
            let index = (cycle.index + 1) % cycle.candidates.len();
            let token = cycle.candidates[index].clone();
            let label = cycle
                .labels
                .get(index)
                .cloned()
                .unwrap_or_else(|| token.clone());
            let total = cycle.candidates.len();

            replace_input_before_cursor(state, word_start, &token);
            if token.ends_with('/') {
                state.status = format!("папка: {} (Tab — войти)", label);
            } else {
                state.status = path_status(index, total, &label);
                state.sf_cycle = Some(CompletionCycle {
                    start: word_start,
                    index,
                    candidates: cycle.candidates,
                    labels: cycle.labels,
                    last_insert: token,
                });
            }
            return;
        }
    }

    // Отдельно обрабатываем `~`, чтобы не читать текущую директорию.
    if current == "~" {
        replace_input_before_cursor(state, word_start, "~/");
        state.sf_cycle = None;
        state.status = "домашняя директория".to_string();
        return;
    }

    // Разделяем введённое на уже набранную папку и префикс имени.
    let (dir_part, name_part) = match current.rfind('/') {
        Some(pos) => (&current[..=pos], &current[pos + 1..]),
        None => ("", current.as_str()),
    };

    let dir_for_read = if dir_part.is_empty() { "." } else { dir_part };
    let dir_path = match absolute_user_path(dir_for_read) {
        Ok(path) => path,
        Err(e) => {
            state.status = format!("{:#}", e);
            return;
        }
    };

    let entries = match std::fs::read_dir(&dir_path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            state.status = format!("нет прав на чтение: {}", dir_path.display());
            return;
        }
        Err(e) => {
            state.status = format!("не удалось прочитать {}: {}", dir_path.display(), e);
            return;
        }
    };

    let show_hidden = name_part.starts_with('.');
    let mut candidates: Vec<String> = Vec::new();

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with(name_part) {
            continue;
        }
        if !show_hidden && name.starts_with('.') {
            continue;
        }

        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let suffix = if is_dir { "/" } else { "" };
        candidates.push(format!("{}{}{}", dir_part, name, suffix));
    }

    candidates.sort();

    if candidates.is_empty() {
        state.status = if current.is_empty() {
            format!("в {} нет файлов", dir_path.display())
        } else {
            format!("нет файлов по запросу «{}»", current)
        };
        return;
    }

    let total = candidates.len();
    let token = candidates[0].clone();
    let is_dir = token.ends_with('/');
    let label = token.clone();

    replace_input_before_cursor(state, word_start, &token);
    if is_dir {
        if total > 1 {
            state.status = format!("папка: {} (Tab — войти, {} вариантов)", label, total);
        } else {
            state.status = format!("папка: {} (Tab — войти)", label);
        }
    } else {
        state.status = path_status(0, total, &label);
        state.sf_cycle = Some(CompletionCycle {
            start: word_start,
            index: 0,
            labels: candidates.clone(),
            candidates,
            last_insert: token,
        });
    }
}

fn complete_contact(app: &App, state: &mut UiState, word_start: usize) {
    let before = state.input[..state.cursor].to_string();
    let partial = before[word_start..].to_string();
    let lower = partial.to_lowercase();

    let contacts = match app.get_contacts() {
        Ok(contacts) => contacts,
        Err(e) => {
            state.status = format!("ошибка получения контактов: {:#}", e);
            return;
        }
    };

    let mut candidates: Vec<String> = Vec::new();
    for contact in &contacts {
        if contact.nickname.to_lowercase().starts_with(&lower)
            && !candidates.contains(&contact.nickname)
        {
            candidates.push(contact.nickname.clone());
        }
    }
    if !partial.is_empty() {
        for contact in &contacts {
            if contact.hash.starts_with(&lower) && !candidates.contains(&contact.hash) {
                candidates.push(contact.hash.clone());
            }
        }
    }

    match candidates.len() {
        0 => push_system(state, &format!("Нет контактов по запросу «{}»", partial)),
        1 => {
            let choice = candidates.remove(0);
            replace_input_before_cursor(state, word_start, &choice);
            state.status = format!("контакт: {}", choice);
        }
        _ => {
            push_system(
                state,
                &format!("Подходящие контакты:\n{}", candidates.join("\n")),
            );
            state.status = format!("{} вариантов — см. чат", candidates.len());
        }
    }
}

// ============================================================
// ОТРИСОВКА
// ============================================================

fn sidebar_lines(state: &UiState, width: usize) -> Vec<Line<'static>> {
    let width = width.max(1);

    state
        .chats
        .iter()
        .map(|chat| {
            let active = chat.hash == state.room;
            let unread = state.unread.get(&chat.hash).copied().unwrap_or(0);
            let marker = if active { "▸ " } else { "  " };
            let badge = if !active && unread > 0 {
                format!("+{}", unread)
            } else {
                String::new()
            };
            let marker_width = marker.chars().count();
            let badge_width = badge.chars().count();
            let gap = usize::from(!badge.is_empty());
            let label_width = width.saturating_sub(marker_width + badge_width + gap);

            let mut label: String = chat.label.chars().take(label_width).collect();
            if chat.label.chars().count() > label_width && label_width > 0 {
                label.pop();
                label.push('…');
            }

            let pad =
                width.saturating_sub(marker_width + label.chars().count() + badge_width);
            let text = format!("{}{}{}{}", marker, label, " ".repeat(pad), badge);
            let style = if active {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else if unread > 0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Gray)
            };

            Line::from(Span::styled(text, style))
        })
        .collect()
}

fn draw_ui(frame: &mut Frame, state: &mut UiState) {
    let chunks = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .split(frame.area());

    // ---------- 1. Боковая панель и история сообщений ----------
    let show_sidebar = state.sidebar_visible && chunks[0].width >= 44;
    let (sidebar_area, chat_area) = if show_sidebar {
        let desired = ((chunks[0].width as u32 * 20) / 100) as u16;
        let sidebar_width = desired.max(22);
        let split = Layout::horizontal([
            Constraint::Length(sidebar_width),
            Constraint::Min(20),
        ])
        .split(chunks[0]);
        (Some(split[0]), split[1])
    } else {
        (None, chunks[0])
    };

    if let Some(area) = sidebar_area {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Чаты ({}) ", state.chats.len()));
        let inner = block.inner(area);
        let lines = sidebar_lines(state, inner.width as usize);
        frame.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
    }

    let title = if state.room.is_empty() {
        "Чат — нет активной комнаты".to_string()
    } else {
        format!(" {} · {} ", state.room_label, short_hash(&state.room))
    };
    let chat_block = Block::default().borders(Borders::ALL).title(title);
    let chat_inner = chat_block.inner(chat_area);
    state.view_width = chat_inner.width as usize;
    state.view_height = chat_inner.height as usize;

    let bottom = bottom_offset(state);
    let offset = if state.follow {
        bottom
    } else {
        state.scroll.min(bottom)
    };

    let lines: Vec<Line<'static>> = state.feed.iter().flat_map(entry_lines).collect();
    let paragraph = Paragraph::new(Text::from(lines))
        .block(chat_block)
        .wrap(Wrap { trim: false })
        .scroll((offset.min(u16::MAX as usize) as u16, 0));
    frame.render_widget(paragraph, chat_area);

    // ---------- 2. Статус-бар ----------
    let room = if state.room.is_empty() {
        "—".to_string()
    } else {
        format!("{} ({})", state.room_label, short_hash(&state.room))
    };
    let status = if let Some(flow) = state.settings.as_ref() {
        format!(
            " Настройки: {} · {}   Esc — сохранить и закрыть ",
            flow.field().label(),
            if flow.editing { "ввод" } else { "выбор" }
        )
    } else {
        format!(
            " {}   Room: {}   {} ",
            state.nickname, room, state.status
        )
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            status,
            Style::default().bg(Color::DarkGray).fg(Color::White),
        ))),
        chunks[1],
    );

    // ---------- 3. Поле ввода ----------
    let settings_open = state.settings.is_some();
    let (input_title, masked) = if settings_open {
        (" Настройки ".to_string(), false)
    } else if let Some(flow) = state.passwd.as_ref() {
        let title = match flow.stage {
            PasswdStage::Current => " Пароль: текущий ",
            PasswdStage::New => " Пароль: новый ",
            PasswdStage::Confirm => " Пароль: повтор ",
        };
        (title.to_string(), true)
    } else {
        (" Ввод ".to_string(), false)
    };
    let input_block = Block::default()
        .borders(Borders::ALL)
        .title(input_title);
    let input_inner = input_block.inner(chunks[2]);
    frame.render_widget(input_block, chunks[2]);

    if settings_open {
        let hint = match state.settings.as_ref() {
            Some(flow) if flow.editing => {
                " Ввод: Enter — применить · Esc — отменить редактирование "
            }
            _ => {
                " ↑/↓ или Tab/Shift+Tab — выбор · Enter — редактировать · \
                 ←/→ или Space — Notify Level · Esc — сохранить и закрыть "
            }
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                hint,
                Style::default().fg(Color::Gray),
            ))),
            input_inner,
        );
    } else {
        let prefix = "> ";
        let avail = (input_inner.width as usize).saturating_sub(prefix.len());
        let before = state.input[..state.cursor].chars().count();
        let cursor_col = if avail == 0 {
            0
        } else {
            before.min(avail - 1)
        };
        let start = before - cursor_col;
        let visible: String = if masked {
            "*".repeat(state.input.chars().count().min(avail))
        } else {
            state.input.chars().skip(start).take(avail).collect()
        };

        frame.render_widget(
            Paragraph::new(Line::from(format!("{}{}", prefix, visible))),
            input_inner,
        );

        let cursor_x = input_inner.x + prefix.len() as u16 + cursor_col as u16;
        let cursor_y = input_inner.y;
        frame.set_cursor_position(Position::new(
            cursor_x.min(input_inner.right().saturating_sub(1)),
            cursor_y,
        ));
    }

    if settings_open {
        draw_settings_modal(frame, state);
    }
}

/// Рисует центрированное модальное окно `/set` поверх TUI.
fn draw_settings_modal(frame: &mut Frame, state: &UiState) {
    let Some(flow) = state.settings.as_ref() else {
        return;
    };

    let area = frame.area();
    let width = 78.min(area.width.saturating_sub(2)).max(20);
    let height = (SETTINGS_FIELDS.len() as u16 + 5)
        .min(area.height.saturating_sub(2))
        .max(8);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    let rect = Rect::new(x, y, width, height);

    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Настройки · /set ");
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    const LABEL_WIDTH: usize = 20;
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(SETTINGS_FIELDS.len() + 2);

    for (index, field) in SETTINGS_FIELDS.iter().enumerate() {
        let selected = index == flow.selected;
        let marker = if selected { "▸ " } else { "  " };
        let label = format!("{:<width$}", field.label(), width = LABEL_WIDTH);

        let value = if selected && flow.editing && !field.is_notify_level() {
            if field.is_masked() {
                "*".repeat(state.input.chars().count())
            } else {
                state.input.clone()
            }
        } else {
            flow.display_value(*field)
        };

        let text = format!("{}{}  {}", marker, label, value);
        let style = if selected {
            Style::default().bg(Color::DarkGray).fg(Color::White)
        } else {
            Style::default().fg(Color::Gray)
        };
        lines.push(Line::from(Span::styled(text, style)));
    }

    lines.push(Line::from(""));
    let hint = if flow.editing {
        "Enter — применить · Esc — отменить · Ctrl+V — вставить"
    } else {
        "↑/↓, Tab/Shift+Tab — выбор · Enter — изменить · Esc — сохранить и закрыть"
    };
    lines.push(Line::from(Span::styled(
        hint,
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(Paragraph::new(Text::from(lines)), inner);

    if flow.editing {
        let prefix_width = 2 + LABEL_WIDTH + 2;
        let before = state.input[..state.cursor].chars().count();
        let max_x = inner.right().saturating_sub(1);
        let cursor_x = (inner.x + prefix_width as u16 + before as u16).min(max_x);
        let cursor_y = (inner.y + flow.selected as u16).min(inner.bottom().saturating_sub(1));
        frame.set_cursor_position(Position::new(cursor_x, cursor_y));
    }
}

// ============================================================
// ОБРАБОТКА СОБЫТИЙ
// ============================================================

fn apply_notice(state: &mut UiState, notice: UiNotice) {
    match notice {
        UiNotice::Status(text) => state.status = text,
        UiNotice::Error(text) => push_error(state, &text),
    }
}

fn handle_app_event(app: &Arc<App>, state: &mut UiState, event: AppEvent) {
    match event {
        AppEvent::NewMessage {
            room_hash,
            text,
            timestamp,
            sender,
        } => {
            let outgoing = sender.ends_with("(self)");
            let incoming_file = parse_file_notification(&text);
            let should_notify =
                !outgoing && (!state.is_terminal_focused || room_hash != state.room);
            let notify_unread = if room_hash == state.room {
                1
            } else {
                state.unread.get(&room_hash).copied().unwrap_or(0) + 1
            };

            if room_hash == state.room {
                if let Some((file_name, file_hash)) = incoming_file {
                    let id = register_file(state, &room_hash, &file_name, &file_hash, timestamp);
                    state.feed.push(FeedEntry {
                        kind: if outgoing {
                            FeedKind::Outgoing
                        } else {
                            FeedKind::Incoming
                        },
                        text: file_feed_line(
                            &event_time(timestamp),
                            &sender,
                            id,
                            &file_name,
                            outgoing,
                        ),
                    });
                    state.status = format!("файл #{}: {} — /dl {}", id, file_name, id);
                } else {
                    state.feed.push(FeedEntry {
                        kind: FeedKind::Incoming,
                        text: format!("[{}] {}: {}", event_time(timestamp), sender, text),
                    });
                    state.status = format!("новое сообщение от {}", sender);
                }
                state.follow = true;
            } else {
                ensure_chat_entry(state, &room_hash, &sender);
                let count = state.unread.entry(room_hash.clone()).or_insert(0);
                *count += 1;
                let count = *count;

                let file_note = match incoming_file {
                    Some((file_name, file_hash)) => {
                        let id =
                            register_file(state, &room_hash, &file_name, &file_hash, timestamp);
                        format!(" (файл #{}: {})", id, file_name)
                    }
                    None => String::new(),
                };

                state.status = format!(
                    "новое сообщение от {} в «{}» (+{}){}, переключение: Alt+Up/Alt+Down",
                    sender,
                    room_label(app, &room_hash),
                    count,
                    file_note
                );
            }

            if should_notify {
                notify_incoming(app, &sender, &text, notify_unread);
            }
        }
        AppEvent::ContactImport {
            hash,
            x25519,
            nickname,
            ..
        } => match app.add_contact(&hash, &x25519, &nickname) {
            Ok(()) => {
                refresh_chats(app, state);
                switch_to_room(app, state, &hash);
                push_system(
                    state,
                    &format!(
                        "Контакт из deep link добавлен: {} ({})",
                        nickname,
                        short_hash(&hash)
                    ),
                );
                state.status = "контакт добавлен".to_string();
            }
            Err(e) => push_error(
                state,
                &format!("Не удалось добавить контакт из deep link: {:#}", e),
            ),
        },
        AppEvent::ContactImportError { error } => {
            push_error(state, &format!("Ошибка импорта контакта: {}", error));
        }
        AppEvent::UploadStarted { file_name } => {
            push_system(state, &format!("Загрузка файла: {}", file_name));
            state.status = "загрузка файла...".to_string();
        }
        AppEvent::UploadProgress { status, progress } => {
            state.status = format!("загрузка {}% — {}", progress, status);
        }
        AppEvent::UploadCompleted {
            file_name,
            file_hash,
            file_size,
        } => {
            let room = state.room.clone();
            let id = register_file(
                state,
                &room,
                &file_name,
                &file_hash,
                chrono::Utc::now().timestamp(),
            );
            let size = file_size.map(|s| format!(", {} B", s)).unwrap_or_default();
            let hint = if room.is_empty() {
                String::new()
            } else {
                format!("; скачать: /dl {}", id)
            };
            push_system(
                state,
                &format!(
                    "Файл [#{}] {} отправлен, hash={}{}{}",
                    id,
                    file_name,
                    short_hash(&file_hash),
                    size,
                    hint
                ),
            );
            state.status = format!("файл #{} отправлен", id);
        }
        AppEvent::UploadError { error } => {
            push_error(state, &format!("Ошибка загрузки файла: {}", error));
        }
        AppEvent::DownloadStarted => {
            state.status = "скачивание файла...".to_string();
        }
        AppEvent::DownloadCompleted { file_path } => {
            push_system(state, &format!("Файл сохранён: {}", file_path));
            state.status = "файл сохранён".to_string();
        }
        AppEvent::DownloadError { error } => {
            push_error(state, &format!("Ошибка скачивания файла: {}", error));
        }
    }
}

/// Отправляет системное уведомление в фоне.
///
/// Ошибки демона (например, отсутствие D-Bus в голом SSH) намеренно
/// игнорируются: входящее сообщение уже сохранено и отрисовано в TUI.
fn notify_incoming(app: &Arc<App>, sender: &str, text: &str, unread: usize) {
    let app = Arc::clone(app);
    let sender = sender.to_string();
    let text = text.to_string();

    tokio::spawn(async move {
        let _ = tokio::task::spawn_blocking(move || {
            let _ = app.send_notification(&sender, &text, unread);
        })
        .await;
    });
}

async fn handle_terminal_event(
    app: &Arc<App>,
    state: &mut UiState,
    ui_tx: &mpsc::UnboundedSender<UiNotice>,
    event: Event,
) -> Result<bool> {
    match event {
        Event::Key(key) => {
            if key.kind == KeyEventKind::Release {
                return Ok(false);
            }

            let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
            let alt = key.modifiers.contains(KeyModifiers::ALT);

            // Любое действие, кроме повторного Tab, сбрасывает цикл подсказок.
            if !matches!(key.code, KeyCode::Tab) {
                state.dl_cycle = None;
                state.sf_cycle = None;
            }

            if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')) {
                return Ok(true);
            }

            if ctrl && matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V')) {
                let can_paste = state
                    .settings
                    .as_ref()
                    .map(|flow| flow.editing)
                    .unwrap_or(true);
                if can_paste {
                    paste_from_clipboard(state);
                }
                return Ok(false);
            }

            // Модальное окно настроек перехватывает навигацию и ввод.
            if state.settings.is_some() {
                handle_settings_key(app, state, key);
                return Ok(false);
            }

            // Быстрое переключение чатов: Alt+Up/Down и Ctrl+P/Ctrl+N.
            let switch = match key.code {
                KeyCode::Up if alt => Some(-1),
                KeyCode::Down if alt => Some(1),
                KeyCode::Char('p') | KeyCode::Char('P') if ctrl => Some(-1),
                KeyCode::Char('n') | KeyCode::Char('N') if ctrl => Some(1),
                _ => None,
            };
            if let Some(delta) = switch {
                cycle_chat(app, state, delta);
                return Ok(false);
            }

            match key.code {
                KeyCode::Enter => {
                    if state.passwd.is_some() {
                        let raw = std::mem::take(&mut state.input);
                        state.cursor = 0;
                        state.history_index = None;
                        state.history_draft.clear();
                        submit_password(app, state, Zeroizing::new(raw));
                        return Ok(false);
                    }

                    let line = state.input.trim().to_string();
                    state.input.clear();
                    state.cursor = 0;
                    state.history_index = None;
                    state.history_draft.clear();

                    if line.is_empty() {
                        return Ok(false);
                    }

                    history_remember(state, &line);

                    if line.starts_with('/') {
                        return handle_command(app, state, ui_tx, &line).await;
                    }

                    send_plain_message(app, state, &line).await;
                }
                KeyCode::Tab if state.passwd.is_none() => {
                    complete_input(app, state)
                }
                KeyCode::Up if state.passwd.is_none() => {
                    history_prev(state)
                }
                KeyCode::Down if state.passwd.is_none() => {
                    history_next(state)
                }
                KeyCode::Char(c) => {
                    if !ctrl {
                        state.input.insert(state.cursor, c);
                        state.cursor += c.len_utf8();
                    }
                }
                KeyCode::Backspace => {
                    if state.cursor > 0 {
                        let prev = prev_char_boundary(&state.input, state.cursor);
                        state.input.remove(prev);
                        state.cursor = prev;
                    }
                }
                KeyCode::Delete => {
                    if state.cursor < state.input.len() {
                        state.input.remove(state.cursor);
                    }
                }
                KeyCode::Left => {
                    state.cursor = prev_char_boundary(&state.input, state.cursor);
                }
                KeyCode::Right => {
                    state.cursor = next_char_boundary(&state.input, state.cursor);
                }
                KeyCode::Home => state.cursor = 0,
                KeyCode::End => state.cursor = state.input.len(),
                KeyCode::PageUp => scroll_up(state, state.view_height.max(1)),
                KeyCode::PageDown => scroll_down(state, state.view_height.max(1)),
                KeyCode::Esc => {
                    if state.passwd.take().is_some() {
                        state.input.clear();
                        state.cursor = 0;
                        state.history_index = None;
                        state.history_draft.clear();
                        push_system(state, "Смена мастер-пароля отменена");
                        state.status = "смена пароля отменена".to_string();
                        return Ok(false);
                    }

                    state.input.clear();
                    state.cursor = 0;
                    state.history_index = None;
                    state.history_draft.clear();
                }
                _ => {}
            }
        }
        Event::Mouse(mouse) => match mouse.kind {
            MouseEventKind::ScrollUp => scroll_up(state, 3),
            MouseEventKind::ScrollDown => scroll_down(state, 3),
            _ => {}
        },
        Event::Paste(text) => {
            let can_paste = state
                .settings
                .as_ref()
                .map(|flow| flow.editing)
                .unwrap_or(true);
            if can_paste {
                state.dl_cycle = None;
                state.sf_cycle = None;
                insert_text(state, &text);
            }
        }
        Event::FocusGained => {
            state.is_terminal_focused = true;
        }
        Event::FocusLost => {
            state.is_terminal_focused = false;
        }
        Event::Resize(_, _) => {
            // Новые размеры будут учтены на следующем кадре.
        }
    }

    Ok(false)
}

/// Обрабатывает Enter в режиме смены мастер-пароля.
fn submit_password(app: &App, state: &mut UiState, input: Zeroizing<String>) {
    let Some(mut flow) = state.passwd.take() else {
        return;
    };

    match flow.stage {
        PasswdStage::Current => {
            if input.is_empty() {
                push_error(state, "Пароль не может быть пустым");
                state.passwd = Some(flow);
                return;
            }

            match app.verify_master_password(input.as_str()) {
                Ok(()) => {
                    flow.old = input;
                    flow.stage = PasswdStage::New;
                    state.passwd = Some(flow);
                    push_system(
                        state,
                        "Текущий пароль подтверждён. Введите новый мастер-пароль.",
                    );
                    state.status = "новый мастер-пароль".to_string();
                }
                Err(e) => {
                    push_error(state, &format!("Неверный мастер-пароль: {:#}", e));
                }
            }
        }
        PasswdStage::New => {
            if input.chars().count() < vault::MIN_PASSWORD_LEN {
                push_error(
                    state,
                    &format!(
                        "Пароль должен быть не короче {} символов",
                        vault::MIN_PASSWORD_LEN
                    ),
                );
                state.passwd = Some(flow);
                return;
            }

            flow.new = input;
            flow.stage = PasswdStage::Confirm;
            state.passwd = Some(flow);
            push_system(state, "Повторите новый мастер-пароль.");
            state.status = "повторите новый пароль".to_string();
        }
        PasswdStage::Confirm => {
            if input.as_str() != flow.new.as_str() {
                push_error(state, "Пароли не совпадают — введите новый пароль заново");
                flow.new = Zeroizing::new(String::new());
                flow.stage = PasswdStage::New;
                state.passwd = Some(flow);
                return;
            }

            match app.change_master_password(flow.old.as_str(), flow.new.as_str()) {
                Ok(()) => {
                    push_system(
                        state,
                        "Мастер-пароль изменён. Файлы профиля и база перешифрованы.",
                    );
                    state.status = "мастер-пароль изменён".to_string();
                }
                Err(e) => {
                    push_error(state, &format!("Не удалось сменить мастер-пароль: {:#}", e))
                }
            }
        }
    }
}

/// Открывает модальное меню настроек `/set`.
fn start_settings(app: &App, state: &mut UiState) {
    if state.passwd.is_some() {
        push_error(state, "Сначала завершите смену мастер-пароля");
        return;
    }

    state.settings = Some(SettingsFlow::from_config(&app.get_config()));
    state.input.clear();
    state.cursor = 0;
    state.history_index = None;
    state.history_draft.clear();
    state.dl_cycle = None;
    state.sf_cycle = None;
    state.status = "настройки открыты".to_string();
}

/// Обрабатывает клавиши в модальном окне `/set`.
fn handle_settings_key(app: &App, state: &mut UiState, key: KeyEvent) {
    let (editing, field) = match state.settings.as_ref() {
        Some(flow) => (flow.editing, flow.field()),
        None => return,
    };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

    if editing {
        match key.code {
            KeyCode::Enter => {
                let value = std::mem::take(&mut state.input);
                if let Some(flow) = state.settings.as_mut() {
                    flow.apply_edit(field, &value);
                    flow.editing = false;
                }
                state.cursor = 0;
                state.status = format!("настройки: {} обновлено", field.label());
            }
            KeyCode::Esc => {
                if let Some(flow) = state.settings.as_mut() {
                    flow.editing = false;
                }
                state.input.clear();
                state.cursor = 0;
                state.status = "редактирование отменено".to_string();
            }
            KeyCode::Char(c) if !ctrl => {
                state.input.insert(state.cursor, c);
                state.cursor += c.len_utf8();
            }
            KeyCode::Backspace => {
                if state.cursor > 0 {
                    let prev = prev_char_boundary(&state.input, state.cursor);
                    state.input.remove(prev);
                    state.cursor = prev;
                }
            }
            KeyCode::Delete => {
                if state.cursor < state.input.len() {
                    state.input.remove(state.cursor);
                }
            }
            KeyCode::Left => {
                state.cursor = prev_char_boundary(&state.input, state.cursor);
            }
            KeyCode::Right => {
                state.cursor = next_char_boundary(&state.input, state.cursor);
            }
            KeyCode::Home => state.cursor = 0,
            KeyCode::End => state.cursor = state.input.len(),
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Esc => close_settings(app, state),
        KeyCode::Up | KeyCode::BackTab => {
            if let Some(flow) = state.settings.as_mut() {
                flow.move_selection(-1);
            }
        }
        KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
            if let Some(flow) = state.settings.as_mut() {
                flow.move_selection(-1);
            }
        }
        KeyCode::Down | KeyCode::Tab => {
            if let Some(flow) = state.settings.as_mut() {
                flow.move_selection(1);
            }
        }
        KeyCode::Left => {
            if field.is_notify_level() {
                if let Some(flow) = state.settings.as_mut() {
                    flow.cycle_notify(-1);
                }
            }
        }
        KeyCode::Right => {
            if field.is_notify_level() {
                if let Some(flow) = state.settings.as_mut() {
                    flow.cycle_notify(1);
                }
            }
        }
        KeyCode::Char(' ') => {
            if field.is_notify_level() {
                if let Some(flow) = state.settings.as_mut() {
                    flow.cycle_notify(1);
                }
            }
        }
        KeyCode::Enter => {
            if field.is_notify_level() {
                if let Some(flow) = state.settings.as_mut() {
                    flow.cycle_notify(1);
                }
                return;
            }

            if let Some(flow) = state.settings.as_mut() {
                let value = flow.edit_value(field);
                flow.editing = true;
                state.input = value;
                state.cursor = state.input.len();
                state.history_index = None;
                state.history_draft.clear();
            }
        }
        _ => {}
    }
}

/// Закрывает `/set` с сохранением и немедленным применением настроек.
fn close_settings(app: &App, state: &mut UiState) {
    let Some(flow) = state.settings.take() else {
        return;
    };

    state.input.clear();
    state.cursor = 0;
    state.history_index = None;
    state.history_draft.clear();

    let config = flow.to_config();
    let proxy_note = config
        .proxy_url
        .as_deref()
        .map(|url| format!(" Прокси: {}.", url))
        .unwrap_or_else(|| " Прокси: прямое подключение.".to_string());

    match app.update_config(config) {
        Ok(()) => {
            push_system(
                state,
                &format!(
                    "Настройки сохранены в зашифрованный конфиг и применены.{}",
                    proxy_note
                ),
            );
            state.status = "настройки применены".to_string();
        }
        Err(e) => {
            push_error(
                state,
                &format!("Не удалось сохранить настройки: {:#}", e),
            );
            state.status = "ошибка настроек".to_string();
            state.settings = Some(flow);
        }
    }
}

async fn send_plain_message(app: &Arc<App>, state: &mut UiState, text: &str) {
    if state.room.is_empty() {
        push_error(
            state,
            "Нет активной комнаты. Добавьте контакт через /join <link> или /room <hash>.",
        );
        return;
    }

    match app.send_message(&state.room, text).await {
        Ok(()) => {
            state.feed.push(FeedEntry {
                kind: FeedKind::Outgoing,
                text: format!("[{}] {}", now_time(), text),
            });
            state.follow = true;
            state.status = "сообщение отправлено".to_string();
        }
        Err(e) => push_error(state, &format!("Ошибка отправки: {:#}", e)),
    }
}

fn validated_invite_link(app: &App) -> Result<String> {
    let link = app.get_my_contact_link();
    let ed25519 = link
        .split("ed25519=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .unwrap_or_default();

    let bytes = hex::decode(ed25519)
        .map_err(|e| anyhow!("некорректный ed25519 в ссылке: {}", e))?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "ed25519 в ссылке обрезан: {} hex-символов вместо 64",
            ed25519.len()
        ));
    }

    Ok(link)
}

/// Вставляет текст в однострочное поле ввода (переводы строк → пробелы).
fn insert_text(state: &mut UiState, text: &str) {
    let cleaned: String = text
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();

    state.input.insert_str(state.cursor, &cleaned);
    state.cursor += cleaned.len();
}

fn paste_from_clipboard(state: &mut UiState) {
    let result = match state.clipboard.as_mut() {
        Some(clipboard) => clipboard.get_text(),
        None => Err(arboard::Error::ClipboardNotSupported),
    };

    match result {
        Ok(text) => {
            insert_text(state, &text);
            state.status = "вставлено из буфера обмена".to_string();
        }
        Err(e) => {
            state.status = format!("буфер обмена недоступен: {}", e);
        }
    }
}

/// Записывает текст в буфер обмена.
///
/// На Linux используем `SetExtLinux::wait_until`: процесс остаётся владельцем
/// selection ещё некоторое время, поэтому менеджеры буфера обмена успевают
/// забрать содержимое (и оно не пропадает при вставке в другом окне).
#[cfg(target_os = "linux")]
fn write_clipboard(clipboard: &mut arboard::Clipboard, text: &str) -> Result<()> {
    use arboard::SetExtLinux;
    use std::time::{Duration, Instant};

    clipboard
        .set()
        .wait_until(Instant::now() + Duration::from_millis(300))
        .text(text.to_string())?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn write_clipboard(clipboard: &mut arboard::Clipboard, text: &str) -> Result<()> {
    clipboard.set_text(text.to_string())?;
    Ok(())
}

fn copy_to_clipboard(state: &mut UiState, text: &str) -> Result<()> {
    let result = match state.clipboard.as_mut() {
        Some(clipboard) => write_clipboard(clipboard, text),
        None => Err(anyhow!("буфер обмена недоступен")),
    };

    // Даже при ошибке arboard мог успеть вывести диагностику в stderr.
    state.needs_clear = true;
    result
}

fn invite_file_name(nickname: &str) -> String {
    let safe: String = nickname
        .chars()
        .map(|c| if matches!(c, '/' | '\\' | '\0') { '_' } else { c })
        .collect();
    let safe = safe.trim();
    let safe = if safe.is_empty() { "user" } else { safe };

    format!("{}_lastchance.invite", safe)
}

/// Сохраняет ссылку в файл.
/// - `None` → `./<nickname>_lastchance.invite`;
/// - существующая папка или путь с завершающим `/` → `<dir>/<nickname>_lastchance.invite`;
/// - иначе → указанный путь к файлу.
fn save_invite_file(app: &App, target: Option<&str>, link: &str) -> Result<PathBuf> {
    let file_name = invite_file_name(&app.get_nickname());

    let path = match target {
        None => PathBuf::from(file_name),
        Some(raw) => {
            let candidate = PathBuf::from(raw);
            let dir_hint =
                candidate.is_dir() || raw.ends_with('/') || raw.ends_with('\\');

            if dir_hint {
                std::fs::create_dir_all(&candidate).map_err(|e| {
                    anyhow!("не удалось создать папку {}: {}", candidate.display(), e)
                })?;
                candidate.join(file_name)
            } else {
                candidate
            }
        }
    };

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow!("не удалось создать папку {}: {}", parent.display(), e)
            })?;
        }
    }

    std::fs::write(&path, link)
        .map_err(|e| anyhow!("не удалось записать {}: {}", path.display(), e))?;

    let full = std::fs::canonicalize(&path).or_else(|_| {
        if path.is_absolute() {
            Ok(path.clone())
        } else {
            std::env::current_dir().map(|cwd| cwd.join(&path))
        }
    })?;

    Ok(full)
}

/// Добавляет контакт и открывает с ним активную комнату.
fn apply_join(
    app: &App,
    state: &mut UiState,
    hash: &str,
    x25519: &str,
    nickname: &str,
) -> Result<()> {
    app.add_contact(hash, x25519, nickname)?;
    refresh_chats(app, state);
    switch_to_room(app, state, hash);
    push_system(
        state,
        &format!("Контакт добавлен, активная комната: {}", state.room_label),
    );
    state.status = "контакт добавлен".to_string();
    Ok(())
}

async fn handle_command(
    app: &Arc<App>,
    state: &mut UiState,
    ui_tx: &mpsc::UnboundedSender<UiNotice>,
    line: &str,
) -> Result<bool> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let cmd = normalize_command(parts.first().copied().unwrap_or(""));

    match cmd {
        "/help" => push_system(state, HELP),

        "/profile" => match serde_json::to_string_pretty(&app.get_profile()) {
            Ok(text) => push_system(state, &text),
            Err(e) => push_error(state, &format!("Ошибка сериализации профиля: {}", e)),
        },

        "/seed" => push_system(
            state,
            &format!(
                "Seed-фраза (никому не показывайте):\n{}",
                app.get_seed_phrase()
            ),
        ),

        "/invite" => match validated_invite_link(app) {
            Ok(link) => {
                match copy_to_clipboard(state, &link) {
                    Ok(()) => {
                        push_system(state, "Ссылка приглашения скопирована в буфер обмена")
                    }
                    Err(e) => push_system(
                        state,
                        &format!(
                            "Предупреждение: буфер обмена недоступен ({:#})",
                            e
                        ),
                    ),
                }

                let save_requested = parts.get(1).copied() == Some("-f");
                if save_requested {
                    match save_invite_file(app, parts.get(2).copied(), &link) {
                        Ok(path) => {
                            push_system(
                                state,
                                &format!("Инвайт сохранён: {}", path.display()),
                            );
                            state.status = "инвайт сохранён в файл".to_string();
                        }
                        Err(e) => push_error(
                            state,
                            &format!("Ошибка сохранения инвайта: {:#}", e),
                        ),
                    }
                } else {
                    push_system(state, &format!("Ссылка-приглашение:\n{}", link));
                    state.status = "invite готов".to_string();
                }
            }
            Err(e) => push_error(state, &format!("Ошибка /invite: {:#}", e)),
        },

        "/export" => push_system(state, &app.get_my_contact_json()),

        "/contacts" => match app.get_contacts() {
            Ok(contacts) => {
                if contacts.is_empty() {
                    push_system(state, "Контактов нет. Добавьте через /join <link>");
                } else {
                    let text = contacts
                        .iter()
                        .map(|c| format!("{}  {}", short_hash(&c.hash), c.nickname))
                        .collect::<Vec<_>>()
                        .join("\n");
                    push_system(state, &text);
                }
            }
            Err(e) => push_error(state, &format!("Ошибка получения контактов: {:#}", e)),
        },

        "/join" => {
            let rest: Vec<&str> = parts[1..].to_vec();

            let result = if rest.first().copied() == Some("-f") {
                match rest.get(1) {
                    Some(path) => std::fs::read_to_string(path)
                        .map_err(|e| anyhow!("не удалось прочитать файл {}: {}", path, e))
                        .and_then(|content| {
                            let link = content.trim();
                            parse_contact_link(link).and_then(|(hash, key, nickname)| {
                                apply_join(app, state, &hash, &key, &nickname)
                            })
                        }),
                    None => Err(anyhow!("Использование: /join -f <path>")),
                }
            } else if rest.len() == 1 {
                parse_contact_link(rest[0]).and_then(|(hash, key, nickname)| {
                    apply_join(app, state, &hash, &key, &nickname)
                })
            } else if rest.len() >= 3 && !rest[0].starts_with("lastchance://") {
                apply_join(app, state, rest[0], rest[1], rest[2])
            } else {
                Err(anyhow!(
                    "/join <link>, /join -f <path> или /join <hash> <x25519> <nickname>"
                ))
            };

            if let Err(e) = result {
                push_error(state, &format!("Ошибка /join: {:#}", e));
            }
        }

        "/room" => {
            if let Some(token) = parts.get(1) {
                let hash = resolve_room(app, token);
                switch_to_room(app, state, &hash);
                push_system(
                    state,
                    &format!(
                        "Активная комната: {} ({})",
                        state.room_label,
                        short_hash(&state.room)
                    ),
                );
                state.status = "комната переключена".to_string();
            } else if state.room.is_empty() {
                push_system(state, "Активной комнаты нет. Добавьте контакт через /join <link>");
            } else {
                push_system(
                    state,
                    &format!(
                        "Активная комната: {} ({})",
                        state.room_label,
                        state.room
                    ),
                );
            }
        }

        "/messages" => {
            if state.room.is_empty() {
                push_error(state, "Нет активной комнаты. /join <link>");
                return Ok(false);
            }

            let limit: i64 = parts
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(50)
                .max(1);

            let room = state.room.clone();
            let room_title = state.room_label.clone();
            let nickname = state.nickname.clone();

            match app.get_messages(&room, limit) {
                Ok(messages) => {
                    if messages.is_empty() {
                        push_system(state, "Сообщений в этой комнате нет");
                    } else {
                        for m in messages {
                            let outgoing = m.direction != "in";
                            let dir = if outgoing { "→" } else { "←" };
                            let time = m.timestamp.format("%H:%M:%S").to_string();

                            let line = match parse_file_notification(&m.text) {
                                Some((file_name, file_hash)) => {
                                    let id = register_file(
                                        state,
                                        &room,
                                        &file_name,
                                        &file_hash,
                                        m.timestamp.timestamp(),
                                    );
                                    let sender = if outgoing {
                                        nickname.as_str()
                                    } else {
                                        room_title.as_str()
                                    };
                                    file_feed_line(&time, sender, id, &file_name, outgoing)
                                }
                                None => format!("[{}] {} {}", time, dir, m.text),
                            };
                            push_system(state, &line);
                        }
                    }
                }
                Err(e) => push_error(
                    state,
                    &format!("Ошибка загрузки сообщений: {:#}", e),
                ),
            }
        }

        "/sendfile" => {
            let mut force = false;
            let mut path: Option<&str> = None;

            for arg in parts.iter().skip(1) {
                if *arg == "--force" {
                    force = true;
                } else if path.is_none() {
                    path = Some(*arg);
                } else {
                    push_error(state, "Использование: /sendfile [--force] <path>");
                    return Ok(false);
                }
            }

            let Some(path) = path else {
                push_error(state, "Использование: /sendfile [--force] <path>");
                return Ok(false);
            };
            if state.room.is_empty() {
                push_error(state, "Нет активной комнаты. /join <link>");
                return Ok(false);
            }

            let app_ref = app.clone();
            let room = state.room.clone();
            let path = path.to_string();
            let tx = ui_tx.clone();
            if force {
                push_system(
                    state,
                    "⚠ --force: отправка из системной директории разрешена вручную",
                );
                state.status = format!("отправка файла (--force): {}...", path);
            } else {
                state.status = format!("отправка файла: {}...", path);
            }

            tokio::spawn(async move {
                match app_ref.send_file_native(&room, &path, force).await {
                    Ok(()) => {
                        let _ = tx.send(UiNotice::Status("файл отправлен".to_string()));
                    }
                    Err(e) => {
                        let _ = tx.send(UiNotice::Error(format!(
                            "Ошибка отправки файла: {:#}",
                            e
                        )));
                    }
                }
            });
        }

        "/download" => {
            if state.room.is_empty() {
                push_error(state, "Нет активной комнаты. /join <link>");
                return Ok(false);
            }

            let target = parts.get(1).copied();
            let explicit_path = parts.get(2).copied();

            // Без аргумента — последний полученный файл текущей комнаты.
            let file = match target {
                None => state
                    .files
                    .iter()
                    .filter(|f| f.room_hash == state.room)
                    .max_by_key(|f| f.timestamp)
                    .cloned(),
                Some(token) => find_file(&state.files, &state.room, token).cloned(),
            };

            let Some(file) = file else {
                let message = match target {
                    Some(token) => format!(
                        "Файл «{}» не найден. Tab после /dl — список файлов комнаты",
                        token
                    ),
                    None => "В этой комнате пока нет файлов".to_string(),
                };
                push_error(state, &message);
                return Ok(false);
            };

            let path = match resolve_save_path(explicit_path, &file.file_name) {
                Ok(path) => path,
                Err(e) => {
                    push_error(state, &format!("Не удалось выбрать путь: {:#}", e));
                    return Ok(false);
                }
            };
            let path_display = path.to_string_lossy().to_string();

            let app_ref = app.clone();
            let room = file.room_hash.clone();
            let file_hash = file.file_hash.clone();
            let target_display = format!("#{} {}", file.id, file.file_name);
            let tx = ui_tx.clone();
            state.status = format!("скачивание {}...", target_display);

            tokio::spawn(async move {
                match app_ref
                    .download_and_save_file(&room, &file_hash, &path_display)
                    .await
                {
                    Ok(()) => {
                        let _ = tx.send(UiNotice::Status(format!(
                            "файл {} сохранён в {}",
                            target_display, path_display
                        )));
                    }
                    Err(e) => {
                        let _ = tx.send(UiNotice::Error(format!(
                            "Ошибка скачивания {}: {:#}",
                            target_display, e
                        )));
                    }
                }
            });
        }

        "/nick" => {
            let Some(name) = parts.get(1) else {
                push_error(state, "Использование: /nick <name>");
                return Ok(false);
            };
            match app.update_nickname(name) {
                Ok(()) => {
                    state.nickname = app.get_nickname();
                    push_system(state, &format!("Ник изменён: {}", state.nickname));
                    state.status = "ник изменён".to_string();
                }
                Err(e) => push_error(state, &format!("Ошибка смены ника: {:#}", e)),
            }
        }

        "/rename" => {
            if parts.len() < 3 {
                push_error(state, "Использование: /rename <hash> <name>");
                return Ok(false);
            }
            match app.update_contact_nickname(parts[1], parts[2]) {
                Ok(()) => {
                    refresh_chats(app, state);
                    state.room_label = room_label(app, &state.room);
                    push_system(state, "Контакт переименован");
                    state.status = "контакт переименован".to_string();
                }
                Err(e) => push_error(state, &format!("Ошибка переименования: {:#}", e)),
            }
        }

        "/sidebar" => {
            state.sidebar_visible = !state.sidebar_visible;
            let text = if state.sidebar_visible {
                "Боковая панель включена"
            } else {
                "Боковая панель скрыта"
            };
            push_system(state, text);
            state.status = text.to_lowercase();
        }

        "/set" => match parts.get(1).copied() {
            None => start_settings(app, state),
            Some("notify") => {
                let Some(raw) = parts.get(2).copied() else {
                    let level = app.get_config().notify_level;
                    push_system(
                        state,
                        &format!(
                            "Notify Level: {}\nИспользование: /set notify <0|1|2|3>",
                            notify_level_label(level)
                        ),
                    );
                    return Ok(false);
                };

                let level = match raw.parse::<u8>() {
                    Ok(level) if level <= 3 => level,
                    _ => {
                        push_error(state, "Использование: /set notify <0|1|2|3>");
                        return Ok(false);
                    }
                };

                let mut config = app.get_config();
                config.notify_level = level;
                match app.update_config(config) {
                    Ok(()) => {
                        push_system(
                            state,
                            &format!("Notify Level: {}", notify_level_label(level)),
                        );
                        state.status = "режим уведомлений обновлён".to_string();
                    }
                    Err(e) => push_error(
                        state,
                        &format!("Не удалось сохранить настройки: {:#}", e),
                    ),
                }
            }
            Some("test") => {
                let app_ref = app.clone();
                let tx = ui_tx.clone();
                state.status = "отправка тестового уведомления...".to_string();

                tokio::spawn(async move {
                    let result =
                        tokio::task::spawn_blocking(move || app_ref.send_test_notification())
                            .await;

                    let notice = match result {
                        Ok(Ok(())) => UiNotice::Status(
                            "тестовое уведомление отправлено".to_string(),
                        ),
                        Ok(Err(e)) => {
                            UiNotice::Error(format!("Ошибка уведомления: {:#}", e))
                        }
                        Err(e) => {
                            UiNotice::Error(format!("Ошибка уведомления: {}", e))
                        }
                    };
                    let _ = tx.send(notice);
                });
            }
            Some(_) => push_error(
                state,
                "Использование: /set, /set notify <0|1|2|3> или /set test",
            ),
        },

        "/passwd" => {
            if state.settings.is_some() {
                push_error(state, "Сначала закройте настройки (Esc — сохранить и выйти)");
            } else if state.passwd.is_some() {
                push_error(state, "Смена мастер-пароля уже начата");
            } else {
                state.passwd = Some(PasswdFlow::new());
                state.input.clear();
                state.cursor = 0;
                push_system(
                    state,
                    "Смена мастер-пароля.\nВведите текущий пароль (Esc — отмена).",
                );
                state.status = "введите текущий мастер-пароль".to_string();
            }
        }

        "/quit" | "/exit" => return Ok(true),

        _ => push_error(
            state,
            "Неизвестная команда. Введите /help для списка команд.",
        ),
    }

    Ok(false)
}

// ============================================================
// АРГУМЕНТЫ И ГЛАВНЫЙ ЦИКЛ
// ============================================================

/// Разбирает `--data-dir <path>` (и `--data-dir=<path>`) из argv.
fn parse_data_dir(args: &[String]) -> Result<Option<String>> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == "--data-dir" {
            return match iter.next() {
                Some(path) if !path.trim().is_empty() => Ok(Some(path.clone())),
                _ => Err(anyhow!("--data-dir: не указан непустой путь")),
            };
        }
        if let Some(path) = arg.strip_prefix("--data-dir=") {
            if path.trim().is_empty() {
                return Err(anyhow!("--data-dir: не указан непустой путь"));
            }
            return Ok(Some(path.to_string()));
        }
    }
    Ok(None)
}

fn parse_contact_link(raw: &str) -> Result<(String, String, String)> {
    let params_str = raw
        .strip_prefix("lastchance://contact?")
        .ok_or_else(|| anyhow!("это не ссылка lastchance://contact?..."))?;

    let params: std::collections::HashMap<String, String> =
        url::form_urlencoded::parse(params_str.as_bytes())
            .into_owned()
            .collect();

    let hash = params.get("hash").cloned().unwrap_or_default();
    let x25519 = params.get("x25519").cloned().unwrap_or_default();
    let nickname = params.get("nickname").cloned().unwrap_or_default();

    if hash.is_empty() || x25519.is_empty() || nickname.is_empty() {
        return Err(anyhow!("в ссылке не хватает обязательных параметров"));
    }

    Ok((hash, x25519, nickname))
}

#[allow(clippy::too_many_arguments)]
async fn run_loop(
    tui: &mut Tui,
    app: &Arc<App>,
    state: &mut UiState,
    ui_tx: &mpsc::UnboundedSender<UiNotice>,
    app_events: &mut mpsc::UnboundedReceiver<AppEvent>,
    ui_events: &mut mpsc::UnboundedReceiver<UiNotice>,
    term_events: &mut EventStream,
) -> Result<()> {
    loop {
        if state.needs_clear {
            state.needs_clear = false;
            tui.terminal.clear()?;
        }

        tui.terminal.draw(|frame| draw_ui(frame, state))?;

        tokio::select! {
            maybe_event = term_events.next() => {
                match maybe_event {
                    Some(Ok(event)) => {
                        if handle_terminal_event(app, state, ui_tx, event).await? {
                            return Ok(());
                        }
                    }
                    Some(Err(e)) => {
                        state.status = format!("ошибка терминала: {}", e);
                    }
                    None => return Ok(()),
                }
            }
            maybe_app = app_events.recv() => {
                if let Some(event) = maybe_app {
                    handle_app_event(app, state, event);
                }
            }
            maybe_ui = ui_events.recv() => {
                if let Some(notice) = maybe_ui {
                    apply_notice(state, notice);
                }
            }
        }
    }
}

/// Выключает raw mode после ввода пароля, в том числе при ошибке.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Читает строку без эха, отображая `*` на каждый введённый символ.
fn read_password(prompt: &str) -> Result<Zeroizing<String>> {
    use std::io::Write;

    let mut stdout = io::stdout();
    write!(stdout, "{}", prompt)?;
    stdout.flush()?;

    enable_raw_mode()?;
    let _guard = RawModeGuard;
    let mut password = Zeroizing::new(String::new());

    loop {
        match crossterm::event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                match key.code {
                    KeyCode::Enter => {
                        write!(stdout, "\r\n")?;
                        stdout.flush()?;
                        break;
                    }
                    KeyCode::Esc => {
                        write!(stdout, "\r\n")?;
                        stdout.flush()?;
                        return Err(anyhow!("ввод пароля отменён"));
                    }
                    KeyCode::Char('c') | KeyCode::Char('C') if ctrl => {
                        write!(stdout, "\r\n")?;
                        stdout.flush()?;
                        return Err(anyhow!("ввод пароля прерван"));
                    }
                    KeyCode::Backspace => {
                        if password.pop().is_some() {
                            write!(stdout, "\x08 \x08")?;
                            stdout.flush()?;
                        }
                    }
                    KeyCode::Char(c) => {
                        password.push(c);
                        write!(stdout, "*")?;
                        stdout.flush()?;
                    }
                    _ => {}
                }
            }
            Event::Paste(text) => {
                for c in text.chars().filter(|c| !c.is_control()) {
                    password.push(c);
                    write!(stdout, "*")?;
                }
                stdout.flush()?;
            }
            _ => {}
        }
    }

    Ok(password)
}

/// Запрашивает мастер-пароль и открывает либо создаёт хранилище.
fn unlock_vault(base_dir: &str) -> Result<Vault> {
    if Vault::is_initialized(base_dir)? {
        for _ in 0..3 {
            let password = read_password("Мастер-пароль: ")?;
            match Vault::unlock(base_dir, password.as_str()) {
                Ok(vault) => return Ok(vault),
                Err(e) => eprintln!("{:#}", e),
            }
        }
        Err(anyhow!("не удалось разблокировать профиль"))
    } else {
        println!("Первый запуск: создаётся защищённый профиль LastChance.");
        for _ in 0..3 {
            let password = read_password("Новый мастер-пароль: ")?;
            if password.chars().count() < vault::MIN_PASSWORD_LEN {
                eprintln!(
                    "Пароль должен быть не короче {} символов.",
                    vault::MIN_PASSWORD_LEN
                );
                continue;
            }

            let confirm = read_password("Повторите мастер-пароль: ")?;
            if password.as_str() != confirm.as_str() {
                eprintln!("Пароли не совпадают — попробуйте ещё раз.");
                continue;
            }

            return Vault::create(base_dir, password.as_str());
        }
        Err(anyhow!("не удалось создать мастер-пароль"))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    install_panic_hook();

    let args: Vec<String> = std::env::args().collect();
    let data_dir = parse_data_dir(&args)?;
    let base_dir = get_base_dir_with_override(data_dir.as_deref())?;
    let vault = unlock_vault(&base_dir)?;
    let config = Config::load(&base_dir, &vault)?;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();
    let app = Arc::new(App::new(config, base_dir, vault, event_tx)?);

    // Deep link из argv (Linux/Windows): lastchance://contact?...
    for arg in args.iter().skip(1) {
        if arg.starts_with("lastchance://") {
            app.handle_scheme_url(arg);
        }
    }

    // Фоновый пуллер сообщений.
    {
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(e) = app.start().await {
                eprintln!("App::start: {:#}", e);
            }
        });
    }

    let (ui_tx, mut ui_rx) = mpsc::unbounded_channel::<UiNotice>();
    let mut state = UiState::new(&app);
    let mut tui = Tui::new()?;
    let mut term_events = EventStream::new();

    let result = run_loop(
        &mut tui,
        &app,
        &mut state,
        &ui_tx,
        &mut event_rx,
        &mut ui_rx,
        &mut term_events,
    )
    .await;

    drop(tui);
    result
}
