// Полноэкранный TUI-клиент LastChance.
//
// Архитектура:
//   - tokio Runtime живёт весь процесс (ядро: Listener, Sender, события).
//   - crossterm::event::EventStream и канал AppEvent слушаются в одном
//     `tokio::select!`, поэтому интерфейс остаётся отзывчивым.
//   - Вся отрисовка — ratatui: история чата, статус-бар и поле ввода.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Stdout};
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
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Padding, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use lastchance::cli::{parse_headless_args, parse_profile_dir, HeadlessArgs};
use lastchance::i18n::{tr, Lang, Texts, WelcomeText};
use lastchance::identity::{
    fingerprint_hex, Identity, IdentityInvite, IdentityManager, IDENTITY_FILE_NAME,
};
use lastchance::network::config::notify_level_label;
use lastchance::storage::{
    Storage, LEGACY_DB_FILE_NAME, TOFU_CHANGED, TOFU_PENDING, TOFU_VERIFIED, VAULT_FILE_NAME,
};
use lastchance::types::{parse_file_notification, sanitize_display_text, short_hash};
use lastchance::{get_base_dir_with_override, vault, App, AppEvent, Config, TtlSyncOutcome, Vault};

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
    /// Unix timestamp исчезновения RAM-only сообщения.
    expires_at: Option<u64>,
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
    /// Идентификатор конверта из E2E-уведомления (если оно нового формата).
    file_id: Option<String>,
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
    "/recovery",
    "/invite",
    "/export",
    "/contacts",
    "/cnt",
    "/join",
    "/room",
    "/messages",
    "/ttl",
    "/ttl-syn",
    "/ttl-syn-retry",
    "/ratchet-reset",
    "/sendfile",
    "/download",
    "/nick",
    "/rename",
    "/set",
    "/lang",
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
    /// Открытое модальное окно справки (F1, /help).
    help: Option<HelpFlow>,
    /// Модальное окно восстановления идентичности (`/recovery`).
    recovery: Option<RecoveryFlow>,
    /// Менеджер контактов (`/contacts`, `/cnt`).
    contacts: Option<ContactsFlow>,
    /// Диалог подтверждения импорта подписанного invite.
    pending_import: Option<PendingImport>,
    /// Текущий язык интерфейса.
    lang: Lang,
    /// Активный RAM-TTL текущей комнаты (секунды).
    ttl_seconds: Option<u64>,
    /// Включён ли двусторонний режим `/ttl-syn`.
    ttl_synced: bool,
    /// Двусторонний TTL применён локально, но собеседник не подтвердил.
    ttl_pending: bool,
    /// Приветственное окно выбора языка при первом запуске.
    welcome: Option<WelcomeFlow>,
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
enum RecoveryStage {
    /// Подтверждение текущего мастер-пароля.
    Password,
    /// Просмотр текущей фразы восстановления.
    View,
    /// Явное подтверждение перезаписи `identity.json`.
    Confirm,
    /// Ввод новой мнемонической фразы.
    Input,
}

/// Модальное окно `/recovery`.
/// Фраза хранится в `Zeroizing`, чтобы затираться при закрытии окна.
struct RecoveryFlow {
    stage: RecoveryStage,
    phrase: Zeroizing<String>,
    error: Option<String>,
}

impl RecoveryFlow {
    fn password() -> Self {
        Self {
            stage: RecoveryStage::Password,
            phrase: Zeroizing::new(String::new()),
            error: None,
        }
    }

    fn view(phrase: String) -> Self {
        Self {
            stage: RecoveryStage::View,
            phrase: Zeroizing::new(phrase),
            error: None,
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
    Language,
}

const SETTINGS_FIELDS: [SettingField; 10] = [
    SettingField::ServerUrl,
    SettingField::FileServerUrl,
    SettingField::HeaderName,
    SettingField::HeaderValue,
    SettingField::ProxyUrl,
    SettingField::NotifyLevel,
    SettingField::StealthTitle,
    SettingField::StealthBody,
    SettingField::StealthSeconds,
    SettingField::Language,
];

impl SettingField {
    fn label(self, lang: Lang) -> &'static str {
        let texts = lang.texts();
        match self {
            SettingField::ServerUrl => texts.label_text_api,
            SettingField::FileServerUrl => texts.label_file_api,
            SettingField::HeaderName => texts.label_guard_name,
            SettingField::HeaderValue => texts.label_guard_value,
            SettingField::ProxyUrl => texts.label_proxy,
            SettingField::NotifyLevel => texts.label_notify,
            SettingField::StealthTitle => texts.label_stealth_title,
            SettingField::StealthBody => texts.label_stealth_body,
            SettingField::StealthSeconds => texts.label_stealth_seconds,
            SettingField::Language => texts.label_language,
        }
    }

    /// Поле переключается стрелками/Space, а не редактируется как текст.
    fn is_toggle(self) -> bool {
        matches!(self, SettingField::NotifyLevel | SettingField::Language)
    }

    fn is_masked(self) -> bool {
        matches!(self, SettingField::HeaderValue)
    }
}

/// Модальное окно справки.
/// Содержимое прокручивается внутри рамки, поэтому справка читается
/// полностью даже в небольшом терминале.
struct HelpFlow {
    scroll: u16,
    max_scroll: u16,
    viewport: u16,
}

impl HelpFlow {
    fn new() -> Self {
        Self {
            scroll: 0,
            max_scroll: 0,
            viewport: 1,
        }
    }
}

/// Экран модального окна контактов.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContactsStage {
    List,
    Info,
    /// Переименование: текст и курсор живут в `UiState::input`.
    Rename,
    ConfirmDelete,
}

/// Строка списка контактов с уже расшифрованными данными.
#[derive(Clone)]
struct ContactRow {
    hash: String,
    nickname: String,
    x25519: String,
    ed25519: Option<String>,
    fingerprint: Option<String>,
    tofu_state: String,
    messages: usize,
}

/// Подписанный invite, ожидающий подтверждения пользователем.
struct PendingImport {
    invite: IdentityInvite,
}

/// Модальное окно `/contacts`: список, фильтр, карточка и действия.
struct ContactsFlow {
    stage: ContactsStage,
    rows: Vec<ContactRow>,
    /// Индексы `rows`, прошедшие фильтр.
    filtered: Vec<usize>,
    selected: usize,
    filter: String,
    filter_active: bool,
    /// Краткое уведомление в подвале (копирование, переименование).
    notice: Option<String>,
}

impl ContactsFlow {
    fn new(rows: Vec<ContactRow>) -> Self {
        let mut flow = Self {
            stage: ContactsStage::List,
            rows,
            filtered: Vec::new(),
            selected: 0,
            filter: String::new(),
            filter_active: false,
            notice: None,
        };
        flow.apply_filter();
        flow
    }

    fn apply_filter(&mut self) {
        let needle = self.filter.trim().to_lowercase();
        self.filtered = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, row)| {
                needle.is_empty()
                    || row.nickname.to_lowercase().contains(&needle)
                    || row.hash.to_lowercase().contains(&needle)
            })
            .map(|(index, _)| index)
            .collect();

        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
    }

    fn selected_row(&self) -> Option<&ContactRow> {
        self.filtered
            .get(self.selected)
            .and_then(|index| self.rows.get(*index))
    }

    fn move_selection(&mut self, delta: isize) {
        if self.filtered.is_empty() {
            self.selected = 0;
            return;
        }
        let len = self.filtered.len() as isize;
        self.selected = (self.selected as isize + delta).rem_euclid(len) as usize;
    }

    /// Обновляет строку после успешного переименования.
    fn rename_row(&mut self, hash: &str, nickname: &str) {
        if let Some(row) = self.rows.iter_mut().find(|row| row.hash == hash) {
            row.nickname = nickname.to_string();
        }
        self.apply_filter();
    }

    fn mark_verified(&mut self, hash: &str) {
        if let Some(row) = self.rows.iter_mut().find(|row| row.hash == hash) {
            row.tofu_state = TOFU_VERIFIED.to_string();
        }
    }
}

/// Приветственное окно первого запуска с выбором языка.
struct WelcomeFlow {
    selected: Lang,
}impl WelcomeFlow {
    fn new(selected: Lang) -> Self {
        Self { selected }
    }

    fn toggle(&mut self) {
        self.selected = match self.selected {
            Lang::En => Lang::Ru,
            Lang::Ru => Lang::En,
        };
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
    lang: Lang,
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
            lang: config.lang,
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

    /// Циклически переключает язык и переводит нетронутые stealth-шаблоны.
    fn cycle_lang(&mut self) {
        let next = match self.lang {
            Lang::En => Lang::Ru,
            Lang::Ru => Lang::En,
        };
        if self.stealth_title == self.lang.default_stealth_title() {
            self.stealth_title = next.default_stealth_title().to_string();
        }
        if self.stealth_body == self.lang.default_stealth_body() {
            self.stealth_body = next.default_stealth_body().to_string();
        }
        self.lang = next;
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
            SettingField::Language => self.lang.native_name().to_string(),
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
            SettingField::Language => self.cycle_lang(),
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
                    self.lang.texts().direct_connection.to_string()
                } else {
                    self.proxy_url.clone()
                }
            }
            SettingField::NotifyLevel => self.lang.notify_level_label(self.notify_level).to_string(),
            SettingField::StealthTitle => self.stealth_title.clone(),
            SettingField::StealthBody => self.stealth_body.clone(),
            SettingField::StealthSeconds => self.stealth_seconds.clone(),
            SettingField::Language => self.lang.native_name().to_string(),
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
            lang: self.lang,
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
        let lang = app.get_config().lang;
        let texts = lang.texts();

        // Создаём буфер обмена один раз: пересоздание на каждый вызов
        // приводило к предупреждению arboard «dropped too quickly».
        let (clipboard, status) = match arboard::Clipboard::new() {
            Ok(clipboard) => (Some(clipboard), texts.ready.to_string()),
            Err(e) => (
                None,
                texts.clipboard_unavailable.replacen("{}", &e.to_string(), 1),
            ),
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
            help: None,
            recovery: None,
            contacts: None,
            pending_import: None,
            lang,
            ttl_seconds: None,
            ttl_synced: false,
            ttl_pending: false,
            welcome: None,
        };
        refresh_chats(app, &mut state);
        sync_ttl_state(app, &mut state);
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

/// Текущее Unix-время в секундах.
fn now_unix() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// Обратный отсчёт в формате `mm:ss` (для RAM-only сообщений).
fn ttl_countdown(expires_at: u64, now: u64) -> String {
    let remaining = expires_at.saturating_sub(now);
    format!("{:02}:{:02}", remaining / 60, remaining % 60)
}

/// Синхронизирует UI-поля TTL с RAM-состоянием активной комнаты.
fn sync_ttl_state(app: &App, state: &mut UiState) {
    let ttl = app.get_room_ttl(&state.room);
    state.ttl_seconds = ttl.and_then(|value| value.seconds);
    state.ttl_synced = ttl.map(|value| value.synced).unwrap_or(false);
    state.ttl_pending = ttl.map(|value| value.pending_sync).unwrap_or(false);
}

/// Текст статуса TTL для `/ttl` и `/ttl-syn` без аргумента.
fn ttl_status_text(texts: &Texts, seconds: Option<u64>, pending: bool, synced: bool) -> String {
    match seconds {
        Some(value) if pending => tr(texts.ttl_status_pending, &[&value.to_string()]),
        Some(value) if synced => tr(texts.ttl_status_synced, &[&value.to_string()]),
        Some(value) => tr(texts.ttl_status_on, &[&value.to_string()]),
        None => texts.ttl_status_off.to_string(),
    }
}

/// Бейдж TTL для заголовка активного чата.
fn ttl_badge_for(texts: &Texts, seconds: Option<u64>, pending: bool, synced: bool) -> String {
    let Some(value) = seconds else {
        return String::new();
    };
    let value = value.to_string();
    if pending {
        tr(texts.ttl_badge_pending, &[&value])
    } else if synced {
        tr(texts.ttl_badge_synced, &[&value])
    } else {
        tr(texts.ttl_badge, &[&value])
    }
}

/// Бейдж TTL для заголовка активного чата.
fn ttl_badge(state: &UiState, texts: &Texts) -> String {
    ttl_badge_for(texts, state.ttl_seconds, state.ttl_pending, state.ttl_synced)
}

/// Разбирает аргумент `/ttl` и `/ttl-syn`.
///
/// Поддерживаются суффиксы `s`, `m`, `h`, а также `off`.
/// Голое число трактуется как секунды.
fn parse_ttl_duration(raw: &str) -> Result<Option<u64>> {
    let raw = raw.trim();
    if raw.eq_ignore_ascii_case("off") {
        return Ok(None);
    }

    let (number, multiplier) = match raw.chars().last() {
        Some('s') | Some('S') => (&raw[..raw.len() - 1], 1u64),
        Some('m') | Some('M') => (&raw[..raw.len() - 1], 60u64),
        Some('h') | Some('H') => (&raw[..raw.len() - 1], 3600u64),
        _ => (raw, 1u64),
    };

    let value: u64 = number
        .parse()
        .map_err(|_| anyhow!("invalid TTL duration: {}", raw))?;
    let seconds = value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("TTL duration is too large"))?;

    if seconds == 0 {
        return Err(anyhow!("TTL duration must be positive"));
    }

    Ok(Some(seconds))
}

/// Перерисовывает состояние TTL и удаляет истёкшие сообщения из RAM.
fn tick_ttl(app: &App, state: &mut UiState) {
    let now = now_unix();

    if let Err(e) = app.purge_expired_messages() {
        state.status = tr(
            state.lang.texts().ttl_purge_error,
            &[&format!("{:#}", e)],
        );
    }

    // Удаляем истёкшие строки из UI и затираем их буферы нулями.
    let mut kept = Vec::with_capacity(state.feed.len());
    for entry in std::mem::take(&mut state.feed) {
        if entry
            .expires_at
            .is_some_and(|expires| expires <= now)
        {
            let _ = Zeroizing::new(entry.text);
        } else {
            kept.push(entry);
        }
    }
    state.feed = kept;
    sync_ttl_state(app, state);
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
                    Some(notification) => {
                        let id = register_file(
                            state,
                            &room,
                            &notification.file_name,
                            &notification.file_hash,
                            notification.file_id.as_deref(),
                            m.timestamp.timestamp(),
                        );
                        let sender = if outgoing {
                            nickname.as_str()
                        } else {
                            room_title.as_str()
                        };
                        file_feed_line(
                            &time,
                            sender,
                            id,
                            &notification.file_name,
                            outgoing,
                            state.lang,
                        )
                    }
                    None => format!("[{}] {}", time, m.text),
                };

                FeedEntry {
                    kind,
                    text,
                    expires_at: m.expires_at,
                }
            })
            .collect(),
        Err(e) => vec![FeedEntry {
            kind: FeedKind::Error,
            text: tr(
                state.lang.texts().history_load_failed,
                &[&format!("{:#}", e)],
            ),
            expires_at: None,
        }],
    }
}

/// Регистрирует файл в состоянии сессии и возвращает его короткий номер.
fn register_file(
    state: &mut UiState,
    room_hash: &str,
    file_name: &str,
    file_hash: &str,
    file_id: Option<&str>,
    timestamp: i64,
) -> usize {
    if let Some(existing) = state
        .files
        .iter_mut()
        .find(|f| f.room_hash == room_hash && f.file_hash == file_hash)
    {
        existing.timestamp = timestamp;
        if let Some(file_id) = file_id {
            existing.file_id = Some(file_id.to_string());
        }
        return existing.id;
    }

    state.next_file_id += 1;
    let id = state.next_file_id;
    state.files.push(FileEntry {
        id,
        room_hash: room_hash.to_string(),
        file_hash: file_hash.to_string(),
        file_id: file_id.map(str::to_string),
        file_name: sanitize_display_text(file_name),
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
    lang: Lang,
) -> String {
    let texts = lang.texts();
    let id = id.to_string();
    if outgoing {
        tr(
            texts.file_sent_out,
            &[time, &id, file_name, &id],
        )
    } else {
        tr(
            texts.file_sent_in,
            &[time, sender, &id, file_name, &id],
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
    let base = sanitize_display_text(&base);
    let base = base.trim();

    if base.is_empty() || base == "." || base == ".." {
        "download".to_string()
    } else {
        base.to_string()
    }
}

/// Выбирает путь сохранения: аргумент-папка, аргумент-файл или ./downloads/<name>.
fn resolve_save_path(target: Option<&str>, file_name: &str, lang: Lang) -> Result<PathBuf> {
    let file_name = safe_file_name(file_name);
    let create_failed = lang.texts().create_dir_failed;

    let path = match target.map(str::trim).filter(|s| !s.is_empty()) {
        None => {
            let dir = PathBuf::from("./downloads");
            std::fs::create_dir_all(&dir).map_err(|e| {
                anyhow!(
                    "{}",
                    tr(create_failed, &[&dir.display().to_string(), &e.to_string()])
                )
            })?;
            dir.join(file_name)
        }
        Some(raw) => {
            let candidate = PathBuf::from(raw);
            let looks_like_dir =
                candidate.is_dir() || raw.ends_with('/') || raw.ends_with('\\');

            if looks_like_dir {
                std::fs::create_dir_all(&candidate).map_err(|e| {
                    anyhow!(
                        "{}",
                        tr(
                            create_failed,
                            &[&candidate.display().to_string(), &e.to_string()]
                        )
                    )
                })?;
                candidate.join(file_name)
            } else {
                if let Some(parent) = candidate.parent() {
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            anyhow!(
                                "{}",
                                tr(
                                    create_failed,
                                    &[&parent.display().to_string(), &e.to_string()]
                                )
                            )
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
fn absolute_user_path(raw: &str, lang: Lang) -> Result<PathBuf> {
    let expanded = expand_tilde(raw);
    if expanded.is_absolute() {
        Ok(expanded)
    } else {
        let cwd = std::env::current_dir().map_err(|e| {
            anyhow!(
                "{}",
                tr(lang.texts().cwd_failed, &[&e.to_string()])
            )
        })?;
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
    sync_ttl_state(app, state);
    reload_room(app, state);
}

/// Переключает чат на delta позиций по списку боковой панели.
fn cycle_chat(app: &App, state: &mut UiState, delta: isize) {
    if state.chats.is_empty() {
        refresh_chats(app, state);
    }
    if state.chats.is_empty() {
        state.status = state.lang.texts().status_no_chats.to_string();
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
    state.status = tr(state.lang.texts().status_chat, &[&state.room_label]);
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
        "/cnt" => "/contacts",
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
        "/cnt" => Some("/contacts"),
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
        expires_at: None,
    });
    state.follow = true;
}

fn push_error(state: &mut UiState, text: &str) {
    state.feed.push(FeedEntry {
        kind: FeedKind::Error,
        text: text.to_string(),
        expires_at: None,
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

    let countdown = entry
        .expires_at
        .map(|expires| format!(" [{}]", ttl_countdown(expires, now_unix())));

    entry
        .text
        .split('\n')
        .enumerate()
        .map(|(i, part)| {
            let prefix = if i == 0 { marker } else { "  " };
            let mut spans = vec![
                Span::styled(prefix.to_string(), style),
                Span::styled(part.to_string(), style),
            ];
            if i == 0 {
                if let Some(countdown) = &countdown {
                    spans.push(Span::styled(
                        countdown.clone(),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
            }
            Line::from(spans)
        })
        .collect()
}

fn entry_line_count(entry: &FeedEntry, width: usize) -> usize {
    let width = width.max(1);
    let countdown_len = entry
        .expires_at
        .map(|expires| ttl_countdown(expires, now_unix()).chars().count() + 3) // " [mm:ss]"
        .unwrap_or(0);
    entry
        .text
        .split('\n')
        .enumerate()
        .map(|(index, line)| {
            let mut chars = line.chars().count() + 2; // маркер/отступ
            if index == 0 {
                chars += countdown_len;
            }
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

/// Символ слова для навигации и удаления.
///
/// Unicode-aware: кириллица, латиница, цифры и `_` считаются одним словом,
/// а пробелы и пунктуация — разделителями.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Начало слова слева от `idx`.
///
/// Сначала пропускаем разделители (пробелы, пунктуацию), затем — символы слова.
/// Все позиции остаются на границах UTF-8, поэтому русский текст и эмодзи
/// не приводят к панике при срезе строки.
fn word_left_boundary(s: &str, idx: usize) -> usize {
    let mut idx = idx.min(s.len());
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }

    while let Some((i, c)) = s[..idx].char_indices().next_back() {
        if is_word_char(c) {
            break;
        }
        idx = i;
    }
    while let Some((i, c)) = s[..idx].char_indices().next_back() {
        if !is_word_char(c) {
            break;
        }
        idx = i;
    }
    idx
}

/// Конец слова справа от `idx` (позиция сразу после слова).
///
/// Сначала пропускаем разделители, затем — символы слова.
fn word_right_boundary(s: &str, idx: usize) -> usize {
    let mut idx = idx.min(s.len());
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }

    while let Some(c) = s[idx..].chars().next() {
        if is_word_char(c) {
            break;
        }
        idx += c.len_utf8();
    }
    while let Some(c) = s[idx..].chars().next() {
        if !is_word_char(c) {
            break;
        }
        idx += c.len_utf8();
    }
    idx
}

/// Удаляет слово слева от курсора.
fn delete_word_before(input: &mut String, cursor: &mut usize) {
    let end = (*cursor).min(input.len());
    let start = word_left_boundary(input, end);
    if start < end {
        input.replace_range(start..end, "");
    }
    *cursor = start;
}

/// Удаляет слово справа от курсора.
fn delete_word_after(input: &mut String, cursor: &mut usize) {
    let start = (*cursor).min(input.len());
    let end = word_right_boundary(input, start);
    if end > start {
        input.replace_range(start..end, "");
    }
    *cursor = start;
}

/// Удаляет текст от курсора до начала строки (Ctrl+U).
fn delete_to_line_start(input: &mut String, cursor: &mut usize) {
    let end = (*cursor).min(input.len());
    if end > 0 {
        input.replace_range(..end, "");
    }
    *cursor = 0;
}

/// Удаляет текст от курсора до конца строки (Ctrl+K).
fn delete_to_line_end(input: &mut String, cursor: &mut usize) {
    let at = (*cursor).min(input.len());
    input.truncate(at);
    *cursor = at;
}

fn move_word_left(input: &str, cursor: &mut usize) {
    *cursor = word_left_boundary(input, (*cursor).min(input.len()));
}

fn move_word_right(input: &str, cursor: &mut usize) {
    *cursor = word_right_boundary(input, (*cursor).min(input.len()));
}

/// Применяет клавишу редактирования к однострочному полю ввода.
///
/// Возвращает `true`, если клавиша обработана. Функция используется и
/// основным полем ввода, и редактором значений в `/set`, поэтому поведение
/// сочетаний клавиш везде одинаковое.
fn apply_line_edit_key(state: &mut UiState, key: KeyEvent, ctrl: bool, alt: bool) -> bool {
    match key.code {
        // Удаление слова слева. Ctrl+Backspace в разных терминалах приходит
        // как Backspace+CONTROL, Ctrl+H или Alt+Backspace.
        KeyCode::Backspace if ctrl || alt => {
            delete_word_before(&mut state.input, &mut state.cursor);
        }
        KeyCode::Char('w') | KeyCode::Char('W') if ctrl => {
            delete_word_before(&mut state.input, &mut state.cursor);
        }
        KeyCode::Char('h') | KeyCode::Char('H') if ctrl => {
            delete_word_before(&mut state.input, &mut state.cursor);
        }
        KeyCode::Backspace => {
            if state.cursor > 0 {
                let prev = prev_char_boundary(&state.input, state.cursor);
                state.input.remove(prev);
                state.cursor = prev;
            }
        }

        // Удаление слова справа.
        KeyCode::Delete if ctrl || alt => {
            delete_word_after(&mut state.input, &mut state.cursor);
        }
        KeyCode::Char('d') | KeyCode::Char('D') if alt => {
            delete_word_after(&mut state.input, &mut state.cursor);
        }
        KeyCode::Delete => {
            if state.cursor < state.input.len() {
                state.input.remove(state.cursor);
            }
        }

        // Удаление до начала / до конца строки.
        KeyCode::Char('u') | KeyCode::Char('U') if ctrl => {
            delete_to_line_start(&mut state.input, &mut state.cursor);
        }
        KeyCode::Char('k') | KeyCode::Char('K') if ctrl => {
            delete_to_line_end(&mut state.input, &mut state.cursor);
        }

        // Навигация по словам.
        KeyCode::Left if ctrl || alt => {
            move_word_left(&state.input, &mut state.cursor);
        }
        KeyCode::Char('b') | KeyCode::Char('B') if alt => {
            move_word_left(&state.input, &mut state.cursor);
        }
        KeyCode::Left => {
            state.cursor = prev_char_boundary(&state.input, state.cursor);
        }
        KeyCode::Right if ctrl || alt => {
            move_word_right(&state.input, &mut state.cursor);
        }
        KeyCode::Char('f') | KeyCode::Char('F') if alt => {
            move_word_right(&state.input, &mut state.cursor);
        }
        KeyCode::Right => {
            state.cursor = next_char_boundary(&state.input, state.cursor);
        }

        // Начало / конец строки.
        KeyCode::Home => state.cursor = 0,
        KeyCode::End => state.cursor = state.input.len(),
        KeyCode::Char('a') | KeyCode::Char('A') if ctrl => state.cursor = 0,
        KeyCode::Char('e') | KeyCode::Char('E') if ctrl => {
            state.cursor = state.input.len();
        }

        // Обычный ввод. Alt-сочетания не должны попадать в текст.
        KeyCode::Char(c) if !ctrl && !alt => {
            state.input.insert(state.cursor, c);
            state.cursor += c.len_utf8();
        }
        _ => return false,
    }

    true
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
            state.status = state.lang.texts().comp_force.to_string();
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
        state.status = tr(state.lang.texts().comp_command, &[target]);
        return;
    }

    let matches: Vec<&str> = COMMANDS
        .iter()
        .copied()
        .filter(|command| command.starts_with(&before))
        .collect();

    let texts = state.lang.texts();
    match matches.len() {
        0 => state.status = tr(texts.comp_no_commands, &[&before]),
        1 => {
            let target = matches[0];
            replace_input_before_cursor(state, 0, target);
            state.status = tr(texts.comp_command, &[target]);
        }
        _ => {
            push_system(
                state,
                &tr(texts.comp_matching_commands, &[&matches.join("  ")]),
            );
            state.status = tr(texts.comp_variants, &[&matches.len().to_string()]);
        }
    }
}

fn dl_status(lang: Lang, index: usize, total: usize, label: &str) -> String {
    let texts = lang.texts();
    if total > 1 {
        let current = (index + 1).to_string();
        let total = total.to_string();
        tr(texts.dl_status_many, &[&current, &total, label])
    } else {
        tr(texts.dl_status_one, &[label])
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
            state.status = dl_status(state.lang, index, total, &label);
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
        state.status = state.lang.texts().dl_no_files_room.to_string();
        return;
    }

    let matching: Vec<&FileEntry> = if current.trim().is_empty() {
        files.iter().collect()
    } else {
        files.iter().filter(|f| file_matches(f, &current)).collect()
    };

    if matching.is_empty() {
        state.status = tr(state.lang.texts().dl_no_match, &[&current]);
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
    state.status = dl_status(state.lang, 0, total, &label);
    state.dl_cycle = Some(CompletionCycle {
        start: word_start,
        index: 0,
        candidates,
        labels,
        last_insert: token,
    });
}

fn path_status(lang: Lang, index: usize, total: usize, label: &str) -> String {
    let texts = lang.texts();
    if total > 1 {
        let current = (index + 1).to_string();
        let total = total.to_string();
        tr(texts.path_status_many, &[&current, &total, label])
    } else {
        tr(texts.path_status_one, &[label])
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
                state.status = tr(state.lang.texts().sf_folder, &[&label]);
            } else {
                state.status = path_status(state.lang, index, total, &label);
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
        state.status = state.lang.texts().sf_home.to_string();
        return;
    }

    // Разделяем введённое на уже набранную папку и префикс имени.
    let (dir_part, name_part) = match current.rfind('/') {
        Some(pos) => (&current[..=pos], &current[pos + 1..]),
        None => ("", current.as_str()),
    };

    let dir_for_read = if dir_part.is_empty() { "." } else { dir_part };
    let dir_path = match absolute_user_path(dir_for_read, state.lang) {
        Ok(path) => path,
        Err(e) => {
            state.status = format!("{:#}", e);
            return;
        }
    };

    let entries = match std::fs::read_dir(&dir_path) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            state.status = tr(state.lang.texts().sf_permission, &[&dir_path.display().to_string()]);
            return;
        }
        Err(e) => {
            state.status = tr(state.lang.texts().sf_read_failed, &[&dir_path.display().to_string(), &e.to_string()]);
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
            tr(state.lang.texts().sf_no_files_dir, &[&dir_path.display().to_string()])
        } else {
            tr(state.lang.texts().sf_no_match, &[&current])
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
            let total_text = total.to_string();
            state.status = tr(state.lang.texts().sf_folder_many, &[&label, &total_text]);
        } else {
            state.status = tr(state.lang.texts().sf_folder, &[&label]);
        }
    } else {
        state.status = path_status(state.lang, 0, total, &label);
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
            state.status = tr(state.lang.texts().contacts_fetch_error, &[&format!("{:#}", e)]);
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

    let texts = state.lang.texts();
    match candidates.len() {
        0 => push_system(state, &tr(texts.no_contacts_query, &[&partial])),
        1 => {
            let choice = candidates.remove(0);
            replace_input_before_cursor(state, word_start, &choice);
            state.status = tr(texts.comp_contact, &[&choice]);
        }
        _ => {
            push_system(state, &tr(texts.matching_contacts, &[&candidates.join("\n")]));
            state.status = tr(texts.comp_variants, &[&candidates.len().to_string()]);
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
    let texts = state.lang.texts();
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
            .title(tr(texts.sidebar_title, &[&state.chats.len().to_string()]));
        let inner = block.inner(area);
        let lines = sidebar_lines(state, inner.width as usize);
        frame.render_widget(Paragraph::new(Text::from(lines)).block(block), area);
    }

    let title = if state.room.is_empty() {
        texts.chat_no_room.to_string()
    } else {
        let badge = ttl_badge(state, texts);
        if badge.is_empty() {
            format!(" {} · {} ", state.room_label, short_hash(&state.room))
        } else {
            format!(
                " {} · {}  {} ",
                state.room_label,
                short_hash(&state.room),
                badge
            )
        }
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
        let mode = if flow.editing {
            flow.lang.texts().settings_mode_edit
        } else {
            flow.lang.texts().settings_mode_select
        };
        tr(
            flow.lang.texts().settings_status_bar,
            &[flow.field().label(flow.lang), mode],
        )
    } else if let Some(flow) = state.contacts.as_ref() {
        let total = flow.filtered.len();
        let position = if total == 0 { 0 } else { flow.selected + 1 };
        tr(
            texts.contacts_status_bar,
            &[&position.to_string(), &total.to_string()],
        )
    } else if let Some(flow) = state.recovery.as_ref() {
        let stage = match flow.stage {
            RecoveryStage::Password => texts.recovery_stage_password,
            RecoveryStage::View => texts.recovery_stage_view,
            RecoveryStage::Confirm => texts.recovery_stage_confirm,
            RecoveryStage::Input => texts.recovery_stage_input,
        };
        tr(texts.recovery_status_bar, &[stage])
    } else {
        format!(
            " {}   {}: {}   {} ",
            state.nickname, texts.room_label, room, state.status
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
    let contacts_open = state.contacts.is_some();
    let recovery_password = state
        .recovery
        .as_ref()
        .map(|flow| flow.stage == RecoveryStage::Password)
        .unwrap_or(false);
    let (input_title, masked) = if contacts_open {
        (texts.contacts_input_title.to_string(), false)
    } else if settings_open {
        (texts.settings_input_title.to_string(), false)
    } else if let Some(flow) = state.passwd.as_ref() {
        let title = match flow.stage {
            PasswdStage::Current => texts.passwd_input_current,
            PasswdStage::New => texts.passwd_input_new,
            PasswdStage::Confirm => texts.passwd_input_confirm,
        };
        (title.to_string(), true)
    } else if recovery_password {
        (texts.recovery_input_password_title.to_string(), true)
    } else if state.recovery.is_some() {
        (texts.recovery_input_title.to_string(), false)
    } else {
        (texts.input_title.to_string(), false)
    };
    let input_block = Block::default()
        .borders(Borders::ALL)
        .title(input_title);
    let input_inner = input_block.inner(chunks[2]);
    frame.render_widget(input_block, chunks[2]);

    if settings_open {
        let hint = match state.settings.as_ref() {
            Some(flow) if flow.editing => flow.lang.texts().settings_hint_edit,
            Some(flow) => flow.lang.texts().settings_hint_select,
            None => texts.settings_hint_select,
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                hint,
                Style::default().fg(Color::Gray),
            ))),
            input_inner,
        );
    } else if contacts_open {
        let hint: String = match state.contacts.as_ref() {
            Some(flow) if flow.stage == ContactsStage::Rename => {
                texts.contacts_hint_rename.to_string()
            }
            Some(flow) if flow.stage == ContactsStage::Info => {
                texts.contacts_hint_info.to_string()
            }
            Some(flow) if flow.stage == ContactsStage::ConfirmDelete => {
                texts.contacts_hint_confirm.to_string()
            }
            Some(flow) if flow.filter_active => {
                tr(texts.contacts_hint_filter, &[&flow.filter])
            }
            _ => texts.contacts_hint_list.to_string(),
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate_chars(&hint, input_inner.width as usize),
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
        let visible: String = if state.recovery.is_some() {
            // Ввод и секреты показывает модальное окно восстановления.
            String::new()
        } else if masked {
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
        if state.help.is_none()
            && state.recovery.is_none()
            && state.welcome.is_none()
            && state.contacts.is_none()
            && state.pending_import.is_none()
        {
            frame.set_cursor_position(Position::new(
                cursor_x.min(input_inner.right().saturating_sub(1)),
                cursor_y,
            ));
        }
    }

    if settings_open {
        draw_settings_modal(frame, state);
    }
    if state.help.is_some() {
        draw_help_modal(frame, state);
    }
    if state.recovery.is_some() {
        draw_recovery_modal(frame, state);
    }
    if state.contacts.is_some() {
        draw_contacts_modal(frame, state);
    }
    if state.welcome.is_some() {
        draw_welcome_modal(frame, state);
    }
    if state.pending_import.is_some() {
        draw_import_modal(frame, state);
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
        .title(flow.lang.texts().settings_title);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    const LABEL_WIDTH: usize = 20;
    let mut lines: Vec<Line<'static>> = Vec::with_capacity(SETTINGS_FIELDS.len() + 2);

    for (index, field) in SETTINGS_FIELDS.iter().enumerate() {
        let selected = index == flow.selected;
        let marker = if selected { "▸ " } else { "  " };
        let label = format!(
            "{:<width$}",
            field.label(flow.lang),
            width = LABEL_WIDTH
        );

        let value = if selected && flow.editing && !field.is_toggle() {
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
        flow.lang.texts().settings_modal_hint_edit
    } else {
        flow.lang.texts().settings_modal_hint_select
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

/// Рисует центрированное модальное окно справки поверх TUI.
fn draw_help_modal(frame: &mut Frame, state: &mut UiState) {
    let area = frame.area();
    let rect = help_modal_rect(area);

    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![
            Span::styled(
                state.lang.texts().help_title,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" LastChance ", Style::default().fg(Color::DarkGray)),
        ]))
        .padding(Padding::horizontal(1));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    // Нижняя строка с подсказкой и процентом прокрутки не прокручивается.
    let footer_height = if inner.height > 3 { 1 } else { 0 };
    let content_height = inner.height.saturating_sub(footer_height);
    let content_area = Rect::new(inner.x, inner.y, inner.width, content_height);

    let lines = help_lines(inner.width as usize, state.lang);
    let max_scroll = (lines.len() as u16).saturating_sub(content_height);

    let Some(flow) = state.help.as_mut() else {
        return;
    };
    flow.viewport = content_height.max(1);
    flow.max_scroll = max_scroll;
    flow.scroll = flow.scroll.min(max_scroll);

    frame.render_widget(
        Paragraph::new(Text::from(lines)).scroll((flow.scroll, 0)),
        content_area,
    );

    if footer_height > 0 {
        let percent = if max_scroll == 0 {
            100
        } else {
            (flow.scroll as u32 * 100 / max_scroll as u32).min(100) as u16
        };
        let percent = format!("{:>3}", percent);
        let hint = tr(state.lang.texts().help_footer, &[&percent]);
        let hint = truncate_chars(&hint, inner.width as usize);
        let footer_area = Rect::new(inner.x, inner.bottom().saturating_sub(1), inner.width, 1);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                hint,
                Style::default().fg(Color::DarkGray),
            ))),
            footer_area,
        );
    }
}

/// Рисует модальное окно восстановления идентичности (`/recovery`).
fn draw_recovery_modal(frame: &mut Frame, state: &UiState) {
    let Some(flow) = state.recovery.as_ref() else {
        return;
    };
    let texts = state.lang.texts();

    let area = frame.area();
    let width = 88
        .min(area.width.saturating_sub(2))
        .max(24)
        .min(area.width);
    let height = 20
        .min(area.height.saturating_sub(2))
        .max(10)
        .min(area.height);
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );

    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![
            Span::styled(
                texts.recovery_modal_title,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" /recovery ", Style::default().fg(Color::DarkGray)),
        ]))
        .padding(Padding::horizontal(1));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let mut lines: Vec<Line<'static>> = Vec::new();
    match flow.stage {
        RecoveryStage::Password => {
            lines.push(Line::from(Span::styled(
                texts.recovery_password_prompt,
                Style::default().fg(Color::Gray),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("> {}", "*".repeat(state.input.chars().count())),
                Style::default().fg(Color::White),
            )));
        }
        RecoveryStage::View => {
            lines.push(Line::from(Span::styled(
                texts.recovery_phrase_title,
                Style::default().fg(Color::Gray),
            )));
            lines.push(Line::from(""));
            for chunk in wrap_help_text(&flow.phrase, inner.width.saturating_sub(2) as usize) {
                lines.push(Line::from(Span::styled(
                    chunk,
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                texts.recovery_phrase_warning,
                Style::default().fg(Color::DarkGray),
            )));
        }
        RecoveryStage::Confirm => {
            lines.push(Line::from(Span::styled(
                texts.recovery_confirm_title,
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                texts.recovery_confirm_body,
                Style::default().fg(Color::Gray),
            )));
            lines.push(Line::from(Span::styled(
                texts.recovery_confirm_body2,
                Style::default().fg(Color::Gray),
            )));
        }
        RecoveryStage::Input => {
            lines.push(Line::from(Span::styled(
                texts.recovery_new_phrase,
                Style::default().fg(Color::Gray),
            )));
            lines.push(Line::from(""));
            let max_input = inner.width.saturating_sub(3) as usize;
            // Фраза не отображается даже частично: в альтернативном экране
            // она осталась бы видимой до закрытия окна.
            let masked = "*".repeat(state.input.chars().count().min(max_input.max(1)));
            lines.push(Line::from(Span::styled(
                format!("> {}", masked),
                Style::default().fg(Color::White),
            )));
        }
    }

    if let Some(error) = flow.error.as_ref() {
        lines.push(Line::from(""));
        for chunk in wrap_help_text(error, inner.width.saturating_sub(2) as usize) {
            lines.push(Line::from(Span::styled(chunk, Style::default().fg(Color::Red))));
        }
    }

    lines.push(Line::from(""));
    let hint = match flow.stage {
        RecoveryStage::Password => texts.recovery_hint_password,
        RecoveryStage::View => texts.recovery_hint_view,
        RecoveryStage::Confirm => texts.recovery_hint_confirm,
        RecoveryStage::Input => texts.recovery_hint_input,
    };
    lines.push(Line::from(Span::styled(
        hint,
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(Paragraph::new(Text::from(lines)).wrap(Wrap { trim: false }), inner);
}

/// Рисует модальное окно управления контактами (`/contacts`).
fn draw_contacts_modal(frame: &mut Frame, state: &UiState) {
    let Some(flow) = state.contacts.as_ref() else {
        return;
    };
    let texts = state.lang.texts();

    let area = frame.area();
    let width = 80
        .min(area.width.saturating_sub(2))
        .max(20)
        .min(area.width);
    let height = 26
        .min(area.height.saturating_sub(2))
        .max(10)
        .min(area.height);
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );

    frame.render_widget(Clear, rect);
    let title = if flow.stage == ContactsStage::Info {
        texts.contacts_info_title
    } else {
        texts.contacts_modal_title
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![
            Span::styled(
                title,
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" /contacts ", Style::default().fg(Color::DarkGray)),
        ]))
        .padding(Padding::horizontal(1));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    if flow.stage == ContactsStage::Info {
        draw_contact_info(frame, flow, inner, state.lang);
        return;
    }

    let footer_lines: u16 = if inner.height > 6 { 2 } else { 1 };
    let content_height = inner.height.saturating_sub(footer_lines);
    let mut header_height: u16 = 0;

    // Строка живого фильтра или встроенного переименования.
    if flow.stage == ContactsStage::Rename {
        let prompt = texts.contacts_rename_prompt;
        let text = format!("{}{}", prompt, state.input);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate_chars(&text, inner.width as usize),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ))),
            Rect::new(inner.x, inner.y, inner.width, 1),
        );

        let before = state.input[..state.cursor].chars().count();
        let cursor_x = (inner.x + prompt.chars().count() as u16 + before as u16)
            .min(inner.right().saturating_sub(1));
        frame.set_cursor_position(Position::new(cursor_x, inner.y));
        header_height = 1;
    } else if flow.filter_active || !flow.filter.is_empty() {
        let text = format!("{}{}", texts.contacts_filter_prefix, flow.filter);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                truncate_chars(&text, inner.width as usize),
                Style::default().fg(Color::Yellow),
            ))),
            Rect::new(inner.x, inner.y, inner.width, 1),
        );
        if flow.filter_active {
            let before = flow.filter.chars().count();
            let cursor_x = (inner.x
                + texts.contacts_filter_prefix.chars().count() as u16
                + before as u16)
                .min(inner.right().saturating_sub(1));
            frame.set_cursor_position(Position::new(cursor_x, inner.y));
        }
        header_height = 1;
    }

    let list_height = content_height.saturating_sub(header_height);
    let list_area = Rect::new(
        inner.x,
        inner.y + header_height,
        inner.width,
        list_height,
    );

    let mut lines: Vec<Line<'static>> = Vec::new();
    if flow.filtered.is_empty() {
        let message = if flow.rows.is_empty() {
            texts.contacts_empty.to_string()
        } else {
            tr(texts.contacts_no_matches, &[&flow.filter])
        };
        lines.push(Line::from(Span::styled(
            message,
            Style::default().fg(Color::DarkGray),
        )));
    } else {
        let visible = list_height as usize;
        let offset = if visible > 0 && flow.selected >= visible {
            flow.selected + 1 - visible
        } else {
            0
        };
        let end = (offset + visible).min(flow.filtered.len());

        for position in offset..end {
            let Some(row) = flow
                .filtered
                .get(position)
                .and_then(|index| flow.rows.get(*index))
            else {
                continue;
            };
            let selected = position == flow.selected;
            let marker = if selected { "▸ " } else { "  " };
            let count = tr(texts.contacts_messages, &[&row.messages.to_string()]);
            let text = format!(
                "{}{}  {}  {}",
                marker,
                row.nickname,
                short_hash(&row.hash),
                count
            );
            let style = if selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };
            lines.push(Line::from(Span::styled(
                truncate_chars(&text, list_area.width as usize),
                style,
            )));
        }
    }

    frame.render_widget(Paragraph::new(Text::from(lines)), list_area);

    // Подвал: подтверждение/уведомление и подсказка по клавишам.
    let footer_area = Rect::new(inner.x, inner.bottom().saturating_sub(footer_lines), inner.width, footer_lines);
    let mut footer: Vec<Line<'static>> = Vec::new();

    if footer_lines == 2 {
        if flow.stage == ContactsStage::ConfirmDelete {
            let name = flow
                .selected_row()
                .map(|row| row.nickname.as_str())
                .unwrap_or("?");
            footer.push(Line::from(Span::styled(
                truncate_chars(
                    &tr(texts.contacts_delete_confirm, &[name]),
                    inner.width as usize,
                ),
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )));
        } else if let Some(notice) = flow.notice.as_deref() {
            footer.push(Line::from(Span::styled(
                truncate_chars(notice, inner.width as usize),
                Style::default().fg(Color::Yellow),
            )));
        } else {
            footer.push(Line::from(""));
        }
    }

    let hint = if flow.stage == ContactsStage::ConfirmDelete {
        texts.contacts_hint_confirm.to_string()
    } else if flow.stage == ContactsStage::Rename {
        texts.contacts_hint_rename.to_string()
    } else if flow.filter_active {
        tr(texts.contacts_hint_filter, &[&flow.filter])
    } else {
        texts.contacts_hint_list.to_string()
    };
    footer.push(Line::from(Span::styled(
        truncate_chars(&hint, inner.width as usize),
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(Paragraph::new(Text::from(footer)), footer_area);
}

/// Карточка контакта (`i`): полные ключи и статистика.
fn draw_contact_info(frame: &mut Frame, flow: &ContactsFlow, inner: Rect, lang: Lang) {
    let Some(row) = flow.selected_row() else {
        return;
    };
    let texts = lang.texts();
    let width = inner.width.max(1) as usize;

    let missing = texts.contacts_info_ed25519_missing.to_string();
    let fingerprint = row
        .fingerprint
        .as_deref()
        .map(group_fingerprint)
        .unwrap_or_else(|| texts.contacts_info_none.to_string());
    let fields: [(&str, String); 7] = [
        (texts.contacts_info_name, row.nickname.clone()),
        (texts.contacts_info_hash, row.hash.clone()),
        (texts.contacts_info_fingerprint, fingerprint),
        (texts.contacts_info_tofu, tofu_label(lang, &row.tofu_state)),
        (texts.contacts_info_x25519, row.x25519.clone()),
        (
            texts.contacts_info_ed25519,
            row.ed25519.clone().unwrap_or(missing),
        ),
        (
            texts.contacts_info_messages,
            row.messages.to_string(),
        ),
    ];

    let footer_lines: u16 = if inner.height > 4 { 2 } else { 1 };
    let content_height = inner.height.saturating_sub(footer_lines);
    let content_area = Rect::new(inner.x, inner.y, inner.width, content_height);

    let mut lines: Vec<Line<'static>> = Vec::new();
    for (template, value) in fields {
        let text = tr(template, &[&value]);
        let styled = Style::default().fg(Color::Gray);
        for chunk in wrap_help_text(&text, width) {
            lines.push(Line::from(Span::styled(chunk, styled)));
        }
        lines.push(Line::from(""));
    }

    frame.render_widget(Paragraph::new(Text::from(lines)), content_area);

    let footer_area = Rect::new(
        inner.x,
        inner.bottom().saturating_sub(footer_lines),
        inner.width,
        footer_lines,
    );
    let mut footer = vec![Line::from("")];
    footer.push(Line::from(Span::styled(
        texts.contacts_hint_info,
        Style::default().fg(Color::DarkGray),
    )));
    if footer_lines == 1 {
        footer.remove(0);
    }
    frame.render_widget(Paragraph::new(Text::from(footer)), footer_area);
}

/// Диалог подтверждения импорта подписанного invite.
fn draw_import_modal(frame: &mut Frame, state: &UiState) {
    let Some(pending) = state.pending_import.as_ref() else {
        return;
    };
    let invite = &pending.invite;
    let texts = state.lang.texts();

    let area = frame.area();
    let width = 88
        .min(area.width.saturating_sub(2))
        .max(20)
        .min(area.width);
    let height = 24
        .min(area.height.saturating_sub(2))
        .max(10)
        .min(area.height);
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );

    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(Span::styled(
            texts.import_title,
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )))
        .padding(Padding::horizontal(1));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let fields = [
        (texts.import_nickname, invite.display_nickname()),
        (texts.import_hash, invite.hash_hex()),
        (
            texts.import_fingerprint,
            group_fingerprint(&invite.fingerprint_hex()),
        ),
        (
            texts.import_x25519,
            hex::encode(invite.doc.x25519_pub),
        ),
        (
            texts.import_ed25519,
            hex::encode(invite.doc.ed25519_pub),
        ),
    ];

    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(Span::styled(
        texts.import_intro,
        Style::default().fg(Color::Yellow),
    )));
    lines.push(Line::from(""));
    for (template, value) in fields {
        let text = tr(template, &[&value]);
        for chunk in wrap_help_text(&text, inner.width.max(1) as usize) {
            lines.push(Line::from(Span::styled(
                chunk,
                Style::default().fg(Color::Gray),
            )));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        texts.import_hint,
        Style::default().fg(Color::DarkGray),
    )));

    frame.render_widget(Paragraph::new(Text::from(lines)), inner);
}

fn tofu_label(lang: Lang, state: &str) -> String {
    let texts = lang.texts();
    match state {
        TOFU_VERIFIED => texts.contacts_tofu_verified.to_string(),
        TOFU_CHANGED => texts.contacts_tofu_changed.to_string(),
        TOFU_PENDING => texts.contacts_tofu_pending.to_string(),
        other => other.to_string(),
    }
}

/// Рисует приветственное окно первого запуска с выбором языка.
fn draw_welcome_modal(frame: &mut Frame, state: &UiState) {
    let Some(welcome) = state.welcome.as_ref() else {
        return;
    };

    let area = frame.area();
    let width = 96
        .min(area.width.saturating_sub(2))
        .max(24)
        .min(area.width);
    let height = 13
        .min(area.height.saturating_sub(2))
        .max(10)
        .min(area.height);
    let rect = Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    );

    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(vec![
            Span::styled(
                " LastChance ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                welcome.selected.welcome_text().title,
                Style::default().fg(Color::DarkGray),
            ),
        ]))
        .padding(Padding::horizontal(1));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let columns = Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);
    let footer_height = 1;
    let body_height = inner.height.saturating_sub(footer_height);
    let body = Rect::new(inner.x, inner.y, inner.width, body_height);

    for (index, lang) in [Lang::En, Lang::Ru].iter().enumerate() {
        let selected = *lang == welcome.selected;
        let text = lang.welcome_text();
        let lines = welcome_lines(text, selected, columns[index].width as usize);
        let style = if selected {
            Style::default().bg(Color::DarkGray).fg(Color::White)
        } else {
            Style::default().fg(Color::Gray)
        };
        let column = Rect::new(
            columns[index].x,
            body.y,
            columns[index].width,
            body.height,
        );
        frame.render_widget(
            Paragraph::new(Text::from(lines))
                .style(style)
                .wrap(Wrap { trim: false }),
            column,
        );
    }

    let footer_area = Rect::new(
        inner.x,
        inner.bottom().saturating_sub(footer_height),
        inner.width,
        footer_height,
    );
    let footer_text = format!(
        " [1] English   [2] {}   ·   {} ",
        Lang::Ru.native_name(),
        welcome.selected.welcome_text().footer
    );
    let footer_text = truncate_chars(&footer_text, inner.width as usize);
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            footer_text,
            Style::default().fg(Color::Yellow),
        ))),
        footer_area,
    );
}

/// Строки одной колонки приветственного окна.
fn welcome_lines(text: &WelcomeText, selected: bool, width: usize) -> Vec<Line<'static>> {
    let marker = if selected { "▸ " } else { "  " };
    let title = format!("{}{}", marker, text.title);
    let mut lines = vec![
        Line::from(Span::styled(
            truncate_chars(&title, width),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(truncate_chars(text.subtitle, width)),
        Line::from(""),
        Line::from(truncate_chars(text.settings, width)),
        Line::from(truncate_chars(text.help, width)),
        Line::from(truncate_chars(text.language, width)),
    ];
    // Держим обе колонки одинаковой высоты независимо от длины строк.
    while lines.len() < 8 {
        lines.push(Line::from(""));
    }
    lines
}

fn help_modal_rect(area: Rect) -> Rect {
    let width = 92
        .min(area.width.saturating_sub(2))
        .max(20)
        .min(area.width);
    let height = 36
        .min(area.height.saturating_sub(2))
        .max(8)
        .min(area.height);
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

/// Собирает содержимое справки в две колонки: команда/алиас и описание.
fn help_lines(width: usize, lang: Lang) -> Vec<Line<'static>> {
    const MAX_KEY_WIDTH: usize = 36;
    let key_width = (width * 45 / 100).clamp(8, MAX_KEY_WIDTH);
    let desc_width = width.saturating_sub(key_width + 2).max(1);
    let texts = lang.texts();

    let mut lines: Vec<Line<'static>> = Vec::new();
    let header = format!("{:<key_width$}", texts.help_table_key);
    lines.push(Line::from(vec![
        Span::styled(
            header,
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            texts.help_table_desc,
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
    ]));

    for (index, section) in lang.help_sections().iter().enumerate() {
        if index > 0 {
            lines.push(Line::from(""));
        }
        lines.push(Line::from(Span::styled(
            format!(" {} ", section.title),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));

        for row in section.rows {
            for (chunk_index, chunk) in wrap_help_text(row.desc, desc_width).iter().enumerate() {
                let key = if chunk_index == 0 {
                    truncate_chars(row.keys, key_width)
                } else {
                    String::new()
                };
                let key_cell = format!("{:<key_width$}", key);
                lines.push(Line::from(vec![
                    Span::styled(key_cell, Style::default().fg(Color::Yellow)),
                    Span::raw("  "),
                    Span::styled(chunk.clone(), Style::default().fg(Color::Gray)),
                ]));
            }
        }
    }

    lines
}

/// Переносит описание по словам, чтобы таблица оставалась читаемой
/// в узком терминале.
fn wrap_help_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();

    for word in text.split_whitespace() {
        let word_len = word.chars().count();
        if current.is_empty() {
            if word_len > width {
                let mut rest = word;
                while rest.chars().count() > width {
                    let chunk: String = rest.chars().take(width).collect();
                    rest = &rest[chunk.len()..];
                    lines.push(chunk);
                }
                current = rest.to_string();
            } else {
                current.push_str(word);
            }
        } else if current.chars().count() + 1 + word_len <= width {
            current.push(' ');
            current.push_str(word);
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
        }
    }

    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn truncate_chars(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let mut shortened: String = text.chars().take(width.saturating_sub(1)).collect();
    shortened.push('…');
    shortened
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
            is_ephemeral: _,
            expires_at,
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
                if let Some(notification) = incoming_file {
                    let file_name = notification.file_name;
                    let file_hash = notification.file_hash;
                    let file_id = notification.file_id;
                    let id = register_file(
                        state,
                        &room_hash,
                        &file_name,
                        &file_hash,
                        file_id.as_deref(),
                        timestamp,
                    );
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
                            state.lang,
                        ),
                        expires_at,
                    });
                    state.status = tr(state.lang.texts().new_file_status, &[&id.to_string(), &file_name, &id.to_string()]);
                } else {
                    state.feed.push(FeedEntry {
                        kind: FeedKind::Incoming,
                        text: format!("[{}] {}: {}", event_time(timestamp), sender, text),
                        expires_at,
                    });
                    state.status = tr(state.lang.texts().new_message_status, &[&sender]);
                }
                state.follow = true;
            } else {
                ensure_chat_entry(state, &room_hash, &sender);
                let count = state.unread.entry(room_hash.clone()).or_insert(0);
                *count += 1;
                let count = *count;

                let file_note = match incoming_file {
                    Some(notification) => {
                        let id = register_file(
                            state,
                            &room_hash,
                            &notification.file_name,
                            &notification.file_hash,
                            notification.file_id.as_deref(),
                            timestamp,
                        );
                        tr(
                            state.lang.texts().unread_file_note,
                            &[&id.to_string(), &notification.file_name],
                        )
                    }
                    None => String::new(),
                };

                state.status = tr(
                    state.lang.texts().unread_message,
                    &[
                        &sender,
                        &room_label(app, &room_hash),
                        &count.to_string(),
                        &file_note,
                    ],
                );
            }

            if should_notify {
                notify_incoming(app, &sender, &text, notify_unread);
            }
        }
        AppEvent::TtlChanged {
            room_hash,
            seconds,
            from_peer,
        } => {
            if room_hash == state.room {
                sync_ttl_state(app, state);
            }

            let texts = state.lang.texts();
            let message = match (seconds, from_peer) {
                (Some(value), true) => {
                    tr(texts.ttl_peer_enabled, &[&value.to_string()])
                }
                (None, true) => texts.ttl_peer_disabled.to_string(),
                (Some(value), false) => {
                    tr(texts.ttl_self_enabled, &[&value.to_string()])
                }
                (None, false) => texts.ttl_self_disabled.to_string(),
            };
            push_system(state, &message);
            state.status = message;
        }
        AppEvent::ContactImport { invite } => {
            open_import_dialog(state, invite);
        }
        AppEvent::ContactImportError { error } => {
            push_error(state, &tr(state.lang.texts().contact_import_error, &[&error]));
        }
        AppEvent::UploadStarted { file_name } => {
            push_system(state, &tr(state.lang.texts().upload_started, &[&file_name]));
            state.status = state.lang.texts().upload_started_status.to_string();
        }
        AppEvent::UploadProgress { status, progress } => {
            state.status = tr(state.lang.texts().upload_progress, &[&progress.to_string(), &status]);
        }
        AppEvent::UploadCompleted {
            file_name,
            file_hash,
            file_id,
            file_size,
        } => {
            let room = state.room.clone();
            let id = register_file(
                state,
                &room,
                &file_name,
                &file_hash,
                Some(&file_id),
                chrono::Utc::now().timestamp(),
            );
            let size = file_size
                .map(|s| tr(state.lang.texts().upload_size, &[&s.to_string()]))
                .unwrap_or_default();
            let hint = if room.is_empty() {
                String::new()
            } else {
                tr(state.lang.texts().upload_download_hint, &[&id.to_string()])
            };
            push_system(
                state,
                &tr(
                    state.lang.texts().upload_done,
                    &[
                        &id.to_string(),
                        &file_name,
                        &short_hash(&file_hash),
                        &size,
                        &hint,
                    ],
                ),
            );
            state.status = tr(state.lang.texts().upload_done_status, &[&id.to_string()]);
        }
        AppEvent::UploadError { error } => {
            push_error(state, &tr(state.lang.texts().upload_error, &[&error]));
        }
        AppEvent::DownloadStarted => {
            state.status = state.lang.texts().download_started_status.to_string();
        }
        AppEvent::DownloadCompleted { file_path } => {
            push_system(state, &tr(state.lang.texts().download_completed, &[&file_path]));
            state.status = state.lang.texts().download_completed_status.to_string();
        }
        AppEvent::DownloadError { error } => {
            push_error(state, &tr(state.lang.texts().download_failed, &[&error]));
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

/// Разрешена ли вставка из буфера в текущем состоянии интерфейса.
fn can_paste(state: &UiState) -> bool {
    if let Some(flow) = state.contacts.as_ref() {
        return flow.stage == ContactsStage::Rename;
    }
    if let Some(flow) = state.settings.as_ref() {
        return flow.editing;
    }
    match state.recovery.as_ref() {
        Some(flow) => matches!(flow.stage, RecoveryStage::Password | RecoveryStage::Input),
        None => true,
    }
}

fn clear_input(state: &mut UiState) {
    state.input.clear();
    state.cursor = 0;
    state.history_index = None;
    state.history_draft.clear();
}

/// Начинает восстановление идентичности: сначала спрашиваем мастер-пароль.
fn start_recovery(state: &mut UiState) {
    if state.settings.is_some() {
        push_error(state, state.lang.texts().settings_first_close);
    } else if state.passwd.is_some() {
        push_error(state, state.lang.texts().settings_first_finish_password);
    } else if state.recovery.is_some() {
        push_error(state, state.lang.texts().recovery_already_open);
    } else {
        clear_input(state);
        state.recovery = Some(RecoveryFlow::password());
        push_system(state, state.lang.texts().recovery_prompt);
        state.status = state.lang.texts().recovery_enter_password.to_string();
    }
}

/// Обрабатывает клавиши в модальном окне `/recovery`.
fn handle_recovery_key(app: &App, state: &mut UiState, key: KeyEvent) {
    let Some(stage) = state.recovery.as_ref().map(|flow| flow.stage) else {
        return;
    };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    if key.code == KeyCode::Esc {
        state.recovery = None;
        clear_input(state);
        state.status = state.lang.texts().recovery_closed.to_string();
        return;
    }

    match stage {
        RecoveryStage::Password => match key.code {
            KeyCode::Enter => {
                let password = Zeroizing::new(std::mem::take(&mut state.input));
                state.cursor = 0;
                match app.verify_master_password(password.as_str()) {
                    Ok(()) => {
                        state.recovery = Some(RecoveryFlow::view(app.get_seed_phrase()));
                        state.status = state.lang.texts().recovery_password_ok.to_string();
                    }
                    Err(e) => {
                        if let Some(flow) = state.recovery.as_mut() {
                            flow.error = Some(tr(
                                state.lang.texts().recovery_wrong_password,
                                &[&format!("{:#}", e)],
                            ));
                        }
                        state.status = state.lang.texts().recovery_password_bad_status.to_string();
                    }
                }
            }
            _ => {
                apply_line_edit_key(state, key, ctrl, alt);
            }
        },
        RecoveryStage::View => match key.code {
            KeyCode::Tab | KeyCode::Char('r') | KeyCode::Char('R') => {
                if let Some(flow) = state.recovery.as_mut() {
                    flow.stage = RecoveryStage::Confirm;
                    flow.error = None;
                }
                clear_input(state);
                state.status = state.lang.texts().recovery_confirm_request.to_string();
            }
            _ => {}
        },
        RecoveryStage::Confirm => {
            if key.code == KeyCode::Enter {
                if let Some(flow) = state.recovery.as_mut() {
                    flow.stage = RecoveryStage::Input;
                    flow.error = None;
                }
                clear_input(state);
                state.status = state.lang.texts().recovery_enter_new.to_string();
            }
        }
        RecoveryStage::Input => match key.code {
            KeyCode::Enter => {
                let phrase = Zeroizing::new(std::mem::take(&mut state.input));
                state.cursor = 0;
                match app.restore_identity_from_mnemonic(phrase.as_str()) {
                    Ok(hash) => {
                        state.recovery = Some(RecoveryFlow::view(app.get_seed_phrase()));
                        push_system(
                            state,
                            &tr(
                                state.lang.texts().recovery_restored,
                                &[&short_hash(&hash)],
                            ),
                        );
                        state.status =
                            state.lang.texts().recovery_restored_status.to_string();
                    }
                    Err(e) => {
                        if let Some(flow) = state.recovery.as_mut() {
                            flow.error = Some(format!("{:#}", e));
                        }
                        state.status = state.lang.texts().recovery_invalid_phrase.to_string();
                    }
                }
            }
            _ => {
                apply_line_edit_key(state, key, ctrl, alt);
            }
        },
    }
}

/// Обрабатывает клавиши приветственного окна выбора языка.
fn handle_welcome_key(app: &App, state: &mut UiState, key: KeyEvent) {
    let Some(welcome) = state.welcome.as_ref() else {
        return;
    };

    if key.code == KeyCode::Enter {
        let selected = welcome.selected;
        let mut config = app.get_config();
        config.apply_lang(selected);
        match app.update_config(config) {
            Ok(()) => {
                state.lang = selected;
                state.welcome = None;
                let message = tr(selected.texts().welcome_saved, &[selected.native_name()]);
                state.status = message.clone();
                push_system(state, &message);
            }
            Err(e) => {
                state.status = tr(
                    selected.texts().welcome_save_error,
                    &[&format!("{:#}", e)],
                );
            }
        }
        return;
    }

    let selected = {
        let Some(welcome) = state.welcome.as_mut() else {
            return;
        };
        match key.code {
            KeyCode::Left => welcome.selected = Lang::En,
            KeyCode::Right => welcome.selected = Lang::Ru,
            KeyCode::Char('1') => welcome.selected = Lang::En,
            KeyCode::Char('2') => welcome.selected = Lang::Ru,
            KeyCode::Tab | KeyCode::BackTab => welcome.toggle(),
            _ => return,
        }
        welcome.selected
    };

    // Подсказка в статус-баре сразу отражает выбранную подсветку.
    state.status = selected.texts().welcome_status.to_string();
}

/// Открывает модальное окно справки.
fn open_help(state: &mut UiState) {
    state.help = Some(HelpFlow::new());
    state.status = state.lang.texts().help_status_open.to_string();
}

/// Переключает модальное окно справки (F1).
fn toggle_help(state: &mut UiState) {
    if state.help.is_some() {
        state.help = None;
        state.status = state.lang.texts().help_status_closed.to_string();
    } else {
        open_help(state);
    }
}

/// Обрабатывает клавиши внутри открытой справки.
fn handle_help_key(state: &mut UiState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
            state.help = None;
            state.status = state.lang.texts().help_status_closed.to_string();
            return;
        }
        _ => {}
    }

    let Some(flow) = state.help.as_mut() else {
        return;
    };
    let page = flow.viewport.max(1);
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => {
            flow.scroll = flow.scroll.saturating_sub(1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            flow.scroll = flow.scroll.saturating_add(1).min(flow.max_scroll);
        }
        KeyCode::PageUp => {
            flow.scroll = flow.scroll.saturating_sub(page);
        }
        KeyCode::PageDown => {
            flow.scroll = flow.scroll.saturating_add(page).min(flow.max_scroll);
        }
        KeyCode::Home => flow.scroll = 0,
        KeyCode::End => flow.scroll = flow.max_scroll,
        _ => {}
    }
}

/// Загружает контакты для модального окна вместе с числом сообщений.
fn load_contact_rows(app: &App) -> Result<Vec<ContactRow>> {
    let contacts = app.get_contacts()?;
    let mut rows = Vec::with_capacity(contacts.len());

    for contact in contacts {
        if contact.hash == app.identity.hash {
            continue;
        }

        let messages = app
            .count_contact_messages(&contact.hash)
            .unwrap_or(0);

        let computed_fingerprint = contact
            .ed25519
            .as_deref()
            .and_then(|value| hex::decode(value).ok())
            .and_then(|value| <[u8; 32]>::try_from(value).ok())
            .and_then(|ed25519| {
                let x25519 = <[u8; 32]>::try_from(contact.public_key.as_slice()).ok()?;
                Some(fingerprint_hex(&ed25519, &x25519))
            });

        rows.push(ContactRow {
            x25519: hex::encode(&contact.public_key),
            ed25519: contact.ed25519,
            fingerprint: contact.fingerprint.or(computed_fingerprint),
            tofu_state: contact.tofu_state,
            hash: contact.hash,
            nickname: contact.nickname,
            messages,
        });
    }

    Ok(rows)
}

/// Открывает модальное окно `/contacts`.
fn open_contacts(app: &App, state: &mut UiState) {
    clear_input(state);

    match load_contact_rows(app) {
        Ok(rows) => {
            // Пустой список отрисовывается подсказкой в самом окне.
            state.contacts = Some(ContactsFlow::new(rows));
        }
        Err(e) => push_error(
            state,
            &tr(
                state.lang.texts().contacts_error,
                &[&format!("{:#}", e)],
            ),
        ),
    }
}

/// Закрывает модальное окно контактов.
fn close_contacts(state: &mut UiState) {
    state.contacts = None;
    clear_input(state);
    state.status = state.lang.texts().contacts_closed.to_string();
}

/// Отпечаток контакта для копирования и сверки вне канала.
fn contact_fingerprint(row: &ContactRow) -> Option<String> {
    row.fingerprint.as_deref().map(group_fingerprint)
}

fn group_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Возвращает актуальный список контактов в открытое окно, сохраняя фильтр.
fn reload_contacts_modal(app: &App, state: &mut UiState) {
    let Some(flow) = state.contacts.as_mut() else {
        return;
    };
    let selected_hash = flow.selected_row().map(|row| row.hash.clone());
    let filter = flow.filter.clone();
    let filter_active = flow.filter_active;
    let stage = flow.stage;

    match load_contact_rows(app) {
        Ok(rows) => {
            let Some(flow) = state.contacts.as_mut() else {
                return;
            };
            flow.rows = rows;
            flow.filter = filter;
            flow.filter_active = filter_active;
            flow.stage = stage;
            flow.apply_filter();

            if let Some(hash) = selected_hash {
                if let Some(position) = flow
                    .filtered
                    .iter()
                    .position(|index| flow.rows[*index].hash == hash)
                {
                    flow.selected = position;
                }
            }
        }
        Err(e) => {
            let message = format!("{:#}", e);
            let flow = state.contacts.as_mut();
            if let Some(flow) = flow {
                flow.notice = Some(tr(state.lang.texts().contacts_error, &[&message]));
            }
        }
    }
}

/// Действия списка, которым нужен доступ к `App`/`UiState` вне заимствования.
enum ContactsAction {
    None,
    Close,
    Open(ContactRow),
    Rename(ContactRow),
    Info,
    Copy(ContactRow),
    ConfirmDelete,
}

fn handle_contacts_list_key(app: &App, state: &mut UiState, key: KeyEvent, ctrl: bool) {
    let action = match key.code {
        KeyCode::Esc => {
            let has_filter = state
                .contacts
                .as_ref()
                .map(|flow| !flow.filter.is_empty())
                .unwrap_or(false);
            if has_filter {
                if let Some(flow) = state.contacts.as_mut() {
                    flow.filter.clear();
                    flow.filter_active = false;
                    flow.selected = 0;
                    flow.apply_filter();
                }
                ContactsAction::None
            } else {
                ContactsAction::Close
            }
        }
        KeyCode::Char('q') => ContactsAction::Close,
        KeyCode::Up | KeyCode::Char('k') => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.move_selection(-1);
            }
            ContactsAction::None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.move_selection(1);
            }
            ContactsAction::None
        }
        KeyCode::Home => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.selected = 0;
            }
            ContactsAction::None
        }
        KeyCode::End => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.selected = flow.filtered.len().saturating_sub(1);
            }
            ContactsAction::None
        }
        KeyCode::Char('/') => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.filter.clear();
                flow.filter_active = true;
                flow.selected = 0;
                flow.apply_filter();
            }
            ContactsAction::None
        }
        KeyCode::Enter => state
            .contacts
            .as_ref()
            .and_then(ContactsFlow::selected_row)
            .cloned()
            .map(ContactsAction::Open)
            .unwrap_or(ContactsAction::None),
        KeyCode::Char('r') => state
            .contacts
            .as_ref()
            .and_then(ContactsFlow::selected_row)
            .cloned()
            .map(ContactsAction::Rename)
            .unwrap_or(ContactsAction::None),
        KeyCode::Char('i') => ContactsAction::Info,
        KeyCode::Char('c') if !ctrl => state
            .contacts
            .as_ref()
            .and_then(ContactsFlow::selected_row)
            .cloned()
            .map(ContactsAction::Copy)
            .unwrap_or(ContactsAction::None),
        KeyCode::Char('d') if !ctrl => ContactsAction::ConfirmDelete,
        _ => ContactsAction::None,
    };

    match action {
        ContactsAction::None => {}
        ContactsAction::Close => close_contacts(state),
        ContactsAction::Open(row) => {
            switch_to_room(app, state, &row.hash);
            close_contacts(state);
            state.status =
                tr(state.lang.texts().status_chat, &[&state.room_label]);
        }
        ContactsAction::Rename(row) => {
            state.input = row.nickname.clone();
            state.cursor = state.input.len();
            state.history_index = None;
            state.history_draft.clear();
            if let Some(flow) = state.contacts.as_mut() {
                flow.stage = ContactsStage::Rename;
                flow.notice = None;
            }
        }
        ContactsAction::Info => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.stage = ContactsStage::Info;
                flow.notice = None;
            }
        }
        ContactsAction::Copy(row) => {
            let Some(fingerprint) = contact_fingerprint(&row) else {
                if let Some(flow) = state.contacts.as_mut() {
                    flow.notice = Some(
                        state
                            .lang
                            .texts()
                            .contacts_fingerprint_missing
                            .to_string(),
                    );
                }
                return;
            };

            match copy_to_clipboard(state, &fingerprint) {
                Ok(()) => {
                    if let Some(flow) = state.contacts.as_mut() {
                        flow.notice =
                            Some(state.lang.texts().contacts_copied.to_string());
                    }
                }
                Err(e) => {
                    if let Some(flow) = state.contacts.as_mut() {
                        flow.notice = Some(tr(
                            state.lang.texts().contacts_copy_error,
                            &[&format!("{:#}", e)],
                        ));
                    }
                }
            }
        }
        ContactsAction::ConfirmDelete => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.stage = ContactsStage::ConfirmDelete;
                flow.notice = None;
            }
        }
    }
}

/// Ввод в строке живого фильтра.
fn handle_contacts_filter_key(state: &mut UiState, key: KeyEvent, ctrl: bool, alt: bool) {
    let Some(flow) = state.contacts.as_mut() else {
        return;
    };

    match key.code {
        KeyCode::Esc => {
            flow.filter.clear();
            flow.filter_active = false;
            flow.apply_filter();
        }
        KeyCode::Enter => {
            flow.filter_active = false;
        }
        KeyCode::Up => flow.move_selection(-1),
        KeyCode::Down => flow.move_selection(1),
        KeyCode::Backspace => {
            flow.filter.pop();
            flow.selected = 0;
            flow.apply_filter();
        }
        KeyCode::Char(c) if !ctrl && !alt => {
            flow.filter.push(c);
            flow.selected = 0;
            flow.apply_filter();
        }
        _ => {}
    }
}

/// Ввод нового имени контакта (Enter — сохранить, Esc — отмена).
fn handle_contacts_rename_key(app: &App, state: &mut UiState, key: KeyEvent, ctrl: bool, alt: bool) {
    let hash = match state.contacts.as_ref().and_then(ContactsFlow::selected_row) {
        Some(row) => row.hash.clone(),
        None => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.stage = ContactsStage::List;
            }
            return;
        }
    };

    match key.code {
        KeyCode::Esc => {
            clear_input(state);
            if let Some(flow) = state.contacts.as_mut() {
                flow.stage = ContactsStage::List;
                flow.notice = None;
            }
        }
        KeyCode::Enter => {
            let name = state.input.trim().to_string();
            if name.is_empty() {
                if let Some(flow) = state.contacts.as_mut() {
                    flow.notice =
                        Some(state.lang.texts().contacts_rename_empty.to_string());
                }
                return;
            }

            match app.update_contact_nickname(&hash, &name) {
                Ok(()) => {
                    clear_input(state);
                    if let Some(flow) = state.contacts.as_mut() {
                        flow.stage = ContactsStage::List;
                        flow.rename_row(&hash, &name);
                        flow.notice =
                            Some(tr(state.lang.texts().contacts_renamed, &[&name]));
                    }
                    if state.room == hash {
                        state.room_label = name.clone();
                    }
                    refresh_chats(app, state);
                    state.status = state.lang.texts().renamed_status.to_string();
                }
                Err(e) => {
                    if let Some(flow) = state.contacts.as_mut() {
                        flow.notice = Some(tr(
                            state.lang.texts().contacts_rename_error,
                            &[&format!("{:#}", e)],
                        ));
                    }
                }
            }
        }
        _ => {
            apply_line_edit_key(state, key, ctrl, alt);
        }
    }
}

/// Удаляет выбранный контакт вместе с историей и обновляет TUI.
fn delete_selected_contact(app: &App, state: &mut UiState) {
    let Some(row) = state
        .contacts
        .as_ref()
        .and_then(ContactsFlow::selected_row)
        .cloned()
    else {
        if let Some(flow) = state.contacts.as_mut() {
            flow.stage = ContactsStage::List;
        }
        return;
    };

    match app.delete_contact(&row.hash) {
        Ok(()) => {
            let deleted_current = state.room == row.hash;
            if deleted_current {
                state.room.clear();
                state.room_label.clear();
                state.feed.clear();
                state.scroll = 0;
                state.follow = true;
            }

            state.chats.retain(|chat| chat.hash != row.hash);
            state.unread.remove(&row.hash);

            reload_contacts_modal(app, state);

            // Если удалили открытый чат — переключаемся на следующий контакт.
            if deleted_current {
                let next = state
                    .contacts
                    .as_ref()
                    .and_then(ContactsFlow::selected_row)
                    .map(|row| row.hash.clone());
                if let Some(next) = next {
                    switch_to_room(app, state, &next);
                }
            }
            refresh_chats(app, state);

            if let Some(flow) = state.contacts.as_mut() {
                flow.stage = ContactsStage::List;
                flow.notice = Some(tr(
                    state.lang.texts().contacts_deleted,
                    &[&row.nickname],
                ));
            }
            state.status = state.lang.texts().contacts_deleted_status.to_string();
        }
        Err(e) => {
            if let Some(flow) = state.contacts.as_mut() {
                flow.stage = ContactsStage::List;
                flow.notice = Some(tr(
                    state.lang.texts().contacts_delete_error,
                    &[&format!("{:#}", e)],
                ));
            }
        }
    }
}

/// Обрабатывает клавиши внутри модального окна контактов.
fn handle_contacts_key(app: &App, state: &mut UiState, key: KeyEvent) {
    let Some(stage) = state.contacts.as_ref().map(|flow| flow.stage) else {
        return;
    };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    match stage {
        ContactsStage::Rename => handle_contacts_rename_key(app, state, key, ctrl, alt),
        ContactsStage::Info => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('i')) {
                if let Some(flow) = state.contacts.as_mut() {
                    flow.stage = ContactsStage::List;
                }
            } else if matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V')) {
                let hash = state
                    .contacts
                    .as_ref()
                    .and_then(ContactsFlow::selected_row)
                    .map(|row| row.hash.clone());
                let Some(hash) = hash else {
                    return;
                };

                match app.verify_contact_fingerprint(&hash) {
                    Ok(()) => {
                        if let Some(flow) = state.contacts.as_mut() {
                            flow.mark_verified(&hash);
                            flow.notice =
                                Some(state.lang.texts().contacts_verified.to_string());
                        }
                        state.status = state.lang.texts().contacts_verified_status.to_string();
                    }
                    Err(e) => {
                        if let Some(flow) = state.contacts.as_mut() {
                            flow.notice = Some(tr(
                                state.lang.texts().contacts_verify_error,
                                &[&format!("{:#}", e)],
                            ));
                        }
                    }
                }
            }
        }
        ContactsStage::ConfirmDelete => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => delete_selected_contact(app, state),
            _ => {
                if let Some(flow) = state.contacts.as_mut() {
                    flow.stage = ContactsStage::List;
                    flow.notice = None;
                }
            }
        },
        ContactsStage::List => {
            let filter_active = state
                .contacts
                .as_ref()
                .map(|flow| flow.filter_active)
                .unwrap_or(false);
            if filter_active {
                handle_contacts_filter_key(state, key, ctrl, alt);
            } else {
                handle_contacts_list_key(app, state, key, ctrl);
            }
        }
    }
}

/// Прокрутка справки колесом мыши.
fn scroll_help(state: &mut UiState, amount: u16, up: bool) {    let Some(flow) = state.help.as_mut() else {
        return;
    };
    flow.scroll = if up {
        flow.scroll.saturating_sub(amount)
    } else {
        flow.scroll.saturating_add(amount).min(flow.max_scroll)
    };
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

            // Ctrl+C защищён от случайного выхода: пока в поле ввода есть
            // текст, копируем его в буфер и очищаем строку. Выход — только
            // по повторному Ctrl+C на пустой строке или по команде /q.
            if ctrl && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C')) {
                if state.input.is_empty() {
                    return Ok(true);
                }

                // Пароль никогда не копируем в системный буфер.
                let recovery_password = state
                    .recovery
                    .as_ref()
                    .map(|flow| flow.stage == RecoveryStage::Password)
                    .unwrap_or(false);
                if state.passwd.is_some() || recovery_password {
                    state.input.clear();
                    state.cursor = 0;
                    state.history_index = None;
                    state.history_draft.clear();
                    state.status = state.lang.texts().clipboard_password_reset.to_string();
                    return Ok(false);
                }

                // Маскируемые поля настроек (Guard Header Value) тоже
                // не должны попадать в буфер обмена.
                let masked_settings = state
                    .settings
                    .as_ref()
                    .map(|flow| flow.editing && flow.field().is_masked())
                    .unwrap_or(false);
                if masked_settings {
                    state.status = state.lang.texts().clipboard_secret_not_copied.to_string();
                    return Ok(false);
                }

                let text = state.input.clone();
                match copy_to_clipboard(state, &text) {
                    Ok(()) => {
                        state.input.clear();
                        state.cursor = 0;
                        state.history_index = None;
                        state.history_draft.clear();
                        state.status =
                            state.lang.texts().clipboard_input_copied.to_string();
                    }
                    Err(e) => {
                        state.status = tr(
                            state.lang.texts().clipboard_unavailable,
                            &[&format!("{:#}", e)],
                        );
                    }
                }
                return Ok(false);
            }

            // Приветственное окно первого запуска перехватывает навигацию.
            if state.welcome.is_some() {
                handle_welcome_key(app, state, key);
                return Ok(false);
            }

            // Подтверждение импорта invite имеет приоритет над остальными
            // модальными окнами.
            if state.pending_import.is_some() {
                handle_import_key(app, state, key);
                return Ok(false);
            }

            // Ctrl+S — быстрый вызов модального окна настроек (/set).
            if ctrl && matches!(key.code, KeyCode::Char('s') | KeyCode::Char('S')) {
                if state.contacts.is_some() {
                    return Ok(false);
                }
                if state.help.is_some() {
                    state.help = None;
                }
                if state.passwd.is_some() {
                    state.status = state.lang.texts().settings_first_finish_password.to_string();
                } else if state.recovery.is_some() {
                    state.status = state.lang.texts().settings_first_finish_recovery.to_string();
                } else if state.settings.is_none() {
                    start_settings(app, state);
                }
                return Ok(false);
            }

            // F1 открывает/закрывает справку. Одиночный `?` не перехватываем:
            // он должен попадать в поле ввода как обычный текст.
            if matches!(key.code, KeyCode::F(1)) {
                if state.contacts.is_some() {
                    return Ok(false);
                }
                if state.recovery.is_some() {
                    state.status = state.lang.texts().settings_first_finish_recovery.to_string();
                } else {
                    toggle_help(state);
                }
                return Ok(false);
            }

            // Модальное окно справки перехватывает прокрутку и закрытие.
            if state.help.is_some() {
                handle_help_key(state, key);
                return Ok(false);
            }

            if ctrl && matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V')) {
                if can_paste(state) {
                    paste_from_clipboard(state);
                }
                return Ok(false);
            }

            // Модальное окно восстановления перехватывает ввод и навигацию.
            if state.recovery.is_some() {
                handle_recovery_key(app, state, key);
                return Ok(false);
            }

            // Модальное окно настроек перехватывает навигацию и ввод.
            if state.settings.is_some() {
                handle_settings_key(app, state, key);
                return Ok(false);
            }

            // Менеджер контактов перехватывает навигацию и действия.
            if state.contacts.is_some() {
                handle_contacts_key(app, state, key);
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
                KeyCode::PageUp => scroll_up(state, state.view_height.max(1)),
                KeyCode::PageDown => scroll_down(state, state.view_height.max(1)),
                KeyCode::Esc => {
                    if state.passwd.take().is_some() {
                        state.input.clear();
                        state.cursor = 0;
                        state.history_index = None;
                        state.history_draft.clear();
                        push_system(state, state.lang.texts().passwd_cancelled);
                        state.status = state.lang.texts().passwd_cancelled_status.to_string();
                        return Ok(false);
                    }

                    state.input.clear();
                    state.cursor = 0;
                    state.history_index = None;
                    state.history_draft.clear();
                }
                _ => {
                    apply_line_edit_key(state, key, ctrl, alt);
                }
            }
        }
        Event::Mouse(mouse) => {
            if state.help.is_some() {
                match mouse.kind {
                    MouseEventKind::ScrollUp => scroll_help(state, 3, true),
                    MouseEventKind::ScrollDown => scroll_help(state, 3, false),
                    _ => {}
                }
                return Ok(false);
            }
            match mouse.kind {
                MouseEventKind::ScrollUp => scroll_up(state, 3),
                MouseEventKind::ScrollDown => scroll_down(state, 3),
                _ => {}
            }
        }
        Event::Paste(text) => {
            if can_paste(state) {
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
                push_error(state, state.lang.texts().passwd_empty);
                state.passwd = Some(flow);
                return;
            }

            match app.verify_master_password(input.as_str()) {
                Ok(()) => {
                    flow.old = input;
                    flow.stage = PasswdStage::New;
                    state.passwd = Some(flow);
                    push_system(state, state.lang.texts().passwd_confirmed);
                    state.status = state.lang.texts().passwd_new_status.to_string();
                }
                Err(e) => {
                    push_error(
                        state,
                        &tr(state.lang.texts().passwd_wrong, &[&format!("{:#}", e)]),
                    );
                }
            }
        }
        PasswdStage::New => {
            if input.chars().count() < vault::MIN_PASSWORD_LEN {
                push_error(
                    state,
                    &tr(
                        state.lang.texts().passwd_min,
                        &[&vault::MIN_PASSWORD_LEN.to_string()],
                    ),
                );
                state.passwd = Some(flow);
                return;
            }

            flow.new = input;
            flow.stage = PasswdStage::Confirm;
            state.passwd = Some(flow);
            push_system(state, state.lang.texts().passwd_repeat);
            state.status = state.lang.texts().passwd_repeat_status.to_string();
        }
        PasswdStage::Confirm => {
            if input.as_str() != flow.new.as_str() {
                push_error(state, state.lang.texts().passwd_mismatch);
                flow.new = Zeroizing::new(String::new());
                flow.stage = PasswdStage::New;
                state.passwd = Some(flow);
                return;
            }

            match app.change_master_password(flow.old.as_str(), flow.new.as_str()) {
                Ok(()) => {
                    push_system(state, state.lang.texts().passwd_changed);
                    state.status = state.lang.texts().passwd_changed_status.to_string();
                }
                Err(e) => {
                    push_error(
                        state,
                        &tr(state.lang.texts().passwd_change_error, &[&format!("{:#}", e)]),
                    )
                }
            }
        }
    }
}

/// Открывает модальное меню настроек `/set`.
fn start_settings(app: &App, state: &mut UiState) {
    if state.passwd.is_some() {
        push_error(state, state.lang.texts().settings_first_finish_password);
        return;
    }

    state.settings = Some(SettingsFlow::from_config(&app.get_config()));
    state.input.clear();
    state.cursor = 0;
    state.history_index = None;
    state.history_draft.clear();
    state.dl_cycle = None;
    state.sf_cycle = None;
    state.status = state.lang.texts().settings_open.to_string();
}

/// Обрабатывает клавиши в модальном окне `/set`.
fn handle_settings_key(app: &App, state: &mut UiState, key: KeyEvent) {
    let (editing, field) = match state.settings.as_ref() {
        Some(flow) => (flow.editing, flow.field()),
        None => return,
    };
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);

    if editing {
        match key.code {
            KeyCode::Enter => {
                let value = std::mem::take(&mut state.input);
                if let Some(flow) = state.settings.as_mut() {
                    flow.apply_edit(field, &value);
                    flow.editing = false;
                }
                state.cursor = 0;
                state.status = {
                    let flow_lang = state.settings.as_ref().map(|f| f.lang).unwrap_or(state.lang);
                    tr(
                        flow_lang.texts().settings_updated,
                        &[field.label(flow_lang)],
                    )
                };
            }
            KeyCode::Esc => {
                if let Some(flow) = state.settings.as_mut() {
                    flow.editing = false;
                }
                state.input.clear();
                state.cursor = 0;
                state.status = state
                    .settings
                    .as_ref()
                    .map(|flow| flow.lang.texts().settings_edit_cancelled)
                    .unwrap_or(state.lang.texts().settings_edit_cancelled)
                    .to_string();
            }
            _ => {
                apply_line_edit_key(state, key, ctrl, alt);
            }
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
            if let Some(flow) = state.settings.as_mut() {
                match field {
                    SettingField::NotifyLevel => flow.cycle_notify(-1),
                    SettingField::Language => flow.cycle_lang(),
                    _ => {}
                }
            }
        }
        KeyCode::Right => {
            if let Some(flow) = state.settings.as_mut() {
                match field {
                    SettingField::NotifyLevel => flow.cycle_notify(1),
                    SettingField::Language => flow.cycle_lang(),
                    _ => {}
                }
            }
        }
        KeyCode::Char(' ') => {
            if let Some(flow) = state.settings.as_mut() {
                match field {
                    SettingField::NotifyLevel => flow.cycle_notify(1),
                    SettingField::Language => flow.cycle_lang(),
                    _ => {}
                }
            }
        }
        KeyCode::Enter => {
            if field.is_toggle() {
                if let Some(flow) = state.settings.as_mut() {
                    match field {
                        SettingField::NotifyLevel => flow.cycle_notify(1),
                        SettingField::Language => flow.cycle_lang(),
                        _ => {}
                    }
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

    let new_lang = flow.lang;
    let config = flow.to_config();
    let texts = new_lang.texts();
    let saved_message = match config.proxy_url.as_deref() {
        Some(url) => tr(texts.settings_saved_proxy, &[url]),
        None => texts.settings_saved.to_string(),
    };

    match app.update_config(config) {
        Ok(()) => {
            state.lang = new_lang;
            push_system(state, &saved_message);
            state.status = texts.settings_applied.to_string();
        }
        Err(e) => {
            push_error(
                state,
                &tr(texts.settings_save_error, &[&format!("{:#}", e)]),
            );
            state.status = texts.settings_error.to_string();
            state.settings = Some(flow);
        }
    }
}

async fn send_plain_message(app: &Arc<App>, state: &mut UiState, text: &str) {
    if state.room.is_empty() {
        push_error(state, state.lang.texts().no_active_room);
        return;
    }

    match app.send_message(&state.room, text).await {
        Ok(()) => {
            let expires_at = app
                .get_room_ttl(&state.room)
                .and_then(|ttl| ttl.seconds)
                .map(|seconds| now_unix().saturating_add(seconds));
            state.feed.push(FeedEntry {
                kind: FeedKind::Outgoing,
                text: format!("[{}] {}", now_time(), text),
                expires_at,
            });
            state.follow = true;
            state.status = state.lang.texts().message_sent.to_string();
        }
        Err(e) => push_error(
            state,
            &tr(state.lang.texts().send_error, &[&format!("{:#}", e)]),
        ),
    }
}

fn validated_invite_link(app: &App, lang: Lang) -> Result<String> {
    let link = app.get_my_contact_link()?;
    IdentityInvite::from_link(&link).map_err(|e| {
        anyhow!(
            "{}",
            tr(lang.texts().invalid_invite, &[&format!("{:#}", e)])
        )
    })?;
    Ok(link)
}

/// Приводит вставляемый текст к однострочному виду.
///
/// Переносы строк (`\n`, `\r`, `\r\n`) и табуляции заменяются пробелом,
/// а прочие управляющие символы отбрасываются, чтобы в поле ввода не
/// попадали последовательности, ломающие отрисовку терминала.
fn sanitize_pasted_text(text: &str) -> String {
    let mut cleaned = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                cleaned.push(' ');
            }
            '\n' => {
                if chars.peek() == Some(&'\r') {
                    chars.next();
                }
                cleaned.push(' ');
            }
            '\t' => cleaned.push(' '),
            c if c.is_control() => {}
            c => cleaned.push(c),
        }
    }

    cleaned
}

/// Вставляет текст в однострочное поле ввода (переводы строк → пробелы).
fn insert_text(state: &mut UiState, text: &str) {
    let cleaned = sanitize_pasted_text(text);
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
            state.status = state.lang.texts().clipboard_pasted.to_string();
        }
        Err(e) => {
            state.status = tr(
                state.lang.texts().clipboard_unavailable,
                &[&e.to_string()],
            );
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
        None => Err(anyhow!("{}", state.lang.texts().clipboard_unavailable_short)),
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
    let safe = sanitize_display_text(&safe);
    let safe = safe.trim();
    let safe = if safe.is_empty() { "user" } else { safe };

    format!("{}_lastchance.invite", safe)
}

/// Сохраняет ссылку в файл.
/// - `None` → `./<nickname>_lastchance.invite`;
/// - существующая папка или путь с завершающим `/` → `<dir>/<nickname>_lastchance.invite`;
/// - иначе → указанный путь к файлу.
fn save_invite_file(
    app: &App,
    target: Option<&str>,
    link: &str,
    lang: Lang,
) -> Result<PathBuf> {
    let file_name = invite_file_name(&app.get_nickname());
    let texts = lang.texts();

    let path = match target {
        None => PathBuf::from(file_name),
        Some(raw) => {
            let candidate = PathBuf::from(raw);
            let dir_hint =
                candidate.is_dir() || raw.ends_with('/') || raw.ends_with('\\');

            if dir_hint {
                std::fs::create_dir_all(&candidate).map_err(|e| {
                    anyhow!(
                        "{}",
                        tr(
                            texts.create_folder_failed,
                            &[&candidate.display().to_string(), &e.to_string()]
                        )
                    )
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
                anyhow!(
                    "{}",
                    tr(
                        texts.create_folder_failed,
                        &[&parent.display().to_string(), &e.to_string()]
                    )
                )
            })?;
        }
    }

    std::fs::write(&path, link).map_err(|e| {
        anyhow!(
            "{}",
            tr(
                texts.write_file_failed,
                &[&path.display().to_string(), &e.to_string()]
            )
        )
    })?;

    let full = std::fs::canonicalize(&path).or_else(|_| {
        if path.is_absolute() {
            Ok(path.clone())
        } else {
            std::env::current_dir().map(|cwd| cwd.join(&path))
        }
    })?;

    Ok(full)
}

/// Открывает диалог подтверждения импорта; добавление произойдёт только
/// после явного подтверждения пользователем.
fn open_import_dialog(state: &mut UiState, invite: IdentityInvite) {
    clear_input(state);
    state.pending_import = Some(PendingImport { invite });
    state.status = state.lang.texts().import_waiting.to_string();
}

fn handle_import_key(app: &App, state: &mut UiState, key: KeyEvent) {
    match key.code {
        KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('Y') => {
            let Some(pending) = state.pending_import.take() else {
                return;
            };

            match app.add_contact_with_ed25519(&pending.invite) {
                Ok(outcome) => {
                    refresh_chats(app, state);
                    switch_to_room(app, state, &outcome.hash);

                    let fingerprint = group_fingerprint(&outcome.fingerprint);
                    if outcome.x25519_changed {
                        push_system(
                            state,
                            &tr(
                                state.lang.texts().import_changed_warning,
                                &[&outcome.nickname, &fingerprint],
                            ),
                        );
                    } else {
                        push_system(
                            state,
                            &tr(
                                state.lang.texts().import_added,
                                &[&outcome.nickname, &fingerprint],
                            ),
                        );
                    }
                    state.status = state.lang.texts().contact_added.to_string();
                }
                Err(e) => push_error(
                    state,
                    &tr(
                        state.lang.texts().import_error,
                        &[&format!("{:#}", e)],
                    ),
                ),
            }
        }
        KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Char('q') => {
            state.pending_import = None;
            state.status = state.lang.texts().import_cancelled.to_string();
        }
        _ => {}
    }
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
        "/help" => open_help(state),

        "/profile" => match serde_json::to_string_pretty(&app.get_profile()) {
            Ok(text) => push_system(state, &text),
            Err(e) => push_error(
                state,
                &tr(state.lang.texts().profile_serialize_error, &[&e.to_string()]),
            ),
        },

        "/recovery" => start_recovery(state),

        "/invite" => match validated_invite_link(app, state.lang) {
            Ok(link) => {
                match copy_to_clipboard(state, &link) {
                    Ok(()) => {
                        push_system(state, state.lang.texts().invite_copied)
                    }
                    Err(e) => push_system(
                        state,
                        &tr(
                            state.lang.texts().invite_clipboard_warning,
                            &[&format!("{:#}", e)],
                        ),
                    ),
                }

                let save_requested = parts.get(1).copied() == Some("-f");
                if save_requested {
                    match save_invite_file(app, parts.get(2).copied(), &link, state.lang) {
                        Ok(path) => {
                            push_system(
                                state,
                                &tr(
                                    state.lang.texts().invite_saved,
                                    &[&path.display().to_string()],
                                ),
                            );
                            state.status =
                                state.lang.texts().invite_saved_status.to_string();
                        }
                        Err(e) => push_error(
                            state,
                            &tr(
                                state.lang.texts().invite_save_error,
                                &[&format!("{:#}", e)],
                            ),
                        ),
                    }
                } else {
                    push_system(state, &tr(state.lang.texts().invite_link, &[&link]));
                    state.status = state.lang.texts().invite_ready.to_string();
                }
            }
            Err(e) => push_error(
                state,
                &tr(state.lang.texts().invite_error, &[&format!("{:#}", e)]),
            ),
        },

        "/export" => match app.get_my_contact_json() {
            Ok(json) => push_system(state, &json),
            Err(e) => push_error(
                state,
                &tr(state.lang.texts().profile_serialize_error, &[&format!("{:#}", e)]),
            ),
        },

        "/contacts" => open_contacts(app, state),

        "/join" => {
            let rest: Vec<&str> = parts[1..].to_vec();

            let result = if rest.first().copied() == Some("-f") {
                match rest.get(1) {
                    Some(path) => std::fs::read_to_string(path)
                        .map_err(|e| anyhow!("{}", tr(state.lang.texts().join_file_error, &[path, &e.to_string()])))
                        .and_then(|content| parse_contact_link(content.trim(), state.lang)),
                    None => Err(anyhow!("{}", state.lang.texts().join_usage_file)),
                }
            } else if rest.len() == 1 {
                parse_contact_link(rest[0], state.lang)
            } else {
                Err(anyhow!("{}", state.lang.texts().join_usage))
            };

            match result {
                Ok(invite) => open_import_dialog(state, invite),
                Err(e) => push_error(
                    state,
                    &tr(state.lang.texts().join_error, &[&format!("{:#}", e)]),
                ),
            }
        }

        "/room" => {
            if let Some(token) = parts.get(1) {
                let hash = resolve_room(app, token);
                switch_to_room(app, state, &hash);
                push_system(
                    state,
                    &tr(
                        state.lang.texts().room_active,
                        &[&state.room_label, &short_hash(&state.room)],
                    ),
                );
                state.status = state.lang.texts().room_switched.to_string();
            } else if state.room.is_empty() {
                push_system(state, state.lang.texts().room_none);
            } else {
                push_system(
                    state,
                    &tr(
                        state.lang.texts().room_active,
                        &[&state.room_label, &state.room],
                    ),
                );
            }
        }

        "/messages" => {
            if state.room.is_empty() {
                push_error(state, state.lang.texts().no_active_room_short);
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
                        push_system(state, state.lang.texts().messages_empty);
                    } else {
                        for m in messages {
                            let outgoing = m.direction != "in";
                            let dir = if outgoing { "→" } else { "←" };
                            let time = m.timestamp.format("%H:%M:%S").to_string();

                            let line = match parse_file_notification(&m.text) {
                                Some(notification) => {
                                    let id = register_file(
                                        state,
                                        &room,
                                        &notification.file_name,
                                        &notification.file_hash,
                                        notification.file_id.as_deref(),
                                        m.timestamp.timestamp(),
                                    );
                                    let sender = if outgoing {
                                        nickname.as_str()
                                    } else {
                                        room_title.as_str()
                                    };
                                    file_feed_line(
                                        &time,
                                        sender,
                                        id,
                                        &notification.file_name,
                                        outgoing,
                                        state.lang,
                                    )
                                }
                                None => format!("[{}] {} {}", time, dir, m.text),
                            };
                            push_system(state, &line);
                        }
                    }
                }
                Err(e) => push_error(
                    state,
                    &tr(
                        state.lang.texts().messages_error,
                        &[&format!("{:#}", e)],
                    ),
                ),
            }
        }

        "/ttl" => {
            if state.room.is_empty() {
                push_error(state, state.lang.texts().no_active_room_short);
                return Ok(false);
            }

            let Some(raw) = parts.get(1).copied() else {
                let text = ttl_status_text(
                    state.lang.texts(),
                    state.ttl_seconds,
                    state.ttl_pending,
                    state.ttl_synced,
                );
                push_system(state, &text);
                state.status = text;
                return Ok(false);
            };

            let seconds = match parse_ttl_duration(raw) {
                Ok(seconds) => seconds,
                Err(e) => {
                    push_error(
                        state,
                        &tr(
                            state.lang.texts().ttl_invalid,
                            &[&format!("{:#}", e)],
                        ),
                    );
                    return Ok(false);
                }
            };

            // При выключении TTL состояние затирается, поэтому собеседник
            // получает управляющий пакет и тоже начинает сессию заново.
            // При включении текущая сессия просто переносится в RAM.
            if seconds.is_none() {
                let _ = app.reset_ratchet_with_peer(&state.room).await;
            }

            match app.set_room_ttl(&state.room, seconds) {
                Ok(()) => {
                    sync_ttl_state(app, state);
                    let text = match seconds {
                        Some(value) => tr(
                            state.lang.texts().ttl_enabled_local,
                            &[&value.to_string()],
                        ),
                        None => state.lang.texts().ttl_disabled_local.to_string(),
                    };
                    push_system(state, &text);
                    state.status = text;
                }
                Err(e) => push_error(
                    state,
                    &tr(
                        state.lang.texts().ttl_apply_error,
                        &[&format!("{:#}", e)],
                    ),
                ),
            }
        }

        "/ttl-syn" => {
            if state.room.is_empty() {
                push_error(state, state.lang.texts().no_active_room_short);
                return Ok(false);
            }

            let Some(raw) = parts.get(1).copied() else {
                let text = match state.ttl_seconds {
                    Some(seconds) if state.ttl_synced => tr(
                        state.lang.texts().ttl_status_synced,
                        &[&seconds.to_string()],
                    ),
                    _ => state.lang.texts().ttl_status_off.to_string(),
                };
                push_system(state, &text);
                state.status = text;
                return Ok(false);
            };

            let seconds = match parse_ttl_duration(raw) {
                Ok(seconds) => seconds,
                Err(e) => {
                    push_error(
                        state,
                        &tr(
                            state.lang.texts().ttl_invalid,
                            &[&format!("{:#}", e)],
                        ),
                    );
                    return Ok(false);
                }
            };

            match app.set_synced_ttl(&state.room, seconds).await {
                Ok(TtlSyncOutcome::Synced) => {
                    sync_ttl_state(app, state);
                    let text = match seconds {
                        Some(value) => tr(
                            state.lang.texts().ttl_enabled_synced,
                            &[&value.to_string()],
                        ),
                        None => state.lang.texts().ttl_disabled_synced.to_string(),
                    };
                    push_system(state, &text);
                    state.status = text;
                }
                Ok(TtlSyncOutcome::LocalOnly { error }) => {
                    sync_ttl_state(app, state);
                    let text = match seconds {
                        Some(value) => tr(
                            state.lang.texts().ttl_enabled_pending,
                            &[&value.to_string(), &error],
                        ),
                        // Выключение при ошибке отправки откатывается
                        // внутри `set_synced_ttl`, поэтому LocalOnly здесь
                        // возможен только при включении.
                        None => tr(state.lang.texts().ttl_retry_error, &[&error]),
                    };
                    push_system(state, &text);
                    state.status = text;
                }
                Err(e) => push_error(
                    state,
                    &tr(
                        state.lang.texts().ttl_apply_error,
                        &[&format!("{:#}", e)],
                    ),
                ),
            }
        }

        "/ttl-syn-retry" => {
            if state.room.is_empty() {
                push_error(state, state.lang.texts().no_active_room_short);
                return Ok(false);
            }

            let Some(ttl) = app.get_room_ttl(&state.room) else {
                push_error(state, state.lang.texts().ttl_retry_nothing);
                return Ok(false);
            };

            if !ttl.pending_sync {
                push_error(state, state.lang.texts().ttl_retry_not_pending);
                return Ok(false);
            }

            match app.resync_ttl(&state.room).await {
                Ok(TtlSyncOutcome::Synced) => {
                    sync_ttl_state(app, state);
                    let text = state.lang.texts().ttl_retry_done.to_string();
                    push_system(state, &text);
                    state.status = text;
                }
                Ok(TtlSyncOutcome::LocalOnly { error }) => {
                    sync_ttl_state(app, state);
                    let text = tr(state.lang.texts().ttl_retry_error, &[&error]);
                    push_error(state, &text);
                    state.status = text;
                }
                Err(e) => push_error(
                    state,
                    &tr(
                        state.lang.texts().ttl_retry_error,
                        &[&format!("{:#}", e)],
                    ),
                ),
            }
        }

        "/ratchet-reset" => {
            if state.room.is_empty() {
                push_error(state, state.lang.texts().no_active_room_short);
                return Ok(false);
            }

            match app.reset_ratchet_with_peer(&state.room).await {
                Ok(()) => {
                    let text = state.lang.texts().ratchet_reset_done.to_string();
                    push_system(state, &text);
                    state.status = text;
                }
                Err(e) => push_error(
                    state,
                    &tr(
                        state.lang.texts().ratchet_reset_error,
                        &[&format!("{:#}", e)],
                    ),
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
                    push_error(state, state.lang.texts().sendfile_usage);
                    return Ok(false);
                }
            }

            let Some(path) = path else {
                push_error(state, state.lang.texts().sendfile_usage);
                return Ok(false);
            };
            if state.room.is_empty() {
                push_error(state, state.lang.texts().no_active_room_short);
                return Ok(false);
            }

            let app_ref = app.clone();
            let room = state.room.clone();
            let path = path.to_string();
            let tx = ui_tx.clone();
            if force {
                push_system(state, state.lang.texts().sendfile_force);
                state.status = tr(state.lang.texts().sendfile_sending_force, &[&path]);
            } else {
                state.status = tr(state.lang.texts().sendfile_sending, &[&path]);
            }
            let lang = state.lang;

            tokio::spawn(async move {
                match app_ref.send_file_native(&room, &path, force).await {
                    Ok(()) => {
                        let _ = tx.send(UiNotice::Status(
                            lang.texts().sendfile_sent.to_string(),
                        ));
                    }
                    Err(e) => {
                        let _ = tx.send(UiNotice::Error(tr(
                            lang.texts().sendfile_error,
                            &[&format!("{:#}", e)],
                        )));
                    }
                }
            });
        }

        "/download" => {
            if state.room.is_empty() {
                push_error(state, state.lang.texts().no_active_room_short);
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
                    Some(token) => tr(state.lang.texts().download_not_found, &[token]),
                    None => state.lang.texts().download_no_files.to_string(),
                };
                push_error(state, &message);
                return Ok(false);
            };

            let path = match resolve_save_path(explicit_path, &file.file_name, state.lang) {
                Ok(path) => path,
                Err(e) => {
                    push_error(state, &tr(state.lang.texts().download_path_error, &[&format!("{:#}", e)]));
                    return Ok(false);
                }
            };
            let path_display = path.to_string_lossy().to_string();

            let app_ref = app.clone();
            let room = file.room_hash.clone();
            let file_hash = file.file_hash.clone();
            let file_id = file.file_id.clone();
            let target_display = format!("#{} {}", file.id, file.file_name);
            let tx = ui_tx.clone();
            state.status = tr(state.lang.texts().download_saving, &[&target_display]);
            let lang = state.lang;

            tokio::spawn(async move {
                match app_ref
                    .download_and_save_file(&room, &file_hash, file_id.as_deref(), &path_display)
                    .await
                {
                    Ok(()) => {
                        let _ = tx.send(UiNotice::Status(tr(
                            lang.texts().download_saved,
                            &[&target_display, &path_display],
                        )));
                    }
                    Err(e) => {
                        let _ = tx.send(UiNotice::Error(tr(
                            lang.texts().download_error,
                            &[&target_display, &format!("{:#}", e)],
                        )));
                    }
                }
            });
        }

        "/nick" => {
            let Some(name) = parts.get(1) else {
                push_error(state, state.lang.texts().nick_usage);
                return Ok(false);
            };
            match app.update_nickname(name) {
                Ok(()) => {
                    state.nickname = app.get_nickname();
                    push_system(state, &tr(state.lang.texts().nick_changed, &[&state.nickname]));
                    state.status = state.lang.texts().nick_changed_status.to_string();
                }
                Err(e) => push_error(
                    state,
                    &tr(state.lang.texts().nick_error, &[&format!("{:#}", e)]),
                ),
            }
        }

        "/rename" => {
            if parts.len() < 3 {
                push_error(state, state.lang.texts().rename_usage);
                return Ok(false);
            }
            match app.update_contact_nickname(parts[1], parts[2]) {
                Ok(()) => {
                    refresh_chats(app, state);
                    state.room_label = room_label(app, &state.room);
                    push_system(state, state.lang.texts().renamed);
                    state.status = state.lang.texts().renamed_status.to_string();
                }
                Err(e) => push_error(
                    state,
                    &tr(state.lang.texts().rename_error, &[&format!("{:#}", e)]),
                ),
            }
        }

        "/sidebar" => {
            state.sidebar_visible = !state.sidebar_visible;
            let text = if state.sidebar_visible {
                state.lang.texts().sidebar_on
            } else {
                state.lang.texts().sidebar_off
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
                        &tr(
                            state.lang.texts().set_notify_usage,
                            &[notify_level_label(state.lang, level)],
                        ),
                    );
                    return Ok(false);
                };

                let level = match raw.parse::<u8>() {
                    Ok(level) if level <= 3 => level,
                    _ => {
                        push_error(state, state.lang.texts().set_notify_usage);
                        return Ok(false);
                    }
                };

                let mut config = app.get_config();
                config.notify_level = level;
                match app.update_config(config) {
                    Ok(()) => {
                        push_system(
                            state,
                            &tr(
                                state.lang.texts().set_notify_updated,
                                &[notify_level_label(state.lang, level)],
                            ),
                        );
                        state.status =
                            state.lang.texts().set_notify_status.to_string();
                    }
                    Err(e) => push_error(
                        state,
                        &tr(
                            state.lang.texts().settings_save_error,
                            &[&format!("{:#}", e)],
                        ),
                    ),
                }
            }
            Some("test") => {
                let app_ref = app.clone();
                let tx = ui_tx.clone();
                state.status = state.lang.texts().set_test_sending.to_string();
                let lang = state.lang;

                tokio::spawn(async move {
                    let result =
                        tokio::task::spawn_blocking(move || app_ref.send_test_notification())
                            .await;

                    let notice = match result {
                        Ok(Ok(())) => UiNotice::Status(
                            lang.texts().set_test_sent.to_string(),
                        ),
                        Ok(Err(e)) => UiNotice::Error(tr(
                            lang.texts().set_test_error,
                            &[&format!("{:#}", e)],
                        )),
                        Err(e) => UiNotice::Error(tr(
                            lang.texts().set_test_error_join,
                            &[&e.to_string()],
                        )),
                    };
                    let _ = tx.send(notice);
                });
            }
            Some(_) => push_error(state, state.lang.texts().set_usage),
        },

        "/lang" => {
            let selected = match parts.get(1).copied() {
                None => match state.lang {
                    Lang::En => Lang::Ru,
                    Lang::Ru => Lang::En,
                },
                Some(raw) => match Lang::parse(raw) {
                    Some(lang) => lang,
                    None => {
                        push_error(state, &tr(state.lang.texts().lang_invalid, &[raw]));
                        return Ok(false);
                    }
                },
            };

            let mut config = app.get_config();
            config.apply_lang(selected);
            match app.update_config(config) {
                Ok(()) => {
                    state.lang = selected;
                    let message = tr(selected.texts().lang_changed, &[selected.native_name()]);
                    push_system(state, &message);
                    state.status = tr(selected.texts().lang_status, &[selected.code()]);
                }
                Err(e) => push_error(
                    state,
                    &tr(
                        state.lang.texts().lang_saved_error,
                        &[&format!("{:#}", e)],
                    ),
                ),
            }
        }

        "/passwd" => {
            if state.settings.is_some() {
                push_error(state, state.lang.texts().settings_first_close);
            } else if state.passwd.is_some() {
                push_error(state, state.lang.texts().passwd_already_started);
            } else {
                state.passwd = Some(PasswdFlow::new());
                state.input.clear();
                state.cursor = 0;
                push_system(state, state.lang.texts().passwd_start);
                state.status = state.lang.texts().passwd_enter_current.to_string();
            }
        }

        "/quit" | "/exit" => return Ok(true),

        _ => push_error(state, state.lang.texts().unknown_command),
    }

    Ok(false)
}

// ============================================================
// АРГУМЕНТЫ И ГЛАВНЫЙ ЦИКЛ
// ============================================================

/// Печатает справку по аргументам командной строки.
fn print_cli_help(program: &str) {
    println!("LastChance — защищённый мессенджер.");
    println!();
    println!("Использование:");
    println!("  {} [--profile-dir <path>] [--recovery]", program);
    println!(
        "  {} --to <contact> --send <text|-> [--file <path>] [--profile-dir <path>]",
        program
    );
    println!();
    println!("Профиль:");
    println!("  --profile-dir <path>  Каталог профиля (боты и отдельные аккаунты).");
    println!("                        Приоритет: --profile-dir > LASTCHANCE_DIR >");
    println!("                        ~/.config/lastchance");
    println!("  --data-dir <path>     Устаревший синоним --profile-dir");
    println!("  --recovery            Восстановить идентичность из BIP-39 фразы");
    println!("                        Внимание: перезаписывает текущий identity.json!");
    println!();
    println!("Headless-отправка (без TUI):");
    println!("  --to <contact>        Имя контакта из локальной базы, identity_hash");
    println!("                        или ссылка lastchance://contact?...");
    println!("  --send <text|->       Текст сообщения; \"-\" читает текст из stdin");
    println!("  --file <path>         Отправить зашифрованный файл");
    println!("                        (можно вместе с --send)");
    println!();
    println!("Переменные окружения:");
    println!("  LASTCHANCE_DIR        Каталог профиля, если не задан --profile-dir");
    println!("  LASTCHANCE_PASS_FILE  Файл с мастер-паролем (режим 0600);");
    println!("                        приоритетнее LASTCHANCE_PASS");
    println!("  LASTCHANCE_PASS       Мастер-пароль для headless-режима;");
    println!("                        виден в /proc/<pid>/environ, поэтому");
    println!("                        используйте только в отдельном UID/контейнере;");
    println!("                        без этих переменных пароль запрашивается");
    println!("                        скрыто в TTY");
    println!();
    println!("  -h, --help            Показать эту справку");
    println!();
    println!("Без аргументов запускается TUI-клиент. Headless-режим не включает");
    println!("crossterm/ratatui и завершается с кодом 0 при успехе, 1 при ошибке.");
}

/// Читает строку с эхом (для подтверждений y/N).
///
/// Секреты (seed-фраза, пароли) читаются через [`read_secret_line`].
fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::Write;

    let mut stdout = io::stdout();
    write!(stdout, "{}", prompt)?;
    stdout.flush()?;

    let mut line = String::new();
    let read = io::stdin().read_line(&mut line)?;
    if read == 0 {
        return Err(anyhow!("ввод прерван (EOF)"));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Запрашивает подтверждение y/N. По умолчанию (Enter) — отказ.
fn confirm_overwrite(prompt: &str) -> Result<bool> {
    let answer = prompt_line(&format!("{} [y/N]: ", prompt))?;
    Ok(matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "д" | "да"
    ))
}

/// Стандартная установка нового мастер-пароля: ввод дважды с проверкой длины.
fn prompt_new_master_password() -> Result<Zeroizing<String>> {
    loop {
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

        return Ok(password);
    }
}

/// Перешифровывает профиль на новый мастер-пароль при восстановлении
/// существующей идентичности. Возвращает хранилище с новым ключом.
fn rekey_profile(base_dir: &str, old_vault: &Vault, new_password: &str) -> Result<Vault> {
    let old_key = old_vault.key()?;
    let (new_salt, new_key) = vault::derive_new(new_password)?;
    let db_exists = std::path::Path::new(base_dir).join(VAULT_FILE_NAME).exists()
        || std::path::Path::new(base_dir)
            .join(LEGACY_DB_FILE_NAME)
            .exists();

    let rewrite = |from: &vault::MasterKey, to: &vault::MasterKey| -> Result<()> {
        Config::reencrypt(base_dir, from, to)?;
        if db_exists {
            let storage = Storage::new(base_dir, old_vault.clone())?;
            storage.reencrypt_fields_and_replace_key(from, to)?;
        } else {
            old_vault.replace_key(to.clone())?;
        }
        Ok(())
    };

    if let Err(e) = rewrite(&old_key, &new_key) {
        // Best-effort откат: профиль должен остаться доступным старым паролем.
        let _ = rewrite(&new_key, &old_key);
        return Err(e);
    }

    vault::write_meta(base_dir, &new_salt, &new_key)?;
    Ok(old_vault.clone())
}

/// Восстанавливает идентичность из BIP-39 и заново настраивает мастер-пароль.
fn run_recovery(base_dir: &str) -> Result<Vault> {
    let identity_path = std::path::Path::new(base_dir).join(IDENTITY_FILE_NAME);
    if identity_path.exists() {
        println!("⚠ В профиле уже существует identity.json.");
        println!("  Продолжение заменит текущую идентичность без возможности отмены.");
        if !confirm_overwrite("Перезаписать текущую идентичность?")? {
            return Err(anyhow!("восстановление отменено"));
        }
    }

    let identity = loop {
        // Seed-фраза — это идентичность: не показываем ни символы, ни длину.
        let phrase = read_secret_line("Мнемоническая фраза BIP-39: ", SecretEcho::Hidden)?;
        let identity = match Identity::from_mnemonic(phrase.as_str(), "") {
            Ok(identity) => identity,
            Err(e) => {
                eprintln!("Ошибка: {:#}\nВведите фразу повторно.", e);
                continue;
            }
        };

        let confirm = read_secret_line("Повторите фразу: ", SecretEcho::Hidden)?;
        match Identity::from_mnemonic(confirm.as_str(), "") {
            Ok(confirmed) if confirmed.seed_phrase.expose() == identity.seed_phrase.expose() => {
                break identity;
            }
            Ok(_) => eprintln!("Фразы не совпадают — попробуйте ещё раз."),
            Err(e) => eprintln!("Ошибка: {:#}\nВведите фразу повторно.", e),
        }
    };

    let old_vault = if Vault::is_initialized(base_dir)? {
        println!("Профиль уже существует: нужен текущий мастер-пароль, чтобы сохранить данные.");
        let mut unlocked = None;
        for _ in 0..3 {
            let current = read_password("Текущий мастер-пароль: ")?;
            match Vault::unlock(base_dir, current.as_str()) {
                Ok(vault) => {
                    unlocked = Some(vault);
                    break;
                }
                Err(e) => eprintln!("{:#}", e),
            }
        }
        Some(unlocked.ok_or_else(|| anyhow!("не удалось разблокировать профиль"))?)
    } else {
        None
    };

    let new_password = prompt_new_master_password()?;
    let vault = match old_vault {
        Some(old_vault) => rekey_profile(base_dir, &old_vault, new_password.as_str())?,
        None => Vault::create(base_dir, new_password.as_str())?,
    };

    let mut manager = IdentityManager::new(base_dir.to_string(), vault.clone());
    let restored = manager.restore_from_mnemonic(identity.seed_phrase.expose(), &identity.nickname)?;
    manager.save(&restored)?;

    println!("Идентичность восстановлена.");
    println!("  hash: {}", restored.hash);
    println!("  файл: {}", identity_path.display());

    Ok(vault)
}

/// Переменная с мастер-паролем в окружении (совместимость).
const PASS_ENV: &str = "LASTCHANCE_PASS";
/// Переменная с путём к файлу мастер-пароля (предпочтительный способ).
const PASS_FILE_ENV: &str = "LASTCHANCE_PASS_FILE";

/// Читает мастер-пароль из файла.
///
/// На Unix файл должен быть приватным: любые биты group/other запрещены
/// (`0600` и строже). Один завершающий перевод строки отбрасывается, чтобы
/// `echo secret > file` работал предсказуемо. Значение возвращается в
/// `Zeroizing` и никогда не печатается.
fn read_password_file(path: &std::path::Path) -> Result<Zeroizing<String>> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        anyhow!(
            "{}: cannot stat {}: {}",
            PASS_FILE_ENV,
            path.display(),
            e
        )
    })?;
    if !metadata.is_file() {
        return Err(anyhow!(
            "{}: {} is not a regular file",
            PASS_FILE_ENV,
            path.display()
        ));
    }
    // Пароль — одна короткая строка; не читаем произвольный файл целиком.
    const MAX_PASSWORD_FILE_BYTES: u64 = 4096;
    if metadata.len() > MAX_PASSWORD_FILE_BYTES {
        return Err(anyhow!(
            "{}: {} is larger than {} bytes",
            PASS_FILE_ENV,
            path.display(),
            MAX_PASSWORD_FILE_BYTES
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "{}: {} has mode {:04o}; expected 0600 (no group/other access)",
                PASS_FILE_ENV,
                path.display(),
                mode
            ));
        }
    }

    let mut file = std::fs::File::open(path).map_err(|e| {
        anyhow!(
            "{}: cannot open {}: {}",
            PASS_FILE_ENV,
            path.display(),
            e
        )
    })?;
    let mut password = Zeroizing::new(String::new());
    file.read_to_string(&mut password).map_err(|e| {
        anyhow!(
            "{}: cannot read {} as UTF-8: {}",
            PASS_FILE_ENV,
            path.display(),
            e
        )
    })?;

    let len = password.trim_end_matches(['\r', '\n']).len();
    password.truncate(len);
    Ok(password)
}

/// Выбирает мастер-пароль из явных источников.
///
/// Приоритет: `LASTCHANCE_PASS_FILE` > `LASTCHANCE_PASS`. Значения не
/// попадают ни в предупреждения, ни в ошибки; предупреждения — только про
/// сам источник и путь. `warnings` вынесен параметром, чтобы тесты могли
/// убедиться, что секрет туда не утекает.
fn resolve_headless_password(
    file: Option<PathBuf>,
    env_password: Option<Zeroizing<String>>,
    warnings: &mut dyn io::Write,
) -> Result<Zeroizing<String>> {
    if let Some(path) = file {
        if env_password.is_some() {
            let _ = writeln!(
                warnings,
                "warning: {} is ignored because {} is set",
                PASS_ENV, PASS_FILE_ENV
            );
        }
        return read_password_file(&path);
    }

    if let Some(password) = env_password {
        let _ = writeln!(
            warnings,
            "warning: {} is visible in /proc/<pid>/environ to the same UID; prefer {} with mode 0600",
            PASS_ENV, PASS_FILE_ENV
        );
        return Ok(password);
    }

    Err(anyhow!(
        "{} / {} is not set and stdin is not an interactive TTY",
        PASS_ENV,
        PASS_FILE_ENV
    ))
}

/// Читает мастер-пароль для headless-режима.
///
/// Приоритет: `LASTCHANCE_PASS_FILE`, затем `LASTCHANCE_PASS`, затем скрытый
/// ввод, если stdin — TTY. Без TTY возвращаем чистую ошибку (main завершится
/// с кодом 1).
fn read_headless_password() -> Result<Zeroizing<String>> {
    use std::io::IsTerminal;

    let file = std::env::var_os(PASS_FILE_ENV).map(PathBuf::from);
    let env_password = match std::env::var_os(PASS_ENV) {
        Some(raw) => Some(Zeroizing::new(
            raw.into_string()
                .map_err(|_| anyhow!("{} is not valid UTF-8", PASS_ENV))?,
        )),
        None => None,
    };

    if file.is_some() || env_password.is_some() {
        let mut stderr = io::stderr();
        return resolve_headless_password(file, env_password, &mut stderr);
    }

    if !io::stdin().is_terminal() {
        return Err(anyhow!(
            "{} / {} is not set and stdin is not an interactive TTY",
            PASS_ENV,
            PASS_FILE_ENV
        ));
    }

    read_password("Мастер-пароль: ")
}

/// Находит получателя по имени, identity_hash или ссылке `lastchance://`.
///
/// Ссылка с неизвестным контактом импортируется в локальную базу: без
/// публичного ключа отправить зашифрованный пакет невозможно.
fn resolve_headless_recipient(app: &App, raw: &str) -> Result<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(anyhow!("--to: empty recipient"));
    }

    if raw.starts_with("lastchance://") {
        let lang = app.get_config().lang;
        let invite = parse_contact_link(raw, lang)?;
        let hash = invite.hash_hex();
        let known = app
            .get_contacts()?
            .iter()
            .any(|contact| contact.hash == hash);
        if !known {
            app.add_contact_with_ed25519(&invite)?;
        }
        return Ok(hash);
    }

    if raw == app.identity.hash {
        return Ok(raw.to_string());
    }

    let contacts = app.get_contacts()?;
    if contacts.iter().any(|contact| contact.hash == raw) {
        return Ok(raw.to_string());
    }

    let needle = raw.to_lowercase();
    let matches: Vec<&str> = contacts
        .iter()
        .filter(|contact| contact.nickname.to_lowercase() == needle)
        .map(|contact| contact.hash.as_str())
        .collect();

    match matches.as_slice() {
        [] => Err(anyhow!("contact not found: {}", raw)),
        [hash] => Ok((*hash).to_string()),
        _ => Err(anyhow!(
            "ambiguous contact name '{}': {} matches; use the identity hash",
            raw,
            matches.len()
        )),
    }
}

/// Отправляет сообщение и/или файл без запуска ratatui/crossterm.
async fn run_headless(args: &HeadlessArgs, base_dir: &str) -> Result<()> {
    let to = args
        .to
        .as_deref()
        .ok_or_else(|| anyhow!("--to: missing recipient"))?;

    if !Vault::is_initialized(base_dir)? {
        return Err(anyhow!(
            "profile is not initialized: {} (launch the TUI once to create it)",
            base_dir
        ));
    }

    let password = read_headless_password()?;
    let vault = Vault::unlock(base_dir, password.as_str())?;
    drop(password);

    let (config, _needs_language_choice) =
        Config::load_with_language_flag(base_dir, &vault)?;
    let (event_tx, _event_rx) = mpsc::unbounded_channel::<AppEvent>();
    let app = App::new(config, base_dir.to_string(), vault, event_tx)?;

    let recipient = resolve_headless_recipient(&app, to)?;

    let text = match args.send.as_deref() {
        Some("-") => {
            let mut input = String::new();
            io::stdin()
                .read_to_string(&mut input)
                .map_err(|e| anyhow!("cannot read message from stdin: {}", e))?;
            let text = input
                .trim_end_matches(['\r', '\n'])
                .to_string();
            if text.is_empty() {
                return Err(anyhow!("stdin is empty: nothing to send"));
            }
            Some(text)
        }
        Some(text) => Some(text.to_string()),
        None => None,
    };

    if let Some(text) = text.as_deref() {
        app.send_message(&recipient, text).await?;
    }

    if let Some(path) = args.file.as_deref() {
        app.send_file_native(&recipient, path, false).await?;
    }

    Ok(())
}

fn parse_contact_link(raw: &str, lang: Lang) -> Result<IdentityInvite> {
    IdentityInvite::from_link(raw)
        .map_err(|e| anyhow!("{}", tr(lang.texts().invalid_invite, &[&format!("{:#}", e)])))
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
    let mut ttl_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    ttl_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
                        state.status = tr(
                            state.lang.texts().terminal_error,
                            &[&e.to_string()],
                        );
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
            _ = ttl_tick.tick() => {
                tick_ttl(app, state);
            }
        }
    }
}

/// Выключает raw mode после скрытого ввода, в том числе при ошибке.
struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}

/// Что показывать на экране при вводе секрета.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SecretEcho {
    /// Ничего: seed-фраза не должна попадать ни на экран, ни в скроллбэк.
    Hidden,
    /// Один `*` на символ: мастер-пароль.
    Masked,
}

impl SecretEcho {
    /// Строка для только что введённого символа.
    fn char(self) -> &'static str {
        match self {
            SecretEcho::Hidden => "",
            SecretEcho::Masked => "*",
        }
    }

    /// Стирание последнего символа: только если он был виден.
    fn backspace(self) -> &'static str {
        match self {
            SecretEcho::Hidden => "",
            SecretEcho::Masked => "\x08 \x08",
        }
    }
}

/// Одно действие в скрытом вводе.
///
/// Отдельный тип позволяет тестировать эхо и редактирование без терминала
/// (мок-терминал: клавиши подаются напрямую, вывод пишется в `Vec<u8>`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SecretKey {
    Char(char),
    Backspace,
    Enter,
    Cancel,
}

/// Применяет клавишу к секретному буферу.
///
/// Возвращает `Ok(false)`, когда ввод завершён Enter. Само значение никогда
/// не пишется в `out`: только маска, заданная [`SecretEcho`].
fn apply_secret_key(
    secret: &mut Zeroizing<String>,
    echo: SecretEcho,
    out: &mut dyn io::Write,
    key: SecretKey,
) -> Result<bool> {
    match key {
        SecretKey::Enter => {
            write!(out, "\r\n")?;
            Ok(false)
        }
        SecretKey::Cancel => {
            write!(out, "\r\n")?;
            Err(anyhow!("ввод отменён"))
        }
        SecretKey::Backspace => {
            if secret.pop().is_some() {
                write!(out, "{}", echo.backspace())?;
            }
            Ok(true)
        }
        SecretKey::Char(c) => {
            secret.push(c);
            write!(out, "{}", echo.char())?;
            Ok(true)
        }
    }
}

/// Читает строку в raw mode, не показывая сам ввод.
///
/// Буфер возвращается в `Zeroizing`, поэтому затирается при drop (M-5).
fn read_secret_line(prompt: &str, echo: SecretEcho) -> Result<Zeroizing<String>> {
    use std::io::Write;

    let mut stdout = io::stdout();
    write!(stdout, "{}", prompt)?;
    stdout.flush()?;

    enable_raw_mode()?;
    let _guard = RawModeGuard;
    let mut secret = Zeroizing::new(String::new());

    loop {
        match crossterm::event::read()? {
            Event::Key(key) if key.kind != KeyEventKind::Release => {
                let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
                let key = match key.code {
                    KeyCode::Enter => SecretKey::Enter,
                    KeyCode::Esc => SecretKey::Cancel,
                    KeyCode::Char('c') | KeyCode::Char('C') if ctrl => SecretKey::Cancel,
                    KeyCode::Backspace => SecretKey::Backspace,
                    KeyCode::Char(c) => SecretKey::Char(c),
                    _ => continue,
                };

                let keep_going = match apply_secret_key(&mut secret, echo, &mut stdout, key) {
                    Ok(keep_going) => keep_going,
                    Err(e) => {
                        let _ = stdout.flush();
                        return Err(e);
                    }
                };
                stdout.flush()?;
                if !keep_going {
                    return Ok(secret);
                }
            }
            Event::Paste(text) => {
                for c in text.chars().filter(|c| !c.is_control()) {
                    apply_secret_key(&mut secret, echo, &mut stdout, SecretKey::Char(c))?;
                }
                stdout.flush()?;
            }
            _ => {}
        }
    }
}

/// Читает мастер-пароль, маскируя ввод звёздочками.
fn read_password(prompt: &str) -> Result<Zeroizing<String>> {
    read_secret_line(prompt, SecretEcho::Masked)
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
    if args.iter().skip(1).any(|arg| arg == "--help" || arg == "-h") {
        print_cli_help(&args[0]);
        return Ok(());
    }

    let profile_dir = parse_profile_dir(&args)?;
    let headless = parse_headless_args(&args)?;
    let base_dir = get_base_dir_with_override(profile_dir.as_deref())?;
    let recovery = args.iter().skip(1).any(|arg| arg == "--recovery");

    if headless.is_active() {
        if recovery {
            return Err(anyhow!(
                "--recovery cannot be combined with --send/--file"
            ));
        }
        return run_headless(&headless, &base_dir).await;
    }

    let vault = if recovery {
        run_recovery(&base_dir)?
    } else {
        unlock_vault(&base_dir)?
    };
    let (config, needs_language_choice) =
        Config::load_with_language_flag(&base_dir, &vault)?;
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
    if needs_language_choice {
        let lang = state.lang;
        state.welcome = Some(WelcomeFlow::new(lang));
        state.status = lang.texts().welcome_status.to_string();
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const MIXED: &str = "привет мир hello world";

    fn boundary(text: &str, index: usize) {
        assert!(
            text.is_char_boundary(index),
            "индекс {} не на границе UTF-8 в {:?}",
            index,
            text
        );
    }

    #[test]
    fn pending_ttl_is_shown_as_unconfirmed() {
        let texts = Lang::En.texts();

        let pending = ttl_status_text(texts, Some(30), true, false);
        assert_eq!(pending, tr(texts.ttl_status_pending, &["30"]));
        assert!(pending.contains("not confirmed"));

        let synced = ttl_status_text(texts, Some(30), false, true);
        assert!(synced.contains("synced with peer"));

        let one_way = ttl_status_text(texts, Some(30), false, false);
        assert!(one_way.contains("one-way"));

        let badge = ttl_badge_for(texts, Some(30), true, false);
        assert!(badge.contains("unconfirmed"));
        assert_ne!(badge, ttl_badge_for(texts, Some(30), false, true));
    }

    #[test]
    fn word_left_navigation_handles_mixed_text() {
        let mut cursor = MIXED.len();
        boundary(MIXED, cursor);

        move_word_left(MIXED, &mut cursor);
        assert_eq!(cursor, MIXED.find("world").unwrap());
        boundary(MIXED, cursor);

        move_word_left(MIXED, &mut cursor);
        assert_eq!(cursor, MIXED.find("hello").unwrap());
        boundary(MIXED, cursor);

        move_word_left(MIXED, &mut cursor);
        assert_eq!(cursor, MIXED.find("мир").unwrap());
        boundary(MIXED, cursor);

        move_word_left(MIXED, &mut cursor);
        assert_eq!(cursor, 0);

        // Левее начала строки курсор не уходит.
        move_word_left(MIXED, &mut cursor);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn word_right_navigation_handles_mixed_text() {
        let mut cursor = 0;

        move_word_right(MIXED, &mut cursor);
        assert_eq!(cursor, MIXED.find(' ').unwrap());
        boundary(MIXED, cursor);

        move_word_right(MIXED, &mut cursor);
        assert_eq!(cursor, MIXED.find("hello").unwrap() - 1);
        boundary(MIXED, cursor);

        move_word_right(MIXED, &mut cursor);
        assert_eq!(cursor, MIXED.find("world").unwrap() - 1);
        boundary(MIXED, cursor);

        move_word_right(MIXED, &mut cursor);
        assert_eq!(cursor, MIXED.len());

        // Правее конца строки курсор не уходит.
        move_word_right(MIXED, &mut cursor);
        assert_eq!(cursor, MIXED.len());
    }

    #[test]
    fn delete_word_before_removes_one_word() {
        let mut input = MIXED.to_string();
        let mut cursor = input.len();

        delete_word_before(&mut input, &mut cursor);
        assert_eq!(input, "привет мир hello ");
        assert_eq!(cursor, input.len());
        boundary(&input, cursor);

        delete_word_before(&mut input, &mut cursor);
        assert_eq!(input, "привет мир ");
        assert_eq!(cursor, input.len());

        // Разделитель перед словом тоже удаляется.
        delete_word_before(&mut input, &mut cursor);
        assert_eq!(input, "привет ");
        assert_eq!(cursor, input.len());

        delete_word_before(&mut input, &mut cursor);
        assert_eq!(input, "");
        assert_eq!(cursor, 0);

        // На пустой строке ничего не происходит.
        delete_word_before(&mut input, &mut cursor);
        assert_eq!(input, "");
        assert_eq!(cursor, 0);
    }

    #[test]
    fn delete_word_after_removes_one_word() {
        let mut input = "привет  мир!".to_string();
        let mut cursor = 0;

        delete_word_after(&mut input, &mut cursor);
        assert_eq!(input, "  мир!");
        assert_eq!(cursor, 0);

        // Следующее удаление справа съедает разделители и слово «мир».
        delete_word_after(&mut input, &mut cursor);
        assert_eq!(input, "!");
        assert_eq!(cursor, 0);
        boundary(&input, cursor);

        // В конце строки удаление справа безопасно.
        cursor = input.len();
        delete_word_after(&mut input, &mut cursor);
        assert_eq!(input, "!");
        assert_eq!(cursor, input.len());
    }

    #[test]
    fn delete_to_line_start_and_end_keep_utf8_boundaries() {
        let mut input = "hello мир".to_string();
        let mut cursor = input.find("мир").unwrap();

        delete_to_line_start(&mut input, &mut cursor);
        assert_eq!(input, "мир");
        assert_eq!(cursor, 0);
        boundary(&input, cursor);

        let mut input = "hello мир".to_string();
        let mut cursor = input.find(' ').unwrap();
        delete_to_line_end(&mut input, &mut cursor);
        assert_eq!(input, "hello");
        assert_eq!(cursor, input.len());
        boundary(&input, cursor);
    }

    #[test]
    fn utf8_emoji_and_cyrillic_do_not_panic() {
        let mut input = "🙂 тест".to_string();
        let mut cursor = input.len();

        move_word_left(&input, &mut cursor);
        assert_eq!(cursor, input.find("тест").unwrap());
        boundary(&input, cursor);

        // Курсор стоит в начале слова, поэтому удаление назад захватывает
        // и разделитель перед ним (эмодзи с пробелом).
        delete_word_before(&mut input, &mut cursor);
        assert_eq!(input, "тест");
        assert_eq!(cursor, 0);

        // Эмодзи — разделитель, а не часть слова; границы остаются
        // корректными и никакие срезы не паникуют.
        let emoji = "🙂";
        assert_eq!(word_left_boundary(emoji, emoji.len()), 0);
        assert_eq!(word_right_boundary(emoji, 0), emoji.len());
        assert_eq!(word_left_boundary("", 0), 0);
        assert_eq!(word_right_boundary("", 0), 0);
        assert_eq!(word_left_boundary("🙂 тест", 3), 0);
        assert_eq!(word_right_boundary("🙂 тест", 3), "🙂 тест".len());
    }

    #[test]
    fn punctuation_is_a_word_separator() {
        let text = "abc-деф,ghi";
        let mut cursor = text.len();

        move_word_left(text, &mut cursor);
        assert_eq!(cursor, text.find("ghi").unwrap());
        boundary(text, cursor);

        move_word_left(text, &mut cursor);
        assert_eq!(cursor, text.find("деф").unwrap());
        boundary(text, cursor);

        move_word_left(text, &mut cursor);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn paste_normalization_handles_newlines_and_controls() {
        assert_eq!(sanitize_pasted_text("привет\r\nмир"), "привет мир");
        assert_eq!(sanitize_pasted_text("hello\nworld\rok"), "hello world ok");
        assert_eq!(sanitize_pasted_text("a\tb"), "a b");
        assert_eq!(sanitize_pasted_text("a\u{7}b"), "ab");
        assert_eq!(sanitize_pasted_text("🙂\nтест"), "🙂 тест");
    }

    #[test]
    fn file_names_drop_escape_sequences_and_bidi_overrides() {
        assert_eq!(
            safe_file_name("../evil\x1b[31m\u{202E}.txt"),
            "evil[31m.txt"
        );
        assert_eq!(safe_file_name("\x1b\u{202E}"), "download");
        assert_eq!(safe_file_name("🙂 שלום.txt"), "🙂 שלום.txt");
        assert_eq!(
            invite_file_name("Alice\x1b[31m\u{202E}"),
            "Alice[31m_lastchance.invite"
        );
    }

    #[test]
    fn parses_ttl_durations() {
        assert_eq!(parse_ttl_duration("30").unwrap(), Some(30));
        assert_eq!(parse_ttl_duration("45s").unwrap(), Some(45));
        assert_eq!(parse_ttl_duration("5m").unwrap(), Some(300));
        assert_eq!(parse_ttl_duration("2h").unwrap(), Some(7200));
        assert_eq!(parse_ttl_duration("off").unwrap(), None);
        assert!(parse_ttl_duration("0").is_err());
        assert!(parse_ttl_duration("abc").is_err());
        assert!(parse_ttl_duration("").is_err());
        assert_eq!(ttl_countdown(90, 66), "00:24");
    }

    // ============================================================
    // L-6: скрытый ввод seed-фразы
    // ============================================================

    #[test]
    fn hidden_seed_input_never_echoes_characters() {
        let mut secret = Zeroizing::new(String::new());
        let mut output = Vec::new();

        for ch in "abandon ability able".chars() {
            assert!(apply_secret_key(
                &mut secret,
                SecretEcho::Hidden,
                &mut output,
                SecretKey::Char(ch),
            )
            .unwrap());
        }
        assert!(apply_secret_key(
            &mut secret,
            SecretEcho::Hidden,
            &mut output,
            SecretKey::Backspace,
        )
        .unwrap());
        assert!(!apply_secret_key(
            &mut secret,
            SecretEcho::Hidden,
            &mut output,
            SecretKey::Enter,
        )
        .unwrap());

        assert_eq!(secret.as_str(), "abandon ability abl");
        // Единственный вывод — перевод строки после Enter.
        assert_eq!(output, b"\r\n");
        assert!(!String::from_utf8_lossy(&output).contains("abandon"));
    }

    #[test]
    fn masked_password_echoes_one_star_per_char() {
        let mut secret = Zeroizing::new(String::new());
        let mut output = Vec::new();

        for ch in "abc".chars() {
            apply_secret_key(
                &mut secret,
                SecretEcho::Masked,
                &mut output,
                SecretKey::Char(ch),
            )
            .unwrap();
        }
        apply_secret_key(
            &mut secret,
            SecretEcho::Masked,
            &mut output,
            SecretKey::Backspace,
        )
        .unwrap();
        apply_secret_key(
            &mut secret,
            SecretEcho::Masked,
            &mut output,
            SecretKey::Enter,
        )
        .unwrap();

        assert_eq!(secret.as_str(), "ab");
        assert_eq!(output, b"***\x08 \x08\r\n");
    }

    #[test]
    fn secret_cancel_does_not_echo_input() {
        let mut secret = Zeroizing::new(String::new());
        let mut output = Vec::new();

        apply_secret_key(
            &mut secret,
            SecretEcho::Hidden,
            &mut output,
            SecretKey::Char('x'),
        )
        .unwrap();
        let error = apply_secret_key(
            &mut secret,
            SecretEcho::Hidden,
            &mut output,
            SecretKey::Cancel,
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "ввод отменён");
        assert_eq!(output, b"\r\n");
    }

    #[test]
    fn mnemonic_error_does_not_echo_phrase() {
        // 12 x "abandon" — валидные слова, но неверная контрольная сумма.
        let phrase = ["abandon"; 12].join(" ");
        let error = Identity::from_mnemonic(&phrase, "")
            .unwrap_err()
            .to_string();

        assert!(!error.contains("abandon"), "error leaked the phrase: {error}");
    }

    // ============================================================
    // L-5: мастер-пароль из файла и окружения
    // ============================================================

    fn write_password_file(
        dir: &std::path::Path,
        name: &str,
        contents: &str,
        mode: u32,
    ) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    #[test]
    fn password_file_is_read_and_trailing_newline_removed() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_password_file(dir.path(), "pass", "file secret \r\n", 0o600);
        let mut warnings = Vec::new();

        let password = resolve_headless_password(Some(path), None, &mut warnings).unwrap();

        assert_eq!(password.as_str(), "file secret ");
        assert!(warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn password_file_rejects_group_or_world_access() {
        let dir = tempfile::tempdir().unwrap();

        for mode in [0o640, 0o604, 0o666] {
            let path = write_password_file(dir.path(), "pass", "file-secret\n", mode);
            let mut warnings = Vec::new();
            let error = resolve_headless_password(Some(path), None, &mut warnings)
                .unwrap_err()
                .to_string();

            assert!(error.contains("0600"), "mode {mode:04o}: {error}");
            assert!(!error.contains("file-secret"));
        }
    }

    #[test]
    fn password_file_wins_over_environment() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_password_file(dir.path(), "pass", "file-secret\n", 0o600);
        let mut warnings = Vec::new();

        let password = resolve_headless_password(
            Some(path),
            Some(Zeroizing::new("env-secret".to_string())),
            &mut warnings,
        )
        .unwrap();

        assert_eq!(password.as_str(), "file-secret");
        let warnings = String::from_utf8(warnings).unwrap();
        assert!(warnings.contains("ignored"), "{warnings}");
        assert!(!warnings.contains("file-secret"));
        assert!(!warnings.contains("env-secret"));
    }

    #[test]
    fn environment_password_still_works_and_warns_without_value() {
        let mut warnings = Vec::new();

        let password = resolve_headless_password(
            None,
            Some(Zeroizing::new("env-secret".to_string())),
            &mut warnings,
        )
        .unwrap();

        assert_eq!(password.as_str(), "env-secret");
        let warnings = String::from_utf8(warnings).unwrap();
        assert!(warnings.contains("/proc/<pid>/environ"), "{warnings}");
        assert!(!warnings.contains("env-secret"));
    }

    #[test]
    fn missing_password_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut warnings = Vec::new();

        let error = resolve_headless_password(
            Some(dir.path().join("missing")),
            None,
            &mut warnings,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("LASTCHANCE_PASS_FILE"), "{error}");
    }

    #[test]
    fn password_file_must_be_regular() {
        let dir = tempfile::tempdir().unwrap();
        let mut warnings = Vec::new();

        let error = resolve_headless_password(
            Some(dir.path().to_path_buf()),
            None,
            &mut warnings,
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("not a regular file"), "{error}");
    }
}
