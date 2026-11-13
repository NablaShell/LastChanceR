// Полноэкранный TUI-клиент LastChance.
//
// Архитектура:
//   - tokio Runtime живёт весь процесс (ядро: Listener, Sender, события).
//   - crossterm::event::EventStream и канал AppEvent слушаются в одном
//     `tokio::select!`, поэтому интерфейс остаётся отзывчивым.
//   - Вся отрисовка — ratatui: история чата, статус-бар и поле ввода.

use std::io::{self, Stdout};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use crossterm::cursor::Show;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyEventKind,
    KeyModifiers, MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures::StreamExt;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Position};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use tokio::sync::mpsc;

use lastchance::{get_base_dir_with_override, App, AppEvent, Config};

const HELP: &str = "\
Команды:
  /help                        — этот список
  /profile                     — профиль (nickname, hash, ключи)
  /seed                        — seed-фраза (никому не показывайте!)
  /invite [ -f [dir|file] ]    — скопировать ссылку в буфер обмена;
                                 с -f — также сохранить в файл инвайта
  /export                      — контакт в формате JSON
  /contacts                    — список контактов
  /join <link | hash x25519 nickname>
                               — добавить контакт и открыть чат
  /join -f <path>              — добавить контакт из файла-инвайта
  /room [hash]                 — показать или сменить активную комнату
  /messages [limit]            — последние сообщения комнаты
  /sendfile <path>             — отправить файл в активную комнату
  /download <hash> <path>      — скачать и расшифровать файл
  /nick <name>                 — сменить свой ник
  /rename <hash> <name>        — переименовать контакт
  /quit, /exit                 — выход

Любая строка без ведущего / отправляется в активную комнату.
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
    /// Долгоживущий объект буфера обмена: на X11 он остаётся владельцем
    /// selection, пока жив процесс, поэтому вставка в других окнах работает.
    clipboard: Option<arboard::Clipboard>,
    /// Требуется очистка экрана перед следующей перерисовкой (после вывода
    /// диагностики библиотек в stderr, чтобы ratatui не «поехал»).
    needs_clear: bool,
}

enum UiNotice {
    Status(String),
    Error(String),
}

impl UiState {
    fn new(app: &App) -> Self {
        let room = app.get_current_room();
        let room_label = room_label(app, &room);
        let feed = load_room_feed(app, &room);

        // Создаём буфер обмена один раз: пересоздание на каждый вызов
        // приводило к предупреждению arboard «dropped too quickly».
        let (clipboard, status) = match arboard::Clipboard::new() {
            Ok(clipboard) => (Some(clipboard), "готово".to_string()),
            Err(e) => (None, format!("буфер обмена недоступен: {}", e)),
        };

        Self {
            feed,
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
            clipboard,
            needs_clear: false,
        }
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
        if let Err(e) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
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
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture, Show);
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

fn load_room_feed(app: &App, room: &str) -> Vec<FeedEntry> {
    if room.is_empty() {
        return Vec::new();
    }

    match app.get_messages(room, 300) {
        Ok(messages) => messages
            .into_iter()
            .map(|m| FeedEntry {
                kind: if m.direction == "in" {
                    FeedKind::Incoming
                } else {
                    FeedKind::Outgoing
                },
                text: format!("[{}] {}", m.timestamp.format("%H:%M"), m.text),
            })
            .collect(),
        Err(e) => vec![FeedEntry {
            kind: FeedKind::Error,
            text: format!("Не удалось загрузить историю: {:#}", e),
        }],
    }
}

fn reload_room(app: &App, state: &mut UiState) {
    state.feed = load_room_feed(app, &state.room);
    state.scroll = 0;
    state.follow = true;
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
// ОТРИСОВКА
// ============================================================

fn draw_ui(frame: &mut Frame, state: &mut UiState) {
    let chunks = Layout::vertical([
        Constraint::Min(3),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .split(frame.area());

    // ---------- 1. История сообщений ----------
    let title = if state.room.is_empty() {
        "Чат — нет активной комнаты".to_string()
    } else {
        format!(" {} · {} ", state.room_label, short_hash(&state.room))
    };
    let chat_block = Block::default().borders(Borders::ALL).title(title);
    let chat_inner = chat_block.inner(chunks[0]);
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
    frame.render_widget(paragraph, chunks[0]);

    // ---------- 2. Статус-бар ----------
    let room = if state.room.is_empty() {
        "—".to_string()
    } else {
        format!("{} ({})", state.room_label, short_hash(&state.room))
    };
    let status = format!(
        " {}   Room: {}   {} ",
        state.nickname, room, state.status
    );
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            status,
            Style::default().bg(Color::DarkGray).fg(Color::White),
        ))),
        chunks[1],
    );

    // ---------- 3. Поле ввода ----------
    let input_block = Block::default().borders(Borders::ALL).title(" Ввод ");
    let input_inner = input_block.inner(chunks[2]);
    frame.render_widget(input_block, chunks[2]);

    let prefix = "> ";
    let avail = (input_inner.width as usize).saturating_sub(prefix.len());
    let before = state.input[..state.cursor].chars().count();
    let cursor_col = if avail == 0 {
        0
    } else {
        before.min(avail - 1)
    };
    let start = before - cursor_col;
    let visible: String = state.input.chars().skip(start).take(avail).collect();

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
            if room_hash == state.room {
                state.feed.push(FeedEntry {
                    kind: FeedKind::Incoming,
                    text: format!("[{}] {}: {}", event_time(timestamp), sender, text),
                });
                state.status = format!("новое сообщение от {}", sender);
            } else {
                state.status = format!(
                    "новое сообщение в другой комнате ({})",
                    short_hash(&room_hash)
                );
            }
        }
        AppEvent::ContactImport {
            hash,
            x25519,
            nickname,
            ..
        } => match app.add_contact(&hash, &x25519, &nickname) {
            Ok(()) => {
                app.switch_room(&hash);
                state.room = hash.clone();
                state.room_label = nickname.clone();
                reload_room(app, state);
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
            let size = file_size.map(|s| format!(", {} B", s)).unwrap_or_default();
            push_system(
                state,
                &format!(
                    "Файл {} отправлен, hash={}{}",
                    file_name,
                    short_hash(&file_hash),
                    size
                ),
            );
            state.status = "файл отправлен".to_string();
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

            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
            {
                return Ok(true);
            }

            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('v') | KeyCode::Char('V'))
            {
                paste_from_clipboard(state);
                return Ok(false);
            }

            match key.code {
                KeyCode::Enter => {
                    let line = state.input.trim().to_string();
                    state.input.clear();
                    state.cursor = 0;

                    if line.is_empty() {
                        return Ok(false);
                    }

                    if line.starts_with('/') {
                        return handle_command(app, state, ui_tx, &line).await;
                    }

                    send_plain_message(app, state, &line).await;
                }
                KeyCode::Char(c) => {
                    if !key.modifiers.contains(KeyModifiers::CONTROL) {
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
                    state.input.clear();
                    state.cursor = 0;
                }
                _ => {}
            }
        }
        Event::Mouse(mouse) => match mouse.kind {
            MouseEventKind::ScrollUp => scroll_up(state, 3),
            MouseEventKind::ScrollDown => scroll_down(state, 3),
            _ => {}
        },
        Event::Paste(text) => insert_text(state, &text),
        Event::Resize(_, _) => {
            // Новые размеры будут учтены на следующем кадре.
        }
        _ => {}
    }

    Ok(false)
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
    app.switch_room(hash);
    state.room = hash.to_string();
    state.room_label = room_label(app, &state.room);
    reload_room(app, state);
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
    let cmd = parts.first().copied().unwrap_or("");

    match cmd {
        "/help" | "/?" => push_system(state, HELP),

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
            if let Some(hash) = parts.get(1) {
                app.switch_room(hash);
                state.room = hash.to_string();
                state.room_label = room_label(app, &state.room);
                reload_room(app, state);
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

            match app.get_messages(&state.room, limit) {
                Ok(messages) => {
                    if messages.is_empty() {
                        push_system(state, "Сообщений в этой комнате нет");
                    } else {
                        for m in messages {
                            let dir = if m.direction == "in" { "←" } else { "→" };
                            push_system(
                                state,
                                &format!(
                                    "[{}] {} {}",
                                    m.timestamp.format("%H:%M:%S"),
                                    dir,
                                    m.text
                                ),
                            );
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
            let Some(path) = parts.get(1) else {
                push_error(state, "Использование: /sendfile <path>");
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
            state.status = "отправка файла...".to_string();

            tokio::spawn(async move {
                match app_ref.send_file_native(&room, &path).await {
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
            if parts.len() < 3 {
                push_error(state, "Использование: /download <hash> <save_path>");
                return Ok(false);
            }
            if state.room.is_empty() {
                push_error(state, "Нет активной комнаты. /join <link>");
                return Ok(false);
            }

            let app_ref = app.clone();
            let file_hash = parts[1].to_string();
            let save_path = parts[2].to_string();
            let tx = ui_tx.clone();
            state.status = "скачивание файла...".to_string();

            tokio::spawn(async move {
                match app_ref
                    .download_and_save_file(&file_hash, &save_path, &save_path)
                    .await
                {
                    Ok(()) => {
                        let _ = tx.send(UiNotice::Status("файл сохранён".to_string()));
                    }
                    Err(e) => {
                        let _ = tx.send(UiNotice::Error(format!(
                            "Ошибка скачивания файла: {:#}",
                            e
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
                    push_system(state, "Контакт переименован");
                    state.status = "контакт переименован".to_string();
                }
                Err(e) => push_error(state, &format!("Ошибка переименования: {:#}", e)),
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

#[tokio::main]
async fn main() -> Result<()> {
    install_panic_hook();

    let args: Vec<String> = std::env::args().collect();
    let data_dir = parse_data_dir(&args)?;
    let base_dir = get_base_dir_with_override(data_dir.as_deref())?;
    let config = Config::load(&base_dir)?;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();
    let app = Arc::new(App::new(config, base_dir, event_tx)?);

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
