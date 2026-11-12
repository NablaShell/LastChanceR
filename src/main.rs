// CLI-точка входа. Вся логика мессенджера находится в библиотеке (src/lib.rs).
//
// Архитектура:
//   - tokio Runtime живёт весь процесс (ядро: Listener, Sender, события).
//   - rustyline::ExternalPrinter используется, чтобы входящие события выводились
//     в терминал, не затирая текущую строку ввода.
//   - readline-петля работает на главном потоке; команды, которые дергают async
//     методы ядра, выполняются через Handle::block_on.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;
use tokio::sync::mpsc;

use lastchance::{get_base_dir, App, AppEvent, Config};

const PROMPT: &str = "lastchance> ";

#[allow(dead_code)]
type Printer = Arc<Mutex<Box<dyn rustyline::ExternalPrinter + Send>>>;

fn out(printer: &Printer, text: &str) {
    if let Ok(mut p) = printer.lock() {
        let _ = p.print(text.to_string());
    }
}

/// Короткое представление hash (6 символов с начала и с конца).
fn short_hash(h: &str) -> String {
    if h.len() > 12 {
        let (head, tail) = h.split_at(6);
        format!("{}…{}", head, &tail[tail.len() - 6..])
    } else {
        h.to_string()
    }
}

fn format_time(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|t| t.format("%H:%M:%S").to_string())
        .unwrap_or_else(|| "??:??:??".to_string())
}

fn format_event(event: &AppEvent) -> String {
    match event {
        AppEvent::NewMessage {
            room_hash,
            text,
            timestamp,
            sender,
        } => format!(
            "[{}] {} ({}) : {}",
            format_time(*timestamp),
            sender,
            short_hash(room_hash),
            text
        ),
        AppEvent::ContactImport { hash, nickname, .. } => {
            format!("[import] {} ({})", nickname, short_hash(hash))
        }
        AppEvent::ContactImportError { error } => format!("[import] ошибка: {}", error),
        AppEvent::UploadStarted { file_name } => format!("[upload] {}: начало", file_name),
        AppEvent::UploadProgress { status, progress } => {
            format!("[upload] {}% — {}", progress, status)
        }
        AppEvent::UploadCompleted {
            file_name,
            file_hash,
            file_size,
        } => {
            let size = file_size.map(|s| format!(", {} B", s)).unwrap_or_default();
            format!(
                "[upload] {} завершён, hash={}{}",
                file_name,
                short_hash(file_hash),
                size
            )
        }
        AppEvent::UploadError { error } => format!("[upload] ошибка: {}", error),
        AppEvent::DownloadStarted => "[download] начат".to_string(),
        AppEvent::DownloadCompleted { file_path } => format!("[download] сохранён: {}", file_path),
        AppEvent::DownloadError { error } => format!("[download] ошибка: {}", error),
    }
}

fn print_help(printer: &Printer) {
    out(
        printer,
        "\
Команды:
  /help                        — этот список
  /profile                     — ваш профиль (nickname, hash, ключи, seed)
  /invite                      — ссылка-приглашение для импорта вашего контакта
  /export                      — контакт в формате JSON
  /contacts                    — список контактов
  /join <link|hash x25519 nickname>
                               — добавить контакт по ссылке lastchance:// или вручную
  /room [hash]                 — показать активный чат или переключиться
  /messages [limit]            — последние сообщения активного чата (по умолчанию 50)
  /sendfile <path>             — отправить файл в активный чат
  /download <hash> <save_path> — скачать и расшифровать файл в активный чат
  /nick <name>                 — сменить свой ник
  /rename <hash> <name>        — переименовать контакт
  /quit, /exit                 — выход

Любая строка без ведущего / — обычное сообщение в активный чат.",
    );
}

fn parse_contact_link(raw: &str) -> Result<(String, String, String)> {
    let params_str = raw
        .strip_prefix("lastchance://contact?")
        .ok_or_else(|| anyhow!("это не ссылка lastchance://contact?..."))?;

    let params: HashMap<String, String> = url::form_urlencoded::parse(params_str.as_bytes())
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

fn usage(printer: &Printer, text: &str) {
    out(printer, &format!("использование: {}", text));
}

fn run_command(rt: &tokio::runtime::Handle, app: &Arc<App>, printer: &Printer, line: &str) {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let cmd = parts.first().copied().unwrap_or("");

    match cmd {
        "/help" | "/?" => print_help(printer),

        "/profile" => {
            let profile = app.get_profile();
            match serde_json::to_string_pretty(&profile) {
                Ok(s) => out(printer, &s),
                Err(e) => out(printer, &format!("ошибка сериализации: {}", e)),
            }
        }

        "/invite" => out(printer, &app.get_my_contact_link()),

        "/export" => out(printer, &app.get_my_contact_json()),

        "/contacts" => match app.get_contacts() {
            Ok(contacts) => {
                if contacts.is_empty() {
                    out(printer, "контактов нет. Добавьте через /join <link>");
                } else {
                    for c in &contacts {
                        out(printer, &format!("{}  {}", short_hash(&c.hash), c.nickname));
                    }
                }
            }
            Err(e) => out(printer, &format!("ошибка: {:#}", e)),
        },

        "/join" => {
            let rest: Vec<&str> = parts[1..].to_vec();
            let (hash, result) = if rest.len() == 1 {
                match parse_contact_link(rest[0]) {
                    Ok((h, key, nick)) => {
                        (Some(h.clone()), app.add_contact(&h, &key, &nick))
                    }
                    Err(e) => (None, Err(e)),
                }
            } else if rest.len() >= 3 && !rest[0].starts_with("lastchance://") {
                (
                    Some(rest[0].to_string()),
                    app.add_contact(rest[0], rest[1], rest[2]),
                )
            } else {
                (
                    None,
                    Err(anyhow!("/join <link>  или  /join <hash> <x25519> <nickname>")),
                )
            };

            match result {
                Ok(()) => {
                    if let Some(h) = &hash {
                        app.switch_room(h);
                        out(printer, &format!("контакт добавлен, активный чат: {}", short_hash(h)));
                    } else {
                        out(printer, "контакт добавлен");
                    }
                }
                Err(e) => out(printer, &format!("ошибка: {:#}", e)),
            }
        }

        "/room" => {
            if let Some(h) = parts.get(1) {
                app.switch_room(h);
                out(printer, &format!("активный чат: {}", short_hash(h)));
            } else {
                let room = app.get_current_room();
                if room.is_empty() {
                    out(printer, "активного чата нет. /join <link>");
                } else {
                    out(printer, &format!("активный чат: {}", short_hash(&room)));
                }
            }
        }

        "/messages" => {
            let room = app.get_current_room();
            if room.is_empty() {
                out(printer, "активного чата нет. /join <link>");
                return;
            }
            let limit: i64 = parts
                .get(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(50)
                .max(1);
            match app.get_messages(&room, limit) {
                Ok(messages) => {
                    if messages.is_empty() {
                        out(printer, "сообщений в этом чате нет");
                        return;
                    }
                    for m in &messages {
                        let dir = if m.direction == "in" { "<-" } else { "->" };
                        let t = m.timestamp.format("%H:%M:%S").to_string();
                        out(
                            printer,
                            &format!(
                                "[{}] {} {}: {}",
                                t,
                                dir,
                                short_hash(&m.contact_hash),
                                m.text
                            ),
                        );
                    }
                }
                Err(e) => out(printer, &format!("ошибка: {:#}", e)),
            }
        }

        "/sendfile" => {
            let Some(path) = parts.get(1) else {
                usage(printer, "/sendfile <path>");
                return;
            };
            let room = app.get_current_room();
            if room.is_empty() {
                out(printer, "активного чата нет. /join <link>");
                return;
            }
            let path = path.to_string();
            let app_ref = app.clone();
            match rt.block_on(async move { app_ref.send_file_native(&room, &path).await }) {
                Ok(()) => out(printer, "файл отправлен"),
                Err(e) => out(printer, &format!("ошибка: {:#}", e)),
            }
        }

        "/download" => {
            if parts.len() < 3 {
                usage(printer, "/download <hash> <save_path>");
                return;
            }
            let room = app.get_current_room();
            if room.is_empty() {
                out(printer, "активного чата нет. /join <link>");
                return;
            }
            let file_hash = parts[1].to_string();
            let save_path = parts[2].to_string();
            let app_ref = app.clone();
            match rt.block_on(async move {
                app_ref
                    .download_and_save_file(&file_hash, &save_path, &save_path)
                    .await
            }) {
                Ok(()) => out(printer, "файл сохранён"),
                Err(e) => out(printer, &format!("ошибка: {:#}", e)),
            }
        }

        "/nick" => {
            let Some(name) = parts.get(1) else {
                usage(printer, "/nick <name>");
                return;
            };
            match app.update_nickname(name) {
                Ok(()) => out(printer, &format!("ник изменён: {}", name)),
                Err(e) => out(printer, &format!("ошибка: {:#}", e)),
            }
        }

        "/rename" => {
            if parts.len() < 3 {
                usage(printer, "/rename <hash> <name>");
                return;
            }
            match app.update_contact_nickname(parts[1], parts[2]) {
                Ok(()) => out(printer, "контакт переименован"),
                Err(e) => out(printer, &format!("ошибка: {:#}", e)),
            }
        }

        _ => out(
            printer,
            &format!("неизвестная команда: {}. Введите /help", cmd),
        ),
    }
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let handle = runtime.handle().clone();

    // ---------- Инициализация ядра ----------
    let base_dir = get_base_dir()?;
    let config = Config::load(&base_dir)?;
    let (event_tx, event_rx) = mpsc::unbounded_channel::<AppEvent>();
    let app = Arc::new(App::new(config, base_dir, event_tx)?);

    // ---------- ExternalPrinter: вывод не затирает строку ввода ----------
    let mut rl = DefaultEditor::new()?;
    let printer: Printer = Arc::new(Mutex::new(Box::new(rl.create_external_printer()?)));

    // Потребитель событий ядра: печатает через ExternalPrinter в фоне.
    {
        let printer = printer.clone();
        handle.spawn(async move {
            let mut event_rx = event_rx;
            while let Some(event) = event_rx.recv().await {
                if let Ok(mut p) = printer.lock() {
                    let _ = p.print(format_event(&event));
                }
            }
        });
    }

    // Deep link из argv (Linux/Windows): lastchance://contact?...
    for arg in std::env::args().skip(1) {
        if arg.starts_with("lastchance://") {
            app.handle_scheme_url(&arg);
        }
    }

    // Запуск пуллера сообщений в фоне.
    {
        let app_for_start = app.clone();
        handle.spawn(async move {
            if let Err(e) = app_for_start.start().await {
                eprintln!("App::start: {:#}", e);
            }
        });
    }

    print_help(&printer);

    // ---------- Интерактивная readline-петля ----------
    loop {
        match rl.readline(PROMPT) {
            Ok(line) => {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(trimmed);

                if trimmed == "/quit" || trimmed == "/exit" {
                    break;
                }

                if trimmed.starts_with('/') {
                    run_command(&handle, &app, &printer, trimmed);
                } else {
                    // Обычный текст → сообщение в активный чат.
                    let room = app.get_current_room();
                    if room.is_empty() {
                        out(
                            &printer,
                            "активного чата нет. Добавьте контакт: /join <link>",
                        );
                        continue;
                    }
                    match handle.block_on(app.send_message(&room, trimmed)) {
                        Ok(()) => {}
                        Err(e) => out(&printer, &format!("ошибка отправки: {:#}", e)),
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl+C — очищаем строку и продолжаем.
                println!();
            }
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {:?}", e);
                break;
            }
        }
    }

    println!("выход");
    Ok(())
}