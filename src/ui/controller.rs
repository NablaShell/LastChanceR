// src/ui/controller.rs
use std::sync::Arc;

use slint::Model;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use tokio::sync::mpsc;

use anyhow::Result;

use crate::app::{App, AppEvent};
use crate::ui::models::{contacts_to_model, humanize_bytes, message_to_item, parse_file_message};

use crate::{AppWindow, MessageItem};

pub struct UiController {
    app: Arc<App>,
    window: AppWindow,
    rt: tokio::runtime::Handle,
}

impl UiController {
    pub fn new(app: Arc<App>, window: AppWindow, rt: tokio::runtime::Handle) -> Self {
        Self { app, window, rt }
    }

    pub fn wire(&self) -> Result<()> {
        self.refresh_profile();
        self.refresh_contacts();

        self.wire_send_message();
        self.wire_attach_file();
        self.wire_contact_selected();
        self.wire_download_file();
        self.wire_copy_text();
        self.wire_profile_actions();
        self.wire_contact_rename();
        self.wire_add_contact();
        self.wire_modals();
        self.wire_window_controls();

        Ok(())
    }

    fn refresh_profile(&self) {
        let p = self.app.get_profile();
        let get = |k: &str| {
            p.get(k)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_default()
        };
        self.window
            .set_profile_nickname(SharedString::from(get("nickname")));
        self.window
            .set_profile_hash(SharedString::from(get("hash")));
        self.window
            .set_profile_public_key(SharedString::from(get("publicKey")));
        self.window
            .set_profile_ed25519_public_key(SharedString::from(get("ed25519PublicKey")));
        self.window
            .set_profile_seed_phrase(SharedString::from(get("seedPhrase")));
    }

    fn refresh_contacts(&self) {
        if let Ok(contacts) = self.app.get_contacts() {
            self.window.set_contacts(contacts_to_model(&contacts));
        }
    }

    // ----- Send message -----
    fn wire_send_message(&self) {
        let app = self.app.clone();
        let rt = self.rt.clone();
        let window_weak = self.window.as_weak();

        self.window.on_send_message(move |text| {
            let room = {
                let w = match window_weak.upgrade() {
                    Some(w) => w,
                    None => return,
                };
                w.get_selected_id().to_string()
            };
            if room.is_empty() {
                return;
            }
            let text_str = text.to_string();
            let app = app.clone();
            let window_weak = window_weak.clone();

            rt.spawn(async move {
                if let Err(e) = app.send_message(&room, &text_str).await {
                    log::error!("send_message: {}", e);
                    return;
                }
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = window_weak.upgrade() {
                        append_ui_message(&w, &text_str, true, None);
                    }
                });
            });
        });
    }

    // ----- Attach file -----
    fn wire_attach_file(&self) {
        let app = self.app.clone();
        let rt = self.rt.clone();
        let window_weak = self.window.as_weak();

        self.window.on_attach_file(move || {
            let room = {
                let w = match window_weak.upgrade() {
                    Some(w) => w,
                    None => return,
                };
                w.get_selected_id().to_string()
            };
            if room.is_empty() {
                return;
            }

            let app = app.clone();
            let window_weak = window_weak.clone();

            rt.spawn(async move {
                let path = match tokio::task::spawn_blocking(|| {
                    crate::file_dialog::FileDialog::open_file_dialog("Select a file")
                })
                .await
                {
                    Ok(Ok(Some(p))) => p,
                    _ => return,
                };

                if let Err(e) = app.send_file_native(&room, &path).await {
                    log::error!("send_file: {}", e);
                }
                // Добавление в UI происходит через AppEvent UploadCompleted
            });
        });
    }

    // ----- Select contact -----
    fn wire_contact_selected(&self) {
        let app = self.app.clone();
        let rt = self.rt.clone();
        let window_weak = self.window.as_weak();

        self.window.on_contact_selected(move |idx| {
            let (hash, nickname) = {
                let w = match window_weak.upgrade() {
                    Some(w) => w,
                    None => return,
                };
                let contacts = w.get_contacts();
                match contacts.row_data(idx as usize) {
                    Some(c) => (c.hash.to_string(), c.nickname.to_string()),
                    None => return,
                }
            };

            app.switch_room(&hash);

            if let Some(w) = window_weak.upgrade() {
                w.set_selected_id(SharedString::from(&hash));
                w.set_selected_name(SharedString::from(&nickname));

                // сброс бейджа
                let contacts = w.get_contacts();
                let mut items: Vec<crate::ContactItem> = contacts.iter().collect();
                if let Some(c) = items.iter_mut().find(|c| c.hash.to_string() == hash) {
                    c.unread = 0;
                }
                w.set_contacts(ModelRc::new(VecModel::from(items)));
            }

            let app = app.clone();
            let window_weak = window_weak.clone();
            let hash_for_task = hash.clone();

            rt.spawn(async move {
                let msgs = app.get_messages(&hash_for_task, 50).unwrap_or_default();
                let items: Vec<MessageItem> = msgs
                    .iter()
                    .map(|m| {
                        let file_info = parse_file_message(&m.text);
                        message_to_item(
                            &m.id.to_string(),
                            &m.text,
                            m.direction == "out",
                            m.timestamp,
                            file_info,
                        )
                    })
                    .collect();

                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = window_weak.upgrade() {
                        w.set_messages(ModelRc::new(VecModel::from(items)));
                    }
                });
            });
        });
    }

    // ----- Download file -----
    fn wire_download_file(&self) {
        let app = self.app.clone();
        let rt = self.rt.clone();

        self.window.on_download_file(move |hash, name| {
            let app = app.clone();
            let hash = hash.to_string();
            let name = name.to_string();
            rt.spawn(async move {
                let name_for_dialog = name.clone();
                let save_path = match tokio::task::spawn_blocking(move || {
                    crate::file_dialog::FileDialog::save_file_dialog("Save file", &name_for_dialog)
                })
                .await
                {
                    Ok(Ok(Some(p))) => p,
                    _ => return,
                };

                if let Err(e) = app.download_and_save_file(&hash, &name, &save_path).await {
                    log::error!("download: {}", e);
                }
            });
        });
    }

    // ----- Copy text / share link / share json -----
    fn wire_copy_text(&self) {
        let app = self.app.clone();
        self.window.on_copy_text(move |text| {
            let text = text.to_string();
            let final_text = if text == "__share_link__" {
                app.get_my_contact_link()
            } else if text == "__share_json__" {
                app.get_my_contact_json()
            } else {
                text
            };

            if let Ok(mut cb) = arboard::Clipboard::new() {
                if let Err(e) = cb.set_text(final_text) {
                    log::error!("clipboard: {}", e);
                }
            }
        });
    }

    // ----- Profile actions -----
    fn wire_profile_actions(&self) {
        let window_weak = self.window.as_weak();
        self.window.on_open_profile(move || {
            if let Some(w) = window_weak.upgrade() {
                w.set_show_profile_modal(true);
            }
        });

        let window_weak = self.window.as_weak();
        self.window.on_open_share(move || {
            if let Some(w) = window_weak.upgrade() {
                w.set_show_share_modal(true);
            }
        });

        let window_weak = self.window.as_weak();
        self.window.on_open_add_contact(move || {
            if let Some(w) = window_weak.upgrade() {
                w.set_add_contact_input(SharedString::default());
                w.set_add_contact_error(SharedString::default());
                w.set_show_add_contact(true);
            }
        });

        // update own nickname
        let app = self.app.clone();
        let window_weak = self.window.as_weak();
        self.window.on_update_nickname(move |new_nick| {
            let nick = new_nick.to_string();
            if nick.trim().is_empty() {
                return;
            }
            if let Err(e) = app.update_nickname(nick.trim()) {
                log::error!("update_nickname: {}", e);
                return;
            }
            if let Some(w) = window_weak.upgrade() {
                w.set_profile_nickname(SharedString::from(nick.trim()));
            }
        });
    }

    // ----- Contact rename -----
    fn wire_contact_rename(&self) {
        let app = self.app.clone();
        let window_weak = self.window.as_weak();

        self.window.on_update_contact_nickname(move |idx, name| {
            let name = name.to_string();
            if name.trim().is_empty() {
                return;
            }
            let w = match window_weak.upgrade() {
                Some(w) => w,
                None => return,
            };
            let contacts = w.get_contacts();
            let hash = match contacts.row_data(idx as usize) {
                Some(c) => c.hash.to_string(),
                None => return,
            };
            if let Err(e) = app.update_contact_nickname(&hash, name.trim()) {
                log::error!("update_contact_nickname: {}", e);
                return;
            }
            if let Ok(new_contacts) = app.get_contacts() {
                w.set_contacts(contacts_to_model(&new_contacts));
            }
            w.set_renaming_index(-1);
        });

        // paste from clipboard
        let window_weak = self.window.as_weak();
        self.window.on_paste_from_clipboard(move || {
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if let Ok(text) = cb.get_text() {
                    if let Some(w) = window_weak.upgrade() {
                        w.set_add_contact_input(SharedString::from(text));
                    }
                }
            }
        });
    }

    // ----- Add contact -----
    fn wire_add_contact(&self) {
        let app = self.app.clone();
        let window_weak = self.window.as_weak();

        self.window.on_add_contact_submit(move |_h, _x, _n| {
            let w = match window_weak.upgrade() {
                Some(w) => w,
                None => return,
            };

            let input = w.get_add_contact_input().to_string();
            match parse_contact_input(&input) {
                Ok((hash, x25519, nickname)) => match app.add_contact(&hash, &x25519, &nickname) {
                    Ok(_) => {
                        w.set_show_add_contact(false);
                        w.set_add_contact_input(SharedString::default());
                        w.set_add_contact_error(SharedString::default());
                        if let Ok(c) = app.get_contacts() {
                            w.set_contacts(contacts_to_model(&c));
                            if c.len() == 1 {
                                w.invoke_contact_selected(0);
                            }
                        }
                    }
                    Err(e) => {
                        w.set_add_contact_error(SharedString::from(e.to_string()));
                    }
                },
                Err(e) => {
                    w.set_add_contact_error(SharedString::from(e));
                }
            }
        });
    }

    // ----- Modals / window -----
    fn wire_modals(&self) {
        let window_weak = self.window.as_weak();
        self.window.on_close_modals(move || {
            if let Some(w) = window_weak.upgrade() {
                w.set_show_add_contact(false);
                w.set_show_profile_modal(false);
                w.set_show_share_modal(false);
                w.set_add_contact_error(SharedString::default());
            }
        });
    }

    fn wire_window_controls(&self) {
        let window_weak = self.window.as_weak();
        self.window.on_close_app(move || {
            let _ = window_weak; // keep weak alive
            let _ = slint::quit_event_loop();
        });

        // TODO: минимизация недоступна в Slint 1.18.
        // Можно реализовать через winit или обновить Slint до 1.19+.
        self.window.on_minimize_app(move || {
            log::warn!("minimize not implemented for Slint 1.18");
        });

        // TODO: перетаскивание окна недоступно в Slint 1.18.
        // Можно реализовать через winit или обновить Slint до 1.19+.
        self.window.on_drag_window(move || {
            log::warn!("drag_window not implemented for Slint 1.18");
        });
    }

    // ----- Backend -> UI events -----
    pub fn start_event_listener(&self, mut rx: mpsc::UnboundedReceiver<AppEvent>) {
        let window_weak = self.window.as_weak();
        let app = self.app.clone();
        let rt = self.rt.clone(); // ← добавить

        rt.spawn(async move {
            // ← было tokio::spawn
            while let Some(event) = rx.recv().await {
                let window_weak = window_weak.clone();
                let app = app.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(w) = window_weak.upgrade() {
                        handle_app_event(&w, &app, event);
                    }
                });
            }
        });
    }
}

// ----- helpers -----

fn append_ui_message(
    window: &AppWindow,
    text: &str,
    is_own: bool,
    file_info: Option<(String, String, Option<String>)>,
) {
    let mut items: Vec<MessageItem> = window.get_messages().iter().collect();
    let id = format!("{}", chrono::Utc::now().timestamp_millis());
    items.push(message_to_item(
        &id,
        text,
        is_own,
        chrono::Utc::now(),
        file_info,
    ));
    window.set_messages(ModelRc::new(VecModel::from(items)));
}

fn handle_app_event(window: &AppWindow, app: &App, event: AppEvent) {
    match event {
        AppEvent::NewMessage {
            room_hash,
            text,
            timestamp: _,
            sender: _,
        } => {
            let current = window.get_selected_id().to_string();
            if current == room_hash {
                append_ui_message(window, &text, false, None);
            } else {
                // бейдж
                let contacts = window.get_contacts();
                let mut items: Vec<crate::ContactItem> = contacts.iter().collect();
                for c in items.iter_mut() {
                    if c.hash.to_string() == room_hash {
                        c.unread += 1;
                    }
                }
                window.set_contacts(ModelRc::new(VecModel::from(items)));
            }
        }
        AppEvent::UploadStarted { file_name } => {
            window.set_is_uploading(true);
            window.set_upload_status(SharedString::from(format!("Отправка {}...", file_name)));
        }
        AppEvent::UploadProgress { status, progress } => {
            window.set_upload_status(SharedString::from(format!("{} ({}%)", status, progress)));
        }
        AppEvent::UploadCompleted {
            file_name,
            file_hash,
            file_size,
        } => {
            window.set_is_uploading(false);
            window.set_upload_status(SharedString::default());

            let size_str = file_size.map(|s| humanize_bytes(s as u64));
            let text = format!(
                "📎 File: {}\nSize: {}\nHash: {}",
                file_name,
                size_str.clone().unwrap_or_else(|| "unknown".into()),
                file_hash
            );

            append_ui_message(window, &text, true, Some((file_name, file_hash, size_str)));
        }
        AppEvent::UploadError { error } => {
            window.set_is_uploading(false);
            window.set_upload_status(SharedString::default());
            log::error!("upload: {}", error);
        }
        AppEvent::DownloadStarted => {
            window.set_upload_status(SharedString::from("Download..."));
        }
        AppEvent::DownloadCompleted { file_path: _ } => {
            window.set_upload_status(SharedString::default());
        }
        AppEvent::DownloadError { error } => {
            window.set_upload_status(SharedString::default());
            log::error!("download: {}", error);
        }
        AppEvent::ContactImport {
            hash,
            x25519,
            ed25519,
            nickname,
        } => {
            let link = build_contact_link(&hash, &x25519, ed25519.as_deref(), &nickname);
            window.set_add_contact_input(SharedString::from(link));
            window.set_show_add_contact(true);
        }
        AppEvent::ContactImportError { error } => {
            window.set_add_contact_error(SharedString::from(error));
            window.set_show_add_contact(true);
        }
    }
    let _ = app;
}

fn build_contact_link(hash: &str, x25519: &str, ed25519: Option<&str>, nickname: &str) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("hash", hash);
    params.append_pair("x25519", x25519);
    if let Some(e) = ed25519 {
        params.append_pair("ed25519", e);
    }
    params.append_pair("nickname", nickname);
    format!("lastchance://contact?{}", params.finish())
}

/// Парсит contact link (lastchance://) или JSON.
/// Возвращает (hash, x25519, nickname).
fn parse_contact_input(input: &str) -> Result<(String, String, String), String> {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return Err("Введите ссылку, JSON или данные вручную".to_string());
    }

    // lastchance://contact?...
    if let Some(rest) = trimmed.strip_prefix("lastchance://contact?") {
        let params: std::collections::HashMap<String, String> =
            url::form_urlencoded::parse(rest.as_bytes())
                .into_owned()
                .collect();

        let hash = params.get("hash").cloned().unwrap_or_default();
        let x25519 = params.get("x25519").cloned().unwrap_or_default();
        let nickname = params.get("nickname").cloned().unwrap_or_default();

        if !hash.is_empty() && !x25519.is_empty() && !nickname.is_empty() {
            return Ok((hash, x25519, nickname));
        }
        return Err("Ссылка не содержит всех параметров".to_string());
    }

    // JSON
    if trimmed.starts_with('{') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            let hash = v
                .get("hash")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let x25519 = v
                .get("x25519")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let nickname = v
                .get("nickname")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if !hash.is_empty() && !x25519.is_empty() && !nickname.is_empty() {
                return Ok((hash, x25519, nickname));
            }
        }
        return Err("Невалидный JSON контакта".to_string());
    }

    // Manual: hash x25519 nickname
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() >= 3 {
        let hash = parts[0].to_string();
        let x25519 = parts[1].to_string();
        let nickname = parts[2..].join(" ");
        if hash.len() == 64 && x25519.len() == 64 {
            return Ok((hash, x25519, nickname));
        }
    }

    Err("Не удалось распознать формат".to_string())
}
