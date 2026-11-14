//! Локализация интерфейса LastChance.
//!
//! Модуль хранит все пользовательские строки TUI на английском и русском
//! языках. Названия слэш-команд и флаги CLI намеренно не переводятся:
//! они являются частью протокола и остаются одинаковыми для обеих локалей.

use serde::{Deserialize, Serialize};

/// Язык интерфейса. По умолчанию используется английский.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    #[default]
    En,
    Ru,
}

impl Lang {
    /// Разбирает код языка (`en`, `ru`), регистр не важен.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "en" | "english" => Some(Self::En),
            "ru" | "russian" | "рус" | "русский" => Some(Self::Ru),
            _ => None,
        }
    }

    /// Короткий код для `/lang` и конфига.
    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
        }
    }

    /// Название языка на нём самом (для меню настроек и welcome-окна).
    pub fn native_name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::Ru => "Русский",
        }
    }

    /// Возвращает набор строк текущей локали.
    pub fn texts(self) -> &'static Texts {
        match self {
            Self::En => &EN_TEXTS,
            Self::Ru => &RU_TEXTS,
        }
    }

    /// Секции справки `/help` текущей локали.
    pub fn help_sections(self) -> &'static [HelpSection] {
        match self {
            Self::En => EN_HELP_SECTIONS,
            Self::Ru => RU_HELP_SECTIONS,
        }
    }

    /// Стандартный заголовок stealth-уведомления.
    pub fn default_stealth_title(self) -> &'static str {
        match self {
            Self::En => "Eye break",
            Self::Ru => "Перерыв для глаз",
        }
    }

    /// Стандартный текст stealth-уведомления.
    pub fn default_stealth_body(self) -> &'static str {
        match self {
            Self::En => "Time to rest. Take an eye break for {sec} seconds",
            Self::Ru => "Время отдыха. Сделайте разминку для глаз на {sec} секунд",
        }
    }

    /// Человекочитаемая подпись режима уведомлений.
    pub fn notify_level_label(self, level: u8) -> &'static str {
        match (self, level) {
            (Self::En, 0) => "0 — disabled",
            (Self::En, 1) => "1 — Stealth (disguised)",
            (Self::En, 2) => "2 — sender only",
            (Self::En, 3) => "3 — full preview",
            (Self::En, _) => "unknown level",
            (Self::Ru, 0) => "0 — отключены",
            (Self::Ru, 1) => "1 — Stealth (маскировка)",
            (Self::Ru, 2) => "2 — только отправитель",
            (Self::Ru, 3) => "3 — полный предпросмотр",
            (Self::Ru, _) => "неизвестный уровень",
        }
    }
}

/// Подставляет позиционные аргументы `{}` в шаблон текущей локали.
pub fn tr(template: &str, args: &[&str]) -> String {
    let mut text = template.to_string();
    for arg in args {
        text = text.replacen("{}", arg, 1);
    }
    text
}

/// Строка таблицы справки: слева — команда и её алиасы.
pub struct HelpRow {
    pub keys: &'static str,
    pub desc: &'static str,
}

/// Секция справки для модального окна (F1).
pub struct HelpSection {
    pub title: &'static str,
    pub rows: &'static [HelpRow],
}

/// Строки приветственного окна выбора языка.
pub struct WelcomeText {
    pub title: &'static str,
    pub subtitle: &'static str,
    pub settings: &'static str,
    pub help: &'static str,
    pub language: &'static str,
    pub footer: &'static str,
}

impl Lang {
    /// Текст колонки приветственного окна для указанного языка.
    pub fn welcome_text(self) -> &'static WelcomeText {
        match self {
            Self::En => &WELCOME_EN,
            Self::Ru => &WELCOME_RU,
        }
    }
}

macro_rules! texts {
    ( $( $field:ident : $en:expr, $ru:expr ; )* ) => {
        /// Все статические строки TUI и шаблоны для `format!`.
        pub struct Texts {
            $( pub $field: &'static str, )*
        }

        static EN_TEXTS: Texts = Texts {
            $( $field: $en, )*
        };

        static RU_TEXTS: Texts = Texts {
            $( $field: $ru, )*
        };
    };
}

texts! {
    // ---------- Общее ----------
    ready: "ready", "готово";
    clipboard_unavailable: "clipboard unavailable: {}", "буфер обмена недоступен: {}";
    clipboard_unavailable_short: "clipboard unavailable", "буфер обмена недоступен";
    clipboard_copied: "copied to clipboard", "скопировано в буфер обмена";
    clipboard_pasted: "pasted from clipboard", "вставлено из буфера обмена";
    clipboard_input_copied: "input copied; Ctrl+C on an empty line quits", "ввод скопирован; Ctrl+C на пустой строке — выход";
    clipboard_secret_not_copied: "secret field is not copied to the clipboard", "секретное поле не копируется в буфер";
    clipboard_password_reset: "password input cleared", "ввод пароля сброшен";
    clipboard_paste_failed: "clipboard unavailable: {}", "буфер обмена недоступен: {}";
    terminal_error: "terminal error: {}", "ошибка терминала: {}";
    create_dir_failed: "failed to create {}: {}", "не удалось создать {}: {}";
    create_folder_failed: "failed to create folder {}: {}", "не удалось создать папку {}: {}";
    write_file_failed: "failed to write {}: {}", "не удалось записать {}: {}";
    cwd_failed: "failed to determine the current directory: {}", "не удалось определить текущую директорию: {}";
    file_not_found: "file not found: {}", "файл не найден: {}";
    permission_denied: "permission denied: {}", "нет прав на чтение: {}";
    stat_failed: "failed to get info about {}: {}", "не удалось получить информацию о {}: {}";
    not_regular_file: "not a regular file (maybe a directory): {}", "это не обычный файл (возможно, директория): {}";
    resolve_path_failed: "failed to resolve path {}: {}", "не удалось разрешить путь {}: {}";
    system_path_forbidden: "sending from a system directory is forbidden: {} (use /sf --force {})", "отправка из системной директории запрещена: {} (используйте /sf --force {})";
    open_file_failed: "failed to open {}: {}", "не удалось открыть {}: {}";
    invalid_file_path: "invalid file path", "некорректный путь к файлу";
    password_min_app: "new password must be at least {} characters", "новый пароль должен быть не короче {} символов";
    config_lock_failed: "configuration unavailable: lock is poisoned", "конфигурация недоступна: блокировка повреждена";

    // ---------- Боковая панель и чат ----------
    sidebar_title: " Chats ({}) ", " Чаты ({}) ";
    chat_no_room: "Chat — no active room", "Чат — нет активной комнаты";
    room_label: "Room", "Комната";
    status_no_chats: "no chats", "чатов нет";
    status_chat: "chat: {}", "чат: {}";
    history_load_failed: "Failed to load history: {}", "Не удалось загрузить историю: {}";
    file_sent_out: "[{}] 📎 you sent file [#{}] {} (type /dl or /dl {})", "[{}] 📎 вы отправили файл [#{}] {} (введите /dl или /dl {})";
    file_sent_in: "[{}] 📎 {} sent file [#{}] {} (type /dl or /dl {})", "[{}] 📎 {} отправил файл [#{}] {} (введите /dl или /dl {})";
    no_active_room: "No active room. Add a contact via /join <link> or /room <hash>.", "Нет активной комнаты. Добавьте контакт через /join <link> или /room <hash>.";
    no_active_room_short: "No active room. /join <link>", "Нет активной комнаты. /join <link>";
    send_error: "Send error: {}", "Ошибка отправки: {}";
    message_sent: "message sent", "сообщение отправлено";
    sidebar_on: "Sidebar shown", "Боковая панель включена";
    sidebar_off: "Sidebar hidden", "Боковая панель скрыта";

    // ---------- Исчезающие RAM-сообщения (/ttl) ----------
    ttl_status_off: "RAM TTL is off", "RAM TTL выключен";
    ttl_status_on: "RAM TTL: {} (one-way; new messages are RAM-only)", "RAM TTL: {} (односторонний; новые сообщения только в RAM)";
    ttl_status_synced: "RAM TTL-SYN: {} (synced with peer)", "RAM TTL-SYN: {} (синхронизирован с собеседником)";
    ttl_enabled_local: "RAM TTL enabled: {} (one-way)", "RAM TTL включён: {} (односторонний)";
    ttl_enabled_synced: "RAM TTL-SYN enabled: {} (peer notified)", "RAM TTL-SYN включён: {} (собеседник уведомлён)";
    ttl_disabled_local: "RAM TTL disabled", "RAM TTL выключен";
    ttl_disabled_synced: "RAM TTL-SYN disabled; peer notified", "RAM TTL-SYN выключен; собеседник уведомлён";
    ttl_invalid: "Invalid TTL duration: {} (use 30s, 5m, 2h or off)", "Некорректная длительность TTL: {} (используйте 30s, 5m, 2h или off)";
    ttl_apply_error: "Failed to set RAM TTL: {}", "Не удалось установить RAM TTL: {}";
    ttl_peer_enabled: "Peer enabled temporary RAM-TTL: {}s", "Собеседник включил временный RAM-TTL: {}s";
    ttl_peer_disabled: "Peer disabled TTL", "Собеседник отключил TTL";
    ttl_self_enabled: "RAM-TTL sync from your other session: {}s", "Синхронизация RAM-TTL из вашей другой сессии: {}s";
    ttl_self_disabled: "RAM-TTL sync disabled", "Синхронизация RAM-TTL выключена";
    ttl_badge: "[RAM TTL: {}s]", "[RAM TTL: {}s]";
    ttl_badge_synced: "[RAM TTL-SYN: {}s]", "[RAM TTL-SYN: {}s]";
    ttl_purge_error: "TTL cleanup error: {}", "Ошибка очистки TTL: {}";

    // ---------- Автодополнение ----------
    comp_force: "flag --force: allow system paths", "флаг --force: разрешить системные пути";
    comp_command: "command: {}", "команда: {}";
    comp_no_commands: "no commands for «{}»", "нет команд по запросу «{}»";
    comp_matching_commands: "Matching commands:\n{}", "Подходящие команды:\n{}";
    comp_variants: "{} options — see chat", "{} вариантов — см. чат";
    dl_status_many: "file {}/{}: {} (Tab — next)", "файл {}/{}: {} (Tab — далее)";
    dl_status_one: "file: {}", "файл: {}";
    dl_no_files_room: "no files in this room", "в этой комнате нет файлов";
    dl_no_match: "no files for «{}»", "нет файлов по запросу «{}»";
    path_status_many: "path {}/{}: {} (Tab — next)", "путь {}/{}: {} (Tab — далее)";
    path_status_one: "file: {}", "файл: {}";
    sf_folder_many: "folder: {} (Tab — enter, {} options)", "папка: {} (Tab — войти, {} вариантов)";
    sf_folder: "folder: {} (Tab — enter)", "папка: {} (Tab — войти)";
    sf_home: "home directory", "домашняя директория";
    sf_permission: "permission denied: {}", "нет прав на чтение: {}";
    sf_read_failed: "failed to read {}: {}", "не удалось прочитать {}: {}";
    sf_no_files_dir: "no files in {}", "в {} нет файлов";
    sf_no_match: "no files for «{}»", "нет файлов по запросу «{}»";
    contacts_fetch_error: "failed to get contacts: {}", "ошибка получения контактов: {}";
    no_contacts_query: "No contacts for «{}»", "Нет контактов по запросу «{}»";
    matching_contacts: "Matching contacts:\n{}", "Подходящие контакты:\n{}";
    comp_contact: "contact: {}", "контакт: {}";

    // ---------- Настройки ----------
    settings_title: " Settings · /set ", " Настройки · /set ";
    settings_input_title: " Settings ", " Настройки ";
    label_text_api: "Text API", "Text API";
    label_file_api: "File API", "File API";
    label_guard_name: "Guard Header Name", "Guard Header Name";
    label_guard_value: "Guard Header Value", "Guard Header Value";
    label_proxy: "Proxy URL", "Proxy URL";
    label_notify: "Notify Level", "Notify Level";
    label_stealth_title: "Stealth Title", "Stealth Title";
    label_stealth_body: "Stealth Body", "Stealth Body";
    label_stealth_seconds: "Stealth Seconds", "Stealth Seconds";
    label_language: "Language", "Язык";
    direct_connection: "— (direct connection)", "— (прямое подключение)";
    settings_status_bar: " Settings: {} · {} ", " Настройки: {} · {} ";
    settings_mode_edit: "editing", "ввод";
    settings_mode_select: "select", "выбор";
    settings_hint_edit: " Input: Enter — apply · Esc — cancel editing ", " Ввод: Enter — применить · Esc — отменить редактирование ";
    settings_hint_select: " ↑/↓ or Tab/Shift+Tab — select · Enter — edit · ←/→ or Space — toggle · Esc — save and close ", " ↑/↓ или Tab/Shift+Tab — выбор · Enter — редактировать · ←/→ или Space — переключить · Esc — сохранить и закрыть ";
    settings_modal_hint_edit: "Enter — apply · Esc — cancel · Ctrl+V — paste", "Enter — применить · Esc — отменить · Ctrl+V — вставить";
    settings_modal_hint_select: "↑/↓, Tab/Shift+Tab — select · Enter — edit · Esc — save and close", "↑/↓, Tab/Shift+Tab — выбор · Enter — изменить · Esc — сохранить и закрыть";
    settings_updated: "settings: {} updated", "настройки: {} обновлено";
    settings_edit_cancelled: "editing cancelled", "редактирование отменено";
    settings_open: "settings opened", "настройки открыты";
    settings_saved: "settings saved to the encrypted config and applied.", "настройки сохранены в зашифрованный конфиг и применены.";
    settings_saved_proxy: "settings saved to the encrypted config and applied. Proxy: {}.", "настройки сохранены в зашифрованный конфиг и применены. Прокси: {}.";
    settings_proxy_direct: "direct connection", "прямое подключение";
    settings_applied: "settings applied", "настройки применены";
    settings_save_error: "Failed to save settings: {}", "Не удалось сохранить настройки: {}";
    settings_error: "settings error", "ошибка настроек";
    settings_first_close: "Close settings first (Esc — save and exit)", "Сначала закройте настройки (Esc — сохранить и выйти)";
    settings_first_finish_password: "Finish changing the master password first", "Сначала завершите смену мастер-пароля";
    settings_first_finish_recovery: "Close recovery first (Esc)", "Сначала закройте восстановление (Esc)";

    // ---------- /lang ----------
    lang_usage: "Usage: /lang [en|ru]", "Использование: /lang [en|ru]";
    lang_invalid: "Unknown language «{}». Available: en, ru", "Неизвестный язык «{}». Доступны: en, ru";
    lang_changed: "Interface language: {}", "Язык интерфейса: {}";
    lang_saved_error: "Failed to save language: {}", "Не удалось сохранить язык: {}";
    lang_status: "language: {}", "язык: {}";

    // ---------- /recovery ----------
    recovery_modal_title: " Recovery ", " Восстановление ";
    recovery_input_title: " Recovery · /recovery ", " Восстановление · /recovery ";
    recovery_input_password_title: " Password: current ", " Пароль: текущий ";
    recovery_status_bar: " Recovery: {}   Esc — close ", " Восстановление: {}   Esc — close ";
    recovery_stage_password: "password", "пароль";
    recovery_stage_view: "phrase view", "просмотр фразы";
    recovery_stage_confirm: "confirmation", "подтверждение";
    recovery_stage_input: "new phrase", "новая фраза";
    recovery_closed: "recovery closed", "восстановление закрыто";
    recovery_already_open: "Recovery is already open", "Восстановление уже открыто";
    recovery_prompt: "Identity recovery.\nEnter the current master password (Esc — cancel).", "Восстановление идентичности.\nВведите текущий мастер-пароль (Esc — отмена).";
    recovery_enter_password: "enter the current master password", "введите текущий мастер-пароль";
    recovery_password_prompt: "Enter the current master password to reveal the recovery phrase.", "Введите текущий мастер-пароль, чтобы открыть фразу восстановления.";
    recovery_phrase_title: "Current BIP-39 recovery phrase:", "Текущая BIP-39 фраза восстановления:";
    recovery_phrase_warning: "Never show this phrase to anyone: it fully replaces your identity.", "Никому не показывайте фразу: она полностью заменяет идентичность.";
    recovery_confirm_title: "Overwrite identity?", "Перезаписать идентичность?";
    recovery_confirm_body: "The current identity.json will be replaced with the identity restored from the new phrase.", "Текущий identity.json будет заменён личностью, восстановленной из новой фразы.";
    recovery_confirm_body2: "Old keys will stop working; this can only be undone with the old phrase.", "Старые ключи перестанут действовать; отменить это можно только старой фразой.";
    recovery_new_phrase: "New BIP-39 phrase (12/15/18/21/24 words):", "Новая BIP-39 фраза (12/15/18/21/24 слова):";
    recovery_wrong_password: "Wrong master password: {}", "Неверный мастер-пароль: {}";
    recovery_password_ok: "password confirmed · Tab/R — new phrase", "пароль подтверждён · Tab/R — новая фраза";
    recovery_password_bad_status: "wrong master password", "неверный мастер-пароль";
    recovery_confirm_request: "confirm identity overwrite", "подтвердите перезапись идентичности";
    recovery_enter_new: "enter the new mnemonic phrase", "введите новую мнемоническую фразу";
    recovery_restored: "Identity restored: {}.\nRestart the client for the new keys to take effect.", "Идентичность восстановлена: {}.\nПерезапустите клиент, чтобы новые ключи вступили в силу.";
    recovery_restored_status: "identity restored", "идентичность восстановлена";
    recovery_invalid_phrase: "invalid mnemonic phrase", "некорректная мнемоническая фраза";
    recovery_hint_password: "Enter — confirm · Esc — close", "Enter — подтвердить · Esc — закрыть";
    recovery_hint_view: "Tab or R — enter a new phrase · Esc — close", "Tab или R — ввести новую фразу · Esc — закрыть";
    recovery_hint_confirm: "Enter — continue · Esc — close", "Enter — продолжить · Esc — закрыть";
    recovery_hint_input: "Enter — restore · Esc — close", "Enter — восстановить · Esc — закрыть";

    // ---------- Справка ----------
    help_title: " Help ", " Справка ";
    help_table_key: "Command / alias", "Команда / алиас";
    help_table_desc: "Description", "Описание";
    help_footer: " Up/Down, j/k · PgUp/PgDn — scroll   {}% · Esc, q, Enter — close ", " Up/Down, j/k · PgUp/PgDn — прокрутка   {}% · Esc, q, Enter — закрыть ";
    help_status_open: "help · F1/Esc — close, Up/Down — scroll", "справка · F1/Esc — закрыть, Up/Down — прокрутка";
    help_status_closed: "help closed", "справка закрыта";

    // ---------- Смена мастер-пароля ----------
    passwd_input_current: " Password: current ", " Пароль: текущий ";
    passwd_input_new: " Password: new ", " Пароль: новый ";
    passwd_input_confirm: " Password: repeat ", " Пароль: повтор ";
    passwd_empty: "Password cannot be empty", "Пароль не может быть пустым";
    passwd_wrong: "Wrong master password: {}", "Неверный мастер-пароль: {}";
    passwd_confirmed: "Current password confirmed. Enter the new master password.", "Текущий пароль подтверждён. Введите новый мастер-пароль.";
    passwd_new_status: "new master password", "новый мастер-пароль";
    passwd_min: "Password must be at least {} characters", "Пароль должен быть не короче {} символов";
    passwd_repeat: "Repeat the new master password.", "Повторите новый мастер-пароль.";
    passwd_repeat_status: "repeat the new password", "повторите новый пароль";
    passwd_mismatch: "Passwords do not match — enter the new password again", "Пароли не совпадают — введите новый пароль заново";
    passwd_changed: "Master password changed. Profile files and the database have been re-encrypted.", "Мастер-пароль изменён. Файлы профиля и база перешифрованы.";
    passwd_changed_status: "master password changed", "мастер-пароль изменён";
    passwd_change_error: "Failed to change master password: {}", "Не удалось сменить мастер-пароль: {}";
    passwd_cancelled: "Master password change cancelled", "Смена мастер-пароля отменена";
    passwd_cancelled_status: "password change cancelled", "смена пароля отменена";
    passwd_already_started: "Master password change already started", "Смена мастер-пароля уже начата";
    passwd_start: "Master password change.\nEnter the current password (Esc — cancel).", "Смена мастер-пароля.\nВведите текущий пароль (Esc — отмена).";
    passwd_enter_current: "enter the current master password", "введите текущий мастер-пароль";

    // ---------- Команды ----------
    profile_serialize_error: "Profile serialization error: {}", "Ошибка сериализации профиля: {}";
    invite_copied: "Invite link copied to the clipboard", "Ссылка приглашения скопирована в буфер обмена";
    invite_clipboard_warning: "Warning: clipboard unavailable ({})", "Предупреждение: буфер обмена недоступен ({})";
    invite_saved: "Invite saved: {}", "Инвайт сохранён: {}";
    invite_saved_status: "invite saved to file", "инвайт сохранён в файл";
    invite_save_error: "Failed to save invite: {}", "Ошибка сохранения инвайта: {}";
    invite_link: "Invite link:\n{}", "Ссылка-приглашение:\n{}";
    invite_ready: "invite ready", "invite готов";
    invite_error: "/invite error: {}", "Ошибка /invite: {}";
    contacts_empty: "No contacts. Add one via /join <link>", "Контактов нет. Добавьте через /join <link>";
    contacts_error: "Failed to get contacts: {}", "Ошибка получения контактов: {}";
    invalid_ed25519: "invalid ed25519 in link: {}", "некорректный ed25519 в ссылке: {}";
    truncated_ed25519: "ed25519 in link is truncated: {} hex chars instead of 64", "ed25519 в ссылке обрезан: {} hex-символов вместо 64";
    not_contact_link: "this is not a lastchance://contact?... link", "это не ссылка lastchance://contact?...";
    missing_link_params: "the link is missing required parameters", "в ссылке не хватает обязательных параметров";
    join_file_error: "failed to read file {}: {}", "не удалось прочитать файл {}: {}";
    join_usage_file: "Usage: /join -f <path>", "Использование: /join -f <path>";
    join_usage: "/join <link>, /join -f <path> or /join <hash> <x25519> <nickname>", "/join <link>, /join -f <path> или /join <hash> <x25519> <nickname>";
    join_error: "/join error: {}", "Ошибка /join: {}";
    room_active: "Active room: {} ({})", "Активная комната: {} ({})";
    room_switched: "room switched", "комната переключена";
    room_none: "No active room. Add a contact via /join <link>", "Активной комнаты нет. Добавьте контакт через /join <link>";
    messages_empty: "No messages in this room", "Сообщений в этой комнате нет";
    messages_error: "Failed to load messages: {}", "Ошибка загрузки сообщений: {}";
    sendfile_usage: "Usage: /sendfile [--force] <path>", "Использование: /sendfile [--force] <path>";
    sendfile_force: "⚠ --force: sending from a system directory manually allowed", "⚠ --force: отправка из системной директории разрешена вручную";
    sendfile_sending: "sending file: {}...", "отправка файла: {}...";
    sendfile_sending_force: "sending file (--force): {}...", "отправка файла (--force): {}...";
    sendfile_sent: "file sent", "файл отправлен";
    sendfile_error: "Failed to send file: {}", "Ошибка отправки файла: {}";
    download_no_files: "This room has no files yet", "В этой комнате пока нет файлов";
    download_not_found: "File «{}» not found. Tab after /dl lists room files", "Файл «{}» не найден. Tab после /dl — список файлов комнаты";
    download_path_error: "Failed to choose a path: {}", "Не удалось выбрать путь: {}";
    download_saving: "downloading {}...", "скачивание {}...";
    download_saved: "file {} saved to {}", "файл {} сохранён в {}";
    download_error: "Failed to download {}: {}", "Ошибка скачивания {}: {}";
    nick_usage: "Usage: /nick <name>", "Использование: /nick <name>";
    nick_changed: "Nickname changed: {}", "Ник изменён: {}";
    nick_changed_status: "nickname changed", "ник изменён";
    nick_error: "Failed to change nickname: {}", "Ошибка смены ника: {}";
    rename_usage: "Usage: /rename <hash> <name>", "Использование: /rename <hash> <name>";
    renamed: "Contact renamed", "Контакт переименован";
    renamed_status: "contact renamed", "контакт переименован";
    rename_error: "Rename error: {}", "Ошибка переименования: {}";
    set_notify_usage: "Notify Level: {}\nUsage: /set notify <0|1|2|3>", "Notify Level: {}\nИспользование: /set notify <0|1|2|3>";
    set_notify_updated: "Notify Level: {}", "Notify Level: {}";
    set_notify_status: "notification mode updated", "режим уведомлений обновлён";
    set_usage: "Usage: /set, /set notify <0|1|2|3> or /set test", "Использование: /set, /set notify <0|1|2|3> или /set test";
    set_test_sending: "sending test notification...", "отправка тестового уведомления...";
    set_test_sent: "test notification sent", "тестовое уведомление отправлено";
    set_test_error: "Notification error: {}", "Ошибка уведомления: {}";
    set_test_error_join: "Notification error: {}", "Ошибка уведомления: {}";
    unknown_command: "Unknown command. Type /help for the command list.", "Неизвестная команда. Введите /help для списка команд.";

    // ---------- Контакты ----------

    contacts_modal_title: " Contacts · /contacts ", " Контакты · /contacts ";
    contacts_input_title: " Contacts ", " Контакты ";
    contacts_status_bar: " Contacts: {}/{} · ↑/↓ — select · Enter — open · Esc — close ", " Контакты: {}/{} · ↑/↓ — выбор · Enter — открыть · Esc — закрыть ";
    contacts_hint_list: " ↑/↓, j/k — select · Enter — open · / — filter · r — rename · i — info · c — copy link · d — delete · q/Esc — close ", " ↑/↓, j/k — выбор · Enter — открыть · / — фильтр · r — переименовать · i — инфо · c — копировать ссылку · d — удалить · q/Esc — закрыть ";
    contacts_hint_filter: " Filter: {} · type to search by name/hash · Esc — reset ", " Фильтр: {} · ввод — поиск по имени/хешу · Esc — сбросить ";
    contacts_hint_rename: " Enter — save · Esc — cancel ", " Enter — сохранить · Esc — отменить ";
    contacts_hint_info: " Esc or i — back to list ", " Esc или i — назад к списку ";
    contacts_hint_confirm: " y — delete · n/Esc — cancel ", " y — удалить · n/Esc — отмена ";
    contacts_no_matches: "No contacts match «{}»", "Нет контактов по запросу «{}»";
    contacts_filter_prefix: " Filter: ", " Фильтр: ";
    contacts_messages: "{} messages", "сообщений: {}";
    contacts_rename_prompt: " Name: ", " Имя: ";
    contacts_renamed: "Contact renamed: {}", "Контакт переименован: {}";
    contacts_rename_error: "Failed to rename contact: {}", "Не удалось переименовать контакт: {}";
    contacts_rename_empty: "Name cannot be empty", "Имя не может быть пустым";
    contacts_copy_error: "Clipboard unavailable: {}", "Буфер обмена недоступен: {}";
    contacts_copied: "Contact link copied to clipboard", "Ссылка на контакт скопирована в буфер";
    contacts_info_title: " Contact info ", " Информация о контакте ";
    contacts_info_name: "Name: {}", "Имя: {}";
    contacts_info_hash: "Identity hash: {}", "Identity hash: {}";
    contacts_info_x25519: "X25519 public key: {}", "Публичный ключ X25519: {}";
    contacts_info_ed25519: "Ed25519 public key: {}", "Публичный ключ Ed25519: {}";
    contacts_info_ed25519_missing: "not stored for this contact (re-import the invite link)", "не сохранён (импортируйте ссылку-приглашение заново)";
    contacts_info_messages: "Messages in database: {}", "Сообщений в базе: {}";
    contacts_info_none: "—", "—";
    contacts_delete_confirm: "Delete contact '{}' and chat history? [y/N]", "Удалить контакт '{}' и историю чата? [y/N]";
    contacts_deleted: "Contact deleted: {}", "Контакт удалён: {}";
    contacts_delete_error: "Failed to delete contact: {}", "Не удалось удалить контакт: {}";
    contacts_deleted_status: "contact deleted", "контакт удалён";
    contacts_closed: "contacts closed", "контакты закрыты";

    // ---------- События приложения ----------
    deep_link_added: "Contact added from deep link: {} ({})", "Контакт из deep link добавлен: {} ({})";
    contact_added: "contact added", "контакт добавлен";
    deep_link_error: "Failed to add contact from deep link: {}", "Не удалось добавить контакт из deep link: {}";
    contact_import_error: "Contact import error: {}", "Ошибка импорта контакта: {}";
    upload_started: "Uploading file: {}", "Загрузка файла: {}";
    upload_started_status: "uploading file...", "загрузка файла...";
    upload_progress: "upload {}% — {}", "загрузка {}% — {}";
    upload_done: "File [#{}] {} sent, hash={}{}{}", "Файл [#{}] {} отправлен, hash={}{}{}";
    upload_size: ", {} B", ", {} B";
    upload_download_hint: "; download: /dl {}", "; скачать: /dl {}";
    upload_done_status: "file #{} sent", "файл #{} отправлен";
    upload_error: "File upload error: {}", "Ошибка загрузки файла: {}";
    download_started_status: "downloading file...", "скачивание файла...";
    download_completed: "File saved: {}", "Файл сохранён: {}";
    download_completed_status: "file saved", "файл сохранён";
    download_failed: "File download error: {}", "Ошибка скачивания файла: {}";
    new_message_status: "new message from {}", "новое сообщение от {}";
    new_file_status: "file #{}: {} — /dl {}", "файл #{}: {} — /dl {}";
    unread_message: "new message from {} in «{}» (+{}){}, switch: Alt+Up/Alt+Down", "новое сообщение от {} в «{}» (+{}){}, переключение: Alt+Up/Alt+Down";
    unread_file_note: " (file #{}: {})", " (файл #{}: {})";
    contact_added_room: "Contact added, active room: {}", "Контакт добавлен, активная комната: {}";

    // ---------- Системные уведомления ----------
    notify_new_message: "New message from {}", "Новое сообщение от {}";
    notify_new_message_default: "New message", "Новое сообщение";
    notify_file: "File: {}", "Файл: {}";
    notify_test_body: "Test message: notifications are configured.", "Тестовое сообщение: уведомления настроены.";
    notify_disabled: "notifications are disabled (Notify Level: 0)", "уведомления отключены (Notify Level: 0)";
    upload_encrypting: "Encrypting...", "Шифрование...";
    upload_sending: "Sending to server...", "Отправка на сервер...";
    upload_finished: "Completed", "Завершено";
    file_notification: "📎 File: {}\nSize: {}\nHash: {}", "📎 Файл: {}\nРазмер: {}\nХеш: {}";

    // ---------- Welcome ----------
    welcome_status: "choose interface language · ←/→ or 1/2 · Enter — confirm", "выберите язык интерфейса · ←/→ или 1/2 · Enter — подтвердить";
    welcome_saved: "interface language: {}", "язык интерфейса: {}";
    welcome_save_error: "Failed to save language: {}", "Не удалось сохранить язык: {}";
    input_title: " Input ", " Ввод ";
}

static WELCOME_EN: WelcomeText = WelcomeText {
    title: "Welcome to LastChance",
    subtitle: "Private messenger with a terminal interface.",
    settings: "• Servers and proxy: /set or Ctrl+S",
    help: "• Commands: /help or F1",
    language: "• Language: /lang",
    footer: "←/→ or 1/2 — choose · Enter — confirm",
};

static WELCOME_RU: WelcomeText = WelcomeText {
    title: "Добро пожаловать в LastChance",
    subtitle: "Приватный мессенджер с терминальным интерфейсом.",
    settings: "• Серверы и прокси: /set или Ctrl+S",
    help: "• Команды: /help или F1",
    language: "• Язык: /lang",
    footer: "←/→ или 1/2 — выбор · Enter — подтвердить",
};

const COMMAND_LANG: &str = "/lang [en|ru]";

const EN_HELP_SECTIONS: &[HelpSection] = &[
    HelpSection {
        title: "Navigation and chats",
        rows: &[
            HelpRow { keys: "/help, /h, /?", desc: "Open this help" },
            HelpRow { keys: "/contacts, /cnt, /ls, /c", desc: "Contact manager: open a chat, rename, info, copy link, delete" },
            HelpRow { keys: "/join, /jn <link | hash x25519 nick>", desc: "Add a contact and open a chat" },
            HelpRow { keys: "/join, /jn -f <path>", desc: "Add a contact from an invite file" },
            HelpRow { keys: "/room, /r [hash | nick]", desc: "Show or switch the active room" },
            HelpRow { keys: "/sidebar, /sb", desc: "Hide or show the chat panel" },
            HelpRow { keys: "Alt+Up/Down, Ctrl+P/N", desc: "Switch between chats" },
            HelpRow { keys: "Tab", desc: "Complete commands and contacts" },
        ],
    },
    HelpSection {
        title: "Messages and files",
        rows: &[
            HelpRow { keys: "/messages [limit]", desc: "Recent messages in the active room" },
            HelpRow { keys: "/ttl [duration|off]", desc: "One-way RAM-only TTL for new messages (30s, 5m, 2h); without an argument — status" },
            HelpRow { keys: "/ttl-syn [duration|off]", desc: "Two-way RAM TTL: the peer receives the same timer via an encrypted SetTtl" },
            HelpRow { keys: "/sendfile, /sf [--force] <path>", desc: "Send a file; path is from the current directory, ~/ or absolute; system folders require --force" },
            HelpRow { keys: "/download, /dl [id | name | hash] [path]", desc: "Download a room file (the latest by default) to ./downloads" },
            HelpRow { keys: "Tab after /dl", desc: "Cycle through files in the active room" },
            HelpRow { keys: "Tab after /sf", desc: "Complete paths from the current directory" },
            HelpRow { keys: "Text without a leading /", desc: "Send a message to the active room" },
        ],
    },
    HelpSection {
        title: "Profile and settings",
        rows: &[
            HelpRow { keys: "/profile, /p", desc: "Profile: nickname, hash and keys" },
            HelpRow { keys: "/recovery", desc: "Restore identity from a BIP-39 phrase (with overwrite confirmation)" },
            HelpRow { keys: "/invite, /in [-f [dir | file]]", desc: "Copy an invite link to the clipboard; with -f save it to a file" },
            HelpRow { keys: "/export", desc: "Contact as JSON" },
            HelpRow { keys: "/nick <name>", desc: "Change your nickname" },
            HelpRow { keys: "/rename <hash> <name>", desc: "Rename a contact" },
            HelpRow { keys: "/set, /settings", desc: "Interactive settings: API, Guard Header, Proxy, Notify Level, Stealth, Language" },
            HelpRow { keys: "/set notify <0|1|2|3>", desc: "Notification mode: off / stealth / sender / full" },
            HelpRow { keys: "/set test", desc: "Show a test system notification" },
            HelpRow { keys: COMMAND_LANG, desc: "Switch interface language (en/ru) or toggle it without an argument" },
            HelpRow { keys: "/passwd", desc: "Change the master password (files and database are re-encrypted)" },
            HelpRow { keys: "/quit, /q, /exit", desc: "Quit the client" },
        ],
    },
    HelpSection {
        title: "Input editing",
        rows: &[
            HelpRow { keys: "Ctrl+W, Ctrl+Backspace, Alt+Backspace", desc: "Delete the word to the left" },
            HelpRow { keys: "Ctrl+Delete, Alt+D", desc: "Delete the word to the right" },
            HelpRow { keys: "Ctrl+U / Ctrl+K", desc: "Delete to the start / end of the line" },
            HelpRow { keys: "Ctrl+Left, Alt+B / Ctrl+Right, Alt+F", desc: "Move by words" },
            HelpRow { keys: "Home, Ctrl+A / End, Ctrl+E", desc: "Move to the start / end of the line" },
        ],
    },
    HelpSection {
        title: "TUI hotkeys",
        rows: &[
            HelpRow { keys: "F1", desc: "Open or close help" },
            HelpRow { keys: "Esc, q, Enter", desc: "Close help" },
            HelpRow { keys: "Up/Down, j/k", desc: "Scroll help line by line" },
            HelpRow { keys: "PgUp/PgDn", desc: "Scroll help by pages" },
            HelpRow { keys: "Up/Down", desc: "Input history (last 50 lines)" },
            HelpRow { keys: "PgUp/PgDn, mouse wheel", desc: "Scroll chat history" },
            HelpRow { keys: "Ctrl+V", desc: "Paste from the system clipboard" },
            HelpRow { keys: "Ctrl+S", desc: "Open settings (/set)" },
            HelpRow { keys: "Ctrl+C", desc: "Copy input and clear it; on an empty line — quit" },
        ],
    },
];

const RU_HELP_SECTIONS: &[HelpSection] = &[
    HelpSection {
        title: "Навигация и чаты",
        rows: &[
            HelpRow { keys: "/help, /h, /?", desc: "Открыть эту справку" },
            HelpRow { keys: "/contacts, /cnt, /ls, /c", desc: "Менеджер контактов: открыть чат, переименовать, инфо, копировать ссылку, удалить" },
            HelpRow { keys: "/join, /jn <link | hash x25519 nick>", desc: "Добавить контакт и открыть чат" },
            HelpRow { keys: "/join, /jn -f <path>", desc: "Добавить контакт из файла-инвайта" },
            HelpRow { keys: "/room, /r [hash | nick]", desc: "Показать или сменить активную комнату" },
            HelpRow { keys: "/sidebar, /sb", desc: "Скрыть или показать панель чатов" },
            HelpRow { keys: "Alt+Up/Down, Ctrl+P/N", desc: "Переключение между чатами" },
            HelpRow { keys: "Tab", desc: "Автодополнение команд и контактов" },
        ],
    },
    HelpSection {
        title: "Сообщения и файлы",
        rows: &[
            HelpRow { keys: "/messages [limit]", desc: "Последние сообщения активной комнаты" },
            HelpRow { keys: "/ttl [duration|off]", desc: "Односторонний RAM-TTL для новых сообщений (30s, 5m, 2h); без аргумента — статус" },
            HelpRow { keys: "/ttl-syn [duration|off]", desc: "Двусторонний RAM-TTL: собеседник получает тот же таймер через зашифрованный SetTtl" },
            HelpRow { keys: "/sendfile, /sf [--force] <path>", desc: "Отправить файл; путь от текущей директории, ~/ и абсолютный; системные папки — только с --force" },
            HelpRow { keys: "/download, /dl [id | name | hash] [path]", desc: "Скачать файл комнаты (по умолчанию последний) в ./downloads" },
            HelpRow { keys: "Tab после /dl", desc: "Перебор файлов активной комнаты" },
            HelpRow { keys: "Tab после /sf", desc: "Автодополнение путей от текущей директории" },
            HelpRow { keys: "Текст без ведущего /", desc: "Отправить сообщение в активную комнату" },
        ],
    },
    HelpSection {
        title: "Профиль и настройки",
        rows: &[
            HelpRow { keys: "/profile, /p", desc: "Профиль: ник, hash и ключи" },
            HelpRow { keys: "/recovery", desc: "Восстановить идентичность из BIP-39 фразы (с подтверждением перезаписи)" },
            HelpRow { keys: "/invite, /in [-f [dir | file]]", desc: "Скопировать ссылку-приглашение в буфер; с -f сохранить в файл" },
            HelpRow { keys: "/export", desc: "Контакт в формате JSON" },
            HelpRow { keys: "/nick <name>", desc: "Сменить свой ник" },
            HelpRow { keys: "/rename <hash> <name>", desc: "Переименовать контакт" },
            HelpRow { keys: "/set, /settings", desc: "Интерактивное меню настроек: API, Guard Header, Proxy, Notify Level, Stealth, язык" },
            HelpRow { keys: "/set notify <0|1|2|3>", desc: "Режим уведомлений: выкл. / stealth / отправитель / полный" },
            HelpRow { keys: "/set test", desc: "Показать тестовое системное уведомление" },
            HelpRow { keys: COMMAND_LANG, desc: "Переключить язык интерфейса (en/ru) или без аргумента — сменить текущий" },
            HelpRow { keys: "/passwd", desc: "Сменить мастер-пароль (файлы и база перешифровываются)" },
            HelpRow { keys: "/quit, /q, /exit", desc: "Выйти из клиента" },
        ],
    },
    HelpSection {
        title: "Редактирование ввода",
        rows: &[
            HelpRow { keys: "Ctrl+W, Ctrl+Backspace, Alt+Backspace", desc: "Удалить слово слева от курсора" },
            HelpRow { keys: "Ctrl+Delete, Alt+D", desc: "Удалить слово справа от курсора" },
            HelpRow { keys: "Ctrl+U / Ctrl+K", desc: "Удалить до начала / до конца строки" },
            HelpRow { keys: "Ctrl+Left, Alt+B / Ctrl+Right, Alt+F", desc: "Перемещение по словам" },
            HelpRow { keys: "Home, Ctrl+A / End, Ctrl+E", desc: "В начало / в конец строки" },
        ],
    },
    HelpSection {
        title: "Горячие клавиши TUI",
        rows: &[
            HelpRow { keys: "F1", desc: "Открыть или закрыть справку" },
            HelpRow { keys: "Esc, q, Enter", desc: "Закрыть справку" },
            HelpRow { keys: "Up/Down, j/k", desc: "Прокрутка справки построчно" },
            HelpRow { keys: "PgUp/PgDn", desc: "Прокрутка справки страницами" },
            HelpRow { keys: "Up/Down", desc: "История ввода (последние 50 строк)" },
            HelpRow { keys: "PgUp/PgDn, колесо мыши", desc: "Прокрутка истории чата" },
            HelpRow { keys: "Ctrl+V", desc: "Вставить из системного буфера обмена" },
            HelpRow { keys: "Ctrl+S", desc: "Открыть настройки (/set)" },
            HelpRow { keys: "Ctrl+C", desc: "Скопировать ввод и очистить; на пустой строке — выход" },
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Config;

    #[test]
    fn english_is_the_default_language() {
        assert_eq!(Lang::default(), Lang::En);
        assert_eq!(Lang::default().code(), "en");
        assert_eq!(Lang::default().native_name(), "English");
        assert_eq!(Lang::default().texts().ready, "ready");
    }

    #[test]
    fn parses_language_codes() {
        assert_eq!(Lang::parse("en"), Some(Lang::En));
        assert_eq!(Lang::parse("EN"), Some(Lang::En));
        assert_eq!(Lang::parse(" ru "), Some(Lang::Ru));
        assert_eq!(Lang::parse("русский"), Some(Lang::Ru));
        assert_eq!(Lang::parse("de"), None);
    }

    #[test]
    fn old_config_without_lang_defaults_to_english() {
        let json = r#"{
            "server_url": "https://msg.example.com",
            "file_server_url": "https://files.example.com",
            "mask_header_name": "X-DNS-Connect",
            "mask_header_value": "We_Are_Not_Legion"
        }"#;

        let config: Config = serde_json::from_str(json).expect("old config must deserialize");
        assert_eq!(config.lang, Lang::En);
        assert_eq!(config.notify_level, crate::network::config::DEFAULT_NOTIFY_LEVEL);
    }

    #[test]
    fn language_round_trips_through_config_json() {
        let config = Config {
            lang: Lang::Ru,
            ..Config::default()
        };
        let json = serde_json::to_string(&config).expect("config must serialize");
        let restored: Config = serde_json::from_str(&json).expect("config must deserialize");
        assert_eq!(restored.lang, Lang::Ru);
    }

    #[test]
    fn help_sections_follow_the_language() {
        assert_eq!(Lang::En.help_sections()[0].title, "Navigation and chats");
        assert_eq!(Lang::Ru.help_sections()[0].title, "Навигация и чаты");
        assert!(Lang::En
            .help_sections()
            .iter()
            .flat_map(|section| section.rows)
            .any(|row| row.keys.contains("/lang")));
    }
}
