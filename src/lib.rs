// Библиотека сетевого ядра и логики мессенджера.
// Здесь не должно быть зависимостей от Tauri или другого GUI.

pub mod app;
pub mod cli;
pub mod crypto;
pub mod i18n;
pub mod identity;
pub mod network;
pub mod storage;
pub mod types;
pub mod vault;

pub use app::{App, AppEvent, TtlSyncOutcome};
pub use i18n::Lang;
pub use network::Config;
pub use storage::{get_base_dir, get_base_dir_with_override};
pub use vault::Vault;
