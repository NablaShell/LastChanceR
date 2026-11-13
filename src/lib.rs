// Библиотека сетевого ядра и логики мессенджера.
// Здесь не должно быть зависимостей от Tauri или другого GUI.

pub mod app;
pub mod crypto;
pub mod identity;
pub mod network;
pub mod storage;

pub use app::{App, AppEvent};
pub use network::Config;
pub use storage::{get_base_dir, get_base_dir_with_override};
