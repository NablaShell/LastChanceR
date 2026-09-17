// src/main.rs
mod app;
mod crypto;
mod file_dialog;
mod identity;
mod network;
mod storage;
mod ui;

use std::sync::Arc;
use tokio::sync::mpsc;

slint::include_modules!();

use crate::app::{App, AppEvent};
use crate::network::Config;
use crate::storage::get_base_dir;
use crate::ui::controller::UiController;

fn main() -> anyhow::Result<()> {
    env_logger::init();

    // ---- Backend init ----
    let base_dir = get_base_dir()?;
    let config = Config::load(&base_dir)?;
    let (event_tx, event_rx) = mpsc::unbounded_channel::<AppEvent>();

    // ---- Tokio runtime ----
    let rt = tokio::runtime::Runtime::new()?;
    let handle = rt.handle().clone();

    let app = {
        let _guard = rt.enter();
        Arc::new(App::new(config, base_dir, event_tx)?)
    };

    // Запускаем listener
    {
        let app = app.clone();
        rt.spawn(async move {
            if let Err(e) = app.start().await {
                log::error!("App::start: {}", e);
            }
        });
    }
	for arg in std::env::args().skip(1) {
	    if arg.starts_with("lastchance://") {
	        app.handle_scheme_url(&arg);
	    }
	}
    // ---- Slint UI ----
    let window = AppWindow::new()?;
    let controller = UiController::new(app.clone(), window.clone_strong(), handle.clone());
    controller.wire()?;
    controller.start_event_listener(event_rx);

    // ---- Run UI ----
    window.run()?;

    // ---- Shutdown ----
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    Ok(())
}
