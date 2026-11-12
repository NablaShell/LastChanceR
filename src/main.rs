// CLI-точка входа. Вся логика мессенджера находится в библиотеке (src/lib.rs).
use anyhow::Result;
use tokio::sync::mpsc;

use lastchance::{get_base_dir, App, AppEvent, Config};

#[tokio::main]
async fn main() -> Result<()> {
    let base_dir = get_base_dir()?;
    let config = Config::load(&base_dir)?;
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<AppEvent>();

    let app = App::new(config, base_dir, event_tx)?;

    // Обрабатываем deep link из argv (Linux/Windows).
    for arg in std::env::args().skip(1) {
        if arg.starts_with("lastchance://") {
            app.handle_scheme_url(&arg);
        }
    }

    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            println!("[event] {:?}", event);
        }
    });

    app.start().await?;
    println!("LastChance core is running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await?;
    Ok(())
}
