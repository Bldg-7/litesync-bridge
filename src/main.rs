mod bridge;
mod config;
mod hub;
mod peer;
mod reconcile;
mod state;

use std::path::Path;
use std::path::PathBuf;

use clap::Parser;
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "litesync-bridge", version, about)]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "dat/config.json")]
    config: PathBuf,

    /// Reset all state (since sequences) and restart from scratch
    #[arg(long)]
    reset: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,litesync_bridge=debug,litesync_commonlib=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        "litesync-bridge starting"
    );

    let config = config::Config::load(&cli.config)?;
    let data_dir = cli
        .config
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .to_path_buf();

    if cli.reset {
        tracing::info!("resetting all peer state");
        for peer in &config.peers {
            state::SinceTracker::reset(&data_dir, peer.name())?;
        }
    }

    let cancel = CancellationToken::new();
    let cancel_for_signal = cancel.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("received ctrl-c, shutting down...");
        cancel_for_signal.cancel();
    });

    let hub = hub::Hub::new(config);
    hub.run(data_dir, cancel).await
}
