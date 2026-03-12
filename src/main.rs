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

    /// Output logs in JSON format (for systemd journal / structured logging)
    #[arg(long)]
    log_json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,litesync_bridge=debug,litesync_commonlib=debug".into());

    if cli.log_json {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .init();
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %cli.config.display(),
        "litesync-bridge starting"
    );

    let config = config::Config::load(&cli.config)?;
    config.validate()?;
    config.log_summary();

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
        let ctrl_c = tokio::signal::ctrl_c();
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate(),
        )
        .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("received SIGINT, shutting down..."),
            _ = sigterm.recv() => tracing::info!("received SIGTERM, shutting down..."),
        }
        cancel_for_signal.cancel();
    });

    let hub = hub::Hub::new(config);
    hub.run(data_dir, cancel).await
}
