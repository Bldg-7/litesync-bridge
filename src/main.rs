mod bridge;
mod config;
mod hub;
mod peer;

use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[command(name = "litesync-bridge", version, about)]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "dat/config.json")]
    config: PathBuf,
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
    let hub = hub::Hub::new(config);
    hub.run().await
}
