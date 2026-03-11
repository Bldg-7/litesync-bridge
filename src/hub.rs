use crate::config::Config;

/// Central dispatcher that routes change events between peers in the same group.
pub struct Hub {
    config: Config,
}

impl Hub {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        tracing::info!(
            peer_count = self.config.peers.len(),
            "starting hub"
        );

        // TODO: Phase 3 — spawn peer tasks, wire up channels
        tokio::signal::ctrl_c().await?;
        tracing::info!("shutting down");
        Ok(())
    }
}
