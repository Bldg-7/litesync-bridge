use crate::config::StoragePeerConfig;

/// Peer that watches a local directory for file changes and dispatches them.
pub struct StoragePeer {
    config: StoragePeerConfig,
}

impl StoragePeer {
    pub fn new(config: StoragePeerConfig) -> Self {
        Self { config }
    }
}
