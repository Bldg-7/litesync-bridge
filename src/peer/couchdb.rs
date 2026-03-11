use crate::config::CouchDBPeerConfig;

/// Peer that watches a CouchDB database for changes and dispatches them.
pub struct CouchDBPeer {
    config: CouchDBPeerConfig,
}

impl CouchDBPeer {
    pub fn new(config: CouchDBPeerConfig) -> Self {
        Self { config }
    }
}
