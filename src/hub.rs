use std::collections::HashMap;
use std::path::PathBuf;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::bridge::{ChangeEvent, PeerMessage};
use crate::config::{Config, PeerConfig};
use crate::peer::couchdb::CouchDBPeer;
use crate::peer::storage::StoragePeer;

/// Central dispatcher that routes change events between peers in the same group.
pub struct Hub {
    config: Config,
}

impl Hub {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(
        self,
        data_dir: PathBuf,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let (hub_tx, mut hub_rx) = mpsc::channel::<PeerMessage>(256);

        let mut peer_txs: HashMap<String, mpsc::Sender<ChangeEvent>> = HashMap::new();
        let mut peer_groups: HashMap<String, String> = HashMap::new();
        let mut handles: Vec<JoinHandle<()>> = Vec::new();

        for peer_config in self.config.peers {
            let name = peer_config.name().to_string();
            let group = peer_config.group().to_string();
            let (tx, rx) = mpsc::channel::<ChangeEvent>(256);

            peer_txs.insert(name.clone(), tx);
            peer_groups.insert(name.clone(), group);

            match peer_config {
                PeerConfig::CouchDB(config) => {
                    let (peer, since) = CouchDBPeer::init(config, &data_dir).await?;
                    handles.extend(peer.spawn(since, hub_tx.clone(), rx, cancel.clone()));
                }
                PeerConfig::Storage(config) => {
                    let peer = StoragePeer::new(config);
                    handles.extend(peer.spawn(hub_tx.clone(), rx, cancel.clone()));
                }
            }
        }

        // Drop our copy so hub_rx closes when all peer senders are dropped
        drop(hub_tx);

        tracing::info!(peers = peer_txs.len(), "hub routing started");

        // Routing loop
        loop {
            let msg = tokio::select! {
                _ = cancel.cancelled() => break,
                msg = hub_rx.recv() => match msg {
                    Some(m) => m,
                    None => break, // all peer senders dropped
                },
            };

            tracing::trace!(
                source = %msg.source_name,
                group = %msg.group,
                path = %msg.event.path().display(),
                "routing event"
            );

            for (name, tx) in &peer_txs {
                if name.as_str() != &*msg.source_name
                    && peer_groups.get(name).map(String::as_str) == Some(&*msg.group)
                {
                    match tx.try_send(msg.event.clone()) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                target_peer = %name,
                                "inbound channel full, dropping event"
                            );
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            tracing::warn!(target_peer = %name, "peer channel closed");
                        }
                    }
                }
            }
        }

        // Drop senders to signal inbound loops to stop
        drop(peer_txs);

        // Wait for all peer tasks to finish
        for handle in handles {
            let _ = handle.await;
        }

        tracing::info!("hub shut down");
        Ok(())
    }
}
