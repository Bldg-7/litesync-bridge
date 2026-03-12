use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::bridge::{ChangeEvent, PeerMessage};
use crate::config::{Config, PeerConfig};
use crate::peer::couchdb::CouchDBPeer;
use crate::peer::storage::StoragePeer;
use crate::reconcile::{self, InitializedPeer};
use crate::state::StatCache;

/// Timeout for sending an event to a peer's inbound channel.
/// If a peer is slow, the hub waits up to this duration before dropping.
const SEND_TIMEOUT: Duration = Duration::from_secs(30);

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
        // ── Phase 1: Initialize all peers ────────────────────────────────
        let mut initialized: Vec<InitializedPeer> = Vec::new();

        for peer_config in self.config.peers {
            match peer_config {
                PeerConfig::CouchDB(config) => {
                    let (peer, since) = CouchDBPeer::init(config, &data_dir).await?;
                    initialized.push(InitializedPeer::CouchDB { peer, since });
                }
                PeerConfig::Storage(config) => {
                    let peer = StoragePeer::new(config.clone());
                    initialized.push(InitializedPeer::Storage {
                        peer,
                        config,
                    });
                }
            }
        }

        tracing::info!(peers = initialized.len(), "all peers initialized");

        // ── Phase 2: Reconcile offline changes ───────────────────────────
        reconcile::reconcile_all(&mut initialized[..], &data_dir, &cancel).await?;

        if cancel.is_cancelled() {
            return Ok(());
        }

        // ── Phase 2.5: Inject stat caches into StoragePeers ─────────────
        for init_peer in &initialized {
            if let InitializedPeer::Storage { peer, config } = init_peer {
                let stat_cache = StatCache::load(&data_dir, &config.name);
                peer.set_stat_cache(stat_cache);
            }
        }

        // ── Phase 3: Spawn real-time loops ───────────────────────────────
        let (hub_tx, mut hub_rx) = mpsc::channel::<PeerMessage>(256);

        let mut peer_txs: HashMap<String, mpsc::Sender<ChangeEvent>> = HashMap::new();
        let mut peer_groups: HashMap<String, String> = HashMap::new();
        let mut handles: Vec<JoinHandle<()>> = Vec::new();

        for init_peer in initialized {
            let name = init_peer.name().to_string();
            let group = init_peer.group().to_string();
            let (tx, rx) = mpsc::channel::<ChangeEvent>(256);

            peer_txs.insert(name.clone(), tx);
            peer_groups.insert(name, group);

            match init_peer {
                InitializedPeer::CouchDB { peer, since } => {
                    handles.extend(peer.spawn(since, hub_tx.clone(), rx, cancel.clone()));
                }
                InitializedPeer::Storage { peer, .. } => {
                    handles.extend(peer.spawn(hub_tx.clone(), rx, cancel.clone()));
                }
            }
        }

        // Drop our copy so hub_rx closes when all peer senders are dropped
        drop(hub_tx);

        tracing::info!(peers = peer_txs.len(), "hub routing started");

        // ── Phase 4: Routing loop ────────────────────────────────────────
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
                    let send_fut = tx.send(msg.event.clone());
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        result = tokio::time::timeout(SEND_TIMEOUT, send_fut) => {
                            match result {
                                Ok(Ok(())) => {}
                                Ok(Err(_)) => {
                                    tracing::warn!(target_peer = %name, "peer channel closed");
                                }
                                Err(_) => {
                                    tracing::error!(
                                        target_peer = %name,
                                        "send timed out after {SEND_TIMEOUT:?}, dropping event"
                                    );
                                }
                            }
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
