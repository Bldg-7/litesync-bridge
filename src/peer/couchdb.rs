use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use litesync_commonlib::chunk::{self, E2EEContext};
use litesync_commonlib::couchdb::CouchDBClient;
use litesync_commonlib::crypto;
use litesync_commonlib::doc::{RawNoteEntry, TYPE_NEWNOTE, TYPE_PLAIN};
use litesync_commonlib::path;

use crate::bridge::{ChangeEvent, PeerMessage};
use crate::config::CouchDBPeerConfig;
use crate::state::{RevTracker, SinceTracker};

const LONGPOLL_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_PIECE_SIZE: usize = 250_000;

pub struct CouchDBPeer {
    name: String,
    group: String,
    base_dir: String,
    obfuscate_passphrase: Option<String>,
    client: CouchDBClient,
    e2ee: Option<E2EEContext>,
    rev_tracker: Arc<RevTracker>,
}

impl CouchDBPeer {
    /// Initialize the peer: connect to CouchDB, set up E2EE, load since sequence.
    pub async fn init(
        config: CouchDBPeerConfig,
        data_dir: &Path,
    ) -> anyhow::Result<(Self, SinceTracker)> {
        let client = CouchDBClient::new(
            &config.url,
            &config.database,
            &config.username,
            &config.password,
        )?;

        client.ping().await?;
        tracing::info!(peer = %config.name, db = %config.database, "CouchDB connected");

        let e2ee = if let Some(ref passphrase) = config.passphrase {
            let salt = client.get_e2ee_salt().await?;
            tracing::info!(peer = %config.name, "E2EE enabled");
            Some(E2EEContext::new(passphrase, &salt))
        } else {
            None
        };

        let since = SinceTracker::load(data_dir, &config.name);
        tracing::info!(peer = %config.name, since = %since.get(), "loaded since sequence");

        let peer = Self {
            name: config.name,
            group: config.group,
            base_dir: config.base_dir,
            obfuscate_passphrase: config.obfuscate_passphrase,
            client,
            e2ee,
            rev_tracker: Arc::new(RevTracker::new()),
        };

        Ok((peer, since))
    }

    /// Spawn outbound (changes feed) and inbound (write) tasks.
    pub fn spawn(
        self,
        mut since: SinceTracker,
        hub_tx: mpsc::Sender<PeerMessage>,
        inbound_rx: mpsc::Receiver<ChangeEvent>,
        cancel: CancellationToken,
    ) -> Vec<JoinHandle<()>> {
        let peer = Arc::new(self);

        let p = peer.clone();
        let c = cancel.clone();
        let changes_handle = tokio::spawn(async move {
            if let Err(e) = p.run_changes(&mut since, hub_tx, c).await {
                tracing::error!(peer = %p.name, error = %e, "changes loop failed");
            }
        });

        let p = peer;
        let c = cancel;
        let inbound_handle = tokio::spawn(async move {
            if let Err(e) = p.run_inbound(inbound_rx, c).await {
                tracing::error!(peer = %p.name, error = %e, "inbound loop failed");
            }
        });

        vec![changes_handle, inbound_handle]
    }

    // =========================================================================
    // Outbound: CouchDB changes feed → Hub
    // =========================================================================

    async fn run_changes(
        self: &Arc<Self>,
        since: &mut SinceTracker,
        hub_tx: mpsc::Sender<PeerMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        let mut backoff = Duration::from_secs(1);

        loop {
            let result = tokio::select! {
                _ = cancel.cancelled() => break,
                r = self.client.get_changes_longpoll(since.get(), LONGPOLL_TIMEOUT_MS) => r,
            };

            match result {
                Ok(changes) => {
                    backoff = Duration::from_secs(1);
                    let count = changes.results.len();

                    for change in &changes.results {
                        // Skip our own writes (rev-based dedup)
                        if let Some(rev_entry) = change.changes.first() {
                            if self.rev_tracker.check_and_remove(&rev_entry.rev) {
                                tracing::trace!(
                                    peer = %self.name, id = %change.id,
                                    "skipping own write"
                                );
                                continue;
                            }
                        }

                        // Parse doc from the changes feed
                        let Some(ref doc_value) = change.doc else { continue };
                        let raw: RawNoteEntry = match serde_json::from_value(doc_value.clone()) {
                            Ok(r) => r,
                            Err(_) => continue, // not a note document
                        };

                        // Only process note documents
                        if raw.type_ != TYPE_PLAIN && raw.type_ != TYPE_NEWNOTE {
                            continue;
                        }

                        match self.process_change(&raw, change.deleted).await {
                            Ok(Some(event)) => {
                                let msg = PeerMessage {
                                    source_name: self.name.clone(),
                                    group: self.group.clone(),
                                    event,
                                };
                                if hub_tx.send(msg).await.is_err() {
                                    return Ok(()); // Hub dropped
                                }
                            }
                            Ok(None) => {} // filtered out
                            Err(e) => {
                                tracing::warn!(
                                    peer = %self.name, doc_id = %change.id,
                                    "failed to process change: {e}"
                                );
                            }
                        }
                    }

                    since.update(&changes.last_seq)?;
                    if count > 0 {
                        tracing::debug!(
                            peer = %self.name, count,
                            since = %since.get(), "processed changes"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %self.name,
                        backoff_secs = backoff.as_secs(),
                        "changes feed error: {e}"
                    );
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                }
            }
        }

        tracing::info!(peer = %self.name, "changes loop stopped");
        Ok(())
    }

    async fn process_change(
        &self,
        raw: &RawNoteEntry,
        deleted: Option<bool>,
    ) -> anyhow::Result<Option<ChangeEvent>> {
        let note = chunk::resolve_note(raw, self.e2ee.as_ref(), deleted)?;

        // Filter by base_dir
        if !self.base_dir.is_empty() && !note.path.starts_with(&self.base_dir) {
            return Ok(None);
        }

        let rel_path = if self.base_dir.is_empty() {
            note.path.clone()
        } else {
            note.path
                .strip_prefix(&self.base_dir)
                .unwrap_or(&note.path)
                .to_string()
        };

        if path::should_be_ignored(&rel_path) {
            return Ok(None);
        }

        if note.deleted {
            return Ok(Some(ChangeEvent::Deleted {
                path: PathBuf::from(&rel_path),
            }));
        }

        let data = chunk::reassemble(&self.client, &note, self.e2ee.as_ref()).await?;

        Ok(Some(ChangeEvent::Modified {
            path: PathBuf::from(&rel_path),
            data,
            mtime: note.mtime,
            ctime: note.ctime,
            is_binary: note.is_binary,
        }))
    }

    // =========================================================================
    // Inbound: Hub → CouchDB writes
    // =========================================================================

    async fn run_inbound(
        self: &Arc<Self>,
        mut rx: mpsc::Receiver<ChangeEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => break,
                event = rx.recv() => match event {
                    Some(e) => e,
                    None => break,
                },
            };

            if let Err(e) = self.handle_write(event).await {
                tracing::warn!(peer = %self.name, "write to CouchDB failed: {e}");
            }
        }

        tracing::info!(peer = %self.name, "inbound loop stopped");
        Ok(())
    }

    async fn handle_write(&self, event: ChangeEvent) -> anyhow::Result<()> {
        match event {
            ChangeEvent::Modified {
                path,
                data,
                mtime,
                ctime,
                is_binary,
            } => {
                let filename = path.to_string_lossy();
                let full_path = if self.base_dir.is_empty() {
                    filename.to_string()
                } else {
                    format!("{}{}", self.base_dir, filename)
                };

                let doc_id =
                    path::path2id(&full_path, self.obfuscate_passphrase.as_deref());

                // Split content into chunks
                let result = chunk::disassemble(
                    &data,
                    &filename,
                    DEFAULT_PIECE_SIZE,
                    self.e2ee.as_ref(),
                )?;

                // Write chunks (content-addressed, conflict-safe)
                self.client.put_chunks(&result.chunks).await?;

                // Fetch existing _rev if updating
                let existing_rev: Option<String> = self
                    .client
                    .get_doc::<serde_json::Value>(&doc_id)
                    .await
                    .ok()
                    .and_then(|doc| {
                        doc.get("_rev")
                            .and_then(|v| v.as_str())
                            .map(String::from)
                    });

                // Build parent document
                let doc_type = if is_binary { TYPE_NEWNOTE } else { TYPE_PLAIN };
                let path_field = if let Some(ref ctx) = self.e2ee {
                    crypto::encrypt_meta(
                        &full_path,
                        mtime,
                        ctime,
                        data.len() as u64,
                        &result.children,
                        &ctx.master_key,
                    )?
                } else {
                    full_path.clone()
                };

                let mut doc = serde_json::json!({
                    "_id": doc_id,
                    "type": doc_type,
                    "path": path_field,
                    "ctime": ctime,
                    "mtime": mtime,
                    "size": data.len(),
                    "children": result.children,
                    "eden": {},
                });
                if let Some(rev) = existing_rev {
                    doc["_rev"] = serde_json::json!(rev);
                }

                let resp = self.client.put_doc(&doc_id, &doc).await?;
                self.rev_tracker.record(resp.rev.clone());

                tracing::debug!(
                    peer = %self.name, path = %filename,
                    chunks = result.chunks.len(), rev = %resp.rev,
                    "wrote document"
                );
            }
            ChangeEvent::Deleted { path } => {
                let filename = path.to_string_lossy();
                let full_path = if self.base_dir.is_empty() {
                    filename.to_string()
                } else {
                    format!("{}{}", self.base_dir, filename)
                };

                let doc_id =
                    path::path2id(&full_path, self.obfuscate_passphrase.as_deref());

                // Fetch current _rev (required for CouchDB delete)
                let doc: serde_json::Value = match self.client.get_doc(&doc_id).await {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!(
                            peer = %self.name, path = %filename,
                            "doc not found for delete: {e}"
                        );
                        return Ok(());
                    }
                };

                let rev = doc
                    .get("_rev")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| anyhow::anyhow!("missing _rev on {doc_id}"))?;

                let resp = self.client.delete_doc(&doc_id, rev).await?;
                self.rev_tracker.record(resp.rev);

                tracing::debug!(peer = %self.name, path = %filename, "deleted document");
            }
        }

        Ok(())
    }
}
