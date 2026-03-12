use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use litesync_commonlib::chunk::{self, E2EEContext};
use litesync_commonlib::couchdb::{CouchDBClient, CouchDBHttpError, RemoteTweaks};
use litesync_commonlib::doc::{RawNoteEntry, TYPE_NEWNOTE, TYPE_PLAIN};
use litesync_commonlib::path;

use super::couchdb_ops;

use crate::bridge::{ChangeEvent, PeerMessage};
use crate::config::CouchDBPeerConfig;
use crate::state::{PathCache, RevTracker, SinceTracker};

const LONGPOLL_TIMEOUT_MS: u64 = 30_000;
pub(crate) const MAX_CONFLICT_RETRIES: u32 = 3;

pub(crate) fn is_conflict(err: &anyhow::Error) -> bool {
    err.downcast_ref::<CouchDBHttpError>()
        .is_some_and(|e| e.status == 409)
}

pub(crate) fn is_not_found(err: &anyhow::Error) -> bool {
    err.downcast_ref::<CouchDBHttpError>()
        .is_some_and(|e| e.status == 404)
}

/// Check if a relative path refers to a hidden file/directory.
/// Matches the same convention as StoragePeer's watcher filter.
pub(crate) fn is_hidden_path(rel_path: &str) -> bool {
    rel_path.starts_with('.') || rel_path.contains("/.")
}

pub struct CouchDBPeer {
    name: Arc<str>,
    group: Arc<str>,
    base_dir: String,
    obfuscate_passphrase: Option<String>,
    case_sensitive: bool,
    client: CouchDBClient,
    e2ee: Option<E2EEContext>,
    tweaks: RemoteTweaks,
    rev_tracker: Arc<RevTracker>,
    path_cache: Arc<PathCache>,
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

        // Fetch remote tweaks (chunk size, min chunk size, hash alg, etc.)
        let tweaks = client.get_remote_tweaks().await?;
        tracing::info!(
            peer = %config.name,
            piece_size = tweaks.piece_size(),
            min_chunk_size = tweaks.minimum_chunk_size,
            hash_alg = %tweaks.hash_alg,
            case_sensitive = tweaks.handle_filename_case_sensitive,
            "remote tweaks loaded"
        );

        let since = SinceTracker::load(data_dir, &config.name);
        tracing::info!(peer = %config.name, since = %since.get(), "loaded since sequence");

        let base_dir = if config.base_dir.is_empty() {
            String::new()
        } else if config.base_dir.ends_with('/') {
            config.base_dir
        } else {
            format!("{}/", config.base_dir)
        };

        let case_sensitive = tweaks.handle_filename_case_sensitive;

        let peer = Self {
            name: Arc::from(config.name),
            group: Arc::from(config.group),
            base_dir,
            obfuscate_passphrase: config.obfuscate_passphrase,
            case_sensitive,
            client,
            e2ee,
            tweaks,
            rev_tracker: Arc::new(RevTracker::new()),
            path_cache: Arc::new(PathCache::new()),
        };

        Ok((peer, since))
    }

    // ── Accessors for reconciliation ────────────────────────────────────────

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn group(&self) -> &str {
        &self.group
    }

    pub(crate) fn client(&self) -> &CouchDBClient {
        &self.client
    }

    pub(crate) fn e2ee(&self) -> Option<&E2EEContext> {
        self.e2ee.as_ref()
    }

    pub(crate) fn base_dir_prefix(&self) -> &str {
        &self.base_dir
    }

    pub(crate) fn obfuscate_passphrase(&self) -> Option<&str> {
        self.obfuscate_passphrase.as_deref()
    }

    pub(crate) fn rev_tracker(&self) -> &Arc<RevTracker> {
        &self.rev_tracker
    }

    pub(crate) fn path_cache(&self) -> &Arc<PathCache> {
        &self.path_cache
    }

    pub(crate) fn tweaks(&self) -> &RemoteTweaks {
        &self.tweaks
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

                        // Handle deletions: tombstones may lack full doc body
                        if change.deleted == Some(true) {
                            match self.resolve_deleted_path(&change.id, change.doc.as_ref()) {
                                Some(rel_path) => {
                                    let msg = PeerMessage {
                                        source_name: self.name.clone(),
                                        group: self.group.clone(),
                                        event: ChangeEvent::Deleted {
                                            path: PathBuf::from(&rel_path),
                                        },
                                    };
                                    if hub_tx.send(msg).await.is_err() {
                                        return Ok(());
                                    }
                                }
                                None => {
                                    tracing::warn!(
                                        peer = %self.name, doc_id = %change.id,
                                        "cannot resolve path for deleted document"
                                    );
                                }
                            }
                            continue;
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
                                // Cache doc_id → rel_path for future delete lookups
                                let rel_path = event.path().to_string_lossy().to_string();
                                self.path_cache
                                    .insert(change.id.clone(), rel_path);

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

                    since.update(&changes.last_seq).await?;
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

    /// Resolve the relative file path for a deleted document.
    ///
    /// CouchDB tombstones may lack the full document body, so we try multiple
    /// strategies: parse the tombstone body, reverse the doc ID, or fall back
    /// to the in-memory path cache.
    fn resolve_deleted_path(
        &self,
        doc_id: &str,
        doc_value: Option<&serde_json::Value>,
    ) -> Option<String> {
        // Strategy 1: Try parsing whatever fields the tombstone has
        if let Some(val) = doc_value {
            if let Ok(raw) = serde_json::from_value::<RawNoteEntry>(val.clone()) {
                if let Ok(note) = chunk::resolve_note(&raw, self.e2ee.as_ref(), Some(true)) {
                    if let Some(rel) = self.apply_base_dir_filter(&note.path) {
                        if !path::is_internal_livesync_path(&rel)
                            && !path::should_be_ignored(&rel)
                            && !is_hidden_path(&rel)
                        {
                            return Some(rel);
                        }
                    }
                }
            }
        }

        // Strategy 2: Try reversing the doc ID (works for non-obfuscated IDs)
        if let Ok(full_path) = path::id2path(doc_id, None) {
            if let Some(rel) = self.apply_base_dir_filter(&full_path) {
                if !path::is_internal_livesync_path(&rel)
                    && !path::should_be_ignored(&rel)
                    && !is_hidden_path(&rel)
                {
                    return Some(rel);
                }
            }
        }

        // Strategy 3: Path cache lookup (works for obfuscated IDs we've seen before)
        self.path_cache.get(doc_id)
    }

    fn apply_base_dir_filter(&self, full_path: &str) -> Option<String> {
        couchdb_ops::apply_base_dir_filter(&self.base_dir, full_path)
    }

    async fn process_change(
        &self,
        raw: &RawNoteEntry,
        deleted: Option<bool>,
    ) -> anyhow::Result<Option<ChangeEvent>> {
        let note = chunk::resolve_note(raw, self.e2ee.as_ref(), deleted)?;

        let rel_path = match self.apply_base_dir_filter(&note.path) {
            Some(r) => r,
            None => return Ok(None),
        };

        if path::is_internal_livesync_path(&rel_path)
            || path::should_be_ignored(&rel_path)
            || is_hidden_path(&rel_path)
        {
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
                    path::path2id(&full_path, self.obfuscate_passphrase.as_deref(), self.case_sensitive);

                couchdb_ops::upload_to_couchdb(
                    &self.client,
                    self.e2ee.as_ref(),
                    &self.tweaks,
                    &doc_id,
                    &full_path,
                    &filename,
                    &data,
                    mtime,
                    ctime,
                    is_binary,
                    &self.rev_tracker,
                    &self.path_cache,
                )
                .await?;

                tracing::debug!(
                    peer = %self.name, path = %filename,
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
                    path::path2id(&full_path, self.obfuscate_passphrase.as_deref(), self.case_sensitive);

                couchdb_ops::soft_delete_from_couchdb(
                    &self.client,
                    self.e2ee.as_ref(),
                    &doc_id,
                    &full_path,
                    &self.rev_tracker,
                )
                .await?;

                tracing::debug!(
                    peer = %self.name, path = %filename,
                    "soft-deleted document"
                );
            }
        }

        Ok(())
    }
}
