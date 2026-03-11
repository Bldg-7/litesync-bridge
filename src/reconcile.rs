use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio_util::sync::CancellationToken;

use litesync_commonlib::chunk::{self, E2EEContext};
use litesync_commonlib::couchdb::CouchDBClient;
use litesync_commonlib::doc::{RawNoteEntry, TYPE_NEWNOTE, TYPE_PLAIN};
use litesync_commonlib::path;

use crate::peer::couchdb::{
    is_conflict, is_hidden_path, is_not_found, CouchDBPeer, DEFAULT_PIECE_SIZE,
    MAX_CONFLICT_RETRIES,
};
use crate::peer::storage::StoragePeer;
use crate::state::{PathCache, RevTracker, SinceTracker, StatCache};

/// Mtime tolerance: differences within 1 second are considered equal.
const MTIME_TOLERANCE_MS: u64 = 1000;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RemoteEntry {
    pub rel_path: String,
    pub doc_id: String,
    pub mtime: u64,
    pub size: u64,
    pub deleted: bool,
}

#[derive(Debug, Clone)]
pub struct LocalEntry {
    pub rel_path: String,
    pub mtime: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    DownloadToLocal { rel_path: String, doc_id: String },
    UploadToRemote { rel_path: String },
    DeleteLocal { rel_path: String },
    DeleteRemote { rel_path: String, doc_id: String },
    InSync { rel_path: String },
}

#[derive(Debug, Default)]
pub struct ReconcileStats {
    pub downloaded: u32,
    pub uploaded: u32,
    pub deleted_local: u32,
    pub deleted_remote: u32,
    pub in_sync: u32,
    pub errors: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure diff algorithm (no I/O)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute reconciliation actions by comparing remote and local state.
///
/// Uses Last-Writer-Wins (mtime-based, 1s tolerance) for files that exist on
/// both sides. For one-sided entries, the since tracker state and stat cache
/// are used as discriminators.
///
/// `is_first_run` indicates the since tracker had no saved sequence ("now"),
/// meaning we've never synced before. In this case, missing local files are
/// always downloaded rather than triggering a remote delete.
pub fn compute_actions(
    remote_map: &HashMap<String, RemoteEntry>,
    local_map: &HashMap<String, LocalEntry>,
    stat_cache: &StatCache,
    is_first_run: bool,
) -> Vec<ReconcileAction> {
    let mut actions = Vec::new();

    // 1. Process all remote entries
    for (rel_path, remote) in remote_map {
        let local = local_map.get(rel_path);

        if remote.deleted {
            // Remote is deleted
            match local {
                Some(local_entry) => {
                    // Remote deleted + local exists
                    if stat_cache.is_changed(rel_path, local_entry.mtime, local_entry.size) {
                        // Local was modified/new since last sync → upload wins
                        actions.push(ReconcileAction::UploadToRemote {
                            rel_path: rel_path.clone(),
                        });
                    } else {
                        // Local unchanged → delete local
                        actions.push(ReconcileAction::DeleteLocal {
                            rel_path: rel_path.clone(),
                        });
                    }
                }
                None => {
                    // Both deleted → in sync
                    actions.push(ReconcileAction::InSync {
                        rel_path: rel_path.clone(),
                    });
                }
            }
            continue;
        }

        // Remote is alive
        match local {
            Some(local_entry) => {
                // Both exist → mtime LWW with tolerance
                let diff = remote.mtime.abs_diff(local_entry.mtime);
                if diff <= MTIME_TOLERANCE_MS {
                    actions.push(ReconcileAction::InSync {
                        rel_path: rel_path.clone(),
                    });
                } else if remote.mtime > local_entry.mtime {
                    actions.push(ReconcileAction::DownloadToLocal {
                        rel_path: rel_path.clone(),
                        doc_id: remote.doc_id.clone(),
                    });
                } else {
                    actions.push(ReconcileAction::UploadToRemote {
                        rel_path: rel_path.clone(),
                    });
                }
            }
            None => {
                // Remote alive, local missing
                if is_first_run {
                    // First run: always download
                    actions.push(ReconcileAction::DownloadToLocal {
                        rel_path: rel_path.clone(),
                        doc_id: remote.doc_id.clone(),
                    });
                } else if stat_cache.existed(rel_path) {
                    // We had it before → user deleted locally → delete remote
                    actions.push(ReconcileAction::DeleteRemote {
                        rel_path: rel_path.clone(),
                        doc_id: remote.doc_id.clone(),
                    });
                } else {
                    // Never had it → new remote file → download
                    actions.push(ReconcileAction::DownloadToLocal {
                        rel_path: rel_path.clone(),
                        doc_id: remote.doc_id.clone(),
                    });
                }
            }
        }
    }

    // 2. Local-only files (not in remote at all) → upload
    for rel_path in local_map.keys() {
        if !remote_map.contains_key(rel_path) {
            actions.push(ReconcileAction::UploadToRemote {
                rel_path: rel_path.clone(),
            });
        }
    }

    // Sort for deterministic order
    actions.sort_by(|a, b| action_path(a).cmp(action_path(b)));

    actions
}

fn action_path(action: &ReconcileAction) -> &str {
    match action {
        ReconcileAction::DownloadToLocal { rel_path, .. }
        | ReconcileAction::UploadToRemote { rel_path }
        | ReconcileAction::DeleteLocal { rel_path }
        | ReconcileAction::DeleteRemote { rel_path, .. }
        | ReconcileAction::InSync { rel_path } => rel_path,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Filesystem scanning
// ─────────────────────────────────────────────────────────────────────────────

/// Recursively scan a directory and build a map of relative paths to LocalEntry.
pub async fn scan_local_files(base_dir: &Path) -> anyhow::Result<HashMap<String, LocalEntry>> {
    let base = base_dir.to_path_buf();
    tokio::task::spawn_blocking(move || scan_dir_sync(&base))
        .await
        .map_err(|e| anyhow::anyhow!("spawn_blocking failed: {e}"))?
}

fn scan_dir_sync(base_dir: &Path) -> anyhow::Result<HashMap<String, LocalEntry>> {
    let mut map = HashMap::new();
    if !base_dir.exists() {
        return Ok(map);
    }
    scan_dir_recursive(base_dir, base_dir, &mut map)?;
    Ok(map)
}

fn scan_dir_recursive(
    base_dir: &Path,
    current: &Path,
    map: &mut HashMap<String, LocalEntry>,
) -> anyhow::Result<()> {
    let entries = match std::fs::read_dir(current) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };

    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();

        let rel = path.strip_prefix(base_dir).unwrap_or(&path);
        let rel_str = rel.to_string_lossy();

        // Skip hidden files/dirs
        if is_hidden_path(&rel_str) {
            continue;
        }

        if file_type.is_dir() {
            scan_dir_recursive(base_dir, &path, map)?;
        } else if file_type.is_file() {
            if path::should_be_ignored(&rel_str) {
                continue;
            }
            let metadata = entry.metadata()?;
            let mtime = metadata
                .modified()?
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let size = metadata.len();

            map.insert(
                rel_str.to_string(),
                LocalEntry {
                    rel_path: rel_str.to_string(),
                    mtime,
                    size,
                },
            );
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Remote entry fetching
// ─────────────────────────────────────────────────────────────────────────────

/// Fetch all note documents from CouchDB and build a remote entry map.
///
/// Returns `(remote_map, last_seq)` where `last_seq` should be used to update
/// the SinceTracker after reconciliation completes.
pub async fn fetch_remote_entries(
    client: &CouchDBClient,
    e2ee: Option<&E2EEContext>,
    base_dir_prefix: &str,
) -> anyhow::Result<(HashMap<String, RemoteEntry>, serde_json::Value)> {
    let changes = client.get_all_notes().await?;
    let mut map = HashMap::new();

    for change in &changes.results {
        let deleted = change.deleted == Some(true);

        if deleted {
            // For deleted docs, try multiple strategies (matching CouchDBPeer)
            if let Some(rel_path) =
                resolve_deleted_path_static(&change.id, change.doc.as_ref(), e2ee, base_dir_prefix)
            {
                map.insert(
                    rel_path.clone(),
                    RemoteEntry {
                        rel_path,
                        doc_id: change.id.clone(),
                        mtime: 0,
                        size: 0,
                        deleted: true,
                    },
                );
            }
            continue;
        }

        let Some(ref doc_value) = change.doc else {
            continue;
        };
        let raw: RawNoteEntry = match serde_json::from_value(doc_value.clone()) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if raw.type_ != TYPE_PLAIN && raw.type_ != TYPE_NEWNOTE {
            continue;
        }

        let note = match chunk::resolve_note(&raw, e2ee, Some(false)) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(doc_id = %change.id, "failed to resolve note: {e}");
                continue;
            }
        };

        let rel_path = match apply_base_dir_filter(base_dir_prefix, &note.path) {
            Some(r) => r,
            None => continue,
        };

        if path::should_be_ignored(&rel_path) || is_hidden_path(&rel_path) {
            continue;
        }

        map.insert(
            rel_path.clone(),
            RemoteEntry {
                rel_path,
                doc_id: change.id.clone(),
                mtime: note.mtime,
                size: note.size,
                deleted: false,
            },
        );
    }

    Ok((map, changes.last_seq))
}

/// Resolve the relative path for a deleted document using multiple strategies.
/// Mirrors `CouchDBPeer::resolve_deleted_path` but without path cache (unavailable
/// during reconciliation's initial fetch).
fn resolve_deleted_path_static(
    doc_id: &str,
    doc_value: Option<&serde_json::Value>,
    e2ee: Option<&E2EEContext>,
    base_dir_prefix: &str,
) -> Option<String> {
    // Strategy 1: Try parsing the tombstone body (works for E2EE/obfuscated)
    if let Some(val) = doc_value {
        if let Ok(raw) = serde_json::from_value::<RawNoteEntry>(val.clone()) {
            if let Ok(note) = chunk::resolve_note(&raw, e2ee, Some(true)) {
                if let Some(rel) = apply_base_dir_filter(base_dir_prefix, &note.path) {
                    if !path::should_be_ignored(&rel) && !is_hidden_path(&rel) {
                        return Some(rel);
                    }
                }
            }
        }
    }

    // Strategy 2: Try reversing the doc ID (works for non-obfuscated IDs)
    if let Ok(full_path) = path::id2path(doc_id, None) {
        if let Some(rel) = apply_base_dir_filter(base_dir_prefix, &full_path) {
            if !path::should_be_ignored(&rel) && !is_hidden_path(&rel) {
                return Some(rel);
            }
        }
    }

    None
}

fn apply_base_dir_filter(base_dir_prefix: &str, full_path: &str) -> Option<String> {
    if base_dir_prefix.is_empty() {
        return Some(full_path.to_string());
    }
    full_path
        .strip_prefix(base_dir_prefix)
        .map(|s| s.to_string())
}

// ─────────────────────────────────────────────────────────────────────────────
// Reconcile execution
// ─────────────────────────────────────────────────────────────────────────────

/// Execute reconciliation for a single CouchDB↔Storage peer pair.
#[allow(clippy::too_many_arguments)]
async fn reconcile(
    client: &CouchDBClient,
    e2ee: Option<&E2EEContext>,
    base_dir_prefix: &str,
    obfuscate_passphrase: Option<&str>,
    storage_base_dir: &Path,
    since: &mut SinceTracker,
    stat_cache: &mut StatCache,
    rev_tracker: &Arc<RevTracker>,
    path_cache: &Arc<PathCache>,
    cancel: &CancellationToken,
) -> anyhow::Result<ReconcileStats> {
    let is_first_run = since.get() == "now";
    let mut stats = ReconcileStats::default();

    tracing::info!(
        first_run = is_first_run,
        "starting reconciliation"
    );

    // 1. Fetch remote state
    let (remote_map, last_seq) =
        fetch_remote_entries(client, e2ee, base_dir_prefix).await?;
    tracing::info!(remote_count = remote_map.len(), "fetched remote entries");

    if cancel.is_cancelled() {
        return Ok(stats);
    }

    // 2. Scan local state
    let local_map = scan_local_files(storage_base_dir).await?;
    tracing::info!(local_count = local_map.len(), "scanned local files");

    if cancel.is_cancelled() {
        return Ok(stats);
    }

    // 3. Compute diff
    let actions = compute_actions(&remote_map, &local_map, stat_cache, is_first_run);
    let action_count = actions.len();
    let non_sync = actions
        .iter()
        .filter(|a| !matches!(a, ReconcileAction::InSync { .. }))
        .count();
    tracing::info!(
        total = action_count,
        pending = non_sync,
        "computed reconciliation actions"
    );

    // 4. Execute actions
    for action in &actions {
        if cancel.is_cancelled() {
            tracing::info!("reconciliation cancelled");
            break;
        }

        match action {
            ReconcileAction::DownloadToLocal { rel_path, doc_id } => {
                match execute_download(client, e2ee, doc_id, rel_path, storage_base_dir).await {
                    Ok((mtime, size)) => {
                        stat_cache.insert(rel_path.clone(), mtime, size);
                        // Cache doc_id → rel_path for future delete resolution
                        path_cache.insert(doc_id.clone(), rel_path.clone());
                        stats.downloaded += 1;
                        tracing::debug!(path = %rel_path, "downloaded");
                    }
                    Err(e) => {
                        tracing::warn!(path = %rel_path, "download failed: {e}");
                        stats.errors += 1;
                    }
                }
            }
            ReconcileAction::UploadToRemote { rel_path } => {
                match execute_upload(
                    client,
                    e2ee,
                    base_dir_prefix,
                    obfuscate_passphrase,
                    rel_path,
                    storage_base_dir,
                    rev_tracker,
                    path_cache,
                )
                .await
                {
                    Ok((mtime, size)) => {
                        stat_cache.insert(rel_path.clone(), mtime, size);
                        stats.uploaded += 1;
                        tracing::debug!(path = %rel_path, "uploaded");
                    }
                    Err(e) => {
                        tracing::warn!(path = %rel_path, "upload failed: {e}");
                        stats.errors += 1;
                    }
                }
            }
            ReconcileAction::DeleteLocal { rel_path } => {
                let full = storage_base_dir.join(rel_path);
                match tokio::fs::remove_file(&full).await {
                    Ok(()) => {
                        stat_cache.remove(rel_path);
                        stats.deleted_local += 1;
                        tracing::debug!(path = %rel_path, "deleted local");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        stat_cache.remove(rel_path);
                        stats.deleted_local += 1;
                    }
                    Err(e) => {
                        tracing::warn!(path = %rel_path, "delete local failed: {e}");
                        stats.errors += 1;
                    }
                }
            }
            ReconcileAction::DeleteRemote { rel_path, doc_id } => {
                match execute_delete_remote(client, doc_id, rev_tracker).await {
                    Ok(()) => {
                        stat_cache.remove(rel_path);
                        stats.deleted_remote += 1;
                        tracing::debug!(path = %rel_path, "deleted remote");
                    }
                    Err(e) => {
                        tracing::warn!(path = %rel_path, "delete remote failed: {e}");
                        stats.errors += 1;
                    }
                }
            }
            ReconcileAction::InSync { rel_path } => {
                // Update stat cache with current local state
                if let Some(local) = local_map.get(rel_path) {
                    stat_cache.insert(rel_path.clone(), local.mtime, local.size);
                }
                stats.in_sync += 1;
            }
        }
    }

    // 5. On cancellation, don't persist anything — keep prior state intact
    if cancel.is_cancelled() {
        tracing::info!("reconciliation cancelled, not persisting state");
        return Ok(stats);
    }

    // 6. Don't advance since if there were errors — next run will re-reconcile
    if stats.errors > 0 {
        tracing::warn!(
            errors = stats.errors,
            "reconciliation had errors, not advancing since sequence"
        );
        // Still save stat cache so successful actions aren't repeated
        stat_cache.save().await?;
    } else {
        // Persist stat cache
        stat_cache.save().await?;

        // Update since tracker so longpoll starts after this point
        since.update(&last_seq).await?;
    }

    tracing::info!(
        since = %since.get(),
        downloaded = stats.downloaded,
        uploaded = stats.uploaded,
        deleted_local = stats.deleted_local,
        deleted_remote = stats.deleted_remote,
        in_sync = stats.in_sync,
        errors = stats.errors,
        "reconciliation complete"
    );

    Ok(stats)
}

async fn execute_download(
    client: &CouchDBClient,
    e2ee: Option<&E2EEContext>,
    doc_id: &str,
    rel_path: &str,
    storage_base_dir: &Path,
) -> anyhow::Result<(u64, u64)> {
    // Fetch the full document
    let doc_value: serde_json::Value = client.get_doc(doc_id).await?;
    let raw: RawNoteEntry = serde_json::from_value(doc_value)?;
    let note = chunk::resolve_note(&raw, e2ee, Some(false))?;
    let data = chunk::reassemble(client, &note, e2ee).await?;

    let full = storage_base_dir.join(rel_path);
    if let Some(parent) = full.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&full, &data).await?;

    // Restore mtime
    let ft = filetime::FileTime::from_unix_time(
        (note.mtime / 1000) as i64,
        ((note.mtime % 1000) * 1_000_000) as u32,
    );
    let full_clone = full.clone();
    tokio::task::spawn_blocking(move || filetime::set_file_mtime(&full_clone, ft)).await??;

    Ok((note.mtime, data.len() as u64))
}

#[allow(clippy::too_many_arguments)]
async fn execute_upload(
    client: &CouchDBClient,
    e2ee: Option<&E2EEContext>,
    base_dir_prefix: &str,
    obfuscate_passphrase: Option<&str>,
    rel_path: &str,
    storage_base_dir: &Path,
    rev_tracker: &Arc<RevTracker>,
    path_cache: &Arc<PathCache>,
) -> anyhow::Result<(u64, u64)> {
    let full = storage_base_dir.join(rel_path);
    let metadata = tokio::fs::metadata(&full).await?;
    let data = tokio::fs::read(&full).await?;

    let is_binary = !path::is_plain_text(rel_path);

    let mtime = metadata
        .modified()?
        .duration_since(UNIX_EPOCH)?
        .as_millis() as u64;
    let ctime = metadata
        .created()
        .unwrap_or_else(|_| metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH))
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let size = data.len() as u64;

    let full_path = if base_dir_prefix.is_empty() {
        rel_path.to_string()
    } else {
        format!("{base_dir_prefix}{rel_path}")
    };

    let doc_id = path::path2id(&full_path, obfuscate_passphrase);
    let result = chunk::disassemble(&data, rel_path, DEFAULT_PIECE_SIZE, e2ee)?;

    // Write chunks (content-addressed, idempotent — outside retry loop)
    client.put_chunks(&result.chunks).await?;

    let doc_type = if is_binary { TYPE_NEWNOTE } else { TYPE_PLAIN };

    // Retry loop matching CouchDBPeer::handle_write
    for attempt in 0..MAX_CONFLICT_RETRIES {
        // Fetch existing doc for _rev and eden preservation
        let (existing_rev, existing_eden) = client
            .get_doc::<serde_json::Value>(&doc_id)
            .await
            .ok()
            .map(|d| {
                let rev = d
                    .get("_rev")
                    .and_then(|v| v.as_str())
                    .map(String::from);
                let eden = d.get("eden").cloned().unwrap_or(serde_json::json!({}));
                (rev, eden)
            })
            .unwrap_or((None, serde_json::json!({})));

        let (path_field, doc_ctime, doc_mtime, doc_size, doc_children) =
            if let Some(ctx) = e2ee {
                let encrypted = litesync_commonlib::crypto::encrypt_meta(
                    &full_path,
                    mtime,
                    ctime,
                    size,
                    &result.children,
                    &ctx.master_key,
                )?;
                (encrypted, 0u64, 0u64, 0u64, Vec::<String>::new())
            } else {
                (
                    full_path.clone(),
                    ctime,
                    mtime,
                    size,
                    result.children.clone(),
                )
            };

        let mut doc = serde_json::json!({
            "_id": doc_id,
            "type": doc_type,
            "path": path_field,
            "ctime": doc_ctime,
            "mtime": doc_mtime,
            "size": doc_size,
            "children": doc_children,
            "eden": existing_eden,
        });
        if let Some(rev) = existing_rev {
            doc["_rev"] = serde_json::json!(rev);
        }

        match client.put_doc(&doc_id, &doc).await {
            Ok(resp) => {
                rev_tracker.record(resp.rev);
                path_cache.insert(doc_id.clone(), rel_path.to_string());
                break;
            }
            Err(e) if attempt < MAX_CONFLICT_RETRIES - 1 && is_conflict(&e) => {
                tracing::debug!(
                    doc_id = %doc_id, attempt,
                    "409 conflict on reconciliation put, retrying"
                );
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok((mtime, size))
}

async fn execute_delete_remote(
    client: &CouchDBClient,
    doc_id: &str,
    rev_tracker: &Arc<RevTracker>,
) -> anyhow::Result<()> {
    for attempt in 0..MAX_CONFLICT_RETRIES {
        let doc: serde_json::Value = match client.get_doc(doc_id).await {
            Ok(d) => d,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(e),
        };

        let rev = doc
            .get("_rev")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing _rev on {doc_id}"))?;

        match client.delete_doc(doc_id, rev).await {
            Ok(resp) => {
                rev_tracker.record(resp.rev);
                return Ok(());
            }
            Err(e) if attempt < MAX_CONFLICT_RETRIES - 1 && is_conflict(&e) => {
                tracing::debug!(
                    doc_id = %doc_id, attempt,
                    "409 conflict on reconciliation delete, retrying"
                );
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Top-level entry point: reconcile all groups
// ─────────────────────────────────────────────────────────────────────────────

/// Initialized peer state, held between init and spawn phases.
pub enum InitializedPeer {
    CouchDB {
        peer: CouchDBPeer,
        since: SinceTracker,
    },
    Storage {
        peer: StoragePeer,
        config: crate::config::StoragePeerConfig,
    },
}

impl InitializedPeer {
    pub fn name(&self) -> &str {
        match self {
            InitializedPeer::CouchDB { peer, .. } => peer.name(),
            InitializedPeer::Storage { peer, .. } => peer.name(),
        }
    }

    pub fn group(&self) -> &str {
        match self {
            InitializedPeer::CouchDB { peer, .. } => peer.group(),
            InitializedPeer::Storage { peer, .. } => peer.group(),
        }
    }
}

/// Reconcile all CouchDB↔Storage peer pairs in the same group.
pub async fn reconcile_all(
    peers: &mut [InitializedPeer],
    data_dir: &Path,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    // Collect (couch_idx, storage_idx, group) pairs to reconcile.
    let mut pairs: Vec<(usize, usize, String)> = Vec::new();

    {
        let mut couchdb_by_group: HashMap<String, Vec<usize>> = HashMap::new();
        let mut storage_by_group: HashMap<String, Vec<usize>> = HashMap::new();

        for (i, peer) in peers.iter().enumerate() {
            let group = peer.group().to_string();
            match peer {
                InitializedPeer::CouchDB { .. } => {
                    couchdb_by_group.entry(group).or_default().push(i);
                }
                InitializedPeer::Storage { .. } => {
                    storage_by_group.entry(group).or_default().push(i);
                }
            }
        }

        for (group, couch_indices) in &couchdb_by_group {
            if let Some(storage_indices) = storage_by_group.get(group) {
                for &ci in couch_indices {
                    for &si in storage_indices {
                        pairs.push((ci, si, group.clone()));
                    }
                }
            }
        }
    }

    for (couch_idx, storage_idx, group) in pairs {
        if cancel.is_cancelled() {
            return Ok(());
        }

        // Collect storage info (immutable borrow, then drop)
        let (storage_name, storage_base_dir) = match &peers[storage_idx] {
            InitializedPeer::Storage { config, .. } => {
                (config.name.clone(), config.base_dir.clone())
            }
            _ => unreachable!(),
        };

        // Mutably match the CouchDB peer to get disjoint borrows of `peer` and `since`
        let InitializedPeer::CouchDB { peer, since } = &mut peers[couch_idx] else {
            unreachable!();
        };

        tracing::info!(
            group = %group,
            couchdb = %peer.name(),
            storage = %storage_name,
            "reconciling peer pair"
        );

        let mut stat_cache = StatCache::load(data_dir, &storage_name);

        let base_dir_prefix = peer.base_dir_prefix().to_string();
        let obfuscate_passphrase = peer.obfuscate_passphrase().map(String::from);
        let rev_tracker = peer.rev_tracker().clone();
        let path_cache = peer.path_cache().clone();

        let result = reconcile(
            peer.client(),
            peer.e2ee(),
            &base_dir_prefix,
            obfuscate_passphrase.as_deref(),
            &storage_base_dir,
            since,
            &mut stat_cache,
            &rev_tracker,
            &path_cache,
            cancel,
        )
        .await;

        if let Err(e) = result {
            tracing::error!(
                group = %group,
                storage = %storage_name,
                "reconciliation failed: {e}"
            );
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StatCache;

    fn make_stat_cache() -> StatCache {
        StatCache::load(Path::new("/tmp/nonexistent"), "test")
    }

    fn remote(rel_path: &str, mtime: u64, size: u64) -> (String, RemoteEntry) {
        (
            rel_path.to_string(),
            RemoteEntry {
                rel_path: rel_path.to_string(),
                doc_id: format!("doc:{rel_path}"),
                mtime,
                size,
                deleted: false,
            },
        )
    }

    fn remote_deleted(rel_path: &str) -> (String, RemoteEntry) {
        (
            rel_path.to_string(),
            RemoteEntry {
                rel_path: rel_path.to_string(),
                doc_id: format!("doc:{rel_path}"),
                mtime: 0,
                size: 0,
                deleted: true,
            },
        )
    }

    fn local(rel_path: &str, mtime: u64, size: u64) -> (String, LocalEntry) {
        (
            rel_path.to_string(),
            LocalEntry {
                rel_path: rel_path.to_string(),
                mtime,
                size,
            },
        )
    }

    // ── Mtime tolerance boundary tests ──────────────────────────────────

    #[test]
    fn both_exist_in_sync_within_tolerance() {
        let remote_map: HashMap<_, _> = [remote("a.md", 1000, 100)].into_iter().collect();
        let local_map: HashMap<_, _> = [local("a.md", 1500, 100)].into_iter().collect();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(actions, vec![ReconcileAction::InSync {
            rel_path: "a.md".into()
        }]);
    }

    #[test]
    fn both_exist_exact_tolerance_boundary_in_sync() {
        // Exactly 1000ms diff → should be InSync (<=)
        let remote_map: HashMap<_, _> = [remote("a.md", 2000, 100)].into_iter().collect();
        let local_map: HashMap<_, _> = [local("a.md", 1000, 100)].into_iter().collect();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(actions, vec![ReconcileAction::InSync {
            rel_path: "a.md".into()
        }]);
    }

    #[test]
    fn both_exist_just_over_tolerance_download() {
        // 1001ms diff → should trigger download (remote newer)
        let remote_map: HashMap<_, _> = [remote("a.md", 2001, 100)].into_iter().collect();
        let local_map: HashMap<_, _> = [local("a.md", 1000, 100)].into_iter().collect();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::DownloadToLocal {
                rel_path: "a.md".into(),
                doc_id: "doc:a.md".into(),
            }]
        );
    }

    #[test]
    fn both_exist_remote_newer_download() {
        let remote_map: HashMap<_, _> = [remote("a.md", 5000, 100)].into_iter().collect();
        let local_map: HashMap<_, _> = [local("a.md", 2000, 100)].into_iter().collect();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::DownloadToLocal {
                rel_path: "a.md".into(),
                doc_id: "doc:a.md".into(),
            }]
        );
    }

    #[test]
    fn both_exist_local_newer_upload() {
        let remote_map: HashMap<_, _> = [remote("a.md", 2000, 100)].into_iter().collect();
        let local_map: HashMap<_, _> = [local("a.md", 5000, 100)].into_iter().collect();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::UploadToRemote {
                rel_path: "a.md".into(),
            }]
        );
    }

    // ── One-sided: remote only ──────────────────────────────────────────

    #[test]
    fn remote_only_first_run_download() {
        let remote_map: HashMap<_, _> = [remote("a.md", 1000, 100)].into_iter().collect();
        let local_map: HashMap<_, _> = HashMap::new();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, true);
        assert_eq!(
            actions,
            vec![ReconcileAction::DownloadToLocal {
                rel_path: "a.md".into(),
                doc_id: "doc:a.md".into(),
            }]
        );
    }

    #[test]
    fn remote_only_never_existed_download() {
        let remote_map: HashMap<_, _> = [remote("a.md", 1000, 100)].into_iter().collect();
        let local_map: HashMap<_, _> = HashMap::new();
        let cache = make_stat_cache(); // empty = never existed

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::DownloadToLocal {
                rel_path: "a.md".into(),
                doc_id: "doc:a.md".into(),
            }]
        );
    }

    #[test]
    fn remote_only_existed_before_delete_remote() {
        let remote_map: HashMap<_, _> = [remote("a.md", 1000, 100)].into_iter().collect();
        let local_map: HashMap<_, _> = HashMap::new();
        let mut cache = make_stat_cache();
        cache.insert("a.md".to_string(), 1000, 100); // existed before

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::DeleteRemote {
                rel_path: "a.md".into(),
                doc_id: "doc:a.md".into(),
            }]
        );
    }

    // ── One-sided: local only ───────────────────────────────────────────

    #[test]
    fn local_only_upload() {
        let remote_map: HashMap<_, _> = HashMap::new();
        let local_map: HashMap<_, _> = [local("new.md", 3000, 200)].into_iter().collect();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::UploadToRemote {
                rel_path: "new.md".into(),
            }]
        );
    }

    // ── Remote deleted scenarios ────────────────────────────────────────

    #[test]
    fn remote_deleted_local_exists_unchanged_delete_local() {
        let remote_map: HashMap<_, _> = [remote_deleted("a.md")].into_iter().collect();
        let local_map: HashMap<_, _> = [local("a.md", 1000, 100)].into_iter().collect();
        let mut cache = make_stat_cache();
        cache.insert("a.md".to_string(), 1000, 100); // unchanged

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::DeleteLocal {
                rel_path: "a.md".into(),
            }]
        );
    }

    #[test]
    fn remote_deleted_local_exists_modified_upload() {
        let remote_map: HashMap<_, _> = [remote_deleted("a.md")].into_iter().collect();
        let local_map: HashMap<_, _> = [local("a.md", 2000, 200)].into_iter().collect();
        let mut cache = make_stat_cache();
        cache.insert("a.md".to_string(), 1000, 100); // was different

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::UploadToRemote {
                rel_path: "a.md".into(),
            }]
        );
    }

    #[test]
    fn remote_deleted_local_missing_in_sync() {
        let remote_map: HashMap<_, _> = [remote_deleted("a.md")].into_iter().collect();
        let local_map: HashMap<_, _> = HashMap::new();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(actions, vec![ReconcileAction::InSync {
            rel_path: "a.md".into()
        }]);
    }

    #[test]
    fn remote_deleted_local_new_file_upload() {
        // Remote deleted + local exists + NOT in stat cache (new file) → upload
        let remote_map: HashMap<_, _> = [remote_deleted("a.md")].into_iter().collect();
        let local_map: HashMap<_, _> = [local("a.md", 5000, 300)].into_iter().collect();
        let cache = make_stat_cache(); // empty = file is "new"

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![ReconcileAction::UploadToRemote {
                rel_path: "a.md".into(),
            }]
        );
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn empty_remote_and_local() {
        let remote_map: HashMap<_, _> = HashMap::new();
        let local_map: HashMap<_, _> = HashMap::new();
        let cache = make_stat_cache();

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert!(actions.is_empty());
    }

    #[test]
    fn multiple_files_mixed_actions() {
        let remote_map: HashMap<_, _> = [
            remote("sync.md", 1000, 100),
            remote("download.md", 5000, 200),
            remote_deleted("del-local.md"),
        ]
        .into_iter()
        .collect();
        let local_map: HashMap<_, _> = [
            local("sync.md", 1000, 100),
            local("download.md", 2000, 200),
            local("del-local.md", 1000, 50),
            local("upload.md", 3000, 150),
        ]
        .into_iter()
        .collect();

        let mut cache = make_stat_cache();
        cache.insert("del-local.md".to_string(), 1000, 50); // unchanged

        let actions = compute_actions(&remote_map, &local_map, &cache, false);
        assert_eq!(
            actions,
            vec![
                ReconcileAction::DeleteLocal {
                    rel_path: "del-local.md".into(),
                },
                ReconcileAction::DownloadToLocal {
                    rel_path: "download.md".into(),
                    doc_id: "doc:download.md".into(),
                },
                ReconcileAction::InSync {
                    rel_path: "sync.md".into(),
                },
                ReconcileAction::UploadToRemote {
                    rel_path: "upload.md".into(),
                },
            ]
        );
    }

    // ── Scan tests ──────────────────────────────────────────────────────

    #[test]
    fn scan_local_files_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let map = rt.block_on(scan_local_files(dir.path())).unwrap();
        assert!(map.is_empty());
    }

    #[test]
    fn scan_local_files_with_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.md"), "hello").unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/b.md"), "world").unwrap();
        // Hidden file should be skipped
        std::fs::write(dir.path().join(".hidden"), "skip").unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let map = rt.block_on(scan_local_files(dir.path())).unwrap();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("a.md"));
        assert!(map.contains_key("sub/b.md"));
        assert!(!map.contains_key(".hidden"));
    }

    // ── Helper function tests ───────────────────────────────────────────

    #[test]
    fn base_dir_filter_test() {
        assert_eq!(
            apply_base_dir_filter("", "notes/a.md"),
            Some("notes/a.md".to_string())
        );
        assert_eq!(
            apply_base_dir_filter("notes/", "notes/a.md"),
            Some("a.md".to_string())
        );
        assert_eq!(apply_base_dir_filter("notes/", "other/a.md"), None);
    }

    #[test]
    fn hidden_path_edge_cases() {
        assert!(is_hidden_path(".hidden"));
        assert!(is_hidden_path(".obsidian/config.json"));
        assert!(is_hidden_path("a/.hidden/b.md"));
        // Trailing dot is NOT hidden
        assert!(!is_hidden_path("file.md"));
        assert!(!is_hidden_path("a/b.md"));
    }
}
