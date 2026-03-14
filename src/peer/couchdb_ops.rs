use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use litesync_commonlib::chunk::{self, E2EEContext};
use litesync_commonlib::couchdb::{CouchDBClient, RemoteTweaks};
use litesync_commonlib::crypto;
use litesync_commonlib::doc::{TYPE_NEWNOTE, TYPE_PLAIN};

use crate::state::{PathCache, RevTracker};

use super::couchdb::{is_conflict, is_not_found, MAX_CONFLICT_RETRIES};

/// Upload a file to CouchDB: disassemble → put_chunks → put_doc (with conflict retry).
///
/// The caller is responsible for computing `doc_id` and `full_path` (which depend
/// on base_dir, obfuscate_passphrase, and case_sensitive settings).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_to_couchdb(
    client: &CouchDBClient,
    e2ee: Option<&E2EEContext>,
    tweaks: &RemoteTweaks,
    doc_id: &str,
    full_path: &str,
    rel_path: &str,
    data: &[u8],
    mtime: u64,
    ctime: u64,
    is_binary: bool,
    rev_tracker: &Arc<RevTracker>,
    path_cache: &Arc<PathCache>,
) -> anyhow::Result<()> {
    let result = chunk::disassemble(
        data,
        rel_path,
        tweaks.piece_size(),
        tweaks.minimum_chunk_size,
        e2ee,
        &tweaks.hash_alg,
        &tweaks.chunk_splitter_version,
    )?;

    // Write chunks (content-addressed, idempotent — outside retry loop)
    client.put_chunks(&result.chunks).await?;

    let doc_type = if is_binary { TYPE_NEWNOTE } else { TYPE_PLAIN };

    for attempt in 0..MAX_CONFLICT_RETRIES {
        // Fetch existing doc for _rev and eden preservation
        let (existing_rev, existing_eden) = client
            .get_doc::<serde_json::Value>(doc_id)
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

        // Build parent document (E2EE: encrypt_meta uses random IV each call,
        // but decrypt produces the same plaintext — safe to retry)
        let (path_field, doc_ctime, doc_mtime, doc_size, doc_children) =
            if let Some(ctx) = e2ee {
                let encrypted = crypto::encrypt_meta(
                    full_path,
                    mtime,
                    ctime,
                    data.len() as u64,
                    &result.children,
                    &ctx.master_key,
                )?;
                (encrypted, 0u64, 0u64, 0u64, Vec::<String>::new())
            } else {
                (
                    full_path.to_string(),
                    ctime,
                    mtime,
                    data.len() as u64,
                    result.children.clone(),
                )
            };

        let mut doc = serde_json::json!({
            "_id": doc_id,
            "type": doc_type,
            "datatype": doc_type,
            "path": path_field,
            "ctime": doc_ctime,
            "mtime": doc_mtime,
            "size": doc_size,
            "children": doc_children,
            "eden": existing_eden,
        });
        if e2ee.is_some() {
            doc["e_"] = serde_json::json!(true);
        }
        if let Some(rev) = existing_rev {
            doc["_rev"] = serde_json::json!(rev);
        }

        match client.put_doc(doc_id, &doc).await {
            Ok(resp) => {
                rev_tracker.record(resp.rev);
                path_cache.insert(doc_id.to_string(), rel_path.to_string());
                return Ok(());
            }
            Err(e)
                if attempt < MAX_CONFLICT_RETRIES - 1
                    && is_conflict(&e) =>
            {
                tracing::debug!(
                    doc_id = %doc_id, attempt,
                    "409 conflict on put, retrying"
                );
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    unreachable!("all retry attempts return from within the loop")
}

/// Soft-delete a document in CouchDB: get_doc (rev) → build tombstone → put_doc (with retry).
///
/// The caller provides the `doc_id` and the `full_path` (for E2EE metadata encryption).
pub(crate) async fn soft_delete_from_couchdb(
    client: &CouchDBClient,
    e2ee: Option<&E2EEContext>,
    doc_id: &str,
    full_path: &str,
    rev_tracker: &Arc<RevTracker>,
) -> anyhow::Result<()> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    for attempt in 0..MAX_CONFLICT_RETRIES {
        let existing: serde_json::Value = match client.get_doc(doc_id).await {
            Ok(d) => d,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(e),
        };

        let rev = existing
            .get("_rev")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("missing _rev on {doc_id}"))?;

        // Soft-delete: PUT the document back with `deleted: true`,
        // matching the Obsidian LiveSync plugin protocol.
        let (path_field, doc_mtime) = if let Some(ctx) = e2ee {
            let encrypted = crypto::encrypt_meta(
                full_path,
                now_ms,
                0,
                0,
                &[],
                &ctx.master_key,
            )?;
            (encrypted, 0u64)
        } else {
            (full_path.to_string(), now_ms)
        };

        let mut doc = serde_json::json!({
            "_id": doc_id,
            "_rev": rev,
            "type": TYPE_NEWNOTE,
            "datatype": TYPE_NEWNOTE,
            "path": path_field,
            "ctime": 0u64,
            "mtime": doc_mtime,
            "size": 0u64,
            "children": Vec::<String>::new(),
            "eden": {},
            "data": "",
            "deleted": true,
        });
        if e2ee.is_some() {
            doc["e_"] = serde_json::json!(true);
        }

        match client.put_doc(doc_id, &doc).await {
            Ok(resp) => {
                rev_tracker.record(resp.rev);
                return Ok(());
            }
            Err(e)
                if attempt < MAX_CONFLICT_RETRIES - 1
                    && is_conflict(&e) =>
            {
                tracing::debug!(
                    doc_id = %doc_id, attempt,
                    "409 conflict on soft-delete, retrying"
                );
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    unreachable!("all retry attempts return from within the loop")
}

/// Apply base_dir filtering and strip the prefix, returning the relative path.
pub(crate) fn apply_base_dir_filter(base_dir_prefix: &str, full_path: &str) -> Option<String> {
    if base_dir_prefix.is_empty() {
        return Some(full_path.to_string());
    }
    full_path
        .strip_prefix(base_dir_prefix)
        .map(|s| s.to_string())
}
