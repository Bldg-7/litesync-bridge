use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::couchdb::CouchDBClient;
use crate::crypto;
use crate::doc::{NoteEntry, RawNoteEntry, ENCRYPTED_META_PREFIX};

/// Encryption context for decrypting E2EE-protected data.
pub struct E2EEContext<'a> {
    pub passphrase: &'a str,
    pub pbkdf2_salt: &'a [u8],
}

/// Resolve a `RawNoteEntry` from CouchDB into a fully decoded `NoteEntry`.
///
/// If E2EE is enabled (path starts with `/\:`), decrypts the metadata to
/// extract the real path, timestamps, and children list.
pub fn resolve_note(raw: &RawNoteEntry, e2ee: Option<&E2EEContext>) -> anyhow::Result<NoteEntry> {
    if raw.path.starts_with(ENCRYPTED_META_PREFIX) {
        let ctx = e2ee
            .ok_or_else(|| anyhow::anyhow!("document is encrypted but no E2EE context provided"))?;
        let meta = crypto::decrypt_meta(&raw.path, ctx.passphrase, ctx.pbkdf2_salt)?;
        Ok(NoteEntry {
            id: raw._id.clone(),
            rev: raw._rev.clone(),
            path: meta.path,
            ctime: meta.ctime,
            mtime: meta.mtime,
            size: meta.size,
            children: meta.children,
            eden: raw.eden.clone(),
            deleted: raw.is_deleted(),
            is_binary: raw.is_binary(),
        })
    } else {
        Ok(NoteEntry {
            id: raw._id.clone(),
            rev: raw._rev.clone(),
            path: raw.path.clone(),
            ctime: raw.ctime,
            mtime: raw.mtime,
            size: raw.size,
            children: raw.children.clone(),
            eden: raw.eden.clone(),
            deleted: raw.is_deleted(),
            is_binary: raw.is_binary(),
        })
    }
}

/// Reassemble file content from chunk documents.
///
/// For each chunk ID in `entry.children`:
/// 1. Check eden (inline chunks) first.
/// 2. Otherwise, batch-fetch from CouchDB.
/// 3. Decrypt chunk data if E2EE is enabled.
/// 4. Base64-decode each chunk.
/// 5. Concatenate all chunks in order.
pub async fn reassemble(
    client: &CouchDBClient,
    entry: &NoteEntry,
    e2ee: Option<&E2EEContext<'_>>,
) -> anyhow::Result<Vec<u8>> {
    if entry.children.is_empty() {
        return Ok(vec![]);
    }

    // Separate eden chunks from those needing a fetch.
    let mut chunk_data: Vec<Option<String>> = vec![None; entry.children.len()];
    let mut fetch_ids: Vec<(usize, String)> = Vec::new();

    for (i, child_id) in entry.children.iter().enumerate() {
        if let Some(eden_chunk) = entry.eden.get(child_id) {
            chunk_data[i] = Some(eden_chunk.data.clone());
        } else {
            fetch_ids.push((i, child_id.clone()));
        }
    }

    // Batch-fetch missing chunks from CouchDB.
    if !fetch_ids.is_empty() {
        let ids: Vec<String> = fetch_ids.iter().map(|(_, id)| id.clone()).collect();
        let leaves = client.get_chunks(&ids).await?;

        let leaf_map: std::collections::HashMap<&str, &str> = leaves
            .iter()
            .map(|l| (l._id.as_str(), l.data.as_str()))
            .collect();

        for (idx, id) in &fetch_ids {
            let data = leaf_map
                .get(id.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing chunk {id} for document {}", entry.id))?;
            chunk_data[*idx] = Some((*data).to_string());
        }
    }

    // Decrypt and decode each chunk, then concatenate.
    let mut result = Vec::new();
    for (i, data_opt) in chunk_data.into_iter().enumerate() {
        let raw_data = data_opt.ok_or_else(|| {
            anyhow::anyhow!("chunk {} not resolved for document {}", i, entry.id)
        })?;

        // Decrypt if encrypted.
        let decoded_data = if let Some(ctx) = e2ee {
            if raw_data.starts_with("%=") || raw_data.starts_with("%$") {
                crypto::decrypt_leaf_data(&raw_data, ctx.passphrase, ctx.pbkdf2_salt)?
            } else {
                raw_data
            }
        } else {
            raw_data
        };

        let bytes = BASE64.decode(&decoded_data)?;
        result.extend_from_slice(&bytes);
    }

    Ok(result)
}
