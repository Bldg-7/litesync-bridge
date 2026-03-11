use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::couchdb::CouchDBClient;
use crate::crypto;
use std::collections::HashMap;

use crate::doc::{EdenChunk, NoteEntry, RawNoteEntry, ENCRYPTED_META_PREFIX, EDEN_ENCRYPTED_KEY, EDEN_ENCRYPTED_KEY_HKDF};

/// Encryption context for decrypting E2EE-protected data.
///
/// The master key is derived once from the passphrase and PBKDF2 salt,
/// avoiding repeated PBKDF2 (310k iterations) per chunk.
pub struct E2EEContext {
    pub passphrase: String,
    pub pbkdf2_salt: Vec<u8>,
    pub master_key: [u8; 32],
}

impl E2EEContext {
    pub fn new(passphrase: &str, pbkdf2_salt: &[u8]) -> Self {
        let master_key = crypto::derive_master_key(passphrase, pbkdf2_salt);
        Self {
            passphrase: passphrase.to_string(),
            pbkdf2_salt: pbkdf2_salt.to_vec(),
            master_key,
        }
    }
}

/// Resolve a `RawNoteEntry` from CouchDB into a fully decoded `NoteEntry`.
///
/// If E2EE is enabled (path starts with `/\:`), decrypts the metadata to
/// extract the real path, timestamps, and children list. Also decrypts the
/// eden field if it contains an encrypted sentinel key.
pub fn resolve_note(
    raw: &RawNoteEntry,
    e2ee: Option<&E2EEContext>,
    change_deleted: Option<bool>,
) -> anyhow::Result<NoteEntry> {
    // Deletion can come from the changes feed (ChangeResult.deleted) or the
    // document body (_deleted). Either source is authoritative.
    let deleted = change_deleted.unwrap_or(false) || raw.is_deleted();

    if raw.path.starts_with(ENCRYPTED_META_PREFIX) {
        let ctx = e2ee
            .ok_or_else(|| anyhow::anyhow!("document is encrypted but no E2EE context provided"))?;
        let meta = crypto::decrypt_meta(&raw.path, &ctx.master_key, &ctx.passphrase)?;

        // Older plugin versions may not include children in the encrypted meta.
        let children = if meta.children.is_empty() && !raw.children.is_empty() {
            raw.children.clone()
        } else {
            meta.children
        };

        // When E2EE is enabled, the entire eden object is encrypted as a
        // single JSON blob under a sentinel key. Decrypt it back into the
        // original chunk map so reassemble() can look up chunks by ID.
        let eden = decrypt_eden(&raw.eden, &ctx.master_key, &ctx.passphrase)?;

        Ok(NoteEntry {
            id: raw._id.clone(),
            rev: raw._rev.clone(),
            path: meta.path,
            ctime: meta.ctime,
            mtime: meta.mtime,
            size: meta.size,
            children,
            eden,
            deleted,
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
            deleted,
            is_binary: raw.is_binary(),
        })
    }
}

/// Decrypt the eden field if it contains an encrypted sentinel key.
///
/// When E2EE is enabled, the plugin encrypts the entire eden object
/// (`JSON.stringify(eden)`) into a single blob stored under a sentinel key
/// (`h:++encrypted-hkdf` or `h:++encrypted`). This function detects the
/// sentinel, decrypts the blob, and parses it back into the original chunk map.
fn decrypt_eden(
    eden: &HashMap<String, EdenChunk>,
    master_key: &[u8; 32],
    passphrase: &str,
) -> anyhow::Result<HashMap<String, EdenChunk>> {
    let sentinel_data = eden
        .get(EDEN_ENCRYPTED_KEY_HKDF)
        .or_else(|| eden.get(EDEN_ENCRYPTED_KEY));

    let Some(sentinel) = sentinel_data else {
        // No sentinel key — eden is not encrypted (or empty).
        return Ok(eden.clone());
    };

    let json_str = crypto::decrypt_string(&sentinel.data, master_key, passphrase)?;
    let decrypted: HashMap<String, EdenChunk> = serde_json::from_str(&json_str)?;
    Ok(decrypted)
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
    e2ee: Option<&E2EEContext>,
) -> anyhow::Result<Vec<u8>> {
    if entry.children.is_empty() {
        return Ok(vec![]);
    }

    // Separate eden chunks from those needing a fetch.
    let mut chunk_data: Vec<Option<String>> = vec![None; entry.children.len()];
    let mut fetch_ids: Vec<(usize, String)> = Vec::new();

    // Eden is already decrypted by resolve_note(), so chunk IDs can be
    // looked up directly regardless of E2EE mode.
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

        // Decrypt if encrypted, using the cached master key.
        let decoded_data = if let Some(ctx) = e2ee {
            if raw_data.starts_with("%=") || raw_data.starts_with("%$") {
                crypto::decrypt_leaf_data(&raw_data, &ctx.master_key, &ctx.passphrase)?
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
