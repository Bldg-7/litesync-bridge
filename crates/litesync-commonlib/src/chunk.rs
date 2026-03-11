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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::{TYPE_PLAIN, TYPE_NEWNOTE};

    // =====================================================================
    // Test helpers
    // =====================================================================

    const TEST_PASSPHRASE: &str = "test-passphrase-for-unit-tests";
    const TEST_PBKDF2_SALT: [u8; 32] = [0xAA; 32];
    const TEST_IV: [u8; 12] = [0xBB; 12];
    const TEST_HKDF_SALT: [u8; 32] = [0xCC; 32];

    fn test_ctx() -> E2EEContext {
        E2EEContext::new(TEST_PASSPHRASE, &TEST_PBKDF2_SALT)
    }

    /// Encrypt plaintext in `%=` format using test fixtures.
    fn encrypt_hkdf(plaintext: &str, master_key: &[u8; 32]) -> String {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine;
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(&TEST_HKDF_SALT), master_key);
        let mut chunk_key = [0u8; 32];
        hk.expand(&[], &mut chunk_key).unwrap();

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&chunk_key));
        let ciphertext = cipher.encrypt(Nonce::from_slice(&TEST_IV), plaintext.as_bytes()).unwrap();

        let mut binary = Vec::new();
        binary.extend_from_slice(&TEST_IV);
        binary.extend_from_slice(&TEST_HKDF_SALT);
        binary.extend_from_slice(&ciphertext);

        format!("%={}", B64.encode(&binary))
    }

    fn make_raw(path: &str, type_: &str) -> RawNoteEntry {
        RawNoteEntry {
            _id: "doc-id".into(),
            _rev: Some("1-abc".into()),
            type_: type_.into(),
            path: path.into(),
            ctime: 100, mtime: 200, size: 50,
            children: vec!["h:c1".into(), "h:c2".into()],
            eden: HashMap::new(),
            _deleted: None,
        }
    }

    fn make_encrypted_path(master_key: &[u8; 32], meta_json: &str) -> String {
        let encrypted = encrypt_hkdf(meta_json, master_key);
        format!("/\\:{encrypted}")
    }

    // =====================================================================
    // E2EEContext
    // =====================================================================

    #[test]
    fn test_e2ee_context_caches_master_key() {
        let ctx = test_ctx();
        let expected = crypto::derive_master_key(TEST_PASSPHRASE, &TEST_PBKDF2_SALT);
        assert_eq!(ctx.master_key, expected);
        assert_eq!(ctx.passphrase, TEST_PASSPHRASE);
        assert_eq!(ctx.pbkdf2_salt, TEST_PBKDF2_SALT);
    }

    #[test]
    fn test_e2ee_context_deterministic() {
        let ctx1 = E2EEContext::new("pp", &[1u8; 32]);
        let ctx2 = E2EEContext::new("pp", &[1u8; 32]);
        assert_eq!(ctx1.master_key, ctx2.master_key);
    }

    // =====================================================================
    // resolve_note — non-encrypted
    // =====================================================================

    #[test]
    fn test_resolve_note_plain() {
        let raw = make_raw("notes/hello.md", TYPE_PLAIN);
        let note = resolve_note(&raw, None, None).unwrap();
        assert_eq!(note.id, "doc-id");
        assert_eq!(note.rev, Some("1-abc".into()));
        assert_eq!(note.path, "notes/hello.md");
        assert_eq!(note.ctime, 100);
        assert_eq!(note.mtime, 200);
        assert_eq!(note.size, 50);
        assert_eq!(note.children, vec!["h:c1", "h:c2"]);
        assert!(!note.deleted);
        assert!(!note.is_binary);
    }

    #[test]
    fn test_resolve_note_binary() {
        let raw = make_raw("image.png", TYPE_NEWNOTE);
        let note = resolve_note(&raw, None, None).unwrap();
        assert!(note.is_binary);
    }

    // =====================================================================
    // resolve_note — deletion
    // =====================================================================

    #[test]
    fn test_resolve_note_deleted_from_body() {
        let mut raw = make_raw("x.md", TYPE_PLAIN);
        raw._deleted = Some(true);
        let note = resolve_note(&raw, None, None).unwrap();
        assert!(note.deleted);
    }

    #[test]
    fn test_resolve_note_deleted_from_change_feed() {
        let raw = make_raw("x.md", TYPE_PLAIN);
        let note = resolve_note(&raw, None, Some(true)).unwrap();
        assert!(note.deleted);
    }

    #[test]
    fn test_resolve_note_not_deleted() {
        let raw = make_raw("x.md", TYPE_PLAIN);
        let note = resolve_note(&raw, None, Some(false)).unwrap();
        assert!(!note.deleted);
    }

    #[test]
    fn test_resolve_note_deleted_either_source() {
        // change_deleted=false but _deleted=true → deleted
        let mut raw = make_raw("x.md", TYPE_PLAIN);
        raw._deleted = Some(true);
        let note = resolve_note(&raw, None, Some(false)).unwrap();
        assert!(note.deleted);
    }

    // =====================================================================
    // resolve_note — encrypted metadata
    // =====================================================================

    #[test]
    fn test_resolve_note_encrypted() {
        let ctx = test_ctx();
        let meta_json = r#"{"path":"secret/note.md","mtime":9000,"ctime":8000,"size":123,"children":["h:x1","h:x2","h:x3"]}"#;
        let encrypted_path = make_encrypted_path(&ctx.master_key, meta_json);

        let mut raw = make_raw(&encrypted_path, TYPE_PLAIN);
        raw.ctime = 0; raw.mtime = 0; raw.size = 0; // zeroed when encrypted
        raw.children = vec![]; // may be empty in encrypted mode

        let note = resolve_note(&raw, Some(&ctx), None).unwrap();
        assert_eq!(note.path, "secret/note.md");
        assert_eq!(note.mtime, 9000);
        assert_eq!(note.ctime, 8000);
        assert_eq!(note.size, 123);
        assert_eq!(note.children, vec!["h:x1", "h:x2", "h:x3"]);
    }

    #[test]
    fn test_resolve_note_encrypted_children_fallback() {
        // Older plugin versions: encrypted meta has empty children,
        // raw.children has the real list.
        let ctx = test_ctx();
        let meta_json = r#"{"path":"old.md","mtime":1,"ctime":1,"size":1,"children":[]}"#;
        let encrypted_path = make_encrypted_path(&ctx.master_key, meta_json);

        let mut raw = make_raw(&encrypted_path, TYPE_PLAIN);
        raw.children = vec!["h:fallback1".into(), "h:fallback2".into()];

        let note = resolve_note(&raw, Some(&ctx), None).unwrap();
        assert_eq!(note.children, vec!["h:fallback1", "h:fallback2"]);
    }

    #[test]
    fn test_resolve_note_encrypted_no_context_fails() {
        let ctx = test_ctx();
        let meta_json = r#"{"path":"x.md","mtime":0,"ctime":0,"size":0}"#;
        let encrypted_path = make_encrypted_path(&ctx.master_key, meta_json);
        let raw = make_raw(&encrypted_path, TYPE_PLAIN);

        let result = resolve_note(&raw, None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no E2EE context"));
    }

    // =====================================================================
    // resolve_note — eden decryption
    // =====================================================================

    #[test]
    fn test_resolve_note_empty_eden() {
        let raw = make_raw("x.md", TYPE_PLAIN);
        let note = resolve_note(&raw, None, None).unwrap();
        assert!(note.eden.is_empty());
    }

    #[test]
    fn test_resolve_note_unencrypted_eden() {
        let mut raw = make_raw("x.md", TYPE_PLAIN);
        raw.eden.insert("h:inline1".into(), EdenChunk {
            data: "aW5saW5l".into(),
            epoch: 1,
        });
        let note = resolve_note(&raw, None, None).unwrap();
        assert_eq!(note.eden.len(), 1);
        assert_eq!(note.eden.get("h:inline1").unwrap().data, "aW5saW5l");
    }

    #[test]
    fn test_resolve_note_encrypted_eden_sentinel() {
        let ctx = test_ctx();

        // Build the decrypted eden content.
        let eden_json = r#"{"h:real1":{"data":"Y2h1bms=","epoch":1},"h:real2":{"data":"ZGF0YQ==","epoch":2}}"#;
        let encrypted_sentinel = encrypt_hkdf(eden_json, &ctx.master_key);

        // Build raw entry with encrypted metadata + encrypted eden.
        let meta_json = r#"{"path":"eden-test.md","mtime":1,"ctime":1,"size":1,"children":["h:real1","h:real2"]}"#;
        let encrypted_path = make_encrypted_path(&ctx.master_key, meta_json);

        let mut raw = make_raw(&encrypted_path, TYPE_PLAIN);
        raw.children = vec![];
        raw.eden = HashMap::new();
        raw.eden.insert(EDEN_ENCRYPTED_KEY_HKDF.into(), EdenChunk {
            data: encrypted_sentinel,
            epoch: 0,
        });

        let note = resolve_note(&raw, Some(&ctx), None).unwrap();
        assert_eq!(note.eden.len(), 2);
        assert_eq!(note.eden.get("h:real1").unwrap().data, "Y2h1bms=");
        assert_eq!(note.eden.get("h:real2").unwrap().data, "ZGF0YQ==");
        assert_eq!(note.eden.get("h:real2").unwrap().epoch, 2);
    }

    #[test]
    fn test_resolve_note_encrypted_eden_legacy_key() {
        // Uses EDEN_ENCRYPTED_KEY (without -hkdf) as fallback.
        let ctx = test_ctx();
        let eden_json = r#"{"h:legacy":{"data":"bGVn","epoch":1}}"#;
        let encrypted_sentinel = encrypt_hkdf(eden_json, &ctx.master_key);

        let meta_json = r#"{"path":"legacy.md","mtime":1,"ctime":1,"size":1,"children":["h:legacy"]}"#;
        let encrypted_path = make_encrypted_path(&ctx.master_key, meta_json);

        let mut raw = make_raw(&encrypted_path, TYPE_PLAIN);
        raw.children = vec![];
        raw.eden = HashMap::new();
        raw.eden.insert(EDEN_ENCRYPTED_KEY.into(), EdenChunk {
            data: encrypted_sentinel,
            epoch: 0,
        });

        let note = resolve_note(&raw, Some(&ctx), None).unwrap();
        assert_eq!(note.eden.len(), 1);
        assert_eq!(note.eden.get("h:legacy").unwrap().data, "bGVn");
    }
}
