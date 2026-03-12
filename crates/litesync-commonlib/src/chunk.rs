use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

use crate::couchdb::CouchDBClient;
use crate::crypto;
use crate::path;
use std::collections::HashMap;

use crate::doc::{
    EdenChunk, EntryLeaf, NoteEntry, RawNoteEntry, ENCRYPTED_META_PREFIX,
    EDEN_ENCRYPTED_KEY, EDEN_ENCRYPTED_KEY_HKDF, PREFIX_CHUNK, PREFIX_ENCRYPTED_CHUNK,
    TYPE_LEAF,
};

/// Encryption context for decrypting E2EE-protected data.
///
/// The master key is derived once from the passphrase and PBKDF2 salt,
/// avoiding repeated PBKDF2 (310k iterations) per chunk.
#[derive(Clone)]
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
    // Deletion can come from:
    // 1. The changes feed (ChangeResult.deleted) — CouchDB-level hard delete
    // 2. The document body (_deleted) — CouchDB tombstone flag
    // 3. The document body (deleted: true) — Obsidian plugin soft-delete
    // Any source is authoritative.
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
    // Text files: chunks are raw text strings → UTF-8 bytes directly.
    // Binary files: chunks are base64 strings → decode to bytes.
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

        if entry.is_binary {
            // Binary: chunk data is base64-encoded
            let bytes = BASE64.decode(&decoded_data)?;
            result.extend_from_slice(&bytes);
        } else {
            // Text: chunk data is raw text
            result.extend_from_slice(decoded_data.as_bytes());
        }
    }

    Ok(result)
}

// =========================================================================
// Phase 2: Write path (chunk splitting, ID generation, disassembly)
// =========================================================================

// --- Passphrase hashing (MurmurHash3 + FNV-1a) ---
// Replicates the `fallbackMixedHashEach` from octagonal-wheels/hash/purejs.

const SALT_OF_ID: &str = "a83hrf7f\u{0003}y7sa8g31";
const EPOCH_FNV1A: u32 = 2_166_136_261;
const MURMUR_C1: u32 = 0xcc9e_2d51;
const MURMUR_C2: u32 = 0x1b87_3593;
const MURMUR_N: u32 = 0xe654_6b64;

/// Replicate JS `Math.imul(a, b)` — 32-bit truncating multiply.
fn imul(a: u32, b: u32) -> u32 {
    a.wrapping_mul(b)
}

/// Replicate the TS `mixedHash(str, seed, fnv1aHash)` function.
///
/// Processes each UTF-16 code unit of the input string through both
/// MurmurHash3 and FNV-1a, matching the JS `.charCodeAt(i)` semantics.
fn mixed_hash(input: &str, seed: u32, fnv1a_init: u32) -> (u32, u32) {
    let mut h1 = seed;
    let mut fnv = fnv1a_init;
    let mut len: u32 = 0;

    // JS iterates by UTF-16 code units via str.charCodeAt(i)
    for ch in input.chars() {
        let mut buf = [0u16; 2];
        let code_units = ch.encode_utf16(&mut buf);
        for &mut cu in code_units {
            let k1_init = cu as u32;

            // FNV-1a
            fnv ^= k1_init;
            fnv = imul(fnv, 0x0100_0193);

            // MurmurHash3 inner loop
            let mut k1 = imul(k1_init, MURMUR_C1);
            k1 = k1.rotate_left(15);
            k1 = imul(k1, MURMUR_C2);
            h1 ^= k1;
            h1 = h1.rotate_left(13);
            h1 = h1.wrapping_mul(5).wrapping_add(MURMUR_N);

            len += 1;
        }
    }

    // MurmurHash3 finalization
    h1 ^= len;
    h1 ^= h1 >> 16;
    h1 = imul(h1, 0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = imul(h1, 0xc2b2_ae35);
    h1 ^= h1 >> 16;

    (h1, fnv)
}

/// Replicate the TS `fallbackMixedHashEach(src)` function.
///
/// Returns the concatenation of MurmurHash3 and FNV-1a results in base-36.
fn fallback_mixed_hash_each(src: &str) -> String {
    // TS: mixedHash(`${src.length}${src}`, 1, epochFNV1a)
    // src.length is the UTF-16 code unit count
    let utf16_len: usize = src.chars().map(|c| c.len_utf16()).sum();
    let input = format!("{}{}", utf16_len, src);
    let (m, f) = mixed_hash(&input, 1, EPOCH_FNV1A);
    format!("{}{}", u32_to_base36(m), u32_to_base36(f))
}

fn u32_to_base36(n: u32) -> String {
    u64_to_base36(n as u64)
}

/// Compute the hashed passphrase for chunk ID generation.
///
/// Replicates `HashManagerCore.applyOptions` from the TS LiveSync plugin:
/// 1. Truncate passphrase to 75% length (UTF-16 code units)
/// 2. Prepend `SALT_OF_ID`
/// 3. Hash with MurmurHash3 + FNV-1a (`fallbackMixedHashEach`)
fn hash_passphrase_for_chunks(passphrase: &str) -> String {
    let total_utf16_len: usize = passphrase.chars().map(|c| c.len_utf16()).sum();
    let using_letters = (total_utf16_len / 4) * 3;

    // Take first `using_letters` UTF-16 code units worth of chars
    let mut taken = 0;
    let truncated: String = passphrase
        .chars()
        .take_while(|c| {
            if taken >= using_letters {
                return false;
            }
            taken += c.len_utf16();
            taken <= using_letters
        })
        .collect();

    let salted = format!("{}{}", SALT_OF_ID, truncated);
    fallback_mixed_hash_each(&salted)
}

/// Compute a content-addressed chunk ID using xxhash64.
///
/// Replicates the LiveSync `XXHash64HashManager.computeHash` algorithm:
/// - With passphrase: `h64("{piece}-{hashedPassphrase}-{piece.utf16_len}")` in base-36
/// - Without passphrase: `h64("{piece}-{piece.utf16_len}")` in base-36
///
/// Where `hashedPassphrase` is MurmurHash3+FNV-1a of `SALT_OF_ID + passphrase[0..75%]`.
/// The `piece_utf16_len` uses UTF-16 code unit count to match JS `piece.length`.
///
/// The returned ID uses the `h:+` prefix when E2EE is enabled (passphrase provided),
/// or the `h:` prefix otherwise, matching the TS plugin's `HashManagerCore.computeHash`
/// behavior where encrypted hashes include a `"+"` discriminator.
pub fn chunk_id(piece: &str, passphrase: Option<&str>) -> String {
    let piece_utf16_len: usize = piece.chars().map(|c| c.len_utf16()).sum();

    let (prefix, hash_input) = if let Some(pp) = passphrase {
        let hashed_pp = hash_passphrase_for_chunks(pp);
        (PREFIX_ENCRYPTED_CHUNK, format!("{}-{}-{}", piece, hashed_pp, piece_utf16_len))
    } else {
        (PREFIX_CHUNK, format!("{}-{}", piece, piece_utf16_len))
    };

    let hash = xxhash_rust::xxh64::xxh64(hash_input.as_bytes(), 0);
    format!("{}{}", prefix, u64_to_base36(hash))
}

fn u64_to_base36(mut n: u64) -> String {
    if n == 0 {
        return "0".to_string();
    }
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut buf = Vec::new();
    while n > 0 {
        buf.push(DIGITS[(n % 36) as usize]);
        n /= 36;
    }
    buf.reverse();
    String::from_utf8(buf).unwrap()
}

/// Split text content into raw text chunks using newline-aware splitting.
///
/// Replicates the LiveSync `splitPieces2V2` text path:
/// 1. Split by newline delimiter with minimum chunk length
/// 2. Cap each piece at `piece_size` characters (UTF-16 code units to match JS)
///
/// Each yielded piece is a raw text string (NOT base64-encoded), matching
/// the TS plugin's behavior for text files.
pub fn split_text(content: &str, piece_size: usize, minimum_chunk_size: usize) -> Vec<String> {
    if content.is_empty() {
        return vec![];
    }

    // Adaptive minimum: grow until pieces count <= MAX_ITEMS
    // Uses UTF-16 code unit count to match JS `text.length`
    let max_items = 100;
    let content_utf16_len: usize = content.chars().map(|c| c.len_utf16()).sum();
    let mut min_size = minimum_chunk_size;
    while content_utf16_len / min_size > max_items && min_size < content_utf16_len {
        min_size += minimum_chunk_size;
    }

    // Phase 1: split by newline with minimum chunk length (UTF-16 code units)
    //
    // Replicates TS `splitByDelimiterWithMinLength(source, "\n", minSize)`:
    //   - Find each "\n" individually via indexOf("\n", prev)
    //   - Append everything from prev up to and including the "\n" to buf
    //   - If buf.length > minimumChunkLength (strictly greater), yield buf
    //   - After exhausting source, yield any remaining buf
    let mut segments = Vec::new();
    let mut buf = String::new();
    let mut buf_utf16_len: usize = 0;

    // We process the content as a single source string, finding each '\n' one at a time
    let bytes = content.as_bytes();
    let mut prev = 0; // byte offset of current unprocessed start

    loop {
        // Find the next '\n' starting from prev
        let nl_pos = bytes[prev..].iter().position(|&b| b == b'\n');
        match nl_pos {
            Some(rel_pos) => {
                // Absolute byte position of the '\n'
                let abs_pos = prev + rel_pos;
                // Slice from prev up to and including the '\n'
                let slice = &content[prev..abs_pos + 1];
                buf.push_str(slice);
                buf_utf16_len += slice.chars().map(|c| c.len_utf16()).sum::<usize>();
                prev = abs_pos + 1;

                // TS uses strictly greater than: `if (buf.length > minimumChunkLength)`
                if buf_utf16_len > min_size {
                    segments.push(std::mem::take(&mut buf));
                    buf_utf16_len = 0;
                }
            }
            None => {
                // No more newlines — append remainder to buf
                if prev < content.len() {
                    buf.push_str(&content[prev..]);
                }
                break;
            }
        }
    }

    if !buf.is_empty() {
        segments.push(buf);
    }

    // Phase 2: cap each segment at piece_size (UTF-16 code units)
    let mut pieces = Vec::new();
    for seg in &segments {
        let mut taken_utf16: usize = 0;
        let mut piece_start = 0;

        for (i, ch) in seg.char_indices() {
            taken_utf16 += ch.len_utf16();
            if taken_utf16 >= piece_size {
                let end = i + ch.len_utf8();
                pieces.push(seg[piece_start..end].to_string());
                piece_start = end;
                taken_utf16 = 0;
            }
        }
        if piece_start < seg.len() {
            pieces.push(seg[piece_start..].to_string());
        }
    }

    pieces
}

/// Split binary content into base64-encoded chunks.
///
/// Replicates the LiveSync `splitPieces2V2` binary path:
/// 1. Compute dynamic minimum chunk size from file size
/// 2. Find delimiter boundaries (null byte, `/` for PDF, `,` for JSON)
/// 3. Cap each piece at `piece_size` bytes
pub fn split_binary(content: &[u8], piece_size: usize, filename: &str) -> Vec<String> {
    if content.is_empty() {
        return vec![];
    }

    let delimiter: u8 = if filename.ends_with(".pdf") {
        b'/'
    } else if filename.ends_with(".json") {
        b','
    } else {
        0 // null byte
    };

    let can_be_small = filename.ends_with(".json");

    // Dynamic minimum chunk size based on file size (replicates TS logic)
    let clamp_min: usize = if can_be_small { 100 } else { 100_000 };
    let clamp_max: usize = 100_000_000;
    let clamped_size = content.len().max(clamp_min).min(clamp_max);
    let mut step = 1u32;
    let mut w = clamped_size as f64;
    while w > 10.0 {
        w /= 12.5;
        step += 1;
    }
    let minimum_chunk_size = 10_usize.pow(step - 1);

    let size = content.len();
    let mut i = 0;
    let mut pieces = Vec::new();

    while i < size {
        let find_start = i + minimum_chunk_size;
        let default_split_end = (i + piece_size).min(size);

        let split_end = if find_start < size {
            // Replicate TS: buf.indexOf(delimiter, findStart) searches the
            // ENTIRE remaining buffer, not just up to defaultSplitEnd.
            // Only if the delimiter is not found anywhere do we fall back to newline.
            let delim_pos = content[find_start..].iter().position(|&b| b == delimiter)
                .map(|rel| find_start + rel);

            let found_pos = if delim_pos.is_some() {
                // Delimiter exists somewhere — use it (will be capped below)
                delim_pos
            } else {
                // Delimiter not found anywhere — fall back to newline search
                // (also searches entire remaining buffer)
                content[find_start..].iter().position(|&b| b == b'\n')
                    .map(|rel| find_start + rel)
            };

            match found_pos {
                Some(pos) => pos.min(default_split_end),
                None => default_split_end,
            }
        } else {
            default_split_end
        };

        pieces.push(BASE64.encode(&content[i..split_end]));
        i = split_end;
    }

    pieces
}

/// Result of disassembling file content into chunks.
pub struct DisassembleResult {
    /// Chunk documents to write to CouchDB.
    pub chunks: Vec<EntryLeaf>,
    /// Ordered list of chunk IDs (for the parent document's `children` field).
    pub children: Vec<String>,
}

/// Split file content into chunks and generate chunk documents.
///
/// This is the write-path counterpart of `reassemble()`.
///
/// Text files produce raw text chunks; binary files produce base64 chunks.
/// If E2EE is enabled, each chunk's data is encrypted before storage.
/// The returned `children` list contains the chunk IDs in order.
///
/// `min_chunk_size` controls the minimum text chunk size (default: 20 in the
/// Obsidian plugin). This value is fetched from the remote milestone document's
/// `minimumChunkSize` tweak.
pub fn disassemble(
    content: &[u8],
    filename: &str,
    piece_size: usize,
    min_chunk_size: usize,
    e2ee: Option<&E2EEContext>,
) -> anyhow::Result<DisassembleResult> {
    let passphrase_for_hash = e2ee.map(|ctx| ctx.passphrase.as_str());

    // Text files: raw text pieces; Binary files: base64 pieces
    // Use should_split_as_plain_text (md, txt, canvas) — NOT is_plain_text —
    // to match the TS plugin's shouldSplitAsPlainText() split decision.
    // is_plain_text covers more extensions (css, js, html, svg, csv, xml) and
    // is used elsewhere for doc type determination, not for splitting.
    let is_text = path::should_split_as_plain_text(filename);
    let pieces = if is_text {
        let text = std::str::from_utf8(content)
            .map_err(|e| anyhow::anyhow!("invalid UTF-8 for text file: {e}"))?;
        split_text(text, piece_size, min_chunk_size)
    } else {
        split_binary(content, piece_size, filename)
    };

    let mut chunks = Vec::with_capacity(pieces.len());
    let mut children = Vec::with_capacity(pieces.len());
    let mut seen_ids: HashMap<String, usize> = HashMap::new();

    for piece in &pieces {
        let id = chunk_id(piece, passphrase_for_hash);

        children.push(id.clone());

        // Content-addressed dedup: skip if we already created this chunk
        if seen_ids.contains_key(&id) {
            continue;
        }
        seen_ids.insert(id.clone(), chunks.len());

        // Encrypt chunk data if E2EE is enabled
        let data = if let Some(ctx) = e2ee {
            crypto::encrypt_leaf_data_for_write(piece, &ctx.master_key)?
        } else {
            piece.clone()
        };

        chunks.push(EntryLeaf {
            _id: id,
            _rev: None,
            type_: TYPE_LEAF.to_string(),
            data,
            is_corrupted: None,
        });
    }

    Ok(DisassembleResult { chunks, children })
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
            deleted: None,
            data: None,
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

    #[test]
    fn test_resolve_note_soft_deleted_from_body() {
        // Obsidian plugin soft-delete: body `deleted: true` (not `_deleted`)
        let mut raw = make_raw("x.md", TYPE_NEWNOTE);
        raw.deleted = Some(true);
        raw.children = vec![];
        raw.size = 0;
        raw.data = Some("".into());
        let note = resolve_note(&raw, None, Some(false)).unwrap();
        assert!(note.deleted);
    }

    #[test]
    fn test_resolve_note_soft_deleted_not_hard_deleted() {
        // Soft-deleted doc is NOT a CouchDB tombstone — change_deleted is None/false
        let mut raw = make_raw("x.md", TYPE_NEWNOTE);
        raw.deleted = Some(true);
        let note = resolve_note(&raw, None, None).unwrap();
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

    // =====================================================================
    // Phase 2: chunk_id
    // =====================================================================

    #[test]
    fn test_chunk_id_without_passphrase() {
        let piece = "SGVsbG8="; // base64 "Hello"
        let id = chunk_id(piece, None);
        assert!(id.starts_with("h:"));
        // Deterministic
        assert_eq!(id, chunk_id(piece, None));
    }

    #[test]
    fn test_chunk_id_with_passphrase() {
        let piece = "SGVsbG8=";
        let id = chunk_id(piece, Some("my-passphrase"));
        assert!(id.starts_with("h:+"), "E2EE chunk ID should start with 'h:+', got: {id}");
        // Different from without passphrase
        assert_ne!(id, chunk_id(piece, None));
    }

    #[test]
    fn test_chunk_id_different_content_different_id() {
        let id1 = chunk_id("SGVsbG8=", None);
        let id2 = chunk_id("V29ybGQ=", None);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_chunk_id_same_content_same_id() {
        // Content-addressed: same content → same ID
        let id1 = chunk_id("SGVsbG8=", Some("pp"));
        let id2 = chunk_id("SGVsbG8=", Some("pp"));
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_chunk_id_different_passphrase_different_id() {
        let piece = "SGVsbG8=";
        let id1 = chunk_id(piece, Some("completely-different-alpha"));
        let id2 = chunk_id(piece, Some("something-else-entirely-beta"));
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_chunk_id_prefix_matches_ts_plugin() {
        // TS plugin: HashManagerCore.computeHash returns "+" + hash when
        // encryption is active. The caller prepends "h:", giving "h:+hash".
        // Without encryption, the result is "h:hash" (no "+").
        let piece = "test content for prefix check";

        let plain_id = chunk_id(piece, None);
        assert!(plain_id.starts_with("h:"), "plain chunk ID should start with 'h:'");
        assert!(!plain_id.starts_with("h:+"), "plain chunk ID must NOT have '+' discriminator");

        let encrypted_id = chunk_id(piece, Some("my-passphrase"));
        assert!(encrypted_id.starts_with("h:+"), "encrypted chunk ID should start with 'h:+'");

        // The hash portion (after prefix) should be different since the
        // passphrase changes the hash input
        let plain_hash = &plain_id[2..];
        let encrypted_hash = &encrypted_id[3..];
        assert_ne!(plain_hash, encrypted_hash);
    }

    // =====================================================================
    // Phase 2: u64_to_base36
    // =====================================================================

    #[test]
    fn test_u64_to_base36_zero() {
        assert_eq!(u64_to_base36(0), "0");
    }

    #[test]
    fn test_u64_to_base36_small() {
        assert_eq!(u64_to_base36(35), "z");
        assert_eq!(u64_to_base36(36), "10");
        assert_eq!(u64_to_base36(255), "73");
    }

    #[test]
    fn test_u64_to_base36_matches_js() {
        // JS: BigInt(1000000).toString(36) === "lfls"
        assert_eq!(u64_to_base36(1_000_000), "lfls");
        // JS: BigInt(0xdeadbeef).toString(36) === "1ps9wxb"
        assert_eq!(u64_to_base36(0xDEAD_BEEF), "1ps9wxb");
    }

    // =====================================================================
    // Phase 2: split_text
    // =====================================================================

    #[test]
    fn test_split_text_empty() {
        assert!(split_text("", 1000, 100).is_empty());
    }

    #[test]
    fn test_split_text_single_line() {
        let pieces = split_text("Hello World", 1000, 100);
        assert_eq!(pieces.len(), 1);
        // Text chunks are raw text, NOT base64
        assert_eq!(pieces[0], "Hello World");
    }

    #[test]
    fn test_split_text_multiline_under_minimum() {
        // Lines shorter than minimum → merged into one chunk
        let text = "line1\nline2\nline3\n";
        let pieces = split_text(text, 1000, 100);
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0], text);
    }

    #[test]
    fn test_split_text_multiline_exceeds_minimum() {
        // Each "line" is 50+ chars; min=40 → should split at newlines
        let line = "a".repeat(50);
        let text = format!("{line}\n{line}\n{line}\n");
        let pieces = split_text(&text, 1000, 40);
        assert!(pieces.len() > 1, "expected multiple pieces, got {}", pieces.len());
        // Concatenation should recover original
        let reconstructed: String = pieces.join("");
        assert_eq!(reconstructed, text);
    }

    #[test]
    fn test_split_text_piece_size_cap() {
        // Very small piece_size forces splitting even within a segment
        let text = "Hello World, this is a longer line\n";
        let pieces = split_text(text, 10, 5);
        assert!(pieces.len() > 1);
        let reconstructed: String = pieces.join("");
        assert_eq!(reconstructed, text);
    }

    #[test]
    fn test_split_text_unicode_safe() {
        // Must not split in the middle of a multi-byte character
        // piece_size is in UTF-16 code units (matching JS)
        let text = "한글한글한글한글한글";
        let pieces = split_text(text, 5, 3);
        // Each piece must be valid UTF-8
        for piece in &pieces {
            assert!(piece.is_ascii() || !piece.is_empty(), "piece should be valid text");
        }
        let reconstructed: String = pieces.join("");
        assert_eq!(reconstructed, text);
    }

    #[test]
    fn test_split_text_roundtrip_reassembly() {
        let text = "# Header\n\nParagraph one with some content.\n\n## Subheader\n\nMore text here.\n";
        let pieces = split_text(text, 1000, 20);
        let reconstructed: String = pieces.join("");
        assert_eq!(reconstructed, text);
    }

    // =====================================================================
    // Phase 2: split_binary
    // =====================================================================

    #[test]
    fn test_split_binary_empty() {
        assert!(split_binary(&[], 1000, "test.png").is_empty());
    }

    #[test]
    fn test_split_binary_small() {
        let data = vec![0u8; 50];
        let pieces = split_binary(&data, 1000, "test.png");
        assert_eq!(pieces.len(), 1);
        assert_eq!(BASE64.decode(&pieces[0]).unwrap(), data);
    }

    #[test]
    fn test_split_binary_roundtrip() {
        // Large enough to trigger splitting
        let data: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
        let pieces = split_binary(&data, 50_000, "test.bin");
        assert!(pieces.len() > 1);
        let reconstructed: Vec<u8> = pieces.iter()
            .flat_map(|p| BASE64.decode(p).unwrap())
            .collect();
        assert_eq!(reconstructed, data);
    }

    #[test]
    fn test_split_binary_json_small_minimum() {
        // JSON files allow smaller chunks (min 100 vs 100k for other types)
        let data = b",item1,item2,item3,item4,";
        let pieces = split_binary(data, 1000, "data.json");
        // Roundtrip is what matters
        let decoded: Vec<u8> = pieces.iter()
            .flat_map(|p| BASE64.decode(p).unwrap())
            .collect();
        assert_eq!(decoded, data);
    }

    // =====================================================================
    // H3/H4/H5 regression tests: TS compatibility for chunk splitting
    // =====================================================================

    #[test]
    fn test_split_text_h3_strict_greater_than() {
        // H3: TS uses `buf.length > minimumChunkLength` (strictly greater).
        // With min_size=5 and content "abcde\nfgh", the buffer after the \n
        // has length 6 ("abcde\n"), which is > 5, so it should split.
        // With >=, a buffer of exactly 5 would also split; with >, it should not.
        //
        // Content: "abcd\nefgh" — buf after first \n = "abcd\n" = 5 chars
        // With > 5: does NOT split (5 is not > 5), yields one segment
        // With >= 5: WOULD split, yielding two segments
        let pieces = split_text("abcd\nefgh", 1000, 5);
        // "abcd\n" has length 5, which is NOT > 5, so no split occurs.
        // The whole string should be one segment.
        assert_eq!(pieces.len(), 1, "buf of exactly min_size should NOT split (> not >=)");
        assert_eq!(pieces[0], "abcd\nefgh");

        // One more char makes it > 5 → should split
        let pieces2 = split_text("abcde\nfgh", 1000, 5);
        // "abcde\n" has length 6, which IS > 5 → splits
        assert_eq!(pieces2.len(), 2);
        assert_eq!(pieces2[0], "abcde\n");
        assert_eq!(pieces2[1], "fgh");
    }

    #[test]
    fn test_split_text_h4_consecutive_newlines_individual() {
        // H4: TS processes each \n individually via indexOf("\n", prev).
        // Each \n is a potential split boundary.
        //
        // Content: "a\n\n\nb" with min_size=2
        // TS behavior step-by-step (splitByDelimiterWithMinLength):
        //   prev=0, find \n at 1: buf = "a\n" (len=2, NOT > 2) → no yield
        //   prev=2, find \n at 2: buf = "a\n\n" (len=3, IS > 2) → yield "a\n\n"
        //   prev=3, find \n at 3: buf = "\n" (len=1, NOT > 2) → no yield
        //   no more \n: buf += "b" → buf = "\nb" → yield "\nb"
        let pieces = split_text("a\n\n\nb", 1000, 2);
        assert_eq!(pieces, vec!["a\n\n", "\nb"]);
    }

    #[test]
    fn test_split_text_h4_many_consecutive_newlines() {
        // Verify each \n is checked individually with a larger example.
        // "xx\n\n\n\nyy" with min_size=3
        // prev=0, find \n at 2: buf = "xx\n" (len=3, NOT > 3) → no yield
        // prev=3, find \n at 3: buf = "xx\n\n" (len=4, IS > 3) → yield "xx\n\n"
        // prev=4, find \n at 4: buf = "\n" (len=1, NOT > 3)
        // prev=5, find \n at 5: buf = "\n\n" (len=2, NOT > 3)
        // no more \n: buf += "yy" → buf = "\n\nyy" → yield "\n\nyy"
        let pieces = split_text("xx\n\n\n\nyy", 1000, 3);
        assert_eq!(pieces, vec!["xx\n\n", "\n\nyy"]);
    }

    #[test]
    fn test_split_text_h4_all_newlines() {
        // Edge case: content is entirely newlines
        // "\n\n\n\n" with min_size=2
        // prev=0, \n at 0: buf="\n" (1, not > 2)
        // prev=1, \n at 1: buf="\n\n" (2, not > 2)
        // prev=2, \n at 2: buf="\n\n\n" (3, > 2) → yield "\n\n\n"
        // prev=3, \n at 3: buf="\n" (1, not > 2)
        // no more \n, no remaining content → yield "\n"
        let pieces = split_text("\n\n\n\n", 1000, 2);
        assert_eq!(pieces, vec!["\n\n\n", "\n"]);
    }

    #[test]
    fn test_split_text_h3_h4_combined_roundtrip() {
        // Ensure all split_text results concatenate back to original
        let inputs = vec![
            ("a\n\n\nb", 2),
            ("hello\n\n\n\nworld\n", 5),
            ("\n\n\n\n\n", 3),
            ("no-newlines-here", 5),
            ("x\ny\nz\n", 1),
        ];
        for (content, min_size) in inputs {
            let pieces = split_text(content, 1000, min_size);
            let reconstructed: String = pieces.join("");
            assert_eq!(reconstructed, content, "roundtrip failed for {:?} min_size={}", content, min_size);
        }
    }

    #[test]
    fn test_split_binary_h5_delimiter_beyond_default_split_end() {
        // H5: When delimiter exists beyond defaultSplitEnd, TS does NOT fall
        // back to newline search — it just uses defaultSplitEnd.
        //
        // Setup: content where a newline exists within [findStart, defaultSplitEnd)
        // but the delimiter (null byte) only exists BEYOND defaultSplitEnd.
        // The old buggy code would find the newline; correct code should NOT.
        //
        // For a .json file with small data, minimum_chunk_size = 100 (see formula).
        // For a generic binary, minimum_chunk_size = 100_000 which is hard to test.
        // Use .json so minimum is 100.
        //
        // piece_size=200, so defaultSplitEnd = 0 + 200 = 200
        // findStart = 0 + 100 = 100
        // Place a \n at position 120, and a comma at position 250.
        //
        // TS: searches entire buffer for comma from pos 100. Finds it at 250.
        //     Since 250 > -1, does NOT fall back to newline.
        //     splitEnd = min(250, 200) = 200.
        // Buggy Rust: searches [100,200) for comma. Not found. Falls back to
        //     newline search in [100,200). Finds \n at 120. splitEnd = 120.
        let mut data = vec![b'A'; 300];
        data[120] = b'\n'; // newline within search window
        data[250] = b','; // comma (json delimiter) beyond defaultSplitEnd

        let pieces = split_binary(&data, 200, "data.json");
        let decoded: Vec<u8> = pieces.iter()
            .flat_map(|p| BASE64.decode(p).unwrap())
            .collect();
        assert_eq!(decoded, data, "roundtrip must hold");

        // First chunk should be 200 bytes (defaultSplitEnd), NOT 120 bytes (newline)
        let first_chunk = BASE64.decode(&pieces[0]).unwrap();
        assert_eq!(first_chunk.len(), 200,
            "delimiter exists beyond window, so should NOT fall back to newline; \
             expected first chunk of 200 bytes, got {}", first_chunk.len());
    }

    #[test]
    fn test_split_binary_h5_delimiter_within_window_still_works() {
        // When delimiter IS within the window, it should still be used.
        // .json with piece_size=200, minimum=100.
        // Place comma at position 150 (within [100, 200)).
        let mut data = vec![b'A'; 300];
        data[150] = b',';

        let pieces = split_binary(&data, 200, "data.json");
        let decoded: Vec<u8> = pieces.iter()
            .flat_map(|p| BASE64.decode(p).unwrap())
            .collect();
        assert_eq!(decoded, data);

        // First chunk should be 150 bytes (split at the comma position)
        let first_chunk = BASE64.decode(&pieces[0]).unwrap();
        assert_eq!(first_chunk.len(), 150);
    }

    #[test]
    fn test_split_binary_h5_no_delimiter_anywhere_uses_newline() {
        // When delimiter is NOT found anywhere in remaining buffer,
        // TS falls back to newline. Place \n at 130, no commas at all.
        let mut data = vec![b'A'; 300];
        data[130] = b'\n';
        // No comma anywhere

        let pieces = split_binary(&data, 200, "data.json");
        let decoded: Vec<u8> = pieces.iter()
            .flat_map(|p| BASE64.decode(p).unwrap())
            .collect();
        assert_eq!(decoded, data);

        // First chunk should split at the newline (130 bytes)
        let first_chunk = BASE64.decode(&pieces[0]).unwrap();
        assert_eq!(first_chunk.len(), 130);
    }

    // =====================================================================
    // Phase 2: disassemble
    // =====================================================================

    #[test]
    fn test_disassemble_empty_content() {
        let result = disassemble(b"", "test.md", 1000, 20, None).unwrap();
        assert!(result.chunks.is_empty());
        assert!(result.children.is_empty());
    }

    #[test]
    fn test_disassemble_text_basic() {
        let content = b"# Hello\n\nWorld\n";
        let result = disassemble(content, "test.md", 1000, 20, None).unwrap();
        assert!(!result.chunks.is_empty());
        assert_eq!(result.chunks.len(), result.children.len());

        // All chunk IDs start with "h:" (plain, not encrypted "h:+")
        for child in &result.children {
            assert!(child.starts_with("h:"), "chunk ID should start with 'h:', got: {child}");
            assert!(!child.starts_with("h:+"), "non-E2EE chunk ID should NOT start with 'h:+', got: {child}");
        }

        // All chunks are leaf type
        for chunk in &result.chunks {
            assert_eq!(chunk.type_, "leaf");
            assert!(chunk._id.starts_with("h:"));
            assert!(!chunk._id.starts_with("h:+"), "non-E2EE chunk should NOT have 'h:+' prefix");
        }

        // Reassemble: text chunks are raw text, concatenate directly
        let reconstructed: String = result.children.iter()
            .map(|id| {
                let chunk = result.chunks.iter().find(|c| &c._id == id).unwrap();
                chunk.data.clone()
            })
            .collect();
        assert_eq!(reconstructed, std::str::from_utf8(content).unwrap());
    }

    #[test]
    fn test_disassemble_binary() {
        let content: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();
        let result = disassemble(&content, "image.png", 1000, 20, None).unwrap();
        assert!(!result.chunks.is_empty());

        let reconstructed: Vec<u8> = result.children.iter()
            .map(|id| {
                let chunk = result.chunks.iter().find(|c| &c._id == id).unwrap();
                BASE64.decode(&chunk.data).unwrap()
            })
            .flatten()
            .collect();
        assert_eq!(reconstructed, content);
    }

    #[test]
    fn test_disassemble_content_dedup() {
        // Repeated lines → same chunks should be deduped
        let content = "repeated line\nrepeated line\nrepeated line\n";
        let result = disassemble(content.as_bytes(), "test.md", 5, 20, None).unwrap();
        // children may have duplicate IDs, but chunks should be unique
        let unique_ids: std::collections::HashSet<&str> =
            result.chunks.iter().map(|c| c._id.as_str()).collect();
        assert_eq!(unique_ids.len(), result.chunks.len(), "chunks should have unique IDs");
    }

    #[test]
    fn test_disassemble_with_e2ee() {
        let ctx = test_ctx();
        let content = b"# Secret Note\n\nThis is encrypted.\n";
        let result = disassemble(content, "secret.md", 1000, 20, Some(&ctx)).unwrap();

        // All chunk IDs should use the encrypted prefix "h:+"
        for child in &result.children {
            assert!(child.starts_with("h:+"), "E2EE chunk ID should start with 'h:+', got: {child}");
        }

        // All chunk data should be encrypted (starts with %=)
        for chunk in &result.chunks {
            assert!(chunk.data.starts_with("%="), "chunk data should be encrypted");
            assert!(chunk._id.starts_with("h:+"), "E2EE chunk _id should start with 'h:+', got: {}", chunk._id);
        }

        // Decrypt and reassemble to verify roundtrip
        // Text chunks: after decryption, data is raw text (not base64)
        let reconstructed: String = result.children.iter()
            .map(|id| {
                let chunk = result.chunks.iter().find(|c| &c._id == id).unwrap();
                crypto::decrypt_leaf_data(
                    &chunk.data, &ctx.master_key, &ctx.passphrase,
                ).unwrap()
            })
            .collect();
        assert_eq!(reconstructed, std::str::from_utf8(content).unwrap());
    }

    #[test]
    fn test_disassemble_deterministic_ids() {
        // Same content + same passphrase → same chunk IDs
        let content = b"deterministic test";
        let r1 = disassemble(content, "test.md", 1000, 20, None).unwrap();
        let r2 = disassemble(content, "test.md", 1000, 20, None).unwrap();
        assert_eq!(r1.children, r2.children);
    }

    #[test]
    fn test_disassemble_css_js_html_use_binary_splitting() {
        // H5 fix: CSS, JS, HTML, SVG, CSV, XML must use binary splitting
        // (matching the TS plugin's shouldSplitAsPlainText), not text splitting.
        // Only md, txt, canvas use text splitting.
        let content = b"body { color: red; }\n.foo { display: block; }\n";

        for ext in &["css", "js", "html", "svg", "csv", "xml"] {
            let filename = format!("test.{ext}");
            let result = disassemble(content, &filename, 1000, 20, None).unwrap();
            assert!(!result.chunks.is_empty(), "{filename} should produce chunks");

            // Binary-split chunks are base64-encoded. Verify each chunk decodes
            // from base64 (text chunks would be raw text, not valid base64).
            for chunk in &result.chunks {
                assert!(
                    BASE64.decode(&chunk.data).is_ok(),
                    "{filename}: chunk data should be base64 (binary split), got raw text"
                );
            }

            // Roundtrip: decode base64 chunks and verify content matches
            let reconstructed: Vec<u8> = result.children.iter()
                .map(|id| {
                    let chunk = result.chunks.iter().find(|c| &c._id == id).unwrap();
                    BASE64.decode(&chunk.data).unwrap()
                })
                .flatten()
                .collect();
            assert_eq!(reconstructed, content, "{filename}: binary roundtrip failed");
        }
    }

    #[test]
    fn test_disassemble_md_txt_canvas_use_text_splitting() {
        // Counterpart: md, txt, canvas should still use text splitting.
        let content = b"# Hello World\n\nSome text.\n";

        for ext in &["md", "txt", "canvas"] {
            let filename = format!("test.{ext}");
            let result = disassemble(content, &filename, 1000, 20, None).unwrap();
            assert!(!result.chunks.is_empty(), "{filename} should produce chunks");

            // Text-split chunks are raw text, not base64.
            // Concatenation of raw chunk data should equal original content.
            let reconstructed: String = result.children.iter()
                .map(|id| {
                    let chunk = result.chunks.iter().find(|c| &c._id == id).unwrap();
                    chunk.data.clone()
                })
                .collect();
            assert_eq!(
                reconstructed,
                std::str::from_utf8(content).unwrap(),
                "{filename}: text roundtrip failed"
            );
        }
    }
}
