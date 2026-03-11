use sha2::{Digest, Sha256};

use crate::doc::PREFIX_OBFUSCATED;

/// Convert a file path to a CouchDB document ID.
///
/// If `obfuscate_passphrase` is provided, the path is hashed using SHA-256
/// with a passphrase-derived key (iterated SHA-256).
pub fn path2id(path: &str, obfuscate_passphrase: Option<&str>) -> String {
    if path.starts_with(PREFIX_OBFUSCATED) {
        return path.to_string();
    }

    // Paths starting with "_" get a "/" prefix to avoid CouchDB reserved IDs.
    let normalized = if path.starts_with('_') {
        format!("/{path}")
    } else {
        path.to_string()
    };

    let Some(passphrase) = obfuscate_passphrase else {
        return normalized;
    };

    // Split prefix (e.g., "ps:" from "ps:some/path")
    let (prefix, body) = split_prefix(&normalized);
    if body.starts_with(PREFIX_OBFUSCATED) {
        return normalized;
    }

    let hashed_passphrase = hash_string_chain(passphrase);
    // TS path2id_base hashes `filename` (original path), not `x` (escaped).
    // The "/" prefix is only for non-obfuscated CouchDB reserved ID avoidance;
    // obfuscated IDs start with "f:" so no collision is possible.
    let id_hash = sha256_hex(&format!("{hashed_passphrase}:{path}"));

    format!("{prefix}{PREFIX_OBFUSCATED}{id_hash}")
}

/// Convert a CouchDB document ID back to a file path.
///
/// Returns `Err` if the ID is obfuscated (requires entry.path to resolve).
pub fn id2path(id: &str, entry_path: Option<&str>) -> anyhow::Result<String> {
    if let Some(entry_path) = entry_path {
        if !entry_path.starts_with(PREFIX_OBFUSCATED) {
            return id2path(entry_path, None);
        }
    }

    if id.starts_with(PREFIX_OBFUSCATED) {
        anyhow::bail!("cannot reverse obfuscated document ID without entry path");
    }

    let (prefix, body) = split_prefix(id);
    if body.starts_with(PREFIX_OBFUSCATED) {
        anyhow::bail!("cannot reverse obfuscated document ID without entry path");
    }

    // Remove leading "/" that was added for paths starting with "_".
    if let Some(stripped) = body.strip_prefix('/') {
        return Ok(stripped.to_string());
    }

    // Preserve prefix for non-underscore paths (e.g., "ps:notes/hello.md").
    Ok(format!("{prefix}{body}"))
}

/// Whether a file should be treated as plain text for chunk splitting.
pub fn is_plain_text(filename: &str) -> bool {
    matches!(
        filename.rsplit('.').next(),
        Some("md" | "txt" | "svg" | "html" | "csv" | "css" | "js" | "xml" | "canvas")
    )
}

/// Whether a file should use text-aware (newline-based) chunk splitting.
pub fn should_split_as_plain_text(filename: &str) -> bool {
    matches!(
        filename.rsplit('.').next(),
        Some("md" | "txt" | "canvas")
    )
}

/// Files that should be ignored by the sync engine.
pub fn should_be_ignored(filename: &str) -> bool {
    matches!(
        filename,
        "redflag.md" | "redflag2.md" | "redflag3.md" | "flag_rebuild.md" | "flag_fetch.md"
    ) || filename.starts_with("livesync_log_")
        || filename.starts_with("LIVESYNC_LOG_")
}

/// Strip all prefixes (e.g., "ps:" or "i:") from a path.
pub fn strip_all_prefixes(path: &str) -> &str {
    match path.split_once(':') {
        Some((_, rest)) => strip_all_prefixes(rest),
        None => path,
    }
}

// --- Internal helpers ---

fn split_prefix(path: &str) -> (&str, &str) {
    match path.find(':') {
        Some(pos) => (&path[..=pos], &path[pos + 1..]),
        None => ("", path),
    }
}

/// SHA-256 hash of passphrase for path obfuscation.
///
/// The original TypeScript `_hashString` has a bug where the stretching loop
/// rehashes the original key (`buff`) instead of the previous digest, making
/// the loop a no-op. The result is always `SHA-256(key)` regardless of length.
/// We must replicate this behavior for compatibility with existing documents.
fn hash_string_chain(key: &str) -> String {
    sha256_hex(key)
}

fn sha256_hex(input: &str) -> String {
    hex::encode(sha256_bytes(input.as_bytes()))
}

fn sha256_bytes(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // Helper: compute expected obfuscated ID the way TS does it.
    //
    // TS path2id_base (line 121-123):
    //   hashedPassphrase = SHA-256(passphrase)   // _hashString loop is no-op
    //   out = SHA-256(`${hashedPassphrase}:${filename}`)  // filename = ORIGINAL
    //   return prefix + "f:" + out
    // =====================================================================
    fn ts_expected_obfuscated_id(path: &str, passphrase: &str) -> String {
        // TS uses the escaped `x` for prefix splitting, but `filename` (original) for hashing.
        let hashed_pp = sha256_hex(passphrase);

        // TS line 111: underscore escape applied to `x`, not `filename`.
        let x = if path.starts_with('_') {
            format!("/{path}")
        } else {
            path.to_string()
        };

        // TS line 118: prefix split from `x` (escaped).
        let (prefix, _body) = split_prefix(&x);

        // TS line 123: hash computed from `filename` (ORIGINAL path, not `x`).
        let id_hash = sha256_hex(&format!("{hashed_pp}:{path}"));

        format!("{prefix}f:{id_hash}")
    }

    // =====================================================================
    // path2id — no obfuscation
    // =====================================================================

    #[test]
    fn test_path2id_no_obfuscation() {
        assert_eq!(path2id("notes/hello.md", None), "notes/hello.md");
    }

    #[test]
    fn test_path2id_no_obfuscation_underscore_escape() {
        // CouchDB reserves "_"-prefixed IDs; "/" prefix avoids collision.
        assert_eq!(path2id("_design/doc", None), "/_design/doc");
        assert_eq!(path2id("_notes/secret.md", None), "/_notes/secret.md");
    }

    #[test]
    fn test_path2id_no_obfuscation_prefixed_underscore() {
        // Prefixed path: body starts with "_" but full path starts with "ps:",
        // so no CouchDB collision — no "/" escape needed.
        // TS behavior: x.startsWith("_") is false → no escape.
        assert_eq!(path2id("ps:_design/doc", None), "ps:_design/doc");
    }

    #[test]
    fn test_path2id_no_obfuscation_already_obfuscated() {
        // Already obfuscated — pass through.
        assert_eq!(path2id("f:abc123", None), "f:abc123");
    }

    // =====================================================================
    // path2id — with obfuscation
    // =====================================================================

    #[test]
    fn test_path2id_obfuscation_normal() {
        let pp = "my_passphrase";
        let expected = ts_expected_obfuscated_id("notes/hello.md", pp);
        assert_eq!(path2id("notes/hello.md", Some(pp)), expected);
    }

    #[test]
    fn test_path2id_obfuscation_underscore() {
        // KEY TEST: TS hashes the ORIGINAL path ("_design/doc"), not the
        // escaped form ("/_design/doc"). The "/" prefix is only for
        // non-obfuscated CouchDB ID collision avoidance; obfuscated IDs
        // already start with "f:" so no collision is possible.
        let pp = "my_passphrase";
        let expected = ts_expected_obfuscated_id("_design/doc", pp);
        assert_eq!(path2id("_design/doc", Some(pp)), expected);
    }

    #[test]
    fn test_path2id_obfuscation_prefixed() {
        // Prefix should be preserved: "ps:" + "f:" + hash.
        let pp = "my_passphrase";
        let expected = ts_expected_obfuscated_id("ps:notes/hello.md", pp);
        assert_eq!(path2id("ps:notes/hello.md", Some(pp)), expected);
        assert!(expected.starts_with("ps:f:"));
    }

    #[test]
    fn test_path2id_obfuscation_prefixed_underscore() {
        // "ps:_design/doc" — no underscore escape (starts with "ps:", not "_").
        // x === filename, so hash input is the same either way.
        let pp = "my_passphrase";
        let expected = ts_expected_obfuscated_id("ps:_design/doc", pp);
        assert_eq!(path2id("ps:_design/doc", Some(pp)), expected);
        assert!(expected.starts_with("ps:f:"));
    }

    #[test]
    fn test_path2id_obfuscation_already_obfuscated_passthrough() {
        assert_eq!(path2id("f:abc123", Some("pp")), "f:abc123");
    }

    #[test]
    fn test_path2id_obfuscation_body_already_obfuscated_passthrough() {
        // "ps:f:abc123" — body starts with "f:", pass through.
        let normalized = path2id("ps:f:abc123", Some("pp"));
        assert_eq!(normalized, "ps:f:abc123");
    }

    // =====================================================================
    // path2id / id2path roundtrip (non-obfuscated)
    // =====================================================================

    #[test]
    fn test_roundtrip_normal() {
        let path = "notes/hello.md";
        let id = path2id(path, None);
        assert_eq!(id2path(&id, None).unwrap(), path);
    }

    #[test]
    fn test_roundtrip_underscore() {
        let path = "_design/doc";
        let id = path2id(path, None);
        // id = "/_design/doc", id2path strips the "/"
        assert_eq!(id2path(&id, None).unwrap(), path);
    }

    #[test]
    fn test_roundtrip_prefixed() {
        let path = "ps:notes/hello.md";
        let id = path2id(path, None);
        assert_eq!(id2path(&id, None).unwrap(), path);
    }

    #[test]
    fn test_roundtrip_prefixed_underscore() {
        // "ps:_design/doc" has no escape applied, roundtrips directly.
        let path = "ps:_design/doc";
        let id = path2id(path, None);
        assert_eq!(id2path(&id, None).unwrap(), path);
    }

    // =====================================================================
    // id2path
    // =====================================================================

    #[test]
    fn test_id2path_simple() {
        assert_eq!(id2path("notes/hello.md", None).unwrap(), "notes/hello.md");
        assert_eq!(id2path("/_design/doc", None).unwrap(), "_design/doc");
    }

    #[test]
    fn test_id2path_preserves_prefix() {
        assert_eq!(id2path("ps:notes/hello.md", None).unwrap(), "ps:notes/hello.md");
    }

    #[test]
    fn test_id2path_obfuscated_without_entry_path_fails() {
        assert!(id2path("f:abc123", None).is_err());
    }

    #[test]
    fn test_id2path_obfuscated_with_entry_path() {
        // Obfuscated ID is irreversible without entry.path.
        // When entry_path is provided (from decrypted metadata), use it.
        assert_eq!(
            id2path("f:abc123", Some("notes/hello.md")).unwrap(),
            "notes/hello.md"
        );
    }

    #[test]
    fn test_id2path_obfuscated_entry_path_underscore() {
        assert_eq!(
            id2path("f:abc123", Some("_design/doc")).unwrap(),
            "_design/doc"
        );
    }

    #[test]
    fn test_id2path_prefixed_obfuscated_fails() {
        assert!(id2path("ps:f:abc123", None).is_err());
    }

    // =====================================================================
    // hash_string_chain — TS _hashString bug replication
    // =====================================================================

    #[test]
    fn test_hash_string_chain_is_single_sha256() {
        // TS _hashString loop rehashes `buff` (original) instead of `digest`,
        // making it always SHA-256(key). Verify our replication.
        let key = "test_passphrase";
        let result = hash_string_chain(key);
        let expected = sha256_hex(key);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hash_string_chain_deterministic() {
        assert_eq!(hash_string_chain("abc"), hash_string_chain("abc"));
        assert_ne!(hash_string_chain("abc"), hash_string_chain("def"));
    }

    // =====================================================================
    // split_prefix
    // =====================================================================

    #[test]
    fn test_split_prefix_with_prefix() {
        assert_eq!(split_prefix("ps:notes/hello.md"), ("ps:", "notes/hello.md"));
    }

    #[test]
    fn test_split_prefix_no_prefix() {
        assert_eq!(split_prefix("notes/hello.md"), ("", "notes/hello.md"));
    }

    #[test]
    fn test_split_prefix_multiple_colons() {
        // Only splits on first colon, matching TS split(":", 2).
        assert_eq!(split_prefix("a:b:c/d.md"), ("a:", "b:c/d.md"));
    }

    #[test]
    fn test_split_prefix_underscore_path() {
        assert_eq!(split_prefix("/_design/doc"), ("", "/_design/doc"));
    }

    // =====================================================================
    // File classification
    // =====================================================================

    #[test]
    fn test_is_plain_text() {
        assert!(is_plain_text("notes/hello.md"));
        assert!(is_plain_text("style.css"));
        assert!(is_plain_text("data.csv"));
        assert!(is_plain_text("drawing.canvas"));
        assert!(!is_plain_text("image.png"));
        assert!(!is_plain_text("archive.zip"));
    }

    #[test]
    fn test_should_split_as_plain_text() {
        assert!(should_split_as_plain_text("notes.md"));
        assert!(should_split_as_plain_text("file.txt"));
        assert!(should_split_as_plain_text("drawing.canvas"));
        assert!(!should_split_as_plain_text("style.css"));
        assert!(!should_split_as_plain_text("image.png"));
    }

    #[test]
    fn test_should_be_ignored() {
        assert!(should_be_ignored("redflag.md"));
        assert!(should_be_ignored("redflag2.md"));
        assert!(should_be_ignored("redflag3.md"));
        assert!(should_be_ignored("flag_rebuild.md"));
        assert!(should_be_ignored("flag_fetch.md"));
        assert!(should_be_ignored("livesync_log_2024.md"));
        assert!(should_be_ignored("LIVESYNC_LOG_something"));
        assert!(!should_be_ignored("notes.md"));
        assert!(!should_be_ignored("my_redflag.md"));
    }

    #[test]
    fn test_strip_all_prefixes() {
        assert_eq!(strip_all_prefixes("ps:notes/hello.md"), "notes/hello.md");
        assert_eq!(strip_all_prefixes("a:b:c/d.md"), "c/d.md");
        assert_eq!(strip_all_prefixes("hello.md"), "hello.md");
    }
}
