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
    let id_hash = sha256_hex(&format!("{hashed_passphrase}:{normalized}"));

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

    #[test]
    fn test_path2id_no_obfuscation() {
        assert_eq!(path2id("notes/hello.md", None), "notes/hello.md");
        assert_eq!(path2id("_design/doc", None), "/_design/doc");
    }

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
    fn test_id2path_obfuscated_fails() {
        assert!(id2path("f:abc123", None).is_err());
    }

    #[test]
    fn test_is_plain_text() {
        assert!(is_plain_text("notes/hello.md"));
        assert!(is_plain_text("style.css"));
        assert!(!is_plain_text("image.png"));
    }

    #[test]
    fn test_should_be_ignored() {
        assert!(should_be_ignored("redflag.md"));
        assert!(should_be_ignored("livesync_log_2024.md"));
        assert!(!should_be_ignored("notes.md"));
    }

    #[test]
    fn test_strip_all_prefixes() {
        assert_eq!(strip_all_prefixes("ps:notes/hello.md"), "notes/hello.md");
        assert_eq!(strip_all_prefixes("a:b:c/d.md"), "c/d.md");
        assert_eq!(strip_all_prefixes("hello.md"), "hello.md");
    }
}
