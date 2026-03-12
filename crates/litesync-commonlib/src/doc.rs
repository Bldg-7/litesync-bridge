use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Constants ---

pub const PREFIX_OBFUSCATED: &str = "f:";
pub const PREFIX_CHUNK: &str = "h:";
pub const PREFIX_ENCRYPTED_CHUNK: &str = "h:+";
pub const ENCRYPTED_META_PREFIX: &str = "/\\:";

pub const EDEN_ENCRYPTED_KEY: &str = "h:++encrypted";
pub const EDEN_ENCRYPTED_KEY_HKDF: &str = "h:++encrypted-hkdf";

// --- Entry Types ---

pub const TYPE_PLAIN: &str = "plain";
pub const TYPE_NEWNOTE: &str = "newnote";
pub const TYPE_LEAF: &str = "leaf";

// --- Document Models ---

/// Chunk stored inline in a parent document (eden optimization).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EdenChunk {
    pub data: String,
    pub epoch: u64,
}

/// Chunk document stored in CouchDB.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EntryLeaf {
    pub _id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub _rev: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    pub data: String,
    #[serde(default, rename = "isCorrupted", skip_serializing_if = "Option::is_none")]
    pub is_corrupted: Option<bool>,
}

/// Raw note document from CouchDB. When E2EE is enabled, metadata fields
/// (ctime, mtime, size, children) are zeroed and the real values are
/// encrypted inside the `path` field.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawNoteEntry {
    pub _id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub _rev: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    pub path: String,
    #[serde(default)]
    pub ctime: u64,
    #[serde(default)]
    pub mtime: u64,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub children: Vec<String>,
    #[serde(default)]
    pub eden: HashMap<String, EdenChunk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub _deleted: Option<bool>,
    /// Soft-delete flag set by the Obsidian plugin. When `true`, the document
    /// represents a deleted file but is NOT a CouchDB tombstone — it remains
    /// visible in the changes feed so other clients can detect the deletion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    /// Optional inline data field. Present on soft-deleted documents (empty
    /// string) and sometimes on plain-text notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Metadata decrypted from an encrypted path field.
#[derive(Debug, Clone, Deserialize)]
pub struct DecryptedMeta {
    pub path: String,
    pub mtime: u64,
    pub ctime: u64,
    pub size: u64,
    #[serde(default)]
    pub children: Vec<String>,
}

/// Processed note entry with all fields resolved (decrypted if needed).
#[derive(Debug, Clone)]
pub struct NoteEntry {
    pub id: String,
    pub rev: Option<String>,
    pub path: String,
    pub ctime: u64,
    pub mtime: u64,
    pub size: u64,
    pub children: Vec<String>,
    pub eden: HashMap<String, EdenChunk>,
    pub deleted: bool,
    pub is_binary: bool,
}

impl RawNoteEntry {
    pub fn is_encrypted(&self) -> bool {
        self.path.starts_with(ENCRYPTED_META_PREFIX)
    }

    pub fn is_note(&self) -> bool {
        self.type_ == TYPE_PLAIN || self.type_ == TYPE_NEWNOTE
    }

    pub fn is_binary(&self) -> bool {
        self.type_ == TYPE_NEWNOTE
    }

    pub fn is_deleted(&self) -> bool {
        self._deleted.unwrap_or(false) || self.deleted.unwrap_or(false)
    }
}

// --- CouchDB Response Types ---

#[derive(Debug, Deserialize)]
pub struct ChangesResponse {
    pub results: Vec<ChangeResult>,
    pub last_seq: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct ChangeResult {
    pub seq: serde_json::Value,
    pub id: String,
    pub changes: Vec<ChangeRev>,
    #[serde(default)]
    pub doc: Option<serde_json::Value>,
    #[serde(default)]
    pub deleted: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ChangeRev {
    pub rev: String,
}

#[derive(Debug, Deserialize)]
pub struct AllDocsResponse {
    pub total_rows: Option<u64>,
    pub rows: Vec<AllDocsRow>,
}

#[derive(Debug, Deserialize)]
pub struct AllDocsRow {
    pub id: String,
    #[serde(default)]
    pub doc: Option<EntryLeaf>,
    #[serde(default)]
    pub error: Option<String>,
}

// --- CouchDB Write Response Types ---

/// Response from a CouchDB PUT/POST document operation.
#[derive(Debug, Deserialize)]
pub struct PutResponse {
    pub ok: bool,
    pub id: String,
    pub rev: String,
}

/// Response from CouchDB `_bulk_docs` batch write.
#[derive(Debug, Deserialize)]
pub struct BulkDocResult {
    pub ok: Option<bool>,
    pub id: String,
    #[serde(default)]
    pub rev: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // RawNoteEntry deserialization
    // =====================================================================

    #[test]
    fn test_raw_note_entry_full() {
        let json = r#"{
            "_id": "notes/hello.md",
            "_rev": "1-abc",
            "type": "plain",
            "path": "notes/hello.md",
            "ctime": 1000,
            "mtime": 2000,
            "size": 42,
            "children": ["h:chunk1", "h:chunk2"],
            "eden": {}
        }"#;
        let entry: RawNoteEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry._id, "notes/hello.md");
        assert_eq!(entry._rev, Some("1-abc".into()));
        assert_eq!(entry.type_, "plain");
        assert_eq!(entry.ctime, 1000);
        assert_eq!(entry.mtime, 2000);
        assert_eq!(entry.size, 42);
        assert_eq!(entry.children.len(), 2);
        assert!(entry.eden.is_empty());
        assert_eq!(entry._deleted, None);
    }

    #[test]
    fn test_raw_note_entry_minimal() {
        // Only required fields; serde(default) fills the rest.
        let json = r#"{
            "_id": "test.md",
            "type": "newnote",
            "path": "test.md"
        }"#;
        let entry: RawNoteEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry._id, "test.md");
        assert_eq!(entry._rev, None);
        assert_eq!(entry.type_, "newnote");
        assert_eq!(entry.ctime, 0);
        assert_eq!(entry.mtime, 0);
        assert_eq!(entry.size, 0);
        assert!(entry.children.is_empty());
        assert!(entry.eden.is_empty());
    }

    #[test]
    fn test_raw_note_entry_with_eden() {
        let json = r#"{
            "_id": "test.md",
            "type": "plain",
            "path": "test.md",
            "eden": {
                "h:chunk1": {"data": "base64data", "epoch": 5}
            }
        }"#;
        let entry: RawNoteEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.eden.len(), 1);
        let chunk = entry.eden.get("h:chunk1").unwrap();
        assert_eq!(chunk.data, "base64data");
        assert_eq!(chunk.epoch, 5);
    }

    #[test]
    fn test_raw_note_entry_deleted() {
        let json = r#"{
            "_id": "deleted.md",
            "type": "plain",
            "path": "deleted.md",
            "_deleted": true
        }"#;
        let entry: RawNoteEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry._deleted, Some(true));
    }

    // =====================================================================
    // Predicates
    // =====================================================================

    fn make_entry(type_: &str, path: &str) -> RawNoteEntry {
        RawNoteEntry {
            _id: "id".into(),
            _rev: None,
            type_: type_.into(),
            path: path.into(),
            ctime: 0, mtime: 0, size: 0,
            children: vec![],
            eden: HashMap::new(),
            _deleted: None,
            deleted: None,
            data: None,
        }
    }

    #[test]
    fn test_is_note() {
        assert!(make_entry("plain", "x").is_note());
        assert!(make_entry("newnote", "x").is_note());
        assert!(!make_entry("leaf", "x").is_note());
    }

    #[test]
    fn test_is_binary() {
        assert!(make_entry("newnote", "x").is_binary());
        assert!(!make_entry("plain", "x").is_binary());
    }

    #[test]
    fn test_is_deleted() {
        let mut entry = make_entry("plain", "x");
        assert!(!entry.is_deleted());
        entry._deleted = Some(false);
        assert!(!entry.is_deleted());
        entry._deleted = Some(true);
        assert!(entry.is_deleted());
    }

    #[test]
    fn test_is_deleted_soft_delete() {
        // Body-level `deleted: true` (soft-delete from Obsidian plugin)
        let mut entry = make_entry("plain", "x");
        assert!(!entry.is_deleted());
        entry.deleted = Some(true);
        assert!(entry.is_deleted());
        // Both false → not deleted
        entry.deleted = Some(false);
        entry._deleted = Some(false);
        assert!(!entry.is_deleted());
    }

    #[test]
    fn test_soft_delete_deserialization() {
        let json = r#"{
            "_id": "notes/deleted.md",
            "_rev": "5-abc",
            "type": "newnote",
            "path": "notes/deleted.md",
            "deleted": true,
            "children": [],
            "mtime": 1700000000000,
            "size": 0,
            "data": ""
        }"#;
        let entry: RawNoteEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.deleted, Some(true));
        assert_eq!(entry.data, Some("".into()));
        assert!(entry.is_deleted());
        assert!(entry.children.is_empty());
        assert_eq!(entry.size, 0);
    }

    #[test]
    fn test_is_encrypted() {
        assert!(make_entry("plain", "/\\:%=abc").is_encrypted());
        assert!(!make_entry("plain", "notes/hello.md").is_encrypted());
    }

    // =====================================================================
    // EntryLeaf deserialization
    // =====================================================================

    #[test]
    fn test_entry_leaf() {
        let json = r#"{
            "_id": "h:chunk1",
            "_rev": "1-def",
            "type": "leaf",
            "data": "SGVsbG8="
        }"#;
        let leaf: EntryLeaf = serde_json::from_str(json).unwrap();
        assert_eq!(leaf._id, "h:chunk1");
        assert_eq!(leaf.type_, "leaf");
        assert_eq!(leaf.data, "SGVsbG8=");
        assert_eq!(leaf.is_corrupted, None);
    }

    #[test]
    fn test_entry_leaf_corrupted() {
        let json = r#"{
            "_id": "h:chunk1",
            "type": "leaf",
            "data": "",
            "isCorrupted": true
        }"#;
        let leaf: EntryLeaf = serde_json::from_str(json).unwrap();
        assert_eq!(leaf.is_corrupted, Some(true));
    }

    // =====================================================================
    // CouchDB response types
    // =====================================================================

    #[test]
    fn test_changes_response() {
        let json = r#"{
            "results": [
                {
                    "seq": "3-abc",
                    "id": "notes/hello.md",
                    "changes": [{"rev": "1-def"}],
                    "doc": {"_id": "notes/hello.md", "type": "plain", "path": "notes/hello.md"}
                }
            ],
            "last_seq": "3-abc"
        }"#;
        let resp: ChangesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.results.len(), 1);
        assert_eq!(resp.results[0].id, "notes/hello.md");
        assert_eq!(resp.results[0].changes[0].rev, "1-def");
        assert!(resp.results[0].doc.is_some());
        assert_eq!(resp.results[0].deleted, None);
    }

    #[test]
    fn test_changes_response_deleted() {
        let json = r#"{
            "results": [
                {
                    "seq": 5,
                    "id": "deleted.md",
                    "changes": [{"rev": "2-ghi"}],
                    "deleted": true
                }
            ],
            "last_seq": 5
        }"#;
        let resp: ChangesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.results[0].deleted, Some(true));
        assert!(resp.results[0].doc.is_none());
    }

    #[test]
    fn test_all_docs_response() {
        let json = r#"{
            "total_rows": 100,
            "rows": [
                {
                    "id": "h:chunk1",
                    "doc": {"_id": "h:chunk1", "type": "leaf", "data": "SGVsbG8="}
                },
                {
                    "id": "h:missing",
                    "error": "not_found"
                }
            ]
        }"#;
        let resp: AllDocsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.total_rows, Some(100));
        assert_eq!(resp.rows.len(), 2);
        assert!(resp.rows[0].doc.is_some());
        assert_eq!(resp.rows[0].error, None);
        assert!(resp.rows[1].doc.is_none());
        assert_eq!(resp.rows[1].error, Some("not_found".into()));
    }

    // =====================================================================
    // Constants
    // =====================================================================

    // =====================================================================
    // Phase 2: Write response types
    // =====================================================================

    #[test]
    fn test_put_response() {
        let json = r#"{"ok": true, "id": "doc-id", "rev": "1-abc"}"#;
        let resp: super::PutResponse = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert_eq!(resp.id, "doc-id");
        assert_eq!(resp.rev, "1-abc");
    }

    #[test]
    fn test_bulk_doc_result_success() {
        let json = r#"{"ok": true, "id": "h:chunk1", "rev": "1-xyz"}"#;
        let result: super::BulkDocResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.ok, Some(true));
        assert_eq!(result.id, "h:chunk1");
        assert_eq!(result.rev, Some("1-xyz".into()));
        assert_eq!(result.error, None);
    }

    #[test]
    fn test_bulk_doc_result_conflict() {
        let json = r#"{"id": "h:chunk1", "error": "conflict", "reason": "Document update conflict."}"#;
        let result: super::BulkDocResult = serde_json::from_str(json).unwrap();
        assert_eq!(result.error, Some("conflict".into()));
        assert_eq!(result.reason, Some("Document update conflict.".into()));
        assert_eq!(result.ok, None);
    }

    #[test]
    fn test_entry_leaf_serialization_roundtrip() {
        let leaf = EntryLeaf {
            _id: "h:test".into(),
            _rev: None,
            type_: "leaf".into(),
            data: "SGVsbG8=".into(),
            is_corrupted: None,
        };
        let json = serde_json::to_string(&leaf).unwrap();
        let parsed: EntryLeaf = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed._id, "h:test");
        assert_eq!(parsed.data, "SGVsbG8=");
        assert_eq!(parsed.type_, "leaf");
    }

    #[test]
    fn test_entry_leaf_serialization_omits_none_fields() {
        // CouchDB rejects `"_rev": null` — must be omitted.
        let leaf = EntryLeaf {
            _id: "h:test".into(),
            _rev: None,
            type_: "leaf".into(),
            data: "SGVsbG8=".into(),
            is_corrupted: None,
        };
        let json = serde_json::to_string(&leaf).unwrap();
        assert!(!json.contains("_rev"), "None _rev should be omitted: {json}");
        assert!(!json.contains("isCorrupted"), "None isCorrupted should be omitted: {json}");
    }

    #[test]
    fn test_entry_leaf_serialization_includes_some_fields() {
        let leaf = EntryLeaf {
            _id: "h:test".into(),
            _rev: Some("1-abc".into()),
            type_: "leaf".into(),
            data: "SGVsbG8=".into(),
            is_corrupted: Some(false),
        };
        let json = serde_json::to_string(&leaf).unwrap();
        assert!(json.contains("\"_rev\":\"1-abc\""), "Some _rev should be included: {json}");
        assert!(json.contains("\"isCorrupted\":false"), "Some isCorrupted should be included: {json}");
    }

    #[test]
    fn test_raw_note_entry_serialization_omits_none() {
        let entry = make_entry("plain", "test.md");
        let json = serde_json::to_string(&entry).unwrap();
        assert!(!json.contains("\"_rev\":null"), "_rev null should be omitted: {json}");
        assert!(!json.contains("\"_deleted\":null"), "_deleted null should be omitted: {json}");
    }

    #[test]
    fn test_constants() {
        assert_eq!(PREFIX_OBFUSCATED, "f:");
        assert_eq!(PREFIX_CHUNK, "h:");
        assert_eq!(ENCRYPTED_META_PREFIX, "/\\:");
        assert_eq!(EDEN_ENCRYPTED_KEY, "h:++encrypted");
        assert_eq!(EDEN_ENCRYPTED_KEY_HKDF, "h:++encrypted-hkdf");
        assert_eq!(TYPE_PLAIN, "plain");
        assert_eq!(TYPE_NEWNOTE, "newnote");
        assert_eq!(TYPE_LEAF, "leaf");
    }
}
