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
    #[serde(default)]
    pub _rev: Option<String>,
    #[serde(rename = "type")]
    pub type_: String,
    pub data: String,
    #[serde(default, rename = "isCorrupted")]
    pub is_corrupted: Option<bool>,
}

/// Raw note document from CouchDB. When E2EE is enabled, metadata fields
/// (ctime, mtime, size, children) are zeroed and the real values are
/// encrypted inside the `path` field.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RawNoteEntry {
    pub _id: String,
    #[serde(default)]
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
    #[serde(default)]
    pub _deleted: Option<bool>,
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
        self._deleted.unwrap_or(false)
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
