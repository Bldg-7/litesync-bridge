use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Tracks the CouchDB `since` sequence for a peer.
///
/// Persists to `{data_dir}/{peer_name}.since` as a plain text file.
pub struct SinceTracker {
    path: PathBuf,
    current: String,
}

impl SinceTracker {
    /// Load the last known sequence from disk, or default to `"now"`.
    pub fn load(data_dir: &Path, peer_name: &str) -> Self {
        let path = data_dir.join(format!("{peer_name}.since"));
        let current = std::fs::read_to_string(&path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "now".to_string());
        Self { path, current }
    }

    pub fn get(&self) -> &str {
        &self.current
    }

    /// Update the sequence and persist to disk.
    pub fn update(&mut self, seq: &serde_json::Value) -> anyhow::Result<()> {
        self.current = match seq {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => seq.to_string(),
        };
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, &self.current)?;
        Ok(())
    }

    /// Delete the since file so the peer starts from `"now"` on next load.
    pub fn reset(data_dir: &Path, peer_name: &str) -> anyhow::Result<()> {
        let path = data_dir.join(format!("{peer_name}.since"));
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }
}

/// Tracks recent file writes to prevent sync loops in StoragePeer.
///
/// Uses a time-window approach: writes within [`WRITE_SUPPRESS_WINDOW`] are
/// considered "own writes". Stale entries are cleaned up on access, preventing
/// unbounded growth.
pub struct WriteTracker {
    writes: Mutex<HashMap<PathBuf, Instant>>,
}

const WRITE_SUPPRESS_WINDOW: Duration = Duration::from_secs(1);

impl WriteTracker {
    pub fn new() -> Self {
        Self {
            writes: Mutex::new(HashMap::new()),
        }
    }

    /// Record that we just wrote to this path.
    pub fn record(&self, path: PathBuf) {
        self.writes.lock().unwrap().insert(path, Instant::now());
    }

    /// Check if this path was recently written by us (within the suppress window).
    /// Returns `true` if it was our write (caller should skip the event).
    /// Stale entries are removed on access.
    pub fn is_own_write(&self, path: &Path) -> bool {
        let mut map = self.writes.lock().unwrap();
        match map.get(path) {
            Some(t) if t.elapsed() < WRITE_SUPPRESS_WINDOW => true,
            Some(_) => {
                map.remove(path);
                false
            }
            None => false,
        }
    }
}

/// In-memory cache mapping CouchDB doc IDs to resolved relative paths.
///
/// Used to resolve paths for deleted documents where the tombstone may not
/// contain enough information (e.g., obfuscated IDs).
pub struct PathCache {
    map: Mutex<HashMap<String, String>>,
}

impl PathCache {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Cache a doc_id → rel_path mapping.
    pub fn insert(&self, doc_id: String, rel_path: String) {
        self.map.lock().unwrap().insert(doc_id, rel_path);
    }

    /// Look up the cached relative path for a doc_id.
    pub fn get(&self, doc_id: &str) -> Option<String> {
        self.map.lock().unwrap().get(doc_id).cloned()
    }
}

/// Tracks recent CouchDB document revisions to prevent sync loops in CouchDBPeer.
pub struct RevTracker {
    revs: Mutex<HashSet<String>>,
}

impl RevTracker {
    pub fn new() -> Self {
        Self {
            revs: Mutex::new(HashSet::new()),
        }
    }

    /// Record a revision we just wrote.
    pub fn record(&self, rev: String) {
        self.revs.lock().unwrap().insert(rev);
    }

    /// Check if this rev was written by us, and remove it from tracking.
    /// Returns `true` if it was our write (caller should skip the change).
    pub fn check_and_remove(&self, rev: &str) -> bool {
        self.revs.lock().unwrap().remove(rev)
    }
}
