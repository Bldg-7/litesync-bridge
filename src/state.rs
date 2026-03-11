use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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
pub struct WriteTracker {
    paths: Mutex<HashSet<PathBuf>>,
}

impl WriteTracker {
    pub fn new() -> Self {
        Self {
            paths: Mutex::new(HashSet::new()),
        }
    }

    /// Record that we just wrote to this path.
    pub fn record(&self, path: PathBuf) {
        self.paths.lock().unwrap().insert(path);
    }

    /// Check if this path was recently written by us, and remove it from tracking.
    /// Returns `true` if it was our write (caller should skip the event).
    pub fn check_and_remove(&self, path: &Path) -> bool {
        self.paths.lock().unwrap().remove(path)
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
