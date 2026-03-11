use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

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
    pub async fn update(&mut self, seq: &serde_json::Value) -> anyhow::Result<()> {
        self.current = match seq {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            _ => seq.to_string(),
        };
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&self.path, &self.current).await?;
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
        self.writes.lock().insert(path, Instant::now());
    }

    /// Check if this path was recently written by us (within the suppress window).
    /// Returns `true` if it was our write (caller should skip the event).
    /// Stale entries are removed on access.
    pub fn is_own_write(&self, path: &Path) -> bool {
        let mut map = self.writes.lock();
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
/// contain enough information (e.g., obfuscated IDs). Capped at
/// [`PATH_CACHE_MAX`] entries; oldest entries are evicted when full.
pub struct PathCache {
    map: Mutex<HashMap<String, String>>,
}

/// Maximum number of entries in PathCache. 50K docs × ~200 bytes ≈ 10 MB.
const PATH_CACHE_MAX: usize = 50_000;

impl PathCache {
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Cache a doc_id → rel_path mapping. Evicts ~10% of entries when at capacity.
    pub fn insert(&self, doc_id: String, rel_path: String) {
        let mut map = self.map.lock();
        if map.len() >= PATH_CACHE_MAX && !map.contains_key(&doc_id) {
            // Evict ~10% of entries. HashMap iteration order is arbitrary,
            // which provides reasonable pseudo-random eviction.
            let to_remove = PATH_CACHE_MAX / 10;
            let keys: Vec<String> = map.keys().take(to_remove).cloned().collect();
            for k in keys {
                map.remove(&k);
            }
        }
        map.insert(doc_id, rel_path);
    }

    /// Look up the cached relative path for a doc_id.
    pub fn get(&self, doc_id: &str) -> Option<String> {
        self.map.lock().get(doc_id).cloned()
    }
}

/// Tracks recent CouchDB document revisions to prevent sync loops in CouchDBPeer.
///
/// Uses a time-window approach similar to [`WriteTracker`]: revisions older than
/// [`REV_TTL`] are cleaned up on access, preventing unbounded growth.
pub struct RevTracker {
    revs: Mutex<HashMap<String, Instant>>,
}

/// Revisions older than this are considered stale and can be removed.
/// 5 minutes covers worst-case changes feed lag.
const REV_TTL: Duration = Duration::from_secs(300);

impl RevTracker {
    pub fn new() -> Self {
        Self {
            revs: Mutex::new(HashMap::new()),
        }
    }

    /// Record a revision we just wrote.
    pub fn record(&self, rev: String) {
        let mut map = self.revs.lock();
        map.insert(rev, Instant::now());
        // Periodic cleanup: every 1000 entries, sweep stale
        if map.len() % 1000 == 0 {
            map.retain(|_, t| t.elapsed() < REV_TTL);
        }
    }

    /// Check if this rev was written by us, and remove it from tracking.
    /// Returns `true` if it was our write (caller should skip the change).
    pub fn check_and_remove(&self, rev: &str) -> bool {
        self.revs.lock().remove(rev).is_some()
    }
}
