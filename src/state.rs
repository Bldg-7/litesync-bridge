use std::collections::HashMap;
use std::io::BufRead;
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

impl Default for WriteTracker {
    fn default() -> Self {
        Self::new()
    }
}

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

impl Default for PathCache {
    fn default() -> Self {
        Self::new()
    }
}

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

impl Default for RevTracker {
    fn default() -> Self {
        Self::new()
    }
}

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
        // Sweep stale entries when the map grows beyond 1000
        if map.len() > 1000 {
            map.retain(|_, t| t.elapsed() < REV_TTL);
        }
    }

    /// Check if this rev was written by us, and remove it from tracking.
    /// Returns `true` if it was our write (caller should skip the change).
    pub fn check_and_remove(&self, rev: &str) -> bool {
        self.revs.lock().remove(rev).is_some()
    }
}

/// Persistent filesystem stat snapshot for detecting offline changes.
///
/// Stores `rel_path → "mtime_ms-size"` mappings in a TSV file at
/// `{data_dir}/{peer_name}.stats`. Used by reconciliation to distinguish
/// "file was deleted while offline" from "file never existed locally".
pub struct StatCache {
    path: PathBuf,
    entries: HashMap<String, String>,
}

impl StatCache {
    /// Load stat cache from disk. Returns an empty cache if the file doesn't exist.
    pub fn load(data_dir: &Path, peer_name: &str) -> Self {
        let path = data_dir.join(format!("{peer_name}.stats"));
        let entries = Self::read_file(&path).unwrap_or_default();
        Self { path, entries }
    }

    fn read_file(path: &Path) -> Option<HashMap<String, String>> {
        let file = std::fs::File::open(path).ok()?;
        let reader = std::io::BufReader::new(file);
        let mut map = HashMap::new();
        for line in reader.lines() {
            // Skip unreadable lines instead of aborting the whole cache
            let Ok(line) = line else { continue };
            if let Some((rel_path, stat_val)) = line.split_once('\t') {
                if !rel_path.is_empty() && !stat_val.is_empty() {
                    map.insert(rel_path.to_string(), stat_val.to_string());
                }
            }
        }
        Some(map)
    }

    /// Check if a file was previously tracked (existed in the last snapshot).
    pub fn existed(&self, rel_path: &str) -> bool {
        self.entries.contains_key(rel_path)
    }

    /// Get the stored stat value for a path.
    pub fn get(&self, rel_path: &str) -> Option<&str> {
        self.entries.get(rel_path).map(String::as_str)
    }

    /// Check if a file's stat has changed compared to the cached value.
    /// Returns `true` if the file is new or its mtime/size differ.
    pub fn is_changed(&self, rel_path: &str, mtime_ms: u64, size: u64) -> bool {
        match self.entries.get(rel_path) {
            Some(cached) => cached != &Self::stat_value(mtime_ms, size),
            None => true,
        }
    }

    /// Insert or update a stat entry.
    pub fn insert(&mut self, rel_path: String, mtime_ms: u64, size: u64) {
        self.entries
            .insert(rel_path, Self::stat_value(mtime_ms, size));
    }

    /// Remove a stat entry.
    pub fn remove(&mut self, rel_path: &str) {
        self.entries.remove(rel_path);
    }

    /// Check if the cache is empty (first run or reset).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Persist the cache to disk.
    pub async fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut content = String::with_capacity(self.entries.len() * 80);
        // Sort for deterministic output
        let mut keys: Vec<&str> = self.entries.keys().map(String::as_str).collect();
        keys.sort_unstable();
        for key in keys {
            if let Some(val) = self.entries.get(key) {
                content.push_str(key);
                content.push('\t');
                content.push_str(val);
                content.push('\n');
            }
        }
        tokio::fs::write(&self.path, content).await?;
        Ok(())
    }

    fn stat_value(mtime_ms: u64, size: u64) -> String {
        format!("{mtime_ms}-{size}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stat_cache_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path();

        // Create and populate
        let mut cache = StatCache::load(data_dir, "test");
        assert!(cache.is_empty());
        cache.insert("notes/hello.md".to_string(), 1700000000000, 1234);
        cache.insert("attachments/img.png".to_string(), 1700000001000, 5678);
        cache.save().await.unwrap();

        // Reload and verify
        let cache2 = StatCache::load(data_dir, "test");
        assert!(!cache2.is_empty());
        assert_eq!(cache2.get("notes/hello.md"), Some("1700000000000-1234"));
        assert_eq!(
            cache2.get("attachments/img.png"),
            Some("1700000001000-5678")
        );
        assert!(cache2.get("nonexistent.md").is_none());
    }

    #[test]
    fn stat_cache_is_changed() {
        let mut cache = StatCache {
            path: PathBuf::from("/tmp/test.stats"),
            entries: HashMap::new(),
        };
        cache.insert("a.md".to_string(), 1000, 100);

        // Same values → not changed
        assert!(!cache.is_changed("a.md", 1000, 100));
        // Different mtime → changed
        assert!(cache.is_changed("a.md", 2000, 100));
        // Different size → changed
        assert!(cache.is_changed("a.md", 1000, 200));
        // Unknown file → changed
        assert!(cache.is_changed("b.md", 1000, 100));
    }

    #[test]
    fn stat_cache_existed_and_remove() {
        let mut cache = StatCache {
            path: PathBuf::from("/tmp/test.stats"),
            entries: HashMap::new(),
        };
        cache.insert("a.md".to_string(), 1000, 100);
        assert!(cache.existed("a.md"));
        assert!(!cache.existed("b.md"));

        cache.remove("a.md");
        assert!(!cache.existed("a.md"));
    }
}
