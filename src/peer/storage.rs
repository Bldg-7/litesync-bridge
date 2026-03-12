use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use litesync_commonlib::path as lspath;

use crate::bridge::{ChangeEvent, PeerMessage};
use crate::config::StoragePeerConfig;
use crate::state::{StatCache, WriteTracker};

pub struct StoragePeer {
    name: Arc<str>,
    group: Arc<str>,
    base_dir: std::path::PathBuf,
    write_tracker: WriteTracker,
    stat_cache: Mutex<Option<StatCache>>,
}

impl StoragePeer {
    pub fn new(config: StoragePeerConfig) -> Self {
        Self {
            name: Arc::from(config.name),
            group: Arc::from(config.group),
            base_dir: config.base_dir,
            write_tracker: WriteTracker::new(),
            stat_cache: Mutex::new(None),
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn group(&self) -> &str {
        &self.group
    }

    /// Set the stat cache (injected after reconciliation).
    pub(crate) fn set_stat_cache(&self, cache: StatCache) {
        *self.stat_cache.lock() = Some(cache);
    }

    /// Spawn watcher (outbound) and inbound (write) tasks.
    pub fn spawn(
        self,
        hub_tx: mpsc::Sender<PeerMessage>,
        inbound_rx: mpsc::Receiver<ChangeEvent>,
        cancel: CancellationToken,
    ) -> Vec<JoinHandle<()>> {
        let peer = Arc::new(self);

        let p = peer.clone();
        let c = cancel.clone();
        let watcher_handle = tokio::spawn(async move {
            if let Err(e) = p.run_watcher(hub_tx, c).await {
                tracing::error!(peer = %p.name, error = %e, "watcher loop failed");
            }
        });

        let p = peer.clone();
        let c = cancel;
        let inbound_handle = tokio::spawn(async move {
            if let Err(e) = p.run_inbound(inbound_rx, c).await {
                tracing::error!(peer = %p.name, error = %e, "inbound loop failed");
            }
        });

        // Cleanup task: wait for both loops, then save stat cache once
        let cleanup_handle = tokio::spawn(async move {
            let _ = watcher_handle.await;
            let _ = inbound_handle.await;
            peer.save_stat_cache().await;
            tracing::debug!(peer = %peer.name, "stat cache saved after shutdown");
        });

        vec![cleanup_handle]
    }

    // =========================================================================
    // Outbound: filesystem watcher → Hub
    // =========================================================================

    async fn run_watcher(
        self: &Arc<Self>,
        hub_tx: mpsc::Sender<PeerMessage>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        // Ensure base directory exists
        tokio::fs::create_dir_all(&self.base_dir).await?;

        // Bridge notify events into a tokio channel
        let (notify_tx, mut notify_rx) = mpsc::channel::<notify::Event>(256);

        let _watcher = {
            let tx = notify_tx;
            let mut watcher = RecommendedWatcher::new(
                move |res: Result<notify::Event, notify::Error>| {
                    if let Ok(event) = res {
                        let _ = tx.blocking_send(event);
                    }
                },
                notify::Config::default(),
            )?;
            watcher.watch(&self.base_dir, RecursiveMode::Recursive)?;
            watcher // keep alive
        };

        tracing::info!(
            peer = %self.name,
            path = %self.base_dir.display(),
            "watching directory"
        );

        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => break,
                event = notify_rx.recv() => match event {
                    Some(e) => e,
                    None => break,
                },
            };

            for (path_idx, event_path) in event.paths.iter().enumerate() {
                let rel = match event_path.strip_prefix(&self.base_dir) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let rel_str = rel.to_string_lossy();

                // Skip hidden files/dirs (.obsidian, .git, .DS_Store, etc.)
                if rel_str.starts_with('.') || rel_str.contains("/.") {
                    continue;
                }

                if lspath::should_be_ignored(&rel_str) {
                    continue;
                }

                match event.kind {
                    // Rename-from: old path in a mv — treat as deletion.
                    // Must appear before the generic Modify(_) arm.
                    EventKind::Modify(ModifyKind::Name(RenameMode::From)) => {
                        // Never suppress Remove/RenameFrom with WriteTracker —
                        // deletions (including mv source) must always propagate.
                        if rel.extension().is_none() {
                            let is_tracked = self.stat_cache.lock()
                                .as_ref()
                                .is_some_and(|c| c.existed(&rel_str));
                            if !is_tracked {
                                continue;
                            }
                        }
                        self.remove_stat_cache(&rel_str);
                        let msg = PeerMessage {
                            source_name: self.name.clone(),
                            group: self.group.clone(),
                            event: ChangeEvent::Deleted {
                                path: rel.to_path_buf(),
                            },
                        };
                        if hub_tx.send(msg).await.is_err() {
                            return Ok(());
                        }
                    }
                    // Rename-both: paths[0] = old (delete), paths[1] = new (create).
                    // Must appear before the generic Modify(_) arm.
                    EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
                        if path_idx == 0 {
                            // Old path — treat as deletion
                            if rel.extension().is_none() {
                                let is_tracked = self.stat_cache.lock()
                                    .as_ref()
                                    .is_some_and(|c| c.existed(&rel_str));
                                if !is_tracked {
                                    continue;
                                }
                            }
                            self.remove_stat_cache(&rel_str);
                            let msg = PeerMessage {
                                source_name: self.name.clone(),
                                group: self.group.clone(),
                                event: ChangeEvent::Deleted {
                                    path: rel.to_path_buf(),
                                },
                            };
                            if hub_tx.send(msg).await.is_err() {
                                return Ok(());
                            }
                        } else {
                            // New path — treat as creation
                            if self.write_tracker.is_own_write(event_path) {
                                continue;
                            }
                            if event_path.is_dir() {
                                continue;
                            }
                            match self.read_file(event_path, rel).await {
                                Ok(Some(change_event)) => {
                                    if let ChangeEvent::Modified {
                                        ref path, mtime, ref data, ..
                                    } = change_event
                                    {
                                        self.update_stat_cache(
                                            &path.to_string_lossy(),
                                            mtime,
                                            data.len() as u64,
                                        );
                                    }
                                    let msg = PeerMessage {
                                        source_name: self.name.clone(),
                                        group: self.group.clone(),
                                        event: change_event,
                                    };
                                    if hub_tx.send(msg).await.is_err() {
                                        return Ok(());
                                    }
                                }
                                Ok(None) => {}
                                Err(e) => {
                                    tracing::warn!(
                                        peer = %self.name, path = %rel_str,
                                        "read error: {e}"
                                    );
                                }
                            }
                        }
                    }
                    // Create, Modify (including RenameTo) — treat as upsert.
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        // Skip our own writes (only for create/modify, not remove)
                        if self.write_tracker.is_own_write(event_path) {
                            tracing::trace!(peer = %self.name, path = %rel_str, "skipping own write");
                            continue;
                        }
                        // Skip directories (stat is valid here since the file still exists)
                        if event_path.is_dir() {
                            continue;
                        }
                        match self.read_file(event_path, rel).await {
                            Ok(Some(change_event)) => {
                                // Update stat cache
                                if let ChangeEvent::Modified {
                                    ref path,
                                    mtime,
                                    ref data,
                                    ..
                                } = change_event
                                {
                                    self.update_stat_cache(
                                        &path.to_string_lossy(),
                                        mtime,
                                        data.len() as u64,
                                    );
                                }

                                let msg = PeerMessage {
                                    source_name: self.name.clone(),
                                    group: self.group.clone(),
                                    event: change_event,
                                };
                                if hub_tx.send(msg).await.is_err() {
                                    return Ok(());
                                }
                            }
                            Ok(None) => {} // file gone before we could read it
                            Err(e) => {
                                tracing::warn!(
                                    peer = %self.name, path = %rel_str,
                                    "read error: {e}"
                                );
                            }
                        }
                    }
                    EventKind::Remove(_) => {
                        // Never suppress Remove with WriteTracker —
                        // deletions must always propagate.
                        if rel.extension().is_none() {
                            let is_tracked = self.stat_cache.lock()
                                .as_ref()
                                .is_some_and(|c| c.existed(&rel_str));
                            if !is_tracked {
                                continue;
                            }
                        }
                        self.remove_stat_cache(&rel_str);
                        let msg = PeerMessage {
                            source_name: self.name.clone(),
                            group: self.group.clone(),
                            event: ChangeEvent::Deleted {
                                path: rel.to_path_buf(),
                            },
                        };
                        if hub_tx.send(msg).await.is_err() {
                            return Ok(());
                        }
                    }
                    _ => {}
                }
            }
        }

        tracing::info!(peer = %self.name, "watcher loop stopped");
        Ok(())
    }

    async fn read_file(
        &self,
        abs_path: &Path,
        rel_path: &Path,
    ) -> anyhow::Result<Option<ChangeEvent>> {
        let metadata = match tokio::fs::metadata(abs_path).await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let data = match tokio::fs::read(abs_path).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let filename = rel_path.to_string_lossy();
        let is_binary = !lspath::is_plain_text(&filename);

        let mtime = metadata
            .modified()?
            .duration_since(UNIX_EPOCH)?
            .as_millis() as u64;

        let ctime = metadata
            .created()
            .unwrap_or_else(|_| metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH))
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Ok(Some(ChangeEvent::Modified {
            path: rel_path.to_path_buf(),
            data: Arc::new(data),
            mtime,
            ctime,
            is_binary,
        }))
    }

    // =========================================================================
    // Inbound: Hub → filesystem writes
    // =========================================================================

    async fn run_inbound(
        self: &Arc<Self>,
        mut rx: mpsc::Receiver<ChangeEvent>,
        cancel: CancellationToken,
    ) -> anyhow::Result<()> {
        loop {
            let event = tokio::select! {
                _ = cancel.cancelled() => break,
                event = rx.recv() => match event {
                    Some(e) => e,
                    None => break,
                },
            };

            if let Err(e) = self.handle_write(event).await {
                tracing::warn!(peer = %self.name, "file write failed: {e}");
            }
        }

        tracing::info!(peer = %self.name, "inbound loop stopped");
        Ok(())
    }

    async fn handle_write(&self, event: ChangeEvent) -> anyhow::Result<()> {
        match event {
            ChangeEvent::Modified {
                path, data, mtime, ..
            } => {
                let full = self.base_dir.join(&path);

                if let Some(parent) = full.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }

                // Record before writing so the watcher can skip the echo
                self.write_tracker.record(full.clone());

                tokio::fs::write(&full, &*data).await?;

                // Restore original mtime — this fires a second notify event,
                // so refresh the tracker timestamp afterward.
                let ft = filetime::FileTime::from_unix_time(
                    (mtime / 1000) as i64,
                    ((mtime % 1000) * 1_000_000) as u32,
                );
                let full_clone = full.clone();
                tokio::task::spawn_blocking(move || filetime::set_file_mtime(&full_clone, ft))
                    .await??;
                self.write_tracker.record(full);

                // Update stat cache after inbound write
                let rel_str = path.to_string_lossy();
                self.update_stat_cache(&rel_str, mtime, data.len() as u64);

                tracing::debug!(peer = %self.name, path = %path.display(), "wrote file");
            }
            ChangeEvent::Deleted { path } => {
                let full = self.base_dir.join(&path);

                // Record before deleting so the watcher can skip the echo
                self.write_tracker.record(full.clone());

                // Update stat cache
                let rel_str = path.to_string_lossy();
                self.remove_stat_cache(&rel_str);

                match tokio::fs::remove_file(&full).await {
                    Ok(()) => {
                        tracing::debug!(peer = %self.name, path = %path.display(), "deleted file");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }

        Ok(())
    }

    // =========================================================================
    // StatCache helpers
    // =========================================================================

    fn update_stat_cache(&self, rel_path: &str, mtime: u64, size: u64) {
        if let Some(ref mut cache) = *self.stat_cache.lock() {
            cache.insert(rel_path.to_string(), mtime, size);
        }
    }

    fn remove_stat_cache(&self, rel_path: &str) {
        if let Some(ref mut cache) = *self.stat_cache.lock() {
            cache.remove(rel_path);
        }
    }

    async fn save_stat_cache(&self) {
        let cache = self.stat_cache.lock().take();
        if let Some(cache) = cache {
            if let Err(e) = cache.save().await {
                tracing::warn!(peer = %self.name, "failed to save stat cache: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_peer(base_dir: std::path::PathBuf) -> StoragePeer {
        StoragePeer::new(StoragePeerConfig {
            name: "test-local".into(),
            group: "test".into(),
            base_dir,
            scan_offline_changes: false,
        })
    }

    /// Collect messages from hub channel until timeout.
    async fn collect_messages(
        rx: &mut mpsc::Receiver<PeerMessage>,
        timeout: Duration,
    ) -> Vec<PeerMessage> {
        let mut msgs = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                msg = rx.recv() => match msg {
                    Some(m) => msgs.push(m),
                    None => break,
                },
            }
        }
        msgs
    }

    /// External file creation should produce a Modified event.
    #[tokio::test]
    async fn watcher_detects_create() {
        let dir = tempfile::tempdir().unwrap();
        let peer = test_peer(dir.path().to_path_buf());

        let (hub_tx, mut hub_rx) = mpsc::channel(64);
        let (_, inbound_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();

        let handles = peer.spawn(hub_tx, inbound_rx, cancel.clone());

        // Wait for watcher to be ready
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Create a file externally
        tokio::fs::write(dir.path().join("hello.md"), b"hello").await.unwrap();

        let msgs = collect_messages(&mut hub_rx, Duration::from_secs(2)).await;
        cancel.cancel();
        for h in handles { let _ = h.await; }

        let created: Vec<_> = msgs.iter()
            .filter(|m| matches!(&m.event, ChangeEvent::Modified { path, .. } if path.to_str() == Some("hello.md")))
            .collect();
        assert!(!created.is_empty(), "should detect file creation: got {msgs:?}");
    }

    /// External file deletion should produce a Deleted event.
    #[tokio::test]
    async fn watcher_detects_delete() {
        let dir = tempfile::tempdir().unwrap();

        // Pre-create the file before starting watcher
        let file_path = dir.path().join("to-delete.md");
        std::fs::write(&file_path, b"content").unwrap();

        let peer = test_peer(dir.path().to_path_buf());

        let (hub_tx, mut hub_rx) = mpsc::channel(64);
        let (_, inbound_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();

        let handles = peer.spawn(hub_tx, inbound_rx, cancel.clone());
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Delete the file externally
        tokio::fs::remove_file(&file_path).await.unwrap();

        let msgs = collect_messages(&mut hub_rx, Duration::from_secs(2)).await;
        cancel.cancel();
        for h in handles { let _ = h.await; }

        let deleted: Vec<_> = msgs.iter()
            .filter(|m| matches!(&m.event, ChangeEvent::Deleted { path } if path.to_str() == Some("to-delete.md")))
            .collect();
        assert!(!deleted.is_empty(), "should detect file deletion: got {msgs:?}");
    }

    /// `mv old new` should produce both a Deleted event for old and a Modified
    /// event for new. This is the bug scenario: WriteTracker was suppressing the
    /// Remove event for the old path.
    #[tokio::test]
    async fn watcher_detects_mv_delete() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("subfolder");
        std::fs::create_dir_all(&subdir).unwrap();

        // Pre-create the file
        let old_path = dir.path().join("inbox-note.md");
        std::fs::write(&old_path, b"note content").unwrap();

        let peer = test_peer(dir.path().to_path_buf());

        let (hub_tx, mut hub_rx) = mpsc::channel(64);
        let (_, inbound_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();

        let handles = peer.spawn(hub_tx, inbound_rx, cancel.clone());
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Simulate `mv old_path new_path`
        let new_path = subdir.join("inbox-note.md");
        tokio::fs::rename(&old_path, &new_path).await.unwrap();

        let msgs = collect_messages(&mut hub_rx, Duration::from_secs(2)).await;
        cancel.cancel();
        for h in handles { let _ = h.await; }

        let has_delete = msgs.iter().any(|m| {
            matches!(&m.event, ChangeEvent::Deleted { path } if path.to_str() == Some("inbox-note.md"))
        });
        let has_create = msgs.iter().any(|m| {
            matches!(&m.event, ChangeEvent::Modified { path, .. } if path.to_string_lossy().contains("inbox-note.md"))
        });

        assert!(has_create, "should detect new file after mv: got {msgs:?}");
        assert!(has_delete, "should detect deletion of old path after mv: got {msgs:?}");
    }

    /// A file written by the inbound loop (own write) then moved externally
    /// should still produce a Deleted event for the old path. The WriteTracker
    /// must not suppress Remove events.
    #[tokio::test]
    async fn watcher_mv_after_own_write_still_emits_delete() {
        let dir = tempfile::tempdir().unwrap();
        let subdir = dir.path().join("project");
        std::fs::create_dir_all(&subdir).unwrap();

        let peer = test_peer(dir.path().to_path_buf());

        let (hub_tx, mut hub_rx) = mpsc::channel(64);
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        let cancel = CancellationToken::new();

        let handles = peer.spawn(hub_tx, inbound_rx, cancel.clone());
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Simulate inbound write (bridge writes the file → recorded in WriteTracker)
        inbound_tx
            .send(ChangeEvent::Modified {
                path: "synced-note.md".into(),
                data: Arc::new(b"synced content".to_vec()),
                mtime: 1700000000000,
                ctime: 1700000000000,
                is_binary: false,
            })
            .await
            .unwrap();

        // Wait for inbound write to complete (file written + WriteTracker recorded)
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Drain any echo events from the inbound write
        let _ = collect_messages(&mut hub_rx, Duration::from_millis(500)).await;

        // Now externally mv the file (user action, NOT an own write)
        let old_path = dir.path().join("synced-note.md");
        let new_path = subdir.join("synced-note.md");
        assert!(old_path.exists(), "inbound write should have created the file");
        tokio::fs::rename(&old_path, &new_path).await.unwrap();

        let msgs = collect_messages(&mut hub_rx, Duration::from_secs(2)).await;
        cancel.cancel();
        for h in handles { let _ = h.await; }

        let has_delete = msgs.iter().any(|m| {
            matches!(&m.event, ChangeEvent::Deleted { path } if path.to_str() == Some("synced-note.md"))
        });
        let has_create = msgs.iter().any(|m| {
            matches!(&m.event, ChangeEvent::Modified { path, .. } if path.to_string_lossy().contains("synced-note.md"))
        });

        assert!(has_create, "should detect new file at moved path: got {msgs:?}");
        assert!(
            has_delete,
            "BUG: Remove event for old path was suppressed by WriteTracker: got {msgs:?}"
        );
    }
}
