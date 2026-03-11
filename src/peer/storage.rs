use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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

        let p = peer;
        let c = cancel;
        let inbound_handle = tokio::spawn(async move {
            if let Err(e) = p.run_inbound(inbound_rx, c).await {
                tracing::error!(peer = %p.name, error = %e, "inbound loop failed");
            }
        });

        vec![watcher_handle, inbound_handle]
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

            for event_path in &event.paths {
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

                // Skip our own writes
                if self.write_tracker.is_own_write(event_path) {
                    tracing::trace!(peer = %self.name, path = %rel_str, "skipping own write");
                    continue;
                }

                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
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
                        // For Remove events, the path no longer exists so is_dir()
                        // would always return false. Use lack of extension as a
                        // heuristic to skip directory removals.
                        if rel.extension().is_none() {
                            continue;
                        }

                        // Update stat cache
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

        // Save stat cache on shutdown
        self.save_stat_cache().await;

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
            data,
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

                tokio::fs::write(&full, &data).await?;

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
