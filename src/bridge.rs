use std::path::PathBuf;
use std::sync::Arc;

/// A file change event dispatched between peers.
#[derive(Debug, Clone)]
pub enum ChangeEvent {
    Modified {
        path: PathBuf,
        data: Arc<Vec<u8>>,
        mtime: u64,
        ctime: u64,
        is_binary: bool,
    },
    Deleted {
        path: PathBuf,
    },
}

impl ChangeEvent {
    pub fn path(&self) -> &std::path::Path {
        match self {
            ChangeEvent::Modified { path, .. } => path,
            ChangeEvent::Deleted { path } => path,
        }
    }
}

/// Message sent from a peer to the Hub for routing.
#[derive(Debug, Clone)]
pub struct PeerMessage {
    pub source_name: Arc<str>,
    pub group: Arc<str>,
    pub event: ChangeEvent,
}
