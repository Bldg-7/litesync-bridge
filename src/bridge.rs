use std::path::PathBuf;

/// A file change event dispatched between peers.
#[derive(Debug, Clone)]
pub enum ChangeEvent {
    Modified {
        path: PathBuf,
        data: Vec<u8>,
        mtime: u64,
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
