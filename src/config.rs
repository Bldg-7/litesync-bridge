use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum PeerConfig {
    #[serde(rename = "couchdb")]
    CouchDB(CouchDBPeerConfig),
    #[serde(rename = "storage")]
    Storage(StoragePeerConfig),
}

impl PeerConfig {
    pub fn name(&self) -> &str {
        match self {
            PeerConfig::CouchDB(c) => &c.name,
            PeerConfig::Storage(s) => &s.name,
        }
    }

    pub fn group(&self) -> &str {
        match self {
            PeerConfig::CouchDB(c) => &c.group,
            PeerConfig::Storage(s) => &s.group,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CouchDBPeerConfig {
    pub name: String,
    pub group: String,
    pub database: String,
    pub username: String,
    pub password: String,
    pub url: String,
    #[serde(default)]
    pub passphrase: Option<String>,
    #[serde(default)]
    pub obfuscate_passphrase: Option<String>,
    #[serde(default)]
    pub base_dir: String,
}

impl std::fmt::Debug for CouchDBPeerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CouchDBPeerConfig")
            .field("name", &self.name)
            .field("group", &self.group)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("url", &self.url)
            .field("passphrase", &self.passphrase.as_ref().map(|_| "[REDACTED]"))
            .field("obfuscate_passphrase", &self.obfuscate_passphrase.as_ref().map(|_| "[REDACTED]"))
            .field("base_dir", &self.base_dir)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoragePeerConfig {
    pub name: String,
    pub group: String,
    pub base_dir: PathBuf,
    #[serde(default)]
    pub scan_offline_changes: bool,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Validate config integrity. Returns an error for fatal issues, logs warnings for non-fatal ones.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.peers.is_empty() {
            anyhow::bail!("config has no peers defined");
        }

        // Check for duplicate peer names
        let mut seen_names = HashSet::new();
        for peer in &self.peers {
            if !seen_names.insert(peer.name()) {
                anyhow::bail!("duplicate peer name: {}", peer.name());
            }
        }

        // Validate individual peers
        for peer in &self.peers {
            match peer {
                PeerConfig::CouchDB(c) => {
                    if c.name.is_empty() {
                        anyhow::bail!("CouchDB peer has empty name");
                    }
                    if c.url.is_empty() {
                        anyhow::bail!("CouchDB peer '{}' has empty url", c.name);
                    }
                    if !c.url.starts_with("http://") && !c.url.starts_with("https://") {
                        anyhow::bail!(
                            "CouchDB peer '{}' url must start with http:// or https://",
                            c.name
                        );
                    }
                    if c.database.is_empty() {
                        anyhow::bail!("CouchDB peer '{}' has empty database", c.name);
                    }
                    if c.username.is_empty() {
                        anyhow::bail!("CouchDB peer '{}' has empty username", c.name);
                    }
                    if c.password.is_empty() {
                        anyhow::bail!("CouchDB peer '{}' has empty password", c.name);
                    }
                }
                PeerConfig::Storage(s) => {
                    if s.name.is_empty() {
                        anyhow::bail!("Storage peer has empty name");
                    }
                    if s.base_dir.as_os_str().is_empty() {
                        anyhow::bail!("Storage peer '{}' has empty base_dir", s.name);
                    }
                }
            }
        }

        // Warn about unpaired groups
        let mut couchdb_groups: HashMap<&str, Vec<&str>> = HashMap::new();
        let mut storage_groups: HashMap<&str, Vec<&str>> = HashMap::new();
        for peer in &self.peers {
            match peer {
                PeerConfig::CouchDB(c) => {
                    couchdb_groups.entry(&c.group).or_default().push(&c.name);
                }
                PeerConfig::Storage(s) => {
                    storage_groups.entry(&s.group).or_default().push(&s.name);
                }
            }
        }

        for (group, names) in &couchdb_groups {
            if !storage_groups.contains_key(group) {
                tracing::warn!(
                    group = %group,
                    peers = ?names,
                    "CouchDB peers in group have no matching Storage peer"
                );
            }
        }
        for (group, names) in &storage_groups {
            if !couchdb_groups.contains_key(group) {
                tracing::warn!(
                    group = %group,
                    peers = ?names,
                    "Storage peers in group have no matching CouchDB peer"
                );
            }
        }

        Ok(())
    }

    /// Log a summary of configured peers at startup.
    pub fn log_summary(&self) {
        tracing::info!(peer_count = self.peers.len(), "litesync-bridge configured");
        for peer in &self.peers {
            match peer {
                PeerConfig::CouchDB(c) => {
                    // Extract host from URL for concise display
                    let host = c.url.trim_end_matches('/')
                        .rsplit("//")
                        .next()
                        .unwrap_or(&c.url);
                    tracing::info!(
                        peer_type = "couchdb",
                        name = %c.name,
                        database = %c.database,
                        host = %host,
                        group = %c.group,
                    );
                }
                PeerConfig::Storage(s) => {
                    tracing::info!(
                        peer_type = "storage",
                        name = %s.name,
                        base_dir = %s.base_dir.display(),
                        group = %s.group,
                    );
                }
            }
        }
    }
}
