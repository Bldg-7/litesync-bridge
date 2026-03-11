use serde::Deserialize;
use std::path::PathBuf;

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
}
