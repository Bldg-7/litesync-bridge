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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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
