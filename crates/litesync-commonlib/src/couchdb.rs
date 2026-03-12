use std::time::Duration;

use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::doc::{AllDocsResponse, BulkDocResult, ChangesResponse, EntryLeaf, PutResponse, TYPE_LEAF};

/// CouchDB document ID for the LiveSync milestone document.
/// Note: "obsydian" with a 'y' is intentional (matches the Obsidian plugin).
const MILESTONE_DOCID: &str = "_local/obsydian_livesync_milestone";

/// Default binary chunk size in bytes (100KB), matching the TS `MAX_DOC_SIZE_BIN`.
const MAX_DOC_SIZE_BIN: usize = 102_400;

/// Remote tweak values fetched from the CouchDB milestone document.
///
/// The Obsidian plugin stores database-level configuration in
/// `_local/obsydian_livesync_milestone` under `tweak_values`.
/// These override local defaults for chunk splitting parameters.
#[derive(Debug, Clone)]
pub struct RemoteTweaks {
    /// Chunk size coefficient. Actual piece_size = MAX_DOC_SIZE_BIN * (custom_chunk_size + 1).
    pub custom_chunk_size: usize,
    /// Minimum chunk size for text splitting (default: 20).
    pub minimum_chunk_size: usize,
    /// Hash algorithm: "" for legacy xxhash32, "xxhash64" for xxhash64.
    pub hash_alg: String,
    /// Whether the V2 chunk splitter is enabled.
    pub enable_chunk_splitter_v2: bool,
    /// Whether eden (inline chunk incubation) is enabled.
    pub use_eden: bool,
    /// Whether filenames are handled case-sensitively.
    ///
    /// Default is `false` (case-insensitive), matching the TS plugin default.
    /// When `false`, paths are lowercased before generating document IDs.
    pub handle_filename_case_sensitive: bool,
}

impl Default for RemoteTweaks {
    fn default() -> Self {
        Self {
            custom_chunk_size: 0,
            minimum_chunk_size: 20,
            hash_alg: "xxhash64".to_string(),
            enable_chunk_splitter_v2: true,
            use_eden: false,
            handle_filename_case_sensitive: false,
        }
    }
}

impl RemoteTweaks {
    /// Compute the actual piece size from the custom_chunk_size coefficient.
    ///
    /// Matches the TS formula: `Math.floor(MAX_DOC_SIZE_BIN * (customChunkSize + 1))`
    pub fn piece_size(&self) -> usize {
        MAX_DOC_SIZE_BIN * (self.custom_chunk_size + 1)
    }
}

/// Typed HTTP error from CouchDB, enabling callers to match on status code
/// instead of parsing error strings.
#[derive(Debug, thiserror::Error)]
#[error("{method} {id}: {status} — {body}")]
pub struct CouchDBHttpError {
    pub method: &'static str,
    pub id: String,
    pub status: u16,
    pub body: String,
}

/// HTTP client for CouchDB operations.
#[derive(Clone)]
pub struct CouchDBClient {
    base_url: String,
    database: String,
    client: Client,
}

impl CouchDBClient {
    pub fn new(base_url: &str, database: &str, username: &str, password: &str) -> anyhow::Result<Self> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        let credentials = BASE64.encode(format!("{username}:{password}"));
        let mut auth_value = HeaderValue::from_str(&format!("Basic {credentials}"))?;
        auth_value.set_sensitive(true);

        let mut default_headers = HeaderMap::new();
        default_headers.insert(header::AUTHORIZATION, auth_value);

        let client = Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(false)
            .default_headers(default_headers)
            .build()?;

        let url = base_url.trim_end_matches('/').to_string();

        Ok(Self {
            base_url: url,
            database: database.to_string(),
            client,
        })
    }

    fn db_url(&self) -> String {
        format!("{}/{}", self.base_url, self.database)
    }

    /// Fetch a single document by ID.
    pub async fn get_doc<T: DeserializeOwned>(&self, id: &str) -> anyhow::Result<T> {
        let url = format!("{}/{}", self.db_url(), urlencoding::encode(id));
        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(CouchDBHttpError {
                method: "GET",
                id: id.to_string(),
                status: status.as_u16(),
                body,
            }.into());
        }

        Ok(resp.json().await?)
    }

    /// Fetch changes from the `_changes` feed (one-shot, not live).
    ///
    /// Uses `_selector` filter to exclude chunk documents (`type != "leaf"`).
    pub async fn get_changes(
        &self,
        since: &str,
        limit: Option<u32>,
    ) -> anyhow::Result<ChangesResponse> {
        let url = format!(
            "{}/_changes?include_docs=true&filter=_selector",
            self.db_url()
        );

        let mut body = json!({
            "selector": {
                "type": { "$ne": TYPE_LEAF }
            }
        });

        if let Some(limit) = limit {
            body["limit"] = json!(limit);
        }

        let resp = self
            .client
            .post(&url)
            .query(&[("since", since)])
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("_changes: {status} — {text}");
        }

        Ok(resp.json().await?)
    }

    /// Fetch multiple chunk documents by their IDs using `_all_docs`.
    pub async fn get_chunks(&self, chunk_ids: &[String]) -> anyhow::Result<Vec<EntryLeaf>> {
        if chunk_ids.is_empty() {
            return Ok(vec![]);
        }

        let url = format!("{}/_all_docs?include_docs=true", self.db_url());
        let body = json!({ "keys": chunk_ids });

        let resp = self.client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("_all_docs: {status} — {text}");
        }

        let result: AllDocsResponse = resp.json().await?;
        let mut chunks = Vec::with_capacity(result.rows.len());
        for row in result.rows {
            if let Some(error) = row.error {
                anyhow::bail!("failed to fetch chunk {}: {}", row.id, error);
            }
            if let Some(doc) = row.doc {
                chunks.push(doc);
            }
        }

        Ok(chunks)
    }

    /// Fetch changes using CouchDB long-polling.
    ///
    /// Blocks until at least one change is available or `timeout_ms` elapses.
    /// The HTTP request timeout is set to `timeout_ms + 5000ms` to account
    /// for network overhead.
    pub async fn get_changes_longpoll(
        &self,
        since: &str,
        timeout_ms: u64,
    ) -> anyhow::Result<ChangesResponse> {
        let url = format!(
            "{}/_changes?include_docs=true&filter=_selector&feed=longpoll&timeout={}",
            self.db_url(),
            timeout_ms
        );

        let body = json!({
            "selector": {
                "type": { "$ne": TYPE_LEAF }
            }
        });

        let resp = self
            .client
            .post(&url)
            .query(&[("since", since)])
            .timeout(Duration::from_millis(timeout_ms + 5_000))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("_changes longpoll: {status} — {text}");
        }

        Ok(resp.json().await?)
    }

    /// Fetch all note documents (non-leaf) from the database.
    pub async fn get_all_notes(&self) -> anyhow::Result<ChangesResponse> {
        self.get_changes("0", None).await
    }

    /// Fetch the PBKDF2 salt from the LiveSync sync parameters document.
    ///
    /// Self-hosted LiveSync stores the E2EE salt in
    /// `_local/obsidian_livesync_sync_parameters` under the `pbkdf2salt` field
    /// as a base64-encoded string (matching the Obsidian plugin's
    /// `DOCID_SYNC_PARAMETERS`).
    ///
    /// For legacy databases that predate the sync-parameters document, we fall
    /// back to `_local/obsidian-livesync-config` / `_local/obsidian-livesync`
    /// which stored the salt as a hex string in `encryptedPassphraseSalt`.
    pub async fn get_e2ee_salt(&self) -> anyhow::Result<Vec<u8>> {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        // 1. Try the current sync-parameters document (matches TS plugin).
        {
            let config_id = "_local/obsidian_livesync_sync_parameters";
            let url = format!("{}/{}", self.db_url(), urlencoding::encode(config_id));
            let resp = self.client.get(&url).send().await?;
            if resp.status().is_success() {
                let doc: serde_json::Value = resp.json().await?;
                if let Some(salt_b64) = doc.get("pbkdf2salt").and_then(|v| v.as_str()) {
                    if !salt_b64.is_empty() {
                        return BASE64.decode(salt_b64)
                            .map_err(|e| anyhow::anyhow!("invalid PBKDF2 salt base64: {e}"));
                    }
                }
            }
        }

        // 2. Legacy fallback: older config documents with hex-encoded salt.
        let legacy_ids = [
            "_local/obsidian-livesync-config",
            "_local/obsidian-livesync",
        ];

        for config_id in &legacy_ids {
            let url = format!("{}/{}", self.db_url(), urlencoding::encode(config_id));
            let resp = self.client.get(&url).send().await?;
            if !resp.status().is_success() {
                continue;
            }

            let doc: serde_json::Value = resp.json().await?;
            if let Some(salt_hex) = doc.get("encryptedPassphraseSalt").and_then(|v| v.as_str()) {
                return hex::decode(salt_hex)
                    .map_err(|e| anyhow::anyhow!("invalid PBKDF2 salt hex: {e}"));
            }
        }

        anyhow::bail!("PBKDF2 salt not found in CouchDB config documents")
    }

    /// Fetch remote tweak values from the LiveSync milestone document.
    ///
    /// The Obsidian plugin stores database-level configuration in
    /// `_local/obsydian_livesync_milestone` under the `tweak_values` map.
    /// Each key in the map is a device ID; we take the first entry's values.
    ///
    /// If the document doesn't exist or has no tweak_values, returns defaults.
    pub async fn get_remote_tweaks(&self) -> anyhow::Result<RemoteTweaks> {
        let url = format!(
            "{}/{}",
            self.db_url(),
            urlencoding::encode(MILESTONE_DOCID)
        );
        let resp = self.client.get(&url).send().await?;

        if !resp.status().is_success() {
            // Document doesn't exist (404) or other error — use defaults
            tracing::debug!(
                status = resp.status().as_u16(),
                "milestone document not found, using default tweaks"
            );
            return Ok(RemoteTweaks::default());
        }

        let doc: serde_json::Value = resp.json().await?;

        // The tweak_values field is a map of device_id → tweaks.
        // We take the first entry's values (matching TS: Object.values(w["tweak_values"])[0]).
        let tweaks = match doc.get("tweak_values").and_then(|v| v.as_object()) {
            Some(map) if !map.is_empty() => {
                match map.values().next() {
                    Some(first) => first,
                    None => return Ok(RemoteTweaks::default()),
                }
            }
            _ => {
                tracing::debug!("milestone document has no tweak_values, using defaults");
                return Ok(RemoteTweaks::default());
            }
        };

        let custom_chunk_size = tweaks
            .get("customChunkSize")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        let minimum_chunk_size = tweaks
            .get("minimumChunkSize")
            .and_then(|v| v.as_u64())
            .unwrap_or(20) as usize;

        let hash_alg = tweaks
            .get("hashAlg")
            .and_then(|v| v.as_str())
            .unwrap_or("xxhash64")
            .to_string();

        let enable_chunk_splitter_v2 = tweaks
            .get("enableChunkSplitterV2")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let use_eden = tweaks
            .get("useEden")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let handle_filename_case_sensitive = tweaks
            .get("handleFilenameCaseSensitive")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let result = RemoteTweaks {
            custom_chunk_size,
            minimum_chunk_size,
            hash_alg,
            enable_chunk_splitter_v2,
            use_eden,
            handle_filename_case_sensitive,
        };

        tracing::info!(
            piece_size = result.piece_size(),
            min_chunk_size = result.minimum_chunk_size,
            hash_alg = %result.hash_alg,
            chunk_splitter_v2 = result.enable_chunk_splitter_v2,
            use_eden = result.use_eden,
            case_sensitive = result.handle_filename_case_sensitive,
            "fetched remote tweaks"
        );

        Ok(result)
    }

    /// Test the connection to CouchDB.
    pub async fn ping(&self) -> anyhow::Result<()> {
        let url = self.db_url();
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            anyhow::bail!("CouchDB ping failed: {status}");
        }
        Ok(())
    }

    // =================================================================
    // Phase 2: Write operations
    // =================================================================

    /// Write a document to CouchDB via PUT.
    ///
    /// If the document already exists, `_rev` must be set to the current
    /// revision to avoid a 409 Conflict.
    pub async fn put_doc<T: serde::Serialize>(
        &self,
        id: &str,
        doc: &T,
    ) -> anyhow::Result<PutResponse> {
        let url = format!("{}/{}", self.db_url(), urlencoding::encode(id));
        let resp = self.client.put(&url).json(doc).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(CouchDBHttpError {
                method: "PUT",
                id: id.to_string(),
                status: status.as_u16(),
                body,
            }.into());
        }

        Ok(resp.json().await?)
    }

    /// Write multiple chunk documents in a single batch via `_bulk_docs`.
    ///
    /// Chunks that already exist (409 conflict) are silently skipped,
    /// since chunk IDs are content-addressed and immutable.
    pub async fn put_chunks(&self, chunks: &[EntryLeaf]) -> anyhow::Result<()> {
        if chunks.is_empty() {
            return Ok(());
        }

        let url = format!("{}/_bulk_docs", self.db_url());
        let body = json!({ "docs": chunks });

        let resp = self.client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("_bulk_docs: {status} — {text}");
        }

        let results: Vec<BulkDocResult> = resp.json().await?;
        for result in &results {
            if let Some(error) = &result.error {
                // 409 conflict is expected for content-addressed chunks
                // that already exist — skip silently.
                if error == "conflict" {
                    continue;
                }
                let reason = result.reason.as_deref().unwrap_or("unknown");
                anyhow::bail!(
                    "failed to write chunk {}: {} — {}",
                    result.id, error, reason
                );
            }
        }

        Ok(())
    }

    /// Delete a document by ID and revision.
    ///
    /// CouchDB requires the current `_rev` to delete a document.
    pub async fn delete_doc(&self, id: &str, rev: &str) -> anyhow::Result<PutResponse> {
        let url = format!("{}/{}", self.db_url(), urlencoding::encode(id));
        let resp = self
            .client
            .delete(&url)
            .query(&[("rev", rev)])
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(CouchDBHttpError {
                method: "DELETE",
                id: id.to_string(),
                status: status.as_u16(),
                body,
            }.into());
        }

        Ok(resp.json().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_tweaks_default() {
        let tweaks = RemoteTweaks::default();
        assert_eq!(tweaks.custom_chunk_size, 0);
        assert_eq!(tweaks.minimum_chunk_size, 20);
        assert_eq!(tweaks.hash_alg, "xxhash64");
        assert!(tweaks.enable_chunk_splitter_v2);
        assert!(!tweaks.use_eden);
        assert!(!tweaks.handle_filename_case_sensitive);
    }

    #[test]
    fn remote_tweaks_piece_size_default() {
        // customChunkSize=0 → 102400 * (0 + 1) = 102400
        let tweaks = RemoteTweaks::default();
        assert_eq!(tweaks.piece_size(), 102_400);
    }

    #[test]
    fn remote_tweaks_piece_size_custom() {
        // customChunkSize=50 → 102400 * 51 = 5_222_400
        let tweaks = RemoteTweaks {
            custom_chunk_size: 50,
            ..Default::default()
        };
        assert_eq!(tweaks.piece_size(), 102_400 * 51);
    }

    #[test]
    fn remote_tweaks_piece_size_small() {
        // customChunkSize=1 → 102400 * 2 = 204800
        let tweaks = RemoteTweaks {
            custom_chunk_size: 1,
            ..Default::default()
        };
        assert_eq!(tweaks.piece_size(), 204_800);
    }

    #[test]
    fn parse_milestone_tweaks_from_json() {
        // Simulate the JSON structure of the milestone document
        let doc: serde_json::Value = serde_json::json!({
            "_id": "_local/obsydian_livesync_milestone",
            "type": "milestoneinfo",
            "created": 1700000000000u64,
            "tweak_values": {
                "device-abc123": {
                    "customChunkSize": 50,
                    "minimumChunkSize": 20,
                    "hashAlg": "xxhash64",
                    "enableChunkSplitterV2": true,
                    "useEden": true,
                    "encrypt": true,
                    "usePathObfuscation": true,
                    "handleFilenameCaseSensitive": true
                }
            }
        });

        let tweaks_map = doc.get("tweak_values").unwrap().as_object().unwrap();
        let first = tweaks_map.values().next().unwrap();

        let custom_chunk_size = first.get("customChunkSize").unwrap().as_u64().unwrap() as usize;
        let minimum_chunk_size = first.get("minimumChunkSize").unwrap().as_u64().unwrap() as usize;
        let hash_alg = first.get("hashAlg").unwrap().as_str().unwrap();
        let enable_v2 = first.get("enableChunkSplitterV2").unwrap().as_bool().unwrap();
        let use_eden = first.get("useEden").unwrap().as_bool().unwrap();
        let case_sensitive = first.get("handleFilenameCaseSensitive").unwrap().as_bool().unwrap();

        assert_eq!(custom_chunk_size, 50);
        assert_eq!(minimum_chunk_size, 20);
        assert_eq!(hash_alg, "xxhash64");
        assert!(enable_v2);
        assert!(use_eden);
        assert!(case_sensitive);

        let tweaks = RemoteTweaks {
            custom_chunk_size,
            minimum_chunk_size,
            hash_alg: hash_alg.to_string(),
            enable_chunk_splitter_v2: enable_v2,
            use_eden,
            handle_filename_case_sensitive: case_sensitive,
        };
        assert_eq!(tweaks.piece_size(), 102_400 * 51);
    }

    #[test]
    fn parse_milestone_missing_optional_fields() {
        // Minimal tweak_values — missing fields should fall back to defaults
        let doc: serde_json::Value = serde_json::json!({
            "tweak_values": {
                "device-xyz": {
                    "customChunkSize": 10
                }
            }
        });

        let tweaks_map = doc.get("tweak_values").unwrap().as_object().unwrap();
        let first = tweaks_map.values().next().unwrap();

        let custom_chunk_size = first.get("customChunkSize")
            .and_then(|v| v.as_u64()).unwrap_or(0) as usize;
        let minimum_chunk_size = first.get("minimumChunkSize")
            .and_then(|v| v.as_u64()).unwrap_or(20) as usize;
        let hash_alg = first.get("hashAlg")
            .and_then(|v| v.as_str()).unwrap_or("xxhash64");
        let enable_v2 = first.get("enableChunkSplitterV2")
            .and_then(|v| v.as_bool()).unwrap_or(true);
        let use_eden = first.get("useEden")
            .and_then(|v| v.as_bool()).unwrap_or(false);
        let case_sensitive = first.get("handleFilenameCaseSensitive")
            .and_then(|v| v.as_bool()).unwrap_or(false);

        assert_eq!(custom_chunk_size, 10);
        assert_eq!(minimum_chunk_size, 20); // default
        assert_eq!(hash_alg, "xxhash64");   // default
        assert!(enable_v2);                  // default
        assert!(!use_eden);                  // default
        assert!(!case_sensitive);            // default

        let tweaks = RemoteTweaks {
            custom_chunk_size,
            minimum_chunk_size,
            hash_alg: hash_alg.to_string(),
            enable_chunk_splitter_v2: enable_v2,
            use_eden,
            handle_filename_case_sensitive: case_sensitive,
        };
        assert_eq!(tweaks.piece_size(), 102_400 * 11);
    }

    #[test]
    fn parse_milestone_empty_tweak_values() {
        let doc: serde_json::Value = serde_json::json!({
            "tweak_values": {}
        });

        let tweaks_map = doc.get("tweak_values").unwrap().as_object().unwrap();
        assert!(tweaks_map.is_empty());
        // Should fall back to defaults
        let tweaks = RemoteTweaks::default();
        assert_eq!(tweaks.piece_size(), 102_400);
    }

    #[test]
    fn parse_milestone_no_tweak_values_key() {
        let doc: serde_json::Value = serde_json::json!({
            "_id": "_local/obsydian_livesync_milestone",
            "created": 1700000000000u64
        });

        assert!(doc.get("tweak_values").is_none());
        let tweaks = RemoteTweaks::default();
        assert_eq!(tweaks.piece_size(), 102_400);
    }
}
