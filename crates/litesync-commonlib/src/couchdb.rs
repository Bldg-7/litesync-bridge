use std::time::Duration;

use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::doc::{AllDocsResponse, ChangesResponse, EntryLeaf, TYPE_LEAF};

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
            anyhow::bail!("GET {id}: {status} — {body}");
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

    /// Fetch all note documents (non-leaf) from the database.
    pub async fn get_all_notes(&self) -> anyhow::Result<ChangesResponse> {
        self.get_changes("0", None).await
    }

    /// Fetch the PBKDF2 salt from the LiveSync config document.
    ///
    /// Self-hosted LiveSync stores the E2EE salt in `_local/obsidian-livesync-config`
    /// (or `_local/obsidian-livesync`) under the `encryptedPassphraseSalt` field.
    pub async fn get_e2ee_salt(&self) -> anyhow::Result<Vec<u8>> {
        // Try the modern config document first, then the legacy one.
        let config_ids = [
            "_local/obsidian-livesync-config",
            "_local/obsidian-livesync",
        ];

        for config_id in &config_ids {
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
}
