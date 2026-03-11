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
    pub fn new(base_url: &str, database: &str, username: &str, password: &str) -> Self {
        let client = Client::builder()
            .danger_accept_invalid_certs(false)
            .build()
            .expect("failed to build HTTP client");

        // Encode credentials into the base URL for Basic Auth.
        let url = base_url.trim_end_matches('/');
        let auth_url = if let Some(rest) = url.strip_prefix("https://") {
            format!("https://{username}:{password}@{rest}")
        } else if let Some(rest) = url.strip_prefix("http://") {
            format!("http://{username}:{password}@{rest}")
        } else {
            format!("https://{username}:{password}@{url}")
        };

        Self {
            base_url: auth_url,
            database: database.to_string(),
            client,
        }
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
        let chunks = result
            .rows
            .into_iter()
            .filter_map(|row| row.doc)
            .collect();

        Ok(chunks)
    }

    /// Fetch all note documents (non-leaf) from the database.
    pub async fn get_all_notes(&self) -> anyhow::Result<ChangesResponse> {
        self.get_changes("0", None).await
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
