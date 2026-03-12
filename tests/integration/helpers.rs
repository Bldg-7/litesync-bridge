use std::sync::atomic::{AtomicU32, Ordering};

use litesync_commonlib::couchdb::CouchDBClient;

/// Default CouchDB connection for docker-compose test environment.
const COUCHDB_URL: &str = "http://localhost:5984";
const COUCHDB_USER: &str = "admin";
const COUCHDB_PASS: &str = "test";

/// Atomic counter for unique test DB names.
static DB_COUNTER: AtomicU32 = AtomicU32::new(0);

/// A test database that is created on setup and deleted on drop.
pub struct TestDb {
    pub client: CouchDBClient,
    pub db_name: String,
    admin_client: reqwest::Client,
    base_url: String,
}

impl TestDb {
    /// Create a fresh test database with a unique name.
    pub async fn new() -> Self {
        let base_url = std::env::var("LITESYNC_TEST_URL")
            .unwrap_or_else(|_| COUCHDB_URL.to_string());
        let user = std::env::var("LITESYNC_TEST_USER")
            .unwrap_or_else(|_| COUCHDB_USER.to_string());
        let pass = std::env::var("LITESYNC_TEST_PASS")
            .unwrap_or_else(|_| COUCHDB_PASS.to_string());

        let seq = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let db_name = format!("litesync_test_{}_{}", pid, seq);

        // Build admin reqwest client for DB create/delete.
        let admin_client = reqwest::Client::new();

        // Create the database.
        let resp = admin_client
            .put(format!("{}/{}", base_url, db_name))
            .basic_auth(&user, Some(&pass))
            .send()
            .await
            .expect("failed to create test database");
        assert!(
            resp.status().is_success(),
            "failed to create DB {}: {}",
            db_name,
            resp.status()
        );

        let client = CouchDBClient::new(&base_url, &db_name, &user, &pass)
            .expect("failed to create CouchDBClient");

        Self {
            client,
            db_name,
            admin_client,
            base_url,
        }
    }

    /// Seed the `_local/obsidian_livesync_sync_parameters` document with a
    /// PBKDF2 salt, enabling E2EE tests.
    pub async fn seed_e2ee_salt(&self, salt_b64: &str) {
        let user = std::env::var("LITESYNC_TEST_USER")
            .unwrap_or_else(|_| COUCHDB_USER.to_string());
        let pass = std::env::var("LITESYNC_TEST_PASS")
            .unwrap_or_else(|_| COUCHDB_PASS.to_string());

        let url = format!(
            "{}/{}/_local/obsidian_livesync_sync_parameters",
            self.base_url, self.db_name
        );
        let body = serde_json::json!({
            "_id": "_local/obsidian_livesync_sync_parameters",
            "pbkdf2salt": salt_b64,
        });
        let resp = self.admin_client
            .put(&url)
            .basic_auth(&user, Some(&pass))
            .json(&body)
            .send()
            .await
            .expect("failed to seed e2ee salt");
        assert!(
            resp.status().is_success(),
            "failed to seed e2ee salt: {}",
            resp.status()
        );
    }

    /// Seed the `_local/obsydian_livesync_milestone` document with remote tweaks.
    pub async fn seed_tweaks(&self, tweaks: &serde_json::Value) {
        let user = std::env::var("LITESYNC_TEST_USER")
            .unwrap_or_else(|_| COUCHDB_USER.to_string());
        let pass = std::env::var("LITESYNC_TEST_PASS")
            .unwrap_or_else(|_| COUCHDB_PASS.to_string());

        let url = format!(
            "{}/{}/_local/obsydian_livesync_milestone",
            self.base_url, self.db_name
        );
        let body = serde_json::json!({
            "_id": "_local/obsydian_livesync_milestone",
            "tweak_values": {
                "test_device": tweaks,
            },
        });
        let resp = self.admin_client
            .put(&url)
            .basic_auth(&user, Some(&pass))
            .json(&body)
            .send()
            .await
            .expect("failed to seed tweaks");
        assert!(
            resp.status().is_success(),
            "failed to seed tweaks: {}",
            resp.status()
        );
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Fire-and-forget DB deletion. We use a blocking reqwest call since
        // Drop is sync. In test context this is fine.
        let url = format!("{}/{}", self.base_url, self.db_name);
        let user = std::env::var("LITESYNC_TEST_USER")
            .unwrap_or_else(|_| COUCHDB_USER.to_string());
        let pass = std::env::var("LITESYNC_TEST_PASS")
            .unwrap_or_else(|_| COUCHDB_PASS.to_string());

        // Spawn a blocking thread for cleanup — best-effort.
        let _ = std::thread::spawn(move || {
            let client = reqwest::blocking::Client::new();
            let _ = client
                .delete(&url)
                .basic_auth(&user, Some(&pass))
                .send();
        })
        .join();
    }
}
