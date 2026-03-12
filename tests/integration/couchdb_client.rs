use litesync_commonlib::couchdb::RemoteTweaks;
use litesync_commonlib::doc::{EntryLeaf, TYPE_LEAF};
use serde_json::json;

use crate::helpers::TestDb;

#[tokio::test]
#[ignore]
async fn test_ping() {
    let db = TestDb::new().await;
    db.client.ping().await.expect("ping should succeed");
}

#[tokio::test]
#[ignore]
async fn test_get_changes_empty_db() {
    let db = TestDb::new().await;
    let resp = db.client.get_changes("0", None).await.unwrap();
    assert!(resp.results.is_empty(), "empty DB should have no changes");
}

#[tokio::test]
#[ignore]
async fn test_get_all_notes_empty_db() {
    let db = TestDb::new().await;
    let resp = db.client.get_all_notes().await.unwrap();
    assert!(resp.results.is_empty(), "empty DB should have no notes");
}

#[tokio::test]
#[ignore]
async fn test_put_and_get_doc() {
    let db = TestDb::new().await;

    let doc = json!({
        "_id": "test-doc",
        "type": "plain",
        "path": "hello.md",
        "ctime": 1000,
        "mtime": 2000,
        "size": 5,
        "children": ["h:chunk1"],
        "eden": {},
    });

    let put_resp = db.client.put_doc("test-doc", &doc).await.unwrap();
    assert!(put_resp.ok);
    assert_eq!(put_resp.id, "test-doc");
    assert!(!put_resp.rev.is_empty());

    // Read it back.
    let fetched: serde_json::Value = db.client.get_doc("test-doc").await.unwrap();
    assert_eq!(fetched["path"], "hello.md");
    assert_eq!(fetched["mtime"], 2000);
}

#[tokio::test]
#[ignore]
async fn test_put_and_get_chunks() {
    let db = TestDb::new().await;

    let chunks = vec![
        EntryLeaf {
            _id: "h:chunk1".into(),
            _rev: None,
            type_: TYPE_LEAF.into(),
            data: "SGVsbG8=".into(), // base64("Hello")
            is_corrupted: None,
            e_encrypted: None,
        },
        EntryLeaf {
            _id: "h:chunk2".into(),
            _rev: None,
            type_: TYPE_LEAF.into(),
            data: "V29ybGQ=".into(), // base64("World")
            is_corrupted: None,
            e_encrypted: None,
        },
    ];

    db.client.put_chunks(&chunks).await.unwrap();

    // Fetch them back.
    let ids = vec!["h:chunk1".into(), "h:chunk2".into()];
    let fetched = db.client.get_chunks(&ids).await.unwrap();
    assert_eq!(fetched.len(), 2);
    assert_eq!(fetched[0].data, "SGVsbG8=");
    assert_eq!(fetched[1].data, "V29ybGQ=");
}

#[tokio::test]
#[ignore]
async fn test_put_chunks_idempotent() {
    let db = TestDb::new().await;

    let chunk = EntryLeaf {
        _id: "h:dup".into(),
        _rev: None,
        type_: TYPE_LEAF.into(),
        data: "QUJD".into(),
        is_corrupted: None,
        e_encrypted: None,
    };

    // Put twice — second should silently skip (409 conflict is OK for chunks).
    db.client.put_chunks(&[chunk.clone()]).await.unwrap();
    db.client.put_chunks(&[chunk]).await.unwrap();

    let fetched = db.client.get_chunks(&["h:dup".into()]).await.unwrap();
    assert_eq!(fetched.len(), 1);
    assert_eq!(fetched[0].data, "QUJD");
}

#[tokio::test]
#[ignore]
async fn test_delete_doc() {
    let db = TestDb::new().await;

    let doc = json!({
        "_id": "to-delete",
        "type": "plain",
        "path": "bye.md",
        "ctime": 0,
        "mtime": 0,
        "size": 0,
        "children": [],
        "eden": {},
    });

    let put_resp = db.client.put_doc("to-delete", &doc).await.unwrap();
    let del_resp = db.client.delete_doc("to-delete", &put_resp.rev).await.unwrap();
    assert!(del_resp.ok);

    // Should be gone.
    let result: Result<serde_json::Value, _> = db.client.get_doc("to-delete").await;
    assert!(result.is_err(), "deleted doc should not be fetchable");
}

#[tokio::test]
#[ignore]
async fn test_changes_after_put() {
    let db = TestDb::new().await;

    let doc = json!({
        "_id": "change-test",
        "type": "plain",
        "path": "test.md",
        "ctime": 100,
        "mtime": 200,
        "size": 3,
        "children": [],
        "eden": {},
    });
    db.client.put_doc("change-test", &doc).await.unwrap();

    let resp = db.client.get_changes("0", None).await.unwrap();
    let note_changes: Vec<_> = resp
        .results
        .iter()
        .filter(|r| r.id == "change-test")
        .collect();
    assert_eq!(note_changes.len(), 1, "should see one change for our doc");
}

#[tokio::test]
#[ignore]
async fn test_get_e2ee_salt() {
    let db = TestDb::new().await;

    let salt_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"0123456789abcdef0123456789abcdef",
    );
    db.seed_e2ee_salt(&salt_b64).await;

    let salt = db.client.get_e2ee_salt().await.unwrap();
    assert_eq!(salt, b"0123456789abcdef0123456789abcdef");
}

#[tokio::test]
#[ignore]
async fn test_get_remote_tweaks() {
    let db = TestDb::new().await;

    db.seed_tweaks(&json!({
        "customChunkSize": 2,
        "minimumChunkSize": 10,
        "hashAlg": "xxhash64",
        "enableChunkSplitterV2": true,
        "useEden": true,
        "handleFilenameCaseSensitive": true,
        "chunkSplitterVersion": "v3-rabin-karp",
    }))
    .await;

    let tweaks = db.client.get_remote_tweaks().await.unwrap();
    assert_eq!(tweaks.custom_chunk_size, 2);
    assert_eq!(tweaks.minimum_chunk_size, 10);
    assert_eq!(tweaks.hash_alg, "xxhash64");
    assert!(tweaks.enable_chunk_splitter_v2);
    assert!(tweaks.use_eden);
    assert!(tweaks.handle_filename_case_sensitive);
    assert_eq!(tweaks.chunk_splitter_version, "v3-rabin-karp");
    assert_eq!(tweaks.piece_size(), 102_400 * 3); // (2 + 1) * MAX_DOC_SIZE_BIN
}

#[tokio::test]
#[ignore]
async fn test_get_remote_tweaks_defaults() {
    let db = TestDb::new().await;
    // No milestone document seeded — should return defaults.
    let tweaks = db.client.get_remote_tweaks().await.unwrap();
    let defaults = RemoteTweaks::default();
    assert_eq!(tweaks.custom_chunk_size, defaults.custom_chunk_size);
    assert_eq!(tweaks.hash_alg, defaults.hash_alg);
    assert_eq!(tweaks.minimum_chunk_size, defaults.minimum_chunk_size);
}
