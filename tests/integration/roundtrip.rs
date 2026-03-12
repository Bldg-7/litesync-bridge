use litesync_commonlib::chunk::{self, DisassembleResult, E2EEContext};
use litesync_commonlib::couchdb::RemoteTweaks;
use litesync_commonlib::crypto;
use litesync_commonlib::doc::RawNoteEntry;
use serde_json::json;

use crate::helpers::TestDb;

const TEST_PASSPHRASE: &str = "integration-test-passphrase";
// 32 bytes of deterministic salt for tests.
const TEST_SALT: &[u8; 32] = b"IntegrationTestSalt_0123456789ab";

/// Helper: write a file to CouchDB (disassemble → put_chunks → put parent doc),
/// then read it back (get_doc → resolve_note → reassemble) and verify contents match.
async fn roundtrip_file(
    db: &TestDb,
    filename: &str,
    content: &[u8],
    e2ee: Option<&E2EEContext>,
    tweaks: &RemoteTweaks,
) {
    // --- Write path ---
    let DisassembleResult { chunks, children } = chunk::disassemble(
        content,
        filename,
        tweaks.piece_size(),
        tweaks.minimum_chunk_size,
        e2ee,
        &tweaks.hash_alg,
        &tweaks.chunk_splitter_version,
    )
    .expect("disassemble should succeed");

    // Upload chunks.
    if !chunks.is_empty() {
        db.client.put_chunks(&chunks).await.unwrap();
    }

    // Build parent document.
    let is_binary = !litesync_commonlib::path::is_plain_text(filename);
    let doc_type = if is_binary { "newnote" } else { "plain" };

    let doc_id = format!("file:{}", filename);
    let path_field = if let Some(ctx) = e2ee {
        crypto::encrypt_meta(filename, 1000, 500, content.len() as u64, &children, &ctx.master_key)
            .expect("encrypt_meta should succeed")
    } else {
        filename.to_string()
    };

    let mut doc = json!({
        "_id": &doc_id,
        "type": doc_type,
        "datatype": doc_type,
        "path": &path_field,
        "ctime": 500,
        "mtime": 1000,
        "size": content.len(),
        "children": &children,
        "eden": {},
    });

    if e2ee.is_some() {
        doc["e_"] = json!(true);
    }

    db.client.put_doc(&doc_id, &doc).await.unwrap();

    // --- Read path ---
    let raw: RawNoteEntry = db.client.get_doc(&doc_id).await.unwrap();
    let note = chunk::resolve_note(&raw, e2ee, None).expect("resolve_note should succeed");

    assert_eq!(note.path, filename);
    assert_eq!(note.mtime, 1000);
    assert_eq!(note.ctime, 500);
    assert_eq!(note.children.len(), children.len());

    let reassembled = chunk::reassemble(&db.client, &note, e2ee)
        .await
        .expect("reassemble should succeed");
    assert_eq!(
        reassembled, content,
        "roundtrip content mismatch for {filename}"
    );
}

// ----- Text, no E2EE -----

#[tokio::test]
#[ignore]
async fn test_roundtrip_text_plain() {
    let db = TestDb::new().await;
    let tweaks = RemoteTweaks::default();
    let content = b"# Hello World\n\nThis is a test note.\n";
    roundtrip_file(&db, "hello.md", content, None, &tweaks).await;
}

#[tokio::test]
#[ignore]
async fn test_roundtrip_text_large() {
    let db = TestDb::new().await;
    let tweaks = RemoteTweaks::default();
    // Generate content larger than piece_size to force multiple chunks.
    let line = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.\n";
    let content: String = line.repeat(3000);
    roundtrip_file(&db, "large.md", content.as_bytes(), None, &tweaks).await;
}

// ----- Binary, no E2EE -----

#[tokio::test]
#[ignore]
async fn test_roundtrip_binary_plain() {
    let db = TestDb::new().await;
    let tweaks = RemoteTweaks::default();
    // Fake PNG header + random bytes.
    let mut content = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    content.extend_from_slice(&[0xAB; 256]);
    roundtrip_file(&db, "image.png", &content, None, &tweaks).await;
}

// ----- Text, E2EE -----

#[tokio::test]
#[ignore]
async fn test_roundtrip_text_e2ee() {
    let db = TestDb::new().await;

    let salt_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        TEST_SALT,
    );
    db.seed_e2ee_salt(&salt_b64).await;

    let e2ee = E2EEContext::new(TEST_PASSPHRASE, TEST_SALT);
    let tweaks = RemoteTweaks::default();

    let content = b"# Secret Note\n\nThis is encrypted.\n";
    roundtrip_file(&db, "secret.md", content, Some(&e2ee), &tweaks).await;
}

#[tokio::test]
#[ignore]
async fn test_roundtrip_text_e2ee_large() {
    let db = TestDb::new().await;

    let salt_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        TEST_SALT,
    );
    db.seed_e2ee_salt(&salt_b64).await;

    let e2ee = E2EEContext::new(TEST_PASSPHRASE, TEST_SALT);
    let tweaks = RemoteTweaks::default();

    let line = "Encrypted line with some content for chunk splitting.\n";
    let content: String = line.repeat(3000);
    roundtrip_file(&db, "large-secret.md", content.as_bytes(), Some(&e2ee), &tweaks).await;
}

// ----- Binary, E2EE -----

#[tokio::test]
#[ignore]
async fn test_roundtrip_binary_e2ee() {
    let db = TestDb::new().await;

    let salt_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        TEST_SALT,
    );
    db.seed_e2ee_salt(&salt_b64).await;

    let e2ee = E2EEContext::new(TEST_PASSPHRASE, TEST_SALT);
    let tweaks = RemoteTweaks::default();

    let mut content = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG header
    content.extend_from_slice(&[0xCD; 512]);
    roundtrip_file(&db, "photo.jpg", &content, Some(&e2ee), &tweaks).await;
}

// ----- Rabin-Karp V3 splitter -----

#[tokio::test]
#[ignore]
async fn test_roundtrip_rabin_karp_text() {
    let db = TestDb::new().await;
    let mut tweaks = RemoteTweaks::default();
    tweaks.chunk_splitter_version = "v3-rabin-karp".to_string();

    let line = "Rabin-Karp content-defined chunking test line.\n";
    let content: String = line.repeat(3000);
    roundtrip_file(&db, "rabin.md", content.as_bytes(), None, &tweaks).await;
}

#[tokio::test]
#[ignore]
async fn test_roundtrip_rabin_karp_e2ee() {
    let db = TestDb::new().await;

    let salt_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        TEST_SALT,
    );
    db.seed_e2ee_salt(&salt_b64).await;

    let e2ee = E2EEContext::new(TEST_PASSPHRASE, TEST_SALT);
    let mut tweaks = RemoteTweaks::default();
    tweaks.chunk_splitter_version = "v3-rabin-karp".to_string();

    let line = "Encrypted Rabin-Karp chunking test.\n";
    let content: String = line.repeat(3000);
    roundtrip_file(&db, "rabin-secret.md", content.as_bytes(), Some(&e2ee), &tweaks).await;
}

// ----- Soft delete -----

#[tokio::test]
#[ignore]
async fn test_soft_delete() {
    let db = TestDb::new().await;
    let tweaks = RemoteTweaks::default();

    let content = b"To be deleted\n";
    roundtrip_file(&db, "delete-me.md", content, None, &tweaks).await;

    // Soft-delete: PUT with deleted flag.
    let doc_id = "file:delete-me.md";
    let raw: RawNoteEntry = db.client.get_doc(doc_id).await.unwrap();
    let rev = raw._rev.as_deref().unwrap();

    let delete_doc = json!({
        "_id": doc_id,
        "_rev": rev,
        "type": "newnote",
        "path": "delete-me.md",
        "ctime": 0,
        "mtime": 0,
        "size": 0,
        "children": [],
        "eden": {},
        "deleted": true,
        "data": "",
    });
    db.client.put_doc(doc_id, &delete_doc).await.unwrap();

    // Read back and verify deleted.
    let raw2: RawNoteEntry = db.client.get_doc(doc_id).await.unwrap();
    let note = chunk::resolve_note(&raw2, None, None).unwrap();
    assert!(note.deleted, "note should be marked as deleted");
}

// ----- Hash algorithm variants -----

#[tokio::test]
#[ignore]
async fn test_roundtrip_xxhash32() {
    let db = TestDb::new().await;
    let mut tweaks = RemoteTweaks::default();
    tweaks.hash_alg = "xxhash32".to_string();

    let content = b"# xxhash32 test\n";
    roundtrip_file(&db, "xxhash32.md", content, None, &tweaks).await;
}

#[tokio::test]
#[ignore]
async fn test_roundtrip_sha1() {
    let db = TestDb::new().await;
    let mut tweaks = RemoteTweaks::default();
    tweaks.hash_alg = "sha1".to_string();

    let content = b"# sha1 test\n";
    roundtrip_file(&db, "sha1-test.md", content, None, &tweaks).await;
}

#[tokio::test]
#[ignore]
async fn test_roundtrip_mixed_purejs() {
    let db = TestDb::new().await;
    let mut tweaks = RemoteTweaks::default();
    tweaks.hash_alg = "mixed-purejs".to_string();

    let content = b"# mixed-purejs test\n";
    roundtrip_file(&db, "mixed.md", content, None, &tweaks).await;
}

// ----- Unicode content -----

#[tokio::test]
#[ignore]
async fn test_roundtrip_unicode_e2ee() {
    let db = TestDb::new().await;

    let salt_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        TEST_SALT,
    );
    db.seed_e2ee_salt(&salt_b64).await;

    let e2ee = E2EEContext::new(TEST_PASSPHRASE, TEST_SALT);
    let tweaks = RemoteTweaks::default();

    let content = "# 한국어 테스트\n\n이것은 유니코드 노트입니다. 🎉\nEmoji와 CJK 문자를 포함합니다.\n";
    roundtrip_file(&db, "유니코드.md", content.as_bytes(), Some(&e2ee), &tweaks).await;
}

// ----- Empty file -----

#[tokio::test]
#[ignore]
async fn test_roundtrip_empty_file() {
    let db = TestDb::new().await;
    let tweaks = RemoteTweaks::default();
    roundtrip_file(&db, "empty.md", b"", None, &tweaks).await;
}
