use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::doc::{DecryptedMeta, ENCRYPTED_META_PREFIX};

// --- Constants ---

const IV_LENGTH: usize = 12;
const PBKDF2_ITERATIONS: u32 = 310_000;
const HKDF_SALT_LENGTH: usize = 32;
const PBKDF2_SALT_LENGTH: usize = 32;

/// Prefix for HKDF-encrypted data with external pbkdf2Salt.
/// Binary layout: iv(12) | hkdfSalt(32) | ciphertext+tag
const HKDF_ENCRYPTED_PREFIX: &str = "%=";

/// Prefix for HKDF-encrypted data with embedded pbkdf2Salt.
/// Binary layout: pbkdf2Salt(32) | iv(12) | hkdfSalt(32) | ciphertext+tag
const HKDF_SALTED_ENCRYPTED_PREFIX: &str = "%$";

// --- Key Derivation ---

/// Derive a 256-bit master key from a passphrase using PBKDF2-HMAC-SHA256.
///
/// This is expensive (310k iterations). Callers should cache the result
/// rather than calling per-chunk (see `E2EEContext::new`).
pub fn derive_master_key(passphrase: &str, pbkdf2_salt: &[u8]) -> [u8; 32] {
    let mut master_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        passphrase.as_bytes(),
        pbkdf2_salt,
        PBKDF2_ITERATIONS,
        &mut master_key,
    );
    master_key
}

/// Derive a per-chunk AES-256-GCM key from the master key using HKDF-SHA256.
fn derive_chunk_key(master_key: &[u8], hkdf_salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), master_key);
    let mut chunk_key = [0u8; 32];
    hk.expand(&[], &mut chunk_key)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {e}"))?;
    Ok(chunk_key)
}

// --- AES-GCM ---

fn decrypt_aes_gcm(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {e}"))
}

// --- Public API ---

/// Decrypt HKDF-encrypted string with a pre-derived master key (prefix `%=`).
///
/// Used for chunk data and metadata when the pbkdf2Salt is stored separately.
/// The `master_key` should be obtained from `derive_master_key()` once and cached.
pub fn decrypt_hkdf(input: &str, master_key: &[u8; 32]) -> anyhow::Result<String> {
    let encoded = input
        .strip_prefix(HKDF_ENCRYPTED_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("expected prefix '{HKDF_ENCRYPTED_PREFIX}'"))?;

    let binary = BASE64.decode(encoded)?;
    if binary.len() < IV_LENGTH + HKDF_SALT_LENGTH {
        anyhow::bail!("encrypted data too short");
    }

    let iv = &binary[..IV_LENGTH];
    let hkdf_salt = &binary[IV_LENGTH..IV_LENGTH + HKDF_SALT_LENGTH];
    let ciphertext = &binary[IV_LENGTH + HKDF_SALT_LENGTH..];

    let chunk_key = derive_chunk_key(master_key, hkdf_salt)?;
    let plaintext = decrypt_aes_gcm(&chunk_key, iv, ciphertext)?;

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("invalid UTF-8: {e}"))
}

/// Decrypt HKDF-encrypted string with embedded pbkdf2Salt (prefix `%$`).
///
/// Used for metadata encryption where the salt is stored alongside the ciphertext.
/// Derives its own master key from the embedded salt (cannot use cached key).
pub fn decrypt_with_ephemeral_salt(input: &str, passphrase: &str) -> anyhow::Result<String> {
    let encoded = input
        .strip_prefix(HKDF_SALTED_ENCRYPTED_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("expected prefix '{HKDF_SALTED_ENCRYPTED_PREFIX}'"))?;

    let binary = BASE64.decode(encoded)?;
    let min_len = PBKDF2_SALT_LENGTH + IV_LENGTH + HKDF_SALT_LENGTH;
    if binary.len() < min_len {
        anyhow::bail!("encrypted data too short");
    }

    let pbkdf2_salt = &binary[..PBKDF2_SALT_LENGTH];
    let iv = &binary[PBKDF2_SALT_LENGTH..PBKDF2_SALT_LENGTH + IV_LENGTH];
    let hkdf_salt =
        &binary[PBKDF2_SALT_LENGTH + IV_LENGTH..PBKDF2_SALT_LENGTH + IV_LENGTH + HKDF_SALT_LENGTH];
    let ciphertext = &binary[PBKDF2_SALT_LENGTH + IV_LENGTH + HKDF_SALT_LENGTH..];

    let master_key = derive_master_key(passphrase, pbkdf2_salt);
    let chunk_key = derive_chunk_key(&master_key, hkdf_salt)?;
    let plaintext = decrypt_aes_gcm(&chunk_key, iv, ciphertext)?;

    String::from_utf8(plaintext).map_err(|e| anyhow::anyhow!("invalid UTF-8: {e}"))
}

/// Detect encryption format and decrypt accordingly.
///
/// For `%=` prefix: uses the pre-derived `master_key` (fast path).
/// For `%$` prefix: derives a new master key from embedded salt (slow path).
pub fn decrypt_string(
    input: &str,
    master_key: &[u8; 32],
    passphrase: &str,
) -> anyhow::Result<String> {
    if input.starts_with(HKDF_SALTED_ENCRYPTED_PREFIX) {
        decrypt_with_ephemeral_salt(input, passphrase)
    } else if input.starts_with(HKDF_ENCRYPTED_PREFIX) {
        decrypt_hkdf(input, master_key)
    } else {
        anyhow::bail!("unsupported encryption format")
    }
}

/// Decrypt the encrypted metadata from a note's `path` field.
///
/// When E2EE is enabled, the path field contains `/\:` followed by the
/// encrypted JSON of `{path, mtime, ctime, size, children}`.
pub fn decrypt_meta(
    path_field: &str,
    master_key: &[u8; 32],
    passphrase: &str,
) -> anyhow::Result<DecryptedMeta> {
    let encrypted = path_field.strip_prefix(ENCRYPTED_META_PREFIX).ok_or_else(|| {
        anyhow::anyhow!("path is not encrypted (no '{ENCRYPTED_META_PREFIX}' prefix)")
    })?;

    let json_str = decrypt_string(encrypted, master_key, passphrase)?;
    let meta: DecryptedMeta = serde_json::from_str(&json_str)?;
    Ok(meta)
}

/// Decrypt chunk data (EntryLeaf.data field).
pub fn decrypt_leaf_data(
    data: &str,
    master_key: &[u8; 32],
    passphrase: &str,
) -> anyhow::Result<String> {
    decrypt_string(data, master_key, passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    // =====================================================================
    // Test helpers: encrypt functions (mirror decryption for roundtrips)
    // =====================================================================

    /// Encrypt plaintext in `%=` format (external PBKDF2 salt).
    /// Layout: "%=" + base64(iv(12) | hkdf_salt(32) | ciphertext+tag)
    fn encrypt_hkdf(plaintext: &str, master_key: &[u8; 32], iv: &[u8; 12], hkdf_salt: &[u8; 32]) -> String {
        let chunk_key = derive_chunk_key(master_key, hkdf_salt).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&chunk_key));
        let nonce = Nonce::from_slice(iv);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();

        let mut binary = Vec::with_capacity(IV_LENGTH + HKDF_SALT_LENGTH + ciphertext.len());
        binary.extend_from_slice(iv);
        binary.extend_from_slice(hkdf_salt);
        binary.extend_from_slice(&ciphertext);

        format!("{}{}", HKDF_ENCRYPTED_PREFIX, BASE64.encode(&binary))
    }

    /// Encrypt plaintext in `%$` format (embedded PBKDF2 salt).
    /// Layout: "%$" + base64(pbkdf2_salt(32) | iv(12) | hkdf_salt(32) | ciphertext+tag)
    fn encrypt_ephemeral(
        plaintext: &str,
        passphrase: &str,
        pbkdf2_salt: &[u8; 32],
        iv: &[u8; 12],
        hkdf_salt: &[u8; 32],
    ) -> String {
        let master_key = derive_master_key(passphrase, pbkdf2_salt);
        let chunk_key = derive_chunk_key(&master_key, hkdf_salt).unwrap();
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&chunk_key));
        let nonce = Nonce::from_slice(iv);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes()).unwrap();

        let mut binary = Vec::with_capacity(PBKDF2_SALT_LENGTH + IV_LENGTH + HKDF_SALT_LENGTH + ciphertext.len());
        binary.extend_from_slice(pbkdf2_salt);
        binary.extend_from_slice(iv);
        binary.extend_from_slice(hkdf_salt);
        binary.extend_from_slice(&ciphertext);

        format!("{}{}", HKDF_SALTED_ENCRYPTED_PREFIX, BASE64.encode(&binary))
    }

    // Fixed test values (deterministic, not random).
    const TEST_PASSPHRASE: &str = "test-passphrase-for-unit-tests";
    const TEST_PBKDF2_SALT: [u8; 32] = [0xAA; 32];
    const TEST_IV: [u8; 12] = [0xBB; 12];
    const TEST_HKDF_SALT: [u8; 32] = [0xCC; 32];

    fn test_master_key() -> [u8; 32] {
        derive_master_key(TEST_PASSPHRASE, &TEST_PBKDF2_SALT)
    }

    // =====================================================================
    // Key derivation
    // =====================================================================

    #[test]
    fn test_derive_master_key_deterministic() {
        let key1 = derive_master_key("passphrase", &[1u8; 32]);
        let key2 = derive_master_key("passphrase", &[1u8; 32]);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_master_key_different_passphrase() {
        let key1 = derive_master_key("passphrase_a", &[1u8; 32]);
        let key2 = derive_master_key("passphrase_b", &[1u8; 32]);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_master_key_different_salt() {
        let key1 = derive_master_key("passphrase", &[1u8; 32]);
        let key2 = derive_master_key("passphrase", &[2u8; 32]);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_chunk_key_deterministic() {
        let master = [0x11u8; 32];
        let salt = [0x22u8; 32];
        let key1 = derive_chunk_key(&master, &salt).unwrap();
        let key2 = derive_chunk_key(&master, &salt).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_chunk_key_different_salt() {
        let master = [0x11u8; 32];
        let key1 = derive_chunk_key(&master, &[0x22u8; 32]).unwrap();
        let key2 = derive_chunk_key(&master, &[0x33u8; 32]).unwrap();
        assert_ne!(key1, key2);
    }

    // =====================================================================
    // Encrypt → Decrypt roundtrips
    // =====================================================================

    #[test]
    fn test_roundtrip_hkdf_format() {
        let master_key = test_master_key();
        let plaintext = "hello, world!";
        let encrypted = encrypt_hkdf(plaintext, &master_key, &TEST_IV, &TEST_HKDF_SALT);

        assert!(encrypted.starts_with("%="));
        let decrypted = decrypt_hkdf(&encrypted, &master_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_roundtrip_hkdf_unicode() {
        let master_key = test_master_key();
        let plaintext = "한글 테스트 🔑 émojis";
        let encrypted = encrypt_hkdf(plaintext, &master_key, &TEST_IV, &TEST_HKDF_SALT);
        let decrypted = decrypt_hkdf(&encrypted, &master_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_roundtrip_hkdf_empty_string() {
        let master_key = test_master_key();
        let encrypted = encrypt_hkdf("", &master_key, &TEST_IV, &TEST_HKDF_SALT);
        let decrypted = decrypt_hkdf(&encrypted, &master_key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_roundtrip_ephemeral_format() {
        let plaintext = "ephemeral salt data";
        let encrypted = encrypt_ephemeral(
            plaintext, TEST_PASSPHRASE, &TEST_PBKDF2_SALT, &TEST_IV, &TEST_HKDF_SALT,
        );

        assert!(encrypted.starts_with("%$"));
        let decrypted = decrypt_with_ephemeral_salt(&encrypted, TEST_PASSPHRASE).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_roundtrip_different_iv_produces_different_ciphertext() {
        let master_key = test_master_key();
        let plaintext = "same plaintext";
        let enc1 = encrypt_hkdf(plaintext, &master_key, &[0x01; 12], &TEST_HKDF_SALT);
        let enc2 = encrypt_hkdf(plaintext, &master_key, &[0x02; 12], &TEST_HKDF_SALT);
        // Different ciphertext but same plaintext.
        assert_ne!(enc1, enc2);
        assert_eq!(decrypt_hkdf(&enc1, &master_key).unwrap(), plaintext);
        assert_eq!(decrypt_hkdf(&enc2, &master_key).unwrap(), plaintext);
    }

    // =====================================================================
    // decrypt_string dispatch
    // =====================================================================

    #[test]
    fn test_decrypt_string_dispatches_hkdf() {
        let master_key = test_master_key();
        let encrypted = encrypt_hkdf("test", &master_key, &TEST_IV, &TEST_HKDF_SALT);
        let result = decrypt_string(&encrypted, &master_key, TEST_PASSPHRASE).unwrap();
        assert_eq!(result, "test");
    }

    #[test]
    fn test_decrypt_string_dispatches_ephemeral() {
        let encrypted = encrypt_ephemeral(
            "test", TEST_PASSPHRASE, &TEST_PBKDF2_SALT, &TEST_IV, &TEST_HKDF_SALT,
        );
        let dummy_key = [0u8; 32]; // not used for %$ format
        let result = decrypt_string(&encrypted, &dummy_key, TEST_PASSPHRASE).unwrap();
        assert_eq!(result, "test");
    }

    #[test]
    fn test_decrypt_string_unsupported_format() {
        let master_key = test_master_key();
        let result = decrypt_string("plain text", &master_key, "pp");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }

    // =====================================================================
    // decrypt_meta
    // =====================================================================

    #[test]
    fn test_decrypt_meta_roundtrip() {
        let master_key = test_master_key();
        let meta_json = r#"{"path":"notes/hello.md","mtime":1000,"ctime":900,"size":42,"children":["h:abc","h:def"]}"#;
        let encrypted = encrypt_hkdf(meta_json, &master_key, &TEST_IV, &TEST_HKDF_SALT);
        let path_field = format!("{}{}", ENCRYPTED_META_PREFIX, encrypted);

        let meta = decrypt_meta(&path_field, &master_key, TEST_PASSPHRASE).unwrap();
        assert_eq!(meta.path, "notes/hello.md");
        assert_eq!(meta.mtime, 1000);
        assert_eq!(meta.ctime, 900);
        assert_eq!(meta.size, 42);
        assert_eq!(meta.children, vec!["h:abc", "h:def"]);
    }

    #[test]
    fn test_decrypt_meta_no_children() {
        let master_key = test_master_key();
        let meta_json = r#"{"path":"test.md","mtime":0,"ctime":0,"size":0}"#;
        let encrypted = encrypt_hkdf(meta_json, &master_key, &TEST_IV, &TEST_HKDF_SALT);
        let path_field = format!("{}{}", ENCRYPTED_META_PREFIX, encrypted);

        let meta = decrypt_meta(&path_field, &master_key, TEST_PASSPHRASE).unwrap();
        assert_eq!(meta.path, "test.md");
        assert!(meta.children.is_empty());
    }

    #[test]
    fn test_decrypt_meta_missing_prefix() {
        let master_key = test_master_key();
        let result = decrypt_meta("notes/hello.md", &master_key, "pp");
        assert!(result.is_err());
    }

    // =====================================================================
    // Error cases
    // =====================================================================

    #[test]
    fn test_decrypt_hkdf_wrong_key() {
        let master_key = test_master_key();
        let encrypted = encrypt_hkdf("secret", &master_key, &TEST_IV, &TEST_HKDF_SALT);
        let wrong_key = [0xFFu8; 32];
        let result = decrypt_hkdf(&encrypted, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hkdf_wrong_prefix() {
        let result = decrypt_hkdf("not-encrypted", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_hkdf_too_short() {
        // Valid prefix + base64 but too few bytes for iv+salt.
        let short = format!("%={}", BASE64.encode(&[0u8; 10]));
        let result = decrypt_hkdf(&short, &[0u8; 32]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_decrypt_ephemeral_too_short() {
        let short = format!("%${}", BASE64.encode(&[0u8; 40]));
        let result = decrypt_with_ephemeral_salt(&short, "pp");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_decrypt_hkdf_corrupted_ciphertext() {
        let master_key = test_master_key();
        let encrypted = encrypt_hkdf("data", &master_key, &TEST_IV, &TEST_HKDF_SALT);
        // Corrupt one byte in the base64 payload.
        let mut bytes: Vec<u8> = BASE64.decode(&encrypted[2..]).unwrap();
        if let Some(b) = bytes.last_mut() {
            *b ^= 0xFF;
        }
        let corrupted = format!("%={}", BASE64.encode(&bytes));
        let result = decrypt_hkdf(&corrupted, &master_key);
        assert!(result.is_err());
    }
}
