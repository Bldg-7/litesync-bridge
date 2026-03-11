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
