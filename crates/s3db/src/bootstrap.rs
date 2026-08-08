//! Per-bucket encryption bootstrap.
//!
//! The first time a bucket is used, this layer generates a random
//! derivation salt and stores it **unencrypted** at `.conf/encryption.json`
//! (the only object in the bucket that stays in the clear on purpose: a
//! salt isn't secret, and it needs to be readable before the key that
//! decrypts everything else can be derived). Future instances read that
//! salt, derive the same key with the passphrase from local config (never
//! from the bucket), and verify it against a witness value: that way a
//! mistyped passphrase gives a clear error at startup, instead of decrypt
//! failures scattered throughout the code mid-operation.

use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy, SALT_LEN};
use crate::payload::{get_json_plain, put_json_plain};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

const ENCRYPTION_META_KEY: &str = ".conf/encryption.json";
/// Known plaintext sealed with the derived key, to validate it right at
/// startup instead of the first real decrypt error being indistinguishable
/// from "the data is corrupt".
const VERIFIER_PLAINTEXT: &[u8] = b"gits3bridge-verifier-v1";
const VERIFIER_AAD: &str = ".conf/encryption.json#verifier";
/// Retries for a race on the bucket's first use (two instances trying to
/// create `.conf/encryption.json` at the same time).
const MAX_BOOTSTRAP_RETRIES: u32 = 5;

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
struct EncryptionMeta {
    #[serde(default)]
    salt: String,
    #[serde(default)]
    verifier: String,
}

/// Derives (or creates, if the bucket is new) this bucket's cipher.
pub async fn get_or_create_cipher(backend: &dyn Backend, passphrase: &str) -> Result<Cipher> {
    for _ in 0..MAX_BOOTSTRAP_RETRIES {
        let (meta, etag) = get_json_plain::<EncryptionMeta>(backend, ENCRYPTION_META_KEY).await?;

        if etag.is_none() {
            // New bucket (or nothing encrypted yet): we generate the salt.
            let salt = random_salt()?;
            let cipher = Cipher::derive(passphrase, &salt)?;
            let meta = EncryptionMeta {
                salt: BASE64.encode(salt),
                verifier: BASE64.encode(cipher.seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)),
            };
            match put_json_plain(backend, ENCRYPTION_META_KEY, &meta, None).await? {
                Cas::Ok => return Ok(cipher),
                // Another instance started at the same time and created the
                // bucket first: we discard ours and use the one that won.
                Cas::Conflict => continue,
            }
        }

        return derive_and_verify(passphrase, &meta);
    }
    bail!("couldn't initialize bucket encryption after several attempts (high contention)")
}

fn derive_and_verify(passphrase: &str, meta: &EncryptionMeta) -> Result<Cipher> {
    let salt_bytes = BASE64
        .decode(&meta.salt)
        .context(".conf/encryption.json: invalid salt (not base64)")?;
    let salt: [u8; SALT_LEN] = salt_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            ".conf/encryption.json: salt has invalid length ({} bytes, expected {SALT_LEN})",
            bytes.len()
        )
    })?;
    let cipher = Cipher::derive(passphrase, &salt)?;

    let verifier = BASE64
        .decode(&meta.verifier)
        .context(".conf/encryption.json: invalid verifier (not base64)")?;
    cipher.open(VERIFIER_AAD, &verifier).context(
        "the configured passphrase doesn't match the one used to encrypt this bucket \
         (check `passphrase` in the config)",
    )?;
    Ok(cipher)
}

fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).context("couldn't generate encryption salt (system RNG)")?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_passphrase_fails_verification_clearly() {
        let cipher = Cipher::derive("correct", &[3u8; SALT_LEN]).unwrap();
        let meta = EncryptionMeta {
            salt: BASE64.encode([3u8; SALT_LEN]),
            verifier: BASE64.encode(cipher.seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)),
        };
        assert!(derive_and_verify("correct", &meta).is_ok());
        let err = derive_and_verify("incorrect", &meta).unwrap_err();
        assert!(format!("{err:#}").contains("doesn't match"));
    }

    #[test]
    fn rejects_malformed_salt() {
        let meta = EncryptionMeta {
            salt: "not-base64!!".to_string(),
            verifier: String::new(),
        };
        assert!(derive_and_verify("x", &meta).is_err());
    }
}
