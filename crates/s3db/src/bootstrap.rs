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
use crate::cipher::{Cipher, CipherAlgorithm, CompressionStrategy, EncryptionMode, SALT_LEN};
use crate::payload::{get_json_plain, put_json_plain};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::time::Duration;

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

/// Derives (or creates, if the bucket is new) this bucket's cipher, with
/// encryption on and the default algorithm — see [`get_or_create_cipher_for`]
/// for the mode-aware form.
pub async fn get_or_create_cipher(backend: &dyn Backend, passphrase: &str) -> Result<Cipher> {
    get_or_create_cipher_for(backend, EncryptionMode::default(), passphrase).await
}

/// [`get_or_create_cipher`] for a caller that reads its
/// [`EncryptionMode`] from config.
///
/// Under [`EncryptionMode::Disabled`] nothing is derived and nothing is
/// written to the bucket — but a bucket that *was* bootstrapped encrypted is
/// a hard error rather than a silent switch to plaintext writes. Turning
/// encryption off for a bucket that already holds sealed objects is a
/// migration, not a config flip, and this is the one place that can say so
/// before any data moves.
pub async fn get_or_create_cipher_for(backend: &dyn Backend, mode: EncryptionMode, passphrase: &str) -> Result<Cipher> {
    let algorithm = match mode {
        EncryptionMode::Enabled { algorithm } => algorithm,
        EncryptionMode::Disabled => {
            let (_, etag) = get_json_plain::<EncryptionMeta>(backend, ENCRYPTION_META_KEY).await?;
            if etag.is_some() {
                bail!(
                    "this bucket was initialized with encryption enabled ({ENCRYPTION_META_KEY} exists), \
                     but the configured encryption mode is disabled — nothing already sealed could be \
                     read back, so this is refused instead of writing plaintext alongside it"
                );
            }
            return Ok(Cipher::disabled());
        }
    };

    for attempt in 0..MAX_BOOTSTRAP_RETRIES {
        let (meta, etag) = get_json_plain::<EncryptionMeta>(backend, ENCRYPTION_META_KEY).await?;

        if etag.is_none() {
            // New bucket (or nothing encrypted yet): we generate the salt.
            let salt = random_salt()?;
            let cipher = Cipher::derive_with(passphrase, &salt, algorithm)?;
            let meta = EncryptionMeta {
                salt: BASE64.encode(salt),
                verifier: BASE64.encode(cipher.seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)?),
            };
            match put_json_plain(backend, ENCRYPTION_META_KEY, &meta, None).await? {
                Cas::Ok => return Ok(cipher),
                // Another instance started at the same time and created the
                // bucket first: we discard ours and use the one that won.
                // A brief backoff (not a busy-loop retry) before trying
                // again gives whichever instance actually won a moment to
                // finish, instead of every contender immediately re-reading
                // and re-racing the same CAS.
                Cas::Conflict => {
                    tokio::time::sleep(Duration::from_millis(20 * (attempt as u64 + 1))).await;
                    continue;
                }
            }
        }

        return derive_and_verify(passphrase, algorithm, &meta);
    }
    bail!("couldn't initialize bucket encryption after several attempts (high contention)")
}

/// The verifier is opened, never re-sealed, so `algorithm` only decides what
/// this instance will *write* from here on — a bucket whose verifier was
/// sealed by a different algorithm still validates, which is what makes
/// changing the algorithm a config change rather than a re-encryption.
fn derive_and_verify(passphrase: &str, algorithm: CipherAlgorithm, meta: &EncryptionMeta) -> Result<Cipher> {
    let salt_bytes = BASE64
        .decode(&meta.salt)
        .context(".conf/encryption.json: invalid salt (not base64)")?;
    let salt: [u8; SALT_LEN] = salt_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            ".conf/encryption.json: salt has invalid length ({} bytes, expected {SALT_LEN})",
            bytes.len()
        )
    })?;
    let cipher = Cipher::derive_with(passphrase, &salt, algorithm)?;

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
#[path = "../tests/unit/bootstrap.rs"]
mod tests;
