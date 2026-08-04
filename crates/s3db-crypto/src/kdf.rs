//! Key derivation, isolated from the AEAD primitive that uses its output --
//! swapping the KDF (a parameter bump, a different algorithm entirely)
//! never needs to touch [`crate::seal`]/[`crate::open`] or anything in
//! [`crate::stream`], only this file.

use anyhow::Result;
use argon2::Argon2;
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub(crate) const KEY_LEN: usize = 32;

/// Derives an AEAD key from a passphrase + salt via Argon2id. Fixed
/// parameters (not configurable): OWASP's low-memory recommendation, 19 MiB
/// / 2 iterations / 1 thread. Not made choosable on purpose — a weak choice
/// would weaken everyone sharing the bucket, and if these ever change,
/// that's a format version bump, not a flag.
pub(crate) fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<XChaCha20Poly1305> {
    let mut key_bytes = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| anyhow::anyhow!("deriving encryption key: {e}"))?;
    let cipher = XChaCha20Poly1305::new(&Key::from(key_bytes));
    // The local copy of the raw key isn't needed anymore once the cipher is
    // built; don't leave it sitting on the stack longer than necessary.
    key_bytes.zeroize();
    Ok(cipher)
}
