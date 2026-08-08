//! Key derivation, isolated from the AEAD primitive that uses its output --
//! swapping the KDF (a parameter bump, a different algorithm entirely)
//! never needs to touch [`crate::seal`]/[`crate::open`] or anything in
//! [`crate::stream`], only this file.

use anyhow::Result;
use argon2::Argon2;
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub(crate) const KEY_LEN: usize = 32;

/// Derives raw AEAD key material from a passphrase + salt via Argon2id.
/// Fixed parameters (not configurable): OWASP's low-memory recommendation,
/// 19 MiB / 2 iterations / 1 thread. Not made choosable on purpose — a weak
/// choice would weaken everyone sharing the bucket, and if these ever
/// change, that's a format version bump, not a flag.
///
/// Returns raw bytes rather than a built cipher because which AEAD gets
/// built from them is [`crate::CipherAlgorithm`]'s call, not this module's
/// — every supported algorithm takes the same 32-byte key. [`Zeroizing`]
/// so the material is wiped once the caller has built its cipher, without
/// this function having to guess when that is.
pub(crate) fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, key_bytes.as_mut())
        .map_err(|e| anyhow::anyhow!("deriving encryption key: {e}"))?;
    Ok(key_bytes)
}
