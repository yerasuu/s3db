//! Key derivation, isolated from the AEAD primitive that uses its output --
//! swapping the KDF (a parameter bump, a different algorithm entirely)
//! never needs to touch [`crate::Cipher::seal`]/[`crate::Cipher::open`] or
//! anything in [`crate::stream`], only this file.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// This crate's Argon2id cost parameters, and the version stamp a caller
/// stores alongside a salt so a future change to them is a migration rather
/// than a bucket that silently stops opening.
///
/// 64 MiB / 3 passes / 1 lane, deliberately well above OWASP's *minimum*
/// recommendations (their lowest-memory option is 19 MiB / t=2). Those
/// minima are calibrated for per-login password hashing, where the cost is
/// paid on every authentication and a server may be doing thousands a
/// second. This derivation is paid **once, at process startup**, and what
/// it protects is not one account but the key to an entire bucket -- and
/// anyone who can read the bucket has an offline oracle to attack it with
/// (any sealed object serves; see the verifier in `s3db::bootstrap`). The
/// asymmetry is entirely in favour of spending more here: a few hundred
/// milliseconds once per process buys a proportional multiple on every
/// offline guess an attacker makes, forever.
///
/// `p = 1` rather than a higher lane count because the `argon2` crate hashes
/// lanes sequentially unless its parallel feature is on: raising `p` would
/// change the derived key without buying any real wall-clock parallelism.
///
/// These are not configurable, for the same reason they were not before: a
/// weak choice would weaken everyone sharing the bucket. Changing them is a
/// [`KDF_VERSION`] bump.
const MEMORY_KIB: u32 = 64 * 1024;
const ITERATIONS: u32 = 3;
const LANES: u32 = 1;

/// Identifies the parameter set [`derive`] used, for a caller to record next
/// to the salt. Bump this whenever any of the constants above change, so a
/// bucket derived under the old parameters can be recognised (and migrated)
/// instead of just failing to open with a confusing "wrong passphrase".
///
/// `1` is this parameter set. Buckets predating the field were derived under
/// `Argon2::default()` (19 MiB / t=2 / p=1) and have no version recorded at
/// all -- a caller treats a missing version as `0`.
pub const KDF_VERSION: u32 = 1;

fn argon2() -> Result<Argon2<'static>> {
    let params = Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("building Argon2id parameters: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Derives raw AEAD key material from a passphrase + salt via Argon2id, at
/// the parameters [`KDF_VERSION`] names.
///
/// Returns raw bytes rather than a built cipher because which AEAD gets
/// built from them is [`crate::CipherAlgorithm`]'s call, not this module's
/// — every supported algorithm takes the same 32-byte key. [`Zeroizing`]
/// so the material is wiped once the caller has built its cipher, without
/// this function having to guess when that is.
pub(crate) fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
    argon2()?
        .hash_password_into(passphrase.as_bytes(), salt, key_bytes.as_mut())
        .map_err(|e| anyhow::anyhow!("deriving encryption key: {e}"))?;
    Ok(key_bytes)
}

/// A fresh random 32-byte key, for a caller that wants a key nobody derived
/// from a passphrase — the data key in a wrap-a-data-key-under-the-
/// passphrase-key scheme (see `s3db::bootstrap`). Wiped on drop, same as
/// [`derive`]'s output.
pub(crate) fn random_key() -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    getrandom::fill(key.as_mut()).context("couldn't generate a key (system RNG)")?;
    Ok(key)
}
