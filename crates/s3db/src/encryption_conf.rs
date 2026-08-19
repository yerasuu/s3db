//! The pieces [`crate::bootstrap`] and [`crate::key_rotation`] both need to
//! keep `.conf/encryption.json` honest.
//!
//! That object is the one thing in a bucket that stays unencrypted on
//! purpose: it holds the derivation salt, and the salt has to be readable
//! *before* the key that decrypts everything else can be derived. Being
//! unencrypted is fine -- a salt isn't secret. Being **unauthenticated** was
//! not: without the two mechanisms in this module, anything able to write to
//! the bucket (a compromised credential, or the storage provider itself --
//! precisely the adversary [`Cipher`]'s AAD binding and downgrade guard
//! exist to defend against) could
//!
//! 1. **tamper** with the file -- swap the salt, point `active_key_id` at a
//!    different entry, reorder `keys` -- with nothing to notice; or
//! 2. **delete** it outright, at which point bootstrap saw a bucket with no
//!    encryption config, did what it does for a brand-new bucket, and
//!    generated a fresh salt. Every object already sealed under the old key
//!    became permanently unopenable while new writes proceeded happily under
//!    a new one. No error, no warning: a one-request, unauthenticated way to
//!    render a bucket's entire contents unreadable.
//!
//! [`authenticator`]/[`verify`] close (1); [`ensure_safe_to_initialize`]
//! closes (2).
//!
//! ## What is still not covered
//!
//! **Rollback.** An attacker who keeps a byte-for-byte copy of an older
//! version of this file and restores it later presents a genuinely valid
//! MAC, because it genuinely was valid once. Detecting that needs a
//! monotonic counter held somewhere the attacker can't also roll back, which
//! is state this crate has nowhere to put -- the bucket is the only durable
//! thing it owns, and that is exactly what's assumed hostile here. A caller
//! that needs rollback protection has to pin something out of band (object
//! versioning with retention, or its own record of the current `key_id`).

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::cipher::CompressionStrategy;
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

/// AAD for the authenticator tag. Distinct from the verifier's AAD so a
/// value from one can never be replayed as the other.
const MAC_AAD_PREFIX: &str = ".conf/encryption.json#mac\0";

/// Whether a caller will accept creating a brand-new encryption config in a
/// bucket that already holds objects.
///
/// The default is [`Self::RequireEmptyBucket`], and it is the default
/// because the dangerous case and the innocent case are indistinguishable
/// from inside this crate: "the config is missing and there are objects
/// here" is what a first run against a pre-existing bucket looks like, and
/// it is *also* exactly what an attacker deleting the config looks like.
/// Only the operator knows which. Refusing by default puts that decision
/// where the knowledge is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BootstrapPolicy {
    /// Refuse to write a new encryption config unless the bucket is empty.
    #[default]
    RequireEmptyBucket,
    /// Write a new encryption config even though the bucket already holds
    /// objects -- for deliberately adopting a bucket that was already in use
    /// for something else. Anything already sealed under a *different* key
    /// stays unreadable; this only says the caller knows that.
    AllowNonEmptyBucket,
}

/// Refuses to initialize encryption over a bucket that already has objects
/// in it, unless `policy` says otherwise.
///
/// Only ever reached when `.conf/encryption.json` is absent, which for a
/// healthy deployment happens exactly once, against an empty bucket -- so
/// the full listing this does is a one-time cost on the one path where it
/// buys something. On the path where it costs the most (a large bucket) it
/// is also the path where it matters most: a large bucket that has lost its
/// encryption config has lost it to something, and that something is worth
/// stopping for.
pub(crate) async fn ensure_safe_to_initialize(
    backend: &dyn Backend,
    policy: BootstrapPolicy,
    config_key: &str,
) -> Result<()> {
    if policy == BootstrapPolicy::AllowNonEmptyBucket {
        return Ok(());
    }
    let existing = backend
        .list_prefix("")
        .await
        .context("listing the bucket to check whether it is safe to initialize encryption")?;
    // The config object itself can't be in the listing -- this only runs
    // when reading it came back empty -- so any key at all means the bucket
    // held data before encryption was ever set up here.
    let sample: Vec<&str> = existing.iter().take(3).map(|(key, _)| key.as_str()).collect();
    if !sample.is_empty() {
        bail!(
            "refusing to initialize bucket encryption: {config_key} does not exist, but the bucket \
             already holds {} object(s) (e.g. {sample:?}). Either this config was deleted -- in which \
             case generating a new salt here would leave everything already sealed permanently \
             unreadable, and the old config must be restored instead -- or this bucket was genuinely \
             in use for something else first, in which case pass \
             BootstrapPolicy::AllowNonEmptyBucket to say so explicitly.",
            existing.len()
        );
    }
    Ok(())
}

/// A tag over `canonical` that only a holder of `cipher`'s key can produce.
///
/// Built out of [`Cipher::seal`] rather than a separate MAC primitive:
/// sealing an *empty* plaintext with `canonical` as the associated data
/// yields nothing but a nonce, a header, and an authentication tag over
/// those bytes -- which is precisely a MAC, using the AEAD this crate
/// already depends on instead of adding a second construction (and a second
/// dependency) to audit.
pub(crate) fn authenticator(cipher: &Cipher, canonical: &[u8]) -> Result<String> {
    let aad = mac_aad(canonical);
    Ok(BASE64.encode(cipher.seal(&aad, b"", CompressionStrategy::None)?))
}

/// Checks a tag [`authenticator`] produced over the same `canonical` bytes.
pub(crate) fn verify(cipher: &Cipher, canonical: &[u8], mac: &str, config_key: &str) -> Result<()> {
    if mac.is_empty() {
        bail!(
            "{config_key} carries no authentication tag. Either it predates authentication of this \
             file (in which case it needs migrating) or it was replaced by something that couldn't \
             produce one -- refusing to trust it either way."
        );
    }
    let sealed = BASE64
        .decode(mac)
        .with_context(|| format!("{config_key}: authentication tag isn't base64"))?;
    let aad = mac_aad(canonical);
    // Deliberately leads with the passphrase rather than with tampering.
    // This check cannot distinguish the two -- both come down to "the key
    // that would verify this tag isn't the key we derived" -- and of the
    // two, a mistyped passphrase is overwhelmingly the one an operator is
    // actually looking at. Leading with "your file was tampered with" would
    // send almost every real occurrence down the wrong path.
    let opened = cipher.open(&aad, &sealed).with_context(|| {
        format!(
            "{config_key} doesn't match the passphrase supplied for it. Either the configured \
             passphrase isn't the one this bucket was initialized with (check `passphrase` in the \
             config), or this file was modified by something that doesn't hold the passphrase -- \
             unencrypted is not the same as unauthenticated, and this check can't tell the two cases \
             apart."
        )
    })?;
    if !opened.is_empty() {
        bail!("{config_key}: authentication tag has unexpected content");
    }
    Ok(())
}

/// The associated data a tag covers: a fixed prefix plus the canonical bytes
/// themselves. `canonical` is JSON, so it's valid UTF-8 by construction --
/// but it's rebuilt through `String::from_utf8_lossy` rather than assumed,
/// since a malformed tag is a much better outcome than a panic on a file an
/// attacker controls.
fn mac_aad(canonical: &[u8]) -> String {
    format!("{MAC_AAD_PREFIX}{}", String::from_utf8_lossy(canonical))
}

#[cfg(test)]
#[path = "../tests/unit/encryption_conf.rs"]
mod tests;
