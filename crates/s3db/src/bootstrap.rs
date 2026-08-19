//! Per-bucket encryption bootstrap.
//!
//! The first time a bucket is used, this layer generates a random derivation
//! salt plus a random **data key**, and stores them at
//! `.conf/encryption.json` -- the salt in the clear (a salt isn't secret,
//! and it has to be readable before the key that decrypts everything else
//! can be derived), the data key sealed under a key derived from the
//! passphrase. Future instances read the salt, re-derive that wrapping key
//! with the passphrase from local config (never from the bucket), unwrap the
//! data key, and check it against a verifier value: that way a mistyped
//! passphrase gives a clear error at startup, instead of decrypt failures
//! scattered through the code mid-operation.
//!
//! ## Why the data key is wrapped rather than derived directly
//!
//! Everything in the bucket is sealed under the data key, and the passphrase
//! only ever seals the data key. Changing a passphrase is therefore
//! re-sealing 32 bytes ([`change_passphrase`]) rather than re-encrypting
//! every object -- which is what deriving the data key straight from the
//! passphrase would have required, and why that had previously been a
//! migration nobody would run.
//!
//! ## What keeps this file honest
//!
//! `.conf/encryption.json` is unencrypted but not unauthenticated: it
//! carries a tag only a holder of the passphrase can produce, and bootstrap
//! refuses to create a fresh config in a bucket that already has objects in
//! it. See [`crate::encryption_conf`] for both mechanisms and for what they
//! still don't cover.

use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CipherAlgorithm, CompressionStrategy, EncryptionMode, KDF_VERSION, KEY_LEN, SALT_LEN};
use crate::encryption_conf::{BootstrapPolicy, authenticator, ensure_safe_to_initialize, verify};
use crate::payload::{get_json_plain, put_json_plain};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use zeroize::Zeroizing;

const ENCRYPTION_META_KEY: &str = ".conf/encryption.json";
/// Known plaintext sealed with the data key, to validate it right at startup
/// instead of the first real decrypt error being indistinguishable from "the
/// data is corrupt".
const VERIFIER_PLAINTEXT: &[u8] = b"gits3bridge-verifier-v1";
const VERIFIER_AAD: &str = ".conf/encryption.json#verifier";
/// AAD binding the wrapped data key to its role, so a wrapped key can't be
/// replayed as a verifier or an authentication tag.
const WRAP_AAD: &str = ".conf/encryption.json#wrapped-key";
/// Retries for a race on the bucket's first use (two instances trying to
/// create `.conf/encryption.json` at the same time).
const MAX_BOOTSTRAP_RETRIES: u32 = 5;

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
struct EncryptionMeta {
    /// Which Argon2id parameter set derived the wrapping key from the
    /// passphrase. Recorded so a future cost bump is a recognisable
    /// migration rather than a bucket that mysteriously stops opening; `0`
    /// (the `serde` default) means a config written before the field
    /// existed.
    #[serde(default)]
    kdf_version: u32,
    #[serde(default)]
    salt: String,
    /// Base64 data key, sealed under the passphrase-derived wrapping key.
    #[serde(default)]
    wrapped_key: String,
    #[serde(default)]
    verifier: String,
    /// Base64 authentication tag over every other field -- see
    /// [`crate::encryption_conf`].
    #[serde(default)]
    mac: String,
}

impl EncryptionMeta {
    /// The exact bytes the authentication tag covers: this record with `mac`
    /// itself blanked, so producing and checking the tag can never disagree
    /// about whether the tag covers itself. Deterministic because
    /// `serde_json` writes struct fields in declaration order and nothing
    /// here is a map.
    fn canonical(&self) -> Result<Vec<u8>> {
        let unsigned = EncryptionMeta {
            mac: String::new(),
            ..self.clone()
        };
        serde_json::to_vec(&unsigned).context("serializing the encryption config for authentication")
    }
}

/// Derives (or creates, if the bucket is new) this bucket's cipher, with
/// encryption on and the default algorithm — see [`get_or_create_cipher_for`]
/// for the mode-aware form.
pub async fn get_or_create_cipher(backend: &dyn Backend, passphrase: &str) -> Result<Cipher> {
    get_or_create_cipher_for(backend, EncryptionMode::default(), passphrase).await
}

/// [`get_or_create_cipher`] for a caller that reads its [`EncryptionMode`]
/// from config, under the default [`BootstrapPolicy`].
///
/// Under [`EncryptionMode::Disabled`] nothing is derived and nothing is
/// written to the bucket — but a bucket that *was* bootstrapped encrypted is
/// a hard error rather than a silent switch to plaintext writes. Turning
/// encryption off for a bucket that already holds sealed objects is a
/// migration, not a config flip, and this is the one place that can say so
/// before any data moves.
pub async fn get_or_create_cipher_for(backend: &dyn Backend, mode: EncryptionMode, passphrase: &str) -> Result<Cipher> {
    get_or_create_cipher_with_policy(backend, mode, passphrase, BootstrapPolicy::default()).await
}

/// [`get_or_create_cipher_for`] with an explicit [`BootstrapPolicy`] — for
/// the one legitimate case the default refuses, deliberately adopting a
/// bucket that already held objects before encryption was set up on it.
pub async fn get_or_create_cipher_with_policy(
    backend: &dyn Backend,
    mode: EncryptionMode,
    passphrase: &str,
    policy: BootstrapPolicy,
) -> Result<Cipher> {
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
            // A missing config in a bucket that already holds objects is
            // either an attacker having deleted it or an operator adopting a
            // pre-existing bucket -- indistinguishable from here, so this
            // refuses unless the caller has said which it is.
            ensure_safe_to_initialize(backend, policy, ENCRYPTION_META_KEY).await?;
            let (meta, cipher) = new_meta(passphrase, algorithm)?;
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

        return open_meta(passphrase, algorithm, &meta);
    }
    bail!("couldn't initialize bucket encryption after several attempts (high contention)")
}

/// Opens an already-bootstrapped bucket's [`Cipher`], **never creating one**.
///
/// [`get_or_create_cipher`] is right for a server: whichever instance starts
/// first initializes the bucket. It is wrong for anything pointed at a bucket
/// by hand — an inspection tool, a backup script, an operator's one-off — where
/// a mistyped path or a not-yet-restored bucket would silently become a newly
/// initialized empty one, its encryption config written by the very command
/// that was only supposed to look. Failing is the useful answer there.
///
/// Errors if the bucket has no encryption config, or if `passphrase` doesn't
/// authenticate against the one it has.
pub async fn open_cipher(backend: &dyn Backend, passphrase: &str) -> Result<Cipher> {
    open_cipher_with_algorithm(backend, CipherAlgorithm::default(), passphrase).await
}

/// [`open_cipher`] for a bucket written with a non-default
/// [`CipherAlgorithm`]. The algorithm only selects what *new* writes would
/// use, so it rarely matters for reading (each object records its own), but a
/// caller that has it in config may as well pass it.
pub async fn open_cipher_with_algorithm(
    backend: &dyn Backend,
    algorithm: CipherAlgorithm,
    passphrase: &str,
) -> Result<Cipher> {
    let (meta, etag) = get_json_plain::<EncryptionMeta>(backend, ENCRYPTION_META_KEY).await?;
    if etag.is_none() {
        bail!(
            "this bucket has no {ENCRYPTION_META_KEY}: it was never bootstrapped, or the path is wrong.              Refusing to create one -- use get_or_create_cipher if initializing is actually intended"
        );
    }
    open_meta(passphrase, algorithm, &meta)
}

/// Replaces the passphrase protecting this bucket, leaving the data key —
/// and therefore every object already sealed under it — untouched.
///
/// This is the whole point of wrapping the data key rather than deriving it:
/// the write is one small object, and nothing in the bucket needs
/// re-encrypting. For rotating the *data* key (which does mean re-encrypting
/// everything that should stop being readable under the old one), see
/// [`crate::key_rotation`].
///
/// Fails without writing anything if `current_passphrase` is wrong, or if
/// the stored config doesn't authenticate against it.
pub async fn change_passphrase(backend: &dyn Backend, current_passphrase: &str, new_passphrase: &str) -> Result<()> {
    for _ in 0..MAX_BOOTSTRAP_RETRIES {
        let (meta, etag) = get_json_plain::<EncryptionMeta>(backend, ENCRYPTION_META_KEY).await?;
        let etag = etag.context("change_passphrase called before this bucket's encryption was bootstrapped")?;

        let data_key = unwrap_data_key(current_passphrase, &meta)?;
        let new_salt = random_salt()?;
        let new_wrapper = Cipher::derive(new_passphrase, &new_salt)?;
        let mut rewrapped = EncryptionMeta {
            kdf_version: KDF_VERSION,
            salt: BASE64.encode(new_salt),
            wrapped_key: BASE64.encode(new_wrapper.seal(WRAP_AAD, data_key.as_slice(), CompressionStrategy::None)?),
            // Unchanged: the verifier is sealed under the data key, which
            // this doesn't touch.
            verifier: meta.verifier.clone(),
            mac: String::new(),
        };
        rewrapped.mac = authenticator(&new_wrapper, &rewrapped.canonical()?)?;

        match put_json_plain(backend, ENCRYPTION_META_KEY, &rewrapped, Some(&etag)).await? {
            Cas::Ok => return Ok(()),
            // Someone else rewrote the config concurrently; re-read and redo
            // rather than clobber whatever they wrote.
            Cas::Conflict => continue,
        }
    }
    bail!("couldn't change the passphrase after several attempts (high contention)")
}

/// A brand-new config: fresh salt, fresh data key, wrapped and authenticated.
fn new_meta(passphrase: &str, algorithm: CipherAlgorithm) -> Result<(EncryptionMeta, Cipher)> {
    let salt = random_salt()?;
    let wrapper = Cipher::derive(passphrase, &salt)?;
    let data_key = Cipher::random_key()?;
    let cipher = Cipher::from_key(&data_key, algorithm);

    let mut meta = EncryptionMeta {
        kdf_version: KDF_VERSION,
        salt: BASE64.encode(salt),
        wrapped_key: BASE64.encode(wrapper.seal(WRAP_AAD, data_key.as_slice(), CompressionStrategy::None)?),
        verifier: BASE64.encode(cipher.seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)?),
        mac: String::new(),
    };
    meta.mac = authenticator(&wrapper, &meta.canonical()?)?;
    Ok((meta, cipher))
}

/// Authenticates a stored config, unwraps its data key, and checks the
/// verifier — in that order, so a tampered file is rejected before anything
/// derived from it is trusted.
///
/// `algorithm` only decides what this instance will *write* from here on: the
/// verifier is opened, never re-sealed, so a bucket whose verifier was sealed
/// by a different algorithm still validates. That's what makes changing the
/// algorithm a config change rather than a re-encryption.
fn open_meta(passphrase: &str, algorithm: CipherAlgorithm, meta: &EncryptionMeta) -> Result<Cipher> {
    let data_key = unwrap_data_key(passphrase, meta)?;
    let cipher = Cipher::from_key(&data_key, algorithm);

    let verifier = BASE64
        .decode(&meta.verifier)
        .context(".conf/encryption.json: invalid verifier (not base64)")?;
    cipher
        .open(VERIFIER_AAD, &verifier)
        .context(".conf/encryption.json: the unwrapped data key doesn't open this bucket's verifier")?;
    Ok(cipher)
}

/// Re-derives the wrapping key from `passphrase` plus the stored salt,
/// checks the config authenticates under it, and unwraps the data key.
fn unwrap_data_key(passphrase: &str, meta: &EncryptionMeta) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    if meta.wrapped_key.is_empty() {
        bail!(
            "{ENCRYPTION_META_KEY} has no wrapped data key. This bucket was initialized by a version \
             that derived its data key straight from the passphrase; it needs migrating (re-encrypt \
             into a freshly bootstrapped bucket) rather than being opened as-is."
        );
    }
    if meta.kdf_version != KDF_VERSION {
        bail!(
            "{ENCRYPTION_META_KEY} was derived with KDF parameter set {} but this build uses {KDF_VERSION}; \
             re-deriving with the current parameters would produce a different key, so this is refused \
             rather than surfacing as a wrong-passphrase error.",
            meta.kdf_version
        );
    }
    let salt_bytes = BASE64
        .decode(&meta.salt)
        .context(".conf/encryption.json: invalid salt (not base64)")?;
    let salt: [u8; SALT_LEN] = salt_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            ".conf/encryption.json: salt has invalid length ({} bytes, expected {SALT_LEN})",
            bytes.len()
        )
    })?;
    let wrapper = Cipher::derive(passphrase, &salt)?;

    // Before anything else derived from this file is used: a tampered salt
    // changes the wrapping key, so this check covers the salt as much as it
    // covers the rest.
    verify(&wrapper, &meta.canonical()?, &meta.mac, ENCRYPTION_META_KEY)?;

    let wrapped = BASE64
        .decode(&meta.wrapped_key)
        .context(".conf/encryption.json: invalid wrapped key (not base64)")?;
    let key_bytes = wrapper.open(WRAP_AAD, &wrapped).context(
        "the configured passphrase doesn't match the one used to encrypt this bucket \
         (check `passphrase` in the config)",
    )?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    if key_bytes.len() != KEY_LEN {
        bail!(".conf/encryption.json: wrapped key has the wrong length");
    }
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).context("couldn't generate encryption salt (system RNG)")?;
    Ok(salt)
}

#[cfg(test)]
#[path = "../tests/unit/bootstrap.rs"]
mod tests;
