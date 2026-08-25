//! Multi-key encryption rotation, additive to (never required by)
//! [`crate::bootstrap`]'s single-`Cipher` bootstrap. An app that never
//! rotates keys keeps using `bootstrap::get_or_create_cipher`
//! and a bare [`Cipher`] everywhere, untouched -- `Collection`/`SecondaryIndex`/
//! `txn::run`/`payload` all still take `&Cipher`, not `&KeyRing`, so adding
//! this module changes nothing for a caller that doesn't opt in.
//!
//! An app that *does* rotate encryption keys (a suspected passphrase leak,
//! a compliance-driven schedule, ...) uses this module's
//! [`get_or_create_keyring`]/[`rotate`] instead of `bootstrap`'s: a
//! [`KeyRing`] holds one *active* key (what every new write seals under)
//! plus zero or more *retired* keys still needed to open objects nobody has
//! re-encrypted yet. [`KeyRing::open`] tries the active key first, then
//! retired keys most-recently-retired first -- cheap AEAD verification, no
//! KDF, so trying several costs nothing like repeating Argon2id per attempt
//! would (see [`KeyRing`]'s own doc comment for why that matters).
//!
//! Each generation's data key is random and stored wrapped under a key
//! derived from that generation's own passphrase, same as
//! [`crate::bootstrap`]. That is what separates the two things people call
//! "rotation", and they are not interchangeable:
//!
//! - **Changing the passphrase** leaves the data key alone, so nothing in
//!   the bucket needs re-encrypting. That's
//!   [`crate::bootstrap::change_passphrase`], and it's cheap.
//! - **Rotating the key** ([`rotate`]) mints a whole new generation with a
//!   new data key, so anything sealed under the old one genuinely stops
//!   being readable with the new key. That's what a suspected key
//!   compromise calls for, and it's the expensive one -- old objects stay
//!   readable only through [`KeyRing::open`]'s dual-read until something
//!   re-encrypts them.
//!
//! What this module deliberately does NOT solve: surviving a process
//! restart during a rotation's grace window still requires the caller to
//! keep supplying every retired generation's own original passphrase --
//! wrapping makes a *passphrase* change cheap, but each generation's
//! wrapping key is still derived from its own passphrase, so unwrapping a
//! retired generation needs the passphrase it was wrapped under.
//! `retired_passphrases` below is an explicit, honest `key_id -> passphrase`
//! map the caller manages (alongside its own `passphrase` config field), not
//! persisted anywhere in the bucket. Once a caller's own GC confirms zero
//! objects still reference a retired key, it drops that entry from both its
//! own config and (via [`KeyRing::forget_retired`]) from this process's
//! memory, and eventually calls [`forget_key`] to remove it from
//! `EncryptionConfig` for good.
//!
//! `EncryptionConfig` itself is authenticated under the active generation's
//! wrapping key -- see [`crate::encryption_conf`] -- so repointing
//! `active_key_id` or trimming `keys` takes the passphrase, not merely write
//! access to the bucket. That is also why [`rotate`] and [`forget_key`] take
//! a [`KeyRing`]: they rewrite that file and have to re-sign what they wrote.

use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CipherAlgorithm, CompressionStrategy, KDF_VERSION, KEY_LEN, SALT_LEN};
use crate::encryption_conf::{BootstrapPolicy, authenticator, ensure_safe_to_initialize, verify};
use crate::payload::{get_json_plain, put_json_plain};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const ENCRYPTION_CONFIG_KEY: &str = ".conf/encryption.json";
const VERIFIER_PLAINTEXT: &[u8] = b"gits3bridge-verifier-v1";
const VERIFIER_AAD: &str = ".conf/encryption.json#verifier";
/// AAD binding a wrapped data key to its role, so one can never be replayed
/// as a verifier or an authentication tag.
const WRAP_AAD: &str = ".conf/encryption.json#wrapped-key";
const MAX_BOOTSTRAP_RETRIES: u32 = 5;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn random_key_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating key id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn random_salt() -> Result<[u8; SALT_LEN]> {
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt).context("couldn't generate encryption salt (system RNG)")?;
    Ok(salt)
}

/// One key generation's durable record: everything needed to identify and
/// re-derive it, but never the passphrase itself (that never lives in the
/// bucket, only in the caller's own config).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct KeyMaterial {
    pub key_id: String,
    /// Which Argon2id parameter set derived this key's wrapping key -- see
    /// [`crate::bootstrap`]'s field of the same name.
    #[serde(default)]
    pub kdf_version: u32,
    /// Base64 Argon2id salt.
    pub salt: String,
    /// Base64 data key, sealed under the passphrase-derived wrapping key.
    /// The passphrase never seals user data itself, only this -- see
    /// [`crate::bootstrap`]'s module doc for why that indirection is what
    /// makes a passphrase change cheap.
    #[serde(default)]
    pub wrapped_key: String,
    /// Base64 `Cipher::seal`ed verifier under this key's *data* key -- lets
    /// bootstrap fail with one clear error on a wrong passphrase, same
    /// reasoning as [`crate::bootstrap`]'s own single-key verifier.
    pub verifier: String,
    pub retired_at_ms: Option<u64>,
}

/// Durable multi-key record at `.conf/encryption.json` -- unencrypted (a
/// salt isn't secret) and plain JSON on purpose, same as
/// [`crate::bootstrap`]'s single-key `EncryptionMeta` this replaces (this is
/// a breaking format change with no migration: pre-alpha, encryption has
/// always been mandatory and this file has never held anything but a
/// derivation salt, nothing depends on its old single-key shape surviving).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct EncryptionConfig {
    pub active_key_id: String,
    pub keys: Vec<KeyMaterial>,
    /// Base64 authentication tag over every other field, written under the
    /// *active* key's wrapping key -- see [`crate::encryption_conf`]. Without
    /// it, `active_key_id` could be repointed and `keys` reordered or trimmed
    /// by anything able to write to the bucket.
    #[serde(default)]
    pub mac: String,
}

impl EncryptionConfig {
    /// The exact bytes the authentication tag covers: this record with `mac`
    /// itself blanked, so producing and checking the tag can never disagree
    /// about whether the tag covers itself.
    fn canonical(&self) -> Result<Vec<u8>> {
        let unsigned = EncryptionConfig {
            mac: String::new(),
            ..self.clone()
        };
        serde_json::to_vec(&unsigned).context("serializing the encryption config for authentication")
    }
}

/// Every key this process currently has derived, active or retired.
/// Argon2id only ever runs once per key, at [`get_or_create_keyring`]/
/// [`rotate`] time -- not once per [`Self::open`] attempt, which is what
/// makes trying several retired keys in a dual-read cheap instead of a
/// latency cliff that gets worse the further a caller falls behind on
/// re-encrypting old objects under the active key.
pub struct KeyRing {
    active_key_id: String,
    active_cipher: Cipher,
    /// The active key's *wrapping* cipher (passphrase-derived), kept
    /// alongside its data cipher because every edit to `EncryptionConfig`
    /// has to be re-authenticated under it -- see
    /// [`crate::encryption_conf`]. That is also the property worth having:
    /// only a holder of the passphrase can rewrite this bucket's key list.
    active_wrapper: Cipher,
    /// Most-recently-retired first.
    retired: Vec<(String, Cipher)>,
}

// Manual, no derive: same reasoning as `Cipher`'s own manual `Debug` --
// never want an accidental `{:?}` anywhere near a chance of printing key
// material, even indirectly through a struct that holds several `Cipher`s.
impl std::fmt::Debug for KeyRing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRing")
            .field("active_key_id", &self.active_key_id)
            .field(
                "retired_key_ids",
                &self.retired.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl KeyRing {
    fn single(key_id: String, cipher: Cipher, wrapper: Cipher) -> Self {
        KeyRing {
            active_key_id: key_id,
            active_cipher: cipher,
            active_wrapper: wrapper,
            retired: Vec::new(),
        }
    }

    pub fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    /// The key every new write seals under.
    pub fn active(&self) -> &Cipher {
        &self.active_cipher
    }

    /// Dual-read: the active key first, then retired keys most-recently-
    /// retired first. A single generic error if none of them open it --
    /// same reasoning as [`Cipher::open`]'s own single error, to avoid
    /// leaking which key (if any) came close.
    pub fn open(&self, aad: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        if let Ok(plain) = self.active_cipher.open(aad, sealed) {
            return Ok(plain);
        }
        for (_, cipher) in &self.retired {
            if let Ok(plain) = cipher.open(aad, sealed) {
                return Ok(plain);
            }
        }
        bail!("couldn't decrypt (wrong passphrase, or data was modified/moved from a different key)")
    }

    /// Aggressive memory purge: drops a retired key's already-derived
    /// material from this process as soon as a caller (its own GC sweep,
    /// once it confirms zero objects still reference this key) decides
    /// it's safe -- independent of, and can run well before, that key's
    /// removal from `EncryptionConfig` on disk via [`forget_key`]. Widens
    /// the exposure window of derived key material in memory to close a
    /// latency problem (§11); this narrows that window back down as
    /// soon as it's known to be safe, rather than waiting for the slower
    /// on-disk cleanup.
    pub fn forget_retired(&mut self, key_id: &str) {
        self.retired.retain(|(id, _)| id != key_id);
    }
}

/// Re-derives one key's wrapping key from its passphrase plus its stored
/// salt. Split out from [`unwrap_and_verify`] because the config's own
/// authentication tag has to be checked under the *active* key's wrapping
/// key before any key's data key is unwrapped.
fn wrapping_cipher(passphrase: &str, material: &KeyMaterial) -> Result<Cipher> {
    if material.wrapped_key.is_empty() {
        bail!(
            "{ENCRYPTION_CONFIG_KEY}: key {} has no wrapped data key. It was written by a version that \
             derived its data key straight from the passphrase; it needs migrating rather than being \
             opened as-is.",
            material.key_id
        );
    }
    if material.kdf_version != KDF_VERSION {
        bail!(
            "{ENCRYPTION_CONFIG_KEY}: key {} was derived with KDF parameter set {} but this build uses \
             {KDF_VERSION}; re-deriving with the current parameters would produce a different key, so \
             this is refused rather than surfacing as a wrong-passphrase error.",
            material.key_id,
            material.kdf_version
        );
    }
    let salt_bytes = BASE64
        .decode(&material.salt)
        .context(".conf/encryption.json: invalid salt (not base64)")?;
    let salt: [u8; SALT_LEN] = salt_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            ".conf/encryption.json: salt has invalid length ({} bytes, expected {SALT_LEN})",
            bytes.len()
        )
    })?;
    Cipher::derive(passphrase, &salt)
}

/// Unwraps one key's data key and checks it against that key's verifier.
fn unwrap_and_verify(wrapper: &Cipher, material: &KeyMaterial) -> Result<Cipher> {
    let wrapped = BASE64
        .decode(&material.wrapped_key)
        .context(".conf/encryption.json: invalid wrapped key (not base64)")?;
    // `Zeroizing` immediately, not after the length check: `wrapper.open`
    // hands back a plain `Vec<u8>` holding the real data key, and dropping a
    // `Vec` only frees its allocation, never wipes it -- an unwiped copy of
    // the key would otherwise sit in freed heap memory for as long as
    // something else happens to reuse that allocation.
    let key_bytes = Zeroizing::new(wrapper.open(WRAP_AAD, &wrapped).with_context(|| {
        format!(
            "the passphrase supplied for key {} doesn't match the one used to encrypt it \
             (check the passphrase config for this key)",
            material.key_id
        )
    })?);
    if key_bytes.len() != KEY_LEN {
        bail!(
            ".conf/encryption.json: key {} has a wrapped key of the wrong length",
            material.key_id
        );
    }
    let mut data_key = Zeroizing::new([0u8; KEY_LEN]);
    data_key.copy_from_slice(&key_bytes);
    let cipher = Cipher::from_key(&data_key, CipherAlgorithm::default());

    let verifier = BASE64
        .decode(&material.verifier)
        .context(".conf/encryption.json: invalid verifier (not base64)")?;
    cipher.open(VERIFIER_AAD, &verifier).with_context(|| {
        format!(
            "key {}'s unwrapped data key doesn't open its own verifier",
            material.key_id
        )
    })?;
    Ok(cipher)
}

/// A brand-new key generation: fresh id, fresh salt, fresh data key wrapped
/// under a wrapping key derived from `passphrase`. Returns the wrapping
/// cipher too, since whoever writes this material also has to authenticate
/// the config it goes into.
fn new_key_material(passphrase: &str) -> Result<(KeyMaterial, Cipher, Cipher)> {
    let key_id = random_key_id()?;
    let salt = random_salt()?;
    let wrapper = Cipher::derive(passphrase, &salt)?;
    let data_key = Cipher::random_key()?;
    let cipher = Cipher::from_key(&data_key, CipherAlgorithm::default());
    let material = KeyMaterial {
        key_id: key_id.clone(),
        kdf_version: KDF_VERSION,
        salt: BASE64.encode(salt),
        wrapped_key: BASE64.encode(wrapper.seal(WRAP_AAD, data_key.as_slice(), CompressionStrategy::None)?),
        verifier: BASE64.encode(cipher.seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)?),
        retired_at_ms: None,
    };
    Ok((material, cipher, wrapper))
}

/// Derives (or creates, if the bucket is new) this bucket's [`KeyRing`].
/// `retired_passphrases` is `key_id -> passphrase` for every key
/// `EncryptionConfig` lists as retired -- the caller's own responsibility to
/// track (see this module's doc comment); a retired key with no matching
/// entry here fails bootstrap with a clear error naming it, rather than
/// silently building a `KeyRing` that can't actually open that key's old
/// objects.
pub async fn get_or_create_keyring(
    backend: &dyn Backend,
    passphrase: &str,
    retired_passphrases: &HashMap<String, String>,
) -> Result<KeyRing> {
    get_or_create_keyring_with_policy(backend, passphrase, retired_passphrases, BootstrapPolicy::default()).await
}

/// [`get_or_create_keyring`] with an explicit [`BootstrapPolicy`] -- same
/// reasoning as [`crate::bootstrap::get_or_create_cipher_with_policy`].
pub async fn get_or_create_keyring_with_policy(
    backend: &dyn Backend,
    passphrase: &str,
    retired_passphrases: &HashMap<String, String>,
    policy: BootstrapPolicy,
) -> Result<KeyRing> {
    for _ in 0..MAX_BOOTSTRAP_RETRIES {
        let (config, etag) = get_json_plain::<EncryptionConfig>(backend, ENCRYPTION_CONFIG_KEY).await?;

        if etag.is_none() {
            // See `ensure_safe_to_initialize`: a missing config over a
            // non-empty bucket is either deletion by something hostile or a
            // deliberate adoption, and only the caller knows which.
            ensure_safe_to_initialize(backend, policy, ENCRYPTION_CONFIG_KEY).await?;
            let (material, cipher, wrapper) = new_key_material(passphrase)?;
            let mut config = EncryptionConfig {
                active_key_id: material.key_id.clone(),
                keys: vec![material.clone()],
                mac: String::new(),
            };
            config.mac = authenticator(&wrapper, &config.canonical()?)?;
            match put_json_plain(backend, ENCRYPTION_CONFIG_KEY, &config, None).await? {
                Cas::Ok => return Ok(KeyRing::single(material.key_id, cipher, wrapper)),
                // Another instance bootstrapped the bucket first: discard
                // ours and read back the one that won.
                Cas::Conflict => continue,
            }
        }

        // The tag is written under the *active* key's wrapping key, so that
        // one has to be derived first -- and the whole config authenticated
        // -- before any key's data key is unwrapped. Without that ordering,
        // a repointed `active_key_id` or a trimmed `keys` list would be
        // acted on before anything checked it.
        let active_material = config
            .keys
            .iter()
            .find(|k| k.key_id == config.active_key_id)
            .context(".conf/encryption.json: active_key_id doesn't match any key in `keys`")?;
        let active_wrapper = wrapping_cipher(passphrase, active_material)?;
        verify(
            &active_wrapper,
            &config.canonical()?,
            &config.mac,
            ENCRYPTION_CONFIG_KEY,
        )?;

        let active_cipher = unwrap_and_verify(&active_wrapper, active_material)?;
        let mut retired = Vec::new();
        for material in &config.keys {
            if material.key_id == config.active_key_id {
                continue;
            }
            let retired_passphrase = retired_passphrases.get(&material.key_id).with_context(|| {
                format!(
                    "bucket has retired key {} with no matching passphrase supplied",
                    material.key_id
                )
            })?;
            let wrapper = wrapping_cipher(retired_passphrase, material)?;
            retired.push((material.key_id.clone(), unwrap_and_verify(&wrapper, material)?));
        }
        // Most-recently-retired first, matching `KeyRing::open`'s try order.
        retired.reverse();
        return Ok(KeyRing {
            active_key_id: config.active_key_id.clone(),
            active_cipher,
            active_wrapper,
            retired,
        });
    }
    bail!("couldn't initialize bucket encryption after several attempts (high contention)")
}

/// Promotes a brand-new key (derived from `new_passphrase`) to active and
/// retires the current one. Existing objects sealed under the old key stay
/// readable via `ring.open`'s dual-read until something re-encrypts them
/// (or forever, if nothing ever does -- `open` doesn't need to know or care
/// which key it used). Returns the new key's id.
pub async fn rotate(backend: &dyn Backend, ring: &mut KeyRing, new_passphrase: &str) -> Result<String> {
    for _ in 0..MAX_BOOTSTRAP_RETRIES {
        let (mut config, etag) = get_json_plain::<EncryptionConfig>(backend, ENCRYPTION_CONFIG_KEY).await?;
        let etag = etag.context("rotate called before this bucket's encryption was ever bootstrapped")?;

        let (material, new_cipher, new_wrapper) = new_key_material(new_passphrase)?;
        for existing in &mut config.keys {
            if existing.key_id == config.active_key_id {
                existing.retired_at_ms = Some(now_ms());
            }
        }
        let old_active_id = std::mem::replace(&mut config.active_key_id, material.key_id.clone());
        config.keys.push(material.clone());
        // Re-signed under the *new* active key, matching where
        // `get_or_create_keyring` will look for the tag on the next read.
        config.mac = String::new();
        config.mac = authenticator(&new_wrapper, &config.canonical()?)?;

        match put_json_plain(backend, ENCRYPTION_CONFIG_KEY, &config, Some(&etag)).await? {
            Cas::Ok => {
                let old_cipher = std::mem::replace(&mut ring.active_cipher, new_cipher);
                ring.active_wrapper = new_wrapper;
                ring.retired.insert(0, (old_active_id, old_cipher));
                ring.active_key_id = material.key_id.clone();
                return Ok(material.key_id);
            }
            // Someone else rotated (or bootstrapped) concurrently -- our
            // view of `config` is stale, retry against the fresh one.
            Cas::Conflict => continue,
        }
    }
    bail!("couldn't rotate the encryption key after several attempts (high contention)")
}

/// One [`scan_key_usage`] result: how many of the objects it actually
/// checked under a given prefix still open under the key being scanned for
/// -- i.e. still need re-encryption before [`forget_key`] would be safe
/// for *that prefix*.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeyUsageReport {
    pub checked: u64,
    pub still_encrypted_under_this_key: u64,
}

/// Scans every object under `prefix`, reporting how many still open under
/// `key_id` -- this module's answer to "how do I know it's safe to call
/// [`forget_key`]", since forgetting a key that objects still need is
/// permanent, unrecoverable data loss, and this crate has no way to check
/// that automatically (see [`forget_key`]'s own doc comment). It's on the
/// caller to point this at every prefix that key could ever have sealed
/// something under -- every collection, every blob namespace, everything
/// [`crate::snapshot`]/[`crate::ttl`] wrote for it -- so a `0` here is only
/// as trustworthy as the prefixes actually scanned.
///
/// **Does not cover LSM SSTable data.** This checks each object by trying
/// to open it with the object's own key/path as AAD -- the convention
/// every [`crate::payload::put_json`]-based object in this crate follows
/// (`Collection` entries and tombstones, TTL markers, snapshot leases,
/// secondary index entries, blob metadata, ...). An LSM SSTable's blocks
/// and footer are sealed under a different, structured AAD (see
/// `crate::lsm::sstable`'s module doc), so this scan will get a spurious
/// "doesn't open" for them regardless of which key actually sealed them --
/// a false negative, not a true "not this key". Never point this at an LSM
/// table's root expecting a trustworthy answer; that data needs its own,
/// format-aware check.
///
/// Genuinely expensive: unlike a metadata lookup, there is no stored
/// marker of which key sealed a given object (AEAD ciphertext carries no
/// such signal by design), so the only way to know is to try opening each
/// one -- one extra `get` per object, on top of whatever this backend's
/// own listing costs. Meant for an occasional, deliberate check before a
/// `forget_key` call, not a hot path.
pub async fn scan_key_usage(
    backend: &dyn Backend,
    ring: &KeyRing,
    key_id: &str,
    prefix: &str,
) -> Result<KeyUsageReport> {
    let cipher = ring
        .retired
        .iter()
        .find(|(id, _)| id == key_id)
        .map(|(_, cipher)| cipher)
        .with_context(|| format!("{key_id} isn't a retired key this KeyRing knows about"))?;

    let mut report = KeyUsageReport::default();
    for (key, _size) in backend.list_prefix(prefix).await? {
        let (sealed, etag) = backend.get(&key).await?;
        if etag.is_none() {
            continue; // vanished between listing and reading
        }
        report.checked += 1;
        if cipher.open(&key, &sealed).is_ok() {
            report.still_encrypted_under_this_key += 1;
        }
    }
    Ok(report)
}

/// Removes a retired key from `EncryptionConfig` for good -- call only once
/// a caller's own accounting (a GC/maintenance sweep, informed by
/// [`scan_key_usage`] over every prefix that could matter) has confirmed
/// zero objects in the bucket still reference `key_id`; this crate has no
/// way to verify that itself. Doesn't touch the in-memory `KeyRing`
/// ([`KeyRing::forget_retired`] is separate, and should usually run first,
/// well before this on-disk cleanup -- see this module's doc comment). A
/// no-op (`Ok(())`) if `key_id` is already gone or was never retired.
pub async fn forget_key(backend: &dyn Backend, ring: &KeyRing, key_id: &str) -> Result<()> {
    for _ in 0..MAX_BOOTSTRAP_RETRIES {
        let (mut config, etag) = get_json_plain::<EncryptionConfig>(backend, ENCRYPTION_CONFIG_KEY).await?;
        let Some(etag) = etag else { return Ok(()) };
        if key_id == config.active_key_id {
            bail!("refusing to forget {key_id}: it's still the active key");
        }
        let before = config.keys.len();
        config.keys.retain(|k| k.key_id != key_id || k.retired_at_ms.is_none());
        if config.keys.len() == before {
            return Ok(()); // already gone, or never retired
        }
        // Re-signed under the active key's wrapper -- `ring` is taken for
        // exactly this: rewriting the key list requires holding the
        // passphrase, not merely write access to the bucket.
        config.mac = String::new();
        config.mac = authenticator(&ring.active_wrapper, &config.canonical()?)?;
        match put_json_plain(backend, ENCRYPTION_CONFIG_KEY, &config, Some(&etag)).await? {
            Cas::Ok => return Ok(()),
            Cas::Conflict => continue,
        }
    }
    bail!("couldn't forget key {key_id} after several attempts (high contention)")
}

#[cfg(test)]
#[path = "../tests/unit/key_rotation.rs"]
mod tests;
