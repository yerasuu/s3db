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
//! What this module deliberately does NOT solve: surviving a process
//! restart during a rotation's grace window still requires the caller to
//! keep supplying every retired key's own original passphrase (there is no
//! master-key-wraps-data-keys scheme here) -- `retired_passphrases` below is
//! an explicit, honest `key_id -> passphrase` map the caller manages
//! (alongside its own `passphrase` config field), not persisted anywhere in
//! the bucket. Once a caller's own GC confirms zero objects still reference
//! a retired key, it drops that entry from both its own config and (via
//! [`KeyRing::forget_retired`]) from this process's memory, and eventually
//! calls [`forget_key`] to remove it from `EncryptionConfig` for good.

use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy, SALT_LEN};
use crate::payload::{get_json_plain, put_json_plain};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const ENCRYPTION_CONFIG_KEY: &str = ".conf/encryption.json";
const VERIFIER_PLAINTEXT: &[u8] = b"gits3bridge-verifier-v1";
const VERIFIER_AAD: &str = ".conf/encryption.json#verifier";
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
    /// Base64 Argon2id salt.
    pub salt: String,
    /// Base64 `Cipher::seal`ed verifier under this key -- lets bootstrap
    /// fail with one clear error on a wrong passphrase, same reasoning as
    /// [`crate::bootstrap`]'s own single-key verifier.
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
    fn single(key_id: String, cipher: Cipher) -> Self {
        KeyRing {
            active_key_id: key_id,
            active_cipher: cipher,
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

fn derive_and_verify(passphrase: &str, material: &KeyMaterial) -> Result<Cipher> {
    let salt_bytes = BASE64
        .decode(&material.salt)
        .context(".conf/encryption.json: invalid salt (not base64)")?;
    let salt: [u8; SALT_LEN] = salt_bytes.try_into().map_err(|bytes: Vec<u8>| {
        anyhow::anyhow!(
            ".conf/encryption.json: salt has invalid length ({} bytes, expected {SALT_LEN})",
            bytes.len()
        )
    })?;
    let cipher = Cipher::derive(passphrase, &salt)?;
    let verifier = BASE64
        .decode(&material.verifier)
        .context(".conf/encryption.json: invalid verifier (not base64)")?;
    cipher.open(VERIFIER_AAD, &verifier).with_context(|| {
        format!(
            "the passphrase supplied for key {} doesn't match the one used to encrypt it \
             (check the passphrase config for this key)",
            material.key_id
        )
    })?;
    Ok(cipher)
}

fn new_key_material(passphrase: &str) -> Result<(KeyMaterial, Cipher)> {
    let key_id = random_key_id()?;
    let salt = random_salt()?;
    let cipher = Cipher::derive(passphrase, &salt)?;
    let material = KeyMaterial {
        key_id: key_id.clone(),
        salt: BASE64.encode(salt),
        verifier: BASE64.encode(cipher.seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)?),
        retired_at_ms: None,
    };
    Ok((material, cipher))
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
    for _ in 0..MAX_BOOTSTRAP_RETRIES {
        let (config, etag) = get_json_plain::<EncryptionConfig>(backend, ENCRYPTION_CONFIG_KEY).await?;

        if etag.is_none() {
            let (material, cipher) = new_key_material(passphrase)?;
            let config = EncryptionConfig {
                active_key_id: material.key_id.clone(),
                keys: vec![material.clone()],
            };
            match put_json_plain(backend, ENCRYPTION_CONFIG_KEY, &config, None).await? {
                Cas::Ok => return Ok(KeyRing::single(material.key_id, cipher)),
                // Another instance bootstrapped the bucket first: discard
                // ours and read back the one that won.
                Cas::Conflict => continue,
            }
        }

        let mut active_cipher = None;
        let mut retired = Vec::new();
        for material in &config.keys {
            if material.key_id == config.active_key_id {
                active_cipher = Some(derive_and_verify(passphrase, material)?);
            } else {
                let retired_passphrase = retired_passphrases.get(&material.key_id).with_context(|| {
                    format!(
                        "bucket has retired key {} with no matching passphrase supplied",
                        material.key_id
                    )
                })?;
                retired.push((
                    material.key_id.clone(),
                    derive_and_verify(retired_passphrase, material)?,
                ));
            }
        }
        let active_cipher =
            active_cipher.context(".conf/encryption.json: active_key_id doesn't match any key in `keys`")?;
        // Most-recently-retired first, matching `KeyRing::open`'s try order.
        retired.reverse();
        return Ok(KeyRing {
            active_key_id: config.active_key_id.clone(),
            active_cipher,
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

        let (material, new_cipher) = new_key_material(new_passphrase)?;
        for existing in &mut config.keys {
            if existing.key_id == config.active_key_id {
                existing.retired_at_ms = Some(now_ms());
            }
        }
        let old_active_id = std::mem::replace(&mut config.active_key_id, material.key_id.clone());
        config.keys.push(material.clone());

        match put_json_plain(backend, ENCRYPTION_CONFIG_KEY, &config, Some(&etag)).await? {
            Cas::Ok => {
                let old_cipher = std::mem::replace(&mut ring.active_cipher, new_cipher);
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

/// Removes a retired key from `EncryptionConfig` for good -- call only once
/// a caller's own accounting (a GC/maintenance sweep) has confirmed zero
/// objects in the bucket still reference `key_id`; this crate has no way to
/// verify that itself. Doesn't touch the in-memory `KeyRing`
/// ([`KeyRing::forget_retired`] is separate, and should usually run first,
/// well before this on-disk cleanup -- see this module's doc comment). A
/// no-op (`Ok(())`) if `key_id` is already gone or was never retired.
pub async fn forget_key(backend: &dyn Backend, key_id: &str) -> Result<()> {
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
