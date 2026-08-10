//! The raw encrypted-object primitive everything else in this crate builds
//! on. Named `payload`, not `json` (its name until MessagePack replaced JSON
//! here) — the wire format for values passing through [`get_json`]/
//! [`put_json`] is MessagePack now, but the function names/signatures stay
//! the same, so nothing above this module noticed the switch.

use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Hard ceiling on a single object's serialized-but-not-yet-sealed size.
/// This crate's own default profile assumes small, uniformly-sized objects
/// (typed entity structs -- users, groups, configs -- never a blob); without
/// this, an application bug (a field that accidentally ends up holding a
/// large blob) would balloon memory in [`Cipher::seal`] with no warning,
/// since `seal` buffers the whole plaintext before encrypting. A caller that
/// really does need large objects uses `Backend::put_stream`/`get_stream`
/// (the `streaming` feature) instead of this path entirely, so this limit
/// never has to be raised to accommodate one.
pub const MAX_OBJECT_BYTES: usize = 256 * 1024;

/// Reads an object from the bucket and decrypts it with `cipher` (bound to
/// `key` as AAD, see [`Cipher::open`]). Returns `(value, etag)`; if the key
/// doesn't exist yet returns the `Default` and `None` as etag, which is
/// exactly what [`put_json`] expects for a "create if not exists".
pub async fn get_json<T: DeserializeOwned + Default>(
    backend: &dyn Backend,
    key: &str,
    cipher: &Cipher,
) -> Result<(T, Option<String>)> {
    let (sealed, etag) = backend.get(key).await?;
    if sealed.is_empty() {
        return Ok((T::default(), etag));
    }
    let plain = cipher.open(key, &sealed)?;
    let value = rmp_serde::from_slice(&plain).with_context(|| format!("{key} is invalid"))?;
    Ok((value, etag))
}

/// Compare-and-swap write of an object, encrypted before uploading.
/// `expected_etag = None` means "must not exist yet".
pub async fn put_json<T: Serialize>(
    backend: &dyn Backend,
    key: &str,
    value: &T,
    expected_etag: Option<&str>,
    cipher: &Cipher,
) -> Result<Cas> {
    let plain = rmp_serde::to_vec_named(value).with_context(|| format!("serializing {key}"))?;
    if plain.len() > MAX_OBJECT_BYTES {
        bail!(
            "{key}: object is {} bytes, over this crate's {MAX_OBJECT_BYTES}-byte limit for a single object",
            plain.len()
        );
    }
    // Fixed to `None` for this crate's own default profile (small, uniform
    // objects -- see `MAX_OBJECT_BYTES` above): the size check `Auto` would
    // otherwise run on every write essentially never trips at this scale, so
    // the branch is skipped entirely rather than evaluated per write.
    let sealed = cipher.seal(key, &plain, CompressionStrategy::None);
    backend.put_cas(key, sealed, expected_etag).await
}

/// Same as [`get_json`] but WITHOUT encryption, and still plain JSON (not
/// MessagePack): only for [`crate::bootstrap::get_or_create_cipher`], which
/// needs to read the derivation salt before it can build a `Cipher`, and for
/// `.conf/encryption.json` generally -- the one object in the bucket meant
/// to be inspected by hand during an incident, so it stays both unencrypted
/// (a salt isn't secret) and human-readable. Nothing else should use this.
pub(crate) async fn get_json_plain<T: DeserializeOwned + Default>(
    backend: &dyn Backend,
    key: &str,
) -> Result<(T, Option<String>)> {
    let (bytes, etag) = backend.get(key).await?;
    let value = if bytes.is_empty() {
        T::default()
    } else {
        serde_json::from_slice(&bytes).with_context(|| format!("{key} is invalid"))?
    };
    Ok((value, etag))
}

/// Unencrypted, plain-JSON counterpart of [`put_json`], see
/// [`get_json_plain`].
pub(crate) async fn put_json_plain<T: Serialize>(
    backend: &dyn Backend,
    key: &str,
    value: &T,
    expected_etag: Option<&str>,
) -> Result<Cas> {
    let body = serde_json::to_vec_pretty(value).with_context(|| format!("serializing {key}"))?;
    backend.put_cas(key, body, expected_etag).await
}

/// [`Backend::delete`], as a free function so most call sites read the same
/// as [`get_json`]/[`put_json`] instead of needing the trait itself in
/// scope.
pub async fn delete_object(backend: &dyn Backend, key: &str) {
    let _ = backend.delete(key).await;
}

/// [`Backend::list_prefix`], keys only — what most prefix-scans need.
/// Callers that need size too call `Backend::list_prefix` directly.
pub async fn list_all_keys(backend: &dyn Backend, prefix: &str) -> Result<Vec<String>> {
    Ok(backend
        .list_prefix(prefix)
        .await?
        .into_iter()
        .map(|(key, _size)| key)
        .collect())
}

#[cfg(test)]
#[path = "../tests/unit/payload.rs"]
mod tests;
