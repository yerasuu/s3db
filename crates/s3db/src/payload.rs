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
    let sealed = cipher.seal(key, &plain, CompressionStrategy::None)?;
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

/// What one [`delete_prefix`] sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Keys handed to [`Backend::delete_many`] across every pass. A key
    /// that needed two passes is counted twice — this measures work done,
    /// not distinct keys.
    pub attempted: usize,
    /// Deletes the backend confirmed.
    pub confirmed: usize,
    /// Keys still under the prefix when the sweep stopped. Non-zero means
    /// the sweep is unfinished, not that it failed: call it again.
    pub remaining: usize,
}

impl SweepReport {
    /// `true` when nothing is left under the prefix.
    pub fn is_complete(&self) -> bool {
        self.remaining == 0
    }
}

/// How many list/delete passes one [`delete_prefix`] call makes before
/// reporting what's left instead of looping again. A pass exists because
/// [`Backend::delete`] is best-effort per key (see [`crate::DeleteOutcome`]):
/// a delete that didn't confirm has to be retried, and the honest way to
/// know what didn't land is to list again. Bounded because a writer
/// concurrently creating keys under the same prefix would otherwise keep
/// this looping forever — at which point the caller, not this function,
/// should decide whether to keep sweeping.
const MAX_SWEEP_PASSES: u32 = 8;

/// Deletes every object under `prefix`, resumably.
///
/// This is the cascade that a relational schema gets from
/// `ON DELETE CASCADE` and that object storage has no equivalent for: the
/// children of a deleted entity are just keys sharing a prefix, and
/// somebody has to enumerate and remove them. Idempotent by construction —
/// each pass re-lists, so calling it again after a partial sweep (a crash,
/// an exhausted pass budget, a delete that didn't confirm) picks up exactly
/// what's left rather than needing a cursor persisted somewhere.
///
/// Stops early, without consuming its pass budget, if a pass confirms
/// nothing at all: that means the backend is refusing these deletes rather
/// than making slow progress, and re-listing the same keys forever won't
/// change it.
///
/// `prefix` is matched as a literal string prefix, not a path component, so
/// `"work/1"` also matches `"work/10/..."`. Pass the trailing `/` when a
/// directory-like boundary is what's meant. An empty prefix is refused: it
/// would match every object in the bucket, which is never something worth
/// expressing by accident.
pub async fn delete_prefix(backend: &dyn Backend, prefix: &str) -> Result<SweepReport> {
    if prefix.is_empty() {
        bail!("delete_prefix: refusing an empty prefix (it would match every object in the bucket)");
    }
    let mut report = SweepReport::default();
    for _pass in 0..MAX_SWEEP_PASSES {
        let keys = list_all_keys(backend, prefix).await?;
        if keys.is_empty() {
            report.remaining = 0;
            return Ok(report);
        }
        report.attempted += keys.len();
        let outcome = backend.delete_many(&keys).await?;
        report.confirmed += outcome.confirmed;
        if outcome.confirmed == 0 {
            report.remaining = keys.len();
            return Ok(report);
        }
    }
    report.remaining = list_all_keys(backend, prefix).await?.len();
    Ok(report)
}

/// How many objects live under `prefix`, and how many bytes they occupy.
///
/// One `list_prefix` (which every driver already paginates internally), not
/// a read of anything — sizes come from the listing itself. The cheapest
/// honest answer to "how many are there" without maintaining a counter, and
/// the right fallback for a count that isn't hot enough to justify one. For
/// a count that *is* hot, keep a counter with
/// [`crate::Collection::update`] instead: this is O(number of keys) in both
/// requests and memory, every call.
pub async fn count_prefix(backend: &dyn Backend, prefix: &str) -> Result<(u64, u64)> {
    let entries = backend.list_prefix(prefix).await?;
    let bytes = entries.iter().map(|(_key, size)| *size).sum();
    Ok((entries.len() as u64, bytes))
}

#[cfg(test)]
#[path = "../tests/unit/payload.rs"]
mod tests;
