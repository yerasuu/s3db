use crate::config::BackendConfig;
use anyhow::Result;
#[cfg(not(feature = "streaming"))]
use anyhow::bail;
use std::path::Path;
use std::sync::Arc;

/// Wraps an error a driver already knows, from its own HTTP status code,
/// will never succeed no matter how many times it's retried (bad request,
/// auth failure, not found, ...) -- as opposed to a transient one (a
/// dropped connection, a 429, a 5xx) that a retry might actually fix. See
/// [`is_permanent`]/[`is_permanent_status`].
///
/// `Display`/`Debug` delegate straight through to the wrapped error, so
/// tagging one this way never changes what a caller further up sees when
/// it prints or logs it -- only [`is_permanent`] can tell the difference.
#[derive(Debug)]
struct Permanent(anyhow::Error);

impl std::fmt::Display for Permanent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for Permanent {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

/// Tags `err` as [`is_permanent`] -- a driver calls this at the point it
/// already knows (from a status code it just checked) that retrying is
/// pointless, right before handing the error back up to
/// `crate::resilience::RetryBackend`.
pub(crate) fn permanent(err: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(Permanent(err))
}

/// `true` if `err` was tagged via [`permanent`].
pub(crate) fn is_permanent(err: &anyhow::Error) -> bool {
    err.downcast_ref::<Permanent>().is_some()
}

/// `true` for an HTTP status a driver already checked that retrying will
/// never fix: a malformed request, an auth failure, or a resource that
/// genuinely doesn't exist -- as opposed to rate-limiting (429) or a
/// server-side problem (5xx), both worth retrying, or no status at all (a
/// network-level failure below the HTTP layer, also worth retrying).
pub(crate) fn is_permanent_status(status: u16) -> bool {
    matches!(status, 400 | 401 | 403 | 404 | 405 | 501)
}

/// Result of a compare-and-swap write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cas {
    Ok,
    Conflict,
}

/// Outcome of a best-effort delete. Informative bookkeeping, never a
/// business-logic failure signal — nothing here changes the underlying
/// contract that a caller never depends on a delete actually landing. But it
/// gives a caller that *does* want to know (an orphan-purge retry, a GC
/// sweep) a real answer instead of silently guessing: `confirmed < attempted`
/// means some keys are still out there, `confirmed == attempted` means every
/// one of them is gone (or was already gone — a 404 on delete counts as
/// confirmed, same as a 200).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DeleteOutcome {
    pub attempted: usize,
    pub confirmed: usize,
}

impl DeleteOutcome {
    /// Sums a batch of per-key outcomes into one — every driver's
    /// `delete_many` fans out to individual deletes and needs to fold the
    /// results back into a single [`DeleteOutcome`].
    pub(crate) fn combine(results: impl IntoIterator<Item = DeleteOutcome>) -> Self {
        results
            .into_iter()
            .fold(DeleteOutcome::default(), |acc, o| DeleteOutcome {
                attempted: acc.attempted + o.attempted,
                confirmed: acc.confirmed + o.confirmed,
            })
    }
}

/// One storage provider, bound to a single bucket/container/root at
/// construction time — every method below takes just a `key`, never a
/// bucket, because there's nothing left to disambiguate once a `Backend` is
/// built. This is the entire surface every driver (`s3`, `local`, and
/// whatever else `driver = "..."` in the caller's config selects) has to
/// implement; it's deliberately small — derived from an audit of the S3
/// calls a real caller actually makes, not a speculative superset (no
/// presign, multipart, byte-range, versioning, or ACLs anywhere in the
/// tree).
#[async_trait::async_trait]
pub trait Backend: Send + Sync + std::fmt::Debug + 'static {
    /// Raw body + an opaque version token ("etag"), or empty bytes and
    /// `None` if `key` doesn't exist yet.
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)>;
    /// Compare-and-swap write. `expected_etag = None` means "must not exist
    /// yet". A driver with no native conditional-write support (e.g. a
    /// shared network filesystem) must still give this real CAS semantics,
    /// not best-effort — this is what stops one concurrent writer from
    /// silently clobbering another.
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas>;
    /// Best-effort delete: missing-already isn't an error (the caller's
    /// goal, "this key is gone", already holds), and a single key's own
    /// delete failure never aborts the call — never used for anything a
    /// caller actually depends on succeeding, that's what [`Self::put_cas`]
    /// is for. The returned [`DeleteOutcome`] is that "best-effort" made
    /// legible instead of silently swallowed.
    async fn delete(&self, key: &str) -> Result<DeleteOutcome>;
    /// Same as [`Self::delete`], batched — each driver chunks internally to
    /// its own provider-side limit (S3's `DeleteObjects` caps at 1000, for
    /// instance), so callers never have to know it. Same signature as
    /// [`Self::delete`] on purpose (see [`DeleteOutcome`]'s doc comment) —
    /// there's no reason one of the two should be able to report what
    /// happened and the other not.
    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome>;
    /// Every `(key, size)` under `prefix`, fully paginated internally.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>>;
    /// Fetches exactly `len` bytes starting at `offset` in `key`'s stored
    /// object — the primitive `crate::lsm`'s read path is built on
    /// (`docs/s3db-fulldb-roadmap.md` phase 2): a point lookup or range scan
    /// fetches only the footer and the one or two blocks it actually needs,
    /// never a whole multi-megabyte SSTable object. Every driver here
    /// already speaks HTTP and supports native byte-range reads (S3/R2/GCS/
    /// Azure via the standard `Range` header, `Local`/`Redb` via a seek or a
    /// slice) — mechanical per driver, not a capability that had to be
    /// invented. Required (not feature-gated like streaming): unlike large
    /// blobs, every existing driver can give this for free, there's no
    /// dependency or memory-profile tradeoff to opt out of.
    ///
    /// `offset + len` past the object's actual end is an error, not a
    /// short read — a caller that computed `offset`/`len` from a manifest
    /// entry (the only place they should come from) has a real bug if they
    /// don't match what's actually stored.
    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>>;
    /// Uploads `source` (a file already on local disk, already-sealed
    /// ciphertext) to `key`, streaming — bounded memory regardless of the
    /// file's size, unlike a buffered `put`. Deliberately no CAS variant:
    /// nothing that streams ever needs conditional-write semantics.
    ///
    /// Gated behind the `streaming` feature (off by default, see this
    /// crate's `Cargo.toml`): this crate's own default profile assumes small,
    /// uniformly-sized objects (see `json`'s `MAX_OBJECT_BYTES` guard), so
    /// every driver's real chunked-upload code is dead weight, never
    /// exercised, under that profile. Without the feature this is a provided
    /// method returning [`anyhow::Error`] ("streaming disabled") instead of a
    /// required one — a caller that does need it (large binary blobs) just
    /// enables the feature, no driver has to implement a stub for the other
    /// case.
    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()>;
    #[cfg(not(feature = "streaming"))]
    async fn put_stream(&self, _key: &str, _source: &Path) -> Result<()> {
        bail!("streaming is disabled (enable s3db's `streaming` cargo feature)")
    }
    /// Downloads `key`'s raw bytes to `dest`, streaming — the other half of
    /// [`Self::put_stream`]. Missing key is a hard error (`bail`) here,
    /// unlike [`Self::get`]'s empty-bytes-plus-`None`: every real caller of
    /// this already treats "the object exists" as an invariant (a pack the
    /// manifest lists), so this just gives that a clear message instead of
    /// failing later, confusingly, at the decrypt step. Same feature-gating
    /// as [`Self::put_stream`].
    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()>;
    #[cfg(not(feature = "streaming"))]
    async fn get_stream(&self, _key: &str, _dest: &Path) -> Result<()> {
        bail!("streaming is disabled (enable s3db's `streaming` cargo feature)")
    }

    /// Lets a caller downcast `&dyn Backend` back to its concrete type to
    /// check for a capability beyond this trait's minimal surface (see
    /// `crate::atomic::AtomicBackend`). No default body: the unsizing
    /// coercion from `&Self` to `&dyn Any` needs a concrete, sized `Self` at
    /// the call site, which a trait's default method body -- compiled once,
    /// generically, for every implementor at once -- can't give it. Every
    /// implementor's body is the same one line, `self`.
    fn as_any(&self) -> &dyn std::any::Any;

    /// This backend's native-transaction capability, if it has one.
    ///
    /// Capability discovery used to be a downcast to a concrete driver type
    /// performed by the caller (`atomic::as_atomic`), which could only ever
    /// see the type at the very top of an `Arc<dyn Backend>`: a driver behind
    /// [`crate::CachedBackend`] or any other decorator silently lost the
    /// capability, and the resilience stack always puts at least one
    /// decorator in the way. Asking the backend itself lets every layer
    /// answer for its own chain.
    ///
    /// A decorator that only observes traffic (metrics, retries, throttling)
    /// forwards this to what it wraps — the resulting call bypasses that
    /// layer, which costs its bookkeeping and nothing else. A decorator whose
    /// correctness depends on seeing every write (the caches) must **not**
    /// forward a bare inner reference: a batch committed straight to the
    /// driver would leave cached entries for the keys it just changed. Those
    /// implement the capability themselves, so the invalidation still
    /// happens. Which is exactly why this is a method here rather than a
    /// downcast out there: a layer can insert itself into the capability
    /// instead of being skipped by it.
    fn as_atomic(&self) -> Option<&dyn crate::atomic::AtomicBackend> {
        None
    }

    /// This backend's ordered-range-scan capability, if it has one — same
    /// discovery mechanism as [`Self::as_atomic`], see there.
    ///
    /// A range scan is a read that populates no cache, so a caching
    /// decorator forwards this rather than implementing it: bypassing a
    /// write-through cache on a read can't return anything staler than the
    /// cache itself holds.
    fn as_range(&self) -> Option<&dyn crate::range::RangeBackend> {
        None
    }
}

/// Builds the right [`Backend`] for `cfg` — the single place that turns
/// config into a live storage connection.
pub fn build_backend(cfg: &BackendConfig) -> Result<Arc<dyn Backend>> {
    Ok(match cfg {
        BackendConfig::S3(params) => Arc::new(crate::s3::S3Backend::new(params)?),
        BackendConfig::R2(params) => Arc::new(crate::s3::S3Backend::new_r2(params)?),
        BackendConfig::Azure(params) => Arc::new(crate::azure::AzureBackend::new(params)),
        BackendConfig::Gcs(params) => Arc::new(crate::gcs::GcsBackend::new(params)),
        BackendConfig::Local(params) => Arc::new(crate::local::LocalBackend::new(params)),
    })
}
