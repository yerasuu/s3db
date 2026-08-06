use crate::config::BackendConfig;
use anyhow::Result;
#[cfg(not(feature = "streaming"))]
use anyhow::bail;
use std::path::Path;
use std::sync::Arc;

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
/// implement; it's deliberately small — derived from an audit of every S3
/// call gitquarry actually makes, not a speculative superset (no presign,
/// multipart, byte-range, versioning, or ACLs anywhere in the tree).
#[async_trait::async_trait]
pub trait Backend: Send + Sync + std::fmt::Debug {
    /// Raw body + an opaque version token ("etag"), or empty bytes and
    /// `None` if `key` doesn't exist yet.
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)>;
    /// Compare-and-swap write. `expected_etag = None` means "must not exist
    /// yet". A driver with no native conditional-write support (e.g. a
    /// shared network filesystem) must still give this real CAS semantics,
    /// not best-effort — `refs.json`'s CAS is what stops a concurrent push
    /// from silently clobbering another one.
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
    /// required one — a caller that does need it (large blobs: packs, LFS
    /// objects, ...) just enables the feature, no driver has to implement a
    /// stub for the other case.
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
}

/// Builds the right [`Backend`] for `cfg` — the single place that turns
/// config into a live storage connection.
pub fn build_backend(cfg: &BackendConfig) -> Arc<dyn Backend> {
    match cfg {
        BackendConfig::S3(params) => Arc::new(crate::s3::S3Backend::new(params)),
        BackendConfig::R2(params) => Arc::new(crate::s3::S3Backend::new_r2(params)),
        BackendConfig::Azure(params) => Arc::new(crate::azure::AzureBackend::new(params)),
        BackendConfig::Gcs(params) => Arc::new(crate::gcs::GcsBackend::new(params)),
        BackendConfig::Local(params) => Arc::new(crate::local::LocalBackend::new(params)),
    }
}
