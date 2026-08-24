//! Two independent caches, deliberately not one: [`CachedBackend`] caches
//! raw bytes+etag at the [`crate::backend::Backend`] level (reusable across
//! any `Collection`/`SecondaryIndex` touching the same key, never holds
//! decrypted material); [`TypedCache`] is the opt-in alternative a single
//! `Collection` can choose instead, caching the decrypted, deserialized `T`
//! itself (faster, but only reusable by that one collection). See each
//! type's own doc comment for when to reach for which.
//!
//! [`CachedBackend`] is a **write-through** cache: a confirmed `put_cas`
//! populates it with the bytes the driver just accepted (see
//! [`CachedBackend::put_cas`]) instead of merely invalidating, so the very
//! next read doesn't have to round-trip the driver again. There is
//! deliberately no write-*back* mode -- `put_cas` is this crate's only write
//! primitive and its whole point is a real compare-and-swap outcome
//! (`Cas::Ok`/`Cas::Conflict`) that WAL/lease/manifest code elsewhere
//! depends on being true; a cache that answered `Ok` before the driver
//! confirmed it would hand out a fake CAS result and let two concurrent
//! writers both believe they won.

use crate::backend::{Backend, Cas, DeleteOutcome};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Where [`CachedBackend`] keeps its bytes. Both are size-capped the same
/// way (see [`CacheConfig`]); the only difference is what an eviction/miss
/// costs and whether the cache survives a restart.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CacheBacking {
    /// In memory, gone on restart, no filesystem I/O of its own.
    #[default]
    Memory,
    /// One file per key under `dir`, so `max_bytes` can be sized well past
    /// what's comfortable to hold in the process's own RAM (a "cache local
    /// hasta 1GB" in front of a remote driver is the motivating case) --
    /// survives a restart, at the cost of a local disk write/read per
    /// miss/insert instead of a `Vec<u8>` clone. Wiped and recreated at
    /// [`CachedBackend::new`] every start: entries left over from a
    /// previous run aren't in the fresh in-memory LRU index, so leaving
    /// them on disk would grow the directory unbounded across restarts
    /// instead of staying under `max_bytes` -- safe to discard outright
    /// since this is a cache, never the source of truth.
    Disk { dir: PathBuf },
}

/// Sizing for either cache. `max_entries` is the primary, O(1)-per-op
/// budget -- this crate's own default profile assumes small, uniformly-sized
/// objects (see [`crate::payload::MAX_OBJECT_BYTES`]), so entries alone
/// already bound memory predictably (`max_entries × typical size`) without
/// summing/subtracting a byte count on every insert/evict. `max_bytes` is an
/// optional safety net on top, checked only once `max_entries` is already at
/// capacity -- not the primary accounting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub max_bytes: Option<usize>,
    /// Milliseconds in a config file — see [`crate::serde_duration`].
    #[serde(with = "crate::serde_duration")]
    pub ttl: Duration,
    pub backing: CacheBacking,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: 10_000,
            max_bytes: None,
            ttl: Duration::from_secs(30),
            backing: CacheBacking::default(),
        }
    }
}

struct Entry {
    bytes: Vec<u8>,
    etag: Option<String>,
    inserted_at: Instant,
}

/// [`CacheBacking::Disk`]'s index entry: the bytes themselves live in the
/// file at [`disk_path`]`(dir, key)`, this only tracks what's needed to
/// serve a hit without reading the file (`etag`, TTL) and to account the
/// byte budget without stat-ing it (`size`).
struct DiskEntry {
    etag: Option<String>,
    size: usize,
    inserted_at: Instant,
}

/// Builds `dir/key`, rejecting a key that would escape `dir` -- an absolute
/// path or a `..` component would otherwise let a caller-controlled key
/// read/write outside the cache directory (same concern
/// [`crate::local::files`]'s own key validation exists for).
fn disk_path(dir: &Path, key: &str) -> Result<PathBuf> {
    let rel = Path::new(key);
    if rel.is_absolute() || rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        anyhow::bail!("invalid cache key {key:?}: must be a relative path with no \"..\" segments");
    }
    Ok(dir.join(rel))
}

/// Writes `bytes` to `path` via a temp-file-then-rename so a concurrent
/// reader never sees a half-written cache file. Deliberately no fsync,
/// unlike [`crate::local::files::write_atomic`]'s stricter discipline: that
/// driver IS the source of truth, this is a cache -- an entry lost to a
/// power cut before it would have hit disk is just a miss on the next read,
/// never a correctness problem, so it's not worth paying a sync on every
/// write-through.
async fn write_cache_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("cache path has no parent directory")?;
    tokio::fs::create_dir_all(dir)
        .await
        .with_context(|| format!("creating {}", dir.display()))?;
    let tmp = tempfile::Builder::new()
        .prefix(".s3db-cache-tmp-")
        .tempfile_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    let tmp_path = tmp.into_temp_path();
    tokio::fs::write(&tmp_path, bytes)
        .await
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    tmp_path
        .persist(path)
        .with_context(|| format!("moving temp file -> {}", path.display()))?;
    Ok(())
}

/// The actual storage behind [`CachedBackend`] -- see [`CacheBacking`] for
/// the choice between the two. Every method takes what it needs from
/// [`CacheConfig`] as a parameter rather than holding one, so the config
/// stays a single copy on [`CachedBackend`] itself.
enum Store {
    Memory {
        entries: Mutex<lru::LruCache<String, Entry>>,
        total_bytes: Mutex<usize>,
    },
    Disk {
        dir: PathBuf,
        index: Mutex<lru::LruCache<String, DiskEntry>>,
        total_bytes: Mutex<usize>,
    },
}

impl Store {
    fn new(config: &CacheConfig) -> Self {
        let capacity = std::num::NonZeroUsize::new(config.max_entries.max(1)).expect("max(1) is never zero");
        match &config.backing {
            CacheBacking::Memory => Store::Memory {
                entries: Mutex::new(lru::LruCache::new(capacity)),
                total_bytes: Mutex::new(0),
            },
            CacheBacking::Disk { dir } => {
                // Best-effort wipe+recreate -- see `CacheBacking::Disk`'s doc
                // for why starting empty matters. A failure here just means
                // every subsequent insert fails too (logged there, not
                // fatal): the cache degrades to "never populates", writes
                // still land on the real driver same as always.
                let _ = std::fs::remove_dir_all(dir);
                if let Err(e) = std::fs::create_dir_all(dir) {
                    eprintln!(
                        "s3db: warning: cache: failed to create disk cache dir {}: {e}",
                        dir.display()
                    );
                }
                Store::Disk {
                    dir: dir.clone(),
                    index: Mutex::new(lru::LruCache::new(capacity)),
                    total_bytes: Mutex::new(0),
                }
            }
        }
    }

    async fn get_fresh(&self, key: &str, ttl: Duration) -> Option<(Vec<u8>, Option<String>)> {
        match self {
            Store::Memory { entries, total_bytes } => {
                let expired_bytes = {
                    let mut entries = entries.lock().unwrap();
                    let hit = entries.get(key)?;
                    if hit.inserted_at.elapsed() > ttl {
                        Some(entries.pop(key)?.bytes.len())
                    } else {
                        return Some((hit.bytes.clone(), hit.etag.clone()));
                    }
                };
                if let Some(len) = expired_bytes {
                    let mut total = total_bytes.lock().unwrap();
                    *total = total.saturating_sub(len);
                }
                None
            }
            Store::Disk { dir, index, .. } => {
                let (path, etag, expired) = {
                    let mut idx = index.lock().unwrap();
                    let hit = idx.get(key)?;
                    (
                        disk_path(dir, key).ok()?,
                        hit.etag.clone(),
                        hit.inserted_at.elapsed() > ttl,
                    )
                };
                if expired {
                    self.remove(key).await;
                    return None;
                }
                match tokio::fs::read(&path).await {
                    Ok(bytes) => Some((bytes, etag)),
                    Err(_) => {
                        // Evicted/lost out from under the index somehow
                        // (disk cleared by hand, filesystem issue) -- treat
                        // as a miss and drop the now-stale index entry.
                        self.remove(key).await;
                        None
                    }
                }
            }
        }
    }

    async fn insert(&self, key: &str, bytes: Vec<u8>, etag: Option<String>, max_bytes: Option<usize>) {
        match self {
            Store::Memory { entries, total_bytes } => {
                let new_len = bytes.len();
                let mut entries = entries.lock().unwrap();
                let mut total = total_bytes.lock().unwrap();
                if let Some((_, evicted)) = entries.push(
                    key.to_string(),
                    Entry {
                        bytes,
                        etag,
                        inserted_at: Instant::now(),
                    },
                ) {
                    *total = total.saturating_sub(evicted.bytes.len());
                }
                *total += new_len;
                if let Some(max_bytes) = max_bytes {
                    while *total > max_bytes {
                        let Some((_, evicted)) = entries.pop_lru() else { break };
                        *total = total.saturating_sub(evicted.bytes.len());
                    }
                }
            }
            Store::Disk {
                dir,
                index,
                total_bytes,
            } => {
                let Ok(path) = disk_path(dir, key) else { return };
                let new_len = bytes.len();
                if let Err(e) = write_cache_file(&path, &bytes).await {
                    // Best-effort: the real write already landed on the
                    // driver (this only ever runs after that succeeded) --
                    // a disk-cache write failure just means this key stays
                    // cold, not a failed request.
                    eprintln!("s3db: warning: cache: failed to write disk cache entry for {key:?}: {e}");
                    return;
                }
                let mut evict_paths = Vec::new();
                {
                    let mut idx = index.lock().unwrap();
                    let mut total = total_bytes.lock().unwrap();
                    if let Some((evicted_key, evicted)) = idx.push(
                        key.to_string(),
                        DiskEntry {
                            etag,
                            size: new_len,
                            inserted_at: Instant::now(),
                        },
                    ) {
                        *total = total.saturating_sub(evicted.size);
                        if let Ok(p) = disk_path(dir, &evicted_key) {
                            evict_paths.push(p);
                        }
                    }
                    *total += new_len;
                    if let Some(max_bytes) = max_bytes {
                        while *total > max_bytes {
                            let Some((evicted_key, evicted)) = idx.pop_lru() else {
                                break;
                            };
                            *total = total.saturating_sub(evicted.size);
                            if let Ok(p) = disk_path(dir, &evicted_key) {
                                evict_paths.push(p);
                            }
                        }
                    }
                }
                for p in evict_paths {
                    let _ = tokio::fs::remove_file(p).await;
                }
            }
        }
    }

    async fn remove(&self, key: &str) {
        match self {
            Store::Memory { entries, total_bytes } => {
                let mut entries = entries.lock().unwrap();
                if let Some(evicted) = entries.pop(key) {
                    let mut total = total_bytes.lock().unwrap();
                    *total = total.saturating_sub(evicted.bytes.len());
                }
            }
            Store::Disk {
                dir,
                index,
                total_bytes,
            } => {
                let removed_size = {
                    let mut idx = index.lock().unwrap();
                    idx.pop(key).map(|e| e.size)
                };
                if let Some(size) = removed_size {
                    {
                        let mut total = total_bytes.lock().unwrap();
                        *total = total.saturating_sub(size);
                    }
                    if let Ok(path) = disk_path(dir, key) {
                        let _ = tokio::fs::remove_file(path).await;
                    }
                }
            }
        }
    }
}

/// A [`Backend`] decorator caching raw `get()` results (bytes + etag) across
/// requests -- unlike [`crate::request_cache::RequestCache`], which only
/// lives for one request/connection. Sits **below** any per-request cache
/// and **after** the real driver in a resilience stack (see
/// [`crate::resilience::build_resilient_backend`]): a cache entry here
/// never contains plaintext, only whatever bytes the driver itself would
/// have returned, so it's exactly as safe to share across every caller of
/// this `Backend` (any type, any `Collection`) as the driver's own
/// responses are.
///
/// Reusability across types sharing the same S3 key is the entire reason
/// this caches raw bytes rather than a decrypted, deserialized value -- see
/// [`TypedCache`] for the opt-in trade the other way.
pub struct CachedBackend {
    inner: Arc<dyn Backend>,
    config: CacheConfig,
    store: Store,
}

#[async_trait::async_trait]
impl crate::atomic::AtomicBackend for CachedBackend {
    /// Commits through the inner backend's transaction, then drops this
    /// cache's entry for every key the batch touched -- regardless of
    /// outcome, exactly as [`Backend::put_cas`] already does here, since a
    /// `BatchOutcome::Conflict` still means the stored value may have moved
    /// underneath us. Plain invalidation, not write-through: a batch has no
    /// single confirmed body per key to refresh the cache with.
    async fn commit_batch(&self, ops: Vec<crate::atomic::BatchOp>) -> Result<crate::atomic::BatchOutcome> {
        let touched: Vec<String> = ops.iter().map(|op| op.key().to_string()).collect();
        // `as_atomic` only claims this capability when the inner backend has
        // one, so this is unreachable unless a caller built the trait object
        // some other way.
        let inner = self
            .inner
            .as_atomic()
            .context("CachedBackend::commit_batch: the wrapped backend has no native transaction")?;
        let result = inner.commit_batch(ops).await;
        for key in touched {
            self.remove(&key).await;
        }
        result
    }
}

impl std::fmt::Debug for CachedBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedBackend")
            .field("inner", &self.inner)
            .field("config", &self.config)
            .finish()
    }
}

impl CachedBackend {
    pub fn new(inner: Arc<dyn Backend>, config: CacheConfig) -> Self {
        let store = Store::new(&config);
        CachedBackend { inner, config, store }
    }

    async fn get_fresh(&self, key: &str) -> Option<(Vec<u8>, Option<String>)> {
        self.store.get_fresh(key, self.config.ttl).await
    }

    async fn insert(&self, key: &str, bytes: Vec<u8>, etag: Option<String>) {
        self.store.insert(key, bytes, etag, self.config.max_bytes).await;
    }

    async fn remove(&self, key: &str) {
        self.store.remove(key).await;
    }
}

#[async_trait::async_trait]
impl Backend for CachedBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Claims the capability for *this* layer, not the driver's, whenever the
    /// driver has one -- see [`Backend::as_atomic`]. Handing out a bare inner
    /// reference would let a batch change keys this cache still holds stale
    /// entries for, which is the one bypass that turns into wrong reads
    /// rather than lost bookkeeping.
    fn as_atomic(&self) -> Option<&dyn crate::atomic::AtomicBackend> {
        self.inner
            .as_atomic()
            .map(|_| self as &dyn crate::atomic::AtomicBackend)
    }

    /// Forwarded, not claimed: a range scan populates nothing here, and
    /// bypassing a write-through cache on a read can't return anything
    /// staler than the cache itself holds.
    fn as_range(&self) -> Option<&dyn crate::range::RangeBackend> {
        self.inner.as_range()
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        if let Some(hit) = self.get_fresh(key).await {
            return Ok(hit);
        }
        let (bytes, etag) = self.inner.get(key).await?;
        self.insert(key, bytes.clone(), etag.clone()).await;
        Ok((bytes, etag))
    }

    /// Write-through: once the driver actually confirms the write
    /// (`Cas::Ok`), a follow-up `get` refreshes the cache with the
    /// authoritative bytes+etag -- `Cas` itself carries neither (see the
    /// module doc for why guessing them isn't an option), so this costs one
    /// extra round trip on a write, in exchange for every read until the
    /// next eviction/TTL/write serving from the cache instead of hitting
    /// the driver again. `Conflict`/`Err` invalidate instead, same
    /// reasoning `RequestCache` uses: there's no confirmed body to cache,
    /// so a forced re-fetch on the next `get` is the only correct fallback.
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let result = self.inner.put_cas(key, body, expected_etag).await;
        match &result {
            Ok(Cas::Ok) => match self.inner.get(key).await {
                Ok((bytes, etag)) => self.insert(key, bytes, etag).await,
                Err(_) => self.remove(key).await,
            },
            _ => self.remove(key).await,
        }
        result
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        let result = self.inner.delete(key).await;
        self.remove(key).await;
        result
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        let result = self.inner.delete_many(keys).await;
        for key in keys {
            self.remove(key).await;
        }
        result
    }

    async fn list_page(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<crate::backend::ListPage> {
        self.inner.list_page(prefix, after, limit).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner.list_prefix(prefix).await
    }

    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.inner.get_range(key, offset, len).await
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        self.inner.put_stream(key, source).await
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
}

/// One [`TypedCache`] entry: the decrypted, deserialized value itself,
/// wrapped in `Arc` so a cache hit is `Arc::clone` (a refcount bump) rather
/// than copying the whole struct -- for a value with several text fields,
/// that's the difference this cache exists to capture.
struct TypedEntry<T> {
    value: Arc<T>,
    etag: Option<String>,
    inserted_at: Instant,
}

/// Opt-in per-`Collection` cache of the decrypted, deserialized value,
/// instead of [`CachedBackend`]'s raw bytes -- trades away reusability
/// across other types/collections that might share the same S3 key (rare in
/// practice: `Collection`/`SecondaryIndex` use distinct key namespaces by
/// design) for skipping AEAD-open + deserialize on every hit, which matters
/// when the priority is read latency and the collection is read far more
/// than it's written.
pub struct TypedCache<T> {
    config: CacheConfig,
    entries: Mutex<lru::LruCache<String, TypedEntry<T>>>,
}

impl<T> std::fmt::Debug for TypedCache<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypedCache").field("config", &self.config).finish()
    }
}

impl<T> TypedCache<T> {
    pub fn new(config: CacheConfig) -> Self {
        let capacity = std::num::NonZeroUsize::new(config.max_entries.max(1)).expect("max(1) is never zero");
        TypedCache {
            config,
            entries: Mutex::new(lru::LruCache::new(capacity)),
        }
    }

    /// A fresh cache hit for `name`, or `None` on a miss/expired entry --
    /// the caller still has to fall back to a real `get` + [`Self::insert`]
    /// on `None`, this never talks to a `Backend` itself.
    pub fn get(&self, name: &str) -> Option<(Arc<T>, Option<String>)> {
        let mut entries = self.entries.lock().unwrap();
        let hit = entries.get(name)?;
        if hit.inserted_at.elapsed() > self.config.ttl {
            entries.pop(name);
            return None;
        }
        Some((Arc::clone(&hit.value), hit.etag.clone()))
    }

    pub fn insert(&self, name: &str, value: Arc<T>, etag: Option<String>) {
        self.entries.lock().unwrap().put(
            name.to_string(),
            TypedEntry {
                value,
                etag,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Same invalidation moment as `CachedBackend`'s: any write or delete
    /// through the owning `Collection` must drop the stale entry rather
    /// than risk serving it past its own TTL.
    pub fn invalidate(&self, name: &str) {
        self.entries.lock().unwrap().pop(name);
    }
}

#[cfg(test)]
#[path = "../tests/unit/cache.rs"]
mod tests;
