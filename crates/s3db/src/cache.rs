//! Two independent caches, deliberately not one: [`CachedBackend`] caches
//! raw bytes+etag at the [`crate::backend::Backend`] level (reusable across
//! any `Collection`/`SecondaryIndex` touching the same key, never holds
//! decrypted material); [`TypedCache`] is the opt-in alternative a single
//! `Collection` can choose instead, caching the decrypted, deserialized `T`
//! itself (faster, but only reusable by that one collection). See each
//! type's own doc comment for when to reach for which.

use crate::backend::{Backend, Cas, DeleteOutcome};
use anyhow::Result;
#[cfg(feature = "streaming")]
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Sizing for either cache. `max_entries` is the primary, O(1)-per-op
/// budget -- this crate's own default profile assumes small, uniformly-sized
/// objects (see [`crate::payload::MAX_OBJECT_BYTES`]), so entries alone
/// already bound memory predictably (`max_entries × typical size`) without
/// summing/subtracting a byte count on every insert/evict. `max_bytes` is an
/// optional safety net on top, checked only once `max_entries` is already at
/// capacity -- not the primary accounting.
#[derive(Debug, Clone, Copy)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub max_bytes: Option<usize>,
    pub ttl: Duration,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: 10_000,
            max_bytes: None,
            ttl: Duration::from_secs(30),
        }
    }
}

struct Entry {
    bytes: Vec<u8>,
    etag: Option<String>,
    inserted_at: Instant,
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
    entries: Mutex<lru::LruCache<String, Entry>>,
    total_bytes: Mutex<usize>,
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
        let capacity = std::num::NonZeroUsize::new(config.max_entries.max(1)).expect("max(1) is never zero");
        CachedBackend {
            inner,
            config,
            entries: Mutex::new(lru::LruCache::new(capacity)),
            total_bytes: Mutex::new(0),
        }
    }

    fn get_fresh(&self, key: &str) -> Option<(Vec<u8>, Option<String>)> {
        let mut entries = self.entries.lock().unwrap();
        let hit = entries.get(key)?;
        if hit.inserted_at.elapsed() > self.config.ttl {
            drop(entries);
            self.remove(key);
            return None;
        }
        Some((hit.bytes.clone(), hit.etag.clone()))
    }

    fn insert(&self, key: &str, bytes: Vec<u8>, etag: Option<String>) {
        let new_len = bytes.len();
        let mut entries = self.entries.lock().unwrap();
        let mut total = self.total_bytes.lock().unwrap();
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
        // `max_bytes` safety net: once `max_entries`' own LRU eviction isn't
        // enough (a handful of oversized entries blew the byte budget
        // before entry-count capacity was reached), evict oldest until back
        // under budget -- secondary to `max_entries`, never the primary
        // per-operation accounting.
        if let Some(max_bytes) = self.config.max_bytes {
            while *total > max_bytes {
                let Some((_, evicted)) = entries.pop_lru() else { break };
                *total = total.saturating_sub(evicted.bytes.len());
            }
        }
    }

    fn remove(&self, key: &str) {
        let mut entries = self.entries.lock().unwrap();
        if let Some(evicted) = entries.pop(key) {
            let mut total = self.total_bytes.lock().unwrap();
            *total = total.saturating_sub(evicted.bytes.len());
        }
    }
}

#[async_trait::async_trait]
impl Backend for CachedBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        if let Some(hit) = self.get_fresh(key) {
            return Ok(hit);
        }
        let (bytes, etag) = self.inner.get(key).await?;
        self.insert(key, bytes.clone(), etag.clone());
        Ok((bytes, etag))
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let result = self.inner.put_cas(key, body, expected_etag).await;
        // Invalidate regardless of outcome, same reasoning as
        // `RequestCache`: guessing the post-write etag isn't worth the risk
        // of getting it wrong, a forced re-fetch on the next `get` is cheap
        // and always correct.
        self.remove(key);
        result
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        let result = self.inner.delete(key).await;
        self.remove(key);
        result
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        let result = self.inner.delete_many(keys).await;
        for key in keys {
            self.remove(key);
        }
        result
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner.list_prefix(prefix).await
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
    /// the caller (`Collection::get_cached`) still has to fall back to a
    /// real `get` + insert on `None`, this never talks to a `Backend`
    /// itself.
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
mod tests {
    use super::*;
    use crate::config::{LocalEngine, LocalParams};
    use crate::local::LocalBackend;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct CountingBackend {
        inner: LocalBackend,
        gets: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Backend for CountingBackend {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            self.inner.get(key).await
        }
        async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
            self.inner.put_cas(key, body, expected_etag).await
        }
        async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
            self.inner.delete(key).await
        }
        async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
            self.inner.delete_many(keys).await
        }
        async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
            self.inner.list_prefix(prefix).await
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

    fn local(root: &std::path::Path) -> LocalBackend {
        LocalBackend::new(&LocalParams {
            bucket: root.to_string_lossy().to_string(),
            engine: LocalEngine::Files,
        })
    }

    #[tokio::test]
    async fn a_second_get_is_served_from_cache() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBackend {
            inner: local(dir.path()),
            gets: AtomicUsize::new(0),
        });
        counting.put_cas("k", b"v1".to_vec(), None).await.unwrap();
        let cached = CachedBackend::new(counting.clone(), CacheConfig::default());

        cached.get("k").await.unwrap();
        cached.get("k").await.unwrap();
        assert_eq!(counting.gets.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn put_cas_invalidates_the_cached_entry() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBackend {
            inner: local(dir.path()),
            gets: AtomicUsize::new(0),
        });
        counting.put_cas("k", b"v1".to_vec(), None).await.unwrap();
        let cached = CachedBackend::new(counting.clone(), CacheConfig::default());
        let (_, etag) = cached.get("k").await.unwrap();

        cached.put_cas("k", b"v2".to_vec(), etag.as_deref()).await.unwrap();
        let (bytes, _) = cached.get("k").await.unwrap();
        assert_eq!(bytes, b"v2");
        assert_eq!(counting.gets.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn entries_over_ttl_are_treated_as_a_miss() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBackend {
            inner: local(dir.path()),
            gets: AtomicUsize::new(0),
        });
        counting.put_cas("k", b"v1".to_vec(), None).await.unwrap();
        let cached = CachedBackend::new(
            counting.clone(),
            CacheConfig {
                max_entries: 10,
                max_bytes: None,
                ttl: Duration::from_millis(0),
            },
        );

        cached.get("k").await.unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        cached.get("k").await.unwrap();
        assert_eq!(
            counting.gets.load(Ordering::SeqCst),
            2,
            "expired entry must not be served from cache"
        );
    }

    #[tokio::test]
    async fn max_entries_evicts_the_least_recently_used() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBackend {
            inner: local(dir.path()),
            gets: AtomicUsize::new(0),
        });
        for (k, v) in [("a", "1"), ("b", "2")] {
            counting.put_cas(k, v.as_bytes().to_vec(), None).await.unwrap();
        }
        let cached = CachedBackend::new(
            counting.clone(),
            CacheConfig {
                max_entries: 1,
                max_bytes: None,
                ttl: Duration::from_secs(60),
            },
        );

        cached.get("a").await.unwrap(); // cache: {a}
        cached.get("b").await.unwrap(); // cache: {b}, a evicted (capacity 1)
        cached.get("a").await.unwrap(); // miss again
        assert_eq!(counting.gets.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn typed_cache_hit_returns_an_arc_clone() {
        let cache: TypedCache<String> = TypedCache::new(CacheConfig::default());
        let value = Arc::new("hello".to_string());
        cache.insert("k", Arc::clone(&value), Some("etag1".to_string()));

        let (hit, etag) = cache.get("k").unwrap();
        assert!(
            Arc::ptr_eq(&hit, &value),
            "a hit must be the same allocation, not a fresh copy"
        );
        assert_eq!(etag.as_deref(), Some("etag1"));
    }

    #[test]
    fn typed_cache_invalidate_makes_the_next_get_miss() {
        let cache: TypedCache<String> = TypedCache::new(CacheConfig::default());
        cache.insert("k", Arc::new("v".to_string()), None);
        cache.invalidate("k");
        assert!(cache.get("k").is_none());
    }
}
