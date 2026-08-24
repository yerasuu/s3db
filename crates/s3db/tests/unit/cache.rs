use super::*;
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

fn local(root: &std::path::Path) -> LocalBackend {
    crate::local::test_support::files_backend(root)
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
async fn put_cas_refreshes_the_cache_with_confirmed_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let counting = Arc::new(CountingBackend {
        inner: local(dir.path()),
        gets: AtomicUsize::new(0),
    });
    counting.put_cas("k", b"v1".to_vec(), None).await.unwrap();
    let cached = CachedBackend::new(counting.clone(), CacheConfig::default());
    let (_, etag) = cached.get("k").await.unwrap();

    cached.put_cas("k", b"v2".to_vec(), etag.as_deref()).await.unwrap();
    // The confirmed write-through refresh is the driver's only other hit --
    // not yet a fresh read after this point.
    assert_eq!(counting.gets.load(Ordering::SeqCst), 2);

    let (bytes, _) = cached.get("k").await.unwrap();
    let (bytes_again, _) = cached.get("k").await.unwrap();
    assert_eq!(bytes, b"v2");
    assert_eq!(bytes_again, b"v2");
    // Both served from the cache the write-through refresh populated: no
    // further driver hits.
    assert_eq!(counting.gets.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn put_cas_conflict_invalidates_instead_of_caching() {
    let dir = tempfile::tempdir().unwrap();
    let counting = Arc::new(CountingBackend {
        inner: local(dir.path()),
        gets: AtomicUsize::new(0),
    });
    counting.put_cas("k", b"v1".to_vec(), None).await.unwrap();
    let cached = CachedBackend::new(counting.clone(), CacheConfig::default());
    cached.get("k").await.unwrap(); // cache: {k: v1}, gets=1

    // Wrong expected_etag -> Conflict, nothing confirmed to cache.
    let cas = cached.put_cas("k", b"v2".to_vec(), None).await.unwrap();
    assert_eq!(cas, Cas::Conflict);

    // Must re-fetch: the stale entry was invalidated, not refreshed with
    // the rejected body.
    let (bytes, _) = cached.get("k").await.unwrap();
    assert_eq!(bytes, b"v1");
    assert_eq!(counting.gets.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn disk_backing_survives_the_memory_cache_never_seeing_it() {
    let backend_dir = tempfile::tempdir().unwrap();
    let cache_dir = tempfile::tempdir().unwrap();
    let counting = Arc::new(CountingBackend {
        inner: local(backend_dir.path()),
        gets: AtomicUsize::new(0),
    });
    counting.put_cas("a/b/k", b"v1".to_vec(), None).await.unwrap();
    let cached = CachedBackend::new(
        counting.clone(),
        CacheConfig {
            max_entries: 10,
            max_bytes: None,
            ttl: Duration::from_secs(60),
            backing: CacheBacking::Disk {
                dir: cache_dir.path().to_path_buf(),
            },
        },
    );

    let (bytes, _) = cached.get("a/b/k").await.unwrap();
    assert_eq!(bytes, b"v1");
    assert!(
        cache_dir.path().join("a/b/k").is_file(),
        "expected one real file per key under the cache dir"
    );

    cached.get("a/b/k").await.unwrap();
    assert_eq!(
        counting.gets.load(Ordering::SeqCst),
        1,
        "second get must be served from the disk cache"
    );
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
            backing: CacheBacking::Memory,
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
            backing: CacheBacking::Memory,
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
