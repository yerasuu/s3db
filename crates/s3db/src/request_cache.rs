//! A [`Backend`] decorator that memoizes `get` within one request/
//! operation's lifetime — deliberately *not* a process-wide cache.
//! gitquarry runs multiple server instances against the same bucket, so a
//! cached `User`/permission record that outlived the request it was built
//! for could let a revoked permission or key stay "live" longer than it
//! should. Callers are expected to build one `RequestCache` per connection
//! or request and drop it afterward — never stash it somewhere long-lived.

use crate::backend::{Backend, Cas, DeleteOutcome};
use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// A cached `get` result: raw body plus its etag, exactly [`Backend::get`]'s
/// own return shape.
type CachedGet = (Vec<u8>, Option<String>);

/// Wraps an inner [`Backend`], remembering the result of each `get` so a
/// second read of the same key within the same `RequestCache`'s lifetime
/// doesn't hit the inner backend again. Any write-shaped call
/// (`put_cas`/`delete`/`delete_many`) invalidates the keys it touches rather
/// than trying to patch the cached value in place — guessing the post-write
/// etag isn't worth the risk of getting it wrong, a forced re-fetch is cheap
/// and always correct.
#[derive(Debug)]
pub struct RequestCache {
    inner: Arc<dyn Backend>,
    reads: Mutex<HashMap<String, CachedGet>>,
}

impl RequestCache {
    pub fn new(inner: Arc<dyn Backend>) -> Self {
        RequestCache { inner, reads: Mutex::new(HashMap::new()) }
    }
}

#[async_trait::async_trait]
impl Backend for RequestCache {
    async fn get(&self, key: &str) -> Result<CachedGet> {
        if let Some(hit) = self.reads.lock().unwrap().get(key) {
            return Ok(hit.clone());
        }
        let value = self.inner.get(key).await?;
        self.reads.lock().unwrap().insert(key.to_string(), value.clone());
        Ok(value)
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let result = self.inner.put_cas(key, body, expected_etag).await;
        // Invalidate regardless of outcome: even a `Cas::Conflict` means the
        // stored value may have changed underneath us since our last read.
        self.reads.lock().unwrap().remove(key);
        result
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        let result = self.inner.delete(key).await;
        self.reads.lock().unwrap().remove(key);
        result
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        let result = self.inner.delete_many(keys).await;
        let mut reads = self.reads.lock().unwrap();
        for key in keys {
            reads.remove(key);
        }
        drop(reads);
        result
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner.list_prefix(prefix).await
    }

    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        self.inner.put_stream(key, source).await
    }

    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalParams;
    use crate::local::LocalBackend;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test-only decorator counting how many times `get` actually reaches
    /// the inner backend — the thing `RequestCache` is supposed to shield
    /// its inner backend from on a repeat read of the same key.
    #[derive(Debug)]
    struct CountingBackend {
        inner: LocalBackend,
        gets: AtomicUsize,
    }

    impl CountingBackend {
        fn new(inner: LocalBackend) -> Self {
            CountingBackend { inner, gets: AtomicUsize::new(0) }
        }

        fn get_count(&self) -> usize {
            self.gets.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl Backend for CountingBackend {
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

        async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
            self.inner.put_stream(key, source).await
        }

        async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
            self.inner.get_stream(key, dest).await
        }
    }

    fn local_backend(root: &Path) -> LocalBackend {
        LocalBackend::new(&LocalParams { bucket: root.to_string_lossy().to_string() })
    }

    #[tokio::test]
    async fn a_second_get_on_the_same_key_is_served_from_the_cache() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBackend::new(local_backend(dir.path())));
        counting.put_cas("k", b"v1".to_vec(), None).await.unwrap();

        let cache = RequestCache::new(Arc::clone(&counting) as Arc<dyn Backend>);
        let (bytes1, _) = cache.get("k").await.unwrap();
        let (bytes2, _) = cache.get("k").await.unwrap();

        assert_eq!(bytes1, b"v1");
        assert_eq!(bytes2, b"v1");
        assert_eq!(counting.get_count(), 1);
    }

    #[tokio::test]
    async fn put_cas_invalidates_so_the_next_get_is_real_and_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBackend::new(local_backend(dir.path())));
        counting.put_cas("k", b"v1".to_vec(), None).await.unwrap();

        let cache = RequestCache::new(Arc::clone(&counting) as Arc<dyn Backend>);
        let (_, etag1) = cache.get("k").await.unwrap();
        assert_eq!(counting.get_count(), 1);

        // Write through the cache itself, as a real caller would.
        cache.put_cas("k", b"v2".to_vec(), etag1.as_deref()).await.unwrap();

        let (bytes2, _) = cache.get("k").await.unwrap();
        assert_eq!(bytes2, b"v2");
        // The get after the write must have gone to the inner backend again,
        // not returned the stale cached "v1".
        assert_eq!(counting.get_count(), 2);
    }

    #[tokio::test]
    async fn delete_invalidates_so_the_next_get_sees_the_key_is_gone() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBackend::new(local_backend(dir.path())));
        counting.put_cas("k", b"v1".to_vec(), None).await.unwrap();

        let cache = RequestCache::new(Arc::clone(&counting) as Arc<dyn Backend>);
        let (bytes1, _) = cache.get("k").await.unwrap();
        assert_eq!(bytes1, b"v1");
        assert_eq!(counting.get_count(), 1);

        cache.delete("k").await.unwrap();

        let (bytes2, etag2) = cache.get("k").await.unwrap();
        assert!(bytes2.is_empty());
        assert!(etag2.is_none());
        assert_eq!(counting.get_count(), 2);
    }

    #[tokio::test]
    async fn delete_many_invalidates_every_key_it_touches() {
        let dir = tempfile::tempdir().unwrap();
        let counting = Arc::new(CountingBackend::new(local_backend(dir.path())));
        counting.put_cas("a", b"v1".to_vec(), None).await.unwrap();
        counting.put_cas("b", b"v1".to_vec(), None).await.unwrap();

        let cache = RequestCache::new(Arc::clone(&counting) as Arc<dyn Backend>);
        cache.get("a").await.unwrap();
        cache.get("b").await.unwrap();
        assert_eq!(counting.get_count(), 2);

        cache.delete_many(&["a".to_string(), "b".to_string()]).await.unwrap();

        cache.get("a").await.unwrap();
        cache.get("b").await.unwrap();
        assert_eq!(counting.get_count(), 4);
    }
}
