//! A [`Backend`] decorator that memoizes `get` within one request/
//! operation's lifetime — deliberately *not* a process-wide cache.
//! several processes can run against the same bucket at once, so a cached
//! record that outlived the request it was built for could let stale data
//! (a revoked permission, say) stay "live" longer than it should. Callers are expected to build one `RequestCache` per connection
//! or request and drop it afterward — never stash it somewhere long-lived.

use crate::backend::{Backend, Cas, DeleteOutcome};
use anyhow::{Context, Result};
use std::collections::HashMap;
#[cfg(any(test, feature = "streaming"))]
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
        RequestCache {
            inner,
            reads: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait::async_trait]
impl crate::atomic::AtomicBackend for RequestCache {
    async fn commit_batch(&self, ops: Vec<crate::atomic::BatchOp>) -> Result<crate::atomic::BatchOutcome> {
        let touched: Vec<String> = ops.iter().map(|op| op.key().to_string()).collect();
        let inner = self
            .inner
            .as_atomic()
            .context("RequestCache::commit_batch: the wrapped backend has no native transaction")?;
        let result = inner.commit_batch(ops).await;
        let mut reads = self.reads.lock().unwrap();
        for key in touched {
            reads.remove(&key);
        }
        result
    }
}

#[async_trait::async_trait]
impl Backend for RequestCache {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Same reasoning as [`crate::CachedBackend`]: this layer claims the
    /// capability so its own invalidation still runs, rather than handing out
    /// a reference that would let a batch bypass it. See
    /// [`Backend::as_atomic`].
    fn as_atomic(&self) -> Option<&dyn crate::atomic::AtomicBackend> {
        self.inner
            .as_atomic()
            .map(|_| self as &dyn crate::atomic::AtomicBackend)
    }

    fn as_range(&self) -> Option<&dyn crate::range::RangeBackend> {
        self.inner.as_range()
    }

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

#[cfg(test)]
#[path = "../tests/unit/request_cache.rs"]
mod tests;
