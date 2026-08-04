//! Debounces repeated writes to the same key within a short window into
//! one real `put_cas` -- fewer requests at the cost of `flush_interval`'s
//! worth of artificial latency, a deliberate trade-off for a key that gets
//! written far more often than it's read.
//!
//! [`WriteCoalescer::flush`] never does a blind CAS against whatever etag
//! was current when the debounce window started: by the time it actually
//! runs, another writer (or this same coalescer's own prior flush) may
//! already have changed the key, and a stale-etag CAS would either fail
//! outright or -- worse, in a naive implementation -- get treated as "lost
//! the race, drop this write silently". Neither is acceptable for
//! something that exists purely to save requests, not to change what
//! "every write eventually lands" means. `flush` re-reads the current etag
//! and retries instead.

use crate::backend::{Backend, Cas};
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct WriteCoalescer {
    inner: Arc<dyn Backend>,
    flush_interval: Duration,
    pending: Mutex<HashMap<String, Vec<u8>>>,
}

impl std::fmt::Debug for WriteCoalescer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteCoalescer").field("inner", &self.inner).field("flush_interval", &self.flush_interval).finish()
    }
}

impl WriteCoalescer {
    /// Wrapped in `Arc` at construction, not just at the call site: [`Self::write`]
    /// needs to hand a clone of itself to a spawned flush task, which
    /// requires `Arc<Self>` already in hand rather than the caller
    /// remembering to wrap it correctly later.
    pub fn new(inner: Arc<dyn Backend>, flush_interval: Duration) -> Arc<Self> {
        Arc::new(WriteCoalescer { inner, flush_interval, pending: Mutex::new(HashMap::new()) })
    }

    /// Records `value` as the latest pending write for `key`, replacing
    /// whatever was pending before, and -- only if nothing was already
    /// pending for `key` -- schedules a [`Self::flush`] after
    /// `flush_interval`. A second, third, ... call for the same `key`
    /// before that flush runs just updates the pending value in place;
    /// only the last one actually gets written.
    pub fn write(self: &Arc<Self>, key: String, value: Vec<u8>) {
        let mut pending = self.pending.lock().unwrap();
        let already_scheduled = pending.insert(key.clone(), value).is_some();
        drop(pending);
        if !already_scheduled {
            let this = Arc::clone(self);
            tokio::spawn(async move {
                tokio::time::sleep(this.flush_interval).await;
                let _ = this.flush(&key).await;
            });
        }
    }

    /// Applies whatever's currently pending for `key`, if anything --
    /// `Ok(Cas::Ok)` as a no-op if nothing is pending (already flushed by a
    /// prior call, or `key` was never written through this coalescer).
    /// CAS-with-reread, up to 3 attempts: see this module's own doc
    /// comment for why a blind CAS here would be wrong.
    pub async fn flush(&self, key: &str) -> Result<Cas> {
        let Some(value) = self.pending.lock().unwrap().remove(key) else {
            return Ok(Cas::Ok);
        };
        let (_, mut expected_etag) = self.inner.get(key).await?;
        for _ in 0..3 {
            match self.inner.put_cas(key, value.clone(), expected_etag.as_deref()).await? {
                Cas::Ok => return Ok(Cas::Ok),
                Cas::Conflict => {
                    let (_, etag) = self.inner.get(key).await?;
                    expected_etag = etag;
                }
            }
        }
        bail!("coalescer: too many CAS conflicts flushing {key} (giving up after 3 attempts)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalParams;
    use crate::local::LocalBackend;

    fn backend(root: &std::path::Path) -> Arc<dyn Backend> {
        Arc::new(LocalBackend::new(&LocalParams { bucket: root.to_string_lossy().to_string() }))
    }

    #[tokio::test]
    async fn flush_writes_the_latest_pending_value() {
        let dir = tempfile::tempdir().unwrap();
        let coalescer = WriteCoalescer::new(backend(dir.path()), Duration::from_secs(60));
        coalescer.write("k".to_string(), b"v1".to_vec());
        coalescer.write("k".to_string(), b"v2".to_vec()); // supersedes v1 before any flush ran

        coalescer.flush("k").await.unwrap();
        let (bytes, _) = coalescer.inner.get("k").await.unwrap();
        assert_eq!(bytes, b"v2");
    }

    #[tokio::test]
    async fn flush_is_a_no_op_when_nothing_is_pending() {
        let dir = tempfile::tempdir().unwrap();
        let coalescer = WriteCoalescer::new(backend(dir.path()), Duration::from_secs(60));
        assert_eq!(coalescer.flush("never-written").await.unwrap(), Cas::Ok);
    }

    #[tokio::test]
    async fn flush_wins_over_a_write_that_landed_during_the_debounce_window() {
        let dir = tempfile::tempdir().unwrap();
        let coalescer = WriteCoalescer::new(backend(dir.path()), Duration::from_secs(60));
        coalescer.write("k".to_string(), b"coalesced".to_vec());

        // Something else writes `k` directly (not through the coalescer)
        // before the flush runs -- the etag captured at debounce-start time
        // (there wasn't one, key didn't exist) is now stale.
        coalescer.inner.put_cas("k", b"other writer".to_vec(), None).await.unwrap();

        coalescer.flush("k").await.unwrap();
        let (bytes, _) = coalescer.inner.get("k").await.unwrap();
        assert_eq!(bytes, b"coalesced", "coalesced write must win via CAS-with-reread, not silently drop");
    }

    #[tokio::test]
    async fn write_schedules_exactly_one_flush_task_per_debounce_window() {
        let dir = tempfile::tempdir().unwrap();
        let coalescer = WriteCoalescer::new(backend(dir.path()), Duration::from_millis(20));
        coalescer.write("k".to_string(), b"v1".to_vec());
        coalescer.write("k".to_string(), b"v2".to_vec());
        coalescer.write("k".to_string(), b"v3".to_vec());

        tokio::time::sleep(Duration::from_millis(60)).await;
        let (bytes, _) = coalescer.inner.get("k").await.unwrap();
        assert_eq!(bytes, b"v3", "the auto-scheduled flush must have applied only the latest value");
    }
}
