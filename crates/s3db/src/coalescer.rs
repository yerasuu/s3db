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
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct WriteCoalescer {
    inner: Arc<dyn Backend>,
    flush_interval: Duration,
    pending: Mutex<HashMap<String, Vec<u8>>>,
}

impl std::fmt::Debug for WriteCoalescer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteCoalescer")
            .field("inner", &self.inner)
            .field("flush_interval", &self.flush_interval)
            .finish()
    }
}

impl WriteCoalescer {
    /// Wrapped in `Arc` at construction, not just at the call site: [`Self::write`]
    /// needs to hand a clone of itself to a spawned flush task, which
    /// requires `Arc<Self>` already in hand rather than the caller
    /// remembering to wrap it correctly later.
    pub fn new(inner: Arc<dyn Backend>, flush_interval: Duration) -> Arc<Self> {
        Arc::new(WriteCoalescer {
            inner,
            flush_interval,
            pending: Mutex::new(HashMap::new()),
        })
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
    ///
    /// Exhausting those 3 attempts means sustained contention on `key`,
    /// which is exactly the situation coalescing exists for -- so this
    /// doesn't drop `value` on the floor. It's put back as the pending
    /// write (unless a write that landed during these retries already
    /// replaced it) and a fresh flush is scheduled after another debounce
    /// window, same as [`Self::write`] would for a brand-new pending value.
    ///
    /// An explicit boxed-future return (rather than plain `async fn`) is
    /// what lets the retry path below call `flush` again -- an `async fn`
    /// can't recurse into its own opaque future type, only into a boxed,
    /// type-erased one.
    pub fn flush<'a>(self: &'a Arc<Self>, key: &'a str) -> Pin<Box<dyn Future<Output = Result<Cas>> + Send + 'a>> {
        Box::pin(async move {
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
            self.pending.lock().unwrap().entry(key.to_string()).or_insert(value);
            let this = Arc::clone(self);
            let retry_key = key.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(this.flush_interval).await;
                let _ = this.flush(&retry_key).await;
            });
            bail!("coalescer: too many CAS conflicts flushing {key} (giving up after 3 attempts, retry scheduled)")
        })
    }
}

#[cfg(test)]
#[path = "../tests/unit/coalescer.rs"]
mod tests;
