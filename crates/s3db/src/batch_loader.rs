//! Concurrent fan-out fetch of many keys at once, bounded by a
//! [`MemoryBudget`] -- the one place in this crate that owns "read N keys
//! without letting N become the concurrency". [`crate::collection::Collection::list_all`]
//! delegates here rather than keeping its own copy of the shape, so a
//! caller that already has a key list from somewhere else (an index
//! resolve, a batch API request) and a caller that wants every name in a
//! collection get the same bound from the same code.

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::payload::{MAX_OBJECT_BYTES, get_json};
use anyhow::Result;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Bounds [`BatchLoader`]'s fan-out concurrency by a memory budget instead
/// of a fixed constant: with every object capped at
/// [`crate::payload::MAX_OBJECT_BYTES`], `max_buffer_bytes / MAX_OBJECT_BYTES`
/// is exactly how many concurrent fetches can be in flight without risking
/// more than `max_buffer_bytes` of buffered response bodies at once --
/// tune `max_buffer_bytes` for the memory this process can actually spare,
/// not a per-call guess.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct MemoryBudget {
    pub max_buffer_bytes: usize,
}

impl MemoryBudget {
    pub fn max_concurrency(&self) -> usize {
        (self.max_buffer_bytes / MAX_OBJECT_BYTES).max(1)
    }
}

impl Default for MemoryBudget {
    fn default() -> Self {
        // 64 concurrent max-sized objects' worth -- a reasonable default
        // for a single request handler, not a hard ceiling on what a
        // caller can configure.
        MemoryBudget {
            max_buffer_bytes: 64 * MAX_OBJECT_BYTES,
        }
    }
}

pub struct BatchLoader {
    budget: MemoryBudget,
}

impl BatchLoader {
    pub fn new(budget: MemoryBudget) -> Self {
        BatchLoader { budget }
    }

    /// Fetches every key in `keys`, concurrently, bounded by
    /// [`MemoryBudget::max_concurrency`]. `Ok(None)` means the key doesn't
    /// exist -- exact parity with [`crate::collection::Collection::get`],
    /// unlike a signature that could only express "found" or "error" and
    /// would have to lie about which one a missing key is. `Err` is
    /// reserved for what's actually exceptional: a real backend/
    /// deserialization failure after this crate's own resilience layer (if
    /// any) already exhausted its retries.
    pub async fn load_many<T>(
        &self,
        backend: &Arc<dyn Backend>,
        cipher: &Arc<Cipher>,
        keys: impl IntoIterator<Item = String>,
    ) -> HashMap<String, Result<Option<T>>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        let semaphore = Arc::new(Semaphore::new(self.budget.max_concurrency()));
        let mut set = JoinSet::new();
        for key in keys {
            let backend = Arc::clone(backend);
            let cipher = Arc::clone(cipher);
            let semaphore = Arc::clone(&semaphore);
            set.spawn(async move {
                let _permit = semaphore.acquire_owned().await.expect("semaphore is never closed");
                let result = get_json::<T>(backend.as_ref(), &key, &cipher)
                    .await
                    .map(|(value, etag)| etag.is_some().then_some(value));
                (key, result)
            });
        }
        let mut out = HashMap::new();
        while let Some(joined) = set.join_next().await {
            // A panicked fetch task is the one case with no key to report
            // against -- everything else (including a real Err from the
            // fetch itself) is captured in the map, not dropped.
            if let Ok((key, result)) = joined {
                out.insert(key, result);
            }
        }
        out
    }
}

#[cfg(test)]
#[path = "../tests/unit/batch_loader.rs"]
mod tests;
