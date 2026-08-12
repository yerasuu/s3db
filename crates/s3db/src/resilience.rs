//! Decorator stack between a `Collection`/`SecondaryIndex`/`txn::run` call
//! and the real driver, in one fixed composition order
//! ([`build_resilient_backend`]):
//!
//! ```text
//! MeteredBackend       (records what happened)
//!   -> RetryBackend      (orchestrates retries, backoff between attempts)
//!     -> ThrottledBackend  (permit + circuit breaker, held only during
//!                           the actual network call)
//!       -> CachedBackend     (cross-request LRU of raw bytes, see `cache`)
//!         -> the real driver
//! ```
//!
//! Retry sits *outside* throttle deliberately: each individual attempt
//! (including retries) acquires and releases its own permit around just
//! that one call, so a retry's backoff sleep never holds a permit hostage
//! -- the opposite order would let a slow retry sequence starve the
//! concurrency budget everything else is competing for, which is exactly
//! the pressure that pushes the circuit breaker to open on load it
//! generated itself.
//!
//! [`crate::request_cache::RequestCache`] is not part of this stack: it
//! belongs *outside* all of it, at the application layer, wrapping whatever
//! [`build_resilient_backend`] returns -- its own invalidation needs to see
//! the result of a write after retry/throttle have already run, not before.

use crate::backend::{Backend, Cas, DeleteOutcome};
use crate::cache::{CacheConfig, CachedBackend};
use crate::metrics::SharedMetrics;
use anyhow::Result;
#[cfg(feature = "streaming")]
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// Sizing/policy for the whole stack. Connection-pool sizing for the
/// underlying HTTP client (`s3`/`azure`/`gcs`'s own driver construction)
/// isn't a field here -- it's configured once, at driver-construction time,
/// not per-call -- but it should be sized to match (not exceed)
/// `max_concurrent_get + max_concurrent_put + max_concurrent_list`, with
/// keep-alive on and a generous idle timeout: otherwise the concurrency this
/// config grants can end up bottlenecked on re-establishing connections
/// `ThrottledBackend` already decided could be in flight.
#[derive(Debug, Clone)]
pub struct ResilienceConfig {
    pub max_concurrent_get: usize,
    pub max_concurrent_put: usize,
    pub max_concurrent_list: usize,
    pub max_retries: u32,
    pub base_backoff: Duration,
    pub circuit_breaker: CircuitBreakerConfig,
    pub cache: CacheConfig,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        ResilienceConfig {
            max_concurrent_get: 64,
            max_concurrent_put: 32,
            max_concurrent_list: 16,
            max_retries: 4,
            base_backoff: Duration::from_millis(100),
            circuit_breaker: CircuitBreakerConfig::default(),
            cache: CacheConfig::default(),
        }
    }
}

/// Builds the fixed composition order this module's doc comment describes.
pub fn build_resilient_backend(
    inner: Arc<dyn Backend>,
    config: ResilienceConfig,
    metrics: SharedMetrics,
) -> Arc<dyn Backend> {
    let cached: Arc<dyn Backend> = Arc::new(CachedBackend::new(inner, config.cache));
    let throttled: Arc<dyn Backend> = Arc::new(ThrottledBackend::new(cached, &config));
    let retried: Arc<dyn Backend> = Arc::new(RetryBackend::new(throttled, config.max_retries, config.base_backoff));
    Arc::new(MeteredBackend::new(retried, metrics))
}

/// Records a counter per call (`s3db_backend_<op>_total`) and per outcome
/// (`s3db_backend_<op>_errors_total` on `Err`) -- the outermost layer, so
/// what it counts already reflects every retry/throttle decision below it,
/// not raw per-attempt noise.
pub struct MeteredBackend {
    inner: Arc<dyn Backend>,
    metrics: SharedMetrics,
}

impl std::fmt::Debug for MeteredBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeteredBackend").field("inner", &self.inner).finish()
    }
}

impl MeteredBackend {
    pub fn new(inner: Arc<dyn Backend>, metrics: SharedMetrics) -> Self {
        MeteredBackend { inner, metrics }
    }

    fn record<T>(&self, op: &str, result: &Result<T>) {
        self.metrics.counter(&format!("s3db_backend_{op}_total"), 1);
        if result.is_err() {
            self.metrics.counter(&format!("s3db_backend_{op}_errors_total"), 1);
        }
    }
}

#[async_trait::async_trait]
impl Backend for MeteredBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        let result = self.inner.get(key).await;
        self.record("get", &result);
        result
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let result = self.inner.put_cas(key, body, expected_etag).await;
        self.record("put", &result);
        result
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        let result = self.inner.delete(key).await;
        self.record("delete", &result);
        result
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        let result = self.inner.delete_many(keys).await;
        self.record("delete_many", &result);
        result
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        let result = self.inner.list_prefix(prefix).await;
        self.record("list", &result);
        result
    }

    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        let result = self.inner.get_range(key, offset, len).await;
        self.record("get_range", &result);
        result
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        let result = self.inner.put_stream(key, source).await;
        self.record("put_stream", &result);
        result
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        let result = self.inner.get_stream(key, dest).await;
        self.record("get_stream", &result);
        result
    }
}

/// Retries a real `Err` (never a `Cas::Conflict`, which is a legitimate
/// business outcome, not a failure) up to `max_retries` times, exponential
/// backoff with jitter between attempts. Sits *outside*
/// [`ThrottledBackend`] -- see this module's doc comment for why the sleep
/// between attempts must never hold a concurrency permit.
pub struct RetryBackend {
    inner: Arc<dyn Backend>,
    max_retries: u32,
    base_backoff: Duration,
}

impl std::fmt::Debug for RetryBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetryBackend")
            .field("inner", &self.inner)
            .field("max_retries", &self.max_retries)
            .finish()
    }
}

impl RetryBackend {
    pub fn new(inner: Arc<dyn Backend>, max_retries: u32, base_backoff: Duration) -> Self {
        RetryBackend {
            inner,
            max_retries,
            base_backoff,
        }
    }

    /// Full jitter: a random delay in `[0, base * 2^attempt]` -- spreads
    /// out a herd of callers that all started retrying at the same moment
    /// (a shared backend blip) instead of them all retrying in lockstep.
    fn backoff_for(&self, attempt: u32) -> Duration {
        let max = self.base_backoff.saturating_mul(1u32 << attempt.min(10));
        let mut jitter = [0u8; 8];
        match getrandom::fill(&mut jitter) {
            // RNG unavailable: fall back to the unjittered max delay rather
            // than panicking mid-retry-loop over a missing jitter source.
            Err(_) => max,
            Ok(()) => {
                let fraction = u64::from_le_bytes(jitter) as f64 / u64::MAX as f64;
                max.mul_f64(fraction)
            }
        }
    }

    async fn run<T, F, Fut>(&self, f: F) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut attempt = 0;
        loop {
            match f().await {
                Ok(value) => return Ok(value),
                Err(err) if attempt >= self.max_retries => return Err(err),
                Err(_) => {
                    tokio::time::sleep(self.backoff_for(attempt)).await;
                    attempt += 1;
                }
            }
        }
    }

    /// Same retry loop as [`Self::run`], but aware that a `Conflict` seen
    /// only *after* we've already retried a transport failure might be our
    /// own previous attempt landing server-side, not a real competing
    /// writer -- the client saw `Err` (e.g. a dropped connection after the
    /// write actually committed), retried the same conditional write, and
    /// that retry now fails its own precondition against the object it
    /// just wrote. Re-reading and comparing the stored body before
    /// reporting `Conflict` tells the two cases apart.
    async fn run_put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let mut attempt = 0;
        let mut retried_after_failure = false;
        loop {
            match self.inner.put_cas(key, body.clone(), expected_etag).await {
                Ok(Cas::Conflict) if retried_after_failure => {
                    if let Ok((current_body, _etag)) = self.inner.get(key).await {
                        if current_body == body {
                            return Ok(Cas::Ok);
                        }
                    }
                    return Ok(Cas::Conflict);
                }
                Ok(value) => return Ok(value),
                Err(err) if attempt >= self.max_retries => return Err(err),
                Err(_) => {
                    retried_after_failure = true;
                    tokio::time::sleep(self.backoff_for(attempt)).await;
                    attempt += 1;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Backend for RetryBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.run(|| self.inner.get(key)).await
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        self.run_put_cas(key, body, expected_etag).await
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        self.run(|| self.inner.delete(key)).await
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        self.run(|| self.inner.delete_many(keys)).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.run(|| self.inner.list_prefix(prefix)).await
    }

    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.run(|| self.inner.get_range(key, offset, len)).await
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        // Not retried: a stream reads `source` to completion once, retrying
        // would need to re-open/re-seek it, and streaming callers don't
        // need CAS semantics here in the first place (see `Backend::put_stream`'s
        // own doc comment) -- one attempt straight through.
        self.inner.put_stream(key, source).await
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerConfig {
    /// Consecutive real failures (never a `Cas::Conflict`) before the
    /// breaker opens.
    pub failure_threshold: u32,
    /// How long the breaker stays open (failing fast, not even calling the
    /// inner backend) before letting one trial call through.
    pub open_duration: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Closed,
    Open,
    /// One trial call is allowed through; its outcome decides `Closed` vs
    /// re-`Open`.
    HalfOpen,
}

struct CircuitBreaker {
    config: CircuitBreakerConfig,
    consecutive_failures: AtomicU32,
    state: Mutex<(CircuitState, Option<Instant>)>,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        CircuitBreaker {
            config,
            consecutive_failures: AtomicU32::new(0),
            state: Mutex::new((CircuitState::Closed, None)),
        }
    }

    /// `true` if a call should even be attempted right now.
    fn allow(&self) -> bool {
        let mut state = self.lock_state();
        match state.0 {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => false, // a trial is already in flight
            CircuitState::Open => {
                // Missing `opened_at` shouldn't happen (`Open` is always set
                // together with `Some(Instant::now())`), but treating it as
                // "just opened" is a safe fallback -- fail closed rather
                // than panic and poison this lock for every future call.
                let opened_at = state.1.unwrap_or_else(Instant::now);
                if opened_at.elapsed() >= self.config.open_duration {
                    state.0 = CircuitState::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        *self.lock_state() = (CircuitState::Closed, None);
    }

    fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        let mut state = self.lock_state();
        if state.0 == CircuitState::HalfOpen || failures >= self.config.failure_threshold {
            *state = (CircuitState::Open, Some(Instant::now()));
        }
    }

    /// A panic while holding this lock elsewhere must not wedge the breaker
    /// shut forever -- recover the (possibly stale but still usable) state
    /// instead of propagating the poison.
    fn lock_state(&self) -> std::sync::MutexGuard<'_, (CircuitState, Option<Instant>)> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Bounds real network concurrency (separate semaphores for reads, writes,
/// and listings) and hosts the circuit breaker that measures their error
/// rate. The permit for one call is held only for the duration of that one
/// call -- acquired after entering this layer, released before returning --
/// so it's `RetryBackend`'s job (outside this layer) to decide whether to
/// call again, not this layer's.
pub struct ThrottledBackend {
    inner: Arc<dyn Backend>,
    get_permits: Semaphore,
    put_permits: Semaphore,
    list_permits: Semaphore,
    breaker: CircuitBreaker,
}

impl std::fmt::Debug for ThrottledBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThrottledBackend").field("inner", &self.inner).finish()
    }
}

impl ThrottledBackend {
    pub fn new(inner: Arc<dyn Backend>, config: &ResilienceConfig) -> Self {
        ThrottledBackend {
            inner,
            get_permits: Semaphore::new(config.max_concurrent_get),
            put_permits: Semaphore::new(config.max_concurrent_put),
            list_permits: Semaphore::new(config.max_concurrent_list),
            breaker: CircuitBreaker::new(config.circuit_breaker),
        }
    }

    async fn guarded<T>(&self, semaphore: &Semaphore, call: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        if !self.breaker.allow() {
            anyhow::bail!("circuit breaker open: too many recent failures, failing fast");
        }
        let _permit = semaphore.acquire().await.expect("semaphore is never closed");
        let result = call.await;
        match &result {
            Ok(_) => self.breaker.record_success(),
            Err(_) => self.breaker.record_failure(),
        }
        result
    }
}

#[async_trait::async_trait]
impl Backend for ThrottledBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.guarded(&self.get_permits, self.inner.get(key)).await
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        self.guarded(&self.put_permits, self.inner.put_cas(key, body, expected_etag))
            .await
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        self.guarded(&self.put_permits, self.inner.delete(key)).await
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        self.guarded(&self.put_permits, self.inner.delete_many(keys)).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.guarded(&self.list_permits, self.inner.list_prefix(prefix)).await
    }

    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.guarded(&self.get_permits, self.inner.get_range(key, offset, len))
            .await
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        self.guarded(&self.put_permits, self.inner.put_stream(key, source))
            .await
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        self.guarded(&self.get_permits, self.inner.get_stream(key, dest)).await
    }
}

#[cfg(test)]
#[path = "../tests/unit/resilience.rs"]
mod tests;
