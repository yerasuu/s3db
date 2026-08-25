//! Decorator stack between a `Collection`/`SecondaryIndex`/`txn::run` call
//! and the real driver, in one fixed composition order
//! ([`build_resilient_backend`]):
//!
//! ```text
//! MeteredBackend       (records what happened)
//!   -> SpooledBackend     (durable local write-intent, see `crate::spool`)
//!     -> CachedBackend     (cross-request LRU of raw bytes, see `cache`)
//!       -> RetryBackend      (orchestrates retries, backoff between attempts)
//!         -> ThrottledBackend  (per-lane permit + circuit breaker, held only
//!                               during the actual network call)
//!           -> the real driver
//! ```
//!
//! [`crate::spool::SpooledBackend`] sits above the cache and wraps
//! retry+throttle: recording intent before *any* attempt (including
//! retries) is what closes the actual crash window, and going through the
//! cache layer (rather than being wrapped by it) means a
//! [`crate::spool::SpooledBackend::recover_pending`] replay still gets
//! `CachedBackend`'s invalidate-on-write behavior, instead of leaving a
//! stale cached miss behind after silently fixing a write in the
//! background. Unconditional for any `inner` that isn't already a
//! [`crate::local::LocalBackend`] — not an opt-in layer an app can leave
//! unset: a local filesystem call is synchronous (it either landed or it
//! didn't), so only a driver reachable over a network needs the journal at
//! all, and every one of those gets it.
//!
//! Reads, writes and listings travel independent lanes through the throttle
//! (see [`Lane`]): each has its own concurrency budget *and* its own circuit
//! breaker, so one of them going bad can't fail-fast the others.
//!
//! Retry sits *outside* throttle deliberately: each individual attempt
//! (including retries) acquires and releases its own permit around just
//! that one call, so a retry's backoff sleep never holds a permit hostage
//! -- the opposite order would let a slow retry sequence starve the
//! concurrency budget everything else is competing for, which is exactly
//! the pressure that pushes the circuit breaker to open on load it
//! generated itself.
//!
//! The cache sits *outside* both of them, which is what makes a hit a hit:
//! a key this process already holds is served straight from memory/disk,
//! ahead of everything below. Underneath the throttle -- where this stack
//! used to put it -- a cache hit still had to queue for a concurrency
//! permit it was never going to use, waiting behind in-flight network calls
//! for data that needed no network at all; and worse, it went through the
//! circuit breaker, so once the breaker opened every cached read started
//! failing too, at exactly the moment a local copy was most worth having.
//! Above them, a hit costs nothing and stays available while the backend
//! is down; a miss still goes through retry and throttle to the driver,
//! unchanged.
//!
//! Metering stays outermost so what it counts is still every logical call
//! the caller made -- hits included -- rather than only the ones that
//! missed and reached the network.
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
use std::path::PathBuf;
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Every field is optional in a config file: whatever a caller omits comes from
/// [`Default`], so a config only ever spells out what it actually changes.
#[serde(default)]
pub struct ResilienceConfig {
    /// Local directory this stack's on-disk state lives under — today just
    /// `local_dir/spool` for [`crate::spool::SpooledBackend`]'s durable
    /// write-intent journal, always wired in for a non-local `inner` (see
    /// [`build_resilient_backend`]) — there's no flag left to turn that off.
    /// Defaults to `./local` rather than staying unset like the old
    /// `spool_path: Option<PathBuf>` did: a relative, conventional location
    /// beats forcing every caller to spell out a path just to get the
    /// protection this crate now always provides for a remote driver. Still
    /// fully configurable — a config file overrides it like any other field
    /// here, this just removes the option to end up with nothing set.
    pub local_dir: PathBuf,
    pub max_concurrent_get: usize,
    pub max_concurrent_put: usize,
    pub max_concurrent_list: usize,
    pub max_retries: u32,
    /// Milliseconds in a config file — see [`crate::serde_duration`].
    #[serde(with = "crate::serde_duration")]
    pub base_backoff: Duration,
    pub circuit_breaker: CircuitBreakerConfig,
    pub cache: CacheConfig,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        ResilienceConfig {
            local_dir: PathBuf::from("./local"),
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
///
/// [`crate::spool::SpooledBackend`] wraps every `inner` except one that's
/// already a [`crate::local::LocalBackend`] — see this module's doc comment
/// for why a local driver has no ambiguous-failure window for the journal
/// to close, so wrapping it would only cost a second redb file per write.
pub fn build_resilient_backend(
    inner: Arc<dyn Backend>,
    config: ResilienceConfig,
    metrics: SharedMetrics,
) -> Arc<dyn Backend> {
    let is_local = inner.as_any().downcast_ref::<crate::local::LocalBackend>().is_some();
    let throttled: Arc<dyn Backend> = Arc::new(ThrottledBackend::new(inner, &config));
    let retried: Arc<dyn Backend> = Arc::new(RetryBackend::new(throttled, config.max_retries, config.base_backoff));
    let cached: Arc<dyn Backend> = Arc::new(CachedBackend::new(retried, config.cache.clone()));
    let spooled: Arc<dyn Backend> = if is_local {
        cached
    } else {
        Arc::new(crate::spool::SpooledBackend::new(
            cached,
            config.local_dir.join("spool"),
        ))
    };
    Arc::new(MeteredBackend::new(spooled, metrics))
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

    /// Forwards the capability: this layer only observes traffic, so a call
    /// that goes straight to the inner backend loses its metrics and nothing
    /// else -- see [`Backend::as_atomic`] for the layers where that
    /// trade-off would not be acceptable.
    fn as_atomic(&self) -> Option<&dyn crate::atomic::AtomicBackend> {
        self.inner.as_atomic()
    }

    fn as_range(&self) -> Option<&dyn crate::range::RangeBackend> {
        self.inner.as_range()
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

    async fn list_page(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<crate::backend::ListPage> {
        let result = self.inner.list_page(prefix, after, limit).await;
        self.record("list", &result);
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

/// Full jitter: a random delay in `[0, base * 2^attempt]` -- spreads out a
/// herd of callers that all started retrying at the same moment instead of
/// them all retrying in lockstep. Shared by [`RetryBackend`] (retrying a
/// transient transport failure) and
/// [`crate::collection::Collection::update`] (retrying a lost CAS race):
/// different causes, but the same thundering-herd problem and the same
/// answer to it, so one implementation rather than two that drift.
pub(crate) fn full_jitter_backoff(base: Duration, attempt: u32) -> Duration {
    let max = base.saturating_mul(1u32 << attempt.min(10));
    let mut jitter = [0u8; 8];
    match getrandom::fill(&mut jitter) {
        // RNG unavailable: fall back to the unjittered max delay rather than
        // panicking mid-retry-loop over a missing jitter source.
        Err(_) => max,
        Ok(()) => {
            let fraction = u64::from_le_bytes(jitter) as f64 / u64::MAX as f64;
            max.mul_f64(fraction)
        }
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

    fn backoff_for(&self, attempt: u32) -> Duration {
        full_jitter_backoff(self.base_backoff, attempt)
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
                // A driver already checked this error's status code and
                // knows no amount of retrying will fix it (bad request,
                // auth failure, not found, ...) -- fail fast instead of
                // burning `max_retries` round trips against a request
                // that's never going to succeed.
                Err(err) if crate::backend::is_permanent(&err) => return Err(err),
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
                    // The confirming read matters more here than an
                    // ordinary request: a transient failure on it must not
                    // be mistaken for "no, this wasn't my own write" -- it
                    // means this can't tell either way yet, not that it
                    // already knows the answer is `Conflict`. So it gets
                    // the same retry treatment as the write itself, not a
                    // single, unretried attempt that a read-after-write
                    // hiccup could turn into a false `Conflict` for a write
                    // that actually landed.
                    match self.confirm_own_write(key, &body).await {
                        Ok(true) => return Ok(Cas::Ok),
                        Ok(false) => return Ok(Cas::Conflict),
                        Err(_) => return Ok(Cas::Conflict),
                    }
                }
                Ok(value) => return Ok(value),
                Err(err) if crate::backend::is_permanent(&err) => return Err(err),
                Err(err) if attempt >= self.max_retries => return Err(err),
                Err(_) => {
                    retried_after_failure = true;
                    tokio::time::sleep(self.backoff_for(attempt)).await;
                    attempt += 1;
                }
            }
        }
    }

    /// Re-reads `key` up to `max_retries` times (same backoff as
    /// everywhere else here), reporting whether its body matches `body` --
    /// [`Self::run_put_cas`]'s way of telling "this was my own retried
    /// write landing" from "a real competing writer" apart. A confirming
    /// read that keeps failing is genuinely unknown, not evidence either
    /// way, so it comes back as `Err` rather than being coerced into a
    /// guess -- the caller decides what unknown should mean.
    async fn confirm_own_write(&self, key: &str, body: &[u8]) -> Result<bool> {
        let mut attempt = 0;
        loop {
            match self.inner.get(key).await {
                Ok((current_body, _etag)) => return Ok(current_body == *body),
                Err(err) if crate::backend::is_permanent(&err) => return Err(err),
                Err(err) if attempt >= self.max_retries => return Err(err),
                Err(_) => {
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

    /// Forwards the capability: this layer only observes traffic, so a call
    /// that goes straight to the inner backend loses its retries and nothing
    /// else -- see [`Backend::as_atomic`] for the layers where that
    /// trade-off would not be acceptable.
    fn as_atomic(&self) -> Option<&dyn crate::atomic::AtomicBackend> {
        self.inner.as_atomic()
    }

    fn as_range(&self) -> Option<&dyn crate::range::RangeBackend> {
        self.inner.as_range()
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

    async fn list_page(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<crate::backend::ListPage> {
        self.run(|| self.inner.list_page(prefix, after, limit)).await
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

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CircuitBreakerConfig {
    /// Consecutive real failures (never a `Cas::Conflict`) before the
    /// breaker opens.
    pub failure_threshold: u32,
    /// How long the breaker stays open (failing fast, not even calling the
    /// inner backend) before letting one trial call through. Milliseconds in a
    /// config file.
    #[serde(with = "crate::serde_duration")]
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

/// One independent path through [`ThrottledBackend`]: its own concurrency
/// budget *and* its own circuit breaker.
///
/// The breaker belongs to the lane, not to the layer, because reads and
/// writes fail for different reasons and must not take each other down: a
/// storage backend refusing writes (quota, a read-only window, a bad
/// credential on the write path) is still perfectly able to serve reads, and
/// a shared breaker turned those write failures into fail-fast errors on
/// every read -- and vice versa. Per-lane, a sick write path opens only the
/// write breaker and reads keep flowing.
struct Lane {
    /// Names the lane in the fail-fast error, so an open breaker says which
    /// path is actually down instead of just "the backend".
    name: &'static str,
    permits: Semaphore,
    breaker: CircuitBreaker,
}

impl Lane {
    fn new(name: &'static str, max_concurrent: usize, breaker: CircuitBreakerConfig) -> Self {
        Lane {
            name,
            permits: Semaphore::new(max_concurrent),
            breaker: CircuitBreaker::new(breaker),
        }
    }
}

/// Bounds real network concurrency and measures the error rate, both split
/// per [`Lane`] (reads, writes, listings) so the three don't block each
/// other. The permit for one call is held only for the duration of that one
/// call -- acquired after entering this layer, released before returning --
/// so it's `RetryBackend`'s job (outside this layer) to decide whether to
/// call again, not this layer's.
pub struct ThrottledBackend {
    inner: Arc<dyn Backend>,
    reads: Lane,
    writes: Lane,
    lists: Lane,
}

impl std::fmt::Debug for ThrottledBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThrottledBackend").field("inner", &self.inner).finish()
    }
}

impl ThrottledBackend {
    pub fn new(inner: Arc<dyn Backend>, config: &ResilienceConfig) -> Self {
        // Each lane gets its own breaker built from the same config: the
        // thresholds are shared policy, the failure counting is not.
        ThrottledBackend {
            inner,
            reads: Lane::new("reads", config.max_concurrent_get, config.circuit_breaker),
            writes: Lane::new("writes", config.max_concurrent_put, config.circuit_breaker),
            lists: Lane::new("listings", config.max_concurrent_list, config.circuit_breaker),
        }
    }

    async fn guarded<T>(&self, lane: &Lane, call: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        if !lane.breaker.allow() {
            anyhow::bail!(
                "circuit breaker open for {}: too many recent failures, failing fast",
                lane.name
            );
        }
        let _permit = lane.permits.acquire().await.expect("semaphore is never closed");
        let result = call.await;
        match &result {
            Ok(_) => lane.breaker.record_success(),
            Err(_) => lane.breaker.record_failure(),
        }
        result
    }
}

#[async_trait::async_trait]
impl Backend for ThrottledBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Forwards the capability: this layer only observes traffic, so a call
    /// that goes straight to the inner backend loses its concurrency permit and circuit breaker and nothing
    /// else -- see [`Backend::as_atomic`] for the layers where that
    /// trade-off would not be acceptable.
    fn as_atomic(&self) -> Option<&dyn crate::atomic::AtomicBackend> {
        self.inner.as_atomic()
    }

    fn as_range(&self) -> Option<&dyn crate::range::RangeBackend> {
        self.inner.as_range()
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.guarded(&self.reads, self.inner.get(key)).await
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        self.guarded(&self.writes, self.inner.put_cas(key, body, expected_etag))
            .await
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        self.guarded(&self.writes, self.inner.delete(key)).await
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        self.guarded(&self.writes, self.inner.delete_many(keys)).await
    }

    async fn list_page(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<crate::backend::ListPage> {
        self.guarded(&self.lists, self.inner.list_page(prefix, after, limit))
            .await
    }
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.guarded(&self.lists, self.inner.list_prefix(prefix)).await
    }

    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.guarded(&self.reads, self.inner.get_range(key, offset, len)).await
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        self.guarded(&self.writes, self.inner.put_stream(key, source)).await
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        self.guarded(&self.reads, self.inner.get_stream(key, dest)).await
    }
}

#[cfg(test)]
#[path = "../tests/unit/resilience.rs"]
mod tests;
