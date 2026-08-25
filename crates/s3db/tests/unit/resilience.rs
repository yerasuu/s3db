use super::*;
use crate::metrics::test_support::RecordingMetrics;
use std::sync::atomic::AtomicUsize;

fn local(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(crate::local::test_support::files_backend(root))
}

#[derive(Debug)]
struct FlakyBackend {
    inner: Arc<dyn Backend>,
    fail_next: AtomicUsize,
}

#[async_trait::async_trait]
impl Backend for FlakyBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        if self.fail_next.load(Ordering::SeqCst) > 0 {
            self.fail_next.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("simulated transient failure");
        }
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

#[tokio::test]
async fn retry_backend_succeeds_after_transient_failures() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(dir.path());
    inner.put_cas("k", b"v".to_vec(), None).await.unwrap();
    let flaky: Arc<dyn Backend> = Arc::new(FlakyBackend {
        inner,
        fail_next: AtomicUsize::new(2),
    });
    let retry = RetryBackend::new(flaky, 3, Duration::from_millis(1));

    let (bytes, _) = retry.get("k").await.unwrap();
    assert_eq!(bytes, b"v");
}

#[tokio::test]
async fn retry_backend_gives_up_after_max_retries() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(dir.path());
    let flaky: Arc<dyn Backend> = Arc::new(FlakyBackend {
        inner,
        fail_next: AtomicUsize::new(10),
    });
    let retry = RetryBackend::new(flaky, 2, Duration::from_millis(1));

    assert!(retry.get("k").await.is_err());
}

/// Simulates the exact scenario `run_put_cas`'s confirming read exists for:
/// the very first `put_cas` attempt actually commits server-side (delegates
/// for real), but the client never sees that response (a dropped
/// connection) -- so `RetryBackend` retries the same conditional write,
/// which now fails its own precondition against the object it just wrote.
/// `get` additionally fails a fixed number of times, so a test can prove
/// the confirming read itself now retries past a transient failure instead
/// of reporting a false `Conflict` on the first hiccup.
#[derive(Debug)]
struct FirstWriteLandsButReportsFailure {
    inner: Arc<dyn Backend>,
    get_fail_next: AtomicUsize,
    put_cas_calls: AtomicUsize,
}

#[async_trait::async_trait]
impl Backend for FirstWriteLandsButReportsFailure {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        if self.get_fail_next.load(Ordering::SeqCst) > 0 {
            self.get_fail_next.fetch_sub(1, Ordering::SeqCst);
            anyhow::bail!("simulated transient failure on the confirming read");
        }
        self.inner.get(key).await
    }
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        if self.put_cas_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.inner.put_cas(key, body, expected_etag).await.unwrap();
            anyhow::bail!("simulated dropped connection after the write actually committed");
        }
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

/// Regression test: the confirming read used to be a single, unretried
/// `get` -- a transient failure on it fell through to reporting `Conflict`
/// even though the write had actually landed, misleading the caller into
/// believing it lost a race it really won.
#[tokio::test]
async fn run_put_cas_retries_the_confirming_read_instead_of_reporting_a_false_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let flaky: Arc<dyn Backend> = Arc::new(FirstWriteLandsButReportsFailure {
        inner: local(dir.path()),
        get_fail_next: AtomicUsize::new(2),
        put_cas_calls: AtomicUsize::new(0),
    });
    let retry = RetryBackend::new(flaky, 5, Duration::from_millis(1));

    let outcome = retry.put_cas("k", b"v".to_vec(), None).await.unwrap();

    assert_eq!(
        outcome,
        Cas::Ok,
        "must recognize its own write landed despite the confirming read's transient failures"
    );
}

#[derive(Debug, Default)]
struct AlwaysPermanentFailure {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl Backend for AlwaysPermanentFailure {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get(&self, _key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(crate::backend::permanent(anyhow::anyhow!(
            "simulated permanent failure"
        )))
    }
    async fn put_cas(&self, _key: &str, _body: Vec<u8>, _expected_etag: Option<&str>) -> Result<Cas> {
        unimplemented!("not exercised by this test")
    }
    async fn delete(&self, _key: &str) -> Result<DeleteOutcome> {
        unimplemented!("not exercised by this test")
    }
    async fn delete_many(&self, _keys: &[String]) -> Result<DeleteOutcome> {
        unimplemented!("not exercised by this test")
    }
    async fn list_prefix(&self, _prefix: &str) -> Result<Vec<(String, u64)>> {
        unimplemented!("not exercised by this test")
    }
    async fn get_range(&self, _key: &str, _offset: u64, _len: u64) -> Result<Vec<u8>> {
        unimplemented!("not exercised by this test")
    }
    #[cfg(feature = "streaming")]
    async fn put_stream(&self, _key: &str, _source: &Path) -> Result<()> {
        unimplemented!("not exercised by this test")
    }
    #[cfg(feature = "streaming")]
    async fn get_stream(&self, _key: &str, _dest: &Path) -> Result<()> {
        unimplemented!("not exercised by this test")
    }
}

/// A driver-tagged permanent failure must fail fast -- no sleep, no retry
/// -- rather than burning `max_retries` attempts against a request that
/// will never succeed. A huge `max_retries` with a real backoff would make
/// this test hang if `RetryBackend` retried it even once; asserting the
/// inner backend saw exactly one call proves it didn't.
#[tokio::test]
async fn retry_backend_fails_fast_on_a_permanent_error() {
    let backend = Arc::new(AlwaysPermanentFailure::default());
    let retry = RetryBackend::new(backend.clone(), 1000, Duration::from_secs(30));

    let result = tokio::time::timeout(Duration::from_secs(2), retry.get("k")).await;
    let err = result
        .expect("must fail fast, not hang retrying")
        .expect_err("a permanent failure must still surface as an error");
    assert!(format!("{err:#}").contains("simulated permanent failure"));
    assert_eq!(
        backend.calls.load(Ordering::SeqCst),
        1,
        "a permanent failure must not be retried at all"
    );
}

#[tokio::test]
async fn throttled_backend_limits_concurrency() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(dir.path());
    let config = ResilienceConfig {
        max_concurrent_get: 2,
        ..ResilienceConfig::default()
    };
    let throttled = ThrottledBackend::new(inner, &config);
    assert_eq!(throttled.reads.permits.available_permits(), 2);
}

#[tokio::test]
async fn circuit_breaker_opens_after_consecutive_failures_and_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(dir.path());
    let always_fails: Arc<dyn Backend> = Arc::new(FlakyBackend {
        inner,
        fail_next: AtomicUsize::new(usize::MAX),
    });
    let config = ResilienceConfig {
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 2,
            open_duration: Duration::from_secs(60),
        },
        ..ResilienceConfig::default()
    };
    let throttled = ThrottledBackend::new(always_fails, &config);

    let err1 = throttled.get("k").await.unwrap_err();
    assert!(format!("{err1:#}").contains("simulated"));
    let err2 = throttled.get("k").await.unwrap_err();
    assert!(format!("{err2:#}").contains("simulated"));
    // Breaker should now be open: a third call fails fast without even
    // reaching the inner backend's own error message.
    let err3 = throttled.get("k").await.unwrap_err();
    assert!(format!("{err3:#}").contains("circuit breaker open"));
}

/// Fails every write, serves every read -- a real shape for a backend with
/// a quota exhausted, a read-only window, or a credential that only lost
/// write permission.
#[derive(Debug)]
struct WriteFailingBackend {
    inner: Arc<dyn Backend>,
}

#[async_trait::async_trait]
impl Backend for WriteFailingBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.inner.get(key).await
    }
    async fn put_cas(&self, _key: &str, _body: Vec<u8>, _expected_etag: Option<&str>) -> Result<Cas> {
        anyhow::bail!("simulated write failure")
    }
    async fn delete(&self, _key: &str) -> Result<DeleteOutcome> {
        anyhow::bail!("simulated write failure")
    }
    async fn delete_many(&self, _keys: &[String]) -> Result<DeleteOutcome> {
        anyhow::bail!("simulated write failure")
    }
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner.list_prefix(prefix).await
    }
    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.inner.get_range(key, offset, len).await
    }
    #[cfg(feature = "streaming")]
    async fn put_stream(&self, _key: &str, _source: &Path) -> Result<()> {
        anyhow::bail!("simulated write failure")
    }
    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
}

/// Each lane carries its own breaker, so a write path failing hard enough to
/// trip its own breaker leaves the read lane untouched. With one breaker
/// shared across the layer, these write failures fail-fast every read too --
/// even though reads were never the thing that was broken.
#[tokio::test]
async fn a_failing_write_lane_does_not_trip_the_read_lane() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(dir.path());
    inner.put_cas("k", b"v".to_vec(), None).await.unwrap();
    let backend: Arc<dyn Backend> = Arc::new(WriteFailingBackend { inner });
    let config = ResilienceConfig {
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 2,
            open_duration: Duration::from_secs(60),
        },
        ..ResilienceConfig::default()
    };
    let throttled = ThrottledBackend::new(backend, &config);

    // Trip the write lane's breaker.
    for _ in 0..2 {
        assert!(throttled.put_cas("k", b"v2".to_vec(), None).await.is_err());
    }
    let err = throttled.put_cas("k", b"v2".to_vec(), None).await.unwrap_err();
    assert!(
        format!("{err:#}").contains("circuit breaker open for writes"),
        "the write lane's breaker should be open: {err:#}"
    );

    // The read lane never failed, so it is still closed and serving.
    let (bytes, _etag) = throttled.get("k").await.unwrap();
    assert_eq!(bytes, b"v");
}

#[tokio::test]
async fn metered_backend_records_a_counter_per_call() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(dir.path());
    let metrics = Arc::new(RecordingMetrics::default());
    let metered = MeteredBackend::new(inner, metrics.clone());

    metered.get("k").await.unwrap();
    metered.get("k").await.unwrap();

    let counters = metrics.counters.lock().unwrap();
    assert_eq!(
        counters
            .iter()
            .filter(|(name, _)| name == "s3db_backend_get_total")
            .count(),
        2
    );
}

/// The cache sits above the throttle/breaker, so a key this process already
/// holds is served from it even once the backend is failing hard enough to
/// have tripped the breaker -- the moment a local copy is most worth having.
/// With the cache underneath (where this stack used to put it) the cached
/// read went through the breaker too and failed along with everything else.
#[tokio::test]
async fn a_cached_read_is_served_while_the_circuit_breaker_is_open() {
    let dir = tempfile::tempdir().unwrap();
    let flaky = Arc::new(FlakyBackend {
        inner: local(dir.path()),
        fail_next: AtomicUsize::new(0),
    });
    let config = ResilienceConfig {
        // One attempt per call, so each failed call is exactly one strike
        // against the breaker.
        max_retries: 0,
        circuit_breaker: CircuitBreakerConfig {
            failure_threshold: 2,
            open_duration: Duration::from_secs(60),
        },
        ..ResilienceConfig::default()
    };
    let stack = build_resilient_backend(flaky.clone(), config, Arc::new(RecordingMetrics::default()));

    // Write-through populates the cache with the confirmed bytes.
    stack.put_cas("cached", b"v1".to_vec(), None).await.unwrap();

    // From here the driver fails every read.
    flaky.fail_next.store(usize::MAX, Ordering::SeqCst);

    // Two misses to trip the breaker.
    for _ in 0..2 {
        assert!(stack.get("uncached").await.is_err());
    }
    let err = stack.get("uncached").await.unwrap_err();
    assert!(
        format!("{err:#}").contains("circuit breaker open"),
        "expected the breaker to be open: {err:#}"
    );

    // The cached key still reads, from the cache, without touching the driver.
    let (bytes, _etag) = stack.get("cached").await.unwrap();
    assert_eq!(bytes, b"v1");
}

#[tokio::test]
async fn build_resilient_backend_roundtrips_through_the_whole_stack() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(dir.path());
    let metrics = Arc::new(RecordingMetrics::default());
    let stack = build_resilient_backend(inner, ResilienceConfig::default(), metrics);

    assert_eq!(stack.put_cas("k", b"v1".to_vec(), None).await.unwrap(), Cas::Ok);
    let (bytes, etag) = stack.get("k").await.unwrap();
    assert_eq!(bytes, b"v1");
    assert!(etag.is_some());
}

/// Forwards every method to `inner` -- stands in for "a real remote driver"
/// without needing network access: it isn't the `LocalBackend` type, so
/// `build_resilient_backend`'s local-detection can't mistake it for one.
#[derive(Debug)]
struct PassThroughBackend {
    inner: Arc<dyn Backend>,
}

#[async_trait::async_trait]
impl Backend for PassThroughBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
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

#[tokio::test]
async fn a_local_inner_never_gets_spooled() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(&dir.path().join("data"));
    let local_dir = dir.path().join("state");
    let config = ResilienceConfig {
        local_dir: local_dir.clone(),
        ..ResilienceConfig::default()
    };
    let stack = build_resilient_backend(inner, config, Arc::new(RecordingMetrics::default()));

    stack.put_cas("k", b"v".to_vec(), None).await.unwrap();

    assert!(
        !local_dir.join("spool").join("spool.redb").exists(),
        "a local inner must never be wrapped in SpooledBackend"
    );
}

#[tokio::test]
async fn a_non_local_inner_is_always_spooled() {
    let dir = tempfile::tempdir().unwrap();
    let inner: Arc<dyn Backend> = Arc::new(PassThroughBackend {
        inner: local(&dir.path().join("data")),
    });
    let local_dir = dir.path().join("state");
    let config = ResilienceConfig {
        local_dir: local_dir.clone(),
        ..ResilienceConfig::default()
    };
    let stack = build_resilient_backend(inner, config, Arc::new(RecordingMetrics::default()));

    stack.put_cas("k", b"v".to_vec(), None).await.unwrap();

    assert!(
        local_dir.join("spool").join("spool.redb").exists(),
        "spooling must be unconditional for anything that isn't actually local"
    );
}
