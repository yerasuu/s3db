use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;
use crate::metrics::test_support::RecordingMetrics;
use std::sync::atomic::AtomicUsize;

fn local(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    }))
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

#[tokio::test]
async fn throttled_backend_limits_concurrency() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(dir.path());
    let config = ResilienceConfig {
        max_concurrent_get: 2,
        ..ResilienceConfig::default()
    };
    let throttled = ThrottledBackend::new(inner, &config);
    assert_eq!(throttled.get_permits.available_permits(), 2);
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
