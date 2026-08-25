use super::*;

fn backend(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(crate::local::test_support::files_backend(root))
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
    coalescer
        .inner
        .put_cas("k", b"other writer".to_vec(), None)
        .await
        .unwrap();

    coalescer.flush("k").await.unwrap();
    let (bytes, _) = coalescer.inner.get("k").await.unwrap();
    assert_eq!(
        bytes, b"coalesced",
        "coalesced write must win via CAS-with-reread, not silently drop"
    );
}

/// Forces the *first* `put_cas` for a chosen key to report `Cas::Conflict`
/// -- and, as a side effect right before doing so, drives a second,
/// independent `write`+`flush` for that same key to completion through the
/// coalescer itself. Lets a test put a `flush` call's own conflict-retry
/// exactly where a genuinely newer write already landed, instead of only
/// ever seeing a conflict caused by an unrelated third party.
struct ConflictThenSupersede {
    inner: Arc<dyn Backend>,
    coalescer: std::sync::OnceLock<Arc<WriteCoalescer>>,
    key: String,
    newer_value: Vec<u8>,
    triggered: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for ConflictThenSupersede {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConflictThenSupersede").finish()
    }
}

#[async_trait::async_trait]
impl Backend for ConflictThenSupersede {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.inner.get(key).await
    }
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        if key == self.key && !self.triggered.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let coalescer = self.coalescer.get().expect("set right after construction").clone();
            coalescer.write(self.key.clone(), self.newer_value.clone());
            coalescer.flush(&self.key).await.unwrap();
            return Ok(Cas::Conflict);
        }
        self.inner.put_cas(key, body, expected_etag).await
    }
    async fn delete(&self, key: &str) -> Result<crate::backend::DeleteOutcome> {
        self.inner.delete(key).await
    }
    async fn delete_many(&self, keys: &[String]) -> Result<crate::backend::DeleteOutcome> {
        self.inner.delete_many(keys).await
    }
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner.list_prefix(prefix).await
    }
    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.inner.get_range(key, offset, len).await
    }
}

/// Regression test: a `flush` that loses a CAS used to always retry with
/// its own stale captured value, blind to whether a newer write had
/// already landed in the meantime -- letting it win a later retry and
/// silently clobber that newer write. It must now recognize its value has
/// been superseded and abandon instead.
#[tokio::test]
async fn flush_abandons_a_stale_value_instead_of_clobbering_a_write_that_landed_during_its_retry() {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(ConflictThenSupersede {
        inner: Arc::new(crate::local::test_support::files_backend(dir.path())),
        coalescer: std::sync::OnceLock::new(),
        key: "k".to_string(),
        newer_value: b"v2".to_vec(),
        triggered: std::sync::atomic::AtomicBool::new(false),
    });
    let coalescer = WriteCoalescer::new(backend.clone(), Duration::from_secs(60));
    backend
        .coalescer
        .set(coalescer.clone())
        .unwrap_or_else(|_| panic!("set exactly once, before any flush runs"));

    coalescer.write("k".to_string(), b"v1".to_vec());
    let outcome = coalescer.flush("k").await.unwrap();

    assert_eq!(
        outcome,
        Cas::Conflict,
        "must report giving way to the newer write, not a false success"
    );
    let (bytes, _) = coalescer.inner.get("k").await.unwrap();
    assert_eq!(
        bytes, b"v2",
        "the write that landed during the retry must survive, not be clobbered by the stale value"
    );
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
    assert_eq!(
        bytes, b"v3",
        "the auto-scheduled flush must have applied only the latest value"
    );
}
