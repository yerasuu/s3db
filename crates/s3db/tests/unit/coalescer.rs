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
