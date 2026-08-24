use super::*;
use std::sync::Arc;

fn local(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(crate::local::test_support::files_backend(root))
}

#[tokio::test]
async fn a_pending_entry_with_no_matching_write_is_completed_by_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(&dir.path().join("data"));
    let spooled = SpooledBackend::new(inner, dir.path().join("spool"));

    // Simulates a crash right after the intent was recorded but before the
    // real write ever ran.
    let op_id = random_op_id().unwrap();
    spooled.spool.record_intent(&op_id, "k", None, b"value").await.unwrap();
    assert_eq!(spooled.spool.pending().await.unwrap().len(), 1);

    let report = spooled.recover_pending().await.unwrap();
    assert_eq!(
        report,
        RecoveryReport {
            resolved: 1,
            still_pending: 0
        }
    );
    assert!(spooled.spool.pending().await.unwrap().is_empty());

    let (bytes, etag) = spooled.inner.get("k").await.unwrap();
    assert_eq!(bytes, b"value");
    assert!(
        etag.is_some(),
        "recovery must actually land the write, not just clear the record"
    );
}

#[tokio::test]
async fn a_write_that_already_landed_resolves_via_conflict_without_touching_data() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(&dir.path().join("data"));
    let spooled = SpooledBackend::new(inner, dir.path().join("spool"));

    // Simulates a crash right after the real write landed but before its
    // intent record was cleared: the write already happened, straight
    // through `inner`, bypassing `SpooledBackend::put_cas` entirely.
    spooled
        .inner
        .put_cas("k", b"already there".to_vec(), None)
        .await
        .unwrap();
    let op_id = random_op_id().unwrap();
    spooled
        .spool
        .record_intent(&op_id, "k", None, b"already there")
        .await
        .unwrap();

    let report = spooled.recover_pending().await.unwrap();
    assert_eq!(
        report,
        RecoveryReport {
            resolved: 1,
            still_pending: 0
        },
        "a Conflict on replay means this write is already resolved, not a failure"
    );
    assert!(spooled.spool.pending().await.unwrap().is_empty());

    let (bytes, _etag) = spooled.inner.get("k").await.unwrap();
    assert_eq!(
        bytes, b"already there",
        "recovery must never overwrite what's already there"
    );
}

#[tokio::test]
async fn a_normal_successful_write_leaves_no_pending_entry_behind() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(&dir.path().join("data"));
    let spooled = SpooledBackend::new(inner, dir.path().join("spool"));

    let cas = spooled.put_cas("k", b"value".to_vec(), None).await.unwrap();
    assert_eq!(cas, Cas::Ok);
    assert!(spooled.spool.pending().await.unwrap().is_empty());
}
