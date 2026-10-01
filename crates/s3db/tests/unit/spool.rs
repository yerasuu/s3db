use super::*;
use std::sync::Arc;

fn local(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(crate::local::test_support::files_backend(root))
}

async fn own_pending(spooled: &SpooledBackend) -> usize {
    match spooled.spool.own.get() {
        Some((_, db)) => pending_in(Arc::clone(db)).await.unwrap().len(),
        None => 0,
    }
}

fn spool_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    match std::fs::read_dir(root) {
        Ok(entries) => entries.map(|e| e.unwrap().path()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Backdates `path` past `MIN_ORPHAN_AGE`, as if its owner had died a while ago.
fn age(path: &std::path::Path) {
    let old = std::time::SystemTime::now() - MIN_ORPHAN_AGE - Duration::from_secs(1);
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(old)
        .unwrap();
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
    assert_eq!(own_pending(&spooled).await, 1);

    let report = spooled.recover_pending().await.unwrap();
    assert_eq!(
        report,
        RecoveryReport {
            resolved: 1,
            still_pending: 0
        }
    );
    assert_eq!(own_pending(&spooled).await, 0);

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
    assert_eq!(own_pending(&spooled).await, 0);

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
    assert_eq!(own_pending(&spooled).await, 0);
}

/// The bug that made this a file per instance: `redb` locks its file, so two
/// backends on one spool directory used to fail every write of the second.
#[tokio::test]
async fn two_instances_on_one_spool_root_both_write() {
    let dir = tempfile::tempdir().unwrap();
    let inner = local(&dir.path().join("data"));
    let first = SpooledBackend::new(Arc::clone(&inner), dir.path().join("spool"));
    let second = SpooledBackend::new(inner, dir.path().join("spool"));

    assert_eq!(first.put_cas("a", b"1".to_vec(), None).await.unwrap(), Cas::Ok);
    assert_eq!(second.put_cas("b", b"2".to_vec(), None).await.unwrap(), Cas::Ok);
}

#[tokio::test]
async fn an_orphaned_spool_file_is_replayed_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("spool");
    let inner = local(&dir.path().join("data"));

    // A process that recorded an intent and died before the write ran.
    let crashed = SpooledBackend::new(Arc::clone(&inner), &root);
    let op_id = random_op_id().unwrap();
    crashed.spool.record_intent(&op_id, "k", None, b"value").await.unwrap();
    drop(crashed);
    let files = spool_files(&root);
    assert_eq!(files.len(), 1, "a file with a pending write must outlive its owner");
    age(&files[0]);

    let survivor = SpooledBackend::new(inner, &root);
    let report = survivor.recover_pending().await.unwrap();
    assert_eq!(
        report,
        RecoveryReport {
            resolved: 1,
            still_pending: 0
        }
    );
    assert_eq!(survivor.inner.get("k").await.unwrap().0, b"value");
    assert!(spool_files(&root).is_empty(), "a drained orphan must be deleted");
}

#[tokio::test]
async fn a_spool_file_still_held_open_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("spool");
    let inner = local(&dir.path().join("data"));

    let live = SpooledBackend::new(Arc::clone(&inner), &root);
    let op_id = random_op_id().unwrap();
    live.spool.record_intent(&op_id, "k", None, b"value").await.unwrap();
    age(&spool_files(&root)[0]);

    let other = SpooledBackend::new(inner, &root);
    let report = other.recover_pending().await.unwrap();
    assert_eq!(report, RecoveryReport::default());
    assert_eq!(
        own_pending(&live).await,
        1,
        "another instance's live file is not an orphan"
    );
}

#[tokio::test]
async fn dropping_an_instance_with_nothing_pending_removes_its_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("spool");
    let spooled = SpooledBackend::new(local(&dir.path().join("data")), &root);

    spooled.put_cas("k", b"value".to_vec(), None).await.unwrap();
    assert_eq!(spool_files(&root).len(), 1);
    drop(spooled);

    assert!(spool_files(&root).is_empty());
}
