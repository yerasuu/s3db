use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;
use crate::snapshot::ReadSnapshot;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[23u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
}

#[tokio::test]
async fn sweep_leaves_a_fresh_pending_tombstone_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await;

    let report = sweep(&backend, &cipher, &coll, &GcConfig::default()).await.unwrap();
    assert_eq!(
        report.tombstones_retried, 0,
        "tombstone is fresh, not past tombstone_retry_age yet"
    );
}

#[tokio::test]
async fn sweep_retries_an_aged_pending_delete() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await;
    // Since LocalBackend's own delete always confirms, the tombstone is
    // already Purged after `delete` -- age it out immediately with a
    // zero retry threshold instead, which exercises the same "past
    // due" branch regardless of purge_state.
    let config = GcConfig {
        tombstone_retry_age: Duration::ZERO,
        ..GcConfig::default()
    };
    let report = sweep(&backend, &cipher, &coll, &config).await.unwrap();
    assert_eq!(
        report.tombstones_retried, 0,
        "already Purged by delete() itself, nothing Pending left to retry"
    );
}

#[tokio::test]
async fn sweep_forgets_an_aged_purged_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await; // LocalBackend confirms -> tombstone is Purged
    tokio::time::sleep(Duration::from_millis(5)).await; // ensure strictly past a zero-width grace period

    let config = GcConfig {
        tombstone_purge_age: Duration::ZERO,
        ..GcConfig::default()
    };
    let report = sweep(&backend, &cipher, &coll, &config).await.unwrap();
    assert_eq!(report.tombstones_forgotten, 1);
    assert!(coll.list_tombstones(&backend, &cipher).await.unwrap().is_empty());
}

#[tokio::test]
async fn sweep_prunes_old_history_when_enabled() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    let (_, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, etag.as_deref())
        .await
        .unwrap();
    assert_eq!(coll.list_versions(&backend, "a").await.unwrap().len(), 1);
    // Millisecond-resolution timestamps: make sure the archive's own
    // timestamp is strictly in the past relative to the sweep below,
    // rather than racing to land in the same millisecond.
    tokio::time::sleep(Duration::from_millis(5)).await;

    let config = GcConfig {
        history_max_age: Some(Duration::ZERO),
        ..GcConfig::default()
    };
    let report = sweep(&backend, &cipher, &coll, &config).await.unwrap();
    assert_eq!(report.history_versions_pruned, 1);
    assert!(coll.list_versions(&backend, "a").await.unwrap().is_empty());
}

#[tokio::test]
async fn sweep_never_prunes_history_a_live_snapshot_still_needs() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    let (_, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();

    let snap = ReadSnapshot::open(&backend, &cipher, Duration::from_secs(300))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, etag.as_deref())
        .await
        .unwrap();

    let config = GcConfig {
        history_max_age: Some(Duration::ZERO),
        ..GcConfig::default()
    };
    let report = sweep(&backend, &cipher, &coll, &config).await.unwrap();
    assert_eq!(
        report.history_versions_pruned, 0,
        "the snapshot's own moment falls inside this version's lifetime"
    );

    let value: Option<Widget> = snap.get(&backend, &cipher, &coll, "a").await.unwrap();
    assert_eq!(
        value,
        Some(Widget { count: 1 }),
        "version must still be there for the snapshot to read"
    );
}
