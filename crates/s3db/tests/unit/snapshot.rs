use super::*;
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = crate::local::test_support::files_backend(root);
    let cipher = Cipher::derive("test passphrase", &[19u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
struct Widget {
    count: u32,
}

#[tokio::test]
async fn snapshot_sees_the_live_value_when_nothing_has_changed_since() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();

    let snap = ReadSnapshot::open(&backend, &cipher, Duration::from_secs(60))
        .await
        .unwrap();
    let value: Option<Widget> = snap.get(&backend, &cipher, &coll, "a").await.unwrap();
    assert_eq!(value, Some(Widget { count: 1 }));
}

#[tokio::test]
async fn snapshot_is_none_for_a_name_that_never_existed() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    let snap = ReadSnapshot::open(&backend, &cipher, Duration::from_secs(60))
        .await
        .unwrap();
    let value: Option<Widget> = snap.get(&backend, &cipher, &coll, "ghost").await.unwrap();
    assert_eq!(value, None);
}

#[tokio::test]
async fn snapshot_sees_the_value_as_of_its_own_moment_not_later_writes() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    let (_, etag1) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();

    let snap = ReadSnapshot::open(&backend, &cipher, Duration::from_secs(60))
        .await
        .unwrap();
    // Millisecond-resolution timestamps: guarantee the next write's
    // archive timestamp is strictly after the snapshot's own moment,
    // rather than racing to land in the same millisecond.
    tokio::time::sleep(Duration::from_millis(5)).await;

    // Written *after* the snapshot was opened -- must not be visible
    // through it.
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, etag1.as_deref())
        .await
        .unwrap();

    let value: Option<Widget> = snap.get(&backend, &cipher, &coll, "a").await.unwrap();
    assert_eq!(value, Some(Widget { count: 1 }));

    // The live value, meanwhile, reflects the later write.
    let (live, _) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(live, Some(Widget { count: 2 }));
}

/// The one documented phantom-read gap: an entity created *after* the
/// snapshot's own moment, never modified since, has no `.history/` entry to
/// rule it out. `Collection::created_at` (recorded by `put_versioned` at
/// first create) is what closes it.
#[tokio::test]
async fn snapshot_does_not_see_an_entity_created_after_it_was_opened() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");

    let snap = ReadSnapshot::open(&backend, &cipher, Duration::from_secs(60))
        .await
        .unwrap();
    // Millisecond-resolution timestamps: guarantee the create below lands
    // strictly after the snapshot's own moment.
    tokio::time::sleep(Duration::from_millis(5)).await;

    // Created *after* the snapshot was opened, and never touched again --
    // exactly the case with no history entry to place it in time.
    coll.put_versioned(&backend, &cipher, "brand-new", &Widget { count: 1 }, None)
        .await
        .unwrap();

    let value: Option<Widget> = snap.get(&backend, &cipher, &coll, "brand-new").await.unwrap();
    assert_eq!(
        value, None,
        "must not see an entity that didn't exist yet at the snapshot's moment"
    );

    // The live value, meanwhile, does see it.
    let (live, _) = coll.get::<Widget>(&backend, &cipher, "brand-new").await.unwrap();
    assert_eq!(live, Some(Widget { count: 1 }));
}

/// A plain `Collection::put` (no versioning, no creation tracking) can't be
/// ruled out either way -- `created_at` is `None`, so this falls back to
/// the live value exactly as it did before this fix, not a new false
/// negative.
#[tokio::test]
async fn snapshot_falls_back_to_the_live_value_when_creation_time_is_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");

    let snap = ReadSnapshot::open(&backend, &cipher, Duration::from_secs(60))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    coll.put(&backend, &cipher, "plain", &Widget { count: 1 }, None)
        .await
        .unwrap();

    let value: Option<Widget> = snap.get(&backend, &cipher, &coll, "plain").await.unwrap();
    assert_eq!(value, Some(Widget { count: 1 }));
}

#[tokio::test]
async fn close_removes_the_lease_record() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let snap = ReadSnapshot::open(&backend, &cipher, Duration::from_secs(60))
        .await
        .unwrap();
    let (_, etag) = get_json::<SnapshotLease>(&backend, &lease_key(snap.snapshot_id()), &cipher)
        .await
        .unwrap();
    assert!(etag.is_some());

    snap.close(&backend).await;
    let (_, etag) = get_json::<SnapshotLease>(&backend, &lease_key(snap.snapshot_id()), &cipher)
        .await
        .unwrap();
    assert!(etag.is_none());
}
