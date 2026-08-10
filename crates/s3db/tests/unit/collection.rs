use super::*;
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&crate::config::LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: crate::config::LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[5u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
}

#[tokio::test]
async fn hash_prefix_key_nests_under_a_bucket_and_still_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets").with_hash_prefix(16);

    let key = coll.key("alice");
    assert!(key.starts_with("widgets/"), "{key}");
    assert!(key.ends_with("/alice.json"), "{key}");
    assert_ne!(
        key, "widgets/alice.json",
        "must actually nest under a bucket, not fall back to flat"
    );

    coll.put(&backend, &cipher, "alice", &Widget { count: 1 }, None)
        .await
        .unwrap();
    let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(value, Some(Widget { count: 1 }));
}

#[test]
fn write_key_matches_key_and_reuses_the_same_buffer() {
    let coll = Collection::new("widgets");
    let mut buf = String::with_capacity(64);
    let original_capacity = buf.capacity();

    coll.write_key(&mut buf, "alice");
    assert_eq!(buf, coll.key("alice"));

    coll.write_key(&mut buf, "bob");
    assert_eq!(buf, coll.key("bob"));
    assert_eq!(
        buf.capacity(),
        original_capacity,
        "must reuse buf's existing allocation, not grow/reallocate for a same-sized name"
    );
}

#[test]
fn write_key_matches_key_with_hash_prefix_entropy_too() {
    let coll = Collection::new("widgets").with_hash_prefix(16);
    let mut buf = String::new();
    coll.write_key(&mut buf, "alice");
    assert_eq!(buf, coll.key("alice"));
}

#[tokio::test]
async fn hash_prefix_list_names_recovers_the_bare_name() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets").with_hash_prefix(4);
    for (name, count) in [("alice", 1), ("bob", 2), ("carol", 3)] {
        coll.put(&backend, &cipher, name, &Widget { count }, None)
            .await
            .unwrap();
    }
    let mut names = coll.list_names(&backend).await.unwrap();
    names.sort();
    assert_eq!(names, vec!["alice", "bob", "carol"]);
}

#[tokio::test]
async fn get_is_none_before_any_put() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    let (value, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(value, None);
    assert_eq!(etag, None);
}

#[tokio::test]
async fn put_then_get_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    let cas = coll
        .put(&backend, &cipher, "a", &Widget { count: 3 }, None)
        .await
        .unwrap();
    assert_eq!(cas, Cas::Ok);
    let (value, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(value, Some(Widget { count: 3 }));
    assert!(etag.is_some());
}

#[tokio::test]
async fn put_conflicts_on_stale_etag() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    let cas = coll
        .put(&backend, &cipher, "a", &Widget { count: 2 }, None)
        .await
        .unwrap();
    assert_eq!(cas, Cas::Conflict);
}

#[tokio::test]
async fn delete_makes_get_report_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await;
    let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(value, None);
}

#[tokio::test]
async fn delete_writes_a_purged_tombstone_with_a_restore_etag() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await;

    let (tombstone, _) = get_json::<Tombstone>(&backend, &coll.tombstone_key("a"), &cipher)
        .await
        .unwrap();
    assert_eq!(tombstone.purge_state, PurgeState::Purged);
    assert!(tombstone.restore_etag.is_some());
}

#[tokio::test]
async fn delete_of_a_never_written_name_leaves_nothing_to_restore() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.delete(&backend, &cipher, "ghost").await;

    let (tombstone, _) = get_json::<Tombstone>(&backend, &coll.tombstone_key("ghost"), &cipher)
        .await
        .unwrap();
    assert_eq!(tombstone.restore_etag, None);
    assert!(coll.restore::<Widget>(&backend, &cipher, "ghost").await.is_err());
}

#[tokio::test]
async fn restore_brings_back_the_deleted_value_and_clears_the_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await;

    coll.restore::<Widget>(&backend, &cipher, "a").await.unwrap();

    let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(value, Some(Widget { count: 1 }));
    let (_, tomb_etag) = get_json::<Tombstone>(&backend, &coll.tombstone_key("a"), &cipher)
        .await
        .unwrap();
    assert!(tomb_etag.is_none(), "tombstone must be gone after a successful restore");
}

#[tokio::test]
async fn restore_overwrites_whatever_object_currently_occupies_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await;
    // Something re-occupies the now-empty key before the restore runs
    // -- `write_object_for_restore`'s CAS-with-reread must still win,
    // not bounce off a stale-etag conflict against it.
    coll.put(&backend, &cipher, "a", &Widget { count: 99 }, None)
        .await
        .unwrap();

    coll.restore::<Widget>(&backend, &cipher, "a").await.unwrap();
    let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(value, Some(Widget { count: 1 }));
}

#[tokio::test]
async fn list_names_and_list_all_see_every_put_item() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let backend: Arc<dyn Backend> = Arc::new(backend);
    let cipher = Arc::new(cipher);
    let coll = Collection::new("widgets");
    for (name, count) in [("a", 1), ("b", 2), ("c", 3)] {
        coll.put(backend.as_ref(), cipher.as_ref(), name, &Widget { count }, None)
            .await
            .unwrap();
    }
    let mut names = coll.list_names(backend.as_ref()).await.unwrap();
    names.sort();
    assert_eq!(names, vec!["a", "b", "c"]);

    let mut all: Vec<Widget> = coll.list_all(&backend, &cipher).await.unwrap();
    all.sort_by_key(|w| w.count);
    assert_eq!(all, vec![Widget { count: 1 }, Widget { count: 2 }, Widget { count: 3 }]);
}

#[tokio::test]
async fn nested_suffix_roundtrips_and_lists_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new_with_suffix("repos", "/.conf/config.json");
    assert_eq!(coll.key("acme/web"), "repos/acme/web/.conf/config.json");
    coll.put(&backend, &cipher, "acme/web", &Widget { count: 9 }, None)
        .await
        .unwrap();
    let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "acme/web").await.unwrap();
    assert_eq!(value, Some(Widget { count: 9 }));
    assert_eq!(coll.list_names(&backend).await.unwrap(), vec!["acme/web"]);
}

#[tokio::test]
async fn get_or_default_returns_default_not_none_when_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    let (value, etag) = coll
        .get_or_default::<Widget>(&backend, &cipher, "missing")
        .await
        .unwrap();
    assert_eq!(value, Widget::default());
    assert_eq!(etag, None);
}

#[tokio::test]
async fn find_all_filters_by_predicate() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let backend: Arc<dyn Backend> = Arc::new(backend);
    let cipher = Arc::new(cipher);
    let coll = Collection::new("widgets");
    for (name, count) in [("a", 1), ("b", 2), ("c", 3)] {
        coll.put(backend.as_ref(), cipher.as_ref(), name, &Widget { count }, None)
            .await
            .unwrap();
    }
    let mut big: Vec<Widget> = coll
        .find_all(&backend, &cipher, |w: &Widget| w.count > 1)
        .await
        .unwrap();
    big.sort_by_key(|w| w.count);
    assert_eq!(big, vec![Widget { count: 2 }, Widget { count: 3 }]);
}

#[tokio::test]
async fn singleton_put_then_get_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let settings = Singleton::new(".conf/global.json");
    let (value, etag) = settings.get::<Widget>(&backend, &cipher).await.unwrap();
    assert_eq!(value, Widget::default());
    assert_eq!(etag, None);

    settings
        .put(&backend, &cipher, &Widget { count: 7 }, None)
        .await
        .unwrap();
    let (value, etag) = settings.get::<Widget>(&backend, &cipher).await.unwrap();
    assert_eq!(value, Widget { count: 7 });
    assert!(etag.is_some());
}

#[tokio::test]
async fn put_versioned_fresh_create_archives_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    assert_eq!(coll.list_versions(&backend, "a").await.unwrap(), Vec::<String>::new());
}

#[tokio::test]
async fn put_versioned_update_archives_the_previous_value() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    let (_value, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    let etag = etag.unwrap();

    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, Some(&etag))
        .await
        .unwrap();

    let versions = coll.list_versions(&backend, "a").await.unwrap();
    assert_eq!(versions.len(), 1);
    let archived: Widget = coll
        .get_version(&backend, &cipher, "a", &versions[0])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(archived, Widget { count: 1 });

    let (current, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(current, Some(Widget { count: 2 }));
}

#[tokio::test]
async fn manual_rollback_via_get_version_then_put_versioned() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");

    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    let (_value, etag1) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    let etag1 = etag1.unwrap();

    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, Some(&etag1))
        .await
        .unwrap();
    let (_value, etag2) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    let etag2 = etag2.unwrap();

    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 3 }, Some(&etag2))
        .await
        .unwrap();

    let versions = coll.list_versions(&backend, "a").await.unwrap();
    assert_eq!(versions.len(), 2);

    // Oldest archived version is the one written under etag1 (count: 1).
    let oldest: Widget = coll.get_version(&backend, &cipher, "a", &etag1).await.unwrap().unwrap();
    assert_eq!(oldest, Widget { count: 1 });

    let (_value, current_etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    let current_etag = current_etag.unwrap();
    coll.put_versioned(&backend, &cipher, "a", &oldest, Some(&current_etag))
        .await
        .unwrap();

    let (restored, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(restored, Some(Widget { count: 1 }));
}

#[tokio::test]
async fn put_versioned_conflicts_on_stale_etag_without_archiving() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();

    let cas = coll
        .put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, Some("stale-etag"))
        .await
        .unwrap();
    assert_eq!(cas, Cas::Conflict);
    assert_eq!(coll.list_versions(&backend, "a").await.unwrap(), Vec::<String>::new());
}
