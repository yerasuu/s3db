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

    let key = coll.key("alice").unwrap();
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

    coll.write_key(&mut buf, "alice").unwrap();
    assert_eq!(buf, coll.key("alice").unwrap());

    coll.write_key(&mut buf, "bob").unwrap();
    assert_eq!(buf, coll.key("bob").unwrap());
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
    coll.write_key(&mut buf, "alice").unwrap();
    assert_eq!(buf, coll.key("alice").unwrap());
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
    coll.delete(&backend, &cipher, "a").await.unwrap();
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
    coll.delete(&backend, &cipher, "a").await.unwrap();

    let (tombstone, _) = get_json::<Tombstone>(&backend, &coll.tombstone_key("a").unwrap(), &cipher)
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
    coll.delete(&backend, &cipher, "ghost").await.unwrap();

    let (tombstone, _) = get_json::<Tombstone>(&backend, &coll.tombstone_key("ghost").unwrap(), &cipher)
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
    coll.delete(&backend, &cipher, "a").await.unwrap();

    coll.restore::<Widget>(&backend, &cipher, "a").await.unwrap();

    let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(value, Some(Widget { count: 1 }));
    let (_, tomb_etag) = get_json::<Tombstone>(&backend, &coll.tombstone_key("a").unwrap(), &cipher)
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
    coll.delete(&backend, &cipher, "a").await.unwrap();
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
    assert_eq!(coll.key("acme/web").unwrap(), "repos/acme/web/.conf/config.json");
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
async fn created_at_bookkeeping_never_leaks_into_list_names_or_list_all() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let backend: Arc<dyn Backend> = Arc::new(backend);
    let cipher = Arc::new(cipher);
    let coll = Collection::new("widgets");
    coll.put_versioned(backend.as_ref(), cipher.as_ref(), "a", &Widget { count: 1 }, None)
        .await
        .unwrap();

    assert_eq!(coll.list_names(backend.as_ref()).await.unwrap(), vec!["a"]);
    let all: Vec<Widget> = coll.list_all(&backend, &cipher).await.unwrap();
    assert_eq!(all, vec![Widget { count: 1 }]);
}

#[tokio::test]
async fn put_versioned_records_the_creation_time_only_on_the_first_fresh_create() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    assert_eq!(coll.created_at(&backend, &cipher, "a").await.unwrap(), None);

    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    let created_at = coll
        .created_at(&backend, &cipher, "a")
        .await
        .unwrap()
        .expect("a fresh create must record its creation time");

    let (_value, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, etag.as_deref())
        .await
        .unwrap();
    assert_eq!(
        coll.created_at(&backend, &cipher, "a").await.unwrap(),
        Some(created_at),
        "an update must never move the original creation time"
    );
}

#[tokio::test]
async fn plain_put_never_records_a_creation_time() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    assert_eq!(coll.created_at(&backend, &cipher, "a").await.unwrap(), None);
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

/// A `Collection` name goes straight into the object key, so a name that
/// could reach one of the crate's own reserved namespaces
/// (`.history/`, `.deleted/`, `.created/`) has to be refused at the key
/// builder rather than silently landing there.
#[tokio::test]
async fn rejects_a_name_that_would_reach_a_reserved_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    for bad in ["", ".deleted/a", "a/.history/b", "../elsewhere", "a//b", ".hidden"] {
        assert!(coll.key(bad).is_err(), "{bad:?} should be refused by key()");
        assert!(
            coll.put(&backend, &cipher, bad, &Widget { count: 1 }, None)
                .await
                .is_err(),
            "{bad:?} should be refused by put()"
        );
        assert!(
            coll.delete(&backend, &cipher, bad).await.is_err(),
            "{bad:?} should be refused by delete()"
        );
    }
}

/// Records how many `get` calls are in flight at once, so a fan-out bound
/// can be asserted as a fact about real concurrency rather than inferred
/// from the permit arithmetic.
#[derive(Debug)]
struct ConcurrencyProbeBackend {
    inner: LocalBackend,
    in_flight: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Backend for ConcurrencyProbeBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        use std::sync::atomic::Ordering;
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        // Long enough that every permitted fetch really does overlap the
        // others; without it the local driver can finish each get before
        // the next one starts and the peak would say 1 no matter what.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let result = self.inner.get(key).await;
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
        result
    }
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
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
    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &std::path::Path) -> Result<()> {
        self.inner.put_stream(key, source).await
    }
    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &std::path::Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
}

#[tokio::test]
async fn list_all_bounds_its_fan_out_by_the_budget_and_still_returns_everything() {
    let dir = tempfile::tempdir().unwrap();
    let (writer, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    for i in 0..20u32 {
        coll.put(&writer, &cipher, &format!("w{i}"), &Widget { count: i }, None)
            .await
            .unwrap();
    }

    let probe = Arc::new(ConcurrencyProbeBackend {
        inner: test_backend_and_cipher(dir.path()).0,
        in_flight: std::sync::atomic::AtomicUsize::new(0),
        peak: std::sync::atomic::AtomicUsize::new(0),
    });
    let backend: Arc<dyn Backend> = probe.clone();
    let cipher = Arc::new(cipher);
    // 2 max-sized objects' worth of buffer == 2 concurrent fetches.
    let budget = MemoryBudget {
        max_buffer_bytes: 2 * crate::payload::MAX_OBJECT_BYTES,
    };

    let mut counts: Vec<u32> = coll
        .list_all_with_budget::<Widget>(&backend, &cipher, budget)
        .await
        .unwrap()
        .into_iter()
        .map(|w| w.count)
        .collect();
    counts.sort_unstable();

    assert_eq!(
        counts,
        (0..20).collect::<Vec<u32>>(),
        "every entry must still come back"
    );
    let peak = probe.peak.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        peak <= budget.max_concurrency(),
        "fan-out peaked at {peak} concurrent gets, over the budget's {}",
        budget.max_concurrency()
    );
    assert!(
        peak > 1,
        "budget of 2 should still fetch concurrently, peaked at {peak}"
    );
}

#[tokio::test]
async fn update_creates_when_absent_and_mutates_when_present() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");

    let created = coll
        .update::<Widget, _>(&backend, &cipher, "w", |w| {
            w.count += 1;
            Ok(Update::Write)
        })
        .await
        .unwrap();
    assert_eq!(created, Widget { count: 1 }, "absent entry starts from T::default()");

    let bumped = coll
        .update::<Widget, _>(&backend, &cipher, "w", |w| {
            w.count += 10;
            Ok(Update::Write)
        })
        .await
        .unwrap();
    assert_eq!(bumped, Widget { count: 11 });
    let (stored, _etag) = coll.get::<Widget>(&backend, &cipher, "w").await.unwrap();
    assert_eq!(stored, Some(Widget { count: 11 }));
}

#[tokio::test]
async fn update_keep_writes_nothing_and_leaves_the_etag_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "w", &Widget { count: 7 }, None)
        .await
        .unwrap();
    let (_, before) = coll.get::<Widget>(&backend, &cipher, "w").await.unwrap();

    let kept = coll
        .update::<Widget, _>(&backend, &cipher, "w", |w| {
            w.count = 999;
            Ok(Update::Keep)
        })
        .await
        .unwrap();

    assert_eq!(
        kept,
        Widget { count: 7 },
        "Keep returns the stored value, not the mutated one"
    );
    let (stored, after) = coll.get::<Widget>(&backend, &cipher, "w").await.unwrap();
    assert_eq!(stored, Some(Widget { count: 7 }));
    assert_eq!(after, before, "Keep must not bump the etag");
}

#[tokio::test]
async fn update_propagates_a_mutator_error_without_writing() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");

    let err = coll
        .update::<Widget, _>(&backend, &cipher, "w", |_| anyhow::bail!("nope"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("nope"));

    let (stored, _etag) = coll.get::<Widget>(&backend, &cipher, "w").await.unwrap();
    assert_eq!(stored, None, "a refused mutation must not create the entry");
}

/// The whole point of the CAS retry: concurrent increments must all land,
/// which a read-then-blind-write would silently lose.
#[tokio::test]
async fn concurrent_updates_all_land_without_losing_an_increment() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let backend = Arc::new(backend);
    let cipher = Arc::new(cipher);
    let coll = Collection::new("widgets");

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let backend = Arc::clone(&backend);
        let cipher = Arc::clone(&cipher);
        let coll = coll.clone();
        set.spawn(async move {
            coll.update::<Widget, _>(backend.as_ref(), &cipher, "counter", |w| {
                w.count += 1;
                Ok(Update::Write)
            })
            .await
        });
    }
    while let Some(joined) = set.join_next().await {
        joined.unwrap().unwrap();
    }

    let (stored, _etag) = coll.get::<Widget>(backend.as_ref(), &cipher, "counter").await.unwrap();
    assert_eq!(
        stored,
        Some(Widget { count: 8 }),
        "every concurrent increment must survive"
    );
}

#[tokio::test]
async fn singleton_update_shares_the_same_contract() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let single = Singleton::new("global.json");

    single
        .update::<Widget, _>(&backend, &cipher, |w| {
            w.count += 3;
            Ok(Update::Write)
        })
        .await
        .unwrap();
    let kept = single
        .update::<Widget, _>(&backend, &cipher, |w| {
            w.count = 0;
            Ok(Update::Keep)
        })
        .await
        .unwrap();

    assert_eq!(kept, Widget { count: 3 });
    let (stored, _etag) = single.get::<Widget>(&backend, &cipher).await.unwrap();
    assert_eq!(stored, Widget { count: 3 });
}
