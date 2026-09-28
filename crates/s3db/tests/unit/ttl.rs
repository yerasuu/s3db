use super::*;
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = crate::local::test_support::files_backend(root);
    let cipher = Cipher::derive("test passphrase", &[17u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

const SESSIONS: Collection = Collection::new("sessions");

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Session {
    token: String,
}

async fn put(backend: &LocalBackend, cipher: &Cipher, name: &str) {
    SESSIONS
        .put(
            backend,
            cipher,
            name,
            &Session {
                token: name.to_string(),
            },
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_due_entry_is_removed_and_a_future_one_is_not() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "due").await;
    put(&backend, &cipher, "later").await;
    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "due", 1_000)
        .await
        .unwrap();
    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "later", 9_000)
        .await
        .unwrap();

    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, 5_000, &ExpiryConfig::default())
        .await
        .unwrap();

    assert_eq!(report.expired, 1);
    assert_eq!(report.stale_markers, 0);
    assert_eq!(SESSIONS.get::<Session>(&backend, &cipher, "due").await.unwrap().0, None);
    assert!(
        SESSIONS
            .get::<Session>(&backend, &cipher, "later")
            .await
            .unwrap()
            .0
            .is_some(),
        "a deadline in the future must survive"
    );
    assert_eq!(
        crate::ttl::expiry_of(&backend, &cipher, &SESSIONS, "due")
            .await
            .unwrap(),
        None,
        "an expired entry's markers must be gone too"
    );
    assert_eq!(
        crate::ttl::expiry_of(&backend, &cipher, &SESSIONS, "later")
            .await
            .unwrap(),
        Some(9_000)
    );
}

#[tokio::test]
async fn expiry_markers_never_show_up_as_entries() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "a").await;
    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "a", 1_000)
        .await
        .unwrap();

    assert_eq!(SESSIONS.list_names(&backend).await.unwrap(), vec!["a"]);
    let (paged, _cursor) = SESSIONS.list_names_page(&backend, None, 100).await.unwrap();
    assert_eq!(paged, vec!["a"]);
}

/// Re-scheduling must leave exactly one live deadline, and the superseded
/// marker must not remove the entry when its (earlier) time comes.
#[tokio::test]
async fn re_scheduling_supersedes_the_old_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "a").await;

    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "a", 1_000)
        .await
        .unwrap();
    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "a", 9_000)
        .await
        .unwrap();

    assert_eq!(
        crate::ttl::expiry_of(&backend, &cipher, &SESSIONS, "a").await.unwrap(),
        Some(9_000)
    );
    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, 5_000, &ExpiryConfig::default())
        .await
        .unwrap();
    assert_eq!(report.expired, 0, "the old deadline must not fire: {report:?}");
    assert!(
        SESSIONS
            .get::<Session>(&backend, &cipher, "a")
            .await
            .unwrap()
            .0
            .is_some()
    );
}

/// A superseded marker left behind by a crash between the two writes is
/// recognized as stale and cleaned up, not acted on.
#[tokio::test]
async fn a_stale_marker_is_dropped_without_touching_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "a").await;
    // A due marker with no reverse marker at all: the crash case.
    crate::payload::put_json(
        &backend,
        &format!("sessions/.expiry/{}/a.json", crate::ordinal::encode_u64(1_000)),
        &(),
        None,
        &cipher,
    )
    .await
    .unwrap();

    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, 5_000, &ExpiryConfig::default())
        .await
        .unwrap();

    assert_eq!((report.expired, report.stale_markers), (0, 1));
    assert!(
        SESSIONS
            .get::<Session>(&backend, &cipher, "a")
            .await
            .unwrap()
            .0
            .is_some(),
        "an entry with no live deadline must survive"
    );
    let leftovers = crate::payload::list_all_keys(&backend, "sessions/.expiry/")
        .await
        .unwrap();
    assert!(
        leftovers.is_empty(),
        "the stale marker must be cleaned up: {leftovers:?}"
    );
}

#[tokio::test]
async fn clear_expiry_cancels_the_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "a").await;
    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "a", 1_000)
        .await
        .unwrap();

    crate::ttl::clear_expiry(&backend, &cipher, &SESSIONS, "a")
        .await
        .unwrap();

    assert_eq!(
        crate::ttl::expiry_of(&backend, &cipher, &SESSIONS, "a").await.unwrap(),
        None
    );
    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, 5_000, &ExpiryConfig::default())
        .await
        .unwrap();
    assert_eq!((report.expired, report.stale_markers), (0, 0), "{report:?}");
    assert!(
        SESSIONS
            .get::<Session>(&backend, &cipher, "a")
            .await
            .unwrap()
            .0
            .is_some()
    );
    // Clearing again is a no-op.
    crate::ttl::clear_expiry(&backend, &cipher, &SESSIONS, "a")
        .await
        .unwrap();
}

#[tokio::test]
async fn soft_expiry_leaves_the_entry_restorable() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "a").await;
    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "a", 1_000)
        .await
        .unwrap();

    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, 5_000, &ExpiryConfig { soft: true })
        .await
        .unwrap();

    assert_eq!(report.expired, 1);
    assert_eq!(SESSIONS.get::<Session>(&backend, &cipher, "a").await.unwrap().0, None);
    SESSIONS.restore::<Session>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(
        SESSIONS.get::<Session>(&backend, &cipher, "a").await.unwrap().0,
        Some(Session { token: "a".into() }),
        "a soft expiry must be restorable, unlike the default hard one"
    );
}

/// Deadlines are ordinal-encoded so key order is time order — the property the
/// sweep's early stop depends on.
#[tokio::test]
async fn the_sweep_stops_at_the_first_future_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    // 9 before 10 numerically, but "10" before "9" lexicographically: a naive
    // decimal key would make the sweep stop before reaching the earlier one.
    for (name, deadline) in [("nine", 9u64), ("ten", 10), ("eleven", 11)] {
        put(&backend, &cipher, name).await;
        crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, name, deadline)
            .await
            .unwrap();
    }

    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, 10, &ExpiryConfig::default())
        .await
        .unwrap();

    assert_eq!(report.expired, 2, "deadlines 9 and 10 are due, 11 is not: {report:?}");
    assert!(
        SESSIONS
            .get::<Session>(&backend, &cipher, "eleven")
            .await
            .unwrap()
            .0
            .is_some()
    );
    assert_eq!(
        crate::ttl::expiry_of(&backend, &cipher, &SESSIONS, "eleven")
            .await
            .unwrap(),
        Some(11)
    );
}

#[tokio::test]
async fn set_ttl_schedules_relative_to_now() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "a").await;
    let before = crate::ttl::now_ms();

    crate::ttl::set_ttl(&backend, &cipher, &SESSIONS, "a", 60_000)
        .await
        .unwrap();

    let deadline = crate::ttl::expiry_of(&backend, &cipher, &SESSIONS, "a")
        .await
        .unwrap()
        .unwrap();
    assert!(
        deadline >= before + 60_000 && deadline <= crate::ttl::now_ms() + 60_000,
        "deadline {deadline} should be about 60s out from {before}"
    );
}

#[tokio::test]
async fn an_expiry_on_a_nonexistent_entry_is_allowed_and_harmless() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());

    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "ghost", 1_000)
        .await
        .unwrap();
    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, 5_000, &ExpiryConfig::default())
        .await
        .unwrap();

    assert_eq!(report.expired, 1, "the marker fires and cleans itself up: {report:?}");
    assert_eq!(
        crate::payload::list_all_keys(&backend, "sessions/.expiry/")
            .await
            .unwrap(),
        Vec::<String>::new()
    );
}

/// Forces exactly one `Cas::Conflict` on a `put_cas` to a chosen key, then
/// delegates normally -- lets a test drive `set_expiry`'s CAS-with-reread
/// loop through a real conflict instead of only ever seeing a clean write.
#[derive(Debug)]
struct ConflictOnceOn {
    inner: LocalBackend,
    key: String,
    triggered: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl Backend for ConflictOnceOn {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.inner.get(key).await
    }
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        if key == self.key && !self.triggered.swap(true, std::sync::atomic::Ordering::SeqCst) {
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
    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &std::path::Path) -> Result<()> {
        self.inner.put_stream(key, source).await
    }
    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &std::path::Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
}

/// Regression test: `set_expiry` used to discard a `Cas::Conflict` on the
/// reverse marker's write silently, returning `Ok(())` while the actually
/// stored deadline was whichever concurrent writer won -- a caller had no
/// way to know its own call did not take effect. It must now retry past a
/// transient conflict and land its own value.
#[tokio::test]
async fn set_expiry_retries_past_a_conflict_instead_of_silently_dropping_the_write() {
    let dir = tempfile::tempdir().unwrap();
    let (inner, cipher) = test_backend_and_cipher(dir.path());
    put(&inner, &cipher, "a").await;
    let reverse_key = expiry_at_key(&SESSIONS, "a").unwrap();

    let backend = ConflictOnceOn {
        inner,
        key: reverse_key,
        triggered: std::sync::atomic::AtomicBool::new(false),
    };

    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "a", 9_000)
        .await
        .expect("must retry past the injected conflict, not silently give up");

    assert_eq!(
        crate::ttl::expiry_of(&backend.inner, &cipher, &SESSIONS, "a")
            .await
            .unwrap(),
        Some(9_000),
        "the caller's own deadline must actually be the one stored"
    );
}

/// Injects a real, concurrent-looking renewal in the instant right after
/// `expire_due` reads the reverse marker but before it acts -- exactly the
/// window that used to let a sweep destroy a renewal that raced it (the
/// renewal's own fresh deadline, and the reverse marker recording it, both
/// deleted along with the entry). With the claim-before-delete fix, the
/// sweep's own CAS must lose to the renewal's, so it backs off instead.
#[derive(Debug)]
struct ConcurrentRenewalOnFirstGet {
    inner: LocalBackend,
    cipher: Cipher,
    reverse_key: String,
    triggered: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl Backend for ConcurrentRenewalOnFirstGet {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        let result = self.inner.get(key).await?;
        if key == self.reverse_key && !self.triggered.swap(true, std::sync::atomic::Ordering::SeqCst) {
            crate::ttl::set_expiry(&self.inner, &self.cipher, &SESSIONS, "a", 9_000)
                .await
                .unwrap();
        }
        Ok(result)
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
async fn expire_due_does_not_destroy_a_renewal_that_races_the_sweep() {
    let dir = tempfile::tempdir().unwrap();
    let (inner, cipher) = test_backend_and_cipher(dir.path());
    put(&inner, &cipher, "a").await;
    crate::ttl::set_expiry(&inner, &cipher, &SESSIONS, "a", 1_000)
        .await
        .unwrap();

    let backend = ConcurrentRenewalOnFirstGet {
        inner,
        cipher: cipher.clone(),
        reverse_key: expiry_at_key(&SESSIONS, "a").unwrap(),
        triggered: std::sync::atomic::AtomicBool::new(false),
    };

    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, 5_000, &ExpiryConfig::default())
        .await
        .unwrap();

    assert_eq!(
        (report.expired, report.stale_markers),
        (0, 1),
        "the sweep must back off once its claim loses the race: {report:?}"
    );
    assert!(
        SESSIONS
            .get::<Session>(&backend.inner, &cipher, "a")
            .await
            .unwrap()
            .0
            .is_some(),
        "the entry must survive -- the renewal raced the sweep and must win"
    );
    assert_eq!(
        crate::ttl::expiry_of(&backend.inner, &cipher, &SESSIONS, "a")
            .await
            .unwrap(),
        Some(9_000),
        "the renewal's own deadline must survive intact, not be deleted along with the entry"
    );
}

#[tokio::test]
async fn set_expiry_refuses_to_overwrite_a_sweep_s_purge_claim() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "a").await;
    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "a", 1_000)
        .await
        .unwrap();

    // Simulates `expire_due`'s claim landing right before a renewal's own
    // CAS attempt reaches the reverse marker -- whether that renewal's own
    // read happened before or after the claim, its write must not be able
    // to land on top of the sentinel.
    let reverse_key = expiry_at_key(&SESSIONS, "a").unwrap();
    let (_, etag) = get_json::<ExpiryAt>(&backend, &reverse_key, &cipher).await.unwrap();
    assert_eq!(
        put_json(
            &backend,
            &reverse_key,
            &ExpiryAt {
                expires_at_ms: CLAIMED_FOR_PURGE_MS,
            },
            etag.as_deref(),
            &cipher,
        )
        .await
        .unwrap(),
        Cas::Ok
    );

    let err = crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "a", 9_000)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("purging"), "unexpected error: {err}");

    assert_eq!(
        get_json::<ExpiryAt>(&backend, &reverse_key, &cipher).await.unwrap().0,
        ExpiryAt {
            expires_at_ms: CLAIMED_FOR_PURGE_MS
        },
        "the claim must survive a renewal attempt that lost to it"
    );
}

#[tokio::test]
async fn a_foreign_key_under_the_expiry_namespace_is_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put(&backend, &cipher, "a").await;
    backend
        .put_cas("sessions/.expiry/not-an-ordinal/a.json", b"?".to_vec(), None)
        .await
        .unwrap();

    let report = crate::ttl::expire_due(&backend, &cipher, &SESSIONS, u64::MAX, &ExpiryConfig::default())
        .await
        .unwrap();

    assert_eq!((report.expired, report.stale_markers), (0, 0), "{report:?}");
    assert!(
        SESSIONS
            .get::<Session>(&backend, &cipher, "a")
            .await
            .unwrap()
            .0
            .is_some(),
        "an unrecognized marker must not be acted on"
    );
    assert_eq!(
        crate::payload::list_all_keys(&backend, "sessions/.expiry/")
            .await
            .unwrap()
            .len(),
        1,
        "nor deleted"
    );
}
