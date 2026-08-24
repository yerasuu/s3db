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
