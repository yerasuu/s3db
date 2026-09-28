use super::*;
use crate::config::LocalEngine;

fn backend(root: &Path) -> FilesBackend {
    FilesBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    })
}

#[tokio::test]
async fn get_returns_empty_and_no_etag_for_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let (bytes, etag) = backend(dir.path()).get("nope").await.unwrap();
    assert!(bytes.is_empty());
    assert!(etag.is_none());
}

#[tokio::test]
async fn put_cas_create_only_conflicts_on_a_second_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    assert_eq!(b.put_cas("k", b"v1".to_vec(), None).await.unwrap(), Cas::Ok);
    assert_eq!(b.put_cas("k", b"v2".to_vec(), None).await.unwrap(), Cas::Conflict);
    let (bytes, _) = b.get("k").await.unwrap();
    assert_eq!(bytes, b"v1");
}

#[tokio::test]
async fn put_cas_update_requires_the_current_etag() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("k", b"v1".to_vec(), None).await.unwrap();
    let (_, etag) = b.get("k").await.unwrap();
    assert_eq!(
        b.put_cas("k", b"v2".to_vec(), Some("stale")).await.unwrap(),
        Cas::Conflict
    );
    assert_eq!(b.put_cas("k", b"v2".to_vec(), etag.as_deref()).await.unwrap(), Cas::Ok);
    let (bytes, _) = b.get("k").await.unwrap();
    assert_eq!(bytes, b"v2");
}

#[tokio::test]
async fn delete_is_idempotent_and_makes_get_report_missing() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("k", b"v".to_vec(), None).await.unwrap();
    b.delete("k").await.unwrap();
    b.delete("k").await.unwrap(); // second delete of an already-gone key: no error
    let (bytes, etag) = b.get("k").await.unwrap();
    assert!(bytes.is_empty());
    assert!(etag.is_none());
}

#[tokio::test]
async fn list_prefix_finds_nested_keys_and_skips_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("repos/team/proj/refs.json", b"a".to_vec(), None)
        .await
        .unwrap();
    b.put_cas("repos/team/proj/objects/pack/x.pack", b"bb".to_vec(), None)
        .await
        .unwrap();
    b.put_cas("repos/other/refs.json", b"c".to_vec(), None).await.unwrap();

    let mut found = b.list_prefix("repos/team/proj/").await.unwrap();
    found.sort();
    assert_eq!(
        found,
        vec![
            ("repos/team/proj/objects/pack/x.pack".to_string(), 2),
            ("repos/team/proj/refs.json".to_string(), 1),
        ]
    );
}

#[tokio::test]
async fn list_prefix_empty_for_a_directory_that_does_not_exist() {
    let dir = tempfile::tempdir().unwrap();
    let found = backend(dir.path()).list_prefix("nope/").await.unwrap();
    assert!(found.is_empty());
}

#[cfg(feature = "streaming")]
#[tokio::test]
async fn put_stream_then_get_stream_roundtrips_and_bumps_the_etag() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let src_dir = tempfile::tempdir().unwrap();
    let source = src_dir.path().join("source");
    let dest = src_dir.path().join("dest");

    tokio::fs::write(&source, b"content v1").await.unwrap();
    b.put_stream("k", &source).await.unwrap();
    let (_, etag1) = b.get("k").await.unwrap();
    b.get_stream("k", &dest).await.unwrap();
    assert_eq!(tokio::fs::read(&dest).await.unwrap(), b"content v1");

    tokio::fs::write(&source, b"content v2, longer").await.unwrap();
    b.put_stream("k", &source).await.unwrap();
    let (_, etag2) = b.get("k").await.unwrap();
    b.get_stream("k", &dest).await.unwrap();
    assert_eq!(tokio::fs::read(&dest).await.unwrap(), b"content v2, longer");
    assert_ne!(etag1, etag2);

    // `put_stream` doesn't consume/touch its source file.
    assert_eq!(tokio::fs::read(&source).await.unwrap(), b"content v2, longer");
}

#[cfg(feature = "streaming")]
#[tokio::test]
async fn get_stream_errors_on_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();
    let dest = dest_dir.path().join("dest");
    assert!(backend(dir.path()).get_stream("nope", &dest).await.is_err());
}

#[tokio::test]
async fn get_range_returns_exactly_the_requested_slice() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("k", b"0123456789".to_vec(), None).await.unwrap();
    assert_eq!(b.get_range("k", 3, 4).await.unwrap(), b"3456");
    assert_eq!(b.get_range("k", 0, 10).await.unwrap(), b"0123456789");
}

#[tokio::test]
async fn get_range_errors_on_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    assert!(backend(dir.path()).get_range("nope", 0, 1).await.is_err());
}

#[tokio::test]
async fn get_range_errors_when_the_range_exceeds_the_stored_size() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("k", b"short".to_vec(), None).await.unwrap();
    assert!(b.get_range("k", 0, 1000).await.is_err());
}

/// Regression test for the live half of the two-file tear this module's
/// own doc describes: before `get` took the shared lock too, it could read
/// the body and the version-counter sidecar at two different moments, and
/// a `put_cas` racing in between could hand it a body/etag pair that never
/// existed together. Simulates that race directly against the same
/// `<key>.s3dblock` `put_cas` itself locks, instead of trying to land a
/// real concurrent `put_cas` inside the exact write window -- there is no
/// reliable way to pause `put_cas` mid-write from outside it.
#[tokio::test(flavor = "multi_thread")]
async fn get_waits_out_an_exclusive_lock_instead_of_racing_it() {
    let dir = tempfile::tempdir().unwrap();
    let b = std::sync::Arc::new(backend(dir.path()));
    b.put_cas("k", b"v1".to_vec(), None).await.unwrap();
    let etag = b.get("k").await.unwrap().1.unwrap();

    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));

    let lock_path = b.lock_path("k");
    let hold_events = events.clone();
    let holder = tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .unwrap();
        fs4::FileExt::lock(&file).unwrap();
        hold_events.lock().unwrap().push("locked");
        std::thread::sleep(std::time::Duration::from_millis(150));
        hold_events.lock().unwrap().push("unlocked");
        // Dropping `file` here releases the flock.
    });
    // Gives the holder above a moment to actually acquire the lock before
    // the read below tries to race it -- otherwise both could plausibly
    // start from "unlocked" and this would pass for the wrong reason.
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    let get_events = events.clone();
    let reader = std::sync::Arc::clone(&b);
    let getter = tokio::spawn(async move {
        let result = reader.get("k").await.unwrap();
        get_events.lock().unwrap().push("got");
        result
    });

    holder.await.unwrap();
    let (bytes, got_etag) = getter.await.unwrap();

    assert_eq!(bytes, b"v1");
    assert_eq!(got_etag.as_deref(), Some(etag.as_str()));
    assert_eq!(
        *events.lock().unwrap(),
        vec!["locked", "unlocked", "got"],
        "get must wait for the exclusive lock to be released, not race it"
    );
}
