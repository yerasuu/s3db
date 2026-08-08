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
