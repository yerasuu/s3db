use super::*;
use crate::config::LocalEngine;

fn backend(root: &std::path::Path) -> RedbBackend {
    RedbBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Redb,
    })
}

#[tokio::test]
async fn get_returns_empty_and_no_etag_for_a_missing_key_on_a_brand_new_db() {
    // The redb table itself doesn't exist yet -- no write has ever
    // happened, so `open_table` on the read path must be treated as "empty
    // bucket", not propagated as an error.
    let dir = tempfile::tempdir().unwrap();
    let (bytes, etag) = backend(dir.path()).get("nope").await.unwrap();
    assert!(bytes.is_empty());
    assert!(etag.is_none());
}

#[tokio::test]
async fn list_prefix_on_a_brand_new_db_is_empty_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let found = backend(dir.path()).list_prefix("anything/").await.unwrap();
    assert!(found.is_empty());
}

#[tokio::test]
async fn put_cas_create_only_conflicts_on_a_second_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    assert_eq!(b.put_cas("k", b"v1".to_vec(), None).await.unwrap(), Cas::Ok);
    assert_eq!(b.put_cas("k", b"v2".to_vec(), None).await.unwrap(), Cas::Conflict);
    let (bytes, _) = b.get("k").await.unwrap();
    assert_eq!(bytes, b"v1", "the losing write must not have landed");
}

#[tokio::test]
async fn a_conflicting_put_cas_does_not_bump_the_version() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("k", b"v1".to_vec(), None).await.unwrap();
    let (_, etag1) = b.get("k").await.unwrap();
    // Losing write, wrong expected_etag -- the abort() path.
    assert_eq!(
        b.put_cas("k", b"v2".to_vec(), Some("stale")).await.unwrap(),
        Cas::Conflict
    );
    let (_, etag2) = b.get("k").await.unwrap();
    assert_eq!(
        etag1, etag2,
        "an aborted transaction must not have committed a new version"
    );
}

#[tokio::test]
async fn put_cas_update_requires_the_current_etag() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("k", b"v1".to_vec(), None).await.unwrap();
    let (_, etag) = b.get("k").await.unwrap();
    assert_eq!(b.put_cas("k", b"v2".to_vec(), etag.as_deref()).await.unwrap(), Cas::Ok);
    let (bytes, _) = b.get("k").await.unwrap();
    assert_eq!(bytes, b"v2");
}

#[tokio::test]
async fn delete_is_idempotent_and_makes_get_report_missing() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("k", b"v".to_vec(), None).await.unwrap();
    assert_eq!(b.delete("k").await.unwrap().confirmed, 1);
    assert_eq!(b.delete("k").await.unwrap().confirmed, 1);
    let (bytes, etag) = b.get("k").await.unwrap();
    assert!(bytes.is_empty());
    assert!(etag.is_none());
}

#[tokio::test]
async fn delete_many_removes_every_key_in_one_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("a", b"1".to_vec(), None).await.unwrap();
    b.put_cas("b", b"2".to_vec(), None).await.unwrap();
    b.put_cas("c", b"3".to_vec(), None).await.unwrap();
    let outcome = b.delete_many(&["a".to_string(), "b".to_string()]).await.unwrap();
    assert_eq!(
        outcome,
        DeleteOutcome {
            attempted: 2,
            confirmed: 2,
        }
    );
    assert!(b.get("a").await.unwrap().1.is_none());
    assert!(b.get("b").await.unwrap().1.is_none());
    assert_eq!(b.get("c").await.unwrap().0, b"3");
}

#[tokio::test]
async fn delete_many_of_an_empty_slice_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let outcome = backend(dir.path()).delete_many(&[]).await.unwrap();
    assert_eq!(outcome, DeleteOutcome::default());
}

#[tokio::test]
async fn list_prefix_returns_only_matching_keys_ordered() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    for key in ["ab1", "abz", "ac", "a"] {
        b.put_cas(key, key.as_bytes().to_vec(), None).await.unwrap();
    }
    let found = b.list_prefix("ab").await.unwrap();
    // redb's range scan returns keys in sorted order already -- no sort()
    // needed here, unlike the files backend's directory walk.
    assert_eq!(found, vec![("ab1".to_string(), 3), ("abz".to_string(), 3)]);
}

#[tokio::test]
async fn list_prefix_matches_a_key_equal_to_the_prefix_itself() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    b.put_cas("ab", b"x".to_vec(), None).await.unwrap();
    b.put_cas("abc", b"yy".to_vec(), None).await.unwrap();
    let mut found = b.list_prefix("ab").await.unwrap();
    found.sort();
    assert_eq!(found, vec![("ab".to_string(), 1), ("abc".to_string(), 2)]);
}

/// A second `RedbBackend` pointed at the same directory sees what the first
/// one wrote -- pins down that `Database::create` opens an existing file
/// rather than truncating it, which is the whole point of persisting to
/// disk instead of keeping the table in memory.
#[tokio::test]
async fn a_new_backend_instance_over_the_same_directory_sees_prior_writes() {
    let dir = tempfile::tempdir().unwrap();
    backend(dir.path()).put_cas("k", b"v1".to_vec(), None).await.unwrap();
    let reopened = backend(dir.path());
    let (bytes, etag) = reopened.get("k").await.unwrap();
    assert_eq!(bytes, b"v1");
    assert!(etag.is_some());
}

#[cfg(feature = "streaming")]
#[tokio::test]
async fn put_stream_then_get_stream_roundtrips_and_bumps_the_version() {
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
}

#[cfg(feature = "streaming")]
#[tokio::test]
async fn get_stream_errors_on_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let dest_dir = tempfile::tempdir().unwrap();
    let dest = dest_dir.path().join("dest");
    assert!(backend(dir.path()).get_stream("nope", &dest).await.is_err());
}
