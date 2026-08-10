use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[17u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[tokio::test]
async fn a_successful_write_leaves_no_wal_entry_behind() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
    let cas = put_cas_with_wal(&backend, &cipher, "k", sealed, None).await.unwrap();
    assert_eq!(cas, Cas::Ok);
    assert!(
        list_all_keys(&backend, &format!("{WAL_PREFIX}/"))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_genuine_conflict_still_clears_the_wal_entry() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    backend.put_cas("k", b"already there".to_vec(), None).await.unwrap();

    let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
    let cas = put_cas_with_wal(&backend, &cipher, "k", sealed, None).await.unwrap();
    assert_eq!(cas, Cas::Conflict);
    assert!(
        list_all_keys(&backend, &format!("{WAL_PREFIX}/"))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn recover_stale_clears_an_entry_whose_write_actually_landed() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
    // Simulates a crash right after put_cas landed but before `complete`
    // ran: write the WAL entry, do the real write, but never clear it.
    let op_id = begin(&backend, &cipher, "k", &sealed).await.unwrap();
    backend.put_cas("k", sealed, None).await.unwrap();
    // Millisecond-resolution timestamps: make sure the WAL entry's own
    // started_at_ms is strictly in the past relative to recover_stale's
    // "now", rather than racing to land in the same millisecond (which
    // a zero-width max_age would then treat as "still fresh").
    tokio::time::sleep(Duration::from_millis(5)).await;

    let resolved = recover_stale(&backend, &cipher, Duration::ZERO).await.unwrap();
    assert_eq!(resolved, 1);
    assert!(
        list_all_keys(&backend, &format!("{WAL_PREFIX}/"))
            .await
            .unwrap()
            .is_empty()
    );
    let _ = op_id;
}

#[tokio::test]
async fn recover_stale_clears_an_entry_whose_write_never_landed_without_touching_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
    // Simulates a crash before the real put_cas ever ran.
    begin(&backend, &cipher, "k", &sealed).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;

    let resolved = recover_stale(&backend, &cipher, Duration::ZERO).await.unwrap();
    assert_eq!(resolved, 1);
    let (_, etag) = backend.get("k").await.unwrap();
    assert!(etag.is_none(), "recover_stale must never write the key itself");
}

#[tokio::test]
async fn recover_stale_leaves_a_fresh_entry_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let sealed = cipher.seal("k", b"value", crate::cipher::CompressionStrategy::None);
    begin(&backend, &cipher, "k", &sealed).await.unwrap();

    let resolved = recover_stale(&backend, &cipher, Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(resolved, 0);
    assert_eq!(
        list_all_keys(&backend, &format!("{WAL_PREFIX}/")).await.unwrap().len(),
        1
    );
}
