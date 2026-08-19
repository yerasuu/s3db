use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;
use std::sync::Arc;

fn test_backend(root: &std::path::Path) -> Arc<dyn crate::backend::Backend> {
    Arc::new(LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    }))
}

fn test_cipher() -> Cipher {
    Cipher::derive("test passphrase", &[31u8; crate::cipher::SALT_LEN]).unwrap()
}

const TTL: Duration = Duration::from_secs(30);

#[tokio::test]
async fn the_first_writer_gets_the_lease_and_the_second_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());

    let first = WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-a", TTL)
        .await
        .unwrap();
    assert_eq!(first.holder_id(), "writer-a");
    assert!(first.looks_valid());

    let err = WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-b", TTL)
        .await
        .unwrap_err();

    assert!(err.to_string().contains("writer-a"), "{err}");
    assert!(err.to_string().contains("one writer"), "{err}");
}

#[tokio::test]
async fn the_holder_can_reacquire_its_own_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-a", TTL)
        .await
        .unwrap();

    // A restart after a shutdown that didn't release shouldn't have to wait out
    // its own TTL.
    let again = WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-a", TTL).await;

    assert!(again.is_ok(), "{:?}", again.err());
}

#[tokio::test]
async fn an_expired_lease_can_be_taken_over() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    // A lease whose holder stopped renewing long ago -- the crashed-writer case,
    // which is the only way a table ever becomes writable again.
    let stale = LeaseRecord {
        holder_id: "dead-writer".into(),
        acquired_at_ms: 1,
        renewed_at_ms: 1,
        ttl_ms: 10,
    };
    crate::payload::put_json(backend.as_ref(), "rows/WRITER-LEASE.json", &stale, None, &cipher)
        .await
        .unwrap();

    let taken = WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-b", TTL)
        .await
        .unwrap();

    assert_eq!(taken.holder_id(), "writer-b");
    assert_eq!(
        WriterLease::current(backend.as_ref(), &cipher, "rows")
            .await
            .unwrap()
            .unwrap()
            .holder_id,
        "writer-b"
    );
}

/// Renewal is how a writer whose lease was taken over finds out — the signal to
/// stop writing.
#[tokio::test]
async fn renewing_a_lease_that_was_taken_over_fails() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    let mut first = WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-a", TTL)
        .await
        .unwrap();
    assert!(
        first.renew(backend.as_ref(), &cipher).await.is_ok(),
        "its own renewal works"
    );

    // Someone else overwrites the lease record (what a takeover looks like).
    let (_record, etag) = crate::payload::get_json::<LeaseRecord>(backend.as_ref(), "rows/WRITER-LEASE.json", &cipher)
        .await
        .unwrap();
    crate::payload::put_json(
        backend.as_ref(),
        "rows/WRITER-LEASE.json",
        &LeaseRecord {
            holder_id: "writer-b".into(),
            acquired_at_ms: 2,
            renewed_at_ms: 2,
            ttl_ms: 30_000,
        },
        etag.as_deref(),
        &cipher,
    )
    .await
    .unwrap();

    let err = first.renew(backend.as_ref(), &cipher).await.unwrap_err();
    assert!(err.to_string().contains("lease lost"), "{err}");
    assert!(err.to_string().contains("writer-b"), "{err}");
}

#[tokio::test]
async fn releasing_hands_the_table_to_the_next_writer() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    let first = WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-a", TTL)
        .await
        .unwrap();

    first.release(backend.as_ref(), &cipher).await;

    assert_eq!(
        WriterLease::current(backend.as_ref(), &cipher, "rows").await.unwrap(),
        None
    );
    assert!(
        WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-b", TTL)
            .await
            .is_ok(),
        "a released lease must not make the next writer wait out the TTL"
    );
}

/// Releasing a lease that is no longer ours would hand the table to a third
/// process while its current holder is mid-write.
#[tokio::test]
async fn releasing_a_lease_someone_else_now_holds_does_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    let first = WriterLease::acquire(backend.as_ref(), &cipher, "rows", "writer-a", TTL)
        .await
        .unwrap();
    let (_record, etag) = crate::payload::get_json::<LeaseRecord>(backend.as_ref(), "rows/WRITER-LEASE.json", &cipher)
        .await
        .unwrap();
    crate::payload::put_json(
        backend.as_ref(),
        "rows/WRITER-LEASE.json",
        &LeaseRecord {
            holder_id: "writer-b".into(),
            acquired_at_ms: 2,
            renewed_at_ms: crate::lsm::lease::now_ms(),
            ttl_ms: 30_000,
        },
        etag.as_deref(),
        &cipher,
    )
    .await
    .unwrap();

    first.release(backend.as_ref(), &cipher).await;

    assert_eq!(
        WriterLease::current(backend.as_ref(), &cipher, "rows")
            .await
            .unwrap()
            .map(|record| record.holder_id),
        Some("writer-b".to_string()),
        "writer-b's lease must survive writer-a's release"
    );
}

#[tokio::test]
async fn expiry_is_measured_from_the_last_renewal() {
    let record = LeaseRecord {
        holder_id: "a".into(),
        acquired_at_ms: 0,
        renewed_at_ms: 1_000,
        ttl_ms: 100,
    };
    assert!(!record.is_expired(1_050));
    assert!(!record.is_expired(1_100), "the boundary itself is still valid");
    assert!(record.is_expired(1_101));
}

/// Only one of a crowd of contenders may end up holding the lease.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_acquisitions_produce_exactly_one_holder() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), Arc::new(test_cipher()));

    let mut set = tokio::task::JoinSet::new();
    for n in 0..6u32 {
        let backend = Arc::clone(&backend);
        let cipher = Arc::clone(&cipher);
        set.spawn(async move { WriterLease::acquire(backend.as_ref(), &cipher, "rows", &format!("w{n}"), TTL).await });
    }
    let mut acquired = Vec::new();
    while let Some(joined) = set.join_next().await {
        if let Ok(lease) = joined.unwrap() {
            acquired.push(lease.holder_id().to_string());
        }
    }

    assert_eq!(acquired.len(), 1, "acquired by {acquired:?}");
    assert_eq!(
        WriterLease::current(backend.as_ref(), &cipher, "rows")
            .await
            .unwrap()
            .unwrap()
            .holder_id,
        acquired[0]
    );
}
