use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::index::{SecondaryIndex, Segment};
use crate::local::LocalBackend;
use std::sync::Arc;

fn backend_and_cipher(root: &std::path::Path, engine: LocalEngine) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine,
    });
    let cipher = Cipher::derive("test passphrase", &[9u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    owner: String,
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Pointer {
    name: String,
}

fn widgets() -> Collection {
    Collection::new("widgets")
}

fn by_owner() -> SecondaryIndex {
    SecondaryIndex::new(".conf/index", "widget-owner", Segment::Raw)
}

#[tokio::test]
async fn put_with_index_creates_both_the_row_and_the_pointer() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Redb);
    let (row, index) = (widgets(), by_owner());

    let outcome = put_with_index(
        &backend,
        &cipher,
        &row,
        "gadget",
        &Widget { owner: "alice".into() },
        None,
        &index,
        "alice",
        &Pointer { name: "gadget".into() },
        None,
    )
    .await
    .unwrap();
    assert_eq!(outcome, BatchOutcome::Applied);

    let (value, etag) = row.get::<Widget>(&backend, &cipher, "gadget").await.unwrap();
    assert_eq!(value, Some(Widget { owner: "alice".into() }));
    assert!(etag.is_some());

    let (pointer, etag) = index.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(pointer, Some(Pointer { name: "gadget".into() }));
    assert!(etag.is_some());
}

/// The whole point of this function: a reader must never see the row
/// without its pointer, or the pointer without its row.
#[tokio::test]
async fn a_conflict_on_either_side_leaves_neither_write_applied() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Redb);
    let (row, index) = (widgets(), by_owner());

    // Pre-claim the index pointer only -- the row doesn't exist yet.
    index
        .claim_once(
            &backend,
            &cipher,
            "alice",
            &Pointer {
                name: "existing".into(),
            },
        )
        .await
        .unwrap();

    let outcome = put_with_index(
        &backend,
        &cipher,
        &row,
        "gadget",
        &Widget { owner: "alice".into() },
        None, // row condition would hold on its own
        &index,
        "alice",
        &Pointer { name: "gadget".into() },
        None, // index condition fails: "alice" already claimed
    )
    .await
    .unwrap();
    assert_eq!(outcome, BatchOutcome::Conflict);

    let (value, _) = row.get::<Widget>(&backend, &cipher, "gadget").await.unwrap();
    assert_eq!(
        value, None,
        "the row must not have been created once the index write conflicted"
    );
    let (pointer, _) = index.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(
        pointer,
        Some(Pointer {
            name: "existing".into()
        }),
        "the pre-existing pointer must be untouched"
    );
}

#[tokio::test]
async fn put_with_index_supports_updating_both_together() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Redb);
    let (row, index) = (widgets(), by_owner());

    put_with_index(
        &backend,
        &cipher,
        &row,
        "gadget",
        &Widget { owner: "alice".into() },
        None,
        &index,
        "alice",
        &Pointer { name: "gadget".into() },
        None,
    )
    .await
    .unwrap();
    let (_, row_etag) = row.get::<Widget>(&backend, &cipher, "gadget").await.unwrap();
    let (_, index_etag) = index.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();

    let outcome = put_with_index(
        &backend,
        &cipher,
        &row,
        "gadget",
        &Widget {
            owner: "alice-renamed".into(),
        },
        row_etag.as_deref(),
        &index,
        "alice",
        &Pointer {
            name: "gadget-renamed".into(),
        },
        index_etag.as_deref(),
    )
    .await
    .unwrap();
    assert_eq!(outcome, BatchOutcome::Applied);

    let (value, _) = row.get::<Widget>(&backend, &cipher, "gadget").await.unwrap();
    assert_eq!(
        value,
        Some(Widget {
            owner: "alice-renamed".into()
        })
    );
    let (pointer, _) = index.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(
        pointer,
        Some(Pointer {
            name: "gadget-renamed".into()
        })
    );
}

#[tokio::test]
async fn put_with_index_on_files_reports_no_native_capability() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    let (row, index) = (widgets(), by_owner());

    let err = put_with_index(
        &backend,
        &cipher,
        &row,
        "gadget",
        &Widget { owner: "alice".into() },
        None,
        &index,
        "alice",
        &Pointer { name: "gadget".into() },
        None,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("native transaction capability"), "got: {err}");
}

/// Capability discovery used to be a downcast that could only see the type at
/// the top of the chain, so a driver behind the resilience stack silently lost
/// its transaction. This is the regression test for that.
#[tokio::test]
async fn the_transaction_survives_the_whole_resilience_stack() {
    let dir = tempfile::tempdir().unwrap();
    let raw: Arc<dyn Backend> = Arc::new(crate::local::LocalBackend::new(&crate::config::LocalParams {
        bucket: dir.path().to_string_lossy().to_string(),
        engine: crate::config::LocalEngine::Redb,
    }));
    let stacked = crate::resilience::build_resilient_backend(
        raw,
        crate::resilience::ResilienceConfig::default(),
        Arc::new(crate::metrics::NoopMetrics),
    )
    .backend;

    let atomic = stacked
        .as_atomic()
        .expect("redb's transaction must be reachable through Metered -> Retry -> Throttled -> Cached");
    let outcome = atomic
        .commit_batch(vec![
            BatchOp::Put {
                key: "a".to_string(),
                body: b"1".to_vec(),
                expected_etag: None,
            },
            BatchOp::Put {
                key: "b".to_string(),
                body: b"2".to_vec(),
                expected_etag: None,
            },
        ])
        .await
        .unwrap();

    assert_eq!(outcome, BatchOutcome::Applied);
    assert_eq!(stacked.get("a").await.unwrap().0, b"1".to_vec());
    assert_eq!(stacked.get("b").await.unwrap().0, b"2".to_vec());
}

/// The reason the caches claim the capability instead of forwarding it: a
/// batch that bypassed them would leave stale entries for keys it changed.
#[tokio::test]
async fn a_batch_through_a_cache_invalidates_what_it_touched() {
    let dir = tempfile::tempdir().unwrap();
    let raw: Arc<dyn Backend> = Arc::new(crate::local::LocalBackend::new(&crate::config::LocalParams {
        bucket: dir.path().to_string_lossy().to_string(),
        engine: crate::config::LocalEngine::Redb,
    }));
    raw.put_cas("k", b"old".to_vec(), None).await.unwrap();
    let cached: Arc<dyn Backend> = Arc::new(crate::cache::CachedBackend::new(
        Arc::clone(&raw),
        crate::cache::CacheConfig::default(),
    ));

    // Populate the cache, then change the key through the transaction.
    assert_eq!(cached.get("k").await.unwrap().0, b"old".to_vec());
    let (_body, etag) = cached.get("k").await.unwrap();
    cached
        .as_atomic()
        .expect("a cache over an atomic driver must still offer the capability")
        .commit_batch(vec![BatchOp::Put {
            key: "k".to_string(),
            body: b"new".to_vec(),
            expected_etag: etag,
        }])
        .await
        .unwrap();

    assert_eq!(
        cached.get("k").await.unwrap().0,
        b"new".to_vec(),
        "the cache must have dropped its entry for the batched key"
    );
}

#[tokio::test]
async fn a_backend_without_the_capability_still_answers_none() {
    let dir = tempfile::tempdir().unwrap();
    let files: Arc<dyn Backend> = Arc::new(crate::local::LocalBackend::new(&crate::config::LocalParams {
        bucket: dir.path().to_string_lossy().to_string(),
        engine: crate::config::LocalEngine::Files,
    }));
    assert!(
        files.as_atomic().is_none(),
        "the files engine has no native transaction"
    );
    assert!(files.as_range().is_none());

    let stacked = crate::resilience::build_resilient_backend(
        files,
        crate::resilience::ResilienceConfig::default(),
        Arc::new(crate::metrics::NoopMetrics),
    )
    .backend;
    assert!(
        stacked.as_atomic().is_none(),
        "a decorator must not invent a capability its inner backend lacks"
    );
}
