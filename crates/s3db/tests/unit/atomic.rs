use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::index::{SecondaryIndex, Segment};
use crate::local::LocalBackend;

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
