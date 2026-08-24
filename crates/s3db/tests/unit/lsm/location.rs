use super::*;
use crate::lsm::Table;

fn test_backend(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(crate::local::test_support::files_backend(root))
}

fn test_cipher() -> Cipher {
    Cipher::derive("test passphrase", &[3u8; crate::cipher::SALT_LEN]).unwrap()
}

#[test]
fn new_defaults_to_the_default_backend_id() {
    let location = TableLocation::new("audit_log");
    assert_eq!(location.backend_id, DEFAULT_BACKEND_ID);
    assert_eq!(location.root, "audit_log");
}

#[test]
fn with_backend_id_overrides_the_default() {
    let location = TableLocation::new("audit_log").with_backend_id("cold_storage");
    assert_eq!(location.backend_id, "cold_storage");
}

#[test]
fn resolve_of_an_unregistered_backend_id_is_an_error() {
    let registry = BackendRegistry::new();
    let err = registry.resolve(&TableLocation::new("audit_log")).unwrap_err();
    assert!(err.to_string().contains("primary"), "got: {err}");
}

#[tokio::test]
async fn resolve_finds_a_backend_registered_under_the_locations_id() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let mut registry = BackendRegistry::new();
    registry.register(DEFAULT_BACKEND_ID, backend.clone());

    let resolved = registry.resolve(&TableLocation::new("audit_log")).unwrap();
    // Same underlying backend -- a fresh write through the resolved handle
    // must be visible through the original one.
    resolved.put_cas("k", b"v".to_vec(), None).await.unwrap();
    assert_eq!(backend.get("k").await.unwrap().0, b"v");
}

/// Two locations sharing one `root` string but different `backend_id`s
/// must land in genuinely separate backends -- routing at the manifest
/// level only works if this holds.
#[tokio::test]
async fn two_locations_with_the_same_root_on_different_backends_never_collide() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let mut registry = BackendRegistry::new();
    registry.register("backend_a", test_backend(dir_a.path()));
    registry.register("backend_b", test_backend(dir_b.path()));

    let table_a = Table::open(
        registry
            .table_config(
                &TableLocation::new("shared_root").with_backend_id("backend_a"),
                test_cipher(),
                dir_a.path().join("a.wal"),
            )
            .unwrap(),
    )
    .await
    .unwrap();
    let table_b = Table::open(
        registry
            .table_config(
                &TableLocation::new("shared_root").with_backend_id("backend_b"),
                test_cipher(),
                dir_b.path().join("b.wal"),
            )
            .unwrap(),
    )
    .await
    .unwrap();

    table_a.put(b"k".to_vec(), b"from a".to_vec()).await.unwrap();
    table_b.put(b"k".to_vec(), b"from b".to_vec()).await.unwrap();

    assert_eq!(table_a.get(b"k").await.unwrap(), Some(b"from a".to_vec()));
    assert_eq!(table_b.get(b"k").await.unwrap(), Some(b"from b".to_vec()));
}

#[tokio::test]
async fn table_config_is_usable_to_open_and_round_trip_a_table() {
    let dir = tempfile::tempdir().unwrap();
    let mut registry = BackendRegistry::new();
    registry.register(DEFAULT_BACKEND_ID, test_backend(dir.path()));

    let config = registry
        .table_config(
            &TableLocation::new("audit_log"),
            test_cipher(),
            dir.path().join("t.wal"),
        )
        .unwrap();
    let table = Table::open(config).await.unwrap();
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    assert_eq!(table.get(b"a").await.unwrap(), Some(b"1".to_vec()));
}
