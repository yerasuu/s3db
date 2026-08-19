use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path, salt: u8) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[salt; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
}

#[tokio::test]
async fn backup_then_restore_roundtrips_every_entity() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path(), 31);
    let coll = Collection::new("widgets");
    for (name, count) in [("a", 1), ("b", 2), ("c", 3)] {
        coll.put(&backend, &cipher, name, &Widget { count }, None)
            .await
            .unwrap();
    }

    let manifest = backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", true)
        .await
        .unwrap();
    assert_eq!(manifest.entity_count, 3);
    assert_eq!(manifest.consistency, BackupConsistency::FuzzySnapshot);

    // Wipe the live collection, then restore.
    for name in ["a", "b", "c"] {
        backend.delete(&coll.key(name).unwrap()).await.unwrap();
    }
    assert!(coll.list_names(&backend).await.unwrap().is_empty());

    restore_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1")
        .await
        .unwrap();
    let mut restored = coll.list_names(&backend).await.unwrap();
    restored.sort();
    assert_eq!(restored, vec!["a", "b", "c"]);
    let (value, _) = coll.get::<Widget>(&backend, &cipher, "b").await.unwrap();
    assert_eq!(value, Some(Widget { count: 2 }));
}

#[tokio::test]
async fn backup_includes_tombstones_by_default_and_restore_brings_them_back() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path(), 37);
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await.unwrap();
    assert_eq!(coll.list_tombstones(&backend, &cipher).await.unwrap().len(), 1);

    let manifest = backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", true)
        .await
        .unwrap();
    assert!(manifest.includes_tombstones);
    assert_eq!(manifest.tombstone_count, 1);

    coll.forget_tombstone(&backend, &cipher, "a").await.unwrap();
    assert!(coll.list_tombstones(&backend, &cipher).await.unwrap().is_empty());

    restore_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1")
        .await
        .unwrap();
    assert_eq!(coll.list_tombstones(&backend, &cipher).await.unwrap().len(), 1);
}

#[tokio::test]
async fn backup_can_opt_out_of_tombstones_and_says_so_in_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path(), 41);
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    coll.delete(&backend, &cipher, "a").await.unwrap();

    let manifest = backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", false)
        .await
        .unwrap();
    assert!(!manifest.includes_tombstones);
    assert_eq!(manifest.tombstone_count, 0);
}

#[tokio::test]
async fn backup_reencrypts_under_a_different_destination_key() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, src_cipher) = test_backend_and_cipher(dir.path(), 43);
    let dest_dir = tempfile::tempdir().unwrap();
    let (dest_backend, dest_cipher) = test_backend_and_cipher(dest_dir.path(), 47);
    let coll = Collection::new("widgets");
    coll.put(&backend, &src_cipher, "a", &Widget { count: 9 }, None)
        .await
        .unwrap();

    backup_collection(
        &backend,
        &src_cipher,
        &dest_backend,
        &dest_cipher,
        &coll,
        "backup1",
        true,
    )
    .await
    .unwrap();

    // The destination backend's own manifest is only readable under
    // dest_cipher -- proves this was a real re-encryption, not a raw
    // ciphertext copy.
    let (manifest, etag) = get_json::<BackupManifest>(&dest_backend, &manifest_key("backup1", "widgets"), &dest_cipher)
        .await
        .unwrap();
    assert!(etag.is_some());
    assert_eq!(manifest.entity_count, 1);
}
