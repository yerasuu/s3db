use super::*;
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path, salt: u8) -> (LocalBackend, Cipher) {
    let backend = crate::local::test_support::files_backend(root);
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
    let (manifest, etag) = get_json::<BackupManifest>(
        &dest_backend,
        &manifest_key("backup1", "widgets").unwrap(),
        &dest_cipher,
    )
    .await
    .unwrap();
    assert!(etag.is_some());
    assert_eq!(manifest.entity_count, 1);
}

#[tokio::test]
async fn restore_cleans_up_its_progress_marker_once_complete() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path(), 51);
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", true)
        .await
        .unwrap();
    backend.delete(&coll.key("a").unwrap()).await.unwrap();

    restore_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1")
        .await
        .unwrap();

    let (_, etag) = get_json::<RestoreProgress>(&backend, &restore_progress_key(&coll), &cipher)
        .await
        .unwrap();
    assert!(
        etag.is_none(),
        "a completed, verified restore must not leave its progress marker behind"
    );
}

/// The core resumability guarantee: a checkpoint left by an interrupted run
/// makes the next call skip exactly what it already covered, not redo it
/// and not skip past what still needs restoring.
#[tokio::test]
async fn restore_resumes_from_a_checkpoint_instead_of_redoing_completed_work() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path(), 53);
    let coll = Collection::new("widgets");
    for (name, count) in [("a", 1), ("b", 2)] {
        coll.put(&backend, &cipher, name, &Widget { count }, None)
            .await
            .unwrap();
    }
    backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", true)
        .await
        .unwrap();
    for name in ["a", "b"] {
        backend.delete(&coll.key(name).unwrap()).await.unwrap();
    }

    // Simulate a crash right after "a" was restored: a checkpoint whose
    // cursor already points past it, plus a sentinel value at "a" that a
    // real restore of "a" would have overwritten -- if resume actually
    // skips it as already done, the sentinel survives.
    coll.put(&backend, &cipher, "a", &Widget { count: 999 }, None)
        .await
        .unwrap();
    let progress = RestoreProgress {
        backup_id: "backup1".to_string(),
        started_at_ms: now_ms(),
        phase: RestorePhase::Entities,
        last_name: Some("a".to_string()),
        last_key: None,
        entities_restored: 1,
        tombstones_restored: 0,
    };
    put_json(&backend, &restore_progress_key(&coll), &progress, None, &cipher)
        .await
        .unwrap();

    restore_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1")
        .await
        .unwrap();

    let (a, _) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
    assert_eq!(
        a,
        Some(Widget { count: 999 }),
        "resume must skip an entity the checkpoint already covered"
    );
    let (b, _) = coll.get::<Widget>(&backend, &cipher, "b").await.unwrap();
    assert_eq!(
        b,
        Some(Widget { count: 2 }),
        "resume must still restore what came after the checkpoint"
    );
}

#[tokio::test]
async fn restore_refuses_a_different_backup_id_while_one_is_in_progress() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path(), 57);
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", true)
        .await
        .unwrap();
    backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup2", true)
        .await
        .unwrap();

    let progress = RestoreProgress {
        backup_id: "backup1".to_string(),
        started_at_ms: now_ms(),
        ..RestoreProgress::default()
    };
    put_json(&backend, &restore_progress_key(&coll), &progress, None, &cipher)
        .await
        .unwrap();

    let err = restore_collection(&backend, &cipher, &backend, &cipher, &coll, "backup2")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("backup1"), "{err}");
}

/// A backup's own promise -- its manifest's counts -- must actually be
/// checked against what restore found, not assumed true because the
/// listing eventually ran out.
#[tokio::test]
async fn restore_refuses_to_complete_if_the_backup_is_missing_something_its_manifest_promised() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path(), 61);
    let coll = Collection::new("widgets");
    for (name, count) in [("a", 1), ("b", 2)] {
        coll.put(&backend, &cipher, name, &Widget { count }, None)
            .await
            .unwrap();
    }
    backup_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1", true)
        .await
        .unwrap();

    // Corrupt the backup itself: delete one of the two backed-up objects
    // out from under its own manifest.
    let prefix = backup_prefix("backup1", "widgets").unwrap();
    backend.delete(&format!("{prefix}/b.json")).await.unwrap();

    let err = restore_collection(&backend, &cipher, &backend, &cipher, &coll, "backup1")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("manifest accounts for"), "{err}");
}

#[tokio::test]
async fn a_backup_id_that_would_escape_its_namespace_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path(), 47);
    let coll = Collection::new("widgets");

    // Without the check these don't produce an odd-looking backup: they
    // write under `.conf/` and into live data's own namespace.
    for bad in ["../repos", "a/b", ".hidden", "", "with\nnewline"] {
        let err = backup_collection(&backend, &cipher, &backend, &cipher, &coll, bad, true)
            .await
            .expect_err("a backup id that escapes its namespace should be refused");
        assert!(
            err.to_string().contains("backup id"),
            "unexpected error for {bad:?}: {err}"
        );
    }
}
