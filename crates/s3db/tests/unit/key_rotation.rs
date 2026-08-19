use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

fn backend(root: &std::path::Path) -> LocalBackend {
    LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    })
}

#[tokio::test]
async fn fresh_bucket_bootstraps_a_single_active_key() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let ring = get_or_create_keyring(&b, "correct horse", &HashMap::new())
        .await
        .unwrap();
    let sealed = ring.active().seal("k", b"hello", CompressionStrategy::None).unwrap();
    assert_eq!(ring.open("k", &sealed).unwrap(), b"hello");
}

#[tokio::test]
async fn wrong_active_passphrase_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    get_or_create_keyring(&b, "correct horse", &HashMap::new())
        .await
        .unwrap();
    let err = get_or_create_keyring(&b, "wrong horse", &HashMap::new())
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("doesn't match"));
}

#[tokio::test]
async fn rotate_keeps_old_objects_readable_via_dual_read() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let mut ring = get_or_create_keyring(&b, "first passphrase", &HashMap::new())
        .await
        .unwrap();
    let old_key_id = ring.active_key_id().to_string();
    let sealed_under_old = ring
        .active()
        .seal("k", b"old value", CompressionStrategy::None)
        .unwrap();

    let new_key_id = rotate(&b, &mut ring, "second passphrase").await.unwrap();
    assert_ne!(new_key_id, old_key_id);
    assert_eq!(ring.active_key_id(), new_key_id);

    // Old ciphertext still opens (dual-read), new writes use the new key.
    assert_eq!(ring.open("k", &sealed_under_old).unwrap(), b"old value");
    let sealed_under_new = ring
        .active()
        .seal("k2", b"new value", CompressionStrategy::None)
        .unwrap();
    assert_eq!(ring.open("k2", &sealed_under_new).unwrap(), b"new value");
}

#[tokio::test]
async fn restart_after_rotate_needs_the_retired_passphrase_too() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let mut ring = get_or_create_keyring(&b, "first passphrase", &HashMap::new())
        .await
        .unwrap();
    let old_key_id = ring.active_key_id().to_string();
    rotate(&b, &mut ring, "second passphrase").await.unwrap();

    // Simulates a process restart: only the current passphrase is
    // supplied, the retired one is "forgotten" by the caller.
    let err = get_or_create_keyring(&b, "second passphrase", &HashMap::new())
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains(&old_key_id));

    // Supplying it makes bootstrap succeed again.
    let retired = HashMap::from([(old_key_id, "first passphrase".to_string())]);
    assert!(get_or_create_keyring(&b, "second passphrase", &retired).await.is_ok());
}

#[tokio::test]
async fn forget_retired_drops_it_from_memory_only() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let mut ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();
    let old_key_id = ring.active_key_id().to_string();
    let sealed_under_old = ring.active().seal("k", b"v", CompressionStrategy::None).unwrap();
    rotate(&b, &mut ring, "second").await.unwrap();
    assert!(ring.open("k", &sealed_under_old).is_ok());

    ring.forget_retired(&old_key_id);
    assert!(
        ring.open("k", &sealed_under_old).is_err(),
        "forgotten key must no longer be tried"
    );
}

#[tokio::test]
async fn forget_key_removes_a_retired_key_from_disk() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let mut ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();
    let old_key_id = ring.active_key_id().to_string();
    rotate(&b, &mut ring, "second").await.unwrap();

    forget_key(&b, &old_key_id).await.unwrap();

    let (config, _) = get_json_plain::<EncryptionConfig>(&b, ENCRYPTION_CONFIG_KEY)
        .await
        .unwrap();
    assert!(config.keys.iter().all(|k| k.key_id != old_key_id));
}

#[tokio::test]
async fn forget_key_refuses_to_remove_the_active_key() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();
    assert!(forget_key(&b, ring.active_key_id()).await.is_err());
}
