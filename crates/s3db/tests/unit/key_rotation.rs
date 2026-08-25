use super::*;
use crate::local::LocalBackend;

fn backend(root: &std::path::Path) -> LocalBackend {
    crate::local::test_support::files_backend(root)
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

    forget_key(&b, &ring, &old_key_id).await.unwrap();

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
    assert!(forget_key(&b, &ring, ring.active_key_id()).await.is_err());
}

#[tokio::test]
async fn scan_key_usage_counts_down_as_objects_get_re_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let mut ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();
    let old_key_id = ring.active_key_id().to_string();

    for name in ["widgets/a.json", "widgets/b.json"] {
        let sealed = ring.active().seal(name, b"v", CompressionStrategy::None).unwrap();
        b.put_cas(name, sealed, None).await.unwrap();
    }
    rotate(&b, &mut ring, "second").await.unwrap();

    let report = scan_key_usage(&b, &ring, &old_key_id, "widgets/").await.unwrap();
    assert_eq!(
        report,
        KeyUsageReport {
            checked: 2,
            still_encrypted_under_this_key: 2,
        },
        "both objects were sealed under the now-retired key"
    );

    // Re-encrypt one object under the new active key.
    let (sealed, etag) = b.get("widgets/a.json").await.unwrap();
    let plain = ring.open("widgets/a.json", &sealed).unwrap();
    let resealed = ring
        .active()
        .seal("widgets/a.json", &plain, CompressionStrategy::None)
        .unwrap();
    b.put_cas("widgets/a.json", resealed, etag.as_deref()).await.unwrap();

    let report = scan_key_usage(&b, &ring, &old_key_id, "widgets/").await.unwrap();
    assert_eq!(
        report,
        KeyUsageReport {
            checked: 2,
            still_encrypted_under_this_key: 1,
        },
        "only the re-encrypted object should drop out of the count"
    );
}

#[tokio::test]
async fn scan_key_usage_refuses_an_unknown_key_id() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();

    let err = scan_key_usage(&b, &ring, "not-a-real-key-id", "widgets/")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not-a-real-key-id"), "{err}");
}

/// `EncryptionConfig` decides which key is active and which keys exist at
/// all, so anything able to write to the bucket repointing `active_key_id`
/// or trimming `keys` has to be caught before any of it is acted on.
#[tokio::test]
async fn a_tampered_config_is_refused_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let mut ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();
    let first_key_id = ring.active_key_id().to_string();
    rotate(&b, &mut ring, "second").await.unwrap();
    let second_key_id = ring.active_key_id().to_string();
    let retired = HashMap::from([(first_key_id.clone(), "first".to_string())]);

    // Untampered, this reopens fine.
    assert!(get_or_create_keyring(&b, "second", &retired).await.is_ok());

    let (mut config, etag) = get_json_plain::<EncryptionConfig>(&b, ENCRYPTION_CONFIG_KEY)
        .await
        .unwrap();
    // Repoint `active_key_id` back at the retired key.
    config.active_key_id = first_key_id;
    put_json_plain(&b, ENCRYPTION_CONFIG_KEY, &config, etag.as_deref())
        .await
        .unwrap();

    let err = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap_err();
    assert!(format!("{err:#}").contains("doesn't match the passphrase"), "{err:#}");
    assert_ne!(second_key_id, config.active_key_id);
}

/// Dropping a key from `keys` has to fail the tag too -- otherwise a
/// retired key could be silently removed from a bucket that still has
/// objects sealed under it.
#[tokio::test]
async fn removing_a_key_from_the_config_is_refused_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let mut ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();
    let first_key_id = ring.active_key_id().to_string();
    rotate(&b, &mut ring, "second").await.unwrap();
    let retired = HashMap::from([(first_key_id.clone(), "first".to_string())]);

    let (mut config, etag) = get_json_plain::<EncryptionConfig>(&b, ENCRYPTION_CONFIG_KEY)
        .await
        .unwrap();
    config.keys.retain(|k| k.key_id != first_key_id);
    put_json_plain(&b, ENCRYPTION_CONFIG_KEY, &config, etag.as_deref())
        .await
        .unwrap();

    assert!(get_or_create_keyring(&b, "second", &retired).await.is_err());
}

/// Each key generation gets its own random data key, so a rotation really
/// does change what new writes are sealed under.
#[tokio::test]
async fn each_key_generation_has_its_own_data_key() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let mut ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();
    let sealed_under_first = ring.active().seal("k", b"content", CompressionStrategy::None).unwrap();
    rotate(&b, &mut ring, "second").await.unwrap();
    assert!(ring.active().open("k", &sealed_under_first).is_err());
    // Still readable through the ring's dual-read, though.
    assert_eq!(ring.open("k", &sealed_under_first).unwrap(), b"content");
}

/// The deleted-config attack against the keyring path, same as
/// `bootstrap`'s.
#[tokio::test]
async fn deleting_the_config_of_a_populated_bucket_refuses_to_re_key() {
    let dir = tempfile::tempdir().unwrap();
    let b = backend(dir.path());
    let ring = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap();
    let sealed = ring
        .active()
        .seal("users/alice.json", b"secret", CompressionStrategy::None)
        .unwrap();
    b.put_cas("users/alice.json", sealed, None).await.unwrap();
    b.delete(ENCRYPTION_CONFIG_KEY).await.unwrap();

    let err = get_or_create_keyring(&b, "first", &HashMap::new()).await.unwrap_err();
    assert!(format!("{err:#}").contains("refusing to initialize"), "{err:#}");
}
