use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

const DEFAULT_ALGORITHM: CipherAlgorithm = CipherAlgorithm::XChaCha20Poly1305;

fn temp_backend() -> (tempfile::TempDir, LocalBackend) {
    let dir = tempfile::tempdir().unwrap();
    let backend = LocalBackend::new(&LocalParams {
        bucket: dir.path().to_string_lossy().into_owned(),
        engine: LocalEngine::Files,
    });
    (dir, backend)
}

#[test]
fn wrong_passphrase_fails_verification_clearly() {
    let (meta, _) = new_meta("correct", DEFAULT_ALGORITHM).unwrap();
    assert!(open_meta("correct", DEFAULT_ALGORITHM, &meta).is_ok());
    let err = open_meta("incorrect", DEFAULT_ALGORITHM, &meta).unwrap_err();
    assert!(format!("{err:#}").contains("doesn't match"), "{err:#}");
}

#[test]
fn rejects_malformed_salt() {
    let (mut meta, _) = new_meta("pw", DEFAULT_ALGORITHM).unwrap();
    meta.salt = "not-base64!!".to_string();
    assert!(open_meta("pw", DEFAULT_ALGORITHM, &meta).is_err());
}

/// A bucket bootstrapped under one algorithm stays readable when the
/// configured algorithm changes — the verifier is opened, never re-sealed.
#[test]
fn a_verifier_sealed_by_one_algorithm_validates_under_another() {
    let (meta, _) = new_meta("pw", CipherAlgorithm::Aes256Gcm).unwrap();
    let derived = open_meta("pw", CipherAlgorithm::XChaCha20Poly1305, &meta).unwrap();
    assert_eq!(
        derived.mode(),
        EncryptionMode::Enabled {
            algorithm: CipherAlgorithm::XChaCha20Poly1305
        }
    );
}

/// The data key is random, not derived, so two buckets created with the
/// *same* passphrase must still hold different key material.
#[test]
fn the_data_key_is_independent_of_the_passphrase() {
    let (_, a) = new_meta("same passphrase", DEFAULT_ALGORITHM).unwrap();
    let (_, b) = new_meta("same passphrase", DEFAULT_ALGORITHM).unwrap();
    let sealed = a.seal("k", b"content", CompressionStrategy::None).unwrap();
    assert!(b.open("k", &sealed).is_err());
}

/// Tampering with any field has to be caught by the authentication tag,
/// before anything derived from the file is trusted.
#[test]
fn a_modified_config_fails_authentication() {
    let (meta, _) = new_meta("pw", DEFAULT_ALGORITHM).unwrap();

    let (other, _) = new_meta("pw", DEFAULT_ALGORITHM).unwrap();
    let swapped_wrapped_key = EncryptionMeta {
        wrapped_key: other.wrapped_key.clone(),
        ..meta.clone()
    };
    let swapped_verifier = EncryptionMeta {
        verifier: other.verifier.clone(),
        ..meta.clone()
    };
    let swapped_salt = EncryptionMeta {
        salt: other.salt.clone(),
        ..meta.clone()
    };
    let stripped_mac = EncryptionMeta {
        mac: String::new(),
        ..meta.clone()
    };

    for (name, tampered) in [
        ("wrapped_key", swapped_wrapped_key),
        ("verifier", swapped_verifier),
        ("salt", swapped_salt),
        ("mac", stripped_mac),
    ] {
        assert!(
            open_meta("pw", DEFAULT_ALGORITHM, &tampered).is_err(),
            "a swapped {name} should be refused"
        );
    }
}

/// A config from before data-key wrapping has to say so, rather than
/// surfacing as an inscrutable decrypt failure.
#[test]
fn a_config_without_a_wrapped_key_names_the_migration() {
    let (mut meta, _) = new_meta("pw", DEFAULT_ALGORITHM).unwrap();
    meta.wrapped_key = String::new();
    let err = open_meta("pw", DEFAULT_ALGORITHM, &meta).unwrap_err();
    assert!(format!("{err:#}").contains("no wrapped data key"), "{err:#}");
}

#[test]
fn a_config_from_a_different_kdf_parameter_set_is_refused_by_name() {
    let (mut meta, _) = new_meta("pw", DEFAULT_ALGORITHM).unwrap();
    meta.kdf_version = KDF_VERSION + 1;
    let err = open_meta("pw", DEFAULT_ALGORITHM, &meta).unwrap_err();
    assert!(format!("{err:#}").contains("KDF parameter set"), "{err:#}");
}

#[tokio::test]
async fn a_new_bucket_is_bootstrapped_with_the_configured_algorithm() {
    for algorithm in [CipherAlgorithm::XChaCha20Poly1305, CipherAlgorithm::Aes256Gcm] {
        let (_dir, backend) = temp_backend();
        let mode = EncryptionMode::Enabled { algorithm };
        let created = get_or_create_cipher_for(&backend, mode, "pw").await.unwrap();
        assert_eq!(created.mode(), mode);
        // Second call reads the salt back instead of creating a new one.
        let reopened = get_or_create_cipher_for(&backend, mode, "pw").await.unwrap();
        let sealed = created.seal("k", b"content", CompressionStrategy::None).unwrap();
        assert_eq!(reopened.open("k", &sealed).unwrap(), b"content");
    }
}

#[tokio::test]
async fn disabled_leaves_the_bucket_untouched() {
    let (_dir, backend) = temp_backend();
    let cipher = get_or_create_cipher_for(&backend, EncryptionMode::Disabled, "pw")
        .await
        .unwrap();
    assert_eq!(cipher.mode(), EncryptionMode::Disabled);
    let (_, etag) = get_json_plain::<EncryptionMeta>(&backend, ENCRYPTION_META_KEY)
        .await
        .unwrap();
    assert!(etag.is_none(), "disabled mode must not bootstrap a salt");
}

/// The guard that matters: flipping encryption off on a bucket that already
/// holds sealed objects must fail at startup, not start writing plaintext
/// next to data nothing can read anymore.
#[tokio::test]
async fn disabled_refuses_a_bucket_that_was_bootstrapped_encrypted() {
    let (_dir, backend) = temp_backend();
    get_or_create_cipher_for(&backend, EncryptionMode::default(), "pw")
        .await
        .unwrap();
    let err = get_or_create_cipher_for(&backend, EncryptionMode::Disabled, "pw")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("encryption enabled"), "got: {err}");
}

/// The deleted-config attack, end to end: with the config gone, bootstrap
/// must refuse rather than mint a new salt and leave everything already
/// sealed permanently unreadable.
#[tokio::test]
async fn deleting_the_config_of_a_populated_bucket_refuses_to_re_key() {
    let (_dir, backend) = temp_backend();
    let cipher = get_or_create_cipher(&backend, "pw").await.unwrap();
    let sealed = cipher
        .seal("users/alice.json", b"secret", CompressionStrategy::None)
        .unwrap();
    backend.put_cas("users/alice.json", sealed, None).await.unwrap();

    backend.delete(ENCRYPTION_META_KEY).await.unwrap();

    let err = get_or_create_cipher(&backend, "pw").await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("refusing to initialize"), "{msg}");
}

#[tokio::test]
async fn adopting_a_populated_bucket_works_when_asked_for_explicitly() {
    let (_dir, backend) = temp_backend();
    backend
        .put_cas("preexisting.bin", b"not ours".to_vec(), None)
        .await
        .unwrap();
    assert!(
        get_or_create_cipher_with_policy(
            &backend,
            EncryptionMode::default(),
            "pw",
            BootstrapPolicy::AllowNonEmptyBucket,
        )
        .await
        .is_ok()
    );
}

/// Tampering caught end to end, through a real backend rather than in
/// memory.
#[tokio::test]
async fn a_tampered_config_in_the_bucket_is_refused_on_reopen() {
    let (_dir, backend) = temp_backend();
    get_or_create_cipher(&backend, "pw").await.unwrap();

    let (mut meta, etag) = get_json_plain::<EncryptionMeta>(&backend, ENCRYPTION_META_KEY)
        .await
        .unwrap();
    // Whoever can write to the bucket swaps in a salt of their choosing.
    meta.salt = BASE64.encode([0xABu8; SALT_LEN]);
    put_json_plain(&backend, ENCRYPTION_META_KEY, &meta, etag.as_deref())
        .await
        .unwrap();

    let err = get_or_create_cipher(&backend, "pw").await.unwrap_err();
    assert!(format!("{err:#}").contains("doesn't match the passphrase"), "{err:#}");
}

/// The point of wrapping: a new passphrase re-seals 32 bytes, and everything
/// already in the bucket stays readable without being touched.
#[tokio::test]
async fn changing_the_passphrase_keeps_existing_objects_readable() {
    let (_dir, backend) = temp_backend();
    let before = get_or_create_cipher(&backend, "old pw").await.unwrap();
    let sealed = before
        .seal("users/alice.json", b"secret", CompressionStrategy::None)
        .unwrap();

    change_passphrase(&backend, "old pw", "new pw").await.unwrap();

    let after = get_or_create_cipher(&backend, "new pw").await.unwrap();
    assert_eq!(after.open("users/alice.json", &sealed).unwrap(), b"secret");
    // And the old passphrase stops working.
    assert!(get_or_create_cipher(&backend, "old pw").await.is_err());
}

#[tokio::test]
async fn changing_the_passphrase_needs_the_current_one() {
    let (_dir, backend) = temp_backend();
    get_or_create_cipher(&backend, "old pw").await.unwrap();
    assert!(change_passphrase(&backend, "wrong pw", "new pw").await.is_err());
    // Nothing was written: the original passphrase still opens the bucket.
    assert!(get_or_create_cipher(&backend, "old pw").await.is_ok());
}

/// `get_or_create_cipher` is right for a server; it is wrong for anything
/// pointed at a bucket by hand, where a mistyped path would silently become a
/// newly initialized bucket.
#[tokio::test]
async fn open_cipher_refuses_an_unbootstrapped_bucket_without_writing() {
    let (_dir, backend) = temp_backend();

    let err = crate::bootstrap::open_cipher(&backend, "pass").await.unwrap_err();

    assert!(err.to_string().contains("never bootstrapped"), "{err:#}");
    assert_eq!(
        crate::payload::list_all_keys(&backend, "").await.unwrap(),
        Vec::<String>::new(),
        "it must not have created the encryption config it refused to find"
    );
}

#[tokio::test]
async fn open_cipher_opens_a_bootstrapped_bucket_and_rejects_a_wrong_passphrase() {
    let (_dir, backend) = temp_backend();
    let created = crate::bootstrap::get_or_create_cipher(&backend, "right").await.unwrap();
    let sealed = created
        .seal("k", b"payload", crate::cipher::CompressionStrategy::None)
        .unwrap();

    let opened = crate::bootstrap::open_cipher(&backend, "right").await.unwrap();
    assert_eq!(opened.open("k", &sealed).unwrap(), b"payload");

    assert!(
        crate::bootstrap::open_cipher(&backend, "wrong").await.is_err(),
        "a wrong passphrase must fail here, not deeper in the app"
    );
}

/// Writes the exact `.conf/encryption.json` a pre-wrapping bucket had —
/// salt + verifier, no wrapped key, no tag — with an object sealed under
/// the key that format derived straight from the passphrase.
async fn seed_legacy_bucket(backend: &dyn Backend, passphrase: &str) -> ([u8; SALT_LEN], Cipher) {
    let salt = [3u8; SALT_LEN];
    let legacy_key = Cipher::legacy_key_v0(passphrase, &salt).unwrap();
    let data_cipher = Cipher::from_key(&legacy_key, CipherAlgorithm::default());
    let legacy = serde_json::json!({
        "salt": BASE64.encode(salt),
        "verifier": BASE64.encode(
            data_cipher
                .seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)
                .unwrap(),
        ),
    });
    backend
        .put_cas(ENCRYPTION_META_KEY, serde_json::to_vec(&legacy).unwrap(), None)
        .await
        .unwrap();
    (salt, data_cipher)
}

#[tokio::test]
async fn migrating_a_legacy_bucket_keeps_every_object_readable() {
    let (_dir, backend) = temp_backend();
    let (_salt, legacy_cipher) = seed_legacy_bucket(&backend, "hunter2").await;

    // An object sealed the way that bucket's live data was.
    let sealed = legacy_cipher
        .seal("repos/acme/thing", b"payload", CompressionStrategy::None)
        .unwrap();
    backend.put_cas("repos/acme/thing", sealed, None).await.unwrap();

    // Before: today's code refuses the bucket outright.
    assert!(open_cipher(&backend, "hunter2").await.is_err());

    assert_eq!(
        migrate_unwrapped_meta(&backend, "hunter2", CipherAlgorithm::default())
            .await
            .unwrap(),
        MigrationOutcome::Migrated
    );

    // After: it opens, and the key is the same one the old object was
    // sealed under -- which is the whole point of wrapping the legacy key
    // instead of minting a new one.
    let cipher = open_cipher(&backend, "hunter2").await.unwrap();
    let (stored, _etag) = backend.get("repos/acme/thing").await.unwrap();
    assert_eq!(cipher.open("repos/acme/thing", &stored).unwrap(), b"payload");
}

#[tokio::test]
async fn migrating_is_idempotent_and_leaves_a_wrapped_bucket_alone() {
    let (_dir, backend) = temp_backend();
    seed_legacy_bucket(&backend, "hunter2").await;

    migrate_unwrapped_meta(&backend, "hunter2", CipherAlgorithm::default())
        .await
        .unwrap();
    let (after_first, _) = get_json_plain::<EncryptionMeta>(&backend, ENCRYPTION_META_KEY)
        .await
        .unwrap();

    assert_eq!(
        migrate_unwrapped_meta(&backend, "hunter2", CipherAlgorithm::default())
            .await
            .unwrap(),
        MigrationOutcome::AlreadyWrapped
    );
    let (after_second, _) = get_json_plain::<EncryptionMeta>(&backend, ENCRYPTION_META_KEY)
        .await
        .unwrap();
    assert_eq!(after_first.wrapped_key, after_second.wrapped_key);
    assert_eq!(after_first.mac, after_second.mac);
}

#[tokio::test]
async fn a_wrong_passphrase_migrates_nothing() {
    let (_dir, backend) = temp_backend();
    seed_legacy_bucket(&backend, "hunter2").await;
    let (before, _) = get_json_plain::<EncryptionMeta>(&backend, ENCRYPTION_META_KEY)
        .await
        .unwrap();

    let err = migrate_unwrapped_meta(&backend, "not-the-passphrase", CipherAlgorithm::default())
        .await
        .expect_err("a wrong passphrase must not rewrite the config");
    assert!(err.to_string().contains("verifier"), "{err}");

    let (after, _) = get_json_plain::<EncryptionMeta>(&backend, ENCRYPTION_META_KEY)
        .await
        .unwrap();
    assert_eq!(before.salt, after.salt);
    assert!(after.wrapped_key.is_empty());
}
