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
