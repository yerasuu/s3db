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
    let cipher = Cipher::derive("correct", &[3u8; SALT_LEN]).unwrap();
    let meta = EncryptionMeta {
        salt: BASE64.encode([3u8; SALT_LEN]),
        verifier: BASE64.encode(
            cipher
                .seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)
                .unwrap(),
        ),
    };
    assert!(derive_and_verify("correct", DEFAULT_ALGORITHM, &meta).is_ok());
    let err = derive_and_verify("incorrect", DEFAULT_ALGORITHM, &meta).unwrap_err();
    assert!(format!("{err:#}").contains("doesn't match"));
}

#[test]
fn rejects_malformed_salt() {
    let meta = EncryptionMeta {
        salt: "not-base64!!".to_string(),
        verifier: String::new(),
    };
    assert!(derive_and_verify("x", DEFAULT_ALGORITHM, &meta).is_err());
}

/// A bucket bootstrapped under one algorithm stays readable when the
/// configured algorithm changes — the verifier is opened, never re-sealed.
#[test]
fn a_verifier_sealed_by_one_algorithm_validates_under_another() {
    let cipher = Cipher::derive_with("pw", &[3u8; SALT_LEN], CipherAlgorithm::Aes256Gcm).unwrap();
    let meta = EncryptionMeta {
        salt: BASE64.encode([3u8; SALT_LEN]),
        verifier: BASE64.encode(
            cipher
                .seal(VERIFIER_AAD, VERIFIER_PLAINTEXT, CompressionStrategy::None)
                .unwrap(),
        ),
    };
    let derived = derive_and_verify("pw", CipherAlgorithm::XChaCha20Poly1305, &meta).unwrap();
    assert_eq!(
        derived.mode(),
        EncryptionMode::Enabled {
            algorithm: CipherAlgorithm::XChaCha20Poly1305
        }
    );
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
