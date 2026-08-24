use super::*;
use crate::cipher::SALT_LEN;
use crate::local::LocalBackend;

fn temp_backend() -> (tempfile::TempDir, LocalBackend) {
    let dir = tempfile::tempdir().unwrap();
    let backend = crate::local::test_support::files_backend(dir.path());
    (dir, backend)
}

fn test_cipher(passphrase: &str) -> Cipher {
    Cipher::derive(passphrase, &[9u8; SALT_LEN]).unwrap()
}

#[test]
fn a_tag_verifies_against_the_bytes_it_was_made_from() {
    let c = test_cipher("pw");
    let mac = authenticator(&c, b"{\"salt\":\"abc\"}").unwrap();
    assert!(verify(&c, b"{\"salt\":\"abc\"}", &mac, "k").is_ok());
}

#[test]
fn a_tag_fails_against_modified_bytes() {
    let c = test_cipher("pw");
    let mac = authenticator(&c, b"{\"salt\":\"abc\"}").unwrap();
    let err = verify(&c, b"{\"salt\":\"xyz\"}", &mac, "k").unwrap_err();
    assert!(format!("{err:#}").contains("doesn't match the passphrase"), "{err:#}");
}

/// The tag is only producible by a holder of the key, which is what stops
/// anything with mere write access to the bucket from rewriting this file.
#[test]
fn a_tag_fails_under_a_different_key() {
    let mac = authenticator(&test_cipher("pw"), b"payload").unwrap();
    assert!(verify(&test_cipher("other"), b"payload", &mac, "k").is_err());
}

#[test]
fn a_missing_tag_is_refused_rather_than_treated_as_unauthenticated() {
    let err = verify(&test_cipher("pw"), b"payload", "", "k").unwrap_err();
    assert!(format!("{err:#}").contains("no authentication tag"), "{err:#}");
}

#[test]
fn a_non_base64_tag_is_refused() {
    assert!(verify(&test_cipher("pw"), b"payload", "not base64!!", "k").is_err());
}

#[tokio::test]
async fn initializing_over_an_empty_bucket_is_allowed() {
    let (_dir, backend) = temp_backend();
    assert!(
        ensure_safe_to_initialize(&backend, BootstrapPolicy::RequireEmptyBucket, "k")
            .await
            .is_ok()
    );
}

/// The deleted-config attack: the bucket still holds sealed objects, but the
/// encryption config is gone. Generating a fresh salt here would leave every
/// one of those objects permanently unreadable.
#[tokio::test]
async fn initializing_over_a_bucket_that_already_has_objects_is_refused() {
    let (_dir, backend) = temp_backend();
    backend
        .put_cas("users/alice.json", b"sealed".to_vec(), None)
        .await
        .unwrap();
    let err = ensure_safe_to_initialize(&backend, BootstrapPolicy::RequireEmptyBucket, "k")
        .await
        .unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("refusing to initialize"), "{msg}");
    assert!(msg.contains("users/alice.json"), "{msg}");
}

#[tokio::test]
async fn adopting_a_non_empty_bucket_is_allowed_when_asked_for_explicitly() {
    let (_dir, backend) = temp_backend();
    backend
        .put_cas("users/alice.json", b"sealed".to_vec(), None)
        .await
        .unwrap();
    assert!(
        ensure_safe_to_initialize(&backend, BootstrapPolicy::AllowNonEmptyBucket, "k")
            .await
            .is_ok()
    );
}
