//! End-to-end check that `#[derive(Entity)]` produces the same
//! `Collection`/`SecondaryIndex` behavior a hand-written entity
//! (`auth::access::User`, in gitquarry proper) already implements by hand.

use s3db::{Cipher, Entity, LocalBackend, LocalParams};

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize, Entity)]
#[entity(collection = ".conf/accounts")]
struct Account {
    #[entity(key)]
    username: String,
    #[entity(index)]
    email: Option<String>,
    #[entity(index(segment = "base64"))]
    fingerprint: Option<String>,
    is_admin: bool,
}

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams { bucket: root.to_string_lossy().to_string() });
    let cipher = Cipher::derive("test passphrase", &[3u8; s3db::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[tokio::test]
async fn put_then_get_roundtrips_by_key() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let account = Account { username: "alice".into(), email: None, fingerprint: None, is_admin: true };

    assert_eq!(account.put(&backend, &cipher, None).await.unwrap(), s3db::Cas::Ok);
    let (fetched, etag) = Account::get(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(fetched, Some(account));
    assert!(etag.is_some());
}

#[test]
fn write_key_matches_the_collection_key() {
    let mut buf = String::new();
    Account::write_key(&mut buf, "alice");
    assert_eq!(buf, Account::COLLECTION.key("alice"));
}

#[tokio::test]
async fn get_reports_none_for_a_missing_key() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let (fetched, etag) = Account::get(&backend, &cipher, "nobody").await.unwrap();
    assert_eq!(fetched, None);
    assert_eq!(etag, None);
}

#[tokio::test]
async fn indexed_field_claims_and_resolves_back_to_the_owning_entity() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let account = Account { username: "alice".into(), email: Some("alice@example.com".into()), fingerprint: None, is_admin: false };
    account.put(&backend, &cipher, None).await.unwrap();

    assert!(account.claim_email(&backend, &cipher).await.unwrap());
    let found = Account::find_by_email(&backend, &cipher, "alice@example.com").await.unwrap();
    assert_eq!(found, Some(account));
}

#[tokio::test]
async fn claiming_an_already_taken_index_value_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let alice = Account { username: "alice".into(), email: Some("shared@example.com".into()), fingerprint: None, is_admin: false };
    let bob = Account { username: "bob".into(), email: Some("shared@example.com".into()), fingerprint: None, is_admin: false };
    alice.put(&backend, &cipher, None).await.unwrap();
    bob.put(&backend, &cipher, None).await.unwrap();

    assert!(alice.claim_email(&backend, &cipher).await.unwrap());
    assert!(!bob.claim_email(&backend, &cipher).await.unwrap());
}

#[tokio::test]
async fn claiming_a_none_optional_index_is_a_no_op_success() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let account = Account { username: "alice".into(), email: None, fingerprint: None, is_admin: false };
    assert!(account.claim_email(&backend, &cipher).await.unwrap());
    assert_eq!(Account::find_by_email(&backend, &cipher, "").await.unwrap(), None);
}

#[tokio::test]
async fn base64_segment_index_round_trips_a_slash_containing_value() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let account =
        Account { username: "alice".into(), email: None, fingerprint: Some("SHA256:abc/def+ghi".into()), is_admin: false };
    account.put(&backend, &cipher, None).await.unwrap();
    assert!(account.claim_fingerprint(&backend, &cipher).await.unwrap());
    let found = Account::find_by_fingerprint(&backend, &cipher, "SHA256:abc/def+ghi").await.unwrap();
    assert_eq!(found, Some(account));
}

#[tokio::test]
async fn release_then_find_by_reports_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let account = Account { username: "alice".into(), email: Some("alice@example.com".into()), fingerprint: None, is_admin: false };
    account.put(&backend, &cipher, None).await.unwrap();
    account.claim_email(&backend, &cipher).await.unwrap();
    account.release_email(&backend).await;
    assert_eq!(Account::find_by_email(&backend, &cipher, "alice@example.com").await.unwrap(), None);
}

#[tokio::test]
async fn list_keys_returns_every_stored_username_sorted() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    Account { username: "bob".into(), email: None, fingerprint: None, is_admin: false }.put(&backend, &cipher, None).await.unwrap();
    Account { username: "alice".into(), email: None, fingerprint: None, is_admin: false }.put(&backend, &cipher, None).await.unwrap();
    assert_eq!(Account::list_keys(&backend).await.unwrap(), vec!["alice".to_string(), "bob".to_string()]);
}
