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

/// Mirrors a hand-written index whose root/kind/pointer-field don't follow
/// the macro's own defaults (collection prefix / field name / `"key"`) — the
/// shape a real migration of an already-deployed entity needs, so an
/// existing on-disk index doesn't silently move or reshape underneath it.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize, Entity)]
#[entity(collection = ".conf/widgets")]
struct Widget {
    #[entity(key)]
    id: String,
    #[entity(index(root = ".conf/index", kind = "widget-owner", pointer_field = "owner_id"))]
    owner: Option<String>,
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

#[tokio::test]
async fn default_index_root_never_leaks_into_list_keys_or_list_all() {
    // Regression check: an index whose root nests under the entity's own
    // collection prefix would get swept up by `list_names`/`list_all`'s
    // recursive scan as if it were a stored entity -- the default root must
    // land on a sibling prefix, never inside `Account::COLLECTION`'s own.
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let account = Account { username: "alice".into(), email: Some("alice@example.com".into()), fingerprint: None, is_admin: false };
    account.put(&backend, &cipher, None).await.unwrap();
    account.claim_email(&backend, &cipher).await.unwrap();

    assert_eq!(Account::list_keys(&backend).await.unwrap(), vec!["alice".to_string()]);
    let backend: std::sync::Arc<dyn s3db::Backend> = std::sync::Arc::new(backend);
    let cipher = std::sync::Arc::new(cipher);
    let all: Vec<Account> = Account::COLLECTION.list_all(&backend, &cipher).await.unwrap();
    assert_eq!(all, vec![account]);
}

#[test]
fn index_root_kind_and_pointer_field_overrides_match_a_hand_written_index() {
    // Same key shape `SecondaryIndex::new(".conf/index", "widget-owner", Segment::Raw)`
    // would build by hand -- proves the override lands on an arbitrary
    // root/kind, not just the macro's own collection-prefix/field-name defaults.
    assert_eq!(Widget::OWNER_INDEX.key("alice"), ".conf/index/widget-owner/alice.json");
}

#[tokio::test]
async fn claim_op_builds_a_txn_creating_the_override_shaped_pointer() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let widget = Widget { id: "w1".into(), owner: Some("alice".into()) };

    let ops = vec![widget.create_op().unwrap(), widget.owner_claim_op().unwrap().unwrap()];
    assert_eq!(s3db::txn::run(&backend, &cipher, ops).await.unwrap(), s3db::Cas::Ok);

    let (fetched, _) = Widget::get(&backend, &cipher, "w1").await.unwrap();
    assert_eq!(fetched, Some(widget.clone()));
    let found = Widget::find_by_owner(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(found, Some(widget));
}

#[tokio::test]
async fn claim_op_is_none_for_an_unset_optional_index() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let widget = Widget { id: "w2".into(), owner: None };
    assert!(widget.owner_claim_op().unwrap().is_none());
    widget.put(&backend, &cipher, None).await.unwrap();
    assert_eq!(Widget::find_by_owner(&backend, &cipher, "").await.unwrap(), None);
}

#[tokio::test]
async fn create_op_matches_a_plain_put_for_the_same_entity() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let account = Account { username: "alice".into(), email: None, fingerprint: None, is_admin: true };
    assert_eq!(s3db::txn::run(&backend, &cipher, vec![account.create_op().unwrap()]).await.unwrap(), s3db::Cas::Ok);
    let (fetched, _) = Account::get(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(fetched, Some(account));
}
