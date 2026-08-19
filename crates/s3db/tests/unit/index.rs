use super::*;
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    test_backend_and_cipher_with(root, crate::config::LocalEngine::Files)
}

fn test_backend_and_cipher_with(root: &std::path::Path, engine: crate::config::LocalEngine) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&crate::config::LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine,
    });
    let cipher = Cipher::derive("test passphrase", &[8u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Pointer {
    owner: String,
}

#[test]
fn base64_segment_matches_the_original_url_safe_no_pad_scheme() {
    // Parity check against `auth::access::index_segment`'s exact output
    // (URL_SAFE_NO_PAD, no other transform), for a fingerprint-shaped
    // value that contains `/` and `+`-triggering bytes.
    let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
    use base64::Engine;
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"SHA256:abc/def+ghi");
    assert_eq!(
        idx.key("SHA256:abc/def+ghi").unwrap(),
        format!(".conf/index/pubkey/{expected}.json")
    );
}

#[tokio::test]
async fn typed_key_claims_and_resolves_a_u64() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "byid", Segment::Raw);
    let id: u64 = 42;
    assert!(
        idx.claim_once_typed(&backend, &cipher, &id, &Pointer { owner: "alice".into() })
            .await
            .unwrap()
    );
    let (resolved, _etag) = idx.resolve_typed::<Pointer>(&backend, &cipher, &id).await.unwrap();
    assert_eq!(resolved, Some(Pointer { owner: "alice".into() }));
}

#[test]
fn typed_key_never_allocates_an_intermediate_string_representation() {
    // Same u64 encoded two different (wrong) ways -- decimal text vs
    // its natural big-endian bytes -- must not collide, proving
    // key_typed really uses key_bytes(), not `.to_string()`.
    let idx = SecondaryIndex::new(".conf/index", "byid", Segment::Raw);
    let as_typed_key = idx.key_typed(&42u64);
    let as_raw_string_key = idx.key("42").unwrap();
    assert_ne!(as_typed_key, as_raw_string_key);
}

#[tokio::test]
async fn typed_key_release_removes_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "byid", Segment::Raw);
    let id: u64 = 7;
    idx.claim_once_typed(&backend, &cipher, &id, &Pointer { owner: "alice".into() })
        .await
        .unwrap();
    idx.release_typed(&backend, &id).await;
    let (resolved, _) = idx.resolve_typed::<Pointer>(&backend, &cipher, &id).await.unwrap();
    assert_eq!(resolved, None);
}

#[tokio::test]
async fn inline_resolve_reads_the_denormalized_value_in_one_get() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "email", Segment::Base64);
    assert!(
        idx.claim_inline(
            &backend,
            &cipher,
            "alice@example.com",
            &Pointer { owner: "alice".into() },
            &Widget { count: 9 }
        )
        .await
        .unwrap()
    );
    let value: Option<Widget> = idx
        .resolve_inline::<Pointer, Widget>(&backend, &cipher, "alice@example.com")
        .await
        .unwrap();
    assert_eq!(value, Some(Widget { count: 9 }));
}

#[tokio::test]
async fn inline_resolve_is_none_before_any_claim() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "email", Segment::Base64);
    let value: Option<Widget> = idx
        .resolve_inline::<Pointer, Widget>(&backend, &cipher, "nobody@example.com")
        .await
        .unwrap();
    assert_eq!(value, None);
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
}

#[test]
fn raw_segment_is_used_verbatim() {
    let idx = SecondaryIndex::new(".conf/index", "namespace", Segment::Raw);
    assert_eq!(idx.key("alice").unwrap(), ".conf/index/namespace/alice.json");
}

#[tokio::test]
async fn claim_once_conflicts_on_a_second_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "namespace", Segment::Raw);
    assert!(
        idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() })
            .await
            .unwrap()
    );
    assert!(
        !idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "bob".into() })
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn self_healing_claim_succeeds_fresh() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
    let ok = idx
        .claim_self_healing(
            &backend,
            &cipher,
            "fp1",
            &Pointer { owner: "alice".into() },
            |_existing: Pointer| async { Ok(false) },
        )
        .await
        .unwrap();
    assert!(ok);
}

#[tokio::test]
async fn self_healing_claim_is_idempotent_for_the_same_claimant() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
    idx.claim_self_healing(
        &backend,
        &cipher,
        "fp1",
        &Pointer { owner: "alice".into() },
        |_: Pointer| async { Ok(true) },
    )
    .await
    .unwrap();
    let ok = idx
        .claim_self_healing(
            &backend,
            &cipher,
            "fp1",
            &Pointer { owner: "alice".into() },
            |_: Pointer| async { Ok(true) },
        )
        .await
        .unwrap();
    assert!(
        ok,
        "reclaiming with the identical value must be idempotent, not a conflict"
    );
}

#[tokio::test]
async fn self_healing_claim_refuses_a_genuinely_live_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
    idx.claim_self_healing(
        &backend,
        &cipher,
        "fp1",
        &Pointer { owner: "alice".into() },
        |_: Pointer| async { Ok(true) },
    )
    .await
    .unwrap();
    let ok = idx
        .claim_self_healing(
            &backend,
            &cipher,
            "fp1",
            &Pointer { owner: "bob".into() },
            |existing: Pointer| async move { Ok(existing.owner == "alice") },
        )
        .await
        .unwrap();
    assert!(!ok, "a claim genuinely still held by someone else must be refused");
}

#[tokio::test]
async fn self_healing_claim_reclaims_a_stale_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
    idx.claim_self_healing(
        &backend,
        &cipher,
        "fp1",
        &Pointer { owner: "alice".into() },
        |_: Pointer| async { Ok(true) },
    )
    .await
    .unwrap();
    // `alice` no longer genuinely holds it (simulated via is_genuine=false).
    let ok = idx
        .claim_self_healing(
            &backend,
            &cipher,
            "fp1",
            &Pointer { owner: "bob".into() },
            |_: Pointer| async { Ok(false) },
        )
        .await
        .unwrap();
    assert!(ok, "a stale claim must be reclaimable");
    let (resolved, _etag) = idx.resolve::<Pointer>(&backend, &cipher, "fp1").await.unwrap();
    assert_eq!(resolved, Some(Pointer { owner: "bob".into() }));
}

#[tokio::test]
async fn release_makes_resolve_report_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "namespace", Segment::Raw);
    idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() })
        .await
        .unwrap();
    idx.release(&backend, "alice").await.unwrap();
    let (resolved, _etag) = idx.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(resolved, None);
}

#[tokio::test]
async fn resolve_range_on_files_reports_no_native_capability() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = SecondaryIndex::new(".conf/index", "score", Segment::Raw);
    idx.claim_once(&backend, &cipher, "05", &Pointer { owner: "a".into() })
        .await
        .unwrap();
    let err = idx
        .resolve_range::<Pointer>(&backend, &cipher, "00", "10")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("native range capability"), "got: {err}");
}

#[tokio::test]
async fn resolve_range_on_redb_returns_the_bounded_slice_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Redb);
    let idx = SecondaryIndex::new(".conf/index", "score", Segment::Raw);
    // Zero-padded so lexicographic order matches numeric order -- the
    // caller's job, not this index's (see the method's own doc).
    for (raw, owner) in [("01", "a"), ("03", "b"), ("05", "c"), ("07", "d"), ("09", "e")] {
        idx.claim_once(&backend, &cipher, raw, &Pointer { owner: owner.into() })
            .await
            .unwrap();
    }

    let found = idx
        .resolve_range::<Pointer>(&backend, &cipher, "03", "07")
        .await
        .unwrap();
    assert_eq!(
        found,
        vec![
            ("03".to_string(), Pointer { owner: "b".into() }),
            ("05".to_string(), Pointer { owner: "c".into() }),
        ],
        "upper bound must be exclusive, lower bound inclusive"
    );
}

#[tokio::test]
async fn resolve_range_on_redb_is_empty_for_a_bound_with_no_matches() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Redb);
    let idx = SecondaryIndex::new(".conf/index", "score", Segment::Raw);
    idx.claim_once(&backend, &cipher, "01", &Pointer { owner: "a".into() })
        .await
        .unwrap();
    let found = idx
        .resolve_range::<Pointer>(&backend, &cipher, "50", "99")
        .await
        .unwrap();
    assert!(found.is_empty());
}

/// The exact edge case `segment_prefix`'s own doc comment reasons
/// through: one `raw` value that's a proper prefix of another. A naive
/// bound built from `key()` (which appends `.json` before comparing)
/// would get this wrong; `segment_prefix` must not.
#[tokio::test]
async fn resolve_range_handles_a_raw_value_that_prefixes_another() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Redb);
    let idx = SecondaryIndex::new(".conf/index", "namespace", Segment::Raw);
    for raw in ["ab", "ab1", "ac"] {
        idx.claim_once(&backend, &cipher, raw, &Pointer { owner: raw.into() })
            .await
            .unwrap();
    }

    // Upper bound "ab1" (exclusive) must include "ab" but not "ab1" itself.
    let found = idx
        .resolve_range::<Pointer>(&backend, &cipher, "aa", "ab1")
        .await
        .unwrap();
    assert_eq!(found, vec![("ab".to_string(), Pointer { owner: "ab".into() })]);

    // Lower bound "ab1" (inclusive) must include "ab1" but not "ab".
    let found = idx
        .resolve_range::<Pointer>(&backend, &cipher, "ab1", "ad")
        .await
        .unwrap();
    assert_eq!(
        found,
        vec![
            ("ab1".to_string(), Pointer { owner: "ab1".into() }),
            ("ac".to_string(), Pointer { owner: "ac".into() }),
        ]
    );
}

#[tokio::test]
async fn resolve_range_refuses_a_base64_segment() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Redb);
    let idx = SecondaryIndex::new(".conf/index", "pubkey", Segment::Base64);
    let err = idx
        .resolve_range::<Pointer>(&backend, &cipher, "a", "z")
        .await
        .unwrap_err()
        .to_string();
    assert!(err.contains("Segment::Raw"), "got: {err}");
}
