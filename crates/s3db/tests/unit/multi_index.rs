use super::*;

fn test_backend_and_cipher(root: &std::path::Path) -> (Arc<dyn Backend>, Arc<Cipher>) {
    let backend = crate::local::test_support::files_backend(root);
    let cipher = Cipher::derive("test passphrase", &[11u8; crate::cipher::SALT_LEN]).unwrap();
    (Arc::new(backend), Arc::new(cipher))
}

const BY_GENRE: MultiIndex = MultiIndex::new("idx", "genre", Segment::Raw);

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Denormalized {
    title: String,
}

#[tokio::test]
async fn many_members_share_one_value() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());

    for work in ["work-c", "work-a", "work-b"] {
        BY_GENRE
            .add_member(backend.as_ref(), &cipher, "action", work)
            .await
            .unwrap();
    }
    BY_GENRE
        .add_member(backend.as_ref(), &cipher, "romance", "work-a")
        .await
        .unwrap();

    assert_eq!(
        BY_GENRE.members(backend.as_ref(), "action").await.unwrap(),
        vec!["work-a", "work-b", "work-c"],
        "members come back in name order"
    );
    assert_eq!(
        BY_GENRE.members(backend.as_ref(), "romance").await.unwrap(),
        vec!["work-a"],
        "a member can belong to several values"
    );
    assert_eq!(BY_GENRE.count(backend.as_ref(), "action").await.unwrap(), 3);
    assert!(BY_GENRE.contains(backend.as_ref(), "action", "work-b").await.unwrap());
    assert!(!BY_GENRE.contains(backend.as_ref(), "action", "work-z").await.unwrap());
}

#[tokio::test]
async fn a_value_with_no_members_is_empty_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let _ = &cipher;

    assert_eq!(
        BY_GENRE.members(backend.as_ref(), "never-used").await.unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(BY_GENRE.count(backend.as_ref(), "never-used").await.unwrap(), 0);
}

#[tokio::test]
async fn adding_the_same_membership_twice_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());

    BY_GENRE
        .add(
            backend.as_ref(),
            &cipher,
            "action",
            "work-a",
            &Denormalized { title: "first".into() },
        )
        .await
        .unwrap();
    BY_GENRE
        .add(
            backend.as_ref(),
            &cipher,
            "action",
            "work-a",
            &Denormalized { title: "second".into() },
        )
        .await
        .unwrap();

    assert_eq!(BY_GENRE.count(backend.as_ref(), "action").await.unwrap(), 1);
    let payload: Option<Denormalized> = BY_GENRE
        .payload(backend.as_ref(), &cipher, "action", "work-a")
        .await
        .unwrap();
    assert_eq!(
        payload.unwrap().title,
        "second",
        "a re-add overwrites the payload rather than failing"
    );
}

#[tokio::test]
async fn remove_drops_one_membership_and_leaves_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    for work in ["work-a", "work-b"] {
        BY_GENRE
            .add_member(backend.as_ref(), &cipher, "action", work)
            .await
            .unwrap();
    }

    BY_GENRE.remove(backend.as_ref(), "action", "work-a").await;

    assert_eq!(
        BY_GENRE.members(backend.as_ref(), "action").await.unwrap(),
        vec!["work-b"]
    );
    // Removing something that isn't there is a no-op, not an error.
    BY_GENRE.remove(backend.as_ref(), "action", "work-a").await;
    assert_eq!(BY_GENRE.count(backend.as_ref(), "action").await.unwrap(), 1);
}

#[tokio::test]
async fn clear_drops_every_membership_of_one_value_only() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    for work in ["work-a", "work-b", "work-c"] {
        BY_GENRE
            .add_member(backend.as_ref(), &cipher, "action", work)
            .await
            .unwrap();
    }
    BY_GENRE
        .add_member(backend.as_ref(), &cipher, "romance", "work-a")
        .await
        .unwrap();

    let report = BY_GENRE.clear(backend.as_ref(), "action").await.unwrap();

    assert!(report.is_complete(), "{report:?}");
    assert_eq!(BY_GENRE.count(backend.as_ref(), "action").await.unwrap(), 0);
    assert_eq!(
        BY_GENRE.members(backend.as_ref(), "romance").await.unwrap(),
        vec!["work-a"],
        "a sibling value must be untouched"
    );
}

#[tokio::test]
async fn members_with_returns_the_denormalized_payloads() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    for (work, title) in [("work-a", "Alpha"), ("work-b", "Beta")] {
        BY_GENRE
            .add(
                backend.as_ref(),
                &cipher,
                "action",
                work,
                &Denormalized { title: title.into() },
            )
            .await
            .unwrap();
    }

    let listed: Vec<(String, Denormalized)> = BY_GENRE
        .members_with(&backend, &cipher, "action", MemoryBudget::default())
        .await
        .unwrap();

    assert_eq!(
        listed,
        vec![
            ("work-a".to_string(), Denormalized { title: "Alpha".into() }),
            ("work-b".to_string(), Denormalized { title: "Beta".into() }),
        ]
    );
}

/// Hierarchical member names are normal here (`<lang>/<work>`), so they must
/// survive the round trip through the key and back out of the listing.
#[tokio::test]
async fn hierarchical_member_names_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    for member in ["es/work-a", "en/work-a", "en/work-b"] {
        BY_GENRE
            .add_member(backend.as_ref(), &cipher, "action", member)
            .await
            .unwrap();
    }

    assert_eq!(
        BY_GENRE.members(backend.as_ref(), "action").await.unwrap(),
        vec!["en/work-a", "en/work-b", "es/work-a"]
    );
    assert!(
        BY_GENRE
            .contains(backend.as_ref(), "action", "es/work-a")
            .await
            .unwrap()
    );
}

/// A value whose encoded form is a prefix of another must not absorb the
/// other's members — the reason `members_prefix` always ends in `/`.
#[tokio::test]
async fn a_value_that_prefixes_another_keeps_its_own_members() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    BY_GENRE
        .add_member(backend.as_ref(), &cipher, "ab", "one")
        .await
        .unwrap();
    BY_GENRE
        .add_member(backend.as_ref(), &cipher, "ab1", "two")
        .await
        .unwrap();

    assert_eq!(BY_GENRE.members(backend.as_ref(), "ab").await.unwrap(), vec!["one"]);
    assert_eq!(BY_GENRE.members(backend.as_ref(), "ab1").await.unwrap(), vec!["two"]);
}

#[tokio::test]
async fn refuses_a_member_name_that_would_escape_its_value() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    for bad in ["", "../elsewhere", "a//b", ".hidden", "a/.hidden/b"] {
        assert!(BY_GENRE.entry_key("action", bad).is_err(), "{bad:?}");
        assert!(
            BY_GENRE
                .add_member(backend.as_ref(), &cipher, "action", bad)
                .await
                .is_err(),
            "{bad:?}"
        );
    }
}

/// Arbitrary values (a genre name with spaces or slashes) need `Base64`, and
/// must still round-trip.
#[tokio::test]
async fn base64_segments_handle_arbitrary_values() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let index = MultiIndex::new("idx", "tag", Segment::Base64);

    index
        .add_member(backend.as_ref(), &cipher, "slice of life / 日常", "work-a")
        .await
        .unwrap();

    assert_eq!(
        index.members(backend.as_ref(), "slice of life / 日常").await.unwrap(),
        vec!["work-a"]
    );
}

#[tokio::test]
async fn listing_pages_through_a_large_membership() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    for n in 0..1_050u32 {
        BY_GENRE
            .add_member(
                backend.as_ref(),
                &cipher,
                "action",
                &crate::ordinal::encode_u64(n as u64),
            )
            .await
            .unwrap();
    }

    let members = BY_GENRE.members(backend.as_ref(), "action").await.unwrap();

    assert_eq!(
        members.len(),
        1_050,
        "a membership larger than one page must come back whole"
    );
    assert_eq!(
        members.first().map(String::as_str),
        Some(crate::ordinal::encode_u64(0)).as_deref()
    );
    assert_eq!(BY_GENRE.count(backend.as_ref(), "action").await.unwrap(), 1_050);
}
