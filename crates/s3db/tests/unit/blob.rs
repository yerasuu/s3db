use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (Arc<dyn Backend>, Arc<Cipher>) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[3u8; crate::cipher::SALT_LEN]).unwrap();
    (Arc::new(backend), Arc::new(cipher))
}

/// Small parts so a modest test body still spans several of them.
fn blob() -> Blob {
    Blob::new("pages").with_part_bytes(1024)
}

fn body_of(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn roundtrips_a_value_larger_than_one_object() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    let body = body_of(5000);

    assert_eq!(
        blob.put(backend.as_ref(), &cipher, "chapter-1", &body, None)
            .await
            .unwrap(),
        Cas::Ok
    );

    let (read, etag) = blob.get(&backend, &cipher, "chapter-1").await.unwrap();
    assert_eq!(read.as_deref(), Some(body.as_slice()));
    assert!(etag.is_some());

    let (manifest, _etag) = blob.head(backend.as_ref(), &cipher, "chapter-1").await.unwrap();
    let manifest = manifest.unwrap();
    assert_eq!(manifest.total_len, 5000);
    assert_eq!(manifest.parts, 5, "5000 bytes at 1024 per part is 5 parts");
}

#[tokio::test]
async fn a_missing_blob_reads_as_none() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());

    let (read, etag) = blob().get(&backend, &cipher, "nope").await.unwrap();
    assert_eq!(read, None);
    assert_eq!(etag, None);
}

#[tokio::test]
async fn an_empty_body_roundtrips_as_a_zero_part_blob() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();

    blob.put(backend.as_ref(), &cipher, "empty", b"", None).await.unwrap();

    let (manifest, _etag) = blob.head(backend.as_ref(), &cipher, "empty").await.unwrap();
    assert_eq!(manifest.unwrap().parts, 0);
    let (read, _etag) = blob.get(&backend, &cipher, "empty").await.unwrap();
    assert_eq!(read, Some(Vec::new()), "present and empty, not absent");
}

#[tokio::test]
async fn put_is_compare_and_swap_on_the_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    blob.put(backend.as_ref(), &cipher, "k", &body_of(2000), None)
        .await
        .unwrap();

    // Create-only against an existing blob loses.
    assert_eq!(
        blob.put(backend.as_ref(), &cipher, "k", &body_of(10), None)
            .await
            .unwrap(),
        Cas::Conflict
    );
    // A stale etag loses too.
    assert_eq!(
        blob.put(backend.as_ref(), &cipher, "k", &body_of(10), Some("nonsense"))
            .await
            .unwrap(),
        Cas::Conflict
    );
    // The current etag wins.
    let (_manifest, etag) = blob.head(backend.as_ref(), &cipher, "k").await.unwrap();
    assert_eq!(
        blob.put(backend.as_ref(), &cipher, "k", &body_of(10), etag.as_deref())
            .await
            .unwrap(),
        Cas::Ok
    );
    let (read, _etag) = blob.get(&backend, &cipher, "k").await.unwrap();
    assert_eq!(read, Some(body_of(10)));
}

/// A lost CAS race must not leave the parts it wrote lying around: nothing
/// references them and no later read can reach them.
#[tokio::test]
async fn a_conflicting_put_sweeps_the_parts_it_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    blob.put(backend.as_ref(), &cipher, "k", &body_of(2000), None)
        .await
        .unwrap();
    let parts_before = crate::payload::list_all_keys(backend.as_ref(), "pages/.parts/k/")
        .await
        .unwrap()
        .len();

    assert_eq!(
        blob.put(backend.as_ref(), &cipher, "k", &body_of(4000), None)
            .await
            .unwrap(),
        Cas::Conflict
    );

    let parts_after = crate::payload::list_all_keys(backend.as_ref(), "pages/.parts/k/")
        .await
        .unwrap()
        .len();
    assert_eq!(parts_after, parts_before, "the losing write's parts must be gone");
    let (read, _etag) = blob.get(&backend, &cipher, "k").await.unwrap();
    assert_eq!(read, Some(body_of(2000)), "the winning value is untouched");
}

/// The reason parts are generation-scoped instead of overwritten in place: a
/// reader holding the previous manifest must never assemble a mix of old and
/// new parts.
#[tokio::test]
async fn an_overwrite_writes_a_new_generation_and_retires_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    blob.put(backend.as_ref(), &cipher, "k", &body_of(3000), None)
        .await
        .unwrap();
    let (first, etag) = blob.head(backend.as_ref(), &cipher, "k").await.unwrap();
    let first_generation = first.unwrap().generation;

    blob.put(backend.as_ref(), &cipher, "k", &body_of(3000), etag.as_deref())
        .await
        .unwrap();
    let (second, _etag) = blob.head(backend.as_ref(), &cipher, "k").await.unwrap();
    let second_generation = second.unwrap().generation;

    assert_ne!(
        first_generation, second_generation,
        "each write gets its own generation"
    );
    let live: Vec<String> = crate::payload::list_all_keys(backend.as_ref(), "pages/.parts/k/")
        .await
        .unwrap();
    assert!(
        live.iter().all(|key| key.contains(&second_generation)),
        "the retired generation must be swept: {live:?}"
    );
}

#[tokio::test]
async fn get_refuses_to_return_a_truncated_body() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    blob.put(backend.as_ref(), &cipher, "k", &body_of(3000), None)
        .await
        .unwrap();

    // Remove one part behind the manifest's back -- what a half-finished
    // delete, or a sweep racing a read, looks like.
    let (manifest, _etag) = blob.head(backend.as_ref(), &cipher, "k").await.unwrap();
    let generation = manifest.unwrap().generation;
    backend
        .delete(&format!("pages/.parts/k/{generation}/0001"))
        .await
        .unwrap();

    let err = blob.get(&backend, &cipher, "k").await.unwrap_err();
    assert!(
        err.to_string().contains("missing"),
        "a broken blob must not read as a short body: {err}"
    );
}

#[tokio::test]
async fn delete_removes_the_manifest_and_every_part() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    blob.put(backend.as_ref(), &cipher, "k", &body_of(3000), None)
        .await
        .unwrap();

    let report = blob.delete(backend.as_ref(), "k").await.unwrap();

    assert!(report.is_complete(), "{report:?}");
    let (read, _etag) = blob.get(&backend, &cipher, "k").await.unwrap();
    assert_eq!(read, None);
    assert_eq!(
        crate::payload::list_all_keys(backend.as_ref(), "pages/.parts/k/")
            .await
            .unwrap(),
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn list_names_sees_blobs_and_not_their_parts() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    for name in ["b", "a", "nested/c"] {
        blob.put(backend.as_ref(), &cipher, name, &body_of(2000), None)
            .await
            .unwrap();
    }

    assert_eq!(
        blob.list_names(backend.as_ref()).await.unwrap(),
        vec!["a".to_string(), "b".to_string(), "nested/c".to_string()]
    );
}

#[tokio::test]
async fn rejects_a_body_over_the_ceiling_without_writing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = Blob::new("pages").with_part_bytes(1024).with_max_total_bytes(2048);

    assert!(
        blob.put(backend.as_ref(), &cipher, "k", &body_of(4096), None)
            .await
            .is_err()
    );
    assert_eq!(
        crate::payload::list_all_keys(backend.as_ref(), "pages/").await.unwrap(),
        Vec::<String>::new(),
        "a refused blob must leave no parts behind"
    );
}

#[tokio::test]
async fn rejects_a_name_that_would_reach_the_parts_namespace() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    for bad in ["", ".parts/x", "a/.parts/b", "../elsewhere", "a//b"] {
        assert!(blob.manifest_key(bad).is_err(), "{bad:?} should be refused");
        assert!(
            blob.put(backend.as_ref(), &cipher, bad, b"x", None).await.is_err(),
            "{bad:?} should be refused by put()"
        );
    }
}

#[tokio::test]
async fn sweep_orphan_parts_removes_abandoned_writes_but_spares_the_live_one() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    blob.put(backend.as_ref(), &cipher, "k", &body_of(3000), None)
        .await
        .unwrap();
    let (manifest, _etag) = blob.head(backend.as_ref(), &cipher, "k").await.unwrap();
    let live_generation = manifest.unwrap().generation;

    // An abandoned write: parts under a generation no manifest names,
    // stamped old enough to be past any age guard.
    for index in 0..3 {
        let key = format!("pages/.parts/k/0000000000001-deadbeef/{index:04}");
        let sealed = cipher
            .seal(&key, b"orphan", crate::cipher::CompressionStrategy::None)
            .unwrap();
        backend.put_cas(&key, sealed, None).await.unwrap();
    }

    let report = blob
        .sweep_orphan_parts(backend.as_ref(), &cipher, "k", 60_000)
        .await
        .unwrap();

    assert_eq!(report.confirmed, 3, "{report:?}");
    let left = crate::payload::list_all_keys(backend.as_ref(), "pages/.parts/k/")
        .await
        .unwrap();
    assert!(
        left.iter().all(|key| key.contains(&live_generation)),
        "the live generation must survive: {left:?}"
    );
    let (read, _etag) = blob.get(&backend, &cipher, "k").await.unwrap();
    assert_eq!(read, Some(body_of(3000)));
}

/// A generation younger than the age guard is indistinguishable from a write
/// still in flight, so a sweep must leave it alone.
#[tokio::test]
async fn sweep_orphan_parts_spares_a_generation_younger_than_the_guard() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    let key = format!("pages/.parts/k/{:013}-abc123/0000", now_ms());
    let sealed = cipher
        .seal(&key, b"in flight", crate::cipher::CompressionStrategy::None)
        .unwrap();
    backend.put_cas(&key, sealed, None).await.unwrap();

    let report = blob
        .sweep_orphan_parts(backend.as_ref(), &cipher, "k", 60_000)
        .await
        .unwrap();

    assert_eq!(report.confirmed, 0, "{report:?}");
    assert_eq!(
        crate::payload::list_all_keys(backend.as_ref(), "pages/.parts/k/")
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn sweep_all_orphan_parts_covers_every_blob_under_the_prefix_in_one_call() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let blob = blob();
    for name in ["k1", "k2"] {
        blob.put(backend.as_ref(), &cipher, name, &body_of(3000), None)
            .await
            .unwrap();
    }
    let live_generation_of = |name: &str| {
        let backend = backend.clone();
        let cipher = cipher.clone();
        let blob = blob.clone();
        let name = name.to_string();
        async move {
            blob.head(backend.as_ref(), &cipher, &name)
                .await
                .unwrap()
                .0
                .unwrap()
                .generation
        }
    };
    let live_k1 = live_generation_of("k1").await;
    let live_k2 = live_generation_of("k2").await;

    // An abandoned write under each of the two blobs.
    for name in ["k1", "k2"] {
        let key = format!("pages/.parts/{name}/0000000000001-deadbeef/0000");
        let sealed = cipher
            .seal(&key, b"orphan", crate::cipher::CompressionStrategy::None)
            .unwrap();
        backend.put_cas(&key, sealed, None).await.unwrap();
    }

    let report = blob
        .sweep_all_orphan_parts(backend.as_ref(), &cipher, 60_000)
        .await
        .unwrap();

    assert_eq!(report.confirmed, 2, "{report:?}");
    for (name, live) in [("k1", &live_k1), ("k2", &live_k2)] {
        let left = crate::payload::list_all_keys(backend.as_ref(), &format!("pages/.parts/{name}/"))
            .await
            .unwrap();
        assert!(
            left.iter().all(|key| key.contains(live.as_str())),
            "the live generation of {name} must survive: {left:?}"
        );
    }
}

#[test]
fn generation_age_comes_from_the_id_itself() {
    assert_eq!(Blob::generation_age_ms("0000000001000-abc", 1_500), Some(500));
    assert_eq!(
        Blob::generation_age_ms("0000000002000-abc", 1_500),
        Some(0),
        "a clock that went backwards saturates rather than underflowing"
    );
    assert_eq!(Blob::generation_age_ms("not-a-generation", 1_500), None);
    assert_eq!(Blob::generation_age_ms("nodash", 1_500), None);
}
