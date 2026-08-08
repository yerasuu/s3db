use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

fn test_backend(root: &std::path::Path) -> LocalBackend {
    LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    })
}

fn test_cipher() -> Cipher {
    Cipher::derive("test passphrase", &[6u8; crate::cipher::SALT_LEN]).unwrap()
}

fn entry(key: &str) -> ManifestEntry {
    ManifestEntry {
        key: key.to_string(),
        min_key: b"a".to_vec(),
        max_key: b"z".to_vec(),
        byte_len: 100,
        footer_len: 20,
        level: 0,
        flushed_at_ms: 0,
    }
}

#[tokio::test]
async fn load_of_a_table_that_never_flushed_is_empty_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    let (manifest, etag) = load(&backend, &cipher, "t").await.unwrap();
    assert!(manifest.sstables.is_empty());
    assert!(etag.is_none());
}

#[tokio::test]
async fn append_then_load_sees_the_new_entry() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    append(&backend, &cipher, "t", entry("t/sst/1.sst")).await.unwrap();
    let (manifest, etag) = load(&backend, &cipher, "t").await.unwrap();
    assert_eq!(manifest.sstables, vec![entry("t/sst/1.sst")]);
    assert!(etag.is_some());
}

#[tokio::test]
async fn appending_twice_keeps_both_entries_in_flush_order() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    append(&backend, &cipher, "t", entry("t/sst/1.sst")).await.unwrap();
    append(&backend, &cipher, "t", entry("t/sst/2.sst")).await.unwrap();
    let (manifest, _) = load(&backend, &cipher, "t").await.unwrap();
    assert_eq!(manifest.sstables.len(), 2);
    assert_eq!(manifest.sstables[0].key, "t/sst/1.sst");
    assert_eq!(manifest.sstables[1].key, "t/sst/2.sst");
}

#[tokio::test]
async fn two_tables_with_different_roots_have_independent_manifests() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    append(&backend, &cipher, "a", entry("a/sst/1.sst")).await.unwrap();
    let (manifest_a, _) = load(&backend, &cipher, "a").await.unwrap();
    let (manifest_b, _) = load(&backend, &cipher, "b").await.unwrap();
    assert_eq!(manifest_a.sstables.len(), 1);
    assert!(manifest_b.sstables.is_empty());
}
