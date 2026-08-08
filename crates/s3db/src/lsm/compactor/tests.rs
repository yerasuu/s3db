use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;
use crate::lsm::{Table, TableConfig};
use std::sync::Arc;

fn test_backend(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    }))
}

fn test_cipher() -> Cipher {
    Cipher::derive("test passphrase", &[7u8; crate::cipher::SALT_LEN]).unwrap()
}

#[test]
fn should_compact_respects_the_threshold() {
    assert!(!should_compact(0));
    assert!(!should_compact(DEFAULT_COMPACTION_THRESHOLD - 1));
    assert!(should_compact(DEFAULT_COMPACTION_THRESHOLD));
    assert!(should_compact(DEFAULT_COMPACTION_THRESHOLD + 10));
}

#[tokio::test]
async fn compact_of_zero_or_one_sstable_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());

    let report = compact(backend.as_ref(), &cipher, "t", 500).await.unwrap();
    assert_eq!(report, CompactionReport::default());

    let table = Table::open(TableConfig::new(
        backend.clone(),
        cipher.clone(),
        "t",
        dir.path().join("t.wal"),
    ))
    .await
    .unwrap();
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.flush().await.unwrap();

    let report = compact(backend.as_ref(), &cipher, "t", 500).await.unwrap();
    assert_eq!(report.sstables_before, 1);
    assert_eq!(report.sstables_after, 1);
}

#[tokio::test]
async fn compact_merges_several_sstables_into_one_keeping_the_newest_value() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    let table = Table::open(TableConfig::new(
        backend.clone(),
        cipher.clone(),
        "t",
        dir.path().join("t.wal"),
    ))
    .await
    .unwrap();

    table.put(b"a".to_vec(), b"old".to_vec()).await.unwrap();
    table.put(b"b".to_vec(), b"1".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.put(b"a".to_vec(), b"new".to_vec()).await.unwrap(); // overwrite across sstables
    table.put(b"c".to_vec(), b"1".to_vec()).await.unwrap();
    table.flush().await.unwrap();

    let report = compact(backend.as_ref(), &cipher, "t", 500).await.unwrap();
    assert_eq!(report.sstables_before, 2);
    assert_eq!(report.sstables_after, 1);
    assert_eq!(report.rows_read, 4);
    assert_eq!(report.rows_after, 3);

    // The table still answers correctly through the normal read path.
    assert_eq!(table.get(b"a").await.unwrap(), Some(b"new".to_vec()));
    assert_eq!(table.get(b"b").await.unwrap(), Some(b"1".to_vec()));
    assert_eq!(table.get(b"c").await.unwrap(), Some(b"1".to_vec()));
}

#[tokio::test]
async fn compact_drops_tombstones_for_keys_fully_covered_by_the_merge() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    let table = Table::open(TableConfig::new(
        backend.clone(),
        cipher.clone(),
        "t",
        dir.path().join("t.wal"),
    ))
    .await
    .unwrap();

    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.delete(b"a".to_vec()).await.unwrap();
    table.flush().await.unwrap();

    let report = compact(backend.as_ref(), &cipher, "t", 500).await.unwrap();
    assert_eq!(report.rows_after, 0, "the tombstoned key must not survive the merge");
    assert_eq!(
        report.sstables_after, 0,
        "a fully tombstoned table compacts down to zero SSTables"
    );
    assert_eq!(table.get(b"a").await.unwrap(), None);

    // The manifest itself reflects zero SSTables, not just an empty read.
    let (manifest, _) = manifest::load(backend.as_ref(), &cipher, "t").await.unwrap();
    assert!(manifest.sstables.is_empty());
}

#[tokio::test]
async fn compact_deletes_the_old_sstable_objects() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = (test_backend(dir.path()), test_cipher());
    let table = Table::open(TableConfig::new(
        backend.clone(),
        cipher.clone(),
        "t",
        dir.path().join("t.wal"),
    ))
    .await
    .unwrap();
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.put(b"b".to_vec(), b"2".to_vec()).await.unwrap();
    table.flush().await.unwrap();

    let (before, _) = manifest::load(backend.as_ref(), &cipher, "t").await.unwrap();
    let old_keys: Vec<String> = before.sstables.iter().map(|e| e.key.clone()).collect();

    compact(backend.as_ref(), &cipher, "t", 500).await.unwrap();

    for key in old_keys {
        let (_, etag) = backend.get(&key).await.unwrap();
        assert!(etag.is_none(), "{key} should have been deleted after compaction");
    }
}

#[tokio::test]
async fn table_compact_and_should_compact_delegate_correctly() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let cipher = test_cipher();
    let table = Table::open(TableConfig::new(backend, cipher, "t", dir.path().join("t.wal")))
        .await
        .unwrap();
    assert!(!table.should_compact().await.unwrap());

    for i in 0..2u32 {
        table.put(format!("k{i}").into_bytes(), b"v".to_vec()).await.unwrap();
        table.flush().await.unwrap();
    }
    let report = table.compact().await.unwrap();
    assert_eq!(report.sstables_before, 2);
    assert_eq!(report.sstables_after, 1);
}
