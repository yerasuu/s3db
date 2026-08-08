use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

fn test_backend(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    }))
}

fn test_cipher() -> Cipher {
    Cipher::derive("test passphrase", &[13u8; crate::cipher::SALT_LEN]).unwrap()
}

async fn open_table(dir: &std::path::Path) -> Table {
    let backend = test_backend(dir);
    let config = TableConfig::new(backend, test_cipher(), "audit_log", dir.join("table.wal"));
    Table::open(config).await.unwrap()
}

#[tokio::test]
async fn put_is_visible_via_get_unflushed_before_any_flush() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    assert_eq!(table.get_unflushed(b"a").await, Some(MemValue::Put(b"1".to_vec())));
}

#[tokio::test]
async fn delete_is_visible_as_a_tombstone_before_any_flush() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.delete(b"a".to_vec()).await.unwrap();
    assert_eq!(table.get_unflushed(b"a").await, Some(MemValue::Tombstone));
}

#[tokio::test]
async fn flush_of_an_empty_table_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    assert_eq!(table.flush().await.unwrap(), None);
}

#[tokio::test]
async fn flush_writes_exactly_one_object_and_clears_the_memtable() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let config = TableConfig::new(
        backend.clone(),
        test_cipher(),
        "audit_log",
        dir.path().join("table.wal"),
    );
    let table = Table::open(config).await.unwrap();

    table.put(b"b".to_vec(), b"2".to_vec()).await.unwrap();
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.put(b"c".to_vec(), b"3".to_vec()).await.unwrap();

    let flushed = table.flush().await.unwrap().expect("non-empty memtable must flush");
    assert_eq!(flushed.row_count, 3);
    assert_eq!(flushed.min_key, b"a");
    assert_eq!(flushed.max_key, b"c");
    assert!(flushed.key.starts_with("audit_log/sst/"));
    assert!(flushed.key.ends_with(".sst"));

    // Exactly one object landed in the backend, at the returned key.
    let listed = backend.list_prefix("audit_log/sst/").await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, flushed.key);

    // The memtable is empty again post-flush.
    assert_eq!(table.get_unflushed(b"a").await, None);
    assert!(!table.should_flush().await);
}

/// The whole point of sealing: an unauthorized reader of the raw bucket
/// object shouldn't see plaintext row data, and a real `Cipher` for this
/// table (right key) must be able to open what got flushed.
#[tokio::test]
async fn a_flushed_object_is_encrypted_and_decodes_back_to_the_same_rows() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let cipher = test_cipher();
    let config = TableConfig::new(
        backend.clone(),
        cipher.clone(),
        "audit_log",
        dir.path().join("table.wal"),
    );
    let table = Table::open(config).await.unwrap();
    table.put(b"a".to_vec(), b"secret value".to_vec()).await.unwrap();
    let flushed = table.flush().await.unwrap().unwrap();

    let (sealed, etag) = backend.get(&flushed.key).await.unwrap();
    assert!(etag.is_some());
    assert!(
        !sealed.windows(b"secret value".len()).any(|w| w == b"secret value"),
        "plaintext row content must not appear in the sealed object"
    );

    let object = cipher.open(&flushed.key, &sealed).unwrap();
    let rows = sstable::read_all(&object).unwrap();
    assert_eq!(rows, vec![(b"a".to_vec(), MemValue::Put(b"secret value".to_vec()))]);
}

#[tokio::test]
async fn should_flush_reports_true_once_past_the_configured_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let config =
        TableConfig::new(backend, test_cipher(), "t", dir.path().join("table.wal")).with_flush_threshold_bytes(10);
    let table = Table::open(config).await.unwrap();
    assert!(!table.should_flush().await);
    table
        .put(b"key".to_vec(), b"value-longer-than-ten-bytes".to_vec())
        .await
        .unwrap();
    assert!(table.should_flush().await);
}

/// The actual point of the WAL: a fresh `Table::open` over the same WAL
/// path recovers writes that were never flushed, as if the process never
/// stopped.
#[tokio::test]
async fn reopening_a_table_replays_unflushed_writes() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let wal_path = dir.path().join("table.wal");
    {
        let config = TableConfig::new(backend.clone(), test_cipher(), "audit_log", wal_path.clone());
        let table = Table::open(config).await.unwrap();
        table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
        table.put(b"b".to_vec(), b"2".to_vec()).await.unwrap();
        // Table dropped here without ever flushing -- simulates a crash.
    }

    let config = TableConfig::new(backend, test_cipher(), "audit_log", wal_path);
    let reopened = Table::open(config).await.unwrap();
    assert_eq!(reopened.get_unflushed(b"a").await, Some(MemValue::Put(b"1".to_vec())));
    assert_eq!(reopened.get_unflushed(b"b").await, Some(MemValue::Put(b"2".to_vec())));
}

/// After a successful flush, reopening must NOT replay the already-flushed
/// writes again -- the WAL was reset, so a fresh memtable should be empty.
#[tokio::test]
async fn reopening_after_a_flush_starts_with_an_empty_memtable() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let wal_path = dir.path().join("table.wal");
    {
        let config = TableConfig::new(backend.clone(), test_cipher(), "audit_log", wal_path.clone());
        let table = Table::open(config).await.unwrap();
        table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
        table.flush().await.unwrap();
    }

    let config = TableConfig::new(backend, test_cipher(), "audit_log", wal_path);
    let reopened = Table::open(config).await.unwrap();
    assert_eq!(reopened.get_unflushed(b"a").await, None);
}

#[tokio::test]
async fn two_tables_with_different_roots_never_collide_in_the_same_bucket() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let cipher = test_cipher();

    let table_a = Table::open(TableConfig::new(
        backend.clone(),
        cipher.clone(),
        "table_a",
        dir.path().join("a.wal"),
    ))
    .await
    .unwrap();
    let table_b = Table::open(TableConfig::new(
        backend.clone(),
        cipher,
        "table_b",
        dir.path().join("b.wal"),
    ))
    .await
    .unwrap();

    table_a.put(b"k".to_vec(), b"from a".to_vec()).await.unwrap();
    table_b.put(b"k".to_vec(), b"from b".to_vec()).await.unwrap();
    let flushed_a = table_a.flush().await.unwrap().unwrap();
    let flushed_b = table_b.flush().await.unwrap().unwrap();

    assert!(flushed_a.key.starts_with("table_a/sst/"));
    assert!(flushed_b.key.starts_with("table_b/sst/"));
    assert_ne!(flushed_a.key, flushed_b.key);
    assert_eq!(backend.list_prefix("table_a/sst/").await.unwrap().len(), 1);
    assert_eq!(backend.list_prefix("table_b/sst/").await.unwrap().len(), 1);
}
