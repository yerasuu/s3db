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

#[tokio::test]
async fn flush_records_the_sstable_in_the_manifest() {
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
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    let flushed = table.flush().await.unwrap().unwrap();

    let (manifest, _) = manifest::load(backend.as_ref(), &cipher, "audit_log").await.unwrap();
    assert_eq!(manifest.sstables.len(), 1);
    let entry = &manifest.sstables[0];
    assert_eq!(entry.key, flushed.key);
    assert_eq!(entry.min_key, flushed.min_key);
    assert_eq!(entry.max_key, flushed.max_key);
    assert_eq!(entry.byte_len, flushed.byte_len);
    assert_eq!(entry.footer_len, flushed.footer_len);
    assert_eq!(entry.level, 0);
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

    let (object, etag) = backend.get(&flushed.key).await.unwrap();
    assert!(etag.is_some());
    assert!(
        !object.windows(b"secret value".len()).any(|w| w == b"secret value"),
        "plaintext row content must not appear in the stored object"
    );

    let rows = sstable::read_all(&cipher, &flushed.key, &object).unwrap();
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

#[tokio::test]
async fn get_finds_a_row_that_was_never_flushed() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    assert_eq!(table.get(b"a").await.unwrap(), Some(b"1".to_vec()));
}

#[tokio::test]
async fn get_of_a_never_written_key_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    assert_eq!(table.get(b"nope").await.unwrap(), None);
}

/// The actual point of phase 2: a row survives being flushed and remains
/// findable purely through the manifest + `get_range`-driven lookup, with
/// nothing left in the memtable to answer from.
#[tokio::test]
async fn get_finds_a_row_after_it_has_been_flushed() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.put(b"b".to_vec(), b"2".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    assert_eq!(
        table.get_unflushed(b"a").await,
        None,
        "sanity: memtable really is empty"
    );

    assert_eq!(table.get(b"a").await.unwrap(), Some(b"1".to_vec()));
    assert_eq!(table.get(b"b").await.unwrap(), Some(b"2".to_vec()));
    assert_eq!(table.get(b"missing").await.unwrap(), None);
}

/// A row deleted after being flushed must read back as gone, not as its
/// last flushed value -- the tombstone (in the memtable, since delete
/// hasn't been flushed yet) has to win over the older, still-present
/// SSTable entry.
#[tokio::test]
async fn get_prefers_an_unflushed_tombstone_over_an_older_flushed_value() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.delete(b"a".to_vec()).await.unwrap();
    assert_eq!(table.get(b"a").await.unwrap(), None);
}

/// Same as above, but the tombstone itself has also been flushed -- the
/// read has to walk the manifest newest-to-oldest and stop at the first
/// (newer) SSTable's tombstone rather than keep looking and finding the
/// older SSTable's stale value.
#[tokio::test]
async fn get_prefers_a_flushed_tombstone_over_an_older_flushed_value() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.delete(b"a".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    assert_eq!(table.get(b"a").await.unwrap(), None);
}

/// A key updated across two separate flushes must read back as the newer
/// value -- `get` walks the manifest newest-first specifically so this
/// works.
#[tokio::test]
async fn get_prefers_the_most_recently_flushed_value_across_two_sstables() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"old".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.put(b"a".to_vec(), b"new".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    assert_eq!(table.get(b"a").await.unwrap(), Some(b"new".to_vec()));
}

/// Exercises the real multi-block path: enough rows that `get` has to pick
/// the right block out of several via the block index, not just find the
/// only block there is.
#[tokio::test]
async fn get_finds_rows_across_many_blocks_in_one_sstable() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let config =
        TableConfig::new(backend, test_cipher(), "audit_log", dir.path().join("table.wal")).with_rows_per_block(3);
    let table = Table::open(config).await.unwrap();

    for i in 0..50u32 {
        table
            .put(format!("k{i:03}").into_bytes(), format!("v{i}").into_bytes())
            .await
            .unwrap();
    }
    let flushed = table.flush().await.unwrap().unwrap();
    assert!(flushed.row_count == 50);

    for i in [0u32, 1, 25, 48, 49] {
        assert_eq!(
            table.get(format!("k{i:03}").as_bytes()).await.unwrap(),
            Some(format!("v{i}").into_bytes()),
            "row {i}"
        );
    }
    assert_eq!(table.get(b"k999").await.unwrap(), None);
}

/// A key outside every SSTable's `[min_key, max_key]` range must be
/// answered without even fetching a footer -- this test only checks the
/// (correct) result, not the request count, but a wrong range check would
/// also just return the wrong answer here.
#[tokio::test]
async fn get_of_a_key_outside_every_sstables_range_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"m".to_vec(), b"mid".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    assert_eq!(table.get(b"a").await.unwrap(), None); // before the range
    assert_eq!(table.get(b"z").await.unwrap(), None); // after the range
}
