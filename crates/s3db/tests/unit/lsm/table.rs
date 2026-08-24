use super::*;
use crate::backend::DeleteOutcome;
use crate::lsm::value::{ColumnDef, ValueKind};
use std::time::Duration;

fn test_backend(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(crate::local::test_support::files_backend(root))
}

fn test_cipher() -> Cipher {
    Cipher::derive("test passphrase", &[13u8; crate::cipher::SALT_LEN]).unwrap()
}

async fn open_table(dir: &std::path::Path) -> Table {
    let backend = test_backend(dir);
    let config = TableConfig::new(backend, test_cipher(), "audit_log", dir.join("table.wal"));
    Table::open(config).await.unwrap()
}

/// Wraps a real backend so `put_cas` can be made to sleep and/or fail on
/// demand -- lets a test observe what happens *during* `Table::flush`'s
/// network I/O (a concurrent `put`'s own latency, what a failure restores)
/// instead of only ever seeing the before/after.
#[derive(Debug)]
struct FaultyPutCas {
    inner: Arc<dyn Backend>,
    delay: Duration,
    fail: bool,
}

#[async_trait::async_trait]
impl Backend for FaultyPutCas {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.inner.get(key).await
    }
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        tokio::time::sleep(self.delay).await;
        if self.fail {
            anyhow::bail!("simulated put_cas failure");
        }
        self.inner.put_cas(key, body, expected_etag).await
    }
    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        self.inner.delete(key).await
    }
    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        self.inner.delete_many(keys).await
    }
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner.list_prefix(prefix).await
    }
    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.inner.get_range(key, offset, len).await
    }
    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &std::path::Path) -> Result<()> {
        self.inner.put_stream(key, source).await
    }
    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &std::path::Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
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

    let rows = sstable::read_all(&cipher, &flushed.key, None, &object).unwrap();
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

fn people_schema() -> Schema {
    Schema::new(vec![
        ColumnDef {
            name: "age".to_string(),
            kind: ValueKind::Int64,
        },
        ColumnDef {
            name: "name".to_string(),
            kind: ValueKind::Text,
        },
    ])
}

async fn open_typed_table(dir: &std::path::Path) -> Table {
    let backend = test_backend(dir);
    let config = TableConfig::new(backend, test_cipher(), "people", dir.join("table.wal")).with_schema(people_schema());
    Table::open(config).await.unwrap()
}

#[tokio::test]
async fn put_typed_then_get_typed_round_trips_before_any_flush() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_typed_table(dir.path()).await;
    table
        .put_typed(b"a".to_vec(), vec![Value::Int64(30), Value::Text("alice".into())])
        .await
        .unwrap();
    assert_eq!(
        table.get_typed(b"a").await.unwrap(),
        Some(vec![Value::Int64(30), Value::Text("alice".into())])
    );
}

#[tokio::test]
async fn put_typed_rejects_a_row_that_does_not_match_the_schema() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_typed_table(dir.path()).await;
    let err = table
        .put_typed(b"a".to_vec(), vec![Value::Text("wrong shape".into())])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("value"), "got: {err}");
}

#[tokio::test]
async fn put_typed_on_a_schema_less_table_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await; // no schema
    let err = table.put_typed(b"a".to_vec(), vec![Value::Int64(1)]).await.unwrap_err();
    assert!(err.to_string().contains("schema"), "got: {err}");
}

#[tokio::test]
async fn get_typed_on_a_schema_less_table_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    let err = table.get_typed(b"a").await.unwrap_err();
    assert!(err.to_string().contains("schema"), "got: {err}");
}

/// The actual point of phase 4: a typed row survives a real flush (through
/// the columnar block encoder) and reads back correctly through the
/// ordinary `get_range`-driven path, indistinguishable from the outside.
#[tokio::test]
async fn put_typed_survives_a_flush_and_reads_back_via_get_typed() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_typed_table(dir.path()).await;
    table
        .put_typed(b"a".to_vec(), vec![Value::Int64(30), Value::Text("alice".into())])
        .await
        .unwrap();
    table
        .put_typed(b"b".to_vec(), vec![Value::Int64(25), Value::Text("bob".into())])
        .await
        .unwrap();
    table.flush().await.unwrap();

    assert_eq!(
        table.get_typed(b"a").await.unwrap(),
        Some(vec![Value::Int64(30), Value::Text("alice".into())])
    );
    assert_eq!(
        table.get_typed(b"b").await.unwrap(),
        Some(vec![Value::Int64(25), Value::Text("bob".into())])
    );
}

/// A flushed typed block's `column_stats` (fetched exactly the way a real
/// point lookup would -- via the footer's own `get_range`) must reflect the
/// actual min/max of what got written, which is the whole reason phase 4
/// exists: a future range scan can trust these without decoding the block.
#[tokio::test]
async fn a_flushed_typed_blocks_column_stats_reflect_its_rows() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let cipher = test_cipher();
    let config = TableConfig::new(backend.clone(), cipher.clone(), "people", dir.path().join("table.wal"))
        .with_schema(people_schema());
    let table = Table::open(config).await.unwrap();
    table
        .put_typed(b"a".to_vec(), vec![Value::Int64(30), Value::Text("charlie".into())])
        .await
        .unwrap();
    table
        .put_typed(b"b".to_vec(), vec![Value::Int64(10), Value::Text("alice".into())])
        .await
        .unwrap();
    table.flush().await.unwrap();

    let (manifest, _) = manifest::load(backend.as_ref(), &cipher, "people").await.unwrap();
    let entry = &manifest.sstables[0];
    let footer_offset = entry.byte_len - 8 - entry.footer_len;
    let sealed_footer = backend
        .get_range(&entry.key, footer_offset, entry.footer_len)
        .await
        .unwrap();
    let (_, block_index) = sstable::open_footer_bytes(&cipher, &entry.key, &sealed_footer).unwrap();
    assert_eq!(block_index.len(), 1);
    let stats = &block_index[0].column_stats;
    assert_eq!(stats[0].min, Some(Value::Int64(10)));
    assert_eq!(stats[0].max, Some(Value::Int64(30)));
    assert_eq!(stats[1].min, Some(Value::Text("alice".into())));
    assert_eq!(stats[1].max, Some(Value::Text("charlie".into())));
}

/// A schema-less table's blocks must not suddenly grow stats -- there's no
/// schema to have per-column stats about.
#[tokio::test]
async fn a_schema_less_tables_blocks_have_no_column_stats() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let cipher = test_cipher();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.flush().await.unwrap();

    let (manifest, _) = manifest::load(backend.as_ref(), &cipher, "audit_log").await.unwrap();
    let entry = &manifest.sstables[0];
    let footer_offset = entry.byte_len - 8 - entry.footer_len;
    let sealed_footer = backend
        .get_range(&entry.key, footer_offset, entry.footer_len)
        .await
        .unwrap();
    let (_, block_index) = sstable::open_footer_bytes(&cipher, &entry.key, &sealed_footer).unwrap();
    assert!(block_index[0].column_stats.is_empty());
}

/// Compaction works the same way on a typed table -- merges through the
/// columnar codec, not the row-oriented one.
#[tokio::test]
async fn compact_works_on_a_typed_table() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_typed_table(dir.path()).await;
    table
        .put_typed(b"a".to_vec(), vec![Value::Int64(1), Value::Text("old".into())])
        .await
        .unwrap();
    table.flush().await.unwrap();
    table
        .put_typed(b"a".to_vec(), vec![Value::Int64(2), Value::Text("new".into())])
        .await
        .unwrap();
    table.flush().await.unwrap();

    let report = table.compact().await.unwrap();
    assert_eq!(report.sstables_after, 1);
    assert_eq!(
        table.get_typed(b"a").await.unwrap(),
        Some(vec![Value::Int64(2), Value::Text("new".into())])
    );
}

fn scan_keys(rows: &[(LsmKey, Vec<u8>)]) -> Vec<&[u8]> {
    rows.iter().map(|(k, _)| k.as_slice()).collect()
}

#[tokio::test]
async fn scan_with_both_bounds_is_start_inclusive_end_exclusive_before_any_flush() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    for key in [b"a", b"b", b"c", b"d"] {
        table.put(key.to_vec(), key.to_vec()).await.unwrap();
    }
    let found = table.scan(Some(b"b"), Some(b"d")).await.unwrap();
    assert_eq!(scan_keys(&found), vec![b"b".as_slice(), b"c".as_slice()]);
}

#[tokio::test]
async fn scan_with_no_bounds_returns_everything_unflushed_and_flushed() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.put(b"b".to_vec(), b"2".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.put(b"c".to_vec(), b"3".to_vec()).await.unwrap(); // still unflushed

    let found = table.scan(None, None).await.unwrap();
    assert_eq!(
        scan_keys(&found),
        vec![b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
    );
}

/// The memtable must win over an older flushed value for the same key, just
/// like `get` -- scan merges the same way, just over a range.
#[tokio::test]
async fn scan_prefers_the_unflushed_value_over_an_older_flushed_one() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"old".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.put(b"a".to_vec(), b"new".to_vec()).await.unwrap();

    let found = table.scan(None, None).await.unwrap();
    assert_eq!(found, vec![(b"a".to_vec(), b"new".to_vec())]);
}

/// An unflushed tombstone must drop a key from the scan entirely, not just
/// leave its old flushed value in place.
#[tokio::test]
async fn scan_excludes_a_key_deleted_after_its_flush() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();
    table.put(b"b".to_vec(), b"2".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    table.delete(b"a".to_vec()).await.unwrap();

    let found = table.scan(None, None).await.unwrap();
    assert_eq!(found, vec![(b"b".to_vec(), b"2".to_vec())]);
}

/// Exercises the real multi-block, multi-SSTable path: a range that spans
/// several blocks within one SSTable, plus a second SSTable entirely outside
/// the requested range that must contribute nothing.
#[tokio::test]
async fn scan_finds_rows_across_many_blocks_and_skips_sstables_outside_the_range() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let config =
        TableConfig::new(backend, test_cipher(), "audit_log", dir.path().join("table.wal")).with_rows_per_block(3);
    let table = Table::open(config).await.unwrap();

    for i in 0..30u32 {
        table
            .put(format!("k{i:03}").into_bytes(), format!("v{i}").into_bytes())
            .await
            .unwrap();
    }
    table.flush().await.unwrap();

    // A second SSTable entirely outside the range below -- must be skipped.
    table.put(b"z-outside".to_vec(), b"nope".to_vec()).await.unwrap();
    table.flush().await.unwrap();

    let found = table.scan(Some(b"k010"), Some(b"k015")).await.unwrap();
    let expected: Vec<_> = (10..15u32)
        .map(|i| (format!("k{i:03}").into_bytes(), format!("v{i}").into_bytes()))
        .collect();
    assert_eq!(found, expected);
}

#[tokio::test]
async fn scan_typed_on_a_schema_less_table_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    let err = table.scan_typed(None, None).await.unwrap_err();
    assert!(err.to_string().contains("schema"), "got: {err}");
}

#[tokio::test]
async fn scan_typed_where_returns_only_rows_matching_every_predicate() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_typed_table(dir.path()).await;
    table
        .put_typed(b"a".to_vec(), vec![Value::Int64(30), Value::Text("alice".into())])
        .await
        .unwrap();
    table
        .put_typed(b"b".to_vec(), vec![Value::Int64(25), Value::Text("bob".into())])
        .await
        .unwrap();
    table
        .put_typed(b"c".to_vec(), vec![Value::Int64(40), Value::Text("carol".into())])
        .await
        .unwrap();

    let found = table
        .scan_typed_where(None, None, &[query::Predicate::Gt(0, Value::Int64(25))])
        .await
        .unwrap();
    assert_eq!(
        found,
        vec![
            (b"a".to_vec(), vec![Value::Int64(30), Value::Text("alice".into())]),
            (b"c".to_vec(), vec![Value::Int64(40), Value::Text("carol".into())]),
        ]
    );
}

/// The actual point of phase 8: a predicate that a whole block's
/// `column_stats` rules out must still produce the correct answer once
/// merged with the blocks that do get read -- pruning is invisible from
/// the result's point of view.
#[tokio::test]
async fn scan_typed_where_prunes_whole_blocks_but_still_returns_the_right_rows() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let config = TableConfig::new(backend, test_cipher(), "people", dir.path().join("table.wal"))
        .with_schema(people_schema())
        .with_rows_per_block(2);
    let table = Table::open(config).await.unwrap();

    // Block 0: ages 0..2 (both < 100). Block 1: ages 2..4 (both >= 100).
    for i in 0..4u32 {
        let age = if i < 2 { i as i64 } else { 100 + i as i64 };
        table
            .put_typed(
                format!("k{i:03}").into_bytes(),
                vec![Value::Int64(age), Value::Text(format!("p{i}"))],
            )
            .await
            .unwrap();
    }
    table.flush().await.unwrap();

    let found = table
        .scan_typed_where(None, None, &[query::Predicate::Gte(0, Value::Int64(100))])
        .await
        .unwrap();
    assert_eq!(
        found,
        vec![
            (b"k002".to_vec(), vec![Value::Int64(102), Value::Text("p2".into())]),
            (b"k003".to_vec(), vec![Value::Int64(103), Value::Text("p3".into())]),
        ]
    );
}

#[tokio::test]
async fn scan_typed_where_on_a_schema_less_table_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;
    let err = table.scan_typed_where(None, None, &[]).await.unwrap_err();
    assert!(err.to_string().contains("schema"), "got: {err}");
}

/// A predicate must also apply to unflushed memtable rows, not just
/// SSTable ones -- `scan_merged` doesn't prune those (nothing to prune, no
/// blocks), but the final per-row check still has to filter them.
#[tokio::test]
async fn scan_typed_where_filters_unflushed_rows_too() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_typed_table(dir.path()).await;
    table
        .put_typed(b"a".to_vec(), vec![Value::Int64(1), Value::Text("low".into())])
        .await
        .unwrap();
    table
        .put_typed(b"b".to_vec(), vec![Value::Int64(99), Value::Text("high".into())])
        .await
        .unwrap();

    let found = table
        .scan_typed_where(None, None, &[query::Predicate::Eq(1, Value::Text("high".into()))])
        .await
        .unwrap();
    assert_eq!(
        found,
        vec![(b"b".to_vec(), vec![Value::Int64(99), Value::Text("high".into())])]
    );
}

#[tokio::test]
async fn scan_typed_decodes_rows_across_memtable_and_a_flushed_sstable() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_typed_table(dir.path()).await;
    table
        .put_typed(b"a".to_vec(), vec![Value::Int64(30), Value::Text("alice".into())])
        .await
        .unwrap();
    table.flush().await.unwrap();
    table
        .put_typed(b"b".to_vec(), vec![Value::Int64(25), Value::Text("bob".into())])
        .await
        .unwrap();

    let found = table.scan_typed(None, None).await.unwrap();
    assert_eq!(
        found,
        vec![
            (b"a".to_vec(), vec![Value::Int64(30), Value::Text("alice".into())]),
            (b"b".to_vec(), vec![Value::Int64(25), Value::Text("bob".into())]),
        ]
    );
}

#[tokio::test]
async fn flush_does_not_block_a_concurrent_put() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(FaultyPutCas {
        inner: test_backend(dir.path()),
        delay: Duration::from_millis(300),
        fail: false,
    });
    let config = TableConfig::new(backend, test_cipher(), "audit_log", dir.path().join("table.wal"));
    let table = Arc::new(Table::open(config).await.unwrap());
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();

    let flush_table = Arc::clone(&table);
    let flush_task = tokio::spawn(async move { flush_table.flush().await });
    // Give the flush a moment to be sitting inside its (delayed) put_cas,
    // not still holding the table's state lock.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = std::time::Instant::now();
    table.put(b"b".to_vec(), b"2".to_vec()).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "a concurrent put must not wait for the in-flight flush's network I/O, took {:?}",
        started.elapsed()
    );

    flush_task.await.unwrap().unwrap();
    assert_eq!(table.get_unflushed(b"b").await, Some(MemValue::Put(b"2".to_vec())));
}

#[tokio::test]
async fn flush_failure_restores_the_row_into_the_live_memtable() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(FaultyPutCas {
        inner: test_backend(dir.path()),
        delay: Duration::ZERO,
        fail: true,
    });
    let config = TableConfig::new(backend, test_cipher(), "audit_log", dir.path().join("table.wal"));
    let table = Table::open(config).await.unwrap();
    table.put(b"a".to_vec(), b"1".to_vec()).await.unwrap();

    assert!(
        table.flush().await.is_err(),
        "the simulated put_cas failure must surface"
    );
    assert_eq!(
        table.get_unflushed(b"a").await,
        Some(MemValue::Put(b"1".to_vec())),
        "a failed flush must restore the drained row instead of losing it"
    );

    // The table is still fully usable afterward -- the post-rotation WAL
    // generation this restore wrote into isn't left in a broken state.
    table.put(b"b".to_vec(), b"2".to_vec()).await.unwrap();
    assert_eq!(table.get_unflushed(b"b").await, Some(MemValue::Put(b"2".to_vec())));
}

#[tokio::test]
async fn flush_failure_does_not_clobber_a_write_that_landed_during_it() {
    let dir = tempfile::tempdir().unwrap();
    let backend: Arc<dyn Backend> = Arc::new(FaultyPutCas {
        inner: test_backend(dir.path()),
        delay: Duration::from_millis(150),
        fail: true,
    });
    let config = TableConfig::new(backend, test_cipher(), "audit_log", dir.path().join("table.wal"));
    let table = Arc::new(Table::open(config).await.unwrap());
    table.put(b"a".to_vec(), b"old".to_vec()).await.unwrap();

    let flush_table = Arc::clone(&table);
    let flush_task = tokio::spawn(async move { flush_table.flush().await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    // Lands on the fresh post-rotation memtable/WAL while the doomed flush
    // is still sleeping inside its own put_cas.
    table.put(b"a".to_vec(), b"new".to_vec()).await.unwrap();

    assert!(flush_task.await.unwrap().is_err());
    assert_eq!(
        table.get_unflushed(b"a").await,
        Some(MemValue::Put(b"new".to_vec())),
        "the write that landed during the failed flush must win over the value it restores"
    );
}

/// How a non-writer process reads an LSM table. Opening it with `open` instead
/// would create a WAL, accept writes and eventually flush them, becoming the
/// second writer the lease exists to prevent — without anyone having asked.
#[tokio::test]
async fn a_read_only_table_reads_flushed_rows_and_refuses_every_write() {
    let dir = tempfile::tempdir().unwrap();
    let writer = open_table(dir.path()).await;
    writer.put(LsmKey::from(b"k".to_vec()), b"v".to_vec()).await.unwrap();
    writer.flush().await.unwrap();

    let reader_config = TableConfig::new(
        test_backend(dir.path()),
        test_cipher(),
        "audit_log",
        dir.path().join("reader.wal"),
    );
    let reader = Table::open_read_only(reader_config).await.unwrap();

    assert!(reader.is_read_only());
    assert_eq!(
        reader.get(b"k").await.unwrap().as_deref(),
        Some(b"v".as_slice()),
        "a reader sees everything that was flushed"
    );
    assert!(
        !dir.path().join("reader.wal").exists(),
        "a read-only table must not create a WAL at all"
    );

    for result in [
        reader.put(LsmKey::from(b"x".to_vec()), b"1".to_vec()).await,
        reader.delete(LsmKey::from(b"k".to_vec())).await,
        reader.flush().await.map(|_| ()),
        reader.compact().await.map(|_| ()),
    ] {
        let err = result.unwrap_err();
        assert!(err.to_string().contains("read-only"), "{err}");
    }
}

/// A reader sees flushed rows and nothing else, which is what bounds its
/// staleness to the writer's flush interval.
#[tokio::test]
async fn a_read_only_table_does_not_see_unflushed_writes() {
    let dir = tempfile::tempdir().unwrap();
    let writer = open_table(dir.path()).await;
    writer.put(LsmKey::from(b"held".to_vec()), b"v".to_vec()).await.unwrap();

    let reader = Table::open_read_only(TableConfig::new(
        test_backend(dir.path()),
        test_cipher(),
        "audit_log",
        dir.path().join("reader.wal"),
    ))
    .await
    .unwrap();
    assert_eq!(reader.get(b"held").await.unwrap(), None, "not published yet");

    writer.flush().await.unwrap();
    assert_eq!(
        reader.get(b"held").await.unwrap().as_deref(),
        Some(b"v".as_slice()),
        "and visible right after the flush"
    );
}

#[tokio::test]
async fn a_table_holding_a_lease_writes_normally_and_reports_its_holder() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let lease = crate::lsm::WriterLease::acquire(
        backend.as_ref(),
        &test_cipher(),
        "audit_log",
        "writer-a",
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    let table = Table::open(
        TableConfig::new(backend, test_cipher(), "audit_log", dir.path().join("t.wal")).with_writer_lease(lease),
    )
    .await
    .unwrap();

    table.put(LsmKey::from(b"k".to_vec()), b"v".to_vec()).await.unwrap();
    table.flush().await.unwrap();
    assert_eq!(table.get(b"k").await.unwrap().as_deref(), Some(b"v".as_slice()));
    assert_eq!(table.lease_holder().await.unwrap().as_deref(), Some("writer-a"));

    table.renew_lease().await.unwrap();
    table.release_lease().await;
    assert_eq!(table.lease_holder().await.unwrap(), None);

    let err = table.put(LsmKey::from(b"x".to_vec()), b"1".to_vec()).await.unwrap_err();
    assert!(
        err.to_string().contains("released its writer lease"),
        "giving up the lease must revoke this handle's right to write, not restore it: {err}"
    );
    assert!(table.renew_lease().await.is_err(), "and there is nothing left to renew");
}

/// A lease that stopped being renewed makes this handle refuse writes, rather
/// than keep them coming from a process another one has taken over from.
#[tokio::test]
async fn a_locally_expired_lease_stops_the_writes() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let lease = crate::lsm::WriterLease::acquire(
        backend.as_ref(),
        &test_cipher(),
        "audit_log",
        "writer-a",
        // Short enough to lapse during the test, long enough that a renewal
        // then leaves comfortable room to write.
        Duration::from_millis(200),
    )
    .await
    .unwrap();
    let table = Table::open(
        TableConfig::new(backend, test_cipher(), "audit_log", dir.path().join("t.wal")).with_writer_lease(lease),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let err = table.put(LsmKey::from(b"k".to_vec()), b"v".to_vec()).await.unwrap_err();

    assert!(err.to_string().contains("expired locally"), "{err}");
    assert!(err.to_string().contains("writer-a"), "{err}");
    // Renewing brings it back, which is what a renewal timer is for.
    table.renew_lease().await.unwrap();
    assert!(
        table.put(LsmKey::from(b"k".to_vec()), b"v".to_vec()).await.is_ok(),
        "a renewed lease must accept writes again"
    );
}

#[tokio::test]
async fn a_table_without_a_lease_behaves_exactly_as_before() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path()).await;

    table.put(LsmKey::from(b"k".to_vec()), b"v".to_vec()).await.unwrap();

    assert!(!table.is_read_only());
    assert_eq!(table.lease_holder().await.unwrap(), None);
    table.renew_lease().await.unwrap(); // no-op, so a renewal timer needs no branch
    assert_eq!(table.get(b"k").await.unwrap().as_deref(), Some(b"v".as_slice()));
}
