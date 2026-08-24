use super::*;
use crate::backend::Backend;
use crate::cipher::Cipher;
use std::sync::Arc;

fn test_backend(root: &std::path::Path) -> Arc<dyn Backend> {
    Arc::new(crate::local::test_support::files_backend(root))
}

fn test_cipher() -> Cipher {
    Cipher::derive("test passphrase", &[7u8; crate::cipher::SALT_LEN]).unwrap()
}

async fn open_index(dir: &std::path::Path) -> SecondaryLsmIndex {
    let backend = test_backend(dir);
    let config = TableConfig::new(backend, test_cipher(), "by_status", dir.join("index.wal"));
    SecondaryLsmIndex::open(config).await.unwrap()
}

#[test]
fn compose_key_then_split_key_round_trips() {
    let composite = compose_key(b"active", b"row-1");
    assert_eq!(
        split_key(&composite).unwrap(),
        (b"active".as_slice(), b"row-1".as_slice())
    );
}

#[test]
fn split_key_rejects_a_key_with_no_separator() {
    assert!(split_key(b"no-separator-here").is_err());
}

#[test]
fn prefix_successor_increments_the_last_byte() {
    assert_eq!(prefix_successor(b"ab\x00"), Some(b"ab\x01".to_vec()));
}

#[test]
fn prefix_successor_drops_trailing_ff_bytes_before_incrementing() {
    assert_eq!(prefix_successor(&[0x61, 0xFF]), Some(vec![0x62]));
}

#[test]
fn prefix_successor_of_all_ff_bytes_is_none() {
    assert_eq!(prefix_successor(&[0xFF, 0xFF]), None);
}

#[tokio::test]
async fn lookup_finds_every_primary_key_put_under_a_secondary_key() {
    let dir = tempfile::tempdir().unwrap();
    let index = open_index(dir.path()).await;
    index.put(b"active", b"row-1").await.unwrap();
    index.put(b"active", b"row-2").await.unwrap();
    index.put(b"archived", b"row-3").await.unwrap();

    let mut found = index.lookup(b"active").await.unwrap();
    found.sort();
    assert_eq!(found, vec![b"row-1".to_vec(), b"row-2".to_vec()]);
}

#[tokio::test]
async fn lookup_of_an_unindexed_secondary_key_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let index = open_index(dir.path()).await;
    index.put(b"active", b"row-1").await.unwrap();
    assert_eq!(index.lookup(b"archived").await.unwrap(), Vec::<LsmKey>::new());
}

/// The whole reason `lookup`'s upper bound includes the separator: without
/// it, looking up `"ab"` would also match everything indexed under the
/// longer secondary key `"abc"`, since `"abc\0..."` sorts between `"ab\0..."`
/// and a bare `prefix_successor("ab")`.
#[tokio::test]
async fn lookup_does_not_bleed_into_a_secondary_key_that_shares_a_byte_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let index = open_index(dir.path()).await;
    index.put(b"ab", b"row-short").await.unwrap();
    index.put(b"abc", b"row-long").await.unwrap();

    assert_eq!(index.lookup(b"ab").await.unwrap(), vec![b"row-short".to_vec()]);
    assert_eq!(index.lookup(b"abc").await.unwrap(), vec![b"row-long".to_vec()]);
}

#[tokio::test]
async fn delete_removes_a_primary_key_from_its_secondary_keys_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let index = open_index(dir.path()).await;
    index.put(b"active", b"row-1").await.unwrap();
    index.put(b"active", b"row-2").await.unwrap();
    index.delete(b"active", b"row-1").await.unwrap();
    assert_eq!(index.lookup(b"active").await.unwrap(), vec![b"row-2".to_vec()]);
}

/// A lookup/delete pair must survive a real flush, not just live in the
/// memtable -- exercises the underlying `Table::scan`'s SSTable path.
#[tokio::test]
async fn lookup_finds_entries_after_a_flush() {
    let dir = tempfile::tempdir().unwrap();
    let backend = test_backend(dir.path());
    let config = TableConfig::new(backend, test_cipher(), "by_status", dir.path().join("index.wal"));
    let index = SecondaryLsmIndex::open(config).await.unwrap();
    index.put(b"active", b"row-1").await.unwrap();
    index.put(b"archived", b"row-2").await.unwrap();
    index.table.flush().await.unwrap();

    assert_eq!(index.lookup(b"active").await.unwrap(), vec![b"row-1".to_vec()]);
    assert_eq!(index.lookup(b"archived").await.unwrap(), vec![b"row-2".to_vec()]);
}

#[tokio::test]
async fn scan_returns_pairs_ordered_by_the_composite_key() {
    let dir = tempfile::tempdir().unwrap();
    let index = open_index(dir.path()).await;
    index.put(b"2026-01-01", b"row-a").await.unwrap();
    index.put(b"2026-06-01", b"row-b").await.unwrap();
    index.put(b"2026-12-01", b"row-c").await.unwrap();

    let found = index.scan(Some(b"2026-02-01"), Some(b"2026-12-01")).await.unwrap();
    assert_eq!(found, vec![(b"2026-06-01".to_vec(), b"row-b".to_vec())]);
}

#[tokio::test]
async fn scan_with_no_bounds_returns_every_pair() {
    let dir = tempfile::tempdir().unwrap();
    let index = open_index(dir.path()).await;
    index.put(b"a", b"row-1").await.unwrap();
    index.put(b"b", b"row-2").await.unwrap();

    let found = index.scan(None, None).await.unwrap();
    assert_eq!(
        found,
        vec![(b"a".to_vec(), b"row-1".to_vec()), (b"b".to_vec(), b"row-2".to_vec())]
    );
}
