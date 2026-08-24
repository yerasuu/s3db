use super::*;
use crate::lsm::{LsmKey, Table, TableConfig, manifest};
use std::sync::Arc;

fn test_backend(root: &std::path::Path) -> Arc<dyn crate::backend::Backend> {
    Arc::new(crate::local::test_support::files_backend(root))
}

fn test_cipher() -> crate::cipher::Cipher {
    crate::cipher::Cipher::derive("test passphrase", &[19u8; crate::cipher::SALT_LEN]).unwrap()
}

/// A flush threshold small enough that a couple of rows reach it.
async fn open_table(dir: &std::path::Path, wal: &str, threshold: usize) -> Table {
    let config =
        TableConfig::new(test_backend(dir), test_cipher(), "rows", dir.join(wal)).with_flush_threshold_bytes(threshold);
    Table::open(config).await.unwrap()
}

async fn sstable_count(dir: &std::path::Path) -> usize {
    let (manifest, _etag) = manifest::load(test_backend(dir).as_ref(), &test_cipher(), "rows")
        .await
        .unwrap();
    manifest.sstables.len()
}

#[tokio::test]
async fn a_tick_on_a_quiet_table_does_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path(), "a.wal", 4096).await;

    let report = tick(&table, &LsmMaintenanceConfig::default()).await.unwrap();

    assert!(report.did_nothing(), "{report:?}");
    assert_eq!(sstable_count(dir.path()).await, 0);
}

/// The gap this closes: writes are acked into the WAL and nothing publishes
/// them until somebody flushes.
#[tokio::test]
async fn a_tick_flushes_a_memtable_that_reached_its_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path(), "a.wal", 64).await;
    for n in 0..8u32 {
        table
            .put(LsmKey::from(format!("k{n:04}").into_bytes()), vec![b'v'; 32])
            .await
            .unwrap();
    }
    assert!(table.should_flush().await, "the test's threshold should be reached");

    let report = tick(&table, &LsmMaintenanceConfig::default()).await.unwrap();

    assert!(report.flushed.is_some(), "{report:?}");
    assert_eq!(sstable_count(dir.path()).await, 1);
    assert!(table.is_empty().await, "a flushed memtable is empty");
}

#[tokio::test]
async fn a_small_memtable_is_left_alone_unless_asked_for() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path(), "a.wal", 1_000_000).await;
    table.put(LsmKey::from(b"k".to_vec()), b"v".to_vec()).await.unwrap();

    let held = tick(&table, &LsmMaintenanceConfig::default()).await.unwrap();
    assert!(held.did_nothing(), "under the threshold, nothing is due: {held:?}");
    assert_eq!(sstable_count(dir.path()).await, 0);

    let forced = tick(
        &table,
        &LsmMaintenanceConfig {
            flush_even_if_small: true,
            ..LsmMaintenanceConfig::default()
        },
    )
    .await
    .unwrap();
    assert!(
        forced.flushed.is_some(),
        "a caller whose readers are in other processes needs this: {forced:?}"
    );
    assert_eq!(sstable_count(dir.path()).await, 1);
}

/// `flush_even_if_small` must still not manufacture an empty SSTable.
#[tokio::test]
async fn forcing_a_flush_on_an_empty_memtable_still_does_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path(), "a.wal", 64).await;

    let report = tick(
        &table,
        &LsmMaintenanceConfig {
            flush_even_if_small: true,
            ..LsmMaintenanceConfig::default()
        },
    )
    .await
    .unwrap();

    assert!(report.did_nothing(), "{report:?}");
    assert_eq!(sstable_count(dir.path()).await, 0);
}

/// Flush before compact within one tick: the flush is what pushes the count
/// over the threshold, so the opposite order would always leave the newest
/// SSTable for a later tick.
#[tokio::test]
async fn the_tick_that_reaches_the_threshold_also_compacts() {
    let dir = tempfile::tempdir().unwrap();
    let forced = LsmMaintenanceConfig {
        flush_even_if_small: true,
        ..LsmMaintenanceConfig::default()
    };

    // Three flushes, one per tick, each below the compaction threshold of 4.
    for n in 0..3u32 {
        let table = open_table(dir.path(), &format!("w{n}.wal"), 1_000_000).await;
        table
            .put(LsmKey::from(format!("k{n}").into_bytes()), b"v".to_vec())
            .await
            .unwrap();
        let report = tick(&table, &forced).await.unwrap();
        assert!(report.flushed.is_some());
        assert!(report.compaction.is_none(), "not due yet at {} sstables", n + 1);
    }
    assert_eq!(sstable_count(dir.path()).await, 3);

    // The fourth flush reaches the threshold, so the same tick compacts.
    let table = open_table(dir.path(), "w3.wal", 1_000_000).await;
    table.put(LsmKey::from(b"k3".to_vec()), b"v".to_vec()).await.unwrap();
    let report = tick(&table, &forced).await.unwrap();

    assert!(report.flushed.is_some(), "{report:?}");
    assert!(report.compaction.is_some(), "four sstables is due: {report:?}");
    assert_eq!(
        sstable_count(dir.path()).await,
        1,
        "compaction merges every sstable into one"
    );
    // Every row still reads back after the merge.
    for n in 0..4u32 {
        let key = format!("k{n}");
        assert_eq!(
            table.get(key.as_bytes()).await.unwrap().as_deref(),
            Some(b"v".as_slice()),
            "{key} must survive compaction"
        );
    }
}

#[tokio::test]
async fn each_pass_can_be_turned_off_independently() {
    let dir = tempfile::tempdir().unwrap();
    let table = open_table(dir.path(), "a.wal", 64).await;
    for n in 0..8u32 {
        table
            .put(LsmKey::from(format!("k{n:04}").into_bytes()), vec![b'v'; 32])
            .await
            .unwrap();
    }

    let report = tick(
        &table,
        &LsmMaintenanceConfig {
            flush: false,
            compact: false,
            flush_even_if_small: true,
        },
    )
    .await
    .unwrap();

    assert!(report.did_nothing(), "{report:?}");
    assert!(!table.is_empty().await, "the memtable must be untouched");
    assert_eq!(sstable_count(dir.path()).await, 0);
}
