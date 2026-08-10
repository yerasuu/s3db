use super::*;

#[tokio::test]
async fn replay_of_a_missing_file_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let replayed = Wal::replay(&dir.path().join("nope.wal")).await.unwrap();
    assert!(replayed.is_empty());
}

#[tokio::test]
async fn append_put_then_replay_recovers_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone()).await.unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.append_put(b"b", b"2").await.unwrap();

    let replayed = Wal::replay(&path).await.unwrap();
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Put(b"1".to_vec())));
    assert_eq!(replayed.get(b"b".as_slice()), Some(&MemValue::Put(b"2".to_vec())));
}

#[tokio::test]
async fn append_delete_then_replay_recovers_a_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone()).await.unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.append_delete(b"a").await.unwrap();

    let replayed = Wal::replay(&path).await.unwrap();
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Tombstone));
}

#[tokio::test]
async fn a_later_record_for_the_same_key_wins_on_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone()).await.unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.append_put(b"a", b"2").await.unwrap();

    let replayed = Wal::replay(&path).await.unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Put(b"2".to_vec())));
}

#[tokio::test]
async fn reset_truncates_and_appends_resume_from_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone()).await.unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.reset().await.unwrap();
    assert!(Wal::replay(&path).await.unwrap().is_empty());

    wal.append_put(b"b", b"2").await.unwrap();
    let replayed = Wal::replay(&path).await.unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed.get(b"b".as_slice()), Some(&MemValue::Put(b"2".to_vec())));
}

/// Simulates a crash mid-append: the file ends with a record that declares
/// more bytes than actually follow. Replay must recover everything before
/// it and stop cleanly, not error the whole log.
#[tokio::test]
async fn replay_recovers_everything_before_a_truncated_trailing_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    {
        let mut wal = Wal::open(path.clone()).await.unwrap();
        wal.append_put(b"a", b"1").await.unwrap();
    }
    // Append a record whose declared value_len runs past what's written --
    // exactly what a crash mid-write_all would leave behind.
    let mut partial = Vec::new();
    partial.push(TAG_PUT);
    partial.extend_from_slice(&4u32.to_le_bytes()); // key_len = 4
    partial.extend_from_slice(b"key1");
    partial.extend_from_slice(&1000u32.to_le_bytes()); // value_len claims 1000 bytes
    partial.extend_from_slice(b"only a few"); // far fewer than declared
    tokio::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .await
        .unwrap()
        .write_all(&partial)
        .await
        .unwrap();

    let replayed = Wal::replay(&path).await.unwrap();
    assert_eq!(
        replayed.len(),
        1,
        "the complete record before the truncated one must survive"
    );
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Put(b"1".to_vec())));
}

#[tokio::test]
async fn replay_of_an_empty_file_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    Wal::open(path.clone()).await.unwrap(); // creates an empty file, no appends
    assert!(Wal::replay(&path).await.unwrap().is_empty());
}
