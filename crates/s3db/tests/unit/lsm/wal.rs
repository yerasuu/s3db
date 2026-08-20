use super::*;

/// One cipher and one AAD for every test here — the frames are sealed now
/// (see the module doc), so a test that wants to read a WAL back has to
/// hold the same key the writer used.
fn test_cipher() -> Cipher {
    Cipher::derive("wal test passphrase", &[7u8; crate::cipher::SALT_LEN]).unwrap()
}

const TEST_AAD: &str = "tables/widgets\0lsm-wal";

#[tokio::test]
async fn replay_of_a_missing_file_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let replayed = Wal::replay(&dir.path().join("nope.wal"), &test_cipher(), TEST_AAD)
        .await
        .unwrap();
    assert!(replayed.is_empty());
}

#[tokio::test]
async fn append_put_then_replay_recovers_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.append_put(b"b", b"2").await.unwrap();

    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Put(b"1".to_vec())));
    assert_eq!(replayed.get(b"b".as_slice()), Some(&MemValue::Put(b"2".to_vec())));
}

#[tokio::test]
async fn append_delete_then_replay_recovers_a_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.append_delete(b"a").await.unwrap();

    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Tombstone));
}

#[tokio::test]
async fn a_later_record_for_the_same_key_wins_on_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.append_put(b"a", b"2").await.unwrap();

    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Put(b"2".to_vec())));
}

#[tokio::test]
async fn reset_truncates_and_appends_resume_from_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.reset().await.unwrap();
    assert!(Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap().is_empty());

    wal.append_put(b"b", b"2").await.unwrap();
    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
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
        let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
            .await
            .unwrap();
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

    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
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
    Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap(); // creates an empty file, no appends
    assert!(Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap().is_empty());
}

#[tokio::test]
async fn rotate_hands_off_the_old_file_and_leaves_a_fresh_one_appendable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();

    let rotating = wal.rotate().await.unwrap();
    assert_eq!(
        Wal::replay(&rotating, &test_cipher(), TEST_AAD)
            .await
            .unwrap()
            .get(b"a".as_slice()),
        Some(&MemValue::Put(b"1".to_vec()))
    );
    assert!(
        Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap().is_empty(),
        "the freshly reopened file at the original path must start empty"
    );

    wal.append_put(b"b", b"2").await.unwrap();
    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
    assert_eq!(replayed.len(), 1);
    assert_eq!(replayed.get(b"b".as_slice()), Some(&MemValue::Put(b"2".to_vec())));
}

/// Simulates a crash between `rotate()` and the flush that triggered it
/// either finishing or cleaning the rotated file up: a `.rotating` file is
/// left on disk next to a `path` that already has its own (newer) records.
/// Healing must fold both together, rotating's older records first, so a
/// later write to the same key in `path` still wins.
#[tokio::test]
async fn heal_rotating_wal_folds_the_leftover_file_back_in_oldest_first_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.append_put(b"b", b"old").await.unwrap();
    let _rotating = wal.rotate().await.unwrap(); // leaves table.wal.rotating on disk, never cleaned up
    wal.append_put(b"b", b"new").await.unwrap(); // a write that landed in the new generation
    drop(wal);

    heal_rotating_wal(&path).await.unwrap();

    assert!(
        !dir.path().join("table.wal.rotating").exists(),
        "healing must clean up the rotated file it just folded in"
    );
    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Put(b"1".to_vec())));
    assert_eq!(
        replayed.get(b"b".as_slice()),
        Some(&MemValue::Put(b"new".to_vec())),
        "the newer generation's record for a shared key must win"
    );
}

#[tokio::test]
async fn heal_rotating_wal_is_a_no_op_when_nothing_was_rotated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    drop(wal);

    heal_rotating_wal(&path).await.unwrap();

    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Put(b"1".to_vec())));
}

#[tokio::test]
async fn the_log_holds_no_plaintext_rows_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"account-uid-42", b"{\"email\":\"alice@example.com\"}")
        .await
        .unwrap();

    let raw = tokio::fs::read(&path).await.unwrap();
    for secret in [b"alice@example.com".as_slice(), b"account-uid-42".as_slice()] {
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "the WAL wrote {:?} to local disk in the clear",
            String::from_utf8_lossy(secret)
        );
    }
}

#[tokio::test]
async fn another_tables_log_is_refused_rather_than_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();

    // Same key, different table: the AAD binds the table's own root, so
    // this can't be replayed into the wrong memtable.
    let err = Wal::replay(&path, &test_cipher(), "tables/other\0lsm-wal")
        .await
        .expect_err("a WAL sealed for another table should not replay");
    assert!(err.to_string().contains("can't open"), "{err}");

    // And a different key doesn't open it either.
    let other_key = Cipher::derive("a different passphrase", &[9u8; crate::cipher::SALT_LEN]).unwrap();
    assert!(Wal::replay(&path, &other_key, TEST_AAD).await.is_err());
}

#[tokio::test]
async fn a_truncated_trailing_frame_still_recovers_everything_before_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let mut wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    wal.append_put(b"a", b"1").await.unwrap();
    wal.append_put(b"b", b"2").await.unwrap();

    // A crash mid-append leaves a partial frame at the very end.
    let mut raw = tokio::fs::read(&path).await.unwrap();
    raw.truncate(raw.len() - 3);
    tokio::fs::write(&path, &raw).await.unwrap();

    let replayed = Wal::replay(&path, &test_cipher(), TEST_AAD).await.unwrap();
    assert_eq!(replayed.get(b"a".as_slice()), Some(&MemValue::Put(b"1".to_vec())));
    assert!(!replayed.contains_key(b"b".as_slice()));
}

#[cfg(unix)]
#[tokio::test]
async fn the_log_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("table.wal");
    let _wal = Wal::open(path.clone(), test_cipher(), TEST_AAD.to_string())
        .await
        .unwrap();
    let mode = tokio::fs::metadata(&path).await.unwrap().permissions().mode();
    assert_eq!(mode & 0o077, 0, "WAL is readable by other accounts: {mode:o}");
}
