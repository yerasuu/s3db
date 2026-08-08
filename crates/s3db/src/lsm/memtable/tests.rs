use super::*;

#[test]
fn put_then_get_round_trips() {
    let mut m = Memtable::default();
    m.put(b"a".to_vec(), b"1".to_vec());
    assert_eq!(m.get(b"a"), Some(&MemValue::Put(b"1".to_vec())));
}

#[test]
fn delete_records_a_tombstone_not_a_removal() {
    let mut m = Memtable::default();
    m.put(b"a".to_vec(), b"1".to_vec());
    m.delete(b"a".to_vec());
    // Still present as an entry -- a tombstone, not gone from the map.
    assert_eq!(m.get(b"a"), Some(&MemValue::Tombstone));
    assert_eq!(m.len(), 1);
}

#[test]
fn get_of_a_never_written_key_is_none() {
    let m = Memtable::default();
    assert_eq!(m.get(b"nope"), None);
}

#[test]
fn drain_sorted_returns_ascending_key_order() {
    let mut m = Memtable::default();
    for key in [b"c".to_vec(), b"a".to_vec(), b"b".to_vec()] {
        m.put(key.clone(), key);
    }
    let drained: Vec<_> = m.drain_sorted().into_keys().collect();
    assert_eq!(drained, vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
}

#[test]
fn drain_sorted_empties_the_memtable() {
    let mut m = Memtable::default();
    m.put(b"a".to_vec(), b"1".to_vec());
    m.drain_sorted();
    assert!(m.is_empty());
    assert_eq!(m.approx_bytes(), 0);
}

#[test]
fn approx_bytes_tracks_puts_and_deletes() {
    let mut m = Memtable::default();
    assert_eq!(m.approx_bytes(), 0);
    m.put(b"key".to_vec(), b"value".to_vec()); // 3 + 5
    assert_eq!(m.approx_bytes(), 8);
    m.delete(b"key".to_vec()); // same key: value bytes replaced by a 0-byte tombstone
    assert_eq!(m.approx_bytes(), 3);
}

#[test]
fn rewriting_the_same_key_does_not_double_count_toward_approx_bytes() {
    let mut m = Memtable::default();
    m.put(b"key".to_vec(), b"aaaaaaaaaa".to_vec()); // 3 + 10
    m.put(b"key".to_vec(), b"bb".to_vec()); // replaces the old value, not additive
    assert_eq!(m.approx_bytes(), 3 + 2);
    assert_eq!(m.len(), 1);
}

fn keys_of(entries: &[(LsmKey, MemValue)]) -> Vec<&[u8]> {
    entries.iter().map(|(k, _)| k.as_slice()).collect()
}

#[test]
fn range_with_both_bounds_is_start_inclusive_end_exclusive() {
    let mut m = Memtable::default();
    for key in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()] {
        m.put(key.clone(), key);
    }
    let found = m.range(Some(b"b"), Some(b"d"));
    assert_eq!(keys_of(&found), vec![b"b".as_slice(), b"c".as_slice()]);
}

#[test]
fn range_with_no_start_bound_includes_everything_up_to_end() {
    let mut m = Memtable::default();
    for key in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
        m.put(key.clone(), key);
    }
    let found = m.range(None, Some(b"c"));
    assert_eq!(keys_of(&found), vec![b"a".as_slice(), b"b".as_slice()]);
}

#[test]
fn range_with_no_end_bound_includes_everything_from_start() {
    let mut m = Memtable::default();
    for key in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
        m.put(key.clone(), key);
    }
    let found = m.range(Some(b"b"), None);
    assert_eq!(keys_of(&found), vec![b"b".as_slice(), b"c".as_slice()]);
}

#[test]
fn range_with_no_bounds_at_all_returns_everything() {
    let mut m = Memtable::default();
    for key in [b"a".to_vec(), b"b".to_vec()] {
        m.put(key.clone(), key);
    }
    assert_eq!(m.range(None, None).len(), 2);
}

#[test]
fn range_includes_tombstones() {
    let mut m = Memtable::default();
    m.put(b"a".to_vec(), b"1".to_vec());
    m.delete(b"a".to_vec());
    let found = m.range(None, None);
    assert_eq!(found, vec![(b"a".to_vec(), MemValue::Tombstone)]);
}
