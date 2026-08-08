use super::*;

fn rows(pairs: &[(&str, &str)]) -> BTreeMap<LsmKey, MemValue> {
    pairs
        .iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), MemValue::Put(v.as_bytes().to_vec())))
        .collect()
}

#[test]
fn build_then_read_all_round_trips_every_row_in_order() {
    let rows = rows(&[("b", "2"), ("a", "1"), ("c", "3")]);
    let (object, meta) = build(&rows, 2);
    assert_eq!(meta.row_count, 3);
    assert_eq!(meta.min_key, b"a");
    assert_eq!(meta.max_key, b"c");
    assert_eq!(meta.byte_len, object.len() as u64);

    let read_back = read_all(&object).unwrap();
    assert_eq!(
        read_back,
        vec![
            (b"a".to_vec(), MemValue::Put(b"1".to_vec())),
            (b"b".to_vec(), MemValue::Put(b"2".to_vec())),
            (b"c".to_vec(), MemValue::Put(b"3".to_vec())),
        ]
    );
}

#[test]
fn tombstones_survive_the_round_trip() {
    let mut rows = BTreeMap::new();
    rows.insert(b"a".to_vec(), MemValue::Tombstone);
    let (object, _) = build(&rows, 10);
    assert_eq!(read_all(&object).unwrap(), vec![(b"a".to_vec(), MemValue::Tombstone)]);
}

#[test]
fn block_index_has_one_entry_per_block_with_correct_bounds() {
    // 5 rows, 2 per block -> blocks of size 2, 2, 1.
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")]);
    let (_, meta) = build(&rows, 2);
    assert_eq!(meta.block_index.len(), 3);
    assert_eq!(
        (&meta.block_index[0].min_key, &meta.block_index[0].max_key),
        (&b"a".to_vec(), &b"b".to_vec())
    );
    assert_eq!(
        (&meta.block_index[1].min_key, &meta.block_index[1].max_key),
        (&b"c".to_vec(), &b"d".to_vec())
    );
    assert_eq!(
        (&meta.block_index[2].min_key, &meta.block_index[2].max_key),
        (&b"e".to_vec(), &b"e".to_vec())
    );
}

/// The whole point of storing `(offset, len)` in the block index: they must
/// locate exactly the bytes `decode_block` needs, nothing more or less --
/// this is what a real `get_range(key, offset, len)` call will fetch in
/// phase 2, so an off-by-one here would silently corrupt every partial read.
#[test]
fn block_index_offsets_locate_exactly_the_decodable_payload() {
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")]);
    let (object, meta) = build(&rows, 2);
    for entry in &meta.block_index {
        let start = entry.offset as usize;
        let end = start + entry.len as usize;
        let decoded = decode_block(&object[start..end]).unwrap();
        assert_eq!(&decoded.first().unwrap().0, &entry.min_key);
        assert_eq!(&decoded.last().unwrap().0, &entry.max_key);
    }
}

#[test]
fn bloom_filter_in_the_footer_contains_every_key() {
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3")]);
    let (object, _) = build(&rows, 10);
    let footer = open_footer(&object).unwrap();
    for key in rows.keys() {
        assert!(footer.bloom.contains(key));
    }
}

#[test]
fn open_footer_blocks_end_matches_where_the_footer_actually_starts() {
    let rows = rows(&[("a", "1"), ("b", "2")]);
    let (object, _) = build(&rows, 10);
    let footer = open_footer(&object).unwrap();
    // Everything from blocks_end onward, minus the trailing 8-byte length,
    // must be exactly the footer bytes open_footer parsed.
    let footer_len_bytes = &object[object.len() - 8..];
    let footer_len = u64::from_le_bytes(footer_len_bytes.try_into().unwrap());
    assert_eq!(footer.blocks_end + footer_len + 8, object.len() as u64);
}

#[test]
fn read_all_rejects_an_object_too_short_for_a_footer() {
    assert!(read_all(&[1, 2, 3]).is_err());
}

#[test]
fn read_all_rejects_a_truncated_block_payload() {
    let rows = rows(&[("a", "1"), ("b", "2")]);
    let (mut object, _) = build(&rows, 10);
    // Corrupt the first block's declared payload length to run past the
    // actual object -- must error, not panic or silently truncate.
    object[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(read_all(&object).is_err());
}

#[test]
#[should_panic(expected = "at least one row")]
fn build_panics_on_an_empty_memtable_drain() {
    let rows: BTreeMap<LsmKey, MemValue> = BTreeMap::new();
    build(&rows, 10);
}

/// A block boundary that lands exactly on the last row must not produce a
/// stray empty trailing block.
#[test]
fn a_row_count_that_divides_evenly_into_blocks_has_no_empty_trailing_block() {
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")]);
    let (_, meta) = build(&rows, 2);
    assert_eq!(meta.block_index.len(), 2);
}
