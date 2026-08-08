use super::*;

const KEY: &str = "audit_log/sst/test.sst";

fn rows(pairs: &[(&str, &str)]) -> BTreeMap<LsmKey, MemValue> {
    pairs
        .iter()
        .map(|(k, v)| (k.as_bytes().to_vec(), MemValue::Put(v.as_bytes().to_vec())))
        .collect()
}

fn test_cipher() -> Cipher {
    Cipher::derive("test passphrase", &[5u8; crate::cipher::SALT_LEN]).unwrap()
}

#[test]
fn build_then_read_all_round_trips_every_row_in_order() {
    let cipher = test_cipher();
    let rows = rows(&[("b", "2"), ("a", "1"), ("c", "3")]);
    let (object, meta) = build(&cipher, KEY, None, &rows, 2).unwrap();
    assert_eq!(meta.row_count, 3);
    assert_eq!(meta.min_key, b"a");
    assert_eq!(meta.max_key, b"c");
    assert_eq!(meta.byte_len, object.len() as u64);

    let read_back = read_all(&cipher, KEY, None, &object).unwrap();
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
    let cipher = test_cipher();
    let mut rows = BTreeMap::new();
    rows.insert(b"a".to_vec(), MemValue::Tombstone);
    let (object, _) = build(&cipher, KEY, None, &rows, 10).unwrap();
    assert_eq!(
        read_all(&cipher, KEY, None, &object).unwrap(),
        vec![(b"a".to_vec(), MemValue::Tombstone)]
    );
}

#[test]
fn no_plaintext_row_content_appears_in_the_built_object() {
    let cipher = test_cipher();
    let rows = rows(&[("a", "a very identifiable secret")]);
    let (object, _) = build(&cipher, KEY, None, &rows, 10).unwrap();
    let needle = b"a very identifiable secret";
    assert!(!object.windows(needle.len()).any(|w| w == needle));
}

/// The whole reason each unit is sealed on its own: a reader must be able
/// to open one block without the rest of the object, and must fail loudly
/// if a block claims to be from a different SSTable or a different position
/// than it actually is.
#[test]
fn a_block_sealed_under_one_sstable_key_does_not_open_under_another() {
    let cipher = test_cipher();
    let rows = rows(&[("a", "1")]);
    let (object, meta) = build(&cipher, KEY, None, &rows, 10).unwrap();
    let entry = &meta.block_index[0];
    let sealed = &object[entry.offset as usize..entry.offset as usize + entry.len as usize];
    assert!(decode_block(&cipher, "different/key.sst", None, 0, sealed).is_err());
}

#[test]
fn a_block_read_at_the_wrong_index_does_not_open() {
    let cipher = test_cipher();
    let rows = rows(&[("a", "1"), ("b", "2")]);
    let (object, meta) = build(&cipher, KEY, None, &rows, 1).unwrap(); // 2 blocks, one row each
    let entry = &meta.block_index[0];
    let sealed = &object[entry.offset as usize..entry.offset as usize + entry.len as usize];
    // This is block 0's sealed bytes, but claiming it's block 1.
    assert!(decode_block(&cipher, KEY, None, 1, sealed).is_err());
}

#[test]
fn block_index_has_one_entry_per_block_with_correct_bounds() {
    let cipher = test_cipher();
    // 5 rows, 2 per block -> blocks of size 2, 2, 1.
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")]);
    let (_, meta) = build(&cipher, KEY, None, &rows, 2).unwrap();
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
    let cipher = test_cipher();
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")]);
    let (object, meta) = build(&cipher, KEY, None, &rows, 2).unwrap();
    for (idx, entry) in meta.block_index.iter().enumerate() {
        let start = entry.offset as usize;
        let end = start + entry.len as usize;
        let decoded = decode_block(&cipher, KEY, None, idx, &object[start..end]).unwrap();
        assert_eq!(&decoded.first().unwrap().0, &entry.min_key);
        assert_eq!(&decoded.last().unwrap().0, &entry.max_key);
    }
}

#[test]
fn bloom_filter_in_the_footer_contains_every_key() {
    let cipher = test_cipher();
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3")]);
    let (object, _) = build(&cipher, KEY, None, &rows, 10).unwrap();
    let footer = open_footer(&cipher, KEY, &object).unwrap();
    for key in rows.keys() {
        assert!(footer.bloom.contains(key));
    }
}

#[test]
fn open_footer_blocks_end_matches_where_the_footer_actually_starts() {
    let cipher = test_cipher();
    let rows = rows(&[("a", "1"), ("b", "2")]);
    let (object, _) = build(&cipher, KEY, None, &rows, 10).unwrap();
    let footer = open_footer(&cipher, KEY, &object).unwrap();
    // Everything from blocks_end onward, minus the trailing 8-byte length,
    // must be exactly the footer bytes open_footer parsed.
    let footer_len_bytes = &object[object.len() - 8..];
    let footer_len = u64::from_le_bytes(footer_len_bytes.try_into().unwrap());
    assert_eq!(footer.blocks_end + footer_len + 8, object.len() as u64);
}

/// The primitive phase 2's manifest-driven point lookup actually uses:
/// opening a footer from just its own sealed bytes, fetched via the exact
/// `(byte_len - 8 - footer_len, footer_len)` range a manifest entry gives.
#[test]
fn open_footer_bytes_from_just_the_footer_range_matches_open_footer() {
    let cipher = test_cipher();
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3")]);
    let (object, meta) = build(&cipher, KEY, None, &rows, 10).unwrap();
    let footer_start = (meta.byte_len - 8 - meta.footer_len) as usize;
    let footer_end = (meta.byte_len - 8) as usize;
    let sealed_footer = &object[footer_start..footer_end];

    let (bloom, block_index) = open_footer_bytes(&cipher, KEY, sealed_footer).unwrap();
    for key in rows.keys() {
        assert!(bloom.contains(key));
    }
    assert_eq!(block_index, meta.block_index);
}

#[test]
fn read_all_rejects_an_object_too_short_for_a_footer() {
    let cipher = test_cipher();
    assert!(read_all(&cipher, KEY, None, &[1, 2, 3]).is_err());
}

#[test]
fn read_all_rejects_a_truncated_block_payload() {
    let cipher = test_cipher();
    let rows = rows(&[("a", "1"), ("b", "2")]);
    let (mut object, _) = build(&cipher, KEY, None, &rows, 10).unwrap();
    // Corrupt the first block's declared payload length to run past the
    // actual object -- must error, not panic or silently truncate.
    object[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(read_all(&cipher, KEY, None, &object).is_err());
}

#[test]
#[should_panic(expected = "at least one row")]
fn build_panics_on_an_empty_memtable_drain() {
    let cipher = test_cipher();
    let rows: BTreeMap<LsmKey, MemValue> = BTreeMap::new();
    build(&cipher, KEY, None, &rows, 10).unwrap();
}

/// A block boundary that lands exactly on the last row must not produce a
/// stray empty trailing block.
#[test]
fn a_row_count_that_divides_evenly_into_blocks_has_no_empty_trailing_block() {
    let cipher = test_cipher();
    let rows = rows(&[("a", "1"), ("b", "2"), ("c", "3"), ("d", "4")]);
    let (_, meta) = build(&cipher, KEY, None, &rows, 2).unwrap();
    assert_eq!(meta.block_index.len(), 2);
}
