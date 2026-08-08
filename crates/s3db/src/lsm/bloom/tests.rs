use super::*;

#[test]
fn never_false_negative_for_inserted_keys() {
    let mut bloom = Bloom::new(1000);
    let keys: Vec<Vec<u8>> = (0..1000).map(|i| format!("key-{i}").into_bytes()).collect();
    for key in &keys {
        bloom.insert(key);
    }
    for key in &keys {
        assert!(bloom.contains(key), "{key:?} was inserted but reported absent");
    }
}

#[test]
fn empty_filter_reports_nothing_present() {
    let bloom = Bloom::new(100);
    assert!(!bloom.contains(b"anything"));
}

#[test]
fn false_positive_rate_is_reasonably_low_at_the_sized_capacity() {
    let mut bloom = Bloom::new(1000);
    for i in 0..1000 {
        bloom.insert(format!("present-{i}").as_bytes());
    }
    let false_positives = (0..1000)
        .filter(|i| bloom.contains(format!("absent-{i}").as_bytes()))
        .count();
    // Sized for ~1% -- generous slack (10%) so this isn't flaky, just a
    // sanity check that the filter isn't degenerate (e.g. always "maybe").
    assert!(
        false_positives < 100,
        "{false_positives} false positives out of 1000 probes"
    );
}

#[test]
fn to_bytes_and_from_bytes_round_trip() {
    let mut bloom = Bloom::new(50);
    for i in 0..50 {
        bloom.insert(format!("k{i}").as_bytes());
    }
    let bytes = bloom.to_bytes();
    let restored = Bloom::from_bytes(&bytes).unwrap();
    for i in 0..50 {
        assert!(restored.contains(format!("k{i}").as_bytes()));
    }
    assert_eq!(restored.num_bits, bloom.num_bits);
    assert_eq!(restored.k, bloom.k);
}

#[test]
fn from_bytes_rejects_a_truncated_header() {
    assert!(Bloom::from_bytes(&[1, 2, 3]).is_err());
}

#[test]
fn from_bytes_rejects_a_body_length_mismatch() {
    let bloom = Bloom::new(10);
    let mut bytes = bloom.to_bytes();
    bytes.truncate(bytes.len() - 4); // chop off part of the last word
    assert!(Bloom::from_bytes(&bytes).is_err());
}
