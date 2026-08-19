use super::*;

#[test]
fn every_value_encodes_to_the_same_width() {
    for n in [0u64, 1, 9, 10, 999, u64::MAX] {
        assert_eq!(encode_u64(n).len(), ORDINAL_WIDTH, "{n}");
    }
}

#[test]
fn lexicographic_order_matches_numeric_order() {
    let numbers = [0u64, 1, 2, 9, 10, 11, 100, 1_000, u64::MAX / 2, u64::MAX];
    let mut names: Vec<String> = numbers.iter().rev().map(|n| encode_u64(*n)).collect();
    names.sort();
    let decoded: Vec<u64> = names.iter().map(|name| decode_u64(name).unwrap()).collect();
    assert_eq!(decoded, numbers);
}

#[test]
fn signed_order_matches_too_including_negatives() {
    let numbers = [i64::MIN, -1_000, -2, -1, 0, 1, 2, 1_000, i64::MAX];
    let mut names: Vec<String> = numbers.iter().rev().map(|n| encode_i64(*n)).collect();
    names.sort();
    let decoded: Vec<i64> = names.iter().map(|name| decode_i64(name).unwrap()).collect();
    assert_eq!(decoded, numbers);
}

#[test]
fn decode_rejects_anything_it_did_not_write() {
    assert_eq!(decode_u64("9"), None, "an unpadded name is exactly what this stops");
    assert_eq!(decode_u64(""), None);
    assert_eq!(decode_u64(&"1".repeat(ORDINAL_WIDTH + 1)), None);
    assert_eq!(decode_u64(&format!("{:0>20}", "abc")), None);
    // 20 digits, but past u64::MAX.
    assert_eq!(decode_u64("99999999999999999999"), None);
}

#[tokio::test]
async fn collection_list_names_comes_back_in_numeric_order() {
    use crate::collection::Collection;
    use crate::local::LocalBackend;

    #[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
    struct Chapter {
        n: u64,
    }

    let dir = tempfile::tempdir().unwrap();
    let backend = LocalBackend::new(&crate::config::LocalParams {
        bucket: dir.path().to_string_lossy().to_string(),
        engine: crate::config::LocalEngine::Files,
    });
    let cipher = crate::cipher::Cipher::derive("test passphrase", &[7u8; crate::cipher::SALT_LEN]).unwrap();
    let chapters = Collection::new("chapters");

    for n in [1u64, 2, 9, 10, 11, 100] {
        chapters
            .put(&backend, &cipher, &encode_u64(n), &Chapter { n }, None)
            .await
            .unwrap();
    }

    let listed: Vec<u64> = chapters
        .list_names(&backend)
        .await
        .unwrap()
        .iter()
        .map(|name| decode_u64(name).unwrap())
        .collect();
    assert_eq!(listed, vec![1, 2, 9, 10, 11, 100]);
}
