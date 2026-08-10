use super::*;

#[test]
fn none_never_compresses_regardless_of_size() {
    let plaintext = b"repeat ".repeat(200);
    let (header, payload) = compress_for_seal(&plaintext, CompressionStrategy::None);
    assert_eq!(header, NONE);
    assert_eq!(&*payload, &plaintext[..]);
}

#[test]
fn auto_below_threshold_stores_raw() {
    let (header, payload) = compress_for_seal(b"short", CompressionStrategy::Auto { threshold_bytes: 1000 });
    assert_eq!(header, NONE);
    assert_eq!(&*payload, b"short");
}

#[test]
fn auto_above_threshold_compresses_when_it_actually_helps() {
    let plaintext = b"repeat repeat repeat repeat repeat repeat ".repeat(200);
    let (header, payload) = compress_for_seal(&plaintext, CompressionStrategy::Auto { threshold_bytes: 16 });
    assert_eq!(header, ZSTD);
    assert!(payload.len() < plaintext.len());
}

#[test]
fn decompress_reverses_compress_for_seal() {
    let plaintext = b"repeat repeat repeat repeat repeat repeat ".repeat(200);
    let (header, payload) = compress_for_seal(&plaintext, CompressionStrategy::Auto { threshold_bytes: 16 });
    assert_eq!(decompress(header, payload.into_owned()).unwrap(), plaintext);
}

#[test]
fn decompress_rejects_an_unknown_header() {
    assert!(decompress(0xff, vec![1, 2, 3]).is_err());
}
