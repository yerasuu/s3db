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

/// A decompression bomb: a tiny zstd payload that expands to far more than
/// the ratio bound allows. Reachable with no key at all under
/// `EncryptionMode::Disabled`, where nothing authenticates the payload
/// before `decompress` sees it.
#[test]
fn decompress_refuses_a_bomb() {
    let bomb = zstd::encode_all(&vec![0u8; 64 * 1024 * 1024][..], 0).unwrap();
    assert!(bomb.len() < 64 * 1024, "test payload isn't actually a bomb");
    assert!(decompress(ZSTD, bomb).is_err());
}

/// The bound must not reject anything `compress_for_seal` itself produced,
/// including highly compressible input that sits just under the ratio.
#[test]
fn decompress_still_accepts_a_legitimately_compressible_payload() {
    let plaintext = vec![b'a'; 512 * 1024];
    let (header, payload) = compress_for_seal(&plaintext, CompressionStrategy::Auto { threshold_bytes: 16 });
    assert_eq!(header, ZSTD);
    assert_eq!(decompress(header, payload.into_owned()).unwrap(), plaintext);
}
