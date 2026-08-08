use super::*;
use crate::kdf::SALT_LEN;

fn test_cipher() -> Cipher {
    Cipher::derive("correct horse battery staple", &[7u8; SALT_LEN]).unwrap()
}

fn test_cipher_with(algorithm: CipherAlgorithm) -> Cipher {
    Cipher::derive_with("correct horse battery staple", &[7u8; SALT_LEN], algorithm).unwrap()
}

#[test]
fn roundtrips() {
    let c = test_cipher();
    let sealed = c.seal("repo/config.json", b"secret content", CompressionStrategy::None);
    let opened = c.open("repo/config.json", &sealed).unwrap();
    assert_eq!(opened, b"secret content");
}

#[test]
fn rejects_wrong_passphrase() {
    let sealed = test_cipher().seal("k", b"x", CompressionStrategy::None);
    let other = Cipher::derive("another passphrase", &[7u8; SALT_LEN]).unwrap();
    assert!(other.open("k", &sealed).is_err());
}

#[test]
fn rejects_wrong_aad() {
    let c = test_cipher();
    let sealed = c.seal("repo-a/config.json", b"x", CompressionStrategy::None);
    // Simulates a storage provider moving ciphertext to another key.
    assert!(c.open("repo-b/config.json", &sealed).is_err());
}

#[test]
fn rejects_truncated_or_tampered() {
    let c = test_cipher();
    let mut sealed = c.seal("k", b"test content", CompressionStrategy::None);
    assert!(c.open("k", &sealed[..10]).is_err());
    let last = sealed.len() - 1;
    sealed[last] ^= 0xff;
    assert!(c.open("k", &sealed).is_err());
}

#[test]
fn different_salts_give_different_keys() {
    let a = Cipher::derive("pw", &[1u8; SALT_LEN]).unwrap();
    let b = Cipher::derive("pw", &[2u8; SALT_LEN]).unwrap();
    let sealed = a.seal("k", b"x", CompressionStrategy::None);
    assert!(b.open("k", &sealed).is_err());
}

#[test]
fn compression_none_roundtrips() {
    let c = test_cipher();
    let plaintext = b"repeat repeat repeat repeat repeat repeat".repeat(50);
    let sealed = c.seal("k", &plaintext, CompressionStrategy::None);
    assert_eq!(c.open("k", &sealed).unwrap(), plaintext);
}

#[test]
fn compression_auto_shrinks_and_roundtrips_compressible_data() {
    let c = test_cipher();
    let plaintext = b"repeat repeat repeat repeat repeat repeat ".repeat(200);
    let sealed = c.seal("k", &plaintext, CompressionStrategy::Auto { threshold_bytes: 16 });
    assert!(
        sealed.len() < plaintext.len(),
        "highly repetitive data should compress smaller"
    );
    assert_eq!(c.open("k", &sealed).unwrap(), plaintext);
}

#[test]
fn tampering_with_the_compression_header_is_detected() {
    let c = test_cipher();
    let plaintext = b"repeat repeat repeat repeat repeat repeat ".repeat(200);
    let mut sealed = c.seal("k", &plaintext, CompressionStrategy::Auto { threshold_bytes: 16 });
    let (algorithm_code, compression_code) = algorithm::unpack_header(sealed[NONCE_LEN]);
    assert_eq!(compression_code, compression::ZSTD);
    // Flip only the compression half, leaving the algorithm half intact.
    sealed[NONCE_LEN] = algorithm::pack_header(algorithm_code, compression::NONE);
    assert!(
        c.open("k", &sealed).is_err(),
        "header is bound into the AAD, tampering must fail auth"
    );
}

#[test]
fn rejects_a_sealed_blob_too_short_to_contain_a_header() {
    let c = test_cipher();
    assert!(c.open("k", &[0u8; NONCE_LEN]).is_err());
}

#[test]
fn every_algorithm_roundtrips() {
    for algorithm in CipherAlgorithm::ALL {
        let c = test_cipher_with(algorithm);
        assert_eq!(c.algorithm(), algorithm);
        let sealed = c.seal("k", b"secret content", CompressionStrategy::None);
        assert_eq!(algorithm::unpack_header(sealed[NONCE_LEN]).0, algorithm.code());
        assert_eq!(c.open("k", &sealed).unwrap(), b"secret content");
    }
}

/// The point of recording the algorithm per object: one bucket can hold
/// objects sealed by different algorithms at once, so the default can change
/// without re-sealing anything that already exists.
#[test]
fn a_cipher_opens_objects_sealed_by_any_algorithm() {
    let sealed: Vec<Vec<u8>> = CipherAlgorithm::ALL
        .iter()
        .map(|&a| test_cipher_with(a).seal("k", b"secret content", CompressionStrategy::None))
        .collect();
    for reader_algorithm in CipherAlgorithm::ALL {
        let reader = test_cipher_with(reader_algorithm);
        for blob in &sealed {
            assert_eq!(reader.open("k", blob).unwrap(), b"secret content");
        }
    }
}

/// The high nibble is zero for the default algorithm, which is what every
/// object sealed before the header carried an algorithm at all already has
/// -- so those objects are still byte-for-byte valid input to `open`.
#[test]
fn the_default_algorithm_leaves_the_header_byte_unchanged_from_the_original_format() {
    let c = test_cipher();
    assert_eq!(c.algorithm(), CipherAlgorithm::XChaCha20Poly1305);
    let raw = c.seal("k", b"x", CompressionStrategy::None);
    assert_eq!(raw[NONCE_LEN], compression::NONE);
    let zstd = c.seal(
        "k",
        &b"repeat repeat repeat repeat ".repeat(200),
        CompressionStrategy::Auto { threshold_bytes: 16 },
    );
    assert_eq!(zstd[NONCE_LEN], compression::ZSTD);
}

#[test]
fn rejects_an_unknown_algorithm_code() {
    let c = test_cipher();
    let mut sealed = c.seal("k", b"x", CompressionStrategy::None);
    // A code no build of this crate assigns -- an object from a future
    // version must fail loudly, not be misread as an algorithm that exists.
    sealed[NONCE_LEN] = algorithm::pack_header(0xE, compression::NONE);
    let err = c.open("k", &sealed).unwrap_err().to_string();
    assert!(err.contains("unknown cipher algorithm"), "got: {err}");
}

#[test]
fn tampering_with_the_algorithm_header_is_detected() {
    let c = test_cipher_with(CipherAlgorithm::Aes256Gcm);
    let mut sealed = c.seal("k", b"secret content", CompressionStrategy::None);
    // Claim the object was sealed by a different (real) algorithm.
    sealed[NONCE_LEN] = algorithm::pack_header(CipherAlgorithm::XChaCha20Poly1305.code(), compression::NONE);
    assert!(c.open("k", &sealed).is_err());
}
