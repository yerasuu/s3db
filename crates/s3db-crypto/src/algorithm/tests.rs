use super::*;

#[test]
fn header_packing_roundtrips_every_algorithm_and_compression_pair() {
    for algorithm in CipherAlgorithm::ALL {
        for compression in [crate::compression::NONE, crate::compression::ZSTD] {
            let header = pack_header(algorithm.code(), compression);
            assert_eq!(unpack_header(header), (algorithm.code(), compression));
        }
    }
}

/// The whole point of putting the algorithm in the *high* nibble: an object
/// sealed before the byte carried an algorithm at all has a high nibble of
/// zero, which must read back as the algorithm that actually sealed it.
#[test]
fn a_bare_compression_byte_reads_back_as_the_default_algorithm() {
    for compression in [crate::compression::NONE, crate::compression::ZSTD] {
        let (algorithm_code, compression_code) = unpack_header(compression);
        assert_eq!(compression_code, compression);
        assert_eq!(
            algorithm_from_code(algorithm_code).unwrap(),
            CipherAlgorithm::XChaCha20Poly1305
        );
    }
}

#[test]
fn algorithm_codes_are_unique_and_match_their_index() {
    for (i, algorithm) in CipherAlgorithm::ALL.into_iter().enumerate() {
        assert_eq!(algorithm.index(), i, "ALL must be in wire-code order");
        assert_eq!(algorithm_from_code(algorithm.code()).unwrap(), algorithm);
    }
}

#[test]
fn every_nonce_fits_the_fixed_field() {
    for algorithm in CipherAlgorithm::ALL {
        assert!(algorithm.nonce_len() <= NONCE_FIELD_LEN);
    }
}

#[test]
fn every_algorithm_roundtrips_at_the_primitive_level() {
    let key = [3u8; KEY_LEN];
    let nonce = [9u8; NONCE_FIELD_LEN];
    for algorithm in CipherAlgorithm::ALL {
        let keyed = Keyed::new(algorithm, &key);
        assert_eq!(keyed.algorithm(), algorithm);
        let sealed = keyed.encrypt(&nonce, b"content", b"aad");
        assert_eq!(keyed.decrypt(&nonce, &sealed, b"aad").unwrap(), b"content");
        assert!(keyed.decrypt(&nonce, &sealed, b"other aad").is_none());
    }
}

/// AES-GCM reads only the first 12 bytes of the nonce field, so the trailing
/// 12 carry no meaning -- worth pinning down, because a future change that
/// started depending on them would silently break objects already sealed
/// with random padding there.
#[test]
fn aes_ignores_the_unused_tail_of_the_nonce_field() {
    let keyed = Keyed::new(CipherAlgorithm::Aes256Gcm, &[3u8; KEY_LEN]);
    let mut nonce = [9u8; NONCE_FIELD_LEN];
    let sealed = keyed.encrypt(&nonce, b"content", b"aad");
    nonce[12..].fill(0xAB);
    assert_eq!(keyed.decrypt(&nonce, &sealed, b"aad").unwrap(), b"content");
}
