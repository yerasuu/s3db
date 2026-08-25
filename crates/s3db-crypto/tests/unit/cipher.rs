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
    let sealed = c
        .seal("repo/config.json", b"secret content", CompressionStrategy::None)
        .unwrap();
    let opened = c.open("repo/config.json", &sealed).unwrap();
    assert_eq!(opened, b"secret content");
}

#[test]
fn rejects_wrong_passphrase() {
    let sealed = test_cipher().seal("k", b"x", CompressionStrategy::None).unwrap();
    let other = Cipher::derive("another passphrase", &[7u8; SALT_LEN]).unwrap();
    assert!(other.open("k", &sealed).is_err());
}

#[test]
fn rejects_wrong_aad() {
    let c = test_cipher();
    let sealed = c.seal("repo-a/config.json", b"x", CompressionStrategy::None).unwrap();
    // Simulates a storage provider moving ciphertext to another key.
    assert!(c.open("repo-b/config.json", &sealed).is_err());
}

#[test]
fn rejects_truncated_or_tampered() {
    let c = test_cipher();
    let mut sealed = c.seal("k", b"test content", CompressionStrategy::None).unwrap();
    assert!(c.open("k", &sealed[..10]).is_err());
    let last = sealed.len() - 1;
    sealed[last] ^= 0xff;
    assert!(c.open("k", &sealed).is_err());
}

#[test]
fn different_salts_give_different_keys() {
    let a = Cipher::derive("pw", &[1u8; SALT_LEN]).unwrap();
    let b = Cipher::derive("pw", &[2u8; SALT_LEN]).unwrap();
    let sealed = a.seal("k", b"x", CompressionStrategy::None).unwrap();
    assert!(b.open("k", &sealed).is_err());
}

#[test]
fn compression_none_roundtrips() {
    let c = test_cipher();
    let plaintext = b"repeat repeat repeat repeat repeat repeat".repeat(50);
    let sealed = c.seal("k", &plaintext, CompressionStrategy::None).unwrap();
    assert_eq!(c.open("k", &sealed).unwrap(), plaintext);
}

#[test]
fn compression_auto_shrinks_and_roundtrips_compressible_data() {
    let c = test_cipher();
    let plaintext = b"repeat repeat repeat repeat repeat repeat ".repeat(200);
    let sealed = c
        .seal("k", &plaintext, CompressionStrategy::Auto { threshold_bytes: 16 })
        .unwrap();
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
    let mut sealed = c
        .seal("k", &plaintext, CompressionStrategy::Auto { threshold_bytes: 16 })
        .unwrap();
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
        assert_eq!(c.mode(), EncryptionMode::Enabled { algorithm });
        let sealed = c.seal("k", b"secret content", CompressionStrategy::None).unwrap();
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
        .map(|&a| {
            test_cipher_with(a)
                .seal("k", b"secret content", CompressionStrategy::None)
                .unwrap()
        })
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
    assert_eq!(
        c.mode(),
        EncryptionMode::Enabled {
            algorithm: CipherAlgorithm::XChaCha20Poly1305
        }
    );
    let raw = c.seal("k", b"x", CompressionStrategy::None).unwrap();
    assert_eq!(raw[NONCE_LEN], compression::NONE);
    let zstd = c
        .seal(
            "k",
            &b"repeat repeat repeat repeat ".repeat(200),
            CompressionStrategy::Auto { threshold_bytes: 16 },
        )
        .unwrap();
    assert_eq!(zstd[NONCE_LEN], compression::ZSTD);
}

#[test]
fn rejects_an_unknown_algorithm_code() {
    let c = test_cipher();
    let mut sealed = c.seal("k", b"x", CompressionStrategy::None).unwrap();
    // A code no build of this crate assigns -- an object from a future
    // version must fail loudly, not be misread as an algorithm that exists.
    sealed[NONCE_LEN] = algorithm::pack_header(0xE, compression::NONE);
    let err = c.open("k", &sealed).unwrap_err().to_string();
    assert!(err.contains("unknown cipher algorithm"), "got: {err}");
}

#[test]
fn disabled_roundtrips_and_marks_the_object_unencrypted() {
    let c = Cipher::disabled();
    assert_eq!(c.mode(), EncryptionMode::Disabled);
    let sealed = c.seal("k", b"public content", CompressionStrategy::None).unwrap();
    assert_eq!(
        algorithm::unpack_header(sealed[NONCE_LEN]).0,
        algorithm::UNENCRYPTED_CODE
    );
    // No AEAD, so the payload really is the plaintext -- that's the mode's
    // whole point, and worth pinning down rather than assuming.
    assert_eq!(&sealed[NONCE_LEN + 1..], b"public content");
    assert_eq!(c.open("k", &sealed).unwrap(), b"public content");
}

#[test]
fn disabled_still_compresses_when_asked() {
    let c = Cipher::disabled();
    let plaintext = b"repeat repeat repeat repeat ".repeat(200);
    let sealed = c
        .seal("k", &plaintext, CompressionStrategy::Auto { threshold_bytes: 16 })
        .unwrap();
    assert!(sealed.len() < plaintext.len());
    assert_eq!(c.open("k", &sealed).unwrap(), plaintext);
}

/// The downgrade attack `accept` exists to stop: anything able to write to
/// the bucket could otherwise swap a sealed object for a plaintext one and
/// have an encrypting reader hand the content straight back.
#[test]
fn an_encrypting_cipher_refuses_an_unencrypted_object() {
    let unencrypted = Cipher::disabled()
        .seal("k", b"attacker content", CompressionStrategy::None)
        .unwrap();
    let err = test_cipher().open("k", &unencrypted).unwrap_err().to_string();
    assert!(err.contains("encryption enabled"), "got: {err}");
}

#[test]
fn a_disabled_cipher_refuses_an_encrypted_object() {
    let sealed = test_cipher()
        .seal("k", b"secret content", CompressionStrategy::None)
        .unwrap();
    let err = Cipher::disabled().open("k", &sealed).unwrap_err().to_string();
    assert!(err.contains("encryption disabled"), "got: {err}");
}

#[test]
fn derive_for_builds_what_the_mode_asks_for() {
    for algorithm in CipherAlgorithm::ALL {
        let mode = EncryptionMode::Enabled { algorithm };
        assert_eq!(Cipher::derive_for(mode, "pw", &[7u8; SALT_LEN]).unwrap().mode(), mode);
    }
    let disabled = Cipher::derive_for(EncryptionMode::Disabled, "pw", &[7u8; SALT_LEN]).unwrap();
    assert_eq!(disabled.mode(), EncryptionMode::Disabled);
}

#[test]
fn the_default_mode_is_encryption_on() {
    assert_eq!(
        EncryptionMode::default(),
        EncryptionMode::Enabled {
            algorithm: CipherAlgorithm::XChaCha20Poly1305
        }
    );
}

#[test]
fn tampering_with_the_algorithm_header_is_detected() {
    let c = test_cipher_with(CipherAlgorithm::Aes256Gcm);
    let mut sealed = c.seal("k", b"secret content", CompressionStrategy::None).unwrap();
    // Claim the object was sealed by a different (real) algorithm.
    sealed[NONCE_LEN] = algorithm::pack_header(CipherAlgorithm::XChaCha20Poly1305.code(), compression::NONE);
    assert!(c.open("k", &sealed).is_err());
}

/// AES-256-GCM's 96-bit nonce is picked at random, so past NIST's 2^32
/// invocations per key a repeat stops being negligible -- and a repeat under
/// GCM leaks the authentication subkey, not just one message. `seal` has to
/// fail closed at that point rather than keep issuing nonces.
#[test]
fn aes_gcm_refuses_to_seal_past_its_nonce_budget() {
    let c = Cipher::derive_with("pw", &[7u8; SALT_LEN], CipherAlgorithm::Aes256Gcm).unwrap();
    c.seed_nonces_issued((1 << 32) - 1);
    // The last nonce inside the budget is still handed out.
    assert!(c.seal("k", b"still fine", CompressionStrategy::None).is_ok());
    let err = c
        .seal("k", b"one too many", CompressionStrategy::None)
        .unwrap_err()
        .to_string();
    assert!(err.contains("budget"), "{err}");
    // And it stays refused rather than recovering on the next call.
    assert!(c.seal("k", b"still refused", CompressionStrategy::None).is_err());
}

/// The budget belongs to the key, not to one `Cipher` value, so cloning must
/// not hand a caller a fresh allowance.
#[test]
fn the_nonce_budget_is_shared_across_clones() {
    let c = Cipher::derive_with("pw", &[7u8; SALT_LEN], CipherAlgorithm::Aes256Gcm).unwrap();
    c.seed_nonces_issued(1 << 32);
    let clone = c.clone();
    assert!(clone.seal("k", b"x", CompressionStrategy::None).is_err());
}

/// XChaCha20Poly1305's 192-bit nonce has no birthday bound worth enforcing,
/// so the default algorithm must never be capped.
#[test]
fn xchacha_has_no_nonce_budget() {
    let c = Cipher::derive_with("pw", &[7u8; SALT_LEN], CipherAlgorithm::XChaCha20Poly1305).unwrap();
    c.seed_nonces_issued(u64::MAX);
    assert!(c.seal("k", b"x", CompressionStrategy::None).is_ok());
}

/// `nonces_issued` must reflect real sealing, not just what was seeded --
/// the read half of the persistence escape hatch has to agree with the
/// write half.
#[test]
fn nonces_issued_reports_real_usage() {
    let c = Cipher::derive_with("pw", &[7u8; SALT_LEN], CipherAlgorithm::Aes256Gcm).unwrap();
    assert_eq!(c.nonces_issued(), 0);
    c.seal("k", b"a", CompressionStrategy::None).unwrap();
    c.seal("k", b"b", CompressionStrategy::None).unwrap();
    assert_eq!(c.nonces_issued(), 2);
}

/// `nonces_issued`/`seed_nonces_issued` only mean anything for the one
/// algorithm whose budget is tracked at all.
#[test]
fn nonces_issued_is_always_zero_off_aes_gcm() {
    let xchacha = Cipher::derive_with("pw", &[7u8; SALT_LEN], CipherAlgorithm::XChaCha20Poly1305).unwrap();
    xchacha.seal("k", b"a", CompressionStrategy::None).unwrap();
    assert_eq!(xchacha.nonces_issued(), 0);

    let disabled = Cipher::derive_for(EncryptionMode::Disabled, "pw", &[7u8; SALT_LEN]).unwrap();
    assert_eq!(disabled.nonces_issued(), 0);
    disabled.seed_nonces_issued(1 << 32); // a no-op, not a panic
    assert_eq!(disabled.nonces_issued(), 0);
}

/// The scenario `nonces_issued`/`seed_nonces_issued` exist for: a caller
/// persists the count somewhere durable of its own before shutting down,
/// then hands it back to a brand-new `Cipher` (simulating a restart) built
/// from the same key -- the budget must pick up where the old process left
/// off instead of resetting to zero.
#[test]
fn seeding_a_fresh_cipher_carries_the_budget_across_a_simulated_restart() {
    let before_restart = Cipher::derive_with("pw", &[7u8; SALT_LEN], CipherAlgorithm::Aes256Gcm).unwrap();
    before_restart.seed_nonces_issued((1 << 32) - 1);
    before_restart.seal("k", b"last one before shutdown", CompressionStrategy::None).unwrap();
    let persisted_count = before_restart.nonces_issued();

    // A fresh `Cipher`, as if this were a new process re-deriving the same
    // key -- without seeding, it would start back at zero and happily
    // allow another 2^32 nonces this key has no real budget left for.
    let after_restart = Cipher::derive_with("pw", &[7u8; SALT_LEN], CipherAlgorithm::Aes256Gcm).unwrap();
    after_restart.seed_nonces_issued(persisted_count);

    let err = after_restart
        .seal("k", b"first write after restart", CompressionStrategy::None)
        .unwrap_err()
        .to_string();
    assert!(err.contains("budget"), "{err}");
}

/// `from_key` takes raw material, so two ciphers built from the same key
/// interoperate exactly as if they had derived it -- that is what lets a
/// wrapped data key survive a passphrase change.
#[test]
fn from_key_round_trips_between_independent_ciphers() {
    let key = Cipher::random_key().unwrap();
    let a = Cipher::from_key(&key, CipherAlgorithm::default());
    let b = Cipher::from_key(&key, CipherAlgorithm::default());
    let sealed = a.seal("k", b"payload", CompressionStrategy::None).unwrap();
    assert_eq!(b.open("k", &sealed).unwrap(), b"payload");
}

#[test]
fn random_key_is_not_the_same_twice() {
    let a = Cipher::random_key().unwrap();
    let b = Cipher::random_key().unwrap();
    assert_ne!(*a, *b);
}

/// A key derived from a passphrase can wrap a data key, and the wrapping is
/// AEAD like everything else here: a wrong passphrase fails to unwrap rather
/// than yielding wrong-but-plausible key material.
#[test]
fn a_data_key_wrapped_under_a_passphrase_key_unwraps_only_with_it() {
    let data_key = Cipher::random_key().unwrap();
    let wrapper = Cipher::derive("right", &[3u8; SALT_LEN]).unwrap();
    let wrapped = wrapper
        .seal("wrap", data_key.as_slice(), CompressionStrategy::None)
        .unwrap();

    assert_eq!(wrapper.open("wrap", &wrapped).unwrap(), *data_key);
    let wrong = Cipher::derive("wrong", &[3u8; SALT_LEN]).unwrap();
    assert!(wrong.open("wrap", &wrapped).is_err());
}

/// Cloning a `Cipher` must share the one copy of the key material, not make
/// another. Checked through the shared nonce counter, which lives next to it
/// and is observable: if the clone got its own state, the budget would reset
/// with it.
#[test]
fn cloning_shares_key_state_rather_than_copying_it() {
    let c = Cipher::derive_with("pw", &[7u8; SALT_LEN], CipherAlgorithm::Aes256Gcm).unwrap();
    let clone = c.clone();
    c.seal("k", b"x", CompressionStrategy::None).unwrap();
    clone.seed_nonces_issued(1 << 32);
    assert!(c.seal("k", b"x", CompressionStrategy::None).is_err());
}
