//! The `Cipher` type itself: the AEAD primitive (XChaCha20Poly1305) and the
//! small-object `seal`/`open` format, built on [`crate::kdf`] for key
//! derivation and [`crate::compression`] for the optional compression
//! step. [`crate::stream`] is the separate large-object format, sharing
//! only [`NONCE_LEN`] and this type with what's here.

use crate::compression::{self, CompressionStrategy};
use crate::kdf;
use crate::stream;
use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::path::Path;

/// XChaCha20Poly1305: 24-byte nonce (vs. 12 for plain ChaCha20Poly1305).
/// With random nonces (not a counter) the extra 12 bytes matter: at this
/// object volume, a 96-bit nonce collision is no longer astronomically
/// unlikely, a 192-bit one still is.
pub(crate) const NONCE_LEN: usize = 24;

/// Binds the one-byte compression header into the AEAD associated data,
/// alongside the caller's own `aad` (the object's S3 key). The header sits
/// unencrypted next to the nonce ([`Cipher::open`] needs to read it before
/// it can even attempt to decrypt) -- without this, a malicious storage
/// provider could flip it undetected and make `open` misinterpret
/// compressed bytes as raw, or vice versa. The `\0` separator is cheap
/// insurance against `aad` + header colliding with some other `aad` that
/// happens to already end in that same byte.
fn header_bound_aad(aad: &str, header: u8) -> Vec<u8> {
    let mut bound = aad.as_bytes().to_vec();
    bound.push(0);
    bound.push(header);
    bound
}

#[derive(Clone)]
pub struct Cipher(XChaCha20Poly1305);

// Manual, no derive: we don't want an accidental `{:?}` (log, panic message)
// to have the slightest chance of printing key material.
impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cipher(..)")
    }
}

impl Cipher {
    /// Derives the encryption key from a passphrase + salt -- see
    /// [`crate::kdf`] for the actual algorithm and its fixed parameters.
    pub fn derive(passphrase: &str, salt: &[u8; crate::kdf::SALT_LEN]) -> Result<Self> {
        Ok(Cipher(kdf::derive(passphrase, salt)?))
    }

    /// The underlying AEAD instance -- `pub(crate)` so [`crate::stream`]
    /// can seal/open its own chunk framing without this type's one field
    /// ever being `pub`.
    pub(crate) fn aead(&self) -> &XChaCha20Poly1305 {
        &self.0
    }

    /// Encrypts `plaintext`, bound to `aad` (the object's S3 key). This
    /// stops a malicious storage provider from copying one object's
    /// ciphertext onto another and passing it off as valid: `open` with an
    /// `aad` different from the one used in `seal` fails authentication.
    ///
    /// Format: `nonce(24 bytes) || compression_header(1 byte) ||
    /// ciphertext+tag` -- `compression` decides whether the plaintext gets
    /// compressed first (see [`CompressionStrategy`]); the header records
    /// which happened and is itself bound into the AEAD associated data, so
    /// it can't be tampered with independently of the ciphertext.
    pub fn seal(&self, aad: &str, plaintext: &[u8], compression: CompressionStrategy) -> Vec<u8> {
        let (header, payload) = compression::compress_for_seal(plaintext, compression);
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).expect("system RNG unavailable");
        let nonce = XNonce::from(nonce_bytes);
        let combined_aad = header_bound_aad(aad, header);
        let mut ciphertext = self
            .0
            .encrypt(&nonce, Payload { msg: &payload, aad: &combined_aad })
            // The only way this fails in this API is a plaintext bigger than
            // the cipher's theoretical limit (hundreds of GiB); never due to
            // the key or the content itself.
            .expect("XChaCha20Poly1305::encrypt never fails at these sizes");
        let mut sealed = nonce.to_vec();
        sealed.push(header);
        sealed.append(&mut ciphertext);
        sealed
    }

    /// Opens what [`Self::seal`] sealed (decompressing first if its header
    /// says so). Fails if the key, the `aad`, or the content aren't the
    /// originals — a single generic error on purpose, to avoid giving an
    /// attacker an "almost" signal (padding oracle).
    pub fn open(&self, aad: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN + 1 {
            bail!("invalid ciphertext (too short)");
        }
        let (nonce, rest) = sealed.split_at(NONCE_LEN);
        let (header, ciphertext) = rest.split_at(1);
        let header = header[0];
        let nonce = XNonce::try_from(nonce).context("nonce has invalid length")?;
        let combined_aad = header_bound_aad(aad, header);
        let payload = self
            .0
            .decrypt(&nonce, Payload { msg: ciphertext, aad: &combined_aad })
            .map_err(|_| anyhow::anyhow!("couldn't decrypt (wrong passphrase, or data was modified/moved from a different key)"))?;
        compression::decompress(header, payload)
    }

    /// Streaming counterpart of [`Self::seal`] for objects too big to want
    /// fully buffered -- see [`crate::stream`] for the on-disk format and
    /// every failure mode it detects. A thin forward, the real logic lives
    /// there, not here.
    pub async fn seal_stream(&self, aad: &str, plaintext_path: &Path, sealed_path: &Path) -> Result<()> {
        stream::seal_stream(self, aad, plaintext_path, sealed_path).await
    }

    /// Reverses [`Self::seal_stream`] -- see [`crate::stream::open_stream`].
    pub async fn open_stream(&self, aad: &str, sealed_path: &Path, plaintext_path: &Path) -> Result<()> {
        stream::open_stream(self, aad, sealed_path, plaintext_path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::SALT_LEN;

    fn test_cipher() -> Cipher {
        Cipher::derive("correct horse battery staple", &[7u8; SALT_LEN]).unwrap()
    }

    #[test]
    fn roundtrips() {
        let c = test_cipher();
        let sealed = c.seal("repo/refs.json", b"secret content", CompressionStrategy::None);
        let opened = c.open("repo/refs.json", &sealed).unwrap();
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
        let sealed = c.seal("repo-a/refs.json", b"x", CompressionStrategy::None);
        // Simulates a storage provider moving ciphertext to another key.
        assert!(c.open("repo-b/refs.json", &sealed).is_err());
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
        assert!(sealed.len() < plaintext.len(), "highly repetitive data should compress smaller");
        assert_eq!(c.open("k", &sealed).unwrap(), plaintext);
    }

    #[test]
    fn tampering_with_the_compression_header_is_detected() {
        let c = test_cipher();
        let plaintext = b"repeat repeat repeat repeat repeat repeat ".repeat(200);
        let mut sealed = c.seal("k", &plaintext, CompressionStrategy::Auto { threshold_bytes: 16 });
        assert_eq!(sealed[NONCE_LEN], compression::ZSTD);
        sealed[NONCE_LEN] = compression::NONE; // flip the header without re-encrypting
        assert!(c.open("k", &sealed).is_err(), "header is bound into the AAD, tampering must fail auth");
    }

    #[test]
    fn rejects_a_sealed_blob_too_short_to_contain_a_header() {
        let c = test_cipher();
        assert!(c.open("k", &[0u8; NONCE_LEN]).is_err());
    }
}
