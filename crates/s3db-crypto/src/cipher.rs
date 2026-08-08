//! The `Cipher` type itself: the keyed AEAD instances (one per
//! [`CipherAlgorithm`]) and the small-object `seal`/`open` format, built on
//! [`crate::kdf`] for key derivation, [`crate::algorithm`] for the AEAD
//! dispatch, and [`crate::compression`] for the optional compression step.
//! [`crate::stream`] is the separate large-object format, sharing only
//! [`NONCE_LEN`] and this type with what's here.

use crate::algorithm::{self, CipherAlgorithm, Keyed, NONCE_FIELD_LEN};
use crate::compression::{self, CompressionStrategy};
use crate::kdf;
use crate::stream;
use anyhow::{Context, Result, bail};
use std::path::Path;

/// Bytes every sealed object reserves for its nonce, whichever algorithm
/// sealed it -- see [`NONCE_FIELD_LEN`] for why it's fixed rather than
/// per-algorithm.
pub(crate) const NONCE_LEN: usize = NONCE_FIELD_LEN;

/// Binds the one-byte header into the AEAD associated data, alongside the
/// caller's own `aad` (the object's S3 key). The header sits unencrypted
/// next to the nonce ([`Cipher::open`] needs to read it before it can even
/// attempt to decrypt) -- without this, a malicious storage provider could
/// flip it undetected and make `open` misinterpret compressed bytes as raw,
/// or claim an algorithm other than the one that actually sealed the object.
/// The `\0` separator is cheap insurance against `aad` + header colliding
/// with some other `aad` that happens to already end in that same byte.
fn header_bound_aad(aad: &str, header: u8) -> Vec<u8> {
    let mut bound = aad.as_bytes().to_vec();
    bound.push(0);
    bound.push(header);
    bound
}

#[derive(Clone)]
pub struct Cipher {
    /// One keyed instance per [`CipherAlgorithm`], indexed by
    /// [`CipherAlgorithm::index`]. All of them are built up front from the
    /// same derived key, so [`Cipher::open`] can read an object sealed by
    /// any algorithm regardless of which one this instance seals with --
    /// that's what makes changing the default affect new writes only, never
    /// forcing a re-seal of what's already in the bucket.
    keyed: [Keyed; CipherAlgorithm::ALL.len()],
    /// The algorithm [`Cipher::seal`] writes with. Never consulted on
    /// `open`: there the object's own header decides.
    active: CipherAlgorithm,
}

// Manual, no derive: we don't want an accidental `{:?}` (log, panic message)
// to have the slightest chance of printing key material.
impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cipher({:?}, ..)", self.active)
    }
}

impl Cipher {
    /// Derives the encryption key from a passphrase + salt, sealing with the
    /// default algorithm -- see [`crate::kdf`] for the derivation itself and
    /// its fixed parameters, [`CipherAlgorithm`] for what "default" means.
    pub fn derive(passphrase: &str, salt: &[u8; crate::kdf::SALT_LEN]) -> Result<Self> {
        Self::derive_with(passphrase, salt, CipherAlgorithm::default())
    }

    /// [`Self::derive`] with an explicit sealing algorithm. Only affects
    /// what this instance *writes*: the returned `Cipher` opens objects
    /// sealed by any supported algorithm either way.
    pub fn derive_with(
        passphrase: &str,
        salt: &[u8; crate::kdf::SALT_LEN],
        algorithm: CipherAlgorithm,
    ) -> Result<Self> {
        let key = kdf::derive(passphrase, salt)?;
        Ok(Cipher {
            keyed: CipherAlgorithm::ALL.map(|a| Keyed::new(a, &key)),
            active: algorithm,
        })
    }

    /// The algorithm [`Self::seal`] uses.
    pub fn algorithm(&self) -> CipherAlgorithm {
        self.active
    }

    /// The keyed instance for `algorithm` -- `pub(crate)` so
    /// [`crate::stream`] can seal/open its own chunk framing without this
    /// type's fields ever being `pub`.
    pub(crate) fn keyed(&self, algorithm: CipherAlgorithm) -> &Keyed {
        &self.keyed[algorithm.index()]
    }

    /// Encrypts `plaintext`, bound to `aad` (the object's S3 key). This
    /// stops a malicious storage provider from copying one object's
    /// ciphertext onto another and passing it off as valid: `open` with an
    /// `aad` different from the one used in `seal` fails authentication.
    ///
    /// Format: `nonce(24 bytes) || header(1 byte) || ciphertext+tag`. The
    /// header's high nibble records which [`CipherAlgorithm`] sealed the
    /// object and its low nibble whether the plaintext was compressed first
    /// (see [`CompressionStrategy`]); the whole byte is bound into the AEAD
    /// associated data, so neither half can be tampered with independently
    /// of the ciphertext.
    pub fn seal(&self, aad: &str, plaintext: &[u8], compression: CompressionStrategy) -> Vec<u8> {
        let (compression_code, payload) = compression::compress_for_seal(plaintext, compression);
        // Filled end to end even for an algorithm with a shorter nonce: the
        // trailing bytes are never read, and random beats zero-padding for
        // not implying they mean something.
        let mut nonce_field = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_field).expect("system RNG unavailable");
        let header = algorithm::pack_header(self.active.code(), compression_code);
        let combined_aad = header_bound_aad(aad, header);
        let mut ciphertext = self.keyed(self.active).encrypt(&nonce_field, &payload, &combined_aad);
        let mut sealed = nonce_field.to_vec();
        sealed.push(header);
        sealed.append(&mut ciphertext);
        sealed
    }

    /// Opens what [`Self::seal`] sealed, dispatching on the algorithm its
    /// header names (and decompressing first if the header says so). Fails
    /// if the key, the `aad`, or the content aren't the originals — a single
    /// generic error on purpose, to avoid giving an attacker an "almost"
    /// signal (padding oracle).
    pub fn open(&self, aad: &str, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < NONCE_LEN + 1 {
            bail!("invalid ciphertext (too short)");
        }
        let (nonce_field, rest) = sealed.split_at(NONCE_LEN);
        let (header, ciphertext) = rest.split_at(1);
        let header = header[0];
        let nonce_field: &[u8; NONCE_LEN] = nonce_field.try_into().context("nonce has invalid length")?;
        let (algorithm_code, compression_code) = algorithm::unpack_header(header);
        let algorithm = algorithm::algorithm_from_code(algorithm_code)?;
        let combined_aad = header_bound_aad(aad, header);
        let payload = self
            .keyed(algorithm)
            .decrypt(nonce_field, ciphertext, &combined_aad)
            .ok_or_else(|| {
                anyhow::anyhow!("couldn't decrypt (wrong passphrase, or data was modified/moved from a different key)")
            })?;
        compression::decompress(compression_code, payload)
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

    /// `true` if `prefix` (as little as an object's first 8 bytes) was
    /// sealed by [`Self::seal_stream`] rather than [`Self::seal`] -- lets a
    /// caller handling objects of unknown provenance (any object under a
    /// prefix, not just ones it wrote itself) pick the matching
    /// `open`/`open_stream` without needing out-of-band knowledge of which
    /// format a given key used. See [`stream::is_stream_sealed`].
    pub fn is_stream_sealed(prefix: &[u8]) -> bool {
        stream::is_stream_sealed(prefix)
    }
}

#[cfg(test)]
mod tests;
