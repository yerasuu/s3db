//! The `Cipher` type itself: the keyed AEAD instances (one per
//! [`CipherAlgorithm`]) and the small-object `seal`/`open` format, built on
//! [`crate::kdf`] for key derivation, [`crate::algorithm`] for the AEAD
//! dispatch, and [`crate::compression`] for the optional compression step.
//! [`crate::stream`] is the separate large-object format, sharing only
//! [`NONCE_LEN`] and this type with what's here.

use crate::algorithm::{self, CipherAlgorithm, EncryptionMode, Keyed, NONCE_FIELD_LEN, Sealer};
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
enum Inner {
    Encrypting {
        /// One keyed instance per [`CipherAlgorithm`], indexed by
        /// [`CipherAlgorithm::index`]. All of them are built up front from
        /// the same derived key, so [`Cipher::open`] can read an object
        /// sealed by any algorithm regardless of which one this instance
        /// seals with -- that's what makes changing the default affect new
        /// writes only, never forcing a re-seal of what's already stored.
        keyed: [Keyed; CipherAlgorithm::ALL.len()],
        /// The algorithm [`Cipher::seal`] writes with. Never consulted on
        /// `open`: there the object's own header decides.
        active: CipherAlgorithm,
    },
    /// [`EncryptionMode::Disabled`]: no key was ever derived.
    Plaintext,
}

#[derive(Clone)]
pub struct Cipher(Inner);

// Manual, no derive: we don't want an accidental `{:?}` (log, panic message)
// to have the slightest chance of printing key material.
impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Cipher({:?}, ..)", self.mode())
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
        Ok(Cipher(Inner::Encrypting {
            keyed: CipherAlgorithm::ALL.map(|a| Keyed::new(a, &key)),
            active: algorithm,
        }))
    }

    /// A `Cipher` that doesn't encrypt -- see [`EncryptionMode::Disabled`]
    /// for what that gives up. No passphrase, no key derivation, no Argon2id
    /// pass at startup.
    pub fn disabled() -> Self {
        Cipher(Inner::Plaintext)
    }

    /// Builds whichever `Cipher` `mode` calls for, so a caller that reads its
    /// mode from config doesn't have to branch. `passphrase`/`salt` are
    /// ignored (and no key is derived) under [`EncryptionMode::Disabled`].
    pub fn derive_for(mode: EncryptionMode, passphrase: &str, salt: &[u8; crate::kdf::SALT_LEN]) -> Result<Self> {
        match mode {
            EncryptionMode::Enabled { algorithm } => Self::derive_with(passphrase, salt, algorithm),
            EncryptionMode::Disabled => Ok(Self::disabled()),
        }
    }

    /// What this instance seals with.
    pub fn mode(&self) -> EncryptionMode {
        match &self.0 {
            Inner::Encrypting { active, .. } => EncryptionMode::Enabled { algorithm: *active },
            Inner::Plaintext => EncryptionMode::Disabled,
        }
    }

    /// The sealer [`Self::seal`] writes with -- `pub(crate)` so
    /// [`crate::stream`] can stamp its own header with the same choice.
    pub(crate) fn sealer(&self) -> Sealer {
        match &self.0 {
            Inner::Encrypting { active, .. } => Sealer::Algorithm(*active),
            Inner::Plaintext => Sealer::Plaintext,
        }
    }

    /// Refuses an object whose sealer disagrees with this cipher's mode.
    ///
    /// Without this, [`EncryptionMode::Disabled`] would be a downgrade
    /// attack against every *enabled* deployment: anything able to write to
    /// the bucket could replace a sealed object with a plaintext one marked
    /// unencrypted, and a reader that just dispatched on the header would
    /// hand the content back as if nothing were wrong. An encrypting cipher
    /// accepts encrypted objects only; a disabled one accepts unencrypted
    /// objects only.
    pub(crate) fn accept(&self, sealer: Sealer) -> Result<()> {
        match (&self.0, sealer) {
            (Inner::Encrypting { .. }, Sealer::Plaintext) => {
                bail!("refusing an unencrypted object: this cipher has encryption enabled")
            }
            (Inner::Plaintext, Sealer::Algorithm(_)) => {
                bail!("refusing an encrypted object: this cipher has encryption disabled")
            }
            _ => Ok(()),
        }
    }

    /// Seals one buffer with [`Self::sealer`] -- the shared primitive under
    /// both [`Self::seal`] and [`crate::stream`]'s per-chunk framing.
    pub(crate) fn seal_chunk(&self, nonce_field: &[u8; NONCE_LEN], msg: &[u8], aad: &[u8]) -> Vec<u8> {
        match &self.0 {
            Inner::Encrypting { keyed, active } => keyed[active.index()].encrypt(nonce_field, msg, aad),
            Inner::Plaintext => msg.to_vec(),
        }
    }

    /// Reverses [`Self::seal_chunk`] for an object sealed by `sealer`, after
    /// checking that `sealer` is one this cipher's mode accepts at all.
    pub(crate) fn open_chunk(
        &self,
        sealer: Sealer,
        nonce_field: &[u8; NONCE_LEN],
        msg: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>> {
        self.accept(sealer)?;
        match (&self.0, sealer) {
            (Inner::Encrypting { keyed, .. }, Sealer::Algorithm(algorithm)) => {
                keyed[algorithm.index()].decrypt(nonce_field, msg, aad).ok_or_else(|| {
                    anyhow::anyhow!(
                        "couldn't decrypt (wrong passphrase, or data was modified/moved from a different key)"
                    )
                })
            }
            // `accept` above already rejected every other pairing.
            _ => Ok(msg.to_vec()),
        }
    }

    /// Encrypts `plaintext`, bound to `aad` (the object's S3 key). This
    /// stops a malicious storage provider from copying one object's
    /// ciphertext onto another and passing it off as valid: `open` with an
    /// `aad` different from the one used in `seal` fails authentication.
    ///
    /// Format: `nonce(24 bytes) || header(1 byte) || ciphertext+tag`. The
    /// header's high nibble records which [`CipherAlgorithm`] sealed the
    /// object (or that it isn't encrypted at all) and its low nibble whether
    /// the plaintext was compressed first (see [`CompressionStrategy`]); the
    /// whole byte is bound into the AEAD associated data, so neither half
    /// can be tampered with independently of the ciphertext.
    pub fn seal(&self, aad: &str, plaintext: &[u8], compression: CompressionStrategy) -> Vec<u8> {
        let (compression_code, payload) = compression::compress_for_seal(plaintext, compression);
        // Filled end to end even for an algorithm with a shorter nonce: the
        // trailing bytes are never read, and random beats zero-padding for
        // not implying they mean something. Under `Disabled` there's no
        // nonce at all, but the field stays so the header keeps its fixed
        // offset -- `open` has to find it before it knows what sealed the
        // object.
        let mut nonce_field = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_field).expect("system RNG unavailable");
        let header = algorithm::pack_header(self.sealer().code(), compression_code);
        let combined_aad = header_bound_aad(aad, header);
        let mut ciphertext = self.seal_chunk(&nonce_field, &payload, &combined_aad);
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
        let (sealer_code, compression_code) = algorithm::unpack_header(header);
        let sealer = Sealer::from_code(sealer_code)?;
        let combined_aad = header_bound_aad(aad, header);
        let payload = self.open_chunk(sealer, nonce_field, ciphertext, &combined_aad)?;
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
#[path = "../tests/unit/cipher.rs"]
mod tests;
