//! Which AEAD a sealed object was sealed with, and the one-byte header that
//! records it. Isolated from [`crate::Cipher`] so adding an algorithm is a
//! variant plus a match arm here, and from [`crate::kdf`] so the key
//! material stays the same 32 bytes whichever algorithm consumes it.

use crate::kdf::KEY_LEN;
use aes_gcm::Aes256Gcm;
use anyhow::{Result, bail};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

/// Bytes reserved for the nonce in both on-disk formats, sized for the
/// longest nonce any supported algorithm uses. An algorithm with a shorter
/// nonce (AES-256-GCM's 96 bits) takes the first [`CipherAlgorithm::nonce_len`]
/// bytes and ignores the rest.
///
/// Fixed rather than per-algorithm because the header byte that says *which*
/// algorithm sealed an object sits immediately after this field: a
/// variable-length nonce would mean having to know the algorithm to find the
/// byte that tells you the algorithm. The cost is 12 wasted bytes per
/// AES-sealed object; the trailing bytes carry no meaning, so nothing reads
/// or checks them.
pub(crate) const NONCE_FIELD_LEN: usize = 24;

/// The AEAD used to seal an object. Every variant takes the same 32-byte
/// key from [`crate::kdf`], so the algorithm is a per-object property, not a
/// property of the passphrase or the bucket — one bucket can hold objects
/// sealed by different algorithms at once, which is what lets the default be
/// rotated without re-sealing everything up front.
///
/// Wire codes are permanent: a new algorithm gets the next free code, and an
/// existing one is never renumbered or removed, or every object already
/// sealed under it becomes unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherAlgorithm {
    /// 24-byte nonce (vs. 12 for plain ChaCha20Poly1305). With random nonces
    /// (not a counter) the extra 12 bytes matter: at this object volume, a
    /// 96-bit nonce collision is no longer astronomically unlikely, a
    /// 192-bit one still is.
    #[default]
    XChaCha20Poly1305,
    /// For callers that need AES specifically (a hardware-acceleration or
    /// compliance requirement). Its 96-bit nonce is why random nonces are a
    /// real consideration here: the birthday bound is reachable at high
    /// object counts under a single key, so prefer the default unless
    /// something external forces this one.
    Aes256Gcm,
}

impl CipherAlgorithm {
    /// Every variant, in wire-code order. A [`crate::Cipher`] builds one
    /// keyed instance per entry up front so it can open an object sealed by
    /// any of them, not just the one it seals with — adding an algorithm
    /// means adding it here too, or nothing will ever be able to read what
    /// it seals.
    pub(crate) const ALL: [CipherAlgorithm; 2] = [CipherAlgorithm::XChaCha20Poly1305, CipherAlgorithm::Aes256Gcm];

    /// This algorithm's permanent wire code, stored in the header's high
    /// nibble.
    pub(crate) const fn code(self) -> u8 {
        match self {
            CipherAlgorithm::XChaCha20Poly1305 => 0x0,
            CipherAlgorithm::Aes256Gcm => 0x1,
        }
    }

    pub(crate) const fn nonce_len(self) -> usize {
        match self {
            CipherAlgorithm::XChaCha20Poly1305 => 24,
            CipherAlgorithm::Aes256Gcm => 12,
        }
    }

    /// Position in [`Self::ALL`] — the wire code doubles as the index, so
    /// looking up the instance that can open a given object is a direct
    /// array index rather than a search.
    pub(crate) const fn index(self) -> usize {
        self.code() as usize
    }
}

/// Splits [`crate::Cipher::seal`]'s header byte into `(algorithm code,
/// compression code)`. The algorithm lives in the high nibble specifically
/// so that every object sealed before this byte carried an algorithm at all
/// reads back as `0x0` — [`CipherAlgorithm::XChaCha20Poly1305`], which is
/// exactly what sealed them.
pub(crate) const fn unpack_header(header: u8) -> (u8, u8) {
    (header >> 4, header & 0x0F)
}

/// Inverse of [`unpack_header`]. Panics in debug if `compression` doesn't
/// fit a nibble; the compression codes are crate-internal constants, so a
/// value that wide is a bug here, not bad input.
pub(crate) const fn pack_header(algorithm_code: u8, compression: u8) -> u8 {
    debug_assert!(compression <= 0x0F, "compression code must fit one nibble");
    (algorithm_code << 4) | (compression & 0x0F)
}

/// A keyed AEAD instance, one variant per [`CipherAlgorithm`]. Kept
/// crate-private: callers pick an algorithm, never an instance.
#[derive(Clone)]
pub(crate) enum Keyed {
    XChaCha20Poly1305(Box<XChaCha20Poly1305>),
    Aes256Gcm(Box<Aes256Gcm>),
}

impl Keyed {
    pub(crate) fn new(algorithm: CipherAlgorithm, key: &[u8; KEY_LEN]) -> Self {
        match algorithm {
            CipherAlgorithm::XChaCha20Poly1305 => {
                Keyed::XChaCha20Poly1305(Box::new(XChaCha20Poly1305::new(key.into())))
            }
            CipherAlgorithm::Aes256Gcm => Keyed::Aes256Gcm(Box::new(Aes256Gcm::new(key.into()))),
        }
    }

    pub(crate) const fn algorithm(&self) -> CipherAlgorithm {
        match self {
            Keyed::XChaCha20Poly1305(_) => CipherAlgorithm::XChaCha20Poly1305,
            Keyed::Aes256Gcm(_) => CipherAlgorithm::Aes256Gcm,
        }
    }

    /// Encrypts with the first [`CipherAlgorithm::nonce_len`] bytes of
    /// `nonce_field`. Infallible in practice: the only documented failure is
    /// a plaintext past the algorithm's theoretical size limit (hundreds of
    /// GiB for XChaCha, 64 GiB for AES-GCM), which neither the small-object
    /// path (bounded by the caller's own object-size guard) nor the stream
    /// path (bounded by one chunk) can reach.
    pub(crate) fn encrypt(&self, nonce_field: &[u8; NONCE_FIELD_LEN], msg: &[u8], aad: &[u8]) -> Vec<u8> {
        let payload = Payload { msg, aad };
        let nonce = &nonce_field[..self.algorithm().nonce_len()];
        match self {
            Keyed::XChaCha20Poly1305(c) => c
                .encrypt(nonce.try_into().expect("nonce_len matches this algorithm"), payload)
                .expect("XChaCha20Poly1305::encrypt never fails at these sizes"),
            Keyed::Aes256Gcm(c) => c
                .encrypt(nonce.try_into().expect("nonce_len matches this algorithm"), payload)
                .expect("Aes256Gcm::encrypt never fails at these sizes"),
        }
    }

    /// Reverses [`Self::encrypt`]. A single opaque error on purpose — a
    /// caller (and anything watching it) must not be able to tell a wrong
    /// key from a wrong AAD from tampered bytes.
    pub(crate) fn decrypt(&self, nonce_field: &[u8; NONCE_FIELD_LEN], msg: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
        let payload = Payload { msg, aad };
        let nonce = &nonce_field[..self.algorithm().nonce_len()];
        match self {
            Keyed::XChaCha20Poly1305(c) => c.decrypt(nonce.try_into().ok()?, payload).ok(),
            Keyed::Aes256Gcm(c) => c.decrypt(nonce.try_into().ok()?, payload).ok(),
        }
    }
}

/// Header nibble for an object that isn't encrypted at all
/// ([`EncryptionMode::Disabled`]). Deliberately at the top of the range
/// rather than the next free code, so adding algorithms one at a time can
/// never walk into it.
pub(crate) const UNENCRYPTED_CODE: u8 = 0xF;

/// Every supported AEAD's tag length. Both are 128-bit; a future algorithm
/// with a different tag would have to make this per-[`Sealer`] instead —
/// [`crate::stream`]'s size accounting is the only thing that reads it.
pub(crate) const TAG_LEN: usize = 16;

/// What actually sealed an object: an AEAD, or nothing at all. The
/// unencrypted case is deliberately *not* a [`CipherAlgorithm`] variant —
/// callers pick an algorithm, and "no encryption" must never be reachable by
/// picking one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sealer {
    Algorithm(CipherAlgorithm),
    Plaintext,
}

impl Sealer {
    pub(crate) const fn code(self) -> u8 {
        match self {
            Sealer::Algorithm(a) => a.code(),
            Sealer::Plaintext => UNENCRYPTED_CODE,
        }
    }

    /// Rejects an object whose header names something this build doesn't
    /// know — a forward-compatibility guard, not an authentication one: an
    /// object sealed by a newer version must fail loudly here rather than be
    /// misread as one of the algorithms that does exist.
    pub(crate) fn from_code(code: u8) -> Result<Self> {
        match code {
            0x0 => Ok(Sealer::Algorithm(CipherAlgorithm::XChaCha20Poly1305)),
            0x1 => Ok(Sealer::Algorithm(CipherAlgorithm::Aes256Gcm)),
            UNENCRYPTED_CODE => Ok(Sealer::Plaintext),
            other => bail!("invalid ciphertext (unknown cipher algorithm {other:#x})"),
        }
    }

    /// Bytes of authentication tag this sealer appends. Zero for
    /// [`Sealer::Plaintext`] — which is the whole point of the mode, and why
    /// nothing sealed that way can detect tampering.
    pub(crate) const fn tag_len(self) -> usize {
        match self {
            Sealer::Algorithm(_) => TAG_LEN,
            Sealer::Plaintext => 0,
        }
    }
}

/// Whether a [`crate::Cipher`] encrypts at all, and with what. `Enabled` is
/// the default: turning encryption off takes an explicit `Disabled`, never
/// an omission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionMode {
    Enabled {
        algorithm: CipherAlgorithm,
    },
    /// No AEAD, no key derivation, no passphrase required — objects are
    /// stored as-is, marked unencrypted in their header so a reader never
    /// has to guess. Nothing sealed this way is confidential *or*
    /// tamper-evident: with no tag, a storage provider can rewrite content
    /// undetectably. Only for a caller that genuinely doesn't want
    /// encryption-at-rest, not as a performance knob.
    Disabled,
}

impl Default for EncryptionMode {
    fn default() -> Self {
        EncryptionMode::Enabled {
            algorithm: CipherAlgorithm::default(),
        }
    }
}

#[cfg(test)]
mod tests;
