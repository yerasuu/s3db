//! Optional compression before sealing, isolated from the AEAD/framing
//! logic that decides *whether* to apply it -- swapping the codec (a
//! different algorithm, a different level policy) never needs to touch
//! [`crate::Cipher::seal`]/[`crate::Cipher::open`], only this file and its
//! one-byte header constants.

use anyhow::Context;
use std::borrow::Cow;

/// [`crate::Cipher::seal`]'s one-byte compression header: `0` for
/// stored-raw, `1` for zstd. Deliberately not used by [`crate::stream`]'s
/// own format -- what goes through there is always an already-compressed
/// git pack, a second compression pass over already-compressed bytes buys
/// nothing but CPU, so streaming has no compression header of its own.
pub(crate) const NONE: u8 = 0;
pub(crate) const ZSTD: u8 = 1;

/// How [`crate::Cipher::seal`] decides whether to zstd-compress `plaintext`
/// before encrypting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionStrategy {
    /// Never compress. `s3db`'s own default profile (small, uniform
    /// objects -- see `s3db::payload::MAX_OBJECT_BYTES`) fixes this
    /// statically: the size check `Auto` would otherwise run on every write
    /// almost never trips at this scale, so the branch is cut from the hot
    /// path entirely rather than evaluated per call.
    None,
    /// Compress plaintext at or above `threshold_bytes`, zstd default level.
    /// Falls back to storing raw if compression doesn't actually shrink the
    /// input (already-compressed or high-entropy data) -- [`crate::Cipher::open`]
    /// doesn't need to know or care which happened, the header says.
    Auto { threshold_bytes: usize },
}

/// The `(header byte, payload bytes)` [`crate::Cipher::seal`] actually
/// encrypts -- `payload` is `plaintext` itself for [`CompressionStrategy::None`]
/// (or an `Auto` that decided not to compress), or its zstd-compressed form.
pub(crate) fn compress_for_seal(plaintext: &[u8], compression: CompressionStrategy) -> (u8, Cow<'_, [u8]>) {
    let threshold_bytes = match compression {
        CompressionStrategy::None => return (NONE, Cow::Borrowed(plaintext)),
        CompressionStrategy::Auto { threshold_bytes } => threshold_bytes,
    };
    if plaintext.len() < threshold_bytes {
        return (NONE, Cow::Borrowed(plaintext));
    }
    match zstd::encode_all(plaintext, 0) {
        Ok(compressed) if compressed.len() < plaintext.len() => (ZSTD, Cow::Owned(compressed)),
        // Didn't actually help (already-compressed/high-entropy input) or
        // the compressor itself failed -- store raw either way rather than
        // pay decode cost for zero benefit, or fail a write over what's
        // fundamentally an optional optimization.
        _ => (NONE, Cow::Borrowed(plaintext)),
    }
}

/// Reverses [`compress_for_seal`]'s choice, given the header byte
/// [`crate::Cipher::open`] read back.
pub(crate) fn decompress(header: u8, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    match header {
        NONE => Ok(payload),
        ZSTD => zstd::decode_all(&payload[..]).context("decompressing"),
        other => anyhow::bail!("invalid ciphertext (unknown compression header {other})"),
    }
}

#[cfg(test)]
#[path = "../tests/unit/compression.rs"]
mod tests;
