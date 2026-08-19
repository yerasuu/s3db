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

/// The three numbers bounding [`decompress`] against a decompression bomb
/// -- a crafted payload that is a few hundred bytes sealed and gigabytes
/// once expanded. The allowance for a payload is
/// `(len * RATIO).clamp(FLOOR, MAX)`.
///
/// Under [`crate::EncryptionMode::Enabled`] the payload is AEAD-verified
/// before it ever reaches here, so producing one takes the key. Under
/// [`crate::EncryptionMode::Disabled`] nothing authenticates it at all, and
/// anything that can write to the storage behind the caller can flip a
/// header nibble to `ZSTD` and hand over whatever it likes -- which is
/// exactly the case these bounds exist for.
///
/// `FLOOR` is why this isn't a bare ratio: genuinely repetitive plaintext
/// compresses far past 1024x (half a megabyte of one repeated byte lands
/// under a hundred), so a ratio alone would reject perfectly legitimate
/// data that [`compress_for_seal`] itself produced. The floor gives every
/// payload a flat allowance first and only lets the ratio raise it, so the
/// bound can never be tighter than one megabyte of output no matter how
/// small the compressed form got.
const MAX_DECOMPRESSED_RATIO: usize = 1024;
const MIN_DECOMPRESSED_BYTES: usize = 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;

/// How [`crate::Cipher::seal`] decides whether to zstd-compress `plaintext`
/// before encrypting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "compression", rename_all = "snake_case")]
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
/// [`crate::Cipher::open`] read back. Decompression is bounded (see
/// [`MAX_DECOMPRESSED_RATIO`]) rather than run to whatever size the payload
/// asks for.
pub(crate) fn decompress(header: u8, payload: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    match header {
        NONE => Ok(payload),
        ZSTD => decompress_bounded(&payload).context("decompressing"),
        other => anyhow::bail!("invalid ciphertext (unknown compression header {other})"),
    }
}

/// zstd-decodes `payload`, refusing to allocate past the bounds
/// [`MAX_DECOMPRESSED_RATIO`] documents. Streaming rather than
/// `zstd::decode_all` specifically so the limit is enforced *while*
/// decoding: `decode_all` would have to materialize the whole bomb before
/// anything could look at its size.
fn decompress_bounded(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;

    let limit = payload
        .len()
        .saturating_mul(MAX_DECOMPRESSED_RATIO)
        .clamp(MIN_DECOMPRESSED_BYTES, MAX_DECOMPRESSED_BYTES);
    let decoder = zstd::stream::read::Decoder::new(payload)?;
    // `limit + 1` so hitting exactly `limit` bytes is distinguishable from
    // overrunning it -- a payload whose real plaintext is exactly `limit`
    // bytes long is legitimate and must still decode.
    let mut out = Vec::new();
    decoder.take(limit as u64 + 1).read_to_end(&mut out)?;
    anyhow::ensure!(
        out.len() <= limit,
        "compressed payload expands past this crate's {limit}-byte decompression limit \
         (a {}-byte payload); refusing to allocate further",
        payload.len()
    );
    Ok(out)
}

#[cfg(test)]
#[path = "../tests/unit/compression.rs"]
mod tests;
