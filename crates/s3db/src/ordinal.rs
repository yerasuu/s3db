//! Fixed-width numeric names, so that lexicographic key order *is* numeric
//! order.
//!
//! Object storage sorts keys as bytes, and so does
//! [`crate::Collection::list_names`]. That makes `"10"` sort before `"9"`,
//! which is invisible until an entity keyed by a number (a chapter, a
//! revision, a sequence position) reaches double digits and its listing
//! silently interleaves. Nothing in `Backend` can fix that — a lexicographic
//! order is the only one `list_prefix` has to offer — so the fix belongs in
//! how the name is written: zero-pad to a fixed width and the two orders
//! coincide for every value the type can hold.
//!
//! ```
//! use s3db::ordinal;
//! let mut names = vec![ordinal::encode_u64(10), ordinal::encode_u64(9)];
//! names.sort();
//! assert_eq!(ordinal::decode_u64(&names[0]), Some(9));
//! ```
//!
//! These are names, not keys: pass them to `Collection`/`Blob` as the
//! entity name and the prefix layout stays whatever the caller chose.

/// Digits in an encoded name: `u64::MAX` is 20 decimal digits, so every
/// value encodes to exactly this width and comparisons never have to
/// consider length.
pub const ORDINAL_WIDTH: usize = 20;

/// `n` as a zero-padded decimal name of exactly [`ORDINAL_WIDTH`] digits.
pub fn encode_u64(n: u64) -> String {
    format!("{n:0ORDINAL_WIDTH$}")
}

/// The `u64` an [`encode_u64`] name encodes, or `None` if `name` isn't one:
/// wrong width, non-digit bytes, or a value past `u64::MAX`. Strict on width
/// on purpose — accepting `"9"` here would accept exactly the unpadded names
/// this module exists to stop from being written.
pub fn decode_u64(name: &str) -> Option<u64> {
    if name.len() != ORDINAL_WIDTH || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    name.parse().ok()
}

/// `n` as a name that sorts in numeric order *including* negatives, by
/// biasing the value into `u64` first (`i64::MIN` maps to 0). Without the
/// bias a signed value would need a sign character, and `'-'` sorts before
/// every digit, which would put `-1` before `-2`.
pub fn encode_i64(n: i64) -> String {
    encode_u64((n as i128 - i64::MIN as i128) as u64)
}

/// Inverse of [`encode_i64`].
pub fn decode_i64(name: &str) -> Option<i64> {
    let biased = decode_u64(name)?;
    Some((biased as i128 + i64::MIN as i128) as i64)
}

#[cfg(test)]
#[path = "../tests/unit/ordinal.rs"]
mod tests;
