//! A secondary index over an LSM [`Table`] — `docs/s3db-fulldb-roadmap.md`
//! phase 5's other half (see [`Table::scan`] for range scans over the
//! *primary* key). A row's primary key already sorts the base table by
//! whatever the caller chose; this is for the equally common case of
//! needing to find rows by some *other* field ("every row where `status ==
//! X`", "every row with `created_at` in this window") without a full scan.
//!
//! Implemented as a second, ordinary LSM [`Table`] whose own keys are a
//! `secondary_key || 0x00 || primary_key` composite (values are never
//! stored here -- a hit only ever needs to hand back the primary key, which
//! the caller then looks up in the real table). Same division of labor as
//! [`crate::index::SecondaryIndex`]: this crate only ever compares raw
//! bytes, so a caller who wants numeric or timestamp ordering on the
//! secondary field picks a byte encoding that already sorts that way
//! (big-endian integers, ISO-8601 timestamps).
//!
//! `secondary_key` must not itself contain a `0x00` byte -- [`split_key`]
//! finds the *first* one and treats it as the separator, so an embedded
//! `0x00` would silently corrupt the split. The same constraint a
//! null-terminated C string has, and just as workable in practice: none of
//! this crate's own byte encodings ([`super::value::Value`], big-endian
//! integers, UTF-8 text) ever produce one.

use super::LsmKey;
use super::table::{Table, TableConfig};
use anyhow::{Context, Result, ensure};

const SEPARATOR: u8 = 0x00;

/// Enforces this module's own documented invariant: `secondary` must never
/// contain a `0x00` byte, or [`split_key`] would find *that* embedded byte
/// instead of the real separator and silently hand back the wrong
/// primary/secondary split for this entry.
fn ensure_no_separator(secondary: &[u8]) -> Result<()> {
    ensure!(
        !secondary.contains(&SEPARATOR),
        "{secondary:?}: secondary key contains a 0x00 byte, which this index reserves as its separator"
    );
    Ok(())
}

/// `secondary || 0x00 || primary` -- the actual key stored in the index
/// table. Kept as a free function (not a method) since [`prefix_successor`]
/// needs to build the same shape independently, over just `secondary`, to
/// derive [`SecondaryLsmIndex::lookup`]'s upper bound.
fn compose_key(secondary: &[u8], primary: &[u8]) -> LsmKey {
    let mut key = Vec::with_capacity(secondary.len() + 1 + primary.len());
    key.extend_from_slice(secondary);
    key.push(SEPARATOR);
    key.extend_from_slice(primary);
    key
}

/// Reverses [`compose_key`], splitting at the first `0x00`.
fn split_key(composite: &[u8]) -> Result<(&[u8], &[u8])> {
    let separator_at = composite
        .iter()
        .position(|&b| b == SEPARATOR)
        .with_context(|| format!("{composite:?}: not a composite secondary-index key (no separator byte)"))?;
    Ok((&composite[..separator_at], &composite[separator_at + 1..]))
}

/// The smallest byte string that sorts strictly after every string starting
/// with `prefix` -- `None` only if `prefix` is empty or entirely `0xFF`
/// bytes, meaning there's no finite upper bound (nothing *does* sort past
/// "all 0xFF forever").
///
/// Standard technique: drop trailing `0xFF` bytes (they can't be
/// incremented without changing length, which would break the "same
/// length or shorter, sorts higher" property this needs), then increment
/// the last remaining byte. E.g. `[0x61, 0xFF]` -> `[0x62]`.
pub(crate) fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = prefix.to_vec();
    while bytes.last() == Some(&0xFF) {
        bytes.pop();
    }
    let last = bytes.last_mut()?;
    *last += 1;
    Some(bytes)
}

/// A second ordered [`Table`] mapping `secondary_key -> {primary_key, ...}`.
/// Every write against the real data must pair a [`Self::put`] here with
/// the base row write (and [`Self::delete`] with the base row's removal) --
/// nothing here keeps the two in sync automatically, same as
/// [`crate::index::SecondaryIndex`] never auto-syncs either.
pub struct SecondaryLsmIndex {
    table: Table,
}

impl SecondaryLsmIndex {
    /// `config`'s `root` should be a dedicated prefix (e.g. `"{base_root}/by_status"`)
    /// distinct from the base table's own -- they're two independent
    /// [`Table`]s, sharing a bucket but nothing else.
    pub async fn open(config: TableConfig) -> Result<Self> {
        Ok(SecondaryLsmIndex {
            table: Table::open(config).await?,
        })
    }

    pub async fn put(&self, secondary: &[u8], primary: &[u8]) -> Result<()> {
        ensure_no_separator(secondary)?;
        self.table.put(compose_key(secondary, primary), Vec::new()).await
    }

    pub async fn delete(&self, secondary: &[u8], primary: &[u8]) -> Result<()> {
        ensure_no_separator(secondary)?;
        self.table.delete(compose_key(secondary, primary)).await
    }

    /// Every primary key currently indexed under exactly `secondary` --
    /// an equality lookup, not a range.
    ///
    /// The scan bounds are `[secondary || 0x00, prefix_successor(secondary || 0x00))`,
    /// deliberately over `secondary || 0x00` (the separator included in the
    /// prefix), not over bare `secondary`: without the separator, a longer
    /// secondary key that merely starts with these same bytes (e.g. looking
    /// up `"ab"` while `"abc"` is also indexed) would wrongly fall inside
    /// the range too, since `"abc\0..."` sorts between `"ab\0..."` and
    /// `prefix_successor("ab")`. Appending the separator before computing
    /// the successor closes exactly that gap: `"abc..."` now sorts *past*
    /// `prefix_successor("ab\0")` because its third byte (`c`) is greater
    /// than the `0x00` the bound was built from.
    pub async fn lookup(&self, secondary: &[u8]) -> Result<Vec<LsmKey>> {
        ensure_no_separator(secondary)?;
        let mut prefix = secondary.to_vec();
        prefix.push(SEPARATOR);
        let upper = prefix_successor(&prefix);
        let rows = self.table.scan(Some(&prefix), upper.as_deref()).await?;
        rows.into_iter()
            .map(|(key, _)| split_key(&key).map(|(_, primary)| primary.to_vec()))
            .collect()
    }

    /// Every `(secondary_key, primary_key)` pair with `start <= secondary_key < end`
    /// (either bound `None` for unbounded) -- a genuine range over the
    /// secondary field, e.g. "every row with `created_at` in this window."
    ///
    /// Unlike [`Self::lookup`], the bounds are used exactly as given, no
    /// separator appended: comparing a bound *without* a suffix directly
    /// against a composite key *with* one is always correct on its own --
    /// extending a string can never make it sort before the string it
    /// extends -- the same proof [`crate::index::SecondaryIndex::segment_prefix`]
    /// already relies on, just against `0x00 || primary` as the suffix
    /// instead of `.json`.
    pub async fn scan(&self, start: Option<&[u8]>, end: Option<&[u8]>) -> Result<Vec<(LsmKey, LsmKey)>> {
        let rows = self.table.scan(start, end).await?;
        rows.into_iter()
            .map(|(key, _)| {
                let (secondary, primary) = split_key(&key)?;
                Ok((secondary.to_vec(), primary.to_vec()))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/secondary_index.rs"]
mod tests;
