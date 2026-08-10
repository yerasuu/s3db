//! A minimal bloom filter, hand-rolled rather than pulling in a dependency
//! for something this small: a bit array plus double hashing (`h_i(x) = h1(x)
//! + i * h2(x)`, Kirsch–Mitzenmacher), which needs only two real hashes no
//! matter how many `k` ends up being. [`SSTable`](super::sstable::SSTable)
//! keeps one of these per flush so a point lookup can discard a whole
//! immutable object without opening it — see that module's doc and
//! `docs/s3db-fulldb-roadmap.md`'s phase 2 for why that matters.
//!
//! False positives are possible (say a key might be present when it isn't);
//! false negatives are not (if a key is actually in the filter, `contains`
//! always says so) — the one direction a bloom filter is allowed to be
//! wrong in, and the only direction that keeps "skip this SSTable" safe.

use std::hash::{Hash, Hasher};

#[derive(Debug, Clone)]
pub(crate) struct Bloom {
    bits: Vec<u64>,
    num_bits: u64,
    k: u32,
}

impl Bloom {
    /// Sized for `expected_items` at roughly 10 bits/item (~1% false
    /// positive rate at the standard `k = bits_per_item * ln(2)`) — a fixed,
    /// reasonable default rather than a tunable knob nothing here has asked
    /// for yet.
    pub(crate) fn new(expected_items: usize) -> Self {
        const BITS_PER_ITEM: u64 = 10;
        let expected_items = expected_items.max(1) as u64;
        let num_bits = (expected_items * BITS_PER_ITEM).next_power_of_two().max(64);
        let k = ((BITS_PER_ITEM as f64) * std::f64::consts::LN_2).round().max(1.0) as u32;
        Bloom {
            bits: vec![0u64; (num_bits / 64) as usize],
            num_bits,
            k,
        }
    }

    fn hashes(key: &[u8]) -> (u64, u64) {
        // Two independent hashes from one hasher family by salting the
        // input differently -- `DefaultHasher` (SipHash) is already a good
        // enough mix for a probabilistic filter; nothing here needs it to
        // be cryptographic.
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h1);
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        0xA5u8.hash(&mut h2); // salt so h2 isn't just h1 restated
        key.hash(&mut h2);
        (h1.finish(), h2.finish())
    }

    fn bit_positions(&self, key: &[u8]) -> impl Iterator<Item = u64> + '_ {
        let (h1, h2) = Self::hashes(key);
        (0..self.k as u64).map(move |i| h1.wrapping_add(i.wrapping_mul(h2)) % self.num_bits)
    }

    pub(crate) fn insert(&mut self, key: &[u8]) {
        for pos in self.bit_positions(key).collect::<Vec<_>>() {
            self.bits[(pos / 64) as usize] |= 1u64 << (pos % 64);
        }
    }

    /// `false` is a definitive "not in this SSTable"; `true` means "maybe"
    /// (could be a false positive) — see the module doc.
    pub(crate) fn contains(&self, key: &[u8]) -> bool {
        self.bit_positions(key)
            .all(|pos| self.bits[(pos / 64) as usize] & (1u64 << (pos % 64)) != 0)
    }

    /// `[num_bits: u64 LE][k: u32 LE][bits...]` -- fixed header, then the
    /// raw bit array. No length prefix on the bits themselves: `num_bits`
    /// already determines `bits.len()` (`num_bits.div_ceil(64)` words), and
    /// [`Self::from_bytes`] takes the rest of its input as exactly that.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12 + self.bits.len() * 8);
        out.extend_from_slice(&self.num_bits.to_le_bytes());
        out.extend_from_slice(&self.k.to_le_bytes());
        for word in &self.bits {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(bytes.len() >= 12, "bloom filter bytes too short for header");
        let num_bits = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let k = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let word_count = num_bits.div_ceil(64) as usize;
        let body = &bytes[12..];
        anyhow::ensure!(
            body.len() == word_count * 8,
            "bloom filter body length {} doesn't match expected {} bytes for {num_bits} bits",
            body.len(),
            word_count * 8
        );
        let bits = body
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
            .collect();
        Ok(Bloom { bits, num_bits, k })
    }
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/bloom.rs"]
mod tests;
