//! The one hashing primitive [`crate::index::ShardedIndex`] and
//! [`crate::collection::CollectionKeyStrategy::HashPrefix`] both build their
//! key-spreading on. Deliberately not `std`'s default hasher: that's
//! randomized per-process on purpose (DoS resistance for `HashMap`), which
//! is exactly wrong here -- two processes (or the same process across a
//! restart) must compute the *same* shard for the same `raw`, forever, or
//! reads and writes stop agreeing on where an entry lives.

/// FNV-1a, 64-bit. Simple, fast, and (unlike `std`'s `SipHash`) stable
/// across processes and restarts -- the only property this actually needs;
/// cryptographic hash-flooding resistance is irrelevant to a key that's
/// never attacker-controlled input in the way a `HashMap` key can be.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Which of `shard_count` buckets `raw` belongs to -- any positive count,
/// not just a power of two (that's what [`crate::collection::KeyEntropy::HashPrefix`]
/// wants; [`shard_of`] below is the power-of-two-doubling specialization
/// [`crate::sharded_index::ShardedIndex`]'s rebalance protocol needs).
pub(crate) fn shard_of_count(raw: &str, shard_count: u32) -> u32 {
    (fnv1a64(raw.as_bytes()) % (shard_count.max(1) as u64)) as u32
}

/// Which of `2^prefix_bits` shards `raw` belongs to. `prefix_bits: 0` always
/// returns shard `0` (a single, unsharded "shard") -- the natural default
/// for an index/collection that's never been rebalanced.
pub(crate) fn shard_of(raw: &str, prefix_bits: u8) -> u32 {
    shard_of_count(raw, 1u32 << prefix_bits.min(31))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_bits_is_always_shard_zero() {
        assert_eq!(shard_of("anything", 0), 0);
        assert_eq!(shard_of("something else", 0), 0);
    }

    #[test]
    fn same_input_always_lands_on_the_same_shard() {
        assert_eq!(shard_of("alice", 8), shard_of("alice", 8));
    }

    #[test]
    fn spreads_across_multiple_shards() {
        let shards: std::collections::HashSet<u32> = (0..1000).map(|i| shard_of(&format!("user-{i}"), 4)).collect();
        assert!(
            shards.len() > 1,
            "1000 distinct inputs should not all land on the same shard"
        );
    }
}
