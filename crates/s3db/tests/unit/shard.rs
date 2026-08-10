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
