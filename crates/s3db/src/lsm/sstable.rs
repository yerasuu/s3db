//! The immutable, block-structured object one [`super::Table::flush`] call
//! produces — `docs/s3db-fulldb-roadmap.md`'s "one flush = one PUT," the
//! move that decouples request volume from row count.
//!
//! ```text
//! [block 0][block 1]...[block N-1][footer][footer_len: u64 LE, last 8 bytes]
//! ```
//! Each block is `[payload_len: u32 LE][payload]`, `payload` an
//! `rmp_serde`-encoded `Vec<(LsmKey, MemValue)>` — row-oriented for now
//! (`docs/s3db-fulldb-roadmap.md` phase 4 replaces this with real per-column
//! arrays; nothing outside this module's internals needs to change when it
//! does). The footer is `[bloom_len: u32 LE][bloom][block_index]`, written
//! once at the very end so a reader who already knows this object's total
//! size (from the manifest, phase 2) can fetch exactly the footer in one
//! `get_range` call, then exactly the one block it needs in a second —
//! never the whole object.
//!
//! [`build`] is the only way to produce one of these (always from a full,
//! already-sorted memtable drain); [`read_all`]/[`open_footer`] are the two
//! read primitives everything above this module composes: a full linear
//! scan (used by [`super::Table`]'s own point lookups today, and by the
//! phase-3 compactor later to merge whole tables) or a footer-only open (for
//! the bloom+block-index-driven partial reads phase 2 adds).

use super::LsmKey;
use super::bloom::Bloom;
use super::memtable::MemValue;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `(min_key, max_key, offset, len)` for one block — `offset`/`len` describe
/// exactly the block's payload bytes (after its own length prefix), so a
/// targeted `get_range(key, offset, len)` decodes straight into the block's
/// rows with no further trimming.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    pub min_key: LsmKey,
    pub max_key: LsmKey,
    pub offset: u64,
    pub len: u32,
}

/// What [`build`] hands back alongside the object bytes — everything a
/// caller needs to record in a manifest entry (phase 2) without re-parsing
/// the object it just wrote.
#[derive(Debug, Clone, PartialEq)]
pub struct SSTableMeta {
    pub min_key: LsmKey,
    pub max_key: LsmKey,
    pub row_count: usize,
    pub byte_len: u64,
    pub block_index: Vec<BlockIndexEntry>,
}

/// Serializes `rows` (must be non-empty and already sorted — exactly what
/// [`super::Memtable::drain_sorted`] gives) into one SSTable object, grouping
/// every `rows_per_block` entries into a block.
pub fn build(rows: &BTreeMap<LsmKey, MemValue>, rows_per_block: usize) -> (Vec<u8>, SSTableMeta) {
    assert!(
        !rows.is_empty(),
        "build() needs at least one row; caller checks this before flushing"
    );
    assert!(rows_per_block > 0);

    let mut object = Vec::new();
    let mut block_index = Vec::new();
    let mut bloom = Bloom::new(rows.len());
    let mut chunk: Vec<(LsmKey, MemValue)> = Vec::with_capacity(rows_per_block);

    for (key, value) in rows {
        bloom.insert(key);
        chunk.push((key.clone(), value.clone()));
        if chunk.len() >= rows_per_block {
            write_block(&mut object, &mut block_index, std::mem::take(&mut chunk));
        }
    }
    write_block(&mut object, &mut block_index, chunk); // trailing partial block, if any

    let bloom_bytes = bloom.to_bytes();
    let block_index_bytes = rmp_serde::to_vec_named(&block_index).expect("serializing a block index never fails");
    let mut footer = Vec::with_capacity(4 + bloom_bytes.len() + block_index_bytes.len());
    footer.extend_from_slice(&(bloom_bytes.len() as u32).to_le_bytes());
    footer.extend_from_slice(&bloom_bytes);
    footer.extend_from_slice(&block_index_bytes);

    object.extend_from_slice(&footer);
    object.extend_from_slice(&(footer.len() as u64).to_le_bytes());

    let meta = SSTableMeta {
        min_key: rows.keys().next().expect("checked non-empty above").clone(),
        max_key: rows.keys().next_back().expect("checked non-empty above").clone(),
        row_count: rows.len(),
        byte_len: object.len() as u64,
        block_index,
    };
    (object, meta)
}

fn write_block(object: &mut Vec<u8>, block_index: &mut Vec<BlockIndexEntry>, chunk: Vec<(LsmKey, MemValue)>) {
    if chunk.is_empty() {
        return;
    }
    let min_key = chunk.first().expect("checked non-empty above").0.clone();
    let max_key = chunk.last().expect("checked non-empty above").0.clone();
    let payload = rmp_serde::to_vec_named(&chunk).expect("serializing a block never fails");
    let offset = object.len() as u64 + 4; // past this block's own length prefix
    object.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    object.extend_from_slice(&payload);
    block_index.push(BlockIndexEntry {
        min_key,
        max_key,
        offset,
        len: payload.len() as u32,
    });
}

/// The footer's own parsed form: the bloom filter and block index, plus
/// where the footer itself starts (== the byte length of everything that
/// came before it, i.e. all the blocks).
///
/// Nothing in this crate's own non-test code constructs one yet -- see
/// [`read_all`]'s doc for why that's expected at this phase, not a
/// leftover.
#[allow(dead_code)]
pub(crate) struct Footer {
    pub(crate) bloom: Bloom,
    pub(crate) block_index: Vec<BlockIndexEntry>,
    pub(crate) blocks_end: u64,
}

/// Parses the footer out of a *complete* SSTable object already in memory.
/// Phase 2's manifest-driven open fetches only the footer's own byte range
/// via `get_range` instead of the whole object first — this function's
/// parsing logic is what both paths share, just fed a smaller slice.
#[allow(dead_code)]
pub(crate) fn open_footer(object: &[u8]) -> Result<Footer> {
    ensure!(object.len() >= 8, "SSTable object too short to contain a footer length");
    let (body, footer_len_bytes) = object.split_at(object.len() - 8);
    let footer_len = u64::from_le_bytes(footer_len_bytes.try_into().unwrap()) as usize;
    ensure!(
        body.len() >= footer_len,
        "SSTable footer_len {footer_len} exceeds the {} bytes before it",
        body.len()
    );
    let blocks_end = (body.len() - footer_len) as u64;
    let footer = &body[body.len() - footer_len..];

    ensure!(footer.len() >= 4, "SSTable footer too short to contain a bloom length");
    let bloom_len = u32::from_le_bytes(footer[0..4].try_into().unwrap()) as usize;
    ensure!(
        footer.len() >= 4 + bloom_len,
        "SSTable footer shorter than its declared bloom filter"
    );
    let bloom = Bloom::from_bytes(&footer[4..4 + bloom_len]).context("parsing SSTable bloom filter")?;
    let block_index: Vec<BlockIndexEntry> =
        rmp_serde::from_slice(&footer[4 + bloom_len..]).context("parsing SSTable block index")?;

    Ok(Footer {
        bloom,
        block_index,
        blocks_end,
    })
}

/// Decodes one block's rows from its raw payload bytes — exactly what a
/// [`BlockIndexEntry`]'s `(offset, len)` locates, whether those bytes came
/// from a full in-memory object ([`read_all`]) or a single targeted
/// `get_range` (phase 2).
#[allow(dead_code)]
pub(crate) fn decode_block(payload: &[u8]) -> Result<Vec<(LsmKey, MemValue)>> {
    rmp_serde::from_slice(payload).context("decoding SSTable block")
}

/// Every row in a complete SSTable object, in ascending key order — a full
/// linear scan, no bloom/block-index pruning. Not called from this crate's
/// own non-test code yet: [`super::Table`] has no read path at all in this
/// phase (see the crate's `lsm` module doc), only this module's own tests
/// exercise it directly for now. It's not dead weight left over, though --
/// the phase-3 compactor merges whole tables by reading them exactly this
/// way, and phase 2's pruned, `get_range`-driven point lookup is layered on
/// top without this function changing.
#[allow(dead_code)]
pub(crate) fn read_all(object: &[u8]) -> Result<Vec<(LsmKey, MemValue)>> {
    let footer = open_footer(object)?;
    let mut out = Vec::new();
    let mut pos = 0usize;
    while (pos as u64) < footer.blocks_end {
        ensure!(pos + 4 <= object.len(), "SSTable truncated mid block-length-prefix");
        let payload_len = u32::from_le_bytes(object[pos..pos + 4].try_into().unwrap()) as usize;
        let payload_start = pos + 4;
        ensure!(
            payload_start + payload_len <= object.len(),
            "SSTable truncated mid block payload"
        );
        out.extend(decode_block(&object[payload_start..payload_start + payload_len])?);
        pos = payload_start + payload_len;
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
