//! The immutable, block-structured object one [`super::Table::flush`] call
//! produces — `docs/s3db-fulldb-roadmap.md`'s "one flush = one PUT," the
//! move that decouples request volume from row count.
//!
//! ```text
//! [sealed block 0][sealed block 1]...[sealed block N-1][sealed footer][footer_len: u64 LE, last 8 bytes]
//! ```
//! Each unit (`[sealed_len: u32 LE][sealed bytes]`) is sealed
//! *independently* with [`Cipher::seal`], not the object as a whole —
//! deliberately, because AEAD ciphertext can't be partially decrypted or
//! authenticated: verifying the tag needs the complete ciphertext, so a
//! single whole-object seal would make phase 2's whole reason for
//! existing (fetch one block via `get_range`, not the object) impossible.
//! Sealing each block and the footer on their own means each is a
//! self-contained, independently verifiable unit — a targeted `get_range`
//! fetches exactly the sealed bytes for one unit and opens them with
//! nothing else. Each unit's AAD binds it to this exact SSTable key *and*
//! its position (`{sstable_key}#block{idx}` / `{sstable_key}#footer`), so a
//! storage provider can't splice a block from one SSTable — or from a
//! different position in the same one — into another without `open`
//! failing.
//!
//! A block's plaintext payload is `rmp_serde`-encoded `Vec<(LsmKey,
//! MemValue)>` — row-oriented for now (`docs/s3db-fulldb-roadmap.md` phase
//! 4 replaces this with real per-column arrays; nothing outside this
//! module's internals needs to change when it does). The footer's
//! plaintext is `[bloom_len: u32 LE][bloom][block_index]`, written once at
//! the very end so a reader who knows this object's total size and the
//! footer's sealed length (both recorded in the manifest, phase 2) can
//! fetch exactly the sealed footer in one `get_range` call, then exactly
//! the one block it needs in a second — never the whole object.
//!
//! [`build`] is the only way to produce one of these (always from a full,
//! already-sorted memtable drain); [`read_all`]/[`open_footer`] are the two
//! read primitives everything above this module composes: a full linear
//! scan (used by the phase-3 compactor to merge whole tables) or a
//! footer-only open (for the bloom+block-index-driven partial reads phase 2
//! adds).

use super::LsmKey;
use super::bloom::Bloom;
use super::memtable::MemValue;
use crate::cipher::{Cipher, CompressionStrategy};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A block's AAD -- binds a sealed block to this exact SSTable key and its
/// position among that key's blocks.
fn block_aad(sstable_key: &str, block_idx: usize) -> String {
    format!("{sstable_key}#block{block_idx}")
}

/// The footer's AAD -- same binding, for the one footer a table has.
fn footer_aad(sstable_key: &str) -> String {
    format!("{sstable_key}#footer")
}

/// `(min_key, max_key, offset, len)` for one block — `offset`/`len`
/// describe exactly the block's *sealed* bytes (after its own length
/// prefix), so a targeted `get_range(key, offset, len)` fetches exactly
/// what [`Cipher::open`] (with that block's AAD) needs, no further trimming
/// or extra bytes to discard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockIndexEntry {
    pub min_key: LsmKey,
    pub max_key: LsmKey,
    pub offset: u64,
    pub len: u32,
}

/// What [`build`] hands back alongside the object bytes — everything a
/// caller needs to record in a manifest entry (phase 2) without re-parsing
/// the object it just wrote. `footer_len` is the footer's *sealed* byte
/// length, which a reader needs up front to compute the exact `get_range`
/// for it (`byte_len - 8 - footer_len .. byte_len - 8`) without a
/// preliminary fetch just to learn how big the footer is.
#[derive(Debug, Clone, PartialEq)]
pub struct SSTableMeta {
    pub min_key: LsmKey,
    pub max_key: LsmKey,
    pub row_count: usize,
    pub byte_len: u64,
    pub footer_len: u64,
    pub block_index: Vec<BlockIndexEntry>,
}

/// Serializes `rows` (must be non-empty and already sorted — exactly what
/// [`super::Memtable::drain_sorted`] gives) into one SSTable object, sealing
/// every `rows_per_block` entries into their own encrypted block under
/// `sstable_key` (the S3 key this object is about to be written to — bound
/// into every unit's AAD, so it must be decided before calling this, not
/// after).
pub fn build(
    cipher: &Cipher,
    sstable_key: &str,
    rows: &BTreeMap<LsmKey, MemValue>,
    rows_per_block: usize,
) -> (Vec<u8>, SSTableMeta) {
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
            write_block(
                cipher,
                sstable_key,
                &mut object,
                &mut block_index,
                std::mem::take(&mut chunk),
            );
        }
    }
    write_block(cipher, sstable_key, &mut object, &mut block_index, chunk); // trailing partial block, if any

    let bloom_bytes = bloom.to_bytes();
    let block_index_bytes = rmp_serde::to_vec_named(&block_index).expect("serializing a block index never fails");
    let mut footer_plain = Vec::with_capacity(4 + bloom_bytes.len() + block_index_bytes.len());
    footer_plain.extend_from_slice(&(bloom_bytes.len() as u32).to_le_bytes());
    footer_plain.extend_from_slice(&bloom_bytes);
    footer_plain.extend_from_slice(&block_index_bytes);
    let sealed_footer = cipher.seal(
        &footer_aad(sstable_key),
        &footer_plain,
        CompressionStrategy::Auto { threshold_bytes: 4096 },
    );

    object.extend_from_slice(&sealed_footer);
    object.extend_from_slice(&(sealed_footer.len() as u64).to_le_bytes());

    let meta = SSTableMeta {
        min_key: rows.keys().next().expect("checked non-empty above").clone(),
        max_key: rows.keys().next_back().expect("checked non-empty above").clone(),
        row_count: rows.len(),
        byte_len: object.len() as u64,
        footer_len: sealed_footer.len() as u64,
        block_index,
    };
    (object, meta)
}

fn write_block(
    cipher: &Cipher,
    sstable_key: &str,
    object: &mut Vec<u8>,
    block_index: &mut Vec<BlockIndexEntry>,
    chunk: Vec<(LsmKey, MemValue)>,
) {
    if chunk.is_empty() {
        return;
    }
    let block_idx = block_index.len();
    let min_key = chunk.first().expect("checked non-empty above").0.clone();
    let max_key = chunk.last().expect("checked non-empty above").0.clone();
    let plain = rmp_serde::to_vec_named(&chunk).expect("serializing a block never fails");
    let sealed = cipher.seal(
        &block_aad(sstable_key, block_idx),
        &plain,
        CompressionStrategy::Auto { threshold_bytes: 4096 },
    );
    let offset = object.len() as u64 + 4; // past this block's own length prefix
    object.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
    object.extend_from_slice(&sealed);
    block_index.push(BlockIndexEntry {
        min_key,
        max_key,
        offset,
        len: sealed.len() as u32,
    });
}

/// The footer's own parsed (and decrypted) form: the bloom filter and block
/// index, plus where the footer itself starts (== the byte length of
/// everything that came before it, i.e. all the sealed blocks).
#[allow(dead_code)]
pub(crate) struct Footer {
    pub(crate) bloom: Bloom,
    pub(crate) block_index: Vec<BlockIndexEntry>,
    pub(crate) blocks_end: u64,
}

/// Decrypts `[bloom_len][bloom][block_index]` from a footer's already-opened
/// plaintext -- the parsing logic shared by [`open_footer`] (fed a complete
/// object) and phase 2's ranged footer fetch (fed just the footer's own
/// bytes), so the two paths can never disagree about what a footer means.
fn parse_footer_plaintext(plain: &[u8]) -> Result<(Bloom, Vec<BlockIndexEntry>)> {
    ensure!(plain.len() >= 4, "SSTable footer too short to contain a bloom length");
    let bloom_len = u32::from_le_bytes(plain[0..4].try_into().unwrap()) as usize;
    ensure!(
        plain.len() >= 4 + bloom_len,
        "SSTable footer shorter than its declared bloom filter"
    );
    let bloom = Bloom::from_bytes(&plain[4..4 + bloom_len]).context("parsing SSTable bloom filter")?;
    let block_index: Vec<BlockIndexEntry> =
        rmp_serde::from_slice(&plain[4 + bloom_len..]).context("parsing SSTable block index")?;
    Ok((bloom, block_index))
}

/// Opens and parses the footer out of a *complete* SSTable object already in
/// memory (used by [`read_all`]). Phase 2's manifest-driven open instead
/// fetches only the footer's sealed byte range via `get_range` and calls
/// [`open_footer_bytes`] directly on that — this function's job is purely
/// locating the footer within a full object and figuring out `blocks_end`,
/// which only makes sense when the whole object is in hand.
#[allow(dead_code)]
pub(crate) fn open_footer(cipher: &Cipher, sstable_key: &str, object: &[u8]) -> Result<Footer> {
    ensure!(object.len() >= 8, "SSTable object too short to contain a footer length");
    let (body, footer_len_bytes) = object.split_at(object.len() - 8);
    let footer_len = u64::from_le_bytes(footer_len_bytes.try_into().unwrap()) as usize;
    ensure!(
        body.len() >= footer_len,
        "SSTable footer_len {footer_len} exceeds the {} bytes before it",
        body.len()
    );
    let blocks_end = (body.len() - footer_len) as u64;
    let sealed_footer = &body[body.len() - footer_len..];
    let plain = cipher
        .open(&footer_aad(sstable_key), sealed_footer)
        .context("opening SSTable footer")?;
    let (bloom, block_index) = parse_footer_plaintext(&plain)?;
    Ok(Footer {
        bloom,
        block_index,
        blocks_end,
    })
}

/// Opens and parses a footer from *just its own sealed bytes* — exactly
/// what a `get_range(key, byte_len - 8 - footer_len, footer_len)` fetches,
/// per a manifest entry's `byte_len`/`footer_len` (phase 2). No `blocks_end`
/// here: that field only means something relative to a complete object,
/// which this path never has.
pub(crate) fn open_footer_bytes(
    cipher: &Cipher,
    sstable_key: &str,
    sealed_footer: &[u8],
) -> Result<(Bloom, Vec<BlockIndexEntry>)> {
    let plain = cipher
        .open(&footer_aad(sstable_key), sealed_footer)
        .context("opening SSTable footer")?;
    parse_footer_plaintext(&plain)
}

/// Opens and decodes one block's rows from its raw *sealed* bytes and
/// index — exactly what a [`BlockIndexEntry`]'s `(offset, len)` locates,
/// whether those bytes came from a full in-memory object ([`read_all`]) or
/// a single targeted `get_range` (phase 2's point lookup).
pub(crate) fn decode_block(
    cipher: &Cipher,
    sstable_key: &str,
    block_idx: usize,
    sealed: &[u8],
) -> Result<Vec<(LsmKey, MemValue)>> {
    let plain = cipher
        .open(&block_aad(sstable_key, block_idx), sealed)
        .with_context(|| format!("opening block {block_idx} of {sstable_key}"))?;
    rmp_serde::from_slice(&plain).context("decoding SSTable block")
}

/// Every row in a complete SSTable object, in ascending key order — a full
/// linear scan, no bloom/block-index pruning. Not called from this crate's
/// own non-test code yet: `Table::get` (phase 2) always prunes via the
/// bloom filter and block index instead of reading a whole object, so this
/// path is what the phase-3 compactor will use to merge whole tables, and
/// what this module's own tests use today to verify a flush round-trips.
#[allow(dead_code)]
pub(crate) fn read_all(cipher: &Cipher, sstable_key: &str, object: &[u8]) -> Result<Vec<(LsmKey, MemValue)>> {
    let footer = open_footer(cipher, sstable_key, object)?;
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut block_idx = 0usize;
    while (pos as u64) < footer.blocks_end {
        ensure!(pos + 4 <= object.len(), "SSTable truncated mid block-length-prefix");
        let sealed_len = u32::from_le_bytes(object[pos..pos + 4].try_into().unwrap()) as usize;
        let sealed_start = pos + 4;
        ensure!(
            sealed_start + sealed_len <= object.len(),
            "SSTable truncated mid block payload"
        );
        out.extend(decode_block(
            cipher,
            sstable_key,
            block_idx,
            &object[sealed_start..sealed_start + sealed_len],
        )?);
        pos = sealed_start + sealed_len;
        block_idx += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
