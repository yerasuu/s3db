//! [`Table`]: the handle a caller actually holds — wires [`Wal`], [`Memtable`],
//! [`sstable`], and [`super::manifest`] together into "write acks fast,
//! flush produces one immutable object and records it," plus the read path
//! that makes a flushed row findable again: memtable first (always
//! freshest), then the manifest's SSTables newest-to-oldest, each one's
//! bloom filter and block index fetched and searched via targeted
//! [`crate::backend::Backend::get_range`] calls rather than the whole
//! object.

use super::compactor::{self, CompactionReport};
use super::manifest::{self, ManifestEntry};
use super::memtable::MemValue;
use super::{LsmKey, Memtable, Wal, sstable};
use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// 4 MiB — big enough that flushing doesn't dominate write cost, small
/// enough that a crash's un-flushed tail (bounded by this, since the WAL
/// only ever holds what's since the last flush) replays quickly on restart.
/// Not load-bearing beyond "a reasonable default": [`TableConfig::with_flush_threshold_bytes`]
/// overrides it per table.
const DEFAULT_FLUSH_THRESHOLD_BYTES: usize = 4 * 1024 * 1024;
/// Rows per SSTable block. Small enough that a targeted `get_range` (phase
/// 2) fetches a modest amount of wasted surrounding data, large enough that
/// the block index and per-block framing overhead stay a small fraction of
/// the object.
const DEFAULT_ROWS_PER_BLOCK: usize = 500;

pub struct TableConfig {
    pub backend: Arc<dyn Backend>,
    pub cipher: Cipher,
    /// This table's own key prefix in the bucket — every SSTable this table
    /// flushes lives under `{root}/sst/...`, so two tables never collide
    /// even sharing one bucket.
    pub root: String,
    /// Local file this table's WAL lives at. Caller-chosen, no derived
    /// default (see `crate::config`'s "explicit config, no inference"
    /// convention already used throughout this crate) — and deliberately
    /// per-table, since two tables sharing one WAL file would interleave
    /// their records with no way to tell them apart on replay.
    pub wal_path: PathBuf,
    pub flush_threshold_bytes: usize,
    pub rows_per_block: usize,
}

impl TableConfig {
    pub fn new(backend: Arc<dyn Backend>, cipher: Cipher, root: impl Into<String>, wal_path: PathBuf) -> Self {
        TableConfig {
            backend,
            cipher,
            root: root.into(),
            wal_path,
            flush_threshold_bytes: DEFAULT_FLUSH_THRESHOLD_BYTES,
            rows_per_block: DEFAULT_ROWS_PER_BLOCK,
        }
    }

    pub fn with_flush_threshold_bytes(mut self, bytes: usize) -> Self {
        self.flush_threshold_bytes = bytes;
        self
    }

    pub fn with_rows_per_block(mut self, rows: usize) -> Self {
        self.rows_per_block = rows;
        self
    }
}

/// What [`Table::flush`] hands back — everything a manifest entry (phase 2)
/// needs to record about the SSTable it just wrote, without re-parsing the
/// object.
#[derive(Debug, Clone, PartialEq)]
pub struct FlushedSSTable {
    pub key: String,
    pub min_key: LsmKey,
    pub max_key: LsmKey,
    pub row_count: usize,
    pub byte_len: u64,
    pub footer_len: u64,
}

struct State {
    wal: Wal,
    memtable: Memtable,
}

pub struct Table {
    backend: Arc<dyn Backend>,
    cipher: Cipher,
    root: String,
    flush_threshold_bytes: usize,
    rows_per_block: usize,
    state: Mutex<State>,
}

impl Table {
    /// Opens (or creates) this table's WAL and replays it into a fresh
    /// memtable — crash recovery, so a process that died between writes and
    /// its last flush comes back up with exactly the state it acked before
    /// dying.
    pub async fn open(config: TableConfig) -> Result<Self> {
        let recovered = Wal::replay(&config.wal_path).await?;
        let wal = Wal::open(config.wal_path).await?;
        let mut memtable = Memtable::default();
        for (key, value) in recovered {
            match value {
                MemValue::Put(bytes) => memtable.put(key, bytes),
                MemValue::Tombstone => memtable.delete(key),
            }
        }
        Ok(Table {
            backend: config.backend,
            cipher: config.cipher,
            root: config.root,
            flush_threshold_bytes: config.flush_threshold_bytes,
            rows_per_block: config.rows_per_block,
            state: Mutex::new(State { wal, memtable }),
        })
    }

    /// Acks once the WAL append is durable on local disk — no request to
    /// `backend` on this path at all, which is the entire reason a WAL
    /// exists here (see the module doc).
    pub async fn put(&self, key: LsmKey, value: Vec<u8>) -> Result<()> {
        let mut state = self.state.lock().await;
        state.wal.append_put(&key, &value).await?;
        state.memtable.put(key, value);
        Ok(())
    }

    pub async fn delete(&self, key: LsmKey) -> Result<()> {
        let mut state = self.state.lock().await;
        state.wal.append_delete(&key).await?;
        state.memtable.delete(key);
        Ok(())
    }

    /// Reads back a key's state in the *current, unflushed* memtable only —
    /// never touches the manifest or the bucket. Named deliberately not
    /// `get`: [`Self::get`] is the complete read (memtable, then every
    /// flushed SSTable); this one exists for read-your-own-write within one
    /// flush window without paying for a manifest fetch, and for this
    /// module's own tests.
    pub async fn get_unflushed(&self, key: &[u8]) -> Option<MemValue> {
        self.state.lock().await.memtable.get(key).cloned()
    }

    /// The complete read: the current memtable first (always the freshest
    /// state, since anything in it hasn't been flushed yet), then the
    /// manifest's SSTables from most to least recently flushed, stopping at
    /// the first one that has an answer -- a `Put` (returns the value) or a
    /// `Tombstone` (the key was deleted since whichever older SSTable, if
    /// any, still has a stale value for it; `None` is the correct answer,
    /// not "keep looking"). `None` if nothing anywhere ever had this key.
    ///
    /// Re-fetches the manifest on every call rather than caching it --
    /// other processes can be flushing the same table's data (this is a
    /// read, not the single-writer path), and a manifest object is small
    /// enough that this is nowhere near the cost `get_range`-driven block
    /// fetches are optimizing away.
    pub async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        if let Some(value) = self.state.lock().await.memtable.get(key).cloned() {
            return Ok(mem_value_to_get_result(value));
        }
        let (manifest, _) = manifest::load(self.backend.as_ref(), &self.cipher, &self.root).await?;
        for entry in manifest.sstables.iter().rev() {
            if key < entry.min_key.as_slice() || key > entry.max_key.as_slice() {
                continue; // key can't possibly be in this SSTable's range
            }
            if let Some(value) = lookup_in_sstable(self.backend.as_ref(), &self.cipher, entry, key).await? {
                return Ok(mem_value_to_get_result(value));
            }
        }
        Ok(None)
    }

    pub async fn should_flush(&self) -> bool {
        self.state.lock().await.memtable.approx_bytes() >= self.flush_threshold_bytes
    }

    /// Serializes the entire current memtable into one SSTable object,
    /// writes it in a single `put_cas`, and records it in the manifest —
    /// "one flush = one PUT," the move that decouples request volume from
    /// row count (see the module doc). `Ok(None)` if there was nothing to
    /// flush.
    ///
    /// Ordered `put_cas` -> manifest append -> WAL reset specifically so
    /// each failure mode is at worst wasteful, never silently lossy across
    /// a restart:
    /// - If the object write succeeds but the manifest append fails, the
    ///   object sits in the bucket unreferenced by anything (a leak a
    ///   future GC sweep could reclaim) -- but the WAL hasn't been reset, so
    ///   a crash or retry still replays these exact rows and flushes them
    ///   again properly. Within *this* process, before that next flush,
    ///   [`Self::get`] can't see these rows either (they're gone from the
    ///   drained memtable, and the manifest never learned about the
    ///   SSTable that has them) -- a narrow, transient availability gap on
    ///   an error path, not a normal case.
    /// - If the manifest append succeeds but resetting the WAL afterward
    ///   fails, the WAL still holds records for rows now also durable and
    ///   already visible via the new manifest entry. Replaying it again
    ///   later just flushes the same rows into a second, redundant SSTable
    ///   -- wasteful, not incorrect: [`Self::get`] already prefers the
    ///   newest manifest entry for any key, and overlapping SSTables are a
    ///   normal LSM state regardless of how they arose.
    pub async fn flush(&self) -> Result<Option<FlushedSSTable>> {
        let mut state = self.state.lock().await;
        if state.memtable.is_empty() {
            return Ok(None);
        }
        let drained = state.memtable.drain_sorted();
        // Decided before building: every block and the footer bind this key
        // into their own AAD (see `sstable`'s module doc), so `build` needs
        // to know it up front, not after sealing.
        let (key, flushed_at_ms) = sstable::new_object_key(&self.root)?;
        let (object, meta) = sstable::build(&self.cipher, &key, &drained, self.rows_per_block);

        match self.backend.put_cas(&key, object, None).await? {
            Cas::Ok => {}
            // The key includes a millisecond timestamp plus 128 bits of
            // randomness -- a genuine collision here would mean a bug
            // elsewhere, not a race worth retrying (same reasoning
            // `crate::txn::run_with_publisher` already applies to its own
            // random transaction id).
            Cas::Conflict => bail!("SSTable key collision at {key} (should never happen)"),
        }

        manifest::append(
            self.backend.as_ref(),
            &self.cipher,
            &self.root,
            ManifestEntry {
                key: key.clone(),
                min_key: meta.min_key.clone(),
                max_key: meta.max_key.clone(),
                byte_len: meta.byte_len,
                footer_len: meta.footer_len,
                level: 0, // full-tiered compaction only -- see `compactor`'s module doc
                flushed_at_ms,
            },
        )
        .await?;

        state.wal.reset().await?;
        Ok(Some(FlushedSSTable {
            key,
            min_key: meta.min_key,
            max_key: meta.max_key,
            row_count: meta.row_count,
            byte_len: meta.byte_len,
            footer_len: meta.footer_len,
        }))
    }

    /// `true` once this table's manifest has accumulated enough SSTables
    /// that [`Self::compact`] is worth its write amplification — see
    /// [`compactor::should_compact`] for the threshold. A caller (a
    /// periodic maintenance job) checks this on whatever schedule it likes;
    /// nothing here compacts on its own.
    pub async fn should_compact(&self) -> Result<bool> {
        let (manifest, _) = manifest::load(self.backend.as_ref(), &self.cipher, &self.root).await?;
        Ok(compactor::should_compact(manifest.sstables.len()))
    }

    /// Merges every SSTable this table currently has into one, dropping
    /// tombstones — see [`compactor::compact`] for the full contract
    /// (including what happens to a concurrent flush/compaction, and why a
    /// merge with fewer than two SSTables is a no-op). Doesn't touch this
    /// `Table`'s own WAL or memtable at all: compaction only ever operates
    /// on what's already durable in the manifest, so it's equally valid to
    /// run from a separate maintenance process that never writes through
    /// this `Table` handle at all.
    pub async fn compact(&self) -> Result<CompactionReport> {
        compactor::compact(self.backend.as_ref(), &self.cipher, &self.root, self.rows_per_block).await
    }
}

fn mem_value_to_get_result(value: MemValue) -> Option<Vec<u8>> {
    match value {
        MemValue::Put(bytes) => Some(bytes),
        MemValue::Tombstone => None,
    }
}

/// Searches one SSTable for `key`: fetches and opens just its footer (one
/// `get_range`), consults the bloom filter to possibly skip the whole table
/// with zero further requests, binary-searches the block index for the one
/// block that could hold `key`, and fetches and opens just that block (a
/// second `get_range`) -- never the SSTable's full object.
async fn lookup_in_sstable(
    backend: &dyn Backend,
    cipher: &Cipher,
    entry: &ManifestEntry,
    key: &[u8],
) -> Result<Option<MemValue>> {
    let footer_offset = entry.byte_len - 8 - entry.footer_len;
    let sealed_footer = backend
        .get_range(&entry.key, footer_offset, entry.footer_len)
        .await
        .with_context(|| format!("fetching footer of {}", entry.key))?;
    let (bloom, block_index) = sstable::open_footer_bytes(cipher, &entry.key, &sealed_footer)?;
    if !bloom.contains(key) {
        return Ok(None); // definitely not in this table -- zero further requests
    }

    // Blocks are non-overlapping and sorted by key (see `sstable`'s module
    // doc), so the candidate is the last block whose min_key <= key --
    // `partition_point` finds the first index where that's no longer true,
    // one past the candidate.
    let candidate_idx = block_index.partition_point(|b| b.min_key.as_slice() <= key);
    if candidate_idx == 0 {
        return Ok(None); // key is smaller than every block's min_key
    }
    let block_idx = candidate_idx - 1;
    let candidate = &block_index[block_idx];
    if key > candidate.max_key.as_slice() {
        return Ok(None); // falls in a gap -- can't happen with contiguous data, but a real answer either way
    }

    let sealed_block = backend
        .get_range(&entry.key, candidate.offset, candidate.len as u64)
        .await
        .with_context(|| format!("fetching block {block_idx} of {}", entry.key))?;
    let rows = sstable::decode_block(cipher, &entry.key, block_idx, &sealed_block)?;
    Ok(rows.into_iter().find(|(k, _)| k.as_slice() == key).map(|(_, v)| v))
}

#[cfg(test)]
mod tests;
