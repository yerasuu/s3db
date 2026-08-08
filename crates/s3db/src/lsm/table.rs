//! [`Table`]: the handle a caller actually holds — wires [`Wal`], [`Memtable`],
//! and [`sstable::build`] together into "write acks fast, flush produces one
//! immutable object." See this module's parent doc for what's deliberately
//! still missing (everything downstream of a flush).

use super::memtable::MemValue;
use super::{LsmKey, Memtable, Wal, sstable};
use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy};
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

    /// Reads back a key's state in the *current, unflushed* memtable only
    /// -- named deliberately not `get`, because that's all this phase can
    /// honestly answer. Once a row is flushed it's durable in the bucket
    /// but this method can no longer see it; nothing yet tracks what's been
    /// flushed (that's the manifest, phase 2), so there is no complete
    /// `get` here yet. Mainly useful for read-your-own-write within one
    /// flush window, and for this module's own tests.
    pub async fn get_unflushed(&self, key: &[u8]) -> Option<MemValue> {
        self.state.lock().await.memtable.get(key).cloned()
    }

    pub async fn should_flush(&self) -> bool {
        self.state.lock().await.memtable.approx_bytes() >= self.flush_threshold_bytes
    }

    /// Serializes the entire current memtable into one SSTable object and
    /// writes it in a single `put_cas` — "one flush = one PUT," the move
    /// that decouples request volume from row count (see the module doc).
    /// `Ok(None)` if there was nothing to flush.
    ///
    /// If the object write succeeds but resetting the WAL afterward fails
    /// (a local disk error), the WAL still holds records for rows that are
    /// now also durable in the object just written. That's wasteful on the
    /// next restart (those rows replay into a fresh memtable and get
    /// flushed again, into a second SSTable covering an overlapping key
    /// range) but not incorrect -- overlapping SSTables are a normal LSM
    /// state, and phase 2's read path always prefers the most recently
    /// flushed one for a given key.
    pub async fn flush(&self) -> Result<Option<FlushedSSTable>> {
        let mut state = self.state.lock().await;
        if state.memtable.is_empty() {
            return Ok(None);
        }
        let drained = state.memtable.drain_sorted();
        let (object, meta) = sstable::build(&drained, self.rows_per_block);

        let key = flush_object_key(&self.root)?;
        let sealed = self
            .cipher
            .seal(&key, &object, CompressionStrategy::Auto { threshold_bytes: 4096 });
        match self.backend.put_cas(&key, sealed, None).await? {
            Cas::Ok => {}
            // The key includes a millisecond timestamp plus 128 bits of
            // randomness -- a genuine collision here would mean a bug
            // elsewhere, not a race worth retrying (same reasoning
            // `crate::txn::run_with_publisher` already applies to its own
            // random transaction id).
            Cas::Conflict => bail!("SSTable key collision at {key} (should never happen)"),
        }

        state.wal.reset().await?;
        Ok(Some(FlushedSSTable {
            key,
            min_key: meta.min_key,
            max_key: meta.max_key,
            row_count: meta.row_count,
            byte_len: meta.byte_len,
        }))
    }
}

/// `{root}/sst/{millis}-{random hex}.sst` -- monotonic-ish for readability
/// when listing a bucket by hand, unique via the random suffix without
/// needing a persistent counter that would itself need to survive restarts.
fn flush_object_key(root: &str) -> Result<String> {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_millis();
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix).context("generating SSTable key suffix")?;
    let suffix = suffix.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(format!("{root}/sst/{millis}-{suffix}.sst"))
}

#[cfg(test)]
mod tests;
