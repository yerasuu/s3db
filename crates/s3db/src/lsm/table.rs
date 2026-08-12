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
use super::value::{Schema, Value};
use super::{LsmKey, Memtable, Wal, query, sstable};
use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
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
    /// `None` (the default): rows are opaque bytes in, opaque bytes out --
    /// [`Table::put`]/[`Table::get`]. `Some`: every block this table
    /// flushes is columnar-encoded against this exact schema (phase 4, see
    /// `crate::lsm::typed_block`'s module doc), and rows go through
    /// [`Table::put_typed`]/[`Table::get_typed`] instead. Fixed for this
    /// table's lifetime once [`Table::open`] is called -- there's no
    /// migration path for changing a table's schema after rows already
    /// exist under it, any more than there's one for retroactively
    /// re-encoding old blocks.
    pub schema: Option<Schema>,
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
            schema: None,
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

    pub fn with_schema(mut self, schema: Schema) -> Self {
        self.schema = Some(schema);
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
    schema: Option<Schema>,
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
            schema: config.schema,
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

    /// [`Self::put`] for a table with a declared [`TableConfig::schema`] --
    /// `row` must match it exactly ([`Schema::validate`]), checked here so
    /// a mismatch fails immediately with a clear error instead of only
    /// surfacing later at [`Self::flush`] time when the whole block it
    /// landed in fails to columnarize.
    pub async fn put_typed(&self, key: LsmKey, row: Vec<Value>) -> Result<()> {
        let schema = self
            .schema
            .as_ref()
            .context("put_typed needs a schema (see TableConfig::with_schema)")?;
        schema.validate(&row)?;
        let bytes = rmp_serde::to_vec_named(&row).context("serializing a typed row never fails")?;
        self.put(key, bytes).await
    }

    /// [`Self::get`] for a table with a declared [`TableConfig::schema`].
    pub async fn get_typed(&self, key: &[u8]) -> Result<Option<Vec<Value>>> {
        anyhow::ensure!(
            self.schema.is_some(),
            "get_typed needs a schema (see TableConfig::with_schema)"
        );
        let Some(bytes) = self.get(key).await? else {
            return Ok(None);
        };
        let row = rmp_serde::from_slice(&bytes).context("decoding a typed row")?;
        Ok(Some(row))
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
            if let Some(value) =
                lookup_in_sstable(self.backend.as_ref(), &self.cipher, self.schema.as_ref(), entry, key).await?
            {
                return Ok(mem_value_to_get_result(value));
            }
        }
        Ok(None)
    }

    /// Every live row with `start <= key < end` (either bound `None` for
    /// unbounded), merged from the memtable and every overlapping SSTable —
    /// `docs/s3db-fulldb-roadmap.md` phase 5's range scan: SSTables outside
    /// `[start, end)` entirely are skipped via their manifest-recorded
    /// `min_key`/`max_key` without a single request, and *within* an
    /// overlapping SSTable only the blocks that could contain a matching
    /// key are fetched (via `get_range`, per block's own `min_key`/`max_key`
    /// in its `block_index` entry) -- never the whole object, same
    /// discipline [`Self::get`]'s point lookup already applies.
    ///
    /// Merge order is oldest SSTable to newest, then the memtable last (so
    /// it always wins) -- the same rule [`crate::lsm::compactor`] uses,
    /// just scoped to a key range and read-only.
    pub async fn scan(&self, start: Option<&[u8]>, end: Option<&[u8]>) -> Result<Vec<(LsmKey, Vec<u8>)>> {
        let merged = self.scan_merged(start, end, &[]).await?;
        Ok(merged
            .into_iter()
            .filter_map(|(key, value)| mem_value_to_get_result(value).map(|bytes| (key, bytes)))
            .collect())
    }

    /// [`Self::scan`] for a table with a declared [`TableConfig::schema`],
    /// decoding each row the same way [`Self::get_typed`] does.
    pub async fn scan_typed(&self, start: Option<&[u8]>, end: Option<&[u8]>) -> Result<Vec<(LsmKey, Vec<Value>)>> {
        anyhow::ensure!(
            self.schema.is_some(),
            "scan_typed needs a schema (see TableConfig::with_schema)"
        );
        self.scan(start, end)
            .await?
            .into_iter()
            .map(|(key, bytes)| {
                let row = rmp_serde::from_slice(&bytes).context("decoding a typed row")?;
                Ok((key, row))
            })
            .collect()
    }

    /// [`Self::scan_typed`] plus `predicates` (phase 8's query builder,
    /// [`crate::lsm::query::Predicate`]) -- every returned row satisfies
    /// every predicate, exactly as if they'd been applied as a plain
    /// in-memory filter afterward. The difference is I/O, not correctness:
    /// a block whose [`super::ColumnStats`] prove no row in it could
    /// possibly match ([`query::Predicate::cannot_match`]) is skipped before ever
    /// being fetched, on top of the key-range skip [`Self::scan`] already
    /// does. A predicate that can't be decided from stats alone still gets
    /// the real per-row check below -- pruning only ever removes work, it
    /// never changes the answer.
    pub async fn scan_typed_where(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        predicates: &[query::Predicate],
    ) -> Result<Vec<(LsmKey, Vec<Value>)>> {
        anyhow::ensure!(
            self.schema.is_some(),
            "scan_typed_where needs a schema (see TableConfig::with_schema)"
        );
        let merged = self.scan_merged(start, end, predicates).await?;
        let mut out = Vec::new();
        for (key, value) in merged {
            let Some(bytes) = mem_value_to_get_result(value) else {
                continue;
            };
            let row: Vec<Value> = rmp_serde::from_slice(&bytes).context("decoding a typed row")?;
            if predicates.iter().all(|p| p.matches(&row)) {
                out.push((key, row));
            }
        }
        Ok(out)
    }

    /// The shared merge behind [`Self::scan`]/[`Self::scan_typed_where`]:
    /// every SSTable whose `[min_key, max_key]` overlaps `[start, end)`,
    /// oldest to newest, then the memtable last (always freshest) -- same
    /// order [`crate::lsm::compactor`] merges in. `predicates` (empty for
    /// [`Self::scan`]) only ever affects which *blocks* get fetched inside
    /// an overlapping SSTable, never which keys land in the result --
    /// that final filter is each caller's own job.
    async fn scan_merged(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        predicates: &[query::Predicate],
    ) -> Result<BTreeMap<LsmKey, MemValue>> {
        let mut merged: BTreeMap<LsmKey, MemValue> = BTreeMap::new();

        let (manifest, _) = manifest::load(self.backend.as_ref(), &self.cipher, &self.root).await?;
        for entry in &manifest.sstables {
            if let Some(end) = end
                && entry.min_key.as_slice() >= end
            {
                continue; // this whole SSTable starts at or after the range
            }
            if let Some(start) = start
                && entry.max_key.as_slice() < start
            {
                continue; // this whole SSTable ends before the range
            }
            let rows = scan_sstable(
                self.backend.as_ref(),
                &self.cipher,
                self.schema.as_ref(),
                entry,
                start,
                end,
                predicates,
            )
            .await?;
            merged.extend(rows);
        }

        // The memtable is always freshest -- applied last so it overrides
        // whatever any SSTable had for the same key, tombstones included.
        for (key, value) in self.state.lock().await.memtable.range(start, end) {
            merged.insert(key, value);
        }

        Ok(merged)
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
    ///
    /// Every failure path between the drain and the manifest append
    /// restores the drained rows back into the memtable before returning:
    /// without that, they'd only still exist in the (unreset) WAL, which
    /// nothing re-replays into this already-open `Table` -- so within this
    /// same process, `get`/`scan` would silently stop seeing them for as
    /// long as the process keeps running, not just until the next
    /// successful flush. Restoring them means a retried `flush()` (or a
    /// plain read in the meantime) sees exactly the rows this attempt
    /// failed to durably write.
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
        let (object, meta) = match sstable::build(&self.cipher, &key, self.schema.as_ref(), &drained, self.rows_per_block)
        {
            Ok(v) => v,
            Err(err) => {
                state.memtable.restore(drained);
                return Err(err);
            }
        };

        match self.backend.put_cas(&key, object, None).await {
            Ok(Cas::Ok) => {}
            // The key includes a millisecond timestamp plus 128 bits of
            // randomness -- a genuine collision here would mean a bug
            // elsewhere, not a race worth retrying (same reasoning
            // `crate::txn::run_with_publisher` already applies to its own
            // random transaction id).
            Ok(Cas::Conflict) => {
                state.memtable.restore(drained);
                bail!("SSTable key collision at {key} (should never happen)");
            }
            Err(err) => {
                state.memtable.restore(drained);
                return Err(err);
            }
        }

        if let Err(err) = manifest::append(
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
        .await
        {
            // The SSTable object itself is already durable in the bucket at
            // this point, just not yet referenced by the manifest -- restoring
            // the rows here means a retried flush writes a second object and
            // this one leaks, exactly the "future GC sweep can reclaim it"
            // trade-off this method's own doc comment already accepts.
            state.memtable.restore(drained);
            return Err(err);
        }

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
        compactor::compact(
            self.backend.as_ref(),
            &self.cipher,
            &self.root,
            self.schema.as_ref(),
            self.rows_per_block,
        )
        .await
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
    schema: Option<&Schema>,
    entry: &ManifestEntry,
    key: &[u8],
) -> Result<Option<MemValue>> {
    let footer_offset = entry
        .byte_len
        .checked_sub(8)
        .and_then(|n| n.checked_sub(entry.footer_len))
        .with_context(|| format!("{}: manifest entry's byte_len/footer_len is corrupt", entry.key))?;
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
    let rows = sstable::decode_block(cipher, &entry.key, schema, block_idx, &sealed_block)?;
    Ok(rows.into_iter().find(|(k, _)| k.as_slice() == key).map(|(_, v)| v))
}

/// [`Self::scan`]'s per-SSTable half: fetches the footer (one `get_range`,
/// same as [`lookup_in_sstable`]), then fetches and decodes only the blocks
/// whose `[min_key, max_key]` could contain something in `[start, end)` --
/// blocks are non-overlapping and sorted (see `sstable`'s module doc), so
/// this is a contiguous run, found and walked without ever touching a block
/// outside it.
async fn scan_sstable(
    backend: &dyn Backend,
    cipher: &Cipher,
    schema: Option<&Schema>,
    entry: &ManifestEntry,
    start: Option<&[u8]>,
    end: Option<&[u8]>,
    predicates: &[query::Predicate],
) -> Result<Vec<(LsmKey, MemValue)>> {
    let footer_offset = entry
        .byte_len
        .checked_sub(8)
        .and_then(|n| n.checked_sub(entry.footer_len))
        .with_context(|| format!("{}: manifest entry's byte_len/footer_len is corrupt", entry.key))?;
    let sealed_footer = backend
        .get_range(&entry.key, footer_offset, entry.footer_len)
        .await
        .with_context(|| format!("fetching footer of {}", entry.key))?;
    let (_, block_index) = sstable::open_footer_bytes(cipher, &entry.key, &sealed_footer)?;

    // First block that could hold anything >= start: the first whose
    // max_key doesn't sort strictly before start.
    let first_idx = match start {
        Some(start) => block_index.partition_point(|b| b.max_key.as_slice() < start),
        None => 0,
    };

    let mut rows = Vec::new();
    'block: for (block_idx, block) in block_index.iter().enumerate().skip(first_idx) {
        if let Some(end) = end
            && block.min_key.as_slice() >= end
        {
            break; // this and every later block start at or after `end` -- nothing further overlaps
        }
        // Phase 8: a predicate this block's own column_stats definitively
        // rules out means the block never gets fetched at all -- an
        // out-of-range predicate column index (`.get` returns `None`) or a
        // block with no stats for that column just means "can't decide,"
        // never "prune."
        for predicate in predicates {
            if let Some(stats) = block.column_stats.get(predicate.column())
                && predicate.cannot_match(stats)
            {
                continue 'block;
            }
        }
        let sealed_block = backend
            .get_range(&entry.key, block.offset, block.len as u64)
            .await
            .with_context(|| format!("fetching block {block_idx} of {}", entry.key))?;
        let decoded = sstable::decode_block(cipher, &entry.key, schema, block_idx, &sealed_block)?;
        rows.extend(decoded.into_iter().filter(|(key, _)| {
            start.is_none_or(|start| key.as_slice() >= start) && end.is_none_or(|end| key.as_slice() < end)
        }));
    }
    Ok(rows)
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/table.rs"]
mod tests;
