//! [`Table`]: the handle a caller actually holds — wires [`Wal`], [`Memtable`],
//! [`sstable`], and [`super::manifest`] together into "write acks fast,
//! flush produces one immutable object and records it," plus the read path
//! that makes a flushed row findable again: memtable first (always
//! freshest), then the manifest's SSTables newest-to-oldest, each one's
//! bloom filter and block index fetched and searched via targeted
//! [`crate::backend::Backend::get_range`] calls rather than the whole
//! object.

use super::compactor::{self, CompactionReport};
use super::lease::WriterLease;
use super::manifest::{self, ManifestEntry};
use super::memtable::MemValue;
use super::value::{Schema, Value};
use super::{LsmKey, Memtable, Wal, query, sstable};
use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
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
    /// The writer lease this table holds, if the caller took one.
    ///
    /// `None` (the default) keeps the historical behaviour: this process
    /// writes, and nothing checks whether another one is doing the same. That
    /// is safe for a single-process deployment and silently corrupting for any
    /// other — see [`super::lease`] for what two writers actually do to a
    /// table's history, and why the answer is a lease rather than a
    /// coordination protocol.
    pub lease: Option<WriterLease>,
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
            lease: None,
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

    /// Gates this table's writes on a [`WriterLease`] — see
    /// [`super::lease`]. The caller still has to renew it
    /// ([`Table::renew_lease`]); a lease that stops being renewed makes this
    /// table refuse writes rather than keep them coming from a process another
    /// one has taken over from.
    pub fn with_writer_lease(mut self, lease: WriterLease) -> Self {
        self.lease = Some(lease);
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
    /// `None` in a read-only table: there is nothing to log, and creating a
    /// WAL file in a reader would be the first step towards it accidentally
    /// becoming a second writer.
    wal: Option<Wal>,
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
    /// Set by [`Table::open_read_only`]. Every write path checks it.
    read_only: bool,
    /// Behind a `Mutex` rather than plain, so [`Table::release_lease`] and
    /// [`Table::renew_lease`] can move the lease through a `&self` — which is
    /// how every other method here is called.
    lease: Mutex<LeaseState>,
}

/// This handle's relationship to a [`WriterLease`].
///
/// `Unleased` and `Released` are deliberately different states, not one
/// `Option::None`: the first means nobody ever asked for a lease, so writes go
/// unguarded exactly as they always did, and the second means this handle gave
/// up the right to write. Collapsing them would make `release_lease` *restore*
/// permission instead of revoking it.
#[derive(Debug)]
enum LeaseState {
    Unleased,
    Held(WriterLease),
    Released,
}

impl Table {
    /// Opens (or creates) this table's WAL and replays it into a fresh
    /// memtable — crash recovery, so a process that died between writes and
    /// its last flush comes back up with exactly the state it acked before
    /// dying. Also heals a leftover rotated WAL from a flush that was
    /// interrupted mid-checkpoint (see [`super::wal`]'s module doc) before
    /// replaying, so that gets recovered too, not just plain writes.
    pub async fn open(config: TableConfig) -> Result<Self> {
        super::wal::heal_rotating_wal(&config.wal_path).await?;
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
            state: Mutex::new(State {
                wal: Some(wal),
                memtable,
            }),
            read_only: false,
            lease: Mutex::new(match config.lease {
                Some(lease) => LeaseState::Held(lease),
                None => LeaseState::Unleased,
            }),
        })
    }

    /// Opens the table for reading only: no WAL is created or replayed, the
    /// memtable stays empty, and every write path refuses.
    ///
    /// This is how a process that isn't the writer reads an LSM table. Opening
    /// it with [`Self::open`] instead would create a WAL, accept writes, and
    /// eventually flush them — becoming exactly the second writer that
    /// [`super::lease`] exists to prevent, only without having asked anyone.
    ///
    /// A reader sees everything flushed and nothing that isn't, so how stale it
    /// can be is decided entirely by how often the writer flushes — see
    /// [`super::LsmMaintenanceConfig::flush_even_if_small`].
    pub async fn open_read_only(config: TableConfig) -> Result<Self> {
        Ok(Table {
            backend: config.backend,
            cipher: config.cipher,
            root: config.root,
            flush_threshold_bytes: config.flush_threshold_bytes,
            rows_per_block: config.rows_per_block,
            schema: config.schema,
            state: Mutex::new(State {
                wal: None,
                memtable: Memtable::default(),
            }),
            read_only: true,
            lease: Mutex::new(LeaseState::Unleased),
        })
    }

    /// `true` if this handle refuses writes.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Errors unless this handle may write: it isn't read-only, and its lease
    /// (if it has one) still looks valid by the local clock.
    ///
    /// The lease check is deliberately local — asking the bucket whether the
    /// lease still holds, on every write, would cost exactly the round trip
    /// that acking into a local WAL exists to avoid. See [`super::lease`] on
    /// why that makes this a guard against the accidental second writer rather
    /// than a fence.
    async fn ensure_writable(&self) -> Result<()> {
        if self.read_only {
            anyhow::bail!("{}: this table was opened read-only", self.root);
        }
        match &*self.lease.lock().await {
            LeaseState::Unleased => Ok(()),
            LeaseState::Held(lease) if lease.looks_valid() => Ok(()),
            LeaseState::Held(lease) => anyhow::bail!(
                "{}: writer lease held by {:?} has expired locally -- renew it before writing again",
                self.root,
                lease.holder_id()
            ),
            LeaseState::Released => anyhow::bail!(
                "{}: this handle released its writer lease and may no longer write",
                self.root
            ),
        }
    }

    /// Extends this table's writer lease, if it has one. No-op otherwise, so a
    /// caller's renewal timer doesn't have to know whether a lease is in play.
    ///
    /// Errors if the lease was taken over, which is the signal to stop writing:
    /// another process now believes it owns this table.
    pub async fn renew_lease(&self) -> Result<()> {
        match &mut *self.lease.lock().await {
            LeaseState::Held(lease) => lease.renew(self.backend.as_ref(), &self.cipher).await,
            LeaseState::Unleased => Ok(()),
            LeaseState::Released => {
                anyhow::bail!(
                    "{}: this handle released its writer lease, there is nothing to renew",
                    self.root
                )
            }
        }
    }

    /// Gives up this table's writer lease so the next writer doesn't have to
    /// wait out its TTL. Writes are refused afterwards — the handle keeps its
    /// data, it just no longer holds the right to publish it.
    pub async fn release_lease(&self) {
        let mut state = self.lease.lock().await;
        if let LeaseState::Held(lease) = std::mem::replace(&mut *state, LeaseState::Released) {
            lease.release(self.backend.as_ref(), &self.cipher).await;
        }
    }

    /// Who currently holds this table's writer lease, per the bucket. `None`
    /// if nobody does.
    pub async fn lease_holder(&self) -> Result<Option<String>> {
        Ok(WriterLease::current(self.backend.as_ref(), &self.cipher, &self.root)
            .await?
            .map(|record| record.holder_id))
    }

    /// Acks once the WAL append is durable on local disk — no request to
    /// `backend` on this path at all, which is the entire reason a WAL
    /// exists here (see the module doc).
    pub async fn put(&self, key: LsmKey, value: Vec<u8>) -> Result<()> {
        self.ensure_writable().await?;
        let mut state = self.state.lock().await;
        let wal = state.wal.as_mut().expect("a writable table always has a WAL");
        wal.append_put(&key, &value).await?;
        state.memtable.put(key, value);
        Ok(())
    }

    pub async fn delete(&self, key: LsmKey) -> Result<()> {
        self.ensure_writable().await?;
        let mut state = self.state.lock().await;
        let wal = state.wal.as_mut().expect("a writable table always has a WAL");
        wal.append_delete(&key).await?;
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
        // One retry on any error: a concurrent `compact()` can swap the
        // manifest over to a merged SSTable and delete the old ones right
        // after this call loaded the *old* manifest but before it finished
        // reading one of them, turning a perfectly normal compaction into a
        // spurious "missing object" failure here. Reloading the manifest
        // (which `get_from_sstables` does fresh each call) and trying again
        // once resolves that -- a real, persistent failure still surfaces
        // from the second attempt.
        match self.get_from_sstables(key).await {
            Ok(result) => Ok(result),
            Err(_) => self.get_from_sstables(key).await,
        }
    }

    async fn get_from_sstables(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
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
        // Same one-retry reasoning as `Self::get_from_sstables`: a
        // concurrent `compact()` can delete an SSTable this scan just
        // started reading, right after this call's own manifest load --
        // reload (each attempt calls `scan_sstables_merged` fresh) and try
        // once more before treating it as a real failure.
        let mut merged = match self.scan_sstables_merged(start, end, predicates).await {
            Ok(merged) => merged,
            Err(_) => self.scan_sstables_merged(start, end, predicates).await?,
        };

        // The memtable is always freshest -- applied last so it overrides
        // whatever any SSTable had for the same key, tombstones included.
        for (key, value) in self.state.lock().await.memtable.range(start, end) {
            merged.insert(key, value);
        }

        Ok(merged)
    }

    async fn scan_sstables_merged(
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

        Ok(merged)
    }

    /// `true` when the memtable holds nothing to flush. Distinct from
    /// [`Self::should_flush`], which asks whether a flush is *due*: a table
    /// can hold acked writes that haven't reached the threshold, and a caller
    /// that wants those published anyway (see
    /// [`super::maintenance::LsmMaintenanceConfig::flush_even_if_small`])
    /// needs to tell "nothing to do" apart from "not yet worth it".
    pub async fn is_empty(&self) -> bool {
        self.state.lock().await.memtable.is_empty()
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
    /// The drain and the WAL rotation happen under `state`'s lock, but the
    /// SSTable build and the two network calls (`put_cas`, then
    /// `manifest::append`) run *after* releasing it: rotation (see
    /// [`super::wal`]'s module doc) hands the WAL's current file off to a
    /// `.rotating` sibling and puts a fresh, empty one in its place before
    /// the lock is released, so [`Self::put`]/[`Self::delete`] calls landing
    /// during this flush's I/O go to that fresh WAL and the now-empty
    /// memtable, never blocking on (or racing) this flush's own network
    /// round trips.
    ///
    /// Ordered `put_cas` -> manifest append -> rotated-file cleanup
    /// specifically so each failure mode is at worst wasteful, never
    /// silently lossy across a restart:
    /// - If the object write succeeds but the manifest append fails, the
    ///   object sits in the bucket unreferenced by anything (a leak a
    ///   future GC sweep could reclaim) -- but [`Self::abort_flush`] has put
    ///   these rows (and, transitively, the rotated file's records) back
    ///   somewhere replayable, so a crash or retry still recovers and
    ///   flushes them again properly.
    /// - If the manifest append succeeds but deleting the rotated file
    ///   afterward fails, `Table::open`'s startup healing step folds it
    ///   back into the live WAL next time -- replaying it again just
    ///   flushes the same rows into a second, redundant SSTable -- wasteful,
    ///   not incorrect: [`Self::get`] already prefers the newest manifest
    ///   entry for any key, and overlapping SSTables are a normal LSM state
    ///   regardless of how they arose.
    ///
    /// Every failure path between the drain and the manifest append goes
    /// through [`Self::abort_flush`], which restores the drained rows into
    /// the (possibly, by then, no-longer-empty) live memtable and
    /// re-persists exactly the ones a newer write hasn't already superseded
    /// -- without that, they'd only still exist in the rotated file, which
    /// nothing re-replays into this already-open `Table` until its next
    /// restart, so `get`/`scan` would silently stop seeing them for as long
    /// as the process keeps running.
    pub async fn flush(&self) -> Result<Option<FlushedSSTable>> {
        self.ensure_writable().await?;
        let (drained, rotating_path) = {
            let mut state = self.state.lock().await;
            if state.memtable.is_empty() {
                return Ok(None);
            }
            let drained = state.memtable.drain_sorted();
            let rotating_path = state
                .wal
                .as_mut()
                .expect("a writable table always has a WAL")
                .rotate()
                .await?;
            (drained, rotating_path)
        };

        // Decided before building: every block and the footer bind this key
        // into their own AAD (see `sstable`'s module doc), so `build` needs
        // to know it up front, not after sealing.
        let (key, flushed_at_ms) = match sstable::new_object_key(&self.root) {
            Ok(v) => v,
            Err(err) => return self.abort_flush(drained, &rotating_path, err).await,
        };
        let (object, meta) =
            match sstable::build(&self.cipher, &key, self.schema.as_ref(), &drained, self.rows_per_block) {
                Ok(v) => v,
                Err(err) => return self.abort_flush(drained, &rotating_path, err).await,
            };

        match self.backend.put_cas(&key, object, None).await {
            Ok(Cas::Ok) => {}
            // The key includes a millisecond timestamp plus 128 bits of
            // randomness -- a genuine collision here would mean a bug
            // elsewhere, not a race worth retrying (same reasoning
            // `crate::txn::run_with_publisher` already applies to its own
            // random transaction id).
            Ok(Cas::Conflict) => {
                let err = anyhow::anyhow!("SSTable key collision at {key} (should never happen)");
                return self.abort_flush(drained, &rotating_path, err).await;
            }
            Err(err) => return self.abort_flush(drained, &rotating_path, err).await,
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
            // this point, just not yet referenced by the manifest -- same
            // "future GC sweep can reclaim the leaked object" trade-off this
            // method's own doc comment already accepts.
            return self.abort_flush(drained, &rotating_path, err).await;
        }

        // Durable: this rotated file's records are now redundant with the
        // new manifest entry -- best-effort cleanup, same tolerance as
        // every other "leaked file, not a correctness problem" path in this
        // crate (if this fails, `Table::open`'s healing step still cleans
        // it up correctly on the next restart).
        let _ = fs::remove_file(&rotating_path).await;

        Ok(Some(FlushedSSTable {
            key,
            min_key: meta.min_key,
            max_key: meta.max_key,
            row_count: meta.row_count,
            byte_len: meta.byte_len,
            footer_len: meta.footer_len,
        }))
    }

    /// Undoes a failed [`Self::flush`] attempt: merges `drained` back into
    /// the live memtable (a key a write already landed on since the drain
    /// keeps that newer value -- see [`Memtable::merge_older`]) and
    /// re-persists exactly the restored entries into the current WAL
    /// generation, then returns `err` as this call's own result.
    async fn abort_flush(
        &self,
        drained: BTreeMap<LsmKey, MemValue>,
        rotating_path: &std::path::Path,
        err: anyhow::Error,
    ) -> Result<Option<FlushedSSTable>> {
        let mut state = self.state.lock().await;
        let restored = state.memtable.merge_older(drained);
        let Some(wal) = state.wal.as_mut() else {
            // Only a writable table ever gets here (`flush` refuses on a
            // read-only one), so there is nothing to restore into.
            return Err(err);
        };
        for (key, value) in &restored {
            let appended = match value {
                MemValue::Put(bytes) => wal.append_put(key, bytes).await,
                MemValue::Tombstone => wal.append_delete(key).await,
            };
            if appended.is_err() {
                // Couldn't re-persist to the new WAL generation -- leave
                // `rotating_path` alone rather than deleting it, so
                // `Table::open`'s healing step can still recover these
                // records from it if the process goes down before a later
                // flush attempt succeeds.
                return Err(err);
            }
        }
        let _ = fs::remove_file(rotating_path).await;
        Err(err)
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
        self.ensure_writable().await?;
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
