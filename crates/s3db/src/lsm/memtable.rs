//! In-memory, ordered accumulation of writes since the last flush — the
//! piece that gives an LSM [`Table`](super::Table) real key order without a
//! single network request, per `docs/s3db-fulldb-roadmap.md`.

use super::LsmKey;
use std::collections::BTreeMap;

/// One memtable entry: a live value, or a marker that `key` was deleted
/// since the last flush. The tombstone has to be a real entry, not just a
/// removed map key -- without it, a read that checks the memtable and finds
/// nothing would fall through to an older SSTable's now-stale value instead
/// of correctly seeing "deleted."
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MemValue {
    Put(Vec<u8>),
    Tombstone,
}

impl MemValue {
    fn approx_bytes(&self) -> usize {
        match self {
            MemValue::Put(bytes) => bytes.len(),
            MemValue::Tombstone => 0,
        }
    }
}

/// `BTreeMap<LsmKey, MemValue>` plus a running byte-size estimate, so
/// [`Table`](super::Table) can decide when to flush without re-summing the
/// whole map on every write.
#[derive(Debug, Default)]
pub struct Memtable {
    entries: BTreeMap<LsmKey, MemValue>,
    approx_bytes: usize,
}

impl Memtable {
    pub fn put(&mut self, key: LsmKey, value: Vec<u8>) {
        self.insert(key, MemValue::Put(value));
    }

    pub fn delete(&mut self, key: LsmKey) {
        self.insert(key, MemValue::Tombstone);
    }

    fn insert(&mut self, key: LsmKey, value: MemValue) {
        // `key`'s own length is only ever added once, on first insert -- an
        // overwrite reuses the same map entry, so counting `key.len()`
        // again on every rewrite would inflate the estimate (and force
        // flushes) proportional to write count instead of to actual memory
        // held by a hot key rewritten in a loop.
        let key_len = key.len();
        let new_value_bytes = value.approx_bytes();
        match self.entries.insert(key, value) {
            Some(old) => self.approx_bytes = self.approx_bytes + new_value_bytes - old.approx_bytes(),
            None => self.approx_bytes += key_len + new_value_bytes,
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&MemValue> {
        self.entries.get(key)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn approx_bytes(&self) -> usize {
        self.approx_bytes
    }

    /// Ascending-by-key, since `BTreeMap` iteration always is -- this is
    /// exactly the order [`super::sstable::build`] needs its rows in.
    pub fn drain_sorted(&mut self) -> BTreeMap<LsmKey, MemValue> {
        self.approx_bytes = 0;
        std::mem::take(&mut self.entries)
    }

    /// Undoes a [`Self::drain_sorted`] whose rows never actually made it
    /// durable (an SSTable write or manifest append failed after the
    /// drain). Unlike a plain restore, this has to account for writes that
    /// landed here in the meantime -- `older`'s drain happened, then this
    /// memtable's own lock was released for the failed attempt's network
    /// I/O (see `Table::flush`), so a key `older` shares with something
    /// already back in `self.entries` keeps that newer value; `older`'s
    /// copy of it is simply stale and gets dropped. Returns exactly the
    /// entries that *were* restored, so the caller can re-append just
    /// those to the WAL -- one already covered by a newer write is already
    /// durable there, and re-appending it too would place a stale record
    /// after the fresh one in file order, resurrecting it on replay.
    pub fn merge_older(&mut self, older: BTreeMap<LsmKey, MemValue>) -> BTreeMap<LsmKey, MemValue> {
        let mut restored = BTreeMap::new();
        for (key, value) in older {
            if self.entries.contains_key(&key) {
                continue; // superseded by a write that landed after the drain
            }
            self.approx_bytes += key.len() + value.approx_bytes();
            self.entries.insert(key.clone(), value.clone());
            restored.insert(key, value);
        }
        restored
    }

    /// Every entry with `start <= key < end` (either bound `None` for
    /// unbounded), ascending -- the memtable's own contribution to
    /// [`super::Table::scan`], always the freshest since anything in here
    /// hasn't been flushed yet.
    pub fn range(&self, start: Option<&[u8]>, end: Option<&[u8]>) -> Vec<(LsmKey, MemValue)> {
        use std::ops::Bound;
        let start = match start {
            Some(s) => Bound::Included(s.to_vec()),
            None => Bound::Unbounded,
        };
        let end = match end {
            Some(e) => Bound::Excluded(e.to_vec()),
            None => Bound::Unbounded,
        };
        self.entries
            .range((start, end))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/memtable.rs"]
mod tests;
