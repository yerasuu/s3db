//! Merges every SSTable a table currently has into one, purging tombstones
//! along the way — `docs/s3db-fulldb-roadmap.md` phase 3: "mantener el
//! número de SSTables acotado y la amplificación de lectura baja." Replaces
//! `crate::gc`/`crate::maintenance` for LSM tables, which don't apply here
//! (those sweep [`crate::collection::Collection`] tombstones/orphans, a
//! completely different physical layout).
//!
//! Deliberately the simplest strategy that satisfies the goal: full, tiered
//! compaction, not leveled. Every call merges *all* of a table's SSTables
//! into exactly one (or zero, if every key turned out tombstoned away),
//! never a partial subset. That's what makes dropping tombstones safe
//! without a retention window: a merge that covers the *entire* manifest
//! has nothing older left unmerged that a tombstone could still need to
//! shadow, so any tombstone surviving to the end of the merge can just be
//! dropped. A leveled scheme (merge only the oldest few, keep newer ones
//! untouched) would need to keep expired-but-not-provably-safe tombstones
//! around instead — real, but not something anything here has asked for
//! yet. [`ManifestEntry::level`] stays `0` for every SSTable this produces
//! as a result: there's only one tier.
//!
//! Not called automatically by [`super::Table`] on any schedule — same
//! "explicit, caller-driven sweep" shape as [`crate::maintenance::MaintenanceScanner`]
//! and [`crate::gc::GcConfig`], not a background task spawned inside this
//! crate. [`should_compact`] is the policy a caller (a periodic maintenance
//! job) checks before calling [`compact`].

use super::memtable::MemValue;
use super::value::Schema;
use super::{LsmKey, manifest, sstable};
use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::lsm::manifest::ManifestEntry;
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

/// A table with fewer SSTables than this isn't worth compacting yet — the
/// read amplification a point lookup pays (one footer fetch per candidate
/// SSTable before even reaching the right one) is still small. Not
/// load-bearing precision, just a reasonable default a caller can ignore
/// entirely by calling [`compact`] directly on its own schedule instead.
const DEFAULT_COMPACTION_THRESHOLD: usize = 4;

/// `true` once a table has accumulated enough SSTables that compacting is
/// worth the write amplification (rewriting every live row) it costs.
pub fn should_compact(sstable_count: usize) -> bool {
    sstable_count >= DEFAULT_COMPACTION_THRESHOLD
}

/// What one [`compact`] call did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CompactionReport {
    pub sstables_before: usize,
    /// `0` or `1` -- a full merge never produces more than one SSTable.
    pub sstables_after: usize,
    /// Rows read across every merged SSTable, tombstones included --
    /// how much work the compaction actually did, independent of how much
    /// survived it.
    pub rows_read: usize,
    /// Live rows in the merged result, after dropping every tombstone.
    pub rows_after: usize,
}

/// Merges every SSTable currently in `root`'s manifest into one (dropping
/// tombstones, see the module doc), writes it, swaps the manifest over to
/// just that one entry, then best-effort deletes the SSTables it replaced.
///
/// A no-op (`Ok` with `sstables_after == sstables_before`) if there's fewer
/// than two SSTables to merge -- compacting a single SSTable would rewrite
/// it for no benefit.
pub async fn compact(
    backend: &dyn Backend,
    cipher: &Cipher,
    root: &str,
    schema: Option<&Schema>,
    rows_per_block: usize,
) -> Result<CompactionReport> {
    let (manifest, etag) = manifest::load(backend, cipher, root).await?;
    let sstables_before = manifest.sstables.len();
    if sstables_before < 2 {
        return Ok(CompactionReport {
            sstables_before,
            sstables_after: sstables_before,
            rows_read: 0,
            rows_after: 0,
        });
    }

    // Oldest to newest (manifest order, see its own doc) -- inserting into
    // the same map lets a newer SSTable's entry for a key simply overwrite
    // an older one's, which is exactly the LSM "newest write wins" rule.
    let mut merged: BTreeMap<LsmKey, MemValue> = BTreeMap::new();
    let mut rows_read = 0;
    for old_entry in &manifest.sstables {
        let (object, object_etag) = backend.get(&old_entry.key).await?;
        if object_etag.is_none() {
            bail!(
                "manifest at {root} references {}, but it's missing from the backend -- refusing to compact \
                 over a gap instead of silently losing whatever rows it had",
                old_entry.key
            );
        }
        let rows = sstable::read_all(cipher, &old_entry.key, schema, &object)?;
        rows_read += rows.len();
        merged.extend(rows);
    }

    let live: BTreeMap<LsmKey, MemValue> = merged
        .into_iter()
        .filter(|(_, v)| matches!(v, MemValue::Put(_)))
        .collect();
    let rows_after = live.len();

    let new_sstables = if live.is_empty() {
        Vec::new()
    } else {
        let (new_key, flushed_at_ms) = sstable::new_object_key(root)?;
        let (object, meta) = sstable::build(cipher, &new_key, schema, &live, rows_per_block)?;
        match backend.put_cas(&new_key, object, None).await? {
            Cas::Ok => {}
            Cas::Conflict => bail!("compacted SSTable key collision at {new_key} (should never happen)"),
        }
        vec![ManifestEntry {
            key: new_key,
            min_key: meta.min_key,
            max_key: meta.max_key,
            byte_len: meta.byte_len,
            footer_len: meta.footer_len,
            level: 0,
            flushed_at_ms,
        }]
    };
    let sstables_after = new_sstables.len();

    match manifest::replace(backend, cipher, root, new_sstables, etag.as_deref())
        .await
        .context("swapping the manifest to the compacted result")?
    {
        Cas::Ok => {}
        // Something else (a concurrent flush, another compaction run)
        // changed the manifest since the read at the top of this call --
        // the merge this call computed no longer reflects reality. The
        // newly-written SSTable, if any, is simply unreferenced and safe to
        // leave for a future compaction to clean up; nothing here corrupts
        // anything by bailing out instead of forcing the stale result in.
        Cas::Conflict => bail!("manifest at {root} changed concurrently during compaction -- retry"),
    }

    // Best-effort: the manifest no longer references these, so they're
    // already logically gone regardless of whether this delete lands (same
    // "best-effort, GC-style cleanup" contract `Backend::delete_many`
    // documents everywhere else in this crate).
    let old_keys: Vec<String> = manifest.sstables.iter().map(|e| e.key.clone()).collect();
    backend.delete_many(&old_keys).await?;

    Ok(CompactionReport {
        sstables_before,
        sstables_after,
        rows_read,
        rows_after,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/compactor.rs"]
mod tests;
