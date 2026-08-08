//! `{root}/MANIFEST.json`, CAS-controlled — the single source of truth for
//! which SSTables currently make up a [`super::Table`], per
//! `docs/s3db-fulldb-roadmap.md`. Updated the same way every other durable
//! record in this crate is (`crate::payload::put_json`'s CAS loop), single-
//! writer per table, same accepted limitation as everywhere else here: no
//! multi-writer consensus, because that would need a coordinator this crate
//! deliberately doesn't have.

use super::LsmKey;
use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::payload::{get_json, put_json};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Bounded, not infinite: a manifest update racing against another one
/// forever would mean something is fundamentally wrong (two writers on a
/// table meant to have one), not a transient blip worth retrying forever.
const MAX_APPEND_ATTEMPTS: u32 = 10;

/// One flushed SSTable's entry in the manifest -- everything
/// [`super::sstable::open_footer_bytes`]/[`super::sstable::decode_block`]
/// need to fetch and open it without a preliminary round trip just to learn
/// sizes. `level` is recorded from phase 1 on (the roadmap's own manifest
/// shape includes it) even though nothing reads it until phase 3's
/// compactor exists to assign anything other than `0`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub key: String,
    pub min_key: LsmKey,
    pub max_key: LsmKey,
    pub byte_len: u64,
    pub footer_len: u64,
    pub level: u32,
    pub flushed_at_ms: u64,
}

/// Every SSTable currently live for one table. `sstables` is in flush order
/// (oldest first) — a point lookup walks it in reverse so the most recent
/// write for a key is always the one found first.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    pub sstables: Vec<ManifestEntry>,
}

fn manifest_key(root: &str) -> String {
    format!("{root}/MANIFEST.json")
}

/// Reads the current manifest (or an empty default plus `None` if a table
/// has never flushed anything yet — a fresh table isn't an error).
pub(crate) async fn load(backend: &dyn Backend, cipher: &Cipher, root: &str) -> Result<(Manifest, Option<String>)> {
    get_json(backend, &manifest_key(root), cipher).await
}

/// Adds `entry` to the manifest, retrying its own read-modify-write CAS
/// loop on conflict (bounded, see [`MAX_APPEND_ATTEMPTS`]) -- one
/// [`super::Table`] is the only writer this is meant to support, so a
/// conflict here means a concurrent flush from *this same* process (or a
/// misconfigured second writer), not a race this crate is trying to make
/// safe across genuinely independent writers.
pub(crate) async fn append(backend: &dyn Backend, cipher: &Cipher, root: &str, entry: ManifestEntry) -> Result<()> {
    for _ in 0..MAX_APPEND_ATTEMPTS {
        let (mut manifest, etag) = load(backend, cipher, root).await?;
        manifest.sstables.push(entry.clone());
        match put_json(backend, &manifest_key(root), &manifest, etag.as_deref(), cipher).await? {
            Cas::Ok => return Ok(()),
            Cas::Conflict => continue,
        }
    }
    bail!("couldn't update the manifest at {root} after {MAX_APPEND_ATTEMPTS} attempts (high contention)")
}

#[cfg(test)]
mod tests;
