//! Best-effort, time-bounded point-in-time reads over a [`Collection`]'s
//! `.history/` archive. **Not** real MVCC: two entities read through the
//! same [`ReadSnapshot`] at "the same" logical instant were each simply the
//! latest archived version at or before that instant for *that one entity*
//! -- there is no cross-entity atomicity here, the same honesty
//! [`crate::backup`]'s `BackupConsistency::FuzzySnapshot` already commits to
//! for a full-bucket backup, just at the single-entity scale a snapshot
//! actually operates at.
//!
//! A [`ReadSnapshot`] only works for as long as the versions it needs stay
//! in `.history/` -- nothing here prevents pruning by itself.
//! [`SnapshotLease`] is the durable, hard-capped record a GC/maintenance
//! sweep (not built in this crate yet) is expected to check before pruning
//! a history entry: if the entry's timestamp falls inside a live lease's
//! window, skip it this pass. [`ReadSnapshot::open`]'s `max_duration` is a
//! hard cap, not a suggestion -- this is deliberately not a mechanism for
//! "long-lived" snapshots (that's what a real point-in-time backup restore
//! is for); it only exists to stop a GC sweep that happens to run mid-read
//! from yanking a version out from under an in-flight [`ReadSnapshot`].

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::collection::Collection;
use crate::payload::{delete_object, get_json, list_all_keys, put_json};
use anyhow::Result;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SNAPSHOT_PREFIX: &str = ".conf/snapshots";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn random_snapshot_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating snapshot id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn lease_key(snapshot_id: &str) -> String {
    format!("{SNAPSHOT_PREFIX}/{snapshot_id}.json")
}

/// Durable record of one live [`ReadSnapshot`], at
/// `.conf/snapshots/<snapshot_id>.json`. A GC/maintenance sweep checks
/// `now - timestamp_ms < max_duration_ms` before pruning a `.history/`
/// entry whose own timestamp ([`Collection::version_timestamp`]) falls
/// inside `[timestamp_ms, timestamp_ms + max_duration_ms]` -- if so, it
/// skips that entry this pass rather than risk yanking it out from under
/// this snapshot.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct SnapshotLease {
    pub snapshot_id: String,
    pub timestamp_ms: u64,
    pub max_duration_ms: u64,
}

/// A best-effort, time-bounded point-in-time view -- see this module's own
/// doc comment for exactly what guarantee that is (and isn't).
pub struct ReadSnapshot {
    snapshot_id: String,
    as_of_ms: u64,
}

impl ReadSnapshot {
    /// Registers a [`SnapshotLease`] and returns a snapshot fixed at this
    /// moment. `max_duration` is a hard cap enforced by callers pruning
    /// `.history/` (see this module's doc comment) -- not configurable
    /// beyond whatever this caller passes, and not extendable once open.
    pub async fn open(backend: &dyn Backend, cipher: &Cipher, max_duration: Duration) -> Result<Self> {
        let snapshot_id = random_snapshot_id()?;
        let as_of_ms = now_ms();
        let lease = SnapshotLease {
            snapshot_id: snapshot_id.clone(),
            timestamp_ms: as_of_ms,
            max_duration_ms: max_duration.as_millis() as u64,
        };
        put_json(backend, &lease_key(&snapshot_id), &lease, None, cipher).await?;
        Ok(ReadSnapshot { snapshot_id, as_of_ms })
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    /// Releases the lease -- best-effort, same tolerance as every other
    /// cleanup step in this crate. Once this returns (or even if it's never
    /// called and the lease simply expires on its own via `max_duration`),
    /// a GC sweep is free to prune whatever this snapshot was pinning.
    pub async fn close(&self, backend: &dyn Backend) {
        delete_object(backend, &lease_key(&self.snapshot_id)).await;
    }

    /// `name`'s value as of this snapshot's moment.
    ///
    /// A `.history/{etag}` entry's [`Collection::version_timestamp`] is
    /// when it was *retired* (overwritten by the next write), not when it
    /// was created -- so the version live at `as_of_ms` is the one with the
    /// **earliest** retirement timestamp that's still *after* `as_of_ms`
    /// (it was overwritten sometime after our snapshot point, so it must
    /// have still been live at that point). If no version was retired
    /// after `as_of_ms`, nothing has changed since the snapshot was taken,
    /// so the current live value already is the answer -- *unless* `name`
    /// didn't exist yet at `as_of_ms` either: [`Collection::created_at`]
    /// (recorded by [`Collection::put_versioned`] at first create) rules
    /// that phantom-read case out before falling back to the live value.
    /// `None` from `created_at` (written only via plain [`Collection::put`],
    /// or created before this tracking existed) can't rule it out either
    /// way, so it falls back to the live value same as before.
    ///
    /// O(versions of `name`) -- this walks every archived version, since
    /// they aren't necessarily contiguous or bisectable (a version with no
    /// companion timestamp, from a lost race on
    /// `Collection::archive_history_timestamp`, is simply skipped, not
    /// treated as an ordering pivot).
    pub async fn get<T: Serialize + DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        collection: &Collection,
        name: &str,
    ) -> Result<Option<T>> {
        let versions = collection.list_versions(backend, name).await?;
        let mut earliest_after: Option<(u64, String)> = None;
        for version in versions {
            let Some(archived_at_ms) = collection.version_timestamp(backend, cipher, name, &version).await? else {
                continue;
            };
            if archived_at_ms <= self.as_of_ms {
                continue; // retired at or before the snapshot point -- not live at as_of_ms
            }
            if earliest_after.as_ref().is_none_or(|(t, _)| archived_at_ms < *t) {
                earliest_after = Some((archived_at_ms, version));
            }
        }

        if let Some((_, version)) = earliest_after {
            return collection.get_version(backend, cipher, name, &version).await;
        }

        if let Some(created_at_ms) = collection.created_at(backend, cipher, name).await?
            && created_at_ms > self.as_of_ms
        {
            return Ok(None); // didn't exist yet at as_of_ms
        }

        // No version was retired after `as_of_ms`, and `name` either
        // already existed by then or its creation time isn't known:
        // nothing has changed since, so the live value already is the
        // answer.
        let (value, etag) = collection.get::<T>(backend, cipher, name).await?;
        if etag.is_none() {
            return Ok(None);
        }
        Ok(value)
    }
}

/// Every currently-registered lease, for [`crate::gc::sweep`] to check
/// before pruning a `.history/` entry -- a lease past its own
/// `max_duration_ms` is excluded (its `ReadSnapshot` was only ever entitled
/// to protection for that long, whether or not `close` was ever called).
pub async fn list_leases(backend: &dyn Backend, cipher: &Cipher) -> Result<Vec<SnapshotLease>> {
    let now = now_ms();
    let mut leases = Vec::new();
    for key in list_all_keys(backend, &format!("{SNAPSHOT_PREFIX}/")).await? {
        let (lease, etag) = get_json::<SnapshotLease>(backend, &key, cipher).await?;
        if etag.is_some() && now.saturating_sub(lease.timestamp_ms) <= lease.max_duration_ms {
            leases.push(lease);
        }
    }
    Ok(leases)
}

#[cfg(test)]
#[path = "../tests/unit/snapshot.rs"]
mod tests;
