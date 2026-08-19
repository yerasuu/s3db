//! Which process is allowed to write a [`Table`](super::Table).
//!
//! A `Table` acknowledges a write as soon as its **local** WAL is durable and
//! holds it in an **in-process** memtable. Both words matter: they are what
//! make a write cheap, and they are also why a second process writing the same
//! table is not a supported configuration.
//!
//! Two writers do not merely see stale data. They corrupt the table's history:
//! a row's age is decided by the order its SSTable was appended to the
//! manifest, so if A writes `k=1` and B later writes `k=2` but A flushes
//! second, A's older value permanently wins. Nothing in the format records
//! when a row was written, so nothing downstream can resolve it.
//!
//! Making that safe for real (concurrent writers, last-write-wins per row)
//! means a timestamp or sequence number on every row, carried through the
//! WAL, the memtable, the SSTable blocks, and every merge in `Table::get`,
//! `Table::scan`, and the compactor — a change to the storage format, not a
//! coordination layer bolted on top. Until that exists, this module makes the
//! supported topology explicit and enforced instead of documented and hoped
//! for:
//!
//! - **One writer**, holding a [`WriterLease`]. A second process trying to
//!   acquire one is refused, loudly, at startup — rather than silently
//!   becoming the corruption above.
//! - **Any number of readers**, via [`Table::open_read_only`](super::Table::open_read_only),
//!   which never creates a WAL and refuses writes, so a reader can't drift
//!   into being an accidental second writer. A reader sees everything that has
//!   been flushed and nothing that hasn't, so its staleness is bounded by how
//!   often the writer flushes — see
//!   [`LsmMaintenanceConfig::flush_even_if_small`](super::LsmMaintenanceConfig::flush_even_if_small).
//!
//! # What the lease does and does not prevent
//!
//! It prevents the failure that actually happens: two instances of a service
//! started against the same table. The holder renews on a timer and stops
//! writing when renewal fails, so a process that loses its lease learns so
//! within one renewal interval.
//!
//! It is **not a fence**. Between the moment a lease expires and the moment
//! its holder notices, that holder can still write, and S3 has no way to
//! reject the write on the lease's behalf — a real fence needs the storage
//! layer to check a token, which would mean a CAS against the lease on every
//! single write. So `ttl` should be comfortably longer than a flush takes, and
//! a taken-over lease should be treated as "the old writer may still be
//! finishing", not "the old writer is definitely gone".

use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::payload::{delete_object, get_json, put_json};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn lease_key(root: &str) -> String {
    format!("{root}/WRITER-LEASE.json")
}

/// The stored lease. Deliberately in the table's own prefix rather than under
/// `.conf/`: it belongs to this table the same way its `MANIFEST.json` does,
/// and a table copied or backed up should carry it (or visibly not).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    /// Whoever the caller says it is — a hostname, a pod name, a uuid. Only
    /// ever compared for equality and shown in errors, so its shape is the
    /// caller's business.
    pub holder_id: String,
    pub acquired_at_ms: u64,
    pub renewed_at_ms: u64,
    pub ttl_ms: u64,
}

impl LeaseRecord {
    /// Whether this lease has gone unrenewed for longer than its own TTL,
    /// judged against `now`.
    pub fn is_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.renewed_at_ms) > self.ttl_ms
    }
}

/// A held writer lease. Renew it on a timer; stop writing if renewal fails.
#[derive(Debug, Clone)]
pub struct WriterLease {
    root: String,
    holder_id: String,
    ttl: Duration,
    /// The etag of the record as this holder last wrote it. Every renewal CASes
    /// against it, so a holder whose lease was taken over discovers it on the
    /// next renewal instead of writing on regardless.
    etag: Option<String>,
    /// Local clock reading of the last successful renewal — what
    /// [`Self::looks_valid`] answers from, since asking the bucket on every
    /// write is exactly the cost a local WAL exists to avoid.
    renewed_at_ms: u64,
}

impl WriterLease {
    /// Takes the lease for `root`, or refuses if someone else holds a live one.
    ///
    /// A lease whose holder stopped renewing for longer than its TTL is taken
    /// over. That is the only way a crashed writer's table ever becomes
    /// writable again, and it is also why the TTL matters: see the module doc
    /// on why this is not a fence.
    pub async fn acquire(
        backend: &dyn Backend,
        cipher: &Cipher,
        root: &str,
        holder_id: &str,
        ttl: Duration,
    ) -> Result<Self> {
        let key = lease_key(root);
        let now = now_ms();
        let (existing, etag) = get_json::<LeaseRecord>(backend, &key, cipher).await?;

        if etag.is_some() {
            // Re-acquiring one's own lease is allowed: a writer restarting
            // after a clean shutdown that failed to release shouldn't have to
            // wait out its own TTL.
            if existing.holder_id != holder_id && !existing.is_expired(now) {
                bail!(
                    "{root} is already being written by {:?} (lease renewed {}ms ago, ttl {}ms) -- \
an LSM table supports one writer; open it read-only to read it",
                    existing.holder_id,
                    now.saturating_sub(existing.renewed_at_ms),
                    existing.ttl_ms
                );
            }
        }

        let record = LeaseRecord {
            holder_id: holder_id.to_string(),
            acquired_at_ms: now,
            renewed_at_ms: now,
            ttl_ms: ttl.as_millis() as u64,
        };
        // CAS against exactly what was read: if another process acquired in
        // between, this loses rather than overwriting a lease that just went
        // live.
        if put_json(backend, &key, &record, etag.as_deref(), cipher).await? == Cas::Conflict {
            bail!("{root}: lost the race to acquire the writer lease, another process got it first");
        }
        let (_record, new_etag) = get_json::<LeaseRecord>(backend, &key, cipher).await?;
        Ok(WriterLease {
            root: root.to_string(),
            holder_id: holder_id.to_string(),
            ttl,
            etag: new_etag,
            renewed_at_ms: now,
        })
    }

    /// Extends the lease. Errors if it was taken over — at which point the
    /// caller must stop writing, since another process now believes it owns
    /// this table.
    pub async fn renew(&mut self, backend: &dyn Backend, cipher: &Cipher) -> Result<()> {
        let key = lease_key(&self.root);
        let now = now_ms();
        let record = LeaseRecord {
            holder_id: self.holder_id.clone(),
            acquired_at_ms: now,
            renewed_at_ms: now,
            ttl_ms: self.ttl.as_millis() as u64,
        };
        if put_json(backend, &key, &record, self.etag.as_deref(), cipher).await? == Cas::Conflict {
            let (current, _etag) = get_json::<LeaseRecord>(backend, &key, cipher).await?;
            bail!(
                "{}: writer lease lost to {:?} -- stop writing this table",
                self.root,
                current.holder_id
            );
        }
        let (_record, etag) = get_json::<LeaseRecord>(backend, &key, cipher).await?;
        self.etag = etag;
        self.renewed_at_ms = now;
        Ok(())
    }

    /// Gives the lease up, so another writer doesn't have to wait out the TTL.
    /// Best-effort: a lease that outlives its holder is exactly what the TTL
    /// is for.
    pub async fn release(self, backend: &dyn Backend, cipher: &Cipher) {
        let key = lease_key(&self.root);
        let (current, _etag) = match get_json::<LeaseRecord>(backend, &key, cipher).await {
            Ok(pair) => pair,
            Err(_) => return,
        };
        // Never delete a lease that is no longer ours -- that would hand the
        // table to a third process while the current holder is mid-write.
        if current.holder_id == self.holder_id {
            delete_object(backend, &key).await;
        }
    }

    /// Whether this holder still believes the lease is good, from the local
    /// clock alone — no request. What [`Table`](super::Table) checks before
    /// accepting a write, since consulting the bucket per write would undo
    /// the entire reason the WAL is local.
    pub fn looks_valid(&self) -> bool {
        now_ms().saturating_sub(self.renewed_at_ms) <= self.ttl.as_millis() as u64
    }

    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Reads whatever lease is stored for `root`, without touching it — for an
    /// operator asking "who is writing this table?".
    pub async fn current(backend: &dyn Backend, cipher: &Cipher, root: &str) -> Result<Option<LeaseRecord>> {
        let (record, etag) = get_json::<LeaseRecord>(backend, &lease_key(root), cipher).await?;
        Ok(etag.is_some().then_some(record))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/lease.rs"]
mod tests;
