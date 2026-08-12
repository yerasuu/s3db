//! `ShardedIndex`: [`crate::index::SecondaryIndex`], but the pointer key
//! spreads across `2^prefix_bits` shards instead of all landing under one
//! `{root}/{kind}/` prefix -- S3 (and compatibles) partitions internally by
//! key prefix, and gives more aggregate throughput the more distinct
//! partitions requests actually touch. A single hot index (every write
//! landing under the same lexicographic range) caps out at one partition's
//! throughput no matter how many server instances are calling it in
//! parallel; sharding spreads the same logical index across `2^prefix_bits`
//! independent ranges.
//!
//! Rebalancing (splitting shards as an index grows) is explicit and
//! two-phase, gated by [`ShardEpoch`]: [`ShardedIndex::begin_rebalance`]
//! doubles `prefix_bits` but keeps every *write* landing on the old shard
//! layout (`prev_prefix_bits`) until [`ShardedIndex::complete_rebalance`]
//! has actually copied every old entry to its new home -- a writer that
//! computed a shard from a `prefix_bits` value nobody else has agreed to
//! yet would put two different processes' idea of "which shard holds this
//! segment" out of sync, with no CAS able to catch it (CAS only protects
//! within one key, never "this logical segment across however many shards
//! it could be under"). `resolve` checks both layouts while a rebalance is
//! in flight, so reads never see a gap.
//!
//! Simplification versus a fully general per-shard epoch: this crate tracks
//! **one** [`ShardEpoch`] for the whole index, not one per old shard being
//! split. That means a rebalance in flight pins *every* shard's writes to
//! the old layout, not just the one shard actually being split -- a real
//! (if usually brief) throughput cost the more general design would avoid.
//! Chosen deliberately for this crate: one epoch record is far simpler to
//! reason about and CAS correctly than a family of them, and a rebalance is
//! expected to be rare and short-lived, not a steady-state operation.

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::index::Segment;
use crate::metrics::MetricsRecorder;
use crate::payload::{delete_object, get_json, list_all_keys, put_json};
use crate::shard::shard_of;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Ceiling on [`ShardEpoch::prefix_bits`] -- `2^20` (~1M) shards is far more
/// than any real deployment's occupancy threshold should ever require, and
/// [`ShardedIndex::occupancy`]'s per-shard `list_prefix` scan (plus
/// [`ShardedIndex::complete_rebalance`]'s own per-shard copy pass) both cost
/// more the more shards there are -- an unbounded doubling driven by noisy
/// occupancy counts would eventually make routine maintenance itself the
/// expensive operation.
const MAX_PREFIX_BITS: u8 = 20;

/// Durable rebalance state at `{root}/{kind}/.shard-epoch.json` -- see this
/// module's doc comment for the two-phase protocol it drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ShardEpoch {
    pub epoch: u32,
    pub prefix_bits: u8,
    /// `Some` only while a rebalance is in flight -- every writer computes
    /// its shard from *this*, not `prefix_bits`, until it's cleared.
    pub prev_prefix_bits: Option<u8>,
}

impl ShardEpoch {
    fn write_bits(&self) -> u8 {
        self.prev_prefix_bits.unwrap_or(self.prefix_bits)
    }
}

pub struct ShardedIndex {
    root: String,
    kind: String,
    segment: Segment,
    epoch_cache_ttl: Duration,
    epoch_cache: Mutex<Option<(Instant, ShardEpoch)>>,
}

impl ShardedIndex {
    pub fn new(root: impl Into<String>, kind: impl Into<String>, segment: Segment) -> Self {
        ShardedIndex {
            root: root.into(),
            kind: kind.into(),
            segment,
            epoch_cache_ttl: Duration::from_secs(5),
            epoch_cache: Mutex::new(None),
        }
    }

    fn epoch_key(&self) -> String {
        format!("{}/{}/.shard-epoch.json", self.root, self.kind)
    }

    fn shard_prefix(&self, shard: u32, prefix_bits: u8) -> String {
        let width = prefix_bits.div_ceil(4).max(1) as usize;
        format!("{}/{}/{shard:0width$x}/", self.root, self.kind)
    }

    fn key_for(&self, raw: &str, prefix_bits: u8) -> String {
        let shard = shard_of(raw, prefix_bits);
        format!(
            "{}{}.json",
            self.shard_prefix(shard, prefix_bits),
            self.segment.encode(raw)
        )
    }

    /// Reads the current epoch, short-TTL-cached (not per-request) so a
    /// steady stream of `claim_once`/`resolve` calls doesn't turn into a
    /// steady stream of extra reads just to check whether a rebalance
    /// happens to be running.
    ///
    /// The cache is only trusted while it shows *no* rebalance in flight:
    /// once it does, staleness stops being harmless. A writer holding a
    /// stale "rebalance in flight" epoch keeps computing `write_bits()` from
    /// `prev_prefix_bits`, same as a fresh read would while the rebalance is
    /// genuinely still running -- but if the rebalance has *actually*
    /// finished (`complete_rebalance` already cleared `prev_prefix_bits`)
    /// during the up-to-`epoch_cache_ttl` window since this cache entry was
    /// fetched, that write lands on the now-abandoned old shard layout while
    /// every fresh `resolve()` only checks the new one -- the entry becomes
    /// permanently unresolvable. Always re-fetching in that state closes the
    /// window entirely; the cache still fully applies to the (overwhelmingly
    /// common) steady-state case where no rebalance is running.
    async fn current_epoch(&self, backend: &dyn Backend, cipher: &Cipher) -> Result<ShardEpoch> {
        if let Some((fetched_at, epoch)) = *self.epoch_cache.lock().unwrap()
            && fetched_at.elapsed() < self.epoch_cache_ttl
            && epoch.prev_prefix_bits.is_none()
        {
            return Ok(epoch);
        }
        let (epoch, _etag) = get_json::<ShardEpoch>(backend, &self.epoch_key(), cipher).await?;
        *self.epoch_cache.lock().unwrap() = Some((Instant::now(), epoch));
        Ok(epoch)
    }

    /// Single-attempt CAS claim -- same conflict semantics as
    /// [`crate::index::SecondaryIndex::claim_once`]. Always writes to the
    /// shard layout in effect for writers right now (`prev_prefix_bits`
    /// while a rebalance is in flight, `prefix_bits` otherwise).
    pub async fn claim_once<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
        value: &T,
    ) -> Result<bool> {
        let epoch = self.current_epoch(backend, cipher).await?;
        let key = self.key_for(raw, epoch.write_bits());
        match put_json(backend, &key, value, None, cipher).await? {
            crate::backend::Cas::Ok => Ok(true),
            crate::backend::Cas::Conflict => Ok(false),
        }
    }

    /// Resolves `raw`, checking the new shard layout first, then (only
    /// while a rebalance is in flight) the old one -- an entry not yet
    /// copied over by [`Self::complete_rebalance`] must still resolve.
    pub async fn resolve<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        raw: &str,
    ) -> Result<(Option<T>, Option<String>)> {
        let epoch = self.current_epoch(backend, cipher).await?;
        let (value, etag) = get_json::<T>(backend, &self.key_for(raw, epoch.prefix_bits), cipher).await?;
        if etag.is_some() {
            return Ok((Some(value), etag));
        }
        if let Some(prev_bits) = epoch.prev_prefix_bits {
            let (value, etag) = get_json::<T>(backend, &self.key_for(raw, prev_bits), cipher).await?;
            return Ok((etag.is_some().then_some(value), etag));
        }
        Ok((None, None))
    }

    pub async fn release(&self, backend: &dyn Backend, cipher: &Cipher, raw: &str) {
        let Ok(epoch) = self.current_epoch(backend, cipher).await else {
            return;
        };
        delete_object(backend, &self.key_for(raw, epoch.write_bits())).await;
        if let Some(prev_bits) = epoch.prev_prefix_bits {
            delete_object(backend, &self.key_for(raw, prev_bits)).await;
        }
    }

    /// Doubles `prefix_bits`, pinning every writer to the old layout
    /// (`prev_prefix_bits`) until [`Self::complete_rebalance`] runs.
    /// Refuses if a rebalance is already in flight -- callers should check
    /// [`Self::occupancy`]/retry, not stack rebalances.
    pub async fn begin_rebalance(&self, backend: &dyn Backend, cipher: &Cipher) -> Result<()> {
        let (mut epoch, etag) = get_json::<ShardEpoch>(backend, &self.epoch_key(), cipher).await?;
        if epoch.prev_prefix_bits.is_some() {
            bail!("a rebalance is already in progress for {}/{}", self.root, self.kind);
        }
        if epoch.prefix_bits >= MAX_PREFIX_BITS {
            bail!(
                "{}/{} is already at the {MAX_PREFIX_BITS}-bit shard ceiling ({} shards), refusing to grow further",
                self.root,
                self.kind,
                1u32 << MAX_PREFIX_BITS
            );
        }
        epoch.prev_prefix_bits = Some(epoch.prefix_bits);
        epoch.prefix_bits = epoch.prefix_bits.saturating_add(1).min(MAX_PREFIX_BITS);
        epoch.epoch = epoch.epoch.wrapping_add(1);
        match put_json(backend, &self.epoch_key(), &epoch, etag.as_deref(), cipher).await? {
            crate::backend::Cas::Ok => {
                *self.epoch_cache.lock().unwrap() = None;
                Ok(())
            }
            crate::backend::Cas::Conflict => bail!("shard epoch changed concurrently, retry begin_rebalance"),
        }
    }

    /// Copies every entry still sitting under the old shard layout to its
    /// correctly-hashed new shard, then clears `prev_prefix_bits` -- a no-op
    /// if no rebalance is in flight. Safe to call repeatedly (a crash
    /// mid-copy just means some entries were already moved; re-running
    /// finds them already at their new home and moves on, and the create-
    /// only write at the new key is itself idempotent for the same
    /// content).
    pub async fn complete_rebalance(&self, backend: &dyn Backend, cipher: &Cipher) -> Result<()> {
        let (epoch, etag) = get_json::<ShardEpoch>(backend, &self.epoch_key(), cipher).await?;
        let Some(prev_bits) = epoch.prev_prefix_bits else {
            return Ok(());
        };
        let old_shard_count = 1u32 << prev_bits.min(31);

        // Copy in passes rather than once: a claimant can land a fresh
        // write on the old layout after this pass's `list_all_keys` already
        // ran over that shard (still correctly targeting the old layout --
        // see `current_epoch`'s own doc comment -- just not yet moved).
        // Re-scanning until a whole pass finds nothing left means
        // `prev_prefix_bits` below only ever gets cleared once the old
        // layout is verified empty, not just "empty as of one snapshot".
        const MAX_COPY_PASSES: u32 = 5;
        let mut settled = false;
        for _ in 0..MAX_COPY_PASSES {
            let mut moved_any = false;
            for old_shard in 0..old_shard_count {
                let prefix = self.shard_prefix(old_shard, prev_bits);
                for old_key in list_all_keys(backend, &prefix).await? {
                    let segment_encoded = old_key
                        .strip_prefix(&prefix)
                        .and_then(|s| s.strip_suffix(".json"))
                        .with_context(|| format!("{old_key}: doesn't match this index's own key shape"))?;
                    let raw = self.segment.decode(segment_encoded)?;
                    let new_key = self.key_for(&raw, epoch.prefix_bits);
                    if new_key == old_key {
                        continue; // this entry's shard didn't actually change
                    }
                    let (sealed, key_etag) = backend.get(&old_key).await?;
                    if key_etag.is_none() {
                        continue; // already moved (or released) by a prior partial run
                    }
                    let plain = cipher.open(&old_key, &sealed)?;
                    let resealed = cipher.seal(&new_key, &plain, crate::cipher::CompressionStrategy::None);
                    // Create-only, idempotent for the same content -- same
                    // reasoning as `Collection::delete`'s own archive step.
                    backend.put_cas(&new_key, resealed, None).await?;
                    delete_object(backend, &old_key).await;
                    moved_any = true;
                }
            }
            if !moved_any {
                settled = true;
                break;
            }
        }
        // Still draining after `MAX_COPY_PASSES` (sustained writes landing
        // on the old layout faster than each pass can move them) -- leave
        // `prev_prefix_bits` set so `resolve()` keeps checking the old
        // layout too, and a later maintenance-triggered `complete_rebalance`
        // call can keep draining it, instead of silently abandoning
        // stragglers by declaring the rebalance done anyway.
        if !settled {
            return Ok(());
        }

        let done = ShardEpoch {
            prev_prefix_bits: None,
            ..epoch
        };
        match put_json(backend, &self.epoch_key(), &done, etag.as_deref(), cipher).await? {
            crate::backend::Cas::Ok => {
                *self.epoch_cache.lock().unwrap() = None;
                Ok(())
            }
            // Someone else already completed (or started another) rebalance
            // -- leave it to them rather than clobbering a newer epoch.
            crate::backend::Cas::Conflict => Ok(()),
        }
    }

    /// Approximate entry count per current shard -- a real `list_prefix`
    /// scan per shard, not a read-back of whatever an external metrics
    /// system happens to have recorded (a `MetricsRecorder` in this crate
    /// is write-only, matching how most real metrics backends work: an app
    /// pushes to Prometheus/StatsD, it doesn't query its own last-pushed
    /// value back). Still reports each shard's count via `metrics.gauge`
    /// for observability, but the trigger decision below is based on the
    /// direct count this method just did, not a round-trip through the
    /// metrics system. This is an O(total entries) operation -- call it
    /// from periodic maintenance, never a request path.
    pub async fn occupancy(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        metrics: &dyn MetricsRecorder,
    ) -> Result<Vec<usize>> {
        let epoch = self.current_epoch(backend, cipher).await?;
        let shard_count = 1u32 << epoch.prefix_bits.min(31);
        let mut counts = Vec::with_capacity(shard_count as usize);
        for shard in 0..shard_count {
            let prefix = self.shard_prefix(shard, epoch.prefix_bits);
            let count = list_all_keys(backend, &prefix).await?.len();
            metrics.gauge(
                &format!("s3db_shard_occupancy{{kind=\"{}\",shard=\"{shard}\"}}", self.kind),
                count as f64,
            );
            counts.push(count);
        }
        Ok(counts)
    }

    /// Automatic trigger for [`Self::begin_rebalance`]: if any shard's
    /// occupancy exceeds `threshold`, starts a rebalance and returns
    /// `true`. Deliberately conservative — call from a periodic
    /// maintenance pass, not a request path (see [`Self::occupancy`]'s own
    /// cost note), and pick `threshold` well above the expected average
    /// (2x is the doc's own suggestion) so noise in an approximate count
    /// doesn't trigger a rebalance nobody needed.
    pub async fn maybe_rebalance(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        metrics: &dyn MetricsRecorder,
        threshold: usize,
    ) -> Result<bool> {
        let epoch = self.current_epoch(backend, cipher).await?;
        if epoch.prev_prefix_bits.is_some() {
            return Ok(false); // already migrating, don't stack another
        }
        if epoch.prefix_bits >= MAX_PREFIX_BITS {
            return Ok(false); // already at the shard ceiling, nothing more to do
        }
        let counts = self.occupancy(backend, cipher, metrics).await?;
        if counts.into_iter().any(|c| c > threshold) {
            self.begin_rebalance(backend, cipher).await?;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
#[path = "../tests/unit/sharded_index.rs"]
mod tests;
