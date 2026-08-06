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
    async fn current_epoch(&self, backend: &dyn Backend, cipher: &Cipher) -> Result<ShardEpoch> {
        if let Some((fetched_at, epoch)) = *self.epoch_cache.lock().unwrap()
            && fetched_at.elapsed() < self.epoch_cache_ttl
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
        epoch.prev_prefix_bits = Some(epoch.prefix_bits);
        epoch.prefix_bits = epoch.prefix_bits.saturating_add(1).min(31);
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
            }
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
        let counts = self.occupancy(backend, cipher, metrics).await?;
        if counts.into_iter().any(|c| c > threshold) {
            self.begin_rebalance(backend, cipher).await?;
            return Ok(true);
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LocalParams;
    use crate::local::LocalBackend;
    use crate::metrics::NoopMetrics;

    fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
        let backend = LocalBackend::new(&LocalParams {
            bucket: root.to_string_lossy().to_string(),
        });
        let cipher = Cipher::derive("test passphrase", &[13u8; crate::cipher::SALT_LEN]).unwrap();
        (backend, cipher)
    }

    #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Pointer {
        owner: String,
    }

    #[tokio::test]
    async fn claim_then_resolve_roundtrips_with_no_rebalance() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = ShardedIndex::new(".conf/index", "pubkey", Segment::Base64);
        assert!(
            idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() })
                .await
                .unwrap()
        );
        let (resolved, _etag) = idx.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
        assert_eq!(resolved, Some(Pointer { owner: "alice".into() }));
    }

    #[tokio::test]
    async fn rebalance_keeps_every_entry_resolvable_throughout() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);

        let names: Vec<String> = (0..50).map(|i| format!("user-{i}")).collect();
        for name in &names {
            assert!(
                idx.claim_once(&backend, &cipher, name, &Pointer { owner: name.clone() })
                    .await
                    .unwrap()
            );
        }

        idx.begin_rebalance(&backend, &cipher).await.unwrap();
        // Mid-rebalance: every entry (still under the old layout) must
        // still resolve.
        for name in &names {
            let (resolved, _) = idx.resolve::<Pointer>(&backend, &cipher, name).await.unwrap();
            assert_eq!(
                resolved,
                Some(Pointer { owner: name.clone() }),
                "{name} must resolve mid-rebalance"
            );
        }
        // And a claim on a brand-new name during the rebalance must still
        // land on the OLD layout (writers pinned until complete_rebalance).
        assert!(
            idx.claim_once(
                &backend,
                &cipher,
                "new-during-rebalance",
                &Pointer { owner: "x".into() }
            )
            .await
            .unwrap()
        );

        idx.complete_rebalance(&backend, &cipher).await.unwrap();
        for name in &names {
            let (resolved, _) = idx.resolve::<Pointer>(&backend, &cipher, name).await.unwrap();
            assert_eq!(
                resolved,
                Some(Pointer { owner: name.clone() }),
                "{name} must resolve after rebalance completes"
            );
        }
        let (resolved, _) = idx
            .resolve::<Pointer>(&backend, &cipher, "new-during-rebalance")
            .await
            .unwrap();
        assert_eq!(resolved, Some(Pointer { owner: "x".into() }));

        // No rebalance left in flight.
        let (epoch, _) = get_json::<ShardEpoch>(&backend, &idx.epoch_key(), &cipher)
            .await
            .unwrap();
        assert!(epoch.prev_prefix_bits.is_none());
    }

    #[tokio::test]
    async fn begin_rebalance_refuses_to_stack_a_second_one() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);
        idx.begin_rebalance(&backend, &cipher).await.unwrap();
        assert!(idx.begin_rebalance(&backend, &cipher).await.is_err());
    }

    #[tokio::test]
    async fn release_removes_the_entry_from_whichever_layout_it_is_in() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);
        idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() })
            .await
            .unwrap();
        idx.release(&backend, &cipher, "alice").await;
        let (resolved, _) = idx.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
        assert_eq!(resolved, None);
    }

    #[tokio::test]
    async fn maybe_rebalance_triggers_once_a_shard_crosses_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);
        for i in 0..20 {
            idx.claim_once(&backend, &cipher, &format!("user-{i}"), &Pointer { owner: "x".into() })
                .await
                .unwrap();
        }
        let triggered = idx.maybe_rebalance(&backend, &cipher, &NoopMetrics, 10).await.unwrap();
        assert!(triggered);
        let (epoch, _) = get_json::<ShardEpoch>(&backend, &idx.epoch_key(), &cipher)
            .await
            .unwrap();
        assert!(epoch.prev_prefix_bits.is_some());
    }

    #[tokio::test]
    async fn maybe_rebalance_stays_put_under_the_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);
        idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "x".into() })
            .await
            .unwrap();
        let triggered = idx
            .maybe_rebalance(&backend, &cipher, &NoopMetrics, 1000)
            .await
            .unwrap();
        assert!(!triggered);
    }
}
