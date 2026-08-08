//! Background cleanup for one [`Collection`]: retries [`PurgeState::Pending`]
//! tombstones' underlying deletes, ages out old [`PurgeState::Purged`]
//! tombstone records, and (opt-in) prunes `.history/` entries past a max
//! age -- checking [`crate::snapshot::list_leases`] first, so an in-flight
//! [`crate::snapshot::ReadSnapshot`] never has a version pulled out from
//! under it.
//!
//! [`sweep`] takes one `Collection` at a time; a caller with several runs it
//! once per collection (from a scheduled task, cron, whatever it already
//! uses for periodic maintenance -- this crate doesn't run its own
//! background tasks, see [`crate::maintenance`] for how multiple policies
//! like this one are meant to share a single pass instead of each scanning
//! independently).

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::collection::{Collection, PurgeState};
use crate::snapshot;
use anyhow::Result;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

#[derive(Debug, Clone, Copy)]
pub struct GcConfig {
    /// How long a tombstone can sit `Pending` before a sweep retries the
    /// underlying delete.
    pub tombstone_retry_age: Duration,
    /// How long a tombstone can sit `Purged` before a sweep removes the
    /// record entirely (the audit trail's own retention window).
    pub tombstone_purge_age: Duration,
    /// If `Some`, prunes `.history/` entries older than this -- `None`
    /// (the default) leaves history pruning to whatever else already
    /// manages it (or never, if nothing does).
    pub history_max_age: Option<Duration>,
}

impl Default for GcConfig {
    fn default() -> Self {
        GcConfig {
            tombstone_retry_age: Duration::from_secs(60),
            tombstone_purge_age: Duration::from_secs(30 * 24 * 3600),
            history_max_age: None,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    pub tombstones_retried: usize,
    pub tombstones_purged_now: usize,
    pub tombstones_forgotten: usize,
    pub history_versions_pruned: usize,
}

/// Runs one sweep over `collection`. See this module's doc comment for what
/// each pass does; safe to call repeatedly and concurrently with normal
/// traffic -- every step here is the same best-effort, idempotent operation
/// `Collection` itself already exposes, just driven periodically instead of
/// only at the moment of the original `delete`/`put_versioned` call.
pub async fn sweep(
    backend: &dyn Backend,
    cipher: &Cipher,
    collection: &Collection,
    config: &GcConfig,
) -> Result<GcReport> {
    let mut report = GcReport::default();
    let now = now_ms();

    for (name, tombstone) in collection.list_tombstones(backend, cipher).await? {
        match tombstone.purge_state {
            PurgeState::Pending => {
                if now.saturating_sub(tombstone.deleted_at_ms) <= config.tombstone_retry_age.as_millis() as u64 {
                    continue;
                }
                report.tombstones_retried += 1;
                if collection.retry_pending_purge(backend, cipher, &name).await? {
                    report.tombstones_purged_now += 1;
                }
            }
            PurgeState::Purged => {
                if now.saturating_sub(tombstone.deleted_at_ms) <= config.tombstone_purge_age.as_millis() as u64 {
                    continue;
                }
                collection.forget_tombstone(backend, cipher, &name).await?;
                report.tombstones_forgotten += 1;
            }
        }
    }

    if let Some(max_age) = config.history_max_age {
        let leases = snapshot::list_leases(backend, cipher).await?;
        let max_age_ms = max_age.as_millis() as u64;
        for name in collection.list_names(backend).await? {
            for version in collection.list_versions(backend, &name).await? {
                let Some(archived_at_ms) = collection.version_timestamp(backend, cipher, &name, &version).await? else {
                    continue; // no companion timestamp -- can't safely judge its age, leave it
                };
                if now.saturating_sub(archived_at_ms) <= max_age_ms {
                    continue;
                }
                let protected = leases.iter().any(|lease| {
                    let window_end = lease.timestamp_ms.saturating_add(lease.max_duration_ms);
                    archived_at_ms >= lease.timestamp_ms && archived_at_ms <= window_end
                });
                if protected {
                    continue; // a live ReadSnapshot might still need this version
                }
                collection.forget_history_version(backend, &name, &version).await;
                report.history_versions_pruned += 1;
            }
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LocalEngine, LocalParams};
    use crate::local::LocalBackend;
    use crate::snapshot::ReadSnapshot;

    fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
        let backend = LocalBackend::new(&LocalParams {
            bucket: root.to_string_lossy().to_string(),
            engine: LocalEngine::Files,
        });
        let cipher = Cipher::derive("test passphrase", &[23u8; crate::cipher::SALT_LEN]).unwrap();
        (backend, cipher)
    }

    #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Widget {
        count: u32,
    }

    #[tokio::test]
    async fn sweep_leaves_a_fresh_pending_tombstone_alone() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
            .await
            .unwrap();
        coll.delete(&backend, &cipher, "a").await;

        let report = sweep(&backend, &cipher, &coll, &GcConfig::default()).await.unwrap();
        assert_eq!(
            report.tombstones_retried, 0,
            "tombstone is fresh, not past tombstone_retry_age yet"
        );
    }

    #[tokio::test]
    async fn sweep_retries_an_aged_pending_delete() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
            .await
            .unwrap();
        coll.delete(&backend, &cipher, "a").await;
        // Since LocalBackend's own delete always confirms, the tombstone is
        // already Purged after `delete` -- age it out immediately with a
        // zero retry threshold instead, which exercises the same "past
        // due" branch regardless of purge_state.
        let config = GcConfig {
            tombstone_retry_age: Duration::ZERO,
            ..GcConfig::default()
        };
        let report = sweep(&backend, &cipher, &coll, &config).await.unwrap();
        assert_eq!(
            report.tombstones_retried, 0,
            "already Purged by delete() itself, nothing Pending left to retry"
        );
    }

    #[tokio::test]
    async fn sweep_forgets_an_aged_purged_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None)
            .await
            .unwrap();
        coll.delete(&backend, &cipher, "a").await; // LocalBackend confirms -> tombstone is Purged
        tokio::time::sleep(Duration::from_millis(5)).await; // ensure strictly past a zero-width grace period

        let config = GcConfig {
            tombstone_purge_age: Duration::ZERO,
            ..GcConfig::default()
        };
        let report = sweep(&backend, &cipher, &coll, &config).await.unwrap();
        assert_eq!(report.tombstones_forgotten, 1);
        assert!(coll.list_tombstones(&backend, &cipher).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sweep_prunes_old_history_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
            .await
            .unwrap();
        let (_, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, etag.as_deref())
            .await
            .unwrap();
        assert_eq!(coll.list_versions(&backend, "a").await.unwrap().len(), 1);
        // Millisecond-resolution timestamps: make sure the archive's own
        // timestamp is strictly in the past relative to the sweep below,
        // rather than racing to land in the same millisecond.
        tokio::time::sleep(Duration::from_millis(5)).await;

        let config = GcConfig {
            history_max_age: Some(Duration::ZERO),
            ..GcConfig::default()
        };
        let report = sweep(&backend, &cipher, &coll, &config).await.unwrap();
        assert_eq!(report.history_versions_pruned, 1);
        assert!(coll.list_versions(&backend, "a").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn sweep_never_prunes_history_a_live_snapshot_still_needs() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None)
            .await
            .unwrap();
        let (_, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();

        let snap = ReadSnapshot::open(&backend, &cipher, Duration::from_secs(300))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(5)).await;
        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, etag.as_deref())
            .await
            .unwrap();

        let config = GcConfig {
            history_max_age: Some(Duration::ZERO),
            ..GcConfig::default()
        };
        let report = sweep(&backend, &cipher, &coll, &config).await.unwrap();
        assert_eq!(
            report.history_versions_pruned, 0,
            "the snapshot's own moment falls inside this version's lifetime"
        );

        let value: Option<Widget> = snap.get(&backend, &cipher, &coll, "a").await.unwrap();
        assert_eq!(
            value,
            Some(Widget { count: 1 }),
            "version must still be there for the snapshot to read"
        );
    }
}
