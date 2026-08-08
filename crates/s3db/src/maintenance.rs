//! One entry point for periodic maintenance across every [`Collection`] an
//! app cares to register, instead of each caller wiring its own background
//! task per collection.
//!
//! Narrower than the consolidation this is modeled on: the original idea
//! was one `scroll` per object evaluating several unrelated conditions at
//! once (migration due? re-encryption due? tombstone expired?) so N
//! separate full scans don't each re-read the same objects. In this crate,
//! that doesn't actually apply yet -- there's no schema-migration system
//! and no per-object key-rotation rescan (`key_rotation`'s dual-read means
//! re-encryption is never forced, so there's no rescan to fuse in), and
//! [`gc::sweep`]'s own tombstone pass and history pass are two genuinely
//! different key namespaces under one collection (`.deleted/` vs
//! `.history/`), not two conditions checked on the same read. What *is*
//! real today: running [`gc::sweep`] over every registered collection from
//! one call, one place to configure retention. If a migration or
//! re-encryption pass is added later, it belongs here too, evaluated
//! alongside GC in the same per-collection pass rather than as its own
//! separate scanner.

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::collection::Collection;
use crate::gc::{self, GcConfig, GcReport};
use anyhow::Result;

pub struct MaintenanceScanner {
    gc_config: GcConfig,
}

impl MaintenanceScanner {
    pub fn new(gc_config: GcConfig) -> Self {
        MaintenanceScanner { gc_config }
    }

    /// Runs [`gc::sweep`] over every collection in `collections`, in order,
    /// returning one [`GcReport`] per collection (same order). A single
    /// collection's sweep failing (a real backend error, not a business
    /// outcome) stops the whole call -- same all-or-nothing simplicity
    /// [`gc::sweep`] itself has; a caller that wants partial-failure
    /// tolerance across collections can call [`gc::sweep`] directly per
    /// collection instead.
    pub async fn run(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        collections: &[&Collection],
    ) -> Result<Vec<GcReport>> {
        let mut reports = Vec::with_capacity(collections.len());
        for collection in collections {
            reports.push(gc::sweep(backend, cipher, collection, &self.gc_config).await?);
        }
        Ok(reports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LocalEngine, LocalParams};
    use crate::local::LocalBackend;
    use std::time::Duration;

    fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
        let backend = LocalBackend::new(&LocalParams {
            bucket: root.to_string_lossy().to_string(),
            engine: LocalEngine::Files,
        });
        let cipher = Cipher::derive("test passphrase", &[29u8; crate::cipher::SALT_LEN]).unwrap();
        (backend, cipher)
    }

    #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Widget {
        count: u32,
    }

    #[tokio::test]
    async fn run_sweeps_every_registered_collection() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let widgets = Collection::new("widgets");
        let gadgets = Collection::new("gadgets");
        widgets
            .put(&backend, &cipher, "a", &Widget { count: 1 }, None)
            .await
            .unwrap();
        widgets.delete(&backend, &cipher, "a").await;
        gadgets
            .put(&backend, &cipher, "b", &Widget { count: 2 }, None)
            .await
            .unwrap();
        gadgets.delete(&backend, &cipher, "b").await;

        let scanner = MaintenanceScanner::new(GcConfig {
            tombstone_purge_age: Duration::ZERO,
            ..GcConfig::default()
        });
        let reports = scanner.run(&backend, &cipher, &[&widgets, &gadgets]).await.unwrap();

        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].tombstones_forgotten, 1);
        assert_eq!(reports[1].tombstones_forgotten, 1);
    }
}
