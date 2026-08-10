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
#[path = "../tests/unit/maintenance.rs"]
mod tests;
