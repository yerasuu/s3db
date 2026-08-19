//! One entry point for periodic maintenance across every [`Collection`] an
//! app cares to register, instead of each caller wiring its own background
//! task per collection.
//!
//! Narrower than the consolidation this is modeled on: the original idea
//! was one `scroll` per object evaluating several unrelated conditions at
//! once (migration due? re-encryption due? tombstone expired?) so N
//! separate full scans don't each re-read the same objects. That still
//! doesn't apply here, and for a reason worth keeping straight: the passes
//! this runs live in *different key namespaces* under a collection --
//! [`gc::sweep`]'s `.deleted/` and `.history/`, [`ttl::expire_due`]'s
//! `.expiry/` -- so they are separate scans by construction, not several
//! conditions checked against one read. (There's still no per-object
//! key-rotation rescan to fuse in either: `key_rotation`'s dual-read means
//! re-encryption is never forced. And [`crate::migrate`] is a one-shot
//! rewrite driven by a version, not a recurring pass, so it belongs in a
//! deploy step rather than in here.)
//!
//! What this does consolidate: every recurring per-collection pass, over
//! every registered collection, from one call with one config.

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::collection::Collection;
use crate::gc::{self, GcConfig, GcReport};
use crate::ttl::{self, ExpiryConfig, ExpiryReport};
use anyhow::Result;

/// One collection's maintenance outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaintenanceReport {
    pub gc: GcReport,
    pub expiry: ExpiryReport,
}

pub struct MaintenanceScanner {
    gc_config: GcConfig,
    expiry_config: ExpiryConfig,
}

impl MaintenanceScanner {
    pub fn new(gc_config: GcConfig) -> Self {
        MaintenanceScanner {
            gc_config,
            expiry_config: ExpiryConfig::default(),
        }
    }

    /// How the expiry pass removes an entry whose deadline has passed --
    /// hard by default, see [`ExpiryConfig::soft`].
    pub fn with_expiry_config(mut self, expiry_config: ExpiryConfig) -> Self {
        self.expiry_config = expiry_config;
        self
    }

    /// Runs every recurring pass over every collection in `collections`, in
    /// order, returning one [`MaintenanceReport`] per collection (same
    /// order). A single collection's pass failing (a real backend error, not
    /// a business outcome) stops the whole call -- same all-or-nothing
    /// simplicity [`gc::sweep`] itself has; a caller that wants
    /// partial-failure tolerance across collections can call the individual
    /// passes directly per collection instead.
    ///
    /// Expiry runs before GC on purpose: a hard expiry leaves nothing for GC
    /// to do, but a *soft* one writes a tombstone, and running GC afterwards
    /// gives that tombstone's own purge retry a chance in the same sweep
    /// rather than one interval later.
    pub async fn run(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        collections: &[&Collection],
    ) -> Result<Vec<MaintenanceReport>> {
        let now = ttl::now_ms();
        let mut reports = Vec::with_capacity(collections.len());
        for collection in collections {
            let expiry = ttl::expire_due(backend, cipher, collection, now, &self.expiry_config).await?;
            let gc = gc::sweep(backend, cipher, collection, &self.gc_config).await?;
            reports.push(MaintenanceReport { gc, expiry });
        }
        Ok(reports)
    }
}

#[cfg(test)]
#[path = "../tests/unit/maintenance.rs"]
mod tests;
