//! Multi-backend routing at the manifest level — `docs/s3db-fulldb-roadmap.md`
//! phase 6. Every [`Table`] already IS a manifest plus its own set of
//! SSTables under one `root` prefix in one [`Backend`]; [`TableLocation`]
//! just names *which* backend a given table lives in, and
//! [`BackendRegistry`] is the lookup from that name to the actual
//! `Arc<dyn Backend>`. Deliberately no new routing layer: the manifest was
//! already the thing that answers "who owns what," so this routes at the
//! same place, not a parallel one.

use super::table::TableConfig;
use crate::backend::Backend;
use crate::cipher::Cipher;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

/// The default a [`TableLocation`] resolves to when no other backend was
/// ever registered — the common single-backend deployment never has to
/// think about this at all.
pub const DEFAULT_BACKEND_ID: &str = "primary";

/// Which backend a table lives in, and its root prefix within it. Two
/// tables can share a `root` string across two different `backend_id`s
/// without colliding (they're different buckets/prefixes entirely), the
/// same way two tables already don't collide sharing one backend with
/// different `root`s (see `Table`'s own module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableLocation {
    pub backend_id: &'static str,
    pub root: String,
}

impl TableLocation {
    /// A table on [`DEFAULT_BACKEND_ID`] — the right choice unless this
    /// deployment genuinely spreads tables across more than one backend.
    pub fn new(root: impl Into<String>) -> Self {
        TableLocation {
            backend_id: DEFAULT_BACKEND_ID,
            root: root.into(),
        }
    }

    pub fn with_backend_id(mut self, backend_id: &'static str) -> Self {
        self.backend_id = backend_id;
        self
    }
}

/// A name -> `Arc<dyn Backend>` lookup, built once at startup and shared by
/// every [`Table`]/[`super::SecondaryLsmIndex`] this process opens. Not a
/// [`Backend`] itself and not meant to be one -- it never sees a request,
/// it only decides which already-constructed backend a [`TableLocation`]
/// means.
#[derive(Default)]
pub struct BackendRegistry {
    backends: HashMap<&'static str, Arc<dyn Backend>>,
}

impl BackendRegistry {
    pub fn new() -> Self {
        BackendRegistry::default()
    }

    /// Registers `backend` under `id`, replacing whatever (if anything)
    /// was there before -- useful for a test or a hot-reconfigure to swap
    /// one backend for another without rebuilding the whole registry.
    pub fn register(&mut self, id: &'static str, backend: Arc<dyn Backend>) -> &mut Self {
        self.backends.insert(id, backend);
        self
    }

    pub fn resolve(&self, location: &TableLocation) -> Result<Arc<dyn Backend>> {
        self.backends
            .get(location.backend_id)
            .cloned()
            .with_context(|| format!("no backend registered under id {:?}", location.backend_id))
    }

    /// Builds the [`TableConfig`] a [`super::Table::open`]/[`super::SecondaryLsmIndex::open`]
    /// call needs, by resolving `location`'s backend and plugging in
    /// `location.root` -- the one place that actually turns "which backend
    /// and root" into something [`Table`] can open, so a caller never has
    /// to know [`TableConfig`]'s other fields just to route a table.
    pub fn table_config(&self, location: &TableLocation, cipher: Cipher, wal_path: PathBuf) -> Result<TableConfig> {
        let backend = self.resolve(location)?;
        Ok(TableConfig::new(backend, cipher, location.root.clone(), wal_path))
    }
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/location.rs"]
mod tests;
