//! [`Backend`] over local storage, no external provider at all — two
//! interchangeable on-disk representations selected by
//! [`LocalParams::engine`], everything above [`Backend`] blind to which one
//! is in play (same "swapping drivers changes nothing above this line"
//! guarantee every other backend gives).
//!
//! - [`files`] — one real file per key, CAS emulated with `flock` +
//!   a version-counter sidecar. The long-standing default; every directory
//!   that predates [`LocalEngine`] is one of these.
//! - [`redb_backend`] — a single `redb` database file, real ACID
//!   transactions instead of hand-rolled locking. See
//!   `docs/s3db-local-mode.md` for why local mode gets a second engine at
//!   all: none of the constraints that justify the S3-compatible drivers'
//!   design (per-request billing, no byte-range, no native transaction)
//!   apply to a filesystem this process already owns outright.
//!
//! Not additive: a directory is entirely one engine or the other. Changing
//! it on a directory that already has data needs an explicit migration
//! tool, not just flipping the config field — see `s3db-local-migrate`.

mod files;
mod redb_backend;

use crate::backend::{Backend, Cas, DeleteOutcome};
use crate::config::{LocalEngine, LocalParams};
use anyhow::Result;
#[cfg(feature = "streaming")]
use std::path::Path;

pub use files::FilesBackend;
pub use redb_backend::RedbBackend;

/// Picks [`LocalParams::engine`]'s implementation and forwards every
/// [`Backend`] call to it. A thin dispatcher, not a third implementation —
/// all the real logic lives in [`files`]/[`redb_backend`].
#[derive(Debug)]
pub enum LocalBackend {
    Files(FilesBackend),
    Redb(RedbBackend),
}

impl LocalBackend {
    pub fn new(cfg: &LocalParams) -> Self {
        match cfg.engine {
            LocalEngine::Files => LocalBackend::Files(FilesBackend::new(cfg)),
            LocalEngine::Redb => LocalBackend::Redb(RedbBackend::new(cfg)),
        }
    }

    fn inner(&self) -> &dyn Backend {
        match self {
            LocalBackend::Files(b) => b,
            LocalBackend::Redb(b) => b,
        }
    }
}

#[async_trait::async_trait]
impl Backend for LocalBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.inner().get(key).await
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        self.inner().put_cas(key, body, expected_etag).await
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        self.inner().delete(key).await
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        self.inner().delete_many(keys).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner().list_prefix(prefix).await
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        self.inner().put_stream(key, source).await
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        self.inner().get_stream(key, dest).await
    }
}

#[cfg(test)]
mod tests;
