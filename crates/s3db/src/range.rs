//! An opt-in capability beyond [`Backend`]'s minimal surface: a genuine
//! ordered range scan over stored keys, not a full [`Backend::list_prefix`]
//! listing filtered and sorted afterward. Only a backend with a real
//! ordered structure underneath can honestly give this — see
//! `docs/s3db-local-mode.md` for why that's [`crate::local::RedbBackend`]
//! (a B-tree, ordered by construction) and nothing else today. `S3`/`R2`/
//! `Azure`/`Gcs`/`Files` have no such structure to lean on; the LSM design
//! in `docs/s3db-fulldb-roadmap.md` is what eventually gives S3-compatible
//! backends a real range primitive of their own (`Backend::get_range` over
//! sorted SSTable blocks), a different mechanism for a different substrate.
//!
//! Detected the same way as [`crate::atomic::AtomicBackend`]: downcasting
//! `&dyn Backend` (see [`crate::index::SecondaryIndex::resolve_range`]'s
//! detection helper), not by widening [`Backend`] itself.

use crate::backend::Backend;
use anyhow::Result;

/// See the module doc for which backends can honestly implement this.
#[async_trait::async_trait]
pub trait RangeBackend: Backend {
    /// Every `(key, body)` pair with `start_key <= key < end_key`, in
    /// ascending key order. `body` is whatever [`Backend::get`] would
    /// return for that key — already-sealed ciphertext, this trait doesn't
    /// know about [`crate::cipher::Cipher`] any more than [`Backend`] itself
    /// does.
    async fn range(&self, start_key: &str, end_key: &str) -> Result<Vec<(String, Vec<u8>)>>;
}
