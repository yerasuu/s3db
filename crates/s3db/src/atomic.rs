//! An opt-in capability beyond [`Backend`]'s minimal surface: committing
//! several ops (including updates, not just creates) in one real
//! transaction, all-or-nothing. Only a backend with a native transaction can
//! honestly give this — see `docs/s3db-local-mode.md` for why that's
//! [`crate::local::RedbBackend`] and nothing else today. `S3`/`R2`/`Azure`/
//! `Gcs` keep relying on [`crate::txn::run`]'s CAS-sequential protocol
//! (`TxnRecord` + crash recovery), which is the only way to approximate
//! atomicity without a native transaction to lean on.
//!
//! Detected by downcasting `&dyn Backend` (see [`as_atomic`]), not by
//! widening [`Backend`] itself — every backend keeps implementing the same
//! small required surface either way; this is strictly additive for the one
//! backend that can actually back it up.

use crate::backend::Backend;
use crate::cipher::{Cipher, CompressionStrategy};
use crate::collection::Collection;
use crate::index::SecondaryIndex;
use crate::local::LocalBackend;
use anyhow::Result;
use serde::Serialize;

/// One op inside a [`AtomicBackend::commit_batch`] call.
#[derive(Debug, Clone)]
pub enum BatchOp {
    /// Same CAS contract as [`Backend::put_cas`] — `expected_etag: None`
    /// means "must not exist yet" — except every op's condition is checked
    /// *before* any op in the batch is applied, not one at a time. `body` is
    /// already-sealed ciphertext, same as what [`Backend::put_cas`] takes;
    /// this trait doesn't know about [`crate::cipher::Cipher`] any more than
    /// [`Backend`] itself does.
    Put {
        key: String,
        body: Vec<u8>,
        expected_etag: Option<String>,
    },
    /// Unconditional, same best-effort contract as [`Backend::delete`] — no
    /// CAS-delete variant exists because nothing in this crate has needed
    /// one yet (see [`Backend::delete`]'s own doc for why that's fine: a
    /// caller that needs a conditional outcome uses `Put`, never `Delete`,
    /// to enforce it).
    Delete { key: String },
}

/// What [`AtomicBackend::commit_batch`] did — deliberately as coarse as
/// [`crate::backend::Cas`]: a caller that needs to know *which* op
/// conflicted is asking for something this trait doesn't promise, same
/// simplification [`crate::txn::run`] already accepted for its own
/// `Cas::Conflict` (see that module's doc).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchOutcome {
    /// Every op applied, all inside the same underlying transaction.
    Applied,
    /// At least one `Put`'s `expected_etag` didn't match — nothing in the
    /// batch was applied, including ops whose own condition did hold.
    Conflict,
}

/// See the module doc for which backends can honestly implement this and
/// why the rest can't.
#[async_trait::async_trait]
pub trait AtomicBackend: Backend {
    async fn commit_batch(&self, ops: Vec<BatchOp>) -> Result<BatchOutcome>;
}

/// Downcasts `backend` to a concrete type known to implement
/// [`AtomicBackend`] — currently only [`LocalBackend::Redb`]. A `dyn
/// Backend` can't be downcast straight to a trait object of a *different*
/// trait, so this has to name every concrete type that might implement
/// [`AtomicBackend`] explicitly; today there's exactly one. Shared by
/// [`crate::txn::run`] and [`put_with_index`] so the detection logic (and
/// its one limitation) lives in exactly one place.
///
/// Detection is on the concrete type at the top of the `Arc<dyn Backend>`,
/// not on what it might wrap — a `RedbBackend` behind
/// [`crate::cache::CachedBackend`] or another decorator won't be found here,
/// since the decorator itself is what `as_any` returns. That's an accepted
/// limitation, not a bug.
pub(crate) fn as_atomic(backend: &dyn Backend) -> Option<&dyn AtomicBackend> {
    match backend.as_any().downcast_ref::<LocalBackend>()? {
        LocalBackend::Redb(inner) => Some(inner),
        LocalBackend::Files(_) => None,
    }
}

/// Writes one [`Collection`] entry and claims one [`SecondaryIndex`]
/// pointer for it inside a single [`AtomicBackend::commit_batch`] call —
/// `docs/s3db-local-mode.md` phase 5: "row and index entry in the same
/// atomic transaction." Without this, a row write and its index write are
/// two separate [`Backend::put_cas`] calls with an unavoidable window
/// between them where the index points at nothing yet (if the row hasn't
/// landed) or the row exists with no index entry pointing at it yet (if the
/// order is reversed) — a reader can observe either half-applied state. One
/// transaction closes that window entirely: a reader either sees both writes
/// or neither, never one without the other.
///
/// `expected_etag`/`index_expected_etag` follow the same convention as
/// [`Backend::put_cas`] (`None` = "must not exist yet") — this covers both
/// a fresh create and an update of an existing row+pointer pair, unlike
/// [`crate::txn::TxnOp`]'s create-only protocol.
///
/// Returns an error if `backend` doesn't implement [`AtomicBackend`] — there
/// is no meaningful two-step fallback that would still give the atomicity
/// this function exists for; a caller on a backend without this capability
/// has to decide for itself whether a non-atomic two-write fallback is
/// acceptable for its own use case, this function won't silently offer one.
#[allow(clippy::too_many_arguments)]
pub async fn put_with_index<T: Serialize, P: Serialize>(
    backend: &dyn Backend,
    cipher: &Cipher,
    collection: &Collection,
    name: &str,
    value: &T,
    expected_etag: Option<&str>,
    index: &SecondaryIndex,
    index_raw: &str,
    pointer: &P,
    index_expected_etag: Option<&str>,
) -> Result<BatchOutcome> {
    let atomic = as_atomic(backend).ok_or_else(|| {
        anyhow::anyhow!("this backend has no native transaction capability (see docs/s3db-local-mode.md)")
    })?;

    let row_key = collection.key(name);
    let row_plain = rmp_serde::to_vec_named(value)?;
    let row_sealed = cipher.seal(&row_key, &row_plain, CompressionStrategy::None);

    let index_key = index.key(index_raw);
    let index_plain = rmp_serde::to_vec_named(pointer)?;
    let index_sealed = cipher.seal(&index_key, &index_plain, CompressionStrategy::None);

    atomic
        .commit_batch(vec![
            BatchOp::Put {
                key: row_key,
                body: row_sealed,
                expected_etag: expected_etag.map(str::to_string),
            },
            BatchOp::Put {
                key: index_key,
                body: index_sealed,
                expected_etag: index_expected_etag.map(str::to_string),
            },
        ])
        .await
}

#[cfg(test)]
mod tests;
