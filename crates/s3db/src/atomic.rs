//! An opt-in capability beyond [`Backend`]'s minimal surface: committing
//! several ops (including updates, not just creates) in one real
//! transaction, all-or-nothing. Only a backend with a native transaction can
//! honestly give this — see `docs/s3db-local-mode.md` for why that's
//! [`crate::local::RedbBackend`] and nothing else today. `S3`/`R2`/`Azure`/
//! `Gcs` keep relying on [`crate::txn::run`]'s CAS-sequential protocol
//! (`TxnRecord` + crash recovery), which is the only way to approximate
//! atomicity without a native transaction to lean on.
//!
//! Detected by downcasting `&dyn Backend` (see [`crate::txn::run`]'s own
//! detection helper), not by widening [`Backend`] itself — every backend
//! keeps implementing the same small required surface either way; this is
//! strictly additive for the one backend that can actually back it up.

use crate::backend::Backend;
use anyhow::Result;

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
