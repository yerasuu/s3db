//! Create-only multi-key transactions: applies a batch of independent
//! CAS-create writes so either every key ends up created, or none do,
//! surviving a process crash mid-transaction.
//!
//! Deliberately narrow: every op's `expected_etag` is implicitly `None` (no
//! updates in this version). That's what makes the CAS-sequential protocol
//! below simple -- because every write is a create, the target object *is*
//! its own lock: whoever's `put_cas` lands first owns that key, permanently,
//! with no window for someone else to later steal it out from under a live
//! holder. There's no staleness/liveness protocol here (unlike, say, a lock
//! that can be released and re-acquired) because none is needed; that
//! complexity only shows up once updates are in scope.
//!
//! That protocol is a real transaction only in the sense that it recovers
//! from a crash partway through — durable record, sweep, rollback. On a
//! backend with a native transaction (see [`crate::atomic::AtomicBackend`],
//! today only [`crate::local::RedbBackend`]), none of that machinery is
//! needed at all: [`as_atomic`] detects the capability and [`run`]/
//! [`run_with_publisher`] commit the whole batch as one real transaction
//! instead, skipping the durable record, the crash-recovery sweep, and the
//! whole `.conf/txn/` bookkeeping trail. `TxnOp` itself stays create-only
//! either way — a caller that specifically wants an atomic *update* batch
//! calls [`crate::atomic::AtomicBackend::commit_batch`] directly.

use crate::atomic::{AtomicBackend, BatchOp, BatchOutcome, as_atomic};
use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy};
use crate::payload::{delete_object, get_json, list_all_keys, put_json};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where in-flight transaction records live -- deliberately under `.conf/`,
/// alongside every other piece of server-side bookkeeping, never inside a
/// repo's own storage prefix.
const TXN_PREFIX: &str = ".conf/txn";

/// One create-only write inside a [`run`] batch. `value` is already a
/// `serde_json::Value` (not generic `T`) so a batch can freely mix ops for
/// different concrete types -- `TxnRecord` itself has to serialize the whole
/// `Vec<TxnOp>` as one JSON document, which a generic `T` couldn't do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxnOp {
    pub key: String,
    pub value: serde_json::Value,
}

impl TxnOp {
    pub fn create<T: Serialize>(key: String, value: &T) -> Result<Self> {
        Ok(TxnOp {
            key,
            value: serde_json::to_value(value)?,
        })
    }
}

/// One committed write, published through a [`ChangePublisher`] -- see
/// [`run_with_publisher`] for exactly when (never before every op in the
/// same transaction is confirmed committed).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChangeEvent {
    pub key: String,
    pub value: serde_json::Value,
}

/// Where [`run_with_publisher`] sends each [`ChangeEvent`] -- a search
/// index, a webhook dispatcher, a replica feed. Fire-and-forget from
/// `run_with_publisher`'s own perspective: nothing about a transaction's
/// own success/failure depends on whether a subscriber's `published` calls
/// actually land anywhere, same "the caller who wanted delivery guarantees
/// already got them from the CAS commit itself" reasoning as everything
/// else best-effort in this crate.
#[async_trait::async_trait]
pub trait ChangePublisher: Send + Sync + std::fmt::Debug {
    async fn published(&self, event: ChangeEvent);
}

/// The default for [`run`] -- discards every event, so a caller that
/// doesn't care about change notifications never has to think about this
/// at all.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopChangePublisher;

#[async_trait::async_trait]
impl ChangePublisher for NoopChangePublisher {
    async fn published(&self, _event: ChangeEvent) {}
}

/// `Preparing`: ops may or may not all be applied yet -- [`recover_stale`]
/// only ever touches records in this state. `Committed`: every op landed;
/// the record is deleted right after reaching this state, so in practice
/// this value is only ever observed transiently, if at all. `Aborting`:
/// [`recover_stale`] has claimed ownership of a stale `Preparing` record and
/// is (or already did) roll it back -- this is what stops the original
/// `run` call, if it's actually still alive and slow rather than dead, from
/// also trying to commit the same record out from under the sweep.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
enum TxnStatus {
    #[default]
    Preparing,
    Committed,
    Aborting,
}

/// Durable record of one in-flight transaction, at `.conf/txn/<txn_id>.json`.
/// `Default` only exists to satisfy [`get_json`]'s `T: DeserializeOwned +
/// Default` bound for the "doesn't exist yet" case -- every real caller here
/// checks the returned etag for existence, never branches on a
/// `Default`-constructed record's `status`, so `TxnStatus`'s default variant
/// is an implementation detail, not something anyone needs to reason about.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TxnRecord {
    txn_id: String,
    status: TxnStatus,
    started_at_ms: u64,
    ops: Vec<TxnOp>,
}

fn txn_key(txn_id: &str) -> String {
    format!("{TXN_PREFIX}/{txn_id}.json")
}

/// Real wall-clock time, not a deterministic-replay clock: this is only ever
/// compared against `max_age` on this same process's later wall-clock time,
/// never persisted anywhere that needs reproducibility.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

/// 128 bits from the system RNG, lowercase hex -- same technique
/// [`crate::bootstrap::random_salt`] already uses for the encryption salt.
fn random_txn_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating transaction id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The [`AtomicBackend`] fast path for [`run_with_publisher`] — one real
/// commit, no durable record, no rollback bookkeeping, because the backend
/// itself already gives all-or-nothing.
async fn run_atomic(
    atomic: &dyn AtomicBackend,
    cipher: &Cipher,
    ops: Vec<TxnOp>,
    publisher: &dyn ChangePublisher,
) -> Result<Cas> {
    let mut batch = Vec::with_capacity(ops.len());
    for op in &ops {
        // Same wire format as the CAS-sequential path below and as
        // `payload::put_json` -- a `Collection`/entity reads this back
        // through `get_json`/`Collection::get` either way, so the two
        // protocols must produce byte-identical objects.
        let plain = rmp_serde::to_vec_named(&op.value)?;
        let sealed = cipher.seal(&op.key, &plain, CompressionStrategy::None)?;
        batch.push(BatchOp::Put {
            key: op.key.clone(),
            body: sealed,
            expected_etag: None, // TxnOp is create-only; see the module doc.
        });
    }
    match atomic.commit_batch(batch).await? {
        BatchOutcome::Applied => {
            for op in ops {
                publisher
                    .published(ChangeEvent {
                        key: op.key,
                        value: op.value,
                    })
                    .await;
            }
            Ok(Cas::Ok)
        }
        BatchOutcome::Conflict => Ok(Cas::Conflict),
    }
}

/// Applies `ops` atomically: every key ends up created, or none do.
pub async fn run(backend: &dyn Backend, cipher: &Cipher, ops: Vec<TxnOp>) -> Result<Cas> {
    run_with_publisher(backend, cipher, ops, &NoopChangePublisher).await
}

/// Same as [`run`], but publishes a [`ChangeEvent`] per op through
/// `publisher` -- **all of them together, once, after the record reaches
/// `Committed`**, never one at a time as each op's own `put_cas` lands. A
/// consumer (a search index, webhook, replica) that saw events as they
/// applied could observe some of a transaction's writes before knowing
/// whether the whole thing actually committed -- if the last op then
/// genuinely conflicted and everything rolled back, that consumer would
/// have already reacted to writes that no longer exist, with no
/// compensating event telling it so. If the transaction aborts,
/// `pending_events` is simply dropped: nothing was published, because
/// nothing was committed.
pub async fn run_with_publisher(
    backend: &dyn Backend,
    cipher: &Cipher,
    mut ops: Vec<TxnOp>,
    publisher: &dyn ChangePublisher,
) -> Result<Cas> {
    // A native transaction makes everything below unnecessary -- see
    // `as_atomic`'s doc for exactly which backends this applies to.
    if let Some(atomic) = as_atomic(backend) {
        return run_atomic(atomic, cipher, ops, publisher).await;
    }

    // Sorting first means any two transactions racing over an overlapping
    // key set always hit their first shared key in the same order -- one of
    // them deterministically loses there, so there's never a cycle where
    // each is waiting on a key the other already grabbed. Only needed for
    // the CAS-sequential protocol below; `run_atomic`'s single transaction
    // has no such ordering hazard.
    ops.sort_by(|a, b| a.key.cmp(&b.key));

    let txn_id = random_txn_id()?;
    let record_key = txn_key(&txn_id);
    let record = TxnRecord {
        txn_id: txn_id.clone(),
        status: TxnStatus::Preparing,
        started_at_ms: now_ms(),
        ops: ops.clone(),
    };
    match put_json(backend, &record_key, &record, None, cipher).await? {
        Cas::Ok => {}
        // A random 128-bit id colliding with another in-flight transaction
        // is astronomically unlikely -- not worth a retry-with-new-id loop.
        Cas::Conflict => bail!("transaction id collision on {txn_id} (should never happen)"),
    }
    // `put_cas`/`put_json` only ever return `Cas`, never the etag of what
    // they just wrote -- this extra read is what step 4 below needs to
    // CAS the record from `Preparing` to `Committed`.
    let (_, record_etag) = get_json::<TxnRecord>(backend, &record_key, cipher).await?;

    let mut pending_events = Vec::with_capacity(ops.len());
    for op in &ops {
        // MessagePack, not JSON -- matches `payload::put_json`'s wire format,
        // since a `Collection`/entity elsewhere in the app reads this exact
        // key back through `get_json`/`Collection::get`.
        let plain = rmp_serde::to_vec_named(&op.value)?;
        let sealed = cipher.seal(&op.key, &plain, CompressionStrategy::None)?;
        match backend.put_cas(&op.key, sealed, None).await? {
            Cas::Ok => {
                pending_events.push(ChangeEvent {
                    key: op.key.clone(),
                    value: op.value.clone(),
                });
                continue;
            }
            Cas::Conflict => {
                let (existing_sealed, existing_etag) = backend.get(&op.key).await?;
                let is_ours = if existing_etag.is_some() {
                    let existing_plain = cipher.open(&op.key, &existing_sealed)?;
                    let existing_value: serde_json::Value = rmp_serde::from_slice(&existing_plain)?;
                    existing_value == op.value
                } else {
                    false
                };
                if is_ours {
                    // Our own prior attempt at this exact transaction,
                    // re-running after a crash between this op and the next.
                    // Its event was already published by that prior attempt
                    // if the record ever reached Committed, or never should
                    // be if it didn't -- either way, not appended again here.
                    continue;
                }
                // A genuinely different write got there first -- undo
                // whatever this attempt already created and give up.
                rollback(backend, cipher, &record).await?;
                return Ok(Cas::Conflict);
            }
        }
    }

    let committed = TxnRecord {
        status: TxnStatus::Committed,
        ..record
    };
    match put_json(backend, &record_key, &committed, record_etag.as_deref(), cipher).await? {
        Cas::Ok => {
            delete_object(backend, &record_key).await;
            for event in pending_events {
                publisher.published(event).await; // fire-and-forget, already committed
            }
            Ok(Cas::Ok)
        }
        // The record's etag moved out from under us since step 2's read --
        // the only thing that can do that is `recover_stale` flipping it to
        // `Aborting`, meaning it already decided this transaction was dead
        // and is (or just did) roll it back. Doing so ourselves too is safe:
        // rollback only ever deletes a key if its content still matches
        // this transaction's own op, so a second pass over the same ops is
        // a no-op wherever the sweep's pass already ran. `pending_events` is
        // dropped, unpublished -- this transaction never reached Committed.
        Cas::Conflict => {
            rollback(backend, cipher, &committed).await?;
            Ok(Cas::Conflict)
        }
    }
}

/// Undoes whatever `record`'s ops actually got applied, then removes the
/// record itself. Idempotent, and safe to call more than once concurrently
/// (from [`run`] and [`recover_stale`] both) -- every delete is gated on the
/// current content still matching exactly what this transaction wrote.
async fn rollback(backend: &dyn Backend, cipher: &Cipher, record: &TxnRecord) -> Result<()> {
    for op in &record.ops {
        let (sealed, etag) = backend.get(&op.key).await?;
        if etag.is_none() {
            continue; // never got created (or something already cleaned it up)
        }
        let plain = cipher.open(&op.key, &sealed)?;
        let value: serde_json::Value = rmp_serde::from_slice(&plain)?;
        if value == op.value {
            delete_object(backend, &op.key).await;
        }
        // Else: something else legitimately claimed this key after this
        // transaction gave up on it -- never blind-delete on a mismatch,
        // that would destroy someone else's real data.
    }
    delete_object(backend, &txn_key(&record.txn_id)).await;
    Ok(())
}

/// Sweeps `.conf/txn/` for transactions that have been `Preparing` for
/// longer than `max_age` and rolls them back -- the recovery path for a
/// process that crashed mid-[`run`] and never got to either commit or abort
/// its own record. Returns how many this call actually rolled back.
pub async fn recover_stale(backend: &dyn Backend, cipher: &Cipher, max_age: Duration) -> Result<usize> {
    let keys = list_all_keys(backend, &format!("{TXN_PREFIX}/")).await?;
    let cutoff_ms = max_age.as_millis() as u64;
    let now = now_ms();
    let mut recovered = 0;
    for key in keys {
        let (record, etag) = get_json::<TxnRecord>(backend, &key, cipher).await?;
        let Some(etag) = etag else { continue };
        if record.status != TxnStatus::Preparing {
            continue;
        }
        if now.saturating_sub(record.started_at_ms) <= cutoff_ms {
            continue;
        }
        let aborting = TxnRecord {
            status: TxnStatus::Aborting,
            ..record
        };
        match put_json(backend, &key, &aborting, Some(&etag), cipher).await? {
            Cas::Ok => {
                // Ownership has now cleanly transferred to this sweep: the
                // original `run` call's own step-4 CAS is guaranteed to
                // lose from here, since the record's etag just changed.
                rollback(backend, cipher, &aborting).await?;
                recovered += 1;
            }
            // Someone else (the original caller mid-commit, or another
            // concurrent sweep) already moved this record -- leave it alone.
            Cas::Conflict => continue,
        }
    }
    Ok(recovered)
}

#[cfg(test)]
#[path = "../tests/unit/txn.rs"]
#[allow(deprecated)] // test_backend_and_cipher_with is parameterized over both engines
mod tests;
