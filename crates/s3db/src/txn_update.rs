//! Multi-key transactions that can **update**, not only create.
//!
//! [`crate::txn::run`] is create-only, and that restriction is what makes it
//! simple: when every write is a create, the target object *is* its own lock —
//! whoever's `put_cas` lands first owns the key permanently, so there is no
//! window for a second writer and nothing to hold. The moment updates are in
//! scope that disappears. An `expected_etag` observed in one phase can move
//! before the write that depends on it, so something has to stand between the
//! check and the write, and that something has to survive a crash.
//!
//! On [`crate::atomic::AtomicBackend`] (today `redb`) none of this is needed —
//! [`run_update`] delegates to the native transaction. What follows is for
//! S3/R2/Azure/GCS, where `put_cas` is the only primitive there is.
//!
//! # The protocol
//!
//! 1. Write a `Preparing` record listing every op and its expected etag.
//! 2. Take a lock object per key, create-only. Any key already locked ends the
//!    attempt — nothing has been applied yet, so aborting is free.
//! 3. Re-read every key and check its etag still matches what the caller
//!    expected (and that a create-only op's key still doesn't exist). This is
//!    the check the locks make meaningful: no other transaction can invalidate
//!    it between here and step 5.
//! 4. CAS the record to `Committed`. This is the point of no return: past it
//!    the transaction *has happened* and any interruption is finished by
//!    recovery, not undone.
//! 5. Apply every write, release every lock, delete the record.
//!
//! Ordering: ops are sorted by key, so two transactions over overlapping keys
//! meet at their first shared key in the same order and one of them
//! deterministically loses there instead of each holding what the other needs.
//!
//! # What this guarantees, and what it doesn't
//!
//! **Atomic against other transactions.** Two `run_update` calls over
//! overlapping keys cannot interleave: one takes the locks, the other aborts.
//!
//! **Not isolated against plain writes.** A [`crate::Collection::put`] does not
//! consult these locks — making every read and write in the crate check a lock
//! object would double the cost of both, forever, to protect an operation most
//! callers never use. So an unlocked writer *can* touch a key mid-transaction.
//! Since the alternative to resolving that is a half-applied transaction, the
//! transaction wins: step 5 overwrites, and the keys where that happened come
//! back in [`UpdateReport::overwrote_unlocked`] rather than being swallowed. A
//! caller that never mixes the two never sees it.
//!
//! **Liveness needs the sweep.** A crashed transaction leaves locks behind, and
//! nothing steals them: a lock whose owner committed must not be taken by
//! someone who would then race that owner's roll-forward. Instead
//! [`recover_stale_updates`] resolves the owner — rolling a `Preparing` record
//! back, or a `Committed` one forward — and releases the locks as part of that.
//! Run it at startup and periodically, exactly like [`crate::txn::recover_stale`].

use crate::atomic::{BatchOp, BatchOutcome, as_atomic};
use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy};
use crate::index::Segment;
use crate::payload::{delete_object, get_json, list_all_keys, put_json};
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Records and locks live under `.conf/`, alongside every other piece of
/// server-side bookkeeping, never inside a caller's own prefix.
const TXN_PREFIX: &str = ".conf/txn-update";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn random_txn_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating transaction id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// One write inside a [`run_update`] batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOp {
    pub key: String,
    /// Already a `serde_json::Value` so one batch can mix ops for different
    /// concrete types — the record has to serialize the whole `Vec` as one
    /// document, which a generic `T` couldn't do. Same reasoning, and the same
    /// MessagePack-on-the-wire result, as [`crate::txn::TxnOp`].
    pub value: serde_json::Value,
    /// `None` means "must not exist yet" — identical to
    /// [`crate::Backend::put_cas`], so a create-only op is expressible here
    /// too and a batch can mix creates with updates.
    pub expected_etag: Option<String>,
}

impl UpdateOp {
    /// An op that creates `key`, failing the transaction if it already exists.
    pub fn create<T: Serialize>(key: String, value: &T) -> Result<Self> {
        Ok(UpdateOp {
            key,
            value: serde_json::to_value(value)?,
            expected_etag: None,
        })
    }

    /// An op that replaces `key`'s current value, failing the transaction if
    /// the key has moved on from `expected_etag`.
    pub fn update<T: Serialize>(key: String, value: &T, expected_etag: &str) -> Result<Self> {
        Ok(UpdateOp {
            key,
            value: serde_json::to_value(value)?,
            expected_etag: Some(expected_etag.to_string()),
        })
    }
}

/// What [`run_update`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateReport {
    /// `false` means nothing was written at all: a key was locked by another
    /// transaction, or an expected etag no longer matched.
    pub applied: bool,
    /// Keys where step 5 found an unlocked writer's value instead of the one
    /// step 3 verified, and overwrote it. Empty in every deployment that
    /// doesn't mix plain writes with transactions over the same keys — see the
    /// module doc.
    pub overwrote_unlocked: Vec<String>,
}

/// `Preparing`: locks taken, nothing applied — recovery rolls this back.
/// `Committed`: the transaction happened — recovery rolls this *forward*,
/// because undoing a committed transaction is exactly the outcome the commit
/// point exists to rule out. `Aborting`: a sweep has claimed a stale
/// `Preparing` record, which stops the original caller from committing it out
/// from under the sweep.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
enum UpdateStatus {
    #[default]
    Preparing,
    Committed,
    Aborting,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct UpdateRecord {
    txn_id: String,
    status: UpdateStatus,
    started_at_ms: u64,
    ops: Vec<UpdateOp>,
}

/// One held key, at `.conf/txn-update/.locks/<base64 key>.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct LockRecord {
    txn_id: String,
    acquired_at_ms: u64,
}

fn record_key(txn_id: &str) -> String {
    format!("{TXN_PREFIX}/{txn_id}.json")
}

/// Base64 so an arbitrary data key (slashes and all) becomes one safe path
/// component, and so a lock can never collide with a record.
fn lock_key(data_key: &str) -> String {
    format!(
        "{TXN_PREFIX}/.locks/{}.json",
        Segment::Base64
            .encode(data_key)
            .expect("base64 encoding never rejects input")
    )
}

/// Applies `ops` atomically, updates included.
///
/// Read the module doc before relying on this: the guarantee is atomicity
/// against other transactions, not isolation against plain writes.
pub async fn run_update(backend: &dyn Backend, cipher: &Cipher, mut ops: Vec<UpdateOp>) -> Result<UpdateReport> {
    if ops.is_empty() {
        return Ok(UpdateReport {
            applied: true,
            overwrote_unlocked: Vec::new(),
        });
    }
    if let Some(atomic) = as_atomic(backend) {
        let mut batch = Vec::with_capacity(ops.len());
        for op in &ops {
            batch.push(BatchOp::Put {
                key: op.key.clone(),
                body: seal_op(cipher, op)?,
                expected_etag: op.expected_etag.clone(),
            });
        }
        return Ok(match atomic.commit_batch(batch).await? {
            BatchOutcome::Applied => UpdateReport {
                applied: true,
                overwrote_unlocked: Vec::new(),
            },
            BatchOutcome::Conflict => UpdateReport::default(),
        });
    }

    // Deterministic order, so two overlapping transactions can't each end up
    // holding a key the other is waiting for.
    ops.sort_by(|a, b| a.key.cmp(&b.key));
    if let Some(duplicate) = first_duplicate_key(&ops) {
        bail!("run_update: {duplicate:?} appears twice in one batch, which has no single outcome");
    }

    let txn_id = random_txn_id()?;
    let record = UpdateRecord {
        txn_id: txn_id.clone(),
        status: UpdateStatus::Preparing,
        started_at_ms: now_ms(),
        ops,
    };
    let key = record_key(&txn_id);
    if put_json(backend, &key, &record, None, cipher).await? == Cas::Conflict {
        bail!("transaction id collision on {txn_id} (should never happen)");
    }
    let (_record, record_etag) = get_json::<UpdateRecord>(backend, &key, cipher).await?;

    // Phase 2: locks.
    let mut held: Vec<&UpdateOp> = Vec::with_capacity(record.ops.len());
    for op in &record.ops {
        let lock = LockRecord {
            txn_id: txn_id.clone(),
            acquired_at_ms: now_ms(),
        };
        match put_json(backend, &lock_key(&op.key), &lock, None, cipher).await? {
            Cas::Ok => held.push(op),
            // Another transaction holds this key. Nothing is applied yet, so
            // giving up costs only the locks already taken. A stale lock is
            // deliberately not stolen here -- see the module doc.
            Cas::Conflict => {
                release(backend, &held).await;
                delete_object(backend, &key).await;
                return Ok(UpdateReport::default());
            }
        }
    }

    // Phase 3: the etags the caller expected must still hold.
    for op in &record.ops {
        let (_body, current) = backend.get(&op.key).await?;
        if current.as_deref() != op.expected_etag.as_deref() {
            release(backend, &held).await;
            delete_object(backend, &key).await;
            return Ok(UpdateReport::default());
        }
    }

    // Phase 4: the commit point.
    let committed = UpdateRecord {
        status: UpdateStatus::Committed,
        ..record.clone()
    };
    match put_json(backend, &key, &committed, record_etag.as_deref(), cipher).await? {
        Cas::Ok => {}
        // The only thing that moves this record's etag is a sweep flipping it
        // to `Aborting`, having decided this transaction was dead. It owns the
        // rollback from here.
        Cas::Conflict => {
            release(backend, &held).await;
            return Ok(UpdateReport::default());
        }
    }

    // Phase 5: apply, then let go.
    let overwrote_unlocked = apply(backend, cipher, &committed).await?;
    release(backend, &held).await;
    delete_object(backend, &key).await;
    Ok(UpdateReport {
        applied: true,
        overwrote_unlocked,
    })
}

/// Writes every op of a committed record, returning the keys whose expected
/// etag had moved and were overwritten anyway.
///
/// Idempotent, which is what lets recovery re-run it: an op already applied is
/// simply written again with the same bytes.
async fn apply(backend: &dyn Backend, cipher: &Cipher, record: &UpdateRecord) -> Result<Vec<String>> {
    let mut overwrote = Vec::new();
    for op in &record.ops {
        let sealed = seal_op(cipher, op)?;
        match backend.put_cas(&op.key, sealed, op.expected_etag.as_deref()).await? {
            Cas::Ok => {}
            Cas::Conflict => {
                // Phase 3 verified this etag while holding the lock, so the
                // only way it moved is a writer that doesn't take locks (or
                // this record being re-applied by recovery after its own
                // first write landed). Either way the transaction is
                // committed and a half-applied result is not an option, so it
                // wins -- and says so.
                let (current_sealed, current_etag) = backend.get(&op.key).await?;
                let already_ours = current_etag.is_some() && current_sealed == seal_op(cipher, op)?;
                if !already_ours {
                    let sealed = seal_op(cipher, op)?;
                    if backend.put_cas(&op.key, sealed, current_etag.as_deref()).await? == Cas::Ok {
                        overwrote.push(op.key.clone());
                    } else {
                        // Lost the race twice: whoever is writing this key is
                        // doing so continuously, and blindly looping would
                        // never terminate. Recovery will finish the job.
                        bail!(
                            "txn_update: {} is being written continuously by something that ignores transaction locks; \
                             this transaction is committed and will be completed by recover_stale_updates",
                            op.key
                        );
                    }
                }
            }
        }
    }
    Ok(overwrote)
}

/// Same wire format as [`crate::payload::put_json`] -- a `Collection` reads
/// these keys back through `get_json`, so both paths must produce
/// byte-identical objects. Deterministic for a given op, which is what makes
/// the "did our own earlier attempt already write this?" check in [`apply`]
/// possible.
fn seal_op(cipher: &Cipher, op: &UpdateOp) -> Result<Vec<u8>> {
    let plain = rmp_serde::to_vec_named(&op.value)?;
    cipher.seal(&op.key, &plain, CompressionStrategy::None)
}

async fn release(backend: &dyn Backend, held: &[&UpdateOp]) {
    for op in held {
        delete_object(backend, &lock_key(&op.key)).await;
    }
}

async fn release_all(backend: &dyn Backend, record: &UpdateRecord) {
    for op in &record.ops {
        delete_object(backend, &lock_key(&op.key)).await;
    }
}

fn first_duplicate_key(sorted: &[UpdateOp]) -> Option<&str> {
    sorted
        .windows(2)
        .find(|pair| pair[0].key == pair[1].key)
        .map(|pair| pair[0].key.as_str())
}

/// Resolves transactions stuck for longer than `max_age`, and releases their
/// locks. Returns how many records this call finished.
///
/// A `Preparing` record is rolled back (nothing was applied — the commit point
/// is what phase 5 waits for). A `Committed` one is rolled *forward*: it
/// already happened, and its remaining writes are what everyone else is
/// waiting on. Undoing it instead would turn a committed transaction into a
/// partial one, which is the single thing the whole protocol exists to prevent.
pub async fn recover_stale_updates(backend: &dyn Backend, cipher: &Cipher, max_age: Duration) -> Result<usize> {
    let cutoff_ms = max_age.as_millis() as u64;
    let now = now_ms();
    let mut recovered = 0;

    for key in list_all_keys(backend, &format!("{TXN_PREFIX}/")).await? {
        // The lock namespace shares this prefix; those are not records.
        if key.starts_with(&format!("{TXN_PREFIX}/.locks/")) {
            continue;
        }
        let (record, etag) = get_json::<UpdateRecord>(backend, &key, cipher).await?;
        let Some(etag) = etag else { continue };
        if now.saturating_sub(record.started_at_ms) <= cutoff_ms {
            continue;
        }
        match record.status {
            UpdateStatus::Committed => {
                apply(backend, cipher, &record).await?;
                release_all(backend, &record).await;
                delete_object(backend, &key).await;
                recovered += 1;
            }
            UpdateStatus::Preparing => {
                let aborting = UpdateRecord {
                    status: UpdateStatus::Aborting,
                    ..record
                };
                // Claiming the record first: past this CAS the original
                // caller's own commit is guaranteed to lose, so it can't
                // commit a transaction this sweep is dismantling.
                match put_json(backend, &key, &aborting, Some(&etag), cipher).await? {
                    Cas::Ok => {
                        release_all(backend, &aborting).await;
                        delete_object(backend, &key).await;
                        recovered += 1;
                    }
                    Cas::Conflict => continue,
                }
            }
            UpdateStatus::Aborting => {
                // A previous sweep claimed it and died before finishing.
                release_all(backend, &record).await;
                delete_object(backend, &key).await;
                recovered += 1;
            }
        }
    }
    Ok(recovered)
}

#[cfg(test)]
#[path = "../tests/unit/txn_update.rs"]
mod tests;
