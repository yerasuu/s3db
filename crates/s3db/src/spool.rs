//! Local durability for a single [`Backend::put_cas`] call: the record of
//! intent lives in a local `redb` file, committed (`fsync`'d by redb's own
//! transaction) *before* the remote attempt, and cleared only once that
//! attempt returns `Ok`. A crash anywhere between "intent recorded" and
//! "cleared" leaves the write on local disk for [`SpooledBackend::recover_pending`]
//! to finish, instead of losing it silently.
//!
//! [`crate::wal`] already exists and looks similar, but solves a different
//! problem: it records intent *remotely* (on the same backend that might be
//! the one failing) purely to tell an ambiguous error apart from "never
//! started," and it deliberately never retries. This module is the actual
//! delivery guarantee — local disk, and retried automatically once a
//! recovery sweep runs.
//!
//! Retrying a stale intent is safe here in a way it wouldn't be for an
//! arbitrary retry: [`SpooledBackend::recover_pending`] replays the *exact*
//! original `(key, expected_etag, body)`, and CAS makes that safe to redo
//! blindly. A replay can only come back `Cas::Conflict` if the key has
//! already moved past `expected_etag` — which happens only if this same
//! write already landed, or a legitimate concurrent writer legitimately won
//! the race under the usual CAS rules. Either way there's nothing left to
//! redo, so both `Ok` and `Conflict` clear the intent; only a hard `Err`
//! leaves it for the next sweep.
//!
//! Not run automatically: like [`crate::wal::recover_stale`] and
//! [`crate::txn_update::recover_stale_updates`], calling
//! [`SpooledBackend::recover_pending`] at startup and periodically is the
//! embedding application's job — this crate has no scheduler of its own.

use crate::backend::{Backend, Cas, DeleteOutcome, ListPage};
use anyhow::{Context, Result};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
#[cfg(feature = "streaming")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::OnceCell;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_writes");
const DB_FILENAME: &str = "spool.redb";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingWrite {
    key: String,
    expected_etag: Option<String>,
    body: Vec<u8>,
}

fn random_op_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("generating spool op id: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// The local `redb` file backing a [`SpooledBackend`]'s pending-write table
/// — a directory root, same convention as [`crate::local::RedbBackend`]
/// (`root.join(DB_FILENAME)`), not a `RedbBackend` itself: this holds write
/// *intent*, never the data these writes are destined for.
struct WriteSpool {
    root: PathBuf,
    db: OnceCell<Arc<Database>>,
}

impl WriteSpool {
    fn new(root: impl Into<PathBuf>) -> Self {
        WriteSpool {
            root: root.into(),
            db: OnceCell::new(),
        }
    }

    async fn database(&self) -> Result<&Arc<Database>> {
        self.db
            .get_or_try_init(|| async {
                let root = self.root.clone();
                tokio::task::spawn_blocking(move || {
                    std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
                    let path = root.join(DB_FILENAME);
                    let db = Database::create(&path).with_context(|| format!("opening {}", path.display()))?;
                    Ok(Arc::new(db))
                })
                .await
                .context("spool open task panicked")?
            })
            .await
    }

    async fn record_intent(&self, op_id: &str, key: &str, expected_etag: Option<&str>, body: &[u8]) -> Result<()> {
        let db = self.database().await?.clone();
        let op_id = op_id.to_string();
        let pending = PendingWrite {
            key: key.to_string(),
            expected_etag: expected_etag.map(str::to_string),
            body: body.to_vec(),
        };
        tokio::task::spawn_blocking(move || -> Result<()> {
            let serialized = rmp_serde::to_vec_named(&pending).context("serializing pending write")?;
            let write_txn = db.begin_write().context("beginning spool write transaction")?;
            {
                let mut table = write_txn.open_table(TABLE).context("opening spool table")?;
                table
                    .insert(op_id.as_str(), serialized.as_slice())
                    .context("recording pending write")?;
            }
            write_txn.commit().context("committing spool write")
        })
        .await
        .context("spool record task panicked")?
    }

    async fn clear_intent(&self, op_id: &str) -> Result<()> {
        let db = self.database().await?.clone();
        let op_id = op_id.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().context("beginning spool write transaction")?;
            {
                let mut table = write_txn.open_table(TABLE).context("opening spool table")?;
                table.remove(op_id.as_str()).context("clearing pending write")?;
            }
            write_txn.commit().context("committing spool clear")
        })
        .await
        .context("spool clear task panicked")?
    }

    /// Every write still pending, as `(op_id, PendingWrite)` —
    /// [`SpooledBackend::recover_pending`] replays these.
    async fn pending(&self) -> Result<Vec<(String, PendingWrite)>> {
        let db = self.database().await?.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<(String, PendingWrite)>> {
            let read_txn = db.begin_read().context("beginning spool read transaction")?;
            let table = match read_txn.open_table(TABLE) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e).context("opening spool table"),
            };
            let mut out = Vec::new();
            for entry in table.iter().context("scanning spool")? {
                let (op_id, value) = entry.context("reading spool entry")?;
                let pending: PendingWrite =
                    rmp_serde::from_slice(value.value()).context("deserializing pending write")?;
                out.push((op_id.value().to_string(), pending));
            }
            Ok(out)
        })
        .await
        .context("spool scan task panicked")?
    }
}

/// Result of one [`SpooledBackend::recover_pending`] sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Pending writes that landed this sweep (or were already resolved and
    /// just needed their intent record cleared).
    pub resolved: usize,
    /// Pending writes still unresolved after this sweep — a real error on
    /// retry, not a conflict. Left in place for the next sweep.
    pub still_pending: usize,
}

/// [`Backend::put_cas`], wrapped with a durable local write-intent record —
/// see this module's doc comment. Every other method delegates straight to
/// `inner`, unchanged.
pub struct SpooledBackend {
    inner: Arc<dyn Backend>,
    spool: WriteSpool,
}

impl std::fmt::Debug for SpooledBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpooledBackend").field("inner", &self.inner).finish()
    }
}

impl SpooledBackend {
    pub fn new(inner: Arc<dyn Backend>, spool_root: impl Into<PathBuf>) -> Self {
        SpooledBackend {
            inner,
            spool: WriteSpool::new(spool_root),
        }
    }

    /// Replays every write this process (or a prior one that crashed before
    /// clearing it) never confirmed landed. See this module's doc comment
    /// for why a blind retry of the original `(key, expected_etag, body)` is
    /// safe, and why this isn't called automatically.
    pub async fn recover_pending(&self) -> Result<RecoveryReport> {
        let mut report = RecoveryReport::default();
        for (op_id, pending) in self.spool.pending().await? {
            match self
                .inner
                .put_cas(&pending.key, pending.body.clone(), pending.expected_etag.as_deref())
                .await
            {
                Ok(_) => {
                    self.spool.clear_intent(&op_id).await?;
                    report.resolved += 1;
                }
                Err(_) => report.still_pending += 1,
            }
        }
        Ok(report)
    }
}

#[async_trait::async_trait]
impl Backend for SpooledBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Forwards the capability: this layer only guards `put_cas`, so a call
    /// that goes straight to the inner backend loses nothing this layer adds
    /// — see [`Backend::as_atomic`].
    fn as_atomic(&self) -> Option<&dyn crate::atomic::AtomicBackend> {
        self.inner.as_atomic()
    }

    fn as_range(&self) -> Option<&dyn crate::range::RangeBackend> {
        self.inner.as_range()
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.inner.get(key).await
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let op_id = random_op_id()?;
        self.spool.record_intent(&op_id, key, expected_etag, &body).await?;
        let result = self.inner.put_cas(key, body, expected_etag).await;
        if result.is_ok() {
            self.spool.clear_intent(&op_id).await?;
        }
        result
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        self.inner.delete(key).await
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        self.inner.delete_many(keys).await
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner.list_prefix(prefix).await
    }

    async fn list_page(&self, prefix: &str, after: Option<&str>, limit: usize) -> Result<ListPage> {
        self.inner.list_page(prefix, after, limit).await
    }

    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.inner.get_range(key, offset, len).await
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        // No CAS semantics to protect here -- see `Backend::put_stream`'s own
        // doc comment -- so nothing for this layer to add.
        self.inner.put_stream(key, source).await
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
}

#[cfg(test)]
#[path = "../tests/unit/spool.rs"]
mod tests;
