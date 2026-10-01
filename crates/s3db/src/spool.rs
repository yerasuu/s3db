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
//!
//! One `redb` file per [`SpooledBackend`] instance, not one per directory:
//! `redb` locks its file exclusively, so a second opener — another backend in
//! the same process, a CLI run beside a server, two short-lived hook
//! processes — would fail every `put_cas` with "database already open" if
//! they shared one. Each instance names its own file on first write, and
//! [`SpooledBackend::recover_pending`] also adopts every sibling file nobody
//! holds open any more (a crashed or exited process's), replays it and
//! deletes it once empty.
//!
//! The spool directory belongs to exactly one backend: recovery replays a
//! sibling's intents onto *this* instance's `inner`, so two backends sharing
//! a directory would replay each other's writes onto the wrong store.

use crate::backend::{Backend, Cas, DeleteOutcome, ListPage};
use anyhow::{Context, Result};
use redb::{Database, DatabaseError, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
#[cfg(feature = "streaming")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

const TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_writes");
const DB_EXTENSION: &str = "redb";

/// A sibling file younger than this is left alone by recovery even when it
/// opens: `redb` creates the file before it takes the lock, so a brand-new
/// one may belong to an owner still between those two steps.
const MIN_ORPHAN_AGE: Duration = Duration::from_secs(60);

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

/// This instance's pending-write file, created under `root` on first use —
/// a directory root, same convention as [`crate::local::RedbBackend`], not a
/// `RedbBackend` itself: this holds write *intent*, never the data these
/// writes are destined for.
struct WriteSpool {
    root: PathBuf,
    own: OnceCell<(PathBuf, Arc<Database>)>,
}

impl WriteSpool {
    fn new(root: impl Into<PathBuf>) -> Self {
        WriteSpool {
            root: root.into(),
            own: OnceCell::new(),
        }
    }

    async fn database(&self) -> Result<&Arc<Database>> {
        let (_, db) = self
            .own
            .get_or_try_init(|| async {
                let path = self.root.join(format!("{}.{DB_EXTENSION}", random_op_id()?));
                let root = self.root.clone();
                tokio::task::spawn_blocking(move || -> Result<(PathBuf, Arc<Database>)> {
                    std::fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
                    let db = Database::create(&path).with_context(|| format!("opening {}", path.display()))?;
                    Ok((path, Arc::new(db)))
                })
                .await
                .context("spool open task panicked")?
            })
            .await?;
        Ok(db)
    }

    async fn record_intent(&self, op_id: &str, key: &str, expected_etag: Option<&str>, body: &[u8]) -> Result<()> {
        let db = Arc::clone(self.database().await?);
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
        clear_intent_in(Arc::clone(self.database().await?), op_id.to_string()).await
    }

    /// Sibling spool files under `root` old enough to be adopted — see
    /// [`MIN_ORPHAN_AGE`]. Whether one is actually abandoned is only known
    /// once opening it succeeds.
    async fn orphan_candidates(&self) -> Result<Vec<PathBuf>> {
        let own = self.own.get().map(|(path, _)| path.clone());
        let mut entries = match tokio::fs::read_dir(&self.root).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("listing {}", self.root.display())),
        };
        let mut out = Vec::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("listing {}", self.root.display()))?
        {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some(DB_EXTENSION) || Some(&path) == own.as_ref() {
                continue;
            }
            let old_enough = entry
                .metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age >= MIN_ORPHAN_AGE);
            if old_enough {
                out.push(path);
            }
        }
        Ok(out)
    }
}

impl Drop for WriteSpool {
    /// Removes this instance's file when nothing is left pending in it, so a
    /// short-lived process doesn't leave one empty file per run behind for
    /// the next recovery sweep to clean up.
    fn drop(&mut self) {
        let Some((path, db)) = self.own.take() else {
            return;
        };
        // Still shared with an in-flight blocking task: not ours to close.
        let Ok(db) = Arc::try_unwrap(db) else {
            return;
        };
        let empty = db.begin_read().ok().is_some_and(|txn| match txn.open_table(TABLE) {
            Ok(table) => table.is_empty().unwrap_or(false),
            Err(redb::TableError::TableDoesNotExist(_)) => true,
            Err(_) => false,
        });
        drop(db);
        if empty && let Err(e) = std::fs::remove_file(&path) {
            tracing::warn!(target: "s3db::spool", path = %path.display(), error = %e, "removing empty spool file");
        }
    }
}

async fn clear_intent_in(db: Arc<Database>, op_id: String) -> Result<()> {
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

async fn pending_in(db: Arc<Database>) -> Result<Vec<(String, PendingWrite)>> {
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
            let pending: PendingWrite = rmp_serde::from_slice(value.value()).context("deserializing pending write")?;
            out.push((op_id.value().to_string(), pending));
        }
        Ok(out)
    })
    .await
    .context("spool scan task panicked")?
}

/// `None` when another owner still holds `path` open — a live process's
/// spool, not an orphan.
async fn open_if_unlocked(path: PathBuf) -> Result<Option<Arc<Database>>> {
    tokio::task::spawn_blocking(move || match Database::open(&path) {
        Ok(db) => Ok(Some(Arc::new(db))),
        Err(DatabaseError::DatabaseAlreadyOpen) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("opening orphaned spool {}", path.display())),
    })
    .await
    .context("spool open task panicked")?
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
    /// `spool_root` must belong to this backend alone — see this module's
    /// doc comment for what recovery does with every file under it.
    pub fn new(inner: Arc<dyn Backend>, spool_root: impl Into<PathBuf>) -> Self {
        SpooledBackend {
            inner,
            spool: WriteSpool::new(spool_root),
        }
    }

    /// Replays every write this instance, or an earlier owner of a sibling
    /// file that no longer holds it open, never confirmed landed. See this
    /// module's doc comment for why a blind retry of the original
    /// `(key, expected_etag, body)` is safe, and why this isn't called
    /// automatically.
    pub async fn recover_pending(&self) -> Result<RecoveryReport> {
        let mut report = RecoveryReport::default();
        if let Some((_, db)) = self.spool.own.get() {
            self.replay(Arc::clone(db), &mut report).await?;
        }
        for path in self.spool.orphan_candidates().await? {
            let Some(db) = open_if_unlocked(path.clone()).await? else {
                continue;
            };
            if self.replay(Arc::clone(&db), &mut report).await? == 0 {
                drop(db);
                tokio::fs::remove_file(&path)
                    .await
                    .with_context(|| format!("removing drained spool {}", path.display()))?;
            }
        }
        Ok(report)
    }

    /// Replays one spool file's entries; returns how many are still pending.
    async fn replay(&self, db: Arc<Database>, report: &mut RecoveryReport) -> Result<usize> {
        let mut still_pending = 0;
        for (op_id, pending) in pending_in(Arc::clone(&db)).await? {
            match self
                .inner
                .put_cas(&pending.key, pending.body, pending.expected_etag.as_deref())
                .await
            {
                Ok(_) => {
                    clear_intent_in(Arc::clone(&db), op_id).await?;
                    report.resolved += 1;
                }
                Err(_) => still_pending += 1,
            }
        }
        report.still_pending += still_pending;
        Ok(still_pending)
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
