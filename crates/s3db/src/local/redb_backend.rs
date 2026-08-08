//! [`Backend`] over a single `redb` file — `LocalParams { engine: Redb,
//! .. }`. Real ACID transactions from an embedded engine instead of
//! [`crate::local::files`]'s hand-rolled `flock` + version-counter sidecar:
//! `put_cas` is a real compare-and-swap inside one write transaction, not
//! two separate file operations racing each other under a lock.
//!
//! One table, `(key: &str) -> (version: u64, body: &[u8])`, at
//! `{bucket}/s3db.redb`. `list_prefix` is a native B-tree range scan, not a
//! recursive `read_dir` walk — ordered by construction, and it never has to
//! skip bookkeeping sidecars because there are none: the version lives
//! alongside the body in the same row, not a second file.
//!
//! `redb::Database` is safe to share across threads but its own operations
//! are synchronous — every method here runs its actual redb call inside
//! [`tokio::task::spawn_blocking`] so a contended write transaction (redb
//! serializes its own writers internally) stalls a blocking-pool thread,
//! never the async runtime.
//!
//! Also implements [`AtomicBackend`]: a real write transaction can commit
//! several keys — updates included, not just creates — as one all-or-
//! nothing unit, which is exactly the guarantee [`crate::txn::run`] can
//! only approximate over S3-like backends with a durable record and crash
//! recovery. See that trait's module doc for why no other backend here
//! implements it.

use crate::atomic::{AtomicBackend, BatchOp, BatchOutcome};
use crate::backend::{Backend, Cas, DeleteOutcome};
use crate::config::LocalParams;
use anyhow::{Context, Result, bail};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
#[cfg(feature = "streaming")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::OnceCell;

const TABLE: TableDefinition<&str, (u64, &[u8])> = TableDefinition::new("s3db");
const DB_FILENAME: &str = "s3db.redb";

#[derive(Debug)]
pub struct RedbBackend {
    /// Directory holding `s3db.redb` — kept rather than the open `Database`
    /// itself so construction stays synchronous and infallible, matching
    /// every other driver's `new()` (see [`crate::gcs`]'s module doc for the
    /// same deferred-construction reasoning; opening a redb file is a
    /// blocking filesystem call, not an async one, but the "don't fail at
    /// construction" principle is the same).
    root: PathBuf,
    db: OnceCell<Arc<Database>>,
}

impl RedbBackend {
    pub fn new(cfg: &LocalParams) -> Self {
        RedbBackend {
            root: PathBuf::from(&cfg.bucket),
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
                    // `Database::create` opens the file if it's already a
                    // valid redb database, and initializes a fresh one if
                    // it's missing or empty -- there's no separate
                    // "does this already exist" branch to write here.
                    let db = Database::create(&path).with_context(|| format!("opening {}", path.display()))?;
                    Ok(Arc::new(db))
                })
                .await
                .context("redb open task panicked")?
            })
            .await
    }

    /// Loads every `(key, body)` pair into this database's table in one
    /// write transaction, each stamped with version `1` — the primitive
    /// behind `s3db-local-migrate` (see that binary): a bulk load is a
    /// one-time, offline operation, never a live [`Backend::put_cas`], so
    /// there's no prior version to preserve or CAS to honor.
    ///
    /// Refuses to run against a table that already has rows in it, rather
    /// than silently merging — a migration target should be a fresh
    /// location, and a non-empty table here almost certainly means the
    /// caller pointed this at the wrong directory or ran the tool twice.
    pub async fn bulk_load_fresh(&self, entries: Vec<(String, Vec<u8>)>) -> Result<usize> {
        let db = self.database().await?.clone();
        tokio::task::spawn_blocking(move || -> Result<usize> {
            let write_txn = db.begin_write().context("beginning redb write transaction")?;
            let mut inserted = 0;
            {
                let mut table = write_txn.open_table(TABLE).context("opening redb table")?;
                let existing = table.len().context("reading redb table size")?;
                if existing > 0 {
                    bail!(
                        "refusing to bulk-load: this redb table already has {existing} row(s) -- \
                         point the migration at a fresh location, or confirm this table is meant \
                         to be overwritten before deleting it yourself"
                    );
                }
                for (key, body) in &entries {
                    table
                        .insert(key.as_str(), (1u64, body.as_slice()))
                        .with_context(|| format!("writing {key}"))?;
                    inserted += 1;
                }
            }
            write_txn.commit().context("committing bulk load")?;
            Ok(inserted)
        })
        .await
        .context("redb bulk-load task panicked")?
    }
}

#[async_trait::async_trait]
impl Backend for RedbBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        let db = self.database().await?.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().context("beginning redb read transaction")?;
            let table = match read_txn.open_table(TABLE) {
                Ok(table) => table,
                // No write has ever happened yet -- an empty bucket, not an
                // error; every other driver's `get` on a missing key
                // returns the same (empty bytes, no etag).
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok((Vec::new(), None)),
                Err(e) => return Err(e).context("opening redb table"),
            };
            match table.get(key.as_str()).context("reading from redb")? {
                Some(guard) => {
                    let (version, body) = guard.value();
                    Ok((body.to_vec(), Some(version.to_string())))
                }
                None => Ok((Vec::new(), None)),
            }
        })
        .await
        .context("redb read task panicked")?
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let db = self.database().await?.clone();
        let key = key.to_string();
        let expected_etag = expected_etag.map(str::to_string);
        tokio::task::spawn_blocking(move || {
            let write_txn = db.begin_write().context("beginning redb write transaction")?;
            let outcome = {
                let mut table = write_txn.open_table(TABLE).context("opening redb table")?;
                let current_version = table
                    .get(key.as_str())
                    .context("reading from redb")?
                    .map(|g| g.value().0);
                let current_etag = current_version.map(|v| v.to_string());
                if expected_etag.as_deref() != current_etag.as_deref() {
                    Cas::Conflict
                } else {
                    let next = current_version.unwrap_or(0) + 1;
                    table
                        .insert(key.as_str(), (next, body.as_slice()))
                        .context("writing to redb")?;
                    Cas::Ok
                }
            };
            // A conflict must not commit the transaction at all -- `abort`
            // is the explicit way to say "discard whatever this
            // transaction staged," same principle as the files backend
            // never renaming its temp file into place on a losing CAS.
            match outcome {
                Cas::Ok => write_txn.commit().context("committing redb write")?,
                Cas::Conflict => write_txn.abort().context("aborting redb write")?,
            }
            Ok(outcome)
        })
        .await
        .context("redb write task panicked")?
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        let db = self.database().await?.clone();
        let key = key.to_string();
        let key_for_log = key.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().context("beginning redb write transaction")?;
            {
                let mut table = write_txn.open_table(TABLE).context("opening redb table")?;
                // Missing-already isn't an error -- `remove` just returns
                // `None`, same "this key is gone" outcome either way.
                table.remove(key.as_str()).context("removing from redb")?;
            }
            write_txn.commit().context("committing redb delete")?;
            Ok(())
        })
        .await
        .context("redb delete task panicked")?;
        match result {
            Ok(()) => Ok(DeleteOutcome {
                attempted: 1,
                confirmed: 1,
            }),
            Err(e) => {
                eprintln!("warning: couldn't delete {key_for_log}: {e:#}");
                Ok(DeleteOutcome {
                    attempted: 1,
                    confirmed: 0,
                })
            }
        }
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        if keys.is_empty() {
            return Ok(DeleteOutcome::default());
        }
        let db = self.database().await?.clone();
        let attempted = keys.len();
        let keys = keys.to_vec();
        // Unlike every other driver, this doesn't need to chunk at a
        // provider-side batch limit: one redb write transaction can remove
        // any number of keys, so the whole batch commits (or, on an error,
        // fails) as a single real transaction -- strictly stronger than the
        // "best-effort, per-key" contract this method documents elsewhere.
        let result = tokio::task::spawn_blocking(move || -> Result<usize> {
            let write_txn = db.begin_write().context("beginning redb write transaction")?;
            let mut confirmed = 0;
            {
                let mut table = write_txn.open_table(TABLE).context("opening redb table")?;
                for key in &keys {
                    table.remove(key.as_str()).context("removing from redb")?;
                    confirmed += 1;
                }
            }
            write_txn.commit().context("committing redb delete")?;
            Ok(confirmed)
        })
        .await
        .context("redb delete task panicked")?;
        match result {
            Ok(confirmed) => Ok(DeleteOutcome { attempted, confirmed }),
            Err(e) => {
                eprintln!("warning: couldn't delete a batch of {attempted} keys: {e:#}");
                Ok(DeleteOutcome {
                    attempted,
                    confirmed: 0,
                })
            }
        }
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        let db = self.database().await?.clone();
        let prefix = prefix.to_string();
        tokio::task::spawn_blocking(move || {
            let read_txn = db.begin_read().context("beginning redb read transaction")?;
            let table = match read_txn.open_table(TABLE) {
                Ok(table) => table,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e).context("opening redb table"),
            };
            let mut out = Vec::new();
            // Every key sharing `prefix` forms one contiguous run in
            // lexicographic order (the first byte where two keys differ
            // either falls inside the prefix, ruling one of them out
            // entirely, or falls after it) -- so `range(prefix..)` plus
            // "stop at the first non-matching key" visits exactly the
            // matching keys and nothing past them, no full-table scan.
            for entry in table.range(prefix.as_str()..).context("scanning redb")? {
                let (key, value) = entry.context("reading redb range entry")?;
                let key = key.value();
                if !key.starts_with(prefix.as_str()) {
                    break;
                }
                let (_, body) = value.value();
                out.push((key.to_string(), body.len() as u64));
            }
            Ok(out)
        })
        .await
        .context("redb range task panicked")?
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        // No chunked write path into redb -- the whole object is buffered
        // in memory once here, unlike the files backend's bounded-memory
        // copy. Acceptable for what this mode is for (see the crate's
        // local-mode design doc): a caller that genuinely needs bounded
        // memory for very large blobs on `Local` should stay on the
        // `Files` engine.
        let body = tokio::fs::read(source)
            .await
            .with_context(|| format!("reading {}", source.display()))?;
        let db = self.database().await?.clone();
        let key = key.to_string();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write().context("beginning redb write transaction")?;
            {
                let mut table = write_txn.open_table(TABLE).context("opening redb table")?;
                // `put_stream` has no CAS variant (see the trait doc) --
                // same unconditional bump-and-overwrite the files backend
                // does for it.
                let next = table
                    .get(key.as_str())
                    .context("reading from redb")?
                    .map(|g| g.value().0)
                    .unwrap_or(0)
                    + 1;
                table
                    .insert(key.as_str(), (next, body.as_slice()))
                    .context("writing to redb")?;
            }
            write_txn.commit().context("committing redb write")?;
            Ok(())
        })
        .await
        .context("redb write task panicked")?
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        let (body, etag) = self.get(key).await?;
        if etag.is_none() {
            bail!("{key} doesn't exist in local storage");
        }
        tokio::fs::write(dest, &body)
            .await
            .with_context(|| format!("writing {}", dest.display()))
    }
}

#[async_trait::async_trait]
impl AtomicBackend for RedbBackend {
    /// Two passes inside one write transaction: first every `Put`'s
    /// condition is checked against the table as it stands *before this
    /// batch touched anything*, and only if every single one holds does the
    /// second pass actually write. A condition that fails aborts the whole
    /// transaction — nothing from this batch lands, including `Put`s whose
    /// own condition did hold and every `Delete`, exactly the "all or
    /// nothing" [`AtomicBackend`] promises.
    async fn commit_batch(&self, ops: Vec<BatchOp>) -> Result<BatchOutcome> {
        let db = self.database().await?.clone();
        tokio::task::spawn_blocking(move || -> Result<BatchOutcome> {
            let write_txn = db.begin_write().context("beginning redb write transaction")?;
            let outcome = {
                let mut table = write_txn.open_table(TABLE).context("opening redb table")?;
                let mut conflict = false;
                for op in &ops {
                    if let BatchOp::Put { key, expected_etag, .. } = op {
                        let current_etag = table
                            .get(key.as_str())
                            .context("reading from redb")?
                            .map(|g| g.value().0.to_string());
                        if expected_etag.as_deref() != current_etag.as_deref() {
                            conflict = true;
                            break;
                        }
                    }
                }
                if conflict {
                    BatchOutcome::Conflict
                } else {
                    for op in &ops {
                        match op {
                            BatchOp::Put { key, body, .. } => {
                                // Re-reading the version here (rather than
                                // reusing the check above) is what makes a
                                // `Put` a real read-modify-write and not
                                // just a validated blind write -- the two
                                // happen in the same transaction either
                                // way, so there's no window for it to have
                                // changed between them.
                                let next = table
                                    .get(key.as_str())
                                    .context("reading from redb")?
                                    .map(|g| g.value().0)
                                    .unwrap_or(0)
                                    + 1;
                                table
                                    .insert(key.as_str(), (next, body.as_slice()))
                                    .with_context(|| format!("writing {key}"))?;
                            }
                            BatchOp::Delete { key } => {
                                table.remove(key.as_str()).with_context(|| format!("removing {key}"))?;
                            }
                        }
                    }
                    BatchOutcome::Applied
                }
            };
            match outcome {
                BatchOutcome::Applied => write_txn.commit().context("committing redb batch")?,
                BatchOutcome::Conflict => write_txn.abort().context("aborting redb batch")?,
            }
            Ok(outcome)
        })
        .await
        .context("redb batch task panicked")?
    }
}

#[cfg(test)]
mod tests;
