//! Schema versioning and a rewrite runner for one [`Collection`].
//!
//! The wire format is MessagePack of the caller's own struct, with no
//! envelope and no version stamp, which handles the easy half of schema
//! evolution for free: adding an `Option` field, or dropping one, is
//! tolerated by `serde` on both sides. The other half — renaming a field,
//! changing its type, splitting one into two, backfilling a value that can't
//! be a `Default` — needs every stored entry rewritten, and needs somebody to
//! remember which rewrites already ran. A relational deployment gets that
//! second part from its migration table; a bucket had nothing.
//!
//! This is that bookkeeping, per collection, at
//! `<prefix>/.schema.json`:
//!
//! - [`SchemaState::version`] — the highest migration applied.
//! - [`SchemaState::applied`] — the audit trail, one record per migration.
//! - [`SchemaState::in_progress`] — the resume cursor, updated once per page.
//!
//! **Why a cursor and not just a version.** A rewrite pass over a large
//! collection will sometimes die halfway. Without a cursor the only options
//! are re-running the whole pass — which means feeding already-migrated
//! entries back through a `Old -> New` transform that has no reason to accept
//! them — or bumping the version anyway and leaving the tail unmigrated. With
//! a cursor, a resumed run skips what landed and continues from exactly where
//! it stopped, so the transform only ever sees `Old` values.
//!
//! **Writers should be stopped.** This rewrites entries under CAS, so a
//! concurrent writer's update is never silently clobbered — but it will make
//! entries fail this pass and land in [`MigrationReport::conflicted`]
//! instead. Migrating a live collection is possible (re-run until the report
//! is clean); migrating a quiet one is what this is for.

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::collection::Collection;
use crate::payload::{get_json, put_json};
use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Entries rewritten per page, and per cursor checkpoint. Small enough that
/// a crash loses little work, large enough that the checkpoint write is
/// noise next to the rewrites it covers.
const MIGRATE_PAGE: usize = 200;

/// CAS attempts per entry before it's recorded as conflicted.
const MAX_ENTRY_ATTEMPTS: u32 = 3;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

/// One migration that ran to completion.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedMigration {
    pub version: u32,
    pub name: String,
    pub applied_at_ms: u64,
    pub entries_rewritten: u64,
}

/// A migration that started and hasn't finished — the resume cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InProgress {
    pub version: u32,
    pub name: String,
    pub started_at_ms: u64,
    /// Last entry name successfully rewritten. A resume continues strictly
    /// after this one.
    pub last_name: Option<String>,
    pub entries_rewritten: u64,
}

/// One collection's migration bookkeeping, at `<prefix>/.schema.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaState {
    /// Highest migration version applied in full. `0` means "no migration
    /// has ever run here", which is also what an untouched collection reads
    /// as — see [`baseline`] for adopting this on a collection whose data is
    /// already at a later shape.
    pub version: u32,
    pub applied: Vec<AppliedMigration>,
    pub in_progress: Option<InProgress>,
}

/// What [`migrate_entries`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// `false` when the recorded version already covered this migration and
    /// nothing was read or written.
    pub ran: bool,
    pub scanned: u64,
    pub rewritten: u64,
    /// Entries an unchanged transform left alone (`Rewrite::Keep`).
    pub unchanged: u64,
    /// Entries that lost their CAS race every attempt — a concurrent writer.
    /// Re-run the migration to pick them up.
    pub conflicted: Vec<String>,
    /// Entries that vanished between the listing and the read.
    pub vanished: u64,
}

impl MigrationReport {
    /// `true` when nothing needs a re-run.
    pub fn is_clean(&self) -> bool {
        self.conflicted.is_empty()
    }
}

/// What a transform decided for one entry.
#[derive(Debug, Clone)]
pub enum Rewrite<New> {
    /// Store this value in place of the old one.
    Write(New),
    /// Leave the entry exactly as it is — for a migration that only needs to
    /// touch some entries, so the rest cost no write at all.
    Keep,
}

/// Where a collection's schema bookkeeping lives.
fn state_key(collection: &Collection) -> String {
    format!("{}/.schema.json", collection.prefix)
}

/// Reads a collection's migration bookkeeping. A collection that has never
/// been migrated reads as [`SchemaState::default`] (version 0).
pub async fn schema_state(backend: &dyn Backend, cipher: &Cipher, collection: &Collection) -> Result<SchemaState> {
    Ok(get_json::<SchemaState>(backend, &state_key(collection), cipher)
        .await?
        .0)
}

/// Declares a collection to already be at `version` without rewriting
/// anything — for adopting this mechanism on data that predates it. Refuses
/// to lower a recorded version, since that would re-run migrations over
/// already-migrated entries.
pub async fn baseline(
    backend: &dyn Backend,
    cipher: &Cipher,
    collection: &Collection,
    version: u32,
    note: &str,
) -> Result<SchemaState> {
    let key = state_key(collection);
    let (mut state, etag) = get_json::<SchemaState>(backend, &key, cipher).await?;
    if state.version > version {
        bail!(
            "baseline: {key} is already at version {}, refusing to lower it to {version}",
            state.version
        );
    }
    state.version = version;
    state.applied.push(AppliedMigration {
        version,
        name: format!("baseline: {note}"),
        applied_at_ms: now_ms(),
        entries_rewritten: 0,
    });
    state.in_progress = None;
    put_json(backend, &key, &state, etag.as_deref(), cipher).await?;
    Ok(state)
}

/// Rewrites every entry of `collection` from `Old` to `New`, once.
///
/// Skips entirely (`ran: false`) if the recorded version already covers
/// `version`. Resumes from the stored cursor if a previous run of this same
/// version stopped partway. Records the migration as applied only after the
/// pass reaches the end of the collection.
///
/// `transform` sees one deserialized `Old` and returns [`Rewrite`]. It runs
/// once per entry per attempt, so — like [`Collection::update`]'s mutator —
/// it must be a function of its argument rather than something that
/// accumulates into captured state.
pub async fn migrate_entries<Old, New, F>(
    backend: &Arc<dyn Backend>,
    cipher: &Arc<Cipher>,
    collection: &Collection,
    version: u32,
    name: &str,
    transform: F,
) -> Result<MigrationReport>
where
    Old: DeserializeOwned + Default + Send + 'static,
    New: Serialize,
    F: Fn(Old) -> Result<Rewrite<New>>,
{
    if version == 0 {
        bail!("migrate_entries: version 0 is the never-migrated baseline, migrations start at 1");
    }
    let key = state_key(collection);
    let (mut state, mut state_etag) = get_json::<SchemaState>(backend.as_ref(), &key, cipher).await?;
    if state.version >= version {
        return Ok(MigrationReport::default());
    }

    // A cursor left by an interrupted run of *this* version is a resume
    // point; one left by a different version belongs to a migration that
    // never finished and isn't this pass's business, so it's reported by
    // being left alone rather than silently discarded.
    let resumed = state.in_progress.take_if(|progress| progress.version == version);
    if let Some(other) = &state.in_progress {
        bail!(
            "migrate_entries: {key} has an unfinished migration for version {} ({}), finish or clear it first",
            other.version,
            other.name
        );
    }
    let mut report = MigrationReport {
        ran: true,
        ..MigrationReport::default()
    };
    let mut progress = resumed.unwrap_or(InProgress {
        version,
        name: name.to_string(),
        started_at_ms: now_ms(),
        last_name: None,
        entries_rewritten: 0,
    });

    let mut after = progress.last_name.clone();
    loop {
        let (names, next_after) = collection
            .list_names_page(backend.as_ref(), after.as_deref(), MIGRATE_PAGE)
            .await?;
        for entry in &names {
            report.scanned += 1;
            match rewrite_one::<Old, New, _>(backend.as_ref(), cipher, collection, entry, &transform).await? {
                EntryOutcome::Rewritten => {
                    report.rewritten += 1;
                    progress.entries_rewritten += 1;
                }
                EntryOutcome::Unchanged => report.unchanged += 1,
                EntryOutcome::Vanished => report.vanished += 1,
                EntryOutcome::Conflicted => report.conflicted.push(entry.clone()),
            }
        }

        // Checkpoint the cursor once per page: a crash costs at most this
        // page's rewrites, not the whole pass.
        progress.last_name = names.last().cloned().or(progress.last_name);
        state.in_progress = Some(progress.clone());
        state_etag = checkpoint(backend.as_ref(), cipher, &key, &state, state_etag.as_deref()).await?;

        match next_after {
            Some(next) => after = Some(next),
            None => break,
        }
    }

    state.version = version;
    state.applied.push(AppliedMigration {
        version,
        name: name.to_string(),
        applied_at_ms: now_ms(),
        entries_rewritten: progress.entries_rewritten,
    });
    state.in_progress = None;
    checkpoint(backend.as_ref(), cipher, &key, &state, state_etag.as_deref()).await?;
    Ok(report)
}

/// Writes the bookkeeping object and returns its new etag.
///
/// A conflict here means a second migration runner is working on the same
/// collection, which is not something to retry into: two runners rewriting
/// the same entries would each see the other's output as input.
async fn checkpoint(
    backend: &dyn Backend,
    cipher: &Cipher,
    key: &str,
    state: &SchemaState,
    expected_etag: Option<&str>,
) -> Result<Option<String>> {
    if put_json(backend, key, state, expected_etag, cipher).await? == crate::backend::Cas::Conflict {
        bail!("migrate: {key} changed underneath this run -- another migration runner is active");
    }
    let (_state, etag) = get_json::<SchemaState>(backend, key, cipher).await?;
    Ok(etag)
}

enum EntryOutcome {
    Rewritten,
    Unchanged,
    Vanished,
    Conflicted,
}

async fn rewrite_one<Old, New, F>(
    backend: &dyn Backend,
    cipher: &Cipher,
    collection: &Collection,
    name: &str,
    transform: &F,
) -> Result<EntryOutcome>
where
    Old: DeserializeOwned + Default,
    New: Serialize,
    F: Fn(Old) -> Result<Rewrite<New>>,
{
    let entry_key = collection.key(name)?;
    for _attempt in 0..MAX_ENTRY_ATTEMPTS {
        let (old, etag) = get_json::<Old>(backend, &entry_key, cipher).await?;
        let Some(etag) = etag else {
            return Ok(EntryOutcome::Vanished);
        };
        let new = match transform(old).with_context(|| format!("migrating {entry_key}"))? {
            Rewrite::Write(new) => new,
            Rewrite::Keep => return Ok(EntryOutcome::Unchanged),
        };
        if put_json(backend, &entry_key, &new, Some(&etag), cipher).await? == crate::backend::Cas::Ok {
            return Ok(EntryOutcome::Rewritten);
        }
    }
    Ok(EntryOutcome::Conflicted)
}

#[cfg(test)]
#[path = "../tests/unit/migrate.rs"]
mod tests;
