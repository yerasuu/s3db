//! Logical backup/restore of one [`Collection`] at a time -- a `scroll`
//! (list + read every entity) copied to a destination, not a storage-level
//! snapshot (no reliance on any driver-specific point-in-time feature, so it
//! works identically across every [`crate::backend::Backend`]).
//!
//! **Not a point-in-time backup.** [`BackupConsistency::FuzzySnapshot`] is
//! the one variant today, and it says so explicitly rather than leaving the
//! reader to assume more than this actually gives: the scroll runs with no
//! coordination against concurrent writes, so while any *individual* entity
//! is read whole (never a torn read), the overall backup can mix states
//! from different instants anywhere within `[started_at_ms, finished_at_ms]`.
//! A real point-in-time guarantee would need something like MVCC, which
//! this crate deliberately doesn't have (see [`crate::snapshot`]'s own
//! module doc for the same honesty at the single-entity scale a
//! `ReadSnapshot` operates at). [`restore_collection`]'s result carries the
//! same manifest, so a caller restoring from a backup sees the identical
//! caveat rather than assuming more precision than the mechanism gives.

use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy};
use crate::collection::{Collection, Tombstone};
use crate::naming::validate_segment;
use crate::payload::{delete_object, get_json, put_json};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Entities/tombstones restored per page, and per cursor checkpoint --
/// same reasoning as [`crate::migrate`]'s `MIGRATE_PAGE`: a crash loses at
/// most one page's worth of already-redone work, and the checkpoint write
/// is noise next to the page it covers.
const RESTORE_PAGE: usize = 200;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupConsistency {
    /// `scroll` run without coordination against concurrent writes. Every
    /// entity individually consistent (read whole), but the set as a whole
    /// may mix states from different instants within `[started_at_ms,
    /// finished_at_ms]` -- not a cross-entity atomic point-in-time.
    #[default]
    FuzzySnapshot,
}

/// `Default` only to satisfy [`get_json`]'s `T: DeserializeOwned +
/// Default` bound for "doesn't exist yet" -- [`restore_collection`] always
/// checks the returned etag before touching a `Default`-constructed
/// manifest's fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BackupManifest {
    pub backup_id: String,
    pub collection_prefix: String,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub consistency: BackupConsistency,
    /// `false` only if a caller explicitly opted out via
    /// [`backup_collection`]'s `include_tombstones: false` -- default
    /// `true`, since omitting tombstones silently loses the entire audit/
    /// recovery trail soft-delete exists to provide, at exactly the moment
    /// (disaster recovery) it's most needed.
    pub includes_tombstones: bool,
    pub entity_count: usize,
    pub tombstone_count: usize,
    /// Entities that already existed at this `backup_id`'s destination key
    /// (a `Cas::Conflict` on the create-only write, most likely a re-run of
    /// a `backup_id` that was already used) and so were *not* written by
    /// this call -- kept separate from `entity_count` so a caller can tell
    /// "already backed up" apart from "freshly backed up" instead of the
    /// manifest silently claiming every entity landed.
    #[serde(default)]
    pub entity_conflicts: usize,
    #[serde(default)]
    pub tombstone_conflicts: usize,
}

/// `backup_id` is interpolated straight into an object key, so it goes
/// through the same check every other caller-supplied name does — without
/// it an id like `"../repos"` doesn't produce an odd-looking backup, it
/// writes into live data's namespace (see [`crate::naming`]).
fn backup_prefix(backup_id: &str, collection_prefix: &str) -> Result<String> {
    validate_segment(backup_id, "backup id")?;
    Ok(format!(".conf/backups/{backup_id}/{collection_prefix}"))
}

/// Deliberately a sibling of, not nested inside, `backup_prefix`'s own
/// directory: the entities themselves are scanned via
/// `Collection::list_names` over that prefix, which can't tell a real
/// entity apart from a same-shaped `{name}.json` sitting in the same
/// directory -- this stays out of that namespace entirely instead of being
/// filtered out of it.
fn manifest_key(backup_id: &str, collection_prefix: &str) -> Result<String> {
    validate_segment(backup_id, "backup id")?;
    Ok(format!(".conf/backups/{backup_id}/{collection_prefix}.manifest.json"))
}

/// Backs up every live entity (and, by default, every tombstone) in
/// `collection` from `(src_backend, src_cipher)` to `(dest_backend,
/// dest_cipher)` -- the two can be the same backend/cipher (a backup
/// alongside the live data) or genuinely different ones (a separate bucket,
/// a different encryption key); either way each entity is decrypted under
/// its source key and re-sealed under its destination key, never copied as
/// raw ciphertext (which would carry the wrong AAD for its new location).
pub async fn backup_collection(
    src_backend: &dyn Backend,
    src_cipher: &Cipher,
    dest_backend: &dyn Backend,
    dest_cipher: &Cipher,
    collection: &Collection,
    backup_id: &str,
    include_tombstones: bool,
) -> Result<BackupManifest> {
    let started_at_ms = now_ms();
    let prefix = backup_prefix(backup_id, &collection.prefix)?;

    let mut entity_count = 0;
    let mut entity_conflicts = 0;
    for name in collection.list_names(src_backend).await? {
        let key = collection.key(&name)?;
        let (sealed, etag) = src_backend.get(&key).await?;
        if etag.is_none() {
            continue; // vanished between list_names and this read -- skip, not an error
        }
        let plain = src_cipher.open(&key, &sealed)?;
        let dest_key = format!("{prefix}/{name}.json");
        let resealed = dest_cipher.seal(&dest_key, &plain, CompressionStrategy::None)?;
        match dest_backend.put_cas(&dest_key, resealed, None).await? {
            Cas::Ok => entity_count += 1,
            Cas::Conflict => entity_conflicts += 1,
        }
    }

    let mut tombstone_count = 0;
    let mut tombstone_conflicts = 0;
    if include_tombstones {
        for (name, tombstone) in collection.list_tombstones(src_backend, src_cipher).await? {
            let dest_key = format!("{prefix}/.deleted/{name}.json");
            match put_json(dest_backend, &dest_key, &tombstone, None, dest_cipher).await? {
                Cas::Ok => tombstone_count += 1,
                Cas::Conflict => tombstone_conflicts += 1,
            }
        }
    }

    let manifest = BackupManifest {
        backup_id: backup_id.to_string(),
        collection_prefix: collection.prefix.to_string(),
        started_at_ms,
        finished_at_ms: now_ms(),
        consistency: BackupConsistency::FuzzySnapshot,
        includes_tombstones: include_tombstones,
        entity_count,
        tombstone_count,
        entity_conflicts,
        tombstone_conflicts,
    };
    put_json(
        dest_backend,
        &manifest_key(backup_id, &collection.prefix)?,
        &manifest,
        None,
        dest_cipher,
    )
    .await?;
    Ok(manifest)
}

/// Which half of a restore a [`RestoreProgress`] cursor belongs to.
/// Entities restore before tombstones (the same order [`backup_collection`]
/// itself writes them in), so a crash during entities never has to also
/// redo tombstones that hadn't started yet.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestorePhase {
    #[default]
    Entities,
    Tombstones,
}

/// [`restore_collection`]'s own resume cursor, mirroring
/// [`crate::migrate::InProgress`]'s reasoning: a crash partway through a
/// large restore must not require redoing everything, and must not leave
/// the destination in a state indistinguishable from a clean, complete
/// one. Persisted at `<collection.prefix>/.restore.json` on the
/// *destination* -- its mere existence marks "a restore is in progress or
/// was interrupted here", and it's deleted only once every entity and
/// tombstone the manifest says should exist has been accounted for (see
/// [`restore_collection`]'s post-restore check).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct RestoreProgress {
    pub backup_id: String,
    pub started_at_ms: u64,
    pub phase: RestorePhase,
    /// Last entity name restored, for [`RestorePhase::Entities`]. A resume
    /// continues strictly after this one via [`Collection::list_names_page`].
    pub last_name: Option<String>,
    /// Last tombstone *key* restored, for [`RestorePhase::Tombstones`] --
    /// a raw backend key, not a bare name, since that phase resumes via
    /// [`Backend::list_page`] directly rather than a `Collection` view.
    pub last_key: Option<String>,
    pub entities_restored: u64,
    pub tombstones_restored: u64,
}

fn restore_progress_key(collection: &Collection) -> String {
    format!("{}/.restore.json", collection.prefix)
}

/// Writes the resume cursor and returns its new etag -- a conflict means a
/// second restore runner is active against the same destination
/// collection, which is not something to retry into: two runners racing
/// the same entities would each see the other's writes as the state they
/// started from.
async fn checkpoint_restore(
    backend: &dyn Backend,
    cipher: &Cipher,
    key: &str,
    progress: &RestoreProgress,
    expected_etag: Option<&str>,
) -> Result<Option<String>> {
    if put_json(backend, key, progress, expected_etag, cipher).await? == Cas::Conflict {
        bail!("restore: {key} changed underneath this run -- another restore runner is active");
    }
    let (_progress, etag) = get_json::<RestoreProgress>(backend, key, cipher).await?;
    Ok(etag)
}

/// Everything one [`restore_collection`] call shares across every entity
/// and tombstone it restores -- bundled so `restore_one_entity`/
/// `restore_one_tombstone` take one context argument instead of six
/// positional ones for what is, per call, always the same fixed set.
struct RestoreCtx<'a> {
    backup_backend: &'a dyn Backend,
    backup_cipher: &'a Cipher,
    dest_backend: &'a dyn Backend,
    dest_cipher: &'a Cipher,
    collection: &'a Collection,
    backup_id: &'a str,
}

/// Restores one entity from the backup into `ctx.collection`. CAS-with-
/// reread, not a single blind attempt: restore overwrites the destination
/// key unconditionally *by intent* (a deliberate, caller-initiated
/// overwrite, not a CAS-protected merge), but the etag read here isn't
/// atomic with the write below, so a write landing on it in between must
/// not silently leave this entity unrestored.
async fn restore_one_entity(ctx: &RestoreCtx<'_>, backup_view: &Collection, name: &str) -> Result<()> {
    let key = backup_view.key(name)?;
    let (sealed, backup_etag) = ctx.backup_backend.get(&key).await?;
    // Unlike `backup_collection`'s own scroll (where a vanished entity is
    // just a live write racing the backup), a backup is meant to be
    // immutable once taken -- so listed-but-unreadable here means the
    // backup itself is corrupt or was modified since, and silently
    // skipping it would restore an incomplete collection with no signal
    // that anything was wrong.
    backup_etag.with_context(|| {
        format!(
            "{key}: listed as part of backup {} but vanished before it could be read",
            ctx.backup_id
        )
    })?;
    let plain = ctx.backup_cipher.open(&key, &sealed)?;
    let dest_key = ctx.collection.key(name)?;
    let resealed = ctx.dest_cipher.seal(&dest_key, &plain, CompressionStrategy::None)?;
    let (_, mut current_etag) = ctx.dest_backend.get(&dest_key).await?;
    for _ in 0..3 {
        match ctx
            .dest_backend
            .put_cas(&dest_key, resealed.clone(), current_etag.as_deref())
            .await?
        {
            Cas::Ok => return Ok(()),
            Cas::Conflict => current_etag = ctx.dest_backend.get(&dest_key).await?.1,
        }
    }
    bail!("{dest_key}: too many CAS conflicts restoring it (giving up after 3 attempts)")
}

/// [`restore_one_entity`]'s tombstone counterpart -- same immutable-backup
/// reasoning for a vanished read, same CAS-with-reread for the write.
async fn restore_one_tombstone(ctx: &RestoreCtx<'_>, key: &str, name: &str) -> Result<()> {
    let (tombstone, backup_etag) = get_json::<Tombstone>(ctx.backup_backend, key, ctx.backup_cipher).await?;
    backup_etag.with_context(|| {
        format!(
            "{key}: listed as part of backup {} but vanished before it could be read",
            ctx.backup_id
        )
    })?;
    let dest_tombstone_key = format!("{}/.deleted/{name}.json", ctx.collection.prefix);
    let (_, mut current_etag) = ctx.dest_backend.get(&dest_tombstone_key).await?;
    for _ in 0..3 {
        match put_json(
            ctx.dest_backend,
            &dest_tombstone_key,
            &tombstone,
            current_etag.as_deref(),
            ctx.dest_cipher,
        )
        .await?
        {
            Cas::Ok => return Ok(()),
            Cas::Conflict => current_etag = ctx.dest_backend.get(&dest_tombstone_key).await?.1,
        }
    }
    bail!("{dest_tombstone_key}: too many CAS conflicts restoring it (giving up after 3 attempts)")
}

/// Restores every entity (and tombstone, if the backup has any) from a
/// prior [`backup_collection`] call back into `collection` at
/// `(dest_backend, dest_cipher)`. Returns the original manifest, unchanged
/// -- a caller restoring from this inherits the exact same
/// `BackupConsistency::FuzzySnapshot` caveat the backup itself was taken
/// under, and should treat the restored result with the same care, not
/// assume a restore somehow adds precision the backup never had.
///
/// Resumable and self-verifying, via [`RestoreProgress`]: a crash partway
/// through picks back up from its last checkpoint on the next call with
/// the same `backup_id` (a different `backup_id` while one is already in
/// progress is refused, not silently overridden), and this only returns
/// `Ok` once the number of entities and tombstones actually restored
/// matches what the manifest recorded -- never on a guess that reaching
/// the end of a listing meant everything landed.
pub async fn restore_collection(
    backup_backend: &dyn Backend,
    backup_cipher: &Cipher,
    dest_backend: &dyn Backend,
    dest_cipher: &Cipher,
    collection: &Collection,
    backup_id: &str,
) -> Result<BackupManifest> {
    let (manifest, etag) = get_json::<BackupManifest>(
        backup_backend,
        &manifest_key(backup_id, &collection.prefix)?,
        backup_cipher,
    )
    .await?;
    etag.with_context(|| format!("no backup {backup_id} found for collection {}", collection.prefix))?;
    let prefix = backup_prefix(backup_id, &collection.prefix)?;
    // A `Collection` over the backup's own nested prefix -- the backup
    // lives at the same relative shape (`{prefix}/{name}{suffix}`) as the
    // live collection, just under `.conf/backups/<id>/` instead of at the
    // live collection's own prefix, so this is what actually has to be
    // scanned, not `collection` itself.
    let backup_view = Collection {
        suffix: collection.suffix,
        entropy: collection.entropy,
        ..Collection::new_owned(prefix.clone())
    };
    let ctx = RestoreCtx {
        backup_backend,
        backup_cipher,
        dest_backend,
        dest_cipher,
        collection,
        backup_id,
    };

    let progress_key = restore_progress_key(collection);
    let (existing, existing_etag) = get_json::<RestoreProgress>(dest_backend, &progress_key, dest_cipher).await?;
    let mut progress_etag;
    let mut progress = if existing_etag.is_some() {
        if existing.backup_id != backup_id {
            bail!(
                "{progress_key}: an unfinished restore of backup {} is already in progress for this \
                 collection -- finish or clear it before restoring a different backup here",
                existing.backup_id
            );
        }
        progress_etag = existing_etag;
        existing
    } else {
        let fresh = RestoreProgress {
            backup_id: backup_id.to_string(),
            started_at_ms: now_ms(),
            ..RestoreProgress::default()
        };
        progress_etag = checkpoint_restore(dest_backend, dest_cipher, &progress_key, &fresh, None).await?;
        fresh
    };

    if progress.phase == RestorePhase::Entities {
        let mut after = progress.last_name.clone();
        loop {
            let (names, next_after) = backup_view
                .list_names_page(backup_backend, after.as_deref(), RESTORE_PAGE)
                .await?;
            for name in &names {
                restore_one_entity(&ctx, &backup_view, name).await?;
                progress.entities_restored += 1;
            }
            progress.last_name = names.last().cloned().or(progress.last_name);
            progress_etag =
                checkpoint_restore(dest_backend, dest_cipher, &progress_key, &progress, progress_etag.as_deref())
                    .await?;
            match next_after {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        progress.phase = RestorePhase::Tombstones;
        progress_etag =
            checkpoint_restore(dest_backend, dest_cipher, &progress_key, &progress, progress_etag.as_deref()).await?;
    }

    if manifest.includes_tombstones {
        let tombstones_prefix = format!("{prefix}/.deleted/");
        let mut after = progress.last_key.clone();
        loop {
            let page = backup_backend
                .list_page(&tombstones_prefix, after.as_deref(), RESTORE_PAGE)
                .await?;
            if page.entries.is_empty() {
                break;
            }
            for (key, _size) in &page.entries {
                let Some(name) = key.strip_prefix(&tombstones_prefix).and_then(|s| s.strip_suffix(".json")) else {
                    continue; // a foreign key under this namespace -- left alone, not guessed at
                };
                restore_one_tombstone(&ctx, key, name).await?;
                progress.tombstones_restored += 1;
            }
            progress.last_key = page.entries.last().map(|(key, _)| key.clone()).or(progress.last_key);
            progress_etag =
                checkpoint_restore(dest_backend, dest_cipher, &progress_key, &progress, progress_etag.as_deref())
                    .await?;
            match page.next_after {
                Some(next) => after = Some(next),
                None => break,
            }
        }
    }

    // Never declare a restore complete on "the listing ran out" alone --
    // only once the counts actually match what the backup's own manifest
    // recorded for it. `entity_count`/`tombstone_count` are only what this
    // *backup* newly wrote; a name already occupied at backup time
    // (`entity_conflicts`/`tombstone_conflicts`) is still a real object
    // under the backup's prefix today, so both figure into what a restore
    // must account for.
    let expected_entities = (manifest.entity_count + manifest.entity_conflicts) as u64;
    if progress.entities_restored != expected_entities {
        bail!(
            "restore: backup {backup_id}'s manifest accounts for {expected_entities} entities but only \
             {} were found and restored -- not marking this restore complete",
            progress.entities_restored
        );
    }
    if manifest.includes_tombstones {
        let expected_tombstones = (manifest.tombstone_count + manifest.tombstone_conflicts) as u64;
        if progress.tombstones_restored != expected_tombstones {
            bail!(
                "restore: backup {backup_id}'s manifest accounts for {expected_tombstones} tombstones but \
                 only {} were found and restored -- not marking this restore complete",
                progress.tombstones_restored
            );
        }
    }

    delete_object(dest_backend, &progress_key).await;
    Ok(manifest)
}

#[cfg(test)]
#[path = "../tests/unit/backup.rs"]
mod tests;
