//! Typed CRUD over a set of JSON objects that all share one key prefix
//! (`{prefix}/{name}.json`) — the shape every entity kind (users, groups,
//! repo configs, server settings, ...) turned out to need, previously
//! hand-written once per entity.

use crate::backend::{Backend, Cas};
use crate::batch_loader::{BatchLoader, MemoryBudget};
use crate::cipher::{Cipher, CompressionStrategy};
use crate::naming::validate_path;
use crate::payload::{delete_object, get_json, list_all_keys, put_json};
use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Real wall-clock time, not a deterministic-replay clock -- only ever
/// stored for humans/audits to read later, same reasoning as
/// `crate::txn::now_ms`.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

/// Soft-delete marker for one [`Collection`] entry, at
/// `{prefix}/.deleted/{name}.json`. Decoupled on purpose from whether the
/// real object's bytes have actually been scrubbed from the backend yet --
/// [`Backend::delete`] is best-effort and can fail to land, and without this
/// there'd be no durable record that a retry is still owed.
///
/// Deliberately NOT consulted by [`Collection::get`]: checking it on every
/// read would double every `get`'s round-trip cost forever, to serve a retry
/// mechanism that doesn't exist in this crate yet (no GC sweep reads
/// `PurgeState::Pending` today). In the narrow window between a
/// [`Collection::delete`] call and its underlying [`Backend::delete`]
/// actually landing, `get` still faithfully reports the real backend state,
/// not the tombstone's intent -- the same "self-healing, not immediately
/// consistent" tolerance every other best-effort index in this codebase
/// already has, not a new one invented here.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Tombstone {
    pub deleted_at_ms: u64,
    pub purge_state: PurgeState,
    /// The archived-history etag ([`Collection::get_version`]) that held
    /// this entry's value at the moment it was deleted -- `None` if the
    /// entry either didn't exist or couldn't be archived, in which case
    /// [`Collection::restore`] has nothing to bring back.
    pub restore_etag: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PurgeState {
    /// Tombstone written; [`Backend::delete`] on the real object hasn't
    /// confirmed yet (either not attempted, or attempted and failed).
    #[default]
    Pending,
    /// The underlying delete confirmed (or the object was already gone).
    Purged,
}

/// Companion record for one `.history/{name}/{etag}.json` archive -- see
/// [`Collection::archive_history_timestamp`]/[`Collection::version_timestamp`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
struct HistoryTimestamp {
    archived_at_ms: u64,
}

/// Companion record at `{prefix}/.created/{name}.json` -- see
/// [`Collection::record_created_at`]/[`Collection::created_at`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
struct CreatedAt {
    created_at_ms: u64,
}

/// `Cow` rather than a plain `&'static str`: most collections (users,
/// groups, ...) have a fixed prefix known at compile time, but a few are
/// scoped per-call to some runtime value (e.g. "every permission grant
/// under this one repo uid") — same CRUD/list shape either way, so both get
/// to share it instead of the runtime-scoped ones reimplementing it by hand.
/// Whether a [`Collection`]'s keys spread across a hash-prefixed set of
/// sub-paths instead of sitting flat under one prefix. S3 (and compatibles)
/// partitions internally by key prefix, and gives more aggregate throughput
/// the more distinct partitions requests actually touch -- a flat
/// `{prefix}/{name}.json` layout puts every entry under the same
/// lexicographic range, capping throughput at whatever one partition gives
/// regardless of how many server instances call it in parallel. Same
/// principle [`crate::sharded_index::ShardedIndex`] already applies to
/// secondary indexes, generalized to the collection itself -- where the
/// real data lives, not just a pointer to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyEntropy {
    /// `{prefix}/{name}{suffix}` -- today's behavior, unchanged.
    #[default]
    None,
    /// `{prefix}/{bucket:04x}/{name}{suffix}`, `bucket = hash(name) mod
    /// buckets` -- same hash [`crate::sharded_index::ShardedIndex`] uses,
    /// spreading the same names across `buckets` distinct key ranges
    /// without changing `get`/`put`'s public API (callers still pass
    /// `name`, the bucket is computed internally). Opt-in per collection: a
    /// collection already written flat needs an external rewrite pass to
    /// switch (not provided by this crate today), so this only helps a
    /// collection that adopts it from the start, or one deliberately
    /// migrated.
    HashPrefix { buckets: u32 },
}

/// How many CAS attempts [`Collection::update`] makes before giving up.
/// Sized for contention, not for a broken backend: eight attempts with full
/// jitter is far past the point where a real write pattern still collides
/// (two writers racing lose at most once each), so exhausting it means
/// something is hammering one key rather than that the budget was too
/// small -- an error the caller should see, not a wait it should keep
/// paying.
pub const MAX_UPDATE_ATTEMPTS: u32 = 8;

/// Base delay for [`Collection::update`]'s jittered backoff between CAS
/// attempts. Deliberately shorter than [`crate::ResilienceConfig`]'s
/// transport backoff: a lost CAS race means someone else's write *landed*,
/// so the value to re-read is already there -- there's nothing to wait out
/// except the other writers in the same herd.
const UPDATE_BASE_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

/// What [`Collection::update`]'s mutator decided, after seeing the current
/// value.
///
/// Without a `Keep`, a caller expressing "create it if absent, leave it
/// alone otherwise" (SQL's `ON CONFLICT DO NOTHING`, and every `ensure_*`
/// function ever written) would have to write the value back unchanged --
/// paying a round trip, bumping the etag, and racing other writers over an
/// update that was never wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Update {
    /// Persist the mutated value.
    Write,
    /// Leave the stored value as it is; [`Collection::update`] returns it
    /// without writing.
    Keep,
}

#[derive(Debug, Clone)]
pub struct Collection {
    pub prefix: Cow<'static, str>,
    /// Appended after `name` to form the full key — `.json` for a flat
    /// `{prefix}/{name}.json` layout, or something like
    /// `/.conf/config.json` for an entity whose object lives one level
    /// deeper than its own name (e.g. a repo's config, nested under the
    /// repo's own storage prefix rather than sitting flat next to it).
    pub suffix: &'static str,
    pub entropy: KeyEntropy,
}

impl Collection {
    pub const fn new(prefix: &'static str) -> Self {
        Collection {
            prefix: Cow::Borrowed(prefix),
            suffix: ".json",
            entropy: KeyEntropy::None,
        }
    }

    pub const fn new_with_suffix(prefix: &'static str, suffix: &'static str) -> Self {
        Collection {
            prefix: Cow::Borrowed(prefix),
            suffix,
            entropy: KeyEntropy::None,
        }
    }

    pub fn new_owned(prefix: String) -> Self {
        Collection {
            prefix: Cow::Owned(prefix),
            suffix: ".json",
            entropy: KeyEntropy::None,
        }
    }

    /// Opt-in [`KeyEntropy::HashPrefix`] -- chainable at the same `const`
    /// definition site as [`Self::new`]: `Collection::new("...").with_hash_prefix(256)`.
    pub const fn with_hash_prefix(mut self, buckets: u32) -> Self {
        self.entropy = KeyEntropy::HashPrefix { buckets };
        self
    }

    /// This collection's object key for `name`.
    ///
    /// Fallible because `name` is caller-controlled and gets interpolated
    /// straight into the key: see [`crate::naming::validate_segment`] for
    /// what a name carrying a `/` (or a leading `.`) would otherwise do to
    /// the namespace it lands in.
    pub fn key(&self, name: &str) -> Result<String> {
        let mut buf = String::new();
        self.write_key(&mut buf, name)?;
        Ok(buf)
    }

    /// Same key [`Self::key`] builds, written directly into a caller-owned
    /// `buf` instead of allocating a fresh `String` -- `buf` is cleared
    /// first, so reusing the same `buf` across many calls (a hot loop doing
    /// several `get`/`put` calls against this one `Collection`) reuses its
    /// existing heap allocation instead of allocating anew each time.
    /// `#[derive(Entity)]`-generated types expose this as `T::write_key`.
    ///
    /// `buf` is left cleared, not half-written, if `name` is rejected.
    pub fn write_key(&self, buf: &mut String, name: &str) -> Result<()> {
        buf.clear();
        validate_path(name, "entity name")?;
        buf.push_str(&self.prefix);
        buf.push('/');
        match self.entropy {
            KeyEntropy::None => {}
            KeyEntropy::HashPrefix { buckets } => {
                use std::fmt::Write;
                let bucket = crate::shard::shard_of_count(name, buckets);
                write!(buf, "{bucket:04x}/").expect("writing to a String never fails");
            }
        }
        buf.push_str(name);
        buf.push_str(self.suffix);
        Ok(())
    }

    /// Namespace for `name`'s archived versions — parallel to (not nested
    /// inside) `name`'s own [`Self::key`], so it's independent of whatever
    /// `suffix` this collection uses for its main entries.
    ///
    /// Validates `name` in its own right rather than trusting that
    /// [`Self::key`] already did: this namespace is reached by several
    /// paths (`delete`, `restore`, the GC sweep) that don't all build the
    /// main key first.
    fn history_prefix(&self, name: &str) -> Result<String> {
        validate_path(name, "entity name")?;
        Ok(format!("{}/.history/{name}", self.prefix))
    }

    /// Where [`Self::delete`]'s tombstone for `name` lives -- parallel to
    /// (not nested inside) `name`'s own [`Self::key`] and [`Self::history_prefix`],
    /// same reasoning as both: independent of whatever `suffix` this
    /// collection uses for its main entries.
    fn tombstone_key(&self, name: &str) -> Result<String> {
        validate_path(name, "entity name")?;
        Ok(format!("{}/.deleted/{name}.json", self.prefix))
    }

    /// Reads `name`. `None` (not `T::default()`) is the "doesn't exist"
    /// signal — callers don't have to remember `get_json`'s etag-based
    /// convention themselves.
    pub async fn get<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
    ) -> Result<(Option<T>, Option<String>)> {
        let (value, etag) = get_json::<T>(backend, &self.key(name)?, cipher).await?;
        Ok((etag.is_some().then_some(value), etag))
    }

    /// Same read as [`Self::get`] but in `get_json`'s own raw convention:
    /// `T::default()` (not `None`) when `name` doesn't exist yet. For
    /// entities that were already written against that convention (a
    /// missing repo config *is* "defaults", not "absent") where switching
    /// to `Option` would ripple into every caller for no behavior change.
    pub async fn get_or_default<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
    ) -> Result<(T, Option<String>)> {
        get_json(backend, &self.key(name)?, cipher).await
    }

    /// Compare-and-swap write. `expected_etag = None` means "must not exist
    /// yet".
    pub async fn put<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        value: &T,
        expected_etag: Option<&str>,
    ) -> Result<Cas> {
        put_json(backend, &self.key(name)?, value, expected_etag, cipher).await
    }

    /// Same compare-and-swap write as [`Self::put`], but archives whatever
    /// value it's about to overwrite first — under the etag it had, so
    /// [`Self::get_version`] can later fetch it back by that same etag.
    /// `expected_etag = None` (fresh create) has nothing to archive, since
    /// there's no prior value.
    pub async fn put_versioned<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        value: &T,
        expected_etag: Option<&str>,
    ) -> Result<Cas> {
        if let Some(etag) = expected_etag {
            let key = self.key(name)?;
            let (sealed, current_etag) = backend.get(&key).await?;
            if current_etag.as_deref() == Some(etag) {
                // Archived as bytes -- opened under the entry's key, resealed
                // under the archive's -- not by deserializing into `T`. `T`
                // here is the *new* value's type, and the value being archived
                // is the old one: reading it as `T` failed outright whenever a
                // field had been renamed or added without a default, which is
                // exactly the write that most needs its predecessor kept.
                // `Self::delete` already archived this way; this now matches it.
                let plaintext = cipher.open(&key, &sealed)?;
                let history_key = self.history_key(name, etag)?;
                let resealed = cipher.seal(&history_key, &plaintext, CompressionStrategy::None)?;
                // Idempotent: the same etag always archives the same content,
                // so `Cas::Conflict` here just means someone else already
                // wrote this exact archive entry — fine. Only a genuine `Err`
                // (backend/crypto failure) needs to propagate.
                //
                // Run concurrently with its own timestamp write: both derive
                // entirely from the *old* value already read above, so
                // neither depends on the other's completion. The main `put`
                // below stays strictly sequential after both, though --
                // `ReadSnapshot::get` falls back to the live value whenever
                // it finds no archived version retired after its `as_of_ms`,
                // so a racing snapshot read must never observe the new
                // value live before this archive has actually landed.
                let (archive, timestamp) = tokio::join!(
                    backend.put_cas(&history_key, resealed, None),
                    self.archive_history_timestamp(backend, cipher, name, etag),
                );
                archive?;
                timestamp?;
            }
        }
        let cas = self.put(backend, cipher, name, value, expected_etag).await?;
        if expected_etag.is_none() && cas == Cas::Ok {
            // A fresh create that actually landed -- see
            // `Self::record_created_at`'s own doc comment for why this
            // matters to `crate::snapshot::ReadSnapshot`.
            self.record_created_at(backend, cipher, name).await?;
        }
        Ok(cas)
    }

    fn created_at_key(&self, name: &str) -> Result<String> {
        validate_path(name, "entity name")?;
        Ok(format!("{}/.created/{name}.json", self.prefix))
    }

    /// Records when `name` was first created via [`Self::put_versioned`] --
    /// closes [`crate::snapshot::ReadSnapshot::get`]'s one documented
    /// phantom-read gap: without this, an entity created after a
    /// snapshot's `as_of_ms` and never modified since has no `.history/`
    /// entry to rule that out, and would incorrectly appear to have
    /// already existed at that moment. Best-effort and create-only, same
    /// reasoning as [`Self::archive_history_timestamp`]: a lost race here
    /// just means [`Self::created_at`] returns `None`, which
    /// `ReadSnapshot::get` already treats as "can't place it in time,"
    /// same tolerance as an unplaceable history version.
    async fn record_created_at(&self, backend: &dyn Backend, cipher: &Cipher, name: &str) -> Result<()> {
        let record = CreatedAt {
            created_at_ms: now_ms(),
        };
        let _ = put_json(backend, &self.created_at_key(name)?, &record, None, cipher).await;
        Ok(())
    }

    /// When `name` was first created via [`Self::put_versioned`], if known
    /// -- `None` if it was never recorded (written only via plain
    /// [`Self::put`], created before this tracking existed, or a lost race
    /// on [`Self::record_created_at`]).
    pub async fn created_at(&self, backend: &dyn Backend, cipher: &Cipher, name: &str) -> Result<Option<u64>> {
        let (record, etag) = get_json::<CreatedAt>(backend, &self.created_at_key(name)?, cipher).await?;
        Ok(etag.map(|_| record.created_at_ms))
    }

    /// One archived version's key under `name`'s history namespace.
    ///
    /// `etag` is the one interpolated value here that comes from neither a
    /// caller nor this crate: it is whatever the backend answered with (an
    /// S3 `ETag` header, the local driver's counter), so it gets the same
    /// segment check every other name gets before landing in a key. A
    /// provider answering with a weak validator (`W/"abc"`) or anything
    /// else carrying a `/` would otherwise relocate the archive out of this
    /// collection's history namespace instead of failing.
    fn history_key(&self, name: &str, etag: &str) -> Result<String> {
        crate::naming::validate_segment(etag, "etag")?;
        Ok(format!("{}/{etag}.json", self.history_prefix(name)?))
    }

    fn history_timestamp_key(&self, name: &str, etag: &str) -> Result<String> {
        crate::naming::validate_segment(etag, "etag")?;
        Ok(format!("{}/{etag}.meta.json", self.history_prefix(name)?))
    }

    /// Records when the `etag` version of `name` was archived, alongside
    /// the archive itself -- a companion object, not a field on the
    /// archive's own payload, so this stays entirely orthogonal to what `T`
    /// is (both [`Self::put_versioned`]'s typed archiving and
    /// [`Self::archive_for_delete`]'s raw-byte archiving can write one the
    /// same way). Best-effort and create-only: same idempotency reasoning
    /// as the archive write itself (the same `etag` always archives at
    /// close to the same moment in practice; a lost race here just means
    /// [`Self::version_timestamp`] returns `None` for this version, which
    /// [`crate::snapshot::ReadSnapshot`] already treats as "can't place
    /// this version in time, skip it").
    async fn archive_history_timestamp(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        etag: &str,
    ) -> Result<()> {
        let record = HistoryTimestamp {
            archived_at_ms: now_ms(),
        };
        let _ = put_json(backend, &self.history_timestamp_key(name, etag)?, &record, None, cipher).await;
        Ok(())
    }

    /// When the `etag` version of `name` was archived, if that's known --
    /// `None` if no companion timestamp was ever written (a lost race on
    /// [`Self::archive_history_timestamp`]) or the version itself doesn't
    /// exist. [`crate::snapshot::ReadSnapshot`] uses this to find the
    /// version that was live as of a given moment.
    pub async fn version_timestamp(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        etag: &str,
    ) -> Result<Option<u64>> {
        let (record, found) =
            get_json::<HistoryTimestamp>(backend, &self.history_timestamp_key(name, etag)?, cipher).await?;
        Ok(found.map(|_| record.archived_at_ms))
    }

    /// Soft-delete: archives whatever value currently lives at `name` (so
    /// [`Self::restore`] has something to bring back), writes a `Pending`
    /// tombstone recording that archive's etag, then best-effort-deletes the
    /// real object -- marking the tombstone `Purged` only once that
    /// underlying delete actually confirms (or the object was already
    /// gone). A delete that fails to land leaves the tombstone `Pending`: a
    /// durable, inspectable record that this key still owes a real purge,
    /// instead of a lost fire-and-forget with no trace anyone could act on.
    pub async fn delete(&self, backend: &dyn Backend, cipher: &Cipher, name: &str) -> Result<()> {
        let key = self.key(name)?;
        // A real, hard error here (not `Ok((_, None))`, which is `get`'s own
        // documented "doesn't exist" sentinel) must not be treated the same
        // as "nothing to archive": a transient read failure silently
        // swallowed here used to feed `archive_for_delete` an empty etag,
        // skip archiving whatever was actually still there, and then still
        // run the unconditional `backend.delete` below -- turning a network
        // blip into a real object destroyed with no backup and no trace
        // beyond a warning. Refusing to delete without a confirmed read is
        // the only safe response.
        let (sealed, etag) = backend.get(&key).await.with_context(|| {
            format!("reading {name} before deleting it -- refusing to delete without a confirmed read")
        })?;
        let restore_etag = self
            .archive_for_delete(backend, cipher, name, &key, &sealed, etag.as_deref())
            .await?;

        let tombstone_key = self.tombstone_key(name)?;
        let (_, mut tomb_etag) = get_json::<Tombstone>(backend, &tombstone_key, cipher)
            .await
            .unwrap_or_default();
        let pending = Tombstone {
            deleted_at_ms: now_ms(),
            purge_state: PurgeState::Pending,
            restore_etag,
        };
        // CAS-with-reread, not a single blind attempt: a `Cas::Conflict`
        // here means some other tombstone (with a different, or no,
        // `restore_etag`) is already at this key -- silently treating that
        // as success would proceed to purge under `pending`'s etag/archive
        // while the *actually stored* tombstone still points `restore` at
        // the wrong (or no) archived version.
        let mut wrote_pending = false;
        for _ in 0..3 {
            match put_json(backend, &tombstone_key, &pending, tomb_etag.as_deref(), cipher).await {
                Ok(Cas::Ok) => {
                    wrote_pending = true;
                    break;
                }
                Ok(Cas::Conflict) => {
                    tomb_etag = get_json::<Tombstone>(backend, &tombstone_key, cipher)
                        .await
                        .unwrap_or_default()
                        .1;
                }
                Err(_) => break,
            }
        }
        if !wrote_pending {
            // Couldn't even record intent -- nothing to retry from, bail.
            // Not an error: the tombstone is best-effort by design, same as
            // the underlying delete it tracks.
            return Ok(());
        }

        let confirmed = backend
            .delete(&key)
            .await
            .map(|o| o.confirmed == o.attempted)
            .unwrap_or(false);
        if confirmed {
            // Re-read for a fresh etag rather than reusing the one from the
            // `put_json` above (which only returns `Cas`, never the etag it
            // just wrote) -- same technique `txn::run` uses for its own
            // record.
            if let Ok((_, fresh_etag)) = get_json::<Tombstone>(backend, &tombstone_key, cipher).await {
                let purged = Tombstone {
                    purge_state: PurgeState::Purged,
                    ..pending
                };
                let _ = put_json(backend, &tombstone_key, &purged, fresh_etag.as_deref(), cipher).await;
            }
        }
        // Else: leave `Pending` -- there's no GC sweep to retry it yet, but
        // the record is there for whenever one exists.
        Ok(())
    }

    /// Re-encrypts `name`'s current sealed bytes under its own
    /// `.history/{etag}.json` key (new AAD, since AAD binds to the exact S3
    /// key) and returns that etag on success -- the exact archive
    /// [`Self::restore`] later reads back by way of the tombstone's
    /// `restore_etag`. `None` if there was nothing to archive (`etag` is
    /// `None`, i.e. `name` didn't exist) or the archive write/decrypt
    /// failed -- either way, best-effort, same tolerance as everywhere else
    /// in this method: a failure to archive just means a later `restore` on
    /// this particular delete won't have anything to bring back.
    async fn archive_for_delete(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        key: &str,
        sealed: &[u8],
        etag: Option<&str>,
    ) -> Result<Option<String>> {
        let Some(etag) = etag else { return Ok(None) };
        let plaintext = match cipher.open(key, sealed) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(target: "s3db::collection", name, error = %e, "couldn't decrypt entry to archive it before deleting");
                return Ok(None);
            }
        };
        let history_key = self.history_key(name, etag)?;
        let resealed = cipher.seal(&history_key, &plaintext, CompressionStrategy::None)?;
        // Create-only, but idempotent in practice: the same etag always
        // archives the same content, so a `Cas::Conflict` here just means
        // this exact archive entry already exists (a prior delete attempt
        // that got this far but failed later) -- fine either way.
        match backend.put_cas(&history_key, resealed, None).await {
            Ok(_) => {
                self.archive_history_timestamp(backend, cipher, name, etag).await?;
                Ok(Some(etag.to_string()))
            }
            Err(e) => {
                tracing::warn!(target: "s3db::collection", name, error = %e, "couldn't archive entry before deleting it");
                Ok(None)
            }
        }
    }

    /// Undoes a [`Self::delete`]: re-writes `name` from the archived
    /// version its tombstone points at, then removes the tombstone that's
    /// been hiding it. In that order deliberately -- if the tombstone
    /// removal (best-effort, same as everywhere else) doesn't land, the
    /// worst case is "restored but still hidden" (recoverable by retrying
    /// just the tombstone delete); the reverse order could lose the object
    /// being restored.
    pub async fn restore<T: Serialize + DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
    ) -> Result<()> {
        let tombstone_key = self.tombstone_key(name)?;
        let (tombstone, _) = get_json::<Tombstone>(backend, &tombstone_key, cipher).await?;
        let etag = tombstone
            .restore_etag
            .context("nothing to restore: no archived version for this name")?;
        let value: T = self
            .get_version(backend, cipher, name, &etag)
            .await?
            .context("archived version vanished mid-restore")?;
        self.write_object_for_restore(backend, cipher, name, &value).await?;
        delete_object(backend, &tombstone_key).await;
        Ok(())
    }

    /// CAS-with-reread instead of a blind create-only write: the key
    /// `name` restores to may still be occupied by an orphaned object a
    /// failed [`Backend::delete`] never actually cleared (see
    /// [`PurgeState::Pending`]) -- in that case the restored value should
    /// win, not bounce off a CAS conflict against bytes that were already
    /// supposed to be gone. Also makes a repeated [`Self::restore`] call
    /// idempotent instead of failing the second time on "already exists".
    async fn write_object_for_restore<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        value: &T,
    ) -> Result<()> {
        let key = self.key(name)?;
        let (_, mut expected_etag) = backend.get(&key).await?;
        for _ in 0..3 {
            match put_json(backend, &key, value, expected_etag.as_deref(), cipher).await? {
                Cas::Ok => return Ok(()),
                Cas::Conflict => {
                    let (_, etag) = backend.get(&key).await?;
                    expected_etag = etag;
                }
            }
        }
        bail!("restore: too many CAS conflicts writing {name} (giving up after 3 attempts)")
    }

    /// Every tombstone this collection currently has, with the name it
    /// shadows -- what [`crate::gc::sweep`] scans to retry [`PurgeState::Pending`]
    /// deletes and age out old [`PurgeState::Purged`] ones. A separate scan
    /// from [`Self::list_names`] on purpose: tombstones live under
    /// `.deleted/`, a namespace `list_names` explicitly excludes.
    pub async fn list_tombstones(&self, backend: &dyn Backend, cipher: &Cipher) -> Result<Vec<(String, Tombstone)>> {
        let scan_prefix = format!("{}/.deleted/", self.prefix);
        let mut out = Vec::new();
        for key in list_all_keys(backend, &scan_prefix).await? {
            let Some(name) = key.strip_prefix(&scan_prefix).and_then(|s| s.strip_suffix(".json")) else {
                continue;
            };
            let (tombstone, etag) = get_json::<Tombstone>(backend, &key, cipher).await?;
            if etag.is_some() {
                out.push((name.to_string(), tombstone));
            }
        }
        Ok(out)
    }

    /// Retries the underlying delete for a [`PurgeState::Pending`]
    /// tombstone -- the same second half [`Self::delete`] itself runs, for
    /// a maintenance sweep to call later instead of the caller who
    /// originally deleted `name` being the only one who ever gets to try
    /// again. Returns `true` if `name`'s tombstone is `Purged` by the time
    /// this returns (already was, or just became so).
    pub async fn retry_pending_purge(&self, backend: &dyn Backend, cipher: &Cipher, name: &str) -> Result<bool> {
        let tombstone_key = self.tombstone_key(name)?;
        let (tombstone, tomb_etag) = get_json::<Tombstone>(backend, &tombstone_key, cipher).await?;
        if tomb_etag.is_none() {
            return Ok(false); // nothing to retry
        }
        if tombstone.purge_state == PurgeState::Purged {
            return Ok(true);
        }
        let confirmed = backend
            .delete(&self.key(name)?)
            .await
            .map(|o| o.confirmed == o.attempted)
            .unwrap_or(false);
        if confirmed {
            let purged = Tombstone {
                purge_state: PurgeState::Purged,
                ..tombstone
            };
            put_json(backend, &tombstone_key, &purged, tomb_etag.as_deref(), cipher).await?;
        }
        Ok(confirmed)
    }

    /// Removes a [`PurgeState::Purged`] tombstone record entirely -- call
    /// once it's old enough nobody needs the audit trail anymore. A no-op
    /// on a `Pending` tombstone: removing the record while the underlying
    /// delete still isn't confirmed would destroy the one durable sign that
    /// a retry is still owed.
    pub async fn forget_tombstone(&self, backend: &dyn Backend, cipher: &Cipher, name: &str) -> Result<()> {
        let tombstone_key = self.tombstone_key(name)?;
        let (tombstone, etag) = get_json::<Tombstone>(backend, &tombstone_key, cipher).await?;
        if etag.is_some() && tombstone.purge_state == PurgeState::Purged {
            delete_object(backend, &tombstone_key).await;
        }
        Ok(())
    }

    /// Best-effort removal of one archived history version and its
    /// companion timestamp -- for a maintenance sweep pruning old
    /// versions. Never touches `name`'s live object.
    pub async fn forget_history_version(&self, backend: &dyn Backend, name: &str, version: &str) -> Result<()> {
        delete_object(backend, &self.history_key(name, version)?).await;
        delete_object(backend, &self.history_timestamp_key(name, version)?).await;
        Ok(())
    }

    /// Every name currently stored, sorted.
    /// Read-modify-write of one entry under CAS, retrying the read when it
    /// loses the race.
    ///
    /// This is the loop three separate places in this crate had already
    /// hand-rolled (`Self::restore`, the tombstone write inside
    /// `Self::delete`, `sharded_index`'s epoch bump) and that every caller
    /// implementing an upsert or a counter has to hand-roll too: read the
    /// current value with its etag, derive the next one, `put` conditioned
    /// on that etag, and on [`Cas::Conflict`] start over from a fresh read
    /// -- because a conflict means someone else's write landed, so the
    /// value `mutate` was handed is stale and its result must be discarded,
    /// not retried as-is.
    ///
    /// A missing entry is `T::default()`, and the first attempt writes with
    /// `expected_etag: None` ("must not exist yet"). So this is an upsert:
    /// `mutate` sees either the stored value or the default, and can tell
    /// them apart by whatever field of `T` distinguishes them.
    ///
    /// **`mutate` must be a pure function of the value it's handed.** It is
    /// called once per attempt, always against a freshly read value, and
    /// its earlier results are thrown away -- a mutator that instead
    /// accumulates into a captured variable (pushing to a `Vec` it owns,
    /// incrementing a local counter) will double-count on every retry.
    /// Deriving the new value from its `&mut T` argument alone is always
    /// safe; anything else is the caller's own hazard.
    ///
    /// Returns the value as it now stands: the one written, or the stored
    /// one *as read* if `mutate` answered [`Update::Keep`] -- so a mutator
    /// that modified its buffer and then decided against writing it cannot
    /// hand back a value that was never stored. That guarantee is what the
    /// `T: Clone` bound pays for: `mutate` works on a copy.
    pub async fn update<T, F>(&self, backend: &dyn Backend, cipher: &Cipher, name: &str, mutate: F) -> Result<T>
    where
        T: Clone + Serialize + DeserializeOwned + Default,
        F: FnMut(&mut T) -> Result<Update>,
    {
        update_at_key(backend, cipher, &self.key(name)?, mutate).await
    }

    pub async fn list_names(&self, backend: &dyn Backend) -> Result<Vec<String>> {
        let scan_prefix = format!("{}/", self.prefix);
        // `name_from_key` drops this collection's own bookkeeping
        // (`.history/`, `.deleted/`, `.created/`, `.schema.json`), which is
        // never an entry.
        let mut names: Vec<String> = list_all_keys(backend, &scan_prefix)
            .await?
            .into_iter()
            .filter_map(|key| self.name_from_key(&key, &scan_prefix))
            .collect();
        names.sort();
        Ok(names)
    }

    /// One page of [`Self::list_names`], in ascending name order.
    ///
    /// Same cursor contract as [`Backend::list_page`] (`after` is a *name*
    /// here, not a key, since that's what a caller of this method holds),
    /// for the case `list_names` can't serve: a collection large enough that
    /// materializing every name at once is the problem — a migration pass, an
    /// export, a sweep over millions of entries.
    ///
    /// Because this collection's reserved bookkeeping namespaces get filtered
    /// *after* the page comes back, a page can contain fewer than `limit`
    /// names while more still remain; trust the returned cursor, never the
    /// page's length, to decide whether to continue.
    pub async fn list_names_page(
        &self,
        backend: &dyn Backend,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<String>, Option<String>)> {
        let scan_prefix = format!("{}/", self.prefix);
        // The cursor a caller hands back is a name; the backend wants a key.
        let mut after_key = match after {
            Some(name) => Some(self.key(name)?),
            None => None,
        };

        // A single backend page can be ENTIRELY bookkeeping (`.history/`,
        // `.deleted/`, ...) — a collection with as many tombstones as (or
        // more than) one page's worth of entries makes this the common
        // case, not an edge one, since every name in the raw keyspace sorts
        // before any of them (`.` < alphanumeric). That page still has a
        // real `next_after` from the backend's point of view; translating
        // *that* key through `name_from_key` (as an earlier version of this
        // function did) hits the exact same "starts with `.`" filter and
        // collapses it to `None`, which reports "no more entries" while
        // real ones sit just past this page — silently truncating the
        // collection from every caller's point of view. Looping past
        // bookkeeping-only pages instead of stopping at the first one keeps
        // the cursor honest: it always names a real entry, never a raw key
        // that doesn't have one.
        // How many entries EACH backend round-trip inside the loop asks for
        // — deliberately NOT `limit`. A collection whose bookkeeping-shaped
        // run is genuinely large (`Blob`'s `.parts/` holds one entry per
        // *chunk* of every blob, not one per blob, so it can outnumber real
        // names by orders of magnitude) would need `run_length / limit`
        // round-trips to skip past it if each one only asked for `limit`
        // keys — thousands of them for a `limit` in the tens. Asking for a
        // full page every time bounds that to `run_length / SCAN_BATCH`
        // regardless of what the caller wants back; `SCAN_BATCH` is S3's own
        // real `max-keys` ceiling ([`crate::s3::S3Backend::list_page`]
        // clamps to it already), so this never asks for more than a single
        // provider round-trip can return anyway.
        const SCAN_BATCH: usize = 1000;
        let mut names: Vec<String> = Vec::new();
        let mut backend_exhausted = false;
        loop {
            let page = backend
                .list_page(&scan_prefix, after_key.as_deref(), limit.max(SCAN_BATCH))
                .await?;
            for (key, _size) in &page.entries {
                if let Some(name) = self.name_from_key(key, &scan_prefix) {
                    names.push(name);
                }
            }
            match page.next_after {
                Some(next_key) => after_key = Some(next_key),
                None => backend_exhausted = true,
            }
            if names.len() >= limit || backend_exhausted {
                break;
            }
        }

        // A page can contribute up to `limit` names on top of what earlier
        // loop iterations already had, so the total can overshoot `limit`
        // by the time the loop above breaks — trim back to it and hand
        // back the name AT that boundary as the resume point, not whatever
        // extra names came along with it.
        let next_after = if names.len() > limit {
            let cursor = names[limit - 1].clone();
            names.truncate(limit);
            Some(cursor)
        } else if backend_exhausted {
            None
        } else {
            names.last().cloned()
        };
        Ok((names, next_after))
    }

    /// The entity name a full object key belongs to, or `None` if the key is
    /// this collection's own bookkeeping rather than an entry. Shared by
    /// [`Self::list_names`] and [`Self::list_names_page`] so the two can't
    /// disagree about what counts as an entry.
    fn name_from_key(&self, key: &str, scan_prefix: &str) -> Option<String> {
        let rest = key.strip_prefix(scan_prefix)?;
        // Anything under this prefix whose first component starts with `.` is
        // this crate's own bookkeeping, never an entry: `validate_path`
        // forbids a name from starting one, so the rule is exact rather than
        // heuristic. It used to be a list of the three known namespaces
        // (`.history/`, `.deleted/`, `.created/`), which silently admitted
        // the next one added -- `migrate`'s `.schema.json` -- as an entry
        // named ".schema", whose key then failed to build at all.
        if rest.starts_with('.') {
            return None;
        }
        match self.entropy {
            KeyEntropy::None => rest.strip_suffix(self.suffix).map(str::to_string),
            KeyEntropy::HashPrefix { .. } => {
                let (_bucket, name_and_suffix) = rest.split_once('/')?;
                name_and_suffix.strip_suffix(self.suffix).map(str::to_string)
            }
        }
    }

    /// Every archived etag for `name`, sorted. There is deliberately no
    /// "rollback" method — restoring an old version is just [`Self::get_version`]
    /// followed by [`Self::put_versioned`], composed by the caller.
    pub async fn list_versions(&self, backend: &dyn Backend, name: &str) -> Result<Vec<String>> {
        let scan_prefix = format!("{}/", self.history_prefix(name)?);
        let mut etags: Vec<String> = list_all_keys(backend, &scan_prefix)
            .await?
            .into_iter()
            .filter_map(|key| {
                let rest = key.strip_prefix(&scan_prefix)?;
                // `.meta.json` companions carry `Self::version_timestamp`,
                // not an archived value themselves.
                if rest.ends_with(".meta.json") {
                    return None;
                }
                rest.strip_suffix(".json").map(str::to_string)
            })
            .collect();
        etags.sort();
        Ok(etags)
    }

    /// Reads one archived version of `name`. `None` if that particular
    /// historical entry doesn't exist (same "missing" convention as
    /// [`Self::get`], not `get_json`'s raw `T::default()`).
    pub async fn get_version<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        etag: &str,
    ) -> Result<Option<T>> {
        let (value, found_etag) = get_json::<T>(backend, &self.history_key(name, etag)?, cipher).await?;
        Ok(found_etag.is_some().then_some(value))
    }

    /// Every stored value, fetched concurrently. Missing/failed fetches are
    /// dropped rather than propagated (a name can vanish between the list
    /// and the get); unordered — sort by whatever field matters to the
    /// caller.
    ///
    /// Concurrency is bounded by [`MemoryBudget::default`]. Use
    /// [`Self::list_all_with_budget`] to size it for the memory the calling
    /// process can actually spare.
    pub async fn list_all<T>(&self, backend: &Arc<dyn Backend>, cipher: &Arc<Cipher>) -> Result<Vec<T>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        self.list_all_with_budget(backend, cipher, MemoryBudget::default())
            .await
    }

    /// [`Self::list_all`] with an explicit fan-out budget.
    ///
    /// This used to spawn one unbounded task per name, which on a
    /// collection of a few thousand entries meant a few thousand
    /// simultaneous in-flight `get`s — every one of them buffering a
    /// response body up to [`crate::payload::MAX_OBJECT_BYTES`], and every
    /// one of them competing for the same connection pool. [`BatchLoader`]
    /// already had exactly the right bounded-fan-out shape for this
    /// (`max_buffer_bytes / MAX_OBJECT_BYTES` permits, which is precisely
    /// how many max-sized objects can be buffered at once within the
    /// budget), so this delegates to it rather than growing a second
    /// copy of that logic.
    pub async fn list_all_with_budget<T>(
        &self,
        backend: &Arc<dyn Backend>,
        cipher: &Arc<Cipher>,
        budget: MemoryBudget,
    ) -> Result<Vec<T>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        let names = self.list_names(backend.as_ref()).await?;
        let mut keys = Vec::with_capacity(names.len());
        for name in &names {
            keys.push(self.key(name)?);
        }
        let loaded = BatchLoader::new(budget).load_many::<T>(backend, cipher, keys).await;
        // Same tolerance as before: a name that vanished between the list
        // and the get (`Ok(None)`), or a fetch that genuinely failed
        // (`Err`), is dropped rather than failing the whole listing.
        Ok(loaded
            .into_values()
            .filter_map(|result| result.ok().flatten())
            .collect())
    }

    /// [`Self::list_all`] plus an in-memory filter. **O(n) in the
    /// collection's total size, every call** — there is no native
    /// server-side query in S3, so this is a full fetch-everything-then-
    /// filter, only appropriate for admin/debug tooling or genuinely small
    /// collections. A field that needs fast lookup by value belongs behind
    /// a [`crate::SecondaryIndex`] instead, maintained on write, not
    /// scanned on read.
    pub async fn find_all<T>(
        &self,
        backend: &Arc<dyn Backend>,
        cipher: &Arc<Cipher>,
        predicate: impl Fn(&T) -> bool,
    ) -> Result<Vec<T>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        self.find_all_with_budget(backend, cipher, MemoryBudget::default(), predicate)
            .await
    }

    /// [`Self::find_all`] with an explicit fan-out budget, see
    /// [`Self::list_all_with_budget`].
    pub async fn find_all_with_budget<T>(
        &self,
        backend: &Arc<dyn Backend>,
        cipher: &Arc<Cipher>,
        budget: MemoryBudget,
        predicate: impl Fn(&T) -> bool,
    ) -> Result<Vec<T>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        Ok(self
            .list_all_with_budget::<T>(backend, cipher, budget)
            .await?
            .into_iter()
            .filter(predicate)
            .collect())
    }
}

/// A single JSON object at one fixed key — no name dimension, unlike
/// [`Collection`]. For server-wide config where there's exactly one of the
/// thing, not a set of them.
#[derive(Debug, Clone, Copy)]
pub struct Singleton {
    pub key: &'static str,
}

impl Singleton {
    pub const fn new(key: &'static str) -> Self {
        Singleton { key }
    }

    /// `get_json`'s own convention: `T::default()`, not an `Option`, when
    /// nothing has been written yet — for a singleton, "doesn't exist" and
    /// "still at its defaults" are the same thing.
    pub async fn get<T: DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
    ) -> Result<(T, Option<String>)> {
        get_json(backend, self.key, cipher).await
    }

    pub async fn put<T: Serialize>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        value: &T,
        expected_etag: Option<&str>,
    ) -> Result<Cas> {
        put_json(backend, self.key, value, expected_etag, cipher).await
    }

    /// [`Collection::update`] against this singleton's one fixed key --
    /// same CAS-retry contract, including the requirement that `mutate` be
    /// a pure function of the value it's handed.
    pub async fn update<T, F>(&self, backend: &dyn Backend, cipher: &Cipher, mutate: F) -> Result<T>
    where
        T: Clone + Serialize + DeserializeOwned + Default,
        F: FnMut(&mut T) -> Result<Update>,
    {
        update_at_key(backend, cipher, self.key, mutate).await
    }
}

/// The CAS read-modify-write loop behind [`Collection::update`] and
/// [`Singleton::update`] -- the two differ only in how they arrive at a
/// key, so the retry contract lives here once instead of in both.
async fn update_at_key<T, F>(backend: &dyn Backend, cipher: &Cipher, key: &str, mut mutate: F) -> Result<T>
where
    T: Clone + Serialize + DeserializeOwned + Default,
    F: FnMut(&mut T) -> Result<Update>,
{
    for attempt in 0..MAX_UPDATE_ATTEMPTS {
        let (stored, etag) = get_json::<T>(backend, key, cipher).await?;
        // `mutate` gets a copy, so answering `Keep` can return the value as
        // it actually stands in the backend rather than whatever the
        // mutator happened to leave in the buffer before deciding not to
        // write it. One clone per attempt, of a type already bounded by
        // `MAX_OBJECT_BYTES`, buys a `Keep` that can't lie.
        let mut next = stored.clone();
        if mutate(&mut next)? == Update::Keep {
            return Ok(stored);
        }
        match put_json(backend, key, &next, etag.as_deref(), cipher).await? {
            Cas::Ok => return Ok(next),
            // Someone else wrote between our read and our put, so the value
            // `mutate` just produced was derived from stale input and gets
            // discarded. Back off with jitter before re-reading: under a
            // herd of writers on one key (a counter), retrying in lockstep
            // just reproduces the same collision.
            Cas::Conflict => {
                tokio::time::sleep(crate::resilience::full_jitter_backoff(UPDATE_BASE_BACKOFF, attempt)).await;
            }
        }
    }
    bail!("update: too many CAS conflicts on {key} (gave up after {MAX_UPDATE_ATTEMPTS} attempts)")
}

#[cfg(test)]
#[path = "../tests/unit/collection.rs"]
mod tests;
