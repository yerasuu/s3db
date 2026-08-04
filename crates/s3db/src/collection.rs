//! Typed CRUD over a set of JSON objects that all share one key prefix
//! (`{prefix}/{name}.json`) — the shape every entity kind (users, groups,
//! repo configs, server settings, ...) turned out to need, previously
//! hand-written once per entity.

use crate::backend::{Backend, Cas};
use crate::cipher::{Cipher, CompressionStrategy};
use crate::payload::{delete_object, get_json, list_all_keys, put_json};
use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinSet;

/// Real wall-clock time, not a deterministic-replay clock -- only ever
/// stored for humans/audits to read later, same reasoning as
/// `crate::txn::now_ms`.
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock before unix epoch").as_millis() as u64
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

/// `Cow` rather than a plain `&'static str`: most collections (users,
/// groups, ...) have a fixed prefix known at compile time, but a few are
/// scoped per-call to some runtime value (e.g. "every permission grant
/// under this one repo uid") — same CRUD/list shape either way, so both get
/// to share it instead of the runtime-scoped ones reimplementing it by hand.
#[derive(Debug, Clone)]
pub struct Collection {
    pub prefix: Cow<'static, str>,
    /// Appended after `name` to form the full key — `.json` for a flat
    /// `{prefix}/{name}.json` layout, or something like
    /// `/.conf/config.json` for an entity whose object lives one level
    /// deeper than its own name (e.g. a repo's config, nested under the
    /// repo's own storage prefix rather than sitting flat next to it).
    pub suffix: &'static str,
}

impl Collection {
    pub const fn new(prefix: &'static str) -> Self {
        Collection { prefix: Cow::Borrowed(prefix), suffix: ".json" }
    }

    pub const fn new_with_suffix(prefix: &'static str, suffix: &'static str) -> Self {
        Collection { prefix: Cow::Borrowed(prefix), suffix }
    }

    pub fn new_owned(prefix: String) -> Self {
        Collection { prefix: Cow::Owned(prefix), suffix: ".json" }
    }

    pub fn key(&self, name: &str) -> String {
        format!("{}/{name}{}", self.prefix, self.suffix)
    }

    /// Namespace for `name`'s archived versions — parallel to (not nested
    /// inside) `name`'s own [`Self::key`], so it's independent of whatever
    /// `suffix` this collection uses for its main entries.
    fn history_prefix(&self, name: &str) -> String {
        format!("{}/.history/{name}", self.prefix)
    }

    /// Where [`Self::delete`]'s tombstone for `name` lives -- parallel to
    /// (not nested inside) `name`'s own [`Self::key`] and [`Self::history_prefix`],
    /// same reasoning as both: independent of whatever `suffix` this
    /// collection uses for its main entries.
    fn tombstone_key(&self, name: &str) -> String {
        format!("{}/.deleted/{name}.json", self.prefix)
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
        let (value, etag) = get_json::<T>(backend, &self.key(name), cipher).await?;
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
        get_json(backend, &self.key(name), cipher).await
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
        put_json(backend, &self.key(name), value, expected_etag, cipher).await
    }

    /// Same compare-and-swap write as [`Self::put`], but archives whatever
    /// value it's about to overwrite first — under the etag it had, so
    /// [`Self::get_version`] can later fetch it back by that same etag.
    /// `expected_etag = None` (fresh create) has nothing to archive, since
    /// there's no prior value.
    pub async fn put_versioned<T: Serialize + DeserializeOwned + Default>(
        &self,
        backend: &dyn Backend,
        cipher: &Cipher,
        name: &str,
        value: &T,
        expected_etag: Option<&str>,
    ) -> Result<Cas> {
        if let Some(etag) = expected_etag {
            let (current_value, current_etag) = self.get::<T>(backend, cipher, name).await?;
            if let (Some(current_value), Some(current_etag)) = (current_value, current_etag)
                && current_etag == etag
            {
                // Idempotent: the same etag always archives the same
                // content, so `Cas::Conflict` here just means someone else
                // already wrote this exact archive entry — fine. Only a
                // genuine `Err` (backend/serialization failure) needs to
                // propagate.
                put_json(backend, &format!("{}/{etag}.json", self.history_prefix(name)), &current_value, None, cipher).await?;
            }
        }
        self.put(backend, cipher, name, value, expected_etag).await
    }

    /// Soft-delete: archives whatever value currently lives at `name` (so
    /// [`Self::restore`] has something to bring back), writes a `Pending`
    /// tombstone recording that archive's etag, then best-effort-deletes the
    /// real object -- marking the tombstone `Purged` only once that
    /// underlying delete actually confirms (or the object was already
    /// gone). A delete that fails to land leaves the tombstone `Pending`: a
    /// durable, inspectable record that this key still owes a real purge,
    /// instead of a lost fire-and-forget with no trace anyone could act on.
    pub async fn delete(&self, backend: &dyn Backend, cipher: &Cipher, name: &str) {
        let key = self.key(name);
        let (sealed, etag) = match backend.get(&key).await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("warning: couldn't read {name} before deleting it: {e:#}");
                (Vec::new(), None)
            }
        };
        let restore_etag = self.archive_for_delete(backend, cipher, name, &key, &sealed, etag.as_deref()).await;

        let tombstone_key = self.tombstone_key(name);
        let (_, tomb_etag) = get_json::<Tombstone>(backend, &tombstone_key, cipher).await.unwrap_or_default();
        let pending = Tombstone { deleted_at_ms: now_ms(), purge_state: PurgeState::Pending, restore_etag };
        if put_json(backend, &tombstone_key, &pending, tomb_etag.as_deref(), cipher).await.is_err() {
            return; // couldn't even record intent -- nothing to retry from, bail
        }

        let confirmed = backend.delete(&key).await.map(|o| o.confirmed == o.attempted).unwrap_or(false);
        if confirmed {
            // Re-read for a fresh etag rather than reusing the one from the
            // `put_json` above (which only returns `Cas`, never the etag it
            // just wrote) -- same technique `txn::run` uses for its own
            // record.
            if let Ok((_, fresh_etag)) = get_json::<Tombstone>(backend, &tombstone_key, cipher).await {
                let purged = Tombstone { purge_state: PurgeState::Purged, ..pending };
                let _ = put_json(backend, &tombstone_key, &purged, fresh_etag.as_deref(), cipher).await;
            }
        }
        // Else: leave `Pending` -- there's no GC sweep to retry it yet, but
        // the record is there for whenever one exists.
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
    async fn archive_for_delete(&self, backend: &dyn Backend, cipher: &Cipher, name: &str, key: &str, sealed: &[u8], etag: Option<&str>) -> Option<String> {
        let etag = etag?;
        let plaintext = match cipher.open(key, sealed) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: couldn't decrypt {name} to archive it before deleting: {e:#}");
                return None;
            }
        };
        let history_key = format!("{}/{etag}.json", self.history_prefix(name));
        let resealed = cipher.seal(&history_key, &plaintext, CompressionStrategy::None);
        // Create-only, but idempotent in practice: the same etag always
        // archives the same content, so a `Cas::Conflict` here just means
        // this exact archive entry already exists (a prior delete attempt
        // that got this far but failed later) -- fine either way.
        match backend.put_cas(&history_key, resealed, None).await {
            Ok(_) => Some(etag.to_string()),
            Err(e) => {
                eprintln!("warning: couldn't archive {name} before deleting it: {e:#}");
                None
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
    pub async fn restore<T: Serialize + DeserializeOwned + Default>(&self, backend: &dyn Backend, cipher: &Cipher, name: &str) -> Result<()> {
        let tombstone_key = self.tombstone_key(name);
        let (tombstone, _) = get_json::<Tombstone>(backend, &tombstone_key, cipher).await?;
        let etag = tombstone.restore_etag.context("nothing to restore: no archived version for this name")?;
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
    async fn write_object_for_restore<T: Serialize>(&self, backend: &dyn Backend, cipher: &Cipher, name: &str, value: &T) -> Result<()> {
        let key = self.key(name);
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

    /// Every name currently stored, sorted.
    pub async fn list_names(&self, backend: &dyn Backend) -> Result<Vec<String>> {
        let scan_prefix = format!("{}/", self.prefix);
        let mut names: Vec<String> = list_all_keys(backend, &scan_prefix)
            .await?
            .into_iter()
            .filter_map(|key| {
                let rest = key.strip_prefix(&scan_prefix)?;
                // `.history/`/`.deleted/` are this collection's own internal
                // bookkeeping (archived versions, tombstones — see
                // `Self::history_prefix`/`Self::tombstone_key`), not real
                // entries; a real `name` never starts with `.` in practice
                // (usernames, uids, ...), but this checks the exact two
                // reserved prefixes rather than relying on that.
                if rest.starts_with(".history/") || rest.starts_with(".deleted/") {
                    return None;
                }
                rest.strip_suffix(self.suffix).map(str::to_string)
            })
            .collect();
        names.sort();
        Ok(names)
    }

    /// Every archived etag for `name`, sorted. There is deliberately no
    /// "rollback" method — restoring an old version is just [`Self::get_version`]
    /// followed by [`Self::put_versioned`], composed by the caller.
    pub async fn list_versions(&self, backend: &dyn Backend, name: &str) -> Result<Vec<String>> {
        let scan_prefix = format!("{}/", self.history_prefix(name));
        let mut etags: Vec<String> = list_all_keys(backend, &scan_prefix)
            .await?
            .into_iter()
            .filter_map(|key| key.strip_prefix(&scan_prefix)?.strip_suffix(".json").map(str::to_string))
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
        let (value, found_etag) = get_json::<T>(backend, &format!("{}/{etag}.json", self.history_prefix(name)), cipher).await?;
        Ok(found_etag.is_some().then_some(value))
    }

    /// Every stored value, fetched concurrently. Missing/failed fetches are
    /// dropped rather than propagated (a name can vanish between the list
    /// and the get); unordered — sort by whatever field matters to the
    /// caller.
    pub async fn list_all<T>(&self, backend: &Arc<dyn Backend>, cipher: &Arc<Cipher>) -> Result<Vec<T>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        let names = self.list_names(backend.as_ref()).await?;
        let mut set = JoinSet::new();
        for name in names {
            let key = self.key(&name);
            let backend = Arc::clone(backend);
            let cipher = Arc::clone(cipher);
            set.spawn(async move { get_json::<T>(backend.as_ref(), &key, &cipher).await });
        }
        let mut items = Vec::new();
        while let Some(result) = set.join_next().await {
            if let Ok(Ok((value, Some(_etag)))) = result {
                items.push(value);
            }
        }
        Ok(items)
    }

    /// [`Self::list_all`] plus an in-memory filter. **O(n) in the
    /// collection's total size, every call** — there is no native
    /// server-side query in S3, so this is a full fetch-everything-then-
    /// filter, only appropriate for admin/debug tooling or genuinely small
    /// collections. A field that needs fast lookup by value belongs behind
    /// a [`crate::SecondaryIndex`] instead, maintained on write, not
    /// scanned on read.
    pub async fn find_all<T>(&self, backend: &Arc<dyn Backend>, cipher: &Arc<Cipher>, predicate: impl Fn(&T) -> bool) -> Result<Vec<T>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        Ok(self.list_all::<T>(backend, cipher).await?.into_iter().filter(predicate).collect())
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
    pub async fn get<T: DeserializeOwned + Default>(&self, backend: &dyn Backend, cipher: &Cipher) -> Result<(T, Option<String>)> {
        get_json(backend, self.key, cipher).await
    }

    pub async fn put<T: Serialize>(&self, backend: &dyn Backend, cipher: &Cipher, value: &T, expected_etag: Option<&str>) -> Result<Cas> {
        put_json(backend, self.key, value, expected_etag, cipher).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::LocalBackend;

    fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
        let backend = LocalBackend::new(&crate::config::LocalParams { bucket: root.to_string_lossy().to_string() });
        let cipher = Cipher::derive("test passphrase", &[5u8; crate::cipher::SALT_LEN]).unwrap();
        (backend, cipher)
    }

    #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Widget {
        count: u32,
    }

    #[tokio::test]
    async fn get_is_none_before_any_put() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        let (value, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        assert_eq!(value, None);
        assert_eq!(etag, None);
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        let cas = coll.put(&backend, &cipher, "a", &Widget { count: 3 }, None).await.unwrap();
        assert_eq!(cas, Cas::Ok);
        let (value, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        assert_eq!(value, Some(Widget { count: 3 }));
        assert!(etag.is_some());
    }

    #[tokio::test]
    async fn put_conflicts_on_stale_etag() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();
        let cas = coll.put(&backend, &cipher, "a", &Widget { count: 2 }, None).await.unwrap();
        assert_eq!(cas, Cas::Conflict);
    }

    #[tokio::test]
    async fn delete_makes_get_report_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();
        coll.delete(&backend, &cipher, "a").await;
        let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn delete_writes_a_purged_tombstone_with_a_restore_etag() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();
        coll.delete(&backend, &cipher, "a").await;

        let (tombstone, _) = get_json::<Tombstone>(&backend, &coll.tombstone_key("a"), &cipher).await.unwrap();
        assert_eq!(tombstone.purge_state, PurgeState::Purged);
        assert!(tombstone.restore_etag.is_some());
    }

    #[tokio::test]
    async fn delete_of_a_never_written_name_leaves_nothing_to_restore() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.delete(&backend, &cipher, "ghost").await;

        let (tombstone, _) = get_json::<Tombstone>(&backend, &coll.tombstone_key("ghost"), &cipher).await.unwrap();
        assert_eq!(tombstone.restore_etag, None);
        assert!(coll.restore::<Widget>(&backend, &cipher, "ghost").await.is_err());
    }

    #[tokio::test]
    async fn restore_brings_back_the_deleted_value_and_clears_the_tombstone() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();
        coll.delete(&backend, &cipher, "a").await;

        coll.restore::<Widget>(&backend, &cipher, "a").await.unwrap();

        let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        assert_eq!(value, Some(Widget { count: 1 }));
        let (_, tomb_etag) = get_json::<Tombstone>(&backend, &coll.tombstone_key("a"), &cipher).await.unwrap();
        assert!(tomb_etag.is_none(), "tombstone must be gone after a successful restore");
    }

    #[tokio::test]
    async fn restore_overwrites_whatever_object_currently_occupies_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();
        coll.delete(&backend, &cipher, "a").await;
        // Something re-occupies the now-empty key before the restore runs
        // -- `write_object_for_restore`'s CAS-with-reread must still win,
        // not bounce off a stale-etag conflict against it.
        coll.put(&backend, &cipher, "a", &Widget { count: 99 }, None).await.unwrap();

        coll.restore::<Widget>(&backend, &cipher, "a").await.unwrap();
        let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        assert_eq!(value, Some(Widget { count: 1 }));
    }

    #[tokio::test]
    async fn list_names_and_list_all_see_every_put_item() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let backend: Arc<dyn Backend> = Arc::new(backend);
        let cipher = Arc::new(cipher);
        let coll = Collection::new("widgets");
        for (name, count) in [("a", 1), ("b", 2), ("c", 3)] {
            coll.put(backend.as_ref(), cipher.as_ref(), name, &Widget { count }, None).await.unwrap();
        }
        let mut names = coll.list_names(backend.as_ref()).await.unwrap();
        names.sort();
        assert_eq!(names, vec!["a", "b", "c"]);

        let mut all: Vec<Widget> = coll.list_all(&backend, &cipher).await.unwrap();
        all.sort_by_key(|w| w.count);
        assert_eq!(all, vec![Widget { count: 1 }, Widget { count: 2 }, Widget { count: 3 }]);
    }

    #[tokio::test]
    async fn nested_suffix_roundtrips_and_lists_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new_with_suffix("repos", "/.conf/config.json");
        assert_eq!(coll.key("acme/web"), "repos/acme/web/.conf/config.json");
        coll.put(&backend, &cipher, "acme/web", &Widget { count: 9 }, None).await.unwrap();
        let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "acme/web").await.unwrap();
        assert_eq!(value, Some(Widget { count: 9 }));
        assert_eq!(coll.list_names(&backend).await.unwrap(), vec!["acme/web"]);
    }

    #[tokio::test]
    async fn get_or_default_returns_default_not_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        let (value, etag) = coll.get_or_default::<Widget>(&backend, &cipher, "missing").await.unwrap();
        assert_eq!(value, Widget::default());
        assert_eq!(etag, None);
    }

    #[tokio::test]
    async fn find_all_filters_by_predicate() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let backend: Arc<dyn Backend> = Arc::new(backend);
        let cipher = Arc::new(cipher);
        let coll = Collection::new("widgets");
        for (name, count) in [("a", 1), ("b", 2), ("c", 3)] {
            coll.put(backend.as_ref(), cipher.as_ref(), name, &Widget { count }, None).await.unwrap();
        }
        let mut big: Vec<Widget> = coll.find_all(&backend, &cipher, |w: &Widget| w.count > 1).await.unwrap();
        big.sort_by_key(|w| w.count);
        assert_eq!(big, vec![Widget { count: 2 }, Widget { count: 3 }]);
    }

    #[tokio::test]
    async fn singleton_put_then_get_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let settings = Singleton::new(".conf/global.json");
        let (value, etag) = settings.get::<Widget>(&backend, &cipher).await.unwrap();
        assert_eq!(value, Widget::default());
        assert_eq!(etag, None);

        settings.put(&backend, &cipher, &Widget { count: 7 }, None).await.unwrap();
        let (value, etag) = settings.get::<Widget>(&backend, &cipher).await.unwrap();
        assert_eq!(value, Widget { count: 7 });
        assert!(etag.is_some());
    }

    #[tokio::test]
    async fn put_versioned_fresh_create_archives_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();
        assert_eq!(coll.list_versions(&backend, "a").await.unwrap(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn put_versioned_update_archives_the_previous_value() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();
        let (_value, etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        let etag = etag.unwrap();

        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, Some(&etag)).await.unwrap();

        let versions = coll.list_versions(&backend, "a").await.unwrap();
        assert_eq!(versions.len(), 1);
        let archived: Widget = coll.get_version(&backend, &cipher, "a", &versions[0]).await.unwrap().unwrap();
        assert_eq!(archived, Widget { count: 1 });

        let (current, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        assert_eq!(current, Some(Widget { count: 2 }));
    }

    #[tokio::test]
    async fn manual_rollback_via_get_version_then_put_versioned() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");

        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();
        let (_value, etag1) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        let etag1 = etag1.unwrap();

        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, Some(&etag1)).await.unwrap();
        let (_value, etag2) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        let etag2 = etag2.unwrap();

        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 3 }, Some(&etag2)).await.unwrap();

        let versions = coll.list_versions(&backend, "a").await.unwrap();
        assert_eq!(versions.len(), 2);

        // Oldest archived version is the one written under etag1 (count: 1).
        let oldest: Widget = coll.get_version(&backend, &cipher, "a", &etag1).await.unwrap().unwrap();
        assert_eq!(oldest, Widget { count: 1 });

        let (_value, current_etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        let current_etag = current_etag.unwrap();
        coll.put_versioned(&backend, &cipher, "a", &oldest, Some(&current_etag)).await.unwrap();

        let (restored, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        assert_eq!(restored, Some(Widget { count: 1 }));
    }

    #[tokio::test]
    async fn put_versioned_conflicts_on_stale_etag_without_archiving() {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = test_backend_and_cipher(dir.path());
        let coll = Collection::new("widgets");
        coll.put_versioned(&backend, &cipher, "a", &Widget { count: 1 }, None).await.unwrap();

        let cas = coll.put_versioned(&backend, &cipher, "a", &Widget { count: 2 }, Some("stale-etag")).await.unwrap();
        assert_eq!(cas, Cas::Conflict);
        assert_eq!(coll.list_versions(&backend, "a").await.unwrap(), Vec::<String>::new());
    }
}
