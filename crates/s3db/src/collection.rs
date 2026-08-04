//! Typed CRUD over a set of JSON objects that all share one key prefix
//! (`{prefix}/{name}.json`) — the shape every entity kind (users, groups,
//! repo configs, server settings, ...) turned out to need, previously
//! hand-written once per entity.

use crate::backend::{Backend, Cas};
use crate::cipher::Cipher;
use crate::json::{delete_object, get_json, list_all_keys, put_json};
use anyhow::Result;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::borrow::Cow;
use std::sync::Arc;
use tokio::task::JoinSet;

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

    /// Best-effort delete — same contract as [`Backend::delete`].
    pub async fn delete(&self, backend: &dyn Backend, name: &str) {
        delete_object(backend, &self.key(name)).await;
    }

    /// Every name currently stored, sorted.
    pub async fn list_names(&self, backend: &dyn Backend) -> Result<Vec<String>> {
        let scan_prefix = format!("{}/", self.prefix);
        let mut names: Vec<String> = list_all_keys(backend, &scan_prefix)
            .await?
            .into_iter()
            .filter_map(|key| key.strip_prefix(&scan_prefix)?.strip_suffix(self.suffix).map(str::to_string))
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
        coll.delete(&backend, "a").await;
        let (value, _etag) = coll.get::<Widget>(&backend, &cipher, "a").await.unwrap();
        assert_eq!(value, None);
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
