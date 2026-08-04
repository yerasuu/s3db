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
use std::sync::Arc;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Copy)]
pub struct Collection {
    pub prefix: &'static str,
}

impl Collection {
    pub const fn new(prefix: &'static str) -> Self {
        Collection { prefix }
    }

    pub fn key(&self, name: &str) -> String {
        format!("{}/{name}.json", self.prefix)
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
            .filter_map(|key| key.strip_prefix(&scan_prefix)?.strip_suffix(".json").map(str::to_string))
            .collect();
        names.sort();
        Ok(names)
    }

    /// Every stored value, fetched concurrently. Missing/failed fetches are
    /// dropped rather than propagated (a name can vanish between the list
    /// and the get); unordered — sort by whatever field matters to the
    /// caller.
    pub async fn list_all<T>(&self, backend: &Arc<dyn Backend>, cipher: &Arc<Cipher>) -> Result<Vec<T>>
    where
        T: DeserializeOwned + Default + Send + 'static,
    {
        let prefix = self.prefix;
        let names = self.list_names(backend.as_ref()).await?;
        let mut set = JoinSet::new();
        for name in names {
            let backend = Arc::clone(backend);
            let cipher = Arc::clone(cipher);
            set.spawn(async move {
                let key = format!("{prefix}/{name}.json");
                get_json::<T>(backend.as_ref(), &key, &cipher).await
            });
        }
        let mut items = Vec::new();
        while let Some(result) = set.join_next().await {
            if let Ok(Ok((value, Some(_etag)))) = result {
                items.push(value);
            }
        }
        Ok(items)
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
}
