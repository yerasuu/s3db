use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[9u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
    name: String,
}

#[tokio::test]
async fn put_then_get_roundtrips_through_messagepack() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put_json(
        &backend,
        "k",
        &Widget {
            count: 3,
            name: "a".into(),
        },
        None,
        &cipher,
    )
    .await
    .unwrap();
    let (value, etag): (Widget, _) = get_json(&backend, "k", &cipher).await.unwrap();
    assert_eq!(
        value,
        Widget {
            count: 3,
            name: "a".into()
        }
    );
    assert!(etag.is_some());
}

#[tokio::test]
async fn put_json_rejects_an_object_over_the_size_limit() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let big = Widget {
        count: 1,
        name: "x".repeat(MAX_OBJECT_BYTES),
    };
    assert!(put_json(&backend, "k", &big, None, &cipher).await.is_err());
}

#[tokio::test]
async fn get_json_plain_stays_readable_as_plain_json() {
    let dir = tempfile::tempdir().unwrap();
    let backend = LocalBackend::new(&LocalParams {
        bucket: dir.path().to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    });
    put_json_plain(
        &backend,
        "k",
        &Widget {
            count: 5,
            name: "plain".into(),
        },
        None,
    )
    .await
    .unwrap();
    let (raw, _etag) = backend.get("k").await.unwrap();
    // Genuinely human-readable JSON on the wire, not MessagePack.
    assert!(serde_json::from_slice::<serde_json::Value>(&raw).is_ok());
    let (value, _etag): (Widget, _) = get_json_plain(&backend, "k").await.unwrap();
    assert_eq!(
        value,
        Widget {
            count: 5,
            name: "plain".into()
        }
    );
}

/// A backend whose deletes never land — the "backend is refusing these
/// deletes" case `delete_prefix` must detect instead of burning its whole
/// pass budget re-listing the same keys.
#[derive(Debug)]
struct NeverDeletesBackend {
    inner: LocalBackend,
    passes: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Backend for NeverDeletesBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        self.inner.get(key).await
    }
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        self.inner.put_cas(key, body, expected_etag).await
    }
    async fn delete(&self, _key: &str) -> Result<crate::backend::DeleteOutcome> {
        Ok(crate::backend::DeleteOutcome {
            attempted: 1,
            confirmed: 0,
        })
    }
    async fn delete_many(&self, keys: &[String]) -> Result<crate::backend::DeleteOutcome> {
        self.passes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::backend::DeleteOutcome {
            attempted: keys.len(),
            confirmed: 0,
        })
    }
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        self.inner.list_prefix(prefix).await
    }
    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.inner.get_range(key, offset, len).await
    }
    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &std::path::Path) -> Result<()> {
        self.inner.put_stream(key, source).await
    }
    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &std::path::Path) -> Result<()> {
        self.inner.get_stream(key, dest).await
    }
}

#[tokio::test]
async fn delete_prefix_clears_only_its_own_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, _cipher) = test_backend_and_cipher(dir.path());
    for key in ["work/a/1", "work/a/2", "work/a/nested/3", "work/b/1"] {
        backend.put_cas(key, b"body".to_vec(), None).await.unwrap();
    }

    let report = delete_prefix(&backend, "work/a/").await.unwrap();

    assert!(report.is_complete(), "{report:?}");
    assert_eq!(report.confirmed, 3);
    assert_eq!(list_all_keys(&backend, "work/a/").await.unwrap(), Vec::<String>::new());
    assert_eq!(
        list_all_keys(&backend, "work/b/").await.unwrap().len(),
        1,
        "a sibling prefix must be untouched"
    );
}

#[tokio::test]
async fn delete_prefix_refuses_an_empty_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, _cipher) = test_backend_and_cipher(dir.path());
    backend.put_cas("k", b"body".to_vec(), None).await.unwrap();

    assert!(delete_prefix(&backend, "").await.is_err());
    assert_eq!(list_all_keys(&backend, "").await.unwrap().len(), 1, "nothing may be deleted");
}

#[tokio::test]
async fn delete_prefix_reports_what_it_could_not_delete_without_spinning() {
    let dir = tempfile::tempdir().unwrap();
    let (inner, _cipher) = test_backend_and_cipher(dir.path());
    for key in ["work/a/1", "work/a/2"] {
        inner.put_cas(key, b"body".to_vec(), None).await.unwrap();
    }
    let backend = NeverDeletesBackend {
        inner,
        passes: std::sync::atomic::AtomicUsize::new(0),
    };

    let report = delete_prefix(&backend, "work/a/").await.unwrap();

    assert!(!report.is_complete(), "{report:?}");
    assert_eq!(report.remaining, 2);
    assert_eq!(report.confirmed, 0);
    assert_eq!(
        backend.passes.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a pass that confirms nothing must stop the sweep, not retry it"
    );
}

#[tokio::test]
async fn count_prefix_counts_keys_and_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, _cipher) = test_backend_and_cipher(dir.path());
    backend.put_cas("c/1", vec![0u8; 10], None).await.unwrap();
    backend.put_cas("c/2", vec![0u8; 25], None).await.unwrap();
    backend.put_cas("other/1", vec![0u8; 99], None).await.unwrap();

    assert_eq!(count_prefix(&backend, "c/").await.unwrap(), (2, 35));
    assert_eq!(count_prefix(&backend, "nothing/").await.unwrap(), (0, 0));
}
