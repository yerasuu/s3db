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
