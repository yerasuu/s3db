use super::*;
use crate::local::LocalBackend;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&crate::config::LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: crate::config::LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[9u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
}

async fn request(app: Router, uri: &str) -> (axum::http::StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(uri)
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, body)
}

#[tokio::test]
async fn discovers_lists_and_reads_a_collection() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let coll = Collection::new("widgets");
    coll.put(&backend, &cipher, "alice", &Widget { count: 1 }, None)
        .await
        .unwrap();

    let backend: Arc<dyn Backend> = Arc::new(backend);
    let state = AppState { backend, cipher };

    let (status, body) = request(router(state.clone()), "/collections").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["collections"], serde_json::json!(["widgets"]));

    let (status, body) = request(router(state.clone()), "/collections/widgets").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["entries"], serde_json::json!(["alice"]));

    let (status, body) = request(router(state.clone()), "/collections/widgets/alice").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(body["count"], 1);

    let (status, _) = request(router(state.clone()), "/collections/widgets/missing").await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn rejects_a_collection_name_that_would_reach_reserved_bookkeeping() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let backend: Arc<dyn Backend> = Arc::new(backend);
    let state = AppState { backend, cipher };

    let (status, _) = request(router(state.clone()), "/collections/.conf").await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);

    let (status, _) = request(router(state), "/collections/widgets/.deleted").await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
}
