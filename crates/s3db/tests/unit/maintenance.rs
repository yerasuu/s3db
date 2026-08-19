use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;
use std::time::Duration;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[29u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
}

#[tokio::test]
async fn run_sweeps_every_registered_collection() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let widgets = Collection::new("widgets");
    let gadgets = Collection::new("gadgets");
    widgets
        .put(&backend, &cipher, "a", &Widget { count: 1 }, None)
        .await
        .unwrap();
    widgets.delete(&backend, &cipher, "a").await.unwrap();
    gadgets
        .put(&backend, &cipher, "b", &Widget { count: 2 }, None)
        .await
        .unwrap();
    gadgets.delete(&backend, &cipher, "b").await.unwrap();

    let scanner = MaintenanceScanner::new(GcConfig {
        tombstone_purge_age: Duration::ZERO,
        ..GcConfig::default()
    });
    let reports = scanner.run(&backend, &cipher, &[&widgets, &gadgets]).await.unwrap();

    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].tombstones_forgotten, 1);
    assert_eq!(reports[1].tombstones_forgotten, 1);
}
