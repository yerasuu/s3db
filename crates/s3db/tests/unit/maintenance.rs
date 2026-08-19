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
    assert_eq!(reports[0].gc.tombstones_forgotten, 1);
    assert_eq!(reports[1].gc.tombstones_forgotten, 1);
}

/// The scanner is the one place an app wires periodic work, so an expiry that
/// only fires when a caller remembers to call `ttl::expire_due` separately is
/// an expiry that silently doesn't happen.
#[tokio::test]
async fn the_scanner_also_expires_due_entries() {
    #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Session {
        token: String,
    }
    const SESSIONS: Collection = Collection::new("sessions");

    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    SESSIONS
        .put(&backend, &cipher, "gone", &Session { token: "x".into() }, None)
        .await
        .unwrap();
    SESSIONS
        .put(&backend, &cipher, "kept", &Session { token: "y".into() }, None)
        .await
        .unwrap();
    // One deadline already in the past, one far in the future.
    crate::ttl::set_expiry(&backend, &cipher, &SESSIONS, "gone", 1)
        .await
        .unwrap();
    crate::ttl::set_ttl(&backend, &cipher, &SESSIONS, "kept", 3_600_000)
        .await
        .unwrap();

    let reports = MaintenanceScanner::new(GcConfig::default())
        .run(&backend, &cipher, &[&SESSIONS])
        .await
        .unwrap();

    assert_eq!(reports[0].expiry.expired, 1);
    assert_eq!(
        SESSIONS.get::<Session>(&backend, &cipher, "gone").await.unwrap().0,
        None
    );
    assert!(
        SESSIONS
            .get::<Session>(&backend, &cipher, "kept")
            .await
            .unwrap()
            .0
            .is_some(),
        "a future deadline must survive the scanner"
    );
}
