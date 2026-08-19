use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;
use crate::metrics::NoopMetrics;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[13u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Pointer {
    owner: String,
}

#[tokio::test]
async fn claim_then_resolve_roundtrips_with_no_rebalance() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = ShardedIndex::new(".conf/index", "pubkey", Segment::Base64);
    assert!(
        idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() })
            .await
            .unwrap()
    );
    let (resolved, _etag) = idx.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(resolved, Some(Pointer { owner: "alice".into() }));
}

#[tokio::test]
async fn rebalance_keeps_every_entry_resolvable_throughout() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);

    let names: Vec<String> = (0..50).map(|i| format!("user-{i}")).collect();
    for name in &names {
        assert!(
            idx.claim_once(&backend, &cipher, name, &Pointer { owner: name.clone() })
                .await
                .unwrap()
        );
    }

    idx.begin_rebalance(&backend, &cipher).await.unwrap();
    // Mid-rebalance: every entry (still under the old layout) must
    // still resolve.
    for name in &names {
        let (resolved, _) = idx.resolve::<Pointer>(&backend, &cipher, name).await.unwrap();
        assert_eq!(
            resolved,
            Some(Pointer { owner: name.clone() }),
            "{name} must resolve mid-rebalance"
        );
    }
    // And a claim on a brand-new name during the rebalance must still
    // land on the OLD layout (writers pinned until complete_rebalance).
    assert!(
        idx.claim_once(
            &backend,
            &cipher,
            "new-during-rebalance",
            &Pointer { owner: "x".into() }
        )
        .await
        .unwrap()
    );

    idx.complete_rebalance(&backend, &cipher).await.unwrap();
    for name in &names {
        let (resolved, _) = idx.resolve::<Pointer>(&backend, &cipher, name).await.unwrap();
        assert_eq!(
            resolved,
            Some(Pointer { owner: name.clone() }),
            "{name} must resolve after rebalance completes"
        );
    }
    let (resolved, _) = idx
        .resolve::<Pointer>(&backend, &cipher, "new-during-rebalance")
        .await
        .unwrap();
    assert_eq!(resolved, Some(Pointer { owner: "x".into() }));

    // No rebalance left in flight.
    let (epoch, _) = get_json::<ShardEpoch>(&backend, &idx.epoch_key(), &cipher)
        .await
        .unwrap();
    assert!(epoch.prev_prefix_bits.is_none());
}

#[tokio::test]
async fn begin_rebalance_refuses_to_stack_a_second_one() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);
    idx.begin_rebalance(&backend, &cipher).await.unwrap();
    assert!(idx.begin_rebalance(&backend, &cipher).await.is_err());
}

#[tokio::test]
async fn release_removes_the_entry_from_whichever_layout_it_is_in() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);
    idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "alice".into() })
        .await
        .unwrap();
    idx.release(&backend, &cipher, "alice").await.unwrap();
    let (resolved, _) = idx.resolve::<Pointer>(&backend, &cipher, "alice").await.unwrap();
    assert_eq!(resolved, None);
}

#[tokio::test]
async fn maybe_rebalance_triggers_once_a_shard_crosses_the_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);
    for i in 0..20 {
        idx.claim_once(&backend, &cipher, &format!("user-{i}"), &Pointer { owner: "x".into() })
            .await
            .unwrap();
    }
    let triggered = idx.maybe_rebalance(&backend, &cipher, &NoopMetrics, 10).await.unwrap();
    assert!(triggered);
    let (epoch, _) = get_json::<ShardEpoch>(&backend, &idx.epoch_key(), &cipher)
        .await
        .unwrap();
    assert!(epoch.prev_prefix_bits.is_some());
}

#[tokio::test]
async fn maybe_rebalance_stays_put_under_the_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let idx = ShardedIndex::new(".conf/index", "namespace", Segment::Raw);
    idx.claim_once(&backend, &cipher, "alice", &Pointer { owner: "x".into() })
        .await
        .unwrap();
    let triggered = idx
        .maybe_rebalance(&backend, &cipher, &NoopMetrics, 1000)
        .await
        .unwrap();
    assert!(!triggered);
}
