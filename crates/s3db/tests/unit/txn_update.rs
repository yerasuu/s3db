use super::*;
use crate::config::{LocalEngine, LocalParams};
use crate::local::LocalBackend;
use crate::payload::list_all_keys;

fn backend_and_cipher(root: &std::path::Path, engine: LocalEngine) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine,
    });
    let cipher = Cipher::derive("test passphrase", &[23u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

async fn value_at(backend: &LocalBackend, cipher: &Cipher, key: &str) -> Option<i64> {
    let (value, etag) = get_json::<serde_json::Value>(backend, key, cipher).await.unwrap();
    etag.is_some().then(|| value.as_i64().unwrap_or_default())
}

async fn etag_of(backend: &LocalBackend, key: &str) -> Option<String> {
    backend.get(key).await.unwrap().1
}

async fn locks(backend: &LocalBackend) -> Vec<String> {
    list_all_keys(backend, ".conf/txn-update/.locks/").await.unwrap()
}

async fn records(backend: &LocalBackend) -> Vec<String> {
    list_all_keys(backend, ".conf/txn-update/")
        .await
        .unwrap()
        .into_iter()
        .filter(|key| !key.contains("/.locks/"))
        .collect()
}

/// The thing `txn::run` cannot express: two existing keys updated together.
#[tokio::test]
async fn updates_two_existing_keys_together() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = backend_and_cipher(dir.path(), engine);
        put_json(&backend, "a", &1i64, None, &cipher).await.unwrap();
        put_json(&backend, "b", &1i64, None, &cipher).await.unwrap();
        let (a_etag, b_etag) = (etag_of(&backend, "a").await, etag_of(&backend, "b").await);

        let report = run_update(
            &backend,
            &cipher,
            vec![
                UpdateOp::update("a".into(), &2i64, a_etag.as_deref().unwrap()).unwrap(),
                UpdateOp::update("b".into(), &2i64, b_etag.as_deref().unwrap()).unwrap(),
            ],
        )
        .await
        .unwrap();

        assert!(report.applied, "engine {engine:?}: {report:?}");
        assert!(report.overwrote_unlocked.is_empty(), "engine {engine:?}");
        assert_eq!(value_at(&backend, &cipher, "a").await, Some(2), "engine {engine:?}");
        assert_eq!(value_at(&backend, &cipher, "b").await, Some(2), "engine {engine:?}");
        assert!(
            locks(&backend).await.is_empty(),
            "engine {engine:?}: locks must be released"
        );
        assert!(
            records(&backend).await.is_empty(),
            "engine {engine:?}: record must be gone"
        );
    }
}

#[tokio::test]
async fn a_stale_expected_etag_applies_nothing() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let (backend, cipher) = backend_and_cipher(dir.path(), engine);
        put_json(&backend, "a", &1i64, None, &cipher).await.unwrap();
        put_json(&backend, "b", &1i64, None, &cipher).await.unwrap();
        let a_etag = etag_of(&backend, "a").await.unwrap();

        let report = run_update(
            &backend,
            &cipher,
            vec![
                UpdateOp::update("a".into(), &2i64, &a_etag).unwrap(),
                // A "current" etag that never existed.
                UpdateOp::update("b".into(), &2i64, "stale").unwrap(),
            ],
        )
        .await
        .unwrap();

        assert!(!report.applied, "engine {engine:?}: {report:?}");
        assert_eq!(
            value_at(&backend, &cipher, "a").await,
            Some(1),
            "engine {engine:?}: the op whose etag was fine must not have applied either"
        );
        assert_eq!(value_at(&backend, &cipher, "b").await, Some(1), "engine {engine:?}");
        assert!(locks(&backend).await.is_empty(), "engine {engine:?}");
        assert!(records(&backend).await.is_empty(), "engine {engine:?}");
    }
}

#[tokio::test]
async fn creates_and_updates_mix_in_one_batch() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    put_json(&backend, "existing", &1i64, None, &cipher).await.unwrap();
    let etag = etag_of(&backend, "existing").await.unwrap();

    let report = run_update(
        &backend,
        &cipher,
        vec![
            UpdateOp::update("existing".into(), &2i64, &etag).unwrap(),
            UpdateOp::create("fresh".into(), &7i64).unwrap(),
        ],
    )
    .await
    .unwrap();

    assert!(report.applied, "{report:?}");
    assert_eq!(value_at(&backend, &cipher, "existing").await, Some(2));
    assert_eq!(value_at(&backend, &cipher, "fresh").await, Some(7));
}

#[tokio::test]
async fn a_create_op_conflicts_when_the_key_already_exists() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    put_json(&backend, "taken", &1i64, None, &cipher).await.unwrap();

    let report = run_update(
        &backend,
        &cipher,
        vec![
            UpdateOp::create("free".into(), &1i64).unwrap(),
            UpdateOp::create("taken".into(), &9i64).unwrap(),
        ],
    )
    .await
    .unwrap();

    assert!(!report.applied, "{report:?}");
    assert_eq!(value_at(&backend, &cipher, "taken").await, Some(1));
    assert_eq!(
        value_at(&backend, &cipher, "free").await,
        None,
        "the create that could have succeeded must not have"
    );
}

/// The core mutual-exclusion claim: an overlapping transaction can't slip in.
#[tokio::test]
async fn a_key_locked_by_another_transaction_blocks_the_batch() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    put_json(&backend, "a", &1i64, None, &cipher).await.unwrap();
    let etag = etag_of(&backend, "a").await.unwrap();
    // Simulate another transaction holding "a".
    put_json(&backend, &lock_key("a"), &LockRecord::default(), None, &cipher)
        .await
        .unwrap();

    let report = run_update(
        &backend,
        &cipher,
        vec![UpdateOp::update("a".into(), &2i64, &etag).unwrap()],
    )
    .await
    .unwrap();

    assert!(!report.applied, "{report:?}");
    assert_eq!(value_at(&backend, &cipher, "a").await, Some(1));
    assert_eq!(
        locks(&backend).await.len(),
        1,
        "the other transaction's lock must be left alone, not stolen"
    );
    assert!(
        records(&backend).await.is_empty(),
        "the aborted attempt's record must be gone"
    );
}

#[tokio::test]
async fn a_duplicate_key_in_one_batch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);

    let err = run_update(
        &backend,
        &cipher,
        vec![
            UpdateOp::create("a".into(), &1i64).unwrap(),
            UpdateOp::create("a".into(), &2i64).unwrap(),
        ],
    )
    .await
    .unwrap_err();

    assert!(err.to_string().contains("twice"), "{err}");
    assert_eq!(value_at(&backend, &cipher, "a").await, None);
}

#[tokio::test]
async fn an_empty_batch_succeeds_without_bookkeeping() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);

    let report = run_update(&backend, &cipher, Vec::new()).await.unwrap();

    assert!(report.applied);
    assert!(list_all_keys(&backend, ".conf/").await.unwrap().is_empty());
}

/// A `Preparing` record means the commit point was never reached, so nothing
/// was applied and recovery's job is to let go of the locks.
#[tokio::test]
async fn recovery_rolls_back_a_stale_preparing_record() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    put_json(&backend, "a", &1i64, None, &cipher).await.unwrap();
    let record = UpdateRecord {
        txn_id: "dead".into(),
        status: UpdateStatus::Preparing,
        started_at_ms: 1,
        ops: vec![UpdateOp::update("a".into(), &2i64, "whatever").unwrap()],
    };
    put_json(&backend, &record_key("dead"), &record, None, &cipher)
        .await
        .unwrap();
    put_json(&backend, &lock_key("a"), &LockRecord::default(), None, &cipher)
        .await
        .unwrap();

    let recovered = recover_stale_updates(&backend, &cipher, Duration::from_millis(1))
        .await
        .unwrap();

    assert_eq!(recovered, 1);
    assert_eq!(
        value_at(&backend, &cipher, "a").await,
        Some(1),
        "a preparing transaction had applied nothing, so nothing changes"
    );
    assert!(locks(&backend).await.is_empty(), "its locks must be released");
    assert!(records(&backend).await.is_empty());
}

/// A `Committed` record already happened; recovery must finish it, not undo it.
#[tokio::test]
async fn recovery_rolls_a_stale_committed_record_forward() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    put_json(&backend, "a", &1i64, None, &cipher).await.unwrap();
    put_json(&backend, "b", &1i64, None, &cipher).await.unwrap();
    let a_etag = etag_of(&backend, "a").await.unwrap();
    let b_etag = etag_of(&backend, "b").await.unwrap();
    // "a" already applied before the crash, "b" did not.
    put_json(&backend, "a", &2i64, Some(&a_etag), &cipher).await.unwrap();
    let record = UpdateRecord {
        txn_id: "half".into(),
        status: UpdateStatus::Committed,
        started_at_ms: 1,
        ops: vec![
            UpdateOp::update("a".into(), &2i64, &a_etag).unwrap(),
            UpdateOp::update("b".into(), &2i64, &b_etag).unwrap(),
        ],
    };
    put_json(&backend, &record_key("half"), &record, None, &cipher)
        .await
        .unwrap();
    for key in ["a", "b"] {
        put_json(&backend, &lock_key(key), &LockRecord::default(), None, &cipher)
            .await
            .unwrap();
    }

    let recovered = recover_stale_updates(&backend, &cipher, Duration::from_millis(1))
        .await
        .unwrap();

    assert_eq!(recovered, 1);
    assert_eq!(
        value_at(&backend, &cipher, "a").await,
        Some(2),
        "already applied, stays"
    );
    assert_eq!(
        value_at(&backend, &cipher, "b").await,
        Some(2),
        "the missing half of a committed transaction must be completed"
    );
    assert!(locks(&backend).await.is_empty());
    assert!(records(&backend).await.is_empty());
}

/// Regression test for a real bug, not just an efficiency gap: comparing
/// re-sealed *ciphertext* to decide "did our own earlier attempt already
/// write this?" can never work, since `Cipher::seal` issues a fresh random
/// nonce every call -- two seals of identical plaintext are never
/// byte-equal. `apply` must compare what the bytes decrypt to instead, or
/// every retry falls through to a redundant re-write and gets misreported
/// in `overwrote_unlocked` as if an unlocked writer had touched the key.
#[tokio::test]
async fn apply_recognizes_an_op_already_applied_by_a_prior_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    put_json(&backend, "a", &1i64, None, &cipher).await.unwrap();
    let original_etag = etag_of(&backend, "a").await.unwrap();
    // A prior (crashed) attempt already applied this exact op.
    put_json(&backend, "a", &2i64, Some(&original_etag), &cipher)
        .await
        .unwrap();

    let record = UpdateRecord {
        txn_id: "retry".into(),
        status: UpdateStatus::Committed,
        started_at_ms: 1,
        ops: vec![UpdateOp::update("a".into(), &2i64, &original_etag).unwrap()],
    };

    let overwrote = apply(&backend, &cipher, &record).await.unwrap();

    assert!(
        overwrote.is_empty(),
        "a value that already matches this op's own target must be recognized as ours, not \
         reported as an unlocked overwrite: {overwrote:?}"
    );
    assert_eq!(value_at(&backend, &cipher, "a").await, Some(2));
}

#[tokio::test]
async fn recovery_leaves_a_young_transaction_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    let record = UpdateRecord {
        txn_id: "live".into(),
        status: UpdateStatus::Preparing,
        started_at_ms: crate::txn_update::now_ms(),
        ops: vec![UpdateOp::create("a".into(), &1i64).unwrap()],
    };
    put_json(&backend, &record_key("live"), &record, None, &cipher)
        .await
        .unwrap();
    put_json(&backend, &lock_key("a"), &LockRecord::default(), None, &cipher)
        .await
        .unwrap();

    let recovered = recover_stale_updates(&backend, &cipher, Duration::from_secs(60))
        .await
        .unwrap();

    assert_eq!(recovered, 0, "a transaction still in flight must not be dismantled");
    assert_eq!(locks(&backend).await.len(), 1);
    assert_eq!(records(&backend).await.len(), 1);
}

/// A plain write doesn't take locks, so it can land mid-transaction. The
/// transaction wins — and says which keys that happened to.
#[tokio::test]
async fn an_unlocked_write_is_overwritten_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    put_json(&backend, "a", &1i64, None, &cipher).await.unwrap();
    let a_etag = etag_of(&backend, "a").await.unwrap();
    // A committed record whose expected etag no longer matches, exactly what a
    // non-participating writer leaves behind.
    put_json(&backend, "a", &99i64, Some(&a_etag), &cipher).await.unwrap();
    let record = UpdateRecord {
        txn_id: "raced".into(),
        status: UpdateStatus::Committed,
        started_at_ms: 1,
        ops: vec![UpdateOp::update("a".into(), &2i64, &a_etag).unwrap()],
    };
    put_json(&backend, &record_key("raced"), &record, None, &cipher)
        .await
        .unwrap();

    recover_stale_updates(&backend, &cipher, Duration::from_millis(1))
        .await
        .unwrap();

    assert_eq!(
        value_at(&backend, &cipher, "a").await,
        Some(2),
        "a committed transaction must not be left half-applied"
    );
}

#[tokio::test]
async fn recovery_finishes_an_abandoned_aborting_record() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    let record = UpdateRecord {
        txn_id: "swept".into(),
        status: UpdateStatus::Aborting,
        started_at_ms: 1,
        ops: vec![UpdateOp::create("a".into(), &1i64).unwrap()],
    };
    put_json(&backend, &record_key("swept"), &record, None, &cipher)
        .await
        .unwrap();
    put_json(&backend, &lock_key("a"), &LockRecord::default(), None, &cipher)
        .await
        .unwrap();

    let recovered = recover_stale_updates(&backend, &cipher, Duration::from_millis(1))
        .await
        .unwrap();

    assert_eq!(
        recovered, 1,
        "a sweep that died mid-abort must be finished by the next one"
    );
    assert!(locks(&backend).await.is_empty());
    assert!(records(&backend).await.is_empty());
}

/// Concurrent overlapping transactions: exactly one may apply.
#[tokio::test(flavor = "multi_thread")]
async fn only_one_of_two_overlapping_transactions_applies() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = backend_and_cipher(dir.path(), LocalEngine::Files);
    let backend = std::sync::Arc::new(backend);
    let cipher = std::sync::Arc::new(cipher);
    put_json(backend.as_ref(), "a", &0i64, None, &cipher).await.unwrap();
    put_json(backend.as_ref(), "b", &0i64, None, &cipher).await.unwrap();
    let a_etag = etag_of(&backend, "a").await.unwrap();
    let b_etag = etag_of(&backend, "b").await.unwrap();

    let mut set = tokio::task::JoinSet::new();
    for n in 1..=2i64 {
        let backend = std::sync::Arc::clone(&backend);
        let cipher = std::sync::Arc::clone(&cipher);
        let (a_etag, b_etag) = (a_etag.clone(), b_etag.clone());
        set.spawn(async move {
            run_update(
                backend.as_ref(),
                &cipher,
                vec![
                    UpdateOp::update("a".into(), &n, &a_etag).unwrap(),
                    UpdateOp::update("b".into(), &n, &b_etag).unwrap(),
                ],
            )
            .await
        });
    }
    let mut applied = 0;
    while let Some(joined) = set.join_next().await {
        if joined.unwrap().unwrap().applied {
            applied += 1;
        }
    }

    assert_eq!(
        applied, 1,
        "both transactions expected the same etags, so one must lose"
    );
    let a = value_at(&backend, &cipher, "a").await.unwrap();
    let b = value_at(&backend, &cipher, "b").await.unwrap();
    assert_eq!(a, b, "both keys must carry the same winner's value, never a mix");
    assert!(locks(&backend).await.is_empty(), "no lock may be left behind");
    assert!(records(&backend).await.is_empty());
}
