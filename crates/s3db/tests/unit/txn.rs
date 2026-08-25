use super::*;
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (LocalBackend, Cipher) {
    test_backend_and_cipher_with(root, crate::config::LocalEngine::Files)
}

fn test_backend_and_cipher_with(root: &std::path::Path, engine: crate::config::LocalEngine) -> (LocalBackend, Cipher) {
    let backend = LocalBackend::new(&crate::config::LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine,
    });
    let cipher = Cipher::derive("test passphrase", &[11u8; crate::cipher::SALT_LEN]).unwrap();
    (backend, cipher)
}

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
struct Widget {
    count: u32,
}

#[derive(Debug, Default)]
struct RecordingPublisher {
    events: std::sync::Mutex<Vec<ChangeEvent>>,
}

#[async_trait::async_trait]
impl ChangePublisher for RecordingPublisher {
    async fn published(&self, event: ChangeEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[tokio::test]
async fn run_with_publisher_publishes_every_op_once_committed() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let publisher = RecordingPublisher::default();
    let ops = vec![
        TxnOp::create("a.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("b.json".to_string(), &Widget { count: 2 }).unwrap(),
    ];

    let cas = run_with_publisher(&backend, &cipher, ops, &publisher).await.unwrap();
    assert_eq!(cas, Cas::Ok);

    let events = publisher.events.lock().unwrap();
    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|e| e.key == "a.json"));
    assert!(events.iter().any(|e| e.key == "b.json"));
}

#[tokio::test]
async fn run_with_publisher_publishes_nothing_on_a_genuine_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    put_json(&backend, "b.json", &Widget { count: 99 }, None, &cipher)
        .await
        .unwrap();
    let publisher = RecordingPublisher::default();
    let ops = vec![
        TxnOp::create("a.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("b.json".to_string(), &Widget { count: 2 }).unwrap(),
    ];

    let cas = run_with_publisher(&backend, &cipher, ops, &publisher).await.unwrap();
    assert_eq!(cas, Cas::Conflict);
    assert!(
        publisher.events.lock().unwrap().is_empty(),
        "an aborted transaction must publish nothing"
    );
}

#[tokio::test]
async fn happy_path_creates_all_keys_and_no_leftover_record() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let ops = vec![
        TxnOp::create("a.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("b.json".to_string(), &Widget { count: 2 }).unwrap(),
        TxnOp::create("c.json".to_string(), &Widget { count: 3 }).unwrap(),
    ];
    let cas = run(&backend, &cipher, ops).await.unwrap();
    assert_eq!(cas, Cas::Ok);

    for (key, expected) in [("a.json", 1), ("b.json", 2), ("c.json", 3)] {
        let (value, etag) = get_json::<Widget>(&backend, key, &cipher).await.unwrap();
        assert_eq!(value.count, expected);
        assert!(etag.is_some());
    }
    assert!(list_all_keys(&backend, ".conf/txn/").await.unwrap().is_empty());
}

#[tokio::test]
async fn conflicting_op_aborts_and_rolls_back_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    // Pre-created with content different from what the transaction below
    // will try to write -- a genuine collision, not our own retry.
    put_json(&backend, "b.json", &Widget { count: 99 }, None, &cipher)
        .await
        .unwrap();

    let ops = vec![
        TxnOp::create("a.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("b.json".to_string(), &Widget { count: 2 }).unwrap(),
        TxnOp::create("c.json".to_string(), &Widget { count: 3 }).unwrap(),
    ];
    let cas = run(&backend, &cipher, ops).await.unwrap();
    assert_eq!(cas, Cas::Conflict);

    // "a.json" (sorts before "b.json") got created by this attempt, then
    // rolled back; "c.json" never got created in the first place.
    let (_, a_etag) = get_json::<Widget>(&backend, "a.json", &cipher).await.unwrap();
    assert!(a_etag.is_none());
    let (_, c_etag) = get_json::<Widget>(&backend, "c.json", &cipher).await.unwrap();
    assert!(c_etag.is_none());
    // "b.json" keeps its original content untouched -- never blind-deleted.
    let (b, _) = get_json::<Widget>(&backend, "b.json", &cipher).await.unwrap();
    assert_eq!(b.count, 99);
    assert!(list_all_keys(&backend, ".conf/txn/").await.unwrap().is_empty());
}

#[tokio::test]
async fn rerun_after_partial_crash_treats_the_already_applied_op_as_ours() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let ops = vec![
        TxnOp::create("a.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("b.json".to_string(), &Widget { count: 2 }).unwrap(),
        TxnOp::create("c.json".to_string(), &Widget { count: 3 }).unwrap(),
    ];
    // Simulates a crash after a previous `run` wrote its own txn record and
    // applied only this one op, then died before reaching the next op --
    // the record is what makes this a genuine "my own prior attempt",
    // distinct from some unrelated write that merely happens to match.
    let crashed_record = TxnRecord {
        txn_id: "crashed-attempt".to_string(),
        status: TxnStatus::Preparing,
        started_at_ms: 0,
        ops: ops.clone(),
    };
    assert_eq!(
        put_json(
            &backend,
            &txn_key(&crashed_record.txn_id),
            &crashed_record,
            None,
            &cipher
        )
        .await
        .unwrap(),
        Cas::Ok
    );
    let sealed = cipher
        .seal(
            &ops[0].key,
            &rmp_serde::to_vec_named(&ops[0].value).unwrap(),
            CompressionStrategy::None,
        )
        .unwrap();
    assert_eq!(backend.put_cas(&ops[0].key, sealed, None).await.unwrap(), Cas::Ok);

    let cas = run(&backend, &cipher, ops).await.unwrap();
    assert_eq!(cas, Cas::Ok);
    for (key, expected) in [("a.json", 1), ("b.json", 2), ("c.json", 3)] {
        let (value, etag) = get_json::<Widget>(&backend, key, &cipher).await.unwrap();
        assert_eq!(value.count, expected);
        assert!(etag.is_some());
    }
    // The crashed attempt's own record isn't this `run` call's to clean up
    // -- that's `recover_stale`'s job, once it's old enough. `run` only ever
    // deletes the record it itself wrote.
    assert_eq!(
        list_all_keys(&backend, ".conf/txn/").await.unwrap(),
        vec![txn_key(&crashed_record.txn_id)]
    );
}

#[tokio::test]
async fn recover_stale_rolls_back_an_abandoned_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let op = TxnOp::create("a.json".to_string(), &Widget { count: 1 }).unwrap();
    let record = TxnRecord {
        txn_id: "deadbeef".to_string(),
        status: TxnStatus::Preparing,
        started_at_ms: 0, // arbitrarily old
        ops: vec![op.clone()],
    };
    put_json(&backend, &txn_key(&record.txn_id), &record, None, &cipher)
        .await
        .unwrap();
    // Simulates the real partial-apply a crashed `run` would leave behind.
    let sealed = cipher
        .seal(
            &op.key,
            &rmp_serde::to_vec_named(&op.value).unwrap(),
            CompressionStrategy::None,
        )
        .unwrap();
    assert_eq!(backend.put_cas(&op.key, sealed, None).await.unwrap(), Cas::Ok);

    let recovered = recover_stale(&backend, &cipher, Duration::ZERO).await.unwrap();
    assert_eq!(recovered, 1);
    let (_, etag) = get_json::<Widget>(&backend, &op.key, &cipher).await.unwrap();
    assert!(etag.is_none());
    assert!(list_all_keys(&backend, ".conf/txn/").await.unwrap().is_empty());
}

#[tokio::test]
async fn two_overlapping_transactions_exactly_one_wins() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let ops_a = vec![
        TxnOp::create("shared.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("only_a.json".to_string(), &Widget { count: 10 }).unwrap(),
    ];
    let ops_b = vec![
        TxnOp::create("shared.json".to_string(), &Widget { count: 2 }).unwrap(),
        TxnOp::create("only_b.json".to_string(), &Widget { count: 20 }).unwrap(),
    ];

    let cas_a = run(&backend, &cipher, ops_a).await.unwrap();
    let cas_b = run(&backend, &cipher, ops_b).await.unwrap();
    assert_eq!(cas_a, Cas::Ok);
    assert_eq!(cas_b, Cas::Conflict);

    let (shared, _) = get_json::<Widget>(&backend, "shared.json", &cipher).await.unwrap();
    assert_eq!(shared.count, 1);
    let (_, only_a_etag) = get_json::<Widget>(&backend, "only_a.json", &cipher).await.unwrap();
    assert!(only_a_etag.is_some());
    let (_, only_b_etag) = get_json::<Widget>(&backend, "only_b.json", &cipher).await.unwrap();
    assert!(
        only_b_etag.is_none(),
        "the loser's non-conflicting op must have been rolled back too"
    );
    assert!(list_all_keys(&backend, ".conf/txn/").await.unwrap().is_empty());
}

#[test]
fn as_atomic_finds_it_only_on_the_redb_engine() {
    let dir = tempfile::tempdir().unwrap();
    let (files, _) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Files);
    assert!(as_atomic(&files).is_none());

    let dir = tempfile::tempdir().unwrap();
    let (redb, _) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Redb);
    assert!(as_atomic(&redb).is_some());
}

/// Same observable behavior as `happy_path_creates_all_keys_and_no_leftover_record`,
/// but on the engine that takes the `run_atomic` fast path instead of the
/// CAS-sequential one -- pins down that switching protocols under the
/// hood doesn't change what a caller of `run` sees.
#[tokio::test]
async fn happy_path_on_redb_creates_all_keys_via_the_atomic_path() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Redb);
    let ops = vec![
        TxnOp::create("a.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("b.json".to_string(), &Widget { count: 2 }).unwrap(),
    ];
    assert_eq!(run(&backend, &cipher, ops).await.unwrap(), Cas::Ok);
    for (key, expected) in [("a.json", 1), ("b.json", 2)] {
        let (value, etag) = get_json::<Widget>(&backend, key, &cipher).await.unwrap();
        assert_eq!(value.count, expected);
        assert!(etag.is_some());
    }
    // No durable record trail at all -- the atomic path never wrote one.
    assert!(list_all_keys(&backend, ".conf/txn/").await.unwrap().is_empty());
}

/// On the CAS-sequential path a losing transaction can create, then roll
/// back, its earlier keys before hitting the conflict. The atomic path
/// has no such window: the whole batch is checked before anything is
/// written, so a conflicting op means literally nothing in the batch
/// ever touched the table.
#[tokio::test]
async fn conflicting_op_on_redb_applies_nothing_at_all() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Redb);
    put_json(&backend, "b.json", &Widget { count: 99 }, None, &cipher)
        .await
        .unwrap();

    let ops = vec![
        TxnOp::create("a.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("b.json".to_string(), &Widget { count: 2 }).unwrap(),
    ];
    assert_eq!(run(&backend, &cipher, ops).await.unwrap(), Cas::Conflict);

    let (_, a_etag) = get_json::<Widget>(&backend, "a.json", &cipher).await.unwrap();
    assert!(a_etag.is_none(), "a.json must never have been written at all");
    let (b, _) = get_json::<Widget>(&backend, "b.json", &cipher).await.unwrap();
    assert_eq!(b.count, 99, "b.json's original content must be untouched");
}

#[tokio::test]
async fn two_overlapping_transactions_on_redb_exactly_one_wins() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher_with(dir.path(), crate::config::LocalEngine::Redb);
    let ops_a = vec![
        TxnOp::create("shared.json".to_string(), &Widget { count: 1 }).unwrap(),
        TxnOp::create("only_a.json".to_string(), &Widget { count: 10 }).unwrap(),
    ];
    let ops_b = vec![
        TxnOp::create("shared.json".to_string(), &Widget { count: 2 }).unwrap(),
        TxnOp::create("only_b.json".to_string(), &Widget { count: 20 }).unwrap(),
    ];

    assert_eq!(run(&backend, &cipher, ops_a).await.unwrap(), Cas::Ok);
    assert_eq!(run(&backend, &cipher, ops_b).await.unwrap(), Cas::Conflict);

    let (shared, _) = get_json::<Widget>(&backend, "shared.json", &cipher).await.unwrap();
    assert_eq!(shared.count, 1);
    assert!(
        get_json::<Widget>(&backend, "only_a.json", &cipher)
            .await
            .unwrap()
            .1
            .is_some()
    );
    assert!(
        get_json::<Widget>(&backend, "only_b.json", &cipher)
            .await
            .unwrap()
            .1
            .is_none(),
        "the loser's non-conflicting op must not have landed either"
    );
}

#[tokio::test]
async fn two_independent_transactions_with_identical_low_entropy_values_do_not_collide() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    // A create-only "claim this name" marker, exactly the pattern the
    // module's own doc frames this primitive for -- and exactly the case
    // where two entirely unrelated transactions can write byte-identical
    // content. Neither transaction here has any relation to the other; the
    // second must never be told it "already" owns what the first holds.
    let marker = serde_json::json!({});
    let claim_a = vec![TxnOp::create("reservations/alice.json".to_string(), &marker).unwrap()];
    let claim_b = vec![TxnOp::create("reservations/alice.json".to_string(), &marker).unwrap()];

    assert_eq!(run(&backend, &cipher, claim_a).await.unwrap(), Cas::Ok);
    assert_eq!(
        run(&backend, &cipher, claim_b).await.unwrap(),
        Cas::Conflict,
        "an unrelated transaction must not be able to mistake someone else's identical-content claim for its own"
    );
}
