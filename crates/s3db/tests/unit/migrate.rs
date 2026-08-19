use super::*;
use crate::local::LocalBackend;

fn test_backend_and_cipher(root: &std::path::Path) -> (Arc<dyn Backend>, Arc<Cipher>) {
    let backend = LocalBackend::new(&crate::config::LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: crate::config::LocalEngine::Files,
    });
    let cipher = Cipher::derive("test passphrase", &[13u8; crate::cipher::SALT_LEN]).unwrap();
    (Arc::new(backend), Arc::new(cipher))
}

const WORKS: Collection = Collection::new("works");

/// The shape before the migration: one `name` field.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct WorkV1 {
    name: String,
}

/// The shape after: `name` split into `title` and a language stamp that has
/// no sensible `Default` and so can't be handled by serde tolerance alone.
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct WorkV2 {
    title: String,
    lang: String,
}

async fn seed(backend: &Arc<dyn Backend>, cipher: &Arc<Cipher>, count: u32) {
    for n in 0..count {
        WORKS
            .put(
                backend.as_ref(),
                cipher,
                &format!("w{n:04}"),
                &WorkV1 {
                    name: format!("work {n}"),
                },
                None,
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn a_migration_rewrites_every_entry_and_records_itself() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    seed(&backend, &cipher, 3).await;

    let report = crate::migrate::migrate_entries::<WorkV1, WorkV2, _>(
        &backend,
        &cipher,
        &WORKS,
        1,
        "split name into title+lang",
        |old| {
            Ok(Rewrite::Write(WorkV2 {
                title: old.name,
                lang: "en".to_string(),
            }))
        },
    )
    .await
    .unwrap();

    assert!(report.ran);
    assert_eq!((report.scanned, report.rewritten), (3, 3));
    assert!(report.is_clean(), "{report:?}");

    let (migrated, _etag) = WORKS.get::<WorkV2>(backend.as_ref(), &cipher, "w0001").await.unwrap();
    assert_eq!(
        migrated,
        Some(WorkV2 {
            title: "work 1".to_string(),
            lang: "en".to_string()
        })
    );

    let state = crate::migrate::schema_state(backend.as_ref(), &cipher, &WORKS)
        .await
        .unwrap();
    assert_eq!(state.version, 1);
    assert_eq!(state.applied.len(), 1);
    assert_eq!(state.applied[0].entries_rewritten, 3);
    assert_eq!(state.in_progress, None, "a finished pass leaves no cursor");
}

#[tokio::test]
async fn a_second_run_of_the_same_version_does_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    seed(&backend, &cipher, 2).await;

    for _ in 0..2 {
        let report = crate::migrate::migrate_entries::<WorkV1, WorkV2, _>(&backend, &cipher, &WORKS, 1, "v1", |old| {
            Ok(Rewrite::Write(WorkV2 {
                title: old.name,
                lang: "en".to_string(),
            }))
        })
        .await
        .unwrap();
        // The second call must not feed already-migrated entries back through
        // the transform, which is exactly what an unversioned rewrite would do.
        if !report.ran {
            assert_eq!(report.scanned, 0);
            return;
        }
    }
    panic!("the second run should have been skipped as already applied");
}

#[tokio::test]
async fn keep_leaves_an_entry_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    seed(&backend, &cipher, 4).await;
    let (_before, etag_before) = WORKS.get::<WorkV1>(backend.as_ref(), &cipher, "w0000").await.unwrap();

    let report = crate::migrate::migrate_entries::<WorkV1, WorkV1, _>(
        &backend,
        &cipher,
        &WORKS,
        1,
        "touch only work 3",
        |old| {
            if old.name.ends_with('3') {
                Ok(Rewrite::Write(WorkV1 {
                    name: "touched".to_string(),
                }))
            } else {
                Ok(Rewrite::Keep)
            }
        },
    )
    .await
    .unwrap();

    assert_eq!((report.rewritten, report.unchanged), (1, 3));
    let (_after, etag_after) = WORKS.get::<WorkV1>(backend.as_ref(), &cipher, "w0000").await.unwrap();
    assert_eq!(
        etag_after, etag_before,
        "Keep must not write, so the etag must not move"
    );
}

/// The resume path: a cursor left by an interrupted run means the transform
/// only ever sees entries it hasn't already converted.
#[tokio::test]
async fn an_interrupted_pass_resumes_from_its_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    seed(&backend, &cipher, 4).await;

    // Simulate a crash after w0000/w0001 were rewritten: their new shape is
    // stored, and the bookkeeping records the cursor but not the version.
    for n in 0..2 {
        let name = format!("w{n:04}");
        let (_old, etag) = WORKS.get::<WorkV1>(backend.as_ref(), &cipher, &name).await.unwrap();
        WORKS
            .put(
                backend.as_ref(),
                &cipher,
                &name,
                &WorkV2 {
                    title: format!("work {n}"),
                    lang: "en".to_string(),
                },
                etag.as_deref(),
            )
            .await
            .unwrap();
    }
    let interrupted = crate::migrate::SchemaState {
        version: 0,
        applied: Vec::new(),
        in_progress: Some(crate::migrate::InProgress {
            version: 1,
            name: "v1".to_string(),
            started_at_ms: 1,
            last_name: Some("w0001".to_string()),
            entries_rewritten: 2,
        }),
    };
    crate::payload::put_json(
        backend.as_ref(),
        &format!("{}/.schema.json", WORKS.prefix),
        &interrupted,
        None,
        &cipher,
    )
    .await
    .unwrap();

    let report = crate::migrate::migrate_entries::<WorkV1, WorkV2, _>(&backend, &cipher, &WORKS, 1, "v1", |old| {
        // Anything already converted would arrive here with an empty `name`
        // (WorkV2 has no such field), which this refuses -- so the test fails
        // loudly if the resume re-scans what already landed.
        if old.name.is_empty() {
            anyhow::bail!("transform saw an already-migrated entry");
        }
        Ok(Rewrite::Write(WorkV2 {
            title: old.name,
            lang: "en".to_string(),
        }))
    })
    .await
    .unwrap();

    assert_eq!(report.scanned, 2, "only the entries after the cursor");
    assert_eq!(report.rewritten, 2);
    let state = crate::migrate::schema_state(backend.as_ref(), &cipher, &WORKS)
        .await
        .unwrap();
    assert_eq!(state.version, 1);
    assert_eq!(
        state.applied[0].entries_rewritten, 4,
        "the record counts the whole migration, not just this run"
    );
}

#[tokio::test]
async fn a_cursor_from_a_different_version_is_refused_not_discarded() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    seed(&backend, &cipher, 1).await;
    crate::payload::put_json(
        backend.as_ref(),
        &format!("{}/.schema.json", WORKS.prefix),
        &crate::migrate::SchemaState {
            version: 0,
            applied: Vec::new(),
            in_progress: Some(crate::migrate::InProgress {
                version: 7,
                name: "someone else".to_string(),
                started_at_ms: 1,
                last_name: None,
                entries_rewritten: 0,
            }),
        },
        None,
        &cipher,
    )
    .await
    .unwrap();

    let err = crate::migrate::migrate_entries::<WorkV1, WorkV1, _>(&backend, &cipher, &WORKS, 1, "v1", |old| {
        Ok(Rewrite::Write(old))
    })
    .await
    .unwrap_err();
    assert!(err.to_string().contains("unfinished migration"), "{err}");
}

#[tokio::test]
async fn baseline_adopts_an_existing_collection_without_rewriting() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    seed(&backend, &cipher, 2).await;

    crate::migrate::baseline(backend.as_ref(), &cipher, &WORKS, 3, "data already at v3")
        .await
        .unwrap();

    let skipped = crate::migrate::migrate_entries::<WorkV1, WorkV1, _>(&backend, &cipher, &WORKS, 3, "v3", |_old| {
        anyhow::bail!("must not run")
    })
    .await
    .unwrap();
    assert!(!skipped.ran, "a baselined version must not re-run");

    let err = crate::migrate::baseline(backend.as_ref(), &cipher, &WORKS, 1, "backwards")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("refusing to lower"), "{err}");
}

#[tokio::test]
async fn version_zero_is_rejected_as_a_migration() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    let err = crate::migrate::migrate_entries::<WorkV1, WorkV1, _>(&backend, &cipher, &WORKS, 0, "nope", |old| {
        Ok(Rewrite::Write(old))
    })
    .await
    .unwrap_err();
    assert!(err.to_string().contains("version 0"), "{err}");
}

/// More entries than one page, so the cursor path is exercised end to end.
#[tokio::test]
async fn a_pass_spanning_several_pages_migrates_all_of_them() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    seed(&backend, &cipher, 450).await;

    let report = crate::migrate::migrate_entries::<WorkV1, WorkV2, _>(&backend, &cipher, &WORKS, 1, "v1", |old| {
        Ok(Rewrite::Write(WorkV2 {
            title: old.name,
            lang: "en".to_string(),
        }))
    })
    .await
    .unwrap();

    assert_eq!((report.scanned, report.rewritten), (450, 450));
    let (last, _etag) = WORKS.get::<WorkV2>(backend.as_ref(), &cipher, "w0449").await.unwrap();
    assert_eq!(last.unwrap().lang, "en", "the last page must be migrated too");
}

/// The bookkeeping object must not look like an entry to the very pass that
/// maintains it.
#[tokio::test]
async fn the_schema_object_is_not_itself_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let (backend, cipher) = test_backend_and_cipher(dir.path());
    seed(&backend, &cipher, 2).await;
    crate::migrate::baseline(backend.as_ref(), &cipher, &WORKS, 1, "seed")
        .await
        .unwrap();

    let report = crate::migrate::migrate_entries::<WorkV1, WorkV1, _>(&backend, &cipher, &WORKS, 2, "v2", |old| {
        Ok(Rewrite::Write(old))
    })
    .await
    .unwrap();

    assert_eq!(report.scanned, 2, "only the two real entries: {report:?}");
    assert_eq!(WORKS.list_names(backend.as_ref()).await.unwrap().len(), 2);
}
