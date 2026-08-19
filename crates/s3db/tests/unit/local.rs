//! Same behavior, either engine — each engine's own module has thorough
//! unit tests of its own; this file only pins down that [`LocalBackend`]'s
//! dispatch doesn't lose or change behavior for either variant, and that
//! `LocalParams::engine` actually selects the one asked for.

use super::*;

fn backend(root: &std::path::Path, engine: LocalEngine) -> LocalBackend {
    LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine,
    })
}

#[tokio::test]
async fn engine_files_is_the_default() {
    assert_eq!(LocalEngine::default(), LocalEngine::Files);
}

#[tokio::test]
async fn both_engines_round_trip_get_and_put_cas() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        assert_eq!(b.put_cas("k", b"v1".to_vec(), None).await.unwrap(), Cas::Ok);
        assert_eq!(b.put_cas("k", b"v2".to_vec(), None).await.unwrap(), Cas::Conflict);
        let (bytes, etag) = b.get("k").await.unwrap();
        assert_eq!(bytes, b"v1", "engine {engine:?}");
        assert_eq!(b.put_cas("k", b"v2".to_vec(), etag.as_deref()).await.unwrap(), Cas::Ok);
        let (bytes, _) = b.get("k").await.unwrap();
        assert_eq!(bytes, b"v2", "engine {engine:?}");
    }
}

#[tokio::test]
async fn both_engines_delete_idempotently() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        b.put_cas("k", b"v".to_vec(), None).await.unwrap();
        assert_eq!(b.delete("k").await.unwrap().confirmed, 1);
        assert_eq!(b.delete("k").await.unwrap().confirmed, 1, "engine {engine:?}");
        let (bytes, etag) = b.get("k").await.unwrap();
        assert!(bytes.is_empty());
        assert!(etag.is_none());
    }
}

#[tokio::test]
async fn both_engines_delete_many_in_one_call() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        b.put_cas("a", b"1".to_vec(), None).await.unwrap();
        b.put_cas("b", b"2".to_vec(), None).await.unwrap();
        let outcome = b
            .delete_many(&["a".to_string(), "b".to_string(), "missing".to_string()])
            .await
            .unwrap();
        assert_eq!(outcome.attempted, 3, "engine {engine:?}");
        assert_eq!(outcome.confirmed, 3, "engine {engine:?}");
    }
}

#[tokio::test]
async fn both_engines_list_prefix_ordered_and_scoped() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        b.put_cas("repos/team/proj/refs.json", b"a".to_vec(), None)
            .await
            .unwrap();
        b.put_cas("repos/team/proj/objects/pack/x.pack", b"bb".to_vec(), None)
            .await
            .unwrap();
        b.put_cas("repos/other/refs.json", b"c".to_vec(), None).await.unwrap();

        let mut found = b.list_prefix("repos/team/proj/").await.unwrap();
        found.sort();
        assert_eq!(
            found,
            vec![
                ("repos/team/proj/objects/pack/x.pack".to_string(), 2),
                ("repos/team/proj/refs.json".to_string(), 1),
            ],
            "engine {engine:?}"
        );
    }
}

#[tokio::test]
async fn both_engines_list_prefix_empty_for_a_prefix_with_no_keys() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let found = backend(dir.path(), engine).list_prefix("nope/").await.unwrap();
        assert!(found.is_empty(), "engine {engine:?}");
    }
}

#[cfg(feature = "streaming")]
#[tokio::test]
async fn both_engines_round_trip_put_stream_and_get_stream() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        let src_dir = tempfile::tempdir().unwrap();
        let source = src_dir.path().join("source");
        let dest = src_dir.path().join("dest");

        tokio::fs::write(&source, b"content v1").await.unwrap();
        b.put_stream("k", &source).await.unwrap();
        b.get_stream("k", &dest).await.unwrap();
        assert_eq!(
            tokio::fs::read(&dest).await.unwrap(),
            b"content v1",
            "engine {engine:?}"
        );

        tokio::fs::write(&source, b"content v2, longer").await.unwrap();
        b.put_stream("k", &source).await.unwrap();
        b.get_stream("k", &dest).await.unwrap();
        assert_eq!(
            tokio::fs::read(&dest).await.unwrap(),
            b"content v2, longer",
            "engine {engine:?}"
        );
    }
}

#[tokio::test]
async fn both_engines_get_range_returns_the_same_slice() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        b.put_cas("k", b"0123456789".to_vec(), None).await.unwrap();
        assert_eq!(b.get_range("k", 2, 5).await.unwrap(), b"23456", "engine {engine:?}");
    }
}

/// Deliberately on the default single-threaded runtime: the whole point is
/// that waiting for a contended `flock` must not occupy the runtime worker
/// that the lock holder needs in order to finish and release it. Before
/// `lock_key` moved the wait to the blocking pool, this hung forever
/// instead of failing — so it is a liveness test, and its timeout is the
/// assertion.
#[tokio::test]
async fn files_engine_serializes_contending_writers_without_blocking_the_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let b = std::sync::Arc::new(backend(dir.path(), LocalEngine::Files));

    let mut set = tokio::task::JoinSet::new();
    for i in 0..8u8 {
        let b = std::sync::Arc::clone(&b);
        set.spawn(async move {
            // Every writer races the same key with the same expectation, so
            // exactly one can win: the losers must come back as
            // `Cas::Conflict`, never hang and never corrupt the revision
            // sidecar.
            b.put_cas("contended", vec![i], None).await
        });
    }

    let mut wins = 0;
    let mut conflicts = 0;
    while let Some(joined) = set.join_next().await {
        match joined.unwrap().unwrap() {
            Cas::Ok => wins += 1,
            Cas::Conflict => conflicts += 1,
        }
    }
    assert_eq!(wins, 1, "exactly one create-only write can win");
    assert_eq!(conflicts, 7);
}

/// The cursor contract, asserted against both engines — `redb` pushes it into
/// its B-tree range, `files` gets the sorting default — so the two can never
/// drift on what a page means.
#[tokio::test]
async fn both_engines_page_a_prefix_in_key_order() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        // Written out of order on purpose: a page is defined by key order,
        // not insertion order.
        for n in [3u32, 1, 5, 2, 4] {
            b.put_cas(&format!("p/{n:04}"), vec![0u8; n as usize], None)
                .await
                .unwrap();
        }

        let mut seen = Vec::new();
        let mut after: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = b.list_page("p/", after.as_deref(), 2).await.unwrap();
            pages += 1;
            assert!(page.entries.len() <= 2, "engine {engine:?} overran the limit");
            seen.extend(page.entries.iter().map(|(key, _size)| key.clone()));
            match page.next_after {
                Some(next) => after = Some(next),
                None => break,
            }
            assert!(pages < 10, "engine {engine:?} never finished");
        }

        assert_eq!(
            seen,
            vec!["p/0001", "p/0002", "p/0003", "p/0004", "p/0005"],
            "engine {engine:?}"
        );
        assert_eq!(pages, 3, "engine {engine:?}: 5 keys at 2 per page");
    }
}

#[tokio::test]
async fn both_engines_agree_on_an_empty_and_a_partial_page() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);

        let empty = b.list_page("nothing/", None, 10).await.unwrap();
        assert!(empty.entries.is_empty(), "engine {engine:?}");
        assert_eq!(empty.next_after, None, "engine {engine:?}");

        b.put_cas("p/a", b"x".to_vec(), None).await.unwrap();
        let partial = b.list_page("p/", None, 10).await.unwrap();
        assert_eq!(partial.entries.len(), 1, "engine {engine:?}");
        assert_eq!(
            partial.next_after, None,
            "engine {engine:?}: a page short of the limit is the last one"
        );

        // A cursor past every key yields nothing, not a wrap-around.
        let past = b.list_page("p/", Some("p/zzz"), 10).await.unwrap();
        assert!(past.entries.is_empty(), "engine {engine:?}");
        assert_eq!(past.next_after, None, "engine {engine:?}");
    }
}

/// A page whose entries exactly fill the limit must still say whether more
/// remain — otherwise a caller has to guess, and guessing wrong either drops
/// the tail or makes one wasted request per sweep.
#[tokio::test]
async fn a_full_page_reports_whether_more_remain() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        for n in 0..4u32 {
            b.put_cas(&format!("p/{n:04}"), b"x".to_vec(), None).await.unwrap();
        }

        let full_with_more = b.list_page("p/", None, 2).await.unwrap();
        assert_eq!(full_with_more.entries.len(), 2, "engine {engine:?}");
        assert_eq!(
            full_with_more.next_after.as_deref(),
            Some("p/0001"),
            "engine {engine:?}"
        );

        let full_exactly = b.list_page("p/", None, 4).await.unwrap();
        assert_eq!(full_exactly.entries.len(), 4, "engine {engine:?}");
        assert_eq!(
            full_exactly.next_after, None,
            "engine {engine:?}: the limit matching the key count is still the last page"
        );
    }
}

/// `after` names a key, so it keeps working when that key is gone — which is
/// the whole point for a sweep that deletes as it pages.
#[tokio::test]
async fn a_cursor_survives_the_deletion_of_the_key_it_names() {
    for engine in [LocalEngine::Files, LocalEngine::Redb] {
        let dir = tempfile::tempdir().unwrap();
        let b = backend(dir.path(), engine);
        for n in 0..4u32 {
            b.put_cas(&format!("p/{n:04}"), b"x".to_vec(), None).await.unwrap();
        }
        b.delete("p/0001").await.unwrap();

        let page = b.list_page("p/", Some("p/0001"), 10).await.unwrap();
        assert_eq!(
            page.entries.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            vec!["p/0002", "p/0003"],
            "engine {engine:?}"
        );
    }
}
