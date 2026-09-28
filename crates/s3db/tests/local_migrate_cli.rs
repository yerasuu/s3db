//! Drives the `s3db-local-migrate` binary the way an operator would: as a
//! process, against a real `Files`-format directory on disk.
#![allow(deprecated)]

use s3db::{Backend, FilesBackend, LocalEngine, LocalParams, RedbBackend};
use std::process::Command;

fn files_backend(root: &std::path::Path) -> FilesBackend {
    FilesBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    })
}

fn redb_backend(root: &std::path::Path) -> RedbBackend {
    RedbBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Redb,
    })
}

struct Output {
    stdout: String,
    success: bool,
}

fn run(root: &std::path::Path, args: &[&str]) -> Output {
    let out = Command::new(env!("CARGO_BIN_EXE_s3db-local-migrate"))
        .arg(root)
        .args(args)
        .output()
        .expect("running s3db-local-migrate");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        success: out.status.success(),
    }
}

#[tokio::test]
async fn migrate_moves_every_key_and_reads_back_identical_on_redb() {
    let dir = tempfile::tempdir().unwrap();
    let files = files_backend(dir.path());
    files.put_cas("a", b"one".to_vec(), None).await.unwrap();
    files.put_cas("nested/b", b"two".to_vec(), None).await.unwrap();

    let out = run(dir.path(), &[]);

    assert!(out.success, "{}", out.stdout);
    assert!(out.stdout.contains("migrated and verified 2 key(s)"), "{}", out.stdout);

    let redb = redb_backend(dir.path());
    assert_eq!(redb.get("a").await.unwrap().0, b"one");
    assert_eq!(redb.get("nested/b").await.unwrap().0, b"two");

    // The old per-key files are left in place, not deleted by the tool.
    assert_eq!(files.get("a").await.unwrap().0, b"one");
}

#[tokio::test]
async fn dry_run_reports_the_count_but_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let files = files_backend(dir.path());
    files.put_cas("a", b"one".to_vec(), None).await.unwrap();

    let out = run(dir.path(), &["--dry-run"]);

    assert!(out.success, "{}", out.stdout);
    assert!(out.stdout.contains("dry run"), "{}", out.stdout);
    assert!(
        !dir.path().join("s3db.redb").exists(),
        "a dry run must never create s3db.redb"
    );
}

#[tokio::test]
async fn an_empty_bucket_has_nothing_to_migrate() {
    let dir = tempfile::tempdir().unwrap();

    let out = run(dir.path(), &[]);

    assert!(out.success, "{}", out.stdout);
    assert!(out.stdout.contains("nothing to migrate"), "{}", out.stdout);
    assert!(!dir.path().join("s3db.redb").exists());
}
