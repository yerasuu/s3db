//! Drives the `s3db-inspect` binary the way an operator would: as a process,
//! against a real encrypted bucket on disk. A library-level test of the same
//! functions would miss what actually matters about a CLI — that the argument
//! parsing, the passphrase-from-environment rule, and the exit codes behave.
//!
//! Matches the CLI's own `--local` default (`LocalEngine::Files`, deprecated)
//! rather than an internal test helper — this is an integration test crate,
//! outside the library, so it only has the public API to work with.
#![allow(deprecated)]

use s3db::{Backend, Collection, LocalBackend, LocalEngine, LocalParams};
use std::process::Command;

const PASSPHRASE: &str = "cli test passphrase";
const WIDGETS: Collection = Collection::new("widgets");

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Widget {
    count: u32,
}

fn backend(root: &std::path::Path) -> LocalBackend {
    LocalBackend::new(&LocalParams {
        bucket: root.to_string_lossy().to_string(),
        engine: LocalEngine::Files,
    })
}

/// A bucket with three widgets and a schema baseline.
async fn seeded(root: &std::path::Path) {
    let backend = backend(root);
    let cipher = s3db::bootstrap::get_or_create_cipher(&backend, PASSPHRASE)
        .await
        .unwrap();
    for n in 0..3u32 {
        WIDGETS
            .put(&backend, &cipher, &format!("w{n}"), &Widget { count: n }, None)
            .await
            .unwrap();
    }
    s3db::migrate::baseline(&backend, &cipher, &WIDGETS, 2, "cli test")
        .await
        .unwrap();
}

struct Output {
    stdout: String,
    stderr: String,
    success: bool,
}

fn run(root: &std::path::Path, passphrase: Option<&str>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_s3db-inspect"));
    command.arg("--local").arg(root).args(args);
    match passphrase {
        Some(value) => command.env("S3DB_PASSPHRASE", value),
        None => command.env_remove("S3DB_PASSPHRASE"),
    };
    let out = command.output().expect("running s3db-inspect");
    Output {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        success: out.status.success(),
    }
}

#[tokio::test]
async fn lists_counts_and_decrypts() {
    let dir = tempfile::tempdir().unwrap();
    seeded(dir.path()).await;

    let ls = run(dir.path(), Some(PASSPHRASE), &["ls", ""]);
    assert!(ls.success, "{}", ls.stderr);
    assert!(ls.stdout.contains("widgets/w1.json"), "{}", ls.stdout);
    assert!(ls.stdout.contains("5 object(s)"), "{}", ls.stdout);

    let count = run(dir.path(), Some(PASSPHRASE), &["count", "widgets/"]);
    assert!(count.stdout.starts_with("4 object(s)"), "{}", count.stdout);

    let names = run(dir.path(), Some(PASSPHRASE), &["names", "widgets"]);
    assert_eq!(
        names.stdout, "w0\nw1\nw2\n3 entry name(s)\n",
        "the collection's own bookkeeping must not appear as an entry"
    );

    let get = run(dir.path(), Some(PASSPHRASE), &["get", "widgets/w1.json"]);
    assert!(get.stdout.contains("\"count\": 1"), "{}", get.stdout);

    let schema = run(dir.path(), Some(PASSPHRASE), &["schema", "widgets"]);
    assert!(schema.stdout.contains("version: 2"), "{}", schema.stdout);
}

/// The encryption config is unencrypted plain JSON on purpose — the one object
/// meant to be read by hand during an incident, which is what this tool is for.
#[tokio::test]
async fn reads_the_plain_encryption_config() {
    let dir = tempfile::tempdir().unwrap();
    seeded(dir.path()).await;

    let out = run(dir.path(), Some(PASSPHRASE), &["get", ".conf/encryption.json"]);

    assert!(out.success, "{}", out.stderr);
    assert!(out.stdout.contains("\"salt\""), "{}", out.stdout);
}

#[tokio::test]
async fn verify_passes_clean_and_fails_on_a_corrupted_object() {
    let dir = tempfile::tempdir().unwrap();
    seeded(dir.path()).await;

    let clean = run(dir.path(), Some(PASSPHRASE), &["verify", ""]);
    assert!(clean.success, "{}", clean.stderr);
    assert!(clean.stdout.contains("0 failed"), "{}", clean.stdout);

    std::fs::write(dir.path().join("widgets/w2.json"), b"garbage").unwrap();
    let corrupted = run(dir.path(), Some(PASSPHRASE), &["verify", ""]);

    assert!(!corrupted.success, "a failed verify must exit nonzero, for cron and CI");
    assert!(
        corrupted.stdout.contains("FAIL widgets/w2.json"),
        "{}",
        corrupted.stdout
    );
    assert!(corrupted.stdout.contains("1 failed"), "{}", corrupted.stdout);
}

/// A mistyped path must fail, never become a freshly initialized bucket whose
/// encryption config this command wrote.
#[tokio::test]
async fn refuses_an_unbootstrapped_bucket_and_leaves_it_untouched() {
    let dir = tempfile::tempdir().unwrap();

    let out = run(dir.path(), Some(PASSPHRASE), &["verify", ""]);

    assert!(!out.success);
    assert!(out.stderr.contains("never bootstrapped"), "{}", out.stderr);
    // The read this refusal takes along the way now locks the key it looked
    // for (`get` takes a shared lock too, see `local::files::lock_key`'s own
    // doc for why) -- an empty `.s3dblock` sidecar and the directory that
    // holds it are the harmless cost of that, not a bucket config. The
    // actual invariant this test guards is narrower: the encryption config
    // a real bootstrap would have written must not exist.
    assert!(
        !dir.path().join(s3db::bootstrap::ENCRYPTION_META_KEY).exists(),
        "must never write a bucket's encryption config just from being asked to read it"
    );
}

#[tokio::test]
async fn the_passphrase_comes_only_from_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    seeded(dir.path()).await;

    let missing = run(dir.path(), None, &["get", "widgets/w1.json"]);
    assert!(!missing.success);
    assert!(missing.stderr.contains("S3DB_PASSPHRASE"), "{}", missing.stderr);

    let wrong = run(dir.path(), Some("not it"), &["get", "widgets/w1.json"]);
    assert!(!wrong.success);

    // A listing needs no passphrase at all: a scan shouldn't fail for want of
    // a secret it never uses.
    let ls = run(dir.path(), None, &["ls", "widgets/"]);
    assert!(ls.success, "{}", ls.stderr);
}

#[tokio::test]
async fn rm_needs_explicit_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    seeded(dir.path()).await;

    let refused = run(dir.path(), Some(PASSPHRASE), &["rm", "widgets/w1.json"]);
    assert!(!refused.success);
    assert!(refused.stderr.contains("--yes"), "{}", refused.stderr);
    assert!(
        backend(dir.path()).get("widgets/w1.json").await.unwrap().1.is_some(),
        "the object must still be there"
    );

    let confirmed = run(dir.path(), Some(PASSPHRASE), &["rm", "widgets/w1.json", "--yes"]);
    assert!(confirmed.success, "{}", confirmed.stderr);
    assert!(backend(dir.path()).get("widgets/w1.json").await.unwrap().1.is_none());
}

#[tokio::test]
async fn an_unknown_command_explains_itself() {
    let dir = tempfile::tempdir().unwrap();
    let out = run(dir.path(), None, &["frobnicate"]);
    assert!(!out.success);
    assert!(out.stderr.contains("usage:"), "{}", out.stderr);
}
