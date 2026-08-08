//! Migrates a `local` driver bucket from the `Files` engine's one-file-
//! per-key layout to a single `redb` database, per `docs/s3db-local-mode.md`.
//!
//! Deliberately a separate, explicitly-invoked binary rather than an
//! automatic upgrade path a server takes at startup: a format change this
//! size (`.s3dbrev`/`.s3dblock` sidecars scattered across a directory tree
//! -> one `s3db.redb` file) should never happen without the operator
//! choosing the moment, and being able to inspect the result before
//! flipping `engine` in config and restarting anything that reads this
//! bucket.
//!
//! Reads every real key with [`FilesBackend`] (its own `list_prefix`
//! already skips the CAS sidecars), then hands them all to
//! [`RedbBackend::bulk_load_fresh`] for a single write transaction --
//! either every key lands, or none of them do. Old per-key files are left
//! untouched; this tool only ever adds `s3db.redb`, never deletes anything,
//! so a failed or aborted run leaves the bucket exactly as it found it.

use anyhow::{Context, Result, bail};
use s3db::{Backend, FilesBackend, LocalEngine, LocalParams, RedbBackend};

const USAGE: &str = "usage: s3db-local-migrate <bucket-directory> [--dry-run]";

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let root = args.next().context(USAGE)?;
    let dry_run = match args.next().as_deref() {
        None => false,
        Some("--dry-run") => true,
        Some(other) => bail!("unrecognized argument {other:?}\n{USAGE}"),
    };

    let files = FilesBackend::new(&LocalParams {
        bucket: root.clone(),
        engine: LocalEngine::Files,
    });
    let keys = files.list_prefix("").await.context("listing existing keys")?;
    println!("found {} key(s) under {root}", keys.len());
    if keys.is_empty() {
        println!("nothing to migrate");
        return Ok(());
    }

    if dry_run {
        println!(
            "dry run: would migrate {} key(s) into {root}/s3db.redb, nothing written",
            keys.len()
        );
        return Ok(());
    }

    let mut entries = Vec::with_capacity(keys.len());
    for (key, _size) in &keys {
        let (body, _etag) = files.get(key).await.with_context(|| format!("reading {key}"))?;
        entries.push((key.clone(), body));
    }

    let redb = RedbBackend::new(&LocalParams {
        bucket: root.clone(),
        engine: LocalEngine::Redb,
    });
    let migrated = redb.bulk_load_fresh(entries).await.context("bulk-loading into redb")?;

    println!("migrated {migrated} key(s) into {root}/s3db.redb");
    println!(
        "old per-key files under {root} were left untouched -- verify the new engine works, \
         then either remove them yourself or set `engine = \"files\"` again to roll back"
    );
    Ok(())
}
