//! Reads a bucket by hand: list, count, decrypt, verify.
//!
//! Every object in an `s3db` bucket is encrypted MessagePack, which is the
//! point, and which means that when something looks wrong there is no
//! equivalent of opening a `psql` shell. A caller migrating off a relational
//! database gives that up on the day of the cutover; this gives it back.
//!
//! Read-only apart from `rm`, which needs `--yes`. In particular it opens the
//! bucket's cipher with [`s3db::bootstrap::open_cipher`], never
//! `get_or_create_cipher`: a mistyped path must fail, not become a freshly
//! initialized empty bucket whose encryption config was written by a command
//! that was only meant to look at it.
//!
//! The passphrase comes from `S3DB_PASSPHRASE` and never from an argument: an
//! argument lands in shell history and in every `ps` listing on the machine.

use anyhow::{Context, Result, bail};
use s3db::{Backend, BackendConfig, Cipher, Collection, build_backend};
use std::sync::Arc;

const USAGE: &str = "\
usage: s3db-inspect [--local <dir> | --config <file.json>] <command> [args]

commands:
  ls <prefix> [limit]     list keys and sizes under a prefix
  count <prefix>          how many objects, and how many bytes
  get <key>               decrypt one object and print it as JSON
  names <collection>      entry names of a Collection (skips its bookkeeping)
  schema <collection>     a Collection's migration bookkeeping
  verify <prefix>         try to decrypt everything under a prefix, report what fails
  rm <key> --yes          delete one object

backend:
  --local <dir>           the local `files` driver over a directory
  --config <file.json>    a serialized BackendConfig ({\"driver\": \"s3\", ...})

environment:
  S3DB_PASSPHRASE         required for `get`/`names`/`schema`/`verify`
";

/// Keys per page while listing or verifying.
const PAGE: usize = 500;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (backend, rest) = parse_backend(&args)?;
    let Some((command, operands)) = rest.split_first() else {
        bail!("{USAGE}");
    };

    match command.as_str() {
        "ls" => ls(&backend, operands).await,
        "count" => count(&backend, operands).await,
        "get" => get(&backend, operands).await,
        "names" => names(&backend, operands).await,
        "schema" => schema(&backend, operands).await,
        "verify" => verify(&backend, operands).await,
        "rm" => rm(&backend, operands).await,
        "--help" | "-h" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => bail!("unrecognized command {other:?}\n{USAGE}"),
    }
}

/// Builds the backend from the leading flags and returns whatever is left.
fn parse_backend(args: &[String]) -> Result<(Arc<dyn Backend>, &[String])> {
    match args.split_first().map(|(head, tail)| (head.as_str(), tail)) {
        Some(("--local", tail)) => {
            let (dir, rest) = tail.split_first().context("--local needs a directory\n")?;
            let config = BackendConfig::Local(s3db::LocalParams {
                bucket: dir.clone(),
                engine: s3db::LocalEngine::Files,
            });
            Ok((build_backend(&config)?, rest))
        }
        Some(("--config", tail)) => {
            let (path, rest) = tail.split_first().context("--config needs a file\n")?;
            let text = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
            let config: BackendConfig = serde_json::from_str(&text).with_context(|| format!("parsing {path}"))?;
            Ok((build_backend(&config)?, rest))
        }
        _ => bail!("{USAGE}"),
    }
}

/// Opens the bucket's cipher. Separate from [`parse_backend`] because half
/// these commands never need it, and a listing shouldn't fail for want of a
/// passphrase.
async fn cipher_for(backend: &Arc<dyn Backend>) -> Result<Cipher> {
    let passphrase = std::env::var("S3DB_PASSPHRASE")
        .context("S3DB_PASSPHRASE is not set (it is read from the environment, never from an argument)")?;
    s3db::bootstrap::open_cipher(backend.as_ref(), &passphrase).await
}

fn operand<'a>(operands: &'a [String], index: usize, what: &str) -> Result<&'a str> {
    operands
        .get(index)
        .map(String::as_str)
        .with_context(|| format!("missing {what}\n{USAGE}"))
}

async fn ls(backend: &Arc<dyn Backend>, operands: &[String]) -> Result<()> {
    let prefix = operand(operands, 0, "<prefix>")?;
    let limit: usize = match operands.get(1) {
        Some(raw) => raw.parse().with_context(|| format!("limit {raw:?} is not a number"))?,
        None => usize::MAX,
    };

    let mut shown = 0usize;
    let mut after: Option<String> = None;
    loop {
        let page = backend.list_page(prefix, after.as_deref(), PAGE).await?;
        for (key, size) in &page.entries {
            if shown == limit {
                println!("... (limit reached)");
                return Ok(());
            }
            println!("{size:>12}  {key}");
            shown += 1;
        }
        match page.next_after {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    println!("{shown} object(s)");
    Ok(())
}

async fn count(backend: &Arc<dyn Backend>, operands: &[String]) -> Result<()> {
    let prefix = operand(operands, 0, "<prefix>")?;
    let (objects, bytes) = s3db::count_prefix(backend.as_ref(), prefix).await?;
    println!("{objects} object(s), {bytes} byte(s) under {prefix:?}");
    Ok(())
}

async fn get(backend: &Arc<dyn Backend>, operands: &[String]) -> Result<()> {
    let key = operand(operands, 0, "<key>")?;
    let (sealed, etag) = backend.get(key).await?;
    if etag.is_none() {
        bail!("{key} does not exist");
    }
    // `.conf/encryption.json` is unencrypted plain JSON on purpose -- the one
    // object meant to be read by hand during an incident, which is exactly
    // what this tool is for.
    if key.ends_with("encryption.json") {
        println!("{}", String::from_utf8_lossy(&sealed));
        return Ok(());
    }

    let cipher = cipher_for(backend).await?;
    let plain = cipher.open(key, &sealed).with_context(|| format!("decrypting {key}"))?;
    match rmp_serde::from_slice::<serde_json::Value>(&plain) {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value)?),
        // Not every MessagePack value maps onto JSON (a `bytes` field is the
        // common one). Say so and dump what's there rather than pretending the
        // object is unreadable.
        Err(e) => {
            eprintln!("note: {key} decrypted but is not JSON-representable ({e}); showing raw MessagePack");
            println!("{}", hex_dump(&plain));
        }
    }
    Ok(())
}

async fn names(backend: &Arc<dyn Backend>, operands: &[String]) -> Result<()> {
    let prefix = operand(operands, 0, "<collection>")?;
    let collection = Collection::new_owned(prefix.trim_end_matches('/').to_string());
    let mut after: Option<String> = None;
    let mut total = 0usize;
    loop {
        let (names, next) = collection
            .list_names_page(backend.as_ref(), after.as_deref(), PAGE)
            .await?;
        for name in &names {
            println!("{name}");
            total += 1;
        }
        match next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    println!("{total} entry name(s)");
    Ok(())
}

async fn schema(backend: &Arc<dyn Backend>, operands: &[String]) -> Result<()> {
    let prefix = operand(operands, 0, "<collection>")?;
    let cipher = cipher_for(backend).await?;
    let collection = Collection::new_owned(prefix.trim_end_matches('/').to_string());
    let state = s3db::migrate::schema_state(backend.as_ref(), &cipher, &collection).await?;
    println!("version: {}", state.version);
    for applied in &state.applied {
        println!(
            "  applied v{} {:?} at {}ms, {} entries rewritten",
            applied.version, applied.name, applied.applied_at_ms, applied.entries_rewritten
        );
    }
    match &state.in_progress {
        Some(progress) => println!(
            "  IN PROGRESS v{} {:?}, cursor {:?}, {} rewritten so far",
            progress.version, progress.name, progress.last_name, progress.entries_rewritten
        ),
        None => println!("  no migration in progress"),
    }
    Ok(())
}

async fn verify(backend: &Arc<dyn Backend>, operands: &[String]) -> Result<()> {
    let prefix = operand(operands, 0, "<prefix>")?;
    let cipher = cipher_for(backend).await?;

    let mut checked = 0u64;
    let mut failed = 0u64;
    let mut after: Option<String> = None;
    loop {
        let page = backend.list_page(prefix, after.as_deref(), PAGE).await?;
        for (key, _size) in &page.entries {
            // The unencrypted config would obviously fail an AEAD open; it is
            // not a finding.
            if key.ends_with("encryption.json") {
                continue;
            }
            checked += 1;
            let (sealed, _etag) = backend.get(key).await?;
            if let Err(e) = cipher.open(key, &sealed) {
                failed += 1;
                println!("FAIL {key}: {e:#}");
            }
        }
        match page.next_after {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    println!("checked {checked} object(s), {failed} failed to decrypt");
    if failed > 0 {
        // A nonzero exit so this is usable from a cron job or a CI step
        // without parsing the output.
        std::process::exit(1);
    }
    Ok(())
}

async fn rm(backend: &Arc<dyn Backend>, operands: &[String]) -> Result<()> {
    let key = operand(operands, 0, "<key>")?;
    if operands.get(1).map(String::as_str) != Some("--yes") {
        bail!("refusing to delete {key} without --yes");
    }
    let outcome = backend.delete(key).await?;
    println!(
        "delete {key}: attempted {}, confirmed {}",
        outcome.attempted, outcome.confirmed
    );
    Ok(())
}

/// Enough of a hex dump to recognize what an object holds when it can't be
/// rendered as JSON.
fn hex_dump(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for (offset, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(out, "{:08x}  ", offset * 16);
        for byte in chunk {
            let _ = write!(out, "{byte:02x} ");
        }
        for _ in chunk.len()..16 {
            out.push_str("   ");
        }
        out.push(' ');
        for byte in chunk {
            out.push(if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            });
        }
        out.push('\n');
    }
    out
}
