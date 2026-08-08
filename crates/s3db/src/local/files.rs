//! [`Backend`] over a plain local filesystem directory, one real file per
//! key — the original `local` driver, still the default
//! ([`LocalEngine::Files`][crate::config::LocalEngine::Files]) and the only
//! format any pre-existing deployment has on disk.
//!
//! Unlike every other driver, a local filesystem has no native
//! compare-and-swap primitive to build [`Backend::put_cas`] on. This
//! backend adds one: a version-counter sidecar (`<key>.s3dbrev`) next to
//! each object, updated under an exclusive `flock` on a second sidecar
//! (`<key>.s3dblock`) so the read-compare-write sequence is atomic. That
//! gives real CAS semantics, but only **within one machine**: `flock` has
//! no meaning across a network filesystem shared by two different hosts,
//! so this driver is scoped to "one deployment, one machine", not a
//! shared/clustered setup. Don't point two separate machines at the same
//! NFS-mounted root and expect the same safety S3/R2/Azure/GCS give.
//!
//! See [`crate::local::redb_backend`] for the alternative that replaces all
//! of this hand-rolled CAS with a real embedded transaction engine.

use crate::backend::{Backend, Cas, DeleteOutcome};
use crate::config::LocalParams;
#[cfg(feature = "streaming")]
use anyhow::bail;
use anyhow::{Context, Result};
use fs4::tokio::AsyncFileExt;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File, OpenOptions};

const REV_SUFFIX: &str = ".s3dbrev";
const LOCK_SUFFIX: &str = ".s3dblock";
/// How many keys [`FilesBackend::delete_many`] deletes at once — each
/// delete takes its own `flock`, so a bit of overlap is still worth
/// something even though this is all local disk (no network round trip to
/// hide behind).
const DELETE_CONCURRENCY: usize = 8;

#[derive(Debug)]
pub struct FilesBackend {
    root: PathBuf,
}

impl FilesBackend {
    pub fn new(cfg: &LocalParams) -> Self {
        FilesBackend {
            root: PathBuf::from(&cfg.bucket),
        }
    }

    fn data_path(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }

    fn rev_path(&self, key: &str) -> PathBuf {
        let mut p = self.data_path(key).into_os_string();
        p.push(REV_SUFFIX);
        PathBuf::from(p)
    }

    fn lock_path(&self, key: &str) -> PathBuf {
        let mut p = self.data_path(key).into_os_string();
        p.push(LOCK_SUFFIX);
        PathBuf::from(p)
    }
}

/// Reads the decimal counter in `path`, or `None` if it doesn't exist yet.
async fn read_rev(path: &Path) -> Result<Option<u64>> {
    match fs::read_to_string(path).await {
        Ok(s) => {
            Ok(Some(s.trim().parse().with_context(|| {
                format!("{}: invalid version counter", path.display())
            })?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Writes `bytes` to `path` via a temp-file-then-rename so a reader never
/// sees a half-written file.
async fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().context("local storage path has no parent directory")?;
    fs::create_dir_all(dir)
        .await
        .with_context(|| format!("creating {}", dir.display()))?;
    let tmp = tempfile::Builder::new()
        .prefix(".s3db-tmp-")
        .tempfile_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    let tmp_path = tmp.into_temp_path();
    fs::write(&tmp_path, bytes)
        .await
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    // fsync before the rename: a cut halfway through must not leave a valid
    // name pointing at half-written content.
    let file = File::open(&tmp_path)
        .await
        .with_context(|| format!("reopening {}", tmp_path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("syncing {}", tmp_path.display()))?;
    drop(file);
    tmp_path
        .persist(path)
        .with_context(|| format!("moving temp file -> {}", path.display()))?;
    Ok(())
}

/// Same discipline as [`write_atomic`], but streams `source`'s bytes into
/// `path` (via `tokio::io::copy`) instead of taking them as an in-memory
/// buffer — bounded memory regardless of `source`'s size.
#[cfg(feature = "streaming")]
async fn write_atomic_from_file(path: &Path, source: &Path) -> Result<()> {
    let dir = path.parent().context("local storage path has no parent directory")?;
    fs::create_dir_all(dir)
        .await
        .with_context(|| format!("creating {}", dir.display()))?;
    let tmp = tempfile::Builder::new()
        .prefix(".s3db-tmp-")
        .tempfile_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    let tmp_path = tmp.into_temp_path();
    {
        let mut src = File::open(source)
            .await
            .with_context(|| format!("opening {}", source.display()))?;
        let mut dst = File::create(&tmp_path)
            .await
            .with_context(|| format!("writing {}", tmp_path.display()))?;
        tokio::io::copy(&mut src, &mut dst)
            .await
            .with_context(|| format!("copying to {}", tmp_path.display()))?;
        // fsync before the rename, same reasoning as `write_atomic`.
        dst.sync_all()
            .await
            .with_context(|| format!("syncing {}", tmp_path.display()))?;
    }
    tmp_path
        .persist(path)
        .with_context(|| format!("moving temp file -> {}", path.display()))?;
    Ok(())
}

/// Opens (creating if missing) and exclusively locks `<key>.s3dblock`,
/// serializing every write to this one key — across processes on this
/// machine (see module doc), not just within this one call. `flock` itself
/// is a blocking syscall; even `fs4`'s tokio support only forwards to it
/// directly rather than offloading to a blocking-pool thread, so a
/// contended call here can stall this task briefly. Acceptable: the only
/// real contention is two processes racing the same key at once — a local
/// filesystem operation, not a network call, so the stall is bounded and
/// short.
async fn lock_key(lock_path: &Path) -> Result<File> {
    if let Some(dir) = lock_path.parent() {
        fs::create_dir_all(dir)
            .await
            .with_context(|| format!("creating {}", dir.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)
        .await
        .with_context(|| format!("opening {}", lock_path.display()))?;
    file.lock()
        .with_context(|| format!("taking exclusive lock on {}", lock_path.display()))?;
    Ok(file)
}

#[async_trait::async_trait]
impl Backend for FilesBackend {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)> {
        let data_path = self.data_path(key);
        let bytes = match fs::read(&data_path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), None)),
            Err(e) => return Err(e).with_context(|| format!("reading {}", data_path.display())),
        };
        let etag = read_rev(&self.rev_path(key)).await?.map(|n| n.to_string());
        Ok((bytes, etag))
    }

    async fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let data_path = self.data_path(key);
        let mut file = File::open(&data_path)
            .await
            .with_context(|| format!("opening {}", data_path.display()))?;
        file.seek(std::io::SeekFrom::Start(offset))
            .await
            .with_context(|| format!("seeking {} to offset {offset}", data_path.display()))?;
        let mut buf = vec![0u8; len as usize];
        file.read_exact(&mut buf)
            .await
            .with_context(|| format!("reading {len} bytes at offset {offset} of {}", data_path.display()))?;
        Ok(buf)
    }

    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas> {
        let lock_file = lock_key(&self.lock_path(key)).await?;
        let rev_path = self.rev_path(key);
        let current = read_rev(&rev_path).await?;
        let current_etag = current.map(|n| n.to_string());
        if expected_etag != current_etag.as_deref() {
            return Ok(Cas::Conflict);
        }
        let next = current.unwrap_or(0) + 1;
        write_atomic(&self.data_path(key), &body).await?;
        write_atomic(&rev_path, next.to_string().as_bytes()).await?;
        drop(lock_file); // releases the flock
        Ok(Cas::Ok)
    }

    async fn delete(&self, key: &str) -> Result<DeleteOutcome> {
        let lock_file = match lock_key(&self.lock_path(key)).await {
            Ok(f) => f,
            Err(e) => {
                eprintln!("warning: couldn't delete {key}: {e:#}");
                return Ok(DeleteOutcome {
                    attempted: 1,
                    confirmed: 0,
                });
            }
        };
        let _ = fs::remove_file(self.data_path(key)).await;
        let _ = fs::remove_file(self.rev_path(key)).await;
        drop(lock_file);
        Ok(DeleteOutcome {
            attempted: 1,
            confirmed: 1,
        })
    }

    async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome> {
        let mut outcome = DeleteOutcome::default();
        for chunk in keys.chunks(DELETE_CONCURRENCY) {
            let results: Vec<DeleteOutcome> =
                futures::future::try_join_all(chunk.iter().map(|key| self.delete(key))).await?;
            outcome = DeleteOutcome::combine([outcome].into_iter().chain(results));
        }
        Ok(outcome)
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>> {
        // Every prefix this crate actually scans with ends in '/' (a real
        // directory boundary — `.conf/txn/`, a collection's own prefix,
        // ...), so walking root.join(prefix) as a directory covers every
        // real call site.
        let dir = self.root.join(prefix);
        let mut out = Vec::new();
        if dir.is_dir() {
            walk_dir(&dir, &self.root, &mut out).await?;
        } else if let Ok(meta) = fs::metadata(&dir).await {
            // `prefix` happens to name a single object exactly (no
            // trailing '/'), not a directory of them — a narrow safety
            // net, not the common path (see above).
            let key = relative_key(&dir, &self.root);
            out.push((key, meta.len()));
        }
        Ok(out)
    }

    #[cfg(feature = "streaming")]
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()> {
        let lock_file = lock_key(&self.lock_path(key)).await?;
        let rev_path = self.rev_path(key);
        let next = read_rev(&rev_path).await?.unwrap_or(0) + 1;
        write_atomic_from_file(&self.data_path(key), source).await?;
        write_atomic(&rev_path, next.to_string().as_bytes()).await?;
        drop(lock_file);
        Ok(())
    }

    #[cfg(feature = "streaming")]
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()> {
        let data_path = self.data_path(key);
        match fs::copy(&data_path, dest).await {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!("{key} doesn't exist in local storage"),
            Err(e) => Err(e).with_context(|| format!("reading {}", data_path.display())),
        }
    }
}

fn relative_key(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Recursive directory walk collecting `(key, size)` for every real object
/// under `dir` — boxed because an async fn can't call itself directly
/// (the resulting future would have unbounded size).
fn walk_dir<'a>(
    dir: &'a Path,
    root: &'a Path,
    out: &'a mut Vec<(String, u64)>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
    Box::pin(async move {
        let mut entries = fs::read_dir(dir)
            .await
            .with_context(|| format!("listing {}", dir.display()))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("listing {}", dir.display()))?
        {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .await
                .with_context(|| format!("checking type of {}", path.display()))?;
            if file_type.is_dir() {
                walk_dir(&path, root, out).await?;
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            if name.ends_with(REV_SUFFIX) || name.ends_with(LOCK_SUFFIX) {
                continue; // internal bookkeeping sidecars, not real keys
            }
            let size = entry.metadata().await.map(|m| m.len()).unwrap_or(0);
            out.push((relative_key(&path, root), size));
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests;
