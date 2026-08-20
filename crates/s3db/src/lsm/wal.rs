//! Local, per-[`super::Table`] write-ahead log — every [`super::Table::put`]/
//! [`super::Table::delete`] lands here (and is `fsync`'d) before it's
//! acknowledged, so a crash between writes and the next flush loses
//! nothing: [`Wal::replay`] on [`super::Table::open`] reconstructs the
//! memtable exactly as it stood. `docs/s3db-fulldb-roadmap.md`: "ack rápido
//! al caller sin tocar S3 por write individual."
//!
//! Deliberately local disk, not the bucket -- durability here is about
//! surviving *this process* crashing, not about surviving losing the whole
//! machine, which the eventual SSTable flush to the bucket already covers.
//! Single-writer per table, same as everywhere else in this crate's
//! CAS-based concurrency story: two processes appending to the same WAL
//! file would corrupt it, so exactly one process should own a given
//! [`super::Table`] at a time.
//!
//! Format: a flat sequence of `[frame_len: u32 LE][sealed frame]` frames.
//! Each frame is one AEAD-sealed record, and the record inside it is
//! `[tag: u8][key_len: u32 LE][key][value_len: u32 LE][value]`
//! (`value_len`/`value` omitted for a delete tag).
//!
//! Sealed, not raw: this file holds every acknowledged write until the next
//! flush, so writing it in the clear would put the same rows on local disk
//! that the bucket only ever sees encrypted -- and a `.rotating` leftover
//! from a crashed flush can sit there indefinitely. The AAD binds the
//! table's own root prefix, so a WAL file moved to another table's path
//! fails to open rather than replaying someone else's rows.
//!
//! [`Wal::replay`] stops at the first *incomplete* frame rather than
//! erroring -- the one way a crash can corrupt this file is a truncated
//! write in progress at the moment of the crash, always at the very end,
//! and stopping there recovers everything before it instead of losing the
//! whole log over its last, incomplete record. A frame that is complete but
//! doesn't open is a different thing entirely (a WAL from another table, a
//! different key, or tampering) and is a hard error: silently continuing
//! would drop acknowledged writes.
//!
//! [`Wal::rotate`] lets [`super::Table::flush`] hand off the current file to
//! a sibling `<path>.rotating` name and keep appending new writes to a
//! fresh one at `path`, so a flush's SSTable build + bucket write can run
//! without blocking those new writes on the same lock. If the process dies
//! before the flush finishes cleaning that rotated file up,
//! [`heal_rotating_wal`] (called from [`super::Table::open`]) folds it back
//! into `path`, oldest-first, before anything replays it -- from then on
//! it's exactly as if the crash had happened before the flush ever started
//! rotating.

use super::LsmKey;
use super::memtable::MemValue;
use crate::cipher::{Cipher, CompressionStrategy};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;

const TAG_PUT: u8 = 0;
const TAG_DELETE: u8 = 1;

/// The one fixed sibling name [`Wal::rotate`] hands the current file off
/// to. A single fixed name (not a generation counter) is enough because
/// [`super::Table`] never has more than one flush in flight at a time --
/// its own `state` lock only ever gets rotated out from under one flush
/// attempt before that attempt either finishes or aborts.
fn rotating_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".rotating");
    PathBuf::from(p)
}

/// Folds a leftover `<path>.rotating` file (left behind by a process that
/// died between [`Wal::rotate`] and the flush that triggered it either
/// finishing or cleaning the rotated file back up) into `path`, in the
/// correct oldest-first order, before anything opens or replays `path` --
/// see this module's own doc comment. A no-op if there's no such file,
/// which is by far the common case (most flushes complete normally).
pub async fn heal_rotating_wal(path: &Path) -> Result<()> {
    let rotating = rotating_path(path);
    let old_bytes = match fs::read(&rotating).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", rotating.display())),
    };
    let current_bytes = match fs::read(path).await {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut combined = old_bytes;
    combined.extend_from_slice(&current_bytes);

    let dir = path.parent().context("WAL path has no parent directory")?;
    let tmp = tempfile::Builder::new()
        .prefix(".s3db-wal-heal-")
        .tempfile_in(dir)
        .with_context(|| format!("creating temp file in {}", dir.display()))?;
    let tmp_path = tmp.into_temp_path();
    fs::write(&tmp_path, &combined)
        .await
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    let file = fs::File::open(&tmp_path)
        .await
        .with_context(|| format!("reopening {}", tmp_path.display()))?;
    file.sync_all()
        .await
        .with_context(|| format!("syncing {}", tmp_path.display()))?;
    drop(file);
    tmp_path
        .persist(path)
        .with_context(|| format!("healing WAL -> {}", path.display()))?;

    // The rotated file's content is now folded into `path` -- best-effort
    // cleanup, same tolerance as every other post-recovery tidy-up in this
    // crate; a leftover `.rotating` file next to an already-healed `path`
    // is harmless (nothing reads it unless it's about to be healed again).
    let _ = fs::remove_file(&rotating).await;
    Ok(())
}

/// Ceiling on one frame's sealed length, so a corrupt or hostile length
/// prefix can't make replay allocate before anything has been
/// authenticated. Generous next to any real record: a memtable row that
/// approached this would never have fit the flush threshold either.
const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

pub struct Wal {
    path: PathBuf,
    file: fs::File,
    cipher: Cipher,
    /// What every frame's AEAD binds -- see this module's doc comment.
    aad: String,
}

/// The AAD every frame of the WAL for the table rooted at `root` is sealed
/// under. A free function so [`Wal::replay`] can build it without a `Wal`.
pub fn wal_aad(root: &str) -> String {
    format!("{root}\0lsm-wal")
}

impl Wal {
    /// Opens (creating if missing, and any missing parent directories)
    /// `path` for appending. Doesn't replay it -- see [`Self::replay`],
    /// called separately so [`super::Table::open`] can build its memtable
    /// from the result before this handle even exists.
    pub async fn open(path: PathBuf, cipher: Cipher, aad: String) -> Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .await
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        // Owner-only: the frames are sealed, but the file's existence and
        // size still describe this table's write activity, and there is no
        // reason for any other account on the machine to read it.
        #[cfg(unix)]
        options.mode(0o600);
        let file = options
            .open(&path)
            .await
            .with_context(|| format!("opening WAL {}", path.display()))?;
        Ok(Wal {
            path,
            file,
            cipher,
            aad,
        })
    }

    pub async fn append_put(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        let mut record = Vec::with_capacity(1 + 4 + key.len() + 4 + value.len());
        record.push(TAG_PUT);
        record.extend_from_slice(&(key.len() as u32).to_le_bytes());
        record.extend_from_slice(key);
        record.extend_from_slice(&(value.len() as u32).to_le_bytes());
        record.extend_from_slice(value);
        self.append_record(&record).await
    }

    pub async fn append_delete(&mut self, key: &[u8]) -> Result<()> {
        let mut record = Vec::with_capacity(1 + 4 + key.len());
        record.push(TAG_DELETE);
        record.extend_from_slice(&(key.len() as u32).to_le_bytes());
        record.extend_from_slice(key);
        self.append_record(&record).await
    }

    async fn append_record(&mut self, record: &[u8]) -> Result<()> {
        let sealed = self
            .cipher
            .seal(&self.aad, record, CompressionStrategy::None)
            .with_context(|| format!("sealing a WAL record for {}", self.path.display()))?;
        if sealed.len() > MAX_FRAME_LEN {
            bail!(
                "WAL record for {} is {} bytes sealed, over the {MAX_FRAME_LEN}-byte frame ceiling",
                self.path.display(),
                sealed.len()
            );
        }
        let mut frame = Vec::with_capacity(4 + sealed.len());
        frame.extend_from_slice(&(sealed.len() as u32).to_le_bytes());
        frame.extend_from_slice(&sealed);
        self.file
            .write_all(&frame)
            .await
            .with_context(|| format!("appending to WAL {}", self.path.display()))?;
        // Durability before this call returns is the entire point of a
        // WAL -- an ack that hasn't hit disk yet isn't a real ack.
        self.file
            .sync_all()
            .await
            .with_context(|| format!("syncing WAL {}", self.path.display()))
    }

    /// Truncates the log to empty -- called once a flush has durably
    /// written every record here into an SSTable, so replaying them again
    /// would be redundant. `append` mode means the next write always lands
    /// at end-of-file, so truncating to zero length is enough; no seek or
    /// reopen needed.
    pub async fn reset(&mut self) -> Result<()> {
        self.file
            .set_len(0)
            .await
            .with_context(|| format!("truncating WAL {}", self.path.display()))
    }

    /// Hands the current file off to its `.rotating` sibling and reopens a
    /// fresh, empty file at this `Wal`'s own path for it to keep appending
    /// to -- see this module's doc comment. Returns the rotated-away
    /// file's path; the caller owns cleaning it up (or, on failure, folding
    /// still-undurable records back into the WAL this `Wal` now represents).
    pub async fn rotate(&mut self) -> Result<PathBuf> {
        let rotating = rotating_path(&self.path);
        fs::rename(&self.path, &rotating)
            .await
            .with_context(|| format!("rotating WAL {} -> {}", self.path.display(), rotating.display()))?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .with_context(|| format!("reopening WAL {}", self.path.display()))?;
        Ok(rotating)
    }

    /// Replays `path` into an ordered map of the state it describes — a
    /// missing file (nothing was ever written, or a prior `reset` already
    /// cleared it) replays to empty, not an error.
    pub async fn replay(path: &Path, cipher: &Cipher, aad: &str) -> Result<BTreeMap<LsmKey, MemValue>> {
        let bytes = match fs::read(path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(e).with_context(|| format!("reading WAL {}", path.display())),
        };
        let mut out = BTreeMap::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let Some(frame) = next_frame(&bytes[pos..]) else {
                // Incomplete trailing frame: the crash case, see the module
                // doc. Everything before it is already recovered.
                break;
            };
            let record = cipher.open(aad, frame.sealed).with_context(|| {
                format!(
                    "WAL {} has a frame this table's key can't open -- a log from another table, \
                     a different encryption key, or tampering. Refusing to replay past it rather \
                     than silently dropping acknowledged writes.",
                    path.display()
                )
            })?;
            pos += frame.consumed;
            match parse_record(&record) {
                Some((_consumed, key, value)) => {
                    out.insert(key, value);
                }
                // A frame that opened but doesn't parse can't come from a
                // partial write (the AEAD tag covers the whole record), so
                // this is a real inconsistency rather than the crash case.
                None => bail!("WAL {} holds a sealed frame that isn't a valid record", path.display()),
            }
        }
        Ok(out)
    }
}

/// One complete frame at the start of `buf`.
struct Frame<'a> {
    sealed: &'a [u8],
    consumed: usize,
}

/// Reads the frame at the start of `buf` — `None` when `buf` doesn't hold
/// a complete one (the truncated-tail case [`Wal::replay`] tolerates). The
/// declared length is bounded before any slice is taken: it is the one
/// number here that is read before anything is authenticated.
fn next_frame(buf: &[u8]) -> Option<Frame<'_>> {
    let len = u32::from_le_bytes(buf.get(0..4)?.try_into().ok()?) as usize;
    if len == 0 || len > MAX_FRAME_LEN {
        return None;
    }
    let sealed = buf.get(4..4 + len)?;
    Some(Frame {
        sealed,
        consumed: 4 + len,
    })
}

/// Parses one record from the start of `buf`, returning `(bytes consumed,
/// key, value)` — `None` if `buf` doesn't hold a complete record (the
/// truncation case [`Wal::replay`]'s doc describes).
fn parse_record(buf: &[u8]) -> Option<(usize, LsmKey, MemValue)> {
    let (&tag, rest) = buf.split_first()?;
    let key_len = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?) as usize;
    let rest = &rest[4..];
    let key = rest.get(0..key_len)?.to_vec();
    let rest = &rest[key_len..];
    match tag {
        TAG_PUT => {
            let value_len = u32::from_le_bytes(rest.get(0..4)?.try_into().ok()?) as usize;
            let value = rest.get(4..4 + value_len)?.to_vec();
            Some((1 + 4 + key_len + 4 + value_len, key, MemValue::Put(value)))
        }
        TAG_DELETE => Some((1 + 4 + key_len, key, MemValue::Tombstone)),
        _ => None, // unrecognized tag: same as truncation, stop replaying here
    }
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/wal.rs"]
mod tests;
