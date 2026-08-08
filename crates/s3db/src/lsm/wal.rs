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
//! Format: a flat sequence of `[tag: u8][key_len: u32 LE][key][value_len:
//! u32 LE][value]` records (`value_len`/`value` omitted for a delete tag).
//! [`Wal::replay`] stops at the first record it can't fully parse rather
//! than erroring -- the one way a crash can corrupt this file is a
//! truncated write in progress at the moment of the crash, always at the
//! very end, and stopping there recovers everything before it instead of
//! losing the whole log over its last, incomplete record.

use super::LsmKey;
use super::memtable::MemValue;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs::{self, OpenOptions};
use tokio::io::AsyncWriteExt;

const TAG_PUT: u8 = 0;
const TAG_DELETE: u8 = 1;

pub struct Wal {
    path: PathBuf,
    file: fs::File,
}

impl Wal {
    /// Opens (creating if missing, and any missing parent directories)
    /// `path` for appending. Doesn't replay it -- see [`Self::replay`],
    /// called separately so [`super::Table::open`] can build its memtable
    /// from the result before this handle even exists.
    pub async fn open(path: PathBuf) -> Result<Self> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)
                .await
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("opening WAL {}", path.display()))?;
        Ok(Wal { path, file })
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
        self.file
            .write_all(record)
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

    /// Replays `path` into an ordered map of the state it describes — a
    /// missing file (nothing was ever written, or a prior `reset` already
    /// cleared it) replays to empty, not an error.
    pub async fn replay(path: &Path) -> Result<BTreeMap<LsmKey, MemValue>> {
        let bytes = match fs::read(path).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(e) => return Err(e).with_context(|| format!("reading WAL {}", path.display())),
        };
        let mut out = BTreeMap::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            match parse_record(&bytes[pos..]) {
                Some((consumed, key, value)) => {
                    out.insert(key, value);
                    pos += consumed;
                }
                // Truncated (or, in principle, corrupted) trailing bytes --
                // per the module doc, stop here rather than fail the whole
                // replay over a write that was never fully durable anyway.
                None => break,
            }
        }
        Ok(out)
    }
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
mod tests;
