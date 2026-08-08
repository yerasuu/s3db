//! LSM-tree engine over S3-compatible object storage — `docs/s3db-fulldb-roadmap.md`.
//! An opt-in storage mode, not a replacement for [`crate::collection::Collection`]:
//! that model stays exactly right for exact-key access over thousands (not
//! millions) of entities; this one exists for the case it structurally
//! can't serve — high write volume, range queries, typed columns — where
//! "one entity = one S3 object = one request" hits the partition-request
//! ceiling `docs/s3db.md` documents no matter how the keys are spread.
//!
//! This module (phase 1 of the roadmap) is the write path only: [`Wal`]
//! (local durability so [`Table::put`] acks without touching the bucket),
//! [`Memtable`] (in-memory order, no network round trip), and [`sstable`]
//! (serializing a full memtable into one immutable object per flush — the
//! move that turns "N requests for N rows" into "one request per flush").
//! [`Table::flush`] is deliberately still a dead end here: nothing yet
//! tracks which SSTables exist or reads them back through the bucket. That
//! needs a manifest and [`crate::backend::Backend::get_range`]-driven
//! bloom/block-index lookups — phase 2, not this one.
//!
//! A "row" at this layer is opaque bytes in, opaque bytes out — typed,
//! columnar values ([`docs/s3db-fulldb-roadmap.md`]'s block format) are
//! phase 4's job, layered on top of this without changing anything here.

mod bloom;
mod memtable;
pub mod sstable;
mod table;
mod wal;

pub use memtable::{MemValue, Memtable};
pub use table::{FlushedSSTable, Table, TableConfig};
pub use wal::Wal;

/// A row's sort key in an LSM [`Table`] — arbitrary bytes, ordering is
/// whatever `Ord` on `Vec<u8>` gives (plain byte-lexicographic). Same
/// division of responsibility as [`crate::index::SecondaryIndex::resolve_range`]:
/// this engine only ever compares the bytes it's given, a caller who wants
/// numeric or timestamp ordering picks a byte encoding that sorts that way
/// (big-endian for integers, ISO-8601 for timestamps).
pub type LsmKey = Vec<u8>;
