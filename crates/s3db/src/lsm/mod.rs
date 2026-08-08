//! LSM-tree engine over S3-compatible object storage — `docs/s3db-fulldb-roadmap.md`.
//! An opt-in storage mode, not a replacement for [`crate::collection::Collection`]:
//! that model stays exactly right for exact-key access over thousands (not
//! millions) of entities; this one exists for the case it structurally
//! can't serve — high write volume, range queries, typed columns — where
//! "one entity = one S3 object = one request" hits the partition-request
//! ceiling `docs/s3db.md` documents no matter how the keys are spread.
//!
//! Phases 1+2 of the roadmap, the "minimum functional block": [`Wal`]
//! (local durability so [`Table::put`] acks without touching the bucket),
//! [`Memtable`] (in-memory order, no network round trip), [`sstable`]
//! (serializing a full memtable into one immutable, per-block-encrypted
//! object per flush — the move that turns "N requests for N rows" into
//! "one request per flush"), [`manifest`] (the CAS-controlled record of
//! which SSTables currently exist), and [`Table::get`] (memtable first,
//! then the manifest's SSTables newest-to-oldest, each one's bloom filter
//! and block index driving targeted [`crate::backend::Backend::get_range`]
//! reads instead of ever fetching a whole SSTable object).
//!
//! A "row" at this layer is opaque bytes in, opaque bytes out — typed,
//! columnar values ([`docs/s3db-fulldb-roadmap.md`]'s block format) are
//! phase 4's job, layered on top of this without changing anything here.
//! Compaction (phase 3) isn't implemented yet either: SSTables only ever
//! accumulate, never merge, so read amplification grows unbounded with
//! flush count until that lands.

mod bloom;
pub mod manifest;
mod memtable;
pub mod sstable;
mod table;
mod wal;

pub use manifest::{Manifest, ManifestEntry};
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
