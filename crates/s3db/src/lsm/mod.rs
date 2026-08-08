//! LSM-tree engine over S3-compatible object storage — `docs/s3db-fulldb-roadmap.md`.
//! An opt-in storage mode, not a replacement for [`crate::collection::Collection`]:
//! that model stays exactly right for exact-key access over thousands (not
//! millions) of entities; this one exists for the case it structurally
//! can't serve — high write volume, range queries, typed columns — where
//! "one entity = one S3 object = one request" hits the partition-request
//! ceiling `docs/s3db.md` documents no matter how the keys are spread.
//!
//! Phases 1-4 of the roadmap: [`Wal`] (local durability so [`Table::put`]
//! acks without touching the bucket), [`Memtable`] (in-memory order, no
//! network round trip), [`sstable`] (serializing a full memtable into one
//! immutable, per-block-encrypted object per flush — the move that turns
//! "N requests for N rows" into "one request per flush"), [`manifest`] (the
//! CAS-controlled record of which SSTables currently exist), [`Table::get`]
//! (memtable first, then the manifest's SSTables newest-to-oldest, each
//! one's bloom filter and block index driving targeted
//! [`crate::backend::Backend::get_range`] reads instead of ever fetching a
//! whole SSTable object), [`compactor`] (merges every SSTable into one,
//! purging tombstones, so read amplification doesn't grow unbounded with
//! flush count), [`value`]/[`typed_block`] (a table declared with a
//! [`value::Schema`] stores real typed, columnar blocks instead of opaque
//! bytes, with per-column min/max stats a future query builder — phase 8 —
//! can use to skip whole blocks), [`Table::scan`] (a range over the primary
//! key, merging the memtable with every overlapping SSTable, skipping
//! non-overlapping SSTables and blocks via the same manifest/block-index
//! metadata [`Table::get`] already uses), [`SecondaryLsmIndex`] (a
//! second ordered [`Table`] for finding rows by a non-primary field —
//! phase 5's other half), [`location`] ([`TableLocation`]/[`BackendRegistry`],
//! phase 6's multi-backend routing at the same manifest level every table
//! already had), and [`query`] ([`Predicate`], phase 8's minimal query
//! builder — [`Table::scan_typed_where`] uses a predicate's own
//! [`query::Predicate::cannot_match`] against each block's [`ColumnStats`]
//! to skip fetching whole blocks it can prove can't match, the reason
//! phase 4 computed those stats in the first place).
//!
//! A row is opaque bytes in, opaque bytes out ([`Table::put`]/[`Table::get`])
//! *unless* a table declares a [`value::Schema`] ([`TableConfig::schema`]),
//! in which case it's [`value::Value`]s in and out
//! ([`Table::put_typed`]/[`Table::get_typed`]) instead — a per-table choice
//! fixed at creation, not something that varies block to block.

mod bloom;
pub mod compactor;
mod location;
pub mod manifest;
mod memtable;
pub mod query;
mod secondary_index;
pub mod sstable;
mod table;
mod typed_block;
pub mod value;
mod wal;

pub use compactor::{CompactionReport, compact, should_compact};
pub use location::{BackendRegistry, DEFAULT_BACKEND_ID, TableLocation};
pub use manifest::{Manifest, ManifestEntry};
pub use memtable::{MemValue, Memtable};
pub use query::Predicate;
pub use secondary_index::SecondaryLsmIndex;
pub use table::{FlushedSSTable, Table, TableConfig};
pub use typed_block::ColumnStats;
pub use value::{ColumnDef, Schema, Value, ValueKind};
pub use wal::Wal;

/// A row's sort key in an LSM [`Table`] — arbitrary bytes, ordering is
/// whatever `Ord` on `Vec<u8>` gives (plain byte-lexicographic). Same
/// division of responsibility as [`crate::index::SecondaryIndex::resolve_range`]:
/// this engine only ever compares the bytes it's given, a caller who wants
/// numeric or timestamp ordering picks a byte encoding that sorts that way
/// (big-endian for integers, ISO-8601 for timestamps).
pub type LsmKey = Vec<u8>;
