//! Typed row values and the schema that declares their shape —
//! `docs/s3db-fulldb-roadmap.md` phase 4: "resueltos por el formato de
//! bloque, no por un enum ad-hoc" for the *storage* side ([`super::typed_block`]
//! is where that actually happens); this module is just the type vocabulary
//! both that and a future caller (phase 5's range scan, phase 8's query
//! builder) share.
//!
//! Same principle as Arrow/Parquet, deliberately minimal: no dictionary
//! encoding, no decimal/date-only types, no unions beyond [`Value::Json`]'s
//! escape hatch for whatever doesn't fit the declared shape.

use serde::{Deserialize, Serialize};

/// One row's worth of typed data, matching a [`Schema`]'s column order and
/// count. Missing a value where the schema declares one isn't representable
/// at this level -- use [`Value`]'s own absence (there is none; a caller
/// that wants "no value" for a column reaches for [`Value::Json`] with
/// `serde_json::Value::Null`, or picks a column type where an empty/zero
/// value is a legitimate default) rather than this crate inventing a
/// separate nullability story on top of an already-minimal format.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Int64(i64),
    Float64(f64),
    Text(String),
    Bytes(Vec<u8>),
    /// Milliseconds since the Unix epoch -- same convention every other
    /// timestamp in this crate already uses (`crate::txn::now_ms`, etc.),
    /// so a caller never has to convert between two.
    Timestamp(i64),
    Bool(bool),
    /// Elements aren't further columnarized -- a real nested/repeated-field
    /// columnar layout (what Parquet does) is real complexity this "minimal
    /// version" explicitly isn't taking on; an array column stores one
    /// opaque encoded `Vec<Value>` per row instead of per-element arrays of
    /// its own. Still gets a real column slot and a place in a [`Schema`];
    /// it just isn't a target [`super::typed_block::ColumnStats`] computes
    /// min/max for (see that type's own doc).
    Array(Vec<Value>),
    /// Escape hatch for anything that doesn't fit a declared shape --
    /// same role `serde_json::Value` already plays as
    /// [`crate::txn::TxnOp::value`]'s type, reused here rather than
    /// inventing a second "arbitrary JSON" representation.
    Json(serde_json::Value),
}

/// Which [`Value`] variant a column holds — a [`Schema`] is a sequence of
/// `(name, ValueKind)` pairs, checked against actual [`Value`]s at
/// [`super::typed_block::encode`] time so a mismatched row fails loudly
/// there rather than silently miscolumnarizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueKind {
    Int64,
    Float64,
    Text,
    Bytes,
    Timestamp,
    Bool,
    Array,
    Json,
}

impl Value {
    pub fn kind(&self) -> ValueKind {
        match self {
            Value::Int64(_) => ValueKind::Int64,
            Value::Float64(_) => ValueKind::Float64,
            Value::Text(_) => ValueKind::Text,
            Value::Bytes(_) => ValueKind::Bytes,
            Value::Timestamp(_) => ValueKind::Timestamp,
            Value::Bool(_) => ValueKind::Bool,
            Value::Array(_) => ValueKind::Array,
            Value::Json(_) => ValueKind::Json,
        }
    }

    /// `true` for the kinds [`super::typed_block::ColumnStats`] can
    /// meaningfully compute a min/max over -- a total order a block-pruning
    /// reader could later use to skip a whole block. `Bytes`/`Array`/`Json`
    /// don't get one: comparing arbitrary bytes or JSON documents
    /// lexicographically wouldn't mean anything a caller could use to prune
    /// a real predicate, so those columns are always "must read" instead of
    /// pretending to offer a bound that doesn't help.
    pub(crate) fn is_orderable(kind: ValueKind) -> bool {
        matches!(
            kind,
            ValueKind::Int64 | ValueKind::Float64 | ValueKind::Text | ValueKind::Timestamp | ValueKind::Bool
        )
    }
}

/// One column's name and declared type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ColumnDef {
    pub name: String,
    pub kind: ValueKind,
}

/// A [`super::Table`]'s declared row shape, fixed for that table's lifetime
/// (see [`super::TableConfig::schema`]) -- every row [`super::Table::put_typed`]
/// accepts must have exactly this many [`Value`]s, each matching its
/// column's [`ValueKind`] in order. Column *names* exist for a caller's own
/// readability and for a future query builder (phase 8) to reference by
/// name; nothing in this crate's own encoding looks a column up by name
/// today, only by position.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Schema {
    pub columns: Vec<ColumnDef>,
}

impl Schema {
    pub fn new(columns: Vec<ColumnDef>) -> Self {
        Schema { columns }
    }

    /// `Ok(())` if `row` has exactly one [`Value`] per column, each
    /// matching that column's declared [`ValueKind`] -- the check
    /// [`super::typed_block::encode`] runs before columnarizing anything,
    /// so a caller's mistake surfaces as a clear error at write time, not
    /// as silently wrong data read back later.
    pub(crate) fn validate(&self, row: &[Value]) -> anyhow::Result<()> {
        anyhow::ensure!(
            row.len() == self.columns.len(),
            "row has {} value(s), schema declares {}",
            row.len(),
            self.columns.len()
        );
        for (value, column) in row.iter().zip(&self.columns) {
            anyhow::ensure!(
                value.kind() == column.kind,
                "column {:?} is declared {:?}, got {:?}",
                column.name,
                column.kind,
                value.kind()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/value.rs"]
mod tests;
