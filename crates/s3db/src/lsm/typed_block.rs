//! The columnar block body a schema'd [`super::Table`] flushes instead of
//! the row-oriented `Vec<(LsmKey, MemValue)>` blob a schema-less table
//! uses — `docs/s3db-fulldb-roadmap.md` phase 4. Struct-of-arrays, one
//! [`ColumnData`] per [`Schema`] column, each holding every row's value for
//! that column contiguously (`Option<T>`, `None` marking a tombstoned
//! row's slot). That's what lets [`column_stats`] compute a real per-column
//! min/max in one pass over one homogeneously-typed vector, instead of
//! branching on a mixed-type enum per row the way a row-oriented layout
//! would need to.
//!
//! Sits *inside* the same sealed-block framing [`super::sstable`] already
//! has (one AEAD unit per block, `[len: u32 LE][sealed bytes]` in the
//! object, an entry in `BlockIndexEntry`) — only the *plaintext* a block
//! carries differs; everything about how a block is sealed, located, and
//! fetched via `Backend::get_range` stays exactly what phase 1-3 built.
//! [`super::sstable::BlockIndexEntry::column_stats`] is empty for a
//! schema-less table's blocks and one entry per column for a schema'd
//! table's — `sstable::build`/`decode_block` pick which of the two
//! plaintext formats to use based on whether a [`Schema`] was passed in,
//! which a caller always knows (it's fixed for a `Table`'s lifetime, see
//! [`super::TableConfig::schema`]), so nothing about *which* format a block
//! uses needs to be self-describing in the bytes themselves.

use super::LsmKey;
use super::memtable::MemValue;
use super::value::{Schema, Value, ValueKind};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// One column's values across every row in a block, in row order --
/// `None` at index `i` means row `i` is a tombstone (see [`TypedBlock::is_tombstone`]),
/// since a real, live row always has every column populated
/// ([`Schema::validate`] guarantees that before a row ever reaches here).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
enum ColumnData {
    Int64(Vec<Option<i64>>),
    Float64(Vec<Option<f64>>),
    Text(Vec<Option<String>>),
    Bytes(Vec<Option<Vec<u8>>>),
    Timestamp(Vec<Option<i64>>),
    Bool(Vec<Option<bool>>),
    Array(Vec<Option<Vec<Value>>>),
    Json(Vec<Option<serde_json::Value>>),
}

impl ColumnData {
    fn new(kind: ValueKind, capacity: usize) -> Self {
        macro_rules! with_capacity {
            ($variant:ident) => {
                ColumnData::$variant(Vec::with_capacity(capacity))
            };
        }
        match kind {
            ValueKind::Int64 => with_capacity!(Int64),
            ValueKind::Float64 => with_capacity!(Float64),
            ValueKind::Text => with_capacity!(Text),
            ValueKind::Bytes => with_capacity!(Bytes),
            ValueKind::Timestamp => with_capacity!(Timestamp),
            ValueKind::Bool => with_capacity!(Bool),
            ValueKind::Array => with_capacity!(Array),
            ValueKind::Json => with_capacity!(Json),
        }
    }

    /// Pushes `value` (or a `None` slot, for a tombstoned row) -- panics on
    /// a type mismatch, which [`Schema::validate`] having already run on
    /// every non-tombstone row before this is called rules out.
    fn push(&mut self, value: Option<Value>) {
        match (self, value) {
            (ColumnData::Int64(v), val) => v.push(val.map(unwrap_int64)),
            (ColumnData::Float64(v), val) => v.push(val.map(unwrap_float64)),
            (ColumnData::Text(v), val) => v.push(val.map(unwrap_text)),
            (ColumnData::Bytes(v), val) => v.push(val.map(unwrap_bytes)),
            (ColumnData::Timestamp(v), val) => v.push(val.map(unwrap_timestamp)),
            (ColumnData::Bool(v), val) => v.push(val.map(unwrap_bool)),
            (ColumnData::Array(v), val) => v.push(val.map(unwrap_array)),
            (ColumnData::Json(v), val) => v.push(val.map(unwrap_json)),
        }
    }

    fn get(&self, row_idx: usize) -> Option<Value> {
        match self {
            ColumnData::Int64(v) => v[row_idx].map(Value::Int64),
            ColumnData::Float64(v) => v[row_idx].map(Value::Float64),
            ColumnData::Text(v) => v[row_idx].clone().map(Value::Text),
            ColumnData::Bytes(v) => v[row_idx].clone().map(Value::Bytes),
            ColumnData::Timestamp(v) => v[row_idx].map(Value::Timestamp),
            ColumnData::Bool(v) => v[row_idx].map(Value::Bool),
            ColumnData::Array(v) => v[row_idx].clone().map(Value::Array),
            ColumnData::Json(v) => v[row_idx].clone().map(Value::Json),
        }
    }
}

fn unwrap_int64(v: Value) -> i64 {
    match v {
        Value::Int64(v) => v,
        _ => unreachable!("Schema::validate already checked this column's type"),
    }
}
fn unwrap_float64(v: Value) -> f64 {
    match v {
        Value::Float64(v) => v,
        _ => unreachable!("Schema::validate already checked this column's type"),
    }
}
fn unwrap_text(v: Value) -> String {
    match v {
        Value::Text(v) => v,
        _ => unreachable!("Schema::validate already checked this column's type"),
    }
}
fn unwrap_bytes(v: Value) -> Vec<u8> {
    match v {
        Value::Bytes(v) => v,
        _ => unreachable!("Schema::validate already checked this column's type"),
    }
}
fn unwrap_timestamp(v: Value) -> i64 {
    match v {
        Value::Timestamp(v) => v,
        _ => unreachable!("Schema::validate already checked this column's type"),
    }
}
fn unwrap_bool(v: Value) -> bool {
    match v {
        Value::Bool(v) => v,
        _ => unreachable!("Schema::validate already checked this column's type"),
    }
}
fn unwrap_array(v: Value) -> Vec<Value> {
    match v {
        Value::Array(v) => v,
        _ => unreachable!("Schema::validate already checked this column's type"),
    }
}
fn unwrap_json(v: Value) -> serde_json::Value {
    match v {
        Value::Json(v) => v,
        _ => unreachable!("Schema::validate already checked this column's type"),
    }
}

/// The block's plaintext, before sealing -- keys and tombstone markers
/// row-major (there's only one of each per row, no benefit to columnarizing
/// them), the declared columns struct-of-arrays.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct TypedBlock {
    keys: Vec<LsmKey>,
    is_tombstone: Vec<bool>,
    columns: Vec<ColumnData>,
}

/// Per-column min/max over the *live* (non-tombstoned) rows in one block —
/// `None` for both a column [`Value::is_orderable`] says has no meaningful
/// order (`Bytes`/`Array`/`Json`), or for a block whose every row happens
/// to be a tombstone. A future range-scan/query layer (phases 5, 8) uses
/// this to skip a whole block without decoding it: if a predicate's bound
/// falls entirely outside `[min, max]`, nothing in the block can match.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ColumnStats {
    pub min: Option<Value>,
    pub max: Option<Value>,
}

/// Total order over two [`Value`]s of the *same* orderable kind — panics on
/// a kind mismatch or a non-orderable kind, both of which
/// [`compute_column_stats`] never passes it (it only ever compares values
/// already known to share one [`Value::is_orderable`] kind).
fn compare_orderable(a: &Value, b: &Value) -> Ordering {
    match (a, b) {
        (Value::Int64(a), Value::Int64(b)) => a.cmp(b),
        (Value::Timestamp(a), Value::Timestamp(b)) => a.cmp(b),
        (Value::Text(a), Value::Text(b)) => a.cmp(b),
        (Value::Bool(a), Value::Bool(b)) => a.cmp(b),
        // NaN has no order; treated as neither less nor greater so one
        // NaN among otherwise-comparable floats doesn't panic or poison
        // the whole block's stats -- an edge case, not a claim that NaN
        // bounds are meaningful for pruning.
        (Value::Float64(a), Value::Float64(b)) => a.partial_cmp(b).unwrap_or(Ordering::Equal),
        _ => unreachable!("compute_column_stats only compares same-kind orderable values"),
    }
}

fn compute_column_stats(kind: ValueKind, column: &ColumnData, row_count: usize) -> ColumnStats {
    if !Value::is_orderable(kind) {
        return ColumnStats::default();
    }
    let mut min: Option<Value> = None;
    let mut max: Option<Value> = None;
    for row_idx in 0..row_count {
        let Some(value) = column.get(row_idx) else { continue }; // tombstoned row
        if min
            .as_ref()
            .is_none_or(|m| compare_orderable(&value, m) == Ordering::Less)
        {
            min = Some(value.clone());
        }
        if max
            .as_ref()
            .is_none_or(|m| compare_orderable(&value, m) == Ordering::Greater)
        {
            max = Some(value);
        }
    }
    ColumnStats { min, max }
}

/// Columnarizes `rows` (each already-sealed-then-opened as plain
/// `(LsmKey, MemValue)` pairs, same shape the row-oriented format works
/// with) into one block's plaintext bytes, plus the per-column stats for
/// [`super::sstable::BlockIndexEntry::column_stats`]. Every non-tombstone
/// row's bytes are decoded as `Vec<Value>` and checked against `schema`
/// before anything is pushed into a column -- a mismatch fails the whole
/// block rather than columnarizing a partially-invalid row.
pub(crate) fn encode(schema: &Schema, rows: &[(LsmKey, MemValue)]) -> Result<(Vec<u8>, Vec<ColumnStats>)> {
    let mut keys = Vec::with_capacity(rows.len());
    let mut is_tombstone = Vec::with_capacity(rows.len());
    let mut columns: Vec<ColumnData> = schema
        .columns
        .iter()
        .map(|c| ColumnData::new(c.kind, rows.len()))
        .collect();

    for (key, value) in rows {
        keys.push(key.clone());
        match value {
            MemValue::Tombstone => {
                is_tombstone.push(true);
                for column in &mut columns {
                    column.push(None);
                }
            }
            MemValue::Put(bytes) => {
                let row: Vec<Value> = rmp_serde::from_slice(bytes)
                    .with_context(|| format!("row at key {key:?} isn't valid for a typed table"))?;
                schema.validate(&row)?;
                is_tombstone.push(false);
                for (column, value) in columns.iter_mut().zip(row) {
                    column.push(Some(value));
                }
            }
        }
    }

    let stats = schema
        .columns
        .iter()
        .zip(&columns)
        .map(|(def, column)| compute_column_stats(def.kind, column, rows.len()))
        .collect();

    let block = TypedBlock {
        keys,
        is_tombstone,
        columns,
    };
    let bytes = rmp_serde::to_vec_named(&block).context("serializing a typed block never fails")?;
    Ok((bytes, stats))
}

/// Reverses [`encode`]: decodes a typed block's plaintext back into the
/// same `(LsmKey, MemValue)` shape the row-oriented format produces, so
/// everything above the block layer (point lookups, `read_all`, the
/// compactor) works identically regardless of which format a table uses.
pub(crate) fn decode(schema: &Schema, plain: &[u8]) -> Result<Vec<(LsmKey, MemValue)>> {
    let block: TypedBlock = rmp_serde::from_slice(plain).context("decoding typed block")?;
    let row_count = block.keys.len();
    bail_unless_consistent(&block, schema, row_count)?;

    let mut out = Vec::with_capacity(row_count);
    for row_idx in 0..row_count {
        let key = block.keys[row_idx].clone();
        if block.is_tombstone[row_idx] {
            out.push((key, MemValue::Tombstone));
            continue;
        }
        let mut row = Vec::with_capacity(schema.columns.len());
        for column in &block.columns {
            let value = column
                .get(row_idx)
                .with_context(|| format!("row {row_idx} at key {key:?}: live row missing a column value"))?;
            row.push(value);
        }
        let bytes = rmp_serde::to_vec_named(&row).context("serializing a decoded typed row never fails")?;
        out.push((key, MemValue::Put(bytes)));
    }
    Ok(out)
}

fn bail_unless_consistent(block: &TypedBlock, schema: &Schema, row_count: usize) -> Result<()> {
    if block.is_tombstone.len() != row_count {
        bail!(
            "typed block has {} keys but {} tombstone markers",
            row_count,
            block.is_tombstone.len()
        );
    }
    if block.columns.len() != schema.columns.len() {
        bail!(
            "typed block has {} column(s) but the schema declares {}",
            block.columns.len(),
            schema.columns.len()
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/typed_block.rs"]
mod tests;
