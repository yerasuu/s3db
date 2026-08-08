//! A minimal query builder over phases 1-5's primitives —
//! `docs/s3db-fulldb-roadmap.md` phase 8, "condicionado a uso real": this
//! stays intentionally small (one predicate shape, no joins, no
//! aggregation) rather than growing into a planner nothing has asked for
//! yet.
//!
//! [`Predicate`] is the one new idea: a single-column comparison that
//! [`super::Table::scan_typed_where`] can decide *without opening a
//! block* whenever that block's [`super::ColumnStats`] (phase 4's per-block
//! min/max, computed at flush time and otherwise unused until now) rules
//! it out entirely. This is a pure optimization -- [`Predicate::cannot_match`]
//! only ever says "definitely nothing in here," never "everything in here
//! matches," so every block it doesn't prune still gets the real,
//! authoritative per-row check via [`Predicate::matches`] after decoding.
//! A predicate over a non-orderable column, or one compared against a
//! block with no stats at all (a schema-less table, or an all-tombstone
//! block), simply never prunes -- correctness never depends on stats being
//! present or precise.

use super::typed_block::ColumnStats;
use super::value::Value;
use std::cmp::Ordering;

/// A single `row[column] <op> value` comparison, by column position (see
/// [`super::Schema`]'s own doc on why position, not name -- nothing in this
/// crate looks a column up by name today).
#[derive(Debug, Clone, PartialEq)]
pub enum Predicate {
    Eq(usize, Value),
    Lt(usize, Value),
    Lte(usize, Value),
    Gt(usize, Value),
    Gte(usize, Value),
}

/// Same rule [`super::typed_block::compare_orderable`] enforces at the
/// storage layer, but total instead of panicking: two values of different
/// kinds (or a kind stats/predicates were never meant to order, like
/// `Bytes`/`Array`/`Json`) simply aren't comparable here -- `None`, not a
/// crash. A caller who compares mismatched kinds gets "never prunes, never
/// matches," which is always a safe (if uninteresting) answer.
fn try_compare(a: &Value, b: &Value) -> Option<Ordering> {
    match (a, b) {
        (Value::Int64(a), Value::Int64(b)) => Some(a.cmp(b)),
        (Value::Timestamp(a), Value::Timestamp(b)) => Some(a.cmp(b)),
        (Value::Text(a), Value::Text(b)) => Some(a.cmp(b)),
        (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
        (Value::Float64(a), Value::Float64(b)) => a.partial_cmp(b),
        _ => None,
    }
}

impl Predicate {
    pub(crate) fn column(&self) -> usize {
        match self {
            Predicate::Eq(c, _)
            | Predicate::Lt(c, _)
            | Predicate::Lte(c, _)
            | Predicate::Gt(c, _)
            | Predicate::Gte(c, _) => *c,
        }
    }

    fn value(&self) -> &Value {
        match self {
            Predicate::Eq(_, v)
            | Predicate::Lt(_, v)
            | Predicate::Lte(_, v)
            | Predicate::Gt(_, v)
            | Predicate::Gte(_, v) => v,
        }
    }

    /// The authoritative, always-correct check -- run against every row a
    /// [`Predicate::cannot_match`]-driven prune didn't already rule out at
    /// the block level.
    pub(crate) fn matches(&self, row: &[Value]) -> bool {
        let Some(actual) = row.get(self.column()) else {
            return false; // out-of-range column index -- never matches, never panics
        };
        match self {
            Predicate::Eq(_, v) => actual == v,
            Predicate::Lt(_, v) => try_compare(actual, v) == Some(Ordering::Less),
            Predicate::Lte(_, v) => matches!(try_compare(actual, v), Some(Ordering::Less | Ordering::Equal)),
            Predicate::Gt(_, v) => try_compare(actual, v) == Some(Ordering::Greater),
            Predicate::Gte(_, v) => matches!(try_compare(actual, v), Some(Ordering::Greater | Ordering::Equal)),
        }
    }

    /// `true` only when `stats` *proves* no row in the block this came from
    /// can satisfy this predicate -- e.g. `Gt(v)` can't match a block whose
    /// `max <= v`. `false` (never "definitely does match") whenever
    /// `stats` doesn't pin the column down (no min/max at all -- an
    /// all-tombstone block or a non-orderable kind) or the comparison
    /// itself is undecidable (mismatched kinds): the caller falls back to
    /// actually reading the block, which is always correct, just not free.
    pub(crate) fn cannot_match(&self, stats: &ColumnStats) -> bool {
        let (Some(min), Some(max)) = (&stats.min, &stats.max) else {
            return false;
        };
        let v = self.value();
        match self {
            Predicate::Eq(..) => {
                matches!(try_compare(v, min), Some(Ordering::Less))
                    || matches!(try_compare(v, max), Some(Ordering::Greater))
            }
            // A row < v is possible only if min < v.
            Predicate::Lt(..) => matches!(try_compare(min, v), Some(Ordering::Greater | Ordering::Equal)),
            // A row <= v is possible only if min <= v.
            Predicate::Lte(..) => matches!(try_compare(min, v), Some(Ordering::Greater)),
            // A row > v is possible only if max > v.
            Predicate::Gt(..) => matches!(try_compare(max, v), Some(Ordering::Less | Ordering::Equal)),
            // A row >= v is possible only if max >= v.
            Predicate::Gte(..) => matches!(try_compare(max, v), Some(Ordering::Less)),
        }
    }
}

#[cfg(test)]
mod tests;
