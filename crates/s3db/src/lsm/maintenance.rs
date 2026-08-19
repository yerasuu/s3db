//! The periodic work an [`super::Table`] needs somebody to drive.
//!
//! A `Table` acknowledges a write as soon as its local WAL is durable, which
//! is the entire point of having one — but nothing is visible to another
//! process, and nothing is durable in the bucket, until a flush turns the
//! memtable into an SSTable. And every flush adds an SSTable that later reads
//! have to consult, so without compaction read amplification grows without
//! bound. Both operations existed ([`super::Table::flush`],
//! [`super::Table::compact`], with `should_*` predicates to decide); what was
//! missing was anything that ran them, so a caller that forgot left a table
//! that acked writes and never published them.
//!
//! [`crate::MaintenanceScanner`] covers the `Collection` side of the same
//! problem. This is deliberately the narrow half of it: a `tick` a caller
//! drives from its own timer, not a task this crate spawns. Who owns the
//! background task, how it shuts down, and whether flushes are allowed to
//! contend with foreground writes are the caller's decisions, and a spawned
//! task would take all three away.

use super::table::{FlushedSSTable, Table};
use crate::lsm::compactor::CompactionReport;
use anyhow::Result;

/// Which passes a [`tick`] is allowed to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct LsmMaintenanceConfig {
    /// Flush the memtable when it has reached its threshold.
    pub flush: bool,
    /// Compact when the manifest has accumulated enough SSTables.
    pub compact: bool,
    /// Flush even when the memtable is under its threshold, as long as it
    /// holds anything at all.
    ///
    /// Off by default. On, it trades write amplification (more, smaller
    /// SSTables, and so more compaction) for visibility: an acked write
    /// reaches the bucket within one tick instead of whenever the memtable
    /// happens to fill. Worth it for a table whose readers live in other
    /// processes, which is the only way they see anything at all.
    pub flush_even_if_small: bool,
}

impl Default for LsmMaintenanceConfig {
    fn default() -> Self {
        LsmMaintenanceConfig {
            flush: true,
            compact: true,
            flush_even_if_small: false,
        }
    }
}

/// What one [`tick`] did. Both fields `None` means the table was already in
/// good shape, which is the common case and costs one manifest read.
#[derive(Debug, Default)]
pub struct LsmMaintenanceReport {
    pub flushed: Option<FlushedSSTable>,
    pub compaction: Option<CompactionReport>,
}

impl LsmMaintenanceReport {
    pub fn did_nothing(&self) -> bool {
        self.flushed.is_none() && self.compaction.is_none()
    }
}

/// Runs one round of maintenance on `table`.
///
/// Flush before compact, in the same tick: a flush is what pushes the SSTable
/// count over the compaction threshold, so checking compaction first would
/// always leave the newest SSTable for the tick after next.
pub async fn tick(table: &Table, config: &LsmMaintenanceConfig) -> Result<LsmMaintenanceReport> {
    let mut report = LsmMaintenanceReport::default();

    if config.flush {
        let due = table.should_flush().await || (config.flush_even_if_small && !table.is_empty().await);
        if due {
            report.flushed = table.flush().await?;
        }
    }

    if config.compact && table.should_compact().await? {
        report.compaction = Some(table.compact().await?);
    }

    Ok(report)
}

#[cfg(test)]
#[path = "../../tests/unit/lsm/maintenance.rs"]
mod tests;
