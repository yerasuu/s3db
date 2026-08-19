//! The metrics surface [`crate::resilience::MeteredBackend`] records
//! against -- deliberately just two primitives (a counter and a gauge), no
//! histograms or a specific metrics-library dependency baked in. A caller
//! wires [`MetricsRecorder`] to whatever it already uses (Prometheus,
//! StatsD, an in-process registry); this crate never assumes which.
//!
//! [`InMemoryMetrics`] is the batteries-included recorder for a caller that
//! doesn't already have one: it accumulates in a map and renders Prometheus
//! text on demand, with no dependency and no exporter runtime. Without it the
//! only shipped recorder was [`NoopMetrics`], so metering a backend produced
//! numbers nobody could read.

use std::sync::Arc;

/// Where [`crate::resilience::MeteredBackend`] reports what it observes.
/// `name` is a stable metric name (e.g. `s3db_backend_get_total`,
/// `s3db_shard_occupancy`) -- this trait doesn't namespace or validate it,
/// that's the recorder implementation's job.
pub trait MetricsRecorder: Send + Sync + std::fmt::Debug {
    /// Increments a monotonic counter by `value`.
    fn counter(&self, name: &str, value: u64);
    /// Sets a point-in-time value (not cumulative) -- occupancy, queue
    /// depth, anything that goes up and down rather than only up.
    fn gauge(&self, name: &str, value: f64);
}

/// Discards everything -- the default for a caller that doesn't care to
/// wire up real metrics, so [`crate::resilience::MeteredBackend`] never
/// needs an `Option<Arc<dyn MetricsRecorder>>` scattered through its call
/// sites.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopMetrics;

impl MetricsRecorder for NoopMetrics {
    fn counter(&self, _name: &str, _value: u64) {}
    fn gauge(&self, _name: &str, _value: f64) {}
}

/// `Arc<dyn MetricsRecorder>` shorthand -- every recorder is shared across
/// however many decorator layers/backends reference it.
pub type SharedMetrics = Arc<dyn MetricsRecorder>;

/// Accumulates every counter and gauge in memory and renders them in the
/// Prometheus text exposition format.
///
/// [`MetricsRecorder`] stays a trait for the same reason it always was: this
/// crate has no business deciding that an application's telemetry goes to
/// Prometheus. But "wire it to whatever you already use" is only a reasonable
/// answer to a caller that *has* something already, and [`NoopMetrics`] was
/// the only other option -- so the default outcome of enabling
/// [`crate::resilience::MeteredBackend`] was numbers nobody could see. This
/// is the missing middle: no dependency, no exporter runtime, no protocol
/// beyond a `String` a caller serves from whatever HTTP handler it already
/// has.
///
/// ```
/// # use std::sync::Arc;
/// # use s3db::{MetricsRecorder, InMemoryMetrics};
/// let metrics = Arc::new(InMemoryMetrics::default());
/// metrics.counter("s3db_backend_get_total", 1);
/// metrics.gauge("s3db_shard_occupancy", 0.5);
/// let body = metrics.render_prometheus();
/// assert!(body.contains("s3db_backend_get_total 1"));
/// ```
///
/// Counters accumulate (a counter is monotonic, so repeated increments sum);
/// gauges keep the last value written (a gauge is point-in-time, so an older
/// reading is not evidence of anything). Cardinality is the caller's
/// responsibility: names arrive from [`MetricsRecorder`] already formatted,
/// and a caller that bakes a per-key label into one will grow this map without
/// bound.
#[derive(Debug, Default)]
pub struct InMemoryMetrics {
    counters: std::sync::Mutex<std::collections::BTreeMap<String, u64>>,
    gauges: std::sync::Mutex<std::collections::BTreeMap<String, f64>>,
}

impl InMemoryMetrics {
    /// Every counter's total, sorted by name.
    pub fn counters(&self) -> Vec<(String, u64)> {
        self.counters
            .lock()
            .expect("metrics mutex poisoned")
            .iter()
            .map(|(name, value)| (name.clone(), *value))
            .collect()
    }

    /// Every gauge's latest value, sorted by name.
    pub fn gauges(&self) -> Vec<(String, f64)> {
        self.gauges
            .lock()
            .expect("metrics mutex poisoned")
            .iter()
            .map(|(name, value)| (name.clone(), *value))
            .collect()
    }

    /// One counter's total, or `None` if nothing ever reported it. Absent is
    /// deliberately not zero: "never happened" and "happened zero times" are
    /// different claims, and only the first is knowable here.
    pub fn counter_value(&self, name: &str) -> Option<u64> {
        self.counters.lock().expect("metrics mutex poisoned").get(name).copied()
    }

    /// One gauge's latest value.
    pub fn gauge_value(&self, name: &str) -> Option<f64> {
        self.gauges.lock().expect("metrics mutex poisoned").get(name).copied()
    }

    /// The Prometheus text exposition format: one `# TYPE` line per metric
    /// followed by its sample, sorted by name so a diff between two scrapes
    /// is readable.
    ///
    /// No `# HELP` lines: this type never learns what a metric means, since
    /// [`MetricsRecorder`] passes a name and a value and nothing else, and
    /// inventing help text here would be documentation that lies. `# TYPE` it
    /// can state truthfully, because which method was called *is* the type.
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for (name, value) in self.counters() {
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {value}");
        }
        for (name, value) in self.gauges() {
            let _ = writeln!(out, "# TYPE {name} gauge");
            // Prometheus wants `Inf`/`-Inf`/`NaN` spelled exactly that way,
            // which is not what Rust's float formatting produces.
            let rendered = if value.is_nan() {
                "NaN".to_string()
            } else if value.is_infinite() {
                if value.is_sign_negative() { "-Inf" } else { "+Inf" }.to_string()
            } else {
                value.to_string()
            };
            let _ = writeln!(out, "{name} {rendered}");
        }
        out
    }

    /// Drops every accumulated value. For a test, or a caller that scrapes by
    /// delta rather than by absolute value.
    pub fn reset(&self) {
        self.counters.lock().expect("metrics mutex poisoned").clear();
        self.gauges.lock().expect("metrics mutex poisoned").clear();
    }
}

impl MetricsRecorder for InMemoryMetrics {
    fn counter(&self, name: &str, value: u64) {
        let mut counters = self.counters.lock().expect("metrics mutex poisoned");
        let total = counters.entry(name.to_string()).or_insert(0);
        // Saturating, not wrapping: a counter that wrapped would read as a
        // reset to a scraper computing rates, which is worse than one that
        // sticks at the ceiling.
        *total = total.saturating_add(value);
    }

    fn gauge(&self, name: &str, value: f64) {
        self.gauges
            .lock()
            .expect("metrics mutex poisoned")
            .insert(name.to_string(), value);
    }
}

#[cfg(test)]
#[path = "../tests/unit/metrics.rs"]
mod tests;

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Mutex;

    /// In-memory recorder for asserting on what a decorator actually
    /// reported, without a real metrics backend in the loop.
    #[derive(Debug, Default)]
    pub(crate) struct RecordingMetrics {
        pub counters: Mutex<Vec<(String, u64)>>,
        pub gauges: Mutex<Vec<(String, f64)>>,
    }

    impl MetricsRecorder for RecordingMetrics {
        fn counter(&self, name: &str, value: u64) {
            self.counters.lock().unwrap().push((name.to_string(), value));
        }
        fn gauge(&self, name: &str, value: f64) {
            self.gauges.lock().unwrap().push((name.to_string(), value));
        }
    }
}
