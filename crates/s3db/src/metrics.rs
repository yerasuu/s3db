//! The metrics surface [`crate::resilience::MeteredBackend`] records
//! against -- deliberately just two primitives (a counter and a gauge), no
//! histograms or a specific metrics-library dependency baked in. A caller
//! wires [`MetricsRecorder`] to whatever it already uses (Prometheus,
//! StatsD, an in-process registry); this crate never assumes which.

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
