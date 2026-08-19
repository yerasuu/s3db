use super::*;

#[test]
fn counters_accumulate_and_gauges_keep_the_latest() {
    let metrics = InMemoryMetrics::default();

    metrics.counter("s3db_backend_get_total", 1);
    metrics.counter("s3db_backend_get_total", 4);
    metrics.gauge("s3db_shard_occupancy", 0.25);
    metrics.gauge("s3db_shard_occupancy", 0.75);

    assert_eq!(
        metrics.counter_value("s3db_backend_get_total"),
        Some(5),
        "a counter is monotonic, so increments sum"
    );
    assert_eq!(
        metrics.gauge_value("s3db_shard_occupancy"),
        Some(0.75),
        "a gauge is point-in-time, so the older reading is not evidence of anything"
    );
}

#[test]
fn a_metric_nobody_reported_is_absent_not_zero() {
    let metrics = InMemoryMetrics::default();
    assert_eq!(metrics.counter_value("never"), None);
    assert_eq!(metrics.gauge_value("never"), None);
    assert!(metrics.render_prometheus().is_empty());
}

#[test]
fn rendering_is_prometheus_text_sorted_by_name() {
    let metrics = InMemoryMetrics::default();
    metrics.counter("b_total", 2);
    metrics.counter("a_total", 1);
    metrics.gauge("z_ratio", 0.5);

    assert_eq!(
        metrics.render_prometheus(),
        "# TYPE a_total counter\na_total 1\n# TYPE b_total counter\nb_total 2\n# TYPE z_ratio gauge\nz_ratio 0.5\n",
        "sorted so a diff between two scrapes is readable"
    );
}

/// Prometheus spells these three exactly this way, which is not what Rust's
/// float formatting produces.
#[test]
fn special_floats_render_the_way_prometheus_expects() {
    let metrics = InMemoryMetrics::default();
    metrics.gauge("nan", f64::NAN);
    metrics.gauge("pos", f64::INFINITY);
    metrics.gauge("neg", f64::NEG_INFINITY);

    let body = metrics.render_prometheus();
    assert!(body.contains("nan NaN\n"), "{body}");
    assert!(body.contains("pos +Inf\n"), "{body}");
    assert!(body.contains("neg -Inf\n"), "{body}");
}

/// A wrapped counter reads as a reset to a scraper computing rates, which is
/// worse than one that sticks.
#[test]
fn a_counter_saturates_instead_of_wrapping() {
    let metrics = InMemoryMetrics::default();
    metrics.counter("c", u64::MAX);
    metrics.counter("c", 10);
    assert_eq!(metrics.counter_value("c"), Some(u64::MAX));
}

#[test]
fn reset_clears_everything() {
    let metrics = InMemoryMetrics::default();
    metrics.counter("c", 1);
    metrics.gauge("g", 1.0);

    metrics.reset();

    assert!(metrics.counters().is_empty());
    assert!(metrics.gauges().is_empty());
}

/// The point of the type: a metered backend's numbers become readable without
/// the caller wiring an exporter.
#[tokio::test]
async fn a_metered_backend_reports_into_it() {
    use crate::backend::Backend;
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let raw: Arc<dyn Backend> = Arc::new(crate::local::LocalBackend::new(&crate::config::LocalParams {
        bucket: dir.path().to_string_lossy().to_string(),
        engine: crate::config::LocalEngine::Files,
    }));
    let metrics = Arc::new(InMemoryMetrics::default());
    let metered = crate::resilience::MeteredBackend::new(raw, metrics.clone());

    metered.put_cas("k", b"v".to_vec(), None).await.unwrap();
    metered.get("k").await.unwrap();

    let body = metrics.render_prometheus();
    assert!(!body.is_empty(), "a metered backend must have reported something");
    assert!(
        metrics
            .counters()
            .iter()
            .any(|(name, value)| name.contains("get") && *value > 0),
        "{body}"
    );
}
