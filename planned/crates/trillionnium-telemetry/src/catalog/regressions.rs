//! Hostile regressions for PR77's catalog and atomic-admission review findings.
use super::tests::{catalog, event};
use super::*;

fn snapshot(ingestor: &CatalogIngestor) -> String {
    format!("{:?}", ingestor.state.lock().unwrap())
}

fn rejects_unchanged(ingestor: &CatalogIngestor, value: MetricEvent) {
    let before = snapshot(ingestor);
    assert!(ingestor.ingest(value.clone()).is_err());
    assert_eq!(before, snapshot(ingestor));
    assert!(ingestor.ingest(value).is_err());
    assert_eq!(before, snapshot(ingestor));
}

#[test]
fn unknown_and_registered_but_not_allowed_dimensions_are_rejected() {
    let mut definition = catalog(8);
    definition.dimension_catalog.push(DimensionDefinition {
        name: "phase".into(),
        cardinality_ceiling: 2,
        privacy_class: "PUBLIC_MECHANICAL".into(),
    });
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    for name in ["customer_id", "unregistered_dimension", "phase"] {
        let mut value = event(0, 10, "accept");
        value.dimensions.insert(name.into(), "mechanical".into());
        rejects_unchanged(&ingestor, value);
    }
}

#[test]
fn restricted_dimension_cannot_enter_public_metric() {
    let mut definition = catalog(8);
    definition.dimension_catalog[1].privacy_class = "PSEUDONYMOUS_RESTRICTED".into();
    assert!(CatalogIngestor::new(definition, 8, 8, 8).is_err());
}

#[test]
fn restricted_dimension_requires_redaction() {
    let mut definition = catalog(8);
    definition.dimension_catalog[1].privacy_class = "PSEUDONYMOUS_RESTRICTED".into();
    definition.metrics[0].privacy_class = "PSEUDONYMOUS_RESTRICTED".into();
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    let mut value = event(0, 10, "accept");
    value.redacted = false;
    rejects_unchanged(&ingestor, value);
}

#[test]
fn operation_dimension_rejects_sixty_fifth_distinct_value() {
    let ingestor = CatalogIngestor::new(catalog(128), 128, 8, 8).unwrap();
    for index in 0..64 {
        ingestor.ingest(event(index, index + 1, &format!("op-{index}"))).unwrap();
    }
    rejects_unchanged(&ingestor, event(64, 65, "op-64"));
    assert_eq!(ingestor.state.lock().unwrap().windows.len(), 64);
}

#[test]
fn phase_dimension_rejects_third_distinct_value() {
    let mut definition = catalog(8);
    definition.dimension_catalog.push(DimensionDefinition {
        name: "phase".into(),
        cardinality_ceiling: 2,
        privacy_class: "PUBLIC_MECHANICAL".into(),
    });
    definition.metrics[0].required_dimensions.push("phase".into());
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    for (index, phase) in ["cold", "steady", "third"].into_iter().enumerate() {
        let mut value = event(index as u64, index as u64 + 1, "accept");
        value.dimensions.insert("phase".into(), phase.into());
        if index < 2 {
            ingestor.ingest(value).unwrap();
        } else {
            rejects_unchanged(&ingestor, value);
        }
    }
}

#[test]
fn dimension_cardinality_is_shared_across_metrics_for_ingestor_lifetime() {
    let mut definition = catalog(8);
    definition.dimension_catalog[1].cardinality_ceiling = 1;
    let mut second = definition.metrics[0].clone();
    second.name = "broker.forward.duration_ms".into();
    definition.metrics.push(second);
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    let mut value = event(0, 11, "forward");
    value.metric = "broker.forward.duration_ms".into();
    rejects_unchanged(&ingestor, value);
}

#[test]
fn per_metric_sample_limit_overrides_larger_global_limit() {
    let mut definition = catalog(8);
    definition.metrics[0].retention.max_samples = 2;
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    for index in 0..3 {
        ingestor.ingest(event(index, index + 1, "accept")).unwrap();
    }
    let projection = ingestor.project("broker.accept.duration_ms").unwrap();
    assert_eq!(projection.sample_count, 2);
    assert_eq!(projection.dropped_samples, 1);
    assert!(!projection.coverage_complete);
}

#[test]
fn smaller_global_sample_limit_still_applies() {
    let ingestor = CatalogIngestor::new(catalog(8), 8, 1, 8).unwrap();
    ingestor.ingest(event(0, 1, "accept")).unwrap();
    ingestor.ingest(event(1, 2, "accept")).unwrap();
    assert_eq!(ingestor.project("broker.accept.duration_ms").unwrap().sample_count, 1);
}

#[test]
fn retention_cutoff_is_inclusive_and_expires_one_nanosecond_later() {
    let mut definition = catalog(8);
    definition.metrics[0].retention.window_seconds = 2;
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    ingestor.ingest(event(0, 1, "accept")).unwrap();
    ingestor.ingest(event(1, 2_000_000_001, "accept")).unwrap();
    assert_eq!(ingestor.project("broker.accept.duration_ms").unwrap().sample_count, 2);
    ingestor.ingest(event(2, 2_000_000_002, "accept")).unwrap();
    let projection = ingestor.project("broker.accept.duration_ms").unwrap();
    assert_eq!(projection.sample_count, 2);
    assert_eq!(projection.dropped_samples, 1);
    assert_eq!(projection.gaps[0].kind, CoverageGapKind::TimeWindowEviction);
}

#[test]
fn time_eviction_reaches_other_label_series_in_the_same_clock_domain() {
    let mut definition = catalog(8);
    definition.metrics[0].retention.window_seconds = 2;
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    ingestor.ingest(event(0, 1, "accept")).unwrap();
    ingestor.ingest(event(1, 3_000_000_002, "forward")).unwrap();
    let projection = ingestor.project("broker.accept.duration_ms").unwrap();
    assert_eq!(projection.sample_count, 1);
    assert_eq!(projection.dropped_samples, 1);
    assert!(projection.gaps.iter().any(|gap| gap.kind == CoverageGapKind::ClockJump));
}

#[test]
fn idle_watermark_expires_samples_without_reinserting_duplicate() {
    let mut definition = catalog(8);
    definition.metrics[0].retention.window_seconds = 1;
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    let first = event(0, 1, "accept");
    ingestor.ingest(first.clone()).unwrap();
    ingestor.advance_watermark("broker.accept.duration_ms", "broker-1", 1, 1_000_000_002).unwrap();
    assert!(ingestor.project("broker.accept.duration_ms").is_err());
    let before = snapshot(&ingestor);
    assert!(ingestor.ingest(first).unwrap().idempotent_duplicate);
    assert_eq!(before, snapshot(&ingestor));
}

#[test]
fn watermark_regression_unknown_domain_and_capacity_failure_do_not_mutate() {
    let ingestor = CatalogIngestor::new(catalog(8), 8, 1, 1).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    ingestor.ingest(event(1, 11, "accept")).unwrap();
    let before = snapshot(&ingestor);
    assert!(ingestor.advance_watermark("broker.accept.duration_ms", "broker-1", 1, 9).is_err());
    assert!(ingestor.advance_watermark("broker.accept.duration_ms", "other", 1, 20).is_err());
    assert!(ingestor.advance_watermark("broker.accept.duration_ms", "broker-1", 1, 70_000_000_000).is_err());
    assert_eq!(before, snapshot(&ingestor));
}

#[test]
fn one_clock_domain_cannot_expire_another_instances_samples() {
    let ingestor = CatalogIngestor::new(catalog(8), 8, 8, 8).unwrap();
    ingestor.ingest(event(0, 1, "accept")).unwrap();
    let mut other = event(0, 2, "accept");
    other.module_instance_id = "broker-2".into();
    ingestor.ingest(other).unwrap();
    ingestor.advance_watermark("broker.accept.duration_ms", "broker-1", 1, 70_000_000_000).unwrap();
    assert_eq!(ingestor.project("broker.accept.duration_ms").unwrap().sample_count, 1);
}

#[test]
fn late_observation_and_clock_regression_are_explicit_atomic_errors() {
    let ingestor = CatalogIngestor::new(catalog(8), 8, 8, 8).unwrap();
    ingestor.ingest(event(1, 10, "accept")).unwrap();
    let before = snapshot(&ingestor);
    assert!(ingestor.ingest(event(0, 11, "accept")).unwrap_err().to_string().contains("LATE_OBSERVATION"));
    assert!(ingestor.ingest(event(2, 9, "accept")).unwrap_err().to_string().contains("CLOCK_REGRESSION"));
    assert_eq!(before, snapshot(&ingestor));
    ingestor.advance_watermark("broker.accept.duration_ms", "broker-1", 1, 20).unwrap();
    rejects_unchanged(&ingestor, event(2, 19, "accept"));
}

#[test]
fn full_gap_queue_cannot_partially_commit_eviction_on_any_retry() {
    let ingestor = CatalogIngestor::new(catalog(8), 8, 1, 1).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    ingestor.ingest(event(1, 11, "accept")).unwrap();
    rejects_unchanged(&ingestor, event(2, 12, "accept"));
}

#[test]
fn pending_sequence_gap_is_not_committed_when_new_series_is_rejected() {
    let ingestor = CatalogIngestor::new(catalog(1), 8, 8, 8).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    rejects_unchanged(&ingestor, event(2, 12, "forward"));
    assert!(ingestor.coverage_gaps().unwrap().is_empty());
}

#[test]
fn drop_counter_overflow_is_rejected_before_eviction() {
    let ingestor = CatalogIngestor::new(catalog(8), 8, 1, 8).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    ingestor.state.lock().unwrap().dropped_by_metric.insert("broker.accept.duration_ms".into(), u64::MAX);
    rejects_unchanged(&ingestor, event(1, 11, "accept"));
}

#[test]
fn stream_identity_churn_cannot_grow_unbounded_metadata_in_one_series() {
    let ingestor = CatalogIngestor::new(catalog(8), 2, 8, 8).unwrap();
    for name in ["broker-1", "broker-2"] {
        let mut value = event(0, 1, "accept");
        value.module_instance_id = name.into();
        ingestor.ingest(value).unwrap();
    }
    let mut third = event(0, 1, "accept");
    third.module_instance_id = "broker-3".into();
    rejects_unchanged(&ingestor, third);
    assert_eq!(ingestor.state.lock().unwrap().last_events.len(), 2);
}

#[test]
fn count_metrics_admit_only_the_documented_exact_range() {
    let mut definition = catalog(8);
    definition.metrics[0].value_type = "U64_COUNT".into();
    definition.metrics[0].unit = "count".into();
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    for count in [-1.0, 0.5, 9_007_199_254_740_992.0, 18_446_744_073_709_551_616.0, f64::INFINITY, f64::NAN] {
        let mut value = event(0, 1, "accept");
        value.unit = "count".into();
        value.value = count;
        rejects_unchanged(&ingestor, value);
    }
    let mut maximum = event(0, 1, "accept");
    maximum.unit = "count".into();
    maximum.value = MAX_EXACT_COUNT;
    assert!(ingestor.ingest(maximum).unwrap().accepted);
}

#[test]
fn every_observation_sampling_means_exactly_one_over_one() {
    for (numerator, denominator) in [(1, 2), (2, 2), (0, 1), (1, 0)] {
        let mut definition = catalog(8);
        definition.metrics[0].sampling.rate_numerator = numerator;
        definition.metrics[0].sampling.rate_denominator = denominator;
        assert!(definition.validate().is_err());
    }
    assert!(catalog(8).validate().is_ok());
}

#[test]
fn observed_gaps_and_cardinality_are_not_reset_by_time_eviction() {
    let mut definition = catalog(8);
    definition.metrics[0].retention.window_seconds = 1;
    definition.dimension_catalog[1].cardinality_ceiling = 1;
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    ingestor.ingest(event(0, 1, "accept")).unwrap();
    ingestor.advance_watermark("broker.accept.duration_ms", "broker-1", 1, 2_000_000_000).unwrap();
    rejects_unchanged(&ingestor, event(1, 2_000_000_001, "forward"));
    ingestor.ingest(event(1, 2_000_000_001, "accept")).unwrap();
    assert!(!ingestor.project("broker.accept.duration_ms").unwrap().coverage_complete);
}

#[test]
fn concurrent_dimension_admission_has_one_winner_at_capacity() {
    let mut definition = catalog(8);
    definition.dimension_catalog[1].cardinality_ceiling = 1;
    let ingestor = CatalogIngestor::new(definition, 8, 8, 8).unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let workers = (0..2).map(|index| {
        let ingestor = ingestor.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            let mut value = event(0, 1, &format!("op-{index}"));
            value.module_instance_id = format!("broker-{index}");
            barrier.wait();
            ingestor.ingest(value).is_ok()
        })
    }).collect::<Vec<_>>();
    let admitted = workers.into_iter().map(|worker| usize::from(worker.join().unwrap())).sum::<usize>();
    assert_eq!(admitted, 1);
    let state = ingestor.state.lock().unwrap();
    assert_eq!(state.windows.len(), 1);
    assert_eq!(state.last_events.len(), 1);
    assert!(state.gaps.is_empty());
}
