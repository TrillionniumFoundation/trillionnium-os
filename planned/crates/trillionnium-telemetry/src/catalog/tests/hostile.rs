use super::*;

fn snapshot(ingestor: &CatalogIngestor) -> String {
    // Includes all maps, windows, last events/rejections, counters and gaps.
    // Ordered maps make this byte representation deterministic.
    format!("{:?}", ingestor.state.lock().unwrap())
}

fn rejected_unchanged(ingestor: &CatalogIngestor, sample: MetricEvent) {
    let before = snapshot(ingestor);
    assert!(ingestor.ingest(sample).is_err());
    assert_eq!(before.as_bytes(), snapshot(ingestor).as_bytes());
}

#[test]
fn unknown_and_registered_but_undeclared_dimensions_are_rejected() {
    let mut definitions = catalog(8);
    definitions.dimension_catalog.push(DimensionDefinition {
        name: "phase".into(),
        cardinality_ceiling: 2,
        privacy_class: "PUBLIC_MECHANICAL".into(),
    });
    let ingestor = CatalogIngestor::new(definitions, 16, 16, 16).unwrap();
    for key in ["unregistered_dimension", "phase"] {
        let mut sample = event(0, 10, "accept");
        sample.dimensions.insert(key.into(), "steady".into());
        rejected_unchanged(&ingestor, sample);
    }
}

#[test]
fn dimension_value_limit_is_enforced_across_instances_and_metrics() {
    let mut definitions = catalog(8);
    definitions.dimension_catalog[1].cardinality_ceiling = 1;
    let mut second_metric = definitions.metrics[0].clone();
    second_metric.name = "broker.forward.duration_ms".into();
    definitions.metrics.push(second_metric);
    let ingestor = CatalogIngestor::new(definitions, 16, 16, 16).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    let mut sample = event(0, 10, "forward");
    sample.module_instance_id = "broker-2".into();
    sample.metric = "broker.forward.duration_ms".into();
    rejected_unchanged(&ingestor, sample);
    let mut allowed = event(0, 10, "accept");
    allowed.module_instance_id = "broker-2".into();
    allowed.metric = "broker.forward.duration_ms".into();
    assert!(ingestor.ingest(allowed).unwrap().accepted);
}

#[test]
fn dimension_privacy_cannot_be_downgraded_or_unredacted() {
    let mut definitions = catalog(8);
    definitions.dimension_catalog[1].privacy_class = "PSEUDONYMOUS_RESTRICTED".into();
    assert!(definitions.validate().is_err());
    definitions.metrics[0].privacy_class = "PSEUDONYMOUS_RESTRICTED".into();
    let ingestor = CatalogIngestor::new(definitions, 16, 16, 16).unwrap();
    let mut sample = event(0, 10, "accept");
    sample.redacted = false;
    rejected_unchanged(&ingestor, sample);
    assert!(ingestor.ingest(event(0, 10, "accept")).unwrap().accepted);
}

#[test]
fn catalog_and_caller_sample_limits_use_the_stricter_value() {
    for (catalog_limit, caller_limit) in [(1, 8), (8, 1), (2, 8)] {
        let mut definitions = catalog(8);
        definitions.metrics[0].retention.max_samples = catalog_limit;
        let ingestor = CatalogIngestor::new(definitions, 16, caller_limit, 16).unwrap();
        for n in 0..4 {
            ingestor.ingest(event(n, 10 + n, "accept")).unwrap();
        }
        let projection = ingestor.project("broker.accept.duration_ms").unwrap();
        let expected = u64::from(catalog_limit).min(caller_limit as u64);
        assert_eq!(projection.sample_count, expected);
        assert_eq!(projection.dropped_samples, 4 - expected);
    }
}

#[test]
fn time_window_boundary_and_forward_jump_are_explicit() {
    let mut definitions = catalog(8);
    definitions.metrics[0].retention.window_seconds = 1;
    let ingestor = CatalogIngestor::new(definitions, 16, 16, 16).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    ingestor.ingest(event(1, 1_000_000_009, "accept")).unwrap();
    assert_eq!(
        ingestor
            .project("broker.accept.duration_ms")
            .unwrap()
            .sample_count,
        2
    );
    ingestor.ingest(event(2, 1_000_000_010, "accept")).unwrap();
    assert_eq!(
        ingestor
            .project("broker.accept.duration_ms")
            .unwrap()
            .sample_count,
        2
    );
    ingestor.ingest(event(3, 2_000_000_011, "accept")).unwrap();
    let projection = ingestor.project("broker.accept.duration_ms").unwrap();
    assert_eq!(projection.sample_count, 1);
    assert_eq!(projection.dropped_samples, 3);
    assert!(
        projection
            .gaps
            .iter()
            .any(|gap| gap.kind == CoverageGapKind::ClockJump)
    );
    assert!(
        projection
            .gaps
            .iter()
            .any(|gap| gap.kind == CoverageGapKind::TimeWindowEviction)
    );
    assert!(!projection.coverage_complete);
}

#[test]
fn late_clock_observations_have_nonaccepting_idempotent_receipts() {
    let ingestor = CatalogIngestor::new(catalog(8), 16, 16, 16).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    ingestor.ingest(event(1, 20, "accept")).unwrap();
    for (sample, kind) in [
        (event(0, 10, "accept"), CoverageGapKind::LateObservation),
        (event(2, 19, "accept"), CoverageGapKind::ClockRegression),
    ] {
        let result = ingestor.ingest(sample.clone()).unwrap();
        assert!(!result.accepted && !result.idempotent_duplicate && !result.coverage_complete);
        assert_eq!(ingestor.coverage_gaps().unwrap().last().unwrap().kind, kind);
        let before = snapshot(&ingestor);
        let repeated = ingestor.ingest(sample).unwrap();
        assert!(!repeated.accepted && repeated.idempotent_duplicate);
        assert_eq!(before, snapshot(&ingestor));
    }
    assert_eq!(
        ingestor
            .project("broker.accept.duration_ms")
            .unwrap()
            .sample_count,
        2
    );
}

#[test]
fn full_gap_queue_rejection_rolls_back_every_state_family_and_retry() {
    let ingestor = CatalogIngestor::new(catalog(8), 16, 1, 1).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    ingestor.ingest(event(1, 11, "accept")).unwrap();
    for _ in 0..3 {
        rejected_unchanged(&ingestor, event(2, 12, "accept"));
    }
    let mut new_series = event(3, 13, "forward");
    new_series.module_instance_id = "broker-2".into();
    rejected_unchanged(&ingestor, new_series);
    rejected_unchanged(&ingestor, event(2, 9, "accept"));
}

#[test]
fn multiple_required_gaps_are_reserved_atomically() {
    let ingestor = CatalogIngestor::new(catalog(8), 16, 1, 1).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    // Needs both MissingSequence and WindowEviction, but only one slot exists.
    rejected_unchanged(&ingestor, event(2, 12, "accept"));
    assert!(ingestor.ingest(event(1, 11, "accept")).unwrap().accepted);
}

#[test]
fn drop_counter_overflow_has_no_partial_commit() {
    let ingestor = CatalogIngestor::new(catalog(8), 16, 1, 16).unwrap();
    ingestor.ingest(event(0, 10, "accept")).unwrap();
    ingestor
        .state
        .lock()
        .unwrap()
        .dropped_by_metric
        .insert("broker.accept.duration_ms".into(), u64::MAX);
    rejected_unchanged(&ingestor, event(1, 11, "accept"));
}

#[test]
fn producer_clock_domains_and_identity_churn_are_bounded() {
    let ingestor = CatalogIngestor::new(catalog(8), 2, 8, 16).unwrap();
    ingestor.ingest(event(0, 100, "accept")).unwrap();
    let mut other = event(0, 1, "accept");
    other.module_instance_id = "broker-2".into();
    assert!(ingestor.ingest(other.clone()).unwrap().accepted);
    other.module_instance_id = "broker-3".into();
    rejected_unchanged(&ingestor, other);
    let state = ingestor.state.lock().unwrap();
    assert_eq!(state.windows.len(), 2);
    assert_eq!(state.last_events.len(), 2);
    assert_eq!(state.latest_epoch.len(), 2);
}

#[test]
fn count_wire_rejects_rounded_u64_and_inexact_integer_boundaries() {
    let mut definitions = catalog(8);
    definitions.metrics[0].value_type = "U64_COUNT".into();
    let ingestor = CatalogIngestor::new(definitions, 16, 16, 16).unwrap();
    for value in [
        1.5,
        9_007_199_254_740_992.0,
        u64::MAX as f64,
        f64::NAN,
        f64::INFINITY,
    ] {
        let mut sample = event(0, 10, "accept");
        sample.value = value;
        rejected_unchanged(&ingestor, sample);
    }
    let mut sample = event(0, 10, "accept");
    sample.value = MAX_EXACT_COUNT_V1;
    assert!(ingestor.ingest(sample).unwrap().accepted);
}

#[test]
fn concurrent_duplicate_admission_has_one_commit() {
    let ingestor = CatalogIngestor::new(catalog(8), 16, 16, 16).unwrap();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let copy = ingestor.clone();
            std::thread::spawn(move || copy.ingest(event(0, 10, "accept")).unwrap())
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|item| item.accepted).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|item| item.idempotent_duplicate)
            .count(),
        7
    );
    assert_eq!(
        ingestor
            .project("broker.accept.duration_ms")
            .unwrap()
            .sample_count,
        1
    );
}

#[test]
fn every_real_metric_enforces_catalog_sample_and_event_time_retention() {
    let source = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/machine/metric-catalog.v1.json"
    ));
    let original = MetricCatalog::from_json(source).unwrap();
    for definition in &original.metrics {
        let mut single = original.clone();
        single.metrics = vec![definition.clone()];
        let ingestor = CatalogIngestor::new(single, 2, MAX_SAMPLES_PER_SERIES, 8).unwrap();
        let mut sample = event(0, 10, "accept");
        sample.metric = definition.name.clone();
        sample.unit = definition.unit.clone();
        sample.source_module = definition.source_module.clone();
        sample.value = 1.0;
        sample.dimensions = definition
            .required_dimensions
            .iter()
            .map(|name| {
                let value = match name.as_str() {
                    "module_id" => definition.source_module.clone(),
                    "instance_epoch" => "1".into(),
                    "ordering_key_digest" => "b".repeat(64),
                    _ => "test-only".into(),
                };
                (name.clone(), value)
            })
            .collect();
        for n in 0..=u64::from(definition.retention.max_samples) {
            sample.sequence = n;
            sample.monotonic_ns = 10 + n;
            assert!(ingestor.ingest(sample.clone()).unwrap().accepted);
        }
        let projection = ingestor.project(&definition.name).unwrap();
        assert_eq!(
            projection.sample_count,
            u64::from(definition.retention.max_samples)
        );
        assert_eq!(projection.dropped_samples, 1);
        sample.sequence += 1;
        sample.monotonic_ns += definition.retention.window_seconds * 1_000_000_000 + 1;
        assert!(ingestor.ingest(sample).unwrap().accepted);
        let projection = ingestor.project(&definition.name).unwrap();
        assert_eq!(projection.sample_count, 1);
        assert_eq!(
            projection.dropped_samples,
            u64::from(definition.retention.max_samples) + 1
        );
    }
}
