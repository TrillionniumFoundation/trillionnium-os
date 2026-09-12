//! Exercise the actual checked-in metric authority through the public Rust API.
//! These are source fixtures, not installed samples or performance evidence.
use std::collections::BTreeMap;

use trillionnium_telemetry::catalog::{
    CatalogIngestor, METRIC_EVENT_SCHEMA, MetricCatalog, MetricDefinition, MetricEvent,
};

const CATALOG_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../docs/machine/metric-catalog.v1.json"
));

fn event(definition: &MetricDefinition) -> MetricEvent {
    let dimensions = definition
        .required_dimensions
        .iter()
        .map(|name| {
            let value = match name.as_str() {
                "module_id" => definition.source_module.clone(),
                "instance_epoch" => "1".into(),
                "ordering_key_digest" => "b".repeat(64),
                "operation_class" => "source_fixture".into(),
                "outcome" => "success".into(),
                "phase" => "steady_state".into(),
                "resource_scope" => "fixture_process".into(),
                "workload_id" => "WL-01".into(),
                unexpected => panic!("add an explicit fixture for dimension {unexpected}"),
            };
            (name.clone(), value)
        })
        .collect::<BTreeMap<_, _>>();
    MetricEvent {
        schema: METRIC_EVENT_SCHEMA.into(),
        metric: definition.name.clone(),
        unit: definition.unit.clone(),
        value: 0.0,
        source_module: definition.source_module.clone(),
        module_instance_id: "source-fixture-1".into(),
        operation_id_digest: "a".repeat(64),
        control_epoch: 1,
        sequence: 0,
        monotonic_ns: 1,
        dimensions,
        redacted: true,
    }
}

#[test]
fn checked_in_authority_roundtrips_and_admits_every_registered_metric() {
    let catalog = MetricCatalog::from_json(CATALOG_BYTES).unwrap();
    assert_eq!(catalog.metrics.len(), 43);
    let encoded = serde_json::to_vec(&catalog).unwrap();
    assert_eq!(MetricCatalog::from_json(&encoded).unwrap(), catalog);
    let ingestor = CatalogIngestor::new(catalog.clone(), 128, 4, 128).unwrap();
    for definition in &catalog.metrics {
        let sample = event(definition);
        assert!(ingestor.ingest(sample.clone()).unwrap().accepted);
        assert!(ingestor.ingest(sample).unwrap().idempotent_duplicate);
        let projection = ingestor.project(&definition.name).unwrap();
        assert_eq!(projection.sample_count, 1);
        assert_eq!(projection.unit, definition.unit);
        assert!(projection.coverage_complete);
        assert!(!projection.semantic_authority);
        assert!(!projection.automatic_redispatch);
    }
}

#[test]
fn every_real_metric_rejects_extra_or_missing_labels_without_projection_change() {
    let catalog = MetricCatalog::from_json(CATALOG_BYTES).unwrap();
    let ingestor = CatalogIngestor::new(catalog.clone(), 128, 4, 128).unwrap();
    for definition in &catalog.metrics {
        let initial = event(definition);
        ingestor.ingest(initial.clone()).unwrap();
        let before = ingestor.project(&definition.name).unwrap();
        let mut next = initial;
        next.sequence = 1;
        next.monotonic_ns = 2;
        for forbidden in ["customer_id", "credential", "unregistered"] {
            let mut invalid = next.clone();
            invalid.dimensions.insert(forbidden.into(), "fixture".into());
            assert!(ingestor.ingest(invalid).is_err());
            assert_eq!(ingestor.project(&definition.name).unwrap(), before);
        }
        for required in &definition.required_dimensions {
            let mut invalid = next.clone();
            invalid.dimensions.remove(required);
            assert!(ingestor.ingest(invalid).is_err());
            assert_eq!(ingestor.project(&definition.name).unwrap(), before);
        }
        assert!(ingestor.ingest(next).unwrap().accepted);
    }
}

#[test]
fn actual_authority_rejects_fractional_sampling_and_public_restricted_labels() {
    let catalog = MetricCatalog::from_json(CATALOG_BYTES).unwrap();
    let mut sampled = catalog.clone();
    sampled.metrics[0].sampling.rate_denominator = 2;
    assert!(sampled.validate().is_err());
    let mut leaked = catalog;
    let restricted = leaked
        .metrics
        .iter_mut()
        .find(|definition| definition.privacy_class == "PSEUDONYMOUS_RESTRICTED")
        .unwrap();
    restricted.privacy_class = "PUBLIC_MECHANICAL".into();
    assert!(leaked.validate().is_err());
}
