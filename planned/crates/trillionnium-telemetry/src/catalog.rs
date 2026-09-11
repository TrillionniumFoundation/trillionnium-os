//! Catalog-bound, privacy-reviewed telemetry ingestion for OBSERVE/SHADOW.
//!
//! This module deliberately exposes observations only. It cannot carry command
//! text, prompts, credentials, retry instructions, semantic intent or effect
//! authority. A complete projection can be labelled durable only after an
//! explicit file-and-directory fsync receipt is supplied by the owning store.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{Result, TelemetryError};

pub const METRIC_CATALOG_SCHEMA: &str = "org.trillionnium.metric-catalog.v1";
pub const METRIC_EVENT_SCHEMA: &str = "trillionnium.owner-open.metric-event.v1";
pub const METRIC_PROJECTION_SCHEMA: &str = "trillionnium.owner-open.metric-projection.v1";
pub const COVERAGE_GAP_SCHEMA: &str = "trillionnium.owner-open.metric-gap.v1";
pub const DURABILITY_RECEIPT_SCHEMA: &str = "trillionnium.owner-open.metric-durability-receipt.v1";
pub const DURABLE_PROJECTION_SCHEMA: &str = "trillionnium.owner-open.durable-metric-projection.v1";

pub const MAX_CATALOG_METRICS: usize = 4_096;
pub const MAX_CATALOG_DIMENSIONS: usize = 256;
pub const MAX_CATALOG_TEXT_BYTES: usize = 256;
pub const MAX_EVENT_DIMENSIONS: usize = 32;
pub const MAX_DIMENSION_VALUE_BYTES: usize = 256;
pub const MAX_INGEST_SERIES: usize = 1_048_576;
pub const MAX_SAMPLES_PER_SERIES: usize = 1_048_576;
pub const MAX_COVERAGE_GAPS: usize = 1_048_576;

const SENSITIVE_TOKENS: [&str; 10] = [
    "command",
    "prompt",
    "credential",
    "secret",
    "token",
    "user_input",
    "tool_argument",
    "intent",
    "model_message",
    "retry_instruction",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DimensionDefinition {
    pub name: String,
    pub cardinality_ceiling: u32,
    pub privacy_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub window_seconds: u64,
    pub max_samples: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SamplingPolicy {
    pub mode: String,
    pub rate_numerator: u32,
    pub rate_denominator: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricDefinition {
    pub name: String,
    pub unit: String,
    pub value_type: String,
    pub source_module: String,
    pub collection_point: String,
    pub aggregation: String,
    pub retention: RetentionPolicy,
    pub cardinality_ceiling: u32,
    pub privacy_class: String,
    pub required_dimensions: Vec<String>,
    pub forbidden_dimensions: Vec<String>,
    pub sampling: SamplingPolicy,
    pub missing_data: String,
    pub clock_source: String,
    pub evidence_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricCatalog {
    pub schema: String,
    pub program_revision: String,
    pub catalog_version: String,
    pub status: String,
    pub activation_ceiling: String,
    pub semantic_authority: bool,
    pub automatic_redispatch: bool,
    pub dimension_catalog: Vec<DimensionDefinition>,
    pub forbidden_dimension_names: Vec<String>,
    pub metrics: Vec<MetricDefinition>,
}

impl MetricCatalog {
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let catalog: Self = serde_json::from_slice(bytes)
            .map_err(|error| TelemetryError::Invalid(format!("metric catalog JSON: {error}")))?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != METRIC_CATALOG_SCHEMA
            || self.program_revision.trim().is_empty()
            || self.catalog_version.trim().is_empty()
            || self.status != "SOURCE_CONTRACT_OBSERVE_SHADOW_ONLY"
            || self.activation_ceiling != "SHADOW"
        {
            return invalid("metric catalog identity or activation ceiling differs");
        }
        if self.semantic_authority || self.automatic_redispatch {
            return invalid("metric catalog widened semantic/effect authority");
        }
        if self.dimension_catalog.is_empty()
            || self.dimension_catalog.len() > MAX_CATALOG_DIMENSIONS
            || self.metrics.is_empty()
            || self.metrics.len() > MAX_CATALOG_METRICS
        {
            return invalid("metric catalog dimensions or metrics exceed bounds");
        }
        let mut dimensions = BTreeMap::new();
        for dimension in &self.dimension_catalog {
            require_identifier(&dimension.name, "dimension name")?;
            if dimension.cardinality_ceiling == 0
                || dimension.cardinality_ceiling as usize > MAX_INGEST_SERIES
                || !matches!(
                    dimension.privacy_class.as_str(),
                    "PUBLIC_MECHANICAL" | "PSEUDONYMOUS_RESTRICTED"
                )
            {
                return invalid("metric dimension bound or privacy class is invalid");
            }
            if dimensions
                .insert(dimension.name.as_str(), dimension)
                .is_some()
            {
                return invalid("duplicate metric dimension");
            }
        }
        if self.forbidden_dimension_names.is_empty() {
            return invalid("metric catalog forbidden dimension set is empty");
        }
        let forbidden = self
            .forbidden_dimension_names
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if forbidden.len() != self.forbidden_dimension_names.len()
            || SENSITIVE_TOKENS
                .iter()
                .any(|token| !forbidden.contains(token))
        {
            return invalid("metric catalog forbidden dimensions are incomplete");
        }

        let mut metric_names = BTreeSet::new();
        for definition in &self.metrics {
            definition.validate(&dimensions, &forbidden)?;
            if !metric_names.insert(definition.name.as_str()) {
                return invalid("duplicate metric name");
            }
        }
        if self
            .metrics
            .windows(2)
            .any(|pair| pair[0].name >= pair[1].name)
        {
            return invalid("metric definitions must be strictly name-sorted");
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| TelemetryError::Invalid(format!("metric catalog encode: {error}")))?;
        Ok(hex_digest(&bytes))
    }

    pub fn definition(&self, name: &str) -> Option<&MetricDefinition> {
        self.metrics
            .binary_search_by_key(&name, |definition| definition.name.as_str())
            .ok()
            .map(|index| &self.metrics[index])
    }
}

impl MetricDefinition {
    fn validate(
        &self,
        dimensions: &BTreeMap<&str, &DimensionDefinition>,
        global_forbidden: &BTreeSet<&str>,
    ) -> Result<()> {
        require_metric_name(&self.name)?;
        require_text(&self.source_module, "metric source module")?;
        require_text(&self.collection_point, "metric collection point")?;
        if SENSITIVE_TOKENS
            .iter()
            .any(|token| self.name.contains(token) || self.collection_point.contains(token))
        {
            return invalid("metric definition contains semantic or sensitive vocabulary");
        }
        if !matches!(
            self.unit.as_str(),
            "milliseconds" | "seconds" | "bytes" | "count" | "ratio" | "microseconds"
        ) || !matches!(
            self.value_type.as_str(),
            "F64_NONNEGATIVE" | "U64_COUNT" | "RATIO_0_1"
        ) || !matches!(
            self.aggregation.as_str(),
            "HISTOGRAM" | "SUM" | "MAX" | "LAST" | "MEAN"
        ) || !matches!(
            self.privacy_class.as_str(),
            "PUBLIC_MECHANICAL" | "PSEUDONYMOUS_RESTRICTED"
        ) || !matches!(
            self.missing_data.as_str(),
            "EXPLICIT_UNAVAILABLE" | "WINDOW_INCOMPLETE" | "COUNTER_NOT_OBSERVED"
        ) || !matches!(
            self.clock_source.as_str(),
            "MONOTONIC" | "PROCESS_COUNTER" | "CGROUP_COUNTER"
        ) || !matches!(self.evidence_level.as_str(), "L1_SOURCE" | "L2_TARGET")
        {
            return invalid("metric definition vocabulary is invalid");
        }
        if self.retention.window_seconds == 0
            || self.retention.window_seconds > 86_400
            || self.retention.max_samples == 0
            || self.retention.max_samples as usize > MAX_SAMPLES_PER_SERIES
            || self.cardinality_ceiling == 0
            || self.cardinality_ceiling as usize > MAX_INGEST_SERIES
        {
            return invalid("metric retention or cardinality bound is invalid");
        }
        if self.sampling.mode != "EVERY_OBSERVATION"
            || self.sampling.rate_numerator == 0
            || self.sampling.rate_denominator == 0
            || self.sampling.rate_numerator > self.sampling.rate_denominator
        {
            return invalid("metric sampling policy is invalid");
        }
        if self.required_dimensions.is_empty()
            || self.required_dimensions.len() > MAX_EVENT_DIMENSIONS
            || self.forbidden_dimensions.is_empty()
        {
            return invalid("metric dimension policy is empty or unbounded");
        }
        let required = self
            .required_dimensions
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let forbidden = self
            .forbidden_dimensions
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if required.len() != self.required_dimensions.len()
            || forbidden.len() != self.forbidden_dimensions.len()
            || required.iter().any(|name| !dimensions.contains_key(name))
            || !required.is_disjoint(&forbidden)
            || global_forbidden
                .iter()
                .any(|name| !forbidden.contains(name))
        {
            return invalid("metric required/forbidden dimension policy differs");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricEvent {
    pub schema: String,
    pub metric: String,
    pub unit: String,
    pub value: f64,
    pub source_module: String,
    pub module_instance_id: String,
    pub operation_id_digest: String,
    pub control_epoch: u64,
    pub sequence: u64,
    pub monotonic_ns: u64,
    pub dimensions: BTreeMap<String, String>,
    pub redacted: bool,
}

impl MetricEvent {
    fn validate(&self, definition: &MetricDefinition) -> Result<()> {
        if self.schema != METRIC_EVENT_SCHEMA
            || self.metric != definition.name
            || self.unit != definition.unit
            || self.source_module != definition.source_module
            || self.control_epoch == 0
            || self.monotonic_ns == 0
        {
            return invalid("metric event identity, unit, source, epoch or clock differs");
        }
        require_identifier(&self.module_instance_id, "module instance id")?;
        require_lower_hex(&self.operation_id_digest, 64, "operation digest")?;
        if !self.value.is_finite() || self.value < 0.0 {
            return invalid("metric event value must be finite and nonnegative");
        }
        match definition.value_type.as_str() {
            "U64_COUNT" if self.value.fract() != 0.0 || self.value > u64::MAX as f64 => {
                return invalid("count metric is not an exact u64-compatible value");
            }
            "RATIO_0_1" if self.value > 1.0 => {
                return invalid("ratio metric is outside [0,1]");
            }
            _ => {}
        }
        if self.dimensions.len() > MAX_EVENT_DIMENSIONS {
            return invalid("metric event has too many dimensions");
        }
        let keys = self
            .dimensions
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let required = definition
            .required_dimensions
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let forbidden = definition
            .forbidden_dimensions
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if !required.is_subset(&keys) || !keys.is_disjoint(&forbidden) {
            return invalid("metric event required/forbidden dimensions differ");
        }
        for (name, value) in &self.dimensions {
            require_identifier(name, "metric dimension")?;
            require_text(value, "metric dimension value")?;
            if value.len() > MAX_DIMENSION_VALUE_BYTES
                || value.contains('\n')
                || value.contains('\r')
            {
                return invalid("metric dimension value exceeds the mechanical bound");
            }
        }
        if self.dimensions.get("module_id") != Some(&self.source_module) {
            return invalid("module_id dimension does not bind source_module");
        }
        if let Some(epoch) = self.dimensions.get("instance_epoch")
            && epoch != &self.control_epoch.to_string()
        {
            return invalid("instance_epoch dimension does not bind control_epoch");
        }
        if let Some(digest) = self.dimensions.get("ordering_key_digest") {
            require_lower_hex(digest, 64, "ordering key digest")?;
        }
        if definition.privacy_class == "PSEUDONYMOUS_RESTRICTED" && !self.redacted {
            return invalid("restricted metric event is not redacted");
        }
        Ok(())
    }

    fn digest(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)
            .map_err(|error| TelemetryError::Invalid(format!("metric event encode: {error}")))?;
        Ok(hex_digest(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StreamKey {
    metric: String,
    module_instance_id: String,
    control_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SeriesKey {
    metric: String,
    dimensions_digest: String,
}

#[derive(Debug, Clone)]
struct LastEvent {
    sequence: u64,
    monotonic_ns: u64,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoverageGapKind {
    MissingSequence,
    ClockRegression,
    WindowEviction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageGap {
    pub schema: String,
    pub metric: String,
    pub module_instance_id: String,
    pub control_epoch: u64,
    pub kind: CoverageGapKind,
    pub expected_sequence: u64,
    pub observed_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestReceipt {
    pub accepted: bool,
    pub idempotent_duplicate: bool,
    pub event_digest: String,
    pub series_digest: String,
    pub coverage_complete: bool,
    pub semantic_authority: bool,
    pub automatic_redispatch: bool,
}

#[derive(Debug)]
struct IngestState {
    latest_epoch: BTreeMap<String, u64>,
    last_events: BTreeMap<StreamKey, LastEvent>,
    series_by_metric: BTreeMap<String, BTreeSet<String>>,
    windows: BTreeMap<SeriesKey, VecDeque<MetricEvent>>,
    gaps: VecDeque<CoverageGap>,
    dropped_by_metric: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
pub struct CatalogIngestor {
    catalog: MetricCatalog,
    catalog_digest: String,
    max_series: usize,
    max_samples_per_series: usize,
    max_gaps: usize,
    state: Arc<Mutex<IngestState>>,
}

impl CatalogIngestor {
    pub fn new(
        catalog: MetricCatalog,
        max_series: usize,
        max_samples_per_series: usize,
        max_gaps: usize,
    ) -> Result<Self> {
        catalog.validate()?;
        if max_series == 0
            || max_series > MAX_INGEST_SERIES
            || max_samples_per_series == 0
            || max_samples_per_series > MAX_SAMPLES_PER_SERIES
            || max_gaps == 0
            || max_gaps > MAX_COVERAGE_GAPS
        {
            return invalid("catalog ingestor bounds are invalid");
        }
        let catalog_digest = catalog.digest()?;
        Ok(Self {
            catalog,
            catalog_digest,
            max_series,
            max_samples_per_series,
            max_gaps,
            state: Arc::new(Mutex::new(IngestState {
                latest_epoch: BTreeMap::new(),
                last_events: BTreeMap::new(),
                series_by_metric: BTreeMap::new(),
                windows: BTreeMap::new(),
                gaps: VecDeque::new(),
                dropped_by_metric: BTreeMap::new(),
            })),
        })
    }

    pub fn ingest(&self, event: MetricEvent) -> Result<IngestReceipt> {
        let definition = self
            .catalog
            .definition(&event.metric)
            .ok_or_else(|| TelemetryError::Invalid("unknown metric event name".into()))?;
        event.validate(definition)?;
        let event_digest = event.digest()?;
        let stream_key = StreamKey {
            metric: event.metric.clone(),
            module_instance_id: event.module_instance_id.clone(),
            control_epoch: event.control_epoch,
        };
        let dimensions_bytes = serde_json::to_vec(&event.dimensions).map_err(|error| {
            TelemetryError::Invalid(format!("metric dimensions encode: {error}"))
        })?;
        let series_digest = hex_digest(&dimensions_bytes);
        let series_key = SeriesKey {
            metric: event.metric.clone(),
            dimensions_digest: series_digest.clone(),
        };

        let mut state = self
            .state
            .lock()
            .map_err(|_| TelemetryError::Invalid("catalog ingestor lock poisoned".into()))?;
        if state
            .latest_epoch
            .get(&event.module_instance_id)
            .is_some_and(|epoch| event.control_epoch < *epoch)
        {
            return invalid("metric event control epoch regressed");
        }
        let last_event = state.last_events.get(&stream_key).cloned();
        if let Some(last) = last_event {
            if event.sequence == last.sequence {
                if event_digest == last.digest {
                    return Ok(IngestReceipt {
                        accepted: false,
                        idempotent_duplicate: true,
                        event_digest,
                        series_digest,
                        coverage_complete: !state.gaps.iter().any(|gap| gap.metric == event.metric),
                        semantic_authority: false,
                        automatic_redispatch: false,
                    });
                }
                return invalid("metric event sequence conflicts with retained bytes");
            }
            if event.sequence < last.sequence {
                return invalid("metric event sequence regressed");
            }
            if event.monotonic_ns <= last.monotonic_ns {
                push_gap(
                    &mut state.gaps,
                    self.max_gaps,
                    CoverageGap {
                        schema: COVERAGE_GAP_SCHEMA.to_string(),
                        metric: event.metric.clone(),
                        module_instance_id: event.module_instance_id.clone(),
                        control_epoch: event.control_epoch,
                        kind: CoverageGapKind::ClockRegression,
                        expected_sequence: last.sequence.saturating_add(1),
                        observed_sequence: event.sequence,
                    },
                )?;
                return invalid("metric event monotonic clock regressed");
            }
            if event.sequence > last.sequence.saturating_add(1) {
                push_gap(
                    &mut state.gaps,
                    self.max_gaps,
                    CoverageGap {
                        schema: COVERAGE_GAP_SCHEMA.to_string(),
                        metric: event.metric.clone(),
                        module_instance_id: event.module_instance_id.clone(),
                        control_epoch: event.control_epoch,
                        kind: CoverageGapKind::MissingSequence,
                        expected_sequence: last.sequence.saturating_add(1),
                        observed_sequence: event.sequence,
                    },
                )?;
            }
        }

        let existing_total = state
            .series_by_metric
            .values()
            .map(BTreeSet::len)
            .sum::<usize>();
        let metric_series = state
            .series_by_metric
            .entry(event.metric.clone())
            .or_default();
        let is_new_series = !metric_series.contains(&series_digest);
        if is_new_series
            && (metric_series.len() >= definition.cardinality_ceiling as usize
                || existing_total >= self.max_series)
        {
            return invalid("metric series cardinality ceiling reached");
        }
        if is_new_series {
            metric_series.insert(series_digest.clone());
        }

        let window_evicted = {
            let window = state.windows.entry(series_key).or_default();
            let evicted = window.len() == self.max_samples_per_series;
            if evicted {
                window.pop_front();
            }
            window.push_back(event.clone());
            evicted
        };
        if window_evicted {
            let dropped = state
                .dropped_by_metric
                .entry(event.metric.clone())
                .or_default();
            *dropped = dropped
                .checked_add(1)
                .ok_or_else(|| TelemetryError::Invalid("metric drop count overflow".into()))?;
            push_gap(
                &mut state.gaps,
                self.max_gaps,
                CoverageGap {
                    schema: COVERAGE_GAP_SCHEMA.to_string(),
                    metric: event.metric.clone(),
                    module_instance_id: event.module_instance_id.clone(),
                    control_epoch: event.control_epoch,
                    kind: CoverageGapKind::WindowEviction,
                    expected_sequence: event.sequence,
                    observed_sequence: event.sequence,
                },
            )?;
        }
        state
            .latest_epoch
            .insert(event.module_instance_id.clone(), event.control_epoch);
        state.last_events.insert(
            stream_key,
            LastEvent {
                sequence: event.sequence,
                monotonic_ns: event.monotonic_ns,
                digest: event_digest.clone(),
            },
        );
        let coverage_complete = !state.gaps.iter().any(|gap| gap.metric == event.metric);
        Ok(IngestReceipt {
            accepted: true,
            idempotent_duplicate: false,
            event_digest,
            series_digest,
            coverage_complete,
            semantic_authority: false,
            automatic_redispatch: false,
        })
    }

    pub fn coverage_gaps(&self) -> Result<Vec<CoverageGap>> {
        let state = self
            .state
            .lock()
            .map_err(|_| TelemetryError::Invalid("catalog ingestor lock poisoned".into()))?;
        Ok(state.gaps.iter().cloned().collect())
    }

    pub fn project(&self, metric: &str) -> Result<MetricProjection> {
        let definition = self
            .catalog
            .definition(metric)
            .ok_or_else(|| TelemetryError::Invalid("unknown metric projection name".into()))?;
        let state = self
            .state
            .lock()
            .map_err(|_| TelemetryError::Invalid("catalog ingestor lock poisoned".into()))?;
        let mut events = state
            .windows
            .iter()
            .filter(|(key, _)| key.metric == metric)
            .flat_map(|(_, window)| window.iter().cloned())
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            (
                left.module_instance_id.as_str(),
                left.control_epoch,
                left.sequence,
                left.monotonic_ns,
            )
                .cmp(&(
                    right.module_instance_id.as_str(),
                    right.control_epoch,
                    right.sequence,
                    right.monotonic_ns,
                ))
        });
        if events.is_empty() {
            return invalid("metric projection has no retained observations");
        }
        let values = events.iter().map(|event| event.value).collect::<Vec<_>>();
        let sum = values.iter().try_fold(0.0_f64, |total, value| {
            let next = total + value;
            next.is_finite()
                .then_some(next)
                .ok_or_else(|| TelemetryError::Invalid("metric projection sum overflow".into()))
        })?;
        let min = values.iter().copied().fold(f64::INFINITY, f64::min);
        let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let last = events.last().map(|event| event.value).unwrap_or_default();
        let mean = sum / values.len() as f64;
        if !mean.is_finite() {
            return invalid("metric projection mean is nonfinite");
        }
        let gaps = state
            .gaps
            .iter()
            .filter(|gap| gap.metric == metric)
            .cloned()
            .collect::<Vec<_>>();
        let dropped_samples = *state.dropped_by_metric.get(metric).unwrap_or(&0);
        let mut projection = MetricProjection {
            schema: METRIC_PROJECTION_SCHEMA.to_string(),
            catalog_digest: self.catalog_digest.clone(),
            metric: metric.to_string(),
            unit: definition.unit.clone(),
            aggregation: definition.aggregation.clone(),
            sample_count: u64::try_from(events.len())
                .map_err(|_| TelemetryError::Invalid("metric sample count overflow".into()))?,
            dropped_samples,
            coverage_complete: gaps.is_empty() && dropped_samples == 0,
            gaps,
            min,
            max,
            sum,
            mean,
            last,
            semantic_authority: false,
            automatic_redispatch: false,
            projection_digest: String::new(),
        };
        projection.projection_digest = projection.compute_digest()?;
        projection.validate()?;
        Ok(projection)
    }
}

fn push_gap(gaps: &mut VecDeque<CoverageGap>, maximum: usize, gap: CoverageGap) -> Result<()> {
    if gaps.len() >= maximum {
        return invalid("metric coverage gap capacity reached");
    }
    gaps.push_back(gap);
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricProjection {
    pub schema: String,
    pub catalog_digest: String,
    pub metric: String,
    pub unit: String,
    pub aggregation: String,
    pub sample_count: u64,
    pub dropped_samples: u64,
    pub coverage_complete: bool,
    pub gaps: Vec<CoverageGap>,
    pub min: f64,
    pub max: f64,
    pub sum: f64,
    pub mean: f64,
    pub last: f64,
    pub semantic_authority: bool,
    pub automatic_redispatch: bool,
    pub projection_digest: String,
}

impl MetricProjection {
    pub fn validate(&self) -> Result<()> {
        if self.schema != METRIC_PROJECTION_SCHEMA
            || self.sample_count == 0
            || self.semantic_authority
            || self.automatic_redispatch
            || self.gaps.len() > MAX_COVERAGE_GAPS
        {
            return invalid("metric projection identity or authority differs");
        }
        require_lower_hex(&self.catalog_digest, 64, "catalog digest")?;
        require_metric_name(&self.metric)?;
        for value in [self.min, self.max, self.sum, self.mean, self.last] {
            if !value.is_finite() || value < 0.0 {
                return invalid("metric projection contains a nonfinite/negative value");
            }
        }
        if self.min > self.max
            || self.coverage_complete != (self.gaps.is_empty() && self.dropped_samples == 0)
            || self.projection_digest != self.compute_digest()?
        {
            return invalid("metric projection statistics, coverage or digest differ");
        }
        Ok(())
    }

    fn compute_digest(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.projection_digest.clear();
        let bytes = serde_json::to_vec(&copy).map_err(|error| {
            TelemetryError::Invalid(format!("metric projection encode: {error}"))
        })?;
        Ok(hex_digest(&bytes))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurabilityReceipt {
    pub schema: String,
    pub source_commit: String,
    pub source_tree: String,
    pub journal_record_digest: String,
    pub file_fsync_confirmed: bool,
    pub directory_fsync_confirmed: bool,
}

impl DurabilityReceipt {
    pub fn validate(&self) -> Result<()> {
        if self.schema != DURABILITY_RECEIPT_SCHEMA
            || !self.file_fsync_confirmed
            || !self.directory_fsync_confirmed
        {
            return invalid("metric durability receipt is incomplete");
        }
        require_lower_hex(&self.source_commit, 40, "durability source commit")?;
        require_lower_hex(&self.source_tree, 40, "durability source tree")?;
        require_lower_hex(
            &self.journal_record_digest,
            64,
            "durability journal record digest",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableMetricProjection {
    pub schema: String,
    pub projection: MetricProjection,
    pub durability: DurabilityReceipt,
    pub durable_complete: bool,
    pub semantic_authority: bool,
    pub automatic_redispatch: bool,
}

impl DurableMetricProjection {
    pub fn seal(projection: MetricProjection, durability: DurabilityReceipt) -> Result<Self> {
        projection.validate()?;
        durability.validate()?;
        if !projection.coverage_complete {
            return invalid("incomplete metric projection cannot be sealed durable-complete");
        }
        Ok(Self {
            schema: DURABLE_PROJECTION_SCHEMA.to_string(),
            projection,
            durability,
            durable_complete: true,
            semantic_authority: false,
            automatic_redispatch: false,
        })
    }
}

fn require_text(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > MAX_CATALOG_TEXT_BYTES || value.contains('\0') {
        return invalid(&format!("{label} is invalid"));
    }
    Ok(())
}

fn require_identifier(value: &str, label: &str) -> Result<()> {
    require_text(value, label)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return invalid(&format!("{label} contains non-mechanical characters"));
    }
    Ok(())
}

fn require_metric_name(value: &str) -> Result<()> {
    require_identifier(value, "metric name")?;
    if value.starts_with('.')
        || value.ends_with('.')
        || !value.contains('.')
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return invalid("metric name is not canonical lowercase dotted form");
    }
    Ok(())
}

fn require_lower_hex(value: &str, length: usize, label: &str) -> Result<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return invalid(&format!("{label} is not lowercase hexadecimal"));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(TelemetryError::Invalid(message.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(cardinality: u32) -> MetricCatalog {
        MetricCatalog {
            schema: METRIC_CATALOG_SCHEMA.to_string(),
            program_revision: "2026-08-31-g1".to_string(),
            catalog_version: "1.0.0".to_string(),
            status: "SOURCE_CONTRACT_OBSERVE_SHADOW_ONLY".to_string(),
            activation_ceiling: "SHADOW".to_string(),
            semantic_authority: false,
            automatic_redispatch: false,
            dimension_catalog: vec![
                DimensionDefinition {
                    name: "module_id".to_string(),
                    cardinality_ceiling: 16,
                    privacy_class: "PUBLIC_MECHANICAL".to_string(),
                },
                DimensionDefinition {
                    name: "operation_class".to_string(),
                    cardinality_ceiling: 64,
                    privacy_class: "PUBLIC_MECHANICAL".to_string(),
                },
                DimensionDefinition {
                    name: "outcome".to_string(),
                    cardinality_ceiling: 32,
                    privacy_class: "PUBLIC_MECHANICAL".to_string(),
                },
            ],
            forbidden_dimension_names: SENSITIVE_TOKENS
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            metrics: vec![MetricDefinition {
                name: "broker.accept.duration_ms".to_string(),
                unit: "milliseconds".to_string(),
                value_type: "F64_NONNEGATIVE".to_string(),
                source_module: "MOD-BROKER".to_string(),
                collection_point: "broker.accept.end".to_string(),
                aggregation: "HISTOGRAM".to_string(),
                retention: RetentionPolicy {
                    window_seconds: 60,
                    max_samples: 4096,
                },
                cardinality_ceiling: cardinality,
                privacy_class: "PUBLIC_MECHANICAL".to_string(),
                required_dimensions: vec![
                    "module_id".to_string(),
                    "operation_class".to_string(),
                    "outcome".to_string(),
                ],
                forbidden_dimensions: SENSITIVE_TOKENS
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
                sampling: SamplingPolicy {
                    mode: "EVERY_OBSERVATION".to_string(),
                    rate_numerator: 1,
                    rate_denominator: 1,
                },
                missing_data: "WINDOW_INCOMPLETE".to_string(),
                clock_source: "MONOTONIC".to_string(),
                evidence_level: "L2_TARGET".to_string(),
            }],
        }
    }

    fn event(sequence: u64, monotonic_ns: u64, operation_class: &str) -> MetricEvent {
        MetricEvent {
            schema: METRIC_EVENT_SCHEMA.to_string(),
            metric: "broker.accept.duration_ms".to_string(),
            unit: "milliseconds".to_string(),
            value: 1.5,
            source_module: "MOD-BROKER".to_string(),
            module_instance_id: "broker-1".to_string(),
            operation_id_digest: "a".repeat(64),
            control_epoch: 1,
            sequence,
            monotonic_ns,
            dimensions: BTreeMap::from([
                ("module_id".to_string(), "MOD-BROKER".to_string()),
                ("operation_class".to_string(), operation_class.to_string()),
                ("outcome".to_string(), "success".to_string()),
            ]),
            redacted: true,
        }
    }

    #[test]
    fn catalog_rejects_semantic_authority_and_sensitive_metric_names() {
        let mut value = catalog(4);
        value.semantic_authority = true;
        assert!(value.validate().is_err());
        value.semantic_authority = false;
        value.metrics[0].name = "provider.command.count".to_string();
        assert!(value.validate().is_err());
    }

    #[test]
    fn ingestion_is_catalog_bound_and_exact_duplicate_is_idempotent() {
        let ingestor = CatalogIngestor::new(catalog(4), 8, 8, 8).unwrap();
        let first = event(0, 10, "accept");
        assert!(ingestor.ingest(first.clone()).unwrap().accepted);
        let duplicate = ingestor.ingest(first).unwrap();
        assert!(!duplicate.accepted && duplicate.idempotent_duplicate);
        let mut wrong = event(1, 11, "accept");
        wrong.unit = "seconds".to_string();
        assert!(ingestor.ingest(wrong).is_err());
    }

    #[test]
    fn sequence_gap_is_retained_and_blocks_durable_complete_seal() {
        let ingestor = CatalogIngestor::new(catalog(4), 8, 8, 8).unwrap();
        ingestor.ingest(event(0, 10, "accept")).unwrap();
        let receipt = ingestor.ingest(event(2, 12, "accept")).unwrap();
        assert!(!receipt.coverage_complete);
        assert_eq!(ingestor.coverage_gaps().unwrap().len(), 1);
        let projection = ingestor.project("broker.accept.duration_ms").unwrap();
        assert!(!projection.coverage_complete);
        assert!(DurableMetricProjection::seal(projection, durability()).is_err());
    }

    #[test]
    fn clock_regression_is_retained_and_rejected() {
        let ingestor = CatalogIngestor::new(catalog(4), 8, 8, 8).unwrap();
        ingestor.ingest(event(0, 10, "accept")).unwrap();
        assert!(ingestor.ingest(event(1, 9, "accept")).is_err());
        assert!(matches!(
            ingestor.coverage_gaps().unwrap()[0].kind,
            CoverageGapKind::ClockRegression
        ));
    }

    #[test]
    fn series_cardinality_is_enforced_before_state_growth() {
        let ingestor = CatalogIngestor::new(catalog(1), 8, 8, 8).unwrap();
        ingestor.ingest(event(0, 10, "accept")).unwrap();
        let mut second = event(1, 11, "forward");
        second.module_instance_id = "broker-2".to_string();
        assert!(ingestor.ingest(second).is_err());
    }

    #[test]
    fn window_eviction_is_explicit_and_projection_digest_is_deterministic() {
        let ingestor = CatalogIngestor::new(catalog(4), 8, 1, 8).unwrap();
        ingestor.ingest(event(0, 10, "accept")).unwrap();
        ingestor.ingest(event(1, 11, "accept")).unwrap();
        let first = ingestor.project("broker.accept.duration_ms").unwrap();
        let second = ingestor.project("broker.accept.duration_ms").unwrap();
        assert_eq!(first, second);
        assert_eq!(first.dropped_samples, 1);
        assert!(!first.coverage_complete);
    }

    #[test]
    fn complete_projection_requires_explicit_file_and_directory_fsync() {
        let ingestor = CatalogIngestor::new(catalog(4), 8, 8, 8).unwrap();
        ingestor.ingest(event(0, 10, "accept")).unwrap();
        let projection = ingestor.project("broker.accept.duration_ms").unwrap();
        let sealed = DurableMetricProjection::seal(projection.clone(), durability()).unwrap();
        assert!(sealed.durable_complete);
        let mut incomplete = durability();
        incomplete.directory_fsync_confirmed = false;
        assert!(DurableMetricProjection::seal(projection, incomplete).is_err());
    }

    fn durability() -> DurabilityReceipt {
        DurabilityReceipt {
            schema: DURABILITY_RECEIPT_SCHEMA.to_string(),
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(40),
            journal_record_digest: "c".repeat(64),
            file_fsync_confirmed: true,
            directory_fsync_confirmed: true,
        }
    }
}
