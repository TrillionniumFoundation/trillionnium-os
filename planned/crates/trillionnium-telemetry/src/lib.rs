//! Bounded, content-addressed telemetry primitives for G1 qualification.
//!
//! This crate intentionally records mechanical observations only.  It never
//! accepts command text, model messages, intent, or a retry instruction.  A
//! [`MetricWindow`] is bounded by construction and its eviction count is
//! exposed, so a report cannot silently pretend that dropped samples exist.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const METRIC_SAMPLE_SCHEMA: &str = "trillionnium.owner-open.metric-sample.v1";
pub const BASELINE_REPORT_SCHEMA: &str = "trillionnium.owner-open.baseline-report.v1";
pub const REQUIRED_WORKLOADS: [&str; 12] = [
    "WL-01", "WL-02", "WL-03", "WL-04", "WL-05", "WL-06", "WL-07", "WL-08", "WL-09", "WL-10",
    "WL-11", "WL-12",
];

/// Hard bounds for serialized baseline inputs and derived projections.  They
/// are deliberately generous for host qualification, while preventing a
/// malformed artifact or iterator from turning validation into an unbounded
/// allocation/scan.
pub const MAX_WORKLOAD_SAMPLES: usize = 1_048_576;
pub const MAX_BASELINE_REPETITIONS: u32 = 1_048_576;
pub const MAX_DROPPED_SAMPLES: u64 = 1_048_576;
pub const MAX_BASELINE_WORKLOADS: usize = REQUIRED_WORKLOADS.len();
pub const MAX_OBJECTIVE_SUMMARIES: usize = 4096;
pub const MAX_ENVIRONMENT_MODULE_VERSIONS: usize = 4096;
pub const MAX_ENVIRONMENT_FIELD_BYTES: usize = 256;
pub const MAX_COST_CONCURRENCY: u32 = 1_048_576;
pub const MAX_COST_RESOURCE_BYTES: u64 = 1_u64 << 40; // 1 TiB.

/// Upper bound for one in-memory metric window.  The bound is intentionally
/// explicit: `VecDeque::with_capacity` may otherwise panic or consume an
/// unbounded amount of memory when a value comes from configuration or a
/// serialized control message.
pub const MAX_METRIC_WINDOW_CAPACITY: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryError {
    Invalid(String),
    IncompleteWorkloads(Vec<String>),
}

impl std::fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::IncompleteWorkloads(ids) => write!(f, "missing workload profiles: {ids:?}"),
        }
    }
}

impl std::error::Error for TelemetryError {}

pub type Result<T> = std::result::Result<T, TelemetryError>;

/// One raw measurement row.  Values are intentionally primitive and finite;
/// the row is suitable for a JSONL artifact without hidden process state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricSample {
    pub schema: String,
    pub workload_id: String,
    pub repetition: u32,
    pub throughput: f64,
    pub latency_p50: f64,
    pub latency_p95: f64,
    pub latency_p99: f64,
    pub latency_max: f64,
    pub queue_wait: f64,
    pub lock_wait: f64,
    pub lock_hold: f64,
    pub cpu: f64,
    pub rss: u64,
    pub fd_count: u64,
    pub thread_count: u64,
    pub process_count: u64,
    pub io_bytes: u64,
    pub fsync_count: u64,
    pub recovery_time: f64,
    pub unknown_rate: f64,
    pub redispatch_count: u64,
    pub fairness: f64,
}

impl MetricSample {
    pub fn validate(&self) -> Result<()> {
        if self.schema != METRIC_SAMPLE_SCHEMA {
            return Err(TelemetryError::Invalid(
                "metric sample schema mismatch".into(),
            ));
        }
        if !REQUIRED_WORKLOADS.contains(&self.workload_id.as_str()) {
            return Err(TelemetryError::Invalid(format!(
                "unknown workload profile {}",
                self.workload_id
            )));
        }
        if !self.workload_id.is_ascii() || self.workload_id.len() != 5 {
            return Err(TelemetryError::Invalid("workload id is malformed".into()));
        }
        if self.repetition >= MAX_BASELINE_REPETITIONS {
            return Err(TelemetryError::Invalid(
                "metric repetition exceeds hard bound".into(),
            ));
        }
        for (name, value) in self.float_fields() {
            if !value.is_finite() || value < 0.0 {
                return Err(TelemetryError::Invalid(format!(
                    "metric {name} must be finite and nonnegative"
                )));
            }
        }
        if self.fairness > 1.0 || self.unknown_rate > 1.0 {
            return Err(TelemetryError::Invalid(
                "fairness and unknown_rate must be in [0,1]".into(),
            ));
        }
        if self.latency_p50 > self.latency_p95
            || self.latency_p95 > self.latency_p99
            || self.latency_p99 > self.latency_max
        {
            return Err(TelemetryError::Invalid(
                "latency measurements must be monotonic (p50 <= p95 <= p99 <= max)".into(),
            ));
        }
        Ok(())
    }

    fn float_fields(&self) -> [(&'static str, f64); 12] {
        [
            ("throughput", self.throughput),
            ("latency_p50", self.latency_p50),
            ("latency_p95", self.latency_p95),
            ("latency_p99", self.latency_p99),
            ("latency_max", self.latency_max),
            ("queue_wait", self.queue_wait),
            ("lock_wait", self.lock_wait),
            ("lock_hold", self.lock_hold),
            ("cpu", self.cpu),
            ("recovery_time", self.recovery_time),
            ("unknown_rate", self.unknown_rate),
            ("fairness", self.fairness),
        ]
    }
}

/// A fixed-capacity ring.  It never allocates beyond `capacity` after
/// construction and records how many rows were evicted under pressure.
#[derive(Debug, Clone)]
pub struct MetricWindow {
    capacity: usize,
    samples: VecDeque<MetricSample>,
    dropped: u64,
}

impl MetricWindow {
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_METRIC_WINDOW_CAPACITY {
            return Err(TelemetryError::Invalid(format!(
                "metric window capacity must be between 1 and {MAX_METRIC_WINDOW_CAPACITY}"
            )));
        }
        Ok(Self {
            capacity,
            samples: VecDeque::with_capacity(capacity),
            dropped: 0,
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn push(&mut self, sample: MetricSample) -> Result<()> {
        sample.validate()?;
        if self.samples.len() == self.capacity {
            // Validate the accounting transition before evicting the oldest
            // row.  A rejected push must not silently discard retained
            // evidence or let the public drop count exceed its hard bound.
            let next_dropped = self
                .dropped
                .checked_add(1)
                .filter(|value| *value <= MAX_DROPPED_SAMPLES)
                .ok_or_else(|| {
                    TelemetryError::Invalid(
                        "metric window dropped sample count exceeds hard bound".into(),
                    )
                })?;
            self.samples.pop_front();
            self.dropped = next_dropped;
        }
        self.samples.push_back(sample);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn samples(&self) -> impl ExactSizeIterator<Item = &MetricSample> {
        self.samples.iter()
    }

    pub fn into_samples(self) -> Vec<MetricSample> {
        self.samples.into_iter().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSummary {
    pub workload_id: String,
    pub sample_count: u32,
    pub dropped_samples: u64,
    pub throughput: f64,
    pub latency_p50: f64,
    pub latency_p95: f64,
    pub latency_p99: f64,
    pub latency_max: f64,
    pub queue_wait: f64,
    pub lock_wait: f64,
    pub lock_hold: f64,
    pub cpu: f64,
    pub rss: u64,
    pub fd_count: u64,
    pub thread_count: u64,
    pub process_count: u64,
    pub io_bytes: u64,
    pub fsync_count: u64,
    pub recovery_time: f64,
    pub unknown_rate: f64,
    pub redispatch_count: u64,
    pub fairness: f64,
}

impl WorkloadSummary {
    pub fn from_samples(
        workload_id: impl Into<String>,
        samples: &[MetricSample],
        dropped_samples: u64,
    ) -> Result<Self> {
        let workload_id = workload_id.into();
        if samples.is_empty() {
            return Err(TelemetryError::Invalid(format!(
                "workload {workload_id} has no samples"
            )));
        }
        if samples.len() > MAX_WORKLOAD_SAMPLES {
            return Err(TelemetryError::Invalid(format!(
                "workload {workload_id} has more than {MAX_WORKLOAD_SAMPLES} samples"
            )));
        }
        if dropped_samples > MAX_DROPPED_SAMPLES {
            return Err(TelemetryError::Invalid(
                "workload summary dropped sample count exceeds hard bound".into(),
            ));
        }
        if samples
            .iter()
            .any(|sample| sample.workload_id != workload_id)
        {
            return Err(TelemetryError::Invalid(
                "workload summary received mixed profile rows".into(),
            ));
        }
        let mut repetitions = BTreeSet::new();
        let retained = u32::try_from(samples.len())
            .map_err(|_| TelemetryError::Invalid("workload summary has too many samples".into()))?;
        let total = retained
            .checked_add(u32::try_from(dropped_samples).map_err(|_| {
                TelemetryError::Invalid("workload summary sample accounting overflows".into())
            })?)
            .ok_or_else(|| {
                TelemetryError::Invalid("workload summary sample accounting overflows".into())
            })?;
        if total == 0 || total > MAX_BASELINE_REPETITIONS {
            return Err(TelemetryError::Invalid(
                "workload summary sample accounting exceeds hard bound".into(),
            ));
        }
        for sample in samples {
            sample.validate()?;
            if sample.repetition >= total {
                return Err(TelemetryError::Invalid(
                    "workload summary repetition is outside accounted sample set".into(),
                ));
            }
            if !repetitions.insert(sample.repetition) {
                return Err(TelemetryError::Invalid(
                    "workload summary contains duplicate repetitions".into(),
                ));
            }
        }
        // With no evictions, the repetition set must be exactly the ordinal
        // run represented by the retained rows.  Otherwise a producer could
        // claim a complete baseline while silently omitting one repetition
        // and replacing it with an arbitrary high number.
        if dropped_samples == 0
            && repetitions
                .iter()
                .enumerate()
                .any(|(index, repetition)| *repetition != index as u32)
        {
            return Err(TelemetryError::Invalid(
                "workload summary repetitions are not an exact ordinal set".into(),
            ));
        }
        let sample_count = retained;
        let mean = |value: fn(&MetricSample) -> f64| -> Result<f64> {
            let mut total = 0.0_f64;
            for sample in samples {
                total += value(sample);
                if !total.is_finite() {
                    return Err(TelemetryError::Invalid(
                        "workload summary metric sum is not finite".into(),
                    ));
                }
            }
            let mean = total / samples.len() as f64;
            if !mean.is_finite() {
                return Err(TelemetryError::Invalid(
                    "workload summary metric mean is not finite".into(),
                ));
            }
            Ok(mean)
        };
        let max_u64 =
            |value: fn(&MetricSample) -> u64| samples.iter().map(value).max().unwrap_or_default();
        // Preserve the percentile series supplied by the producer. Deriving
        // p50/p95 from the p99 column would make a lower-tail regression
        // invisible while still producing a self-consistent summary.
        let latency_p50_values = samples.iter().map(|s| s.latency_p50).collect::<Vec<_>>();
        let latency_p95_values = samples.iter().map(|s| s.latency_p95).collect::<Vec<_>>();
        let latency_p99_values = samples.iter().map(|s| s.latency_p99).collect::<Vec<_>>();
        Ok(Self {
            workload_id,
            sample_count,
            dropped_samples,
            throughput: mean(|s| s.throughput)?,
            latency_p50: percentile(&latency_p50_values, 0.50)?,
            latency_p95: percentile(&latency_p95_values, 0.95)?,
            latency_p99: percentile(&latency_p99_values, 0.99)?,
            latency_max: samples
                .iter()
                .map(|s| s.latency_max)
                .fold(0.0_f64, f64::max),
            queue_wait: mean(|s| s.queue_wait)?,
            lock_wait: mean(|s| s.lock_wait)?,
            lock_hold: mean(|s| s.lock_hold)?,
            cpu: mean(|s| s.cpu)?,
            rss: max_u64(|s| s.rss),
            fd_count: max_u64(|s| s.fd_count),
            thread_count: max_u64(|s| s.thread_count),
            process_count: max_u64(|s| s.process_count),
            io_bytes: samples.iter().map(|s| s.io_bytes).max().unwrap_or_default(),
            fsync_count: samples
                .iter()
                .map(|s| s.fsync_count)
                .max()
                .unwrap_or_default(),
            recovery_time: samples
                .iter()
                .map(|s| s.recovery_time)
                .fold(0.0_f64, f64::max),
            unknown_rate: mean(|s| s.unknown_rate)?,
            redispatch_count: samples.iter().try_fold(0_u64, |total, sample| {
                total.checked_add(sample.redispatch_count).ok_or_else(|| {
                    TelemetryError::Invalid("workload redispatch count overflow".into())
                })
            })?,
            fairness: mean(|s| s.fairness)?,
        })
    }

    /// Validate a serialized summary before it is used in a baseline or
    /// objective.  Summary values are derived data, but accepting a malformed
    /// hand-edited summary would let it bypass the raw-sample contract.
    pub fn validate(&self) -> Result<()> {
        if !REQUIRED_WORKLOADS.contains(&self.workload_id.as_str())
            || !self.workload_id.is_ascii()
            || self.workload_id.len() != 5
        {
            return Err(TelemetryError::Invalid(format!(
                "workload summary id is malformed: {}",
                self.workload_id
            )));
        }
        if self.sample_count == 0 {
            return Err(TelemetryError::Invalid(format!(
                "workload {} has no retained samples",
                self.workload_id
            )));
        }
        if usize::try_from(self.sample_count).unwrap_or(usize::MAX) > MAX_WORKLOAD_SAMPLES {
            return Err(TelemetryError::Invalid(
                "workload summary sample count exceeds hard bound".into(),
            ));
        }
        if self.dropped_samples > MAX_DROPPED_SAMPLES {
            return Err(TelemetryError::Invalid(
                "workload summary dropped sample count exceeds hard bound".into(),
            ));
        }
        for (name, value) in [
            ("throughput", self.throughput),
            ("latency_p50", self.latency_p50),
            ("latency_p95", self.latency_p95),
            ("latency_p99", self.latency_p99),
            ("latency_max", self.latency_max),
            ("queue_wait", self.queue_wait),
            ("lock_wait", self.lock_wait),
            ("lock_hold", self.lock_hold),
            ("cpu", self.cpu),
            ("recovery_time", self.recovery_time),
            ("unknown_rate", self.unknown_rate),
            ("fairness", self.fairness),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(TelemetryError::Invalid(format!(
                    "summary metric {name} must be finite and nonnegative"
                )));
            }
        }
        if self.fairness > 1.0 || self.unknown_rate > 1.0 {
            return Err(TelemetryError::Invalid(
                "summary fairness and unknown_rate must be in [0,1]".into(),
            ));
        }
        if self.latency_p50 > self.latency_p95
            || self.latency_p95 > self.latency_p99
            || self.latency_p99 > self.latency_max
        {
            return Err(TelemetryError::Invalid(
                "summary latency measurements are not monotonic".into(),
            ));
        }
        Ok(())
    }
}

pub fn percentile(values: &[f64], quantile: f64) -> Result<f64> {
    if values.is_empty() || !quantile.is_finite() || !(0.0..=1.0).contains(&quantile) {
        return Err(TelemetryError::Invalid(
            "percentile requires nonempty finite values and q in [0,1]".into(),
        ));
    }
    if values.len() > MAX_WORKLOAD_SAMPLES {
        return Err(TelemetryError::Invalid(
            "percentile input exceeds hard bound".into(),
        ));
    }
    if values
        .iter()
        .any(|value| !value.is_finite() || *value < 0.0)
    {
        return Err(TelemetryError::Invalid(
            "percentile values must be finite and nonnegative".into(),
        ));
    }
    let mut ordered = values.to_vec();
    ordered.sort_by(f64::total_cmp);
    let rank = ((ordered.len() as f64) * quantile).ceil() as usize;
    let index = rank.saturating_sub(1).min(ordered.len() - 1);
    Ok(ordered[index])
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveWeights {
    pub useful_work: f64,
    pub latency_p99: f64,
    pub unknown_rate: f64,
    pub resource_cost: f64,
    pub fairness_deviation: f64,
    pub recovery_time: f64,
}

impl Default for ObjectiveWeights {
    fn default() -> Self {
        Self {
            useful_work: 1.0,
            latency_p99: 1.0,
            unknown_rate: 10.0,
            resource_cost: 0.01,
            fairness_deviation: 1.0,
            recovery_time: 1.0,
        }
    }
}

impl ObjectiveWeights {
    pub fn validate(&self) -> Result<()> {
        let values = [
            self.useful_work,
            self.latency_p99,
            self.unknown_rate,
            self.resource_cost,
            self.fairness_deviation,
            self.recovery_time,
        ];
        if values
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
        {
            return Err(TelemetryError::Invalid(
                "objective weights must be finite and nonnegative".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveProjection {
    pub useful_work: f64,
    pub latency_penalty: f64,
    pub unknown_penalty: f64,
    pub resource_penalty: f64,
    pub fairness_penalty: f64,
    pub recovery_penalty: f64,
    pub score: f64,
}

pub fn project_objective(
    summaries: impl IntoIterator<Item = WorkloadSummary>,
    weights: ObjectiveWeights,
) -> Result<ObjectiveProjection> {
    weights.validate()?;
    let mut bounded_summaries = Vec::new();
    for summary in summaries {
        if bounded_summaries.len() >= MAX_OBJECTIVE_SUMMARIES {
            return Err(TelemetryError::Invalid(
                "objective projection has too many workload summaries".into(),
            ));
        }
        bounded_summaries.push(summary);
    }
    let summaries = bounded_summaries;
    if summaries.is_empty() {
        return Err(TelemetryError::Invalid(
            "objective projection requires at least one workload".into(),
        ));
    }
    for summary in &summaries {
        summary.validate()?;
    }
    let count = summaries.len() as f64;
    let mean = |name: &'static str, value: fn(&WorkloadSummary) -> f64| -> Result<f64> {
        let mut total = 0.0_f64;
        for summary in &summaries {
            total += value(summary);
            if !total.is_finite() {
                return Err(TelemetryError::Invalid(format!(
                    "objective {name} mean is not finite"
                )));
            }
        }
        let mean = total / count;
        if !mean.is_finite() {
            return Err(TelemetryError::Invalid(format!(
                "objective {name} mean is not finite"
            )));
        }
        Ok(mean)
    };
    let useful_work = mean("useful_work", |s| s.throughput)?;
    let latency_penalty = mean("latency_penalty", |s| s.latency_p99)?;
    let unknown_penalty = mean("unknown_penalty", |s| s.unknown_rate)?;
    let resource_penalty = mean("resource_penalty", |s| {
        s.cpu + s.rss as f64 / 1_048_576.0 + s.io_bytes as f64 / 1_048_576.0
    })?;
    let fairness_penalty = mean("fairness_penalty", |s| (1.0 - s.fairness).max(0.0))?;
    let recovery_penalty = mean("recovery_penalty", |s| s.recovery_time)?;
    let terms = [
        weights.useful_work * useful_work,
        -(weights.latency_p99 * latency_penalty),
        -(weights.unknown_rate * unknown_penalty),
        -(weights.resource_cost * resource_penalty),
        -(weights.fairness_deviation * fairness_penalty),
        -(weights.recovery_time * recovery_penalty),
    ];
    let mut score = 0.0_f64;
    for term in terms {
        if !term.is_finite() {
            return Err(TelemetryError::Invalid(
                "objective score term is not finite".into(),
            ));
        }
        score += term;
        if !score.is_finite() {
            return Err(TelemetryError::Invalid(
                "objective score is not finite".into(),
            ));
        }
    }
    let projection = ObjectiveProjection {
        useful_work,
        latency_penalty,
        unknown_penalty,
        resource_penalty,
        fairness_penalty,
        recovery_penalty,
        score,
    };
    projection.validate()?;
    Ok(projection)
}

impl ObjectiveProjection {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("useful_work", self.useful_work),
            ("latency_penalty", self.latency_penalty),
            ("unknown_penalty", self.unknown_penalty),
            ("resource_penalty", self.resource_penalty),
            ("fairness_penalty", self.fairness_penalty),
            ("recovery_penalty", self.recovery_penalty),
            ("score", self.score),
        ] {
            if !value.is_finite() {
                return Err(TelemetryError::Invalid(format!(
                    "objective field {name} must be finite"
                )));
            }
            if name != "score" && value < 0.0 {
                return Err(TelemetryError::Invalid(format!(
                    "objective field {name} must be nonnegative"
                )));
            }
        }
        if self.unknown_penalty > 1.0 || self.fairness_penalty > 1.0 {
            return Err(TelemetryError::Invalid(
                "objective rate penalties must be in [0,1]".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentIdentity {
    pub source_commit: String,
    pub source_tree: String,
    pub toolchain: String,
    pub hardware: String,
    pub kernel: String,
    pub filesystem: String,
    pub durability_policy: String,
    pub module_versions: BTreeMap<String, String>,
    pub control_configuration: String,
}

impl EnvironmentIdentity {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("source_commit", &self.source_commit),
            ("source_tree", &self.source_tree),
            ("toolchain", &self.toolchain),
            ("hardware", &self.hardware),
            ("kernel", &self.kernel),
            ("filesystem", &self.filesystem),
            ("durability_policy", &self.durability_policy),
            ("control_configuration", &self.control_configuration),
        ] {
            if value.trim().is_empty() || value.len() > MAX_ENVIRONMENT_FIELD_BYTES {
                return Err(TelemetryError::Invalid(format!(
                    "environment field {name} is empty or exceeds hard bound"
                )));
            }
        }
        for (name, value) in [
            ("source_commit", self.source_commit.as_str()),
            ("source_tree", self.source_tree.as_str()),
        ] {
            if !is_source_digest(value) {
                return Err(TelemetryError::Invalid(format!(
                    "environment field {name} must be a lowercase 40- or 64-hex digest"
                )));
            }
        }
        if self.module_versions.len() > MAX_ENVIRONMENT_MODULE_VERSIONS {
            return Err(TelemetryError::Invalid(
                "environment module version map exceeds hard bound".into(),
            ));
        }
        for (module, version) in &self.module_versions {
            if module.trim().is_empty()
                || module.len() > 256
                || version.trim().is_empty()
                || version.len() > 256
            {
                return Err(TelemetryError::Invalid(
                    "environment module version identity is invalid".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaselineReport {
    pub schema: String,
    pub environment: EnvironmentIdentity,
    pub repetitions: u32,
    pub workloads: BTreeMap<String, WorkloadSummary>,
    pub objective: ObjectiveProjection,
    pub artifact_digest: String,
}

impl BaselineReport {
    pub fn new(
        environment: EnvironmentIdentity,
        repetitions: u32,
        workloads: BTreeMap<String, WorkloadSummary>,
        weights: ObjectiveWeights,
    ) -> Result<Self> {
        if repetitions == 0 || repetitions > MAX_BASELINE_REPETITIONS {
            return Err(TelemetryError::Invalid(format!(
                "baseline repetitions must be between 1 and {MAX_BASELINE_REPETITIONS}"
            )));
        }
        environment.validate()?;
        if workloads.len() > MAX_BASELINE_WORKLOADS {
            return Err(TelemetryError::Invalid(format!(
                "baseline workload map exceeds hard bound {MAX_BASELINE_WORKLOADS}"
            )));
        }
        let missing = REQUIRED_WORKLOADS
            .iter()
            .filter(|id| !workloads.contains_key(**id))
            .map(|id| (*id).to_string())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(TelemetryError::IncompleteWorkloads(missing));
        }
        validate_workload_map(&workloads, repetitions)?;
        let objective = project_objective(workloads.values().cloned(), weights)?;
        let mut report = Self {
            schema: BASELINE_REPORT_SCHEMA.to_string(),
            environment,
            repetitions,
            workloads,
            objective,
            artifact_digest: String::new(),
        };
        report.artifact_digest = report.compute_digest()?;
        Ok(report)
    }

    /// Validate a report against the versioned objective weights used to
    /// produce it.  The v1 wire shape stores the projection but not its
    /// weights, so callers that gate on the score must supply the exact
    /// configuration explicitly.  This path deliberately does not call
    /// [`Self::validate`], whose compatibility default is
    /// [`ObjectiveWeights::default`].
    pub fn validate_with_weights(&self, weights: ObjectiveWeights) -> Result<()> {
        self.validate_structure()?;
        weights.validate()?;
        let expected = project_objective(self.workloads.values().cloned(), weights)?;
        compare_projection(&self.objective, &expected, true)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_structure()?;
        let expected = project_objective(
            self.workloads.values().cloned(),
            ObjectiveWeights::default(),
        )?;
        // A v1 report does not carry its weight configuration.  The
        // compatibility validator therefore treats the default weights as
        // canonical and checks the score as well as every component.  Reports
        // produced with another versioned weight set must use
        // `validate_with_weights` at the trust boundary.
        compare_projection(&self.objective, &expected, true)
    }

    /// Validate all weight-independent fields and the content digest.  The
    /// helper is intentionally private so callers cannot accidentally accept
    /// a report whose objective score was changed without checking the
    /// configured weights.
    fn validate_structure(&self) -> Result<()> {
        if self.schema != BASELINE_REPORT_SCHEMA {
            return Err(TelemetryError::Invalid(
                "baseline report schema mismatch".into(),
            ));
        }
        self.environment.validate()?;
        if self.repetitions == 0 || self.repetitions > MAX_BASELINE_REPETITIONS {
            return Err(TelemetryError::Invalid(format!(
                "baseline repetitions must be between 1 and {MAX_BASELINE_REPETITIONS}"
            )));
        }
        if self.workloads.len() > MAX_BASELINE_WORKLOADS {
            return Err(TelemetryError::Invalid(format!(
                "baseline workload map exceeds hard bound {MAX_BASELINE_WORKLOADS}"
            )));
        }
        let missing = REQUIRED_WORKLOADS
            .iter()
            .filter(|id| !self.workloads.contains_key(**id))
            .map(|id| (*id).to_string())
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(TelemetryError::IncompleteWorkloads(missing));
        }
        validate_workload_map(&self.workloads, self.repetitions)?;
        self.objective.validate()?;
        if self.artifact_digest != self.compute_digest()? {
            return Err(TelemetryError::Invalid(
                "baseline artifact digest does not match content".into(),
            ));
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String> {
        let mut clone = self.clone();
        clone.artifact_digest.clear();
        let bytes = serde_json::to_vec(&clone)
            .map_err(|error| TelemetryError::Invalid(format!("encode baseline: {error}")))?;
        Ok(hex(&Sha256::digest(bytes)))
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| TelemetryError::Invalid(format!("encode baseline: {error}")))
    }
}

fn compare_projection(
    actual: &ObjectiveProjection,
    expected: &ObjectiveProjection,
    include_score: bool,
) -> Result<()> {
    let mut fields = vec![
        ("useful_work", actual.useful_work, expected.useful_work),
        (
            "latency_penalty",
            actual.latency_penalty,
            expected.latency_penalty,
        ),
        (
            "unknown_penalty",
            actual.unknown_penalty,
            expected.unknown_penalty,
        ),
        (
            "resource_penalty",
            actual.resource_penalty,
            expected.resource_penalty,
        ),
        (
            "fairness_penalty",
            actual.fairness_penalty,
            expected.fairness_penalty,
        ),
        (
            "recovery_penalty",
            actual.recovery_penalty,
            expected.recovery_penalty,
        ),
    ];
    if include_score {
        fields.push(("score", actual.score, expected.score));
    }
    for (name, actual, expected) in fields {
        if actual.to_bits() != expected.to_bits() {
            return Err(TelemetryError::Invalid(format!(
                "objective field {name} does not match recomputed projection"
            )));
        }
    }
    Ok(())
}

fn validate_workload_map(
    workloads: &BTreeMap<String, WorkloadSummary>,
    repetitions: u32,
) -> Result<()> {
    if repetitions == 0 || repetitions > MAX_BASELINE_REPETITIONS {
        return Err(TelemetryError::Invalid(format!(
            "baseline repetitions exceed hard bound {MAX_BASELINE_REPETITIONS}"
        )));
    }
    if workloads.len() > MAX_BASELINE_WORKLOADS {
        return Err(TelemetryError::Invalid(format!(
            "baseline workload map exceeds hard bound {MAX_BASELINE_WORKLOADS}"
        )));
    }
    for (key, summary) in workloads {
        summary.validate()?;
        if key != &summary.workload_id {
            return Err(TelemetryError::Invalid(format!(
                "workload map key {key} does not match summary id {}",
                summary.workload_id
            )));
        }
        let retained = u64::from(summary.sample_count);
        let dropped = summary.dropped_samples;
        let expected = u64::from(repetitions);
        let accounted = retained.checked_add(dropped).ok_or_else(|| {
            TelemetryError::Invalid(format!("workload {key} sample accounting overflows"))
        })?;
        if retained > expected || accounted != expected {
            return Err(TelemetryError::Invalid(format!(
                "workload {key} sample accounting does not match repetitions"
            )));
        }
    }
    if workloads
        .keys()
        .any(|key| !REQUIRED_WORKLOADS.contains(&key.as_str()))
    {
        return Err(TelemetryError::Invalid(
            "baseline contains an unknown workload profile".into(),
        ));
    }
    Ok(())
}

pub fn required_workloads() -> BTreeSet<&'static str> {
    REQUIRED_WORKLOADS.into_iter().collect()
}

/// A mechanical observation for one module instance.  This is deliberately
/// separate from [`MetricSample`]: a read model may be fed by a live module
/// stream and must not acquire workload labels, command text or semantic
/// policy fields.
pub const MODULE_SAMPLE_SCHEMA: &str = "trillionnium.owner-open.module-sample.v1";
pub const MODULE_READ_MODEL_SCHEMA: &str = "trillionnium.owner-open.module-read-model.v1";
pub const COST_CURVE_SCHEMA: &str = "trillionnium.owner-open.cost-curve.v1";
pub const MAX_READ_MODEL_ENTRIES: usize = 1_048_576;
pub const MAX_COST_CURVE_POINTS: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleKey {
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
}

impl ModuleKey {
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("module_id", self.module_id.as_str()),
            ("module_instance_id", self.module_instance_id.as_str()),
            ("partition", self.partition.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(TelemetryError::Invalid(format!(
                    "module key {name} is invalid"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleTelemetrySample {
    pub schema: String,
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
    pub observed_at_ms: u64,
    pub queue_depth: u32,
    pub active_count: u32,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub io_bytes: u64,
    pub latency_p99_ms: f64,
    pub unknown_rate: f64,
    pub health_score: f64,
}

impl ModuleTelemetrySample {
    pub fn key(&self) -> ModuleKey {
        ModuleKey {
            module_id: self.module_id.clone(),
            module_instance_id: self.module_instance_id.clone(),
            partition: self.partition.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != MODULE_SAMPLE_SCHEMA {
            return Err(TelemetryError::Invalid(
                "module sample schema mismatch".into(),
            ));
        }
        self.key().validate()?;
        for (name, value) in [
            ("latency_p99_ms", self.latency_p99_ms),
            ("unknown_rate", self.unknown_rate),
            ("health_score", self.health_score),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(TelemetryError::Invalid(format!(
                    "module sample {name} must be finite and nonnegative"
                )));
            }
        }
        if self.unknown_rate > 1.0 || self.health_score > 1.0 {
            return Err(TelemetryError::Invalid(
                "module sample rates/scores must be in [0,1]".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleReadModel {
    pub schema: String,
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
    pub observed_at_ms: u64,
    pub sample_count: u64,
    pub queue_depth: u32,
    pub active_count: u32,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub io_bytes: u64,
    pub latency_p99_ms: f64,
    pub unknown_rate: f64,
    pub health_score: f64,
}

impl ModuleReadModel {
    fn from_sample(sample: &ModuleTelemetrySample) -> Self {
        Self {
            schema: MODULE_READ_MODEL_SCHEMA.to_string(),
            module_id: sample.module_id.clone(),
            module_instance_id: sample.module_instance_id.clone(),
            partition: sample.partition.clone(),
            observed_at_ms: sample.observed_at_ms,
            sample_count: 1,
            queue_depth: sample.queue_depth,
            active_count: sample.active_count,
            cpu_millis: sample.cpu_millis,
            memory_bytes: sample.memory_bytes,
            io_bytes: sample.io_bytes,
            latency_p99_ms: sample.latency_p99_ms,
            unknown_rate: sample.unknown_rate,
            health_score: sample.health_score,
        }
    }

    pub fn key(&self) -> ModuleKey {
        ModuleKey {
            module_id: self.module_id.clone(),
            module_instance_id: self.module_instance_id.clone(),
            partition: self.partition.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != MODULE_READ_MODEL_SCHEMA {
            return Err(TelemetryError::Invalid(
                "module read model schema mismatch".into(),
            ));
        }
        self.key().validate()?;
        if self.sample_count == 0 {
            return Err(TelemetryError::Invalid(
                "module read model sample count is zero".into(),
            ));
        }
        if self.sample_count > MAX_READ_MODEL_ENTRIES as u64 {
            return Err(TelemetryError::Invalid(
                "module read model sample count exceeds hard bound".into(),
            ));
        }
        for (name, value) in [
            ("latency_p99_ms", self.latency_p99_ms),
            ("unknown_rate", self.unknown_rate),
            ("health_score", self.health_score),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(TelemetryError::Invalid(format!(
                    "module read model {name} must be finite and nonnegative"
                )));
            }
        }
        if self.unknown_rate > 1.0 || self.health_score > 1.0 {
            return Err(TelemetryError::Invalid(
                "module read model rates/scores must be in [0,1]".into(),
            ));
        }
        Ok(())
    }

    fn matches_sample(&self, sample: &ModuleTelemetrySample) -> bool {
        self.module_id == sample.module_id
            && self.module_instance_id == sample.module_instance_id
            && self.partition == sample.partition
            && self.observed_at_ms == sample.observed_at_ms
            && self.queue_depth == sample.queue_depth
            && self.active_count == sample.active_count
            && self.cpu_millis == sample.cpu_millis
            && self.memory_bytes == sample.memory_bytes
            && self.io_bytes == sample.io_bytes
            && self.latency_p99_ms.to_bits() == sample.latency_p99_ms.to_bits()
            && self.unknown_rate.to_bits() == sample.unknown_rate.to_bits()
            && self.health_score.to_bits() == sample.health_score.to_bits()
    }
}

#[derive(Debug)]
struct ReadModelState {
    max_entries: usize,
    models: BTreeMap<ModuleKey, ModuleReadModel>,
}

/// Bounded, thread-safe latest-value projections for module telemetry.
/// Updates are monotonic per module identity; an exact retransmission is
/// idempotent, while a same-timestamp conflict fails closed.
#[derive(Debug, Clone)]
pub struct ModuleReadModelStore {
    inner: Arc<Mutex<ReadModelState>>,
}

impl ModuleReadModelStore {
    pub fn new(max_entries: usize) -> Result<Self> {
        if max_entries == 0 || max_entries > MAX_READ_MODEL_ENTRIES {
            return Err(TelemetryError::Invalid(format!(
                "module read model capacity must be between 1 and {MAX_READ_MODEL_ENTRIES}"
            )));
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(ReadModelState {
                max_entries,
                models: BTreeMap::new(),
            })),
        })
    }

    pub fn max_entries(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.max_entries)
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.models.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn upsert(&self, sample: ModuleTelemetrySample) -> Result<()> {
        sample.validate()?;
        let key = sample.key();
        let mut state = self
            .inner
            .lock()
            .map_err(|_| TelemetryError::Invalid("module read model lock poisoned".into()))?;
        if let Some(model) = state.models.get_mut(&key) {
            if sample.observed_at_ms < model.observed_at_ms {
                return Err(TelemetryError::Invalid(
                    "module telemetry timestamp regressed".into(),
                ));
            }
            if sample.observed_at_ms == model.observed_at_ms {
                if model.matches_sample(&sample) {
                    return Ok(());
                }
                return Err(TelemetryError::Invalid(
                    "module telemetry timestamp collision".into(),
                ));
            }
            let next_sample_count = model
                .sample_count
                .checked_add(1)
                .ok_or_else(|| TelemetryError::Invalid("module sample count overflow".into()))?;
            if next_sample_count > MAX_READ_MODEL_ENTRIES as u64 {
                return Err(TelemetryError::Invalid(
                    "module read model sample count exceeds hard bound".into(),
                ));
            }
            model.observed_at_ms = sample.observed_at_ms;
            model.sample_count = next_sample_count;
            model.queue_depth = sample.queue_depth;
            model.active_count = sample.active_count;
            model.cpu_millis = sample.cpu_millis;
            model.memory_bytes = sample.memory_bytes;
            model.io_bytes = sample.io_bytes;
            model.latency_p99_ms = sample.latency_p99_ms;
            model.unknown_rate = sample.unknown_rate;
            model.health_score = sample.health_score;
            return Ok(());
        }
        if state.models.len() >= state.max_entries {
            return Err(TelemetryError::Invalid(
                "module read model capacity exceeded".into(),
            ));
        }
        state
            .models
            .insert(key, ModuleReadModel::from_sample(&sample));
        Ok(())
    }

    pub fn get(&self, key: &ModuleKey) -> Result<Option<ModuleReadModel>> {
        key.validate()?;
        let state = self
            .inner
            .lock()
            .map_err(|_| TelemetryError::Invalid("module read model lock poisoned".into()))?;
        Ok(state.models.get(key).cloned())
    }

    pub fn snapshot(&self) -> Result<Vec<ModuleReadModel>> {
        let state = self
            .inner
            .lock()
            .map_err(|_| TelemetryError::Invalid("module read model lock poisoned".into()))?;
        Ok(state.models.values().cloned().collect())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostPoint {
    pub concurrency: u32,
    pub throughput: f64,
    pub latency_p99_ms: f64,
    pub cpu: f64,
    pub memory_bytes: u64,
    pub io_bytes: u64,
    pub unknown_rate: f64,
}

impl CostPoint {
    pub fn validate(&self) -> Result<()> {
        if self.concurrency == 0 || self.concurrency > MAX_COST_CONCURRENCY {
            return Err(TelemetryError::Invalid(format!(
                "cost point concurrency must be between 1 and {MAX_COST_CONCURRENCY}"
            )));
        }
        if self.memory_bytes > MAX_COST_RESOURCE_BYTES || self.io_bytes > MAX_COST_RESOURCE_BYTES {
            return Err(TelemetryError::Invalid(
                "cost point resource bytes exceed hard bound".into(),
            ));
        }
        for (name, value) in [
            ("throughput", self.throughput),
            ("latency_p99_ms", self.latency_p99_ms),
            ("cpu", self.cpu),
            ("unknown_rate", self.unknown_rate),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(TelemetryError::Invalid(format!(
                    "cost point {name} must be finite and nonnegative"
                )));
            }
        }
        if self.unknown_rate > 1.0 {
            return Err(TelemetryError::Invalid(
                "cost point unknown_rate must be in [0,1]".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostEstimate {
    pub concurrency: u32,
    pub throughput: f64,
    pub latency_p99_ms: f64,
    pub cpu: f64,
    pub memory_bytes: f64,
    pub io_bytes: f64,
    pub unknown_rate: f64,
}

impl CostEstimate {
    pub fn validate(&self) -> Result<()> {
        if self.concurrency == 0 || self.concurrency > MAX_COST_CONCURRENCY {
            return Err(TelemetryError::Invalid(format!(
                "cost estimate concurrency must be between 1 and {MAX_COST_CONCURRENCY}"
            )));
        }
        for (name, value) in [
            ("throughput", self.throughput),
            ("latency_p99_ms", self.latency_p99_ms),
            ("cpu", self.cpu),
            ("memory_bytes", self.memory_bytes),
            ("io_bytes", self.io_bytes),
            ("unknown_rate", self.unknown_rate),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(TelemetryError::Invalid(format!(
                    "cost estimate {name} must be finite and nonnegative"
                )));
            }
        }
        if self.memory_bytes > MAX_COST_RESOURCE_BYTES as f64
            || self.io_bytes > MAX_COST_RESOURCE_BYTES as f64
        {
            return Err(TelemetryError::Invalid(
                "cost estimate resource bytes exceed hard bound".into(),
            ));
        }
        if self.unknown_rate > 1.0 {
            return Err(TelemetryError::Invalid(
                "cost estimate unknown_rate must be in [0,1]".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostCurve {
    pub schema: String,
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
    /// Monotonic producer timestamp for this curve revision.  A zero value is
    /// retained for backwards-compatible v1 artifacts; once a producer emits
    /// a nonzero timestamp, stale or same-time conflicting replacements are
    /// rejected by [`CostCurveStore`].
    #[serde(default)]
    pub observed_at_ms: u64,
    pub max_points: usize,
    pub points: Vec<CostPoint>,
}

impl CostCurve {
    pub fn new(
        module_id: impl Into<String>,
        module_instance_id: impl Into<String>,
        partition: impl Into<String>,
        max_points: usize,
    ) -> Result<Self> {
        if max_points == 0 || max_points > MAX_COST_CURVE_POINTS {
            return Err(TelemetryError::Invalid(format!(
                "cost curve capacity must be between 1 and {MAX_COST_CURVE_POINTS}"
            )));
        }
        let curve = Self {
            schema: COST_CURVE_SCHEMA.to_string(),
            module_id: module_id.into(),
            module_instance_id: module_instance_id.into(),
            partition: partition.into(),
            observed_at_ms: 0,
            max_points,
            points: Vec::new(),
        };
        curve.validate()?;
        Ok(curve)
    }

    /// Set the producer timestamp used for monotonic store updates.
    pub fn with_observed_at_ms(mut self, observed_at_ms: u64) -> Self {
        self.observed_at_ms = observed_at_ms;
        self
    }

    pub fn set_observed_at_ms(&mut self, observed_at_ms: u64) {
        self.observed_at_ms = observed_at_ms;
    }

    pub fn key(&self) -> ModuleKey {
        ModuleKey {
            module_id: self.module_id.clone(),
            module_instance_id: self.module_instance_id.clone(),
            partition: self.partition.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != COST_CURVE_SCHEMA {
            return Err(TelemetryError::Invalid("cost curve schema mismatch".into()));
        }
        self.key().validate()?;
        if self.max_points == 0 || self.max_points > MAX_COST_CURVE_POINTS {
            return Err(TelemetryError::Invalid(
                "cost curve capacity is outside the hard bound".into(),
            ));
        }
        if self.points.len() > self.max_points {
            return Err(TelemetryError::Invalid(
                "cost curve contains more points than its capacity".into(),
            ));
        }
        let mut previous = 0;
        for point in &self.points {
            point.validate()?;
            if point.concurrency <= previous {
                return Err(TelemetryError::Invalid(
                    "cost curve points must have unique ascending concurrency".into(),
                ));
            }
            previous = point.concurrency;
        }
        Ok(())
    }

    pub fn push(&mut self, point: CostPoint) -> Result<()> {
        point.validate()?;
        self.validate()?;
        match self
            .points
            .binary_search_by_key(&point.concurrency, |existing| existing.concurrency)
        {
            Ok(index) => {
                if self.points[index] == point {
                    return Ok(());
                }
                return Err(TelemetryError::Invalid(
                    "conflicting cost point for the same concurrency".into(),
                ));
            }
            Err(index) => {
                if self.points.len() >= self.max_points {
                    return Err(TelemetryError::Invalid(
                        "cost curve capacity exceeded".into(),
                    ));
                }
                self.points.insert(index, point);
            }
        }
        Ok(())
    }

    pub fn estimate(&self, concurrency: u32) -> Result<CostEstimate> {
        self.validate()?;
        if concurrency == 0 || concurrency > MAX_COST_CONCURRENCY || self.points.is_empty() {
            return Err(TelemetryError::Invalid(format!(
                "cost estimate concurrency must be between 1 and {MAX_COST_CONCURRENCY} and a point must exist"
            )));
        }
        let (left, right) = match self
            .points
            .binary_search_by_key(&concurrency, |point| point.concurrency)
        {
            Ok(index) => (&self.points[index], &self.points[index]),
            Err(0) => (&self.points[0], &self.points[0]),
            Err(index) if index == self.points.len() => {
                let last = self.points.len() - 1;
                (&self.points[last], &self.points[last])
            }
            Err(index) => (&self.points[index - 1], &self.points[index]),
        };
        let span = f64::from(right.concurrency.saturating_sub(left.concurrency));
        let fraction = if span == 0.0 {
            0.0
        } else {
            f64::from(concurrency.saturating_sub(left.concurrency)) / span
        };
        let interpolate = |a: f64, b: f64| a + (b - a) * fraction;
        let estimate = CostEstimate {
            concurrency,
            throughput: interpolate(left.throughput, right.throughput),
            latency_p99_ms: interpolate(left.latency_p99_ms, right.latency_p99_ms),
            cpu: interpolate(left.cpu, right.cpu),
            memory_bytes: interpolate(left.memory_bytes as f64, right.memory_bytes as f64),
            io_bytes: interpolate(left.io_bytes as f64, right.io_bytes as f64),
            unknown_rate: interpolate(left.unknown_rate, right.unknown_rate),
        };
        estimate.validate()?;
        Ok(estimate)
    }

    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| TelemetryError::Invalid(format!("encode cost curve: {error}")))?;
        Ok(hex(&Sha256::digest(bytes)))
    }
}

#[derive(Debug)]
struct CostCurveState {
    max_curves: usize,
    curves: BTreeMap<ModuleKey, CostCurve>,
}

/// Bounded storage for per-instance cost curves.  Replacing a curve for the
/// same identity is atomic; introducing a new identity beyond the configured
/// bound is rejected instead of evicting evidence silently.
#[derive(Debug, Clone)]
pub struct CostCurveStore {
    inner: Arc<Mutex<CostCurveState>>,
}

impl CostCurveStore {
    pub fn new(max_curves: usize) -> Result<Self> {
        if max_curves == 0 || max_curves > MAX_READ_MODEL_ENTRIES {
            return Err(TelemetryError::Invalid(format!(
                "cost curve store capacity must be between 1 and {MAX_READ_MODEL_ENTRIES}"
            )));
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(CostCurveState {
                max_curves,
                curves: BTreeMap::new(),
            })),
        })
    }

    pub fn max_curves(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.max_curves)
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.curves.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn upsert(&self, curve: CostCurve) -> Result<()> {
        curve.validate()?;
        let key = curve.key();
        let mut state = self
            .inner
            .lock()
            .map_err(|_| TelemetryError::Invalid("cost curve store lock poisoned".into()))?;
        if let Some(existing) = state.curves.get(&key) {
            if curve.observed_at_ms < existing.observed_at_ms {
                return Err(TelemetryError::Invalid(
                    "cost curve timestamp regressed".into(),
                ));
            }
            if curve.observed_at_ms == existing.observed_at_ms {
                if curve == *existing {
                    return Ok(());
                }
                return Err(TelemetryError::Invalid(
                    "cost curve timestamp collision".into(),
                ));
            }
        } else if state.curves.len() >= state.max_curves {
            return Err(TelemetryError::Invalid(
                "cost curve store capacity exceeded".into(),
            ));
        }
        state.curves.insert(key, curve);
        Ok(())
    }

    pub fn get(&self, key: &ModuleKey) -> Result<Option<CostCurve>> {
        key.validate()?;
        let state = self
            .inner
            .lock()
            .map_err(|_| TelemetryError::Invalid("cost curve store lock poisoned".into()))?;
        Ok(state.curves.get(key).cloned())
    }

    pub fn snapshot(&self) -> Result<Vec<CostCurve>> {
        let state = self
            .inner
            .lock()
            .map_err(|_| TelemetryError::Invalid("cost curve store lock poisoned".into()))?;
        Ok(state.curves.values().cloned().collect())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String formatting cannot fail");
    }
    output
}

fn is_source_digest(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: &str, repetition: u32, p99: f64) -> MetricSample {
        MetricSample {
            schema: METRIC_SAMPLE_SCHEMA.to_string(),
            workload_id: id.to_string(),
            repetition,
            throughput: 10.0,
            latency_p50: p99 / 2.0,
            latency_p95: p99,
            latency_p99: p99,
            latency_max: p99 + 1.0,
            queue_wait: 1.0,
            lock_wait: 0.1,
            lock_hold: 0.2,
            cpu: 2.0,
            rss: 100,
            fd_count: 3,
            thread_count: 4,
            process_count: 1,
            io_bytes: 20,
            fsync_count: 1,
            recovery_time: 0.0,
            unknown_rate: 0.0,
            redispatch_count: 0,
            fairness: 1.0,
        }
    }

    #[test]
    fn ring_is_bounded_and_reports_eviction() {
        let mut window = MetricWindow::new(2).unwrap();
        window.push(sample("WL-01", 0, 2.0)).unwrap();
        window.push(sample("WL-01", 1, 3.0)).unwrap();
        window.push(sample("WL-01", 2, 4.0)).unwrap();
        assert_eq!(window.len(), 2);
        assert_eq!(window.dropped(), 1);
        assert_eq!(window.samples().next().unwrap().repetition, 1);
    }

    #[test]
    fn ring_drop_bound_rejects_without_evicting() {
        let retained = sample("WL-01", 0, 2.0);
        let mut window = MetricWindow::new(1).unwrap();
        window.push(retained.clone()).unwrap();
        window.dropped = MAX_DROPPED_SAMPLES;

        assert!(matches!(
            window.push(sample("WL-01", 1, 3.0)),
            Err(TelemetryError::Invalid(message)) if message.contains("hard bound")
        ));
        assert_eq!(window.dropped(), MAX_DROPPED_SAMPLES);
        assert_eq!(
            window.samples().cloned().collect::<Vec<_>>(),
            vec![retained]
        );
    }

    #[test]
    fn ring_rejects_unbounded_capacity() {
        assert!(MetricWindow::new(0).is_err());
        assert!(MetricWindow::new(1).is_ok());
        assert!(MetricWindow::new(MAX_METRIC_WINDOW_CAPACITY + 1).is_err());
    }

    #[test]
    fn percentiles_are_deterministic_nearest_rank() {
        assert_eq!(percentile(&[4.0, 1.0, 3.0, 2.0], 0.5).unwrap(), 2.0);
        assert_eq!(percentile(&[4.0, 1.0, 3.0, 2.0], 0.99).unwrap(), 4.0);
    }

    #[test]
    fn report_requires_all_profiles_and_has_stable_digest() {
        let mut workloads = BTreeMap::new();
        for id in REQUIRED_WORKLOADS {
            let rows = vec![sample(id, 0, 2.0), sample(id, 1, 3.0)];
            workloads.insert(
                id.to_string(),
                WorkloadSummary::from_samples(id, &rows, 0).unwrap(),
            );
        }
        let env = EnvironmentIdentity {
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(64),
            toolchain: "rustc-test".into(),
            hardware: "host-test".into(),
            kernel: "kernel-test".into(),
            filesystem: "ext4".into(),
            durability_policy: "full".into(),
            module_versions: BTreeMap::new(),
            control_configuration: "observe".into(),
        };
        let report = BaselineReport::new(env, 2, workloads, ObjectiveWeights::default()).unwrap();
        report.validate().unwrap();
        assert_eq!(report.artifact_digest, report.compute_digest().unwrap());
        assert_eq!(report.workloads.len(), 12);

        let weighted = ObjectiveWeights {
            useful_work: 2.0,
            ..ObjectiveWeights::default()
        };
        let weighted_report = BaselineReport::new(
            report.environment.clone(),
            report.repetitions,
            report.workloads.clone(),
            weighted,
        )
        .unwrap();
        // The v1 shape does not carry the weight configuration.  The
        // compatibility validator must reject a non-default score, while the
        // explicit validator accepts it when the caller supplies the exact
        // versioned weights.
        assert!(weighted_report.validate().is_err());
        weighted_report.validate_with_weights(weighted).unwrap();
        let mut tampered = weighted_report;
        tampered.objective.score += 1.0;
        tampered.artifact_digest = tampered.compute_digest().unwrap();
        assert!(tampered.validate_with_weights(weighted).is_err());

        let mut default_tampered = report;
        default_tampered.objective.score += 1.0;
        default_tampered.artifact_digest = default_tampered.compute_digest().unwrap();
        assert!(default_tampered.validate().is_err());
    }

    #[test]
    fn semantic_fields_are_not_part_of_sample() {
        let bytes = serde_json::to_vec(&sample("WL-01", 0, 1.0)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(!text.contains("command"));
        assert!(!text.contains("intent"));
        assert!(!text.contains("prompt"));
    }

    #[test]
    fn malformed_latency_and_duplicate_repetitions_fail_closed() {
        let mut invalid = sample("WL-01", 0, 1.0);
        invalid.latency_p50 = 2.0;
        assert!(invalid.validate().is_err());

        let rows = vec![sample("WL-01", 0, 1.0), sample("WL-01", 0, 1.0)];
        assert!(WorkloadSummary::from_samples("WL-01", &rows, 0).is_err());

        // A complete (non-evicted) workload must account for exactly the
        // ordinal repetition set; a sparse set would hide a missing run.
        let sparse = vec![sample("WL-01", 0, 1.0), sample("WL-01", 2, 1.0)];
        assert!(WorkloadSummary::from_samples("WL-01", &sparse, 0).is_err());

        // Once rows have been evicted, retained repetition IDs still must fit
        // the accounted total and cannot be fabricated beyond it.
        let out_of_range = vec![sample("WL-01", 3, 1.0)];
        assert!(WorkloadSummary::from_samples("WL-01", &out_of_range, 2).is_err());
    }

    #[test]
    fn summary_aggregates_fail_closed_on_numeric_overflow() {
        let mut first = sample("WL-01", 0, 1.0);
        let mut second = sample("WL-01", 1, 1.0);
        first.redispatch_count = u64::MAX;
        second.redispatch_count = 1;
        assert!(matches!(
            WorkloadSummary::from_samples("WL-01", &[first.clone(), second.clone()], 0),
            Err(TelemetryError::Invalid(message)) if message.contains("redispatch")
        ));

        first.redispatch_count = 0;
        second.redispatch_count = 0;
        first.throughput = f64::MAX;
        second.throughput = f64::MAX;
        assert!(matches!(
            WorkloadSummary::from_samples("WL-01", &[first, second], 0),
            Err(TelemetryError::Invalid(message)) if message.contains("mean") || message.contains("sum")
        ));
    }

    #[test]
    fn telemetry_inputs_and_objective_outputs_are_hard_bounded() {
        let repeated = sample("WL-01", MAX_BASELINE_REPETITIONS, 1.0);
        assert!(repeated.validate().is_err());
        assert!(
            WorkloadSummary::from_samples(
                "WL-01",
                &[sample("WL-01", 0, 1.0)],
                MAX_DROPPED_SAMPLES + 1,
            )
            .is_err()
        );

        let percentile_input = vec![0.0; MAX_WORKLOAD_SAMPLES + 1];
        assert!(percentile(&percentile_input, 0.5).is_err());

        let summary =
            WorkloadSummary::from_samples("WL-01", &[sample("WL-01", 0, 1.0)], 0).unwrap();
        assert!(
            project_objective(
                std::iter::repeat_n(summary.clone(), MAX_OBJECTIVE_SUMMARIES + 1),
                ObjectiveWeights::default(),
            )
            .is_err()
        );

        let mut overflow_summary = summary;
        overflow_summary.throughput = f64::MAX;
        let overflow_weights = ObjectiveWeights {
            useful_work: f64::MAX,
            ..ObjectiveWeights::default()
        };
        assert!(project_objective([overflow_summary], overflow_weights).is_err());

        let mut environment = EnvironmentIdentity {
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(64),
            toolchain: "rustc-test".into(),
            hardware: "host-test".into(),
            kernel: "kernel-test".into(),
            filesystem: "ext4".into(),
            durability_policy: "full".into(),
            module_versions: BTreeMap::new(),
            control_configuration: "observe".into(),
        };
        for index in 0..=MAX_ENVIRONMENT_MODULE_VERSIONS {
            environment
                .module_versions
                .insert(format!("module-{index}"), "v1".into());
        }
        assert!(environment.validate().is_err());
        assert!(
            BaselineReport::new(
                EnvironmentIdentity {
                    module_versions: BTreeMap::new(),
                    ..environment
                },
                MAX_BASELINE_REPETITIONS + 1,
                BTreeMap::new(),
                ObjectiveWeights::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn summary_keeps_each_latency_series_distinct() {
        let mut first = sample("WL-01", 0, 10.0);
        first.latency_p50 = 1.0;
        first.latency_p95 = 5.0;
        first.latency_p99 = 10.0;
        first.latency_max = 12.0;
        let mut second = sample("WL-01", 1, 20.0);
        second.latency_p50 = 2.0;
        second.latency_p95 = 6.0;
        second.latency_p99 = 20.0;
        second.latency_max = 22.0;
        let summary = WorkloadSummary::from_samples("WL-01", &[first, second], 0).unwrap();
        assert_eq!(summary.latency_p50, 1.0);
        assert_eq!(summary.latency_p95, 6.0);
        assert_eq!(summary.latency_p99, 20.0);
    }

    #[test]
    fn report_rejects_incomplete_sample_accounting_and_tampered_projection() {
        let mut workloads = BTreeMap::new();
        for id in REQUIRED_WORKLOADS {
            let rows = vec![sample(id, 0, 2.0), sample(id, 1, 3.0)];
            workloads.insert(
                id.to_string(),
                WorkloadSummary::from_samples(id, &rows, 0).unwrap(),
            );
        }
        let env = EnvironmentIdentity {
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(64),
            toolchain: "rustc-test".into(),
            hardware: "host-test".into(),
            kernel: "kernel-test".into(),
            filesystem: "ext4".into(),
            durability_policy: "full".into(),
            module_versions: BTreeMap::new(),
            control_configuration: "observe".into(),
        };
        let mut report =
            BaselineReport::new(env, 2, workloads, ObjectiveWeights::default()).unwrap();
        report.objective.latency_penalty += 1.0;
        report.artifact_digest = report.compute_digest().unwrap();
        assert!(report.validate().is_err());

        let mut malformed = report;
        malformed.objective.latency_penalty -= 1.0;
        malformed.workloads.get_mut("WL-01").unwrap().sample_count = 1;
        malformed.artifact_digest = malformed.compute_digest().unwrap();
        assert!(malformed.validate().is_err());
    }

    #[test]
    fn environment_identity_requires_git_digest_shapes() {
        let mut identity = EnvironmentIdentity {
            source_commit: "a".repeat(40),
            source_tree: "b".repeat(64),
            toolchain: "rustc-test".into(),
            hardware: "host-test".into(),
            kernel: "kernel-test".into(),
            filesystem: "ext4".into(),
            durability_policy: "full".into(),
            module_versions: BTreeMap::from([(String::from("telemetry"), String::from("v1"))]),
            control_configuration: "observe".into(),
        };
        identity.validate().unwrap();
        identity.source_commit = "A".repeat(40);
        assert!(identity.validate().is_err());
        identity.source_commit = "a".repeat(39);
        assert!(identity.validate().is_err());
        identity.source_commit = "a".repeat(40);
        identity.module_versions.insert(" ".into(), "v1".into());
        assert!(identity.validate().is_err());
        identity.module_versions.clear();
        identity.toolchain = "x".repeat(MAX_ENVIRONMENT_FIELD_BYTES + 1);
        assert!(identity.validate().is_err());
    }

    fn module_sample(instance: &str, timestamp: u64, health: f64) -> ModuleTelemetrySample {
        ModuleTelemetrySample {
            schema: MODULE_SAMPLE_SCHEMA.to_string(),
            module_id: "broker".into(),
            module_instance_id: instance.into(),
            partition: "p0".into(),
            observed_at_ms: timestamp,
            queue_depth: 2,
            active_count: 1,
            cpu_millis: 3,
            memory_bytes: 4,
            io_bytes: 5,
            latency_p99_ms: 6.0,
            unknown_rate: 0.0,
            health_score: health,
        }
    }

    #[test]
    fn read_model_is_bounded_monotonic_and_idempotent() {
        let store = ModuleReadModelStore::new(1).unwrap();
        let first = module_sample("b-1", 10, 1.0);
        store.upsert(first.clone()).unwrap();
        store.upsert(first).unwrap();
        assert_eq!(store.len(), 1);
        let mut regressed = module_sample("b-1", 9, 1.0);
        assert!(store.upsert(regressed.clone()).is_err());
        regressed.observed_at_ms = 10;
        regressed.health_score = 0.5;
        assert!(store.upsert(regressed).is_err());
        assert!(store.upsert(module_sample("b-2", 11, 1.0)).is_err());
        let model = store
            .get(&ModuleKey {
                module_id: "broker".into(),
                module_instance_id: "b-1".into(),
                partition: "p0".into(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(model.sample_count, 1);
    }

    #[test]
    fn read_model_sample_count_is_hard_bounded_without_partial_update() {
        let store = ModuleReadModelStore::new(1).unwrap();
        let first = module_sample("b-1", 10, 1.0);
        store.upsert(first.clone()).unwrap();
        {
            let mut state = store.inner.lock().unwrap();
            state.models.get_mut(&first.key()).unwrap().sample_count =
                MAX_READ_MODEL_ENTRIES as u64;
        }
        let mut next = first;
        next.observed_at_ms = 11;
        assert!(store.upsert(next).is_err());
        assert_eq!(
            store.snapshot().unwrap()[0].sample_count,
            MAX_READ_MODEL_ENTRIES as u64
        );
        assert_eq!(store.snapshot().unwrap()[0].observed_at_ms, 10);
    }

    #[test]
    fn cost_curve_is_sorted_bounded_and_interpolates() {
        let mut curve = CostCurve::new("broker", "b-1", "p0", 2).unwrap();
        curve
            .push(CostPoint {
                concurrency: 1,
                throughput: 10.0,
                latency_p99_ms: 2.0,
                cpu: 1.0,
                memory_bytes: 100,
                io_bytes: 200,
                unknown_rate: 0.0,
            })
            .unwrap();
        curve
            .push(CostPoint {
                concurrency: 3,
                throughput: 30.0,
                latency_p99_ms: 6.0,
                cpu: 3.0,
                memory_bytes: 300,
                io_bytes: 400,
                unknown_rate: 0.2,
            })
            .unwrap();
        let estimate = curve.estimate(2).unwrap();
        assert_eq!(estimate.throughput, 20.0);
        assert_eq!(estimate.latency_p99_ms, 4.0);
        assert_eq!(estimate.memory_bytes, 200.0);
        assert_eq!(curve.points[0].concurrency, 1);
        assert!(
            curve
                .push(CostPoint {
                    concurrency: 5,
                    throughput: 50.0,
                    latency_p99_ms: 10.0,
                    cpu: 5.0,
                    memory_bytes: 500,
                    io_bytes: 600,
                    unknown_rate: 0.0,
                })
                .is_err()
        );
        assert_eq!(curve.digest().unwrap().len(), 64);
    }

    #[test]
    fn cost_curve_rejects_conflicting_duplicate_points() {
        let mut curve = CostCurve::new("broker", "b-1", "p0", 4).unwrap();
        let point = CostPoint {
            concurrency: 1,
            throughput: 1.0,
            latency_p99_ms: 1.0,
            cpu: 1.0,
            memory_bytes: 1,
            io_bytes: 1,
            unknown_rate: 0.0,
        };
        curve.push(point.clone()).unwrap();
        curve.push(point.clone()).unwrap();
        let mut conflict = point;
        conflict.throughput = 2.0;
        assert!(curve.push(conflict).is_err());
    }

    #[test]
    fn cost_points_and_estimates_reject_unbounded_values() {
        let mut point = CostPoint {
            concurrency: MAX_COST_CONCURRENCY + 1,
            throughput: 1.0,
            latency_p99_ms: 1.0,
            cpu: 1.0,
            memory_bytes: 1,
            io_bytes: 1,
            unknown_rate: 0.0,
        };
        assert!(point.validate().is_err());

        point.concurrency = 1;
        point.memory_bytes = MAX_COST_RESOURCE_BYTES + 1;
        assert!(point.validate().is_err());

        let mut curve = CostCurve::new("broker", "b-1", "p0", 1).unwrap();
        point.memory_bytes = 1;
        curve.push(point).unwrap();
        assert!(curve.estimate(MAX_COST_CONCURRENCY + 1).is_err());

        let estimate = CostEstimate {
            concurrency: 1,
            throughput: 1.0,
            latency_p99_ms: 1.0,
            cpu: 1.0,
            memory_bytes: MAX_COST_RESOURCE_BYTES as f64 + 1.0,
            io_bytes: 1.0,
            unknown_rate: 0.0,
        };
        assert!(estimate.validate().is_err());
    }

    #[test]
    fn cost_curve_store_replaces_by_identity_and_is_bounded() {
        let store = CostCurveStore::new(1).unwrap();
        let curve = CostCurve::new("broker", "b-1", "p0", 1).unwrap();
        store.upsert(curve.clone()).unwrap();
        store.upsert(curve).unwrap();
        assert_eq!(store.len(), 1);
        let other = CostCurve::new("broker", "b-2", "p0", 1).unwrap();
        assert!(store.upsert(other).is_err());
    }

    #[test]
    fn cost_curve_store_rejects_stale_and_conflicting_timestamps() {
        let store = CostCurveStore::new(1).unwrap();
        let base = CostCurve::new("broker", "b-1", "p0", 1)
            .unwrap()
            .with_observed_at_ms(10);
        store.upsert(base.clone()).unwrap();
        store.upsert(base.clone()).unwrap();

        let stale = CostCurve::new("broker", "b-1", "p0", 1)
            .unwrap()
            .with_observed_at_ms(9);
        assert!(matches!(
            store.upsert(stale),
            Err(TelemetryError::Invalid(message)) if message.contains("regressed")
        ));

        let mut collision = base.clone();
        collision.max_points = 2;
        assert!(matches!(
            store.upsert(collision),
            Err(TelemetryError::Invalid(message)) if message.contains("collision")
        ));

        let replacement = CostCurve::new("broker", "b-1", "p0", 2)
            .unwrap()
            .with_observed_at_ms(11);
        store.upsert(replacement.clone()).unwrap();
        assert_eq!(store.get(&replacement.key()).unwrap(), Some(replacement));
    }
}
