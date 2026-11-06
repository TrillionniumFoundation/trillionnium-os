use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use trillionnium_owner_open_job_registry::{JobEvent, JobKey, JobRequest, JobSnapshot};

#[derive(Debug, Error)]
pub enum JobRuntimeError {
    #[error("invalid owner-open job runtime request: {0}")]
    InvalidRequest(String),
    #[error("owner-open job is not registered")]
    NotFound,
    #[error("owner-open job is not live")]
    NotLive,
    #[error("owner-open job request conflicts with durable state")]
    JobConflict,
    #[error("owner-open job operation is uncertain after restart")]
    UnknownAfterRestart,
    #[error("owner-open job process spawn failed: {0}")]
    Spawn(String),
    #[error("owner-open job process setup failed after child spawn: {0}")]
    SpawnAfterFork(String),
    #[error("owner-open job process I/O failed: {0}")]
    Io(String),
    #[error("owner-open job process control failed: {0}")]
    Control(String),
    #[error("owner-open job registry failed: {0}")]
    Registry(String),
    #[error("owner-open job journal failed: {0}")]
    Journal(String),
    #[error("owner-open job runtime state lock is poisoned")]
    StatePoisoned,
}

pub type Result<T> = std::result::Result<T, JobRuntimeError>;

/// Hard mechanical ceilings for one owner-open job runtime.
///
/// Deployments may choose lower values, but accepting an arbitrary
/// `usize` from configuration would let a malformed profile turn admission,
/// input, or resident observation state into an effectively unbounded
/// allocation. Count, buffer and resident-window budgets apply together;
/// they are not claims about the host's measured available capacity.
pub const MAX_JOB_RUNTIME_JOBS: usize = 8;
pub const MAX_JOB_RUNTIME_OPERATION_ID_BYTES: usize = 4_096;
pub const MAX_JOB_RUNTIME_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_JOB_RUNTIME_OUTPUT_CHUNK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_JOB_RUNTIME_OBSERVATIONS_PER_JOB: usize = 1_048_576;
pub const MAX_JOB_RUNTIME_OBSERVATION_BYTES_PER_JOB: usize = 1 << 30;
/// Aggregate resident window and raw process-buffer ceilings, independent of
/// the per-job limits. These do not describe the event store or whole RSS.
pub const MAX_JOB_RUNTIME_OBSERVATION_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_JOB_RUNTIME_OBSERVATIONS: usize = 4096;
pub const MAX_JOB_RUNTIME_PROCESS_BUFFER_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_JOB_RUNTIME_RETAINED_KEYS: usize = 256;
pub const MAX_JOB_RUNTIME_REGISTRY_EVENTS_PER_JOB: usize = 16;
pub(crate) const MAX_OBSERVATION_STAGING_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const OBSERVATION_STAGING_FIXED_BYTES: usize = 1024 * 1024;
pub(crate) const OUTPUT_VALUE_STAGING_PER_BYTE: usize = 224;
// Covers 256 bounded keys, hash buckets and cursor/gap state even when their
// event prefixes have been evicted. Registry identity is never budget-evicted.
pub(crate) const OBSERVATION_METADATA_RESERVE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRuntimeConfig {
    pub max_jobs: usize,
    pub max_operation_id_bytes: usize,
    pub max_input_bytes: usize,
    pub max_output_chunk_bytes: usize,
    pub max_observations_per_job: usize,
    pub max_observation_bytes_per_job: usize,
    pub max_observations: usize,
    pub max_observation_bytes: usize,
    pub allow_unjournaled_effects: bool,
}

impl Default for JobRuntimeConfig {
    fn default() -> Self {
        Self {
            max_jobs: 8,
            max_operation_id_bytes: 256,
            max_input_bytes: 1024 * 1024,
            max_output_chunk_bytes: 64 * 1024,
            max_observations_per_job: 4096,
            max_observation_bytes_per_job: 16 * 1024 * 1024,
            max_observations: MAX_JOB_RUNTIME_OBSERVATIONS,
            max_observation_bytes: MAX_JOB_RUNTIME_OBSERVATION_BYTES,
            allow_unjournaled_effects: false,
        }
    }
}

impl JobRuntimeConfig {
    /// Explicit development-only fail-open configuration. Production callers
    /// must use the fail-closed default and provide a durable journal.
    #[must_use]
    pub fn development_unsafe() -> Self {
        Self {
            allow_unjournaled_effects: true,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<()> {
        for (name, value, maximum) in [
            ("max_jobs", self.max_jobs, MAX_JOB_RUNTIME_JOBS),
            (
                "max_operation_id_bytes",
                self.max_operation_id_bytes,
                MAX_JOB_RUNTIME_OPERATION_ID_BYTES,
            ),
            (
                "max_input_bytes",
                self.max_input_bytes,
                MAX_JOB_RUNTIME_INPUT_BYTES,
            ),
            (
                "max_output_chunk_bytes",
                self.max_output_chunk_bytes,
                MAX_JOB_RUNTIME_OUTPUT_CHUNK_BYTES,
            ),
            (
                "max_observations_per_job",
                self.max_observations_per_job,
                MAX_JOB_RUNTIME_OBSERVATIONS_PER_JOB,
            ),
            (
                "max_observation_bytes_per_job",
                self.max_observation_bytes_per_job,
                MAX_JOB_RUNTIME_OBSERVATION_BYTES_PER_JOB,
            ),
            (
                "max_observations",
                self.max_observations,
                MAX_JOB_RUNTIME_OBSERVATIONS,
            ),
            (
                "max_observation_bytes",
                self.max_observation_bytes,
                MAX_JOB_RUNTIME_OBSERVATION_BYTES,
            ),
        ] {
            if value > maximum {
                return Err(JobRuntimeError::InvalidRequest(format!(
                    "{name} exceeds hard bound {maximum}"
                )));
            }
        }
        if self.max_jobs == 0
            || self.max_operation_id_bytes == 0
            || self.max_input_bytes == 0
            || self.max_output_chunk_bytes == 0
            || self.max_observations_per_job == 0
            || self.max_observation_bytes_per_job == 0
            || self.max_observations == 0
            || self.max_observation_bytes <= OBSERVATION_METADATA_RESERVE
            || self.max_output_chunk_bytes > self.max_observation_bytes_per_job
        {
            return Err(JobRuntimeError::InvalidRequest(
                "job runtime bounds are inconsistent".to_string(),
            ));
        }
        // The stdin request is cloned into its worker. Two reader workspaces,
        // two blocked sends and dispatcher/event staging can coexist with a
        // full channel. Arc process handles share allocations rather than
        // multiplying this reservation. Use checked arithmetic before any
        // durable acceptance, allocation or spawn.
        let buffers = self
            .max_output_chunk_bytes
            .checked_mul(crate::process::PROCESS_EVENT_QUEUE + 6)
            .and_then(|output| self.max_input_bytes.checked_mul(2)?.checked_add(output))
            .and_then(|per_job| per_job.checked_mul(self.max_jobs));
        if buffers.is_none_or(|bytes| bytes > MAX_JOB_RUNTIME_PROCESS_BUFFER_BYTES) {
            return Err(JobRuntimeError::InvalidRequest(
                "aggregate process buffers exceed the runtime budget".to_string(),
            ));
        }
        // Runtime output is carried as a numeric Value array. Bound the
        // existing schema's DOM/clone/encoder staging as well as raw buffers;
        // its shared serialization lane is reserved before the first DOM.
        if self
            .max_output_chunk_bytes
            .checked_mul(OUTPUT_VALUE_STAGING_PER_BYTE)
            .and_then(|bytes| bytes.checked_add(OBSERVATION_STAGING_FIXED_BYTES))
            .is_none_or(|bytes| bytes > MAX_OBSERVATION_STAGING_BYTES)
        {
            return Err(JobRuntimeError::InvalidRequest(
                "observation Value staging exceeds the runtime budget".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runtime_bounds_validate() {
        JobRuntimeConfig::default()
            .validate()
            .expect("default runtime bounds are valid");
    }

    #[test]
    fn default_process_buffers_fit_the_aggregate_source_budget() {
        let config = JobRuntimeConfig::default();
        // One bounded queue and two reader work buffers, plus initial stdin.
        let resident = config.max_jobs
            * (2 * config.max_input_bytes
                + (crate::process::PROCESS_EVENT_QUEUE + 6) * config.max_output_chunk_bytes);
        assert!(resident <= 32 * 1024 * 1024, "process buffers: {resident}");
    }

    #[test]
    fn oversized_runtime_bounds_fail_closed() {
        macro_rules! assert_oversized {
            ($name:literal, $field:ident, $maximum:ident) => {{
                let mut config = JobRuntimeConfig::default();
                config.$field = $maximum + 1;
                let error = config
                    .validate()
                    .expect_err("oversized bound must be rejected");
                assert!(
                    error.to_string().contains($name),
                    "unexpected error: {error}"
                );
            }};
        }
        assert_oversized!("max_jobs", max_jobs, MAX_JOB_RUNTIME_JOBS);
        assert_oversized!(
            "max_operation_id_bytes",
            max_operation_id_bytes,
            MAX_JOB_RUNTIME_OPERATION_ID_BYTES
        );
        assert_oversized!(
            "max_input_bytes",
            max_input_bytes,
            MAX_JOB_RUNTIME_INPUT_BYTES
        );
        assert_oversized!(
            "max_output_chunk_bytes",
            max_output_chunk_bytes,
            MAX_JOB_RUNTIME_OUTPUT_CHUNK_BYTES
        );
        assert_oversized!(
            "max_observations_per_job",
            max_observations_per_job,
            MAX_JOB_RUNTIME_OBSERVATIONS_PER_JOB
        );
        assert_oversized!(
            "max_observation_bytes_per_job",
            max_observation_bytes_per_job,
            MAX_JOB_RUNTIME_OBSERVATION_BYTES_PER_JOB
        );
        assert_oversized!(
            "max_observations",
            max_observations,
            MAX_JOB_RUNTIME_OBSERVATIONS
        );
        assert_oversized!(
            "max_observation_bytes",
            max_observation_bytes,
            MAX_JOB_RUNTIME_OBSERVATION_BYTES
        );
    }

    #[test]
    fn aggregate_process_reservation_rejects_a_single_oversized_input_profile() {
        let config = JobRuntimeConfig {
            max_jobs: 2,
            max_input_bytes: 16 * 1024 * 1024,
            ..JobRuntimeConfig::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("aggregate process buffers")
        );
    }

    #[test]
    fn numeric_output_dom_staging_rejects_a_profile_before_journal_or_spawn() {
        let config = JobRuntimeConfig {
            max_jobs: 1,
            max_output_chunk_bytes: 128 * 1024,
            ..JobRuntimeConfig::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("Value staging")
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobInvocation {
    Command { command: String },
    Argv { argv: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
}

impl Default for PtySize {
    fn default() -> Self {
        Self { rows: 24, cols: 80 }
    }
}

#[derive(Debug, Clone)]
pub struct JobStartRequest {
    pub key: JobKey,
    pub request: JobRequest,
    pub operation_id: String,
    pub invocation: JobInvocation,
    pub shell_executable: PathBuf,
    pub cwd: Option<PathBuf>,
    pub env: BTreeMap<String, Option<String>>,
    pub initial_stdin: Vec<u8>,
    pub pty: Option<PtySize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    Durable,
    BestEffortUnreplayable,
    UnknownAfterRestart,
}

/// Persistence health advertised alongside read-only job inspection.
///
/// `Unavailable` is deliberately a degraded state, not an authorization
/// grant: effectful operations remain inhibited unless the caller explicitly
/// selected the development-only unjournaled mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum EventLogStatus {
    Durable,
    BestEffortUnreplayable,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartDisposition {
    Started,
    ExistingLive,
    ExistingTerminal,
    UnknownAfterRestart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStartResult {
    pub disposition: StartDisposition,
    pub snapshot: Option<JobSnapshot>,
    pub replay_status: ReplayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlDisposition {
    Applied,
    Existing,
    UnknownAfterRestart,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuntimeJobEventKind {
    /// The kernel identity tuple was captured and bound to this start
    /// generation before the job became available for live controls.
    ///
    /// `boot_id` carries the canonical SHA-256 of the kernel boot identity;
    /// it is intentionally a digest rather than the raw host identifier.
    ProcessIdentityBound {
        generation: u64,
        identity: ProcessIdentity,
    },
    Started {
        generation: u64,
        pid: u32,
        pty: bool,
    },
    Output {
        generation: u64,
        output_seq: u64,
        stream: String,
        bytes: Vec<u8>,
        sha256: String,
    },
    Terminal {
        generation: u64,
        terminal_kind: String,
        exit_code: Option<i32>,
        signal: Option<i32>,
        observation_sha256: String,
        stdout_bytes: u64,
        stderr_bytes: u64,
    },
    ProcessFault {
        phase: String,
        error: String,
    },
    JournalUnavailable {
        error: Option<String>,
    },
}

/// Kernel-observed process identity exposed in the runtime observation stream.
///
/// The tuple distinguishes a live child from a later process that happens to
/// reuse its numeric PID or process-group ID.  `boot_id` is the SHA-256 digest
/// of `/proc/sys/kernel/random/boot_id`, never the raw host value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub process_group_id: i32,
    pub session_id: i32,
    pub boot_id: String,
    pub start_time_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeJobEvent {
    pub seq: u64,
    pub job_id: String,
    pub event: RuntimeJobEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobObservationGap {
    pub first_missing_cursor: u64,
    pub last_missing_cursor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobInspection {
    pub snapshot: Option<JobSnapshot>,
    pub registry_events: Vec<JobEvent>,
    pub runtime_events: Vec<RuntimeJobEvent>,
    pub inclusive_cursor: u64,
    #[serde(default)]
    pub oldest_available_cursor: u64,
    pub next_cursor: u64,
    #[serde(default)]
    pub total_events: u64,
    pub has_more: bool,
    #[serde(default)]
    pub resync_required: bool,
    #[serde(default)]
    pub gap: Option<JobObservationGap>,
    #[serde(default)]
    pub durable_fallback_available: bool,
    #[serde(default)]
    pub event_log_status: EventLogStatus,
    #[serde(default)]
    pub journal_error: Option<String>,
    pub replay_status: ReplayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InternalProcessEvent {
    Output {
        stream: String,
        bytes: Vec<u8>,
    },
    InputFailed {
        error: String,
    },
    Exited {
        terminal_kind: String,
        exit_code: Option<i32>,
        signal: Option<i32>,
        cleanup_error: Option<String>,
    },
    ReaderFailed {
        stream: String,
        error: String,
    },
}
