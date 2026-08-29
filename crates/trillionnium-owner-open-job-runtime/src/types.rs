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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRuntimeConfig {
    pub max_jobs: usize,
    pub max_operation_id_bytes: usize,
    pub max_input_bytes: usize,
    pub max_output_chunk_bytes: usize,
    pub max_observations_per_job: usize,
    pub max_observation_bytes_per_job: usize,
    pub allow_unjournaled_effects: bool,
}

impl Default for JobRuntimeConfig {
    fn default() -> Self {
        Self {
            max_jobs: 256,
            max_operation_id_bytes: 256,
            max_input_bytes: 1024 * 1024,
            max_output_chunk_bytes: 64 * 1024,
            max_observations_per_job: 4096,
            max_observation_bytes_per_job: 16 * 1024 * 1024,
            allow_unjournaled_effects: true,
        }
    }
}

impl JobRuntimeConfig {
    pub fn validate(&self) -> Result<()> {
        if self.max_jobs == 0
            || self.max_operation_id_bytes == 0
            || self.max_input_bytes == 0
            || self.max_output_chunk_bytes == 0
            || self.max_observations_per_job == 0
            || self.max_observation_bytes_per_job == 0
            || self.max_output_chunk_bytes > self.max_observation_bytes_per_job
        {
            return Err(JobRuntimeError::InvalidRequest(
                "job runtime bounds are inconsistent".to_string(),
            ));
        }
        Ok(())
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
    JournalUnavailable {
        error: Option<String>,
    },
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
    pub oldest_available_cursor: u64,
    pub next_cursor: u64,
    pub total_events: u64,
    pub has_more: bool,
    pub resync_required: bool,
    pub gap: Option<JobObservationGap>,
    pub durable_fallback_available: bool,
    pub replay_status: ReplayStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InternalProcessEvent {
    Output {
        stream: String,
        bytes: Vec<u8>,
    },
    Exited {
        terminal_kind: String,
        exit_code: Option<i32>,
        signal: Option<i32>,
    },
    ReaderFailed {
        stream: String,
        error: String,
    },
}
