use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JobRegistryError {
    #[error("invalid owner-open job request: {0}")]
    InvalidRequest(String),
    #[error("owner-open job is not registered")]
    NotFound,
    #[error("owner-open job_id is already bound to different request bytes")]
    JobIdConflict,
    #[error("owner-open job request digest does not match")]
    RequestDigestMismatch,
    #[error("invalid owner-open job transition: {0}")]
    InvalidTransition(&'static str),
    #[error("owner-open job spawn generation does not match")]
    SpawnGenerationMismatch,
    #[error("owner-open job process identity conflicts")]
    PidConflict,
    #[error("owner-open job terminal observation conflicts")]
    TerminalConflict,
    #[error("owner-open job registry capacity is exhausted")]
    CapacityExhausted,
    #[error("owner-open job spawn generation is exhausted")]
    GenerationExhausted,
    #[error("owner-open job registry lock is poisoned")]
    StatePoisoned,
}

pub type Result<T> = std::result::Result<T, JobRegistryError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRegistryLimits {
    pub max_entries: usize,
    pub max_history_per_job: usize,
    pub max_attachments_per_job: usize,
    pub max_id_bytes: usize,
    pub max_tool_bytes: usize,
    pub max_target_bytes: usize,
}

impl Default for JobRegistryLimits {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_history_per_job: 512,
            max_attachments_per_job: 32,
            max_id_bytes: 256,
            max_tool_bytes: 256,
            max_target_bytes: 4096,
        }
    }
}

impl JobRegistryLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_entries == 0
            || self.max_history_per_job == 0
            || self.max_attachments_per_job == 0
            || self.max_id_bytes == 0
            || self.max_tool_bytes == 0
            || self.max_target_bytes == 0
        {
            return Err(JobRegistryError::InvalidRequest(
                "job registry limits must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobScope {
    pub session_id: String,
    pub profile_id: String,
    pub task_id: String,
    pub turn_id: String,
    pub turn_stream_id: String,
}

impl JobScope {
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        profile_id: impl Into<String>,
        task_id: impl Into<String>,
        turn_id: impl Into<String>,
        turn_stream_id: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            profile_id: profile_id.into(),
            task_id: task_id.into(),
            turn_id: turn_id.into(),
            turn_stream_id: turn_stream_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobKey {
    pub scope: JobScope,
    pub job_id: String,
}

impl JobKey {
    #[must_use]
    pub fn new(scope: JobScope, job_id: impl Into<String>) -> Self {
        Self {
            scope,
            job_id: job_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub request_sha256: String,
    pub binding_fingerprint: String,
    pub tool: String,
    pub mode: String,
    pub target_id: Option<String>,
}

impl JobRequest {
    #[must_use]
    pub fn new(
        request_sha256: impl Into<String>,
        binding_fingerprint: impl Into<String>,
        tool: impl Into<String>,
        mode: impl Into<String>,
        target_id: Option<String>,
    ) -> Self {
        Self {
            request_sha256: request_sha256.into(),
            binding_fingerprint: binding_fingerprint.into(),
            tool: tool.into(),
            mode: mode.into(),
            target_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobTerminal {
    pub terminal_kind: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub observation_sha256: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobEffectiveState {
    Accepted,
    Starting {
        generation: u64,
    },
    Running {
        generation: u64,
        pid: u32,
        pty: bool,
    },
    ProvenNotStartedAfterRestart,
    UnknownAfterRestart {
        generation: u64,
        pid: Option<u32>,
        pty: Option<bool>,
    },
    Terminal {
        generation: u64,
        terminal: JobTerminal,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobEventKind {
    Accepted,
    SpawnClaimed {
        generation: u64,
    },
    Started {
        generation: u64,
        pid: u32,
        pty: bool,
    },
    OutputObserved {
        generation: u64,
        output_seq: u64,
        stream: String,
        bytes: u64,
        sha256: String,
    },
    InputWritten {
        bytes: u64,
        sha256: String,
    },
    Resized {
        rows: u16,
        cols: u16,
    },
    StdinClosed,
    KillRequested {
        signal: i32,
    },
    Attached {
        attachment_id: String,
    },
    Detached {
        attachment_id: String,
    },
    RestartObserved,
    TerminalRecorded {
        generation: u64,
        terminal: JobTerminal,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobEvent {
    pub seq: u64,
    pub event: JobEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSnapshot {
    pub key: JobKey,
    pub request: JobRequest,
    pub state: JobEffectiveState,
    pub stdin_closed: bool,
    pub kill_requested: bool,
    pub attachments: Vec<String>,
    pub next_output_seq: u64,
    pub earliest_history_seq: u64,
    pub next_event_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginDisposition {
    New,
    Existing,
}

#[derive(Debug, Clone)]
pub struct BeginResult {
    pub disposition: BeginDisposition,
    pub snapshot: JobSnapshot,
}

#[derive(Debug, Clone)]
pub enum SpawnClaim {
    Granted {
        generation: u64,
        snapshot: JobSnapshot,
    },
    Existing(JobSnapshot),
    Inhibited(JobSnapshot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOutcome {
    Applied,
    Idempotent,
}
