use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use thiserror::Error;

pub(crate) const DEFAULT_SHELL: &str = "/bin/sh";
pub(crate) const DEFAULT_ADB: &str = "adb";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("invalid owner-open process request: {0}")]
    InvalidRequest(String),
}

pub type Result<T> = std::result::Result<T, RuntimeError>;

/// Mechanical liveness bounds. None of these fields classifies the meaning of
/// a command or ADB subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MechanicalLimits {
    pub max_call_id_bytes: usize,
    pub max_target_id_bytes: usize,
    pub max_argv_items: usize,
    pub max_argument_bytes: usize,
    pub max_total_argument_bytes: usize,
    pub max_environment_items: usize,
    pub max_environment_bytes: usize,
    pub max_cwd_bytes: usize,
    pub max_stdin_bytes: usize,
    pub max_output_bytes: usize,
    pub stream_chunk_bytes: usize,
    pub reader_queue_depth: usize,
    pub default_timeout: Duration,
    pub poll_interval: Duration,
    pub terminate_grace: Duration,
}

impl Default for MechanicalLimits {
    fn default() -> Self {
        Self {
            max_call_id_bytes: 128,
            max_target_id_bytes: 256,
            max_argv_items: 4_096,
            max_argument_bytes: 64 * 1024,
            max_total_argument_bytes: 256 * 1024,
            max_environment_items: 4_096,
            max_environment_bytes: 512 * 1024,
            max_cwd_bytes: 16 * 1024,
            max_stdin_bytes: 16 * 1024 * 1024,
            max_output_bytes: 16 * 1024 * 1024,
            stream_chunk_bytes: 16 * 1024,
            reader_queue_depth: 32,
            default_timeout: Duration::from_secs(90),
            poll_interval: Duration::from_millis(10),
            terminate_grace: Duration::from_millis(250),
        }
    }
}

impl MechanicalLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_call_id_bytes == 0
            || self.max_target_id_bytes == 0
            || self.max_argv_items == 0
            || self.max_argument_bytes == 0
            || self.max_total_argument_bytes == 0
            || self.max_environment_items == 0
            || self.max_environment_bytes == 0
            || self.max_cwd_bytes == 0
            || self.max_stdin_bytes == 0
            || self.max_output_bytes == 0
            || self.stream_chunk_bytes == 0
            || self.reader_queue_depth == 0
            || self.default_timeout.is_zero()
            || self.poll_interval.is_zero()
            || self.terminate_grace.is_zero()
        {
            return Err(RuntimeError::InvalidRequest(
                "mechanical limits must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolKind {
    ShellExec,
    AdbExec,
}

impl ToolKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShellExec => "shell.exec",
            Self::AdbExec => "adb.exec",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellInvocation {
    Command(String),
    Argv(Vec<String>),
}

/// Environment delta: `Some(value)` sets/replaces a variable and `None`
/// removes it. An absent key is inherited only when it belongs to the finite
/// mechanical allowlist; arbitrary Host secrets are never inherited.
pub type EnvironmentDelta = BTreeMap<String, Option<String>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellExecRequest {
    pub call_id: String,
    pub target_id: Option<String>,
    pub invocation: ShellInvocation,
    pub shell_executable: PathBuf,
    pub cwd: Option<PathBuf>,
    pub env: EnvironmentDelta,
    pub stdin: Vec<u8>,
    pub timeout: Option<Duration>,
}

impl ShellExecRequest {
    #[must_use]
    pub fn command(call_id: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            call_id: call_id.into(),
            target_id: None,
            invocation: ShellInvocation::Command(command.into()),
            shell_executable: PathBuf::from(DEFAULT_SHELL),
            cwd: None,
            env: EnvironmentDelta::new(),
            stdin: Vec::new(),
            timeout: None,
        }
    }

    #[must_use]
    pub fn argv(call_id: impl Into<String>, argv: Vec<String>) -> Self {
        Self {
            call_id: call_id.into(),
            target_id: None,
            invocation: ShellInvocation::Argv(argv),
            shell_executable: PathBuf::from(DEFAULT_SHELL),
            cwd: None,
            env: EnvironmentDelta::new(),
            stdin: Vec::new(),
            timeout: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbExecRequest {
    pub call_id: String,
    pub target_id: Option<String>,
    /// Exact adb argv excluding the program name. Unknown and future
    /// subcommands remain valid.
    pub argv: Vec<String>,
    pub adb_executable: PathBuf,
    pub cwd: Option<PathBuf>,
    pub env: EnvironmentDelta,
    pub stdin: Vec<u8>,
    pub timeout: Option<Duration>,
}

impl AdbExecRequest {
    #[must_use]
    pub fn new(call_id: impl Into<String>, argv: Vec<String>) -> Self {
        Self {
            call_id: call_id.into(),
            target_id: None,
            argv,
            adb_executable: PathBuf::from(DEFAULT_ADB),
            cwd: None,
            env: EnvironmentDelta::new(),
            stdin: Vec::new(),
            timeout: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalKind {
    Exited,
    Signaled,
    TimedOut,
    Cancelled,
    OutputLimitExceeded,
    SpawnFailed,
    IoError,
}

impl TerminalKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::Signaled => "signaled",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "client_cancelled",
            Self::OutputLimitExceeded => "resource_exhausted",
            Self::SpawnFailed => "spawn_failed",
            Self::IoError => "io_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionTerminal {
    pub kind: TerminalKind,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub output_truncated: bool,
    pub elapsed_ms: u64,
    pub error: Option<String>,
}

impl ExecutionTerminal {
    #[must_use]
    pub fn success(&self) -> bool {
        self.kind == TerminalKind::Exited && self.exit_code == Some(0) && self.error.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionEventKind {
    Accepted,
    Started { pid: u32 },
    Output { stream: StreamKind, bytes: Vec<u8> },
    Terminal(ExecutionTerminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionEvent {
    pub call_id: String,
    pub target_id: Option<String>,
    pub tool: ToolKind,
    pub seq: u64,
    pub elapsed_ms: u64,
    pub kind: ExecutionEventKind,
}

#[derive(Debug)]
pub(crate) struct ProcessSpec {
    pub call_id: String,
    pub target_id: Option<String>,
    pub tool: ToolKind,
    pub program: OsString,
    pub args: Vec<OsString>,
    pub cwd: Option<PathBuf>,
    pub env: EnvironmentDelta,
    pub stdin: Vec<u8>,
    pub timeout: Duration,
}
