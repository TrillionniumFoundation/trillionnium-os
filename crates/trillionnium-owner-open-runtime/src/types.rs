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
///
/// The schema ceilings below are intentionally independent of the defaults.
/// A deployment may lower a limit for its available capacity, but a caller
/// cannot use a configuration object to turn a bounded reader/channel or a
/// finite timeout into an effectively unbounded allocation or wait.
pub const MAX_RUNTIME_CALL_ID_BYTES: usize = 4 * 1024;
pub const MAX_RUNTIME_TARGET_ID_BYTES: usize = 1024 * 1024;
pub const MAX_RUNTIME_ARGV_ITEMS: usize = 65_536;
pub const MAX_RUNTIME_ARGUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_RUNTIME_TOTAL_ARGUMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RUNTIME_ENVIRONMENT_ITEMS: usize = 65_536;
pub const MAX_RUNTIME_ENVIRONMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RUNTIME_CWD_BYTES: usize = 1024 * 1024;
pub const MAX_RUNTIME_STDIN_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_RUNTIME_OUTPUT_BYTES: usize = 1024 * 1024 * 1024;
pub const MAX_RUNTIME_STREAM_CHUNK_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RUNTIME_READER_QUEUE_DEPTH: usize = 65_536;
/// The queue is bounded by the product of its depth and one reader chunk.
/// There are two readers in pipe mode, so this still leaves a finite, explicit
/// two-stream resident-memory ceiling rather than relying on allocator luck.
pub const MAX_RUNTIME_READER_BUFFER_BYTES: usize = 1024 * 1024 * 1024;
pub const MAX_RUNTIME_DEFAULT_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// Ceiling for a caller-selected non-zero timeout. This remains separate from
/// the owner's default so changing a profile default cannot widen request
/// liveness implicitly.
pub const MAX_RUNTIME_REQUEST_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_RUNTIME_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub const MAX_RUNTIME_TERMINATE_GRACE: Duration = Duration::from_secs(60);

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

        for (name, value, maximum) in [
            (
                "max_call_id_bytes",
                self.max_call_id_bytes,
                MAX_RUNTIME_CALL_ID_BYTES,
            ),
            (
                "max_target_id_bytes",
                self.max_target_id_bytes,
                MAX_RUNTIME_TARGET_ID_BYTES,
            ),
            (
                "max_argv_items",
                self.max_argv_items,
                MAX_RUNTIME_ARGV_ITEMS,
            ),
            (
                "max_argument_bytes",
                self.max_argument_bytes,
                MAX_RUNTIME_ARGUMENT_BYTES,
            ),
            (
                "max_total_argument_bytes",
                self.max_total_argument_bytes,
                MAX_RUNTIME_TOTAL_ARGUMENT_BYTES,
            ),
            (
                "max_environment_items",
                self.max_environment_items,
                MAX_RUNTIME_ENVIRONMENT_ITEMS,
            ),
            (
                "max_environment_bytes",
                self.max_environment_bytes,
                MAX_RUNTIME_ENVIRONMENT_BYTES,
            ),
            ("max_cwd_bytes", self.max_cwd_bytes, MAX_RUNTIME_CWD_BYTES),
            (
                "max_stdin_bytes",
                self.max_stdin_bytes,
                MAX_RUNTIME_STDIN_BYTES,
            ),
            (
                "max_output_bytes",
                self.max_output_bytes,
                MAX_RUNTIME_OUTPUT_BYTES,
            ),
            (
                "stream_chunk_bytes",
                self.stream_chunk_bytes,
                MAX_RUNTIME_STREAM_CHUNK_BYTES,
            ),
            (
                "reader_queue_depth",
                self.reader_queue_depth,
                MAX_RUNTIME_READER_QUEUE_DEPTH,
            ),
        ] {
            if value > maximum {
                return Err(RuntimeError::InvalidRequest(format!(
                    "{name} exceeds hard bound {maximum}"
                )));
            }
        }

        for (name, value, maximum) in [
            (
                "default_timeout",
                self.default_timeout,
                MAX_RUNTIME_DEFAULT_TIMEOUT,
            ),
            (
                "poll_interval",
                self.poll_interval,
                MAX_RUNTIME_POLL_INTERVAL,
            ),
            (
                "terminate_grace",
                self.terminate_grace,
                MAX_RUNTIME_TERMINATE_GRACE,
            ),
        ] {
            if value > maximum {
                return Err(RuntimeError::InvalidRequest(format!(
                    "{name} exceeds hard bound {maximum:?}"
                )));
            }
        }

        if self.max_argument_bytes > self.max_total_argument_bytes {
            return Err(RuntimeError::InvalidRequest(
                "max_argument_bytes cannot exceed max_total_argument_bytes".to_string(),
            ));
        }
        if self.stream_chunk_bytes > self.max_output_bytes {
            return Err(RuntimeError::InvalidRequest(
                "stream_chunk_bytes cannot exceed max_output_bytes".to_string(),
            ));
        }
        let reader_buffer_bytes = self
            .stream_chunk_bytes
            .checked_mul(self.reader_queue_depth)
            .ok_or_else(|| {
                RuntimeError::InvalidRequest(
                    "stream_chunk_bytes and reader_queue_depth overflow the reader buffer bound"
                        .to_string(),
                )
            })?;
        if reader_buffer_bytes > MAX_RUNTIME_READER_BUFFER_BYTES {
            return Err(RuntimeError::InvalidRequest(format!(
                "stream_chunk_bytes * reader_queue_depth exceeds hard bound {MAX_RUNTIME_READER_BUFFER_BYTES}"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod mechanical_limit_tests {
    use super::*;

    #[test]
    fn default_mechanical_limits_validate() {
        MechanicalLimits::default()
            .validate()
            .expect("default mechanical limits are valid");
    }

    #[test]
    fn usize_schema_ceilings_are_enforced() {
        macro_rules! assert_oversized {
            ($field:ident, $maximum:ident) => {{
                let mut limits = MechanicalLimits::default();
                limits.$field = $maximum + 1;
                let error = limits
                    .validate()
                    .expect_err("oversized mechanical limit must fail closed");
                assert!(
                    error.to_string().contains(stringify!($field)),
                    "unexpected error for {}: {error}",
                    stringify!($field)
                );
            }};
        }

        assert_oversized!(max_call_id_bytes, MAX_RUNTIME_CALL_ID_BYTES);
        assert_oversized!(max_target_id_bytes, MAX_RUNTIME_TARGET_ID_BYTES);
        assert_oversized!(max_argv_items, MAX_RUNTIME_ARGV_ITEMS);
        assert_oversized!(max_argument_bytes, MAX_RUNTIME_ARGUMENT_BYTES);
        assert_oversized!(max_total_argument_bytes, MAX_RUNTIME_TOTAL_ARGUMENT_BYTES);
        assert_oversized!(max_environment_items, MAX_RUNTIME_ENVIRONMENT_ITEMS);
        assert_oversized!(max_environment_bytes, MAX_RUNTIME_ENVIRONMENT_BYTES);
        assert_oversized!(max_cwd_bytes, MAX_RUNTIME_CWD_BYTES);
        assert_oversized!(max_stdin_bytes, MAX_RUNTIME_STDIN_BYTES);
        assert_oversized!(max_output_bytes, MAX_RUNTIME_OUTPUT_BYTES);
        assert_oversized!(stream_chunk_bytes, MAX_RUNTIME_STREAM_CHUNK_BYTES);
        assert_oversized!(reader_queue_depth, MAX_RUNTIME_READER_QUEUE_DEPTH);
    }

    #[test]
    fn duration_schema_ceilings_are_enforced() {
        macro_rules! assert_oversized {
            ($field:ident, $maximum:ident) => {{
                let mut limits = MechanicalLimits::default();
                limits.$field = $maximum + Duration::from_nanos(1);
                let error = limits
                    .validate()
                    .expect_err("oversized duration must fail closed");
                assert!(
                    error.to_string().contains(stringify!($field)),
                    "unexpected error for {}: {error}",
                    stringify!($field)
                );
            }};
        }

        assert_oversized!(default_timeout, MAX_RUNTIME_DEFAULT_TIMEOUT);
        assert_oversized!(poll_interval, MAX_RUNTIME_POLL_INTERVAL);
        assert_oversized!(terminate_grace, MAX_RUNTIME_TERMINATE_GRACE);
    }

    #[test]
    fn derived_reader_and_argument_bounds_are_enforced() {
        let mut limits = MechanicalLimits::default();
        limits.max_argument_bytes = limits.max_total_argument_bytes + 1;
        let error = limits
            .validate()
            .expect_err("argument relationship must fail");
        assert!(error.to_string().contains("max_argument_bytes"));

        let limits = MechanicalLimits {
            max_output_bytes: 512 * 1024,
            stream_chunk_bytes: 1024 * 1024,
            ..MechanicalLimits::default()
        };
        let error = limits
            .validate()
            .expect_err("output relationship must fail");
        assert!(error.to_string().contains("stream_chunk_bytes"));

        let stream_chunk_bytes = MAX_RUNTIME_STREAM_CHUNK_BYTES;
        let reader_queue_depth = MAX_RUNTIME_READER_BUFFER_BYTES
            .checked_div(stream_chunk_bytes)
            .and_then(|depth| depth.checked_add(1))
            .expect("test bound arithmetic must fit");
        let limits = MechanicalLimits {
            max_output_bytes: MAX_RUNTIME_OUTPUT_BYTES,
            stream_chunk_bytes,
            reader_queue_depth,
            ..MechanicalLimits::default()
        };
        let error = limits.validate().expect_err("reader product must fail");
        assert!(error.to_string().contains("reader_queue_depth"));
    }
}

/// A cheap, cloneable cancellation token for one runtime operation.
///
/// The token owns one local flag and may observe additional flags belonging to
/// an enclosing owner (for example a turn cancellation) without spawning a
/// forwarding thread.  The linked flags are immutable after construction and
/// are scoped to this operation, so cancellation cannot accidentally fan out
/// to an unrelated call.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    linked: Arc<Vec<Arc<AtomicBool>>>,
}

impl CancellationToken {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a token that observes the supplied per-operation flags in
    /// addition to its own local flag.  This is intentionally a flags-only
    /// interface: semantic cancellation ownership remains with the caller,
    /// while the process runtime only observes a bounded mechanical signal.
    #[must_use]
    pub fn from_shared_flags<I>(flags: I) -> Self
    where
        I: IntoIterator<Item = Arc<AtomicBool>>,
    {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            linked: Arc::new(flags.into_iter().collect()),
        }
    }

    /// Return the locally-owned flag so an enclosing operation can link this
    /// token without exposing its internal state representation.
    #[must_use]
    pub fn shared_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
            || self.linked.iter().any(|flag| flag.load(Ordering::SeqCst))
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

/// Initial terminal dimensions for an owner-open PTY call.
///
/// PTY support is exposed as an additive execution entry point rather than a
/// field on [`ShellExecRequest`].  Keeping the existing request shape intact
/// means legacy codecs can continue to construct it with a struct literal
/// while an owner-open caller can opt into a real controlling terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtySize {
    pub rows: u16,
    pub cols: u16,
}

impl PtySize {
    #[must_use]
    pub const fn new(rows: u16, cols: u16) -> Self {
        Self { rows, cols }
    }

    pub(crate) fn validate(self) -> Result<()> {
        if self.rows == 0 || self.cols == 0 {
            return Err(RuntimeError::InvalidRequest(
                "PTY rows and cols must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for PtySize {
    fn default() -> Self {
        Self { rows: 24, cols: 80 }
    }
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

    /// Construct a request whose transport executable is intentionally absent.
    /// The runtime preserves the requested argv and emits a
    /// `transport_unavailable` terminal observation instead of attempting a
    /// policy fallback.
    #[must_use]
    pub fn unconfigured(call_id: impl Into<String>, argv: Vec<String>) -> Self {
        let mut request = Self::new(call_id, argv);
        request.adb_executable.clear();
        request
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Stdout,
    Stderr,
    /// One merged byte stream produced by a foreground PTY.
    ///
    /// This remains distinct from `Stdout`: when a PTY is selected the kernel
    /// presents stdout and stderr through one terminal stream, and the wire
    /// contract labels that stream `pty` rather than pretending it is a pipe.
    Pty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalKind {
    Exited,
    Signaled,
    TimedOut,
    Cancelled,
    OutputLimitExceeded,
    /// The selected ADB client/relay was not configured or could not be
    /// resolved.  This is distinct from a process that ran `adb` and returned
    /// a non-zero device/command status.
    TransportUnavailable,
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
            Self::TransportUnavailable => "transport_unavailable",
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
    pub io_mode: ProcessIoMode,
}

/// Internal process wiring mode.  A PTY deliberately remains a transport
/// concern; it does not add command or target policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProcessIoMode {
    Pipe,
    Pty(PtySize),
}
