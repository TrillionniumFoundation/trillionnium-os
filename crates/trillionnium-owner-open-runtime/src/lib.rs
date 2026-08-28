//! Mechanism-only owner-open process substrate.
//!
//! This crate deliberately has no semantic command allowlist, risk classifier,
//! approval gate, target substitution, serial injection, or ADB subcommand
//! parser.  It validates only framing/resource bounds, starts the exact process
//! selected by the caller, streams raw stdout/stderr bytes, and reports one
//! terminal observation.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use thiserror::Error;

const DEFAULT_SHELL: &str = "/bin/sh";
const DEFAULT_ADB: &str = "adb";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    #[error("invalid owner-open process request: {0}")]
    InvalidRequest(String),
}

pub type Result<T> = std::result::Result<T, RuntimeError>;

/// Mechanical liveness bounds.  None of these fields classify the meaning of
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
        {
            return Err(invalid("mechanical limits must be non-zero"));
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

/// Environment delta: `Some(value)` sets/replaces a variable, `None` removes
/// it, and an absent key inherits the parent value.
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
    /// Exact adb argv excluding the program name.  Unknown and future
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
struct ProcessSpec {
    call_id: String,
    target_id: Option<String>,
    tool: ToolKind,
    program: OsString,
    args: Vec<OsString>,
    cwd: Option<PathBuf>,
    env: EnvironmentDelta,
    stdin: Vec<u8>,
    timeout: Duration,
}

#[derive(Debug)]
enum ReaderMessage {
    Chunk(StreamKind, Vec<u8>),
    Eof(StreamKind),
    Error(StreamKind, String),
}

/// Execute a first-class command string with the configured shell, or an exact
/// element-preserving argv.  Command strings use `<shell> -c <command>`; argv
/// bypasses shell parsing entirely.
pub fn execute_shell<F>(
    request: ShellExecRequest,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    limits.validate()?;
    validate_common_request(
        &request.call_id,
        request.target_id.as_deref(),
        request.cwd.as_ref(),
        &request.env,
        &request.stdin,
        limits,
    )?;

    let (program, args) = match &request.invocation {
        ShellInvocation::Command(command) => {
            validate_scalar(
                command,
                "shell command",
                limits.max_total_argument_bytes,
                false,
            )?;
            validate_os_value(
                request.shell_executable.as_os_str(),
                "shell executable",
                limits.max_cwd_bytes,
                false,
            )?;
            (
                request.shell_executable.clone().into_os_string(),
                vec![OsString::from("-c"), OsString::from(command)],
            )
        }
        ShellInvocation::Argv(argv) => {
            validate_argv(argv, limits, "shell argv")?;
            (
                OsString::from(&argv[0]),
                argv[1..].iter().map(OsString::from).collect(),
            )
        }
    };

    Ok(execute_process(
        ProcessSpec {
            call_id: request.call_id,
            target_id: request.target_id,
            tool: ToolKind::ShellExec,
            program,
            args,
            cwd: request.cwd,
            env: request.env,
            stdin: request.stdin,
            timeout: normalized_timeout(request.timeout, limits),
        },
        limits,
        cancellation,
        sink,
    ))
}

/// Execute an ordinary adb process with exact argv passthrough.  This function
/// never inserts `-s`, a host/port, a privilege mode, or a known-subcommand
/// restriction.  `target_id` is correlation metadata only.
pub fn execute_adb<F>(
    request: AdbExecRequest,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    limits.validate()?;
    validate_common_request(
        &request.call_id,
        request.target_id.as_deref(),
        request.cwd.as_ref(),
        &request.env,
        &request.stdin,
        limits,
    )?;
    validate_argv(&request.argv, limits, "adb argv")?;
    validate_os_value(
        request.adb_executable.as_os_str(),
        "adb executable",
        limits.max_cwd_bytes,
        false,
    )?;

    Ok(execute_process(
        ProcessSpec {
            call_id: request.call_id,
            target_id: request.target_id,
            tool: ToolKind::AdbExec,
            program: request.adb_executable.into_os_string(),
            args: request.argv.into_iter().map(OsString::from).collect(),
            cwd: request.cwd,
            env: request.env,
            stdin: request.stdin,
            timeout: normalized_timeout(request.timeout, limits),
        },
        limits,
        cancellation,
        sink,
    ))
}

fn normalized_timeout(timeout: Option<Duration>, limits: &MechanicalLimits) -> Duration {
    timeout
        .filter(|value| !value.is_zero())
        .unwrap_or(limits.default_timeout)
}

fn validate_common_request(
    call_id: &str,
    target_id: Option<&str>,
    cwd: Option<&PathBuf>,
    env: &EnvironmentDelta,
    stdin: &[u8],
    limits: &MechanicalLimits,
) -> Result<()> {
    if call_id.is_empty()
        || call_id.len() > limits.max_call_id_bytes
        || !call_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid("call_id is empty, oversized, or malformed"));
    }
    if let Some(target_id) = target_id {
        validate_scalar(target_id, "target_id", limits.max_target_id_bytes, false)?;
    }
    if let Some(cwd) = cwd {
        validate_os_value(cwd.as_os_str(), "cwd", limits.max_cwd_bytes, false)?;
    }
    if stdin.len() > limits.max_stdin_bytes {
        return Err(invalid("stdin exceeds the configured byte bound"));
    }
    if env.len() > limits.max_environment_items {
        return Err(invalid("environment delta has too many entries"));
    }
    let mut environment_bytes = 0usize;
    for (key, value) in env {
        if key.is_empty() || key.contains('=') || key.as_bytes().contains(&0) {
            return Err(invalid("environment key is empty or malformed"));
        }
        environment_bytes = environment_bytes
            .checked_add(key.len())
            .ok_or_else(|| invalid("environment byte count overflow"))?;
        if let Some(value) = value {
            if value.as_bytes().contains(&0) {
                return Err(invalid("environment value contains NUL"));
            }
            environment_bytes = environment_bytes
                .checked_add(value.len())
                .ok_or_else(|| invalid("environment byte count overflow"))?;
        }
    }
    if environment_bytes > limits.max_environment_bytes {
        return Err(invalid(
            "environment delta exceeds the configured byte bound",
        ));
    }
    Ok(())
}

fn validate_argv(argv: &[String], limits: &MechanicalLimits, field: &str) -> Result<()> {
    if argv.is_empty() {
        return Err(invalid(format!("{field} must not be empty")));
    }
    if argv.len() > limits.max_argv_items {
        return Err(invalid(format!("{field} has too many elements")));
    }
    let mut total = 0usize;
    for argument in argv {
        validate_scalar(argument, field, limits.max_argument_bytes, true)?;
        total = total
            .checked_add(argument.len())
            .ok_or_else(|| invalid(format!("{field} byte count overflow")))?;
    }
    if total > limits.max_total_argument_bytes {
        return Err(invalid(format!("{field} exceeds the total byte bound")));
    }
    Ok(())
}

fn validate_scalar(value: &str, field: &str, max_bytes: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > max_bytes
        || value.as_bytes().contains(&0)
    {
        return Err(invalid(format!(
            "{field} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

fn validate_os_value(
    value: &OsStr,
    field: &str,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<()> {
    let bytes = value.as_bytes();
    if (!allow_empty && bytes.is_empty()) || bytes.len() > max_bytes || bytes.contains(&0) {
        return Err(invalid(format!(
            "{field} is empty, oversized, or contains NUL"
        )));
    }
    Ok(())
}

fn execute_process<F>(
    spec: ProcessSpec,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    mut sink: F,
) -> ExecutionTerminal
where
    F: FnMut(ExecutionEvent),
{
    let started_at = Instant::now();
    let mut sequence = 0u64;
    let mut emit = |kind: ExecutionEventKind| {
        let event = ExecutionEvent {
            call_id: spec.call_id.clone(),
            target_id: spec.target_id.clone(),
            tool: spec.tool,
            seq: sequence,
            elapsed_ms: elapsed_ms(started_at),
            kind,
        };
        sequence = sequence.saturating_add(1);
        sink(event);
    };

    emit(ExecutionEventKind::Accepted);

    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in &spec.env {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }

    // A dedicated process group is a mechanical lifecycle primitive: timeout,
    // cancellation and output exhaustion must not leave descendants running.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let terminal = ExecutionTerminal {
                kind: TerminalKind::SpawnFailed,
                exit_code: None,
                signal: None,
                stdout_bytes: 0,
                stderr_bytes: 0,
                output_truncated: false,
                elapsed_ms: elapsed_ms(started_at),
                error: Some(error.to_string()),
            };
            emit(ExecutionEventKind::Terminal(terminal.clone()));
            return terminal;
        }
    };

    let pid = child.id();
    emit(ExecutionEventKind::Started { pid });

    let (sender, receiver) = sync_channel::<ReaderMessage>(limits.reader_queue_depth);
    let stdout_thread = child.stdout.take().map(|stdout| {
        spawn_reader(
            stdout,
            StreamKind::Stdout,
            limits.stream_chunk_bytes,
            sender.clone(),
        )
    });
    let stderr_thread = child.stderr.take().map(|stderr| {
        spawn_reader(
            stderr,
            StreamKind::Stderr,
            limits.stream_chunk_bytes,
            sender,
        )
    });
    let stdin_thread = child.stdin.take().map(|mut stdin| {
        let bytes = spec.stdin;
        thread::spawn(move || {
            if bytes.is_empty() {
                return None;
            }
            match stdin.write_all(&bytes).and_then(|_| stdin.flush()) {
                Ok(()) => None,
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                    Some(format!("stdin_closed: {error}"))
                }
                Err(error) => Some(format!("stdin_io_error: {error}")),
            }
        })
    });

    let mut stdout_eof = stdout_thread.is_none();
    let mut stderr_eof = stderr_thread.is_none();
    let mut stdout_bytes = 0usize;
    let mut stderr_bytes = 0usize;
    let mut child_status: Option<ExitStatus> = None;
    let mut forced_kind: Option<TerminalKind> = None;
    let mut runtime_error: Option<String> = None;
    let mut termination_attempted = false;

    loop {
        if child_status.is_none() {
            match child.try_wait() {
                Ok(status) => child_status = status,
                Err(error) => {
                    runtime_error = Some(format!("child_status_error: {error}"));
                    forced_kind.get_or_insert(TerminalKind::IoError);
                }
            }
        }

        if child_status.is_none() && forced_kind.is_none() {
            if cancellation.is_cancelled() {
                forced_kind = Some(TerminalKind::Cancelled);
            } else if started_at.elapsed() >= spec.timeout {
                forced_kind = Some(TerminalKind::TimedOut);
            }
        }

        if child_status.is_none() && forced_kind.is_some() && !termination_attempted {
            termination_attempted = true;
            match terminate_process_group(&mut child, pid, limits.terminate_grace) {
                Ok(status) => child_status = Some(status),
                Err(error) => {
                    runtime_error = Some(join_error(runtime_error, error));
                    forced_kind = Some(TerminalKind::IoError);
                    child_status = child.wait().ok();
                }
            }
        }

        if child_status.is_some() && stdout_eof && stderr_eof {
            break;
        }

        match receiver.recv_timeout(limits.poll_interval) {
            Ok(ReaderMessage::Chunk(stream, bytes)) => {
                let used = stdout_bytes.saturating_add(stderr_bytes);
                let remaining = limits.max_output_bytes.saturating_sub(used);
                let delivered = bytes.len().min(remaining);
                if delivered > 0 {
                    let output = bytes[..delivered].to_vec();
                    match stream {
                        StreamKind::Stdout => stdout_bytes = stdout_bytes.saturating_add(delivered),
                        StreamKind::Stderr => stderr_bytes = stderr_bytes.saturating_add(delivered),
                    }
                    emit(ExecutionEventKind::Output {
                        stream,
                        bytes: output,
                    });
                }
                if delivered < bytes.len() || remaining == 0 {
                    forced_kind.get_or_insert(TerminalKind::OutputLimitExceeded);
                    if child_status.is_none() && !termination_attempted {
                        termination_attempted = true;
                        match terminate_process_group(&mut child, pid, limits.terminate_grace) {
                            Ok(status) => child_status = Some(status),
                            Err(error) => {
                                runtime_error = Some(join_error(runtime_error, error));
                                forced_kind = Some(TerminalKind::IoError);
                                child_status = child.wait().ok();
                            }
                        }
                    }
                }
            }
            Ok(ReaderMessage::Eof(stream)) => match stream {
                StreamKind::Stdout => stdout_eof = true,
                StreamKind::Stderr => stderr_eof = true,
            },
            Ok(ReaderMessage::Error(stream, error)) => {
                runtime_error = Some(join_error(runtime_error, error));
                forced_kind.get_or_insert(TerminalKind::IoError);
                match stream {
                    StreamKind::Stdout => stdout_eof = true,
                    StreamKind::Stderr => stderr_eof = true,
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                stdout_eof = true;
                stderr_eof = true;
            }
        }
    }

    let status = child_status.or_else(|| child.wait().ok());
    join_reader(stdout_thread, &mut runtime_error, "stdout_reader");
    join_reader(stderr_thread, &mut runtime_error, "stderr_reader");
    if let Some(stdin_thread) = stdin_thread {
        match stdin_thread.join() {
            Ok(Some(error)) => runtime_error = Some(join_error(runtime_error, error)),
            Ok(None) => {}
            Err(_) => {
                runtime_error = Some(join_error(
                    runtime_error,
                    "stdin_writer_panicked".to_string(),
                ))
            }
        }
    }

    let status_kind =
        forced_kind.unwrap_or_else(|| match status.as_ref().and_then(ExitStatusExt::signal) {
            Some(_) => TerminalKind::Signaled,
            None => TerminalKind::Exited,
        });
    let output_truncated = status_kind == TerminalKind::OutputLimitExceeded;
    let terminal = ExecutionTerminal {
        kind: status_kind,
        exit_code: status.as_ref().and_then(ExitStatus::code),
        signal: status.as_ref().and_then(ExitStatusExt::signal),
        stdout_bytes: u64::try_from(stdout_bytes).unwrap_or(u64::MAX),
        stderr_bytes: u64::try_from(stderr_bytes).unwrap_or(u64::MAX),
        output_truncated,
        elapsed_ms: elapsed_ms(started_at),
        error: runtime_error,
    };
    emit(ExecutionEventKind::Terminal(terminal.clone()));
    terminal
}

fn spawn_reader<R>(
    mut reader: R,
    stream: StreamKind,
    chunk_bytes: usize,
    sender: SyncSender<ReaderMessage>,
) -> JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = vec![0u8; chunk_bytes];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(ReaderMessage::Eof(stream));
                    return;
                }
                Ok(count) => {
                    if sender
                        .send(ReaderMessage::Chunk(stream, buffer[..count].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => {
                    let _ = sender.send(ReaderMessage::Error(
                        stream,
                        format!(
                            "{}_read_error: {error}",
                            match stream {
                                StreamKind::Stdout => "stdout",
                                StreamKind::Stderr => "stderr",
                            }
                        ),
                    ));
                    return;
                }
            }
        }
    })
}

fn join_reader(thread: Option<JoinHandle<()>>, error: &mut Option<String>, label: &str) {
    if let Some(thread) = thread
        && thread.join().is_err()
    {
        *error = Some(join_error(error.take(), format!("{label}_panicked")));
    }
}

fn terminate_process_group(
    child: &mut Child,
    pid: u32,
    grace: Duration,
) -> std::result::Result<ExitStatus, String> {
    send_process_group_signal(pid, libc::SIGTERM)?;
    let deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            Ok(None) => break,
            Err(error) => return Err(format!("child_status_after_sigterm_failed: {error}")),
        }
    }
    send_process_group_signal(pid, libc::SIGKILL)?;
    child
        .wait()
        .map_err(|error| format!("child_reap_after_sigkill_failed: {error}"))
}

fn send_process_group_signal(pid: u32, signal: i32) -> std::result::Result<(), String> {
    let process_group = i32::try_from(pid)
        .map_err(|_| "child pid does not fit a POSIX process-group id".to_string())?;
    let rc = unsafe { libc::kill(-process_group, signal) };
    if rc == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(format!("process_group_signal_{signal}_failed: {error}"))
}

fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn join_error(existing: Option<String>, next: String) -> String {
    match existing {
        Some(existing) => format!("{existing}; {next}"),
        None => next,
    }
}

fn invalid(message: impl Into<String>) -> RuntimeError {
    RuntimeError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_requests_are_rejected_before_acceptance() {
        let limits = MechanicalLimits::default();
        let cancellation = CancellationToken::new();
        let mut events = Vec::new();
        let error = execute_shell(
            ShellExecRequest::argv("call-empty", Vec::new()),
            &limits,
            &cancellation,
            |event| events.push(event),
        )
        .unwrap_err();
        assert!(error.to_string().contains("must not be empty"));
        assert!(events.is_empty());
    }

    #[test]
    fn zero_request_timeout_uses_owner_default() {
        let limits = MechanicalLimits::default();
        assert_eq!(
            normalized_timeout(Some(Duration::ZERO), &limits),
            limits.default_timeout
        );
    }
}
