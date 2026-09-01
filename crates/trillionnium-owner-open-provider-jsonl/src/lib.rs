//! Bounded duplex JSONL adapter for an external owner-open provider process.
//!
//! The provider owns semantic reasoning. This adapter owns only process
//! lifecycle, strict JSONL framing, correlation, tool callback transport and
//! truthful terminal reporting. It never adds plan, risk, approval, target
//! substitution, command rewriting or a typed ADB subcommand table.

mod process;
mod protocol;
mod strict_json;

use std::collections::BTreeMap;
use std::env;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use trillionnium_owner_open_runtime::EnvironmentDelta;
use trillionnium_owner_open_turn_loop::{
    ProviderEvent, ProviderHost, ProviderTerminal, ProviderTerminalStatus, SameTurnProvider,
    TurnRequest,
};

use process::{
    ProviderChildGuard, ProviderOutput, allow_natural_exit_grace, capture_process_identity,
    join_provider_workers_bounded, spawn_stderr_reader, spawn_stdout_reader,
};
use protocol::{
    decode_bound_tool_call, encode_tool_error, encode_tool_outcome, handle_provider_event,
    optional_string, required_string, validate_envelope,
};

pub const PROVIDER_PROTOCOL: &str = "trillionnium.owner-open.provider-jsonl.v1";
/// Schema ceilings for provider process liveness and resident buffering.
/// Deployments may lower these values, but a malformed provider profile cannot
/// request an unbounded line, queue, output retention or wait interval.
pub const MAX_JSONL_PROVIDER_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
pub const MAX_JSONL_PROVIDER_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub const MAX_JSONL_PROVIDER_TERMINATE_GRACE: Duration = Duration::from_secs(60);
pub const MAX_JSONL_PROVIDER_LINE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_JSONL_PROVIDER_STDOUT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_JSONL_PROVIDER_EVENT_COUNT: usize = 1_048_576;
pub const MAX_JSONL_PROVIDER_STDERR_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_JSONL_PROVIDER_OUTPUT_QUEUE_DEPTH: usize = 4_096;
/// Worst-case bytes queued as complete stdout lines before the provider loop
/// drains them. Two reader-side allocations remain finite under this ceiling.
pub const MAX_JSONL_PROVIDER_QUEUE_BYTES: usize = 2 * 1024 * 1024 * 1024;
const PROVIDER_OUTPUT_DRAIN_GRACE_MINIMUM: Duration = Duration::from_secs(2);
// Provider callbacks are mechanism-only, but a child that stops reading its
// stdin must not be able to wedge the Host loop in `Write::write_all`.  Keep
// each outbound JSONL frame on one finite deadline; the surrounding turn
// timeout remains the higher-level semantic bound.
const PROVIDER_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
// Provider credentials and host-local state are not implicit request input.
// Preserve only the mechanical runtime settings needed to resolve the
// configured executable and ordinary shell/ADB tools; all other values must
// be supplied through the validated provider environment delta.
const PROVIDER_INHERITED_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "CODEX_HOME",
    "LANG",
    "LC_ALL",
    "TERM",
    "NO_COLOR",
    "ADB_SERVER_SOCKET",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];
#[derive(Debug, Error)]
pub enum JsonlProviderError {
    #[error("invalid owner-open provider configuration: {0}")]
    InvalidConfiguration(String),
    #[error("cannot spawn owner-open provider: {0}")]
    Spawn(String),
    #[error("owner-open provider I/O failed: {0}")]
    Io(String),
    #[error("owner-open provider protocol failed: {0}")]
    Protocol(String),
    #[error("owner-open provider exceeded its turn deadline")]
    TimedOut,
    #[error("owner-open provider exited before a terminal frame: {0}")]
    Interrupted(String),
    #[error("owner-open provider cleanup failed: {0}")]
    Cleanup(String),
}

pub type Result<T> = std::result::Result<T, JsonlProviderError>;

#[derive(Debug, Clone)]
pub struct JsonlProviderConfig {
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub shell_executable: PathBuf,
    pub adb_executable: PathBuf,
    /// Owner-store generation captured for the provider turn.  `None` means
    /// that this source adapter has no durable generation source; the
    /// canonical request still records JSON `null` rather than silently
    /// inventing a generation value.
    pub config_generation: Option<Value>,
    pub cwd: Option<PathBuf>,
    pub env: EnvironmentDelta,
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub terminate_grace: Duration,
    pub max_line_bytes: usize,
    pub max_stdout_bytes: usize,
    pub max_event_count: usize,
    pub max_stderr_bytes: usize,
    pub output_queue_depth: usize,
}

impl JsonlProviderConfig {
    pub fn validate(&self) -> Result<()> {
        validate_os_value(&self.executable, "provider executable", 16 * 1024)?;
        validate_os_value(&self.shell_executable, "shell executable", 16 * 1024)?;
        validate_os_value(&self.adb_executable, "adb executable", 16 * 1024)?;
        if let Some(cwd) = &self.cwd {
            validate_os_value(cwd, "provider cwd", 16 * 1024)?;
        }
        if self.args.len() > 4096 {
            return Err(invalid_config("provider argv has too many elements"));
        }
        let mut total = 0usize;
        for argument in &self.args {
            if argument.len() > 64 * 1024 || argument.as_bytes().contains(&0) {
                return Err(invalid_config(
                    "provider argument exceeds its bound or contains NUL",
                ));
            }
            total = total
                .checked_add(argument.len())
                .ok_or_else(|| invalid_config("provider argv byte count overflow"))?;
        }
        if total > 1024 * 1024 {
            return Err(invalid_config("provider argv exceeds one MiB"));
        }
        if self.timeout.is_zero()
            || self.poll_interval.is_zero()
            || self.terminate_grace.is_zero()
            || self.max_line_bytes == 0
            || self.max_event_count == 0
            || self.max_stderr_bytes == 0
            || self.output_queue_depth == 0
        {
            return Err(invalid_config(
                "provider duration/count/byte limits are invalid",
            ));
        }
        for (name, value, maximum) in [
            ("timeout", self.timeout, MAX_JSONL_PROVIDER_TIMEOUT),
            (
                "poll_interval",
                self.poll_interval,
                MAX_JSONL_PROVIDER_POLL_INTERVAL,
            ),
            (
                "terminate_grace",
                self.terminate_grace,
                MAX_JSONL_PROVIDER_TERMINATE_GRACE,
            ),
        ] {
            if value > maximum {
                return Err(invalid_config(format!(
                    "provider {name} exceeds hard bound {maximum:?}"
                )));
            }
        }
        for (name, value, maximum) in [
            (
                "max_line_bytes",
                self.max_line_bytes,
                MAX_JSONL_PROVIDER_LINE_BYTES,
            ),
            (
                "max_stdout_bytes",
                self.max_stdout_bytes,
                MAX_JSONL_PROVIDER_STDOUT_BYTES,
            ),
            (
                "max_event_count",
                self.max_event_count,
                MAX_JSONL_PROVIDER_EVENT_COUNT,
            ),
            (
                "max_stderr_bytes",
                self.max_stderr_bytes,
                MAX_JSONL_PROVIDER_STDERR_BYTES,
            ),
            (
                "output_queue_depth",
                self.output_queue_depth,
                MAX_JSONL_PROVIDER_OUTPUT_QUEUE_DEPTH,
            ),
        ] {
            if value > maximum {
                return Err(invalid_config(format!(
                    "provider {name} exceeds hard bound {maximum}"
                )));
            }
        }
        if self.max_stdout_bytes < self.max_line_bytes {
            return Err(invalid_config(
                "provider duration/count/byte limits are invalid",
            ));
        }
        let queued_bytes = self
            .max_line_bytes
            .checked_mul(self.output_queue_depth)
            .ok_or_else(|| invalid_config("provider output queue byte bound overflow"))?;
        if queued_bytes > MAX_JSONL_PROVIDER_QUEUE_BYTES {
            return Err(invalid_config(format!(
                "provider max_line_bytes * output_queue_depth exceeds hard bound {MAX_JSONL_PROVIDER_QUEUE_BYTES}"
            )));
        }
        validate_environment(&self.env)?;
        if let Some(generation) = &self.config_generation {
            validate_config_generation(generation)?;
        }
        Ok(())
    }
}

impl Default for JsonlProviderConfig {
    fn default() -> Self {
        Self {
            executable: PathBuf::from("codex"),
            args: Vec::new(),
            shell_executable: PathBuf::from("/bin/sh"),
            adb_executable: PathBuf::from("adb"),
            config_generation: None,
            cwd: None,
            env: BTreeMap::new(),
            timeout: Duration::from_secs(300),
            poll_interval: Duration::from_millis(20),
            terminate_grace: Duration::from_millis(250),
            // A bounded tool.result may contain 16 MiB of runtime output in
            // base64 plus lifecycle metadata. Incremental result frames remain
            // a later optimization; this first protocol keeps one finite line.
            max_line_bytes: 32 * 1024 * 1024,
            max_stdout_bytes: 64 * 1024 * 1024,
            max_event_count: 4096,
            max_stderr_bytes: 1024 * 1024,
            output_queue_depth: 64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JsonlProvider {
    config: JsonlProviderConfig,
}

impl JsonlProvider {
    pub fn new(config: JsonlProviderConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    #[must_use]
    pub fn config(&self) -> &JsonlProviderConfig {
        &self.config
    }

    fn run_session(
        &self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> Result<ProviderTerminal> {
        self.config.validate()?;
        let started = Instant::now();
        let mut command = Command::new(&self.config.executable);
        command.env_clear();
        for &key in PROVIDER_INHERITED_ENV_ALLOWLIST {
            if let Some(value) = env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .args(&self.config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = &self.config.cwd {
            command.current_dir(cwd);
        }
        for (key, value) in &self.config.env {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
        let parent_pid = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(any(target_os = "linux", target_os = "android"))]
                {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::getppid() != parent_pid {
                        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
                    }
                }
                Ok(())
            });
        }

        let child = command
            .spawn()
            .map_err(|error| JsonlProviderError::Spawn(error.to_string()))?;
        // Install the guard before touching any child-owned pipe.  Every
        // operation below can fail (including OS thread creation), and a bare
        // `Child` would otherwise leave the provider process/group alive on
        // those early-return paths.
        let mut child = ProviderChildGuard::new(child, self.config.terminate_grace);
        // Bind the kernel-observed process generation before touching any
        // child-owned descriptor.  If the leader exits during this tiny
        // window, the guard's exact Child handle performs bounded cleanup and
        // no raw PID/PGID signal is attempted.
        let identity = capture_process_identity(child.id()).map_err(|error| {
            JsonlProviderError::Io(format!(
                "failed to capture provider process identity: {error}"
            ))
        })?;
        child.bind_identity(identity);
        let mut provider_stdin = child
            .stdin
            .take()
            .ok_or_else(|| JsonlProviderError::Io("provider stdin was not piped".to_string()))?;
        let provider_stdout = child
            .stdout
            .take()
            .ok_or_else(|| JsonlProviderError::Io("provider stdout was not piped".to_string()))?;
        let provider_stderr = child
            .stderr
            .take()
            .ok_or_else(|| JsonlProviderError::Io("provider stderr was not piped".to_string()))?;

        let (sender, receiver) = sync_channel(self.config.output_queue_depth);
        let stdout_thread = spawn_stdout_reader(
            provider_stdout,
            self.config.max_line_bytes,
            self.config.max_stdout_bytes,
            sender,
        )
        .map_err(|error| JsonlProviderError::Io(error.to_string()))?;
        let stderr_capture = Arc::new(Mutex::new(Vec::new()));
        let stderr_overflow = Arc::new(AtomicBool::new(false));
        let stderr_thread = spawn_stderr_reader(
            provider_stderr,
            self.config.max_stderr_bytes,
            Arc::clone(&stderr_capture),
            Arc::clone(&stderr_overflow),
        )
        .map_err(|error| JsonlProviderError::Io(error.to_string()))?;

        let result = (|| {
            let mut outbound_seq = 0_u64;
            let mut inbound_seq = 0_u64;
            write_json_line(
                &mut provider_stdin,
                &json!({
                    "protocol": PROVIDER_PROTOCOL,
                    "kind": "turn.start",
                    "seq": outbound_seq,
                    "turn": {
                        "session_id": &request.session_id,
                        "profile_id": &request.profile_id,
                        "task_id": &request.task_id,
                        "turn_id": &request.turn_id,
                        "turn_stream_id": &request.turn_stream_id,
                        "user_input": &request.user_input
                    }
                }),
                self.config.max_line_bytes,
            )?;
            outbound_seq = outbound_seq.saturating_add(1);

            let mut terminal = None;
            let mut event_count = 0usize;
            let mut cancellation_sent = false;
            let mut cancellation_deadline = None::<Instant>;
            let mut observed_exit = None::<(String, Instant)>;
            while terminal.is_none() {
                if started.elapsed() >= self.config.timeout {
                    return Err(JsonlProviderError::TimedOut);
                }
                if host.is_cancelled() && !cancellation_sent {
                    write_json_line(
                        &mut provider_stdin,
                        &json!({
                            "protocol": PROVIDER_PROTOCOL,
                            "kind": "turn.cancel",
                            "seq": outbound_seq,
                            "turn": {
                                "session_id": &request.session_id,
                                "profile_id": &request.profile_id,
                                "task_id": &request.task_id,
                                "turn_id": &request.turn_id,
                                "turn_stream_id": &request.turn_stream_id
                            }
                        }),
                        self.config.max_line_bytes,
                    )?;
                    outbound_seq = outbound_seq.saturating_add(1);
                    cancellation_sent = true;
                    cancellation_deadline = Instant::now().checked_add(self.config.terminate_grace);
                }
                if cancellation_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    terminal = Some(ProviderTerminal::cancelled(
                        "provider cancellation grace expired; its process group was terminated",
                    ));
                    continue;
                }

                match receiver.recv_timeout(self.config.poll_interval) {
                    Ok(ProviderOutput::Line(raw)) => {
                        event_count = event_count.saturating_add(1);
                        if event_count > self.config.max_event_count {
                            return Err(JsonlProviderError::Protocol(
                                "provider event count exceeds its bound".to_string(),
                            ));
                        }
                        let value = strict_json::decode_object(&raw)
                            .map_err(JsonlProviderError::Protocol)?;
                        validate_envelope(&value, inbound_seq)?;
                        inbound_seq = inbound_seq.saturating_add(1);
                        match required_string(&value, "kind")? {
                            "provider.event" => handle_provider_event(&value, host)?,
                            "tool.call" => {
                                let call_id = value
                                    .get("call")
                                    .and_then(Value::as_object)
                                    .and_then(|call| call.get("call_id"))
                                    .and_then(Value::as_str)
                                    .unwrap_or("unknown-call")
                                    .to_string();
                                let response =
                                    match decode_bound_tool_call(&value, request, &self.config) {
                                        Ok(call) => match host.invoke_tool(call) {
                                            Ok(outcome) => {
                                                encode_tool_outcome(outbound_seq, &call_id, outcome)
                                            }
                                            Err(error) => encode_tool_error(
                                                outbound_seq,
                                                &call_id,
                                                "host_error",
                                                &error.to_string(),
                                            ),
                                        },
                                        Err(error) => encode_tool_error(
                                            outbound_seq,
                                            &call_id,
                                            "invalid_request",
                                            &error.to_string(),
                                        ),
                                    };
                                write_json_line(
                                    &mut provider_stdin,
                                    &response,
                                    self.config.max_line_bytes,
                                )?;
                                outbound_seq = outbound_seq.saturating_add(1);
                            }
                            "turn.complete" => {
                                terminal = Some(ProviderTerminal {
                                    status: ProviderTerminalStatus::Completed,
                                    summary: optional_string(&value, "summary")?
                                        .map(str::to_string),
                                    error: None,
                                });
                            }
                            "turn.cancelled" => {
                                terminal = Some(ProviderTerminal {
                                    status: ProviderTerminalStatus::Cancelled,
                                    summary: optional_string(&value, "summary")?
                                        .map(str::to_string),
                                    error: None,
                                });
                            }
                            "turn.fail" => {
                                return Err(JsonlProviderError::Interrupted(
                                    required_string(&value, "error")?.to_string(),
                                ));
                            }
                            other => {
                                host.emit(ProviderEvent::Opaque {
                                    kind: other.to_string(),
                                    payload: String::from_utf8(raw).map_err(|error| {
                                        JsonlProviderError::Protocol(error.to_string())
                                    })?,
                                })
                                .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
                            }
                        }
                    }
                    Ok(ProviderOutput::Eof) => {
                        if cancellation_sent {
                            terminal = Some(ProviderTerminal::cancelled(
                                "provider exited after turn cancellation",
                            ));
                            continue;
                        }
                        let status = match observed_exit.as_ref() {
                            Some((status, _)) => status.clone(),
                            None => format!(
                                "{:?}",
                                child
                                    .try_wait()
                                    .map_err(|error| JsonlProviderError::Io(error.to_string()))?
                            ),
                        };
                        return Err(JsonlProviderError::Interrupted(format!(
                            "EOF before turn terminal; status={status}"
                        )));
                    }
                    Ok(ProviderOutput::Error(error)) => {
                        return Err(JsonlProviderError::Protocol(error));
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if observed_exit.is_none()
                            && let Some(status) = child
                                .try_wait()
                                .map_err(|error| JsonlProviderError::Io(error.to_string()))?
                        {
                            // Child exit and stdout delivery are observed by different
                            // threads. Exit must never overtake an already-read terminal
                            // line; wait for the ordered reader outcome (Line then Eof).
                            observed_exit = Some((status.to_string(), Instant::now()));
                        }
                        if let Some((status, observed_at)) = observed_exit.as_ref()
                            && observed_at.elapsed()
                                >= self
                                    .config
                                    .terminate_grace
                                    .max(PROVIDER_OUTPUT_DRAIN_GRACE_MINIMUM)
                        {
                            if cancellation_sent {
                                terminal = Some(ProviderTerminal::cancelled(format!(
                                    "provider exited after cancellation: {status}"
                                )));
                            } else {
                                return Err(JsonlProviderError::Interrupted(format!(
                                    "provider exited and stdout did not deliver a turn terminal within the drain grace: {status}"
                                )));
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        if cancellation_sent {
                            terminal = Some(ProviderTerminal::cancelled(
                                "provider output closed after turn cancellation",
                            ));
                        } else {
                            return Err(JsonlProviderError::Interrupted(
                                "provider stdout reader disconnected".to_string(),
                            ));
                        }
                    }
                }
            }
            terminal.ok_or_else(|| {
                JsonlProviderError::Interrupted("provider produced no terminal".to_string())
            })
        })();

        drop(provider_stdin);
        let natural_exit_wait = if result
            .as_ref()
            .is_ok_and(|terminal| terminal.status == ProviderTerminalStatus::Completed)
        {
            // A valid terminal frame may be read before the provider leader has
            // completed its ordinary exit. Do not manufacture a SIGTERM failure.
            allow_natural_exit_grace(&mut child, self.config.terminate_grace)
                .map_err(JsonlProviderError::Cleanup)
        } else {
            Ok(())
        };
        let cleanup = child.finish().map_err(JsonlProviderError::Cleanup);
        drop(receiver);
        let worker_errors = join_provider_workers_bounded(vec![stdout_thread, stderr_thread]);
        let stderr = stderr_capture
            .lock()
            .map_err(|_| JsonlProviderError::Cleanup("stderr capture was poisoned".to_string()))?
            .clone();

        // Preserve the first protocol/tool/provider error. Cleanup exists to
        // close the process tree, not to rewrite the semantic observation.
        let terminal = result?;
        natural_exit_wait?;
        if !worker_errors.is_empty() {
            return Err(JsonlProviderError::Cleanup(worker_errors.join("; ")));
        }
        let status = cleanup?;
        if stderr_overflow.load(Ordering::SeqCst) {
            return Err(JsonlProviderError::Protocol(format!(
                "provider stderr exceeded its bound; prefix={}",
                String::from_utf8_lossy(&stderr)
            )));
        }
        if !status.success() && terminal.status != ProviderTerminalStatus::Cancelled {
            return Err(JsonlProviderError::Interrupted(format!(
                "provider exited unsuccessfully: {status}; stderr={}",
                String::from_utf8_lossy(&stderr)
            )));
        }
        Ok(terminal)
    }
}

impl SameTurnProvider for JsonlProvider {
    fn run_turn(
        &mut self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> std::result::Result<ProviderTerminal, String> {
        self.run_session(request, host)
            .map_err(|error| error.to_string())
    }
}

fn write_json_line<W: Write + AsRawFd>(
    writer: &mut W,
    value: &impl Serialize,
    maximum: usize,
) -> Result<()> {
    let encoded =
        serde_json::to_vec(value).map_err(|error| JsonlProviderError::Io(error.to_string()))?;
    // `max_line_bytes` bounds the complete JSONL frame, including its
    // newline delimiter.  Check with a subtraction rather than `len() + 1`
    // so a caller-provided maximum cannot wrap on an oversized value.
    if encoded.is_empty() || maximum == 0 || encoded.len() >= maximum {
        return Err(JsonlProviderError::Io(
            "provider outbound JSONL record exceeds its bound".to_string(),
        ));
    }
    let mut framed = encoded;
    framed.push(b'\n');
    write_nonblocking(writer, &framed, PROVIDER_WRITE_TIMEOUT)
}

/// Write one provider frame without an unbounded blocking syscall.  The
/// descriptor's original flags are restored before returning so a caller that
/// reuses the handle observes the same ownership semantics.  `ChildStdin` is
/// intentionally the only production writer, but keeping the helper generic
/// makes the invariant directly testable with an ordinary pipe.
fn write_nonblocking<W: Write + AsRawFd>(
    writer: &mut W,
    bytes: &[u8],
    timeout: Duration,
) -> Result<()> {
    let fd = writer.as_raw_fd();
    let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if original_flags < 0 {
        return Err(JsonlProviderError::Io(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0 {
        return Err(JsonlProviderError::Io(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    let write_result = write_nonblocking_loop(writer, fd, bytes, timeout);
    let restore_result = unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags) };
    if restore_result < 0 {
        let restore_error = std::io::Error::last_os_error();
        return match write_result {
            Ok(()) => Err(JsonlProviderError::Io(format!(
                "failed to restore provider stdin descriptor flags: {restore_error}"
            ))),
            Err(error) => Err(JsonlProviderError::Io(format!(
                "{error}; failed to restore provider stdin descriptor flags: {restore_error}"
            ))),
        };
    }
    write_result
}

fn write_nonblocking_loop<W: Write>(
    writer: &mut W,
    fd: i32,
    bytes: &[u8],
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut offset = 0usize;
    while offset < bytes.len() {
        match writer.write(&bytes[offset..]) {
            Ok(0) => {
                return Err(JsonlProviderError::Io(
                    "provider stdin write returned zero bytes".to_string(),
                ));
            }
            Ok(written) if written <= bytes.len() - offset => {
                offset += written;
            }
            Ok(_) => {
                return Err(JsonlProviderError::Io(
                    "provider stdin writer reported more bytes than requested".to_string(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(JsonlProviderError::Io(error.to_string())),
        }
        if offset >= bytes.len() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(JsonlProviderError::Io(
                "provider stdin write timed out while the child was not reading".to_string(),
            ));
        }
        let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let polled = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if polled < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(JsonlProviderError::Io(error.to_string()));
        }
        if polled == 0 {
            return Err(JsonlProviderError::Io(
                "provider stdin write timed out while the child was not reading".to_string(),
            ));
        }
        if poll_fd.revents & (libc::POLLNVAL | libc::POLLERR | libc::POLLHUP) != 0 {
            return Err(JsonlProviderError::Io(
                "provider stdin descriptor became unavailable while writing".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_os_value(path: &Path, label: &str, maximum: usize) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > maximum || bytes.contains(&0) {
        return Err(invalid_config(format!(
            "{label} is empty, oversized or contains NUL"
        )));
    }
    Ok(())
}

fn validate_environment(environment: &EnvironmentDelta) -> Result<()> {
    if environment.len() > 4096 {
        return Err(invalid_config("provider environment has too many entries"));
    }
    let mut total = 0usize;
    for (key, value) in environment {
        if key.is_empty() || key.contains('=') || key.as_bytes().contains(&0) {
            return Err(invalid_config("provider environment key is invalid"));
        }
        total = total.saturating_add(key.len());
        if let Some(value) = value {
            if value.as_bytes().contains(&0) {
                return Err(invalid_config("provider environment value contains NUL"));
            }
            total = total.saturating_add(value.len());
        }
    }
    if total > 1024 * 1024 {
        return Err(invalid_config("provider environment exceeds one MiB"));
    }
    Ok(())
}

fn validate_config_generation(value: &Value) -> Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => Ok(()),
        Value::String(value) if !value.as_bytes().contains(&0) => Ok(()),
        _ => Err(invalid_config(
            "provider config_generation must be an integer, string or null",
        )),
    }
}

fn invalid_config(message: impl Into<String>) -> JsonlProviderError {
    JsonlProviderError::InvalidConfiguration(message.into())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::fd::FromRawFd;
    use std::time::Instant;

    use super::*;

    #[test]
    fn provider_stdin_write_is_bounded_when_the_child_stops_reading() {
        let mut descriptors = [0_i32; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        // Keep the read end open but deliberately do not drain it.  Once the
        // kernel pipe fills, the bounded writer must return instead of
        // blocking the provider turn forever.
        let _reader = unsafe { File::from_raw_fd(descriptors[0]) };
        let mut writer = unsafe { File::from_raw_fd(descriptors[1]) };
        let original_flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert!(original_flags >= 0);
        let payload = vec![b'x'; 2 * 1024 * 1024];
        let started = Instant::now();
        let error = write_nonblocking(&mut writer, &payload, Duration::from_millis(25))
            .expect_err("a stalled pipe must hit the finite write deadline");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
        let restored_flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(restored_flags, original_flags);
    }

    #[test]
    fn provider_outbound_bound_includes_the_jsonl_delimiter() {
        let mut descriptors = [0_i32; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let _reader = unsafe { File::from_raw_fd(descriptors[0]) };
        let mut writer = unsafe { File::from_raw_fd(descriptors[1]) };
        let value = json!({"kind": "turn.complete"});
        let encoded = serde_json::to_vec(&value).unwrap();
        write_json_line(&mut writer, &value, encoded.len() + 1)
            .expect("the exact framed length must fit");
        let error = write_json_line(&mut writer, &value, encoded.len())
            .expect_err("the delimiter must count against the frame bound");
        assert!(error.to_string().contains("exceeds its bound"));
    }

    #[test]
    fn default_provider_resource_bounds_validate() {
        JsonlProviderConfig::default()
            .validate()
            .expect("default provider configuration is valid");
    }

    #[test]
    fn provider_resource_schema_ceilings_fail_closed() {
        macro_rules! assert_oversized {
            ($field:ident, $maximum:ident) => {{
                let mut config = JsonlProviderConfig::default();
                config.$field = $maximum + 1;
                let error = config
                    .validate()
                    .expect_err("oversized provider bound must fail closed");
                assert!(
                    error.to_string().contains(stringify!($field)),
                    "unexpected error for {}: {error}",
                    stringify!($field)
                );
            }};
        }

        assert_oversized!(max_line_bytes, MAX_JSONL_PROVIDER_LINE_BYTES);
        assert_oversized!(max_stdout_bytes, MAX_JSONL_PROVIDER_STDOUT_BYTES);
        assert_oversized!(max_event_count, MAX_JSONL_PROVIDER_EVENT_COUNT);
        assert_oversized!(max_stderr_bytes, MAX_JSONL_PROVIDER_STDERR_BYTES);
        assert_oversized!(output_queue_depth, MAX_JSONL_PROVIDER_OUTPUT_QUEUE_DEPTH);

        let config = JsonlProviderConfig {
            timeout: MAX_JSONL_PROVIDER_TIMEOUT + Duration::from_nanos(1),
            ..JsonlProviderConfig::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("timeout")
        );
        let config = JsonlProviderConfig {
            poll_interval: MAX_JSONL_PROVIDER_POLL_INTERVAL + Duration::from_nanos(1),
            ..JsonlProviderConfig::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("poll_interval")
        );
        let config = JsonlProviderConfig {
            terminate_grace: MAX_JSONL_PROVIDER_TERMINATE_GRACE + Duration::from_nanos(1),
            ..JsonlProviderConfig::default()
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("terminate_grace")
        );

        let config = JsonlProviderConfig {
            max_line_bytes: MAX_JSONL_PROVIDER_LINE_BYTES,
            max_stdout_bytes: MAX_JSONL_PROVIDER_STDOUT_BYTES,
            output_queue_depth: MAX_JSONL_PROVIDER_QUEUE_BYTES
                .checked_div(MAX_JSONL_PROVIDER_LINE_BYTES)
                .and_then(|depth| depth.checked_add(1))
                .expect("provider queue test arithmetic fits"),
            ..JsonlProviderConfig::default()
        };
        let error = config
            .validate()
            .expect_err("provider queue product must fail closed");
        assert!(error.to_string().contains("output_queue_depth"));
    }
}
