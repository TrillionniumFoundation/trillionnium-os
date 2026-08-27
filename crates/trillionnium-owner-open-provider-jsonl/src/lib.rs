//! Bounded duplex JSONL adapter for an external owner-open provider process.
//!
//! The provider owns semantic reasoning. This adapter owns only process
//! lifecycle, strict JSONL framing, correlation, tool callback transport and
//! truthful terminal reporting. It never adds plan, risk, approval, target
//! substitution, command rewriting or a typed ADB subcommand table.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use trillionnium_owner_open_call_registry::{CallKey, CallSnapshot};
use trillionnium_owner_open_runtime::{
    AdbExecRequest, EnvironmentDelta, ExecutionEvent, ExecutionEventKind, ExecutionTerminal,
    ShellExecRequest, ShellInvocation, StreamKind,
};
use trillionnium_owner_open_tool_bridge::{BoundToolCall, DirectToolRequest};
use trillionnium_owner_open_turn_loop::{
    ProviderEvent, ProviderHost, ProviderTerminal, SameTurnProvider, ToolOutcome, TurnRequest,
};
use trillionnium_owner_open_types::{MechanicalLimits as CodecLimits, ToolCall};

pub const PROVIDER_PROTOCOL: &str = "trillionnium.owner-open.provider-jsonl.v1";

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
    pub cwd: Option<PathBuf>,
    pub env: EnvironmentDelta,
    pub timeout: Duration,
    pub poll_interval: Duration,
    pub terminate_grace: Duration,
    pub max_line_bytes: usize,
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
            || self.max_line_bytes == 0
            || self.max_event_count == 0
            || self.max_stderr_bytes == 0
            || self.output_queue_depth == 0
        {
            return Err(invalid_config(
                "provider duration/count/byte limits must be non-zero",
            ));
        }
        validate_environment(&self.env)?;
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
            cwd: None,
            env: BTreeMap::new(),
            timeout: Duration::from_secs(300),
            poll_interval: Duration::from_millis(20),
            terminate_grace: Duration::from_millis(250),
            max_line_bytes: 1024 * 1024,
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
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let mut child = command
            .spawn()
            .map_err(|error| JsonlProviderError::Spawn(error.to_string()))?;
        let pid = child.id();
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
            sender,
        );
        let stderr_capture = Arc::new(Mutex::new(StderrCapture::default()));
        let stderr_overflow = Arc::new(AtomicBool::new(false));
        let stderr_thread = spawn_stderr_reader(
            provider_stderr,
            self.config.max_stderr_bytes,
            Arc::clone(&stderr_capture),
            Arc::clone(&stderr_overflow),
        );

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
                        "session_id": request.session_id,
                        "profile_id": request.profile_id,
                        "task_id": request.task_id,
                        "turn_id": request.turn_id,
                        "turn_stream_id": request.turn_stream_id,
                        "user_input": request.user_input
                    }
                }),
                self.config.max_line_bytes,
            )?;
            outbound_seq = outbound_seq.saturating_add(1);

            let mut terminal = None;
            let mut event_count = 0usize;
            while terminal.is_none() {
                if started.elapsed() >= self.config.timeout {
                    return Err(JsonlProviderError::TimedOut);
                }
                match receiver.recv_timeout(self.config.poll_interval) {
                    Ok(ProviderOutput::Line(raw)) => {
                        event_count = event_count.saturating_add(1);
                        if event_count > self.config.max_event_count {
                            return Err(JsonlProviderError::Protocol(
                                "provider event count exceeds its bound".to_string(),
                            ));
                        }
                        let value = decode_strict_object(&raw)?;
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
                                let response = match decode_bound_tool_call(
                                    &value,
                                    request,
                                    &self.config,
                                ) {
                                    Ok(call) => match host.invoke_tool(call) {
                                        Ok(outcome) => encode_tool_outcome(
                                            outbound_seq,
                                            &call_id,
                                            outcome,
                                        ),
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
                                    status: trillionnium_owner_open_turn_loop::ProviderTerminalStatus::Completed,
                                    summary: optional_string(&value, "summary")?.map(str::to_string),
                                    error: None,
                                });
                            }
                            "turn.cancelled" => {
                                terminal = Some(ProviderTerminal {
                                    status: trillionnium_owner_open_turn_loop::ProviderTerminalStatus::Cancelled,
                                    summary: optional_string(&value, "summary")?.map(str::to_string),
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
                                .map_err(|error| {
                                    JsonlProviderError::Protocol(error.to_string())
                                })?;
                            }
                        }
                    }
                    Ok(ProviderOutput::Eof) => {
                        let status = child
                            .try_wait()
                            .map_err(|error| JsonlProviderError::Io(error.to_string()))?;
                        return Err(JsonlProviderError::Interrupted(format!(
                            "EOF before turn terminal; status={status:?}"
                        )));
                    }
                    Ok(ProviderOutput::Error(error)) => {
                        return Err(JsonlProviderError::Protocol(error));
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if let Some(status) = child
                            .try_wait()
                            .map_err(|error| JsonlProviderError::Io(error.to_string()))?
                        {
                            return Err(JsonlProviderError::Interrupted(format!(
                                "process exited before turn terminal: {status}"
                            )));
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(JsonlProviderError::Interrupted(
                            "provider stdout reader disconnected".to_string(),
                        ));
                    }
                }
            }
            terminal.ok_or_else(|| {
                JsonlProviderError::Interrupted("provider produced no terminal".to_string())
            })
        })();

        drop(provider_stdin);
        drop(receiver);
        let cleanup = finish_child(&mut child, pid, self.config.terminate_grace);
        let stdout_join = stdout_thread.join();
        let stderr_join = stderr_thread.join();
        let stderr = stderr_capture
            .lock()
            .map_err(|_| JsonlProviderError::Cleanup("stderr capture was poisoned".to_string()))?
            .clone();

        if stdout_join.is_err() || stderr_join.is_err() {
            return Err(JsonlProviderError::Cleanup(
                "provider reader thread panicked".to_string(),
            ));
        }
        if stderr_overflow.load(Ordering::SeqCst) {
            return Err(JsonlProviderError::Protocol(format!(
                "provider stderr exceeded its bound; prefix={}",
                String::from_utf8_lossy(&stderr.bytes)
            )));
        }
        let status = cleanup?;
        if !status.success() {
            return Err(JsonlProviderError::Interrupted(format!(
                "provider exited unsuccessfully: {status}; stderr={}",
                String::from_utf8_lossy(&stderr.bytes)
            )));
        }
        result
    }
}

impl SameTurnProvider for JsonlProvider {
    fn run_turn(
        &mut self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> std::result::Result<ProviderTerminal, String> {
        self.run_session(request, host).map_err(|error| error.to_string())
    }
}

#[derive(Debug)]
enum ProviderOutput {
    Line(Vec<u8>),
    Eof,
    Error(String),
}

#[derive(Debug, Default, Clone)]
struct StderrCapture {
    bytes: Vec<u8>,
    total_bytes: u64,
}

fn spawn_stdout_reader(
    stdout: impl Read + Send + 'static,
    max_line_bytes: usize,
    sender: SyncSender<ProviderOutput>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            match read_bounded_line(&mut reader, max_line_bytes) {
                Ok(Some(line)) => {
                    if sender.send(ProviderOutput::Line(line)).is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = sender.send(ProviderOutput::Eof);
                    return;
                }
                Err(error) => {
                    let _ = sender.send(ProviderOutput::Error(error));
                    return;
                }
            }
        }
    })
}

fn spawn_stderr_reader(
    mut stderr: impl Read + Send + 'static,
    maximum: usize,
    capture: Arc<Mutex<StderrCapture>>,
    overflow: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => return,
                Ok(count) => {
                    let Ok(mut state) = capture.lock() else {
                        return;
                    };
                    state.total_bytes = state
                        .total_bytes
                        .saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                    let remaining = maximum.saturating_sub(state.bytes.len());
                    state.bytes.extend_from_slice(&buffer[..count.min(remaining)]);
                    if count > remaining {
                        overflow.store(true, Ordering::SeqCst);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    })
}

fn read_bounded_line(reader: &mut impl BufRead, maximum: usize) -> std::result::Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    let read = reader
        .take(maximum as u64 + 2)
        .read_until(b'\n', &mut line)
        .map_err(|error| format!("provider stdout read failed: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err("provider JSONL record is unterminated or oversized".to_string());
    }
    line.pop();
    if line.is_empty() || line.len() > maximum {
        return Err("provider JSONL record is empty or oversized".to_string());
    }
    Ok(Some(line))
}

fn write_json_line(
    writer: &mut impl Write,
    value: &impl Serialize,
    maximum: usize,
) -> Result<()> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| JsonlProviderError::Io(error.to_string()))?;
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(JsonlProviderError::Io(
            "provider outbound JSONL record exceeds its bound".to_string(),
        ));
    }
    writer
        .write_all(&encoded)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|error| JsonlProviderError::Io(error.to_string()))
}

fn validate_envelope(value: &Value, expected_seq: u64) -> Result<()> {
    if required_string(value, "protocol")? != PROVIDER_PROTOCOL {
        return Err(JsonlProviderError::Protocol(
            "provider protocol does not match".to_string(),
        ));
    }
    if value.get("seq").and_then(Value::as_u64) != Some(expected_seq) {
        return Err(JsonlProviderError::Protocol(format!(
            "provider seq is not the expected value {expected_seq}"
        )));
    }
    required_string(value, "kind")?;
    Ok(())
}

fn handle_provider_event(value: &Value, host: &mut ProviderHost<'_>) -> Result<()> {
    let event = required_string(value, "event")?;
    let converted = match event {
        "model.delta" => ProviderEvent::ModelDelta(required_string(value, "text")?.to_string()),
        "model.message" => {
            ProviderEvent::ModelMessage(required_string(value, "text")?.to_string())
        }
        "provider.status" => ProviderEvent::Status {
            status: required_string(value, "status")?.to_string(),
            detail: optional_string(value, "detail")?.map(str::to_string),
        },
        other => ProviderEvent::Opaque {
            kind: other.to_string(),
            payload: serde_json::to_string(value)
                .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?,
        },
    };
    host.emit(converted)
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))
}

fn decode_bound_tool_call(
    envelope: &Value,
    turn: &TurnRequest,
    config: &JsonlProviderConfig,
) -> Result<BoundToolCall> {
    let raw_call = envelope
        .get("call")
        .cloned()
        .ok_or_else(|| JsonlProviderError::Protocol("tool.call has no call object".to_string()))?;
    let mut call: ToolCall = serde_json::from_value(raw_call)
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
    bind_scope(&mut call, turn)?;
    let claimed_request_sha256 = call.request_sha256.clone();
    let claimed_binding = call.binding_fingerprint.clone();
    call.request_sha256 = None;
    call.binding_fingerprint = None;
    let canonical_request = serde_json::to_vec(&call)
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
    let binding_fingerprint = configuration_fingerprint(&call, config)?;
    if claimed_binding
        .as_deref()
        .is_some_and(|claimed| claimed != binding_fingerprint)
    {
        return Err(JsonlProviderError::Protocol(
            "tool.call binding_fingerprint does not match resolved configuration".to_string(),
        ));
    }

    let target_id = call.target_id.clone().or(call.target.clone());
    let direct_request = match call.tool.as_str() {
        "shell.exec" => {
            call.validate_shell_exec(&CodecLimits::default())
                .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
            DirectToolRequest::Shell(shell_request(&call, config)?)
        }
        "adb.exec" => {
            call.validate_adb_exec(&CodecLimits::default())
                .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
            DirectToolRequest::Adb(adb_request(&call, config)?)
        }
        _ => {
            return Err(JsonlProviderError::Protocol(format!(
                "tool {} has no owner-open process backend",
                call.tool
            )));
        }
    };
    let key = CallKey::new(turn.scope(), call.call_id.clone());
    match claimed_request_sha256 {
        Some(claimed) => BoundToolCall::with_claimed_digest(
            key,
            binding_fingerprint,
            target_id,
            canonical_request,
            claimed,
            direct_request,
        )
        .map_err(|error| JsonlProviderError::Protocol(error.to_string())),
        None => BoundToolCall::new(
            key,
            binding_fingerprint,
            target_id,
            canonical_request,
            direct_request,
        )
        .map_err(|error| JsonlProviderError::Protocol(error.to_string())),
    }
}

fn bind_scope(call: &mut ToolCall, turn: &TurnRequest) -> Result<()> {
    bind_optional(&mut call.session_id, &turn.session_id, "session_id")?;
    bind_optional(&mut call.profile_id, &turn.profile_id, "profile_id")?;
    bind_optional(&mut call.task_id, &turn.task_id, "task_id")?;
    bind_optional(&mut call.turn_id, &turn.turn_id, "turn_id")?;
    bind_optional(
        &mut call.turn_stream_id,
        &turn.turn_stream_id,
        "turn_stream_id",
    )?;
    Ok(())
}

fn bind_optional(field: &mut Option<String>, expected: &str, label: &str) -> Result<()> {
    match field {
        Some(value) if value != expected => Err(JsonlProviderError::Protocol(format!(
            "tool.call {label} conflicts with the active turn"
        ))),
        Some(_) => Ok(()),
        None => {
            *field = Some(expected.to_string());
            Ok(())
        }
    }
}

fn shell_request(call: &ToolCall, config: &JsonlProviderConfig) -> Result<ShellExecRequest> {
    reject_active_pty(call)?;
    let invocation = match (&call.command, &call.argv) {
        (Some(command), None) => ShellInvocation::Command(command.clone()),
        (None, Some(argv)) => ShellInvocation::Argv(argv.clone()),
        _ => {
            return Err(JsonlProviderError::Protocol(
                "shell.exec command/argv shape is invalid".to_string(),
            ));
        }
    };
    Ok(ShellExecRequest {
        call_id: call.call_id.clone(),
        target_id: call.target_id.clone().or(call.target.clone()),
        invocation,
        shell_executable: config.shell_executable.clone(),
        cwd: call.cwd.as_ref().map(PathBuf::from),
        env: call.env.clone(),
        stdin: decode_stdin(call.stdin.as_ref())?,
        timeout: decode_timeout(call.timeout_ms)?,
    })
}

fn adb_request(call: &ToolCall, config: &JsonlProviderConfig) -> Result<AdbExecRequest> {
    reject_active_pty(call)?;
    Ok(AdbExecRequest {
        call_id: call.call_id.clone(),
        target_id: call.target_id.clone().or(call.target.clone()),
        argv: call.argv.clone().ok_or_else(|| {
            JsonlProviderError::Protocol("adb.exec has no argv".to_string())
        })?,
        adb_executable: config.adb_executable.clone(),
        cwd: call.cwd.as_ref().map(PathBuf::from),
        env: call.env.clone(),
        stdin: decode_stdin(call.stdin.as_ref())?,
        timeout: decode_timeout(call.timeout_ms)?,
    })
}

fn reject_active_pty(call: &ToolCall) -> Result<()> {
    let enabled = match call.pty.as_ref() {
        None | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(Value::Object(value)) => value
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        Some(_) => true,
    };
    if enabled {
        return Err(JsonlProviderError::Protocol(
            "PTY transport is not implemented in the R5 JSONL adapter".to_string(),
        ));
    }
    Ok(())
}

fn decode_stdin(value: Option<&Value>) -> Result<Vec<u8>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(value) => Ok(value.as_bytes().to_vec()),
        Value::Object(object) => {
            let encoding = object
                .get("encoding")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JsonlProviderError::Protocol("stdin object has no encoding".to_string())
                })?;
            let data = object
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    JsonlProviderError::Protocol("stdin object has no data".to_string())
                })?;
            match encoding {
                "utf8" | "utf-8" => Ok(data.as_bytes().to_vec()),
                "base64" => BASE64_STANDARD.decode(data).map_err(|error| {
                    JsonlProviderError::Protocol(format!("stdin base64 is invalid: {error}"))
                }),
                other => Err(JsonlProviderError::Protocol(format!(
                    "stdin encoding {other} is unsupported"
                ))),
            }
        }
        _ => Err(JsonlProviderError::Protocol(
            "stdin has an unsupported shape".to_string(),
        )),
    }
}

fn decode_timeout(value: Option<i64>) -> Result<Option<Duration>> {
    match value {
        None | Some(0) => Ok(None),
        Some(value) if value > 0 => Ok(Some(Duration::from_millis(
            u64::try_from(value).map_err(|_| {
                JsonlProviderError::Protocol("timeout_ms is out of range".to_string())
            })?,
        ))),
        Some(_) => Err(JsonlProviderError::Protocol(
            "timeout_ms must be nonnegative".to_string(),
        )),
    }
}

fn configuration_fingerprint(call: &ToolCall, config: &JsonlProviderConfig) -> Result<String> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"schema", b"trillionnium.owner-open.binding.v1");
    hash_field(&mut hasher, b"tool", call.tool.as_bytes());
    let executable = if call.tool == "adb.exec" {
        &config.adb_executable
    } else {
        &config.shell_executable
    };
    hash_field(&mut hasher, b"executable", executable.as_os_str().as_bytes());
    hash_field(
        &mut hasher,
        b"config_generation",
        &serde_json::to_vec(&call.config_generation)
            .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?,
    );
    Ok(hex_lower(&hasher.finalize()))
}

fn encode_tool_outcome(seq: u64, call_id: &str, outcome: ToolOutcome) -> Value {
    match outcome {
        ToolOutcome::Executed {
            generation,
            events,
            terminal,
            observation_sha256,
            snapshot,
        } => json!({
            "protocol": PROVIDER_PROTOCOL,
            "kind": "tool.result",
            "seq": seq,
            "call_id": call_id,
            "status": "terminal",
            "generation": generation,
            "events": events.iter().map(encode_execution_event).collect::<Vec<_>>(),
            "terminal": encode_terminal(&terminal),
            "observation_sha256": observation_sha256,
            "registry": encode_snapshot(&snapshot)
        }),
        ToolOutcome::Existing(snapshot) => json!({
            "protocol": PROVIDER_PROTOCOL,
            "kind": "tool.result",
            "seq": seq,
            "call_id": call_id,
            "status": "existing",
            "registry": encode_snapshot(&snapshot)
        }),
        ToolOutcome::Inhibited(snapshot) => json!({
            "protocol": PROVIDER_PROTOCOL,
            "kind": "tool.result",
            "seq": seq,
            "call_id": call_id,
            "status": "inhibited",
            "registry": encode_snapshot(&snapshot)
        }),
    }
}

fn encode_tool_error(seq: u64, call_id: &str, status: &str, error: &str) -> Value {
    json!({
        "protocol": PROVIDER_PROTOCOL,
        "kind": "tool.result",
        "seq": seq,
        "call_id": call_id,
        "status": status,
        "error": error
    })
}

fn encode_execution_event(event: &ExecutionEvent) -> Value {
    let body = match &event.kind {
        ExecutionEventKind::Accepted => json!({"kind": "accepted"}),
        ExecutionEventKind::Started { pid } => json!({"kind": "started", "pid": pid}),
        ExecutionEventKind::Output { stream, bytes } => json!({
            "kind": "output",
            "stream": match stream {
                StreamKind::Stdout => "stdout",
                StreamKind::Stderr => "stderr"
            },
            "encoding": "base64",
            "data": BASE64_STANDARD.encode(bytes),
            "byte_count": bytes.len()
        }),
        ExecutionEventKind::Terminal(terminal) => json!({
            "kind": "terminal",
            "terminal": encode_terminal(terminal)
        }),
    };
    json!({
        "call_id": event.call_id,
        "target_id": event.target_id,
        "tool": event.tool.as_str(),
        "seq": event.seq,
        "elapsed_ms": event.elapsed_ms,
        "event": body
    })
}

fn encode_terminal(terminal: &ExecutionTerminal) -> Value {
    json!({
        "kind": terminal.kind.as_str(),
        "exit_code": terminal.exit_code,
        "signal": terminal.signal,
        "stdout_bytes": terminal.stdout_bytes,
        "stderr_bytes": terminal.stderr_bytes,
        "output_truncated": terminal.output_truncated,
        "elapsed_ms": terminal.elapsed_ms,
        "error": terminal.error
    })
}

fn encode_snapshot(snapshot: &CallSnapshot) -> Value {
    json!({
        "call_id": snapshot.key.call_id,
        "request_sha256": snapshot.request.request_sha256,
        "binding_fingerprint": snapshot.request.binding_fingerprint,
        "tool": snapshot.request.tool,
        "target_id": snapshot.request.target_id,
        "state": format!("{:?}", snapshot.state),
        "cancellation_requested": snapshot.cancellation_requested,
        "connection_lost": snapshot.connection_lost,
        "earliest_history_seq": snapshot.earliest_history_seq,
        "next_event_seq": snapshot.next_event_seq
    })
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.as_bytes().contains(&0))
        .ok_or_else(|| {
            JsonlProviderError::Protocol(format!("provider field {field} is absent or invalid"))
        })
}

fn optional_string<'a>(value: &'a Value, field: &str) -> Result<Option<&'a str>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.as_bytes().contains(&0) => Ok(Some(value)),
        _ => Err(JsonlProviderError::Protocol(format!(
            "provider field {field} has an invalid shape"
        ))),
    }
}

fn validate_os_value(path: &PathBuf, label: &str, maximum: usize) -> Result<()> {
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

fn finish_child(child: &mut Child, pid: u32, grace: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now().checked_add(grace).unwrap_or_else(Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
            Err(error) => return Err(JsonlProviderError::Cleanup(error.to_string())),
        }
    }
    terminate_process_group(child, pid, grace)
}

fn terminate_process_group(child: &mut Child, pid: u32, grace: Duration) -> Result<ExitStatus> {
    send_group_signal(pid, libc::SIGTERM)?;
    let deadline = Instant::now().checked_add(grace).unwrap_or_else(Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
            Err(error) => return Err(JsonlProviderError::Cleanup(error.to_string())),
        }
    }
    send_group_signal(pid, libc::SIGKILL)?;
    child
        .wait()
        .map_err(|error| JsonlProviderError::Cleanup(error.to_string()))
}

fn send_group_signal(pid: u32, signal: i32) -> Result<()> {
    let group = i32::try_from(pid).map_err(|_| {
        JsonlProviderError::Cleanup("provider pid does not fit a process-group id".to_string())
    })?;
    if unsafe { libc::kill(-group, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(JsonlProviderError::Cleanup(format!(
            "provider process-group signal {signal} failed: {error}"
        )))
    }
}

fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hex_lower(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn invalid_config(message: impl Into<String>) -> JsonlProviderError {
    JsonlProviderError::InvalidConfiguration(message.into())
}

struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJson::deserialize(deserializer)
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJson)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJson(Value::String(value)))
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJson>()? {
            output.push(value.0);
        }
        Ok(UniqueJson(Value::Array(output)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if output.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key {key}")));
            }
            let value = map.next_value::<UniqueJson>()?;
            output.insert(key, value.0);
        }
        Ok(UniqueJson(Value::Object(output)))
    }
}

fn decode_strict_object(encoded: &[u8]) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(encoded);
    let UniqueJson(value) = UniqueJson::deserialize(&mut deserializer)
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
    if !value.is_object() {
        return Err(JsonlProviderError::Protocol(
            "provider JSONL record must be an object".to_string(),
        ));
    }
    Ok(value)
}
