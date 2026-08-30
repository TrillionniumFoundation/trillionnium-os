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
use std::io::Write;
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

use process::{ProviderOutput, finish_child, spawn_stderr_reader, spawn_stdout_reader};
use protocol::{
    decode_bound_tool_call, encode_tool_error, encode_tool_outcome, handle_provider_event,
    optional_string, required_string, validate_envelope,
};

pub const PROVIDER_PROTOCOL: &str = "trillionnium.owner-open.provider-jsonl.v1";
const PROVIDER_OUTPUT_DRAIN_GRACE_MINIMUM: Duration = Duration::from_secs(2);

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
            || self.max_stdout_bytes < self.max_line_bytes
            || self.max_event_count == 0
            || self.max_stderr_bytes == 0
            || self.output_queue_depth == 0
        {
            return Err(invalid_config(
                "provider duration/count/byte limits are invalid",
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
            self.config.max_stdout_bytes,
            sender,
        );
        let stderr_capture = Arc::new(Mutex::new(Vec::new()));
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
        let cleanup = finish_child(&mut child, pid, self.config.terminate_grace)
            .map_err(JsonlProviderError::Cleanup);
        drop(receiver);
        let stdout_join = stdout_thread.join();
        let stderr_join = stderr_thread.join();
        let stderr = stderr_capture
            .lock()
            .map_err(|_| JsonlProviderError::Cleanup("stderr capture was poisoned".to_string()))?
            .clone();

        // Preserve the first protocol/tool/provider error. Cleanup exists to
        // close the process tree, not to rewrite the semantic observation.
        let terminal = result?;
        if stdout_join.is_err() || stderr_join.is_err() {
            return Err(JsonlProviderError::Cleanup(
                "provider reader thread panicked".to_string(),
            ));
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

fn write_json_line(writer: &mut impl Write, value: &impl Serialize, maximum: usize) -> Result<()> {
    let encoded =
        serde_json::to_vec(value).map_err(|error| JsonlProviderError::Io(error.to_string()))?;
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

fn invalid_config(message: impl Into<String>) -> JsonlProviderError {
    JsonlProviderError::InvalidConfiguration(message.into())
}
