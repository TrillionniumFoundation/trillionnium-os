use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_call_registry::{CallKey, CallSnapshot};
use trillionnium_owner_open_runtime::{
    AdbExecRequest, ExecutionEvent, ExecutionEventKind, ExecutionTerminal, ShellExecRequest,
    ShellInvocation, StreamKind,
};
use trillionnium_owner_open_tool_bridge::{BoundToolCall, DirectToolRequest};
use trillionnium_owner_open_turn_loop::{ProviderEvent, ProviderHost, ToolOutcome, TurnRequest};
use trillionnium_owner_open_types::{MechanicalLimits as CodecLimits, ToolCall};

use super::{JsonlProviderConfig, JsonlProviderError, PROVIDER_PROTOCOL, Result};

pub(crate) fn validate_envelope(value: &Value, expected_seq: u64) -> Result<()> {
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

pub(crate) fn handle_provider_event(
    value: &Value,
    host: &mut ProviderHost<'_>,
) -> Result<()> {
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

pub(crate) fn decode_bound_tool_call(
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

pub(crate) fn encode_tool_outcome(seq: u64, call_id: &str, outcome: ToolOutcome) -> Value {
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

pub(crate) fn encode_tool_error(
    seq: u64,
    call_id: &str,
    status: &str,
    error: &str,
) -> Value {
    json!({
        "protocol": PROVIDER_PROTOCOL,
        "kind": "tool.result",
        "seq": seq,
        "call_id": call_id,
        "status": status,
        "error": error
    })
}

pub(crate) fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.as_bytes().contains(&0))
        .ok_or_else(|| {
            JsonlProviderError::Protocol(format!("provider field {field} is absent or invalid"))
        })
}

pub(crate) fn optional_string<'a>(value: &'a Value, field: &str) -> Result<Option<&'a str>> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.as_bytes().contains(&0) => Ok(Some(value)),
        _ => Err(JsonlProviderError::Protocol(format!(
            "provider field {field} has an invalid shape"
        ))),
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
        "call_id": &event.call_id,
        "target_id": &event.target_id,
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
        "error": &terminal.error
    })
}

fn encode_snapshot(snapshot: &CallSnapshot) -> Value {
    json!({
        "call_id": &snapshot.key.call_id,
        "request_sha256": &snapshot.request.request_sha256,
        "binding_fingerprint": &snapshot.request.binding_fingerprint,
        "tool": &snapshot.request.tool,
        "target_id": &snapshot.request.target_id,
        "state": format!("{:?}", snapshot.state),
        "cancellation_requested": snapshot.cancellation_requested,
        "connection_lost": snapshot.connection_lost,
        "earliest_history_seq": snapshot.earliest_history_seq,
        "next_event_seq": snapshot.next_event_seq
    })
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
