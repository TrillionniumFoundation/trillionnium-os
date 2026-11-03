use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, PAD, STANDARD as BASE64_STANDARD};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_call_registry::{CallKey, CallSnapshot};
use trillionnium_owner_open_runtime::{
    AdbExecRequest, ExecutionEvent, ExecutionEventKind, ExecutionTerminal,
    MAX_RUNTIME_REQUEST_TIMEOUT, PtySize, ShellExecRequest, ShellInvocation, StreamKind,
};
use trillionnium_owner_open_tool_bridge::{BoundToolCall, DirectToolRequest};
use trillionnium_owner_open_turn_loop::{ProviderEvent, ProviderHost, ToolOutcome, TurnRequest};
use trillionnium_owner_open_types::{
    MechanicalLimits as CodecLimits, PROTOCOL as DIRECT_PROTOCOL,
    PROTOCOL_VERSION as DIRECT_PROTOCOL_VERSION, ToolCall,
};

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

pub(crate) fn handle_provider_event(value: &Value, host: &mut ProviderHost<'_>) -> Result<()> {
    let event = required_string(value, "event")?;
    let converted = match event {
        "model.delta" => ProviderEvent::ModelDelta(required_string(value, "text")?.to_string()),
        "model.message" => ProviderEvent::ModelMessage(required_string(value, "text")?.to_string()),
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
    let raw_object = raw_call.as_object().ok_or_else(|| {
        JsonlProviderError::Protocol("tool.call call member must be an object".to_string())
    })?;
    validate_direct_protocol_fields(raw_object)?;
    let mut call: ToolCall = serde_json::from_value(raw_call.clone())
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
    normalize_stream_alias(&mut call)?;
    // Validate the wire shape before aliases are collapsed.  In particular,
    // this catches a conflicting target/target_id pair before one alias is
    // moved into the canonical target_id member.
    call.validate_mechanical(&CodecLimits::default())
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
    bind_scope(&mut call, turn)?;
    normalize_target_alias(&mut call)?;
    normalize_config_generation(&mut call, raw_object, config)?;
    normalize_mode(&mut call)?;
    let pty = normalize_pty(&mut call)?;
    call.stdin = normalize_stdin(call.stdin.as_ref())?;
    // Zero, null and omission all select the owner-configured timeout.  Keep
    // one explicit sentinel in the digest while retaining the runtime's
    // existing `None`/zero handling in decode_timeout.
    if call.timeout_ms.unwrap_or(0) == 0 {
        call.timeout_ms = Some(0);
    }
    // Streaming is the owner-open default.  The runtime may still buffer a
    // complete result for this provider revision, but the requested option is
    // part of the stable call identity.
    call.stream = Some(call.stream.unwrap_or(true));

    let claimed_request_sha256 = call.request_sha256.clone();
    let claimed_binding = call.binding_fingerprint.clone();
    call.request_sha256 = None;
    call.binding_fingerprint = None;
    let canonical_request = canonical_request_bytes(&call, raw_object)?;
    let binding_fingerprint = configuration_fingerprint(&call, config)?;
    if claimed_binding
        .as_deref()
        .is_some_and(|claimed| claimed != binding_fingerprint)
    {
        return Err(JsonlProviderError::Protocol(
            "tool.call binding_fingerprint does not match resolved configuration".to_string(),
        ));
    }

    let target_id = call.target_id.clone();
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
        Some(claimed) => BoundToolCall::with_claimed_digest_and_pty(
            key,
            binding_fingerprint,
            target_id,
            canonical_request,
            claimed,
            direct_request,
            pty,
        )
        .map_err(|error| JsonlProviderError::Protocol(error.to_string())),
        None => BoundToolCall::new_with_pty(
            key,
            binding_fingerprint,
            target_id,
            canonical_request,
            direct_request,
            pty,
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

pub(crate) fn encode_tool_error(seq: u64, call_id: &str, status: &str, error: &str) -> Value {
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

/// The provider JSONL envelope is a transport wrapper.  The request digest is
/// defined over the direct-tools request schema, so a provider may optionally
/// repeat that schema's protocol/version in its call object only when the
/// values agree with the generated owner-open constants.
fn validate_direct_protocol_fields(object: &Map<String, Value>) -> Result<()> {
    if let Some(protocol) = object.get("protocol")
        && protocol.as_str() != Some(DIRECT_PROTOCOL)
    {
        return Err(JsonlProviderError::Protocol(
            "tool.call protocol does not match direct-tools protocol".to_string(),
        ));
    }
    if let Some(version) = object.get("protocol_version") {
        let valid = match version {
            Value::Number(number) => number.as_u64() == Some(u64::from(DIRECT_PROTOCOL_VERSION)),
            Value::String(value) => value == &DIRECT_PROTOCOL_VERSION.to_string(),
            _ => false,
        };
        if !valid {
            return Err(JsonlProviderError::Protocol(
                "tool.call protocol_version does not match direct-tools protocol".to_string(),
            ));
        }
    }
    Ok(())
}

fn normalize_stream_alias(call: &mut ToolCall) -> Result<()> {
    let Some(alias) = call.extensions.remove("stream_id") else {
        return Ok(());
    };
    let alias = match alias {
        Value::Null => None,
        Value::String(value) if !value.is_empty() && !value.as_bytes().contains(&0) => Some(value),
        _ => {
            return Err(JsonlProviderError::Protocol(
                "tool.call stream_id alias has an invalid shape".to_string(),
            ));
        }
    };
    if let (Some(existing), Some(alias)) = (&call.turn_stream_id, &alias)
        && existing != alias
    {
        return Err(JsonlProviderError::Protocol(
            "tool.call stream_id conflicts with turn_stream_id".to_string(),
        ));
    }
    if call.turn_stream_id.is_none() {
        call.turn_stream_id = alias;
    }
    Ok(())
}

fn normalize_target_alias(call: &mut ToolCall) -> Result<()> {
    if let (Some(target), Some(target_id)) = (&call.target, &call.target_id)
        && target != target_id
    {
        return Err(JsonlProviderError::Protocol(
            "tool.call target conflicts with target_id".to_string(),
        ));
    }
    if call.target_id.is_none() {
        call.target_id = call.target.clone();
    }
    // `target_id` is the canonical spelling.  The original alias remains a
    // routing hint only and is not allowed to create a second digest identity.
    call.target = None;
    Ok(())
}

fn normalize_config_generation(
    call: &mut ToolCall,
    raw_object: &Map<String, Value>,
    config: &JsonlProviderConfig,
) -> Result<()> {
    let snapshot = config.config_generation.clone().unwrap_or(Value::Null);
    validate_generation_value(&snapshot)?;
    if raw_object.contains_key("config_generation") {
        let supplied = call.config_generation.clone().unwrap_or(Value::Null);
        validate_generation_value(&supplied)?;
        if supplied != snapshot {
            return Err(JsonlProviderError::Protocol(
                "tool.call config_generation conflicts with the active provider snapshot"
                    .to_string(),
            ));
        }
    }
    call.config_generation = Some(snapshot);
    Ok(())
}

fn validate_generation_value(value: &Value) -> Result<()> {
    match value {
        Value::Null => Ok(()),
        Value::Number(number) if number.as_i64().is_some() || number.as_u64().is_some() => Ok(()),
        Value::String(value) if !value.as_bytes().contains(&0) => Ok(()),
        _ => Err(JsonlProviderError::Protocol(
            "config_generation must be an integer, string or null".to_string(),
        )),
    }
}

fn normalize_mode(call: &mut ToolCall) -> Result<()> {
    if let Some(mode) = call.mode.as_deref()
        && !matches!(mode, "command" | "argv")
    {
        return Err(JsonlProviderError::Protocol(format!(
            "tool.call mode {mode:?} is unsupported"
        )));
    }
    let expected = match (&call.command, &call.argv) {
        (Some(_), None) => Some("command"),
        (None, Some(_)) => Some("argv"),
        _ => None,
    };
    let Some(expected) = expected else {
        // The tool-specific codec below reports the mutually-exclusive or
        // missing command/argv shape.  Do not manufacture a mode for it.
        return Ok(());
    };
    if let Some(mode) = call.mode.as_deref()
        && mode != expected
    {
        return Err(JsonlProviderError::Protocol(format!(
            "tool.call mode {mode:?} conflicts with the requested {expected} form"
        )));
    }
    call.mode = Some(expected.to_string());
    Ok(())
}

fn normalize_pty(call: &mut ToolCall) -> Result<Option<PtySize>> {
    let decoded = decode_pty(call.pty.as_ref())?;
    match decoded {
        Some(decoded) => {
            // An explicit env.TERM entry, including null/unset, wins over the
            // PTY object's term.  With no entry, materialize the owner default
            // into the effective process environment so the digest and the
            // launched process observe the same bytes.
            let effective_term = match call.env.get("TERM").cloned() {
                Some(Some(term)) => Value::String(term),
                Some(None) => Value::Null,
                None => {
                    call.env
                        .insert("TERM".to_string(), Some(decoded.term.clone()));
                    Value::String(decoded.term.clone())
                }
            };
            call.pty = Some(json!({
                "enabled": true,
                "rows": decoded.size.rows,
                "cols": decoded.size.cols,
                "term": effective_term
            }));
            Ok(Some(decoded.size))
        }
        None => {
            // Omitted, null and false are one disabled transport mode in the
            // provider protocol; use one explicit canonical spelling.
            call.pty = Some(Value::Bool(false));
            Ok(None)
        }
    }
}

fn shell_request(call: &ToolCall, config: &JsonlProviderConfig) -> Result<ShellExecRequest> {
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
        target_id: call.target_id.clone(),
        invocation,
        shell_executable: config.shell_executable.clone(),
        cwd: call.cwd.as_ref().map(PathBuf::from),
        env: call.env.clone(),
        stdin: decode_stdin(call.stdin.as_ref())?,
        timeout: decode_timeout(call.timeout_ms)?,
    })
}

fn adb_request(call: &ToolCall, config: &JsonlProviderConfig) -> Result<AdbExecRequest> {
    Ok(AdbExecRequest {
        call_id: call.call_id.clone(),
        target_id: call.target_id.clone(),
        argv: call
            .argv
            .clone()
            .ok_or_else(|| JsonlProviderError::Protocol("adb.exec has no argv".to_string()))?,
        adb_executable: config.adb_executable.clone(),
        cwd: call.cwd.as_ref().map(PathBuf::from),
        env: call.env.clone(),
        stdin: decode_stdin(call.stdin.as_ref())?,
        timeout: decode_timeout(call.timeout_ms)?,
    })
}

#[derive(Debug, Clone)]
struct DecodedPty {
    size: PtySize,
    term: String,
}

fn decode_pty(value: Option<&Value>) -> Result<Option<DecodedPty>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null | Value::Bool(false) => Ok(None),
        Value::Bool(true) => Ok(Some(DecodedPty {
            size: PtySize::default(),
            term: "xterm-256color".to_string(),
        })),
        Value::Object(object) => {
            let enabled = match object.get("enabled") {
                None => true,
                Some(Value::Bool(value)) => *value,
                Some(_) => {
                    return Err(JsonlProviderError::Protocol(
                        "pty.enabled must be boolean".to_string(),
                    ));
                }
            };
            let rows = decode_pty_dimension(object.get("rows"), "rows", 24)?;
            let cols = decode_pty_dimension(object.get("cols"), "cols", 80)?;
            if !enabled {
                return Ok(None);
            }
            let term = match object.get("term") {
                None | Some(Value::Null) => "xterm-256color".to_string(),
                Some(Value::String(value))
                    if !value.is_empty()
                        && value.len() <= 256
                        && !value.as_bytes().contains(&0)
                        && !value.chars().any(char::is_control) =>
                {
                    value.clone()
                }
                Some(_) => {
                    return Err(JsonlProviderError::Protocol(
                        "pty.term must be a non-empty control-free string".to_string(),
                    ));
                }
            };
            Ok(Some(DecodedPty {
                size: PtySize::new(rows, cols),
                term,
            }))
        }
        _ => Err(JsonlProviderError::Protocol(
            "pty must be boolean or object".to_string(),
        )),
    }
}

fn decode_pty_dimension(value: Option<&Value>, label: &str, default: u16) -> Result<u16> {
    let Some(value) = value else {
        return Ok(default);
    };
    let Some(value) = value.as_u64() else {
        return Err(JsonlProviderError::Protocol(format!(
            "pty.{label} must be an integer"
        )));
    };
    let value = u16::try_from(value).map_err(|_| {
        JsonlProviderError::Protocol(format!("pty.{label} is outside the u16 bound"))
    })?;
    if value == 0 {
        return Err(JsonlProviderError::Protocol(format!(
            "pty.{label} must be non-zero"
        )));
    }
    Ok(value)
}

fn decode_stdin(value: Option<&Value>) -> Result<Vec<u8>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(value) => Ok(value.as_bytes().to_vec()),
        Value::Object(object) => decode_stdin_data_object(object),
        _ => Err(JsonlProviderError::Protocol(
            "stdin has an unsupported shape".to_string(),
        )),
    }
}

fn decode_stdin_data_object(object: &Map<String, Value>) -> Result<Vec<u8>> {
    let encoding = object
        .get("encoding")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonlProviderError::Protocol("stdin object has no encoding".to_string()))?;
    let data = object
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| JsonlProviderError::Protocol("stdin object has no data".to_string()))?;
    match encoding {
        "utf8" | "utf-8" => Ok(data.as_bytes().to_vec()),
        "base64" => GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            PAD.with_decode_padding_mode(DecodePaddingMode::Indifferent),
        )
        .decode(data)
        .map_err(|error| JsonlProviderError::Protocol(format!("stdin base64 is invalid: {error}"))),
        other => Err(JsonlProviderError::Protocol(format!(
            "stdin encoding {other} is unsupported"
        ))),
    }
}

fn normalize_stdin(value: Option<&Value>) -> Result<Option<Value>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(Some(Value::Null)),
        Value::String(value) => Ok(Some(canonical_stdin_bytes(value.as_bytes()))),
        Value::Object(object) => {
            let has_encoding = object.contains_key("encoding");
            let has_data = object.contains_key("data");
            let has_fd = object.contains_key("fd_id");
            let has_spool = object.contains_key("spool_path");
            let data_variant = has_encoding || has_data;
            let descriptor_count = usize::from(has_fd) + usize::from(has_spool);
            if (data_variant && descriptor_count != 0) || descriptor_count > 1 {
                return Err(JsonlProviderError::Protocol(
                    "stdin data, fd_id and spool_path are mutually exclusive".to_string(),
                ));
            }
            if data_variant {
                let bytes = decode_stdin_data_object(object)?;
                let mut canonical = object.clone();
                canonical.insert("encoding".to_string(), Value::String("base64".to_string()));
                canonical.insert(
                    "data".to_string(),
                    Value::String(BASE64_STANDARD.encode(bytes)),
                );
                Ok(Some(Value::Object(canonical)))
            } else if descriptor_count != 0 {
                // The current direct process backend cannot dereference an
                // inherited FD or target spool path.  Preserve its descriptor
                // bytes for a truthful unsupported-mechanism result, while
                // normalizing the documented close-after default.
                let mut canonical = object.clone();
                canonical
                    .entry("close_after".to_string())
                    .or_insert(Value::Bool(true));
                Ok(Some(Value::Object(canonical)))
            } else {
                Err(JsonlProviderError::Protocol(
                    "stdin object has no supported data or descriptor variant".to_string(),
                ))
            }
        }
        _ => Err(JsonlProviderError::Protocol(
            "stdin has an unsupported shape".to_string(),
        )),
    }
}

fn canonical_stdin_bytes(bytes: &[u8]) -> Value {
    json!({
        "encoding": "base64",
        "data": BASE64_STANDARD.encode(bytes)
    })
}

// These members identify a transport instance or a caller-supplied digest;
// none describe the requested direct effect.  They are deliberately removed
// only at the top level of the ToolCall object.  Unknown extension members,
// including nested values, remain opaque and continue to participate in JCS.
const VOLATILE_CALL_MEMBERS: &[&str] = &[
    "call_id",
    "turn_stream_id",
    "stream_id",
    "connection_id",
    "event_id",
    "client_request_id",
    "server_request_id",
    "parent_turn_id",
    "continuation_of",
    "prior_connection_id",
    "resume_cursor",
    "resume_token",
    "seq",
    "client_seq",
    "host_seq",
    "timestamps",
    "frame_sha256",
    "request_sha256",
    "binding_fingerprint",
    "resolved_endpoint",
    "resolved_target",
];

fn canonical_request_bytes(call: &ToolCall, raw_object: &Map<String, Value>) -> Result<Vec<u8>> {
    let value = serde_json::to_value(call)
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))?;
    let mut object = value.as_object().cloned().ok_or_else(|| {
        JsonlProviderError::Protocol("normalized tool.call is not an object".to_string())
    })?;

    for member in VOLATILE_CALL_MEMBERS {
        object.remove(*member);
    }
    // The direct-tools schema has one canonical target spelling.  Explicit
    // null is retained when the caller sent only the alias; an omitted target
    // remains omitted, so a configured target is never invented here.
    if (raw_object.get("target").is_some_and(Value::is_null)
        || raw_object.get("target_id").is_some_and(Value::is_null))
        && !object.contains_key("target_id")
    {
        object.insert("target_id".to_string(), Value::Null);
    }
    // serde's skip-if-empty representation cannot distinguish an explicitly
    // supplied empty env object from omission.  Preserve that wire choice;
    // it is an extension-compatible value and costs no execution semantics.
    if raw_object.get("env").is_some_and(Value::is_object) && !object.contains_key("env") {
        object.insert("env".to_string(), raw_object["env"].clone());
    }
    // An explicit null cwd is meaningful under the schema's null-preservation
    // rule even though ToolCall stores it as None.
    if raw_object.get("cwd").is_some_and(Value::is_null) {
        object.insert("cwd".to_string(), Value::Null);
    }

    // Protocol/version belong to the direct request preimage (the enclosing
    // provider protocol is only a transport envelope).  Numeric version 1 is
    // canonical even when a caller supplied the equivalent string "1".
    object.insert(
        "protocol".to_string(),
        Value::String(DIRECT_PROTOCOL.to_string()),
    );
    object.insert(
        "protocol_version".to_string(),
        json!(DIRECT_PROTOCOL_VERSION),
    );

    serde_jcs::to_vec(&Value::Object(object))
        .map_err(|error| JsonlProviderError::Protocol(error.to_string()))
}

fn decode_timeout(value: Option<i64>) -> Result<Option<Duration>> {
    match value {
        None | Some(0) => Ok(None),
        Some(value) if value > 0 => {
            let timeout = Duration::from_millis(u64::try_from(value).map_err(|_| {
                JsonlProviderError::Protocol("timeout_ms is out of range".to_string())
            })?);
            if timeout > MAX_RUNTIME_REQUEST_TIMEOUT {
                return Err(JsonlProviderError::Protocol(format!(
                    "timeout_ms exceeds runtime hard bound {MAX_RUNTIME_REQUEST_TIMEOUT:?}"
                )));
            }
            Ok(Some(timeout))
        }
        Some(_) => Err(JsonlProviderError::Protocol(
            "timeout_ms must be nonnegative".to_string(),
        )),
    }
}

fn configuration_fingerprint(call: &ToolCall, config: &JsonlProviderConfig) -> Result<String> {
    let mut hasher = Sha256::new();
    hash_field(
        &mut hasher,
        b"schema",
        b"trillionnium.owner-open.binding.v1",
    );
    hash_field(&mut hasher, b"tool", call.tool.as_bytes());
    let executable = if call.tool == "adb.exec" {
        &config.adb_executable
    } else {
        &config.shell_executable
    };
    hash_field(
        &mut hasher,
        b"executable",
        executable.as_os_str().as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"config_generation",
        &serde_jcs::to_vec(&call.config_generation)
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
                StreamKind::Stderr => "stderr",
                StreamKind::Pty => "pty",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn turn() -> TurnRequest {
        TurnRequest {
            session_id: "session-protocol-test".to_string(),
            profile_id: "owner-open".to_string(),
            task_id: "task-protocol-test".to_string(),
            turn_id: "turn-protocol-test".to_string(),
            turn_stream_id: "stream-protocol-test".to_string(),
            user_input: "test".to_string(),
        }
    }

    #[test]
    fn equivalent_pty_spellings_have_one_canonical_digest() {
        let config = JsonlProviderConfig::default();
        let boolean = json!({
            "call": {
                "call_id": "call-pty-normalized",
                "tool": "shell.exec",
                "command": "printf ok",
                "pty": true
            }
        });
        let object = json!({
            "call": {
                "call_id": "call-pty-normalized",
                "tool": "shell.exec",
                "command": "printf ok",
                "pty": {"enabled": true, "rows": 24, "cols": 80, "term": "xterm-256color"}
            }
        });
        let first = decode_bound_tool_call(&boolean, &turn(), &config).unwrap();
        let second = decode_bound_tool_call(&object, &turn(), &config).unwrap();
        assert_eq!(first.canonical_request, second.canonical_request);
        assert_eq!(first.request_sha256, second.request_sha256);
        assert_eq!(first.pty, second.pty);
    }

    #[test]
    fn explicit_null_term_wins_and_stays_in_the_digest() {
        let config = JsonlProviderConfig::default();
        let call = json!({
            "call": {
                "call_id": "call-pty-unset-term",
                "tool": "shell.exec",
                "command": "printf ok",
                "env": {"TERM": null},
                "pty": {"enabled": true}
            }
        });
        let bound = decode_bound_tool_call(&call, &turn(), &config).unwrap();
        let canonical: Value = serde_json::from_slice(&bound.canonical_request).unwrap();
        assert_eq!(canonical["env"]["TERM"], Value::Null);
        assert_eq!(canonical["pty"]["term"], Value::Null);
    }

    #[test]
    fn explicit_null_target_aliases_have_one_canonical_member() {
        let config = JsonlProviderConfig::default();
        let call = json!({
            "call": {
                "call_id": "call-null-target",
                "tool": "shell.exec",
                "command": "printf ok",
                "target": null,
                "target_id": null
            }
        });
        let bound = decode_bound_tool_call(&call, &turn(), &config).unwrap();
        let canonical: Value = serde_json::from_slice(&bound.canonical_request).unwrap();
        assert_eq!(canonical["target_id"], Value::Null);
        assert!(canonical.get("target").is_none());
    }

    #[test]
    fn request_timeout_decode_enforces_the_runtime_hard_bound() {
        let maximum_millis = i64::try_from(MAX_RUNTIME_REQUEST_TIMEOUT.as_millis())
            .expect("runtime timeout bound fits the provider protocol integer");
        assert_eq!(
            decode_timeout(Some(maximum_millis)).unwrap(),
            Some(MAX_RUNTIME_REQUEST_TIMEOUT)
        );
        let error = decode_timeout(Some(maximum_millis + 1))
            .expect_err("provider timeout above the runtime bound must fail closed");
        assert!(error.to_string().contains("timeout_ms"));
        assert_eq!(decode_timeout(Some(0)).unwrap(), None);
    }
}
