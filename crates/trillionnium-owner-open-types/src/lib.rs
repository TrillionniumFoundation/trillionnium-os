//! Mechanism-only codec and validation types for the owner-open Direct Agent Host.
//!
//! This crate is deliberately isolated from the legacy plan, Authority,
//! capability-lease, privilege-broker and typed shell/ADB closures. Validation
//! is limited to framing, correlation shape, byte representation and finite
//! resource bounds. It must not classify commands, inject targets, require
//! semantic approval or rewrite tool arguments.

mod generated;

pub use generated::*;

use std::collections::BTreeMap;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const PROTOCOL: &str = "trillionnium.agent.turn.v1";
pub const PROTOCOL_VERSION: u32 = 1;

pub const FRAME_HELLO: &str = "hello";
pub const FRAME_HELLO_ACK: &str = "hello.ack";
pub const FRAME_TURN_START: &str = "turn.start";
pub const FRAME_TURN_ACCEPTED: &str = "turn.accepted";
pub const FRAME_TURN_CANCEL: &str = "turn.cancel";
pub const FRAME_TURN_END: &str = "turn.end";
pub const FRAME_TOOL_CALL: &str = "tool.call";
pub const FRAME_TOOL_ACCEPTED: &str = "tool.accepted";
pub const FRAME_TOOL_STARTED: &str = "tool.started";
pub const FRAME_TOOL_STDOUT: &str = "tool.stdout";
pub const FRAME_TOOL_STDERR: &str = "tool.stderr";
pub const FRAME_TOOL_RESULT: &str = "tool.result";
pub const FRAME_TOOL_CANCEL: &str = "tool.cancel";
pub const FRAME_STREAM_WINDOW_UPDATE: &str = "stream.window_update";
pub const FRAME_STREAM_PAUSE: &str = "stream.pause";
pub const FRAME_STREAM_RESUME: &str = "stream.resume";

/// Finite parser and process ceilings. These are liveness constraints, not
/// semantic permissions. An owner profile may select other finite values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MechanicalLimits {
    pub max_frame_bytes: usize,
    pub max_label_bytes: usize,
    pub max_id_bytes: usize,
    pub max_user_input_bytes: usize,
    pub max_command_bytes: usize,
    pub max_argv_items: usize,
    pub max_argument_bytes: usize,
    pub max_total_argv_bytes: usize,
    pub max_env_items: usize,
    pub max_env_key_bytes: usize,
    pub max_env_value_bytes: usize,
}

impl Default for MechanicalLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_label_bytes: 256,
            max_id_bytes: 256,
            max_user_input_bytes: 1024 * 1024,
            max_command_bytes: 256 * 1024,
            max_argv_items: 4096,
            max_argument_bytes: 64 * 1024,
            max_total_argv_bytes: 1024 * 1024,
            max_env_items: 4096,
            max_env_key_bytes: 4096,
            max_env_value_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("frame_boundary: {0}")]
    FrameBoundary(&'static str),
    #[error("invalid_json: {0}")]
    InvalidJson(String),
    #[error("invalid_frame: {0}")]
    InvalidFrame(String),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunTurnFrame {
    pub kind: String,
    pub seq: u64,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl RunTurnFrame {
    pub fn decode(encoded: &[u8], limits: &MechanicalLimits) -> Result<Self> {
        decode_strict_frame(encoded, limits)
    }

    pub fn validate_mechanical(&self, limits: &MechanicalLimits) -> Result<()> {
        validate_label("kind", &self.kind, limits.max_label_bytes)?;
        if !self.payload.is_object() {
            return Err(invalid("payload must be a JSON object"));
        }
        if let Some(direction) = self.direction.as_deref() {
            if !matches!(direction, "client_to_host" | "host_to_client") {
                return Err(invalid("direction is not a supported transport role"));
            }
        }
        validate_optional_digest("frame_sha256", self.frame_sha256.as_deref())?;
        for (name, value) in [
            ("event_id", self.event_id.as_deref()),
            ("connection_id", self.connection_id.as_deref()),
            ("stream_id", self.stream_id.as_deref()),
            ("turn_stream_id", self.turn_stream_id.as_deref()),
            ("session_id", self.session_id.as_deref()),
            ("profile_id", self.profile_id.as_deref()),
            ("task_id", self.task_id.as_deref()),
            ("turn_id", self.turn_id.as_deref()),
            ("call_id", self.call_id.as_deref()),
            ("job_id", self.job_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_id(name, value, limits.max_id_bytes)?;
            }
        }
        for (name, value) in [
            ("tool", self.tool.as_deref()),
            ("target", self.target.as_deref()),
            ("target_id", self.target_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_label(name, value, limits.max_label_bytes)?;
            }
        }
        validate_alias_pair(
            "stream_id",
            self.stream_id.as_deref(),
            "turn_stream_id",
            self.turn_stream_id.as_deref(),
        )?;
        validate_alias_pair(
            "target",
            self.target.as_deref(),
            "target_id",
            self.target_id.as_deref(),
        )?;
        Ok(())
    }

    pub fn turn_request(&self, limits: &MechanicalLimits) -> Result<RunTurnRequest> {
        if self.kind != FRAME_TURN_START {
            return Err(invalid("frame kind is not turn.start"));
        }
        let request: RunTurnRequest = serde_json::from_value(self.payload.clone())
            .map_err(|error| invalid(format!("invalid turn.start payload: {error}")))?;
        request.validate_mechanical(limits)?;
        validate_mirrored_id("session_id", self.session_id.as_deref(), &request.session_id)?;
        validate_mirrored_id("task_id", self.task_id.as_deref(), &request.task_id)?;
        validate_mirrored_id("turn_id", self.turn_id.as_deref(), &request.turn_id)?;
        if let Some(profile_id) = self.profile_id.as_deref() {
            if profile_id != request.effective_profile_id() {
                return Err(invalid(
                    "envelope profile_id conflicts with payload profile_id",
                ));
            }
        }
        Ok(request)
    }

    pub fn turn_cancel(&self, limits: &MechanicalLimits) -> Result<TurnCancelRequest> {
        if self.kind != FRAME_TURN_CANCEL {
            return Err(invalid("frame kind is not turn.cancel"));
        }
        let request: TurnCancelRequest = serde_json::from_value(self.payload.clone())
            .map_err(|error| invalid(format!("invalid turn.cancel payload: {error}")))?;
        request.validate_mechanical(limits)?;
        validate_mirrored_id("session_id", self.session_id.as_deref(), &request.session_id)?;
        validate_mirrored_id("turn_id", self.turn_id.as_deref(), &request.turn_id)?;
        validate_optional_alias(
            "profile_id",
            self.profile_id.as_deref(),
            request.profile_id.as_deref(),
        )?;
        validate_optional_alias(
            "task_id",
            self.task_id.as_deref(),
            request.task_id.as_deref(),
        )?;
        validate_alias_pair(
            "turn_stream_id",
            self.turn_stream_id.as_deref().or(self.stream_id.as_deref()),
            "payload.turn_stream_id",
            request.turn_stream_id.as_deref(),
        )?;
        Ok(request)
    }

    pub fn tool_call(&self, limits: &MechanicalLimits) -> Result<ToolCall> {
        if self.kind != FRAME_TOOL_CALL {
            return Err(invalid("frame kind is not tool.call"));
        }
        let call: ToolCall = serde_json::from_value(self.payload.clone())
            .map_err(|error| invalid(format!("invalid tool.call payload: {error}")))?;
        call.validate_mechanical(limits)?;
        validate_mirrored_id("call_id", self.call_id.as_deref(), &call.call_id)?;
        validate_mirrored_id("tool", self.tool.as_deref(), &call.tool)?;
        Ok(call)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunTurnRequest {
    pub protocol: String,
    pub protocol_version: Value,
    pub session_id: String,
    pub task_id: String,
    pub turn_id: String,
    pub user_input: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_generation: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_request_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_cursor: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_connection_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_of: Option<String>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl RunTurnRequest {
    pub fn validate_mechanical(&self, limits: &MechanicalLimits) -> Result<()> {
        if self.protocol != PROTOCOL {
            return Err(invalid("unsupported turn protocol"));
        }
        validate_protocol_version(&self.protocol_version)?;
        validate_id("session_id", &self.session_id, limits.max_id_bytes)?;
        validate_id("task_id", &self.task_id, limits.max_id_bytes)?;
        validate_id("turn_id", &self.turn_id, limits.max_id_bytes)?;
        if self.user_input.len() > limits.max_user_input_bytes {
            return Err(invalid("user_input exceeds the configured byte bound"));
        }
        if self.user_input.contains('\0') {
            return Err(invalid("user_input contains NUL"));
        }
        for (name, value) in [
            ("profile_id", self.profile_id.as_deref()),
            ("context_ref", self.context_ref.as_deref()),
            ("client_request_id", self.client_request_id.as_deref()),
            ("server_request_id", self.server_request_id.as_deref()),
            ("resume_token", self.resume_token.as_deref()),
            ("prior_connection_id", self.prior_connection_id.as_deref()),
            ("parent_turn_id", self.parent_turn_id.as_deref()),
            ("continuation_of", self.continuation_of.as_deref()),
        ] {
            if let Some(value) = value {
                validate_id(name, value, limits.max_id_bytes)?;
            }
        }
        validate_optional_digest("turn_request_sha256", self.turn_request_sha256.as_deref())?;
        validate_alias_pair(
            "parent_turn_id",
            self.parent_turn_id.as_deref(),
            "continuation_of",
            self.continuation_of.as_deref(),
        )?;
        validate_resume_pair(self.resume_cursor.as_ref(), self.resume_token.as_deref())?;
        if self.prior_connection_id.is_some()
            && self.resume_cursor.is_none()
            && self.resume_token.is_none()
        {
            return Err(invalid(
                "prior_connection_id requires exactly one resume cursor or token",
            ));
        }
        Ok(())
    }

    pub fn effective_profile_id(&self) -> &str {
        self.profile_id.as_deref().unwrap_or(DEFAULT_PROFILE_ID)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TurnCancelRequest {
    pub session_id: String,
    pub turn_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_stream_id: Option<String>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl TurnCancelRequest {
    pub fn validate_mechanical(&self, limits: &MechanicalLimits) -> Result<()> {
        validate_id("session_id", &self.session_id, limits.max_id_bytes)?;
        validate_id("turn_id", &self.turn_id, limits.max_id_bytes)?;
        for (name, value) in [
            ("profile_id", self.profile_id.as_deref()),
            ("task_id", self.task_id.as_deref()),
            ("turn_stream_id", self.turn_stream_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_id(name, value, limits.max_id_bytes)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub call_id: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_stream_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_generation: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argv: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, Option<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pty: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ToolCall {
    pub fn validate_mechanical(&self, limits: &MechanicalLimits) -> Result<()> {
        validate_id("call_id", &self.call_id, limits.max_id_bytes)?;
        validate_label("tool", &self.tool, limits.max_label_bytes)?;
        for (name, value) in [
            ("session_id", self.session_id.as_deref()),
            ("profile_id", self.profile_id.as_deref()),
            ("task_id", self.task_id.as_deref()),
            ("turn_id", self.turn_id.as_deref()),
            ("turn_stream_id", self.turn_stream_id.as_deref()),
        ] {
            if let Some(value) = value {
                validate_id(name, value, limits.max_id_bytes)?;
            }
        }
        validate_optional_digest("request_sha256", self.request_sha256.as_deref())?;
        validate_optional_digest(
            "binding_fingerprint",
            self.binding_fingerprint.as_deref(),
        )?;
        for (name, value) in [
            ("target", self.target.as_deref()),
            ("target_id", self.target_id.as_deref()),
            ("mode", self.mode.as_deref()),
        ] {
            if let Some(value) = value {
                validate_label(name, value, limits.max_label_bytes)?;
            }
        }
        validate_alias_pair(
            "target",
            self.target.as_deref(),
            "target_id",
            self.target_id.as_deref(),
        )?;
        if self.timeout_ms.is_some_and(|value| value < 0) {
            return Err(invalid("timeout_ms must be nonnegative"));
        }
        if let Some(cwd) = self.cwd.as_deref() {
            if cwd.contains('\0') {
                return Err(invalid("cwd contains NUL"));
            }
        }
        validate_env(&self.env, limits)?;
        if let Some(command) = self.command.as_deref() {
            validate_command(command, limits)?;
        }
        if let Some(argv) = self.argv.as_deref() {
            validate_argv(argv, limits)?;
        }
        Ok(())
    }

    /// Validate only the wire shape for `shell.exec`. No allowlist, target
    /// substitution, risk class or approval decision is performed.
    pub fn validate_shell_exec(&self, limits: &MechanicalLimits) -> Result<()> {
        self.validate_mechanical(limits)?;
        if self.tool != "shell.exec" {
            return Err(invalid("shell.exec codec requires tool=shell.exec"));
        }
        match (&self.command, &self.argv) {
            (Some(_), None) | (None, Some(_)) => Ok(()),
            (None, None) => Err(invalid("shell.exec requires command or argv")),
            (Some(_), Some(_)) => Err(invalid(
                "shell.exec command and argv are mutually exclusive",
            )),
        }
    }

    /// Validate only the wire shape for `adb.exec`. Unknown and future ADB
    /// subcommands stay valid, and no serial/host/port/privilege is injected.
    pub fn validate_adb_exec(&self, limits: &MechanicalLimits) -> Result<()> {
        self.validate_mechanical(limits)?;
        if self.tool != "adb.exec" {
            return Err(invalid("adb.exec codec requires tool=adb.exec"));
        }
        if self.command.is_some() {
            return Err(invalid("adb.exec accepts argv, not command"));
        }
        if self.argv.is_none() {
            return Err(invalid("adb.exec requires argv"));
        }
        Ok(())
    }
}

pub fn decode_strict_frame(encoded: &[u8], limits: &MechanicalLimits) -> Result<RunTurnFrame> {
    if encoded.is_empty() {
        return Err(ProtocolError::FrameBoundary("frame is empty"));
    }
    if encoded.len() > limits.max_frame_bytes {
        return Err(ProtocolError::FrameBoundary(
            "frame exceeds the configured byte bound",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(encoded);
    let UniqueJson(value) = UniqueJson::deserialize(&mut deserializer)
        .map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| ProtocolError::InvalidJson(error.to_string()))?;
    let frame: RunTurnFrame = serde_json::from_value(value)
        .map_err(|error| invalid(format!("invalid frame envelope: {error}")))?;
    frame.validate_mechanical(limits)?;
    Ok(frame)
}

fn validate_protocol_version(value: &Value) -> Result<()> {
    match value {
        Value::Number(number) if number.as_u64() == Some(u64::from(PROTOCOL_VERSION)) => Ok(()),
        Value::String(version) if version == &PROTOCOL_VERSION.to_string() => Ok(()),
        _ => Err(invalid("unsupported protocol_version")),
    }
}

fn validate_resume_pair(cursor: Option<&Value>, token: Option<&str>) -> Result<()> {
    if cursor.is_some() && token.is_some() {
        return Err(invalid(
            "resume_cursor and resume_token are mutually exclusive",
        ));
    }
    if let Some(cursor) = cursor {
        match cursor {
            Value::Number(number) if number.as_u64().is_some() => {}
            Value::String(value)
                if !value.is_empty() && !value.chars().any(char::is_control) => {}
            _ => return Err(invalid("resume_cursor has an invalid shape")),
        }
    }
    Ok(())
}

fn validate_mirrored_id(name: &str, envelope: Option<&str>, payload: &str) -> Result<()> {
    if envelope.is_some_and(|value| value != payload) {
        return Err(invalid(format!(
            "envelope {name} conflicts with payload {name}"
        )));
    }
    Ok(())
}

fn validate_optional_alias(name: &str, first: Option<&str>, second: Option<&str>) -> Result<()> {
    if let (Some(first), Some(second)) = (first, second) {
        if first != second {
            return Err(invalid(format!(
                "envelope {name} conflicts with payload {name}"
            )));
        }
    }
    Ok(())
}

fn validate_alias_pair(
    first_name: &str,
    first: Option<&str>,
    second_name: &str,
    second: Option<&str>,
) -> Result<()> {
    if let (Some(first), Some(second)) = (first, second) {
        if first != second {
            return Err(invalid(format!(
                "{first_name} conflicts with alias {second_name}"
            )));
        }
    }
    Ok(())
}

fn validate_optional_digest(name: &str, value: Option<&str>) -> Result<()> {
    if value.is_some_and(|value| !is_lower_sha256(value)) {
        return Err(invalid(format!("{name} must be a lowercase SHA-256")));
    }
    Ok(())
}

fn validate_command(command: &str, limits: &MechanicalLimits) -> Result<()> {
    if command.is_empty() {
        return Err(invalid("command is empty"));
    }
    if command.len() > limits.max_command_bytes {
        return Err(invalid("command exceeds the configured byte bound"));
    }
    if command.contains('\0') {
        return Err(invalid("command contains NUL"));
    }
    Ok(())
}

fn validate_argv(argv: &[String], limits: &MechanicalLimits) -> Result<()> {
    if argv.is_empty() {
        return Err(invalid("argv is empty"));
    }
    if argv.len() > limits.max_argv_items {
        return Err(invalid("argv exceeds the configured item bound"));
    }
    let mut total = 0usize;
    for argument in argv {
        if argument.len() > limits.max_argument_bytes {
            return Err(invalid("argv element exceeds the configured byte bound"));
        }
        if argument.contains('\0') {
            return Err(invalid("argv element contains NUL"));
        }
        total = total
            .checked_add(argument.len())
            .ok_or_else(|| invalid("argv byte count overflow"))?;
        if total > limits.max_total_argv_bytes {
            return Err(invalid("argv exceeds the configured total byte bound"));
        }
    }
    Ok(())
}

fn validate_env(env: &BTreeMap<String, Option<String>>, limits: &MechanicalLimits) -> Result<()> {
    if env.len() > limits.max_env_items {
        return Err(invalid("env exceeds the configured item bound"));
    }
    for (key, value) in env {
        if key.is_empty()
            || key.len() > limits.max_env_key_bytes
            || key.contains('\0')
            || key.contains('=')
        {
            return Err(invalid("env key is not mechanically representable"));
        }
        if value.as_deref().is_some_and(|value| {
            value.len() > limits.max_env_value_bytes || value.contains('\0')
        }) {
            return Err(invalid("env value is not mechanically representable"));
        }
    }
    Ok(())
}

fn validate_label(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(invalid(format!(
            "{name} is empty, oversized, or contains control bytes"
        )));
    }
    Ok(())
}

fn validate_id(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    validate_label(name, value, max_bytes)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn invalid(message: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidFrame(message.into())
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_tool_call() -> ToolCall {
        ToolCall {
            call_id: "call-1".to_string(),
            tool: "shell.exec".to_string(),
            session_id: Some("session-1".to_string()),
            profile_id: Some(DEFAULT_PROFILE_ID.to_string()),
            task_id: Some("task-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            turn_stream_id: Some("stream-1".to_string()),
            request_sha256: None,
            binding_fingerprint: None,
            target: Some("rootlinux".to_string()),
            target_id: None,
            mode: None,
            config_generation: None,
            command: None,
            argv: None,
            cwd: None,
            env: BTreeMap::new(),
            stdin: None,
            timeout_ms: Some(0),
            pty: None,
            stream: Some(true),
            extensions: BTreeMap::new(),
        }
    }

    #[test]
    fn strict_decoder_rejects_duplicate_members_recursively() {
        let encoded = br#"{
          "kind":"tool.call",
          "seq":1,
          "payload":{"call_id":"one","call_id":"two","tool":"shell.exec","command":"pwd"}
        }"#;
        let error = RunTurnFrame::decode(encoded, &MechanicalLimits::default()).unwrap_err();
        assert!(error.to_string().contains("duplicate key call_id"));
    }

    #[test]
    fn frame_extensions_round_trip_without_becoming_policy() {
        let encoded = br#"{
          "kind":"tool.call",
          "seq":7,
          "payload":{"call_id":"call-7","tool":"vendor.future.exec","argv":["future"]},
          "vendor_trace":{"opaque":true}
        }"#;
        let frame = RunTurnFrame::decode(encoded, &MechanicalLimits::default()).unwrap();
        assert_eq!(frame.extensions["vendor_trace"], json!({"opaque": true}));
        assert_eq!(
            serde_json::to_value(frame).unwrap()["vendor_trace"],
            json!({"opaque": true})
        );
    }

    #[test]
    fn shell_command_and_argv_are_first_class_and_mutually_exclusive() {
        let limits = MechanicalLimits::default();
        let mut call = base_tool_call();
        call.command = Some("printf 'owner-open\\n'".to_string());
        call.validate_shell_exec(&limits).unwrap();
        call.command = None;
        call.argv = Some(vec!["/bin/printf".to_string(), "owner-open\\n".to_string()]);
        call.validate_shell_exec(&limits).unwrap();
        call.command = Some("pwd".to_string());
        assert!(call.validate_shell_exec(&limits).is_err());
    }

    #[test]
    fn adb_unknown_subcommands_and_absent_target_are_transport_valid() {
        let limits = MechanicalLimits::default();
        let mut call = base_tool_call();
        call.tool = "adb.exec".to_string();
        call.target = None;
        call.argv = Some(vec![
            "future-subcommand".to_string(),
            "--future-flag".to_string(),
        ]);
        call.validate_adb_exec(&limits).unwrap();
    }

    #[test]
    fn no_serial_host_port_or_privilege_is_injected_by_the_codec() {
        let call: ToolCall = serde_json::from_value(json!({
            "call_id": "adb-call",
            "tool": "adb.exec",
            "argv": ["shell", "id"]
        }))
        .unwrap();
        call.validate_adb_exec(&MechanicalLimits::default()).unwrap();
        assert_eq!(
            call.argv.unwrap(),
            vec!["shell".to_string(), "id".to_string()]
        );
        assert!(call.target.is_none());
        assert!(call.target_id.is_none());
    }

    #[test]
    fn turn_start_requires_exact_mirrored_correlation_when_present() {
        let frame = RunTurnFrame {
            kind: FRAME_TURN_START.to_string(),
            seq: 1,
            payload: json!({
                "protocol": PROTOCOL,
                "protocol_version": 1,
                "session_id": "session-a",
                "task_id": "task-a",
                "turn_id": "turn-a",
                "user_input": "run pwd"
            }),
            direction: Some("client_to_host".to_string()),
            client_seq: Some(1),
            host_seq: None,
            frame_sha256: None,
            event_id: None,
            connection_id: None,
            stream_id: None,
            turn_stream_id: None,
            session_id: Some("session-b".to_string()),
            profile_id: None,
            task_id: None,
            turn_id: None,
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        };
        let error = frame.turn_request(&MechanicalLimits::default()).unwrap_err();
        assert!(error.to_string().contains("envelope session_id conflicts"));
    }

    #[test]
    fn resource_limits_are_mechanical_not_semantic() {
        let mut limits = MechanicalLimits::default();
        limits.max_total_argv_bytes = 3;
        let mut call = base_tool_call();
        call.argv = Some(vec!["abcd".to_string()]);
        let error = call.validate_shell_exec(&limits).unwrap_err();
        assert!(error.to_string().contains("argv exceeds"));
    }

    #[test]
    fn turn_cancel_is_typed_and_correlation_bound() {
        let frame = RunTurnFrame {
            kind: FRAME_TURN_CANCEL.to_string(),
            seq: 2,
            payload: json!({
                "session_id": "session-a",
                "turn_id": "turn-a",
                "turn_stream_id": "stream-a"
            }),
            direction: Some("client_to_host".to_string()),
            client_seq: Some(2),
            host_seq: None,
            frame_sha256: None,
            event_id: None,
            connection_id: None,
            stream_id: Some("stream-a".to_string()),
            turn_stream_id: None,
            session_id: Some("session-a".to_string()),
            profile_id: None,
            task_id: None,
            turn_id: Some("turn-a".to_string()),
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        };
        let cancel = frame.turn_cancel(&MechanicalLimits::default()).unwrap();
        assert_eq!(cancel.turn_stream_id.as_deref(), Some("stream-a"));
    }

    #[test]
    fn aliases_must_not_conflict() {
        let frame = RunTurnFrame {
            kind: FRAME_HELLO.to_string(),
            seq: 0,
            payload: json!({}),
            direction: None,
            client_seq: None,
            host_seq: None,
            frame_sha256: None,
            event_id: None,
            connection_id: None,
            stream_id: Some("stream-a".to_string()),
            turn_stream_id: Some("stream-b".to_string()),
            session_id: None,
            profile_id: None,
            task_id: None,
            turn_id: None,
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: BTreeMap::new(),
        };
        assert!(frame.validate_mechanical(&MechanicalLimits::default()).is_err());
    }
}
