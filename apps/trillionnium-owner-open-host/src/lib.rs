//! Minimal mechanism-only owner-open Direct Agent Host.
//!
//! The default provider is intentionally unavailable. Source presence must not
//! be confused with a live Codex turn, shell effect, ADB effect, or Android
//! integration. Legacy plan/Authority/broker crates are not dependencies.

use serde_json::{Value, json};
use thiserror::Error;
use trillionnium_owner_open_types::{
    DEFAULT_PROFILE_ID, FRAME_HELLO, FRAME_HELLO_ACK, FRAME_TURN_ACCEPTED,
    FRAME_TURN_CANCEL, FRAME_TURN_END, FRAME_TURN_START, MechanicalLimits, PROTOCOL,
    PROTOCOL_VERSION, RunTurnFrame, RunTurnRequest,
};

pub const FRAME_HOST_ERROR: &str = "host.error";
pub const FRAME_PROVIDER_STATUS: &str = "provider.status";
pub const FRAME_MODEL_DELTA: &str = "model.delta";
pub const FRAME_MODEL_MESSAGE: &str = "model.message";
pub const HOST_IMPLEMENTATION: &str = "trillionnium-owner-open-host-r4-foundation";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HostError {
    #[error("invalid_frame: {0}")]
    InvalidFrame(String),
    #[error("connection_state: {0}")]
    ConnectionState(String),
}

impl HostError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidFrame(_) => "invalid_frame",
            Self::ConnectionState(_) => "connection_state",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnContext {
    pub connection_id: String,
    pub turn_stream_id: String,
    pub session_id: String,
    pub profile_id: String,
    pub task_id: String,
    pub turn_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProviderEvent {
    Status { status: String, detail: Option<String> },
    ModelDelta { text: String },
    ModelMessage { text: String },
    Extension { label: String, payload: Value },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderTerminalStatus {
    Completed,
    Cancelled,
    ProviderUnavailable,
    Failed,
}

impl ProviderTerminalStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTerminal {
    pub status: ProviderTerminalStatus,
    pub summary: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProviderRun {
    pub events: Vec<ProviderEvent>,
    pub terminal: ProviderTerminal,
}

/// The future Codex adapter implements this boundary. The Host owns transport,
/// correlation and process/event mechanics; the provider owns model semantics
/// and tool selection. Events are observations, not hidden approval decisions.
pub trait TurnProvider {
    fn run_turn(&mut self, request: &RunTurnRequest, context: &TurnContext) -> ProviderRun;

    fn cancel_turn(&mut self, _context: &TurnContext) -> ProviderTerminal {
        ProviderTerminal {
            status: ProviderTerminalStatus::Cancelled,
            summary: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnavailableProvider {
    reason: String,
}

impl UnavailableProvider {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl Default for UnavailableProvider {
    fn default() -> Self {
        Self::new("Codex provider bridge is not wired in the r4 foundation build")
    }
}

impl TurnProvider for UnavailableProvider {
    fn run_turn(&mut self, _request: &RunTurnRequest, _context: &TurnContext) -> ProviderRun {
        ProviderRun {
            events: vec![ProviderEvent::Status {
                status: "provider_unavailable".to_string(),
                detail: Some(self.reason.clone()),
            }],
            terminal: ProviderTerminal {
                status: ProviderTerminalStatus::ProviderUnavailable,
                summary: None,
                error: Some(self.reason.clone()),
            },
        }
    }
}

pub struct ConnectionEngine<P> {
    provider: P,
    limits: MechanicalLimits,
    connection_id: String,
    next_host_seq: u64,
    next_stream_ordinal: u64,
    active: Option<TurnContext>,
}

impl<P: TurnProvider> ConnectionEngine<P> {
    pub fn new(connection_id: impl Into<String>, provider: P) -> Result<Self, HostError> {
        let connection_id = connection_id.into();
        validate_local_id("connection_id", &connection_id)?;
        Ok(Self {
            provider,
            limits: MechanicalLimits::default(),
            connection_id,
            next_host_seq: 0,
            next_stream_ordinal: 0,
            active: None,
        })
    }

    pub fn with_limits(mut self, limits: MechanicalLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    pub fn has_active_turn(&self) -> bool {
        self.active.is_some()
    }

    pub fn handle_encoded(&mut self, encoded: &[u8]) -> Result<Vec<RunTurnFrame>, HostError> {
        let frame = RunTurnFrame::decode(encoded, &self.limits)
            .map_err(|error| HostError::InvalidFrame(error.to_string()))?;
        self.handle_frame(frame)
    }

    pub fn handle_frame(&mut self, frame: RunTurnFrame) -> Result<Vec<RunTurnFrame>, HostError> {
        match frame.kind.as_str() {
            FRAME_HELLO => self.handle_hello(frame),
            FRAME_TURN_START => self.handle_turn_start(frame),
            FRAME_TURN_CANCEL => self.handle_turn_cancel(frame),
            other => Err(HostError::InvalidFrame(format!(
                "unsupported client frame kind {other}"
            ))),
        }
    }

    pub fn error_frame(&mut self, error: &HostError) -> RunTurnFrame {
        self.output_frame(
            FRAME_HOST_ERROR,
            json!({"code": error.code(), "message": error.to_string(), "retryable": false}),
            None,
        )
    }

    fn handle_hello(&mut self, frame: RunTurnFrame) -> Result<Vec<RunTurnFrame>, HostError> {
        if self.active.is_some() {
            return Err(HostError::ConnectionState(
                "hello is valid only before an active turn".to_string(),
            ));
        }
        if frame
            .payload
            .get("protocol")
            .is_some_and(|value| value.as_str() != Some(PROTOCOL))
        {
            return Err(HostError::InvalidFrame(
                "hello protocol does not match the Host protocol".to_string(),
            ));
        }
        if let Some(version) = frame.payload.get("protocol_version") {
            let version_string = PROTOCOL_VERSION.to_string();
            if version.as_u64() != Some(u64::from(PROTOCOL_VERSION))
                && version.as_str() != Some(version_string.as_str())
            {
                return Err(HostError::InvalidFrame(
                    "hello protocol_version is unsupported".to_string(),
                ));
            }
        }
        Ok(vec![self.output_frame(
            FRAME_HELLO_ACK,
            json!({
                "protocol": PROTOCOL,
                "protocol_version": PROTOCOL_VERSION,
                "connection_id": self.connection_id.clone(),
                "profile_id": DEFAULT_PROFILE_ID,
                "host_implementation": HOST_IMPLEMENTATION,
                "provider_status": "unavailable_until_configured",
                "runtime_ready": false,
                "one_active_turn_per_connection": true
            }),
            None,
        )])
    }

    fn handle_turn_start(&mut self, frame: RunTurnFrame) -> Result<Vec<RunTurnFrame>, HostError> {
        if self.active.is_some() {
            return Err(HostError::ConnectionState(
                "one active turn is already attached to this connection".to_string(),
            ));
        }
        let request = frame
            .turn_request(&self.limits)
            .map_err(|error| HostError::InvalidFrame(error.to_string()))?;
        let context = self.allocate_turn_context(&request)?;
        self.active = Some(context.clone());
        let mut output = vec![self.output_frame(
            FRAME_TURN_ACCEPTED,
            json!({
                "status": "accepted",
                "event_log_status": "best_effort",
                "provider_status": "starting"
            }),
            Some(&context),
        )];

        let ProviderRun { events, terminal } = self.provider.run_turn(&request, &context);
        for event in events {
            let (kind, payload) = provider_event_frame(event)?;
            output.push(self.output_frame(&kind, payload, Some(&context)));
        }
        output.push(self.output_frame(
            FRAME_TURN_END,
            json!({
                "status": terminal.status.as_str(),
                "summary": terminal.summary,
                "error": terminal.error,
                "runtime_ready": false
            }),
            Some(&context),
        ));
        self.active = None;
        Ok(output)
    }

    fn handle_turn_cancel(&mut self, frame: RunTurnFrame) -> Result<Vec<RunTurnFrame>, HostError> {
        let request = frame
            .turn_cancel(&self.limits)
            .map_err(|error| HostError::InvalidFrame(error.to_string()))?;
        let active = self.active.clone().ok_or_else(|| {
            HostError::ConnectionState("turn.cancel has no active turn".to_string())
        })?;
        if request.session_id != active.session_id
            || request.turn_id != active.turn_id
            || request
                .turn_stream_id
                .as_deref()
                .is_some_and(|value| value != active.turn_stream_id.as_str())
        {
            return Err(HostError::ConnectionState(
                "turn.cancel correlation does not match the active turn".to_string(),
            ));
        }
        let terminal = self.provider.cancel_turn(&active);
        let output = vec![self.output_frame(
            FRAME_TURN_END,
            json!({
                "status": terminal.status.as_str(),
                "summary": terminal.summary,
                "error": terminal.error
            }),
            Some(&active),
        )];
        self.active = None;
        Ok(output)
    }

    fn allocate_turn_context(&mut self, request: &RunTurnRequest) -> Result<TurnContext, HostError> {
        self.next_stream_ordinal = self
            .next_stream_ordinal
            .checked_add(1)
            .ok_or_else(|| HostError::ConnectionState("turn stream ordinal overflow".to_string()))?;
        Ok(TurnContext {
            connection_id: self.connection_id.clone(),
            turn_stream_id: format!(
                "{}-turn-stream-{}",
                self.connection_id, self.next_stream_ordinal
            ),
            session_id: request.session_id.clone(),
            profile_id: request.effective_profile_id().to_string(),
            task_id: request.task_id.clone(),
            turn_id: request.turn_id.clone(),
        })
    }

    fn output_frame(
        &mut self,
        kind: &str,
        payload: Value,
        context: Option<&TurnContext>,
    ) -> RunTurnFrame {
        let seq = self.next_host_seq;
        self.next_host_seq = self.next_host_seq.saturating_add(1);
        RunTurnFrame {
            kind: kind.to_string(),
            seq,
            payload,
            direction: Some("host_to_client".to_string()),
            client_seq: None,
            host_seq: Some(seq),
            frame_sha256: None,
            event_id: Some(format!("{}-event-{seq}", self.connection_id)),
            connection_id: Some(self.connection_id.clone()),
            stream_id: context.map(|value| value.turn_stream_id.clone()),
            turn_stream_id: context.map(|value| value.turn_stream_id.clone()),
            session_id: context.map(|value| value.session_id.clone()),
            profile_id: context.map(|value| value.profile_id.clone()),
            task_id: context.map(|value| value.task_id.clone()),
            turn_id: context.map(|value| value.turn_id.clone()),
            call_id: None,
            job_id: None,
            tool: None,
            target: None,
            target_id: None,
            extensions: Default::default(),
        }
    }
}

fn provider_event_frame(event: ProviderEvent) -> Result<(String, Value), HostError> {
    match event {
        ProviderEvent::Status { status, detail } => Ok((
            FRAME_PROVIDER_STATUS.to_string(),
            json!({"status": status, "detail": detail}),
        )),
        ProviderEvent::ModelDelta { text } => {
            Ok((FRAME_MODEL_DELTA.to_string(), json!({"text": text})))
        }
        ProviderEvent::ModelMessage { text } => {
            Ok((FRAME_MODEL_MESSAGE.to_string(), json!({"text": text})))
        }
        ProviderEvent::Extension { label, payload } => {
            validate_extension_label(&label)?;
            if !payload.is_object() {
                return Err(HostError::InvalidFrame(
                    "provider extension event payload must be an object".to_string(),
                ));
            }
            Ok((label, payload))
        }
    }
}

fn validate_local_id(name: &str, value: &str) -> Result<(), HostError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(HostError::InvalidFrame(format!(
            "{name} is empty, oversized, or contains control bytes"
        )));
    }
    Ok(())
}

fn validate_extension_label(value: &str) -> Result<(), HostError> {
    if value.is_empty()
        || value.len() > 256
        || value.chars().any(char::is_control)
        || matches!(
            value,
            FRAME_HELLO
                | FRAME_HELLO_ACK
                | FRAME_TURN_START
                | FRAME_TURN_ACCEPTED
                | FRAME_TURN_CANCEL
                | FRAME_TURN_END
        )
    {
        return Err(HostError::InvalidFrame(
            "provider extension label is invalid or reserved".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_owner_open_types::FRAME_TOOL_CALL;

    struct FixtureProvider;

    impl TurnProvider for FixtureProvider {
        fn run_turn(&mut self, _request: &RunTurnRequest, _context: &TurnContext) -> ProviderRun {
            ProviderRun {
                events: vec![
                    ProviderEvent::Status {
                        status: "ready".to_string(),
                        detail: None,
                    },
                    ProviderEvent::ModelDelta {
                        text: "hello ".to_string(),
                    },
                    ProviderEvent::ModelMessage {
                        text: "world".to_string(),
                    },
                    ProviderEvent::Extension {
                        label: "vendor.fixture".to_string(),
                        payload: json!({"opaque": true}),
                    },
                ],
                terminal: ProviderTerminal {
                    status: ProviderTerminalStatus::Completed,
                    summary: Some("fixture complete".to_string()),
                    error: None,
                },
            }
        }
    }

    fn turn_start() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "kind": FRAME_TURN_START,
            "seq": 1,
            "direction": "client_to_host",
            "payload": {
                "protocol": PROTOCOL,
                "protocol_version": PROTOCOL_VERSION,
                "session_id": "session-1",
                "task_id": "task-1",
                "turn_id": "turn-1",
                "user_input": "say hello"
            }
        }))
        .unwrap()
    }

    #[test]
    fn hello_reports_the_foundation_hold_without_claiming_runtime_ready() {
        let mut engine = ConnectionEngine::new("connection-test", UnavailableProvider::default())
            .unwrap();
        let output = engine
            .handle_encoded(
                &serde_json::to_vec(&json!({
                    "kind": FRAME_HELLO,
                    "seq": 0,
                    "payload": {"protocol": PROTOCOL, "protocol_version": 1}
                }))
                .unwrap(),
            )
            .unwrap();
        assert_eq!(output[0].kind, FRAME_HELLO_ACK);
        assert_eq!(output[0].payload["runtime_ready"], false);
    }

    #[test]
    fn unavailable_provider_returns_an_honest_same_turn_terminal_result() {
        let mut engine = ConnectionEngine::new("connection-test", UnavailableProvider::default())
            .unwrap();
        let output = engine.handle_encoded(&turn_start()).unwrap();
        assert_eq!(output.first().unwrap().kind, FRAME_TURN_ACCEPTED);
        assert_eq!(output.last().unwrap().kind, FRAME_TURN_END);
        assert_eq!(output.last().unwrap().payload["status"], "provider_unavailable");
        let stream = output[0].turn_stream_id.clone();
        assert!(stream.is_some());
        assert!(output.iter().all(|frame| frame.turn_stream_id == stream));
        assert!(!engine.has_active_turn());
    }

    #[test]
    fn injected_provider_events_keep_one_turn_lineage() {
        let mut engine = ConnectionEngine::new("connection-test", FixtureProvider).unwrap();
        let output = engine.handle_encoded(&turn_start()).unwrap();
        let kinds = output
            .iter()
            .map(|frame| frame.kind.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            kinds,
            vec![
                FRAME_TURN_ACCEPTED,
                FRAME_PROVIDER_STATUS,
                FRAME_MODEL_DELTA,
                FRAME_MODEL_MESSAGE,
                "vendor.fixture",
                FRAME_TURN_END
            ]
        );
    }

    #[test]
    fn legacy_plan_or_direct_tool_frames_are_not_host_entrypoints() {
        let mut engine = ConnectionEngine::new("connection-test", FixtureProvider).unwrap();
        let error = engine
            .handle_encoded(
                &serde_json::to_vec(&json!({
                    "kind": FRAME_TOOL_CALL,
                    "seq": 1,
                    "payload": {"call_id": "call-1", "tool": "shell.exec", "command": "pwd"}
                }))
                .unwrap(),
            )
            .unwrap_err();
        assert!(error.to_string().contains("unsupported client frame kind"));
    }

    #[test]
    fn duplicate_json_members_fail_before_state_change() {
        let mut engine = ConnectionEngine::new("connection-test", FixtureProvider).unwrap();
        let error = engine
            .handle_encoded(
                br#"{"kind":"turn.start","kind":"hello","seq":1,"payload":{}}"#,
            )
            .unwrap_err();
        assert!(error.to_string().contains("duplicate key kind"));
        assert!(!engine.has_active_turn());
    }
}
