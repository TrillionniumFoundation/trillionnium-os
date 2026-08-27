//! Same-turn provider/tool callback loop for the owner-open R5 source closure.
//!
//! A provider retains semantic ownership of the turn. It may emit model/status
//! events, invoke direct shell or ordinary ADB through one mechanism-only Host
//! callback, inspect the raw observation, continue reasoning, and then produce
//! one terminal result. The loop imports no plan, Authority, approval, risk,
//! typed-ADB, or sealed shell-broker graph.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use thiserror::Error;
use trillionnium_owner_open_call_registry::{CallRegistry, CallSnapshot, TurnScope};
use trillionnium_owner_open_runtime::{ExecutionEvent, ExecutionTerminal};
use trillionnium_owner_open_tool_bridge::{
    BoundToolCall, BridgeError, BridgeLimits, DirectToolBridge, DispatchResult,
};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TurnLoopError {
    #[error("invalid owner-open turn request: {0}")]
    InvalidRequest(String),
    #[error("provider tool call is outside the active turn scope")]
    ToolScopeMismatch,
    #[error("owner-open direct tool bridge failed: {0}")]
    ToolBridge(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnRequest {
    pub session_id: String,
    pub profile_id: String,
    pub task_id: String,
    pub turn_id: String,
    pub turn_stream_id: String,
    pub user_input: String,
}

impl TurnRequest {
    pub fn validate(&self) -> Result<(), TurnLoopError> {
        for (label, value) in [
            ("session_id", self.session_id.as_str()),
            ("profile_id", self.profile_id.as_str()),
            ("task_id", self.task_id.as_str()),
            ("turn_id", self.turn_id.as_str()),
            ("turn_stream_id", self.turn_stream_id.as_str()),
        ] {
            validate_id(label, value)?;
        }
        if self.user_input.len() > 1024 * 1024 || self.user_input.as_bytes().contains(&0) {
            return Err(invalid(
                "user_input exceeds one MiB or contains a NUL byte",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn scope(&self) -> TurnScope {
        TurnScope::new(
            self.session_id.clone(),
            self.profile_id.clone(),
            self.task_id.clone(),
            self.turn_id.clone(),
            self.turn_stream_id.clone(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderEvent {
    Status {
        status: String,
        detail: Option<String>,
    },
    ModelDelta(String),
    ModelMessage(String),
    Opaque {
        kind: String,
        payload: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderTerminalStatus {
    Completed,
    Cancelled,
    Failed,
    Panicked,
}

impl ProviderTerminalStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "provider_failed",
            Self::Panicked => "provider_panicked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderTerminal {
    pub status: ProviderTerminalStatus,
    pub summary: Option<String>,
    pub error: Option<String>,
}

impl ProviderTerminal {
    #[must_use]
    pub fn completed(summary: impl Into<String>) -> Self {
        Self {
            status: ProviderTerminalStatus::Completed,
            summary: Some(summary.into()),
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ToolOutcome {
    Executed {
        generation: u64,
        events: Vec<ExecutionEvent>,
        terminal: ExecutionTerminal,
        observation_sha256: String,
        snapshot: CallSnapshot,
    },
    Existing(CallSnapshot),
    Inhibited(CallSnapshot),
}

#[derive(Debug, Clone)]
pub enum TurnEventKind {
    TurnAccepted,
    Provider(ProviderEvent),
    ToolRuntime(ExecutionEvent),
    ToolExisting(CallSnapshot),
    ToolInhibited(CallSnapshot),
    TurnTerminal(ProviderTerminal),
}

#[derive(Debug, Clone)]
pub struct TurnEvent {
    pub seq: u64,
    pub kind: TurnEventKind,
}

#[derive(Debug, Clone)]
pub struct TurnRun {
    pub request: TurnRequest,
    pub events: Vec<TurnEvent>,
    pub terminal: ProviderTerminal,
}

/// Provider-facing callback surface. Calls return raw process observations;
/// the provider remains responsible for interpreting them and deciding whether
/// to continue, retry with a new call ID, compensate, or finish the turn.
pub struct ProviderHost<'a> {
    scope: TurnScope,
    registry: Arc<CallRegistry>,
    limits: &'a BridgeLimits,
    events: &'a mut Vec<TurnEvent>,
    next_seq: &'a mut u64,
}

impl ProviderHost<'_> {
    pub fn emit(&mut self, event: ProviderEvent) -> Result<(), TurnLoopError> {
        validate_provider_event(&event)?;
        push_event(self.events, self.next_seq, TurnEventKind::Provider(event));
        Ok(())
    }

    pub fn invoke_tool(&mut self, call: BoundToolCall) -> Result<ToolOutcome, TurnLoopError> {
        if call.key.scope != self.scope {
            return Err(TurnLoopError::ToolScopeMismatch);
        }
        let bridge = DirectToolBridge::new(Arc::clone(&self.registry));
        let mut runtime_events = Vec::new();
        let result = bridge
            .execute_fallible(call, self.limits, |event| {
                runtime_events.push(event);
                Ok::<(), &'static str>(())
            })
            .map_err(map_bridge_error)?;

        for event in &runtime_events {
            push_event(
                self.events,
                self.next_seq,
                TurnEventKind::ToolRuntime(event.clone()),
            );
        }

        match result {
            DispatchResult::Executed {
                generation,
                terminal,
                observation_sha256,
                snapshot,
            } => Ok(ToolOutcome::Executed {
                generation,
                events: runtime_events,
                terminal,
                observation_sha256,
                snapshot,
            }),
            DispatchResult::Existing(snapshot) => {
                push_event(
                    self.events,
                    self.next_seq,
                    TurnEventKind::ToolExisting(snapshot.clone()),
                );
                Ok(ToolOutcome::Existing(snapshot))
            }
            DispatchResult::Inhibited(snapshot) => {
                push_event(
                    self.events,
                    self.next_seq,
                    TurnEventKind::ToolInhibited(snapshot.clone()),
                );
                Ok(ToolOutcome::Inhibited(snapshot))
            }
        }
    }

    #[must_use]
    pub fn registry(&self) -> &Arc<CallRegistry> {
        &self.registry
    }
}

pub trait SameTurnProvider {
    /// Run exactly one semantic turn. A tool failure is an observation and does
    /// not require the provider to fail; the provider chooses the next step.
    fn run_turn(
        &mut self,
        request: &TurnRequest,
        host: &mut ProviderHost<'_>,
    ) -> std::result::Result<ProviderTerminal, String>;
}

#[derive(Debug)]
pub struct TurnRunner {
    registry: Arc<CallRegistry>,
    bridge_limits: BridgeLimits,
}

impl TurnRunner {
    #[must_use]
    pub fn new(registry: Arc<CallRegistry>) -> Self {
        Self {
            registry,
            bridge_limits: BridgeLimits::default(),
        }
    }

    #[must_use]
    pub fn with_bridge_limits(mut self, limits: BridgeLimits) -> Self {
        self.bridge_limits = limits;
        self
    }

    #[must_use]
    pub fn registry(&self) -> &Arc<CallRegistry> {
        &self.registry
    }

    pub fn run<P: SameTurnProvider>(
        &self,
        request: TurnRequest,
        provider: &mut P,
    ) -> Result<TurnRun, TurnLoopError> {
        request.validate()?;
        self.bridge_limits
            .validate()
            .map_err(|error| invalid(error.to_string()))?;

        let mut events = Vec::new();
        let mut next_seq = 0_u64;
        push_event(&mut events, &mut next_seq, TurnEventKind::TurnAccepted);

        let scope = request.scope();
        let mut host = ProviderHost {
            scope,
            registry: Arc::clone(&self.registry),
            limits: &self.bridge_limits,
            events: &mut events,
            next_seq: &mut next_seq,
        };

        let provider_result = catch_unwind(AssertUnwindSafe(|| {
            provider.run_turn(&request, &mut host)
        }));
        let terminal = match provider_result {
            Ok(Ok(terminal)) => terminal,
            Ok(Err(error)) => ProviderTerminal {
                status: ProviderTerminalStatus::Failed,
                summary: None,
                error: Some(error),
            },
            Err(_) => ProviderTerminal {
                status: ProviderTerminalStatus::Panicked,
                summary: None,
                error: Some("provider panicked inside the same-turn callback".to_string()),
            },
        };
        validate_terminal(&terminal)?;
        push_event(
            &mut events,
            &mut next_seq,
            TurnEventKind::TurnTerminal(terminal.clone()),
        );
        Ok(TurnRun {
            request,
            events,
            terminal,
        })
    }
}

fn push_event(events: &mut Vec<TurnEvent>, next_seq: &mut u64, kind: TurnEventKind) {
    let seq = *next_seq;
    *next_seq = (*next_seq).saturating_add(1);
    events.push(TurnEvent { seq, kind });
}

fn validate_id(label: &str, value: &str) -> Result<(), TurnLoopError> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid(format!(
            "{label} is empty, oversized, or malformed"
        )));
    }
    Ok(())
}

fn validate_provider_event(event: &ProviderEvent) -> Result<(), TurnLoopError> {
    let values: Vec<&str> = match event {
        ProviderEvent::Status { status, detail } => {
            let mut values = vec![status.as_str()];
            if let Some(detail) = detail {
                values.push(detail.as_str());
            }
            values
        }
        ProviderEvent::ModelDelta(value) | ProviderEvent::ModelMessage(value) => vec![value],
        ProviderEvent::Opaque { kind, payload } => vec![kind, payload],
    };
    if values
        .iter()
        .any(|value| value.len() > 1024 * 1024 || value.as_bytes().contains(&0))
    {
        return Err(invalid(
            "provider event contains a NUL or exceeds one MiB",
        ));
    }
    Ok(())
}

fn validate_terminal(terminal: &ProviderTerminal) -> Result<(), TurnLoopError> {
    if terminal
        .summary
        .as_deref()
        .into_iter()
        .chain(terminal.error.as_deref())
        .any(|value| value.len() > 1024 * 1024 || value.as_bytes().contains(&0))
    {
        return Err(invalid(
            "provider terminal text contains a NUL or exceeds one MiB",
        ));
    }
    Ok(())
}

fn map_bridge_error(error: BridgeError) -> TurnLoopError {
    TurnLoopError::ToolBridge(error.to_string())
}

fn invalid(message: impl Into<String>) -> TurnLoopError {
    TurnLoopError::InvalidRequest(message.into())
}
