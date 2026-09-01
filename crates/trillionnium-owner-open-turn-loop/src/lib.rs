//! Same-turn provider/tool callback loop for the owner-open R5 source closure.
//!
//! A provider retains semantic ownership of the turn. It may emit model/status
//! events, invoke direct shell or ordinary ADB through one mechanism-only Host
//! callback, inspect the raw observation, continue reasoning, and then produce
//! one terminal result. The loop imports no plan, Authority, approval, risk,
//! typed-ADB, or sealed shell-broker graph.

use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use thiserror::Error;
use trillionnium_owner_open_call_registry::{
    CallRegistry, CallSnapshot, EffectiveState, TerminalRecord, TurnScope,
};
use trillionnium_owner_open_runtime::{ExecutionEvent, ExecutionEventKind, ExecutionTerminal};
use trillionnium_owner_open_tool_bridge::{
    BoundToolCall, BridgeError, BridgeLimits, DirectToolBridge, DispatchResult,
};

// Keep the provider-facing retention bound finite even when a provider emits
// a very large stream of deltas or runtime observations. Delivery sinks still
// receive every event; only the returned in-memory run is a bounded diagnostic
// tail (with the initial acceptance event retained). The byte values are a
// conservative estimate of the owned String/Vec capacities plus fixed Rust
// value layouts; they are not a wire-serialization limit.
pub const MAX_RETAINED_TURN_EVENTS: usize = 4096;
pub const MAX_RETAINED_TURN_EVENT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RETAINED_TOOL_EVENTS: usize = 4096;
pub const MAX_RETAINED_TOOL_EVENT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TurnLoopError {
    #[error("invalid owner-open turn request: {0}")]
    InvalidRequest(String),
    #[error("provider tool call is outside the active turn scope")]
    ToolScopeMismatch,
    #[error("owner-open direct tool bridge failed: {0}")]
    ToolBridge(String),
    #[error("owner-open turn event sink failed: {0}")]
    EventSink(String),
    #[error("owner-open turn was cancelled before the tool call could start")]
    TurnCancelled,
}

#[derive(Debug, Clone, Default)]
pub struct TurnCancellation {
    cancelled: Arc<AtomicBool>,
}

impl TurnCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) -> bool {
        !self.cancelled.swap(true, Ordering::SeqCst)
    }

    /// Expose the turn-local cancellation flag for direct tool execution.
    /// The bridge observes it as an additional, targeted flag and does not
    /// create a forwarding worker per tool invocation.
    #[must_use]
    pub fn shared_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
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
            return Err(invalid("user_input exceeds one MiB or contains a NUL byte"));
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

    #[must_use]
    pub fn cancelled(summary: impl Into<String>) -> Self {
        Self {
            status: ProviderTerminalStatus::Cancelled,
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

pub trait TurnEventSink {
    fn on_event(&mut self, event: &TurnEvent) -> std::result::Result<(), String>;
}

impl<F> TurnEventSink for F
where
    F: FnMut(&TurnEvent) -> std::result::Result<(), String>,
{
    fn on_event(&mut self, event: &TurnEvent) -> std::result::Result<(), String> {
        self(event)
    }
}

struct IgnoreEvents;

impl TurnEventSink for IgnoreEvents {
    fn on_event(&mut self, _event: &TurnEvent) -> std::result::Result<(), String> {
        Ok(())
    }
}

/// Provider-facing callback surface. Calls return raw process observations;
/// the provider remains responsible for interpreting them and deciding whether
/// to continue, retry with a new call ID, compensate, or finish the turn.
pub struct ProviderHost<'a> {
    scope: TurnScope,
    registry: Arc<CallRegistry>,
    limits: &'a BridgeLimits,
    events: &'a mut Vec<TurnEvent>,
    retained_event_bytes: &'a mut usize,
    next_seq: &'a mut u64,
    sink: &'a mut dyn TurnEventSink,
    cancellation: TurnCancellation,
}

impl ProviderHost<'_> {
    pub fn emit(&mut self, event: ProviderEvent) -> Result<(), TurnLoopError> {
        validate_provider_event(&event)?;
        push_event(
            self.events,
            self.retained_event_bytes,
            self.next_seq,
            self.sink,
            TurnEventKind::Provider(event),
        )
    }

    pub fn invoke_tool(&mut self, call: BoundToolCall) -> Result<ToolOutcome, TurnLoopError> {
        if call.key.scope != self.scope {
            return Err(TurnLoopError::ToolScopeMismatch);
        }
        if self.cancellation.is_cancelled() {
            return Err(TurnLoopError::TurnCancelled);
        }

        let bridge = DirectToolBridge::new(Arc::clone(&self.registry));
        let mut runtime_events = Vec::new();
        let mut runtime_event_bytes = 0_usize;
        let result = {
            let events = &mut *self.events;
            let retained_event_bytes = &mut *self.retained_event_bytes;
            let next_seq = &mut *self.next_seq;
            let sink = &mut *self.sink;
            bridge.execute_fallible_with_external_flags(
                call,
                self.limits,
                std::iter::once(self.cancellation.shared_flag()),
                |event| {
                    retain_tool_event(&mut runtime_events, &mut runtime_event_bytes, event.clone());
                    push_event(
                        events,
                        retained_event_bytes,
                        next_seq,
                        sink,
                        TurnEventKind::ToolRuntime(event),
                    )
                    .map_err(|error| error.to_string())
                },
            )
        };

        match result.map_err(map_bridge_error)? {
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
                    self.retained_event_bytes,
                    self.next_seq,
                    self.sink,
                    TurnEventKind::ToolExisting(snapshot.clone()),
                )?;
                Ok(ToolOutcome::Existing(snapshot))
            }
            DispatchResult::Inhibited(snapshot) => {
                push_event(
                    self.events,
                    self.retained_event_bytes,
                    self.next_seq,
                    self.sink,
                    TurnEventKind::ToolInhibited(snapshot.clone()),
                )?;
                Ok(ToolOutcome::Inhibited(snapshot))
            }
        }
    }

    #[must_use]
    pub fn registry(&self) -> &Arc<CallRegistry> {
        &self.registry
    }

    #[must_use]
    pub fn cancellation(&self) -> TurnCancellation {
        self.cancellation.clone()
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
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
        let mut sink = IgnoreEvents;
        self.run_with_sink_and_cancellation(request, provider, &TurnCancellation::new(), &mut sink)
    }

    pub fn run_with_sink<P: SameTurnProvider>(
        &self,
        request: TurnRequest,
        provider: &mut P,
        sink: &mut dyn TurnEventSink,
    ) -> Result<TurnRun, TurnLoopError> {
        self.run_with_sink_and_cancellation(request, provider, &TurnCancellation::new(), sink)
    }

    pub fn run_with_sink_and_cancellation<P: SameTurnProvider>(
        &self,
        request: TurnRequest,
        provider: &mut P,
        cancellation: &TurnCancellation,
        sink: &mut dyn TurnEventSink,
    ) -> Result<TurnRun, TurnLoopError> {
        request.validate()?;
        self.bridge_limits
            .validate()
            .map_err(|error| invalid(error.to_string()))?;

        let mut events = Vec::new();
        let mut retained_event_bytes = 0_usize;
        let mut next_seq = 0_u64;
        push_event(
            &mut events,
            &mut retained_event_bytes,
            &mut next_seq,
            sink,
            TurnEventKind::TurnAccepted,
        )?;

        let terminal = if cancellation.is_cancelled() {
            ProviderTerminal::cancelled("turn was cancelled before provider start")
        } else {
            let scope = request.scope();
            let mut host = ProviderHost {
                scope,
                registry: Arc::clone(&self.registry),
                limits: &self.bridge_limits,
                events: &mut events,
                retained_event_bytes: &mut retained_event_bytes,
                next_seq: &mut next_seq,
                sink,
                cancellation: cancellation.clone(),
            };

            let provider_result =
                catch_unwind(AssertUnwindSafe(|| provider.run_turn(&request, &mut host)));
            drop(host);
            match provider_result {
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
            }
        };

        validate_terminal(&terminal)?;
        push_event(
            &mut events,
            &mut retained_event_bytes,
            &mut next_seq,
            sink,
            TurnEventKind::TurnTerminal(terminal.clone()),
        )?;
        Ok(TurnRun {
            request,
            events,
            terminal,
        })
    }
}

fn push_event(
    events: &mut Vec<TurnEvent>,
    retained_bytes: &mut usize,
    next_seq: &mut u64,
    sink: &mut dyn TurnEventSink,
    kind: TurnEventKind,
) -> Result<(), TurnLoopError> {
    let seq = *next_seq;
    *next_seq = next_seq
        .checked_add(1)
        .ok_or_else(|| invalid("turn event sequence exhausted"))?;
    let event = TurnEvent { seq, kind };
    retain_turn_event(events, retained_bytes, event.clone());
    match catch_unwind(AssertUnwindSafe(|| sink.on_event(&event))) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(TurnLoopError::EventSink(error)),
        Err(_) => Err(TurnLoopError::EventSink(
            "turn event sink panicked".to_string(),
        )),
    }
}

fn retain_turn_event(events: &mut Vec<TurnEvent>, retained_bytes: &mut usize, event: TurnEvent) {
    let Some(incoming_bytes) = turn_event_weight(&event) else {
        // A size calculation overflow is itself an invalid retention request.
        // The event is still delivered to the sink by the caller, but never
        // allowed into the returned diagnostic vector.
        return;
    };
    if incoming_bytes > MAX_RETAINED_TURN_EVENT_BYTES {
        return;
    }

    while events.len() >= MAX_RETAINED_TURN_EVENTS
        || retained_bytes
            .checked_add(incoming_bytes)
            .is_none_or(|total| total > MAX_RETAINED_TURN_EVENT_BYTES)
    {
        // Keep the acceptance marker as a stable prefix when possible. The
        // sequence numbers remain authoritative, so a consumer can detect a
        // retention gap from the first retained sequence without mistaking it
        // for a contiguous replay.
        let remove_at = if events
            .first()
            .is_some_and(|candidate| matches!(candidate.kind, TurnEventKind::TurnAccepted))
            && events.len() > 1
        {
            1
        } else if events
            .first()
            .is_some_and(|candidate| matches!(candidate.kind, TurnEventKind::TurnAccepted))
        {
            // Never evict the acceptance marker merely to fit an unusually
            // large diagnostic item. The sink still receives that item; the
            // returned tail simply omits it when no legal eviction remains.
            break;
        } else if events.is_empty() {
            break;
        } else {
            0
        };
        let removed = events.remove(remove_at);
        let Some(removed_bytes) = turn_event_weight(&removed) else {
            // Rebuild from an empty diagnostic tail if accounting overflows.
            // This preserves the sink/terminal semantics while failing closed
            // for the in-memory retention path.
            events.clear();
            *retained_bytes = 0;
            break;
        };
        if let Some(total) = retained_bytes.checked_sub(removed_bytes) {
            *retained_bytes = total;
        } else {
            events.clear();
            *retained_bytes = 0;
            break;
        }
    }

    if events.len() < MAX_RETAINED_TURN_EVENTS
        && retained_bytes
            .checked_add(incoming_bytes)
            .is_some_and(|total| total <= MAX_RETAINED_TURN_EVENT_BYTES)
    {
        events.push(event);
        // The checked fit above makes this addition infallible. Keep the
        // checked form anyway so the accounting remains fail-closed if the
        // implementation changes later.
        if let Some(total) = retained_bytes.checked_add(incoming_bytes) {
            *retained_bytes = total;
        } else {
            let _ = events.pop();
        }
    }
}

fn retain_tool_event(
    events: &mut Vec<ExecutionEvent>,
    retained_bytes: &mut usize,
    event: ExecutionEvent,
) {
    let Some(incoming_bytes) = execution_event_weight(&event) else {
        return;
    };
    if incoming_bytes > MAX_RETAINED_TOOL_EVENT_BYTES {
        return;
    }
    while events.len() >= MAX_RETAINED_TOOL_EVENTS
        || retained_bytes
            .checked_add(incoming_bytes)
            .is_none_or(|total| total > MAX_RETAINED_TOOL_EVENT_BYTES)
    {
        let Some(removed) = events.first() else {
            break;
        };
        let Some(removed_bytes) = execution_event_weight(removed) else {
            events.clear();
            *retained_bytes = 0;
            break;
        };
        events.remove(0);
        if let Some(total) = retained_bytes.checked_sub(removed_bytes) {
            *retained_bytes = total;
        } else {
            events.clear();
            *retained_bytes = 0;
            break;
        }
    }
    if events.len() < MAX_RETAINED_TOOL_EVENTS
        && retained_bytes
            .checked_add(incoming_bytes)
            .is_some_and(|total| total <= MAX_RETAINED_TOOL_EVENT_BYTES)
    {
        events.push(event);
        if let Some(total) = retained_bytes.checked_add(incoming_bytes) {
            *retained_bytes = total;
        } else {
            let _ = events.pop();
        }
    }
}

/// Add one owned allocation's capacity to a checked diagnostic-size total.
///
/// The event types are intentionally not required to implement `Serialize`.
/// Counting the actual `String`/`Vec` capacities (rather than only their
/// lengths) is conservative for the cloned values retained by this crate and
/// avoids introducing a second wire schema solely for accounting.
fn add_capacity(total: &mut usize, capacity: usize) -> Option<()> {
    *total = total.checked_add(capacity)?;
    Some(())
}

fn add_string_capacity(total: &mut usize, value: &String) -> Option<()> {
    add_capacity(total, value.capacity())
}

fn add_optional_string_capacity(total: &mut usize, value: Option<&String>) -> Option<()> {
    if let Some(value) = value {
        add_string_capacity(total, value)?;
    }
    Some(())
}

fn provider_event_weight(event: &ProviderEvent) -> Option<usize> {
    let mut total = size_of::<ProviderEvent>();
    match event {
        ProviderEvent::Status { status, detail } => {
            add_string_capacity(&mut total, status)?;
            add_optional_string_capacity(&mut total, detail.as_ref())?;
        }
        ProviderEvent::ModelDelta(value) | ProviderEvent::ModelMessage(value) => {
            add_string_capacity(&mut total, value)?;
        }
        ProviderEvent::Opaque { kind, payload } => {
            add_string_capacity(&mut total, kind)?;
            add_string_capacity(&mut total, payload)?;
        }
    }
    Some(total)
}

fn provider_terminal_weight(terminal: &ProviderTerminal) -> Option<usize> {
    let mut total = size_of::<ProviderTerminal>();
    add_optional_string_capacity(&mut total, terminal.summary.as_ref())?;
    add_optional_string_capacity(&mut total, terminal.error.as_ref())?;
    Some(total)
}

fn execution_terminal_weight(terminal: &ExecutionTerminal) -> Option<usize> {
    let mut total = size_of::<ExecutionTerminal>();
    add_optional_string_capacity(&mut total, terminal.error.as_ref())?;
    Some(total)
}

fn execution_event_weight(event: &ExecutionEvent) -> Option<usize> {
    let mut total = size_of::<ExecutionEvent>();
    add_string_capacity(&mut total, &event.call_id)?;
    add_optional_string_capacity(&mut total, event.target_id.as_ref())?;
    match &event.kind {
        ExecutionEventKind::Accepted | ExecutionEventKind::Started { .. } => {}
        ExecutionEventKind::Output { bytes, .. } => add_capacity(&mut total, bytes.capacity())?,
        ExecutionEventKind::Terminal(terminal) => {
            total = total.checked_add(execution_terminal_weight(terminal)?)?;
        }
    }
    Some(total)
}

fn turn_scope_weight(scope: &TurnScope) -> Option<usize> {
    let mut total = size_of::<TurnScope>();
    for value in [
        &scope.session_id,
        &scope.profile_id,
        &scope.task_id,
        &scope.turn_id,
        &scope.turn_stream_id,
    ] {
        add_string_capacity(&mut total, value)?;
    }
    Some(total)
}

fn call_snapshot_weight(snapshot: &CallSnapshot) -> Option<usize> {
    let mut total = size_of::<CallSnapshot>();
    total = total.checked_add(call_key_weight(&snapshot.key)?)?;
    total = total.checked_add(call_request_weight(&snapshot.request)?)?;
    total = total.checked_add(effective_state_weight(&snapshot.state)?)?;
    Some(total)
}

fn call_key_weight(key: &trillionnium_owner_open_call_registry::CallKey) -> Option<usize> {
    let mut total = size_of::<trillionnium_owner_open_call_registry::CallKey>();
    total = total.checked_add(turn_scope_weight(&key.scope)?)?;
    add_string_capacity(&mut total, &key.call_id)?;
    Some(total)
}

fn call_request_weight(
    request: &trillionnium_owner_open_call_registry::CallRequest,
) -> Option<usize> {
    let mut total = size_of::<trillionnium_owner_open_call_registry::CallRequest>();
    add_string_capacity(&mut total, &request.request_sha256)?;
    add_string_capacity(&mut total, &request.binding_fingerprint)?;
    add_string_capacity(&mut total, &request.tool)?;
    add_optional_string_capacity(&mut total, request.target_id.as_ref())?;
    Some(total)
}

fn effective_state_weight(state: &EffectiveState) -> Option<usize> {
    let mut total = size_of::<EffectiveState>();
    if let EffectiveState::Terminal { terminal, .. } = state {
        total = total.checked_add(terminal_record_weight(terminal)?)?;
    }
    Some(total)
}

fn terminal_record_weight(record: &TerminalRecord) -> Option<usize> {
    let mut total = size_of::<TerminalRecord>();
    add_string_capacity(&mut total, &record.terminal_kind)?;
    add_string_capacity(&mut total, &record.observation_sha256)?;
    Some(total)
}

fn turn_event_weight(event: &TurnEvent) -> Option<usize> {
    let mut total = size_of::<TurnEvent>();
    match &event.kind {
        TurnEventKind::TurnAccepted => {}
        TurnEventKind::Provider(provider) => {
            total = total.checked_add(provider_event_weight(provider)?)?;
        }
        TurnEventKind::ToolRuntime(runtime) => {
            total = total.checked_add(execution_event_weight(runtime)?)?;
        }
        TurnEventKind::ToolExisting(snapshot) | TurnEventKind::ToolInhibited(snapshot) => {
            total = total.checked_add(call_snapshot_weight(snapshot)?)?;
        }
        TurnEventKind::TurnTerminal(terminal) => {
            total = total.checked_add(provider_terminal_weight(terminal)?)?;
        }
    }
    Some(total)
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
        return Err(invalid("provider event contains a NUL or exceeds one MiB"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_owner_open_runtime::{StreamKind, ToolKind};

    fn accepted_event() -> TurnEvent {
        TurnEvent {
            seq: 0,
            kind: TurnEventKind::TurnAccepted,
        }
    }

    #[test]
    fn turn_and_tool_retention_are_bounded_by_checked_bytes() {
        let mut turn_events = Vec::new();
        let mut turn_bytes = 0_usize;
        retain_turn_event(&mut turn_events, &mut turn_bytes, accepted_event());

        // More than the 64 MiB turn budget, while staying within the
        // provider's one-item validation bound only matters at the public
        // boundary; this direct retention fixture exercises aggregate
        // accounting independently of that per-event check.
        let provider_payload = "p".repeat(5 * 1024 * 1024);
        for seq in 1..=14 {
            retain_turn_event(
                &mut turn_events,
                &mut turn_bytes,
                TurnEvent {
                    seq,
                    kind: TurnEventKind::Provider(ProviderEvent::ModelMessage(
                        provider_payload.clone(),
                    )),
                },
            );
        }
        let terminal = ProviderTerminal::completed("terminal survives diagnostic eviction");
        retain_turn_event(
            &mut turn_events,
            &mut turn_bytes,
            TurnEvent {
                seq: 15,
                kind: TurnEventKind::TurnTerminal(terminal),
            },
        );
        assert!(turn_bytes <= MAX_RETAINED_TURN_EVENT_BYTES);
        assert!(turn_events.len() < 15);
        let recomputed_turn_bytes = turn_events
            .iter()
            .try_fold(0_usize, |total, event| {
                total.checked_add(turn_event_weight(event)?)
            })
            .unwrap();
        assert_eq!(turn_bytes, recomputed_turn_bytes);
        assert!(matches!(
            turn_events.first().map(|event| &event.kind),
            Some(TurnEventKind::TurnAccepted)
        ));
        assert!(matches!(
            turn_events.last().map(|event| &event.kind),
            Some(TurnEventKind::TurnTerminal(_))
        ));

        let mut tool_events = Vec::new();
        let mut tool_bytes = 0_usize;
        let output = vec![b'x'; 8 * 1024 * 1024];
        for seq in 0..10 {
            retain_tool_event(
                &mut tool_events,
                &mut tool_bytes,
                ExecutionEvent {
                    call_id: "bounded-call".to_string(),
                    target_id: None,
                    tool: ToolKind::ShellExec,
                    seq,
                    elapsed_ms: 0,
                    kind: ExecutionEventKind::Output {
                        stream: StreamKind::Stdout,
                        bytes: output.clone(),
                    },
                },
            );
        }
        assert!(tool_bytes <= MAX_RETAINED_TOOL_EVENT_BYTES);
        assert!(tool_events.len() < 10);
        let recomputed_tool_bytes = tool_events
            .iter()
            .try_fold(0_usize, |total, event| {
                total.checked_add(execution_event_weight(event)?)
            })
            .unwrap();
        assert_eq!(tool_bytes, recomputed_tool_bytes);
    }

    #[test]
    fn retention_drops_an_item_that_cannot_fit_without_changing_accounting() {
        let mut events = Vec::new();
        let mut retained_bytes = 0_usize;
        retain_turn_event(&mut events, &mut retained_bytes, accepted_event());

        // Reserve a capacity just over the schema budget without populating
        // it. Accounting uses capacity deliberately, so this item is rejected
        // and the stable acceptance marker remains available for diagnostics.
        let oversized = String::with_capacity(MAX_RETAINED_TURN_EVENT_BYTES);
        retain_turn_event(
            &mut events,
            &mut retained_bytes,
            TurnEvent {
                seq: 1,
                kind: TurnEventKind::Provider(ProviderEvent::ModelMessage(oversized)),
            },
        );
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].kind, TurnEventKind::TurnAccepted));
        assert_eq!(retained_bytes, turn_event_weight(&events[0]).unwrap());
    }
}
