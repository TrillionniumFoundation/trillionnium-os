//! Concurrent owner-open call registry.
//!
//! The registry is a mechanism-only in-memory state machine. It binds one call
//! ID to one exact request inside one turn scope, grants at most one spawn
//! generation, carries cancellation, records disconnect uncertainty and accepts
//! a late terminal result. It does not interpret command meaning, approve a
//! tool, retry an effect or confer execution authority.

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    InvalidRequest(String),
    NotFound,
    CallIdConflict,
    RequestDigestMismatch,
    InvalidTransition(&'static str),
    SpawnGenerationMismatch,
    PidConflict,
    TerminalConflict,
    CapacityExhausted,
    GenerationExhausted,
    StatePoisoned,
}

impl Display for RegistryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRequest(message) => {
                write!(
                    formatter,
                    "invalid owner-open call registry request: {message}"
                )
            }
            Self::NotFound => formatter.write_str("owner-open call is not registered"),
            Self::CallIdConflict => formatter
                .write_str("owner-open call_id is already bound to different request bytes"),
            Self::RequestDigestMismatch => formatter
                .write_str("owner-open call request digest does not match the registered call"),
            Self::InvalidTransition(message) => {
                write!(formatter, "invalid owner-open call transition: {message}")
            }
            Self::SpawnGenerationMismatch => formatter
                .write_str("owner-open spawn generation does not match the registered call"),
            Self::PidConflict => {
                formatter.write_str("owner-open call already records a different process identity")
            }
            Self::TerminalConflict => formatter
                .write_str("owner-open call already records a different terminal observation"),
            Self::CapacityExhausted => {
                formatter.write_str("owner-open call registry capacity is exhausted")
            }
            Self::GenerationExhausted => {
                formatter.write_str("owner-open spawn generation is exhausted")
            }
            Self::StatePoisoned => formatter.write_str("owner-open call registry lock is poisoned"),
        }
    }
}

impl Error for RegistryError {}

pub type Result<T> = std::result::Result<T, RegistryError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryLimits {
    pub max_entries: usize,
    pub max_history_per_call: usize,
    pub max_id_bytes: usize,
    pub max_tool_bytes: usize,
    pub max_target_bytes: usize,
}

impl Default for RegistryLimits {
    fn default() -> Self {
        Self {
            max_entries: 4_096,
            max_history_per_call: 64,
            max_id_bytes: 256,
            max_tool_bytes: 256,
            max_target_bytes: 4_096,
        }
    }
}

impl RegistryLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_entries == 0
            || self.max_history_per_call == 0
            || self.max_id_bytes == 0
            || self.max_tool_bytes == 0
            || self.max_target_bytes == 0
        {
            return Err(invalid("registry limits must be non-zero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TurnScope {
    pub session_id: String,
    pub profile_id: String,
    pub task_id: String,
    pub turn_id: String,
    pub turn_stream_id: String,
}

impl TurnScope {
    pub fn new(
        session_id: impl Into<String>,
        profile_id: impl Into<String>,
        task_id: impl Into<String>,
        turn_id: impl Into<String>,
        turn_stream_id: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            profile_id: profile_id.into(),
            task_id: task_id.into(),
            turn_id: turn_id.into(),
            turn_stream_id: turn_stream_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallKey {
    pub scope: TurnScope,
    pub call_id: String,
}

impl CallKey {
    pub fn new(scope: TurnScope, call_id: impl Into<String>) -> Self {
        Self {
            scope,
            call_id: call_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRequest {
    pub request_sha256: String,
    pub binding_fingerprint: String,
    pub tool: String,
    pub target_id: Option<String>,
}

impl CallRequest {
    pub fn new(
        request_sha256: impl Into<String>,
        binding_fingerprint: impl Into<String>,
        tool: impl Into<String>,
        target_id: Option<String>,
    ) -> Self {
        Self {
            request_sha256: request_sha256.into(),
            binding_fingerprint: binding_fingerprint.into(),
            tool: tool.into(),
            target_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalRecord {
    pub terminal_kind: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub observation_sha256: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
}

impl TerminalRecord {
    pub fn new(
        terminal_kind: impl Into<String>,
        exit_code: Option<i32>,
        signal: Option<i32>,
        observation_sha256: impl Into<String>,
        stdout_bytes: u64,
        stderr_bytes: u64,
    ) -> Self {
        Self {
            terminal_kind: terminal_kind.into(),
            exit_code,
            signal,
            observation_sha256: observation_sha256.into(),
            stdout_bytes,
            stderr_bytes,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CancellationSignal(Arc<AtomicBool>);

impl CancellationSignal {
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }

    /// Returns true only for the first cancellation request.
    pub fn cancel(&self) -> bool {
        !self.0.swap(true, Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallEventKind {
    Accepted,
    SpawnClaimed {
        generation: u64,
    },
    PidObserved {
        generation: u64,
        pid: u32,
    },
    CancelRequested,
    ConnectionLost,
    ConnectionAttached,
    TerminalRecorded {
        generation: u64,
        terminal: TerminalRecord,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEvent {
    pub seq: u64,
    pub kind: CallEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveState {
    Accepted,
    Started {
        generation: u64,
        pid: Option<u32>,
    },
    ProvenNotStartedAfterDisconnect,
    UnknownAfterDisconnect {
        generation: u64,
        pid: Option<u32>,
    },
    Terminal {
        generation: u64,
        terminal: TerminalRecord,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSnapshot {
    pub key: CallKey,
    pub request: CallRequest,
    pub state: EffectiveState,
    pub cancellation_requested: bool,
    pub connection_lost: bool,
    pub earliest_history_seq: u64,
    pub next_event_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginDisposition {
    New,
    Existing,
}

#[derive(Debug, Clone)]
pub struct BeginResult {
    pub disposition: BeginDisposition,
    pub snapshot: CallSnapshot,
    pub cancellation: CancellationSignal,
}

#[derive(Debug, Clone)]
pub enum SpawnClaim {
    Granted {
        generation: u64,
        cancellation: CancellationSignal,
        snapshot: CallSnapshot,
    },
    Existing(CallSnapshot),
    Inhibited(CallSnapshot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOutcome {
    Applied,
    Idempotent,
}

#[derive(Debug, Clone)]
enum DispatchState {
    Accepted {
        spawn_inhibited: bool,
    },
    Started {
        generation: u64,
        pid: Option<u32>,
    },
    Terminal {
        generation: u64,
        terminal: TerminalRecord,
    },
}

#[derive(Debug, Clone)]
struct Entry {
    key: CallKey,
    request: CallRequest,
    dispatch: DispatchState,
    connection_lost: bool,
    cancellation: CancellationSignal,
    history: VecDeque<CallEvent>,
    next_event_seq: u64,
}

impl Entry {
    fn effective_state(&self) -> EffectiveState {
        match &self.dispatch {
            DispatchState::Accepted { spawn_inhibited } => {
                if *spawn_inhibited || self.connection_lost {
                    EffectiveState::ProvenNotStartedAfterDisconnect
                } else {
                    EffectiveState::Accepted
                }
            }
            DispatchState::Started { generation, pid } => {
                if self.connection_lost {
                    EffectiveState::UnknownAfterDisconnect {
                        generation: *generation,
                        pid: *pid,
                    }
                } else {
                    EffectiveState::Started {
                        generation: *generation,
                        pid: *pid,
                    }
                }
            }
            DispatchState::Terminal {
                generation,
                terminal,
            } => EffectiveState::Terminal {
                generation: *generation,
                terminal: terminal.clone(),
            },
        }
    }

    fn snapshot(&self) -> CallSnapshot {
        CallSnapshot {
            key: self.key.clone(),
            request: self.request.clone(),
            state: self.effective_state(),
            cancellation_requested: self.cancellation.is_cancelled(),
            connection_lost: self.connection_lost,
            earliest_history_seq: self
                .history
                .front()
                .map_or(self.next_event_seq, |event| event.seq),
            next_event_seq: self.next_event_seq,
        }
    }

    fn push_event(&mut self, kind: CallEventKind, max_history: usize) {
        let event = CallEvent {
            seq: self.next_event_seq,
            kind,
        };
        self.next_event_seq = self.next_event_seq.saturating_add(1);
        if self.history.len() == max_history {
            self.history.pop_front();
        }
        self.history.push_back(event);
    }
}

#[derive(Debug)]
struct State {
    entries: HashMap<CallKey, Entry>,
    next_spawn_generation: u64,
}

#[derive(Debug)]
pub struct CallRegistry {
    limits: RegistryLimits,
    state: Mutex<State>,
}

impl CallRegistry {
    pub fn new(limits: RegistryLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            state: Mutex::new(State {
                entries: HashMap::new(),
                next_spawn_generation: 1,
            }),
        })
    }

    pub fn begin(&self, key: CallKey, request: CallRequest) -> Result<BeginResult> {
        self.validate_key(&key)?;
        self.validate_request(&request)?;
        let mut state = self.lock()?;
        if let Some(entry) = state.entries.get(&key) {
            if entry.request != request {
                return Err(RegistryError::CallIdConflict);
            }
            return Ok(BeginResult {
                disposition: BeginDisposition::Existing,
                snapshot: entry.snapshot(),
                cancellation: entry.cancellation.clone(),
            });
        }
        if state.entries.len() >= self.limits.max_entries {
            return Err(RegistryError::CapacityExhausted);
        }
        let cancellation = CancellationSignal(Arc::new(AtomicBool::new(false)));
        let mut entry = Entry {
            key: key.clone(),
            request,
            dispatch: DispatchState::Accepted {
                spawn_inhibited: false,
            },
            connection_lost: false,
            cancellation: cancellation.clone(),
            history: VecDeque::new(),
            next_event_seq: 0,
        };
        entry.push_event(CallEventKind::Accepted, self.limits.max_history_per_call);
        let snapshot = entry.snapshot();
        state.entries.insert(key, entry);
        Ok(BeginResult {
            disposition: BeginDisposition::New,
            snapshot,
            cancellation,
        })
    }

    pub fn claim_spawn(&self, key: &CallKey, request_sha256: &str) -> Result<SpawnClaim> {
        require_sha256(request_sha256, "request_sha256")?;
        let mut state = self.lock()?;
        let entry = state.entries.get(key).ok_or(RegistryError::NotFound)?;
        if entry.request.request_sha256 != request_sha256 {
            return Err(RegistryError::RequestDigestMismatch);
        }
        match &entry.dispatch {
            DispatchState::Accepted {
                spawn_inhibited: true,
            } => return Ok(SpawnClaim::Inhibited(entry.snapshot())),
            DispatchState::Started { .. } | DispatchState::Terminal { .. } => {
                return Ok(SpawnClaim::Existing(entry.snapshot()));
            }
            DispatchState::Accepted {
                spawn_inhibited: false,
            } => {}
        }

        let generation = state.next_spawn_generation;
        if generation == 0 || generation == u64::MAX {
            return Err(RegistryError::GenerationExhausted);
        }
        state.next_spawn_generation = generation + 1;
        let entry = state.entries.get_mut(key).ok_or(RegistryError::NotFound)?;
        entry.dispatch = DispatchState::Started {
            generation,
            pid: None,
        };
        entry.push_event(
            CallEventKind::SpawnClaimed { generation },
            self.limits.max_history_per_call,
        );
        Ok(SpawnClaim::Granted {
            generation,
            cancellation: entry.cancellation.clone(),
            snapshot: entry.snapshot(),
        })
    }

    pub fn record_pid(&self, key: &CallKey, generation: u64, pid: u32) -> Result<MutationOutcome> {
        if pid == 0 {
            return Err(invalid("pid must be non-zero"));
        }
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(RegistryError::NotFound)?;
        match &mut entry.dispatch {
            DispatchState::Started {
                generation: expected,
                pid: observed,
            } if *expected == generation => match observed {
                Some(existing) if *existing == pid => Ok(MutationOutcome::Idempotent),
                Some(_) => Err(RegistryError::PidConflict),
                None => {
                    *observed = Some(pid);
                    entry.push_event(
                        CallEventKind::PidObserved { generation, pid },
                        self.limits.max_history_per_call,
                    );
                    Ok(MutationOutcome::Applied)
                }
            },
            DispatchState::Started { .. } | DispatchState::Terminal { .. } => {
                Err(RegistryError::SpawnGenerationMismatch)
            }
            DispatchState::Accepted { .. } => Err(RegistryError::InvalidTransition(
                "cannot record a pid before spawn is claimed",
            )),
        }
    }

    pub fn request_cancel(&self, key: &CallKey) -> Result<CallSnapshot> {
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(RegistryError::NotFound)?;
        if entry.cancellation.cancel() {
            entry.push_event(
                CallEventKind::CancelRequested,
                self.limits.max_history_per_call,
            );
        }
        Ok(entry.snapshot())
    }

    pub fn mark_connection_lost(&self, key: &CallKey) -> Result<CallSnapshot> {
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(RegistryError::NotFound)?;
        if !entry.connection_lost {
            entry.connection_lost = true;
            if let DispatchState::Accepted { spawn_inhibited } = &mut entry.dispatch {
                *spawn_inhibited = true;
            }
            entry.push_event(
                CallEventKind::ConnectionLost,
                self.limits.max_history_per_call,
            );
        }
        Ok(entry.snapshot())
    }

    pub fn mark_connection_attached(&self, key: &CallKey) -> Result<CallSnapshot> {
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(RegistryError::NotFound)?;
        if entry.connection_lost {
            entry.connection_lost = false;
            entry.push_event(
                CallEventKind::ConnectionAttached,
                self.limits.max_history_per_call,
            );
        }
        Ok(entry.snapshot())
    }

    pub fn complete(
        &self,
        key: &CallKey,
        generation: u64,
        terminal: TerminalRecord,
    ) -> Result<MutationOutcome> {
        self.validate_terminal(&terminal)?;
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(RegistryError::NotFound)?;
        match &entry.dispatch {
            DispatchState::Started {
                generation: expected,
                ..
            } if *expected == generation => {}
            DispatchState::Started { .. } => {
                return Err(RegistryError::SpawnGenerationMismatch);
            }
            DispatchState::Terminal {
                generation: expected,
                terminal: existing,
            } if *expected == generation && *existing == terminal => {
                return Ok(MutationOutcome::Idempotent);
            }
            DispatchState::Terminal { .. } => return Err(RegistryError::TerminalConflict),
            DispatchState::Accepted { .. } => {
                return Err(RegistryError::InvalidTransition(
                    "cannot complete a call before spawn is claimed",
                ));
            }
        }
        entry.dispatch = DispatchState::Terminal {
            generation,
            terminal: terminal.clone(),
        };
        entry.push_event(
            CallEventKind::TerminalRecorded {
                generation,
                terminal,
            },
            self.limits.max_history_per_call,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn snapshot(&self, key: &CallKey) -> Result<CallSnapshot> {
        let state = self.lock()?;
        state
            .entries
            .get(key)
            .map(Entry::snapshot)
            .ok_or(RegistryError::NotFound)
    }

    pub fn history_from(&self, key: &CallKey, inclusive_seq: u64) -> Result<Vec<CallEvent>> {
        let state = self.lock()?;
        let entry = state.entries.get(key).ok_or(RegistryError::NotFound)?;
        Ok(entry
            .history
            .iter()
            .filter(|event| event.seq >= inclusive_seq)
            .cloned()
            .collect())
    }

    pub fn remove_terminal(&self, key: &CallKey) -> Result<bool> {
        let mut state = self.lock()?;
        let terminal = state
            .entries
            .get(key)
            .is_some_and(|entry| matches!(entry.dispatch, DispatchState::Terminal { .. }));
        if terminal {
            state.entries.remove(key);
        }
        Ok(terminal)
    }

    #[must_use]
    pub fn len(&self) -> Result<usize> {
        Ok(self.lock()?.entries.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| RegistryError::StatePoisoned)
    }

    fn validate_key(&self, key: &CallKey) -> Result<()> {
        for (label, value) in [
            ("session_id", key.scope.session_id.as_str()),
            ("profile_id", key.scope.profile_id.as_str()),
            ("task_id", key.scope.task_id.as_str()),
            ("turn_id", key.scope.turn_id.as_str()),
            ("turn_stream_id", key.scope.turn_stream_id.as_str()),
            ("call_id", key.call_id.as_str()),
        ] {
            require_id(value, label, self.limits.max_id_bytes)?;
        }
        Ok(())
    }

    fn validate_request(&self, request: &CallRequest) -> Result<()> {
        require_sha256(&request.request_sha256, "request_sha256")?;
        require_sha256(&request.binding_fingerprint, "binding_fingerprint")?;
        require_text(&request.tool, "tool", self.limits.max_tool_bytes, false)?;
        if let Some(target_id) = &request.target_id {
            require_text(target_id, "target_id", self.limits.max_target_bytes, true)?;
        }
        Ok(())
    }

    fn validate_terminal(&self, terminal: &TerminalRecord) -> Result<()> {
        require_text(&terminal.terminal_kind, "terminal_kind", 128, false)?;
        require_sha256(&terminal.observation_sha256, "observation_sha256")?;
        if terminal
            .signal
            .is_some_and(|signal| !(1..=128).contains(&signal))
        {
            return Err(invalid("terminal signal is outside the supported range"));
        }
        if terminal.exit_code.is_some() && terminal.signal.is_some() {
            return Err(invalid("terminal cannot contain both exit code and signal"));
        }
        Ok(())
    }
}

impl Default for CallRegistry {
    fn default() -> Self {
        Self::new(RegistryLimits::default()).expect("default call registry limits are valid")
    }
}

fn require_id(value: &str, label: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid(format!("{label} is empty, oversized or malformed")));
    }
    Ok(())
}

fn require_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid(format!("{label} must be a lowercase SHA-256")));
    }
    Ok(())
}

fn require_text(value: &str, label: &str, maximum: usize, allow_empty: bool) -> Result<()> {
    if (!allow_empty && value.is_empty())
        || value.len() > maximum
        || value.as_bytes().contains(&0)
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!("{label} is empty, oversized or malformed")));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> RegistryError {
    RegistryError::InvalidRequest(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> TurnScope {
        TurnScope::new("session-1", "owner-open", "task-1", "turn-1", "stream-1")
    }

    fn key(call_id: &str) -> CallKey {
        CallKey::new(scope(), call_id)
    }

    fn request(seed: char) -> CallRequest {
        CallRequest::new(
            seed.to_string().repeat(64),
            "b".repeat(64),
            "shell.exec",
            Some("rootlinux".to_string()),
        )
    }

    fn terminal(seed: char) -> TerminalRecord {
        TerminalRecord::new("exited", Some(0), None, seed.to_string().repeat(64), 3, 4)
    }

    #[test]
    fn begin_is_idempotent_for_exact_request_and_conflicts_on_drift() {
        let registry = CallRegistry::default();
        let call = key("call-1");
        let first = registry.begin(call.clone(), request('a')).unwrap();
        assert_eq!(first.disposition, BeginDisposition::New);
        assert_eq!(first.snapshot.state, EffectiveState::Accepted);
        let again = registry.begin(call.clone(), request('a')).unwrap();
        assert_eq!(again.disposition, BeginDisposition::Existing);
        assert_eq!(again.snapshot.next_event_seq, 1);
        assert_eq!(
            registry.begin(call, request('c')).unwrap_err(),
            RegistryError::CallIdConflict
        );
    }

    #[test]
    fn disconnect_before_spawn_permanently_inhibits_the_call() {
        let registry = CallRegistry::default();
        let call = key("call-not-started");
        registry.begin(call.clone(), request('a')).unwrap();
        let lost = registry.mark_connection_lost(&call).unwrap();
        assert_eq!(lost.state, EffectiveState::ProvenNotStartedAfterDisconnect);
        let attached = registry.mark_connection_attached(&call).unwrap();
        assert_eq!(
            attached.state,
            EffectiveState::ProvenNotStartedAfterDisconnect
        );
        match registry.claim_spawn(&call, &"a".repeat(64)).unwrap() {
            SpawnClaim::Inhibited(snapshot) => assert_eq!(
                snapshot.state,
                EffectiveState::ProvenNotStartedAfterDisconnect
            ),
            other => panic!("unexpected spawn claim: {other:?}"),
        }
    }

    #[test]
    fn disconnect_after_spawn_is_unknown_until_late_terminal_arrives() {
        let registry = CallRegistry::default();
        let call = key("call-unknown");
        registry.begin(call.clone(), request('a')).unwrap();
        let generation = match registry.claim_spawn(&call, &"a".repeat(64)).unwrap() {
            SpawnClaim::Granted { generation, .. } => generation,
            other => panic!("unexpected spawn claim: {other:?}"),
        };
        registry.record_pid(&call, generation, 42).unwrap();
        let lost = registry.mark_connection_lost(&call).unwrap();
        assert_eq!(
            lost.state,
            EffectiveState::UnknownAfterDisconnect {
                generation,
                pid: Some(42)
            }
        );
        registry.complete(&call, generation, terminal('d')).unwrap();
        assert_eq!(
            registry.snapshot(&call).unwrap().state,
            EffectiveState::Terminal {
                generation,
                terminal: terminal('d')
            }
        );
    }

    #[test]
    fn cancellation_signal_is_shared_and_event_is_idempotent() {
        let registry = CallRegistry::default();
        let call = key("call-cancel");
        let begin = registry.begin(call.clone(), request('a')).unwrap();
        assert!(!begin.cancellation.is_cancelled());
        let first = registry.request_cancel(&call).unwrap();
        assert!(first.cancellation_requested);
        assert!(begin.cancellation.is_cancelled());
        let second = registry.request_cancel(&call).unwrap();
        assert_eq!(first.next_event_seq, second.next_event_seq);
        assert_eq!(
            registry
                .history_from(&call, 0)
                .unwrap()
                .iter()
                .filter(|event| matches!(event.kind, CallEventKind::CancelRequested))
                .count(),
            1
        );
    }

    #[test]
    fn terminal_is_exactly_once_and_exact_duplicate_is_idempotent() {
        let registry = CallRegistry::default();
        let call = key("call-terminal");
        registry.begin(call.clone(), request('a')).unwrap();
        let generation = match registry.claim_spawn(&call, &"a".repeat(64)).unwrap() {
            SpawnClaim::Granted { generation, .. } => generation,
            other => panic!("unexpected spawn claim: {other:?}"),
        };
        assert_eq!(
            registry.complete(&call, generation, terminal('d')).unwrap(),
            MutationOutcome::Applied
        );
        assert_eq!(
            registry.complete(&call, generation, terminal('d')).unwrap(),
            MutationOutcome::Idempotent
        );
        assert_eq!(
            registry
                .complete(&call, generation, terminal('e'))
                .unwrap_err(),
            RegistryError::TerminalConflict
        );
    }

    #[test]
    fn history_is_bounded_with_an_explicit_earliest_cursor() {
        let registry = CallRegistry::new(RegistryLimits {
            max_history_per_call: 3,
            ..RegistryLimits::default()
        })
        .unwrap();
        let call = key("call-history");
        registry.begin(call.clone(), request('a')).unwrap();
        registry.request_cancel(&call).unwrap();
        registry.mark_connection_lost(&call).unwrap();
        registry.mark_connection_attached(&call).unwrap();
        let snapshot = registry.snapshot(&call).unwrap();
        assert_eq!(snapshot.earliest_history_seq, 1);
        assert_eq!(snapshot.next_event_seq, 4);
        assert_eq!(
            registry
                .history_from(&call, 0)
                .unwrap()
                .iter()
                .map(|event| event.seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn terminal_cleanup_is_explicit_and_only_removes_terminal_calls() {
        let registry = CallRegistry::default();
        let active = key("call-active");
        registry.begin(active.clone(), request('a')).unwrap();
        assert!(!registry.remove_terminal(&active).unwrap());
        let finished = key("call-finished");
        registry.begin(finished.clone(), request('c')).unwrap();
        let generation = match registry.claim_spawn(&finished, &"c".repeat(64)).unwrap() {
            SpawnClaim::Granted { generation, .. } => generation,
            other => panic!("unexpected spawn claim: {other:?}"),
        };
        registry
            .complete(&finished, generation, terminal('d'))
            .unwrap();
        assert!(registry.remove_terminal(&finished).unwrap());
        assert_eq!(registry.len().unwrap(), 1);
    }
}
