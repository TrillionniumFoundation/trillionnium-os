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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

// Registry state is partitioned by a versioned, deterministic hash.  The
// count is deliberately fixed for this state schema: changing it changes the
// ownership of existing keys and therefore requires a migration, rather than
// silently rehashing a live registry.
const REGISTRY_SHARD_COUNT: usize = 64;
const REGISTRY_SHARD_HASH_VERSION: u8 = 1;
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;

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

/// Hard upper bounds for caller-provided registry limits.
///
/// `RegistryLimits` is part of the local configuration surface, so checking
/// only for zero is not enough: a malformed configuration could otherwise
/// make an attacker-controlled admission path reserve an effectively
/// unbounded number of entries or retain an unbounded event history.  The
/// defaults remain deliberately below these ceilings; deployments may lower
/// them, but never raise them past the schema-level bound.
pub const MAX_REGISTRY_ENTRIES: usize = 1_048_576;
pub const MAX_HISTORY_PER_CALL: usize = 16_384;
pub const MAX_ID_BYTES: usize = 4_096;
pub const MAX_TOOL_BYTES: usize = 64 * 1024;
pub const MAX_TARGET_BYTES: usize = 1_048_576;

/// Bound the total number of retained history slots implied by a registry
/// configuration.  Histories are allocated lazily, but this product still
/// provides a useful worst-case memory fence for a configuration review.
pub const MAX_HISTORY_SLOTS: usize = 16 * 1024 * 1024;

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
        if self.max_entries > MAX_REGISTRY_ENTRIES
            || self.max_history_per_call > MAX_HISTORY_PER_CALL
            || self.max_id_bytes > MAX_ID_BYTES
            || self.max_tool_bytes > MAX_TOOL_BYTES
            || self.max_target_bytes > MAX_TARGET_BYTES
        {
            return Err(invalid(format!(
                "registry limits exceed hard bounds (entries <= {MAX_REGISTRY_ENTRIES}, history <= {MAX_HISTORY_PER_CALL}, id <= {MAX_ID_BYTES}, tool <= {MAX_TOOL_BYTES}, target <= {MAX_TARGET_BYTES})"
            )));
        }
        if self
            .max_entries
            .checked_mul(self.max_history_per_call)
            .is_none_or(|slots| slots > MAX_HISTORY_SLOTS)
        {
            return Err(invalid(format!(
                "registry entry/history product exceeds hard bound {MAX_HISTORY_SLOTS}"
            )));
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
    /// Return the per-call cancellation flag for a lower-level runtime that
    /// can observe linked scopes directly.  The flag is never shared across
    /// registry entries unless an enclosing caller explicitly supplies it.
    #[must_use]
    pub fn shared_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.0)
    }

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
    /// The accepted call was fenced before spawn after a local failure that
    /// could not prove the entry was still untouched.  This is deliberately
    /// distinct from `ConnectionLost`: the transport may still be healthy,
    /// but the call is no longer eligible for a spawn claim.
    SpawnInhibited,
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
    CancelledBeforeSpawn,
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
                if self.cancellation.is_cancelled() {
                    EffectiveState::CancelledBeforeSpawn
                } else if *spawn_inhibited || self.connection_lost {
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
struct ShardState {
    entries: HashMap<CallKey, Entry>,
}

#[derive(Debug)]
pub struct CallRegistry {
    limits: RegistryLimits,
    shards: Vec<Mutex<ShardState>>,
    entry_count: AtomicUsize,
    next_spawn_generation: AtomicU64,
    state_poisoned: AtomicBool,
}

impl CallRegistry {
    pub fn new(limits: RegistryLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            shards: (0..REGISTRY_SHARD_COUNT)
                .map(|_| {
                    Mutex::new(ShardState {
                        entries: HashMap::new(),
                    })
                })
                .collect(),
            entry_count: AtomicUsize::new(0),
            next_spawn_generation: AtomicU64::new(1),
            state_poisoned: AtomicBool::new(false),
        })
    }

    pub fn begin(&self, key: CallKey, request: CallRequest) -> Result<BeginResult> {
        self.ensure_healthy()?;
        self.validate_key(&key)?;
        self.validate_request(&request)?;
        let mut state = self.lock_shard(&key)?;
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
        self.reserve_entry()?;
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
        let previous = state.entries.insert(key, entry);
        debug_assert!(previous.is_none(), "key was checked under its shard lock");
        Ok(BeginResult {
            disposition: BeginDisposition::New,
            snapshot,
            cancellation,
        })
    }

    /// Roll back an acceptance that has not crossed the spawn boundary.
    ///
    /// This is used when a caller reserves a fresh key and a subsequent
    /// pre-spawn registry step fails.  The exact request and every mutable
    /// pre-start field are checked while holding the key shard, so a
    /// concurrent lifecycle transition can never cause a live or claimed
    /// entry to be removed accidentally.  `Ok(false)` means the key was
    /// already absent; a present but changed entry is an explicit transition
    /// error and must be fenced by the caller instead of being retried.
    pub fn rollback_accept(&self, key: &CallKey, request: &CallRequest) -> Result<bool> {
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
        let Some(entry) = state.entries.get(key) else {
            return Ok(false);
        };
        if entry.request != *request {
            return Err(RegistryError::CallIdConflict);
        }
        let rollbackable = matches!(
            entry.dispatch,
            DispatchState::Accepted {
                spawn_inhibited: false
            }
        ) && !entry.connection_lost
            && !entry.cancellation.is_cancelled()
            && entry.history.len() == 1
            && matches!(
                entry.history.front().map(|event| &event.kind),
                Some(CallEventKind::Accepted)
            );
        if !rollbackable {
            return Err(RegistryError::InvalidTransition(
                "only an untouched accepted call can be rolled back",
            ));
        }
        let removed = state.entries.remove(key);
        debug_assert!(removed.is_some());
        self.release_entry();
        Ok(true)
    }

    /// Fence an accepted call against any future spawn claim.
    ///
    /// Unlike `mark_connection_lost`, this records no transport assertion.
    /// It is the fail-closed fallback when a local pre-spawn failure races a
    /// lifecycle transition and exact rollback is no longer provable.  The
    /// effective state intentionally remains the existing conservative
    /// `ProvenNotStartedAfterDisconnect` no-start barrier for compatibility;
    /// the history event identifies the actual cause.
    pub fn inhibit_spawn(&self, key: &CallKey) -> Result<CallSnapshot> {
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
        let entry = state.entries.get_mut(key).ok_or(RegistryError::NotFound)?;
        if let DispatchState::Accepted { spawn_inhibited } = &mut entry.dispatch
            && !*spawn_inhibited
        {
            *spawn_inhibited = true;
            entry.push_event(
                CallEventKind::SpawnInhibited,
                self.limits.max_history_per_call,
            );
        }
        Ok(entry.snapshot())
    }

    pub fn claim_spawn(&self, key: &CallKey, request_sha256: &str) -> Result<SpawnClaim> {
        self.ensure_healthy()?;
        require_sha256(request_sha256, "request_sha256")?;
        let mut state = self.lock_shard(key)?;
        let entry = state.entries.get(key).ok_or(RegistryError::NotFound)?;
        if entry.request.request_sha256 != request_sha256 {
            return Err(RegistryError::RequestDigestMismatch);
        }
        match &entry.dispatch {
            DispatchState::Accepted { spawn_inhibited }
                if *spawn_inhibited || entry.cancellation.is_cancelled() =>
            {
                return Ok(SpawnClaim::Inhibited(entry.snapshot()));
            }
            DispatchState::Started { .. } | DispatchState::Terminal { .. } => {
                return Ok(SpawnClaim::Existing(entry.snapshot()));
            }
            DispatchState::Accepted { .. } => {}
        }

        let generation = self.allocate_generation()?;
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
        self.ensure_healthy()?;
        if pid == 0 {
            return Err(invalid("pid must be non-zero"));
        }
        let mut state = self.lock_shard(key)?;
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
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
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
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
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
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
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
        self.ensure_healthy()?;
        self.validate_terminal(&terminal)?;
        let mut state = self.lock_shard(key)?;
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
        self.ensure_healthy()?;
        let state = self.lock_shard(key)?;
        state
            .entries
            .get(key)
            .map(Entry::snapshot)
            .ok_or(RegistryError::NotFound)
    }

    pub fn history_from(&self, key: &CallKey, inclusive_seq: u64) -> Result<Vec<CallEvent>> {
        self.ensure_healthy()?;
        let state = self.lock_shard(key)?;
        let entry = state.entries.get(key).ok_or(RegistryError::NotFound)?;
        Ok(entry
            .history
            .iter()
            .filter(|event| event.seq >= inclusive_seq)
            .cloned()
            .collect())
    }

    pub fn remove_terminal(&self, key: &CallKey) -> Result<bool> {
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
        let terminal = state
            .entries
            .get(key)
            .is_some_and(|entry| matches!(entry.dispatch, DispatchState::Terminal { .. }));
        if terminal {
            let removed = state.entries.remove(key);
            debug_assert!(removed.is_some());
            self.release_entry();
        }
        Ok(terminal)
    }

    pub fn len(&self) -> Result<usize> {
        self.ensure_healthy()?;
        Ok(self.entry_count.load(Ordering::Acquire))
    }

    pub fn is_empty(&self) -> Result<bool> {
        self.ensure_healthy()?;
        Ok(self.entry_count.load(Ordering::Acquire) == 0)
    }

    /// Number of independent state shards used by this registry.
    ///
    /// This is exposed for diagnostics and benchmark metadata; it is not a
    /// caller-selectable policy knob because changing the count requires a
    /// state migration.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    fn shard_index(&self, key: &CallKey) -> usize {
        stable_shard_index(
            b"owner-open-call-registry",
            &[
                &key.scope.session_id,
                &key.scope.profile_id,
                &key.scope.task_id,
                &key.scope.turn_id,
                &key.scope.turn_stream_id,
                &key.call_id,
            ],
        )
    }

    fn lock_shard(&self, key: &CallKey) -> Result<MutexGuard<'_, ShardState>> {
        self.shards[self.shard_index(key)].lock().map_err(|_| {
            self.state_poisoned.store(true, Ordering::Release);
            RegistryError::StatePoisoned
        })
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.state_poisoned.load(Ordering::Acquire) {
            return Err(RegistryError::StatePoisoned);
        }
        // A shard can be poisoned by code that held its mutex directly (for
        // example, a diagnostic or a future maintenance operation) before a
        // registry method gets a chance to call `lock_shard`.  Inspect the
        // mutex poison bits as well as the fast-path latch so aggregate
        // observations such as `len` and `is_empty` fail closed immediately.
        let shard_poisoned = self.shards.iter().any(Mutex::is_poisoned);
        if shard_poisoned {
            self.state_poisoned.store(true, Ordering::Release);
        }
        if self.state_poisoned.load(Ordering::Acquire) {
            Err(RegistryError::StatePoisoned)
        } else {
            Ok(())
        }
    }

    fn reserve_entry(&self) -> Result<()> {
        let mut current = self.entry_count.load(Ordering::Acquire);
        loop {
            if current >= self.limits.max_entries {
                return Err(RegistryError::CapacityExhausted);
            }
            let next = current
                .checked_add(1)
                .ok_or(RegistryError::CapacityExhausted)?;
            match self.entry_count.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    fn release_entry(&self) {
        let previous = self.entry_count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "call registry entry count underflow");
    }

    fn allocate_generation(&self) -> Result<u64> {
        let mut current = self.next_spawn_generation.load(Ordering::Acquire);
        loop {
            if current == 0 || current == u64::MAX {
                return Err(RegistryError::GenerationExhausted);
            }
            match self.next_spawn_generation.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(current),
                Err(observed) => current = observed,
            }
        }
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

/// Return a stable shard for a sequence of length-delimited fields.
///
/// This is intentionally a small non-cryptographic hash: shard selection is
/// an implementation detail, not an authorization decision.  The explicit
/// version and shard count are part of the preimage so a future layout change
/// cannot silently reinterpret persisted or in-flight state.
fn stable_shard_index(domain: &[u8], fields: &[&str]) -> usize {
    let mut hash = FNV_OFFSET_BASIS;
    fn feed(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    fn feed_len(hash: &mut u64, length: usize) {
        feed(hash, &(length as u64).to_be_bytes());
    }

    feed(&mut hash, &[REGISTRY_SHARD_HASH_VERSION]);
    feed_len(&mut hash, REGISTRY_SHARD_COUNT);
    feed_len(&mut hash, domain.len());
    feed(&mut hash, domain);
    for field in fields {
        feed_len(&mut hash, field.len());
        feed(&mut hash, field.as_bytes());
    }
    (hash % REGISTRY_SHARD_COUNT as u64) as usize
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
    fn configured_limits_cannot_escape_schema_hard_bounds() {
        let oversized = [
            RegistryLimits {
                max_entries: MAX_REGISTRY_ENTRIES + 1,
                ..RegistryLimits::default()
            },
            RegistryLimits {
                max_history_per_call: MAX_HISTORY_PER_CALL + 1,
                ..RegistryLimits::default()
            },
            RegistryLimits {
                max_id_bytes: MAX_ID_BYTES + 1,
                ..RegistryLimits::default()
            },
            RegistryLimits {
                max_tool_bytes: MAX_TOOL_BYTES + 1,
                ..RegistryLimits::default()
            },
            RegistryLimits {
                max_target_bytes: MAX_TARGET_BYTES + 1,
                ..RegistryLimits::default()
            },
        ];
        for limits in oversized {
            assert!(
                CallRegistry::new(limits).is_err(),
                "configured call-registry limit exceeded its hard bound"
            );
        }
        assert!(
            CallRegistry::new(RegistryLimits {
                max_entries: MAX_REGISTRY_ENTRIES,
                max_history_per_call: MAX_HISTORY_SLOTS / MAX_REGISTRY_ENTRIES + 1,
                ..RegistryLimits::default()
            })
            .is_err(),
            "entry/history product must remain bounded"
        );
        assert!(
            CallRegistry::new(RegistryLimits {
                max_entries: MAX_HISTORY_SLOTS / 64,
                max_history_per_call: 64,
                ..RegistryLimits::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn poisoned_shard_fails_closed_for_observation_and_admission() {
        let registry = CallRegistry::default();
        let call = key("call-poisoned");
        let shard_index = registry.shard_index(&call);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = registry.shards[shard_index].lock().unwrap();
            panic!("intentional shard poison for regression test");
        }));

        assert_eq!(registry.len(), Err(RegistryError::StatePoisoned));
        assert_eq!(registry.is_empty(), Err(RegistryError::StatePoisoned));
        assert_eq!(
            registry.begin(call, request('p')).unwrap_err(),
            RegistryError::StatePoisoned
        );
    }

    #[test]
    fn untouched_acceptance_can_be_rolled_back_and_failed_cleanup_is_fenced() {
        let registry = CallRegistry::default();
        let call = key("call-rollback");
        let request = request('a');
        registry.begin(call.clone(), request.clone()).unwrap();
        assert!(registry.rollback_accept(&call, &request).unwrap());
        assert_eq!(
            registry.snapshot(&call).unwrap_err(),
            RegistryError::NotFound
        );
        assert!(registry.is_empty().unwrap());

        registry.begin(call.clone(), request.clone()).unwrap();
        let inhibited = registry.inhibit_spawn(&call).unwrap();
        assert_eq!(
            inhibited.state,
            EffectiveState::ProvenNotStartedAfterDisconnect
        );
        assert_eq!(
            registry.rollback_accept(&call, &request).unwrap_err(),
            RegistryError::InvalidTransition("only an untouched accepted call can be rolled back")
        );
        assert!(matches!(
            registry
                .claim_spawn(&call, &request.request_sha256)
                .unwrap(),
            SpawnClaim::Inhibited(_)
        ));
        assert!(matches!(
            registry.history_from(&call, 0).unwrap().as_slice(),
            [
                CallEvent {
                    kind: CallEventKind::Accepted,
                    ..
                },
                CallEvent {
                    kind: CallEventKind::SpawnInhibited,
                    ..
                }
            ]
        ));
    }

    #[test]
    fn generation_failure_leaves_an_entry_rollbackable_before_spawn() {
        let registry = CallRegistry::default();
        let call = key("call-generation-exhausted");
        let request = request('b');
        registry.begin(call.clone(), request.clone()).unwrap();
        registry
            .next_spawn_generation
            .store(u64::MAX, Ordering::Release);
        assert_eq!(
            registry
                .claim_spawn(&call, &request.request_sha256)
                .unwrap_err(),
            RegistryError::GenerationExhausted
        );
        assert!(registry.rollback_accept(&call, &request).unwrap());
        assert!(registry.is_empty().unwrap());
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

    #[test]
    fn shard_mapping_is_versioned_and_stable() {
        let registry = CallRegistry::default();
        // Keep one golden vector so a future hash/count change cannot silently
        // move live keys without an explicit schema migration.
        assert_eq!(
            registry.shard_index(&key("call-1")),
            42,
            "registry shard hash vector changed"
        );
        let another_instance = CallRegistry::default();
        assert_eq!(
            registry.shard_index(&key("call-1")),
            another_instance.shard_index(&key("call-1"))
        );
    }

    #[test]
    fn shard_mapping_has_bounded_collision_pressure_for_typical_keys() {
        let registry = CallRegistry::default();
        let mut occupied = std::collections::HashSet::new();
        for index in 0..4_096 {
            occupied.insert(registry.shard_index(&key(&format!("call-distribution-{index}"))));
        }
        assert!(
            occupied.len() >= REGISTRY_SHARD_COUNT / 2,
            "deterministic shard hash is unexpectedly concentrated: {occupied:?}"
        );
    }

    #[test]
    fn an_independent_shard_progresses_while_one_shard_is_held() {
        use std::sync::mpsc::sync_channel;
        use std::time::Duration;

        let registry = Arc::new(CallRegistry::default());
        let blocked = key("call-blocked-shard");
        let blocked_index = registry.shard_index(&blocked);
        let independent = (0..10_000)
            .map(|index| key(&format!("call-independent-{index}")))
            .find(|candidate| registry.shard_index(candidate) != blocked_index)
            .expect("fixed shard count must provide an independent key");

        let guard = registry.shards[blocked_index]
            .lock()
            .expect("blocked shard lock");
        let worker_registry = Arc::clone(&registry);
        let (sender, receiver) = sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = worker_registry.begin(independent, request('c'));
            sender.send(result).expect("send independent result");
        });
        let result = receiver.recv_timeout(Duration::from_secs(1));
        drop(guard);
        let result = result
            .expect("an unrelated key must not wait on another shard")
            .expect("independent begin must succeed");
        worker.join().expect("independent shard worker");
        assert_eq!(result.disposition, BeginDisposition::New);
    }

    #[test]
    fn concurrent_admission_never_exceeds_global_capacity() {
        use std::sync::{Arc, Barrier};

        const LIMIT: usize = 8;
        const THREADS: usize = 64;
        let registry = Arc::new(
            CallRegistry::new(RegistryLimits {
                max_entries: LIMIT,
                ..RegistryLimits::default()
            })
            .expect("valid limits"),
        );
        let barrier = Arc::new(Barrier::new(THREADS));
        let workers = (0..THREADS)
            .map(|index| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    registry.begin(key(&format!("call-capacity-{index}")), request('d'))
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("capacity worker"))
            .collect::<Vec<_>>();
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            LIMIT
        );
        assert_eq!(registry.len().unwrap(), LIMIT);
    }
}
