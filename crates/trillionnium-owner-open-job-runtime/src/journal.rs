use std::collections::HashMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_event_store::{
    DurableEventStore, EventInput, EventRecord, EventStoreLimits, SegmentedEventStore,
    SegmentedEventStoreConfig, SyncPolicy, TurnScope,
};
use trillionnium_owner_open_job_registry::{JobKey, JobMemoryLease, JobRequest};

use crate::validate::{require_id, require_sha256, require_text};
use crate::{JobRuntimeError, Result};

/// Canonical schema carried by every durable job-journal envelope.
pub const JOB_JOURNAL_SCHEMA: &str = "trillionnium.owner-open.job-journal.v1";
const JOURNAL_SCHEMA: &str = JOB_JOURNAL_SCHEMA;

// Journal state transitions are serialized per job key.  The fixed layout is
// an in-memory implementation detail (there is no persisted shard ownership),
// but keeping the version/count explicit makes the contention topology stable
// for diagnostics and prevents accidental use of a process-randomized hash in
// benchmark comparisons.
const JOURNAL_SHARD_COUNT: usize = 64;
const JOURNAL_SHARD_HASH_VERSION: u8 = 1;
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;

/// Select the durability boundary for a journal envelope.  Operation
/// acceptance and terminal records are authority records: a segmented store
/// must force them through its sync barrier before the caller may treat the
/// transition as durable.  Ordinary observations can use the event-store's
/// bounded group-commit path.
#[derive(Debug, Clone, Copy)]
enum AppendMode {
    Durable,
    Grouped,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalStatus {
    Durable,
    BestEffortMemoryOnly,
    Unavailable { error: String },
}

#[derive(Debug, Clone, PartialEq)]
pub enum OperationBegin {
    New,
    ExistingTerminal(Value),
    ExistingAccepted { restart_uncertain: bool },
    Unjournaled,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RecoveredJob {
    pub key: JobKey,
    pub request: JobRequest,
    pub start_result: Option<Value>,
    pub terminal: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OperationKey {
    job: JobKey,
    operation_id: String,
}

#[derive(Debug, Clone)]
struct OperationState {
    /// The full canonical request accepted for this operation.  Keeping the
    /// request alongside the operation digest prevents a later terminal call
    /// (or a recovered record) from silently changing the effect identity.
    request: JobRequest,
    operation_kind: String,
    operation_sha256: String,
    terminal: Option<CachedPayload>,
    preexisting: bool,
    /// True only when the accepted record was committed to the durable store.
    /// This prevents a later journal outage from being mistaken for a
    /// successful after-effect append.
    durable_accept: bool,
}

#[derive(Debug, Clone)]
struct JobState {
    request: JobRequest,
    start_result: Option<CachedPayload>,
    terminal: Option<CachedPayload>,
    next_runtime_cursor: u64,
}

type OperationStates = HashMap<OperationKey, OperationState>;
type JobStates = HashMap<JobKey, JobState>;
type RecoveredState = (OperationStates, JobStates, Vec<JobMemoryLease>);

#[derive(Debug, Clone, PartialEq)]
enum CachedPayload {
    Memory(Arc<Value>),
    Durable {
        event_id: String,
        record_sha256: String,
    },
}

#[derive(Debug)]
enum EventStoreBackend {
    Legacy(Box<DurableEventStore>),
    Segmented(Box<SegmentedEventStore>),
}

impl EventStoreBackend {
    fn append(&self, input: EventInput) -> trillionnium_owner_open_event_store::Result<String> {
        match self {
            Self::Legacy(store) => store
                .append(input)
                .map(|result| result.record.record_sha256),
            Self::Segmented(store) => store
                .append(input)
                .map(|result| result.record.record_sha256),
        }
    }

    fn append_durable(
        &self,
        input: EventInput,
    ) -> trillionnium_owner_open_event_store::Result<String> {
        match self {
            Self::Legacy(store) => store
                .append(input)
                .map(|result| result.record.record_sha256),
            Self::Segmented(store) => store
                .append_durable(input)
                .map(|result| result.record.record_sha256),
        }
    }

    fn get(
        &self,
        scope: &TurnScope,
        event_id: &str,
    ) -> trillionnium_owner_open_event_store::Result<Option<EventRecord>> {
        match self {
            Self::Legacy(store) => store.get(scope, event_id),
            Self::Segmented(store) => store.get(scope, event_id),
        }
    }

    fn visit_records<E>(
        &self,
        visit: impl FnMut(&EventRecord) -> std::result::Result<(), E>,
    ) -> trillionnium_owner_open_event_store::Result<std::result::Result<(), E>> {
        match self {
            Self::Legacy(store) => store.visit_records(visit),
            Self::Segmented(store) => store.visit_records(visit),
        }
    }

    fn visit_scope_records<E>(
        &self,
        scope: &TurnScope,
        visit: impl FnMut(&EventRecord) -> std::result::Result<(), E>,
    ) -> trillionnium_owner_open_event_store::Result<std::result::Result<(), E>> {
        match self {
            Self::Legacy(store) => store.visit_scope_records(scope, 0, visit),
            Self::Segmented(store) => store.visit_scope_records(scope, 0, visit),
        }
    }

    fn flush(&self) -> trillionnium_owner_open_event_store::Result<()> {
        match self {
            // v1 journal appends use SyncPolicy::Full, so there is no pending
            // group-commit queue to drain here.
            Self::Legacy(_) => Ok(()),
            Self::Segmented(store) => store.flush(),
        }
    }
}

#[derive(Debug)]
struct State {
    store: Option<Arc<EventStoreBackend>>,
    configured: bool,
    error: Option<String>,
    operations: HashMap<OperationKey, OperationState>,
    jobs: HashMap<JobKey, JobState>,
    charges: Vec<JobMemoryLease>,
    #[cfg(test)]
    fail_next_accept: bool,
    #[cfg(test)]
    fail_next_observation: bool,
}

#[derive(Debug)]
pub struct JobJournal {
    state: Mutex<State>,
    key_shards: Vec<Mutex<()>>,
    _fixed_lease: Option<JobMemoryLease>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    schema: String,
    record: String,
    job_id: String,
    request: JobRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    operation_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_seq: Option<u64>,
    payload: Value,
}

/// Decode only the fixed envelope identity while borrowing a store record.
/// IgnoredAny avoids cloning a large terminal/output payload during recovery.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalHeader {
    schema: String,
    record: String,
    job_id: String,
    request: JobRequest,
    #[serde(default)]
    operation_id: Option<String>,
    #[serde(default)]
    operation_kind: Option<String>,
    #[serde(default)]
    operation_sha256: Option<String>,
    #[serde(default)]
    event_seq: Option<u64>,
    #[serde(rename = "payload")]
    _payload: serde::de::IgnoredAny,
}

impl JobJournal {
    fn from_state(mut state: State) -> Self {
        let fixed_lease = JobMemoryLease::acquire(64 * 1024);
        if let Err(error) = &fixed_lease {
            state.store = None;
            state.configured = true;
            state.error = Some(error.to_string());
            state.operations.clear();
            state.jobs.clear();
            state.charges.clear();
        }
        Self {
            state: Mutex::new(state),
            key_shards: (0..JOURNAL_SHARD_COUNT).map(|_| Mutex::new(())).collect(),
            _fixed_lease: fixed_lease.ok(),
        }
    }

    #[must_use]
    pub fn memory_only() -> Self {
        Self::from_state(State {
            store: None,
            configured: false,
            error: None,
            operations: HashMap::new(),
            jobs: HashMap::new(),
            charges: Vec::new(),
            #[cfg(test)]
            fail_next_accept: false,
            #[cfg(test)]
            fail_next_observation: false,
        })
    }

    #[must_use]
    pub fn open_best_effort(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self::memory_only();
        };
        Self::from_backend_result(
            DurableEventStore::open(path, EventStoreLimits::default(), SyncPolicy::Full)
                .map(|store| Arc::new(EventStoreBackend::Legacy(Box::new(store)))),
        )
    }

    /// Open a segmented v2 job journal.  `legacy_path` is optional; when it
    /// points at an existing v1 file, the event-store layer performs an
    /// idempotent migration before the journal is exposed as durable.
    ///
    /// The long-standing [`Self::open_best_effort`] API remains v1-compatible
    /// for rolling upgrades and callers that still provide a JSONL file path.
    #[must_use]
    pub fn open_best_effort_segmented(root: Option<&Path>, legacy_path: Option<&Path>) -> Self {
        let Some(root) = root else {
            return Self::memory_only();
        };
        let result = open_segmented_job_store(root, legacy_path);
        Self::from_backend_result(
            result.map(|store| Arc::new(EventStoreBackend::Segmented(Box::new(store)))),
        )
    }

    fn from_backend_result(
        result: std::result::Result<
            Arc<EventStoreBackend>,
            trillionnium_owner_open_event_store::EventStoreError,
        >,
    ) -> Self {
        match result {
            Ok(store) => match recover(&store) {
                Ok((operations, jobs, charges)) => Self::from_state(State {
                    store: Some(store),
                    configured: true,
                    error: None,
                    operations,
                    jobs,
                    charges,
                    #[cfg(test)]
                    fail_next_accept: false,
                    #[cfg(test)]
                    fail_next_observation: false,
                }),
                Err(error) => Self::from_state(State {
                    store: None,
                    configured: true,
                    error: Some(error),
                    operations: HashMap::new(),
                    jobs: HashMap::new(),
                    charges: Vec::new(),
                    #[cfg(test)]
                    fail_next_accept: false,
                    #[cfg(test)]
                    fail_next_observation: false,
                }),
            },
            Err(error) => Self::from_state(State {
                store: None,
                configured: true,
                error: Some(error.to_string()),
                operations: HashMap::new(),
                jobs: HashMap::new(),
                charges: Vec::new(),
                #[cfg(test)]
                fail_next_accept: false,
                #[cfg(test)]
                fail_next_observation: false,
            }),
        }
    }

    pub fn status(&self) -> Result<JournalStatus> {
        let state = self.lock()?;
        Ok(
            match (&state.store, state.configured, state.error.as_deref()) {
                (Some(_), _, _) => JournalStatus::Durable,
                (None, false, _) => JournalStatus::BestEffortMemoryOnly,
                (None, true, Some(error)) => JournalStatus::Unavailable {
                    error: error.to_string(),
                },
                (None, true, None) => JournalStatus::Unavailable {
                    error: "job journal is unavailable".to_string(),
                },
            },
        )
    }

    pub fn is_durable(&self) -> Result<bool> {
        Ok(self.lock()?.store.is_some())
    }

    pub fn error(&self) -> Result<Option<String>> {
        Ok(self.lock()?.error.clone())
    }

    /// Force the selected backend's pending bytes and derived index to disk.
    ///
    /// The backend handle is cloned while the journal state lock is held and
    /// the potentially slow filesystem operation runs after that lock is
    /// released. This keeps an explicit durability boundary from becoming a
    /// global journal contention point.
    pub fn flush(&self) -> Result<()> {
        let backend = self.lock()?.store.clone();
        let Some(backend) = backend else {
            return Ok(());
        };
        backend
            .flush()
            .map_err(|error| JobRuntimeError::Journal(error.to_string()))
    }

    /// Inject one durable acceptance append failure for the runtime's
    /// fail-closed rollback tests.  This is compiled only for the crate's
    /// unit-test configuration and cannot affect production builds.
    #[cfg(test)]
    pub(crate) fn fail_next_accept_for_test(&self) -> Result<()> {
        self.lock()?.fail_next_accept = true;
        Ok(())
    }

    /// Inject one observation append failure for post-spawn convergence tests.
    /// This hook is test-only and cannot alter production behavior.
    #[cfg(test)]
    pub(crate) fn fail_next_observation_for_test(&self) -> Result<()> {
        self.lock()?.fail_next_observation = true;
        Ok(())
    }

    pub fn recovered_job(&self, key: &JobKey) -> Result<Option<RecoveredJob>> {
        let _key_guard = self.key_guard(key)?;
        let (store, job) = {
            let state = self.lock()?;
            (state.store.clone(), state.jobs.get(key).cloned())
        };
        let Some(job) = job else {
            return Ok(None);
        };
        Ok(Some(RecoveredJob {
            key: key.clone(),
            start_result: job
                .start_result
                .as_ref()
                .map(|cached| self.resolve_payload(store.as_ref(), key, &job.request, cached))
                .transpose()?,
            terminal: job
                .terminal
                .as_ref()
                .map(|cached| self.resolve_payload(store.as_ref(), key, &job.request, cached))
                .transpose()?,
            request: job.request,
        }))
    }

    /// Retained authoritative high-water for a resident window that was
    /// archived. This is derived from existing v1 envelope event_seq fields;
    /// no journal or wire schema change is required.
    pub fn runtime_next_cursor(&self, key: &JobKey) -> Result<u64> {
        let _key_guard = self.key_guard(key)?;
        Ok(self
            .lock()?
            .jobs
            .get(key)
            .map_or(0, |job| job.next_runtime_cursor))
    }

    /// Inspection needs presence, not a retained copy of every terminal DOM.
    /// A degraded backend does not erase already observed registry/runtime
    /// truth; full payload retrieval still fails explicitly when unavailable.
    pub(crate) fn recovered_nonterminal(&self, key: &JobKey) -> Result<bool> {
        let _key_guard = self.key_guard(key)?;
        Ok(self
            .lock()?
            .jobs
            .get(key)
            .is_some_and(|job| job.terminal.is_none()))
    }

    pub fn begin_operation(
        &self,
        key: &JobKey,
        request: &JobRequest,
        operation_id: &str,
        operation_kind: &str,
        operation_sha256: &str,
        details: Value,
    ) -> Result<OperationBegin> {
        let (_working_lane, _working_lease, details) = journal_input_lane(key, request, details)?;
        validate_operation(operation_id, operation_kind, operation_sha256)?;
        // A key shard preserves the linearizable begin/append transition for
        // this job while allowing unrelated jobs to release the global state
        // mutex during filesystem I/O.
        let _key_guard = self.key_guard(key)?;
        let operation_key = OperationKey {
            job: key.clone(),
            operation_id: operation_id.to_string(),
        };
        let (store, envelope, charge) = {
            let mut state = self.lock()?;
            ensure_request_for_key(&state, key, request)?;
            if let Some(existing) = state.operations.get(&operation_key) {
                if existing.request != *request
                    || existing.operation_kind != operation_kind
                    || existing.operation_sha256 != operation_sha256
                {
                    return Err(JobRuntimeError::JobConflict);
                }
                if let Some(terminal) = &existing.terminal {
                    let terminal = terminal.clone();
                    let store = state.store.clone();
                    drop(state);
                    return self
                        .resolve_payload(store.as_ref(), key, request, &terminal)
                        .map(OperationBegin::ExistingTerminal);
                }
                return Ok(OperationBegin::ExistingAccepted {
                    restart_uncertain: existing.preexisting,
                });
            }

            if operation_kind == "start"
                && let Some(existing) = state.jobs.get(key)
            {
                if existing.request != *request {
                    return Err(JobRuntimeError::JobConflict);
                }
                return Ok(OperationBegin::ExistingAccepted {
                    restart_uncertain: existing.start_result.is_some(),
                });
            }

            let charge = journal_metadata_charge(
                key,
                request,
                operation_id,
                operation_kind,
                !state.jobs.contains_key(key) && operation_kind == "start",
                state.store.is_none(),
            )?;
            if state.store.is_none() {
                if state.configured {
                    return Err(JobRuntimeError::Journal(
                        state.error.clone().unwrap_or_else(|| {
                            "configured job journal is unavailable before acceptance".to_string()
                        }),
                    ));
                }
                state.charges.push(charge);
                state.operations.insert(
                    operation_key,
                    OperationState {
                        request: request.clone(),
                        operation_kind: operation_kind.to_string(),
                        operation_sha256: operation_sha256.to_string(),
                        terminal: None,
                        preexisting: false,
                        durable_accept: false,
                    },
                );
                if operation_kind == "start" {
                    state.jobs.insert(
                        key.clone(),
                        JobState {
                            request: request.clone(),
                            start_result: None,
                            terminal: None,
                            next_runtime_cursor: 0,
                        },
                    );
                }
                return Ok(OperationBegin::Unjournaled);
            }

            #[cfg(test)]
            if state.fail_next_accept {
                state.fail_next_accept = false;
                return Err(disable(
                    &mut state,
                    "injected durable acceptance append failure".to_string(),
                ));
            }
            let envelope = JournalEnvelope {
                schema: JOURNAL_SCHEMA.to_string(),
                record: "operation.accepted".to_string(),
                job_id: key.job_id.clone(),
                request: request.clone(),
                operation_id: Some(operation_id.to_string()),
                operation_kind: Some(operation_kind.to_string()),
                operation_sha256: Some(operation_sha256.to_string()),
                event_seq: None,
                payload: details,
            };
            let store = Arc::clone(state.store.as_ref().expect("store presence checked"));
            (store, envelope, charge)
        };

        // Do not hold the global journal-state mutex while serializing and
        // syncing the event-store record.  The per-job shard above still
        // excludes a same-key transition from overtaking this append.
        let append_result = append_envelope(
            store.as_ref(),
            key,
            &format!("job.operation.accepted.{operation_kind}"),
            event_id("accepted", key, operation_id),
            &envelope,
            AppendMode::Durable,
        );
        let mut state = self.lock()?;
        if let Err(error) = append_result {
            return Err(disable(&mut state, error));
        }

        // Another key may have observed a store fault while this append was
        // in flight.  Keep the accepted record in memory for exact recovery,
        // but report it as restart-uncertain so the caller cannot dispatch an
        // effect while the journal is globally degraded.
        let degraded = state.store.is_none();
        state.charges.push(charge);
        state.operations.insert(
            operation_key,
            OperationState {
                request: request.clone(),
                operation_kind: operation_kind.to_string(),
                operation_sha256: operation_sha256.to_string(),
                terminal: None,
                preexisting: degraded,
                durable_accept: true,
            },
        );
        if operation_kind == "start" {
            state.jobs.insert(
                key.clone(),
                JobState {
                    request: request.clone(),
                    start_result: None,
                    terminal: None,
                    next_runtime_cursor: 0,
                },
            );
        }
        if degraded {
            return Ok(OperationBegin::ExistingAccepted {
                restart_uncertain: true,
            });
        }
        Ok(OperationBegin::New)
    }

    pub fn complete_operation(
        &self,
        key: &JobKey,
        request: &JobRequest,
        operation_id: &str,
        operation_kind: &str,
        operation_sha256: &str,
        result: Value,
    ) -> Result<()> {
        let (_working_lane, _working_lease, result) = journal_input_lane(key, request, result)?;
        validate_operation(operation_id, operation_kind, operation_sha256)?;
        let _key_guard = self.key_guard(key)?;
        let operation_key = OperationKey {
            job: key.clone(),
            operation_id: operation_id.to_string(),
        };
        let previous = {
            let state = self.lock()?;
            if let Some(existing) = state.operations.get(&operation_key) {
                if existing.request != *request
                    || existing.operation_kind != operation_kind
                    || existing.operation_sha256 != operation_sha256
                {
                    return Err(JobRuntimeError::JobConflict);
                }
                existing
                    .terminal
                    .clone()
                    .map(|terminal| (state.store.clone(), terminal))
            } else {
                None
            }
        };
        if let Some((store, previous)) = previous {
            return if self.resolve_payload(store.as_ref(), key, request, &previous)? == result {
                Ok(())
            } else {
                Err(JobRuntimeError::JobConflict)
            };
        }
        let (store, envelope) = {
            let mut state = self.lock()?;
            ensure_request_for_key(&state, key, request)?;
            let durable_accept = if let Some(existing) = state.operations.get(&operation_key) {
                if existing.request != *request
                    || existing.operation_kind != operation_kind
                    || existing.operation_sha256 != operation_sha256
                {
                    return Err(JobRuntimeError::JobConflict);
                }
                existing.durable_accept
            } else {
                return Err(JobRuntimeError::Journal(
                    "operation terminal has no accepted record".to_string(),
                ));
            };
            if durable_accept && state.store.is_none() {
                mark_operation_uncertain(&mut state, &operation_key);
                return Err(JobRuntimeError::Journal(
                    state.error.clone().unwrap_or_else(|| {
                        "job journal became unavailable before operation terminal".to_string()
                    }),
                ));
            }
            let Some(store) = state.store.as_ref() else {
                if state.configured {
                    mark_operation_uncertain(&mut state, &operation_key);
                    return Err(JobRuntimeError::Journal(
                        state.error.clone().unwrap_or_else(|| {
                            "job journal is unavailable before terminal append".to_string()
                        }),
                    ));
                }
                // Deliberate memory-only mode has no filesystem operation.  A
                // terminal transition is still idempotent and request-bound.
                let result = memory_payload(result)?;
                commit_operation_terminal(&mut state, &operation_key, key, operation_kind, result)?;
                return Ok(());
            };
            let envelope = JournalEnvelope {
                schema: JOURNAL_SCHEMA.to_string(),
                record: "operation.terminal".to_string(),
                job_id: key.job_id.clone(),
                request: request.clone(),
                operation_id: Some(operation_id.to_string()),
                operation_kind: Some(operation_kind.to_string()),
                operation_sha256: Some(operation_sha256.to_string()),
                event_seq: None,
                payload: result,
            };
            (Arc::clone(store), envelope)
        };

        let append_result = append_envelope(
            store.as_ref(),
            key,
            &format!("job.operation.terminal.{operation_kind}"),
            event_id("terminal", key, operation_id),
            &envelope,
            AppendMode::Durable,
        );
        let mut state = self.lock()?;
        let record_sha256 = match append_result {
            Ok(hash) => hash,
            Err(error) => {
                mark_operation_uncertain(&mut state, &operation_key);
                return Err(disable(&mut state, error));
            }
        };
        if state.store.is_none() {
            mark_operation_uncertain(&mut state, &operation_key);
            return Err(JobRuntimeError::Journal(
                state.error.clone().unwrap_or_else(|| {
                    "job journal became unavailable after operation terminal append".to_string()
                }),
            ));
        }
        commit_operation_terminal(
            &mut state,
            &operation_key,
            key,
            operation_kind,
            CachedPayload::Durable {
                event_id: event_id("terminal", key, operation_id),
                record_sha256,
            },
        )
    }

    pub fn append_observation(
        &self,
        key: &JobKey,
        request: &JobRequest,
        event_seq: u64,
        kind: &str,
        payload: Value,
    ) -> Result<()> {
        let (_working_lane, _working_lease, payload) = journal_input_lane(key, request, payload)?;
        self.append_observation_reserved(key, request, event_seq, kind, payload)
    }

    /// Manager already holds the matching shared working lane/reservation.
    pub(crate) fn append_observation_reserved(
        &self,
        key: &JobKey,
        request: &JobRequest,
        event_seq: u64,
        kind: &str,
        payload: Value,
    ) -> Result<()> {
        let _terminal_trace = (kind == "job.terminal.observation").then(|| {
            trillionnium_owner_open_trace::span(
                trillionnium_owner_open_trace::Stage::TerminalPersistence,
                &key.job_id,
            )
        });
        let next_cursor = event_seq.checked_add(1).ok_or_else(|| {
            JobRuntimeError::Journal("runtime observation sequence exhausted".to_string())
        })?;
        require_text(kind, "observation kind", 256, false)
            .map_err(|error| JobRuntimeError::InvalidRequest(error.to_string()))?;
        let terminal_payload = if kind == "job.terminal.observation" {
            let event = payload.get("event").ok_or_else(|| {
                JobRuntimeError::Journal(
                    "terminal observation is missing its event payload".to_string(),
                )
            })?;
            if event.get("kind").and_then(Value::as_str) != Some("terminal") {
                return Err(JobRuntimeError::Journal(
                    "terminal observation payload is not terminal".to_string(),
                ));
            }
            Some(event.clone())
        } else {
            None
        };

        let _key_guard = self.key_guard(key)?;
        if let Some(payload) = terminal_payload.as_ref() {
            let previous = {
                let state = self.lock()?;
                state
                    .jobs
                    .get(key)
                    .and_then(|job| job.terminal.clone())
                    .map(|cached| (state.store.clone(), cached))
            };
            if let Some((store, previous)) = previous
                && self.resolve_payload(store.as_ref(), key, request, &previous)? != *payload
            {
                return Err(JobRuntimeError::JobConflict);
            }
        }
        let (store, envelope, charge) = {
            let mut state = self.lock()?;
            ensure_request_for_key(&state, key, request)?;
            let charge = if !state.jobs.contains_key(key) {
                Some(journal_metadata_charge(
                    key,
                    request,
                    "",
                    "",
                    true,
                    state.store.is_none(),
                )?)
            } else {
                None
            };
            let Some(store) = state.store.as_ref() else {
                if state.configured {
                    return Err(JobRuntimeError::Journal(
                        state.error.clone().unwrap_or_else(|| {
                            "job journal is unavailable before observation append".to_string()
                        }),
                    ));
                }
                // Memory-only mode is intentionally unreplayable, but retain
                // the request binding in the in-process state so a later call
                // cannot append an observation for different request bytes
                // under the same job key.
                if let Some(charge) = charge {
                    state.charges.push(charge);
                }
                let job = state.jobs.entry(key.clone()).or_insert(JobState {
                    request: request.clone(),
                    start_result: None,
                    terminal: None,
                    next_runtime_cursor: 0,
                });
                job.next_runtime_cursor = job.next_runtime_cursor.max(next_cursor);
                if let Some(terminal_payload) = terminal_payload
                    && job.terminal.is_none()
                {
                    job.terminal = Some(memory_payload(terminal_payload)?);
                }
                return Ok(());
            };
            #[cfg(test)]
            if state.fail_next_observation {
                state.fail_next_observation = false;
                return Err(disable(
                    &mut state,
                    "injected durable observation append failure".to_string(),
                ));
            }
            let envelope = JournalEnvelope {
                schema: JOURNAL_SCHEMA.to_string(),
                record: "observation".to_string(),
                job_id: key.job_id.clone(),
                request: request.clone(),
                operation_id: None,
                operation_kind: None,
                operation_sha256: None,
                event_seq: Some(event_seq),
                payload,
            };
            (Arc::clone(store), envelope, charge)
        };

        // The key shard keeps this append ordered for the job, while the
        // global journal-state mutex is free for unrelated jobs.
        let append_result = append_envelope(
            store.as_ref(),
            key,
            kind,
            event_id("observation", key, &event_seq.to_string()),
            &envelope,
            AppendMode::Grouped,
        );
        let mut state = self.lock()?;
        if let Err(error) = append_result {
            return Err(disable(&mut state, error));
        }
        if let Some(charge) = charge {
            state.charges.push(charge);
        }

        // Bind the request as soon as the observation append succeeds.  If a
        // subsequent terminal append fails, the request identity still
        // remains recorded in memory and future calls fail closed instead of
        // mixing another request into this job's journal lineage.
        let job = state.jobs.entry(key.clone()).or_insert(JobState {
            request: request.clone(),
            start_result: None,
            terminal: None,
            next_runtime_cursor: 0,
        });
        job.next_runtime_cursor = job.next_runtime_cursor.max(next_cursor);
        if state.store.is_none() {
            return Err(JobRuntimeError::Journal(
                state.error.clone().unwrap_or_else(|| {
                    "job journal became unavailable after observation append".to_string()
                }),
            ));
        }

        let Some(terminal_payload) = terminal_payload else {
            return Ok(());
        };
        if state
            .jobs
            .get(key)
            .and_then(|job| job.terminal.as_ref())
            .is_some()
        {
            return Ok(());
        }
        let terminal_envelope = JournalEnvelope {
            schema: JOURNAL_SCHEMA.to_string(),
            record: "job.terminal".to_string(),
            job_id: key.job_id.clone(),
            request: request.clone(),
            operation_id: None,
            operation_kind: None,
            operation_sha256: None,
            event_seq: Some(event_seq),
            payload: terminal_payload.clone(),
        };
        let terminal_store = Arc::clone(state.store.as_ref().expect("store presence checked"));
        drop(state);

        let terminal_append_result = append_envelope(
            terminal_store.as_ref(),
            key,
            "job.terminal",
            event_id("job-terminal", key, "terminal"),
            &terminal_envelope,
            AppendMode::Durable,
        );
        let mut state = self.lock()?;
        let record_sha256 = match terminal_append_result {
            Ok(hash) => hash,
            Err(error) => return Err(disable(&mut state, error)),
        };
        if state.store.is_none() {
            return Err(JobRuntimeError::Journal(
                state.error.clone().unwrap_or_else(|| {
                    "job journal became unavailable after terminal append".to_string()
                }),
            ));
        }
        let cached = CachedPayload::Durable {
            event_id: event_id("job-terminal", key, "terminal"),
            record_sha256,
        };
        state
            .jobs
            .entry(key.clone())
            .and_modify(|job| job.terminal = Some(cached.clone()))
            .or_insert(JobState {
                request: request.clone(),
                start_result: None,
                terminal: Some(cached),
                next_runtime_cursor: 0,
            });
        Ok(())
    }

    pub fn record_job_terminal(
        &self,
        key: &JobKey,
        request: &JobRequest,
        event_seq: u64,
        payload: Value,
    ) -> Result<()> {
        let (_working_lane, _working_lease, payload) = journal_input_lane(key, request, payload)?;
        let next_cursor = event_seq.checked_add(1).ok_or_else(|| {
            JobRuntimeError::InvalidRequest("runtime observation sequence exhausted".to_string())
        })?;
        let _key_guard = self.key_guard(key)?;
        let previous = {
            let state = self.lock()?;
            state
                .jobs
                .get(key)
                .and_then(|job| job.terminal.clone())
                .map(|cached| (state.store.clone(), cached))
        };
        if let Some((store, previous)) = previous {
            return if self.resolve_payload(store.as_ref(), key, request, &previous)? == payload {
                Ok(())
            } else {
                Err(JobRuntimeError::JobConflict)
            };
        }
        let (store, envelope, charge) = {
            let mut state = self.lock()?;
            ensure_request_for_key(&state, key, request)?;
            let charge = if !state.jobs.contains_key(key) {
                Some(journal_metadata_charge(
                    key,
                    request,
                    "",
                    "",
                    true,
                    state.store.is_none(),
                )?)
            } else {
                None
            };

            let Some(store) = state.store.as_ref() else {
                if state.configured {
                    return Err(JobRuntimeError::Journal(
                        state.error.clone().unwrap_or_else(|| {
                            "job journal is unavailable before terminal append".to_string()
                        }),
                    ));
                }
                let payload = memory_payload(payload)?;
                if let Some(charge) = charge {
                    state.charges.push(charge);
                }
                state
                    .jobs
                    .entry(key.clone())
                    .and_modify(|job| {
                        job.terminal = Some(payload.clone());
                        job.next_runtime_cursor = job.next_runtime_cursor.max(next_cursor);
                    })
                    .or_insert(JobState {
                        request: request.clone(),
                        start_result: None,
                        terminal: Some(payload),
                        next_runtime_cursor: next_cursor,
                    });
                return Ok(());
            };
            let envelope = JournalEnvelope {
                schema: JOURNAL_SCHEMA.to_string(),
                record: "job.terminal".to_string(),
                job_id: key.job_id.clone(),
                request: request.clone(),
                operation_id: None,
                operation_kind: None,
                operation_sha256: None,
                event_seq: Some(event_seq),
                payload,
            };
            (Arc::clone(store), envelope, charge)
        };

        let append_result = append_envelope(
            store.as_ref(),
            key,
            "job.terminal",
            event_id("job-terminal", key, "terminal"),
            &envelope,
            AppendMode::Durable,
        );
        let mut state = self.lock()?;
        let record_sha256 = match append_result {
            Ok(hash) => hash,
            Err(error) => return Err(disable(&mut state, error)),
        };
        if state.store.is_none() {
            return Err(JobRuntimeError::Journal(
                state.error.clone().unwrap_or_else(|| {
                    "job journal became unavailable after terminal append".to_string()
                }),
            ));
        }
        if let Some(charge) = charge {
            state.charges.push(charge);
        }
        let cached = CachedPayload::Durable {
            event_id: event_id("job-terminal", key, "terminal"),
            record_sha256,
        };
        state
            .jobs
            .entry(key.clone())
            .and_modify(|job| {
                job.terminal = Some(cached.clone());
                job.next_runtime_cursor = job.next_runtime_cursor.max(next_cursor);
            })
            .or_insert(JobState {
                request: request.clone(),
                start_result: None,
                terminal: Some(cached),
                next_runtime_cursor: next_cursor,
            });
        Ok(())
    }

    /// Return the legacy payload-only view of the records belonging to `key`.
    ///
    /// The event store is scoped by turn, rather than by job.  Keep the
    /// filtering here (at the journal boundary) so callers that use this
    /// compatibility API can never accidentally receive a sibling job's
    /// records from the same turn.
    pub fn inspect_records(&self, key: &JobKey) -> Result<Vec<Value>> {
        let _staging_lane = crate::resources::working_lane()?;
        let _staging_lease = JobMemoryLease::acquire_working(crate::MAX_OBSERVATION_STAGING_BYTES)
            .map_err(|error| JobRuntimeError::Registry(error.to_string()))?;
        self.replay_job_records(key)
            .map(|records| records.into_iter().map(|record| record.payload).collect())
    }

    /// Return the durable records for `key`, including event-store metadata.
    ///
    /// Each item is the canonical [`EventRecord`] JSON object with one
    /// additive `job_record_seq` field.  `job_record_seq` is a zero-based,
    /// contiguous cursor in this job's filtered sequence; it is deliberately
    /// distinct from the event store's global `store_seq` and per-turn
    /// `turn_seq` values.  Keeping the metadata makes replay/audit consumers
    /// able to verify scope, event identity and hash-chain position without
    /// changing the long-standing payload-only API above.
    pub fn inspect_records_with_metadata(&self, key: &JobKey) -> Result<Vec<Value>> {
        let _staging_lane = crate::resources::working_lane()?;
        let _staging_lease = JobMemoryLease::acquire_working(crate::MAX_OBSERVATION_STAGING_BYTES)
            .map_err(|error| JobRuntimeError::Registry(error.to_string()))?;
        self.replay_job_records(key)?
            .into_iter()
            .enumerate()
            .map(|(job_record_seq, record)| {
                let mut value = serde_json::to_value(record).map_err(|error| {
                    JobRuntimeError::Journal(format!(
                        "failed to encode durable job journal metadata: {error}"
                    ))
                })?;
                let sequence = u64::try_from(job_record_seq).map_err(|_| {
                    JobRuntimeError::Journal(
                        "durable job journal record sequence exceeds u64".to_string(),
                    )
                })?;
                value
                    .as_object_mut()
                    .ok_or_else(|| {
                        JobRuntimeError::Journal(
                            "durable event-store record did not encode as an object".to_string(),
                        )
                    })?
                    .insert("job_record_seq".to_string(), json!(sequence));
                Ok(value)
            })
            .collect()
    }

    /// Replay the turn scope and retain only valid journal envelopes for the
    /// requested job.  A malformed payload is an integrity failure, not a
    /// reason to silently drop one record; returning an error preserves the
    /// fail-closed inspection contract.
    fn replay_job_records(&self, key: &JobKey) -> Result<Vec<EventRecord>> {
        let _key_guard = self.key_guard(key)?;
        let (store, mut expected_request) = {
            let state = self.lock()?;
            let Some(store) = state.store.as_ref() else {
                return Ok(Vec::new());
            };
            let expected_request =
                state
                    .jobs
                    .get(key)
                    .map(|job| job.request.clone())
                    .or_else(|| {
                        state
                            .operations
                            .iter()
                            .find(|(operation_key, _)| operation_key.job == *key)
                            .map(|(_, operation)| operation.request.clone())
                    });
            (Arc::clone(store), expected_request)
        };
        let scope = turn_scope(key);
        // Startup authenticates the complete history. Inspection uses the
        // existing turn-scope index and reads only that scope's payloads; jobs
        // sharing one turn scope still need the job_id filter below. Keep I/O
        // outside the journal-state mutex while the key shard fences same-key
        // mutations. This does not reauthenticate unrelated live payloads.
        let mut matching = Vec::new();
        let mut working: usize = 64 * 1024;
        store
            .visit_scope_records(&scope, |record| {
                if record.scope != scope {
                    return Err(JobRuntimeError::Journal(
                        "durable scoped journal reader returned another scope".to_string(),
                    ));
                }
                let envelope = journal_header(&record.payload)?;
                if envelope.schema != JOURNAL_SCHEMA {
                    return Err(JobRuntimeError::Journal(
                        "durable job journal record schema does not match".to_string(),
                    ));
                }
                if envelope.job_id.is_empty() {
                    return Err(JobRuntimeError::Journal(
                        "durable job journal record has an empty job_id".to_string(),
                    ));
                }
                if envelope.job_id == key.job_id {
                    if let Some(expected) = expected_request.as_ref() {
                        if expected != &envelope.request {
                            return Err(JobRuntimeError::JobConflict);
                        }
                    } else {
                        expected_request = Some(envelope.request.clone());
                    }
                    let reservation = value_owned_bytes(&record.payload, 0)?
                        .checked_mul(4)
                        .and_then(|bytes| bytes.checked_add(16 * 1024))
                        .ok_or_else(journal_capacity)?;
                    working = working
                        .checked_add(reservation)
                        .ok_or_else(journal_capacity)?;
                    if working > crate::MAX_OBSERVATION_STAGING_BYTES {
                        return Err(journal_capacity());
                    }
                    matching.push(record.clone());
                }
                Ok::<(), JobRuntimeError>(())
            })
            .map_err(|error| JobRuntimeError::Journal(error.to_string()))??;
        Ok(matching)
    }

    fn resolve_payload(
        &self,
        store: Option<&Arc<EventStoreBackend>>,
        key: &JobKey,
        request: &JobRequest,
        cached: &CachedPayload,
    ) -> Result<Value> {
        let result = match cached {
            CachedPayload::Memory(value) => Ok(value.as_ref().clone()),
            CachedPayload::Durable {
                event_id,
                record_sha256,
            } => (|| {
                let store = store.ok_or_else(|| {
                    JobRuntimeError::Journal(
                        "referenced terminal backend is unavailable".to_string(),
                    )
                })?;
                let record = store
                    .get(&turn_scope(key), event_id)
                    .map_err(|error| JobRuntimeError::Journal(error.to_string()))?
                    .ok_or_else(|| {
                        JobRuntimeError::Journal("referenced terminal is missing".to_string())
                    })?;
                if record.scope != turn_scope(key)
                    || record.event_id != *event_id
                    || record.record_sha256 != *record_sha256
                {
                    return Err(JobRuntimeError::Journal(
                        "referenced terminal identity/hash conflicts".to_string(),
                    ));
                }
                let envelope: JournalEnvelope = serde_json::from_value(record.payload)
                    .map_err(|error| JobRuntimeError::Journal(error.to_string()))?;
                if envelope.schema != JOURNAL_SCHEMA
                    || envelope.job_id != key.job_id
                    || envelope.request != *request
                    || !matches!(
                        envelope.record.as_str(),
                        "operation.terminal" | "job.terminal"
                    )
                {
                    return Err(JobRuntimeError::Journal(
                        "referenced terminal envelope conflicts".to_string(),
                    ));
                }
                Ok(envelope.payload)
            })(),
        };
        if let Err(error) = &result {
            let mut state = self.lock()?;
            return Err(disable(&mut state, error.to_string()));
        }
        result
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)
    }

    /// Acquire the deterministic per-job serialization lane.  Callers must
    /// take this guard before the journal state mutex; all journal mutation
    /// paths follow that order so a slow append cannot block unrelated keys
    /// and no lock-order inversion can deadlock a transition.
    fn key_guard(&self, key: &JobKey) -> Result<MutexGuard<'_, ()>> {
        self.key_shards[stable_journal_shard_index(key)]
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)
    }
}

/// Open the v2 job journal while treating a retained v1 file as a migration
/// source rather than a live mirror. The event-store helper fences the source
/// writer across snapshot/copy, and allows a destination that is already
/// ahead only when the legacy file is an exact prefix. Routing every restart
/// through the strict `open_or_migrate` API would incorrectly classify that
/// healthy post-upgrade state as an extra-destination conflict.
fn open_segmented_job_store(
    root: &Path,
    legacy_path: Option<&Path>,
) -> trillionnium_owner_open_event_store::Result<SegmentedEventStore> {
    let config = SegmentedEventStoreConfig::default();
    // Pass an explicitly supplied source through to the event-store layer
    // even when its pathname is concurrently removed.  That layer performs
    // the lstat/open identity check and fails closed; filtering with
    // `Path::exists()` here could silently downgrade a migration race into a
    // fresh empty journal.
    let Some(legacy_path) = legacy_path else {
        return SegmentedEventStore::open(root, config);
    };

    // The event-store helper keeps the source writer lease until the v2
    // destination has been opened and reconciled.  This prevents a legacy
    // writer from appending an unobserved tail between the source snapshot
    // and migration copy while still accepting an exact stale prefix after
    // v2 takes authority.
    SegmentedEventStore::open_or_migrate_with_legacy_prefix(root, legacy_path, config)
}

fn recover(store: &EventStoreBackend) -> std::result::Result<RecoveredState, String> {
    let mut operations = HashMap::new();
    let mut jobs = HashMap::<JobKey, JobState>::new();
    let mut requests = HashMap::<JobKey, JobRequest>::new();
    let mut charges = Vec::new();
    let mut request_charges = Vec::new();
    store
        .visit_records(|record| {
            let envelope = journal_header(&record.payload).map_err(|error| error.to_string())?;
            if envelope.schema != JOURNAL_SCHEMA {
                return Err("job journal schema does not match".to_string());
            }
            let key = JobKey::new(
                trillionnium_owner_open_job_registry::JobScope::new(
                    record.scope.session_id.clone(),
                    record.scope.profile_id.clone(),
                    record.scope.task_id.clone(),
                    record.scope.turn_id.clone(),
                    record.scope.turn_stream_id.clone(),
                ),
                envelope.job_id.clone(),
            );
            if record.scope != turn_scope(&key) {
                return Err("job journal record scope does not match payload".to_string());
            }
            if let Some(existing) = requests.get(&key) {
                if existing != &envelope.request {
                    return Err("job journal request binding conflicts for job".to_string());
                }
            } else {
                request_charges.push(
                    journal_metadata_charge(&key, &envelope.request, "", "", true, false)
                        .map_err(|error| error.to_string())?,
                );
                requests.insert(key.clone(), envelope.request.clone());
            }
            let cursor_key = key.clone();
            let next_cursor = if matches!(envelope.record.as_str(), "observation" | "job.terminal")
            {
                Some(
                    envelope
                        .event_seq
                        .ok_or_else(|| "job observation has no event_seq".to_string())?
                        .checked_add(1)
                        .ok_or_else(|| "runtime observation sequence exhausted".to_string())?,
                )
            } else {
                None
            };
            match envelope.record.as_str() {
                "operation.accepted" => {
                    let operation_id = envelope
                        .operation_id
                        .ok_or_else(|| "accepted operation has no operation_id".to_string())?;
                    let operation_kind = envelope
                        .operation_kind
                        .ok_or_else(|| "accepted operation has no kind".to_string())?;
                    let operation_sha256 = envelope
                        .operation_sha256
                        .ok_or_else(|| "accepted operation has no digest".to_string())?;
                    let operation_key = OperationKey {
                        job: key.clone(),
                        operation_id,
                    };
                    if operations.contains_key(&operation_key) {
                        return Err("job operation accepted record is duplicated".to_string());
                    }
                    charges.push(
                        journal_metadata_charge(
                            &key,
                            &envelope.request,
                            &operation_key.operation_id,
                            &operation_kind,
                            false,
                            false,
                        )
                        .map_err(|error| error.to_string())?,
                    );
                    operations.insert(
                        operation_key,
                        OperationState {
                            request: envelope.request.clone(),
                            operation_kind: operation_kind.clone(),
                            operation_sha256,
                            terminal: None,
                            preexisting: true,
                            durable_accept: true,
                        },
                    );
                    if operation_kind == "start" {
                        if !jobs.contains_key(&key) {
                            charges.push(
                                journal_metadata_charge(
                                    &key,
                                    &envelope.request,
                                    "",
                                    "",
                                    true,
                                    false,
                                )
                                .map_err(|error| error.to_string())?,
                            );
                        }
                        jobs.entry(key).or_insert(JobState {
                            request: envelope.request,
                            start_result: None,
                            terminal: None,
                            next_runtime_cursor: 0,
                        });
                    }
                }
                "operation.terminal" => {
                    let operation_id = envelope
                        .operation_id
                        .ok_or_else(|| "terminal operation has no operation_id".to_string())?;
                    let operation_kind = envelope
                        .operation_kind
                        .ok_or_else(|| "terminal operation has no kind".to_string())?;
                    let operation_sha256 = envelope
                        .operation_sha256
                        .ok_or_else(|| "terminal operation has no digest".to_string())?;
                    let operation_key = OperationKey {
                        job: key.clone(),
                        operation_id,
                    };
                    let operation = operations
                        .get_mut(&operation_key)
                        .ok_or_else(|| "operation terminal precedes acceptance".to_string())?;
                    if operation.request != envelope.request
                        || operation.operation_kind != operation_kind
                        || operation.operation_sha256 != operation_sha256
                        || operation
                            .terminal
                            .replace(CachedPayload::Durable {
                                event_id: record.event_id.clone(),
                                record_sha256: record.record_sha256.clone(),
                            })
                            .is_some()
                    {
                        return Err("job operation terminal conflicts".to_string());
                    }
                    if operation_kind == "start" {
                        if !jobs.contains_key(&key) {
                            charges.push(
                                journal_metadata_charge(
                                    &key,
                                    &envelope.request,
                                    "",
                                    "",
                                    true,
                                    false,
                                )
                                .map_err(|error| error.to_string())?,
                            );
                        }
                        let cached = CachedPayload::Durable {
                            event_id: record.event_id.clone(),
                            record_sha256: record.record_sha256.clone(),
                        };
                        jobs.entry(key)
                            .and_modify(|job| job.start_result = Some(cached.clone()))
                            .or_insert(JobState {
                                request: envelope.request,
                                start_result: Some(cached),
                                terminal: None,
                                next_runtime_cursor: 0,
                            });
                    }
                }
                "observation" => {
                    if !jobs.contains_key(&key) {
                        charges.push(
                            journal_metadata_charge(&key, &envelope.request, "", "", true, false)
                                .map_err(|error| error.to_string())?,
                        );
                    }
                    jobs.entry(key).or_insert(JobState {
                        request: envelope.request,
                        start_result: None,
                        terminal: None,
                        next_runtime_cursor: 0,
                    });
                }
                "job.terminal" => {
                    if !jobs.contains_key(&key) {
                        charges.push(
                            journal_metadata_charge(&key, &envelope.request, "", "", true, false)
                                .map_err(|error| error.to_string())?,
                        );
                    }
                    let job = jobs.entry(key).or_insert(JobState {
                        request: envelope.request,
                        start_result: None,
                        terminal: None,
                        next_runtime_cursor: 0,
                    });
                    if job
                        .terminal
                        .replace(CachedPayload::Durable {
                            event_id: record.event_id.clone(),
                            record_sha256: record.record_sha256.clone(),
                        })
                        .is_some()
                    {
                        return Err("job terminal record is duplicated".to_string());
                    }
                }
                other => return Err(format!("unsupported job journal record {other}")),
            }
            if let Some(next_cursor) = next_cursor {
                let job = jobs
                    .get_mut(&cursor_key)
                    .expect("observation binds its job");
                job.next_runtime_cursor = job.next_runtime_cursor.max(next_cursor);
            }
            Ok::<(), String>(())
        })
        .map_err(|error| error.to_string())??;
    Ok((operations, jobs, charges))
}

fn validate_operation(operation_id: &str, kind: &str, digest: &str) -> Result<()> {
    require_id(operation_id, "operation_id", 256)
        .map_err(|error| JobRuntimeError::InvalidRequest(error.to_string()))?;
    require_text(kind, "operation_kind", 64, false)
        .map_err(|error| JobRuntimeError::InvalidRequest(error.to_string()))?;
    require_sha256(digest, "operation_sha256")
        .map_err(|error| JobRuntimeError::InvalidRequest(error.to_string()))
}

fn journal_capacity() -> JobRuntimeError {
    JobRuntimeError::Journal("job journal owned memory capacity is exhausted".to_string())
}

fn journal_header(payload: &Value) -> Result<JournalHeader> {
    let mut bytes: usize = 1024;
    for field in [
        "schema",
        "record",
        "job_id",
        "operation_id",
        "operation_kind",
        "operation_sha256",
    ] {
        if let Some(value) = payload.get(field).and_then(Value::as_str) {
            bytes = bytes
                .checked_add(value.len())
                .ok_or_else(journal_capacity)?;
        }
    }
    if let Some(request) = payload.get("request").and_then(Value::as_object) {
        for value in request.values() {
            if let Some(value) = value.as_str() {
                bytes = bytes
                    .checked_add(value.len())
                    .ok_or_else(journal_capacity)?;
            }
        }
    }
    if bytes > crate::resources::MAX_START_SPEC_BYTES {
        return Err(journal_capacity());
    }
    JournalHeader::deserialize(payload).map_err(|error| {
        JobRuntimeError::Journal(format!("durable job journal header is invalid: {error}"))
    })
}

const MEMORY_TERMINAL_BYTES: usize = 8 * 1024;

fn journal_metadata_charge(
    key: &JobKey,
    request: &JobRequest,
    operation_id: &str,
    operation_kind: &str,
    new_job: bool,
    memory: bool,
) -> Result<JobMemoryLease> {
    let mut bytes = 2048usize;
    for value in [
        &key.scope.session_id,
        &key.scope.profile_id,
        &key.scope.task_id,
        &key.scope.turn_id,
        &key.scope.turn_stream_id,
        &key.job_id,
        &request.request_sha256,
        &request.binding_fingerprint,
        &request.tool,
        &request.mode,
    ] {
        bytes = bytes
            .checked_add(value.len())
            .ok_or_else(journal_capacity)?;
    }
    bytes = bytes
        .checked_add(request.target_id.as_ref().map_or(0, String::len))
        .ok_or_else(journal_capacity)?;
    bytes = bytes
        .checked_add(operation_id.len())
        .and_then(|bytes| bytes.checked_add(operation_kind.len()))
        .ok_or_else(journal_capacity)?;
    if bytes > crate::resources::MAX_START_SPEC_BYTES {
        return Err(journal_capacity());
    }
    // Four copies cover keys/requests in derived maps, growth buckets and
    // reference/index metadata. Future terminal references are pre-reserved.
    bytes = bytes.checked_mul(4).ok_or_else(journal_capacity)?;
    if new_job {
        bytes = bytes.checked_mul(2).ok_or_else(journal_capacity)?;
    }
    if memory {
        bytes = bytes
            .checked_add(MEMORY_TERMINAL_BYTES * if new_job { 3 } else { 1 })
            .ok_or_else(journal_capacity)?;
    }
    JobMemoryLease::acquire(bytes).map_err(|error| JobRuntimeError::Journal(error.to_string()))
}

fn journal_input_lane(
    key: &JobKey,
    request: &JobRequest,
    payload: Value,
) -> Result<(MutexGuard<'static, ()>, JobMemoryLease, Value)> {
    if let Some(lane) = crate::resources::try_working_lane()? {
        return Ok((lane, journal_working_charge(key, request, &payload)?, payload));
    }
    // The moved payload remains owned by this call while waiting. Reserve
    // its actual heap (including spare capacity) before a blocking lock.
    // A free lane uses working headroom directly so a full resident registry
    // does not make zero-heap exact-identity requests unreadable.
    let owned = value_owned_bytes(&payload, 0)?;
    if owned > crate::MAX_OBSERVATION_STAGING_BYTES / 4 {
        return Err(journal_capacity());
    }
    let pending = JobMemoryLease::acquire(owned)
        .map_err(|error| JobRuntimeError::Journal(error.to_string()))?;
    // Own the input in a later local so even a poisoned lane or working
    // admission error destroys its heap before releasing the pending lease.
    #[allow(clippy::redundant_locals)]
    let payload = payload;
    let lane = crate::resources::working_lane()?;
    let working = journal_working_charge(key, request, &payload)?;
    drop(pending);
    // Callers bind the returned input after its guards, preserving drop order.
    Ok((lane, working, payload))
}

fn journal_working_charge(
    key: &JobKey,
    request: &JobRequest,
    payload: &Value,
) -> Result<JobMemoryLease> {
    let mut metadata = 64 * 1024usize;
    for value in [
        &key.scope.session_id,
        &key.scope.profile_id,
        &key.scope.task_id,
        &key.scope.turn_id,
        &key.scope.turn_stream_id,
        &key.job_id,
        &request.request_sha256,
        &request.binding_fingerprint,
        &request.tool,
        &request.mode,
    ] {
        metadata = metadata
            .checked_add(value.len().checked_mul(12).ok_or_else(journal_capacity)?)
            .ok_or_else(journal_capacity)?;
    }
    metadata = metadata
        .checked_add(
            request
                .target_id
                .as_ref()
                .map_or(0, String::len)
                .checked_mul(12)
                .ok_or_else(journal_capacity)?,
        )
        .ok_or_else(journal_capacity)?;
    let owned = value_owned_bytes(payload, 0)?
        .checked_mul(4)
        .ok_or_else(journal_capacity)?;
    if owned > crate::MAX_OBSERVATION_STAGING_BYTES {
        return Err(journal_capacity());
    }
    // Count real JSON escaping into a bounded sink before DOM/encoder copies.
    // Encoded length can be six times a control-character string's capacity;
    // a plain heap multiplier alone would miss that legal input shape.
    let mut counter = CountingWriter {
        bytes: 0,
        maximum: crate::MAX_OBSERVATION_STAGING_BYTES / 2,
    };
    serde_json::to_writer(&mut counter, payload).map_err(|_| journal_capacity())?;
    let bytes = counter
        .bytes
        .checked_mul(2)
        .and_then(|encoded| owned.checked_add(encoded))
        .and_then(|bytes| bytes.checked_add(metadata))
        .ok_or_else(journal_capacity)?;
    JobMemoryLease::acquire_working(bytes)
        .map_err(|error| JobRuntimeError::Journal(error.to_string()))
}

struct CountingWriter {
    bytes: usize,
    maximum: usize,
}
impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| io::Error::other("job JSON staging exceeds its bound"))?;
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn value_owned_bytes(value: &Value, depth: usize) -> Result<usize> {
    if depth > 64 {
        return Err(journal_capacity());
    }
    let add = |left: usize, right: usize| left.checked_add(right).ok_or_else(journal_capacity);
    match value {
        Value::String(value) => Ok(value.capacity()),
        Value::Array(values) => {
            let mut bytes = values
                .capacity()
                .checked_mul(std::mem::size_of::<Value>())
                .ok_or_else(journal_capacity)?;
            if bytes > crate::MAX_OBSERVATION_STAGING_BYTES {
                return Err(journal_capacity());
            }
            for value in values {
                bytes = add(bytes, value_owned_bytes(value, depth + 1)?)?;
            }
            Ok(bytes)
        }
        Value::Object(values) => {
            let mut bytes = values.len().checked_mul(256).ok_or_else(journal_capacity)?;
            if bytes > crate::MAX_OBSERVATION_STAGING_BYTES {
                return Err(journal_capacity());
            }
            for (key, value) in values {
                bytes = add(
                    add(bytes, key.capacity())?,
                    value_owned_bytes(value, depth + 1)?,
                )?;
            }
            Ok(bytes)
        }
        _ => Ok(0),
    }
}

fn memory_payload(value: Value) -> Result<CachedPayload> {
    if value_owned_bytes(&value, 0)? > MEMORY_TERMINAL_BYTES {
        return Err(journal_capacity());
    }
    Ok(CachedPayload::Memory(Arc::new(value)))
}

/// Map a complete job key to one of the fixed journal serialization lanes.
/// Length-prefixing each field makes concatenation unambiguous while FNV-1a
/// keeps the implementation allocation-free and deterministic across process
/// restarts (unlike `DefaultHasher`).
fn stable_journal_shard_index(key: &JobKey) -> usize {
    let fields = [
        key.scope.session_id.as_str(),
        key.scope.profile_id.as_str(),
        key.scope.task_id.as_str(),
        key.scope.turn_id.as_str(),
        key.scope.turn_stream_id.as_str(),
        key.job_id.as_str(),
    ];
    let mut hash = FNV_OFFSET_BASIS;
    fn feed(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    feed(&mut hash, &[JOURNAL_SHARD_HASH_VERSION]);
    for field in fields {
        let length = u64::try_from(field.len()).unwrap_or(u64::MAX);
        feed(&mut hash, &length.to_le_bytes());
        feed(&mut hash, field.as_bytes());
    }
    (hash % JOURNAL_SHARD_COUNT as u64) as usize
}

/// Verify that every in-memory record already associated with `key` carries
/// the same canonical request.  A job key is only reusable for byte-identical
/// requests; allowing a later observation/terminal call to supply a different
/// request would make replay appear to belong to the wrong effect.
fn ensure_request_for_key(state: &State, key: &JobKey, request: &JobRequest) -> Result<()> {
    if state
        .jobs
        .get(key)
        .is_some_and(|job| job.request != *request)
    {
        return Err(JobRuntimeError::JobConflict);
    }
    if state
        .operations
        .iter()
        .filter(|(operation_key, _)| operation_key.job == *key)
        .any(|(_, operation)| operation.request != *request)
    {
        return Err(JobRuntimeError::JobConflict);
    }
    Ok(())
}

fn append_envelope(
    store: &EventStoreBackend,
    key: &JobKey,
    kind: &str,
    event_id: String,
    envelope: &JournalEnvelope,
    mode: AppendMode,
) -> std::result::Result<String, String> {
    let payload = serde_json::to_value(envelope).map_err(|error| error.to_string())?;
    let input = EventInput {
        scope: turn_scope(key),
        event_id,
        kind: kind.to_string(),
        payload,
    };
    let append_result = match mode {
        AppendMode::Durable => store.append_durable(input),
        AppendMode::Grouped => store.append(input),
    };
    append_result.map_err(|error| error.to_string())
}

fn turn_scope(key: &JobKey) -> TurnScope {
    TurnScope::new(
        key.scope.session_id.clone(),
        key.scope.profile_id.clone(),
        key.scope.task_id.clone(),
        key.scope.turn_id.clone(),
        key.scope.turn_stream_id.clone(),
    )
}

fn event_id(prefix: &str, key: &JobKey, discriminator: &str) -> String {
    let encoded = serde_json::to_vec(&json!({
        "schema": JOURNAL_SCHEMA,
        "prefix": prefix,
        "scope": &key.scope,
        "job_id": &key.job_id,
        "discriminator": discriminator
    }))
    .expect("job journal event identity serialization cannot fail");
    format!("job-{prefix}-{}", hex_lower(&Sha256::digest(encoded)))
}

fn hex_lower(value: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn disable(state: &mut State, error: String) -> JobRuntimeError {
    state.store = None;
    state.configured = true;
    state.error = Some(error.clone());
    JobRuntimeError::Journal(error)
}

fn mark_operation_uncertain(state: &mut State, key: &OperationKey) {
    if let Some(operation) = state.operations.get_mut(key) {
        // `preexisting` is also the compact persisted-state signal used by
        // `OperationBegin::ExistingAccepted`: once a terminal append fails,
        // a same-process retry must receive UnknownAfterRestart rather than
        // the weaker Existing disposition.
        operation.preexisting = true;
    }
}

/// Commit an operation terminal after its durable append has completed.  The
/// caller holds the journal state mutex and the job-key shard, so this helper
/// only performs the short in-memory phase.  Keeping it separate makes it
/// difficult to accidentally hold the global mutex across filesystem I/O.
fn commit_operation_terminal(
    state: &mut State,
    operation_key: &OperationKey,
    key: &JobKey,
    operation_kind: &str,
    result: CachedPayload,
) -> Result<()> {
    {
        let operation = state.operations.get_mut(operation_key).ok_or_else(|| {
            JobRuntimeError::Journal(
                "accepted operation presence changed before terminal commit".to_string(),
            )
        })?;
        if let Some(existing) = &operation.terminal {
            if existing == &result {
                return Ok(());
            }
            return Err(JobRuntimeError::JobConflict);
        }
        operation.terminal = Some(result.clone());
    }
    if operation_kind == "start"
        && let Some(job) = state.jobs.get_mut(key)
    {
        job.start_result = Some(result);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use serde_json::json;
    use tempfile::tempdir;
    use trillionnium_owner_open_job_registry::{JobKey, JobRequest, JobScope};

    use super::*;

    fn key(job_id: &str) -> JobKey {
        JobKey::new(
            JobScope::new("session-1", "owner-open", "task-1", "turn-1", "stream-1"),
            job_id,
        )
    }

    fn request(seed: char) -> JobRequest {
        JobRequest::new(
            seed.to_string().repeat(64),
            "b".repeat(64),
            "shell.job",
            "pipe",
            None,
        )
    }

    fn secure_tempdir() -> tempfile::TempDir {
        let directory = tempdir().expect("temporary directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("harden temporary directory");
        directory
    }

    #[test]
    fn oversized_owned_payloads_refuse_before_waiting_for_the_working_lane() {
        const ISOLATED: &str = "TRILLIONNIUM_JOURNAL_QUEUED_INPUT_CHILD";
        if std::env::var_os(ISOLATED).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "journal::tests::oversized_owned_payloads_refuse_before_waiting_for_the_working_lane", "--nocapture"])
                .env(ISOLATED, "1").output().unwrap();
            assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        }
        let journal = Arc::new(JobJournal::memory_only());
        let held = crate::resources::working_lane().unwrap();
        let mut waiting = Vec::new();
        for operation in 0..4 {
            let journal = Arc::clone(&journal);
            let (sender, receiver) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let mut spare = String::with_capacity(8 * 1024 * 1024);
                spare.push('x');
                let payload = Value::String(spare);
                let owner = key("queued");
                let request = request('a');
                let digest = "d".repeat(64);
                let result = match operation {
                    0 => journal.begin_operation(&owner, &request, "start", "start", &digest, payload).map(|_| ()),
                    1 => journal.complete_operation(&owner, &request, "start", "start", &digest, payload),
                    2 => journal.append_observation(&owner, &request, 0, "job.output", payload),
                    _ => journal.record_job_terminal(&owner, &request, 0, payload),
                };
                sender.send(result.is_err()).unwrap();
            });
            waiting.push((worker, receiver));
        }
        let rejected: Vec<_> = waiting.iter().map(|(_, receiver)|
            receiver.recv_timeout(std::time::Duration::from_millis(250))).collect();
        // Release before asserting so a regression cannot poison the global
        // lane or strand test workers while reporting its real failure.
        drop(held);
        for (worker, _) in waiting { worker.join().unwrap(); }
        assert!(rejected.iter().all(|result| matches!(result, Ok(true))),
                "owned oversized input was retained without admission while queued: {rejected:?}");
        assert!(journal.lock().unwrap().operations.is_empty());
        assert!(journal.lock().unwrap().jobs.is_empty());
    }

    #[test]
    fn queued_small_heap_is_not_treated_as_stack_storage() {
        const ISOLATED: &str = "TRILLIONNIUM_JOURNAL_SMALL_PENDING_CHILD";
        if std::env::var_os(ISOLATED).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "journal::tests::queued_small_heap_is_not_treated_as_stack_storage", "--nocapture"])
                .env(ISOLATED, "1").output().unwrap();
            assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        }
        let lane = crate::resources::working_lane().unwrap();
        let mut pressure = JobMemoryLease::acquire(0).unwrap();
        let (mut low, mut high) = (0, 48 * 1024 * 1024 + 1);
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            if pressure.resize(middle).is_ok() { low = middle; } else { high = middle; }
        }
        pressure.resize(low).unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let mut value = String::with_capacity(std::mem::size_of::<Value>());
            value.push('x');
            let result = journal_input_lane(&key("small"), &request('a'), Value::String(value));
            sender.send(result.is_err()).unwrap();
        });
        let refused = receiver.recv_timeout(std::time::Duration::from_millis(500));
        drop(lane);
        worker.join().unwrap();
        drop(pressure);
        assert!(matches!(refused, Ok(true)), "small heap bypassed queued admission: {refused:?}");
    }

    #[test]
    fn queued_valid_payloads_share_resident_admission_and_release_it() {
        const ISOLATED: &str = "TRILLIONNIUM_JOURNAL_PENDING_LEASE_CHILD";
        if std::env::var_os(ISOLATED).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "journal::tests::queued_valid_payloads_share_resident_admission_and_release_it", "--nocapture"])
                .env(ISOLATED, "1").output().unwrap();
            assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        }
        let journal = Arc::new(JobJournal::memory_only());
        let lane = crate::resources::working_lane().unwrap();
        let mut pressure = JobMemoryLease::acquire(0).unwrap();
        let (mut low, mut high) = (0, 48 * 1024 * 1024 + 1);
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            if pressure.resize(middle).is_ok() { low = middle; } else { high = middle; }
        }
        pressure.resize(low - 512 * 1024).unwrap();
        let clone = Arc::clone(&journal);
        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            ready_sender.send(()).unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let mut spare = String::with_capacity(256 * 1024);
                spare.push('x');
                let result = clone.complete_operation(&key("pending"), &request('a'), "missing", "write", &"d".repeat(64), Value::String(spare));
                // The observer itself briefly reserves capacity. Retry only
                // that real admission refusal so it cannot race the first
                // request into an early exit before its lease is observable.
                if matches!(&result, Err(JobRuntimeError::Journal(error))
                    if *error == trillionnium_owner_open_job_registry::JobRegistryError::CapacityExhausted.to_string())
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                done_sender.send(result.is_err()).unwrap();
                break;
            }
        });
        ready_receiver.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let admitted = loop {
            match JobMemoryLease::acquire(384 * 1024) {
                Ok(probe) => { drop(probe); }
                Err(_) => break true,
            }
            if std::time::Instant::now() >= deadline { break false; }
            std::thread::sleep(std::time::Duration::from_millis(1));
        };
        let mut oversized = String::with_capacity(384 * 1024);
        oversized.push('x');
        let owner = key("second");
        let req = request('a');
        let (second_sender, second_receiver) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            let refusal = journal_input_lane(&owner, &req, Value::String(oversized));
            second_sender.send(refusal.is_err()).unwrap();
        });
        let refused = second_receiver.recv_timeout(std::time::Duration::from_millis(500));
        // Release the shared lane even on regression before assertions.
        drop(lane);
        worker.join().unwrap();
        second.join().unwrap();
        let done = done_receiver.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
        assert!(matches!(refused, Ok(true)), "aggregate queued input was not refused: {refused:?}");
        assert!(admitted, "waiting input never consumed shared resident capacity");
        assert!(done, "fixture must remain effect-free for the missing operation");
        let released = JobMemoryLease::acquire(512 * 1024).expect("pending capacity returned after error");
        drop(released);
        drop(pressure);
        assert!(journal.lock().unwrap().operations.is_empty());
    }

    #[test]
    fn durable_terminals_are_references_and_large_payloads_survive_recovery() {
        let directory = secure_tempdir();
        let root = directory.path().join("references-v2");
        let journal = JobJournal::open_best_effort_segmented(Some(&root), None);
        let owner = key("large-terminals");
        let request = request('a');
        let digest = "d".repeat(64);
        for index in 0..12 {
            let operation = format!("operation-{index}");
            let kind = if index == 0 { "start" } else { "write" };
            assert_eq!(
                journal
                    .begin_operation(
                        &owner,
                        &request,
                        &operation,
                        kind,
                        &digest,
                        json!({"index": index})
                    )
                    .unwrap(),
                OperationBegin::New
            );
            journal
                .complete_operation(
                    &owner,
                    &request,
                    &operation,
                    kind,
                    &digest,
                    json!({"result": "x".repeat(512 * 1024), "index": index}),
                )
                .unwrap();
        }
        {
            let state = journal.lock().unwrap();
            assert_eq!(state.operations.len(), 12);
            assert!(state.operations.values().all(|operation| matches!(
                operation.terminal,
                Some(CachedPayload::Durable { .. })
            )));
            assert!(matches!(
                state.jobs.get(&owner).unwrap().start_result,
                Some(CachedPayload::Durable { .. })
            ));
        }
        assert_eq!(
            journal
                .begin_operation(
                    &owner,
                    &request,
                    "operation-11",
                    "write",
                    &digest,
                    json!({"index": 11})
                )
                .unwrap(),
            OperationBegin::ExistingTerminal(
                json!({"result": "x".repeat(512 * 1024), "index": 11})
            )
        );
        drop(journal);
        let reopened = JobJournal::open_best_effort_segmented(Some(&root), None);
        assert_eq!(reopened.status().unwrap(), JournalStatus::Durable);
        assert!(
            reopened
                .lock()
                .unwrap()
                .operations
                .values()
                .all(|operation| matches!(operation.terminal, Some(CachedPayload::Durable { .. })))
        );
        assert_eq!(
            reopened
                .recovered_job(&owner)
                .unwrap()
                .unwrap()
                .start_result
                .unwrap()
                .get("result")
                .unwrap()
                .as_str()
                .unwrap()
                .len(),
            512 * 1024
        );
    }

    fn fill_resident_pool() -> Vec<JobMemoryLease> {
        let mut leases = Vec::new();
        let mut bytes = 1024 * 1024;
        while bytes > 0 {
            match JobMemoryLease::acquire(bytes) {
                Ok(lease) => leases.push(lease),
                Err(_) => bytes /= 2,
            }
        }
        leases
    }

    #[test]
    fn escaped_and_spare_capacity_journal_payloads_refuse_before_any_wal_acceptance() {
        let directory = secure_tempdir();
        let path = directory.path().join("staging.jsonl");
        let journal = JobJournal::open_best_effort(Some(&path));
        let before = fs::read(&path).unwrap();
        let owner = key("staging");
        let request = request('a');
        let digest = "d".repeat(64);
        for payload in [
            Value::String("\n".repeat(2 * 1024 * 1024)),
            Value::Array(Vec::with_capacity(1024 * 1024)),
        ] {
            assert!(
                journal
                    .begin_operation(&owner, &request, "start", "start", &digest, payload)
                    .is_err()
            );
            assert!(journal.lock().unwrap().operations.is_empty());
            assert_eq!(fs::read(&path).unwrap(), before);
            assert_eq!(journal.status().unwrap(), JournalStatus::Durable);
        }
    }

    #[test]
    fn journal_capacity_precedes_wal_and_recovery_refusal_preserves_original_bytes() {
        const ISOLATED: &str = "TRILLIONNIUM_JOURNAL_POOL_CHILD";
        if std::env::var_os(ISOLATED).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "journal::tests::journal_capacity_precedes_wal_and_recovery_refusal_preserves_original_bytes", "--nocapture"])
                .env(ISOLATED, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let directory = secure_tempdir();
        let path = directory.path().join("capacity.jsonl");
        let journal = JobJournal::open_best_effort(Some(&path));
        let owner = key("capacity");
        let request = request('a');
        let digest = "d".repeat(64);
        let before = fs::read(&path).unwrap();
        let pressure = fill_resident_pool();
        assert!(
            journal
                .begin_operation(
                    &owner,
                    &request,
                    "start",
                    "start",
                    &digest,
                    json!({"start": true})
                )
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(journal.lock().unwrap().operations.is_empty());
        assert_eq!(journal.status().unwrap(), JournalStatus::Durable);
        drop(pressure);
        assert_eq!(
            journal
                .begin_operation(
                    &owner,
                    &request,
                    "start",
                    "start",
                    &digest,
                    json!({"start": true})
                )
                .unwrap(),
            OperationBegin::New
        );
        let pressure = fill_resident_pool();
        assert!(matches!(
            journal
                .begin_operation(
                    &owner,
                    &request,
                    "start",
                    "start",
                    &digest,
                    json!({"start": true})
                )
                .unwrap(),
            OperationBegin::ExistingAccepted { .. }
        ));
        journal
            .complete_operation(
                &owner,
                &request,
                "start",
                "start",
                &digest,
                json!({"result": "x".repeat(512 * 1024)}),
            )
            .unwrap();
        assert!(matches!(
            journal
                .begin_operation(
                    &owner,
                    &request,
                    "start",
                    "start",
                    &digest,
                    json!({"start": true})
                )
                .unwrap(),
            OperationBegin::ExistingTerminal(_)
        ));
        drop(pressure);
        drop(journal);
        let before = fs::read(&path).unwrap();
        let pressure = fill_resident_pool();
        let refused = JobJournal::open_best_effort(Some(&path));
        assert!(matches!(
            refused.status().unwrap(),
            JournalStatus::Unavailable { .. }
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(
            refused
                .begin_operation(&key("new"), &request, "new", "start", &digest, json!({}))
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(refused);
        drop(pressure);
        let reopened = JobJournal::open_best_effort(Some(&path));
        assert_eq!(reopened.status().unwrap(), JournalStatus::Durable);
        assert!(matches!(
            reopened
                .begin_operation(
                    &owner,
                    &request,
                    "start",
                    "start",
                    &digest,
                    json!({"start": true})
                )
                .unwrap(),
            OperationBegin::ExistingTerminal(_)
        ));
    }

    #[test]
    fn referenced_terminal_tampering_disables_the_journal_and_never_accepts_a_new_identity() {
        let directory = secure_tempdir();
        let root = directory.path().join("tamper-v2");
        let journal = JobJournal::open_best_effort_segmented(Some(&root), None);
        let owner = key("tamper");
        let request = request('a');
        let digest = "d".repeat(64);
        journal
            .begin_operation(&owner, &request, "start", "start", &digest, json!({}))
            .unwrap();
        journal
            .complete_operation(
                &owner,
                &request,
                "start",
                "start",
                &digest,
                json!({"result": "original-terminal-value"}),
            )
            .unwrap();
        let segment = fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("segment-")
            })
            .unwrap();
        let mut bytes = fs::read(&segment).unwrap();
        let offset = bytes
            .windows(b"original-terminal-value".len())
            .position(|part| part == b"original-terminal-value")
            .unwrap();
        bytes[offset] = b'X';
        fs::write(&segment, &bytes).unwrap();
        assert!(
            journal
                .begin_operation(&owner, &request, "start", "start", &digest, json!({}))
                .is_err()
        );
        assert!(matches!(
            journal.status().unwrap(),
            JournalStatus::Unavailable { .. }
        ));
        assert!(
            journal
                .begin_operation(
                    &key("fresh"),
                    &request,
                    "fresh",
                    "start",
                    &digest,
                    json!({})
                )
                .is_err()
        );
        assert_eq!(journal.lock().unwrap().operations.len(), 1);
        assert_eq!(fs::read(&segment).unwrap(), bytes);
    }

    #[test]
    fn direct_terminal_cursor_survives_restart_and_exhaustion_precedes_wal() {
        let directory = secure_tempdir();
        let path = directory.path().join("cursor.jsonl");
        let journal = JobJournal::open_best_effort(Some(&path));
        let owner = key("terminal");
        let request = request('a');
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            journal.record_job_terminal(&owner, &request, u64::MAX, json!({"terminal": true})),
            Err(JobRuntimeError::InvalidRequest(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        journal
            .record_job_terminal(&owner, &request, 7, json!({"terminal": true}))
            .unwrap();
        assert_eq!(journal.runtime_next_cursor(&owner).unwrap(), 8);
        drop(journal);
        let reopened = JobJournal::open_best_effort(Some(&path));
        assert!(matches!(reopened.status().unwrap(), JournalStatus::Durable));
        assert_eq!(reopened.runtime_next_cursor(&owner).unwrap(), 8);
    }

    #[test]
    fn scoped_inspection_does_not_skip_other_scopes_during_restart_authentication() {
        for segmented in [false, true] {
            let directory = secure_tempdir();
            let path = directory.path().join("all-scopes");
            let open = || {
                if segmented {
                    JobJournal::open_best_effort_segmented(Some(&path), None)
                } else {
                    JobJournal::open_best_effort(Some(&path))
                }
            };
            let journal = open();
            let owner = key("selected");
            let other = JobKey::new(
                JobScope::new("other-session", "owner-open", "other-task", "other-turn", "other-stream"),
                "unselected",
            );
            let request = request('a');
            journal.record_job_terminal(&owner, &request, 0, json!({"result": "selected-value"})).unwrap();
            journal.record_job_terminal(&other, &request, 0, json!({"result": "other-scope-value"})).unwrap();
            let selected = journal.inspect_records_with_metadata(&owner).unwrap();
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0]["payload"]["job_id"], "selected");
            assert_eq!(selected[0]["scope"]["session_id"], "session-1");
            drop(journal);
            let wal = if segmented {
                fs::read_dir(&path)
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|file| {
                        file.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with("segment-")
                    })
                    .unwrap()
            } else {
                path.clone()
            };
            let mut bytes = fs::read(&wal).unwrap();
            let offset = bytes.windows(b"other-scope-value".len())
                .position(|value| value == b"other-scope-value").unwrap();
            bytes[offset] = b'X';
            fs::write(&wal, &bytes).unwrap();
            let reopened = open();
            assert!(matches!(reopened.status().unwrap(), JournalStatus::Unavailable { .. }));
            assert!(reopened.begin_operation(&owner, &request, "fresh", "start", &"c".repeat(64), json!({})).is_err());
            assert_eq!(fs::read(&wal).unwrap(), bytes);
        }
    }

    #[test]
    fn inspect_records_is_job_scoped_and_metadata_has_contiguous_job_cursor() {
        let directory = secure_tempdir();
        let journal_path = directory.path().join("jobs.jsonl");
        let journal = JobJournal::open_best_effort(Some(&journal_path));
        assert!(matches!(journal.status().unwrap(), JournalStatus::Durable));

        let key_a = key("job-a");
        let key_b = key("job-b");
        let request_a = request('a');
        let request_b = request('b');
        let digest_a = "c".repeat(64);
        let digest_b = "d".repeat(64);

        // Interleave two jobs in one turn.  Event-store turn_seq is global to
        // that turn, while the metadata API must expose a separate contiguous
        // cursor for each filtered job.
        assert!(matches!(
            journal
                .begin_operation(
                    &key_a,
                    &request_a,
                    "start-a",
                    "start",
                    &digest_a,
                    json!({"status": "accepted"}),
                )
                .unwrap(),
            OperationBegin::New
        ));
        assert!(matches!(
            journal
                .begin_operation(
                    &key_b,
                    &request_b,
                    "start-b",
                    "start",
                    &digest_b,
                    json!({"status": "accepted"}),
                )
                .unwrap(),
            OperationBegin::New
        ));
        journal
            .append_observation(
                &key_a,
                &request_a,
                0,
                "job.output",
                json!({"stream": "stdout", "bytes": [1]}),
            )
            .unwrap();
        journal
            .append_observation(
                &key_b,
                &request_b,
                0,
                "job.output",
                json!({"stream": "stdout", "bytes": [2]}),
            )
            .unwrap();
        journal
            .complete_operation(
                &key_a,
                &request_a,
                "start-a",
                "start",
                &digest_a,
                json!({"status": "started"}),
            )
            .unwrap();

        let payloads = journal.inspect_records(&key_a).unwrap();
        assert_eq!(payloads.len(), 3);
        assert!(
            payloads
                .iter()
                .all(|payload| payload["job_id"] == json!("job-a"))
        );

        let metadata = journal.inspect_records_with_metadata(&key_a).unwrap();
        assert_eq!(metadata.len(), 3);
        for (expected, record) in metadata.iter().enumerate() {
            assert_eq!(record["job_record_seq"], json!(expected as u64));
            assert_eq!(
                record["schema"],
                json!(trillionnium_owner_open_event_store::EVENT_RECORD_SCHEMA)
            );
            assert_eq!(record["scope"]["turn_id"], json!("turn-1"));
            assert_eq!(record["payload"]["schema"], json!(JOB_JOURNAL_SCHEMA));
            assert_eq!(record["payload"]["job_id"], json!("job-a"));
            assert!(record["event_id"].as_str().is_some());
            assert!(record["record_sha256"].as_str().is_some());
        }
        // The sibling's record occupies turn_seq=1, so A's second record has
        // a non-contiguous turn_seq while its explicit job cursor is 1.
        assert_eq!(metadata[0]["turn_seq"], json!(0));
        assert_eq!(metadata[1]["turn_seq"], json!(2));
        assert_eq!(metadata[2]["turn_seq"], json!(4));

        drop(journal);
        let reopened = JobJournal::open_best_effort(Some(&journal_path));
        let reopened_metadata = reopened.inspect_records_with_metadata(&key_a).unwrap();
        assert_eq!(reopened_metadata, metadata);
        assert!(
            reopened
                .inspect_records_with_metadata(&key_b)
                .unwrap()
                .iter()
                .all(|record| record["payload"]["job_id"] == json!("job-b"))
        );
    }

    #[test]
    fn segmented_backend_is_an_additive_job_journal_path() {
        let directory = secure_tempdir();
        let root = directory.path().join("jobs-v2");
        let journal = JobJournal::open_best_effort_segmented(Some(&root), None);
        assert!(matches!(journal.status().unwrap(), JournalStatus::Durable));

        let job = key("job-v2");
        let request = request('v');
        let digest = "e".repeat(64);
        assert!(matches!(
            journal
                .begin_operation(
                    &job,
                    &request,
                    "start-v2",
                    "start",
                    &digest,
                    json!({"status": "accepted"}),
                )
                .unwrap(),
            OperationBegin::New
        ));
        journal
            .append_observation(
                &job,
                &request,
                0,
                "job.output",
                json!({"stream": "stdout", "bytes": [7]}),
            )
            .unwrap();
        journal.flush().unwrap();
        let metadata = journal.inspect_records_with_metadata(&job).unwrap();
        assert_eq!(metadata.len(), 2);
        assert!(root.join("segment-00000000000000000001.jsonl").is_file());
        assert!(root.join("index.v2.json").is_file());
        drop(journal);

        let reopened = JobJournal::open_best_effort_segmented(Some(&root), None);
        assert_eq!(
            reopened.inspect_records_with_metadata(&job).unwrap(),
            metadata
        );
    }

    #[test]
    fn segmented_migration_accepts_new_records_after_the_legacy_prefix() {
        let directory = secure_tempdir();
        let legacy_path = directory.path().join("jobs.jsonl");
        let root = directory.path().join("jobs.jsonl.segments");
        let job = key("job-migrated");
        let request = request('m');
        let digest = "f".repeat(64);

        let legacy = JobJournal::open_best_effort(Some(&legacy_path));
        assert!(matches!(
            legacy
                .begin_operation(
                    &job,
                    &request,
                    "start-migrated",
                    "start",
                    &digest,
                    json!({"status": "accepted"}),
                )
                .unwrap(),
            OperationBegin::New
        ));
        legacy
            .append_observation(
                &job,
                &request,
                0,
                "job.output",
                json!({"stream": "stdout", "bytes": [1]}),
            )
            .unwrap();
        drop(legacy);

        let migrated = JobJournal::open_best_effort_segmented(Some(&root), Some(&legacy_path));
        assert!(matches!(migrated.status().unwrap(), JournalStatus::Durable));
        migrated
            .append_observation(
                &job,
                &request,
                1,
                "job.output",
                json!({"stream": "stdout", "bytes": [2]}),
            )
            .unwrap();
        migrated.flush().unwrap();
        drop(migrated);

        // The legacy JSONL source is now a shorter, valid prefix.  A restart
        // must preserve the segmented tail instead of reporting a false
        // extra-destination conflict.
        let reopened = JobJournal::open_best_effort_segmented(Some(&root), Some(&legacy_path));
        assert!(matches!(reopened.status().unwrap(), JournalStatus::Durable));
        assert_eq!(reopened.inspect_records(&job).unwrap().len(), 3);
    }
}
