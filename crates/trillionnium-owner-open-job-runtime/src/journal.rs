use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_event_store::{
    DurableEventStore, EventInput, EventRecord, EventStoreLimits, SegmentedEventStore,
    SegmentedEventStoreConfig, SyncPolicy, TurnScope,
};
use trillionnium_owner_open_job_registry::{JobKey, JobRequest};

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
    terminal: Option<Value>,
    preexisting: bool,
    /// True only when the accepted record was committed to the durable store.
    /// This prevents a later journal outage from being mistaken for a
    /// successful after-effect append.
    durable_accept: bool,
}

#[derive(Debug, Clone)]
struct JobState {
    request: JobRequest,
    start_result: Option<Value>,
    terminal: Option<Value>,
}

type OperationStates = HashMap<OperationKey, OperationState>;
type JobStates = HashMap<JobKey, JobState>;
type RecoveredState = (OperationStates, JobStates);

#[derive(Debug)]
enum EventStoreBackend {
    Legacy(Box<DurableEventStore>),
    Segmented(Box<SegmentedEventStore>),
}

impl EventStoreBackend {
    fn append(&self, input: EventInput) -> trillionnium_owner_open_event_store::Result<()> {
        match self {
            Self::Legacy(store) => store.append(input).map(|_| ()),
            Self::Segmented(store) => store.append(input).map(|_| ()),
        }
    }

    fn append_durable(&self, input: EventInput) -> trillionnium_owner_open_event_store::Result<()> {
        match self {
            Self::Legacy(store) => store.append(input).map(|_| ()),
            Self::Segmented(store) => store.append_durable(input).map(|_| ()),
        }
    }

    fn all_records(&self) -> trillionnium_owner_open_event_store::Result<Vec<EventRecord>> {
        match self {
            Self::Legacy(store) => store.all_records(),
            Self::Segmented(store) => store.all_records(),
        }
    }

    fn replay(
        &self,
        scope: &TurnScope,
        inclusive_turn_seq: u64,
    ) -> trillionnium_owner_open_event_store::Result<Vec<EventRecord>> {
        match self {
            Self::Legacy(store) => store.replay(scope, inclusive_turn_seq),
            Self::Segmented(store) => store.replay(scope, inclusive_turn_seq),
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
    #[cfg(test)]
    fail_next_accept: bool,
    #[cfg(test)]
    fail_next_observation: bool,
}

#[derive(Debug)]
pub struct JobJournal {
    state: Mutex<State>,
    key_shards: Vec<Mutex<()>>,
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

impl JobJournal {
    fn from_state(state: State) -> Self {
        Self {
            state: Mutex::new(state),
            key_shards: (0..JOURNAL_SHARD_COUNT).map(|_| Mutex::new(())).collect(),
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
                Ok((operations, jobs)) => Self::from_state(State {
                    store: Some(store),
                    configured: true,
                    error: None,
                    operations,
                    jobs,
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
        let state = self.lock()?;
        Ok(state.jobs.get(key).map(|job| RecoveredJob {
            key: key.clone(),
            request: job.request.clone(),
            start_result: job.start_result.clone(),
            terminal: job.terminal.clone(),
        }))
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
        validate_operation(operation_id, operation_kind, operation_sha256)?;
        // A key shard preserves the linearizable begin/append transition for
        // this job while allowing unrelated jobs to release the global state
        // mutex during filesystem I/O.
        let _key_guard = self.key_guard(key)?;
        let operation_key = OperationKey {
            job: key.clone(),
            operation_id: operation_id.to_string(),
        };
        let (store, envelope) = {
            let mut state = self.lock()?;
            ensure_request_for_key(&state, key, request)?;
            if let Some(existing) = state.operations.get(&operation_key) {
                if existing.request != *request
                    || existing.operation_kind != operation_kind
                    || existing.operation_sha256 != operation_sha256
                {
                    return Err(JobRuntimeError::JobConflict);
                }
                return Ok(match &existing.terminal {
                    Some(terminal) => OperationBegin::ExistingTerminal(terminal.clone()),
                    None => OperationBegin::ExistingAccepted {
                        restart_uncertain: existing.preexisting,
                    },
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

            if state.store.is_none() {
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
            (store, envelope)
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
        validate_operation(operation_id, operation_kind, operation_sha256)?;
        let _key_guard = self.key_guard(key)?;
        let operation_key = OperationKey {
            job: key.clone(),
            operation_id: operation_id.to_string(),
        };
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
                if let Some(terminal) = &existing.terminal {
                    if terminal == &result {
                        return Ok(());
                    }
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
        if let Err(error) = append_result {
            mark_operation_uncertain(&mut state, &operation_key);
            return Err(disable(&mut state, error));
        }
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
            envelope.payload,
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
        let (store, envelope) = {
            let mut state = self.lock()?;
            ensure_request_for_key(&state, key, request)?;
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
                let job = state.jobs.entry(key.clone()).or_insert(JobState {
                    request: request.clone(),
                    start_result: None,
                    terminal: None,
                });
                if let Some(terminal_payload) = terminal_payload {
                    if let Some(existing) = &job.terminal {
                        if existing != &terminal_payload {
                            return Err(JobRuntimeError::JobConflict);
                        }
                    } else {
                        job.terminal = Some(terminal_payload);
                    }
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
            (Arc::clone(store), envelope)
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

        // Bind the request as soon as the observation append succeeds.  If a
        // subsequent terminal append fails, the request identity still
        // remains recorded in memory and future calls fail closed instead of
        // mixing another request into this job's journal lineage.
        state.jobs.entry(key.clone()).or_insert(JobState {
            request: request.clone(),
            start_result: None,
            terminal: None,
        });
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
        if let Some(existing) = state.jobs.get(key).and_then(|job| job.terminal.as_ref()) {
            if existing == &terminal_payload {
                return Ok(());
            }
            return Err(JobRuntimeError::JobConflict);
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
        if let Err(error) = terminal_append_result {
            return Err(disable(&mut state, error));
        }
        if state.store.is_none() {
            return Err(JobRuntimeError::Journal(
                state.error.clone().unwrap_or_else(|| {
                    "job journal became unavailable after terminal append".to_string()
                }),
            ));
        }
        state
            .jobs
            .entry(key.clone())
            .and_modify(|job| job.terminal = Some(terminal_payload.clone()))
            .or_insert(JobState {
                request: request.clone(),
                start_result: None,
                terminal: Some(terminal_payload),
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
        let _key_guard = self.key_guard(key)?;
        let (store, envelope) = {
            let mut state = self.lock()?;
            ensure_request_for_key(&state, key, request)?;
            if let Some(existing) = state.jobs.get(key).and_then(|job| job.terminal.as_ref()) {
                if existing == &payload {
                    return Ok(());
                }
                return Err(JobRuntimeError::JobConflict);
            }

            let Some(store) = state.store.as_ref() else {
                if state.configured {
                    return Err(JobRuntimeError::Journal(
                        state.error.clone().unwrap_or_else(|| {
                            "job journal is unavailable before terminal append".to_string()
                        }),
                    ));
                }
                state
                    .jobs
                    .entry(key.clone())
                    .and_modify(|job| job.terminal = Some(payload.clone()))
                    .or_insert(JobState {
                        request: request.clone(),
                        start_result: None,
                        terminal: Some(payload),
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
            (Arc::clone(store), envelope)
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
        if let Err(error) = append_result {
            return Err(disable(&mut state, error));
        }
        if state.store.is_none() {
            return Err(JobRuntimeError::Journal(
                state.error.clone().unwrap_or_else(|| {
                    "job journal became unavailable after terminal append".to_string()
                }),
            ));
        }
        if let Some(existing) = state.jobs.get(key).and_then(|job| job.terminal.as_ref()) {
            if existing == &envelope.payload {
                return Ok(());
            }
            return Err(JobRuntimeError::JobConflict);
        }
        state
            .jobs
            .entry(key.clone())
            .and_modify(|job| job.terminal = Some(envelope.payload.clone()))
            .or_insert(JobState {
                request: request.clone(),
                start_result: None,
                terminal: Some(envelope.payload),
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
        // Replay is read-only but can scan a large legacy store.  Keep it out
        // of the global journal-state mutex; the key shard still prevents a
        // same-key mutation from racing the request-binding checks below.
        let records = store
            .replay(&scope, 0)
            .map_err(|error| JobRuntimeError::Journal(error.to_string()))?;
        let mut matching = Vec::with_capacity(records.len());
        for record in records {
            if record.scope != scope {
                return Err(JobRuntimeError::Journal(
                    "durable job journal record scope metadata does not match replay scope"
                        .to_string(),
                ));
            }
            let envelope: JournalEnvelope = serde_json::from_value(record.payload.clone())
                .map_err(|error| {
                    JobRuntimeError::Journal(format!(
                        "durable job journal record envelope is invalid: {error}"
                    ))
                })?;
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
                matching.push(record);
            }
        }
        Ok(matching)
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
    let Some(legacy_path) = legacy_path.filter(|path| path.exists()) else {
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
    for record in store.all_records().map_err(|error| error.to_string())? {
        let envelope: JournalEnvelope =
            serde_json::from_value(record.payload.clone()).map_err(|error| error.to_string())?;
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
            requests.insert(key.clone(), envelope.request.clone());
        }
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
                    jobs.entry(key).or_insert(JobState {
                        request: envelope.request,
                        start_result: None,
                        terminal: None,
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
                        .replace(envelope.payload.clone())
                        .is_some()
                {
                    return Err("job operation terminal conflicts".to_string());
                }
                if operation_kind == "start" {
                    jobs.entry(key)
                        .and_modify(|job| job.start_result = Some(envelope.payload.clone()))
                        .or_insert(JobState {
                            request: envelope.request,
                            start_result: Some(envelope.payload),
                            terminal: None,
                        });
                }
            }
            "observation" => {
                jobs.entry(key).or_insert(JobState {
                    request: envelope.request,
                    start_result: None,
                    terminal: None,
                });
            }
            "job.terminal" => {
                let job = jobs.entry(key).or_insert(JobState {
                    request: envelope.request,
                    start_result: None,
                    terminal: None,
                });
                if job.terminal.replace(envelope.payload).is_some() {
                    return Err("job terminal record is duplicated".to_string());
                }
            }
            other => return Err(format!("unsupported job journal record {other}")),
        }
    }
    Ok((operations, jobs))
}

fn validate_operation(operation_id: &str, kind: &str, digest: &str) -> Result<()> {
    require_id(operation_id, "operation_id", 256)
        .map_err(|error| JobRuntimeError::InvalidRequest(error.to_string()))?;
    require_text(kind, "operation_kind", 64, false)
        .map_err(|error| JobRuntimeError::InvalidRequest(error.to_string()))?;
    require_sha256(digest, "operation_sha256")
        .map_err(|error| JobRuntimeError::InvalidRequest(error.to_string()))
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
) -> std::result::Result<(), String> {
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
    append_result.map(|_| ()).map_err(|error| error.to_string())
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
    result: Value,
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
