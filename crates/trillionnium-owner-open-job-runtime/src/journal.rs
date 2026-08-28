use std::collections::HashMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_event_store::{
    DurableEventStore, EventInput, EventStoreLimits, SyncPolicy, TurnScope,
};
use trillionnium_owner_open_job_registry::{JobKey, JobRequest};

use crate::validate::{require_id, require_sha256, require_text};
use crate::{JobRuntimeError, Result};

const JOURNAL_SCHEMA: &str = "trillionnium.owner-open.job-journal.v1";

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
    operation_kind: String,
    operation_sha256: String,
    terminal: Option<Value>,
    preexisting: bool,
}

#[derive(Debug, Clone)]
struct JobState {
    request: JobRequest,
    start_result: Option<Value>,
    terminal: Option<Value>,
}

#[derive(Debug)]
struct State {
    store: Option<DurableEventStore>,
    configured: bool,
    error: Option<String>,
    operations: HashMap<OperationKey, OperationState>,
    jobs: HashMap<JobKey, JobState>,
}

#[derive(Debug)]
pub struct JobJournal {
    state: Mutex<State>,
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
    #[must_use]
    pub fn memory_only() -> Self {
        Self {
            state: Mutex::new(State {
                store: None,
                configured: false,
                error: None,
                operations: HashMap::new(),
                jobs: HashMap::new(),
            }),
        }
    }

    #[must_use]
    pub fn open_best_effort(path: Option<&Path>) -> Self {
        let Some(path) = path else {
            return Self::memory_only();
        };
        match DurableEventStore::open(path, EventStoreLimits::default(), SyncPolicy::Full) {
            Ok(store) => match recover(&store) {
                Ok((operations, jobs)) => Self {
                    state: Mutex::new(State {
                        store: Some(store),
                        configured: true,
                        error: None,
                        operations,
                        jobs,
                    }),
                },
                Err(error) => Self {
                    state: Mutex::new(State {
                        store: None,
                        configured: true,
                        error: Some(error),
                        operations: HashMap::new(),
                        jobs: HashMap::new(),
                    }),
                },
            },
            Err(error) => Self {
                state: Mutex::new(State {
                    store: None,
                    configured: true,
                    error: Some(error.to_string()),
                    operations: HashMap::new(),
                    jobs: HashMap::new(),
                }),
            },
        }
    }

    pub fn status(&self) -> Result<JournalStatus> {
        let state = self.lock()?;
        Ok(match (&state.store, state.configured, state.error.as_deref()) {
            (Some(_), _, _) => JournalStatus::Durable,
            (None, false, _) => JournalStatus::BestEffortMemoryOnly,
            (None, true, Some(error)) => JournalStatus::Unavailable {
                error: error.to_string(),
            },
            (None, true, None) => JournalStatus::Unavailable {
                error: "job journal is unavailable".to_string(),
            },
        })
    }

    pub fn is_durable(&self) -> Result<bool> {
        Ok(self.lock()?.store.is_some())
    }

    pub fn error(&self) -> Result<Option<String>> {
        Ok(self.lock()?.error.clone())
    }

    pub fn recovered_job(&self, key: &JobKey) -> Result<Option<RecoveredJob>> {
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
        let operation_key = OperationKey {
            job: key.clone(),
            operation_id: operation_id.to_string(),
        };
        let mut state = self.lock()?;
        if let Some(existing) = state.operations.get(&operation_key) {
            if existing.operation_kind != operation_kind
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
        if operation_kind == "start" {
            if let Some(existing) = state.jobs.get(key) {
                if existing.request != *request {
                    return Err(JobRuntimeError::JobConflict);
                }
                return Ok(OperationBegin::ExistingAccepted {
                    restart_uncertain: existing.start_result.is_some(),
                });
            }
        }
        if state.store.is_none() {
            state.operations.insert(
                operation_key,
                OperationState {
                    operation_kind: operation_kind.to_string(),
                    operation_sha256: operation_sha256.to_string(),
                    terminal: None,
                    preexisting: false,
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
        let append_result = {
            let store = state.store.as_ref().expect("store presence checked");
            append_envelope(
                store,
                key,
                &format!("job.operation.accepted.{operation_kind}"),
                event_id("accepted", key, operation_id),
                &envelope,
            )
        };
        if let Err(error) = append_result {
            return Err(disable(&mut state, error));
        }
        state.operations.insert(
            operation_key,
            OperationState {
                operation_kind: operation_kind.to_string(),
                operation_sha256: operation_sha256.to_string(),
                terminal: None,
                preexisting: false,
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
        let operation_key = OperationKey {
            job: key.clone(),
            operation_id: operation_id.to_string(),
        };
        let mut state = self.lock()?;
        if let Some(existing) = state.operations.get(&operation_key) {
            if existing.operation_kind != operation_kind
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
        } else {
            return Err(JobRuntimeError::Journal(
                "operation terminal has no accepted record".to_string(),
            ));
        }
        if state.store.is_some() {
            let envelope = JournalEnvelope {
                schema: JOURNAL_SCHEMA.to_string(),
                record: "operation.terminal".to_string(),
                job_id: key.job_id.clone(),
                request: request.clone(),
                operation_id: Some(operation_id.to_string()),
                operation_kind: Some(operation_kind.to_string()),
                operation_sha256: Some(operation_sha256.to_string()),
                event_seq: None,
                payload: result.clone(),
            };
            let append_result = {
                let store = state.store.as_ref().expect("store presence checked");
                append_envelope(
                    store,
                    key,
                    &format!("job.operation.terminal.{operation_kind}"),
                    event_id("terminal", key, operation_id),
                    &envelope,
                )
            };
            if let Err(error) = append_result {
                return Err(disable(&mut state, error));
            }
        }
        state
            .operations
            .get_mut(&operation_key)
            .expect("accepted operation presence checked")
            .terminal = Some(result.clone());
        if operation_kind == "start" {
            if let Some(job) = state.jobs.get_mut(key) {
                job.start_result = Some(result);
            }
        }
        Ok(())
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
        let mut state = self.lock()?;
        if state.store.is_none() {
            return Ok(());
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
        let append_result = {
            let store = state.store.as_ref().expect("store presence checked");
            append_envelope(
                store,
                key,
                kind,
                event_id("observation", key, &event_seq.to_string()),
                &envelope,
            )
        };
        match append_result {
            Ok(()) => Ok(()),
            Err(error) => Err(disable(&mut state, error)),
        }
    }

    pub fn record_job_terminal(
        &self,
        key: &JobKey,
        request: &JobRequest,
        event_seq: u64,
        payload: Value,
    ) -> Result<()> {
        let mut state = self.lock()?;
        if let Some(existing) = state.jobs.get(key).and_then(|job| job.terminal.as_ref()) {
            if existing == &payload {
                return Ok(());
            }
            return Err(JobRuntimeError::JobConflict);
        }
        if state.store.is_some() {
            let envelope = JournalEnvelope {
                schema: JOURNAL_SCHEMA.to_string(),
                record: "job.terminal".to_string(),
                job_id: key.job_id.clone(),
                request: request.clone(),
                operation_id: None,
                operation_kind: None,
                operation_sha256: None,
                event_seq: Some(event_seq),
                payload: payload.clone(),
            };
            let append_result = {
                let store = state.store.as_ref().expect("store presence checked");
                append_envelope(
                    store,
                    key,
                    "job.terminal",
                    event_id("job-terminal", key, "terminal"),
                    &envelope,
                )
            };
            if let Err(error) = append_result {
                return Err(disable(&mut state, error));
            }
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
        Ok(())
    }

    pub fn inspect_records(&self, key: &JobKey) -> Result<Vec<Value>> {
        let state = self.lock()?;
        let Some(store) = state.store.as_ref() else {
            return Ok(Vec::new());
        };
        let scope = turn_scope(key);
        store
            .replay(&scope, 0)
            .map(|records| records.into_iter().map(|record| record.payload).collect())
            .map_err(|error| JobRuntimeError::Journal(error.to_string()))
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)
    }
}

fn recover(
    store: &DurableEventStore,
) -> std::result::Result<
    (HashMap<OperationKey, OperationState>, HashMap<JobKey, JobState>),
    String,
> {
    let mut operations = HashMap::new();
    let mut jobs = HashMap::<JobKey, JobState>::new();
    for record in store.all_records().map_err(|error| error.to_string())? {
        let envelope: JournalEnvelope = serde_json::from_value(record.payload.clone())
            .map_err(|error| error.to_string())?;
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
                        operation_kind: operation_kind.clone(),
                        operation_sha256,
                        terminal: None,
                        preexisting: true,
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
                if operation.operation_kind != operation_kind
                    || operation.operation_sha256 != operation_sha256
                    || operation.terminal.replace(envelope.payload.clone()).is_some()
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

fn append_envelope(
    store: &DurableEventStore,
    key: &JobKey,
    kind: &str,
    event_id: String,
    envelope: &JournalEnvelope,
) -> std::result::Result<(), String> {
    let payload = serde_json::to_value(envelope).map_err(|error| error.to_string())?;
    store
        .append(EventInput {
            scope: turn_scope(key),
            event_id,
            kind: kind.to_string(),
            payload,
        })
        .map(|_| ())
        .map_err(|error| error.to_string())
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
