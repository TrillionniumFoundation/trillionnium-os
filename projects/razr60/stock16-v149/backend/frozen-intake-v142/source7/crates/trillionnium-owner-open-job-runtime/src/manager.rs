use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use trillionnium_owner_open_job_registry::{
    BeginDisposition, JobEffectiveState, JobEvent, JobKey, JobRegistry, JobRegistryError,
    JobRequest, JobTerminal, SpawnClaim,
};

use crate::journal::{JournalStatus, OperationBegin};
use crate::process::{ProcessControl, StdinCloseEffect, spawn_process};
use crate::{
    ControlDisposition, EventLogStatus, InternalProcessEvent, JobInspection, JobJournal,
    JobObservationGap, JobRuntimeConfig, JobRuntimeError, JobStartRequest, JobStartResult,
    ProcessIdentity, PtySize, ReplayStatus, Result, RuntimeJobEvent, RuntimeJobEventKind,
    StartDisposition,
};

const START_SHARD_COUNT: usize = 64;
const START_SHARD_HASH_VERSION: u8 = 1;
const START_SHARD_DOMAIN: &[u8] = b"owner-open-job-manager-start";
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;

struct AdmissionPool {
    active: AtomicUsize,
    maximum: usize,
}

impl AdmissionPool {
    fn new(maximum: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum,
        }
    }

    fn try_acquire(self: &Arc<Self>) -> Result<AdmissionPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.maximum {
                return Err(JobRuntimeError::InvalidRequest(
                    "job runtime capacity is exhausted before acceptance".to_string(),
                ));
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(AdmissionPermit {
                        pool: Arc::clone(self),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

struct AdmissionPermit {
    pool: Arc<AdmissionPool>,
}

impl Drop for AdmissionPermit {
    fn drop(&mut self) {
        let previous = self.pool.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "job admission permit underflow");
    }
}

struct RunningJob {
    control: Arc<ProcessControl>,
    request: JobRequest,
    generation: u64,
    _admission_permit: AdmissionPermit,
    startup: Arc<StartupGate>,
    lifecycle: Mutex<()>,
    stdout_bytes: Mutex<u64>,
    stderr_bytes: Mutex<u64>,
}

/// Barrier between publishing a locally-owned process and authorizing live
/// controls against it.  The running-map entry is intentionally installed
/// before the identity/started observations so a child that exits immediately
/// can still be reaped by the dispatcher; controls must nevertheless wait
/// until those facts and the durable start terminal have been committed.
struct StartupGate {
    state: Mutex<StartupState>,
    changed: Condvar,
}

enum StartupState {
    Pending,
    Ready,
    Failed(String),
    Terminal,
}

impl StartupGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(StartupState::Pending),
            changed: Condvar::new(),
        }
    }

    fn wait(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        loop {
            match &*state {
                StartupState::Pending => {
                    state = self
                        .changed
                        .wait(state)
                        .map_err(|_| JobRuntimeError::StatePoisoned)?;
                }
                StartupState::Ready => return Ok(()),
                StartupState::Failed(error) => {
                    return Err(JobRuntimeError::Io(format!(
                        "job startup did not become live: {error}"
                    )));
                }
                StartupState::Terminal => return Err(JobRuntimeError::NotLive),
            }
        }
    }

    fn ready(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        if matches!(*state, StartupState::Pending) {
            *state = StartupState::Ready;
            self.changed.notify_all();
        }
        Ok(())
    }

    fn fail(&self, error: impl Into<String>) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        if matches!(*state, StartupState::Pending) {
            *state = StartupState::Failed(error.into());
            self.changed.notify_all();
        }
        Ok(())
    }

    /// Close the startup window when the child reaches its terminal event
    /// before the start caller has had a chance to mark the gate ready.  A
    /// terminal state is distinct from an internal startup failure: the
    /// start operation did become effectful, but no control captured during
    /// the pending window may run against the now-terminal process.
    fn terminal(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        if matches!(*state, StartupState::Pending) {
            *state = StartupState::Terminal;
            self.changed.notify_all();
        }
        Ok(())
    }
}

#[derive(Default)]
struct ObservationState {
    events: VecDeque<RuntimeJobEvent>,
    next_seq: u64,
    byte_count: usize,
    journal_unavailable_emitted: bool,
}

struct Inner {
    config: JobRuntimeConfig,
    registry: Arc<JobRegistry>,
    journal: Arc<JobJournal>,
    running: Mutex<HashMap<JobKey, Arc<RunningJob>>>,
    admission: Arc<AdmissionPool>,
    start_shards: Vec<Mutex<()>>,
    observations: Mutex<HashMap<JobKey, ObservationState>>,
    durability_error: Mutex<Option<String>>,
}

#[derive(Clone)]
pub struct JobManager {
    inner: Arc<Inner>,
}

impl JobManager {
    pub fn new(config: JobRuntimeConfig, journal: JobJournal) -> Result<Self> {
        config.validate()?;
        let max_jobs = config.max_jobs;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                registry: Arc::new(JobRegistry::default()),
                journal: Arc::new(journal),
                running: Mutex::new(HashMap::new()),
                admission: Arc::new(AdmissionPool::new(max_jobs)),
                start_shards: (0..START_SHARD_COUNT).map(|_| Mutex::new(())).collect(),
                observations: Mutex::new(HashMap::new()),
                durability_error: Mutex::new(None),
            }),
        })
    }

    pub fn open(config: JobRuntimeConfig, journal_path: Option<&Path>) -> Result<Self> {
        Self::new(config, JobJournal::open_best_effort(journal_path))
    }

    /// Open the segmented v2 job journal used by the G1 runtime path. The
    /// legacy JSONL path is imported once into a sibling `<path>.segments`
    /// directory when present. Appending the suffix to the complete path is
    /// intentional: a turn store at `events.jsonl` and its derived job store
    /// at `events.jsonl.jobs` must never share one segmented root. Callers
    /// that still need the v1 file API can continue using [`Self::open`].
    pub fn open_segmented(config: JobRuntimeConfig, journal_path: Option<&Path>) -> Result<Self> {
        let root: Option<PathBuf> = journal_path.map(|path| {
            let mut root = path.as_os_str().to_os_string();
            root.push(".segments");
            root.into()
        });
        Self::new(
            config,
            JobJournal::open_best_effort_segmented(root.as_deref(), journal_path),
        )
    }

    #[must_use]
    pub fn registry(&self) -> &Arc<JobRegistry> {
        &self.inner.registry
    }

    #[must_use]
    pub fn journal(&self) -> &Arc<JobJournal> {
        &self.inner.journal
    }

    pub fn start(&self, request: JobStartRequest) -> Result<JobStartResult> {
        validate_start_request(&request, &self.inner.config)?;
        // Serialize only the exact start shard. The running map is never held
        // across journal I/O, process spawn, or dispatcher creation, so
        // unrelated keys can start concurrently while one key remains
        // linearizable.
        let _start_guard = self.start_guard(&request.key)?;
        if let Some(running) = self.running()?.get(&request.key).cloned() {
            if running.request != request.request {
                return Err(JobRuntimeError::JobConflict);
            }
            // A locally-owned entry is published before its identity and
            // durable start terminal.  Duplicate starts must not observe it
            // as live until that startup barrier has opened.
            running.startup.wait()?;
            return Ok(JobStartResult {
                disposition: StartDisposition::ExistingLive,
                snapshot: self.inner.registry.snapshot(&request.key).ok(),
                replay_status: self.replay_status(false)?,
            });
        }

        // A live in-process child is stronger than a stale recovered record:
        // restart recovery may still contain the accepted/start record while
        // a child that this manager owns is running.  Check the live map first
        // so an idempotent repeat returns ExistingLive rather than incorrectly
        // downgrading the operation to UnknownAfterRestart.
        if let Some(recovered) = self.inner.journal.recovered_job(&request.key)? {
            if recovered.request != request.request {
                return Err(JobRuntimeError::JobConflict);
            }
            // A recovered record is authoritative only for the durable
            // operation outcome.  If this manager also has a registry entry
            // but no owned RunningJob, fence that entry before returning: a
            // stale Accepted/Starting/Running state must never remain
            // redispatchable through the public registry API.
            let snapshot = match self.inner.registry.snapshot(&request.key) {
                Ok(_) => Some(
                    self.inner
                        .registry
                        .mark_restart_uncertain(&request.key)
                        .map_err(registry_error)?,
                ),
                Err(JobRegistryError::NotFound) => None,
                Err(error) => return Err(registry_error(error)),
            };
            return Ok(JobStartResult {
                disposition: if recovered.terminal.is_some() {
                    StartDisposition::ExistingTerminal
                } else {
                    StartDisposition::UnknownAfterRestart
                },
                snapshot,
                replay_status: if recovered.terminal.is_some() {
                    self.replay_status(false)?
                } else {
                    ReplayStatus::UnknownAfterRestart
                },
            });
        }

        let registry_entry_exists = match self.inner.registry.snapshot(&request.key) {
            Ok(_) => true,
            Err(JobRegistryError::NotFound) => false,
            Err(error) => return Err(registry_error(error)),
        };
        // Compute the exact operation identity before the registry accepts the
        // key.  A serialization/digest failure must not leave an Accepted
        // entry that has no corresponding journal operation.
        let operation_sha256 = start_operation_sha256(&request)?;

        // Fail closed before the registry accepts the job.  An unavailable or
        // deliberately memory-only journal must not leave an Accepted entry
        // behind when production policy rejects unjournaled effects.
        let journal_status = self.inner.journal.status()?;
        if !self.inner.config.allow_unjournaled_effects
            && !matches!(&journal_status, JournalStatus::Durable)
        {
            let reason = journal_status_reason(&journal_status);
            let _ = self.note_journal_degraded_for_job(&request.key, reason);
            if registry_entry_exists {
                // A pre-existing registry marker must not remain an
                // unowned, redispatchable Accepted state while persistence
                // is unavailable. The live-map check above already ruled
                // out a locally owned process, so fence the entry now.
                self.inner
                    .registry
                    .mark_restart_uncertain(&request.key)
                    .map_err(registry_error)?;
            }
            return Err(JobRuntimeError::Journal(
                "job journal is unavailable and unjournaled effects are disabled".to_string(),
            ));
        }

        // Reserve finite process capacity before the registry can accept a
        // new key. The permit is RAII-owned and transferred into RunningJob
        // only after spawn succeeds; every pre-spawn error releases it.
        let admission_permit = if registry_entry_exists {
            None
        } else {
            Some(self.inner.admission.try_acquire()?)
        };

        let begin = self
            .inner
            .registry
            .begin(request.key.clone(), request.request.clone())
            .map_err(registry_error)?;
        if begin.disposition == BeginDisposition::Existing {
            let (disposition, snapshot, replay_status) = match begin.snapshot.state {
                JobEffectiveState::Terminal { .. } => (
                    StartDisposition::ExistingTerminal,
                    begin.snapshot,
                    self.replay_status(false)?,
                ),
                JobEffectiveState::UnknownAfterRestart { .. }
                | JobEffectiveState::ProvenNotStartedAfterRestart
                | JobEffectiveState::Accepted
                | JobEffectiveState::Starting { .. }
                | JobEffectiveState::Running { .. } => {
                    // `BeginDisposition::Existing` does not imply that a
                    // process is live.  Accepted and claimed/running states
                    // without a matching in-process owner are stale or
                    // recovery remnants; fence them before exposing the
                    // idempotent result so a later claim cannot redispatch
                    // an effect whose boundary is unknown.
                    let snapshot = self
                        .inner
                        .registry
                        .mark_restart_uncertain(&request.key)
                        .map_err(registry_error)?;
                    (
                        StartDisposition::UnknownAfterRestart,
                        snapshot,
                        ReplayStatus::UnknownAfterRestart,
                    )
                }
            };
            return Ok(JobStartResult {
                disposition,
                snapshot: Some(snapshot),
                replay_status,
            });
        }
        if matches!(&journal_status, JournalStatus::Unavailable { .. }) {
            let _ = self.note_journal_degraded_for_job(
                &request.key,
                journal_status_reason(&journal_status),
            );
            let snapshot = self
                .inner
                .registry
                .mark_restart_uncertain(&request.key)
                .map_err(registry_error)?;
            return Ok(JobStartResult {
                disposition: StartDisposition::UnknownAfterRestart,
                snapshot: Some(snapshot),
                replay_status: ReplayStatus::UnknownAfterRestart,
            });
        }

        let journal_begin = match self.inner.journal.begin_operation(
            &request.key,
            &request.request,
            &request.operation_id,
            "start",
            &operation_sha256,
            start_details(&request),
        ) {
            Ok(begin) => begin,
            Err(error) => {
                let journal_error = error.to_string();
                let _ = self.note_journal_failure_for_job(&request.key, journal_error);
                // `registry.begin` ran first to reserve the exact key.  If
                // durable acceptance fails, remove only that untouched
                // Accepted entry; rollback_accept validates request and state
                // while holding the registry lock.  If it cannot prove the
                // entry is untouched, inhibit redispatch conservatively.
                let original = error.to_string();
                if let Err(rollback_error) = self
                    .inner
                    .registry
                    .rollback_accept(&request.key, &request.request)
                    .map(|_| ())
                    .map_err(registry_error)
                {
                    let _ = self.inner.registry.mark_restart_uncertain(&request.key);
                    return Err(JobRuntimeError::Journal(format!(
                        "{original}; registry acceptance rollback failed: {rollback_error}"
                    )));
                }
                return Err(error);
            }
        };
        let unjournaled = matches!(journal_begin, OperationBegin::Unjournaled);
        match journal_begin {
            OperationBegin::ExistingTerminal(_) => {
                // `registry.begin` may have created a fresh Accepted entry
                // while a retained journal already contained this terminal
                // operation (for example after an in-memory registry was
                // reconstructed from a partial snapshot).  Reconcile that
                // untouched entry before returning; otherwise a later retry
                // would observe a redispatchable Accepted state even though
                // the durable truth is terminal.
                if let Err(rollback_error) = self
                    .inner
                    .registry
                    .rollback_accept(&request.key, &request.request)
                    .map(|_| ())
                    .map_err(registry_error)
                {
                    let _ = self.inner.registry.mark_restart_uncertain(&request.key);
                    return Err(JobRuntimeError::Journal(format!(
                        "durable terminal exists but registry reconciliation failed: {rollback_error}"
                    )));
                }
                return Ok(JobStartResult {
                    disposition: StartDisposition::ExistingTerminal,
                    snapshot: None,
                    replay_status: self.replay_status(false)?,
                });
            }
            OperationBegin::ExistingAccepted { .. } => {
                let snapshot = self
                    .inner
                    .registry
                    .mark_restart_uncertain(&request.key)
                    .map_err(registry_error)?;
                return Ok(JobStartResult {
                    disposition: StartDisposition::UnknownAfterRestart,
                    snapshot: Some(snapshot),
                    replay_status: ReplayStatus::UnknownAfterRestart,
                });
            }
            OperationBegin::Unjournaled if !self.inner.config.allow_unjournaled_effects => {
                // The journal may have degraded between the status check and
                // begin_operation.  Its in-memory accepted marker is retained
                // only as a conservative restart barrier; do not leave a
                // redispatchable Accepted registry state behind.
                let _ = self.inner.registry.mark_restart_uncertain(&request.key);
                let _ = self.note_journal_degraded_for_job(
                    &request.key,
                    self.journal_error()?.unwrap_or_else(|| {
                        "job journal is unavailable and unjournaled effects are disabled"
                            .to_string()
                    }),
                );
                return Err(JobRuntimeError::Journal(
                    "job journal is unavailable and unjournaled effects are disabled".to_string(),
                ));
            }
            OperationBegin::New => {}
            OperationBegin::Unjournaled => {
                // Memory-only/degraded mode is an explicit, caller-selected
                // best-effort path.  Preserve that policy while exposing a
                // resident degradation event for inspection; this event is
                // intentionally not written to the unavailable journal.
                let reason = self.journal_degradation_reason()?;
                self.note_journal_degraded_for_job(&request.key, reason)?;
                // A configured journal that disappeared between the status
                // preflight and `begin_operation` is not equivalent to the
                // deliberate memory-only development mode.  Keep the
                // accepted registry marker as an explicit restart barrier and
                // never dispatch a new effect from that race, even when the
                // unsafe opt-in is enabled.
                if matches!(
                    self.inner.journal.status()?,
                    JournalStatus::Unavailable { .. }
                ) {
                    let snapshot = self
                        .inner
                        .registry
                        .mark_restart_uncertain(&request.key)
                        .map_err(registry_error)?;
                    return Ok(JobStartResult {
                        disposition: StartDisposition::UnknownAfterRestart,
                        snapshot: Some(snapshot),
                        replay_status: ReplayStatus::UnknownAfterRestart,
                    });
                }
            }
        }

        let admission_permit = admission_permit.ok_or_else(|| {
            JobRuntimeError::Registry(
                "new job registry entry was created without an admission permit".to_string(),
            )
        })?;

        let generation = match self
            .inner
            .registry
            .claim_spawn(&request.key, &request.request.request_sha256)
        {
            Err(registry_failure) => {
                let error = registry_error(registry_failure);
                // A claim failure occurs before fork.  Resolve the durable
                // acceptance to a non-effectful terminal fact and inhibit any
                // later redispatch rather than leaving an Accepted entry that
                // can be mistaken for an admission still in progress.
                if let Err(journal_error) = self.inner.journal.complete_operation(
                    &request.key,
                    &request.request,
                    &request.operation_id,
                    "start",
                    &operation_sha256,
                    json!({
                        "status": "spawn_failed",
                        "error": error.to_string(),
                        "effect_attempted": false,
                        "effect_may_have_started": false,
                        "automatic_redispatch": false
                    }),
                ) {
                    let _ =
                        self.note_journal_failure_for_job(&request.key, journal_error.to_string());
                }
                let _ = self.inner.registry.mark_restart_uncertain(&request.key);
                return Err(error);
            }
            Ok(SpawnClaim::Granted { generation, .. }) => generation,
            Ok(SpawnClaim::Existing(snapshot)) => {
                return Ok(JobStartResult {
                    disposition: StartDisposition::ExistingLive,
                    snapshot: Some(snapshot),
                    replay_status: self.replay_status(false)?,
                });
            }
            Ok(SpawnClaim::Inhibited(snapshot)) => {
                return Ok(JobStartResult {
                    disposition: StartDisposition::UnknownAfterRestart,
                    snapshot: Some(snapshot),
                    replay_status: ReplayStatus::UnknownAfterRestart,
                });
            }
        };

        let spawned = match spawn_process(&request, self.inner.config.max_output_chunk_bytes) {
            Ok(spawned) => spawned,
            Err(error) => {
                let effect_may_have_started = matches!(&error, JobRuntimeError::SpawnAfterFork(_));
                if let Err(journal_error) = self.inner.journal.complete_operation(
                    &request.key,
                    &request.request,
                    &request.operation_id,
                    "start",
                    &operation_sha256,
                    json!({
                        "status": if effect_may_have_started {
                            "started_then_internal_failure"
                        } else {
                            "spawn_failed"
                        },
                        "error": error.to_string(),
                        "effect_attempted": effect_may_have_started,
                        "effect_may_have_started": effect_may_have_started,
                        "automatic_redispatch": false
                    }),
                ) {
                    let _ =
                        self.note_journal_failure_for_job(&request.key, journal_error.to_string());
                }
                let _ = self.inner.registry.mark_restart_uncertain(&request.key);
                return Err(error);
            }
        };
        let control = Arc::clone(&spawned.control);
        if let Err(error) = self
            .inner
            .registry
            .record_started(&request.key, generation, control.pid, control.pty)
            .map_err(registry_error)
        {
            // record_started failed after the child was spawned. The admission
            // permit is dropped when this start path returns.
            let cleanup_error = control
                .kill(libc::SIGKILL)
                .err()
                .map(|value| value.to_string());
            if let Err(journal_error) = self.inner.journal.complete_operation(
                &request.key,
                &request.request,
                &request.operation_id,
                "start",
                &operation_sha256,
                json!({
                    "status": "started_then_internal_failure",
                    "error": error.to_string(),
                    "cleanup_error": cleanup_error,
                    "effect_may_have_started": true,
                    "pid": control.pid,
                    "process_group": control.process_group,
                    "session_id": control.session_id,
                    "start_time_ticks": control.start_time_ticks,
                    "boot_id_sha256": control.boot_id_sha256,
                    "process_group_id": i32::try_from(control.process_group).ok(),
                    "process_session_id": i32::try_from(control.session_id).ok(),
                    "boot_id": control.boot_id_sha256.as_ref(),
                    "process_start_time_ticks": control.start_time_ticks,
                    "automatic_redispatch": false
                }),
            ) {
                let _ = self.note_journal_failure_for_job(&request.key, journal_error.to_string());
            }
            let _ = self.inner.registry.mark_restart_uncertain(&request.key);
            return Err(error);
        }
        let running = Arc::new(RunningJob {
            control,
            request: request.request.clone(),
            generation,
            _admission_permit: admission_permit,
            startup: Arc::new(StartupGate::new()),
            lifecycle: Mutex::new(()),
            stdout_bytes: Mutex::new(0),
            stderr_bytes: Mutex::new(0),
        });

        // Publish the control entry before lifecycle events or dispatcher
        // creation. A fast child may exit immediately; inserting first lets
        // its terminal path remove an entry that is already visible.
        self.running()?
            .insert(request.key.clone(), Arc::clone(&running));

        // Publish the kernel-observed identity before announcing `started`.
        // This event is the immutable process-generation binding that a
        // reconnecting observer can use to distinguish a recycled PID/PGID.
        // Keep the admission guard held through both observations and the
        // durable start completion; no live-control lookup may race ahead of
        // those facts.
        let identity = match process_identity_for_event(&running.control) {
            Ok(identity) => identity,
            Err(error) => {
                self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
                return Err(error);
            }
        };
        let identity_bound = RuntimeJobEventKind::ProcessIdentityBound {
            generation,
            identity: identity.clone(),
        };
        if let Err(error) = self.push_runtime_event(&request.key, &request.request, identity_bound)
        {
            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
            return Err(error);
        }

        let started = RuntimeJobEventKind::Started {
            generation,
            pid: running.control.pid,
            pty: running.control.pty,
        };
        if let Err(error) = self.push_runtime_event(&request.key, &request.request, started) {
            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
            return Err(error);
        }
        if let Err(error) = self.inner.journal.complete_operation(
            &request.key,
            &request.request,
            &request.operation_id,
            "start",
            &operation_sha256,
            json!({
                "status": "started",
                "generation": generation,
                "pid": running.control.pid,
                "process_group": running.control.process_group,
                "session_id": running.control.session_id,
                "start_time_ticks": running.control.start_time_ticks,
                "boot_id_sha256": running.control.boot_id_sha256,
                // Canonical names used by the public identity observation.
                // Keep the historical fields above for journal readers that
                // predate the identity-bound event.
                "process_group_id": identity.process_group_id,
                "process_session_id": identity.session_id,
                "boot_id": &identity.boot_id,
                "process_start_time_ticks": identity.start_time_ticks,
                "pty": running.control.pty,
                "automatic_redispatch": false
            }),
        ) {
            let _ = self.note_journal_failure_for_job(&request.key, error.to_string());
            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
            return Err(error);
        }

        if let Err(error) = self.spawn_dispatcher(
            request.key.clone(),
            request.request.clone(),
            generation,
            Arc::clone(&running),
            spawned.events,
        ) {
            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
            return Err(error);
        }
        // Only now are identity/started observations, the durable start
        // terminal, and the dispatcher all in place.  Controls that found the
        // early running-map entry are released together after this point.
        if let Err(error) = running.startup.ready() {
            self.abort_started_job(&request, &operation_sha256, &running, &error.to_string());
            return Err(error);
        }
        Ok(JobStartResult {
            disposition: StartDisposition::Started,
            snapshot: self.inner.registry.snapshot(&request.key).ok(),
            replay_status: self.replay_status(unjournaled)?,
        })
    }

    pub fn write(
        &self,
        key: &JobKey,
        operation_id: &str,
        bytes: &[u8],
    ) -> Result<ControlDisposition> {
        if bytes.is_empty() || bytes.len() > self.inner.config.max_input_bytes {
            return Err(JobRuntimeError::InvalidRequest(
                "job input is empty or exceeds its bound".to_string(),
            ));
        }
        let running = self.running_job(key)?;
        let _lifecycle_guard = running
            .lifecycle
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        self.ensure_running_generation(key, &running)?;
        let digest = control_sha256(
            "write",
            key,
            &json!({
                "encoding": "raw-bytes",
                "sha256": sha256_hex(bytes),
                "byte_count": bytes.len()
            }),
        )?;
        if let Some(disposition) = self.begin_control(
            key,
            &running.request,
            operation_id,
            "write",
            &digest,
            json!({
                "byte_count": bytes.len(),
                "sha256": sha256_hex(bytes)
            }),
        )? {
            return Ok(disposition);
        }
        if let Err(error) = running.control.write(bytes) {
            return Err(self.resolve_control_failure(
                key,
                &running.request,
                operation_id,
                "write",
                &digest,
                "process_input",
                error,
                true,
                true,
            ));
        }
        if let Err(error) = self
            .inner
            .registry
            .record_input(key, bytes.len() as u64, sha256_hex(bytes))
            .map_err(registry_error)
        {
            return Err(self.resolve_control_failure(
                key,
                &running.request,
                operation_id,
                "write",
                &digest,
                "registry_input",
                error,
                true,
                true,
            ));
        }
        self.complete_control(
            key,
            &running.request,
            operation_id,
            "write",
            &digest,
            json!({"status": "written", "byte_count": bytes.len()}),
        )?;
        Ok(ControlDisposition::Applied)
    }

    pub fn resize(
        &self,
        key: &JobKey,
        operation_id: &str,
        size: PtySize,
    ) -> Result<ControlDisposition> {
        if size.rows == 0 || size.cols == 0 {
            return Err(JobRuntimeError::InvalidRequest(
                "PTY rows and cols must be non-zero".to_string(),
            ));
        }
        let running = self.running_job(key)?;
        let _lifecycle_guard = running
            .lifecycle
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        self.ensure_running_generation(key, &running)?;
        let details = json!({"rows": size.rows, "cols": size.cols});
        let digest = control_sha256("resize", key, &details)?;
        if let Some(disposition) = self.begin_control(
            key,
            &running.request,
            operation_id,
            "resize",
            &digest,
            details.clone(),
        )? {
            return Ok(disposition);
        }
        if let Err(error) = running.control.resize(size) {
            return Err(self.resolve_control_failure(
                key,
                &running.request,
                operation_id,
                "resize",
                &digest,
                "process_resize",
                error,
                true,
                true,
            ));
        }
        if let Err(error) = self
            .inner
            .registry
            .record_resize(key, size.rows, size.cols)
            .map_err(registry_error)
        {
            return Err(self.resolve_control_failure(
                key,
                &running.request,
                operation_id,
                "resize",
                &digest,
                "registry_resize",
                error,
                true,
                true,
            ));
        }
        self.complete_control(
            key,
            &running.request,
            operation_id,
            "resize",
            &digest,
            json!({"status": "resized", "rows": size.rows, "cols": size.cols}),
        )?;
        Ok(ControlDisposition::Applied)
    }

    pub fn close_stdin(&self, key: &JobKey, operation_id: &str) -> Result<ControlDisposition> {
        let running = self.running_job(key)?;
        let _lifecycle_guard = running
            .lifecycle
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        self.ensure_running_generation(key, &running)?;
        let details = json!({
            "mode": if running.control.pty {
                "pty_eot"
            } else {
                "pipe_close"
            }
        });
        let digest = control_sha256("close_stdin", key, &details)?;
        if let Some(disposition) = self.begin_control(
            key,
            &running.request,
            operation_id,
            "close_stdin",
            &digest,
            details,
        )? {
            return Ok(disposition);
        }
        let effect = match running.control.close_stdin() {
            Ok(effect) => effect,
            Err(error) => {
                return Err(self.resolve_control_failure(
                    key,
                    &running.request,
                    operation_id,
                    "close_stdin",
                    &digest,
                    "process_close_stdin",
                    error,
                    true,
                    true,
                ));
            }
        };
        if effect == StdinCloseEffect::PipeClosed
            && let Err(error) = self.inner.registry.close_stdin(key).map_err(registry_error)
        {
            return Err(self.resolve_control_failure(
                key,
                &running.request,
                operation_id,
                "close_stdin",
                &digest,
                "registry_close_stdin",
                error,
                true,
                true,
            ));
        }
        let (status, stdin_closed) = match effect {
            StdinCloseEffect::AlreadyClosed => ("already_applied", !running.control.pty),
            StdinCloseEffect::PipeClosed => ("pipe_stdin_closed", true),
            StdinCloseEffect::PtyEofCharacterSent => ("pty_eof_character_sent", false),
        };
        self.complete_control(
            key,
            &running.request,
            operation_id,
            "close_stdin",
            &digest,
            json!({
                "status": status,
                "stdin_closed": stdin_closed,
                "pty": running.control.pty
            }),
        )?;
        Ok(ControlDisposition::Applied)
    }

    pub fn kill(
        &self,
        key: &JobKey,
        operation_id: &str,
        signal: i32,
    ) -> Result<ControlDisposition> {
        if !(1..=128).contains(&signal) {
            return Err(JobRuntimeError::InvalidRequest(
                "kill signal is outside the supported range".to_string(),
            ));
        }
        let running = self.running_job(key)?;
        let _lifecycle_guard = running
            .lifecycle
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        self.ensure_running_generation(key, &running)?;
        let details = json!({"signal": signal});
        let digest = control_sha256("kill", key, &details)?;
        if let Some(disposition) = self.begin_control(
            key,
            &running.request,
            operation_id,
            "kill",
            &digest,
            details,
        )? {
            return Ok(disposition);
        }
        if let Err(error) = self
            .inner
            .registry
            .request_kill(key, signal)
            .map_err(registry_error)
        {
            return Err(self.resolve_control_failure(
                key,
                &running.request,
                operation_id,
                "kill",
                &digest,
                "registry_kill_request",
                error,
                false,
                false,
            ));
        }
        if let Err(error) = running.control.kill(signal) {
            return Err(self.resolve_control_failure(
                key,
                &running.request,
                operation_id,
                "kill",
                &digest,
                "process_group_signal",
                error,
                true,
                true,
            ));
        }
        self.complete_control(
            key,
            &running.request,
            operation_id,
            "kill",
            &digest,
            json!({"status": "signal_sent", "signal": signal}),
        )?;
        Ok(ControlDisposition::Applied)
    }

    pub fn attach(
        &self,
        key: &JobKey,
        attachment_id: &str,
        inclusive_cursor: u64,
        limit: usize,
    ) -> Result<JobInspection> {
        self.inner
            .registry
            .attach(key, attachment_id)
            .map_err(registry_error)?;
        self.inspect(key, inclusive_cursor, limit)
    }

    pub fn detach(&self, key: &JobKey, attachment_id: &str) -> Result<()> {
        self.inner
            .registry
            .detach(key, attachment_id)
            .map_err(registry_error)?;
        Ok(())
    }

    pub fn inspect(
        &self,
        key: &JobKey,
        inclusive_cursor: u64,
        limit: usize,
    ) -> Result<JobInspection> {
        if limit == 0 || limit > self.inner.config.max_observations_per_job {
            return Err(JobRuntimeError::InvalidRequest(
                "job inspect limit is outside the configured bound".to_string(),
            ));
        }
        let snapshot = self.inner.registry.snapshot(key).ok();
        let registry_events = match &snapshot {
            Some(_) => self
                .inner
                .registry
                .history_from(key, 0)
                .map_err(registry_error)?,
            None => Vec::<JobEvent>::new(),
        };
        // Copy the bounded resident window out before consulting the journal.
        // Journal failure reporting takes the durability lock and then the
        // observation lock; releasing this guard avoids a lock-order cycle
        // with an asynchronous dispatcher that is publishing a degradation
        // event at the same time.
        let (total, oldest_available_cursor, gap, events, next_cursor) = {
            let observations = self.observations()?;
            let state = observations.get(key);
            let total = state.map_or(0, |state| state.next_seq);
            if inclusive_cursor > total {
                return Err(JobRuntimeError::InvalidRequest(format!(
                    "inclusive cursor {inclusive_cursor} is after next cursor {total}"
                )));
            }
            let oldest_available_cursor = state
                .and_then(|state| state.events.front())
                .map_or(total, |event| event.seq);
            let gap = (inclusive_cursor < oldest_available_cursor).then_some(JobObservationGap {
                first_missing_cursor: inclusive_cursor,
                last_missing_cursor: oldest_available_cursor.saturating_sub(1),
            });
            let events = state
                .map(|state| {
                    state
                        .events
                        .iter()
                        .filter(|event| event.seq >= inclusive_cursor)
                        .take(limit)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let next_cursor = match events.last() {
                Some(event) => event.seq.checked_add(1).ok_or_else(|| {
                    JobRuntimeError::Journal("runtime observation sequence exhausted".to_string())
                })?,
                None => inclusive_cursor.max(oldest_available_cursor),
            };
            (total, oldest_available_cursor, gap, events, next_cursor)
        };
        let recovered = self.inner.journal.recovered_job(key)?;
        let replay_status =
            if snapshot.is_none() && recovered.as_ref().is_some_and(|job| job.terminal.is_none()) {
                ReplayStatus::UnknownAfterRestart
            } else {
                self.replay_status(false)?
            };
        let event_log_status = self.event_log_status()?;
        let journal_error = self.journal_error()?;
        let durable_fallback_available = matches!(event_log_status, EventLogStatus::Durable);
        Ok(JobInspection {
            snapshot,
            registry_events,
            runtime_events: events,
            inclusive_cursor,
            oldest_available_cursor,
            next_cursor,
            total_events: total,
            has_more: next_cursor < total,
            resync_required: gap.is_some(),
            gap,
            durable_fallback_available,
            event_log_status,
            journal_error,
            replay_status,
        })
    }

    pub fn durable_records(&self, key: &JobKey) -> Result<Vec<Value>> {
        self.inner.journal.inspect_records(key)
    }

    /// Return job-scoped durable journal records with event-store metadata.
    ///
    /// The compatibility [`Self::durable_records`] method intentionally
    /// exposes only envelope payloads.  Host inspection/reconnect paths should
    /// use this metadata-preserving view so scope, event identity and the
    /// per-job durable cursor remain auditable on the wire.
    pub fn durable_records_with_metadata(&self, key: &JobKey) -> Result<Vec<Value>> {
        self.inner.journal.inspect_records_with_metadata(key)
    }

    fn begin_control(
        &self,
        key: &JobKey,
        request: &JobRequest,
        operation_id: &str,
        operation_kind: &str,
        digest: &str,
        details: Value,
    ) -> Result<Option<ControlDisposition>> {
        validate_operation_id(operation_id, self.inner.config.max_operation_id_bytes)?;
        if let Some(error) = self.durability_error()?
            && !self.inner.config.allow_unjournaled_effects
        {
            let message = format!(
                "job runtime durability is degraded; effectful control is inhibited: {error}"
            );
            self.note_journal_degraded_for_job(key, message.clone())?;
            return Err(JobRuntimeError::Journal(message));
        }
        // Do the same fail-closed preflight as `start`.  Without this check a
        // configured-but-unavailable journal would insert an in-memory
        // accepted control and then return an error, leaving an accepted
        // operation with no terminal record.
        let journal_status = self.inner.journal.status()?;
        if !self.inner.config.allow_unjournaled_effects
            && !matches!(&journal_status, JournalStatus::Durable)
        {
            let message =
                "job journal is unavailable and unjournaled effects are disabled".to_string();
            self.note_journal_degraded_for_job(key, journal_status_reason(&journal_status))?;
            return Err(JobRuntimeError::Journal(message));
        }
        let begin = match self.inner.journal.begin_operation(
            key,
            request,
            operation_id,
            operation_kind,
            digest,
            details,
        ) {
            Ok(begin) => begin,
            Err(error) => {
                self.note_journal_failure_for_job(key, error.to_string())?;
                return Err(error);
            }
        };
        Ok(match begin {
            OperationBegin::New => None,
            OperationBegin::ExistingTerminal(_) => Some(ControlDisposition::Existing),
            OperationBegin::ExistingAccepted {
                restart_uncertain: true,
            } => Some(ControlDisposition::UnknownAfterRestart),
            OperationBegin::ExistingAccepted {
                restart_uncertain: false,
            } => Some(ControlDisposition::Existing),
            OperationBegin::Unjournaled if self.inner.config.allow_unjournaled_effects => {
                self.note_journal_degraded_for_job(key, self.journal_degradation_reason()?)?;
                None
            }
            OperationBegin::Unjournaled => {
                let message =
                    "job journal is unavailable and unjournaled effects are disabled".to_string();
                self.note_journal_degraded_for_job(key, message.clone())?;
                // The journal can disappear between the status preflight and
                // `begin_operation`.  That call may have retained an
                // in-memory accepted marker; attempt to close it with an
                // explicit no-effect terminal before returning the error.
                let failure = JobRuntimeError::Journal(message);
                return Err(self.resolve_control_failure(
                    key,
                    request,
                    operation_id,
                    operation_kind,
                    digest,
                    "journal_preflight_race",
                    failure,
                    false,
                    false,
                ));
            }
        })
    }

    fn complete_control(
        &self,
        key: &JobKey,
        request: &JobRequest,
        operation_id: &str,
        operation_kind: &str,
        digest: &str,
        result: Value,
    ) -> Result<()> {
        match self.inner.journal.complete_operation(
            key,
            request,
            operation_id,
            operation_kind,
            digest,
            result,
        ) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.note_journal_failure_for_job(key, error.to_string())?;
                // The effect already crossed durable acceptance and may have
                // happened, but its terminal record could not be committed.
                // Inhibit any later control dispatch from treating the live
                // registry snapshot as fully converged.
                let _ = self.inner.registry.mark_restart_uncertain(key);
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_control_failure(
        &self,
        key: &JobKey,
        request: &JobRequest,
        operation_id: &str,
        operation_kind: &str,
        digest: &str,
        phase: &str,
        error: JobRuntimeError,
        effect_attempted: bool,
        effect_may_have_started: bool,
    ) -> JobRuntimeError {
        let original = error.to_string();
        let terminal = json!({
            "status": "control_failed",
            "phase": phase,
            "error": original,
            "effect_attempted": effect_attempted,
            "effect_may_have_started": effect_may_have_started,
            "automatic_redispatch": false
        });
        match self.complete_control(key, request, operation_id, operation_kind, digest, terminal) {
            Ok(()) => error,
            Err(terminal_error) => JobRuntimeError::Journal(format!(
                "{original}; operation terminal could not be persisted: {terminal_error}"
            )),
        }
    }

    fn running_job(&self, key: &JobKey) -> Result<Arc<RunningJob>> {
        let running = self
            .running()?
            .get(key)
            .cloned()
            .ok_or(JobRuntimeError::NotLive)?;
        // Do not hold the running-map mutex while waiting: the dispatcher may
        // need it to remove a child that exits during startup.
        running.startup.wait()?;
        Ok(running)
    }

    /// Recheck the registry while holding the per-job lifecycle mutex.  The
    /// dispatcher takes the same mutex before committing a terminal state, so
    /// a control that passed the startup gate cannot perform a process effect
    /// after that terminal transition wins the race.
    fn ensure_running_generation(&self, key: &JobKey, running: &RunningJob) -> Result<()> {
        let snapshot = self.inner.registry.snapshot(key).map_err(registry_error)?;
        match snapshot.state {
            JobEffectiveState::Running { generation, .. } if generation == running.generation => {
                Ok(())
            }
            JobEffectiveState::UnknownAfterRestart { .. } => {
                Err(JobRuntimeError::UnknownAfterRestart)
            }
            _ => Err(JobRuntimeError::NotLive),
        }
    }

    fn abort_started_job(
        &self,
        request: &JobStartRequest,
        operation_sha256: &str,
        running: &Arc<RunningJob>,
        failure: &str,
    ) {
        // Wake any controls that captured the early running-map entry before
        // removing it.  They must fail closed rather than race a process that
        // is being torn down or a start operation whose terminal could not be
        // committed.
        let _ = running.startup.fail(failure.to_string());
        let cleanup_error = running
            .control
            .kill(libc::SIGKILL)
            .err()
            .map(|error| error.to_string());
        if let Ok(mut jobs) = self.running() {
            jobs.remove(&request.key);
        }
        if let Err(error) = self.inner.journal.complete_operation(
            &request.key,
            &request.request,
            &request.operation_id,
            "start",
            operation_sha256,
            json!({
                "status": "started_then_internal_failure",
                "error": failure,
                "cleanup_error": cleanup_error,
                "effect_may_have_started": true,
                "pid": running.control.pid,
                "process_group": running.control.process_group,
                "session_id": running.control.session_id,
                "start_time_ticks": running.control.start_time_ticks,
                "boot_id_sha256": running.control.boot_id_sha256,
                "process_group_id": i32::try_from(running.control.process_group).ok(),
                "process_session_id": i32::try_from(running.control.session_id).ok(),
                "boot_id": running.control.boot_id_sha256.as_ref(),
                "process_start_time_ticks": running.control.start_time_ticks,
                "automatic_redispatch": false
            }),
        ) {
            let _ = self.note_journal_failure_for_job(&request.key, error.to_string());
        }
        let _ = self.inner.registry.mark_restart_uncertain(&request.key);
    }

    fn spawn_dispatcher(
        &self,
        key: JobKey,
        request: JobRequest,
        generation: u64,
        running: Arc<RunningJob>,
        receiver: std::sync::mpsc::Receiver<InternalProcessEvent>,
    ) -> Result<()> {
        let manager = self.clone();
        thread::Builder::new()
            .name(format!("owner-open-job-dispatch-{}", key.job_id))
            .spawn(move || {
                // A registry output failure can be caused by a stale
                // generation, a terminal transition, or a poisoned/missing
                // entry.  Report it once and stop the effect, but keep
                // draining until `Exited` so the reaper can close the
                // terminal lifecycle and release the owned child marker.
                let mut registry_output_failure_reported = false;
                while let Ok(event) = receiver.recv() {
                    match event {
                        InternalProcessEvent::Output { stream, bytes } => {
                            let digest = sha256_hex(&bytes);
                            let output_seq = match manager.inner.registry.record_output(
                                &key,
                                generation,
                                stream.clone(),
                                bytes.len() as u64,
                                digest.clone(),
                            ) {
                                Ok(seq) => seq,
                                Err(error) => {
                                    if !registry_output_failure_reported {
                                        registry_output_failure_reported = true;
                                        let registry_error = error.to_string();
                                        let uncertainty_error = manager
                                            .inner
                                            .registry
                                            .mark_restart_uncertain(&key)
                                            .err()
                                            .map(|error| error.to_string());
                                        let kill_error = running
                                            .control
                                            .kill(libc::SIGKILL)
                                            .err()
                                            .map(|error| error.to_string());
                                        let mut diagnostic = format!(
                                            "output observation rejected: {registry_error}; stream={stream}; bytes={}; sha256={digest}",
                                            bytes.len()
                                        );
                                        if let Some(error) = uncertainty_error {
                                            diagnostic.push_str(&format!(
                                                "; registry uncertainty marker failed: {error}"
                                            ));
                                        }
                                        if let Some(error) = kill_error {
                                            diagnostic.push_str(&format!(
                                                "; process-group termination failed: {error}"
                                            ));
                                        }
                                        let diagnostic = bound_journal_error(diagnostic);
                                        let _ = manager.push_runtime_event(
                                            &key,
                                            &request,
                                            RuntimeJobEventKind::ProcessFault {
                                                phase: "registry_output".to_string(),
                                                error: diagnostic,
                                            },
                                        );
                                    }
                                    continue;
                                }
                            };
                            if let Ok(mut counter) = if stream == "stderr" {
                                running.stderr_bytes.lock()
                            } else {
                                running.stdout_bytes.lock()
                            } {
                                *counter = counter.saturating_add(bytes.len() as u64);
                            }
                            if let Err(error) = manager.push_runtime_event(
                                &key,
                                &request,
                                RuntimeJobEventKind::Output {
                                    generation,
                                    output_seq,
                                    stream,
                                    bytes,
                                    sha256: digest,
                                },
                            ) {
                                let _ =
                                    manager.note_journal_failure_for_job(&key, error.to_string());
                                if !manager.inner.config.allow_unjournaled_effects {
                                    let _ = running.control.kill(libc::SIGKILL);
                                }
                            }
                        }
                        InternalProcessEvent::InputFailed { error } => {
                            let _ = manager.push_runtime_event(
                                &key,
                                &request,
                                RuntimeJobEventKind::ProcessFault {
                                    phase: "initial_stdin".to_string(),
                                    error,
                                },
                            );
                            let _ = running.control.kill(libc::SIGKILL);
                        }
                        InternalProcessEvent::ReaderFailed { stream, error } => {
                            let _ = manager.push_runtime_event(
                                &key,
                                &request,
                                RuntimeJobEventKind::ProcessFault {
                                    phase: format!("{stream}_reader"),
                                    error,
                                },
                            );
                            let _ = running.control.kill(libc::SIGKILL);
                        }
                        InternalProcessEvent::Exited {
                            terminal_kind,
                            exit_code,
                            signal,
                            cleanup_error,
                        } => {
                            // The child may exit before the start caller
                            // returns from dispatcher creation.  Close the
                            // pending startup gate first so a control that
                            // captured the early running-map entry cannot be
                            // released against a terminal process.
                            if running.startup.terminal().is_err() {
                                // A poisoned startup gate means a waiter may
                                // no longer have a trustworthy view of the
                                // process lifecycle.  Preserve the explicit
                                // unknown state instead of publishing a
                                // terminal result that could authorize a
                                // follow-up control.
                                let diagnostic =
                                    "job startup gate was poisoned during terminal handling";
                                let _ = manager.inner.registry.mark_restart_uncertain(&key);
                                let _ = manager.push_runtime_event(
                                    &key,
                                    &request,
                                    RuntimeJobEventKind::ProcessFault {
                                        phase: "startup_gate_terminal".to_string(),
                                        error: diagnostic.to_string(),
                                    },
                                );
                                if let Ok(mut jobs) = manager.running() {
                                    jobs.remove(&key);
                                }
                                return;
                            }
                            // Serialize terminal publication with every
                            // effectful control.  A control that already owns
                            // this lock completes (or durably fails) before
                            // the registry becomes terminal; a later control
                            // rechecks the generation and is rejected before
                            // touching the process.
                            let _lifecycle_guard = match running.lifecycle.lock() {
                                Ok(guard) => guard,
                                Err(_) => {
                                    // Never silently continue without the
                                    // per-job lifecycle barrier.  A poisoned
                                    // mutex means we cannot prove that a
                                    // control did not overlap terminal
                                    // publication, so keep the job explicitly
                                    // uncertain and inhibit future effects.
                                    let diagnostic =
                                        "job lifecycle lock was poisoned during terminal handling";
                                    let _ = manager.inner.registry.mark_restart_uncertain(&key);
                                    let _ = manager.push_runtime_event(
                                        &key,
                                        &request,
                                        RuntimeJobEventKind::ProcessFault {
                                            phase: "lifecycle_lock".to_string(),
                                            error: diagnostic.to_string(),
                                        },
                                    );
                                    if let Ok(mut jobs) = manager.running() {
                                        jobs.remove(&key);
                                    }
                                    return;
                                }
                            };
                            if let Some(error) = cleanup_error {
                                let _ = manager.push_runtime_event(
                                    &key,
                                    &request,
                                    RuntimeJobEventKind::ProcessFault {
                                        phase: "process_group_cleanup".to_string(),
                                        error,
                                    },
                                );
                            }
                            let stdout_bytes = match running.stdout_bytes.lock() {
                                Ok(value) => *value,
                                Err(_) => {
                                    // A poisoned counter cannot be replaced
                                    // with zero: doing so would turn an
                                    // incomplete output observation into a
                                    // false terminal fact.  Keep the registry
                                    // in the explicit unknown state and leave
                                    // a bounded diagnostic for reconciliation.
                                    let diagnostic =
                                        "stdout byte counter was poisoned during terminal handling";
                                    let _ = manager.inner.registry.mark_restart_uncertain(&key);
                                    let _ = manager.push_runtime_event(
                                        &key,
                                        &request,
                                        RuntimeJobEventKind::ProcessFault {
                                            phase: "stdout_counter".to_string(),
                                            error: diagnostic.to_string(),
                                        },
                                    );
                                    if let Ok(mut jobs) = manager.running() {
                                        jobs.remove(&key);
                                    }
                                    return;
                                }
                            };
                            let stderr_bytes = match running.stderr_bytes.lock() {
                                Ok(value) => *value,
                                Err(_) => {
                                    let diagnostic =
                                        "stderr byte counter was poisoned during terminal handling";
                                    let _ = manager.inner.registry.mark_restart_uncertain(&key);
                                    let _ = manager.push_runtime_event(
                                        &key,
                                        &request,
                                        RuntimeJobEventKind::ProcessFault {
                                            phase: "stderr_counter".to_string(),
                                            error: diagnostic.to_string(),
                                        },
                                    );
                                    if let Ok(mut jobs) = manager.running() {
                                        jobs.remove(&key);
                                    }
                                    return;
                                }
                            };
                            let observation_sha256 = terminal_digest(
                                &key,
                                generation,
                                &terminal_kind,
                                exit_code,
                                signal,
                                stdout_bytes,
                                stderr_bytes,
                            );
                            let terminal = JobTerminal {
                                terminal_kind: terminal_kind.clone(),
                                exit_code,
                                signal,
                                observation_sha256: observation_sha256.clone(),
                                stdout_bytes,
                                stderr_bytes,
                            };
                            let event = RuntimeJobEventKind::Terminal {
                                generation,
                                terminal_kind,
                                exit_code,
                                signal,
                                observation_sha256,
                                stdout_bytes,
                                stderr_bytes,
                            };
                            // The reaper has already waited for the leader and
                            // joined every output worker.  Commit the registry
                            // terminal state and release the in-process
                            // admission slot before publishing the terminal
                            // observation.  A consumer may return from
                            // `inspect` as soon as that observation is visible;
                            // keeping the old RunningJob until after the
                            // observation creates a race where an otherwise
                            // free capacity slot is rejected for one turn.
                            if let Err(error) =
                                manager.inner.registry.complete(&key, generation, terminal)
                            {
                                // A registry commit failure is not a journal
                                // failure.  Preserve the distinction in the
                                // observable state and inhibit redispatch;
                                // otherwise a registry fault would falsely
                                // advertise an event-store outage.
                                let error_text = error.to_string();
                                let _ = manager.inner.registry.mark_restart_uncertain(&key);
                                let _ = manager.push_runtime_event(
                                    &key,
                                    &request,
                                    RuntimeJobEventKind::ProcessFault {
                                        phase: "registry_terminal".to_string(),
                                        error: error_text,
                                    },
                                );
                            }
                            // `push_runtime_event` retains the terminal observation and attempts
                            // the observation/`job.terminal` append.  If persistence fails, it
                            // publishes an explicit in-memory degradation marker; do not write the
                            // same terminal again after publication because that redundant call
                            // keeps the exclusive writer lease alive after a consumer can observe
                            // completion and makes an immediate in-process manager handoff
                            // spuriously fail closed.
                            if let Err(error) = manager.push_runtime_event(&key, &request, event) {
                                let _ =
                                    manager.note_journal_failure_for_job(&key, error.to_string());
                            }
                            // Keep the owned process marker until the durable
                            // terminal record has been attempted.  The
                            // registry is already terminal above, so admission
                            // capacity is free; the marker only prevents the
                            // Host loop from exiting in the small interval
                            // between publishing the terminal observation and
                            // recording `job.terminal`.
                            if let Ok(mut jobs) = manager.running() {
                                jobs.remove(&key);
                            }
                            // Process truth remains terminal even when the
                            // observation journal append failed. Replay status
                            // will remain degraded and no new durable-required
                            // effect is authorized from that missing record.
                            return;
                        }
                    }
                }

                // A process event channel is expected to close only after
                // the reaper has published `Exited`.  If every sender drops
                // without that terminal event, treating the clean receive
                // error as normal would leak the RunningJob entry (and its
                // admission permit) indefinitely while leaving the registry
                // looking live.  Fail closed: make the lifecycle explicitly
                // uncertain, terminate the still-owned process group, expose
                // a bounded diagnostic, and release the running marker.  The
                // normal `Exited` arm returns before reaching this path, so a
                // terminal observation is never duplicated.
                let diagnostic = "process event channel closed before exited";
                let _ = running.startup.fail(diagnostic);
                let kill_error = running
                    .control
                    .kill(libc::SIGKILL)
                    .err()
                    .map(|error| error.to_string());
                let mut diagnostic = diagnostic.to_string();
                if let Some(error) = kill_error {
                    diagnostic.push_str("; process-group termination failed: ");
                    diagnostic.push_str(&error);
                }
                let _ = manager.inner.registry.mark_restart_uncertain(&key);
                let diagnostic = bound_journal_error(diagnostic);
                if let Err(error) = manager.push_runtime_event(
                    &key,
                    &request,
                    RuntimeJobEventKind::ProcessFault {
                        phase: "dispatcher_channel_closed".to_string(),
                        error: diagnostic,
                    },
                ) {
                    let _ = manager.note_journal_failure_for_job(&key, error.to_string());
                }
                if let Ok(mut jobs) = manager.running() {
                    jobs.remove(&key);
                }
            })
            .map(|_| ())
            .map_err(|error| {
                JobRuntimeError::Io(format!(
                    "failed to spawn owner-open job dispatcher: {error}"
                ))
            })
    }

    fn push_runtime_event(
        &self,
        key: &JobKey,
        request: &JobRequest,
        kind: RuntimeJobEventKind,
    ) -> Result<u64> {
        // Reserve and retain the resident event before touching the journal.
        // This keeps the inspection cursor monotonic even when the append
        // fails, and (critically) lets the failure path publish a synthetic
        // in-memory degradation event without holding the observation lock.
        let (seq, event, payload) = {
            let mut observations = self.observations()?;
            let state = observations.entry(key.clone()).or_default();
            let seq = state.next_seq;
            // Observation cursors are persisted/replayed semantic ordering,
            // not a bounded resource counter.  Wrapping would make a new
            // event indistinguishable from an old one and invalidate gap
            // detection.  Reserve the successor before retaining or writing
            // anything so exhaustion fails closed without a phantom event.
            let next_seq = seq.checked_add(1).ok_or_else(|| {
                JobRuntimeError::Journal("runtime observation sequence exhausted".to_string())
            })?;
            state.next_seq = next_seq;
            let event = RuntimeJobEvent {
                seq,
                job_id: key.job_id.clone(),
                event: kind,
            };
            let payload = serde_json::to_value(&event)
                .map_err(|error| JobRuntimeError::Journal(error.to_string()))?;
            retain_runtime_event(
                state,
                event.clone(),
                self.inner.config.max_observations_per_job,
                self.inner.config.max_observation_bytes_per_job,
            );
            (seq, event, payload)
        };
        let journal_result = self.inner.journal.append_observation(
            key,
            request,
            seq,
            runtime_event_kind(&event),
            payload,
        );
        if let Err(error) = journal_result {
            let error_text = error.to_string();
            let note_result = self.note_journal_failure_for_job(key, error_text.clone());
            if !self.inner.config.allow_unjournaled_effects {
                return match note_result {
                    Ok(()) => Err(error),
                    Err(note_error) => Err(JobRuntimeError::Journal(format!(
                        "{error_text}; failed to expose journal degradation: {note_error}"
                    ))),
                };
            }
            note_result?;
        }
        Ok(seq)
    }

    fn note_journal_failure(&self, error: String) -> Result<()> {
        let mut state = self
            .inner
            .durability_error
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        state.get_or_insert(bound_journal_error(error));
        Ok(())
    }

    /// Retain a resident, non-durable marker that explains why this job's
    /// event stream cannot currently be replayed.  The marker is emitted at
    /// most once per key and is deliberately never sent back through the
    /// failed journal.
    fn note_journal_degraded_for_job(&self, key: &JobKey, error: String) -> Result<()> {
        let mut observations = self.observations()?;
        let state = observations.entry(key.clone()).or_default();
        if state.journal_unavailable_emitted {
            return Ok(());
        }
        let seq = state.next_seq;
        let next_seq = seq.checked_add(1).ok_or_else(|| {
            JobRuntimeError::Journal("runtime observation sequence exhausted".to_string())
        })?;
        state.journal_unavailable_emitted = true;
        state.next_seq = next_seq;
        retain_runtime_event(
            state,
            RuntimeJobEvent {
                seq,
                job_id: key.job_id.clone(),
                event: RuntimeJobEventKind::JournalUnavailable {
                    error: Some(bound_journal_error(error)),
                },
            },
            self.inner.config.max_observations_per_job,
            self.inner.config.max_observation_bytes_per_job,
        );
        Ok(())
    }

    fn note_journal_failure_for_job(&self, key: &JobKey, error: String) -> Result<()> {
        self.note_journal_failure(error)?;
        let reason = self
            .durability_error()?
            .unwrap_or_else(|| "job journal is unavailable".to_string());
        self.note_journal_degraded_for_job(key, reason)
    }

    fn journal_degradation_reason(&self) -> Result<String> {
        if let Some(error) = self.durability_error()? {
            return Ok(error);
        }
        Ok(journal_status_reason(&self.inner.journal.status()?))
    }

    fn event_log_status(&self) -> Result<EventLogStatus> {
        if self.durability_error()?.is_some() {
            return Ok(EventLogStatus::Unavailable);
        }
        Ok(match self.inner.journal.status()? {
            JournalStatus::Durable => EventLogStatus::Durable,
            JournalStatus::BestEffortMemoryOnly => EventLogStatus::BestEffortUnreplayable,
            JournalStatus::Unavailable { .. } => EventLogStatus::Unavailable,
        })
    }

    fn journal_error(&self) -> Result<Option<String>> {
        if let Some(error) = self.durability_error()? {
            return Ok(Some(error));
        }
        Ok(match self.inner.journal.status()? {
            JournalStatus::Unavailable { error } => Some(bound_journal_error(error)),
            JournalStatus::Durable | JournalStatus::BestEffortMemoryOnly => None,
        })
    }

    fn durability_error(&self) -> Result<Option<String>> {
        self.inner
            .durability_error
            .lock()
            .map(|value| value.clone())
            .map_err(|_| JobRuntimeError::StatePoisoned)
    }

    fn replay_status(&self, unjournaled: bool) -> Result<ReplayStatus> {
        if unjournaled || self.durability_error()?.is_some() {
            return Ok(ReplayStatus::BestEffortUnreplayable);
        }
        Ok(match self.inner.journal.status()? {
            JournalStatus::Durable => ReplayStatus::Durable,
            JournalStatus::BestEffortMemoryOnly | JournalStatus::Unavailable { .. } => {
                ReplayStatus::BestEffortUnreplayable
            }
        })
    }

    fn running(&self) -> Result<MutexGuard<'_, HashMap<JobKey, Arc<RunningJob>>>> {
        self.inner
            .running
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)
    }

    fn start_shard_index(&self, key: &JobKey) -> usize {
        // Keep the admission serialization lane stable across process
        // restarts.  `DefaultHasher` is an implementation detail of the
        // standard library and is not a persistence/benchmark contract; a
        // deterministic, length-delimited FNV layout makes a key's lane
        // reproducible while retaining the fixed shard topology.
        stable_start_shard_index(key, self.inner.start_shards.len())
    }

    fn start_guard(&self, key: &JobKey) -> Result<MutexGuard<'_, ()>> {
        self.inner.start_shards[self.start_shard_index(key)]
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)
    }

    /// Returns true while a locally owned child is live or its terminal
    /// observation is still being committed.  The latter state is deliberately
    /// kept separate from registry admission capacity: a terminal registry
    /// entry no longer consumes a job slot, but the Host must not exit before
    /// the durable terminal record is attempted.
    pub fn has_live_or_pending_jobs(&self) -> bool {
        self.running().map(|jobs| !jobs.is_empty()).unwrap_or(true)
    }

    fn observations(&self) -> Result<MutexGuard<'_, HashMap<JobKey, ObservationState>>> {
        self.inner
            .observations
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)
    }
}

fn stable_start_shard_index(key: &JobKey, shard_count: usize) -> usize {
    debug_assert!(shard_count > 0);
    fn feed(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    fn feed_len(hash: &mut u64, length: usize) {
        feed(hash, &(length as u64).to_be_bytes());
    }

    let fields = [
        key.scope.session_id.as_str(),
        key.scope.profile_id.as_str(),
        key.scope.task_id.as_str(),
        key.scope.turn_id.as_str(),
        key.scope.turn_stream_id.as_str(),
        key.job_id.as_str(),
    ];
    let mut hash = FNV_OFFSET_BASIS;
    feed(&mut hash, &[START_SHARD_HASH_VERSION]);
    feed_len(&mut hash, shard_count);
    feed_len(&mut hash, START_SHARD_DOMAIN.len());
    feed(&mut hash, START_SHARD_DOMAIN);
    for field in fields {
        feed_len(&mut hash, field.len());
        feed(&mut hash, field.as_bytes());
    }
    (hash % shard_count as u64) as usize
}

fn retain_runtime_event(
    state: &mut ObservationState,
    event: RuntimeJobEvent,
    max_observations: usize,
    max_bytes: usize,
) {
    state.byte_count = state.byte_count.saturating_add(runtime_event_bytes(&event));
    state.events.push_back(event);
    while state.events.len() > max_observations || state.byte_count > max_bytes {
        let Some(removed) = state.events.pop_front() else {
            break;
        };
        state.byte_count = state
            .byte_count
            .saturating_sub(runtime_event_bytes(&removed));
    }
}

const MAX_JOURNAL_ERROR_CHARS: usize = 4096;

fn bound_journal_error(error: String) -> String {
    let mut chars = error.chars();
    let bounded = chars
        .by_ref()
        .take(MAX_JOURNAL_ERROR_CHARS)
        .collect::<String>();
    if chars.next().is_some() {
        format!("{bounded}…")
    } else {
        bounded
    }
}

fn journal_status_reason(status: &JournalStatus) -> String {
    match status {
        JournalStatus::Durable => "job journal is durable".to_string(),
        JournalStatus::BestEffortMemoryOnly => {
            "job journal is memory-only; observations are unreplayable".to_string()
        }
        JournalStatus::Unavailable { error } => error.clone(),
    }
}

fn validate_start_request(request: &JobStartRequest, config: &JobRuntimeConfig) -> Result<()> {
    validate_operation_id(&request.operation_id, config.max_operation_id_bytes)?;
    if request.initial_stdin.len() > config.max_input_bytes {
        return Err(JobRuntimeError::InvalidRequest(
            "initial stdin exceeds its bound".to_string(),
        ));
    }
    Ok(())
}

fn validate_operation_id(value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(JobRuntimeError::InvalidRequest(
            "operation_id is empty, oversized or malformed".to_string(),
        ));
    }
    Ok(())
}

/// Convert the private process-control identity into the stable observation
/// shape exposed by `RuntimeJobEventKind::ProcessIdentityBound`.
///
/// Linux/Android capture all five fields immediately after `spawn`. If a
/// platform cannot provide the start-time or boot tuple, fail closed after
/// fork instead of emitting an identity event that could not protect a later
/// numeric process-group control.
fn process_identity_for_event(control: &ProcessControl) -> Result<ProcessIdentity> {
    let identity = control.identity();
    let process_group_id = i32::try_from(identity.process_group).map_err(|_| {
        JobRuntimeError::Control("child process group does not fit a POSIX identity".to_string())
    })?;
    let session_id = i32::try_from(identity.session_id).map_err(|_| {
        JobRuntimeError::Control("child session does not fit a POSIX identity".to_string())
    })?;
    let start_time_ticks = identity.start_time_ticks.ok_or_else(|| {
        JobRuntimeError::Control("child start-time identity is unavailable".to_string())
    })?;
    let boot_id = identity.boot_id_sha256.ok_or_else(|| {
        JobRuntimeError::Control("child boot identity is unavailable".to_string())
    })?;
    Ok(ProcessIdentity {
        pid: identity.pid,
        process_group_id,
        session_id,
        boot_id,
        start_time_ticks,
    })
}

fn start_details(request: &JobStartRequest) -> Value {
    json!({
        "invocation": &request.invocation,
        "shell_executable": request.shell_executable.to_string_lossy(),
        "cwd": request.cwd.as_ref().map(|path| path.to_string_lossy().to_string()),
        "env": &request.env,
        "initial_stdin_sha256": sha256_hex(&request.initial_stdin),
        "initial_stdin_bytes": request.initial_stdin.len(),
        "pty": request.pty
    })
}

fn start_operation_sha256(request: &JobStartRequest) -> Result<String> {
    control_sha256("start", &request.key, &start_details(request))
}

fn control_sha256(kind: &str, key: &JobKey, details: &Value) -> Result<String> {
    let encoded = serde_json::to_vec(&json!({
        "schema": "trillionnium.owner-open.job-operation.v1",
        "kind": kind,
        "key": key,
        "details": details
    }))
    .map_err(|error| JobRuntimeError::InvalidRequest(error.to_string()))?;
    Ok(sha256_hex(&encoded))
}

fn terminal_digest(
    key: &JobKey,
    generation: u64,
    terminal_kind: &str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout_bytes: u64,
    stderr_bytes: u64,
) -> String {
    let encoded = serde_json::to_vec(&json!({
        "schema": "trillionnium.owner-open.job-terminal.v1",
        "key": key,
        "generation": generation,
        "terminal_kind": terminal_kind,
        "exit_code": exit_code,
        "signal": signal,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes
    }))
    .expect("job terminal digest serialization cannot fail");
    sha256_hex(&encoded)
}

fn runtime_event_kind(event: &RuntimeJobEvent) -> &'static str {
    match &event.event {
        RuntimeJobEventKind::ProcessIdentityBound { .. } => "job.process_identity_bound",
        RuntimeJobEventKind::Started { .. } => "job.started",
        RuntimeJobEventKind::Output { .. } => "job.output",
        RuntimeJobEventKind::Terminal { .. } => "job.terminal.observation",
        RuntimeJobEventKind::ProcessFault { .. } => "job.process_fault",
        RuntimeJobEventKind::JournalUnavailable { .. } => "job.journal_unavailable",
    }
}

fn runtime_event_bytes(event: &RuntimeJobEvent) -> usize {
    match &event.event {
        RuntimeJobEventKind::Output { bytes, .. } => bytes.len(),
        _ => 0,
    }
}

fn registry_error(error: JobRegistryError) -> JobRuntimeError {
    match error {
        JobRegistryError::NotFound => JobRuntimeError::NotFound,
        other => JobRuntimeError::Registry(other.to_string()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use tempfile::tempdir;
    use trillionnium_owner_open_job_registry::{JobKey, JobRequest, JobScope, JobTerminal};

    use super::*;
    use crate::{JobInvocation, JobJournal};

    fn rollback_test_key() -> JobKey {
        JobKey::new(
            JobScope::new("session", "owner-open", "task", "turn", "stream"),
            "job-accept-rollback",
        )
    }

    fn rollback_test_request() -> JobRequest {
        JobRequest::new(
            "a".repeat(64),
            "b".repeat(64),
            "shell.job",
            "pipe",
            Some("rootlinux".to_string()),
        )
    }

    fn stale_start_request(
        key: JobKey,
        request: JobRequest,
        operation_id: &str,
    ) -> JobStartRequest {
        JobStartRequest {
            key,
            request,
            operation_id: operation_id.to_string(),
            invocation: JobInvocation::Command {
                command: ":".to_string(),
            },
            shell_executable: PathBuf::from("/bin/sh"),
            cwd: None,
            env: BTreeMap::new(),
            initial_stdin: Vec::new(),
            pty: None,
        }
    }

    #[test]
    fn durable_acceptance_failure_removes_unclaimed_registry_entry() {
        let directory = tempdir().expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("harden temporary directory");
        let journal_path = directory.path().join("jobs.jsonl");
        let journal = JobJournal::open_best_effort(Some(&journal_path));
        assert!(matches!(journal.status().unwrap(), JournalStatus::Durable));
        journal
            .fail_next_accept_for_test()
            .expect("inject acceptance failure");
        let manager = JobManager::new(JobRuntimeConfig::default(), journal).unwrap();
        let key = rollback_test_key();
        let request = rollback_test_request();
        let error = manager
            .start(JobStartRequest {
                key: key.clone(),
                request,
                operation_id: "start-rollback".to_string(),
                invocation: JobInvocation::Command {
                    command: "exit 0".to_string(),
                },
                shell_executable: PathBuf::from("/bin/sh"),
                cwd: None,
                env: BTreeMap::new(),
                initial_stdin: Vec::new(),
                pty: None,
            })
            .expect_err("injected durable append must fail");
        assert!(
            error
                .to_string()
                .contains("injected durable acceptance append failure")
        );
        assert!(matches!(
            manager.registry().snapshot(&key),
            Err(JobRegistryError::NotFound)
        ));
        assert!(!manager.has_live_or_pending_jobs());
        let inspection = manager.inspect(&key, 0, 16).expect("degraded inspection");
        assert_eq!(inspection.event_log_status, EventLogStatus::Unavailable);
        assert!(
            inspection
                .journal_error
                .as_deref()
                .is_some_and(|error| error.contains("injected durable acceptance append failure"))
        );
        assert!(
            inspection
                .runtime_events
                .iter()
                .any(|event| matches!(event.event, RuntimeJobEventKind::JournalUnavailable { .. }))
        );
    }

    #[test]
    fn stale_accepted_registry_entry_is_fenced_before_existing_mapping() {
        let manager = JobManager::new(
            JobRuntimeConfig::development_unsafe(),
            JobJournal::memory_only(),
        )
        .expect("development manager");
        let key = rollback_test_key();
        let request = rollback_test_request();
        manager
            .registry()
            .begin(key.clone(), request.clone())
            .expect("seed stale accepted registry entry");

        // The registry entry has no matching RunningJob and no journal
        // operation.  Treating BeginDisposition::Existing as ExistingLive
        // would let a caller mistake an unowned Accepted marker for a live
        // effect and would leave claim_spawn redispatchable.
        let result = manager
            .start(stale_start_request(
                key.clone(),
                request.clone(),
                "stale-accepted",
            ))
            .expect("stale state is an explicit unknown result");
        assert_eq!(result.disposition, StartDisposition::UnknownAfterRestart);
        assert_eq!(result.replay_status, ReplayStatus::UnknownAfterRestart);
        assert!(matches!(
            result.snapshot.as_ref().map(|snapshot| &snapshot.state),
            Some(JobEffectiveState::ProvenNotStartedAfterRestart)
        ));
        assert!(matches!(
            manager
                .registry()
                .claim_spawn(&key, &request.request_sha256)
                .expect("fenced registry entry"),
            SpawnClaim::Inhibited(_)
        ));
    }

    #[test]
    fn recovered_accepted_entry_also_fences_same_process_registry_state() {
        let manager = JobManager::new(
            JobRuntimeConfig::development_unsafe(),
            JobJournal::memory_only(),
        )
        .expect("development manager");
        let key = rollback_test_key();
        let request = rollback_test_request();
        manager
            .journal()
            .begin_operation(
                &key,
                &request,
                "recovered-accepted",
                "start",
                &"c".repeat(64),
                json!({"status": "accepted"}),
            )
            .expect("seed recovered accepted operation");
        manager
            .registry()
            .begin(key.clone(), request.clone())
            .expect("seed matching registry entry");

        let result = manager
            .start(stale_start_request(
                key.clone(),
                request.clone(),
                "different-retry",
            ))
            .expect("recovered accepted state is explicit unknown");
        assert_eq!(result.disposition, StartDisposition::UnknownAfterRestart);
        assert_eq!(result.replay_status, ReplayStatus::UnknownAfterRestart);
        assert!(matches!(
            result.snapshot.as_ref().map(|snapshot| &snapshot.state),
            Some(JobEffectiveState::ProvenNotStartedAfterRestart)
        ));
        assert!(matches!(
            manager
                .registry()
                .claim_spawn(&key, &request.request_sha256)
                .expect("recovered entry remains fenced"),
            SpawnClaim::Inhibited(_)
        ));
    }

    #[test]
    fn post_spawn_observation_failure_keeps_effectful_truth_degraded() {
        let directory = tempdir().expect("temporary directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("harden temporary directory");
        let journal_path = directory.path().join("jobs.jsonl");
        let journal = JobJournal::open_best_effort(Some(&journal_path));
        assert!(matches!(journal.status().unwrap(), JournalStatus::Durable));
        journal
            .fail_next_observation_for_test()
            .expect("inject observation failure");
        let manager = JobManager::new(JobRuntimeConfig::default(), journal).unwrap();
        let key = rollback_test_key();
        let error = manager
            .start(JobStartRequest {
                key: key.clone(),
                request: rollback_test_request(),
                operation_id: "start-observation-failure".to_string(),
                invocation: JobInvocation::Command {
                    command: "sleep 30".to_string(),
                },
                shell_executable: PathBuf::from("/bin/sh"),
                cwd: None,
                env: BTreeMap::new(),
                initial_stdin: Vec::new(),
                pty: None,
            })
            .expect_err("injected post-spawn append must fail closed");
        assert!(
            error
                .to_string()
                .contains("injected durable observation append failure")
        );
        assert!(!manager.has_live_or_pending_jobs());
        let snapshot = manager
            .registry()
            .snapshot(&key)
            .expect("conservative registry marker");
        assert!(matches!(
            snapshot.state,
            JobEffectiveState::UnknownAfterRestart { .. }
        ));
        let inspection = manager.inspect(&key, 0, 16).expect("degraded inspection");
        assert_eq!(inspection.event_log_status, EventLogStatus::Unavailable);
        assert!(
            inspection
                .runtime_events
                .iter()
                .any(|event| matches!(event.event, RuntimeJobEventKind::JournalUnavailable { .. }))
        );
    }

    #[test]
    fn explicit_memory_only_mode_reports_unreplayable_inspection() {
        let manager = JobManager::new(
            JobRuntimeConfig::development_unsafe(),
            JobJournal::memory_only(),
        )
        .expect("memory-only manager");
        let key = rollback_test_key();
        let result = manager
            .start(JobStartRequest {
                key: key.clone(),
                request: rollback_test_request(),
                operation_id: "start-memory-only".to_string(),
                invocation: JobInvocation::Command {
                    command: "sleep 0.1".to_string(),
                },
                shell_executable: PathBuf::from("/bin/sh"),
                cwd: None,
                env: BTreeMap::new(),
                initial_stdin: Vec::new(),
                pty: None,
            })
            .expect("explicit unsafe mode may dispatch");
        assert_eq!(result.disposition, StartDisposition::Started);
        assert_eq!(result.replay_status, ReplayStatus::BestEffortUnreplayable);
        let inspection = manager.inspect(&key, 0, 16).expect("degraded inspection");
        assert_eq!(
            inspection.event_log_status,
            EventLogStatus::BestEffortUnreplayable
        );
        assert!(inspection.journal_error.is_none());
        assert!(
            inspection
                .runtime_events
                .iter()
                .any(|event| matches!(event.event, RuntimeJobEventKind::JournalUnavailable { .. }))
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while manager.has_live_or_pending_jobs() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!manager.has_live_or_pending_jobs());
    }

    #[test]
    fn control_rechecks_terminal_generation_before_process_effect() {
        let directory = tempdir().expect("temporary directory");
        let marker = directory.path().join("post-terminal-write");
        let manager = JobManager::new(
            JobRuntimeConfig::development_unsafe(),
            JobJournal::memory_only(),
        )
        .expect("memory-only manager");
        let key = rollback_test_key();
        manager
            .start(JobStartRequest {
                key: key.clone(),
                request: rollback_test_request(),
                operation_id: "start-terminal-race".to_string(),
                invocation: JobInvocation::Command {
                    command: format!("IFS= read -r _ && touch '{}' ; sleep 30", marker.display()),
                },
                shell_executable: PathBuf::from("/bin/sh"),
                cwd: None,
                env: BTreeMap::new(),
                initial_stdin: Vec::new(),
                pty: None,
            })
            .expect("start live job");
        let running = manager
            .running()
            .expect("running map")
            .get(&key)
            .cloned()
            .expect("live running job");
        manager
            .registry()
            .complete(
                &key,
                running.generation,
                JobTerminal {
                    terminal_kind: "exit".to_string(),
                    exit_code: Some(0),
                    signal: None,
                    observation_sha256: "c".repeat(64),
                    stdout_bytes: 0,
                    stderr_bytes: 0,
                },
            )
            .expect("simulate terminal transition winning lifecycle race");

        assert!(matches!(
            manager.write(&key, "write-after-terminal", b"must-not-cross\n"),
            Err(JobRuntimeError::NotLive)
        ));
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(!marker.exists(), "post-terminal bytes reached the child");

        let _ = running.control.kill(libc::SIGKILL);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while manager.has_live_or_pending_jobs() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(!manager.has_live_or_pending_jobs());
    }

    #[test]
    fn runtime_observation_sequence_exhaustion_fails_closed_without_a_phantom_event() {
        let manager = JobManager::new(
            JobRuntimeConfig::development_unsafe(),
            JobJournal::memory_only(),
        )
        .expect("memory-only manager");
        let key = rollback_test_key();
        let request = rollback_test_request();
        {
            let mut observations = manager.observations().expect("observations lock");
            let state = observations.entry(key.clone()).or_default();
            state.next_seq = u64::MAX;
        }

        let error = manager
            .push_runtime_event(
                &key,
                &request,
                RuntimeJobEventKind::ProcessFault {
                    phase: "test".to_string(),
                    error: "sequence probe".to_string(),
                },
            )
            .expect_err("MAX cursor cannot be incremented");
        assert!(matches!(
            error,
            JobRuntimeError::Journal(message)
                if message == "runtime observation sequence exhausted"
        ));
        let observations = manager.observations().expect("observations lock");
        let state = observations.get(&key).expect("observation state");
        assert_eq!(state.next_seq, u64::MAX);
        assert!(state.events.is_empty());
    }

    #[test]
    fn degradation_marker_does_not_consume_an_exhausted_observation_cursor() {
        let manager = JobManager::new(
            JobRuntimeConfig::development_unsafe(),
            JobJournal::memory_only(),
        )
        .expect("memory-only manager");
        let key = rollback_test_key();
        {
            let mut observations = manager.observations().expect("observations lock");
            let state = observations.entry(key.clone()).or_default();
            state.next_seq = u64::MAX;
        }

        let error = manager
            .note_journal_degraded_for_job(&key, "sequence probe".to_string())
            .expect_err("MAX cursor cannot be incremented");
        assert!(matches!(
            error,
            JobRuntimeError::Journal(message)
                if message == "runtime observation sequence exhausted"
        ));
        let observations = manager.observations().expect("observations lock");
        let state = observations.get(&key).expect("observation state");
        assert_eq!(state.next_seq, u64::MAX);
        assert!(!state.journal_unavailable_emitted);
        assert!(state.events.is_empty());
    }
}

#[cfg(test)]
mod concurrency_tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use trillionnium_owner_open_job_registry::{JobKey, JobScope};

    use super::{AdmissionPool, JobManager, JobRuntimeConfig, StartupGate};

    fn key(job_id: &str) -> JobKey {
        JobKey::new(
            JobScope::new("session", "profile", "task", "turn", "stream"),
            job_id,
        )
    }

    #[test]
    fn admission_permit_releases_capacity_on_every_drop_path() {
        let pool = std::sync::Arc::new(AdmissionPool::new(1));
        let first = pool.try_acquire().expect("first permit");
        assert!(pool.try_acquire().is_err());
        drop(first);
        let second = pool.try_acquire().expect("capacity released");
        drop(second);
    }

    #[test]
    fn unrelated_start_shards_can_progress_concurrently() {
        let manager = JobManager::open(JobRuntimeConfig::development_unsafe(), None)
            .expect("development manager");
        let blocked = key("blocked");
        let blocked_index = manager.start_shard_index(&blocked);
        let independent = (0..10_000)
            .map(|index| key(&format!("independent-{index}")))
            .find(|candidate| manager.start_shard_index(candidate) != blocked_index)
            .expect("an independent shard");

        let guard = manager.start_guard(&blocked).expect("blocked shard guard");
        let clone = manager.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _independent_guard = clone
                .start_guard(&independent)
                .expect("independent shard guard");
            sender.send(()).expect("signal independent progress");
        });

        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("independent shard must not wait for unrelated key");
        drop(guard);
        worker.join().expect("start shard worker");
    }

    #[test]
    fn startup_gate_blocks_controls_until_ready_and_wakes_all_waiters() {
        let gate = std::sync::Arc::new(StartupGate::new());
        let (sender, receiver) = mpsc::sync_channel(2);
        let first_gate = std::sync::Arc::clone(&gate);
        let first = std::thread::spawn(move || {
            first_gate.wait().expect("startup gate opens");
            sender.send(()).expect("first waiter signal");
        });
        let second_gate = std::sync::Arc::clone(&gate);
        let (second_sender, second_receiver) = mpsc::sync_channel(1);
        let second = std::thread::spawn(move || {
            second_gate.wait().expect("startup gate opens");
            second_sender.send(()).expect("second waiter signal");
        });

        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        assert!(
            second_receiver
                .recv_timeout(Duration::from_millis(50))
                .is_err()
        );
        gate.ready().expect("mark startup ready");
        receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("first waiter wakes");
        second_receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("second waiter wakes");
        first.join().expect("first waiter exits");
        second.join().expect("second waiter exits");
    }

    #[test]
    fn startup_gate_failure_wakes_waiters_fail_closed() {
        let gate = std::sync::Arc::new(StartupGate::new());
        let waiter_gate = std::sync::Arc::clone(&gate);
        let waiter = std::thread::spawn(move || waiter_gate.wait());
        gate.fail("identity binding failed")
            .expect("mark startup failed");
        let error = waiter
            .join()
            .expect("waiter exits")
            .expect_err("failed startup cannot authorize controls");
        assert!(
            matches!(error, super::JobRuntimeError::Io(message) if message.contains("identity binding failed"))
        );
    }

    #[test]
    fn terminal_startup_gate_cannot_be_reopened_by_late_ready() {
        let gate = StartupGate::new();
        gate.terminal().expect("mark terminal");
        gate.ready().expect("late ready is a harmless no-op");
        assert!(matches!(gate.wait(), Err(super::JobRuntimeError::NotLive)));
    }
}
