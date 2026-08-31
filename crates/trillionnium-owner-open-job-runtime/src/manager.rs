use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
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
    ControlDisposition, InternalProcessEvent, JobInspection, JobJournal, JobObservationGap,
    JobRuntimeConfig, JobRuntimeError, JobStartRequest, JobStartResult, PtySize, ReplayStatus,
    Result, RuntimeJobEvent, RuntimeJobEventKind, StartDisposition,
};

struct RunningJob {
    control: Arc<ProcessControl>,
    request: JobRequest,
    stdout_bytes: Mutex<u64>,
    stderr_bytes: Mutex<u64>,
}

#[derive(Default)]
struct ObservationState {
    events: VecDeque<RuntimeJobEvent>,
    next_seq: u64,
    byte_count: usize,
}

struct Inner {
    config: JobRuntimeConfig,
    registry: Arc<JobRegistry>,
    journal: Arc<JobJournal>,
    running: Mutex<HashMap<JobKey, Arc<RunningJob>>>,
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
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                registry: Arc::new(JobRegistry::default()),
                journal: Arc::new(journal),
                running: Mutex::new(HashMap::new()),
                observations: Mutex::new(HashMap::new()),
                durability_error: Mutex::new(None),
            }),
        })
    }

    pub fn open(config: JobRuntimeConfig, journal_path: Option<&Path>) -> Result<Self> {
        Self::new(config, JobJournal::open_best_effort(journal_path))
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
        // Hold the running-map lock across the capacity check, registry begin,
        // spawn and insertion.  A new key must be rejected before
        // `registry.begin`, otherwise a full runtime leaves an Accepted entry
        // that falsely occupies the key and prevents a later retry.
        let mut running_jobs = self.running()?;
        if let Some(running) = running_jobs.get(&request.key) {
            if running.request != request.request {
                return Err(JobRuntimeError::JobConflict);
            }
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
            return Ok(JobStartResult {
                disposition: if recovered.terminal.is_some() {
                    StartDisposition::ExistingTerminal
                } else {
                    StartDisposition::UnknownAfterRestart
                },
                snapshot: None,
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
        let active_running_jobs = running_jobs
            .keys()
            .filter(|key| {
                self.inner
                    .registry
                    .snapshot(key)
                    .map(|snapshot| {
                        matches!(
                            snapshot.state,
                            JobEffectiveState::Accepted
                                | JobEffectiveState::Starting { .. }
                                | JobEffectiveState::Running { .. }
                        )
                    })
                    // A registry read failure is conservatively counted as
                    // occupied.  Admission must not turn an uncertain state
                    // into an additional child process.
                    .unwrap_or(true)
            })
            .count();
        if !registry_entry_exists && active_running_jobs >= self.inner.config.max_jobs {
            return Err(JobRuntimeError::InvalidRequest(
                "job runtime capacity is exhausted before acceptance".to_string(),
            ));
        }

        // Fail closed before the registry accepts the job.  An unavailable or
        // deliberately memory-only journal must not leave an Accepted entry
        // behind when production policy rejects unjournaled effects.
        let journal_status = self.inner.journal.status()?;
        if !self.inner.config.allow_unjournaled_effects
            && !matches!(&journal_status, JournalStatus::Durable)
        {
            return Err(JobRuntimeError::Journal(
                "job journal is unavailable and unjournaled effects are disabled".to_string(),
            ));
        }

        let begin = self
            .inner
            .registry
            .begin(request.key.clone(), request.request.clone())
            .map_err(registry_error)?;
        if begin.disposition == BeginDisposition::Existing {
            return Ok(JobStartResult {
                disposition: match &begin.snapshot.state {
                    JobEffectiveState::Terminal { .. } => StartDisposition::ExistingTerminal,
                    JobEffectiveState::UnknownAfterRestart { .. }
                    | JobEffectiveState::ProvenNotStartedAfterRestart => {
                        StartDisposition::UnknownAfterRestart
                    }
                    _ => StartDisposition::ExistingLive,
                },
                snapshot: Some(begin.snapshot),
                replay_status: self.replay_status(false)?,
            });
        }
        if matches!(&journal_status, JournalStatus::Unavailable { .. }) {
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

        let operation_sha256 = start_operation_sha256(&request)?;
        let journal_begin = self.inner.journal.begin_operation(
            &request.key,
            &request.request,
            &request.operation_id,
            "start",
            &operation_sha256,
            start_details(&request),
        )?;
        let unjournaled = matches!(journal_begin, OperationBegin::Unjournaled);
        match journal_begin {
            OperationBegin::ExistingTerminal(_) => {
                return Ok(JobStartResult {
                    disposition: StartDisposition::ExistingTerminal,
                    snapshot: Some(begin.snapshot),
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
                return Err(JobRuntimeError::Journal(
                    "job journal is unavailable and unjournaled effects are disabled".to_string(),
                ));
            }
            OperationBegin::New | OperationBegin::Unjournaled => {}
        }

        let generation = match self
            .inner
            .registry
            .claim_spawn(&request.key, &request.request.request_sha256)
            .map_err(registry_error)?
        {
            SpawnClaim::Granted { generation, .. } => generation,
            SpawnClaim::Existing(snapshot) => {
                return Ok(JobStartResult {
                    disposition: StartDisposition::ExistingLive,
                    snapshot: Some(snapshot),
                    replay_status: self.replay_status(false)?,
                });
            }
            SpawnClaim::Inhibited(snapshot) => {
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
                        "automatic_redispatch": false
                    }),
                ) {
                    let _ = self.note_journal_failure(journal_error.to_string());
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
            // record_started failed after the child was spawned. Release the
            // admission reservation before the rollback path tries to remove
            // the running entry; otherwise abort_started_job would attempt to
            // lock this same mutex and deadlock forever.
            drop(running_jobs);
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
                    "automatic_redispatch": false
                }),
            ) {
                let _ = self.note_journal_failure(journal_error.to_string());
            }
            let _ = self.inner.registry.mark_restart_uncertain(&request.key);
            return Err(error);
        }
        let running = Arc::new(RunningJob {
            control,
            request: request.request.clone(),
            stdout_bytes: Mutex::new(0),
            stderr_bytes: Mutex::new(0),
        });
        running_jobs.insert(request.key.clone(), Arc::clone(&running));
        drop(running_jobs);

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
                "pty": running.control.pty,
                "automatic_redispatch": false
            }),
        ) {
            let _ = self.note_journal_failure(error.to_string());
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
        running.control.write(bytes)?;
        self.inner
            .registry
            .record_input(key, bytes.len() as u64, sha256_hex(bytes))
            .map_err(registry_error)?;
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
        running.control.resize(size)?;
        self.inner
            .registry
            .record_resize(key, size.rows, size.cols)
            .map_err(registry_error)?;
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
        let effect = running.control.close_stdin()?;
        if effect == StdinCloseEffect::PipeClosed {
            self.inner
                .registry
                .close_stdin(key)
                .map_err(registry_error)?;
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
        self.inner
            .registry
            .request_kill(key, signal)
            .map_err(registry_error)?;
        running.control.kill(signal)?;
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
        let next_cursor = events
            .last()
            .map_or(inclusive_cursor.max(oldest_available_cursor), |event| {
                event.seq.saturating_add(1)
            });
        let recovered = self.inner.journal.recovered_job(key)?;
        let replay_status =
            if snapshot.is_none() && recovered.as_ref().is_some_and(|job| job.terminal.is_none()) {
                ReplayStatus::UnknownAfterRestart
            } else {
                self.replay_status(false)?
            };
        let durable_fallback_available =
            matches!(self.inner.journal.status()?, JournalStatus::Durable)
                && self.durability_error()?.is_none();
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
            replay_status,
        })
    }

    pub fn durable_records(&self, key: &JobKey) -> Result<Vec<Value>> {
        self.inner.journal.inspect_records(key)
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
            return Err(JobRuntimeError::Journal(format!(
                "job runtime durability is degraded; effectful control is inhibited: {error}"
            )));
        }
        Ok(
            match self.inner.journal.begin_operation(
                key,
                request,
                operation_id,
                operation_kind,
                digest,
                details,
            )? {
                OperationBegin::New => None,
                OperationBegin::ExistingTerminal(_) => Some(ControlDisposition::Existing),
                OperationBegin::ExistingAccepted {
                    restart_uncertain: true,
                } => Some(ControlDisposition::UnknownAfterRestart),
                OperationBegin::ExistingAccepted {
                    restart_uncertain: false,
                } => Some(ControlDisposition::Existing),
                OperationBegin::Unjournaled if self.inner.config.allow_unjournaled_effects => None,
                OperationBegin::Unjournaled => {
                    return Err(JobRuntimeError::Journal(
                        "job journal is unavailable and unjournaled effects are disabled"
                            .to_string(),
                    ));
                }
            },
        )
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
                self.note_journal_failure(error.to_string())?;
                Err(error)
            }
        }
    }

    fn running_job(&self, key: &JobKey) -> Result<Arc<RunningJob>> {
        self.running()?
            .get(key)
            .cloned()
            .ok_or(JobRuntimeError::NotLive)
    }

    fn abort_started_job(
        &self,
        request: &JobStartRequest,
        operation_sha256: &str,
        running: &Arc<RunningJob>,
        failure: &str,
    ) {
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
                "automatic_redispatch": false
            }),
        ) {
            let _ = self.note_journal_failure(error.to_string());
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
                                Err(_) => continue,
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
                                let _ = manager.note_journal_failure(error.to_string());
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
                            let stdout_bytes =
                                running.stdout_bytes.lock().map(|value| *value).unwrap_or(0);
                            let stderr_bytes =
                                running.stderr_bytes.lock().map(|value| *value).unwrap_or(0);
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
                                let _ = manager.note_journal_failure(error.to_string());
                            }
                            // `push_runtime_event` appends the terminal observation and
                            // the canonical `job.terminal` record under one journal lock before
                            // exposing the in-memory terminal event. Do not write the same terminal
                            // again after publication: that redundant call keeps the exclusive
                            // writer lease alive after a consumer can observe completion and makes
                            // an immediate in-process manager handoff spuriously fail closed.
                            if let Err(error) = manager.push_runtime_event(&key, &request, event) {
                                let _ = manager.note_journal_failure(error.to_string());
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
        let mut observations = self.observations()?;
        let state = observations.entry(key.clone()).or_default();
        let seq = state.next_seq;
        state.next_seq = state.next_seq.saturating_add(1);
        let event = RuntimeJobEvent {
            seq,
            job_id: key.job_id.clone(),
            event: kind,
        };
        let payload = serde_json::to_value(&event)
            .map_err(|error| JobRuntimeError::Journal(error.to_string()))?;
        let journal_result = self.inner.journal.append_observation(
            key,
            request,
            seq,
            runtime_event_kind(&event),
            payload,
        );
        let bytes = runtime_event_bytes(&event);
        state.byte_count = state.byte_count.saturating_add(bytes);
        state.events.push_back(event);
        while state.events.len() > self.inner.config.max_observations_per_job
            || state.byte_count > self.inner.config.max_observation_bytes_per_job
        {
            let Some(removed) = state.events.pop_front() else {
                break;
            };
            state.byte_count = state
                .byte_count
                .saturating_sub(runtime_event_bytes(&removed));
        }
        if let Err(error) = journal_result {
            self.note_journal_failure(error.to_string())?;
            if !self.inner.config.allow_unjournaled_effects {
                return Err(error);
            }
        }
        Ok(seq)
    }

    fn note_journal_failure(&self, error: String) -> Result<()> {
        let mut state = self
            .inner
            .durability_error
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        state.get_or_insert(error);
        Ok(())
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
