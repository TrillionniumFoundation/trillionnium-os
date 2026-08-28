use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard};

use crate::validate::{invalid, require_id, require_sha256, require_text, validate_terminal};
use crate::{
    BeginDisposition, BeginResult, JobEffectiveState, JobEvent, JobEventKind, JobKey,
    JobRegistryError, JobRegistryLimits, JobRequest, JobSnapshot, JobTerminal,
    MutationOutcome, Result, SpawnClaim,
};

#[derive(Debug, Clone)]
enum DispatchState {
    Accepted { spawn_inhibited: bool },
    Claimed { generation: u64, restart_uncertain: bool },
    Running {
        generation: u64,
        pid: u32,
        pty: bool,
        restart_uncertain: bool,
    },
    Terminal { generation: u64, terminal: JobTerminal },
}

#[derive(Debug, Clone)]
struct Entry {
    key: JobKey,
    request: JobRequest,
    dispatch: DispatchState,
    stdin_closed: bool,
    kill_requested: bool,
    attachments: HashSet<String>,
    next_output_seq: u64,
    history: VecDeque<JobEvent>,
    next_event_seq: u64,
}

impl Entry {
    fn state(&self) -> JobEffectiveState {
        match &self.dispatch {
            DispatchState::Accepted { spawn_inhibited: false } => JobEffectiveState::Accepted,
            DispatchState::Accepted { spawn_inhibited: true } => {
                JobEffectiveState::ProvenNotStartedAfterRestart
            }
            DispatchState::Claimed { generation, restart_uncertain: false } => {
                JobEffectiveState::Starting { generation: *generation }
            }
            DispatchState::Claimed { generation, restart_uncertain: true } => {
                JobEffectiveState::UnknownAfterRestart {
                    generation: *generation,
                    pid: None,
                    pty: None,
                }
            }
            DispatchState::Running {
                generation,
                pid,
                pty,
                restart_uncertain: false,
            } => JobEffectiveState::Running {
                generation: *generation,
                pid: *pid,
                pty: *pty,
            },
            DispatchState::Running {
                generation,
                pid,
                pty,
                restart_uncertain: true,
            } => JobEffectiveState::UnknownAfterRestart {
                generation: *generation,
                pid: Some(*pid),
                pty: Some(*pty),
            },
            DispatchState::Terminal { generation, terminal } => JobEffectiveState::Terminal {
                generation: *generation,
                terminal: terminal.clone(),
            },
        }
    }

    fn snapshot(&self) -> JobSnapshot {
        let mut attachments = self.attachments.iter().cloned().collect::<Vec<_>>();
        attachments.sort();
        JobSnapshot {
            key: self.key.clone(),
            request: self.request.clone(),
            state: self.state(),
            stdin_closed: self.stdin_closed,
            kill_requested: self.kill_requested,
            attachments,
            next_output_seq: self.next_output_seq,
            earliest_history_seq: self
                .history
                .front()
                .map_or(self.next_event_seq, |event| event.seq),
            next_event_seq: self.next_event_seq,
        }
    }

    fn push(&mut self, event: JobEventKind, limit: usize) {
        self.history.push_back(JobEvent {
            seq: self.next_event_seq,
            event,
        });
        self.next_event_seq = self.next_event_seq.saturating_add(1);
        if self.history.len() > limit {
            self.history.pop_front();
        }
    }
}

#[derive(Debug)]
struct State {
    entries: HashMap<JobKey, Entry>,
    next_spawn_generation: u64,
}

#[derive(Debug)]
pub struct JobRegistry {
    limits: JobRegistryLimits,
    state: Mutex<State>,
}

impl JobRegistry {
    pub fn new(limits: JobRegistryLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            state: Mutex::new(State {
                entries: HashMap::new(),
                next_spawn_generation: 1,
            }),
        })
    }

    pub fn begin(&self, key: JobKey, request: JobRequest) -> Result<BeginResult> {
        self.validate_key(&key)?;
        self.validate_request(&request)?;
        let mut state = self.lock()?;
        if let Some(entry) = state.entries.get(&key) {
            if entry.request != request {
                return Err(JobRegistryError::JobIdConflict);
            }
            return Ok(BeginResult {
                disposition: BeginDisposition::Existing,
                snapshot: entry.snapshot(),
            });
        }
        if state.entries.len() >= self.limits.max_entries {
            return Err(JobRegistryError::CapacityExhausted);
        }
        let mut entry = Entry {
            key: key.clone(),
            request,
            dispatch: DispatchState::Accepted {
                spawn_inhibited: false,
            },
            stdin_closed: false,
            kill_requested: false,
            attachments: HashSet::new(),
            next_output_seq: 0,
            history: VecDeque::new(),
            next_event_seq: 0,
        };
        entry.push(JobEventKind::Accepted, self.limits.max_history_per_job);
        let snapshot = entry.snapshot();
        state.entries.insert(key, entry);
        Ok(BeginResult {
            disposition: BeginDisposition::New,
            snapshot,
        })
    }

    pub fn claim_spawn(&self, key: &JobKey, request_sha256: &str) -> Result<SpawnClaim> {
        require_sha256(request_sha256, "request_sha256")?;
        let mut state = self.lock()?;
        let entry = state.entries.get(key).ok_or(JobRegistryError::NotFound)?;
        if entry.request.request_sha256 != request_sha256 {
            return Err(JobRegistryError::RequestDigestMismatch);
        }
        match &entry.dispatch {
            DispatchState::Accepted { spawn_inhibited: true } => {
                return Ok(SpawnClaim::Inhibited(entry.snapshot()));
            }
            DispatchState::Claimed { .. }
            | DispatchState::Running { .. }
            | DispatchState::Terminal { .. } => {
                return Ok(SpawnClaim::Existing(entry.snapshot()));
            }
            DispatchState::Accepted { spawn_inhibited: false } => {}
        }
        let generation = state.next_spawn_generation;
        if generation == 0 || generation == u64::MAX {
            return Err(JobRegistryError::GenerationExhausted);
        }
        state.next_spawn_generation += 1;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        entry.dispatch = DispatchState::Claimed {
            generation,
            restart_uncertain: false,
        };
        entry.push(
            JobEventKind::SpawnClaimed { generation },
            self.limits.max_history_per_job,
        );
        Ok(SpawnClaim::Granted {
            generation,
            snapshot: entry.snapshot(),
        })
    }

    pub fn record_started(
        &self,
        key: &JobKey,
        generation: u64,
        pid: u32,
        pty: bool,
    ) -> Result<MutationOutcome> {
        if pid == 0 {
            return Err(invalid("pid must be non-zero"));
        }
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        match &entry.dispatch {
            DispatchState::Claimed {
                generation: expected,
                restart_uncertain: false,
            } if *expected == generation => {}
            DispatchState::Running {
                generation: expected,
                pid: existing_pid,
                pty: existing_pty,
                ..
            } if *expected == generation && *existing_pid == pid && *existing_pty == pty => {
                return Ok(MutationOutcome::Idempotent);
            }
            DispatchState::Claimed { .. } => {
                return Err(JobRegistryError::SpawnGenerationMismatch);
            }
            DispatchState::Running { .. } => return Err(JobRegistryError::PidConflict),
            DispatchState::Accepted { .. } => {
                return Err(JobRegistryError::InvalidTransition("job start was not claimed"));
            }
            DispatchState::Terminal { .. } => {
                return Err(JobRegistryError::InvalidTransition("terminal job cannot start"));
            }
        }
        entry.dispatch = DispatchState::Running {
            generation,
            pid,
            pty,
            restart_uncertain: false,
        };
        entry.push(
            JobEventKind::Started {
                generation,
                pid,
                pty,
            },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn record_output(
        &self,
        key: &JobKey,
        generation: u64,
        stream: impl Into<String>,
        bytes: u64,
        sha256: impl Into<String>,
    ) -> Result<u64> {
        let stream = stream.into();
        let sha256 = sha256.into();
        require_text(&stream, "stream", 64, false)?;
        require_sha256(&sha256, "sha256")?;
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        match &entry.dispatch {
            DispatchState::Running {
                generation: expected,
                restart_uncertain: false,
                ..
            } if *expected == generation => {}
            DispatchState::Claimed { .. } | DispatchState::Running { .. } => {
                return Err(JobRegistryError::SpawnGenerationMismatch);
            }
            DispatchState::Accepted { .. } => {
                return Err(JobRegistryError::InvalidTransition(
                    "cannot record output before job start",
                ));
            }
            DispatchState::Terminal { .. } => {
                return Err(JobRegistryError::InvalidTransition(
                    "cannot record output after terminal",
                ));
            }
        }
        let output_seq = entry.next_output_seq;
        entry.next_output_seq = entry.next_output_seq.saturating_add(1);
        entry.push(
            JobEventKind::OutputObserved {
                generation,
                output_seq,
                stream,
                bytes,
                sha256,
            },
            self.limits.max_history_per_job,
        );
        Ok(output_seq)
    }

    pub fn record_input(
        &self,
        key: &JobKey,
        bytes: u64,
        sha256: impl Into<String>,
    ) -> Result<MutationOutcome> {
        let sha256 = sha256.into();
        require_sha256(&sha256, "sha256")?;
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        require_live(entry)?;
        if entry.stdin_closed {
            return Err(JobRegistryError::InvalidTransition("stdin is already closed"));
        }
        entry.push(
            JobEventKind::InputWritten { bytes, sha256 },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn record_resize(&self, key: &JobKey, rows: u16, cols: u16) -> Result<MutationOutcome> {
        if rows == 0 || cols == 0 {
            return Err(invalid("PTY rows and cols must be non-zero"));
        }
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        match &entry.dispatch {
            DispatchState::Running {
                pty: true,
                restart_uncertain: false,
                ..
            } => {}
            DispatchState::Running { pty: false, .. } => {
                return Err(JobRegistryError::InvalidTransition(
                    "non-PTY job cannot resize",
                ));
            }
            _ => return Err(JobRegistryError::InvalidTransition("job is not live")),
        }
        entry.push(
            JobEventKind::Resized { rows, cols },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn close_stdin(&self, key: &JobKey) -> Result<MutationOutcome> {
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        require_live(entry)?;
        if entry.stdin_closed {
            return Ok(MutationOutcome::Idempotent);
        }
        entry.stdin_closed = true;
        entry.push(JobEventKind::StdinClosed, self.limits.max_history_per_job);
        Ok(MutationOutcome::Applied)
    }

    pub fn request_kill(&self, key: &JobKey, signal: i32) -> Result<MutationOutcome> {
        if !(1..=128).contains(&signal) {
            return Err(invalid("kill signal is outside the supported range"));
        }
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        require_live(entry)?;
        entry.kill_requested = true;
        entry.push(
            JobEventKind::KillRequested { signal },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn attach(&self, key: &JobKey, attachment_id: impl Into<String>) -> Result<MutationOutcome> {
        let attachment_id = attachment_id.into();
        require_id(&attachment_id, "attachment_id", self.limits.max_id_bytes)?;
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        if entry.attachments.contains(&attachment_id) {
            return Ok(MutationOutcome::Idempotent);
        }
        if entry.attachments.len() >= self.limits.max_attachments_per_job {
            return Err(JobRegistryError::CapacityExhausted);
        }
        entry.attachments.insert(attachment_id.clone());
        entry.push(
            JobEventKind::Attached { attachment_id },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn detach(&self, key: &JobKey, attachment_id: &str) -> Result<MutationOutcome> {
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        if !entry.attachments.remove(attachment_id) {
            return Ok(MutationOutcome::Idempotent);
        }
        entry.push(
            JobEventKind::Detached {
                attachment_id: attachment_id.to_string(),
            },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn mark_restart_uncertain(&self, key: &JobKey) -> Result<JobSnapshot> {
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        let changed = match &mut entry.dispatch {
            DispatchState::Accepted { spawn_inhibited } => {
                let changed = !*spawn_inhibited;
                *spawn_inhibited = true;
                changed
            }
            DispatchState::Claimed { restart_uncertain, .. }
            | DispatchState::Running { restart_uncertain, .. } => {
                let changed = !*restart_uncertain;
                *restart_uncertain = true;
                changed
            }
            DispatchState::Terminal { .. } => false,
        };
        if changed {
            entry.push(
                JobEventKind::RestartObserved,
                self.limits.max_history_per_job,
            );
        }
        Ok(entry.snapshot())
    }

    pub fn complete(
        &self,
        key: &JobKey,
        generation: u64,
        terminal: JobTerminal,
    ) -> Result<MutationOutcome> {
        validate_terminal(&terminal)?;
        let mut state = self.lock()?;
        let entry = state.entries.get_mut(key).ok_or(JobRegistryError::NotFound)?;
        match &entry.dispatch {
            DispatchState::Running {
                generation: expected,
                ..
            } if *expected == generation => {}
            DispatchState::Running { .. } => {
                return Err(JobRegistryError::SpawnGenerationMismatch);
            }
            DispatchState::Terminal {
                generation: expected,
                terminal: existing,
            } if *expected == generation && *existing == terminal => {
                return Ok(MutationOutcome::Idempotent);
            }
            DispatchState::Terminal { .. } => return Err(JobRegistryError::TerminalConflict),
            DispatchState::Accepted { .. } | DispatchState::Claimed { .. } => {
                return Err(JobRegistryError::InvalidTransition(
                    "cannot complete job before start",
                ));
            }
        }
        entry.dispatch = DispatchState::Terminal {
            generation,
            terminal: terminal.clone(),
        };
        entry.push(
            JobEventKind::TerminalRecorded {
                generation,
                terminal,
            },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn snapshot(&self, key: &JobKey) -> Result<JobSnapshot> {
        self.lock()?
            .entries
            .get(key)
            .map(Entry::snapshot)
            .ok_or(JobRegistryError::NotFound)
    }

    pub fn history_from(&self, key: &JobKey, inclusive_seq: u64) -> Result<Vec<JobEvent>> {
        let state = self.lock()?;
        let entry = state.entries.get(key).ok_or(JobRegistryError::NotFound)?;
        Ok(entry
            .history
            .iter()
            .filter(|event| event.seq >= inclusive_seq)
            .cloned()
            .collect())
    }

    pub fn keys(&self) -> Result<Vec<JobKey>> {
        Ok(self.lock()?.entries.keys().cloned().collect())
    }

    pub fn remove_terminal(&self, key: &JobKey) -> Result<bool> {
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

    fn validate_key(&self, key: &JobKey) -> Result<()> {
        for (label, value) in [
            ("session_id", key.scope.session_id.as_str()),
            ("profile_id", key.scope.profile_id.as_str()),
            ("task_id", key.scope.task_id.as_str()),
            ("turn_id", key.scope.turn_id.as_str()),
            ("turn_stream_id", key.scope.turn_stream_id.as_str()),
            ("job_id", key.job_id.as_str()),
        ] {
            require_id(value, label, self.limits.max_id_bytes)?;
        }
        Ok(())
    }

    fn validate_request(&self, request: &JobRequest) -> Result<()> {
        require_sha256(&request.request_sha256, "request_sha256")?;
        require_sha256(&request.binding_fingerprint, "binding_fingerprint")?;
        require_text(&request.tool, "tool", self.limits.max_tool_bytes, false)?;
        require_text(&request.mode, "mode", 64, false)?;
        if let Some(target_id) = &request.target_id {
            require_text(
                target_id,
                "target_id",
                self.limits.max_target_bytes,
                true,
            )?;
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| JobRegistryError::StatePoisoned)
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new(JobRegistryLimits::default())
            .expect("default owner-open job registry limits are valid")
    }
}

fn require_live(entry: &Entry) -> Result<()> {
    match entry.dispatch {
        DispatchState::Running {
            restart_uncertain: false,
            ..
        } => Ok(()),
        DispatchState::Running {
            restart_uncertain: true,
            ..
        } => Err(JobRegistryError::InvalidTransition(
            "restart-uncertain job cannot accept live control",
        )),
        DispatchState::Accepted { .. } | DispatchState::Claimed { .. } => {
            Err(JobRegistryError::InvalidTransition("job has not started"))
        }
        DispatchState::Terminal { .. } => {
            Err(JobRegistryError::InvalidTransition("job is terminal"))
        }
    }
}
