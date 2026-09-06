use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

// A key always maps to one shard for the lifetime of this state schema.  The
// version and count are included in the hash preimage so changing either is an
// explicit migration decision rather than an accidental live-state split.
const REGISTRY_SHARD_COUNT: usize = 64;
const REGISTRY_SHARD_HASH_VERSION: u8 = 1;
const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x00000100000001b3;

use crate::validate::{invalid, require_id, require_sha256, require_text, validate_terminal};
use crate::{
    BeginDisposition, BeginResult, JobEffectiveState, JobEvent, JobEventKind, JobKey,
    JobRegistryError, JobRegistryLimits, JobRequest, JobSnapshot, JobTerminal, MutationOutcome,
    Result, SpawnClaim,
};

#[derive(Debug, Clone)]
enum DispatchState {
    Accepted {
        spawn_inhibited: bool,
    },
    Claimed {
        generation: u64,
        restart_uncertain: bool,
    },
    Running {
        generation: u64,
        pid: u32,
        pty: bool,
        restart_uncertain: bool,
    },
    Terminal {
        generation: u64,
        terminal: JobTerminal,
    },
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
            DispatchState::Accepted {
                spawn_inhibited: false,
            } => JobEffectiveState::Accepted,
            DispatchState::Accepted {
                spawn_inhibited: true,
            } => JobEffectiveState::ProvenNotStartedAfterRestart,
            DispatchState::Claimed {
                generation,
                restart_uncertain: false,
            } => JobEffectiveState::Starting {
                generation: *generation,
            },
            DispatchState::Claimed {
                generation,
                restart_uncertain: true,
            } => JobEffectiveState::UnknownAfterRestart {
                generation: *generation,
                pid: None,
                pty: None,
            },
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
            DispatchState::Terminal {
                generation,
                terminal,
            } => JobEffectiveState::Terminal {
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
struct ShardState {
    entries: HashMap<JobKey, Entry>,
}

#[derive(Debug)]
pub struct JobRegistry {
    limits: JobRegistryLimits,
    shards: Vec<Mutex<ShardState>>,
    entry_count: AtomicUsize,
    next_spawn_generation: AtomicU64,
    state_poisoned: AtomicBool,
}

impl JobRegistry {
    pub fn new(limits: JobRegistryLimits) -> Result<Self> {
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

    pub fn begin(&self, key: JobKey, request: JobRequest) -> Result<BeginResult> {
        self.ensure_healthy()?;
        self.validate_key(&key)?;
        self.validate_request(&request)?;
        let mut state = self.lock_shard(&key)?;
        if let Some(entry) = state.entries.get(&key) {
            if entry.request != request {
                return Err(JobRegistryError::JobIdConflict);
            }
            return Ok(BeginResult {
                disposition: BeginDisposition::Existing,
                snapshot: entry.snapshot(),
            });
        }
        self.reserve_entry()?;
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
        let previous = state.entries.insert(key, entry);
        debug_assert!(previous.is_none(), "key was checked under its shard lock");
        Ok(BeginResult {
            disposition: BeginDisposition::New,
            snapshot,
        })
    }

    /// Roll back an acceptance that has not yet crossed the spawn claim.
    ///
    /// The owner-open runtime uses this when durable operation acceptance
    /// fails after the in-memory registry has accepted a new key.  The
    /// request and the exact pre-spawn state are checked while holding the
    /// registry lock so a concurrent lifecycle transition can never cause a
    /// live/claimed entry to be removed accidentally.
    pub fn rollback_accept(&self, key: &JobKey, request: &JobRequest) -> Result<bool> {
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
        let Some(entry) = state.entries.get(key) else {
            return Ok(false);
        };
        if entry.request != *request {
            return Err(JobRegistryError::JobIdConflict);
        }
        let rollbackable = matches!(
            entry.dispatch,
            DispatchState::Accepted {
                spawn_inhibited: false
            }
        ) && !entry.stdin_closed
            && !entry.kill_requested
            && entry.attachments.is_empty()
            && entry.history.len() == 1
            && matches!(
                entry.history.front().map(|event| &event.event),
                Some(JobEventKind::Accepted)
            );
        if !rollbackable {
            return Err(JobRegistryError::InvalidTransition(
                "only an untouched accepted job can be rolled back",
            ));
        }
        let removed = state.entries.remove(key);
        debug_assert!(removed.is_some());
        self.release_entry();
        Ok(true)
    }

    pub fn claim_spawn(&self, key: &JobKey, request_sha256: &str) -> Result<SpawnClaim> {
        self.ensure_healthy()?;
        require_sha256(request_sha256, "request_sha256")?;
        let mut state = self.lock_shard(key)?;
        let entry = state.entries.get(key).ok_or(JobRegistryError::NotFound)?;
        if entry.request.request_sha256 != request_sha256 {
            return Err(JobRegistryError::RequestDigestMismatch);
        }
        match &entry.dispatch {
            DispatchState::Accepted {
                spawn_inhibited: true,
            } => {
                return Ok(SpawnClaim::Inhibited(entry.snapshot()));
            }
            DispatchState::Claimed { .. }
            | DispatchState::Running { .. }
            | DispatchState::Terminal { .. } => {
                return Ok(SpawnClaim::Existing(entry.snapshot()));
            }
            DispatchState::Accepted {
                spawn_inhibited: false,
            } => {}
        }
        let generation = self.allocate_generation()?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
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
        self.ensure_healthy()?;
        if pid == 0 {
            return Err(invalid("pid must be non-zero"));
        }
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
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
                return Err(JobRegistryError::InvalidTransition(
                    "job start was not claimed",
                ));
            }
            DispatchState::Terminal { .. } => {
                return Err(JobRegistryError::InvalidTransition(
                    "terminal job cannot start",
                ));
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
        self.ensure_healthy()?;
        let stream = stream.into();
        let sha256 = sha256.into();
        require_text(&stream, "stream", 64, false)?;
        require_sha256(&sha256, "sha256")?;
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
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
        self.ensure_healthy()?;
        let sha256 = sha256.into();
        require_sha256(&sha256, "sha256")?;
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
        require_live(entry)?;
        if entry.stdin_closed {
            return Err(JobRegistryError::InvalidTransition(
                "stdin is already closed",
            ));
        }
        entry.push(
            JobEventKind::InputWritten { bytes, sha256 },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn record_resize(&self, key: &JobKey, rows: u16, cols: u16) -> Result<MutationOutcome> {
        self.ensure_healthy()?;
        if rows == 0 || cols == 0 {
            return Err(invalid("PTY rows and cols must be non-zero"));
        }
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
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
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
        require_live(entry)?;
        if entry.stdin_closed {
            return Ok(MutationOutcome::Idempotent);
        }
        entry.stdin_closed = true;
        entry.push(JobEventKind::StdinClosed, self.limits.max_history_per_job);
        Ok(MutationOutcome::Applied)
    }

    pub fn request_kill(&self, key: &JobKey, signal: i32) -> Result<MutationOutcome> {
        self.ensure_healthy()?;
        if !(1..=128).contains(&signal) {
            return Err(invalid("kill signal is outside the supported range"));
        }
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
        require_live(entry)?;
        entry.kill_requested = true;
        entry.push(
            JobEventKind::KillRequested { signal },
            self.limits.max_history_per_job,
        );
        Ok(MutationOutcome::Applied)
    }

    pub fn attach(
        &self,
        key: &JobKey,
        attachment_id: impl Into<String>,
    ) -> Result<MutationOutcome> {
        self.ensure_healthy()?;
        let attachment_id = attachment_id.into();
        require_id(&attachment_id, "attachment_id", self.limits.max_id_bytes)?;
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
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
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
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
        self.ensure_healthy()?;
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
        let changed = match &mut entry.dispatch {
            DispatchState::Accepted { spawn_inhibited } => {
                let changed = !*spawn_inhibited;
                *spawn_inhibited = true;
                changed
            }
            DispatchState::Claimed {
                restart_uncertain, ..
            }
            | DispatchState::Running {
                restart_uncertain, ..
            } => {
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
        self.ensure_healthy()?;
        validate_terminal(&terminal)?;
        let mut state = self.lock_shard(key)?;
        let entry = state
            .entries
            .get_mut(key)
            .ok_or(JobRegistryError::NotFound)?;
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
        self.ensure_healthy()?;
        self.lock_shard(key)?
            .entries
            .get(key)
            .map(Entry::snapshot)
            .ok_or(JobRegistryError::NotFound)
    }

    pub fn history_from(&self, key: &JobKey, inclusive_seq: u64) -> Result<Vec<JobEvent>> {
        self.ensure_healthy()?;
        let state = self.lock_shard(key)?;
        let entry = state.entries.get(key).ok_or(JobRegistryError::NotFound)?;
        Ok(entry
            .history
            .iter()
            .filter(|event| event.seq >= inclusive_seq)
            .cloned()
            .collect())
    }

    pub fn keys(&self) -> Result<Vec<JobKey>> {
        self.ensure_healthy()?;
        let mut keys = Vec::with_capacity(self.entry_count.load(Ordering::Acquire));
        for shard in &self.shards {
            let state = shard.lock().map_err(|_| {
                self.state_poisoned.store(true, Ordering::Release);
                JobRegistryError::StatePoisoned
            })?;
            keys.extend(state.entries.keys().cloned());
        }
        // Hash-map iteration order is intentionally unspecified. Sorting the
        // aggregate view makes inspection deterministic without introducing a
        // global lock into per-key transitions.
        keys.sort_by(|left, right| {
            let left_fields = [
                &left.scope.session_id,
                &left.scope.profile_id,
                &left.scope.task_id,
                &left.scope.turn_id,
                &left.scope.turn_stream_id,
                &left.job_id,
            ];
            let right_fields = [
                &right.scope.session_id,
                &right.scope.profile_id,
                &right.scope.task_id,
                &right.scope.turn_id,
                &right.scope.turn_stream_id,
                &right.job_id,
            ];
            left_fields.cmp(&right_fields)
        });
        Ok(keys)
    }

    pub fn remove_terminal(&self, key: &JobKey) -> Result<bool> {
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

    fn shard_index(&self, key: &JobKey) -> usize {
        stable_shard_index(
            b"owner-open-job-registry",
            &[
                &key.scope.session_id,
                &key.scope.profile_id,
                &key.scope.task_id,
                &key.scope.turn_id,
                &key.scope.turn_stream_id,
                &key.job_id,
            ],
        )
    }

    fn lock_shard(&self, key: &JobKey) -> Result<MutexGuard<'_, ShardState>> {
        self.shards[self.shard_index(key)].lock().map_err(|_| {
            self.state_poisoned.store(true, Ordering::Release);
            JobRegistryError::StatePoisoned
        })
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.state_poisoned.load(Ordering::Acquire) {
            return Err(JobRegistryError::StatePoisoned);
        }
        // A shard can be poisoned by code that held its mutex directly before
        // a registry method attempts a per-key lock. Aggregate observations
        // must detect that state and remain fail-closed.
        if self.shards.iter().any(Mutex::is_poisoned) {
            self.state_poisoned.store(true, Ordering::Release);
            return Err(JobRegistryError::StatePoisoned);
        }
        Ok(())
    }

    fn reserve_entry(&self) -> Result<()> {
        let mut current = self.entry_count.load(Ordering::Acquire);
        loop {
            if current >= self.limits.max_entries {
                return Err(JobRegistryError::CapacityExhausted);
            }
            let next = current
                .checked_add(1)
                .ok_or(JobRegistryError::CapacityExhausted)?;
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
        debug_assert!(previous > 0, "job registry entry count underflow");
    }

    fn allocate_generation(&self) -> Result<u64> {
        let mut current = self.next_spawn_generation.load(Ordering::Acquire);
        loop {
            if current == 0 || current == u64::MAX {
                return Err(JobRegistryError::GenerationExhausted);
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
            require_text(target_id, "target_id", self.limits.max_target_bytes, true)?;
        }
        Ok(())
    }
}

impl Default for JobRegistry {
    fn default() -> Self {
        Self::new(JobRegistryLimits::default())
            .expect("default owner-open job registry limits are valid")
    }
}

/// Hash length-delimited key fields with a fixed, versioned FNV-1a layout.
/// Sharding does not carry authorization meaning, so a compact deterministic
/// hash is sufficient and avoids depending on an implementation-randomized
/// `DefaultHasher`.  The explicit version/count make layout changes visible
/// migration events instead of silent ownership changes.
fn stable_shard_index(domain: &[u8], fields: &[&str]) -> usize {
    fn feed(hash: &mut u64, bytes: &[u8]) {
        for byte in bytes {
            *hash ^= u64::from(*byte);
            *hash = hash.wrapping_mul(FNV_PRIME);
        }
    }
    fn feed_len(hash: &mut u64, length: usize) {
        feed(hash, &(length as u64).to_be_bytes());
    }

    let mut hash = FNV_OFFSET_BASIS;
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc::sync_channel;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    use super::*;
    use crate::{
        JobScope, MAX_ATTACHMENTS_PER_JOB, MAX_HISTORY_PER_JOB, MAX_HISTORY_SLOTS, MAX_ID_BYTES,
        MAX_REGISTRY_ENTRIES, MAX_TARGET_BYTES, MAX_TOOL_BYTES,
    };

    fn scope() -> JobScope {
        JobScope::new("session-1", "owner-open", "task-1", "turn-1", "stream-1")
    }

    fn key(job_id: &str) -> JobKey {
        JobKey::new(scope(), job_id)
    }

    fn request(seed: char) -> JobRequest {
        JobRequest::new(
            seed.to_string().repeat(64),
            "b".repeat(64),
            "shell.job",
            "pipe",
            Some("rootlinux".to_string()),
        )
    }

    #[test]
    fn configured_limits_cannot_escape_schema_hard_bounds() {
        let oversized = [
            JobRegistryLimits {
                max_entries: MAX_REGISTRY_ENTRIES + 1,
                ..JobRegistryLimits::default()
            },
            JobRegistryLimits {
                max_history_per_job: MAX_HISTORY_PER_JOB + 1,
                ..JobRegistryLimits::default()
            },
            JobRegistryLimits {
                max_attachments_per_job: MAX_ATTACHMENTS_PER_JOB + 1,
                ..JobRegistryLimits::default()
            },
            JobRegistryLimits {
                max_id_bytes: MAX_ID_BYTES + 1,
                ..JobRegistryLimits::default()
            },
            JobRegistryLimits {
                max_tool_bytes: MAX_TOOL_BYTES + 1,
                ..JobRegistryLimits::default()
            },
            JobRegistryLimits {
                max_target_bytes: MAX_TARGET_BYTES + 1,
                ..JobRegistryLimits::default()
            },
        ];
        for limits in oversized {
            assert!(
                JobRegistry::new(limits).is_err(),
                "configured job-registry limit exceeded its hard bound"
            );
        }
        assert!(
            JobRegistry::new(JobRegistryLimits {
                max_entries: MAX_REGISTRY_ENTRIES,
                max_history_per_job: MAX_HISTORY_SLOTS / MAX_REGISTRY_ENTRIES + 1,
                ..JobRegistryLimits::default()
            })
            .is_err(),
            "entry/history product must remain bounded"
        );
        assert!(
            JobRegistry::new(JobRegistryLimits {
                max_entries: MAX_HISTORY_SLOTS / 512,
                max_history_per_job: 512,
                ..JobRegistryLimits::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn poisoned_shard_fails_closed_for_observation_and_admission() {
        let registry = JobRegistry::default();
        let job = key("job-poisoned");
        let shard_index = registry.shard_index(&job);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = registry.shards[shard_index].lock().unwrap();
            panic!("intentional shard poison for regression test");
        }));

        assert_eq!(registry.len(), Err(JobRegistryError::StatePoisoned));
        assert_eq!(registry.is_empty(), Err(JobRegistryError::StatePoisoned));
        assert_eq!(
            registry.begin(job, request('p')).unwrap_err(),
            JobRegistryError::StatePoisoned
        );
        assert_eq!(
            registry.keys().unwrap_err(),
            JobRegistryError::StatePoisoned
        );
    }

    #[test]
    fn shard_mapping_is_versioned_and_stable() {
        let registry = JobRegistry::default();
        assert_eq!(
            registry.shard_index(&key("job-1")),
            14,
            "registry shard hash vector changed"
        );
        let another_instance = JobRegistry::default();
        assert_eq!(
            registry.shard_index(&key("job-1")),
            another_instance.shard_index(&key("job-1"))
        );
    }

    #[test]
    fn shard_mapping_has_bounded_collision_pressure_for_typical_keys() {
        let registry = JobRegistry::default();
        let mut occupied = std::collections::HashSet::new();
        for index in 0..4_096 {
            occupied.insert(registry.shard_index(&key(&format!("job-distribution-{index}"))));
        }
        assert!(
            occupied.len() >= REGISTRY_SHARD_COUNT / 2,
            "deterministic shard hash is unexpectedly concentrated: {occupied:?}"
        );
    }

    #[test]
    fn an_independent_shard_progresses_while_one_shard_is_held() {
        let registry = Arc::new(JobRegistry::default());
        let blocked = key("job-blocked-shard");
        let blocked_index = registry.shard_index(&blocked);
        let independent = (0..10_000)
            .map(|index| key(&format!("job-independent-{index}")))
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
        const LIMIT: usize = 8;
        const THREADS: usize = 64;
        let registry = Arc::new(
            JobRegistry::new(JobRegistryLimits {
                max_entries: LIMIT,
                ..JobRegistryLimits::default()
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
                    registry.begin(key(&format!("job-capacity-{index}")), request('d'))
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

    #[test]
    fn concurrent_spawn_generations_remain_unique_across_shards() {
        const THREADS: usize = 32;
        let registry = Arc::new(JobRegistry::default());
        let entries = (0..THREADS)
            .map(|index| {
                let key = key(&format!("job-generation-{index}"));
                let request = request('e');
                registry.begin(key.clone(), request.clone()).unwrap();
                (key, request)
            })
            .collect::<Vec<_>>();
        let barrier = Arc::new(Barrier::new(THREADS));
        let workers = entries
            .into_iter()
            .map(|(key, request)| {
                let registry = Arc::clone(&registry);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    match registry.claim_spawn(&key, &request.request_sha256).unwrap() {
                        SpawnClaim::Granted { generation, .. } => generation,
                        other => panic!("unexpected spawn claim: {other:?}"),
                    }
                })
            })
            .collect::<Vec<_>>();
        let mut generations = workers
            .into_iter()
            .map(|worker| worker.join().expect("generation worker"))
            .collect::<Vec<_>>();
        generations.sort_unstable();
        generations.dedup();
        assert_eq!(generations.len(), THREADS);
    }
}
