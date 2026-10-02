use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::resources::{MAX_INHERITED_ENV_BYTES, MAX_INHERITED_ENV_VALUE_BYTES, ProcessLease};
use sha2::{Digest, Sha256};

use crate::{
    InternalProcessEvent, JobInvocation, JobRuntimeError, JobStartRequest, PtySize, Result,
};

pub(crate) const PROCESS_EVENT_QUEUE: usize = 16;
const DESCENDANT_TERM_GRACE: Duration = Duration::from_millis(100);
const DESCENDANT_KILL_GRACE: Duration = Duration::from_millis(100);
const SPAWN_GUARD_REAP_GRACE: Duration = Duration::from_millis(500);
const PROCESS_GROUP_SCAN_BUDGET: Duration = Duration::from_millis(500);
const READER_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WORKER_NATURAL_JOIN_GRACE: Duration = Duration::from_millis(250);
const WORKER_CANCEL_JOIN_GRACE: Duration = Duration::from_secs(2);
// Only pass through the small set of mechanical process settings that the
// owner-open contract names.  Credentials, agent tokens and arbitrary host
// state must never leak into a durable job merely because the Host inherited
// them from its parent environment; request.env remains the explicit delta.
const JOB_INHERITED_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TERM",
    "NO_COLOR",
    "ADB_SERVER_SOCKET",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
];
// A control call must never hold the Host loop indefinitely when a child does
// not read stdin.  The fd is switched to non-blocking for the duration of one
// serialized write and polled up to this bound; callers receive a terminal
// operation failure rather than an unbounded write_all wait.
const INPUT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_GATE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessPhase {
    Active,
    Retiring,
    Retired,
}

struct ProcessLifecycle {
    retirement_requested: AtomicBool,
    phase: Mutex<ProcessPhase>,
}

impl ProcessLifecycle {
    fn new() -> Self {
        Self {
            retirement_requested: AtomicBool::new(false),
            phase: Mutex::new(ProcessPhase::Active),
        }
    }

    fn control(&self) -> Result<MutexGuard<'_, ProcessPhase>> {
        let deadline = Instant::now() + CONTROL_GATE_TIMEOUT;
        loop {
            if self.retirement_requested.load(Ordering::Acquire) {
                return Err(JobRuntimeError::NotLive);
            }
            match self.phase.try_lock() {
                Ok(guard) => {
                    if self.retirement_requested.load(Ordering::Acquire)
                        || *guard != ProcessPhase::Active
                    {
                        return Err(JobRuntimeError::NotLive);
                    }
                    if Instant::now() >= deadline {
                        return Err(JobRuntimeError::Control(
                            "process control gate deadline exceeded".to_string(),
                        ));
                    }
                    return Ok(guard);
                }
                Err(TryLockError::Poisoned(_)) => return Err(JobRuntimeError::StatePoisoned),
                Err(TryLockError::WouldBlock) => {}
            }
            if Instant::now() >= deadline {
                return Err(JobRuntimeError::Control(
                    "process control gate deadline exceeded".to_string(),
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn retirement_lock(&self) -> std::result::Result<(MutexGuard<'_, ProcessPhase>, bool), String> {
        self.retirement_requested.store(true, Ordering::Release);
        let deadline = Instant::now() + CONTROL_GATE_TIMEOUT;
        loop {
            let acquired = match self.phase.try_lock() {
                Ok(guard) => Some((guard, false)),
                Err(TryLockError::Poisoned(error)) => Some((error.into_inner(), true)),
                Err(TryLockError::WouldBlock) => None,
            };
            if let Some(acquired) = acquired {
                if Instant::now() >= deadline {
                    return Err("process retirement gate acquired after deadline; anchor ownership retained".to_string());
                }
                return Ok(acquired);
            }
            if Instant::now() >= deadline {
                return Err(
                    "process retirement gate deadline exceeded; anchor ownership retained"
                        .to_string(),
                );
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn begin_retirement(&self) -> std::result::Result<bool, String> {
        // Atomic admission closure prevents a stream of later controls from
        // starving the same mutex used by each actual effect. The only
        // admitted writer is bounded; retirement never waits for I/O workers
        // while holding this gate.
        let (mut phase, poisoned) = self.retirement_lock()?;
        if *phase == ProcessPhase::Active {
            *phase = ProcessPhase::Retiring;
        }
        Ok(poisoned)
    }

    fn finish_retirement(&self) -> std::result::Result<bool, String> {
        let (mut phase, poisoned) = self.retirement_lock()?;
        *phase = ProcessPhase::Retired;
        Ok(poisoned)
    }

    fn is_retired(&self) -> bool {
        let phase = match self.phase.lock() {
            Ok(guard) => guard,
            Err(error) => error.into_inner(),
        };
        self.retirement_requested.load(Ordering::Acquire) && *phase == ProcessPhase::Retired
    }
}

enum InputHandle {
    Pipe(ChildStdin),
    Pty(File),
}

/// Kernel-observed identity captured immediately after a child is spawned.
///
/// Linux/Android provide the PID start-time and boot-id pair that makes a PID
/// generation distinguishable from a later PID reuse.  Other Unix targets do
/// not expose procfs boot identity, so those fields remain `None`; process
/// group and session IDs are still bound where the libc primitives exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pub pid: u32,
    pub process_group: u32,
    pub session_id: u32,
    pub start_time_ticks: Option<u64>,
    pub boot_id_sha256: Option<String>,
}

pub(crate) struct ProcessControl {
    pub pid: u32,
    pub process_group: u32,
    pub session_id: u32,
    pub start_time_ticks: Option<u64>,
    pub boot_id_sha256: Option<String>,
    pub pty: bool,
    input: Arc<Mutex<Option<InputHandle>>>,
    pty_master: Option<Arc<File>>,
    pty_eof_sent: AtomicBool,
    lifecycle: Arc<ProcessLifecycle>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StdinCloseEffect {
    AlreadyClosed,
    PipeClosed,
    PtyEofCharacterSent,
}

pub(crate) struct SpawnedProcess {
    pub control: Arc<ProcessControl>,
    pub events: Receiver<InternalProcessEvent>,
}

/// A process-I/O worker together with a cooperative stop flag.  Reader
/// workers poll their descriptor, so setting the flag is sufficient to
/// unblock a worker even when an untrusted descendant kept the inherited pipe
/// open after cleanup could not be proven.  The initial-stdin worker also
/// observes the flag before entering its bounded write helper.
struct ProcessWorker {
    handle: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl ProcessWorker {
    fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn join(mut self) -> thread::Result<()> {
        self.handle
            .take()
            .expect("job worker handle is present before join")
            .join()
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl Drop for ProcessWorker {
    fn drop(&mut self) {
        // Early setup failures can drop a worker before the reaper owns the
        // full worker set. Request cooperative shutdown so a polling reader
        // does not remain detached with an inherited descriptor.
        self.request_stop();
    }
}

struct SpawnGuard {
    child: Option<Child>,
    pid: u32,
    identity: Option<ProcessIdentity>,
    _process_lease: Option<Arc<ProcessLease>>,
    lifecycle: Arc<ProcessLifecycle>,
}

impl SpawnGuard {
    fn new(child: Child) -> Self {
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
            identity: None,
            _process_lease: None,
            lifecycle: Arc::new(ProcessLifecycle::new()),
        }
    }

    fn bind_identity(&mut self, identity: ProcessIdentity) {
        debug_assert_eq!(identity.pid, self.pid);
        self.identity = Some(identity);
    }

    fn child_mut(&mut self) -> std::io::Result<&mut Child> {
        self.child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("spawn guard no longer owns its child"))
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        if !self.lifecycle.is_retired() {
            return Err(std::io::Error::other(
                "child wait before control retirement barrier",
            ));
        }
        if !observe_owned_child(self.pid, true)? {
            return Err(std::io::Error::other(
                "child is not terminal at final consuming wait",
            ));
        }
        let status = self.child_mut()?.wait();
        if status.is_ok() {
            self.child.take();
        }
        status
    }
}

// Production quarantines are never cleared by elapsed time, numeric PID
// disappearance, or a successful no-op. Their charge requires full offline
// service/cgroup cleanup and external reconciliation before Host restart.
// Every production guard owns a ProcessLease; the shared 16-owner admission
// bound therefore bounds retained quarantines as well as live processes.
type QuarantinedChild = (
    Child,
    Option<ProcessIdentity>,
    Arc<ProcessLifecycle>,
    Option<Arc<ProcessLease>>,
    String,
);
static UNCERTAIN_CHILD_QUARANTINE: Mutex<Vec<QuarantinedChild>> = Mutex::new(Vec::new());

enum AbortFailure {
    Unsupported(String),
    Retryable(String),
}

fn quarantine_owned_child(
    child: Child,
    identity: Option<ProcessIdentity>,
    lifecycle: Arc<ProcessLifecycle>,
    lease: Option<Arc<ProcessLease>>,
    reason: String,
) {
    lifecycle
        .retirement_requested
        .store(true, Ordering::Release);
    let _ = lifecycle.finish_retirement();
    UNCERTAIN_CHILD_QUARANTINE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push((child, identity, lifecycle, lease, reason));
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Err(error) = self.lifecycle.begin_retirement() {
            defer_guard_cleanup(
                child,
                self.identity.take(),
                Arc::clone(&self.lifecycle),
                self._process_lease.take(),
                error,
            );
            return;
        }
        match abort_owned_child(&mut child, self.identity.as_ref()) {
            Ok(()) => {}
            Err(AbortFailure::Unsupported(reason)) => {
                quarantine_owned_child(
                    child,
                    self.identity.take(),
                    Arc::clone(&self.lifecycle),
                    self._process_lease.take(),
                    reason,
                );
                return;
            }
            Err(AbortFailure::Retryable(reason)) => {
                defer_guard_cleanup(
                    child,
                    self.identity.take(),
                    Arc::clone(&self.lifecycle),
                    self._process_lease.take(),
                    reason,
                );
                return;
            }
        }
        if let Err(error) = self.lifecycle.finish_retirement() {
            defer_guard_cleanup(
                child,
                self.identity.take(),
                Arc::clone(&self.lifecycle),
                self._process_lease.take(),
                error,
            );
            return;
        }
        reap_owned_child_bounded(
            child,
            self.pid,
            self.identity.take(),
            Arc::clone(&self.lifecycle),
            self._process_lease.take(),
        );
    }
}

fn abort_owned_child(
    child: &mut Child,
    identity: Option<&ProcessIdentity>,
) -> std::result::Result<(), AbortFailure> {
    // Unix Child is a numeric-PID handle, not a pidfd. Never use Child.kill or
    // Child.wait after loss of exclusive wait ownership or SIGCHLD support.
    observe_owned_child(child.id(), true).map_err(|error| {
        AbortFailure::Unsupported(format!(
            "direct-child wait ownership is unavailable; child/lease quarantined: {error}"
        ))
    })?;
    let Some(identity) = identity else {
        let kill_result = child.kill();
        return Err(AbortFailure::Unsupported(format!(
            "group identity was never bound; exact owned Child.kill result={kill_result:?}; group quiet unproven; child/lease quarantined"
        )));
    };
    ensure_bound_process_group(identity).map_err(|error| AbortFailure::Unsupported(format!("bound leader anchor unavailable; no numeric group recovery; child/lease quarantined: {error}")))?;
    send_bound_process_group_signal(identity, libc::SIGKILL).map_err(AbortFailure::Retryable)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    match wait_group_quiet(identity, SPAWN_GUARD_REAP_GRACE, deadline)
        .map_err(AbortFailure::Retryable)?
    {
        true => Ok(()),
        false => Err(AbortFailure::Retryable(
            "abort group quiet is unproven; owned anchor/identity/lease retained for recovery"
                .to_string(),
        )),
    }
}

fn reap_owned_child_bounded(
    mut child: Child,
    pid: u32,
    identity: Option<ProcessIdentity>,
    lifecycle: Arc<ProcessLifecycle>,
    lease: Option<Arc<ProcessLease>>,
) {
    let deadline = Instant::now() + SPAWN_GUARD_REAP_GRACE;
    loop {
        // A successful group proof did not transfer wait ownership. Recheck
        // before every consuming primitive; external wait/SIGCHLD mutation is
        // unsupported and must never target a later numeric PID generation.
        if let Err(error) = observe_owned_child(child.id(), true) {
            quarantine_owned_child(
                child,
                identity,
                lifecycle,
                lease,
                format!("wait ownership lost after group quiet proof: {error}"),
            );
            return;
        }
        match child.try_wait() {
            Ok(Some(_)) => return,
            Err(error) => {
                quarantine_owned_child(
                    child,
                    identity,
                    lifecycle,
                    lease,
                    format!("consuming abort wait failed: {error}"),
                );
                return;
            }
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
        }
    }
    // Kernel/caller suspension can exceed the foreground attempt. This
    // eventual waiter still owns the exact Child and lease; it is unknown,
    // not a promise of finite cleanup or reclaimed resource capacity.
    let retained = Arc::new(Mutex::new(Some((child, identity, lifecycle, lease))));
    let worker_retained = Arc::clone(&retained);
    let spawned = thread::Builder::new()
        .name(format!("owner-open-job-abort-reaper-{pid}"))
        .spawn(move || {
            let (mut child, identity, lifecycle, lease) = worker_retained
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
                .expect("abort reaper owns child");
            match observe_owned_child(child.id(), true) {
                Err(error) => quarantine_owned_child(
                    child,
                    identity,
                    lifecycle,
                    lease,
                    format!("eventual wait ownership observation failed: {error}"),
                ),
                Ok(_) => match child.wait() {
                    Ok(_) => {}
                    Err(error) => quarantine_owned_child(
                        child,
                        identity,
                        lifecycle,
                        lease,
                        format!("eventual consuming wait failed: {error}"),
                    ),
                },
            }
        });
    if let Err(error) = spawned {
        let (child, identity, lifecycle, lease) = retained
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("failed waiter retains child");
        quarantine_owned_child(
            child,
            identity,
            lifecycle,
            lease,
            format!("eventual abort waiter could not be started: {error}"),
        );
    }
}

fn defer_guard_cleanup(
    child: Child,
    identity: Option<ProcessIdentity>,
    lifecycle: Arc<ProcessLifecycle>,
    lease: Option<Arc<ProcessLease>>,
    first_error: String,
) {
    // Repeated attempts each have a gate/scan budget; no total recovery time
    // is claimed. The anchor, identity and resource charge stay retained
    // through every signal and scan. Only a complete owned quiet proof
    // authorizes consuming wait; unsupported ownership goes to quarantine.
    let retained = Arc::new(Mutex::new(Some((
        child,
        identity,
        lifecycle,
        lease,
        first_error,
    ))));
    let worker_retained = Arc::clone(&retained);
    let spawned = thread::Builder::new()
        .name("owner-open-job-retirement-recovery".to_string())
        .spawn(move || {
            let (mut child, identity, lifecycle, lease, first_error) = worker_retained
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .take()
                .expect("recovery owns child");
            let mut recovery_errors = vec![first_error];
            loop {
                if let Err(error) = lifecycle.begin_retirement() {
                    if recovery_errors.len() < 8 {
                        recovery_errors.push(error);
                    }
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                match abort_owned_child(&mut child, identity.as_ref()) {
                    Ok(()) => {
                        if let Err(error) = lifecycle.finish_retirement() {
                            if recovery_errors.len() < 8 {
                                recovery_errors.push(error);
                            }
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        let pid = child.id();
                        reap_owned_child_bounded(child, pid, identity, lifecycle, lease);
                        return;
                    }
                    Err(AbortFailure::Unsupported(reason)) => {
                        recovery_errors.push(reason);
                        quarantine_owned_child(
                            child,
                            identity,
                            lifecycle,
                            lease,
                            recovery_errors.join("; "),
                        );
                        return;
                    }
                    Err(AbortFailure::Retryable(reason)) => {
                        if recovery_errors.len() < 8 {
                            recovery_errors.push(reason);
                        }
                        thread::sleep(Duration::from_millis(5));
                    }
                }
            }
        });
    if let Err(error) = spawned {
        let (child, identity, lifecycle, lease, first_error) = retained
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .expect("failed recovery retains child");
        quarantine_owned_child(
            child,
            identity,
            lifecycle,
            lease,
            format!("{first_error}; retirement recovery worker could not be started: {error}"),
        );
    }
}

impl ProcessControl {
    pub fn write(&self, bytes: &[u8]) -> Result<()> {
        let _effect_gate = self.lifecycle.control()?;
        let mut guard = self
            .input
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        let handle = guard.as_mut().ok_or(JobRuntimeError::NotLive)?;
        write_input(handle, bytes)?;
        if matches!(handle, InputHandle::Pty(_)) {
            self.pty_eof_sent.store(false, Ordering::Release);
        }
        Ok(())
    }

    pub fn close_stdin(&self) -> Result<StdinCloseEffect> {
        let _effect_gate = self.lifecycle.control()?;
        let mut guard = self
            .input
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        match guard.as_mut() {
            None => Ok(StdinCloseEffect::AlreadyClosed),
            Some(InputHandle::Pipe(_)) => {
                *guard = None;
                Ok(StdinCloseEffect::PipeClosed)
            }
            Some(InputHandle::Pty(master)) => {
                if self
                    .pty_eof_sent
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    return Ok(StdinCloseEffect::AlreadyClosed);
                }
                if let Err(error) = write_nonblocking_fd(master.as_raw_fd(), &[0x04]) {
                    self.pty_eof_sent.store(false, Ordering::Release);
                    return Err(error);
                }
                Ok(StdinCloseEffect::PtyEofCharacterSent)
            }
        }
    }

    pub fn resize(&self, size: PtySize) -> Result<()> {
        let _effect_gate = self.lifecycle.control()?;
        let master = self
            .pty_master
            .as_ref()
            .ok_or_else(|| JobRuntimeError::Control("non-PTY job cannot resize".to_string()))?;
        let winsize = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let result = unsafe {
            libc::ioctl(
                master.as_raw_fd(),
                libc::TIOCSWINSZ as _,
                &winsize as *const libc::winsize,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(JobRuntimeError::Control(
                std::io::Error::last_os_error().to_string(),
            ))
        }
    }

    pub fn kill(&self, signal: i32) -> Result<()> {
        let _effect_gate = self.lifecycle.control()?;
        // Never signal a process group solely by a recycled PID.  A vanished
        // leader is an uncertainty; a different live process
        // generation is a hard control failure and is left for reconciliation.
        let identity = self.identity();
        match observe_process_identity(self.pid)
            .map_err(|error| JobRuntimeError::Control(error.to_string()))?
        {
            Some(observed) if !identity_matches(&identity, &observed) => {
                return Err(JobRuntimeError::Control(
                    "job process identity changed before signal".to_string(),
                ));
            }
            Some(_) => {}
            None => {
                return Err(JobRuntimeError::Control(
                    "original process leader anchor unavailable before signal".to_string(),
                ));
            }
        }
        send_bound_process_group_signal(&identity, signal).map_err(JobRuntimeError::Control)
    }

    pub(crate) fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            process_group: self.process_group,
            session_id: self.session_id,
            start_time_ticks: self.start_time_ticks,
            boot_id_sha256: self.boot_id_sha256.clone(),
        }
    }
}

pub(crate) fn spawn_process(
    request: &JobStartRequest,
    maximum_chunk: usize,
    inherited: &[(OsString, OsString)],
    lease: Arc<ProcessLease>,
) -> Result<SpawnedProcess> {
    validate_start(request)?;
    ensure_sigchld_ownership_configuration()
        .map_err(|error| JobRuntimeError::Spawn(error.to_string()))?;
    match request.pty {
        Some(size) => spawn_pty(request, size, maximum_chunk, inherited, lease),
        None => spawn_pipe(request, maximum_chunk, inherited, lease),
    }
}

fn spawn_pipe(
    request: &JobStartRequest,
    maximum_chunk: usize,
    inherited: &[(OsString, OsString)],
    lease: Arc<ProcessLease>,
) -> Result<SpawnedProcess> {
    let mut command = base_command(request, inherited)?;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(std::io::Error::from_raw_os_error(libc::EPIPE));
                }
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|error| JobRuntimeError::Spawn(error.to_string()))?;
    let mut guard = SpawnGuard::new(child);
    guard._process_lease = Some(Arc::clone(&lease));
    let identity = capture_process_identity(guard.pid).map_err(|error| {
        post_fork_error(JobRuntimeError::Io(format!(
            "failed to capture child process identity: {error}"
        )))
    })?;
    guard.bind_identity(identity.clone());
    let pid = guard.pid;
    let stdin = guard
        .child_mut()
        .map_err(|error| post_fork_error(JobRuntimeError::Io(error.to_string())))?
        .stdin
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stdin was not piped".to_string()))
        .map_err(post_fork_error)?;
    let stdout = guard
        .child_mut()
        .map_err(|error| post_fork_error(JobRuntimeError::Io(error.to_string())))?
        .stdout
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stdout was not piped".to_string()))
        .map_err(post_fork_error)?;
    let stderr = guard
        .child_mut()
        .map_err(|error| post_fork_error(JobRuntimeError::Io(error.to_string())))?
        .stderr
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stderr was not piped".to_string()))
        .map_err(post_fork_error)?;
    let input = Arc::new(Mutex::new(Some(InputHandle::Pipe(stdin))));
    let (sender, receiver) = sync_channel(PROCESS_EVENT_QUEUE);
    let stdout_thread = spawn_reader(
        stdout,
        "stdout",
        maximum_chunk,
        sender.clone(),
        Arc::clone(&lease),
    )
    .map_err(post_fork_error)?;
    let stderr_thread = spawn_reader(
        stderr,
        "stderr",
        maximum_chunk,
        sender.clone(),
        Arc::clone(&lease),
    )
    .map_err(post_fork_error)?;
    let mut workers = vec![stdout_thread, stderr_thread];
    if let Some(writer) = spawn_initial_writer(
        Arc::clone(&guard.lifecycle),
        Arc::clone(&input),
        request.initial_stdin.clone(),
        sender.clone(),
        Arc::clone(&lease),
    )
    .map_err(post_fork_error)?
    {
        workers.push(writer);
    }
    let lifecycle = Arc::clone(&guard.lifecycle);
    spawn_reaper(guard, workers, sender, lease).map_err(post_fork_error)?;
    Ok(SpawnedProcess {
        control: Arc::new(ProcessControl {
            pid,
            process_group: identity.process_group,
            session_id: identity.session_id,
            start_time_ticks: identity.start_time_ticks,
            boot_id_sha256: identity.boot_id_sha256,
            pty: false,
            input,
            pty_master: None,
            pty_eof_sent: AtomicBool::new(false),
            lifecycle,
        }),
        events: receiver,
    })
}

fn spawn_pty(
    request: &JobStartRequest,
    size: PtySize,
    maximum_chunk: usize,
    inherited: &[(OsString, OsString)],
    lease: Arc<ProcessLease>,
) -> Result<SpawnedProcess> {
    if size.rows == 0 || size.cols == 0 {
        return Err(JobRuntimeError::InvalidRequest(
            "PTY rows and cols must be non-zero".to_string(),
        ));
    }
    let (master, slave) = open_pty(size)?;
    let slave_raw = slave.as_raw_fd();
    let stdin_slave = slave
        .try_clone()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    let stdout_slave = slave
        .try_clone()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    let stderr_slave = slave
        .try_clone()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    let mut command = base_command(request, inherited)?;
    command
        .stdin(Stdio::from(stdin_slave))
        .stdout(Stdio::from(stdout_slave))
        .stderr(Stdio::from(stderr_slave));
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave_raw, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != parent_pid {
                    return Err(std::io::Error::from_raw_os_error(libc::EPIPE));
                }
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|error| JobRuntimeError::Spawn(error.to_string()))?;
    let mut guard = SpawnGuard::new(child);
    guard._process_lease = Some(Arc::clone(&lease));
    let identity = capture_process_identity(guard.pid).map_err(|error| {
        post_fork_error(JobRuntimeError::Io(format!(
            "failed to capture child process identity: {error}"
        )))
    })?;
    guard.bind_identity(identity.clone());
    let pid = guard.pid;
    drop(slave);
    let master = Arc::new(master);
    let reader = master
        .try_clone()
        .map_err(|error| post_fork_error(JobRuntimeError::Io(error.to_string())))?;
    let writer = master
        .try_clone()
        .map_err(|error| post_fork_error(JobRuntimeError::Io(error.to_string())))?;
    let input = Arc::new(Mutex::new(Some(InputHandle::Pty(writer))));
    let (sender, receiver) = sync_channel(PROCESS_EVENT_QUEUE);
    let reader_thread = spawn_reader(
        reader,
        "pty",
        maximum_chunk,
        sender.clone(),
        Arc::clone(&lease),
    )
    .map_err(post_fork_error)?;
    let mut workers = vec![reader_thread];
    if let Some(writer) = spawn_initial_writer(
        Arc::clone(&guard.lifecycle),
        Arc::clone(&input),
        request.initial_stdin.clone(),
        sender.clone(),
        Arc::clone(&lease),
    )
    .map_err(post_fork_error)?
    {
        workers.push(writer);
    }
    let lifecycle = Arc::clone(&guard.lifecycle);
    spawn_reaper(guard, workers, sender, lease).map_err(post_fork_error)?;
    Ok(SpawnedProcess {
        control: Arc::new(ProcessControl {
            pid,
            process_group: identity.process_group,
            session_id: identity.session_id,
            start_time_ticks: identity.start_time_ticks,
            boot_id_sha256: identity.boot_id_sha256,
            pty: true,
            input,
            pty_master: Some(master),
            pty_eof_sent: AtomicBool::new(false),
            lifecycle,
        }),
        events: receiver,
    })
}

fn base_command(request: &JobStartRequest, inherited: &[(OsString, OsString)]) -> Result<Command> {
    let mut command = match &request.invocation {
        JobInvocation::Command { command: value } => {
            let mut command = Command::new(&request.shell_executable);
            command.arg("-c").arg(value);
            command
        }
        JobInvocation::Argv { argv } => {
            let executable = argv
                .first()
                .ok_or_else(|| JobRuntimeError::InvalidRequest("job argv is empty".to_string()))?;
            let mut command = Command::new(executable);
            command.args(&argv[1..]);
            command
        }
    };
    command.env_clear();
    command.envs(inherited.iter().map(|(key, value)| (key, value)));
    if let Some(cwd) = &request.cwd {
        command.current_dir(cwd);
    }
    apply_environment(&mut command, &request.env);
    Ok(command)
}

/// Capture the allowlist before accepted/hash staging. Command must consume
/// this exact snapshot; a later host environment mutation cannot widen it.
/// std::env::var_os itself allocates before we can inspect capacity, so this
/// is not a preallocation guarantee against arbitrary in-process host code.
pub(crate) fn inherited_environment() -> Result<Vec<(OsString, OsString)>> {
    let mut output = Vec::with_capacity(JOB_INHERITED_ENV_ALLOWLIST.len());
    let mut bytes = JOB_INHERITED_ENV_ALLOWLIST.len() * 128;
    for &key in JOB_INHERITED_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            bytes = bytes.checked_add(value.capacity()).ok_or_else(|| {
                JobRuntimeError::InvalidRequest(
                    "inherited job environment exceeds owned memory bound".to_string(),
                )
            })?;
            if value.capacity() > MAX_INHERITED_ENV_VALUE_BYTES || bytes > MAX_INHERITED_ENV_BYTES {
                return Err(JobRuntimeError::InvalidRequest(
                    "inherited job environment exceeds owned memory bound".to_string(),
                ));
            }
            output.push((OsString::from(key), value));
        }
    }
    Ok(output)
}

fn apply_environment(command: &mut Command, env: &BTreeMap<String, Option<String>>) {
    for (key, value) in env {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }
}

pub(crate) fn validate_start(request: &JobStartRequest) -> Result<()> {
    validate_path(&request.shell_executable, "shell executable")?;
    if let Some(cwd) = &request.cwd {
        validate_path(cwd, "cwd")?;
    }
    match &request.invocation {
        JobInvocation::Command { command } => {
            if command.is_empty() || command.as_bytes().contains(&0) {
                return Err(JobRuntimeError::InvalidRequest(
                    "job command is empty or contains NUL".to_string(),
                ));
            }
        }
        JobInvocation::Argv { argv } => {
            if argv.is_empty()
                || argv[0].is_empty()
                || argv.iter().any(|argument| argument.as_bytes().contains(&0))
            {
                return Err(JobRuntimeError::InvalidRequest(
                    "job argv is empty or contains an invalid element".to_string(),
                ));
            }
        }
    }
    if request
        .pty
        .is_some_and(|size| size.rows == 0 || size.cols == 0)
    {
        return Err(JobRuntimeError::InvalidRequest(
            "PTY rows and cols must be non-zero".to_string(),
        ));
    }
    for (key, value) in &request.env {
        if key.is_empty() || key.contains('=') || key.as_bytes().contains(&0) {
            return Err(JobRuntimeError::InvalidRequest(
                "job environment key is invalid".to_string(),
            ));
        }
        if value
            .as_deref()
            .is_some_and(|value| value.as_bytes().contains(&0))
        {
            return Err(JobRuntimeError::InvalidRequest(
                "job environment value contains NUL".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_path(path: &Path, label: &str) -> Result<()> {
    if path.as_os_str().is_empty() || path.as_os_str().as_bytes().contains(&0) {
        return Err(JobRuntimeError::InvalidRequest(format!(
            "{label} is empty or contains NUL"
        )));
    }
    Ok(())
}

fn write_input(handle: &mut InputHandle, bytes: &[u8]) -> Result<()> {
    let fd = match handle {
        InputHandle::Pipe(stdin) => stdin.as_raw_fd(),
        InputHandle::Pty(master) => master.as_raw_fd(),
    };
    write_nonblocking_fd(fd, bytes)
}

/// Write a bounded byte slice without ever blocking on a child that has
/// stopped reading.  The original descriptor flags are restored before this
/// function returns, so PTY/pipe ownership semantics remain unchanged for
/// the child and for subsequent controls.
fn write_nonblocking_fd(fd: i32, bytes: &[u8]) -> Result<()> {
    let original_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if original_flags < 0 {
        return Err(JobRuntimeError::Io(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags | libc::O_NONBLOCK) } < 0 {
        return Err(JobRuntimeError::Io(
            std::io::Error::last_os_error().to_string(),
        ));
    }

    let write_result = write_nonblocking_loop(fd, bytes);
    let restore_result = unsafe { libc::fcntl(fd, libc::F_SETFL, original_flags) };
    if restore_result < 0 {
        let restore_error = std::io::Error::last_os_error();
        return match write_result {
            Ok(()) => Err(JobRuntimeError::Io(format!(
                "failed to restore stdin descriptor flags: {restore_error}"
            ))),
            Err(error) => Err(JobRuntimeError::Io(format!(
                "{error}; failed to restore stdin descriptor flags: {restore_error}"
            ))),
        };
    }
    write_result
}

fn write_nonblocking_loop(fd: i32, bytes: &[u8]) -> Result<()> {
    write_nonblocking_loop_with(fd, bytes, |fd, remaining| unsafe {
        libc::write(
            fd,
            remaining.as_ptr().cast::<libc::c_void>(),
            remaining.len(),
        )
    })
}

fn write_nonblocking_loop_with<F>(fd: i32, bytes: &[u8], mut write: F) -> Result<()>
where
    F: FnMut(i32, &[u8]) -> isize,
{
    let deadline = Instant::now()
        .checked_add(INPUT_WRITE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut offset = 0usize;
    while offset < bytes.len() {
        if Instant::now() >= deadline {
            return Err(JobRuntimeError::Control(
                "stdin write deadline exceeded; partial effect may exist".to_string(),
            ));
        }
        let remaining = &bytes[offset..];
        let written = write(fd, remaining);
        if Instant::now() >= deadline {
            return Err(JobRuntimeError::Control(
                "stdin write deadline exceeded; partial effect may exist".to_string(),
            ));
        }
        if written > 0 {
            let written = usize::try_from(written).map_err(|_| {
                JobRuntimeError::Io("stdin write returned an invalid byte count".to_string())
            })?;
            offset = offset.saturating_add(written);
            continue;
        }
        if written == 0 {
            return Err(JobRuntimeError::Io(
                "stdin write returned zero bytes".to_string(),
            ));
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {
                let remaining_duration = deadline.saturating_duration_since(Instant::now());
                if remaining_duration.is_zero() {
                    return Err(JobRuntimeError::Control(
                        "stdin write timed out while child was not reading".to_string(),
                    ));
                }
                let timeout_ms =
                    remaining_duration.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
                let mut poll_fd = libc::pollfd {
                    fd,
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let polled = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
                if polled == 0 {
                    return Err(JobRuntimeError::Control(
                        "stdin write timed out while child was not reading".to_string(),
                    ));
                }
                if polled < 0 {
                    let poll_error = std::io::Error::last_os_error();
                    if poll_error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(JobRuntimeError::Io(poll_error.to_string()));
                }
                if poll_fd.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                    return Err(JobRuntimeError::Io(
                        "stdin descriptor became invalid while writing".to_string(),
                    ));
                }
            }
            _ => return Err(JobRuntimeError::Io(error.to_string())),
        }
    }
    if Instant::now() >= deadline {
        return Err(JobRuntimeError::Control(
            "stdin final write exceeded deadline; partial effect may exist".to_string(),
        ));
    }
    Ok(())
}

fn spawn_initial_writer(
    lifecycle: Arc<ProcessLifecycle>,
    input: Arc<Mutex<Option<InputHandle>>>,
    bytes: Vec<u8>,
    sender: SyncSender<InternalProcessEvent>,
    lease: Arc<ProcessLease>,
) -> Result<Option<ProcessWorker>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = thread::Builder::new()
        .name("owner-open-job-initial-stdin".to_string())
        .spawn(move || {
            let _process_lease = lease;
            // Captured buffers become locals, dropped before the lease on every exit.
            let owned_input = bytes;
            let owned_sender = sender;
            let owned_input_handle = input;
            if worker_stop.load(Ordering::Acquire) {
                return;
            }
            let result = (|| {
                let _effect_gate = lifecycle.control()?;
                let mut guard = owned_input_handle
                    .lock()
                    .map_err(|_| JobRuntimeError::StatePoisoned)?;
                let handle = guard.as_mut().ok_or(JobRuntimeError::NotLive)?;
                write_input(handle, &owned_input)
            })();
            if let Err(error) = result {
                let _ = send_process_event(
                    &owned_sender,
                    InternalProcessEvent::InputFailed {
                        error: error.to_string(),
                    },
                    &worker_stop,
                );
            }
        })
        .map_err(|error| {
            JobRuntimeError::Io(format!("failed to spawn initial stdin writer: {error}"))
        })?;
    Ok(Some(ProcessWorker {
        handle: Some(handle),
        stop,
    }))
}

fn open_pty(size: PtySize) -> Result<(File, File)> {
    let mut master = -1;
    let mut slave = -1;
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &winsize,
        )
    };
    if result != 0 {
        return Err(JobRuntimeError::Io(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if let Err(error) = set_cloexec(master).and_then(|_| set_cloexec(slave)) {
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(error);
    }
    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    Ok((master, slave))
}

fn set_cloexec(fd: i32) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(JobRuntimeError::Io(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

fn post_fork_error(error: JobRuntimeError) -> JobRuntimeError {
    match error {
        JobRuntimeError::SpawnAfterFork(_) => error,
        other => JobRuntimeError::SpawnAfterFork(other.to_string()),
    }
}

fn capture_process_identity(pid: u32) -> std::io::Result<ProcessIdentity> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let (start_time_ticks, process_group, session_id) = read_proc_stat_identity(pid)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "child exited before process identity could be captured",
                )
            })?;
        let boot_id_sha256 = Some(read_boot_id_sha256()?);
        Ok(ProcessIdentity {
            pid,
            process_group,
            session_id,
            start_time_ticks: Some(start_time_ticks),
            boot_id_sha256,
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let process = libc::pid_t::try_from(pid)
            .map_err(|_| std::io::Error::other("child pid does not fit pid_t"))?;
        let process_group = unsafe { libc::getpgid(process) };
        if process_group <= 0 {
            return Err(std::io::Error::last_os_error());
        }
        let session_id = unsafe { libc::getsid(process) };
        if session_id <= 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ProcessIdentity {
            pid,
            process_group: u32::try_from(process_group)
                .map_err(|_| std::io::Error::other("invalid process group"))?,
            session_id: u32::try_from(session_id)
                .map_err(|_| std::io::Error::other("invalid session id"))?,
            start_time_ticks: None,
            boot_id_sha256: None,
        })
    }
}

fn observe_process_identity(pid: u32) -> std::io::Result<Option<ProcessIdentity>> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let Some((start_time_ticks, process_group, session_id)) = read_proc_stat_identity(pid)?
        else {
            return Ok(None);
        };
        Ok(Some(ProcessIdentity {
            pid,
            process_group,
            session_id,
            start_time_ticks: Some(start_time_ticks),
            boot_id_sha256: Some(read_boot_id_sha256()?),
        }))
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let process = libc::pid_t::try_from(pid)
            .map_err(|_| std::io::Error::other("child pid does not fit pid_t"))?;
        let process_group = unsafe { libc::getpgid(process) };
        if process_group <= 0 {
            let error = std::io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let session_id = unsafe { libc::getsid(process) };
        if session_id <= 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(ProcessIdentity {
            pid,
            process_group: u32::try_from(process_group)
                .map_err(|_| std::io::Error::other("invalid process group"))?,
            session_id: u32::try_from(session_id)
                .map_err(|_| std::io::Error::other("invalid session id"))?,
            start_time_ticks: None,
            boot_id_sha256: None,
        }))
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_proc_stat_identity(pid: u32) -> std::io::Result<Option<(u64, u32, u32)>> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    parse_proc_stat_identity(&stat).map(Some)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_proc_stat_identity(stat: &str) -> std::io::Result<(u64, u32, u32)> {
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| std::io::Error::other("proc stat omitted command terminator"))?;
    let fields = stat
        .get(command_end + 1..)
        .ok_or_else(|| std::io::Error::other("proc stat is truncated"))?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    // The first item after the command is field 3 (state): pgrp is field 5,
    // session is field 6, and starttime is field 22.
    let process_group = fields
        .get(2)
        .ok_or_else(|| std::io::Error::other("proc stat omitted process group"))?
        .parse::<u32>()
        .map_err(|_| std::io::Error::other("proc stat process group is invalid"))?;
    let session_id = fields
        .get(3)
        .ok_or_else(|| std::io::Error::other("proc stat omitted session id"))?
        .parse::<u32>()
        .map_err(|_| std::io::Error::other("proc stat session id is invalid"))?;
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(|| std::io::Error::other("proc stat omitted start time"))?
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("proc stat start time is invalid"))?;
    if process_group == 0 || session_id == 0 || start_time_ticks == 0 {
        return Err(std::io::Error::other("proc stat identity is zero"));
    }
    Ok((start_time_ticks, process_group, session_id))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_boot_id_sha256() -> std::io::Result<String> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot_id = boot_id.trim();
    let valid = boot_id.len() == 36
        && boot_id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(byte, b'a'..=b'f' | b'A'..=b'F')
            }
        });
    if !valid {
        return Err(std::io::Error::other("kernel boot identity is malformed"));
    }
    Ok(hex_lower(&Sha256::digest(boot_id.as_bytes())))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn identity_matches(expected: &ProcessIdentity, observed: &ProcessIdentity) -> bool {
    expected.pid == observed.pid
        && expected.process_group == observed.process_group
        && expected.session_id == observed.session_id
        && expected.start_time_ticks == observed.start_time_ticks
        && expected.boot_id_sha256 == observed.boot_id_sha256
}

/// Return a process-group target for a guarded abort only after the child
/// identity is present and still live.  In particular, `None` means identity
/// capture failed and must never be interpreted as "use the raw PID".
#[cfg(test)]
fn guarded_group_signal_target(identity: Option<&ProcessIdentity>) -> Option<u32> {
    let identity = identity?;
    ensure_bound_process_group(identity)
        .ok()
        .map(|()| identity.process_group)
}

fn ensure_bound_process_group(identity: &ProcessIdentity) -> std::result::Result<(), String> {
    let observed = observe_process_identity(identity.pid)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            "original process leader anchor is unavailable; group cleanup uncertain".to_string()
        })?;
    if !identity_matches(identity, &observed) {
        return Err("job process identity changed before group cleanup".to_string());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn ensure_sigchld_ownership_configuration() -> std::io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(std::io::Error::other(
            "exclusive child wait ownership requires default SIGCHLD without SA_NOCLDWAIT",
        ));
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn ensure_sigchld_ownership_configuration() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "retained child anchor requires Linux/Android waitid WNOWAIT",
    ))
}

fn observe_owned_child(pid: u32, nonblocking: bool) -> std::io::Result<bool> {
    observe_owned_child_status(pid, nonblocking).map(|status| status.is_some())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn observe_owned_child_status(pid: u32, nonblocking: bool) -> std::io::Result<Option<ExitStatus>> {
    ensure_sigchld_ownership_configuration()?;
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let flags = libc::WEXITED | libc::WNOWAIT | if nonblocking { libc::WNOHANG } else { 0 };
    let deadline = Instant::now() + PROCESS_GROUP_SCAN_BUDGET;
    loop {
        if nonblocking && Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "child wait ownership observation deadline exceeded",
            ));
        }
        let result = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags) };
        if nonblocking && Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "child wait ownership observation completed too late",
            ));
        }
        if result == 0 {
            let observed_pid = unsafe { info.si_pid() };
            if observed_pid == 0 {
                return Ok(None);
            }
            if observed_pid != pid as libc::pid_t {
                return Err(std::io::Error::other("waitid child identity differs"));
            }
            let status = unsafe { info.si_status() };
            let raw = match info.si_code {
                libc::CLD_EXITED => status << 8,
                libc::CLD_KILLED => status,
                libc::CLD_DUMPED => status | 0x80,
                _ => return Err(std::io::Error::other("waitid terminal kind is invalid")),
            };
            return Ok(Some(ExitStatus::from_raw(raw)));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn observe_owned_child_status(
    _pid: u32,
    _nonblocking: bool,
) -> std::io::Result<Option<ExitStatus>> {
    ensure_sigchld_ownership_configuration()?;
    unreachable!()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_proc_group_state(stat: &str) -> std::io::Result<Option<(u32, u32, u8)>> {
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| std::io::Error::other("proc stat omitted command terminator"))?;
    let fields = stat
        .get(command_end + 1..)
        .ok_or_else(|| std::io::Error::other("proc stat is truncated"))?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let state = fields
        .first()
        .filter(|field| field.len() == 1)
        .and_then(|field| field.bytes().next())
        .filter(|state| b"RSDZTtXxKWPI".contains(state))
        .ok_or_else(|| std::io::Error::other("proc stat state is invalid"))?;
    let process_group = fields
        .get(2)
        .ok_or_else(|| std::io::Error::other("proc stat omitted process group"))?
        .parse::<u32>()
        .map_err(|_| std::io::Error::other("proc stat process group is invalid"))?;
    let session_id = fields
        .get(3)
        .ok_or_else(|| std::io::Error::other("proc stat omitted session id"))?
        .parse::<u32>()
        .map_err(|_| std::io::Error::other("proc stat session id is invalid"))?;
    if process_group == 0 || session_id == 0 {
        return Ok(None);
    }
    Ok(Some((process_group, session_id, state)))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_proc_task_stat(path: &Path) -> std::io::Result<Option<String>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut stat = String::new();
    file.take(8193).read_to_string(&mut stat)?;
    if stat.len() > 8192 {
        return Err(std::io::Error::other("proc task stat exceeds bounded size"));
    }
    Ok(Some(stat))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_group_is_quiet(
    identity: &ProcessIdentity,
    deadline: Instant,
) -> std::result::Result<bool, String> {
    process_group_is_quiet_with(identity, deadline, read_proc_task_stat)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn process_group_is_quiet_with<F>(
    identity: &ProcessIdentity,
    deadline: Instant,
    mut read_stat: F,
) -> std::result::Result<bool, String>
where
    F: FnMut(&Path) -> std::io::Result<Option<String>>,
{
    let deadline = deadline.min(Instant::now() + PROCESS_GROUP_SCAN_BUDGET);
    ensure_bound_process_group(identity)?;
    let entries = fs::read_dir("/proc").map_err(|error| error.to_string())?;
    let mut live = false;
    let require_deadline = || {
        if Instant::now() >= deadline {
            Err("job process-group observation exceeded deadline".to_string())
        } else {
            Ok(())
        }
    };
    for entry in entries {
        require_deadline()?;
        let entry = entry.map_err(|error| error.to_string())?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(stat) = read_stat(&entry.path().join("stat"))
            .map_err(|error| format!("incomplete job process-group scan: {error}"))?
        else {
            require_deadline()?;
            continue;
        };
        require_deadline()?;
        let Some((pgid, sid, state)) =
            parse_proc_group_state(&stat).map_err(|error| error.to_string())?
        else {
            continue;
        };
        if pgid != identity.process_group || sid != identity.session_id {
            continue;
        }
        if !matches!(state, b'Z' | b'X' | b'x') {
            live = true;
        }
        // A TGID leader can be Z while other threads are live. Linux group
        // membership is shared by its task group, so inspect every task of
        // every matching process, including zombie process leaders.
        let tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
            Ok(tasks) => tasks,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                require_deadline()?;
                continue;
            }
            Err(error) => return Err(format!("incomplete job task scan: {error}")),
        };
        for task in tasks {
            require_deadline()?;
            let task = task.map_err(|error| error.to_string())?;
            let Some(tid) = task
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                return Err("proc task entry is not a numeric TID".to_string());
            };
            let Some(stat) = read_stat(&task.path().join("stat"))
                .map_err(|error| format!("incomplete job task observation: {error}"))?
            else {
                require_deadline()?;
                continue;
            };
            require_deadline()?;
            let Some((task_pgid, task_sid, task_state)) =
                parse_proc_group_state(&stat).map_err(|error| error.to_string())?
            else {
                return Err(
                    "userspace group task has zero process group/session identity".to_string(),
                );
            };
            if task_pgid != pgid || task_sid != sid {
                return Err(format!("job task {tid} group/session changed during scan"));
            }
            if !matches!(task_state, b'Z' | b'X' | b'x') {
                live = true;
            }
        }
    }
    ensure_bound_process_group(identity)?;
    require_deadline()?;
    Ok(!live)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn process_group_is_quiet(
    _identity: &ProcessIdentity,
    _deadline: Instant,
) -> std::result::Result<bool, String> {
    Err("complete retained-anchor group scan requires Linux/Android procfs".to_string())
}

fn spawn_reader<R>(
    reader: R,
    stream: &'static str,
    maximum_chunk: usize,
    sender: SyncSender<InternalProcessEvent>,
    lease: Arc<ProcessLease>,
) -> Result<ProcessWorker>
where
    R: Read + AsRawFd + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = thread::Builder::new()
        .name(format!("owner-open-job-{stream}"))
        .spawn(move || {
            let _process_lease = lease;
            let mut owned_reader = reader;
            let owned_sender = sender;
            let mut buffer = vec![0_u8; maximum_chunk];
            loop {
                if worker_stop.load(Ordering::Acquire) {
                    return;
                }
                // Do not block forever in Read::read when a descendant keeps
                // an inherited output descriptor open.  Polling with a short
                // bound lets the reaper request cooperative shutdown and
                // still drains normal output as it arrives.
                let mut poll_fd = libc::pollfd {
                    fd: owned_reader.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                };
                let timeout_ms =
                    READER_POLL_INTERVAL.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
                let polled = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
                if polled < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    let _ = send_process_event(
                        &owned_sender,
                        InternalProcessEvent::ReaderFailed {
                            stream: stream.to_string(),
                            error: error.to_string(),
                        },
                        &worker_stop,
                    );
                    return;
                }
                if polled == 0 {
                    continue;
                }
                if worker_stop.load(Ordering::Acquire) {
                    return;
                }
                if poll_fd.revents & libc::POLLNVAL != 0 {
                    let _ = send_process_event(
                        &owned_sender,
                        InternalProcessEvent::ReaderFailed {
                            stream: stream.to_string(),
                            error: "output descriptor became invalid".to_string(),
                        },
                        &worker_stop,
                    );
                    return;
                }
                match owned_reader.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(read) => {
                        if !send_process_event(
                            &owned_sender,
                            InternalProcessEvent::Output {
                                stream: stream.to_string(),
                                bytes: buffer[..read].to_vec(),
                            },
                            &worker_stop,
                        ) {
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) if stream == "pty" && error.raw_os_error() == Some(libc::EIO) => {
                        return;
                    }
                    Err(error) => {
                        let _ = send_process_event(
                            &owned_sender,
                            InternalProcessEvent::ReaderFailed {
                                stream: stream.to_string(),
                                error: error.to_string(),
                            },
                            &worker_stop,
                        );
                        return;
                    }
                }
            }
        })
        .map_err(|error| {
            JobRuntimeError::Io(format!("failed to spawn {stream} reader: {error}"))
        })?;
    Ok(ProcessWorker {
        handle: Some(handle),
        stop,
    })
}

/// Send a process event without allowing a full bounded queue to strand the
/// reader. The stop flag is checked between finite `try_send` attempts so the
/// reaper can always release workers during cleanup.
fn send_process_event(
    sender: &SyncSender<InternalProcessEvent>,
    mut event: InternalProcessEvent,
    stop: &AtomicBool,
) -> bool {
    loop {
        match sender.try_send(event) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                event = returned;
                if stop.load(Ordering::Acquire) {
                    return false;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn spawn_reaper(
    guard: SpawnGuard,
    workers: Vec<ProcessWorker>,
    sender: SyncSender<InternalProcessEvent>,
    lease: Arc<ProcessLease>,
) -> Result<()> {
    spawn_reaper_with_cleanup(guard, workers, sender, lease, cleanup_process_group)
}

fn spawn_reaper_with_cleanup<F>(
    guard: SpawnGuard,
    workers: Vec<ProcessWorker>,
    sender: SyncSender<InternalProcessEvent>,
    lease: Arc<ProcessLease>,
    cleanup: F,
) -> Result<()>
where
    F: FnOnce(&ProcessIdentity) -> std::result::Result<(), String> + Send + 'static,
{
    let pid = guard.pid;
    let identity = guard
        .identity
        .clone()
        .ok_or_else(|| JobRuntimeError::Io("child process identity was not bound".to_string()))?;
    thread::Builder::new()
        .name(format!("owner-open-job-reaper-{pid}"))
        .spawn(move || {
            let _process_lease = lease;
            let owned_guard = guard;
            let owned_workers = workers;
            let owned_sender = sender;
            // waitid WNOWAIT observes exit without consuming the anchor.
            // All effects share the retirement gate; close it before group
            // cleanup, and finish it before any consuming Child.wait.
            let observed = observe_owned_child_status(pid, false).and_then(|status| status.ok_or_else(|| std::io::Error::other("blocking WNOWAIT observation was not terminal")));
            let mut cleanup_errors = Vec::new();
            let status = match owned_guard.lifecycle.begin_retirement() {
                Ok(poisoned) => {
                    if poisoned { cleanup_errors.push("process retirement gate was poisoned".to_string()); }
                    let cleanup_proven = if observed.is_ok() {
                        match cleanup(&identity) {
                            Ok(()) => true,
                            Err(error) => { cleanup_errors.push(format!("{error}; unreaped leader/identity/lease retained for bounded-attempt recovery")); false }
                        }
                    } else {
                        cleanup_errors.push("child wait ownership/anchor could not be observed; no group signals attempted; child/lease quarantined".to_string());
                        false
                    };
                    match owned_guard.lifecycle.finish_retirement() {
                        Ok(poisoned) => {
                            if poisoned { cleanup_errors.push("process retirement gate was poisoned".to_string()); }
                            match observed {
                                Ok(_status) if cleanup_proven => owned_guard.wait(),
                                Ok(status) => Ok(status), // WNOWAIT status; guard remains owned for recovery.
                                Err(error) => Err(error),
                            }
                        }
                        Err(error) => { cleanup_errors.push(error); Err(std::io::Error::other("retirement barrier did not close")) }
                    }
                }
                Err(error) => { cleanup_errors.push(error); Err(std::io::Error::other("retirement gate unavailable; retained ownership recovery required")) }
            };
            cleanup_errors.extend(join_workers_bounded(owned_workers));
            let cleanup_error = (!cleanup_errors.is_empty()).then(|| cleanup_errors.join("; "));
            let event = match status {
                Ok(status) => InternalProcessEvent::Exited {
                    terminal_kind: if cleanup_error.is_some() {
                        // Keep the effect outcome (`exited`/`signaled`) and
                        // cleanup uncertainty in the normative terminal
                        // vocabulary.  The cleanup detail remains in the
                        // separate `cleanup_error` field and must not be
                        // hidden behind an implementation-specific label.
                        "unknown_after_cleanup_failure".to_string()
                    } else if status.signal().is_some() {
                        "signaled".to_string()
                    } else {
                        "exited".to_string()
                    },
                    exit_code: status.code(),
                    signal: status.signal(),
                    cleanup_error,
                },
                Err(error) => InternalProcessEvent::Exited {
                    terminal_kind: "reaper_error".to_string(),
                    exit_code: None,
                    signal: None,
                    cleanup_error: Some(match cleanup_error {
                        Some(cleanup) => format!("child wait failed: {error}; {cleanup}"),
                        None => format!("child wait failed: {error}"),
                    }),
                },
            };
            let _ = owned_sender.send(event);
        })
        .map(|_| ())
        .map_err(|error| JobRuntimeError::Io(format!("failed to spawn job reaper: {error}")))
}

/// Join process-I/O workers without allowing a descendant-owned descriptor to
/// wedge the lifecycle forever.  Workers first get a short natural-drain
/// window; anything still running is asked to stop and gets a bounded second
/// window.  A worker that ignores cancellation is detached and the terminal
/// event carries an explicit cleanup error, preserving truthful uncertainty.
fn join_workers_bounded(mut workers: Vec<ProcessWorker>) -> Vec<String> {
    let mut errors = Vec::new();
    let natural_deadline = Instant::now()
        .checked_add(WORKER_NATURAL_JOIN_GRACE)
        .unwrap_or_else(Instant::now);
    let mut pending = Vec::new();
    for worker in workers.drain(..) {
        if worker.is_finished() {
            if worker.join().is_err() {
                errors.push("job I/O worker panicked".to_string());
            }
        } else {
            pending.push(worker);
        }
    }
    while !pending.is_empty() && Instant::now() < natural_deadline {
        let mut still_pending = Vec::with_capacity(pending.len());
        for worker in pending {
            if worker.is_finished() {
                if worker.join().is_err() {
                    errors.push("job I/O worker panicked".to_string());
                }
            } else {
                still_pending.push(worker);
            }
        }
        pending = still_pending;
        if !pending.is_empty() {
            thread::sleep(Duration::from_millis(5));
        }
    }
    if pending.is_empty() {
        return errors;
    }

    for worker in &pending {
        worker.request_stop();
    }
    let cancel_deadline = Instant::now()
        .checked_add(WORKER_CANCEL_JOIN_GRACE)
        .unwrap_or_else(Instant::now);
    while !pending.is_empty() && Instant::now() < cancel_deadline {
        let mut still_pending = Vec::with_capacity(pending.len());
        for worker in pending {
            if worker.is_finished() {
                if worker.join().is_err() {
                    errors.push("job I/O worker panicked".to_string());
                }
            } else {
                still_pending.push(worker);
            }
        }
        pending = still_pending;
        if !pending.is_empty() {
            thread::sleep(Duration::from_millis(10));
        }
    }
    for worker in pending {
        // Dropping the handle detaches only after the finite cancellation
        // window.  The worker's stop flag remains set; readers poll their fd,
        // and the initial writer's write helper has its own finite timeout.
        errors.push("job I/O worker did not stop within bounded cleanup grace".to_string());
        drop(worker);
    }
    errors
}

fn quiet_twice(identity: &ProcessIdentity, deadline: Instant) -> std::result::Result<bool, String> {
    if !process_group_is_quiet(identity, deadline)? {
        return Ok(false);
    }
    thread::sleep(Duration::from_millis(5));
    let quiet = process_group_is_quiet(identity, deadline)?;
    if Instant::now() >= deadline {
        return Err("process-group final quiet proof exceeded deadline".to_string());
    }
    Ok(quiet)
}

fn wait_group_quiet(
    identity: &ProcessIdentity,
    grace: Duration,
    cleanup_deadline: Instant,
) -> std::result::Result<bool, String> {
    let grace_deadline = Instant::now() + grace;
    while Instant::now() < grace_deadline {
        // The grace controls escalation, while a full /proc scan has its own
        // existing 500ms bound inside the absolute overall cleanup deadline.
        if quiet_twice(identity, cleanup_deadline)? {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(false)
}

fn cleanup_process_group(identity: &ProcessIdentity) -> std::result::Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    ensure_bound_process_group(identity)?;
    // A retained zombie keeps kill(-pgid, 0) true. Only two complete bounded
    // scans with no live same-group/session task can establish quiet.
    match quiet_twice(identity, deadline) {
        Ok(true) => return Ok(()),
        Ok(false) => {}
        Err(error) => {
            // Incomplete scans are never proof of cleanup. Still make one
            // best-effort anchored kill; never recover a lost numeric PGID.
            let kill = send_bound_process_group_signal(identity, libc::SIGKILL);
            return Err(format!("{error}; bounded cleanup kill result: {kill:?}"));
        }
    }
    send_bound_process_group_signal(identity, libc::SIGTERM)?;
    let term_error = match wait_group_quiet(identity, DESCENDANT_TERM_GRACE, deadline) {
        Ok(true) => return Ok(()),
        Ok(false) => None,
        Err(error) => Some(error),
    };
    send_bound_process_group_signal(identity, libc::SIGKILL)?;
    let kill_result = wait_group_quiet(identity, DESCENDANT_KILL_GRACE, deadline);
    if let Some(error) = term_error {
        return Err(format!(
            "{error}; cleanup quiet after kill: {kill_result:?}"
        ));
    }
    if Instant::now() >= deadline {
        return Err("process-group final cleanup deadline exceeded".to_string());
    }
    match kill_result {
        Ok(true) => Ok(()),
        Ok(false) => Err("live process-group members remain after SIGKILL grace".to_string()),
        Err(error) => Err(error),
    }
}

fn send_process_group_signal(process_group: u32, signal: i32) -> std::result::Result<(), String> {
    let process_group = i32::try_from(process_group)
        .map_err(|_| "child pid does not fit a POSIX process-group id".to_string())?;
    let result = unsafe { libc::kill(-process_group, signal) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(format!("process group signal {signal} failed: {error}"))
    }
}

/// Recheck the complete bound process identity immediately before issuing a
/// process-group signal.  POSIX exposes only a numeric PGID for `kill(2)`, so
/// the check and syscall cannot be made one kernel-atomic operation; keeping
/// them in one helper makes every owner-open group signal take the narrowest
/// possible, fail-closed path and avoids callers accidentally skipping the
/// final generation check.
fn send_bound_process_group_signal(
    identity: &ProcessIdentity,
    signal: i32,
) -> std::result::Result<(), String> {
    observe_owned_child(identity.pid, true)
        .map_err(|error| format!("direct-child wait ownership is unavailable: {error}"))?;
    ensure_bound_process_group(identity)?;
    send_process_group_signal(identity.process_group, signal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn proc_stat_identity_parser_handles_parentheses_and_generation_fields() {
        let mut fields = vec![
            "S".to_string(),
            "0".to_string(),
            "1234".to_string(),
            "5678".to_string(),
        ];
        while fields.len() < 19 {
            fields.push("0".to_string());
        }
        fields.push("4242".to_string());
        let stat = format!("17 (worker (nested)) {}", fields.join(" "));
        assert_eq!(parse_proc_stat_identity(&stat).unwrap(), (4242, 1234, 5678));
    }

    #[test]
    fn current_process_identity_is_nonzero_and_stable() {
        let identity = capture_process_identity(std::process::id()).unwrap();
        assert_eq!(identity.pid, std::process::id());
        assert!(identity.process_group > 0);
        assert!(identity.session_id > 0);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert!(identity.start_time_ticks.is_some_and(|value| value > 0));
            assert!(
                identity
                    .boot_id_sha256
                    .as_deref()
                    .is_some_and(|value| value.len() == 64)
            );
        }
        assert!(identity_matches(&identity, &identity));
        let mut changed = identity.clone();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            changed.start_time_ticks = changed
                .start_time_ticks
                .map(|value| value.saturating_add(1));
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        {
            changed.process_group = changed.process_group.saturating_add(1);
        }
        assert!(!identity_matches(&identity, &changed));
        assert!(ensure_bound_process_group(&changed).is_err());
    }

    #[test]
    fn post_fork_errors_are_explicitly_effectful() {
        let error = post_fork_error(JobRuntimeError::Io("reader setup failed".to_string()));
        assert!(
            matches!(error, JobRuntimeError::SpawnAfterFork(message) if message.contains("reader setup failed"))
        );
    }

    #[test]
    fn spawn_guard_without_identity_never_targets_raw_pid_as_a_group() {
        // A missing identity is an abort-time uncertainty.  The guard may
        // still kill its exact Child handle, but it must not broadcast to
        // `-pid`, which could now denote an unrelated process group.
        assert_eq!(guarded_group_signal_target(None), None);
    }

    fn reconcile_quarantine_fixture(pid: u32) -> String {
        // Explicit test-only offline reconciliation after fixture teardown.
        // No production method unlocks quarantine from elapsed/PID/no-op.
        let (mut child, _identity, lifecycle, _lease, reason) = {
            let mut quarantine = UNCERTAIN_CHILD_QUARANTINE
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let index = quarantine
                .iter()
                .position(|entry| entry.0.id() == pid)
                .expect("fixture quarantine exists");
            quarantine.remove(index)
        };
        assert!(lifecycle.retirement_requested.load(Ordering::Acquire));
        let deadline = Instant::now() + Duration::from_secs(1);
        let observed = loop {
            match observe_owned_child(pid, true) {
                Ok(false) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                observed => break observed,
            }
        };
        match observed {
            Ok(true) => {
                // This explicit external fixture observer still owns the
                // unreaped child, and every owned member was torn down.
                let fixture_identity = capture_process_identity(pid).unwrap();
                assert!(
                    quiet_twice(&fixture_identity, Instant::now() + Duration::from_secs(1))
                        .unwrap()
                );
                child.wait().unwrap();
            }
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {}
            observed => panic!("fixture is not offline for reconciliation: {observed:?}"),
        }
        reason
    }

    #[test]
    fn spawn_guard_without_identity_does_not_kill_a_group_member() {
        // Exercise the Drop path itself: make an unbound leader and a second
        // process share its group.  The guard must kill only the exact Child
        // it owns; a raw `kill(-pid, SIGKILL)` fallback would also terminate
        // the surviving member.
        let mut leader_command = Command::new("/bin/sh");
        leader_command.args(["-c", "exec sleep 10"]);
        unsafe {
            leader_command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let leader = leader_command.spawn().expect("spawn process-group leader");
        let leader_pid = leader.id();

        let mut member_command = Command::new("/bin/sh");
        member_command.args(["-c", "exec sleep 10"]);
        unsafe {
            member_command.pre_exec(move || {
                let process_group = libc::pid_t::try_from(leader_pid)
                    .map_err(|_| std::io::Error::other("leader pid does not fit pid_t"))?;
                if libc::setpgid(0, process_group) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut member = match member_command.spawn() {
            Ok(member) => member,
            Err(error) => {
                let mut leader = leader;
                let _ = leader.kill();
                let _ = leader.wait();
                panic!("spawn process-group member: {error}");
            }
        };
        let member_pid = member.id();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            let observed_group = unsafe { libc::getpgid(member_pid as libc::pid_t) };
            if observed_group == leader_pid as libc::pid_t {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        let observed_group = unsafe { libc::getpgid(member_pid as libc::pid_t) };
        if observed_group != leader_pid as libc::pid_t {
            let _ = unsafe { libc::kill(member_pid as libc::pid_t, libc::SIGKILL) };
            let _ = member.wait();
            panic!(
                "member did not join leader process group (expected {}, got {})",
                leader_pid, observed_group
            );
        }

        // Deliberately leave the guard's identity unbound to model an early
        // post-spawn failure before procfs identity capture completed.
        drop(SpawnGuard::new(leader));
        let member_alive = unsafe { libc::kill(member_pid as libc::pid_t, 0) == 0 };
        // `exec` above makes the member itself the long-lived process, so an
        // exact Child kill below cannot leave a shell descendant behind.
        let _ = member.kill();
        let _ = member.wait();
        assert!(
            reconcile_quarantine_fixture(leader_pid).contains("group identity was never bound")
        );
        assert!(
            member_alive,
            "unbound SpawnGuard broadcast to the whole group"
        );
    }

    #[test]
    fn nonreading_stdin_write_is_bounded_and_restores_descriptor_flags() {
        let mut descriptors = [-1_i32; 2];
        let result = unsafe { libc::pipe(descriptors.as_mut_ptr()) };
        assert_eq!(result, 0, "create test pipe");
        let read_fd = descriptors[0];
        let write_fd = descriptors[1];
        let before = unsafe { libc::fcntl(write_fd, libc::F_GETFL) };
        assert!(before >= 0, "read initial descriptor flags");
        let started = Instant::now();
        let error = write_nonblocking_fd(write_fd, &vec![0_u8; 1024 * 1024])
            .expect_err("a pipe with no reader should hit the finite write bound");
        assert!(
            matches!(error, JobRuntimeError::Control(message) if message.contains("timed out"))
        );
        assert!(started.elapsed() < INPUT_WRITE_TIMEOUT + Duration::from_secs(1));
        let after = unsafe { libc::fcntl(write_fd, libc::F_GETFL) };
        assert_eq!(after, before, "write helper must restore descriptor flags");
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
    }
    struct OwnedTestChild(Child);
    impl Drop for OwnedTestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn leader_fixture() -> SpawnGuard {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "IFS= read -r line || :"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut guard = SpawnGuard::new(command.spawn().unwrap());
        guard.bind_identity(capture_process_identity(guard.pid).unwrap());
        guard
    }

    fn fixture_control(guard: &SpawnGuard) -> Arc<ProcessControl> {
        let identity = guard.identity.as_ref().unwrap();
        Arc::new(ProcessControl {
            pid: identity.pid,
            process_group: identity.process_group,
            session_id: identity.session_id,
            start_time_ticks: identity.start_time_ticks,
            boot_id_sha256: identity.boot_id_sha256.clone(),
            pty: false,
            input: Arc::new(Mutex::new(None)),
            pty_master: None,
            pty_eof_sent: AtomicBool::new(false),
            lifecycle: Arc::clone(&guard.lifecycle),
        })
    }

    fn assert_all_controls_retired(control: &ProcessControl) {
        assert!(matches!(
            control.write(b"forbidden"),
            Err(JobRuntimeError::NotLive)
        ));
        assert!(matches!(
            control.close_stdin(),
            Err(JobRuntimeError::NotLive)
        ));
        assert!(matches!(
            control.resize(PtySize::default()),
            Err(JobRuntimeError::NotLive)
        ));
        assert!(matches!(
            control.kill(libc::SIGKILL),
            Err(JobRuntimeError::NotLive)
        ));
    }

    #[test]
    fn retained_leader_survives_all_group_signals_then_controls_stay_retired() {
        let mut guard = leader_fixture();
        let identity = guard.identity.clone().unwrap();
        let control = fixture_control(&guard);
        let mut command = Command::new("/bin/sleep");
        command
            .arg("10")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let pgid = identity.process_group as libc::pid_t;
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, pgid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::signal(libc::SIGTERM, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut member = OwnedTestChild(command.spawn().unwrap());
        let member_pid = member.0.id();
        assert_eq!(unsafe { libc::getpgid(member_pid as libc::pid_t) }, pgid);
        drop(guard.child_mut().unwrap().stdin.take());
        assert!(observe_owned_child(guard.pid, false).unwrap());
        assert!(identity_matches(
            &identity,
            &observe_process_identity(guard.pid).unwrap().unwrap()
        ));
        guard.lifecycle.begin_retirement().unwrap();
        assert_all_controls_retired(&control);
        cleanup_process_group(&identity).unwrap();
        assert!(
            identity_matches(
                &identity,
                &observe_process_identity(guard.pid).unwrap().unwrap()
            ),
            "leader anchor survives TERM and KILL cleanup"
        );
        assert!(
            observe_owned_child(member_pid, true).unwrap(),
            "member terminal before consuming anchor"
        );
        guard.lifecycle.finish_retirement().unwrap();
        let status = guard.wait().unwrap();
        assert_eq!(status.code(), Some(0));
        assert!(observe_process_identity(identity.pid).unwrap().is_none());
        let member_status = member.0.wait().unwrap();
        assert_eq!(member_status.signal(), Some(libc::SIGKILL));
        assert_all_controls_retired(&control);
        eprintln!(
            "actual_retained_leader: wait0, member_SIGKILL, all_control_methods_rejected_before_and_after_wait"
        );
    }

    #[test]
    fn controls_reject_after_wait_before_terminal_event_can_be_delivered() {
        let mut guard = leader_fixture();
        let control = fixture_control(&guard);
        let pid = guard.pid;
        let lifecycle = Arc::clone(&guard.lifecycle);
        let (sender, receiver) = sync_channel(1);
        sender
            .send(InternalProcessEvent::Output {
                stream: "fixture".to_string(),
                bytes: b"occupy-terminal-queue".to_vec(),
            })
            .unwrap();
        drop(guard.child_mut().unwrap().stdin.take());
        spawn_reaper(
            guard,
            Vec::new(),
            sender,
            ProcessLease::acquire(1024).unwrap(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !(lifecycle.is_retired() && observe_process_identity(pid).unwrap().is_none()) {
            assert!(
                Instant::now() < deadline,
                "real reaper did not retire and consume child"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert_all_controls_retired(&control);
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            InternalProcessEvent::Output { .. }
        ));
        assert!(
            matches!(receiver.recv_timeout(Duration::from_secs(1)).unwrap(), InternalProcessEvent::Exited { terminal_kind, exit_code: Some(0), cleanup_error: None, .. } if terminal_kind == "exited")
        );
        eprintln!(
            "actual_terminal_delivery_window: leader_consumed, terminal_queue_full, cloned_controls_rejected"
        );
    }

    #[test]
    fn retirement_waits_for_the_one_admitted_effect_and_closes_new_admission() {
        let mut guard = leader_fixture();
        let control = fixture_control(&guard);
        let lifecycle = Arc::clone(&guard.lifecycle);
        let held_gate = lifecycle.control().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker_lifecycle = Arc::clone(&lifecycle);
        let worker = thread::spawn(move || {
            sender.send(worker_lifecycle.begin_retirement()).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while !lifecycle.retirement_requested.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline);
            thread::yield_now();
        }
        assert!(
            receiver.try_recv().is_err(),
            "retirement cannot pass admitted effect gate"
        );
        assert_all_controls_retired(&control);
        assert!(observe_process_identity(guard.pid).unwrap().is_some());
        // Real admitted child effect occurs while it still owns the gate.
        drop(guard.child_mut().unwrap().stdin.take());
        drop(held_gate);
        receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap();
        worker.join().unwrap();
        assert!(observe_owned_child(guard.pid, false).unwrap());
        cleanup_process_group(guard.identity.as_ref().unwrap()).unwrap();
        lifecycle.finish_retirement().unwrap();
        assert_eq!(guard.wait().unwrap().code(), Some(0));
        assert_all_controls_retired(&control);
    }

    #[test]
    fn poisoned_retirement_gate_seals_controls_and_guard_still_reaps_exact_child() {
        let guard = leader_fixture();
        let pid = guard.pid;
        let control = fixture_control(&guard);
        let lifecycle = Arc::clone(&guard.lifecycle);
        let worker_lifecycle = Arc::clone(&lifecycle);
        assert!(
            thread::spawn(move || {
                let _gate = worker_lifecycle.control().unwrap();
                panic!("intentional isolated lifecycle poison");
            })
            .join()
            .is_err()
        );
        assert!(matches!(
            control.kill(libc::SIGKILL),
            Err(JobRuntimeError::StatePoisoned)
        ));
        drop(guard);
        assert!(lifecycle.is_retired());
        assert!(observe_process_identity(pid).unwrap().is_none());
        assert_all_controls_retired(&control);
    }

    #[test]
    fn missing_original_anchor_refuses_numeric_group_fallback_with_live_member() {
        let mut guard = leader_fixture();
        let identity = guard.identity.clone().unwrap();
        let pgid = identity.process_group as libc::pid_t;
        let mut command = Command::new("/bin/sleep");
        command.arg("10");
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, pgid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut member = OwnedTestChild(command.spawn().unwrap());
        drop(guard.child_mut().unwrap().stdin.take());
        assert!(observe_owned_child(guard.pid, false).unwrap());
        // Deliberate external consumption models an unsupported competing
        // reaper, not PID reuse. Original numeric PGID is still populated.
        guard.child_mut().unwrap().wait().unwrap();
        assert!(observe_process_identity(identity.pid).unwrap().is_none());
        assert!(ensure_bound_process_group(&identity).is_err());
        assert!(send_bound_process_group_signal(&identity, libc::SIGKILL).is_err());
        assert!(
            member.0.try_wait().unwrap().is_none(),
            "lost-anchor path signaled original numeric group"
        );
        drop(guard);
        assert!(
            member.0.try_wait().unwrap().is_none(),
            "guard fallback signaled group without direct-child anchor"
        );
        member
            .0
            .kill()
            .expect("stop exact owned unsupported fixture member");
        member
            .0
            .wait()
            .expect("reap fixture member before explicit reconciliation");
        let reason = reconcile_quarantine_fixture(identity.pid);
        assert!(reason.contains("wait ownership"));
    }

    #[test]
    fn continuous_real_fd_writes_reject_late_completion_and_preserve_partial_effect() {
        let mut file = tempfile::tempfile().unwrap();
        let fd = file.as_raw_fd();
        let started = Instant::now();
        let mut calls = 0;
        let result = write_nonblocking_loop_with(fd, b"four", |fd, bytes| {
            thread::sleep(Duration::from_millis(650));
            calls += 1;
            unsafe { libc::write(fd, bytes.as_ptr().cast(), 1) }
        });
        assert!(
            matches!(result, Err(JobRuntimeError::Control(ref message)) if message.contains("deadline") && message.contains("partial"))
        );
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(
            actual.len(),
            calls,
            "real bytes remain despite returned timeout"
        );
        assert_eq!(
            actual, b"four",
            "same four real callbacks reproduce old late success but now reject"
        );
        assert!(started.elapsed() >= INPUT_WRITE_TIMEOUT);
        eprintln!(
            "actual_late_write: elapsed={:?}, calls={}, actual_bytes={:?}, result={:?}",
            started.elapsed(),
            calls,
            actual,
            result
        );
    }

    #[test]
    fn late_final_real_fd_write_is_timeout_with_unknown_effect() {
        let mut file = tempfile::tempfile().unwrap();
        let fd = file.as_raw_fd();
        let started = Instant::now();
        let result = write_nonblocking_loop_with(fd, b"done", |fd, bytes| {
            thread::sleep(INPUT_WRITE_TIMEOUT + Duration::from_millis(100));
            unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) }
        });
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut actual = Vec::new();
        file.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, b"done");
        assert!(
            matches!(result, Err(JobRuntimeError::Control(ref message)) if message.contains("partial"))
        );
        eprintln!(
            "actual_late_final_write: elapsed={:?}, actual_bytes={:?}, result={:?}",
            started.elapsed(),
            actual,
            result
        );
    }

    fn test_start_request(pty: bool, command: &str, input: Vec<u8>) -> JobStartRequest {
        use trillionnium_owner_open_job_registry::{JobKey, JobRequest, JobScope};
        JobStartRequest {
            key: JobKey::new(
                JobScope::new("session", "owner-open", "task", "turn", "stream"),
                "actual-retirement-fixture",
            ),
            request: JobRequest::new(
                "a".repeat(64),
                "b".repeat(64),
                "shell.job",
                if pty { "pty" } else { "pipe" },
                Some("rootlinux".to_string()),
            ),
            operation_id: "start".to_string(),
            invocation: JobInvocation::Command {
                command: command.to_string(),
            },
            shell_executable: "/bin/sh".into(),
            cwd: None,
            env: BTreeMap::new(),
            initial_stdin: input,
            pty: pty.then(PtySize::default),
        }
    }

    #[test]
    fn real_pipe_and_pty_reapers_close_cloned_controls() {
        for pty in [false, true] {
            let request = test_start_request(
                pty,
                "printf ready; IFS= read -r line; printf drained",
                Vec::new(),
            );
            let spawned = spawn_process(
                &request,
                1024,
                &[],
                ProcessLease::acquire(64 * 1024).unwrap(),
            )
            .unwrap();
            let control = Arc::clone(&spawned.control);
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut output = Vec::new();
            while !output.windows(5).any(|part| part == b"ready") {
                match spawned
                    .events
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap()
                {
                    InternalProcessEvent::Output { bytes, .. } => output.extend(bytes),
                    event => panic!("unexpected readiness event: {event:?}"),
                }
            }
            control.write(b"line\n").unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                match spawned
                    .events
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .unwrap()
                {
                    InternalProcessEvent::Exited {
                        exit_code: Some(0),
                        cleanup_error: None,
                        ..
                    } => break,
                    InternalProcessEvent::Output { bytes, .. } => output.extend(bytes),
                    event => panic!("unexpected terminal event: {event:?}"),
                }
            }
            assert!(output.windows(7).any(|part| part == b"drained"));
            assert_all_controls_retired(&control);
            assert!(observe_process_identity(control.pid).unwrap().is_none());
            eprintln!("actual_spawn_retirement: pty={pty}, exit0, drained, controls_closed");
        }
    }

    #[test]
    fn initial_writer_and_retirement_gate_use_one_lock_order_without_deadlock() {
        let request = test_start_request(
            false,
            "printf ready; IFS= read -r line; printf drained",
            b"initial\n".to_vec(),
        );
        let spawned = spawn_process(
            &request,
            1024,
            &[],
            ProcessLease::acquire(64 * 1024).unwrap(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut output = Vec::new();
        loop {
            match spawned
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap()
            {
                InternalProcessEvent::Output { bytes, .. } => output.extend(bytes),
                InternalProcessEvent::Exited {
                    exit_code: Some(0),
                    cleanup_error: None,
                    ..
                } => break,
                event => panic!("unexpected initial writer event: {event:?}"),
            }
        }
        assert!(output.windows(7).any(|part| part == b"drained"));
        assert_all_controls_retired(&spawned.control);
    }

    #[test]
    fn unsupported_sigchld_is_refused_in_isolated_real_process() {
        const CHILD: &str = "TRILLIONNIUM_REAL_SIGCHLD_BOUNDARY";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "process::tests::unsupported_sigchld_is_refused_in_isolated_real_process",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let mut original: libc::sigaction = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut original) },
            0
        );
        let mut action = original;
        for ignored in [true, false] {
            action.sa_sigaction = if ignored {
                libc::SIG_IGN
            } else {
                libc::SIG_DFL
            };
            action.sa_flags = if ignored { 0 } else { libc::SA_NOCLDWAIT };
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) },
                0
            );
            assert!(ensure_sigchld_ownership_configuration().is_err());
            let request = test_start_request(false, ":", Vec::new());
            assert!(
                matches!(spawn_process(&request, 1024, &[], ProcessLease::acquire(1024).unwrap()), Err(JobRuntimeError::Spawn(message)) if message.contains("SIGCHLD"))
            );
        }
        assert_eq!(
            unsafe { libc::sigaction(libc::SIGCHLD, &original, std::ptr::null_mut()) },
            0
        );
        assert!(ensure_sigchld_ownership_configuration().is_ok());
    }

    #[test]
    fn proc_scan_terminal_states_and_expired_deadline_never_fake_quiet() {
        for state in ["Z", "X", "R", "S"] {
            let stat = format!("17 (worker (nested)) {state} 1 1234 5678");
            assert_eq!(
                parse_proc_group_state(&stat).unwrap(),
                Some((1234, 5678, state.as_bytes()[0]))
            );
        }
        assert!(parse_proc_group_state("17 (bad) ? 1 1234 5678").is_err());
        let guard = leader_fixture();
        let identity = guard.identity.as_ref().unwrap();
        assert!(
            !process_group_is_quiet(identity, Instant::now() + Duration::from_secs(1)).unwrap()
        );
        assert!(process_group_is_quiet(identity, Instant::now()).is_err());
    }
    #[test]
    fn complete_task_scan_finds_live_thread_below_zombie_member_leader() {
        let mut guard = leader_fixture();
        let identity = guard.identity.clone().unwrap();
        let fixture_dir = tempfile::tempdir().unwrap();
        let fixture = fixture_dir.path().join("task_leader_fixture");
        let fixture_source = fixture_dir.path().join("task_leader_fixture.c");
        fs::write(&fixture_source, r#"#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
static void *worker(void *unused) { (void)unused; char data[16]; while (read(STDIN_FILENO, data, sizeof(data)) > 0) {} return NULL; }
int main(void) { pthread_t thread; if (pthread_create(&thread, NULL, worker, NULL) != 0) return 2; puts("ready"); fflush(stdout); pthread_exit(NULL); }
"#).unwrap();
        let compiler = Command::new("cc")
            .args(["-pthread", "-Wall", "-Wextra", "-Werror", "-O0"])
            .arg(&fixture_source)
            .arg("-o")
            .arg(&fixture)
            .output()
            .unwrap();
        assert!(
            compiler.status.success(),
            "{}",
            String::from_utf8_lossy(&compiler.stderr)
        );
        let mut command = Command::new(fixture);
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        let pgid = identity.process_group as libc::pid_t;
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, pgid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut member = OwnedTestChild(command.spawn().unwrap());
        let member_pid = member.0.id();
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(member.0.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line, "ready\n");
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let stat = fs::read_to_string(format!("/proc/{member_pid}/stat")).unwrap();
            if parse_proc_group_state(&stat).unwrap().unwrap().2 == b'Z' {
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        drop(guard.child_mut().unwrap().stdin.take());
        assert!(observe_owned_child(guard.pid, false).unwrap());
        assert!(
            !observe_owned_child(member_pid, true).unwrap(),
            "member still owns a live thread"
        );
        let quiet =
            process_group_is_quiet(&identity, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(
            !quiet,
            "complete task scan must refuse quiet with a live member thread"
        );
        guard.lifecycle.begin_retirement().unwrap();
        cleanup_process_group(&identity).unwrap();
        assert!(observe_process_identity(identity.pid).unwrap().is_some());
        assert!(observe_owned_child(member_pid, true).unwrap());
        let status = member.0.wait().unwrap();
        assert!(matches!(
            status.signal(),
            Some(libc::SIGTERM | libc::SIGKILL)
        ));
        guard.lifecycle.finish_retirement().unwrap();
        assert_eq!(guard.wait().unwrap().code(), Some(0));
        eprintln!(
            "actual_fixed_task_quiet: initial_quiet=false, member_leader_Z_with_live_task, group_signal={:?}, retained_anchor_consumed_last",
            status.signal()
        );
    }
    #[test]
    fn delayed_actual_proc_stat_observation_and_incomplete_scan_refuse_quiet() {
        let mut guard = leader_fixture();
        let identity = guard.identity.clone().unwrap();
        drop(guard.child_mut().unwrap().stdin.take());
        assert!(observe_owned_child(guard.pid, false).unwrap());
        let started = Instant::now();
        let mut actual_reads = 0;
        let result =
            process_group_is_quiet_with(&identity, started + Duration::from_millis(30), |path| {
                let stat = read_proc_task_stat(path)?;
                actual_reads += 1;
                thread::sleep(Duration::from_millis(75));
                Ok(stat)
            });
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.contains("deadline"))
        );
        assert!(actual_reads > 0);
        assert!(started.elapsed() >= Duration::from_millis(75));
        let incomplete =
            process_group_is_quiet_with(&identity, Instant::now() + Duration::from_secs(1), |_| {
                Err(std::io::Error::from_raw_os_error(libc::EACCES))
            });
        assert!(
            incomplete
                .as_ref()
                .is_err_and(|error| error.contains("incomplete"))
        );
        guard.lifecycle.begin_retirement().unwrap();
        cleanup_process_group(&identity).unwrap();
        guard.lifecycle.finish_retirement().unwrap();
        assert_eq!(guard.wait().unwrap().code(), Some(0));
        eprintln!(
            "actual_delayed_proc_scan: elapsed={:?}, reads={}, result={:?}; incomplete=EACCES_refused",
            started.elapsed(),
            actual_reads,
            result
        );
    }
    #[test]
    fn admitted_gate_timeout_retains_real_child_and_lease_until_recovery() {
        let mut guard = leader_fixture();
        let pid = guard.pid;
        let control = fixture_control(&guard);
        let lifecycle = Arc::clone(&guard.lifecycle);
        let lease = ProcessLease::acquire(1024).unwrap();
        let weak = Arc::downgrade(&lease);
        guard._process_lease = Some(lease);
        let held_gate = lifecycle.control().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            drop(guard);
            sender.send(started.elapsed()).unwrap();
        });
        let elapsed = receiver
            .recv_timeout(CONTROL_GATE_TIMEOUT + Duration::from_secs(2))
            .unwrap();
        assert!(elapsed >= CONTROL_GATE_TIMEOUT);
        assert!(
            observe_process_identity(pid).unwrap().is_some(),
            "cannot consume anchor through admitted effect"
        );
        assert!(
            weak.upgrade().is_some(),
            "recovery must retain resource ownership"
        );
        assert_all_controls_retired(&control);
        drop(held_gate);
        worker.join().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while observe_process_identity(pid).unwrap().is_some() || weak.upgrade().is_some() {
            assert!(
                Instant::now() < deadline,
                "recovery failed after admitted effect released its real gate"
            );
            thread::sleep(Duration::from_millis(5));
        }
        assert!(lifecycle.is_retired());
        assert_all_controls_retired(&control);
        eprintln!(
            "actual_gate_timeout: elapsed={elapsed:?}, anchor_and_lease_retained_until_gate_release_then_reaped"
        );
    }

    #[test]
    fn poisoned_real_reaper_emits_cleanup_uncertainty_and_blocks_all_controls() {
        let mut guard = leader_fixture();
        let control = fixture_control(&guard);
        let lifecycle = Arc::clone(&guard.lifecycle);
        let worker_lifecycle = Arc::clone(&lifecycle);
        assert!(
            thread::spawn(move || {
                let _held = worker_lifecycle.control().unwrap();
                panic!("intentional reaper poison");
            })
            .join()
            .is_err()
        );
        drop(guard.child_mut().unwrap().stdin.take());
        let (sender, receiver) = sync_channel(1);
        spawn_reaper(
            guard,
            Vec::new(),
            sender,
            ProcessLease::acquire(1024).unwrap(),
        )
        .unwrap();
        let event = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(
            matches!(event,InternalProcessEvent::Exited{ref terminal_kind,exit_code:Some(0),cleanup_error:Some(ref error),..} if terminal_kind=="unknown_after_cleanup_failure" && error.contains("poisoned"))
        );
        assert_all_controls_retired(&control);
        assert!(observe_process_identity(control.pid).unwrap().is_none());
    }
    #[test]
    fn unbound_abort_retains_owned_anchor_and_charge_until_explicit_fixture_reconciliation() {
        let mut guard = leader_fixture();
        let identity = guard.identity.take().unwrap();
        let pid = guard.pid;
        let lease = ProcessLease::acquire(1024).unwrap();
        let weak = Arc::downgrade(&lease);
        guard._process_lease = Some(lease);
        let lifecycle = Arc::clone(&guard.lifecycle);
        drop(guard);
        let deadline = Instant::now() + Duration::from_secs(1);
        while !observe_owned_child(pid, true).unwrap() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(identity_matches(
            &identity,
            &observe_process_identity(pid).unwrap().unwrap()
        ));
        assert!(lifecycle.is_retired());
        assert!(weak.upgrade().is_some());
        // Elapsed time and an already-terminal numeric PID do not release
        // quarantined charge or consume its exact owned child.
        thread::sleep(Duration::from_millis(30));
        assert!(observe_process_identity(pid).unwrap().is_some());
        assert!(weak.upgrade().is_some());
        assert!(
            process_group_is_quiet(&identity, Instant::now() + Duration::from_secs(1)).unwrap()
        );
        let reason = reconcile_quarantine_fixture(pid);
        assert!(reason.contains("quiet unproven"));
        assert!(observe_process_identity(pid).unwrap().is_none());
        assert!(weak.upgrade().is_none());
        eprintln!(
            "actual_unbound_quarantine: terminal_anchor_and_charge_retained_before_explicit_fixture_offline_reconciliation"
        );
    }

    #[test]
    fn bound_abort_requires_complete_quiet_before_consuming_anchor_and_dropping_charge() {
        let mut guard = leader_fixture();
        let identity = guard.identity.clone().unwrap();
        let pid = guard.pid;
        let lease = ProcessLease::acquire(1024).unwrap();
        let weak = Arc::downgrade(&lease);
        guard._process_lease = Some(lease);
        let mut command = Command::new("/bin/sleep");
        command.arg("10");
        let pgid = identity.process_group as libc::pid_t;
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, pgid) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut member = OwnedTestChild(command.spawn().unwrap());
        assert!(
            !process_group_is_quiet(&identity, Instant::now() + Duration::from_secs(1)).unwrap()
        );
        guard.lifecycle.begin_retirement().unwrap();
        assert!(abort_owned_child(guard.child_mut().unwrap(), Some(&identity)).is_ok());
        assert!(observe_owned_child(pid, true).unwrap());
        assert!(observe_process_identity(pid).unwrap().is_some());
        assert!(weak.upgrade().is_some());
        assert!(quiet_twice(&identity, Instant::now() + Duration::from_secs(1)).unwrap());
        assert!(observe_owned_child(member.0.id(), true).unwrap());
        drop(guard);
        assert!(observe_process_identity(pid).unwrap().is_none());
        assert!(weak.upgrade().is_none());
        assert_eq!(member.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn real_cleanup_error_keeps_wnowait_anchor_and_charge_before_event_then_recovery() {
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::tempdir().unwrap();
        let inaccessible = temporary.path().join("denied");
        fs::write(&inaccessible, b"owned fixture").unwrap();
        fs::set_permissions(&inaccessible, fs::Permissions::from_mode(0o0)).unwrap();
        let actual_error = File::open(&inaccessible).unwrap_err();
        assert_eq!(actual_error.kind(), std::io::ErrorKind::PermissionDenied);
        let mut guard = leader_fixture();
        let pid = guard.pid;
        let control = fixture_control(&guard);
        let lease = ProcessLease::acquire(1024).unwrap();
        let weak = Arc::downgrade(&lease);
        guard._process_lease = Some(Arc::clone(&lease));
        let (sender, receiver) = sync_channel(1);
        sender
            .send(InternalProcessEvent::Output {
                stream: "fixture".into(),
                bytes: b"hold terminal delivery".to_vec(),
            })
            .unwrap();
        let (observed_sender, observed_receiver) = std::sync::mpsc::channel();
        drop(guard.child_mut().unwrap().stdin.take());
        spawn_reaper_with_cleanup(guard, Vec::new(), sender, lease, move |identity| {
            let error = File::open(&inaccessible).unwrap_err();
            observed_sender.send(identity.clone()).unwrap();
            Err(format!("actual owned observation fixture failed: {error}"))
        })
        .unwrap();
        let identity = observed_receiver
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(1);
        while !control.lifecycle.is_retired() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert!(identity_matches(
            &identity,
            &observe_process_identity(pid).unwrap().unwrap()
        ));
        assert!(observe_owned_child(pid, true).unwrap());
        assert!(weak.upgrade().is_some());
        assert_all_controls_retired(&control);
        assert!(matches!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            InternalProcessEvent::Output { .. }
        ));
        let event = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(
            matches!(event,InternalProcessEvent::Exited{ref terminal_kind,exit_code:Some(0),cleanup_error:Some(ref error),..} if terminal_kind=="unknown_after_cleanup_failure"&&error.contains("Permission denied")&&error.contains("retained"))
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while observe_process_identity(pid).unwrap().is_some() || weak.upgrade().is_some() {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(5));
        }
        assert_all_controls_retired(&control);
        eprintln!(
            "actual_cleanup_error: owned_EACCES, WNOWAIT_status0, terminal_unknown, anchor_charge_retained_through_delivery_then_owned_complete_recovery"
        );
    }
}
