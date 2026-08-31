use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::{
    InternalProcessEvent, JobInvocation, JobRuntimeError, JobStartRequest, PtySize, Result,
};

const PROCESS_EVENT_QUEUE: usize = 256;
const DESCENDANT_TERM_GRACE: Duration = Duration::from_millis(100);
const DESCENDANT_KILL_GRACE: Duration = Duration::from_millis(100);
const SPAWN_GUARD_REAP_GRACE: Duration = Duration::from_millis(500);
const PROCESS_GROUP_SCAN_BUDGET: Duration = Duration::from_millis(500);
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

struct SpawnGuard {
    child: Option<Child>,
    pid: u32,
    identity: Option<ProcessIdentity>,
}

impl SpawnGuard {
    fn new(child: Child) -> Self {
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
            identity: None,
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
        self.child
            .take()
            .ok_or_else(|| std::io::Error::other("spawn guard no longer owns its child"))?
            .wait()
    }
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        // A `SpawnGuard` normally drops immediately after `spawn`, but an
        // error path can be delayed long enough for the leader PID to be
        // recycled.  Check the bound generation before broadcasting SIGKILL
        // to its process group.  The exact `Child` handle remains safe to
        // kill on its own, so it is still used as a conservative fallback
        // when the identity check cannot prove that the group is ours.
        // Never fall back to treating the raw PID as a process-group ID when
        // identity capture itself failed.  A PID is not proof of its current
        // process group and may have been recycled; in that state the exact
        // `Child` handle below is the only safe cleanup primitive.
        if let Some(process_group) = guarded_group_signal_target(self.identity.as_ref()) {
            let _ = send_process_group_signal(process_group, libc::SIGKILL);
        }
        let _ = child.kill();

        let deadline = Instant::now()
            .checked_add(SPAWN_GUARD_REAP_GRACE)
            .unwrap_or_else(Instant::now);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(5));
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }

        // Preserve eventual wait(2) ownership without allowing Drop to wedge
        // an error-return path indefinitely.
        let name = format!("owner-open-job-abort-reaper-{}", self.pid);
        let _ = thread::Builder::new().name(name).spawn(move || {
            let _ = child.wait();
        });
    }
}

impl ProcessControl {
    pub fn write(&self, bytes: &[u8]) -> Result<()> {
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
        // Never signal a process group solely by a recycled PID.  A vanished
        // leader is treated as an idempotent no-op; a different live process
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
                // The leader may have exited just before a control request
                // arrived while descendants still own the original group.
                // Prove that group/session lineage before signalling it; if
                // the group is already gone this is an idempotent no-op.
                ensure_bound_process_group(&identity).map_err(JobRuntimeError::Control)?;
                if !process_group_exists(identity.process_group)
                    .map_err(JobRuntimeError::Control)?
                {
                    return Ok(());
                }
            }
        }
        send_process_group_signal(identity.process_group, signal).map_err(JobRuntimeError::Control)
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
) -> Result<SpawnedProcess> {
    validate_start(request)?;
    match request.pty {
        Some(size) => spawn_pty(request, size, maximum_chunk),
        None => spawn_pipe(request, maximum_chunk),
    }
}

fn spawn_pipe(request: &JobStartRequest, maximum_chunk: usize) -> Result<SpawnedProcess> {
    let mut command = base_command(request)?;
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
    let stdout_thread =
        spawn_reader(stdout, "stdout", maximum_chunk, sender.clone()).map_err(post_fork_error)?;
    let stderr_thread =
        spawn_reader(stderr, "stderr", maximum_chunk, sender.clone()).map_err(post_fork_error)?;
    let mut workers = vec![stdout_thread, stderr_thread];
    if let Some(writer) = spawn_initial_writer(
        Arc::clone(&input),
        request.initial_stdin.clone(),
        sender.clone(),
    )
    .map_err(post_fork_error)?
    {
        workers.push(writer);
    }
    spawn_reaper(guard, workers, sender).map_err(post_fork_error)?;
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
        }),
        events: receiver,
    })
}

fn spawn_pty(
    request: &JobStartRequest,
    size: PtySize,
    maximum_chunk: usize,
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
    let mut command = base_command(request)?;
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
    let reader_thread =
        spawn_reader(reader, "pty", maximum_chunk, sender.clone()).map_err(post_fork_error)?;
    let mut workers = vec![reader_thread];
    if let Some(writer) = spawn_initial_writer(
        Arc::clone(&input),
        request.initial_stdin.clone(),
        sender.clone(),
    )
    .map_err(post_fork_error)?
    {
        workers.push(writer);
    }
    spawn_reaper(guard, workers, sender).map_err(post_fork_error)?;
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
        }),
        events: receiver,
    })
}

fn base_command(request: &JobStartRequest) -> Result<Command> {
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
    for &key in JOB_INHERITED_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(cwd) = &request.cwd {
        command.current_dir(cwd);
    }
    apply_environment(&mut command, &request.env);
    Ok(command)
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

fn validate_start(request: &JobStartRequest) -> Result<()> {
    if request.shell_executable.as_os_str().is_empty() {
        return Err(JobRuntimeError::InvalidRequest(
            "shell executable is empty".to_string(),
        ));
    }
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
                || argv
                    .iter()
                    .any(|argument| argument.is_empty() || argument.as_bytes().contains(&0))
            {
                return Err(JobRuntimeError::InvalidRequest(
                    "job argv is empty or contains an invalid element".to_string(),
                ));
            }
        }
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
    if path.as_os_str().is_empty() {
        return Err(JobRuntimeError::InvalidRequest(format!("{label} is empty")));
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
    let deadline = Instant::now()
        .checked_add(INPUT_WRITE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut offset = 0usize;
    while offset < bytes.len() {
        let remaining = &bytes[offset..];
        let written = unsafe {
            libc::write(
                fd,
                remaining.as_ptr().cast::<libc::c_void>(),
                remaining.len(),
            )
        };
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
    Ok(())
}

fn spawn_initial_writer(
    input: Arc<Mutex<Option<InputHandle>>>,
    bytes: Vec<u8>,
    sender: SyncSender<InternalProcessEvent>,
) -> Result<Option<JoinHandle<()>>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    thread::Builder::new()
        .name("owner-open-job-initial-stdin".to_string())
        .spawn(move || {
            let result = match input.lock() {
                Ok(mut guard) => match guard.as_mut() {
                    Some(handle) => write_input(handle, &bytes),
                    None => Err(JobRuntimeError::NotLive),
                },
                Err(_) => Err(JobRuntimeError::StatePoisoned),
            };
            if let Err(error) = result {
                let _ = sender.send(InternalProcessEvent::InputFailed {
                    error: error.to_string(),
                });
            }
        })
        .map(Some)
        .map_err(|error| {
            JobRuntimeError::Io(format!("failed to spawn initial stdin writer: {error}"))
        })
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
fn guarded_group_signal_target(identity: Option<&ProcessIdentity>) -> Option<u32> {
    let identity = identity?;
    ensure_bound_process_group(identity)
        .ok()
        .map(|()| identity.process_group)
}

fn ensure_bound_process_group(identity: &ProcessIdentity) -> std::result::Result<(), String> {
    let observed = observe_process_identity(identity.pid).map_err(|error| error.to_string())?;
    let Some(observed) = observed else {
        // The leader has already been reaped.  A non-empty process group keeps
        // its original PGID until its members leave, so cleanup may still
        // target the bound group only when a member with the bound session is
        // observable.  If a recycled PGID has no such member, refuse the
        // broadcast and report cleanup uncertainty instead of risking an
        // unrelated process group.
        if process_group_exists(identity.process_group)?
            && !bound_process_group_has_member(identity)?
        {
            return Err("process-group identity cannot be proven after leader exit".to_string());
        }
        return Ok(());
    };
    if !identity_matches(identity, &observed) {
        return Err("job process identity changed before group cleanup".to_string());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bound_process_group_has_member(identity: &ProcessIdentity) -> std::result::Result<bool, String> {
    let entries = fs::read_dir("/proc").map_err(|error| error.to_string())?;
    let deadline = Instant::now()
        .checked_add(PROCESS_GROUP_SCAN_BUDGET)
        .unwrap_or_else(Instant::now);
    for entry in entries {
        if Instant::now() >= deadline {
            return Err("job process-group member scan exceeded its bounded deadline".to_string());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        // The leader is already known to be absent (or was separately
        // validated by `ensure_bound_process_group`); only a distinct member
        // can prove that the old group is still populated.
        if pid == identity.pid {
            continue;
        }
        match read_proc_stat_identity(pid) {
            Ok(Some((_start_time, process_group, session_id)))
                if process_group == identity.process_group && session_id == identity.session_id =>
            {
                return Ok(true);
            }
            Ok(Some(_)) | Ok(None) => {}
            // `/proc` is inherently racy when a task disappears, which is
            // represented by `Ok(None)`.  Any other read/parse failure means
            // the old group cannot be positively identified, so propagate it
            // instead of treating an incomplete scan as an empty group.
            Err(error) => {
                return Err(format!(
                    "job process-group member identity probe failed: {error}"
                ));
            }
        }
    }
    Ok(false)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bound_process_group_has_member(identity: &ProcessIdentity) -> std::result::Result<bool, String> {
    process_group_exists(identity.process_group)
}

fn spawn_reader<R>(
    mut reader: R,
    stream: &'static str,
    maximum_chunk: usize,
    sender: SyncSender<InternalProcessEvent>,
) -> Result<JoinHandle<()>>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("owner-open-job-{stream}"))
        .spawn(move || {
            let mut buffer = vec![0_u8; maximum_chunk];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(read) => {
                        if sender
                            .send(InternalProcessEvent::Output {
                                stream: stream.to_string(),
                                bytes: buffer[..read].to_vec(),
                            })
                            .is_err()
                        {
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) if stream == "pty" && error.raw_os_error() == Some(libc::EIO) => {
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(InternalProcessEvent::ReaderFailed {
                            stream: stream.to_string(),
                            error: error.to_string(),
                        });
                        return;
                    }
                }
            }
        })
        .map_err(|error| JobRuntimeError::Io(format!("failed to spawn {stream} reader: {error}")))
}

fn spawn_reaper(
    guard: SpawnGuard,
    workers: Vec<JoinHandle<()>>,
    sender: SyncSender<InternalProcessEvent>,
) -> Result<()> {
    let pid = guard.pid;
    let identity = guard
        .identity
        .clone()
        .ok_or_else(|| JobRuntimeError::Io("child process identity was not bound".to_string()))?;
    thread::Builder::new()
        .name(format!("owner-open-job-reaper-{pid}"))
        .spawn(move || {
            let status = guard.wait();
            let mut cleanup_errors = Vec::new();
            if let Err(error) = cleanup_process_group(&identity) {
                cleanup_errors.push(error);
            }
            for worker in workers {
                if worker.join().is_err() {
                    cleanup_errors.push("job I/O worker panicked".to_string());
                }
            }
            let cleanup_error = (!cleanup_errors.is_empty()).then(|| cleanup_errors.join("; "));
            let event = match status {
                Ok(status) => InternalProcessEvent::Exited {
                    terminal_kind: if cleanup_error.is_some() {
                        "cleanup_uncertain".to_string()
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
            let _ = sender.send(event);
        })
        .map(|_| ())
        .map_err(|error| JobRuntimeError::Io(format!("failed to spawn job reaper: {error}")))
}

fn cleanup_process_group(identity: &ProcessIdentity) -> std::result::Result<(), String> {
    ensure_bound_process_group(identity)?;
    if !process_group_exists(identity.process_group)? {
        return Ok(());
    }
    send_process_group_signal(identity.process_group, libc::SIGTERM)?;
    let term_deadline = Instant::now()
        .checked_add(DESCENDANT_TERM_GRACE)
        .unwrap_or_else(Instant::now);
    while Instant::now() < term_deadline {
        if !process_group_exists(identity.process_group)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    // Revalidate the bound leader/member lineage immediately before the
    // escalation.  A bare PGID probe here would permit a recycled group to be
    // killed after the original descendants had already disappeared.
    ensure_bound_process_group(identity)?;
    send_process_group_signal(identity.process_group, libc::SIGKILL)?;
    let kill_deadline = Instant::now()
        .checked_add(DESCENDANT_KILL_GRACE)
        .unwrap_or_else(Instant::now);
    while Instant::now() < kill_deadline {
        if !process_group_exists(identity.process_group)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    if process_group_exists(identity.process_group)? {
        Err("process group remains observable after SIGKILL grace".to_string())
    } else {
        Ok(())
    }
}

fn process_group_exists(process_group: u32) -> std::result::Result<bool, String> {
    let process_group = i32::try_from(process_group)
        .map_err(|_| "child pid does not fit a POSIX process-group id".to_string())?;
    let result = unsafe { libc::kill(-process_group, 0) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(format!("process group existence check failed: {error}")),
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
}
