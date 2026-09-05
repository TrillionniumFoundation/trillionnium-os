use std::fs::{self, File};
use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::types::{
    CancellationToken, ExecutionEvent, ExecutionEventKind, ExecutionTerminal, MechanicalLimits,
    ProcessIoMode, ProcessSpec, PtySize, Result, ShellExecRequest, StreamKind, TerminalKind,
};
use crate::validate::shell_spec;

#[derive(Debug)]
enum ReaderMessage {
    Chunk(StreamKind, Vec<u8>),
    Eof(StreamKind),
    Error(StreamKind, String),
}

#[derive(Debug)]
struct PtyPair {
    master: File,
    slave: File,
}

const SPAWN_GUARD_REAP_GRACE: Duration = Duration::from_millis(500);
const PROCESS_GROUP_SCAN_BUDGET: Duration = Duration::from_millis(500);
// Keep the child environment deterministic and mechanism-only.  Arbitrary
// parent variables can contain credentials or provider state; callers add
// intentional values through ProcessSpec.env instead.
const PROCESS_INHERITED_ENV_ALLOWLIST: &[&str] = &[
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

/// Kernel-observed child generation and process namespace identity.
///
/// Linux/Android bind the PID to `/proc` start-time plus boot identity.  PGID
/// and SID are captured independently because a numeric PID alone is not safe
/// authority for a later process-group signal.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    process_group: u32,
    session_id: u32,
    start_time_ticks: Option<u64>,
    boot_id_sha256: Option<String>,
}

/// Owns every successfully spawned direct-runtime child until leader reap and
/// process-group disappearance are observed.
struct ProcessChildGuard {
    child: Option<Child>,
    pid: u32,
    identity: Option<ProcessIdentity>,
    grace: Duration,
    armed: bool,
}

impl ProcessChildGuard {
    fn new(child: Child, grace: Duration) -> Self {
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
            identity: None,
            grace,
            armed: true,
        }
    }

    fn bind_identity(&mut self, identity: ProcessIdentity) {
        debug_assert_eq!(identity.pid, self.pid);
        self.identity = Some(identity);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Deref for ProcessChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        self.child
            .as_ref()
            .expect("direct-runtime guard no longer owns its child")
    }
}

impl DerefMut for ProcessChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child
            .as_mut()
            .expect("direct-runtime guard no longer owns its child")
    }
}

impl Drop for ProcessChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(mut child) = self.child.take() else {
            self.armed = false;
            return;
        };
        if let Some(identity) = self.identity.as_ref() {
            let _ = terminate_process_group(&mut child, identity, self.grace);
        } else {
            // Identity capture failed after spawn.  The exact Child handle is
            // still safe, but `kill(-pid, ...)` is not.
            let _ = child.kill();
        }
        reap_child_bounded(child, SPAWN_GUARD_REAP_GRACE);
        self.armed = false;
    }
}

/// Execute a first-class command string with the configured shell, or an exact
/// element-preserving argv. Command strings use `<shell> -c <command>`; argv
/// bypasses shell parsing entirely.
pub fn execute_shell<F>(
    request: ShellExecRequest,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    execute_process(shell_spec(request, limits)?, limits, cancellation, sink)
}

/// Execute a shell request attached to a real POSIX pseudo-terminal.
///
/// PTY output is reported as the distinct `StreamKind::Pty` stream: a terminal
/// has one byte stream and therefore naturally merges the child's stdout and
/// stderr.  The command/argv, environment, cwd and lifecycle semantics are
/// otherwise identical to [`execute_shell`].
pub fn execute_shell_pty<F>(
    request: ShellExecRequest,
    size: PtySize,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    size.validate()?;
    let mut spec = shell_spec(request, limits)?;
    spec.io_mode = ProcessIoMode::Pty(size);
    execute_process(spec, limits, cancellation, sink)
}

pub(crate) fn execute_process<F>(
    spec: ProcessSpec,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    mut sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    let started_at = Instant::now();
    let mut sequence = 0u64;
    let mut emit = |kind: ExecutionEventKind| {
        let event = ExecutionEvent {
            call_id: spec.call_id.clone(),
            target_id: spec.target_id.clone(),
            tool: spec.tool,
            seq: sequence,
            elapsed_ms: elapsed_ms(started_at),
            kind,
        };
        sequence = sequence.saturating_add(1);
        sink(event);
    };

    emit(ExecutionEventKind::Accepted);

    // An empty ADB executable is an explicit configuration state, not a
    // malformed command.  Keep it observable as a terminal result so an
    // unavailable transport cannot silently become a policy rejection.
    if spec.tool == crate::types::ToolKind::AdbExec && spec.program.as_os_str().is_empty() {
        let terminal = terminal_observation(
            TerminalKind::TransportUnavailable,
            None,
            None,
            (0, 0),
            false,
            started_at,
            Some("adb transport unavailable: executable is not configured".to_string()),
        );
        emit(ExecutionEventKind::Terminal(terminal.clone()));
        return Ok(terminal);
    }

    let pty_pair = match spec.io_mode {
        ProcessIoMode::Pipe => None,
        ProcessIoMode::Pty(size) => match open_pty(size) {
            Ok(pair) => Some(pair),
            Err(error) => {
                let terminal = terminal_observation(
                    TerminalKind::IoError,
                    None,
                    None,
                    (0, 0),
                    false,
                    started_at,
                    Some(format!("pty_open_failed: {error}")),
                );
                emit(ExecutionEventKind::Terminal(terminal.clone()));
                return Ok(terminal);
            }
        },
    };

    let mut command = Command::new(&spec.program);
    command.env_clear();
    for &key in PROCESS_INHERITED_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    command.args(&spec.args);
    let pty_slave_fd = pty_pair.as_ref().map(|pair| pair.slave.as_raw_fd());
    if let Some(pair) = pty_pair.as_ref() {
        let stdin = match pair.slave.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let terminal = terminal_observation(
                    TerminalKind::IoError,
                    None,
                    None,
                    (0, 0),
                    false,
                    started_at,
                    Some(format!("pty_stdin_clone_failed: {error}")),
                );
                emit(ExecutionEventKind::Terminal(terminal.clone()));
                return Ok(terminal);
            }
        };
        let stdout = match pair.slave.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let terminal = terminal_observation(
                    TerminalKind::IoError,
                    None,
                    None,
                    (0, 0),
                    false,
                    started_at,
                    Some(format!("pty_stdout_clone_failed: {error}")),
                );
                emit(ExecutionEventKind::Terminal(terminal.clone()));
                return Ok(terminal);
            }
        };
        let stderr = match pair.slave.try_clone() {
            Ok(file) => file,
            Err(error) => {
                let terminal = terminal_observation(
                    TerminalKind::IoError,
                    None,
                    None,
                    (0, 0),
                    false,
                    started_at,
                    Some(format!("pty_stderr_clone_failed: {error}")),
                );
                emit(ExecutionEventKind::Terminal(terminal.clone()));
                return Ok(terminal);
            }
        };
        command
            .stdin(Stdio::from(stdin))
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
    } else {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
    }
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    for (key, value) in &spec.env {
        match value {
            Some(value) => {
                command.env(key, value);
            }
            None => {
                command.env_remove(key);
            }
        }
    }

    let parent_pid = unsafe { libc::getpid() };
    // A dedicated process group and parent-death signal are lifecycle
    // primitives, not semantic policy. They prevent timeout, cancellation,
    // output exhaustion, or Host death from silently leaving descendants.
    unsafe {
        command.pre_exec(move || configure_child_lifecycle(parent_pid, pty_slave_fd));
    }

    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let kind = if spec.tool == crate::types::ToolKind::AdbExec
                && error.kind() == std::io::ErrorKind::NotFound
            {
                TerminalKind::TransportUnavailable
            } else {
                TerminalKind::SpawnFailed
            };
            let error_message = if kind == TerminalKind::TransportUnavailable {
                format!("adb transport unavailable: {error}")
            } else {
                error.to_string()
            };
            let terminal = terminal_observation(
                kind,
                None,
                None,
                (0, 0),
                false,
                started_at,
                Some(error_message),
            );
            emit(ExecutionEventKind::Terminal(terminal.clone()));
            return Ok(terminal);
        }
    };
    // Install total post-spawn ownership before any fallible descriptor or
    // thread setup.  An identity-capture failure can still kill/reap the exact
    // Child, but it must never broadcast to a group inferred from raw PID.
    let mut child = ProcessChildGuard::new(child, limits.terminate_grace);
    let identity = match capture_process_identity(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let terminal = terminal_observation(
                TerminalKind::IoError,
                None,
                None,
                (0, 0),
                false,
                started_at,
                Some(format!("child_identity_capture_failed: {error}")),
            );
            emit(ExecutionEventKind::Terminal(terminal.clone()));
            return Ok(terminal);
        }
    };
    child.bind_identity(identity.clone());
    // `Command` retains the Stdio wrappers used for PTY slave descriptors on
    // some libc/Rust combinations.  Release those parent-side duplicates as
    // soon as spawn succeeds; otherwise the PTY master can wait forever for a
    // slave that is already closed in the child.
    drop(command);

    // The slave descriptors are now owned by the child stdio handles.  Close
    // the parent's copies so EOF/EIO accurately follows child lifecycle.
    let pty_master = pty_pair.map(|pair| {
        drop(pair.slave);
        pair.master
    });

    let pid = identity.pid;
    emit(ExecutionEventKind::Started { pid });

    // Readers are live before initial stdin is written. This order prevents a
    // child that writes before reading from deadlocking the Host setup path.
    let (sender, receiver) = sync_channel::<ReaderMessage>(limits.reader_queue_depth);
    let (stdout_thread, stderr_thread, pty_stdin) = if let Some(master) = pty_master {
        let reader = match master.try_clone() {
            Ok(reader) => reader,
            Err(error) => {
                let _ = terminate_process_group(&mut child, &identity, limits.terminate_grace);
                let terminal = terminal_observation(
                    TerminalKind::IoError,
                    None,
                    None,
                    (0, 0),
                    false,
                    started_at,
                    Some(format!("pty_reader_clone_failed: {error}")),
                );
                emit(ExecutionEventKind::Terminal(terminal.clone()));
                return Ok(terminal);
            }
        };
        let writer = match master.try_clone() {
            Ok(writer) => Some(writer),
            Err(error) => {
                let _ = terminate_process_group(&mut child, &identity, limits.terminate_grace);
                let terminal = terminal_observation(
                    TerminalKind::IoError,
                    None,
                    None,
                    (0, 0),
                    false,
                    started_at,
                    Some(format!("pty_writer_clone_failed: {error}")),
                );
                emit(ExecutionEventKind::Terminal(terminal.clone()));
                return Ok(terminal);
            }
        };
        (
            Some(spawn_reader(
                reader,
                StreamKind::Pty,
                limits.stream_chunk_bytes,
                sender.clone(),
                true,
            )),
            None,
            writer,
        )
    } else {
        let stdout_thread = child.stdout.take().map(|stdout| {
            spawn_reader(
                stdout,
                StreamKind::Stdout,
                limits.stream_chunk_bytes,
                sender.clone(),
                false,
            )
        });
        let stderr_thread = child.stderr.take().map(|stderr| {
            spawn_reader(
                stderr,
                StreamKind::Stderr,
                limits.stream_chunk_bytes,
                sender.clone(),
                false,
            )
        });
        (stdout_thread, stderr_thread, None)
    };
    let stdin_thread = if let Some(writer) = pty_stdin {
        let bytes = spec.stdin;
        Some(thread::spawn(move || write_initial_stdin(writer, bytes)))
    } else {
        child.stdin.take().map(|stdin| {
            let bytes = spec.stdin;
            thread::spawn(move || write_initial_stdin(stdin, bytes))
        })
    };

    let mut stdout_eof = stdout_thread.is_none();
    let mut stderr_eof = stderr_thread.is_none();
    let mut stdout_bytes = 0usize;
    let mut stderr_bytes = 0usize;
    let mut child_status: Option<ExitStatus> = None;
    let mut forced_kind: Option<TerminalKind> = None;
    let mut runtime_error: Option<String> = None;
    let mut termination_attempted = false;
    let mut post_exit_deadline: Option<Instant> = None;

    loop {
        if child_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    child_status = Some(status);
                    post_exit_deadline = Instant::now().checked_add(post_exit_grace(limits));
                    match bound_process_group_exists(&identity) {
                        Ok(true) => {
                            forced_kind.get_or_insert(TerminalKind::IoError);
                            runtime_error = Some(join_error(
                                runtime_error,
                                "leader_exited_with_live_descendants".to_string(),
                            ));
                        }
                        Ok(false) => {}
                        Err(error) => {
                            forced_kind.get_or_insert(TerminalKind::IoError);
                            runtime_error = Some(join_error(runtime_error, error));
                        }
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    runtime_error = Some(join_error(
                        runtime_error,
                        format!("child_status_error: {error}"),
                    ));
                    forced_kind.get_or_insert(TerminalKind::IoError);
                }
            }
        }

        if child_status.is_none() && forced_kind.is_none() {
            if cancellation.is_cancelled() {
                forced_kind = Some(TerminalKind::Cancelled);
            } else if started_at.elapsed() >= spec.timeout {
                forced_kind = Some(TerminalKind::TimedOut);
            }
        }

        if forced_kind.is_some() && !termination_attempted {
            termination_attempted = true;
            match terminate_process_group(&mut child, &identity, limits.terminate_grace) {
                Ok(status) => child_status = Some(status),
                Err(error) => {
                    runtime_error = Some(join_error(runtime_error, error));
                    forced_kind = Some(TerminalKind::IoError);
                    child_status = child.try_wait().ok().flatten();
                }
            }
            post_exit_deadline = Instant::now().checked_add(post_exit_grace(limits));
        }

        if child_status.is_some() && stdout_eof && stderr_eof {
            break;
        }
        if child_status.is_some()
            && post_exit_deadline.is_some_and(|deadline| Instant::now() >= deadline)
        {
            runtime_error = Some(join_error(
                runtime_error,
                "output_pipes_remained_open_after_leader_exit".to_string(),
            ));
            forced_kind = Some(TerminalKind::IoError);
            break;
        }

        match receiver.recv_timeout(limits.poll_interval) {
            Ok(ReaderMessage::Chunk(stream, bytes)) => {
                let used = stdout_bytes.saturating_add(stderr_bytes);
                let remaining = limits.max_output_bytes.saturating_sub(used);
                let delivered = bytes.len().min(remaining);
                if delivered > 0 {
                    let output = bytes[..delivered].to_vec();
                    match stream {
                        // TerminalRecord predates the explicit PTY stream and
                        // exposes stdout/stderr counters only. Keep merged PTY
                        // bytes in stdout for compatibility while preserving
                        // the authoritative `stream=pty` event label.
                        StreamKind::Stdout | StreamKind::Pty => {
                            stdout_bytes = stdout_bytes.saturating_add(delivered)
                        }
                        StreamKind::Stderr => stderr_bytes = stderr_bytes.saturating_add(delivered),
                    }
                    emit(ExecutionEventKind::Output {
                        stream,
                        bytes: output,
                    });
                }
                if delivered < bytes.len() || remaining == 0 {
                    forced_kind.get_or_insert(TerminalKind::OutputLimitExceeded);
                }
            }
            Ok(ReaderMessage::Eof(stream)) => match stream {
                StreamKind::Stdout | StreamKind::Pty => stdout_eof = true,
                StreamKind::Stderr => stderr_eof = true,
            },
            Ok(ReaderMessage::Error(stream, error)) => {
                runtime_error = Some(join_error(runtime_error, error));
                forced_kind.get_or_insert(TerminalKind::IoError);
                match stream {
                    StreamKind::Stdout | StreamKind::Pty => stdout_eof = true,
                    StreamKind::Stderr => stderr_eof = true,
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                stdout_eof = true;
                stderr_eof = true;
            }
        }
    }

    if child_status.is_none() {
        match terminate_process_group(&mut child, &identity, limits.terminate_grace) {
            Ok(status) => child_status = Some(status),
            Err(error) => {
                runtime_error = Some(join_error(runtime_error, error));
                forced_kind = Some(TerminalKind::IoError);
                child_status = child.try_wait().ok().flatten();
            }
        }
    }

    let join_grace = post_exit_grace(limits);
    if !join_reader_bounded(
        stdout_thread,
        &mut runtime_error,
        "stdout_reader",
        join_grace,
    ) {
        forced_kind = Some(TerminalKind::IoError);
    }
    if !join_reader_bounded(
        stderr_thread,
        &mut runtime_error,
        "stderr_reader",
        join_grace,
    ) {
        forced_kind = Some(TerminalKind::IoError);
    }
    if !join_stdin_bounded(stdin_thread, &mut runtime_error, join_grace) {
        forced_kind = Some(TerminalKind::IoError);
    }

    let status = child_status.or_else(|| child.try_wait().ok().flatten());
    if status.is_some() {
        match bound_process_group_exists(&identity) {
            Ok(false) => child.disarm(),
            Ok(true) => {
                forced_kind = Some(TerminalKind::IoError);
                runtime_error = Some(join_error(
                    runtime_error,
                    "process_group_remained_live_after_cleanup".to_string(),
                ));
            }
            Err(error) => {
                forced_kind = Some(TerminalKind::IoError);
                runtime_error = Some(join_error(runtime_error, error));
            }
        }
    }
    let status_kind =
        forced_kind.unwrap_or_else(|| match status.as_ref().and_then(ExitStatusExt::signal) {
            Some(_) => TerminalKind::Signaled,
            None => TerminalKind::Exited,
        });
    let terminal = ExecutionTerminal {
        kind: status_kind,
        exit_code: status.as_ref().and_then(ExitStatus::code),
        signal: status.as_ref().and_then(ExitStatusExt::signal),
        stdout_bytes: u64::try_from(stdout_bytes).unwrap_or(u64::MAX),
        stderr_bytes: u64::try_from(stderr_bytes).unwrap_or(u64::MAX),
        output_truncated: status_kind == TerminalKind::OutputLimitExceeded,
        elapsed_ms: elapsed_ms(started_at),
        error: runtime_error,
    };
    emit(ExecutionEventKind::Terminal(terminal.clone()));
    Ok(terminal)
}

fn configure_child_lifecycle(
    parent_pid: libc::pid_t,
    pty_slave_fd: Option<i32>,
) -> std::io::Result<()> {
    if let Some(pty_slave_fd) = pty_slave_fd {
        // A PTY child must become a session leader before acquiring its
        // controlling terminal. `setsid` also gives it a dedicated process
        // group, so the normal group cleanup path remains effective.
        if unsafe { libc::setsid() } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::ioctl(pty_slave_fd, libc::TIOCSCTTY as _, 0) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
    } else if unsafe { libc::setpgid(0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::getppid() } != parent_pid {
            return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
        }
    }
    Ok(())
}

fn spawn_reader<R>(
    mut reader: R,
    stream: StreamKind,
    chunk_bytes: usize,
    sender: SyncSender<ReaderMessage>,
    pty: bool,
) -> JoinHandle<()>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = vec![0u8; chunk_bytes];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = sender.send(ReaderMessage::Eof(stream));
                    return;
                }
                Ok(count) => {
                    if sender
                        .send(ReaderMessage::Chunk(stream, buffer[..count].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) if pty && error.raw_os_error() == Some(libc::EIO) => {
                    let _ = sender.send(ReaderMessage::Eof(stream));
                    return;
                }
                Err(error) => {
                    let _ = sender.send(ReaderMessage::Error(
                        stream,
                        format!(
                            "{}_read_error: {error}",
                            match stream {
                                StreamKind::Stdout => "stdout",
                                StreamKind::Stderr => "stderr",
                                StreamKind::Pty => "pty",
                            }
                        ),
                    ));
                    return;
                }
            }
        }
    })
}

fn write_initial_stdin<W>(mut writer: W, bytes: Vec<u8>) -> Option<String>
where
    W: Write,
{
    if bytes.is_empty() {
        return None;
    }
    match writer.write_all(&bytes).and_then(|_| writer.flush()) {
        Ok(()) => None,
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
            Some(format!("stdin_closed: {error}"))
        }
        Err(error) => Some(format!("stdin_io_error: {error}")),
    }
}

fn open_pty(size: PtySize) -> std::io::Result<PtyPair> {
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
        return Err(std::io::Error::last_os_error());
    }
    if let Err(error) = set_cloexec(master).and_then(|_| set_cloexec(slave)) {
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
        return Err(error);
    }
    // SAFETY: `openpty` returned two owned descriptors and no other owner has
    // been created yet.
    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    Ok(PtyPair { master, slave })
}

fn set_cloexec(fd: i32) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn wait_until_finished<T>(thread: &JoinHandle<T>, timeout: Duration) -> bool {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    while !thread.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(1));
    }
    thread.is_finished()
}

fn join_reader_bounded(
    thread: Option<JoinHandle<()>>,
    error: &mut Option<String>,
    label: &str,
    timeout: Duration,
) -> bool {
    let Some(thread) = thread else {
        return true;
    };
    if !wait_until_finished(&thread, timeout) {
        *error = Some(join_error(
            error.take(),
            format!("{label}_did_not_finish_after_process_cleanup"),
        ));
        drop(thread);
        return false;
    }
    if thread.join().is_err() {
        *error = Some(join_error(error.take(), format!("{label}_panicked")));
        return false;
    }
    true
}

fn join_stdin_bounded(
    thread: Option<JoinHandle<Option<String>>>,
    error: &mut Option<String>,
    timeout: Duration,
) -> bool {
    let Some(thread) = thread else {
        return true;
    };
    if !wait_until_finished(&thread, timeout) {
        *error = Some(join_error(
            error.take(),
            "stdin_writer_did_not_finish_after_process_cleanup".to_string(),
        ));
        drop(thread);
        return false;
    }
    match thread.join() {
        Ok(Some(next)) => {
            *error = Some(join_error(error.take(), next));
            true
        }
        Ok(None) => true,
        Err(_) => {
            *error = Some(join_error(
                error.take(),
                "stdin_writer_panicked".to_string(),
            ));
            false
        }
    }
}

fn terminate_process_group(
    child: &mut Child,
    identity: &ProcessIdentity,
    grace: Duration,
) -> std::result::Result<ExitStatus, String> {
    let grace = grace.max(Duration::from_millis(250));
    let mut status = match child.try_wait() {
        Ok(status) => status,
        Err(error) => {
            let primary = format!("child_status_before_cleanup_failed: {error}");
            return Err(with_direct_fallback(
                child,
                primary,
                "direct_child_sigkill_after_status_probe_failed",
            ));
        }
    };

    // A raw PID is never sufficient to address a process group.  Revalidate
    // generation, PGID and SID immediately before each group signal.
    let group_alive = match bound_process_group_exists(identity) {
        Ok(group_alive) => group_alive,
        Err(error) => {
            return Err(with_direct_fallback(
                child,
                error,
                "direct_child_sigkill_after_identity_probe_failed",
            ));
        }
    };
    if group_alive {
        if let Err(error) = send_bound_process_group_signal(identity, libc::SIGTERM) {
            return Err(with_direct_fallback(
                child,
                error,
                "direct_child_sigkill_after_sigterm_failed",
            ));
        }
        let deadline = Instant::now()
            .checked_add(grace)
            .unwrap_or_else(Instant::now);
        while Instant::now() < deadline {
            if status.is_none() {
                status = match child.try_wait() {
                    Ok(status) => status,
                    Err(error) => {
                        let primary = format!("child_status_after_sigterm_failed: {error}");
                        return Err(with_direct_fallback(
                            child,
                            primary,
                            "direct_child_sigkill_after_status_probe_failed",
                        ));
                    }
                };
            }
            if status.is_some() {
                match bound_process_group_exists(identity) {
                    Ok(false) => return status.ok_or("child status disappeared".to_string()),
                    Ok(true) => {}
                    Err(error) => {
                        return Err(with_direct_fallback(
                            child,
                            error,
                            "direct_child_sigkill_after_identity_probe_failed",
                        ));
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }

        let group_alive = match bound_process_group_exists(identity) {
            Ok(group_alive) => group_alive,
            Err(error) => {
                return Err(with_direct_fallback(
                    child,
                    error,
                    "direct_child_sigkill_after_identity_probe_failed",
                ));
            }
        };
        if group_alive {
            match send_bound_process_group_signal(identity, libc::SIGKILL) {
                Ok(()) => {}
                Err(error) => {
                    return Err(with_direct_fallback(
                        child,
                        error,
                        "direct_child_sigkill_after_sigkill_failed",
                    ));
                }
            }
        }
    }

    // A child can change its own process group between spawn and cleanup. Kill
    // the direct PID as a bounded fallback; never turn a missing PGID into an
    // unbounded child.wait().
    if status.is_none() {
        match kill_direct_child(child, "direct_child_sigkill_failed") {
            Ok(()) => {}
            Err(error) => return Err(error.to_string()),
        }
    }

    let deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    let primary = format!("child_status_after_sigkill_failed: {error}");
                    return Err(with_direct_fallback(
                        child,
                        primary,
                        "direct_child_sigkill_after_status_probe_failed",
                    ));
                }
            };
        }
        if status.is_some() {
            match bound_process_group_exists(identity) {
                Ok(false) => return status.ok_or("child status disappeared".to_string()),
                Ok(true) => {}
                Err(error) => {
                    return Err(with_direct_fallback(
                        child,
                        error,
                        "direct_child_sigkill_after_identity_probe_failed",
                    ));
                }
            }
        }
        thread::sleep(Duration::from_millis(5));
    }

    let group_alive = match bound_process_group_exists(identity) {
        Ok(group_alive) => group_alive,
        Err(error) => {
            return Err(with_direct_fallback(
                child,
                error,
                "direct_child_sigkill_after_identity_probe_failed",
            ));
        }
    };
    Err(format!(
        "process_cleanup_deadline_exceeded: leader_reaped={}, process_group_alive={group_alive}",
        status.is_some()
    ))
}

fn kill_direct_child(child: &mut Child, context: &str) -> std::result::Result<(), String> {
    match child.kill() {
        Ok(()) => Ok(()),
        // InvalidInput means the exact leader has already exited. It is
        // idempotent; importantly, it never licenses a raw-PID group kill.
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        Err(error) => Err(format!("{context}: {error}")),
    }
}

fn with_direct_fallback(child: &mut Child, primary: String, context: &str) -> String {
    match kill_direct_child(child, context) {
        Ok(()) => primary,
        Err(error) => format!("{primary}; {error}"),
    }
}

fn process_group_exists(process_group: u32) -> std::result::Result<bool, String> {
    let group = i32::try_from(process_group)
        .map_err(|_| "process-group id does not fit a POSIX pid_t".to_string())?;
    if unsafe { libc::kill(-group, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(format!("process_group_probe_failed: {error}")),
    }
}

fn send_process_group_signal(process_group: u32, signal: i32) -> std::result::Result<(), String> {
    let group = i32::try_from(process_group)
        .map_err(|_| "process-group id does not fit a POSIX pid_t".to_string())?;
    if unsafe { libc::kill(-group, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(format!("process_group_signal_{signal}_failed: {error}"))
    }
}

/// Revalidate the captured generation, process group and session immediately
/// before the group syscall.  `kill(2)` accepts only a numeric PGID, so this
/// cannot eliminate the final POSIX check/use race atomically; centralizing the
/// check keeps the residual window minimal and makes the safe, fail-closed
/// behavior explicit at every call site.
fn send_bound_process_group_signal(
    identity: &ProcessIdentity,
    signal: i32,
) -> std::result::Result<(), String> {
    ensure_bound_process_group(identity)?;
    send_process_group_signal(identity.process_group, signal)
}

#[allow(clippy::needless_return)]
fn capture_process_identity(pid: u32) -> std::io::Result<ProcessIdentity> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let (start_time_ticks, process_group, session_id) = read_proc_stat_identity(pid)?
            .ok_or_else(|| std::io::Error::other("child exited before identity capture"))?;
        return Ok(ProcessIdentity {
            pid,
            process_group,
            session_id,
            start_time_ticks: Some(start_time_ticks),
            boot_id_sha256: Some(read_boot_id_sha256()?),
        });
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
        return Ok(ProcessIdentity {
            pid,
            process_group: u32::try_from(process_group)
                .map_err(|_| std::io::Error::other("invalid process group"))?,
            session_id: u32::try_from(session_id)
                .map_err(|_| std::io::Error::other("invalid session id"))?,
            start_time_ticks: None,
            boot_id_sha256: None,
        });
    }
}

#[allow(clippy::needless_return)]
fn observe_process_identity(pid: u32) -> std::io::Result<Option<ProcessIdentity>> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let Some((start_time_ticks, process_group, session_id)) = read_proc_stat_identity(pid)?
        else {
            return Ok(None);
        };
        return Ok(Some(ProcessIdentity {
            pid,
            process_group,
            session_id,
            start_time_ticks: Some(start_time_ticks),
            boot_id_sha256: Some(read_boot_id_sha256()?),
        }));
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
        return Ok(Some(ProcessIdentity {
            pid,
            process_group: u32::try_from(process_group)
                .map_err(|_| std::io::Error::other("invalid process group"))?,
            session_id: u32::try_from(session_id)
                .map_err(|_| std::io::Error::other("invalid session id"))?,
            start_time_ticks: None,
            boot_id_sha256: None,
        }));
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
    Ok(sha256_hex(boot_id.as_bytes()))
}

/// Compute the SHA-256 digest without widening this deliberately small
/// isolated runtime's dependency surface.  The only production input is the
/// validated 36-byte kernel boot UUID, but the implementation accepts any
/// bounded byte slice so its padding and length handling remain explicit.
fn sha256_hex(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const ROUND: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let bit_length = (input.len() as u64).wrapping_mul(8);
    let padded_len = input.len().saturating_add(9).div_ceil(64) * 64;
    let mut padded = vec![0_u8; padded_len];
    padded[..input.len()].copy_from_slice(input);
    padded[input.len()] = 0x80;
    padded[padded_len - 8..].copy_from_slice(&bit_length.to_be_bytes());

    let mut state = INITIAL;
    for block in padded.chunks_exact(64) {
        let mut schedule = [0_u32; 64];
        for (index, word) in schedule.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }

        let mut working = state;
        for index in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choice = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(ROUND[index])
                .wrapping_add(schedule[index]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(majority);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp1);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp1.wrapping_add(temp2);
        }
        for (value, update) in state.iter_mut().zip(working) {
            *value = value.wrapping_add(update);
        }
    }

    let mut digest = [0_u8; 32];
    for (index, value) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&value.to_be_bytes());
    }
    hex_lower(&digest)
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

fn ensure_bound_process_group(identity: &ProcessIdentity) -> std::result::Result<(), String> {
    let observed = observe_process_identity(identity.pid).map_err(|error| error.to_string())?;
    let Some(observed) = observed else {
        if process_group_exists(identity.process_group)?
            && !bound_process_group_has_member(identity)?
        {
            return Err("process-group identity cannot be proven after leader exit".to_string());
        }
        return Ok(());
    };
    if !identity_matches(identity, &observed) {
        return Err("child process identity changed before group cleanup".to_string());
    }
    Ok(())
}

fn bound_process_group_exists(identity: &ProcessIdentity) -> std::result::Result<bool, String> {
    if !process_group_exists(identity.process_group)? {
        return Ok(false);
    }
    match observe_process_identity(identity.pid).map_err(|error| error.to_string())? {
        Some(_) => {
            ensure_bound_process_group(identity)?;
            Ok(true)
        }
        None => bound_process_group_has_member(identity),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bound_process_group_has_member(identity: &ProcessIdentity) -> std::result::Result<bool, String> {
    let entries = fs::read_dir("/proc").map_err(|error| error.to_string())?;
    let deadline = Instant::now()
        .checked_add(PROCESS_GROUP_SCAN_BUDGET)
        .unwrap_or_else(Instant::now);
    for entry in entries {
        if Instant::now() >= deadline {
            return Err("process-group member scan exceeded its bounded deadline".to_string());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == identity.pid {
            continue;
        }
        match read_proc_group_identity(pid) {
            Ok(Some((process_group, session_id)))
                if process_group == identity.process_group && session_id == identity.session_id =>
            {
                return Ok(true);
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(error) => {
                return Err(format!(
                    "process-group member identity probe failed: {error}"
                ));
            }
        }
    }
    Ok(false)
}

/// Read only the process-group/session fields needed while proving that a
/// bound group still has a member after its leader has exited.  `/proc`
/// exposes kernel worker threads whose stat records use zero for these fields;
/// those are not userspace group members and must be ignored rather than
/// turning an otherwise valid cleanup scan into an uncertainty.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_proc_group_identity(pid: u32) -> std::io::Result<Option<(u32, u32)>> {
    let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| std::io::Error::other("proc stat omitted command terminator"))?;
    let fields = stat
        .get(command_end + 1..)
        .ok_or_else(|| std::io::Error::other("proc stat is truncated"))?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
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
    Ok(Some((process_group, session_id)))
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bound_process_group_has_member(identity: &ProcessIdentity) -> std::result::Result<bool, String> {
    process_group_exists(identity.process_group)
}

fn reap_child_bounded(mut child: Child, timeout: Duration) {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
        }
    }
    let _ = thread::Builder::new()
        .name("owner-open-direct-runtime-abort-reaper".to_string())
        .spawn(move || {
            let _ = child.wait();
        });
}

fn post_exit_grace(limits: &MechanicalLimits) -> Duration {
    let scaled = limits
        .terminate_grace
        .checked_mul(4)
        .unwrap_or(Duration::from_secs(10));
    scaled.clamp(Duration::from_secs(1), Duration::from_secs(10))
}

fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn terminal_observation(
    kind: TerminalKind,
    exit_code: Option<i32>,
    signal: Option<i32>,
    (stdout_bytes, stderr_bytes): (usize, usize),
    output_truncated: bool,
    started_at: Instant,
    error: Option<String>,
) -> ExecutionTerminal {
    ExecutionTerminal {
        kind,
        exit_code,
        signal,
        stdout_bytes: u64::try_from(stdout_bytes).unwrap_or(u64::MAX),
        stderr_bytes: u64::try_from(stderr_bytes).unwrap_or(u64::MAX),
        output_truncated,
        elapsed_ms: elapsed_ms(started_at),
        error,
    }
}

fn join_error(existing: Option<String>, next: String) -> String {
    match existing {
        Some(existing) => format!("{existing}; {next}"),
        None => next,
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn proc_stat_identity_parser_binds_generation_and_namespace() {
        let mut fields = vec!["S", "0", "1234", "5678"];
        while fields.len() < 19 {
            fields.push("0");
        }
        fields.push("4242");
        let stat = format!("17 (worker (nested)) {}", fields.join(" "));
        assert_eq!(parse_proc_stat_identity(&stat).unwrap(), (4242, 1234, 5678));
    }

    #[test]
    fn current_process_identity_is_stable_and_generation_bound() {
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
    fn local_sha256_matches_the_standard_abc_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn unbound_spawn_guard_never_broadcasts_to_raw_pid_group() {
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
        let mut member = member_command.spawn().expect("spawn process-group member");
        let member_pid = member.id();
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline
            && unsafe { libc::getpgid(member_pid as libc::pid_t) } != leader_pid as libc::pid_t
        {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            unsafe { libc::getpgid(member_pid as libc::pid_t) },
            leader_pid as libc::pid_t
        );

        // Model a post-spawn identity-capture failure.  Drop may kill the
        // exact leader handle, but must not infer a group target from its PID.
        drop(ProcessChildGuard::new(leader, Duration::from_millis(20)));
        assert!(unsafe { libc::kill(member_pid as libc::pid_t, 0) } == 0);
        let _ = member.kill();
        let _ = member.wait();
    }
}
