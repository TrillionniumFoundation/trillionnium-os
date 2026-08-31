use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::{
    InternalProcessEvent, JobInvocation, JobRuntimeError, JobStartRequest, PtySize, Result,
};

const PROCESS_EVENT_QUEUE: usize = 256;
const DESCENDANT_TERM_GRACE: Duration = Duration::from_millis(100);
const DESCENDANT_KILL_GRACE: Duration = Duration::from_millis(100);
const SPAWN_GUARD_REAP_GRACE: Duration = Duration::from_millis(500);
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

enum InputHandle {
    Pipe(ChildStdin),
    Pty(File),
}

pub(crate) struct ProcessControl {
    pub pid: u32,
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
}

impl SpawnGuard {
    fn new(child: Child) -> Self {
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
        }
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
        let _ = send_process_group_signal(self.pid, libc::SIGKILL);
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
                if let Err(error) = master.write_all(&[0x04]).and_then(|_| master.flush()) {
                    self.pty_eof_sent.store(false, Ordering::Release);
                    return Err(JobRuntimeError::Io(error.to_string()));
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
        send_process_group_signal(self.pid, signal).map_err(JobRuntimeError::Control)
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
    let pid = guard.pid;
    let stdin = guard
        .child_mut()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?
        .stdin
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stdin was not piped".to_string()))?;
    let stdout = guard
        .child_mut()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?
        .stdout
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stdout was not piped".to_string()))?;
    let stderr = guard
        .child_mut()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?
        .stderr
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stderr was not piped".to_string()))?;
    let input = Arc::new(Mutex::new(Some(InputHandle::Pipe(stdin))));
    let (sender, receiver) = sync_channel(PROCESS_EVENT_QUEUE);
    let stdout_thread = spawn_reader(stdout, "stdout", maximum_chunk, sender.clone())?;
    let stderr_thread = spawn_reader(stderr, "stderr", maximum_chunk, sender.clone())?;
    let mut workers = vec![stdout_thread, stderr_thread];
    if let Some(writer) = spawn_initial_writer(
        Arc::clone(&input),
        request.initial_stdin.clone(),
        sender.clone(),
    )? {
        workers.push(writer);
    }
    spawn_reaper(guard, workers, sender)?;
    Ok(SpawnedProcess {
        control: Arc::new(ProcessControl {
            pid,
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
    let guard = SpawnGuard::new(child);
    let pid = guard.pid;
    drop(slave);
    let master = Arc::new(master);
    let reader = master
        .try_clone()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    let writer = master
        .try_clone()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    let input = Arc::new(Mutex::new(Some(InputHandle::Pty(writer))));
    let (sender, receiver) = sync_channel(PROCESS_EVENT_QUEUE);
    let reader_thread = spawn_reader(reader, "pty", maximum_chunk, sender.clone())?;
    let mut workers = vec![reader_thread];
    if let Some(writer) = spawn_initial_writer(
        Arc::clone(&input),
        request.initial_stdin.clone(),
        sender.clone(),
    )? {
        workers.push(writer);
    }
    spawn_reaper(guard, workers, sender)?;
    Ok(SpawnedProcess {
        control: Arc::new(ProcessControl {
            pid,
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
    match handle {
        InputHandle::Pipe(stdin) => stdin
            .write_all(bytes)
            .and_then(|_| stdin.flush())
            .map_err(|error| JobRuntimeError::Io(error.to_string())),
        InputHandle::Pty(master) => master
            .write_all(bytes)
            .and_then(|_| master.flush())
            .map_err(|error| JobRuntimeError::Io(error.to_string())),
    }
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
    thread::Builder::new()
        .name(format!("owner-open-job-reaper-{pid}"))
        .spawn(move || {
            let status = guard.wait();
            let mut cleanup_errors = Vec::new();
            if let Err(error) = cleanup_process_group(pid) {
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

fn cleanup_process_group(pid: u32) -> std::result::Result<(), String> {
    if !process_group_exists(pid)? {
        return Ok(());
    }
    send_process_group_signal(pid, libc::SIGTERM)?;
    let term_deadline = Instant::now()
        .checked_add(DESCENDANT_TERM_GRACE)
        .unwrap_or_else(Instant::now);
    while Instant::now() < term_deadline {
        if !process_group_exists(pid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    send_process_group_signal(pid, libc::SIGKILL)?;
    let kill_deadline = Instant::now()
        .checked_add(DESCENDANT_KILL_GRACE)
        .unwrap_or_else(Instant::now);
    while Instant::now() < kill_deadline {
        if !process_group_exists(pid)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
    if process_group_exists(pid)? {
        Err("process group remains observable after SIGKILL grace".to_string())
    } else {
        Ok(())
    }
}

fn process_group_exists(pid: u32) -> std::result::Result<bool, String> {
    let process_group = i32::try_from(pid)
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

fn send_process_group_signal(pid: u32, signal: i32) -> std::result::Result<(), String> {
    let process_group = i32::try_from(pid)
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
