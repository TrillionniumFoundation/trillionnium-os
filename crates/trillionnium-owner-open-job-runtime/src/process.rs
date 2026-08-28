use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::{
    InternalProcessEvent, JobInvocation, JobRuntimeError, JobStartRequest, PtySize, Result,
};

const PROCESS_EVENT_QUEUE: usize = 256;

enum InputHandle {
    Pipe(ChildStdin),
    Pty(File),
}

pub(crate) struct ProcessControl {
    pub pid: u32,
    pub pty: bool,
    input: Arc<Mutex<Option<InputHandle>>>,
    pty_master: Option<Arc<File>>,
}

pub(crate) struct SpawnedProcess {
    pub control: Arc<ProcessControl>,
    pub events: Receiver<InternalProcessEvent>,
}

impl ProcessControl {
    pub fn write(&self, bytes: &[u8]) -> Result<()> {
        let mut guard = self
            .input
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        let handle = guard.as_mut().ok_or(JobRuntimeError::NotLive)?;
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

    pub fn close_stdin(&self) -> Result<()> {
        let mut guard = self
            .input
            .lock()
            .map_err(|_| JobRuntimeError::StatePoisoned)?;
        match guard.as_mut() {
            None => Ok(()),
            Some(InputHandle::Pipe(_)) => {
                *guard = None;
                Ok(())
            }
            Some(InputHandle::Pty(master)) => master
                .write_all(&[0x04])
                .and_then(|_| master.flush())
                .map_err(|error| JobRuntimeError::Io(error.to_string())),
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
        let pid = i32::try_from(self.pid)
            .map_err(|_| JobRuntimeError::Control("pid is out of range".to_string()))?;
        let result = unsafe { libc::kill(-pid, signal) };
        if result == 0 {
            Ok(())
        } else {
            Err(JobRuntimeError::Control(
                std::io::Error::last_os_error().to_string(),
            ))
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
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|error| JobRuntimeError::Spawn(error.to_string()))?;
    let pid = child.id();
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stdin was not piped".to_string()))?;
    if !request.initial_stdin.is_empty() {
        stdin
            .write_all(&request.initial_stdin)
            .and_then(|_| stdin.flush())
            .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    }
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stdout was not piped".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| JobRuntimeError::Io("child stderr was not piped".to_string()))?;
    let (sender, receiver) = sync_channel(PROCESS_EVENT_QUEUE);
    let stdout_thread = spawn_reader(stdout, "stdout", maximum_chunk, sender.clone());
    let stderr_thread = spawn_reader(stderr, "stderr", maximum_chunk, sender.clone());
    spawn_reaper(child, vec![stdout_thread, stderr_thread], sender);
    Ok(SpawnedProcess {
        control: Arc::new(ProcessControl {
            pid,
            pty: false,
            input: Arc::new(Mutex::new(Some(InputHandle::Pipe(stdin)))),
            pty_master: None,
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
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave_raw, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|error| JobRuntimeError::Spawn(error.to_string()))?;
    let pid = child.id();
    drop(slave);
    let master = Arc::new(master);
    let mut initial_writer = master
        .try_clone()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    if !request.initial_stdin.is_empty() {
        initial_writer
            .write_all(&request.initial_stdin)
            .and_then(|_| initial_writer.flush())
            .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    }
    let reader = master
        .try_clone()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    let writer = master
        .try_clone()
        .map_err(|error| JobRuntimeError::Io(error.to_string()))?;
    let (sender, receiver) = sync_channel(PROCESS_EVENT_QUEUE);
    let reader_thread = spawn_reader(reader, "pty", maximum_chunk, sender.clone());
    spawn_reaper(child, vec![reader_thread], sender);
    Ok(SpawnedProcess {
        control: Arc::new(ProcessControl {
            pid,
            pty: true,
            input: Arc::new(Mutex::new(Some(InputHandle::Pty(writer)))),
            pty_master: Some(master),
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
    set_cloexec(master)?;
    set_cloexec(slave)?;
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
) -> JoinHandle<()>
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
        .expect("spawn owner-open job reader")
}

fn spawn_reaper(
    mut child: std::process::Child,
    readers: Vec<JoinHandle<()>>,
    sender: SyncSender<InternalProcessEvent>,
) {
    thread::Builder::new()
        .name(format!("owner-open-job-reaper-{}", child.id()))
        .spawn(move || {
            let status = child.wait();
            for reader in readers {
                let _ = reader.join();
            }
            let event = match status {
                Ok(status) => InternalProcessEvent::Exited {
                    terminal_kind: if status.signal().is_some() {
                        "signaled".to_string()
                    } else {
                        "exited".to_string()
                    },
                    exit_code: status.code(),
                    signal: status.signal(),
                },
                Err(error) => InternalProcessEvent::ReaderFailed {
                    stream: "reaper".to_string(),
                    error: error.to_string(),
                },
            };
            let _ = sender.send(event);
        })
        .expect("spawn owner-open job reaper");
}
