use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::types::{
    AdbExecRequest, CancellationToken, ExecutionEvent, ExecutionEventKind, ExecutionTerminal,
    MechanicalLimits, ProcessSpec, Result, ShellExecRequest, StreamKind, TerminalKind,
};
use crate::validate::{adb_spec, shell_spec};

#[derive(Debug)]
enum ReaderMessage {
    Chunk(StreamKind, Vec<u8>),
    Eof(StreamKind),
    Error(StreamKind, String),
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

/// Execute an ordinary adb process with exact argv passthrough. This function
/// never inserts `-s`, a host/port, a privilege mode, or a known-subcommand
/// restriction. `target_id` is correlation metadata only.
pub fn execute_adb<F>(
    request: AdbExecRequest,
    limits: &MechanicalLimits,
    cancellation: &CancellationToken,
    sink: F,
) -> Result<ExecutionTerminal>
where
    F: FnMut(ExecutionEvent),
{
    execute_process(adb_spec(request, limits)?, limits, cancellation, sink)
}

fn execute_process<F>(
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

    let mut command = Command::new(&spec.program);
    command
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
        command.pre_exec(move || configure_child_lifecycle(parent_pid));
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let terminal = ExecutionTerminal {
                kind: TerminalKind::SpawnFailed,
                exit_code: None,
                signal: None,
                stdout_bytes: 0,
                stderr_bytes: 0,
                output_truncated: false,
                elapsed_ms: elapsed_ms(started_at),
                error: Some(error.to_string()),
            };
            emit(ExecutionEventKind::Terminal(terminal.clone()));
            return Ok(terminal);
        }
    };

    let pid = child.id();
    emit(ExecutionEventKind::Started { pid });

    // Readers are live before initial stdin is written. This order prevents a
    // child that writes before reading from deadlocking the Host setup path.
    let (sender, receiver) = sync_channel::<ReaderMessage>(limits.reader_queue_depth);
    let stdout_thread = child.stdout.take().map(|stdout| {
        spawn_reader(
            stdout,
            StreamKind::Stdout,
            limits.stream_chunk_bytes,
            sender.clone(),
        )
    });
    let stderr_thread = child.stderr.take().map(|stderr| {
        spawn_reader(
            stderr,
            StreamKind::Stderr,
            limits.stream_chunk_bytes,
            sender,
        )
    });
    let stdin_thread = child.stdin.take().map(|mut stdin| {
        let bytes = spec.stdin;
        thread::spawn(move || {
            if bytes.is_empty() {
                return None;
            }
            match stdin.write_all(&bytes).and_then(|_| stdin.flush()) {
                Ok(()) => None,
                Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
                    Some(format!("stdin_closed: {error}"))
                }
                Err(error) => Some(format!("stdin_io_error: {error}")),
            }
        })
    });

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
                    match process_group_exists(pid) {
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
            match terminate_process_group(&mut child, pid, limits.terminate_grace) {
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
                        StreamKind::Stdout => stdout_bytes = stdout_bytes.saturating_add(delivered),
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
                StreamKind::Stdout => stdout_eof = true,
                StreamKind::Stderr => stderr_eof = true,
            },
            Ok(ReaderMessage::Error(stream, error)) => {
                runtime_error = Some(join_error(runtime_error, error));
                forced_kind.get_or_insert(TerminalKind::IoError);
                match stream {
                    StreamKind::Stdout => stdout_eof = true,
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
        match terminate_process_group(&mut child, pid, limits.terminate_grace) {
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

fn configure_child_lifecycle(parent_pid: libc::pid_t) -> std::io::Result<()> {
    if unsafe { libc::setpgid(0, 0) } != 0 {
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
                Err(error) => {
                    let _ = sender.send(ReaderMessage::Error(
                        stream,
                        format!(
                            "{}_read_error: {error}",
                            match stream {
                                StreamKind::Stdout => "stdout",
                                StreamKind::Stderr => "stderr",
                            }
                        ),
                    ));
                    return;
                }
            }
        }
    })
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
    pid: u32,
    grace: Duration,
) -> std::result::Result<ExitStatus, String> {
    let grace = grace.max(Duration::from_millis(250));
    let mut status = child
        .try_wait()
        .map_err(|error| format!("child_status_before_cleanup_failed: {error}"))?;

    if process_group_exists(pid)? {
        send_process_group_signal(pid, libc::SIGTERM)?;
        let deadline = Instant::now()
            .checked_add(grace)
            .unwrap_or_else(Instant::now);
        while Instant::now() < deadline {
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|error| format!("child_status_after_sigterm_failed: {error}"))?;
            }
            if status.is_some() && !process_group_exists(pid)? {
                return status.ok_or("child status disappeared".to_string());
            }
            thread::sleep(Duration::from_millis(5));
        }

        send_process_group_signal(pid, libc::SIGKILL)?;
    }

    // A child can change its own process group between spawn and cleanup. Kill
    // the direct PID as a bounded fallback; never turn a missing PGID into an
    // unbounded child.wait().
    if status.is_none() {
        match child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
            Err(error) => return Err(format!("direct_child_sigkill_failed: {error}")),
        }
    }

    let deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| format!("child_status_after_sigkill_failed: {error}"))?;
        }
        let group_alive = process_group_exists(pid)?;
        if status.is_some() && !group_alive {
            return status.ok_or("child status disappeared".to_string());
        }
        thread::sleep(Duration::from_millis(5));
    }

    let group_alive = process_group_exists(pid).unwrap_or(true);
    Err(format!(
        "process_cleanup_deadline_exceeded: leader_reaped={}, process_group_alive={group_alive}",
        status.is_some()
    ))
}

fn process_group_exists(pid: u32) -> std::result::Result<bool, String> {
    let group = i32::try_from(pid)
        .map_err(|_| "child pid does not fit a POSIX process-group id".to_string())?;
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

fn send_process_group_signal(pid: u32, signal: i32) -> std::result::Result<(), String> {
    let group = i32::try_from(pid)
        .map_err(|_| "child pid does not fit a POSIX process-group id".to_string())?;
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

fn join_error(existing: Option<String>, next: String) -> String {
    match existing {
        Some(existing) => format!("{existing}; {next}"),
        None => next,
    }
}
