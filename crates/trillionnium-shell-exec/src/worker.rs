use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use trillionnium_os_types::direct_effect::{
    DirectEffectBinaryOutputV1, DirectEffectIndeterminateReasonV1, DirectEffectRequestV1,
    DirectEffectTerminalKindV1, DirectEffectTerminalResponseV1, TERMINAL_RESPONSE_SCHEMA,
};

use crate::{
    CancellationTokenV1, ShellExecWorkerV1, WorkerCompletionV1, validate_first_slice_request,
};

const PIPE_CHUNK_BYTES: usize = 16 * 1024;
const WAIT_POLL: Duration = Duration::from_millis(2);
const FORCED_CLEANUP_GRACE: Duration = Duration::from_millis(250);

#[derive(Clone, Debug)]
pub struct RootLinuxPathPolicyV1 {
    workspace_root: PathBuf,
    _temporary_root: PathBuf,
}

impl RootLinuxPathPolicyV1 {
    /// Host conformance only. Product must receive these roots from measured
    /// Root Linux namespace custody rather than a caller-supplied path.
    pub fn for_host_conformance(
        workspace_root: impl Into<PathBuf>,
        temporary_root: impl Into<PathBuf>,
    ) -> std::io::Result<Self> {
        let workspace_root = fs::canonicalize(workspace_root.into())?;
        let temporary_root = fs::canonicalize(temporary_root.into())?;
        if !workspace_root.is_dir() || !temporary_root.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "shell exec roots must be directories",
            ));
        }
        Ok(Self {
            workspace_root,
            _temporary_root: temporary_root,
        })
    }

    fn cwd_for(&self, request: &DirectEffectRequestV1) -> std::io::Result<PathBuf> {
        use trillionnium_os_types::direct_effect::DirectEffectWorkingDirectoryScopeV1;

        let (root, relative) = match &request.arguments.cwd {
            Some(cwd) => match cwd.scope {
                DirectEffectWorkingDirectoryScopeV1::Workspace => {
                    (&self.workspace_root, Some(cwd.relative.as_str()))
                }
            },
            None => (&self.workspace_root, None),
        };
        let candidate = relative.map_or_else(|| root.clone(), |relative| root.join(relative));
        let canonical = fs::canonicalize(candidate)?;
        if !canonical.is_dir() || !canonical.starts_with(root) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "shell exec cwd escaped its fixed scope",
            ));
        }
        Ok(canonical)
    }
}

pub struct HostConformanceWorkerV1 {
    paths: RootLinuxPathPolicyV1,
}

impl HostConformanceWorkerV1 {
    #[must_use]
    pub fn new(paths: RootLinuxPathPolicyV1) -> Self {
        Self { paths }
    }
}

impl ShellExecWorkerV1 for HostConformanceWorkerV1 {
    fn execute(
        &mut self,
        request: &DirectEffectRequestV1,
        dispatch_started_boottime_ms: u64,
        cancellation: &CancellationTokenV1,
    ) -> std::result::Result<WorkerCompletionV1, String> {
        validate_first_slice_request(request).map_err(|error| error.to_string())?;
        let cwd = self
            .paths
            .cwd_for(request)
            .map_err(|error| format!("cwd_policy_denied:{error}"))?;
        let executable = request.arguments.argv[0].as_str();
        let mut command = Command::new(executable);
        command
            .args(&request.arguments.argv[1..])
            .current_dir(cwd)
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("HOME", "/var/empty")
            .env("LANG", "C.UTF-8")
            .env("LC_ALL", "C.UTF-8")
            .env("TMPDIR", "/tmp")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: the closure uses async-signal-safe libc calls only and does
        // not allocate. Product adds namespace/cgroup/seccomp custody before
        // this host-conformance seam can be promoted.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        // CWD resolution and command construction happen after the broker's
        // post-marker sample. Re-sample immediately before fork/exec so a
        // cancellation or deadline crossing in that window never launches a
        // process. DISPATCHED is already durable, hence the conservative
        // indeterminate classification.
        let pre_spawn_boottime_ms = boottime_ms().max(dispatch_started_boottime_ms);
        if cancellation.is_cancelled() {
            return Ok(WorkerCompletionV1::Indeterminate {
                reason: DirectEffectIndeterminateReasonV1::CancelledAfterDispatch,
                observed_boottime_ms: pre_spawn_boottime_ms,
            });
        }
        if pre_spawn_boottime_ms >= request.absolute_deadline_boottime_ms {
            return Ok(WorkerCompletionV1::Indeterminate {
                reason: DirectEffectIndeterminateReasonV1::DeadlineAfterDispatch,
                observed_boottime_ms: pre_spawn_boottime_ms,
            });
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                let response = terminal_response(
                    request,
                    dispatch_started_boottime_ms,
                    boottime_ms().max(dispatch_started_boottime_ms),
                    DirectEffectTerminalKindV1::LaunchRejected,
                    None,
                    None,
                    Some("execve_denied".to_string()),
                    b"",
                    b"",
                );
                return Ok(WorkerCompletionV1::Terminal(response));
            }
        };
        let process_group = child.id() as i32;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| "stdout_pipe_missing".to_string())?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| "stderr_pipe_missing".to_string())?;
        set_nonblocking(stdout.as_raw_fd()).map_err(|error| error.to_string())?;
        set_nonblocking(stderr.as_raw_fd()).map_err(|error| error.to_string())?;

        let mut stdout_bytes = Vec::new();
        let mut stderr_bytes = Vec::new();
        let mut stdout_closed = false;
        let mut stderr_closed = false;
        let mut forced_reason = None;
        let mut status = None;
        let mut group_killed = false;
        let mut forced_cleanup_deadline_ms = None;
        loop {
            drain_nonblocking_pipe(
                &mut stdout,
                &mut stdout_bytes,
                &mut stdout_closed,
                request.arguments.stdout_limit_bytes,
                stderr_bytes.len(),
                request.arguments.total_output_limit_bytes,
                &mut forced_reason,
            );
            drain_nonblocking_pipe(
                &mut stderr,
                &mut stderr_bytes,
                &mut stderr_closed,
                request.arguments.stderr_limit_bytes,
                stdout_bytes.len(),
                request.arguments.total_output_limit_bytes,
                &mut forced_reason,
            );

            if forced_reason.is_none() {
                if cancellation.is_cancelled() {
                    forced_reason = Some(DirectEffectIndeterminateReasonV1::CancelledAfterDispatch);
                } else if boottime_ms() >= request.absolute_deadline_boottime_ms {
                    forced_reason = Some(DirectEffectIndeterminateReasonV1::DeadlineAfterDispatch);
                }
            }

            if forced_reason.is_some() && !group_killed {
                kill_process_group(process_group);
                group_killed = true;
                forced_cleanup_deadline_ms =
                    Some(boottime_ms().saturating_add(FORCED_CLEANUP_GRACE.as_millis() as u64));
            }

            if status.is_none() {
                status = child.try_wait().map_err(|error| error.to_string())?;
            }

            if status.is_some() && forced_reason.is_none() && (!stdout_closed || !stderr_closed) {
                // The child may have exited immediately after the first drain.
                // Re-observe both pipes after collecting exit status before
                // classifying an inherited descriptor as an escape.
                drain_nonblocking_pipe(
                    &mut stdout,
                    &mut stdout_bytes,
                    &mut stdout_closed,
                    request.arguments.stdout_limit_bytes,
                    stderr_bytes.len(),
                    request.arguments.total_output_limit_bytes,
                    &mut forced_reason,
                );
                drain_nonblocking_pipe(
                    &mut stderr,
                    &mut stderr_bytes,
                    &mut stderr_closed,
                    request.arguments.stderr_limit_bytes,
                    stdout_bytes.len(),
                    request.arguments.total_output_limit_bytes,
                    &mut forced_reason,
                );
            }

            if status.is_some() && forced_reason.is_none() && (!stdout_closed || !stderr_closed) {
                // A normal main-process exit must synchronously close both
                // capture pipes. An inherited descriptor proves a descendant
                // escaped the main process lifetime. Kill its process group,
                // bound cleanup, and refuse to report a definitive terminal
                // result even if the pipes subsequently close.
                forced_reason = Some(DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch);
                kill_process_group(process_group);
                group_killed = true;
                forced_cleanup_deadline_ms =
                    Some(boottime_ms().saturating_add(FORCED_CLEANUP_GRACE.as_millis() as u64));
            }

            if status.is_some() && stdout_closed && stderr_closed {
                break;
            }

            if forced_reason.is_some()
                && forced_cleanup_deadline_ms.is_some_and(|deadline| boottime_ms() >= deadline)
            {
                // Dropping the nonblocking pipe handles prevents an escaped
                // descendant from hanging the broker. Product promotion still
                // requires cgroup/namespace custody capable of proving that
                // no process escaped this cleanup boundary.
                break;
            }

            thread::sleep(WAIT_POLL);
        }

        let finished = boottime_ms().max(dispatch_started_boottime_ms);
        if let Some(reason) = forced_reason {
            return Ok(WorkerCompletionV1::Indeterminate {
                reason,
                observed_boottime_ms: finished,
            });
        }
        let status = status.ok_or_else(|| "child_exit_status_missing".to_string())?;
        let (kind, exit_code, signal) = match status.code() {
            Some(code) => (DirectEffectTerminalKindV1::Exited, Some(code), None),
            None => (
                DirectEffectTerminalKindV1::Signaled,
                None,
                status.signal().map(|value| value as u32),
            ),
        };
        Ok(WorkerCompletionV1::Terminal(terminal_response(
            request,
            dispatch_started_boottime_ms,
            finished,
            kind,
            exit_code,
            signal,
            None,
            &stdout_bytes,
            &stderr_bytes,
        )))
    }
}

fn set_nonblocking(fd: i32) -> std::io::Result<()> {
    // SAFETY: fd is an owned child pipe and fcntl does not outlive it.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: same owned descriptor; only O_NONBLOCK is added.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn drain_nonblocking_pipe<R: Read>(
    reader: &mut R,
    output: &mut Vec<u8>,
    closed: &mut bool,
    stream_limit: u64,
    other_len: usize,
    total_limit: u64,
    forced_reason: &mut Option<DirectEffectIndeterminateReasonV1>,
) {
    if *closed {
        return;
    }
    let mut buffer = [0_u8; PIPE_CHUNK_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                *closed = true;
                return;
            }
            Ok(read) => append_bounded(
                output,
                &buffer[..read],
                stream_limit,
                other_len,
                total_limit,
                forced_reason,
            ),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return,
            Err(_) => {
                *closed = true;
                *forced_reason = Some(DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch);
                return;
            }
        }
    }
}

fn append_bounded(
    output: &mut Vec<u8>,
    incoming: &[u8],
    stream_limit: u64,
    other_len: usize,
    total_limit: u64,
    forced_reason: &mut Option<DirectEffectIndeterminateReasonV1>,
) {
    let stream_remaining = stream_limit.saturating_sub(output.len() as u64) as usize;
    let total_used = output.len().saturating_add(other_len) as u64;
    let total_remaining = total_limit.saturating_sub(total_used) as usize;
    let accepted = incoming.len().min(stream_remaining).min(total_remaining);
    output.extend_from_slice(&incoming[..accepted]);
    if accepted != incoming.len() {
        *forced_reason = Some(DirectEffectIndeterminateReasonV1::OutputLimitAfterDispatch);
    }
}

fn kill_process_group(process_group: i32) {
    // SAFETY: a negative PID targets only the freshly-created process group.
    unsafe {
        libc::kill(-process_group, libc::SIGKILL);
    }
}

fn boottime_ms() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is valid writable storage.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return 0;
    }
    u64::try_from(value.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1000)
        .saturating_add(u64::try_from(value.tv_nsec).unwrap_or(0) / 1_000_000)
}

#[allow(clippy::too_many_arguments)]
fn terminal_response(
    request: &DirectEffectRequestV1,
    started: u64,
    finished: u64,
    kind: DirectEffectTerminalKindV1,
    exit_code: Option<i32>,
    signal: Option<u32>,
    backend_error_code: Option<String>,
    stdout: &[u8],
    stderr: &[u8],
) -> DirectEffectTerminalResponseV1 {
    DirectEffectTerminalResponseV1 {
        schema: TERMINAL_RESPONSE_SCHEMA.to_string(),
        effect_id: request.effect_id.clone(),
        request_sha256: request.request_sha256.clone(),
        dispatch_occurred: true,
        kind,
        exit_code,
        signal,
        backend_error_code,
        stdout: DirectEffectBinaryOutputV1::from_complete_bytes(stdout),
        stderr: DirectEffectBinaryOutputV1::from_complete_bytes(stderr),
        started_boottime_ms: started,
        finished_boottime_ms: finished,
    }
}

#[allow(dead_code)]
fn _absolute_path_only(path: &Path) -> bool {
    path.is_absolute()
}
