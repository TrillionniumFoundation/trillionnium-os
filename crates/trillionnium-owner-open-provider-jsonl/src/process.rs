use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::ops::{Deref, DerefMut};
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(crate) enum ProviderOutput {
    Line(Vec<u8>),
    Eof,
    Error(String),
}

const SPAWN_GUARD_REAP_GRACE: Duration = Duration::from_millis(500);
const PROCESS_GROUP_SCAN_BUDGET: Duration = Duration::from_millis(500);

/// Kernel-observed identity for a provider leader and its process namespace.
///
/// On Linux/Android the start-time and boot-id fields distinguish a live PID
/// from a later PID reuse.  PGID and SID bind descendant cleanup to the group
/// created by this spawn rather than to a raw, potentially recycled PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: u32,
    pub(crate) process_group: u32,
    pub(crate) session_id: u32,
    pub(crate) start_time_ticks: Option<u64>,
    pub(crate) boot_id_sha256: Option<String>,
}

/// Owns a spawned provider until its process group has been reaped.
///
/// `Child`'s default `Drop` implementation only closes the handles; it does
/// not terminate a provider or descendants that inherited one of the pipes.
/// The JSONL adapter performs several fallible setup operations after spawn
/// (pipe extraction and reader-thread creation), so a guard is installed
/// immediately after a successful spawn.  Any early return consequently
/// executes the same bounded process-group cleanup as the normal turn path.
pub(crate) struct ProviderChildGuard {
    child: Option<Child>,
    pid: u32,
    grace: Duration,
    identity: Option<ProcessIdentity>,
    armed: bool,
}

impl ProviderChildGuard {
    pub(crate) fn new(child: Child, grace: Duration) -> Self {
        let pid = child.id();
        Self {
            child: Some(child),
            pid,
            grace,
            identity: None,
            armed: true,
        }
    }

    pub(crate) fn bind_identity(&mut self, identity: ProcessIdentity) {
        debug_assert_eq!(identity.pid, self.pid);
        self.identity = Some(identity);
    }

    fn child_mut(&mut self) -> Result<&mut Child, String> {
        self.child
            .as_mut()
            .ok_or_else(|| "provider guard no longer owns its child".to_string())
    }

    /// Explicitly reap the process group.  A failed cleanup leaves the guard
    /// armed so `Drop` gets one last bounded attempt without replacing the
    /// caller's primary provider/protocol error.
    pub(crate) fn finish(&mut self) -> Result<ExitStatus, String> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| "provider process identity was not bound".to_string())?
            .clone();
        let grace = self.grace;
        let result = finish_child(self.child_mut()?, &identity, grace);
        if result.is_ok() {
            self.armed = false;
        }
        result
    }
}

impl Deref for ProviderChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        self.child
            .as_ref()
            .expect("provider guard no longer owns its child")
    }
}

impl DerefMut for ProviderChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child
            .as_mut()
            .expect("provider guard no longer owns its child")
    }
}

impl Drop for ProviderChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(mut child) = self.child.take() else {
            self.armed = false;
            return;
        };
        // Cleanup is best effort in `Drop`: the semantic error that caused an
        // early return must remain the one observed by the caller.  A missing
        // identity is never converted into `kill(-pid, ...)`; the exact Child
        // handle is the only safe primitive until generation/PGID/SID capture
        // succeeds.
        if let Some(identity) = self.identity.as_ref() {
            let _ = finish_child(&mut child, identity, self.grace);
        } else {
            let _ = child.kill();
            reap_child_bounded(child, SPAWN_GUARD_REAP_GRACE);
            self.armed = false;
            return;
        }
        // `finish_child` normally reaps the leader.  If it could not prove
        // the original group, still preserve exact Child wait ownership with
        // a bounded fallback; never broadcast to an unverified group.
        reap_child_bounded(child, SPAWN_GUARD_REAP_GRACE);
        self.armed = false;
    }
}

pub(crate) fn spawn_stdout_reader(
    stdout: impl Read + Send + 'static,
    max_line_bytes: usize,
    max_stdout_bytes: usize,
    sender: SyncSender<ProviderOutput>,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("owner-open-provider-stdout".to_string())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut total = 0usize;
            loop {
                match read_bounded_line(&mut reader, max_line_bytes) {
                    Ok(Some(line)) => {
                        total = match total.checked_add(line.len().saturating_add(1)) {
                            Some(total) if total <= max_stdout_bytes => total,
                            _ => {
                                let _ = sender.send(ProviderOutput::Error(
                                    "provider aggregate stdout exceeds its bound".to_string(),
                                ));
                                return;
                            }
                        };
                        if sender.send(ProviderOutput::Line(line)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(ProviderOutput::Eof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(ProviderOutput::Error(error));
                        return;
                    }
                }
            }
        })
}

pub(crate) fn spawn_stderr_reader(
    mut stderr: impl Read + Send + 'static,
    maximum: usize,
    capture: Arc<Mutex<Vec<u8>>>,
    overflow: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("owner-open-provider-stderr".to_string())
        .spawn(move || {
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                match stderr.read(&mut buffer) {
                    Ok(0) => return,
                    Ok(count) => {
                        let Ok(mut bytes) = capture.lock() else {
                            return;
                        };
                        let remaining = maximum.saturating_sub(bytes.len());
                        bytes.extend_from_slice(&buffer[..count.min(remaining)]);
                        if count > remaining {
                            overflow.store(true, Ordering::SeqCst);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return,
                }
            }
        })
}

fn read_bounded_line(reader: &mut impl BufRead, maximum: usize) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    let read = reader
        .take(maximum as u64 + 2)
        .read_until(b'\n', &mut line)
        .map_err(|error| format!("provider stdout read failed: {error}"))?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err("provider JSONL record is unterminated or oversized".to_string());
    }
    line.pop();
    if line.is_empty() || line.len() > maximum {
        return Err("provider JSONL record is empty or oversized".to_string());
    }
    Ok(Some(line))
}

/// Allow a provider that emitted a valid completed terminal to perform its
/// ordinary zero-status exit before process-group cleanup escalates signals.
pub(crate) fn allow_natural_exit_grace(child: &mut Child, grace: Duration) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(grace.max(Duration::from_millis(250)))
        .unwrap_or_else(Instant::now);
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("provider natural-exit status failed: {error}"))?
            .is_some()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Reap the provider leader and prove its original process group is gone.
///
/// The leader may already have exited while one of its descendants still owns
/// stdout/stderr. Returning immediately in that state would let the caller hang
/// forever while joining reader threads. This routine therefore treats leader
/// status and process-group disappearance as separate completion conditions.
pub(crate) fn finish_child(
    child: &mut Child,
    identity: &ProcessIdentity,
    grace: Duration,
) -> Result<ExitStatus, String> {
    let grace = grace.max(Duration::from_millis(250));
    let mut status = match child.try_wait() {
        Ok(status) => status,
        Err(error) => {
            let primary = format!("provider status before cleanup failed: {error}");
            return Err(with_direct_fallback(
                child,
                primary,
                "provider direct SIGKILL after status probe failed",
            ));
        }
    };

    // Never turn a leader PID into a process-group target without first
    // proving that the same PID generation, PGID and SID are still present.
    // If the leader has exited, a matching descendant in the original group
    // is sufficient proof; an unrelated recycled group is not.
    let group_alive = match bound_process_group_exists(identity) {
        Ok(group_alive) => group_alive,
        Err(error) => {
            return Err(with_direct_fallback(
                child,
                error,
                "provider direct SIGKILL after identity probe failed",
            ));
        }
    };
    if group_alive {
        if let Err(error) = send_group_signal(identity.process_group, libc::SIGTERM) {
            return Err(with_direct_fallback(
                child,
                error,
                "provider direct SIGKILL after SIGTERM failed",
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
                        let primary = format!("provider status after SIGTERM failed: {error}");
                        return Err(with_direct_fallback(
                            child,
                            primary,
                            "provider direct SIGKILL after status probe failed",
                        ));
                    }
                };
            }
            if status.is_some() {
                match bound_process_group_exists(identity) {
                    Ok(false) => return status.ok_or("provider status disappeared".to_string()),
                    Ok(true) => {}
                    Err(error) => {
                        return Err(with_direct_fallback(
                            child,
                            error,
                            "provider direct SIGKILL after identity probe failed",
                        ));
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
        // Revalidate immediately before escalation: a group can disappear and
        // its numeric ID can be reused during the TERM grace interval.
        let group_alive = match bound_process_group_exists(identity) {
            Ok(group_alive) => group_alive,
            Err(error) => {
                return Err(with_direct_fallback(
                    child,
                    error,
                    "provider direct SIGKILL after identity probe failed",
                ));
            }
        };
        if group_alive {
            match send_group_signal(identity.process_group, libc::SIGKILL) {
                Ok(()) => {}
                Err(error) => {
                    return Err(with_direct_fallback(
                        child,
                        error,
                        "provider direct SIGKILL after SIGKILL failed",
                    ));
                }
            }
        }
    }

    // If the provider changed its process group after exec, the old PGID can be
    // absent while the direct child is still alive. Kill the direct PID as a
    // bounded fallback instead of calling an unbounded wait().
    if status.is_none() {
        kill_direct_child(child, "provider direct SIGKILL failed")?;
    }

    let deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    let primary = format!("provider status after SIGKILL failed: {error}");
                    return Err(with_direct_fallback(
                        child,
                        primary,
                        "provider direct SIGKILL after status probe failed",
                    ));
                }
            };
        }
        if status.is_some() {
            match bound_process_group_exists(identity) {
                Ok(false) => return status.ok_or("provider status disappeared".to_string()),
                Ok(true) => {}
                Err(error) => {
                    return Err(with_direct_fallback(
                        child,
                        error,
                        "provider direct SIGKILL after identity probe failed",
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
                "provider direct SIGKILL after identity probe failed",
            ));
        }
    };
    Err(format!(
        "provider cleanup deadline exceeded: leader_reaped={}, process_group_alive={group_alive}",
        status.is_some()
    ))
}

fn kill_direct_child(child: &mut Child, context: &str) -> Result<(), String> {
    match child.kill() {
        Ok(()) => Ok(()),
        // `Child::kill` reports InvalidInput when the leader already exited;
        // that is an idempotent cleanup outcome, not a reason to address a
        // process group by an unverified numeric PID.
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

fn process_group_exists(process_group: u32) -> Result<bool, String> {
    let group = i32::try_from(process_group)
        .map_err(|_| "provider process-group id does not fit pid_t".to_string())?;
    if unsafe { libc::kill(-group, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(format!("provider process-group probe failed: {error}")),
    }
}

fn send_group_signal(process_group: u32, signal: i32) -> Result<(), String> {
    let group = i32::try_from(process_group)
        .map_err(|_| "provider process-group id does not fit pid_t".to_string())?;
    if unsafe { libc::kill(-group, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(format!(
            "provider process-group signal {signal} failed: {error}"
        ))
    }
}

/// Capture the child identity immediately after spawn.  The caller must bind
/// this result before extracting pipes or starting reader threads so every
/// post-spawn failure has an identity-aware cleanup path.
#[allow(clippy::needless_return)]
pub(crate) fn capture_process_identity(pid: u32) -> std::io::Result<ProcessIdentity> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let (start_time_ticks, process_group, session_id) = read_proc_stat_identity(pid)?
            .ok_or_else(|| std::io::Error::other("provider exited before identity capture"))?;
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
            .map_err(|_| std::io::Error::other("provider pid does not fit pid_t"))?;
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
                .map_err(|_| std::io::Error::other("invalid provider process group"))?,
            session_id: u32::try_from(session_id)
                .map_err(|_| std::io::Error::other("invalid provider session id"))?,
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
            .map_err(|_| std::io::Error::other("provider pid does not fit pid_t"))?;
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
                .map_err(|_| std::io::Error::other("invalid provider process group"))?,
            session_id: u32::try_from(session_id)
                .map_err(|_| std::io::Error::other("invalid provider session id"))?,
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
        .ok_or_else(|| std::io::Error::other("provider proc stat omitted command terminator"))?;
    let fields = stat
        .get(command_end + 1..)
        .ok_or_else(|| std::io::Error::other("provider proc stat is truncated"))?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    // The first item after the command is field 3 (state): pgrp is field 5,
    // session is field 6, and starttime is field 22.
    let process_group = fields
        .get(2)
        .ok_or_else(|| std::io::Error::other("provider proc stat omitted process group"))?
        .parse::<u32>()
        .map_err(|_| std::io::Error::other("provider proc stat process group is invalid"))?;
    let session_id = fields
        .get(3)
        .ok_or_else(|| std::io::Error::other("provider proc stat omitted session id"))?
        .parse::<u32>()
        .map_err(|_| std::io::Error::other("provider proc stat session id is invalid"))?;
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(|| std::io::Error::other("provider proc stat omitted start time"))?
        .parse::<u64>()
        .map_err(|_| std::io::Error::other("provider proc stat start time is invalid"))?;
    if process_group == 0 || session_id == 0 || start_time_ticks == 0 {
        return Err(std::io::Error::other("provider proc stat identity is zero"));
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
        return Err(std::io::Error::other(
            "provider kernel boot identity is malformed",
        ));
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

fn ensure_bound_process_group(identity: &ProcessIdentity) -> Result<(), String> {
    let observed = observe_process_identity(identity.pid).map_err(|error| error.to_string())?;
    let Some(observed) = observed else {
        if process_group_exists(identity.process_group)?
            && !bound_process_group_has_member(identity)?
        {
            return Err(
                "provider process-group identity cannot be proven after leader exit".to_string(),
            );
        }
        return Ok(());
    };
    if !identity_matches(identity, &observed) {
        return Err("provider process identity changed before group cleanup".to_string());
    }
    Ok(())
}

fn bound_process_group_exists(identity: &ProcessIdentity) -> Result<bool, String> {
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
fn bound_process_group_has_member(identity: &ProcessIdentity) -> Result<bool, String> {
    let entries = fs::read_dir("/proc").map_err(|error| error.to_string())?;
    let deadline = Instant::now()
        .checked_add(PROCESS_GROUP_SCAN_BUDGET)
        .unwrap_or_else(Instant::now);
    for entry in entries {
        if Instant::now() >= deadline {
            return Err(
                "provider process-group member scan exceeded its bounded deadline".to_string(),
            );
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
        match read_proc_stat_identity(pid) {
            Ok(Some((_start, process_group, session_id)))
                if process_group == identity.process_group && session_id == identity.session_id =>
            {
                return Ok(true);
            }
            Ok(Some(_)) | Ok(None) => {}
            Err(error) => {
                return Err(format!(
                    "provider process-group member identity probe failed: {error}"
                ));
            }
        }
    }
    Ok(false)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bound_process_group_has_member(identity: &ProcessIdentity) -> Result<bool, String> {
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
    // Keep wait(2) ownership without allowing a destructor/error path to hang
    // forever.  The detached reaper is only used after the bounded attempt.
    let _ = thread::Builder::new()
        .name("owner-open-provider-abort-reaper".to_string())
        .spawn(move || {
            let _ = child.wait();
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    #[test]
    fn leader_exit_does_not_leave_reader_pipes_owned_by_a_descendant() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("provider-descendant.pid");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("sleep 30 & descendant=$!; printf '%s\\n' \"$descendant\" >\"$1\"; exit 0")
            .arg("owner-open-provider-process-test")
            .arg(&pid_file)
            .stdin(Stdio::null())
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
        let mut child = command.spawn().unwrap();
        let identity = capture_process_identity(child.id()).unwrap();
        let leader_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            assert!(
                Instant::now() < leader_deadline,
                "provider leader did not exit"
            );
            thread::sleep(Duration::from_millis(5));
        }

        let status = finish_child(&mut child, &identity, Duration::from_millis(20)).unwrap();
        assert!(status.success());
        let descendant = fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if unsafe { libc::kill(descendant, 0) } != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    break;
                }
                panic!("unexpected descendant liveness probe error: {error}");
            }
            assert!(
                Instant::now() < deadline,
                "provider descendant survived cleanup"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn proc_stat_identity_parser_binds_generation_and_namespace() {
        let mut fields = vec!["S", "0", "1234", "5678"];
        while fields.len() < 19 {
            fields.push("0");
        }
        fields.push("4242");
        let stat = format!("17 (provider (nested)) {}", fields.join(" "));
        assert_eq!(parse_proc_stat_identity(&stat).unwrap(), (4242, 1234, 5678));
    }

    #[test]
    fn current_provider_identity_is_stable_and_generation_bound() {
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
    fn unbound_provider_guard_never_broadcasts_to_raw_pid_group() {
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
        let leader = leader_command.spawn().expect("spawn provider group leader");
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
        let mut member = member_command.spawn().expect("spawn provider group member");
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

        drop(ProviderChildGuard::new(leader, Duration::from_millis(20)));
        assert!(unsafe { libc::kill(member_pid as libc::pid_t, 0) } == 0);
        let _ = member.kill();
        let _ = member.wait();
    }
}
