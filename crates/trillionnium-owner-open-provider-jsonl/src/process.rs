use std::io::{BufRead, BufReader, Read};
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub(crate) enum ProviderOutput {
    Line(Vec<u8>),
    Eof,
    Error(String),
}

pub(crate) fn spawn_stdout_reader(
    stdout: impl Read + Send + 'static,
    max_line_bytes: usize,
    max_stdout_bytes: usize,
    sender: SyncSender<ProviderOutput>,
) -> JoinHandle<()> {
    thread::spawn(move || {
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
) -> JoinHandle<()> {
    thread::spawn(move || {
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
    pid: u32,
    grace: Duration,
) -> Result<ExitStatus, String> {
    let grace = grace.max(Duration::from_millis(250));
    let mut status = child
        .try_wait()
        .map_err(|error| format!("provider status before cleanup failed: {error}"))?;

    if process_group_exists(pid)? {
        send_group_signal(pid, libc::SIGTERM)?;
        let deadline = Instant::now()
            .checked_add(grace)
            .unwrap_or_else(Instant::now);
        while Instant::now() < deadline {
            if status.is_none() {
                status = child
                    .try_wait()
                    .map_err(|error| format!("provider status after SIGTERM failed: {error}"))?;
            }
            if status.is_some() && !process_group_exists(pid)? {
                return status.ok_or("provider status disappeared".to_string());
            }
            thread::sleep(Duration::from_millis(5));
        }
        send_group_signal(pid, libc::SIGKILL)?;
    }

    // If the provider changed its process group after exec, the old PGID can be
    // absent while the direct child is still alive. Kill the direct PID as a
    // bounded fallback instead of calling an unbounded wait().
    if status.is_none() {
        match child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
            Err(error) => return Err(format!("provider direct SIGKILL failed: {error}")),
        }
    }

    let deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| format!("provider status after SIGKILL failed: {error}"))?;
        }
        if status.is_some() && !process_group_exists(pid)? {
            return status.ok_or("provider status disappeared".to_string());
        }
        thread::sleep(Duration::from_millis(5));
    }

    let group_alive = process_group_exists(pid).unwrap_or(true);
    Err(format!(
        "provider cleanup deadline exceeded: leader_reaped={}, process_group_alive={group_alive}",
        status.is_some()
    ))
}

fn process_group_exists(pid: u32) -> Result<bool, String> {
    let group = i32::try_from(pid)
        .map_err(|_| "provider pid does not fit a process-group id".to_string())?;
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

fn send_group_signal(pid: u32, signal: i32) -> Result<(), String> {
    let group = i32::try_from(pid)
        .map_err(|_| "provider pid does not fit a process-group id".to_string())?;
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
        let pid = child.id();
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

        let status = finish_child(&mut child, pid, Duration::from_millis(20)).unwrap();
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
}
