use std::io::{BufRead, BufReader, Read};
use std::process::{Child, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
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
    sender: Sender<ProviderOutput>,
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

fn read_bounded_line(
    reader: &mut impl BufRead,
    maximum: usize,
) -> Result<Option<Vec<u8>>, String> {
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

pub(crate) fn finish_child(
    child: &mut Child,
    pid: u32,
    grace: Duration,
) -> Result<ExitStatus, String> {
    let deadline = Instant::now().checked_add(grace).unwrap_or_else(Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    terminate_process_group(child, pid, grace)
}

fn terminate_process_group(
    child: &mut Child,
    pid: u32,
    grace: Duration,
) -> Result<ExitStatus, String> {
    send_group_signal(pid, libc::SIGTERM)?;
    let deadline = Instant::now().checked_add(grace).unwrap_or_else(Instant::now);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Ok(None) => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    send_group_signal(pid, libc::SIGKILL)?;
    child.wait().map_err(|error| error.to_string())
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
