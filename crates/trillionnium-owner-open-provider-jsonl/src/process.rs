//! Hardened provider process boundary.
//!
//! The retained implementation below owns process-group identity, child reap
//! and provider cleanup. This facade replaces only reader-worker ownership:
//! every pipe is nonblocking, every stop is observable within one poll interval
//! and every worker handle is joined on normal cleanup and on all early-return
//! Drop paths. No provider reader may be detached.

#[path = "process_retained.rs"]
#[allow(dead_code)]
mod retained;

pub(crate) use retained::{
    ProviderChildGuard, ProviderOutput, allow_natural_exit_grace, capture_process_identity,
};

use std::io::{self, BufRead, BufReader, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const READER_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WORKER_NATURAL_JOIN_GRACE: Duration = Duration::from_millis(250);
const WORKER_CANCEL_JOIN_GRACE: Duration = Duration::from_secs(2);

/// Exclusive owner of one provider reader thread.
///
/// Drop is intentionally a stop-and-join operation. The descriptor is placed
/// in nonblocking mode before thread creation, and the bounded queue sender is
/// cooperative, so there is no syscall or channel path on which a reader can
/// remain permanently asleep after the stop flag is published.
pub(crate) struct ProviderWorker {
    handle: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl ProviderWorker {
    fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    fn join(mut self) -> thread::Result<()> {
        self.request_stop();
        self.handle
            .take()
            .expect("provider worker handle is present before join")
            .join()
    }

    fn stop_and_join(&mut self) -> thread::Result<()> {
        self.request_stop();
        match self.handle.take() {
            Some(handle) => handle.join(),
            None => Ok(()),
        }
    }
}

impl Drop for ProviderWorker {
    fn drop(&mut self) {
        // Early setup failures, including failure to create the second reader,
        // pass through here. Never convert ownership into a detached thread.
        let _ = self.stop_and_join();
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` comes from a live object implementing AsRawFd and remains
    // owned by that object for the complete call.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK != 0 {
        return Ok(());
    }
    // SAFETY: F_SETFL updates only the status flags of the same live fd.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn spawn_stdout_reader(
    stdout: impl Read + AsRawFd + Send + 'static,
    max_line_bytes: usize,
    max_stdout_bytes: usize,
    sender: SyncSender<ProviderOutput>,
) -> io::Result<ProviderWorker> {
    let fd = stdout.as_raw_fd();
    set_nonblocking(fd)?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = thread::Builder::new()
        .name("owner-open-provider-stdout".to_string())
        .spawn(move || {
            let mut reader =
                BufReader::new(PollingReader::new(stdout, fd, Arc::clone(&worker_stop)));
            let mut total = 0usize;
            loop {
                match read_bounded_line(&mut reader, max_line_bytes) {
                    Ok(Some(line)) => {
                        total = match total.checked_add(line.len().saturating_add(1)) {
                            Some(total) if total <= max_stdout_bytes => total,
                            _ => {
                                let _ = send_provider_output(
                                    &sender,
                                    ProviderOutput::Error(
                                        "provider aggregate stdout exceeds its bound".to_string(),
                                    ),
                                    &worker_stop,
                                );
                                return;
                            }
                        };
                        if !send_provider_output(&sender, ProviderOutput::Line(line), &worker_stop)
                        {
                            return;
                        }
                    }
                    Ok(None) => {
                        if !worker_stop.load(Ordering::Acquire) {
                            let _ =
                                send_provider_output(&sender, ProviderOutput::Eof, &worker_stop);
                        }
                        return;
                    }
                    Err(error) => {
                        if !worker_stop.load(Ordering::Acquire) {
                            let _ = send_provider_output(
                                &sender,
                                ProviderOutput::Error(error),
                                &worker_stop,
                            );
                        }
                        return;
                    }
                }
            }
        })?;
    Ok(ProviderWorker {
        handle: Some(handle),
        stop,
    })
}

pub(crate) fn spawn_stderr_reader(
    stderr: impl Read + AsRawFd + Send + 'static,
    maximum: usize,
    capture: Arc<Mutex<Vec<u8>>>,
    overflow: Arc<AtomicBool>,
) -> io::Result<ProviderWorker> {
    let fd = stderr.as_raw_fd();
    set_nonblocking(fd)?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let handle = thread::Builder::new()
        .name("owner-open-provider-stderr".to_string())
        .spawn(move || {
            let mut stderr = PollingReader::new(stderr, fd, Arc::clone(&worker_stop));
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                if worker_stop.load(Ordering::Acquire) {
                    return;
                }
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
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return,
                }
            }
        })?;
    Ok(ProviderWorker {
        handle: Some(handle),
        stop,
    })
}

/// Poll readiness, then perform a nonblocking read. The second property is
/// load-bearing: readiness is advisory and may be consumed or invalidated
/// before the read syscall, so poll alone cannot make a blocking descriptor
/// cancellable.
struct PollingReader<R> {
    inner: R,
    fd: RawFd,
    stop: Arc<AtomicBool>,
}

impl<R> PollingReader<R> {
    fn new(inner: R, fd: RawFd, stop: Arc<AtomicBool>) -> Self {
        Self { inner, fd, stop }
    }
}

impl<R: Read> Read for PollingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            if self.stop.load(Ordering::Acquire) {
                return Ok(0);
            }
            let timeout_ms =
                READER_POLL_INTERVAL.as_millis().clamp(1, i32::MAX as u128) as libc::c_int;
            let mut poll_fd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                revents: 0,
            };
            // SAFETY: poll receives one valid pollfd for the duration of this
            // call; the owned reader keeps the descriptor alive.
            let polled = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
            if polled < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if self.stop.load(Ordering::Acquire) {
                return Ok(0);
            }
            if polled == 0 {
                continue;
            }
            if poll_fd.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::other(
                    "provider output descriptor became invalid",
                ));
            }
            match self.inner.read(buffer) {
                Ok(count) => return Ok(count),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }
}

fn send_provider_output(
    sender: &SyncSender<ProviderOutput>,
    mut output: ProviderOutput,
    stop: &AtomicBool,
) -> bool {
    loop {
        match sender.try_send(output) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(returned)) => {
                output = returned;
                if stop.load(Ordering::Acquire) {
                    return false;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
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

/// Give readers a short natural-exit window, then publish stop and join every
/// handle. The deadline is diagnostic only; crossing it is never permission to
/// detach a reader from its owning turn.
pub(crate) fn join_provider_workers_bounded(mut workers: Vec<ProviderWorker>) -> Vec<String> {
    let mut errors = Vec::new();
    let natural_deadline = Instant::now()
        .checked_add(WORKER_NATURAL_JOIN_GRACE)
        .unwrap_or_else(Instant::now);
    let mut pending = Vec::new();
    for worker in workers.drain(..) {
        if worker.is_finished() {
            if worker.join().is_err() {
                errors.push("provider reader thread panicked".to_string());
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
                    errors.push("provider reader thread panicked".to_string());
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
                    errors.push("provider reader thread panicked".to_string());
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
        if !worker.is_finished() {
            errors.push(
                "provider reader exceeded bounded cleanup grace; mandatory join retained ownership"
                    .to_string(),
            );
        }
        if worker.join().is_err() {
            errors.push("provider reader thread panicked".to_string());
        }
    }
    errors
}

#[cfg(test)]
mod worker_ownership_tests {
    use super::*;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixStream;

    struct TrackedReader {
        stream: UnixStream,
        dropped: Arc<AtomicBool>,
    }

    impl Read for TrackedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.stream.read(buffer)
        }
    }

    impl AsRawFd for TrackedReader {
        fn as_raw_fd(&self) -> RawFd {
            self.stream.as_raw_fd()
        }
    }

    impl Drop for TrackedReader {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn early_worker_drop_stops_joins_and_releases_reader() {
        let (reader, _peer) = UnixStream::pair().expect("unix stream pair");
        let dropped = Arc::new(AtomicBool::new(false));
        let tracked = TrackedReader {
            stream: reader,
            dropped: Arc::clone(&dropped),
        };
        let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
        let worker =
            spawn_stdout_reader(tracked, 1024, 4096, sender).expect("spawn provider reader");

        drop(worker);
        assert!(
            dropped.load(Ordering::SeqCst),
            "Drop must join before returning and release the reader"
        );
    }

    #[test]
    fn bounded_cleanup_never_detaches_a_polling_reader() {
        let (reader, _peer) = UnixStream::pair().expect("unix stream pair");
        let dropped = Arc::new(AtomicBool::new(false));
        let tracked = TrackedReader {
            stream: reader,
            dropped: Arc::clone(&dropped),
        };
        let (sender, _receiver) = std::sync::mpsc::sync_channel(1);
        let worker =
            spawn_stdout_reader(tracked, 1024, 4096, sender).expect("spawn provider reader");
        let started = Instant::now();

        let errors = join_provider_workers_bounded(vec![worker]);
        assert!(
            errors.is_empty(),
            "cooperative nonblocking reader must stop cleanly: {errors:?}"
        );
        assert!(dropped.load(Ordering::SeqCst));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
