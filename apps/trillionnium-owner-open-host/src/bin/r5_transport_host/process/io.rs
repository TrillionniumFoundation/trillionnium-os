const CORE_CLEANUP_GRACE: Duration = Duration::from_millis(250);
const CORE_ABORT_REAP_GRACE: Duration = Duration::from_millis(500);
const CORE_PROCESS_GROUP_SCAN_BUDGET: Duration = Duration::from_millis(500);

/// Kernel-observed identity for the transport core child.  The start-time and
/// boot-id pair distinguish a PID generation; PGID and SID bind descendant
/// cleanup to the namespace created by this spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    process_group: u32,
    session_id: u32,
    start_time_ticks: Option<u64>,
    boot_id_sha256: Option<String>,
}

/// Total post-spawn owner for the transport core.  The guard remains armed
/// through pipe extraction and reader/waiter setup; every early return or
/// thread-spawn failure therefore has a bounded, identity-checked reap path.
struct CoreChildGuard {
    child: Option<Child>,
    identity: Option<ProcessIdentity>,
    grace: Duration,
    armed: bool,
}

impl CoreChildGuard {
    fn new(child: Child, grace: Duration) -> Self {
        Self {
            child: Some(child),
            identity: None,
            grace,
            armed: true,
        }
    }

    fn bind_identity(&mut self, identity: ProcessIdentity) {
        debug_assert_eq!(self.id(), identity.pid);
        self.identity = Some(identity);
    }

    fn id(&self) -> u32 {
        self.child
            .as_ref()
            .expect("transport core guard no longer owns its child")
            .id()
    }

    fn child_mut(&mut self) -> Result<&mut Child, String> {
        self.child
            .as_mut()
            .ok_or_else(|| "transport core guard no longer owns its child".to_string())
    }

    fn wait_and_cleanup(&mut self) -> Result<ExitStatus, String> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| "transport core process identity was not bound".to_string())?
            .clone();
        let status = self
            .child_mut()?
            .wait()
            .map_err(|error| format!("cannot wait for core Host: {error}"));
        let grace = self.grace;
        let cleanup = match self.child_mut() {
            Ok(child) => finish_core_child(child, &identity, grace),
            Err(error) => Err(error),
        };
        match (status, cleanup) {
            (Ok(status), Ok(())) => {
                self.armed = false;
                Ok(status)
            }
            (Err(error), Ok(())) => {
                self.armed = false;
                Err(error)
            }
            (Ok(_status), Err(cleanup)) => Err(cleanup),
            (Err(wait), Err(cleanup)) => Err(format!("{wait}; {cleanup}")),
        }
    }
}

impl std::ops::Deref for CoreChildGuard {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        self.child
            .as_ref()
            .expect("transport core guard no longer owns its child")
    }
}

impl std::ops::DerefMut for CoreChildGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.child
            .as_mut()
            .expect("transport core guard no longer owns its child")
    }
}

impl Drop for CoreChildGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(mut child) = self.child.take() else {
            self.armed = false;
            return;
        };
        if let Some(identity) = self.identity.as_ref() {
            let _ = finish_core_child(&mut child, identity, self.grace);
        } else {
            // Before identity capture, only the exact Child handle is safe;
            // never infer a process group from the raw PID.
            let _ = child.kill();
        }
        reap_core_child_bounded(child, CORE_ABORT_REAP_GRACE);
        self.armed = false;
    }
}

fn spawn_core(
    options: &Options,
) -> Result<
    (
        CoreChildGuard,
        Option<ChildStdin>,
        ChildStdout,
        std::process::ChildStderr,
    ),
    String,
> {
    let mut command = Command::new(&options.core);
    command
        .args(&options.core_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let parent_pid = unsafe { libc::getpid() };
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // `PR_SET_PDEATHSIG` alone has a fork/exec race: the parent
                // may die between fork and installing the signal.  Recheck
                // the parent identity in the child before allowing the core
                // Host to execute.
                if libc::getppid() != parent_pid {
                    return Err(io::Error::from_raw_os_error(libc::ECHILD));
                }
            }
            Ok(())
        });
    }
    let child = command
        .spawn()
        .map_err(|error| format!("cannot spawn core Host {}: {error}", options.core.display()))?;
    let mut child = CoreChildGuard::new(child, CORE_CLEANUP_GRACE);
    let identity = capture_process_identity(child.id())
        .map_err(|error| format!("cannot capture core Host process identity: {error}"))?;
    child.bind_identity(identity);
    let stdin = child.child_mut()?.stdin.take();
    let stdout = match child.child_mut()?.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err("core Host stdout was not piped".to_string());
        }
    };
    let stderr = match child.child_mut()?.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return Err("core Host stderr was not piped".to_string());
        }
    };
    Ok((child, stdin, stdout, stderr))
}

fn spawn_core_waiter(
    mut child: CoreChildGuard,
    sender: SyncSender<TransportMessage>,
) -> Result<(), String> {
    thread::Builder::new()
        .name("owner-open-transport-core-waiter".to_string())
        .spawn(move || {
            let result = child.wait_and_cleanup();
            let _ = sender.send(TransportMessage::CoreExited(result));
        })
        .map(|_| ())
        .map_err(|error| format!("cannot spawn transport core waiter: {error}"))
}

fn spawn_client_reader(
    sender: SyncSender<TransportMessage>,
    max_frame_bytes: usize,
) -> Result<(), String> {
    thread::Builder::new()
        .name("owner-open-transport-client-reader".to_string())
        .spawn(move || {
            let stdin = io::stdin();
            let mut reader = BufReader::new(stdin.lock());
            loop {
                match read_bounded_line(&mut reader, max_frame_bytes) {
                    Ok(Some(frame)) => {
                        if sender.send(TransportMessage::ClientFrame(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(TransportMessage::ClientEof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(TransportMessage::ClientError(error));
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| format!("cannot spawn transport client reader: {error}"))
}

fn spawn_core_reader(
    stdout: ChildStdout,
    sender: SyncSender<TransportMessage>,
    max_frame_bytes: usize,
) -> Result<(), String> {
    thread::Builder::new()
        .name("owner-open-transport-core-reader".to_string())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_bounded_line(&mut reader, max_frame_bytes) {
                    Ok(Some(frame)) => {
                        if sender.send(TransportMessage::CoreFrame(frame)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {
                        let _ = sender.send(TransportMessage::CoreEof);
                        return;
                    }
                    Err(error) => {
                        let _ = sender.send(TransportMessage::CoreError(error));
                        return;
                    }
                }
            }
        })
        .map(|_| ())
        .map_err(|error| format!("cannot spawn transport core reader: {error}"))
}

fn spawn_stderr_drain(stderr: std::process::ChildStderr) -> Result<(), String> {
    thread::Builder::new()
        .name("owner-open-transport-core-stderr".to_string())
        .spawn(move || {
            let mut output = io::stderr().lock();
            let _ = io::copy(&mut stderr.take(1024 * 1024), &mut output);
        })
        .map(|_| ())
        .map_err(|error| format!("cannot spawn core stderr drain: {error}"))
}

#[allow(clippy::needless_return)]
fn capture_process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let (start_time_ticks, process_group, session_id) = read_proc_stat_identity(pid)?
            .ok_or_else(|| io::Error::other("core Host exited before identity capture"))?;
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
            .map_err(|_| io::Error::other("core Host pid does not fit pid_t"))?;
        let process_group = unsafe { libc::getpgid(process) };
        if process_group <= 0 {
            return Err(io::Error::last_os_error());
        }
        let session_id = unsafe { libc::getsid(process) };
        if session_id <= 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(ProcessIdentity {
            pid,
            process_group: u32::try_from(process_group)
                .map_err(|_| io::Error::other("invalid core process group"))?,
            session_id: u32::try_from(session_id)
                .map_err(|_| io::Error::other("invalid core session id"))?,
            start_time_ticks: None,
            boot_id_sha256: None,
        });
    }
}

#[allow(clippy::needless_return)]
fn observe_process_identity(pid: u32) -> io::Result<Option<ProcessIdentity>> {
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
            .map_err(|_| io::Error::other("core Host pid does not fit pid_t"))?;
        let process_group = unsafe { libc::getpgid(process) };
        if process_group <= 0 {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        let session_id = unsafe { libc::getsid(process) };
        if session_id <= 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(Some(ProcessIdentity {
            pid,
            process_group: u32::try_from(process_group)
                .map_err(|_| io::Error::other("invalid core process group"))?,
            session_id: u32::try_from(session_id)
                .map_err(|_| io::Error::other("invalid core session id"))?,
            start_time_ticks: None,
            boot_id_sha256: None,
        }));
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_proc_stat_identity(pid: u32) -> io::Result<Option<(u64, u32, u32)>> {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    parse_proc_stat_identity(&stat).map(Some)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn parse_proc_stat_identity(stat: &str) -> io::Result<(u64, u32, u32)> {
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("core proc stat omitted command terminator"))?;
    let fields = stat
        .get(command_end + 1..)
        .ok_or_else(|| io::Error::other("core proc stat is truncated"))?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    let process_group = fields
        .get(2)
        .ok_or_else(|| io::Error::other("core proc stat omitted process group"))?
        .parse::<u32>()
        .map_err(|_| io::Error::other("core proc stat process group is invalid"))?;
    let session_id = fields
        .get(3)
        .ok_or_else(|| io::Error::other("core proc stat omitted session id"))?
        .parse::<u32>()
        .map_err(|_| io::Error::other("core proc stat session id is invalid"))?;
    let start_time_ticks = fields
        .get(19)
        .ok_or_else(|| io::Error::other("core proc stat omitted start time"))?
        .parse::<u64>()
        .map_err(|_| io::Error::other("core proc stat start time is invalid"))?;
    if process_group == 0 || session_id == 0 || start_time_ticks == 0 {
        return Err(io::Error::other("core proc stat identity is zero"));
    }
    Ok((start_time_ticks, process_group, session_id))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_boot_id_sha256() -> io::Result<String> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
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
        return Err(io::Error::other("core kernel boot identity is malformed"));
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
                "core process-group identity cannot be proven after leader exit".to_string(),
            );
        }
        return Ok(());
    };
    if !identity_matches(identity, &observed) {
        return Err("core process identity changed before group cleanup".to_string());
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
        None => {
            // Once the leader is reaped, a matching descendant is the only
            // proof that this numeric PGID still belongs to us.  A group with
            // no matching member is treated as gone; it may be a recycled
            // PGID and must never be signalled.
            bound_process_group_has_member(identity)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn bound_process_group_has_member(identity: &ProcessIdentity) -> Result<bool, String> {
    let entries = std::fs::read_dir("/proc").map_err(|error| error.to_string())?;
    let deadline = Instant::now()
        .checked_add(CORE_PROCESS_GROUP_SCAN_BUDGET)
        .unwrap_or_else(Instant::now);
    for entry in entries {
        if Instant::now() >= deadline {
            return Ok(false);
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
            Ok(Some(_)) | Ok(None) | Err(_) => {}
        }
    }
    Ok(false)
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn bound_process_group_has_member(identity: &ProcessIdentity) -> Result<bool, String> {
    process_group_exists(identity.process_group)
}

fn process_group_exists(process_group: u32) -> Result<bool, String> {
    let process_group = i32::try_from(process_group)
        .map_err(|_| "core process-group id does not fit pid_t".to_string())?;
    if unsafe { libc::kill(-process_group, 0) } == 0 {
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(format!("core process-group probe failed: {error}")),
    }
}

fn send_process_group_signal(process_group: u32, signal: i32) -> Result<(), String> {
    let process_group = i32::try_from(process_group)
        .map_err(|_| "core process-group id does not fit pid_t".to_string())?;
    if unsafe { libc::kill(-process_group, signal) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(format!(
            "core process-group signal {signal} failed: {error}"
        ))
    }
}

fn finish_core_child(
    child: &mut Child,
    identity: &ProcessIdentity,
    grace: Duration,
) -> Result<(), String> {
    let grace = grace.max(Duration::from_millis(250));
    let mut status = match child.try_wait() {
        Ok(status) => status,
        Err(error) => {
            let primary = format!("core status before cleanup failed: {error}");
            return Err(with_direct_fallback(
                child,
                primary,
                "core direct SIGKILL after status probe failed",
            ));
        }
    };
    let group_alive = match bound_process_group_exists(identity) {
        Ok(group_alive) => group_alive,
        Err(error) => {
            return Err(with_direct_fallback(
                child,
                error,
                "core direct SIGKILL after identity probe failed",
            ));
        }
    };
    if group_alive {
        if let Err(error) = send_process_group_signal(identity.process_group, libc::SIGTERM) {
            return Err(with_direct_fallback(
                child,
                error,
                "core direct SIGKILL after SIGTERM failed",
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
                        let primary = format!("core status after SIGTERM failed: {error}");
                        return Err(with_direct_fallback(
                            child,
                            primary,
                            "core direct SIGKILL after status probe failed",
                        ));
                    }
                };
            }
            match bound_process_group_exists(identity) {
                Ok(false) => return Ok(()),
                Ok(true) => {}
                Err(error) => {
                    return Err(with_direct_fallback(
                        child,
                        error,
                        "core direct SIGKILL after identity probe failed",
                    ));
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
                    "core direct SIGKILL after identity probe failed",
                ));
            }
        };
        if group_alive
            && let Err(error) = send_process_group_signal(identity.process_group, libc::SIGKILL)
        {
            return Err(with_direct_fallback(
                child,
                error,
                "core direct SIGKILL after SIGKILL failed",
            ));
        }
    }
    if status.is_none() {
        kill_direct_child(child, "core direct SIGKILL failed")?;
    }
    let deadline = Instant::now()
        .checked_add(grace)
        .unwrap_or_else(Instant::now);
    while Instant::now() < deadline {
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    let primary = format!("core status after SIGKILL failed: {error}");
                    return Err(with_direct_fallback(
                        child,
                        primary,
                        "core direct SIGKILL after status probe failed",
                    ));
                }
            };
        }
        match bound_process_group_exists(identity) {
            Ok(false) => return Ok(()),
            Ok(true) => {}
            Err(error) => {
                return Err(with_direct_fallback(
                    child,
                    error,
                    "core direct SIGKILL after identity probe failed",
                ));
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
                "core direct SIGKILL after identity probe failed",
            ));
        }
    };
    Err(format!(
        "core cleanup deadline exceeded: leader_reaped={}, process_group_alive={group_alive}",
        status.is_some(),
    ))
}

fn kill_direct_child(child: &mut Child, context: &str) -> Result<(), String> {
    match child.kill() {
        Ok(()) => Ok(()),
        // InvalidInput means the exact leader has already exited. It is
        // idempotent; it never authorizes a raw-PID process-group signal.
        Err(error) if error.kind() == io::ErrorKind::InvalidInput => Ok(()),
        Err(error) => Err(format!("{context}: {error}")),
    }
}

fn with_direct_fallback(child: &mut Child, primary: String, context: &str) -> String {
    match kill_direct_child(child, context) {
        Ok(()) => primary,
        Err(error) => format!("{primary}; {error}"),
    }
}

fn reap_core_child_bounded(mut child: Child, timeout: Duration) {
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
        .name("owner-open-transport-core-abort-reaper".to_string())
        .spawn(move || {
            let _ = child.wait();
        });
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    max_frame_bytes: usize,
) -> Result<Option<Vec<u8>>, String> {
    let mut line = Vec::new();
    let read = reader
        .take(max_frame_bytes as u64 + 2)
        .read_until(b'\n', &mut line)
        .map_err(|error| error.to_string())?;
    if read == 0 {
        return Ok(None);
    }
    if line.last() != Some(&b'\n') {
        return Err("frame is not newline terminated or exceeds its bound".to_string());
    }
    line.pop();
    if line.is_empty() || line.len() > max_frame_bytes {
        return Err("frame is empty or exceeds its bound".to_string());
    }
    Ok(Some(line))
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
        let stat = format!("17 (core (nested)) {}", fields.join(" "));
        assert_eq!(parse_proc_stat_identity(&stat).unwrap(), (4242, 1234, 5678));
    }

    #[test]
    fn current_core_identity_is_stable_and_generation_bound() {
        let identity = capture_process_identity(std::process::id()).unwrap();
        assert_eq!(identity.pid, std::process::id());
        assert!(identity.process_group > 0);
        assert!(identity.session_id > 0);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert!(identity.start_time_ticks.is_some_and(|value| value > 0));
            assert!(identity
                .boot_id_sha256
                .as_deref()
                .is_some_and(|value| value.len() == 64));
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
    fn unbound_core_guard_never_broadcasts_to_raw_pid_group() {
        let mut leader_command = Command::new("/bin/sh");
        leader_command.args(["-c", "exec sleep 10"]);
        unsafe {
            leader_command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let leader = leader_command.spawn().expect("spawn core group leader");
        let leader_pid = leader.id();

        let mut member_command = Command::new("/bin/sh");
        member_command.args(["-c", "exec sleep 10"]);
        unsafe {
            member_command.pre_exec(move || {
                let process_group = libc::pid_t::try_from(leader_pid)
                    .map_err(|_| io::Error::other("leader pid does not fit pid_t"))?;
                if libc::setpgid(0, process_group) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut member = member_command.spawn().expect("spawn core group member");
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

        drop(CoreChildGuard::new(leader, Duration::from_millis(20)));
        assert!(unsafe { libc::kill(member_pid as libc::pid_t, 0) } == 0);
        let _ = member.kill();
        let _ = member.wait();
    }
}
