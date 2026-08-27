use std::collections::BTreeSet;
use std::ffi::{CString, c_char, c_int, c_uint, c_ulong, c_void};
use std::fs;
use std::io::{self, Read as _};
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use super::linux_replay_sync_publisher_ops::{
    LinuxReplaySyncPublisherKernel, LinuxReplaySyncPublisherLaunchOps,
};
use super::replay_sync_publisher_custody::{
    CompletedReplaySyncPublisher, MeasuredPublisherExecutable, ReplaySyncPublisherLaunchError,
    ReplaySyncPublisherLaunchSpec, RunningReplaySyncPublisher, VerifiedPublisherExec,
    complete_replay_sync_publisher, launch_replay_sync_publisher_with_authentication_sink,
};
use super::root_authentication_proof_socket::FixedRootProofSocket;
use super::root_authentication_proof_transport::{
    RootProofAuthenticationSink, RootProofConnection,
};
use trillionnium_os_types::capability_lease_root_publication::{
    CapabilityLeaseRootTaskPublicationAckV1, CapabilityLeaseRootTaskPublicationV1,
    MAXIMUM_PAYLOAD_BYTES,
};

pub(crate) const SOURCE_STATUS: &str =
    "source_only_concrete_clone3_pidfd_kernel_backend_no_broker_route_no_product_constructor_v1";

const OPENAT2_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const OPENAT2_RESOLVE_NO_SYMLINKS: u64 = 0x04;
const CLOSE_RANGE_UNSHARE: c_uint = 1 << 1;
const CLONE_PIDFD_FLAG: u64 = 0x0000_1000;
const PTRACE_EVENT_EXEC_VALUE: c_int = 4;
const PTRACE_O_TRACEEXEC_VALUE: c_ulong = 1 << 4;
const SECCOMP_MODE_FILTER_VALUE: c_ulong = 2;
const SECCOMP_RET_ALLOW_VALUE: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO_VALUE: u32 = 0x0005_0000;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const EXECUTABLE_FD: RawFd = 3;
const RESULT_TIMEOUT: Duration = Duration::from_millis(15_000);

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

struct RetainedExecutable {
    fd: OwnedFd,
    identity: String,
    sha256: String,
}

#[derive(Debug)]
pub(crate) struct ConcreteLinuxReplaySyncPublisherChild {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    stdin_write: Option<OwnedFd>,
    stdout_read: OwnedFd,
    pre_exec_start_time_ticks: u64,
    request_frame: Vec<u8>,
    expected_executable_sha256: String,
    expected_uid: u32,
    expected_gid: u32,
    expected_selinux_domain: String,
    executable_identity: String,
    exec_stop_observed: bool,
    hardening_stop_observed: bool,
}

pub(crate) struct ConcreteLinuxReplaySyncPublisherKernel {
    measured: Option<RetainedExecutable>,
}

impl ConcreteLinuxReplaySyncPublisherKernel {
    pub(crate) fn source_disabled() -> Self {
        Self { measured: None }
    }
}

pub(crate) fn launch_concrete_with_injected_proof_connection<C: RootProofConnection>(
    spec: ReplaySyncPublisherLaunchSpec,
    connection: &mut C,
) -> Result<
    RunningReplaySyncPublisher<ConcreteLinuxReplaySyncPublisherChild>,
    ReplaySyncPublisherLaunchError,
> {
    let kernel = ConcreteLinuxReplaySyncPublisherKernel::source_disabled();
    let mut ops = LinuxReplaySyncPublisherLaunchOps::source_disabled(kernel);
    let mut sink = RootProofAuthenticationSink::new(connection);
    launch_replay_sync_publisher_with_authentication_sink(spec, &mut ops, &mut sink)
}

pub(crate) fn launch_concrete_with_fixed_proof_socket(
    spec: ReplaySyncPublisherLaunchSpec,
) -> Result<
    (
        RunningReplaySyncPublisher<ConcreteLinuxReplaySyncPublisherChild>,
        LinuxReplaySyncPublisherLaunchOps<ConcreteLinuxReplaySyncPublisherKernel>,
    ),
    ReplaySyncPublisherLaunchError,
> {
    let mut connection = FixedRootProofSocket::connect_source_disabled()
        .map_err(|_| ReplaySyncPublisherLaunchError::AuthenticationDeliveryDenied)?;
    let kernel = ConcreteLinuxReplaySyncPublisherKernel::source_disabled();
    let mut ops = LinuxReplaySyncPublisherLaunchOps::source_disabled(kernel);
    let mut sink = RootProofAuthenticationSink::new(&mut connection);
    let running = launch_replay_sync_publisher_with_authentication_sink(spec, &mut ops, &mut sink)?;
    Ok((running, ops))
}

pub(crate) fn complete_concrete(
    running: RunningReplaySyncPublisher<ConcreteLinuxReplaySyncPublisherChild>,
    ops: &mut LinuxReplaySyncPublisherLaunchOps<ConcreteLinuxReplaySyncPublisherKernel>,
) -> Result<CompletedReplaySyncPublisher, ReplaySyncPublisherLaunchError> {
    complete_replay_sync_publisher(running, ops)
}

impl LinuxReplaySyncPublisherKernel for ConcreteLinuxReplaySyncPublisherKernel {
    type Child = ConcreteLinuxReplaySyncPublisherChild;

    fn open_measure_readonly_elf_same_fd(
        &mut self,
        spec: &ReplaySyncPublisherLaunchSpec,
    ) -> Result<MeasuredPublisherExecutable, ReplaySyncPublisherLaunchError> {
        if self.measured.is_some() || spec.executable_identity.starts_with('/') {
            return Err(ReplaySyncPublisherLaunchError::MeasurementDenied);
        }
        let absolute_path = CString::new(format!("/{}", spec.executable_identity))
            .map_err(|_| ReplaySyncPublisherLaunchError::MeasurementDenied)?;
        let fd = open_fixed_executable(&absolute_path)
            .map_err(|_| ReplaySyncPublisherLaunchError::MeasurementDenied)?;
        let metadata = executable_metadata(fd.as_raw_fd())
            .map_err(|_| ReplaySyncPublisherLaunchError::MeasurementDenied)?;
        if !metadata.regular_single_link || !metadata.read_only_mount || !metadata.elf_image {
            return Err(ReplaySyncPublisherLaunchError::MeasurementDenied);
        }
        let sha256 = sha256_fd(fd.as_raw_fd())
            .map_err(|_| ReplaySyncPublisherLaunchError::MeasurementDenied)?;
        if sha256 != spec.expected_executable_sha256 {
            return Err(ReplaySyncPublisherLaunchError::MeasurementDenied);
        }
        self.measured = Some(RetainedExecutable {
            fd,
            identity: spec.executable_identity.clone(),
            sha256: sha256.clone(),
        });
        Ok(MeasuredPublisherExecutable {
            executable_identity: spec.executable_identity.clone(),
            executable_sha256: sha256,
            same_fd_for_execveat: true,
            read_only_mount: true,
            regular_single_link: true,
            elf_image: true,
        })
    }

    fn clone3_pidfd_stopped_execveat(
        &mut self,
        spec: &ReplaySyncPublisherLaunchSpec,
        executable: &MeasuredPublisherExecutable,
        exact_request_frame: &[u8],
    ) -> Result<Self::Child, ReplaySyncPublisherLaunchError> {
        let retained = self
            .measured
            .take()
            .ok_or(ReplaySyncPublisherLaunchError::SpawnFailed)?;
        if retained.identity != executable.executable_identity
            || retained.sha256 != executable.executable_sha256
            || exact_request_frame != spec.request_frame
            || exact_request_frame.is_empty()
            || exact_request_frame.len()
                > trillionnium_os_types::capability_lease_root_publication::MAXIMUM_PAYLOAD_BYTES
                    + mem::size_of::<u32>()
        {
            return Err(ReplaySyncPublisherLaunchError::SpawnFailed);
        }
        let (stdin_read, stdin_write) =
            pipe_cloexec().map_err(|_| ReplaySyncPublisherLaunchError::SpawnFailed)?;
        ensure_pipe_capacity(stdin_write.as_raw_fd(), exact_request_frame.len())
            .map_err(|_| ReplaySyncPublisherLaunchError::SpawnFailed)?;
        let (stdout_read, stdout_write) =
            pipe_cloexec().map_err(|_| ReplaySyncPublisherLaunchError::SpawnFailed)?;
        let executable_identity = CString::new(spec.executable_identity.clone())
            .map_err(|_| ReplaySyncPublisherLaunchError::SpawnFailed)?;
        let selinux_domain = CString::new(
            trillionnium_os_types::capability_lease_root_publisher_launch::PUBLISHER_SELINUX_DOMAIN,
        )
        .map_err(|_| ReplaySyncPublisherLaunchError::SpawnFailed)?;
        let mut pidfd_raw: c_int = -1;
        let mut clone_args = CloneArgs {
            flags: CLONE_PIDFD_FLAG,
            pidfd: (&mut pidfd_raw as *mut c_int) as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..CloneArgs::default()
        };
        let result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &mut clone_args as *mut CloneArgs,
                mem::size_of::<CloneArgs>(),
            )
        };
        if result == 0 {
            unsafe {
                child_exec(
                    retained.fd.as_raw_fd(),
                    stdin_read.as_raw_fd(),
                    stdout_write.as_raw_fd(),
                    spec.uid,
                    spec.gid,
                    executable_identity.as_ptr(),
                    selinux_domain.as_ptr(),
                )
            }
        }
        if result < 0 || pidfd_raw < 0 {
            return Err(ReplaySyncPublisherLaunchError::SpawnFailed);
        }
        let pid =
            c_int::try_from(result).map_err(|_| ReplaySyncPublisherLaunchError::SpawnFailed)?;
        drop(stdin_read);
        drop(stdout_write);
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
        let setup = (|| {
            wait_for_stop(pid, libc::SIGSTOP)?;
            let start_time = read_proc_start_time(pid)?;
            ptrace_setoptions(pid, PTRACE_O_TRACEEXEC_VALUE)?;
            Ok::<u64, io::Error>(start_time)
        })();
        let pre_exec_start_time_ticks = match setup {
            Ok(start_time) => start_time,
            Err(_) => {
                return match kill_pidfd_and_reap(pidfd.as_raw_fd(), pid) {
                    Ok(()) => Err(ReplaySyncPublisherLaunchError::SpawnFailed),
                    Err(_) => Err(ReplaySyncPublisherLaunchError::CleanupAmbiguous),
                };
            }
        };
        Ok(ConcreteLinuxReplaySyncPublisherChild {
            pid,
            pidfd,
            stdin_write: Some(stdin_write),
            stdout_read,
            pre_exec_start_time_ticks,
            request_frame: exact_request_frame.to_vec(),
            expected_executable_sha256: retained.sha256,
            expected_uid: spec.uid,
            expected_gid: spec.gid,
            expected_selinux_domain: trillionnium_os_types::capability_lease_root_publisher_launch::PUBLISHER_SELINUX_DOMAIN.to_string(),
            executable_identity: spec.executable_identity.clone(),
            exec_stop_observed: false,
            hardening_stop_observed: false,
        })
    }

    fn observe_ptrace_exec_stop(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<VerifiedPublisherExec, ReplaySyncPublisherLaunchError> {
        ptrace_continue(child.pid).map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        wait_for_exec_stop(child.pid)
            .map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        child.exec_stop_observed = true;
        ptrace_continue(child.pid).map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        wait_for_self_hardening_stop(child.pid)
            .map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        child.hardening_stop_observed = true;
        let first_start_time = read_proc_start_time(child.pid)
            .map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        let process = inspect_process(child.pid, &child.executable_identity)
            .map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        let second_start_time = read_proc_start_time(child.pid)
            .map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        if first_start_time != child.pre_exec_start_time_ticks
            || second_start_time != first_start_time
            || process.uid != child.expected_uid
            || process.gid != child.expected_gid
            || process.selinux_domain != child.expected_selinux_domain
            || process.executable_sha256 != child.expected_executable_sha256
            || !process.stdio_exact
            || !process.environment_empty
            || !process.arguments_empty
            || !process.no_new_privs
            || !process.dumpable_disabled
            || !process.capabilities_empty
            || !process.descendants_forbidden
        {
            return Err(ReplaySyncPublisherLaunchError::PostExecDenied);
        }
        let stdin_write = child
            .stdin_write
            .take()
            .ok_or(ReplaySyncPublisherLaunchError::PostExecDenied)?;
        write_all_fd(stdin_write.as_raw_fd(), &child.request_frame)
            .map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        drop(stdin_write);
        let pidfd_identity_sha256 =
            pidfd_identity(child.pidfd.as_raw_fd(), child.pid, first_start_time)
                .map_err(|_| ReplaySyncPublisherLaunchError::PostExecDenied)?;
        Ok(VerifiedPublisherExec {
            pid: child.pid as u32,
            start_time_ticks: first_start_time,
            pidfd_identity_sha256,
            pidfd_returned_by_clone3: true,
            ptrace_exec_stop_observed: child.exec_stop_observed,
            post_exec_hardening_stop_observed: child.hardening_stop_observed,
            start_time_stable_after_exec: true,
            request_frame_bound_to_stdin: true,
            uid: process.uid,
            gid: process.gid,
            selinux_domain: process.selinux_domain,
            executable_sha256: process.executable_sha256,
            stdin_pipe_only: true,
            stdout_pipe_only: true,
            stderr_closed: true,
            other_fds_closed: true,
            environment_empty: true,
            arguments_empty: true,
            pdeathsig_sigkill: true,
            no_new_privs: true,
            dumpable_disabled: true,
            capabilities_empty: true,
            descendants_forbidden: true,
        })
    }

    fn pidfd_resume(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<(), ReplaySyncPublisherLaunchError> {
        if !child.exec_stop_observed
            || !child.hardening_stop_observed
            || child.stdin_write.is_some()
        {
            return Err(ReplaySyncPublisherLaunchError::ResumeFailed);
        }
        ptrace_detach(child.pid).map_err(|_| ReplaySyncPublisherLaunchError::ResumeFailed)
    }

    fn collect_exact_ack_and_reap(
        &mut self,
        mut child: Self::Child,
        publication: &CapabilityLeaseRootTaskPublicationV1,
    ) -> Result<CapabilityLeaseRootTaskPublicationAckV1, ReplaySyncPublisherLaunchError> {
        match collect_exact_ack_and_reap_inner(&mut child, publication) {
            Ok(ack) => Ok(ack),
            Err(_) => {
                kill_pidfd_and_reap(child.pidfd.as_raw_fd(), child.pid)
                    .map_err(|_| ReplaySyncPublisherLaunchError::CleanupAmbiguous)?;
                Err(ReplaySyncPublisherLaunchError::ResultDenied)
            }
        }
    }

    fn pidfd_kill_and_reap(
        &mut self,
        child: Self::Child,
    ) -> Result<(), ReplaySyncPublisherLaunchError> {
        kill_pidfd_and_reap(child.pidfd.as_raw_fd(), child.pid)
            .map_err(|_| ReplaySyncPublisherLaunchError::CleanupAmbiguous)
    }
}

fn collect_exact_ack_and_reap_inner(
    child: &mut ConcreteLinuxReplaySyncPublisherChild,
    publication: &CapabilityLeaseRootTaskPublicationV1,
) -> io::Result<CapabilityLeaseRootTaskPublicationAckV1> {
    let deadline = Instant::now() + RESULT_TIMEOUT;
    let frame = read_bounded_to_exact_eof(
        child.stdout_read.as_raw_fd(),
        MAXIMUM_PAYLOAD_BYTES + mem::size_of::<u32>(),
        deadline,
    )?;
    let ack = CapabilityLeaseRootTaskPublicationAckV1::decode_frame(&frame)
        .map_err(|_| io::Error::other("invalid publisher ACK"))?;
    if ack.publication_binding_sha256 != publication.publication_binding_sha256
        || ack.registration_binding_sha256 != publication.registration.registration_binding_sha256
        || ack.publisher_epoch != publication.registration.publisher_epoch
        || ack.publisher_sequence != publication.registration.publisher_sequence
        || ack.root_record_sha256 != publication.root_record_sha256
        || ack.root_record_proof_sha256 != publication.root_record_proof_sha256
    {
        return Err(io::Error::other("publisher ACK binding drift"));
    }
    poll_until(child.pidfd.as_raw_fd(), libc::POLLIN, deadline)?;
    let status = waitpid_exact(child.pid)?;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(io::Error::other("publisher did not exit successfully"));
    }
    Ok(ack)
}

fn read_bounded_to_exact_eof(fd: RawFd, maximum: usize, deadline: Instant) -> io::Result<Vec<u8>> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) } {
            0 => break,
            count if count > 0 => {
                let count = count as usize;
                if bytes.len().saturating_add(count) > maximum {
                    return Err(io::Error::other("publisher result exceeds bound"));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            _ => {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() != io::ErrorKind::WouldBlock {
                    return Err(error);
                }
                poll_until(fd, libc::POLLIN | libc::POLLHUP, deadline)?;
            }
        }
    }
    if bytes.is_empty() {
        return Err(io::Error::other("publisher returned no ACK"));
    }
    Ok(bytes)
}

fn poll_until(fd: RawFd, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "publisher result timeout"))?;
        let timeout = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("publisher result descriptor failed"));
            }
            if descriptor.revents & events != 0 || descriptor.revents & libc::POLLHUP != 0 {
                return Ok(());
            }
        } else if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "publisher result timeout",
            ));
        } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}

struct ExecutableMetadata {
    regular_single_link: bool,
    read_only_mount: bool,
    elf_image: bool,
}

struct ProcessInspection {
    uid: u32,
    gid: u32,
    selinux_domain: String,
    executable_sha256: String,
    stdio_exact: bool,
    environment_empty: bool,
    arguments_empty: bool,
    no_new_privs: bool,
    dumpable_disabled: bool,
    capabilities_empty: bool,
    descendants_forbidden: bool,
}

fn open_fixed_executable(path: &CString) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: OPENAT2_RESOLVE_NO_MAGICLINKS | OPENAT2_RESOLVE_NO_SYMLINKS,
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how as *const OpenHow,
            mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

fn executable_metadata(fd: RawFd) -> io::Result<ExecutableMetadata> {
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    let mut statvfs = MaybeUninit::<libc::statvfs>::zeroed();
    if unsafe { libc::fstatvfs(fd, statvfs.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let statvfs = unsafe { statvfs.assume_init() };
    let mut magic = [0u8; 4];
    read_exact_at_start(fd, &mut magic)?;
    Ok(ExecutableMetadata {
        regular_single_link: (stat.st_mode & libc::S_IFMT) == libc::S_IFREG && stat.st_nlink == 1,
        read_only_mount: (statvfs.f_flag as c_ulong & libc::ST_RDONLY as c_ulong) != 0,
        elf_image: magic == [0x7f, b'E', b'L', b'F'],
    })
}

fn read_exact_at_start(fd: RawFd, output: &mut [u8]) -> io::Result<()> {
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut offset = 0;
    while offset < output.len() {
        let read = unsafe {
            libc::read(
                fd,
                output[offset..].as_mut_ptr().cast::<c_void>(),
                output.len() - offset,
            )
        };
        if read <= 0 {
            return Err(if read == 0 {
                io::Error::from(io::ErrorKind::UnexpectedEof)
            } else {
                io::Error::last_os_error()
            });
        }
        offset += read as usize;
    }
    Ok(())
}

fn sha256_fd(fd: RawFd) -> io::Result<String> {
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast::<c_void>(), buffer.len()) };
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read as usize]);
    }
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn ensure_pipe_capacity(fd: RawFd, required: usize) -> io::Result<()> {
    let current = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
    if current < 0 {
        return Err(io::Error::last_os_error());
    }
    if current as usize >= required {
        return Ok(());
    }
    let updated = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, required as c_int) };
    if updated < 0 || (updated as usize) < required {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe fn child_exec(
    executable_fd: RawFd,
    stdin_fd: RawFd,
    stdout_fd: RawFd,
    uid: u32,
    gid: u32,
    executable_identity: *const c_char,
    selinux_domain: *const c_char,
) -> ! {
    if unsafe { child_security_ceremony(uid, gid, selinux_domain) } != 0
        || unsafe { libc::dup2(stdin_fd, libc::STDIN_FILENO) } < 0
        || unsafe { libc::dup2(stdout_fd, libc::STDOUT_FILENO) } < 0
        || prepare_executable_fd(executable_fd) != 0
        || unsafe { libc::close(libc::STDERR_FILENO) } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_close_range,
                4 as c_uint,
                c_uint::MAX,
                CLOSE_RANGE_UNSHARE,
            )
        } != 0
        || unsafe { libc::raise(libc::SIGSTOP) } != 0
    {
        unsafe { libc::_exit(127) }
    }
    let argv = [executable_identity, std::ptr::null()];
    let environment = [std::ptr::null::<c_char>()];
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            EXECUTABLE_FD,
            c"".as_ptr(),
            argv.as_ptr(),
            environment.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        libc::_exit(127)
    }
}

fn prepare_executable_fd(executable_fd: RawFd) -> c_int {
    if executable_fd == EXECUTABLE_FD {
        unsafe { libc::fcntl(EXECUTABLE_FD, libc::F_SETFD, libc::FD_CLOEXEC) }
    } else {
        unsafe { libc::dup3(executable_fd, EXECUTABLE_FD, libc::O_CLOEXEC) }
    }
}

unsafe fn child_security_ceremony(uid: u32, gid: u32, selinux_domain: *const c_char) -> c_int {
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        || unsafe { libc::getppid() } == 1
        || unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) } != 0
    {
        return -1;
    }
    if write_selinux_exec_domain(selinux_domain) != 0 {
        return -1;
    }
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(gid, gid, gid) } != 0
        || unsafe { libc::setresuid(uid, uid, uid) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
        || set_empty_capabilities() != 0
        || set_descendant_filter() != 0
    {
        return -1;
    }
    0
}

fn write_selinux_exec_domain(domain: *const c_char) -> c_int {
    let fd = unsafe {
        libc::open(
            c"/proc/self/attr/exec".as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return -1;
    }
    let length = unsafe { libc::strlen(domain) };
    let written = unsafe { libc::write(fd, domain.cast::<c_void>(), length) };
    let close_result = unsafe { libc::close(fd) };
    if written == length as isize && close_result == 0 {
        0
    } else {
        -1
    }
}

fn set_empty_capabilities() -> c_int {
    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: c_int,
    }
    #[repr(C)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapabilityData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) as c_int }
}

fn set_descendant_filter() -> c_int {
    let deny = SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32;
    #[cfg(target_arch = "aarch64")]
    let filters = [
        libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        syscall_deny_filter(libc::SYS_clone as u32),
        return_filter(deny),
        syscall_deny_filter(libc::SYS_clone3 as u32),
        return_filter(deny),
        return_filter(SECCOMP_RET_ALLOW_VALUE),
    ];
    #[cfg(not(target_arch = "aarch64"))]
    let filters = [
        libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: SECCOMP_DATA_NR_OFFSET,
        },
        syscall_deny_filter(libc::SYS_clone as u32),
        return_filter(deny),
        syscall_deny_filter(libc::SYS_clone3 as u32),
        return_filter(deny),
        syscall_deny_filter(libc::SYS_fork as u32),
        return_filter(deny),
        syscall_deny_filter(libc::SYS_vfork as u32),
        return_filter(deny),
        return_filter(SECCOMP_RET_ALLOW_VALUE),
    ];
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_ptr().cast_mut(),
    };
    unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER_VALUE,
            &program as *const libc::sock_fprog,
        )
    }
}

const fn syscall_deny_filter(number: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 0,
        jf: 1,
        k: number,
    }
}

const fn return_filter(value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: value,
    }
}

fn ptrace_setoptions(pid: libc::pid_t, options: c_ulong) -> io::Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, options) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ptrace_continue(pid: libc::pid_t) -> io::Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ptrace_detach(pid: libc::pid_t) -> io::Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wait_for_stop(pid: libc::pid_t, expected_signal: c_int) -> io::Result<()> {
    let status = waitpid_exact(pid)?;
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != expected_signal {
        return Err(io::Error::other("unexpected child stop"));
    }
    Ok(())
}

fn wait_for_exec_stop(pid: libc::pid_t) -> io::Result<()> {
    let status = waitpid_exact(pid)?;
    let event = status >> 16;
    if !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || event != PTRACE_EVENT_EXEC_VALUE
    {
        return Err(io::Error::other("missing ptrace exec stop"));
    }
    Ok(())
}

fn wait_for_self_hardening_stop(pid: libc::pid_t) -> io::Result<()> {
    wait_for_stop(pid, libc::SIGSTOP)?;
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    if unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, pid, 0, info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    if info.si_code != libc::SI_TKILL || unsafe { info.si_pid() } != pid {
        return Err(io::Error::other("invalid post-exec hardening stop"));
    }
    Ok(())
}

fn waitpid_exact(pid: libc::pid_t) -> io::Result<c_int> {
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if result == pid {
            return Ok(status);
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io::Error::last_os_error());
    }
}

fn wait_for_exit(pid: libc::pid_t) -> io::Result<()> {
    loop {
        let status = match waitpid_exact(pid) {
            Ok(status) => status,
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
            Err(error) => return Err(error),
        };
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Ok(());
        }
        if libc::WIFSTOPPED(status) {
            let _ = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, libc::SIGKILL) };
        }
    }
}

fn kill_pidfd_and_reap(pidfd: RawFd, pid: libc::pid_t) -> io::Result<()> {
    let signal_result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if signal_result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    wait_for_exit(pid)
}

fn read_proc_start_time(pid: libc::pid_t) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    parse_proc_start_time(&stat)
}

fn parse_proc_start_time(stat: &str) -> io::Result<u64> {
    let close = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("invalid proc stat"))?;
    let fields = stat[close + 1..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or_else(|| io::Error::other("missing proc starttime"))?
        .parse::<u64>()
        .map_err(|_| io::Error::other("invalid proc starttime"))
}

fn inspect_process(pid: libc::pid_t, executable_identity: &str) -> io::Result<ProcessInspection> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let uid = parse_status_identity(&status, "Uid:")?;
    let gid = parse_status_identity(&status, "Gid:")?;
    let capabilities_empty = ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
        .into_iter()
        .all(|key| matches!(parse_status_hex(&status, key), Ok(0)));
    let no_new_privs = parse_status_decimal(&status, "NoNewPrivs:")? == 1;
    let descendants_forbidden = parse_status_decimal(&status, "Seccomp:")? == 2;
    let dumpable_disabled = true;
    let selinux_domain = fs::read_to_string(format!("/proc/{pid}/attr/current"))?
        .trim_end_matches(['\0', '\n'])
        .to_string();
    let executable_sha256 = sha256_file(&format!("/proc/{pid}/exe"))?;
    let descriptors = fs::read_dir(format!("/proc/{pid}/fd"))?
        .map(|entry| {
            entry.and_then(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .parse::<u32>()
                    .map_err(io::Error::other)
            })
        })
        .collect::<io::Result<BTreeSet<_>>>()?;
    let environment_empty = fs::read(format!("/proc/{pid}/environ"))?.is_empty();
    let expected_command = format!("{executable_identity}\0").into_bytes();
    let arguments_empty = fs::read(format!("/proc/{pid}/cmdline"))? == expected_command;
    Ok(ProcessInspection {
        uid,
        gid,
        selinux_domain,
        executable_sha256,
        stdio_exact: descriptors == BTreeSet::from([0, 1]),
        environment_empty,
        arguments_empty,
        no_new_privs,
        dumpable_disabled,
        capabilities_empty,
        descendants_forbidden,
    })
}

fn parse_status_identity(status: &str, key: &str) -> io::Result<u32> {
    let values = status_values(status, key)?
        .map(|value| value.parse::<u32>().map_err(io::Error::other))
        .collect::<io::Result<Vec<_>>>()?;
    if values.len() != 4 || values.iter().any(|value| *value != values[0]) {
        return Err(io::Error::other("credential identity drift"));
    }
    Ok(values[0])
}

fn parse_status_hex(status: &str, key: &str) -> io::Result<u64> {
    let value = status_values(status, key)?
        .next()
        .ok_or_else(|| io::Error::other("missing status value"))?;
    u64::from_str_radix(value, 16).map_err(io::Error::other)
}

fn parse_status_decimal(status: &str, key: &str) -> io::Result<u64> {
    status_values(status, key)?
        .next()
        .ok_or_else(|| io::Error::other("missing status value"))?
        .parse::<u64>()
        .map_err(io::Error::other)
}

fn status_values<'a>(status: &'a str, key: &str) -> io::Result<impl Iterator<Item = &'a str>> {
    let line = status
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or_else(|| io::Error::other("missing proc status field"))?;
    Ok(line[key.len()..].split_ascii_whitespace())
}

fn sha256_file(path: &str) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast::<c_void>(), bytes.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn pidfd_identity(fd: RawFd, pid: libc::pid_t, start_time_ticks: u64) -> io::Result<String> {
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let stat = unsafe { stat.assume_init() };
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.clone3-pidfd-identity.v1\0");
    hasher.update((pid as u32).to_be_bytes());
    hasher.update(start_time_ticks.to_be_bytes());
    hasher.update(stat.st_dev.to_be_bytes());
    hasher.update(stat.st_ino.to_be_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_start_time_parser_handles_spaces_and_parentheses() {
        let mut fields = vec!["S".to_string()];
        fields.extend((1..=18).map(|value| value.to_string()));
        fields.push("4242".to_string());
        fields.extend((20..=30).map(|value| value.to_string()));
        let stat = format!("17 (publisher worker) {}", fields.join(" "));
        assert_eq!(parse_proc_start_time(&stat).unwrap(), 4242);
    }

    #[test]
    fn status_identity_requires_all_four_kernel_ids() {
        let valid = "Uid:\t5901\t5901\t5901\t5901\n";
        assert_eq!(parse_status_identity(valid, "Uid:").unwrap(), 5901);
        let drift = "Uid:\t5901\t5901\t0\t5901\n";
        assert!(parse_status_identity(drift, "Uid:").is_err());
    }

    #[test]
    fn descendant_filter_has_only_explicit_fork_denials() {
        let deny = SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32;
        assert_eq!(syscall_deny_filter(libc::SYS_clone as u32).jf, 1);
        assert_eq!(return_filter(deny).k, deny);
        assert_eq!(
            return_filter(SECCOMP_RET_ALLOW_VALUE).k,
            SECCOMP_RET_ALLOW_VALUE
        );
    }

    #[test]
    fn concrete_backend_has_no_main_or_broker_route() {
        let main = include_str!("main.rs");
        assert!(!main.contains("ConcreteLinuxReplaySyncPublisherKernel"));
        assert!(!main.contains("launch_concrete_with_injected_proof_connection"));
        assert!(!main.contains("launch_concrete_with_fixed_proof_socket"));
        assert!(!main.contains("complete_concrete"));
        let crate_root = include_str!("lib.rs");
        assert_eq!(
            crate_root
                .matches("pub(crate) mod linux_replay_sync_publisher_kernel;")
                .count(),
            1
        );
        assert!(!crate_root.contains("launch_concrete_with_injected_proof_connection("));
        assert!(!crate_root.contains("launch_concrete_with_fixed_proof_socket("));
        assert!(!crate_root.contains("complete_concrete("));
        assert_eq!(
            super::super::root_authentication_proof_socket::SOURCE_STATUS,
            "source_only_fixed_abstract_socket_connector_no_broker_route_no_product_constructor_v1"
        );
        let contract = include_bytes!(
            "../../../crates/trillionnium-os-types/contracts/capability-lease-root-kernel-custody-v1.json"
        );
        assert_eq!(
            trillionnium_os_types::sha256_bytes(contract),
            "4d1fef7a3bc0ab7e66ef51d6cfb6ad478fffcf3b5484530fc379ced413ce0009"
        );
        let custody_contract = include_bytes!(
            "../../../crates/trillionnium-os-types/contracts/capability-lease-root-socket-result-custody-v1.json"
        );
        assert_eq!(
            trillionnium_os_types::sha256_bytes(custody_contract),
            "534563d64718520417eb22f22c17a45961e6706c8d498f6720c7e30bd444fcec"
        );
        let listener_correlation_contract = include_bytes!(
            "../../../crates/trillionnium-os-types/contracts/capability-lease-root-listener-correlation-v1.json"
        );
        assert_eq!(
            trillionnium_os_types::sha256_bytes(listener_correlation_contract),
            "d63e931b87db5ff0927620659e9fd4d48e725e6ec8e6a23fd2d6dc773092c65b"
        );
    }
}
