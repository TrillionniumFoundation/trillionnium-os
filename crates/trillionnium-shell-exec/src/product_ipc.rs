//! Private broker/worker protocol for the Android product lane.
//!
//! The channel is a broker-created `SOCK_SEQPACKET` pair inherited across the
//! measured worker exec.  The worker never owns a listener.  Every record is
//! canonical JSON and every receive requires kernel `SCM_CREDENTIALS`; GO is
//! the only record allowed to carry descriptors, in the fixed order
//! executable, cwd, effect-local temporary directory.

use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::path::{Component, Path};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::direct_effect::{DirectEffectExecutionProfileV1, DirectEffectRequestV1};

use crate::WorkerCompletionV1;

pub const WORKER_PROTOCOL: &str = "org.trillionnium.shell-exec.worker-ipc.v1";
pub const STANDARD_EXECUTABLE_PATHS: [&str; 7] = [
    "/bin/echo",
    "/bin/false",
    "/bin/sleep",
    "/bin/true",
    "/bin/uname",
    "/usr/bin/id",
    "/usr/bin/printf",
];
pub const WORKER_HELLO_SCHEMA: &str = "org.trillionnium.shell-exec.worker-hello.v1";
pub const WORKER_BOOTSTRAP_SCHEMA: &str = "org.trillionnium.shell-exec.worker-bootstrap.v1";
pub const WORKER_READY_SCHEMA: &str = "org.trillionnium.shell-exec.worker-ready.v1";
pub const WORKER_GO_SCHEMA: &str = "org.trillionnium.shell-exec.worker-go.v1";
pub const WORKER_CANCEL_SCHEMA: &str = "org.trillionnium.shell-exec.worker-cancel.v1";
pub const WORKER_COMPLETION_SCHEMA: &str = "org.trillionnium.shell-exec.worker-completion.v1";
pub const MAX_WORKER_PACKET_BYTES: usize = 256 * 1024;
const MAX_KERNEL_SCM_RIGHTS_FDS: usize = 253;
pub const WORKER_CONTROL_FD: RawFd = 3;
pub const WORKER_ROOTFS_FD: RawFd = 4;
pub const WORKER_IMAGE_FD: RawFd = 5;
pub const WORKER_DEV_NULL_FD: RawFd = 6;
pub const WORKER_MEMORY_MAX_BYTES: u64 = 536_870_912;
pub const WORKER_RLIMIT_NOFILE: u64 = 64;
pub const WORKER_RLIMIT_NPROC: u64 = 64;
pub const WORKER_RLIMIT_CORE: u64 = 0;
pub const WORKER_RLIMIT_CPU_MAX_SECONDS: u64 = 61;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedWorkerCgroupPolicyV1 {
    pub schema: String,
    pub cgroup_v2_path: String,
    pub memory_max_bytes: u64,
    pub memory_oom_group: bool,
    pub memory_swap_max_bytes_when_available: u64,
    pub cleanup_method: String,
}

impl FixedWorkerCgroupPolicyV1 {
    #[must_use]
    pub fn fixed() -> Self {
        Self {
            schema: "org.trillionnium.shell-exec.worker-cgroup-policy.v1".to_string(),
            cgroup_v2_path: crate::ANDROID_WORKER_CGROUP.to_string(),
            memory_max_bytes: WORKER_MEMORY_MAX_BYTES,
            memory_oom_group: true,
            memory_swap_max_bytes_when_available: 0,
            cleanup_method: "freeze_stable_enumerate_pidfd_sigkill_unfreeze_reap_v1".to_string(),
        }
    }

    pub fn digest_sha256(&self) -> Result<String> {
        if self != &Self::fixed() {
            return Err(WorkerIpcError::InvalidRecord);
        }
        canonical_digest(b"trillionnium.shell-exec.worker-cgroup-policy.v1", self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedWorkerIsolationPolicyV1 {
    pub schema: String,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups_empty: bool,
    pub chroot_root: String,
    pub workspace_parent: String,
    pub temporary_parent: String,
    pub no_new_privileges: bool,
    pub seccomp_default_allow: bool,
    pub seccomp_denied_syscalls: Vec<String>,
    pub rlimit_nofile: u64,
    pub rlimit_nproc: u64,
    pub rlimit_core: u64,
    pub rlimit_cpu_max_seconds: u64,
    pub umask: u32,
    pub exact_argv_execveat: bool,
    pub retained_component_walk_no_symlinks: bool,
}

impl FixedWorkerIsolationPolicyV1 {
    #[must_use]
    pub fn fixed() -> Self {
        Self {
            schema: "org.trillionnium.shell-exec.worker-isolation-policy.v1".to_string(),
            uid: crate::SHELL_WORKER_UID,
            gid: crate::SHELL_WORKER_GID,
            supplementary_groups_empty: true,
            chroot_root: crate::ROOT_LINUX_HOST_ROOT.to_string(),
            workspace_parent: crate::ROOT_LINUX_WORKSPACE_PARENT.to_string(),
            temporary_parent: crate::ROOT_LINUX_TEMPORARY_PARENT.to_string(),
            no_new_privileges: true,
            seccomp_default_allow: true,
            seccomp_denied_syscalls: vec![
                "socket",
                "socketpair",
                "connect",
                "bind",
                "listen",
                "accept",
                "accept4",
                "mount",
                "umount2",
                "pivot_root",
                "chroot",
                "unshare",
                "setns",
                "clone(CLONE_NEW*)",
                "clone3",
                "ptrace",
                "bpf",
                "perf_event_open",
                "keyctl",
                "add_key",
                "request_key",
                "reboot",
                "kexec_load",
                "kexec_file_load",
                "setuid",
                "setgid",
                "setresuid",
                "setresgid",
                "setgroups",
                "capset",
                "setsid",
                "setpgid",
                "io_uring_setup",
                "io_uring_enter",
                "io_uring_register",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            rlimit_nofile: WORKER_RLIMIT_NOFILE,
            rlimit_nproc: WORKER_RLIMIT_NPROC,
            rlimit_core: WORKER_RLIMIT_CORE,
            rlimit_cpu_max_seconds: WORKER_RLIMIT_CPU_MAX_SECONDS,
            umask: 0o007,
            exact_argv_execveat: true,
            retained_component_walk_no_symlinks: true,
        }
    }

    pub fn digest_sha256(&self) -> Result<String> {
        if self != &Self::fixed() {
            return Err(WorkerIpcError::InvalidRecord);
        }
        canonical_digest(b"trillionnium.shell-exec.worker-isolation-policy.v1", self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardExecutablePolicyEntryV1 {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandardExecutablePolicyV1 {
    pub schema: String,
    pub profile: DirectEffectExecutionProfileV1,
    pub entries: Vec<StandardExecutablePolicyEntryV1>,
}

impl StandardExecutablePolicyV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(WorkerIpcError::InvalidRecord);
        }
        // The packager's canonical form is compact UTF-8 JSON with every map
        // recursively sorted by key. Deserialize through Value first so the
        // byte check follows map ordering rather than Rust struct field order.
        let json: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| WorkerIpcError::InvalidRecord)?;
        if serde_json::to_vec(&json).map_err(|_| WorkerIpcError::InvalidRecord)? != bytes {
            return Err(WorkerIpcError::InvalidRecord);
        }
        let value: Self =
            serde_json::from_value(json).map_err(|_| WorkerIpcError::InvalidRecord)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != "org.trillionnium.shell-exec.standard-executable-policy.v1"
            || self.profile != DirectEffectExecutionProfileV1::Standard
            || self.entries.len() != STANDARD_EXECUTABLE_PATHS.len()
        {
            return Err(WorkerIpcError::InvalidRecord);
        }
        let mut previous = None;
        for (executable, expected_path) in self.entries.iter().zip(STANDARD_EXECUTABLE_PATHS) {
            let path = Path::new(&executable.path);
            let basename = path.file_name().and_then(|value| value.to_str());
            if !path.is_absolute()
                || path.file_name().is_none()
                || path.components().next() != Some(Component::RootDir)
                || path
                    .components()
                    .skip(1)
                    .any(|component| !matches!(component, Component::Normal(_)))
                || !trillionnium_os_types::is_nonzero_lower_sha256(&executable.sha256)
                || executable.path != expected_path
                || basename.is_some_and(|value| {
                    matches!(
                        value,
                        "sh" | "ash"
                            | "bash"
                            | "dash"
                            | "ksh"
                            | "mksh"
                            | "zsh"
                            | "env"
                            | "busybox"
                            | "find"
                            | "mkdir"
                            | "touch"
                            | "xargs"
                            | "run-parts"
                            | "python"
                            | "python3"
                            | "perl"
                            | "ruby"
                            | "node"
                            | "java"
                            | "ld-linux-aarch64.so.1"
                    )
                })
                || previous.is_some_and(|value: &str| value >= executable.path.as_str())
            {
                return Err(WorkerIpcError::InvalidRecord);
            }
            previous = Some(executable.path.as_str());
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> Result<String> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|_| WorkerIpcError::InvalidRecord)?;
        canonical_digest(
            b"trillionnium.shell-exec.standard-executable-policy.v1",
            &value,
        )
    }

    #[must_use]
    pub fn authorizes(&self, path: &str, sha256: &str) -> bool {
        self.entries
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
            .ok()
            .is_some_and(|index| self.entries[index].sha256 == sha256)
    }

    #[must_use]
    pub fn contains_path(&self, path: &str) -> bool {
        self.entries
            .binary_search_by(|entry| entry.path.as_str().cmp(path))
            .is_ok()
    }
}

#[derive(Debug, Error)]
pub enum WorkerIpcError {
    #[error("worker IPC I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("worker IPC record is invalid")]
    InvalidRecord,
    #[error("worker IPC peer disconnected")]
    Disconnected,
}

pub type Result<T> = std::result::Result<T, WorkerIpcError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerHelloV1 {
    pub schema: String,
    pub protocol: String,
    pub pid: u32,
    pub parent_pid: u32,
    pub process_starttime_ticks: u64,
    pub selinux_domain: String,
    pub worker_executable_sha256: String,
    pub rootfs_custody_sha256: String,
    pub dev_null_custody_sha256: String,
    pub executable_policy_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerBootstrapV1 {
    pub schema: String,
    pub protocol: String,
    pub pid: u32,
    pub cgroup_membership_sha256: String,
    pub cgroup_policy_sha256: String,
    pub isolation_policy_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerReadyV1 {
    pub schema: String,
    pub protocol: String,
    pub pid: u32,
    pub process_starttime_ticks: u64,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups: Vec<u32>,
    pub selinux_domain: String,
    pub worker_executable_sha256: String,
    pub rootfs_custody_sha256: String,
    pub dev_null_custody_sha256: String,
    pub workspace_parent_custody_sha256: String,
    pub temporary_parent_custody_sha256: String,
    pub cgroup_membership_sha256: String,
    pub cgroup_policy_sha256: String,
    pub isolation_policy_sha256: String,
    pub executable_policy_sha256: String,
    pub no_new_privileges: bool,
    pub seccomp_mode: u32,
    pub effective_capabilities_hex: String,
    pub umask: u32,
    pub kernel_launch_custody_sha256: String,
    pub backend_identity_sha256: String,
}

impl WorkerReadyV1 {
    pub fn validate(&self) -> Result<()> {
        if self.schema != WORKER_READY_SCHEMA
            || self.protocol != WORKER_PROTOCOL
            || self.pid == 0
            || self.process_starttime_ticks == 0
            || self.uid != crate::SHELL_WORKER_UID
            || self.gid != crate::SHELL_WORKER_GID
            || !self.supplementary_groups.is_empty()
            || self.selinux_domain != crate::SHELL_WORKER_SELINUX_DOMAIN
            || !self.no_new_privileges
            || self.seccomp_mode != 2
            || self.effective_capabilities_hex != "0000000000000000"
            || self.umask != 0o007
            || !all_digests_valid([
                self.worker_executable_sha256.as_str(),
                self.rootfs_custody_sha256.as_str(),
                self.dev_null_custody_sha256.as_str(),
                self.workspace_parent_custody_sha256.as_str(),
                self.temporary_parent_custody_sha256.as_str(),
                self.cgroup_membership_sha256.as_str(),
                self.cgroup_policy_sha256.as_str(),
                self.isolation_policy_sha256.as_str(),
                self.executable_policy_sha256.as_str(),
                self.kernel_launch_custody_sha256.as_str(),
                self.backend_identity_sha256.as_str(),
            ])
        {
            return Err(WorkerIpcError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerGoV1 {
    pub schema: String,
    pub protocol: String,
    pub request: DirectEffectRequestV1,
    pub dispatch_started_boottime_ms: u64,
    pub dispatch_binding_sha256: String,
    pub semantic_arguments_sha256: String,
    pub approved_executable_path: String,
    pub approved_executable_sha256: String,
    pub approved_executable_custody_sha256: String,
    pub cwd_custody_sha256: String,
    pub tmpdir_path: String,
    pub tmpdir_custody_sha256: String,
    pub cpu_limit_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCancelV1 {
    pub schema: String,
    pub protocol: String,
    pub request_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCompletionFrameV1 {
    pub schema: String,
    pub protocol: String,
    pub request_sha256: String,
    pub completion: WorkerCompletionV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
// The largest variant is still below the bounded SEQPACKET record limit.
// Boxing it would alter constructors and ownership without changing the
// canonical JSON wire bytes, so keep the reviewed direct carrier.
#[allow(clippy::large_enum_variant)]
pub enum BrokerWorkerFrameV1 {
    Bootstrap(WorkerBootstrapV1),
    Go(WorkerGoV1),
    Cancel(WorkerCancelV1),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WorkerBrokerFrameV1 {
    Hello(WorkerHelloV1),
    Ready(WorkerReadyV1),
    Completion(WorkerCompletionFrameV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameCredentialsV1 {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

pub struct AuthenticatedFrameV1<T> {
    pub value: T,
    pub credentials: FrameCredentialsV1,
    pub descriptors: Vec<OwnedFd>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct RetainedDescriptorIdentityV1 {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
}

pub fn descriptor_custody_sha256(descriptor: RawFd, require_directory: bool) -> Result<String> {
    // SAFETY: zero is a valid initial representation and fstat initializes the
    // complete struct for a live descriptor.
    let mut metadata: libc::stat = unsafe { zeroed() };
    // SAFETY: metadata is writable and descriptor remains live for the call.
    if unsafe { libc::fstat(descriptor, &mut metadata) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file_type = metadata.st_mode & libc::S_IFMT;
    if (require_directory && file_type != libc::S_IFDIR)
        || (!require_directory && file_type != libc::S_IFREG)
    {
        return Err(WorkerIpcError::InvalidRecord);
    }
    canonical_digest(
        b"trillionnium.shell-exec.retained-descriptor.v1",
        &RetainedDescriptorIdentityV1 {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mode: metadata.st_mode,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
        },
    )
}

pub fn dev_null_custody_sha256(descriptor: RawFd) -> Result<String> {
    // SAFETY: zero is a valid initial representation and fstat initializes it.
    let mut metadata: libc::stat = unsafe { zeroed() };
    // SAFETY: metadata is writable and descriptor remains live.
    if unsafe { libc::fstat(descriptor, &mut metadata) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFCHR
        || libc::major(metadata.st_rdev) != 1
        || libc::minor(metadata.st_rdev) != 3
    {
        return Err(WorkerIpcError::InvalidRecord);
    }
    canonical_digest(
        b"trillionnium.shell-exec.dev-null-custody.v1",
        &RetainedDescriptorIdentityV1 {
            device: metadata.st_dev,
            inode: metadata.st_ino,
            mode: metadata.st_mode,
            uid: metadata.st_uid,
            gid: metadata.st_gid,
        },
    )
}

pub fn sha256_regular_descriptor(descriptor: RawFd, maximum_bytes: u64) -> Result<String> {
    // SAFETY: zero is a valid initial representation and fstat initializes it.
    let mut metadata: libc::stat = unsafe { zeroed() };
    // SAFETY: metadata is writable and descriptor is live.
    if unsafe { libc::fstat(descriptor, &mut metadata) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_size < 1
        || metadata.st_size as u64 > maximum_bytes
        || metadata.st_nlink != 1
    {
        return Err(WorkerIpcError::InvalidRecord);
    }
    let mut hasher = Sha256::new();
    let mut offset = 0_i64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        // SAFETY: buffer is writable; pread does not mutate descriptor offset.
        let read =
            unsafe { libc::pread(descriptor, buffer.as_mut_ptr().cast(), buffer.len(), offset) };
        if read == 0 {
            break;
        }
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        let read = read as usize;
        hasher.update(&buffer[..read]);
        offset = offset
            .checked_add(read as i64)
            .ok_or(WorkerIpcError::InvalidRecord)?;
        if offset as u64 > maximum_bytes {
            return Err(WorkerIpcError::InvalidRecord);
        }
    }
    if offset != metadata.st_size {
        return Err(WorkerIpcError::InvalidRecord);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn seqpacket_pair() -> Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: descriptors names two writable ints; success initializes both
    // with distinct close-on-exec AF_UNIX SOCK_SEQPACKET endpoints.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: socketpair returned two fresh independently owned descriptors.
    let first = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: ownership of the second descriptor is also unique.
    let second = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    require_passcred(&first)?;
    require_passcred(&second)?;
    Ok((first, second))
}

pub fn require_passcred(descriptor: &OwnedFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: enabled is the exact value type required by SO_PASSCRED and the
    // descriptor is a live AF_UNIX socket.
    if unsafe {
        libc::setsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            std::ptr::from_ref(&enabled).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub fn send_frame<T: Serialize>(
    descriptor: RawFd,
    value: &T,
    passed_descriptors: &[RawFd],
) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| WorkerIpcError::InvalidRecord)?;
    if bytes.is_empty() || bytes.len() > MAX_WORKER_PACKET_BYTES {
        return Err(WorkerIpcError::InvalidRecord);
    }
    let mut io_vector = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    if passed_descriptors.len() > 3 || passed_descriptors.iter().any(|value| *value < 0) {
        return Err(WorkerIpcError::InvalidRecord);
    }
    // One aligned cmsghdr plus at most three RawFd values. CMSG_SPACE includes
    // required tail padding, and zero initialization is valid ancillary
    // storage.
    let rights_bytes = size_of::<RawFd>()
        .checked_mul(passed_descriptors.len())
        .ok_or(WorkerIpcError::InvalidRecord)?;
    let rights_space = unsafe { libc::CMSG_SPACE(rights_bytes as u32) as usize };
    let mut ancillary = vec![0_u8; rights_space];
    // SAFETY: zero is a valid initial representation for msghdr; every field
    // used by sendmsg is populated below and all buffers outlive the call.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = std::ptr::from_mut(&mut io_vector);
    message.msg_iovlen = 1;
    if !passed_descriptors.is_empty() {
        message.msg_control = ancillary.as_mut_ptr().cast();
        message.msg_controllen = ancillary.len() as _;
        // SAFETY: msg_control has CMSG_SPACE bytes and is aligned sufficiently
        // for cmsghdr as allocated by the system allocator.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if header.is_null() {
                return Err(WorkerIpcError::InvalidRecord);
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(rights_bytes as u32) as _;
            std::ptr::copy_nonoverlapping(
                passed_descriptors.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                rights_bytes,
            );
            message.msg_controllen = (*header).cmsg_len;
        }
    }
    loop {
        // SAFETY: message points only to live immutable payload and ancillary
        // storage for this synchronous call.
        let sent = unsafe { libc::sendmsg(descriptor, &message, libc::MSG_NOSIGNAL) };
        if sent == bytes.len() as isize {
            return Ok(());
        }
        if sent >= 0 {
            return Err(WorkerIpcError::InvalidRecord);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

pub fn receive_frame<T: DeserializeOwned + Serialize>(
    descriptor: RawFd,
) -> Result<AuthenticatedFrameV1<T>> {
    let mut bytes = vec![0_u8; MAX_WORKER_PACKET_BYTES];
    let mut io_vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let credentials_space = unsafe { libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) as usize };
    // Linux caps one SCM_RIGHTS record at SCM_MAX_FD (253). Receive the whole
    // kernel-legal maximum, then reject anything above this protocol's three
    // descriptors after every installed fd is owned by the drop guard.
    let maximum_rights_bytes = MAX_KERNEL_SCM_RIGHTS_FDS * size_of::<RawFd>();
    let rights_space = unsafe { libc::CMSG_SPACE(maximum_rights_bytes as u32) as usize };
    let mut ancillary = vec![0_u8; credentials_space + rights_space];
    // SAFETY: zero is a valid initial representation for msghdr; all buffer
    // pointers and lengths are populated and remain valid through recvmsg.
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = std::ptr::from_mut(&mut io_vector);
    message.msg_iovlen = 1;
    message.msg_control = ancillary.as_mut_ptr().cast();
    message.msg_controllen = ancillary.len() as _;
    let received = loop {
        // SAFETY: message names writable payload and ancillary buffers.
        let received = unsafe { libc::recvmsg(descriptor, &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received >= 0 {
            break received as usize;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    };
    if received == 0 {
        return Err(WorkerIpcError::Disconnected);
    }
    if received > bytes.len() || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        // Linux may already have installed the prefix of an oversized
        // SCM_RIGHTS array before reporting MSG_CTRUNC. Close every complete
        // descriptor visible in the returned ancillary prefix before failing.
        unsafe { close_received_rights(&message) };
        return Err(WorkerIpcError::InvalidRecord);
    }
    bytes.truncate(received);
    let mut credentials = None;
    let mut passed_descriptors = Vec::new();
    // SAFETY: recvmsg initialized the ancillary region described by message;
    // CMSG_NXTHDR bounds-checks each next header against that region.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level != libc::SOL_SOCKET {
                return Err(WorkerIpcError::InvalidRecord);
            }
            match (*header).cmsg_type {
                libc::SCM_CREDENTIALS => {
                    if credentials.is_some()
                        || (*header).cmsg_len as usize
                            != libc::CMSG_LEN(size_of::<libc::ucred>() as u32) as usize
                    {
                        return Err(WorkerIpcError::InvalidRecord);
                    }
                    let observed: libc::ucred =
                        std::ptr::read_unaligned(libc::CMSG_DATA(header).cast());
                    credentials = Some(observed);
                }
                libc::SCM_RIGHTS => {
                    let header_length = (*header).cmsg_len as usize;
                    let minimum = libc::CMSG_LEN(0) as usize;
                    if !passed_descriptors.is_empty() || header_length < minimum {
                        return Err(WorkerIpcError::InvalidRecord);
                    }
                    let rights_bytes = header_length - minimum;
                    if rights_bytes == 0
                        || rights_bytes > maximum_rights_bytes
                        || !rights_bytes.is_multiple_of(size_of::<RawFd>())
                    {
                        return Err(WorkerIpcError::InvalidRecord);
                    }
                    let count = rights_bytes / size_of::<RawFd>();
                    for index in 0..count {
                        let observed: RawFd = std::ptr::read_unaligned(
                            libc::CMSG_DATA(header)
                                .add(index * size_of::<RawFd>())
                                .cast(),
                        );
                        if observed < 0 {
                            return Err(WorkerIpcError::InvalidRecord);
                        }
                        passed_descriptors.push(OwnedFd::from_raw_fd(observed));
                    }
                }
                _ => return Err(WorkerIpcError::InvalidRecord),
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    let credentials = credentials.ok_or(WorkerIpcError::InvalidRecord)?;
    if passed_descriptors.len() > 3 {
        return Err(WorkerIpcError::InvalidRecord);
    }
    let pid = u32::try_from(credentials.pid).map_err(|_| WorkerIpcError::InvalidRecord)?;
    if pid == 0 {
        return Err(WorkerIpcError::InvalidRecord);
    }
    let value: T = serde_json::from_slice(&bytes).map_err(|_| WorkerIpcError::InvalidRecord)?;
    if serde_json::to_vec(&value).map_err(|_| WorkerIpcError::InvalidRecord)? != bytes {
        return Err(WorkerIpcError::InvalidRecord);
    }
    Ok(AuthenticatedFrameV1 {
        value,
        credentials: FrameCredentialsV1 {
            pid,
            uid: credentials.uid,
            gid: credentials.gid,
        },
        descriptors: passed_descriptors,
    })
}

unsafe fn close_received_rights(message: &libc::msghdr) {
    // SAFETY: caller passes the msghdr just initialized by recvmsg. CMSG macros
    // bound traversal to msg_controllen; malformed headers terminate cleanup.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            let length = (*header).cmsg_len as usize;
            let minimum = libc::CMSG_LEN(0) as usize;
            if length < minimum {
                break;
            }
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = length - minimum;
                let count = bytes / size_of::<RawFd>();
                for index in 0..count {
                    let descriptor: RawFd = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header)
                            .add(index * size_of::<RawFd>())
                            .cast(),
                    );
                    if descriptor >= 0 {
                        libc::close(descriptor);
                    }
                }
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
    }
}

fn all_digests_valid<const N: usize>(values: [&str; N]) -> bool {
    values
        .into_iter()
        .all(trillionnium_os_types::is_nonzero_lower_sha256)
}

pub fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).map_err(|_| WorkerIpcError::InvalidRecord)?;
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    format!("{:x}", hasher.finalize())
}

#[allow(clippy::too_many_arguments)]
pub fn effect_dispatch_binding_sha256(
    request_sha256: &str,
    ready: &WorkerReadyV1,
    semantic_arguments_sha256: &str,
    approved_executable_path: &str,
    approved_executable_sha256: &str,
    approved_executable_custody_sha256: &str,
    cwd_custody_sha256: &str,
    tmpdir_path: &str,
    tmpdir_custody_sha256: &str,
) -> String {
    domain_digest(
        b"trillionnium.shell-exec.dispatch-binding.v2",
        &[
            request_sha256.as_bytes(),
            ready.kernel_launch_custody_sha256.as_bytes(),
            ready.backend_identity_sha256.as_bytes(),
            &ready.pid.to_be_bytes(),
            &ready.process_starttime_ticks.to_be_bytes(),
            semantic_arguments_sha256.as_bytes(),
            approved_executable_path.as_bytes(),
            approved_executable_sha256.as_bytes(),
            approved_executable_custody_sha256.as_bytes(),
            cwd_custody_sha256.as_bytes(),
            tmpdir_path.as_bytes(),
            tmpdir_custody_sha256.as_bytes(),
        ],
    )
}

pub fn effect_scope_leaf_name(request: &DirectEffectRequestV1) -> Result<String> {
    request
        .validate()
        .map_err(|_| WorkerIpcError::InvalidRecord)?;
    if !trillionnium_os_types::is_nonzero_lower_sha256(&request.direct_binding_sha256) {
        return Err(WorkerIpcError::InvalidRecord);
    }
    Ok(format!("w-{}", request.direct_binding_sha256))
}

pub fn scope_marker_binding(request: &DirectEffectRequestV1) -> Result<&str> {
    request
        .validate()
        .map_err(|_| WorkerIpcError::InvalidRecord)?;
    Ok(&request.direct_binding_sha256)
}

pub fn effect_tmpdir_name(request: &DirectEffectRequestV1) -> Result<String> {
    request
        .validate()
        .map_err(|_| WorkerIpcError::InvalidRecord)?;
    let digest = request
        .effect_id
        .strip_prefix("effect:")
        .filter(|value| trillionnium_os_types::is_nonzero_lower_sha256(value))
        .ok_or(WorkerIpcError::InvalidRecord)?;
    Ok(format!(".tmp-{digest}"))
}
