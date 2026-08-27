//! Measured Root Linux worker for the Android product lane.
//!
//! The broker execs this ELF through a retained descriptor so SELinux enters
//! the dedicated worker domain before any model-selected executable is
//! considered.  This process then chroots through a retained rootfs dirfd,
//! drops to the fixed worker UID/GID, clears capabilities, installs NNP and a
//! syscall filter, emits READY, and waits on its inherited private socket.
//! It never creates, binds, connects, accepts, or listens on a socket.

use std::ffi::CString;
use std::fs::File;
use std::io::Read as _;
use std::mem::zeroed;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::thread;
use std::time::Duration;

use thiserror::Error;
use trillionnium_os_types::direct_effect::{
    DirectEffectBinaryOutputV1, DirectEffectIndeterminateReasonV1, DirectEffectRequestV1,
    DirectEffectTerminalKindV1, DirectEffectTerminalResponseV1, TERMINAL_RESPONSE_SCHEMA,
};

use crate::product_ipc::{
    AuthenticatedFrameV1, BrokerWorkerFrameV1, FixedWorkerCgroupPolicyV1,
    FixedWorkerIsolationPolicyV1, StandardExecutablePolicyV1, WORKER_BOOTSTRAP_SCHEMA,
    WORKER_CANCEL_SCHEMA, WORKER_COMPLETION_SCHEMA, WORKER_CONTROL_FD, WORKER_DEV_NULL_FD,
    WORKER_GO_SCHEMA, WORKER_HELLO_SCHEMA, WORKER_IMAGE_FD, WORKER_PROTOCOL, WORKER_READY_SCHEMA,
    WORKER_RLIMIT_CORE, WORKER_RLIMIT_CPU_MAX_SECONDS, WORKER_RLIMIT_NOFILE, WORKER_RLIMIT_NPROC,
    WORKER_ROOTFS_FD, WorkerBootstrapV1, WorkerBrokerFrameV1, WorkerCancelV1,
    WorkerCompletionFrameV1, WorkerGoV1, WorkerHelloV1, WorkerIpcError, WorkerReadyV1,
    descriptor_custody_sha256, dev_null_custody_sha256, domain_digest,
    effect_dispatch_binding_sha256, effect_tmpdir_name, receive_frame, require_passcred,
    send_frame, sha256_regular_descriptor,
};
use crate::product_paths::{RequiredFileTypeV1, open_beneath_component_walk};
use crate::{
    ROOT_LINUX_EXECUTABLE_POLICY, ROOT_LINUX_TEMPORARY_PARENT, ROOT_LINUX_WORKSPACE_PARENT,
    SHELL_BROKER_UID, SHELL_WORKER_GID, SHELL_WORKER_SELINUX_DOMAIN, SHELL_WORKER_UID,
    WorkerCompletionV1, validate_first_slice_request,
};

const MAX_WORKER_ELF_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PROC_RECORD_BYTES: u64 = 16 * 1024;
const PIPE_CHUNK_BYTES: usize = 16 * 1024;
const EXECUTION_POLL: Duration = Duration::from_millis(2);
const FORCED_CLEANUP_GRACE_MS: u64 = 250;
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGUMENT_ZERO_OFFSET: u32 = 16;
const CLONE_NEW_NAMESPACE_FLAGS: u32 = 0x7e02_0080;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_00b7;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const SYS_KEXEC_FILE_LOAD_NATIVE: libc::c_long = 294;
#[cfg(target_arch = "x86_64")]
const SYS_KEXEC_FILE_LOAD_NATIVE: libc::c_long = 320;

#[derive(Debug, Error)]
pub enum ProductWorkerError {
    #[error("worker bootstrap failed: {0}")]
    Bootstrap(&'static str),
    #[error("worker I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("worker IPC failed: {0}")]
    Ipc(#[from] WorkerIpcError),
}

type Result<T> = std::result::Result<T, ProductWorkerError>;

struct ProductWorkerV1 {
    control: OwnedFd,
    _rootfs: OwnedFd,
    _proc_self: OwnedFd,
    _workspace_parent: OwnedFd,
    _temporary_parent: OwnedFd,
    dev_null: OwnedFd,
    executable_policy: StandardExecutablePolicyV1,
    parent_pid: u32,
    ready: WorkerReadyV1,
}

pub fn run() -> Result<()> {
    let mut worker = ProductWorkerV1::bootstrap()?;
    worker.serve()
}

impl ProductWorkerV1 {
    fn bootstrap() -> Result<Self> {
        let control = adopt_fixed_descriptor(WORKER_CONTROL_FD)?;
        let rootfs = adopt_fixed_descriptor(WORKER_ROOTFS_FD)?;
        let worker_image = adopt_fixed_descriptor(WORKER_IMAGE_FD)?;
        let dev_null = adopt_fixed_descriptor(WORKER_DEV_NULL_FD)?;
        require_passcred(&control)?;
        validate_rootfs_descriptor(rootfs.as_raw_fd())?;
        set_parent_death_signal()?;
        let pid = current_pid()?;
        let parent_pid = parent_pid()?;
        if parent_pid <= 1 {
            return Err(ProductWorkerError::Bootstrap("broker_parent_absent"));
        }

        let proc_self = open_absolute_directory("/proc/self")?;
        let process_starttime_ticks = process_starttime_ticks(proc_self.as_raw_fd())?;
        let selinux_domain = read_selinux_domain(proc_self.as_raw_fd())?;
        if selinux_domain != SHELL_WORKER_SELINUX_DOMAIN {
            return Err(ProductWorkerError::Bootstrap(
                "worker_selinux_transition_missing",
            ));
        }
        let executable = open_absolute_file("/proc/self/exe")?;
        let worker_executable_sha256 =
            sha256_regular_descriptor(executable.as_raw_fd(), MAX_WORKER_ELF_BYTES)?;
        if sha256_regular_descriptor(worker_image.as_raw_fd(), MAX_WORKER_ELF_BYTES)?
            != worker_executable_sha256
        {
            return Err(ProductWorkerError::Bootstrap(
                "worker_image_binding_invalid",
            ));
        }
        let rootfs_custody_sha256 = descriptor_custody_sha256(rootfs.as_raw_fd(), true)?;
        validate_dev_null(dev_null.as_raw_fd())?;
        let dev_null_custody_sha256 = dev_null_custody_sha256(dev_null.as_raw_fd())?;
        let executable_policy_descriptor =
            open_beneath_component_walk(
                rootfs.as_raw_fd(),
                ROOT_LINUX_EXECUTABLE_POLICY.strip_prefix('/').ok_or(
                    ProductWorkerError::Bootstrap("executable_policy_path_invalid"),
                )?,
                libc::O_RDONLY | libc::O_CLOEXEC,
                RequiredFileTypeV1::Regular,
            )
            .map_err(|_| ProductWorkerError::Bootstrap("executable_policy_open_invalid"))?;
        validate_root_owned_policy_file(executable_policy_descriptor.as_raw_fd())?;
        let executable_policy_bytes =
            read_bounded_descriptor(executable_policy_descriptor.as_raw_fd(), 64 * 1024)?;
        let executable_policy =
            StandardExecutablePolicyV1::from_canonical_bytes(&executable_policy_bytes)?;
        let executable_policy_sha256 = executable_policy.digest_sha256()?;
        let hello = WorkerBrokerFrameV1::Hello(WorkerHelloV1 {
            schema: WORKER_HELLO_SCHEMA.to_string(),
            protocol: WORKER_PROTOCOL.to_string(),
            pid,
            parent_pid,
            process_starttime_ticks,
            selinux_domain: selinux_domain.clone(),
            worker_executable_sha256: worker_executable_sha256.clone(),
            rootfs_custody_sha256: rootfs_custody_sha256.clone(),
            dev_null_custody_sha256: dev_null_custody_sha256.clone(),
            executable_policy_sha256: executable_policy_sha256.clone(),
        });
        // The retained image fd was needed only to bind the exact exec image.
        // Drop it before READY; all other fixed descriptors have CLOEXEC
        // restored by adopt_fixed_descriptor().
        drop(worker_image);
        send_frame(control.as_raw_fd(), &hello, &[])?;

        let bootstrap: AuthenticatedFrameV1<BrokerWorkerFrameV1> =
            receive_frame(control.as_raw_fd())?;
        require_broker_credentials(&bootstrap, parent_pid)?;
        if !bootstrap.descriptors.is_empty() {
            return Err(ProductWorkerError::Bootstrap(
                "bootstrap_descriptor_forbidden",
            ));
        }
        let BrokerWorkerFrameV1::Bootstrap(bootstrap) = bootstrap.value else {
            return Err(ProductWorkerError::Bootstrap("bootstrap_frame_expected"));
        };
        validate_bootstrap(&bootstrap, pid)?;
        let cgroup_membership = read_proc_record(proc_self.as_raw_fd(), "cgroup")?;
        validate_fixed_cgroup_membership(&cgroup_membership)?;
        let cgroup_membership_sha256 = domain_digest(
            b"trillionnium.shell-exec.worker-cgroup-membership.v1",
            &[cgroup_membership.as_bytes()],
        );
        if bootstrap.cgroup_membership_sha256 != cgroup_membership_sha256 {
            return Err(ProductWorkerError::Bootstrap(
                "cgroup_membership_binding_mismatch",
            ));
        }

        let workspace_parent = open_beneath_component_walk(
            rootfs.as_raw_fd(),
            ROOT_LINUX_WORKSPACE_PARENT
                .strip_prefix('/')
                .ok_or(ProductWorkerError::Bootstrap("workspace_path_invalid"))?,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RequiredFileTypeV1::Directory,
        )
        .map_err(|_| ProductWorkerError::Bootstrap("workspace_parent_open_invalid"))?;
        let temporary_parent = open_beneath_component_walk(
            rootfs.as_raw_fd(),
            ROOT_LINUX_TEMPORARY_PARENT
                .strip_prefix('/')
                .ok_or(ProductWorkerError::Bootstrap("temporary_path_invalid"))?,
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            RequiredFileTypeV1::Directory,
        )
        .map_err(|_| ProductWorkerError::Bootstrap("temporary_parent_open_invalid"))?;
        validate_scope_parent(workspace_parent.as_raw_fd())?;
        validate_scope_parent(temporary_parent.as_raw_fd())?;
        let workspace_parent_custody_sha256 =
            descriptor_custody_sha256(workspace_parent.as_raw_fd(), true)?;
        let temporary_parent_custody_sha256 =
            descriptor_custody_sha256(temporary_parent.as_raw_fd(), true)?;
        enter_retained_rootfs(rootfs.as_raw_fd())?;
        install_supervisor_resource_limits()?;
        set_and_verify_umask()?;
        drop_worker_credentials(parent_pid)?;
        install_no_new_privileges_and_seccomp()?;
        verify_isolation_state(parent_pid)?;

        let kernel_launch_custody_sha256 = domain_digest(
            b"trillionnium.shell-exec.kernel-launch-custody.v1",
            &[
                selinux_domain.as_bytes(),
                worker_executable_sha256.as_bytes(),
                rootfs_custody_sha256.as_bytes(),
                dev_null_custody_sha256.as_bytes(),
                workspace_parent_custody_sha256.as_bytes(),
                temporary_parent_custody_sha256.as_bytes(),
                bootstrap.cgroup_membership_sha256.as_bytes(),
                bootstrap.cgroup_policy_sha256.as_bytes(),
                bootstrap.isolation_policy_sha256.as_bytes(),
                executable_policy_sha256.as_bytes(),
            ],
        );
        let backend_identity_sha256 = domain_digest(
            b"trillionnium.shell-exec.worker-backend-identity.v1",
            &[
                WORKER_PROTOCOL.as_bytes(),
                worker_executable_sha256.as_bytes(),
                dev_null_custody_sha256.as_bytes(),
                bootstrap.cgroup_policy_sha256.as_bytes(),
                bootstrap.isolation_policy_sha256.as_bytes(),
                executable_policy_sha256.as_bytes(),
            ],
        );
        let ready = WorkerReadyV1 {
            schema: WORKER_READY_SCHEMA.to_string(),
            protocol: WORKER_PROTOCOL.to_string(),
            pid,
            process_starttime_ticks,
            uid: SHELL_WORKER_UID,
            gid: SHELL_WORKER_GID,
            supplementary_groups: Vec::new(),
            selinux_domain,
            worker_executable_sha256,
            rootfs_custody_sha256,
            dev_null_custody_sha256,
            workspace_parent_custody_sha256,
            temporary_parent_custody_sha256,
            cgroup_membership_sha256: bootstrap.cgroup_membership_sha256,
            cgroup_policy_sha256: bootstrap.cgroup_policy_sha256,
            isolation_policy_sha256: bootstrap.isolation_policy_sha256,
            executable_policy_sha256,
            no_new_privileges: true,
            seccomp_mode: 2,
            effective_capabilities_hex: "0000000000000000".to_string(),
            umask: 0o007,
            kernel_launch_custody_sha256,
            backend_identity_sha256,
        };
        ready.validate()?;
        send_frame(
            control.as_raw_fd(),
            &WorkerBrokerFrameV1::Ready(ready.clone()),
            &[],
        )?;
        Ok(Self {
            control,
            _rootfs: rootfs,
            _proc_self: proc_self,
            _workspace_parent: workspace_parent,
            _temporary_parent: temporary_parent,
            dev_null,
            executable_policy,
            parent_pid,
            ready,
        })
    }

    fn serve(&mut self) -> Result<()> {
        let frame: AuthenticatedFrameV1<BrokerWorkerFrameV1> =
            receive_frame(self.control.as_raw_fd())?;
        require_broker_credentials(&frame, self.parent_pid)?;
        let BrokerWorkerFrameV1::Go(go) = frame.value else {
            return Err(ProductWorkerError::Bootstrap("go_frame_expected"));
        };
        if frame.descriptors.len() != 3 {
            return Err(ProductWorkerError::Bootstrap("go_descriptors_invalid"));
        }
        let mut descriptors = frame.descriptors.into_iter();
        let executable = descriptors.next().unwrap();
        let cwd = descriptors.next().unwrap();
        let tmpdir = descriptors.next().unwrap();
        let completion = self.execute(&go, executable, cwd, tmpdir)?;
        let response = WorkerBrokerFrameV1::Completion(WorkerCompletionFrameV1 {
            schema: WORKER_COMPLETION_SCHEMA.to_string(),
            protocol: WORKER_PROTOCOL.to_string(),
            request_sha256: go.request.request_sha256.clone(),
            completion,
        });
        send_frame(self.control.as_raw_fd(), &response, &[])?;
        Ok(())
    }

    fn execute(
        &self,
        go: &WorkerGoV1,
        approved_executable: OwnedFd,
        cwd: OwnedFd,
        tmpdir: OwnedFd,
    ) -> Result<WorkerCompletionV1> {
        validate_go(go, &self.ready)?;
        validate_executable(approved_executable.as_raw_fd())?;
        validate_preopened_cwd(cwd.as_raw_fd())?;
        validate_effect_tmpdir(tmpdir.as_raw_fd())?;
        let executable_sha256 =
            sha256_regular_descriptor(approved_executable.as_raw_fd(), MAX_WORKER_ELF_BYTES)?;
        if executable_sha256 != go.approved_executable_sha256
            || descriptor_custody_sha256(approved_executable.as_raw_fd(), false)?
                != go.approved_executable_custody_sha256
            || descriptor_custody_sha256(cwd.as_raw_fd(), true)? != go.cwd_custody_sha256
            || descriptor_custody_sha256(tmpdir.as_raw_fd(), true)? != go.tmpdir_custody_sha256
            || !self
                .executable_policy
                .authorizes(&go.approved_executable_path, &executable_sha256)
        {
            return Err(ProductWorkerError::Bootstrap(
                "go_descriptor_binding_invalid",
            ));
        }
        let argv = c_strings(&go.request.arguments.argv)?;
        let environment = c_strings(&[
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
            "HOME=/var/empty".to_string(),
            "LANG=C.UTF-8".to_string(),
            "LC_ALL=C.UTF-8".to_string(),
            format!("TMPDIR={}", go.tmpdir_path),
        ])?;
        let argv_pointers = argv
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>();
        let environment_pointers = environment
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>();
        let (stdout_read, stdout_write) = pipe_cloexec()?;
        let (stderr_read, stderr_write) = pipe_cloexec()?;
        let (exec_error_read, exec_error_write) = pipe_cloexec()?;

        if let Some(reason) = self.pending_cancel_reason(&go.request)? {
            return Ok(WorkerCompletionV1::Indeterminate {
                reason,
                observed_boottime_ms: product_boottime_ms()?.max(go.dispatch_started_boottime_ms),
            });
        }
        if product_boottime_ms()? >= go.request.absolute_deadline_boottime_ms {
            return Ok(WorkerCompletionV1::Indeterminate {
                reason: DirectEffectIndeterminateReasonV1::DeadlineAfterDispatch,
                observed_boottime_ms: product_boottime_ms()?.max(go.dispatch_started_boottime_ms),
            });
        }

        // SAFETY: this worker is single-threaded. The child branch performs
        // only async-signal-safe libc operations and then execveat/_exit.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Ok(WorkerCompletionV1::Terminal(terminal_response(
                &go.request,
                go.dispatch_started_boottime_ms,
                product_boottime_ms()?.max(go.dispatch_started_boottime_ms),
                DirectEffectTerminalKindV1::LaunchRejected,
                None,
                None,
                Some("fork_denied".to_string()),
                b"",
                b"",
            )));
        }
        if child == 0 {
            child_exec(
                cwd.as_raw_fd(),
                approved_executable.as_raw_fd(),
                self.dev_null.as_raw_fd(),
                stdout_write.as_raw_fd(),
                stderr_write.as_raw_fd(),
                exec_error_write.as_raw_fd(),
                &argv_pointers,
                &environment_pointers,
                go.cpu_limit_seconds,
            );
        }
        drop(stdout_write);
        drop(stderr_write);
        drop(exec_error_write);
        set_nonblocking(stdout_read.as_raw_fd())?;
        set_nonblocking(stderr_read.as_raw_fd())?;
        set_nonblocking(exec_error_read.as_raw_fd())?;
        supervise_child(
            child,
            &go.request,
            go.dispatch_started_boottime_ms,
            self.control.as_raw_fd(),
            self.parent_pid,
            stdout_read.as_raw_fd(),
            stderr_read.as_raw_fd(),
            exec_error_read.as_raw_fd(),
        )
    }

    fn pending_cancel_reason(
        &self,
        request: &DirectEffectRequestV1,
    ) -> Result<Option<DirectEffectIndeterminateReasonV1>> {
        let mut descriptor = libc::pollfd {
            fd: self.control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP,
            revents: 0,
        };
        // SAFETY: descriptor points to one initialized pollfd.
        let observed = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if observed < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if observed == 0 {
            return Ok(None);
        }
        if descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP) != 0 {
            return Ok(Some(
                DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch,
            ));
        }
        let frame: AuthenticatedFrameV1<BrokerWorkerFrameV1> =
            receive_frame(self.control.as_raw_fd())?;
        require_broker_credentials(&frame, self.parent_pid)?;
        if !frame.descriptors.is_empty() {
            return Ok(Some(
                DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch,
            ));
        }
        match frame.value {
            BrokerWorkerFrameV1::Cancel(cancel)
                if cancel.schema == WORKER_CANCEL_SCHEMA
                    && cancel.protocol == WORKER_PROTOCOL
                    && cancel.request_sha256 == request.request_sha256 =>
            {
                Ok(Some(
                    DirectEffectIndeterminateReasonV1::CancelledAfterDispatch,
                ))
            }
            _ => Ok(Some(
                DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch,
            )),
        }
    }
}

fn validate_bootstrap(bootstrap: &WorkerBootstrapV1, pid: u32) -> Result<()> {
    let cgroup_policy = FixedWorkerCgroupPolicyV1::fixed().digest_sha256()?;
    let isolation_policy = FixedWorkerIsolationPolicyV1::fixed().digest_sha256()?;
    if bootstrap.schema != WORKER_BOOTSTRAP_SCHEMA
        || bootstrap.protocol != WORKER_PROTOCOL
        || bootstrap.pid != pid
        || bootstrap.cgroup_policy_sha256 != cgroup_policy
        || bootstrap.isolation_policy_sha256 != isolation_policy
        || !trillionnium_os_types::is_nonzero_lower_sha256(&bootstrap.cgroup_membership_sha256)
    {
        return Err(ProductWorkerError::Bootstrap("bootstrap_binding_invalid"));
    }
    Ok(())
}

fn valid_absolute_product_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    path.is_absolute()
        && path.file_name().is_some()
        && path
            .components()
            .skip(1)
            .all(|component| matches!(component, std::path::Component::Normal(_)))
}

fn validate_go(go: &WorkerGoV1, ready: &WorkerReadyV1) -> Result<()> {
    validate_first_slice_request(&go.request)
        .map_err(|_| ProductWorkerError::Bootstrap("go_request_invalid"))?;
    let semantic_arguments_sha256 = go
        .request
        .arguments
        .canonical_sha256()
        .map_err(|_| ProductWorkerError::Bootstrap("go_arguments_invalid"))?;
    let dispatch_binding_sha256 = effect_dispatch_binding_sha256(
        &go.request.request_sha256,
        ready,
        &go.semantic_arguments_sha256,
        &go.approved_executable_path,
        &go.approved_executable_sha256,
        &go.approved_executable_custody_sha256,
        &go.cwd_custody_sha256,
        &go.tmpdir_path,
        &go.tmpdir_custody_sha256,
    );
    if go.schema != WORKER_GO_SCHEMA
        || go.protocol != WORKER_PROTOCOL
        || go.request.kernel_launch_custody_sha256 != ready.kernel_launch_custody_sha256
        || go.request.backend_identity_sha256 != ready.backend_identity_sha256
        || go.request.arguments.argv[0] != go.approved_executable_path
        || semantic_arguments_sha256 != go.semantic_arguments_sha256
        || !valid_absolute_product_path(&go.approved_executable_path)
        || !valid_absolute_product_path(&go.tmpdir_path)
        || !trillionnium_os_types::is_nonzero_lower_sha256(&go.approved_executable_sha256)
        || !trillionnium_os_types::is_nonzero_lower_sha256(&go.approved_executable_custody_sha256)
        || !trillionnium_os_types::is_nonzero_lower_sha256(&go.cwd_custody_sha256)
        || !trillionnium_os_types::is_nonzero_lower_sha256(&go.tmpdir_custody_sha256)
        || !go
            .tmpdir_path
            .ends_with(&format!("/{}", effect_tmpdir_name(&go.request)?))
        || go.dispatch_started_boottime_ms == 0
        || go.dispatch_started_boottime_ms >= go.request.absolute_deadline_boottime_ms
        || go.dispatch_binding_sha256 != dispatch_binding_sha256
        || go.cpu_limit_seconds == 0
        || go.cpu_limit_seconds > WORKER_RLIMIT_CPU_MAX_SECONDS
    {
        return Err(ProductWorkerError::Bootstrap("go_binding_invalid"));
    }
    Ok(())
}

fn require_broker_credentials<T>(frame: &AuthenticatedFrameV1<T>, parent_pid: u32) -> Result<()> {
    if frame.credentials.pid != parent_pid
        || frame.credentials.uid != SHELL_BROKER_UID
        || frame.credentials.gid != 0
    {
        return Err(ProductWorkerError::Bootstrap(
            "broker_frame_credentials_invalid",
        ));
    }
    Ok(())
}

fn adopt_fixed_descriptor(descriptor: RawFd) -> Result<OwnedFd> {
    // SAFETY: F_GETFD observes validity without changing descriptor state.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // The broker necessarily clears CLOEXEC for the one measured worker exec.
    // Restore it immediately so no fixed control/rootfs/image descriptor can
    // leak into the later model-selected exec.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        || unsafe { libc::fcntl(descriptor, libc::F_GETFD) } & libc::FD_CLOEXEC == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: product startup contract transfers unique ownership of each
    // fixed inherited descriptor to this process exactly once.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn open_absolute_directory(path: &str) -> Result<OwnedFd> {
    open_absolute(path, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
}

fn open_absolute_file(path: &str) -> Result<OwnedFd> {
    open_absolute(path, libc::O_RDONLY | libc::O_CLOEXEC)
}

fn open_absolute(path: &str, flags: libc::c_int) -> Result<OwnedFd> {
    let path =
        CString::new(path).map_err(|_| ProductWorkerError::Bootstrap("absolute_path_invalid"))?;
    // SAFETY: path is NUL-terminated and ownership of a successful descriptor
    // transfers immediately to OwnedFd.
    let descriptor = unsafe { libc::open(path.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn validate_rootfs_descriptor(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_mode & 0o022 != 0
    {
        return Err(ProductWorkerError::Bootstrap("rootfs_custody_invalid"));
    }
    Ok(())
}

fn validate_scope_parent(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_mode & 0o777 != 0o711
    {
        return Err(ProductWorkerError::Bootstrap(
            "scope_parent_custody_invalid",
        ));
    }
    Ok(())
}

fn validate_executable(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_mode & 0o022 != 0
        || metadata.st_mode & 0o111 == 0
    {
        return Err(ProductWorkerError::Bootstrap(
            "opened_executable_custody_invalid",
        ));
    }
    Ok(())
}

fn validate_root_owned_policy_file(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_uid != 0
        || metadata.st_gid != 0
        || metadata.st_nlink != 1
        || metadata.st_mode & 0o777 != 0o444
    {
        return Err(ProductWorkerError::Bootstrap(
            "executable_policy_custody_invalid",
        ));
    }
    Ok(())
}

fn validate_effect_tmpdir(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR
        || metadata.st_uid != 0
        || metadata.st_gid != SHELL_WORKER_GID
        || metadata.st_mode & 0o777 != 0o770
    {
        return Err(ProductWorkerError::Bootstrap("tmpdir_custody_invalid"));
    }
    Ok(())
}

fn validate_preopened_cwd(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(ProductWorkerError::Bootstrap("cwd_custody_invalid"));
    }
    Ok(())
}

fn validate_dev_null(descriptor: RawFd) -> Result<()> {
    let metadata = descriptor_metadata(descriptor)?;
    if metadata.st_mode & libc::S_IFMT != libc::S_IFCHR
        || libc::major(metadata.st_rdev) != 1
        || libc::minor(metadata.st_rdev) != 3
    {
        return Err(ProductWorkerError::Bootstrap("dev_null_custody_invalid"));
    }
    Ok(())
}

fn read_bounded_descriptor(descriptor: RawFd, maximum: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut offset = 0_i64;
    let mut buffer = [0_u8; 4096];
    loop {
        // SAFETY: buffer is writable and pread does not mutate shared offset.
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
        if output.len().saturating_add(read) > maximum {
            return Err(ProductWorkerError::Bootstrap("bounded_file_oversized"));
        }
        output.extend_from_slice(&buffer[..read]);
        offset = offset
            .checked_add(read as i64)
            .ok_or(ProductWorkerError::Bootstrap("bounded_file_oversized"))?;
    }
    if output.is_empty() {
        return Err(ProductWorkerError::Bootstrap("bounded_file_empty"));
    }
    Ok(output)
}

fn descriptor_metadata(descriptor: RawFd) -> Result<libc::stat> {
    // SAFETY: zero is a valid initial representation; fstat initializes it.
    let mut metadata: libc::stat = unsafe { zeroed() };
    // SAFETY: metadata is writable and descriptor remains live.
    if unsafe { libc::fstat(descriptor, &mut metadata) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(metadata)
}

fn enter_retained_rootfs(rootfs: RawFd) -> Result<()> {
    // SAFETY: rootfs is a retained validated directory descriptor.
    if unsafe { libc::fchdir(rootfs) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let dot = c".";
    // SAFETY: cwd is the retained directory; chroot resolves only that fixed
    // dot and cannot be swapped through a pathname lookup.
    if unsafe { libc::chroot(dot.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let slash = c"/";
    // SAFETY: slash is the new chroot root.
    if unsafe { libc::chdir(slash.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn install_supervisor_resource_limits() -> Result<()> {
    set_limit(libc::RLIMIT_NOFILE as libc::c_int, WORKER_RLIMIT_NOFILE)?;
    set_limit(libc::RLIMIT_NPROC as libc::c_int, WORKER_RLIMIT_NPROC)?;
    set_limit(libc::RLIMIT_CORE as libc::c_int, WORKER_RLIMIT_CORE)?;
    Ok(())
}

fn set_and_verify_umask() -> Result<()> {
    // SAFETY: umask is process-local here because the worker is single-threaded.
    unsafe { libc::umask(0o007) };
    // A second set returns the currently installed mask; restore the same
    // value and fail if ambient/process state did not converge exactly.
    let observed = unsafe { libc::umask(0o007) };
    if observed != 0o007 {
        return Err(ProductWorkerError::Bootstrap("worker_umask_invalid"));
    }
    Ok(())
}

fn set_limit(resource: libc::c_int, value: u64) -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: value as _,
        rlim_max: value as _,
    };
    // SAFETY: limit is fully initialized for the exact resource.
    if unsafe { libc::setrlimit(resource as _, &limit) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn drop_worker_credentials(expected_parent: u32) -> Result<()> {
    // SAFETY: null group list with count zero clears all supplementary groups.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fixed product gid for all real/saved/effective identities.
    if unsafe { libc::setresgid(SHELL_WORKER_GID, SHELL_WORKER_GID, SHELL_WORKER_GID) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: fixed product uid for all real/saved/effective identities.
    if unsafe { libc::setresuid(SHELL_WORKER_UID, SHELL_WORKER_UID, SHELL_WORKER_UID) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    clear_capabilities()?;
    // SAFETY: prevents core dumps and ptrace relaxation after credential drop.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // set*id clears PDEATHSIG; reinstall and close the race by re-observing
    // the exact parent immediately afterwards.
    set_parent_death_signal()?;
    if parent_pid()? != expected_parent {
        return Err(ProductWorkerError::Bootstrap("broker_parent_changed"));
    }
    Ok(())
}

#[repr(C)]
struct CapabilityHeaderV1 {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityDataV1 {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn clear_capabilities() -> Result<()> {
    let mut header = CapabilityHeaderV1 {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapabilityDataV1 {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: header/data match Linux capability ABI v3 and request only a
    // reduction to the empty set.
    if unsafe {
        libc::syscall(
            libc::SYS_capset,
            std::ptr::from_mut(&mut header),
            data.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn install_no_new_privileges_and_seccomp() -> Result<()> {
    // SAFETY: fixed prctl request; all unused arguments are zero.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut filter = vec![
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        bpf_jump(BPF_JMP_JEQ_K, AUDIT_ARCH_NATIVE, 1, 0),
        bpf_statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
    ];
    // fork(2) is required for the one model child, but namespace creation is
    // never part of the first slice. Inspect clone's low flags word and deny
    // every CLONE_NEW* bit while preserving ordinary fork semantics.
    filter.push(bpf_jump(BPF_JMP_JEQ_K, libc::SYS_clone as u32, 0, 4));
    filter.push(bpf_statement(
        BPF_LD_W_ABS,
        SECCOMP_DATA_ARGUMENT_ZERO_OFFSET,
    ));
    filter.push(bpf_statement(BPF_ALU_AND_K, CLONE_NEW_NAMESPACE_FLAGS));
    filter.push(bpf_jump(BPF_JMP_JEQ_K, 0, 1, 0));
    filter.push(bpf_statement(
        BPF_RET_K,
        SECCOMP_RET_ERRNO | libc::EPERM as u32,
    ));
    filter.push(bpf_statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET));
    for syscall in denied_syscalls() {
        filter.push(bpf_jump(BPF_JMP_JEQ_K, syscall as u32, 0, 1));
        filter.push(bpf_statement(
            BPF_RET_K,
            SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }
    filter.push(bpf_statement(BPF_RET_K, SECCOMP_RET_ALLOW));
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len())
            .map_err(|_| ProductWorkerError::Bootstrap("seccomp_filter_oversized"))?,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: program points to a complete classic-BPF filter that remains
    // live for this synchronous prctl call.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            std::ptr::from_ref(&program),
            0,
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn denied_syscalls() -> [libc::c_long; 34] {
    [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_clone3,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        SYS_KEXEC_FILE_LOAD_NATIVE,
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setgroups,
        libc::SYS_capset,
        libc::SYS_setsid,
        libc::SYS_setpgid,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
}

const fn bpf_statement(code: u16, value: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k: value,
    }
}

const fn bpf_jump(code: u16, value: u32, yes: u8, no: u8) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: yes,
        jf: no,
        k: value,
    }
}

fn verify_isolation_state(expected_parent: u32) -> Result<()> {
    // SAFETY: getters have no side effects.
    let uid = unsafe { libc::getuid() };
    // SAFETY: getters have no side effects.
    let gid = unsafe { libc::getgid() };
    let mut group_probe = [0_u32; 1];
    // SAFETY: group_probe is valid but count zero requests only the count.
    let groups = unsafe { libc::getgroups(0, group_probe.as_mut_ptr()) };
    // SAFETY: fixed prctl getters; unused arguments are zero.
    let no_new_privileges = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    // SAFETY: fixed prctl getter.
    let seccomp = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if uid != SHELL_WORKER_UID
        || gid != SHELL_WORKER_GID
        || groups != 0
        || no_new_privileges != 1
        || seccomp != 2
        || parent_pid()? != expected_parent
    {
        return Err(ProductWorkerError::Bootstrap(
            "worker_isolation_observation_invalid",
        ));
    }
    Ok(())
}

fn set_parent_death_signal() -> Result<()> {
    // SAFETY: fixed signal and unused arguments.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn current_pid() -> Result<u32> {
    // SAFETY: getter has no side effects and Linux pids are positive.
    u32::try_from(unsafe { libc::getpid() })
        .map_err(|_| ProductWorkerError::Bootstrap("worker_pid_invalid"))
}

fn parent_pid() -> Result<u32> {
    // SAFETY: getter has no side effects.
    u32::try_from(unsafe { libc::getppid() })
        .map_err(|_| ProductWorkerError::Bootstrap("worker_parent_pid_invalid"))
}

fn read_selinux_domain(proc_self: RawFd) -> Result<String> {
    let value = read_proc_record(proc_self, "attr/current")?;
    let value = value.trim_end_matches(['\n', '\0']);
    if value.is_empty() || value.as_bytes().contains(&0) {
        return Err(ProductWorkerError::Bootstrap("selinux_domain_invalid"));
    }
    Ok(value.to_string())
}

fn process_starttime_ticks(proc_self: RawFd) -> Result<u64> {
    let record = read_proc_record(proc_self, "stat")?;
    let close = record
        .rfind(')')
        .ok_or(ProductWorkerError::Bootstrap("proc_stat_invalid"))?;
    let tail = record
        .get(close + 2..)
        .ok_or(ProductWorkerError::Bootstrap("proc_stat_invalid"))?;
    tail.split_ascii_whitespace()
        .nth(19)
        .ok_or(ProductWorkerError::Bootstrap("proc_stat_invalid"))?
        .parse()
        .map_err(|_| ProductWorkerError::Bootstrap("proc_stat_invalid"))
}

fn read_proc_record(proc_self: RawFd, name: &str) -> Result<String> {
    let name = CString::new(name)
        .map_err(|_| ProductWorkerError::Bootstrap("proc_record_name_invalid"))?;
    // SAFETY: name is one fixed relative basename and proc_self is retained.
    let descriptor = unsafe {
        libc::openat(
            proc_self,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_PROC_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_PROC_RECORD_BYTES {
        return Err(ProductWorkerError::Bootstrap("proc_record_invalid"));
    }
    String::from_utf8(bytes).map_err(|_| ProductWorkerError::Bootstrap("proc_record_not_utf8"))
}

fn validate_fixed_cgroup_membership(value: &str) -> Result<()> {
    let expected = "0::/system/trillionnium_shell_exec_worker";
    if value.trim_end() != expected {
        return Err(ProductWorkerError::Bootstrap(
            "fixed_cgroup_membership_missing",
        ));
    }
    Ok(())
}

fn c_strings(values: &[String]) -> Result<Vec<CString>> {
    values
        .iter()
        .map(|value| {
            CString::new(value.as_bytes())
                .map_err(|_| ProductWorkerError::Bootstrap("exec_string_contains_nul"))
        })
        .collect()
}

fn pipe_cloexec() -> Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: descriptors points to two writable ints initialized on success.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: pipe2 returned two distinct fresh descriptors.
    let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: ownership of the write descriptor is independent.
    let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    Ok((read, write))
}

fn set_nonblocking(descriptor: RawFd) -> Result<()> {
    // SAFETY: descriptor is live and fcntl does not retain it.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0
        // SAFETY: descriptor remains live and only O_NONBLOCK is added.
        || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn child_exec(
    cwd: RawFd,
    executable: RawFd,
    dev_null: RawFd,
    stdout: RawFd,
    stderr: RawFd,
    exec_error: RawFd,
    argv_pointers: &[*const libc::c_char],
    environment_pointers: &[*const libc::c_char],
    cpu_limit_seconds: u64,
) -> ! {
    // SAFETY: all calls in this post-fork branch are async-signal-safe.
    unsafe {
        if libc::fchdir(cwd) != 0
            || libc::dup2(dev_null, libc::STDIN_FILENO) < 0
            || libc::dup2(stdout, libc::STDOUT_FILENO) < 0
            || libc::dup2(stderr, libc::STDERR_FILENO) < 0
        {
            child_exec_error(exec_error);
        }
        let cpu_limit = libc::rlimit {
            rlim_cur: cpu_limit_seconds as _,
            rlim_max: cpu_limit_seconds as _,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
            child_exec_error(exec_error);
        }
        // Mark the complete non-stdio descriptor space close-on-exec in one
        // kernel operation. Lowering RLIMIT_NOFILE does not close an ambient
        // high descriptor inherited before the limit was installed, so a
        // bounded numeric loop is not a sufficient custody boundary. The
        // executable and error pipe remain usable until execveat; both close
        // atomically with every other non-stdio descriptor on success.
        if libc::syscall(
            libc::SYS_close_range,
            3_u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        ) != 0
        {
            child_exec_error(exec_error);
        }
        let empty = c"";
        libc::syscall(
            libc::SYS_execveat,
            executable,
            empty.as_ptr(),
            argv_pointers.as_ptr(),
            environment_pointers.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        child_exec_error(exec_error);
    }
}

unsafe fn child_exec_error(descriptor: RawFd) -> ! {
    let error = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
        .to_be_bytes();
    // SAFETY: descriptor is the private exec-error pipe and error is live.
    unsafe {
        libc::write(descriptor, error.as_ptr().cast(), error.len());
        libc::_exit(127);
    }
}

#[allow(clippy::too_many_arguments)]
fn supervise_child(
    child: libc::pid_t,
    request: &DirectEffectRequestV1,
    started: u64,
    control: RawFd,
    parent_pid: u32,
    stdout: RawFd,
    stderr: RawFd,
    exec_error: RawFd,
) -> Result<WorkerCompletionV1> {
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_closed = false;
    let mut stderr_closed = false;
    let mut exec_error_bytes = Vec::new();
    let mut exec_error_closed = false;
    let mut wait_status = None;
    let mut forced_reason = None;
    let mut killed = false;
    let mut cleanup_deadline = None;
    loop {
        drain_pipe(
            stdout,
            &mut stdout_bytes,
            &mut stdout_closed,
            request.arguments.stdout_limit_bytes,
            stderr_bytes.len(),
            request.arguments.total_output_limit_bytes,
            &mut forced_reason,
        );
        drain_pipe(
            stderr,
            &mut stderr_bytes,
            &mut stderr_closed,
            request.arguments.stderr_limit_bytes,
            stdout_bytes.len(),
            request.arguments.total_output_limit_bytes,
            &mut forced_reason,
        );
        drain_exec_error(exec_error, &mut exec_error_bytes, &mut exec_error_closed);
        if forced_reason.is_none() {
            forced_reason = observe_control_cancel(control, parent_pid, request)?;
            if forced_reason.is_none()
                && product_boottime_ms()? >= request.absolute_deadline_boottime_ms
            {
                forced_reason = Some(DirectEffectIndeterminateReasonV1::DeadlineAfterDispatch);
            }
        }
        if forced_reason.is_some() && !killed {
            // SAFETY: child is the exact owned process. Descendant containment
            // and complete cleanup are broker-enforced through the fixed
            // cgroup/pidfd protocol, never inferred from this best-effort kill.
            unsafe { libc::kill(child, libc::SIGKILL) };
            killed = true;
            cleanup_deadline = Some(product_boottime_ms()?.saturating_add(FORCED_CLEANUP_GRACE_MS));
        }
        if wait_status.is_none() {
            let mut status = 0;
            // SAFETY: status is writable and child is this worker's child.
            let observed = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
            if observed == child {
                wait_status = Some(status);
            } else if observed < 0 {
                forced_reason = Some(DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch);
            }
        }
        if wait_status.is_some() && forced_reason.is_none() && (!stdout_closed || !stderr_closed) {
            drain_pipe(
                stdout,
                &mut stdout_bytes,
                &mut stdout_closed,
                request.arguments.stdout_limit_bytes,
                stderr_bytes.len(),
                request.arguments.total_output_limit_bytes,
                &mut forced_reason,
            );
            drain_pipe(
                stderr,
                &mut stderr_bytes,
                &mut stderr_closed,
                request.arguments.stderr_limit_bytes,
                stdout_bytes.len(),
                request.arguments.total_output_limit_bytes,
                &mut forced_reason,
            );
        }
        if wait_status.is_some() && forced_reason.is_none() && (!stdout_closed || !stderr_closed) {
            forced_reason = Some(DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch);
        }
        if wait_status.is_some() && stdout_closed && stderr_closed && exec_error_closed {
            break;
        }
        let cleanup_expired = match cleanup_deadline {
            Some(deadline) => product_boottime_ms()? >= deadline,
            None => false,
        };
        if forced_reason.is_some() && cleanup_expired {
            break;
        }
        thread::sleep(EXECUTION_POLL);
    }
    let finished = product_boottime_ms()?.max(started);
    if let Some(reason) = forced_reason {
        return Ok(WorkerCompletionV1::Indeterminate {
            reason,
            observed_boottime_ms: finished,
        });
    }
    if !exec_error_bytes.is_empty() {
        return Ok(WorkerCompletionV1::Terminal(terminal_response(
            request,
            started,
            finished,
            DirectEffectTerminalKindV1::LaunchRejected,
            None,
            None,
            Some("execveat_denied".to_string()),
            b"",
            b"",
        )));
    }
    let status = wait_status.ok_or(ProductWorkerError::Bootstrap("wait_status_missing"))?;
    let (kind, exit_code, signal) = if libc::WIFEXITED(status) {
        (
            DirectEffectTerminalKindV1::Exited,
            Some(libc::WEXITSTATUS(status)),
            None,
        )
    } else if libc::WIFSIGNALED(status) {
        (
            DirectEffectTerminalKindV1::Signaled,
            None,
            Some(libc::WTERMSIG(status) as u32),
        )
    } else {
        return Ok(WorkerCompletionV1::Indeterminate {
            reason: DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch,
            observed_boottime_ms: finished,
        });
    };
    Ok(WorkerCompletionV1::Terminal(terminal_response(
        request,
        started,
        finished,
        kind,
        exit_code,
        signal,
        None,
        &stdout_bytes,
        &stderr_bytes,
    )))
}

fn observe_control_cancel(
    control: RawFd,
    parent_pid: u32,
    request: &DirectEffectRequestV1,
) -> Result<Option<DirectEffectIndeterminateReasonV1>> {
    let mut descriptor = libc::pollfd {
        fd: control,
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP,
        revents: 0,
    };
    // SAFETY: descriptor points to one initialized pollfd.
    let observed = unsafe { libc::poll(&mut descriptor, 1, 0) };
    if observed < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if observed == 0 {
        return Ok(None);
    }
    if descriptor.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLRDHUP) != 0 {
        return Ok(Some(
            DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch,
        ));
    }
    let frame: AuthenticatedFrameV1<BrokerWorkerFrameV1> = receive_frame(control)?;
    require_broker_credentials(&frame, parent_pid)?;
    let valid = frame.descriptors.is_empty()
        && matches!(
            frame.value,
            BrokerWorkerFrameV1::Cancel(WorkerCancelV1 {
                schema,
                protocol,
                request_sha256,
            }) if schema == WORKER_CANCEL_SCHEMA
                && protocol == WORKER_PROTOCOL
                && request_sha256 == request.request_sha256
        );
    Ok(Some(if valid {
        DirectEffectIndeterminateReasonV1::CancelledAfterDispatch
    } else {
        DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch
    }))
}

fn drain_pipe(
    descriptor: RawFd,
    output: &mut Vec<u8>,
    closed: &mut bool,
    stream_limit: u64,
    other_len: usize,
    total_limit: u64,
    forced_reason: &mut Option<DirectEffectIndeterminateReasonV1>,
) {
    if *closed || forced_reason.is_some() {
        return;
    }
    let mut buffer = [0_u8; PIPE_CHUNK_BYTES];
    loop {
        // SAFETY: buffer is writable and descriptor is a live pipe read end.
        let read = unsafe { libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read == 0 {
            *closed = true;
            return;
        }
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return;
            }
            *closed = true;
            *forced_reason = Some(DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch);
            return;
        }
        let incoming = &buffer[..read as usize];
        let stream_remaining = stream_limit.saturating_sub(output.len() as u64) as usize;
        let total_used = output.len().saturating_add(other_len) as u64;
        let total_remaining = total_limit.saturating_sub(total_used) as usize;
        let accepted = incoming.len().min(stream_remaining).min(total_remaining);
        output.extend_from_slice(&incoming[..accepted]);
        if accepted != incoming.len() {
            *forced_reason = Some(DirectEffectIndeterminateReasonV1::OutputLimitAfterDispatch);
            // Never keep draining a perpetually-readable source after the
            // first denied byte. Return to the supervisor immediately so it
            // can kill and enter the bounded cleanup path.
            return;
        }
    }
}

fn drain_exec_error(descriptor: RawFd, output: &mut Vec<u8>, closed: &mut bool) {
    if *closed {
        return;
    }
    let mut buffer = [0_u8; 4];
    loop {
        // SAFETY: buffer is writable and descriptor is a live pipe read end.
        let read = unsafe { libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read == 0 {
            *closed = true;
            return;
        }
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == std::io::ErrorKind::WouldBlock {
                return;
            }
            *closed = true;
            return;
        }
        output.extend_from_slice(&buffer[..read as usize]);
        if output.len() > 4 {
            *closed = true;
            return;
        }
    }
}

fn product_boottime_ms() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is writable storage for CLOCK_BOOTTIME.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| ProductWorkerError::Bootstrap("boottime_invalid"))?;
    let nanos = u64::try_from(value.tv_nsec)
        .map_err(|_| ProductWorkerError::Bootstrap("boottime_invalid"))?;
    Ok(seconds
        .saturating_mul(1000)
        .saturating_add(nanos / 1_000_000))
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

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::io::Read as _;
    use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _};

    use tempfile::tempfile;

    use super::*;

    #[test]
    fn adopted_fixed_descriptor_restores_cloexec() {
        let file = tempfile().unwrap();
        let descriptor = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 80) };
        assert!(descriptor >= 80);
        let adopted = adopt_fixed_descriptor(descriptor).unwrap();
        let flags = unsafe { libc::fcntl(adopted.as_raw_fd(), libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn seccomp_denies_async_rings_clone3_and_every_namespace_clone_flag() {
        let denied = denied_syscalls();
        for syscall in [
            libc::SYS_clone3,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert!(denied.contains(&syscall));
        }
        let expected_namespace_flags = libc::CLONE_NEWCGROUP
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWNS
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWTIME
            | libc::CLONE_NEWUSER
            | libc::CLONE_NEWUTS;
        assert_eq!(CLONE_NEW_NAMESPACE_FLAGS, expected_namespace_flags as u32);
        assert!(!denied.contains(&libc::SYS_clone));
    }

    #[test]
    fn model_exec_does_not_inherit_control_or_custody_descriptors() {
        let cwd = OpenOptions::new().read(true).open("/").unwrap();
        let executable = OpenOptions::new().read(true).open("/bin/ls").unwrap();
        let dev_null = OpenOptions::new().read(true).open("/dev/null").unwrap();
        let (stdout_read, stdout_write) = pipe_cloexec().unwrap();
        let (_stderr_read, stderr_write) = pipe_cloexec().unwrap();
        let (error_read, error_write) = pipe_cloexec().unwrap();
        let secret = tempfile().unwrap();
        // Allocate an unused descriptor instead of overwriting process fd 20;
        // Rust unit tests share a process and may hold unrelated descriptors
        // concurrently.
        let secret_descriptor = unsafe { libc::fcntl(secret.as_raw_fd(), libc::F_DUPFD, 20) };
        assert!(secret_descriptor >= 20);

        let argv = c_strings(&[
            "/bin/ls".to_string(),
            "-1".to_string(),
            "/proc/self/fd".to_string(),
        ])
        .unwrap();
        let environment = c_strings(&["PATH=/usr/bin:/bin".to_string()]).unwrap();
        let argv_pointers = argv
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>();
        let environment_pointers = environment
            .iter()
            .map(|value| value.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect::<Vec<_>>();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            child_exec(
                cwd.as_raw_fd(),
                executable.as_raw_fd(),
                dev_null.as_raw_fd(),
                stdout_write.as_raw_fd(),
                stderr_write.as_raw_fd(),
                error_write.as_raw_fd(),
                &argv_pointers,
                &environment_pointers,
                2,
            );
        }
        drop(stdout_write);
        drop(stderr_write);
        drop(error_write);
        unsafe { libc::close(secret_descriptor) };
        let mut output = String::new();
        let mut stdout = unsafe { File::from_raw_fd(stdout_read.into_raw_fd()) };
        stdout.read_to_string(&mut output).unwrap();
        let mut error = Vec::new();
        let mut error_file = unsafe { File::from_raw_fd(error_read.into_raw_fd()) };
        error_file.read_to_end(&mut error).unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0, "exec error bytes: {error:?}");
        let descriptors = output
            .lines()
            .map(|line| line.parse::<i32>().unwrap())
            .collect::<Vec<_>>();
        assert!(descriptors.contains(&0));
        assert!(descriptors.contains(&1));
        assert!(descriptors.contains(&2));
        assert!(!descriptors.contains(&secret_descriptor));
        assert!(descriptors.iter().all(|descriptor| *descriptor <= 3));
    }
}
