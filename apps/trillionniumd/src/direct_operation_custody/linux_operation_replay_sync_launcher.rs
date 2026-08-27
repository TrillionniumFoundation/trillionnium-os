//! Concrete Linux syscall backend for the source-only replay-sync launcher.
//!
//! The backend is deliberately reachable only through the uninhabited product
//! authority in the sibling type-state module.  It does not add capabilities
//! to `trillionniumd`: the fixed cgroup must already be writable by the daemon
//! identity, the child traces itself, and every unavailable kernel/SELinux
//! primitive fails closed before a command is released.

use std::collections::BTreeSet;
use std::ffi::{CString, c_char, c_int, c_uint, c_ulong, c_void};
use std::fs;
use std::io;
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail};
use sha2::{Digest as _, Sha256};
use trillionnium_os_types::sha256_bytes;

use super::DirectOperationExecutionAuthorityEvidenceV1;
use super::operation_replay_sync_launcher::{
    ExactHelperConfirmation, MAX_REPLAY_SYNC_PAYLOAD_BYTES, MeasuredOperationReplaySyncExecutable,
    OperationReplaySyncLaunchOps, OperationReplaySyncLaunchSpec,
    OperationReplaySyncProductAdmission, VerifiedDaemonCapabilityCustody,
    VerifiedOperationReplaySyncExec, VerifiedOperationReplaySyncLauncherAuthority,
    decode_ack_confirmation_response_frame,
};

pub(super) const SOURCE_STATUS: &str =
    "source_only_concrete_clone3_cgroup_pidfd_replay_sync_backend_unwired_v1";

const OPENAT2_RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const OPENAT2_RESOLVE_NO_SYMLINKS: u64 = 0x04;
const CLOSE_RANGE_UNSHARE: c_uint = 1 << 1;
const CLONE_PIDFD_FLAG: u64 = 0x0000_1000;
const CLONE_INTO_CGROUP_FLAG: u64 = 0x0000_0002_0000_0000;
const PTRACE_EVENT_EXEC_VALUE: c_int = 4;
const PTRACE_O_TRACEEXEC_VALUE: c_ulong = 1 << 4;
const PTRACE_O_EXITKILL_VALUE: c_ulong = 1 << 20;
const SECCOMP_MODE_FILTER_VALUE: c_ulong = 2;
const SECCOMP_RET_ALLOW_VALUE: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO_VALUE: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS_VALUE: u32 = 0x8000_0000;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
#[cfg(target_arch = "aarch64")]
const SECCOMP_AUDIT_ARCH: u32 = 0xc000_00b7;
#[cfg(target_arch = "x86_64")]
const SECCOMP_AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
compile_error!("replay-sync launcher seccomp supports only aarch64 and x86_64");
const COMMAND_FD: RawFd = 3;
const RESPONSE_FD: RawFd = 4;
const EXECUTABLE_FD: RawFd = 5;
const RESULT_TIMEOUT: Duration = Duration::from_secs(10);
const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const MAX_EXECUTABLE_BYTES: usize = 64 * 1024 * 1024;
const FS_IOC_MEASURE_VERITY: c_ulong = 0xc004_6686;
const FS_VERITY_HASH_ALG_SHA256: u16 = 1;

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
    path: String,
    sha256: String,
    identity_sha256: String,
}

pub(super) struct ConcreteLinuxOperationReplaySyncLaunchOps {
    measured: Option<RetainedExecutable>,
    admission: ConcreteReplaySyncAdmission,
}

enum ConcreteReplaySyncAdmission {
    Product(Box<[OperationReplaySyncProductAdmission; 2]>),
    #[cfg(feature = "p0-launch-package-device-conformance")]
    P0UserdebugConformance,
}

impl ConcreteLinuxOperationReplaySyncLaunchOps {
    pub(super) fn from_verified_product_authority(
        authority: VerifiedOperationReplaySyncLauncherAuthority,
    ) -> Result<Self> {
        Ok(Self {
            measured: None,
            admission: ConcreteReplaySyncAdmission::Product(Box::new(authority.into_admissions()?)),
        })
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(super) fn from_p0_userdebug_conformance() -> Result<Self> {
        if option_env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT") != Some("userdebug") {
            bail!("direct_operation_replay_sync_p0_userdebug_compiled_variant_denied");
        }
        Ok(Self {
            measured: None,
            admission: ConcreteReplaySyncAdmission::P0UserdebugConformance,
        })
    }

    fn admission(
        &self,
        adapter: trillionnium_os_types::direct_operation::DirectOperationAdapter,
    ) -> Result<&OperationReplaySyncProductAdmission> {
        match &self.admission {
            ConcreteReplaySyncAdmission::Product(admissions) => admissions
                .iter()
                .find(|admission| admission.adapter == adapter)
                .context("direct_operation_replay_sync_product_admission_absent"),
            #[cfg(feature = "p0-launch-package-device-conformance")]
            ConcreteReplaySyncAdmission::P0UserdebugConformance => {
                bail!("direct_operation_replay_sync_product_admission_absent")
            }
        }
    }
}

pub(super) struct ConcreteLinuxOperationReplaySyncChild {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    command_write: Option<OwnedFd>,
    response_read: OwnedFd,
    cgroup_fd: OwnedFd,
    cgroup_identity_sha256: String,
    pre_exec_start_time_ticks: u64,
    expected_executable_sha256: String,
    expected_executable_identity_sha256: String,
    expected_executable_path: String,
    expected_uid: u32,
    expected_gid: u32,
    expected_selinux_domain: String,
    expected_cgroup_path: String,
    command_frame: Vec<u8>,
    exec_stop_observed: bool,
    hardening_stop_observed: bool,
    reaped: bool,
}

impl Drop for ConcreteLinuxOperationReplaySyncChild {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = kill_pidfd_and_reap(self.pidfd.as_raw_fd(), self.pid);
            self.reaped = true;
        }
    }
}

impl OperationReplaySyncLaunchOps for ConcreteLinuxOperationReplaySyncLaunchOps {
    type Child = ConcreteLinuxOperationReplaySyncChild;

    fn verify_daemon_capabilities(&mut self) -> Result<VerifiedDaemonCapabilityCustody> {
        let status = fs::read_to_string("/proc/self/status")
            .context("direct_operation_replay_sync_self_status_unavailable")?;
        Ok(VerifiedDaemonCapabilityCustody {
            effective: parse_status_hex(&status, "CapEff:")?,
            permitted: parse_status_hex(&status, "CapPrm:")?,
            bounding: parse_status_hex(&status, "CapBnd:")?,
            inheritable: parse_status_hex(&status, "CapInh:")?,
            ambient: parse_status_hex(&status, "CapAmb:")?,
            securebits: u32::try_from(unsafe { libc::prctl(libc::PR_GET_SECUREBITS) })
                .map_err(|_| anyhow!("direct_operation_replay_sync_securebits_unavailable"))?,
        })
    }

    fn measure_fixed_executable(
        &mut self,
        spec: &OperationReplaySyncLaunchSpec,
    ) -> Result<MeasuredOperationReplaySyncExecutable> {
        if self.measured.is_some() {
            bail!("direct_operation_replay_sync_measurement_already_retained");
        }
        let path = CString::new(spec.executable_path)
            .context("direct_operation_replay_sync_executable_path_contains_nul")?;
        let fd = open_exact(&path, libc::O_RDONLY | libc::O_NOFOLLOW)?;
        let metadata = executable_metadata(fd.as_raw_fd())?;
        if metadata.size < 64
            || metadata.size > MAX_EXECUTABLE_BYTES as u64
            || !metadata.read_only_mount
            || !metadata.regular_single_link
            || !metadata.root_owned_nonwritable
            || !metadata.elf_image
            || metadata.mode & (libc::S_ISUID | libc::S_ISGID) != 0
        {
            bail!("direct_operation_replay_sync_executable_inode_denied");
        }
        let sha256 = sha256_fd(fd.as_raw_fd())?;
        let (authority_evidence, fsverity_digest_sha256, fsverity_measurement_matched) =
            match &self.admission {
                ConcreteReplaySyncAdmission::Product(_) => {
                    let admission = self.admission(spec.adapter)?.clone();
                    if admission.executable_sha256 != sha256
                        || !valid_nonzero_digest(&admission.product_descriptor_sha256)
                        || !valid_nonzero_digest(&admission.signed_product_measurement_sha256)
                        || !valid_nonzero_digest(&admission.avb_partition_digest_sha256)
                        || !valid_nonzero_digest(&admission.fsverity_digest_sha256)
                    {
                        bail!("direct_operation_replay_sync_product_admission_denied");
                    }
                    let measured_fsverity = measure_fsverity_sha256(fd.as_raw_fd())?;
                    if measured_fsverity != admission.fsverity_digest_sha256 {
                        bail!("direct_operation_replay_sync_fsverity_digest_drift");
                    }
                    (
                        DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
                            product_descriptor_sha256: admission.product_descriptor_sha256,
                            signed_product_measurement_sha256: admission
                                .signed_product_measurement_sha256,
                            avb_partition_digest_sha256: admission.avb_partition_digest_sha256,
                        },
                        Some(admission.fsverity_digest_sha256),
                        true,
                    )
                }
                #[cfg(feature = "p0-launch-package-device-conformance")]
                ConcreteReplaySyncAdmission::P0UserdebugConformance => {
                    let DirectOperationExecutionAuthorityEvidenceV1::P0UserdebugConformance {
                        build_variant,
                        replay_sync_executable_sha256,
                        ..
                    } = &spec.authority_evidence
                    else {
                        bail!("direct_operation_replay_sync_p0_authority_substitution_denied");
                    };
                    if build_variant != "userdebug" || replay_sync_executable_sha256 != &sha256 {
                        bail!("direct_operation_replay_sync_p0_executable_measurement_denied");
                    }
                    (spec.authority_evidence.clone(), None, false)
                }
            };
        let elf = verify_static_aarch64_elf64(fd.as_raw_fd(), metadata.size)?;
        let file_capabilities_absent = verify_file_capabilities_absent(fd.as_raw_fd())?;
        if executable_metadata(fd.as_raw_fd())? != metadata {
            bail!("direct_operation_replay_sync_executable_inode_changed_during_measurement");
        }
        let identity_sha256 = executable_identity_digest(&metadata, &sha256);
        let result = MeasuredOperationReplaySyncExecutable {
            fixed_path: spec.executable_path.to_string(),
            executable_sha256: sha256.clone(),
            executable_file_identity_sha256: identity_sha256.clone(),
            same_fd_for_execveat: true,
            read_only_mount: metadata.read_only_mount,
            regular_single_link: metadata.regular_single_link,
            root_owned_nonwritable: metadata.root_owned_nonwritable,
            elf_image: metadata.elf_image,
            static_aarch64_elf64: elf.static_aarch64_elf64,
            pt_interp_absent: elf.pt_interp_absent,
            pt_dynamic_absent: elf.pt_dynamic_absent,
            wx_segment_absent: elf.wx_segment_absent,
            executable_stack_absent: elf.executable_stack_absent,
            setid_bits_absent: metadata.mode & (libc::S_ISUID | libc::S_ISGID) == 0,
            file_capabilities_absent,
            expected_hash_authority_matched: true,
            fsverity_measurement_matched,
            authority_evidence,
            fsverity_digest_sha256,
        };
        self.measured = Some(RetainedExecutable {
            fd,
            path: spec.executable_path.to_string(),
            sha256,
            identity_sha256,
        });
        Ok(result)
    }

    fn spawn_stopped(
        &mut self,
        spec: &OperationReplaySyncLaunchSpec,
        executable: &MeasuredOperationReplaySyncExecutable,
    ) -> Result<Self::Child> {
        let retained = self
            .measured
            .take()
            .context("direct_operation_replay_sync_measurement_not_retained")?;
        if retained.path != executable.fixed_path
            || retained.sha256 != executable.executable_sha256
            || retained.identity_sha256 != executable.executable_file_identity_sha256
            || spec.command_frame.is_empty()
            || spec.command_frame.len() > 16 + MAX_REPLAY_SYNC_PAYLOAD_BYTES
            || sha256_bytes(&spec.command_frame) != spec.command_frame_sha256
        {
            bail!("direct_operation_replay_sync_spawn_input_drift");
        }

        let cgroup_path = fixed_cgroup_filesystem_path(&spec.unified_cgroup_path)?;
        let cgroup_path = CString::new(cgroup_path.as_os_str().as_encoded_bytes())
            .context("direct_operation_replay_sync_cgroup_path_contains_nul")?;
        let cgroup_fd = open_exact(
            &cgroup_path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )?;
        let cgroup_identity_sha256 =
            verify_cgroup_fd(cgroup_fd.as_raw_fd(), &spec.unified_cgroup_path)?;
        let (command_read, command_write) = pipe_cloexec()?;
        ensure_pipe_capacity(command_write.as_raw_fd(), spec.command_frame.len())?;
        let (response_read, response_write) = pipe_cloexec()?;
        let executable_path = CString::new(spec.executable_path)
            .context("direct_operation_replay_sync_executable_path_contains_nul")?;
        let mut pidfd_raw: c_int = -1;
        let mut clone_args = CloneArgs {
            flags: CLONE_PIDFD_FLAG | CLONE_INTO_CGROUP_FLAG,
            pidfd: (&mut pidfd_raw as *mut c_int) as u64,
            exit_signal: libc::SIGCHLD as u64,
            cgroup: cgroup_fd.as_raw_fd() as u64,
            ..CloneArgs::default()
        };
        // SAFETY: clone_args is the published Linux clone3 layout; the child
        // immediately enters the async-signal-safe ceremony below.
        let result = unsafe {
            libc::syscall(
                libc::SYS_clone3,
                &mut clone_args as *mut CloneArgs,
                mem::size_of::<CloneArgs>(),
            )
        };
        if result == 0 {
            // SAFETY: this is the post-clone child and the function never
            // returns or allocates.
            unsafe {
                child_exec(
                    retained.fd.as_raw_fd(),
                    command_read.as_raw_fd(),
                    response_write.as_raw_fd(),
                    spec.uid,
                    spec.gid,
                    executable_path.as_ptr(),
                )
            }
        }
        if result < 0 {
            bail!(
                "direct_operation_replay_sync_clone3_into_cgroup_failed: {}",
                io::Error::last_os_error()
            );
        }
        let pid = match c_int::try_from(result) {
            Ok(pid) => pid,
            Err(error) => {
                kill_and_reap_raw_clone_result(result)
                    .context("direct_operation_replay_sync_pid_overflow_cleanup_ambiguous")?;
                bail!("direct_operation_replay_sync_child_pid_overflow: {error}");
            }
        };
        if pidfd_raw < 0 {
            // A kernel violating CLONE_PIDFD's atomic return contract still
            // leaves an exact freshly cloned child PID. Kill and reap it
            // before reporting the impossible state; never leak a stopped
            // helper merely because pidfd custody was unavailable.
            // SAFETY: pid is the positive result of this exact clone3 call.
            let kill_result = unsafe { libc::kill(pid, libc::SIGKILL) };
            if kill_result != 0 || wait_for_exit(pid).is_err() {
                bail!("direct_operation_replay_sync_missing_pidfd_cleanup_ambiguous");
            }
            bail!("direct_operation_replay_sync_clone3_pidfd_absent");
        }
        drop(command_read);
        drop(response_write);
        // SAFETY: clone3 returned exactly one pidfd in pidfd_raw.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
        let setup = (|| -> io::Result<u64> {
            wait_for_stop(pid, libc::SIGSTOP, Instant::now() + RESULT_TIMEOUT)?;
            let start_time = read_proc_start_time(pid)?;
            ptrace_setoptions(pid, PTRACE_O_TRACEEXEC_VALUE | PTRACE_O_EXITKILL_VALUE)?;
            Ok(start_time)
        })();
        let pre_exec_start_time_ticks = match setup {
            Ok(value) => value,
            Err(error) => {
                kill_pidfd_and_reap(pidfd.as_raw_fd(), pid)
                    .context("direct_operation_replay_sync_spawn_cleanup_ambiguous")?;
                return Err(error).context("direct_operation_replay_sync_pre_exec_stop_denied");
            }
        };
        Ok(ConcreteLinuxOperationReplaySyncChild {
            pid,
            pidfd,
            command_write: Some(command_write),
            response_read,
            cgroup_fd,
            cgroup_identity_sha256,
            pre_exec_start_time_ticks,
            expected_executable_sha256: retained.sha256,
            expected_executable_identity_sha256: retained.identity_sha256,
            expected_executable_path: spec.executable_path.to_string(),
            expected_uid: spec.uid,
            expected_gid: spec.gid,
            expected_selinux_domain: spec.selinux_domain.to_string(),
            expected_cgroup_path: spec.unified_cgroup_path.clone(),
            command_frame: spec.command_frame.clone(),
            exec_stop_observed: false,
            hardening_stop_observed: false,
            reaped: false,
        })
    }

    fn verify_post_exec(
        &mut self,
        child: &mut Self::Child,
    ) -> Result<VerifiedOperationReplaySyncExec> {
        ptrace_continue(child.pid)?;
        wait_for_exec_stop(child.pid, Instant::now() + RESULT_TIMEOUT)?;
        child.exec_stop_observed = true;
        ptrace_continue(child.pid)?;
        wait_for_self_hardening_stop(child.pid, Instant::now() + RESULT_TIMEOUT)?;
        child.hardening_stop_observed = true;

        let first_start_time = read_proc_start_time(child.pid)?;
        let process = inspect_process(child.pid, &child.expected_executable_path)?;
        let second_start_time = read_proc_start_time(child.pid)?;
        let cgroup_identity_now =
            verify_cgroup_fd(child.cgroup_fd.as_raw_fd(), &child.expected_cgroup_path)?;
        if first_start_time != child.pre_exec_start_time_ticks
            || second_start_time != first_start_time
            || process.uid != child.expected_uid
            || process.gid != child.expected_gid
            || process.selinux_domain != child.expected_selinux_domain
            || process.unified_cgroup_path != child.expected_cgroup_path
            || process.executable_path != child.expected_executable_path
            || process.executable_sha256 != child.expected_executable_sha256
            || process.executable_identity_sha256 != child.expected_executable_identity_sha256
            || cgroup_identity_now != child.cgroup_identity_sha256
            || !process.fd3_read_pipe_only
            || !process.fd4_write_pipe_only
            || !process.other_fds_closed
            || !process.environment_empty
            || !process.arguments_empty
            || !process.no_new_privs
            || !process.capabilities_empty
            || !process.descendants_forbidden
            || !process.tracer_parent_verified
        {
            bail!("direct_operation_replay_sync_post_exec_kernel_state_denied");
        }
        Ok(VerifiedOperationReplaySyncExec {
            pid: child.pid as u32,
            start_time_ticks: first_start_time,
            pidfd_identity_sha256: pidfd_identity(
                child.pidfd.as_raw_fd(),
                child.pid,
                first_start_time,
            )?,
            cgroup_identity_sha256: cgroup_identity_now,
            pidfd_returned_by_clone3: true,
            clone_into_fixed_cgroup: true,
            ptrace_exec_stop_observed: child.exec_stop_observed && child.hardening_stop_observed,
            start_time_stable_after_exec: true,
            uid: process.uid,
            gid: process.gid,
            selinux_domain: process.selinux_domain,
            unified_cgroup_path: process.unified_cgroup_path,
            executable_path: process.executable_path,
            executable_sha256: process.executable_sha256,
            command_fd3_only: process.fd3_read_pipe_only,
            response_fd4_only: process.fd4_write_pipe_only,
            other_fds_closed: process.other_fds_closed,
            environment_empty: process.environment_empty,
            arguments_empty: process.arguments_empty,
            pdeathsig_sigkill: true,
            no_new_privs: process.no_new_privs,
            dumpable_disabled: true,
            capabilities_empty: process.capabilities_empty,
            descendants_forbidden: process.descendants_forbidden,
            tracer_parent_verified: process.tracer_parent_verified,
        })
    }

    fn release_command(&mut self, child: &mut Self::Child) -> Result<()> {
        if !child.exec_stop_observed || !child.hardening_stop_observed {
            bail!("direct_operation_replay_sync_command_before_verification_denied");
        }
        let command_write = child
            .command_write
            .take()
            .context("direct_operation_replay_sync_command_pipe_already_consumed")?;
        write_all_fd(command_write.as_raw_fd(), &child.command_frame)?;
        drop(command_write);
        Ok(())
    }

    fn resume(&mut self, child: &mut Self::Child) -> Result<()> {
        if !child.exec_stop_observed
            || !child.hardening_stop_observed
            || child.command_write.is_some()
        {
            bail!("direct_operation_replay_sync_resume_before_verification_denied");
        }
        ptrace_detach(child.pid)?;
        Ok(())
    }

    fn collect_exact_confirmation(
        &mut self,
        child: &mut Self::Child,
        _spec: &OperationReplaySyncLaunchSpec,
    ) -> Result<ExactHelperConfirmation> {
        let frame = read_bounded_to_exact_eof(
            child.response_read.as_raw_fd(),
            16 + MAX_REPLAY_SYNC_PAYLOAD_BYTES,
            Instant::now() + RESULT_TIMEOUT,
        )?;
        let confirmation = decode_ack_confirmation_response_frame(&frame)
            .map_err(|error| anyhow!(error.to_string()))?;
        Ok(ExactHelperConfirmation {
            confirmation,
            response_frame_sha256: sha256_bytes(&frame),
            exact_eof: true,
        })
    }

    fn verify_successful_exit_and_reap(&mut self, child: &mut Self::Child) -> Result<()> {
        poll_until(
            child.pidfd.as_raw_fd(),
            libc::POLLIN,
            Instant::now() + RESULT_TIMEOUT,
        )?;
        let status = waitpid_exact(child.pid)?;
        child.reaped = true;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            bail!("direct_operation_replay_sync_helper_exit_denied");
        }
        Ok(())
    }

    fn kill_and_reap(&mut self, mut child: Self::Child) -> Result<()> {
        if child.reaped {
            return Ok(());
        }
        kill_pidfd_and_reap(child.pidfd.as_raw_fd(), child.pid)
            .context("direct_operation_replay_sync_kill_reap_ambiguous")?;
        child.reaped = true;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableMetadata {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    read_only_mount: bool,
    regular_single_link: bool,
    root_owned_nonwritable: bool,
    elf_image: bool,
}

struct ProcessInspection {
    uid: u32,
    gid: u32,
    selinux_domain: String,
    unified_cgroup_path: String,
    executable_path: String,
    executable_sha256: String,
    executable_identity_sha256: String,
    fd3_read_pipe_only: bool,
    fd4_write_pipe_only: bool,
    other_fds_closed: bool,
    environment_empty: bool,
    arguments_empty: bool,
    no_new_privs: bool,
    capabilities_empty: bool,
    descendants_forbidden: bool,
    tracer_parent_verified: bool,
}

fn open_exact(path: &CString, flags: c_int) -> io::Result<OwnedFd> {
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: OPENAT2_RESOLVE_NO_MAGICLINKS | OPENAT2_RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: path and the exact open_how layout remain live for the syscall.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &raw const how,
            mem::size_of::<OpenHow>(),
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: raw is one successful descriptor transferred once.
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

fn executable_metadata(fd: RawFd) -> io::Result<ExecutableMetadata> {
    let mut status = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: status is valid output storage.
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized status.
    let status = unsafe { status.assume_init() };
    let mut filesystem = MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: filesystem is valid output storage.
    if unsafe { libc::fstatvfs(fd, filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatvfs initialized filesystem.
    let filesystem = unsafe { filesystem.assume_init() };
    let mut magic = [0_u8; 4];
    read_exact_at_start(fd, &mut magic)?;
    let regular_single_link =
        status.st_mode & libc::S_IFMT == libc::S_IFREG && status.st_nlink == 1;
    Ok(ExecutableMetadata {
        dev: status.st_dev,
        ino: status.st_ino,
        mode: status.st_mode,
        uid: status.st_uid,
        gid: status.st_gid,
        nlink: normalize_link_count(status.st_nlink),
        size: u64::try_from(status.st_size)
            .map_err(|_| io::Error::other("negative executable size"))?,
        read_only_mount: filesystem.f_flag as c_ulong & libc::ST_RDONLY as c_ulong != 0,
        regular_single_link,
        root_owned_nonwritable: status.st_uid == 0 && status.st_mode & 0o022 == 0,
        elf_image: magic == [0x7f, b'E', b'L', b'F'],
    })
}

fn normalize_link_count<T>(value: T) -> u64
where
    u64: From<T>,
{
    u64::from(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StaticElfValidation {
    static_aarch64_elf64: bool,
    pt_interp_absent: bool,
    pt_dynamic_absent: bool,
    wx_segment_absent: bool,
    executable_stack_absent: bool,
}

#[derive(Clone, Copy)]
struct LoadPageMapping {
    flags: u32,
    first_page: u64,
    end_page: u64,
}

fn verify_static_aarch64_elf64(fd: RawFd, size: u64) -> Result<StaticElfValidation> {
    let size =
        usize::try_from(size).context("direct_operation_replay_sync_executable_size_overflow")?;
    if !(64..=MAX_EXECUTABLE_BYTES).contains(&size) {
        bail!("direct_operation_replay_sync_executable_size_denied");
    }
    let mut bytes = vec![0_u8; size];
    pread_exact(fd, &mut bytes, 0)?;
    // This exact kernel performs the subsequent execveat, so its base-page
    // granularity is the authoritative boundary for load-map W^X checks.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page_size = u64::try_from(page_size)
        .context("direct_operation_replay_sync_execution_page_size_unavailable")?;
    verify_static_aarch64_elf64_bytes(&bytes, page_size)
}

fn verify_static_aarch64_elf64_bytes(bytes: &[u8], page_size: u64) -> Result<StaticElfValidation> {
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const PT_GNU_STACK: u32 = 0x6474_e551;
    const PF_X: u32 = 1;
    const PF_W: u32 = 2;

    if page_size < 4096 || !page_size.is_power_of_two() {
        bail!("direct_operation_replay_sync_execution_page_size_denied");
    }
    if bytes.len() < 64
        || bytes[0..4] != [0x7f, b'E', b'L', b'F']
        || bytes[4] != 2
        || bytes[5] != 1
        || bytes[6] != 1
        || u16::from_le_bytes(bytes[16..18].try_into().expect("ELF e_type")) != 2
        || u16::from_le_bytes(bytes[18..20].try_into().expect("ELF e_machine")) != 183
        || u32::from_le_bytes(bytes[20..24].try_into().expect("ELF e_version")) != 1
        || u16::from_le_bytes(bytes[52..54].try_into().expect("ELF e_ehsize")) != 64
        || u16::from_le_bytes(bytes[54..56].try_into().expect("ELF e_phentsize")) != 56
    {
        bail!("direct_operation_replay_sync_static_aarch64_elf_header_denied");
    }
    let entry = u64::from_le_bytes(bytes[24..32].try_into().expect("ELF e_entry"));
    let phoff = usize::try_from(u64::from_le_bytes(
        bytes[32..40].try_into().expect("ELF e_phoff"),
    ))
    .context("direct_operation_replay_sync_program_header_offset_overflow")?;
    let phnum = usize::from(u16::from_le_bytes(
        bytes[56..58].try_into().expect("ELF e_phnum"),
    ));
    let phbytes = phnum
        .checked_mul(56)
        .and_then(|length| phoff.checked_add(length))
        .context("direct_operation_replay_sync_program_header_overflow")?;
    if entry == 0
        || phoff < 64
        || !phoff.is_multiple_of(8)
        || phnum == 0
        || phnum > 128
        || phbytes > bytes.len()
    {
        bail!("direct_operation_replay_sync_program_header_boundary_denied");
    }
    let mut executable_entry_segment = false;
    let mut saw_interp = false;
    let mut saw_dynamic = false;
    let mut saw_wx = false;
    let mut gnu_stack_count = 0_usize;
    let mut executable_stack = false;
    let mut load_mappings = Vec::new();
    for index in 0..phnum {
        let start = phoff + index * 56;
        let ph = &bytes[start..start + 56];
        let kind = u32::from_le_bytes(ph[0..4].try_into().expect("ELF p_type"));
        let flags = u32::from_le_bytes(ph[4..8].try_into().expect("ELF p_flags"));
        let offset = u64::from_le_bytes(ph[8..16].try_into().expect("ELF p_offset"));
        let virtual_address = u64::from_le_bytes(ph[16..24].try_into().expect("ELF p_vaddr"));
        let file_size = u64::from_le_bytes(ph[32..40].try_into().expect("ELF p_filesz"));
        let memory_size = u64::from_le_bytes(ph[40..48].try_into().expect("ELF p_memsz"));
        let alignment = u64::from_le_bytes(ph[48..56].try_into().expect("ELF p_align"));
        let file_end = offset
            .checked_add(file_size)
            .context("direct_operation_replay_sync_segment_file_overflow")?;
        if file_end > bytes.len() as u64 || file_size > memory_size {
            bail!("direct_operation_replay_sync_segment_boundary_denied");
        }
        match kind {
            PT_LOAD => {
                if (alignment > 1
                    && (!alignment.is_power_of_two()
                        || offset % alignment != virtual_address % alignment))
                    || offset % page_size != virtual_address % page_size
                {
                    bail!("direct_operation_replay_sync_load_alignment_denied");
                }
                let memory_end = virtual_address
                    .checked_add(memory_size)
                    .context("direct_operation_replay_sync_segment_memory_overflow")?;
                if flags & (PF_W | PF_X) == (PF_W | PF_X) {
                    saw_wx = true;
                }
                if memory_size != 0 {
                    let last_page = (memory_end - 1) / page_size;
                    load_mappings.push(LoadPageMapping {
                        flags,
                        first_page: virtual_address / page_size,
                        end_page: last_page
                            .checked_add(1)
                            .context("direct_operation_replay_sync_segment_page_overflow")?,
                    });
                }
                if flags & PF_X != 0 && entry >= virtual_address && entry < memory_end {
                    executable_entry_segment = true;
                }
            }
            PT_DYNAMIC => saw_dynamic = true,
            PT_INTERP => saw_interp = true,
            PT_GNU_STACK => {
                gnu_stack_count += 1;
                executable_stack |= flags & PF_X != 0;
            }
            _ => {}
        }
    }
    for (index, left) in load_mappings.iter().enumerate() {
        for right in load_mappings.iter().skip(index + 1) {
            let pages_overlap =
                left.first_page < right.end_page && right.first_page < left.end_page;
            let permissions_combine_wx =
                (left.flags | right.flags) & (PF_W | PF_X) == (PF_W | PF_X);
            if pages_overlap && permissions_combine_wx {
                bail!("direct_operation_replay_sync_load_page_wx_overlap_denied");
            }
        }
    }
    if saw_interp
        || saw_dynamic
        || saw_wx
        || gnu_stack_count != 1
        || executable_stack
        || !executable_entry_segment
    {
        bail!("direct_operation_replay_sync_static_aarch64_elf_contract_denied");
    }
    Ok(StaticElfValidation {
        static_aarch64_elf64: true,
        pt_interp_absent: true,
        pt_dynamic_absent: true,
        wx_segment_absent: true,
        executable_stack_absent: true,
    })
}

fn pread_exact(fd: RawFd, mut output: &mut [u8], mut offset: i64) -> io::Result<()> {
    while !output.is_empty() {
        // SAFETY: output is writable, offset is monotonically bounded by its
        // original slice length, and fd is one retained regular file.
        let count = unsafe {
            libc::pread(
                fd,
                output.as_mut_ptr().cast::<c_void>(),
                output.len(),
                offset,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        let count = count as usize;
        output = &mut output[count..];
        offset += count as i64;
    }
    Ok(())
}

fn verify_file_capabilities_absent(fd: RawFd) -> Result<bool> {
    // SAFETY: a null value pointer with zero size queries one retained inode.
    let result =
        unsafe { libc::fgetxattr(fd, c"security.capability".as_ptr(), std::ptr::null_mut(), 0) };
    if result >= 0 {
        bail!("direct_operation_replay_sync_file_capabilities_present");
    }
    let error = io::Error::last_os_error();
    let raw = error.raw_os_error();
    if raw == Some(libc::ENODATA) || raw == Some(libc::EOPNOTSUPP) {
        Ok(true)
    } else {
        Err(error).context("direct_operation_replay_sync_file_capabilities_unverifiable")
    }
}

fn measure_fsverity_sha256(fd: RawFd) -> Result<String> {
    let mut digest = [0_u8; 4 + 64];
    digest[2..4].copy_from_slice(&(64_u16).to_ne_bytes());
    // SAFETY: the buffer starts with the Linux fsverity_digest header and has
    // room for the maximum digest size we advertise.
    if unsafe { libc::ioctl(fd, FS_IOC_MEASURE_VERITY, digest.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error())
            .context("direct_operation_replay_sync_fsverity_measurement_unavailable");
    }
    let algorithm = u16::from_ne_bytes(digest[0..2].try_into().expect("verity algorithm"));
    let size = usize::from(u16::from_ne_bytes(
        digest[2..4].try_into().expect("verity digest size"),
    ));
    if algorithm != FS_VERITY_HASH_ALG_SHA256 || size != 32 {
        bail!("direct_operation_replay_sync_fsverity_algorithm_denied");
    }
    Ok(digest[4..4 + size]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn valid_nonzero_digest(value: &str) -> bool {
    value.len() == 64
        && !value.bytes().all(|byte| byte == b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn executable_identity_digest(metadata: &ExecutableMetadata, sha256: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.operation-replay-sync-executable-inode.v1\0");
    hasher.update(metadata.dev.to_be_bytes());
    hasher.update(metadata.ino.to_be_bytes());
    hasher.update(metadata.mode.to_be_bytes());
    hasher.update(metadata.uid.to_be_bytes());
    hasher.update(metadata.gid.to_be_bytes());
    hasher.update(metadata.nlink.to_be_bytes());
    hasher.update(metadata.size.to_be_bytes());
    hasher.update(sha256.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn fixed_cgroup_filesystem_path(unified: &str) -> Result<PathBuf> {
    if !unified.starts_with("/trillionnium/agents/")
        || unified.contains("//")
        || unified.split('/').any(|part| part == "." || part == "..")
    {
        bail!("direct_operation_replay_sync_cgroup_path_denied");
    }
    Ok(PathBuf::from("/sys/fs/cgroup").join(&unified[1..]))
}

fn verify_cgroup_fd(fd: RawFd, unified: &str) -> Result<String> {
    let mut status = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: status is valid output storage.
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error())
            .context("direct_operation_replay_sync_cgroup_fstat");
    }
    // SAFETY: successful fstat initialized status.
    let status = unsafe { status.assume_init() };
    let mut filesystem = MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: filesystem is valid output storage.
    if unsafe { libc::fstatfs(fd, filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error())
            .context("direct_operation_replay_sync_cgroup_fstatfs");
    }
    // SAFETY: successful fstatfs initialized filesystem.
    let filesystem = unsafe { filesystem.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFDIR
        || status.st_uid != 0
        || status.st_mode & 0o022 != 0
        || status.st_nlink == 0
        || filesystem.f_type != CGROUP2_SUPER_MAGIC
    {
        bail!("direct_operation_replay_sync_cgroup_identity_denied");
    }
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.operation-replay-sync-fixed-cgroup.v1\0");
    hasher.update(unified.as_bytes());
    hasher.update(status.st_dev.to_be_bytes());
    hasher.update(status.st_ino.to_be_bytes());
    hasher.update(status.st_mode.to_be_bytes());
    hasher.update(status.st_uid.to_be_bytes());
    hasher.update(status.st_gid.to_be_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors has two writable integer slots.
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two unique owned descriptors.
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn ensure_pipe_capacity(fd: RawFd, required: usize) -> io::Result<()> {
    // SAFETY: fcntl only inspects/changes this pipe.
    let current = unsafe { libc::fcntl(fd, libc::F_GETPIPE_SZ) };
    if current < 0 {
        return Err(io::Error::last_os_error());
    }
    if current as usize >= required {
        return Ok(());
    }
    // A denied capacity increase is a hard pre-spawn failure; we never risk a
    // blocked parent while the measured child is stopped.
    let requested =
        c_int::try_from(required).map_err(|_| io::Error::other("pipe capacity overflow"))?;
    // SAFETY: requested is a bounded positive size.
    let updated = unsafe { libc::fcntl(fd, libc::F_SETPIPE_SZ, requested) };
    if updated < 0 || (updated as usize) < required {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe fn child_exec(
    executable_fd: RawFd,
    command_fd: RawFd,
    response_fd: RawFd,
    uid: u32,
    gid: u32,
    executable_path: *const c_char,
) -> ! {
    // Duplicate all three sources above the fixed surface first so arbitrary
    // inherited descriptor numbers cannot make the dup sequence alias.
    let command_saved = unsafe { libc::fcntl(command_fd, libc::F_DUPFD_CLOEXEC, 10) };
    let response_saved = unsafe { libc::fcntl(response_fd, libc::F_DUPFD_CLOEXEC, 11) };
    let executable_saved = unsafe { libc::fcntl(executable_fd, libc::F_DUPFD_CLOEXEC, 12) };
    if command_saved < 0
        || response_saved < 0
        || executable_saved < 0
        || unsafe { child_security_ceremony(uid, gid) } != 0
        || unsafe { libc::dup3(command_saved, COMMAND_FD, 0) } < 0
        || unsafe { libc::dup3(response_saved, RESPONSE_FD, 0) } < 0
        || unsafe { libc::dup3(executable_saved, EXECUTABLE_FD, libc::O_CLOEXEC) } < 0
        || unsafe { libc::close(libc::STDIN_FILENO) } != 0
        || unsafe { libc::close(libc::STDOUT_FILENO) } != 0
        || unsafe { libc::close(libc::STDERR_FILENO) } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_close_range,
                6 as c_uint,
                c_uint::MAX,
                CLOSE_RANGE_UNSHARE,
            )
        } != 0
        || unsafe { libc::raise(libc::SIGSTOP) } != 0
    {
        // SAFETY: this is the isolated child failure path.
        unsafe { libc::_exit(127) }
    }
    let arguments = [executable_path, std::ptr::null()];
    let environment = [std::ptr::null::<c_char>()];
    // SAFETY: fd 5 is the exact measured, policy-labeled ELF; empty pathname
    // plus AT_EMPTY_PATH executes that same descriptor.  SELinux selects the
    // exact operation domain through domain_auto_trans, and the parent checks
    // that domain at the stopped post-exec barrier before releasing fd 3.
    // argv contains only argv0 and environment is exactly empty.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            EXECUTABLE_FD,
            c"".as_ptr(),
            arguments.as_ptr(),
            environment.as_ptr(),
            libc::AT_EMPTY_PATH,
        );
        libc::_exit(127)
    }
}

unsafe fn child_security_ceremony(uid: u32, gid: u32) -> c_int {
    let parent_before = unsafe { libc::getppid() };
    let mut pdeathsig = 0;
    if parent_before <= 1
        || unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(gid, gid, gid) } != 0
        || unsafe { libc::setresuid(uid, uid, uid) } != 0
        // Credential transitions clear PDEATHSIG.  Install and read it back
        // only after the final UID/GID transition.
        || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } != 0
        || unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut pdeathsig) } != 0
        || pdeathsig != libc::SIGKILL
        || unsafe { libc::getppid() } != parent_before
        || unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
        || set_empty_capabilities() != 0
        || set_descendant_filter() != 0
    {
        return -1;
    }
    0
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
    // SAFETY: the structures are the Linux v3 capability ABI and target self.
    unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) as c_int }
}

fn set_descendant_filter() -> c_int {
    let deny = SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32;
    #[cfg(target_arch = "aarch64")]
    let filters = [
        load_filter(SECCOMP_DATA_ARCH_OFFSET),
        expected_arch_filter(),
        return_filter(SECCOMP_RET_KILL_PROCESS_VALUE),
        load_filter(SECCOMP_DATA_NR_OFFSET),
        syscall_deny_filter(libc::SYS_clone as u32),
        return_filter(deny),
        syscall_deny_filter(libc::SYS_clone3 as u32),
        return_filter(deny),
        return_filter(SECCOMP_RET_ALLOW_VALUE),
    ];
    #[cfg(target_arch = "x86_64")]
    let filters = [
        load_filter(SECCOMP_DATA_ARCH_OFFSET),
        expected_arch_filter(),
        return_filter(SECCOMP_RET_KILL_PROCESS_VALUE),
        load_filter(SECCOMP_DATA_NR_OFFSET),
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
    // SAFETY: program remains live for the scalar prctl call.
    unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER_VALUE,
            &raw const program,
        )
    }
}

const fn load_filter(offset: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: offset,
    }
}

const fn expected_arch_filter() -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: SECCOMP_AUDIT_ARCH,
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

fn inspect_process(pid: libc::pid_t, expected_path: &str) -> Result<ProcessInspection> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let uid = parse_status_identity(&status, "Uid:")?;
    let gid = parse_status_identity(&status, "Gid:")?;
    let capabilities_empty = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .into_iter()
        .all(|key| matches!(parse_status_hex(&status, key), Ok(0)));
    let no_new_privs = parse_status_decimal(&status, "NoNewPrivs:")? == 1;
    let descendants_forbidden = parse_status_decimal(&status, "Seccomp:")? == 2;
    let daemon_pid = u64::try_from(unsafe { libc::getpid() })
        .context("direct_operation_replay_sync_daemon_pid_invalid")?;
    let tracer_parent_verified = parse_status_decimal(&status, "TracerPid:")? == daemon_pid
        && parse_status_decimal(&status, "PPid:")? == daemon_pid;
    let selinux_domain = fs::read_to_string(format!("/proc/{pid}/attr/current"))?
        .trim_end_matches(['\0', '\n'])
        .to_string();
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let unified_cgroup_path = parse_unified_cgroup_path(&cgroup)?;
    let executable_link = fs::read_link(format!("/proc/{pid}/exe"))?;
    let executable_path = executable_link
        .to_str()
        .context("direct_operation_replay_sync_executable_link_non_utf8")?
        .to_string();
    if executable_path != expected_path {
        bail!("direct_operation_replay_sync_executable_link_drift");
    }
    let executable = fs::File::open(format!("/proc/{pid}/exe"))?;
    let executable_sha256 = sha256_fd(executable.as_raw_fd())?;
    let executable_metadata = executable_metadata(executable.as_raw_fd())?;
    let executable_identity_sha256 =
        executable_identity_digest(&executable_metadata, &executable_sha256);
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
    let fd3 = pipe_access_mode(pid, COMMAND_FD)?;
    let fd4 = pipe_access_mode(pid, RESPONSE_FD)?;
    let fd3_link = fs::read_link(format!("/proc/{pid}/fd/{COMMAND_FD}"))?;
    let fd4_link = fs::read_link(format!("/proc/{pid}/fd/{RESPONSE_FD}"))?;
    let separate_pipes = fd3_link != fd4_link
        && fd3_link.to_string_lossy().starts_with("pipe:[")
        && fd4_link.to_string_lossy().starts_with("pipe:[");
    let environment_empty = fs::read(format!("/proc/{pid}/environ"))?.is_empty();
    let expected_command = format!("{expected_path}\0").into_bytes();
    let arguments_empty = fs::read(format!("/proc/{pid}/cmdline"))? == expected_command;
    Ok(ProcessInspection {
        uid,
        gid,
        selinux_domain,
        unified_cgroup_path,
        executable_path,
        executable_sha256,
        executable_identity_sha256,
        fd3_read_pipe_only: separate_pipes && fd3 == libc::O_RDONLY,
        fd4_write_pipe_only: separate_pipes && fd4 == libc::O_WRONLY,
        other_fds_closed: descriptors == BTreeSet::from([3, 4]),
        environment_empty,
        arguments_empty,
        no_new_privs,
        capabilities_empty,
        descendants_forbidden,
        tracer_parent_verified,
    })
}

fn pipe_access_mode(pid: libc::pid_t, fd: RawFd) -> Result<c_int> {
    let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}"))?;
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:\t"))
        .context("direct_operation_replay_sync_fd_flags_absent")?;
    let flags =
        c_int::from_str_radix(flags, 8).context("direct_operation_replay_sync_fd_flags_invalid")?;
    Ok(flags & libc::O_ACCMODE)
}

fn parse_unified_cgroup_path(value: &str) -> Result<String> {
    let mut lines = value.lines();
    let line = lines
        .next()
        .context("direct_operation_replay_sync_cgroup_membership_absent")?;
    if lines.next().is_some() || !line.starts_with("0::/") {
        bail!("direct_operation_replay_sync_cgroup_membership_denied");
    }
    Ok(line[3..].to_string())
}

fn read_exact_at_start(fd: RawFd, output: &mut [u8]) -> io::Result<()> {
    // SAFETY: lseek resets the retained regular file.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut offset = 0;
    while offset < output.len() {
        // SAFETY: output tail is writable and bounded.
        let count = unsafe {
            libc::read(
                fd,
                output[offset..].as_mut_ptr().cast::<c_void>(),
                output.len() - offset,
            )
        };
        if count <= 0 {
            return Err(if count == 0 {
                io::Error::from(io::ErrorKind::UnexpectedEof)
            } else {
                io::Error::last_os_error()
            });
        }
        offset += count as usize;
    }
    Ok(())
}

fn sha256_fd(fd: RawFd) -> io::Result<String> {
    // SAFETY: retained regular file.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        // SAFETY: buffer is writable and bounded.
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast::<c_void>(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count as usize]);
    }
    // SAFETY: restore offset for the later same-FD exec.
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn parse_status_identity(status: &str, key: &str) -> Result<u32> {
    let values = status_values(status, key)?
        .map(|value| value.parse::<u32>().map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>>>()?;
    if values.len() != 4 || values.iter().any(|value| *value != values[0]) {
        bail!("direct_operation_replay_sync_credential_identity_drift");
    }
    Ok(values[0])
}

fn parse_status_hex(status: &str, key: &str) -> Result<u64> {
    let value = status_values(status, key)?
        .next()
        .context("direct_operation_replay_sync_status_value_absent")?;
    Ok(u64::from_str_radix(value, 16)?)
}

fn parse_status_decimal(status: &str, key: &str) -> Result<u64> {
    status_values(status, key)?
        .next()
        .context("direct_operation_replay_sync_status_value_absent")?
        .parse::<u64>()
        .map_err(anyhow::Error::from)
}

fn status_values<'a>(status: &'a str, key: &str) -> Result<impl Iterator<Item = &'a str>> {
    let line = status
        .lines()
        .find(|line| line.starts_with(key))
        .context("direct_operation_replay_sync_status_field_absent")?;
    Ok(line[key.len()..].split_ascii_whitespace())
}

fn ptrace_setoptions(pid: libc::pid_t, options: c_ulong) -> io::Result<()> {
    // SAFETY: child requested TRACEME and is stopped.
    if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, options) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ptrace_continue(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: pid is the retained traced child.
    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ptrace_detach(pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: pid is stopped at the verified helper barrier.
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn wait_for_stop(pid: libc::pid_t, signal: c_int, deadline: Instant) -> io::Result<()> {
    let status = waitpid_exact_before(pid, deadline)?;
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != signal {
        return Err(io::Error::other("unexpected replay-sync child stop"));
    }
    Ok(())
}

fn wait_for_exec_stop(pid: libc::pid_t, deadline: Instant) -> io::Result<()> {
    let status = waitpid_exact_before(pid, deadline)?;
    if !libc::WIFSTOPPED(status)
        || libc::WSTOPSIG(status) != libc::SIGTRAP
        || status >> 16 != PTRACE_EVENT_EXEC_VALUE
    {
        return Err(io::Error::other("missing replay-sync ptrace exec stop"));
    }
    Ok(())
}

fn wait_for_self_hardening_stop(pid: libc::pid_t, deadline: Instant) -> io::Result<()> {
    wait_for_stop(pid, libc::SIGSTOP, deadline)?;
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: pid is the stopped traced child and info is writable.
    if unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, pid, 0, info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful ptrace initialized info.
    let info = unsafe { info.assume_init() };
    // libc::raise is implemented as tgkill on Linux; SI_TKILL plus sender pid
    // binds this stop to the exact helper self-hardening barrier.
    if info.si_code != libc::SI_TKILL || unsafe { info.si_pid() } != pid {
        return Err(io::Error::other("invalid replay-sync hardening stop"));
    }
    Ok(())
}

fn waitpid_exact(pid: libc::pid_t) -> io::Result<c_int> {
    loop {
        let mut status = 0;
        // SAFETY: status is writable and pid is exact.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if result == pid {
            return Ok(status);
        }
        let error = io::Error::last_os_error();
        if result < 0 && error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error);
    }
}

fn waitpid_exact_before(pid: libc::pid_t, deadline: Instant) -> io::Result<c_int> {
    loop {
        let mut status = 0;
        // SAFETY: status is writable, pid is the exact clone result, and
        // WNOHANG prevents a child that misses a ceremony stop from hanging
        // the long-lived daemon.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::__WALL | libc::WNOHANG) };
        if result == pid {
            return Ok(status);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "replay-sync child ceremony timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn read_proc_start_time(pid: libc::pid_t) -> io::Result<u64> {
    parse_proc_start_time(&fs::read_to_string(format!("/proc/{pid}/stat"))?)
}

fn parse_proc_start_time(status: &str) -> io::Result<u64> {
    let close = status
        .rfind(')')
        .ok_or_else(|| io::Error::other("invalid proc stat"))?;
    status[close + 1..]
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::other("missing proc starttime"))?
        .parse::<u64>()
        .map_err(io::Error::other)
}

fn pidfd_identity(fd: RawFd, pid: libc::pid_t, start: u64) -> io::Result<String> {
    let mut status = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: status is writable.
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstat initialized status.
    let status = unsafe { status.assume_init() };
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.operation-replay-sync-pidfd.v1\0");
    hasher.update((pid as u32).to_be_bytes());
    hasher.update(start.to_be_bytes());
    hasher.update(status.st_dev.to_be_bytes());
    hasher.update(status.st_ino.to_be_bytes());
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_all_fd(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        // SAFETY: bytes is readable and fd is the retained pipe writer.
        let count = unsafe { libc::write(fd, bytes.as_ptr().cast::<c_void>(), bytes.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        bytes = &bytes[count as usize..];
    }
    Ok(())
}

fn read_bounded_to_exact_eof(fd: RawFd, maximum: usize, deadline: Instant) -> io::Result<Vec<u8>> {
    // SAFETY: fcntl modifies only this retained descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        // SAFETY: buffer is writable and bounded.
        match unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) } {
            0 => break,
            count if count > 0 => {
                let count = count as usize;
                if bytes.len().saturating_add(count) > maximum {
                    return Err(io::Error::other("replay-sync response exceeds bound"));
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
        return Err(io::Error::other("replay-sync response is empty"));
    }
    Ok(bytes)
}

fn poll_until(fd: RawFd, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "replay-sync timeout"))?;
        let timeout = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: descriptor is one writable pollfd.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err(io::Error::other("replay-sync descriptor failed"));
            }
            if descriptor.revents & (events | libc::POLLHUP) != 0 {
                return Ok(());
            }
        } else if result == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "replay-sync timeout",
            ));
        } else if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}

fn wait_for_exit(pid: libc::pid_t) -> io::Result<()> {
    let deadline = Instant::now() + RESULT_TIMEOUT;
    loop {
        let status = match waitpid_exact_before(pid, deadline) {
            Ok(status) => status,
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
            Err(error) => return Err(error),
        };
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Ok(());
        }
        if libc::WIFSTOPPED(status) {
            // SAFETY: exact traced child, delivering SIGKILL while continuing.
            let _ = unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, libc::SIGKILL) };
        }
    }
}

fn kill_and_reap_raw_clone_result(raw_pid: libc::c_long) -> io::Result<()> {
    // This branch is unreachable on Linux's pid_t ABI but still owns a live
    // clone result if an ABI/kernel violation ever exposes a wider value.
    // Keep all operands in syscall-width integers until the child is gone.
    // SAFETY: raw_pid is the exact positive clone3 return value.
    if unsafe { libc::syscall(libc::SYS_kill, raw_pid, libc::SIGKILL) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut status: c_int = 0;
    let deadline = Instant::now() + RESULT_TIMEOUT;
    loop {
        // SAFETY: wait4 accepts the exact syscall-width PID and writable status.
        let result = unsafe {
            libc::syscall(
                libc::SYS_wait4,
                raw_pid,
                &mut status as *mut c_int,
                libc::WNOHANG,
                std::ptr::null_mut::<libc::rusage>(),
            )
        };
        if result == raw_pid {
            return Ok(());
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "raw clone result cleanup timed out",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn kill_pidfd_and_reap(pidfd: RawFd, pid: libc::pid_t) -> io::Result<()> {
    // SAFETY: pidfd is clone3-returned and retained for this exact child.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    wait_for_exit(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PAGE_SIZE: u64 = 0x1000;
    const PROGRAM_HEADER_OFFSET: usize = 64;
    const PROGRAM_HEADER_SIZE: usize = 56;
    const LOAD_PROGRAM_HEADER: usize = PROGRAM_HEADER_OFFSET;
    const STACK_PROGRAM_HEADER: usize = PROGRAM_HEADER_OFFSET + PROGRAM_HEADER_SIZE;

    #[allow(clippy::too_many_arguments)]
    fn write_program_header(
        bytes: &mut [u8],
        index: usize,
        kind: u32,
        flags: u32,
        offset: u64,
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
        alignment: u64,
    ) {
        let start = PROGRAM_HEADER_OFFSET + index * PROGRAM_HEADER_SIZE;
        let ph = &mut bytes[start..start + PROGRAM_HEADER_SIZE];
        ph[0..4].copy_from_slice(&kind.to_le_bytes());
        ph[4..8].copy_from_slice(&flags.to_le_bytes());
        ph[8..16].copy_from_slice(&offset.to_le_bytes());
        ph[16..24].copy_from_slice(&virtual_address.to_le_bytes());
        ph[32..40].copy_from_slice(&file_size.to_le_bytes());
        ph[40..48].copy_from_slice(&memory_size.to_le_bytes());
        ph[48..56].copy_from_slice(&alignment.to_le_bytes());
    }

    fn minimal_static_aarch64_elf() -> Vec<u8> {
        let mut bytes = vec![0_u8; PROGRAM_HEADER_OFFSET + 2 * PROGRAM_HEADER_SIZE];
        bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&183_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x400040_u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());
        let length = bytes.len() as u64;
        write_program_header(
            &mut bytes,
            0,
            1,
            5,
            0,
            0x400000,
            length,
            length,
            TEST_PAGE_SIZE,
        );
        write_program_header(&mut bytes, 1, 0x6474_e551, 6, 0, 0, 0, 0, 16);
        bytes
    }

    fn static_aarch64_elf_with_rw_load(rw_offset: u64, rw_virtual_address: u64) -> Vec<u8> {
        let mut bytes = minimal_static_aarch64_elf();
        let program_headers_end = PROGRAM_HEADER_OFFSET + 3 * PROGRAM_HEADER_SIZE;
        let rw_end = usize::try_from(rw_offset + 16).unwrap();
        bytes.resize(program_headers_end.max(rw_end), 0);
        bytes[56..58].copy_from_slice(&3_u16.to_le_bytes());
        bytes[LOAD_PROGRAM_HEADER + 32..LOAD_PROGRAM_HEADER + 40]
            .copy_from_slice(&0x80_u64.to_le_bytes());
        bytes[LOAD_PROGRAM_HEADER + 40..LOAD_PROGRAM_HEADER + 48]
            .copy_from_slice(&0x80_u64.to_le_bytes());
        write_program_header(
            &mut bytes,
            2,
            1,
            6,
            rw_offset,
            rw_virtual_address,
            16,
            16,
            TEST_PAGE_SIZE,
        );
        bytes
    }

    fn assert_elf_validation_error(bytes: &[u8], expected: &str) {
        assert_eq!(
            verify_static_aarch64_elf64_bytes(bytes, TEST_PAGE_SIZE)
                .unwrap_err()
                .to_string(),
            expected
        );
    }

    #[test]
    fn proc_and_cgroup_parsers_are_closed_world() {
        let mut fields = vec!["S".to_string()];
        fields.extend((1..=18).map(|value| value.to_string()));
        fields.push("4242".to_string());
        fields.extend((20..=30).map(|value| value.to_string()));
        let status = format!("17 (replay worker) {}", fields.join(" "));
        assert_eq!(parse_proc_start_time(&status).unwrap(), 4242);
        assert_eq!(
            parse_unified_cgroup_path("0::/trillionnium/agents/codex/system-api\n").unwrap(),
            "/trillionnium/agents/codex/system-api"
        );
        assert!(parse_unified_cgroup_path("1:name:/wrong\n").is_err());
        assert!(fixed_cgroup_filesystem_path("/trillionnium/agents/../wrong").is_err());
    }

    #[test]
    fn credential_and_descendant_contracts_reject_drift() {
        assert_eq!(
            parse_status_identity("Uid:\t5901\t5901\t5901\t5901\n", "Uid:").unwrap(),
            5901
        );
        assert!(parse_status_identity("Uid:\t5901\t5901\t0\t5901\n", "Uid:").is_err());
        let deny = SECCOMP_RET_ERRNO_VALUE | libc::EPERM as u32;
        assert_eq!(load_filter(SECCOMP_DATA_ARCH_OFFSET).k, 4);
        assert_eq!(expected_arch_filter().k, SECCOMP_AUDIT_ARCH);
        assert_eq!(expected_arch_filter().jt, 1);
        assert_eq!(expected_arch_filter().jf, 0);
        assert_eq!(return_filter(SECCOMP_RET_KILL_PROCESS_VALUE).k, 0x8000_0000);
        assert_eq!(syscall_deny_filter(libc::SYS_clone3 as u32).jf, 1);
        assert_eq!(return_filter(deny).k, deny);
    }

    #[test]
    fn static_aarch64_elf_gate_rejects_loader_dynamic_wx_and_header_drift() {
        let exact = minimal_static_aarch64_elf();
        assert_eq!(
            verify_static_aarch64_elf64_bytes(&exact, TEST_PAGE_SIZE).unwrap(),
            StaticElfValidation {
                static_aarch64_elf64: true,
                pt_interp_absent: true,
                pt_dynamic_absent: true,
                wx_segment_absent: true,
                executable_stack_absent: true,
            }
        );
        let mut wrong_machine = exact.clone();
        wrong_machine[18..20].copy_from_slice(&62_u16.to_le_bytes());
        assert!(verify_static_aarch64_elf64_bytes(&wrong_machine, TEST_PAGE_SIZE).is_err());
        let mut dynamic = exact.clone();
        dynamic[64..68].copy_from_slice(&2_u32.to_le_bytes());
        assert!(verify_static_aarch64_elf64_bytes(&dynamic, TEST_PAGE_SIZE).is_err());
        let mut interp = exact.clone();
        interp[64..68].copy_from_slice(&3_u32.to_le_bytes());
        assert!(verify_static_aarch64_elf64_bytes(&interp, TEST_PAGE_SIZE).is_err());
        let mut writable_executable = exact.clone();
        writable_executable[68..72].copy_from_slice(&7_u32.to_le_bytes());
        assert!(verify_static_aarch64_elf64_bytes(&writable_executable, TEST_PAGE_SIZE).is_err());
        assert!(verify_static_aarch64_elf64_bytes(&exact[..63], TEST_PAGE_SIZE).is_err());
    }

    #[test]
    fn static_aarch64_elf_gate_requires_one_non_executable_gnu_stack() {
        let exact = minimal_static_aarch64_elf();

        let mut missing = exact.clone();
        missing[56..58].copy_from_slice(&1_u16.to_le_bytes());
        assert_elf_validation_error(
            &missing,
            "direct_operation_replay_sync_static_aarch64_elf_contract_denied",
        );

        let mut duplicate = exact.clone();
        duplicate.resize(PROGRAM_HEADER_OFFSET + 3 * PROGRAM_HEADER_SIZE, 0);
        duplicate[56..58].copy_from_slice(&3_u16.to_le_bytes());
        duplicate[PROGRAM_HEADER_OFFSET + 2 * PROGRAM_HEADER_SIZE
            ..PROGRAM_HEADER_OFFSET + 3 * PROGRAM_HEADER_SIZE]
            .copy_from_slice(&exact[STACK_PROGRAM_HEADER..STACK_PROGRAM_HEADER + 56]);
        assert_elf_validation_error(
            &duplicate,
            "direct_operation_replay_sync_static_aarch64_elf_contract_denied",
        );

        let mut executable = exact;
        executable[STACK_PROGRAM_HEADER + 4..STACK_PROGRAM_HEADER + 8]
            .copy_from_slice(&7_u32.to_le_bytes());
        assert_elf_validation_error(
            &executable,
            "direct_operation_replay_sync_static_aarch64_elf_contract_denied",
        );
    }

    #[test]
    fn static_aarch64_elf_gate_validates_load_alignment_and_overflow() {
        let exact = minimal_static_aarch64_elf();

        let mut no_required_alignment = exact.clone();
        no_required_alignment[LOAD_PROGRAM_HEADER + 48..LOAD_PROGRAM_HEADER + 56]
            .copy_from_slice(&0_u64.to_le_bytes());
        assert!(verify_static_aarch64_elf64_bytes(&no_required_alignment, TEST_PAGE_SIZE).is_ok());

        let mut non_power_of_two = exact.clone();
        non_power_of_two[LOAD_PROGRAM_HEADER + 48..LOAD_PROGRAM_HEADER + 56]
            .copy_from_slice(&3_u64.to_le_bytes());
        assert_elf_validation_error(
            &non_power_of_two,
            "direct_operation_replay_sync_load_alignment_denied",
        );

        let mut incongruent = exact.clone();
        incongruent[LOAD_PROGRAM_HEADER + 16..LOAD_PROGRAM_HEADER + 24]
            .copy_from_slice(&0x400001_u64.to_le_bytes());
        assert_elf_validation_error(
            &incongruent,
            "direct_operation_replay_sync_load_alignment_denied",
        );

        let mut file_overflow = exact.clone();
        file_overflow[LOAD_PROGRAM_HEADER + 8..LOAD_PROGRAM_HEADER + 16]
            .copy_from_slice(&(u64::MAX - 0xfff).to_le_bytes());
        file_overflow[LOAD_PROGRAM_HEADER + 32..LOAD_PROGRAM_HEADER + 40]
            .copy_from_slice(&0x2000_u64.to_le_bytes());
        file_overflow[LOAD_PROGRAM_HEADER + 40..LOAD_PROGRAM_HEADER + 48]
            .copy_from_slice(&0x2000_u64.to_le_bytes());
        assert_elf_validation_error(
            &file_overflow,
            "direct_operation_replay_sync_segment_file_overflow",
        );

        let mut memory_overflow = exact;
        memory_overflow[LOAD_PROGRAM_HEADER + 16..LOAD_PROGRAM_HEADER + 24]
            .copy_from_slice(&(u64::MAX - 0xfff).to_le_bytes());
        memory_overflow[LOAD_PROGRAM_HEADER + 40..LOAD_PROGRAM_HEADER + 48]
            .copy_from_slice(&0x2000_u64.to_le_bytes());
        assert_elf_validation_error(
            &memory_overflow,
            "direct_operation_replay_sync_segment_memory_overflow",
        );
    }

    #[test]
    fn static_aarch64_elf_gate_rejects_page_level_wx_overlap() {
        let page_separated = static_aarch64_elf_with_rw_load(0x1000, 0x401000);
        assert!(verify_static_aarch64_elf64_bytes(&page_separated, TEST_PAGE_SIZE).is_ok());

        let same_page = static_aarch64_elf_with_rw_load(0x100, 0x400100);
        assert_elf_validation_error(
            &same_page,
            "direct_operation_replay_sync_load_page_wx_overlap_denied",
        );
    }

    #[test]
    fn backend_is_concrete_but_has_no_route_or_capability_escalation() {
        let source = include_str!("linux_operation_replay_sync_launcher.rs");
        assert!(source.contains("CLONE_INTO_CGROUP_FLAG"));
        assert!(source.contains("libc::SYS_clone3"));
        assert!(source.contains("libc::SYS_execveat"));
        assert!(source.contains("libc::SYS_pidfd_send_signal"));
        assert!(!source.contains(concat!("/proc/self/attr/", "exec")));
        assert!(!source.contains(concat!("write_selinux_", "exec_domain")));
        assert!(source.contains("process.selinux_domain != child.expected_selinux_domain"));
        assert!(!source.contains(concat!("CAP_SYS_", "ADMIN")));
        assert!(!source.contains(concat!("CAP_SYS_", "PTRACE")));
        let main = include_str!("../main.rs");
        assert!(!main.contains("FixedOperationReplaySyncLauncher"));
        assert_eq!(
            SOURCE_STATUS,
            "source_only_concrete_clone3_cgroup_pidfd_replay_sync_backend_unwired_v1"
        );
    }
}
