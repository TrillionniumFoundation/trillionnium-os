//! Host-kernel-only producer for the final-image bootstrap fixture.
//!
//! This module is compiled only by Linux tests. It deliberately does not
//! implement the product `ProviderLaunchCustodyOps`: the host cannot prove the
//! target SELinux/cgroup contracts, exact dumpability is not independently
//! observable through procfs ownership, and the current fogos kernel/broker
//! profile cannot use `PTRACE_SECCOMP_GET_FILTER`. The producer nevertheless
//! exercises the real clone3-returned pidfd, ptrace exec stream, pre-entry
//! barrier, Codex final-image entry, bootstrap `SI_TKILL` stop,
//! exact filter readback, and fail-stop cleanup. It is not evidence for the
//! real Codex link map or production device custody.

use std::collections::BTreeSet;
use std::ffi::{CString, c_char, c_int, c_uint, c_ulong, c_void};
use std::fs;
use std::io::{self, Read as _};
use std::mem::{self, MaybeUninit};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use thiserror::Error;
use trillionnium_privilege_broker_protocol::{Digest, FixedBytes32, Provider};

use super::provider_post_exec_bootstrap::{
    AuthenticatedProviderBootstrapRecipeInputs, ClassicBpfInstruction,
    ClosedProviderFinalRuntimeBootstrapRecipe, FinalRuntimeNativeBootstrapMechanismV2,
    close_native_provider_bootstrap_recipe, exact_provider_seccomp_filter, seccomp_filter_sha256,
};

const FIXTURE_SOURCE: &str = include_str!("provider_post_exec_bootstrap_fixture.c");
const MUSL_SPAWN_FIXTURE_SOURCE: &str = include_str!("provider_post_exec_musl_spawn_fixture.c");
const FIXTURE_ADAPTER_SOURCE: &str = include_str!("provider_post_exec_bootstrap_fixture_adapter.h");
const BOOTSTRAP_HEADER_SOURCE: &str = include_str!(
    "../../../packaging/provider-post-exec-bootstrap/include/trillionnium_provider_post_exec_bootstrap.h"
);
const BOOTSTRAP_CORE_SOURCE: &str = include_str!(
    "../../../packaging/provider-post-exec-bootstrap/src/provider_post_exec_bootstrap.c"
);
const BOOTSTRAP_ENTRY_SOURCE: &str =
    include_str!("../../../packaging/provider-post-exec-bootstrap/src/provider_post_exec_entry.S");
const CLONE_PIDFD_FLAG: u64 = 0x0000_1000;
const PTRACE_EVENT_EXEC_VALUE: c_int = 4;
const PTRACE_O_TRACEEXEC_VALUE: c_ulong = 1 << 4;
const PTRACE_O_EXITKILL_VALUE: c_ulong = 1 << 20;
const PTRACE_SECCOMP_GET_FILTER_REQUEST: c_uint = 0x420c;
const MAX_CLASSIC_BPF_INSTRUCTIONS: usize = 4096;
const CLOSE_RANGE_UNSHARE: c_uint = 1 << 1;
const MARKER_FD: RawFd = 3;
const EXECUTABLE_FD: RawFd = 4;
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
const EXTERNAL_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const PRIVILEGED_FIXTURE_ENV: &str = "TRILLIONNIUM_RUN_PRIVILEGED_POST_EXEC_FIXTURE";

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureFault {
    None,
    EarlyUserMarker,
    DumpableNotReasserted,
    WrongFilter,
    WrongSignalSource,
    SecondExec,
}

impl FixtureFault {
    const fn compiler_define(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::EarlyUserMarker => Some("FAULT_EARLY_MARKER"),
            Self::DumpableNotReasserted => Some("FAULT_NO_DUMPABLE"),
            Self::WrongFilter => Some("FAULT_WRONG_FILTER"),
            Self::WrongSignalSource => Some("FAULT_WRONG_SIGNAL"),
            Self::SecondExec => Some("FAULT_SECOND_EXEC"),
        }
    }
}

struct BuiltFixture {
    _directory: TempDir,
    path: PathBuf,
    executable_sha256: Digest,
    closure_sha256: Digest,
    elf_contract_sha256: Digest,
    mechanism: FinalRuntimeNativeBootstrapMechanismV2,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
enum LinuxFixtureError {
    #[error("the real Linux fixture requires a privileged root test child")]
    PrivilegedTestRequired,
    #[error("the fixture compiler or static toolchain is unavailable")]
    FixtureBuildUnavailable,
    #[error("the freestanding bootstrap object has an unresolved runtime dependency")]
    FreestandingObjectDependency,
    #[error("the final fixture ELF failed its bounded mechanism gate")]
    FinalElfContractInvalid,
    #[error("the fixture executable does not match its closed recipe")]
    RecipeExecutableMismatch,
    #[error("clone3 did not return the exact child pidfd")]
    Clone3PidfdUnavailable,
    #[error("the pre-exec stopped child or pidfd identity drifted")]
    PreExecIdentityDrift,
    #[error("the final ptrace exec event drifted or a second exec occurred")]
    FinalExecEventDrift,
    #[error("the broker-queued pre-entry stop was unavailable")]
    PreEntryBarrierDrift,
    #[error("the final-image hardening stop was missing or had the wrong source")]
    HardeningStopDrift,
    #[error("user code ran before the final-image hardening stop")]
    EarlyUserCodeObserved,
    #[error("the kernel-installed exact seccomp filter could not be exported")]
    ExactFilterReadbackUnavailable,
    #[error("the kernel-installed seccomp filter did not match the recipe")]
    ExactFilterMismatch,
    #[error("the independently observed held-process state drifted")]
    HeldObservationDrift,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxFixtureHoldReason {
    PreExecIdentityDrift,
    FinalExecEventDrift,
    PreEntryBarrierDrift,
    HardeningStopDrift,
    EarlyUserCodeObserved,
    ExactFilterReadbackUnavailable,
    ExactFilterMismatch,
    HeldObservationDrift,
    DropBeforeAdoption,
    CleanupProofMissing,
}

#[derive(Clone, Default)]
struct SharedHoldSink {
    reasons: Arc<Mutex<Vec<LinuxFixtureHoldReason>>>,
}

impl SharedHoldSink {
    fn record(&self, reason: LinuxFixtureHoldReason) {
        self.reasons
            .lock()
            .expect("hold sink poisoned")
            .push(reason);
    }

    fn snapshot(&self) -> Vec<LinuxFixtureHoldReason> {
        self.reasons.lock().expect("hold sink poisoned").clone()
    }
}

#[derive(Debug)]
struct HeldKernelObservation {
    provider: Provider,
    tgid: u32,
    starttime_ticks: u64,
    pidfd_identity_sha256: Digest,
    final_runtime_executable_sha256: Digest,
    runtime_maps_closure_sha256: Digest,
    observed_uid: u32,
    observed_gid: u32,
    observed_selinux_domain_sha256: Digest,
    observed_argv_sha256: Digest,
    observed_environment_sha256: Digest,
    observed_fd_table_sha256: Digest,
    observed_cgroup_identity_sha256: Digest,
    exec_event_identity_sha256: Digest,
    pre_entry_barrier_identity_sha256: Digest,
    hardening_event_identity_sha256: Digest,
    exact_seccomp_filter_sha256: Digest,
    procfs_nondump_owner_observed: bool,
    exact_parent_dumpable_observation_available: bool,
    target_selinux_verified: bool,
    target_cgroup_verified: bool,
    product_qualifies: bool,
}

/// Affine owner of one exact clone3-returned pidfd and ptrace-held final
/// runtime fixture. It has no release/admission/effect surface. Drop always
/// pidfd-kills and exactly reaps the process, then records permanent fixture
/// HOLD. The product launch producer remains absent.
#[must_use = "dropping held Linux fixture custody fail-stops the exact child"]
struct LinuxHeldProviderFixture {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    proc_dir: OwnedFd,
    marker_read: OwnedFd,
    retained_executable: OwnedFd,
    _fixture: Option<BuiltFixture>,
    recipe: Option<ClosedProviderFinalRuntimeBootstrapRecipe>,
    observation: HeldKernelObservation,
    sink: SharedHoldSink,
    pending_hold: LinuxFixtureHoldReason,
    force_cleanup_unknown: bool,
    alive: bool,
}

impl LinuxHeldProviderFixture {
    fn fail(
        mut self,
        error: LinuxFixtureError,
        reason: LinuxFixtureHoldReason,
    ) -> LinuxFixtureError {
        self.pending_hold = reason;
        drop(self);
        error
    }

    fn resume_and_collect_fixture_markers_for_test(
        &mut self,
    ) -> Result<Vec<u8>, LinuxFixtureError> {
        ptrace_continue(self.pid, 0).map_err(|_| LinuxFixtureError::HeldObservationDrift)?;
        let deadline = Instant::now() + WAIT_TIMEOUT;
        let mut output = Vec::new();
        while output.len() < 3 {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(LinuxFixtureError::HeldObservationDrift)?;
            let timeout = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
            let mut pollfd = libc::pollfd {
                fd: self.marker_read.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut pollfd, 1, timeout) };
            if polled <= 0 {
                return Err(LinuxFixtureError::HeldObservationDrift);
            }
            let mut byte = [0_u8; 8];
            let count = unsafe {
                libc::read(
                    self.marker_read.as_raw_fd(),
                    byte.as_mut_ptr().cast::<c_void>(),
                    byte.len(),
                )
            };
            if count <= 0 {
                return Err(LinuxFixtureError::HeldObservationDrift);
            }
            output.extend_from_slice(&byte[..count as usize]);
        }
        Ok(output)
    }
}

impl Drop for LinuxHeldProviderFixture {
    fn drop(&mut self) {
        if !self.alive {
            return;
        }
        let cleanup = kill_pidfd_and_reap(self.pidfd.as_raw_fd(), self.pid);
        self.alive = false;
        if cleanup.is_err() || self.force_cleanup_unknown {
            self.sink
                .record(LinuxFixtureHoldReason::CleanupProofMissing);
        } else {
            self.sink.record(self.pending_hold);
        }
    }
}

fn build_fixture(
    provider: Provider,
    fault: FixtureFault,
) -> Result<BuiltFixture, LinuxFixtureError> {
    let descriptor = match provider {
        Provider::Codex => &trillionnium_os_types::agent_descriptor_registry::CODEX,
    };
    let mechanism = FinalRuntimeNativeBootstrapMechanismV2::ControlledElfEntryTrampolineBeforeCrt;
    let directory = tempfile::tempdir().map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    let include_directory = directory.path().join("include");
    fs::create_dir(&include_directory).map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    let source = directory.path().join("final-runtime-fixture.c");
    let adapter = directory.path().join("fixture-bootstrap-adapter.h");
    let bootstrap_header = include_directory.join("trillionnium_provider_post_exec_bootstrap.h");
    let bootstrap_core = directory.path().join("provider-post-exec-bootstrap.c");
    let bootstrap_entry = directory.path().join("provider-post-exec-entry.S");
    let core_object = directory.path().join("provider-post-exec-bootstrap.o");
    let fixture_object = directory.path().join("final-runtime-fixture.o");
    let mechanism_object = directory.path().join("provider-post-exec-mechanism.o");
    let executable = directory.path().join("final-runtime-fixture");
    fs::write(&source, FIXTURE_SOURCE).map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    for (path, bytes) in [
        (&adapter, FIXTURE_ADAPTER_SOURCE.as_bytes()),
        (&bootstrap_header, BOOTSTRAP_HEADER_SOURCE.as_bytes()),
        (&bootstrap_core, BOOTSTRAP_CORE_SOURCE.as_bytes()),
        (&bootstrap_entry, BOOTSTRAP_ENTRY_SOURCE.as_bytes()),
    ] {
        fs::write(path, bytes).map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    }

    let mut core_compiler = Command::new("cc");
    core_compiler
        .arg("-std=c11")
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-ffreestanding")
        .arg("-fno-builtin")
        .arg("-fno-stack-protector")
        .arg("-fno-lto")
        .arg("-fno-unwind-tables")
        .arg("-fno-asynchronous-unwind-tables")
        .arg("-fvisibility=hidden")
        .arg("-I")
        .arg(&include_directory)
        .arg("-include")
        .arg(&adapter)
        .arg(format!("-DTRILLIONNIUM_EXPECTED_UID={}", descriptor.uid))
        .arg(format!("-DTRILLIONNIUM_EXPECTED_GID={}", descriptor.gid));
    core_compiler.arg("-fno-pie");
    if let Some(define) = fault.compiler_define() {
        core_compiler.arg(format!("-D{define}"));
    }
    core_compiler
        .arg("-c")
        .arg(&bootstrap_core)
        .arg("-o")
        .arg(&core_object);
    let status = command_status_with_deadline(&mut core_compiler, EXTERNAL_COMMAND_TIMEOUT)
        .map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    if !status.success() {
        return Err(LinuxFixtureError::FixtureBuildUnavailable);
    }

    let undefined_symbols = directory.path().join("bootstrap-undefined-symbols.txt");
    let undefined_output = fs::File::create(&undefined_symbols)
        .map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    let mut nm = Command::new("nm");
    nm.arg("-u")
        .arg(&core_object)
        .stdout(Stdio::from(undefined_output))
        .stderr(Stdio::null());
    let status = command_status_with_deadline(&mut nm, EXTERNAL_COMMAND_TIMEOUT)
        .map_err(|_| LinuxFixtureError::FreestandingObjectDependency)?;
    if !status.success()
        || !fs::read(&undefined_symbols)
            .map_err(|_| LinuxFixtureError::FreestandingObjectDependency)?
            .iter()
            .all(u8::is_ascii_whitespace)
    {
        return Err(LinuxFixtureError::FreestandingObjectDependency);
    }

    let mut fixture_compiler = Command::new("cc");
    fixture_compiler
        .arg("-std=c11")
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-fno-stack-protector")
        .arg("-fno-lto")
        .arg("-pthread");
    fixture_compiler.arg("-fno-pie");
    fixture_compiler
        .arg("-c")
        .arg(&source)
        .arg("-o")
        .arg(&fixture_object);
    let status = command_status_with_deadline(&mut fixture_compiler, EXTERNAL_COMMAND_TIMEOUT)
        .map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    if !status.success() {
        return Err(LinuxFixtureError::FixtureBuildUnavailable);
    }

    let mut mechanism_compiler = Command::new("cc");
    mechanism_compiler
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-fno-stack-protector")
        .arg("-fno-lto")
        .arg("-I")
        .arg(&include_directory);
    mechanism_compiler.arg("-fno-pie").arg(&bootstrap_entry);
    mechanism_compiler
        .arg("-c")
        .arg("-o")
        .arg(&mechanism_object);
    let status = command_status_with_deadline(&mut mechanism_compiler, EXTERNAL_COMMAND_TIMEOUT)
        .map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    if !status.success() {
        return Err(LinuxFixtureError::FixtureBuildUnavailable);
    }

    let mut linker = Command::new("cc");
    linker
        .arg(&mechanism_object)
        .arg(&core_object)
        .arg(&fixture_object)
        .arg("-pthread")
        .arg("-Wl,-z,now")
        .arg("-Wl,-z,noexecstack");
    linker
        .arg("-static")
        .arg("-no-pie")
        .arg("-Wl,-e,trillionnium_provider_post_final_exec_entry");
    linker.arg("-o").arg(&executable);
    let status = command_status_with_deadline(&mut linker, EXTERNAL_COMMAND_TIMEOUT)
        .map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    if !status.success() {
        return Err(LinuxFixtureError::FixtureBuildUnavailable);
    }

    let elf_contract_sha256 = inspect_fixture_elf(&executable, provider, mechanism)?;
    let executable_sha256 =
        sha256_path(&executable).map_err(|_| LinuxFixtureError::FixtureBuildUnavailable)?;
    let closure_sha256 = digest_fields(
        b"org.trillionnium.provider-fixture-closure.v1\0",
        &[
            executable_sha256.value().as_bytes(),
            elf_contract_sha256.value().as_bytes(),
            b"static-controlled-entry",
        ],
    );
    Ok(BuiltFixture {
        _directory: directory,
        path: executable,
        executable_sha256,
        closure_sha256,
        elf_contract_sha256,
        mechanism,
    })
}

#[derive(Clone, Debug)]
struct ElfSection {
    name: String,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    entry_size: u64,
}

#[derive(Clone, Copy, Debug)]
struct ElfLoadSegment {
    flags: u32,
    virtual_address: u64,
    memory_size: u64,
}

fn inspect_fixture_elf(
    executable: &Path,
    provider: Provider,
    mechanism: FinalRuntimeNativeBootstrapMechanismV2,
) -> Result<Digest, LinuxFixtureError> {
    const ELF_HEADER_SIZE: usize = 64;
    const PROGRAM_HEADER_SIZE: usize = 56;
    const SECTION_HEADER_SIZE: usize = 64;
    const SYMBOL_SIZE: usize = 24;
    const MAX_FIXTURE_ELF_BYTES: u64 = 64 * 1024 * 1024;
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const PT_GNU_STACK: u32 = 0x6474_e551;
    const PF_EXECUTE: u32 = 1;
    const PF_WRITE: u32 = 2;
    const SHT_PROGBITS: u32 = 1;
    const SHT_SYMTAB: u32 = 2;
    const SHT_PREINIT_ARRAY: u32 = 16;
    const SHF_WRITE: u64 = 1;
    const SHF_ALLOC: u64 = 2;
    const SHF_EXECINSTR: u64 = 4;

    if !matches!(
        (provider, mechanism),
        (
            Provider::Codex,
            FinalRuntimeNativeBootstrapMechanismV2::ControlledElfEntryTrampolineBeforeCrt
        )
    ) {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }

    let metadata =
        fs::metadata(executable).map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    if metadata.len() < ELF_HEADER_SIZE as u64 || metadata.len() > MAX_FIXTURE_ELF_BYTES {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }
    let bytes = fs::read(executable).map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    if bytes.get(..6) != Some(b"\x7fELF\x02\x01") {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }
    let elf_type = elf_u16(&bytes, 16)?;
    let machine = elf_u16(&bytes, 18)?;
    let entry = elf_u64(&bytes, 24)?;
    let program_offset = usize::try_from(elf_u64(&bytes, 32)?)
        .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    let section_offset = usize::try_from(elf_u64(&bytes, 40)?)
        .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    let program_entry_size = usize::from(elf_u16(&bytes, 54)?);
    let program_count = usize::from(elf_u16(&bytes, 56)?);
    let section_entry_size = usize::from(elf_u16(&bytes, 58)?);
    let section_count = usize::from(elf_u16(&bytes, 60)?);
    let section_name_index = usize::from(elf_u16(&bytes, 62)?);
    let expected_machine = if cfg!(target_arch = "x86_64") {
        62
    } else if cfg!(target_arch = "aarch64") {
        183
    } else {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    };
    let expected_type = match mechanism {
        FinalRuntimeNativeBootstrapMechanismV2::ControlledElfEntryTrampolineBeforeCrt => 2,
    };
    if machine != expected_machine
        || elf_type != expected_type
        || program_entry_size < PROGRAM_HEADER_SIZE
        || program_count == 0
        || program_count > 256
        || section_entry_size < SECTION_HEADER_SIZE
        || section_count == 0
        || section_count > 4096
        || section_name_index >= section_count
    {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }

    let mut load_segments = Vec::new();
    let mut interpreter_count = 0_usize;
    let mut dynamic_segment = None;
    let mut stack_count = 0_usize;
    for index in 0..program_count {
        let offset = checked_table_offset(
            program_offset,
            index,
            program_entry_size,
            PROGRAM_HEADER_SIZE,
            bytes.len(),
        )?;
        let program_type = elf_u32(&bytes, offset)?;
        let flags = elf_u32(&bytes, offset + 4)?;
        match program_type {
            PT_LOAD => {
                if flags & (PF_EXECUTE | PF_WRITE) == (PF_EXECUTE | PF_WRITE) {
                    return Err(LinuxFixtureError::FinalElfContractInvalid);
                }
                load_segments.push(ElfLoadSegment {
                    flags,
                    virtual_address: elf_u64(&bytes, offset + 16)?,
                    memory_size: elf_u64(&bytes, offset + 40)?,
                });
            }
            PT_DYNAMIC => {
                if dynamic_segment.is_some() {
                    return Err(LinuxFixtureError::FinalElfContractInvalid);
                }
                let dynamic_offset = usize::try_from(elf_u64(&bytes, offset + 8)?)
                    .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
                let dynamic_size = usize::try_from(elf_u64(&bytes, offset + 32)?)
                    .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
                elf_slice(&bytes, dynamic_offset, dynamic_size)?;
                dynamic_segment = Some((dynamic_offset, dynamic_size));
            }
            PT_INTERP => interpreter_count += 1,
            PT_GNU_STACK => {
                stack_count += 1;
                if flags & PF_EXECUTE != 0 {
                    return Err(LinuxFixtureError::FinalElfContractInvalid);
                }
            }
            _ => {}
        }
    }
    if load_segments.is_empty() || stack_count != 1 {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }
    if interpreter_count != 0 || dynamic_segment.is_some() {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }

    let section_name_header = checked_table_offset(
        section_offset,
        section_name_index,
        section_entry_size,
        SECTION_HEADER_SIZE,
        bytes.len(),
    )?;
    let section_name_offset = usize::try_from(elf_u64(&bytes, section_name_header + 24)?)
        .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    let section_name_size = usize::try_from(elf_u64(&bytes, section_name_header + 32)?)
        .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    let section_names = elf_slice(&bytes, section_name_offset, section_name_size)?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = checked_table_offset(
            section_offset,
            index,
            section_entry_size,
            SECTION_HEADER_SIZE,
            bytes.len(),
        )?;
        let name_offset = usize::try_from(elf_u32(&bytes, offset)?)
            .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
        let name = elf_c_string(section_names, name_offset)?;
        sections.push(ElfSection {
            name,
            section_type: elf_u32(&bytes, offset + 4)?,
            flags: elf_u64(&bytes, offset + 8)?,
            address: elf_u64(&bytes, offset + 16)?,
            offset: elf_u64(&bytes, offset + 24)?,
            size: elf_u64(&bytes, offset + 32)?,
            link: elf_u32(&bytes, offset + 40)?,
            entry_size: elf_u64(&bytes, offset + 56)?,
        });
    }

    let start = elf_symbol_value(&bytes, &sections, SHT_SYMTAB, SYMBOL_SIZE, "_start")?;
    let core = elf_symbol_value(
        &bytes,
        &sections,
        SHT_SYMTAB,
        SYMBOL_SIZE,
        "trillionnium_provider_post_final_exec_bootstrap",
    )?;
    let controlled_entry = elf_optional_symbol_value(
        &bytes,
        &sections,
        SHT_SYMTAB,
        SYMBOL_SIZE,
        "trillionnium_provider_post_final_exec_entry",
    )?;
    if start == core
        || !address_is_executable(start, &load_segments)
        || !address_is_executable(core, &load_segments)
    {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }

    let preinit_sections = sections
        .iter()
        .filter(|section| section.section_type == SHT_PREINIT_ARRAY)
        .collect::<Vec<_>>();
    let controlled_entry = controlled_entry.ok_or(LinuxFixtureError::FinalElfContractInvalid)?;
    if entry != controlled_entry
        || controlled_entry == start
        || controlled_entry == core
        || !address_is_executable(controlled_entry, &load_segments)
        || !preinit_sections.is_empty()
    {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }

    let filter_sections = sections
        .iter()
        .filter(|section| section.name == ".trillionnium.provider_filter")
        .collect::<Vec<_>>();
    if filter_sections.len() != 1 {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }
    let filter = filter_sections[0];
    let expected_filter = exact_provider_seccomp_filter();
    if filter.section_type != SHT_PROGBITS
        || filter.flags & SHF_ALLOC == 0
        || filter.flags & (SHF_WRITE | SHF_EXECINSTR) != 0
        || filter.size != (expected_filter.len() * 8) as u64
        || !section_is_read_only(filter, &load_segments)
    {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }
    let filter_offset =
        usize::try_from(filter.offset).map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    let filter_size =
        usize::try_from(filter.size).map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    let filter_bytes = elf_slice(&bytes, filter_offset, filter_size)?;
    let parsed_filter = filter_bytes
        .chunks_exact(8)
        .map(|instruction| ClassicBpfInstruction {
            code: u16::from_le_bytes([instruction[0], instruction[1]]),
            jump_true: instruction[2],
            jump_false: instruction[3],
            value: u32::from_le_bytes([
                instruction[4],
                instruction[5],
                instruction[6],
                instruction[7],
            ]),
        })
        .collect::<Vec<_>>();
    if parsed_filter.as_slice() != expected_filter
        || seccomp_filter_sha256(&parsed_filter) != seccomp_filter_sha256(&expected_filter)
    {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }

    let provider_byte = [match provider {
        Provider::Codex => 1,
    }];
    let mechanism_byte = [match mechanism {
        FinalRuntimeNativeBootstrapMechanismV2::ControlledElfEntryTrampolineBeforeCrt => 1,
    }];
    let entry_bytes = entry.to_be_bytes();
    let start_bytes = start.to_be_bytes();
    let core_bytes = core.to_be_bytes();
    let filter_digest = seccomp_filter_sha256(&parsed_filter);
    Ok(digest_fields(
        b"org.trillionnium.provider-fixture-final-elf-contract.v2\0",
        &[
            &provider_byte,
            &mechanism_byte,
            &entry_bytes,
            &start_bytes,
            &core_bytes,
            filter_digest.value().as_bytes(),
        ],
    ))
}

fn checked_table_offset(
    table_offset: usize,
    index: usize,
    entry_size: usize,
    required_size: usize,
    file_size: usize,
) -> Result<usize, LinuxFixtureError> {
    let offset = index
        .checked_mul(entry_size)
        .and_then(|offset| table_offset.checked_add(offset))
        .ok_or(LinuxFixtureError::FinalElfContractInvalid)?;
    if entry_size < required_size
        || offset
            .checked_add(required_size)
            .is_none_or(|end| end > file_size)
    {
        return Err(LinuxFixtureError::FinalElfContractInvalid);
    }
    Ok(offset)
}

fn elf_slice(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8], LinuxFixtureError> {
    bytes
        .get(
            offset
                ..offset
                    .checked_add(size)
                    .ok_or(LinuxFixtureError::FinalElfContractInvalid)?,
        )
        .ok_or(LinuxFixtureError::FinalElfContractInvalid)
}

fn elf_u16(bytes: &[u8], offset: usize) -> Result<u16, LinuxFixtureError> {
    let value: [u8; 2] = elf_slice(bytes, offset, 2)?
        .try_into()
        .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    Ok(u16::from_le_bytes(value))
}

fn elf_u32(bytes: &[u8], offset: usize) -> Result<u32, LinuxFixtureError> {
    let value: [u8; 4] = elf_slice(bytes, offset, 4)?
        .try_into()
        .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    Ok(u32::from_le_bytes(value))
}

fn elf_u64(bytes: &[u8], offset: usize) -> Result<u64, LinuxFixtureError> {
    let value: [u8; 8] = elf_slice(bytes, offset, 8)?
        .try_into()
        .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
    Ok(u64::from_le_bytes(value))
}

fn elf_c_string(bytes: &[u8], offset: usize) -> Result<String, LinuxFixtureError> {
    let tail = bytes
        .get(offset..)
        .ok_or(LinuxFixtureError::FinalElfContractInvalid)?;
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(LinuxFixtureError::FinalElfContractInvalid)?;
    std::str::from_utf8(&tail[..length])
        .map(str::to_owned)
        .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)
}

fn elf_optional_symbol_value(
    bytes: &[u8],
    sections: &[ElfSection],
    symbol_table_type: u32,
    required_symbol_size: usize,
    expected_name: &str,
) -> Result<Option<u64>, LinuxFixtureError> {
    let mut matched = None;
    for symbol_table in sections
        .iter()
        .filter(|section| section.section_type == symbol_table_type)
    {
        let string_table = sections
            .get(symbol_table.link as usize)
            .ok_or(LinuxFixtureError::FinalElfContractInvalid)?;
        let string_offset = usize::try_from(string_table.offset)
            .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
        let string_size = usize::try_from(string_table.size)
            .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
        let strings = elf_slice(bytes, string_offset, string_size)?;
        let entry_size = usize::try_from(symbol_table.entry_size)
            .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
        let table_size = usize::try_from(symbol_table.size)
            .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
        let table_offset = usize::try_from(symbol_table.offset)
            .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
        if entry_size < required_symbol_size || table_size % entry_size != 0 {
            return Err(LinuxFixtureError::FinalElfContractInvalid);
        }
        for index in 0..(table_size / entry_size) {
            let offset = checked_table_offset(
                table_offset,
                index,
                entry_size,
                required_symbol_size,
                bytes.len(),
            )?;
            let name_offset = usize::try_from(elf_u32(bytes, offset)?)
                .map_err(|_| LinuxFixtureError::FinalElfContractInvalid)?;
            if elf_c_string(strings, name_offset)? == expected_name {
                let section_index = elf_u16(bytes, offset + 6)?;
                let value = elf_u64(bytes, offset + 8)?;
                if section_index == 0 || value == 0 || matched.replace(value).is_some() {
                    return Err(LinuxFixtureError::FinalElfContractInvalid);
                }
            }
        }
    }
    Ok(matched)
}

fn elf_symbol_value(
    bytes: &[u8],
    sections: &[ElfSection],
    symbol_table_type: u32,
    required_symbol_size: usize,
    expected_name: &str,
) -> Result<u64, LinuxFixtureError> {
    elf_optional_symbol_value(
        bytes,
        sections,
        symbol_table_type,
        required_symbol_size,
        expected_name,
    )?
    .ok_or(LinuxFixtureError::FinalElfContractInvalid)
}

fn address_is_executable(address: u64, segments: &[ElfLoadSegment]) -> bool {
    segments.iter().any(|segment| {
        segment.flags & 1 != 0
            && address >= segment.virtual_address
            && address
                < segment
                    .virtual_address
                    .checked_add(segment.memory_size)
                    .unwrap_or(0)
    })
}

fn section_is_read_only(section: &ElfSection, segments: &[ElfLoadSegment]) -> bool {
    let Some(section_end) = section.address.checked_add(section.size) else {
        return false;
    };
    segments.iter().any(|segment| {
        let Some(segment_end) = segment.virtual_address.checked_add(segment.memory_size) else {
            return false;
        };
        segment.flags & 2 == 0
            && segment.flags & 1 == 0
            && section.address >= segment.virtual_address
            && section_end <= segment_end
    })
}

fn recipe_for_fixture(
    provider: Provider,
    fixture: &BuiltFixture,
) -> ClosedProviderFinalRuntimeBootstrapRecipe {
    close_native_provider_bootstrap_recipe(AuthenticatedProviderBootstrapRecipeInputs::for_test(
        provider,
        fixture.executable_sha256,
        fixture.closure_sha256,
        expected_argv_sha256(provider),
        digest_fields(
            b"org.trillionnium.provider-fixture-environment.v1\0",
            &[b"empty"],
        ),
        expected_fd_table_sha256(),
    ))
    .expect("closed fixture recipe")
}

fn launch_held_fixture(
    recipe: ClosedProviderFinalRuntimeBootstrapRecipe,
    fixture: BuiltFixture,
    sink: SharedHoldSink,
) -> Result<LinuxHeldProviderFixture, LinuxFixtureError> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(LinuxFixtureError::PrivilegedTestRequired);
    }
    if recipe.final_runtime_executable_sha256() != fixture.executable_sha256
        || recipe.final_runtime_closure_sha256() != fixture.closure_sha256
        || recipe.mechanism() != fixture.mechanism
    {
        return Err(LinuxFixtureError::RecipeExecutableMismatch);
    }
    let executable_file =
        fs::File::open(&fixture.path).map_err(|_| LinuxFixtureError::RecipeExecutableMismatch)?;
    let retained_executable: OwnedFd = executable_file.into();
    let executable_metadata = fstat(retained_executable.as_raw_fd())
        .map_err(|_| LinuxFixtureError::RecipeExecutableMismatch)?;
    if (executable_metadata.st_mode & libc::S_IFMT) != libc::S_IFREG
        || executable_metadata.st_nlink != 1
        || sha256_fd(retained_executable.as_raw_fd())
            .map_err(|_| LinuxFixtureError::RecipeExecutableMismatch)?
            != fixture.executable_sha256
    {
        return Err(LinuxFixtureError::RecipeExecutableMismatch);
    }

    let (marker_read, marker_write) =
        pipe_cloexec().map_err(|_| LinuxFixtureError::Clone3PidfdUnavailable)?;
    set_nonblocking(marker_read.as_raw_fd())
        .map_err(|_| LinuxFixtureError::Clone3PidfdUnavailable)?;
    let null = open_dev_null().map_err(|_| LinuxFixtureError::Clone3PidfdUnavailable)?;
    let expected_parent_pid = unsafe { libc::getpid() };
    let mut pidfd_raw: RawFd = -1;
    let mut clone_args = CloneArgs {
        flags: CLONE_PIDFD_FLAG,
        pidfd: (&mut pidfd_raw as *mut RawFd) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    let cloned = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &mut clone_args as *mut CloneArgs,
            mem::size_of::<CloneArgs>(),
        )
    };
    if cloned == 0 {
        unsafe {
            child_setup_and_exec(
                recipe.provider(),
                recipe.expected_uid(),
                recipe.expected_gid(),
                retained_executable.as_raw_fd(),
                marker_write.as_raw_fd(),
                null.as_raw_fd(),
                expected_parent_pid,
            )
        }
    }
    if cloned < 0 || pidfd_raw < 0 {
        return Err(LinuxFixtureError::Clone3PidfdUnavailable);
    }
    let pid = c_int::try_from(cloned).map_err(|_| LinuxFixtureError::Clone3PidfdUnavailable)?;
    drop(marker_write);
    drop(null);
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
    let proc_dir = match open_proc_dir(pid) {
        Ok(fd) => fd,
        Err(_) => {
            let _ = kill_pidfd_and_reap(pidfd.as_raw_fd(), pid);
            return Err(LinuxFixtureError::PreExecIdentityDrift);
        }
    };
    let placeholder = digest_fields(
        b"org.trillionnium.provider-fixture-placeholder.v1\0",
        &[b"not-authority"],
    );
    let mut held = LinuxHeldProviderFixture {
        pid,
        pidfd,
        proc_dir,
        marker_read,
        retained_executable,
        _fixture: Some(fixture),
        recipe: Some(recipe),
        observation: HeldKernelObservation {
            provider: Provider::Codex,
            tgid: 0,
            starttime_ticks: 0,
            pidfd_identity_sha256: placeholder,
            final_runtime_executable_sha256: placeholder,
            runtime_maps_closure_sha256: placeholder,
            observed_uid: 0,
            observed_gid: 0,
            observed_selinux_domain_sha256: placeholder,
            observed_argv_sha256: placeholder,
            observed_environment_sha256: placeholder,
            observed_fd_table_sha256: placeholder,
            observed_cgroup_identity_sha256: placeholder,
            exec_event_identity_sha256: placeholder,
            pre_entry_barrier_identity_sha256: placeholder,
            hardening_event_identity_sha256: placeholder,
            exact_seccomp_filter_sha256: placeholder,
            procfs_nondump_owner_observed: false,
            exact_parent_dumpable_observation_available: false,
            target_selinux_verified: false,
            target_cgroup_verified: false,
            product_qualifies: false,
        },
        sink,
        pending_hold: LinuxFixtureHoldReason::PreExecIdentityDrift,
        force_cleanup_unknown: false,
        alive: true,
    };

    let provider = held.recipe.as_ref().expect("recipe").provider();
    let expected_uid = held.recipe.as_ref().expect("recipe").expected_uid();
    let expected_gid = held.recipe.as_ref().expect("recipe").expected_gid();
    let starttime_ticks = match wait_for_initial_stop_and_identity(&held) {
        Ok(starttime) => starttime,
        Err(error) => {
            return Err(held.fail(error, LinuxFixtureHoldReason::PreExecIdentityDrift));
        }
    };
    if ptrace_setoptions(pid, PTRACE_O_TRACEEXEC_VALUE | PTRACE_O_EXITKILL_VALUE).is_err()
        || ptrace_continue(pid, 0).is_err()
    {
        return Err(held.fail(
            LinuxFixtureError::FinalExecEventDrift,
            LinuxFixtureHoldReason::FinalExecEventDrift,
        ));
    }
    let exec_status = match waitpid_exact(pid) {
        Ok(status) if is_ptrace_exec_status(status) => status,
        _ => {
            return Err(held.fail(
                LinuxFixtureError::FinalExecEventDrift,
                LinuxFixtureHoldReason::FinalExecEventDrift,
            ));
        }
    };
    let exec_event_identity_sha256 = event_digest(
        b"org.trillionnium.provider-fixture-final-exec-event.v1\0",
        pid,
        starttime_ticks,
        exec_status,
        &[],
    );
    // A signal argument supplied to PTRACE_CONT from a PTRACE_EVENT_EXEC stop
    // is not a reliable signal-delivery injection point. Queue the barrier on
    // the exact clone3-returned pidfd while the child is still held, then
    // resume without injection so the pending SIGSTOP becomes its own
    // signal-delivery stop before final-runtime user code can execute.
    if pidfd_send_signal(held.pidfd.as_raw_fd(), libc::SIGSTOP).is_err()
        || ptrace_continue(pid, 0).is_err()
    {
        return Err(held.fail(
            LinuxFixtureError::PreEntryBarrierDrift,
            LinuxFixtureHoldReason::PreEntryBarrierDrift,
        ));
    }
    let pre_entry_status = match waitpid_exact(pid) {
        Ok(status) if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP => status,
        _ => {
            return Err(held.fail(
                LinuxFixtureError::PreEntryBarrierDrift,
                LinuxFixtureHoldReason::PreEntryBarrierDrift,
            ));
        }
    };
    let broker_pid = unsafe { libc::getpid() };
    let broker_uid = unsafe { libc::geteuid() };
    let pre_entry_siginfo = match ptrace_siginfo(pid) {
        Ok(info)
            if info.si_signo == libc::SIGSTOP
                && info.si_code == libc::SI_USER
                && unsafe { info.si_pid() } == broker_pid
                && unsafe { info.si_uid() } == broker_uid =>
        {
            info
        }
        _ => {
            return Err(held.fail(
                LinuxFixtureError::PreEntryBarrierDrift,
                LinuxFixtureHoldReason::PreEntryBarrierDrift,
            ));
        }
    };
    if marker_has_data(held.marker_read.as_raw_fd()).unwrap_or(true) {
        return Err(held.fail(
            LinuxFixtureError::EarlyUserCodeObserved,
            LinuxFixtureHoldReason::EarlyUserCodeObserved,
        ));
    }
    let pre_entry_siginfo_bytes = [
        pre_entry_siginfo.si_signo.to_be_bytes().as_slice(),
        pre_entry_siginfo.si_code.to_be_bytes().as_slice(),
        unsafe { pre_entry_siginfo.si_pid() }
            .to_be_bytes()
            .as_slice(),
        unsafe { pre_entry_siginfo.si_uid() }
            .to_be_bytes()
            .as_slice(),
    ]
    .concat();
    let pre_entry_barrier_identity_sha256 = event_digest(
        b"org.trillionnium.provider-fixture-pre-entry-barrier.v1\0",
        pid,
        starttime_ticks,
        pre_entry_status,
        &pre_entry_siginfo_bytes,
    );
    if ptrace_continue(pid, 0).is_err() {
        return Err(held.fail(
            LinuxFixtureError::HardeningStopDrift,
            LinuxFixtureHoldReason::HardeningStopDrift,
        ));
    }
    let hardening_status = match waitpid_exact(pid) {
        Ok(status) => status,
        Err(_) => {
            return Err(held.fail(
                LinuxFixtureError::HardeningStopDrift,
                LinuxFixtureHoldReason::HardeningStopDrift,
            ));
        }
    };
    if is_ptrace_exec_status(hardening_status) {
        return Err(held.fail(
            LinuxFixtureError::FinalExecEventDrift,
            LinuxFixtureHoldReason::FinalExecEventDrift,
        ));
    }
    let siginfo = match ptrace_siginfo(pid) {
        Ok(info)
            if libc::WIFSTOPPED(hardening_status)
                && libc::WSTOPSIG(hardening_status) == libc::SIGSTOP
                && info.si_code == libc::SI_TKILL
                && unsafe { info.si_pid() } == pid
                && unsafe { info.si_uid() } == expected_uid =>
        {
            info
        }
        _ => {
            return Err(held.fail(
                LinuxFixtureError::HardeningStopDrift,
                LinuxFixtureHoldReason::HardeningStopDrift,
            ));
        }
    };
    if marker_has_data(held.marker_read.as_raw_fd()).unwrap_or(true) {
        return Err(held.fail(
            LinuxFixtureError::EarlyUserCodeObserved,
            LinuxFixtureHoldReason::EarlyUserCodeObserved,
        ));
    }
    let siginfo_bytes = [
        siginfo.si_signo.to_be_bytes().as_slice(),
        siginfo.si_code.to_be_bytes().as_slice(),
    ]
    .concat();
    let hardening_event_identity_sha256 = event_digest(
        b"org.trillionnium.provider-fixture-hardening-event.v1\0",
        pid,
        starttime_ticks,
        hardening_status,
        &siginfo_bytes,
    );

    let exported_filter = match export_kernel_seccomp_filter(pid) {
        Ok(filter) => filter,
        Err(_) => {
            return Err(held.fail(
                LinuxFixtureError::ExactFilterReadbackUnavailable,
                LinuxFixtureHoldReason::ExactFilterReadbackUnavailable,
            ));
        }
    };
    let exported_filter_sha256 = seccomp_filter_sha256(&exported_filter);
    if exported_filter_sha256
        != held
            .recipe
            .as_ref()
            .expect("recipe")
            .exact_seccomp_filter_sha256()
        || exported_filter.as_slice() != exact_provider_seccomp_filter()
    {
        return Err(held.fail(
            LinuxFixtureError::ExactFilterMismatch,
            LinuxFixtureHoldReason::ExactFilterMismatch,
        ));
    }

    let observation = match observe_held_process(
        &held,
        provider,
        expected_uid,
        expected_gid,
        starttime_ticks,
        exec_event_identity_sha256,
        pre_entry_barrier_identity_sha256,
        hardening_event_identity_sha256,
        exported_filter_sha256,
    ) {
        Ok(observation) => observation,
        Err(error) => {
            eprintln!("held-process observation failed closed: {error}");
            return Err(held.fail(
                LinuxFixtureError::HeldObservationDrift,
                LinuxFixtureHoldReason::HeldObservationDrift,
            ));
        }
    };
    if observation.observed_argv_sha256
        != held
            .recipe
            .as_ref()
            .expect("recipe")
            .permitted_argv_sha256()
        || observation.observed_environment_sha256
            != held
                .recipe
                .as_ref()
                .expect("recipe")
                .permitted_environment_sha256()
        || observation.observed_fd_table_sha256
            != held
                .recipe
                .as_ref()
                .expect("recipe")
                .permitted_fd_table_sha256()
    {
        return Err(held.fail(
            LinuxFixtureError::HeldObservationDrift,
            LinuxFixtureHoldReason::HeldObservationDrift,
        ));
    }
    held.observation = observation;
    held.pending_hold = LinuxFixtureHoldReason::DropBeforeAdoption;
    Ok(held)
}

fn wait_for_initial_stop_and_identity(
    held: &LinuxHeldProviderFixture,
) -> Result<u64, LinuxFixtureError> {
    let status = waitpid_exact(held.pid).map_err(|_| LinuxFixtureError::PreExecIdentityDrift)?;
    if !libc::WIFSTOPPED(status) || libc::WSTOPSIG(status) != libc::SIGSTOP {
        return Err(LinuxFixtureError::PreExecIdentityDrift);
    }
    let first = read_proc_starttime(held.proc_dir.as_raw_fd())
        .map_err(|_| LinuxFixtureError::PreExecIdentityDrift)?;
    let second = read_proc_starttime(held.proc_dir.as_raw_fd())
        .map_err(|_| LinuxFixtureError::PreExecIdentityDrift)?;
    if first == 0 || first != second || pidfd_exited(held.pidfd.as_raw_fd()).unwrap_or(true) {
        return Err(LinuxFixtureError::PreExecIdentityDrift);
    }
    Ok(first)
}

#[allow(clippy::too_many_arguments)]
fn observe_held_process(
    held: &LinuxHeldProviderFixture,
    provider: Provider,
    expected_uid: u32,
    expected_gid: u32,
    expected_starttime: u64,
    exec_event_identity_sha256: Digest,
    pre_entry_barrier_identity_sha256: Digest,
    hardening_event_identity_sha256: Digest,
    exact_seccomp_filter_sha256: Digest,
) -> io::Result<HeldKernelObservation> {
    let first_starttime = read_proc_starttime(held.proc_dir.as_raw_fd())?;
    let status = read_proc_file(held.proc_dir.as_raw_fd(), "status")?;
    let second_starttime = read_proc_starttime(held.proc_dir.as_raw_fd())?;
    if first_starttime != expected_starttime || second_starttime != first_starttime {
        return Err(io::Error::other("starttime drift"));
    }
    let observed_uid = parse_status_identity(&status, "Uid:")?;
    let observed_gid = parse_status_identity(&status, "Gid:")?;
    let groups = status_values(&status, "Groups:")?.collect::<Vec<_>>();
    let caps_empty = ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"]
        .into_iter()
        .all(|key| matches!(parse_status_hex(&status, key), Ok(0)));
    if observed_uid != expected_uid
        || observed_gid != expected_gid
        || !groups.is_empty()
        || !caps_empty
        || parse_status_decimal(&status, "NoNewPrivs:")? != 1
        || parse_status_decimal(&status, "Seccomp:")? != 2
        || parse_status_decimal(&status, "Seccomp_filters:")? != 1
    {
        return Err(io::Error::other("hardening observation drift"));
    }
    // Linux deliberately preserves task ownership on the mode-0555
    // `/proc/<pid>` directory even for nondumpable tasks. The `exe` symlink is
    // not covered by that exception: root ownership distinguishes the
    // nondumpable {0,2} class from dumpable 1. It still cannot prove exact
    // dumpable 0, so this remains auxiliary host evidence only.
    let proc_exe_link_stat = fstatat_nofollow(held.proc_dir.as_raw_fd(), "exe")?;
    let procfs_nondump_owner_observed = (proc_exe_link_stat.st_mode & libc::S_IFMT)
        == libc::S_IFLNK
        && proc_exe_link_stat.st_uid == 0
        && proc_exe_link_stat.st_gid == 0;
    if !procfs_nondump_owner_observed {
        return Err(io::Error::other("procfs exe nondump ownership absent"));
    }
    let live_executable = open_proc_file(held.proc_dir.as_raw_fd(), "exe", libc::O_RDONLY)?;
    let live_stat = fstat(live_executable.as_raw_fd())?;
    let retained_stat = fstat(held.retained_executable.as_raw_fd())?;
    if live_stat.st_dev != retained_stat.st_dev || live_stat.st_ino != retained_stat.st_ino {
        return Err(io::Error::other("final executable fd identity drift"));
    }
    let final_runtime_executable_sha256 = sha256_fd(live_executable.as_raw_fd())?;
    if final_runtime_executable_sha256
        != held
            .recipe
            .as_ref()
            .expect("recipe")
            .final_runtime_executable_sha256()
    {
        return Err(io::Error::other("final executable bytes drift"));
    }
    let argv = read_proc_file_bytes(held.proc_dir.as_raw_fd(), "cmdline")?;
    let environment = read_proc_file_bytes(held.proc_dir.as_raw_fd(), "environ")?;
    let descriptors = fs::read_dir(format!("/proc/{}/fd", held.pid))?
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
    if descriptors != BTreeSet::from([0, 1, 2, 3]) {
        return Err(io::Error::other("fd table drift"));
    }
    let children =
        read_proc_file(held.proc_dir.as_raw_fd(), "task/self/children").or_else(|_| {
            fs::read_to_string(format!("/proc/{}/task/{}/children", held.pid, held.pid))
        })?;
    if !children.trim().is_empty() {
        return Err(io::Error::other("process descendant observed"));
    }
    let selinux = read_proc_file(held.proc_dir.as_raw_fd(), "attr/current")?;
    let cgroup = read_proc_file(held.proc_dir.as_raw_fd(), "cgroup")?;
    let maps = read_proc_file_bytes(held.proc_dir.as_raw_fd(), "maps")?;
    let pidfd_identity_sha256 =
        pidfd_identity(held.pidfd.as_raw_fd(), held.pid, expected_starttime)?;
    Ok(HeldKernelObservation {
        provider,
        tgid: held.pid as u32,
        starttime_ticks: expected_starttime,
        pidfd_identity_sha256,
        final_runtime_executable_sha256,
        runtime_maps_closure_sha256: digest_fields(
            b"org.trillionnium.provider-fixture-live-maps.v1\0",
            &[&maps],
        ),
        observed_uid,
        observed_gid,
        observed_selinux_domain_sha256: digest_fields(
            b"org.trillionnium.provider-fixture-selinux.v1\0",
            &[selinux.trim_end_matches(['\0', '\n']).as_bytes()],
        ),
        observed_argv_sha256: digest_fields(
            b"org.trillionnium.provider-fixture-argv.v1\0",
            &[&argv],
        ),
        observed_environment_sha256: digest_fields(
            b"org.trillionnium.provider-fixture-environment.v1\0",
            &[if environment.is_empty() {
                b"empty"
            } else {
                &environment
            }],
        ),
        observed_fd_table_sha256: digest_fields(
            b"org.trillionnium.provider-fixture-fd-table.v1\0",
            &[b"0:null", b"1:null", b"2:null", b"3:marker"],
        ),
        observed_cgroup_identity_sha256: digest_fields(
            b"org.trillionnium.provider-fixture-host-cgroup.v1\0",
            &[cgroup.as_bytes()],
        ),
        exec_event_identity_sha256,
        pre_entry_barrier_identity_sha256,
        hardening_event_identity_sha256,
        exact_seccomp_filter_sha256,
        procfs_nondump_owner_observed,
        // Procfs ownership cannot distinguish dumpable 0 from 2.
        exact_parent_dumpable_observation_available: false,
        // Host tests cannot prove target Android SELinux or fixed-leaf policy.
        target_selinux_verified: false,
        target_cgroup_verified: false,
        product_qualifies: false,
    })
}

unsafe fn child_setup_and_exec(
    provider: Provider,
    uid: u32,
    gid: u32,
    executable_fd: RawFd,
    marker_fd: RawFd,
    null_fd: RawFd,
    expected_parent_pid: libc::pid_t,
) -> ! {
    let exec_copy = unsafe { libc::fcntl(executable_fd, libc::F_DUPFD_CLOEXEC, 10) };
    let marker_copy = unsafe { libc::fcntl(marker_fd, libc::F_DUPFD_CLOEXEC, 10) };
    let null_copy = unsafe { libc::fcntl(null_fd, libc::F_DUPFD_CLOEXEC, 10) };
    if exec_copy < 0
        || marker_copy < 0
        || null_copy < 0
        || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
        || unsafe { libc::getppid() } != expected_parent_pid
        || unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) } != 0
        || drop_bounding_and_ambient_capabilities() != 0
        || unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(gid, gid, gid) } != 0
        || unsafe { libc::setresuid(uid, uid, uid) } != 0
        || clear_current_capabilities() != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        // Effective/fs credential changes clear PDEATHSIG. Re-arm it after
        // the final credential transition and immediately recheck parent
        // liveness before exposing any final descriptor or exec boundary.
        || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
        || unsafe { libc::getppid() } != expected_parent_pid
        || unsafe { libc::dup2(null_copy, libc::STDIN_FILENO) } < 0
        || unsafe { libc::dup2(null_copy, libc::STDOUT_FILENO) } < 0
        || unsafe { libc::dup2(null_copy, libc::STDERR_FILENO) } < 0
        || unsafe { libc::dup3(marker_copy, MARKER_FD, 0) } < 0
        || unsafe { libc::dup3(exec_copy, EXECUTABLE_FD, libc::O_CLOEXEC) } < 0
        || unsafe {
            libc::syscall(
                libc::SYS_close_range,
                5 as c_uint,
                c_uint::MAX,
                CLOSE_RANGE_UNSHARE,
            )
        } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                libc::getpid(),
                libc::syscall(libc::SYS_gettid),
                libc::SIGSTOP,
            )
        } != 0
    {
        unsafe { libc::_exit(127) }
    }
    let arg0 = c"trillionnium-final-runtime-fixture";
    let provider_arg = match provider {
        Provider::Codex => c"codex",
    };
    let arguments = [
        arg0.as_ptr(),
        provider_arg.as_ptr(),
        std::ptr::null::<c_char>(),
    ];
    let environment = [std::ptr::null::<c_char>()];
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

fn drop_bounding_and_ambient_capabilities() -> c_int {
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return -1;
    }
    for capability in 0..64 {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
            return -1;
        }
    }
    0
}

fn clear_current_capabilities() -> c_int {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: c_int,
    }
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) as c_int }
}

fn export_kernel_seccomp_filter(pid: libc::pid_t) -> io::Result<Vec<ClassicBpfInstruction>> {
    let measured_count = unsafe {
        libc::ptrace(
            PTRACE_SECCOMP_GET_FILTER_REQUEST,
            pid,
            0,
            std::ptr::null_mut::<libc::sock_filter>(),
        )
    };
    if measured_count <= 0 {
        return Err(io::Error::last_os_error());
    }
    let measured_count = usize::try_from(measured_count)
        .map_err(|_| io::Error::other("negative kernel seccomp filter length"))?;
    if measured_count > MAX_CLASSIC_BPF_INSTRUCTIONS {
        return Err(io::Error::other(
            "kernel seccomp filter exceeds the classic-BPF instruction bound",
        ));
    }
    let mut filters = vec![
        libc::sock_filter {
            code: 0,
            jt: 0,
            jf: 0,
            k: 0,
        };
        measured_count
    ];
    let exported_count = unsafe {
        libc::ptrace(
            PTRACE_SECCOMP_GET_FILTER_REQUEST,
            pid,
            0,
            filters.as_mut_ptr(),
        )
    };
    if exported_count != measured_count as libc::c_long {
        return Err(io::Error::other(
            "kernel seccomp filter length changed during export",
        ));
    }
    Ok(filters
        .into_iter()
        .map(|instruction| ClassicBpfInstruction {
            code: instruction.code,
            jump_true: instruction.jt,
            jump_false: instruction.jf,
            value: instruction.k,
        })
        .collect())
}

fn expected_argv_sha256(provider: Provider) -> Digest {
    let provider = match provider {
        Provider::Codex => b"codex".as_slice(),
    };
    let mut bytes = b"trillionnium-final-runtime-fixture\0".to_vec();
    bytes.extend_from_slice(provider);
    bytes.push(0);
    digest_fields(b"org.trillionnium.provider-fixture-argv.v1\0", &[&bytes])
}

fn expected_fd_table_sha256() -> Digest {
    digest_fields(
        b"org.trillionnium.provider-fixture-fd-table.v1\0",
        &[b"0:null", b"1:null", b"2:null", b"3:marker"],
    )
}

fn event_digest(
    domain: &[u8],
    pid: libc::pid_t,
    starttime_ticks: u64,
    status: c_int,
    extra: &[u8],
) -> Digest {
    let pid_bytes = (pid as u32).to_be_bytes();
    let starttime_bytes = starttime_ticks.to_be_bytes();
    let status_bytes = status.to_be_bytes();
    digest_fields(
        domain,
        &[&pid_bytes, &starttime_bytes, &status_bytes, extra],
    )
}

fn pidfd_identity(fd: RawFd, pid: libc::pid_t, starttime_ticks: u64) -> io::Result<Digest> {
    let stat = fstat(fd)?;
    let pid_bytes = (pid as u32).to_be_bytes();
    let starttime_bytes = starttime_ticks.to_be_bytes();
    let dev = stat.st_dev.to_be_bytes();
    let inode = stat.st_ino.to_be_bytes();
    Ok(digest_fields(
        b"org.trillionnium.provider-fixture-clone3-pidfd.v1\0",
        &[&pid_bytes, &starttime_bytes, &dev, &inode],
    ))
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Digest::new(FixedBytes32::new(bytes).expect("domain-separated digest is non-zero"))
}

fn command_status_with_deadline(
    command: &mut Command,
    timeout: Duration,
) -> io::Result<ExitStatus> {
    command.process_group(0).stdin(Stdio::null());
    let mut child = command.spawn()?;
    let process_group = c_int::try_from(child.id())
        .map_err(|_| io::Error::other("spawned command pid does not fit pid_t"))?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::other("external command deadline overflow"))?;

    loop {
        if Instant::now() >= deadline {
            terminate_process_group_and_reap(&mut child, process_group)?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "external command exceeded its absolute deadline",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                let _ = terminate_process_group_and_reap(&mut child, process_group);
                return Err(error);
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn terminate_process_group_and_reap(
    child: &mut Child,
    process_group: libc::pid_t,
) -> io::Result<()> {
    let kill_result = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    let kill_error = (kill_result != 0).then(io::Error::last_os_error);
    let deadline = Instant::now()
        .checked_add(WAIT_TIMEOUT)
        .ok_or_else(|| io::Error::other("external command reap deadline overflow"))?;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "killed external command was not reaped before its deadline",
            ));
        }
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if let Some(error) = kill_error
        && error.raw_os_error() != Some(libc::ESRCH)
    {
        return Err(error);
    }
    Ok(())
}

fn sha256_path(path: &Path) -> io::Result<Digest> {
    let file = fs::File::open(path)?;
    sha256_fd(file.as_raw_fd())
}

fn sha256_fd(fd: RawFd) -> io::Result<Digest> {
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
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
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Ok(Digest::new(
        FixedBytes32::new(bytes).expect("SHA-256 is non-zero"),
    ))
}

fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            OwnedFd::from_raw_fd(descriptors[0]),
            OwnedFd::from_raw_fd(descriptors[1]),
        )
    })
}

fn open_dev_null() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_proc_dir(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let path = CString::new(format!("/proc/{pid}")).map_err(io::Error::other)?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn open_proc_file(proc_dir: RawFd, name: &str, flags: c_int) -> io::Result<OwnedFd> {
    let name = CString::new(name).map_err(io::Error::other)?;
    let fd = unsafe { libc::openat(proc_dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn read_proc_file(proc_dir: RawFd, name: &str) -> io::Result<String> {
    String::from_utf8(read_proc_file_bytes(proc_dir, name)?).map_err(io::Error::other)
}

fn read_proc_file_bytes(proc_dir: RawFd, name: &str) -> io::Result<Vec<u8>> {
    let fd = open_proc_file(proc_dir, name, libc::O_RDONLY)?;
    let mut file = fs::File::from(fd);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_proc_starttime(proc_dir: RawFd) -> io::Result<u64> {
    let stat = read_proc_file(proc_dir, "stat")?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("invalid proc stat"))?;
    let fields = stat[close + 1..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or_else(|| io::Error::other("missing starttime"))?
        .parse::<u64>()
        .map_err(io::Error::other)
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
}

fn fstatat_nofollow(directory: RawFd, name: &str) -> io::Result<libc::stat> {
    let name = CString::new(name).map_err(io::Error::other)?;
    let mut stat = MaybeUninit::<libc::stat>::zeroed();
    if unsafe {
        libc::fstatat(
            directory,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn marker_has_data(fd: RawFd) -> io::Result<bool> {
    let mut byte = [0_u8; 1];
    let count = unsafe { libc::read(fd, byte.as_mut_ptr().cast::<c_void>(), byte.len()) };
    if count > 0 {
        return Ok(true);
    }
    if count == 0 {
        return Ok(false);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(error)
    }
}

fn ptrace_setoptions(pid: libc::pid_t, options: c_ulong) -> io::Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, options) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ptrace_continue(pid: libc::pid_t, signal: c_int) -> io::Result<()> {
    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, signal) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ptrace_siginfo(pid: libc::pid_t) -> io::Result<libc::siginfo_t> {
    let mut info = MaybeUninit::<libc::siginfo_t>::zeroed();
    if unsafe { libc::ptrace(libc::PTRACE_GETSIGINFO, pid, 0, info.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init() })
}

fn waitpid_exact(pid: libc::pid_t) -> io::Result<c_int> {
    waitpid_exact_until(pid, Instant::now() + WAIT_TIMEOUT)
}

fn waitpid_exact_until(pid: libc::pid_t, deadline: Instant) -> io::Result<c_int> {
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) if !remaining.is_zero() => remaining,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "waitpid deadline exceeded",
                ));
            }
        };
        let mut status = 0;
        let result = unsafe { libc::waitpid(pid, &mut status, libc::__WALL | libc::WNOHANG) };
        if result == pid {
            return Ok(status);
        }
        if result == 0 {
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
            continue;
        }
        if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io::Error::last_os_error());
    }
}

fn is_ptrace_exec_status(status: c_int) -> bool {
    libc::WIFSTOPPED(status)
        && libc::WSTOPSIG(status) == libc::SIGTRAP
        && status >> 16 == PTRACE_EVENT_EXEC_VALUE
}

fn pidfd_exited(pidfd: RawFd) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(result > 0)
}

fn pidfd_send_signal(pidfd: RawFd, signal: c_int) -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn kill_pidfd_and_reap(pidfd: RawFd, pid: libc::pid_t) -> io::Result<()> {
    if let Err(error) = pidfd_send_signal(pidfd, libc::SIGKILL)
        && error.raw_os_error() != Some(libc::ESRCH)
    {
        return Err(error);
    }
    let _ = ptrace_continue(pid, libc::SIGKILL);
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        match waitpid_exact_until(pid, deadline) {
            Ok(status) if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) => return Ok(()),
            Ok(_) => {
                let _ = ptrace_continue(pid, libc::SIGKILL);
            }
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
            Err(error) => return Err(error),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT_REENTRY_ENV: &str = "TRILLIONNIUM_PROVIDER_FIXTURE_ROOT_REENTRY";

    fn write_test_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_test_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn test_program_header_offset(bytes: &[u8], expected_type: u32) -> usize {
        let table_offset = usize::try_from(elf_u64(bytes, 32).expect("program offset"))
            .expect("bounded program offset");
        let entry_size = usize::from(elf_u16(bytes, 54).expect("program entry size"));
        let count = usize::from(elf_u16(bytes, 56).expect("program count"));
        (0..count)
            .map(|index| {
                checked_table_offset(table_offset, index, entry_size, 56, bytes.len())
                    .expect("bounded program header")
            })
            .find(|offset| elf_u32(bytes, *offset).expect("program type") == expected_type)
            .expect("expected program header")
    }

    fn test_section_header_offset(bytes: &[u8], expected_name: &str) -> usize {
        let table_offset = usize::try_from(elf_u64(bytes, 40).expect("section offset"))
            .expect("bounded section offset");
        let entry_size = usize::from(elf_u16(bytes, 58).expect("section entry size"));
        let count = usize::from(elf_u16(bytes, 60).expect("section count"));
        let names_index = usize::from(elf_u16(bytes, 62).expect("section names index"));
        let names_header =
            checked_table_offset(table_offset, names_index, entry_size, 64, bytes.len())
                .expect("bounded names header");
        let names_offset =
            usize::try_from(elf_u64(bytes, names_header + 24).expect("names offset"))
                .expect("bounded names offset");
        let names_size = usize::try_from(elf_u64(bytes, names_header + 32).expect("names size"))
            .expect("bounded names size");
        let names = elf_slice(bytes, names_offset, names_size).expect("bounded section names");
        (0..count)
            .map(|index| {
                checked_table_offset(table_offset, index, entry_size, 64, bytes.len())
                    .expect("bounded section header")
            })
            .find(|offset| {
                let name_offset =
                    usize::try_from(elf_u32(bytes, *offset).expect("section name offset"))
                        .expect("bounded section name offset");
                elf_c_string(names, name_offset).expect("valid section name") == expected_name
            })
            .expect("expected section header")
    }

    fn assert_elf_mutation_rejected(
        fixture: &BuiltFixture,
        provider: Provider,
        label: &str,
        mutate: impl FnOnce(&mut Vec<u8>),
    ) {
        let mut bytes = fs::read(&fixture.path).expect("read valid fixture");
        mutate(&mut bytes);
        let path = fixture
            .path
            .parent()
            .expect("fixture parent")
            .join(format!("mutated-{label}"));
        fs::write(&path, bytes).expect("write mutated fixture");
        assert_eq!(
            inspect_fixture_elf(&path, provider, fixture.mechanism),
            Err(LinuxFixtureError::FinalElfContractInvalid),
            "mutation {label} must fail closed"
        );
    }

    #[test]
    fn codex_host_build_and_elf_gate_rejects_drift_without_root() {
        let fixture = build_fixture(Provider::Codex, FixtureFault::None)
            .expect("non-root Codex controlled-entry build and gate");

        assert_elf_mutation_rejected(&fixture, Provider::Codex, "truncated", |bytes| {
            bytes.truncate(63);
        });
        assert_elf_mutation_rejected(&fixture, Provider::Codex, "wrong-entry", |bytes| {
            write_test_u64(bytes, 24, 0);
        });
        assert_elf_mutation_rejected(&fixture, Provider::Codex, "write-execute-load", |bytes| {
            let header = test_program_header_offset(bytes, 1);
            let flags = elf_u32(bytes, header + 4).expect("load flags");
            write_test_u32(bytes, header + 4, flags | 3);
        });
        assert_elf_mutation_rejected(&fixture, Provider::Codex, "executable-stack", |bytes| {
            let header = test_program_header_offset(bytes, 0x6474_e551);
            let flags = elf_u32(bytes, header + 4).expect("stack flags");
            write_test_u32(bytes, header + 4, flags | 1);
        });
        assert_elf_mutation_rejected(&fixture, Provider::Codex, "filter-byte", |bytes| {
            let header = test_section_header_offset(bytes, ".trillionnium.provider_filter");
            let offset = usize::try_from(elf_u64(bytes, header + 24).expect("filter offset"))
                .expect("bounded filter offset");
            bytes[offset] ^= 1;
        });
        assert_elf_mutation_rejected(&fixture, Provider::Codex, "filter-section-name", |bytes| {
            let header = test_section_header_offset(bytes, ".trillionnium.provider_filter");
            write_test_u32(bytes, header, 0);
        });
        assert_elf_mutation_rejected(&fixture, Provider::Codex, "residual-preinit", |bytes| {
            let header = test_section_header_offset(bytes, ".init_array");
            write_test_u32(bytes, header + 4, 16);
        });
        assert_elf_mutation_rejected(&fixture, Provider::Codex, "interpreter", |bytes| {
            let header = test_program_header_offset(bytes, 1);
            write_test_u32(bytes, header, 3);
        });
    }

    #[test]
    fn real_kernel_dynamic_static_and_fault_matrix() {
        if std::env::var(PRIVILEGED_FIXTURE_ENV).as_deref() != Ok("1") {
            eprintln!(
                "SKIP real privileged fixture: set {PRIVILEGED_FIXTURE_ENV}=1 to run the mandatory root lane"
            );
            return;
        }
        if unsafe { libc::geteuid() } != 0 {
            let executable = std::env::current_exe().expect("current test executable");
            let mut sudo = Command::new("sudo");
            sudo.arg("-n")
                .arg("env")
                .arg(format!("{PRIVILEGED_FIXTURE_ENV}=1"))
                .arg(format!("{ROOT_REENTRY_ENV}=1"))
                .arg(executable)
                .arg("--exact")
                .arg("linux_provider_post_exec_test_kernel::tests::real_kernel_dynamic_static_and_fault_matrix")
                .arg("--nocapture");
            let status = command_status_with_deadline(&mut sudo, EXTERNAL_COMMAND_TIMEOUT);
            match status {
                Ok(status) if status.success() => return,
                Ok(status) => panic!("privileged fixture re-entry failed: {status}"),
                Err(error) => panic!("privileged fixture sudo re-entry unavailable: {error}"),
            }
        }
        if let Ok(root_reentry) = std::env::var(ROOT_REENTRY_ENV) {
            assert_eq!(root_reentry, "1");
        }

        {
            let provider = Provider::Codex;
            let fixture = build_fixture(provider, FixtureFault::None)
                .expect("purpose-built provider-specific final ELF fixture");
            assert_ne!(fixture.elf_contract_sha256, fixture.executable_sha256);
            let mechanism = fixture.mechanism;
            let recipe = recipe_for_fixture(provider, &fixture);
            assert_eq!(recipe.mechanism(), mechanism);
            let sink = SharedHoldSink::default();
            let mut held = match launch_held_fixture(recipe, fixture, sink.clone()) {
                Ok(held) => held,
                Err(LinuxFixtureError::ExactFilterReadbackUnavailable) => {
                    assert_eq!(
                        sink.snapshot(),
                        vec![LinuxFixtureHoldReason::ExactFilterReadbackUnavailable]
                    );
                    panic!("mandatory privileged lane cannot export the installed exact filter");
                }
                Err(error) => panic!("real held fixture failed: {error:?}"),
            };
            assert_eq!(held.observation.provider, provider);
            assert!(held.observation.tgid > 1);
            assert_ne!(held.observation.starttime_ticks, 0);
            assert_ne!(
                held.observation.pidfd_identity_sha256,
                held.observation.exec_event_identity_sha256
            );
            assert_ne!(
                held.observation.runtime_maps_closure_sha256,
                held.observation.observed_selinux_domain_sha256
            );
            assert_eq!(
                (held.observation.observed_uid, held.observation.observed_gid),
                (
                    held.recipe.as_ref().expect("recipe").expected_uid(),
                    held.recipe.as_ref().expect("recipe").expected_gid()
                )
            );
            assert_ne!(
                held.observation.observed_cgroup_identity_sha256,
                held.observation.pre_entry_barrier_identity_sha256
            );
            assert_ne!(
                held.observation.exec_event_identity_sha256,
                held.observation.hardening_event_identity_sha256
            );
            assert_eq!(
                held.observation.final_runtime_executable_sha256,
                held.recipe
                    .as_ref()
                    .expect("recipe")
                    .final_runtime_executable_sha256()
            );
            assert_eq!(
                held.observation.exact_seccomp_filter_sha256,
                held.recipe
                    .as_ref()
                    .expect("recipe")
                    .exact_seccomp_filter_sha256()
            );
            assert!(held.observation.procfs_nondump_owner_observed);
            assert!(!held.observation.exact_parent_dumpable_observation_available);
            assert!(!held.observation.target_selinux_verified);
            assert!(!held.observation.target_cgroup_verified);
            assert!(!held.observation.product_qualifies);
            let markers = held
                .resume_and_collect_fixture_markers_for_test()
                .expect("thread-positive/process-negative fixture");
            assert_eq!(markers, vec![0x43, 0x54, 0x5a]);
            drop(held);
            assert_eq!(
                sink.snapshot(),
                vec![LinuxFixtureHoldReason::DropBeforeAdoption]
            );
        }

        for (fault, expected_error, expected_hold) in [
            (
                FixtureFault::EarlyUserMarker,
                LinuxFixtureError::EarlyUserCodeObserved,
                LinuxFixtureHoldReason::EarlyUserCodeObserved,
            ),
            (
                FixtureFault::DumpableNotReasserted,
                LinuxFixtureError::HardeningStopDrift,
                LinuxFixtureHoldReason::HardeningStopDrift,
            ),
            (
                FixtureFault::WrongFilter,
                LinuxFixtureError::ExactFilterMismatch,
                LinuxFixtureHoldReason::ExactFilterMismatch,
            ),
            (
                FixtureFault::WrongSignalSource,
                LinuxFixtureError::HardeningStopDrift,
                LinuxFixtureHoldReason::HardeningStopDrift,
            ),
            (
                FixtureFault::SecondExec,
                LinuxFixtureError::FinalExecEventDrift,
                LinuxFixtureHoldReason::FinalExecEventDrift,
            ),
        ] {
            let provider = Provider::Codex;
            let fixture = build_fixture(provider, fault).expect("fixture");
            let recipe = recipe_for_fixture(provider, &fixture);
            let sink = SharedHoldSink::default();
            let error = match launch_held_fixture(recipe, fixture, sink.clone()) {
                Ok(_) => panic!("fault must fail closed"),
                Err(error) => error,
            };
            assert_eq!(error, expected_error);
            assert_eq!(sink.snapshot(), vec![expected_hold]);
        }

        let fixture = build_fixture(Provider::Codex, FixtureFault::None).expect("fixture");
        let recipe = recipe_for_fixture(Provider::Codex, &fixture);
        let sink = SharedHoldSink::default();
        let mut held = launch_held_fixture(recipe, fixture, sink.clone()).expect("held fixture");
        held.force_cleanup_unknown = true;
        drop(held);
        assert_eq!(
            sink.snapshot(),
            vec![LinuxFixtureHoldReason::CleanupProofMissing]
        );

        let fixture = build_fixture(Provider::Codex, FixtureFault::None).expect("fixture");
        let recipe = recipe_for_fixture(Provider::Codex, &fixture);
        let sink = SharedHoldSink::default();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let sink = sink.clone();
            move || {
                let _held = launch_held_fixture(recipe, fixture, sink).expect("held fixture");
                panic!("injected callback unwind");
            }
        }));
        assert!(unwind.is_err());
        assert_eq!(
            sink.snapshot(),
            vec![LinuxFixtureHoldReason::DropBeforeAdoption]
        );
    }

    #[test]
    fn producer_is_test_only_affine_and_product_unwired() {
        let source = include_str!("linux_provider_post_exec_test_kernel.rs");
        let declaration = source
            .find("struct LinuxHeldProviderFixture")
            .expect("held fixture declaration");
        let derives = &source[declaration.saturating_sub(220)..declaration];
        assert!(!derives.contains("Clone"));
        assert!(!derives.contains("Copy"));
        assert!(!derives.contains("Serialize"));
        assert!(!derives.contains("Deserialize"));
        let library = include_str!("lib.rs");
        assert!(library.contains("#[cfg(all(test, target_os = \"linux\"))]"));
        let main = include_str!("main.rs");
        assert!(!main.contains("linux_provider_post_exec_test_kernel"));
        assert!(!main.contains("ClosedProviderFinalRuntimeBootstrapRecipe"));
        assert!(!source.contains(concat!("Provider", "EffectAdmission")));
        assert!(!source.contains(concat!("Broker", "Core")));
        assert!(!source.contains(concat!("linux_replay_sync_", "publisher_kernel")));
    }

    #[test]
    fn pre_entry_barrier_uses_exact_pidfd_and_every_waitpid_is_deadlined() {
        let source = include_str!("linux_provider_post_exec_test_kernel.rs");
        assert!(source.contains(concat!(
            "pidfd_send_signal(held.pidfd.as_raw_fd(), libc::",
            "SIGSTOP)"
        )));
        assert!(!source.contains(concat!("ptrace_continue(pid, libc::", "SIGSTOP)")));
        assert_eq!(source.matches(concat!("libc::", "waitpid(")).count(), 1);
        assert!(source.contains(concat!("libc::__WALL | libc::", "WNOHANG")));
        assert!(source.contains(concat!("checked_duration_", "since(Instant::now())")));
        let wait_helper = &source[source
            .find("fn waitpid_exact_until")
            .expect("deadline helper exists")..];
        assert!(
            wait_helper
                .find(concat!("checked_duration_", "since(Instant::now())"))
                .expect("deadline checked")
                < wait_helper
                    .find(concat!("libc::", "waitpid("))
                    .expect("single waitpid call")
        );
    }

    #[test]
    fn child_binds_exact_parent_and_rearms_parent_death_kill_after_credential_drop() {
        let source = include_str!("linux_provider_post_exec_test_kernel.rs");
        let launcher = &source[source
            .find("fn launch_held_fixture")
            .expect("fixture launcher exists")
            ..source
                .find("fn wait_for_initial_stop_and_identity")
                .expect("fixture launcher end exists")];
        let child_setup = &source[source
            .find("unsafe fn child_setup_and_exec")
            .expect("child setup exists")
            ..source
                .find("fn drop_bounding_and_ambient_capabilities")
                .expect("child setup end exists")];
        let pdeathsig = concat!("libc::PR_SET_", "PDEATHSIG");
        assert_eq!(child_setup.matches(pdeathsig).count(), 2);
        assert_eq!(
            child_setup
                .matches("libc::getppid() } != expected_parent_pid")
                .count(),
            2
        );
        assert!(!child_setup.contains("libc::getppid() } == 1"));
        assert!(
            launcher
                .find("let expected_parent_pid = unsafe { libc::getpid() };")
                .expect("exact parent captured")
                < launcher.find("libc::SYS_clone3").expect("clone3 boundary")
        );
        assert!(
            launcher
                .find("null.as_raw_fd(),\n                expected_parent_pid,")
                .is_some()
        );
        assert!(
            child_setup.rfind(pdeathsig).expect("post-drop rearm")
                > child_setup
                    .find("libc::setresuid")
                    .expect("credential drop")
        );
        assert!(
            child_setup.rfind(pdeathsig).expect("post-drop rearm")
                < child_setup
                    .find("libc::dup2(null_copy")
                    .expect("descriptor publication")
        );
    }

    #[test]
    fn filter_readback_failure_is_a_permanent_hold_not_mode_only_success() {
        assert_eq!(
            LinuxFixtureError::ExactFilterReadbackUnavailable.to_string(),
            "the kernel-installed exact seccomp filter could not be exported"
        );
        assert_ne!(
            LinuxFixtureHoldReason::ExactFilterReadbackUnavailable,
            LinuxFixtureHoldReason::ExactFilterMismatch
        );
    }

    #[test]
    fn static_musl_posix_spawn_uses_the_exact_inherited_filter_path() {
        let target = if cfg!(target_arch = "x86_64") {
            "x86_64-linux-musl"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-linux-musl"
        } else {
            eprintln!("SKIP static musl spawn fixture on an unsupported architecture");
            return;
        };
        let mut zig_version = Command::new("zig");
        zig_version
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if !matches!(
            command_status_with_deadline(&mut zig_version, EXTERNAL_COMMAND_TIMEOUT),
            Ok(status) if status.success()
        ) {
            eprintln!("SKIP static musl spawn fixture because Zig is unavailable");
            return;
        }

        let directory = tempfile::tempdir().expect("musl spawn fixture directory");
        let include_directory = directory.path().join("include");
        fs::create_dir(&include_directory).expect("musl spawn include directory");
        let header = include_directory.join("trillionnium_provider_post_exec_bootstrap.h");
        let core = directory.path().join("provider-post-exec-bootstrap.c");
        let fixture = directory
            .path()
            .join("provider-post-exec-musl-spawn-fixture.c");
        let executable = directory
            .path()
            .join("provider-post-exec-musl-spawn-fixture");
        fs::write(&header, BOOTSTRAP_HEADER_SOURCE).expect("write bootstrap header");
        fs::write(&core, BOOTSTRAP_CORE_SOURCE).expect("write bootstrap core");
        fs::write(&fixture, MUSL_SPAWN_FIXTURE_SOURCE).expect("write musl spawn fixture");

        let mut compiler = Command::new("zig");
        compiler
            .arg("cc")
            .arg("-target")
            .arg(target)
            .arg("-std=c11")
            .arg("-O2")
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-Werror")
            .arg("-static")
            .arg("-fno-stack-protector")
            .arg("-fno-lto")
            .arg("-I")
            .arg(&include_directory)
            .arg(format!(
                "-DTRILLIONNIUM_PROVIDER_FILTER_INSTRUCTION_COUNT={}",
                exact_provider_seccomp_filter().len()
            ))
            .arg("-DTRILLIONNIUM_EXPECTED_UID=0")
            .arg("-DTRILLIONNIUM_EXPECTED_GID=0")
            .arg(&core)
            .arg(&fixture)
            .arg("-o")
            .arg(&executable)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = command_status_with_deadline(&mut compiler, EXTERNAL_COMMAND_TIMEOUT)
            .expect("compile exact static-musl spawn fixture");
        assert!(status.success(), "static-musl spawn fixture compilation");

        let mut run = Command::new(&executable);
        run.env_clear().stdout(Stdio::null()).stderr(Stdio::null());
        let status = command_status_with_deadline(&mut run, EXTERNAL_COMMAND_TIMEOUT)
            .expect("run exact static-musl spawn fixture");
        assert!(
            status.success(),
            "musl posix_spawn and post-exec dumpability re-hardening must pass under the exact filter: {status}"
        );
    }

    #[test]
    fn external_command_timeout_kills_the_process_group_and_reaps_the_leader() {
        let directory = tempfile::tempdir().expect("timeout fixture directory");
        let leaked_marker = directory.path().join("descendant-survived");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("(sleep 1; printf leaked > \"$1\") & wait")
            .arg("sh")
            .arg(&leaked_marker);
        let started = Instant::now();
        let error = command_status_with_deadline(&mut command, Duration::from_millis(50))
            .expect_err("sleeping process group must time out");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(
            !leaked_marker.exists(),
            "timeout leaked a descendant outside group cleanup"
        );

        let source = include_str!("linux_provider_post_exec_test_kernel.rs");
        assert!(!source.contains(concat!(".sta", "tus()")));
        assert!(source.contains("process_group(0)"));
        assert!(source.contains("libc::kill(-process_group, libc::SIGKILL)"));
    }
}
