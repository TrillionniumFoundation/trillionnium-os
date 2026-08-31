//! Serializable source contracts for exact built-in provider post-exec
//! seccomp containment.
//!
//! This module contains data and validation only. It cannot create launch,
//! process or effect authority; product observers remain unavailable.

use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::agent_descriptor_registry::{self, CODEX};
use crate::direct_operation::ProviderCgroupResourcePolicyV1;

pub const SECCOMP_PROFILE_V1_SCHEMA: &str = "trillionnium.provider-seccomp-profile.v1";
pub const SECCOMP_INSTALLATION_RECIPE_V1_SCHEMA: &str =
    "trillionnium.provider-seccomp-installation-recipe.v1";
pub const REMOTE_DUMPABLE_EVIDENCE_V1_SCHEMA: &str =
    "trillionnium.provider-remote-dumpable-evidence.v1";
pub const ATOMIC_CGROUP_PLACEMENT_EVIDENCE_V1_SCHEMA: &str =
    "trillionnium.provider-atomic-cgroup-placement-evidence.v1";
pub const POST_EXEC_OBSERVATION_V1_SCHEMA: &str = "trillionnium.provider-post-exec-observation.v1";

pub const SOURCE_SERIALIZABLE_SECCOMP_CONTRACT_IMPLEMENTED: bool = true;
pub const SOURCE_EXACT_SECCOMP_PROGRAM_BOUND: bool = true;
pub const SOURCE_PROVIDER_SEPARATED_RECIPE_IMPLEMENTED: bool = true;
pub const PRODUCT_EXACT_SECCOMP_OBSERVER_AVAILABLE: bool = false;
pub const PRODUCT_REMOTE_DUMPABLE_OBSERVER_AVAILABLE: bool = false;
pub const PRODUCT_ATOMIC_CGROUP_PLACEMENT_OBSERVER_AVAILABLE: bool = false;
pub const PRODUCT_POST_EXEC_OBSERVATION_AUTHORITY_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

const FILTER_DIGEST_DOMAIN: &[u8] = b"org.trillionnium.provider-post-final-exec-seccomp-cbpf.v1\0";
const PROFILE_DIGEST_DOMAIN: &[u8] = b"org.trillionnium.provider-seccomp-profile.v1\0";
const RECIPE_DIGEST_DOMAIN: &[u8] = b"org.trillionnium.provider-seccomp-installation-recipe.v1\0";
const DUMPABLE_DIGEST_DOMAIN: &[u8] = b"org.trillionnium.provider-remote-dumpable-evidence.v1\0";
const CGROUP_DIGEST_DOMAIN: &[u8] =
    b"org.trillionnium.provider-atomic-cgroup-placement-evidence.v1\0";
const OBSERVATION_DIGEST_DOMAIN: &[u8] = b"org.trillionnium.provider-post-exec-observation.v1\0";

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;
const SECCOMP_RET_ERRNO_ENOSYS: u32 = 0x0005_0026;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const ABSENT_SYSCALL: u32 = u32::MAX;
const REQUIRED_PTHREAD_CLONE_FLAGS: u32 = 0x0001_0900;
const FORBIDDEN_PROCESS_CLONE_FLAGS: u32 = 0x7ec2_f0ff;
const EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS: u32 = 0x0000_4111;
const EXACT_FILTER_INSTRUCTION_COUNT: usize = 37;

pub type ProviderSeccompContractResult<T> = Result<T, ProviderSeccompContractError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderSeccompContractError(&'static str);

impl ProviderSeccompContractError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ProviderSeccompContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for ProviderSeccompContractError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSeccompAuditArchV1 {
    X86_64,
    Aarch64,
}

impl LinuxSeccompAuditArchV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }

    const fn audit_arch(self) -> u32 {
        match self {
            Self::X86_64 => AUDIT_ARCH_X86_64,
            Self::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }

    const fn x32_bit(self) -> u32 {
        match self {
            Self::X86_64 => 0x4000_0000,
            Self::Aarch64 => 0,
        }
    }

    const fn denied_syscalls(self) -> [u32; 4] {
        match self {
            Self::X86_64 => [56, 435, 57, 58],
            Self::Aarch64 => [220, 435, ABSENT_SYSCALL, ABSENT_SYSCALL],
        }
    }

    const fn prctl_syscall(self) -> u32 {
        match self {
            Self::X86_64 => 157,
            Self::Aarch64 => 167,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderFinalRuntimeBootstrapMechanismV1 {
    ControlledElfEntryTrampolineBeforeCrt,
    DynamicElfPreinitAfterBoundLoader,
}

impl ProviderFinalRuntimeBootstrapMechanismV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ControlledElfEntryTrampolineBeforeCrt => {
                "controlled_elf_entry_trampoline_before_crt"
            }
            Self::DynamicElfPreinitAfterBoundLoader => "dynamic_elf_preinit_after_bound_loader",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSeccompInstallationApiV1 {
    PrctlSetSeccompFilter,
}

impl ProviderSeccompInstallationApiV1 {
    const fn as_str(self) -> &'static str {
        "prctl_set_seccomp_filter"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPostExecObservationAuthorityV1 {
    PrivilegeBrokerPidfdPtraceHeld,
}

impl ProviderPostExecObservationAuthorityV1 {
    const fn as_str(self) -> &'static str {
        "privilege_broker_pidfd_ptrace_held"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRemoteDumpableObservationAuthorityV1 {
    PrivilegeBrokerRemotePrctlGetDumpable,
}

impl ProviderRemoteDumpableObservationAuthorityV1 {
    const fn as_str(self) -> &'static str {
        "privilege_broker_remote_prctl_get_dumpable"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCgroupPlacementObservationAuthorityV1 {
    Clone3IntoCgroupRetainedDirfd,
}

impl ProviderCgroupPlacementObservationAuthorityV1 {
    const fn as_str(self) -> &'static str {
        "clone3_into_cgroup_retained_dirfd"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassicBpfInstructionV1 {
    pub code: u16,
    pub jump_true: u8,
    pub jump_false: u8,
    pub value: u32,
}

const fn statement(code: u16, value: u32) -> ClassicBpfInstructionV1 {
    ClassicBpfInstructionV1 {
        code,
        jump_true: 0,
        jump_false: 0,
        value,
    }
}

const fn jump(code: u16, value: u32, jt: u8, jf: u8) -> ClassicBpfInstructionV1 {
    ClassicBpfInstructionV1 {
        code,
        jump_true: jt,
        jump_false: jf,
        value,
    }
}

const fn exact_filter(
    arch: LinuxSeccompAuditArchV1,
) -> [ClassicBpfInstructionV1; EXACT_FILTER_INSTRUCTION_COUNT] {
    let denied = arch.denied_syscalls();
    [
        statement(BPF_LD_W_ABS, 4),
        jump(BPF_JMP_JEQ_K, arch.audit_arch(), 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, 0),
        statement(BPF_ALU_AND_K, arch.x32_bit()),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, 0),
        jump(BPF_JMP_JEQ_K, denied[1], 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_ENOSYS),
        jump(BPF_JMP_JEQ_K, denied[2], 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        jump(BPF_JMP_JEQ_K, denied[3], 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        jump(BPF_JMP_JEQ_K, arch.prctl_syscall(), 0, 7),
        statement(BPF_LD_W_ABS, 16),
        jump(BPF_JMP_JEQ_K, 4, 0, 5),
        statement(BPF_LD_W_ABS, 28),
        jump(BPF_JMP_JEQ_K, 0, 0, 2),
        statement(BPF_LD_W_ABS, 24),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        statement(BPF_LD_W_ABS, 0),
        jump(BPF_JMP_JEQ_K, denied[0], 0, 12),
        statement(BPF_LD_W_ABS, 20),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        statement(BPF_LD_W_ABS, 16),
        jump(BPF_JMP_JEQ_K, EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS, 7, 0),
        statement(BPF_LD_W_ABS, 16),
        statement(BPF_ALU_AND_K, REQUIRED_PTHREAD_CLONE_FLAGS),
        jump(BPF_JMP_JEQ_K, REQUIRED_PTHREAD_CLONE_FLAGS, 0, 3),
        statement(BPF_LD_W_ABS, 16),
        statement(BPF_ALU_AND_K, FORBIDDEN_PROCESS_CLONE_FLAGS),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderSeccompProfileV1 {
    pub schema: String,
    pub provider_id: String,
    pub audit_arch: LinuxSeccompAuditArchV1,
    pub instruction_count: u16,
    pub instructions: Vec<ClassicBpfInstructionV1>,
    pub filter_program_sha256: String,
    pub profile_sha256: String,
}

impl ProviderSeccompProfileV1 {
    pub fn exact_builtin(
        provider_id: &str,
        audit_arch: LinuxSeccompAuditArchV1,
    ) -> ProviderSeccompContractResult<Self> {
        require_builtin(provider_id)?;
        let instructions = exact_filter(audit_arch).to_vec();
        let mut value = Self {
            schema: SECCOMP_PROFILE_V1_SCHEMA.to_string(),
            provider_id: provider_id.to_string(),
            audit_arch,
            instruction_count: EXACT_FILTER_INSTRUCTION_COUNT as u16,
            filter_program_sha256: filter_sha256(&instructions),
            instructions,
            profile_sha256: String::new(),
        };
        value.profile_sha256 = value.expected_sha256()?;
        value.validate_for(provider_id, audit_arch)?;
        Ok(value)
    }

    pub fn validate_for(
        &self,
        provider_id: &str,
        audit_arch: LinuxSeccompAuditArchV1,
    ) -> ProviderSeccompContractResult<()> {
        require_builtin(provider_id)?;
        if self.schema != SECCOMP_PROFILE_V1_SCHEMA
            || self.provider_id != provider_id
            || self.audit_arch != audit_arch
            || usize::from(self.instruction_count) != EXACT_FILTER_INSTRUCTION_COUNT
            || self.instructions.as_slice() != exact_filter(audit_arch)
            || self.filter_program_sha256 != filter_sha256(&self.instructions)
            || !valid_sha256(&self.profile_sha256)
            || self.profile_sha256 != self.expected_sha256()?
        {
            return Err(denied("provider_seccomp_profile_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> ProviderSeccompContractResult<String> {
        self.validate_for(&self.provider_id, self.audit_arch)?;
        Ok(self.profile_sha256.clone())
    }

    fn expected_sha256(&self) -> ProviderSeccompContractResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_DIGEST_DOMAIN);
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "provider_id", &self.provider_id)?;
        hash_string(&mut hasher, "audit_arch", self.audit_arch.as_str())?;
        hash_u16(&mut hasher, "instruction_count", self.instruction_count)?;
        hash_string(
            &mut hasher,
            "filter_program_sha256",
            &self.filter_program_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderSeccompInstallationRecipeV1 {
    pub schema: String,
    pub provider_id: String,
    pub audit_arch: LinuxSeccompAuditArchV1,
    pub bootstrap_mechanism: ProviderFinalRuntimeBootstrapMechanismV1,
    pub expected_uid: u32,
    pub expected_gid: u32,
    pub expected_selinux_domain_sha256: String,
    pub final_runtime_executable_sha256: String,
    pub final_runtime_closure_sha256: String,
    pub permitted_argv_sha256: String,
    pub permitted_environment_sha256: String,
    pub permitted_fd_table_sha256: String,
    pub seccomp_profile: ProviderSeccompProfileV1,
    pub installation_api: ProviderSeccompInstallationApiV1,
    pub installation_flags: u32,
    pub required_dumpable: u8,
    pub required_no_new_privs: u8,
    pub expected_seccomp_mode: u8,
    pub post_install_tgkill_self_sigstop: bool,
    pub recipe_sha256: String,
}

impl ProviderSeccompInstallationRecipeV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn exact_builtin(
        provider_id: &str,
        audit_arch: LinuxSeccompAuditArchV1,
        final_runtime_executable_sha256: String,
        final_runtime_closure_sha256: String,
        permitted_argv_sha256: String,
        permitted_environment_sha256: String,
        permitted_fd_table_sha256: String,
    ) -> ProviderSeccompContractResult<Self> {
        let descriptor = require_builtin(provider_id)?;
        let mut value = Self {
            schema: SECCOMP_INSTALLATION_RECIPE_V1_SCHEMA.to_string(),
            provider_id: provider_id.to_string(),
            audit_arch,
            bootstrap_mechanism: required_mechanism(provider_id)?,
            expected_uid: descriptor.uid,
            expected_gid: descriptor.gid,
            expected_selinux_domain_sha256: sha256_bytes(
                descriptor.agent_selinux_domain.as_bytes(),
            ),
            final_runtime_executable_sha256,
            final_runtime_closure_sha256,
            permitted_argv_sha256,
            permitted_environment_sha256,
            permitted_fd_table_sha256,
            seccomp_profile: ProviderSeccompProfileV1::exact_builtin(provider_id, audit_arch)?,
            installation_api: ProviderSeccompInstallationApiV1::PrctlSetSeccompFilter,
            installation_flags: 0,
            required_dumpable: 0,
            required_no_new_privs: 1,
            expected_seccomp_mode: 2,
            post_install_tgkill_self_sigstop: true,
            recipe_sha256: String::new(),
        };
        value.recipe_sha256 = value.expected_sha256()?;
        value.validate_for(provider_id, audit_arch)?;
        Ok(value)
    }

    pub fn validate_for(
        &self,
        provider_id: &str,
        audit_arch: LinuxSeccompAuditArchV1,
    ) -> ProviderSeccompContractResult<()> {
        let descriptor = require_builtin(provider_id)?;
        self.seccomp_profile.validate_for(provider_id, audit_arch)?;
        let bound_digests = [
            self.expected_selinux_domain_sha256.as_str(),
            self.final_runtime_executable_sha256.as_str(),
            self.final_runtime_closure_sha256.as_str(),
            self.permitted_argv_sha256.as_str(),
            self.permitted_environment_sha256.as_str(),
            self.permitted_fd_table_sha256.as_str(),
            self.seccomp_profile.profile_sha256.as_str(),
        ];
        if self.schema != SECCOMP_INSTALLATION_RECIPE_V1_SCHEMA
            || self.provider_id != provider_id
            || self.audit_arch != audit_arch
            || self.bootstrap_mechanism != required_mechanism(provider_id)?
            || self.expected_uid != descriptor.uid
            || self.expected_gid != descriptor.gid
            || self.expected_selinux_domain_sha256
                != sha256_bytes(descriptor.agent_selinux_domain.as_bytes())
            || self.installation_api != ProviderSeccompInstallationApiV1::PrctlSetSeccompFilter
            || self.installation_flags != 0
            || self.required_dumpable != 0
            || self.required_no_new_privs != 1
            || self.expected_seccomp_mode != 2
            || !self.post_install_tgkill_self_sigstop
            || !bound_digests.iter().copied().all(valid_sha256)
            || !all_distinct(&bound_digests)
            || !valid_sha256(&self.recipe_sha256)
            || self.recipe_sha256 != self.expected_sha256()?
        {
            return Err(denied("provider_seccomp_installation_recipe_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> ProviderSeccompContractResult<String> {
        self.validate_for(&self.provider_id, self.audit_arch)?;
        Ok(self.recipe_sha256.clone())
    }

    fn expected_sha256(&self) -> ProviderSeccompContractResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(RECIPE_DIGEST_DOMAIN);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("provider_id", self.provider_id.as_str()),
            ("audit_arch", self.audit_arch.as_str()),
            ("bootstrap_mechanism", self.bootstrap_mechanism.as_str()),
            (
                "expected_selinux_domain_sha256",
                self.expected_selinux_domain_sha256.as_str(),
            ),
            (
                "final_runtime_executable_sha256",
                self.final_runtime_executable_sha256.as_str(),
            ),
            (
                "final_runtime_closure_sha256",
                self.final_runtime_closure_sha256.as_str(),
            ),
            ("permitted_argv_sha256", self.permitted_argv_sha256.as_str()),
            (
                "permitted_environment_sha256",
                self.permitted_environment_sha256.as_str(),
            ),
            (
                "permitted_fd_table_sha256",
                self.permitted_fd_table_sha256.as_str(),
            ),
            (
                "seccomp_profile_sha256",
                self.seccomp_profile.profile_sha256.as_str(),
            ),
            ("installation_api", self.installation_api.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        for (name, value) in [
            ("expected_uid", self.expected_uid),
            ("expected_gid", self.expected_gid),
            ("installation_flags", self.installation_flags),
        ] {
            hash_u32(&mut hasher, name, value)?;
        }
        for (name, value) in [
            ("required_dumpable", self.required_dumpable),
            ("required_no_new_privs", self.required_no_new_privs),
            ("expected_seccomp_mode", self.expected_seccomp_mode),
        ] {
            hash_u8(&mut hasher, name, value)?;
        }
        hash_bool(
            &mut hasher,
            "post_install_tgkill_self_sigstop",
            self.post_install_tgkill_self_sigstop,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Candidate evidence for an exact remote `PR_GET_DUMPABLE == 0` observation.
///
/// The current broker has no product producer for this record. In particular,
/// procfs ownership and `Seccomp: 2` cannot construct it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderRemoteDumpableEvidenceV1 {
    pub schema: String,
    pub authority: ProviderRemoteDumpableObservationAuthorityV1,
    pub provider_id: String,
    pub provider_pid: u32,
    pub provider_start_time_ticks: u64,
    pub provider_pidfd_identity_sha256: String,
    pub observed_dumpable: u8,
    pub task_stopped: bool,
    pub evidence_sha256: String,
}

impl ProviderRemoteDumpableEvidenceV1 {
    pub fn candidate(
        provider_id: &str,
        provider_pid: u32,
        provider_start_time_ticks: u64,
        provider_pidfd_identity_sha256: String,
    ) -> ProviderSeccompContractResult<Self> {
        require_builtin(provider_id)?;
        let mut value = Self {
            schema: REMOTE_DUMPABLE_EVIDENCE_V1_SCHEMA.to_string(),
            authority:
                ProviderRemoteDumpableObservationAuthorityV1::PrivilegeBrokerRemotePrctlGetDumpable,
            provider_id: provider_id.to_string(),
            provider_pid,
            provider_start_time_ticks,
            provider_pidfd_identity_sha256,
            observed_dumpable: 0,
            task_stopped: true,
            evidence_sha256: String::new(),
        };
        value.evidence_sha256 = value.expected_sha256()?;
        value.validate_for(provider_id, provider_pid, provider_start_time_ticks)?;
        Ok(value)
    }

    fn validate_for(
        &self,
        provider_id: &str,
        provider_pid: u32,
        provider_start_time_ticks: u64,
    ) -> ProviderSeccompContractResult<()> {
        if self.schema != REMOTE_DUMPABLE_EVIDENCE_V1_SCHEMA
            || self.authority
                != ProviderRemoteDumpableObservationAuthorityV1::PrivilegeBrokerRemotePrctlGetDumpable
            || self.provider_id != provider_id
            || self.provider_pid != provider_pid
            || self.provider_start_time_ticks != provider_start_time_ticks
            || !valid_process_identity(
                self.provider_pid,
                self.provider_start_time_ticks,
                &self.provider_pidfd_identity_sha256,
            )
            || self.observed_dumpable != 0
            || !self.task_stopped
            || !valid_sha256(&self.evidence_sha256)
            || self.evidence_sha256 != self.expected_sha256()?
        {
            return Err(denied("provider_remote_dumpable_evidence_denied"));
        }
        Ok(())
    }

    fn expected_sha256(&self) -> ProviderSeccompContractResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(DUMPABLE_DIGEST_DOMAIN);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("authority", self.authority.as_str()),
            ("provider_id", self.provider_id.as_str()),
            (
                "provider_pidfd_identity_sha256",
                self.provider_pidfd_identity_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u32(&mut hasher, "provider_pid", self.provider_pid)?;
        hash_u64(
            &mut hasher,
            "provider_start_time_ticks",
            self.provider_start_time_ticks,
        )?;
        hash_u8(&mut hasher, "observed_dumpable", self.observed_dumpable)?;
        hash_bool(&mut hasher, "task_stopped", self.task_stopped)?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Candidate evidence that one pidfd-bound task was atomically born in the
/// retained runtime cgroup and that every typed resource control was read back.
/// The current product broker does not construct this record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderAtomicCgroupPlacementEvidenceV1 {
    pub schema: String,
    pub authority: ProviderCgroupPlacementObservationAuthorityV1,
    pub provider_id: String,
    pub provider_pid: u32,
    pub provider_start_time_ticks: u64,
    pub provider_pidfd_identity_sha256: String,
    pub clone3_into_cgroup_used: bool,
    pub retained_runtime_leaf_dirfd: bool,
    pub exact_resource_readback_complete: bool,
    pub observed_resource_policy: ProviderCgroupResourcePolicyV1,
    pub runtime_leaf_fd_identity_sha256: String,
    pub atomic_placement_proof_sha256: String,
    pub evidence_sha256: String,
}

impl ProviderAtomicCgroupPlacementEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn candidate(
        provider_id: &str,
        provider_pid: u32,
        provider_start_time_ticks: u64,
        provider_pidfd_identity_sha256: String,
        observed_resource_policy: ProviderCgroupResourcePolicyV1,
        runtime_leaf_fd_identity_sha256: String,
        atomic_placement_proof_sha256: String,
    ) -> ProviderSeccompContractResult<Self> {
        require_builtin(provider_id)?;
        observed_resource_policy
            .validate_for(provider_id)
            .map_err(|_| denied("provider_cgroup_resource_policy_denied"))?;
        let mut value = Self {
            schema: ATOMIC_CGROUP_PLACEMENT_EVIDENCE_V1_SCHEMA.to_string(),
            authority: ProviderCgroupPlacementObservationAuthorityV1::Clone3IntoCgroupRetainedDirfd,
            provider_id: provider_id.to_string(),
            provider_pid,
            provider_start_time_ticks,
            provider_pidfd_identity_sha256,
            clone3_into_cgroup_used: true,
            retained_runtime_leaf_dirfd: true,
            exact_resource_readback_complete: true,
            observed_resource_policy,
            runtime_leaf_fd_identity_sha256,
            atomic_placement_proof_sha256,
            evidence_sha256: String::new(),
        };
        value.evidence_sha256 = value.expected_sha256()?;
        value.validate_for(
            provider_id,
            provider_pid,
            provider_start_time_ticks,
            &value.observed_resource_policy,
        )?;
        Ok(value)
    }

    fn validate_for(
        &self,
        provider_id: &str,
        provider_pid: u32,
        provider_start_time_ticks: u64,
        expected_resource_policy: &ProviderCgroupResourcePolicyV1,
    ) -> ProviderSeccompContractResult<()> {
        self.observed_resource_policy
            .validate_for(provider_id)
            .map_err(|_| denied("provider_cgroup_resource_policy_denied"))?;
        if self.schema != ATOMIC_CGROUP_PLACEMENT_EVIDENCE_V1_SCHEMA
            || self.authority
                != ProviderCgroupPlacementObservationAuthorityV1::Clone3IntoCgroupRetainedDirfd
            || self.provider_id != provider_id
            || self.provider_pid != provider_pid
            || self.provider_start_time_ticks != provider_start_time_ticks
            || !valid_process_identity(
                self.provider_pid,
                self.provider_start_time_ticks,
                &self.provider_pidfd_identity_sha256,
            )
            || !self.clone3_into_cgroup_used
            || !self.retained_runtime_leaf_dirfd
            || !self.exact_resource_readback_complete
            || &self.observed_resource_policy != expected_resource_policy
            || !valid_sha256(&self.runtime_leaf_fd_identity_sha256)
            || !valid_sha256(&self.atomic_placement_proof_sha256)
            || self.runtime_leaf_fd_identity_sha256 == self.atomic_placement_proof_sha256
            || !valid_sha256(&self.evidence_sha256)
            || self.evidence_sha256 != self.expected_sha256()?
        {
            return Err(denied("provider_atomic_cgroup_placement_evidence_denied"));
        }
        Ok(())
    }

    fn expected_sha256(&self) -> ProviderSeccompContractResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(CGROUP_DIGEST_DOMAIN);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("authority", self.authority.as_str()),
            ("provider_id", self.provider_id.as_str()),
            (
                "provider_pidfd_identity_sha256",
                self.provider_pidfd_identity_sha256.as_str(),
            ),
            (
                "observed_resource_policy_sha256",
                self.observed_resource_policy.policy_sha256.as_str(),
            ),
            (
                "runtime_leaf_fd_identity_sha256",
                self.runtime_leaf_fd_identity_sha256.as_str(),
            ),
            (
                "atomic_placement_proof_sha256",
                self.atomic_placement_proof_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u32(&mut hasher, "provider_pid", self.provider_pid)?;
        hash_u64(
            &mut hasher,
            "provider_start_time_ticks",
            self.provider_start_time_ticks,
        )?;
        for (name, value) in [
            ("clone3_into_cgroup_used", self.clone3_into_cgroup_used),
            (
                "retained_runtime_leaf_dirfd",
                self.retained_runtime_leaf_dirfd,
            ),
            (
                "exact_resource_readback_complete",
                self.exact_resource_readback_complete,
            ),
        ] {
            hash_bool(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Complete pidfd-bound post-exec observation data for one held final runtime.
///
/// Optional proof fields deliberately deserialize as `None`: old or partial
/// records can be quarantined with a stable denial code, but can never validate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderPostExecObservationV1 {
    pub schema: String,
    pub authority: ProviderPostExecObservationAuthorityV1,
    pub provider_id: String,
    pub audit_arch: LinuxSeccompAuditArchV1,
    pub recipe_sha256: String,
    pub seccomp_profile_sha256: String,
    pub provider_pid: u32,
    pub provider_start_time_before_ticks: u64,
    pub provider_start_time_after_ticks: u64,
    pub provider_pidfd_identity_sha256: String,
    pub task_stopped: bool,
    pub pidfd_not_exited: bool,
    pub final_exec_event_identity_sha256: String,
    pub hardening_stop_event_identity_sha256: String,
    pub observed_no_new_privs: u8,
    pub observed_seccomp_mode: u8,
    pub observed_seccomp_profile_sha256: String,
    #[serde(default)]
    pub exact_seccomp_filter_observation_sha256: Option<String>,
    #[serde(default)]
    pub remote_dumpable_evidence: Option<ProviderRemoteDumpableEvidenceV1>,
    #[serde(default)]
    pub atomic_cgroup_placement_evidence: Option<ProviderAtomicCgroupPlacementEvidenceV1>,
    pub observation_sha256: String,
}

impl ProviderPostExecObservationV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn candidate(
        recipe: &ProviderSeccompInstallationRecipeV1,
        expected_resource_policy: &ProviderCgroupResourcePolicyV1,
        provider_pid: u32,
        provider_start_time_ticks: u64,
        provider_pidfd_identity_sha256: String,
        final_exec_event_identity_sha256: String,
        hardening_stop_event_identity_sha256: String,
        exact_seccomp_filter_observation_sha256: String,
        remote_dumpable_evidence: ProviderRemoteDumpableEvidenceV1,
        atomic_cgroup_placement_evidence: ProviderAtomicCgroupPlacementEvidenceV1,
    ) -> ProviderSeccompContractResult<Self> {
        recipe.validate_for(&recipe.provider_id, recipe.audit_arch)?;
        expected_resource_policy
            .validate_for(&recipe.provider_id)
            .map_err(|_| denied("provider_cgroup_resource_policy_denied"))?;
        let mut value = Self {
            schema: POST_EXEC_OBSERVATION_V1_SCHEMA.to_string(),
            authority: ProviderPostExecObservationAuthorityV1::PrivilegeBrokerPidfdPtraceHeld,
            provider_id: recipe.provider_id.clone(),
            audit_arch: recipe.audit_arch,
            recipe_sha256: recipe.recipe_sha256.clone(),
            seccomp_profile_sha256: recipe.seccomp_profile.profile_sha256.clone(),
            provider_pid,
            provider_start_time_before_ticks: provider_start_time_ticks,
            provider_start_time_after_ticks: provider_start_time_ticks,
            provider_pidfd_identity_sha256,
            task_stopped: true,
            pidfd_not_exited: true,
            final_exec_event_identity_sha256,
            hardening_stop_event_identity_sha256,
            observed_no_new_privs: 1,
            observed_seccomp_mode: 2,
            observed_seccomp_profile_sha256: recipe.seccomp_profile.profile_sha256.clone(),
            exact_seccomp_filter_observation_sha256: Some(exact_seccomp_filter_observation_sha256),
            remote_dumpable_evidence: Some(remote_dumpable_evidence),
            atomic_cgroup_placement_evidence: Some(atomic_cgroup_placement_evidence),
            observation_sha256: String::new(),
        };
        value.observation_sha256 = value.expected_sha256()?;
        value.validate_for(recipe, expected_resource_policy)?;
        Ok(value)
    }

    pub fn validate_for(
        &self,
        recipe: &ProviderSeccompInstallationRecipeV1,
        expected_resource_policy: &ProviderCgroupResourcePolicyV1,
    ) -> ProviderSeccompContractResult<()> {
        recipe.validate_for(&self.provider_id, self.audit_arch)?;
        expected_resource_policy
            .validate_for(&self.provider_id)
            .map_err(|_| denied("provider_cgroup_resource_policy_denied"))?;
        let start_time = self.provider_start_time_before_ticks;
        let dumpable = self
            .remote_dumpable_evidence
            .as_ref()
            .ok_or_else(|| denied("provider_remote_dumpable_evidence_missing"))?;
        let cgroup = self
            .atomic_cgroup_placement_evidence
            .as_ref()
            .ok_or_else(|| denied("provider_atomic_cgroup_placement_evidence_missing"))?;
        let exact_filter = self
            .exact_seccomp_filter_observation_sha256
            .as_deref()
            .ok_or_else(|| denied("provider_exact_seccomp_observation_missing"))?;
        dumpable.validate_for(&self.provider_id, self.provider_pid, start_time)?;
        cgroup.validate_for(
            &self.provider_id,
            self.provider_pid,
            start_time,
            expected_resource_policy,
        )?;
        if self.schema != POST_EXEC_OBSERVATION_V1_SCHEMA
            || self.authority
                != ProviderPostExecObservationAuthorityV1::PrivilegeBrokerPidfdPtraceHeld
            || self.provider_id != recipe.provider_id
            || self.audit_arch != recipe.audit_arch
            || self.recipe_sha256 != recipe.recipe_sha256
            || self.seccomp_profile_sha256 != recipe.seccomp_profile.profile_sha256
            || !valid_process_identity(
                self.provider_pid,
                start_time,
                &self.provider_pidfd_identity_sha256,
            )
            || self.provider_start_time_after_ticks != start_time
            || !self.task_stopped
            || !self.pidfd_not_exited
            || !valid_sha256(&self.final_exec_event_identity_sha256)
            || !valid_sha256(&self.hardening_stop_event_identity_sha256)
            || self.final_exec_event_identity_sha256 == self.hardening_stop_event_identity_sha256
            || self.observed_no_new_privs != recipe.required_no_new_privs
            || self.observed_seccomp_mode != recipe.expected_seccomp_mode
            || self.observed_seccomp_profile_sha256 != recipe.seccomp_profile.profile_sha256
            || !valid_sha256(exact_filter)
            || exact_filter == self.observed_seccomp_profile_sha256
            || dumpable.provider_pidfd_identity_sha256 != self.provider_pidfd_identity_sha256
            || cgroup.provider_pidfd_identity_sha256 != self.provider_pidfd_identity_sha256
            || !valid_sha256(&self.observation_sha256)
            || self.observation_sha256 != self.expected_sha256()?
        {
            return Err(denied("provider_post_exec_observation_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(
        &self,
        recipe: &ProviderSeccompInstallationRecipeV1,
        expected_resource_policy: &ProviderCgroupResourcePolicyV1,
    ) -> ProviderSeccompContractResult<String> {
        self.validate_for(recipe, expected_resource_policy)?;
        Ok(self.observation_sha256.clone())
    }

    fn expected_sha256(&self) -> ProviderSeccompContractResult<String> {
        let mut hasher = Sha256::new();
        hasher.update(OBSERVATION_DIGEST_DOMAIN);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("authority", self.authority.as_str()),
            ("provider_id", self.provider_id.as_str()),
            ("audit_arch", self.audit_arch.as_str()),
            ("recipe_sha256", self.recipe_sha256.as_str()),
            (
                "seccomp_profile_sha256",
                self.seccomp_profile_sha256.as_str(),
            ),
            (
                "provider_pidfd_identity_sha256",
                self.provider_pidfd_identity_sha256.as_str(),
            ),
            (
                "final_exec_event_identity_sha256",
                self.final_exec_event_identity_sha256.as_str(),
            ),
            (
                "hardening_stop_event_identity_sha256",
                self.hardening_stop_event_identity_sha256.as_str(),
            ),
            (
                "observed_seccomp_profile_sha256",
                self.observed_seccomp_profile_sha256.as_str(),
            ),
            (
                "exact_seccomp_filter_observation_sha256",
                self.exact_seccomp_filter_observation_sha256
                    .as_deref()
                    .unwrap_or("missing"),
            ),
            (
                "remote_dumpable_evidence_sha256",
                self.remote_dumpable_evidence
                    .as_ref()
                    .map_or("missing", |value| value.evidence_sha256.as_str()),
            ),
            (
                "atomic_cgroup_placement_evidence_sha256",
                self.atomic_cgroup_placement_evidence
                    .as_ref()
                    .map_or("missing", |value| value.evidence_sha256.as_str()),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u32(&mut hasher, "provider_pid", self.provider_pid)?;
        hash_u64(
            &mut hasher,
            "provider_start_time_before_ticks",
            self.provider_start_time_before_ticks,
        )?;
        hash_u64(
            &mut hasher,
            "provider_start_time_after_ticks",
            self.provider_start_time_after_ticks,
        )?;
        hash_bool(&mut hasher, "task_stopped", self.task_stopped)?;
        hash_bool(&mut hasher, "pidfd_not_exited", self.pidfd_not_exited)?;
        hash_u8(
            &mut hasher,
            "observed_no_new_privs",
            self.observed_no_new_privs,
        )?;
        hash_u8(
            &mut hasher,
            "observed_seccomp_mode",
            self.observed_seccomp_mode,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

fn required_mechanism(
    provider_id: &str,
) -> ProviderSeccompContractResult<ProviderFinalRuntimeBootstrapMechanismV1> {
    match provider_id {
        value if value == CODEX.provider_id => {
            Ok(ProviderFinalRuntimeBootstrapMechanismV1::ControlledElfEntryTrampolineBeforeCrt)
        }
        _ => Err(denied("provider_seccomp_builtin_provider_denied")),
    }
}

fn require_builtin(
    provider_id: &str,
) -> ProviderSeccompContractResult<&'static agent_descriptor_registry::AgentDescriptor> {
    match provider_id {
        value if value == CODEX.provider_id => Ok(&CODEX),
        _ => Err(denied("provider_seccomp_builtin_provider_denied")),
    }
}

fn filter_sha256(instructions: &[ClassicBpfInstructionV1]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(FILTER_DIGEST_DOMAIN);
    for instruction in instructions {
        hasher.update(instruction.code.to_be_bytes());
        hasher.update([instruction.jump_true, instruction.jump_false]);
        hasher.update(instruction.value.to_be_bytes());
    }
    lower_hex(&hasher.finalize())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

fn all_distinct(values: &[&str]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| values[..index].iter().all(|other| other != value))
}

fn sha256_bytes(value: &[u8]) -> String {
    lower_hex(&Sha256::digest(value))
}

fn valid_process_identity(pid: u32, start_time_ticks: u64, pidfd_sha256: &str) -> bool {
    pid > 1 && start_time_ticks != 0 && valid_sha256(pidfd_sha256)
}

fn hash_prefix(
    hasher: &mut Sha256,
    name: &str,
    value_len: usize,
) -> ProviderSeccompContractResult<()> {
    let name_len = u64::try_from(name.len()).map_err(|_| denied("seccomp_hash_length_denied"))?;
    let value_len = u64::try_from(value_len).map_err(|_| denied("seccomp_hash_length_denied"))?;
    hasher.update(name_len.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_len.to_be_bytes());
    Ok(())
}

fn hash_string(hasher: &mut Sha256, name: &str, value: &str) -> ProviderSeccompContractResult<()> {
    hash_prefix(hasher, name, value.len())?;
    hasher.update(value.as_bytes());
    Ok(())
}

fn hash_u16(hasher: &mut Sha256, name: &str, value: u16) -> ProviderSeccompContractResult<()> {
    hash_prefix(hasher, name, 2)?;
    hasher.update(value.to_be_bytes());
    Ok(())
}

fn hash_u8(hasher: &mut Sha256, name: &str, value: u8) -> ProviderSeccompContractResult<()> {
    hash_prefix(hasher, name, 1)?;
    hasher.update([value]);
    Ok(())
}

fn hash_u32(hasher: &mut Sha256, name: &str, value: u32) -> ProviderSeccompContractResult<()> {
    hash_prefix(hasher, name, 4)?;
    hasher.update(value.to_be_bytes());
    Ok(())
}

fn hash_u64(hasher: &mut Sha256, name: &str, value: u64) -> ProviderSeccompContractResult<()> {
    hash_prefix(hasher, name, 8)?;
    hasher.update(value.to_be_bytes());
    Ok(())
}

fn hash_bool(hasher: &mut Sha256, name: &str, value: bool) -> ProviderSeccompContractResult<()> {
    hash_u8(hasher, name, u8::from(value))
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn denied(code: &'static str) -> ProviderSeccompContractError {
    ProviderSeccompContractError(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: &str) -> String {
        sha256_bytes(seed.as_bytes())
    }

    fn recipe(provider_id: &str) -> ProviderSeccompInstallationRecipeV1 {
        ProviderSeccompInstallationRecipeV1::exact_builtin(
            provider_id,
            LinuxSeccompAuditArchV1::Aarch64,
            digest(&format!("{provider_id}-runtime")),
            digest(&format!("{provider_id}-closure")),
            digest(&format!("{provider_id}-argv")),
            digest(&format!("{provider_id}-environment")),
            digest(&format!("{provider_id}-fd-table")),
        )
        .unwrap()
    }

    fn resource_policy(provider_id: &str) -> ProviderCgroupResourcePolicyV1 {
        ProviderCgroupResourcePolicyV1::provisioned(
            provider_id,
            128,
            1024 * 1024 * 1024,
            200_000,
            100_000,
        )
        .unwrap()
    }

    fn observation(
        provider_id: &str,
    ) -> (
        ProviderSeccompInstallationRecipeV1,
        ProviderCgroupResourcePolicyV1,
        ProviderPostExecObservationV1,
    ) {
        let recipe = recipe(provider_id);
        let policy = resource_policy(provider_id);
        let pid = 42;
        let start_time = 12_345;
        let pidfd = digest(&format!("{provider_id}-pidfd"));
        let dumpable = ProviderRemoteDumpableEvidenceV1::candidate(
            provider_id,
            pid,
            start_time,
            pidfd.clone(),
        )
        .unwrap();
        let cgroup = ProviderAtomicCgroupPlacementEvidenceV1::candidate(
            provider_id,
            pid,
            start_time,
            pidfd.clone(),
            policy.clone(),
            digest(&format!("{provider_id}-leaf-fd")),
            digest(&format!("{provider_id}-atomic-placement")),
        )
        .unwrap();
        let observation = ProviderPostExecObservationV1::candidate(
            &recipe,
            &policy,
            pid,
            start_time,
            pidfd,
            digest(&format!("{provider_id}-final-exec")),
            digest(&format!("{provider_id}-hardening-stop")),
            recipe.seccomp_profile.filter_program_sha256.clone(),
            dumpable,
            cgroup,
        )
        .unwrap();
        (recipe, policy, observation)
    }

    #[test]
    fn codex_profile_is_serializable_and_bootstrap_bound() {
        let codex = recipe(CODEX.provider_id);
        assert_eq!(
            codex.bootstrap_mechanism,
            ProviderFinalRuntimeBootstrapMechanismV1::ControlledElfEntryTrampolineBeforeCrt
        );
        {
            let value = codex;
            let encoded = serde_json::to_vec(&value).unwrap();
            let decoded: ProviderSeccompInstallationRecipeV1 =
                serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, value);
            decoded
                .validate_for(&value.provider_id, LinuxSeccompAuditArchV1::Aarch64)
                .unwrap();
        }
    }

    #[test]
    fn forged_profile_wrong_arch_syscall_and_action_fail_after_rehash() {
        let exact = ProviderSeccompProfileV1::exact_builtin(
            CODEX.provider_id,
            LinuxSeccompAuditArchV1::Aarch64,
        )
        .unwrap();

        let mut forged_provider = exact.clone();
        forged_provider.provider_id = "unregistered-provider".to_string();
        assert!(
            forged_provider
                .validate_for(CODEX.provider_id, LinuxSeccompAuditArchV1::Aarch64)
                .is_err()
        );

        let mut wrong_arch = exact.clone();
        wrong_arch.audit_arch = LinuxSeccompAuditArchV1::X86_64;
        wrong_arch.instructions = exact_filter(LinuxSeccompAuditArchV1::X86_64).to_vec();
        wrong_arch.filter_program_sha256 = filter_sha256(&wrong_arch.instructions);
        wrong_arch.profile_sha256 = wrong_arch.expected_sha256().unwrap();
        assert!(
            wrong_arch
                .validate_for(CODEX.provider_id, LinuxSeccompAuditArchV1::Aarch64)
                .is_err()
        );

        let mut wrong_syscall = exact.clone();
        wrong_syscall.instructions[8].value ^= 1;
        wrong_syscall.filter_program_sha256 = filter_sha256(&wrong_syscall.instructions);
        wrong_syscall.profile_sha256 = wrong_syscall.expected_sha256().unwrap();
        assert!(
            wrong_syscall
                .validate_for(CODEX.provider_id, LinuxSeccompAuditArchV1::Aarch64)
                .is_err()
        );

        let mut wrong_action = exact;
        wrong_action.instructions[2].value = SECCOMP_RET_ALLOW;
        wrong_action.filter_program_sha256 = filter_sha256(&wrong_action.instructions);
        wrong_action.profile_sha256 = wrong_action.expected_sha256().unwrap();
        assert!(
            wrong_action
                .validate_for(CODEX.provider_id, LinuxSeccompAuditArchV1::Aarch64)
                .is_err()
        );
    }

    #[test]
    fn provider_profile_or_bootstrap_mechanism_substitution_fails() {
        let mut codex = recipe(CODEX.provider_id);
        codex.bootstrap_mechanism =
            ProviderFinalRuntimeBootstrapMechanismV1::DynamicElfPreinitAfterBoundLoader;
        codex.recipe_sha256 = codex.expected_sha256().unwrap();
        assert!(
            codex
                .validate_for(CODEX.provider_id, LinuxSeccompAuditArchV1::Aarch64)
                .is_err()
        );
    }

    #[test]
    fn dumpable_cgroup_and_exact_filter_evidence_are_mandatory() {
        let (recipe, policy, valid) = observation(CODEX.provider_id);
        valid.validate_for(&recipe, &policy).unwrap();

        let mut missing_dumpable = valid.clone();
        missing_dumpable.remote_dumpable_evidence = None;
        missing_dumpable.observation_sha256 = missing_dumpable.expected_sha256().unwrap();
        assert_eq!(
            missing_dumpable
                .validate_for(&recipe, &policy)
                .unwrap_err()
                .code(),
            "provider_remote_dumpable_evidence_missing"
        );

        let mut missing_cgroup = valid.clone();
        missing_cgroup.atomic_cgroup_placement_evidence = None;
        missing_cgroup.observation_sha256 = missing_cgroup.expected_sha256().unwrap();
        assert_eq!(
            missing_cgroup
                .validate_for(&recipe, &policy)
                .unwrap_err()
                .code(),
            "provider_atomic_cgroup_placement_evidence_missing"
        );

        let mut missing_filter = valid;
        missing_filter.exact_seccomp_filter_observation_sha256 = None;
        missing_filter.observation_sha256 = missing_filter.expected_sha256().unwrap();
        assert_eq!(
            missing_filter
                .validate_for(&recipe, &policy)
                .unwrap_err()
                .code(),
            "provider_exact_seccomp_observation_missing"
        );
    }

    #[test]
    fn nonzero_dumpable_resource_drift_and_pid_reuse_fail_closed() {
        let (recipe, policy, valid) = observation(CODEX.provider_id);

        let mut nonzero_dumpable = valid.clone();
        let dumpable = nonzero_dumpable.remote_dumpable_evidence.as_mut().unwrap();
        dumpable.observed_dumpable = 1;
        dumpable.evidence_sha256 = dumpable.expected_sha256().unwrap();
        nonzero_dumpable.observation_sha256 = nonzero_dumpable.expected_sha256().unwrap();
        assert!(nonzero_dumpable.validate_for(&recipe, &policy).is_err());

        let mut resource_drift = valid.clone();
        resource_drift
            .atomic_cgroup_placement_evidence
            .as_mut()
            .unwrap()
            .exact_resource_readback_complete = false;
        let cgroup = resource_drift
            .atomic_cgroup_placement_evidence
            .as_mut()
            .unwrap();
        cgroup.evidence_sha256 = cgroup.expected_sha256().unwrap();
        resource_drift.observation_sha256 = resource_drift.expected_sha256().unwrap();
        assert!(resource_drift.validate_for(&recipe, &policy).is_err());

        let mut pid_reuse = valid;
        pid_reuse.provider_start_time_after_ticks += 1;
        pid_reuse.observation_sha256 = pid_reuse.expected_sha256().unwrap();
        assert!(pid_reuse.validate_for(&recipe, &policy).is_err());
    }

    #[test]
    fn source_contract_does_not_claim_product_authority() {
        const {
            assert!(SOURCE_SERIALIZABLE_SECCOMP_CONTRACT_IMPLEMENTED);
            assert!(SOURCE_EXACT_SECCOMP_PROGRAM_BOUND);
            assert!(SOURCE_PROVIDER_SEPARATED_RECIPE_IMPLEMENTED);
            assert!(!PRODUCT_EXACT_SECCOMP_OBSERVER_AVAILABLE);
            assert!(!PRODUCT_REMOTE_DUMPABLE_OBSERVER_AVAILABLE);
            assert!(!PRODUCT_ATOMIC_CGROUP_PLACEMENT_OBSERVER_AVAILABLE);
            assert!(!PRODUCT_POST_EXEC_OBSERVATION_AUTHORITY_AVAILABLE);
            assert!(!CONFERS_EFFECT_AUTHORITY);
        }
    }
}
