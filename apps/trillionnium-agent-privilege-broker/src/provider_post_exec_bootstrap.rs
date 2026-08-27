//! Closed source contract for final-runtime post-exec hardening.
//!
//! A launcher which hardens and then execs the provider runtime is not enough:
//! ordinary ELF exec resets dumpability. The final ELF must therefore own one
//! provider-closed native entry mechanism. Static Codex uses a controlled ELF
//! `e_entry` trampoline before the original CRT `_start`, calling the
//! freestanding raw-syscall core, which reasserts `PR_SET_DUMPABLE=0`, verifies
//! inherited no-new-privileges/credentials/capability closure, installs one
//! exact architecture-bound classic-BPF seccomp program, and enters an exact-
//! parent-observable `tgkill(SIGSTOP)` barrier.
//!
//! This file defines expectation data only. No product image contains the
//! bootstrap yet, and no product constructor authenticates a recipe. The
//! Linux fixture producer is test-only. In particular, neither `Seccomp:2` nor
//! procfs ownership alone proves the exact filter or exact dumpability state.

use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::agent_descriptor_registry;
use trillionnium_privilege_broker_protocol::{Digest, FixedBytes32, Provider};

pub(crate) const SOURCE_POST_FINAL_EXEC_BOOTSTRAP_RECIPE_IMPLEMENTED: bool = true;
pub(crate) const SOURCE_EXACT_SECCOMP_FILTER_DIGEST_BOUND: bool = true;
pub(crate) const SOURCE_LINUX_HELD_FIXTURE_PRODUCER_IMPLEMENTED: bool = true;
pub(crate) const SOURCE_SHARED_FREESTANDING_BOOTSTRAP_CORE_IMPLEMENTED: bool = true;
pub(crate) const PRODUCT_POST_FINAL_EXEC_BOOTSTRAP_AVAILABLE: bool = false;
pub(crate) const PRODUCT_EXACT_SECCOMP_FILTER_OBSERVATION_AVAILABLE: bool = false;
pub(crate) const PRODUCT_EXACT_DUMPABLE_OBSERVATION_AVAILABLE: bool = false;
pub(crate) const PRODUCT_PROVIDER_PAYLOAD_RECIPE_WIRED: bool = false;
pub(crate) const CONFERS_EFFECT_AUTHORITY: bool = false;

const BOOTSTRAP_ABI_DOMAIN: &[u8] =
    b"org.trillionnium.provider-post-final-exec-native-bootstrap.v2\0";
const FILTER_DIGEST_DOMAIN: &[u8] = b"org.trillionnium.provider-post-final-exec-seccomp-cbpf.v1\0";
const RECIPE_DIGEST_DOMAIN: &[u8] =
    b"org.trillionnium.provider-post-final-exec-bootstrap-recipe.v2\0";
const WOULD_DUMP_KERNEL_CONTRACT_DOMAIN: &[u8] =
    b"org.trillionnium.linux-would-dump-execute-only-contract.v1\0";

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_ALU_AND_K: u16 = 0x54;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
const SECCOMP_DATA_ARGUMENT_ZERO_OFFSET: u32 = 16;
const SECCOMP_DATA_ARGUMENT_ZERO_HIGH_OFFSET: u32 = 20;
const SECCOMP_DATA_ARGUMENT_ONE_OFFSET: u32 = 24;
const SECCOMP_DATA_ARGUMENT_ONE_HIGH_OFFSET: u32 = 28;
const PR_SET_DUMPABLE_VALUE: u32 = 4;
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

#[cfg(target_arch = "x86_64")]
const REVIEWED_AUDIT_ARCH: u32 = AUDIT_ARCH_X86_64;
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
#[cfg(target_arch = "aarch64")]
const REVIEWED_AUDIT_ARCH: u32 = AUDIT_ARCH_AARCH64;
#[cfg(target_arch = "aarch64")]
const X32_SYSCALL_BIT: u32 = 0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const REVIEWED_AUDIT_ARCH: u32 = 0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const X32_SYSCALL_BIT: u32 = 0;

#[cfg(target_arch = "x86_64")]
const DENIED_SYSCALLS: [u32; 4] = [56, 435, 57, 58];
#[cfg(target_arch = "x86_64")]
const EXEC_SYSCALLS: [u32; 2] = [59, 322];
#[cfg(target_arch = "x86_64")]
const PRCTL_SYSCALL: u32 = 157;
#[cfg(target_arch = "aarch64")]
const DENIED_SYSCALLS: [u32; 4] = [220, 435, ABSENT_SYSCALL, ABSENT_SYSCALL];
#[cfg(target_arch = "aarch64")]
const EXEC_SYSCALLS: [u32; 2] = [221, 281];
#[cfg(target_arch = "aarch64")]
const PRCTL_SYSCALL: u32 = 167;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const DENIED_SYSCALLS: [u32; 4] = [ABSENT_SYSCALL; 4];
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const EXEC_SYSCALLS: [u32; 2] = [ABSENT_SYSCALL; 2];
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const PRCTL_SYSCALL: u32 = ABSENT_SYSCALL;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClassicBpfInstruction {
    pub code: u16,
    pub jump_true: u8,
    pub jump_false: u8,
    pub value: u32,
}

const fn statement(code: u16, value: u32) -> ClassicBpfInstruction {
    ClassicBpfInstruction {
        code,
        jump_true: 0,
        jump_false: 0,
        value,
    }
}

const fn jump(code: u16, value: u32, jump_true: u8, jump_false: u8) -> ClassicBpfInstruction {
    ClassicBpfInstruction {
        code,
        jump_true,
        jump_false,
        value,
    }
}

/// Exact architecture-bound filter installed by the native final-image
/// bootstrap. It denies every reviewed descendant primitive except the exact
/// legacy-clone shape shared by musl `posix_spawn` and musl-compatible vfork,
/// and allows `execve` and `execveat`. Seccomp cannot authenticate that clone's
/// callsite or count: exact direct-tool entrypoint authority and child-count
/// ownership remain external SELinux and retained broker/cgroup custody
/// obligations. The architecture check kills instead of interpreting a syscall
/// number under another ABI.
#[must_use]
pub(crate) const fn exact_provider_seccomp_filter() -> [ClassicBpfInstruction; 37] {
    exact_provider_seccomp_filter_for_arch(
        REVIEWED_AUDIT_ARCH,
        X32_SYSCALL_BIT,
        DENIED_SYSCALLS,
        PRCTL_SYSCALL,
    )
}

/// Exact target AArch64 filter bytes used by the retained final-payload gate.
///
/// This is intentionally explicit instead of using the build host's
/// `cfg(target_arch)`: the product payload gate always inspects an AArch64 ELF,
/// including when the verifier itself runs on an x86_64 builder.
#[must_use]
pub(crate) const fn exact_aarch64_provider_seccomp_filter() -> [ClassicBpfInstruction; 37] {
    exact_provider_seccomp_filter_for_arch(
        AUDIT_ARCH_AARCH64,
        0,
        [220, 435, ABSENT_SYSCALL, ABSENT_SYSCALL],
        167,
    )
}

const fn exact_provider_seccomp_filter_for_arch(
    audit_arch: u32,
    x32_syscall_bit: u32,
    denied_syscalls: [u32; 4],
    prctl_syscall: u32,
) -> [ClassicBpfInstruction; 37] {
    [
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARCH_OFFSET),
        jump(BPF_JMP_JEQ_K, audit_arch, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        statement(BPF_ALU_AND_K, x32_syscall_bit),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JMP_JEQ_K, denied_syscalls[1], 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_ENOSYS),
        jump(BPF_JMP_JEQ_K, denied_syscalls[2], 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        jump(BPF_JMP_JEQ_K, denied_syscalls[3], 0, 1),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        jump(BPF_JMP_JEQ_K, prctl_syscall, 0, 7),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_ZERO_OFFSET),
        jump(BPF_JMP_JEQ_K, PR_SET_DUMPABLE_VALUE, 0, 5),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_ONE_HIGH_OFFSET),
        jump(BPF_JMP_JEQ_K, 0, 0, 2),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_ONE_OFFSET),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_NR_OFFSET),
        jump(BPF_JMP_JEQ_K, denied_syscalls[0], 0, 12),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_ZERO_HIGH_OFFSET),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_ZERO_OFFSET),
        jump(BPF_JMP_JEQ_K, EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS, 7, 0),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_ZERO_OFFSET),
        statement(BPF_ALU_AND_K, REQUIRED_PTHREAD_CLONE_FLAGS),
        jump(BPF_JMP_JEQ_K, REQUIRED_PTHREAD_CLONE_FLAGS, 0, 3),
        statement(BPF_LD_W_ABS, SECCOMP_DATA_ARGUMENT_ZERO_OFFSET),
        statement(BPF_ALU_AND_K, FORBIDDEN_PROCESS_CLONE_FLAGS),
        jump(BPF_JMP_JEQ_K, 0, 1, 0),
        statement(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM),
        statement(BPF_RET_K, SECCOMP_RET_ALLOW),
    ]
}

pub(crate) fn exact_provider_seccomp_filter_sha256() -> Digest {
    seccomp_filter_sha256(&exact_provider_seccomp_filter())
}

pub(crate) fn seccomp_filter_sha256(instructions: &[ClassicBpfInstruction]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(FILTER_DIGEST_DOMAIN);
    for instruction in instructions {
        hasher.update(instruction.code.to_be_bytes());
        hasher.update([instruction.jump_true, instruction.jump_false]);
        hasher.update(instruction.value.to_be_bytes());
    }
    digest_from_hasher(hasher)
}

pub(crate) fn provider_native_bootstrap_abi_sha256(
    provider: Provider,
) -> Result<Digest, ProviderBootstrapRecipeError> {
    if REVIEWED_AUDIT_ARCH == 0 {
        return Err(ProviderBootstrapRecipeError::ArchitectureUnsupported);
    }
    let mechanism = required_native_bootstrap_mechanism(provider);
    let mut hasher = Sha256::new();
    hasher.update(BOOTSTRAP_ABI_DOMAIN);
    hasher.update([match provider {
        Provider::Codex => 1,
    }]);
    hasher.update([native_bootstrap_mechanism_discriminator(mechanism)]);
    hasher.update(REVIEWED_AUDIT_ARCH.to_be_bytes());
    hasher.update(b"pr-set-dumpable-zero\0");
    hasher.update(b"verify-no-new-privs-one\0");
    hasher.update(b"verify-real-effective-saved-fs-uid-gid-and-zero-groups\0");
    hasher.update(b"verify-cap-inh-prm-eff-bnd-amb-empty\0");
    hasher.update(b"install-exact-arch-bound-filter\0");
    hasher.update(b"deny-x86-x32-syscall-bit\0");
    hasher.update(b"clone3-enosys-legacy-clone-exact-pthread-or-musl-vfork-spawn-shape-only\0");
    hasher.update(b"clone-flags-upper-word-zero\0");
    hasher.update(b"musl-vfork-posix-spawn-clone-vm-clone-vfork-sigchld-exact-shape\0");
    hasher.update(b"deny-other-process-clone-flags\0");
    hasher.update(b"allow-only-post-exec-pr-set-dumpable-zero\0");
    hasher.update(b"tgkill-self-sigstop-si-tkill\0");
    hasher.update(
        b"allow-execve-execveat-requires-exact-selinux-entrypoint-and-retained-broker-cgroup-custody\0",
    );
    hasher.update(b"failure-exit-group-self-sigkill-architecture-trap-loop\0");
    match mechanism {
        FinalRuntimeNativeBootstrapMechanismV2::ControlledElfEntryTrampolineBeforeCrt => {
            hasher.update(b"final-static-elf-e-entry-is-controlled-trampoline\0");
            hasher.update(b"raw-syscalls-no-libc-tls-plt-ifunc-runtime-relocations\0");
            hasher.update(b"preserve-kernel-entry-stack-and-required-registers\0");
            hasher.update(b"tail-transfer-once-to-receipt-bound-original-crt-start\0");
            hasher.update(b"static-musl-preinit-array-is-not-authority\0");
            hasher.update(b"no-pt-interp-or-dynamic-needed-closure\0");
        }
    }
    Ok(digest_from_hasher(hasher))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalRuntimeNativeBootstrapMechanismV2 {
    ControlledElfEntryTrampolineBeforeCrt,
}

const fn required_native_bootstrap_mechanism(
    provider: Provider,
) -> FinalRuntimeNativeBootstrapMechanismV2 {
    match provider {
        Provider::Codex => {
            FinalRuntimeNativeBootstrapMechanismV2::ControlledElfEntryTrampolineBeforeCrt
        }
    }
}

const fn native_bootstrap_mechanism_discriminator(
    mechanism: FinalRuntimeNativeBootstrapMechanismV2,
) -> u8 {
    match mechanism {
        FinalRuntimeNativeBootstrapMechanismV2::ControlledElfEntryTrampolineBeforeCrt => 1,
    }
}

/// Affine authenticated inputs for closing one provider-specific recipe.
///
/// The product source is intentionally uninhabited. Raw hashes supplied by a
/// daemon or broker socket cannot create this value.
enum AuthenticatedRecipeSource {
    Product(std::convert::Infallible),
    #[cfg(test)]
    Test,
}

#[must_use = "authenticated recipe inputs must be consumed into one closed recipe"]
pub(crate) struct AuthenticatedProviderBootstrapRecipeInputs {
    provider: Provider,
    final_runtime_executable_sha256: Digest,
    final_runtime_closure_sha256: Digest,
    permitted_argv_sha256: Digest,
    permitted_environment_sha256: Digest,
    permitted_fd_table_sha256: Digest,
    source: AuthenticatedRecipeSource,
}

impl AuthenticatedProviderBootstrapRecipeInputs {
    #[cfg(test)]
    pub(crate) fn for_test(
        provider: Provider,
        final_runtime_executable_sha256: Digest,
        final_runtime_closure_sha256: Digest,
        permitted_argv_sha256: Digest,
        permitted_environment_sha256: Digest,
        permitted_fd_table_sha256: Digest,
    ) -> Self {
        Self {
            provider,
            final_runtime_executable_sha256,
            final_runtime_closure_sha256,
            permitted_argv_sha256,
            permitted_environment_sha256,
            permitted_fd_table_sha256,
            source: AuthenticatedRecipeSource::Test,
        }
    }
}

/// Closed provider-specific final-image recipe.
///
/// This type is affine and deliberately implements neither Clone, Copy,
/// Serialize nor Deserialize. Its digest is expectation data, not launch or
/// effect authority.
#[must_use = "a closed final-runtime recipe must be consumed by held launch custody"]
pub(crate) struct ClosedProviderFinalRuntimeBootstrapRecipe {
    provider: Provider,
    expected_uid: u32,
    expected_gid: u32,
    expected_selinux_domain_sha256: Digest,
    final_runtime_executable_sha256: Digest,
    final_runtime_closure_sha256: Digest,
    bootstrap_abi_sha256: Digest,
    exact_seccomp_filter_sha256: Digest,
    permitted_argv_sha256: Digest,
    permitted_environment_sha256: Digest,
    permitted_fd_table_sha256: Digest,
    recipe_binding_sha256: Digest,
    mechanism: FinalRuntimeNativeBootstrapMechanismV2,
    _source: AuthenticatedRecipeSource,
}

pub(crate) fn close_native_provider_bootstrap_recipe(
    inputs: AuthenticatedProviderBootstrapRecipeInputs,
) -> Result<ClosedProviderFinalRuntimeBootstrapRecipe, ProviderBootstrapRecipeError> {
    let descriptor = match inputs.provider {
        Provider::Codex => &agent_descriptor_registry::CODEX,
    };
    let expected_selinux_domain_sha256 = digest_bytes(descriptor.agent_selinux_domain.as_bytes());
    let mechanism = required_native_bootstrap_mechanism(inputs.provider);
    let bootstrap_abi_sha256 = provider_native_bootstrap_abi_sha256(inputs.provider)?;
    let exact_seccomp_filter_sha256 = exact_provider_seccomp_filter_sha256();
    let mut recipe = ClosedProviderFinalRuntimeBootstrapRecipe {
        provider: inputs.provider,
        expected_uid: descriptor.uid,
        expected_gid: descriptor.gid,
        expected_selinux_domain_sha256,
        final_runtime_executable_sha256: inputs.final_runtime_executable_sha256,
        final_runtime_closure_sha256: inputs.final_runtime_closure_sha256,
        bootstrap_abi_sha256,
        exact_seccomp_filter_sha256,
        permitted_argv_sha256: inputs.permitted_argv_sha256,
        permitted_environment_sha256: inputs.permitted_environment_sha256,
        permitted_fd_table_sha256: inputs.permitted_fd_table_sha256,
        recipe_binding_sha256: bootstrap_abi_sha256,
        mechanism,
        _source: inputs.source,
    };
    recipe.recipe_binding_sha256 = recipe.canonical_sha256()?;
    if !recipe.validate() {
        return Err(ProviderBootstrapRecipeError::RecipeBindingInvalid);
    }
    Ok(recipe)
}

impl ClosedProviderFinalRuntimeBootstrapRecipe {
    fn validate(&self) -> bool {
        let descriptor = match self.provider {
            Provider::Codex => &agent_descriptor_registry::CODEX,
        };
        self.expected_uid == descriptor.uid
            && self.expected_gid == descriptor.gid
            && self.expected_selinux_domain_sha256
                == digest_bytes(descriptor.agent_selinux_domain.as_bytes())
            && provider_native_bootstrap_abi_sha256(self.provider)
                .is_ok_and(|digest| self.bootstrap_abi_sha256 == digest)
            && self.exact_seccomp_filter_sha256 == exact_provider_seccomp_filter_sha256()
            && self.mechanism == required_native_bootstrap_mechanism(self.provider)
            && digests_are_distinct(&[
                self.expected_selinux_domain_sha256,
                self.final_runtime_executable_sha256,
                self.final_runtime_closure_sha256,
                self.bootstrap_abi_sha256,
                self.exact_seccomp_filter_sha256,
                self.permitted_argv_sha256,
                self.permitted_environment_sha256,
                self.permitted_fd_table_sha256,
            ])
            && self
                .canonical_sha256()
                .is_ok_and(|digest| digest == self.recipe_binding_sha256)
    }

    fn canonical_sha256(&self) -> Result<Digest, ProviderBootstrapRecipeError> {
        if REVIEWED_AUDIT_ARCH == 0 {
            return Err(ProviderBootstrapRecipeError::ArchitectureUnsupported);
        }
        let mut hasher = Sha256::new();
        hasher.update(RECIPE_DIGEST_DOMAIN);
        hasher.update([match self.provider {
            Provider::Codex => 1,
        }]);
        hasher.update([native_bootstrap_mechanism_discriminator(self.mechanism)]);
        hasher.update(self.expected_uid.to_be_bytes());
        hasher.update(self.expected_gid.to_be_bytes());
        for digest in [
            self.expected_selinux_domain_sha256,
            self.final_runtime_executable_sha256,
            self.final_runtime_closure_sha256,
            self.bootstrap_abi_sha256,
            self.exact_seccomp_filter_sha256,
            self.permitted_argv_sha256,
            self.permitted_environment_sha256,
            self.permitted_fd_table_sha256,
        ] {
            hasher.update(digest.value().as_bytes());
        }
        Ok(digest_from_hasher(hasher))
    }

    #[cfg(test)]
    pub(crate) const fn provider(&self) -> Provider {
        self.provider
    }

    #[cfg(test)]
    pub(crate) const fn expected_uid(&self) -> u32 {
        self.expected_uid
    }

    #[cfg(test)]
    pub(crate) const fn expected_gid(&self) -> u32 {
        self.expected_gid
    }

    #[cfg(test)]
    pub(crate) const fn final_runtime_executable_sha256(&self) -> Digest {
        self.final_runtime_executable_sha256
    }

    #[cfg(test)]
    pub(crate) const fn final_runtime_closure_sha256(&self) -> Digest {
        self.final_runtime_closure_sha256
    }

    #[cfg(test)]
    pub(crate) const fn exact_seccomp_filter_sha256(&self) -> Digest {
        self.exact_seccomp_filter_sha256
    }

    #[cfg(test)]
    pub(crate) const fn bootstrap_abi_sha256(&self) -> Digest {
        self.bootstrap_abi_sha256
    }

    #[cfg(test)]
    pub(crate) const fn mechanism(&self) -> FinalRuntimeNativeBootstrapMechanismV2 {
        self.mechanism
    }

    #[cfg(test)]
    pub(crate) const fn permitted_argv_sha256(&self) -> Digest {
        self.permitted_argv_sha256
    }

    #[cfg(test)]
    pub(crate) const fn permitted_environment_sha256(&self) -> Digest {
        self.permitted_environment_sha256
    }

    #[cfg(test)]
    pub(crate) const fn permitted_fd_table_sha256(&self) -> Digest {
        self.permitted_fd_table_sha256
    }

    #[cfg(test)]
    pub(crate) const fn recipe_binding_sha256(&self) -> Digest {
        self.recipe_binding_sha256
    }
}

/// Source-model evidence for the optional execute-only `would_dump` mechanism.
///
/// This cannot qualify a product on its own. Product use additionally needs a
/// trusted-init sealed `fs.suid_dumpable=0` fact (or a new exact kernel
/// observation), a target-kernel/config receipt, and immutable FD/inode/xattr/
/// mount custody. Procfs ownership distinguishes dumpable 1 from {0,2}; it
/// cannot distinguish exact 0 from 2.
#[must_use = "execute-only evidence is source-model data, not product authority"]
pub(crate) struct KernelWouldDumpExecuteOnlyEvidenceV1 {
    executable_mode: u32,
    executable_uid: u32,
    executable_gid: u32,
    regular_single_link: bool,
    read_only_verified_mount: bool,
    no_setid_bits: bool,
    no_acl: bool,
    no_file_capabilities: bool,
    private_root_measurement_fd_retained: bool,
    private_root_measurement_fd_not_inherited: bool,
    separate_execution_fd_bound_to_same_inode: bool,
    provider_read_denied: bool,
    child_dac_override_absent: bool,
    child_dac_read_search_absent: bool,
    fs_suid_dumpable: u8,
    trusted_init_sealed_sysctl: bool,
    target_would_dump_contract_verified: bool,
    target_kernel_config_verified: bool,
    kernel_contract_sha256: Digest,
}

impl KernelWouldDumpExecuteOnlyEvidenceV1 {
    #[cfg(test)]
    fn valid_for_test() -> Self {
        Self {
            executable_mode: 0o511,
            executable_uid: 0,
            executable_gid: 0,
            regular_single_link: true,
            read_only_verified_mount: true,
            no_setid_bits: true,
            no_acl: true,
            no_file_capabilities: true,
            private_root_measurement_fd_retained: true,
            private_root_measurement_fd_not_inherited: true,
            separate_execution_fd_bound_to_same_inode: true,
            provider_read_denied: true,
            child_dac_override_absent: true,
            child_dac_read_search_absent: true,
            fs_suid_dumpable: 0,
            trusted_init_sealed_sysctl: true,
            target_would_dump_contract_verified: true,
            target_kernel_config_verified: true,
            kernel_contract_sha256: would_dump_kernel_contract_sha256(),
        }
    }

    pub(crate) fn validates_source_candidate(&self) -> bool {
        self.executable_mode == 0o511
            && self.executable_uid == 0
            && self.executable_gid == 0
            && self.regular_single_link
            && self.read_only_verified_mount
            && self.no_setid_bits
            && self.no_acl
            && self.no_file_capabilities
            && self.private_root_measurement_fd_retained
            && self.private_root_measurement_fd_not_inherited
            && self.separate_execution_fd_bound_to_same_inode
            && self.provider_read_denied
            && self.child_dac_override_absent
            && self.child_dac_read_search_absent
            && self.fs_suid_dumpable == 0
            && self.trusted_init_sealed_sysctl
            && self.target_would_dump_contract_verified
            && self.target_kernel_config_verified
            && self.kernel_contract_sha256 == would_dump_kernel_contract_sha256()
    }
}

fn would_dump_kernel_contract_sha256() -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(WOULD_DUMP_KERNEL_CONTRACT_DOMAIN);
    hasher.update(b"root-readable-provider-execute-only-mode-0511\0");
    hasher.update(b"private-measurement-fd-not-inherited\0");
    hasher.update(b"separate-execution-fd-same-inode\0");
    hasher.update(b"would_dump-before-begin-new-exec\0");
    hasher.update(b"trusted-init-sealed-fs-suid-dumpable-zero\0");
    hasher.update(b"proc-ownership-not-exact-dumpable-proof\0");
    digest_from_hasher(hasher)
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ProviderBootstrapRecipeError {
    #[error("the provider final-runtime bootstrap architecture is unsupported")]
    ArchitectureUnsupported,
    #[error("the provider final-runtime bootstrap recipe binding is invalid")]
    RecipeBindingInvalid,
}

fn digest_bytes(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    digest_from_hasher(hasher)
}

fn digest_from_hasher(hasher: Sha256) -> Digest {
    let bytes: [u8; 32] = hasher.finalize().into();
    Digest::new(FixedBytes32::new(bytes).expect("domain-separated SHA-256 is non-zero"))
}

fn digests_are_distinct(digests: &[Digest]) -> bool {
    digests
        .iter()
        .enumerate()
        .all(|(index, digest)| digests[..index].iter().all(|other| other != digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> Digest {
        Digest::new(FixedBytes32::new([seed; 32]).unwrap())
    }

    fn recipe(provider: Provider) -> ClosedProviderFinalRuntimeBootstrapRecipe {
        close_native_provider_bootstrap_recipe(
            AuthenticatedProviderBootstrapRecipeInputs::for_test(
                provider,
                digest(1),
                digest(2),
                digest(3),
                digest(4),
                digest(5),
            ),
        )
        .unwrap()
    }

    fn evaluate_filter(
        filter: &[ClassicBpfInstruction],
        arch: u32,
        syscall: u32,
        argument_zero: u64,
    ) -> u32 {
        evaluate_filter_with_arguments(filter, arch, syscall, argument_zero, 0)
    }

    fn evaluate_filter_with_arguments(
        filter: &[ClassicBpfInstruction],
        arch: u32,
        syscall: u32,
        argument_zero: u64,
        argument_one: u64,
    ) -> u32 {
        let mut accumulator = 0_u32;
        let mut program_counter = 0_usize;
        loop {
            let instruction = filter
                .get(program_counter)
                .expect("closed filter jump stays in bounds");
            match instruction.code {
                BPF_LD_W_ABS => {
                    accumulator = match instruction.value {
                        SECCOMP_DATA_NR_OFFSET => syscall,
                        SECCOMP_DATA_ARCH_OFFSET => arch,
                        SECCOMP_DATA_ARGUMENT_ZERO_OFFSET => argument_zero as u32,
                        SECCOMP_DATA_ARGUMENT_ZERO_HIGH_OFFSET => {
                            (argument_zero >> u32::BITS) as u32
                        }
                        SECCOMP_DATA_ARGUMENT_ONE_OFFSET => argument_one as u32,
                        SECCOMP_DATA_ARGUMENT_ONE_HIGH_OFFSET => (argument_one >> u32::BITS) as u32,
                        _ => panic!("unexpected seccomp-data offset"),
                    };
                    program_counter += 1;
                }
                BPF_ALU_AND_K => {
                    accumulator &= instruction.value;
                    program_counter += 1;
                }
                BPF_JMP_JEQ_K => {
                    let displacement = if accumulator == instruction.value {
                        instruction.jump_true
                    } else {
                        instruction.jump_false
                    };
                    program_counter += usize::from(displacement) + 1;
                }
                BPF_RET_K => return instruction.value,
                _ => panic!("unexpected classic-BPF opcode"),
            }
        }
    }

    fn evaluate_exact_filter(arch: u32, syscall: u32, argument_zero: u64) -> u32 {
        evaluate_filter(
            &exact_provider_seccomp_filter(),
            arch,
            syscall,
            argument_zero,
        )
    }

    fn evaluate_exact_filter_with_arguments(
        arch: u32,
        syscall: u32,
        argument_zero: u64,
        argument_one: u64,
    ) -> u32 {
        evaluate_filter_with_arguments(
            &exact_provider_seccomp_filter(),
            arch,
            syscall,
            argument_zero,
            argument_one,
        )
    }

    #[test]
    fn provider_native_bootstrap_abi_substitution_fails_after_rehash() {
        let mut abi_drift = recipe(Provider::Codex);
        abi_drift.bootstrap_abi_sha256 = digest(99);
        abi_drift.recipe_binding_sha256 = abi_drift.canonical_sha256().unwrap();
        assert!(!abi_drift.validate());
    }

    #[test]
    fn exact_filter_binds_arch_descendant_denials_and_exec_allowance() {
        let filter = exact_provider_seccomp_filter();
        assert_eq!(filter.len(), 37);
        assert_eq!(filter[0].value, SECCOMP_DATA_ARCH_OFFSET);
        assert_eq!(filter[1].value, REVIEWED_AUDIT_ARCH);
        assert_eq!(filter[2].value, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(filter[3].value, SECCOMP_DATA_NR_OFFSET);
        assert_eq!(filter[4].value, X32_SYSCALL_BIT);
        assert_eq!(filter[6].value, SECCOMP_RET_KILL_PROCESS);
        assert_eq!(filter[7].value, SECCOMP_DATA_NR_OFFSET);
        assert_eq!(filter[8].value, DENIED_SYSCALLS[1]);
        assert_eq!(filter[9].value, SECCOMP_RET_ERRNO_ENOSYS);
        for (offset, syscall) in DENIED_SYSCALLS[2..].iter().copied().enumerate() {
            assert_eq!(filter[10 + offset * 2].value, syscall);
            assert_eq!(filter[11 + offset * 2].value, SECCOMP_RET_ERRNO_EPERM);
        }
        assert_eq!(filter[14].value, PRCTL_SYSCALL);
        assert_eq!(filter[15].value, SECCOMP_DATA_ARGUMENT_ZERO_OFFSET);
        assert_eq!(filter[16].value, PR_SET_DUMPABLE_VALUE);
        assert_eq!(filter[17].value, SECCOMP_DATA_ARGUMENT_ONE_HIGH_OFFSET);
        assert_eq!(filter[19].value, SECCOMP_DATA_ARGUMENT_ONE_OFFSET);
        assert_eq!(filter[21].value, SECCOMP_RET_ERRNO_EPERM);
        assert_eq!(filter[23].value, DENIED_SYSCALLS[0]);
        assert_eq!(filter[24].value, SECCOMP_DATA_ARGUMENT_ZERO_HIGH_OFFSET);
        assert_eq!(filter[26].value, SECCOMP_RET_ERRNO_EPERM);
        assert_eq!(filter[28].value, EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS);
        assert_eq!(filter[30].value, REQUIRED_PTHREAD_CLONE_FLAGS);
        assert_eq!(filter[31].value, REQUIRED_PTHREAD_CLONE_FLAGS);
        assert_eq!(filter[33].value, FORBIDDEN_PROCESS_CLONE_FLAGS);
        assert_eq!(filter[36].value, SECCOMP_RET_ALLOW);
        assert_eq!(
            evaluate_exact_filter(REVIEWED_AUDIT_ARCH, DENIED_SYSCALLS[1], 0),
            SECCOMP_RET_ERRNO_ENOSYS
        );
        for syscall in DENIED_SYSCALLS[2..].iter().copied() {
            assert_eq!(
                evaluate_exact_filter(REVIEWED_AUDIT_ARCH, syscall, 0),
                SECCOMP_RET_ERRNO_EPERM
            );
        }
        assert_eq!(
            evaluate_exact_filter_with_arguments(
                REVIEWED_AUDIT_ARCH,
                PRCTL_SYSCALL,
                u64::from(PR_SET_DUMPABLE_VALUE),
                0,
            ),
            SECCOMP_RET_ALLOW
        );
        for nonzero in [1, 1_u64 << 40] {
            assert_eq!(
                evaluate_exact_filter_with_arguments(
                    REVIEWED_AUDIT_ARCH,
                    PRCTL_SYSCALL,
                    u64::from(PR_SET_DUMPABLE_VALUE),
                    nonzero,
                ),
                SECCOMP_RET_ERRNO_EPERM
            );
        }
        assert_eq!(
            evaluate_exact_filter(
                REVIEWED_AUDIT_ARCH,
                DENIED_SYSCALLS[0],
                u64::from(EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS),
            ),
            SECCOMP_RET_ALLOW
        );
        for drift in [
            0x0000_0011,
            EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS ^ 17,
            EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS | 0x0000_1000,
            EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS | 0x1000_0000,
        ] {
            assert_eq!(
                evaluate_exact_filter(REVIEWED_AUDIT_ARCH, DENIED_SYSCALLS[0], u64::from(drift),),
                SECCOMP_RET_ERRNO_EPERM
            );
        }
        assert_eq!(
            evaluate_exact_filter(
                REVIEWED_AUDIT_ARCH,
                DENIED_SYSCALLS[0],
                u64::from(EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS) | (1_u64 << 40),
            ),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            evaluate_exact_filter(
                REVIEWED_AUDIT_ARCH,
                DENIED_SYSCALLS[0],
                u64::from(REQUIRED_PTHREAD_CLONE_FLAGS),
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate_exact_filter(
                REVIEWED_AUDIT_ARCH,
                DENIED_SYSCALLS[0],
                u64::from(REQUIRED_PTHREAD_CLONE_FLAGS) | (1_u64 << 40),
            ),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            evaluate_exact_filter(REVIEWED_AUDIT_ARCH, EXEC_SYSCALLS[0], 0),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate_exact_filter(REVIEWED_AUDIT_ARCH, EXEC_SYSCALLS[1], 0),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate_exact_filter(REVIEWED_AUDIT_ARCH ^ 1, DENIED_SYSCALLS[0], 0),
            SECCOMP_RET_KILL_PROCESS
        );
        #[cfg(target_arch = "x86_64")]
        assert_eq!(
            evaluate_exact_filter(REVIEWED_AUDIT_ARCH, X32_SYSCALL_BIT | EXEC_SYSCALLS[1], 0,),
            SECCOMP_RET_KILL_PROCESS
        );
        assert_ne!(
            exact_provider_seccomp_filter_sha256(),
            provider_native_bootstrap_abi_sha256(Provider::Codex).unwrap()
        );
    }

    #[test]
    fn target_aarch64_filter_is_explicit_and_semantically_closed_on_any_builder() {
        let filter = exact_aarch64_provider_seccomp_filter();
        assert_eq!(filter.len(), 37);
        assert_eq!(filter[1].value, AUDIT_ARCH_AARCH64);
        assert_eq!(filter[4].value, 0);
        assert_eq!(filter[8].value, 435);
        assert_eq!(filter[10].value, ABSENT_SYSCALL);
        assert_eq!(filter[12].value, ABSENT_SYSCALL);
        assert_eq!(filter[14].value, 167);
        assert_eq!(filter[23].value, 220);
        assert_eq!(filter[28].value, EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS);

        assert_eq!(
            evaluate_filter(&filter, AUDIT_ARCH_AARCH64, 435, 0),
            SECCOMP_RET_ERRNO_ENOSYS
        );
        for syscall in [221, 281] {
            assert_eq!(
                evaluate_filter(&filter, AUDIT_ARCH_AARCH64, syscall, 0),
                SECCOMP_RET_ALLOW
            );
        }
        assert_eq!(
            evaluate_filter_with_arguments(
                &filter,
                AUDIT_ARCH_AARCH64,
                167,
                u64::from(PR_SET_DUMPABLE_VALUE),
                1,
            ),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            evaluate_filter_with_arguments(
                &filter,
                AUDIT_ARCH_AARCH64,
                167,
                u64::from(PR_SET_DUMPABLE_VALUE),
                0,
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate_filter(
                &filter,
                AUDIT_ARCH_AARCH64,
                220,
                u64::from(EXACT_MUSL_VFORK_SPAWN_CLONE_FLAGS),
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate_filter(
                &filter,
                AUDIT_ARCH_AARCH64,
                220,
                u64::from(REQUIRED_PTHREAD_CLONE_FLAGS),
            ),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            evaluate_filter(
                &filter,
                AUDIT_ARCH_AARCH64,
                220,
                u64::from(REQUIRED_PTHREAD_CLONE_FLAGS) | 0x2000_0000,
            ),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            evaluate_filter(&filter, AUDIT_ARCH_AARCH64 ^ 1, 220, 0),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[test]
    fn execute_only_would_dump_candidate_rejects_representative_contract_drift() {
        let valid = KernelWouldDumpExecuteOnlyEvidenceV1::valid_for_test();
        assert!(valid.validates_source_candidate());

        let mut sysctl_two = KernelWouldDumpExecuteOnlyEvidenceV1::valid_for_test();
        sysctl_two.fs_suid_dumpable = 2;
        assert!(!sysctl_two.validates_source_candidate());

        let mut readable = KernelWouldDumpExecuteOnlyEvidenceV1::valid_for_test();
        readable.executable_mode = 0o555;
        assert!(!readable.validates_source_candidate());

        let mut unsealed = KernelWouldDumpExecuteOnlyEvidenceV1::valid_for_test();
        unsealed.trusted_init_sealed_sysctl = false;
        assert!(!unsealed.validates_source_candidate());

        let mut target_unknown = KernelWouldDumpExecuteOnlyEvidenceV1::valid_for_test();
        target_unknown.target_kernel_config_verified = false;
        assert!(!target_unknown.validates_source_candidate());

        let mut wrong_contract = KernelWouldDumpExecuteOnlyEvidenceV1::valid_for_test();
        wrong_contract.kernel_contract_sha256 = digest(99);
        assert!(!wrong_contract.validates_source_candidate());
    }

    #[test]
    fn source_contract_is_affine_non_serde_and_product_closed() {
        let source = include_str!("provider_post_exec_bootstrap.rs");
        for affine in [
            "AuthenticatedProviderBootstrapRecipeInputs",
            "ClosedProviderFinalRuntimeBootstrapRecipe",
            "KernelWouldDumpExecuteOnlyEvidenceV1",
        ] {
            let declaration = source
                .find(&format!("struct {affine}"))
                .expect("affine declaration");
            let attributes_start = source[..declaration]
                .rfind("#[must_use")
                .expect("must-use affine attribute");
            let attributes = &source[attributes_start..declaration];
            assert!(!attributes.contains("#[derive"));
        }
        const {
            assert!(SOURCE_POST_FINAL_EXEC_BOOTSTRAP_RECIPE_IMPLEMENTED);
            assert!(SOURCE_EXACT_SECCOMP_FILTER_DIGEST_BOUND);
            assert!(SOURCE_LINUX_HELD_FIXTURE_PRODUCER_IMPLEMENTED);
            assert!(SOURCE_SHARED_FREESTANDING_BOOTSTRAP_CORE_IMPLEMENTED);
            assert!(!PRODUCT_POST_FINAL_EXEC_BOOTSTRAP_AVAILABLE);
            assert!(!PRODUCT_EXACT_SECCOMP_FILTER_OBSERVATION_AVAILABLE);
            assert!(!PRODUCT_EXACT_DUMPABLE_OBSERVATION_AVAILABLE);
            assert!(!PRODUCT_PROVIDER_PAYLOAD_RECIPE_WIRED);
            assert!(!CONFERS_EFFECT_AUTHORITY);
        }
        assert!(!source.contains(concat!("serde", "::")));
    }
}
