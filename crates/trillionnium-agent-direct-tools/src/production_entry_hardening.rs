//! Product Direct Tool entry re-hardening checkpoint.
//!
//! `execve` resets dumpability after the provider boundary has already entered
//! the executable loader and language runtime.  The two product Direct Tool
//! binaries therefore call [`enter_product_direct_tool_checkpoint`] as their
//! first Rust action, before inspecting argv or reading stdin.  The checkpoint
//! reasserts dumpable zero and validates the inherited kernel state using
//! syscalls wherever Linux exposes an exact query.  Only the SELinux domain
//! and cgroup-v2 membership require bounded kernel-generated procfs files.
//!
//! This is intentionally **not** an admission capability or an effect
//! authority.  It cannot observe or close the loader/CRT interval before the
//! first Rust instruction. `PR_GET_SECCOMP == 2` proves only that some filter
//! is active: Linux provides no unprivileged readback that could bind this
//! process to the expected 37-instruction provider filter. Exact filter-image
//! measurement remains an outer bootstrap/broker responsibility. Its cgroup
//! membership sample likewise cannot replace a broker-retained cgroup
//! directory FD, pidfd, descendant census, or a post-effect zero-survivor
//! proof. Product manifests and the existing effect gates must remain closed
//! until that outer custody exists.

use std::io;

use thiserror::Error;
use trillionnium_os_types::agent_principal_registry::{
    ACCESSIBILITY_ENDPOINT, AgentStablePrincipal, SYSTEM_API_ENDPOINT, from_uid_gid,
};
use trillionnium_os_types::direct_operation::DirectOperationAdapter;

use crate::trusted_context::{
    TrustedContextError, current_selinux_domain, read_current_unified_cgroup,
    require_fixed_adapter_cgroup,
};

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const MAX_V3_CAPABILITY: u32 = 63;
const FIRST_UNREPRESENTABLE_CAPABILITY: u32 = MAX_V3_CAPABILITY + 1;

pub type ProductEntryResult<T> = Result<T, ProductEntryError>;

#[derive(Debug, Error)]
pub enum ProductEntryError {
    #[error("product Direct Tool entry checkpoint denied: {0}")]
    Denied(&'static str),
    #[error("product Direct Tool entry checkpoint kernel query failed: {0}")]
    Io(#[from] io::Error),
    #[error("product Direct Tool entry checkpoint trusted identity failed: {0}")]
    Trusted(#[from] TrustedContextError),
}

/// Instantaneous local observation that this process completed the entry check.
///
/// The value deliberately exposes no constructor, authority method, or
/// serializable evidence.  It proves neither the pre-Rust loader interval nor
/// continued outer custody after this instantaneous observation.
#[derive(Debug)]
#[must_use = "a successful local product entry observation must not be silently discarded"]
pub struct ProductDirectToolEntryCheckpoint {
    _private: (),
}

/// Reassert and validate the local product Direct Tool process boundary.
///
/// The caller must invoke this as its first Rust action.  Success does not
/// authorize any backend request; the separately sealed trusted context and
/// outer operation authorities remain mandatory.
pub fn enter_product_direct_tool_checkpoint(
    adapter: DirectOperationAdapter,
) -> ProductEntryResult<ProductDirectToolEntryCheckpoint> {
    enter_with_kernel(adapter, &mut LinuxEntryKernel)
}

trait EntryKernel {
    fn set_dumpable_zero(&mut self) -> ProductEntryResult<()>;
    fn dumpable(&mut self) -> ProductEntryResult<libc::c_int>;
    fn no_new_privs(&mut self) -> ProductEntryResult<libc::c_int>;
    fn seccomp_mode(&mut self) -> ProductEntryResult<libc::c_int>;
    fn process_identity(&mut self) -> ProductEntryResult<ProcessIdentity>;
    fn supplementary_group_count(&mut self) -> ProductEntryResult<libc::c_int>;
    fn capabilities(&mut self) -> ProductEntryResult<CapabilitySnapshot>;
    fn core_limits(&mut self) -> ProductEntryResult<CoreLimits>;
    fn selinux_domain(&mut self) -> ProductEntryResult<String>;
    fn unified_cgroup(&mut self) -> ProductEntryResult<String>;
}

fn enter_with_kernel(
    adapter: DirectOperationAdapter,
    kernel: &mut impl EntryKernel,
) -> ProductEntryResult<ProductDirectToolEntryCheckpoint> {
    // Keep this first. The provider's inherited filter permits exactly this
    // PR_SET_DUMPABLE argument and denies attempts to restore a nonzero value.
    // This local checkpoint consumes that outer contract; it cannot attest the
    // installed filter program's identity.
    kernel.set_dumpable_zero()?;
    if kernel.dumpable()? != 0 {
        return Err(denied("dumpability is not exactly zero"));
    }
    if kernel.no_new_privs()? != 1 {
        return Err(denied("no-new-privileges is not exactly one"));
    }
    if kernel.seccomp_mode()? != libc::SECCOMP_MODE_FILTER as libc::c_int {
        return Err(denied("seccomp filter mode is not active"));
    }

    let identity = kernel.process_identity()?;
    let principal = fixed_agent_principal(identity)?;
    if kernel.supplementary_group_count()? != 0 {
        return Err(denied("supplementary groups are not empty"));
    }

    let capabilities = kernel.capabilities()?;
    if capabilities.inheritable != 0
        || capabilities.permitted != 0
        || capabilities.effective != 0
        || capabilities.bounding != 0
        || capabilities.ambient != 0
    {
        return Err(denied("one or more Linux capability sets are nonempty"));
    }

    let limits = kernel.core_limits()?;
    if limits.soft != 0 || limits.hard != 0 {
        return Err(denied("RLIMIT_CORE soft and hard limits are not zero"));
    }

    let expected_domain = match adapter {
        DirectOperationAdapter::SystemApi => SYSTEM_API_ENDPOINT.tool_selinux_domain,
        DirectOperationAdapter::Accessibility => ACCESSIBILITY_ENDPOINT.tool_selinux_domain,
    };
    if kernel.selinux_domain()? != expected_domain {
        return Err(denied("SELinux domain is not the fixed Direct Tool domain"));
    }
    require_fixed_adapter_cgroup(principal.provider_id, adapter, &kernel.unified_cgroup()?)?;

    Ok(ProductDirectToolEntryCheckpoint { _private: () })
}

fn fixed_agent_principal(
    identity: ProcessIdentity,
) -> ProductEntryResult<&'static AgentStablePrincipal> {
    if identity.real_uid != identity.effective_uid || identity.real_gid != identity.effective_gid {
        return Err(denied("real and effective UID/GID identities do not match"));
    }
    let principal = from_uid_gid(identity.real_uid, identity.real_gid)
        .ok_or_else(|| denied("UID/GID identity is not the canonical Codex principal"))?;
    if identity.saved_uid != principal.uid
        || identity.filesystem_uid != principal.uid
        || identity.saved_gid != principal.gid
        || identity.filesystem_gid != principal.gid
    {
        return Err(denied(
            "saved or filesystem UID/GID does not match the canonical Agent principal",
        ));
    }
    Ok(principal)
}

const fn denied(message: &'static str) -> ProductEntryError {
    ProductEntryError::Denied(message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcessIdentity {
    real_uid: u32,
    effective_uid: u32,
    saved_uid: u32,
    filesystem_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    saved_gid: u32,
    filesystem_gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CapabilitySnapshot {
    inheritable: u64,
    permitted: u64,
    effective: u64,
    bounding: u64,
    ambient: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoreLimits {
    soft: libc::rlim_t,
    hard: libc::rlim_t,
}

struct LinuxEntryKernel;

impl EntryKernel for LinuxEntryKernel {
    fn set_dumpable_zero(&mut self) -> ProductEntryResult<()> {
        // SAFETY: this is the documented scalar PR_SET_DUMPABLE form. All
        // unused arguments are explicitly zero for the inherited BPF policy.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn dumpable(&mut self) -> ProductEntryResult<libc::c_int> {
        prctl_get_scalar(libc::PR_GET_DUMPABLE)
    }

    fn no_new_privs(&mut self) -> ProductEntryResult<libc::c_int> {
        prctl_get_scalar(libc::PR_GET_NO_NEW_PRIVS)
    }

    fn seccomp_mode(&mut self) -> ProductEntryResult<libc::c_int> {
        prctl_get_scalar(libc::PR_GET_SECCOMP)
    }

    fn process_identity(&mut self) -> ProductEntryResult<ProcessIdentity> {
        let mut real_uid = u32::MAX;
        let mut effective_uid = u32::MAX;
        let mut saved_uid = u32::MAX;
        let mut real_gid = u32::MAX;
        let mut effective_gid = u32::MAX;
        let mut saved_gid = u32::MAX;
        // SAFETY: all pointers name live writable uid_t/gid_t values.
        if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
            || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
        {
            return Err(io::Error::last_os_error().into());
        }
        // Linux has no read-only fsuid/fsgid syscall. Passing `(id_t)-1` is
        // the documented query idiom: UINT32_MAX is not a valid mapped ID, so
        // the attempted assignment is ignored and the syscall returns the
        // prior value. The fixed product IDs are small canonical registry IDs.
        let filesystem_uid = unsafe { libc::setfsuid(u32::MAX) };
        let filesystem_gid = unsafe { libc::setfsgid(u32::MAX) };
        if filesystem_uid < 0 || filesystem_gid < 0 {
            return Err(denied("filesystem UID/GID query returned an invalid value"));
        }
        Ok(ProcessIdentity {
            real_uid,
            effective_uid,
            saved_uid,
            filesystem_uid: filesystem_uid as u32,
            real_gid,
            effective_gid,
            saved_gid,
            filesystem_gid: filesystem_gid as u32,
        })
    }

    fn supplementary_group_count(&mut self) -> ProductEntryResult<libc::c_int> {
        // A zero-sized getgroups call returns the exact supplementary-list
        // length without accepting or truncating caller-sized storage.
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if count < 0 {
            return Err(io::Error::last_os_error().into());
        }
        Ok(count)
    }

    fn capabilities(&mut self) -> ProductEntryResult<CapabilitySnapshot> {
        current_capabilities()
    }

    fn core_limits(&mut self) -> ProductEntryResult<CoreLimits> {
        let mut limits = std::mem::MaybeUninit::<libc::rlimit>::zeroed();
        // SAFETY: limits points to writable storage for one libc::rlimit.
        if unsafe { libc::getrlimit(libc::RLIMIT_CORE, limits.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: getrlimit succeeded and initialized both scalar fields.
        let limits = unsafe { limits.assume_init() };
        Ok(CoreLimits {
            soft: limits.rlim_cur,
            hard: limits.rlim_max,
        })
    }

    fn selinux_domain(&mut self) -> ProductEntryResult<String> {
        current_selinux_domain().map_err(Into::into)
    }

    fn unified_cgroup(&mut self) -> ProductEntryResult<String> {
        read_current_unified_cgroup().map_err(Into::into)
    }
}

fn prctl_get_scalar(option: libc::c_int) -> ProductEntryResult<libc::c_int> {
    // SAFETY: these PR_GET operations return a scalar and require zeroed
    // unused arguments.
    let value = unsafe { libc::prctl(option, 0, 0, 0, 0) };
    if value < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(value)
    }
}

#[repr(C)]
struct UserCapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UserCapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn current_capabilities() -> ProductEntryResult<CapabilitySnapshot> {
    let mut header = UserCapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [UserCapabilityData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: capget receives the exact v3 header and writable two-word data
    // array required for the current thread (`pid == 0`).
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if header.version != LINUX_CAPABILITY_VERSION_3 {
        return Err(denied("kernel did not honor capability ABI v3"));
    }

    let inheritable = u64::from(data[0].inheritable) | (u64::from(data[1].inheritable) << 32);
    let permitted = u64::from(data[0].permitted) | (u64::from(data[1].permitted) << 32);
    let effective = u64::from(data[0].effective) | (u64::from(data[1].effective) << 32);
    let mut bounding = 0_u64;
    let mut ambient = 0_u64;
    let mut invalid_capability_seen = false;
    for capability in 0..=MAX_V3_CAPABILITY {
        let bounding_value = query_capability(libc::PR_CAPBSET_READ, 0, capability)?;
        let ambient_value = query_capability(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_IS_SET,
            capability,
        )?;
        match (bounding_value, ambient_value) {
            (Some(bound), Some(amb)) if !invalid_capability_seen => {
                if bound {
                    bounding |= 1_u64 << capability;
                }
                if amb {
                    ambient |= 1_u64 << capability;
                }
            }
            (None, None) => invalid_capability_seen = true,
            _ => {
                return Err(denied(
                    "kernel capability namespace is sparse or query semantics disagree",
                ));
            }
        }
    }
    if query_capability(libc::PR_CAPBSET_READ, 0, FIRST_UNREPRESENTABLE_CAPABILITY)?.is_some()
        || query_capability(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_IS_SET,
            FIRST_UNREPRESENTABLE_CAPABILITY,
        )?
        .is_some()
    {
        return Err(denied(
            "kernel exposes capabilities outside the v3 observation width",
        ));
    }

    Ok(CapabilitySnapshot {
        inheritable,
        permitted,
        effective,
        bounding,
        ambient,
    })
}

fn query_capability(
    option: libc::c_int,
    suboption: libc::c_int,
    capability: u32,
) -> ProductEntryResult<Option<bool>> {
    // SAFETY: both query forms are scalar prctl operations. No pointer is
    // passed and all unused words are zero.
    let value = unsafe {
        if option == libc::PR_CAP_AMBIENT {
            libc::prctl(option, suboption, capability, 0, 0)
        } else {
            libc::prctl(option, capability, 0, 0, 0)
        }
    };
    match value {
        0 => Ok(Some(false)),
        1 => Ok(Some(true)),
        -1 if io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) => Ok(None),
        -1 => Err(io::Error::last_os_error().into()),
        _ => Err(denied(
            "kernel capability query returned a non-boolean value",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL;
    use trillionnium_os_types::direct_operation::fixed_adapter_cgroup_path;

    #[derive(Clone)]
    struct FakeKernel {
        fail_set_dumpable: bool,
        retain_nonzero_dumpable: bool,
        dumpable: libc::c_int,
        no_new_privs: libc::c_int,
        seccomp_mode: libc::c_int,
        identity: ProcessIdentity,
        supplementary_groups: libc::c_int,
        capabilities: CapabilitySnapshot,
        limits: CoreLimits,
        domain: String,
        cgroup: String,
        calls: Vec<&'static str>,
    }

    impl FakeKernel {
        fn exact(
            principal: &'static AgentStablePrincipal,
            adapter: DirectOperationAdapter,
        ) -> Self {
            let domain = match adapter {
                DirectOperationAdapter::SystemApi => SYSTEM_API_ENDPOINT.tool_selinux_domain,
                DirectOperationAdapter::Accessibility => ACCESSIBILITY_ENDPOINT.tool_selinux_domain,
            };
            Self {
                fail_set_dumpable: false,
                retain_nonzero_dumpable: false,
                dumpable: 0,
                no_new_privs: 1,
                seccomp_mode: libc::SECCOMP_MODE_FILTER as libc::c_int,
                identity: ProcessIdentity {
                    real_uid: principal.uid,
                    effective_uid: principal.uid,
                    saved_uid: principal.uid,
                    filesystem_uid: principal.uid,
                    real_gid: principal.gid,
                    effective_gid: principal.gid,
                    saved_gid: principal.gid,
                    filesystem_gid: principal.gid,
                },
                supplementary_groups: 0,
                capabilities: CapabilitySnapshot {
                    inheritable: 0,
                    permitted: 0,
                    effective: 0,
                    bounding: 0,
                    ambient: 0,
                },
                limits: CoreLimits { soft: 0, hard: 0 },
                domain: domain.to_string(),
                cgroup: format!(
                    "0::{}\n",
                    fixed_adapter_cgroup_path(principal.provider_id, adapter).unwrap()
                ),
                calls: Vec::new(),
            }
        }
    }

    impl EntryKernel for FakeKernel {
        fn set_dumpable_zero(&mut self) -> ProductEntryResult<()> {
            self.calls.push("set-dumpable-zero");
            if self.fail_set_dumpable {
                Err(io::Error::from_raw_os_error(libc::EPERM).into())
            } else {
                if !self.retain_nonzero_dumpable {
                    self.dumpable = 0;
                }
                Ok(())
            }
        }

        fn dumpable(&mut self) -> ProductEntryResult<libc::c_int> {
            self.calls.push("get-dumpable");
            Ok(self.dumpable)
        }

        fn no_new_privs(&mut self) -> ProductEntryResult<libc::c_int> {
            self.calls.push("get-no-new-privs");
            Ok(self.no_new_privs)
        }

        fn seccomp_mode(&mut self) -> ProductEntryResult<libc::c_int> {
            self.calls.push("get-seccomp");
            Ok(self.seccomp_mode)
        }

        fn process_identity(&mut self) -> ProductEntryResult<ProcessIdentity> {
            self.calls.push("get-identity");
            Ok(self.identity)
        }

        fn supplementary_group_count(&mut self) -> ProductEntryResult<libc::c_int> {
            self.calls.push("get-groups");
            Ok(self.supplementary_groups)
        }

        fn capabilities(&mut self) -> ProductEntryResult<CapabilitySnapshot> {
            self.calls.push("get-capabilities");
            Ok(self.capabilities)
        }

        fn core_limits(&mut self) -> ProductEntryResult<CoreLimits> {
            self.calls.push("get-core-limits");
            Ok(self.limits)
        }

        fn selinux_domain(&mut self) -> ProductEntryResult<String> {
            self.calls.push("get-selinux-domain");
            Ok(self.domain.clone())
        }

        fn unified_cgroup(&mut self) -> ProductEntryResult<String> {
            self.calls.push("get-cgroup");
            Ok(self.cgroup.clone())
        }
    }

    #[test]
    fn all_fixed_provider_adapter_pairs_pass_the_local_checkpoint() {
        for principal in [&CODEX_STABLE_PRINCIPAL] {
            for adapter in [
                DirectOperationAdapter::SystemApi,
                DirectOperationAdapter::Accessibility,
            ] {
                let mut kernel = FakeKernel::exact(principal, adapter);
                let _checkpoint = enter_with_kernel(adapter, &mut kernel).unwrap();
                assert_eq!(kernel.calls.first(), Some(&"set-dumpable-zero"));
            }
        }
    }

    #[test]
    fn every_required_kernel_property_fails_closed() {
        type Mutation = Box<dyn Fn(&mut FakeKernel)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(|k| k.fail_set_dumpable = true),
            Box::new(|k| {
                k.dumpable = 1;
                k.retain_nonzero_dumpable = true;
            }),
            Box::new(|k| k.no_new_privs = 0),
            Box::new(|k| k.seccomp_mode = libc::SECCOMP_MODE_DISABLED as libc::c_int),
            Box::new(|k| k.seccomp_mode = libc::SECCOMP_MODE_STRICT as libc::c_int),
            Box::new(|k| k.identity.effective_uid += 1),
            Box::new(|k| k.identity.effective_gid += 1),
            Box::new(|k| k.identity.saved_uid += 1),
            Box::new(|k| k.identity.filesystem_uid += 1),
            Box::new(|k| k.identity.saved_gid += 1),
            Box::new(|k| k.identity.filesystem_gid += 1),
            Box::new(|k| {
                k.identity.real_uid = 1234;
                k.identity.effective_uid = 1234;
            }),
            Box::new(|k| {
                k.identity.real_gid = 1234;
                k.identity.effective_gid = 1234;
                k.identity.saved_gid = 1234;
                k.identity.filesystem_gid = 1234;
            }),
            Box::new(|k| k.supplementary_groups = 1),
            Box::new(|k| k.capabilities.inheritable = 1),
            Box::new(|k| k.capabilities.permitted = 1),
            Box::new(|k| k.capabilities.effective = 1),
            Box::new(|k| k.capabilities.bounding = 1),
            Box::new(|k| k.capabilities.bounding = 1_u64 << 63),
            Box::new(|k| k.capabilities.ambient = 1),
            Box::new(|k| k.limits.soft = 1),
            Box::new(|k| k.limits.hard = 1),
            Box::new(|k| k.domain = ACCESSIBILITY_ENDPOINT.tool_selinux_domain.to_string()),
            Box::new(|k| k.cgroup = "0::/trillionnium/agents/other/system-api\n".into()),
            Box::new(|k| k.cgroup = "0::/trillionnium/agents/codex/system-api/child\n".into()),
        ];
        for mutate in mutations {
            let mut kernel =
                FakeKernel::exact(&CODEX_STABLE_PRINCIPAL, DirectOperationAdapter::SystemApi);
            mutate(&mut kernel);
            assert!(enter_with_kernel(DirectOperationAdapter::SystemApi, &mut kernel).is_err());
            assert_eq!(kernel.calls.first(), Some(&"set-dumpable-zero"));
        }
    }

    #[test]
    fn dumpable_is_reasserted_before_it_is_observed() {
        let mut kernel =
            FakeKernel::exact(&CODEX_STABLE_PRINCIPAL, DirectOperationAdapter::SystemApi);
        kernel.dumpable = 1;
        let _checkpoint =
            enter_with_kernel(DirectOperationAdapter::SystemApi, &mut kernel).unwrap();
        assert_eq!(kernel.calls[..2], ["set-dumpable-zero", "get-dumpable"]);
        assert_eq!(kernel.dumpable, 0);
    }

    #[test]
    fn product_binary_sources_enter_before_argv_or_stdin() {
        for source in [
            include_str!("bin/system_api.rs"),
            include_str!("bin/accessibility.rs"),
        ] {
            let entry = source
                .find(
                    "let _entry_checkpoint = production_entry_hardening::enter_product_direct_tool_checkpoint(",
                )
                .expect("product entry checkpoint call");
            let run = source[..entry]
                .rfind("fn run() -> trillionnium_agent_direct_tools::Result<()> {")
                .expect("product run function containing entry checkpoint");
            let argv = source.find("std::env::args_os").expect("argv read");
            let stdin = source.find("read_request()?").expect("stdin read");
            assert!(run < entry && entry < argv && entry < stdin);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_product_linux_host_capability_query_boundary_is_dense() {
        // These are read-only, unprivileged kernel queries. This host-only
        // interface check is neither AArch64 product-success evidence nor a
        // measurement of any process capability set.
        let mut invalid_capability_seen = false;
        for capability in 0..=FIRST_UNREPRESENTABLE_CAPABILITY {
            let bounding = query_capability(libc::PR_CAPBSET_READ, 0, capability).unwrap();
            let ambient = query_capability(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET,
                capability,
            )
            .unwrap();
            assert_eq!(
                bounding.is_some(),
                ambient.is_some(),
                "host capability query APIs disagree at {capability}"
            );
            if invalid_capability_seen {
                assert!(
                    bounding.is_none(),
                    "host capability namespace is sparse at {capability}"
                );
            }
            invalid_capability_seen |= bounding.is_none();
        }
        assert!(
            invalid_capability_seen,
            "host exposes a capability outside the v3 observation width"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_dumpable_filter_model_denies_nonzero_reenable() {
        // This isolated child filter models the exact inherited provider
        // property consumed by this checkpoint. It is not product admission
        // evidence and deliberately does not duplicate the full provider BPF.
        const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
        const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
        const SECCOMP_DATA_NR: u32 = 0;
        const SECCOMP_DATA_ARGS_0: u32 = 16;
        const SECCOMP_DATA_ARGS_1_LOW: u32 = 24;
        const SECCOMP_DATA_ARGS_1_HIGH: u32 = 28;
        let mut filters = [
            bpf_statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, SECCOMP_DATA_NR),
            bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                libc::SYS_prctl as u32,
                0,
                7,
            ),
            bpf_statement(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                SECCOMP_DATA_ARGS_0,
            ),
            bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                libc::PR_SET_DUMPABLE as u32,
                0,
                5,
            ),
            bpf_statement(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                SECCOMP_DATA_ARGS_1_HIGH,
            ),
            bpf_jump(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 0, 2),
            bpf_statement(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                SECCOMP_DATA_ARGS_1_LOW,
            ),
            bpf_jump(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 1, 0),
            bpf_statement(
                libc::BPF_RET | libc::BPF_K,
                SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ),
            bpf_statement(libc::BPF_RET | libc::BPF_K, SECCOMP_RET_ALLOW),
        ];
        let program = libc::sock_fprog {
            len: filters.len() as u16,
            filter: filters.as_mut_ptr(),
        };
        // SAFETY: the child executes only scalar syscalls and exits via
        // _exit; the parent retains all Rust runtime state.
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let ok = unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
                    && libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) == 0
                    && libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0
                    && libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
                    && libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) == -1
                    && *libc::__errno_location() == libc::EPERM
                    && libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
                    && libc::prctl(libc::PR_SET_DUMPABLE, 2, 0, 0, 0) == -1
                    && *libc::__errno_location() == libc::EPERM
                    && libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
                    && libc::prctl(
                        libc::PR_SET_DUMPABLE,
                        (1_u64 << 32) as libc::c_ulong,
                        0,
                        0,
                        0,
                    ) == -1
                    && *libc::__errno_location() == libc::EPERM
                    && libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
            };
            unsafe { libc::_exit(i32::from(!ok)) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[cfg(target_os = "linux")]
    const fn bpf_statement(code: u32, value: u32) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k: value,
        }
    }

    #[cfg(target_os = "linux")]
    const fn bpf_jump(code: u32, value: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k: value,
        }
    }
}
