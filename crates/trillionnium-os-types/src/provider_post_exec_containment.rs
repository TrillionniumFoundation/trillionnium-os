//! Requirements, evidence ABI and affine source carrier for future provider
//! post-exec containment.
//!
//! Record validation proves only that caller-visible data is canonical and
//! internally bound. It does not authenticate who produced a record. An opaque
//! affine carrier is also defined, but this checkpoint deliberately has no
//! production constructor for it. Its private injected producer and held-child
//! custody seams exist only in module tests. A future product implementation
//! must authenticate the exact provisioned policy anchor and obtain every
//! observation from one OS-owned, pidfd-bound launch broker while the child
//! remains stopped after its final exec and hardening event.
//!
//! No production policy constructor, broker transport, launch implementation,
//! process-supervisor consumer, resource-release token, or provider wiring is
//! present in this checkpoint.

use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(test)]
use crate::agent_descriptor_registry;
use crate::agent_principal_registry;
use crate::direct_operation::{
    PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT,
    PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT, PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH,
    PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS, PROVIDER_SUBTREE_EXPECTED_DESCENDANT_COUNT,
    PROVIDER_SUBTREE_EXPECTED_DYING_DESCENDANT_COUNT, PROVIDER_SUBTREE_EXPECTED_MAX_DEPTH,
    PROVIDER_SUBTREE_EXPECTED_MAX_DESCENDANTS, PROVIDER_SUBTREE_EXPECTED_PROCESS_COUNT,
    ProviderCgroupResourcePolicyV1, ProviderCgroupTopologyV2, fixed_provider_runtime_cgroup_path,
};

pub const PROTOCOL: &str = "trillionnium.provider-post-exec-containment.requirements.v2";
pub const PROVISIONED_POLICY_V2_SCHEMA: &str =
    "trillionnium.provisioned-provider-runtime-policy.v2";
pub const PROVIDER_SUBTREE_RESERVATION_EVIDENCE_V2_SCHEMA: &str =
    "trillionnium.provider-subtree-reservation-evidence.v2";
pub const LAUNCH_INTENT_V2_SCHEMA: &str =
    "trillionnium.provider-post-exec-containment-launch-intent.v2";
pub const SPAWN_HELD_EVIDENCE_V2_SCHEMA: &str =
    "trillionnium.provider-post-exec-containment-spawn-held-evidence.v2";
pub const FINAL_EXEC_EVIDENCE_V2_SCHEMA: &str =
    "trillionnium.provider-post-exec-containment-final-exec-evidence.v2";

pub const SOURCE_REQUIREMENTS_EVIDENCE_ABI_IMPLEMENTED: bool = true;
pub const SOURCE_AFFINE_AUTHORITY_CARRIER_IMPLEMENTED: bool = true;
pub const PROVISIONED_POLICY_AUTHORITY_PRODUCT_AVAILABLE: bool = false;
pub const OS_LAUNCH_BROKER_PRODUCT_AVAILABLE: bool = false;
pub const EXEC_EVENT_AUTHORITY_PRODUCT_AVAILABLE: bool = false;
pub const POST_EXEC_HARDENING_PRODUCT_AVAILABLE: bool = false;
pub const DAEMON_CLIENT_PRODUCT_WIRED: bool = false;
pub const PROCESS_SUPERVISOR_PRODUCT_WIRED: bool = false;
pub const CODEX_PROVIDER_PRODUCT_WIRED: bool = false;
pub const PROVIDER_RESOURCE_ACTIVATION_PRODUCT_WIRED: bool = false;
pub const POST_EXEC_CONTAINMENT_PRODUCT_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

/// One-based sequence number of the sole accepted final-runtime image for an
/// invocation. This is not a raw kernel exec-event count or a launcher-to-final
/// transition distance; execution topology is expressed by the event-identity
/// relation validated below.
pub const FINAL_RUNTIME_EXEC_SEQUENCE: u64 = 1;

pub type ProviderPostExecContainmentResult<T> = Result<T, ProviderPostExecContainmentEvidenceError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderPostExecContainmentEvidenceError(&'static str);

impl ProviderPostExecContainmentEvidenceError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ProviderPostExecContainmentEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for ProviderPostExecContainmentEvidenceError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPostExecContainmentPhaseV2 {
    SpawnHeld,
    FinalExecVerifiedHeld,
}

impl ProviderPostExecContainmentPhaseV2 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SpawnHeld => "spawn_held",
            Self::FinalExecVerifiedHeld => "final_exec_verified_held",
        }
    }
}

/// Closed execution topology for the provisioned provider runtime.
///
/// The topology is provisioned policy, not an inference from two digest
/// strings. Both built-in providers enter through a measured native launcher
/// which retains outer supervision while it execs a distinct final runtime
/// image. `SingleFinalRuntimeImage` remains reserved for a future provider and
/// is not valid for either built-in Agent.
///
/// This `V1` is part of the unpublished source draft described on
/// [`ProvisionedProviderRuntimePolicyV2`]. Unknown or missing variants fail
/// closed; no compatibility fallback or provider-authored extension exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderRuntimeExecTopologyV1 {
    SingleFinalRuntimeImage,
    LauncherThenFinalRuntime,
}

impl ProviderRuntimeExecTopologyV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SingleFinalRuntimeImage => "single_final_runtime_image",
            Self::LauncherThenFinalRuntime => "launcher_then_final_runtime",
        }
    }
}

/// OS-owned source for the exec and hardening event stream.
///
/// A provider health probe or provider-authored message is intentionally not
/// representable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderExecEventAuthorityV1 {
    PrivilegeBrokerPtraceExecStop,
    PrivilegeBrokerSeccompExecNotification,
}

impl ProviderExecEventAuthorityV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PrivilegeBrokerPtraceExecStop => "privilege_broker_ptrace_exec_stop",
            Self::PrivilegeBrokerSeccompExecNotification => {
                "privilege_broker_seccomp_exec_notification"
            }
        }
    }
}

macro_rules! typed_sha256 {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            #[cfg(test)]
            fn test_value(seed: &str) -> Self {
                Self(test_digest(seed))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                if valid_nonzero_sha256(&value) {
                    Ok(Self(value))
                } else {
                    Err(serde::de::Error::custom(concat!(
                        stringify!($name),
                        " must be one non-zero lowercase SHA-256"
                    )))
                }
            }
        }
    };
}

typed_sha256!(DaemonChallengeV1);
typed_sha256!(DaemonRequestNonceV1);
typed_sha256!(BrokerReservationNonceV1);
typed_sha256!(BrokerSpawnNonceV1);
typed_sha256!(BrokerHardeningNonceV1);
typed_sha256!(BrokerVerificationNonceV1);

/// Privilege-broker allocated, non-zero provider-subtree generation.
///
/// There is intentionally no public raw-value constructor. Deserialization is
/// data parsing only and does not make the value authoritative.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct BrokerSubtreeGenerationV2(u64);

impl BrokerSubtreeGenerationV2 {
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    #[cfg(test)]
    const fn test_value(value: u64) -> Self {
        assert!(value != 0);
        Self(value)
    }
}

impl<'de> Deserialize<'de> for BrokerSubtreeGenerationV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 {
            Err(serde::de::Error::custom(
                "BrokerSubtreeGenerationV2 must be non-zero",
            ))
        } else {
            Ok(Self(value))
        }
    }
}

/// Immutable provisioned requirements for one provider runtime.
///
/// Fields are private and no product constructor exists. A future authority
/// must authenticate the exact `policy_anchor_sha256` against rollback-
/// resistant provisioned state before treating this data as policy.
///
/// `V2` is an unpublished source draft, not a frozen product wire version:
/// there is no product constructor, persisted product consumer, or released
/// byte contract. A product activation review must assign and freeze the first
/// published version rather than treating this draft label as compatibility.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvisionedProviderRuntimePolicyV2 {
    schema: String,
    protocol: String,
    provider_id: String,
    agent_id: String,
    runtime_exec_topology: ProviderRuntimeExecTopologyV1,
    /// Measured identity key for the dynamically provisioned Agent launcher
    /// entry executable. Stable provider identity is validated separately via
    /// the principal registry and deliberately does not pin this digest. For a
    /// single-image topology this is the final runtime executable itself.
    ///
    /// This is deliberately distinct from `agent_manifest_sha256`.
    agent_identity_key_sha256: String,
    /// SHA-256 of the exact, validated source AgentManifest bytes retained by
    /// the provisioner before any OS-authored timestamp mutation.
    ///
    /// A runtime `AgentRegistration` is not that source object: the OS mutates
    /// its registration and update timestamps. Product issuance must therefore
    /// authenticate retained source-manifest custody instead of hashing the
    /// runtime-mutated registration.
    agent_manifest_sha256: String,
    policy_authority_identity_sha256: String,
    policy_store_instance_sha256: String,
    system_image_sha256: String,
    avb_chain_sha256: String,
    boot_id_sha256: String,
    provisioning_manifest_sha256: String,
    provision_epoch_sha256: String,
    provisioned_launcher_executable_sha256: String,
    provisioned_final_runtime_executable_sha256: String,
    provisioned_final_runtime_closure_sha256: String,
    expected_uid: u32,
    expected_gid: u32,
    expected_selinux_domain: String,
    expected_provider_runtime_cgroup_leaf: String,
    expected_provider_cgroup_topology: ProviderCgroupTopologyV2,
    expected_provider_cgroup_resource_policy: ProviderCgroupResourcePolicyV1,
    fixed_cgroup_inventory_sha256: String,
    cgroup_directory_ancestry_sha256: String,
    provider_runtime_leaf_binding_sha256: String,
    provider_cgroup_policy_sha256: String,
    expected_exec_event_authority: ProviderExecEventAuthorityV1,
    /// Canonical SHA-256 of the exact classic-BPF seccomp program required
    /// after the final exec. `Seccomp: 2` alone is not evidence of this
    /// policy: an allow-all filter has the same mode.
    expected_post_exec_seccomp_filter_sha256: String,
    permitted_argv_sha256: String,
    permitted_environment_sha256: String,
    permitted_fd_table_sha256: String,
    permitted_supplementary_groups_sha256: String,
    permitted_descendant_closure_sha256: String,
    policy_anchor_sha256: String,
}

/// Borrowed, non-serializable view of every identity field in one validated
/// provisioned runtime policy.
///
/// This is data, not authority.  The P0 conformance seam may use it only while
/// the privilege broker retains the affine authenticated policy custody from
/// which the view was borrowed.  Per-boot and rollback-sensitive identities
/// therefore never become caller descriptor fields.
#[cfg(feature = "p0-launch-package-device-conformance")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P0ConformanceProvisionedRuntimePolicyIdentityV2<'a> {
    policy: &'a ProvisionedProviderRuntimePolicyV2,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl<'a> P0ConformanceProvisionedRuntimePolicyIdentityV2<'a> {
    #[must_use]
    pub fn provider_id(self) -> &'a str {
        &self.policy.provider_id
    }

    #[must_use]
    pub fn agent_id(self) -> &'a str {
        &self.policy.agent_id
    }

    #[must_use]
    pub const fn runtime_exec_topology(self) -> ProviderRuntimeExecTopologyV1 {
        self.policy.runtime_exec_topology
    }

    #[must_use]
    pub fn agent_identity_key_sha256(self) -> &'a str {
        &self.policy.agent_identity_key_sha256
    }

    #[must_use]
    pub fn agent_manifest_sha256(self) -> &'a str {
        &self.policy.agent_manifest_sha256
    }

    #[must_use]
    pub fn policy_authority_identity_sha256(self) -> &'a str {
        &self.policy.policy_authority_identity_sha256
    }

    #[must_use]
    pub fn policy_store_instance_sha256(self) -> &'a str {
        &self.policy.policy_store_instance_sha256
    }

    #[must_use]
    pub fn system_image_sha256(self) -> &'a str {
        &self.policy.system_image_sha256
    }

    #[must_use]
    pub fn avb_chain_sha256(self) -> &'a str {
        &self.policy.avb_chain_sha256
    }

    #[must_use]
    pub fn boot_id_sha256(self) -> &'a str {
        &self.policy.boot_id_sha256
    }

    #[must_use]
    pub fn provisioning_manifest_sha256(self) -> &'a str {
        &self.policy.provisioning_manifest_sha256
    }

    #[must_use]
    pub fn provision_epoch_sha256(self) -> &'a str {
        &self.policy.provision_epoch_sha256
    }

    #[must_use]
    pub fn launcher_executable_sha256(self) -> &'a str {
        &self.policy.provisioned_launcher_executable_sha256
    }

    #[must_use]
    pub fn final_runtime_executable_sha256(self) -> &'a str {
        &self.policy.provisioned_final_runtime_executable_sha256
    }

    #[must_use]
    pub fn final_runtime_closure_sha256(self) -> &'a str {
        &self.policy.provisioned_final_runtime_closure_sha256
    }

    #[must_use]
    pub const fn expected_uid(self) -> u32 {
        self.policy.expected_uid
    }

    #[must_use]
    pub const fn expected_gid(self) -> u32 {
        self.policy.expected_gid
    }

    #[must_use]
    pub fn expected_selinux_domain(self) -> &'a str {
        &self.policy.expected_selinux_domain
    }

    #[must_use]
    pub fn expected_provider_runtime_cgroup_leaf(self) -> &'a str {
        &self.policy.expected_provider_runtime_cgroup_leaf
    }

    #[must_use]
    pub fn expected_provider_cgroup_topology(self) -> &'a ProviderCgroupTopologyV2 {
        &self.policy.expected_provider_cgroup_topology
    }

    #[must_use]
    pub fn expected_provider_cgroup_resource_policy(self) -> &'a ProviderCgroupResourcePolicyV1 {
        &self.policy.expected_provider_cgroup_resource_policy
    }

    #[must_use]
    pub fn fixed_cgroup_inventory_sha256(self) -> &'a str {
        &self.policy.fixed_cgroup_inventory_sha256
    }

    #[must_use]
    pub fn cgroup_directory_ancestry_sha256(self) -> &'a str {
        &self.policy.cgroup_directory_ancestry_sha256
    }

    #[must_use]
    pub fn provider_runtime_leaf_binding_sha256(self) -> &'a str {
        &self.policy.provider_runtime_leaf_binding_sha256
    }

    #[must_use]
    pub fn provider_cgroup_policy_sha256(self) -> &'a str {
        &self.policy.provider_cgroup_policy_sha256
    }

    #[must_use]
    pub const fn expected_exec_event_authority(self) -> ProviderExecEventAuthorityV1 {
        self.policy.expected_exec_event_authority
    }

    #[must_use]
    pub fn post_exec_seccomp_filter_sha256(self) -> &'a str {
        &self.policy.expected_post_exec_seccomp_filter_sha256
    }

    #[must_use]
    pub fn permitted_argv_sha256(self) -> &'a str {
        &self.policy.permitted_argv_sha256
    }

    #[must_use]
    pub fn permitted_environment_sha256(self) -> &'a str {
        &self.policy.permitted_environment_sha256
    }

    #[must_use]
    pub fn permitted_fd_table_sha256(self) -> &'a str {
        &self.policy.permitted_fd_table_sha256
    }

    #[must_use]
    pub fn permitted_supplementary_groups_sha256(self) -> &'a str {
        &self.policy.permitted_supplementary_groups_sha256
    }

    #[must_use]
    pub fn permitted_descendant_closure_sha256(self) -> &'a str {
        &self.policy.permitted_descendant_closure_sha256
    }

    /// The validated policy anchor is also the canonical SHA-256 of every
    /// field exposed by this view.
    #[must_use]
    pub fn policy_anchor_sha256(self) -> &'a str {
        &self.policy.policy_anchor_sha256
    }
}

impl ProvisionedProviderRuntimePolicyV2 {
    pub fn validate(&self) -> ProviderPostExecContainmentResult<()> {
        self.validate_shape()?;
        if !valid_nonzero_sha256(&self.policy_anchor_sha256)
            || self.canonical_sha256()? != self.policy_anchor_sha256
        {
            return Err(denied("provider_runtime_policy_anchor_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> ProviderPostExecContainmentResult<String> {
        self.validate_shape()?;
        let mut hasher = domain_hasher(PROVISIONED_POLICY_V2_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("runtime_exec_topology", self.runtime_exec_topology.as_str()),
            (
                "agent_identity_key_sha256",
                self.agent_identity_key_sha256.as_str(),
            ),
            ("agent_manifest_sha256", self.agent_manifest_sha256.as_str()),
            (
                "policy_authority_identity_sha256",
                self.policy_authority_identity_sha256.as_str(),
            ),
            (
                "policy_store_instance_sha256",
                self.policy_store_instance_sha256.as_str(),
            ),
            ("system_image_sha256", self.system_image_sha256.as_str()),
            ("avb_chain_sha256", self.avb_chain_sha256.as_str()),
            ("boot_id_sha256", self.boot_id_sha256.as_str()),
            (
                "provisioning_manifest_sha256",
                self.provisioning_manifest_sha256.as_str(),
            ),
            (
                "provision_epoch_sha256",
                self.provision_epoch_sha256.as_str(),
            ),
            (
                "provisioned_launcher_executable_sha256",
                self.provisioned_launcher_executable_sha256.as_str(),
            ),
            (
                "provisioned_final_runtime_executable_sha256",
                self.provisioned_final_runtime_executable_sha256.as_str(),
            ),
            (
                "provisioned_final_runtime_closure_sha256",
                self.provisioned_final_runtime_closure_sha256.as_str(),
            ),
            (
                "expected_selinux_domain",
                self.expected_selinux_domain.as_str(),
            ),
            (
                "expected_provider_runtime_cgroup_leaf",
                self.expected_provider_runtime_cgroup_leaf.as_str(),
            ),
            (
                "expected_provider_cgroup_topology_sha256",
                self.expected_provider_cgroup_topology
                    .topology_sha256
                    .as_str(),
            ),
            (
                "expected_provider_cgroup_resource_policy_sha256",
                self.expected_provider_cgroup_resource_policy
                    .policy_sha256
                    .as_str(),
            ),
            (
                "fixed_cgroup_inventory_sha256",
                self.fixed_cgroup_inventory_sha256.as_str(),
            ),
            (
                "cgroup_directory_ancestry_sha256",
                self.cgroup_directory_ancestry_sha256.as_str(),
            ),
            (
                "provider_runtime_leaf_binding_sha256",
                self.provider_runtime_leaf_binding_sha256.as_str(),
            ),
            (
                "provider_cgroup_policy_sha256",
                self.provider_cgroup_policy_sha256.as_str(),
            ),
            (
                "expected_exec_event_authority",
                self.expected_exec_event_authority.as_str(),
            ),
            (
                "expected_post_exec_seccomp_filter_sha256",
                self.expected_post_exec_seccomp_filter_sha256.as_str(),
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
                "permitted_supplementary_groups_sha256",
                self.permitted_supplementary_groups_sha256.as_str(),
            ),
            (
                "permitted_descendant_closure_sha256",
                self.permitted_descendant_closure_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u32(&mut hasher, "expected_uid", self.expected_uid)?;
        hash_u32(&mut hasher, "expected_gid", self.expected_gid)?;
        Ok(lower_hex(&hasher.finalize()))
    }

    #[must_use]
    pub fn policy_anchor_sha256(&self) -> &str {
        &self.policy_anchor_sha256
    }

    /// Return a complete borrowed identity only after canonical validation.
    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub fn p0_conformance_runtime_policy_identity(
        &self,
    ) -> ProviderPostExecContainmentResult<P0ConformanceProvisionedRuntimePolicyIdentityV2<'_>>
    {
        self.validate()?;
        Ok(P0ConformanceProvisionedRuntimePolicyIdentityV2 { policy: self })
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    #[must_use]
    pub const fn runtime_exec_topology(&self) -> ProviderRuntimeExecTopologyV1 {
        self.runtime_exec_topology
    }

    #[must_use]
    pub fn agent_identity_key_sha256(&self) -> &str {
        &self.agent_identity_key_sha256
    }

    #[must_use]
    pub fn agent_manifest_sha256(&self) -> &str {
        &self.agent_manifest_sha256
    }

    fn validate_shape(&self) -> ProviderPostExecContainmentResult<()> {
        let principal =
            agent_principal_registry::from_provider_agent_pair(&self.provider_id, &self.agent_id)
                .ok_or_else(|| denied("provider_runtime_policy_identity_denied"))?;
        let required_topology = required_runtime_exec_topology(&self.provider_id)?;
        let executable_relation_matches_topology = match self.runtime_exec_topology {
            ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => {
                self.provisioned_launcher_executable_sha256
                    == self.provisioned_final_runtime_executable_sha256
            }
            ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
                self.provisioned_launcher_executable_sha256
                    != self.provisioned_final_runtime_executable_sha256
            }
        };
        let digests = [
            self.agent_identity_key_sha256.as_str(),
            self.agent_manifest_sha256.as_str(),
            self.policy_authority_identity_sha256.as_str(),
            self.policy_store_instance_sha256.as_str(),
            self.system_image_sha256.as_str(),
            self.avb_chain_sha256.as_str(),
            self.boot_id_sha256.as_str(),
            self.provisioning_manifest_sha256.as_str(),
            self.provision_epoch_sha256.as_str(),
            self.provisioned_launcher_executable_sha256.as_str(),
            self.provisioned_final_runtime_executable_sha256.as_str(),
            self.provisioned_final_runtime_closure_sha256.as_str(),
            self.fixed_cgroup_inventory_sha256.as_str(),
            self.cgroup_directory_ancestry_sha256.as_str(),
            self.provider_runtime_leaf_binding_sha256.as_str(),
            self.provider_cgroup_policy_sha256.as_str(),
            self.expected_post_exec_seccomp_filter_sha256.as_str(),
            self.permitted_argv_sha256.as_str(),
            self.permitted_environment_sha256.as_str(),
            self.permitted_fd_table_sha256.as_str(),
            self.permitted_supplementary_groups_sha256.as_str(),
            self.permitted_descendant_closure_sha256.as_str(),
        ];
        if self.schema != PROVISIONED_POLICY_V2_SCHEMA
            || self.protocol != PROTOCOL
            || self.runtime_exec_topology != required_topology
            || self.agent_identity_key_sha256
                != self.provisioned_launcher_executable_sha256
            // Equality here is not the semantic type distinction. It is a
            // fail-closed defense against copying the launcher identity into
            // the source-manifest slot or an assumed-impossible SHA collision.
            || self.agent_manifest_sha256 == self.agent_identity_key_sha256
            || self.expected_uid != principal.uid
            || self.expected_gid != principal.gid
            || self.expected_selinux_domain != principal.agent_selinux_domain
            || self.expected_provider_runtime_cgroup_leaf
                != fixed_provider_runtime_cgroup_path(&self.provider_id)
                    .map_err(|_| denied("provider_runtime_policy_cgroup_topology_denied"))?
            || self
                .expected_provider_cgroup_topology
                .validate_for(&self.provider_id)
                .is_err()
            || self
                .expected_provider_cgroup_resource_policy
                .validate_for(&self.provider_id)
                .is_err()
            || self.provider_cgroup_policy_sha256
                != self.expected_provider_cgroup_resource_policy.policy_sha256
            || !digests.into_iter().all(valid_nonzero_sha256)
            || !executable_relation_matches_topology
        {
            return Err(denied("provider_runtime_policy_shape_denied"));
        }
        Ok(())
    }
}

/// Broker-authored reservation of one exact provider subtree generation.
/// The bound empty proof must cover the process-free parent and all three
/// canonical child leaves; a legacy childless-provider proof is not this type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderSubtreeReservationEvidenceV2 {
    schema: String,
    protocol: String,
    policy_anchor_sha256: String,
    provider_id: String,
    agent_id: String,
    provider_invocation_id_sha256: String,
    fixed_cgroup_inventory_sha256: String,
    cgroup_directory_ancestry_sha256: String,
    provider_runtime_leaf_binding_sha256: String,
    provider_subtree_lifecycle_sha256: String,
    lifecycle_operation_id_sha256: String,
    lifecycle_reservation_id_sha256: String,
    broker_subtree_generation: BrokerSubtreeGenerationV2,
    provider_subtree_empty_proof_sha256: String,
    reservation_nonce: BrokerReservationNonceV1,
    reservation_evidence_sha256: String,
}

impl ProviderSubtreeReservationEvidenceV2 {
    pub fn validate_for(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
    ) -> ProviderPostExecContainmentResult<()> {
        policy.validate()?;
        self.validate_shape(policy)?;
        if !valid_nonzero_sha256(&self.reservation_evidence_sha256)
            || self.canonical_sha256(policy)? != self.reservation_evidence_sha256
        {
            return Err(denied("provider_subtree_reservation_evidence_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
    ) -> ProviderPostExecContainmentResult<String> {
        self.validate_shape(policy)?;
        let mut hasher = domain_hasher(PROVIDER_SUBTREE_RESERVATION_EVIDENCE_V2_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            ("policy_anchor_sha256", self.policy_anchor_sha256.as_str()),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            (
                "provider_invocation_id_sha256",
                self.provider_invocation_id_sha256.as_str(),
            ),
            (
                "fixed_cgroup_inventory_sha256",
                self.fixed_cgroup_inventory_sha256.as_str(),
            ),
            (
                "cgroup_directory_ancestry_sha256",
                self.cgroup_directory_ancestry_sha256.as_str(),
            ),
            (
                "provider_runtime_leaf_binding_sha256",
                self.provider_runtime_leaf_binding_sha256.as_str(),
            ),
            (
                "provider_subtree_lifecycle_sha256",
                self.provider_subtree_lifecycle_sha256.as_str(),
            ),
            (
                "lifecycle_operation_id_sha256",
                self.lifecycle_operation_id_sha256.as_str(),
            ),
            (
                "lifecycle_reservation_id_sha256",
                self.lifecycle_reservation_id_sha256.as_str(),
            ),
            (
                "provider_subtree_empty_proof_sha256",
                self.provider_subtree_empty_proof_sha256.as_str(),
            ),
            ("reservation_nonce", self.reservation_nonce.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u64(
            &mut hasher,
            "broker_subtree_generation",
            self.broker_subtree_generation.value(),
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_shape(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
    ) -> ProviderPostExecContainmentResult<()> {
        if self.schema != PROVIDER_SUBTREE_RESERVATION_EVIDENCE_V2_SCHEMA
            || self.protocol != PROTOCOL
            || self.policy_anchor_sha256 != policy.policy_anchor_sha256
            || self.provider_id != policy.provider_id
            || self.agent_id != policy.agent_id
            || self.fixed_cgroup_inventory_sha256 != policy.fixed_cgroup_inventory_sha256
            || self.cgroup_directory_ancestry_sha256 != policy.cgroup_directory_ancestry_sha256
            || self.provider_runtime_leaf_binding_sha256
                != policy.provider_runtime_leaf_binding_sha256
            || ![
                self.provider_invocation_id_sha256.as_str(),
                self.provider_subtree_lifecycle_sha256.as_str(),
                self.lifecycle_operation_id_sha256.as_str(),
                self.lifecycle_reservation_id_sha256.as_str(),
                self.provider_subtree_empty_proof_sha256.as_str(),
                self.reservation_nonce.as_str(),
            ]
            .into_iter()
            .all(valid_nonzero_sha256)
            || !all_distinct(&[
                self.provider_invocation_id_sha256.as_str(),
                self.provider_subtree_lifecycle_sha256.as_str(),
                self.lifecycle_operation_id_sha256.as_str(),
                self.lifecycle_reservation_id_sha256.as_str(),
                self.provider_subtree_empty_proof_sha256.as_str(),
                self.reservation_nonce.as_str(),
            ])
        {
            return Err(denied("provider_subtree_reservation_shape_denied"));
        }
        Ok(())
    }
}

/// Daemon request bound to one provisioned policy and one broker reservation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderPostExecContainmentLaunchIntentV2 {
    schema: String,
    protocol: String,
    policy_anchor_sha256: String,
    reservation_evidence_sha256: String,
    provider_id: String,
    agent_id: String,
    provider_invocation_id_sha256: String,
    provider_session_id_sha256: String,
    daemon_challenge: DaemonChallengeV1,
    daemon_request_nonce: DaemonRequestNonceV1,
    launch_intent_sha256: String,
}

impl ProviderPostExecContainmentLaunchIntentV2 {
    pub fn validate_for(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
    ) -> ProviderPostExecContainmentResult<()> {
        policy.validate()?;
        reservation.validate_for(policy)?;
        self.validate_shape(policy, reservation)?;
        if !valid_nonzero_sha256(&self.launch_intent_sha256)
            || self.canonical_sha256(policy, reservation)? != self.launch_intent_sha256
        {
            return Err(denied(
                "provider_post_exec_containment_launch_intent_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
    ) -> ProviderPostExecContainmentResult<String> {
        self.validate_shape(policy, reservation)?;
        let mut hasher = domain_hasher(LAUNCH_INTENT_V2_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            ("policy_anchor_sha256", self.policy_anchor_sha256.as_str()),
            (
                "reservation_evidence_sha256",
                self.reservation_evidence_sha256.as_str(),
            ),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            (
                "provider_invocation_id_sha256",
                self.provider_invocation_id_sha256.as_str(),
            ),
            (
                "provider_session_id_sha256",
                self.provider_session_id_sha256.as_str(),
            ),
            ("daemon_challenge", self.daemon_challenge.as_str()),
            ("daemon_request_nonce", self.daemon_request_nonce.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_shape(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
    ) -> ProviderPostExecContainmentResult<()> {
        if self.schema != LAUNCH_INTENT_V2_SCHEMA
            || self.protocol != PROTOCOL
            || self.policy_anchor_sha256 != policy.policy_anchor_sha256
            || self.reservation_evidence_sha256 != reservation.reservation_evidence_sha256
            || self.provider_id != policy.provider_id
            || self.agent_id != policy.agent_id
            || self.provider_invocation_id_sha256 != reservation.provider_invocation_id_sha256
            || !valid_nonzero_sha256(&self.provider_session_id_sha256)
            || !all_distinct(&[
                self.provider_invocation_id_sha256.as_str(),
                self.provider_session_id_sha256.as_str(),
                reservation.reservation_nonce.as_str(),
                self.daemon_challenge.as_str(),
                self.daemon_request_nonce.as_str(),
            ])
        {
            return Err(denied(
                "provider_post_exec_containment_launch_intent_shape_denied",
            ));
        }
        Ok(())
    }
}

/// OS-owned evidence that the launcher exists in the reserved runtime leaf and remains
/// stopped before the final runtime exec is accepted.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderPostExecContainmentSpawnHeldEvidenceV2 {
    schema: String,
    protocol: String,
    phase: ProviderPostExecContainmentPhaseV2,
    policy_anchor_sha256: String,
    reservation_evidence_sha256: String,
    launch_intent_sha256: String,
    provider_id: String,
    agent_id: String,
    provider_invocation_id_sha256: String,
    provider_session_id_sha256: String,
    boot_id_sha256: String,
    provider_pid: u32,
    provider_start_time_ticks: u64,
    provider_pidfd_identity_sha256: String,
    pid_namespace_identity_sha256: String,
    cgroup_namespace_identity_sha256: String,
    expected_provider_runtime_cgroup_leaf: String,
    observed_provider_runtime_cgroup_leaf_identity_sha256: String,
    fixed_cgroup_inventory_sha256: String,
    cgroup_directory_ancestry_sha256: String,
    provider_runtime_leaf_binding_sha256: String,
    provider_subtree_lifecycle_sha256: String,
    lifecycle_operation_id_sha256: String,
    lifecycle_reservation_id_sha256: String,
    broker_subtree_generation: BrokerSubtreeGenerationV2,
    provider_subtree_empty_proof_sha256: String,
    observed_launcher_executable_sha256: String,
    observed_uid: u32,
    observed_gid: u32,
    observed_selinux_domain: String,
    exec_event_authority: ProviderExecEventAuthorityV1,
    exec_event_stream_identity_sha256: String,
    spawn_stop_event_identity_sha256: String,
    launcher_exec_event_identity_sha256: String,
    broker_spawn_nonce: BrokerSpawnNonceV1,
    spawn_held_evidence_sha256: String,
}

impl ProviderPostExecContainmentSpawnHeldEvidenceV2 {
    pub fn validate_for(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
    ) -> ProviderPostExecContainmentResult<()> {
        policy.validate()?;
        reservation.validate_for(policy)?;
        intent.validate_for(policy, reservation)?;
        self.validate_shape(policy, reservation, intent)?;
        if !valid_nonzero_sha256(&self.spawn_held_evidence_sha256)
            || self.canonical_sha256(policy, reservation, intent)?
                != self.spawn_held_evidence_sha256
        {
            return Err(denied(
                "provider_post_exec_containment_spawn_held_evidence_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
    ) -> ProviderPostExecContainmentResult<String> {
        self.validate_shape(policy, reservation, intent)?;
        let mut hasher = domain_hasher(SPAWN_HELD_EVIDENCE_V2_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            ("phase", self.phase.as_str()),
            ("policy_anchor_sha256", self.policy_anchor_sha256.as_str()),
            (
                "reservation_evidence_sha256",
                self.reservation_evidence_sha256.as_str(),
            ),
            ("launch_intent_sha256", self.launch_intent_sha256.as_str()),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            (
                "provider_invocation_id_sha256",
                self.provider_invocation_id_sha256.as_str(),
            ),
            (
                "provider_session_id_sha256",
                self.provider_session_id_sha256.as_str(),
            ),
            ("boot_id_sha256", self.boot_id_sha256.as_str()),
            (
                "provider_pidfd_identity_sha256",
                self.provider_pidfd_identity_sha256.as_str(),
            ),
            (
                "pid_namespace_identity_sha256",
                self.pid_namespace_identity_sha256.as_str(),
            ),
            (
                "cgroup_namespace_identity_sha256",
                self.cgroup_namespace_identity_sha256.as_str(),
            ),
            (
                "expected_provider_runtime_cgroup_leaf",
                self.expected_provider_runtime_cgroup_leaf.as_str(),
            ),
            (
                "observed_provider_runtime_cgroup_leaf_identity_sha256",
                self.observed_provider_runtime_cgroup_leaf_identity_sha256
                    .as_str(),
            ),
            (
                "fixed_cgroup_inventory_sha256",
                self.fixed_cgroup_inventory_sha256.as_str(),
            ),
            (
                "cgroup_directory_ancestry_sha256",
                self.cgroup_directory_ancestry_sha256.as_str(),
            ),
            (
                "provider_runtime_leaf_binding_sha256",
                self.provider_runtime_leaf_binding_sha256.as_str(),
            ),
            (
                "provider_subtree_lifecycle_sha256",
                self.provider_subtree_lifecycle_sha256.as_str(),
            ),
            (
                "lifecycle_operation_id_sha256",
                self.lifecycle_operation_id_sha256.as_str(),
            ),
            (
                "lifecycle_reservation_id_sha256",
                self.lifecycle_reservation_id_sha256.as_str(),
            ),
            (
                "provider_subtree_empty_proof_sha256",
                self.provider_subtree_empty_proof_sha256.as_str(),
            ),
            (
                "observed_launcher_executable_sha256",
                self.observed_launcher_executable_sha256.as_str(),
            ),
            (
                "observed_selinux_domain",
                self.observed_selinux_domain.as_str(),
            ),
            ("exec_event_authority", self.exec_event_authority.as_str()),
            (
                "exec_event_stream_identity_sha256",
                self.exec_event_stream_identity_sha256.as_str(),
            ),
            (
                "spawn_stop_event_identity_sha256",
                self.spawn_stop_event_identity_sha256.as_str(),
            ),
            (
                "launcher_exec_event_identity_sha256",
                self.launcher_exec_event_identity_sha256.as_str(),
            ),
            ("broker_spawn_nonce", self.broker_spawn_nonce.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u32(&mut hasher, "provider_pid", self.provider_pid)?;
        hash_u64(
            &mut hasher,
            "provider_start_time_ticks",
            self.provider_start_time_ticks,
        )?;
        hash_u64(
            &mut hasher,
            "broker_subtree_generation",
            self.broker_subtree_generation.value(),
        )?;
        hash_u32(&mut hasher, "observed_uid", self.observed_uid)?;
        hash_u32(&mut hasher, "observed_gid", self.observed_gid)?;
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_shape(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
    ) -> ProviderPostExecContainmentResult<()> {
        if self.schema != SPAWN_HELD_EVIDENCE_V2_SCHEMA
            || self.protocol != PROTOCOL
            || self.phase != ProviderPostExecContainmentPhaseV2::SpawnHeld
            || self.policy_anchor_sha256 != policy.policy_anchor_sha256
            || self.reservation_evidence_sha256 != reservation.reservation_evidence_sha256
            || self.launch_intent_sha256 != intent.launch_intent_sha256
            || self.provider_id != policy.provider_id
            || self.agent_id != policy.agent_id
            || self.provider_invocation_id_sha256 != intent.provider_invocation_id_sha256
            || self.provider_session_id_sha256 != intent.provider_session_id_sha256
            || self.boot_id_sha256 != policy.boot_id_sha256
            || self.provider_pid == 0
            || self.provider_start_time_ticks == 0
            || self.expected_provider_runtime_cgroup_leaf
                != policy.expected_provider_runtime_cgroup_leaf
            || self.observed_provider_runtime_cgroup_leaf_identity_sha256
                != policy.provider_runtime_leaf_binding_sha256
            || self.fixed_cgroup_inventory_sha256 != policy.fixed_cgroup_inventory_sha256
            || self.cgroup_directory_ancestry_sha256 != policy.cgroup_directory_ancestry_sha256
            || self.provider_runtime_leaf_binding_sha256
                != policy.provider_runtime_leaf_binding_sha256
            || self.provider_subtree_lifecycle_sha256
                != reservation.provider_subtree_lifecycle_sha256
            || self.lifecycle_operation_id_sha256 != reservation.lifecycle_operation_id_sha256
            || self.lifecycle_reservation_id_sha256 != reservation.lifecycle_reservation_id_sha256
            || self.broker_subtree_generation != reservation.broker_subtree_generation
            || self.provider_subtree_empty_proof_sha256
                != reservation.provider_subtree_empty_proof_sha256
            || self.observed_launcher_executable_sha256
                != policy.provisioned_launcher_executable_sha256
            || self.observed_uid != policy.expected_uid
            || self.observed_gid != policy.expected_gid
            || self.observed_selinux_domain != policy.expected_selinux_domain
            || self.exec_event_authority != policy.expected_exec_event_authority
            || ![
                self.provider_pidfd_identity_sha256.as_str(),
                self.pid_namespace_identity_sha256.as_str(),
                self.cgroup_namespace_identity_sha256.as_str(),
                self.exec_event_stream_identity_sha256.as_str(),
                self.spawn_stop_event_identity_sha256.as_str(),
                self.launcher_exec_event_identity_sha256.as_str(),
                self.broker_spawn_nonce.as_str(),
            ]
            .into_iter()
            .all(valid_nonzero_sha256)
            || !all_distinct(&[
                intent.provider_invocation_id_sha256.as_str(),
                intent.provider_session_id_sha256.as_str(),
                reservation.reservation_nonce.as_str(),
                intent.daemon_challenge.as_str(),
                intent.daemon_request_nonce.as_str(),
                self.broker_spawn_nonce.as_str(),
            ])
            || self.spawn_stop_event_identity_sha256 == self.launcher_exec_event_identity_sha256
        {
            return Err(denied(
                "provider_post_exec_containment_spawn_held_shape_denied",
            ));
        }
        Ok(())
    }
}

/// Complete structural evidence observed while the final runtime remains held.
///
/// Passing [`Self::validate_for`] does not release the process and does not
/// grant access to prompts, broker sessions, invocation temporary storage,
/// child creation, tools, or effects.
///
/// Like the provisioned policy, this `V2` is an unpublished source draft. No
/// product path persists or accepts these bytes, so the newly required exact
/// filter digest is fail-closed source evolution rather than a wire migration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderPostExecContainmentFinalExecEvidenceV2 {
    schema: String,
    protocol: String,
    phase: ProviderPostExecContainmentPhaseV2,
    policy_anchor_sha256: String,
    reservation_evidence_sha256: String,
    launch_intent_sha256: String,
    spawn_held_evidence_sha256: String,
    provider_id: String,
    agent_id: String,
    provider_invocation_id_sha256: String,
    provider_session_id_sha256: String,
    boot_id_sha256: String,
    provider_pid: u32,
    provider_start_time_ticks: u64,
    provider_pidfd_identity_sha256: String,
    pid_namespace_identity_sha256: String,
    cgroup_namespace_identity_sha256: String,
    expected_provider_runtime_cgroup_leaf: String,
    expected_provider_cgroup_topology_sha256: String,
    observed_provider_cgroup_resource_policy: ProviderCgroupResourcePolicyV1,
    observed_provider_runtime_cgroup_leaf_identity_sha256: String,
    fixed_cgroup_inventory_sha256: String,
    cgroup_directory_ancestry_sha256: String,
    provider_runtime_leaf_binding_sha256: String,
    provider_subtree_lifecycle_sha256: String,
    lifecycle_operation_id_sha256: String,
    lifecycle_reservation_id_sha256: String,
    broker_subtree_generation: BrokerSubtreeGenerationV2,
    provider_subtree_empty_proof_sha256: String,
    observed_final_runtime_executable_sha256: String,
    observed_final_runtime_closure_sha256: String,
    observed_uid: u32,
    observed_gid: u32,
    observed_selinux_domain: String,
    exec_event_authority: ProviderExecEventAuthorityV1,
    exec_event_stream_identity_sha256: String,
    final_exec_event_identity_sha256: String,
    hardening_stop_event_identity_sha256: String,
    hardening_event_identity_sha256: String,
    final_exec_sequence: u64,
    post_verification_exec_event_count: u64,
    post_exec_dumpable: u8,
    post_exec_no_new_privs: u8,
    post_exec_seccomp_mode: u8,
    /// Kernel-exported canonical digest of the installed classic-BPF filter.
    ///
    /// A provider-authored digest or a mode-only observation is insufficient.
    observed_post_exec_seccomp_filter_sha256: String,
    effective_capabilities: u64,
    permitted_capabilities: u64,
    inheritable_capabilities: u64,
    ambient_capabilities: u64,
    bounding_capabilities: u64,
    supplementary_groups: Vec<u32>,
    observed_supplementary_groups_sha256: String,
    observed_argv_sha256: String,
    observed_environment_sha256: String,
    observed_fd_table_sha256: String,
    observed_descendant_closure_sha256: String,
    provider_subtree_process_count: u64,
    provider_subtree_descendant_count: u64,
    provider_subtree_dying_descendant_count: u64,
    provider_subtree_max_descendants: u64,
    provider_subtree_max_depth: u64,
    runtime_leaf_process_count: u64,
    runtime_leaf_descendant_count: u64,
    runtime_leaf_dying_descendant_count: u64,
    runtime_leaf_max_descendants: u64,
    runtime_leaf_max_depth: u64,
    system_api_leaf_process_count: u64,
    system_api_leaf_descendant_count: u64,
    system_api_leaf_dying_descendant_count: u64,
    system_api_leaf_max_descendants: u64,
    system_api_leaf_max_depth: u64,
    accessibility_leaf_process_count: u64,
    accessibility_leaf_descendant_count: u64,
    accessibility_leaf_dying_descendant_count: u64,
    accessibility_leaf_max_descendants: u64,
    accessibility_leaf_max_depth: u64,
    prompt_access_count: u64,
    broker_access_count: u64,
    invocation_tmp_access_count: u64,
    child_spawn_count: u64,
    tool_access_count: u64,
    broker_hardening_nonce: BrokerHardeningNonceV1,
    broker_verification_nonce: BrokerVerificationNonceV1,
    os_observation_sha256: String,
    final_exec_evidence_sha256: String,
}

impl ProviderPostExecContainmentFinalExecEvidenceV2 {
    pub fn validate_for(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
        spawn: &ProviderPostExecContainmentSpawnHeldEvidenceV2,
    ) -> ProviderPostExecContainmentResult<()> {
        policy.validate()?;
        reservation.validate_for(policy)?;
        intent.validate_for(policy, reservation)?;
        spawn.validate_for(policy, reservation, intent)?;
        self.validate_shape(policy, reservation, intent, spawn)?;
        if !valid_nonzero_sha256(&self.final_exec_evidence_sha256)
            || self.canonical_sha256(policy, reservation, intent, spawn)?
                != self.final_exec_evidence_sha256
        {
            return Err(denied(
                "provider_post_exec_containment_final_exec_evidence_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
        spawn: &ProviderPostExecContainmentSpawnHeldEvidenceV2,
    ) -> ProviderPostExecContainmentResult<String> {
        self.validate_shape(policy, reservation, intent, spawn)?;
        let mut hasher = domain_hasher(FINAL_EXEC_EVIDENCE_V2_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            ("phase", self.phase.as_str()),
            ("policy_anchor_sha256", self.policy_anchor_sha256.as_str()),
            (
                "reservation_evidence_sha256",
                self.reservation_evidence_sha256.as_str(),
            ),
            ("launch_intent_sha256", self.launch_intent_sha256.as_str()),
            (
                "spawn_held_evidence_sha256",
                self.spawn_held_evidence_sha256.as_str(),
            ),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            (
                "provider_invocation_id_sha256",
                self.provider_invocation_id_sha256.as_str(),
            ),
            (
                "provider_session_id_sha256",
                self.provider_session_id_sha256.as_str(),
            ),
            ("boot_id_sha256", self.boot_id_sha256.as_str()),
            (
                "provider_pidfd_identity_sha256",
                self.provider_pidfd_identity_sha256.as_str(),
            ),
            (
                "pid_namespace_identity_sha256",
                self.pid_namespace_identity_sha256.as_str(),
            ),
            (
                "cgroup_namespace_identity_sha256",
                self.cgroup_namespace_identity_sha256.as_str(),
            ),
            (
                "expected_provider_runtime_cgroup_leaf",
                self.expected_provider_runtime_cgroup_leaf.as_str(),
            ),
            (
                "expected_provider_cgroup_topology_sha256",
                self.expected_provider_cgroup_topology_sha256.as_str(),
            ),
            (
                "observed_provider_cgroup_resource_policy_sha256",
                self.observed_provider_cgroup_resource_policy
                    .policy_sha256
                    .as_str(),
            ),
            (
                "observed_provider_runtime_cgroup_leaf_identity_sha256",
                self.observed_provider_runtime_cgroup_leaf_identity_sha256
                    .as_str(),
            ),
            (
                "fixed_cgroup_inventory_sha256",
                self.fixed_cgroup_inventory_sha256.as_str(),
            ),
            (
                "cgroup_directory_ancestry_sha256",
                self.cgroup_directory_ancestry_sha256.as_str(),
            ),
            (
                "provider_runtime_leaf_binding_sha256",
                self.provider_runtime_leaf_binding_sha256.as_str(),
            ),
            (
                "provider_subtree_lifecycle_sha256",
                self.provider_subtree_lifecycle_sha256.as_str(),
            ),
            (
                "lifecycle_operation_id_sha256",
                self.lifecycle_operation_id_sha256.as_str(),
            ),
            (
                "lifecycle_reservation_id_sha256",
                self.lifecycle_reservation_id_sha256.as_str(),
            ),
            (
                "provider_subtree_empty_proof_sha256",
                self.provider_subtree_empty_proof_sha256.as_str(),
            ),
            (
                "observed_final_runtime_executable_sha256",
                self.observed_final_runtime_executable_sha256.as_str(),
            ),
            (
                "observed_final_runtime_closure_sha256",
                self.observed_final_runtime_closure_sha256.as_str(),
            ),
            (
                "observed_selinux_domain",
                self.observed_selinux_domain.as_str(),
            ),
            ("exec_event_authority", self.exec_event_authority.as_str()),
            (
                "exec_event_stream_identity_sha256",
                self.exec_event_stream_identity_sha256.as_str(),
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
                "hardening_event_identity_sha256",
                self.hardening_event_identity_sha256.as_str(),
            ),
            (
                "observed_post_exec_seccomp_filter_sha256",
                self.observed_post_exec_seccomp_filter_sha256.as_str(),
            ),
            (
                "observed_supplementary_groups_sha256",
                self.observed_supplementary_groups_sha256.as_str(),
            ),
            ("observed_argv_sha256", self.observed_argv_sha256.as_str()),
            (
                "observed_environment_sha256",
                self.observed_environment_sha256.as_str(),
            ),
            (
                "observed_fd_table_sha256",
                self.observed_fd_table_sha256.as_str(),
            ),
            (
                "observed_descendant_closure_sha256",
                self.observed_descendant_closure_sha256.as_str(),
            ),
            (
                "broker_hardening_nonce",
                self.broker_hardening_nonce.as_str(),
            ),
            (
                "broker_verification_nonce",
                self.broker_verification_nonce.as_str(),
            ),
            ("os_observation_sha256", self.os_observation_sha256.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        for (name, value) in [
            ("provider_pid", self.provider_pid),
            ("observed_uid", self.observed_uid),
            ("observed_gid", self.observed_gid),
        ] {
            hash_u32(&mut hasher, name, value)?;
        }
        for (name, value) in [
            ("provider_start_time_ticks", self.provider_start_time_ticks),
            (
                "broker_subtree_generation",
                self.broker_subtree_generation.value(),
            ),
            ("final_exec_sequence", self.final_exec_sequence),
            (
                "post_verification_exec_event_count",
                self.post_verification_exec_event_count,
            ),
            ("effective_capabilities", self.effective_capabilities),
            ("permitted_capabilities", self.permitted_capabilities),
            ("inheritable_capabilities", self.inheritable_capabilities),
            ("ambient_capabilities", self.ambient_capabilities),
            ("bounding_capabilities", self.bounding_capabilities),
            (
                "provider_subtree_process_count",
                self.provider_subtree_process_count,
            ),
            (
                "provider_subtree_descendant_count",
                self.provider_subtree_descendant_count,
            ),
            (
                "provider_subtree_dying_descendant_count",
                self.provider_subtree_dying_descendant_count,
            ),
            (
                "provider_subtree_max_descendants",
                self.provider_subtree_max_descendants,
            ),
            (
                "provider_subtree_max_depth",
                self.provider_subtree_max_depth,
            ),
            (
                "runtime_leaf_process_count",
                self.runtime_leaf_process_count,
            ),
            (
                "runtime_leaf_descendant_count",
                self.runtime_leaf_descendant_count,
            ),
            (
                "runtime_leaf_dying_descendant_count",
                self.runtime_leaf_dying_descendant_count,
            ),
            (
                "runtime_leaf_max_descendants",
                self.runtime_leaf_max_descendants,
            ),
            ("runtime_leaf_max_depth", self.runtime_leaf_max_depth),
            (
                "system_api_leaf_process_count",
                self.system_api_leaf_process_count,
            ),
            (
                "system_api_leaf_descendant_count",
                self.system_api_leaf_descendant_count,
            ),
            (
                "system_api_leaf_dying_descendant_count",
                self.system_api_leaf_dying_descendant_count,
            ),
            (
                "system_api_leaf_max_descendants",
                self.system_api_leaf_max_descendants,
            ),
            ("system_api_leaf_max_depth", self.system_api_leaf_max_depth),
            (
                "accessibility_leaf_process_count",
                self.accessibility_leaf_process_count,
            ),
            (
                "accessibility_leaf_descendant_count",
                self.accessibility_leaf_descendant_count,
            ),
            (
                "accessibility_leaf_dying_descendant_count",
                self.accessibility_leaf_dying_descendant_count,
            ),
            (
                "accessibility_leaf_max_descendants",
                self.accessibility_leaf_max_descendants,
            ),
            (
                "accessibility_leaf_max_depth",
                self.accessibility_leaf_max_depth,
            ),
            ("prompt_access_count", self.prompt_access_count),
            ("broker_access_count", self.broker_access_count),
            (
                "invocation_tmp_access_count",
                self.invocation_tmp_access_count,
            ),
            ("child_spawn_count", self.child_spawn_count),
            ("tool_access_count", self.tool_access_count),
        ] {
            hash_u64(&mut hasher, name, value)?;
        }
        for (name, value) in [
            ("post_exec_dumpable", self.post_exec_dumpable),
            ("post_exec_no_new_privs", self.post_exec_no_new_privs),
            ("post_exec_seccomp_mode", self.post_exec_seccomp_mode),
        ] {
            hash_u8(&mut hasher, name, value)?;
        }
        hash_u32_list(
            &mut hasher,
            "supplementary_groups",
            &self.supplementary_groups,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }

    #[allow(clippy::too_many_lines)]
    fn validate_shape(
        &self,
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
        spawn: &ProviderPostExecContainmentSpawnHeldEvidenceV2,
    ) -> ProviderPostExecContainmentResult<()> {
        let exact_bindings = self.schema == FINAL_EXEC_EVIDENCE_V2_SCHEMA
            && self.protocol == PROTOCOL
            && self.phase == ProviderPostExecContainmentPhaseV2::FinalExecVerifiedHeld
            && self.policy_anchor_sha256 == policy.policy_anchor_sha256
            && self.reservation_evidence_sha256 == reservation.reservation_evidence_sha256
            && self.launch_intent_sha256 == intent.launch_intent_sha256
            && self.spawn_held_evidence_sha256 == spawn.spawn_held_evidence_sha256
            && self.provider_id == policy.provider_id
            && self.agent_id == policy.agent_id
            && self.provider_invocation_id_sha256 == intent.provider_invocation_id_sha256
            && self.provider_session_id_sha256 == intent.provider_session_id_sha256
            && self.boot_id_sha256 == policy.boot_id_sha256
            && self.provider_pid == spawn.provider_pid
            && self.provider_start_time_ticks == spawn.provider_start_time_ticks
            && self.provider_pidfd_identity_sha256 == spawn.provider_pidfd_identity_sha256
            && self.pid_namespace_identity_sha256 == spawn.pid_namespace_identity_sha256
            && self.cgroup_namespace_identity_sha256 == spawn.cgroup_namespace_identity_sha256
            && self.expected_provider_runtime_cgroup_leaf
                == policy.expected_provider_runtime_cgroup_leaf
            && self.expected_provider_cgroup_topology_sha256
                == policy.expected_provider_cgroup_topology.topology_sha256
            && self.observed_provider_cgroup_resource_policy
                == policy.expected_provider_cgroup_resource_policy
            && self
                .observed_provider_cgroup_resource_policy
                .validate_for(&self.provider_id)
                .is_ok()
            && self.observed_provider_runtime_cgroup_leaf_identity_sha256
                == policy.provider_runtime_leaf_binding_sha256
            && self.fixed_cgroup_inventory_sha256 == policy.fixed_cgroup_inventory_sha256
            && self.cgroup_directory_ancestry_sha256 == policy.cgroup_directory_ancestry_sha256
            && self.provider_runtime_leaf_binding_sha256
                == policy.provider_runtime_leaf_binding_sha256
            && self.provider_subtree_lifecycle_sha256
                == reservation.provider_subtree_lifecycle_sha256
            && self.lifecycle_operation_id_sha256 == reservation.lifecycle_operation_id_sha256
            && self.lifecycle_reservation_id_sha256 == reservation.lifecycle_reservation_id_sha256
            && self.broker_subtree_generation == reservation.broker_subtree_generation
            && self.provider_subtree_empty_proof_sha256
                == reservation.provider_subtree_empty_proof_sha256
            && self.observed_final_runtime_executable_sha256
                == policy.provisioned_final_runtime_executable_sha256
            && self.observed_final_runtime_closure_sha256
                == policy.provisioned_final_runtime_closure_sha256
            && self.observed_uid == policy.expected_uid
            && self.observed_gid == policy.expected_gid
            && self.observed_selinux_domain == policy.expected_selinux_domain
            && self.exec_event_authority == policy.expected_exec_event_authority
            && self.exec_event_stream_identity_sha256 == spawn.exec_event_stream_identity_sha256
            && self.observed_supplementary_groups_sha256
                == policy.permitted_supplementary_groups_sha256
            && self.observed_argv_sha256 == policy.permitted_argv_sha256
            && self.observed_environment_sha256 == policy.permitted_environment_sha256
            && self.observed_fd_table_sha256 == policy.permitted_fd_table_sha256
            && self.observed_descendant_closure_sha256
                == policy.permitted_descendant_closure_sha256
            && self.observed_post_exec_seccomp_filter_sha256
                == policy.expected_post_exec_seccomp_filter_sha256;
        let exact_hardening = self.final_exec_sequence == FINAL_RUNTIME_EXEC_SEQUENCE
            && self.post_verification_exec_event_count == 0
            && self.post_exec_dumpable == 0
            && self.post_exec_no_new_privs == 1
            && self.post_exec_seccomp_mode == 2
            && self.effective_capabilities == 0
            && self.permitted_capabilities == 0
            && self.inheritable_capabilities == 0
            && self.ambient_capabilities == 0
            && self.bounding_capabilities == 0
            && self.supplementary_groups.is_empty()
            && self.provider_subtree_process_count == PROVIDER_SUBTREE_EXPECTED_PROCESS_COUNT
            && self.provider_subtree_descendant_count == PROVIDER_SUBTREE_EXPECTED_DESCENDANT_COUNT
            && self.provider_subtree_dying_descendant_count
                == PROVIDER_SUBTREE_EXPECTED_DYING_DESCENDANT_COUNT
            && self.provider_subtree_max_descendants == PROVIDER_SUBTREE_EXPECTED_MAX_DESCENDANTS
            && self.provider_subtree_max_depth == PROVIDER_SUBTREE_EXPECTED_MAX_DEPTH
            && self.runtime_leaf_process_count == 1
            && self.runtime_leaf_descendant_count == PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT
            && self.runtime_leaf_dying_descendant_count
                == PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT
            && self.runtime_leaf_max_descendants == PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS
            && self.runtime_leaf_max_depth == PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH
            && self.system_api_leaf_process_count == 0
            && self.system_api_leaf_descendant_count
                == PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT
            && self.system_api_leaf_dying_descendant_count
                == PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT
            && self.system_api_leaf_max_descendants == PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS
            && self.system_api_leaf_max_depth == PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH
            && self.accessibility_leaf_process_count == 0
            && self.accessibility_leaf_descendant_count
                == PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT
            && self.accessibility_leaf_dying_descendant_count
                == PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT
            && self.accessibility_leaf_max_descendants
                == PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS
            && self.accessibility_leaf_max_depth == PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH
            && self.prompt_access_count == 0
            && self.broker_access_count == 0
            && self.invocation_tmp_access_count == 0
            && self.child_spawn_count == 0
            && self.tool_access_count == 0;
        let evidence_digests = [
            self.final_exec_event_identity_sha256.as_str(),
            self.hardening_stop_event_identity_sha256.as_str(),
            self.hardening_event_identity_sha256.as_str(),
            self.observed_post_exec_seccomp_filter_sha256.as_str(),
            self.os_observation_sha256.as_str(),
            self.broker_hardening_nonce.as_str(),
            self.broker_verification_nonce.as_str(),
        ];
        let nonce_chain = [
            intent.provider_invocation_id_sha256.as_str(),
            intent.provider_session_id_sha256.as_str(),
            reservation.reservation_nonce.as_str(),
            intent.daemon_challenge.as_str(),
            intent.daemon_request_nonce.as_str(),
            spawn.broker_spawn_nonce.as_str(),
            self.broker_hardening_nonce.as_str(),
            self.broker_verification_nonce.as_str(),
        ];
        let final_runtime_event_chain = [
            spawn.spawn_stop_event_identity_sha256.as_str(),
            self.final_exec_event_identity_sha256.as_str(),
            self.hardening_stop_event_identity_sha256.as_str(),
            self.hardening_event_identity_sha256.as_str(),
        ];
        let exec_event_relation_matches_topology = match policy.runtime_exec_topology {
            ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => {
                spawn.launcher_exec_event_identity_sha256 == self.final_exec_event_identity_sha256
            }
            ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
                spawn.launcher_exec_event_identity_sha256 != self.final_exec_event_identity_sha256
                    && !final_runtime_event_chain
                        .contains(&spawn.launcher_exec_event_identity_sha256.as_str())
            }
        };
        if !exact_bindings
            || !exact_hardening
            || !evidence_digests.into_iter().all(valid_nonzero_sha256)
            || !all_distinct(&nonce_chain)
            || !all_distinct(&final_runtime_event_chain)
            || !exec_event_relation_matches_topology
        {
            return Err(denied(
                "provider_post_exec_containment_final_exec_shape_denied",
            ));
        }
        Ok(())
    }
}

/// Exact identity a provider-side consumer must already know before it may
/// consume an affine post-exec containment carrier.
///
/// This value is an expectation, not authority. It is intentionally
/// constructible as plain Rust data and is neither serialized nor accepted by
/// any product adapter in this checkpoint. The final evidence digest binds the
/// complete validated policy/reservation/intent/spawn/final chain, including
/// all hardening and zero-resource-access invariants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderPostExecContainmentConsumerExpectation<'a> {
    pub policy_anchor_sha256: &'a str,
    pub reservation_evidence_sha256: &'a str,
    pub launch_intent_sha256: &'a str,
    pub spawn_held_evidence_sha256: &'a str,
    pub final_exec_evidence_sha256: &'a str,
    pub provider_id: &'a str,
    pub agent_id: &'a str,
    pub runtime_exec_topology: ProviderRuntimeExecTopologyV1,
    pub agent_identity_key_sha256: &'a str,
    pub agent_manifest_sha256: &'a str,
    pub provider_invocation_id_sha256: &'a str,
    pub provider_session_id_sha256: &'a str,
    pub provision_epoch_sha256: &'a str,
    pub expected_uid: u32,
    pub expected_gid: u32,
    pub expected_selinux_domain: &'a str,
    pub launcher_executable_sha256: &'a str,
    pub final_runtime_executable_sha256: &'a str,
    pub final_runtime_closure_sha256: &'a str,
    pub post_exec_seccomp_filter_sha256: &'a str,
    pub boot_id_sha256: &'a str,
    pub broker_subtree_generation: u64,
    pub provider_pid: u32,
    pub provider_start_time_ticks: u64,
    pub provider_pidfd_identity_sha256: &'a str,
    pub exec_event_authority: ProviderExecEventAuthorityV1,
    pub exec_event_stream_identity_sha256: &'a str,
    pub final_exec_event_identity_sha256: &'a str,
    pub hardening_stop_event_identity_sha256: &'a str,
    pub hardening_event_identity_sha256: &'a str,
    pub os_observation_sha256: &'a str,
    pub fixed_cgroup_inventory_sha256: &'a str,
    pub cgroup_directory_ancestry_sha256: &'a str,
    pub provider_runtime_leaf_binding_sha256: &'a str,
    pub provider_cgroup_resource_policy_sha256: &'a str,
    pub provider_subtree_empty_proof_sha256: &'a str,
    pub provider_subtree_lifecycle_sha256: &'a str,
    pub lifecycle_operation_id_sha256: &'a str,
    pub lifecycle_reservation_id_sha256: &'a str,
}

#[derive(Clone, Eq, PartialEq)]
struct ProviderPostExecContainmentAuthorityBinding {
    policy_anchor_sha256: String,
    reservation_evidence_sha256: String,
    launch_intent_sha256: String,
    spawn_held_evidence_sha256: String,
    final_exec_evidence_sha256: String,
    provider_id: String,
    agent_id: String,
    runtime_exec_topology: ProviderRuntimeExecTopologyV1,
    agent_identity_key_sha256: String,
    agent_manifest_sha256: String,
    provider_invocation_id_sha256: String,
    provider_session_id_sha256: String,
    provision_epoch_sha256: String,
    expected_uid: u32,
    expected_gid: u32,
    expected_selinux_domain: String,
    launcher_executable_sha256: String,
    final_runtime_executable_sha256: String,
    final_runtime_closure_sha256: String,
    post_exec_seccomp_filter_sha256: String,
    boot_id_sha256: String,
    broker_subtree_generation: u64,
    provider_pid: u32,
    provider_start_time_ticks: u64,
    provider_pidfd_identity_sha256: String,
    exec_event_authority: ProviderExecEventAuthorityV1,
    exec_event_stream_identity_sha256: String,
    final_exec_event_identity_sha256: String,
    hardening_stop_event_identity_sha256: String,
    hardening_event_identity_sha256: String,
    os_observation_sha256: String,
    fixed_cgroup_inventory_sha256: String,
    cgroup_directory_ancestry_sha256: String,
    provider_runtime_leaf_binding_sha256: String,
    provider_cgroup_resource_policy_sha256: String,
    provider_subtree_empty_proof_sha256: String,
    provider_subtree_lifecycle_sha256: String,
    lifecycle_operation_id_sha256: String,
    lifecycle_reservation_id_sha256: String,
}

impl ProviderPostExecContainmentAuthorityBinding {
    fn from_complete_chain(
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
        spawn: &ProviderPostExecContainmentSpawnHeldEvidenceV2,
        final_evidence: &ProviderPostExecContainmentFinalExecEvidenceV2,
    ) -> ProviderPostExecContainmentResult<Self> {
        final_evidence.validate_for(policy, reservation, intent, spawn)?;
        Ok(Self {
            policy_anchor_sha256: policy.policy_anchor_sha256.clone(),
            reservation_evidence_sha256: reservation.reservation_evidence_sha256.clone(),
            launch_intent_sha256: intent.launch_intent_sha256.clone(),
            spawn_held_evidence_sha256: spawn.spawn_held_evidence_sha256.clone(),
            final_exec_evidence_sha256: final_evidence.final_exec_evidence_sha256.clone(),
            provider_id: policy.provider_id.clone(),
            agent_id: policy.agent_id.clone(),
            runtime_exec_topology: policy.runtime_exec_topology,
            agent_identity_key_sha256: policy.agent_identity_key_sha256.clone(),
            agent_manifest_sha256: policy.agent_manifest_sha256.clone(),
            provider_invocation_id_sha256: intent.provider_invocation_id_sha256.clone(),
            provider_session_id_sha256: intent.provider_session_id_sha256.clone(),
            provision_epoch_sha256: policy.provision_epoch_sha256.clone(),
            expected_uid: policy.expected_uid,
            expected_gid: policy.expected_gid,
            expected_selinux_domain: policy.expected_selinux_domain.clone(),
            launcher_executable_sha256: policy.provisioned_launcher_executable_sha256.clone(),
            final_runtime_executable_sha256: policy
                .provisioned_final_runtime_executable_sha256
                .clone(),
            final_runtime_closure_sha256: policy.provisioned_final_runtime_closure_sha256.clone(),
            post_exec_seccomp_filter_sha256: final_evidence
                .observed_post_exec_seccomp_filter_sha256
                .clone(),
            boot_id_sha256: policy.boot_id_sha256.clone(),
            broker_subtree_generation: reservation.broker_subtree_generation.value(),
            provider_pid: spawn.provider_pid,
            provider_start_time_ticks: spawn.provider_start_time_ticks,
            provider_pidfd_identity_sha256: spawn.provider_pidfd_identity_sha256.clone(),
            exec_event_authority: final_evidence.exec_event_authority,
            exec_event_stream_identity_sha256: final_evidence
                .exec_event_stream_identity_sha256
                .clone(),
            final_exec_event_identity_sha256: final_evidence
                .final_exec_event_identity_sha256
                .clone(),
            hardening_stop_event_identity_sha256: final_evidence
                .hardening_stop_event_identity_sha256
                .clone(),
            hardening_event_identity_sha256: final_evidence.hardening_event_identity_sha256.clone(),
            os_observation_sha256: final_evidence.os_observation_sha256.clone(),
            fixed_cgroup_inventory_sha256: policy.fixed_cgroup_inventory_sha256.clone(),
            cgroup_directory_ancestry_sha256: policy.cgroup_directory_ancestry_sha256.clone(),
            provider_runtime_leaf_binding_sha256: policy
                .provider_runtime_leaf_binding_sha256
                .clone(),
            provider_cgroup_resource_policy_sha256: policy
                .expected_provider_cgroup_resource_policy
                .policy_sha256
                .clone(),
            provider_subtree_empty_proof_sha256: reservation
                .provider_subtree_empty_proof_sha256
                .clone(),
            provider_subtree_lifecycle_sha256: reservation
                .provider_subtree_lifecycle_sha256
                .clone(),
            lifecycle_operation_id_sha256: reservation.lifecycle_operation_id_sha256.clone(),
            lifecycle_reservation_id_sha256: reservation.lifecycle_reservation_id_sha256.clone(),
        })
    }

    fn matches_consumer(
        &self,
        expected: &ProviderPostExecContainmentConsumerExpectation<'_>,
    ) -> bool {
        self.policy_anchor_sha256 == expected.policy_anchor_sha256
            && self.reservation_evidence_sha256 == expected.reservation_evidence_sha256
            && self.launch_intent_sha256 == expected.launch_intent_sha256
            && self.spawn_held_evidence_sha256 == expected.spawn_held_evidence_sha256
            && self.final_exec_evidence_sha256 == expected.final_exec_evidence_sha256
            && self.provider_id == expected.provider_id
            && self.agent_id == expected.agent_id
            && self.runtime_exec_topology == expected.runtime_exec_topology
            && self.agent_identity_key_sha256 == expected.agent_identity_key_sha256
            && self.agent_manifest_sha256 == expected.agent_manifest_sha256
            && self.provider_invocation_id_sha256 == expected.provider_invocation_id_sha256
            && self.provider_session_id_sha256 == expected.provider_session_id_sha256
            && self.provision_epoch_sha256 == expected.provision_epoch_sha256
            && self.expected_uid == expected.expected_uid
            && self.expected_gid == expected.expected_gid
            && self.expected_selinux_domain == expected.expected_selinux_domain
            && self.launcher_executable_sha256 == expected.launcher_executable_sha256
            && self.final_runtime_executable_sha256 == expected.final_runtime_executable_sha256
            && self.final_runtime_closure_sha256 == expected.final_runtime_closure_sha256
            && self.post_exec_seccomp_filter_sha256 == expected.post_exec_seccomp_filter_sha256
            && self.boot_id_sha256 == expected.boot_id_sha256
            && self.broker_subtree_generation == expected.broker_subtree_generation
            && self.provider_pid == expected.provider_pid
            && self.provider_start_time_ticks == expected.provider_start_time_ticks
            && self.provider_pidfd_identity_sha256 == expected.provider_pidfd_identity_sha256
            && self.exec_event_authority == expected.exec_event_authority
            && self.exec_event_stream_identity_sha256 == expected.exec_event_stream_identity_sha256
            && self.final_exec_event_identity_sha256 == expected.final_exec_event_identity_sha256
            && self.hardening_stop_event_identity_sha256
                == expected.hardening_stop_event_identity_sha256
            && self.hardening_event_identity_sha256 == expected.hardening_event_identity_sha256
            && self.os_observation_sha256 == expected.os_observation_sha256
            && self.fixed_cgroup_inventory_sha256 == expected.fixed_cgroup_inventory_sha256
            && self.cgroup_directory_ancestry_sha256 == expected.cgroup_directory_ancestry_sha256
            && self.provider_runtime_leaf_binding_sha256
                == expected.provider_runtime_leaf_binding_sha256
            && self.provider_cgroup_resource_policy_sha256
                == expected.provider_cgroup_resource_policy_sha256
            && self.provider_subtree_empty_proof_sha256
                == expected.provider_subtree_empty_proof_sha256
            && self.provider_subtree_lifecycle_sha256 == expected.provider_subtree_lifecycle_sha256
            && self.lifecycle_operation_id_sha256 == expected.lifecycle_operation_id_sha256
            && self.lifecycle_reservation_id_sha256 == expected.lifecycle_reservation_id_sha256
    }

    fn consumer_expectation(&self) -> ProviderPostExecContainmentConsumerExpectation<'_> {
        ProviderPostExecContainmentConsumerExpectation {
            policy_anchor_sha256: &self.policy_anchor_sha256,
            reservation_evidence_sha256: &self.reservation_evidence_sha256,
            launch_intent_sha256: &self.launch_intent_sha256,
            spawn_held_evidence_sha256: &self.spawn_held_evidence_sha256,
            final_exec_evidence_sha256: &self.final_exec_evidence_sha256,
            provider_id: &self.provider_id,
            agent_id: &self.agent_id,
            runtime_exec_topology: self.runtime_exec_topology,
            agent_identity_key_sha256: &self.agent_identity_key_sha256,
            agent_manifest_sha256: &self.agent_manifest_sha256,
            provider_invocation_id_sha256: &self.provider_invocation_id_sha256,
            provider_session_id_sha256: &self.provider_session_id_sha256,
            provision_epoch_sha256: &self.provision_epoch_sha256,
            expected_uid: self.expected_uid,
            expected_gid: self.expected_gid,
            expected_selinux_domain: &self.expected_selinux_domain,
            launcher_executable_sha256: &self.launcher_executable_sha256,
            final_runtime_executable_sha256: &self.final_runtime_executable_sha256,
            final_runtime_closure_sha256: &self.final_runtime_closure_sha256,
            post_exec_seccomp_filter_sha256: &self.post_exec_seccomp_filter_sha256,
            boot_id_sha256: &self.boot_id_sha256,
            broker_subtree_generation: self.broker_subtree_generation,
            provider_pid: self.provider_pid,
            provider_start_time_ticks: self.provider_start_time_ticks,
            provider_pidfd_identity_sha256: &self.provider_pidfd_identity_sha256,
            exec_event_authority: self.exec_event_authority,
            exec_event_stream_identity_sha256: &self.exec_event_stream_identity_sha256,
            final_exec_event_identity_sha256: &self.final_exec_event_identity_sha256,
            hardening_stop_event_identity_sha256: &self.hardening_stop_event_identity_sha256,
            hardening_event_identity_sha256: &self.hardening_event_identity_sha256,
            os_observation_sha256: &self.os_observation_sha256,
            fixed_cgroup_inventory_sha256: &self.fixed_cgroup_inventory_sha256,
            cgroup_directory_ancestry_sha256: &self.cgroup_directory_ancestry_sha256,
            provider_runtime_leaf_binding_sha256: &self.provider_runtime_leaf_binding_sha256,
            provider_cgroup_resource_policy_sha256: &self.provider_cgroup_resource_policy_sha256,
            provider_subtree_empty_proof_sha256: &self.provider_subtree_empty_proof_sha256,
            provider_subtree_lifecycle_sha256: &self.provider_subtree_lifecycle_sha256,
            lifecycle_operation_id_sha256: &self.lifecycle_operation_id_sha256,
            lifecycle_reservation_id_sha256: &self.lifecycle_reservation_id_sha256,
        }
    }

    fn canonical_sha256(&self) -> ProviderPostExecContainmentResult<String> {
        let mut hasher =
            domain_hasher("trillionnium.provider-post-exec-containment.complete-chain-binding.v2");
        for (name, value) in [
            ("policy_anchor_sha256", self.policy_anchor_sha256.as_str()),
            (
                "reservation_evidence_sha256",
                self.reservation_evidence_sha256.as_str(),
            ),
            ("launch_intent_sha256", self.launch_intent_sha256.as_str()),
            (
                "spawn_held_evidence_sha256",
                self.spawn_held_evidence_sha256.as_str(),
            ),
            (
                "final_exec_evidence_sha256",
                self.final_exec_evidence_sha256.as_str(),
            ),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("runtime_exec_topology", self.runtime_exec_topology.as_str()),
            (
                "provider_cgroup_resource_policy_sha256",
                self.provider_cgroup_resource_policy_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Validated data-only binding of the complete post-exec containment chain.
///
/// This value is deliberately not an authority. It is cloneable expectation
/// data and cannot release a process, activate a provider resource, or
/// authorize an effect. The opaque binding is useful to a broker-internal
/// affine custody implementation that already owns authenticated provisioned
/// policy, exact source-manifest, exact subtree reservation, and held-child
/// custody without rebuilding a weaker parallel identity record.
#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedProviderPostExecContainmentChainBinding {
    binding: ProviderPostExecContainmentAuthorityBinding,
    binding_sha256: String,
}

impl ValidatedProviderPostExecContainmentChainBinding {
    pub fn validate_complete_chain(
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
        spawn: &ProviderPostExecContainmentSpawnHeldEvidenceV2,
        final_evidence: &ProviderPostExecContainmentFinalExecEvidenceV2,
    ) -> ProviderPostExecContainmentResult<Self> {
        let binding = ProviderPostExecContainmentAuthorityBinding::from_complete_chain(
            policy,
            reservation,
            intent,
            spawn,
            final_evidence,
        )?;
        let binding_sha256 = binding.canonical_sha256()?;
        Ok(Self {
            binding,
            binding_sha256,
        })
    }

    #[must_use]
    pub fn binding_sha256(&self) -> &str {
        &self.binding_sha256
    }

    #[must_use]
    pub fn consumer_expectation(&self) -> ProviderPostExecContainmentConsumerExpectation<'_> {
        self.binding.consumer_expectation()
    }
}

#[cfg(test)]
trait TestAuthenticatedPostExecAuthorityProducer {
    fn authenticate_and_claim(
        &self,
        binding: &ProviderPostExecContainmentAuthorityBinding,
    ) -> ProviderPostExecContainmentResult<()>;
}

#[cfg(test)]
trait TestHeldProviderChildCustody {
    fn exact_binding(&self) -> &ProviderPostExecContainmentAuthorityBinding;
}

enum ProviderPostExecContainmentAuthoritySource {
    #[allow(dead_code)]
    Product(std::convert::Infallible),
    #[cfg(test)]
    Test(Box<dyn TestHeldProviderChildCustody>),
}

impl ProviderPostExecContainmentAuthoritySource {
    fn retain_for_consumed_typestate(self) -> Self {
        match self {
            Self::Product(never) => match never {},
            #[cfg(test)]
            Self::Test(custody) => Self::Test(custody),
        }
    }
}

/// Opaque affine proof that one exact final-exec-held provider chain was
/// authenticated by an out-of-band authority while custody of that exact
/// stopped child remained retained.
///
/// This type deliberately implements neither `Clone`, `Copy`, `Debug`,
/// `Default`, `Serialize` nor `Deserialize`. There is no production
/// constructor. Caller-authored or deserialized records can therefore never
/// mint it. Consuming it does not release the process or authorize an effect.
#[must_use = "dropping unconsumed containment authority must fail-stop retained child custody"]
pub struct ProviderPostExecContainmentAuthority {
    binding: ProviderPostExecContainmentAuthorityBinding,
    source: ProviderPostExecContainmentAuthoritySource,
}

impl ProviderPostExecContainmentAuthority {
    /// Consume this carrier exactly once for a consumer that already knows
    /// every identity in the authenticated chain.
    ///
    /// The returned typestate still retains the held-child custody. This
    /// source-only step cannot release the process, expose provider resources,
    /// or confer tool/effect authority.
    #[allow(
        unreachable_code,
        reason = "the production source is deliberately Infallible until broker custody is wired"
    )]
    pub fn consume_for(
        self,
        expected: &ProviderPostExecContainmentConsumerExpectation<'_>,
    ) -> ProviderPostExecContainmentResult<ConsumedProviderPostExecContainmentAuthority> {
        if !self.binding.matches_consumer(expected) {
            return Err(denied(
                "provider_post_exec_containment_consumer_binding_denied",
            ));
        }
        let Self { binding, source } = self;
        Ok(ConsumedProviderPostExecContainmentAuthority {
            binding,
            _source: source.retain_for_consumed_typestate(),
        })
    }

    #[cfg(test)]
    fn mint_for_test<P, C>(
        policy: &ProvisionedProviderRuntimePolicyV2,
        reservation: &ProviderSubtreeReservationEvidenceV2,
        intent: &ProviderPostExecContainmentLaunchIntentV2,
        spawn: &ProviderPostExecContainmentSpawnHeldEvidenceV2,
        final_evidence: &ProviderPostExecContainmentFinalExecEvidenceV2,
        producer: &P,
        custody: C,
    ) -> ProviderPostExecContainmentResult<Self>
    where
        P: TestAuthenticatedPostExecAuthorityProducer,
        C: TestHeldProviderChildCustody + 'static,
    {
        let binding = ProviderPostExecContainmentAuthorityBinding::from_complete_chain(
            policy,
            reservation,
            intent,
            spawn,
            final_evidence,
        )?;
        if custody.exact_binding() != &binding {
            return Err(denied(
                "provider_post_exec_containment_held_child_custody_denied",
            ));
        }
        producer.authenticate_and_claim(&binding)?;
        Ok(Self {
            binding,
            source: ProviderPostExecContainmentAuthoritySource::Test(Box::new(custody)),
        })
    }
}

/// Consumed source typestate for one exact provider containment carrier.
///
/// This value is also affine and opaque. It intentionally has no release,
/// activation, effect, serialization, reconstruction, or raw-parts surface.
/// Until listener/backend custody is implemented, dropping it fail-stops the
/// retained child in tests and no product instance can exist.
#[must_use = "consumed containment authority still retains held-child custody"]
pub struct ConsumedProviderPostExecContainmentAuthority {
    binding: ProviderPostExecContainmentAuthorityBinding,
    _source: ProviderPostExecContainmentAuthoritySource,
}

impl ConsumedProviderPostExecContainmentAuthority {
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.binding.provider_id
    }

    #[must_use]
    pub fn agent_id(&self) -> &str {
        &self.binding.agent_id
    }

    #[must_use]
    pub const fn runtime_exec_topology(&self) -> ProviderRuntimeExecTopologyV1 {
        self.binding.runtime_exec_topology
    }

    #[must_use]
    pub fn provider_invocation_id_sha256(&self) -> &str {
        &self.binding.provider_invocation_id_sha256
    }

    #[must_use]
    pub fn provider_session_id_sha256(&self) -> &str {
        &self.binding.provider_session_id_sha256
    }

    #[must_use]
    pub const fn expected_uid(&self) -> u32 {
        self.binding.expected_uid
    }

    #[must_use]
    pub const fn expected_gid(&self) -> u32 {
        self.binding.expected_gid
    }

    #[must_use]
    pub fn final_runtime_executable_sha256(&self) -> &str {
        &self.binding.final_runtime_executable_sha256
    }

    #[must_use]
    pub fn final_runtime_closure_sha256(&self) -> &str {
        &self.binding.final_runtime_closure_sha256
    }

    #[must_use]
    pub const fn provider_pid(&self) -> u32 {
        self.binding.provider_pid
    }

    #[must_use]
    pub const fn provider_start_time_ticks(&self) -> u64 {
        self.binding.provider_start_time_ticks
    }

    #[must_use]
    pub fn provider_pidfd_identity_sha256(&self) -> &str {
        &self.binding.provider_pidfd_identity_sha256
    }

    #[must_use]
    pub fn final_exec_evidence_sha256(&self) -> &str {
        &self.binding.final_exec_evidence_sha256
    }
}

fn required_runtime_exec_topology(
    provider_id: &str,
) -> ProviderPostExecContainmentResult<ProviderRuntimeExecTopologyV1> {
    if provider_id == agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id {
        Ok(ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime)
    } else {
        Err(denied(
            "provider_post_exec_containment_unknown_provider_denied",
        ))
    }
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

fn all_distinct(values: &[&str]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

fn domain_hasher(domain: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.provider-post-exec-containment.requirements\0");
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher
}

fn hash_string(
    hasher: &mut Sha256,
    name: &str,
    value: &str,
) -> ProviderPostExecContainmentResult<()> {
    hash_bytes(hasher, name, value.as_bytes())
}

fn hash_u8(hasher: &mut Sha256, name: &str, value: u8) -> ProviderPostExecContainmentResult<()> {
    hash_bytes(hasher, name, &[value])
}

fn hash_u32(hasher: &mut Sha256, name: &str, value: u32) -> ProviderPostExecContainmentResult<()> {
    hash_bytes(hasher, name, &value.to_be_bytes())
}

fn hash_u64(hasher: &mut Sha256, name: &str, value: u64) -> ProviderPostExecContainmentResult<()> {
    hash_bytes(hasher, name, &value.to_be_bytes())
}

fn hash_u32_list(
    hasher: &mut Sha256,
    name: &str,
    values: &[u32],
) -> ProviderPostExecContainmentResult<()> {
    let count = u64::try_from(values.len())
        .map_err(|_| denied("provider_post_exec_containment_hash_length_denied"))?;
    hash_u64(hasher, name, count)?;
    for value in values {
        hasher.update(value.to_be_bytes());
    }
    Ok(())
}

fn hash_bytes(
    hasher: &mut Sha256,
    name: &str,
    value: &[u8],
) -> ProviderPostExecContainmentResult<()> {
    let name_len = u64::try_from(name.len())
        .map_err(|_| denied("provider_post_exec_containment_hash_length_denied"))?;
    let value_len = u64::try_from(value.len())
        .map_err(|_| denied("provider_post_exec_containment_hash_length_denied"))?;
    hasher.update(name_len.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_len.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

const fn denied(code: &'static str) -> ProviderPostExecContainmentEvidenceError {
    ProviderPostExecContainmentEvidenceError(code)
}

#[cfg(test)]
fn test_digest(seed: &str) -> String {
    lower_hex(&Sha256::digest(seed.as_bytes()))
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use super::*;

    struct Fixture {
        policy: ProvisionedProviderRuntimePolicyV2,
        reservation: ProviderSubtreeReservationEvidenceV2,
        intent: ProviderPostExecContainmentLaunchIntentV2,
        spawn: ProviderPostExecContainmentSpawnHeldEvidenceV2,
        final_evidence: ProviderPostExecContainmentFinalExecEvidenceV2,
    }

    impl Fixture {
        fn new(provider_id: &str, seed: &str) -> Self {
            let principal =
                agent_principal_registry::from_provider_id(provider_id).expect("stable provider");
            let runtime_cgroup_leaf = fixed_provider_runtime_cgroup_path(provider_id).unwrap();
            let cgroup_topology = ProviderCgroupTopologyV2::fixed_for(provider_id).unwrap();
            let cgroup_resource_policy = ProviderCgroupResourcePolicyV1::provisioned(
                provider_id,
                128,
                1024 * 1024 * 1024,
                200_000,
                100_000,
            )
            .unwrap();
            let runtime_exec_topology = required_runtime_exec_topology(provider_id).unwrap();
            let launcher_executable_sha256 = test_digest(&format!("{seed}-launcher-executable"));
            let final_runtime_executable_sha256 = match runtime_exec_topology {
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => {
                    launcher_executable_sha256.clone()
                }
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
                    test_digest(&format!("{seed}-final-exe"))
                }
            };
            let mut policy = ProvisionedProviderRuntimePolicyV2 {
                schema: PROVISIONED_POLICY_V2_SCHEMA.to_string(),
                protocol: PROTOCOL.to_string(),
                provider_id: principal.provider_id.to_string(),
                agent_id: principal.agent_id.to_string(),
                runtime_exec_topology,
                agent_identity_key_sha256: launcher_executable_sha256.clone(),
                agent_manifest_sha256: test_digest(&format!("{seed}-agent-manifest")),
                policy_authority_identity_sha256: test_digest(&format!("{seed}-authority")),
                policy_store_instance_sha256: test_digest(&format!("{seed}-store")),
                system_image_sha256: test_digest(&format!("{seed}-system-image")),
                avb_chain_sha256: test_digest(&format!("{seed}-avb")),
                boot_id_sha256: test_digest(&format!("{seed}-boot")),
                provisioning_manifest_sha256: test_digest(&format!("{seed}-manifest")),
                provision_epoch_sha256: test_digest(&format!("{seed}-epoch")),
                provisioned_launcher_executable_sha256: launcher_executable_sha256,
                provisioned_final_runtime_executable_sha256: final_runtime_executable_sha256,
                provisioned_final_runtime_closure_sha256: test_digest(&format!(
                    "{seed}-final-closure"
                )),
                expected_uid: principal.uid,
                expected_gid: principal.gid,
                expected_selinux_domain: principal.agent_selinux_domain.to_string(),
                expected_provider_runtime_cgroup_leaf: runtime_cgroup_leaf,
                expected_provider_cgroup_topology: cgroup_topology,
                expected_provider_cgroup_resource_policy: cgroup_resource_policy.clone(),
                fixed_cgroup_inventory_sha256: test_digest(&format!("{seed}-inventory")),
                cgroup_directory_ancestry_sha256: test_digest(&format!("{seed}-ancestry")),
                provider_runtime_leaf_binding_sha256: test_digest(&format!("{seed}-leaf")),
                provider_cgroup_policy_sha256: cgroup_resource_policy.policy_sha256.clone(),
                expected_exec_event_authority:
                    ProviderExecEventAuthorityV1::PrivilegeBrokerPtraceExecStop,
                expected_post_exec_seccomp_filter_sha256: test_digest(&format!(
                    "{seed}-seccomp-filter"
                )),
                permitted_argv_sha256: test_digest(&format!("{seed}-argv")),
                permitted_environment_sha256: test_digest(&format!("{seed}-environment")),
                permitted_fd_table_sha256: test_digest(&format!("{seed}-fds")),
                permitted_supplementary_groups_sha256: test_digest(&format!("{seed}-groups")),
                permitted_descendant_closure_sha256: test_digest(&format!("{seed}-descendants")),
                policy_anchor_sha256: test_digest("placeholder-policy"),
            };
            policy.policy_anchor_sha256 = policy.canonical_sha256().unwrap();

            let mut reservation = ProviderSubtreeReservationEvidenceV2 {
                schema: PROVIDER_SUBTREE_RESERVATION_EVIDENCE_V2_SCHEMA.to_string(),
                protocol: PROTOCOL.to_string(),
                policy_anchor_sha256: policy.policy_anchor_sha256.clone(),
                provider_id: policy.provider_id.clone(),
                agent_id: policy.agent_id.clone(),
                provider_invocation_id_sha256: test_digest(&format!("{seed}-invocation")),
                fixed_cgroup_inventory_sha256: policy.fixed_cgroup_inventory_sha256.clone(),
                cgroup_directory_ancestry_sha256: policy.cgroup_directory_ancestry_sha256.clone(),
                provider_runtime_leaf_binding_sha256: policy
                    .provider_runtime_leaf_binding_sha256
                    .clone(),
                provider_subtree_lifecycle_sha256: test_digest(&format!("{seed}-lifecycle")),
                lifecycle_operation_id_sha256: test_digest(&format!("{seed}-operation")),
                lifecycle_reservation_id_sha256: test_digest(&format!("{seed}-reservation-id")),
                broker_subtree_generation: BrokerSubtreeGenerationV2::test_value(41),
                provider_subtree_empty_proof_sha256: test_digest(&format!("{seed}-empty-proof")),
                reservation_nonce: BrokerReservationNonceV1::test_value(&format!(
                    "{seed}-reservation-nonce"
                )),
                reservation_evidence_sha256: test_digest("placeholder-reservation"),
            };
            reservation.reservation_evidence_sha256 =
                reservation.canonical_sha256(&policy).unwrap();

            let mut intent = ProviderPostExecContainmentLaunchIntentV2 {
                schema: LAUNCH_INTENT_V2_SCHEMA.to_string(),
                protocol: PROTOCOL.to_string(),
                policy_anchor_sha256: policy.policy_anchor_sha256.clone(),
                reservation_evidence_sha256: reservation.reservation_evidence_sha256.clone(),
                provider_id: policy.provider_id.clone(),
                agent_id: policy.agent_id.clone(),
                provider_invocation_id_sha256: reservation.provider_invocation_id_sha256.clone(),
                provider_session_id_sha256: test_digest(&format!("{seed}-session")),
                daemon_challenge: DaemonChallengeV1::test_value(&format!("{seed}-challenge")),
                daemon_request_nonce: DaemonRequestNonceV1::test_value(&format!(
                    "{seed}-request-nonce"
                )),
                launch_intent_sha256: test_digest("placeholder-intent"),
            };
            intent.launch_intent_sha256 = intent.canonical_sha256(&policy, &reservation).unwrap();

            let mut spawn = ProviderPostExecContainmentSpawnHeldEvidenceV2 {
                schema: SPAWN_HELD_EVIDENCE_V2_SCHEMA.to_string(),
                protocol: PROTOCOL.to_string(),
                phase: ProviderPostExecContainmentPhaseV2::SpawnHeld,
                policy_anchor_sha256: policy.policy_anchor_sha256.clone(),
                reservation_evidence_sha256: reservation.reservation_evidence_sha256.clone(),
                launch_intent_sha256: intent.launch_intent_sha256.clone(),
                provider_id: policy.provider_id.clone(),
                agent_id: policy.agent_id.clone(),
                provider_invocation_id_sha256: intent.provider_invocation_id_sha256.clone(),
                provider_session_id_sha256: intent.provider_session_id_sha256.clone(),
                boot_id_sha256: policy.boot_id_sha256.clone(),
                provider_pid: 4242,
                provider_start_time_ticks: 90_001,
                provider_pidfd_identity_sha256: test_digest(&format!("{seed}-pidfd")),
                pid_namespace_identity_sha256: test_digest(&format!("{seed}-pid-ns")),
                cgroup_namespace_identity_sha256: test_digest(&format!("{seed}-cgroup-ns")),
                expected_provider_runtime_cgroup_leaf: policy
                    .expected_provider_runtime_cgroup_leaf
                    .clone(),
                observed_provider_runtime_cgroup_leaf_identity_sha256: policy
                    .provider_runtime_leaf_binding_sha256
                    .clone(),
                fixed_cgroup_inventory_sha256: policy.fixed_cgroup_inventory_sha256.clone(),
                cgroup_directory_ancestry_sha256: policy.cgroup_directory_ancestry_sha256.clone(),
                provider_runtime_leaf_binding_sha256: policy
                    .provider_runtime_leaf_binding_sha256
                    .clone(),
                provider_subtree_lifecycle_sha256: reservation
                    .provider_subtree_lifecycle_sha256
                    .clone(),
                lifecycle_operation_id_sha256: reservation.lifecycle_operation_id_sha256.clone(),
                lifecycle_reservation_id_sha256: reservation
                    .lifecycle_reservation_id_sha256
                    .clone(),
                broker_subtree_generation: reservation.broker_subtree_generation,
                provider_subtree_empty_proof_sha256: reservation
                    .provider_subtree_empty_proof_sha256
                    .clone(),
                observed_launcher_executable_sha256: policy
                    .provisioned_launcher_executable_sha256
                    .clone(),
                observed_uid: policy.expected_uid,
                observed_gid: policy.expected_gid,
                observed_selinux_domain: policy.expected_selinux_domain.clone(),
                exec_event_authority: policy.expected_exec_event_authority,
                exec_event_stream_identity_sha256: test_digest(&format!("{seed}-event-stream")),
                spawn_stop_event_identity_sha256: test_digest(&format!("{seed}-spawn-stop")),
                launcher_exec_event_identity_sha256: test_digest(&format!("{seed}-launcher-exec")),
                broker_spawn_nonce: BrokerSpawnNonceV1::test_value(&format!("{seed}-spawn-nonce")),
                spawn_held_evidence_sha256: test_digest("placeholder-spawn"),
            };
            spawn.spawn_held_evidence_sha256 = spawn
                .canonical_sha256(&policy, &reservation, &intent)
                .unwrap();

            let final_exec_event_identity_sha256 = match policy.runtime_exec_topology {
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => {
                    spawn.launcher_exec_event_identity_sha256.clone()
                }
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => {
                    test_digest(&format!("{seed}-final-exec"))
                }
            };
            let mut final_evidence = ProviderPostExecContainmentFinalExecEvidenceV2 {
                schema: FINAL_EXEC_EVIDENCE_V2_SCHEMA.to_string(),
                protocol: PROTOCOL.to_string(),
                phase: ProviderPostExecContainmentPhaseV2::FinalExecVerifiedHeld,
                policy_anchor_sha256: policy.policy_anchor_sha256.clone(),
                reservation_evidence_sha256: reservation.reservation_evidence_sha256.clone(),
                launch_intent_sha256: intent.launch_intent_sha256.clone(),
                spawn_held_evidence_sha256: spawn.spawn_held_evidence_sha256.clone(),
                provider_id: policy.provider_id.clone(),
                agent_id: policy.agent_id.clone(),
                provider_invocation_id_sha256: intent.provider_invocation_id_sha256.clone(),
                provider_session_id_sha256: intent.provider_session_id_sha256.clone(),
                boot_id_sha256: policy.boot_id_sha256.clone(),
                provider_pid: spawn.provider_pid,
                provider_start_time_ticks: spawn.provider_start_time_ticks,
                provider_pidfd_identity_sha256: spawn.provider_pidfd_identity_sha256.clone(),
                pid_namespace_identity_sha256: spawn.pid_namespace_identity_sha256.clone(),
                cgroup_namespace_identity_sha256: spawn.cgroup_namespace_identity_sha256.clone(),
                expected_provider_runtime_cgroup_leaf: policy
                    .expected_provider_runtime_cgroup_leaf
                    .clone(),
                expected_provider_cgroup_topology_sha256: policy
                    .expected_provider_cgroup_topology
                    .topology_sha256
                    .clone(),
                observed_provider_cgroup_resource_policy: policy
                    .expected_provider_cgroup_resource_policy
                    .clone(),
                observed_provider_runtime_cgroup_leaf_identity_sha256: policy
                    .provider_runtime_leaf_binding_sha256
                    .clone(),
                fixed_cgroup_inventory_sha256: policy.fixed_cgroup_inventory_sha256.clone(),
                cgroup_directory_ancestry_sha256: policy.cgroup_directory_ancestry_sha256.clone(),
                provider_runtime_leaf_binding_sha256: policy
                    .provider_runtime_leaf_binding_sha256
                    .clone(),
                provider_subtree_lifecycle_sha256: reservation
                    .provider_subtree_lifecycle_sha256
                    .clone(),
                lifecycle_operation_id_sha256: reservation.lifecycle_operation_id_sha256.clone(),
                lifecycle_reservation_id_sha256: reservation
                    .lifecycle_reservation_id_sha256
                    .clone(),
                broker_subtree_generation: reservation.broker_subtree_generation,
                provider_subtree_empty_proof_sha256: reservation
                    .provider_subtree_empty_proof_sha256
                    .clone(),
                observed_final_runtime_executable_sha256: policy
                    .provisioned_final_runtime_executable_sha256
                    .clone(),
                observed_final_runtime_closure_sha256: policy
                    .provisioned_final_runtime_closure_sha256
                    .clone(),
                observed_uid: policy.expected_uid,
                observed_gid: policy.expected_gid,
                observed_selinux_domain: policy.expected_selinux_domain.clone(),
                exec_event_authority: policy.expected_exec_event_authority,
                exec_event_stream_identity_sha256: spawn.exec_event_stream_identity_sha256.clone(),
                final_exec_event_identity_sha256,
                hardening_stop_event_identity_sha256: test_digest(&format!(
                    "{seed}-hardening-stop"
                )),
                hardening_event_identity_sha256: test_digest(&format!("{seed}-hardening-event")),
                final_exec_sequence: FINAL_RUNTIME_EXEC_SEQUENCE,
                post_verification_exec_event_count: 0,
                post_exec_dumpable: 0,
                post_exec_no_new_privs: 1,
                post_exec_seccomp_mode: 2,
                observed_post_exec_seccomp_filter_sha256: policy
                    .expected_post_exec_seccomp_filter_sha256
                    .clone(),
                effective_capabilities: 0,
                permitted_capabilities: 0,
                inheritable_capabilities: 0,
                ambient_capabilities: 0,
                bounding_capabilities: 0,
                supplementary_groups: Vec::new(),
                observed_supplementary_groups_sha256: policy
                    .permitted_supplementary_groups_sha256
                    .clone(),
                observed_argv_sha256: policy.permitted_argv_sha256.clone(),
                observed_environment_sha256: policy.permitted_environment_sha256.clone(),
                observed_fd_table_sha256: policy.permitted_fd_table_sha256.clone(),
                observed_descendant_closure_sha256: policy
                    .permitted_descendant_closure_sha256
                    .clone(),
                provider_subtree_process_count: PROVIDER_SUBTREE_EXPECTED_PROCESS_COUNT,
                provider_subtree_descendant_count: PROVIDER_SUBTREE_EXPECTED_DESCENDANT_COUNT,
                provider_subtree_dying_descendant_count:
                    PROVIDER_SUBTREE_EXPECTED_DYING_DESCENDANT_COUNT,
                provider_subtree_max_descendants: PROVIDER_SUBTREE_EXPECTED_MAX_DESCENDANTS,
                provider_subtree_max_depth: PROVIDER_SUBTREE_EXPECTED_MAX_DEPTH,
                runtime_leaf_process_count: 1,
                runtime_leaf_descendant_count: PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT,
                runtime_leaf_dying_descendant_count:
                    PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT,
                runtime_leaf_max_descendants: PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS,
                runtime_leaf_max_depth: PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH,
                system_api_leaf_process_count: 0,
                system_api_leaf_descendant_count: PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT,
                system_api_leaf_dying_descendant_count:
                    PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT,
                system_api_leaf_max_descendants: PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS,
                system_api_leaf_max_depth: PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH,
                accessibility_leaf_process_count: 0,
                accessibility_leaf_descendant_count: PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT,
                accessibility_leaf_dying_descendant_count:
                    PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT,
                accessibility_leaf_max_descendants: PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS,
                accessibility_leaf_max_depth: PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH,
                prompt_access_count: 0,
                broker_access_count: 0,
                invocation_tmp_access_count: 0,
                child_spawn_count: 0,
                tool_access_count: 0,
                broker_hardening_nonce: BrokerHardeningNonceV1::test_value(&format!(
                    "{seed}-hardening-nonce"
                )),
                broker_verification_nonce: BrokerVerificationNonceV1::test_value(&format!(
                    "{seed}-verification-nonce"
                )),
                os_observation_sha256: test_digest(&format!("{seed}-observation")),
                final_exec_evidence_sha256: test_digest("placeholder-final"),
            };
            final_evidence.final_exec_evidence_sha256 = final_evidence
                .canonical_sha256(&policy, &reservation, &intent, &spawn)
                .unwrap();

            Self {
                policy,
                reservation,
                intent,
                spawn,
                final_evidence,
            }
        }

        fn validate(&self) -> ProviderPostExecContainmentResult<()> {
            self.final_evidence.validate_for(
                &self.policy,
                &self.reservation,
                &self.intent,
                &self.spawn,
            )
        }

        fn authority_binding(&self) -> ProviderPostExecContainmentAuthorityBinding {
            ProviderPostExecContainmentAuthorityBinding::from_complete_chain(
                &self.policy,
                &self.reservation,
                &self.intent,
                &self.spawn,
                &self.final_evidence,
            )
            .unwrap()
        }

        fn consumer_expectation(&self) -> ProviderPostExecContainmentConsumerExpectation<'_> {
            ProviderPostExecContainmentConsumerExpectation {
                policy_anchor_sha256: &self.policy.policy_anchor_sha256,
                reservation_evidence_sha256: &self.reservation.reservation_evidence_sha256,
                launch_intent_sha256: &self.intent.launch_intent_sha256,
                spawn_held_evidence_sha256: &self.spawn.spawn_held_evidence_sha256,
                final_exec_evidence_sha256: &self.final_evidence.final_exec_evidence_sha256,
                provider_id: &self.policy.provider_id,
                agent_id: &self.policy.agent_id,
                runtime_exec_topology: self.policy.runtime_exec_topology,
                agent_identity_key_sha256: &self.policy.agent_identity_key_sha256,
                agent_manifest_sha256: &self.policy.agent_manifest_sha256,
                provider_invocation_id_sha256: &self.intent.provider_invocation_id_sha256,
                provider_session_id_sha256: &self.intent.provider_session_id_sha256,
                provision_epoch_sha256: &self.policy.provision_epoch_sha256,
                expected_uid: self.policy.expected_uid,
                expected_gid: self.policy.expected_gid,
                expected_selinux_domain: &self.policy.expected_selinux_domain,
                launcher_executable_sha256: &self.policy.provisioned_launcher_executable_sha256,
                final_runtime_executable_sha256: &self
                    .policy
                    .provisioned_final_runtime_executable_sha256,
                final_runtime_closure_sha256: &self.policy.provisioned_final_runtime_closure_sha256,
                post_exec_seccomp_filter_sha256: &self
                    .policy
                    .expected_post_exec_seccomp_filter_sha256,
                boot_id_sha256: &self.policy.boot_id_sha256,
                broker_subtree_generation: self.reservation.broker_subtree_generation.value(),
                provider_pid: self.spawn.provider_pid,
                provider_start_time_ticks: self.spawn.provider_start_time_ticks,
                provider_pidfd_identity_sha256: &self.spawn.provider_pidfd_identity_sha256,
                exec_event_authority: self.final_evidence.exec_event_authority,
                exec_event_stream_identity_sha256: &self
                    .final_evidence
                    .exec_event_stream_identity_sha256,
                final_exec_event_identity_sha256: &self
                    .final_evidence
                    .final_exec_event_identity_sha256,
                hardening_stop_event_identity_sha256: &self
                    .final_evidence
                    .hardening_stop_event_identity_sha256,
                hardening_event_identity_sha256: &self
                    .final_evidence
                    .hardening_event_identity_sha256,
                os_observation_sha256: &self.final_evidence.os_observation_sha256,
                fixed_cgroup_inventory_sha256: &self.policy.fixed_cgroup_inventory_sha256,
                cgroup_directory_ancestry_sha256: &self.policy.cgroup_directory_ancestry_sha256,
                provider_runtime_leaf_binding_sha256: &self
                    .policy
                    .provider_runtime_leaf_binding_sha256,
                provider_cgroup_resource_policy_sha256: &self
                    .policy
                    .expected_provider_cgroup_resource_policy
                    .policy_sha256,
                provider_subtree_empty_proof_sha256: &self
                    .reservation
                    .provider_subtree_empty_proof_sha256,
                provider_subtree_lifecycle_sha256: &self
                    .reservation
                    .provider_subtree_lifecycle_sha256,
                lifecycle_operation_id_sha256: &self.reservation.lifecycle_operation_id_sha256,
                lifecycle_reservation_id_sha256: &self.reservation.lifecycle_reservation_id_sha256,
            }
        }

        fn set_invocation_and_rehash(&mut self, invocation: String) {
            self.reservation.provider_invocation_id_sha256 = invocation.clone();
            self.intent.provider_invocation_id_sha256 = invocation.clone();
            self.spawn.provider_invocation_id_sha256 = invocation.clone();
            self.final_evidence.provider_invocation_id_sha256 = invocation;
            self.rehash_reservation_and_successors();
        }

        fn set_session_and_rehash(&mut self, session: String) {
            self.intent.provider_session_id_sha256 = session.clone();
            self.intent.launch_intent_sha256 = self
                .intent
                .canonical_sha256(&self.policy, &self.reservation)
                .unwrap();
            self.spawn.provider_session_id_sha256 = session.clone();
            self.spawn.launch_intent_sha256 = self.intent.launch_intent_sha256.clone();
            self.spawn.spawn_held_evidence_sha256 = self
                .spawn
                .canonical_sha256(&self.policy, &self.reservation, &self.intent)
                .unwrap();
            self.final_evidence.provider_session_id_sha256 = session;
            self.rehash_final();
        }

        fn rehash_reservation_and_successors(&mut self) {
            self.reservation.reservation_evidence_sha256 =
                self.reservation.canonical_sha256(&self.policy).unwrap();
            self.intent.reservation_evidence_sha256 =
                self.reservation.reservation_evidence_sha256.clone();
            self.intent.launch_intent_sha256 = self
                .intent
                .canonical_sha256(&self.policy, &self.reservation)
                .unwrap();
            self.spawn.reservation_evidence_sha256 =
                self.reservation.reservation_evidence_sha256.clone();
            self.spawn.launch_intent_sha256 = self.intent.launch_intent_sha256.clone();
            self.spawn.provider_subtree_lifecycle_sha256 =
                self.reservation.provider_subtree_lifecycle_sha256.clone();
            self.spawn.lifecycle_operation_id_sha256 =
                self.reservation.lifecycle_operation_id_sha256.clone();
            self.spawn.lifecycle_reservation_id_sha256 =
                self.reservation.lifecycle_reservation_id_sha256.clone();
            self.spawn.broker_subtree_generation = self.reservation.broker_subtree_generation;
            self.spawn.provider_subtree_empty_proof_sha256 =
                self.reservation.provider_subtree_empty_proof_sha256.clone();
            self.spawn.spawn_held_evidence_sha256 = self
                .spawn
                .canonical_sha256(&self.policy, &self.reservation, &self.intent)
                .unwrap();
            self.final_evidence.provider_subtree_lifecycle_sha256 =
                self.reservation.provider_subtree_lifecycle_sha256.clone();
            self.final_evidence.lifecycle_operation_id_sha256 =
                self.reservation.lifecycle_operation_id_sha256.clone();
            self.final_evidence.lifecycle_reservation_id_sha256 =
                self.reservation.lifecycle_reservation_id_sha256.clone();
            self.final_evidence.broker_subtree_generation =
                self.reservation.broker_subtree_generation;
            self.final_evidence.provider_subtree_empty_proof_sha256 =
                self.reservation.provider_subtree_empty_proof_sha256.clone();
            self.rehash_final();
        }

        fn rehash_spawn_and_final(&mut self) {
            self.spawn.spawn_held_evidence_sha256 = self
                .spawn
                .canonical_sha256(&self.policy, &self.reservation, &self.intent)
                .unwrap();
            self.final_evidence.boot_id_sha256 = self.spawn.boot_id_sha256.clone();
            self.final_evidence.provider_pid = self.spawn.provider_pid;
            self.final_evidence.provider_start_time_ticks = self.spawn.provider_start_time_ticks;
            self.final_evidence.provider_pidfd_identity_sha256 =
                self.spawn.provider_pidfd_identity_sha256.clone();
            self.final_evidence.pid_namespace_identity_sha256 =
                self.spawn.pid_namespace_identity_sha256.clone();
            self.final_evidence.cgroup_namespace_identity_sha256 =
                self.spawn.cgroup_namespace_identity_sha256.clone();
            self.final_evidence.expected_provider_runtime_cgroup_leaf =
                self.spawn.expected_provider_runtime_cgroup_leaf.clone();
            self.final_evidence
                .observed_provider_runtime_cgroup_leaf_identity_sha256 = self
                .spawn
                .observed_provider_runtime_cgroup_leaf_identity_sha256
                .clone();
            self.final_evidence.fixed_cgroup_inventory_sha256 =
                self.spawn.fixed_cgroup_inventory_sha256.clone();
            self.final_evidence.cgroup_directory_ancestry_sha256 =
                self.spawn.cgroup_directory_ancestry_sha256.clone();
            self.final_evidence.provider_runtime_leaf_binding_sha256 =
                self.spawn.provider_runtime_leaf_binding_sha256.clone();
            self.final_evidence.provider_subtree_lifecycle_sha256 =
                self.spawn.provider_subtree_lifecycle_sha256.clone();
            self.final_evidence.lifecycle_operation_id_sha256 =
                self.spawn.lifecycle_operation_id_sha256.clone();
            self.final_evidence.lifecycle_reservation_id_sha256 =
                self.spawn.lifecycle_reservation_id_sha256.clone();
            self.final_evidence.broker_subtree_generation = self.spawn.broker_subtree_generation;
            self.final_evidence.provider_subtree_empty_proof_sha256 =
                self.spawn.provider_subtree_empty_proof_sha256.clone();
            self.final_evidence.observed_uid = self.spawn.observed_uid;
            self.final_evidence.observed_gid = self.spawn.observed_gid;
            self.final_evidence.observed_selinux_domain =
                self.spawn.observed_selinux_domain.clone();
            self.final_evidence.exec_event_authority = self.spawn.exec_event_authority;
            self.final_evidence.exec_event_stream_identity_sha256 =
                self.spawn.exec_event_stream_identity_sha256.clone();
            self.rehash_final();
        }

        fn rehash_final(&mut self) {
            self.final_evidence.reservation_evidence_sha256 =
                self.reservation.reservation_evidence_sha256.clone();
            self.final_evidence.launch_intent_sha256 = self.intent.launch_intent_sha256.clone();
            self.final_evidence.spawn_held_evidence_sha256 =
                self.spawn.spawn_held_evidence_sha256.clone();
            self.final_evidence.final_exec_evidence_sha256 = self
                .final_evidence
                .canonical_sha256(&self.policy, &self.reservation, &self.intent, &self.spawn)
                .unwrap();
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestProducerFault {
        BeforeClaim,
        AfterClaim,
    }

    struct TestAuthenticatedProducer {
        exact_binding: ProviderPostExecContainmentAuthorityBinding,
        claimed: Cell<bool>,
        fault: Cell<Option<TestProducerFault>>,
    }

    impl TestAuthenticatedProducer {
        fn new(exact_binding: ProviderPostExecContainmentAuthorityBinding) -> Self {
            Self {
                exact_binding,
                claimed: Cell::new(false),
                fault: Cell::new(None),
            }
        }

        fn inject_fault(&self, fault: TestProducerFault) {
            self.fault.set(Some(fault));
        }
    }

    impl TestAuthenticatedPostExecAuthorityProducer for TestAuthenticatedProducer {
        fn authenticate_and_claim(
            &self,
            binding: &ProviderPostExecContainmentAuthorityBinding,
        ) -> ProviderPostExecContainmentResult<()> {
            let fault = self.fault.replace(None);
            if fault == Some(TestProducerFault::BeforeClaim) {
                return Err(denied(
                    "provider_post_exec_containment_test_authentication_fault",
                ));
            }
            if binding != &self.exact_binding {
                return Err(denied(
                    "provider_post_exec_containment_authenticated_binding_denied",
                ));
            }
            if self.claimed.replace(true) {
                return Err(denied(
                    "provider_post_exec_containment_authority_replay_denied",
                ));
            }
            if fault == Some(TestProducerFault::AfterClaim) {
                return Err(denied(
                    "provider_post_exec_containment_test_claim_outcome_unknown",
                ));
            }
            Ok(())
        }
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct TestCleanupCounts {
        kill: usize,
        reap: usize,
        drain_subtree: usize,
    }

    struct TestHeldChildCustody {
        exact_binding: ProviderPostExecContainmentAuthorityBinding,
        cleanup: Rc<RefCell<TestCleanupCounts>>,
    }

    impl TestHeldProviderChildCustody for TestHeldChildCustody {
        fn exact_binding(&self) -> &ProviderPostExecContainmentAuthorityBinding {
            &self.exact_binding
        }
    }

    impl Drop for TestHeldChildCustody {
        fn drop(&mut self) {
            let mut cleanup = self.cleanup.borrow_mut();
            cleanup.kill += 1;
            cleanup.reap += 1;
            cleanup.drain_subtree += 1;
        }
    }

    fn held_child_custody(
        exact_binding: ProviderPostExecContainmentAuthorityBinding,
    ) -> (TestHeldChildCustody, Rc<RefCell<TestCleanupCounts>>) {
        let cleanup = Rc::new(RefCell::new(TestCleanupCounts::default()));
        (
            TestHeldChildCustody {
                exact_binding,
                cleanup: Rc::clone(&cleanup),
            },
            cleanup,
        )
    }

    fn mint_for_test(
        fixture: &Fixture,
        producer: &TestAuthenticatedProducer,
        custody: TestHeldChildCustody,
    ) -> ProviderPostExecContainmentResult<ProviderPostExecContainmentAuthority> {
        ProviderPostExecContainmentAuthority::mint_for_test(
            &fixture.policy,
            &fixture.reservation,
            &fixture.intent,
            &fixture.spawn,
            &fixture.final_evidence,
            producer,
            custody,
        )
    }

    #[test]
    fn codex_complete_evidence_chain_validates_structurally() {
        for provider in [agent_descriptor_registry::CODEX.provider_id] {
            let fixture = Fixture::new(provider, provider);
            fixture.validate().unwrap();
            assert_eq!(
                fixture.policy.runtime_exec_topology,
                required_runtime_exec_topology(provider).unwrap()
            );
            match fixture.policy.runtime_exec_topology {
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => assert_eq!(
                    fixture.policy.provisioned_launcher_executable_sha256,
                    fixture.policy.provisioned_final_runtime_executable_sha256
                ),
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => assert_ne!(
                    fixture.policy.provisioned_launcher_executable_sha256,
                    fixture.policy.provisioned_final_runtime_executable_sha256
                ),
            }
            match fixture.policy.runtime_exec_topology {
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage => assert_eq!(
                    fixture.spawn.launcher_exec_event_identity_sha256,
                    fixture.final_evidence.final_exec_event_identity_sha256
                ),
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime => assert_ne!(
                    fixture.spawn.launcher_exec_event_identity_sha256,
                    fixture.final_evidence.final_exec_event_identity_sha256
                ),
            }
            assert_eq!(
                serde_json::from_slice::<ProviderPostExecContainmentFinalExecEvidenceV2>(
                    &serde_json::to_vec(&fixture.final_evidence).unwrap()
                )
                .unwrap(),
                fixture.final_evidence
            );
        }
    }

    #[test]
    fn validated_complete_chain_binding_is_stable_data_not_authority() {
        for provider in [agent_descriptor_registry::CODEX.provider_id] {
            let fixture = Fixture::new(provider, "validated-chain-binding");
            let binding =
                ValidatedProviderPostExecContainmentChainBinding::validate_complete_chain(
                    &fixture.policy,
                    &fixture.reservation,
                    &fixture.intent,
                    &fixture.spawn,
                    &fixture.final_evidence,
                )
                .unwrap();
            let cloned = binding.clone();
            assert_eq!(binding.binding_sha256(), cloned.binding_sha256());
            assert_ne!(
                binding.binding_sha256(),
                fixture.final_evidence.final_exec_evidence_sha256
            );
            let expected = binding.consumer_expectation();
            assert_eq!(
                expected.runtime_exec_topology,
                fixture.policy.runtime_exec_topology
            );
            assert_eq!(
                expected.agent_manifest_sha256,
                fixture.policy.agent_manifest_sha256
            );
            assert_eq!(
                expected.fixed_cgroup_inventory_sha256,
                fixture.policy.fixed_cgroup_inventory_sha256
            );
            assert_eq!(
                expected.cgroup_directory_ancestry_sha256,
                fixture.policy.cgroup_directory_ancestry_sha256
            );
            assert_eq!(
                expected.provider_runtime_leaf_binding_sha256,
                fixture.policy.provider_runtime_leaf_binding_sha256
            );
            assert_eq!(
                expected.provider_subtree_empty_proof_sha256,
                fixture.reservation.provider_subtree_empty_proof_sha256
            );
        }
    }

    #[test]
    fn authenticated_affine_carrier_covers_codex_without_releasing_custody() {
        for provider in [agent_descriptor_registry::CODEX.provider_id] {
            let fixture = Fixture::new(provider, provider);
            let binding = fixture.authority_binding();
            let producer = TestAuthenticatedProducer::new(binding.clone());
            let (custody, cleanup) = held_child_custody(binding);
            let authority = mint_for_test(&fixture, &producer, custody).unwrap();
            assert_eq!(*cleanup.borrow(), TestCleanupCounts::default());

            let consumed = authority
                .consume_for(&fixture.consumer_expectation())
                .unwrap();
            assert_eq!(consumed.provider_id(), fixture.policy.provider_id);
            assert_eq!(consumed.agent_id(), fixture.policy.agent_id);
            assert_eq!(
                consumed.runtime_exec_topology(),
                fixture.policy.runtime_exec_topology
            );
            assert_eq!(
                consumed.provider_invocation_id_sha256(),
                fixture.intent.provider_invocation_id_sha256
            );
            assert_eq!(
                consumed.provider_session_id_sha256(),
                fixture.intent.provider_session_id_sha256
            );
            assert_eq!(consumed.expected_uid(), fixture.policy.expected_uid);
            assert_eq!(consumed.expected_gid(), fixture.policy.expected_gid);
            assert_eq!(
                consumed.final_runtime_executable_sha256(),
                fixture.policy.provisioned_final_runtime_executable_sha256
            );
            assert_eq!(
                consumed.final_runtime_closure_sha256(),
                fixture.policy.provisioned_final_runtime_closure_sha256
            );
            assert_eq!(consumed.provider_pid(), fixture.spawn.provider_pid);
            assert_eq!(
                consumed.provider_start_time_ticks(),
                fixture.spawn.provider_start_time_ticks
            );
            assert_eq!(
                consumed.provider_pidfd_identity_sha256(),
                fixture.spawn.provider_pidfd_identity_sha256
            );
            assert_eq!(
                consumed.final_exec_evidence_sha256(),
                fixture.final_evidence.final_exec_evidence_sha256
            );
            assert_eq!(*cleanup.borrow(), TestCleanupCounts::default());

            // This tranche has no release typestate. Dropping the consumed
            // carrier therefore still kills, reaps and drains the held subtree.
            drop(consumed);
            assert_eq!(
                *cleanup.borrow(),
                TestCleanupCounts {
                    kill: 1,
                    reap: 1,
                    drain_subtree: 1,
                }
            );
        }
    }

    #[test]
    fn authenticated_producer_rejects_rehashed_cross_provider_invocation_and_session_chains() {
        let authentic = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-chain",
        );
        let producer = TestAuthenticatedProducer::new(authentic.authority_binding());

        let mut rehashed = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-chain",
        );
        rehashed.policy.agent_manifest_sha256 = test_digest("attacker-source-agent-manifest");
        rehashed.policy.policy_anchor_sha256 = rehashed.policy.canonical_sha256().unwrap();
        rehashed.reservation.policy_anchor_sha256 = rehashed.policy.policy_anchor_sha256.clone();
        rehashed.intent.policy_anchor_sha256 = rehashed.policy.policy_anchor_sha256.clone();
        rehashed.spawn.policy_anchor_sha256 = rehashed.policy.policy_anchor_sha256.clone();
        rehashed.final_evidence.policy_anchor_sha256 = rehashed.policy.policy_anchor_sha256.clone();
        rehashed.rehash_reservation_and_successors();
        rehashed.validate().unwrap();
        let (custody, cleanup) = held_child_custody(rehashed.authority_binding());
        assert!(mint_for_test(&rehashed, &producer, custody).is_err());
        assert_eq!(cleanup.borrow().kill, 1);
        assert!(!producer.claimed.get());

        let mut cross_invocation = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-chain",
        );
        cross_invocation.set_invocation_and_rehash(test_digest("other-invocation"));
        cross_invocation.validate().unwrap();
        let (custody, cleanup) = held_child_custody(cross_invocation.authority_binding());
        assert!(mint_for_test(&cross_invocation, &producer, custody).is_err());
        assert_eq!(cleanup.borrow().drain_subtree, 1);
        assert!(!producer.claimed.get());

        let mut cross_session = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-chain",
        );
        cross_session.set_session_and_rehash(test_digest("other-session"));
        cross_session.validate().unwrap();
        let (custody, cleanup) = held_child_custody(cross_session.authority_binding());
        assert!(mint_for_test(&cross_session, &producer, custody).is_err());
        assert_eq!(cleanup.borrow().kill, 1);
        assert!(!producer.claimed.get());
    }

    #[test]
    fn authenticated_producer_rejects_generation_process_event_hardening_and_resource_drift() {
        let authentic = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-observation",
        );
        let producer = TestAuthenticatedProducer::new(authentic.authority_binding());

        let mut boot = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-observation",
        );
        boot.policy.boot_id_sha256 = test_digest("stale-boot");
        boot.policy.policy_anchor_sha256 = boot.policy.canonical_sha256().unwrap();
        boot.reservation.policy_anchor_sha256 = boot.policy.policy_anchor_sha256.clone();
        boot.intent.policy_anchor_sha256 = boot.policy.policy_anchor_sha256.clone();
        boot.spawn.policy_anchor_sha256 = boot.policy.policy_anchor_sha256.clone();
        boot.spawn.boot_id_sha256 = boot.policy.boot_id_sha256.clone();
        boot.final_evidence.policy_anchor_sha256 = boot.policy.policy_anchor_sha256.clone();
        boot.final_evidence.boot_id_sha256 = boot.policy.boot_id_sha256.clone();
        boot.rehash_reservation_and_successors();
        boot.validate().unwrap();
        let (custody, cleanup) = held_child_custody(boot.authority_binding());
        assert!(mint_for_test(&boot, &producer, custody).is_err());
        assert_eq!(cleanup.borrow().kill, 1);

        let mut generation = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-observation",
        );
        generation.reservation.broker_subtree_generation =
            BrokerSubtreeGenerationV2::test_value(42);
        generation.rehash_reservation_and_successors();
        generation.validate().unwrap();
        let (custody, cleanup) = held_child_custody(generation.authority_binding());
        assert!(mint_for_test(&generation, &producer, custody).is_err());
        assert_eq!(cleanup.borrow().kill, 1);

        let mut process = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-observation",
        );
        process.spawn.provider_pid += 1;
        process.spawn.provider_start_time_ticks += 1;
        process.spawn.provider_pidfd_identity_sha256 = test_digest("other-held-pidfd");
        process.rehash_spawn_and_final();
        process.validate().unwrap();
        let (custody, cleanup) = held_child_custody(process.authority_binding());
        assert!(mint_for_test(&process, &producer, custody).is_err());
        assert_eq!(cleanup.borrow().reap, 1);

        let mut event = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "authenticated-observation",
        );
        event.spawn.launcher_exec_event_identity_sha256 = test_digest("other-launcher-exec-event");
        event.final_evidence.final_exec_event_identity_sha256 =
            test_digest("other-final-exec-event");
        event.rehash_spawn_and_final();
        event.validate().unwrap();
        let (custody, cleanup) = held_child_custody(event.authority_binding());
        assert!(mint_for_test(&event, &producer, custody).is_err());
        assert_eq!(cleanup.borrow().drain_subtree, 1);

        for drift in [
            |value: &mut ProviderPostExecContainmentFinalExecEvidenceV2| {
                value.post_exec_dumpable = 1;
            },
            |value: &mut ProviderPostExecContainmentFinalExecEvidenceV2| {
                value.tool_access_count = 1;
            },
        ] {
            let mut invalid = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "authenticated-observation",
            );
            drift(&mut invalid.final_evidence);
            let (custody, cleanup) = held_child_custody(authentic.authority_binding());
            assert!(mint_for_test(&invalid, &producer, custody).is_err());
            assert_eq!(
                *cleanup.borrow(),
                TestCleanupCounts {
                    kill: 1,
                    reap: 1,
                    drain_subtree: 1,
                }
            );
        }
        assert!(!producer.claimed.get());
    }

    #[test]
    fn replay_consumer_mismatch_and_injected_claim_faults_fail_stop_exactly_once() {
        let fixture = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "fault-cleanup",
        );
        let binding = fixture.authority_binding();

        let before = TestAuthenticatedProducer::new(binding.clone());
        before.inject_fault(TestProducerFault::BeforeClaim);
        let (custody, cleanup) = held_child_custody(binding.clone());
        assert!(mint_for_test(&fixture, &before, custody).is_err());
        assert_eq!(cleanup.borrow().kill, 1);
        assert!(!before.claimed.get());

        let after = TestAuthenticatedProducer::new(binding.clone());
        after.inject_fault(TestProducerFault::AfterClaim);
        let (custody, cleanup) = held_child_custody(binding.clone());
        assert!(mint_for_test(&fixture, &after, custody).is_err());
        assert_eq!(cleanup.borrow().reap, 1);
        assert!(after.claimed.get());
        let (custody, retry_cleanup) = held_child_custody(binding.clone());
        assert!(mint_for_test(&fixture, &after, custody).is_err());
        assert_eq!(retry_cleanup.borrow().drain_subtree, 1);

        let replay = TestAuthenticatedProducer::new(binding.clone());
        let (first_custody, first_cleanup) = held_child_custody(binding.clone());
        let authority = mint_for_test(&fixture, &replay, first_custody).unwrap();
        let (second_custody, second_cleanup) = held_child_custody(binding.clone());
        assert!(mint_for_test(&fixture, &replay, second_custody).is_err());
        assert_eq!(second_cleanup.borrow().kill, 1);

        let other = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "other-consumer",
        );
        assert!(
            authority
                .consume_for(&other.consumer_expectation())
                .is_err()
        );
        assert_eq!(
            *first_cleanup.borrow(),
            TestCleanupCounts {
                kill: 1,
                reap: 1,
                drain_subtree: 1,
            }
        );

        let custody_mismatch = TestAuthenticatedProducer::new(binding);
        let wrong = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "wrong-held-child",
        );
        let (custody, cleanup) = held_child_custody(wrong.authority_binding());
        assert!(mint_for_test(&fixture, &custody_mismatch, custody).is_err());
        assert_eq!(cleanup.borrow().kill, 1);
        assert!(!custody_mismatch.claimed.get());
    }

    #[test]
    fn provisioned_policy_rejects_stable_principal_cgroup_and_anchor_drift() {
        type Drift = Box<dyn Fn(&mut ProvisionedProviderRuntimePolicyV2)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|value| value.provider_id = "model-provider".to_string()),
            Box::new(|value| {
                value.agent_id = "unregistered-agent".to_string();
            }),
            Box::new(|value| value.agent_identity_key_sha256 = test_digest("identity-key-drift")),
            Box::new(|value| value.expected_uid += 1),
            Box::new(|value| value.expected_gid += 1),
            Box::new(|value| value.expected_selinux_domain.push_str("-drift")),
            Box::new(|value| {
                value
                    .expected_provider_runtime_cgroup_leaf
                    .push_str("/nested");
            }),
            Box::new(|value| {
                value.expected_provider_runtime_cgroup_leaf =
                    crate::direct_operation::CODEX_PROVIDER_CGROUP_SUBTREE.to_string();
            }),
            Box::new(|value| {
                value.expected_provider_cgroup_topology.child_leaves.pop();
            }),
            Box::new(|value| {
                value
                    .expected_provider_cgroup_topology
                    .child_leaves
                    .swap(0, 1);
            }),
            Box::new(|value| {
                value.provisioned_final_runtime_executable_sha256 =
                    value.provisioned_launcher_executable_sha256.clone();
            }),
        ];
        for drift in drifts {
            let mut fixture = Fixture::new(
                agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id,
                "policy-drift",
            );
            drift(&mut fixture.policy);
            assert!(fixture.policy.canonical_sha256().is_err());
        }

        let mut fixture = Fixture::new(
            agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id,
            "policy-anchor",
        );
        fixture.policy.policy_anchor_sha256 = test_digest("wrong-anchor");
        assert!(fixture.policy.validate().is_err());
    }

    #[test]
    fn built_in_runtime_topologies_require_distinct_launcher_and_final_images() {
        for (provider_id, seed) in [(
            agent_descriptor_registry::CODEX.provider_id,
            "codex-topology",
        )] {
            let fixture = Fixture::new(provider_id, seed);
            assert_eq!(
                fixture.policy.runtime_exec_topology,
                ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime
            );
            assert_ne!(
                fixture.policy.provisioned_launcher_executable_sha256,
                fixture.policy.provisioned_final_runtime_executable_sha256
            );

            let mut aliased_images = fixture.policy.clone();
            aliased_images.provisioned_final_runtime_executable_sha256 = aliased_images
                .provisioned_launcher_executable_sha256
                .clone();
            assert!(aliased_images.canonical_sha256().is_err());

            // The enum value remains available for a future provider, but is
            // not a valid substitution for either currently built-in agent.
            let mut single_image = fixture.policy.clone();
            single_image.runtime_exec_topology =
                ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage;
            single_image.provisioned_final_runtime_executable_sha256 =
                single_image.provisioned_launcher_executable_sha256.clone();
            assert!(single_image.canonical_sha256().is_err());
        }
    }

    #[test]
    fn runtime_exec_topology_serde_and_schema_are_closed_and_required() {
        let fixture = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "topology-wire-shape",
        );
        let policy_json = serde_json::to_value(&fixture.policy).unwrap();
        assert_eq!(
            policy_json["runtime_exec_topology"],
            "launcher_then_final_runtime"
        );

        let mut missing = policy_json.clone();
        missing
            .as_object_mut()
            .unwrap()
            .remove("runtime_exec_topology");
        assert!(serde_json::from_value::<ProvisionedProviderRuntimePolicyV2>(missing).is_err());

        let mut unknown = policy_json.clone();
        unknown["runtime_exec_topology"] = serde_json::json!("provider_selected");
        assert!(serde_json::from_value::<ProvisionedProviderRuntimePolicyV2>(unknown).is_err());
        assert!(
            serde_json::from_str::<ProviderRuntimeExecTopologyV1>("\"single_final_image\"")
                .is_err()
        );

        let schema =
            serde_json::to_value(schemars::schema_for!(ProvisionedProviderRuntimePolicyV2))
                .unwrap();
        assert_eq!(schema["additionalProperties"], false);
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "runtime_exec_topology")
        );
        assert_eq!(
            schema["definitions"]["ProviderRuntimeExecTopologyV1"]["enum"],
            serde_json::json!(["single_final_runtime_image", "launcher_then_final_runtime"])
        );
    }

    #[test]
    fn validated_downstream_binding_rejects_topology_only_substitution() {
        let fixture = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "downstream-topology",
        );
        let authentic_binding = fixture.authority_binding();
        let authentic_binding_sha256 = authentic_binding.canonical_sha256().unwrap();

        let mut substituted_binding = authentic_binding.clone();
        substituted_binding.runtime_exec_topology =
            ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage;
        assert_ne!(
            substituted_binding.canonical_sha256().unwrap(),
            authentic_binding_sha256
        );

        let producer = TestAuthenticatedProducer::new(authentic_binding.clone());
        let (custody, cleanup) = held_child_custody(substituted_binding);
        assert!(mint_for_test(&fixture, &producer, custody).is_err());
        assert_eq!(cleanup.borrow().kill, 1);
        assert!(!producer.claimed.get());

        let producer = TestAuthenticatedProducer::new(authentic_binding.clone());
        let (custody, cleanup) = held_child_custody(authentic_binding);
        let authority = mint_for_test(&fixture, &producer, custody).unwrap();
        let mut wrong_consumer = fixture.consumer_expectation();
        wrong_consumer.runtime_exec_topology =
            ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage;
        assert!(authority.consume_for(&wrong_consumer).is_err());
        assert_eq!(cleanup.borrow().reap, 1);
    }

    #[test]
    fn provisioned_policy_rejects_measured_launcher_binding_drift() {
        let principal = agent_principal_registry::CODEX_STABLE_PRINCIPAL;
        let mut fixture = Fixture::new(principal.provider_id, principal.provider_id);
        assert_eq!(
            fixture.policy.agent_identity_key_sha256,
            fixture.policy.provisioned_launcher_executable_sha256
        );
        fixture.policy.provisioned_launcher_executable_sha256 =
            test_digest("other-launcher-executable");
        assert!(fixture.policy.canonical_sha256().is_err());
    }

    #[test]
    fn source_manifest_copy_or_sha_collision_with_launcher_fails_closed() {
        let mut fixture = Fixture::new(
            agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id,
            "manifest-copy-defense",
        );
        fixture.policy.agent_manifest_sha256 = fixture.policy.agent_identity_key_sha256.clone();
        assert!(fixture.policy.canonical_sha256().is_err());
    }

    #[test]
    fn provisioned_policy_accepts_measured_launcher_distinct_from_legacy_descriptor_identity() {
        let fixture = Fixture::new(
            agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id,
            "identity-contract",
        );
        let principal = agent_principal_registry::CODEX_STABLE_PRINCIPAL;
        let legacy_descriptor = agent_descriptor_registry::CODEX;
        let value = serde_json::to_value(&fixture.policy).unwrap();
        assert_eq!(
            fixture.policy.agent_identity_key_sha256,
            fixture.policy.provisioned_launcher_executable_sha256
        );
        assert_ne!(
            fixture.policy.agent_identity_key_sha256,
            legacy_descriptor.identity_key_sha256
        );
        assert_eq!(fixture.policy.provider_id, principal.provider_id);
        assert_eq!(fixture.policy.agent_id, principal.agent_id);
        assert_eq!(fixture.policy.expected_uid, principal.uid);
        assert_eq!(fixture.policy.expected_gid, principal.gid);
        assert_eq!(
            fixture.policy.expected_selinux_domain,
            principal.agent_selinux_domain
        );
        fixture.policy.validate().unwrap();
        assert_eq!(
            value["agent_manifest_sha256"],
            fixture.policy.agent_manifest_sha256
        );
        assert_ne!(
            fixture.policy.agent_identity_key_sha256,
            fixture.policy.agent_manifest_sha256
        );
        assert!(value.get("agent_manifest_identity_sha256").is_none());

        let mut legacy = value.clone();
        let identity = legacy
            .as_object_mut()
            .unwrap()
            .remove("agent_identity_key_sha256")
            .unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .insert("agent_manifest_identity_sha256".to_string(), identity);
        assert!(serde_json::from_value::<ProvisionedProviderRuntimePolicyV2>(legacy).is_err());

        let mut missing_manifest = value.clone();
        missing_manifest
            .as_object_mut()
            .unwrap()
            .remove("agent_manifest_sha256");
        assert!(
            serde_json::from_value::<ProvisionedProviderRuntimePolicyV2>(missing_manifest).is_err()
        );

        let mut crossed = fixture.policy.clone();
        std::mem::swap(
            &mut crossed.agent_identity_key_sha256,
            &mut crossed.agent_manifest_sha256,
        );
        assert!(crossed.canonical_sha256().is_err());

        let mut manifest_drift = fixture.policy.clone();
        manifest_drift.agent_manifest_sha256 = test_digest("other-exact-source-manifest");
        assert!(manifest_drift.canonical_sha256().is_ok());
        assert!(manifest_drift.validate().is_err());
    }

    #[test]
    fn reservation_rejects_policy_anchor_drift_and_stale_structural_successors() {
        type Drift = Box<dyn Fn(&mut ProviderSubtreeReservationEvidenceV2)>;
        let policy_anchored_drifts: Vec<Drift> = vec![
            Box::new(|value| value.fixed_cgroup_inventory_sha256 = test_digest("inventory-fork")),
            Box::new(|value| {
                value.cgroup_directory_ancestry_sha256 = test_digest("ancestry-fork");
            }),
            Box::new(|value| value.provider_runtime_leaf_binding_sha256 = test_digest("leaf-fork")),
        ];
        for drift in policy_anchored_drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "custody-anchor-drift",
            );
            drift(&mut fixture.reservation);
            assert!(
                fixture
                    .reservation
                    .canonical_sha256(&fixture.policy)
                    .is_err()
            );
        }

        let broker_observation_drifts: Vec<Drift> = vec![
            Box::new(|value| {
                value.provider_subtree_lifecycle_sha256 = test_digest("lifecycle-fork")
            }),
            Box::new(|value| value.lifecycle_operation_id_sha256 = test_digest("operation-fork")),
            Box::new(|value| {
                value.lifecycle_reservation_id_sha256 = test_digest("reservation-fork");
            }),
            Box::new(|value| {
                value.broker_subtree_generation = BrokerSubtreeGenerationV2::test_value(42)
            }),
            Box::new(|value| {
                value.provider_subtree_empty_proof_sha256 = test_digest("empty-proof-fork");
            }),
        ];
        for drift in broker_observation_drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "custody-observation",
            );
            drift(&mut fixture.reservation);
            assert!(fixture.validate().is_err());

            // These are structural broker observations, not authenticated
            // history. A caller can consistently rebuild the evidence chain,
            // but doing so still produces no authority-consumption surface.
            fixture.rehash_reservation_and_successors();
            fixture.validate().unwrap();
        }
        assert!(serde_json::from_str::<BrokerSubtreeGenerationV2>("0").is_err());
        assert!(serde_json::from_str::<BrokerSubtreeGenerationV2>(&u64::MAX.to_string()).is_ok());
    }

    #[test]
    fn spawn_rejects_policy_anchor_drift_and_stale_structural_successors() {
        type SpawnDrift = Box<dyn Fn(&mut ProviderPostExecContainmentSpawnHeldEvidenceV2)>;
        let policy_anchored_drifts: Vec<SpawnDrift> = vec![
            Box::new(|value| value.boot_id_sha256 = test_digest("other-boot")),
            Box::new(|value| value.observed_uid += 1),
            Box::new(|value| value.observed_gid += 1),
            Box::new(|value| value.observed_selinux_domain.push_str("-other")),
            Box::new(|value| {
                value.observed_launcher_executable_sha256 = test_digest("other-launcher");
            }),
        ];
        for drift in policy_anchored_drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "spawn-anchor-drift",
            );
            drift(&mut fixture.spawn);
            assert!(
                fixture
                    .spawn
                    .canonical_sha256(&fixture.policy, &fixture.reservation, &fixture.intent)
                    .is_err()
            );
        }

        let os_observation_drifts: Vec<SpawnDrift> = vec![
            Box::new(|value| value.provider_pid += 1),
            Box::new(|value| value.provider_start_time_ticks += 1),
            Box::new(|value| value.provider_pidfd_identity_sha256 = test_digest("other-pidfd")),
            Box::new(|value| value.pid_namespace_identity_sha256 = test_digest("other-pid-ns")),
            Box::new(|value| {
                value.cgroup_namespace_identity_sha256 = test_digest("other-cgroup-ns");
            }),
        ];
        for drift in os_observation_drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "spawn-observation",
            );
            drift(&mut fixture.spawn);
            assert!(fixture.validate().is_err());

            // The ABI only proves cross-record structural continuity. A
            // consistently rebuilt observation remains data, not admission.
            fixture.rehash_spawn_and_final();
            fixture.validate().unwrap();
        }
    }

    #[test]
    fn final_exec_rejects_anchored_drift_and_stale_event_successors() {
        type Drift = Box<dyn Fn(&mut ProviderPostExecContainmentFinalExecEvidenceV2)>;
        let anchored_drifts: Vec<Drift> = vec![
            Box::new(|value| {
                value.observed_final_runtime_executable_sha256 = test_digest("other-final-exe");
            }),
            Box::new(|value| {
                value.observed_final_runtime_closure_sha256 = test_digest("other-final-closure");
            }),
            Box::new(|value| {
                value.observed_post_exec_seccomp_filter_sha256 =
                    test_digest("other-seccomp-filter");
            }),
            Box::new(|value| {
                value.exec_event_authority =
                    ProviderExecEventAuthorityV1::PrivilegeBrokerSeccompExecNotification;
            }),
            Box::new(|value| {
                value.exec_event_stream_identity_sha256 = test_digest("other-event-stream");
            }),
            Box::new(|value| value.final_exec_sequence = 2),
            Box::new(|value| value.post_verification_exec_event_count = 1),
        ];
        for drift in anchored_drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "event-anchor-drift",
            );
            drift(&mut fixture.final_evidence);
            assert!(
                fixture
                    .final_evidence
                    .canonical_sha256(
                        &fixture.policy,
                        &fixture.reservation,
                        &fixture.intent,
                        &fixture.spawn
                    )
                    .is_err()
            );
        }

        for provider_id in [agent_descriptor_registry::CODEX.provider_id] {
            let mut aliased_two_image_event = Fixture::new(provider_id, "two-image-event-alias");
            aliased_two_image_event
                .final_evidence
                .final_exec_event_identity_sha256 = aliased_two_image_event
                .spawn
                .launcher_exec_event_identity_sha256
                .clone();
            assert!(
                aliased_two_image_event
                    .final_evidence
                    .canonical_sha256(
                        &aliased_two_image_event.policy,
                        &aliased_two_image_event.reservation,
                        &aliased_two_image_event.intent,
                        &aliased_two_image_event.spawn,
                    )
                    .is_err()
            );
        }

        for collision_role in 0..3 {
            let mut collided = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "two-image-event-collision",
            );
            let collided_event = match collision_role {
                0 => collided.spawn.spawn_stop_event_identity_sha256.clone(),
                1 => collided
                    .final_evidence
                    .hardening_stop_event_identity_sha256
                    .clone(),
                _ => collided
                    .final_evidence
                    .hardening_event_identity_sha256
                    .clone(),
            };
            collided.final_evidence.final_exec_event_identity_sha256 = collided_event;
            assert!(
                collided
                    .final_evidence
                    .canonical_sha256(
                        &collided.policy,
                        &collided.reservation,
                        &collided.intent,
                        &collided.spawn,
                    )
                    .is_err()
            );
        }

        let mut rebuilt_two_image_event = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "two-image-event-rebuilt",
        );
        rebuilt_two_image_event
            .spawn
            .launcher_exec_event_identity_sha256 = test_digest("rebuilt-launcher-image-exec-event");
        rebuilt_two_image_event
            .final_evidence
            .final_exec_event_identity_sha256 = test_digest("rebuilt-final-image-exec-event");
        assert!(rebuilt_two_image_event.validate().is_err());
        rebuilt_two_image_event.rehash_spawn_and_final();
        rebuilt_two_image_event.validate().unwrap();

        let os_event_identity_drifts: Vec<Drift> = vec![
            Box::new(|value| {
                value.hardening_stop_event_identity_sha256 = test_digest("other-hardening-stop");
            }),
            Box::new(|value| {
                value.hardening_event_identity_sha256 = test_digest("other-hardening-event");
            }),
        ];
        for drift in os_event_identity_drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "event-observation",
            );
            drift(&mut fixture.final_evidence);
            assert!(fixture.validate().is_err());

            // Event identities are OS-authored only in the future broker. At
            // this checkpoint, full rehashing proves structural consistency
            // and cannot mint an activation or effect-authority token.
            fixture.rehash_final();
            fixture.validate().unwrap();
        }
    }

    #[test]
    fn final_exec_requires_exact_kernel_hardening_and_empty_groups() {
        type Drift = Box<dyn Fn(&mut ProviderPostExecContainmentFinalExecEvidenceV2)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|value| value.post_exec_dumpable = 1),
            Box::new(|value| value.post_exec_no_new_privs = 0),
            Box::new(|value| value.post_exec_seccomp_mode = 0),
            Box::new(|value| value.effective_capabilities = 1),
            Box::new(|value| value.permitted_capabilities = 1),
            Box::new(|value| value.inheritable_capabilities = 1),
            Box::new(|value| value.ambient_capabilities = 1),
            Box::new(|value| value.bounding_capabilities = 1),
            Box::new(|value| value.supplementary_groups.push(5901)),
            Box::new(|value| value.provider_subtree_process_count = 1),
            Box::new(|value| value.provider_subtree_descendant_count = 2),
            Box::new(|value| value.provider_subtree_dying_descendant_count = 1),
            Box::new(|value| value.provider_subtree_max_descendants = 2),
            Box::new(|value| value.provider_subtree_max_depth = 0),
            Box::new(|value| value.runtime_leaf_process_count = 0),
            Box::new(|value| value.runtime_leaf_descendant_count = 1),
            Box::new(|value| value.runtime_leaf_dying_descendant_count = 1),
            Box::new(|value| value.runtime_leaf_max_descendants = 1),
            Box::new(|value| value.runtime_leaf_max_depth = 1),
            Box::new(|value| value.system_api_leaf_process_count = 1),
            Box::new(|value| value.system_api_leaf_descendant_count = 1),
            Box::new(|value| value.system_api_leaf_dying_descendant_count = 1),
            Box::new(|value| value.system_api_leaf_max_descendants = 1),
            Box::new(|value| value.system_api_leaf_max_depth = 1),
            Box::new(|value| value.accessibility_leaf_process_count = 1),
            Box::new(|value| value.accessibility_leaf_descendant_count = 1),
            Box::new(|value| value.accessibility_leaf_dying_descendant_count = 1),
            Box::new(|value| value.accessibility_leaf_max_descendants = 1),
            Box::new(|value| value.accessibility_leaf_max_depth = 1),
            Box::new(|value| {
                value.expected_provider_cgroup_topology_sha256 = test_digest("wrong-topology")
            }),
        ];
        for drift in drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "hardening-drift",
            );
            drift(&mut fixture.final_evidence);
            assert!(
                fixture
                    .final_evidence
                    .canonical_sha256(
                        &fixture.policy,
                        &fixture.reservation,
                        &fixture.intent,
                        &fixture.spawn
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn final_exec_requires_exact_fd_env_argv_group_and_descendant_allowlists() {
        type Drift = Box<dyn Fn(&mut ProviderPostExecContainmentFinalExecEvidenceV2)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|value| {
                value.observed_supplementary_groups_sha256 = test_digest("group-drift");
            }),
            Box::new(|value| value.observed_argv_sha256 = test_digest("argv-drift")),
            Box::new(|value| value.observed_environment_sha256 = test_digest("env-drift")),
            Box::new(|value| value.observed_fd_table_sha256 = test_digest("fd-drift")),
            Box::new(|value| {
                value.observed_descendant_closure_sha256 = test_digest("descendant-drift");
            }),
        ];
        for drift in drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "allowlist-drift",
            );
            drift(&mut fixture.final_evidence);
            assert!(
                fixture
                    .final_evidence
                    .canonical_sha256(
                        &fixture.policy,
                        &fixture.reservation,
                        &fixture.intent,
                        &fixture.spawn
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn all_resource_access_counters_must_remain_zero() {
        type Drift = Box<dyn Fn(&mut ProviderPostExecContainmentFinalExecEvidenceV2)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|value| value.prompt_access_count = 1),
            Box::new(|value| value.broker_access_count = 1),
            Box::new(|value| value.invocation_tmp_access_count = 1),
            Box::new(|value| value.child_spawn_count = 1),
            Box::new(|value| value.tool_access_count = 1),
        ];
        for drift in drifts {
            let mut fixture = Fixture::new(
                agent_descriptor_registry::CODEX.provider_id,
                "resource-drift",
            );
            drift(&mut fixture.final_evidence);
            assert!(
                fixture
                    .final_evidence
                    .canonical_sha256(
                        &fixture.policy,
                        &fixture.reservation,
                        &fixture.intent,
                        &fixture.spawn
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn typed_nonce_chain_is_pairwise_distinct_and_cross_invocation_bound() {
        let mut fixture = Fixture::new(agent_descriptor_registry::CODEX.provider_id, "nonce-drift");
        fixture.intent.daemon_request_nonce =
            DaemonRequestNonceV1(fixture.intent.daemon_challenge.0.clone());
        assert!(
            fixture
                .intent
                .canonical_sha256(&fixture.policy, &fixture.reservation)
                .is_err()
        );

        let mut fixture = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "nonce-drift-2",
        );
        fixture.final_evidence.broker_verification_nonce =
            BrokerVerificationNonceV1(fixture.spawn.broker_spawn_nonce.0.clone());
        assert!(
            fixture
                .final_evidence
                .canonical_sha256(
                    &fixture.policy,
                    &fixture.reservation,
                    &fixture.intent,
                    &fixture.spawn
                )
                .is_err()
        );

        let mut fixture = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "nonce-drift-3",
        );
        fixture.spawn.broker_spawn_nonce =
            BrokerSpawnNonceV1(fixture.intent.provider_invocation_id_sha256.clone());
        assert!(
            fixture
                .spawn
                .canonical_sha256(&fixture.policy, &fixture.reservation, &fixture.intent)
                .is_err()
        );

        let mut fixture = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "nonce-drift-4",
        );
        fixture.final_evidence.broker_hardening_nonce =
            BrokerHardeningNonceV1(fixture.intent.provider_session_id_sha256.clone());
        assert!(
            fixture
                .final_evidence
                .canonical_sha256(
                    &fixture.policy,
                    &fixture.reservation,
                    &fixture.intent,
                    &fixture.spawn
                )
                .is_err()
        );

        let mut fixture = Fixture::new(
            agent_descriptor_registry::CODEX.provider_id,
            "nonce-drift-5",
        );
        fixture.final_evidence.broker_verification_nonce =
            BrokerVerificationNonceV1(fixture.intent.provider_invocation_id_sha256.clone());
        assert!(
            fixture
                .final_evidence
                .canonical_sha256(
                    &fixture.policy,
                    &fixture.reservation,
                    &fixture.intent,
                    &fixture.spawn
                )
                .is_err()
        );

        let first = Fixture::new(agent_descriptor_registry::CODEX.provider_id, "first");
        let second = Fixture::new(agent_descriptor_registry::CODEX.provider_id, "second");
        assert!(
            first
                .final_evidence
                .validate_for(
                    &second.policy,
                    &second.reservation,
                    &second.intent,
                    &second.spawn
                )
                .is_err()
        );
    }

    #[test]
    fn all_json_records_are_boolean_free_and_unknown_fields_fail_closed() {
        fn assert_boolean_free(value: &serde_json::Value) {
            match value {
                serde_json::Value::Bool(_) => panic!("serialized evidence contained a boolean"),
                serde_json::Value::Array(values) => {
                    for value in values {
                        assert_boolean_free(value);
                    }
                }
                serde_json::Value::Object(values) => {
                    for value in values.values() {
                        assert_boolean_free(value);
                    }
                }
                _ => {}
            }
        }

        let fixture = Fixture::new(agent_descriptor_registry::CODEX.provider_id, "json");
        for value in [
            serde_json::to_value(&fixture.policy).unwrap(),
            serde_json::to_value(&fixture.reservation).unwrap(),
            serde_json::to_value(&fixture.intent).unwrap(),
            serde_json::to_value(&fixture.spawn).unwrap(),
            serde_json::to_value(&fixture.final_evidence).unwrap(),
        ] {
            assert_boolean_free(&value);
        }

        let mut unknown = serde_json::to_value(&fixture.final_evidence).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("model_claimed_safe".to_string(), serde_json::json!(1));
        assert!(
            serde_json::from_value::<ProviderPostExecContainmentFinalExecEvidenceV2>(unknown)
                .is_err()
        );
        assert!(
            serde_json::from_str::<ProviderExecEventAuthorityV1>("\"provider_health_probe\"")
                .is_err()
        );
    }

    #[test]
    fn source_surface_is_affine_only_and_every_product_gate_is_false() {
        let source = include_str!("provider_post_exec_containment.rs");
        for forbidden in [
            concat!("into_", "verified("),
            concat!("Verified", "Provider"),
            concat!("Sealed", "Capability"),
            concat!("Effect", "Admission"),
            concat!("pub fn ", "release"),
            concat!("pub fn ", "activate"),
            concat!("authorized", ": bool"),
            concat!("success", ": bool"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden surface: {forbidden}"
            );
        }
        const {
            assert!(SOURCE_REQUIREMENTS_EVIDENCE_ABI_IMPLEMENTED);
            assert!(SOURCE_AFFINE_AUTHORITY_CARRIER_IMPLEMENTED);
        }
        for flag in [
            PROVISIONED_POLICY_AUTHORITY_PRODUCT_AVAILABLE,
            OS_LAUNCH_BROKER_PRODUCT_AVAILABLE,
            EXEC_EVENT_AUTHORITY_PRODUCT_AVAILABLE,
            POST_EXEC_HARDENING_PRODUCT_AVAILABLE,
            DAEMON_CLIENT_PRODUCT_WIRED,
            PROCESS_SUPERVISOR_PRODUCT_WIRED,
            CODEX_PROVIDER_PRODUCT_WIRED,
            PROVIDER_RESOURCE_ACTIVATION_PRODUCT_WIRED,
            POST_EXEC_CONTAINMENT_PRODUCT_AVAILABLE,
            CONFERS_EFFECT_AUTHORITY,
        ] {
            assert!(!flag);
        }
    }

    #[test]
    fn authority_carriers_are_opaque_affine_nonserde_and_product_unconstructible() {
        let source = include_str!("provider_post_exec_containment.rs");
        for name in [
            "ProviderPostExecContainmentAuthority",
            "ConsumedProviderPostExecContainmentAuthority",
        ] {
            let declaration = format!("pub struct {name}");
            let start = source.find(&declaration).unwrap();
            let preceding = &source[start.saturating_sub(256)..start];
            assert!(
                !preceding.contains("#[derive"),
                "{name} gained a derived capability trait"
            );
        }
        for forbidden in [
            concat!("impl Clone for ProviderPostExec", "ContainmentAuthority"),
            concat!("impl Copy for ProviderPostExec", "ContainmentAuthority"),
            concat!("impl Debug for ProviderPostExec", "ContainmentAuthority"),
            concat!("impl Default for ProviderPostExec", "ContainmentAuthority"),
            concat!(
                "impl Serialize for ProviderPostExec",
                "ContainmentAuthority"
            ),
            concat!(
                "impl serde::Serialize for ProviderPostExec",
                "ContainmentAuthority"
            ),
            concat!(
                "impl Deserialize for ProviderPostExec",
                "ContainmentAuthority"
            ),
            concat!(
                "impl serde::Deserialize for ProviderPostExec",
                "ContainmentAuthority"
            ),
            concat!(
                "impl Clone for ConsumedProviderPostExec",
                "ContainmentAuthority"
            ),
            concat!(
                "impl Copy for ConsumedProviderPostExec",
                "ContainmentAuthority"
            ),
            concat!(
                "impl Serialize for ConsumedProviderPostExec",
                "ContainmentAuthority"
            ),
            concat!(
                "impl Deserialize for ConsumedProviderPostExec",
                "ContainmentAuthority"
            ),
            concat!("pub fn mint_", "for_test"),
            concat!("pub fn from_", "complete_chain"),
            concat!("pub fn from_", "records"),
            concat!("pub fn into_", "parts"),
        ] {
            assert!(
                !source.contains(forbidden),
                "authority gained forbidden reconstruction or trait surface: {forbidden}"
            );
        }
        assert!(source.contains("Product(std::convert::Infallible)"));
        assert!(source.contains("#[cfg(test)]\n    Test(Box<dyn TestHeldProviderChildCustody>)"));
        assert!(source.contains("#[cfg(test)]\n    fn mint_for_test"));
    }

    #[test]
    fn typed_sha256_deserialization_rejects_zero_uppercase_and_wrong_width() {
        let lowercase = test_digest("typed");
        assert!(serde_json::from_str::<DaemonChallengeV1>(&format!("\"{lowercase}\"")).is_ok());
        for value in [
            "0".repeat(64),
            lowercase.to_uppercase(),
            "11".repeat(31),
            "11".repeat(33),
        ] {
            assert!(serde_json::from_str::<DaemonChallengeV1>(&format!("\"{value}\"")).is_err());
        }
    }

    #[test]
    fn rehashed_or_deserialized_caller_data_never_mints_without_authenticated_custody() {
        let authentic = Fixture::new(agent_descriptor_registry::CODEX.provider_id, "rehash");
        let producer = TestAuthenticatedProducer::new(authentic.authority_binding());

        let mut caller = Fixture::new(agent_descriptor_registry::CODEX.provider_id, "rehash");
        caller.policy =
            serde_json::from_slice(&serde_json::to_vec(&caller.policy).unwrap()).unwrap();
        caller.reservation =
            serde_json::from_slice(&serde_json::to_vec(&caller.reservation).unwrap()).unwrap();
        caller.intent =
            serde_json::from_slice(&serde_json::to_vec(&caller.intent).unwrap()).unwrap();
        caller.spawn = serde_json::from_slice(&serde_json::to_vec(&caller.spawn).unwrap()).unwrap();
        caller.final_evidence =
            serde_json::from_slice(&serde_json::to_vec(&caller.final_evidence).unwrap()).unwrap();
        caller.validate().unwrap();

        caller.policy.system_image_sha256 = test_digest("attacker-system-image");
        caller.policy.policy_anchor_sha256 = caller.policy.canonical_sha256().unwrap();
        caller.reservation.policy_anchor_sha256 = caller.policy.policy_anchor_sha256.clone();
        caller.intent.policy_anchor_sha256 = caller.policy.policy_anchor_sha256.clone();
        caller.spawn.policy_anchor_sha256 = caller.policy.policy_anchor_sha256.clone();
        caller.final_evidence.policy_anchor_sha256 = caller.policy.policy_anchor_sha256.clone();
        caller.rehash_reservation_and_successors();
        caller.validate().unwrap();

        let (custody, cleanup) = held_child_custody(caller.authority_binding());
        assert!(mint_for_test(&caller, &producer, custody).is_err());
        assert_eq!(
            *cleanup.borrow(),
            TestCleanupCounts {
                kill: 1,
                reap: 1,
                drain_subtree: 1,
            }
        );
        assert!(!producer.claimed.get());
    }
}
