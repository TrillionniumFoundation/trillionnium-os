//! Closed, data-only contracts for direct Agent operation identity and durable
//! acknowledgement handoff.
//!
//! These types do not dispatch a backend and do not form a broker. They carry
//! only OS-authored identity and digests. Raw requests, URIs, text, backend
//! results, credentials, egress grants, nonces, and expiry values are not part
//! of any schema in this module.

use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::direct_operation_custody_high_water::DirectOperationCustodyHead;

pub const STABLE_SEED_SCHEMA: &str = "trillionnium.direct-operation-seed.v1";
pub const BINDING_SCHEMA: &str = "trillionnium.direct-operation-binding.v3";
pub const BINDING_INBOX_SCHEMA: &str = "trillionnium.direct-operation-binding-inbox.v3";
pub const AUTHORIZED_ADAPTER_SET_V3_SCHEMA: &str =
    "trillionnium.direct-operation-authorized-adapter-set.v3";
pub const KERNEL_LAUNCH_CUSTODY_V3_SCHEMA: &str =
    "trillionnium.direct-operation-kernel-launch-custody.v3";
pub const KERNEL_LAUNCH_CUSTODY_KIND_V3: &str =
    "cgroup_v2_fixed_adapter_leaf_boot_pid_starttime_measured_exec_binding_v3";
pub const KERNEL_LAUNCH_CUSTODY_PRODUCER_V3: &str = "trillionnium-agent-privilege-broker";
pub const TOOL_CALL_UNCORRELATED_ALLOCATION_REQUEST_V3_SCHEMA: &str =
    "trillionnium.direct-operation-tool-call-uncorrelated-allocation-request.v3";
pub const TOOL_CALL_RETRY_CORRELATION_ABSENT_PRODUCT_HOLD: &str = "absent_product_hold";
pub const TOOL_CALL_DELIVERY_V3_SCHEMA: &str =
    "trillionnium.direct-operation-tool-call-delivery.v3";
pub const TOOL_CALL_ALLOCATION_REQUEST_V3_SCHEMA: &str =
    "trillionnium.direct-operation-tool-call-allocation-request.v3";
pub const TOOL_CALL_RETRY_CORRELATION_DAEMON_DELIVERY_V3: &str =
    "daemon_durable_logical_delivery_v3";
pub const TOOL_CALL_ENVELOPE_V3_SCHEMA: &str =
    "trillionnium.direct-operation-tool-call-envelope.v3";
pub const TOOL_CALL_PREPARED_ACK_V3_SCHEMA: &str =
    "trillionnium.direct-operation-tool-call-prepared-ack.v3";
pub const TOOL_CALL_COMMIT_RECEIPT_V3_SCHEMA: &str =
    "trillionnium.direct-operation-tool-call-commit-receipt.v3";
pub const OS_TOOL_CALL_ID_PREFIX: &str = "tool-call:";
pub const JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA: &str =
    "trillionnium.direct-operation-journal-evidence-snapshot.v1";
pub const ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA: &str =
    "trillionnium.direct-operation-adapter-terminal-disposition.v1";
pub const OUTER_RECEIPT_V3_SCHEMA: &str = "trillionnium.direct-operation-outer-receipt.v3";
pub const OUTER_ACK_V3_SCHEMA: &str = "trillionnium.direct-operation-outer-ack.v3";
pub const OUTER_ACK_CHAIN_STEP_V3_SCHEMA: &str =
    "trillionnium.direct-operation-outer-ack-chain-step.v3";
pub const OUTER_ACK_INBOX_V3_SCHEMA: &str = "trillionnium.direct-operation-outer-ack-inbox.v3";
pub const OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA: &str =
    "trillionnium.direct-operation-replay-sync-command.v3";
pub const P0_REPLAY_SYNC_SEALED_AUTHORITY_V1_SCHEMA: &str =
    "trillionnium.p0-replay-sync-sealed-authority.v1";
pub const OPERATION_REPLAY_SYNC_OBSERVATION_V3_SCHEMA: &str =
    "trillionnium.direct-operation-replay-sync-observation.v3";
pub const OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA: &str =
    "trillionnium.direct-operation-replay-sync-ack-confirmation.v3";
pub const P0_REPLAY_SYNC_ACK_CONFIRMATION_V1_SCHEMA: &str =
    "trillionnium.p0-replay-sync-ack-confirmation.v1";
pub const P0_REPLAY_SYNC_ACK_CONFIRMATION_LANE: &str = "non_product_userdebug_daemon_custody";
pub const INVOCATION_ID_PREFIX: &str = "inv:";
pub const PROVIDER_ATTEMPT_ID_PREFIX: &str = "attempt:";
pub const MAX_OUTER_ACK_EVIDENCE: usize = 256;
pub const MAX_AUTHORIZED_ADAPTERS_V3: usize = 2;
pub const MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE: u64 = i64::MAX as u64;

/// Canonical source-only cgroup-v2 topology for each built-in provider.
///
/// The provider path is a process-free subtree, not a runnable leaf. Its three
/// exact direct children are the provider runtime and the two Direct adapters.
/// These constants describe policy only; they do not prove that Android init
/// created the topology or that a broker retains its directory FDs.
pub const PROVIDER_CGROUP_TOPOLOGY_V2_SCHEMA: &str = "trillionnium.provider-cgroup-topology.v2";
pub const PROVIDER_CGROUP_RESOURCE_POLICY_V1_SCHEMA: &str =
    "trillionnium.provider-cgroup-resource-policy.v1";
pub const CODEX_PROVIDER_CGROUP_SUBTREE: &str = "/trillionnium/agents/codex";
pub const CODEX_PROVIDER_RUNTIME_CGROUP_PATH: &str = "/trillionnium/agents/codex/runtime";
pub const PROVIDER_SUBTREE_EXPECTED_PROCESS_COUNT: u64 = 0;
pub const PROVIDER_SUBTREE_EXPECTED_DESCENDANT_COUNT: u64 = 3;
pub const PROVIDER_SUBTREE_EXPECTED_DYING_DESCENDANT_COUNT: u64 = 0;
pub const PROVIDER_SUBTREE_EXPECTED_MAX_DESCENDANTS: u64 = 3;
pub const PROVIDER_SUBTREE_EXPECTED_MAX_DEPTH: u64 = 1;
pub const PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT: u64 = 0;
pub const PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT: u64 = 0;
pub const PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS: u64 = 0;
pub const PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH: u64 = 0;

/// Lower and upper bounds for a provisioned provider-runtime cgroup policy.
///
/// These are validation bounds, not product defaults. A trusted provisioning
/// authority must select and authenticate one exact policy per provider and
/// device class. The current product has no such authority and therefore may
/// not infer values from these bounds.
pub const PROVIDER_RUNTIME_MIN_PIDS_MAX: u64 = 2;
pub const PROVIDER_RUNTIME_MAX_PIDS_MAX: u64 = 4_096;
pub const PROVIDER_RUNTIME_MIN_MEMORY_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const PROVIDER_RUNTIME_MAX_MEMORY_MAX_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const PROVIDER_RUNTIME_MEMORY_ALIGNMENT_BYTES: u64 = 4_096;
pub const PROVIDER_RUNTIME_MIN_CPU_PERIOD_US: u64 = 1_000;
pub const PROVIDER_RUNTIME_MAX_CPU_PERIOD_US: u64 = 1_000_000;
pub const PROVIDER_RUNTIME_MAX_CPU_QUOTA_MULTIPLIER: u64 = 8;

const SHA256_HEX_BYTES: usize = 64;
const JOURNAL_EPOCH_HEX_BYTES: usize = 32;
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub type DirectOperationResult<T> = Result<T, DirectOperationProtocolError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectOperationProtocolError(&'static str);

impl DirectOperationProtocolError {
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DirectOperationProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for DirectOperationProtocolError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationStableSeed {
    pub schema: String,
    pub provider_id: String,
    pub agent_id: String,
    pub task_id: String,
    pub provider_invocation_id_sha256: String,
    pub provider_session_id_sha256: String,
    pub subject_uid: u32,
    pub subject_selinux_domain_sha256: String,
}

impl DirectOperationStableSeed {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != STABLE_SEED_SCHEMA {
            return Err(invalid("unknown stable invocation seed schema"));
        }
        if !valid_provider_agent_pair(&self.provider_id, &self.agent_id) {
            return Err(invalid("provider and Agent identity do not match"));
        }
        if !valid_atom(&self.task_id, 128)
            || !valid_sha256(&self.provider_invocation_id_sha256)
            || !valid_sha256(&self.provider_session_id_sha256)
            || self.subject_uid == 0
            || !valid_sha256(&self.subject_selinux_domain_sha256)
        {
            return Err(invalid("stable invocation seed field is malformed"));
        }
        Ok(())
    }

    pub fn invocation_id(&self) -> DirectOperationResult<String> {
        self.validate()?;
        let mut hasher = domain_hasher(b"trillionnium.direct-operation-invocation-id.v1");
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"task_id", &self.task_id);
        hash_string_field(
            &mut hasher,
            b"provider_invocation_id_sha256",
            &self.provider_invocation_id_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"provider_session_id_sha256",
            &self.provider_session_id_sha256,
        );
        hash_bytes_field(&mut hasher, b"subject_uid", &self.subject_uid.to_be_bytes());
        hash_string_field(
            &mut hasher,
            b"subject_selinux_domain_sha256",
            &self.subject_selinux_domain_sha256,
        );
        Ok(format!(
            "{INVOCATION_ID_PREFIX}{}",
            lower_hex(&hasher.finalize())
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationProviderAttempt {
    pub delivery_provider_attempt_id: String,
    pub runtime_lifecycle_binding_sha256: String,
    pub attempt_generation: u64,
    pub daemon_attempt_context_sha256: String,
}

impl DirectOperationProviderAttempt {
    /// Derive the only accepted provider-attempt identity from daemon-authored
    /// lifecycle material. `attempt_generation` is a daemon-maintained,
    /// non-zero generation within that lifecycle; it is not model input.
    pub fn derive(
        runtime_lifecycle_binding_sha256: String,
        attempt_generation: u64,
        daemon_attempt_context_sha256: String,
    ) -> DirectOperationResult<Self> {
        if !valid_sha256(&runtime_lifecycle_binding_sha256)
            || attempt_generation == 0
            || !valid_sha256(&daemon_attempt_context_sha256)
        {
            return Err(invalid("provider attempt derivation field is malformed"));
        }
        let delivery_provider_attempt_id = derive_provider_attempt_id(
            &runtime_lifecycle_binding_sha256,
            attempt_generation,
            &daemon_attempt_context_sha256,
        );
        Ok(Self {
            delivery_provider_attempt_id,
            runtime_lifecycle_binding_sha256,
            attempt_generation,
            daemon_attempt_context_sha256,
        })
    }

    pub fn validate(&self) -> DirectOperationResult<()> {
        if !valid_prefixed_sha256(
            &self.delivery_provider_attempt_id,
            PROVIDER_ATTEMPT_ID_PREFIX,
        ) || !valid_sha256(&self.runtime_lifecycle_binding_sha256)
            || self.attempt_generation == 0
            || !valid_sha256(&self.daemon_attempt_context_sha256)
            || self.delivery_provider_attempt_id
                != derive_provider_attempt_id(
                    &self.runtime_lifecycle_binding_sha256,
                    self.attempt_generation,
                    &self.daemon_attempt_context_sha256,
                )
        {
            return Err(invalid("provider attempt identity is malformed"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationBinding {
    pub schema: String,
    pub stable_seed: DirectOperationStableSeed,
    pub invocation_id: String,
    pub workflow_id_sha256: String,
    pub agent_identity_key_sha256: String,
    pub agent_executable_sha256: String,
    pub authorized_adapter_set: DirectOperationAuthorizedAdapterSetV3,
    pub attempt: DirectOperationProviderAttempt,
}

impl DirectOperationBinding {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != BINDING_SCHEMA {
            return Err(invalid("unknown direct operation binding schema"));
        }
        self.stable_seed.validate()?;
        self.attempt.validate()?;
        self.authorized_adapter_set.validate()?;
        if self.invocation_id != self.stable_seed.invocation_id()?
            || !valid_nonzero_sha256(&self.workflow_id_sha256)
            || !valid_nonzero_sha256(&self.agent_identity_key_sha256)
            || !valid_nonzero_sha256(&self.agent_executable_sha256)
        {
            return Err(invalid(
                "direct operation invocation or OS identity binding is malformed",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate()?;
        let mut hasher = domain_hasher(b"trillionnium.direct-operation-binding-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"provider_id", &self.stable_seed.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.stable_seed.agent_id);
        hash_string_field(&mut hasher, b"task_id", &self.stable_seed.task_id);
        hash_string_field(
            &mut hasher,
            b"provider_invocation_id_sha256",
            &self.stable_seed.provider_invocation_id_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"provider_session_id_sha256",
            &self.stable_seed.provider_session_id_sha256,
        );
        hash_bytes_field(
            &mut hasher,
            b"subject_uid",
            &self.stable_seed.subject_uid.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"subject_selinux_domain_sha256",
            &self.stable_seed.subject_selinux_domain_sha256,
        );
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(&mut hasher, b"workflow_id_sha256", &self.workflow_id_sha256);
        hash_string_field(
            &mut hasher,
            b"agent_identity_key_sha256",
            &self.agent_identity_key_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"agent_executable_sha256",
            &self.agent_executable_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"authorized_adapter_set_sha256",
            &self.authorized_adapter_set.digest_sha256()?,
        );
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.attempt.delivery_provider_attempt_id,
        );
        hash_string_field(
            &mut hasher,
            b"runtime_lifecycle_binding_sha256",
            &self.attempt.runtime_lifecycle_binding_sha256,
        );
        hash_bytes_field(
            &mut hasher,
            b"attempt_generation",
            &self.attempt.attempt_generation.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"daemon_attempt_context_sha256",
            &self.attempt.daemon_attempt_context_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationBindingInbox {
    pub schema: String,
    pub binding: DirectOperationBinding,
    pub binding_sha256: String,
}

impl DirectOperationBindingInbox {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != BINDING_INBOX_SCHEMA
            || !valid_sha256(&self.binding_sha256)
            || self.binding.digest_sha256()? != self.binding_sha256
        {
            return Err(invalid("binding inbox digest or schema does not match"));
        }
        Ok(())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, PartialOrd, Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationAdapter {
    SystemApi,
    Accessibility,
}

/// Root-authored, closed adapter authorization policy for one Direct binding.
///
/// V3 accepts exactly the first-slice profile `[system_api]` and reserves the
/// canonical future profile `[system_api, accessibility]`. Empty,
/// Accessibility-only, duplicate, reversed, or extended sets are invalid.
/// Structural validation is not effect authority; all product/effect gates
/// remain closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationAuthorizedAdapterSetV3 {
    pub schema: String,
    pub authorized_adapters: Vec<DirectOperationAdapter>,
    pub authorized_adapters_sha256: String,
}

impl DirectOperationAuthorizedAdapterSetV3 {
    #[must_use]
    pub fn p0_system_api() -> Self {
        Self::from_canonical(vec![DirectOperationAdapter::SystemApi])
    }

    /// Reserved exact dual-adapter V3 shape for the later Accessibility slice.
    /// The current P0 constructor must not select it.
    #[must_use]
    pub fn future_system_api_and_accessibility() -> Self {
        Self::from_canonical(vec![
            DirectOperationAdapter::SystemApi,
            DirectOperationAdapter::Accessibility,
        ])
    }

    pub fn validate(&self) -> DirectOperationResult<()> {
        self.validate_shape()?;
        if !valid_nonzero_sha256(&self.authorized_adapters_sha256)
            || self.authorized_adapters_sha256 != self.digest_sha256()?
        {
            return Err(invalid(
                "authorized adapter set digest does not match canonical policy",
            ));
        }
        Ok(())
    }

    pub fn validate_p0_system_api(&self) -> DirectOperationResult<()> {
        self.validate()?;
        if self.authorized_adapters.as_slice() != [DirectOperationAdapter::SystemApi] {
            return Err(invalid(
                "P0 authorized adapter profile is not exactly System API",
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn authorizes(&self, adapter: DirectOperationAdapter) -> bool {
        self.validate().is_ok() && self.authorized_adapters.contains(&adapter)
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate_shape()?;
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-authorized-adapter-set-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_bytes_field(
            &mut hasher,
            b"count",
            &(self.authorized_adapters.len() as u64).to_be_bytes(),
        );
        for adapter in &self.authorized_adapters {
            hash_string_field(&mut hasher, b"authorized_adapter", adapter.adapter_id());
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    fn from_canonical(authorized_adapters: Vec<DirectOperationAdapter>) -> Self {
        let mut value = Self {
            schema: AUTHORIZED_ADAPTER_SET_V3_SCHEMA.to_string(),
            authorized_adapters,
            authorized_adapters_sha256: String::new(),
        };
        value.authorized_adapters_sha256 = value
            .digest_sha256()
            .expect("fixed authorized adapter profile must be canonical");
        value
    }

    fn validate_shape(&self) -> DirectOperationResult<()> {
        let adapters = self.authorized_adapters.as_slice();
        let p0 = [DirectOperationAdapter::SystemApi];
        let future_dual = [
            DirectOperationAdapter::SystemApi,
            DirectOperationAdapter::Accessibility,
        ];
        if self.schema != AUTHORIZED_ADAPTER_SET_V3_SCHEMA
            || adapters.is_empty()
            || adapters.len() > MAX_AUTHORIZED_ADAPTERS_V3
            || (adapters != p0 && adapters != future_dual)
        {
            return Err(invalid(
                "authorized adapter set is empty, unordered, duplicated, or unsupported",
            ));
        }
        Ok(())
    }
}

/// Closed child roles below one process-free provider subtree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCgroupChildRoleV2 {
    Runtime,
    SystemApi,
    Accessibility,
}

impl ProviderCgroupChildRoleV2 {
    #[must_use]
    pub const fn directory_name(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::SystemApi => "system-api",
            Self::Accessibility => "accessibility",
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::SystemApi => "system_api",
            Self::Accessibility => "accessibility",
        }
    }
}

/// Exact zero-descendant policy for one child leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderCgroupChildLeafV2 {
    pub role: ProviderCgroupChildRoleV2,
    pub unified_cgroup_path: String,
    pub descendant_count: u64,
    pub dying_descendant_count: u64,
    pub max_descendants: u64,
    pub max_depth: u64,
}

/// Exact topology expectation used by the source-only provider containment
/// contract.
///
/// This is deliberately plain data. `validate_for` proves only that the record
/// exactly matches the closed expectation; it is not a kernel observation and
/// does not confer effect authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderCgroupTopologyV2 {
    pub schema: String,
    pub provider_id: String,
    pub provider_subtree_path: String,
    pub provider_subtree_process_count: u64,
    pub provider_subtree_descendant_count: u64,
    pub provider_subtree_dying_descendant_count: u64,
    pub provider_subtree_max_descendants: u64,
    pub provider_subtree_max_depth: u64,
    pub child_leaves: Vec<ProviderCgroupChildLeafV2>,
    pub topology_sha256: String,
}

impl ProviderCgroupTopologyV2 {
    pub fn fixed_for(provider_id: &str) -> DirectOperationResult<Self> {
        let child_leaves = [
            ProviderCgroupChildRoleV2::Runtime,
            ProviderCgroupChildRoleV2::SystemApi,
            ProviderCgroupChildRoleV2::Accessibility,
        ]
        .into_iter()
        .map(|role| {
            Ok(ProviderCgroupChildLeafV2 {
                role,
                unified_cgroup_path: fixed_provider_cgroup_leaf_path(provider_id, role)?,
                descendant_count: PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT,
                dying_descendant_count: PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT,
                max_descendants: PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS,
                max_depth: PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH,
            })
        })
        .collect::<DirectOperationResult<Vec<_>>>()?;
        let mut value = Self {
            schema: PROVIDER_CGROUP_TOPOLOGY_V2_SCHEMA.to_string(),
            provider_id: provider_id.to_string(),
            provider_subtree_path: fixed_provider_cgroup_subtree(provider_id)?.to_string(),
            provider_subtree_process_count: PROVIDER_SUBTREE_EXPECTED_PROCESS_COUNT,
            provider_subtree_descendant_count: PROVIDER_SUBTREE_EXPECTED_DESCENDANT_COUNT,
            provider_subtree_dying_descendant_count:
                PROVIDER_SUBTREE_EXPECTED_DYING_DESCENDANT_COUNT,
            provider_subtree_max_descendants: PROVIDER_SUBTREE_EXPECTED_MAX_DESCENDANTS,
            provider_subtree_max_depth: PROVIDER_SUBTREE_EXPECTED_MAX_DEPTH,
            child_leaves,
            topology_sha256: String::new(),
        };
        value.topology_sha256 = value.digest_sha256()?;
        Ok(value)
    }

    pub fn validate_for(&self, provider_id: &str) -> DirectOperationResult<()> {
        self.validate_shape_for(provider_id)?;
        if !valid_nonzero_sha256(&self.topology_sha256)
            || self.topology_sha256 != self.digest_sha256()?
        {
            return Err(invalid("provider cgroup topology digest is invalid"));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate_shape_for(&self.provider_id)?;
        let mut hasher = domain_hasher(b"trillionnium.provider-cgroup-topology-digest.v2");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(
            &mut hasher,
            b"provider_subtree_path",
            &self.provider_subtree_path,
        );
        for (name, value) in [
            (
                b"provider_subtree_process_count".as_slice(),
                self.provider_subtree_process_count,
            ),
            (
                b"provider_subtree_descendant_count".as_slice(),
                self.provider_subtree_descendant_count,
            ),
            (
                b"provider_subtree_dying_descendant_count".as_slice(),
                self.provider_subtree_dying_descendant_count,
            ),
            (
                b"provider_subtree_max_descendants".as_slice(),
                self.provider_subtree_max_descendants,
            ),
            (
                b"provider_subtree_max_depth".as_slice(),
                self.provider_subtree_max_depth,
            ),
        ] {
            hash_bytes_field(&mut hasher, name, &value.to_be_bytes());
        }
        for leaf in &self.child_leaves {
            hash_string_field(&mut hasher, b"child_role", leaf.role.as_str());
            hash_string_field(
                &mut hasher,
                b"child_unified_cgroup_path",
                &leaf.unified_cgroup_path,
            );
            for (name, value) in [
                (b"child_descendant_count".as_slice(), leaf.descendant_count),
                (
                    b"child_dying_descendant_count".as_slice(),
                    leaf.dying_descendant_count,
                ),
                (b"child_max_descendants".as_slice(), leaf.max_descendants),
                (b"child_max_depth".as_slice(), leaf.max_depth),
            ] {
                hash_bytes_field(&mut hasher, name, &value.to_be_bytes());
            }
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_shape_for(&self, provider_id: &str) -> DirectOperationResult<()> {
        let expected_roles = [
            ProviderCgroupChildRoleV2::Runtime,
            ProviderCgroupChildRoleV2::SystemApi,
            ProviderCgroupChildRoleV2::Accessibility,
        ];
        if self.schema != PROVIDER_CGROUP_TOPOLOGY_V2_SCHEMA
            || self.provider_id != provider_id
            || self.provider_subtree_path != fixed_provider_cgroup_subtree(provider_id)?
            || self.provider_subtree_process_count != PROVIDER_SUBTREE_EXPECTED_PROCESS_COUNT
            || self.provider_subtree_descendant_count != PROVIDER_SUBTREE_EXPECTED_DESCENDANT_COUNT
            || self.provider_subtree_dying_descendant_count
                != PROVIDER_SUBTREE_EXPECTED_DYING_DESCENDANT_COUNT
            || self.provider_subtree_max_descendants != PROVIDER_SUBTREE_EXPECTED_MAX_DESCENDANTS
            || self.provider_subtree_max_depth != PROVIDER_SUBTREE_EXPECTED_MAX_DEPTH
            || self.child_leaves.len() != expected_roles.len()
        {
            return Err(invalid("provider cgroup parent topology is invalid"));
        }
        for (leaf, expected_role) in self.child_leaves.iter().zip(expected_roles) {
            if leaf.role != expected_role
                || leaf.unified_cgroup_path
                    != fixed_provider_cgroup_leaf_path(provider_id, expected_role)?
                || leaf.descendant_count != PROVIDER_CHILD_LEAF_EXPECTED_DESCENDANT_COUNT
                || leaf.dying_descendant_count
                    != PROVIDER_CHILD_LEAF_EXPECTED_DYING_DESCENDANT_COUNT
                || leaf.max_descendants != PROVIDER_CHILD_LEAF_EXPECTED_MAX_DESCENDANTS
                || leaf.max_depth != PROVIDER_CHILD_LEAF_EXPECTED_MAX_DEPTH
            {
                return Err(invalid("provider cgroup child topology is invalid"));
            }
        }
        Ok(())
    }
}

/// Exact finite resource controls for one provider runtime cgroup-v2 leaf.
///
/// This record binds the kernel files which prevent an admitted model runtime
/// from consuming ambient process, memory, swap, or CPU capacity. It is plain
/// policy data: parsing or validating it neither writes a cgroup nor proves a
/// process was placed there. Product admission additionally requires a
/// retained-FD kernel observer to read back these exact values while the final
/// runtime remains held.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProviderCgroupResourcePolicyV1 {
    pub schema: String,
    pub provider_id: String,
    pub runtime_leaf_path: String,
    pub pids_max: u64,
    pub memory_max_bytes: u64,
    pub memory_swap_max_bytes: u64,
    pub memory_oom_group: u8,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub policy_sha256: String,
}

impl ProviderCgroupResourcePolicyV1 {
    /// Construct one provisioned candidate. Values are deliberately explicit;
    /// there is no product default that a caller can accidentally promote.
    pub fn provisioned(
        provider_id: &str,
        pids_max: u64,
        memory_max_bytes: u64,
        cpu_quota_us: u64,
        cpu_period_us: u64,
    ) -> DirectOperationResult<Self> {
        let mut value = Self {
            schema: PROVIDER_CGROUP_RESOURCE_POLICY_V1_SCHEMA.to_string(),
            provider_id: provider_id.to_string(),
            runtime_leaf_path: fixed_provider_runtime_cgroup_path(provider_id)?,
            pids_max,
            memory_max_bytes,
            memory_swap_max_bytes: 0,
            memory_oom_group: 1,
            cpu_quota_us,
            cpu_period_us,
            policy_sha256: String::new(),
        };
        value.policy_sha256 = value.digest_sha256()?;
        Ok(value)
    }

    pub fn validate_for(&self, provider_id: &str) -> DirectOperationResult<()> {
        self.validate_shape_for(provider_id)?;
        if !valid_nonzero_sha256(&self.policy_sha256)
            || self.policy_sha256 != self.digest_sha256()?
        {
            return Err(invalid("provider cgroup resource policy digest is invalid"));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate_shape_for(&self.provider_id)?;
        let mut hasher = domain_hasher(b"trillionnium.provider-cgroup-resource-policy-digest.v1");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"runtime_leaf_path", &self.runtime_leaf_path);
        for (name, value) in [
            (b"pids_max".as_slice(), self.pids_max),
            (b"memory_max_bytes".as_slice(), self.memory_max_bytes),
            (
                b"memory_swap_max_bytes".as_slice(),
                self.memory_swap_max_bytes,
            ),
            (
                b"memory_oom_group".as_slice(),
                u64::from(self.memory_oom_group),
            ),
            (b"cpu_quota_us".as_slice(), self.cpu_quota_us),
            (b"cpu_period_us".as_slice(), self.cpu_period_us),
        ] {
            hash_bytes_field(&mut hasher, name, &value.to_be_bytes());
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_shape_for(&self, provider_id: &str) -> DirectOperationResult<()> {
        let max_quota = self
            .cpu_period_us
            .checked_mul(PROVIDER_RUNTIME_MAX_CPU_QUOTA_MULTIPLIER)
            .ok_or_else(|| invalid("provider cgroup CPU quota overflow"))?;
        if self.schema != PROVIDER_CGROUP_RESOURCE_POLICY_V1_SCHEMA
            || self.provider_id != provider_id
            || self.runtime_leaf_path != fixed_provider_runtime_cgroup_path(provider_id)?
            || !(PROVIDER_RUNTIME_MIN_PIDS_MAX..=PROVIDER_RUNTIME_MAX_PIDS_MAX)
                .contains(&self.pids_max)
            || !(PROVIDER_RUNTIME_MIN_MEMORY_MAX_BYTES..=PROVIDER_RUNTIME_MAX_MEMORY_MAX_BYTES)
                .contains(&self.memory_max_bytes)
            || !self
                .memory_max_bytes
                .is_multiple_of(PROVIDER_RUNTIME_MEMORY_ALIGNMENT_BYTES)
            || self.memory_swap_max_bytes != 0
            || self.memory_oom_group != 1
            || !(PROVIDER_RUNTIME_MIN_CPU_PERIOD_US..=PROVIDER_RUNTIME_MAX_CPU_PERIOD_US)
                .contains(&self.cpu_period_us)
            || self.cpu_quota_us < PROVIDER_RUNTIME_MIN_CPU_PERIOD_US
            || self.cpu_quota_us > max_quota
        {
            return Err(invalid("provider cgroup resource policy is invalid"));
        }
        Ok(())
    }
}

impl DirectOperationAdapter {
    #[must_use]
    pub const fn adapter_id(self) -> &'static str {
        match self {
            Self::SystemApi => "system_api",
            Self::Accessibility => "accessibility",
        }
    }

    #[must_use]
    pub const fn tool_name(self) -> &'static str {
        match self {
            Self::SystemApi => "trillionnium_system_api",
            Self::Accessibility => "trillionnium_accessibility",
        }
    }
}

/// Root-authored proof required by production Direct adapters before they may
/// consume a binding or contact a backend.
///
/// This is a closed handoff from kernel-owned provider-subtree custody. It does
/// not itself create, drain, or mutate a cgroup. A product producer may emit it
/// only after reserving the exact subtree generation, proving the selected
/// adapter child leaf empty, and completing measured atomic exec into that
/// leaf. The daemon-maintained provider-attempt generation and the
/// broker-maintained subtree generation are deliberately independent. The
/// latter is bound to the broker's exact reservation evidence by a separate
/// digest. The adapter independently verifies that its live process remains
/// in the exact fixed adapter leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationKernelLaunchCustodyV3 {
    pub schema: String,
    pub kernel_custody_kind: String,
    pub custody_producer: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub adapter_binary_kind: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_subtree_generation: u64,
    pub provider_subtree_reservation_evidence_sha256: String,
    pub boot_id_sha256: String,
    pub adapter_pid: u32,
    pub adapter_start_time_ticks: u64,
    pub adapter_executable_sha256: String,
    pub unified_cgroup_path: String,
    pub adapter_leaf_empty_proof_sha256: String,
    pub measured_exec_proof_sha256: String,
    pub launch_custody_sha256: String,
}

impl DirectOperationKernelLaunchCustodyV3 {
    pub fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationResult<()> {
        binding.validate()?;
        if self.schema != KERNEL_LAUNCH_CUSTODY_V3_SCHEMA
            || self.kernel_custody_kind != KERNEL_LAUNCH_CUSTODY_KIND_V3
            || self.custody_producer != KERNEL_LAUNCH_CUSTODY_PRODUCER_V3
            || self.provider_id != binding.stable_seed.provider_id
            || self.agent_id != binding.stable_seed.agent_id
            || self.adapter != adapter
            || !binding.authorized_adapter_set.authorizes(adapter)
            || self.adapter_binary_kind != adapter_binary_kind(adapter)
            || self.binding_sha256 != binding_sha256
            || binding.digest_sha256()? != self.binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || self.provider_subtree_generation == 0
            || !valid_nonzero_sha256(&self.provider_subtree_reservation_evidence_sha256)
            || !valid_nonzero_sha256(&self.boot_id_sha256)
            || self.adapter_pid == 0
            || self.adapter_start_time_ticks == 0
            || !valid_nonzero_sha256(&self.adapter_executable_sha256)
            || self.unified_cgroup_path != fixed_adapter_cgroup_path(&self.provider_id, adapter)?
            || !valid_nonzero_sha256(&self.adapter_leaf_empty_proof_sha256)
            || !valid_nonzero_sha256(&self.measured_exec_proof_sha256)
            || self.digest_sha256()? != self.launch_custody_sha256
        {
            return Err(invalid(
                "kernel launch custody does not match the direct operation binding",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        if self.schema != KERNEL_LAUNCH_CUSTODY_V3_SCHEMA
            || self.kernel_custody_kind != KERNEL_LAUNCH_CUSTODY_KIND_V3
            || self.custody_producer != KERNEL_LAUNCH_CUSTODY_PRODUCER_V3
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || self.adapter_binary_kind != adapter_binary_kind(self.adapter)
            || !valid_sha256(&self.binding_sha256)
            || !valid_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || self.provider_subtree_generation == 0
            || !valid_nonzero_sha256(&self.provider_subtree_reservation_evidence_sha256)
            || !valid_nonzero_sha256(&self.boot_id_sha256)
            || self.adapter_pid == 0
            || self.adapter_start_time_ticks == 0
            || !valid_nonzero_sha256(&self.adapter_executable_sha256)
            || self.unified_cgroup_path
                != fixed_adapter_cgroup_path(&self.provider_id, self.adapter)?
            || !valid_nonzero_sha256(&self.adapter_leaf_empty_proof_sha256)
            || !valid_nonzero_sha256(&self.measured_exec_proof_sha256)
        {
            return Err(invalid("kernel launch custody field is malformed"));
        }
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-kernel-launch-custody-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(
            &mut hasher,
            b"kernel_custody_kind",
            &self.kernel_custody_kind,
        );
        hash_string_field(&mut hasher, b"custody_producer", &self.custody_producer);
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(
            &mut hasher,
            b"adapter_binary_kind",
            &self.adapter_binary_kind,
        );
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_bytes_field(
            &mut hasher,
            b"provider_subtree_generation",
            &self.provider_subtree_generation.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"provider_subtree_reservation_evidence_sha256",
            &self.provider_subtree_reservation_evidence_sha256,
        );
        hash_string_field(&mut hasher, b"boot_id_sha256", &self.boot_id_sha256);
        hash_bytes_field(&mut hasher, b"adapter_pid", &self.adapter_pid.to_be_bytes());
        hash_bytes_field(
            &mut hasher,
            b"adapter_start_time_ticks",
            &self.adapter_start_time_ticks.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"adapter_executable_sha256",
            &self.adapter_executable_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"unified_cgroup_path",
            &self.unified_cgroup_path,
        );
        hash_string_field(
            &mut hasher,
            b"adapter_leaf_empty_proof_sha256",
            &self.adapter_leaf_empty_proof_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"measured_exec_proof_sha256",
            &self.measured_exec_proof_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// One typed request from an already launch-authenticated OS adapter to the
/// OS-owned logical-call allocator. The request is created only after the
/// semantic arguments have been parsed and canonicalized. It contains no
/// model-authored call identity and requests no particular token or ordinal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationUncorrelatedToolCallAllocationRequestV3 {
    pub schema: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub canonical_request_sha256: String,
    /// v1 intentionally carries no stable upstream logical-delivery identity.
    /// A production allocator must not interpret equal request bytes as either
    /// a retry or a new call; live activation requires a later schema with
    /// daemon-owned durable correlation.
    pub retry_correlation_authority: String,
    pub request_sha256: String,
}

impl DirectOperationUncorrelatedToolCallAllocationRequestV3 {
    pub fn derive(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        canonical_request_sha256: String,
    ) -> DirectOperationResult<Self> {
        binding.validate()?;
        if binding.digest_sha256()? != binding_sha256
            || !binding.authorized_adapter_set.authorizes(adapter)
            || !valid_nonzero_sha256(&canonical_request_sha256)
        {
            return Err(invalid(
                "tool-call allocation request input does not match the direct operation binding",
            ));
        }
        let mut request = Self {
            schema: TOOL_CALL_UNCORRELATED_ALLOCATION_REQUEST_V3_SCHEMA.to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            canonical_request_sha256,
            retry_correlation_authority: TOOL_CALL_RETRY_CORRELATION_ABSENT_PRODUCT_HOLD
                .to_string(),
            request_sha256: String::new(),
        };
        request.request_sha256 = request.digest_sha256()?;
        Ok(request)
    }

    pub fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationResult<()> {
        binding.validate()?;
        if self.schema != TOOL_CALL_UNCORRELATED_ALLOCATION_REQUEST_V3_SCHEMA
            || self.binding_sha256 != binding_sha256
            || binding.digest_sha256()? != self.binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || self.provider_id != binding.stable_seed.provider_id
            || self.agent_id != binding.stable_seed.agent_id
            || self.adapter != adapter
            || !binding.authorized_adapter_set.authorizes(adapter)
            || !valid_nonzero_sha256(&self.canonical_request_sha256)
            || self.retry_correlation_authority != TOOL_CALL_RETRY_CORRELATION_ABSENT_PRODUCT_HOLD
            || self.digest_sha256()? != self.request_sha256
        {
            return Err(invalid(
                "tool-call allocation request does not match the direct operation binding",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        if self.schema != TOOL_CALL_UNCORRELATED_ALLOCATION_REQUEST_V3_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || !valid_nonzero_sha256(&self.canonical_request_sha256)
            || self.retry_correlation_authority != TOOL_CALL_RETRY_CORRELATION_ABSENT_PRODUCT_HOLD
        {
            return Err(invalid("tool-call allocation request field is malformed"));
        }
        let mut hasher = domain_hasher(
            b"trillionnium.direct-operation-tool-call-uncorrelated-allocation-request-digest.v3",
        );
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(
            &mut hasher,
            b"canonical_request_sha256",
            &self.canonical_request_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"retry_correlation_authority",
            &self.retry_correlation_authority,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// A daemon-issued logical-delivery identity published before one provider
/// tool-call delivery enters an adapter transport. This value is not an
/// authorization bearer by itself: a live route must carry it through a
/// root-authenticated handoff that the Agent/model cannot write or select.
/// The token and ordinal are allocated durably by the OS and therefore remain
/// stable across an exact crash retry while equal canonical content delivered
/// under a new token remains a distinct logical call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationToolCallDeliveryV3 {
    pub schema: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub delivery_sha256: String,
}

impl DirectOperationToolCallDeliveryV3 {
    pub fn derive(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        os_tool_call_id: String,
        adapter_effect_ordinal: u64,
    ) -> DirectOperationResult<Self> {
        binding.validate()?;
        if binding.digest_sha256()? != binding_sha256
            || !binding.authorized_adapter_set.authorizes(adapter)
            || !valid_nonzero_prefixed_sha256(&os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || adapter_effect_ordinal >= MAX_OUTER_ACK_EVIDENCE as u64
        {
            return Err(invalid(
                "tool-call delivery input does not match the direct operation binding",
            ));
        }
        let mut delivery = Self {
            schema: TOOL_CALL_DELIVERY_V3_SCHEMA.to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            os_tool_call_id,
            adapter_effect_ordinal,
            delivery_sha256: String::new(),
        };
        delivery.delivery_sha256 = delivery.digest_sha256()?;
        Ok(delivery)
    }

    pub fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationResult<()> {
        binding.validate()?;
        if self.schema != TOOL_CALL_DELIVERY_V3_SCHEMA
            || self.binding_sha256 != binding_sha256
            || binding.digest_sha256()? != self.binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || self.provider_id != binding.stable_seed.provider_id
            || self.agent_id != binding.stable_seed.agent_id
            || self.adapter != adapter
            || !binding.authorized_adapter_set.authorizes(adapter)
            || !valid_nonzero_prefixed_sha256(&self.os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || self.adapter_effect_ordinal >= MAX_OUTER_ACK_EVIDENCE as u64
            || self.digest_sha256()? != self.delivery_sha256
        {
            return Err(invalid(
                "tool-call delivery does not match the direct operation binding",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        if self.schema != TOOL_CALL_DELIVERY_V3_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || !valid_nonzero_prefixed_sha256(&self.os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || self.adapter_effect_ordinal >= MAX_OUTER_ACK_EVIDENCE as u64
        {
            return Err(invalid("tool-call delivery field is malformed"));
        }
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-tool-call-delivery-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(&mut hasher, b"os_tool_call_id", &self.os_tool_call_id);
        hash_bytes_field(
            &mut hasher,
            b"adapter_effect_ordinal",
            &self.adapter_effect_ordinal.to_be_bytes(),
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Allocation request for a daemon-issued logical delivery. Unlike v1, this
/// contract carries stable OS retry correlation. It must be received over an
/// authenticated OS transport together with the exact delivery envelope; a
/// model/provider call ID or equal canonical bytes are never sufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationToolCallAllocationRequestV3 {
    pub schema: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub delivery_sha256: String,
    pub canonical_request_sha256: String,
    pub retry_correlation_authority: String,
    pub request_sha256: String,
}

impl DirectOperationToolCallAllocationRequestV3 {
    pub fn derive(
        delivery: &DirectOperationToolCallDeliveryV3,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        canonical_request_sha256: String,
    ) -> DirectOperationResult<Self> {
        delivery.validate_for(binding, binding_sha256, adapter)?;
        if !valid_nonzero_sha256(&canonical_request_sha256) {
            return Err(invalid(
                "tool-call allocation request canonical digest is malformed",
            ));
        }
        let mut request = Self {
            schema: TOOL_CALL_ALLOCATION_REQUEST_V3_SCHEMA.to_string(),
            binding_sha256: delivery.binding_sha256.clone(),
            invocation_id: delivery.invocation_id.clone(),
            delivery_provider_attempt_id: delivery.delivery_provider_attempt_id.clone(),
            provider_id: delivery.provider_id.clone(),
            agent_id: delivery.agent_id.clone(),
            adapter: delivery.adapter,
            os_tool_call_id: delivery.os_tool_call_id.clone(),
            adapter_effect_ordinal: delivery.adapter_effect_ordinal,
            delivery_sha256: delivery.delivery_sha256.clone(),
            canonical_request_sha256,
            retry_correlation_authority: TOOL_CALL_RETRY_CORRELATION_DAEMON_DELIVERY_V3.to_string(),
            request_sha256: String::new(),
        };
        request.request_sha256 = request.digest_sha256()?;
        Ok(request)
    }

    pub fn validate_for(
        &self,
        delivery: &DirectOperationToolCallDeliveryV3,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationResult<()> {
        delivery.validate_for(binding, binding_sha256, adapter)?;
        if self.schema != TOOL_CALL_ALLOCATION_REQUEST_V3_SCHEMA
            || self.binding_sha256 != delivery.binding_sha256
            || self.invocation_id != delivery.invocation_id
            || self.delivery_provider_attempt_id != delivery.delivery_provider_attempt_id
            || self.provider_id != delivery.provider_id
            || self.agent_id != delivery.agent_id
            || self.adapter != delivery.adapter
            || self.os_tool_call_id != delivery.os_tool_call_id
            || self.adapter_effect_ordinal != delivery.adapter_effect_ordinal
            || self.delivery_sha256 != delivery.delivery_sha256
            || !valid_nonzero_sha256(&self.canonical_request_sha256)
            || self.retry_correlation_authority != TOOL_CALL_RETRY_CORRELATION_DAEMON_DELIVERY_V3
            || self.digest_sha256()? != self.request_sha256
        {
            return Err(invalid(
                "tool-call allocation request does not match the daemon delivery",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        if self.schema != TOOL_CALL_ALLOCATION_REQUEST_V3_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || !valid_nonzero_prefixed_sha256(&self.os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || self.adapter_effect_ordinal >= MAX_OUTER_ACK_EVIDENCE as u64
            || !valid_nonzero_sha256(&self.delivery_sha256)
            || !valid_nonzero_sha256(&self.canonical_request_sha256)
            || self.retry_correlation_authority != TOOL_CALL_RETRY_CORRELATION_DAEMON_DELIVERY_V3
        {
            return Err(invalid(
                "tool-call allocation request v3 field is malformed",
            ));
        }
        let embedded_delivery = DirectOperationToolCallDeliveryV3 {
            schema: TOOL_CALL_DELIVERY_V3_SCHEMA.to_string(),
            binding_sha256: self.binding_sha256.clone(),
            invocation_id: self.invocation_id.clone(),
            delivery_provider_attempt_id: self.delivery_provider_attempt_id.clone(),
            provider_id: self.provider_id.clone(),
            agent_id: self.agent_id.clone(),
            adapter: self.adapter,
            os_tool_call_id: self.os_tool_call_id.clone(),
            adapter_effect_ordinal: self.adapter_effect_ordinal,
            delivery_sha256: self.delivery_sha256.clone(),
        };
        if embedded_delivery.digest_sha256()? != self.delivery_sha256 {
            return Err(invalid(
                "tool-call allocation request v3 embedded delivery digest does not match",
            ));
        }
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-tool-call-allocation-request-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(&mut hasher, b"os_tool_call_id", &self.os_tool_call_id);
        hash_bytes_field(
            &mut hasher,
            b"adapter_effect_ordinal",
            &self.adapter_effect_ordinal.to_be_bytes(),
        );
        hash_string_field(&mut hasher, b"delivery_sha256", &self.delivery_sha256);
        hash_string_field(
            &mut hasher,
            b"canonical_request_sha256",
            &self.canonical_request_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"retry_correlation_authority",
            &self.retry_correlation_authority,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// One root-authored logical tool-call allocation returned by the OS-owned
/// allocator for exactly one canonicalized request. Canonical request content
/// is represented only by its digest; the OS token and ordinal, not that
/// digest, distinguish a retry from a deliberate repeated action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationToolCallEnvelopeV3 {
    pub schema: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub canonical_request_sha256: String,
    pub envelope_sha256: String,
}

impl DirectOperationToolCallEnvelopeV3 {
    /// Validate the root-authored allocation against the already frozen
    /// invocation/attempt/adapter binding. This is a per-logical-call check
    /// after canonicalization, not launch admission.
    pub fn validate_for_binding(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationResult<()> {
        binding.validate()?;
        if self.schema != TOOL_CALL_ENVELOPE_V3_SCHEMA
            || self.binding_sha256 != binding_sha256
            || binding.digest_sha256()? != self.binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || self.provider_id != binding.stable_seed.provider_id
            || self.agent_id != binding.stable_seed.agent_id
            || self.adapter != adapter
            || !binding.authorized_adapter_set.authorizes(adapter)
            || !valid_nonzero_prefixed_sha256(&self.os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || self.adapter_effect_ordinal >= MAX_OUTER_ACK_EVIDENCE as u64
            || !valid_nonzero_sha256(&self.canonical_request_sha256)
            || self.digest_sha256()? != self.envelope_sha256
        {
            return Err(invalid(
                "OS tool-call envelope does not match the direct operation binding",
            ));
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        canonical_request_sha256: &str,
    ) -> DirectOperationResult<()> {
        self.validate_for_binding(binding, binding_sha256, adapter)?;
        if self.canonical_request_sha256 != canonical_request_sha256 {
            return Err(invalid(
                "OS tool-call envelope does not match the direct operation call",
            ));
        }
        Ok(())
    }

    pub fn validate_for_allocation_request(
        &self,
        request: &DirectOperationUncorrelatedToolCallAllocationRequestV3,
    ) -> DirectOperationResult<()> {
        if request.digest_sha256()? != request.request_sha256
            || self.binding_sha256 != request.binding_sha256
            || self.invocation_id != request.invocation_id
            || self.delivery_provider_attempt_id != request.delivery_provider_attempt_id
            || self.provider_id != request.provider_id
            || self.agent_id != request.agent_id
            || self.adapter != request.adapter
            || self.canonical_request_sha256 != request.canonical_request_sha256
            || self.digest_sha256()? != self.envelope_sha256
        {
            return Err(invalid(
                "OS tool-call envelope does not match the allocation request",
            ));
        }
        Ok(())
    }

    pub fn validate_for_allocation_request_v3(
        &self,
        request: &DirectOperationToolCallAllocationRequestV3,
    ) -> DirectOperationResult<()> {
        if request.digest_sha256()? != request.request_sha256
            || self.binding_sha256 != request.binding_sha256
            || self.invocation_id != request.invocation_id
            || self.delivery_provider_attempt_id != request.delivery_provider_attempt_id
            || self.provider_id != request.provider_id
            || self.agent_id != request.agent_id
            || self.adapter != request.adapter
            || self.os_tool_call_id != request.os_tool_call_id
            || self.adapter_effect_ordinal != request.adapter_effect_ordinal
            || self.canonical_request_sha256 != request.canonical_request_sha256
            || self.digest_sha256()? != self.envelope_sha256
        {
            return Err(invalid(
                "OS tool-call envelope does not match the daemon-correlated allocation request",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        if self.schema != TOOL_CALL_ENVELOPE_V3_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || !valid_nonzero_prefixed_sha256(&self.os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || self.adapter_effect_ordinal >= MAX_OUTER_ACK_EVIDENCE as u64
            || !valid_nonzero_sha256(&self.canonical_request_sha256)
        {
            return Err(invalid("OS tool-call envelope field is malformed"));
        }
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-tool-call-envelope-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(&mut hasher, b"os_tool_call_id", &self.os_tool_call_id);
        hash_bytes_field(
            &mut hasher,
            b"adapter_effect_ordinal",
            &self.adapter_effect_ordinal.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"canonical_request_sha256",
            &self.canonical_request_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Adapter-to-daemon acknowledgement emitted only after the exact allocated
/// logical call is durably present as PREPARED in the adapter operation
/// journal. The acknowledgement binds the journal epoch and payload to its
/// stable external first-use lineage. Every restart separately requires a
/// current replay/high-water decision, but reproduces the same unresolved ACK.
/// This remains a transport/storage value, not an authority constructor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationToolCallPreparedAckV3 {
    pub schema: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub canonical_request_sha256: String,
    pub envelope_sha256: String,
    pub journal_epoch: String,
    pub journal_sequence: u64,
    pub backend_request_id_sha256: String,
    pub journal_payload_sha256: String,
    pub operation_epoch_authority_sha256: String,
    pub prepared_ack_sha256: String,
}

impl DirectOperationToolCallPreparedAckV3 {
    pub fn derive(
        envelope: &DirectOperationToolCallEnvelopeV3,
        journal_epoch: String,
        journal_sequence: u64,
        backend_request_id_sha256: String,
        journal_payload_sha256: String,
        operation_epoch_authority_sha256: String,
    ) -> DirectOperationResult<Self> {
        envelope.digest_sha256()?;
        let mut acknowledgement = Self {
            schema: TOOL_CALL_PREPARED_ACK_V3_SCHEMA.to_string(),
            binding_sha256: envelope.binding_sha256.clone(),
            invocation_id: envelope.invocation_id.clone(),
            delivery_provider_attempt_id: envelope.delivery_provider_attempt_id.clone(),
            provider_id: envelope.provider_id.clone(),
            agent_id: envelope.agent_id.clone(),
            adapter: envelope.adapter,
            os_tool_call_id: envelope.os_tool_call_id.clone(),
            adapter_effect_ordinal: envelope.adapter_effect_ordinal,
            canonical_request_sha256: envelope.canonical_request_sha256.clone(),
            envelope_sha256: envelope.envelope_sha256.clone(),
            journal_epoch,
            journal_sequence,
            backend_request_id_sha256,
            journal_payload_sha256,
            operation_epoch_authority_sha256,
            prepared_ack_sha256: String::new(),
        };
        acknowledgement.prepared_ack_sha256 = acknowledgement.digest_sha256()?;
        acknowledgement.validate_for_envelope(envelope)?;
        Ok(acknowledgement)
    }

    pub fn validate_for_envelope(
        &self,
        envelope: &DirectOperationToolCallEnvelopeV3,
    ) -> DirectOperationResult<()> {
        envelope.digest_sha256()?;
        if self.schema != TOOL_CALL_PREPARED_ACK_V3_SCHEMA
            || self.binding_sha256 != envelope.binding_sha256
            || self.invocation_id != envelope.invocation_id
            || self.delivery_provider_attempt_id != envelope.delivery_provider_attempt_id
            || self.provider_id != envelope.provider_id
            || self.agent_id != envelope.agent_id
            || self.adapter != envelope.adapter
            || self.os_tool_call_id != envelope.os_tool_call_id
            || self.adapter_effect_ordinal != envelope.adapter_effect_ordinal
            || self.canonical_request_sha256 != envelope.canonical_request_sha256
            || self.envelope_sha256 != envelope.envelope_sha256
            || self.digest_sha256()? != self.prepared_ack_sha256
        {
            return Err(invalid(
                "tool-call PREPARED acknowledgement does not match the allocated envelope",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        if self.schema != TOOL_CALL_PREPARED_ACK_V3_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || !valid_nonzero_prefixed_sha256(&self.os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || self.adapter_effect_ordinal >= MAX_OUTER_ACK_EVIDENCE as u64
            || !valid_nonzero_sha256(&self.canonical_request_sha256)
            || !valid_nonzero_sha256(&self.envelope_sha256)
            || !valid_journal_epoch(&self.journal_epoch)
            || self.journal_sequence == 0
            || self.journal_sequence > MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE
            || !valid_nonzero_sha256(&self.backend_request_id_sha256)
            || !valid_nonzero_sha256(&self.journal_payload_sha256)
            || !valid_nonzero_sha256(&self.operation_epoch_authority_sha256)
        {
            return Err(invalid(
                "tool-call PREPARED acknowledgement field is malformed",
            ));
        }
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-tool-call-prepared-ack-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(&mut hasher, b"os_tool_call_id", &self.os_tool_call_id);
        hash_bytes_field(
            &mut hasher,
            b"adapter_effect_ordinal",
            &self.adapter_effect_ordinal.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"canonical_request_sha256",
            &self.canonical_request_sha256,
        );
        hash_string_field(&mut hasher, b"envelope_sha256", &self.envelope_sha256);
        hash_string_field(&mut hasher, b"journal_epoch", &self.journal_epoch);
        hash_bytes_field(
            &mut hasher,
            b"journal_sequence",
            &self.journal_sequence.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"backend_request_id_sha256",
            &self.backend_request_id_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"journal_payload_sha256",
            &self.journal_payload_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"operation_epoch_authority_sha256",
            &self.operation_epoch_authority_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Daemon-to-adapter receipt returned only after the allocator's PREPARED ACK
/// transition and parent-directory fsync complete. The record digest and
/// generation make an exact retry deterministic without claiming that the
/// daemon-local store is rollback resistant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationToolCallCommitReceiptV3 {
    pub schema: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub adapter: DirectOperationAdapter,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub envelope_sha256: String,
    pub prepared_ack_sha256: String,
    pub allocator_generation: u64,
    pub allocation_record_sha256: String,
    pub commit_receipt_sha256: String,
}

impl DirectOperationToolCallCommitReceiptV3 {
    pub fn derive(
        acknowledgement: &DirectOperationToolCallPreparedAckV3,
        allocator_generation: u64,
        allocation_record_sha256: String,
    ) -> DirectOperationResult<Self> {
        acknowledgement.digest_sha256()?;
        let mut receipt = Self {
            schema: TOOL_CALL_COMMIT_RECEIPT_V3_SCHEMA.to_string(),
            binding_sha256: acknowledgement.binding_sha256.clone(),
            invocation_id: acknowledgement.invocation_id.clone(),
            adapter: acknowledgement.adapter,
            os_tool_call_id: acknowledgement.os_tool_call_id.clone(),
            adapter_effect_ordinal: acknowledgement.adapter_effect_ordinal,
            envelope_sha256: acknowledgement.envelope_sha256.clone(),
            prepared_ack_sha256: acknowledgement.prepared_ack_sha256.clone(),
            allocator_generation,
            allocation_record_sha256,
            commit_receipt_sha256: String::new(),
        };
        receipt.commit_receipt_sha256 = receipt.digest_sha256()?;
        receipt.validate_for_acknowledgement(acknowledgement)?;
        Ok(receipt)
    }

    pub fn validate_for_acknowledgement(
        &self,
        acknowledgement: &DirectOperationToolCallPreparedAckV3,
    ) -> DirectOperationResult<()> {
        acknowledgement.digest_sha256()?;
        if self.schema != TOOL_CALL_COMMIT_RECEIPT_V3_SCHEMA
            || self.binding_sha256 != acknowledgement.binding_sha256
            || self.invocation_id != acknowledgement.invocation_id
            || self.adapter != acknowledgement.adapter
            || self.os_tool_call_id != acknowledgement.os_tool_call_id
            || self.adapter_effect_ordinal != acknowledgement.adapter_effect_ordinal
            || self.envelope_sha256 != acknowledgement.envelope_sha256
            || self.prepared_ack_sha256 != acknowledgement.prepared_ack_sha256
            || self.digest_sha256()? != self.commit_receipt_sha256
        {
            return Err(invalid(
                "tool-call commit receipt does not match the PREPARED acknowledgement",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        if self.schema != TOOL_CALL_COMMIT_RECEIPT_V3_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(&self.os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || self.adapter_effect_ordinal >= MAX_OUTER_ACK_EVIDENCE as u64
            || !valid_nonzero_sha256(&self.envelope_sha256)
            || !valid_nonzero_sha256(&self.prepared_ack_sha256)
            || self.allocator_generation == 0
            || !valid_nonzero_sha256(&self.allocation_record_sha256)
        {
            return Err(invalid("tool-call commit receipt field is malformed"));
        }
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-tool-call-commit-receipt-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(&mut hasher, b"os_tool_call_id", &self.os_tool_call_id);
        hash_bytes_field(
            &mut hasher,
            b"adapter_effect_ordinal",
            &self.adapter_effect_ordinal.to_be_bytes(),
        );
        hash_string_field(&mut hasher, b"envelope_sha256", &self.envelope_sha256);
        hash_string_field(
            &mut hasher,
            b"prepared_ack_sha256",
            &self.prepared_ack_sha256,
        );
        hash_bytes_field(
            &mut hasher,
            b"allocator_generation",
            &self.allocator_generation.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"allocation_record_sha256",
            &self.allocation_record_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[must_use]
pub const fn adapter_binary_kind(adapter: DirectOperationAdapter) -> &'static str {
    match adapter {
        DirectOperationAdapter::SystemApi => "trillionnium-agent-system-api",
        DirectOperationAdapter::Accessibility => "trillionnium-agent-accessibility",
    }
}

pub fn fixed_provider_cgroup_subtree(provider_id: &str) -> DirectOperationResult<&'static str> {
    if provider_id == crate::agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id {
        Ok(CODEX_PROVIDER_CGROUP_SUBTREE)
    } else {
        Err(invalid("provider has no fixed cgroup subtree"))
    }
}

pub fn fixed_provider_cgroup_leaf_path(
    provider_id: &str,
    role: ProviderCgroupChildRoleV2,
) -> DirectOperationResult<String> {
    Ok(format!(
        "{}/{}",
        fixed_provider_cgroup_subtree(provider_id)?,
        role.directory_name()
    ))
}

pub fn fixed_provider_runtime_cgroup_path(provider_id: &str) -> DirectOperationResult<String> {
    fixed_provider_cgroup_leaf_path(provider_id, ProviderCgroupChildRoleV2::Runtime)
}

pub fn fixed_adapter_cgroup_path(
    provider_id: &str,
    adapter: DirectOperationAdapter,
) -> DirectOperationResult<String> {
    let role = match adapter {
        DirectOperationAdapter::SystemApi => ProviderCgroupChildRoleV2::SystemApi,
        DirectOperationAdapter::Accessibility => ProviderCgroupChildRoleV2::Accessibility,
    };
    fixed_provider_cgroup_leaf_path(provider_id, role)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationOuterOutcome {
    Success,
    BackendError,
    Indeterminate,
}

impl DirectOperationOuterOutcome {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Success => b"success",
            Self::BackendError => b"backend_error",
            Self::Indeterminate => b"indeterminate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationOuterEvidence {
    /// Attempt that originally allocated this durable operation identity.
    pub allocating_provider_attempt_id: String,
    /// Durable unique-canonical ordinal within this one adapter journal. It is
    /// not a provider-global call or effect ordinal.
    pub adapter_effect_ordinal: u64,
    /// Global sequence within this one durable adapter journal. It is not a
    /// provider-global call or effect ordinal.
    pub journal_sequence: u64,
    pub tool: String,
    pub canonical_request_sha256: String,
    pub backend_request_id_sha256: String,
    pub backend_result_sha256: String,
    pub outcome: DirectOperationOuterOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_error_code: Option<String>,
}

impl DirectOperationOuterEvidence {
    /// Validate one evidence item against its adapter profile.
    ///
    /// The journal snapshot validator uses the same check internally.  The
    /// allocator-to-Android ACK/replay handoff needs to validate one already
    /// selected item without fabricating a complete snapshot, so expose this
    /// exact structural check as a read-only wrapper.  It does not authorize
    /// an effect or establish rollback/high-water authority.
    pub fn validate_for_adapter(
        &self,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationResult<()> {
        self.validate_for(adapter)
    }

    fn validate_for(&self, adapter: DirectOperationAdapter) -> DirectOperationResult<()> {
        if self.journal_sequence == 0
            || self.journal_sequence > MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE
            || !valid_prefixed_sha256(
                &self.allocating_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || self.tool != adapter.tool_name()
            || !valid_sha256(&self.canonical_request_sha256)
            || !valid_sha256(&self.backend_request_id_sha256)
            || !valid_sha256(&self.backend_result_sha256)
        {
            return Err(invalid("outer evidence digest or tool is malformed"));
        }
        match (self.outcome, self.backend_error_code.as_deref()) {
            (DirectOperationOuterOutcome::Success, None) => Ok(()),
            (
                DirectOperationOuterOutcome::BackendError
                | DirectOperationOuterOutcome::Indeterminate,
                Some(code),
            ) if valid_error_code(code) => Ok(()),
            _ => Err(invalid("outer evidence outcome contradicts its error code")),
        }
    }
}

/// Adapter-private, digest-only export of one complete durable operation
/// journal allocation. This is a data contract, not proof that the named file
/// was securely opened or that an outer receipt is durable. A future trusted
/// adapter handoff must authenticate the source before a daemon may rely on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationJournalEvidenceSnapshotV1 {
    pub schema: String,
    /// Digest of the exact binding whose attempt allocated every item.
    pub allocation_binding_sha256: String,
    pub invocation_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub allocating_provider_attempt_id: String,
    pub adapter: DirectOperationAdapter,
    /// Exact 128-bit lower-hex adapter journal epoch. It is OS-generated
    /// identity, not model input and not wall-clock time.
    pub journal_epoch: String,
    /// Digest of the complete canonical durable journal payload from which
    /// this closed snapshot was exported. The payload itself is never carried.
    pub journal_payload_sha256: String,
    /// Exact durable backend replay baseline observed before this allocation.
    /// Watermark zero is paired only with the all-zero genesis chain.
    pub previous_ack_watermark: u64,
    pub previous_ack_chain_sha256: String,
    pub journal_allocation_count: u32,
    pub journal_evidence_count: u32,
    pub first_journal_sequence: u64,
    pub last_journal_sequence: u64,
    pub evidence: Vec<DirectOperationOuterEvidence>,
    pub evidence_sha256: String,
}

impl DirectOperationJournalEvidenceSnapshotV1 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA
            || !valid_nonzero_sha256(&self.allocation_binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || !valid_nonzero_prefixed_sha256(
                &self.allocating_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_journal_epoch(&self.journal_epoch)
            || !valid_nonzero_sha256(&self.journal_payload_sha256)
            || self.previous_ack_watermark > MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE
            || !valid_sha256(&self.previous_ack_chain_sha256)
            || (self.previous_ack_watermark == 0 && self.previous_ack_chain_sha256 != ZERO_SHA256)
            || (self.previous_ack_watermark != 0
                && !valid_nonzero_sha256(&self.previous_ack_chain_sha256))
            || self.journal_allocation_count == 0
            || self.journal_evidence_count == 0
            || self.journal_allocation_count != self.journal_evidence_count
            || self.journal_evidence_count as usize != self.evidence.len()
            || self.evidence.len() > MAX_OUTER_ACK_EVIDENCE
            || self.first_journal_sequence == 0
            || self.last_journal_sequence > MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE
            || self.first_journal_sequence > self.last_journal_sequence
            || !valid_nonzero_sha256(&self.evidence_sha256)
        {
            return Err(invalid("journal evidence snapshot header is malformed"));
        }

        let expected_span = self
            .last_journal_sequence
            .checked_sub(self.first_journal_sequence)
            .and_then(|span| span.checked_add(1))
            .ok_or_else(|| invalid("journal evidence sequence span is malformed"))?;
        if expected_span != u64::from(self.journal_evidence_count) {
            return Err(invalid(
                "journal evidence count does not cover the exact sequence span",
            ));
        }
        if self.previous_ack_watermark.checked_add(1) != Some(self.first_journal_sequence) {
            return Err(invalid(
                "journal evidence does not continue the durable ACK watermark",
            ));
        }

        for (index, item) in self.evidence.iter().enumerate() {
            validate_outer_evidence_v3(item, self.adapter)?;
            let index =
                u64::try_from(index).map_err(|_| invalid("journal evidence index is oversized"))?;
            let expected_sequence = self
                .first_journal_sequence
                .checked_add(index)
                .ok_or_else(|| invalid("journal evidence sequence overflows"))?;
            if item.allocating_provider_attempt_id != self.allocating_provider_attempt_id
                || item.adapter_effect_ordinal != index
                || item.journal_sequence != expected_sequence
            {
                return Err(invalid(
                    "journal evidence allocation, ordinal, or sequence is not exact",
                ));
            }
        }
        if self.evidence_digest_sha256()? != self.evidence_sha256 {
            return Err(invalid("journal evidence set digest does not match"));
        }
        Ok(())
    }

    pub fn validate_for_allocation_binding(
        &self,
        allocation_binding: &DirectOperationBinding,
        expected_adapter: DirectOperationAdapter,
    ) -> DirectOperationResult<()> {
        self.validate()?;
        allocation_binding.validate()?;
        if self.allocation_binding_sha256 != allocation_binding.digest_sha256()?
            || self.invocation_id != allocation_binding.invocation_id
            || self.provider_id != allocation_binding.stable_seed.provider_id
            || self.agent_id != allocation_binding.stable_seed.agent_id
            || self.allocating_provider_attempt_id
                != allocation_binding.attempt.delivery_provider_attempt_id
            || self.adapter != expected_adapter
        {
            return Err(invalid(
                "journal evidence snapshot does not match the allocation binding",
            ));
        }
        Ok(())
    }

    pub fn evidence_digest_sha256(&self) -> DirectOperationResult<String> {
        journal_evidence_digest_sha256(self.adapter, &self.evidence)
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate()?;
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-journal-evidence-snapshot-digest.v1");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(
            &mut hasher,
            b"allocation_binding_sha256",
            &self.allocation_binding_sha256,
        );
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(
            &mut hasher,
            b"allocating_provider_attempt_id",
            &self.allocating_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(&mut hasher, b"journal_epoch", &self.journal_epoch);
        hash_string_field(
            &mut hasher,
            b"journal_payload_sha256",
            &self.journal_payload_sha256,
        );
        hash_bytes_field(
            &mut hasher,
            b"previous_ack_watermark",
            &self.previous_ack_watermark.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"previous_ack_chain_sha256",
            &self.previous_ack_chain_sha256,
        );
        hash_bytes_field(
            &mut hasher,
            b"journal_allocation_count",
            &self.journal_allocation_count.to_be_bytes(),
        );
        hash_bytes_field(
            &mut hasher,
            b"journal_evidence_count",
            &self.journal_evidence_count.to_be_bytes(),
        );
        hash_bytes_field(
            &mut hasher,
            b"first_journal_sequence",
            &self.first_journal_sequence.to_be_bytes(),
        );
        hash_bytes_field(
            &mut hasher,
            b"last_journal_sequence",
            &self.last_journal_sequence.to_be_bytes(),
        );
        hash_string_field(&mut hasher, b"evidence_sha256", &self.evidence_sha256);
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Exact terminal state of one adapter for one daemon delivery binding. The
/// authenticated terminal/hold digests are produced by a future trusted
/// adapter handoff; this type only closes and hashes their data shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "disposition", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectOperationAdapterTerminalStateV1 {
    Ackable {
        journal_evidence_snapshot: DirectOperationJournalEvidenceSnapshotV1,
    },
    NoOperations {
        journal_epoch: String,
        journal_payload_sha256: String,
        previous_ack_watermark: u64,
        previous_ack_chain_sha256: String,
        authenticated_terminal_sha256: String,
    },
    HeldIndeterminate {
        journal_epoch: String,
        journal_payload_sha256: String,
        previous_ack_watermark: u64,
        previous_ack_chain_sha256: String,
        authenticated_hold_sha256: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationAdapterTerminalDispositionV1 {
    pub schema: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub terminal_state: DirectOperationAdapterTerminalStateV1,
}

impl DirectOperationAdapterTerminalDispositionV1 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
        {
            return Err(invalid("adapter terminal disposition header is malformed"));
        }
        match &self.terminal_state {
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot,
            } => {
                journal_evidence_snapshot.validate()?;
                if journal_evidence_snapshot.invocation_id != self.invocation_id
                    || journal_evidence_snapshot.provider_id != self.provider_id
                    || journal_evidence_snapshot.agent_id != self.agent_id
                    || journal_evidence_snapshot.adapter != self.adapter
                {
                    return Err(invalid(
                        "ackable disposition journal snapshot identity does not match",
                    ));
                }
            }
            DirectOperationAdapterTerminalStateV1::NoOperations {
                journal_epoch,
                journal_payload_sha256,
                previous_ack_watermark,
                previous_ack_chain_sha256,
                authenticated_terminal_sha256,
            } => {
                validate_terminal_journal_baseline(
                    journal_epoch,
                    journal_payload_sha256,
                    *previous_ack_watermark,
                    previous_ack_chain_sha256,
                )?;
                if !valid_nonzero_sha256(authenticated_terminal_sha256) {
                    return Err(invalid("no-operations terminal digest is malformed"));
                }
            }
            DirectOperationAdapterTerminalStateV1::HeldIndeterminate {
                journal_epoch,
                journal_payload_sha256,
                previous_ack_watermark,
                previous_ack_chain_sha256,
                authenticated_hold_sha256,
            } => {
                validate_terminal_journal_baseline(
                    journal_epoch,
                    journal_payload_sha256,
                    *previous_ack_watermark,
                    previous_ack_chain_sha256,
                )?;
                if !valid_nonzero_sha256(authenticated_hold_sha256) {
                    return Err(invalid("indeterminate hold digest is malformed"));
                }
            }
        }
        Ok(())
    }

    pub fn validate_for_binding(
        &self,
        delivery_binding: &DirectOperationBinding,
        expected_adapter: DirectOperationAdapter,
    ) -> DirectOperationResult<()> {
        self.validate()?;
        delivery_binding.validate()?;
        if self.binding_sha256 != delivery_binding.digest_sha256()?
            || self.invocation_id != delivery_binding.invocation_id
            || self.delivery_provider_attempt_id
                != delivery_binding.attempt.delivery_provider_attempt_id
            || self.provider_id != delivery_binding.stable_seed.provider_id
            || self.agent_id != delivery_binding.stable_seed.agent_id
            || self.adapter != expected_adapter
            || !delivery_binding
                .authorized_adapter_set
                .authorizes(expected_adapter)
        {
            return Err(invalid(
                "adapter terminal disposition does not match the delivery binding",
            ));
        }
        Ok(())
    }

    pub fn ackable_snapshot(
        &self,
    ) -> DirectOperationResult<&DirectOperationJournalEvidenceSnapshotV1> {
        self.validate()?;
        match &self.terminal_state {
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot,
            } => Ok(journal_evidence_snapshot),
            DirectOperationAdapterTerminalStateV1::NoOperations { .. }
            | DirectOperationAdapterTerminalStateV1::HeldIndeterminate { .. } => Err(invalid(
                "non-ackable adapter terminal disposition cannot produce an ACK",
            )),
        }
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate()?;
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-adapter-terminal-disposition-digest.v1");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        match &self.terminal_state {
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot,
            } => {
                hash_bytes_field(&mut hasher, b"disposition", b"ackable");
                hash_string_field(
                    &mut hasher,
                    b"journal_evidence_snapshot_sha256",
                    &journal_evidence_snapshot.digest_sha256()?,
                );
            }
            DirectOperationAdapterTerminalStateV1::NoOperations {
                journal_epoch,
                journal_payload_sha256,
                previous_ack_watermark,
                previous_ack_chain_sha256,
                authenticated_terminal_sha256,
            } => {
                hash_bytes_field(&mut hasher, b"disposition", b"no_operations");
                hash_terminal_journal_baseline(
                    &mut hasher,
                    journal_epoch,
                    journal_payload_sha256,
                    *previous_ack_watermark,
                    previous_ack_chain_sha256,
                );
                hash_string_field(
                    &mut hasher,
                    b"authenticated_terminal_sha256",
                    authenticated_terminal_sha256,
                );
            }
            DirectOperationAdapterTerminalStateV1::HeldIndeterminate {
                journal_epoch,
                journal_payload_sha256,
                previous_ack_watermark,
                previous_ack_chain_sha256,
                authenticated_hold_sha256,
            } => {
                hash_bytes_field(&mut hasher, b"disposition", b"held_indeterminate");
                hash_terminal_journal_baseline(
                    &mut hasher,
                    journal_epoch,
                    journal_payload_sha256,
                    *previous_ack_watermark,
                    previous_ack_chain_sha256,
                );
                hash_string_field(
                    &mut hasher,
                    b"authenticated_hold_sha256",
                    authenticated_hold_sha256,
                );
            }
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Daemon-owned preimage for a durable direct-execution outer receipt. Every
/// field is identity, a bounded count, or a digest. Possession or structural
/// validity of this value grants no authority and does not prove that provider
/// teardown, egress finalization, or UI replay publication actually occurred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationOuterReceiptV3 {
    pub schema: String,
    /// Digest of the current delivery binding. Allocation bindings remain
    /// explicit inside each adapter-private journal snapshot.
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub direct_execution_receipt_sha256: String,
    pub ui_replay_completion_proof_sha256: String,
    pub ui_replay_semantic_sha256: String,
    /// Domain-separated digest of the daemon's closed terminal egress-CAS
    /// snapshot (including exact binding/grant, Completed state, terminal
    /// record and predecessor, runtime evidence, and completion ACK). This is
    /// not a caller-supplied digest of one naked journal field.
    pub terminal_egress_cas_sha256: String,
    pub runtime_evidence_sha256: String,
    pub provider_teardown_completion_ack_sha256: String,
    /// Exact ordered adapter policy already bound into the delivery binding.
    pub authorized_adapter_set: DirectOperationAuthorizedAdapterSetV3,
    /// Exactly one disposition per authorized adapter, in policy order.
    pub adapter_terminal_dispositions: Vec<DirectOperationAdapterTerminalDispositionV1>,
    pub adapter_terminal_dispositions_sha256: String,
}

impl DirectOperationOuterReceiptV3 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        self.authorized_adapter_set.validate()?;
        if self.schema != OUTER_RECEIPT_V3_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || !valid_nonzero_sha256(&self.direct_execution_receipt_sha256)
            || !valid_nonzero_sha256(&self.ui_replay_completion_proof_sha256)
            || !valid_nonzero_sha256(&self.ui_replay_semantic_sha256)
            || !valid_nonzero_sha256(&self.terminal_egress_cas_sha256)
            || !valid_nonzero_sha256(&self.runtime_evidence_sha256)
            || !valid_nonzero_sha256(&self.provider_teardown_completion_ack_sha256)
            || self.adapter_terminal_dispositions.len()
                != self.authorized_adapter_set.authorized_adapters.len()
            || !valid_nonzero_sha256(&self.adapter_terminal_dispositions_sha256)
        {
            return Err(invalid("outer receipt v3 header is malformed"));
        }

        for (disposition, expected_adapter) in self
            .adapter_terminal_dispositions
            .iter()
            .zip(&self.authorized_adapter_set.authorized_adapters)
        {
            disposition.validate()?;
            if disposition.binding_sha256 != self.binding_sha256
                || disposition.invocation_id != self.invocation_id
                || disposition.delivery_provider_attempt_id != self.delivery_provider_attempt_id
                || disposition.provider_id != self.provider_id
                || disposition.agent_id != self.agent_id
                || disposition.adapter != *expected_adapter
            {
                return Err(invalid(
                    "outer receipt adapter disposition identity or ordering does not match",
                ));
            }
        }
        if self.adapter_dispositions_digest_sha256()? != self.adapter_terminal_dispositions_sha256 {
            return Err(invalid(
                "outer receipt adapter disposition digest does not match",
            ));
        }
        Ok(())
    }

    pub fn validate_for_binding(
        &self,
        delivery_binding: &DirectOperationBinding,
    ) -> DirectOperationResult<()> {
        self.validate()?;
        delivery_binding.validate()?;
        if self.binding_sha256 != delivery_binding.digest_sha256()?
            || self.invocation_id != delivery_binding.invocation_id
            || self.delivery_provider_attempt_id
                != delivery_binding.attempt.delivery_provider_attempt_id
            || self.provider_id != delivery_binding.stable_seed.provider_id
            || self.agent_id != delivery_binding.stable_seed.agent_id
            || self.authorized_adapter_set != delivery_binding.authorized_adapter_set
        {
            return Err(invalid(
                "outer receipt v3 does not match the delivery binding and adapter policy",
            ));
        }
        Ok(())
    }

    pub fn adapter_dispositions_digest_sha256(&self) -> DirectOperationResult<String> {
        self.authorized_adapter_set.validate()?;
        if self.adapter_terminal_dispositions.len()
            != self.authorized_adapter_set.authorized_adapters.len()
        {
            return Err(invalid(
                "outer receipt disposition count does not match authorized adapter policy",
            ));
        }
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-outer-receipt-adapter-dispositions.v3");
        hash_string_field(
            &mut hasher,
            b"authorized_adapter_set_sha256",
            &self.authorized_adapter_set.digest_sha256()?,
        );
        hash_bytes_field(
            &mut hasher,
            b"count",
            &(self.adapter_terminal_dispositions.len() as u64).to_be_bytes(),
        );
        for (disposition, expected_adapter) in self
            .adapter_terminal_dispositions
            .iter()
            .zip(&self.authorized_adapter_set.authorized_adapters)
        {
            disposition.validate()?;
            if disposition.adapter != *expected_adapter {
                return Err(invalid(
                    "outer receipt disposition ordering does not match authorized adapters",
                ));
            }
            hash_string_field(&mut hasher, b"adapter", disposition.adapter.adapter_id());
            hash_string_field(
                &mut hasher,
                b"adapter_terminal_disposition_sha256",
                &disposition.digest_sha256()?,
            );
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate()?;
        let mut hasher = domain_hasher(b"trillionnium.direct-operation-outer-receipt-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(
            &mut hasher,
            b"direct_execution_receipt_sha256",
            &self.direct_execution_receipt_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"ui_replay_completion_proof_sha256",
            &self.ui_replay_completion_proof_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"ui_replay_semantic_sha256",
            &self.ui_replay_semantic_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"terminal_egress_cas_sha256",
            &self.terminal_egress_cas_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"runtime_evidence_sha256",
            &self.runtime_evidence_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"provider_teardown_completion_ack_sha256",
            &self.provider_teardown_completion_ack_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"authorized_adapter_set_sha256",
            &self.authorized_adapter_set.digest_sha256()?,
        );
        hash_string_field(
            &mut hasher,
            b"adapter_terminal_dispositions_sha256",
            &self.adapter_terminal_dispositions_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Per-adapter outer acknowledgement v3. The acknowledgement binds an exact
/// daemon receipt and exact private journal snapshot, but remains inert data;
/// it cannot open a journal or reclaim a backend replay record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationOuterAckV3 {
    pub schema: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub authorized_adapter_set_sha256: String,
    pub outer_receipt_sha256: String,
    pub journal_evidence_snapshot: DirectOperationJournalEvidenceSnapshotV1,
    pub journal_evidence_snapshot_sha256: String,
}

impl DirectOperationOuterAckV3 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != OUTER_ACK_V3_SCHEMA
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_nonzero_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_nonzero_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_provider_agent_pair(&self.provider_id, &self.agent_id)
            || !valid_nonzero_sha256(&self.authorized_adapter_set_sha256)
            || !valid_nonzero_sha256(&self.outer_receipt_sha256)
            || !valid_nonzero_sha256(&self.journal_evidence_snapshot_sha256)
        {
            return Err(invalid("outer acknowledgement v3 header is malformed"));
        }
        self.journal_evidence_snapshot.validate()?;
        if self.journal_evidence_snapshot.invocation_id != self.invocation_id
            || self.journal_evidence_snapshot.provider_id != self.provider_id
            || self.journal_evidence_snapshot.agent_id != self.agent_id
            || self.journal_evidence_snapshot.adapter != self.adapter
            || self.journal_evidence_snapshot.digest_sha256()?
                != self.journal_evidence_snapshot_sha256
        {
            return Err(invalid(
                "outer acknowledgement v3 journal snapshot does not match",
            ));
        }
        Ok(())
    }

    pub fn validate_for_outer_receipt(
        &self,
        receipt: &DirectOperationOuterReceiptV3,
    ) -> DirectOperationResult<()> {
        self.validate()?;
        receipt.validate()?;
        if !receipt.authorized_adapter_set.authorizes(self.adapter) {
            return Err(invalid(
                "outer acknowledgement adapter is not authorized by the receipt",
            ));
        }
        let receipt_disposition = receipt
            .adapter_terminal_dispositions
            .iter()
            .find(|disposition| disposition.adapter == self.adapter)
            .ok_or_else(|| invalid("outer receipt omits acknowledged adapter disposition"))?;
        let receipt_snapshot = receipt_disposition.ackable_snapshot()?;
        if self.outer_receipt_sha256 != receipt.digest_sha256()?
            || self.binding_sha256 != receipt.binding_sha256
            || self.invocation_id != receipt.invocation_id
            || self.delivery_provider_attempt_id != receipt.delivery_provider_attempt_id
            || self.provider_id != receipt.provider_id
            || self.agent_id != receipt.agent_id
            || self.authorized_adapter_set_sha256
                != receipt.authorized_adapter_set.digest_sha256()?
            || receipt_snapshot != &self.journal_evidence_snapshot
        {
            return Err(invalid(
                "outer acknowledgement v3 does not match the durable outer receipt",
            ));
        }
        Ok(())
    }

    pub fn validate_for_bindings_and_receipt(
        &self,
        delivery_binding: &DirectOperationBinding,
        allocation_binding: &DirectOperationBinding,
        receipt: &DirectOperationOuterReceiptV3,
    ) -> DirectOperationResult<()> {
        self.validate_for_outer_receipt(receipt)?;
        receipt.validate_for_binding(delivery_binding)?;
        if allocation_binding.authorized_adapter_set != delivery_binding.authorized_adapter_set
            || !allocation_binding
                .authorized_adapter_set
                .authorizes(self.adapter)
        {
            return Err(invalid(
                "outer acknowledgement allocation binding adapter policy does not match",
            ));
        }
        self.journal_evidence_snapshot
            .validate_for_allocation_binding(allocation_binding, self.adapter)
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate()?;
        let mut hasher = domain_hasher(b"trillionnium.direct-operation-outer-ack-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"binding_sha256", &self.binding_sha256);
        hash_string_field(&mut hasher, b"invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            b"delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, b"provider_id", &self.provider_id);
        hash_string_field(&mut hasher, b"agent_id", &self.agent_id);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(
            &mut hasher,
            b"authorized_adapter_set_sha256",
            &self.authorized_adapter_set_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"outer_receipt_sha256",
            &self.outer_receipt_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"journal_evidence_snapshot_sha256",
            &self.journal_evidence_snapshot_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// One domain-separated, per-adapter authenticated ACK-chain transition. The
/// all-zero chain is accepted only as `previous_ack_chain_sha256` at watermark
/// zero. A chain step never authorizes an ACK on its own; the future trusted
/// consumer must also authenticate the exact ACK and its durable provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationOuterAckChainStepV3 {
    pub schema: String,
    pub adapter: DirectOperationAdapter,
    pub journal_epoch: String,
    pub previous_ack_watermark: u64,
    pub acknowledged_through_sequence: u64,
    pub acknowledgement_sha256: String,
    pub previous_ack_chain_sha256: String,
    pub authenticated_ack_chain_sha256: String,
}

impl DirectOperationOuterAckChainStepV3 {
    pub fn derive(
        adapter: DirectOperationAdapter,
        journal_epoch: String,
        previous_ack_watermark: u64,
        acknowledged_through_sequence: u64,
        acknowledgement_sha256: String,
        previous_ack_chain_sha256: String,
    ) -> DirectOperationResult<Self> {
        let mut value = Self {
            schema: OUTER_ACK_CHAIN_STEP_V3_SCHEMA.to_string(),
            adapter,
            journal_epoch,
            previous_ack_watermark,
            acknowledged_through_sequence,
            acknowledgement_sha256,
            previous_ack_chain_sha256,
            authenticated_ack_chain_sha256: String::new(),
        };
        value.validate_preimage()?;
        value.authenticated_ack_chain_sha256 = value.expected_chain_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> DirectOperationResult<()> {
        self.validate_preimage()?;
        if !valid_nonzero_sha256(&self.authenticated_ack_chain_sha256)
            || self.expected_chain_sha256()? != self.authenticated_ack_chain_sha256
        {
            return Err(invalid("outer acknowledgement chain digest does not match"));
        }
        Ok(())
    }

    pub fn validate_for_ack(&self, ack: &DirectOperationOuterAckV3) -> DirectOperationResult<()> {
        self.validate()?;
        ack.validate()?;
        let expected_first = self
            .previous_ack_watermark
            .checked_add(1)
            .ok_or_else(|| invalid("outer acknowledgement watermark overflows"))?;
        if self.adapter != ack.adapter
            || self.journal_epoch != ack.journal_evidence_snapshot.journal_epoch
            || self.previous_ack_watermark != ack.journal_evidence_snapshot.previous_ack_watermark
            || self.previous_ack_chain_sha256
                != ack.journal_evidence_snapshot.previous_ack_chain_sha256
            || self.acknowledgement_sha256 != ack.digest_sha256()?
            || expected_first != ack.journal_evidence_snapshot.first_journal_sequence
            || self.acknowledged_through_sequence
                != ack.journal_evidence_snapshot.last_journal_sequence
        {
            return Err(invalid(
                "outer acknowledgement chain does not exactly cover the ACK evidence",
            ));
        }
        Ok(())
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        self.validate()?;
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-outer-ack-chain-step-digest.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(&mut hasher, b"journal_epoch", &self.journal_epoch);
        hash_bytes_field(
            &mut hasher,
            b"previous_ack_watermark",
            &self.previous_ack_watermark.to_be_bytes(),
        );
        hash_bytes_field(
            &mut hasher,
            b"acknowledged_through_sequence",
            &self.acknowledged_through_sequence.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"acknowledgement_sha256",
            &self.acknowledgement_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"previous_ack_chain_sha256",
            &self.previous_ack_chain_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"authenticated_ack_chain_sha256",
            &self.authenticated_ack_chain_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_preimage(&self) -> DirectOperationResult<()> {
        if self.schema != OUTER_ACK_CHAIN_STEP_V3_SCHEMA
            || !valid_journal_epoch(&self.journal_epoch)
            || self.acknowledged_through_sequence == 0
            || self.acknowledged_through_sequence > MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE
            || self.previous_ack_watermark >= self.acknowledged_through_sequence
            || !valid_nonzero_sha256(&self.acknowledgement_sha256)
            || !valid_sha256(&self.previous_ack_chain_sha256)
            || (self.previous_ack_watermark == 0 && self.previous_ack_chain_sha256 != ZERO_SHA256)
            || (self.previous_ack_watermark != 0
                && !valid_nonzero_sha256(&self.previous_ack_chain_sha256))
        {
            return Err(invalid(
                "outer acknowledgement chain preimage is malformed or discontinuous",
            ));
        }
        Ok(())
    }

    fn expected_chain_sha256(&self) -> DirectOperationResult<String> {
        self.validate_preimage()?;
        let mut hasher = domain_hasher(b"trillionnium.direct-operation-outer-ack-chain-step.v3");
        hash_string_field(&mut hasher, b"schema", &self.schema);
        hash_string_field(&mut hasher, b"adapter", self.adapter.adapter_id());
        hash_string_field(&mut hasher, b"journal_epoch", &self.journal_epoch);
        hash_bytes_field(
            &mut hasher,
            b"previous_ack_watermark",
            &self.previous_ack_watermark.to_be_bytes(),
        );
        hash_bytes_field(
            &mut hasher,
            b"acknowledged_through_sequence",
            &self.acknowledged_through_sequence.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"acknowledgement_sha256",
            &self.acknowledgement_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"previous_ack_chain_sha256",
            &self.previous_ack_chain_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Closed publisher-to-adapter envelope for one v3 acknowledgement and its
/// exact authenticated chain transition. This is an inert wire/storage shape;
/// validation grants no journal capability and performs no reclamation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationOuterAckInboxV3 {
    pub schema: String,
    pub acknowledgement: DirectOperationOuterAckV3,
    pub acknowledgement_sha256: String,
    pub chain_step: DirectOperationOuterAckChainStepV3,
    pub chain_step_sha256: String,
}

impl DirectOperationOuterAckInboxV3 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != OUTER_ACK_INBOX_V3_SCHEMA
            || !valid_nonzero_sha256(&self.acknowledgement_sha256)
            || !valid_nonzero_sha256(&self.chain_step_sha256)
        {
            return Err(invalid(
                "outer acknowledgement inbox v3 header is malformed",
            ));
        }
        self.acknowledgement.validate()?;
        self.chain_step.validate_for_ack(&self.acknowledgement)?;
        if self.acknowledgement.digest_sha256()? != self.acknowledgement_sha256
            || self.chain_step.digest_sha256()? != self.chain_step_sha256
        {
            return Err(invalid(
                "outer acknowledgement inbox v3 digest does not match",
            ));
        }
        Ok(())
    }

    pub fn validate_for_bindings_and_receipt(
        &self,
        delivery_binding: &DirectOperationBinding,
        allocation_binding: &DirectOperationBinding,
        receipt: &DirectOperationOuterReceiptV3,
    ) -> DirectOperationResult<()> {
        self.validate()?;
        self.acknowledgement.validate_for_bindings_and_receipt(
            delivery_binding,
            allocation_binding,
            receipt,
        )
    }

    /// Digest of the exact endpoint-local Android ACK intent. This binds the
    /// adapter, epoch, terminal sequence, acknowledgement and authenticated
    /// ACK-chain successor without exposing any selector or raw result.
    pub fn operation_replay_sync_ack_intent_sha256(&self) -> DirectOperationResult<String> {
        self.validate()?;
        let snapshot = &self.acknowledgement.journal_evidence_snapshot;
        let mut hasher = domain_hasher(b"trillionnium.direct-operation-replay-sync-ack-intent.v3");
        hash_string_field(
            &mut hasher,
            b"binding_sha256",
            &self.acknowledgement.binding_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"adapter",
            self.acknowledgement.adapter.adapter_id(),
        );
        hash_string_field(
            &mut hasher,
            b"authorized_adapter_set_sha256",
            &self.acknowledgement.authorized_adapter_set_sha256,
        );
        hash_string_field(&mut hasher, b"journal_epoch", &snapshot.journal_epoch);
        hash_bytes_field(
            &mut hasher,
            b"last_journal_sequence",
            &snapshot.last_journal_sequence.to_be_bytes(),
        );
        hash_string_field(
            &mut hasher,
            b"acknowledgement_sha256",
            &self.acknowledgement_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"authenticated_ack_chain_sha256",
            &self.chain_step.authenticated_ack_chain_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Closed, daemon-to-helper capability preimage for the separately packaged
/// P0 replay-sync helper. The value becomes authoritative only when received
/// from the measured launcher's fixed FD 3 after exact post-exec custody has
/// been verified; parsing the same bytes from any other surface grants
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationP0ReplaySyncSealedAuthorityV1 {
    pub schema: String,
    pub delivery_binding: DirectOperationBinding,
    pub allocation_binding: DirectOperationBinding,
    pub outer_receipt: DirectOperationOuterReceiptV3,
    pub committed_custody_head: DirectOperationCustodyHead,
    pub committed_custody_head_sha256: String,
    pub binding_publication_sha256: String,
    pub binding_inbox_bytes_sha256: String,
    pub high_water_route_sha256: String,
    pub daemon_high_water_observation_sha256: String,
    pub daemon_binding_publication_identity_sha256: String,
    pub launch_challenge_sha256: String,
    pub ack_intent_sha256: String,
    pub sealed_authority_sha256: String,
}

impl DirectOperationP0ReplaySyncSealedAuthorityV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        delivery_binding: DirectOperationBinding,
        allocation_binding: DirectOperationBinding,
        outer_receipt: DirectOperationOuterReceiptV3,
        committed_custody_head: DirectOperationCustodyHead,
        binding_publication_sha256: String,
        binding_inbox_bytes_sha256: String,
        high_water_route_sha256: String,
        launch_challenge_sha256: String,
        ack_intent_sha256: String,
    ) -> DirectOperationResult<Self> {
        let committed_custody_head_sha256 =
            p0_replay_sync_committed_head_sha256(&committed_custody_head)?;
        let daemon_high_water_observation_sha256 = p0_replay_sync_high_water_observation_sha256(
            &high_water_route_sha256,
            &committed_custody_head_sha256,
        )?;
        let daemon_binding_publication_identity_sha256 =
            p0_replay_sync_daemon_binding_publication_sha256(
                &delivery_binding.digest_sha256()?,
                &binding_publication_sha256,
                &binding_inbox_bytes_sha256,
                &committed_custody_head_sha256,
            )?;
        let mut value = Self {
            schema: P0_REPLAY_SYNC_SEALED_AUTHORITY_V1_SCHEMA.to_string(),
            delivery_binding,
            allocation_binding,
            outer_receipt,
            committed_custody_head,
            committed_custody_head_sha256,
            binding_publication_sha256,
            binding_inbox_bytes_sha256,
            high_water_route_sha256,
            daemon_high_water_observation_sha256,
            daemon_binding_publication_identity_sha256,
            launch_challenge_sha256,
            ack_intent_sha256,
            sealed_authority_sha256: String::new(),
        };
        value.sealed_authority_sha256 = value.expected_sealed_authority_sha256()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> DirectOperationResult<()> {
        self.delivery_binding.validate()?;
        self.allocation_binding.validate()?;
        self.delivery_binding
            .authorized_adapter_set
            .validate_p0_system_api()?;
        self.allocation_binding
            .authorized_adapter_set
            .validate_p0_system_api()?;
        self.outer_receipt
            .validate_for_binding(&self.delivery_binding)?;
        self.committed_custody_head.validate().map_err(invalid)?;
        if self.schema != P0_REPLAY_SYNC_SEALED_AUTHORITY_V1_SCHEMA
            || self.committed_custody_head.generation == 0
            || self.delivery_binding.stable_seed != self.allocation_binding.stable_seed
            || self.delivery_binding.invocation_id != self.allocation_binding.invocation_id
            || self.delivery_binding.workflow_id_sha256
                != self.allocation_binding.workflow_id_sha256
            || self.delivery_binding.agent_identity_key_sha256
                != self.allocation_binding.agent_identity_key_sha256
            || self.delivery_binding.agent_executable_sha256
                != self.allocation_binding.agent_executable_sha256
            || self.delivery_binding.authorized_adapter_set
                != self.allocation_binding.authorized_adapter_set
            || !valid_nonzero_sha256(&self.binding_publication_sha256)
            || !valid_nonzero_sha256(&self.binding_inbox_bytes_sha256)
            || !valid_nonzero_sha256(&self.high_water_route_sha256)
            || !valid_nonzero_sha256(&self.launch_challenge_sha256)
            || !valid_nonzero_sha256(&self.ack_intent_sha256)
            || self.committed_custody_head_sha256
                != p0_replay_sync_committed_head_sha256(&self.committed_custody_head)?
            || self.daemon_high_water_observation_sha256
                != p0_replay_sync_high_water_observation_sha256(
                    &self.high_water_route_sha256,
                    &self.committed_custody_head_sha256,
                )?
            || self.daemon_binding_publication_identity_sha256
                != p0_replay_sync_daemon_binding_publication_sha256(
                    &self.delivery_binding.digest_sha256()?,
                    &self.binding_publication_sha256,
                    &self.binding_inbox_bytes_sha256,
                    &self.committed_custody_head_sha256,
                )?
            || self.sealed_authority_sha256 != self.expected_sealed_authority_sha256()?
        {
            return Err(invalid("P0 replay-sync sealed authority is malformed"));
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        inbox: &DirectOperationOuterAckInboxV3,
        binding_sha256: &str,
        ack_intent_sha256: &str,
        launch_challenge_sha256: &str,
    ) -> DirectOperationResult<()> {
        self.validate()?;
        inbox.validate_for_bindings_and_receipt(
            &self.delivery_binding,
            &self.allocation_binding,
            &self.outer_receipt,
        )?;
        if self.delivery_binding.digest_sha256()? != binding_sha256
            || self.ack_intent_sha256 != ack_intent_sha256
            || self.launch_challenge_sha256 != launch_challenge_sha256
            || inbox.operation_replay_sync_ack_intent_sha256()? != self.ack_intent_sha256
        {
            return Err(invalid(
                "P0 replay-sync sealed authority does not match the fixed command and ACK",
            ));
        }
        Ok(())
    }

    fn expected_sealed_authority_sha256(&self) -> DirectOperationResult<String> {
        let delivery_binding_sha256 = self.delivery_binding.digest_sha256()?;
        let allocation_binding_sha256 = self.allocation_binding.digest_sha256()?;
        let outer_receipt_sha256 = self.outer_receipt.digest_sha256()?;
        let mut hasher = domain_hasher(b"trillionnium.p0-replay-sync-sealed-authority.v1");
        for (name, value) in [
            (b"schema".as_slice(), self.schema.as_str()),
            (
                b"delivery_binding_sha256".as_slice(),
                delivery_binding_sha256.as_str(),
            ),
            (
                b"allocation_binding_sha256".as_slice(),
                allocation_binding_sha256.as_str(),
            ),
            (
                b"outer_receipt_sha256".as_slice(),
                outer_receipt_sha256.as_str(),
            ),
            (
                b"committed_custody_head_sha256".as_slice(),
                self.committed_custody_head_sha256.as_str(),
            ),
            (
                b"binding_publication_sha256".as_slice(),
                self.binding_publication_sha256.as_str(),
            ),
            (
                b"binding_inbox_bytes_sha256".as_slice(),
                self.binding_inbox_bytes_sha256.as_str(),
            ),
            (
                b"high_water_route_sha256".as_slice(),
                self.high_water_route_sha256.as_str(),
            ),
            (
                b"daemon_high_water_observation_sha256".as_slice(),
                self.daemon_high_water_observation_sha256.as_str(),
            ),
            (
                b"daemon_binding_publication_identity_sha256".as_slice(),
                self.daemon_binding_publication_identity_sha256.as_str(),
            ),
            (
                b"launch_challenge_sha256".as_slice(),
                self.launch_challenge_sha256.as_str(),
            ),
            (
                b"ack_intent_sha256".as_slice(),
                self.ack_intent_sha256.as_str(),
            ),
        ] {
            hash_string_field(&mut hasher, name, value);
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

fn p0_replay_sync_committed_head_sha256(
    head: &DirectOperationCustodyHead,
) -> DirectOperationResult<String> {
    head.validate().map_err(invalid)?;
    let mut hasher = domain_hasher(b"trillionnium.p0-replay-sync-committed-head.v1");
    hash_bytes_field(&mut hasher, b"generation", &head.generation.to_be_bytes());
    hash_string_field(&mut hasher, b"store_sha256", &head.store_sha256);
    Ok(lower_hex(&hasher.finalize()))
}

fn p0_replay_sync_high_water_observation_sha256(
    route_sha256: &str,
    committed_head_sha256: &str,
) -> DirectOperationResult<String> {
    if !valid_nonzero_sha256(route_sha256) || !valid_nonzero_sha256(committed_head_sha256) {
        return Err(invalid(
            "P0 replay-sync high-water observation is malformed",
        ));
    }
    let mut hasher = domain_hasher(b"trillionnium.p0-replay-sync-high-water-observation.v1");
    hash_string_field(&mut hasher, b"route_sha256", route_sha256);
    hash_string_field(&mut hasher, b"committed_head_sha256", committed_head_sha256);
    Ok(lower_hex(&hasher.finalize()))
}

fn p0_replay_sync_daemon_binding_publication_sha256(
    binding_sha256: &str,
    binding_publication_sha256: &str,
    binding_inbox_bytes_sha256: &str,
    committed_head_sha256: &str,
) -> DirectOperationResult<String> {
    if [
        binding_sha256,
        binding_publication_sha256,
        binding_inbox_bytes_sha256,
        committed_head_sha256,
    ]
    .into_iter()
    .any(|value| !valid_nonzero_sha256(value))
    {
        return Err(invalid(
            "P0 replay-sync daemon binding publication is malformed",
        ));
    }
    let mut hasher = domain_hasher(b"trillionnium.p0-replay-sync-daemon-binding-publication.v1");
    hash_string_field(&mut hasher, b"binding_sha256", binding_sha256);
    hash_string_field(
        &mut hasher,
        b"binding_publication_sha256",
        binding_publication_sha256,
    );
    hash_string_field(
        &mut hasher,
        b"binding_inbox_bytes_sha256",
        binding_inbox_bytes_sha256,
    );
    hash_string_field(&mut hasher, b"committed_head_sha256", committed_head_sha256);
    Ok(lower_hex(&hasher.finalize()))
}

/// Closed root-to-helper request. The selected adapter, provider identity,
/// journal path, binary path, UID/GID and SELinux domain are deliberately
/// absent: a measured fixed helper derives all of them from kernel custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectOperationReplaySyncCommandV3 {
    ObserveDisposition {
        schema: String,
        binding_sha256: String,
        launch_challenge_sha256: String,
    },
    ApplyAck {
        schema: String,
        binding_sha256: String,
        ack_intent_sha256: String,
        launch_challenge_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        p0_sealed_authority: Option<Box<DirectOperationP0ReplaySyncSealedAuthorityV1>>,
    },
}

impl DirectOperationReplaySyncCommandV3 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        let (schema, binding_sha256, launch_challenge_sha256, ack_intent_sha256) = match self {
            Self::ObserveDisposition {
                schema,
                binding_sha256,
                launch_challenge_sha256,
            } => (schema, binding_sha256, launch_challenge_sha256, None),
            Self::ApplyAck {
                schema,
                binding_sha256,
                ack_intent_sha256,
                launch_challenge_sha256,
                p0_sealed_authority,
            } => (
                schema,
                binding_sha256,
                launch_challenge_sha256,
                Some((ack_intent_sha256, p0_sealed_authority.as_deref())),
            ),
        };
        if schema != OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA
            || !valid_nonzero_sha256(binding_sha256)
            || !valid_nonzero_sha256(launch_challenge_sha256)
            || ack_intent_sha256.is_some_and(|(digest, _)| !valid_nonzero_sha256(digest))
        {
            return Err(invalid("operation replay-sync command is malformed"));
        }
        if let Some((ack_intent_sha256, Some(authority))) = ack_intent_sha256 {
            authority.validate()?;
            if authority.ack_intent_sha256.as_str() != ack_intent_sha256.as_str()
                || authority.launch_challenge_sha256.as_str() != launch_challenge_sha256.as_str()
                || authority.delivery_binding.digest_sha256()?.as_str() != binding_sha256.as_str()
            {
                return Err(invalid(
                    "operation replay-sync command sealed authority does not match",
                ));
            }
        }
        Ok(())
    }

    /// Product V3 commands never carry the non-product daemon-custody lane.
    /// Generic canonical parsing remains schema-only; every product consumer
    /// must call this before using command material as launch input.
    pub fn validate_product_lane(&self) -> DirectOperationResult<()> {
        self.validate()?;
        if self.p0_sealed_authority().is_some() {
            return Err(invalid(
                "product replay-sync command contains P0 daemon-custody material",
            ));
        }
        Ok(())
    }

    /// The P0 userdebug daemon-custody helper accepts only ApplyAck with one
    /// sealed handoff. An ordinary product command cannot silently enter this
    /// lane merely because its shared V3 envelope parsed successfully.
    pub fn validate_p0_daemon_custody_lane(&self) -> DirectOperationResult<()> {
        self.validate()?;
        match self {
            Self::ApplyAck {
                p0_sealed_authority: Some(_),
                ..
            } => Ok(()),
            _ => Err(invalid(
                "P0 replay-sync command lacks its daemon-custody handoff",
            )),
        }
    }

    #[must_use]
    pub const fn opcode(&self) -> u8 {
        match self {
            Self::ObserveDisposition { .. } => 1,
            Self::ApplyAck { .. } => 2,
        }
    }

    #[must_use]
    pub fn binding_sha256(&self) -> &str {
        match self {
            Self::ObserveDisposition { binding_sha256, .. }
            | Self::ApplyAck { binding_sha256, .. } => binding_sha256,
        }
    }

    #[must_use]
    pub fn launch_challenge_sha256(&self) -> &str {
        match self {
            Self::ObserveDisposition {
                launch_challenge_sha256,
                ..
            }
            | Self::ApplyAck {
                launch_challenge_sha256,
                ..
            } => launch_challenge_sha256,
        }
    }

    #[must_use]
    pub fn ack_intent_sha256(&self) -> Option<&str> {
        match self {
            Self::ObserveDisposition { .. } => None,
            Self::ApplyAck {
                ack_intent_sha256, ..
            } => Some(ack_intent_sha256),
        }
    }

    #[must_use]
    pub fn p0_sealed_authority(&self) -> Option<&DirectOperationP0ReplaySyncSealedAuthorityV1> {
        match self {
            Self::ObserveDisposition { .. } => None,
            Self::ApplyAck {
                p0_sealed_authority,
                ..
            } => p0_sealed_authority.as_deref(),
        }
    }

    pub fn canonical_json(&self) -> DirectOperationResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|_| invalid("operation replay-sync command serialization failed"))
    }

    pub fn from_canonical_json(bytes: &[u8]) -> DirectOperationResult<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("operation replay-sync command JSON is invalid"))?;
        value.validate()?;
        if value.canonical_json()?.as_slice() != bytes {
            return Err(invalid(
                "operation replay-sync command JSON is not canonical",
            ));
        }
        Ok(value)
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        let canonical = self.canonical_json()?;
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-replay-sync-command-digest.v3");
        hash_bytes_field(&mut hasher, b"canonical_json", &canonical);
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Authenticated, digest-only observation exported by one endpoint-specific
/// helper. It contains no raw backend result and grants no ACK authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationReplaySyncObservationV3 {
    pub schema: String,
    pub terminal_disposition: DirectOperationAdapterTerminalDispositionV1,
    pub terminal_disposition_sha256: String,
    pub journal_state_sha256: String,
    pub journal_file_identity_sha256: String,
}

impl DirectOperationReplaySyncObservationV3 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        self.terminal_disposition.validate()?;
        let terminal_journal_sha256 = match &self.terminal_disposition.terminal_state {
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot,
            } => &journal_evidence_snapshot.journal_payload_sha256,
            DirectOperationAdapterTerminalStateV1::NoOperations {
                journal_payload_sha256,
                ..
            }
            | DirectOperationAdapterTerminalStateV1::HeldIndeterminate {
                journal_payload_sha256,
                ..
            } => journal_payload_sha256,
        };
        if self.schema != OPERATION_REPLAY_SYNC_OBSERVATION_V3_SCHEMA
            || !valid_nonzero_sha256(&self.terminal_disposition_sha256)
            || self.terminal_disposition.digest_sha256()? != self.terminal_disposition_sha256
            || !valid_nonzero_sha256(&self.journal_state_sha256)
            || &self.journal_state_sha256 != terminal_journal_sha256
            || !valid_nonzero_sha256(&self.journal_file_identity_sha256)
        {
            return Err(invalid("operation replay-sync observation is malformed"));
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> DirectOperationResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|_| invalid("operation replay-sync observation serialization failed"))
    }

    pub fn from_canonical_json(bytes: &[u8]) -> DirectOperationResult<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("operation replay-sync observation JSON is invalid"))?;
        value.validate()?;
        if value.canonical_json()?.as_slice() != bytes {
            return Err(invalid(
                "operation replay-sync observation JSON is not canonical",
            ));
        }
        Ok(value)
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        let canonical = self.canonical_json()?;
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-replay-sync-observation-digest.v3");
        hash_bytes_field(&mut hasher, b"canonical_json", &canonical);
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Proof returned only after Android accepted or exactly replayed the ACK,
/// local journal compaction was durable, and the compacted state was reopened
/// and read back. A non-zero mutation-CAS committed head remains mandatory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationReplaySyncAckConfirmationV3 {
    pub schema: String,
    pub ack_intent_sha256: String,
    pub android_ack_echo_sha256: String,
    pub acknowledgement_sha256: String,
    pub authenticated_ack_chain_sha256: String,
    pub compacted_ack_watermark: u64,
    pub post_compaction_journal_sha256: String,
    pub journal_file_identity_sha256: String,
    pub mutation_cas_committed_head_sha256: String,
}

impl DirectOperationReplaySyncAckConfirmationV3 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA
            || !valid_nonzero_sha256(&self.ack_intent_sha256)
            || !valid_nonzero_sha256(&self.android_ack_echo_sha256)
            || !valid_nonzero_sha256(&self.acknowledgement_sha256)
            || !valid_nonzero_sha256(&self.authenticated_ack_chain_sha256)
            || self.compacted_ack_watermark == 0
            || self.compacted_ack_watermark > MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE
            || !valid_nonzero_sha256(&self.post_compaction_journal_sha256)
            || !valid_nonzero_sha256(&self.journal_file_identity_sha256)
            || !valid_nonzero_sha256(&self.mutation_cas_committed_head_sha256)
        {
            return Err(invalid(
                "operation replay-sync ACK confirmation is malformed",
            ));
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> DirectOperationResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|_| invalid("operation replay-sync ACK confirmation serialization failed"))
    }

    pub fn from_canonical_json(bytes: &[u8]) -> DirectOperationResult<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("operation replay-sync ACK confirmation JSON is invalid"))?;
        value.validate()?;
        if value.canonical_json()?.as_slice() != bytes {
            return Err(invalid(
                "operation replay-sync ACK confirmation JSON is not canonical",
            ));
        }
        Ok(value)
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        let canonical = self.canonical_json()?;
        let mut hasher =
            domain_hasher(b"trillionnium.direct-operation-replay-sync-ack-confirmation-digest.v3");
        hash_bytes_field(&mut hasher, b"canonical_json", &canonical);
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// P0-only confirmation for the userdebug daemon-custody lane. This is
/// deliberately not the product V3 confirmation: it makes no mutation-CAS,
/// rollback-resistant hardware, or production authority claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationP0ReplaySyncAckConfirmationV1 {
    pub schema: String,
    pub lane: String,
    pub ack_intent_sha256: String,
    pub android_ack_echo_sha256: String,
    pub acknowledgement_sha256: String,
    pub authenticated_ack_chain_sha256: String,
    pub compacted_ack_watermark: u64,
    pub post_compaction_journal_sha256: String,
    pub journal_file_identity_sha256: String,
    pub daemon_custody_committed_head_sha256: String,
    pub daemon_high_water_observation_sha256: String,
    pub daemon_binding_publication_identity_sha256: String,
    pub sealed_authority_sha256: String,
}

impl DirectOperationP0ReplaySyncAckConfirmationV1 {
    pub fn validate(&self) -> DirectOperationResult<()> {
        if self.schema != P0_REPLAY_SYNC_ACK_CONFIRMATION_V1_SCHEMA
            || self.lane != P0_REPLAY_SYNC_ACK_CONFIRMATION_LANE
            || !valid_nonzero_sha256(&self.ack_intent_sha256)
            || !valid_nonzero_sha256(&self.android_ack_echo_sha256)
            || !valid_nonzero_sha256(&self.acknowledgement_sha256)
            || !valid_nonzero_sha256(&self.authenticated_ack_chain_sha256)
            || self.compacted_ack_watermark == 0
            || self.compacted_ack_watermark > MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE
            || !valid_nonzero_sha256(&self.post_compaction_journal_sha256)
            || !valid_nonzero_sha256(&self.journal_file_identity_sha256)
            || !valid_nonzero_sha256(&self.daemon_custody_committed_head_sha256)
            || !valid_nonzero_sha256(&self.daemon_high_water_observation_sha256)
            || !valid_nonzero_sha256(&self.daemon_binding_publication_identity_sha256)
            || !valid_nonzero_sha256(&self.sealed_authority_sha256)
        {
            return Err(invalid(
                "P0 replay-sync ACK confirmation is malformed or overclaims authority",
            ));
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> DirectOperationResult<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|_| invalid("P0 replay-sync ACK confirmation serialization failed"))
    }

    pub fn from_canonical_json(bytes: &[u8]) -> DirectOperationResult<Self> {
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid("P0 replay-sync ACK confirmation JSON is invalid"))?;
        value.validate()?;
        if value.canonical_json()?.as_slice() != bytes {
            return Err(invalid(
                "P0 replay-sync ACK confirmation JSON is not canonical",
            ));
        }
        Ok(value)
    }

    pub fn digest_sha256(&self) -> DirectOperationResult<String> {
        let canonical = self.canonical_json()?;
        let mut hasher = domain_hasher(b"trillionnium.p0-replay-sync-ack-confirmation-digest.v1");
        hash_bytes_field(&mut hasher, b"canonical_json", &canonical);
        Ok(lower_hex(&hasher.finalize()))
    }
}

const fn invalid(message: &'static str) -> DirectOperationProtocolError {
    DirectOperationProtocolError(message)
}

fn domain_hasher(domain: &[u8]) -> Sha256 {
    let mut hasher = Sha256::new();
    hash_bytes_field(&mut hasher, b"domain", domain);
    hasher
}

fn derive_provider_attempt_id(
    runtime_lifecycle_binding_sha256: &str,
    attempt_generation: u64,
    daemon_attempt_context_sha256: &str,
) -> String {
    let mut hasher = domain_hasher(b"trillionnium.direct-operation-provider-attempt-id.v1");
    hash_string_field(
        &mut hasher,
        b"runtime_lifecycle_binding_sha256",
        runtime_lifecycle_binding_sha256,
    );
    hash_bytes_field(
        &mut hasher,
        b"attempt_generation",
        &attempt_generation.to_be_bytes(),
    );
    hash_string_field(
        &mut hasher,
        b"daemon_attempt_context_sha256",
        daemon_attempt_context_sha256,
    );
    format!(
        "{PROVIDER_ATTEMPT_ID_PREFIX}{}",
        lower_hex(&hasher.finalize())
    )
}

fn hash_string_field(hasher: &mut Sha256, name: &[u8], value: &str) {
    hash_bytes_field(hasher, name, value.as_bytes());
}

fn hash_bytes_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn valid_atom(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_nonzero_sha256(value: &str) -> bool {
    valid_sha256(value) && value != ZERO_SHA256
}

fn valid_prefixed_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_sha256)
}

fn valid_nonzero_prefixed_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_nonzero_sha256)
}

fn valid_journal_epoch(value: &str) -> bool {
    value.len() == JOURNAL_EPOCH_HEX_BYTES
        && value != "00000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_provider_agent_pair(provider_id: &str, agent_id: &str) -> bool {
    crate::agent_principal_registry::from_provider_agent_pair(provider_id, agent_id).is_some()
}

fn validate_terminal_journal_baseline(
    journal_epoch: &str,
    journal_payload_sha256: &str,
    previous_ack_watermark: u64,
    previous_ack_chain_sha256: &str,
) -> DirectOperationResult<()> {
    if !valid_journal_epoch(journal_epoch)
        || !valid_nonzero_sha256(journal_payload_sha256)
        || previous_ack_watermark > MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE
        || !valid_sha256(previous_ack_chain_sha256)
        || (previous_ack_watermark == 0 && previous_ack_chain_sha256 != ZERO_SHA256)
        || (previous_ack_watermark != 0 && !valid_nonzero_sha256(previous_ack_chain_sha256))
    {
        return Err(invalid("adapter terminal journal baseline is malformed"));
    }
    Ok(())
}

fn hash_terminal_journal_baseline(
    hasher: &mut Sha256,
    journal_epoch: &str,
    journal_payload_sha256: &str,
    previous_ack_watermark: u64,
    previous_ack_chain_sha256: &str,
) {
    hash_string_field(hasher, b"journal_epoch", journal_epoch);
    hash_string_field(hasher, b"journal_payload_sha256", journal_payload_sha256);
    hash_bytes_field(
        hasher,
        b"previous_ack_watermark",
        &previous_ack_watermark.to_be_bytes(),
    );
    hash_string_field(
        hasher,
        b"previous_ack_chain_sha256",
        previous_ack_chain_sha256,
    );
}

fn validate_outer_evidence_v3(
    evidence: &DirectOperationOuterEvidence,
    adapter: DirectOperationAdapter,
) -> DirectOperationResult<()> {
    evidence.validate_for(adapter)?;
    if !valid_nonzero_prefixed_sha256(
        &evidence.allocating_provider_attempt_id,
        PROVIDER_ATTEMPT_ID_PREFIX,
    ) || !valid_nonzero_sha256(&evidence.canonical_request_sha256)
        || !valid_nonzero_sha256(&evidence.backend_request_id_sha256)
        || !valid_nonzero_sha256(&evidence.backend_result_sha256)
        || evidence.outcome == DirectOperationOuterOutcome::Indeterminate
    {
        return Err(invalid(
            "journal evidence contains a zero digest or indeterminate outcome",
        ));
    }
    Ok(())
}

fn journal_evidence_digest_sha256(
    adapter: DirectOperationAdapter,
    evidence: &[DirectOperationOuterEvidence],
) -> DirectOperationResult<String> {
    if evidence.is_empty() || evidence.len() > MAX_OUTER_ACK_EVIDENCE {
        return Err(invalid("journal evidence set is empty or oversized"));
    }
    let mut hasher = domain_hasher(b"trillionnium.direct-operation-journal-evidence-set.v1");
    hash_string_field(&mut hasher, b"adapter", adapter.adapter_id());
    hash_bytes_field(
        &mut hasher,
        b"count",
        &(evidence.len() as u64).to_be_bytes(),
    );
    for item in evidence {
        validate_outer_evidence_v3(item, adapter)?;
        hash_string_field(
            &mut hasher,
            b"allocating_provider_attempt_id",
            &item.allocating_provider_attempt_id,
        );
        hash_bytes_field(
            &mut hasher,
            b"adapter_effect_ordinal",
            &item.adapter_effect_ordinal.to_be_bytes(),
        );
        hash_bytes_field(
            &mut hasher,
            b"journal_sequence",
            &item.journal_sequence.to_be_bytes(),
        );
        hash_string_field(&mut hasher, b"tool", &item.tool);
        hash_string_field(
            &mut hasher,
            b"canonical_request_sha256",
            &item.canonical_request_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"backend_request_id_sha256",
            &item.backend_request_id_sha256,
        );
        hash_string_field(
            &mut hasher,
            b"backend_result_sha256",
            &item.backend_result_sha256,
        );
        hash_bytes_field(&mut hasher, b"outcome", item.outcome.as_bytes());
        hash_string_field(
            &mut hasher,
            b"backend_error_code",
            item.backend_error_code.as_deref().unwrap_or(""),
        );
    }
    Ok(lower_hex(&hasher.finalize()))
}

fn valid_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn seed() -> DirectOperationStableSeed {
        DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: "task-0f77a838-b43b-491a-aab0-2a56bd490f01".to_string(),
            provider_invocation_id_sha256: digest('1'),
            provider_session_id_sha256: digest('2'),
            subject_uid: 10_100,
            subject_selinux_domain_sha256: digest('3'),
        }
    }

    fn binding() -> DirectOperationBinding {
        let seed = seed();
        DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            invocation_id: seed.invocation_id().unwrap(),
            stable_seed: seed,
            workflow_id_sha256: digest('6'),
            agent_identity_key_sha256: digest('7'),
            agent_executable_sha256: digest('8'),
            authorized_adapter_set: DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(digest('5'), 7, digest('4')).unwrap(),
        }
    }

    fn journal_snapshot_v1() -> DirectOperationJournalEvidenceSnapshotV1 {
        let allocation_binding = binding();
        let allocating_provider_attempt_id = allocation_binding
            .attempt
            .delivery_provider_attempt_id
            .clone();
        let mut value = DirectOperationJournalEvidenceSnapshotV1 {
            schema: JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA.to_string(),
            allocation_binding_sha256: allocation_binding.digest_sha256().unwrap(),
            invocation_id: allocation_binding.invocation_id,
            provider_id: allocation_binding.stable_seed.provider_id,
            agent_id: allocation_binding.stable_seed.agent_id,
            allocating_provider_attempt_id: allocating_provider_attempt_id.clone(),
            adapter: DirectOperationAdapter::SystemApi,
            journal_epoch: "01".repeat(16),
            journal_payload_sha256: digest('d'),
            previous_ack_watermark: 0,
            previous_ack_chain_sha256: ZERO_SHA256.to_string(),
            journal_allocation_count: 2,
            journal_evidence_count: 2,
            first_journal_sequence: 1,
            last_journal_sequence: 2,
            evidence: vec![
                DirectOperationOuterEvidence {
                    allocating_provider_attempt_id: allocating_provider_attempt_id.clone(),
                    adapter_effect_ordinal: 0,
                    journal_sequence: 1,
                    tool: DirectOperationAdapter::SystemApi.tool_name().to_string(),
                    canonical_request_sha256: digest('7'),
                    backend_request_id_sha256: digest('8'),
                    backend_result_sha256: digest('9'),
                    outcome: DirectOperationOuterOutcome::Success,
                    backend_error_code: None,
                },
                DirectOperationOuterEvidence {
                    allocating_provider_attempt_id,
                    adapter_effect_ordinal: 1,
                    journal_sequence: 2,
                    tool: DirectOperationAdapter::SystemApi.tool_name().to_string(),
                    canonical_request_sha256: digest('a'),
                    backend_request_id_sha256: digest('b'),
                    backend_result_sha256: digest('c'),
                    outcome: DirectOperationOuterOutcome::BackendError,
                    backend_error_code: Some("backend_rejected".to_string()),
                },
            ],
            evidence_sha256: String::new(),
        };
        value.evidence_sha256 = value.evidence_digest_sha256().unwrap();
        value
    }

    fn terminal_disposition(
        delivery_binding: DirectOperationBinding,
        adapter: DirectOperationAdapter,
        terminal_state: DirectOperationAdapterTerminalStateV1,
    ) -> DirectOperationAdapterTerminalDispositionV1 {
        DirectOperationAdapterTerminalDispositionV1 {
            schema: ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA.to_string(),
            binding_sha256: delivery_binding.digest_sha256().unwrap(),
            invocation_id: delivery_binding.invocation_id,
            delivery_provider_attempt_id: delivery_binding.attempt.delivery_provider_attempt_id,
            provider_id: delivery_binding.stable_seed.provider_id,
            agent_id: delivery_binding.stable_seed.agent_id,
            adapter,
            terminal_state,
        }
    }

    fn system_api_ackable_disposition() -> DirectOperationAdapterTerminalDispositionV1 {
        terminal_disposition(
            binding(),
            DirectOperationAdapter::SystemApi,
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot: journal_snapshot_v1(),
            },
        )
    }

    fn accessibility_no_operations_disposition() -> DirectOperationAdapterTerminalDispositionV1 {
        terminal_disposition(
            dual_binding(),
            DirectOperationAdapter::Accessibility,
            DirectOperationAdapterTerminalStateV1::NoOperations {
                journal_epoch: "02".repeat(16),
                journal_payload_sha256: digest('e'),
                previous_ack_watermark: 0,
                previous_ack_chain_sha256: ZERO_SHA256.to_string(),
                authenticated_terminal_sha256: digest('1'),
            },
        )
    }

    fn dual_binding() -> DirectOperationBinding {
        let mut value = binding();
        value.authorized_adapter_set =
            DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility();
        value
    }

    fn dual_outer_receipt_v3() -> DirectOperationOuterReceiptV3 {
        let delivery_binding = dual_binding();
        let system_disposition = terminal_disposition(
            delivery_binding.clone(),
            DirectOperationAdapter::SystemApi,
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot: journal_snapshot_v1(),
            },
        );
        let mut value = DirectOperationOuterReceiptV3 {
            schema: OUTER_RECEIPT_V3_SCHEMA.to_string(),
            binding_sha256: delivery_binding.digest_sha256().unwrap(),
            invocation_id: delivery_binding.invocation_id,
            delivery_provider_attempt_id: delivery_binding.attempt.delivery_provider_attempt_id,
            provider_id: delivery_binding.stable_seed.provider_id,
            agent_id: delivery_binding.stable_seed.agent_id,
            direct_execution_receipt_sha256: digest('a'),
            ui_replay_completion_proof_sha256: digest('b'),
            ui_replay_semantic_sha256: digest('c'),
            terminal_egress_cas_sha256: digest('d'),
            runtime_evidence_sha256: digest('e'),
            provider_teardown_completion_ack_sha256: digest('f'),
            authorized_adapter_set: delivery_binding.authorized_adapter_set,
            adapter_terminal_dispositions: vec![
                system_disposition,
                accessibility_no_operations_disposition(),
            ],
            adapter_terminal_dispositions_sha256: String::new(),
        };
        value.adapter_terminal_dispositions_sha256 =
            value.adapter_dispositions_digest_sha256().unwrap();
        value
    }

    fn outer_receipt_v3() -> DirectOperationOuterReceiptV3 {
        let delivery_binding = binding();
        let mut value = DirectOperationOuterReceiptV3 {
            schema: OUTER_RECEIPT_V3_SCHEMA.to_string(),
            binding_sha256: delivery_binding.digest_sha256().unwrap(),
            invocation_id: delivery_binding.invocation_id,
            delivery_provider_attempt_id: delivery_binding.attempt.delivery_provider_attempt_id,
            provider_id: delivery_binding.stable_seed.provider_id,
            agent_id: delivery_binding.stable_seed.agent_id,
            direct_execution_receipt_sha256: digest('a'),
            ui_replay_completion_proof_sha256: digest('b'),
            ui_replay_semantic_sha256: digest('c'),
            terminal_egress_cas_sha256: digest('d'),
            runtime_evidence_sha256: digest('e'),
            provider_teardown_completion_ack_sha256: digest('f'),
            authorized_adapter_set: delivery_binding.authorized_adapter_set,
            adapter_terminal_dispositions: vec![system_api_ackable_disposition()],
            adapter_terminal_dispositions_sha256: String::new(),
        };
        value.adapter_terminal_dispositions_sha256 =
            value.adapter_dispositions_digest_sha256().unwrap();
        value
    }

    fn outer_ack_v3() -> DirectOperationOuterAckV3 {
        let receipt = outer_receipt_v3();
        outer_ack_for_receipt(&receipt, DirectOperationAdapter::SystemApi)
    }

    fn outer_ack_for_receipt(
        receipt: &DirectOperationOuterReceiptV3,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationOuterAckV3 {
        let snapshot = receipt
            .adapter_terminal_dispositions
            .iter()
            .find(|disposition| disposition.adapter == adapter)
            .unwrap()
            .ackable_snapshot()
            .unwrap()
            .clone();
        DirectOperationOuterAckV3 {
            schema: OUTER_ACK_V3_SCHEMA.to_string(),
            binding_sha256: receipt.binding_sha256.clone(),
            invocation_id: receipt.invocation_id.clone(),
            delivery_provider_attempt_id: receipt.delivery_provider_attempt_id.clone(),
            provider_id: receipt.provider_id.clone(),
            agent_id: receipt.agent_id.clone(),
            adapter: snapshot.adapter,
            authorized_adapter_set_sha256: receipt.authorized_adapter_set.digest_sha256().unwrap(),
            outer_receipt_sha256: receipt.digest_sha256().unwrap(),
            journal_evidence_snapshot_sha256: snapshot.digest_sha256().unwrap(),
            journal_evidence_snapshot: snapshot,
        }
    }

    fn outer_ack_chain_step_v3() -> DirectOperationOuterAckChainStepV3 {
        let ack = outer_ack_v3();
        DirectOperationOuterAckChainStepV3::derive(
            ack.adapter,
            ack.journal_evidence_snapshot.journal_epoch.clone(),
            ack.journal_evidence_snapshot.previous_ack_watermark,
            ack.journal_evidence_snapshot.last_journal_sequence,
            ack.digest_sha256().unwrap(),
            ack.journal_evidence_snapshot
                .previous_ack_chain_sha256
                .clone(),
        )
        .unwrap()
    }

    fn outer_ack_inbox_v3() -> DirectOperationOuterAckInboxV3 {
        let acknowledgement = outer_ack_v3();
        let chain_step = outer_ack_chain_step_v3();
        DirectOperationOuterAckInboxV3 {
            schema: OUTER_ACK_INBOX_V3_SCHEMA.to_string(),
            acknowledgement_sha256: acknowledgement.digest_sha256().unwrap(),
            chain_step_sha256: chain_step.digest_sha256().unwrap(),
            acknowledgement,
            chain_step,
        }
    }

    #[test]
    fn stable_invocation_excludes_attempt_and_egress_ephemera() {
        let seed = seed();
        let expected = seed.invocation_id().unwrap();
        let mut first = binding();
        first.attempt =
            DirectOperationProviderAttempt::derive(digest('b'), 8, digest('a')).unwrap();
        let mut second = binding();
        second.attempt =
            DirectOperationProviderAttempt::derive(digest('d'), 9, digest('c')).unwrap();
        assert_eq!(first.stable_seed.invocation_id().unwrap(), expected);
        assert_eq!(second.stable_seed.invocation_id().unwrap(), expected);
        assert_ne!(
            first.digest_sha256().unwrap(),
            second.digest_sha256().unwrap()
        );

        let mut encoded = serde_json::to_value(seed).unwrap();
        encoded["egress_grant_id"] = json!("forbidden");
        encoded["nonce"] = json!("forbidden");
        encoded["expires_at_unix_ms"] = json!(42);
        assert!(serde_json::from_value::<DirectOperationStableSeed>(encoded).is_err());
    }

    #[test]
    fn every_stable_identity_component_changes_the_invocation() {
        type SeedMutation = Box<dyn Fn(&mut DirectOperationStableSeed)>;

        let original = seed();
        let expected = original.invocation_id().unwrap();
        let mutations: Vec<SeedMutation> = vec![
            Box::new(|value| value.task_id.push('x')),
            Box::new(|value| value.provider_invocation_id_sha256 = digest('a')),
            Box::new(|value| value.provider_session_id_sha256 = digest('b')),
            Box::new(|value| value.subject_uid += 1),
            Box::new(|value| value.subject_selinux_domain_sha256 = digest('c')),
        ];
        for mutate in mutations {
            let mut candidate = original.clone();
            mutate(&mut candidate);
            assert_ne!(candidate.invocation_id().unwrap(), expected);
        }

        let mut unregistered = original;
        unregistered.provider_id = "unregistered-provider".to_string();
        unregistered.agent_id = "unregistered-agent".to_string();
        assert!(unregistered.invocation_id().is_err());
    }

    #[test]
    fn binding_and_inbox_are_closed_and_digest_bound() {
        let binding = binding();
        binding.validate().unwrap();
        let mut inbox = DirectOperationBindingInbox {
            schema: BINDING_INBOX_SCHEMA.to_string(),
            binding_sha256: binding.digest_sha256().unwrap(),
            binding,
        };
        inbox.validate().unwrap();
        inbox.binding.attempt.runtime_lifecycle_binding_sha256 = digest('e');
        assert!(inbox.validate().is_err());

        let mut value = serde_json::to_value(&inbox).unwrap();
        value["journal_path"] = json!("/attacker");
        value["request_id"] = json!("attacker");
        assert!(serde_json::from_value::<DirectOperationBindingInbox>(value).is_err());
    }

    #[test]
    fn binding_v3_commits_every_os_identity_and_authorized_set_without_changing_invocation() {
        type BindingMutation = Box<dyn Fn(&mut DirectOperationBinding)>;

        let original = binding();
        let original_digest = original.digest_sha256().unwrap();
        let original_invocation = original.invocation_id.clone();
        let mutations: Vec<BindingMutation> = vec![
            Box::new(|value| value.workflow_id_sha256 = digest('9')),
            Box::new(|value| value.agent_identity_key_sha256 = digest('a')),
            Box::new(|value| value.agent_executable_sha256 = digest('b')),
            Box::new(|value| {
                value.authorized_adapter_set =
                    DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility();
            }),
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_eq!(changed.invocation_id, original_invocation);
            assert_eq!(
                changed.stable_seed.invocation_id().unwrap(),
                original_invocation
            );
            assert_ne!(changed.digest_sha256().unwrap(), original_digest);
        }

        let retry = original.clone();
        assert_eq!(retry.invocation_id, original.invocation_id);
        assert_eq!(retry.digest_sha256().unwrap(), original_digest);
        assert_eq!(
            serde_json::to_vec(&retry).unwrap(),
            serde_json::to_vec(&original).unwrap()
        );
    }

    #[test]
    fn binding_v3_rejects_old_schema_missing_unknown_zero_uppercase_and_length_drift() {
        let original = binding();

        let mut old_binding = original.clone();
        old_binding.schema = "trillionnium.direct-operation-binding.v1".to_string();
        assert!(old_binding.validate().is_err());

        let inbox = DirectOperationBindingInbox {
            schema: BINDING_INBOX_SCHEMA.to_string(),
            binding_sha256: original.digest_sha256().unwrap(),
            binding: original.clone(),
        };
        let mut old_inbox = inbox.clone();
        old_inbox.schema = "trillionnium.direct-operation-binding-inbox.v1".to_string();
        assert!(old_inbox.validate().is_err());

        for field in [
            "workflow_id_sha256",
            "agent_identity_key_sha256",
            "agent_executable_sha256",
        ] {
            let mut missing = serde_json::to_value(&original).unwrap();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<DirectOperationBinding>(missing).is_err());

            let mut zero = original.clone();
            match field {
                "workflow_id_sha256" => zero.workflow_id_sha256 = ZERO_SHA256.to_string(),
                "agent_identity_key_sha256" => {
                    zero.agent_identity_key_sha256 = ZERO_SHA256.to_string();
                }
                "agent_executable_sha256" => {
                    zero.agent_executable_sha256 = ZERO_SHA256.to_string();
                }
                _ => unreachable!(),
            }
            assert!(zero.validate().is_err());

            let mut uppercase = serde_json::to_value(&original).unwrap();
            uppercase[field] = json!("A".repeat(64));
            let uppercase: DirectOperationBinding = serde_json::from_value(uppercase).unwrap();
            assert!(uppercase.validate().is_err());

            for drifted_length in [63, 65] {
                let mut length_drift = serde_json::to_value(&original).unwrap();
                length_drift[field] = json!("a".repeat(drifted_length));
                let length_drift: DirectOperationBinding =
                    serde_json::from_value(length_drift).unwrap();
                assert!(length_drift.validate().is_err());
            }
        }

        let mut unknown = serde_json::to_value(original).unwrap();
        unknown["agent_identity_key"] = json!("forbidden");
        assert!(serde_json::from_value::<DirectOperationBinding>(unknown).is_err());
    }

    #[test]
    fn identity_drift_cannot_reuse_an_outer_ack_binding() {
        let trusted = binding();
        let receipt = outer_receipt_v3();
        let ack = outer_ack_v3();
        ack.validate_for_bindings_and_receipt(&trusted, &trusted, &receipt)
            .unwrap();

        for changed in [
            DirectOperationBinding {
                workflow_id_sha256: digest('9'),
                ..trusted.clone()
            },
            DirectOperationBinding {
                agent_identity_key_sha256: digest('a'),
                ..trusted.clone()
            },
            DirectOperationBinding {
                agent_executable_sha256: digest('b'),
                ..trusted.clone()
            },
        ] {
            changed.validate().unwrap();
            assert_eq!(changed.invocation_id, trusted.invocation_id);
            assert!(
                ack.validate_for_bindings_and_receipt(&changed, &trusted, &receipt)
                    .is_err()
            );
        }
    }

    #[test]
    fn authorized_adapter_set_v3_accepts_only_p0_and_reserved_ordered_dual_profiles() {
        let p0 = DirectOperationAuthorizedAdapterSetV3::p0_system_api();
        let dual = DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility();
        p0.validate_p0_system_api().unwrap();
        dual.validate().unwrap();
        assert!(dual.validate_p0_system_api().is_err());
        assert!(p0.authorizes(DirectOperationAdapter::SystemApi));
        assert!(!p0.authorizes(DirectOperationAdapter::Accessibility));
        assert!(dual.authorizes(DirectOperationAdapter::SystemApi));
        assert!(dual.authorizes(DirectOperationAdapter::Accessibility));
        assert_eq!(
            p0.digest_sha256().unwrap(),
            "c6ae5a2c8923d96d6e4b8050bbbdb3a1ea5322259306c646a1475c354b2ea29b"
        );
        assert_eq!(
            dual.digest_sha256().unwrap(),
            "fe4e90c4d1fb4729f34d14c4621cd0f6ab9baa82da99cffb2c80dc91ae700987"
        );

        for adapters in [
            vec![],
            vec![DirectOperationAdapter::Accessibility],
            vec![
                DirectOperationAdapter::SystemApi,
                DirectOperationAdapter::SystemApi,
            ],
            vec![
                DirectOperationAdapter::Accessibility,
                DirectOperationAdapter::SystemApi,
            ],
            vec![
                DirectOperationAdapter::SystemApi,
                DirectOperationAdapter::Accessibility,
                DirectOperationAdapter::Accessibility,
            ],
        ] {
            let candidate = DirectOperationAuthorizedAdapterSetV3 {
                schema: AUTHORIZED_ADAPTER_SET_V3_SCHEMA.to_string(),
                authorized_adapters: adapters,
                authorized_adapters_sha256: digest('1'),
            };
            assert!(candidate.validate().is_err());
        }

        let mut wrong_schema = p0.clone();
        wrong_schema.schema = "trillionnium.direct-operation-authorized-adapter-set.v1".to_string();
        assert!(wrong_schema.validate().is_err());
        let mut digest_drift = p0;
        digest_drift.authorized_adapters_sha256 = digest('2');
        assert!(digest_drift.validate().is_err());
    }

    #[test]
    fn outer_ack_v3_contains_only_ordered_digest_evidence_and_rejects_old_schemas() {
        let mut inbox = outer_ack_inbox_v3();
        inbox.validate().unwrap();

        inbox.acknowledgement.journal_evidence_snapshot.evidence[0].backend_result_sha256 =
            digest('1');
        assert!(inbox.validate().is_err());

        let exact = outer_ack_inbox_v3();
        let mut raw = serde_json::to_value(&exact).unwrap();
        raw["acknowledgement"]["journal_evidence_snapshot"]["evidence"][0]["uri"] =
            json!("content://secret");
        assert!(serde_json::from_value::<DirectOperationOuterAckInboxV3>(raw).is_err());

        for old_schema in [
            "trillionnium.direct-operation-outer-ack-inbox.v1",
            "trillionnium.direct-operation-outer-ack-inbox.v2",
        ] {
            let mut old = exact.clone();
            old.schema = old_schema.to_string();
            assert!(old.validate().is_err());
        }
        for old_schema in [
            "trillionnium.direct-operation-outer-ack.v1",
            "trillionnium.direct-operation-outer-ack.v2",
        ] {
            let mut old = exact.acknowledgement.clone();
            old.schema = old_schema.to_string();
            assert!(old.validate().is_err());
        }
    }

    #[test]
    fn structurally_valid_v3_cross_binding_ack_is_rejected_by_context_match() {
        let trusted = binding();
        let receipt = outer_receipt_v3();
        let ack = outer_ack_v3();
        ack.validate().unwrap();
        ack.validate_for_bindings_and_receipt(&trusted, &trusted, &receipt)
            .unwrap();

        let mut cross_task = trusted.clone();
        cross_task.stable_seed.task_id = "task-cross-binding".to_string();
        cross_task.invocation_id = cross_task.stable_seed.invocation_id().unwrap();
        cross_task.validate().unwrap();
        assert!(
            ack.validate_for_bindings_and_receipt(&cross_task, &trusted, &receipt)
                .is_err()
        );
        let mut cross_adapter = ack;
        cross_adapter.adapter = DirectOperationAdapter::Accessibility;
        assert!(cross_adapter.validate().is_err());
    }

    #[test]
    fn outer_ack_v3_rejects_tool_outcome_order_and_digest_forgery() {
        let mut wrong_tool = outer_ack_v3();
        wrong_tool.journal_evidence_snapshot.evidence[0].tool =
            "trillionnium_accessibility".to_string();
        assert!(wrong_tool.validate().is_err());

        let mut contradiction = outer_ack_v3();
        contradiction.journal_evidence_snapshot.evidence[0].backend_error_code =
            Some("request_in_flight".to_string());
        assert!(contradiction.validate().is_err());

        let mut duplicate = outer_ack_v3();
        duplicate
            .journal_evidence_snapshot
            .evidence
            .push(duplicate.journal_evidence_snapshot.evidence[0].clone());
        assert!(duplicate.validate().is_err());

        let mut indeterminate = outer_ack_v3();
        indeterminate.journal_evidence_snapshot.evidence[0].outcome =
            DirectOperationOuterOutcome::Indeterminate;
        indeterminate.journal_evidence_snapshot.evidence[0].backend_error_code =
            Some("effect_indeterminate".to_string());
        assert!(indeterminate.validate().is_err());

        let mut zero_sequence = outer_ack_v3();
        zero_sequence.journal_evidence_snapshot.evidence[0].journal_sequence = 0;
        assert!(zero_sequence.validate().is_err());

        let mut oversized_sequence = outer_ack_v3();
        oversized_sequence.journal_evidence_snapshot.evidence[0].journal_sequence =
            MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE + 1;
        assert!(oversized_sequence.validate().is_err());

        let mut oversized_set = outer_ack_v3();
        let template = oversized_set.journal_evidence_snapshot.evidence[0].clone();
        oversized_set.journal_evidence_snapshot.evidence = (0..=MAX_OUTER_ACK_EVIDENCE)
            .map(|index| DirectOperationOuterEvidence {
                adapter_effect_ordinal: index as u64,
                journal_sequence: index as u64 + 1,
                ..template.clone()
            })
            .collect();
        assert_eq!(oversized_set.journal_evidence_snapshot.evidence.len(), 257);
        assert!(oversized_set.validate().is_err());
    }

    #[test]
    fn recovery_delivery_attempt_may_differ_from_one_uniform_allocating_attempt() {
        let delivery_binding = binding();
        let delivery_attempt_b = delivery_binding
            .attempt
            .delivery_provider_attempt_id
            .clone();
        let allocating_attempt_a =
            DirectOperationProviderAttempt::derive(digest('a'), 11, digest('b')).unwrap();
        let allocating_attempt_c =
            DirectOperationProviderAttempt::derive(digest('c'), 12, digest('d'))
                .unwrap()
                .delivery_provider_attempt_id;
        assert_ne!(
            delivery_attempt_b,
            allocating_attempt_a.delivery_provider_attempt_id
        );

        let mut allocation_binding = delivery_binding.clone();
        allocation_binding.attempt = allocating_attempt_a;
        let allocating_attempt_id = allocation_binding
            .attempt
            .delivery_provider_attempt_id
            .clone();
        let mut snapshot = journal_snapshot_v1();
        snapshot.allocation_binding_sha256 = allocation_binding.digest_sha256().unwrap();
        snapshot.allocating_provider_attempt_id = allocating_attempt_id.clone();
        for evidence in &mut snapshot.evidence {
            evidence.allocating_provider_attempt_id = allocating_attempt_id.clone();
        }
        snapshot.evidence_sha256 = snapshot.evidence_digest_sha256().unwrap();
        snapshot.validate().unwrap();

        let mut receipt = outer_receipt_v3();
        receipt.adapter_terminal_dispositions = vec![terminal_disposition(
            delivery_binding.clone(),
            DirectOperationAdapter::SystemApi,
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot: snapshot,
            },
        )];
        receipt.adapter_terminal_dispositions_sha256 =
            receipt.adapter_dispositions_digest_sha256().unwrap();
        receipt.validate_for_binding(&delivery_binding).unwrap();
        let mut acknowledgement =
            outer_ack_for_receipt(&receipt, DirectOperationAdapter::SystemApi);
        acknowledgement
            .validate_for_bindings_and_receipt(&delivery_binding, &allocation_binding, &receipt)
            .unwrap();

        acknowledgement.journal_evidence_snapshot.evidence[1].allocating_provider_attempt_id =
            allocating_attempt_c;
        acknowledgement.journal_evidence_snapshot.evidence_sha256 = acknowledgement
            .journal_evidence_snapshot
            .evidence_digest_sha256()
            .unwrap();
        acknowledgement.journal_evidence_snapshot_sha256 = acknowledgement
            .journal_evidence_snapshot
            .digest_sha256()
            .unwrap_err()
            .to_string();
        assert!(acknowledgement.validate().is_err());
    }

    #[test]
    fn v3_snapshot_receipt_ack_and_chain_have_stable_golden_digests() {
        let allocation_binding = binding();
        let snapshot = journal_snapshot_v1();
        snapshot.validate().unwrap();
        snapshot
            .validate_for_allocation_binding(&allocation_binding, DirectOperationAdapter::SystemApi)
            .unwrap();

        let receipt = outer_receipt_v3();
        receipt.validate().unwrap();
        receipt.validate_for_binding(&binding()).unwrap();

        let ack = outer_ack_v3();
        ack.validate().unwrap();
        ack.validate_for_outer_receipt(&receipt).unwrap();
        ack.validate_for_bindings_and_receipt(&binding(), &allocation_binding, &receipt)
            .unwrap();

        let chain = outer_ack_chain_step_v3();
        chain.validate().unwrap();
        chain.validate_for_ack(&ack).unwrap();

        let inbox = outer_ack_inbox_v3();
        inbox.validate().unwrap();
        inbox
            .validate_for_bindings_and_receipt(&binding(), &allocation_binding, &receipt)
            .unwrap();

        assert_eq!(
            snapshot.digest_sha256().unwrap(),
            "239608b97778f8008c77b8b70fe05837db3946b885747cf9f56dbb058b5e700f"
        );
        assert_eq!(
            receipt.digest_sha256().unwrap(),
            "2b4ab51794b5532ad3ed4f8972cdce5f4347c1cc59578923a389d01eed3f772a"
        );
        assert_eq!(
            ack.digest_sha256().unwrap(),
            "790d77ebc4b77fbc4e4f00a45111162740f791508b6161da46b7f1bdbdd38eca"
        );
        assert_eq!(
            chain.authenticated_ack_chain_sha256,
            "27b80aa464d59c5d66afa10c0b9e17ddd36941c0a4ae50c958fc5447bb100b52"
        );
        assert_eq!(
            chain.digest_sha256().unwrap(),
            "c615ac7d60317c1c850d5cadd4869cf37f70e50705f5667e66193bf302ec1eeb"
        );
    }

    #[test]
    fn v3_contracts_are_closed_and_carry_no_raw_request_or_result() {
        let mut snapshot = serde_json::to_value(journal_snapshot_v1()).unwrap();
        snapshot["raw_request"] = json!({"uri": "content://secret"});
        assert!(
            serde_json::from_value::<DirectOperationJournalEvidenceSnapshotV1>(snapshot).is_err()
        );

        let mut receipt = serde_json::to_value(outer_receipt_v3()).unwrap();
        receipt["provider_result"] = json!({"text": "secret"});
        assert!(serde_json::from_value::<DirectOperationOuterReceiptV3>(receipt).is_err());

        let mut ack = serde_json::to_value(outer_ack_v3()).unwrap();
        ack["lease"] = json!({"raw": "forbidden"});
        assert!(serde_json::from_value::<DirectOperationOuterAckV3>(ack).is_err());

        let mut chain = serde_json::to_value(outer_ack_chain_step_v3()).unwrap();
        chain["backend_response"] = json!("forbidden");
        assert!(serde_json::from_value::<DirectOperationOuterAckChainStepV3>(chain).is_err());

        let mut inbox = serde_json::to_value(outer_ack_inbox_v3()).unwrap();
        inbox["publisher_path"] = json!("/forbidden");
        assert!(serde_json::from_value::<DirectOperationOuterAckInboxV3>(inbox).is_err());

        let mut nested = serde_json::to_value(outer_ack_v3()).unwrap();
        nested["journal_evidence_snapshot"]["evidence"][0]["text"] = json!("secret");
        assert!(serde_json::from_value::<DirectOperationOuterAckV3>(nested).is_err());
    }

    #[test]
    fn v3_snapshot_rejects_identity_count_order_and_outcome_drift() {
        let trusted_binding = binding();
        let snapshot = journal_snapshot_v1();

        let mut cross_binding = trusted_binding.clone();
        cross_binding.stable_seed.task_id = "task-cross-allocation".to_string();
        cross_binding.invocation_id = cross_binding.stable_seed.invocation_id().unwrap();
        cross_binding.validate().unwrap();
        assert!(
            snapshot
                .validate_for_allocation_binding(&cross_binding, DirectOperationAdapter::SystemApi,)
                .is_err()
        );
        assert!(
            snapshot
                .validate_for_allocation_binding(
                    &trusted_binding,
                    DirectOperationAdapter::Accessibility,
                )
                .is_err()
        );

        let mut provider_mismatch = snapshot.clone();
        provider_mismatch.provider_id = "unregistered-provider".to_string();
        assert!(provider_mismatch.validate().is_err());

        let mut agent_mismatch = snapshot.clone();
        agent_mismatch.agent_id = "unregistered-agent".to_string();
        assert!(agent_mismatch.validate().is_err());

        let mut allocation_count = snapshot.clone();
        allocation_count.journal_allocation_count += 1;
        assert!(allocation_count.validate().is_err());

        let mut evidence_count = snapshot.clone();
        evidence_count.journal_evidence_count -= 1;
        assert!(evidence_count.validate().is_err());

        let mut forged_genesis = snapshot.clone();
        forged_genesis.previous_ack_chain_sha256 = digest('1');
        assert!(forged_genesis.validate().is_err());

        let mut missing_prior_chain = snapshot.clone();
        missing_prior_chain.previous_ack_watermark = 1;
        assert!(missing_prior_chain.validate().is_err());

        let mut discontinuous_prior = snapshot.clone();
        discontinuous_prior.previous_ack_watermark = 1;
        discontinuous_prior.previous_ack_chain_sha256 = digest('1');
        assert!(discontinuous_prior.validate().is_err());

        let mut sequence_gap = snapshot.clone();
        sequence_gap.evidence[1].journal_sequence += 1;
        sequence_gap.last_journal_sequence += 1;
        sequence_gap.evidence_sha256 = sequence_gap.evidence_digest_sha256().unwrap();
        assert!(sequence_gap.validate().is_err());

        let mut reversed = snapshot.clone();
        reversed.evidence.reverse();
        reversed.evidence_sha256 = reversed.evidence_digest_sha256().unwrap();
        assert!(reversed.validate().is_err());

        let mut wrong_ordinal = snapshot.clone();
        wrong_ordinal.evidence[1].adapter_effect_ordinal = 2;
        wrong_ordinal.evidence_sha256 = wrong_ordinal.evidence_digest_sha256().unwrap();
        assert!(wrong_ordinal.validate().is_err());

        let mut digest_drift = snapshot.clone();
        digest_drift.evidence_sha256 = digest('f');
        assert!(digest_drift.validate().is_err());

        let mut indeterminate = snapshot.clone();
        indeterminate.evidence[0].outcome = DirectOperationOuterOutcome::Indeterminate;
        indeterminate.evidence[0].backend_error_code = Some("effect_indeterminate".to_string());
        assert!(indeterminate.validate().is_err());
        assert!(indeterminate.evidence_digest_sha256().is_err());
    }

    #[test]
    fn v3_terminal_dispositions_enforce_authorized_adapter_policy_and_ackability() {
        let trusted_binding = dual_binding();
        let no_operations = accessibility_no_operations_disposition();
        no_operations.validate().unwrap();
        no_operations
            .validate_for_binding(&trusted_binding, DirectOperationAdapter::Accessibility)
            .unwrap();
        assert!(
            no_operations
                .validate_for_binding(&binding(), DirectOperationAdapter::Accessibility)
                .is_err()
        );
        assert!(no_operations.ackable_snapshot().is_err());

        let mut held = no_operations.clone();
        held.terminal_state = DirectOperationAdapterTerminalStateV1::HeldIndeterminate {
            journal_epoch: "02".repeat(16),
            journal_payload_sha256: digest('e'),
            previous_ack_watermark: 0,
            previous_ack_chain_sha256: ZERO_SHA256.to_string(),
            authenticated_hold_sha256: digest('2'),
        };
        held.validate().unwrap();
        assert!(held.ackable_snapshot().is_err());
        assert_ne!(
            held.digest_sha256().unwrap(),
            no_operations.digest_sha256().unwrap()
        );

        let mut cross_binding = no_operations.clone();
        cross_binding.binding_sha256 = digest('3');
        cross_binding.validate().unwrap();
        assert!(
            cross_binding
                .validate_for_binding(&trusted_binding, DirectOperationAdapter::Accessibility)
                .is_err()
        );

        let mut cross_provider = no_operations.clone();
        cross_provider.provider_id = "unregistered-provider".to_string();
        cross_provider.agent_id = "unregistered-agent".to_string();
        assert!(cross_provider.validate().is_err());

        let mut raw = serde_json::to_value(&no_operations).unwrap();
        raw["terminal_state"]["raw_result"] = json!("forbidden");
        assert!(
            serde_json::from_value::<DirectOperationAdapterTerminalDispositionV1>(raw).is_err()
        );

        let mut variant_only_drift = serde_json::to_value(&no_operations).unwrap();
        variant_only_drift["terminal_state"]["disposition"] = json!("held_indeterminate");
        assert!(
            serde_json::from_value::<DirectOperationAdapterTerminalDispositionV1>(
                variant_only_drift
            )
            .is_err()
        );

        let mut accessibility_snapshot = journal_snapshot_v1();
        accessibility_snapshot.adapter = DirectOperationAdapter::Accessibility;
        accessibility_snapshot.journal_epoch = "02".repeat(16);
        accessibility_snapshot.journal_payload_sha256 = digest('e');
        for evidence in &mut accessibility_snapshot.evidence {
            evidence.tool = DirectOperationAdapter::Accessibility
                .tool_name()
                .to_string();
        }
        accessibility_snapshot.evidence_sha256 =
            accessibility_snapshot.evidence_digest_sha256().unwrap();
        accessibility_snapshot.validate().unwrap();

        let receipt = dual_outer_receipt_v3();
        let candidate = DirectOperationOuterAckV3 {
            schema: OUTER_ACK_V3_SCHEMA.to_string(),
            binding_sha256: receipt.binding_sha256.clone(),
            invocation_id: receipt.invocation_id.clone(),
            delivery_provider_attempt_id: receipt.delivery_provider_attempt_id.clone(),
            provider_id: receipt.provider_id.clone(),
            agent_id: receipt.agent_id.clone(),
            adapter: DirectOperationAdapter::Accessibility,
            authorized_adapter_set_sha256: receipt.authorized_adapter_set.digest_sha256().unwrap(),
            outer_receipt_sha256: receipt.digest_sha256().unwrap(),
            journal_evidence_snapshot_sha256: accessibility_snapshot.digest_sha256().unwrap(),
            journal_evidence_snapshot: accessibility_snapshot,
        };
        candidate.validate().unwrap();
        assert!(candidate.validate_for_outer_receipt(&receipt).is_err());

        let mut held_receipt = receipt.clone();
        held_receipt.adapter_terminal_dispositions[1] = held;
        held_receipt.adapter_terminal_dispositions_sha256 =
            held_receipt.adapter_dispositions_digest_sha256().unwrap();
        held_receipt.validate().unwrap();
        let mut system_ack_with_opposite_hold =
            outer_ack_for_receipt(&receipt, DirectOperationAdapter::SystemApi);
        system_ack_with_opposite_hold.outer_receipt_sha256 = held_receipt.digest_sha256().unwrap();
        system_ack_with_opposite_hold
            .validate_for_outer_receipt(&held_receipt)
            .unwrap();
        assert!(candidate.validate_for_outer_receipt(&held_receipt).is_err());
    }

    #[test]
    fn v3_receipt_binds_completion_proofs_and_exact_ordered_authorized_dispositions() {
        type ReceiptMutation = Box<dyn Fn(&mut DirectOperationOuterReceiptV3)>;

        let receipt = dual_outer_receipt_v3();
        let expected = receipt.digest_sha256().unwrap();
        let mutations: Vec<ReceiptMutation> = vec![
            Box::new(|value| value.direct_execution_receipt_sha256 = digest('1')),
            Box::new(|value| value.ui_replay_completion_proof_sha256 = digest('2')),
            Box::new(|value| value.ui_replay_semantic_sha256 = digest('3')),
            Box::new(|value| value.terminal_egress_cas_sha256 = digest('4')),
            Box::new(|value| value.runtime_evidence_sha256 = digest('5')),
            Box::new(|value| value.provider_teardown_completion_ack_sha256 = digest('6')),
        ];
        for mutate in mutations {
            let mut candidate = receipt.clone();
            mutate(&mut candidate);
            candidate.validate().unwrap();
            assert_ne!(candidate.digest_sha256().unwrap(), expected);
        }

        let mut omitted = receipt.clone();
        omitted.adapter_terminal_dispositions.pop();
        assert!(omitted.validate().is_err());

        let mut reversed = receipt.clone();
        reversed.adapter_terminal_dispositions.reverse();
        assert!(reversed.adapter_dispositions_digest_sha256().is_err());
        assert!(reversed.validate().is_err());

        let mut duplicate = receipt.clone();
        duplicate.adapter_terminal_dispositions[1] =
            duplicate.adapter_terminal_dispositions[0].clone();
        assert!(duplicate.adapter_dispositions_digest_sha256().is_err());
        assert!(duplicate.validate().is_err());

        let mut unauthenticated_disposition_drift = receipt.clone();
        unauthenticated_disposition_drift.adapter_terminal_dispositions[1].terminal_state =
            DirectOperationAdapterTerminalStateV1::HeldIndeterminate {
                journal_epoch: "02".repeat(16),
                journal_payload_sha256: digest('e'),
                previous_ack_watermark: 0,
                previous_ack_chain_sha256: ZERO_SHA256.to_string(),
                authenticated_hold_sha256: digest('2'),
            };
        assert!(unauthenticated_disposition_drift.validate().is_err());

        let mut held = unauthenticated_disposition_drift;
        held.adapter_terminal_dispositions_sha256 =
            held.adapter_dispositions_digest_sha256().unwrap();
        held.validate().unwrap();
        assert_ne!(
            held.digest_sha256().unwrap(),
            receipt.digest_sha256().unwrap()
        );
    }

    #[test]
    fn p0_receipt_allows_only_one_system_api_disposition_and_dual_is_future_only() {
        let p0 = outer_receipt_v3();
        p0.validate_for_binding(&binding()).unwrap();
        assert_eq!(
            p0.authorized_adapter_set.authorized_adapters,
            [DirectOperationAdapter::SystemApi]
        );
        assert_eq!(p0.adapter_terminal_dispositions.len(), 1);

        let mut extra = p0.clone();
        extra
            .adapter_terminal_dispositions
            .push(accessibility_no_operations_disposition());
        assert!(extra.adapter_dispositions_digest_sha256().is_err());
        assert!(extra.validate().is_err());

        let mut accessibility_only = p0;
        accessibility_only.adapter_terminal_dispositions =
            vec![accessibility_no_operations_disposition()];
        assert!(
            accessibility_only
                .adapter_dispositions_digest_sha256()
                .is_err()
        );
        assert!(accessibility_only.validate().is_err());

        let dual = dual_outer_receipt_v3();
        dual.validate_for_binding(&dual_binding()).unwrap();
        assert_eq!(
            dual.authorized_adapter_set.authorized_adapters,
            [
                DirectOperationAdapter::SystemApi,
                DirectOperationAdapter::Accessibility,
            ]
        );
    }

    #[test]
    fn v3_ack_rejects_cross_authorized_set_replay_and_old_schema_splice() {
        let p0_receipt = outer_receipt_v3();
        let p0_ack = outer_ack_v3();
        let dual_receipt = dual_outer_receipt_v3();
        let dual_system_ack =
            outer_ack_for_receipt(&dual_receipt, DirectOperationAdapter::SystemApi);

        assert!(p0_ack.validate_for_outer_receipt(&dual_receipt).is_err());
        assert!(
            dual_system_ack
                .validate_for_outer_receipt(&p0_receipt)
                .is_err()
        );

        let mut old_receipt = p0_receipt;
        old_receipt.schema = "trillionnium.direct-operation-outer-receipt.v2".to_string();
        assert!(old_receipt.validate().is_err());
        let mut old_ack = p0_ack;
        old_ack.schema = "trillionnium.direct-operation-outer-ack.v2".to_string();
        assert!(old_ack.validate().is_err());

        let legacy_command = br#"{"command":"observe_disposition","schema":"trillionnium.direct-operation-replay-sync-command.v1","binding_sha256":"1111111111111111111111111111111111111111111111111111111111111111","launch_challenge_sha256":"2222222222222222222222222222222222222222222222222222222222222222"}"#;
        assert!(DirectOperationReplaySyncCommandV3::from_canonical_json(legacy_command).is_err());
    }

    #[test]
    fn v3_ack_rejects_receipt_binding_provider_agent_adapter_and_epoch_drift() {
        let receipt = outer_receipt_v3();
        let ack = outer_ack_v3();

        let mut receipt_binding_drift = receipt.clone();
        receipt_binding_drift.binding_sha256 = digest('1');
        for disposition in &mut receipt_binding_drift.adapter_terminal_dispositions {
            disposition.binding_sha256 = digest('1');
        }
        receipt_binding_drift.adapter_terminal_dispositions_sha256 = receipt_binding_drift
            .adapter_dispositions_digest_sha256()
            .unwrap();
        receipt_binding_drift.validate().unwrap();
        assert!(
            ack.validate_for_outer_receipt(&receipt_binding_drift)
                .is_err()
        );

        let mut provider_drift = ack.clone();
        provider_drift.provider_id = "unregistered-provider".to_string();
        provider_drift.agent_id = "unregistered-agent".to_string();
        assert!(provider_drift.validate().is_err());

        let mut adapter_drift = ack.clone();
        adapter_drift.adapter = DirectOperationAdapter::Accessibility;
        assert!(adapter_drift.validate().is_err());

        let mut epoch_drift = ack.clone();
        epoch_drift.journal_evidence_snapshot.journal_epoch = "03".repeat(16);
        epoch_drift.journal_evidence_snapshot_sha256 = epoch_drift
            .journal_evidence_snapshot
            .digest_sha256()
            .unwrap();
        epoch_drift.validate().unwrap();
        assert!(epoch_drift.validate_for_outer_receipt(&receipt).is_err());

        let mut snapshot_digest_drift = ack.clone();
        snapshot_digest_drift.journal_evidence_snapshot_sha256 = digest('6');
        assert!(snapshot_digest_drift.validate().is_err());

        let mut outer_digest_drift = ack.clone();
        outer_digest_drift.outer_receipt_sha256 = digest('5');
        outer_digest_drift.validate().unwrap();
        assert!(
            outer_digest_drift
                .validate_for_outer_receipt(&receipt)
                .is_err()
        );
    }

    #[test]
    fn v3_ack_chain_enforces_genesis_continuity_and_exact_ack() {
        let ack = outer_ack_v3();
        let chain = outer_ack_chain_step_v3();

        let mut chain_digest_drift = chain.clone();
        chain_digest_drift.authenticated_ack_chain_sha256 = digest('f');
        assert!(chain_digest_drift.validate().is_err());

        assert!(
            DirectOperationOuterAckChainStepV3::derive(
                ack.adapter,
                ack.journal_evidence_snapshot.journal_epoch.clone(),
                0,
                2,
                ack.digest_sha256().unwrap(),
                digest('1'),
            )
            .is_err()
        );
        assert!(
            DirectOperationOuterAckChainStepV3::derive(
                ack.adapter,
                ack.journal_evidence_snapshot.journal_epoch.clone(),
                1,
                2,
                ack.digest_sha256().unwrap(),
                ZERO_SHA256.to_string(),
            )
            .is_err()
        );

        let discontinuous = DirectOperationOuterAckChainStepV3::derive(
            ack.adapter,
            ack.journal_evidence_snapshot.journal_epoch.clone(),
            1,
            2,
            ack.digest_sha256().unwrap(),
            digest('1'),
        )
        .unwrap();
        assert!(discontinuous.validate_for_ack(&ack).is_err());

        let short = DirectOperationOuterAckChainStepV3::derive(
            ack.adapter,
            ack.journal_evidence_snapshot.journal_epoch.clone(),
            0,
            1,
            ack.digest_sha256().unwrap(),
            ZERO_SHA256.to_string(),
        )
        .unwrap();
        assert!(short.validate_for_ack(&ack).is_err());

        let wrong_ack = DirectOperationOuterAckChainStepV3::derive(
            ack.adapter,
            ack.journal_evidence_snapshot.journal_epoch.clone(),
            0,
            2,
            digest('1'),
            ZERO_SHA256.to_string(),
        )
        .unwrap();
        assert!(wrong_ack.validate_for_ack(&ack).is_err());

        let wrong_adapter = DirectOperationOuterAckChainStepV3::derive(
            DirectOperationAdapter::Accessibility,
            ack.journal_evidence_snapshot.journal_epoch.clone(),
            0,
            2,
            ack.digest_sha256().unwrap(),
            ZERO_SHA256.to_string(),
        )
        .unwrap();
        assert!(wrong_adapter.validate_for_ack(&ack).is_err());

        let wrong_epoch = DirectOperationOuterAckChainStepV3::derive(
            ack.adapter,
            "04".repeat(16),
            0,
            2,
            ack.digest_sha256().unwrap(),
            ZERO_SHA256.to_string(),
        )
        .unwrap();
        assert!(wrong_epoch.validate_for_ack(&ack).is_err());
    }

    #[test]
    fn v3_ack_inbox_recomputes_both_digests_and_cross_binds_chain() {
        let inbox = outer_ack_inbox_v3();
        inbox.validate().unwrap();

        let mut ack_digest_drift = inbox.clone();
        ack_digest_drift.acknowledgement_sha256 = digest('1');
        assert!(ack_digest_drift.validate().is_err());

        let mut chain_digest_drift = inbox.clone();
        chain_digest_drift.chain_step_sha256 = digest('2');
        assert!(chain_digest_drift.validate().is_err());

        let mut cross_ack = inbox.clone();
        cross_ack.chain_step = DirectOperationOuterAckChainStepV3::derive(
            cross_ack.acknowledgement.adapter,
            cross_ack
                .acknowledgement
                .journal_evidence_snapshot
                .journal_epoch
                .clone(),
            0,
            2,
            digest('3'),
            ZERO_SHA256.to_string(),
        )
        .unwrap();
        cross_ack.chain_step_sha256 = cross_ack.chain_step.digest_sha256().unwrap();
        assert!(cross_ack.validate().is_err());

        let mut embedded_ack_drift = inbox.clone();
        embedded_ack_drift
            .acknowledgement
            .journal_evidence_snapshot
            .journal_payload_sha256 = digest('4');
        embedded_ack_drift
            .acknowledgement
            .journal_evidence_snapshot_sha256 = embedded_ack_drift
            .acknowledgement
            .journal_evidence_snapshot
            .digest_sha256()
            .unwrap();
        embedded_ack_drift.acknowledgement_sha256 =
            embedded_ack_drift.acknowledgement.digest_sha256().unwrap();
        assert!(embedded_ack_drift.validate().is_err());
    }

    #[test]
    fn v3_contracts_reject_uppercase_and_forbidden_zero_digests() {
        let mut snapshot = journal_snapshot_v1();
        snapshot.journal_payload_sha256 = "A".repeat(64);
        assert!(snapshot.validate().is_err());

        let mut snapshot = journal_snapshot_v1();
        snapshot.allocation_binding_sha256 = ZERO_SHA256.to_string();
        assert!(snapshot.validate().is_err());

        let mut snapshot = journal_snapshot_v1();
        snapshot.evidence[0].backend_result_sha256 = ZERO_SHA256.to_string();
        assert!(snapshot.validate().is_err());

        let mut receipt = outer_receipt_v3();
        receipt.ui_replay_completion_proof_sha256 = ZERO_SHA256.to_string();
        assert!(receipt.validate().is_err());

        let mut receipt = outer_receipt_v3();
        receipt.runtime_evidence_sha256 = "F".repeat(64);
        assert!(receipt.validate().is_err());

        let mut no_operations = accessibility_no_operations_disposition();
        if let DirectOperationAdapterTerminalStateV1::NoOperations {
            authenticated_terminal_sha256,
            ..
        } = &mut no_operations.terminal_state
        {
            *authenticated_terminal_sha256 = ZERO_SHA256.to_string();
        }
        assert!(no_operations.validate().is_err());

        let mut held = accessibility_no_operations_disposition();
        held.terminal_state = DirectOperationAdapterTerminalStateV1::HeldIndeterminate {
            journal_epoch: "02".repeat(16),
            journal_payload_sha256: digest('e'),
            previous_ack_watermark: 0,
            previous_ack_chain_sha256: ZERO_SHA256.to_string(),
            authenticated_hold_sha256: "A".repeat(64),
        };
        assert!(held.validate().is_err());

        let mut ack = outer_ack_v3();
        ack.outer_receipt_sha256 = ZERO_SHA256.to_string();
        assert!(ack.validate().is_err());

        let mut chain = outer_ack_chain_step_v3();
        chain.acknowledgement_sha256 = "A".repeat(64);
        assert!(chain.validate().is_err());

        let mut chain = outer_ack_chain_step_v3();
        chain.authenticated_ack_chain_sha256 = ZERO_SHA256.to_string();
        assert!(chain.validate().is_err());
    }

    #[test]
    fn operation_replay_sync_contracts_are_canonical_digest_bound_and_closed() {
        let command = DirectOperationReplaySyncCommandV3::ObserveDisposition {
            schema: OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA.to_string(),
            binding_sha256: digest('1'),
            launch_challenge_sha256: digest('2'),
        };
        command.validate().unwrap();
        assert_eq!(command.opcode(), 1);
        let canonical_command = command.canonical_json().unwrap();
        assert_eq!(
            DirectOperationReplaySyncCommandV3::from_canonical_json(&canonical_command).unwrap(),
            command
        );
        assert!(valid_nonzero_sha256(&command.digest_sha256().unwrap()));

        let expected_ack_intent = digest('3');
        let apply = DirectOperationReplaySyncCommandV3::ApplyAck {
            schema: OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA.to_string(),
            binding_sha256: digest('1'),
            ack_intent_sha256: expected_ack_intent.clone(),
            launch_challenge_sha256: digest('2'),
            p0_sealed_authority: None,
        };
        apply.validate().unwrap();
        apply.validate_product_lane().unwrap();
        assert!(apply.validate_p0_daemon_custody_lane().is_err());
        assert_eq!(apply.opcode(), 2);
        assert_eq!(
            apply.ack_intent_sha256(),
            Some(expected_ack_intent.as_str())
        );
        let canonical_apply = apply.canonical_json().unwrap();
        assert_eq!(
            DirectOperationReplaySyncCommandV3::from_canonical_json(&canonical_apply).unwrap(),
            apply
        );
        assert_ne!(
            command.digest_sha256().unwrap(),
            apply.digest_sha256().unwrap()
        );

        for invalid in [
            DirectOperationReplaySyncCommandV3::ObserveDisposition {
                schema: "wrong".to_string(),
                binding_sha256: digest('1'),
                launch_challenge_sha256: digest('2'),
            },
            DirectOperationReplaySyncCommandV3::ObserveDisposition {
                schema: OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA.to_string(),
                binding_sha256: ZERO_SHA256.to_string(),
                launch_challenge_sha256: digest('2'),
            },
            DirectOperationReplaySyncCommandV3::ObserveDisposition {
                schema: OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA.to_string(),
                binding_sha256: digest('1'),
                launch_challenge_sha256: ZERO_SHA256.to_string(),
            },
            DirectOperationReplaySyncCommandV3::ApplyAck {
                schema: OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA.to_string(),
                binding_sha256: digest('1'),
                ack_intent_sha256: ZERO_SHA256.to_string(),
                launch_challenge_sha256: digest('2'),
                p0_sealed_authority: None,
            },
        ] {
            assert!(invalid.validate().is_err());
        }

        let ack_intent = outer_ack_inbox_v3()
            .operation_replay_sync_ack_intent_sha256()
            .unwrap();
        assert!(valid_nonzero_sha256(&ack_intent));

        let disposition = system_api_ackable_disposition();
        let mut observation = DirectOperationReplaySyncObservationV3 {
            schema: OPERATION_REPLAY_SYNC_OBSERVATION_V3_SCHEMA.to_string(),
            terminal_disposition_sha256: disposition.digest_sha256().unwrap(),
            journal_state_sha256: digest('d'),
            journal_file_identity_sha256: digest('3'),
            terminal_disposition: disposition,
        };
        observation.validate().unwrap();
        let canonical_observation = observation.canonical_json().unwrap();
        assert_eq!(
            DirectOperationReplaySyncObservationV3::from_canonical_json(&canonical_observation)
                .unwrap(),
            observation
        );
        assert!(valid_nonzero_sha256(&observation.digest_sha256().unwrap()));

        let mut confirmation = DirectOperationReplaySyncAckConfirmationV3 {
            schema: OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA.to_string(),
            ack_intent_sha256: digest('4'),
            android_ack_echo_sha256: digest('5'),
            acknowledgement_sha256: digest('6'),
            authenticated_ack_chain_sha256: digest('7'),
            compacted_ack_watermark: 2,
            post_compaction_journal_sha256: digest('8'),
            journal_file_identity_sha256: digest('9'),
            mutation_cas_committed_head_sha256: digest('a'),
        };
        confirmation.validate().unwrap();
        let canonical_confirmation = confirmation.canonical_json().unwrap();
        assert_eq!(
            DirectOperationReplaySyncAckConfirmationV3::from_canonical_json(
                &canonical_confirmation
            )
            .unwrap(),
            confirmation
        );
        assert!(valid_nonzero_sha256(&confirmation.digest_sha256().unwrap()));

        for invalid in [
            DirectOperationReplaySyncAckConfirmationV3 {
                schema: "wrong".to_string(),
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                ack_intent_sha256: ZERO_SHA256.to_string(),
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                android_ack_echo_sha256: ZERO_SHA256.to_string(),
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                acknowledgement_sha256: ZERO_SHA256.to_string(),
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                authenticated_ack_chain_sha256: ZERO_SHA256.to_string(),
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                compacted_ack_watermark: 0,
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                compacted_ack_watermark: MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE + 1,
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                post_compaction_journal_sha256: ZERO_SHA256.to_string(),
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                journal_file_identity_sha256: ZERO_SHA256.to_string(),
                ..confirmation.clone()
            },
            DirectOperationReplaySyncAckConfirmationV3 {
                mutation_cas_committed_head_sha256: ZERO_SHA256.to_string(),
                ..confirmation.clone()
            },
        ] {
            assert!(invalid.validate().is_err());
        }

        let mut whitespace = canonical_command.clone();
        whitespace.push(b'\n');
        assert!(DirectOperationReplaySyncCommandV3::from_canonical_json(&whitespace).is_err());
        let unknown = br#"{"command":"observe_disposition","schema":"trillionnium.direct-operation-replay-sync-command.v3","binding_sha256":"1111111111111111111111111111111111111111111111111111111111111111","launch_challenge_sha256":"2222222222222222222222222222222222222222222222222222222222222222","adapter":"system_api"}"#;
        assert!(DirectOperationReplaySyncCommandV3::from_canonical_json(unknown).is_err());
        let duplicate = br#"{"command":"apply_ack","schema":"trillionnium.direct-operation-replay-sync-command.v3","binding_sha256":"1111111111111111111111111111111111111111111111111111111111111111","ack_intent_sha256":"3333333333333333333333333333333333333333333333333333333333333333","ack_intent_sha256":"3333333333333333333333333333333333333333333333333333333333333333","launch_challenge_sha256":"2222222222222222222222222222222222222222222222222222222222222222"}"#;
        assert!(DirectOperationReplaySyncCommandV3::from_canonical_json(duplicate).is_err());

        let duplicate_top_level = |canonical: &[u8], field: &str, value: &str| {
            let mut bytes = canonical[..canonical.len() - 1].to_vec();
            bytes.extend_from_slice(format!(",\"{field}\":\"{value}\"}}").as_bytes());
            bytes
        };
        assert!(
            DirectOperationReplaySyncObservationV3::from_canonical_json(&duplicate_top_level(
                &canonical_observation,
                "journal_file_identity_sha256",
                &digest('3'),
            ))
            .is_err()
        );
        assert!(
            DirectOperationReplaySyncAckConfirmationV3::from_canonical_json(&duplicate_top_level(
                &canonical_confirmation,
                "mutation_cas_committed_head_sha256",
                &digest('a'),
            ))
            .is_err()
        );

        observation.journal_state_sha256 = digest('e');
        assert!(observation.validate().is_err());
        let mut observation =
            DirectOperationReplaySyncObservationV3::from_canonical_json(&canonical_observation)
                .unwrap();
        observation.schema = "wrong".to_string();
        assert!(observation.validate().is_err());
        let mut observation =
            DirectOperationReplaySyncObservationV3::from_canonical_json(&canonical_observation)
                .unwrap();
        observation.terminal_disposition_sha256 = ZERO_SHA256.to_string();
        assert!(observation.validate().is_err());
        let mut observation =
            DirectOperationReplaySyncObservationV3::from_canonical_json(&canonical_observation)
                .unwrap();
        observation.journal_file_identity_sha256 = ZERO_SHA256.to_string();
        assert!(observation.validate().is_err());
        confirmation.mutation_cas_committed_head_sha256 = ZERO_SHA256.to_string();
        assert!(confirmation.validate().is_err());
    }

    #[test]
    fn p0_replay_sync_daemon_custody_lane_is_bound_and_cannot_substitute_product_v3() {
        let delivery = binding();
        let allocation = binding();
        let receipt = outer_receipt_v3();
        let inbox = outer_ack_inbox_v3();
        let binding_sha256 = delivery.digest_sha256().unwrap();
        let ack_intent_sha256 = inbox.operation_replay_sync_ack_intent_sha256().unwrap();
        let launch_challenge_sha256 = digest('e');
        let authority = DirectOperationP0ReplaySyncSealedAuthorityV1::seal(
            delivery,
            allocation,
            receipt,
            DirectOperationCustodyHead::new(7, digest('a')).unwrap(),
            digest('b'),
            digest('c'),
            digest('d'),
            launch_challenge_sha256.clone(),
            ack_intent_sha256.clone(),
        )
        .unwrap();
        authority
            .validate_for(
                &inbox,
                &binding_sha256,
                &ack_intent_sha256,
                &launch_challenge_sha256,
            )
            .unwrap();

        let command = DirectOperationReplaySyncCommandV3::ApplyAck {
            schema: OPERATION_REPLAY_SYNC_COMMAND_V3_SCHEMA.to_string(),
            binding_sha256,
            ack_intent_sha256: ack_intent_sha256.clone(),
            launch_challenge_sha256,
            p0_sealed_authority: Some(Box::new(authority.clone())),
        };
        let canonical_command = command.canonical_json().unwrap();
        command.validate_p0_daemon_custody_lane().unwrap();
        assert!(command.validate_product_lane().is_err());
        assert_eq!(
            DirectOperationReplaySyncCommandV3::from_canonical_json(&canonical_command).unwrap(),
            command
        );

        let mut tampered = authority.clone();
        tampered.binding_inbox_bytes_sha256 = digest('f');
        assert!(tampered.validate().is_err());

        let confirmation = DirectOperationP0ReplaySyncAckConfirmationV1 {
            schema: P0_REPLAY_SYNC_ACK_CONFIRMATION_V1_SCHEMA.to_string(),
            lane: P0_REPLAY_SYNC_ACK_CONFIRMATION_LANE.to_string(),
            ack_intent_sha256,
            android_ack_echo_sha256: digest('1'),
            acknowledgement_sha256: inbox.acknowledgement_sha256,
            authenticated_ack_chain_sha256: inbox.chain_step.authenticated_ack_chain_sha256,
            compacted_ack_watermark: 2,
            post_compaction_journal_sha256: digest('2'),
            journal_file_identity_sha256: digest('3'),
            daemon_custody_committed_head_sha256: authority.committed_custody_head_sha256,
            daemon_high_water_observation_sha256: authority.daemon_high_water_observation_sha256,
            daemon_binding_publication_identity_sha256: authority
                .daemon_binding_publication_identity_sha256,
            sealed_authority_sha256: authority.sealed_authority_sha256,
        };
        let canonical_confirmation = confirmation.canonical_json().unwrap();
        assert_eq!(
            DirectOperationP0ReplaySyncAckConfirmationV1::from_canonical_json(
                &canonical_confirmation
            )
            .unwrap(),
            confirmation
        );
        assert!(
            DirectOperationReplaySyncAckConfirmationV3::from_canonical_json(
                &canonical_confirmation
            )
            .is_err()
        );
    }

    #[test]
    fn provider_attempt_identity_is_deterministic_and_not_free_form() {
        let attempt = DirectOperationProviderAttempt::derive(digest('a'), 42, digest('b')).unwrap();
        assert_eq!(
            attempt,
            DirectOperationProviderAttempt::derive(digest('a'), 42, digest('b')).unwrap()
        );
        attempt.validate().unwrap();

        for mut forged in [
            {
                let mut value = attempt.clone();
                value.runtime_lifecycle_binding_sha256 = digest('c');
                value
            },
            {
                let mut value = attempt.clone();
                value.attempt_generation += 1;
                value
            },
            {
                let mut value = attempt.clone();
                value.daemon_attempt_context_sha256 = digest('d');
                value
            },
            {
                let mut value = attempt.clone();
                value.delivery_provider_attempt_id =
                    format!("{PROVIDER_ATTEMPT_ID_PREFIX}{}", digest('e'));
                value
            },
        ] {
            assert!(forged.validate().is_err());
            forged.delivery_provider_attempt_id.clear();
        }
        assert!(DirectOperationProviderAttempt::derive(digest('a'), 0, digest('b')).is_err());

        let mut raw = serde_json::to_value(attempt).unwrap();
        raw["model_nonce"] = json!("must-not-enter-daemon-attempt-context");
        assert!(serde_json::from_value::<DirectOperationProviderAttempt>(raw).is_err());
    }

    #[test]
    fn provider_cgroup_topology_v2_is_exact_and_rejects_legacy_parent_leaf() {
        for provider_id in [crate::agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id] {
            let topology = ProviderCgroupTopologyV2::fixed_for(provider_id).unwrap();
            topology.validate_for(provider_id).unwrap();
            assert_eq!(topology.provider_subtree_process_count, 0);
            assert_eq!(topology.provider_subtree_descendant_count, 3);
            assert_eq!(topology.provider_subtree_dying_descendant_count, 0);
            assert_eq!(topology.provider_subtree_max_descendants, 3);
            assert_eq!(topology.provider_subtree_max_depth, 1);
            assert_eq!(
                topology
                    .child_leaves
                    .iter()
                    .map(|leaf| leaf.role)
                    .collect::<Vec<_>>(),
                vec![
                    ProviderCgroupChildRoleV2::Runtime,
                    ProviderCgroupChildRoleV2::SystemApi,
                    ProviderCgroupChildRoleV2::Accessibility,
                ]
            );
            assert_eq!(
                topology.child_leaves[0].unified_cgroup_path,
                fixed_provider_runtime_cgroup_path(provider_id).unwrap()
            );
            assert_eq!(
                topology.child_leaves[1].unified_cgroup_path,
                fixed_adapter_cgroup_path(provider_id, DirectOperationAdapter::SystemApi).unwrap()
            );
            assert_eq!(
                topology.child_leaves[2].unified_cgroup_path,
                fixed_adapter_cgroup_path(provider_id, DirectOperationAdapter::Accessibility)
                    .unwrap()
            );
            assert!(topology.child_leaves.iter().all(|leaf| {
                leaf.descendant_count == 0
                    && leaf.dying_descendant_count == 0
                    && leaf.max_descendants == 0
                    && leaf.max_depth == 0
            }));

            let mut invalid = Vec::new();
            let mut legacy_parent_as_runtime = topology.clone();
            legacy_parent_as_runtime.child_leaves[0].unified_cgroup_path =
                fixed_provider_cgroup_subtree(provider_id)
                    .unwrap()
                    .to_string();
            invalid.push(legacy_parent_as_runtime);
            let mut missing = topology.clone();
            missing.child_leaves.pop();
            invalid.push(missing);
            let mut extra = topology.clone();
            extra.child_leaves.push(extra.child_leaves[0].clone());
            invalid.push(extra);
            let mut swapped = topology.clone();
            swapped.child_leaves.swap(0, 1);
            invalid.push(swapped);
            let mut aliased = topology.clone();
            aliased.child_leaves[2].unified_cgroup_path =
                aliased.child_leaves[1].unified_cgroup_path.clone();
            invalid.push(aliased);
            let mut parent_member = topology.clone();
            parent_member.provider_subtree_process_count = 1;
            invalid.push(parent_member);
            let mut wrong_parent_limit = topology.clone();
            wrong_parent_limit.provider_subtree_max_descendants = 2;
            invalid.push(wrong_parent_limit);
            let mut wrong_child_limit = topology.clone();
            wrong_child_limit.child_leaves[0].max_depth = 1;
            invalid.push(wrong_child_limit);

            for candidate in invalid {
                assert!(candidate.validate_for(provider_id).is_err());
                assert!(candidate.digest_sha256().is_err());
            }
        }
        assert!(ProviderCgroupTopologyV2::fixed_for("third-party-provider").is_err());
    }

    #[test]
    fn provider_cgroup_resource_policy_binds_finite_pids_memory_swap_oom_and_cpu() {
        for provider_id in [crate::agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id] {
            let policy = ProviderCgroupResourcePolicyV1::provisioned(
                provider_id,
                128,
                1024 * 1024 * 1024,
                200_000,
                100_000,
            )
            .unwrap();
            policy.validate_for(provider_id).unwrap();
            assert_eq!(
                policy.runtime_leaf_path,
                fixed_provider_runtime_cgroup_path(provider_id).unwrap()
            );
            assert_eq!(policy.memory_swap_max_bytes, 0);
            assert_eq!(policy.memory_oom_group, 1);
            assert_ne!(policy.policy_sha256, policy.runtime_leaf_path);

            for drift in [
                |value: &mut ProviderCgroupResourcePolicyV1| value.pids_max = 0,
                |value: &mut ProviderCgroupResourcePolicyV1| value.memory_swap_max_bytes = 1,
                |value: &mut ProviderCgroupResourcePolicyV1| value.memory_oom_group = 0,
                |value: &mut ProviderCgroupResourcePolicyV1| value.cpu_quota_us = 900_000,
            ] {
                let mut invalid = policy.clone();
                drift(&mut invalid);
                assert!(invalid.validate_for(provider_id).is_err());
                assert!(invalid.digest_sha256().is_err());
            }

            let mut rehashed_drift = policy.clone();
            rehashed_drift.memory_max_bytes = 2 * 1024 * 1024 * 1024;
            rehashed_drift.policy_sha256 = rehashed_drift.digest_sha256().unwrap();
            rehashed_drift.validate_for(provider_id).unwrap();
            assert_ne!(rehashed_drift.policy_sha256, policy.policy_sha256);
        }
        assert!(
            ProviderCgroupResourcePolicyV1::provisioned(
                "third-party-provider",
                128,
                1024 * 1024 * 1024,
                200_000,
                100_000,
            )
            .is_err()
        );
    }

    #[test]
    fn kernel_launch_custody_is_exactly_bound_and_not_self_asserted() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let mut custody = DirectOperationKernelLaunchCustodyV3 {
            schema: KERNEL_LAUNCH_CUSTODY_V3_SCHEMA.to_string(),
            kernel_custody_kind: KERNEL_LAUNCH_CUSTODY_KIND_V3.to_string(),
            custody_producer: KERNEL_LAUNCH_CUSTODY_PRODUCER_V3.to_string(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter: DirectOperationAdapter::SystemApi,
            adapter_binary_kind: adapter_binary_kind(DirectOperationAdapter::SystemApi).to_string(),
            binding_sha256: binding_sha256.clone(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_subtree_generation: 41,
            provider_subtree_reservation_evidence_sha256: digest('e'),
            boot_id_sha256: digest('c'),
            adapter_pid: 123,
            adapter_start_time_ticks: 456,
            adapter_executable_sha256: digest('d'),
            unified_cgroup_path: fixed_adapter_cgroup_path(
                &binding.stable_seed.provider_id,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap(),
            adapter_leaf_empty_proof_sha256: digest('a'),
            measured_exec_proof_sha256: digest('b'),
            launch_custody_sha256: String::new(),
        };
        custody.launch_custody_sha256 = custody.digest_sha256().unwrap();
        custody
            .validate_for(&binding, &binding_sha256, DirectOperationAdapter::SystemApi)
            .unwrap();
        assert_ne!(
            custody.provider_subtree_generation,
            binding.attempt.attempt_generation
        );

        for forged in [
            {
                let mut value = custody.clone();
                value.provider_subtree_generation += 1;
                value
            },
            {
                let mut value = custody.clone();
                value.provider_subtree_reservation_evidence_sha256 = digest('f');
                value
            },
            {
                let mut value = custody.clone();
                value.adapter = DirectOperationAdapter::Accessibility;
                value
            },
            {
                let mut value = custody.clone();
                value.measured_exec_proof_sha256 = digest('c');
                value
            },
            {
                let mut value = custody.clone();
                value.adapter_start_time_ticks += 1;
                value
            },
            {
                let mut value = custody.clone();
                value.unified_cgroup_path.push_str("/copy");
                value
            },
        ] {
            assert!(
                forged
                    .validate_for(&binding, &binding_sha256, DirectOperationAdapter::SystemApi,)
                    .is_err()
            );
        }

        let mut raw = serde_json::to_value(custody).unwrap();
        raw["kernel_custody_proven"] = json!(true);
        assert!(serde_json::from_value::<DirectOperationKernelLaunchCustodyV3>(raw).is_err());
    }

    #[test]
    fn tool_call_envelope_separates_logical_identity_from_canonical_content() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let canonical_request_sha256 = digest('c');
        let request = DirectOperationUncorrelatedToolCallAllocationRequestV3::derive(
            &binding,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
            canonical_request_sha256.clone(),
        )
        .unwrap();
        request
            .validate_for(&binding, &binding_sha256, DirectOperationAdapter::SystemApi)
            .unwrap();
        assert_eq!(
            request.retry_correlation_authority,
            TOOL_CALL_RETRY_CORRELATION_ABSENT_PRODUCT_HOLD
        );
        let mut forged_correlation = request.clone();
        forged_correlation.retry_correlation_authority =
            "daemon_durable_logical_delivery_v3".to_string();
        assert!(
            forged_correlation
                .validate_for(&binding, &binding_sha256, DirectOperationAdapter::SystemApi,)
                .is_err()
        );
        let mut envelope = DirectOperationToolCallEnvelopeV3 {
            schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
            binding_sha256: binding_sha256.clone(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter: DirectOperationAdapter::SystemApi,
            os_tool_call_id: format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('d')),
            adapter_effect_ordinal: 3,
            canonical_request_sha256: canonical_request_sha256.clone(),
            envelope_sha256: String::new(),
        };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        envelope
            .validate_for_binding(&binding, &binding_sha256, DirectOperationAdapter::SystemApi)
            .unwrap();
        envelope
            .validate_for(
                &binding,
                &binding_sha256,
                DirectOperationAdapter::SystemApi,
                &canonical_request_sha256,
            )
            .unwrap();
        envelope.validate_for_allocation_request(&request).unwrap();

        assert!(
            envelope
                .validate_for(
                    &binding,
                    &binding_sha256,
                    DirectOperationAdapter::SystemApi,
                    &digest('e'),
                )
                .is_err()
        );

        let mut repeated_content_new_call = envelope.clone();
        repeated_content_new_call.os_tool_call_id =
            format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('e'));
        repeated_content_new_call.adapter_effect_ordinal += 1;
        repeated_content_new_call.envelope_sha256 =
            repeated_content_new_call.digest_sha256().unwrap();
        repeated_content_new_call
            .validate_for(
                &binding,
                &binding_sha256,
                DirectOperationAdapter::SystemApi,
                &canonical_request_sha256,
            )
            .unwrap();
        assert_ne!(
            repeated_content_new_call.os_tool_call_id,
            envelope.os_tool_call_id
        );
        assert_eq!(
            repeated_content_new_call.canonical_request_sha256,
            envelope.canonical_request_sha256
        );

        let mut raw = serde_json::to_value(envelope).unwrap();
        raw["model_tool_call_id"] = json!("must-not-enter-root-authored-envelope");
        assert!(serde_json::from_value::<DirectOperationToolCallEnvelopeV3>(raw).is_err());

        let mut raw = serde_json::to_value(request).unwrap();
        raw["requested_os_tool_call_id"] = json!("must-not-enter-allocation-request");
        assert!(
            serde_json::from_value::<DirectOperationUncorrelatedToolCallAllocationRequestV3>(raw)
                .is_err()
        );
    }

    #[test]
    fn daemon_delivery_v3_binds_retry_identity_and_authorized_adapter_set() {
        let binding = dual_binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let delivery = DirectOperationToolCallDeliveryV3::derive(
            &binding,
            &binding_sha256,
            DirectOperationAdapter::Accessibility,
            format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('b')),
            4,
        )
        .unwrap();
        delivery
            .validate_for(
                &binding,
                &binding_sha256,
                DirectOperationAdapter::Accessibility,
            )
            .unwrap();
        let request = DirectOperationToolCallAllocationRequestV3::derive(
            &delivery,
            &binding,
            &binding_sha256,
            DirectOperationAdapter::Accessibility,
            digest('c'),
        )
        .unwrap();
        request
            .validate_for(
                &delivery,
                &binding,
                &binding_sha256,
                DirectOperationAdapter::Accessibility,
            )
            .unwrap();
        assert_eq!(
            request.retry_correlation_authority,
            TOOL_CALL_RETRY_CORRELATION_DAEMON_DELIVERY_V3
        );

        let mut envelope = DirectOperationToolCallEnvelopeV3 {
            schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
            binding_sha256: binding_sha256.clone(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter: DirectOperationAdapter::Accessibility,
            os_tool_call_id: delivery.os_tool_call_id.clone(),
            adapter_effect_ordinal: delivery.adapter_effect_ordinal,
            canonical_request_sha256: request.canonical_request_sha256.clone(),
            envelope_sha256: String::new(),
        };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        envelope
            .validate_for_allocation_request_v3(&request)
            .unwrap();

        let mut wrong_digest = request.clone();
        wrong_digest.canonical_request_sha256 = digest('d');
        wrong_digest.request_sha256 = wrong_digest.digest_sha256().unwrap();
        assert!(
            envelope
                .validate_for_allocation_request_v3(&wrong_digest)
                .is_err()
        );

        let mut wrong_ordinal = delivery.clone();
        wrong_ordinal.adapter_effect_ordinal += 1;
        wrong_ordinal.delivery_sha256 = wrong_ordinal.digest_sha256().unwrap();
        assert!(
            request
                .validate_for(
                    &wrong_ordinal,
                    &binding,
                    &binding_sha256,
                    DirectOperationAdapter::Accessibility,
                )
                .is_err()
        );

        let mut forged_delivery_digest = serde_json::to_value(&request).unwrap();
        forged_delivery_digest["delivery_sha256"] = json!(digest('e'));
        forged_delivery_digest["request_sha256"] = json!(digest('f'));
        let forged_delivery_digest = serde_json::from_value::<
            DirectOperationToolCallAllocationRequestV3,
        >(forged_delivery_digest)
        .unwrap();
        assert!(forged_delivery_digest.digest_sha256().is_err());
        assert!(
            envelope
                .validate_for_allocation_request_v3(&forged_delivery_digest)
                .is_err()
        );

        for forbidden in [
            "model_tool_call_id",
            "provider_json_rpc_id",
            "provider_tool_call_id",
        ] {
            let mut raw = serde_json::to_value(&delivery).unwrap();
            raw[forbidden] = json!("provider-authored-value");
            assert!(serde_json::from_value::<DirectOperationToolCallDeliveryV3>(raw).is_err());
        }
    }

    #[test]
    fn prepared_ack_and_commit_receipt_bind_epoch_journal_and_allocation() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let delivery = DirectOperationToolCallDeliveryV3::derive(
            &binding,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
            format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('b')),
            0,
        )
        .unwrap();
        let request = DirectOperationToolCallAllocationRequestV3::derive(
            &delivery,
            &binding,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
            digest('c'),
        )
        .unwrap();
        let mut envelope = DirectOperationToolCallEnvelopeV3 {
            schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
            binding_sha256,
            invocation_id: binding.invocation_id,
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id,
            provider_id: binding.stable_seed.provider_id,
            agent_id: binding.stable_seed.agent_id,
            adapter: DirectOperationAdapter::SystemApi,
            os_tool_call_id: delivery.os_tool_call_id,
            adapter_effect_ordinal: delivery.adapter_effect_ordinal,
            canonical_request_sha256: request.canonical_request_sha256,
            envelope_sha256: String::new(),
        };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        let acknowledgement = DirectOperationToolCallPreparedAckV3::derive(
            &envelope,
            "01".repeat(16),
            7,
            digest('d'),
            digest('e'),
            digest('f'),
        )
        .unwrap();
        acknowledgement.validate_for_envelope(&envelope).unwrap();
        let receipt =
            DirectOperationToolCallCommitReceiptV3::derive(&acknowledgement, 3, digest('a'))
                .unwrap();
        receipt
            .validate_for_acknowledgement(&acknowledgement)
            .unwrap();

        let mut epoch_drift = acknowledgement.clone();
        epoch_drift.journal_epoch = "02".repeat(16);
        assert!(epoch_drift.validate_for_envelope(&envelope).is_err());
        let mut authority_absent = acknowledgement.clone();
        authority_absent.operation_epoch_authority_sha256 = ZERO_SHA256.to_string();
        assert!(authority_absent.digest_sha256().is_err());
        let mut receipt_drift = receipt;
        receipt_drift.allocator_generation += 1;
        assert!(
            receipt_drift
                .validate_for_acknowledgement(&acknowledgement)
                .is_err()
        );

        let mut raw = serde_json::to_value(acknowledgement).unwrap();
        raw["effect_authorized"] = json!(true);
        assert!(serde_json::from_value::<DirectOperationToolCallPreparedAckV3>(raw).is_err());
    }

    #[test]
    fn json_schema_rejects_non_lowercase_hashes_and_unknown_provider_pairs() {
        let mut invalid = seed();
        invalid.provider_invocation_id_sha256 = "A".repeat(64);
        assert!(invalid.validate().is_err());
        invalid = seed();
        invalid.agent_id = "unregistered-agent".to_string();
        assert!(invalid.validate().is_err());

        let parsed: Value =
            serde_json::from_str(r#"{"schema":"unknown","provider_id":"openai-codex"}"#).unwrap();
        assert!(serde_json::from_value::<DirectOperationStableSeed>(parsed).is_err());
    }
}
