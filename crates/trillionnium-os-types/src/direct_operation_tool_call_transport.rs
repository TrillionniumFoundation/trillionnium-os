//! Closed contracts for the dedicated daemon-to-adapter Direct operation
//! tool-call session.
//!
//! This protocol is intentionally distinct from capability-lease root
//! publication and from Android System API/Accessibility backend protocols.
//! It carries only the already root-authored Direct binding, logical delivery,
//! canonical digest allocation, durable PREPARED acknowledgement, and commit
//! receipt. None of these data values can construct first-use, replay, epoch,
//! rollback-high-water, outer-ACK, or effect authority.

use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_descriptor_registry::{ACCESSIBILITY_ENDPOINT, SYSTEM_API_ENDPOINT};
use crate::direct_operation::{
    DirectOperationAdapter, DirectOperationBinding, DirectOperationKernelLaunchCustodyV3,
};
#[cfg(feature = "p0-launch-package-device-conformance")]
use crate::direct_operation::{
    DirectOperationAdapterTerminalDispositionV1, DirectOperationToolCallCommitReceiptV3,
};

pub const HELLO_V3_SCHEMA: &str = "trillionnium.direct-operation-tool-call-session-hello.v3";
#[cfg(feature = "p0-launch-package-device-conformance")]
pub const P0_USERDEBUG_HELLO_V1_SCHEMA: &str =
    "trillionnium.direct-operation-tool-call-p0-userdebug-session-hello.v1";
pub const PROTOCOL: &str = "trillionnium.direct-operation-tool-call-session.v3";
pub const OPERATION: &str = "recover_preissued_delivery_allocate_and_ack_prepared";
pub const HELLO_BINDING_DOMAIN: &str = "trillionnium.direct-operation-tool-call-session-hello.v3";
#[cfg(feature = "p0-launch-package-device-conformance")]
pub const P0_USERDEBUG_HELLO_BINDING_DOMAIN: &str =
    "trillionnium.direct-operation-tool-call-p0-userdebug-session-hello.v1";
#[cfg(feature = "p0-launch-package-device-conformance")]
pub const P0_USERDEBUG_TERMINAL_COMMIT_V1_SCHEMA: &str =
    "trillionnium.direct-operation-tool-call-p0-userdebug-terminal-commit.v1";
#[cfg(feature = "p0-launch-package-device-conformance")]
pub const P0_USERDEBUG_TERMINAL_COMMIT_DOMAIN: &str =
    "trillionnium.direct-operation-tool-call-p0-userdebug-terminal-commit.v1";
pub const SOCKET_NAME: &str = "trillionnium_direct_operation_allocator";
pub const SOCKET_ADDRESS: &str = "@trillionnium_direct_operation_allocator";
pub const DAEMON_UID: u32 = 0;
pub const DAEMON_GID: u32 = 0;
pub const DAEMON_SELINUX_DOMAIN: &str = "u:r:trillionnium_agentd:s0";
pub const SYSTEM_API_SELINUX_DOMAIN: &str = SYSTEM_API_ENDPOINT.tool_selinux_domain;
pub const ACCESSIBILITY_SELINUX_DOMAIN: &str = ACCESSIBILITY_ENDPOINT.tool_selinux_domain;
pub const MAXIMUM_FRAME_BYTES: usize = 512 * 1024;

pub const SOURCE_CLIENT_IMPLEMENTED: bool = true;
pub const SOURCE_LISTENER_IMPLEMENTED: bool = true;
pub const SOURCE_SESSION_HANDLER_IMPLEMENTED: bool = true;
pub const DAEMON_LISTENER_PRODUCT_WIRED: bool = false;
pub const ADAPTER_CONNECTOR_PRODUCT_WIRED: bool = false;
pub const PROVIDER_DELIVERY_PRODUCT_WIRED: bool = false;
pub const FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE: bool = false;
pub const ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

/// Stable error returned when the product transport has not crossed every
/// source-level admission prerequisite. This is a pre-effect HOLD: a true
/// result below would still require live kernel custody, a verified provider
/// delivery, and the durable replay/high-water checks at the call site.
pub const PRODUCTION_ADMISSION_HOLD_CODE: &str =
    "direct_tool_call_transport_product_admission_contract_unavailable";

/// Return whether the *static* product admission contract is complete.
///
/// These flags deliberately describe wiring and authority publication, not
/// runtime proof. Keeping this check in the shared protocol-types crate gives
/// every production boundary one fail-closed predicate and prevents a caller
/// from accidentally treating a source-only transport as an effect route.
#[must_use]
pub const fn product_admission_contract_is_complete() -> bool {
    DAEMON_LISTENER_PRODUCT_WIRED
        && ADAPTER_CONNECTOR_PRODUCT_WIRED
        && PROVIDER_DELIVERY_PRODUCT_WIRED
        && FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE
        && ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE
        && CONFERS_EFFECT_AUTHORITY
}

/// Require the static product admission contract before touching any product
/// allocator store, socket, or adapter effect path.
pub fn require_product_admission_contract() -> DirectToolCallTransportResult<()> {
    if product_admission_contract_is_complete() {
        Ok(())
    } else {
        Err(denied(PRODUCTION_ADMISSION_HOLD_CODE))
    }
}

pub type DirectToolCallTransportResult<T> = Result<T, DirectToolCallTransportError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectToolCallTransportError(&'static str);

impl DirectToolCallTransportError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DirectToolCallTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for DirectToolCallTransportError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationToolCallSessionHelloV3 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub kernel_launch_custody_sha256: String,
    pub hello_sha256: String,
}

impl DirectOperationToolCallSessionHelloV3 {
    pub fn derive(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> DirectToolCallTransportResult<Self> {
        binding
            .validate()
            .map_err(|_| denied("direct_tool_call_transport_binding_denied"))?;
        custody
            .validate_for(binding, binding_sha256, adapter)
            .map_err(|_| denied("direct_tool_call_transport_custody_denied"))?;
        if binding
            .digest_sha256()
            .map_err(|_| denied("direct_tool_call_transport_binding_denied"))?
            != binding_sha256
        {
            return Err(denied("direct_tool_call_transport_binding_denied"));
        }
        let mut hello = Self {
            schema: HELLO_V3_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: OPERATION.to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            kernel_launch_custody_sha256: custody.launch_custody_sha256.clone(),
            hello_sha256: String::new(),
        };
        hello.hello_sha256 = hello.expected_sha256()?;
        hello.validate_for(binding, binding_sha256, adapter, custody)?;
        Ok(hello)
    }

    pub fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> DirectToolCallTransportResult<()> {
        binding
            .validate()
            .map_err(|_| denied("direct_tool_call_transport_binding_denied"))?;
        custody
            .validate_for(binding, binding_sha256, adapter)
            .map_err(|_| denied("direct_tool_call_transport_custody_denied"))?;
        if self.schema != HELLO_V3_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || self.binding_sha256 != binding_sha256
            || binding
                .digest_sha256()
                .map_err(|_| denied("direct_tool_call_transport_binding_denied"))?
                != self.binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || self.provider_id != binding.stable_seed.provider_id
            || self.agent_id != binding.stable_seed.agent_id
            || self.adapter != adapter
            || self.kernel_launch_custody_sha256 != custody.launch_custody_sha256
            || !valid_nonzero_sha256(&self.hello_sha256)
            || self.expected_sha256()? != self.hello_sha256
        {
            return Err(denied("direct_tool_call_transport_hello_denied"));
        }
        Ok(())
    }

    fn expected_sha256(&self) -> DirectToolCallTransportResult<String> {
        if self.schema != HELLO_V3_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || !valid_nonzero_sha256(&self.binding_sha256)
            || self.invocation_id.is_empty()
            || self.delivery_provider_attempt_id.is_empty()
            || self.provider_id.is_empty()
            || self.agent_id.is_empty()
            || !valid_nonzero_sha256(&self.kernel_launch_custody_sha256)
        {
            return Err(denied("direct_tool_call_transport_hello_denied"));
        }
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "domain", HELLO_BINDING_DOMAIN)?;
        hash_field(&mut hasher, "schema", &self.schema)?;
        hash_field(&mut hasher, "protocol", &self.protocol)?;
        hash_field(&mut hasher, "operation", &self.operation)?;
        hash_field(&mut hasher, "binding_sha256", &self.binding_sha256)?;
        hash_field(&mut hasher, "invocation_id", &self.invocation_id)?;
        hash_field(
            &mut hasher,
            "delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        )?;
        hash_field(&mut hasher, "provider_id", &self.provider_id)?;
        hash_field(&mut hasher, "agent_id", &self.agent_id)?;
        hash_field(&mut hasher, "adapter", self.adapter.adapter_id())?;
        hash_field(
            &mut hasher,
            "kernel_launch_custody_sha256",
            &self.kernel_launch_custody_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Closed non-product hello for the exact P0 userdebug System API slice.
///
/// Unlike `DirectOperationToolCallSessionHelloV3`, this value never claims a
/// root-authored kernel launch-custody envelope. The daemon must independently
/// authenticate the live socket peer, exact executable digest, UID/GID and
/// SELinux domain before reading or mutating allocator state. The data remains
/// a session-binding message, not an authority constructor.
#[cfg(feature = "p0-launch-package-device-conformance")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct P0UserdebugDirectOperationToolCallSessionHelloV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub authority_scope: String,
    pub binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub hello_sha256: String,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl P0UserdebugDirectOperationToolCallSessionHelloV1 {
    pub const AUTHORITY_SCOPE: &'static str = "p0_userdebug_conformance_only";

    pub fn derive(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectToolCallTransportResult<Self> {
        binding
            .validate()
            .map_err(|_| denied("direct_tool_call_transport_p0_binding_denied"))?;
        if binding
            .digest_sha256()
            .map_err(|_| denied("direct_tool_call_transport_p0_binding_denied"))?
            != binding_sha256
        {
            return Err(denied("direct_tool_call_transport_p0_binding_denied"));
        }
        if adapter != DirectOperationAdapter::SystemApi
            || !binding.authorized_adapter_set.authorizes(adapter)
        {
            return Err(denied("direct_tool_call_transport_p0_adapter_denied"));
        }
        let mut hello = Self {
            schema: P0_USERDEBUG_HELLO_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: OPERATION.to_string(),
            authority_scope: Self::AUTHORITY_SCOPE.to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            hello_sha256: String::new(),
        };
        hello.hello_sha256 = hello.expected_sha256()?;
        hello.validate_for(binding, binding_sha256, adapter)?;
        Ok(hello)
    }

    pub fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> DirectToolCallTransportResult<()> {
        binding
            .validate()
            .map_err(|_| denied("direct_tool_call_transport_p0_binding_denied"))?;
        if self.schema != P0_USERDEBUG_HELLO_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || self.authority_scope != Self::AUTHORITY_SCOPE
            || self.binding_sha256 != binding_sha256
            || binding
                .digest_sha256()
                .map_err(|_| denied("direct_tool_call_transport_p0_binding_denied"))?
                != self.binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || self.provider_id != binding.stable_seed.provider_id
            || self.agent_id != binding.stable_seed.agent_id
            || self.adapter != adapter
            || adapter != DirectOperationAdapter::SystemApi
            || !binding.authorized_adapter_set.authorizes(adapter)
            || !valid_nonzero_sha256(&self.hello_sha256)
            || self.expected_sha256()? != self.hello_sha256
        {
            return Err(denied("direct_tool_call_transport_p0_hello_denied"));
        }
        Ok(())
    }

    fn expected_sha256(&self) -> DirectToolCallTransportResult<String> {
        if self.schema != P0_USERDEBUG_HELLO_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || self.authority_scope != Self::AUTHORITY_SCOPE
            || !valid_nonzero_sha256(&self.binding_sha256)
            || self.invocation_id.is_empty()
            || self.delivery_provider_attempt_id.is_empty()
            || self.provider_id.is_empty()
            || self.agent_id.is_empty()
            || self.adapter != DirectOperationAdapter::SystemApi
        {
            return Err(denied("direct_tool_call_transport_p0_hello_denied"));
        }
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "domain", P0_USERDEBUG_HELLO_BINDING_DOMAIN)?;
        hash_field(&mut hasher, "schema", &self.schema)?;
        hash_field(&mut hasher, "protocol", &self.protocol)?;
        hash_field(&mut hasher, "operation", &self.operation)?;
        hash_field(&mut hasher, "authority_scope", &self.authority_scope)?;
        hash_field(&mut hasher, "binding_sha256", &self.binding_sha256)?;
        hash_field(&mut hasher, "invocation_id", &self.invocation_id)?;
        hash_field(
            &mut hasher,
            "delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        )?;
        hash_field(&mut hasher, "provider_id", &self.provider_id)?;
        hash_field(&mut hasher, "agent_id", &self.agent_id)?;
        hash_field(&mut hasher, "adapter", self.adapter.adapter_id())?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Daemon acknowledgement emitted only after the authenticated adapter's
/// terminal disposition is durably attached to the root custody store.
/// This is a userdebug conformance receipt, not product effect authority.
#[cfg(feature = "p0-launch-package-device-conformance")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct P0UserdebugAdapterTerminalCommitV1 {
    pub schema: String,
    pub authority_scope: String,
    pub binding_sha256: String,
    pub adapter: DirectOperationAdapter,
    pub tool_call_commit_receipt_sha256: String,
    pub terminal_disposition_sha256: String,
    pub custody_commit_sha256: String,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl P0UserdebugAdapterTerminalCommitV1 {
    pub fn derive(
        tool_call_commit: &DirectOperationToolCallCommitReceiptV3,
        terminal_disposition: &DirectOperationAdapterTerminalDispositionV1,
    ) -> DirectToolCallTransportResult<Self> {
        let tool_call_commit_receipt_sha256 = tool_call_commit
            .digest_sha256()
            .map_err(|_| denied("direct_tool_call_transport_p0_terminal_commit_denied"))?;
        let terminal_disposition_sha256 = terminal_disposition
            .digest_sha256()
            .map_err(|_| denied("direct_tool_call_transport_p0_terminal_commit_denied"))?;
        if tool_call_commit.binding_sha256 != terminal_disposition.binding_sha256
            || tool_call_commit.adapter != terminal_disposition.adapter
        {
            return Err(denied(
                "direct_tool_call_transport_p0_terminal_commit_denied",
            ));
        }
        let mut commit = Self {
            schema: P0_USERDEBUG_TERMINAL_COMMIT_V1_SCHEMA.to_string(),
            authority_scope: P0UserdebugDirectOperationToolCallSessionHelloV1::AUTHORITY_SCOPE
                .to_string(),
            binding_sha256: tool_call_commit.binding_sha256.clone(),
            adapter: tool_call_commit.adapter,
            tool_call_commit_receipt_sha256,
            terminal_disposition_sha256,
            custody_commit_sha256: String::new(),
        };
        commit.custody_commit_sha256 = commit.expected_sha256()?;
        commit.validate_for(tool_call_commit, terminal_disposition)?;
        Ok(commit)
    }

    pub fn validate_for(
        &self,
        tool_call_commit: &DirectOperationToolCallCommitReceiptV3,
        terminal_disposition: &DirectOperationAdapterTerminalDispositionV1,
    ) -> DirectToolCallTransportResult<()> {
        if self.schema != P0_USERDEBUG_TERMINAL_COMMIT_V1_SCHEMA
            || self.authority_scope
                != P0UserdebugDirectOperationToolCallSessionHelloV1::AUTHORITY_SCOPE
            || self.binding_sha256 != tool_call_commit.binding_sha256
            || self.binding_sha256 != terminal_disposition.binding_sha256
            || self.adapter != tool_call_commit.adapter
            || self.adapter != terminal_disposition.adapter
            || self.tool_call_commit_receipt_sha256
                != tool_call_commit
                    .digest_sha256()
                    .map_err(|_| denied("direct_tool_call_transport_p0_terminal_commit_denied"))?
            || self.terminal_disposition_sha256
                != terminal_disposition
                    .digest_sha256()
                    .map_err(|_| denied("direct_tool_call_transport_p0_terminal_commit_denied"))?
            || self.expected_sha256()? != self.custody_commit_sha256
        {
            return Err(denied(
                "direct_tool_call_transport_p0_terminal_commit_denied",
            ));
        }
        Ok(())
    }

    fn expected_sha256(&self) -> DirectToolCallTransportResult<String> {
        if self.schema != P0_USERDEBUG_TERMINAL_COMMIT_V1_SCHEMA
            || self.authority_scope
                != P0UserdebugDirectOperationToolCallSessionHelloV1::AUTHORITY_SCOPE
            || !valid_nonzero_sha256(&self.binding_sha256)
            || self.adapter != DirectOperationAdapter::SystemApi
            || !valid_nonzero_sha256(&self.tool_call_commit_receipt_sha256)
            || !valid_nonzero_sha256(&self.terminal_disposition_sha256)
        {
            return Err(denied(
                "direct_tool_call_transport_p0_terminal_commit_denied",
            ));
        }
        let mut hasher = Sha256::new();
        hash_field(&mut hasher, "domain", P0_USERDEBUG_TERMINAL_COMMIT_DOMAIN)?;
        hash_field(&mut hasher, "schema", &self.schema)?;
        hash_field(&mut hasher, "authority_scope", &self.authority_scope)?;
        hash_field(&mut hasher, "binding_sha256", &self.binding_sha256)?;
        hash_field(&mut hasher, "adapter", self.adapter.adapter_id())?;
        hash_field(
            &mut hasher,
            "tool_call_commit_receipt_sha256",
            &self.tool_call_commit_receipt_sha256,
        )?;
        hash_field(
            &mut hasher,
            "terminal_disposition_sha256",
            &self.terminal_disposition_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[must_use]
pub const fn adapter_selinux_domain(adapter: DirectOperationAdapter) -> &'static str {
    match adapter {
        DirectOperationAdapter::SystemApi => SYSTEM_API_SELINUX_DOMAIN,
        DirectOperationAdapter::Accessibility => ACCESSIBILITY_SELINUX_DOMAIN,
    }
}

fn hash_field(hasher: &mut Sha256, name: &str, value: &str) -> DirectToolCallTransportResult<()> {
    let name_length =
        u32::try_from(name.len()).map_err(|_| denied("direct_tool_call_transport_hello_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("direct_tool_call_transport_hello_denied"))?;
    hasher.update(name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_length.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(())
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value != "0000000000000000000000000000000000000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

const fn denied(code: &'static str) -> DirectToolCallTransportError {
    DirectToolCallTransportError(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_operation::{
        BINDING_SCHEMA, DirectOperationKernelLaunchCustodyV3, DirectOperationProviderAttempt,
        DirectOperationStableSeed, KERNEL_LAUNCH_CUSTODY_KIND_V3,
        KERNEL_LAUNCH_CUSTODY_PRODUCER_V3, KERNEL_LAUNCH_CUSTODY_V3_SCHEMA, STABLE_SEED_SCHEMA,
        adapter_binary_kind, fixed_adapter_cgroup_path,
    };
    use crate::sha256_bytes;

    const _: () = {
        assert!(!CONFERS_EFFECT_AUTHORITY);
        assert!(SOURCE_LISTENER_IMPLEMENTED);
        assert!(!DAEMON_LISTENER_PRODUCT_WIRED);
        assert!(!ADAPTER_CONNECTOR_PRODUCT_WIRED);
        assert!(!PROVIDER_DELIVERY_PRODUCT_WIRED);
        assert!(!FIRST_USE_AUTHORITY_PRODUCT_AVAILABLE);
        assert!(!ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE);
        assert!(!product_admission_contract_is_complete());
    };

    #[test]
    fn product_admission_contract_is_explicitly_fail_closed() {
        let error = require_product_admission_contract().unwrap_err();
        assert_eq!(error.code(), PRODUCTION_ADMISSION_HOLD_CODE);
        assert!(!product_admission_contract_is_complete());
    }

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    fn binding() -> DirectOperationBinding {
        let seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: "task.transport".to_string(),
            provider_invocation_id_sha256: digest("provider-invocation"),
            provider_session_id_sha256: digest("provider-session"),
            subject_uid: 10_100,
            subject_selinux_domain_sha256: digest("subject-domain"),
        };
        DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            invocation_id: seed.invocation_id().unwrap(),
            stable_seed: seed,
            workflow_id_sha256: digest("workflow"),
            agent_identity_key_sha256: digest("identity"),
            agent_executable_sha256: digest("agent-executable"),
            authorized_adapter_set:
                crate::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                digest("lifecycle"),
                1,
                digest("attempt"),
            )
            .unwrap(),
        }
    }

    fn custody(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
    ) -> DirectOperationKernelLaunchCustodyV3 {
        let adapter = DirectOperationAdapter::SystemApi;
        let mut custody = DirectOperationKernelLaunchCustodyV3 {
            schema: KERNEL_LAUNCH_CUSTODY_V3_SCHEMA.to_string(),
            kernel_custody_kind: KERNEL_LAUNCH_CUSTODY_KIND_V3.to_string(),
            custody_producer: KERNEL_LAUNCH_CUSTODY_PRODUCER_V3.to_string(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            adapter_binary_kind: adapter_binary_kind(adapter).to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_subtree_generation: 41,
            provider_subtree_reservation_evidence_sha256: digest("reservation"),
            boot_id_sha256: digest("boot"),
            adapter_pid: 42,
            adapter_start_time_ticks: 88,
            adapter_executable_sha256: digest("adapter"),
            unified_cgroup_path: fixed_adapter_cgroup_path(
                &binding.stable_seed.provider_id,
                adapter,
            )
            .unwrap(),
            adapter_leaf_empty_proof_sha256: digest("empty"),
            measured_exec_proof_sha256: digest("exec"),
            launch_custody_sha256: String::new(),
        };
        custody.launch_custody_sha256 = custody.digest_sha256().unwrap();
        custody
    }

    #[test]
    fn hello_is_exactly_bound_and_protocol_is_not_root_publication() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let custody = custody(&binding, &binding_sha256);
        let hello = DirectOperationToolCallSessionHelloV3::derive(
            &binding,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
            &custody,
        )
        .unwrap();
        hello
            .validate_for(
                &binding,
                &binding_sha256,
                DirectOperationAdapter::SystemApi,
                &custody,
            )
            .unwrap();
        assert_ne!(
            SOCKET_NAME,
            crate::capability_lease_root_route_transport::SOCKET_NAME
        );
        assert_ne!(PROTOCOL, crate::capability_lease_root_publication::PROTOCOL);
        assert!(!PROTOCOL.contains("capability-lease"));
    }

    #[test]
    fn identity_custody_and_unknown_field_drift_fail_closed() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let custody = custody(&binding, &binding_sha256);
        let hello = DirectOperationToolCallSessionHelloV3::derive(
            &binding,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
            &custody,
        )
        .unwrap();

        let mut drifted = hello.clone();
        drifted.kernel_launch_custody_sha256 = digest("other-custody");
        assert!(
            drifted
                .validate_for(
                    &binding,
                    &binding_sha256,
                    DirectOperationAdapter::SystemApi,
                    &custody,
                )
                .is_err()
        );
        let mut raw = serde_json::to_value(hello).unwrap();
        raw["root_publication_binding_sha256"] =
            serde_json::Value::String(digest("wrong-authority"));
        assert!(serde_json::from_value::<DirectOperationToolCallSessionHelloV3>(raw).is_err());
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_userdebug_hello_is_system_api_only_and_never_claims_kernel_custody() {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let hello = P0UserdebugDirectOperationToolCallSessionHelloV1::derive(
            &binding,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
        )
        .unwrap();
        hello
            .validate_for(&binding, &binding_sha256, DirectOperationAdapter::SystemApi)
            .unwrap();
        let encoded = serde_json::to_value(&hello).unwrap();
        assert!(encoded.get("kernel_launch_custody_sha256").is_none());
        assert!(
            P0UserdebugDirectOperationToolCallSessionHelloV1::derive(
                &binding,
                &binding_sha256,
                DirectOperationAdapter::Accessibility,
            )
            .is_err()
        );

        let mut substituted = encoded;
        substituted["authority_scope"] = serde_json::Value::String("signed_product".to_string());
        assert!(
            serde_json::from_value::<P0UserdebugDirectOperationToolCallSessionHelloV1>(substituted)
                .unwrap()
                .validate_for(&binding, &binding_sha256, DirectOperationAdapter::SystemApi,)
                .is_err()
        );
    }
}
