//! Closed, data-only ABI for the source-disabled Direct operation runtime
//! authority carrier.
//!
//! The carrier is deliberately disjoint from capability-lease root
//! publication, Direct tool-call allocation, and Android replay-control
//! protocols.  Its product response vocabulary contains only a terminal HOLD.
//! In particular, this module defines no success response and cannot construct
//! first-use, replay, rollback-high-water, mutation-CAS, activation, or effect
//! authority.

use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_descriptor_registry;
use crate::direct_operation::{
    DirectOperationAdapter, DirectOperationBinding, DirectOperationKernelLaunchCustodyV3,
};

pub const SESSION_CHALLENGE_V3_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-session-challenge.v3";
pub const SESSION_HELLO_V3_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-session-hello.v3";
pub const PROBE_V3_SCHEMA: &str = "trillionnium.direct-operation-runtime-authority-probe.v3";
pub const HOLD_V3_SCHEMA: &str = "trillionnium.direct-operation-runtime-authority-hold.v3";
pub const PROTOCOL: &str = "trillionnium.direct-operation-runtime-authority.v3";
pub const OPERATION: &str = "observe_first_use_or_replay_authority";
pub const CHALLENGE_BINDING_DOMAIN: &str =
    "trillionnium.direct-operation-runtime-authority-session-challenge.v3";
pub const HELLO_BINDING_DOMAIN: &str =
    "trillionnium.direct-operation-runtime-authority-session-hello.v3";
pub const PROBE_BINDING_DOMAIN: &str = "trillionnium.direct-operation-runtime-authority-probe.v3";
pub const HOLD_BINDING_DOMAIN: &str = "trillionnium.direct-operation-runtime-authority-hold.v3";
pub const SOCKET_NAME: &str = "trillionnium_direct_operation_runtime_authority";
pub const SOCKET_ADDRESS: &str = "@trillionnium_direct_operation_runtime_authority";
pub const MAXIMUM_FRAME_BYTES: usize = 64 * 1024;
pub const HOLD_CODE: &str = "external_runtime_authority_unavailable";

pub const SOURCE_CLIENT_IMPLEMENTED: bool = true;
pub const SOURCE_LISTENER_IMPLEMENTED: bool = false;
pub const SOURCE_INJECTED_HANDLER_IMPLEMENTED: bool = true;
pub const SOURCE_HOLD_RESPONSE_IMPLEMENTED: bool = true;

pub const EXTERNAL_RUNTIME_AUTHORITY_PRODUCT_AVAILABLE: bool = false;
pub const DAEMON_LISTENER_PRODUCT_WIRED: bool = false;
pub const ADAPTER_CONNECTOR_PRODUCT_WIRED: bool = false;
pub const AUTHORITY_BACKEND_PRODUCT_WIRED: bool = false;
pub const FIRST_USE_DECISION_PRODUCT_AVAILABLE: bool = false;
pub const REPLAY_DECISION_PRODUCT_AVAILABLE: bool = false;
pub const FIRST_USE_PRODUCT_WIRED: bool = false;
pub const REPLAY_PRODUCT_WIRED: bool = false;
pub const MUTATION_CAS_PRODUCT_AVAILABLE: bool = false;
pub const ACTIVATION_PRODUCT_WIRED: bool = false;
pub const ANDROID_ACTIVATION_PRODUCT_WIRED: bool = false;
pub const ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

const JOURNAL_EPOCH_HEX_BYTES: usize = 32;

pub type DirectOperationRuntimeAuthorityResult<T> = Result<T, DirectOperationRuntimeAuthorityError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectOperationRuntimeAuthorityError(&'static str);

impl DirectOperationRuntimeAuthorityError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DirectOperationRuntimeAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for DirectOperationRuntimeAuthorityError {}

/// Daemon-authored freshness and live adapter-peer binding for one injected
/// connection. The adapter can echo this closed challenge, but cannot select
/// either the server nonce or the daemon's pidfd-bracketed peer digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthoritySessionChallengeV3 {
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
    pub adapter_peer_identity_sha256: String,
    pub server_nonce_sha256: String,
    pub challenge_sha256: String,
}

impl DirectOperationRuntimeAuthoritySessionChallengeV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
        adapter_peer_identity_sha256: &str,
        server_nonce_sha256: &str,
    ) -> DirectOperationRuntimeAuthorityResult<Self> {
        validate_binding_and_custody(binding, binding_sha256, adapter, custody)?;
        if !valid_nonzero_sha256(adapter_peer_identity_sha256)
            || !valid_nonzero_sha256(server_nonce_sha256)
        {
            return Err(denied(
                "direct_operation_runtime_authority_challenge_denied",
            ));
        }
        let mut challenge = Self {
            schema: SESSION_CHALLENGE_V3_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: OPERATION.to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            kernel_launch_custody_sha256: custody.launch_custody_sha256.clone(),
            adapter_peer_identity_sha256: adapter_peer_identity_sha256.to_string(),
            server_nonce_sha256: server_nonce_sha256.to_string(),
            challenge_sha256: String::new(),
        };
        challenge.challenge_sha256 = challenge.canonical_sha256()?;
        challenge.validate_for(
            binding,
            binding_sha256,
            adapter,
            custody,
            adapter_peer_identity_sha256,
            server_nonce_sha256,
        )?;
        Ok(challenge)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_for(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
        adapter_peer_identity_sha256: &str,
        server_nonce_sha256: &str,
    ) -> DirectOperationRuntimeAuthorityResult<()> {
        self.validate_client_context(binding, binding_sha256, adapter, custody)?;
        if self.adapter_peer_identity_sha256 != adapter_peer_identity_sha256
            || self.server_nonce_sha256 != server_nonce_sha256
        {
            return Err(denied(
                "direct_operation_runtime_authority_challenge_denied",
            ));
        }
        Ok(())
    }

    pub fn validate_client_context(
        &self,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> DirectOperationRuntimeAuthorityResult<()> {
        validate_binding_and_custody(binding, binding_sha256, adapter, custody)?;
        if self.binding_sha256 != binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || self.provider_id != binding.stable_seed.provider_id
            || self.agent_id != binding.stable_seed.agent_id
            || self.adapter != adapter
            || self.kernel_launch_custody_sha256 != custody.launch_custody_sha256
            || !valid_nonzero_sha256(&self.adapter_peer_identity_sha256)
            || !valid_nonzero_sha256(&self.server_nonce_sha256)
            || !valid_nonzero_sha256(&self.challenge_sha256)
            || self.canonical_sha256()? != self.challenge_sha256
        {
            return Err(denied(
                "direct_operation_runtime_authority_challenge_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityResult<String> {
        if self.schema != SESSION_CHALLENGE_V3_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_prefixed_sha256(&self.invocation_id, "inv:")
            || !valid_prefixed_sha256(&self.delivery_provider_attempt_id, "attempt:")
            || agent_descriptor_registry::from_provider_agent_pair(
                &self.provider_id,
                &self.agent_id,
            )
            .is_none()
            || !valid_nonzero_sha256(&self.kernel_launch_custody_sha256)
            || !valid_nonzero_sha256(&self.adapter_peer_identity_sha256)
            || !valid_nonzero_sha256(&self.server_nonce_sha256)
        {
            return Err(denied(
                "direct_operation_runtime_authority_challenge_denied",
            ));
        }
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", CHALLENGE_BINDING_DOMAIN)?;
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(&mut hasher, "operation", &self.operation)?;
        hash_string(&mut hasher, "binding_sha256", &self.binding_sha256)?;
        hash_string(&mut hasher, "invocation_id", &self.invocation_id)?;
        hash_string(
            &mut hasher,
            "delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        )?;
        hash_string(&mut hasher, "provider_id", &self.provider_id)?;
        hash_string(&mut hasher, "agent_id", &self.agent_id)?;
        hash_string(&mut hasher, "adapter", self.adapter.adapter_id())?;
        hash_string(
            &mut hasher,
            "kernel_launch_custody_sha256",
            &self.kernel_launch_custody_sha256,
        )?;
        hash_string(
            &mut hasher,
            "adapter_peer_identity_sha256",
            &self.adapter_peer_identity_sha256,
        )?;
        hash_string(
            &mut hasher,
            "server_nonce_sha256",
            &self.server_nonce_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// Adapter echo authored only after validating the daemon-first challenge on
/// the same authenticated connection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthoritySessionHelloV3 {
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
    pub challenge_sha256: String,
    pub adapter_peer_identity_sha256: String,
    pub server_nonce_sha256: String,
    pub hello_sha256: String,
}

impl DirectOperationRuntimeAuthoritySessionHelloV3 {
    pub fn derive(
        challenge: &DirectOperationRuntimeAuthoritySessionChallengeV3,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> DirectOperationRuntimeAuthorityResult<Self> {
        challenge.validate_client_context(binding, binding_sha256, adapter, custody)?;
        let mut hello = Self {
            schema: SESSION_HELLO_V3_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: OPERATION.to_string(),
            binding_sha256: binding_sha256.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter,
            kernel_launch_custody_sha256: custody.launch_custody_sha256.clone(),
            challenge_sha256: challenge.challenge_sha256.clone(),
            adapter_peer_identity_sha256: challenge.adapter_peer_identity_sha256.clone(),
            server_nonce_sha256: challenge.server_nonce_sha256.clone(),
            hello_sha256: String::new(),
        };
        hello.hello_sha256 = hello.canonical_sha256()?;
        hello.validate_for(challenge, binding, binding_sha256, adapter, custody)?;
        Ok(hello)
    }

    pub fn validate_for(
        &self,
        challenge: &DirectOperationRuntimeAuthoritySessionChallengeV3,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        custody: &DirectOperationKernelLaunchCustodyV3,
    ) -> DirectOperationRuntimeAuthorityResult<()> {
        challenge.validate_client_context(binding, binding_sha256, adapter, custody)?;
        if self.binding_sha256 != binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || self.provider_id != binding.stable_seed.provider_id
            || self.agent_id != binding.stable_seed.agent_id
            || self.adapter != adapter
            || self.kernel_launch_custody_sha256 != custody.launch_custody_sha256
            || self.challenge_sha256 != challenge.challenge_sha256
            || self.adapter_peer_identity_sha256 != challenge.adapter_peer_identity_sha256
            || self.server_nonce_sha256 != challenge.server_nonce_sha256
        {
            return Err(denied("direct_operation_runtime_authority_hello_denied"));
        }
        self.validate_closed()
    }

    /// Canonical typed-field digest.  `hello_sha256` is intentionally excluded
    /// from its own preimage.
    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityResult<String> {
        if self.schema != SESSION_HELLO_V3_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != OPERATION
            || !valid_nonzero_sha256(&self.binding_sha256)
            || !valid_prefixed_sha256(&self.invocation_id, "inv:")
            || !valid_prefixed_sha256(&self.delivery_provider_attempt_id, "attempt:")
            || agent_descriptor_registry::from_provider_agent_pair(
                &self.provider_id,
                &self.agent_id,
            )
            .is_none()
            || !valid_nonzero_sha256(&self.kernel_launch_custody_sha256)
            || !valid_nonzero_sha256(&self.challenge_sha256)
            || !valid_nonzero_sha256(&self.adapter_peer_identity_sha256)
            || !valid_nonzero_sha256(&self.server_nonce_sha256)
        {
            return Err(denied("direct_operation_runtime_authority_hello_denied"));
        }
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", HELLO_BINDING_DOMAIN)?;
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(&mut hasher, "operation", &self.operation)?;
        hash_string(&mut hasher, "binding_sha256", &self.binding_sha256)?;
        hash_string(&mut hasher, "invocation_id", &self.invocation_id)?;
        hash_string(
            &mut hasher,
            "delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        )?;
        hash_string(&mut hasher, "provider_id", &self.provider_id)?;
        hash_string(&mut hasher, "agent_id", &self.agent_id)?;
        hash_string(&mut hasher, "adapter", self.adapter.adapter_id())?;
        hash_string(
            &mut hasher,
            "kernel_launch_custody_sha256",
            &self.kernel_launch_custody_sha256,
        )?;
        hash_string(&mut hasher, "challenge_sha256", &self.challenge_sha256)?;
        hash_string(
            &mut hasher,
            "adapter_peer_identity_sha256",
            &self.adapter_peer_identity_sha256,
        )?;
        hash_string(
            &mut hasher,
            "server_nonce_sha256",
            &self.server_nonce_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_closed(&self) -> DirectOperationRuntimeAuthorityResult<()> {
        if !valid_nonzero_sha256(&self.hello_sha256)
            || self.canonical_sha256()? != self.hello_sha256
        {
            return Err(denied("direct_operation_runtime_authority_hello_denied"));
        }
        Ok(())
    }
}

/// Endpoint-typed observation.  First-use and replay are intentionally
/// disjoint closed variants, so fields from one phase cannot be accepted in
/// the other.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectOperationRuntimeAuthorityObservationV3 {
    FirstUse {
        state_directory_identity_sha256: String,
        journal_name_absent: bool,
        sentinel_name_absent: bool,
    },
    Replay {
        state_directory_identity_sha256: String,
        journal_epoch: String,
        current_journal_identity_sha256: String,
        current_journal_bytes_sha256: String,
        sentinel_identity_sha256: String,
        sentinel_bytes_sha256: String,
        first_use_committed_result_binding_sha256: String,
    },
}

impl DirectOperationRuntimeAuthorityObservationV3 {
    #[must_use]
    pub const fn is_first_use(&self) -> bool {
        matches!(self, Self::FirstUse { .. })
    }

    #[must_use]
    pub const fn is_replay(&self) -> bool {
        matches!(self, Self::Replay { .. })
    }

    fn validate(&self) -> DirectOperationRuntimeAuthorityResult<()> {
        match self {
            Self::FirstUse {
                state_directory_identity_sha256,
                journal_name_absent,
                sentinel_name_absent,
            } => {
                if !valid_nonzero_sha256(state_directory_identity_sha256)
                    || !journal_name_absent
                    || !sentinel_name_absent
                {
                    return Err(denied(
                        "direct_operation_runtime_authority_first_use_probe_denied",
                    ));
                }
            }
            Self::Replay {
                state_directory_identity_sha256,
                journal_epoch,
                current_journal_identity_sha256,
                current_journal_bytes_sha256,
                sentinel_identity_sha256,
                sentinel_bytes_sha256,
                first_use_committed_result_binding_sha256,
            } => {
                if !valid_nonzero_sha256(state_directory_identity_sha256)
                    || !valid_journal_epoch(journal_epoch)
                    || !valid_nonzero_sha256(current_journal_identity_sha256)
                    || !valid_nonzero_sha256(current_journal_bytes_sha256)
                    || !valid_nonzero_sha256(sentinel_identity_sha256)
                    || !valid_nonzero_sha256(sentinel_bytes_sha256)
                    || !valid_nonzero_sha256(first_use_committed_result_binding_sha256)
                {
                    return Err(denied(
                        "direct_operation_runtime_authority_replay_probe_denied",
                    ));
                }
            }
        }
        Ok(())
    }

    fn hash_into(&self, hasher: &mut Sha256) -> DirectOperationRuntimeAuthorityResult<()> {
        self.validate()?;
        match self {
            Self::FirstUse {
                state_directory_identity_sha256,
                journal_name_absent,
                sentinel_name_absent,
            } => {
                hash_string(hasher, "phase", "first_use")?;
                hash_string(
                    hasher,
                    "state_directory_identity_sha256",
                    state_directory_identity_sha256,
                )?;
                hash_bool(hasher, "journal_name_absent", *journal_name_absent)?;
                hash_bool(hasher, "sentinel_name_absent", *sentinel_name_absent)?;
            }
            Self::Replay {
                state_directory_identity_sha256,
                journal_epoch,
                current_journal_identity_sha256,
                current_journal_bytes_sha256,
                sentinel_identity_sha256,
                sentinel_bytes_sha256,
                first_use_committed_result_binding_sha256,
            } => {
                hash_string(hasher, "phase", "replay")?;
                hash_string(
                    hasher,
                    "state_directory_identity_sha256",
                    state_directory_identity_sha256,
                )?;
                hash_string(hasher, "journal_epoch", journal_epoch)?;
                hash_string(
                    hasher,
                    "current_journal_identity_sha256",
                    current_journal_identity_sha256,
                )?;
                hash_string(
                    hasher,
                    "current_journal_bytes_sha256",
                    current_journal_bytes_sha256,
                )?;
                hash_string(hasher, "sentinel_identity_sha256", sentinel_identity_sha256)?;
                hash_string(hasher, "sentinel_bytes_sha256", sentinel_bytes_sha256)?;
                hash_string(
                    hasher,
                    "first_use_committed_result_binding_sha256",
                    first_use_committed_result_binding_sha256,
                )?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityProbeV3 {
    pub schema: String,
    pub protocol: String,
    pub hello_sha256: String,
    pub observation: DirectOperationRuntimeAuthorityObservationV3,
    pub probe_sha256: String,
}

impl DirectOperationRuntimeAuthorityProbeV3 {
    pub fn derive_first_use(
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
        state_directory_identity_sha256: &str,
    ) -> DirectOperationRuntimeAuthorityResult<Self> {
        Self::derive(
            hello,
            DirectOperationRuntimeAuthorityObservationV3::FirstUse {
                state_directory_identity_sha256: state_directory_identity_sha256.to_string(),
                journal_name_absent: true,
                sentinel_name_absent: true,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derive_replay(
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
        state_directory_identity_sha256: &str,
        journal_epoch: &str,
        current_journal_identity_sha256: &str,
        current_journal_bytes_sha256: &str,
        sentinel_identity_sha256: &str,
        sentinel_bytes_sha256: &str,
        first_use_committed_result_binding_sha256: &str,
    ) -> DirectOperationRuntimeAuthorityResult<Self> {
        Self::derive(
            hello,
            DirectOperationRuntimeAuthorityObservationV3::Replay {
                state_directory_identity_sha256: state_directory_identity_sha256.to_string(),
                journal_epoch: journal_epoch.to_string(),
                current_journal_identity_sha256: current_journal_identity_sha256.to_string(),
                current_journal_bytes_sha256: current_journal_bytes_sha256.to_string(),
                sentinel_identity_sha256: sentinel_identity_sha256.to_string(),
                sentinel_bytes_sha256: sentinel_bytes_sha256.to_string(),
                first_use_committed_result_binding_sha256:
                    first_use_committed_result_binding_sha256.to_string(),
            },
        )
    }

    pub fn derive(
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
        observation: DirectOperationRuntimeAuthorityObservationV3,
    ) -> DirectOperationRuntimeAuthorityResult<Self> {
        hello.validate_closed()?;
        observation.validate()?;
        let mut probe = Self {
            schema: PROBE_V3_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            hello_sha256: hello.hello_sha256.clone(),
            observation,
            probe_sha256: String::new(),
        };
        probe.probe_sha256 = probe.canonical_sha256()?;
        probe.validate_for_hello(hello)?;
        Ok(probe)
    }

    pub fn validate_for_hello(
        &self,
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
    ) -> DirectOperationRuntimeAuthorityResult<()> {
        hello.validate_closed()?;
        if self.hello_sha256 != hello.hello_sha256
            || !valid_nonzero_sha256(&self.probe_sha256)
            || self.canonical_sha256()? != self.probe_sha256
        {
            return Err(denied("direct_operation_runtime_authority_probe_denied"));
        }
        Ok(())
    }

    pub fn validate_first_use_for_hello(
        &self,
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
    ) -> DirectOperationRuntimeAuthorityResult<()> {
        self.validate_for_hello(hello)?;
        if !self.observation.is_first_use() {
            return Err(denied(
                "direct_operation_runtime_authority_first_use_probe_denied",
            ));
        }
        Ok(())
    }

    pub fn validate_replay_for_hello(
        &self,
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
    ) -> DirectOperationRuntimeAuthorityResult<()> {
        self.validate_for_hello(hello)?;
        if !self.observation.is_replay() {
            return Err(denied(
                "direct_operation_runtime_authority_replay_probe_denied",
            ));
        }
        Ok(())
    }

    /// Canonical typed-field digest.  `probe_sha256` is intentionally excluded
    /// from its own preimage.
    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityResult<String> {
        if self.schema != PROBE_V3_SCHEMA
            || self.protocol != PROTOCOL
            || !valid_nonzero_sha256(&self.hello_sha256)
        {
            return Err(denied("direct_operation_runtime_authority_probe_denied"));
        }
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", PROBE_BINDING_DOMAIN)?;
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(&mut hasher, "hello_sha256", &self.hello_sha256)?;
        self.observation.hash_into(&mut hasher)?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// The sole product-deserializable result.  No success/authorization result
/// exists in this v1 ABI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityHoldV3 {
    pub schema: String,
    pub protocol: String,
    pub hello_sha256: String,
    pub probe_sha256: String,
    pub code: String,
    pub retryable: bool,
    pub response_sha256: String,
}

impl DirectOperationRuntimeAuthorityHoldV3 {
    pub fn derive(
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
        probe: &DirectOperationRuntimeAuthorityProbeV3,
    ) -> DirectOperationRuntimeAuthorityResult<Self> {
        probe.validate_for_hello(hello)?;
        let mut hold = Self {
            schema: HOLD_V3_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            hello_sha256: hello.hello_sha256.clone(),
            probe_sha256: probe.probe_sha256.clone(),
            code: HOLD_CODE.to_string(),
            retryable: false,
            response_sha256: String::new(),
        };
        hold.response_sha256 = hold.canonical_sha256()?;
        hold.validate_for(hello, probe)?;
        Ok(hold)
    }

    pub fn validate_for(
        &self,
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
        probe: &DirectOperationRuntimeAuthorityProbeV3,
    ) -> DirectOperationRuntimeAuthorityResult<()> {
        probe.validate_for_hello(hello)?;
        if self.hello_sha256 != hello.hello_sha256
            || self.probe_sha256 != probe.probe_sha256
            || !valid_nonzero_sha256(&self.response_sha256)
            || self.canonical_sha256()? != self.response_sha256
        {
            return Err(denied("direct_operation_runtime_authority_hold_denied"));
        }
        Ok(())
    }

    /// Canonical typed-field digest.  `response_sha256` is intentionally
    /// excluded from its own preimage.
    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityResult<String> {
        if self.schema != HOLD_V3_SCHEMA
            || self.protocol != PROTOCOL
            || !valid_nonzero_sha256(&self.hello_sha256)
            || !valid_nonzero_sha256(&self.probe_sha256)
            || self.code != HOLD_CODE
            || self.retryable
        {
            return Err(denied("direct_operation_runtime_authority_hold_denied"));
        }
        let mut hasher = Sha256::new();
        hash_string(&mut hasher, "domain", HOLD_BINDING_DOMAIN)?;
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(&mut hasher, "hello_sha256", &self.hello_sha256)?;
        hash_string(&mut hasher, "probe_sha256", &self.probe_sha256)?;
        hash_string(&mut hasher, "code", &self.code)?;
        hash_bool(&mut hasher, "retryable", self.retryable)?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

fn validate_binding_and_custody(
    binding: &DirectOperationBinding,
    binding_sha256: &str,
    adapter: DirectOperationAdapter,
    custody: &DirectOperationKernelLaunchCustodyV3,
) -> DirectOperationRuntimeAuthorityResult<()> {
    binding
        .validate()
        .map_err(|_| denied("direct_operation_runtime_authority_binding_denied"))?;
    if !valid_nonzero_sha256(binding_sha256)
        || binding
            .digest_sha256()
            .map_err(|_| denied("direct_operation_runtime_authority_binding_denied"))?
            != binding_sha256
    {
        return Err(denied("direct_operation_runtime_authority_binding_denied"));
    }
    custody
        .validate_for(binding, binding_sha256, adapter)
        .map_err(|_| denied("direct_operation_runtime_authority_custody_denied"))
}

fn hash_string(
    hasher: &mut Sha256,
    name: &str,
    value: &str,
) -> DirectOperationRuntimeAuthorityResult<()> {
    hash_bytes(hasher, name, value.as_bytes())
}

fn hash_bool(
    hasher: &mut Sha256,
    name: &str,
    value: bool,
) -> DirectOperationRuntimeAuthorityResult<()> {
    hash_bytes(hasher, name, &[u8::from(value)])
}

fn hash_bytes(
    hasher: &mut Sha256,
    name: &str,
    value: &[u8],
) -> DirectOperationRuntimeAuthorityResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("direct_operation_runtime_authority_digest_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("direct_operation_runtime_authority_digest_denied"))?;
    hasher.update(name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && !value.bytes().all(|byte| byte == b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_prefixed_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_nonzero_sha256)
}

fn valid_journal_epoch(value: &str) -> bool {
    value.len() == JOURNAL_EPOCH_HEX_BYTES
        && !value.bytes().all(|byte| byte == b'0')
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

const fn denied(code: &'static str) -> DirectOperationRuntimeAuthorityError {
    DirectOperationRuntimeAuthorityError(code)
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use super::*;
    use crate::direct_operation::{
        BINDING_SCHEMA, DirectOperationProviderAttempt, DirectOperationStableSeed,
        KERNEL_LAUNCH_CUSTODY_KIND_V3, KERNEL_LAUNCH_CUSTODY_PRODUCER_V3,
        KERNEL_LAUNCH_CUSTODY_V3_SCHEMA, STABLE_SEED_SCHEMA, adapter_binary_kind,
        fixed_adapter_cgroup_path,
    };
    use crate::sha256_bytes;

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    fn binding() -> DirectOperationBinding {
        let seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: "task.runtime-authority".to_string(),
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
        adapter: DirectOperationAdapter,
    ) -> DirectOperationKernelLaunchCustodyV3 {
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

    struct Fixture {
        binding: DirectOperationBinding,
        binding_sha256: String,
        adapter: DirectOperationAdapter,
        custody: DirectOperationKernelLaunchCustodyV3,
        peer_sha256: String,
        nonce_sha256: String,
        challenge: DirectOperationRuntimeAuthoritySessionChallengeV3,
        hello: DirectOperationRuntimeAuthoritySessionHelloV3,
    }

    fn fixture() -> Fixture {
        let binding = binding();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let adapter = DirectOperationAdapter::SystemApi;
        let custody = custody(&binding, &binding_sha256, adapter);
        let peer_sha256 = digest("peer");
        let nonce_sha256 = digest("nonce");
        let challenge = DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
            &binding,
            &binding_sha256,
            adapter,
            &custody,
            &peer_sha256,
            &nonce_sha256,
        )
        .unwrap();
        let hello = DirectOperationRuntimeAuthoritySessionHelloV3::derive(
            &challenge,
            &binding,
            &binding_sha256,
            adapter,
            &custody,
        )
        .unwrap();
        Fixture {
            binding,
            binding_sha256,
            adapter,
            custody,
            peer_sha256,
            nonce_sha256,
            challenge,
            hello,
        }
    }

    fn replay_probe(
        hello: &DirectOperationRuntimeAuthoritySessionHelloV3,
    ) -> DirectOperationRuntimeAuthorityProbeV3 {
        DirectOperationRuntimeAuthorityProbeV3::derive_replay(
            hello,
            &digest("state-directory"),
            &"01".repeat(16),
            &digest("journal-identity"),
            &digest("journal-bytes"),
            &digest("sentinel-identity"),
            &digest("sentinel-bytes"),
            &digest("first-use-commit"),
        )
        .unwrap()
    }

    fn refresh_hello(hello: &mut DirectOperationRuntimeAuthoritySessionHelloV3) {
        hello.hello_sha256 = hello.canonical_sha256().unwrap();
    }

    #[test]
    fn canonical_hello_probe_and_hold_round_trip() {
        let fixture = fixture();
        let first_use = DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
            &fixture.hello,
            &digest("state-directory"),
        )
        .unwrap();
        let replay = replay_probe(&fixture.hello);
        let hold = DirectOperationRuntimeAuthorityHoldV3::derive(&fixture.hello, &replay).unwrap();

        fixture
            .challenge
            .validate_for(
                &fixture.binding,
                &fixture.binding_sha256,
                fixture.adapter,
                &fixture.custody,
                &fixture.peer_sha256,
                &fixture.nonce_sha256,
            )
            .unwrap();
        fixture
            .hello
            .validate_for(
                &fixture.challenge,
                &fixture.binding,
                &fixture.binding_sha256,
                fixture.adapter,
                &fixture.custody,
            )
            .unwrap();
        first_use
            .validate_first_use_for_hello(&fixture.hello)
            .unwrap();
        replay.validate_replay_for_hello(&fixture.hello).unwrap();
        hold.validate_for(&fixture.hello, &replay).unwrap();

        let challenge_bytes = serde_json::to_vec(&fixture.challenge).unwrap();
        let hello_bytes = serde_json::to_vec(&fixture.hello).unwrap();
        let probe_bytes = serde_json::to_vec(&replay).unwrap();
        let hold_bytes = serde_json::to_vec(&hold).unwrap();
        assert_eq!(
            serde_json::to_vec(
                &serde_json::from_slice::<DirectOperationRuntimeAuthoritySessionChallengeV3>(
                    &challenge_bytes,
                )
                .unwrap()
            )
            .unwrap(),
            challenge_bytes
        );
        assert_eq!(
            serde_json::to_vec(
                &serde_json::from_slice::<DirectOperationRuntimeAuthoritySessionHelloV3>(
                    &hello_bytes,
                )
                .unwrap()
            )
            .unwrap(),
            hello_bytes
        );
        assert_eq!(
            serde_json::to_vec(
                &serde_json::from_slice::<DirectOperationRuntimeAuthorityProbeV3>(&probe_bytes,)
                    .unwrap()
            )
            .unwrap(),
            probe_bytes
        );
        assert_eq!(
            serde_json::to_vec(
                &serde_json::from_slice::<DirectOperationRuntimeAuthorityHoldV3>(&hold_bytes)
                    .unwrap()
            )
            .unwrap(),
            hold_bytes
        );
    }

    #[test]
    fn schemas_reject_unknown_missing_and_type_drift() {
        let fixture = fixture();
        let probe = replay_probe(&fixture.hello);
        let hold = DirectOperationRuntimeAuthorityHoldV3::derive(&fixture.hello, &probe).unwrap();

        let mut challenge_unknown = serde_json::to_value(&fixture.challenge).unwrap();
        challenge_unknown["caller_selected_nonce"] = serde_json::Value::String(digest("forged"));
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthoritySessionChallengeV3>(
                challenge_unknown,
            )
            .is_err()
        );
        let mut challenge_missing = serde_json::to_value(&fixture.challenge).unwrap();
        challenge_missing
            .as_object_mut()
            .unwrap()
            .remove("adapter_peer_identity_sha256");
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthoritySessionChallengeV3>(
                challenge_missing,
            )
            .is_err()
        );
        let mut challenge_type = serde_json::to_value(&fixture.challenge).unwrap();
        challenge_type["server_nonce_sha256"] = serde_json::json!(7);
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthoritySessionChallengeV3>(
                challenge_type,
            )
            .is_err()
        );

        let mut hello_unknown = serde_json::to_value(&fixture.hello).unwrap();
        hello_unknown["success_authority_sha256"] =
            serde_json::Value::String(digest("forged-success"));
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthoritySessionHelloV3>(hello_unknown)
                .is_err()
        );
        let mut hello_missing = serde_json::to_value(&fixture.hello).unwrap();
        hello_missing.as_object_mut().unwrap().remove("agent_id");
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthoritySessionHelloV3>(hello_missing)
                .is_err()
        );
        let mut hello_type = serde_json::to_value(&fixture.hello).unwrap();
        hello_type["adapter"] = serde_json::json!(7);
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthoritySessionHelloV3>(hello_type)
                .is_err()
        );

        let mut probe_unknown = serde_json::to_value(&probe).unwrap();
        probe_unknown["rollback_high_water"] = serde_json::json!(1);
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthorityProbeV3>(probe_unknown)
                .is_err()
        );
        let mut probe_missing = serde_json::to_value(&probe).unwrap();
        probe_missing.as_object_mut().unwrap().remove("observation");
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthorityProbeV3>(probe_missing)
                .is_err()
        );
        let mut probe_type = serde_json::to_value(&probe).unwrap();
        probe_type["hello_sha256"] = serde_json::json!(false);
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthorityProbeV3>(probe_type).is_err()
        );

        let mut hold_unknown = serde_json::to_value(&hold).unwrap();
        hold_unknown["replay_authorized"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthorityHoldV3>(hold_unknown).is_err()
        );
        let mut hold_missing = serde_json::to_value(&hold).unwrap();
        hold_missing.as_object_mut().unwrap().remove("code");
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthorityHoldV3>(hold_missing).is_err()
        );
        let mut hold_type = serde_json::to_value(&hold).unwrap();
        hold_type["retryable"] = serde_json::json!("false");
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthorityHoldV3>(hold_type).is_err()
        );
    }

    #[test]
    fn binding_agent_adapter_custody_peer_and_nonce_drift_fail_closed() {
        let fixture = fixture();

        let mut binding_hash_drift = fixture.hello.clone();
        binding_hash_drift.binding_sha256 = digest("other-binding");
        refresh_hello(&mut binding_hash_drift);
        assert!(
            binding_hash_drift
                .validate_for(
                    &fixture.challenge,
                    &fixture.binding,
                    &fixture.binding_sha256,
                    fixture.adapter,
                    &fixture.custody,
                )
                .is_err()
        );

        let mut identity_drift = fixture.hello.clone();
        identity_drift.provider_id = "unregistered-provider".to_string();
        identity_drift.agent_id = "unregistered-agent".to_string();
        assert!(identity_drift.canonical_sha256().is_err());

        let mut adapter_drift = fixture.hello.clone();
        adapter_drift.adapter = DirectOperationAdapter::Accessibility;
        refresh_hello(&mut adapter_drift);
        assert!(
            adapter_drift
                .validate_for(
                    &fixture.challenge,
                    &fixture.binding,
                    &fixture.binding_sha256,
                    fixture.adapter,
                    &fixture.custody,
                )
                .is_err()
        );

        let mut custody_drift = fixture.hello.clone();
        custody_drift.kernel_launch_custody_sha256 = digest("other-custody");
        refresh_hello(&mut custody_drift);
        assert!(
            custody_drift
                .validate_for(
                    &fixture.challenge,
                    &fixture.binding,
                    &fixture.binding_sha256,
                    fixture.adapter,
                    &fixture.custody,
                )
                .is_err()
        );

        let mut peer_drift = fixture.hello.clone();
        peer_drift.adapter_peer_identity_sha256 = digest("other-peer");
        refresh_hello(&mut peer_drift);
        assert!(
            peer_drift
                .validate_for(
                    &fixture.challenge,
                    &fixture.binding,
                    &fixture.binding_sha256,
                    fixture.adapter,
                    &fixture.custody,
                )
                .is_err()
        );

        let mut nonce_drift = fixture.hello.clone();
        nonce_drift.server_nonce_sha256 = digest("other-nonce");
        refresh_hello(&mut nonce_drift);
        assert!(
            nonce_drift
                .validate_for(
                    &fixture.challenge,
                    &fixture.binding,
                    &fixture.binding_sha256,
                    fixture.adapter,
                    &fixture.custody,
                )
                .is_err()
        );
    }

    #[test]
    fn phase_and_response_correlation_are_exact() {
        let fixture = fixture();
        let first_use = DirectOperationRuntimeAuthorityProbeV3::derive_first_use(
            &fixture.hello,
            &digest("state-directory"),
        )
        .unwrap();
        let replay = replay_probe(&fixture.hello);
        assert!(first_use.validate_replay_for_hello(&fixture.hello).is_err());
        assert!(replay.validate_first_use_for_hello(&fixture.hello).is_err());

        let mut hello_digest_drift = fixture.hello.clone();
        hello_digest_drift.hello_sha256 = digest("other-hello");
        assert!(
            hello_digest_drift
                .validate_for(
                    &fixture.challenge,
                    &fixture.binding,
                    &fixture.binding_sha256,
                    fixture.adapter,
                    &fixture.custody,
                )
                .is_err()
        );

        let mut false_absence = first_use.clone();
        let DirectOperationRuntimeAuthorityObservationV3::FirstUse {
            journal_name_absent,
            ..
        } = &mut false_absence.observation
        else {
            unreachable!()
        };
        *journal_name_absent = false;
        assert!(false_absence.canonical_sha256().is_err());

        let mut probe_digest_drift = replay.clone();
        probe_digest_drift.probe_sha256 = digest("other-probe");
        assert!(
            probe_digest_drift
                .validate_for_hello(&fixture.hello)
                .is_err()
        );

        let hold = DirectOperationRuntimeAuthorityHoldV3::derive(&fixture.hello, &replay).unwrap();
        let mut response_digest_drift = hold.clone();
        response_digest_drift.response_sha256 = digest("other-response");
        assert!(
            response_digest_drift
                .validate_for(&fixture.hello, &replay)
                .is_err()
        );
        let mut wrong_probe = hold.clone();
        wrong_probe.probe_sha256 = first_use.probe_sha256.clone();
        wrong_probe.response_sha256 = wrong_probe.canonical_sha256().unwrap();
        assert!(wrong_probe.validate_for(&fixture.hello, &replay).is_err());
        let mut forged_success = hold.clone();
        forged_success.code = "replay_authorized".to_string();
        assert!(forged_success.canonical_sha256().is_err());
        let mut retryable = hold;
        retryable.retryable = true;
        assert!(retryable.canonical_sha256().is_err());
    }

    #[test]
    fn zero_uppercase_and_replay_digest_drift_fail_closed() {
        let fixture = fixture();
        assert!(
            DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
                &fixture.binding,
                &fixture.binding_sha256,
                fixture.adapter,
                &fixture.custody,
                &"0".repeat(64),
                &fixture.nonce_sha256,
            )
            .is_err()
        );
        assert!(
            DirectOperationRuntimeAuthoritySessionChallengeV3::derive(
                &fixture.binding,
                &fixture.binding_sha256,
                fixture.adapter,
                &fixture.custody,
                &fixture.peer_sha256,
                &"A".repeat(64),
            )
            .is_err()
        );
        assert!(
            DirectOperationRuntimeAuthorityProbeV3::derive_replay(
                &fixture.hello,
                &digest("state-directory"),
                &"00".repeat(16),
                &digest("journal-identity"),
                &digest("journal-bytes"),
                &digest("sentinel-identity"),
                &digest("sentinel-bytes"),
                &digest("first-use-commit"),
            )
            .is_err()
        );
        assert!(
            DirectOperationRuntimeAuthorityProbeV3::derive_replay(
                &fixture.hello,
                &digest("state-directory"),
                &"AA".repeat(16),
                &digest("journal-identity"),
                &digest("journal-bytes"),
                &digest("sentinel-identity"),
                &digest("sentinel-bytes"),
                &digest("first-use-commit"),
            )
            .is_err()
        );
        assert!(
            DirectOperationRuntimeAuthorityProbeV3::derive_replay(
                &fixture.hello,
                &digest("state-directory"),
                &"01".repeat(16),
                &digest("journal-identity"),
                &"F".repeat(64),
                &digest("sentinel-identity"),
                &digest("sentinel-bytes"),
                &digest("first-use-commit"),
            )
            .is_err()
        );
    }

    #[test]
    fn source_only_flags_and_fixed_namespace_are_disjoint() {
        assert!(SOURCE_CLIENT_IMPLEMENTED);
        assert!(!SOURCE_LISTENER_IMPLEMENTED);
        assert!(SOURCE_INJECTED_HANDLER_IMPLEMENTED);
        assert!(SOURCE_HOLD_RESPONSE_IMPLEMENTED);
        assert!(!EXTERNAL_RUNTIME_AUTHORITY_PRODUCT_AVAILABLE);
        assert!(!DAEMON_LISTENER_PRODUCT_WIRED);
        assert!(!ADAPTER_CONNECTOR_PRODUCT_WIRED);
        assert!(!AUTHORITY_BACKEND_PRODUCT_WIRED);
        assert!(!FIRST_USE_DECISION_PRODUCT_AVAILABLE);
        assert!(!REPLAY_DECISION_PRODUCT_AVAILABLE);
        assert!(!FIRST_USE_PRODUCT_WIRED);
        assert!(!REPLAY_PRODUCT_WIRED);
        assert!(!MUTATION_CAS_PRODUCT_AVAILABLE);
        assert!(!ACTIVATION_PRODUCT_WIRED);
        assert!(!ANDROID_ACTIVATION_PRODUCT_WIRED);
        assert!(!ROLLBACK_HIGH_WATER_PRODUCT_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);

        assert_eq!(SOCKET_ADDRESS, format!("@{SOCKET_NAME}"));
        assert_ne!(
            SOCKET_NAME,
            crate::direct_operation_tool_call_transport::SOCKET_NAME
        );
        assert_ne!(
            SOCKET_NAME,
            crate::capability_lease_root_route_transport::SOCKET_NAME
        );
        assert_ne!(SOCKET_NAME, "trillionnium_system_api_replay_control");
        assert_ne!(SOCKET_NAME, "trillionnium_accessibility_replay_control");
        assert_ne!(
            PROTOCOL,
            crate::direct_operation_tool_call_transport::PROTOCOL
        );
        assert_ne!(PROTOCOL, crate::capability_lease_root_publication::PROTOCOL);
    }
}
