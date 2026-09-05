//! Closed draft-v2 wire foundation for the Android privilege broker.
//!
//! The contract deliberately has no path, uid, gid, pid, executable, argv, or
//! environment input. A provider is selected from a closed enum and all
//! executable/credential locations remain broker-owned manifest data. Large
//! inputs and outputs use one exact sealed, read-only memfd whose size and
//! digest are bound into the JSON frame.
//!
//! The production broker can run this contract in foundation-only mode while
//! its mutation backend is still absent. In that mode every lifecycle request
//! returns an exact [`Response::MutationUnavailable`] and cannot advance the
//! shared [`LifecycleState`]. Source-only provider-leaf recovery/reservation
//! shapes are defined for fault testing, but are intentionally not variants of
//! [`Request`]. The draft is deliberately not freeze-ready: the operational
//! durable wire protocol, credential revocation, and typed recovery hydration
//! still require review.

use std::collections::HashSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use trillionnium_os_types::agent_descriptor_registry::CODEX;

#[cfg(feature = "p0-launch-package-device-conformance")]
pub mod p0_launch_package_device_conformance;

pub const PROTOCOL_VERSION: u16 = 2;
pub const MAX_FRAME_BYTES: usize = 4_096;
pub const FIXED_BYTES: usize = 32;
pub const MAX_CREDENTIAL_BYTES: u64 = 1_048_576;
pub const MAX_INVOCATION_REQUEST_BYTES: u64 = 1_048_576;
pub const MAX_INVOCATION_REPORT_BYTES: u64 = 262_144;
pub const MAX_RECOVERY_EVIDENCE_BYTES: u64 = 262_144;
pub const MAX_ANCILLARY_PAYLOAD_BYTES: u64 = MAX_CREDENTIAL_BYTES;
pub const MAX_REQUESTS_PER_SESSION: u64 = 1_024;
pub const MAX_INVOCATIONS_PER_SESSION: usize = 64;
pub const FOUNDATION_MUTATIONS_ENABLED: bool = false;
pub const OPERATIONAL_HANDLES_REQUIRE_PIDFD_OWNERSHIP: bool = true;
pub const PROTOCOL_FREEZE_READY: bool = false;

/// A non-zero, fixed-width value used anywhere a random binding or digest is
/// required.  JSON uses an exact 32-byte array; strings and variable-length
/// byte vectors are intentionally not accepted.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FixedBytes32([u8; FIXED_BYTES]);

impl FixedBytes32 {
    pub fn new(bytes: [u8; FIXED_BYTES]) -> Result<Self, ProtocolError> {
        if bytes == [0; FIXED_BYTES] {
            return Err(ProtocolError::ZeroFixedValue);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; FIXED_BYTES] {
        &self.0
    }

    #[cfg(test)]
    fn test_value(value: u8) -> Self {
        assert_ne!(value, 0);
        Self([value; FIXED_BYTES])
    }
}

impl<'de> Deserialize<'de> for FixedBytes32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = <[u8; FIXED_BYTES]>::deserialize(deserializer)?;
        Self::new(bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionBinding(FixedBytes32);

impl SessionBinding {
    pub const fn new(value: FixedBytes32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> FixedBytes32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Nonce(FixedBytes32);

impl Nonce {
    pub const fn new(value: FixedBytes32) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Digest(FixedBytes32);

impl Digest {
    pub const fn new(value: FixedBytes32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> FixedBytes32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueHandle(FixedBytes32);

impl OpaqueHandle {
    pub const fn new(value: FixedBytes32) -> Self {
        Self(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InvocationId(FixedBytes32);

impl InvocationId {
    pub const fn new(value: FixedBytes32) -> Self {
        Self(value)
    }
}

/// OS-allocated operation identity for one provider-leaf custody cycle. This
/// is deliberately distinct from an invocation ID: the kernel lifecycle must
/// be recoverable before a provider invocation exists.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LifecycleOperationId(FixedBytes32);

impl LifecycleOperationId {
    pub const fn new(value: FixedBytes32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> FixedBytes32 {
        self.0
    }
}

/// OS-allocated identity for a single reservation of an empty, frozen
/// provider cgroup leaf. The in-memory foundation retires accepted identities
/// for its process lifetime; an operational implementation would require a
/// durable tombstone before making the same claim across restart. The identity
/// may never select a path, PID, UID, executable, or cgroup.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LifecycleReservationId(FixedBytes32);

impl LifecycleReservationId {
    pub const fn new(value: FixedBytes32) -> Self {
        Self(value)
    }

    pub const fn value(self) -> FixedBytes32 {
        self.0
    }
}

/// Monotonic, non-zero generation allocated by the privilege broker for one
/// fixed provider leaf.  It is deliberately not the daemon's local attempt
/// generation: separate daemon lifecycle bindings may both legitimately use
/// local generation `1` while the broker advances this value from `1` to `2`.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BrokerLeafGeneration(u64);

impl BrokerLeafGeneration {
    pub fn new(value: u64) -> Result<Self, ProtocolError> {
        if value == 0 {
            return Err(ProtocolError::ZeroGeneration);
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for BrokerLeafGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Non-zero generation local to one daemon lifecycle binding.  Unlike
/// [`BrokerLeafGeneration`], this value is not globally monotonic for a
/// provider and may repeat across distinct, fully bound lifecycle records.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct DaemonAttemptGeneration(u64);

impl DaemonAttemptGeneration {
    pub fn new(value: u64) -> Result<Self, ProtocolError> {
        if value == 0 {
            return Err(ProtocolError::ZeroGeneration);
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for DaemonAttemptGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Monotonic, non-zero generation allocated by the OS control plane. The
/// broker persists the accepted value and rejects rollback for each provider.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Generation(u64);

impl Generation {
    pub fn new(value: u64) -> Result<Self, ProtocolError> {
        if value == 0 {
            return Err(ProtocolError::ZeroGeneration);
        }
        Ok(Self(value))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for Generation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Codex,
}

/// Closed daemon-to-kernel custody binding for one Direct provider attempt.
///
/// This source-only contract is not a live [`Request`] variant.  It contains
/// no path, PID, UID, argv, environment, cgroup selector, or caller-generated
/// reservation identity.  [`DirectAttemptKernelBindingV1::validate`] checks
/// carrier integrity, compiled provider/agent identity constants, and the
/// exact delivery-attempt derivation only.  It does **not** authenticate the
/// daemon journal or prove the allocation/context/direct cross-record
/// relations, and therefore must never mint broker authority by itself.  A
/// broker-side sealed capability from the future authenticated daemon-journal
/// verifier remains mandatory before this carrier can reach durable custody.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectAttemptKernelBindingV1 {
    pub provider: Provider,
    pub provider_id_sha256: Digest,
    pub agent_id_sha256: Digest,
    pub task_id_sha256: Digest,
    pub runtime_lifecycle_binding_sha256: Digest,
    pub daemon_attempt_generation: DaemonAttemptGeneration,
    /// Whole-record digest of the allocation-successor Egress CAS record.
    /// This is never the allocation predecessor or the terminal CAS digest.
    pub daemon_attempt_allocation_record_sha256: Digest,
    pub daemon_attempt_context_sha256: Digest,
    pub delivery_provider_attempt_id_sha256: Digest,
    pub direct_binding_sha256: Digest,
    pub direct_attempt_kernel_binding_sha256: Digest,
}

impl DirectAttemptKernelBindingV1 {
    // The constructor deliberately mirrors every field in this closed
    // authority-neutral carrier.  Introducing a bag of optional builder
    // fields would weaken call-site review and create another protocol shape.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: Provider,
        provider_id_sha256: Digest,
        agent_id_sha256: Digest,
        task_id_sha256: Digest,
        runtime_lifecycle_binding_sha256: Digest,
        daemon_attempt_generation: DaemonAttemptGeneration,
        daemon_attempt_allocation_record_sha256: Digest,
        daemon_attempt_context_sha256: Digest,
        delivery_provider_attempt_id_sha256: Digest,
        direct_binding_sha256: Digest,
    ) -> Result<Self, ProtocolError> {
        let mut binding = Self {
            provider,
            provider_id_sha256,
            agent_id_sha256,
            task_id_sha256,
            runtime_lifecycle_binding_sha256,
            daemon_attempt_generation,
            daemon_attempt_allocation_record_sha256,
            daemon_attempt_context_sha256,
            delivery_provider_attempt_id_sha256,
            direct_binding_sha256,
            // Replaced below before the value can escape.
            direct_attempt_kernel_binding_sha256: direct_binding_sha256,
        };
        binding.direct_attempt_kernel_binding_sha256 = binding.expected_sha256()?;
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        let descriptor = match self.provider {
            Provider::Codex => &CODEX,
        };
        if self.provider_id_sha256 != digest_utf8(descriptor.provider_id.as_bytes())?
            || self.agent_id_sha256 != digest_utf8(descriptor.agent_id.as_bytes())?
            || self.delivery_provider_attempt_id_sha256
                != derive_delivery_provider_attempt_id_sha256(
                    self.runtime_lifecycle_binding_sha256,
                    self.daemon_attempt_generation,
                    self.daemon_attempt_context_sha256,
                )?
            || self.expected_sha256()? != self.direct_attempt_kernel_binding_sha256
        {
            return Err(ProtocolError::RecoveryEvidenceEquivocation);
        }
        Ok(())
    }

    pub fn expected_sha256(&self) -> Result<Digest, ProtocolError> {
        use sha2::{Digest as _, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"org.trillionnium.direct-attempt-kernel-binding.v1\0");
        hasher.update([match self.provider {
            Provider::Codex => 1,
        }]);
        for digest in [
            self.provider_id_sha256,
            self.agent_id_sha256,
            self.task_id_sha256,
            self.runtime_lifecycle_binding_sha256,
        ] {
            hasher.update(digest.value().as_bytes());
        }
        hasher.update(self.daemon_attempt_generation.value().to_be_bytes());
        for digest in [
            self.daemon_attempt_allocation_record_sha256,
            self.daemon_attempt_context_sha256,
            self.delivery_provider_attempt_id_sha256,
            self.direct_binding_sha256,
        ] {
            hasher.update(digest.value().as_bytes());
        }
        let bytes: [u8; FIXED_BYTES] = hasher.finalize().into();
        Ok(Digest::new(FixedBytes32::new(bytes)?))
    }
}

/// Reconstruct the daemon-authored `attempt:<64-lower-hex>` identity with the
/// exact os-types length-prefix algorithm, then hash the raw ASCII identity.
/// This prevents substituting the hash of hex, dropping a field prefix, or
/// treating the attempt generation as a decimal string.
pub fn derive_delivery_provider_attempt_id_sha256(
    runtime_lifecycle_binding_sha256: Digest,
    daemon_attempt_generation: DaemonAttemptGeneration,
    daemon_attempt_context_sha256: Digest,
) -> Result<Digest, ProtocolError> {
    use sha2::{Digest as _, Sha256};

    fn hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    let runtime_hex = lower_hex(runtime_lifecycle_binding_sha256.value().as_bytes());
    let context_hex = lower_hex(daemon_attempt_context_sha256.value().as_bytes());
    let mut hasher = Sha256::new();
    hash_field(
        &mut hasher,
        b"domain",
        b"trillionnium.direct-operation-provider-attempt-id.v1",
    );
    hash_field(
        &mut hasher,
        b"runtime_lifecycle_binding_sha256",
        runtime_hex.as_bytes(),
    );
    hash_field(
        &mut hasher,
        b"attempt_generation",
        &daemon_attempt_generation.value().to_be_bytes(),
    );
    hash_field(
        &mut hasher,
        b"daemon_attempt_context_sha256",
        context_hex.as_bytes(),
    );
    let raw = format!("attempt:{}", lower_hex(&hasher.finalize()));
    digest_utf8(raw.as_bytes())
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn digest_utf8(value: &[u8]) -> Result<Digest, ProtocolError> {
    use sha2::{Digest as _, Sha256};

    let bytes: [u8; FIXED_BYTES] = Sha256::digest(value).into();
    Ok(Digest::new(FixedBytes32::new(bytes)?))
}

/// Closed binding used to prove that a fixed provider cgroup leaf was drained
/// and observed frozen and empty for one OS attempt. These draft contracts are
/// not reachable through [`Request`]; the production foundation continues to
/// return `mutation_unavailable` for every lifecycle operation.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLeafRecoveryBinding {
    pub provider: Provider,
    pub broker_leaf_generation: BrokerLeafGeneration,
    pub operation_id: LifecycleOperationId,
    pub lifecycle_digest: Digest,
}

/// Closed reservation request for an already-proven empty, frozen provider
/// leaf. No caller-selected process, filesystem, cgroup, credential, or
/// execution input is representable.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLeafReserveRequest {
    pub provider: Provider,
    pub broker_leaf_generation: BrokerLeafGeneration,
    pub operation_id: LifecycleOperationId,
    pub reservation_id: LifecycleReservationId,
    pub lifecycle_digest: Digest,
    pub empty_proof_sha256: Digest,
}

/// Exact abort/recovery request for a reservation previously accepted by the
/// broker. The implementation must reject field drift and retain the
/// reservation identity as a tombstone after successful drain. The current
/// foundation's tombstone is explicitly not durable across broker restart.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLeafAbortRequest {
    pub provider: Provider,
    pub broker_leaf_generation: BrokerLeafGeneration,
    pub operation_id: LifecycleOperationId,
    pub reservation_id: LifecycleReservationId,
    pub lifecycle_digest: Digest,
}

/// Domain-bound kernel observation proof. The digest is recomputed by the
/// custody state machine and cannot be accepted merely because this closed
/// shape deserializes.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderLeafEmptyProof {
    pub binding: ProviderLeafRecoveryBinding,
    pub frozen_observation_sha256: Digest,
    pub membership_observation_sha256: Digest,
    /// Stable max-depth/max-descendants and live/dying descendant counters,
    /// observed before signalling and again in the final empty sandwich.
    pub descendant_observation_sha256: Digest,
    pub populated_zero_observation_sha256: Digest,
    pub final_observation_sha256: Digest,
    pub empty_proof_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    UserCancel,
    DeadlineExceeded,
    PolicyRevoked,
    DaemonShutdown,
}

/// Closed runtime ceilings. The broker maps these to compiled constants; no
/// caller-provided wall-clock deadline reaches process supervision.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationTimeout {
    Seconds30,
    Minutes2,
    Minutes5,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationOutcome {
    Succeeded,
    ProviderFailed,
    DeadlineExceeded,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationBinding {
    pub provider: Provider,
    pub invocation_id: InvocationId,
    pub lifecycle_digest: Digest,
    pub credential_generation: Generation,
    pub credential_sha256: Digest,
    pub request_sha256: Digest,
    pub request_size: u64,
    pub timeout: InvocationTimeout,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Hello,
    Status,
    InstallCredential,
    SpawnInvocation,
    CollectInvocation,
    TerminateInvocation,
    GetRecoveryEvidence,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Hello,
    Status,
    InstallCredential {
        provider: Provider,
        credential_generation: Generation,
        credential_sha256: Digest,
        credential_size: u64,
    },
    SpawnInvocation {
        provider: Provider,
        invocation_id: InvocationId,
        lifecycle_digest: Digest,
        credential_generation: Generation,
        credential_sha256: Digest,
        request_sha256: Digest,
        request_size: u64,
        timeout: InvocationTimeout,
    },
    CollectInvocation {
        handle: OpaqueHandle,
    },
    TerminateInvocation {
        handle: OpaqueHandle,
        reason: TerminationReason,
    },
    GetRecoveryEvidence,
}

impl Request {
    pub const fn operation(&self) -> Operation {
        match self {
            Self::Hello => Operation::Hello,
            Self::Status => Operation::Status,
            Self::InstallCredential { .. } => Operation::InstallCredential,
            Self::SpawnInvocation { .. } => Operation::SpawnInvocation,
            Self::CollectInvocation { .. } => Operation::CollectInvocation,
            Self::TerminateInvocation { .. } => Operation::TerminateInvocation,
            Self::GetRecoveryEvidence => Operation::GetRecoveryEvidence,
        }
    }

    pub const fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::InstallCredential { .. }
                | Self::SpawnInvocation { .. }
                | Self::CollectInvocation { .. }
                | Self::TerminateInvocation { .. }
        )
    }

    pub const fn invocation_binding(&self) -> Option<InvocationBinding> {
        match self {
            Self::SpawnInvocation {
                provider,
                invocation_id,
                lifecycle_digest,
                credential_generation,
                credential_sha256,
                request_sha256,
                request_size,
                timeout,
            } => Some(InvocationBinding {
                provider: *provider,
                invocation_id: *invocation_id,
                lifecycle_digest: *lifecycle_digest,
                credential_generation: *credential_generation,
                credential_sha256: *credential_sha256,
                request_sha256: *request_sha256,
                request_size: *request_size,
                timeout: *timeout,
            }),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFrame {
    pub protocol_version: u16,
    pub session_binding: SessionBinding,
    pub sequence: u64,
    pub nonce: Nonce,
    pub request: Request,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerGreeting {
    pub protocol_version: u16,
    pub challenge: FixedBytes32,
    pub session_binding: SessionBinding,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerMode {
    V2FoundationNoMutation,
    V2Operational,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityContract {
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub bounding: u64,
    pub ambient: u64,
}

/// Values a mutually authenticated client must pin independently of the
/// response being validated. This prevents a syntactically valid broker frame
/// from changing peer identity, capability claims, or operating mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseExpectations {
    pub peer_binding: Digest,
    pub mode: BrokerMode,
    pub capability_contract: CapabilityContract,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialStatus {
    Empty,
    Installed {
        generation: Generation,
        credential_sha256: Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum InvocationStatus {
    Idle,
    Running {
        invocation_id: InvocationId,
        handle: OpaqueHandle,
    },
    Terminating {
        invocation_id: InvocationId,
        handle: OpaqueHandle,
        reason: TerminationReason,
    },
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStatus {
    pub credential: CredentialStatus,
    pub invocation: InvocationStatus,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInventory {
    pub codex: ProviderStatus,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryStatus {
    Empty,
    Available {
        generation: Generation,
        evidence_sha256: Digest,
    },
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationUnavailableReason {
    BackendNotInstalled,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Hello {
        peer_binding: Digest,
    },
    Status {
        mode: BrokerMode,
        capability_contract: CapabilityContract,
        mutation_effect_count: u64,
        inventory: Box<ProviderInventory>,
        recovery: RecoveryStatus,
    },
    CredentialInstalled {
        provider: Provider,
        credential_generation: Generation,
        credential_sha256: Digest,
    },
    InvocationSpawned {
        binding: Box<InvocationBinding>,
        handle: OpaqueHandle,
    },
    InvocationRunning {
        handle: OpaqueHandle,
    },
    InvocationTerminating {
        handle: OpaqueHandle,
        reason: TerminationReason,
    },
    InvocationCollected {
        handle: OpaqueHandle,
        outcome: InvocationOutcome,
        report_sha256: Digest,
        report_size: u64,
    },
    InvocationTerminationAccepted {
        handle: OpaqueHandle,
        reason: TerminationReason,
    },
    RecoveryEvidence {
        generation: Generation,
        evidence_sha256: Digest,
        evidence_size: u64,
    },
    MutationUnavailable {
        operation: Operation,
        reason: MutationUnavailableReason,
    },
    Denied {
        code: DenialCode,
    },
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenialCode {
    InvalidFrame,
    VersionMismatch,
    SessionMismatch,
    SequenceMismatch,
    NonceReplay,
    SessionExhausted,
    HelloRequired,
    HelloAlreadyCompleted,
    AncillaryDataDenied,
    CredentialGenerationRollback,
    CredentialMismatch,
    ProviderBusy,
    InvocationUnknown,
    InvocationReplay,
    HandleCollision,
    LifecycleMismatch,
    ResponseMismatch,
    PayloadDigestMismatch,
    PayloadSizeDenied,
    RecoveryGenerationRollback,
    RecoveryEvidenceEquivocation,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseFrame {
    pub protocol_version: u16,
    pub session_binding: SessionBinding,
    pub sequence: u64,
    pub request_nonce: Nonce,
    pub response: Response,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Hello,
    Status,
    Lifecycle(Operation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdKind {
    SealedMemfd,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdAccess {
    ReadOnly,
    Writable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FdFact {
    pub kind: FdKind,
    pub access: FdAccess,
    pub fully_sealed: bool,
    pub size: u64,
    pub sha256: Digest,
}

pub trait FdPolicy {
    fn validate(&self, request: &Request, fds: &[FdFact]) -> Result<(), ProtocolError>;
}

/// Request-side FD policy. Credential installation and invocation spawn each
/// consume one exact sealed, read-only memfd. Extra or ambiguous descriptors
/// never reach dispatch.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClosedFdPolicy;

impl FdPolicy for ClosedFdPolicy {
    fn validate(&self, request: &Request, fds: &[FdFact]) -> Result<(), ProtocolError> {
        match request {
            Request::InstallCredential {
                credential_size,
                credential_sha256,
                ..
            } => validate_sealed_payload(
                fds,
                *credential_size,
                *credential_sha256,
                MAX_CREDENTIAL_BYTES,
            ),
            Request::SpawnInvocation {
                request_size,
                request_sha256,
                ..
            } => validate_sealed_payload(
                fds,
                *request_size,
                *request_sha256,
                MAX_INVOCATION_REQUEST_BYTES,
            ),
            _ if fds.is_empty() => Ok(()),
            _ => Err(ProtocolError::FdCountMismatch),
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ClosedResponseFdPolicy;

impl ClosedResponseFdPolicy {
    pub fn validate(&self, response: &Response, fds: &[FdFact]) -> Result<(), ProtocolError> {
        match response {
            Response::InvocationCollected {
                report_sha256,
                report_size,
                ..
            } => validate_sealed_payload(
                fds,
                *report_size,
                *report_sha256,
                MAX_INVOCATION_REPORT_BYTES,
            ),
            Response::RecoveryEvidence {
                evidence_sha256,
                evidence_size,
                ..
            } => validate_sealed_payload(
                fds,
                *evidence_size,
                *evidence_sha256,
                MAX_RECOVERY_EVIDENCE_BYTES,
            ),
            _ if fds.is_empty() => Ok(()),
            _ => Err(ProtocolError::FdCountMismatch),
        }
    }
}

fn validate_sealed_payload(
    fds: &[FdFact],
    declared_size: u64,
    declared_sha256: Digest,
    maximum_size: u64,
) -> Result<(), ProtocolError> {
    if declared_size == 0 || declared_size > maximum_size {
        return Err(ProtocolError::PayloadSizeDenied);
    }
    let [fd] = fds else {
        return Err(ProtocolError::FdCountMismatch);
    };
    if fd.kind != FdKind::SealedMemfd
        || fd.access != FdAccess::ReadOnly
        || !fd.fully_sealed
        || fd.size != declared_size
    {
        return Err(ProtocolError::FdPolicyDenied);
    }
    if fd.sha256 != declared_sha256 {
        return Err(ProtocolError::PayloadDigestMismatch);
    }
    Ok(())
}

#[derive(Debug)]
pub struct SessionState {
    binding: SessionBinding,
    next_sequence: u64,
    seen_nonces: HashSet<Nonce>,
    hello_complete: bool,
}

impl SessionState {
    pub fn new(binding: SessionBinding) -> Self {
        Self {
            binding,
            next_sequence: 1,
            seen_nonces: HashSet::new(),
            hello_complete: false,
        }
    }

    pub fn validate(
        &mut self,
        frame: &RequestFrame,
        fds: &[FdFact],
    ) -> Result<Disposition, ProtocolError> {
        if self.next_sequence > MAX_REQUESTS_PER_SESSION {
            return Err(ProtocolError::SessionExhausted);
        }
        if frame.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::VersionMismatch);
        }
        if frame.session_binding != self.binding {
            return Err(ProtocolError::SessionMismatch);
        }
        if frame.sequence != self.next_sequence {
            return Err(ProtocolError::SequenceMismatch);
        }
        if self.seen_nonces.contains(&frame.nonce) {
            return Err(ProtocolError::NonceReplay);
        }
        if !self.hello_complete && !matches!(frame.request, Request::Hello) {
            return Err(ProtocolError::HelloRequired);
        }
        if self.hello_complete && matches!(frame.request, Request::Hello) {
            return Err(ProtocolError::HelloAlreadyCompleted);
        }
        ClosedFdPolicy.validate(&frame.request, fds)?;

        let disposition = match frame.request {
            Request::Hello => {
                self.hello_complete = true;
                Disposition::Hello
            }
            Request::Status => Disposition::Status,
            _ => Disposition::Lifecycle(frame.request.operation()),
        };
        self.seen_nonces.insert(frame.nonce);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)?;
        Ok(disposition)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CredentialRecord {
    generation: Generation,
    credential_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActiveLifecycle {
    Running,
    Terminating(TerminationReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InvocationRecord {
    invocation_id: InvocationId,
    handle: OpaqueHandle,
    lifecycle: ActiveLifecycle,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ProviderRuntimeState {
    credential: Option<CredentialRecord>,
    active: Option<InvocationRecord>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecoveryRecord {
    generation: Generation,
    evidence_sha256: Digest,
}

/// Shared lifecycle ledger for both sides of the v2 contract. It models
/// broker-owned credential slots and pidfd-owned invocation handles without
/// exposing an operating-system PID. A transition is committed only after a
/// matching success response and its exact FD inventory have been validated.
#[derive(Debug, Default)]
pub struct LifecycleState {
    codex: ProviderRuntimeState,
    seen_invocation_ids: HashSet<InvocationId>,
    seen_handles: HashSet<OpaqueHandle>,
    recovery: Option<RecoveryRecord>,
    mutation_effect_count: u64,
}

impl LifecycleState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inventory(&self) -> ProviderInventory {
        ProviderInventory {
            codex: Self::provider_status(self.codex),
        }
    }

    pub fn recovery_status(&self) -> RecoveryStatus {
        match self.recovery {
            Some(record) => RecoveryStatus::Available {
                generation: record.generation,
                evidence_sha256: record.evidence_sha256,
            },
            None => RecoveryStatus::Empty,
        }
    }

    pub const fn mutation_effect_count(&self) -> u64 {
        self.mutation_effect_count
    }

    pub fn apply_exchange(
        &mut self,
        expectations: &ResponseExpectations,
        request: &Request,
        request_fds: &[FdFact],
        response: &Response,
        response_fds: &[FdFact],
    ) -> Result<(), ProtocolError> {
        ClosedFdPolicy.validate(request, request_fds)?;
        self.validate_response_semantics(expectations, request, response, response_fds)?;
        self.apply_success(request, response, response_fds)
    }

    pub fn validate_response_semantics(
        &self,
        expectations: &ResponseExpectations,
        request: &Request,
        response: &Response,
        response_fds: &[FdFact],
    ) -> Result<(), ProtocolError> {
        ClosedResponseFdPolicy.validate(response, response_fds)?;
        match (request, response) {
            (Request::Hello, Response::Hello { peer_binding })
                if *peer_binding == expectations.peer_binding =>
            {
                Ok(())
            }
            (
                Request::Status,
                Response::Status {
                    mode,
                    capability_contract,
                    mutation_effect_count,
                    inventory,
                    recovery,
                },
            ) if *mode == expectations.mode
                && *capability_contract == expectations.capability_contract
                && *mutation_effect_count == self.mutation_effect_count()
                && **inventory == self.inventory()
                && *recovery == self.recovery_status() =>
            {
                Ok(())
            }
            (
                lifecycle_request,
                Response::MutationUnavailable {
                    operation,
                    reason: MutationUnavailableReason::BackendNotInstalled,
                },
            ) if expectations.mode == BrokerMode::V2FoundationNoMutation
                && !matches!(lifecycle_request, Request::Hello | Request::Status)
                && *operation == lifecycle_request.operation() =>
            {
                Ok(())
            }
            (_, Response::Denied { .. }) => Ok(()),
            (Request::Hello | Request::Status, _) => Err(ProtocolError::ResponseMismatch),
            (_, Response::MutationUnavailable { .. }) => Err(ProtocolError::ResponseMismatch),
            _ => Ok(()),
        }
    }

    fn apply_success(
        &mut self,
        request: &Request,
        response: &Response,
        response_fds: &[FdFact],
    ) -> Result<(), ProtocolError> {
        ClosedResponseFdPolicy.validate(response, response_fds)?;

        if let Response::Denied { .. } = response {
            return Ok(());
        }
        if let Response::MutationUnavailable { operation, reason } = response {
            if *reason != MutationUnavailableReason::BackendNotInstalled
                || *operation != request.operation()
                || matches!(request, Request::Hello | Request::Status)
            {
                return Err(ProtocolError::ResponseMismatch);
            }
            return Ok(());
        }

        match (request, response) {
            (Request::Hello, Response::Hello { .. }) => Ok(()),
            (
                Request::Status,
                Response::Status {
                    mode,
                    mutation_effect_count,
                    inventory,
                    recovery,
                    ..
                },
            ) if **inventory == self.inventory()
                && *recovery == self.recovery_status()
                && *mutation_effect_count == self.mutation_effect_count()
                && (*mode != BrokerMode::V2FoundationNoMutation
                    || (self.mutation_effect_count() == 0
                        && self.inventory() == LifecycleState::new().inventory()
                        && self.recovery_status() == RecoveryStatus::Empty)) =>
            {
                Ok(())
            }
            (
                Request::InstallCredential {
                    provider,
                    credential_generation,
                    credential_sha256,
                    ..
                },
                Response::CredentialInstalled {
                    provider: response_provider,
                    credential_generation: response_generation,
                    credential_sha256: response_digest,
                },
            ) if provider == response_provider
                && credential_generation == response_generation
                && credential_sha256 == response_digest =>
            {
                self.record_credential(*provider, *credential_generation, *credential_sha256)
            }
            (
                Request::SpawnInvocation {
                    provider,
                    invocation_id,
                    credential_generation,
                    credential_sha256,
                    ..
                },
                Response::InvocationSpawned { binding, handle },
            ) if Some(**binding) == request.invocation_binding() => self.record_spawn(
                *provider,
                *invocation_id,
                *credential_generation,
                *credential_sha256,
                *handle,
            ),
            (
                Request::CollectInvocation { handle },
                Response::InvocationRunning {
                    handle: response_handle,
                },
            ) if handle == response_handle => self.validate_running(*handle),
            (
                Request::CollectInvocation { handle },
                Response::InvocationTerminating {
                    handle: response_handle,
                    reason,
                },
            ) if handle == response_handle => self.validate_terminating(*handle, *reason),
            (
                Request::CollectInvocation { handle },
                Response::InvocationCollected {
                    handle: response_handle,
                    outcome,
                    ..
                },
            ) if handle == response_handle => self.record_collected(*handle, *outcome),
            (
                Request::TerminateInvocation { handle, reason },
                Response::InvocationTerminationAccepted {
                    handle: response_handle,
                    reason: response_reason,
                },
            ) if handle == response_handle && reason == response_reason => {
                self.record_termination(*handle, *reason)
            }
            (
                Request::GetRecoveryEvidence,
                Response::RecoveryEvidence {
                    generation,
                    evidence_sha256,
                    ..
                },
            ) => self.record_recovery(*generation, *evidence_sha256),
            _ => Err(ProtocolError::ResponseMismatch),
        }
    }

    fn provider_status(state: ProviderRuntimeState) -> ProviderStatus {
        let credential = match state.credential {
            Some(record) => CredentialStatus::Installed {
                generation: record.generation,
                credential_sha256: record.credential_sha256,
            },
            None => CredentialStatus::Empty,
        };
        let invocation = match state.active {
            Some(InvocationRecord {
                invocation_id,
                handle,
                lifecycle: ActiveLifecycle::Running,
            }) => InvocationStatus::Running {
                invocation_id,
                handle,
            },
            Some(InvocationRecord {
                invocation_id,
                handle,
                lifecycle: ActiveLifecycle::Terminating(reason),
            }) => InvocationStatus::Terminating {
                invocation_id,
                handle,
                reason,
            },
            None => InvocationStatus::Idle,
        };
        ProviderStatus {
            credential,
            invocation,
        }
    }

    fn provider(&self, provider: Provider) -> &ProviderRuntimeState {
        match provider {
            Provider::Codex => &self.codex,
        }
    }

    fn provider_mut(&mut self, provider: Provider) -> &mut ProviderRuntimeState {
        match provider {
            Provider::Codex => &mut self.codex,
        }
    }

    fn record_credential(
        &mut self,
        provider: Provider,
        generation: Generation,
        credential_sha256: Digest,
    ) -> Result<(), ProtocolError> {
        let state = self.provider_mut(provider);
        if state.active.is_some() {
            return Err(ProtocolError::ProviderBusy);
        }
        if state
            .credential
            .is_some_and(|current| generation <= current.generation)
        {
            return Err(ProtocolError::CredentialGenerationRollback);
        }
        state.credential = Some(CredentialRecord {
            generation,
            credential_sha256,
        });
        self.record_mutation_effect()?;
        Ok(())
    }

    fn record_spawn(
        &mut self,
        provider: Provider,
        invocation_id: InvocationId,
        credential_generation: Generation,
        credential_sha256: Digest,
        handle: OpaqueHandle,
    ) -> Result<(), ProtocolError> {
        if self.seen_invocation_ids.len() >= MAX_INVOCATIONS_PER_SESSION {
            return Err(ProtocolError::InvocationLimitExhausted);
        }
        if self.seen_invocation_ids.contains(&invocation_id) {
            return Err(ProtocolError::InvocationReplay);
        }
        if self.seen_handles.contains(&handle) {
            return Err(ProtocolError::HandleCollision);
        }
        let state = self.provider(provider);
        if state.active.is_some() {
            return Err(ProtocolError::ProviderBusy);
        }
        if state.credential
            != Some(CredentialRecord {
                generation: credential_generation,
                credential_sha256,
            })
        {
            return Err(ProtocolError::CredentialMismatch);
        }
        self.provider_mut(provider).active = Some(InvocationRecord {
            invocation_id,
            handle,
            lifecycle: ActiveLifecycle::Running,
        });
        self.seen_invocation_ids.insert(invocation_id);
        self.seen_handles.insert(handle);
        self.record_mutation_effect()?;
        Ok(())
    }

    fn validate_running(&self, handle: OpaqueHandle) -> Result<(), ProtocolError> {
        let active = self
            .active_invocation_for_handle(handle)
            .ok_or(ProtocolError::InvocationUnknown)?;
        if active.lifecycle != ActiveLifecycle::Running {
            return Err(ProtocolError::LifecycleMismatch);
        }
        Ok(())
    }

    fn validate_terminating(
        &self,
        handle: OpaqueHandle,
        reason: TerminationReason,
    ) -> Result<(), ProtocolError> {
        let active = self
            .active_invocation_for_handle(handle)
            .ok_or(ProtocolError::InvocationUnknown)?;
        if active.lifecycle != ActiveLifecycle::Terminating(reason) {
            return Err(ProtocolError::LifecycleMismatch);
        }
        Ok(())
    }

    fn record_termination(
        &mut self,
        handle: OpaqueHandle,
        reason: TerminationReason,
    ) -> Result<(), ProtocolError> {
        let provider = self
            .active_provider_for_handle(handle)
            .ok_or(ProtocolError::InvocationUnknown)?;
        let active = self
            .provider_mut(provider)
            .active
            .as_mut()
            .ok_or(ProtocolError::InvocationUnknown)?;
        let changed = match active.lifecycle {
            ActiveLifecycle::Running => {
                active.lifecycle = ActiveLifecycle::Terminating(reason);
                true
            }
            ActiveLifecycle::Terminating(existing) if existing == reason => false,
            ActiveLifecycle::Terminating(_) => return Err(ProtocolError::LifecycleMismatch),
        };
        if changed {
            self.record_mutation_effect()?;
        }
        Ok(())
    }

    fn record_collected(
        &mut self,
        handle: OpaqueHandle,
        outcome: InvocationOutcome,
    ) -> Result<(), ProtocolError> {
        let provider = self
            .active_provider_for_handle(handle)
            .ok_or(ProtocolError::InvocationUnknown)?;
        let active = self
            .provider(provider)
            .active
            .ok_or(ProtocolError::InvocationUnknown)?;
        let outcome_valid = matches!(
            (active.lifecycle, outcome),
            (
                ActiveLifecycle::Running,
                InvocationOutcome::Succeeded
                    | InvocationOutcome::ProviderFailed
                    | InvocationOutcome::DeadlineExceeded,
            ) | (
                ActiveLifecycle::Terminating(TerminationReason::DeadlineExceeded),
                InvocationOutcome::DeadlineExceeded,
            ) | (
                ActiveLifecycle::Terminating(
                    TerminationReason::UserCancel
                        | TerminationReason::PolicyRevoked
                        | TerminationReason::DaemonShutdown,
                ),
                InvocationOutcome::Terminated,
            )
        );
        if !outcome_valid {
            return Err(ProtocolError::LifecycleMismatch);
        }
        self.provider_mut(provider).active = None;
        self.record_mutation_effect()?;
        Ok(())
    }

    fn active_provider_for_handle(&self, handle: OpaqueHandle) -> Option<Provider> {
        [Provider::Codex].into_iter().find(|provider| {
            self.provider(*provider)
                .active
                .is_some_and(|record| record.handle == handle)
        })
    }

    fn active_invocation_for_handle(&self, handle: OpaqueHandle) -> Option<InvocationRecord> {
        self.active_provider_for_handle(handle)
            .and_then(|provider| self.provider(provider).active)
    }

    fn record_recovery(
        &mut self,
        generation: Generation,
        evidence_sha256: Digest,
    ) -> Result<(), ProtocolError> {
        match self.recovery {
            Some(existing) if generation < existing.generation => {
                return Err(ProtocolError::RecoveryGenerationRollback);
            }
            Some(existing)
                if generation == existing.generation
                    && evidence_sha256 != existing.evidence_sha256 =>
            {
                return Err(ProtocolError::RecoveryEvidenceEquivocation);
            }
            _ => {}
        }
        self.recovery = Some(RecoveryRecord {
            generation,
            evidence_sha256,
        });
        Ok(())
    }

    fn record_mutation_effect(&mut self) -> Result<(), ProtocolError> {
        self.mutation_effect_count = self
            .mutation_effect_count
            .checked_add(1)
            .ok_or(ProtocolError::MutationEffectCountExhausted)?;
        Ok(())
    }
}

pub fn decode_request(bytes: &[u8]) -> Result<RequestFrame, ProtocolError> {
    validate_frame_size(bytes)?;
    let frame: RequestFrame = serde_json::from_slice(bytes).map_err(ProtocolError::InvalidJson)?;
    if frame.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    Ok(frame)
}

pub fn decode_response(bytes: &[u8]) -> Result<ResponseFrame, ProtocolError> {
    validate_frame_size(bytes)?;
    let frame: ResponseFrame = serde_json::from_slice(bytes).map_err(ProtocolError::InvalidJson)?;
    if frame.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    Ok(frame)
}

pub fn decode_greeting(bytes: &[u8]) -> Result<ServerGreeting, ProtocolError> {
    validate_frame_size(bytes)?;
    let greeting: ServerGreeting =
        serde_json::from_slice(bytes).map_err(ProtocolError::InvalidJson)?;
    if greeting.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    Ok(greeting)
}

pub fn validate_response_correlation(
    request: &RequestFrame,
    response: &ResponseFrame,
) -> Result<(), ProtocolError> {
    if response.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    if response.session_binding != request.session_binding
        || response.sequence != request.sequence
        || response.request_nonce != request.nonce
    {
        return Err(ProtocolError::ResponseMismatch);
    }
    Ok(())
}

pub fn encode_response(frame: &ResponseFrame) -> Result<Vec<u8>, ProtocolError> {
    if frame.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    let bytes = serde_json::to_vec(frame).map_err(ProtocolError::InvalidJson)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameSizeDenied);
    }
    Ok(bytes)
}

pub fn encode_greeting(greeting: &ServerGreeting) -> Result<Vec<u8>, ProtocolError> {
    if greeting.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch);
    }
    let bytes = serde_json::to_vec(greeting).map_err(ProtocolError::InvalidJson)?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameSizeDenied);
    }
    Ok(bytes)
}

fn validate_frame_size(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameSizeDenied);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("frame must contain between 1 and {MAX_FRAME_BYTES} bytes")]
    FrameSizeDenied,
    #[error("invalid closed JSON frame: {0}")]
    InvalidJson(serde_json::Error),
    #[error("protocol version mismatch")]
    VersionMismatch,
    #[error("session binding mismatch")]
    SessionMismatch,
    #[error("sequence mismatch")]
    SequenceMismatch,
    #[error("sequence exhausted")]
    SequenceExhausted,
    #[error("session request limit exhausted")]
    SessionExhausted,
    #[error("nonce replay")]
    NonceReplay,
    #[error("hello must be the first request")]
    HelloRequired,
    #[error("hello was already completed")]
    HelloAlreadyCompleted,
    #[error("fixed-width values must not be all zero")]
    ZeroFixedValue,
    #[error("generation must be non-zero")]
    ZeroGeneration,
    #[error("ancillary file descriptor count mismatch")]
    FdCountMismatch,
    #[error("ancillary file descriptor policy denied")]
    FdPolicyDenied,
    #[error("ancillary payload size denied")]
    PayloadSizeDenied,
    #[error("ancillary payload digest mismatch")]
    PayloadDigestMismatch,
    #[error("credential generation rollback denied")]
    CredentialGenerationRollback,
    #[error("credential binding mismatch")]
    CredentialMismatch,
    #[error("provider already owns an active invocation")]
    ProviderBusy,
    #[error("invocation handle is unknown or no longer active")]
    InvocationUnknown,
    #[error("invocation identifier replay")]
    InvocationReplay,
    #[error("invocation handle collision")]
    HandleCollision,
    #[error("invocation lifecycle mismatch")]
    LifecycleMismatch,
    #[error("request/response pair mismatch")]
    ResponseMismatch,
    #[error("per-session invocation limit exhausted")]
    InvocationLimitExhausted,
    #[error("mutation effect count exhausted")]
    MutationEffectCountExhausted,
    #[error("recovery evidence generation rollback")]
    RecoveryGenerationRollback,
    #[error("recovery evidence equivocation at one generation")]
    RecoveryEvidenceEquivocation,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(value: u8) -> SessionBinding {
        SessionBinding::new(FixedBytes32::test_value(value))
    }

    fn nonce(value: u8) -> Nonce {
        Nonce::new(FixedBytes32::test_value(value))
    }

    fn digest(value: u8) -> Digest {
        Digest::new(FixedBytes32::test_value(value))
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).unwrap()
    }

    fn invocation_id(value: u8) -> InvocationId {
        InvocationId::new(FixedBytes32::test_value(value))
    }

    fn handle(value: u8) -> OpaqueHandle {
        OpaqueHandle::new(FixedBytes32::test_value(value))
    }

    fn broker_leaf_generation(value: u64) -> BrokerLeafGeneration {
        BrokerLeafGeneration::new(value).unwrap()
    }

    fn lifecycle_operation_id(value: u8) -> LifecycleOperationId {
        LifecycleOperationId::new(FixedBytes32::test_value(value))
    }

    fn lifecycle_reservation_id(value: u8) -> LifecycleReservationId {
        LifecycleReservationId::new(FixedBytes32::test_value(value))
    }

    fn digest_hex_value(value: &str) -> Digest {
        assert_eq!(value.len(), 64);
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
        }
        Digest::new(FixedBytes32::new(bytes).unwrap())
    }

    fn sealed_fd(size: u64, sha256: Digest) -> FdFact {
        FdFact {
            kind: FdKind::SealedMemfd,
            access: FdAccess::ReadOnly,
            fully_sealed: true,
            size,
            sha256,
        }
    }

    fn install(provider: Provider, generation_value: u64, digest_value: u8) -> Request {
        Request::InstallCredential {
            provider,
            credential_generation: generation(generation_value),
            credential_sha256: digest(digest_value),
            credential_size: 12,
        }
    }

    fn spawn(
        provider: Provider,
        invocation_value: u8,
        generation_value: u64,
        credential_digest_value: u8,
        request_digest_value: u8,
    ) -> Request {
        Request::SpawnInvocation {
            provider,
            invocation_id: invocation_id(invocation_value),
            lifecycle_digest: digest(40),
            credential_generation: generation(generation_value),
            credential_sha256: digest(credential_digest_value),
            request_sha256: digest(request_digest_value),
            request_size: 12,
            timeout: InvocationTimeout::Minutes2,
        }
    }

    fn spawned(request: &Request, handle_value: u8) -> Response {
        Response::InvocationSpawned {
            binding: Box::new(request.invocation_binding().unwrap()),
            handle: handle(handle_value),
        }
    }

    fn expectations() -> ResponseExpectations {
        ResponseExpectations {
            peer_binding: digest(50),
            mode: BrokerMode::V2FoundationNoMutation,
            capability_contract: CapabilityContract {
                effective: 0xe1,
                permitted: 0xe1,
                inheritable: 0,
                bounding: 0,
                ambient: 0,
            },
        }
    }

    fn status_for(state: &LifecycleState, expected: ResponseExpectations) -> Response {
        Response::Status {
            mode: expected.mode,
            capability_contract: expected.capability_contract,
            mutation_effect_count: state.mutation_effect_count(),
            inventory: Box::new(state.inventory()),
            recovery: state.recovery_status(),
        }
    }

    fn frame(sequence: u64, nonce_value: u8, request: Request) -> RequestFrame {
        RequestFrame {
            protocol_version: PROTOCOL_VERSION,
            session_binding: binding(1),
            sequence,
            nonce: nonce(nonce_value),
            request,
        }
    }

    fn hello() -> Request {
        Request::Hello
    }

    #[test]
    fn exact_fixed_values_reject_zero_and_wrong_lengths() {
        assert!(FixedBytes32::new([0; FIXED_BYTES]).is_err());
        assert!(serde_json::from_str::<FixedBytes32>("[1,2,3]").is_err());
        let zeros = format!("[{}]", vec!["0"; FIXED_BYTES].join(","));
        assert!(serde_json::from_str::<FixedBytes32>(&zeros).is_err());
    }

    #[test]
    fn closed_wire_rejects_unknown_missing_and_wrong_type_fields() {
        let valid = serde_json::to_value(frame(1, 3, hello())).unwrap();
        let mut extra = valid.clone();
        extra["path"] = serde_json::json!("/data/escape");
        assert!(serde_json::from_value::<RequestFrame>(extra).is_err());

        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("sequence");
        assert!(serde_json::from_value::<RequestFrame>(missing).is_err());

        let mut wrong_type = valid;
        wrong_type["sequence"] = serde_json::json!("1");
        assert!(serde_json::from_value::<RequestFrame>(wrong_type).is_err());
    }

    #[test]
    fn reserved_operations_reject_injection_fields() {
        let forbidden = [
            "path",
            "uid",
            "gid",
            "pid",
            "executable",
            "argv",
            "environment",
        ];
        for field in forbidden {
            let mut value =
                serde_json::to_value(frame(1, 3, spawn(Provider::Codex, 4, 1, 5, 6))).unwrap();
            value["request"][field] = serde_json::json!("injected");
            assert!(
                serde_json::from_value::<RequestFrame>(value).is_err(),
                "unexpectedly accepted {field}"
            );
        }
    }

    #[test]
    fn decode_rejects_oversize_and_wrong_version() {
        assert!(matches!(
            decode_request(&vec![b' '; MAX_FRAME_BYTES + 1]),
            Err(ProtocolError::FrameSizeDenied)
        ));
        let mut wrong = frame(1, 3, hello());
        wrong.protocol_version += 1;
        assert!(matches!(
            decode_request(&serde_json::to_vec(&wrong).unwrap()),
            Err(ProtocolError::VersionMismatch)
        ));

        let request = frame(1, 3, hello());
        let response = ResponseFrame {
            protocol_version: PROTOCOL_VERSION,
            session_binding: request.session_binding,
            sequence: request.sequence,
            request_nonce: request.nonce,
            response: Response::Hello {
                peer_binding: digest(8),
            },
        };
        let encoded = encode_response(&response).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        validate_response_correlation(&request, &decoded).unwrap();
        let mut mismatched = decoded;
        mismatched.sequence += 1;
        assert!(matches!(
            validate_response_correlation(&request, &mismatched),
            Err(ProtocolError::ResponseMismatch)
        ));

        let mut greeting = ServerGreeting {
            protocol_version: PROTOCOL_VERSION,
            challenge: FixedBytes32::test_value(9),
            session_binding: binding(1),
        };
        assert_eq!(
            decode_greeting(&encode_greeting(&greeting).unwrap()).unwrap(),
            greeting
        );
        greeting.protocol_version -= 1;
        assert!(matches!(
            encode_greeting(&greeting),
            Err(ProtocolError::VersionMismatch)
        ));
    }

    #[test]
    fn state_machine_rejects_gap_replay_nonce_reuse_and_cross_session() {
        let mut state = SessionState::new(binding(1));
        assert_eq!(
            state.validate(&frame(1, 3, hello()), &[]).unwrap(),
            Disposition::Hello
        );
        assert!(matches!(
            state.validate(&frame(3, 4, Request::Status), &[]),
            Err(ProtocolError::SequenceMismatch)
        ));
        assert_eq!(
            state.validate(&frame(2, 4, Request::Status), &[]).unwrap(),
            Disposition::Status
        );
        assert!(matches!(
            state.validate(&frame(2, 4, Request::Status), &[]),
            Err(ProtocolError::SequenceMismatch)
        ));
        assert!(matches!(
            state.validate(&frame(3, 4, Request::Status), &[]),
            Err(ProtocolError::NonceReplay)
        ));
        let mut foreign = frame(3, 5, Request::Status);
        foreign.session_binding = binding(9);
        assert!(matches!(
            state.validate(&foreign, &[]),
            Err(ProtocolError::SessionMismatch)
        ));
    }

    #[test]
    fn hello_is_mandatory_and_single_use() {
        let mut state = SessionState::new(binding(1));
        assert!(matches!(
            state.validate(&frame(1, 3, Request::Status), &[]),
            Err(ProtocolError::HelloRequired)
        ));
        state.validate(&frame(1, 3, hello()), &[]).unwrap();
        assert!(matches!(
            state.validate(&frame(2, 4, hello()), &[]),
            Err(ProtocolError::HelloAlreadyCompleted)
        ));
    }

    #[test]
    fn session_has_a_hard_request_limit() {
        let mut state = SessionState::new(binding(1));
        state.next_sequence = MAX_REQUESTS_PER_SESSION + 1;
        assert!(matches!(
            state.validate(
                &frame(MAX_REQUESTS_PER_SESSION + 1, 4, Request::Status),
                &[]
            ),
            Err(ProtocolError::SessionExhausted)
        ));
    }

    #[test]
    fn v2_lifecycle_operations_have_closed_dispositions_and_fd_shapes() {
        assert!(!std::hint::black_box(FOUNDATION_MUTATIONS_ENABLED));
        let operations = [
            install(Provider::Codex, 1, 6),
            spawn(Provider::Codex, 7, 1, 8, 9),
            Request::CollectInvocation { handle: handle(10) },
            Request::TerminateInvocation {
                handle: handle(11),
                reason: TerminationReason::UserCancel,
            },
            Request::GetRecoveryEvidence,
        ];
        let mut state = SessionState::new(binding(1));
        state.validate(&frame(1, 2, hello()), &[]).unwrap();
        for (index, request) in operations.into_iter().enumerate() {
            let fds = match &request {
                Request::InstallCredential {
                    credential_sha256, ..
                } => vec![sealed_fd(12, *credential_sha256)],
                Request::SpawnInvocation { request_sha256, .. } => {
                    vec![sealed_fd(12, *request_sha256)]
                }
                _ => Vec::new(),
            };
            let operation = request.operation();
            let disposition = state
                .validate(&frame(index as u64 + 2, index as u8 + 11, request), &fds)
                .unwrap();
            assert_eq!(disposition, Disposition::Lifecycle(operation));
        }
    }

    #[test]
    fn fd_policy_rejects_extra_or_unsafe_descriptors() {
        assert!(matches!(
            ClosedFdPolicy.validate(
                &Request::Status,
                &[FdFact {
                    kind: FdKind::Other,
                    access: FdAccess::ReadOnly,
                    fully_sealed: false,
                    size: 0,
                    sha256: digest(1),
                }]
            ),
            Err(ProtocolError::FdCountMismatch)
        ));
        let install = install(Provider::Codex, 1, 6);
        assert!(matches!(
            ClosedFdPolicy.validate(
                &install,
                &[FdFact {
                    kind: FdKind::SealedMemfd,
                    access: FdAccess::Writable,
                    fully_sealed: true,
                    size: 12,
                    sha256: digest(6),
                }]
            ),
            Err(ProtocolError::FdPolicyDenied)
        ));
        assert!(matches!(
            ClosedFdPolicy.validate(&install, &[sealed_fd(12, digest(7))]),
            Err(ProtocolError::PayloadDigestMismatch)
        ));

        let mut lifecycle = LifecycleState::new();
        assert!(matches!(
            lifecycle.apply_exchange(
                &expectations(),
                &install,
                &[sealed_fd(12, digest(7))],
                &Response::CredentialInstalled {
                    provider: Provider::Codex,
                    credential_generation: generation(1),
                    credential_sha256: digest(6),
                },
                &[],
            ),
            Err(ProtocolError::PayloadDigestMismatch)
        ));
        assert_eq!(
            lifecycle.inventory().codex.credential,
            CredentialStatus::Empty
        );
    }

    #[test]
    fn generation_is_nonzero_and_closed_json_rejects_lifecycle_injection() {
        assert!(matches!(
            Generation::new(0),
            Err(ProtocolError::ZeroGeneration)
        ));
        assert!(serde_json::from_str::<Generation>("0").is_err());

        let mut value = serde_json::to_value(spawn(Provider::Codex, 4, 1, 5, 6)).unwrap();
        value["pid"] = serde_json::json!(1234);
        assert!(serde_json::from_value::<Request>(value).is_err());

        let spawn_request = spawn(Provider::Codex, 4, 1, 5, 6);
        let response = spawned(&spawn_request, 5);
        let mut value = serde_json::to_value(response).unwrap();
        value["pidfd"] = serde_json::json!(9);
        assert!(serde_json::from_value::<Response>(value).is_err());
    }

    #[test]
    fn provider_leaf_custody_contracts_are_closed_and_not_wire_operations() {
        assert!(matches!(
            BrokerLeafGeneration::new(0),
            Err(ProtocolError::ZeroGeneration)
        ));
        assert!(serde_json::from_str::<BrokerLeafGeneration>("0").is_err());
        assert!(DaemonAttemptGeneration::new(0).is_err());
        assert!(serde_json::from_str::<DaemonAttemptGeneration>("0").is_err());

        let recovery = ProviderLeafRecoveryBinding {
            provider: Provider::Codex,
            broker_leaf_generation: broker_leaf_generation(7),
            operation_id: lifecycle_operation_id(61),
            lifecycle_digest: digest(62),
        };
        let reserve = ProviderLeafReserveRequest {
            provider: recovery.provider,
            broker_leaf_generation: recovery.broker_leaf_generation,
            operation_id: recovery.operation_id,
            reservation_id: lifecycle_reservation_id(63),
            lifecycle_digest: recovery.lifecycle_digest,
            empty_proof_sha256: digest(64),
        };
        let abort = ProviderLeafAbortRequest {
            provider: reserve.provider,
            broker_leaf_generation: reserve.broker_leaf_generation,
            operation_id: reserve.operation_id,
            reservation_id: reserve.reservation_id,
            lifecycle_digest: reserve.lifecycle_digest,
        };
        let proof = ProviderLeafEmptyProof {
            binding: recovery,
            frozen_observation_sha256: digest(65),
            membership_observation_sha256: digest(66),
            descendant_observation_sha256: digest(70),
            populated_zero_observation_sha256: digest(67),
            final_observation_sha256: digest(68),
            empty_proof_sha256: digest(69),
        };

        for mut value in [
            serde_json::to_value(recovery).unwrap(),
            serde_json::to_value(reserve).unwrap(),
            serde_json::to_value(abort).unwrap(),
            serde_json::to_value(proof).unwrap(),
        ] {
            value["path"] = serde_json::json!("/sys/fs/cgroup/injected");
            assert!(
                serde_json::from_value::<ProviderLeafRecoveryBinding>(value.clone()).is_err()
                    && serde_json::from_value::<ProviderLeafReserveRequest>(value.clone()).is_err()
                    && serde_json::from_value::<ProviderLeafAbortRequest>(value.clone()).is_err()
                    && serde_json::from_value::<ProviderLeafEmptyProof>(value).is_err()
            );
        }

        // None of these draft shapes is a Request variant. Unknown operation
        // tags therefore remain closed at the live v2 broker boundary.
        let injected = serde_json::json!({
            "operation": "reserve_provider_leaf",
            "provider": "codex",
            "broker_leaf_generation": 7,
        });
        assert!(serde_json::from_value::<Request>(injected).is_err());
    }

    #[test]
    fn delivery_provider_attempt_digest_matches_os_types_golden_vectors() {
        let generation = DaemonAttemptGeneration::new(1).unwrap();
        assert_eq!(
            derive_delivery_provider_attempt_id_sha256(digest(0x11), generation, digest(0x22))
                .unwrap(),
            digest_hex_value("6139f509c33678aadfb86d7fc271d6124a4d0b5c0d9ab2c339864ecbf79ce402")
        );
        assert_eq!(
            derive_delivery_provider_attempt_id_sha256(digest(0x33), generation, digest(0x44))
                .unwrap(),
            digest_hex_value("a58c6e327f915bda582aa690b2f90c27646c1410e1864e7033e0e36839185f35")
        );
    }

    #[test]
    fn direct_attempt_kernel_binding_is_closed_and_every_field_is_checksum_bound() {
        let generation = DaemonAttemptGeneration::new(1).unwrap();
        let runtime = digest(0x31);
        let context = digest(0x32);
        let delivery =
            derive_delivery_provider_attempt_id_sha256(runtime, generation, context).unwrap();
        let binding = DirectAttemptKernelBindingV1::new(
            Provider::Codex,
            digest_utf8(b"openai-codex").unwrap(),
            digest_utf8(b"agent-codex-direct-v1").unwrap(),
            digest(0x33),
            runtime,
            generation,
            digest(0x34),
            context,
            delivery,
            digest(0x35),
        )
        .unwrap();
        binding.validate().unwrap();

        let canonical = serde_json::to_value(binding).unwrap();
        for (field, replacement) in [
            ("provider_id_sha256", serde_json::json!(digest(0x40))),
            ("agent_id_sha256", serde_json::json!(digest(0x41))),
            ("task_id_sha256", serde_json::json!(digest(0x42))),
            (
                "runtime_lifecycle_binding_sha256",
                serde_json::json!(digest(0x43)),
            ),
            ("daemon_attempt_generation", serde_json::json!(2)),
            (
                "daemon_attempt_allocation_record_sha256",
                serde_json::json!(digest(0x44)),
            ),
            (
                "daemon_attempt_context_sha256",
                serde_json::json!(digest(0x45)),
            ),
            (
                "delivery_provider_attempt_id_sha256",
                serde_json::json!(digest(0x46)),
            ),
            ("direct_binding_sha256", serde_json::json!(digest(0x47))),
            (
                "direct_attempt_kernel_binding_sha256",
                serde_json::json!(digest(0x48)),
            ),
        ] {
            let mut drifted = canonical.clone();
            drifted[field] = replacement;
            let decoded: DirectAttemptKernelBindingV1 = serde_json::from_value(drifted).unwrap();
            assert!(decoded.validate().is_err(), "accepted drift in {field}");
        }

        let mut unknown_provider = canonical.clone();
        unknown_provider["provider"] = serde_json::json!("unregistered_provider");
        assert!(serde_json::from_value::<DirectAttemptKernelBindingV1>(unknown_provider).is_err());

        let mut unknown = canonical.clone();
        unknown["path"] = serde_json::json!("/sys/fs/cgroup/injected");
        assert!(serde_json::from_value::<DirectAttemptKernelBindingV1>(unknown).is_err());
        let mut missing = canonical;
        missing
            .as_object_mut()
            .unwrap()
            .remove("daemon_attempt_allocation_record_sha256");
        assert!(serde_json::from_value::<DirectAttemptKernelBindingV1>(missing).is_err());

        assert!(
            DirectAttemptKernelBindingV1::new(
                Provider::Codex,
                digest(0x50),
                digest_utf8(b"agent-codex-direct-v1").unwrap(),
                digest(0x33),
                runtime,
                generation,
                digest(0x34),
                context,
                delivery,
                digest(0x35),
            )
            .is_err()
        );
        assert!(
            DirectAttemptKernelBindingV1::new(
                Provider::Codex,
                digest_utf8(b"openai-codex").unwrap(),
                digest_utf8(b"agent-codex-direct-v1").unwrap(),
                digest(0x33),
                runtime,
                generation,
                digest(0x34),
                context,
                digest(0x51),
                digest(0x35),
            )
            .is_err()
        );
    }

    #[test]
    fn foundation_unavailable_response_never_advances_lifecycle() {
        let mut lifecycle = LifecycleState::new();
        let request = install(Provider::Codex, 1, 6);
        lifecycle
            .apply_success(
                &request,
                &Response::MutationUnavailable {
                    operation: Operation::InstallCredential,
                    reason: MutationUnavailableReason::BackendNotInstalled,
                },
                &[],
            )
            .unwrap();
        assert_eq!(
            lifecycle.inventory(),
            ProviderInventory {
                codex: ProviderStatus {
                    credential: CredentialStatus::Empty,
                    invocation: InvocationStatus::Idle,
                },
            }
        );
        assert!(matches!(
            lifecycle.apply_success(
                &request,
                &Response::MutationUnavailable {
                    operation: Operation::SpawnInvocation,
                    reason: MutationUnavailableReason::BackendNotInstalled,
                },
                &[],
            ),
            Err(ProtocolError::ResponseMismatch)
        ));
    }

    #[test]
    fn response_semantics_pin_hello_peer_and_every_status_claim() {
        let lifecycle = LifecycleState::new();
        let expected = expectations();
        lifecycle
            .validate_response_semantics(
                &expected,
                &Request::Hello,
                &Response::Hello {
                    peer_binding: expected.peer_binding,
                },
                &[],
            )
            .unwrap();
        assert!(matches!(
            lifecycle.validate_response_semantics(
                &expected,
                &Request::Hello,
                &Response::Hello {
                    peer_binding: digest(51),
                },
                &[],
            ),
            Err(ProtocolError::ResponseMismatch)
        ));

        let valid = status_for(&lifecycle, expected);
        lifecycle
            .validate_response_semantics(&expected, &Request::Status, &valid, &[])
            .unwrap();

        let wrong_mode = Response::Status {
            mode: BrokerMode::V2Operational,
            capability_contract: expected.capability_contract,
            mutation_effect_count: 0,
            inventory: Box::new(lifecycle.inventory()),
            recovery: lifecycle.recovery_status(),
        };
        let mut wrong_capability = expected.capability_contract;
        wrong_capability.effective ^= 1;
        let wrong_capability = Response::Status {
            mode: expected.mode,
            capability_contract: wrong_capability,
            mutation_effect_count: 0,
            inventory: Box::new(lifecycle.inventory()),
            recovery: lifecycle.recovery_status(),
        };
        let wrong_inventory = Response::Status {
            mode: expected.mode,
            capability_contract: expected.capability_contract,
            mutation_effect_count: 0,
            inventory: Box::new(ProviderInventory {
                codex: ProviderStatus {
                    credential: CredentialStatus::Installed {
                        generation: generation(1),
                        credential_sha256: digest(9),
                    },
                    invocation: InvocationStatus::Idle,
                },
            }),
            recovery: lifecycle.recovery_status(),
        };
        let wrong_recovery = Response::Status {
            mode: expected.mode,
            capability_contract: expected.capability_contract,
            mutation_effect_count: 0,
            inventory: Box::new(lifecycle.inventory()),
            recovery: RecoveryStatus::Available {
                generation: generation(1),
                evidence_sha256: digest(9),
            },
        };
        let wrong_effect_count = Response::Status {
            mode: expected.mode,
            capability_contract: expected.capability_contract,
            mutation_effect_count: 1,
            inventory: Box::new(lifecycle.inventory()),
            recovery: lifecycle.recovery_status(),
        };
        for response in [
            wrong_mode,
            wrong_capability,
            wrong_inventory,
            wrong_recovery,
            wrong_effect_count,
        ] {
            assert!(matches!(
                lifecycle.validate_response_semantics(&expected, &Request::Status, &response, &[],),
                Err(ProtocolError::ResponseMismatch)
            ));
        }

        let mut operational = expected;
        operational.mode = BrokerMode::V2Operational;
        assert!(matches!(
            lifecycle.validate_response_semantics(
                &operational,
                &Request::GetRecoveryEvidence,
                &Response::MutationUnavailable {
                    operation: Operation::GetRecoveryEvidence,
                    reason: MutationUnavailableReason::BackendNotInstalled,
                },
                &[],
            ),
            Err(ProtocolError::ResponseMismatch)
        ));
    }

    #[test]
    fn lifecycle_requires_credential_and_tracks_pidfd_opaque_handle_to_collection() {
        let mut lifecycle = LifecycleState::new();
        let spawn_request = spawn(Provider::Codex, 11, 1, 6, 7);
        let spawn_response = spawned(&spawn_request, 12);
        assert!(matches!(
            lifecycle.apply_success(&spawn_request, &spawn_response, &[]),
            Err(ProtocolError::CredentialMismatch)
        ));

        let install_request = install(Provider::Codex, 1, 6);
        lifecycle
            .apply_success(
                &install_request,
                &Response::CredentialInstalled {
                    provider: Provider::Codex,
                    credential_generation: generation(1),
                    credential_sha256: digest(6),
                },
                &[],
            )
            .unwrap();
        lifecycle
            .apply_success(&spawn_request, &spawn_response, &[])
            .unwrap();
        assert!(matches!(
            lifecycle.inventory().codex.invocation,
            InvocationStatus::Running { .. }
        ));
        let early_collect = Request::CollectInvocation { handle: handle(12) };
        assert!(matches!(
            lifecycle.apply_success(
                &early_collect,
                &Response::InvocationCollected {
                    handle: handle(12),
                    outcome: InvocationOutcome::Terminated,
                    report_sha256: digest(9),
                    report_size: 12,
                },
                &[sealed_fd(12, digest(9))],
            ),
            Err(ProtocolError::LifecycleMismatch)
        ));

        let rotate = install(Provider::Codex, 2, 8);
        assert!(matches!(
            lifecycle.apply_success(
                &rotate,
                &Response::CredentialInstalled {
                    provider: Provider::Codex,
                    credential_generation: generation(2),
                    credential_sha256: digest(8),
                },
                &[],
            ),
            Err(ProtocolError::ProviderBusy)
        ));

        let terminate = Request::TerminateInvocation {
            handle: handle(12),
            reason: TerminationReason::PolicyRevoked,
        };
        lifecycle
            .apply_success(
                &terminate,
                &Response::InvocationTerminationAccepted {
                    handle: handle(12),
                    reason: TerminationReason::PolicyRevoked,
                },
                &[],
            )
            .unwrap();
        assert!(matches!(
            lifecycle.inventory().codex.invocation,
            InvocationStatus::Terminating { .. }
        ));

        let collect = Request::CollectInvocation { handle: handle(12) };
        assert!(matches!(
            lifecycle.apply_success(
                &collect,
                &Response::InvocationRunning { handle: handle(12) },
                &[],
            ),
            Err(ProtocolError::LifecycleMismatch)
        ));
        lifecycle
            .apply_success(
                &collect,
                &Response::InvocationTerminating {
                    handle: handle(12),
                    reason: TerminationReason::PolicyRevoked,
                },
                &[],
            )
            .unwrap();
        assert!(matches!(
            lifecycle.apply_success(
                &collect,
                &Response::InvocationTerminating {
                    handle: handle(12),
                    reason: TerminationReason::UserCancel,
                },
                &[],
            ),
            Err(ProtocolError::LifecycleMismatch)
        ));
        assert!(matches!(
            lifecycle.apply_success(
                &collect,
                &Response::InvocationCollected {
                    handle: handle(12),
                    outcome: InvocationOutcome::Succeeded,
                    report_sha256: digest(9),
                    report_size: 12,
                },
                &[sealed_fd(12, digest(9))],
            ),
            Err(ProtocolError::LifecycleMismatch)
        ));
        lifecycle
            .apply_success(
                &collect,
                &Response::InvocationCollected {
                    handle: handle(12),
                    outcome: InvocationOutcome::Terminated,
                    report_sha256: digest(9),
                    report_size: 12,
                },
                &[sealed_fd(12, digest(9))],
            )
            .unwrap();
        assert_eq!(
            lifecycle.inventory().codex.invocation,
            InvocationStatus::Idle
        );

        assert!(matches!(
            lifecycle.apply_success(&spawn_request, &spawn_response, &[]),
            Err(ProtocolError::InvocationReplay)
        ));
        assert!(matches!(
            lifecycle.apply_success(
                &collect,
                &Response::InvocationRunning { handle: handle(12) },
                &[],
            ),
            Err(ProtocolError::InvocationUnknown)
        ));
    }

    #[test]
    fn lifecycle_rejects_generation_rollback_and_concurrent_codex_invocations() {
        let mut lifecycle = LifecycleState::new();
        {
            let provider = Provider::Codex;
            let request = install(provider, 2, 6);
            lifecycle
                .apply_success(
                    &request,
                    &Response::CredentialInstalled {
                        provider,
                        credential_generation: generation(2),
                        credential_sha256: digest(6),
                    },
                    &[],
                )
                .unwrap();
        }
        let rollback = install(Provider::Codex, 1, 7);
        assert!(matches!(
            lifecycle.apply_success(
                &rollback,
                &Response::CredentialInstalled {
                    provider: Provider::Codex,
                    credential_generation: generation(1),
                    credential_sha256: digest(7),
                },
                &[],
            ),
            Err(ProtocolError::CredentialGenerationRollback)
        ));

        let first = spawn(Provider::Codex, 20, 2, 6, 8);
        lifecycle
            .apply_success(&first, &spawned(&first, 30), &[])
            .unwrap();
        let second = spawn(Provider::Codex, 21, 2, 6, 9);
        assert!(matches!(
            lifecycle.apply_success(&second, &spawned(&second, 31), &[]),
            Err(ProtocolError::ProviderBusy)
        ));
    }

    #[test]
    fn deadline_termination_requires_deadline_outcome() {
        let mut lifecycle = LifecycleState::new();
        let install_request = install(Provider::Codex, 1, 6);
        lifecycle
            .apply_success(
                &install_request,
                &Response::CredentialInstalled {
                    provider: Provider::Codex,
                    credential_generation: generation(1),
                    credential_sha256: digest(6),
                },
                &[],
            )
            .unwrap();
        let spawn_request = spawn(Provider::Codex, 22, 1, 6, 8);
        lifecycle
            .apply_success(&spawn_request, &spawned(&spawn_request, 23), &[])
            .unwrap();
        let terminate = Request::TerminateInvocation {
            handle: handle(23),
            reason: TerminationReason::DeadlineExceeded,
        };
        lifecycle
            .apply_success(
                &terminate,
                &Response::InvocationTerminationAccepted {
                    handle: handle(23),
                    reason: TerminationReason::DeadlineExceeded,
                },
                &[],
            )
            .unwrap();
        let collect = Request::CollectInvocation { handle: handle(23) };
        assert!(matches!(
            lifecycle.apply_success(
                &collect,
                &Response::InvocationCollected {
                    handle: handle(23),
                    outcome: InvocationOutcome::Terminated,
                    report_sha256: digest(9),
                    report_size: 12,
                },
                &[sealed_fd(12, digest(9))],
            ),
            Err(ProtocolError::LifecycleMismatch)
        ));
        lifecycle
            .apply_success(
                &collect,
                &Response::InvocationCollected {
                    handle: handle(23),
                    outcome: InvocationOutcome::DeadlineExceeded,
                    report_sha256: digest(9),
                    report_size: 12,
                },
                &[sealed_fd(12, digest(9))],
            )
            .unwrap();
    }

    #[test]
    fn response_payload_policy_binds_report_and_recovery_digest_size() {
        assert!(std::hint::black_box(
            OPERATIONAL_HANDLES_REQUIRE_PIDFD_OWNERSHIP
        ));
        assert!(!std::hint::black_box(PROTOCOL_FREEZE_READY));
        let collected = Response::InvocationCollected {
            handle: handle(2),
            outcome: InvocationOutcome::Succeeded,
            report_sha256: digest(3),
            report_size: 12,
        };
        ClosedResponseFdPolicy
            .validate(&collected, &[sealed_fd(12, digest(3))])
            .unwrap();
        assert!(matches!(
            ClosedResponseFdPolicy.validate(&collected, &[sealed_fd(12, digest(4))]),
            Err(ProtocolError::PayloadDigestMismatch)
        ));

        let recovery = Response::RecoveryEvidence {
            generation: generation(1),
            evidence_sha256: digest(5),
            evidence_size: MAX_RECOVERY_EVIDENCE_BYTES + 1,
        };
        assert!(matches!(
            ClosedResponseFdPolicy.validate(
                &recovery,
                &[sealed_fd(MAX_RECOVERY_EVIDENCE_BYTES + 1, digest(5))],
            ),
            Err(ProtocolError::PayloadSizeDenied)
        ));
    }

    #[test]
    fn recovery_evidence_is_monotonic_and_cannot_equivocate() {
        let mut lifecycle = LifecycleState::new();
        let request = Request::GetRecoveryEvidence;
        let response = |generation_value, digest_value| Response::RecoveryEvidence {
            generation: generation(generation_value),
            evidence_sha256: digest(digest_value),
            evidence_size: 12,
        };
        lifecycle
            .apply_success(&request, &response(2, 8), &[sealed_fd(12, digest(8))])
            .unwrap();
        lifecycle
            .apply_success(&request, &response(2, 8), &[sealed_fd(12, digest(8))])
            .unwrap();
        assert_eq!(
            lifecycle.recovery_status(),
            RecoveryStatus::Available {
                generation: generation(2),
                evidence_sha256: digest(8),
            }
        );
        assert!(matches!(
            lifecycle.apply_success(&request, &response(1, 9), &[sealed_fd(12, digest(9))]),
            Err(ProtocolError::RecoveryGenerationRollback)
        ));
        assert!(matches!(
            lifecycle.apply_success(&request, &response(2, 9), &[sealed_fd(12, digest(9))]),
            Err(ProtocolError::RecoveryEvidenceEquivocation)
        ));
    }
}
