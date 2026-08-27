//! Activation-only Android operation replay-control client foundation.
//!
//! This module deliberately exposes two endpoint-typed activation functions,
//! not a caller-selected socket, protocol, role, or operation. Each function
//! connects to one compile-time-fixed abstract socket, authenticates the
//! Android server through the existing kernel peer boundary, and sends only an
//! ACTIVATE request. There is no ACK encoder or API.
//!
//! Activation is never accepted from local state alone. A caller must consume
//! an endpoint-specific sealed external expectation. No production
//! constructor for either expectation exists in this source batch. First use
//! accepts only a CREATED, pristine response for the externally fixed epoch.
//! Restart accepts only an EXISTING response that exactly matches every
//! externally sealed field. Any mismatch is a rollback/HOLD; this layer never
//! repairs, retries with different state, or advances a watermark.

use std::io::{self, Read as _, Write as _};
use std::net::Shutdown;
use std::path::Path;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use thiserror::Error;
#[cfg(feature = "device-launch-package-conformance")]
use trillionnium_os_types::direct_operation::{DirectOperationAdapter, DirectOperationBinding};

use crate::DirectToolError;
use crate::uds::{self, ExpectedBackendPeer};

const SYSTEM_API_SOCKET: &str = "@trillionnium_system_api_replay_control";
const ACCESSIBILITY_SOCKET: &str = "@trillionnium_accessibility_replay_control";
const SYSTEM_API_MAGIC: [u8; 8] = *b"TRSYSC01";
const ACCESSIBILITY_MAGIC: [u8; 8] = *b"TRACSC01";

const VERSION: u8 = 1;
const ACTIVATE_OPERATION: u8 = 1;
const ACTIVATE_RESPONSE_OPERATION: u8 = 0x81;
const HEADER_BYTES: usize = 12;
const EPOCH_BYTES: usize = 32;
const DIGEST_BYTES: usize = 64;
const ACTIVATE_REQUEST_PAYLOAD_BYTES: usize = EPOCH_BYTES;
const ACTIVATE_REQUEST_FRAME_BYTES: usize = HEADER_BYTES + ACTIVATE_REQUEST_PAYLOAD_BYTES;
const ACTIVATE_RESPONSE_PAYLOAD_BYTES: usize = 188;
const ACTIVATE_RESPONSE_FRAME_BYTES: usize = HEADER_BYTES + ACTIVATE_RESPONSE_PAYLOAD_BYTES;
const ZERO_EPOCH: &str = "00000000000000000000000000000000";
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const CREATED_STATUS: u8 = 1;
const EXISTING_STATUS: u8 = 2;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Error)]
pub(crate) enum AndroidOperationReplayControlError {
    #[error("Android operation replay-control transport failed: {0}")]
    Transport(#[from] DirectToolError),
    #[error("Android operation replay-control protocol HOLD: {0}")]
    ProtocolHold(&'static str),
    #[error("Android operation replay-control rollback/HOLD: {0}")]
    RollbackHold(&'static str),
}

type ControlResult<T> = std::result::Result<T, AndroidOperationReplayControlError>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct ActivationSnapshot {
    epoch: String,
    acknowledged_through: i64,
    next_sequence: i64,
    highest_retained_sequence: i64,
    operation_epoch_blocked: bool,
    operation_epoch_exhausted: bool,
    authenticated_ack_sha256: String,
    authenticated_ack_chain_sha256: String,
}

#[cfg(feature = "device-launch-package-conformance")]
pub(crate) struct DeviceConformanceActivation {
    android_ack_already_applied: bool,
    journal_effect_role: bool,
    provider_id: String,
    agent_id: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    invocation_id: String,
    delivery_provider_attempt_id: String,
    current_snapshot: ActivationSnapshot,
    activation_request_sha256: String,
    activation_response_sha256: String,
    activation_exchange_sha256: String,
    operation_epoch_authority_sha256: crate::operation_journal::Sha256Digest,
}

#[cfg(feature = "device-launch-package-conformance")]
impl DeviceConformanceActivation {
    pub(crate) fn android_ack_already_applied(&self) -> bool {
        !self.journal_effect_role && self.android_ack_already_applied
    }

    /// Consume the exact peer-authenticated ACTIVATE exchange for the one
    /// conformance journal which supplied its expectation.  The private
    /// journal token prevents another crate module from extracting a digest
    /// and self-reporting it as epoch authority.
    pub(crate) fn consume_for_journal(
        self,
        _consumer: crate::operation_journal::DeviceConformanceEpochAuthorityConsumerToken,
        binding: &DirectOperationBinding,
        binding_sha256: &str,
        adapter_id: &str,
        agent_id: &str,
        invocation_id: &str,
        delivery_provider_attempt_id: &str,
        current: &crate::operation_journal::DeviceConformanceReplayState,
    ) -> std::result::Result<crate::operation_journal::Sha256Digest, &'static str> {
        let current_snapshot = activation_snapshot_from_device_conformance(current)
            .map_err(|_| "ACTIVATE authority current journal state is invalid")?;
        if !self.journal_effect_role
            || self.adapter != DirectOperationAdapter::SystemApi
            || adapter_id != DirectOperationAdapter::SystemApi.adapter_id()
            || binding.validate().is_err()
            || binding.digest_sha256().ok().as_deref() != Some(binding_sha256)
            || binding.stable_seed.provider_id != self.provider_id
            || binding.stable_seed.agent_id != self.agent_id
            || binding.invocation_id != self.invocation_id
            || binding.attempt.delivery_provider_attempt_id != self.delivery_provider_attempt_id
            || agent_id != self.agent_id
            || invocation_id != self.invocation_id
            || delivery_provider_attempt_id != self.delivery_provider_attempt_id
            || current_snapshot != self.current_snapshot
        {
            return Err("ACTIVATE authority does not match the exact journal identity and state");
        }
        let expected_lineage = device_conformance_operation_epoch_authority_sha256(
            &self.provider_id,
            &self.agent_id,
            self.adapter,
            &self.binding_sha256,
            &self.invocation_id,
            &self.delivery_provider_attempt_id,
            &self.current_snapshot.epoch,
            &self.activation_request_sha256,
        );
        let expected_exchange = device_conformance_activation_exchange_sha256(
            expected_lineage,
            &self.current_snapshot,
            &self.activation_request_sha256,
            &self.activation_response_sha256,
        );
        if self.binding_sha256 != binding_sha256
            || self.operation_epoch_authority_sha256 != expected_lineage
            || self.activation_exchange_sha256 != expected_exchange
        {
            return Err("ACTIVATE authority proof is internally inconsistent");
        }
        Ok(self.operation_epoch_authority_sha256)
    }

    #[cfg(test)]
    fn operation_epoch_authority_sha256_for_test(&self) -> String {
        self.operation_epoch_authority_sha256.to_hex()
    }

    #[cfg(test)]
    fn activation_exchange_sha256_for_test(&self) -> &str {
        &self.activation_exchange_sha256
    }
}

impl ActivationSnapshot {
    fn is_pristine(&self) -> bool {
        self.acknowledged_through == 0
            && self.next_sequence == 1
            && self.highest_retained_sequence == 0
            && !self.operation_epoch_blocked
            && !self.operation_epoch_exhausted
            && self.authenticated_ack_sha256 == ZERO_SHA256
            && self.authenticated_ack_chain_sha256 == ZERO_SHA256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ActivationStatus {
    Created,
    Existing,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedActivation {
    status: ActivationStatus,
    snapshot: ActivationSnapshot,
}

enum ExternalActivationExpectation {
    FirstUse {
        epoch: String,
    },
    Restart {
        snapshot: ActivationSnapshot,
    },
    #[cfg(feature = "device-launch-package-conformance")]
    ConformanceExact {
        current: ActivationSnapshot,
        after_pending_ack: Option<ActivationSnapshot>,
    },
}

impl ExternalActivationExpectation {
    fn epoch(&self) -> &str {
        match self {
            Self::FirstUse { epoch } => epoch,
            Self::Restart { snapshot } => &snapshot.epoch,
            #[cfg(feature = "device-launch-package-conformance")]
            Self::ConformanceExact { current, .. } => &current.epoch,
        }
    }
}

/// Sealed external expectation for System API activation.
///
/// Fields are private and there is intentionally no production constructor.
/// A future rollback-resistant authority verifier must be the only component
/// allowed to add such a constructor.
pub(crate) struct SealedSystemApiActivationExpectation {
    expectation: ExternalActivationExpectation,
}

/// Sealed external expectation for Accessibility activation.
///
/// This is a distinct type so an Accessibility decision cannot be passed to
/// the System API activation function, or vice versa.
pub(crate) struct SealedAccessibilityActivationExpectation {
    expectation: ExternalActivationExpectation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifiedEndpoint {
    SystemApi,
    Accessibility,
}

/// Exact activation state accepted against one consumed sealed expectation.
///
/// This type has no constructor outside this module and therefore cannot turn
/// caller-authored state into activation authority.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct VerifiedOperationReplayActivation {
    endpoint: VerifiedEndpoint,
    status: ActivationStatus,
    snapshot: ActivationSnapshot,
    activation_request_sha256: String,
    activation_response_sha256: String,
}

#[derive(Debug, Eq, PartialEq)]
struct ReconciledOperationReplayActivation {
    endpoint: VerifiedEndpoint,
    status: ActivationStatus,
    snapshot: ActivationSnapshot,
}

#[cfg(feature = "device-launch-package-conformance")]
#[derive(Clone, Copy)]
enum DeviceConformanceActivationRole {
    AdapterEffect,
    ReplaySync,
}

#[cfg(feature = "device-launch-package-conformance")]
struct TrustedDeviceConformanceActivationIdentity<'a> {
    role: DeviceConformanceActivationRole,
    provider_id: &'a str,
    agent_id: &'a str,
    adapter: DirectOperationAdapter,
    binding: &'a DirectOperationBinding,
    binding_sha256: &'a str,
    invocation_id: &'a str,
    delivery_provider_attempt_id: &'a str,
}

#[derive(Clone, Copy)]
struct FixedEndpoint {
    socket: &'static str,
    magic: [u8; 8],
    expected_peer: ExpectedBackendPeer,
    verified_endpoint: VerifiedEndpoint,
}

const SYSTEM_API_ENDPOINT: FixedEndpoint = FixedEndpoint {
    socket: SYSTEM_API_SOCKET,
    magic: SYSTEM_API_MAGIC,
    expected_peer: ExpectedBackendPeer::SystemServer,
    verified_endpoint: VerifiedEndpoint::SystemApi,
};

const ACCESSIBILITY_ENDPOINT: FixedEndpoint = FixedEndpoint {
    socket: ACCESSIBILITY_SOCKET,
    magic: ACCESSIBILITY_MAGIC,
    expected_peer: ExpectedBackendPeer::AccessibilityService,
    verified_endpoint: VerifiedEndpoint::Accessibility,
};

/// Activate the fixed System API operation replay-control endpoint.
///
/// The expectation is consumed so the same sealed decision cannot be reused
/// for another activation attempt.
pub(crate) fn activate_system_api(
    expectation: SealedSystemApiActivationExpectation,
) -> ControlResult<VerifiedOperationReplayActivation> {
    activate_fixed(SYSTEM_API_ENDPOINT, expectation.expectation)
}

/// Activate the fixed System API endpoint against a definitive, durable P0
/// conformance journal state.
///
/// A pristine state accepts either the exact CREATED first use or the exact
/// EXISTING restart.  When a root-owned, binding-checked outer ACK is pending,
/// the one permitted crash window accepts either the pre-ACK state or the
/// exact post-ACK state.  No third state is repaired or adopted.  This local
/// comparison is deliberately non-product and cannot construct the product
/// rollback authority.
#[cfg(feature = "device-launch-package-conformance")]
pub(crate) fn activate_system_api_for_device_conformance(
    current: &crate::operation_journal::DeviceConformanceReplayState,
    pending_ack: Option<&trillionnium_os_types::direct_operation::DirectOperationOuterAckInboxV3>,
    context: &crate::trusted_context::TrustedAdapterContext,
) -> crate::Result<DeviceConformanceActivation> {
    let identity = TrustedDeviceConformanceActivationIdentity {
        role: DeviceConformanceActivationRole::AdapterEffect,
        provider_id: context.provider_id(),
        agent_id: context.agent_id(),
        adapter: context.adapter(),
        binding: context.binding(),
        binding_sha256: context.binding_sha256(),
        invocation_id: context.invocation_id(),
        delivery_provider_attempt_id: context.delivery_provider_attempt_id(),
    };
    activate_system_api_for_device_conformance_with(
        current,
        pending_ack,
        &identity,
        activate_system_api,
    )
}

/// Replay-sync uses the same exact Android ACTIVATE codec and trusted
/// provider/adapter binding, but its result can prove only ACK recovery.  The
/// role bit carried inside the opaque result prevents it from being installed
/// as adapter effect authority.
#[cfg(feature = "device-launch-package-conformance")]
pub(crate) fn activate_system_api_for_device_conformance_replay_sync(
    current: &crate::operation_journal::DeviceConformanceReplayState,
    pending_ack: Option<&trillionnium_os_types::direct_operation::DirectOperationOuterAckInboxV3>,
    context: &crate::trusted_context::TrustedReplaySyncContext,
) -> crate::Result<DeviceConformanceActivation> {
    let identity = TrustedDeviceConformanceActivationIdentity {
        role: DeviceConformanceActivationRole::ReplaySync,
        provider_id: context.provider_id(),
        agent_id: context.agent_id(),
        adapter: context.adapter(),
        binding: context.binding(),
        binding_sha256: context.binding_sha256(),
        invocation_id: context.invocation_id(),
        delivery_provider_attempt_id: context.delivery_provider_attempt_id(),
    };
    activate_system_api_for_device_conformance_with(
        current,
        pending_ack,
        &identity,
        activate_system_api,
    )
}

#[cfg(feature = "device-launch-package-conformance")]
fn activate_system_api_for_device_conformance_with(
    current: &crate::operation_journal::DeviceConformanceReplayState,
    pending_ack: Option<&trillionnium_os_types::direct_operation::DirectOperationOuterAckInboxV3>,
    identity: &TrustedDeviceConformanceActivationIdentity<'_>,
    activate: impl FnOnce(
        SealedSystemApiActivationExpectation,
    ) -> ControlResult<VerifiedOperationReplayActivation>,
) -> crate::Result<DeviceConformanceActivation> {
    validate_device_conformance_activation_identity(identity)?;
    let current = activation_snapshot_from_device_conformance(current)?;
    let after_pending_ack = pending_ack
        .map(|inbox| activation_snapshot_after_pending_ack(&current, inbox))
        .transpose()?;
    let verified = activate(SealedSystemApiActivationExpectation {
        expectation: ExternalActivationExpectation::ConformanceExact {
            current: current.clone(),
            after_pending_ack: after_pending_ack.clone(),
        },
    })
    .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    if verified.endpoint != VerifiedEndpoint::SystemApi {
        return Err(DirectToolError::BackendUnavailable(
            "P0 launch conformance activated a non-System-API endpoint".to_string(),
        ));
    }
    let operation_epoch_authority_sha256 = device_conformance_operation_epoch_authority_sha256(
        identity.provider_id,
        identity.agent_id,
        identity.adapter,
        identity.binding_sha256,
        identity.invocation_id,
        identity.delivery_provider_attempt_id,
        &current.epoch,
        &verified.activation_request_sha256,
    );
    let activation_exchange_sha256 = device_conformance_activation_exchange_sha256(
        operation_epoch_authority_sha256,
        &current,
        &verified.activation_request_sha256,
        &verified.activation_response_sha256,
    );
    Ok(DeviceConformanceActivation {
        android_ack_already_applied: (current.acknowledged_through > 0
            && verified.snapshot == current)
            || after_pending_ack
                .as_ref()
                .is_some_and(|advanced| verified.snapshot == *advanced),
        journal_effect_role: matches!(
            identity.role,
            DeviceConformanceActivationRole::AdapterEffect
        ),
        provider_id: identity.provider_id.to_string(),
        agent_id: identity.agent_id.to_string(),
        adapter: identity.adapter,
        binding_sha256: identity.binding_sha256.to_string(),
        invocation_id: identity.invocation_id.to_string(),
        delivery_provider_attempt_id: identity.delivery_provider_attempt_id.to_string(),
        current_snapshot: current,
        activation_request_sha256: verified.activation_request_sha256,
        activation_response_sha256: verified.activation_response_sha256,
        activation_exchange_sha256,
        operation_epoch_authority_sha256,
    })
}

#[cfg(feature = "device-launch-package-conformance")]
fn validate_device_conformance_activation_identity(
    identity: &TrustedDeviceConformanceActivationIdentity<'_>,
) -> crate::Result<()> {
    identity
        .binding
        .validate()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    let observed_binding_sha256 = identity
        .binding
        .digest_sha256()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    if identity.adapter != DirectOperationAdapter::SystemApi
        || !identity
            .binding
            .authorized_adapter_set
            .authorizes(identity.adapter)
        || observed_binding_sha256 != identity.binding_sha256
        || identity.binding.stable_seed.provider_id != identity.provider_id
        || identity.binding.stable_seed.agent_id != identity.agent_id
        || identity.binding.invocation_id != identity.invocation_id
        || identity.binding.attempt.delivery_provider_attempt_id
            != identity.delivery_provider_attempt_id
    {
        return Err(DirectToolError::BackendUnavailable(
            "P0 ACTIVATE identity differs from the trusted provider/adapter binding".to_string(),
        ));
    }
    Ok(())
}

#[cfg(feature = "device-launch-package-conformance")]
fn activation_snapshot_from_device_conformance(
    state: &crate::operation_journal::DeviceConformanceReplayState,
) -> crate::Result<ActivationSnapshot> {
    let snapshot = ActivationSnapshot {
        epoch: state.epoch.clone(),
        acknowledged_through: i64::try_from(state.acknowledged_through).map_err(|_| {
            DirectToolError::BackendUnavailable(
                "P0 conformance acknowledged watermark exceeds Android range".to_string(),
            )
        })?,
        next_sequence: i64::try_from(state.next_sequence).map_err(|_| {
            DirectToolError::BackendUnavailable(
                "P0 conformance next sequence exceeds Android range".to_string(),
            )
        })?,
        highest_retained_sequence: i64::try_from(state.highest_retained_sequence).map_err(
            |_| {
                DirectToolError::BackendUnavailable(
                    "P0 conformance retained sequence exceeds Android range".to_string(),
                )
            },
        )?,
        operation_epoch_blocked: false,
        operation_epoch_exhausted: state.operation_epoch_exhausted,
        authenticated_ack_sha256: state.authenticated_ack_sha256.clone(),
        authenticated_ack_chain_sha256: state.authenticated_ack_chain_sha256.clone(),
    };
    validate_activation_snapshot(&snapshot)
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    Ok(snapshot)
}

#[cfg(feature = "device-launch-package-conformance")]
fn activation_snapshot_after_pending_ack(
    current: &ActivationSnapshot,
    inbox: &trillionnium_os_types::direct_operation::DirectOperationOuterAckInboxV3,
) -> crate::Result<ActivationSnapshot> {
    inbox
        .validate()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    let evidence = &inbox.acknowledgement.journal_evidence_snapshot;
    let current_acknowledged = u64::try_from(current.acknowledged_through).map_err(|_| {
        DirectToolError::BackendUnavailable(
            "P0 conformance current ACK watermark is negative".to_string(),
        )
    })?;
    let current_retained = u64::try_from(current.highest_retained_sequence).map_err(|_| {
        DirectToolError::BackendUnavailable(
            "P0 conformance current retained sequence is negative".to_string(),
        )
    })?;
    if evidence.journal_epoch != current.epoch
        || evidence.previous_ack_watermark != current_acknowledged
        || evidence.previous_ack_chain_sha256 != current.authenticated_ack_chain_sha256
        || evidence.journal_evidence_count != 1
        || evidence.first_journal_sequence != evidence.last_journal_sequence
        || evidence.last_journal_sequence != current_retained
    {
        return Err(DirectToolError::BackendUnavailable(
            "P0 conformance pending outer ACK does not exactly advance the current single-operation replay state"
                .to_string(),
        ));
    }
    let acknowledged_through = i64::try_from(evidence.last_journal_sequence).map_err(|_| {
        DirectToolError::BackendUnavailable(
            "P0 conformance pending outer ACK exceeds Android range".to_string(),
        )
    })?;
    let advanced = ActivationSnapshot {
        epoch: current.epoch.clone(),
        acknowledged_through,
        next_sequence: current.next_sequence,
        highest_retained_sequence: 0,
        operation_epoch_blocked: false,
        operation_epoch_exhausted: current.operation_epoch_exhausted,
        authenticated_ack_sha256: inbox.acknowledgement_sha256.clone(),
        authenticated_ack_chain_sha256: inbox.chain_step.authenticated_ack_chain_sha256.clone(),
    };
    validate_activation_snapshot(&advanced)
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    Ok(advanced)
}

/// Activate the fixed Accessibility operation replay-control endpoint.
///
/// There is no endpoint, socket, role, protocol, or operation selector.
pub(crate) fn activate_accessibility(
    expectation: SealedAccessibilityActivationExpectation,
) -> ControlResult<VerifiedOperationReplayActivation> {
    activate_fixed(ACCESSIBILITY_ENDPOINT, expectation.expectation)
}

fn activate_fixed(
    endpoint: FixedEndpoint,
    expectation: ExternalActivationExpectation,
) -> ControlResult<VerifiedOperationReplayActivation> {
    let fixed_path = Path::new(endpoint.socket);
    activate_fixed_at_path(endpoint, fixed_path, expectation)
}

fn activate_fixed_at_path(
    endpoint: FixedEndpoint,
    fixed_path: &Path,
    expectation: ExternalActivationExpectation,
) -> ControlResult<VerifiedOperationReplayActivation> {
    let request = encode_activate_request(endpoint.magic, expectation.epoch())?;
    let mut stream = uds::connect(fixed_path)?;
    uds::verify_connected_peer(fixed_path, &stream, endpoint.expected_peer)?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(DirectToolError::from)?;
    stream
        .set_write_timeout(Some(WRITE_TIMEOUT))
        .map_err(DirectToolError::from)?;
    stream.write_all(&request).map_err(DirectToolError::from)?;
    stream.flush().map_err(DirectToolError::from)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(DirectToolError::from)?;

    let response = read_exact_activation_response(&mut stream)?;
    let observed = decode_activation_response(endpoint.magic, &response)?;
    let reconciled =
        reconcile_external_expectation(endpoint.verified_endpoint, expectation, observed)?;
    Ok(VerifiedOperationReplayActivation {
        endpoint: reconciled.endpoint,
        status: reconciled.status,
        snapshot: reconciled.snapshot,
        activation_request_sha256: sha256_hex(&request),
        activation_response_sha256: sha256_hex(&response),
    })
}

fn encode_activate_request(magic: [u8; 8], epoch: &str) -> ControlResult<[u8; 44]> {
    if !valid_nonzero_epoch(epoch) {
        return Err(AndroidOperationReplayControlError::RollbackHold(
            "sealed activation epoch is invalid",
        ));
    }
    let mut frame = [0_u8; ACTIVATE_REQUEST_FRAME_BYTES];
    frame[..8].copy_from_slice(&magic);
    frame[8] = VERSION;
    frame[9] = ACTIVATE_OPERATION;
    frame[10..12].copy_from_slice(&(ACTIVATE_REQUEST_PAYLOAD_BYTES as u16).to_be_bytes());
    frame[HEADER_BYTES..].copy_from_slice(epoch.as_bytes());
    Ok(frame)
}

fn read_exact_activation_response(
    stream: &mut std::os::unix::net::UnixStream,
) -> ControlResult<[u8; ACTIVATE_RESPONSE_FRAME_BYTES]> {
    let mut frame = [0_u8; ACTIVATE_RESPONSE_FRAME_BYTES];
    if let Err(error) = stream.read_exact(&mut frame) {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return Err(AndroidOperationReplayControlError::ProtocolHold(
                "activation response is not exactly 200 bytes",
            ));
        }
        return Err(DirectToolError::from(error).into());
    }
    stream
        .set_read_timeout(Some(RESPONSE_CLOSE_TIMEOUT))
        .map_err(DirectToolError::from)?;
    let mut trailing = [0_u8; 1];
    match stream.read(&mut trailing) {
        Ok(0) => Ok(frame),
        Ok(_) => Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response has trailing bytes",
        )),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Err(AndroidOperationReplayControlError::ProtocolHold(
                "activation responder did not close after 200 bytes",
            ))
        }
        Err(error) => Err(DirectToolError::from(error).into()),
    }
}

fn decode_activation_response(
    expected_magic: [u8; 8],
    frame: &[u8],
) -> ControlResult<ObservedActivation> {
    if frame.len() != ACTIVATE_RESPONSE_FRAME_BYTES {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response is not exactly 200 bytes",
        ));
    }
    if frame[..8] != expected_magic {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response magic mismatch",
        ));
    }
    if frame[8] != VERSION {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response version mismatch",
        ));
    }
    if frame[9] != ACTIVATE_RESPONSE_OPERATION {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response operation mismatch",
        ));
    }
    if u16::from_be_bytes([frame[10], frame[11]]) as usize != ACTIVATE_RESPONSE_PAYLOAD_BYTES {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response payload length mismatch",
        ));
    }

    let payload = &frame[HEADER_BYTES..];
    let status = match payload[0] {
        CREATED_STATUS => ActivationStatus::Created,
        EXISTING_STATUS => ActivationStatus::Existing,
        _ => {
            return Err(AndroidOperationReplayControlError::ProtocolHold(
                "activation response status is invalid",
            ));
        }
    };
    let operation_epoch_blocked = strict_boolean(payload[1])?;
    let operation_epoch_exhausted = strict_boolean(payload[2])?;
    if payload[3] != 0 {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response reserved byte is non-zero",
        ));
    }

    let epoch = parse_lower_hex(&payload[4..36], EPOCH_BYTES, false, "epoch")?;
    let acknowledged_through = parse_i64(&payload[36..44]);
    let next_sequence = parse_i64(&payload[44..52]);
    let highest_retained_sequence = parse_i64(&payload[52..60]);
    let authenticated_ack_sha256 =
        parse_lower_hex(&payload[60..124], DIGEST_BYTES, true, "ACK digest")?;
    let authenticated_ack_chain_sha256 =
        parse_lower_hex(&payload[124..188], DIGEST_BYTES, true, "ACK chain digest")?;

    let snapshot = ActivationSnapshot {
        epoch,
        acknowledged_through,
        next_sequence,
        highest_retained_sequence,
        operation_epoch_blocked,
        operation_epoch_exhausted,
        authenticated_ack_sha256,
        authenticated_ack_chain_sha256,
    };
    validate_activation_snapshot(&snapshot)?;
    if status == ActivationStatus::Created && !snapshot.is_pristine() {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "CREATED activation response is not pristine",
        ));
    }
    Ok(ObservedActivation { status, snapshot })
}

fn strict_boolean(value: u8) -> ControlResult<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response boolean is not canonical",
        )),
    }
}

fn parse_i64(bytes: &[u8]) -> i64 {
    let mut exact = [0_u8; 8];
    exact.copy_from_slice(bytes);
    i64::from_be_bytes(exact)
}

fn parse_lower_hex(
    bytes: &[u8],
    expected_len: usize,
    allow_zero: bool,
    field: &'static str,
) -> ControlResult<String> {
    if !valid_lower_hex(bytes, expected_len)
        || (!allow_zero && bytes.iter().all(|byte| *byte == b'0'))
    {
        return Err(AndroidOperationReplayControlError::ProtocolHold(field));
    }
    Ok(std::str::from_utf8(bytes)
        .expect("lower-hex bytes are ASCII")
        .to_string())
}

fn valid_lower_hex(bytes: &[u8], expected_len: usize) -> bool {
    bytes.len() == expected_len
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn valid_nonzero_epoch(epoch: &str) -> bool {
    epoch != ZERO_EPOCH && valid_lower_hex(epoch.as_bytes(), EPOCH_BYTES)
}

fn validate_activation_snapshot(snapshot: &ActivationSnapshot) -> ControlResult<()> {
    if !valid_nonzero_epoch(&snapshot.epoch)
        || snapshot.acknowledged_through < 0
        || snapshot.next_sequence <= 0
        || snapshot.highest_retained_sequence < 0
        || (snapshot.highest_retained_sequence != 0
            && snapshot.highest_retained_sequence <= snapshot.acknowledged_through)
    {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response sequence state is invalid",
        ));
    }

    let ack_is_zero = snapshot.authenticated_ack_sha256 == ZERO_SHA256;
    let chain_is_zero = snapshot.authenticated_ack_chain_sha256 == ZERO_SHA256;
    if (snapshot.acknowledged_through == 0 && (!ack_is_zero || !chain_is_zero))
        || (snapshot.acknowledged_through > 0 && (ack_is_zero || chain_is_zero))
    {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response ACK binding is invalid",
        ));
    }

    let highest_known = snapshot
        .acknowledged_through
        .max(snapshot.highest_retained_sequence);
    if highest_known == i64::MAX {
        if !snapshot.operation_epoch_exhausted || snapshot.next_sequence != i64::MAX {
            return Err(AndroidOperationReplayControlError::ProtocolHold(
                "activation response exhaustion state is invalid",
            ));
        }
    } else if snapshot.operation_epoch_exhausted || snapshot.next_sequence != highest_known + 1 {
        return Err(AndroidOperationReplayControlError::ProtocolHold(
            "activation response next sequence is invalid",
        ));
    }
    Ok(())
}

fn reconcile_external_expectation(
    endpoint: VerifiedEndpoint,
    expectation: ExternalActivationExpectation,
    observed: ObservedActivation,
) -> ControlResult<ReconciledOperationReplayActivation> {
    match expectation {
        ExternalActivationExpectation::FirstUse { epoch } => {
            if observed.status != ActivationStatus::Created {
                return Err(AndroidOperationReplayControlError::RollbackHold(
                    "first-use expectation received EXISTING state",
                ));
            }
            if observed.snapshot.epoch != epoch || !observed.snapshot.is_pristine() {
                return Err(AndroidOperationReplayControlError::RollbackHold(
                    "first-use activation does not match sealed pristine state",
                ));
            }
        }
        ExternalActivationExpectation::Restart { snapshot } => {
            if observed.status != ActivationStatus::Existing {
                return Err(AndroidOperationReplayControlError::RollbackHold(
                    "restart expectation received CREATED state",
                ));
            }
            if observed.snapshot != snapshot {
                return Err(AndroidOperationReplayControlError::RollbackHold(
                    "restart activation differs from sealed external state",
                ));
            }
        }
        #[cfg(feature = "device-launch-package-conformance")]
        ExternalActivationExpectation::ConformanceExact {
            current,
            after_pending_ack,
        } => {
            let current_matches = observed.snapshot == current
                && (observed.status == ActivationStatus::Existing
                    || (observed.status == ActivationStatus::Created && current.is_pristine()));
            let pending_matches = observed.status == ActivationStatus::Existing
                && after_pending_ack
                    .as_ref()
                    .is_some_and(|advanced| observed.snapshot == *advanced);
            if !current_matches && !pending_matches {
                return Err(AndroidOperationReplayControlError::RollbackHold(
                    "device-conformance activation differs from both exact crash-reconciliation states",
                ));
            }
        }
    }
    Ok(ReconciledOperationReplayActivation {
        endpoint,
        status: observed.status,
        snapshot: observed.snapshot,
    })
}

#[cfg(feature = "device-launch-package-conformance")]
fn device_conformance_operation_epoch_authority_sha256(
    provider_id: &str,
    agent_id: &str,
    adapter: DirectOperationAdapter,
    binding_sha256: &str,
    invocation_id: &str,
    delivery_provider_attempt_id: &str,
    epoch: &str,
    activation_request_sha256: &str,
) -> crate::operation_journal::Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.p0-device-conformance-operation-epoch-authority.v1\0");
    for (name, value) in [
        (b"endpoint".as_slice(), b"system_api".as_slice()),
        (b"provider_id".as_slice(), provider_id.as_bytes()),
        (b"agent_id".as_slice(), agent_id.as_bytes()),
        (b"adapter".as_slice(), adapter.adapter_id().as_bytes()),
        (b"binding_sha256".as_slice(), binding_sha256.as_bytes()),
        (b"invocation_id".as_slice(), invocation_id.as_bytes()),
        (
            b"delivery_provider_attempt_id".as_slice(),
            delivery_provider_attempt_id.as_bytes(),
        ),
        (b"current_epoch".as_slice(), epoch.as_bytes()),
        (
            b"activation_request_sha256".as_slice(),
            activation_request_sha256.as_bytes(),
        ),
    ] {
        hash_activation_field(&mut hasher, name, value);
    }
    crate::operation_journal::Sha256Digest::of_bytes(&hasher.finalize())
}

#[cfg(feature = "device-launch-package-conformance")]
fn device_conformance_activation_exchange_sha256(
    operation_epoch_authority_sha256: crate::operation_journal::Sha256Digest,
    current: &ActivationSnapshot,
    activation_request_sha256: &str,
    activation_response_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.p0-device-conformance-activation-exchange.v1\0");
    let current_snapshot_sha256 = activation_snapshot_sha256(current);
    for (name, value) in [
        (
            b"operation_epoch_authority_sha256".as_slice(),
            operation_epoch_authority_sha256.to_hex().as_bytes(),
        ),
        (
            b"current_snapshot_sha256".as_slice(),
            current_snapshot_sha256.as_bytes(),
        ),
        (
            b"activation_request_sha256".as_slice(),
            activation_request_sha256.as_bytes(),
        ),
        (
            b"activation_response_sha256".as_slice(),
            activation_response_sha256.as_bytes(),
        ),
    ] {
        hash_activation_field(&mut hasher, name, value);
    }
    lower_hex(&hasher.finalize())
}

#[cfg(feature = "device-launch-package-conformance")]
fn activation_snapshot_sha256(snapshot: &ActivationSnapshot) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.p0-device-conformance-activation-snapshot.v1\0");
    for (name, value) in [
        (b"epoch".as_slice(), snapshot.epoch.as_bytes()),
        (
            b"acknowledged_through".as_slice(),
            snapshot.acknowledged_through.to_be_bytes().as_slice(),
        ),
        (
            b"next_sequence".as_slice(),
            snapshot.next_sequence.to_be_bytes().as_slice(),
        ),
        (
            b"highest_retained_sequence".as_slice(),
            snapshot.highest_retained_sequence.to_be_bytes().as_slice(),
        ),
        (
            b"operation_epoch_blocked".as_slice(),
            [u8::from(snapshot.operation_epoch_blocked)].as_slice(),
        ),
        (
            b"operation_epoch_exhausted".as_slice(),
            [u8::from(snapshot.operation_epoch_exhausted)].as_slice(),
        ),
        (
            b"authenticated_ack_sha256".as_slice(),
            snapshot.authenticated_ack_sha256.as_bytes(),
        ),
        (
            b"authenticated_ack_chain_sha256".as_slice(),
            snapshot.authenticated_ack_chain_sha256.as_bytes(),
        ),
    ] {
        hash_activation_field(&mut hasher, name, value);
    }
    lower_hex(&hasher.finalize())
}

#[cfg(feature = "device-launch-package-conformance")]
fn hash_activation_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn sha256_hex(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(ALPHABET[(byte >> 4) as usize] as char);
        encoded.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
impl SealedSystemApiActivationExpectation {
    fn first_use_for_test(epoch: &str) -> Self {
        assert!(valid_nonzero_epoch(epoch));
        Self {
            expectation: ExternalActivationExpectation::FirstUse {
                epoch: epoch.to_string(),
            },
        }
    }

    fn restart_for_test(snapshot: ActivationSnapshot) -> Self {
        validate_activation_snapshot(&snapshot).unwrap();
        Self {
            expectation: ExternalActivationExpectation::Restart { snapshot },
        }
    }
}

#[cfg(test)]
impl SealedAccessibilityActivationExpectation {
    fn first_use_for_test(epoch: &str) -> Self {
        assert!(valid_nonzero_epoch(epoch));
        Self {
            expectation: ExternalActivationExpectation::FirstUse {
                epoch: epoch.to_string(),
            },
        }
    }

    fn restart_for_test(snapshot: ActivationSnapshot) -> Self {
        validate_activation_snapshot(&snapshot).unwrap();
        Self {
            expectation: ExternalActivationExpectation::Restart { snapshot },
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "device-launch-package-conformance")]
    use std::fs;
    #[cfg(feature = "device-launch-package-conformance")]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(feature = "device-launch-package-conformance")]
    use std::os::unix::net::UnixListener;
    use std::os::unix::net::UnixStream;
    use std::thread;

    #[cfg(feature = "device-launch-package-conformance")]
    use tempfile::TempDir;
    #[cfg(feature = "device-launch-package-conformance")]
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationProviderAttempt, DirectOperationStableSeed,
        DirectOperationToolCallAllocationRequestV3, DirectOperationToolCallDeliveryV3,
        DirectOperationToolCallEnvelopeV3, STABLE_SEED_SCHEMA, TOOL_CALL_ENVELOPE_V3_SCHEMA,
    };

    use super::*;

    const EPOCH: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_EPOCH: &str = "fedcba9876543210fedcba9876543210";
    const ACK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CHAIN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn pristine_snapshot() -> ActivationSnapshot {
        ActivationSnapshot {
            epoch: EPOCH.to_string(),
            acknowledged_through: 0,
            next_sequence: 1,
            highest_retained_sequence: 0,
            operation_epoch_blocked: false,
            operation_epoch_exhausted: false,
            authenticated_ack_sha256: ZERO_SHA256.to_string(),
            authenticated_ack_chain_sha256: ZERO_SHA256.to_string(),
        }
    }

    fn existing_snapshot() -> ActivationSnapshot {
        ActivationSnapshot {
            epoch: EPOCH.to_string(),
            acknowledged_through: 3,
            next_sequence: 6,
            highest_retained_sequence: 5,
            operation_epoch_blocked: true,
            operation_epoch_exhausted: false,
            authenticated_ack_sha256: ACK.to_string(),
            authenticated_ack_chain_sha256: CHAIN.to_string(),
        }
    }

    fn response_frame(
        magic: [u8; 8],
        status: ActivationStatus,
        snapshot: &ActivationSnapshot,
    ) -> Vec<u8> {
        let mut frame = Vec::with_capacity(ACTIVATE_RESPONSE_FRAME_BYTES);
        frame.extend_from_slice(&magic);
        frame.push(VERSION);
        frame.push(ACTIVATE_RESPONSE_OPERATION);
        frame.extend_from_slice(&(ACTIVATE_RESPONSE_PAYLOAD_BYTES as u16).to_be_bytes());
        frame.push(match status {
            ActivationStatus::Created => CREATED_STATUS,
            ActivationStatus::Existing => EXISTING_STATUS,
        });
        frame.push(u8::from(snapshot.operation_epoch_blocked));
        frame.push(u8::from(snapshot.operation_epoch_exhausted));
        frame.push(0);
        frame.extend_from_slice(snapshot.epoch.as_bytes());
        frame.extend_from_slice(&snapshot.acknowledged_through.to_be_bytes());
        frame.extend_from_slice(&snapshot.next_sequence.to_be_bytes());
        frame.extend_from_slice(&snapshot.highest_retained_sequence.to_be_bytes());
        frame.extend_from_slice(snapshot.authenticated_ack_sha256.as_bytes());
        frame.extend_from_slice(snapshot.authenticated_ack_chain_sha256.as_bytes());
        assert_eq!(frame.len(), ACTIVATE_RESPONSE_FRAME_BYTES);
        frame
    }

    #[cfg(feature = "device-launch-package-conformance")]
    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    #[cfg(feature = "device-launch-package-conformance")]
    fn conformance_binding(task_id: &str) -> DirectOperationBinding {
        let seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: task_id.to_string(),
            provider_invocation_id_sha256: digest('1'),
            provider_session_id_sha256: digest('2'),
            subject_uid: 5_901,
            subject_selinux_domain_sha256: digest('3'),
        };
        let invocation_id = seed.invocation_id().unwrap();
        let attempt = DirectOperationProviderAttempt::derive(digest('a'), 1, digest('4')).unwrap();
        let binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed: seed,
            invocation_id,
            workflow_id_sha256: digest('5'),
            agent_identity_key_sha256: digest('6'),
            agent_executable_sha256: digest('7'),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt,
        };
        binding.validate().unwrap();
        binding
    }

    #[cfg(feature = "device-launch-package-conformance")]
    fn activation_from_real_client(
        current: &crate::operation_journal::DeviceConformanceReplayState,
        binding: &DirectOperationBinding,
        status: ActivationStatus,
        role: DeviceConformanceActivationRole,
    ) -> DeviceConformanceActivation {
        let directory = TempDir::new().unwrap();
        let socket = directory.path().join("activation.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let snapshot = activation_snapshot_from_device_conformance(current).unwrap();
        let response = response_frame(SYSTEM_API_MAGIC, status, &snapshot);
        let expected_request = encode_activate_request(SYSTEM_API_MAGIC, &snapshot.epoch).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; ACTIVATE_REQUEST_FRAME_BYTES];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, expected_request);
            let mut trailing = [0_u8; 1];
            assert_eq!(stream.read(&mut trailing).unwrap(), 0);
            stream.write_all(&response).unwrap();
            stream.shutdown(Shutdown::Write).unwrap();
        });
        let binding_sha256 = binding.digest_sha256().unwrap();
        let identity = TrustedDeviceConformanceActivationIdentity {
            role,
            provider_id: &binding.stable_seed.provider_id,
            agent_id: &binding.stable_seed.agent_id,
            adapter: DirectOperationAdapter::SystemApi,
            binding,
            binding_sha256: &binding_sha256,
            invocation_id: &binding.invocation_id,
            delivery_provider_attempt_id: &binding.attempt.delivery_provider_attempt_id,
        };
        let activation = activate_system_api_for_device_conformance_with(
            current,
            None,
            &identity,
            |expectation| {
                activate_fixed_at_path(SYSTEM_API_ENDPOINT, &socket, expectation.expectation)
            },
        )
        .unwrap();
        server.join().unwrap();
        activation
    }

    #[cfg(feature = "device-launch-package-conformance")]
    fn delivery_allocation_and_envelope(
        binding: &DirectOperationBinding,
        canonical_request: &[u8],
    ) -> (
        DirectOperationToolCallDeliveryV3,
        DirectOperationToolCallAllocationRequestV3,
        DirectOperationToolCallEnvelopeV3,
    ) {
        let binding_sha256 = binding.digest_sha256().unwrap();
        let delivery = DirectOperationToolCallDeliveryV3::derive(
            binding,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
            format!("tool-call:{}", digest('d')),
            0,
        )
        .unwrap();
        let allocation = DirectOperationToolCallAllocationRequestV3::derive(
            &delivery,
            binding,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
            crate::operation_journal::Sha256Digest::of_bytes(canonical_request).to_hex(),
        )
        .unwrap();
        allocation
            .validate_for(
                &delivery,
                binding,
                &binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();
        let mut envelope = DirectOperationToolCallEnvelopeV3 {
            schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
            binding_sha256: allocation.binding_sha256.clone(),
            invocation_id: allocation.invocation_id.clone(),
            delivery_provider_attempt_id: allocation.delivery_provider_attempt_id.clone(),
            provider_id: allocation.provider_id.clone(),
            agent_id: allocation.agent_id.clone(),
            adapter: allocation.adapter,
            os_tool_call_id: allocation.os_tool_call_id.clone(),
            adapter_effect_ordinal: allocation.adapter_effect_ordinal,
            canonical_request_sha256: allocation.canonical_request_sha256.clone(),
            envelope_sha256: String::new(),
        };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        envelope
            .validate_for_allocation_request_v3(&allocation)
            .unwrap();
        (delivery, allocation, envelope)
    }

    fn assert_protocol_hold(frame: &[u8]) {
        assert!(matches!(
            decode_activation_response(SYSTEM_API_MAGIC, frame),
            Err(AndroidOperationReplayControlError::ProtocolHold(_))
        ));
    }

    #[test]
    fn fixed_dual_protocol_request_and_response_golden_vectors_match_android() {
        for (magic, socket, peer) in [
            (
                SYSTEM_API_MAGIC,
                SYSTEM_API_SOCKET,
                ExpectedBackendPeer::SystemServer,
            ),
            (
                ACCESSIBILITY_MAGIC,
                ACCESSIBILITY_SOCKET,
                ExpectedBackendPeer::AccessibilityService,
            ),
        ] {
            let request = encode_activate_request(magic, EPOCH).unwrap();
            let mut expected = Vec::new();
            expected.extend_from_slice(&magic);
            expected.extend_from_slice(&[1, 1, 0, 32]);
            expected.extend_from_slice(EPOCH.as_bytes());
            assert_eq!(request.as_slice(), expected);
            assert_eq!(request.len(), 44);

            let created = response_frame(magic, ActivationStatus::Created, &pristine_snapshot());
            let decoded = decode_activation_response(magic, &created).unwrap();
            assert_eq!(decoded.status, ActivationStatus::Created);
            assert_eq!(decoded.snapshot, pristine_snapshot());
            assert_eq!(created.len(), 200);

            let endpoint = if magic == SYSTEM_API_MAGIC {
                SYSTEM_API_ENDPOINT
            } else {
                ACCESSIBILITY_ENDPOINT
            };
            assert_eq!(endpoint.socket, socket);
            assert_eq!(endpoint.magic, magic);
            assert_eq!(endpoint.expected_peer, peer);
        }
        for invalid_epoch in [
            ZERO_EPOCH,
            "0123456789ABCDEF0123456789abcdef",
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcde",
        ] {
            assert!(matches!(
                encode_activate_request(SYSTEM_API_MAGIC, invalid_epoch),
                Err(AndroidOperationReplayControlError::RollbackHold(_))
            ));
        }

        let system_existing = response_frame(
            SYSTEM_API_MAGIC,
            ActivationStatus::Existing,
            &existing_snapshot(),
        );
        let accessibility_existing = response_frame(
            ACCESSIBILITY_MAGIC,
            ActivationStatus::Existing,
            &existing_snapshot(),
        );
        assert_eq!(
            decode_activation_response(SYSTEM_API_MAGIC, &system_existing)
                .unwrap()
                .snapshot,
            existing_snapshot()
        );
        assert_eq!(
            decode_activation_response(ACCESSIBILITY_MAGIC, &accessibility_existing)
                .unwrap()
                .snapshot,
            existing_snapshot()
        );
        assert!(decode_activation_response(ACCESSIBILITY_MAGIC, &system_existing).is_err());
        assert!(decode_activation_response(SYSTEM_API_MAGIC, &accessibility_existing).is_err());
    }

    #[test]
    fn activation_response_rejects_header_payload_and_state_tampering() {
        let pristine = response_frame(
            SYSTEM_API_MAGIC,
            ActivationStatus::Created,
            &pristine_snapshot(),
        );
        assert_protocol_hold(&pristine[..pristine.len() - 1]);
        let mut extra = pristine.clone();
        extra.push(0);
        assert_protocol_hold(&extra);

        for index in [
            0,
            8,
            9,
            10,
            11,
            HEADER_BYTES,
            HEADER_BYTES + 1,
            HEADER_BYTES + 3,
        ] {
            let mut tampered = pristine.clone();
            tampered[index] ^= 0x01;
            assert_protocol_hold(&tampered);
        }

        let mut uppercase_epoch = pristine.clone();
        uppercase_epoch[HEADER_BYTES + 4] = b'A';
        assert_protocol_hold(&uppercase_epoch);
        let mut invalid_epoch = pristine.clone();
        invalid_epoch[HEADER_BYTES + 4] = b'g';
        assert_protocol_hold(&invalid_epoch);
        let mut zero_epoch = pristine.clone();
        zero_epoch[HEADER_BYTES + 4..HEADER_BYTES + 36].fill(b'0');
        assert_protocol_hold(&zero_epoch);
        for index in [HEADER_BYTES + 1, HEADER_BYTES + 2] {
            let mut noncanonical_boolean = pristine.clone();
            noncanonical_boolean[index] = 2;
            assert_protocol_hold(&noncanonical_boolean);
        }

        for (range, value) in [(36..44, -1_i64), (44..52, 0_i64), (52..60, -1_i64)] {
            let mut tampered = pristine.clone();
            tampered[HEADER_BYTES + range.start..HEADER_BYTES + range.end]
                .copy_from_slice(&value.to_be_bytes());
            assert_protocol_hold(&tampered);
        }

        let mut nonzero_pristine_ack = pristine.clone();
        nonzero_pristine_ack[HEADER_BYTES + 60] = b'a';
        assert_protocol_hold(&nonzero_pristine_ack);
        let mut nonzero_pristine_chain = pristine.clone();
        nonzero_pristine_chain[HEADER_BYTES + 124] = b'b';
        assert_protocol_hold(&nonzero_pristine_chain);

        let existing = response_frame(
            SYSTEM_API_MAGIC,
            ActivationStatus::Existing,
            &existing_snapshot(),
        );
        let mut zero_existing_ack = existing.clone();
        zero_existing_ack[HEADER_BYTES + 60..HEADER_BYTES + 124].fill(b'0');
        assert_protocol_hold(&zero_existing_ack);
        let mut zero_existing_chain = existing.clone();
        zero_existing_chain[HEADER_BYTES + 124..HEADER_BYTES + 188].fill(b'0');
        assert_protocol_hold(&zero_existing_chain);
        let mut uppercase_digest = existing.clone();
        uppercase_digest[HEADER_BYTES + 60] = b'A';
        assert_protocol_hold(&uppercase_digest);
        let mut discontinuous = existing.clone();
        discontinuous[HEADER_BYTES + 44..HEADER_BYTES + 52].copy_from_slice(&7_i64.to_be_bytes());
        assert_protocol_hold(&discontinuous);

        let mut created_non_pristine = existing;
        created_non_pristine[HEADER_BYTES] = CREATED_STATUS;
        assert_protocol_hold(&created_non_pristine);

        let mut invalid_exhausted = pristine;
        invalid_exhausted[HEADER_BYTES + 2] = 1;
        assert_protocol_hold(&invalid_exhausted);
    }

    #[test]
    fn framing_requires_exactly_one_200_byte_response_and_peer_close() {
        for (bytes, accepted) in [
            (
                response_frame(
                    SYSTEM_API_MAGIC,
                    ActivationStatus::Created,
                    &pristine_snapshot(),
                ),
                true,
            ),
            (vec![0_u8; ACTIVATE_RESPONSE_FRAME_BYTES - 1], false),
            (vec![0_u8; ACTIVATE_RESPONSE_FRAME_BYTES + 1], false),
        ] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let writer = thread::spawn(move || {
                server.write_all(&bytes).unwrap();
            });
            let result = read_exact_activation_response(&mut client);
            writer.join().unwrap();
            assert_eq!(result.is_ok(), accepted);
        }
    }

    #[test]
    fn first_use_and_restart_are_sealed_exact_and_never_repaired() {
        let created = decode_activation_response(
            SYSTEM_API_MAGIC,
            &response_frame(
                SYSTEM_API_MAGIC,
                ActivationStatus::Created,
                &pristine_snapshot(),
            ),
        )
        .unwrap();
        let verified = reconcile_external_expectation(
            VerifiedEndpoint::SystemApi,
            SealedSystemApiActivationExpectation::first_use_for_test(EPOCH).expectation,
            created.clone(),
        )
        .unwrap();
        assert_eq!(verified.status, ActivationStatus::Created);
        assert_eq!(verified.snapshot, pristine_snapshot());

        assert!(matches!(
            reconcile_external_expectation(
                VerifiedEndpoint::SystemApi,
                SealedSystemApiActivationExpectation::first_use_for_test(OTHER_EPOCH).expectation,
                created,
            ),
            Err(AndroidOperationReplayControlError::RollbackHold(_))
        ));

        let existing = decode_activation_response(
            ACCESSIBILITY_MAGIC,
            &response_frame(
                ACCESSIBILITY_MAGIC,
                ActivationStatus::Existing,
                &existing_snapshot(),
            ),
        )
        .unwrap();
        let verified = reconcile_external_expectation(
            VerifiedEndpoint::Accessibility,
            SealedAccessibilityActivationExpectation::restart_for_test(existing_snapshot())
                .expectation,
            existing.clone(),
        )
        .unwrap();
        assert_eq!(verified.status, ActivationStatus::Existing);
        assert_eq!(verified.snapshot, existing_snapshot());

        assert!(matches!(
            reconcile_external_expectation(
                VerifiedEndpoint::Accessibility,
                SealedAccessibilityActivationExpectation::first_use_for_test(EPOCH).expectation,
                existing.clone(),
            ),
            Err(AndroidOperationReplayControlError::RollbackHold(_))
        ));

        let mut mismatches = Vec::new();
        let mut epoch = existing_snapshot();
        epoch.epoch = OTHER_EPOCH.to_string();
        mismatches.push(epoch);
        let mut watermark = existing_snapshot();
        watermark.acknowledged_through = 2;
        mismatches.push(watermark);
        let mut retained = existing_snapshot();
        retained.highest_retained_sequence = 6;
        retained.next_sequence = 7;
        mismatches.push(retained);
        let mut blocked = existing_snapshot();
        blocked.operation_epoch_blocked = false;
        mismatches.push(blocked);
        let mut ack = existing_snapshot();
        ack.authenticated_ack_sha256 = "c".repeat(DIGEST_BYTES);
        mismatches.push(ack);
        let mut chain = existing_snapshot();
        chain.authenticated_ack_chain_sha256 = "d".repeat(DIGEST_BYTES);
        mismatches.push(chain);
        mismatches.push(ActivationSnapshot {
            epoch: EPOCH.to_string(),
            acknowledged_through: i64::MAX,
            next_sequence: i64::MAX,
            highest_retained_sequence: 0,
            operation_epoch_blocked: true,
            operation_epoch_exhausted: true,
            authenticated_ack_sha256: ACK.to_string(),
            authenticated_ack_chain_sha256: CHAIN.to_string(),
        });

        for mismatch in mismatches {
            assert!(matches!(
                reconcile_external_expectation(
                    VerifiedEndpoint::Accessibility,
                    SealedAccessibilityActivationExpectation::restart_for_test(mismatch)
                        .expectation,
                    existing.clone(),
                ),
                Err(AndroidOperationReplayControlError::RollbackHold(_))
            ));
        }

        assert!(matches!(
            reconcile_external_expectation(
                VerifiedEndpoint::Accessibility,
                SealedAccessibilityActivationExpectation::restart_for_test(existing_snapshot())
                    .expectation,
                ObservedActivation {
                    status: ActivationStatus::Created,
                    snapshot: pristine_snapshot(),
                },
            ),
            Err(AndroidOperationReplayControlError::RollbackHold(_))
        ));
    }

    #[test]
    #[cfg(feature = "device-launch-package-conformance")]
    fn android_ack_response_loss_restart_accepts_only_exact_post_ack_state() {
        let before_ack = ActivationSnapshot {
            epoch: EPOCH.to_string(),
            acknowledged_through: 0,
            next_sequence: 2,
            highest_retained_sequence: 1,
            operation_epoch_blocked: false,
            operation_epoch_exhausted: false,
            authenticated_ack_sha256: ZERO_SHA256.to_string(),
            authenticated_ack_chain_sha256: ZERO_SHA256.to_string(),
        };
        let after_ack = ActivationSnapshot {
            epoch: EPOCH.to_string(),
            acknowledged_through: 1,
            next_sequence: 2,
            highest_retained_sequence: 0,
            operation_epoch_blocked: false,
            operation_epoch_exhausted: false,
            authenticated_ack_sha256: ACK.to_string(),
            authenticated_ack_chain_sha256: CHAIN.to_string(),
        };
        validate_activation_snapshot(&before_ack).unwrap();
        validate_activation_snapshot(&after_ack).unwrap();

        // If the ACK was not applied, restart may retry from the exact durable
        // terminal state. If Android applied it but its echo was lost, restart
        // may instead observe only the exact derived post-ACK state.
        for observed in [before_ack.clone(), after_ack.clone()] {
            reconcile_external_expectation(
                VerifiedEndpoint::SystemApi,
                ExternalActivationExpectation::ConformanceExact {
                    current: before_ack.clone(),
                    after_pending_ack: Some(after_ack.clone()),
                },
                ObservedActivation {
                    status: ActivationStatus::Existing,
                    snapshot: observed,
                },
            )
            .unwrap();
        }

        // Without a pending host ACK, an advanced Android watermark is never
        // adopted from the device alone.
        assert!(matches!(
            reconcile_external_expectation(
                VerifiedEndpoint::SystemApi,
                ExternalActivationExpectation::ConformanceExact {
                    current: before_ack.clone(),
                    after_pending_ack: None,
                },
                ObservedActivation {
                    status: ActivationStatus::Existing,
                    snapshot: after_ack.clone(),
                },
            ),
            Err(AndroidOperationReplayControlError::RollbackHold(_))
        ));

        let mut drifted = after_ack.clone();
        drifted.next_sequence += 1;
        assert!(matches!(
            reconcile_external_expectation(
                VerifiedEndpoint::SystemApi,
                ExternalActivationExpectation::ConformanceExact {
                    current: before_ack,
                    after_pending_ack: Some(after_ack),
                },
                ObservedActivation {
                    status: ActivationStatus::Existing,
                    snapshot: drifted,
                },
            ),
            Err(AndroidOperationReplayControlError::RollbackHold(_))
        ));
    }

    #[test]
    #[cfg(feature = "device-launch-package-conformance")]
    fn real_activate_client_mints_one_exact_journal_prepared_authority() {
        let directory = TempDir::new().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let binding = conformance_binding("task-p0-activate-epoch-bridge");
        let journal_path = directory.path().join("operations.json");
        let mut journal =
            crate::operation_journal::OperationJournal::open_device_conformance_for_test(
                &journal_path,
                &binding,
            )
            .unwrap();
        let current = journal.device_conformance_replay_state().unwrap();

        let created = activation_from_real_client(
            &current,
            &binding,
            ActivationStatus::Created,
            DeviceConformanceActivationRole::AdapterEffect,
        );
        let existing = activation_from_real_client(
            &current,
            &binding,
            ActivationStatus::Existing,
            DeviceConformanceActivationRole::AdapterEffect,
        );
        // CREATED and EXISTING are distinct exact wire responses, while both
        // prove the same immutable epoch lineage for byte-identical PREPARED
        // recovery.
        assert_eq!(
            created.operation_epoch_authority_sha256_for_test(),
            existing.operation_epoch_authority_sha256_for_test()
        );
        assert_ne!(
            created.activation_exchange_sha256_for_test(),
            existing.activation_exchange_sha256_for_test()
        );
        let expected_authority = created.operation_epoch_authority_sha256_for_test();
        journal
            .install_device_conformance_epoch_authority(created)
            .unwrap();

        let canonical_request =
            br#"{"action":"launch_package","package":"com.android.settings","user":0}"#;
        let (_delivery, _allocation, envelope) =
            delivery_allocation_and_envelope(&binding, canonical_request);
        let prepared = journal
            .begin_effect_with_identity(
                &envelope.os_tool_call_id,
                envelope.adapter_effect_ordinal,
                canonical_request,
            )
            .unwrap()
            .into_prepared();
        let acknowledgement = journal
            .prepared_transport_ack(&envelope, &prepared)
            .unwrap();
        assert_eq!(
            acknowledgement.operation_epoch_authority_sha256,
            expected_authority
        );
        acknowledgement.validate_for_envelope(&envelope).unwrap();

        // A conformance handle without ACTIVATE authority cannot even write a
        // PREPARED record. The journal bytes remain unchanged.
        let missing_path = directory.path().join("missing-authority.json");
        let mut missing =
            crate::operation_journal::OperationJournal::open_device_conformance_for_test(
                &missing_path,
                &binding,
            )
            .unwrap();
        let before_missing = fs::read(&missing_path).unwrap();
        let (_delivery, _allocation, missing_envelope) =
            delivery_allocation_and_envelope(&binding, canonical_request);
        assert!(matches!(
            missing.begin_effect_with_identity(
                &missing_envelope.os_tool_call_id,
                missing_envelope.adapter_effect_ordinal,
                canonical_request,
            ),
            Err(crate::operation_journal::OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)
        ));
        assert_eq!(fs::read(&missing_path).unwrap(), before_missing);

        // An otherwise genuine ACTIVATE result for another current epoch is
        // move-only but not transferable. Installation fails before any
        // PREPARED mutation on the drifted journal.
        let source_path = directory.path().join("authority-source.json");
        let mut source =
            crate::operation_journal::OperationJournal::open_device_conformance_for_test(
                &source_path,
                &binding,
            )
            .unwrap();
        let source_current = source.device_conformance_replay_state().unwrap();
        let drifted_authority = activation_from_real_client(
            &source_current,
            &binding,
            ActivationStatus::Created,
            DeviceConformanceActivationRole::AdapterEffect,
        );
        let drifted_path = directory.path().join("different-current-epoch.json");
        let mut drifted =
            crate::operation_journal::OperationJournal::open_device_conformance_for_test(
                &drifted_path,
                &binding,
            )
            .unwrap();
        assert_ne!(
            source_current.epoch,
            drifted.device_conformance_replay_state().unwrap().epoch
        );
        let before_drift = fs::read(&drifted_path).unwrap();
        assert!(matches!(
            drifted.install_device_conformance_epoch_authority(drifted_authority),
            Err(crate::operation_journal::OperationJournalError::EvidenceMismatch(_))
        ));
        assert_eq!(fs::read(&drifted_path).unwrap(), before_drift);

        // Replay-sync receives the same exact client result for response-loss
        // recovery, but that role cannot be promoted into adapter effect
        // authority.
        let replay_role_path = directory.path().join("replay-role.json");
        let mut replay_role =
            crate::operation_journal::OperationJournal::open_device_conformance_for_test(
                &replay_role_path,
                &binding,
            )
            .unwrap();
        let replay_current = replay_role.device_conformance_replay_state().unwrap();
        let replay_activation = activation_from_real_client(
            &replay_current,
            &binding,
            ActivationStatus::Created,
            DeviceConformanceActivationRole::ReplaySync,
        );
        let before_replay_role = fs::read(&replay_role_path).unwrap();
        assert!(matches!(
            replay_role.install_device_conformance_epoch_authority(replay_activation),
            Err(crate::operation_journal::OperationJournalError::EvidenceMismatch(_))
        ));
        assert_eq!(fs::read(&replay_role_path).unwrap(), before_replay_role);
    }

    #[test]
    fn production_surface_is_activation_only_path_closed_and_unwired() {
        let source = include_str!("android_operation_replay_control.rs");
        let crate_visibility = ["pub", "(crate)"].concat();
        let system_api_signature =
            [crate_visibility.as_str(), " fn activate_", "system_api("].concat();
        let accessibility_signature =
            [crate_visibility.as_str(), " fn activate_", "accessibility("].concat();
        let system_api_socket = ["@trillionnium_system_api_", "replay_control"].concat();
        let accessibility_socket = ["@trillionnium_accessibility_", "replay_control"].concat();
        let crate_function = ["pub(crate)", " fn "].concat();
        let peer_verifier = ["uds::verify_", "connected_peer"].concat();
        let conformance_constructor = [
            crate_visibility.as_str(),
            " fn activate_system_api_for_device_conformance(",
        ]
        .concat();
        let conformance_replay_constructor = [
            crate_visibility.as_str(),
            " fn activate_system_api_for_device_conformance_replay_sync(",
        ]
        .concat();
        let conformance_feature = ["feature = ", "\"device-launch-package-conformance\""].concat();
        assert_eq!(source.matches(&system_api_signature).count(), 1);
        assert_eq!(source.matches(&accessibility_signature).count(), 1);
        assert_eq!(source.matches(&system_api_socket).count(), 1);
        assert_eq!(source.matches(&accessibility_socket).count(), 1);
        assert_eq!(source.matches(&crate_function).count(), 6);
        assert_eq!(source.matches(&conformance_constructor).count(), 1);
        assert_eq!(source.matches(&conformance_replay_constructor).count(), 1);
        assert_eq!(source.matches(&conformance_feature).count(), 29);
        assert_eq!(source.matches(&peer_verifier).count(), 1);
        assert!(!source.contains(&["OP_", "ACK"].concat()));
        assert!(!source.contains(&["0x", "82"].concat()));
        assert!(!source.contains(&["std::", "env::"].concat()));
        assert!(!source.contains(&["env::", "args"].concat()));
        assert!(!source.contains(&["runtime_", "wired"].concat()));
        assert!(!source.contains(&[crate_visibility.as_str(), " fn ", "connect"].concat()));

        let system_first = SealedSystemApiActivationExpectation::first_use_for_test(EPOCH);
        let accessibility_first =
            SealedAccessibilityActivationExpectation::first_use_for_test(EPOCH);
        assert_eq!(system_first.expectation.epoch(), EPOCH);
        assert_eq!(accessibility_first.expectation.epoch(), EPOCH);
        let system_restart =
            SealedSystemApiActivationExpectation::restart_for_test(existing_snapshot());
        let accessibility_restart =
            SealedAccessibilityActivationExpectation::restart_for_test(existing_snapshot());
        assert_eq!(system_restart.expectation.epoch(), EPOCH);
        assert_eq!(accessibility_restart.expectation.epoch(), EPOCH);
    }
}
