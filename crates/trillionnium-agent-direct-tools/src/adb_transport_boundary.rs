//! OS-owned boundary for the typed `android.adb.*` contract.
//!
//! This module is deliberately one layer above [`super::SelfAdbdSession`].
//! Wire correctness does not confer authority: a broker must first validate a
//! model request against an OS-selected device binding, a finite key-generation
//! policy, and an expiring permission tier.  Only the broker can construct an
//! [`AdmittedAdbRequest`], and the transport trait accepts that type rather than
//! raw JSON or model arguments.
//!
//! The implementation is source-only.  The in-memory transport and the UDS
//! frame codec are test contracts; no listener, socket connector, adb process,
//! fastboot path, private-key byte container, or product transport is defined
//! here.  [`ProductionAdbTransport::new`] always returns a fail-closed HOLD.

use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use super::{
    AdbKeyCustody, AdbTransportRequest, AndroidAdbContractError, AndroidAdbOperation,
    AndroidAdbPermissionGrant, AndroidAdbTier, DeviceBinding, KeyRotationPolicy,
    MAX_ANDROID_ADB_REQUEST_BYTES, parse_android_adb_model_request,
};

/// Stable boundary schema.  This is distinct from both the low-level ADB wire
/// schema and the `rootlinux.exec.*` operation namespace.
pub const ADB_TRANSPORT_BOUNDARY_SCHEMA: &str = "android.adb.os-owned-boundary.v1";
pub const ADB_BROKER_UDS_SCHEMA: &str = "android.adb.os-owned-uds.v1";

/// Production transport is intentionally unavailable until OS enrollment,
/// same-device routing, measured adapter custody, and durable replay authority
/// are wired.  Keeping the status string in source gives release audits one
/// stable marker to search for.
pub const ADB_PRODUCTION_TRANSPORT_STATUS: &str =
    "HOLD: production Android ADB transport/key custody is not wired";

pub const MAX_ADB_BROKER_FRAME_BYTES: usize = 128 * 1024;
pub const MAX_ADB_BROKER_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_ADB_BROKER_LEDGER_ENTRIES: usize = 128;
const MAX_ADB_BROKER_ERROR_CODE_BYTES: usize = 128;
const ADMISSION_DIGEST_DOMAIN: &[u8] = b"trillionnium.android-adb-admission.v1\0";

pub type AdbTransportBoundaryResult<T> = std::result::Result<T, AdbTransportBoundaryError>;

/// Errors at the OS-owned boundary.  A malformed model request is kept
/// distinguishable from a transport HOLD so callers cannot accidentally turn
/// an unavailable production backend into a retryable model error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdbTransportBoundaryError {
    #[error(transparent)]
    Contract(#[from] AndroidAdbContractError),
    #[error("ADB admission denied: {0}")]
    AdmissionDenied(&'static str),
    #[error("ADB request id conflicts with a prior request")]
    RequestIdConflict,
    #[error("ADB broker replay ledger is at its bounded capacity")]
    LedgerCapacityExceeded,
    #[error("ADB transport is unavailable: {0}")]
    TransportUnavailable(&'static str),
    #[error("ADB transport timed out: {0}")]
    TransportTimedOut(&'static str),
    #[error("ADB transport protocol failure: {0}")]
    TransportProtocol(&'static str),
    #[error("ADB transport outcome is indeterminate: {0}")]
    Indeterminate(&'static str),
    #[error("ADB transport output exceeds the bounded result limit")]
    OutputTooLarge,
    #[error("ADB broker frame has length {length}, maximum is {maximum}")]
    FrameTooLarge { length: usize, maximum: usize },
    #[error("ADB broker frame is malformed: {0}")]
    MalformedFrame(&'static str),
    #[error("ADB broker frame JSON is invalid: {0}")]
    FrameJson(String),
    #[error("ADB broker error code is invalid")]
    InvalidErrorCode,
}

/// A transport outcome is deliberately narrower than an arbitrary backend
/// JSON object.  `stdout` and `stderr` are bounded binary fields; the broker
/// verifies the request identity and operation before returning this value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdbTransportDisposition {
    Completed,
    Rejected,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdbTransportResult {
    pub schema: String,
    pub request_id: String,
    pub operation: AndroidAdbOperation,
    pub disposition: AdbTransportDisposition,
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub error_code: Option<String>,
}

impl AdbTransportResult {
    fn validate_for(&self, request: &AdmittedAdbRequest) -> AdbTransportBoundaryResult<()> {
        if self.schema != ADB_TRANSPORT_BOUNDARY_SCHEMA
            || self.request_id != request.request_id()
            || self.operation != request.operation()
        {
            return Err(AdbTransportBoundaryError::TransportProtocol(
                "outcome identity does not match the admitted request",
            ));
        }
        if self.stdout.len() > MAX_ADB_BROKER_OUTPUT_BYTES
            || self.stderr.len() > MAX_ADB_BROKER_OUTPUT_BYTES
            || self
                .stdout
                .len()
                .checked_add(self.stderr.len())
                .is_none_or(|total| total > MAX_ADB_BROKER_OUTPUT_BYTES)
        {
            return Err(AdbTransportBoundaryError::OutputTooLarge);
        }
        match self.disposition {
            AdbTransportDisposition::Completed => {
                if self.error_code.is_some() {
                    return Err(AdbTransportBoundaryError::TransportProtocol(
                        "completed outcome cannot carry an error code",
                    ));
                }
                // A transport invocation may have produced an effect even
                // when its result body is malformed.  Requiring an explicit
                // process status keeps a partial response from being
                // mistaken for a terminal success (and lets a production
                // broker convert an ambiguous call into an indeterminate
                // HOLD instead of replaying it).
                if self.exit_code.is_none() {
                    return Err(AdbTransportBoundaryError::TransportProtocol(
                        "completed outcome must carry an exit code",
                    ));
                }
            }
            AdbTransportDisposition::Rejected | AdbTransportDisposition::Indeterminate => {
                if !self.stdout.is_empty() || !self.stderr.is_empty() || self.exit_code.is_some() {
                    return Err(AdbTransportBoundaryError::TransportProtocol(
                        "non-completed outcome cannot carry process output",
                    ));
                }
                let Some(code) = self.error_code.as_deref() else {
                    return Err(AdbTransportBoundaryError::InvalidErrorCode);
                };
                validate_error_code(code)?;
            }
        }
        Ok(())
    }

    fn indeterminate(request: &AdmittedAdbRequest, code: &'static str) -> Self {
        Self {
            schema: ADB_TRANSPORT_BOUNDARY_SCHEMA.to_string(),
            request_id: request.request_id().to_string(),
            operation: request.operation(),
            disposition: AdbTransportDisposition::Indeterminate,
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            error_code: Some(code.to_string()),
        }
    }
}

/// A request after OS admission.  Fields are private so a model/provider can
/// never mint one by deserializing JSON.  It carries only opaque binding and
/// generation facts; key custody itself is intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdmittedAdbRequest {
    request: AdbTransportRequest,
    binding_generation: u64,
    key_generation: u64,
    tier: AndroidAdbTier,
    boot: u64,
    admission_digest: String,
}

impl AdmittedAdbRequest {
    fn from_admission(
        request: AdbTransportRequest,
        binding: &DeviceBinding,
        grant: AndroidAdbPermissionGrant,
        boot: u64,
    ) -> AdbTransportBoundaryResult<Self> {
        let admission_digest = admission_digest(&request, binding, grant.tier, boot)?;
        Ok(Self {
            request,
            binding_generation: binding.binding_generation,
            key_generation: binding.key_generation,
            tier: grant.tier,
            boot,
            admission_digest,
        })
    }

    #[must_use]
    pub fn request(&self) -> &AdbTransportRequest {
        &self.request
    }

    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request.request_id
    }

    #[must_use]
    pub const fn operation(&self) -> AndroidAdbOperation {
        self.request.operation
    }

    #[must_use]
    pub fn device_binding(&self) -> &str {
        &self.request.device_binding
    }

    #[must_use]
    pub const fn binding_generation(&self) -> u64 {
        self.binding_generation
    }

    #[must_use]
    pub const fn key_generation(&self) -> u64 {
        self.key_generation
    }

    #[must_use]
    pub const fn tier(&self) -> AndroidAdbTier {
        self.tier
    }

    #[must_use]
    pub const fn boot(&self) -> u64 {
        self.boot
    }

    #[must_use]
    pub fn admission_digest(&self) -> &str {
        &self.admission_digest
    }
}

/// OS-owned policy snapshot used to admit model requests.  It is not
/// serializable and has no model-facing constructor for key bytes: custody is
/// represented by the pre-existing opaque [`AdbKeyCustody`] metadata only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdbAdmissionPolicy {
    binding: DeviceBinding,
    rotation: KeyRotationPolicy,
    grant: AndroidAdbPermissionGrant,
    boot: u64,
}

impl AdbAdmissionPolicy {
    pub fn new(
        binding: DeviceBinding,
        rotation: KeyRotationPolicy,
        grant: AndroidAdbPermissionGrant,
        boot: u64,
    ) -> AdbTransportBoundaryResult<Self> {
        if boot == 0 {
            return Err(AdbTransportBoundaryError::AdmissionDenied(
                "boot generation must be non-zero",
            ));
        }
        if !matches!(rotation.custody, AdbKeyCustody::OsOwned { .. }) {
            return Err(AdbTransportBoundaryError::AdmissionDenied(
                "OS-owned ADB key custody is unavailable",
            ));
        }
        binding.validate_key_generation(&rotation, boot)?;
        grant.validate()?;
        // A confirmation-required grant cannot be consumed by this source
        // seam because no issuer receipt is present.  Denying here prevents a
        // future caller from accidentally treating the boolean as a token.
        if grant.user_confirmation_required {
            return Err(AdbTransportBoundaryError::AdmissionDenied(
                "user confirmation receipt is not wired",
            ));
        }
        Ok(Self {
            binding,
            rotation,
            grant,
            boot,
        })
    }

    #[must_use]
    pub fn binding(&self) -> &DeviceBinding {
        &self.binding
    }

    #[must_use]
    pub fn rotation(&self) -> &KeyRotationPolicy {
        &self.rotation
    }

    #[must_use]
    pub const fn grant(&self) -> AndroidAdbPermissionGrant {
        self.grant
    }

    #[must_use]
    pub const fn boot(&self) -> u64 {
        self.boot
    }

    /// Admit one already-parsed model request.  The request is checked again
    /// here rather than trusting an upstream parser, then bound to the exact
    /// OS-selected device and current key generation.
    pub fn admit(
        &self,
        request: AdbTransportRequest,
    ) -> AdbTransportBoundaryResult<AdmittedAdbRequest> {
        request.validate_admission(&self.binding, &self.rotation, self.grant, self.boot)?;
        AdmittedAdbRequest::from_admission(request, &self.binding, self.grant, self.boot)
    }

    /// Parse and admit model bytes in one fail-closed operation.  The parser
    /// recursively rejects private-key material before typed deserialization.
    pub fn admit_json(&self, bytes: &[u8]) -> AdbTransportBoundaryResult<AdmittedAdbRequest> {
        if bytes.len() > MAX_ANDROID_ADB_REQUEST_BYTES {
            return Err(AdbTransportBoundaryError::Contract(
                AndroidAdbContractError::RequestTooLarge {
                    maximum: MAX_ANDROID_ADB_REQUEST_BYTES,
                },
            ));
        }
        self.admit(parse_android_adb_model_request(bytes)?)
    }

    /// Rotate to a strictly newer OS-held key generation.  The old generation
    /// is retained only for the bounded overlap accepted by
    /// [`KeyRotationPolicy::rotate`].  Binding generation advances together,
    /// preventing an old admission record from being mistaken for the new
    /// device binding.
    pub fn rotate_key_generation(
        &mut self,
        next_generation: u64,
        overlap_until_boot: Option<u64>,
        custody: AdbKeyCustody,
    ) -> AdbTransportBoundaryResult<()> {
        // `AdbAdmissionPolicy::new` applies this check at initial enrollment,
        // but rotation is a second authority transition and must not be able
        // to smuggle an external signer (or unavailable custody) into an
        // already-live broker.  Without this guard,
        // `binding.validate_key_generation` would continue to accept the new
        // generation even though no OS-held ADB key exists.
        if !matches!(custody, AdbKeyCustody::OsOwned { .. }) {
            return Err(AdbTransportBoundaryError::AdmissionDenied(
                "OS-owned ADB key custody is unavailable",
            ));
        }
        let next_rotation = self
            .rotation
            .rotate(next_generation, overlap_until_boot, custody)?;
        let next_binding_generation = self.binding.binding_generation.checked_add(1).ok_or(
            AdbTransportBoundaryError::AdmissionDenied("device binding generation exhausted"),
        )?;
        let mut next_binding = self.binding.clone();
        next_binding.binding_generation = next_binding_generation;
        next_binding.key_generation = next_generation;
        next_binding.validate_key_generation(&next_rotation, self.boot)?;
        self.binding = next_binding;
        self.rotation = next_rotation;
        Ok(())
    }
}

/// The only product-facing transport seam in this source slice.  An
/// implementation receives an admitted request, never model JSON, a serial,
/// a host/port selector, or key material.  A real implementation is still
/// absent; tests provide an in-memory implementation below.
pub trait OsOwnedAdbTransport {
    fn execute(
        &mut self,
        request: &AdmittedAdbRequest,
    ) -> AdbTransportBoundaryResult<AdbTransportResult>;
}

/// Short alias for callers that name the boundary by its capability rather
/// than its ownership model.
pub trait AdbTransport: OsOwnedAdbTransport {}

impl<T: OsOwnedAdbTransport + ?Sized> AdbTransport for T {}

/// Broker result distinguishes a first execution from an in-memory exact
/// replay.  The replay ledger is intentionally not durable and therefore does
/// not satisfy the production exactly-once/reboot gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdbBrokerDispatch {
    Executed(AdbTransportResult),
    Replayed(AdbTransportResult),
}

#[derive(Debug)]
struct LedgerEntry {
    request_digest: String,
    result: AdbTransportResult,
}

/// Typed request broker.  It owns admission and duplicate handling; the
/// transport implementation cannot bypass those checks because `execute`
/// accepts only [`AdmittedAdbRequest`].
#[derive(Debug)]
pub struct AdbTransportBroker<T> {
    policy: AdbAdmissionPolicy,
    transport: T,
    ledger: HashMap<String, LedgerEntry>,
}

impl<T> AdbTransportBroker<T>
where
    T: OsOwnedAdbTransport,
{
    pub fn new(policy: AdbAdmissionPolicy, transport: T) -> Self {
        Self {
            policy,
            transport,
            ledger: HashMap::new(),
        }
    }

    #[must_use]
    pub fn policy(&self) -> &AdbAdmissionPolicy {
        &self.policy
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    #[must_use]
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[must_use]
    pub fn ledger_len(&self) -> usize {
        self.ledger.len()
    }

    pub fn admit(
        &self,
        request: AdbTransportRequest,
    ) -> AdbTransportBoundaryResult<AdmittedAdbRequest> {
        self.policy.admit(request)
    }

    pub fn admit_json(&self, bytes: &[u8]) -> AdbTransportBoundaryResult<AdmittedAdbRequest> {
        self.policy.admit_json(bytes)
    }

    pub fn dispatch(
        &mut self,
        request: AdbTransportRequest,
    ) -> AdbTransportBoundaryResult<AdbBrokerDispatch> {
        let admitted = self.policy.admit(request)?;
        let request_id = admitted.request_id().to_string();
        let digest = admitted.admission_digest().to_string();
        if let Some(previous) = self.ledger.get(&request_id) {
            if previous.request_digest != digest {
                return Err(AdbTransportBoundaryError::RequestIdConflict);
            }
            return Ok(AdbBrokerDispatch::Replayed(previous.result.clone()));
        }
        if self.ledger.len() >= MAX_ADB_BROKER_LEDGER_ENTRIES {
            return Err(AdbTransportBoundaryError::LedgerCapacityExceeded);
        }

        let result = match self.transport.execute(&admitted) {
            Ok(result) => result,
            Err(AdbTransportBoundaryError::Indeterminate(code)) => {
                AdbTransportResult::indeterminate(&admitted, code)
            }
            Err(error) => return Err(error),
        };
        result.validate_for(&admitted)?;
        self.ledger.insert(
            request_id,
            LedgerEntry {
                request_digest: digest,
                result: result.clone(),
            },
        );
        Ok(AdbBrokerDispatch::Executed(result))
    }

    pub fn dispatch_json(&mut self, bytes: &[u8]) -> AdbTransportBoundaryResult<AdbBrokerDispatch> {
        let request = parse_android_adb_model_request(bytes)?;
        self.dispatch(request)
    }
}

/// A source-only production placeholder.  It deliberately has no fields and
/// no transport constructor.  The `new` method exists so callers can make the
/// HOLD explicit instead of accidentally falling back to a host `adb` binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductionAdbTransport;

impl ProductionAdbTransport {
    pub fn new() -> AdbTransportBoundaryResult<Self> {
        Err(AdbTransportBoundaryError::TransportUnavailable(
            ADB_PRODUCTION_TRANSPORT_STATUS,
        ))
    }
}

/// Untrusted wire envelope used by the source-only UDS contract.  A receiver
/// must call [`AdbBrokerRequestFrame::verify_against`] with a locally admitted
/// request before dispatch; serialized generation/tier fields are evidence,
/// not authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdbBrokerRequestFrame {
    pub schema: String,
    pub request: AdbTransportRequest,
    pub binding_generation: u64,
    pub key_generation: u64,
    pub tier: AndroidAdbTier,
    pub boot: u64,
    pub admission_digest: String,
}

impl AdbBrokerRequestFrame {
    #[must_use]
    pub fn from_admitted(request: &AdmittedAdbRequest) -> Self {
        Self {
            schema: ADB_BROKER_UDS_SCHEMA.to_string(),
            request: request.request.clone(),
            binding_generation: request.binding_generation,
            key_generation: request.key_generation,
            tier: request.tier,
            boot: request.boot,
            admission_digest: request.admission_digest.clone(),
        }
    }

    pub fn verify_against(&self, admitted: &AdmittedAdbRequest) -> AdbTransportBoundaryResult<()> {
        let expected = Self::from_admitted(admitted);
        if self != &expected {
            return Err(AdbTransportBoundaryError::TransportProtocol(
                "UDS request frame does not match local OS admission",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdbBrokerResponseFrame {
    pub schema: String,
    pub result: AdbTransportResult,
}

impl AdbBrokerResponseFrame {
    pub fn from_result(result: &AdbTransportResult) -> Self {
        Self {
            schema: ADB_BROKER_UDS_SCHEMA.to_string(),
            result: result.clone(),
        }
    }

    pub fn validate_for(&self, admitted: &AdmittedAdbRequest) -> AdbTransportBoundaryResult<()> {
        if self.schema != ADB_BROKER_UDS_SCHEMA {
            return Err(AdbTransportBoundaryError::MalformedFrame(
                "unexpected UDS response schema",
            ));
        }
        self.result.validate_for(admitted)
    }
}

/// Encode one bounded length-prefixed UDS contract frame.  This is a codec,
/// not a socket operation; callers still need an OS-owned authenticated
/// listener before a product implementation could use it.
pub fn encode_uds_frame<T: Serialize>(value: &T) -> AdbTransportBoundaryResult<Vec<u8>> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| AdbTransportBoundaryError::FrameJson(error.to_string()))?;
    if payload.is_empty() {
        return Err(AdbTransportBoundaryError::MalformedFrame(
            "UDS payload cannot be empty",
        ));
    }
    if payload.len() > MAX_ADB_BROKER_FRAME_BYTES {
        return Err(AdbTransportBoundaryError::FrameTooLarge {
            length: payload.len(),
            maximum: MAX_ADB_BROKER_FRAME_BYTES,
        });
    }
    let length =
        u32::try_from(payload.len()).map_err(|_| AdbTransportBoundaryError::FrameTooLarge {
            length: payload.len(),
            maximum: MAX_ADB_BROKER_FRAME_BYTES,
        })?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode exactly one bounded length-prefixed UDS contract frame.  Trailing
/// bytes are rejected so a peer cannot smuggle a second request into one
/// admission/response exchange.
pub fn decode_uds_frame<T: DeserializeOwned>(frame: &[u8]) -> AdbTransportBoundaryResult<T> {
    if frame.len() < 4 {
        return Err(AdbTransportBoundaryError::MalformedFrame(
            "UDS frame is shorter than its length prefix",
        ));
    }
    let length = u32::from_be_bytes(frame[..4].try_into().expect("slice length checked")) as usize;
    if length == 0 || length > MAX_ADB_BROKER_FRAME_BYTES {
        return Err(AdbTransportBoundaryError::FrameTooLarge {
            length,
            maximum: MAX_ADB_BROKER_FRAME_BYTES,
        });
    }
    if frame.len() != 4 + length {
        return Err(AdbTransportBoundaryError::MalformedFrame(
            "UDS frame has trailing or truncated bytes",
        ));
    }
    serde_json::from_slice(&frame[4..])
        .map_err(|error| AdbTransportBoundaryError::FrameJson(error.to_string()))
}

fn admission_digest(
    request: &AdbTransportRequest,
    binding: &DeviceBinding,
    tier: AndroidAdbTier,
    boot: u64,
) -> AdbTransportBoundaryResult<String> {
    let request_bytes = serde_json::to_vec(request)
        .map_err(|error| AdbTransportBoundaryError::FrameJson(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(ADMISSION_DIGEST_DOMAIN);
    hash_len_prefixed(&mut hasher, &request_bytes);
    hash_len_prefixed(&mut hasher, binding.binding_id.as_bytes());
    hash_len_prefixed(&mut hasher, binding.device_identity_sha256.as_bytes());
    hash_len_prefixed(&mut hasher, binding.build_fingerprint_sha256.as_bytes());
    hash_len_prefixed(&mut hasher, binding.avb_public_key_sha256.as_bytes());
    hasher.update(binding.binding_generation.to_be_bytes());
    hasher.update(binding.key_generation.to_be_bytes());
    hasher.update([tier.rank()]);
    hasher.update(boot.to_be_bytes());
    Ok(lower_hex(&hasher.finalize()))
}

fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
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

fn validate_error_code(value: &str) -> AdbTransportBoundaryResult<()> {
    if value.is_empty()
        || value.len() > MAX_ADB_BROKER_ERROR_CODE_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(AdbTransportBoundaryError::InvalidErrorCode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    use super::super::{AndroidAdbArguments, AndroidAdbOperation};
    use super::*;

    #[derive(Debug)]
    struct MemoryAdbTransport {
        calls: usize,
        disposition: AdbTransportDisposition,
    }

    impl Default for MemoryAdbTransport {
        fn default() -> Self {
            Self {
                calls: 0,
                disposition: AdbTransportDisposition::Completed,
            }
        }
    }

    impl OsOwnedAdbTransport for MemoryAdbTransport {
        fn execute(
            &mut self,
            request: &AdmittedAdbRequest,
        ) -> AdbTransportBoundaryResult<AdbTransportResult> {
            self.calls += 1;
            Ok(AdbTransportResult {
                schema: ADB_TRANSPORT_BOUNDARY_SCHEMA.to_string(),
                request_id: request.request_id().to_string(),
                operation: request.operation(),
                disposition: self.disposition,
                exit_code: (self.disposition == AdbTransportDisposition::Completed).then_some(0),
                stdout: if self.disposition == AdbTransportDisposition::Completed {
                    b"fixture-ok".to_vec()
                } else {
                    Vec::new()
                },
                stderr: Vec::new(),
                error_code: (self.disposition != AdbTransportDisposition::Completed)
                    .then_some("fixture_outcome".to_string()),
            })
        }
    }

    struct InvalidIndeterminateTransport;

    impl OsOwnedAdbTransport for InvalidIndeterminateTransport {
        fn execute(
            &mut self,
            _request: &AdmittedAdbRequest,
        ) -> AdbTransportBoundaryResult<AdbTransportResult> {
            Err(AdbTransportBoundaryError::Indeterminate("BAD-CODE"))
        }
    }

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn custody(generation: u64) -> AdbKeyCustody {
        AdbKeyCustody::OsOwned {
            handle_id: format!("adb-key-handle-{generation}"),
            public_key_sha256: digest('a'),
            generation,
        }
    }

    fn policy(grant_tier: AndroidAdbTier) -> AdbAdmissionPolicy {
        let binding = DeviceBinding::new(
            "device-binding-1",
            digest('1'),
            digest('2'),
            digest('3'),
            1,
            1,
        )
        .unwrap();
        let rotation = KeyRotationPolicy::new(1, custody(1)).unwrap();
        AdbAdmissionPolicy::new(
            binding,
            rotation,
            AndroidAdbPermissionGrant {
                tier: grant_tier,
                expires_at_boot: Some(20),
                user_confirmation_required: false,
            },
            10,
        )
        .unwrap()
    }

    fn shell_request(id: &str) -> AdbTransportRequest {
        AdbTransportRequest::new(
            id,
            AndroidAdbOperation::Shell,
            "self",
            AndroidAdbArguments::Shell {
                argv: vec!["id".to_string()],
            },
        )
        .unwrap()
    }

    #[test]
    fn broker_admits_typed_request_and_replays_without_second_transport_call() {
        let transport = MemoryAdbTransport {
            disposition: AdbTransportDisposition::Completed,
            ..Default::default()
        };
        let mut broker = AdbTransportBroker::new(policy(AndroidAdbTier::User), transport);
        let first = broker.dispatch(shell_request("adb-request-1")).unwrap();
        let second = broker.dispatch(shell_request("adb-request-1")).unwrap();
        assert!(matches!(first, AdbBrokerDispatch::Executed(_)));
        assert!(matches!(second, AdbBrokerDispatch::Replayed(_)));
        assert_eq!(broker.transport().calls, 1);
        assert_eq!(broker.ledger_len(), 1);
    }

    #[test]
    fn broker_rejects_request_id_reuse_with_changed_typed_arguments() {
        let transport = MemoryAdbTransport {
            disposition: AdbTransportDisposition::Completed,
            ..Default::default()
        };
        let mut broker = AdbTransportBroker::new(policy(AndroidAdbTier::User), transport);
        broker.dispatch(shell_request("adb-request-1")).unwrap();
        let changed = AdbTransportRequest::new(
            "adb-request-1",
            AndroidAdbOperation::Shell,
            "self",
            AndroidAdbArguments::Shell {
                argv: vec!["getprop".to_string()],
            },
        )
        .unwrap();
        assert_eq!(
            broker.dispatch(changed).unwrap_err(),
            AdbTransportBoundaryError::RequestIdConflict
        );
        assert_eq!(broker.transport().calls, 1);
    }

    #[test]
    fn admission_enforces_tier_binding_and_confirmation_hold() {
        let read_only = policy(AndroidAdbTier::ReadOnly);
        assert!(matches!(
            read_only.admit(shell_request("adb-request-1")),
            Err(AdbTransportBoundaryError::Contract(_))
        ));

        let mut wrong_binding = shell_request("adb-request-2");
        wrong_binding.device_binding = "other-device".to_string();
        assert!(matches!(
            policy(AndroidAdbTier::User).admit(wrong_binding),
            Err(AdbTransportBoundaryError::Contract(_))
        ));

        let binding = DeviceBinding::new(
            "device-binding-1",
            digest('1'),
            digest('2'),
            digest('3'),
            1,
            1,
        )
        .unwrap();
        let rotation = KeyRotationPolicy::new(1, custody(1)).unwrap();
        assert_eq!(
            AdbAdmissionPolicy::new(
                binding,
                rotation,
                AndroidAdbPermissionGrant {
                    tier: AndroidAdbTier::User,
                    expires_at_boot: Some(20),
                    user_confirmation_required: true,
                },
                10,
            )
            .unwrap_err(),
            AdbTransportBoundaryError::AdmissionDenied("user confirmation receipt is not wired")
        );
    }

    #[test]
    fn key_rotation_advances_binding_and_rejects_old_generation_after_overlap() {
        let mut policy = policy(AndroidAdbTier::User);
        let old = policy.admit(shell_request("adb-old")).unwrap();
        assert_eq!(old.key_generation(), 1);
        policy
            .rotate_key_generation(2, Some(12), custody(2))
            .unwrap();
        assert_eq!(policy.binding().binding_generation, 2);
        assert_eq!(policy.binding().key_generation, 2);
        let current = policy.admit(shell_request("adb-current")).unwrap();
        assert_eq!(current.key_generation(), 2);
        assert_eq!(current.binding_generation(), 2);
        assert!(policy.rotation().accepts_generation(1, 12));
        assert!(!policy.rotation().accepts_generation(1, 13));
    }

    #[test]
    fn key_rotation_cannot_replace_os_owned_custody_with_external_or_unavailable() {
        let mut policy = policy(AndroidAdbTier::User);
        let external = AdbKeyCustody::ExternalSigner {
            signer_id: "external-signer-2".to_string(),
            public_key_sha256: digest('b'),
            generation: 2,
        };
        assert_eq!(
            policy.rotate_key_generation(2, Some(12), external),
            Err(AdbTransportBoundaryError::AdmissionDenied(
                "OS-owned ADB key custody is unavailable"
            ))
        );
        assert_eq!(policy.binding().key_generation, 1);
        assert_eq!(policy.rotation().current_generation, 1);
        assert_eq!(
            policy.rotate_key_generation(2, Some(12), AdbKeyCustody::Unavailable),
            Err(AdbTransportBoundaryError::AdmissionDenied(
                "OS-owned ADB key custody is unavailable"
            ))
        );
        assert_eq!(policy.binding().key_generation, 1);
    }

    #[test]
    fn completed_transport_outcome_requires_an_explicit_exit_code() {
        let policy = policy(AndroidAdbTier::User);
        let admitted = policy.admit(shell_request("adb-no-exit-code")).unwrap();
        let result = AdbTransportResult {
            schema: ADB_TRANSPORT_BOUNDARY_SCHEMA.to_string(),
            request_id: admitted.request_id().to_string(),
            operation: admitted.operation(),
            disposition: AdbTransportDisposition::Completed,
            exit_code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            error_code: None,
        };
        assert_eq!(
            result.validate_for(&admitted),
            Err(AdbTransportBoundaryError::TransportProtocol(
                "completed outcome must carry an exit code"
            ))
        );
    }

    #[test]
    fn indeterminate_transport_outcome_is_recorded_and_replayed() {
        let transport = MemoryAdbTransport {
            disposition: AdbTransportDisposition::Indeterminate,
            ..Default::default()
        };
        let mut broker = AdbTransportBroker::new(policy(AndroidAdbTier::User), transport);
        let first = broker.dispatch(shell_request("adb-indeterminate")).unwrap();
        let second = broker.dispatch(shell_request("adb-indeterminate")).unwrap();
        let AdbBrokerDispatch::Executed(result) = first else {
            panic!("first call must execute");
        };
        assert_eq!(result.disposition, AdbTransportDisposition::Indeterminate);
        assert!(matches!(second, AdbBrokerDispatch::Replayed(_)));
        assert_eq!(broker.transport().calls, 1);
    }

    #[test]
    fn invalid_indeterminate_code_is_not_committed_to_the_replay_ledger() {
        let mut broker =
            AdbTransportBroker::new(policy(AndroidAdbTier::User), InvalidIndeterminateTransport);
        assert_eq!(
            broker.dispatch(shell_request("adb-invalid-indeterminate")),
            Err(AdbTransportBoundaryError::InvalidErrorCode)
        );
        assert_eq!(broker.ledger_len(), 0);
    }

    #[test]
    fn uds_codec_requires_exact_frame_and_local_admission_match() {
        let policy = policy(AndroidAdbTier::User);
        let admitted = policy.admit(shell_request("adb-uds-1")).unwrap();
        let request_frame = AdbBrokerRequestFrame::from_admitted(&admitted);
        let encoded = encode_uds_frame(&request_frame).unwrap();
        let decoded: AdbBrokerRequestFrame = decode_uds_frame(&encoded).unwrap();
        decoded.verify_against(&admitted).unwrap();

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(matches!(
            decode_uds_frame::<AdbBrokerRequestFrame>(&trailing),
            Err(AdbTransportBoundaryError::MalformedFrame(_))
        ));

        let mut forged = decoded;
        forged.key_generation += 1;
        assert!(matches!(
            forged.verify_against(&admitted),
            Err(AdbTransportBoundaryError::TransportProtocol(_))
        ));
    }

    #[test]
    fn unix_stream_pair_exercises_only_the_source_codec_not_a_real_endpoint() {
        let policy = policy(AndroidAdbTier::User);
        let admitted = policy.admit(shell_request("adb-pair-1")).unwrap();
        let request = AdbBrokerRequestFrame::from_admitted(&admitted);
        let response = AdbBrokerResponseFrame::from_result(&AdbTransportResult {
            schema: ADB_TRANSPORT_BOUNDARY_SCHEMA.to_string(),
            request_id: admitted.request_id().to_string(),
            operation: admitted.operation(),
            disposition: AdbTransportDisposition::Completed,
            exit_code: Some(0),
            stdout: b"ok".to_vec(),
            stderr: Vec::new(),
            error_code: None,
        });
        let (mut left, mut right) = UnixStream::pair().unwrap();
        let expected_response = response.clone();
        let writer = std::thread::spawn(move || {
            let frame = encode_uds_frame(&request).unwrap();
            right.write_all(&frame).unwrap();
            let mut prefix = [0_u8; 4];
            right.read_exact(&mut prefix).unwrap();
            let length = u32::from_be_bytes(prefix) as usize;
            let mut body = vec![0_u8; length];
            right.read_exact(&mut body).unwrap();
            let received: AdbBrokerResponseFrame =
                decode_uds_frame(&[prefix.to_vec(), body].concat()).unwrap();
            assert_eq!(received, expected_response);
        });
        let mut prefix = [0_u8; 4];
        left.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        let mut body = vec![0_u8; length];
        left.read_exact(&mut body).unwrap();
        let received: AdbBrokerRequestFrame =
            decode_uds_frame(&[prefix.to_vec(), body].concat()).unwrap();
        received.verify_against(&admitted).unwrap();
        left.write_all(&encode_uds_frame(&response).unwrap())
            .unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn production_constructor_is_an_explicit_hold() {
        assert_eq!(
            ProductionAdbTransport::new().unwrap_err(),
            AdbTransportBoundaryError::TransportUnavailable(ADB_PRODUCTION_TRANSPORT_STATUS)
        );
        assert!(ADB_PRODUCTION_TRANSPORT_STATUS.contains("HOLD"));
    }

    #[test]
    fn model_json_cannot_reach_transport_with_private_key_or_selector() {
        let policy = policy(AndroidAdbTier::User);
        let malicious = serde_json::json!({
            "protocol_version": 1,
            "request_id": "adb-private",
            "operation": "shell",
            "device_binding": "self",
            "arguments": {"kind": "shell", "argv": ["id"]},
            "host": "127.0.0.1",
            "private_key_pem": "-----BEGIN PRIVATE KEY-----",
        });
        assert!(matches!(
            policy.admit_json(&serde_json::to_vec(&malicious).unwrap()),
            Err(AdbTransportBoundaryError::Contract(
                AndroidAdbContractError::PrivateKeyMaterialForbidden { .. }
            ))
        ));
    }
}
