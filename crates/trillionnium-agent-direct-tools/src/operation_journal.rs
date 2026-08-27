//! Agent-side durable pre-effect operation journal.
//!
//! The trusted-context integration path derives the journal capability and
//! stable Agent/adapter/invocation identities from fixed OS custody; model
//! request fields can never select them or provide a backend request ID. The
//! Root product builds compile the durable hotpath. Missing launch custody,
//! secure first-use provisioning, or exact outer acknowledgement keeps runtime
//! activation held before any backend effect.

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use trillionnium_os_types::direct_operation::{
    ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA, DirectOperationAdapter,
    DirectOperationAdapterTerminalDispositionV1, DirectOperationAdapterTerminalStateV1,
    DirectOperationBinding, DirectOperationJournalEvidenceSnapshotV1,
    DirectOperationOuterAckInboxV3, DirectOperationOuterEvidence, DirectOperationOuterOutcome,
    DirectOperationReplaySyncAckConfirmationV3, DirectOperationReplaySyncObservationV3,
    DirectOperationToolCallEnvelopeV3, DirectOperationToolCallPreparedAckV3,
    JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA, OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA,
    OPERATION_REPLAY_SYNC_OBSERVATION_V3_SCHEMA, TOOL_CALL_ENVELOPE_V3_SCHEMA,
};
use trillionnium_os_types::direct_operation_runtime_authority_mutation_cas as mutation_cas;

pub use crate::OperationOutcome;
use crate::{
    BackendCompletion, ClassifiedBackendCompletion, classify_backend_completion,
    valid_backend_error_code,
};

const JOURNAL_SCHEMA: &str = "trillionnium.agent-operation-journal.v5";
const REQUEST_ID_PREFIX: &str = "op";
const TOOL_CALL_ID_PREFIX: &str = "tool-call:";
const EPOCH_BYTES: usize = 16;
const ZERO_EPOCH_HEX: &str = "00000000000000000000000000000000";
const DIGEST_BYTES: usize = 32;
const DIGEST_HEX_BYTES: usize = DIGEST_BYTES * 2;
const MAX_ID_BYTES: usize = 128;
// Keep the decimal journal-sequence component at nineteen digits so the closed
// `op:<epoch>:<journal-sequence>:<sha256>` representation is bounded to 120
// bytes. Exhaustion is fail-closed; journal-sequence identity is never wrapped
// or shortened.
const MAX_JOURNAL_SEQUENCE: u64 =
    trillionnium_os_types::direct_operation::MAX_DIRECT_OPERATION_JOURNAL_SEQUENCE;
// A definitive backend result is part of the exactly-once authority, not just
// evidence about it.  Keep enough bounded space for sixteen maximum-size
// backend frames plus base64/JSON overhead.  `begin_effect` reserves one full
// frame before allocating another identity, so a response can never become
// unrecordable merely because earlier results filled the store.
const MAX_ACTIVE_TERMINAL_RESULT_BYTES: usize = 16 * crate::MAX_RESPONSE_BYTES;
pub(crate) const MAX_JOURNAL_BYTES: usize = 32 * 1024 * 1024;
// The replay-sync response carries the complete digest-only evidence snapshot
// inside one 64 KiB canonical frame. Sixty-four maximum-width evidence items
// (long signed-range sequences and 128-byte backend error codes) remain below
// that bound; admitting more would create a valid journal with no encodable
// terminal observation.
pub(crate) const MAX_ACTIVE_OPERATIONS: usize = 64;
const MAX_ACKNOWLEDGEMENTS: usize = 16;
const MUTATION_STAGE_SIDECAR_SCHEMA: &str =
    "trillionnium.agent-operation-journal-mutation-stage-sidecar.v1";
const MAX_MUTATION_STAGE_SIDECAR_BYTES: usize = 64 * 1024;
const MUTATION_PRIVATE_IDENTITY_DOMAIN: &[u8] =
    b"trillionnium.agent-operation-journal-mutation-private-identity.v1\0";
// The generation-one authority already commits this exact identity domain.
// Successor versions must retain it until the identity ABI is centralized;
// changing it here would make the first local CAS successor incomparable with
// its externally committed predecessor.
const JOURNAL_IDENTITY_DOMAIN: &[u8] = b"genesis-journal";
// The production first-use consumer is intentionally source-complete but has
// no product authority transport yet, so this bound is unused until that
// fail-closed seam is wired.
#[allow(dead_code)]
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(2);
const TEMP_CREATE_ATTEMPTS: usize = 8;
const ZERO_DIGEST_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub type JournalResult<T> = std::result::Result<T, OperationJournalError>;
type SealedJournalMutationStageProof =
    crate::direct_operation_runtime_authority_mutation_cas_client::SealedDurableStagedMutationProof;

#[derive(Debug, Error)]
pub enum OperationJournalError {
    #[error("invalid operation journal argument: {0}")]
    InvalidArgument(&'static str),
    #[error("operation journal identity does not match persisted state")]
    IdentityMismatch,
    #[error("operation journal is corrupt: {0}")]
    Corrupt(String),
    #[error("operation journal lock acquisition timed out")]
    LockTimeout,
    #[error("recovery is required for invocation {pending_invocation_id}")]
    RecoveryRequired { pending_invocation_id: String },
    #[error("recovery canonical request digest does not match the prepared operation")]
    CanonicalDigestMismatch,
    #[error("recovery digest matches more than one durable operation; journal is ambiguous")]
    AmbiguousRecovery,
    #[error("adapter effect ordinal is not contiguous: expected {expected}, received {received}")]
    AdapterEffectOrdinalMismatch { expected: u64, received: u64 },
    #[error("operation journal entry was not found")]
    OperationNotFound,
    #[error("operation journal evidence mismatch: {0}")]
    EvidenceMismatch(&'static str),
    #[error("operation journal transition is invalid: {0}")]
    InvalidTransition(&'static str),
    #[error("operation journal capacity is exhausted")]
    CapacityExhausted,
    #[error(
        "trusted operation journal is absent; secure first-use provisioning is not implemented and activation is held"
    )]
    MissingTrustedJournal,
    #[error(
        "secure first-use COMMITTED runtime authority is unavailable; product journal activation is held"
    )]
    FirstUseAuthorityUnavailable,
    #[error("secure first-use COMMITTED runtime authority failed closed: {0}")]
    FirstUseAuthority(String),
    #[error("operation journal epoch does not match secure first-use COMMITTED authority")]
    FirstUseEpochMismatch,
    #[error(
        "rollback-resistant journal replay authority is unavailable; product journal restart activation is held"
    )]
    ReplayAuthorityUnavailable,
    #[error("rollback-resistant journal replay authority failed closed: {0}")]
    ReplayAuthority(String),
    #[error(
        "external journal runtime authority is unavailable for durable PREPARED acknowledgement"
    )]
    PreparedAcknowledgementAuthorityUnavailable,
    #[error(
        "same-store operation-journal mutation CAS authority is unavailable; activation is held"
    )]
    MutationAuthorityUnavailable,
    #[error("same-store operation-journal mutation CAS failed closed: {0}")]
    MutationAuthority(&'static str),
    #[error(
        "bounded invocation reuse index is exhausted; activation is held before any identity can be forgotten"
    )]
    InvocationReuseIndexExhausted,
    #[error(
        "journal publish occurred but parent-directory durability is uncertain; reopen required"
    )]
    DurabilityUncertain,
    #[error("operation journal handle is fail-stopped; reopen and inspect recovery state")]
    ReopenRequired,
    #[error("operation journal I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; DIGEST_BYTES]);

impl Sha256Digest {
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let digest: [u8; DIGEST_BYTES] = Sha256::digest(bytes).into();
        Self(digest)
    }

    pub fn from_hex(value: &str) -> JournalResult<Self> {
        if value.len() != DIGEST_HEX_BYTES || !is_lower_hex(value) {
            return Err(OperationJournalError::InvalidArgument(
                "SHA-256 must be exactly 64 lowercase hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; DIGEST_BYTES];
        for (index, output) in bytes.iter_mut().enumerate() {
            let high = decode_hex_nibble(value.as_bytes()[index * 2]);
            let low = decode_hex_nibble(value.as_bytes()[index * 2 + 1]);
            *output = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        lower_hex(&self.0)
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Sha256Digest")
            .field(&self.to_hex())
            .finish()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl OperationEvidence {
    /// Export the exact closed journal evidence shape consumed by the outer
    /// acknowledgement protocol. `backend_result_sha256` is the canonical,
    /// domain-separated semantic result identity; the independent exact-byte
    /// digest and raw backend bytes never cross this boundary.
    pub fn to_outer_evidence(&self) -> JournalResult<DirectOperationOuterEvidence> {
        validate_operation_evidence(self)?;
        let adapter = match self.adapter_id.as_str() {
            "system_api" => DirectOperationAdapter::SystemApi,
            "accessibility" => DirectOperationAdapter::Accessibility,
            _ => {
                return Err(OperationJournalError::EvidenceMismatch(
                    "journal adapter is not a closed direct-operation adapter",
                ));
            }
        };
        Ok(DirectOperationOuterEvidence {
            allocating_provider_attempt_id: self.allocating_provider_attempt_id.clone(),
            adapter_effect_ordinal: self.adapter_effect_ordinal,
            journal_sequence: self.journal_sequence,
            tool: adapter.tool_name().to_string(),
            canonical_request_sha256: self.canonical_request_sha256.to_hex(),
            backend_request_id_sha256: Sha256Digest::of_bytes(self.request_id.as_bytes()).to_hex(),
            backend_result_sha256: self.backend_result_sha256.to_hex(),
            outcome: match self.outcome {
                OperationOutcome::Success => DirectOperationOuterOutcome::Success,
                OperationOutcome::BackendError => DirectOperationOuterOutcome::BackendError,
                OperationOutcome::Indeterminate => DirectOperationOuterOutcome::Indeterminate,
            },
            backend_error_code: self.backend_error_code.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOperation {
    pub agent_id: String,
    pub adapter_id: String,
    pub invocation_id: String,
    pub allocating_provider_attempt_id: String,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub epoch: String,
    pub journal_sequence: u64,
    pub request_id: String,
    pub canonical_request_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationEvidence {
    pub agent_id: String,
    pub adapter_id: String,
    pub invocation_id: String,
    pub allocating_provider_attempt_id: String,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub epoch: String,
    pub journal_sequence: u64,
    pub request_id: String,
    pub canonical_request_sha256: Sha256Digest,
    /// Exact backend response-byte digest retained for replay and journal
    /// integrity. It is never exported as the outer semantic result identity.
    pub raw_backend_result_sha256: Sha256Digest,
    /// Canonical, domain-separated semantic backend-result digest exported to
    /// the daemon outer evidence and reconciled with provider evidence.
    pub backend_result_sha256: Sha256Digest,
    pub outcome: OperationOutcome,
    pub backend_error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryDecision {
    RetryPrepared(PreparedOperation),
    ResultRecorded(OperationEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectStart {
    Allocated(PreparedOperation),
    Recovery(RecoveryDecision),
}

impl EffectStart {
    /// Return the immutable backend identity for either a newly durable
    /// PREPARED record or an exact recovery. A RESULT_RECORDED recovery keeps
    /// the same token so the journal can release its exact retained terminal
    /// bytes without contacting the backend.
    #[must_use]
    pub fn into_prepared(self) -> PreparedOperation {
        match self {
            Self::Allocated(prepared)
            | Self::Recovery(RecoveryDecision::RetryPrepared(prepared)) => prepared,
            Self::Recovery(RecoveryDecision::ResultRecorded(evidence)) => PreparedOperation {
                agent_id: evidence.agent_id,
                adapter_id: evidence.adapter_id,
                invocation_id: evidence.invocation_id,
                allocating_provider_attempt_id: evidence.allocating_provider_attempt_id,
                os_tool_call_id: evidence.os_tool_call_id,
                adapter_effect_ordinal: evidence.adapter_effect_ordinal,
                epoch: evidence.epoch,
                journal_sequence: evidence.journal_sequence,
                request_id: evidence.request_id,
                canonical_request_sha256: evidence.canonical_request_sha256,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOperationState {
    Prepared,
    ResultRecorded {
        backend_result_sha256: Sha256Digest,
        outcome: OperationOutcome,
        backend_error_code: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOperation {
    pub allocating_provider_attempt_id: String,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub journal_sequence: u64,
    pub request_id: String,
    pub canonical_request_sha256: Sha256Digest,
    pub state: RecoveryOperationState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub pending_invocation_id: String,
    pub pending_allocating_provider_attempt_id: String,
    pub recovery_only: bool,
    pub operations: Vec<RecoveryOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationAcknowledgement {
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub first_journal_sequence: u64,
    pub last_journal_sequence: u64,
    pub operation_count: u32,
    pub evidence_set_sha256: Sha256Digest,
    pub outer_receipt_sha256: Sha256Digest,
}

/// Exact local replay state compared with the Android System API replay
/// controller by the separately packaged P0 launch-package conformance lane.
///
/// This is deliberately not a product replay authority.  It is available only
/// in the userdebug-only conformance feature and is derived from an already
/// durable journal; callers cannot use it to select an epoch or sequence.
#[cfg(feature = "device-launch-package-conformance")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceConformanceReplayState {
    pub(crate) epoch: String,
    pub(crate) acknowledged_through: u64,
    pub(crate) next_sequence: u64,
    pub(crate) highest_retained_sequence: u64,
    pub(crate) operation_epoch_exhausted: bool,
    pub(crate) authenticated_ack_sha256: String,
    pub(crate) authenticated_ack_chain_sha256: String,
}

/// One retained-FD observation of the non-product conformance journal.  The
/// payload and file identities are descriptive local facts only; they do not
/// become rollback or mutation authority without an independent external
/// high-water/root publication proof.
#[cfg(feature = "device-launch-package-conformance")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceConformanceJournalObservation {
    pub(crate) replay_state: DeviceConformanceReplayState,
    pub(crate) evidence_snapshot: Option<DirectOperationJournalEvidenceSnapshotV1>,
    pub(crate) journal_payload_sha256: String,
    pub(crate) journal_file_identity_sha256: String,
}

mod runtime_open_consumer {
    use super::{
        FileIdentity, JournalOpenParameters, JournalResult, LOCK_TIMEOUT, OperationJournal,
        OperationJournalError,
    };

    /// Module seal for the custody-wrapped first-use and replay consumers.
    /// The type is nameable by `secure_first_use_journal`, but only this
    /// private child module can create a value in non-test safe Rust.
    pub(crate) struct Token {
        _private: (),
    }

    const fn claim() -> Token {
        Token { _private: () }
    }

    #[cfg(test)]
    pub(crate) const fn claim_for_test() -> Token {
        claim()
    }

    impl OperationJournal {
        /// Consume the exact externally COMMITTED first-use result for the first
        /// runtime open. This is the only source-level seam that can turn the
        /// provision ceremony into a live journal handle. No product caller can
        /// construct the capability yet.
        #[allow(dead_code)]
        pub(crate) fn open_trusted_after_first_use(
            context: &crate::trusted_context::TrustedAdapterContext,
            authority: crate::secure_first_use_journal::VerifiedFirstUseJournal,
        ) -> JournalResult<Self> {
            let trusted_state_directory = context.clone_state_directory()?;
            let open_state_directory = trusted_state_directory.try_clone()?;
            let (mut journal, mutation_cas_session) = authority
                .consume_for_runtime_open(
                    claim(),
                    &trusted_state_directory,
                    context.agent_id(),
                    context.adapter().adapter_id(),
                    |authority| {
                        let pinned_epoch = authority.journal_epoch().to_string();
                        let required_initial_state_sha256 = authority.journal_bytes_sha256();
                        let (required_device, required_inode) = authority.journal_file_identity();
                        let operation_epoch_authority_sha256 =
                            authority.operation_epoch_authority_sha256();
                        Self::open_with_parameters(JournalOpenParameters {
                            path: context.journal_path().to_path_buf(),
                            agent_id: context.agent_id().to_string(),
                            adapter_id: context.adapter().adapter_id().to_string(),
                            invocation_id: context.invocation_id().to_string(),
                            delivery_provider_attempt_id: context
                                .delivery_provider_attempt_id()
                                .to_string(),
                            trusted_delivery_binding: Some(context.binding().clone()),
                            trusted_delivery_binding_sha256: Some(
                                context.binding_sha256().to_string(),
                            ),
                            lock_timeout: LOCK_TIMEOUT,
                            initialize_missing: false,
                            trusted_state_directory: Some(open_state_directory),
                            pinned_epoch: Some(pinned_epoch),
                            operation_epoch_authority_sha256: Some(
                                operation_epoch_authority_sha256,
                            ),
                            device_conformance_epoch_authority_bridge: false,
                            required_open_state_sha256: Some(required_initial_state_sha256),
                            required_open_file_identity: Some(FileIdentity {
                                device: required_device,
                                inode: required_inode,
                            }),
                        })
                    },
                )
                .map_err(|error| OperationJournalError::FirstUseAuthority(error.to_string()))??;
            journal.mutation_cas_session = Some(mutation_cas_session);
            Ok(journal)
        }

        /// Consume one exact external replay/high-water result for a restart of an
        /// already-provisioned journal. The capability is one-shot and pins the
        /// named state directory, current journal inode/bytes, immutable first-use
        /// sentinel lineage, journal epoch, and external monotonic replay head.
        ///
        /// This is intentionally distinct from first-use: it cannot provision a
        /// missing journal and it cannot treat local valid bytes as rollback
        /// authority. No ordinary product constructor exists yet.
        #[allow(dead_code)]
        pub(crate) fn open_trusted_after_replay(
            context: &crate::trusted_context::TrustedAdapterContext,
            authority: crate::secure_first_use_journal::VerifiedJournalReplayAuthority,
        ) -> JournalResult<Self> {
            let trusted_state_directory = context.clone_state_directory()?;
            let open_state_directory = trusted_state_directory.try_clone()?;
            let (opened, replay_authority) = authority
                .consume_for_runtime_open(
                    claim(),
                    &trusted_state_directory,
                    context.agent_id(),
                    context.adapter().adapter_id(),
                    |authority| {
                        let pinned_epoch = authority.journal_epoch().to_string();
                        let required_open_state_sha256 = authority.journal_bytes_sha256();
                        let (required_device, required_inode) = authority.journal_file_identity();
                        let operation_epoch_authority_sha256 =
                            authority.operation_epoch_authority_sha256();
                        Self::open_with_parameters(JournalOpenParameters {
                            path: context.journal_path().to_path_buf(),
                            agent_id: context.agent_id().to_string(),
                            adapter_id: context.adapter().adapter_id().to_string(),
                            invocation_id: context.invocation_id().to_string(),
                            delivery_provider_attempt_id: context
                                .delivery_provider_attempt_id()
                                .to_string(),
                            trusted_delivery_binding: Some(context.binding().clone()),
                            trusted_delivery_binding_sha256: Some(
                                context.binding_sha256().to_string(),
                            ),
                            lock_timeout: LOCK_TIMEOUT,
                            initialize_missing: false,
                            trusted_state_directory: Some(open_state_directory),
                            pinned_epoch: Some(pinned_epoch),
                            operation_epoch_authority_sha256: Some(
                                operation_epoch_authority_sha256,
                            ),
                            device_conformance_epoch_authority_bridge: false,
                            required_open_state_sha256: Some(required_open_state_sha256),
                            required_open_file_identity: Some(FileIdentity {
                                device: required_device,
                                inode: required_inode,
                            }),
                        })
                    },
                )
                .map_err(|error| OperationJournalError::ReplayAuthority(error.to_string()))?;
            let mut journal = opened?;
            journal.activate_replay_authority(replay_authority)?;
            Ok(journal)
        }
    }
}

pub(crate) use runtime_open_consumer::Token as OperationJournalRuntimeOpenConsumerToken;

#[cfg(test)]
pub(crate) use runtime_open_consumer::claim_for_test as operation_journal_runtime_open_consumer_for_test;

#[cfg(feature = "device-launch-package-conformance")]
mod device_conformance_epoch_authority_consumer {
    /// Private journal-side half of the ACTIVATE bridge.  The Android client
    /// can name this type in its consume signature, but only the journal
    /// implementation below can construct it.
    pub(crate) struct Token {
        _private: (),
    }

    pub(super) const fn claim() -> Token {
        Token { _private: () }
    }
}

#[cfg(feature = "device-launch-package-conformance")]
pub(crate) use device_conformance_epoch_authority_consumer::Token as DeviceConformanceEpochAuthorityConsumerToken;

/// Crate-internal proof that fd-derived journal facts are being sealed by this
/// module. The private field prevents ABI records or sibling modules from
/// minting writer-lock, durable-stage, publication, or cleanup evidence.
pub(crate) struct MutationCasJournalSeal {
    _private: (),
}

pub struct OperationJournal {
    path: PathBuf,
    agent_id: String,
    adapter_id: String,
    invocation_id: String,
    delivery_provider_attempt_id: String,
    trusted_delivery_binding: Option<DirectOperationBinding>,
    trusted_delivery_binding_sha256: Option<String>,
    lock_timeout: Duration,
    fail_stopped: bool,
    // Product handles retain the exact state-directory inode authenticated by
    // TrustedAdapterContext. Test-only raw constructors intentionally have no
    // such capability and are unavailable in non-test builds.
    trusted_state_directory: Option<File>,
    // A first-use COMMITTED capability pins the generated epoch for the
    // lifetime of this handle. Named-file replacement with another otherwise
    // valid epoch can never be accepted after activation.
    pinned_epoch: Option<String>,
    // Stable external first-use lineage which authored this operation epoch.
    // A replay/high-water decision must separately validate each restart, but
    // reuses this lineage digest so an unresolved PREPARED acknowledgement is
    // byte-identical after a safe restart. Local journal bytes can never
    // populate this field.
    operation_epoch_authority_sha256: Option<Sha256Digest>,
    // The userdebug-only adapter cannot prepare an effect until one exact
    // Android ACTIVATE exchange is consumed.  Replay-sync opens the same
    // journal read-only without inventing this authority.
    device_conformance_epoch_authority_bridge: bool,
    #[cfg(feature = "device-launch-package-conformance")]
    device_conformance_activation_admission: Option<DeviceConformanceReplayState>,
    // The first-use authority and the opened journal are one affine runtime
    // capability. Every authoritative mutation consumes and replaces this
    // sealed same-store session through local staging, PREPARE, publication,
    // COMMIT, cleanup, and a fresh OBSERVE.
    mutation_cas_session: Option<
        crate::direct_operation_runtime_authority_mutation_cas_client::SealedCommittedMutationCasSession,
    >,
    #[cfg(test)]
    legacy_mutation_without_cas_for_test: bool,
}

/// Sealed pre-Android-ACK admission. It proves the fixed replay-sync context,
/// exact inbox, local terminal snapshot and mutation-CAS session were all
/// admitted before any Android state transition. Its fields are private and
/// it is consumed by `apply_outer_ack_and_confirm` after the exact Android
/// echo is observed.
pub(crate) struct PreparedReplaySyncOuterAck<'a> {
    launch_authority: crate::trusted_context::AuthorizedReplaySyncContext<'a>,
    inbox: DirectOperationOuterAckInboxV3,
    ack_intent_sha256: String,
    binding_sha256: String,
}

impl PreparedReplaySyncOuterAck<'_> {
    pub(crate) fn inbox(&self) -> &DirectOperationOuterAckInboxV3 {
        &self.inbox
    }

    pub(crate) fn context(&self) -> &crate::trusted_context::TrustedReplaySyncContext {
        self.launch_authority.context()
    }
}

impl fmt::Debug for OperationJournal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("OperationJournal");
        debug
            .field("path", &self.path)
            .field("agent_id", &self.agent_id)
            .field("adapter_id", &self.adapter_id)
            .field("invocation_id", &self.invocation_id)
            .field(
                "delivery_provider_attempt_id",
                &self.delivery_provider_attempt_id,
            )
            .field("trusted_delivery_binding", &self.trusted_delivery_binding)
            .field(
                "trusted_delivery_binding_sha256",
                &self.trusted_delivery_binding_sha256,
            )
            .field("lock_timeout", &self.lock_timeout)
            .field("fail_stopped", &self.fail_stopped)
            .field(
                "has_trusted_state_directory",
                &self.trusted_state_directory.is_some(),
            )
            .field("pinned_epoch", &self.pinned_epoch)
            .field(
                "operation_epoch_authority_sha256",
                &self.operation_epoch_authority_sha256,
            )
            .field(
                "device_conformance_epoch_authority_bridge",
                &self.device_conformance_epoch_authority_bridge,
            );
        #[cfg(feature = "device-launch-package-conformance")]
        debug.field(
            "has_device_conformance_activation_admission",
            &self.device_conformance_activation_admission.is_some(),
        );
        debug.finish()
    }
}

#[allow(dead_code)]
struct JournalOpenParameters {
    path: PathBuf,
    agent_id: String,
    adapter_id: String,
    invocation_id: String,
    delivery_provider_attempt_id: String,
    trusted_delivery_binding: Option<DirectOperationBinding>,
    trusted_delivery_binding_sha256: Option<String>,
    lock_timeout: Duration,
    initialize_missing: bool,
    trusted_state_directory: Option<File>,
    pinned_epoch: Option<String>,
    operation_epoch_authority_sha256: Option<Sha256Digest>,
    device_conformance_epoch_authority_bridge: bool,
    required_open_state_sha256: Option<Sha256Digest>,
    required_open_file_identity: Option<FileIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    schema: String,
    payload: JournalState,
    payload_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalState {
    agent_id: String,
    adapter_id: String,
    epoch: String,
    next_sequence: u64,
    active_invocation_id: Option<String>,
    active_allocating_provider_attempt_id: Option<String>,
    active_allocation_binding: Option<DirectOperationBinding>,
    active_allocation_binding_sha256: Option<String>,
    compacted_ack_watermark: u64,
    compacted_ack_chain_sha256: String,
    acknowledgements: Vec<AcknowledgementRecord>,
    operations: Vec<OperationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRecord {
    invocation_id: String,
    allocating_provider_attempt_id: String,
    os_tool_call_id: String,
    adapter_effect_ordinal: u64,
    journal_sequence: u64,
    request_id: String,
    canonical_request_sha256: String,
    // Exact durable PREPARED acknowledgement retained before backend I/O.
    // A terminal-result retry must replay these bytes rather than derive a
    // different acknowledgement from the later RESULT_RECORDED payload.
    prepared_transport_ack: Option<DirectOperationToolCallPreparedAckV3>,
    state: PersistedOperationState,
    // Exact bounded response-byte digest. This is the replay/journal identity,
    // not the cross-boundary semantic result identity.
    backend_result_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backend_semantic_result_sha256: Option<String>,
    // Exact response bytes are retained only for definitive terminal
    // outcomes.  Indeterminate transport/protocol observations remain
    // recovery-only and can never be replayed as a terminal result.
    backend_result_base64: Option<String>,
    outcome: Option<OperationOutcome>,
    backend_error_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedOperationState {
    Prepared,
    ResultRecorded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcknowledgementRecord {
    invocation_id: String,
    delivery_provider_attempt_id: String,
    first_journal_sequence: u64,
    last_journal_sequence: u64,
    operation_count: u32,
    evidence_set_sha256: String,
    outer_receipt_sha256: String,
    acknowledgement_sha256: Option<String>,
    authenticated_ack_chain_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrivateFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
}

struct LoadedJournal {
    state: JournalState,
    identity: FileIdentity,
}

struct SecureParent {
    directory: File,
    destination_name: CString,
}

struct JournalLock {
    file: File,
    name: CString,
    identity: PrivateFileIdentity,
}

struct RetainedPrivateFile {
    file: File,
    name: CString,
    identity: PrivateFileIdentity,
    bytes: Vec<u8>,
    bytes_sha256: Sha256Digest,
}

struct MutationPrivateNames {
    lock: CString,
    staged_candidate: CString,
    sidecar: CString,
    sidecar_pending: CString,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MutationStageSidecarPhase {
    Staged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationStageSidecarPayload {
    phase: MutationStageSidecarPhase,
    mutation_intent: mutation_cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    writer_lock_identity_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationStageSidecarEnvelope {
    schema: String,
    payload: MutationStageSidecarPayload,
    payload_sha256: String,
}

/// A typed, canonical CAS intent accepted only inside this module. It is not
/// an authority capability and has no RPC method; the CAS client still binds
/// its own affine same-store session before PREPARE.
#[allow(dead_code)]
struct LocalMutationStagePlan {
    lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    current: mutation_cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    intent: mutation_cas::DirectOperationRuntimeAuthorityMutationIntentV1,
}

/// Candidate bytes are written and fsynced, but the fixed directory entry is
/// not yet a durable PREPARE prerequisite until the sidecar and parent
/// directory have also been sealed.
#[allow(dead_code)]
struct FsyncedMutationCandidate<'a> {
    parent: &'a SecureParent,
    lock: &'a JournalLock,
    named_journal: RetainedPrivateFile,
    candidate: RetainedPrivateFile,
}

/// Exact staged candidate plus canonical transaction sidecar, both durable
/// under the retained writer lock.
#[allow(dead_code)]
struct DurableLocalMutationStage<'a> {
    parent: &'a SecureParent,
    lock: &'a JournalLock,
    named_journal: RetainedPrivateFile,
    candidate: RetainedPrivateFile,
    sidecar: RetainedPrivateFile,
    plan: LocalMutationStagePlan,
}

/// The staged inode is now the exact named journal while the transaction
/// sidecar remains durable through authority COMMIT.
struct PublishedLocalMutationStage<'a> {
    parent: &'a SecureParent,
    lock: &'a JournalLock,
    named_journal: RetainedPrivateFile,
    sidecar: RetainedPrivateFile,
    plan: LocalMutationStagePlan,
}

/// Exact fixed-name layout retained across a replay open. The enum keeps all
/// descriptors and the writer lock alive while the same-store authority
/// classifies the external snapshot.
enum ReopenedReplayLocalState<'a> {
    Clean {
        parent: &'a SecureParent,
        lock: &'a JournalLock,
        named_journal: RetainedPrivateFile,
    },
    Staged(Box<DurableLocalMutationStage<'a>>),
    Published(Box<ReopenedPublishedLocalMutationStage<'a>>),
}

/// Restart view after the candidate has become the named journal but the
/// durable transaction sidecar remains. A predecessor committed record is
/// intentionally not reconstructed here: the same-store CAS client validates
/// either its live pending head or the externally observed successor ancestry.
struct ReopenedPublishedLocalMutationStage<'a> {
    parent: &'a SecureParent,
    lock: &'a JournalLock,
    named_journal: RetainedPrivateFile,
    sidecar: RetainedPrivateFile,
    lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    intent: mutation_cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    writer_lock_identity_sha256: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishState {
    Durable,
    PublishedDurabilityUncertain,
}

fn replay_current_after_cleanup(
    terminal: crate::direct_operation_runtime_authority_mutation_cas_client::ReconciledCommittedMutationCasSession,
    observations: crate::direct_operation_runtime_authority_mutation_cas_client::SealedLocalReconcileObservations,
) -> JournalResult<
    crate::direct_operation_runtime_authority_mutation_cas_client::SealedCommittedMutationCasSession,
>{
    use crate::direct_operation_runtime_authority_mutation_cas_client::ObserveTransition;

    match terminal.reopen_after_local_cleanup(observations) {
        ObserveTransition::Current(current) => Ok(current),
        ObserveTransition::FailStopped(_) => Err(OperationJournalError::ReplayAuthority(
            "fresh authority observation after replay cleanup failed closed".to_string(),
        )),
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    TempFileFsync,
    Rename,
    ParentFsyncAfterRename,
    MutationCandidateFsync,
    MutationSidecarFsync,
    MutationSidecarRename,
    MutationStageParentFsync,
    MutationPublicationRename,
    MutationPublicationParentFsync,
    MutationCleanupParentFsync,
}

#[cfg(test)]
pub(crate) enum MutationCasFaultForTest {
    SidecarFsyncBeforePrepare,
    PublicationRenameAfterPrepare,
    PublicationParentFsyncAfterRename,
    CleanupParentFsyncAfterCommit,
}

#[cfg(test)]
thread_local! {
    static NEXT_FAULT: std::cell::Cell<Option<FaultPoint>> = const { std::cell::Cell::new(None) };
}

impl OperationJournal {
    /// Open the fixed, provider-private P0 launch-package conformance journal.
    ///
    /// The surrounding [`TrustedAdapterContext`] has already consumed the
    /// root-authored binding from the fixed inbox and fixed the provider from
    /// UID/GID plus SELinux identity.  This constructor is intentionally
    /// absent from product builds: it permits a local fsync/rename journal in
    /// a userdebug-only lane while the external first-use and mutation-CAS
    /// authorities remain product HOLDs.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn open_device_conformance(
        context: &crate::trusted_context::TrustedAdapterContext,
    ) -> JournalResult<Self> {
        Self::open_device_conformance_with_mode(context, true)
    }

    /// Open only an already-existing fixed conformance journal for the
    /// replay-sync role.  A missing file is a HOLD and is never initialized by
    /// an ACK consumer before external replay authority exists.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn open_device_conformance_replay_sync(
        context: &crate::trusted_context::TrustedAdapterContext,
    ) -> JournalResult<Self> {
        Self::open_device_conformance_with_mode(context, false)
    }

    #[cfg(feature = "device-launch-package-conformance")]
    fn open_device_conformance_with_mode(
        context: &crate::trusted_context::TrustedAdapterContext,
        initialize_missing: bool,
    ) -> JournalResult<Self> {
        Self::open_with_parameters(JournalOpenParameters {
            path: context.device_conformance_journal_path(),
            agent_id: context.agent_id().to_string(),
            adapter_id: context.adapter().adapter_id().to_string(),
            invocation_id: context.invocation_id().to_string(),
            delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
            trusted_delivery_binding: Some(context.binding().clone()),
            trusted_delivery_binding_sha256: Some(context.binding_sha256().to_string()),
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing,
            // Deliberately do not claim the product state-directory or
            // external mutation-CAS capabilities in this non-product lane.
            trusted_state_directory: None,
            pinned_epoch: None,
            operation_epoch_authority_sha256: None,
            device_conformance_epoch_authority_bridge: true,
            required_open_state_sha256: None,
            required_open_file_identity: None,
        })
    }

    /// Install the move-only result of one exact, peer-authenticated Android
    /// ACTIVATE exchange.  The token revalidates provider, adapter, binding,
    /// invocation, epoch and the complete pre-ACTIVATE replay snapshot while
    /// this method retains the journal lock.  Only then is its stable epoch
    /// lineage admitted for one PREPARED allocation.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn install_device_conformance_epoch_authority(
        &mut self,
        activation: crate::android_operation_replay_control::DeviceConformanceActivation,
    ) -> JournalResult<()> {
        self.require_live()?;
        if !self.device_conformance_epoch_authority_bridge
            || self.operation_epoch_authority_sha256.is_some()
            || self.device_conformance_activation_admission.is_some()
        {
            return Err(OperationJournalError::InvalidTransition(
                "device-conformance ACTIVATE authority is not installable on this journal handle",
            ));
        }
        let binding = self
            .trusted_delivery_binding
            .as_ref()
            .ok_or(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)?;
        let binding_sha256 = self
            .trusted_delivery_binding_sha256
            .as_deref()
            .ok_or(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)?;
        let (_parent, _lock, loaded) = self.load_locked()?;
        let current = device_conformance_replay_state_from_state(&loaded.state)?;
        let operation_epoch_authority_sha256 = activation
            .consume_for_journal(
                device_conformance_epoch_authority_consumer::claim(),
                binding,
                binding_sha256,
                &self.adapter_id,
                &self.agent_id,
                &self.invocation_id,
                &self.delivery_provider_attempt_id,
                &current,
            )
            .map_err(OperationJournalError::EvidenceMismatch)?;
        validate_prepared_transport_ack_runtime_authorities(
            &loaded.state,
            Some(operation_epoch_authority_sha256),
        )?;
        self.pinned_epoch = Some(current.epoch.clone());
        self.operation_epoch_authority_sha256 = Some(operation_epoch_authority_sha256);
        self.device_conformance_activation_admission = Some(current);
        Ok(())
    }

    /// Host-only constructor for the integration test of the exact
    /// ACTIVATE -> journal -> delivery/envelope -> PREPARED path.  It retains
    /// the production bridge flag and trusted binding checks; only the fixed
    /// Android filesystem/cgroup context open is replaced by a test path.
    #[cfg(all(test, feature = "device-launch-package-conformance"))]
    pub(crate) fn open_device_conformance_for_test(
        path: &Path,
        binding: &DirectOperationBinding,
    ) -> JournalResult<Self> {
        Self::open_with_parameters(JournalOpenParameters {
            path: path.to_path_buf(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter_id: DirectOperationAdapter::SystemApi.adapter_id().to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            trusted_delivery_binding: Some(binding.clone()),
            trusted_delivery_binding_sha256: Some(binding.digest_sha256().map_err(|_| {
                OperationJournalError::InvalidArgument("test binding digest is invalid")
            })?),
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing: true,
            trusted_state_directory: None,
            pinned_epoch: None,
            operation_epoch_authority_sha256: None,
            device_conformance_epoch_authority_bridge: true,
            required_open_state_sha256: None,
            required_open_file_identity: None,
        })
    }

    /// Export the exact Android replay state implied by definitive durable
    /// conformance records.  PREPARED or indeterminate records have no safe
    /// Android high-water interpretation and therefore remain a restart HOLD.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn device_conformance_replay_state(
        &mut self,
    ) -> JournalResult<DeviceConformanceReplayState> {
        self.require_live()?;
        let (_parent, _lock, loaded) = self.load_locked()?;
        device_conformance_replay_state_from_state(&loaded.state)
    }

    /// Read replay state, canonical payload digest, and the exact named-file
    /// inode identity under one retained journal lock.  This is the last local
    /// observation available before the conformance replay helper must demand
    /// an independent rollback/high-water/root-publication authority.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn device_conformance_journal_observation(
        &mut self,
    ) -> JournalResult<DeviceConformanceJournalObservation> {
        self.require_live()?;
        let (_parent, _lock, loaded) = self.load_locked()?;
        let replay_state = device_conformance_replay_state_from_state(&loaded.state)?;
        let evidence_snapshot = if loaded.state.operations.is_empty() {
            None
        } else {
            Some(evidence_snapshot_from_state(
                &loaded.state,
                &self.agent_id,
                &self.adapter_id,
            )?)
        };
        let payload = serde_json::to_vec(&loaded.state)
            .map_err(|error| corrupt(format!("could not encode journal payload: {error}")))?;
        let journal_payload_sha256 = Sha256Digest::of_bytes(&payload).to_hex();
        let binding_sha256 = self
            .trusted_delivery_binding_sha256
            .as_deref()
            .ok_or(OperationJournalError::IdentityMismatch)?;
        let journal_file_identity_sha256 = replay_sync_file_identity_digest(
            loaded.identity,
            &journal_payload_sha256,
            binding_sha256,
        );
        Ok(DeviceConformanceJournalObservation {
            replay_state,
            evidence_snapshot,
            journal_payload_sha256,
            journal_file_identity_sha256,
        })
    }

    /// Consume one opaque Android ACK capability, compact the fixed P0
    /// journal durably, and reopen the exact named file before returning. The
    /// complete delivery/allocation/receipt preimages are revalidated here so
    /// a measured helper cannot compact from the delivery binding alone.
    #[cfg(feature = "device-launch-package-conformance")]
    pub(crate) fn apply_device_conformance_outer_ack_and_observe(
        &mut self,
        delivery_binding: &DirectOperationBinding,
        allocation_binding: &DirectOperationBinding,
        outer_receipt: &trillionnium_os_types::direct_operation::DirectOperationOuterReceiptV3,
        inbox: &DirectOperationOuterAckInboxV3,
        android_ack: &crate::android_operation_replay_ack::VerifiedDeviceConformanceReplayAck,
    ) -> JournalResult<DeviceConformanceJournalObservation> {
        inbox
            .validate_for_bindings_and_receipt(delivery_binding, allocation_binding, outer_receipt)
            .map_err(|_| {
                OperationJournalError::EvidenceMismatch(
                    "P0 replay-sync authority preimages do not match the outer ACK",
                )
            })?;
        android_ack.validate_for_inbox(inbox).map_err(|_| {
            OperationJournalError::EvidenceMismatch(
                "P0 replay-sync Android ACK capability does not match the outer ACK",
            )
        })?;
        let delivery_binding_sha256 = delivery_binding.digest_sha256().map_err(|_| {
            OperationJournalError::EvidenceMismatch("P0 delivery binding digest is invalid")
        })?;
        self.acknowledge_outer_v3(delivery_binding, &delivery_binding_sha256, inbox)?;
        let observation = self.device_conformance_journal_observation()?;
        let snapshot = &inbox.acknowledgement.journal_evidence_snapshot;
        if observation.evidence_snapshot.is_some()
            || observation.replay_state.epoch != snapshot.journal_epoch
            || observation.replay_state.acknowledged_through != snapshot.last_journal_sequence
            || observation.replay_state.highest_retained_sequence != 0
            || observation.replay_state.authenticated_ack_sha256 != inbox.acknowledgement_sha256
            || observation.replay_state.authenticated_ack_chain_sha256
                != inbox.chain_step.authenticated_ack_chain_sha256
        {
            return Err(OperationJournalError::EvidenceMismatch(
                "P0 post-compaction journal is not the exact ACK successor",
            ));
        }
        Ok(observation)
    }
}

#[cfg(feature = "device-launch-package-conformance")]
fn device_conformance_replay_state_from_state(
    state: &JournalState,
) -> JournalResult<DeviceConformanceReplayState> {
    if state.operations.iter().any(|operation| {
        operation.state == PersistedOperationState::Prepared
            || operation.outcome == Some(OperationOutcome::Indeterminate)
    }) {
        return Err(OperationJournalError::InvalidTransition(
            "P0 device conformance cannot infer Android replay state from PREPARED or indeterminate operation",
        ));
    }
    let highest_retained_sequence = state
        .operations
        .last()
        .map_or(0, |operation| operation.journal_sequence);
    let (authenticated_ack_sha256, authenticated_ack_chain_sha256) =
        if state.compacted_ack_watermark == 0 {
            (ZERO_DIGEST_HEX.to_string(), ZERO_DIGEST_HEX.to_string())
        } else {
            let acknowledgement = state
                .acknowledgements
                .iter()
                .find(|record| record.last_journal_sequence == state.compacted_ack_watermark)
                .ok_or(OperationJournalError::EvidenceMismatch(
                    "compacted replay watermark has no retained acknowledgement",
                ))?;
            (
                acknowledgement.acknowledgement_sha256.clone().ok_or(
                    OperationJournalError::EvidenceMismatch(
                        "compacted replay watermark lacks an outer ACK digest",
                    ),
                )?,
                acknowledgement
                    .authenticated_ack_chain_sha256
                    .clone()
                    .ok_or(OperationJournalError::EvidenceMismatch(
                        "compacted replay watermark lacks an authenticated ACK chain",
                    ))?,
            )
        };
    let highest_known = state.compacted_ack_watermark.max(highest_retained_sequence);
    Ok(DeviceConformanceReplayState {
        epoch: state.epoch.clone(),
        acknowledged_through: state.compacted_ack_watermark,
        next_sequence: state.next_sequence,
        highest_retained_sequence,
        operation_epoch_exhausted: highest_known == MAX_JOURNAL_SEQUENCE,
        authenticated_ack_sha256,
        authenticated_ack_chain_sha256,
    })
}

impl OperationJournal {
    /// Exercise the same exact pathname open used by the sealed first-use and
    /// replay consumers without constructing a `TrustedAdapterContext`.
    /// Compiled only for custody race tests.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn open_exact_runtime_authority_for_test(
        path: &Path,
        trusted_state_directory: File,
        agent_id: &str,
        adapter_id: &str,
        pinned_epoch: &str,
        operation_epoch_authority_sha256: Sha256Digest,
        required_open_state_sha256: Sha256Digest,
        required_device: u64,
        required_inode: u64,
    ) -> JournalResult<Self> {
        Self::open_with_parameters(JournalOpenParameters {
            path: path.to_path_buf(),
            agent_id: agent_id.to_string(),
            adapter_id: adapter_id.to_string(),
            invocation_id: "runtime-open-custody-race-test".to_string(),
            delivery_provider_attempt_id: format!(
                "{}{}",
                trillionnium_os_types::direct_operation::PROVIDER_ATTEMPT_ID_PREFIX,
                "a".repeat(DIGEST_HEX_BYTES)
            ),
            trusted_delivery_binding: None,
            trusted_delivery_binding_sha256: None,
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing: false,
            trusted_state_directory: Some(trusted_state_directory),
            pinned_epoch: Some(pinned_epoch.to_string()),
            operation_epoch_authority_sha256: Some(operation_epoch_authority_sha256),
            device_conformance_epoch_authority_bridge: false,
            required_open_state_sha256: Some(required_open_state_sha256),
            required_open_file_identity: Some(FileIdentity {
                device: required_device as libc::dev_t,
                inode: required_inode as libc::ino_t,
            }),
        })
    }

    /// Test-only compatibility open for already-created fixtures. Production
    /// code must consume a sealed first-use or future replay/high-water
    /// capability and cannot call this path.
    #[cfg(test)]
    pub(crate) fn open_trusted_without_first_use_for_test(
        context: &crate::trusted_context::TrustedAdapterContext,
    ) -> JournalResult<Self> {
        let trusted_state_directory = context.clone_state_directory()?;
        let mut journal = Self::open_with_parameters(JournalOpenParameters {
            path: context.journal_path().to_path_buf(),
            agent_id: context.agent_id().to_string(),
            adapter_id: context.adapter().adapter_id().to_string(),
            invocation_id: context.invocation_id().to_string(),
            delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
            trusted_delivery_binding: Some(context.binding().clone()),
            trusted_delivery_binding_sha256: Some(context.binding_sha256().to_string()),
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing: false,
            trusted_state_directory: Some(trusted_state_directory),
            pinned_epoch: None,
            operation_epoch_authority_sha256: None,
            device_conformance_epoch_authority_bridge: false,
            required_open_state_sha256: None,
            required_open_file_identity: None,
        })?;
        journal.legacy_mutation_without_cas_for_test = true;
        Ok(journal)
    }

    /// Test-only replay-sync open. It preserves the sealed context identity
    /// but intentionally has no mutation-CAS session, allowing polarity tests
    /// to prove that an empty local journal cannot be reported as
    /// `NoOperations` without external authority.
    #[cfg(test)]
    pub(crate) fn open_replay_sync_without_authority_for_test(
        context: &crate::trusted_context::TrustedReplaySyncContext,
    ) -> JournalResult<Self> {
        let trusted_state_directory = context.clone_state_directory()?;
        Self::open_with_parameters(JournalOpenParameters {
            path: context.journal_path().to_path_buf(),
            agent_id: context.agent_id().to_string(),
            adapter_id: context.adapter().adapter_id().to_string(),
            invocation_id: context.invocation_id().to_string(),
            delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
            trusted_delivery_binding: Some(context.binding().clone()),
            trusted_delivery_binding_sha256: Some(context.binding_sha256().to_string()),
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing: false,
            trusted_state_directory: Some(trusted_state_directory),
            pinned_epoch: None,
            operation_epoch_authority_sha256: None,
            device_conformance_epoch_authority_bridge: false,
            required_open_state_sha256: None,
            required_open_file_identity: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn open(
        path: impl AsRef<Path>,
        agent_id: impl Into<String>,
        adapter_id: impl Into<String>,
        invocation_id: impl Into<String>,
        delivery_provider_attempt_id: impl Into<String>,
    ) -> JournalResult<Self> {
        Self::open_with_parameters(JournalOpenParameters {
            path: path.as_ref().to_path_buf(),
            agent_id: agent_id.into(),
            adapter_id: adapter_id.into(),
            invocation_id: invocation_id.into(),
            delivery_provider_attempt_id: delivery_provider_attempt_id.into(),
            trusted_delivery_binding: None,
            trusted_delivery_binding_sha256: None,
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing: true,
            trusted_state_directory: None,
            pinned_epoch: None,
            operation_epoch_authority_sha256: None,
            device_conformance_epoch_authority_bridge: false,
            required_open_state_sha256: None,
            required_open_file_identity: None,
        })
    }

    #[allow(dead_code)]
    fn open_with_parameters(parameters: JournalOpenParameters) -> JournalResult<Self> {
        let JournalOpenParameters {
            path,
            agent_id,
            adapter_id,
            invocation_id,
            delivery_provider_attempt_id,
            trusted_delivery_binding,
            trusted_delivery_binding_sha256,
            lock_timeout,
            initialize_missing,
            trusted_state_directory,
            pinned_epoch,
            operation_epoch_authority_sha256,
            device_conformance_epoch_authority_bridge,
            required_open_state_sha256,
            required_open_file_identity,
        } = parameters;
        validate_constructor_arguments(
            &path,
            &agent_id,
            &adapter_id,
            &invocation_id,
            &delivery_provider_attempt_id,
            lock_timeout,
        )?;
        validate_trusted_delivery_binding(
            trusted_delivery_binding.as_ref(),
            trusted_delivery_binding_sha256.as_deref(),
            &agent_id,
            &invocation_id,
            &delivery_provider_attempt_id,
        )?;
        let journal = Self {
            path,
            agent_id,
            adapter_id,
            invocation_id,
            delivery_provider_attempt_id,
            trusted_delivery_binding,
            trusted_delivery_binding_sha256,
            lock_timeout,
            fail_stopped: false,
            trusted_state_directory,
            pinned_epoch,
            operation_epoch_authority_sha256,
            device_conformance_epoch_authority_bridge,
            #[cfg(feature = "device-launch-package-conformance")]
            device_conformance_activation_admission: None,
            mutation_cas_session: None,
            #[cfg(test)]
            legacy_mutation_without_cas_for_test: false,
        };
        journal.initialize_or_validate(
            initialize_missing,
            required_open_state_sha256,
            required_open_file_identity,
        )?;
        Ok(journal)
    }

    #[must_use]
    pub const fn is_fail_stopped(&self) -> bool {
        self.fail_stopped
    }

    #[cfg(test)]
    pub(crate) fn has_mutation_cas_session_for_test(&self) -> bool {
        self.mutation_cas_session.is_some()
    }

    #[cfg(test)]
    pub(crate) fn mutation_cas_observation_snapshot_for_test(
        &self,
    ) -> Option<(u64, Vec<(String, String)>)> {
        self.mutation_cas_session
            .as_ref()
            .and_then(|session| session.same_store_observation_snapshot_for_test())
    }

    #[cfg(test)]
    pub(crate) fn mutation_cas_generation_for_test(&self) -> Option<u64> {
        self.mutation_cas_session
            .as_ref()
            .map(|session| session.mutation_generation_for_test())
    }

    #[cfg(test)]
    pub(crate) fn queue_mutation_store_fault_for_test(
        &self,
        fault: crate::direct_operation_runtime_authority_store_session::TestAuthorityStoreFault,
    ) {
        assert!(
            self.mutation_cas_session
                .as_ref()
                .is_some_and(|session| session.queue_same_store_fault_for_test(fault)),
            "test journal does not retain a same-store mutation session"
        );
    }

    /// Recover one OS-authored logical tool call or durably allocate a new one.
    ///
    /// The primary identity is `(os_tool_call_id, adapter_effect_ordinal)`.
    /// The canonical digest is an integrity binding, never a retry identity:
    /// the same token/ordinal plus the same digest recovers, the same identity
    /// plus a changed digest fails closed, and a new contiguous identity may
    /// legally carry the same canonical action again.
    pub fn begin_effect_with_identity(
        &mut self,
        os_tool_call_id: &str,
        adapter_effect_ordinal: u64,
        canonical_request: &[u8],
    ) -> JournalResult<EffectStart> {
        self.require_live()?;
        #[cfg(feature = "device-launch-package-conformance")]
        let activation_admission = if self.device_conformance_epoch_authority_bridge {
            Some(
                self.device_conformance_activation_admission
                    .clone()
                    .ok_or(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)?,
            )
        } else {
            None
        };
        #[cfg(not(feature = "device-launch-package-conformance"))]
        if self.device_conformance_epoch_authority_bridge {
            return Err(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable);
        }
        if !valid_tool_call_id(os_tool_call_id) {
            return Err(OperationJournalError::InvalidArgument(
                "invalid OS tool-call identity",
            ));
        }
        let canonical_request_sha256 = Sha256Digest::of_bytes(canonical_request);
        let (parent, lock, mut loaded) = self.load_locked()?;
        #[cfg(feature = "device-launch-package-conformance")]
        if let Some(expected) = activation_admission.as_ref()
            && device_conformance_replay_state_from_state(&loaded.state)? != *expected
        {
            return Err(OperationJournalError::EvidenceMismatch(
                "journal replay state drifted after the exact Android ACTIVATE response",
            ));
        }
        if loaded
            .state
            .acknowledgements
            .iter()
            .any(|record| record.invocation_id == self.invocation_id)
        {
            return Err(OperationJournalError::InvalidTransition(
                "invocation_id is already acknowledged and cannot allocate another effect",
            ));
        }
        if loaded.state.acknowledgements.len() >= MAX_ACKNOWLEDGEMENTS {
            return Err(OperationJournalError::InvocationReuseIndexExhausted);
        }
        if let Some(active) = loaded.state.operations.first()
            && active.invocation_id != self.invocation_id
        {
            return Err(OperationJournalError::RecoveryRequired {
                pending_invocation_id: active.invocation_id.clone(),
            });
        }
        let matching = loaded
            .state
            .operations
            .iter()
            .filter(|operation| operation.os_tool_call_id == os_tool_call_id)
            .collect::<Vec<_>>();
        match matching.as_slice() {
            [operation] => {
                if operation.adapter_effect_ordinal != adapter_effect_ordinal
                    || operation.canonical_request_sha256 != canonical_request_sha256.to_hex()
                {
                    return Err(OperationJournalError::EvidenceMismatch(
                        "OS tool-call identity was reused with a different ordinal or canonical digest",
                    ));
                }
                let recovered = EffectStart::Recovery(recovery_decision(
                    &loaded.state,
                    operation,
                    &self.agent_id,
                    &self.adapter_id,
                )?);
                #[cfg(feature = "device-launch-package-conformance")]
                if activation_admission.is_some() {
                    self.device_conformance_activation_admission = None;
                }
                return Ok(recovered);
            }
            [] => {}
            _ => return Err(OperationJournalError::AmbiguousRecovery),
        }
        if let Some(active) = loaded.state.operations.first() {
            if active.allocating_provider_attempt_id != self.delivery_provider_attempt_id {
                return Err(OperationJournalError::CanonicalDigestMismatch);
            }
            if loaded.state.operations.iter().any(|operation| {
                operation.state == PersistedOperationState::Prepared
                    || operation.outcome == Some(OperationOutcome::Indeterminate)
            }) {
                return Err(OperationJournalError::RecoveryRequired {
                    pending_invocation_id: active.invocation_id.clone(),
                });
            }
        }
        let expected_ordinal = u64::try_from(loaded.state.operations.len())
            .map_err(|_| OperationJournalError::CapacityExhausted)?;
        if adapter_effect_ordinal != expected_ordinal {
            return Err(OperationJournalError::AdapterEffectOrdinalMismatch {
                expected: expected_ordinal,
                received: adapter_effect_ordinal,
            });
        }
        if loaded.state.operations.len() >= MAX_ACTIVE_OPERATIONS {
            return Err(OperationJournalError::CapacityExhausted);
        }
        let retained_terminal_bytes = retained_terminal_result_bytes(&loaded.state)?;
        if retained_terminal_bytes
            .checked_add(crate::MAX_RESPONSE_BYTES)
            .is_none_or(|reserved| reserved > MAX_ACTIVE_TERMINAL_RESULT_BYTES)
        {
            return Err(OperationJournalError::CapacityExhausted);
        }
        let journal_sequence = loaded.state.next_sequence;
        if journal_sequence > MAX_JOURNAL_SEQUENCE {
            return Err(OperationJournalError::CapacityExhausted);
        }
        let next_sequence = journal_sequence
            .checked_add(1)
            .ok_or(OperationJournalError::CapacityExhausted)?;
        let request_id = generated_request_id(
            &loaded.state.epoch,
            journal_sequence,
            canonical_request_sha256,
        )?;
        let prepared = PreparedOperation {
            agent_id: self.agent_id.clone(),
            adapter_id: self.adapter_id.clone(),
            invocation_id: self.invocation_id.clone(),
            allocating_provider_attempt_id: self.delivery_provider_attempt_id.clone(),
            os_tool_call_id: os_tool_call_id.to_string(),
            adapter_effect_ordinal,
            epoch: loaded.state.epoch.clone(),
            journal_sequence,
            request_id: request_id.clone(),
            canonical_request_sha256,
        };
        loaded.state.operations.push(OperationRecord {
            invocation_id: self.invocation_id.clone(),
            allocating_provider_attempt_id: self.delivery_provider_attempt_id.clone(),
            os_tool_call_id: os_tool_call_id.to_string(),
            adapter_effect_ordinal,
            journal_sequence,
            request_id,
            canonical_request_sha256: canonical_request_sha256.to_hex(),
            prepared_transport_ack: None,
            state: PersistedOperationState::Prepared,
            backend_result_sha256: None,
            backend_semantic_result_sha256: None,
            backend_result_base64: None,
            outcome: None,
            backend_error_code: None,
        });
        if loaded.state.active_invocation_id.is_none() {
            loaded.state.active_invocation_id = Some(self.invocation_id.clone());
            loaded.state.active_allocating_provider_attempt_id =
                Some(self.delivery_provider_attempt_id.clone());
            loaded.state.active_allocation_binding = self.trusted_delivery_binding.clone();
            loaded.state.active_allocation_binding_sha256 =
                self.trusted_delivery_binding_sha256.clone();
        }
        loaded.state.next_sequence = next_sequence;
        self.publish_mutation(
            &parent,
            &lock,
            Some(loaded.identity),
            &loaded.state,
            mutation_cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
        )?;
        #[cfg(feature = "device-launch-package-conformance")]
        if activation_admission.is_some() {
            self.device_conformance_activation_admission = None;
        }
        Ok(EffectStart::Allocated(prepared))
    }

    #[cfg(test)]
    pub fn begin_effect(
        &mut self,
        adapter_effect_ordinal: u64,
        canonical_request: &[u8],
    ) -> JournalResult<EffectStart> {
        self.begin_effect_with_identity(
            &test_tool_call_id(adapter_effect_ordinal),
            adapter_effect_ordinal,
            canonical_request,
        )
    }

    /// Produce the exact adapter-to-daemon transport acknowledgement only
    /// after this logical call is durably PREPARED. The acknowledgement binds
    /// the named journal payload and epoch to the external first-use/replay
    /// result which opened this handle. It does not contact a backend and does
    /// not grant effect authority on its own.
    pub(crate) fn prepared_transport_ack(
        &mut self,
        envelope: &DirectOperationToolCallEnvelopeV3,
        prepared: &PreparedOperation,
    ) -> JournalResult<DirectOperationToolCallPreparedAckV3> {
        self.require_live()?;
        validate_prepared_identity(prepared, self)?;
        let binding = self
            .trusted_delivery_binding
            .as_ref()
            .ok_or(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)?;
        let binding_sha256 = self
            .trusted_delivery_binding_sha256
            .as_deref()
            .ok_or(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)?;
        let operation_epoch_authority_sha256 = self
            .operation_epoch_authority_sha256
            .ok_or(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)?;
        let adapter = closed_adapter(&self.adapter_id)?;
        envelope
            .validate_for(
                binding,
                binding_sha256,
                adapter,
                &prepared.canonical_request_sha256.to_hex(),
            )
            .map_err(|_| {
                OperationJournalError::EvidenceMismatch(
                    "tool-call envelope does not match the prepared journal operation",
                )
            })?;
        if envelope.os_tool_call_id != prepared.os_tool_call_id
            || envelope.adapter_effect_ordinal != prepared.adapter_effect_ordinal
        {
            return Err(OperationJournalError::EvidenceMismatch(
                "tool-call envelope identity does not match the prepared journal operation",
            ));
        }

        let (parent, lock, mut loaded) = self.load_locked()?;
        let operation_index = loaded
            .state
            .operations
            .iter()
            .position(|operation| operation.journal_sequence == prepared.journal_sequence)
            .ok_or(OperationJournalError::OperationNotFound)?;
        let operation = &loaded.state.operations[operation_index];
        validate_prepared_binding(&loaded.state, operation, prepared)?;
        if let Some(acknowledgement) = &operation.prepared_transport_ack {
            validate_stored_prepared_transport_ack(&loaded.state, operation, acknowledgement)?;
            validate_prepared_transport_ack_runtime_authority(
                acknowledgement,
                Some(operation_epoch_authority_sha256),
            )?;
            acknowledgement
                .validate_for_envelope(envelope)
                .map_err(|_| {
                    OperationJournalError::EvidenceMismatch(
                        "stored PREPARED acknowledgement does not match the allocated envelope",
                    )
                })?;
            return Ok(acknowledgement.clone());
        }
        if operation.state != PersistedOperationState::Prepared
            || operation.backend_result_sha256.is_some()
            || operation.backend_result_base64.is_some()
            || operation.outcome.is_some()
            || operation.backend_error_code.is_some()
        {
            return Err(OperationJournalError::InvalidTransition(
                "PREPARED acknowledgement requires one unresolved durable operation or its exact retained acknowledgement",
            ));
        }

        let payload = serde_json::to_vec(&loaded.state)
            .map_err(|error| corrupt(format!("could not encode journal payload: {error}")))?;
        let acknowledgement = DirectOperationToolCallPreparedAckV3::derive(
            envelope,
            prepared.epoch.clone(),
            prepared.journal_sequence,
            Sha256Digest::of_bytes(prepared.request_id.as_bytes()).to_hex(),
            Sha256Digest::of_bytes(&payload).to_hex(),
            operation_epoch_authority_sha256.to_hex(),
        )
        .map_err(|_| {
            OperationJournalError::EvidenceMismatch(
                "durable PREPARED acknowledgement shape is invalid",
            )
        })?;
        loaded.state.operations[operation_index].prepared_transport_ack =
            Some(acknowledgement.clone());
        self.publish_mutation(
            &parent,
            &lock,
            Some(loaded.identity),
            &loaded.state,
            mutation_cas::DirectOperationRuntimeAuthorityMutationKindV1::PersistPreparedTransportAck,
        )?;
        Ok(acknowledgement)
    }

    /// Test-only compatibility helper. Product code must consume an
    /// OS-authored tool-call envelope and cannot infer identity from journal
    /// length or canonical content.
    #[cfg(test)]
    pub fn begin_next_effect(&mut self, canonical_request: &[u8]) -> JournalResult<EffectStart> {
        let next_ordinal = self.recovery_plan()?.map_or(Ok(0), |plan| {
            u64::try_from(plan.operations.len())
                .map_err(|_| OperationJournalError::CapacityExhausted)
        })?;
        self.begin_effect(next_ordinal, canonical_request)
    }

    /// Test-only legacy lookup by canonical digest. Product code never uses
    /// this path because repeated logical calls may intentionally have the
    /// same canonical content; such a test lookup becomes ambiguous.
    #[cfg(test)]
    pub fn recover_effect(&mut self, canonical_request: &[u8]) -> JournalResult<RecoveryDecision> {
        self.require_live()?;
        let digest = Sha256Digest::of_bytes(canonical_request);
        let (_parent, _lock, loaded) = self.load_locked()?;
        require_active_invocation(&loaded.state, &self.invocation_id)?;
        let matches = loaded
            .state
            .operations
            .iter()
            .filter(|operation| operation.canonical_request_sha256 == digest.to_hex())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [] => Err(OperationJournalError::CanonicalDigestMismatch),
            [operation] => {
                recovery_decision(&loaded.state, operation, &self.agent_id, &self.adapter_id)
            }
            _ => Err(OperationJournalError::AmbiguousRecovery),
        }
    }

    /// Recover a known durable journal sequence while independently verifying
    /// the canonical digest. This is a test lookup aid, not an allocation
    /// authority.
    #[cfg(test)]
    pub fn recover_effect_at(
        &mut self,
        journal_sequence: u64,
        canonical_request: &[u8],
    ) -> JournalResult<RecoveryDecision> {
        self.require_live()?;
        let digest = Sha256Digest::of_bytes(canonical_request);
        let (_parent, _lock, loaded) = self.load_locked()?;
        require_active_invocation(&loaded.state, &self.invocation_id)?;
        let operation = loaded
            .state
            .operations
            .iter()
            .find(|operation| operation.journal_sequence == journal_sequence)
            .ok_or(OperationJournalError::OperationNotFound)?;
        if operation.canonical_request_sha256 != digest.to_hex() {
            return Err(OperationJournalError::CanonicalDigestMismatch);
        }
        recovery_decision(&loaded.state, operation, &self.agent_id, &self.adapter_id)
    }

    /// Return the exact already-durable terminal backend response for a
    /// recovered operation.  `PREPARED` and indeterminate records deliberately
    /// return `None`: they must recover through the backend under the same
    /// durable request ID and may never be upgraded into a terminal result.
    ///
    /// The caller must still re-run its typed response validator before
    /// releasing these bytes.  This method performs no backend I/O.
    pub(crate) fn replay_terminal_result(
        &mut self,
        prepared: &PreparedOperation,
    ) -> JournalResult<Option<Vec<u8>>> {
        self.require_live()?;
        validate_prepared_identity(prepared, self)?;
        let (_parent, _lock, loaded) = self.load_locked()?;
        require_active_invocation(&loaded.state, &self.invocation_id)?;
        let operation = loaded
            .state
            .operations
            .iter()
            .find(|operation| operation.journal_sequence == prepared.journal_sequence)
            .ok_or(OperationJournalError::OperationNotFound)?;
        validate_prepared_binding(&loaded.state, operation, prepared)?;
        match operation.state {
            PersistedOperationState::Prepared => Ok(None),
            PersistedOperationState::ResultRecorded
                if operation.outcome == Some(OperationOutcome::Indeterminate) =>
            {
                Ok(None)
            }
            PersistedOperationState::ResultRecorded => decode_terminal_result(operation).map(Some),
        }
    }

    /// Durably bind a closed outcome class and backend-result digest before the
    /// caller may return the backend result to the Agent. Definitive terminal
    /// responses retain their exact bounded bytes so a restart can return the
    /// same result without contacting or re-effecting the backend.
    pub fn record_result(
        &mut self,
        prepared: &PreparedOperation,
        backend_result: &[u8],
        completion: BackendCompletion<'_>,
    ) -> JournalResult<OperationEvidence> {
        let expected_protocol = match self.adapter_id.as_str() {
            "system_api" => crate::system_api::PROTOCOL,
            "accessibility" => crate::accessibility::PROTOCOL,
            _ => {
                return Err(OperationJournalError::InvalidArgument(
                    "journal adapter has no closed backend protocol",
                ));
            }
        };
        let classified = classify_backend_completion(
            backend_result,
            completion,
            expected_protocol,
            &prepared.request_id,
        );
        let semantic_result_sha256 = match classified.outcome {
            OperationOutcome::Success | OperationOutcome::BackendError => {
                canonical_semantic_result_digest(backend_result)?
            }
            // Indeterminate evidence is never ackable/exported. Keep a stable
            // observation identity without pretending malformed/partial bytes
            // form a semantic terminal result.
            OperationOutcome::Indeterminate => Sha256Digest::of_bytes(backend_result),
        };
        self.record_classified_result(prepared, backend_result, semantic_result_sha256, classified)
    }

    fn record_classified_result(
        &mut self,
        prepared: &PreparedOperation,
        backend_result: &[u8],
        semantic_result_sha256: Sha256Digest,
        classified: ClassifiedBackendCompletion,
    ) -> JournalResult<OperationEvidence> {
        self.require_live()?;
        validate_prepared_identity(prepared, self)?;
        let backend_result_sha256 = Sha256Digest::of_bytes(backend_result);
        let terminal_result_base64 = match classified.outcome {
            OperationOutcome::Success | OperationOutcome::BackendError => {
                if backend_result.is_empty() || backend_result.len() > crate::MAX_RESPONSE_BYTES {
                    return Err(OperationJournalError::CapacityExhausted);
                }
                Some(BASE64_STANDARD.encode(backend_result))
            }
            OperationOutcome::Indeterminate => None,
        };
        let (parent, lock, mut loaded) = self.load_locked()?;
        require_active_invocation(&loaded.state, &self.invocation_id)?;
        let index = loaded
            .state
            .operations
            .iter()
            .position(|operation| operation.journal_sequence == prepared.journal_sequence)
            .ok_or(OperationJournalError::OperationNotFound)?;
        validate_prepared_binding(&loaded.state, &loaded.state.operations[index], prepared)?;

        match loaded.state.operations[index].state {
            PersistedOperationState::Prepared => {
                loaded.state.operations[index].state = PersistedOperationState::ResultRecorded;
                loaded.state.operations[index].backend_result_sha256 =
                    Some(backend_result_sha256.to_hex());
                loaded.state.operations[index].backend_semantic_result_sha256 =
                    Some(semantic_result_sha256.to_hex());
                loaded.state.operations[index].backend_result_base64 =
                    terminal_result_base64.clone();
                loaded.state.operations[index].outcome = Some(classified.outcome);
                loaded.state.operations[index].backend_error_code =
                    classified.backend_error_code.clone();
                let evidence = operation_evidence(
                    &loaded.state,
                    &loaded.state.operations[index],
                    &self.agent_id,
                    &self.adapter_id,
                )?;
                self.publish_mutation(
                    &parent,
                    &lock,
                    Some(loaded.identity),
                    &loaded.state,
                    mutation_cas::DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
                )?;
                Ok(evidence)
            }
            PersistedOperationState::ResultRecorded => {
                let evidence = operation_evidence(
                    &loaded.state,
                    &loaded.state.operations[index],
                    &self.agent_id,
                    &self.adapter_id,
                )?;
                if evidence.raw_backend_result_sha256 != backend_result_sha256
                    || evidence.backend_result_sha256 != semantic_result_sha256
                    || evidence.outcome != classified.outcome
                    || evidence.backend_error_code != classified.backend_error_code
                    || loaded.state.operations[index].backend_result_base64
                        != terminal_result_base64
                {
                    return Err(OperationJournalError::EvidenceMismatch(
                        "result bytes, digest, outcome, or backend error code changed",
                    ));
                }
                Ok(evidence)
            }
        }
    }

    #[cfg(test)]
    fn record_result_for_test(
        &mut self,
        prepared: &PreparedOperation,
        backend_result: &[u8],
        outcome: OperationOutcome,
    ) -> JournalResult<OperationEvidence> {
        let backend_error_code = match outcome {
            OperationOutcome::Success => None,
            OperationOutcome::BackendError => Some("backend_error".to_string()),
            OperationOutcome::Indeterminate => Some("effect_indeterminate".to_string()),
        };
        self.record_classified_result(
            prepared,
            backend_result,
            // Test-only arbitrary byte fixtures intentionally do not model a
            // typed backend wire response. Keep their evidence deterministic
            // without weakening the production `record_result` canonicalizer.
            Sha256Digest::of_bytes(backend_result),
            ClassifiedBackendCompletion {
                outcome,
                backend_error_code,
            },
        )
    }

    /// Test-only legacy acknowledgement primitive. Acknowledge an invocation
    /// only when the caller supplies the exact,
    /// ordered adapter-journal evidence set and SHA-256 of the exact
    /// already-durable PlanReady outer receipt. This API cannot prove receipt
    /// custody by itself; only the future trusted outer-receipt consumer may
    /// call it. The acknowledgement records the current delivery attempt while
    /// exact evidence retains its original allocating attempt; those attempts
    /// may intentionally differ after recovery. Indeterminate evidence can
    /// never clear operations.
    #[cfg(test)]
    pub fn ack_invocation(
        &mut self,
        outer_receipt_sha256: Sha256Digest,
        exact_evidence: &[OperationEvidence],
    ) -> JournalResult<InvocationAcknowledgement> {
        self.require_live()?;
        if exact_evidence.is_empty() {
            return Err(OperationJournalError::EvidenceMismatch(
                "operation evidence set must not be empty",
            ));
        }
        let evidence_set_sha256 = evidence_set_digest(exact_evidence)?;
        let (parent, _lock, mut loaded) = self.load_locked()?;

        if loaded.state.operations.is_empty() {
            return find_idempotent_ack(
                &loaded.state,
                &self.invocation_id,
                exact_evidence,
                evidence_set_sha256,
                outer_receipt_sha256,
            );
        }
        require_active_invocation(&loaded.state, &self.invocation_id)?;
        let expected = loaded
            .state
            .operations
            .iter()
            .map(|operation| {
                operation_evidence(&loaded.state, operation, &self.agent_id, &self.adapter_id)
            })
            .collect::<JournalResult<Vec<_>>>()?;
        if expected
            .iter()
            .any(|evidence| evidence.outcome == OperationOutcome::Indeterminate)
        {
            return Err(OperationJournalError::InvalidTransition(
                "indeterminate operation cannot be acknowledged or discarded",
            ));
        }
        if expected != exact_evidence {
            return Err(OperationJournalError::EvidenceMismatch(
                "operation evidence set is not exact and ordered",
            ));
        }
        let first_journal_sequence = expected
            .first()
            .ok_or(OperationJournalError::EvidenceMismatch("missing evidence"))?
            .journal_sequence;
        let last_journal_sequence = expected
            .last()
            .ok_or(OperationJournalError::EvidenceMismatch("missing evidence"))?
            .journal_sequence;
        let operation_count =
            u32::try_from(expected.len()).map_err(|_| OperationJournalError::CapacityExhausted)?;
        let acknowledgement = InvocationAcknowledgement {
            invocation_id: self.invocation_id.clone(),
            delivery_provider_attempt_id: self.delivery_provider_attempt_id.clone(),
            first_journal_sequence,
            last_journal_sequence,
            operation_count,
            evidence_set_sha256,
            outer_receipt_sha256,
        };
        if loaded.state.acknowledgements.len() >= MAX_ACKNOWLEDGEMENTS {
            return Err(OperationJournalError::InvocationReuseIndexExhausted);
        }
        loaded.state.acknowledgements.push(AcknowledgementRecord {
            invocation_id: acknowledgement.invocation_id.clone(),
            delivery_provider_attempt_id: acknowledgement.delivery_provider_attempt_id.clone(),
            first_journal_sequence,
            last_journal_sequence,
            operation_count,
            evidence_set_sha256: evidence_set_sha256.to_hex(),
            outer_receipt_sha256: outer_receipt_sha256.to_hex(),
            acknowledgement_sha256: None,
            authenticated_ack_chain_sha256: None,
        });
        loaded.state.operations.clear();
        loaded.state.active_invocation_id = None;
        loaded.state.active_allocating_provider_attempt_id = None;
        loaded.state.active_allocation_binding = None;
        loaded.state.active_allocation_binding_sha256 = None;
        match publish_state(&parent, Some(loaded.identity), &loaded.state)? {
            PublishState::Durable => {}
            PublishState::PublishedDurabilityUncertain => {
                self.fail_stopped = true;
                return Err(OperationJournalError::DurabilityUncertain);
            }
        }
        Ok(acknowledgement)
    }

    /// Export the exact durable, definitive evidence set consumed by the
    /// daemon's V3 outer-receipt custody. The allocation binding is captured
    /// from the trusted context when the first PREPARED operation is written;
    /// a later recovery delivery attempt cannot replace it.
    pub fn evidence_snapshot(&mut self) -> JournalResult<DirectOperationJournalEvidenceSnapshotV1> {
        self.require_live()?;
        let (_parent, _lock, loaded) = self.load_locked()?;
        require_active_invocation(&loaded.state, &self.invocation_id)?;
        evidence_snapshot_from_state(&loaded.state, &self.agent_id, &self.adapter_id)
    }

    /// Export one authenticated terminal disposition only from the sealed,
    /// endpoint-specific replay-sync context. An external mutation-CAS
    /// session is mandatory even for an apparently empty journal: missing
    /// authority is a HOLD and can never be converted into `NoOperations`.
    pub(crate) fn terminal_disposition(
        &mut self,
        launch_authority: crate::trusted_context::AuthorizedReplaySyncContext<'_>,
    ) -> JournalResult<DirectOperationReplaySyncObservationV3> {
        let context = launch_authority.context();
        let launch_challenge_sha256 = launch_authority.launch_challenge_sha256();
        self.require_live()?;
        validate_replay_sync_context(self, context)?;
        if !is_nonzero_lower_sha256(launch_challenge_sha256) {
            return Err(OperationJournalError::InvalidArgument(
                "replay-sync launch challenge must be non-zero lowercase SHA-256",
            ));
        }
        let (parent, lock, loaded) = self.load_locked()?;
        self.fresh_validate_replay_sync_mutation_authority(&parent, &lock, &loaded)?;
        let payload = serde_json::to_vec(&loaded.state)
            .map_err(|error| corrupt(format!("could not encode journal payload: {error}")))?;
        let journal_state_sha256 = Sha256Digest::of_bytes(&payload).to_hex();
        let journal_file_identity_sha256 = replay_sync_file_identity_digest(
            loaded.identity,
            &journal_state_sha256,
            context.binding_sha256(),
        );
        let adapter = closed_adapter(&self.adapter_id)?;
        let terminal_state = if loaded.state.operations.is_empty() {
            let authenticated_terminal_sha256 = replay_sync_terminal_authentication_digest(
                b"no_operations",
                context,
                launch_challenge_sha256,
                &journal_state_sha256,
                &journal_file_identity_sha256,
            );
            DirectOperationAdapterTerminalStateV1::NoOperations {
                journal_epoch: loaded.state.epoch.clone(),
                journal_payload_sha256: journal_state_sha256.clone(),
                previous_ack_watermark: loaded.state.compacted_ack_watermark,
                previous_ack_chain_sha256: loaded.state.compacted_ack_chain_sha256.clone(),
                authenticated_terminal_sha256,
            }
        } else if loaded.state.operations.iter().any(|operation| {
            operation.state == PersistedOperationState::Prepared
                || operation.outcome == Some(OperationOutcome::Indeterminate)
        }) {
            let authenticated_hold_sha256 = replay_sync_terminal_authentication_digest(
                b"held_indeterminate",
                context,
                launch_challenge_sha256,
                &journal_state_sha256,
                &journal_file_identity_sha256,
            );
            DirectOperationAdapterTerminalStateV1::HeldIndeterminate {
                journal_epoch: loaded.state.epoch.clone(),
                journal_payload_sha256: journal_state_sha256.clone(),
                previous_ack_watermark: loaded.state.compacted_ack_watermark,
                previous_ack_chain_sha256: loaded.state.compacted_ack_chain_sha256.clone(),
                authenticated_hold_sha256,
            }
        } else {
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot: evidence_snapshot_from_state(
                    &loaded.state,
                    &self.agent_id,
                    &self.adapter_id,
                )?,
            }
        };
        let disposition = DirectOperationAdapterTerminalDispositionV1 {
            schema: ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA.to_string(),
            binding_sha256: context.binding_sha256().to_string(),
            invocation_id: context.invocation_id().to_string(),
            delivery_provider_attempt_id: context.delivery_provider_attempt_id().to_string(),
            provider_id: context.provider_id().to_string(),
            agent_id: context.agent_id().to_string(),
            adapter,
            terminal_state,
        };
        let observation = DirectOperationReplaySyncObservationV3 {
            schema: OPERATION_REPLAY_SYNC_OBSERVATION_V3_SCHEMA.to_string(),
            terminal_disposition_sha256: disposition.digest_sha256().map_err(|_| {
                OperationJournalError::EvidenceMismatch(
                    "replay-sync terminal disposition digest is invalid",
                )
            })?,
            terminal_disposition: disposition,
            journal_state_sha256,
            journal_file_identity_sha256,
        };
        observation.validate().map_err(|_| {
            OperationJournalError::EvidenceMismatch("replay-sync terminal observation is invalid")
        })?;
        Ok(observation)
    }

    /// Admit the exact root ACK and local terminal state before Android I/O.
    /// A live mutation-CAS session is required here, so an Android ACK is
    /// never attempted when local compaction authority is already absent.
    pub(crate) fn prepare_outer_ack_for_replay_sync<'a>(
        &mut self,
        launch_authority: crate::trusted_context::AuthorizedReplaySyncContext<'a>,
        inbox: &DirectOperationOuterAckInboxV3,
        ack_intent_sha256: &str,
    ) -> JournalResult<PreparedReplaySyncOuterAck<'a>> {
        let context = launch_authority.context();
        self.require_live()?;
        validate_replay_sync_context(self, context)?;
        inbox
            .validate()
            .map_err(|_| OperationJournalError::EvidenceMismatch("outer ACK v3 is invalid"))?;
        let expected_intent = inbox
            .operation_replay_sync_ack_intent_sha256()
            .map_err(|_| OperationJournalError::EvidenceMismatch("ACK intent is invalid"))?;
        if ack_intent_sha256 != expected_intent
            || inbox.acknowledgement.binding_sha256 != context.binding_sha256()
            || inbox.acknowledgement.invocation_id != context.invocation_id()
            || inbox.acknowledgement.delivery_provider_attempt_id
                != context.delivery_provider_attempt_id()
            || inbox.acknowledgement.provider_id != context.provider_id()
            || inbox.acknowledgement.agent_id != context.agent_id()
            || inbox.acknowledgement.adapter != context.adapter()
        {
            return Err(OperationJournalError::EvidenceMismatch(
                "ACK intent does not match the sealed replay-sync context",
            ));
        }

        let (parent, lock, loaded) = self.load_locked()?;
        self.fresh_validate_replay_sync_mutation_authority(&parent, &lock, &loaded)?;
        if loaded.state.operations.is_empty() {
            find_idempotent_outer_v3(
                &loaded.state,
                context.invocation_id(),
                context.delivery_provider_attempt_id(),
                inbox,
            )?;
        } else {
            require_active_invocation(&loaded.state, context.invocation_id())?;
            let snapshot =
                evidence_snapshot_from_state(&loaded.state, &self.agent_id, &self.adapter_id)?;
            if inbox.acknowledgement.journal_evidence_snapshot != snapshot {
                return Err(OperationJournalError::EvidenceMismatch(
                    "outer ACK v3 journal snapshot is not exact",
                ));
            }
        }
        Ok(PreparedReplaySyncOuterAck {
            launch_authority,
            inbox: inbox.clone(),
            ack_intent_sha256: expected_intent,
            binding_sha256: context.binding_sha256().to_string(),
        })
    }

    /// Consume a pre-admitted ACK only after the endpoint-specific Android
    /// helper returned the exact echo. Local compaction, fresh pathname
    /// readback and mutation-CAS committed-head capture occur in that order.
    pub(crate) fn apply_outer_ack_and_confirm(
        &mut self,
        prepared: PreparedReplaySyncOuterAck<'_>,
        android_ack: &crate::android_operation_replay_ack::VerifiedOperationReplayAck,
    ) -> JournalResult<DirectOperationReplaySyncAckConfirmationV3> {
        let context = prepared.context();
        self.require_live()?;
        validate_replay_sync_context(self, context)?;
        if prepared.binding_sha256 != context.binding_sha256() {
            return Err(OperationJournalError::EvidenceMismatch(
                "prepared replay-sync ACK binding changed",
            ));
        }
        android_ack.validate_for(&prepared).map_err(|_| {
            OperationJournalError::EvidenceMismatch(
                "Android ACK proof does not match the prepared replay-sync ACK",
            )
        })?;

        self.acknowledge_outer_v3(context.binding(), context.binding_sha256(), &prepared.inbox)?;

        let (parent, lock, loaded) = self.load_locked()?;
        self.fresh_validate_replay_sync_mutation_authority(&parent, &lock, &loaded)?;
        find_idempotent_outer_v3(
            &loaded.state,
            context.invocation_id(),
            context.delivery_provider_attempt_id(),
            &prepared.inbox,
        )?;
        let snapshot = &prepared.inbox.acknowledgement.journal_evidence_snapshot;
        if !loaded.state.operations.is_empty()
            || loaded.state.compacted_ack_watermark != snapshot.last_journal_sequence
            || loaded.state.compacted_ack_chain_sha256
                != prepared.inbox.chain_step.authenticated_ack_chain_sha256
        {
            return Err(OperationJournalError::EvidenceMismatch(
                "post-compaction journal readback is not the exact ACK successor",
            ));
        }
        let payload = serde_json::to_vec(&loaded.state)
            .map_err(|error| corrupt(format!("could not encode journal payload: {error}")))?;
        let post_compaction_journal_sha256 = Sha256Digest::of_bytes(&payload).to_hex();
        let journal_file_identity_sha256 = replay_sync_file_identity_digest(
            loaded.identity,
            &post_compaction_journal_sha256,
            context.binding_sha256(),
        );
        let mutation_cas_committed_head_sha256 = self
            .mutation_cas_session
            .as_ref()
            .ok_or(OperationJournalError::MutationAuthorityUnavailable)?
            .committed_head_sha256()
            .to_string();
        if !is_nonzero_lower_sha256(&mutation_cas_committed_head_sha256) {
            return Err(OperationJournalError::MutationAuthority(
                "mutation-CAS committed head is invalid after ACK compaction",
            ));
        }
        let confirmation = DirectOperationReplaySyncAckConfirmationV3 {
            schema: OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA.to_string(),
            ack_intent_sha256: prepared.ack_intent_sha256,
            android_ack_echo_sha256: android_ack.echo_sha256(),
            acknowledgement_sha256: prepared.inbox.acknowledgement_sha256,
            authenticated_ack_chain_sha256: prepared
                .inbox
                .chain_step
                .authenticated_ack_chain_sha256,
            compacted_ack_watermark: loaded.state.compacted_ack_watermark,
            post_compaction_journal_sha256,
            journal_file_identity_sha256,
            mutation_cas_committed_head_sha256,
        };
        confirmation.validate().map_err(|_| {
            OperationJournalError::EvidenceMismatch("replay-sync ACK confirmation is invalid")
        })?;
        Ok(confirmation)
    }

    /// Apply one root-custodied V3 outer acknowledgement. This crate-private
    /// primitive performs exact journal/snapshot/chain comparison and durable
    /// reclamation; only TrustedAdapterContext's fixed, authenticated inbox
    /// consumer may expose it to a product binary.
    fn acknowledge_outer_v3(
        &mut self,
        delivery_binding: &DirectOperationBinding,
        delivery_binding_sha256: &str,
        inbox: &DirectOperationOuterAckInboxV3,
    ) -> JournalResult<InvocationAcknowledgement> {
        self.require_live()?;
        validate_trusted_delivery_binding(
            Some(delivery_binding),
            Some(delivery_binding_sha256),
            &self.agent_id,
            &self.invocation_id,
            &self.delivery_provider_attempt_id,
        )?;
        inbox
            .validate()
            .map_err(|_| OperationJournalError::EvidenceMismatch("outer ACK v3 is invalid"))?;
        let acknowledgement = &inbox.acknowledgement;
        let adapter = closed_adapter(&self.adapter_id)?;
        if acknowledgement.binding_sha256 != delivery_binding_sha256
            || acknowledgement.invocation_id != self.invocation_id
            || acknowledgement.delivery_provider_attempt_id != self.delivery_provider_attempt_id
            || acknowledgement.provider_id != delivery_binding.stable_seed.provider_id
            || acknowledgement.agent_id != self.agent_id
            || acknowledgement.adapter != adapter
        {
            return Err(OperationJournalError::EvidenceMismatch(
                "outer ACK v3 does not match the trusted delivery binding",
            ));
        }

        let (parent, lock, mut loaded) = self.load_locked()?;
        if loaded.state.operations.is_empty() {
            return find_idempotent_outer_v3(
                &loaded.state,
                &self.invocation_id,
                &self.delivery_provider_attempt_id,
                inbox,
            );
        }
        require_active_invocation(&loaded.state, &self.invocation_id)?;
        let snapshot =
            evidence_snapshot_from_state(&loaded.state, &self.agent_id, &self.adapter_id)?;
        if acknowledgement.journal_evidence_snapshot != snapshot {
            return Err(OperationJournalError::EvidenceMismatch(
                "outer ACK v3 journal snapshot is not exact",
            ));
        }
        let allocation_binding = loaded.state.active_allocation_binding.as_ref().ok_or(
            OperationJournalError::EvidenceMismatch("trusted allocation binding is absent"),
        )?;
        snapshot
            .validate_for_allocation_binding(allocation_binding, adapter)
            .map_err(|_| {
                OperationJournalError::EvidenceMismatch(
                    "outer ACK v3 allocation binding is not exact",
                )
            })?;
        if loaded.state.acknowledgements.len() >= MAX_ACKNOWLEDGEMENTS {
            return Err(OperationJournalError::InvocationReuseIndexExhausted);
        }

        let evidence_set_sha256 = Sha256Digest::from_hex(&snapshot.evidence_sha256)?;
        let outer_receipt_sha256 = Sha256Digest::from_hex(&acknowledgement.outer_receipt_sha256)?;
        let operation_count = snapshot.journal_evidence_count;
        let result = InvocationAcknowledgement {
            invocation_id: self.invocation_id.clone(),
            delivery_provider_attempt_id: self.delivery_provider_attempt_id.clone(),
            first_journal_sequence: snapshot.first_journal_sequence,
            last_journal_sequence: snapshot.last_journal_sequence,
            operation_count,
            evidence_set_sha256,
            outer_receipt_sha256,
        };
        loaded.state.acknowledgements.push(AcknowledgementRecord {
            invocation_id: result.invocation_id.clone(),
            delivery_provider_attempt_id: result.delivery_provider_attempt_id.clone(),
            first_journal_sequence: result.first_journal_sequence,
            last_journal_sequence: result.last_journal_sequence,
            operation_count,
            evidence_set_sha256: evidence_set_sha256.to_hex(),
            outer_receipt_sha256: outer_receipt_sha256.to_hex(),
            acknowledgement_sha256: Some(inbox.acknowledgement_sha256.clone()),
            authenticated_ack_chain_sha256: Some(
                inbox.chain_step.authenticated_ack_chain_sha256.clone(),
            ),
        });
        loaded.state.compacted_ack_watermark = result.last_journal_sequence;
        loaded.state.compacted_ack_chain_sha256 =
            inbox.chain_step.authenticated_ack_chain_sha256.clone();
        loaded.state.operations.clear();
        loaded.state.active_invocation_id = None;
        loaded.state.active_allocating_provider_attempt_id = None;
        loaded.state.active_allocation_binding = None;
        loaded.state.active_allocation_binding_sha256 = None;
        self.publish_mutation(
            &parent,
            &lock,
            Some(loaded.identity),
            &loaded.state,
            mutation_cas::DirectOperationRuntimeAuthorityMutationKindV1::AcknowledgeOuterV2,
        )?;
        Ok(result)
    }

    #[cfg(test)]
    pub(crate) fn acknowledge_outer_v3_for_test(
        &mut self,
        delivery_binding: &DirectOperationBinding,
        delivery_binding_sha256: &str,
        inbox: &DirectOperationOuterAckInboxV3,
    ) -> JournalResult<InvocationAcknowledgement> {
        self.acknowledge_outer_v3(delivery_binding, delivery_binding_sha256, inbox)
    }

    /// Inspect unresolved operations without authorizing a backend call or
    /// allocating a new request ID.
    pub fn recovery_plan(&mut self) -> JournalResult<Option<RecoveryPlan>> {
        self.require_live()?;
        let (_parent, _lock, loaded) = self.load_locked()?;
        let Some(first) = loaded.state.operations.first() else {
            return Ok(None);
        };
        let operations = loaded
            .state
            .operations
            .iter()
            .map(recovery_operation)
            .collect::<JournalResult<Vec<_>>>()?;
        Ok(Some(RecoveryPlan {
            pending_invocation_id: first.invocation_id.clone(),
            pending_allocating_provider_attempt_id: first.allocating_provider_attempt_id.clone(),
            recovery_only: first.allocating_provider_attempt_id
                != self.delivery_provider_attempt_id,
            operations,
        }))
    }

    #[allow(dead_code)]
    fn initialize_or_validate(
        &self,
        initialize_missing: bool,
        required_open_state_sha256: Option<Sha256Digest>,
        required_open_file_identity: Option<FileIdentity>,
    ) -> JournalResult<()> {
        let parent = SecureParent::open(&self.path)?;
        self.validate_trusted_parent(&parent)?;
        let _lock = JournalLock::acquire(&parent, self.lock_timeout)?;
        match load_optional(&parent)? {
            Some(loaded) => {
                validate_store_identity(&loaded.state, &self.agent_id, &self.adapter_id)?;
                validate_pinned_epoch(&loaded.state, self.pinned_epoch.as_deref())?;
                if required_open_file_identity.is_some_and(|required| {
                    loaded.identity.device != required.device
                        || loaded.identity.inode != required.inode
                }) {
                    return Err(OperationJournalError::IdentityMismatch);
                }
                if let Some(required_sha256) = required_open_state_sha256
                    && Sha256Digest::of_bytes(&encode_state(&loaded.state)?) != required_sha256
                {
                    return Err(OperationJournalError::IdentityMismatch);
                }
                if !self.device_conformance_epoch_authority_is_pending() {
                    validate_prepared_transport_ack_runtime_authorities(
                        &loaded.state,
                        self.operation_epoch_authority_sha256,
                    )?;
                }
                validate_active_delivery_os_identity(
                    &loaded.state,
                    self.trusted_delivery_binding.as_ref(),
                )
            }
            None => {
                if !initialize_missing {
                    return Err(OperationJournalError::MissingTrustedJournal);
                }
                let state = JournalState::new(self.agent_id.clone(), self.adapter_id.clone())?;
                match publish_state(&parent, None, &state)? {
                    PublishState::Durable => Ok(()),
                    PublishState::PublishedDurabilityUncertain => {
                        Err(OperationJournalError::DurabilityUncertain)
                    }
                }
            }
        }
    }

    fn require_live(&self) -> JournalResult<()> {
        if self.fail_stopped {
            Err(OperationJournalError::ReopenRequired)
        } else {
            Ok(())
        }
    }

    fn device_conformance_epoch_authority_is_pending(&self) -> bool {
        self.device_conformance_epoch_authority_bridge
            && self.operation_epoch_authority_sha256.is_none()
    }

    fn load_locked(&self) -> JournalResult<(SecureParent, JournalLock, LoadedJournal)> {
        let parent = SecureParent::open(&self.path)?;
        self.validate_trusted_parent(&parent)?;
        let lock = JournalLock::acquire(&parent, self.lock_timeout)?;
        let loaded = load_optional(&parent)?.ok_or_else(|| {
            OperationJournalError::Corrupt(
                "initialized journal disappeared instead of failing closed".to_string(),
            )
        })?;
        validate_store_identity(&loaded.state, &self.agent_id, &self.adapter_id)?;
        validate_pinned_epoch(&loaded.state, self.pinned_epoch.as_deref())?;
        if !self.device_conformance_epoch_authority_is_pending() {
            validate_prepared_transport_ack_runtime_authorities(
                &loaded.state,
                self.operation_epoch_authority_sha256,
            )?;
        }
        validate_active_delivery_os_identity(
            &loaded.state,
            self.trusted_delivery_binding.as_ref(),
        )?;
        Ok((parent, lock, loaded))
    }

    /// Bind one replay-sync observation to a fresh external OBSERVE of the
    /// exact named journal version while its writer lock and retained inode
    /// remain live. Presence of a mutation-CAS session is never sufficient:
    /// rollback, replacement or authority denial consumes the affine session
    /// and fail-stops this journal handle.
    fn fresh_validate_replay_sync_mutation_authority(
        &mut self,
        parent: &SecureParent,
        lock: &JournalLock,
        loaded: &LoadedJournal,
    ) -> JournalResult<()> {
        let observed = (|| {
            lock.revalidate(parent)?;
            let retained = open_private_retained(
                &parent.directory,
                &parent.destination_name,
                MAX_JOURNAL_BYTES,
            )?;
            if retained.identity.device != loaded.identity.device
                || retained.identity.inode != loaded.identity.inode
                || encode_state(&loaded.state)? != retained.bytes
            {
                return Err(OperationJournalError::IdentityMismatch);
            }
            retained.revalidate(&parent.directory)?;
            let version = retained_journal_version(&retained)?;
            Ok((retained, version))
        })();
        let (retained, version) = match observed {
            Ok(observed) => observed,
            Err(error) => {
                self.fail_stopped = true;
                return Err(error);
            }
        };
        let Some(session) = self.mutation_cas_session.take() else {
            self.fail_stopped = true;
            return Err(OperationJournalError::MutationAuthorityUnavailable);
        };
        let current = match session.validate_current(version) {
            crate::direct_operation_runtime_authority_mutation_cas_client::ObserveTransition::Current(
                current,
            ) => current,
            crate::direct_operation_runtime_authority_mutation_cas_client::ObserveTransition::FailStopped(
                _failed,
            ) => {
                self.fail_stopped = true;
                return Err(OperationJournalError::MutationAuthority(
                    "replay-sync journal version was not freshly observed",
                ));
            }
        };
        if let Err(error) = lock
            .revalidate(parent)
            .and_then(|()| retained.revalidate(&parent.directory))
        {
            self.fail_stopped = true;
            return Err(error);
        }
        self.mutation_cas_session = Some(current);
        Ok(())
    }

    fn validate_trusted_parent(&self, parent: &SecureParent) -> JournalResult<()> {
        let Some(trusted) = &self.trusted_state_directory else {
            return Ok(());
        };
        let expected = trusted.metadata()?;
        let actual = parent.directory.metadata()?;
        if !expected.is_dir()
            || expected.nlink() == 0
            || expected.dev() != actual.dev()
            || expected.ino() != actual.ino()
        {
            return Err(OperationJournalError::IdentityMismatch);
        }
        Ok(())
    }

    fn activate_replay_authority(
        &mut self,
        authority: crate::direct_operation_runtime_authority_store_session::FreshlyObservedReplayAuthorityStore,
    ) -> JournalResult<()> {
        use crate::direct_operation_runtime_authority_mutation_cas_client::{
            CommitTransition, LocalPublicationTransition, ReconcileTransition,
            ReplayMutationCasActivation, ReprepareTransition, SealedCommittedMutationCasSession,
            SealedLocalReconcileObservations, activate_same_store_replay,
        };

        let result = (|| -> JournalResult<SealedCommittedMutationCasSession> {
            let (parent, lock, _loaded) = self.load_locked()?;
            let local = ReopenedReplayLocalState::reopen(
                &parent,
                &lock,
                authority.lineage().clone(),
                authority.committed_head().clone(),
            )?;
            let seal = MutationCasJournalSeal { _private: () };
            let sealed_local = local.sealed_cas_state(&seal)?;
            let activation = activate_same_store_replay(authority, sealed_local)
                .map_err(|error| OperationJournalError::ReplayAuthority(format!("{error:?}")))?;

            let current = match (activation, local) {
                (
                    ReplayMutationCasActivation::Current(current),
                    ReopenedReplayLocalState::Clean {
                        parent,
                        lock,
                        named_journal,
                    },
                ) => {
                    lock.revalidate(parent)?;
                    named_journal.revalidate(&parent.directory)?;
                    current
                }
                (ReplayMutationCasActivation::Cleanup(terminal), local) => {
                    let observations = local.cleanup_after_authority_terminal(&seal)?;
                    replay_current_after_cleanup(terminal, observations)?
                }
                (ReplayMutationCasActivation::Reconcile(failed, observations), local) => {
                    match failed.reconcile(observations) {
                        ReconcileTransition::NoMutation(terminal)
                        | ReconcileTransition::Committed(terminal) => {
                            let observations = local.cleanup_after_authority_terminal(&seal)?;
                            replay_current_after_cleanup(terminal, observations)?
                        }
                        ReconcileTransition::ResumeExactPreparedPublication(continuation) => {
                            let ReopenedReplayLocalState::Staged(stage) = local else {
                                return Err(OperationJournalError::ReplayAuthority(
                                    "authority requested staged replay publication for a different local layout"
                                        .to_string(),
                                ));
                            };
                            let prepared = match continuation.reprepare() {
                                ReprepareTransition::Prepared(prepared) => prepared,
                                ReprepareTransition::FailStopped(_)
                                | ReprepareTransition::Hold(_) => {
                                    return Err(OperationJournalError::ReplayAuthority(
                                        "exact staged replay PREPARE failed closed".to_string(),
                                    ));
                                }
                            };
                            let published_stage = (*stage).publish()?;
                            let named_journal_version = published_stage.named_journal_version()?;
                            let published = match prepared
                                .bind_journal_publication(&seal, named_journal_version)
                            {
                                LocalPublicationTransition::Published(published) => published,
                                LocalPublicationTransition::FailStopped(_) => {
                                    return Err(OperationJournalError::ReplayAuthority(
                                        "staged replay publication did not bind the prepared head"
                                            .to_string(),
                                    ));
                                }
                            };
                            let terminal = match published.commit() {
                                CommitTransition::Committed(terminal) => terminal,
                                CommitTransition::FailStopped(_) => {
                                    return Err(OperationJournalError::ReplayAuthority(
                                        "staged replay COMMIT failed closed".to_string(),
                                    ));
                                }
                            };
                            let (writer_lock_identity_sha256, named_journal_version) =
                                published_stage.cleanup_after_commit()?;
                            let observations =
                                SealedLocalReconcileObservations::after_journal_cleanup(
                                    &seal,
                                    writer_lock_identity_sha256,
                                    named_journal_version,
                                );
                            replay_current_after_cleanup(terminal, observations)?
                        }
                        ReconcileTransition::RetryExactCommit(continuation) => {
                            let ReopenedReplayLocalState::Published(published_stage) = local else {
                                return Err(OperationJournalError::ReplayAuthority(
                                    "authority requested exact replay COMMIT for a different local layout"
                                        .to_string(),
                                ));
                            };
                            let prepared = match continuation.reprepare() {
                                ReprepareTransition::Prepared(prepared) => prepared,
                                ReprepareTransition::FailStopped(_)
                                | ReprepareTransition::Hold(_) => {
                                    return Err(OperationJournalError::ReplayAuthority(
                                        "exact published replay PREPARE failed closed".to_string(),
                                    ));
                                }
                            };
                            let named_journal_version = published_stage.named_journal_version()?;
                            let published = match prepared
                                .bind_journal_publication(&seal, named_journal_version)
                            {
                                LocalPublicationTransition::Published(published) => published,
                                LocalPublicationTransition::FailStopped(_) => {
                                    return Err(OperationJournalError::ReplayAuthority(
                                        "published replay did not bind the prepared head"
                                            .to_string(),
                                    ));
                                }
                            };
                            let terminal = match published.commit() {
                                CommitTransition::Committed(terminal) => terminal,
                                CommitTransition::FailStopped(_) => {
                                    return Err(OperationJournalError::ReplayAuthority(
                                        "published replay COMMIT failed closed".to_string(),
                                    ));
                                }
                            };
                            let (writer_lock_identity_sha256, named_journal_version) =
                                (*published_stage).cleanup_after_authority_confirmation()?;
                            let observations =
                                SealedLocalReconcileObservations::after_journal_cleanup(
                                    &seal,
                                    writer_lock_identity_sha256,
                                    named_journal_version,
                                );
                            replay_current_after_cleanup(terminal, observations)?
                        }
                        ReconcileTransition::Hold(_) => {
                            return Err(OperationJournalError::ReplayAuthority(
                                "same-store restart reconciliation held for reopen".to_string(),
                            ));
                        }
                    }
                }
                (ReplayMutationCasActivation::Current(_), _) => {
                    return Err(OperationJournalError::ReplayAuthority(
                        "authority classified a non-clean replay layout as current".to_string(),
                    ));
                }
            };
            lock.revalidate(&parent)?;
            Ok(current)
        })();

        match result {
            Ok(current) => {
                self.mutation_cas_session = Some(current);
                Ok(())
            }
            Err(error) => {
                self.fail_stopped = true;
                Err(error)
            }
        }
    }

    fn publish_mutation(
        &mut self,
        parent: &SecureParent,
        lock: &JournalLock,
        expected: Option<FileIdentity>,
        state: &JournalState,
        mutation_kind: mutation_cas::DirectOperationRuntimeAuthorityMutationKindV1,
    ) -> JournalResult<()> {
        use crate::direct_operation_runtime_authority_mutation_cas_client::{
            CommitTransition, DurableStageTransition, LocalPublicationTransition,
            ObserveTransition, PlanTransition, PrepareTransition, SealedLocalReconcileObservations,
            SealedWriterLockWitness,
        };

        if self.mutation_cas_session.is_none() {
            #[cfg(test)]
            let explicitly_legacy_test_fixture = self.legacy_mutation_without_cas_for_test;
            #[cfg(not(test))]
            let explicitly_legacy_test_fixture = false;
            if self.trusted_state_directory.is_some() && !explicitly_legacy_test_fixture {
                self.fail_stopped = true;
                return Err(OperationJournalError::MutationAuthorityUnavailable);
            }
            return match publish_state(parent, expected, state)? {
                PublishState::Durable => Ok(()),
                PublishState::PublishedDurabilityUncertain => {
                    self.fail_stopped = true;
                    Err(OperationJournalError::DurabilityUncertain)
                }
            };
        }

        if let Err(error) = validate_expected_destination(parent, expected) {
            self.fail_stopped = true;
            return Err(error);
        }
        let candidate = match FsyncedMutationCandidate::materialize(parent, lock, state) {
            Ok(candidate) => candidate,
            Err(error) => {
                self.fail_stopped = true;
                return Err(error);
            }
        };
        let (current_journal_version, proposed_journal_version, writer_lock_identity_sha256) =
            match (
                candidate.current_journal_version(),
                candidate.proposed_journal_version(),
                lock.identity_sha256(parent),
            ) {
                (Ok(current), Ok(proposed), Ok(writer_lock)) => {
                    (current, proposed, writer_lock.to_hex())
                }
                (current, proposed, writer_lock) => {
                    self.fail_stopped = true;
                    candidate.cleanup_before_prepare()?;
                    return Err(current
                        .err()
                        .or_else(|| proposed.err())
                        .or_else(|| writer_lock.err())
                        .expect("one local version observation failed"));
                }
            };
        let mutation_nonce_sha256 = match fresh_mutation_nonce_sha256() {
            Ok(nonce) => nonce,
            Err(error) => {
                self.fail_stopped = true;
                candidate.cleanup_before_prepare()?;
                return Err(error);
            }
        };
        let seal = MutationCasJournalSeal { _private: () };
        let session = self
            .mutation_cas_session
            .take()
            .expect("same-store mutation session was checked above");
        let current = match session.validate_current(current_journal_version.clone()) {
            ObserveTransition::Current(current) => current,
            ObserveTransition::FailStopped(_failed) => {
                self.fail_stopped = true;
                candidate.cleanup_before_prepare()?;
                return Err(OperationJournalError::MutationAuthority(
                    "current journal version was not externally observed",
                ));
            }
        };
        let writer_lock = SealedWriterLockWitness::from_journal(&seal, writer_lock_identity_sha256);
        let planned = match current.plan_prepare(
            writer_lock,
            mutation_kind,
            current_journal_version,
            proposed_journal_version,
            mutation_nonce_sha256,
        ) {
            PlanTransition::Planned(planned) => planned,
            PlanTransition::FailStopped(_failed) => {
                self.fail_stopped = true;
                candidate.cleanup_before_prepare()?;
                return Err(OperationJournalError::MutationAuthority(
                    "mutation intent did not bind the current authority head",
                ));
            }
        };
        let (lineage, committed_head, intent) = planned.journal_stage_records(&seal);
        let stage_plan = match LocalMutationStagePlan::new(lineage, committed_head, intent) {
            Ok(plan) => plan,
            Err(error) => {
                self.fail_stopped = true;
                candidate.cleanup_before_prepare()?;
                return Err(error);
            }
        };
        let stage = match candidate.seal(stage_plan) {
            Ok(stage) => stage,
            Err(error) => {
                self.fail_stopped = true;
                return Err(error);
            }
        };
        let proof = match stage.sealed_cas_proof(&seal) {
            Ok(proof) => proof,
            Err(error) => {
                self.fail_stopped = true;
                stage.cleanup_before_prepare()?;
                return Err(error);
            }
        };
        let staged = match planned.bind_durable_stage(proof) {
            DurableStageTransition::Staged(staged) => staged,
            DurableStageTransition::FailStopped(_failed) => {
                self.fail_stopped = true;
                stage.cleanup_before_prepare()?;
                return Err(OperationJournalError::MutationAuthority(
                    "durable local stage did not bind the immutable mutation intent",
                ));
            }
        };
        let prepared = match staged.send_prepare() {
            PrepareTransition::Prepared(prepared) => prepared,
            PrepareTransition::Retryable(retryable) => match retryable.retry() {
                PrepareTransition::Prepared(prepared) => prepared,
                PrepareTransition::Retryable(retryable) => {
                    let _failed = retryable.abandon_not_applied();
                    self.fail_stopped = true;
                    stage.cleanup_before_prepare()?;
                    return Err(OperationJournalError::MutationAuthority(
                        "mutation PREPARE was provably not admitted",
                    ));
                }
                PrepareTransition::FailStopped(failed) => {
                    self.fail_stopped = true;
                    if !failed.durable_stage_must_be_retained() {
                        stage.cleanup_before_prepare()?;
                    }
                    return Err(OperationJournalError::MutationAuthority(
                        "mutation PREPARE retry failed closed",
                    ));
                }
            },
            PrepareTransition::FailStopped(failed) => {
                self.fail_stopped = true;
                if !failed.durable_stage_must_be_retained() {
                    stage.cleanup_before_prepare()?;
                }
                return Err(OperationJournalError::MutationAuthority(
                    "mutation PREPARE failed closed",
                ));
            }
        };

        let published_stage = match stage.publish() {
            Ok(published) => published,
            Err(error) => {
                let _failed = prepared.local_publication_uncertain();
                self.fail_stopped = true;
                return Err(error);
            }
        };
        let named_journal_version = match published_stage.named_journal_version() {
            Ok(version) => version,
            Err(error) => {
                let _failed = prepared.local_publication_uncertain();
                self.fail_stopped = true;
                return Err(error);
            }
        };
        let published = match prepared.bind_journal_publication(&seal, named_journal_version) {
            LocalPublicationTransition::Published(published) => published,
            LocalPublicationTransition::FailStopped(_failed) => {
                self.fail_stopped = true;
                return Err(OperationJournalError::MutationAuthority(
                    "named journal publication did not bind the prepared head",
                ));
            }
        };
        let committed = match published.commit() {
            CommitTransition::Committed(committed) => committed,
            CommitTransition::FailStopped(_failed) => {
                self.fail_stopped = true;
                return Err(OperationJournalError::MutationAuthority(
                    "mutation COMMIT failed closed",
                ));
            }
        };
        let (writer_lock_identity_sha256, named_journal_version) =
            match published_stage.cleanup_after_commit() {
                Ok(observations) => observations,
                Err(error) => {
                    self.fail_stopped = true;
                    return Err(error);
                }
            };
        let observations = SealedLocalReconcileObservations::after_journal_cleanup(
            &seal,
            writer_lock_identity_sha256,
            named_journal_version,
        );
        match committed.reopen_after_local_cleanup(observations) {
            ObserveTransition::Current(current) => {
                self.mutation_cas_session = Some(current);
                Ok(())
            }
            ObserveTransition::FailStopped(_failed) => {
                self.fail_stopped = true;
                Err(OperationJournalError::MutationAuthority(
                    "fresh post-COMMIT authority observation failed closed",
                ))
            }
        }
    }
}

impl JournalState {
    fn new(agent_id: String, adapter_id: String) -> JournalResult<Self> {
        Ok(Self {
            agent_id,
            adapter_id,
            epoch: fresh_journal_epoch()?,
            next_sequence: 1,
            active_invocation_id: None,
            active_allocating_provider_attempt_id: None,
            active_allocation_binding: None,
            active_allocation_binding_sha256: None,
            compacted_ack_watermark: 0,
            compacted_ack_chain_sha256: ZERO_DIGEST_HEX.to_string(),
            acknowledgements: Vec::new(),
            operations: Vec::new(),
        })
    }
}

/// Exact empty v5 journal candidate used only by the source-only first-use
/// provision ceremony.  Its bytes are produced by the same encoder consumed
/// by normal journal open; a second schema implementation is forbidden.
pub(crate) struct CanonicalJournalGenesis {
    bytes: Vec<u8>,
    agent_id: String,
    adapter_id: String,
    epoch: String,
    bytes_sha256: Sha256Digest,
}

impl CanonicalJournalGenesis {
    pub(crate) fn new(agent_id: &str, adapter_id: &str) -> JournalResult<Self> {
        if !valid_identity(agent_id) || !valid_identity(adapter_id) {
            return Err(OperationJournalError::InvalidArgument(
                "invalid first-use journal identity",
            ));
        }
        let state = JournalState::new(agent_id.to_string(), adapter_id.to_string())?;
        let bytes = encode_state(&state)?;
        let candidate = Self {
            bytes_sha256: Sha256Digest::of_bytes(&bytes),
            bytes,
            agent_id: state.agent_id,
            adapter_id: state.adapter_id,
            epoch: state.epoch,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    pub(crate) fn validate(&self) -> JournalResult<()> {
        Self::validate_exact(
            &self.bytes,
            &self.agent_id,
            &self.adapter_id,
            &self.epoch,
            self.bytes_sha256,
        )
    }

    pub(crate) fn validate_exact(
        bytes: &[u8],
        agent_id: &str,
        adapter_id: &str,
        epoch: &str,
        bytes_sha256: Sha256Digest,
    ) -> JournalResult<()> {
        let state = decode_state(bytes)?;
        if state.agent_id != agent_id
            || state.adapter_id != adapter_id
            || state.epoch != epoch
            || state.next_sequence != 1
            || state.active_invocation_id.is_some()
            || state.active_allocating_provider_attempt_id.is_some()
            || state.active_allocation_binding.is_some()
            || state.active_allocation_binding_sha256.is_some()
            || state.compacted_ack_watermark != 0
            || state.compacted_ack_chain_sha256 != ZERO_DIGEST_HEX
            || !state.acknowledgements.is_empty()
            || !state.operations.is_empty()
            || Sha256Digest::of_bytes(bytes) != bytes_sha256
        {
            return Err(OperationJournalError::IdentityMismatch);
        }
        Ok(())
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn epoch(&self) -> &str {
        &self.epoch
    }

    pub(crate) const fn bytes_sha256(&self) -> Sha256Digest {
        self.bytes_sha256
    }
}

#[allow(dead_code)]
fn validate_constructor_arguments(
    path: &Path,
    agent_id: &str,
    adapter_id: &str,
    invocation_id: &str,
    delivery_provider_attempt_id: &str,
    lock_timeout: Duration,
) -> JournalResult<()> {
    if !path.is_absolute() {
        return Err(OperationJournalError::InvalidArgument(
            "journal path must be absolute",
        ));
    }
    if lock_timeout.is_zero() || lock_timeout > LOCK_TIMEOUT {
        return Err(OperationJournalError::InvalidArgument(
            "lock timeout must be non-zero and bounded",
        ));
    }
    for (name, value) in [
        ("agent_id", agent_id),
        ("adapter_id", adapter_id),
        ("invocation_id", invocation_id),
    ] {
        if !valid_identity(value) {
            return Err(OperationJournalError::InvalidArgument(match name {
                "agent_id" => "invalid agent_id",
                "adapter_id" => "invalid adapter_id",
                _ => "invalid invocation_id",
            }));
        }
    }
    if !valid_provider_attempt_id(delivery_provider_attempt_id) {
        return Err(OperationJournalError::InvalidArgument(
            "invalid delivery_provider_attempt_id",
        ));
    }
    Ok(())
}

fn validate_trusted_delivery_binding(
    binding: Option<&DirectOperationBinding>,
    binding_sha256: Option<&str>,
    agent_id: &str,
    invocation_id: &str,
    delivery_provider_attempt_id: &str,
) -> JournalResult<()> {
    match (binding, binding_sha256) {
        (None, None) => Ok(()),
        (Some(binding), Some(binding_sha256)) => {
            binding
                .validate()
                .map_err(|_| OperationJournalError::InvalidArgument("invalid trusted binding"))?;
            let expected_digest = binding.digest_sha256().map_err(|_| {
                OperationJournalError::InvalidArgument("invalid trusted binding digest")
            })?;
            if binding_sha256 != expected_digest
                || binding.stable_seed.agent_id != agent_id
                || binding.invocation_id != invocation_id
                || binding.attempt.delivery_provider_attempt_id != delivery_provider_attempt_id
            {
                return Err(OperationJournalError::IdentityMismatch);
            }
            Ok(())
        }
        _ => Err(OperationJournalError::InvalidArgument(
            "trusted binding and digest must be supplied together",
        )),
    }
}

fn validate_active_delivery_os_identity(
    state: &JournalState,
    delivery_binding: Option<&DirectOperationBinding>,
) -> JournalResult<()> {
    let (Some(allocation_binding), Some(delivery_binding)) =
        (state.active_allocation_binding.as_ref(), delivery_binding)
    else {
        return Ok(());
    };
    if allocation_binding.workflow_id_sha256 != delivery_binding.workflow_id_sha256
        || allocation_binding.agent_identity_key_sha256
            != delivery_binding.agent_identity_key_sha256
        || allocation_binding.agent_executable_sha256 != delivery_binding.agent_executable_sha256
    {
        return Err(OperationJournalError::IdentityMismatch);
    }
    Ok(())
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_provider_attempt_id(value: &str) -> bool {
    value
        .strip_prefix(trillionnium_os_types::direct_operation::PROVIDER_ATTEMPT_ID_PREFIX)
        .is_some_and(|digest| digest.len() == DIGEST_HEX_BYTES && is_lower_hex(digest))
}

fn valid_tool_call_id(value: &str) -> bool {
    value
        .strip_prefix(TOOL_CALL_ID_PREFIX)
        .is_some_and(|digest| digest.len() == DIGEST_HEX_BYTES && is_lower_hex(digest))
}

#[cfg(test)]
fn test_tool_call_id(adapter_effect_ordinal: u64) -> String {
    format!(
        "{TOOL_CALL_ID_PREFIX}{}",
        Sha256Digest::of_bytes(
            format!("test-os-tool-call-ordinal:{adapter_effect_ordinal}").as_bytes()
        )
        .to_hex()
    )
}

fn validate_store_identity(
    state: &JournalState,
    agent_id: &str,
    adapter_id: &str,
) -> JournalResult<()> {
    if state.agent_id == agent_id && state.adapter_id == adapter_id {
        Ok(())
    } else {
        Err(OperationJournalError::IdentityMismatch)
    }
}

fn validate_pinned_epoch(state: &JournalState, pinned_epoch: Option<&str>) -> JournalResult<()> {
    if pinned_epoch.is_some_and(|epoch| state.epoch != epoch) {
        Err(OperationJournalError::FirstUseEpochMismatch)
    } else {
        Ok(())
    }
}

fn require_active_invocation(state: &JournalState, invocation_id: &str) -> JournalResult<()> {
    let Some(active) = state.operations.first() else {
        return Err(OperationJournalError::OperationNotFound);
    };
    if active.invocation_id != invocation_id {
        return Err(OperationJournalError::RecoveryRequired {
            pending_invocation_id: active.invocation_id.clone(),
        });
    }
    Ok(())
}

fn generated_request_id(
    epoch: &str,
    journal_sequence: u64,
    canonical_request_sha256: Sha256Digest,
) -> JournalResult<String> {
    if !valid_journal_epoch(epoch)
        || journal_sequence == 0
        || journal_sequence > MAX_JOURNAL_SEQUENCE
    {
        return Err(OperationJournalError::CapacityExhausted);
    }
    let digest = canonical_request_sha256.to_hex();
    let request_id = format!("{REQUEST_ID_PREFIX}:{epoch}:{journal_sequence}:{digest}");
    if !crate::valid_request_id(&request_id) {
        return Err(OperationJournalError::Corrupt(
            "generated request_id violated the direct-tool request identity contract".to_string(),
        ));
    }
    Ok(request_id)
}

fn validate_prepared_identity(
    prepared: &PreparedOperation,
    journal: &OperationJournal,
) -> JournalResult<()> {
    if prepared.agent_id != journal.agent_id
        || prepared.adapter_id != journal.adapter_id
        || prepared.invocation_id != journal.invocation_id
        || !valid_provider_attempt_id(&prepared.allocating_provider_attempt_id)
        || !valid_tool_call_id(&prepared.os_tool_call_id)
        || prepared.adapter_effect_ordinal >= MAX_ACTIVE_OPERATIONS as u64
    {
        return Err(OperationJournalError::EvidenceMismatch(
            "prepared token identity changed",
        ));
    }
    Ok(())
}

fn validate_prepared_binding(
    state: &JournalState,
    operation: &OperationRecord,
    prepared: &PreparedOperation,
) -> JournalResult<()> {
    if state.epoch != prepared.epoch
        || operation.invocation_id != prepared.invocation_id
        || operation.allocating_provider_attempt_id != prepared.allocating_provider_attempt_id
        || operation.os_tool_call_id != prepared.os_tool_call_id
        || operation.adapter_effect_ordinal != prepared.adapter_effect_ordinal
        || operation.journal_sequence != prepared.journal_sequence
        || operation.request_id != prepared.request_id
        || operation.canonical_request_sha256 != prepared.canonical_request_sha256.to_hex()
    {
        return Err(OperationJournalError::EvidenceMismatch(
            "prepared token does not match the durable operation",
        ));
    }
    Ok(())
}

fn validate_stored_prepared_transport_ack(
    state: &JournalState,
    operation: &OperationRecord,
    acknowledgement: &DirectOperationToolCallPreparedAckV3,
) -> JournalResult<()> {
    let binding = state
        .active_allocation_binding
        .as_ref()
        .ok_or_else(|| corrupt("stored PREPARED acknowledgement has no allocation binding"))?;
    let binding_sha256 = state
        .active_allocation_binding_sha256
        .as_deref()
        .ok_or_else(|| corrupt("stored PREPARED acknowledgement has no binding digest"))?;
    let adapter = closed_adapter(&state.adapter_id)?;
    let mut envelope = DirectOperationToolCallEnvelopeV3 {
        schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
        binding_sha256: binding_sha256.to_string(),
        invocation_id: binding.invocation_id.clone(),
        delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
        provider_id: binding.stable_seed.provider_id.clone(),
        agent_id: binding.stable_seed.agent_id.clone(),
        adapter,
        os_tool_call_id: operation.os_tool_call_id.clone(),
        adapter_effect_ordinal: operation.adapter_effect_ordinal,
        canonical_request_sha256: operation.canonical_request_sha256.clone(),
        envelope_sha256: String::new(),
    };
    envelope.envelope_sha256 = envelope
        .digest_sha256()
        .map_err(|_| corrupt("stored PREPARED acknowledgement envelope is invalid"))?;
    acknowledgement
        .validate_for_envelope(&envelope)
        .map_err(|_| corrupt("stored PREPARED acknowledgement is invalid"))?;
    if acknowledgement.journal_epoch != state.epoch
        || acknowledgement.journal_sequence != operation.journal_sequence
        || acknowledgement.backend_request_id_sha256
            != Sha256Digest::of_bytes(operation.request_id.as_bytes()).to_hex()
    {
        return Err(corrupt(
            "stored PREPARED acknowledgement does not match the durable operation",
        ));
    }
    Ok(())
}

fn validate_prepared_transport_ack_runtime_authority(
    acknowledgement: &DirectOperationToolCallPreparedAckV3,
    operation_epoch_authority_sha256: Option<Sha256Digest>,
) -> JournalResult<()> {
    let expected = operation_epoch_authority_sha256
        .ok_or(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)?
        .to_hex();
    if acknowledgement.operation_epoch_authority_sha256 != expected {
        return Err(OperationJournalError::EvidenceMismatch(
            "stored PREPARED acknowledgement operation-epoch authority does not match current external runtime authority",
        ));
    }
    Ok(())
}

fn validate_prepared_transport_ack_runtime_authorities(
    state: &JournalState,
    operation_epoch_authority_sha256: Option<Sha256Digest>,
) -> JournalResult<()> {
    for acknowledgement in state
        .operations
        .iter()
        .filter_map(|operation| operation.prepared_transport_ack.as_ref())
    {
        validate_prepared_transport_ack_runtime_authority(
            acknowledgement,
            operation_epoch_authority_sha256,
        )?;
    }
    Ok(())
}

fn prepared_operation(
    state: &JournalState,
    operation: &OperationRecord,
    agent_id: &str,
    adapter_id: &str,
) -> JournalResult<PreparedOperation> {
    Ok(PreparedOperation {
        agent_id: agent_id.to_string(),
        adapter_id: adapter_id.to_string(),
        invocation_id: operation.invocation_id.clone(),
        allocating_provider_attempt_id: operation.allocating_provider_attempt_id.clone(),
        os_tool_call_id: operation.os_tool_call_id.clone(),
        adapter_effect_ordinal: operation.adapter_effect_ordinal,
        epoch: state.epoch.clone(),
        journal_sequence: operation.journal_sequence,
        request_id: operation.request_id.clone(),
        canonical_request_sha256: Sha256Digest::from_hex(&operation.canonical_request_sha256)
            .map_err(|_| corrupt("operation canonical request digest is invalid"))?,
    })
}

fn operation_evidence(
    state: &JournalState,
    operation: &OperationRecord,
    agent_id: &str,
    adapter_id: &str,
) -> JournalResult<OperationEvidence> {
    if operation.state != PersistedOperationState::ResultRecorded {
        return Err(OperationJournalError::InvalidTransition(
            "result must be recorded before evidence exists",
        ));
    }
    let backend_result_sha256 = operation
        .backend_result_sha256
        .as_deref()
        .ok_or_else(|| corrupt("result-recorded operation lacks result digest"))?;
    let backend_semantic_result_sha256 = operation
        .backend_semantic_result_sha256
        .as_deref()
        .ok_or_else(|| corrupt("result-recorded operation lacks semantic result digest"))?;
    let outcome = operation
        .outcome
        .ok_or_else(|| corrupt("result-recorded operation lacks outcome"))?;
    validate_outcome_error(outcome, operation.backend_error_code.as_deref())?;
    match outcome {
        OperationOutcome::Success | OperationOutcome::BackendError => {
            let _ = decode_terminal_result(operation)?;
        }
        OperationOutcome::Indeterminate if operation.backend_result_base64.is_none() => {}
        OperationOutcome::Indeterminate => {
            return Err(corrupt(
                "indeterminate operation must not retain terminal result bytes",
            ));
        }
    }
    Ok(OperationEvidence {
        agent_id: agent_id.to_string(),
        adapter_id: adapter_id.to_string(),
        invocation_id: operation.invocation_id.clone(),
        allocating_provider_attempt_id: operation.allocating_provider_attempt_id.clone(),
        os_tool_call_id: operation.os_tool_call_id.clone(),
        adapter_effect_ordinal: operation.adapter_effect_ordinal,
        epoch: state.epoch.clone(),
        journal_sequence: operation.journal_sequence,
        request_id: operation.request_id.clone(),
        canonical_request_sha256: Sha256Digest::from_hex(&operation.canonical_request_sha256)
            .map_err(|_| corrupt("operation canonical request digest is invalid"))?,
        raw_backend_result_sha256: Sha256Digest::from_hex(backend_result_sha256)
            .map_err(|_| corrupt("operation raw backend result digest is invalid"))?,
        backend_result_sha256: Sha256Digest::from_hex(backend_semantic_result_sha256)
            .map_err(|_| corrupt("operation semantic backend result digest is invalid"))?,
        outcome,
        backend_error_code: operation.backend_error_code.clone(),
    })
}

fn canonical_semantic_result_digest(backend_result: &[u8]) -> JournalResult<Sha256Digest> {
    let value: serde_json::Value = serde_json::from_slice(backend_result).map_err(|_| {
        OperationJournalError::EvidenceMismatch(
            "terminal backend result is not canonicalizable typed JSON",
        )
    })?;
    let digest =
        crate::semantic_result::canonical_semantic_result_sha256(&value).map_err(|_| {
            OperationJournalError::EvidenceMismatch(
                "terminal backend result failed semantic canonicalization",
            )
        })?;
    Sha256Digest::from_hex(&digest).map_err(|_| {
        OperationJournalError::EvidenceMismatch(
            "terminal backend semantic result digest is malformed",
        )
    })
}

fn decode_terminal_result(operation: &OperationRecord) -> JournalResult<Vec<u8>> {
    let encoded = operation
        .backend_result_base64
        .as_deref()
        .ok_or_else(|| corrupt("definitive operation lacks exact terminal result bytes"))?;
    let bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| corrupt("terminal result base64 is malformed"))?;
    if bytes.is_empty()
        || bytes.len() > crate::MAX_RESPONSE_BYTES
        || BASE64_STANDARD.encode(&bytes) != encoded
    {
        return Err(corrupt(
            "terminal result bytes are empty, oversized, or noncanonical",
        ));
    }
    let expected = operation
        .backend_result_sha256
        .as_deref()
        .ok_or_else(|| corrupt("definitive operation lacks result digest"))?;
    if Sha256Digest::of_bytes(&bytes).to_hex() != expected {
        return Err(corrupt(
            "terminal result bytes do not match the durable result digest",
        ));
    }
    Ok(bytes)
}

fn retained_terminal_result_bytes(state: &JournalState) -> JournalResult<usize> {
    state
        .operations
        .iter()
        .try_fold(0_usize, |total, operation| {
            let retained = match operation.outcome {
                Some(OperationOutcome::Success | OperationOutcome::BackendError) => {
                    decode_terminal_result(operation)?.len()
                }
                Some(OperationOutcome::Indeterminate) | None => 0,
            };
            total
                .checked_add(retained)
                .ok_or(OperationJournalError::CapacityExhausted)
        })
}

fn recovery_decision(
    state: &JournalState,
    operation: &OperationRecord,
    agent_id: &str,
    adapter_id: &str,
) -> JournalResult<RecoveryDecision> {
    match operation.state {
        PersistedOperationState::Prepared => Ok(RecoveryDecision::RetryPrepared(
            prepared_operation(state, operation, agent_id, adapter_id)?,
        )),
        PersistedOperationState::ResultRecorded => Ok(RecoveryDecision::ResultRecorded(
            operation_evidence(state, operation, agent_id, adapter_id)?,
        )),
    }
}

fn recovery_operation(operation: &OperationRecord) -> JournalResult<RecoveryOperation> {
    let canonical_request_sha256 = Sha256Digest::from_hex(&operation.canonical_request_sha256)
        .map_err(|_| corrupt("operation canonical request digest is invalid"))?;
    let state = match operation.state {
        PersistedOperationState::Prepared => RecoveryOperationState::Prepared,
        PersistedOperationState::ResultRecorded => RecoveryOperationState::ResultRecorded {
            backend_result_sha256: Sha256Digest::from_hex(
                operation
                    .backend_result_sha256
                    .as_deref()
                    .ok_or_else(|| corrupt("result-recorded operation lacks result digest"))?,
            )
            .map_err(|_| corrupt("operation backend result digest is invalid"))?,
            outcome: operation
                .outcome
                .ok_or_else(|| corrupt("result-recorded operation lacks outcome"))?,
            backend_error_code: operation.backend_error_code.clone(),
        },
    };
    Ok(RecoveryOperation {
        allocating_provider_attempt_id: operation.allocating_provider_attempt_id.clone(),
        os_tool_call_id: operation.os_tool_call_id.clone(),
        adapter_effect_ordinal: operation.adapter_effect_ordinal,
        journal_sequence: operation.journal_sequence,
        request_id: operation.request_id.clone(),
        canonical_request_sha256,
        state,
    })
}

fn validate_outcome_error(
    outcome: OperationOutcome,
    backend_error_code: Option<&str>,
) -> JournalResult<()> {
    match (outcome, backend_error_code) {
        (OperationOutcome::Success, None) => Ok(()),
        (OperationOutcome::BackendError | OperationOutcome::Indeterminate, Some(code))
            if valid_backend_error_code(code) =>
        {
            Ok(())
        }
        _ => Err(OperationJournalError::EvidenceMismatch(
            "operation outcome contradicts its backend error code",
        )),
    }
}

fn closed_adapter(adapter_id: &str) -> JournalResult<DirectOperationAdapter> {
    match adapter_id {
        "system_api" => Ok(DirectOperationAdapter::SystemApi),
        "accessibility" => Ok(DirectOperationAdapter::Accessibility),
        _ => Err(OperationJournalError::InvalidArgument(
            "journal adapter is not a closed direct-operation adapter",
        )),
    }
}

fn validate_replay_sync_context(
    journal: &OperationJournal,
    context: &crate::trusted_context::TrustedReplaySyncContext,
) -> JournalResult<()> {
    validate_trusted_delivery_binding(
        Some(context.binding()),
        Some(context.binding_sha256()),
        &journal.agent_id,
        &journal.invocation_id,
        &journal.delivery_provider_attempt_id,
    )?;
    if journal.path != context.journal_path()
        || closed_adapter(&journal.adapter_id)? != context.adapter()
        || journal.agent_id != context.agent_id()
    {
        return Err(OperationJournalError::IdentityMismatch);
    }
    Ok(())
}

fn replay_sync_file_identity_digest(
    identity: FileIdentity,
    journal_state_sha256: &str,
    binding_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    replay_sync_hash_field(
        &mut hasher,
        b"domain",
        b"trillionnium.operation-replay-sync-journal-file-identity.v1",
    );
    replay_sync_hash_field(&mut hasher, b"device", &identity.device.to_be_bytes());
    replay_sync_hash_field(&mut hasher, b"inode", &identity.inode.to_be_bytes());
    replay_sync_hash_field(
        &mut hasher,
        b"journal_state_sha256",
        journal_state_sha256.as_bytes(),
    );
    replay_sync_hash_field(&mut hasher, b"binding_sha256", binding_sha256.as_bytes());
    lower_hex(&hasher.finalize())
}

fn replay_sync_terminal_authentication_digest(
    disposition: &[u8],
    context: &crate::trusted_context::TrustedReplaySyncContext,
    launch_challenge_sha256: &str,
    journal_state_sha256: &str,
    journal_file_identity_sha256: &str,
) -> String {
    let mut hasher = Sha256::new();
    replay_sync_hash_field(
        &mut hasher,
        b"domain",
        b"trillionnium.operation-replay-sync-terminal-authentication.v1",
    );
    replay_sync_hash_field(&mut hasher, b"disposition", disposition);
    replay_sync_hash_field(
        &mut hasher,
        b"binding_sha256",
        context.binding_sha256().as_bytes(),
    );
    replay_sync_hash_field(
        &mut hasher,
        b"launch_challenge_sha256",
        launch_challenge_sha256.as_bytes(),
    );
    replay_sync_hash_field(
        &mut hasher,
        b"journal_state_sha256",
        journal_state_sha256.as_bytes(),
    );
    replay_sync_hash_field(
        &mut hasher,
        b"journal_file_identity_sha256",
        journal_file_identity_sha256.as_bytes(),
    );
    replay_sync_hash_field(
        &mut hasher,
        b"operation_replay_sync_selinux_domain",
        context.operation_replay_sync_selinux_domain().as_bytes(),
    );
    replay_sync_hash_field(
        &mut hasher,
        b"executable_path",
        context.executable_path().as_bytes(),
    );
    lower_hex(&hasher.finalize())
}

fn replay_sync_hash_field(hasher: &mut Sha256, name: &[u8], value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn evidence_snapshot_from_state(
    state: &JournalState,
    agent_id: &str,
    adapter_id: &str,
) -> JournalResult<DirectOperationJournalEvidenceSnapshotV1> {
    validate_state(state)?;
    let allocation_binding =
        state
            .active_allocation_binding
            .as_ref()
            .ok_or(OperationJournalError::EvidenceMismatch(
                "trusted allocation binding is absent",
            ))?;
    let allocation_binding_sha256 = state.active_allocation_binding_sha256.as_ref().ok_or(
        OperationJournalError::EvidenceMismatch("trusted allocation binding digest is absent"),
    )?;
    let first = state
        .operations
        .first()
        .ok_or(OperationJournalError::EvidenceMismatch(
            "journal has no operation evidence",
        ))?;
    let last = state
        .operations
        .last()
        .ok_or(OperationJournalError::EvidenceMismatch(
            "journal has no operation evidence",
        ))?;
    let evidence = state
        .operations
        .iter()
        .map(|operation| operation_evidence(state, operation, agent_id, adapter_id))
        .collect::<JournalResult<Vec<_>>>()?;
    if evidence
        .iter()
        .any(|item| item.outcome == OperationOutcome::Indeterminate)
    {
        return Err(OperationJournalError::InvalidTransition(
            "indeterminate operation has no ackable evidence snapshot",
        ));
    }
    let outer_evidence = evidence
        .iter()
        .map(OperationEvidence::to_outer_evidence)
        .collect::<JournalResult<Vec<_>>>()?;
    let count = u32::try_from(outer_evidence.len())
        .map_err(|_| OperationJournalError::CapacityExhausted)?;
    let payload = serde_json::to_vec(state)
        .map_err(|error| corrupt(format!("could not encode journal payload: {error}")))?;
    let adapter = closed_adapter(adapter_id)?;
    let mut snapshot = DirectOperationJournalEvidenceSnapshotV1 {
        schema: JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA.to_string(),
        allocation_binding_sha256: allocation_binding_sha256.clone(),
        invocation_id: first.invocation_id.clone(),
        provider_id: allocation_binding.stable_seed.provider_id.clone(),
        agent_id: allocation_binding.stable_seed.agent_id.clone(),
        allocating_provider_attempt_id: first.allocating_provider_attempt_id.clone(),
        adapter,
        journal_epoch: state.epoch.clone(),
        journal_payload_sha256: Sha256Digest::of_bytes(&payload).to_hex(),
        previous_ack_watermark: state.compacted_ack_watermark,
        previous_ack_chain_sha256: state.compacted_ack_chain_sha256.clone(),
        journal_allocation_count: count,
        journal_evidence_count: count,
        first_journal_sequence: first.journal_sequence,
        last_journal_sequence: last.journal_sequence,
        evidence: outer_evidence,
        evidence_sha256: String::new(),
    };
    snapshot.evidence_sha256 = snapshot.evidence_digest_sha256().map_err(|_| {
        OperationJournalError::EvidenceMismatch("journal evidence digest is invalid")
    })?;
    snapshot.validate().map_err(|_| {
        OperationJournalError::EvidenceMismatch("journal evidence snapshot is invalid")
    })?;
    Ok(snapshot)
}

fn validate_operation_evidence(item: &OperationEvidence) -> JournalResult<()> {
    if !valid_identity(&item.agent_id)
        || !valid_identity(&item.adapter_id)
        || !valid_identity(&item.invocation_id)
        || !valid_provider_attempt_id(&item.allocating_provider_attempt_id)
        || item.adapter_effect_ordinal >= MAX_ACTIVE_OPERATIONS as u64
        || !valid_journal_epoch(&item.epoch)
        || !crate::valid_request_id(&item.request_id)
        || item.journal_sequence == 0
        || item.journal_sequence > MAX_JOURNAL_SEQUENCE
    {
        return Err(OperationJournalError::EvidenceMismatch(
            "operation evidence identity or bounds are malformed",
        ));
    }
    if generated_request_id(
        &item.epoch,
        item.journal_sequence,
        item.canonical_request_sha256,
    )? != item.request_id
    {
        return Err(OperationJournalError::EvidenceMismatch(
            "operation evidence request identity is not derived from its durable fields",
        ));
    }
    validate_outcome_error(item.outcome, item.backend_error_code.as_deref())
}

#[cfg(test)]
fn evidence_set_digest(evidence: &[OperationEvidence]) -> JournalResult<Sha256Digest> {
    if evidence.is_empty() || evidence.len() > MAX_ACTIVE_OPERATIONS {
        return Err(OperationJournalError::EvidenceMismatch(
            "operation evidence set is empty or oversized",
        ));
    }
    let mut seen_journal_sequences = HashSet::with_capacity(evidence.len());
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, b"trillionnium.operation-evidence-set.v2");
    hash_field(&mut hasher, &(evidence.len() as u64).to_be_bytes());
    let mut previous_journal_sequence = None;
    let mut common_identity: Option<(&str, &str, &str, &str)> = None;
    for (index, item) in evidence.iter().enumerate() {
        validate_operation_evidence(item)?;
        if item.adapter_effect_ordinal != index as u64
            || previous_journal_sequence.is_some_and(|previous| item.journal_sequence <= previous)
            || !seen_journal_sequences.insert(item.journal_sequence)
        {
            return Err(OperationJournalError::EvidenceMismatch(
                "operation evidence is malformed, duplicated, or unordered",
            ));
        }
        let identity = (
            item.agent_id.as_str(),
            item.adapter_id.as_str(),
            item.invocation_id.as_str(),
            item.allocating_provider_attempt_id.as_str(),
        );
        if common_identity
            .replace(identity)
            .is_some_and(|expected| expected != identity)
        {
            return Err(OperationJournalError::EvidenceMismatch(
                "operation evidence spans more than one identity or allocating attempt",
            ));
        }
        hash_field(&mut hasher, item.agent_id.as_bytes());
        hash_field(&mut hasher, item.adapter_id.as_bytes());
        hash_field(&mut hasher, item.invocation_id.as_bytes());
        hash_field(&mut hasher, item.allocating_provider_attempt_id.as_bytes());
        hash_field(&mut hasher, &item.adapter_effect_ordinal.to_be_bytes());
        hash_field(&mut hasher, item.epoch.as_bytes());
        hash_field(&mut hasher, &item.journal_sequence.to_be_bytes());
        hash_field(&mut hasher, item.request_id.as_bytes());
        hash_field(&mut hasher, item.canonical_request_sha256.as_bytes());
        hash_field(&mut hasher, item.raw_backend_result_sha256.as_bytes());
        hash_field(&mut hasher, item.backend_result_sha256.as_bytes());
        hash_field(&mut hasher, outcome_name(item.outcome).as_bytes());
        hash_field(
            &mut hasher,
            item.backend_error_code.as_deref().unwrap_or("").as_bytes(),
        );
        previous_journal_sequence = Some(item.journal_sequence);
    }
    Ok(Sha256Digest(hasher.finalize().into()))
}

#[cfg(test)]
fn find_idempotent_ack(
    state: &JournalState,
    invocation_id: &str,
    exact_evidence: &[OperationEvidence],
    evidence_set_sha256: Sha256Digest,
    outer_receipt_sha256: Sha256Digest,
) -> JournalResult<InvocationAcknowledgement> {
    let record = state
        .acknowledgements
        .iter()
        .find(|record| record.invocation_id == invocation_id)
        .ok_or(OperationJournalError::OperationNotFound)?;
    if record.evidence_set_sha256 != evidence_set_sha256.to_hex()
        || record.outer_receipt_sha256 != outer_receipt_sha256.to_hex()
        || usize::try_from(record.operation_count).ok() != Some(exact_evidence.len())
        || exact_evidence.first().map(|item| item.journal_sequence)
            != Some(record.first_journal_sequence)
        || exact_evidence.last().map(|item| item.journal_sequence)
            != Some(record.last_journal_sequence)
    {
        return Err(OperationJournalError::EvidenceMismatch(
            "acknowledgement retry does not match durable evidence and receipt",
        ));
    }
    Ok(InvocationAcknowledgement {
        invocation_id: invocation_id.to_string(),
        delivery_provider_attempt_id: record.delivery_provider_attempt_id.clone(),
        first_journal_sequence: record.first_journal_sequence,
        last_journal_sequence: record.last_journal_sequence,
        operation_count: record.operation_count,
        evidence_set_sha256,
        outer_receipt_sha256,
    })
}

fn find_idempotent_outer_v3(
    state: &JournalState,
    invocation_id: &str,
    delivery_provider_attempt_id: &str,
    inbox: &DirectOperationOuterAckInboxV3,
) -> JournalResult<InvocationAcknowledgement> {
    let record = state
        .acknowledgements
        .iter()
        .find(|record| record.invocation_id == invocation_id)
        .ok_or(OperationJournalError::OperationNotFound)?;
    let snapshot = &inbox.acknowledgement.journal_evidence_snapshot;
    if record.last_journal_sequence != state.compacted_ack_watermark
        || record.authenticated_ack_chain_sha256.as_deref()
            != Some(state.compacted_ack_chain_sha256.as_str())
        || record.delivery_provider_attempt_id != delivery_provider_attempt_id
        || record.first_journal_sequence != snapshot.first_journal_sequence
        || record.last_journal_sequence != snapshot.last_journal_sequence
        || record.operation_count != snapshot.journal_evidence_count
        || record.evidence_set_sha256 != snapshot.evidence_sha256
        || record.outer_receipt_sha256 != inbox.acknowledgement.outer_receipt_sha256
        || record.acknowledgement_sha256.as_deref() != Some(inbox.acknowledgement_sha256.as_str())
        || record.authenticated_ack_chain_sha256.as_deref()
            != Some(inbox.chain_step.authenticated_ack_chain_sha256.as_str())
    {
        return Err(OperationJournalError::EvidenceMismatch(
            "outer ACK v3 retry does not match durable acknowledgement",
        ));
    }
    Ok(InvocationAcknowledgement {
        invocation_id: invocation_id.to_string(),
        delivery_provider_attempt_id: delivery_provider_attempt_id.to_string(),
        first_journal_sequence: record.first_journal_sequence,
        last_journal_sequence: record.last_journal_sequence,
        operation_count: record.operation_count,
        evidence_set_sha256: Sha256Digest::from_hex(&record.evidence_set_sha256)?,
        outer_receipt_sha256: Sha256Digest::from_hex(&record.outer_receipt_sha256)?,
    })
}

#[cfg(test)]
fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
const fn outcome_name(outcome: OperationOutcome) -> &'static str {
    match outcome {
        OperationOutcome::Success => "success",
        OperationOutcome::BackendError => "backend_error",
        OperationOutcome::Indeterminate => "indeterminate",
    }
}

fn validate_state(state: &JournalState) -> JournalResult<()> {
    if !valid_identity(&state.agent_id)
        || !valid_identity(&state.adapter_id)
        || !valid_journal_epoch(&state.epoch)
        || state.next_sequence == 0
        || state.next_sequence > MAX_JOURNAL_SEQUENCE + 1
        || state.compacted_ack_watermark >= state.next_sequence
        || !is_lower_sha256(&state.compacted_ack_chain_sha256)
        || (state.compacted_ack_watermark == 0
            && state.compacted_ack_chain_sha256 != ZERO_DIGEST_HEX)
        || (state.compacted_ack_watermark != 0
            && state.compacted_ack_chain_sha256 == ZERO_DIGEST_HEX)
        || state.acknowledgements.len() > MAX_ACKNOWLEDGEMENTS
        || state.operations.len() > MAX_ACTIVE_OPERATIONS
    {
        return Err(corrupt("journal header or bounds are invalid"));
    }
    match (
        state.operations.first(),
        state.active_invocation_id.as_deref(),
        state.active_allocating_provider_attempt_id.as_deref(),
    ) {
        (None, None, None) => {}
        (Some(first), Some(invocation), Some(attempt))
            if first.invocation_id == invocation
                && first.allocating_provider_attempt_id == attempt => {}
        _ => {
            return Err(corrupt(
                "active invocation and allocating-attempt binding does not match operations",
            ));
        }
    }
    match (
        state.operations.first(),
        state.active_allocation_binding.as_ref(),
        state.active_allocation_binding_sha256.as_deref(),
    ) {
        (None, None, None) | (Some(_), None, None) => {}
        (Some(first), Some(binding), Some(binding_sha256)) => {
            binding
                .validate()
                .map_err(|_| corrupt("active allocation binding is invalid"))?;
            if binding
                .digest_sha256()
                .map_err(|_| corrupt("active allocation binding digest is invalid"))?
                != binding_sha256
                || binding.stable_seed.agent_id != state.agent_id
                || binding.invocation_id != first.invocation_id
                || binding.attempt.delivery_provider_attempt_id
                    != first.allocating_provider_attempt_id
            {
                return Err(corrupt(
                    "active allocation binding does not match journal operations",
                ));
            }
        }
        _ => {
            return Err(corrupt(
                "active allocation binding and digest are incomplete or stale",
            ));
        }
    }

    let mut expected_journal_sequence = 1;
    let mut acknowledgement_invocations = HashSet::new();
    for acknowledgement in &state.acknowledgements {
        validate_acknowledgement_record(acknowledgement)?;
        if acknowledgement.first_journal_sequence != expected_journal_sequence
            || !acknowledgement_invocations.insert(&acknowledgement.invocation_id)
        {
            return Err(corrupt(
                "acknowledgement records are duplicated or not contiguous",
            ));
        }
        expected_journal_sequence = acknowledgement
            .last_journal_sequence
            .checked_add(1)
            .ok_or(OperationJournalError::CapacityExhausted)?;
    }
    if state.compacted_ack_watermark != 0 {
        let last = state
            .acknowledgements
            .last()
            .ok_or_else(|| corrupt("ACK chain watermark has no acknowledgement record"))?;
        if last.last_journal_sequence != state.compacted_ack_watermark
            || last.authenticated_ack_chain_sha256.as_deref()
                != Some(state.compacted_ack_chain_sha256.as_str())
        {
            return Err(corrupt(
                "ACK chain watermark does not match the final acknowledgement",
            ));
        }
    }

    let mut active_invocation: Option<&str> = None;
    let mut active_allocating_provider_attempt: Option<&str> = None;
    let mut prepared_operation_epoch_authority: Option<&str> = None;
    let mut request_ids = HashSet::with_capacity(state.operations.len());
    let mut tool_call_ids = HashSet::with_capacity(state.operations.len());
    for (index, operation) in state.operations.iter().enumerate() {
        if !valid_identity(&operation.invocation_id)
            || !valid_provider_attempt_id(&operation.allocating_provider_attempt_id)
            || !valid_tool_call_id(&operation.os_tool_call_id)
            || operation.adapter_effect_ordinal != index as u64
            || operation.journal_sequence != expected_journal_sequence
            || !crate::valid_request_id(&operation.request_id)
            || operation.canonical_request_sha256.len() != DIGEST_HEX_BYTES
            || !is_lower_hex(&operation.canonical_request_sha256)
            || !request_ids.insert(&operation.request_id)
            || !tool_call_ids.insert(&operation.os_tool_call_id)
        {
            return Err(corrupt(
                "operation record identity, OS tool-call token, adapter effect ordinal, canonical digest, or journal sequence is malformed, duplicated, or not contiguous",
            ));
        }
        if active_allocating_provider_attempt
            .replace(&operation.allocating_provider_attempt_id)
            .is_some_and(|active| active != operation.allocating_provider_attempt_id)
        {
            return Err(corrupt(
                "unacknowledged operations span more than one allocating attempt",
            ));
        }
        if active_invocation
            .replace(&operation.invocation_id)
            .is_some_and(|active| active != operation.invocation_id)
        {
            return Err(corrupt(
                "unacknowledged operations span more than one invocation",
            ));
        }
        let digest = Sha256Digest::from_hex(&operation.canonical_request_sha256)
            .map_err(|_| corrupt("operation canonical request digest is invalid"))?;
        if generated_request_id(&state.epoch, operation.journal_sequence, digest)?
            != operation.request_id
        {
            return Err(corrupt(
                "operation request_id is not derived from epoch, journal sequence, and digest",
            ));
        }
        if let Some(acknowledgement) = &operation.prepared_transport_ack {
            validate_stored_prepared_transport_ack(state, operation, acknowledgement)?;
            if prepared_operation_epoch_authority
                .replace(&acknowledgement.operation_epoch_authority_sha256)
                .is_some_and(|authority| {
                    authority != acknowledgement.operation_epoch_authority_sha256.as_str()
                })
            {
                return Err(corrupt(
                    "PREPARED acknowledgements span more than one operation-epoch authority",
                ));
            }
        }
        match operation.state {
            PersistedOperationState::Prepared
                if operation.backend_result_sha256.is_none()
                    && operation.backend_semantic_result_sha256.is_none()
                    && operation.backend_result_base64.is_none()
                    && operation.outcome.is_none()
                    && operation.backend_error_code.is_none()
                    && index + 1 == state.operations.len() => {}
            PersistedOperationState::ResultRecorded
                if operation
                    .backend_result_sha256
                    .as_deref()
                    .is_some_and(|digest| {
                        digest.len() == DIGEST_HEX_BYTES && is_lower_hex(digest)
                    })
                    && operation
                        .backend_semantic_result_sha256
                        .as_deref()
                        .is_some_and(|digest| {
                            digest.len() == DIGEST_HEX_BYTES && is_lower_hex(digest)
                        })
                    && operation.outcome.is_some_and(|outcome| {
                        validate_outcome_error(outcome, operation.backend_error_code.as_deref())
                            .is_ok()
                    })
                    && match operation.outcome {
                        Some(OperationOutcome::Success | OperationOutcome::BackendError) => {
                            decode_terminal_result(operation).is_ok()
                        }
                        Some(OperationOutcome::Indeterminate) => {
                            operation.backend_result_base64.is_none()
                        }
                        None => false,
                    }
                    && (operation.outcome != Some(OperationOutcome::Indeterminate)
                        || index + 1 == state.operations.len()) => {}
            _ => {
                return Err(corrupt(
                    "operation state does not match its result digest and outcome",
                ));
            }
        }
        expected_journal_sequence = expected_journal_sequence
            .checked_add(1)
            .ok_or(OperationJournalError::CapacityExhausted)?;
    }
    if expected_journal_sequence != state.next_sequence {
        return Err(corrupt(
            "next journal sequence does not exactly follow durable records",
        ));
    }
    if retained_terminal_result_bytes(state)? > MAX_ACTIVE_TERMINAL_RESULT_BYTES {
        return Err(corrupt(
            "retained terminal result bytes exceed the bounded journal budget",
        ));
    }
    Ok(())
}

fn validate_acknowledgement_record(record: &AcknowledgementRecord) -> JournalResult<()> {
    let expected_count = record
        .last_journal_sequence
        .checked_sub(record.first_journal_sequence)
        .and_then(|difference| difference.checked_add(1))
        .and_then(|count| u32::try_from(count).ok());
    if !valid_identity(&record.invocation_id)
        || !valid_provider_attempt_id(&record.delivery_provider_attempt_id)
        || record.first_journal_sequence == 0
        || expected_count != Some(record.operation_count)
        || record.evidence_set_sha256.len() != DIGEST_HEX_BYTES
        || !is_lower_hex(&record.evidence_set_sha256)
        || record.outer_receipt_sha256.len() != DIGEST_HEX_BYTES
        || !is_lower_hex(&record.outer_receipt_sha256)
    {
        return Err(corrupt("acknowledgement record is malformed"));
    }
    match (
        record.acknowledgement_sha256.as_deref(),
        record.authenticated_ack_chain_sha256.as_deref(),
    ) {
        (None, None) => {}
        (Some(acknowledgement), Some(chain))
            if is_nonzero_lower_sha256(acknowledgement) && is_nonzero_lower_sha256(chain) => {}
        _ => {
            return Err(corrupt(
                "acknowledgement authentication and chain digests are malformed",
            ));
        }
    }
    Ok(())
}

fn encode_state(state: &JournalState) -> JournalResult<Vec<u8>> {
    validate_state(state)?;
    let payload = serde_json::to_vec(state)
        .map_err(|error| corrupt(format!("could not encode journal payload: {error}")))?;
    let envelope = JournalEnvelope {
        schema: JOURNAL_SCHEMA.to_string(),
        payload: state.clone(),
        payload_sha256: Sha256Digest::of_bytes(&payload).to_hex(),
    };
    let mut encoded = serde_json::to_vec(&envelope)
        .map_err(|error| corrupt(format!("could not encode journal envelope: {error}")))?;
    encoded.push(b'\n');
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(OperationJournalError::CapacityExhausted);
    }
    Ok(encoded)
}

fn decode_state(bytes: &[u8]) -> JournalResult<JournalState> {
    if bytes.is_empty()
        || bytes.len() > MAX_JOURNAL_BYTES
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(corrupt(
            "journal must be one bounded newline-terminated envelope",
        ));
    }
    let envelope: JournalEnvelope = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|error| corrupt(format!("journal JSON is invalid: {error}")))?;
    if envelope.schema != JOURNAL_SCHEMA {
        return Err(corrupt("journal schema is unknown"));
    }
    let payload = serde_json::to_vec(&envelope.payload)
        .map_err(|error| corrupt(format!("could not canonicalize journal payload: {error}")))?;
    if envelope.payload_sha256 != Sha256Digest::of_bytes(&payload).to_hex() {
        return Err(corrupt("journal payload checksum does not match"));
    }
    validate_state(&envelope.payload)?;
    Ok(envelope.payload)
}

fn corrupt(message: impl Into<String>) -> OperationJournalError {
    OperationJournalError::Corrupt(message.into())
}

impl SecureParent {
    fn open(path: &Path) -> JournalResult<Self> {
        if !path.is_absolute() {
            return Err(OperationJournalError::InvalidArgument(
                "journal path must be absolute",
            ));
        }
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(value) => components.push(value),
                _ => {
                    return Err(OperationJournalError::InvalidArgument(
                        "journal path must contain only absolute normal components",
                    ));
                }
            }
        }
        let destination = components
            .pop()
            .ok_or(OperationJournalError::InvalidArgument(
                "journal path must name a file",
            ))?;
        let destination_name = checked_component(destination)?;
        let root_name = c"/";
        let root_fd = unsafe {
            libc::open(
                root_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut directory = unsafe { File::from_raw_fd(root_fd) };
        for component in components {
            let name = checked_component(component)?;
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let next = unsafe { File::from_raw_fd(fd) };
            let metadata = next.metadata()?;
            if !metadata.is_dir() || metadata.nlink() == 0 {
                return Err(corrupt("journal ancestor is not a live real directory"));
            }
            directory = next;
        }
        let metadata = directory.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != effective_uid()
            || metadata.mode() & 0o7777 != 0o700
            || metadata.nlink() == 0
        {
            return Err(OperationJournalError::InvalidArgument(
                "pre-provisioned journal directory must be real, owner-controlled, and mode 0700",
            ));
        }
        Ok(Self {
            directory,
            destination_name,
        })
    }
}

impl JournalLock {
    fn acquire(parent: &SecureParent, timeout: Duration) -> JournalResult<Self> {
        let lock_name = MutationPrivateNames::for_destination(&parent.destination_name)?.lock;
        let (file, created) = open_or_create_lock(&parent.directory, &lock_name)?;
        let identity = private_file_identity(&file, Some(0), 0, true)?;
        ensure_private_entry_identity(&parent.directory, &lock_name, identity)?;
        if created {
            file.sync_all()?;
            parent.directory.sync_all()?;
        }
        let deadline =
            Instant::now()
                .checked_add(timeout)
                .ok_or(OperationJournalError::InvalidArgument(
                    "lock deadline overflow",
                ))?;
        loop {
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() != std::io::ErrorKind::WouldBlock {
                return Err(error.into());
            }
            if Instant::now() >= deadline {
                return Err(OperationJournalError::LockTimeout);
            }
            thread::sleep(LOCK_RETRY_DELAY);
        }
        let lock = Self {
            file,
            name: lock_name,
            identity,
        };
        lock.revalidate(parent)?;
        Ok(lock)
    }

    fn revalidate(&self, parent: &SecureParent) -> JournalResult<()> {
        let expected_name = MutationPrivateNames::for_destination(&parent.destination_name)?.lock;
        let observed = private_file_identity(&self.file, Some(0), 0, true)?;
        if self.name != expected_name || observed != self.identity {
            return Err(corrupt(
                "journal writer lock no longer matches its retained descriptor",
            ));
        }
        ensure_private_entry_identity(&parent.directory, &self.name, self.identity)
    }

    fn identity_sha256(&self, parent: &SecureParent) -> JournalResult<Sha256Digest> {
        self.revalidate(parent)?;
        Ok(private_identity_digest(
            b"writer-lock",
            &self.name,
            self.identity,
        ))
    }
}

impl MutationPrivateNames {
    fn for_destination(destination_name: &CStr) -> JournalResult<Self> {
        // Preserve the deployed lock-name derivation while binding every new
        // private artifact to the same exact destination component. No PID,
        // transaction digest, caller string, or random suffix may select
        // these names.
        let destination_digest = Sha256Digest::of_bytes(destination_name.to_bytes()).to_hex();
        let make_name = |prefix: &'static str| {
            CString::new(format!("{prefix}{destination_digest}"))
                .map_err(|_| corrupt("derived mutation-private name contains NUL"))
        };
        Ok(Self {
            lock: make_name(".operation-journal-lock-")?,
            staged_candidate: make_name(".operation-journal-staged-candidate-")?,
            sidecar: make_name(".operation-journal-mutation-sidecar-")?,
            sidecar_pending: make_name(".operation-journal-mutation-sidecar-pending-")?,
        })
    }
}

fn checked_component(value: &OsStr) -> JournalResult<CString> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 || bytes == b"." || bytes == b".." {
        return Err(OperationJournalError::InvalidArgument(
            "journal path component is invalid",
        ));
    }
    CString::new(bytes)
        .map_err(|_| OperationJournalError::InvalidArgument("journal path component contains NUL"))
}

fn open_or_create_lock(parent: &File, name: &CStr) -> JournalResult<(File, bool)> {
    let create_flags =
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), create_flags, 0o600) };
    if fd >= 0 {
        let file = unsafe { File::from_raw_fd(fd) };
        set_exact_mode(file.as_raw_fd(), 0o600)?;
        validate_private_regular_file(&file, 0, true)?;
        return Ok((file, true));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() != std::io::ErrorKind::AlreadyExists {
        return Err(error.into());
    }
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    validate_private_regular_file(&file, 0, true)?;
    Ok((file, false))
}

fn private_file_identity(
    file: &File,
    expected_size: Option<u64>,
    maximum_size: u64,
    allow_empty: bool,
) -> JournalResult<PrivateFileIdentity> {
    let metadata = file.metadata()?;
    let identity = PrivateFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
    };
    if !metadata.is_file()
        || identity.inode == 0
        || identity.uid != effective_uid()
        || identity.gid != effective_gid()
        || identity.mode & 0o7777 != 0o600
        || identity.nlink != 1
        || identity.size > maximum_size
        || (!allow_empty && identity.size == 0)
        || expected_size.is_some_and(|size| identity.size != size)
    {
        return Err(corrupt(
            "mutation-private file must be one live owner-only regular inode",
        ));
    }
    Ok(identity)
}

fn private_directory_identity(directory: &File) -> JournalResult<PrivateFileIdentity> {
    let metadata = directory.metadata()?;
    let identity = PrivateFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        nlink: metadata.nlink(),
    };
    if !metadata.is_dir()
        || identity.inode == 0
        || identity.uid != effective_uid()
        || identity.gid != effective_gid()
        || identity.mode & 0o7777 != 0o700
        || identity.nlink == 0
    {
        return Err(corrupt(
            "mutation-stage directory must retain exact private custody",
        ));
    }
    Ok(identity)
}

fn private_stat_identity(stat: &libc::stat) -> JournalResult<PrivateFileIdentity> {
    Ok(PrivateFileIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        size: u64::try_from(stat.st_size)
            .map_err(|_| corrupt("mutation-private file size is negative"))?,
        mode: stat.st_mode,
        uid: stat.st_uid,
        gid: stat.st_gid,
        nlink: normalized_nlink(stat.st_nlink),
    })
}

fn ensure_private_entry_identity(
    parent: &File,
    name: &CStr,
    expected: PrivateFileIdentity,
) -> JournalResult<()> {
    let stat = stat_entry(parent, name)?
        .ok_or_else(|| corrupt("mutation-private directory entry disappeared"))?;
    let observed = private_stat_identity(&stat)?;
    if observed != expected
        || observed.inode == 0
        || observed.uid != effective_uid()
        || observed.gid != effective_gid()
        || observed.mode & libc::S_IFMT != libc::S_IFREG
        || observed.mode & 0o7777 != 0o600
        || observed.nlink != 1
    {
        return Err(corrupt(
            "mutation-private name does not match its retained file descriptor",
        ));
    }
    Ok(())
}

fn create_private_file(parent: &File, name: &CStr) -> JournalResult<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    set_exact_mode(file.as_raw_fd(), 0o600)?;
    Ok(file)
}

fn open_private_retained(
    parent: &File,
    name: &CStr,
    maximum_size: usize,
) -> JournalResult<RetainedPrivateFile> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let identity = private_file_identity(&file, None, maximum_size as u64, false)?;
    ensure_private_entry_identity(parent, name, identity)?;
    let bytes = read_exact_file_at(&file, identity.size as usize)?;
    let retained = RetainedPrivateFile {
        file,
        name: name.to_owned(),
        identity,
        bytes_sha256: Sha256Digest::of_bytes(&bytes),
        bytes,
    };
    retained.revalidate(parent)?;
    Ok(retained)
}

fn retain_written_private(
    parent: &File,
    name: CString,
    file: File,
    expected_bytes: Vec<u8>,
) -> JournalResult<RetainedPrivateFile> {
    let identity = private_file_identity(
        &file,
        Some(expected_bytes.len() as u64),
        expected_bytes.len() as u64,
        false,
    )?;
    ensure_private_entry_identity(parent, &name, identity)?;
    let observed = read_exact_file_at(&file, expected_bytes.len())?;
    if observed != expected_bytes {
        return Err(corrupt(
            "mutation-private retained bytes differ from canonical bytes",
        ));
    }
    Ok(RetainedPrivateFile {
        file,
        name,
        identity,
        bytes_sha256: Sha256Digest::of_bytes(&expected_bytes),
        bytes: expected_bytes,
    })
}

fn read_exact_file_at(file: &File, expected_size: usize) -> JournalResult<Vec<u8>> {
    let mut bytes = vec![0_u8; expected_size];
    let mut offset = 0;
    while offset < expected_size {
        match file.read_at(&mut bytes[offset..], offset as u64) {
            Ok(0) => {
                return Err(corrupt(
                    "mutation-private file ended before its retained size",
                ));
            }
            Ok(read) => offset += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let mut extra = [0_u8; 1];
    if file.read_at(&mut extra, expected_size as u64)? != 0 {
        return Err(corrupt(
            "mutation-private file grew beyond its retained size",
        ));
    }
    Ok(bytes)
}

impl RetainedPrivateFile {
    fn revalidate(&self, parent: &File) -> JournalResult<()> {
        let observed = private_file_identity(
            &self.file,
            Some(self.identity.size),
            self.identity.size,
            self.identity.size == 0,
        )?;
        if observed != self.identity {
            return Err(corrupt("mutation-private retained file identity changed"));
        }
        ensure_private_entry_identity(parent, &self.name, self.identity)?;
        let bytes = read_exact_file_at(&self.file, self.bytes.len())?;
        if bytes != self.bytes || Sha256Digest::of_bytes(&bytes) != self.bytes_sha256 {
            return Err(corrupt("mutation-private retained file bytes changed"));
        }
        Ok(())
    }
}

fn private_identity_digest(
    role: &[u8],
    name: &CStr,
    identity: PrivateFileIdentity,
) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(MUTATION_PRIVATE_IDENTITY_DOMAIN);
    hasher.update((role.len() as u32).to_be_bytes());
    hasher.update(role);
    hasher.update((name.to_bytes().len() as u32).to_be_bytes());
    hasher.update(name.to_bytes());
    hasher.update(identity.device.to_be_bytes());
    hasher.update(identity.inode.to_be_bytes());
    hasher.update(identity.mode.to_be_bytes());
    hasher.update(identity.uid.to_be_bytes());
    hasher.update(identity.gid.to_be_bytes());
    hasher.update(identity.nlink.to_be_bytes());
    Sha256Digest::of_bytes(&hasher.finalize())
}

fn first_use_identity_digest(role: &[u8], identity: PrivateFileIdentity) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"trillionnium.agent-operation-journal-first-use-identity.v1\0");
    hasher.update((role.len() as u32).to_be_bytes());
    hasher.update(role);
    hasher.update(identity.device.to_be_bytes());
    hasher.update(identity.inode.to_be_bytes());
    hasher.update(identity.mode.to_be_bytes());
    hasher.update(identity.uid.to_be_bytes());
    hasher.update(identity.gid.to_be_bytes());
    hasher.update(identity.nlink.to_be_bytes());
    Sha256Digest::of_bytes(&hasher.finalize())
}

fn journal_identity_digest(identity: PrivateFileIdentity) -> Sha256Digest {
    first_use_identity_digest(JOURNAL_IDENTITY_DOMAIN, identity)
}

fn retained_journal_version(
    retained: &RetainedPrivateFile,
) -> JournalResult<mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1> {
    let mut version = mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1 {
        schema: mutation_cas::JOURNAL_VERSION_V1_SCHEMA.to_string(),
        protocol: mutation_cas::PROTOCOL.to_string(),
        journal_identity_sha256: journal_identity_digest(retained.identity).to_hex(),
        journal_bytes_sha256: retained.bytes_sha256.to_hex(),
        journal_version_sha256: String::new(),
    };
    version.journal_version_sha256 = version
        .canonical_sha256()
        .map_err(|_| corrupt("could not bind retained journal version"))?;
    version
        .validate()
        .map_err(|_| corrupt("retained journal version is not canonical"))?;
    Ok(version)
}

impl LocalMutationStagePlan {
    fn new(
        lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: mutation_cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: mutation_cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    ) -> JournalResult<Self> {
        lineage
            .validate()
            .map_err(|_| corrupt("mutation-stage first-use lineage is invalid"))?;
        current
            .validate(&lineage)
            .map_err(|_| corrupt("mutation-stage committed head is invalid"))?;
        intent
            .validate_for(&lineage, &current)
            .map_err(|_| corrupt("mutation-stage intent does not bind the committed head"))?;
        validate_mutation_stage_intent_shape(&intent)?;
        Ok(Self {
            lineage,
            current,
            intent,
        })
    }
}

fn validate_mutation_stage_intent_shape(
    intent: &mutation_cas::DirectOperationRuntimeAuthorityMutationIntentV1,
) -> JournalResult<()> {
    intent
        .expected_journal_version
        .validate()
        .map_err(|_| corrupt("mutation-stage expected journal version is invalid"))?;
    intent
        .observed_current_journal_version
        .validate()
        .map_err(|_| corrupt("mutation-stage observed journal version is invalid"))?;
    intent
        .proposed_journal_version
        .validate()
        .map_err(|_| corrupt("mutation-stage proposed journal version is invalid"))?;
    let next_generation = intent
        .from_mutation_generation
        .checked_add(1)
        .ok_or(OperationJournalError::CapacityExhausted)?;
    let canonical_sha256 = intent
        .canonical_sha256()
        .map_err(|_| corrupt("mutation-stage intent is not canonical"))?;
    if intent.schema != mutation_cas::MUTATION_INTENT_V1_SCHEMA
        || intent.protocol != mutation_cas::PROTOCOL
        || intent.from_mutation_generation == 0
        || intent.to_mutation_generation != next_generation
        || intent.expected_journal_version != intent.observed_current_journal_version
        || intent.proposed_journal_version.journal_identity_sha256
            == intent.expected_journal_version.journal_identity_sha256
        || intent.proposed_journal_version.journal_bytes_sha256
            == intent.expected_journal_version.journal_bytes_sha256
        || !is_nonzero_lower_sha256(&intent.authority_store_instance_sha256)
        || !is_nonzero_lower_sha256(&intent.first_use_lineage_sha256)
        || !is_nonzero_lower_sha256(&intent.from_committed_head_sha256)
        || !is_nonzero_lower_sha256(&intent.mutation_nonce_sha256)
        || intent.mutation_intent_sha256 != canonical_sha256
    {
        return Err(corrupt("mutation-stage intent is internally inconsistent"));
    }
    Ok(())
}

impl LocalMutationStagePlan {
    fn validate_versions(
        &self,
        named_journal: &RetainedPrivateFile,
        candidate: &RetainedPrivateFile,
    ) -> JournalResult<()> {
        let named_state = validate_canonical_journal(named_journal)?;
        let candidate_state = validate_canonical_journal(candidate)?;
        if retained_journal_version(named_journal)? != self.intent.observed_current_journal_version
            || retained_journal_version(candidate)? != self.intent.proposed_journal_version
            || named_state.agent_id != self.lineage.anchor.agent_id
            || named_state.adapter_id != self.lineage.anchor.adapter.adapter_id()
            || named_state.epoch != self.lineage.anchor.journal_epoch
            || candidate_state.agent_id != named_state.agent_id
            || candidate_state.adapter_id != named_state.adapter_id
            || candidate_state.epoch != named_state.epoch
        {
            return Err(corrupt(
                "mutation-stage retained files do not match the typed CAS intent",
            ));
        }
        Ok(())
    }

    fn validate_directory(&self, parent: &SecureParent) -> JournalResult<()> {
        let directory_identity = private_directory_identity(&parent.directory)?;
        if first_use_identity_digest(b"state-directory", directory_identity).to_hex()
            != self.lineage.anchor.state_directory_identity_sha256
            || self.current.state_directory_identity_sha256
                != self.lineage.anchor.state_directory_identity_sha256
        {
            return Err(corrupt(
                "mutation-stage directory does not match the exact authority lineage",
            ));
        }
        Ok(())
    }
}

fn encode_mutation_stage_sidecar(
    plan: &LocalMutationStagePlan,
    writer_lock_identity_sha256: Sha256Digest,
) -> JournalResult<Vec<u8>> {
    let payload = MutationStageSidecarPayload {
        phase: MutationStageSidecarPhase::Staged,
        mutation_intent: plan.intent.clone(),
        writer_lock_identity_sha256: writer_lock_identity_sha256.to_hex(),
    };
    let canonical_payload = serde_json::to_vec(&payload).map_err(|error| {
        corrupt(format!(
            "could not encode mutation sidecar payload: {error}"
        ))
    })?;
    let envelope = MutationStageSidecarEnvelope {
        schema: MUTATION_STAGE_SIDECAR_SCHEMA.to_string(),
        payload,
        payload_sha256: Sha256Digest::of_bytes(&canonical_payload).to_hex(),
    };
    let mut bytes = serde_json::to_vec(&envelope)
        .map_err(|error| corrupt(format!("could not encode mutation sidecar: {error}")))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_MUTATION_STAGE_SIDECAR_BYTES {
        return Err(OperationJournalError::CapacityExhausted);
    }
    Ok(bytes)
}

fn decode_mutation_stage_sidecar(
    bytes: &[u8],
) -> JournalResult<(
    mutation_cas::DirectOperationRuntimeAuthorityMutationIntentV1,
    Sha256Digest,
)> {
    if bytes.is_empty()
        || bytes.len() > MAX_MUTATION_STAGE_SIDECAR_BYTES
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(corrupt(
            "mutation sidecar must be one bounded newline-terminated envelope",
        ));
    }
    let envelope: MutationStageSidecarEnvelope = serde_json::from_slice(&bytes[..bytes.len() - 1])
        .map_err(|error| corrupt(format!("mutation sidecar JSON is invalid: {error}")))?;
    let canonical_payload = serde_json::to_vec(&envelope.payload).map_err(|error| {
        corrupt(format!(
            "could not canonicalize mutation sidecar payload: {error}"
        ))
    })?;
    if envelope.schema != MUTATION_STAGE_SIDECAR_SCHEMA
        || envelope.payload.phase != MutationStageSidecarPhase::Staged
        || envelope.payload_sha256 != Sha256Digest::of_bytes(&canonical_payload).to_hex()
    {
        return Err(corrupt(
            "mutation sidecar schema, phase, or payload checksum is invalid",
        ));
    }
    validate_mutation_stage_intent_shape(&envelope.payload.mutation_intent)?;
    let writer_lock_identity_sha256 =
        Sha256Digest::from_hex(&envelope.payload.writer_lock_identity_sha256)?;
    if writer_lock_identity_sha256.to_hex() == ZERO_DIGEST_HEX {
        return Err(corrupt("mutation sidecar writer-lock identity is zero"));
    }
    let canonical_payload = MutationStageSidecarPayload {
        phase: MutationStageSidecarPhase::Staged,
        mutation_intent: envelope.payload.mutation_intent.clone(),
        writer_lock_identity_sha256: writer_lock_identity_sha256.to_hex(),
    };
    let canonical_payload_bytes = serde_json::to_vec(&canonical_payload)
        .map_err(|error| corrupt(format!("could not re-encode mutation sidecar: {error}")))?;
    let canonical_envelope = MutationStageSidecarEnvelope {
        schema: MUTATION_STAGE_SIDECAR_SCHEMA.to_string(),
        payload: canonical_payload,
        payload_sha256: Sha256Digest::of_bytes(&canonical_payload_bytes).to_hex(),
    };
    let mut canonical_bytes = serde_json::to_vec(&canonical_envelope)
        .map_err(|error| corrupt(format!("could not re-encode mutation sidecar: {error}")))?;
    canonical_bytes.push(b'\n');
    if canonical_bytes != bytes {
        return Err(corrupt("mutation sidecar bytes are not canonical"));
    }
    Ok((
        envelope.payload.mutation_intent,
        writer_lock_identity_sha256,
    ))
}

fn require_private_name_absent(parent: &File, name: &CStr) -> JournalResult<()> {
    if stat_entry(parent, name)?.is_some() {
        Err(corrupt(
            "mutation-private fixed name is unexpectedly occupied",
        ))
    } else {
        Ok(())
    }
}

fn unlink_retained_private(parent: &File, retained: &RetainedPrivateFile) -> JournalResult<()> {
    retained.revalidate(parent)?;
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), retained.name.as_ptr(), 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn unlink_created_private(parent: &File, name: &CStr, file: &File) -> JournalResult<()> {
    let identity = private_file_identity(file, None, u64::MAX, true)?;
    ensure_private_entry_identity(parent, name, identity)?;
    let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    parent.sync_all()?;
    Ok(())
}

fn validate_canonical_journal(retained: &RetainedPrivateFile) -> JournalResult<JournalState> {
    let state = decode_state(&retained.bytes)?;
    if encode_state(&state)? != retained.bytes {
        return Err(corrupt("retained journal bytes are not canonical"));
    }
    Ok(state)
}

impl<'a> FsyncedMutationCandidate<'a> {
    fn materialize(
        parent: &'a SecureParent,
        lock: &'a JournalLock,
        proposed_state: &JournalState,
    ) -> JournalResult<Self> {
        lock.revalidate(parent)?;
        let names = MutationPrivateNames::for_destination(&parent.destination_name)?;
        require_private_name_absent(&parent.directory, &names.staged_candidate)?;
        require_private_name_absent(&parent.directory, &names.sidecar)?;
        require_private_name_absent(&parent.directory, &names.sidecar_pending)?;

        let named_journal = open_private_retained(
            &parent.directory,
            &parent.destination_name,
            MAX_JOURNAL_BYTES,
        )?;
        validate_canonical_journal(&named_journal)?;
        let candidate_bytes = encode_state(proposed_state)?;
        if candidate_bytes == named_journal.bytes {
            return Err(corrupt(
                "mutation-stage candidate must change the journal version",
            ));
        }

        let mut candidate_file = create_private_file(&parent.directory, &names.staged_candidate)?;
        let candidate_result = (|| {
            candidate_file.write_all(&candidate_bytes)?;
            inject_mutation_candidate_fsync_fault()?;
            candidate_file.sync_all()?;
            retain_written_private(
                &parent.directory,
                names.staged_candidate.clone(),
                candidate_file.try_clone()?,
                candidate_bytes,
            )
        })();
        let candidate = match candidate_result {
            Ok(candidate) => candidate,
            Err(error) => {
                unlink_created_private(
                    &parent.directory,
                    &names.staged_candidate,
                    &candidate_file,
                )?;
                return Err(error);
            }
        };
        lock.revalidate(parent)?;
        named_journal.revalidate(&parent.directory)?;
        candidate.revalidate(&parent.directory)?;
        Ok(Self {
            parent,
            lock,
            named_journal,
            candidate,
        })
    }

    fn current_journal_version(
        &self,
    ) -> JournalResult<mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1> {
        retained_journal_version(&self.named_journal)
    }

    fn proposed_journal_version(
        &self,
    ) -> JournalResult<mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1> {
        retained_journal_version(&self.candidate)
    }

    fn cleanup_before_prepare(self) -> JournalResult<()> {
        cleanup_mutation_stage_before_prepare(
            self.parent,
            self.lock,
            &self.named_journal,
            Some(&self.candidate),
            None,
        )
    }

    fn seal(self, plan: LocalMutationStagePlan) -> JournalResult<DurableLocalMutationStage<'a>> {
        let Self {
            parent,
            lock,
            named_journal,
            candidate,
        } = self;
        let names = MutationPrivateNames::for_destination(&parent.destination_name)?;
        let mut sidecar = None;
        let result = (|| -> JournalResult<()> {
            plan.validate_directory(parent)?;
            plan.validate_versions(&named_journal, &candidate)?;
            lock.revalidate(parent)?;
            named_journal.revalidate(&parent.directory)?;
            candidate.revalidate(&parent.directory)?;
            require_private_name_absent(&parent.directory, &names.sidecar)?;
            require_private_name_absent(&parent.directory, &names.sidecar_pending)?;

            let sidecar_bytes =
                encode_mutation_stage_sidecar(&plan, lock.identity_sha256(parent)?)?;
            let mut pending_file = create_private_file(&parent.directory, &names.sidecar_pending)?;
            let pending_result = (|| {
                pending_file.write_all(&sidecar_bytes)?;
                inject_mutation_sidecar_fsync_fault()?;
                pending_file.sync_all()?;
                retain_written_private(
                    &parent.directory,
                    names.sidecar_pending.clone(),
                    pending_file.try_clone()?,
                    sidecar_bytes,
                )
            })();
            let retained_sidecar = match pending_result {
                Ok(sidecar) => sidecar,
                Err(error) => {
                    unlink_created_private(
                        &parent.directory,
                        &names.sidecar_pending,
                        &pending_file,
                    )?;
                    return Err(error);
                }
            };
            sidecar = Some(retained_sidecar);

            lock.revalidate(parent)?;
            named_journal.revalidate(&parent.directory)?;
            candidate.revalidate(&parent.directory)?;
            sidecar
                .as_ref()
                .expect("sidecar was just installed")
                .revalidate(&parent.directory)?;
            require_private_name_absent(&parent.directory, &names.sidecar)?;
            inject_mutation_sidecar_rename_fault()?;
            let renamed = crate::linux_syscall::renameat2_noreplace(
                parent.directory.as_raw_fd(),
                &names.sidecar_pending,
                parent.directory.as_raw_fd(),
                &names.sidecar,
            );
            if renamed != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            sidecar.as_mut().expect("sidecar was just installed").name = names.sidecar.clone();

            inject_mutation_stage_parent_fsync_fault()?;
            parent.directory.sync_all()?;
            lock.revalidate(parent)?;
            named_journal.revalidate(&parent.directory)?;
            candidate.revalidate(&parent.directory)?;
            let sidecar = sidecar.as_ref().expect("sidecar was just installed");
            sidecar.revalidate(&parent.directory)?;
            require_private_name_absent(&parent.directory, &names.sidecar_pending)?;
            let (decoded_intent, decoded_lock) = decode_mutation_stage_sidecar(&sidecar.bytes)?;
            if decoded_intent != plan.intent || decoded_lock != lock.identity_sha256(parent)? {
                return Err(corrupt(
                    "durable mutation sidecar does not match retained stage facts",
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            cleanup_mutation_stage_before_prepare(
                parent,
                lock,
                &named_journal,
                Some(&candidate),
                sidecar.as_ref(),
            )?;
            return Err(error);
        }
        Ok(DurableLocalMutationStage {
            parent,
            lock,
            named_journal,
            candidate,
            sidecar: sidecar.expect("successful seal retains sidecar"),
            plan,
        })
    }
}

impl<'a> DurableLocalMutationStage<'a> {
    #[allow(dead_code)]
    fn reopen(
        parent: &'a SecureParent,
        lock: &'a JournalLock,
        lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: mutation_cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> JournalResult<DurableLocalMutationStage<'a>> {
        let names = MutationPrivateNames::for_destination(&parent.destination_name)?;
        lock.revalidate(parent)?;
        require_private_name_absent(&parent.directory, &names.sidecar_pending)?;
        let named_journal = open_private_retained(
            &parent.directory,
            &parent.destination_name,
            MAX_JOURNAL_BYTES,
        )?;
        let candidate = open_private_retained(
            &parent.directory,
            &names.staged_candidate,
            MAX_JOURNAL_BYTES,
        )?;
        let sidecar = open_private_retained(
            &parent.directory,
            &names.sidecar,
            MAX_MUTATION_STAGE_SIDECAR_BYTES,
        )?;
        validate_canonical_journal(&named_journal)?;
        validate_canonical_journal(&candidate)?;
        let (intent, writer_lock_identity_sha256) = decode_mutation_stage_sidecar(&sidecar.bytes)?;
        if writer_lock_identity_sha256 != lock.identity_sha256(parent)? {
            return Err(corrupt(
                "reopened mutation sidecar names a different writer lock",
            ));
        }
        let plan = LocalMutationStagePlan::new(lineage, current, intent)?;
        plan.validate_directory(parent)?;
        plan.validate_versions(&named_journal, &candidate)?;
        named_journal.revalidate(&parent.directory)?;
        candidate.revalidate(&parent.directory)?;
        sidecar.revalidate(&parent.directory)?;
        lock.revalidate(parent)?;
        Ok(Self {
            parent,
            lock,
            named_journal,
            candidate,
            sidecar,
            plan,
        })
    }

    fn revalidate(&self) -> JournalResult<()> {
        self.lock.revalidate(self.parent)?;
        self.named_journal.revalidate(&self.parent.directory)?;
        self.candidate.revalidate(&self.parent.directory)?;
        self.sidecar.revalidate(&self.parent.directory)?;
        self.plan.validate_directory(self.parent)?;
        self.plan
            .validate_versions(&self.named_journal, &self.candidate)?;
        let (intent, writer_lock_identity_sha256) =
            decode_mutation_stage_sidecar(&self.sidecar.bytes)?;
        if intent != self.plan.intent
            || writer_lock_identity_sha256 != self.lock.identity_sha256(self.parent)?
        {
            return Err(corrupt("durable mutation stage custody drifted"));
        }
        Ok(())
    }

    fn cleanup_before_prepare(self) -> JournalResult<()> {
        self.revalidate()?;
        cleanup_mutation_stage_before_prepare(
            self.parent,
            self.lock,
            &self.named_journal,
            Some(&self.candidate),
            Some(&self.sidecar),
        )
    }

    fn sealed_cas_proof(
        &self,
        seal: &MutationCasJournalSeal,
    ) -> JournalResult<SealedJournalMutationStageProof> {
        self.revalidate()?;
        let (intent, writer_lock_identity_sha256) =
            decode_mutation_stage_sidecar(&self.sidecar.bytes)?;
        Ok(SealedJournalMutationStageProof::from_journal(
            seal,
            retained_journal_version(&self.candidate)?,
            private_identity_digest(
                b"mutation-sidecar",
                &self.sidecar.name,
                self.sidecar.identity,
            )
            .to_hex(),
            self.sidecar.bytes_sha256.to_hex(),
            self.plan.lineage.first_use_lineage_sha256.clone(),
            self.plan.current.committed_head_sha256.clone(),
            intent.mutation_intent_sha256,
            intent.mutation_kind,
            intent.observed_current_journal_version,
            intent.proposed_journal_version,
            writer_lock_identity_sha256.to_hex(),
        ))
    }

    /// Atomically replace the exact named journal with the already-fsynced
    /// candidate. Once PREPARE has been issued, every error intentionally
    /// leaves the sidecar (and, before rename, the candidate) in place for
    /// external-authority reconciliation.
    fn publish(self) -> JournalResult<PublishedLocalMutationStage<'a>> {
        self.revalidate()?;
        let Self {
            parent,
            lock,
            named_journal: _named_journal,
            mut candidate,
            sidecar,
            plan,
        } = self;
        inject_mutation_publication_rename_fault()?;
        let renamed = unsafe {
            libc::renameat(
                parent.directory.as_raw_fd(),
                candidate.name.as_ptr(),
                parent.directory.as_raw_fd(),
                parent.destination_name.as_ptr(),
            )
        };
        if renamed != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        candidate.name = parent.destination_name.clone();

        if inject_mutation_publication_parent_fsync_fault().is_err()
            || parent.directory.sync_all().is_err()
        {
            return Err(OperationJournalError::DurabilityUncertain);
        }

        lock.revalidate(parent)?;
        candidate.revalidate(&parent.directory)?;
        sidecar.revalidate(&parent.directory)?;
        let names = MutationPrivateNames::for_destination(&parent.destination_name)?;
        require_private_name_absent(&parent.directory, &names.staged_candidate)?;
        require_private_name_absent(&parent.directory, &names.sidecar_pending)?;
        validate_canonical_journal(&candidate)?;
        if retained_journal_version(&candidate)? != plan.intent.proposed_journal_version {
            return Err(corrupt(
                "published journal does not match the prepared mutation version",
            ));
        }
        let (intent, writer_lock_identity_sha256) = decode_mutation_stage_sidecar(&sidecar.bytes)?;
        if intent != plan.intent || writer_lock_identity_sha256 != lock.identity_sha256(parent)? {
            return Err(corrupt(
                "published mutation sidecar does not match retained authority facts",
            ));
        }
        Ok(PublishedLocalMutationStage {
            parent,
            lock,
            named_journal: candidate,
            sidecar,
            plan,
        })
    }
}

impl PublishedLocalMutationStage<'_> {
    fn named_journal_version(
        &self,
    ) -> JournalResult<mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1> {
        retained_journal_version(&self.named_journal)
    }

    fn cleanup_after_commit(
        self,
    ) -> JournalResult<(
        String,
        mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    )> {
        let names = MutationPrivateNames::for_destination(&self.parent.destination_name)?;
        self.lock.revalidate(self.parent)?;
        self.named_journal.revalidate(&self.parent.directory)?;
        self.sidecar.revalidate(&self.parent.directory)?;
        require_private_name_absent(&self.parent.directory, &names.staged_candidate)?;
        require_private_name_absent(&self.parent.directory, &names.sidecar_pending)?;
        let named_journal_version = retained_journal_version(&self.named_journal)?;
        let (intent, writer_lock_identity_sha256) =
            decode_mutation_stage_sidecar(&self.sidecar.bytes)?;
        if intent != self.plan.intent
            || named_journal_version != self.plan.intent.proposed_journal_version
            || writer_lock_identity_sha256 != self.lock.identity_sha256(self.parent)?
        {
            return Err(corrupt(
                "committed mutation cleanup facts do not match the published stage",
            ));
        }

        unlink_retained_private(&self.parent.directory, &self.sidecar)?;
        if inject_mutation_cleanup_parent_fsync_fault().is_err()
            || self.parent.directory.sync_all().is_err()
        {
            return Err(OperationJournalError::DurabilityUncertain);
        }
        self.lock.revalidate(self.parent)?;
        self.named_journal.revalidate(&self.parent.directory)?;
        require_private_name_absent(&self.parent.directory, &names.staged_candidate)?;
        require_private_name_absent(&self.parent.directory, &names.sidecar)?;
        require_private_name_absent(&self.parent.directory, &names.sidecar_pending)?;
        Ok((writer_lock_identity_sha256.to_hex(), named_journal_version))
    }
}

impl<'a> ReopenedReplayLocalState<'a> {
    fn reopen(
        parent: &'a SecureParent,
        lock: &'a JournalLock,
        lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: mutation_cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> JournalResult<Self> {
        let names = MutationPrivateNames::for_destination(&parent.destination_name)?;
        lock.revalidate(parent)?;
        require_private_name_absent(&parent.directory, &names.sidecar_pending)?;
        let staged_candidate_present =
            stat_entry(&parent.directory, &names.staged_candidate)?.is_some();
        let sidecar_present = stat_entry(&parent.directory, &names.sidecar)?.is_some();
        match (staged_candidate_present, sidecar_present) {
            (false, false) => {
                let named_journal = open_private_retained(
                    &parent.directory,
                    &parent.destination_name,
                    MAX_JOURNAL_BYTES,
                )?;
                validate_canonical_journal(&named_journal)?;
                lock.revalidate(parent)?;
                named_journal.revalidate(&parent.directory)?;
                Ok(Self::Clean {
                    parent,
                    lock,
                    named_journal,
                })
            }
            (true, true) => Ok(Self::Staged(Box::new(DurableLocalMutationStage::reopen(
                parent, lock, lineage, current,
            )?))),
            (false, true) => Ok(Self::Published(Box::new(
                ReopenedPublishedLocalMutationStage::reopen(parent, lock, lineage)?,
            ))),
            (true, false) => Err(corrupt(
                "replay found a staged candidate without its durable transaction sidecar",
            )),
        }
    }

    fn sealed_cas_state(
        &self,
        seal: &MutationCasJournalSeal,
    ) -> JournalResult<
        crate::direct_operation_runtime_authority_mutation_cas_client::SealedReplayJournalState,
    > {
        use crate::direct_operation_runtime_authority_mutation_cas_client::SealedReplayJournalState;

        match self {
            Self::Clean {
                parent,
                lock,
                named_journal,
            } => {
                lock.revalidate(parent)?;
                named_journal.revalidate(&parent.directory)?;
                let names = MutationPrivateNames::for_destination(&parent.destination_name)?;
                require_private_name_absent(&parent.directory, &names.staged_candidate)?;
                require_private_name_absent(&parent.directory, &names.sidecar)?;
                require_private_name_absent(&parent.directory, &names.sidecar_pending)?;
                Ok(SealedReplayJournalState::clean(
                    seal,
                    retained_journal_version(named_journal)?,
                ))
            }
            Self::Staged(stage) => {
                stage.revalidate()?;
                let (intent, writer_lock_identity_sha256) =
                    decode_mutation_stage_sidecar(&stage.sidecar.bytes)?;
                Ok(SealedReplayJournalState::staged(
                    seal,
                    retained_journal_version(&stage.named_journal)?,
                    retained_journal_version(&stage.candidate)?,
                    intent,
                    writer_lock_identity_sha256.to_hex(),
                ))
            }
            Self::Published(stage) => {
                stage.revalidate()?;
                Ok(SealedReplayJournalState::published(
                    seal,
                    retained_journal_version(&stage.named_journal)?,
                    stage.intent.clone(),
                    stage.writer_lock_identity_sha256.to_hex(),
                ))
            }
        }
    }

    fn cleanup_after_authority_terminal(
        self,
        seal: &MutationCasJournalSeal,
    ) -> JournalResult<
        crate::direct_operation_runtime_authority_mutation_cas_client::SealedLocalReconcileObservations,
    >{
        use crate::direct_operation_runtime_authority_mutation_cas_client::SealedLocalReconcileObservations;

        let (writer_lock_identity_sha256, named_journal_version) = match self {
            Self::Staged(stage) => {
                stage.revalidate()?;
                let writer_lock_identity_sha256 =
                    stage.lock.identity_sha256(stage.parent)?.to_hex();
                let named_journal_version = retained_journal_version(&stage.named_journal)?;
                (*stage).cleanup_before_prepare()?;
                (writer_lock_identity_sha256, named_journal_version)
            }
            Self::Published(stage) => (*stage).cleanup_after_authority_confirmation()?,
            Self::Clean { .. } => {
                return Err(corrupt(
                    "authority requested replay cleanup for an already-clean journal",
                ));
            }
        };
        Ok(SealedLocalReconcileObservations::after_journal_cleanup(
            seal,
            writer_lock_identity_sha256,
            named_journal_version,
        ))
    }
}

impl<'a> ReopenedPublishedLocalMutationStage<'a> {
    fn reopen(
        parent: &'a SecureParent,
        lock: &'a JournalLock,
        lineage: mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> JournalResult<Self> {
        lineage
            .validate()
            .map_err(|_| corrupt("published replay first-use lineage is invalid"))?;
        let names = MutationPrivateNames::for_destination(&parent.destination_name)?;
        lock.revalidate(parent)?;
        require_private_name_absent(&parent.directory, &names.staged_candidate)?;
        require_private_name_absent(&parent.directory, &names.sidecar_pending)?;
        let named_journal = open_private_retained(
            &parent.directory,
            &parent.destination_name,
            MAX_JOURNAL_BYTES,
        )?;
        let sidecar = open_private_retained(
            &parent.directory,
            &names.sidecar,
            MAX_MUTATION_STAGE_SIDECAR_BYTES,
        )?;
        let named_state = validate_canonical_journal(&named_journal)?;
        let (intent, writer_lock_identity_sha256) = decode_mutation_stage_sidecar(&sidecar.bytes)?;
        let retained_writer_lock_identity_sha256 = lock.identity_sha256(parent)?;
        let directory_identity = private_directory_identity(&parent.directory)?;
        if writer_lock_identity_sha256 != retained_writer_lock_identity_sha256
            || first_use_identity_digest(b"state-directory", directory_identity).to_hex()
                != lineage.anchor.state_directory_identity_sha256
            || intent.authority_store_instance_sha256
                != lineage.anchor.authority_store_instance_sha256
            || intent.first_use_lineage_sha256 != lineage.first_use_lineage_sha256
            || retained_journal_version(&named_journal)? != intent.proposed_journal_version
            || named_state.agent_id != lineage.anchor.agent_id
            || named_state.adapter_id != lineage.anchor.adapter.adapter_id()
            || named_state.epoch != lineage.anchor.journal_epoch
        {
            return Err(corrupt(
                "published replay sidecar does not bind the retained journal and lineage",
            ));
        }
        lock.revalidate(parent)?;
        named_journal.revalidate(&parent.directory)?;
        sidecar.revalidate(&parent.directory)?;
        Ok(Self {
            parent,
            lock,
            named_journal,
            sidecar,
            lineage,
            intent,
            writer_lock_identity_sha256,
        })
    }

    fn revalidate(&self) -> JournalResult<()> {
        let names = MutationPrivateNames::for_destination(&self.parent.destination_name)?;
        self.lineage
            .validate()
            .map_err(|_| corrupt("published replay first-use lineage drifted"))?;
        validate_mutation_stage_intent_shape(&self.intent)?;
        self.lock.revalidate(self.parent)?;
        self.named_journal.revalidate(&self.parent.directory)?;
        self.sidecar.revalidate(&self.parent.directory)?;
        require_private_name_absent(&self.parent.directory, &names.staged_candidate)?;
        require_private_name_absent(&self.parent.directory, &names.sidecar_pending)?;
        let named_state = validate_canonical_journal(&self.named_journal)?;
        let (intent, writer_lock_identity_sha256) =
            decode_mutation_stage_sidecar(&self.sidecar.bytes)?;
        let directory_identity = private_directory_identity(&self.parent.directory)?;
        if intent != self.intent
            || writer_lock_identity_sha256 != self.writer_lock_identity_sha256
            || writer_lock_identity_sha256 != self.lock.identity_sha256(self.parent)?
            || first_use_identity_digest(b"state-directory", directory_identity).to_hex()
                != self.lineage.anchor.state_directory_identity_sha256
            || retained_journal_version(&self.named_journal)?
                != self.intent.proposed_journal_version
            || named_state.agent_id != self.lineage.anchor.agent_id
            || named_state.adapter_id != self.lineage.anchor.adapter.adapter_id()
            || named_state.epoch != self.lineage.anchor.journal_epoch
        {
            return Err(corrupt("published replay custody drifted"));
        }
        Ok(())
    }

    fn named_journal_version(
        &self,
    ) -> JournalResult<mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1> {
        self.revalidate()?;
        retained_journal_version(&self.named_journal)
    }

    fn cleanup_after_authority_confirmation(
        self,
    ) -> JournalResult<(
        String,
        mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1,
    )> {
        self.revalidate()?;
        let names = MutationPrivateNames::for_destination(&self.parent.destination_name)?;
        let named_journal_version = retained_journal_version(&self.named_journal)?;
        unlink_retained_private(&self.parent.directory, &self.sidecar)?;
        if inject_mutation_cleanup_parent_fsync_fault().is_err()
            || self.parent.directory.sync_all().is_err()
        {
            return Err(OperationJournalError::DurabilityUncertain);
        }
        self.lock.revalidate(self.parent)?;
        self.named_journal.revalidate(&self.parent.directory)?;
        require_private_name_absent(&self.parent.directory, &names.staged_candidate)?;
        require_private_name_absent(&self.parent.directory, &names.sidecar)?;
        require_private_name_absent(&self.parent.directory, &names.sidecar_pending)?;
        Ok((
            self.writer_lock_identity_sha256.to_hex(),
            named_journal_version,
        ))
    }
}

fn cleanup_mutation_stage_before_prepare(
    parent: &SecureParent,
    lock: &JournalLock,
    named_journal: &RetainedPrivateFile,
    candidate: Option<&RetainedPrivateFile>,
    sidecar: Option<&RetainedPrivateFile>,
) -> JournalResult<()> {
    let names = MutationPrivateNames::for_destination(&parent.destination_name)?;
    lock.revalidate(parent)?;
    named_journal.revalidate(&parent.directory)?;
    if let Some(sidecar) = sidecar {
        unlink_retained_private(&parent.directory, sidecar)?;
        parent.directory.sync_all()?;
    } else {
        require_private_name_absent(&parent.directory, &names.sidecar)?;
        require_private_name_absent(&parent.directory, &names.sidecar_pending)?;
    }
    lock.revalidate(parent)?;
    named_journal.revalidate(&parent.directory)?;
    if let Some(candidate) = candidate {
        unlink_retained_private(&parent.directory, candidate)?;
        parent.directory.sync_all()?;
    } else {
        require_private_name_absent(&parent.directory, &names.staged_candidate)?;
    }
    lock.revalidate(parent)?;
    named_journal.revalidate(&parent.directory)?;
    require_private_name_absent(&parent.directory, &names.staged_candidate)?;
    require_private_name_absent(&parent.directory, &names.sidecar)?;
    require_private_name_absent(&parent.directory, &names.sidecar_pending)
}

fn load_optional(parent: &SecureParent) -> JournalResult<Option<LoadedJournal>> {
    let fd = unsafe {
        libc::openat(
            parent.directory.as_raw_fd(),
            parent.destination_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error.into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let identity = validate_private_regular_file(&file, MAX_JOURNAL_BYTES as u64, false)?;
    ensure_entry_identity(&parent.directory, &parent.destination_name, identity)?;
    let before = file.metadata()?;
    let mut bytes = Vec::with_capacity((before.len() as usize).min(MAX_JOURNAL_BYTES));
    file.take(MAX_JOURNAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        return Err(corrupt("journal exceeds the file-size bound"));
    }
    let after = open_private_regular_file(
        &parent.directory,
        &parent.destination_name,
        MAX_JOURNAL_BYTES as u64,
        false,
    )?;
    let after_metadata = after.metadata()?;
    if before.dev() != after_metadata.dev()
        || before.ino() != after_metadata.ino()
        || before.len() != after_metadata.len()
        || before.mtime() != after_metadata.mtime()
        || before.mtime_nsec() != after_metadata.mtime_nsec()
        || before.ctime() != after_metadata.ctime()
        || before.ctime_nsec() != after_metadata.ctime_nsec()
    {
        return Err(corrupt("journal changed while it was being read"));
    }
    Ok(Some(LoadedJournal {
        state: decode_state(&bytes)?,
        identity,
    }))
}

fn publish_state(
    parent: &SecureParent,
    expected: Option<FileIdentity>,
    state: &JournalState,
) -> JournalResult<PublishState> {
    let bytes = encode_state(state)?;
    let (temporary_name, mut temporary_file) = create_atomic_temp(&parent.directory)?;
    let mut renamed = false;
    let result = (|| -> JournalResult<PublishState> {
        temporary_file.write_all(&bytes)?;
        inject_temp_fsync_fault()?;
        temporary_file.sync_all()?;
        let temporary_identity =
            validate_private_regular_file(&temporary_file, bytes.len() as u64, false)?;
        if temporary_file.metadata()?.len() != bytes.len() as u64 {
            return Err(corrupt("atomic journal temp length changed"));
        }
        ensure_entry_identity(&parent.directory, &temporary_name, temporary_identity)?;
        validate_expected_destination(parent, expected)?;
        inject_rename_fault()?;
        let rename_result = if expected.is_none() {
            crate::linux_syscall::renameat2_noreplace(
                parent.directory.as_raw_fd(),
                &temporary_name,
                parent.directory.as_raw_fd(),
                &parent.destination_name,
            )
        } else {
            unsafe {
                libc::renameat(
                    parent.directory.as_raw_fd(),
                    temporary_name.as_ptr(),
                    parent.directory.as_raw_fd(),
                    parent.destination_name.as_ptr(),
                )
            }
        };
        if rename_result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        renamed = true;

        let parent_sync = inject_parent_fsync_fault().and_then(|()| {
            parent
                .directory
                .sync_all()
                .map_err(OperationJournalError::from)
        });
        let published = verify_published_bytes(parent, &bytes);
        if parent_sync.is_ok() && published.is_ok() {
            Ok(PublishState::Durable)
        } else {
            Ok(PublishState::PublishedDurabilityUncertain)
        }
    })();
    if result.is_err() && !renamed {
        let cleanup =
            unsafe { libc::unlinkat(parent.directory.as_raw_fd(), temporary_name.as_ptr(), 0) };
        if cleanup == 0 {
            parent.directory.sync_all()?;
        }
    }
    result
}

fn create_atomic_temp(parent: &File) -> JournalResult<(CString, File)> {
    for _ in 0..TEMP_CREATE_ATTEMPTS {
        let mut random = [0_u8; 16];
        fill_kernel_random(&mut random)?;
        let name = CString::new(format!(
            ".operation-journal-tmp-{}-{}",
            std::process::id(),
            lower_hex(&random)
        ))
        .map_err(|_| corrupt("derived temporary name contains NUL"))?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd >= 0 {
            let file = unsafe { File::from_raw_fd(fd) };
            set_exact_mode(file.as_raw_fd(), 0o600)?;
            validate_private_regular_file(&file, MAX_JOURNAL_BYTES as u64, true)?;
            return Ok((name, file));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    Err(OperationJournalError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique atomic journal temp",
    )))
}

fn validate_expected_destination(
    parent: &SecureParent,
    expected: Option<FileIdentity>,
) -> JournalResult<()> {
    match (
        stat_entry(&parent.directory, &parent.destination_name)?,
        expected,
    ) {
        (None, None) => Ok(()),
        (Some(stat), Some(expected))
            if valid_private_stat(&stat, MAX_JOURNAL_BYTES as u64, false)
                && stat.st_dev == expected.device
                && stat.st_ino == expected.inode =>
        {
            Ok(())
        }
        _ => Err(corrupt(
            "journal destination changed before atomic publication",
        )),
    }
}

fn verify_published_bytes(parent: &SecureParent, expected: &[u8]) -> JournalResult<()> {
    let file = open_private_regular_file(
        &parent.directory,
        &parent.destination_name,
        expected.len() as u64,
        false,
    )?;
    if file.metadata()?.len() != expected.len() as u64 {
        return Err(corrupt("published journal length changed"));
    }
    let mut observed = Vec::with_capacity(expected.len());
    file.take(expected.len() as u64 + 1)
        .read_to_end(&mut observed)?;
    if observed != expected {
        return Err(corrupt("published journal bytes do not match staged bytes"));
    }
    Ok(())
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
    unsafe { libc::getegid() }
}

// Linux libc exposes `nlink_t` as `u64` on x86-64 and `u32` on AArch64.
#[allow(clippy::useless_conversion)]
fn normalized_nlink(value: libc::nlink_t) -> u64 {
    u64::from(value)
}

fn open_private_regular_file(
    parent: &File,
    name: &CStr,
    maximum_size: u64,
    allow_empty: bool,
) -> JournalResult<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let identity = validate_private_regular_file(&file, maximum_size, allow_empty)?;
    ensure_entry_identity(parent, name, identity)?;
    Ok(file)
}

fn validate_private_regular_file(
    file: &File,
    maximum_size: u64,
    allow_empty: bool,
) -> JournalResult<FileIdentity> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > maximum_size
        || (!allow_empty && metadata.len() == 0)
    {
        return Err(corrupt(
            "journal state file must be a live owner-only regular file with one link",
        ));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn ensure_entry_identity(parent: &File, name: &CStr, expected: FileIdentity) -> JournalResult<()> {
    let stat = stat_entry(parent, name)?
        .ok_or_else(|| corrupt("journal directory entry disappeared during validation"))?;
    if !valid_private_stat(&stat, u64::MAX, true)
        || stat.st_dev != expected.device
        || stat.st_ino != expected.inode
    {
        return Err(corrupt(
            "journal directory entry does not match the validated file descriptor",
        ));
    }
    Ok(())
}

fn stat_entry(parent: &File, name: &CStr) -> JournalResult<Option<libc::stat>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Ok(Some(unsafe { stat.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(error.into())
    }
}

fn valid_private_stat(stat: &libc::stat, maximum_size: u64, allow_empty: bool) -> bool {
    let size = u64::try_from(stat.st_size).ok();
    stat.st_mode & libc::S_IFMT == libc::S_IFREG
        && stat.st_uid == effective_uid()
        && stat.st_mode & 0o7777 == 0o600
        && stat.st_nlink == 1
        && size.is_some_and(|size| size <= maximum_size && (allow_empty || size != 0))
}

fn set_exact_mode(fd: RawFd, mode: libc::mode_t) -> JournalResult<()> {
    let result = unsafe { libc::fchmod(fd, mode) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn fill_kernel_random(output: &mut [u8]) -> JournalResult<()> {
    let mut offset = 0;
    while offset < output.len() {
        let result = unsafe {
            libc::getrandom(
                output[offset..].as_mut_ptr().cast::<libc::c_void>(),
                output.len() - offset,
                0,
            )
        };
        if result > 0 {
            offset += result as usize;
            continue;
        }
        if result == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "kernel random source returned no bytes",
            )
            .into());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    Ok(())
}

fn fresh_journal_epoch() -> JournalResult<String> {
    fresh_journal_epoch_with(fill_kernel_random)
}

fn fresh_journal_epoch_with(
    mut fill: impl FnMut(&mut [u8]) -> JournalResult<()>,
) -> JournalResult<String> {
    loop {
        let mut epoch = [0_u8; EPOCH_BYTES];
        fill(&mut epoch)?;
        if epoch.iter().any(|byte| *byte != 0) {
            return Ok(lower_hex(&epoch));
        }
    }
}

fn valid_journal_epoch(value: &str) -> bool {
    value.len() == EPOCH_BYTES * 2 && value != ZERO_EPOCH_HEX && is_lower_hex(value)
}

fn fresh_mutation_nonce_sha256() -> JournalResult<String> {
    loop {
        let mut nonce = [0_u8; DIGEST_BYTES];
        fill_kernel_random(&mut nonce)?;
        let digest = Sha256Digest::of_bytes(&nonce).to_hex();
        if digest != ZERO_DIGEST_HEX {
            return Ok(digest);
        }
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn is_lower_hex(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == DIGEST_HEX_BYTES && is_lower_hex(value)
}

fn is_nonzero_lower_sha256(value: &str) -> bool {
    is_lower_sha256(value) && value != ZERO_DIGEST_HEX
}

fn decode_hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => unreachable!("caller validated lowercase hexadecimal input"),
    }
}

#[cfg(test)]
fn inject_fault(point: FaultPoint) -> JournalResult<()> {
    let should_fail = NEXT_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    });
    if should_fail {
        Err(std::io::Error::other(format!("injected operation journal fault at {point:?}")).into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn fail_next_mutation_cas_for_test(point: MutationCasFaultForTest) {
    let point = match point {
        MutationCasFaultForTest::SidecarFsyncBeforePrepare => FaultPoint::MutationSidecarFsync,
        MutationCasFaultForTest::PublicationRenameAfterPrepare => {
            FaultPoint::MutationPublicationRename
        }
        MutationCasFaultForTest::PublicationParentFsyncAfterRename => {
            FaultPoint::MutationPublicationParentFsync
        }
        MutationCasFaultForTest::CleanupParentFsyncAfterCommit => {
            FaultPoint::MutationCleanupParentFsync
        }
    };
    NEXT_FAULT.with(|fault| {
        assert!(fault.replace(Some(point)).is_none(), "fault already armed");
    });
}

#[cfg(test)]
fn inject_temp_fsync_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::TempFileFsync)
}

#[cfg(not(test))]
fn inject_temp_fsync_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_rename_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::Rename)
}

#[cfg(not(test))]
fn inject_rename_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_parent_fsync_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::ParentFsyncAfterRename)
}

#[cfg(not(test))]
fn inject_parent_fsync_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_mutation_candidate_fsync_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::MutationCandidateFsync)
}

#[cfg(not(test))]
fn inject_mutation_candidate_fsync_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_mutation_sidecar_fsync_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::MutationSidecarFsync)
}

#[cfg(not(test))]
fn inject_mutation_sidecar_fsync_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_mutation_sidecar_rename_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::MutationSidecarRename)
}

#[cfg(not(test))]
fn inject_mutation_sidecar_rename_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_mutation_stage_parent_fsync_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::MutationStageParentFsync)
}

#[cfg(not(test))]
fn inject_mutation_stage_parent_fsync_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_mutation_publication_rename_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::MutationPublicationRename)
}

#[cfg(not(test))]
fn inject_mutation_publication_rename_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_mutation_publication_parent_fsync_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::MutationPublicationParentFsync)
}

#[cfg(not(test))]
fn inject_mutation_publication_parent_fsync_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
fn inject_mutation_cleanup_parent_fsync_fault() -> JournalResult<()> {
    inject_fault(FaultPoint::MutationCleanupParentFsync)
}

#[cfg(not(test))]
fn inject_mutation_cleanup_parent_fsync_fault() -> JournalResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::{Arc, Barrier};

    use tempfile::TempDir;
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationOuterAckChainStepV3, DirectOperationOuterAckInboxV3,
        DirectOperationOuterAckV3, DirectOperationProviderAttempt, DirectOperationStableSeed,
        OUTER_ACK_INBOX_V3_SCHEMA, OUTER_ACK_V3_SCHEMA, STABLE_SEED_SCHEMA,
    };

    use super::*;

    const AGENT_ID: &str = "codex";
    const ADAPTER_ID: &str = "system_api";
    const ALLOCATING_ATTEMPT_ID: &str =
        "attempt:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RECOVERY_DELIVERY_ATTEMPT_ID: &str =
        "attempt:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn digest(character: char) -> String {
        character.to_string().repeat(DIGEST_HEX_BYTES)
    }

    fn binding(task_id: &str, attempt_character: char) -> DirectOperationBinding {
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
        let attempt =
            DirectOperationProviderAttempt::derive(digest(attempt_character), 1, digest('4'))
                .unwrap();
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

    fn open_bound_result(
        path: &Path,
        binding: &DirectOperationBinding,
    ) -> JournalResult<OperationJournal> {
        OperationJournal::open_with_parameters(JournalOpenParameters {
            path: path.to_path_buf(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter_id: ADAPTER_ID.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            trusted_delivery_binding: Some(binding.clone()),
            trusted_delivery_binding_sha256: Some(binding.digest_sha256().unwrap()),
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing: true,
            trusted_state_directory: None,
            pinned_epoch: None,
            operation_epoch_authority_sha256: None,
            device_conformance_epoch_authority_bridge: false,
            required_open_state_sha256: None,
            required_open_file_identity: None,
        })
    }

    fn open_bound(path: &Path, binding: &DirectOperationBinding) -> OperationJournal {
        open_bound_result(path, binding).unwrap()
    }

    fn open_bound_with_runtime_authority(
        path: &Path,
        binding: &DirectOperationBinding,
        operation_epoch_authority_sha256: Sha256Digest,
    ) -> OperationJournal {
        OperationJournal::open_with_parameters(JournalOpenParameters {
            path: path.to_path_buf(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter_id: ADAPTER_ID.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            trusted_delivery_binding: Some(binding.clone()),
            trusted_delivery_binding_sha256: Some(binding.digest_sha256().unwrap()),
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing: true,
            trusted_state_directory: None,
            pinned_epoch: None,
            operation_epoch_authority_sha256: Some(operation_epoch_authority_sha256),
            device_conformance_epoch_authority_bridge: false,
            required_open_state_sha256: None,
            required_open_file_identity: None,
        })
        .expect("open bound journal with external runtime authority")
    }

    fn reopen_bound_with_exact_runtime_authority(
        path: &Path,
        binding: &DirectOperationBinding,
        operation_epoch_authority_sha256: Option<Sha256Digest>,
    ) -> JournalResult<OperationJournal> {
        let parent = SecureParent::open(path)?;
        let loaded = load_optional(&parent)?.ok_or(OperationJournalError::MissingTrustedJournal)?;
        let required_open_state_sha256 = Sha256Digest::of_bytes(&encode_state(&loaded.state)?);
        OperationJournal::open_with_parameters(JournalOpenParameters {
            path: path.to_path_buf(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter_id: ADAPTER_ID.to_string(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            trusted_delivery_binding: Some(binding.clone()),
            trusted_delivery_binding_sha256: Some(binding.digest_sha256().unwrap()),
            lock_timeout: LOCK_TIMEOUT,
            initialize_missing: false,
            trusted_state_directory: None,
            pinned_epoch: Some(loaded.state.epoch.clone()),
            operation_epoch_authority_sha256,
            device_conformance_epoch_authority_bridge: false,
            required_open_state_sha256: Some(required_open_state_sha256),
            required_open_file_identity: Some(loaded.identity),
        })
    }

    fn tool_call_envelope(
        binding: &DirectOperationBinding,
        prepared: &PreparedOperation,
    ) -> DirectOperationToolCallEnvelopeV3 {
        let binding_sha256 = binding.digest_sha256().unwrap();
        let mut envelope = DirectOperationToolCallEnvelopeV3 {
            schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
            binding_sha256: binding_sha256.clone(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            provider_id: binding.stable_seed.provider_id.clone(),
            agent_id: binding.stable_seed.agent_id.clone(),
            adapter: DirectOperationAdapter::SystemApi,
            os_tool_call_id: prepared.os_tool_call_id.clone(),
            adapter_effect_ordinal: prepared.adapter_effect_ordinal,
            canonical_request_sha256: prepared.canonical_request_sha256.to_hex(),
            envelope_sha256: String::new(),
        };
        envelope.envelope_sha256 = envelope.digest_sha256().unwrap();
        envelope
            .validate_for(
                binding,
                &binding_sha256,
                DirectOperationAdapter::SystemApi,
                &prepared.canonical_request_sha256.to_hex(),
            )
            .unwrap();
        envelope
    }

    fn record_success(
        journal: &mut OperationJournal,
        prepared: &PreparedOperation,
    ) -> OperationEvidence {
        let response = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id.clone(),
            "ok": true,
        }))
        .unwrap();
        journal
            .record_result(prepared, &response, BackendCompletion::Response)
            .unwrap()
    }

    fn outer_ack_v3(
        delivery_binding: &DirectOperationBinding,
        snapshot: DirectOperationJournalEvidenceSnapshotV1,
    ) -> DirectOperationOuterAckInboxV3 {
        let mut acknowledgement = DirectOperationOuterAckV3 {
            schema: OUTER_ACK_V3_SCHEMA.to_string(),
            binding_sha256: delivery_binding.digest_sha256().unwrap(),
            invocation_id: delivery_binding.invocation_id.clone(),
            delivery_provider_attempt_id: delivery_binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            provider_id: delivery_binding.stable_seed.provider_id.clone(),
            agent_id: delivery_binding.stable_seed.agent_id.clone(),
            adapter: DirectOperationAdapter::SystemApi,
            authorized_adapter_set_sha256: delivery_binding
                .authorized_adapter_set
                .digest_sha256()
                .unwrap(),
            outer_receipt_sha256: digest('e'),
            journal_evidence_snapshot: snapshot,
            journal_evidence_snapshot_sha256: String::new(),
        };
        acknowledgement.journal_evidence_snapshot_sha256 = acknowledgement
            .journal_evidence_snapshot
            .digest_sha256()
            .unwrap();
        let acknowledgement_sha256 = acknowledgement.digest_sha256().unwrap();
        let chain_step = DirectOperationOuterAckChainStepV3::derive(
            acknowledgement.adapter,
            acknowledgement
                .journal_evidence_snapshot
                .journal_epoch
                .clone(),
            acknowledgement
                .journal_evidence_snapshot
                .previous_ack_watermark,
            acknowledgement
                .journal_evidence_snapshot
                .last_journal_sequence,
            acknowledgement_sha256.clone(),
            acknowledgement
                .journal_evidence_snapshot
                .previous_ack_chain_sha256
                .clone(),
        )
        .unwrap();
        let chain_step_sha256 = chain_step.digest_sha256().unwrap();
        let inbox = DirectOperationOuterAckInboxV3 {
            schema: OUTER_ACK_INBOX_V3_SCHEMA.to_string(),
            acknowledgement,
            acknowledgement_sha256,
            chain_step,
            chain_step_sha256,
        };
        inbox.validate().unwrap();
        inbox
    }

    fn fixture() -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("create journal fixture");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("set fixture mode");
        let path = directory.path().join("operations.json");
        (directory, path)
    }

    fn open(path: &Path, invocation_id: &str) -> OperationJournal {
        open_attempt(path, invocation_id, ALLOCATING_ATTEMPT_ID)
    }

    fn open_attempt(
        path: &Path,
        invocation_id: &str,
        delivery_provider_attempt_id: &str,
    ) -> OperationJournal {
        OperationJournal::open(
            path,
            AGENT_ID,
            ADAPTER_ID,
            invocation_id,
            delivery_provider_attempt_id,
        )
        .expect("open operation journal")
    }

    fn allocate(
        journal: &mut OperationJournal,
        adapter_effect_ordinal: u64,
        canonical_request: &[u8],
    ) -> PreparedOperation {
        match journal
            .begin_effect(adapter_effect_ordinal, canonical_request)
            .expect("allocate durable prepared operation")
        {
            EffectStart::Allocated(prepared) => prepared,
            EffectStart::Recovery(_) => {
                panic!("new canonical effect unexpectedly entered recovery")
            }
        }
    }

    fn assert_rejected(result: JournalResult<OperationJournal>) {
        assert!(
            result.is_err(),
            "unsafe journal representation was accepted"
        );
    }

    fn fail_next(point: FaultPoint) {
        NEXT_FAULT.with(|fault| {
            assert!(fault.replace(Some(point)).is_none(), "fault already armed");
        });
    }

    fn read_state(path: &Path) -> JournalState {
        decode_state(&fs::read(path).expect("read journal")).expect("decode journal")
    }

    fn write_unchecked_state(path: &Path, state: JournalState) {
        let payload = serde_json::to_vec(&state).expect("encode unchecked payload");
        let envelope = JournalEnvelope {
            schema: JOURNAL_SCHEMA.to_string(),
            payload: state,
            payload_sha256: Sha256Digest::of_bytes(&payload).to_hex(),
        };
        let mut encoded = serde_json::to_vec(&envelope).expect("encode unchecked envelope");
        encoded.push(b'\n');
        fs::write(path, encoded).expect("replace journal fixture");
    }

    fn labeled_digest(label: &str) -> String {
        Sha256Digest::of_bytes(label.as_bytes()).to_hex()
    }

    fn proposed_stage_state(path: &Path) -> JournalState {
        let mut journal = OperationJournal::open(
            path,
            "agent-codex-direct-v1",
            ADAPTER_ID,
            "inv-mutation-stage",
            ALLOCATING_ATTEMPT_ID,
        )
        .expect("initialize mutation-stage journal");
        let initial = read_state(path);
        allocate(&mut journal, 0, b"mutation-stage-proposal");
        let proposed = read_state(path);
        write_unchecked_state(path, initial);
        proposed
    }

    fn mutation_stage_authority(
        genesis_version: mutation_cas::DirectOperationRuntimeAuthorityJournalVersionV1,
        state_directory_identity_sha256: String,
        journal_epoch: String,
    ) -> (
        mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1,
        mutation_cas::DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) {
        let mut anchor = mutation_cas::DirectOperationRuntimeAuthorityFirstUseAnchorV1 {
            schema: mutation_cas::FIRST_USE_ANCHOR_V1_SCHEMA.to_string(),
            protocol: mutation_cas::PROTOCOL.to_string(),
            authority_identity_sha256: labeled_digest("stage-authority"),
            authority_store_instance_sha256: labeled_digest("stage-store"),
            provision_epoch_sha256: labeled_digest("stage-provision"),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            adapter: DirectOperationAdapter::SystemApi,
            journal_epoch,
            state_directory_identity_sha256,
            genesis_journal_version: genesis_version,
            immutable_sentinel_schema: mutation_cas::FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA
                .to_string(),
            immutable_sentinel_embeds_prepared_head: false,
            sentinel_identity_sha256: labeled_digest("stage-sentinel-identity"),
            sentinel_bytes_sha256: String::new(),
            first_use_anchor_sha256: String::new(),
        };
        anchor.sentinel_bytes_sha256 = anchor.canonical_immutable_sentinel_bytes_sha256().unwrap();
        anchor.first_use_anchor_sha256 = anchor.canonical_sha256().unwrap();

        let mut candidate = mutation_cas::DirectOperationRuntimeAuthorityFirstUseCandidateV1 {
            schema: mutation_cas::FIRST_USE_CANDIDATE_V1_SCHEMA.to_string(),
            protocol: mutation_cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            proposed_genesis_journal_version_sha256: anchor
                .genesis_journal_version
                .journal_version_sha256
                .clone(),
            candidate_nonce_sha256: labeled_digest("stage-first-use-candidate"),
            first_use_candidate_sha256: String::new(),
        };
        candidate.first_use_candidate_sha256 = candidate.canonical_sha256().unwrap();

        let mut prepared = mutation_cas::DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1 {
            schema: mutation_cas::FIRST_USE_PREPARED_HEAD_V1_SCHEMA.to_string(),
            protocol: mutation_cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
            prepared_genesis_journal_version_sha256: anchor
                .genesis_journal_version
                .journal_version_sha256
                .clone(),
            prepared_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
            prepared_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
            prepare_nonce_sha256: labeled_digest("stage-first-use-prepare"),
            first_use_prepared_head_sha256: String::new(),
        };
        prepared.first_use_prepared_head_sha256 = prepared.canonical_sha256().unwrap();

        let mut committed = mutation_cas::DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1 {
            schema: mutation_cas::FIRST_USE_COMMITTED_HEAD_V1_SCHEMA.to_string(),
            protocol: mutation_cas::PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
            first_use_prepared_head_sha256: prepared.first_use_prepared_head_sha256.clone(),
            committed_genesis_journal_version: anchor.genesis_journal_version.clone(),
            committed_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
            committed_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
            durable_commit_evidence_sha256: labeled_digest("stage-first-use-local-commit"),
            first_use_committed_head_sha256: String::new(),
        };
        committed.first_use_committed_head_sha256 = committed.canonical_sha256().unwrap();

        let mut result =
            mutation_cas::DirectOperationRuntimeAuthorityFirstUseCommittedResultBindingV1 {
                schema: mutation_cas::FIRST_USE_COMMITTED_RESULT_BINDING_V1_SCHEMA.to_string(),
                protocol: mutation_cas::PROTOCOL.to_string(),
                first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
                first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
                first_use_prepared_head_sha256: prepared.first_use_prepared_head_sha256.clone(),
                first_use_committed_head_sha256: committed.first_use_committed_head_sha256.clone(),
                committed_genesis_journal_version_sha256: anchor
                    .genesis_journal_version
                    .journal_version_sha256
                    .clone(),
                committed_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
                committed_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
                durable_commit_evidence_sha256: committed.durable_commit_evidence_sha256.clone(),
                result_receipt_sha256: labeled_digest("stage-first-use-result"),
                first_use_committed_result_binding_sha256: String::new(),
            };
        result.first_use_committed_result_binding_sha256 = result.canonical_sha256().unwrap();

        let mut lineage = mutation_cas::DirectOperationRuntimeAuthorityFirstUseLineageV1 {
            schema: mutation_cas::FIRST_USE_LINEAGE_V1_SCHEMA.to_string(),
            protocol: mutation_cas::PROTOCOL.to_string(),
            anchor,
            candidate,
            prepared_head: prepared,
            committed_head: committed,
            committed_result_binding: result,
            first_use_lineage_sha256: String::new(),
        };
        lineage.first_use_lineage_sha256 = lineage.canonical_sha256().unwrap();
        lineage.validate().unwrap();

        let mut head = mutation_cas::DirectOperationRuntimeAuthorityCommittedHeadV1 {
            schema: mutation_cas::COMMITTED_HEAD_V1_SCHEMA.to_string(),
            protocol: mutation_cas::PROTOCOL.to_string(),
            authority_identity_sha256: lineage.anchor.authority_identity_sha256.clone(),
            authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            provider_id: lineage.anchor.provider_id.clone(),
            agent_id: lineage.anchor.agent_id.clone(),
            adapter: lineage.anchor.adapter,
            journal_epoch: lineage.anchor.journal_epoch.clone(),
            state_directory_identity_sha256: lineage.anchor.state_directory_identity_sha256.clone(),
            mutation_generation: 1,
            journal_version: lineage.anchor.genesis_journal_version.clone(),
            ancestry: mutation_cas::DirectOperationRuntimeAuthorityHeadAncestryV1::Genesis {
                first_use_committed_result_binding_sha256: lineage
                    .committed_result_binding
                    .first_use_committed_result_binding_sha256
                    .clone(),
            },
            committed_head_sha256: String::new(),
        };
        head.committed_head_sha256 = head.canonical_sha256().unwrap();
        head.validate(&lineage).unwrap();
        (lineage, head)
    }

    fn mutation_stage_plan(candidate: &FsyncedMutationCandidate<'_>) -> LocalMutationStagePlan {
        let current_version = candidate.current_journal_version().unwrap();
        let proposed_version = candidate.proposed_journal_version().unwrap();
        let directory_identity = private_directory_identity(&candidate.parent.directory).unwrap();
        let state_directory_identity_sha256 =
            first_use_identity_digest(b"state-directory", directory_identity).to_hex();
        let state = validate_canonical_journal(&candidate.named_journal).unwrap();
        let (lineage, current) = mutation_stage_authority(
            current_version.clone(),
            state_directory_identity_sha256,
            state.epoch,
        );
        let mut intent = mutation_cas::DirectOperationRuntimeAuthorityMutationIntentV1 {
            schema: mutation_cas::MUTATION_INTENT_V1_SCHEMA.to_string(),
            protocol: mutation_cas::PROTOCOL.to_string(),
            authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            from_committed_head_sha256: current.committed_head_sha256.clone(),
            from_mutation_generation: current.mutation_generation,
            mutation_kind: mutation_cas::DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            expected_journal_version: current_version.clone(),
            observed_current_journal_version: current_version,
            to_mutation_generation: current.mutation_generation + 1,
            proposed_journal_version: proposed_version,
            mutation_nonce_sha256: labeled_digest("stage-mutation-nonce"),
            mutation_intent_sha256: String::new(),
        };
        intent.mutation_intent_sha256 = intent.canonical_sha256().unwrap();
        LocalMutationStagePlan::new(lineage, current, intent).unwrap()
    }

    #[test]
    fn v3_os_identity_fields_are_exact_replay_bound_and_not_interchangeable() {
        for field in 0..3 {
            let (_directory, path) = fixture();
            let original = binding("task-v3-identity-replay", '8');
            let canonical = b"v3-identity-bound-canonical-request";
            let mut journal = open_bound(&path, &original);
            let prepared = allocate(&mut journal, 0, canonical);
            let evidence = record_success(&mut journal, &prepared);
            drop(journal);

            let mut exact_retry = open_bound_result(&path, &original).unwrap();
            assert_eq!(
                exact_retry.recover_effect(canonical).unwrap(),
                RecoveryDecision::ResultRecorded(evidence)
            );
            drop(exact_retry);

            let mut changed = original.clone();
            match field {
                0 => changed.workflow_id_sha256 = digest('9'),
                1 => changed.agent_identity_key_sha256 = digest('a'),
                2 => changed.agent_executable_sha256 = digest('b'),
                _ => unreachable!(),
            }
            assert_eq!(changed.invocation_id, original.invocation_id);
            assert_ne!(
                changed.digest_sha256().unwrap(),
                original.digest_sha256().unwrap()
            );
            assert!(matches!(
                open_bound_result(&path, &changed),
                Err(OperationJournalError::IdentityMismatch)
                    | Err(OperationJournalError::EvidenceMismatch(_))
            ));
        }
    }

    #[test]
    fn prepared_crash_and_lost_response_recover_without_repeating_identity() {
        let (_directory, path) = fixture();
        let canonical_request = br#"{"action":"set_text","text":"RAW-REQUEST-SECRET"}"#;
        let backend_result = br#"{"ok":true,"value":"RAW-RESULT-SECRET"}"#;

        let mut journal = open(&path, "invocation-1");
        let prepared = allocate(&mut journal, 0, canonical_request);
        assert!(prepared.request_id.len() <= MAX_ID_BYTES);
        assert!(crate::valid_request_id(&prepared.request_id));
        assert_eq!(prepared.journal_sequence, 1);
        let request_id_fields = prepared.request_id.split(':').collect::<Vec<_>>();
        assert_eq!(request_id_fields.len(), 4);
        assert_eq!(request_id_fields[0], REQUEST_ID_PREFIX);
        assert_eq!(request_id_fields[1], prepared.epoch);
        assert_eq!(request_id_fields[2], "1");
        assert_eq!(
            request_id_fields[3],
            prepared.canonical_request_sha256.to_hex()
        );
        assert_eq!(request_id_fields[3].len(), DIGEST_HEX_BYTES);
        drop(journal);

        let mut recovered = open(&path, "invocation-1");
        assert_eq!(
            recovered
                .recover_effect(canonical_request)
                .expect("recover prepared effect"),
            RecoveryDecision::RetryPrepared(prepared.clone())
        );
        assert!(matches!(
            recovered.recover_effect(b"different canonical request"),
            Err(OperationJournalError::CanonicalDigestMismatch)
        ));

        let mut competing = open(&path, "invocation-2");
        assert!(matches!(
            competing.begin_effect(0, b"new invocation effect"),
            Err(OperationJournalError::RecoveryRequired {
                pending_invocation_id
            }) if pending_invocation_id == "invocation-1"
        ));

        let evidence = recovered
            .record_result_for_test(&prepared, backend_result, OperationOutcome::Success)
            .expect("durably record result");
        drop(recovered);

        let persisted = fs::read(&path).expect("read persisted journal");
        assert!(
            !persisted
                .windows(b"RAW-REQUEST-SECRET".len())
                .any(|window| { window == b"RAW-REQUEST-SECRET" })
        );
        assert!(
            !persisted
                .windows(b"RAW-RESULT-SECRET".len())
                .any(|window| { window == b"RAW-RESULT-SECRET" })
        );

        let mut after_lost_response = open(&path, "invocation-1");
        assert_eq!(
            after_lost_response
                .recover_effect(canonical_request)
                .expect("recover recorded result"),
            RecoveryDecision::ResultRecorded(evidence.clone())
        );
        assert_eq!(
            after_lost_response
                .record_result_for_test(&prepared, backend_result, OperationOutcome::Success)
                .expect("idempotently record same result"),
            evidence
        );
        assert!(matches!(
            after_lost_response.record_result_for_test(
                &prepared,
                b"changed result",
                OperationOutcome::Success
            ),
            Err(OperationJournalError::EvidenceMismatch(_))
        ));
    }

    #[test]
    fn os_call_identity_distinguishes_retry_from_deliberate_repeated_action() {
        let (_directory, path) = fixture();
        let mut journal = open(&path, "inv-adapter-effect-ordinal");
        let first = allocate(&mut journal, 0, b"canonical-a");
        let first_evidence = journal
            .record_result_for_test(&first, b"result-a", OperationOutcome::Success)
            .expect("record first result");
        let before_retries = fs::read(&path).expect("read state before retries");

        assert_eq!(
            journal
                .begin_effect_with_identity(
                    &first.os_tool_call_id,
                    first.adapter_effect_ordinal,
                    b"canonical-a",
                )
                .expect("same OS call identity and canonical content recovers"),
            EffectStart::Recovery(RecoveryDecision::ResultRecorded(first_evidence.clone()))
        );
        assert_eq!(fs::read(&path).unwrap(), before_retries);
        assert!(matches!(
            journal.begin_effect_with_identity(
                &first.os_tool_call_id,
                first.adapter_effect_ordinal,
                b"canonical-b",
            ),
            Err(OperationJournalError::EvidenceMismatch(_))
        ));
        assert!(matches!(
            journal.begin_effect_with_identity(
                &first.os_tool_call_id,
                first.adapter_effect_ordinal + 1,
                b"canonical-a",
            ),
            Err(OperationJournalError::EvidenceMismatch(_))
        ));
        assert!(matches!(
            journal.begin_effect(2, b"canonical-a"),
            Err(OperationJournalError::AdapterEffectOrdinalMismatch {
                expected: 1,
                received: 2
            })
        ));
        assert_eq!(fs::read(&path).unwrap(), before_retries);

        let second = allocate(&mut journal, 1, b"canonical-a");
        assert_eq!(second.journal_sequence, first.journal_sequence + 1);
        assert_eq!(second.adapter_effect_ordinal, 1);
        assert_ne!(second.request_id, first.request_id);
        assert_ne!(second.os_tool_call_id, first.os_tool_call_id);
        assert_eq!(
            second.canonical_request_sha256,
            first.canonical_request_sha256
        );
        assert_eq!(
            journal
                .begin_effect_with_identity(
                    &first.os_tool_call_id,
                    first.adapter_effect_ordinal,
                    b"canonical-a",
                )
                .expect("first logical call remains independently recoverable"),
            EffectStart::Recovery(RecoveryDecision::ResultRecorded(first_evidence))
        );
    }

    #[test]
    fn changed_delivery_attempt_is_unique_canonical_recovery_only() {
        let (_directory, path) = fixture();
        let mut original = open(&path, "inv-attempt-recovery");
        let prepared = allocate(&mut original, 0, b"canonical-pending");
        drop(original);

        let mut recovered =
            open_attempt(&path, "inv-attempt-recovery", RECOVERY_DELIVERY_ATTEMPT_ID);
        let plan = recovered
            .recovery_plan()
            .expect("read recovery plan")
            .expect("pending recovery plan");
        assert!(plan.recovery_only);
        assert_eq!(
            plan.pending_allocating_provider_attempt_id,
            ALLOCATING_ATTEMPT_ID
        );
        let before = fs::read(&path).expect("read state before recovery-only calls");
        assert_eq!(
            recovered
                .begin_effect_with_identity(
                    &prepared.os_tool_call_id,
                    prepared.adapter_effect_ordinal,
                    b"canonical-pending",
                )
                .expect("exact OS call identity recovers across delivery attempt"),
            EffectStart::Recovery(RecoveryDecision::RetryPrepared(prepared.clone()))
        );
        assert!(matches!(
            recovered.begin_effect(1, b"new-canonical-must-not-allocate"),
            Err(OperationJournalError::CanonicalDigestMismatch)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        let evidence = recovered
            .record_result_for_test(&prepared, b"recovered-result", OperationOutcome::Success)
            .expect("record result against old allocating attempt");
        assert_eq!(
            evidence.allocating_provider_attempt_id,
            ALLOCATING_ATTEMPT_ID
        );
        let acknowledgement = recovered
            .ack_invocation(
                Sha256Digest::of_bytes(b"durable-plan-ready-receipt"),
                &[evidence],
            )
            .expect("acknowledge recovered operation");
        assert_eq!(
            acknowledgement.delivery_provider_attempt_id,
            RECOVERY_DELIVERY_ATTEMPT_ID
        );
    }

    #[test]
    fn ordered_multi_effect_ack_requires_exact_evidence_and_receipt() {
        let (_directory, path) = fixture();
        let mut journal = open(&path, "invocation-ordered");

        let first = allocate(&mut journal, 0, b"effect-one");
        let first_evidence = journal
            .record_result_for_test(&first, b"result-one", OperationOutcome::Success)
            .expect("record first");
        let second = allocate(&mut journal, 1, b"effect-two");
        let second_evidence = journal
            .record_result_for_test(&second, b"result-two", OperationOutcome::BackendError)
            .expect("record second");
        assert_eq!(second.journal_sequence, first.journal_sequence + 1);

        let exact = vec![first_evidence, second_evidence];
        let mut reversed = exact.clone();
        reversed.reverse();
        assert!(matches!(
            journal.ack_invocation(Sha256Digest::of_bytes(b"receipt"), &[]),
            Err(OperationJournalError::EvidenceMismatch(_))
        ));
        assert!(matches!(
            journal.ack_invocation(Sha256Digest::of_bytes(b"receipt"), &reversed),
            Err(OperationJournalError::EvidenceMismatch(_))
        ));

        let receipt = Sha256Digest::of_bytes(b"durable PlanReady outer receipt bytes");
        let acknowledgement = journal
            .ack_invocation(receipt, &exact)
            .expect("ack exact evidence and receipt");
        assert_eq!(acknowledgement.operation_count, 2);
        assert_eq!(
            journal
                .ack_invocation(receipt, &exact)
                .expect("idempotent exact acknowledgement retry"),
            acknowledgement
        );
        assert!(matches!(
            journal.ack_invocation(Sha256Digest::of_bytes(b"other receipt"), &exact),
            Err(OperationJournalError::EvidenceMismatch(_))
        ));
        assert!(matches!(
            journal.begin_effect(2, b"known invocation id must not be reused"),
            Err(OperationJournalError::InvalidTransition(_))
        ));
        let after_reuse_attempt = read_state(&path);
        assert!(after_reuse_attempt.operations.is_empty());
        assert_eq!(after_reuse_attempt.next_sequence, 3);

        let mut next = open(&path, "invocation-next");
        let prepared = allocate(&mut next, 0, b"safe after exact acknowledgement");
        assert_eq!(prepared.journal_sequence, 3);
    }

    #[test]
    fn indeterminate_result_freezes_invocation_and_cannot_be_acknowledged() {
        let (_directory, path) = fixture();
        let canonical = b"effect-with-unknown-outcome";
        let mut journal = open(&path, "invocation-indeterminate");
        let prepared = allocate(&mut journal, 0, canonical);
        let evidence = journal
            .record_result_for_test(
                &prepared,
                b"backend-explicitly-reported-indeterminate",
                OperationOutcome::Indeterminate,
            )
            .expect("persist indeterminate outcome");
        let before_ack = fs::read(&path).expect("read journal before rejected ack");

        assert!(matches!(
            journal.begin_effect(1, b"must-not-overtake-indeterminate"),
            Err(OperationJournalError::RecoveryRequired {
                pending_invocation_id
            }) if pending_invocation_id == "invocation-indeterminate"
        ));
        assert!(matches!(
            journal.ack_invocation(
                Sha256Digest::of_bytes(b"outer-receipt-must-not-clear-indeterminate"),
                std::slice::from_ref(&evidence),
            ),
            Err(OperationJournalError::InvalidTransition(_))
        ));
        assert_eq!(
            fs::read(&path).expect("read journal after rejected ack"),
            before_ack
        );
        assert_eq!(
            journal
                .recover_effect(canonical)
                .expect("recover frozen indeterminate evidence"),
            RecoveryDecision::ResultRecorded(evidence)
        );

        let mut different_invocation = open(&path, "invocation-after-indeterminate");
        assert!(matches!(
            different_invocation.begin_effect(0, b"new-invocation-must-not-overtake"),
            Err(OperationJournalError::RecoveryRequired {
                pending_invocation_id
            }) if pending_invocation_id == "invocation-indeterminate"
        ));
    }

    #[test]
    fn classified_error_code_is_durable_and_exports_exact_outer_evidence() {
        let (_directory, path) = fixture();
        let mut journal = open(&path, "inv-classified-backend-error");
        let prepared = allocate(&mut journal, 0, b"effect-classified-backend-error");
        let exact_backend_result = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id.clone(),
            "ok": false,
            "error": "permission_denied",
        }))
        .unwrap();
        let evidence = journal
            .record_result(
                &prepared,
                &exact_backend_result,
                BackendCompletion::Response,
            )
            .expect("classify and persist definitive backend error");
        assert_eq!(evidence.outcome, OperationOutcome::BackendError);
        assert_eq!(
            evidence.backend_error_code.as_deref(),
            Some("permission_denied")
        );

        let persisted = read_state(&path);
        assert_eq!(
            persisted.operations[0].backend_error_code.as_deref(),
            Some("permission_denied")
        );
        let outer = evidence.to_outer_evidence().expect("export outer evidence");
        assert_eq!(outer.outcome, DirectOperationOuterOutcome::BackendError);
        assert_eq!(outer.backend_error_code, evidence.backend_error_code);
        assert_eq!(
            outer.backend_request_id_sha256,
            Sha256Digest::of_bytes(evidence.request_id.as_bytes()).to_hex()
        );

        let (_directory, path) = fixture();
        let mut journal = open(&path, "inv-request-in-flight");
        let prepared = allocate(&mut journal, 0, b"effect-request-in-flight");
        let exact_backend_result = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id.clone(),
            "ok": false,
            "error": "request_in_flight",
        }))
        .unwrap();
        let evidence = journal
            .record_result(
                &prepared,
                &exact_backend_result,
                BackendCompletion::Response,
            )
            .expect("persist ambiguous request-in-flight result");
        assert_eq!(evidence.outcome, OperationOutcome::Indeterminate);
        assert_eq!(
            evidence.backend_error_code.as_deref(),
            Some("request_in_flight")
        );
        assert!(matches!(
            journal.ack_invocation(
                Sha256Digest::of_bytes(b"must-not-ack-request-in-flight"),
                &[evidence],
            ),
            Err(OperationJournalError::InvalidTransition(_))
        ));
    }

    #[test]
    #[cfg(feature = "device-launch-package-conformance")]
    fn terminal_crash_before_return_replays_then_host_ack_survives_adapter_restart() {
        let (_directory, path) = fixture();
        let binding = binding("task-p01-device-replay", '4');
        let binding_sha256 = binding.digest_sha256().unwrap();
        let mut journal = open_bound(&path, &binding);

        let pristine = journal.device_conformance_replay_state().unwrap();
        assert_eq!(pristine.acknowledged_through, 0);
        assert_eq!(pristine.next_sequence, 1);
        assert_eq!(pristine.highest_retained_sequence, 0);
        assert_eq!(pristine.authenticated_ack_sha256, ZERO_DIGEST_HEX);

        let canonical = b"fixed-launch-package-settings";
        let prepared = allocate(&mut journal, 0, canonical);
        assert!(matches!(
            journal.device_conformance_replay_state(),
            Err(OperationJournalError::InvalidTransition(_))
        ));
        let exact_response = serde_json::to_vec(&serde_json::json!({
            "protocol": crate::system_api::PROTOCOL,
            "request_id": prepared.request_id,
            "ok": true,
        }))
        .unwrap();
        journal
            .record_result(&prepared, &exact_response, BackendCompletion::Response)
            .unwrap();
        drop(journal);

        let mut journal = open_bound(&path, &binding);
        let recovered = journal
            .begin_effect_with_identity(
                &prepared.os_tool_call_id,
                prepared.adapter_effect_ordinal,
                canonical,
            )
            .unwrap()
            .into_prepared();
        assert_eq!(recovered, prepared);
        assert_eq!(
            journal.replay_terminal_result(&recovered).unwrap(),
            Some(exact_response)
        );
        let terminal = journal.device_conformance_replay_state().unwrap();
        assert_eq!(terminal.epoch, prepared.epoch);
        assert_eq!(terminal.acknowledged_through, 0);
        assert_eq!(terminal.next_sequence, 2);
        assert_eq!(terminal.highest_retained_sequence, 1);

        let snapshot = journal.evidence_snapshot().unwrap();
        let inbox = outer_ack_v3(&binding, snapshot);
        journal
            .acknowledge_outer_v3(&binding, &binding_sha256, &inbox)
            .unwrap();
        let acknowledged = journal.device_conformance_replay_state().unwrap();
        assert_eq!(acknowledged.acknowledged_through, 1);
        assert_eq!(acknowledged.next_sequence, 2);
        assert_eq!(acknowledged.highest_retained_sequence, 0);
        assert_eq!(
            acknowledged.authenticated_ack_sha256,
            inbox.acknowledgement_sha256
        );
        assert_eq!(
            acknowledged.authenticated_ack_chain_sha256,
            inbox.chain_step.authenticated_ack_chain_sha256
        );

        // Simulate host persistence -> root ACK -> adapter crash/restart. The
        // exact ACK is idempotent, while the acknowledged invocation can never
        // allocate or effect again even if the original model call is retried.
        drop(journal);
        let mut restarted = open_bound(&path, &binding);
        assert_eq!(
            restarted.device_conformance_replay_state().unwrap(),
            acknowledged
        );
        restarted
            .acknowledge_outer_v3(&binding, &binding_sha256, &inbox)
            .unwrap();
        assert!(matches!(
            restarted.begin_effect_with_identity(
                &prepared.os_tool_call_id,
                prepared.adapter_effect_ordinal,
                canonical,
            ),
            Err(OperationJournalError::InvalidTransition(
                "invocation_id is already acknowledged and cannot allocate another effect"
            ))
        ));
    }

    #[test]
    fn outer_ack_v3_reclaims_exact_snapshot_and_advances_chain_contiguously() {
        let (_directory, path) = fixture();
        let first_binding = binding("task-outer-ack-first", '5');
        let mut first = open_bound(&path, &first_binding);
        let prepared = allocate(&mut first, 0, b"first-v3-effect");
        record_success(&mut first, &prepared);
        let first_snapshot = first.evidence_snapshot().unwrap();
        assert_eq!(first_snapshot.previous_ack_watermark, 0);
        assert_eq!(first_snapshot.previous_ack_chain_sha256, ZERO_DIGEST_HEX);
        assert_eq!(first_snapshot.first_journal_sequence, 1);
        assert_eq!(first_snapshot.last_journal_sequence, 1);
        assert_eq!(
            first_snapshot.allocation_binding_sha256,
            first_binding.digest_sha256().unwrap()
        );
        let first_ack = outer_ack_v3(&first_binding, first_snapshot.clone());
        let acknowledged = first
            .acknowledge_outer_v3(
                &first_binding,
                &first_binding.digest_sha256().unwrap(),
                &first_ack,
            )
            .unwrap();
        assert_eq!(acknowledged.first_journal_sequence, 1);
        assert_eq!(acknowledged.last_journal_sequence, 1);
        assert_eq!(
            first
                .acknowledge_outer_v3(
                    &first_binding,
                    &first_binding.digest_sha256().unwrap(),
                    &first_ack,
                )
                .unwrap(),
            acknowledged
        );
        let after_first = read_state(&path);
        assert!(after_first.operations.is_empty());
        assert_eq!(after_first.compacted_ack_watermark, 1);
        assert_eq!(
            after_first.compacted_ack_chain_sha256,
            first_ack.chain_step.authenticated_ack_chain_sha256
        );

        let second_binding = binding("task-outer-ack-second", '6');
        let mut second = open_bound(&path, &second_binding);
        let prepared = allocate(&mut second, 0, b"second-v3-effect");
        assert_eq!(prepared.journal_sequence, 2);
        record_success(&mut second, &prepared);
        let second_snapshot = second.evidence_snapshot().unwrap();
        assert_eq!(second_snapshot.previous_ack_watermark, 1);
        assert_eq!(second_snapshot.first_journal_sequence, 2);
        assert_eq!(
            second_snapshot.previous_ack_chain_sha256,
            first_ack.chain_step.authenticated_ack_chain_sha256
        );
        let second_ack = outer_ack_v3(&second_binding, second_snapshot);
        second
            .acknowledge_outer_v3(
                &second_binding,
                &second_binding.digest_sha256().unwrap(),
                &second_ack,
            )
            .unwrap();
        let after_second = read_state(&path);
        assert_eq!(after_second.compacted_ack_watermark, 2);
        assert_eq!(
            after_second.compacted_ack_chain_sha256,
            second_ack.chain_step.authenticated_ack_chain_sha256
        );
        assert!(matches!(
            first.acknowledge_outer_v3(
                &first_binding,
                &first_binding.digest_sha256().unwrap(),
                &first_ack,
            ),
            Err(OperationJournalError::EvidenceMismatch(_))
        ));
    }

    #[test]
    fn outer_ack_v3_rejects_drift_and_indeterminate_without_reclamation() {
        let (_directory, path) = fixture();
        let hold_binding = binding("task-outer-ack-hold", '7');
        let mut journal = open_bound(&path, &hold_binding);
        let prepared = allocate(&mut journal, 0, b"indeterminate-v3-effect");
        journal
            .record_result_for_test(
                &prepared,
                b"ambiguous-backend-observation",
                OperationOutcome::Indeterminate,
            )
            .unwrap();
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            journal.evidence_snapshot(),
            Err(OperationJournalError::InvalidTransition(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        let (_directory, path) = fixture();
        let drift_binding = binding("task-outer-ack-drift", '8');
        let mut journal = open_bound(&path, &drift_binding);
        let prepared = allocate(&mut journal, 0, b"definitive-v3-effect");
        record_success(&mut journal, &prepared);
        let snapshot = journal.evidence_snapshot().unwrap();
        let mut ack = outer_ack_v3(&drift_binding, snapshot);
        ack.acknowledgement.outer_receipt_sha256 = digest('9');
        let before = fs::read(&path).unwrap();
        assert!(matches!(
            journal.acknowledge_outer_v3(
                &drift_binding,
                &drift_binding.digest_sha256().unwrap(),
                &ack,
            ),
            Err(OperationJournalError::EvidenceMismatch(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn journal_v5_epoch_is_nonzero_and_zero_rng_output_is_retried() {
        let mut fills = 0_u8;
        let epoch = fresh_journal_epoch_with(|bytes| {
            fills += 1;
            bytes.fill(0);
            if fills == 2 {
                bytes[EPOCH_BYTES - 1] = 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(fills, 2);
        assert_eq!(epoch, "00000000000000000000000000000001");
        assert!(valid_journal_epoch(&epoch));

        let mut state = JournalState::new(
            "agent-codex-direct-v1".to_string(),
            "system_api".to_string(),
        )
        .unwrap();
        assert_ne!(state.epoch, ZERO_EPOCH_HEX);
        state.epoch = ZERO_EPOCH_HEX.to_string();
        assert!(encode_state(&state).is_err());

        let (_directory, path) = fixture();
        let mut journal = open(&path, "inv-zero-epoch-evidence");
        let prepared = allocate(&mut journal, 0, b"zero-epoch-evidence");
        let mut evidence = record_success(&mut journal, &prepared);
        evidence.epoch = ZERO_EPOCH_HEX.to_string();
        assert!(validate_operation_evidence(&evidence).is_err());
    }

    #[test]
    fn generated_request_identity_uses_full_digest_and_signed_long_sequence_bound() {
        let digest = Sha256Digest::of_bytes(b"full-canonical-request");
        let epoch = "0123456789abcdef0123456789abcdef";
        let request_id = generated_request_id(epoch, MAX_JOURNAL_SEQUENCE, digest)
            .expect("generate maximum bounded request identity");
        assert_eq!(request_id.len(), 120);
        assert_eq!(
            request_id,
            format!("op:{epoch}:{MAX_JOURNAL_SEQUENCE}:{}", digest.to_hex())
        );
        assert!(matches!(
            generated_request_id(epoch, 0, digest),
            Err(OperationJournalError::CapacityExhausted)
        ));
        assert!(matches!(
            generated_request_id(epoch, MAX_JOURNAL_SEQUENCE + 1, digest),
            Err(OperationJournalError::CapacityExhausted)
        ));
        assert!(matches!(
            generated_request_id(ZERO_EPOCH_HEX, 1, digest),
            Err(OperationJournalError::CapacityExhausted)
        ));
    }

    #[test]
    fn corrupt_truncated_unknown_duplicate_and_oversized_files_fail_closed() {
        {
            let (_directory, path) = fixture();
            let _journal = open(&path, "inv-corrupt");
            let mut envelope: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).expect("read envelope"))
                    .expect("parse envelope");
            envelope["payload"]["agent_id"] = serde_json::json!("other-agent");
            let mut encoded = serde_json::to_vec(&envelope).expect("encode corrupt envelope");
            encoded.push(b'\n');
            fs::write(&path, encoded).expect("write corrupt checksum");
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-corrupt",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let _journal = open(&path, "inv-truncated");
            let mut bytes = fs::read(&path).expect("read journal");
            bytes.pop();
            fs::write(&path, bytes).expect("write truncated journal");
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-truncated",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let _journal = open(&path, "inv-unknown");
            let mut envelope: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).expect("read envelope"))
                    .expect("parse envelope");
            envelope["unknown_future_field"] = serde_json::json!(true);
            let mut encoded = serde_json::to_vec(&envelope).expect("encode unknown envelope");
            encoded.push(b'\n');
            fs::write(&path, encoded).expect("write unknown schema field");
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-unknown",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let mut journal = open(&path, "inv-duplicate");
            allocate(&mut journal, 0, b"duplicate-me");
            let mut state = read_state(&path);
            state.operations.push(state.operations[0].clone());
            state.next_sequence += 1;
            write_unchecked_state(&path, state);
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-duplicate",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let mut journal = open(&path, "inv-short-digest-id");
            allocate(&mut journal, 0, b"full-digest-is-required");
            let mut state = read_state(&path);
            state.operations[0].request_id = format!(
                "op:{}:1:{}",
                state.epoch,
                &state.operations[0].canonical_request_sha256[..16]
            );
            write_unchecked_state(&path, state);
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-short-digest-id",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let _journal = open(&path, "inv-oversized");
            OpenOptions::new()
                .write(true)
                .open(&path)
                .expect("open journal for oversize fixture")
                .set_len(MAX_JOURNAL_BYTES as u64 + 1)
                .expect("oversize journal");
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-oversized",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
    }

    #[test]
    fn attempt_ordinal_schema_and_duplicate_call_identity_forgery_fail_closed() {
        {
            let (_directory, path) = fixture();
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-invalid-attempt",
                "attempt:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ));
            assert!(!path.exists());
        }
        {
            let (_directory, path) = fixture();
            let mut journal = open(&path, "inv-attempt-tamper");
            allocate(&mut journal, 0, b"attempt-tamper");
            let mut state = read_state(&path);
            state.operations[0].allocating_provider_attempt_id =
                RECOVERY_DELIVERY_ATTEMPT_ID.to_string();
            write_unchecked_state(&path, state);
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-attempt-tamper",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let mut journal = open(&path, "inv-adapter-ordinal-tamper");
            allocate(&mut journal, 0, b"adapter-ordinal-tamper");
            let mut state = read_state(&path);
            state.operations[0].adapter_effect_ordinal = 1;
            write_unchecked_state(&path, state);
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-adapter-ordinal-tamper",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        for version in 1..=4 {
            let (_directory, path) = fixture();
            let invocation_id = format!("inv-v{version}-schema");
            let _journal = open(&path, &invocation_id);
            let mut envelope: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            envelope["schema"] =
                serde_json::json!(format!("trillionnium.agent-operation-journal.v{version}"));
            let mut encoded = serde_json::to_vec(&envelope).unwrap();
            encoded.push(b'\n');
            fs::write(&path, encoded).unwrap();
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                &invocation_id,
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let mut journal = open(&path, "inv-missing-attempt-field");
            allocate(&mut journal, 0, b"missing-attempt-field");
            let mut envelope: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            envelope["payload"]["operations"][0]
                .as_object_mut()
                .unwrap()
                .remove("allocating_provider_attempt_id");
            let mut encoded = serde_json::to_vec(&envelope).unwrap();
            encoded.push(b'\n');
            fs::write(&path, encoded).unwrap();
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-missing-attempt-field",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let mut journal = open(&path, "inv-duplicate-tool-call");
            let first = allocate(&mut journal, 0, b"canonical-first");
            journal
                .record_result_for_test(&first, b"result-first", OperationOutcome::Success)
                .unwrap();
            allocate(&mut journal, 1, b"canonical-second");
            let mut state = read_state(&path);
            state.operations[1].os_tool_call_id = state.operations[0].os_tool_call_id.clone();
            write_unchecked_state(&path, state);
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-duplicate-tool-call",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let mut journal = open(&path, "inv-indeterminate-tail");
            let prepared = allocate(&mut journal, 0, b"indeterminate-first");
            journal
                .record_result_for_test(
                    &prepared,
                    b"unknown-result",
                    OperationOutcome::Indeterminate,
                )
                .unwrap();
            let mut state = read_state(&path);
            let canonical = Sha256Digest::of_bytes(b"forged-effect-after-indeterminate");
            let journal_sequence = state.next_sequence;
            state.operations.push(OperationRecord {
                invocation_id: "inv-indeterminate-tail".to_string(),
                allocating_provider_attempt_id: ALLOCATING_ATTEMPT_ID.to_string(),
                os_tool_call_id: test_tool_call_id(1),
                adapter_effect_ordinal: 1,
                journal_sequence,
                request_id: generated_request_id(&state.epoch, journal_sequence, canonical)
                    .unwrap(),
                canonical_request_sha256: canonical.to_hex(),
                prepared_transport_ack: None,
                state: PersistedOperationState::ResultRecorded,
                backend_result_sha256: Some(Sha256Digest::of_bytes(b"forged-result").to_hex()),
                backend_semantic_result_sha256: Some(
                    Sha256Digest::of_bytes(b"forged-semantic-result").to_hex(),
                ),
                backend_result_base64: Some(BASE64_STANDARD.encode(b"forged-result")),
                outcome: Some(OperationOutcome::Success),
                backend_error_code: None,
            });
            state.next_sequence += 1;
            write_unchecked_state(&path, state);
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-indeterminate-tail",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
    }

    #[test]
    fn symlink_hardlink_mode_and_ancestor_checks_fail_closed() {
        {
            let (directory, path) = fixture();
            let target = directory.path().join("target");
            fs::write(&target, b"not a journal\n").expect("create symlink target");
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
                .expect("set target mode");
            symlink(&target, &path).expect("create journal symlink");
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-symlink",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (directory, path) = fixture();
            let _journal = open(&path, "inv-hardlink");
            fs::hard_link(&path, directory.path().join("second-link")).expect("create hard link");
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-hardlink",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (_directory, path) = fixture();
            let _journal = open(&path, "inv-mode");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
                .expect("weaken journal mode");
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-mode",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let (directory, path) = fixture();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
                .expect("weaken directory mode");
            assert_rejected(OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "inv-directory-mode",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
        {
            let outer = tempfile::tempdir().expect("create outer fixture");
            fs::set_permissions(outer.path(), fs::Permissions::from_mode(0o700))
                .expect("set outer mode");
            let real = outer.path().join("real");
            fs::create_dir(&real).expect("create real directory");
            fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("set real mode");
            let linked = outer.path().join("linked");
            symlink(&real, &linked).expect("create ancestor symlink");
            assert_rejected(OperationJournal::open(
                linked.join("operations.json"),
                AGENT_ID,
                ADAPTER_ID,
                "inv-ancestor-symlink",
                ALLOCATING_ATTEMPT_ID,
            ));
        }
    }

    #[test]
    fn concurrent_retries_of_same_os_call_identity_allocate_exactly_once() {
        const WRITERS: usize = 8;

        let (_directory, path) = fixture();
        let _journal = open(&path, "inv-concurrent");
        let barrier = Arc::new(Barrier::new(WRITERS));
        let handles = (0..WRITERS)
            .map(|_| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let mut journal = open(&path, "inv-concurrent");
                    barrier.wait();
                    journal
                        .begin_effect(0, b"same-concurrent-effect")
                        .expect("begin concurrent retry of one OS call")
                })
            })
            .collect::<Vec<_>>();
        let starts = handles
            .into_iter()
            .map(|handle| handle.join().expect("join concurrent writer"))
            .collect::<Vec<_>>();
        let allocated = starts
            .iter()
            .filter_map(|start| match start {
                EffectStart::Allocated(prepared) => Some(prepared.clone()),
                EffectStart::Recovery(_) => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(allocated.len(), 1);
        let prepared = allocated[0].clone();
        for start in &starts {
            let request_id = match start {
                EffectStart::Allocated(value)
                | EffectStart::Recovery(RecoveryDecision::RetryPrepared(value)) => {
                    value.request_id.as_str()
                }
                EffectStart::Recovery(RecoveryDecision::ResultRecorded(_)) => {
                    panic!("result was not recorded during concurrent allocation")
                }
            };
            assert_eq!(request_id, prepared.request_id);
        }
        let mut journal = open(&path, "inv-concurrent");
        let evidence = journal
            .record_result_for_test(&prepared, b"one-result", OperationOutcome::Success)
            .expect("record the sole concurrent result");
        journal
            .ack_invocation(Sha256Digest::of_bytes(b"concurrent receipt"), &[evidence])
            .expect("ack concurrent evidence in journal-sequence order");
    }

    #[test]
    fn fsync_and_rename_faults_preserve_pre_effect_boundary() {
        let (_directory, path) = fixture();
        let mut journal = open(&path, "inv-faults");

        fail_next(FaultPoint::TempFileFsync);
        assert!(matches!(
            journal.begin_effect(0, b"temp-fsync-failure"),
            Err(OperationJournalError::Io(_))
        ));
        assert!(!journal.is_fail_stopped());
        assert!(
            journal
                .recovery_plan()
                .expect("inspect after temp fault")
                .is_none()
        );

        fail_next(FaultPoint::Rename);
        assert!(matches!(
            journal.begin_effect(0, b"rename-failure"),
            Err(OperationJournalError::Io(_))
        ));
        assert!(!journal.is_fail_stopped());
        assert!(
            journal
                .recovery_plan()
                .expect("inspect after rename fault")
                .is_none()
        );

        fail_next(FaultPoint::ParentFsyncAfterRename);
        assert!(matches!(
            journal.begin_effect(0, b"post-rename-parent-fsync-failure"),
            Err(OperationJournalError::DurabilityUncertain)
        ));
        assert!(journal.is_fail_stopped());
        assert!(matches!(
            journal.recovery_plan(),
            Err(OperationJournalError::ReopenRequired)
        ));

        let mut reopened = open(&path, "inv-faults");
        let recovered = reopened
            .recover_effect(b"post-rename-parent-fsync-failure")
            .expect("reopen after uncertain publication");
        assert!(matches!(recovered, RecoveryDecision::RetryPrepared(_)));
    }

    #[test]
    fn lock_wait_is_bounded() {
        let (_directory, path) = fixture();
        let _journal = open(&path, "inv-lock");
        let parent = SecureParent::open(&path).expect("open secure parent");
        let held = JournalLock::acquire(&parent, LOCK_TIMEOUT).expect("hold journal lock");
        let contender_path = path.clone();
        let contender = std::thread::spawn(move || {
            OperationJournal::open_with_parameters(JournalOpenParameters {
                path: contender_path,
                agent_id: AGENT_ID.to_string(),
                adapter_id: ADAPTER_ID.to_string(),
                invocation_id: "inv-lock".to_string(),
                delivery_provider_attempt_id: ALLOCATING_ATTEMPT_ID.to_string(),
                trusted_delivery_binding: None,
                trusted_delivery_binding_sha256: None,
                lock_timeout: Duration::from_millis(20),
                initialize_missing: true,
                trusted_state_directory: None,
                pinned_epoch: None,
                operation_epoch_authority_sha256: None,
                device_conformance_epoch_authority_bridge: false,
                required_open_state_sha256: None,
                required_open_file_identity: None,
            })
        });
        assert!(matches!(
            contender.join().expect("join lock contender"),
            Err(OperationJournalError::LockTimeout)
        ));
        drop(held);
    }

    #[test]
    fn mutation_private_names_are_fixed_destination_bound_and_lock_retains_fd_identity() {
        let (_directory, path) = fixture();
        let _journal = open(&path, "inv-fixed-mutation-names");
        let parent = SecureParent::open(&path).unwrap();
        let first = MutationPrivateNames::for_destination(&parent.destination_name).unwrap();
        let second = MutationPrivateNames::for_destination(&parent.destination_name).unwrap();
        assert_eq!(first.lock, second.lock);
        assert_eq!(first.staged_candidate, second.staged_candidate);
        assert_eq!(first.sidecar, second.sidecar);
        assert_eq!(first.sidecar_pending, second.sidecar_pending);
        let other = MutationPrivateNames::for_destination(c"other-operations.json").unwrap();
        assert_ne!(first.lock, other.lock);
        assert_ne!(first.staged_candidate, other.staged_candidate);
        assert_ne!(first.sidecar, other.sidecar);
        for name in [
            &first.lock,
            &first.staged_candidate,
            &first.sidecar,
            &first.sidecar_pending,
        ] {
            let text = name.to_str().unwrap();
            assert!(!text.contains(&std::process::id().to_string()));
            assert!(!text.contains("stage-mutation-nonce"));
        }

        let lock = JournalLock::acquire(&parent, LOCK_TIMEOUT).unwrap();
        assert_eq!(lock.name, first.lock);
        assert_eq!(
            private_file_identity(&lock.file, Some(0), 0, true).unwrap(),
            lock.identity
        );
        lock.revalidate(&parent).unwrap();
        assert_ne!(
            lock.identity_sha256(&parent).unwrap().to_hex(),
            ZERO_DIGEST_HEX
        );
    }

    #[test]
    fn retained_lock_candidate_and_sidecar_reject_link_mode_inode_and_byte_drift() {
        for attack in 0..5 {
            let (_directory, path) = fixture();
            let _journal = open(&path, "inv-lock-custody-drift");
            let parent = SecureParent::open(&path).unwrap();
            let lock = JournalLock::acquire(&parent, LOCK_TIMEOUT).unwrap();
            let lock_path = path.with_file_name(OsStr::from_bytes(lock.name.to_bytes()));
            match attack {
                0 => {
                    fs::remove_file(&lock_path).unwrap();
                    symlink(&path, &lock_path).unwrap();
                }
                1 => fs::hard_link(&lock_path, path.with_file_name("lock-extra-link")).unwrap(),
                2 => fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o640)).unwrap(),
                3 => {
                    let replacement = path.with_file_name("lock-replacement");
                    fs::write(&replacement, b"").unwrap();
                    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
                    fs::rename(replacement, &lock_path).unwrap();
                }
                4 => fs::write(&lock_path, b"x").unwrap(),
                _ => unreachable!(),
            }
            assert!(lock.revalidate(&parent).is_err());
        }

        for role in 0..2 {
            for attack in 0..5 {
                let (_directory, path) = fixture();
                let proposed = proposed_stage_state(&path);
                let parent = SecureParent::open(&path).unwrap();
                let lock = JournalLock::acquire(&parent, LOCK_TIMEOUT).unwrap();
                let candidate =
                    FsyncedMutationCandidate::materialize(&parent, &lock, &proposed).unwrap();
                let plan = mutation_stage_plan(&candidate);
                let stage = candidate.seal(plan).unwrap();
                let retained = if role == 0 {
                    &stage.candidate
                } else {
                    &stage.sidecar
                };
                let target = path.with_file_name(OsStr::from_bytes(retained.name.to_bytes()));
                match attack {
                    0 => {
                        fs::remove_file(&target).unwrap();
                        symlink(&path, &target).unwrap();
                    }
                    1 => fs::hard_link(
                        &target,
                        path.with_file_name(format!("stage-extra-link-{role}-{attack}")),
                    )
                    .unwrap(),
                    2 => fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap(),
                    3 => {
                        let replacement =
                            path.with_file_name(format!("stage-replacement-{role}-{attack}"));
                        fs::write(&replacement, &retained.bytes).unwrap();
                        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
                            .unwrap();
                        fs::rename(replacement, &target).unwrap();
                    }
                    4 => {
                        let mut changed = retained.bytes.clone();
                        changed[0] ^= 1;
                        fs::write(&target, changed).unwrap();
                    }
                    _ => unreachable!(),
                }
                assert!(stage.revalidate().is_err());
            }
        }
    }

    #[test]
    fn durable_mutation_stage_reopens_exact_sidecar_and_cleans_only_before_prepare() {
        let (_directory, path) = fixture();
        let proposed = proposed_stage_state(&path);
        let named_before = fs::read(&path).unwrap();
        let parent = SecureParent::open(&path).unwrap();
        let lock = JournalLock::acquire(&parent, LOCK_TIMEOUT).unwrap();
        let candidate = FsyncedMutationCandidate::materialize(&parent, &lock, &proposed).unwrap();
        let plan = mutation_stage_plan(&candidate);
        let stage = candidate.seal(plan).unwrap();
        stage.revalidate().unwrap();
        let names = MutationPrivateNames::for_destination(&parent.destination_name).unwrap();
        assert!(
            stat_entry(&parent.directory, &names.staged_candidate)
                .unwrap()
                .is_some()
        );
        assert!(
            stat_entry(&parent.directory, &names.sidecar)
                .unwrap()
                .is_some()
        );
        assert!(
            stat_entry(&parent.directory, &names.sidecar_pending)
                .unwrap()
                .is_none()
        );
        let (intent, writer_lock) = decode_mutation_stage_sidecar(&stage.sidecar.bytes).unwrap();
        assert_eq!(intent, stage.plan.intent);
        assert_eq!(writer_lock, lock.identity_sha256(&parent).unwrap());

        let lineage = stage.plan.lineage.clone();
        let current = stage.plan.current.clone();
        drop(stage);
        let reopened = DurableLocalMutationStage::reopen(&parent, &lock, lineage, current).unwrap();
        reopened.cleanup_before_prepare().unwrap();
        assert_eq!(fs::read(&path).unwrap(), named_before);
        for name in [
            &names.staged_candidate,
            &names.sidecar,
            &names.sidecar_pending,
        ] {
            assert!(stat_entry(&parent.directory, name).unwrap().is_none());
        }
        lock.revalidate(&parent).unwrap();
    }

    #[test]
    fn mutation_stage_fault_boundaries_cleanup_before_any_cas_entrypoint() {
        {
            let (_directory, path) = fixture();
            let proposed = proposed_stage_state(&path);
            let parent = SecureParent::open(&path).unwrap();
            let lock = JournalLock::acquire(&parent, LOCK_TIMEOUT).unwrap();
            let names = MutationPrivateNames::for_destination(&parent.destination_name).unwrap();
            fail_next(FaultPoint::MutationCandidateFsync);
            assert!(FsyncedMutationCandidate::materialize(&parent, &lock, &proposed).is_err());
            assert!(
                stat_entry(&parent.directory, &names.staged_candidate)
                    .unwrap()
                    .is_none()
            );
        }

        for point in [
            FaultPoint::MutationSidecarFsync,
            FaultPoint::MutationSidecarRename,
            FaultPoint::MutationStageParentFsync,
        ] {
            let (_directory, path) = fixture();
            let proposed = proposed_stage_state(&path);
            let named_before = fs::read(&path).unwrap();
            let parent = SecureParent::open(&path).unwrap();
            let lock = JournalLock::acquire(&parent, LOCK_TIMEOUT).unwrap();
            let names = MutationPrivateNames::for_destination(&parent.destination_name).unwrap();
            let candidate =
                FsyncedMutationCandidate::materialize(&parent, &lock, &proposed).unwrap();
            let plan = mutation_stage_plan(&candidate);
            fail_next(point);
            assert!(candidate.seal(plan).is_err());
            assert_eq!(fs::read(&path).unwrap(), named_before);
            for name in [
                &names.staged_candidate,
                &names.sidecar,
                &names.sidecar_pending,
            ] {
                assert!(stat_entry(&parent.directory, name).unwrap().is_none());
            }
            lock.revalidate(&parent).unwrap();
        }

        let source = include_str!("operation_journal.rs");
        let stage_source = source
            .split_once("impl LocalMutationStagePlan")
            .unwrap()
            .1
            .split_once("fn load_optional(")
            .unwrap()
            .0;
        for forbidden in ["mutation_cas_session", "send_prepare(", "prepare_call("] {
            assert!(
                !stage_source.contains(forbidden),
                "local materialization must remain backend-free: {forbidden}"
            );
        }
    }

    #[test]
    fn bounded_reuse_index_never_compacts_and_holds_before_identity_loss() {
        let (_directory, path) = fixture();
        for index in 0..MAX_ACKNOWLEDGEMENTS {
            let invocation_id = format!("inv-retained-{index}");
            let mut journal = open(&path, &invocation_id);
            let prepared = allocate(&mut journal, 0, format!("effect-{index}").as_bytes());
            let evidence = journal
                .record_result_for_test(
                    &prepared,
                    format!("result-{index}").as_bytes(),
                    OperationOutcome::Success,
                )
                .expect("record retained invocation");
            journal
                .ack_invocation(
                    Sha256Digest::of_bytes(format!("receipt-{index}").as_bytes()),
                    &[evidence],
                )
                .expect("ack retained invocation");
        }
        let saturated = read_state(&path);
        assert_eq!(saturated.acknowledgements.len(), MAX_ACKNOWLEDGEMENTS);
        assert_eq!(saturated.compacted_ack_watermark, 0);
        assert_eq!(saturated.compacted_ack_chain_sha256, ZERO_DIGEST_HEX);

        let before = fs::read(&path).unwrap();
        let mut reused = open(&path, "inv-retained-0");
        assert!(matches!(
            reused.begin_effect(0, b"compacted-invocation-reuse-must-never-activate"),
            Err(OperationJournalError::InvalidTransition(_))
        ));
        let mut next = open(&path, "inv-after-bounded-history");
        assert!(matches!(
            next.begin_effect(0, b"must-hold-before-forgetting-an-invocation"),
            Err(OperationJournalError::InvocationReuseIndexExhausted)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);

        let mut forged_compacted = saturated;
        forged_compacted.acknowledgements.remove(0);
        forged_compacted.compacted_ack_watermark = 1;
        forged_compacted.compacted_ack_chain_sha256 =
            Sha256Digest::of_bytes(b"forged-chain").to_hex();
        write_unchecked_state(&path, forged_compacted);
        assert_rejected(OperationJournal::open(
            &path,
            AGENT_ID,
            ADAPTER_ID,
            "inv-retained-0",
            ALLOCATING_ATTEMPT_ID,
        ));
    }

    #[test]
    fn deletion_and_product_reopen_never_mint_a_replacement_epoch() {
        let (_directory, path) = fixture();
        let mut journal = open(&path, "inv-delete-reopen");
        let prepared = allocate(&mut journal, 0, b"prepared-before-delete");
        let original_epoch = prepared.epoch;
        fs::remove_file(&path).expect("simulate deleted journal");

        assert!(matches!(
            journal.begin_effect(1, b"same-handle-after-delete"),
            Err(OperationJournalError::Corrupt(_))
        ));
        assert!(matches!(
            OperationJournal::open_with_parameters(JournalOpenParameters {
                path: path.clone(),
                agent_id: AGENT_ID.to_string(),
                adapter_id: ADAPTER_ID.to_string(),
                invocation_id: "inv-delete-reopen".to_string(),
                delivery_provider_attempt_id: ALLOCATING_ATTEMPT_ID.to_string(),
                trusted_delivery_binding: None,
                trusted_delivery_binding_sha256: None,
                lock_timeout: LOCK_TIMEOUT,
                initialize_missing: false,
                trusted_state_directory: None,
                pinned_epoch: None,
                operation_epoch_authority_sha256: None,
                device_conformance_epoch_authority_bridge: false,
                required_open_state_sha256: None,
                required_open_file_identity: None,
            }),
            Err(OperationJournalError::MissingTrustedJournal)
        ));
        assert!(!path.exists());

        // The test-only initializer demonstrates why production cannot use it:
        // it would mint a new epoch after deletion. It remains inaccessible in
        // non-test builds and therefore cannot reactivate product effects.
        let replacement = open(&path, "inv-delete-reopen");
        assert_ne!(read_state(&path).epoch, original_epoch);
        drop(replacement);
    }

    #[test]
    fn identity_and_absolute_path_are_trusted_constructor_inputs() {
        let (_directory, path) = fixture();
        let _journal = open(&path, "inv-identity");
        assert!(matches!(
            OperationJournal::open(
                &path,
                "different-agent",
                ADAPTER_ID,
                "inv-identity",
                ALLOCATING_ATTEMPT_ID,
            ),
            Err(OperationJournalError::IdentityMismatch)
        ));
        assert!(matches!(
            OperationJournal::open(
                Path::new("relative-journal"),
                AGENT_ID,
                ADAPTER_ID,
                "inv-relative",
                ALLOCATING_ATTEMPT_ID,
            ),
            Err(OperationJournalError::InvalidArgument(_))
        ));
        assert!(matches!(
            OperationJournal::open(
                &path,
                AGENT_ID,
                ADAPTER_ID,
                "contains/slash",
                ALLOCATING_ATTEMPT_ID,
            ),
            Err(OperationJournalError::InvalidArgument(_))
        ));
    }

    #[test]
    fn restart_and_replay_require_the_exact_external_prepared_ack_lineage() {
        let (_directory, path) = fixture();
        let binding = binding("task-prepared-ack-lineage", 'a');
        let initial_authority =
            Sha256Digest::of_bytes(b"external first-use operation-epoch lineage");
        let drifted_authority =
            Sha256Digest::of_bytes(b"different external replay operation-epoch lineage");
        assert_ne!(initial_authority, drifted_authority);

        let canonical_request = b"prepared-effect-bound-to-external-lineage";
        let mut initial = open_bound_with_runtime_authority(&path, &binding, initial_authority);
        let prepared = allocate(&mut initial, 0, canonical_request);
        let envelope = tool_call_envelope(&binding, &prepared);
        let acknowledgement = initial
            .prepared_transport_ack(&envelope, &prepared)
            .expect("persist PREPARED acknowledgement under first-use lineage");
        assert_eq!(
            acknowledgement.operation_epoch_authority_sha256,
            initial_authority.to_hex()
        );
        drop(initial);

        let before_rejected_restarts = fs::read(&path).unwrap();
        assert!(matches!(
            reopen_bound_with_exact_runtime_authority(&path, &binding, Some(drifted_authority),),
            Err(OperationJournalError::EvidenceMismatch(
                "stored PREPARED acknowledgement operation-epoch authority does not match current external runtime authority"
            ))
        ));
        assert_eq!(fs::read(&path).unwrap(), before_rejected_restarts);
        assert!(matches!(
            reopen_bound_with_exact_runtime_authority(&path, &binding, None),
            Err(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)
        ));
        assert_eq!(fs::read(&path).unwrap(), before_rejected_restarts);

        let mut exact_restart =
            reopen_bound_with_exact_runtime_authority(&path, &binding, Some(initial_authority))
                .expect("restart under exact external operation-epoch lineage");
        let recovered = match exact_restart
            .begin_effect(0, canonical_request)
            .expect("recover the exact PREPARED operation")
        {
            EffectStart::Recovery(RecoveryDecision::RetryPrepared(prepared)) => prepared,
            other => panic!("unexpected exact-lineage recovery: {other:?}"),
        };
        assert_eq!(
            exact_restart
                .prepared_transport_ack(&envelope, &recovered)
                .expect("replay byte-exact PREPARED acknowledgement"),
            acknowledgement
        );

        let mut drifted_after_open =
            reopen_bound_with_exact_runtime_authority(&path, &binding, Some(initial_authority))
                .expect("open before simulating runtime-authority drift");
        drifted_after_open.operation_epoch_authority_sha256 = Some(drifted_authority);
        assert!(matches!(
            drifted_after_open.prepared_transport_ack(&envelope, &prepared),
            Err(OperationJournalError::EvidenceMismatch(
                "stored PREPARED acknowledgement operation-epoch authority does not match current external runtime authority"
            ))
        ));

        let mut unavailable_after_open =
            reopen_bound_with_exact_runtime_authority(&path, &binding, Some(initial_authority))
                .expect("open before simulating runtime-authority loss");
        unavailable_after_open.operation_epoch_authority_sha256 = None;
        assert!(matches!(
            unavailable_after_open.recovery_plan(),
            Err(OperationJournalError::PreparedAcknowledgementAuthorityUnavailable)
        ));
        assert_eq!(fs::read(&path).unwrap(), before_rejected_restarts);
    }

    #[test]
    fn exact_open_authority_rejects_same_bytes_on_a_replacement_inode() {
        let (_directory, path) = fixture();
        let initialized = open(&path, "inv-open-authority-inode");
        drop(initialized);

        let parent = SecureParent::open(&path).expect("open secure parent");
        let loaded = load_optional(&parent)
            .expect("load journal")
            .expect("journal exists");
        let expected_identity = loaded.identity;
        let expected_state_sha256 =
            Sha256Digest::of_bytes(&encode_state(&loaded.state).expect("encode state"));
        let replacement = path.with_file_name("operations.replacement");
        fs::write(&replacement, fs::read(&path).expect("read original"))
            .expect("write replacement");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600))
            .expect("set replacement mode");
        fs::rename(&replacement, &path).expect("replace named journal");

        let replaced = load_optional(&parent)
            .expect("load replacement")
            .expect("replacement exists");
        assert_eq!(
            Sha256Digest::of_bytes(&encode_state(&replaced.state).expect("encode replacement")),
            expected_state_sha256
        );
        assert!(
            replaced.identity.device != expected_identity.device
                || replaced.identity.inode != expected_identity.inode
        );
        assert!(matches!(
            OperationJournal::open_with_parameters(JournalOpenParameters {
                path: path.clone(),
                agent_id: AGENT_ID.to_string(),
                adapter_id: ADAPTER_ID.to_string(),
                invocation_id: "inv-open-authority-inode".to_string(),
                delivery_provider_attempt_id: ALLOCATING_ATTEMPT_ID.to_string(),
                trusted_delivery_binding: None,
                trusted_delivery_binding_sha256: None,
                lock_timeout: LOCK_TIMEOUT,
                initialize_missing: false,
                trusted_state_directory: None,
                pinned_epoch: Some(replaced.state.epoch.clone()),
                operation_epoch_authority_sha256: None,
                device_conformance_epoch_authority_bridge: false,
                required_open_state_sha256: Some(expected_state_sha256),
                required_open_file_identity: Some(expected_identity),
            }),
            Err(OperationJournalError::IdentityMismatch)
        ));
    }

    #[test]
    fn all_four_mutation_choke_points_enter_the_sealed_same_store_cas_pipeline() {
        let source = include_str!("operation_journal.rs");
        let (product_source, _) = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("operation-journal test module boundary");
        assert!(product_source.contains(
            "mutation_cas_session: Option<\n        crate::direct_operation_runtime_authority_mutation_cas_client::SealedCommittedMutationCasSession,"
        ));
        assert_eq!(
            product_source
                .matches("journal.mutation_cas_session = Some(mutation_cas_session)")
                .count(),
            1,
            "only the successful first-use aggregate may install the affine session"
        );
        assert!(
            !product_source.contains("#[derive(Debug)]\npub struct OperationJournal"),
            "Debug must remain handwritten and omit the sealed session"
        );

        for (start_marker, end_marker, mutation_kind) in [
            (
                "    pub fn begin_effect_with_identity(",
                "\n    #[cfg(test)]\n    pub fn begin_effect(",
                "DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect",
            ),
            (
                "    pub(crate) fn prepared_transport_ack(",
                "\n    /// Test-only compatibility helper.",
                "DirectOperationRuntimeAuthorityMutationKindV1::PersistPreparedTransportAck",
            ),
            (
                "    fn record_classified_result(",
                "\n    #[cfg(test)]\n    fn record_result_for_test(",
                "DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult",
            ),
            (
                "    fn acknowledge_outer_v3(",
                "\n    /// Inspect unresolved operations",
                "DirectOperationRuntimeAuthorityMutationKindV1::AcknowledgeOuterV2",
            ),
        ] {
            let (_, remainder) = product_source
                .split_once(start_marker)
                .unwrap_or_else(|| panic!("missing source marker {start_marker}"));
            let (function_source, _) = remainder
                .split_once(end_marker)
                .unwrap_or_else(|| panic!("missing source boundary {end_marker}"));
            assert!(
                !function_source.contains("mutation_cas_session"),
                "{start_marker} must enter only through the sealed journal pipeline"
            );
            assert!(function_source.contains("self.publish_mutation("));
            assert!(function_source.contains(mutation_kind));
        }

        let (_, remainder) = product_source
            .split_once("    fn publish_mutation(")
            .expect("sealed mutation publisher");
        let (publisher, _) = remainder
            .split_once("\n}\n\nimpl JournalState")
            .expect("sealed mutation publisher boundary");
        for required in [
            "mutation_cas_session",
            ".take()",
            "validate_current(",
            "FsyncedMutationCandidate::materialize(",
            ".seal(stage_plan)",
            ".send_prepare()",
            "stage.publish()",
            ".commit()",
            ".cleanup_after_commit()",
            ".reopen_after_local_cleanup(",
            "self.mutation_cas_session = Some(current)",
        ] {
            assert!(
                publisher.contains(required),
                "sealed mutation publisher is missing {required}"
            );
        }
    }

    #[test]
    fn runtime_open_consumer_token_is_module_sealed_and_required() {
        let source = include_str!("operation_journal.rs");
        let (product_source, _) = source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("operation-journal test module boundary");
        assert_eq!(
            product_source
                .matches("\n}\n\nmod runtime_open_consumer {")
                .count(),
            1,
            "the private child module must have no outer attribute or macro wrapper"
        );
        let (_, consumer_remainder) = product_source
            .split_once("mod runtime_open_consumer {")
            .expect("private runtime-open consumer module");
        let (consumer_source, _) = consumer_remainder
            .split_once(
                "\n}\n\npub(crate) use runtime_open_consumer::Token as \
                 OperationJournalRuntimeOpenConsumerToken;",
            )
            .expect("runtime-open consumer module boundary");

        let token_declaration = concat!(
            "    pub(crate) struct Token {\n",
            "        _private: (),\n",
            "    }",
        );
        assert_eq!(
            consumer_source.matches(token_declaration).count(),
            1,
            "the token declaration must remain opaque"
        );
        assert!(
            !consumer_source.contains("#[derive"),
            "the runtime-open consumer token must remain affine and opaque"
        );
        assert!(
            !consumer_source.contains('!'),
            "the private child forbids macro expansion that could mint or export a token"
        );
        let attributes = consumer_source
            .lines()
            .map(str::trim)
            .filter(|line| line.starts_with("#["))
            .collect::<Vec<_>>();
        assert_eq!(
            attributes,
            ["#[cfg(test)]", "#[allow(dead_code)]", "#[allow(dead_code)]"],
            "only the built-in test gate and two dead-code annotations are allowed in the private child"
        );
        let attribute_free_source =
            consumer_source
                .replacen("#[cfg(test)]", "", 1)
                .replacen("#[allow(dead_code)]", "", 2);
        assert!(
            !attribute_free_source.contains('#'),
            "no spaced, hidden, or additional attribute may expand inside the private child"
        );

        let private_claim = concat!(
            "    const fn ",
            "claim",
            "() -> Token {\n",
            "        Token { _private: () }\n",
            "    }",
        );
        assert_eq!(
            consumer_source.matches(private_claim).count(),
            1,
            "only the private child module may mint a token"
        );

        let test_factory = concat!(
            "    #[cfg(test)]\n",
            "    pub(crate) const fn claim_for_test() -> Token {\n",
            "        ",
            "claim",
            "()\n",
            "    }",
        );
        assert_eq!(
            consumer_source.matches(test_factory).count(),
            1,
            "the only direct test factory must remain explicitly cfg(test)"
        );
        assert_eq!(
            consumer_source.matches("pub(crate)").count(),
            4,
            "the child API is exactly Token, one cfg(test) factory, and two journal opens"
        );
        let identifiers = consumer_source
            .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
            .filter(|token| !token.is_empty())
            .collect::<Vec<_>>();
        for (identifier, expected) in [("pub", 4), ("impl", 1), ("Token", 4), ("claim", 4)] {
            assert_eq!(
                identifiers
                    .iter()
                    .filter(|token| **token == identifier)
                    .count(),
                expected,
                "unexpected lexical {identifier} surface in the private child"
            );
        }
        for forbidden in ["pub(super)", "pub(in ", "macro_rules!"] {
            assert!(
                !consumer_source.contains(forbidden),
                "runtime-open consumer child exposes forbidden visibility or macro surface: {forbidden}"
            );
        }
        for line in consumer_source.lines() {
            assert!(
                !line.trim_start().starts_with("pub "),
                "the private child must not expose an unrestricted public item: {line}"
            );
        }
        assert_eq!(
            consumer_source.matches("impl ").count(),
            1,
            "the child may contain only the OperationJournal inherent impl"
        );
        assert!(consumer_source.contains("    impl OperationJournal {"));
        assert_eq!(
            consumer_source.matches("Token { _private: () }").count(),
            1,
            "no second token value may be materialized"
        );

        let test_reexport = concat!(
            "#[cfg(test)]\n",
            "pub(crate) use runtime_open_consumer::claim_for_test as ",
            "operation_journal_runtime_open_consumer_for_test;\n",
        );
        assert_eq!(
            product_source.matches(test_reexport).count(),
            1,
            "the crate-visible test factory re-export must remain cfg(test)"
        );

        let first_use_header = concat!(
            "        pub(crate) fn open_trusted_after_first_use(\n",
            "            context: &crate::trusted_context::TrustedAdapterContext,\n",
            "            authority: crate::secure_first_use_journal::VerifiedFirstUseJournal,\n",
            "        ) -> JournalResult<Self> {",
        );
        let replay_header = concat!(
            "        pub(crate) fn open_trusted_after_replay(\n",
            "            context: &crate::trusted_context::TrustedAdapterContext,\n",
            "            authority: crate::secure_first_use_journal::VerifiedJournalReplayAuthority,\n",
            "        ) -> JournalResult<Self> {",
        );
        assert_eq!(consumer_source.matches(first_use_header).count(), 1);
        assert_eq!(consumer_source.matches(replay_header).count(), 1);

        let claim_call = ["claim", "()"].concat();
        assert_eq!(
            consumer_source.matches(&claim_call).count(),
            4,
            "the private claim may appear only in its definition, the cfg(test) factory, and two journal opens"
        );
        for (start_marker, end_marker) in [
            (
                "        pub(crate) fn open_trusted_after_first_use(",
                "\n        /// Consume one exact external replay/high-water result",
            ),
            (
                "        pub(crate) fn open_trusted_after_replay(",
                "\n    }",
            ),
        ] {
            let (_, remainder) = consumer_source
                .split_once(start_marker)
                .unwrap_or_else(|| panic!("missing source marker {start_marker}"));
            let (open_source, _) = remainder
                .split_once(end_marker)
                .unwrap_or_else(|| panic!("missing source boundary {end_marker}"));
            assert_eq!(
                open_source.matches(&claim_call).count(),
                1,
                "{start_marker} must consume exactly one sealed runtime-open token"
            );
        }

        let secure_source = include_str!("secure_first_use_journal.rs");
        let (secure_product_source, _) = secure_source
            .split_once("#[cfg(test)]\nmod tests {")
            .expect("secure first-use test module boundary");
        assert_eq!(
            secure_product_source
                .matches(
                    "_consumer: \
                     crate::operation_journal::OperationJournalRuntimeOpenConsumerToken",
                )
                .count(),
            2,
            "first-use and replay consumers must both require the sealed token"
        );
        assert!(
            source.ends_with("// SECURITY: no product source follows the cfg(test) module.\n"),
            "the test module must remain the final source region"
        );
    }
}

// SECURITY: no product source follows the cfg(test) module.
