//! Daemon-owned custody for Direct-operation delivery.
//!
//! Product authority remains source-only and unconstructible from the live
//! product path. The separately compiled P0 userdebug feature wires one exact
//! System API custody chain through publication, measured replay launch,
//! Android ACK confirmation and inbox retirement; it does not promote that
//! conformance chain into product, hardware rollback or device evidence.

mod high_water;
mod linux_operation_replay_sync_launcher;
mod operation_replay_sync_launcher;
mod outer_ack_publisher;

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(feature = "p0-launch-package-device-conformance")]
use trillionnium_os_types::direct_operation::DirectOperationP0ReplaySyncSealedAuthorityV1;
use trillionnium_os_types::direct_operation::{
    BINDING_INBOX_SCHEMA, DirectOperationAdapter, DirectOperationAdapterTerminalDispositionV1,
    DirectOperationBinding, DirectOperationBindingInbox, DirectOperationOuterAckChainStepV3,
    DirectOperationOuterAckInboxV3, DirectOperationOuterAckV3, DirectOperationOuterReceiptV3,
    OUTER_ACK_INBOX_V3_SCHEMA, OUTER_ACK_V3_SCHEMA, OUTER_RECEIPT_V3_SCHEMA,
};
use trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHead;
use trillionnium_os_types::direct_operation_tool_call_transport as transport_contract;
use trillionnium_os_types::sha256_bytes;

#[cfg(test)]
use self::high_water::TestDirectOperationCustodyHighWaterAuthority;
use self::high_water::{
    FIXED_PRODUCT_CUSTODY_STORE_PATH, VerifiedDirectOperationCustodyHighWater, product_route,
};

use crate::context_memory::VerifiedDirectUiReplaySnapshot;
#[cfg(feature = "p0-launch-package-device-conformance")]
use crate::direct_operation_binding_inbox::DirectOperationInboxCustodySeed;
use crate::egress_journal::VerifiedDirectTerminalEgressSnapshot;

const STORE_SCHEMA: &str = "trillionnium.direct-operation-daemon-custody.v3";
const RECORD_SCHEMA: &str = "trillionnium.direct-operation-daemon-custody-record.v3";
const BINDING_PREPARED_SCHEMA: &str = "trillionnium.direct-operation-binding-prepared-custody.v3";
const BINDING_PUBLICATION_SCHEMA: &str =
    "trillionnium.direct-operation-binding-publication-proof.v3";
const BINDING_LEAF_PUBLICATION_SCHEMA: &str =
    "trillionnium.direct-operation-binding-leaf-publication-proof.v3";
const TERMINAL_EGRESS_PROOF_SCHEMA: &str =
    "trillionnium.direct-operation-terminal-egress-cas-proof.v1";
const DIRECT_UI_PROOF_SCHEMA: &str = "trillionnium.direct-operation-direct-ui-custody-proof.v1";
const ACK_INTENT_SCHEMA: &str = "trillionnium.direct-operation-daemon-ack-intent.v3";
const ACK_INBOX_PUBLICATION_PROOF_SCHEMA: &str =
    "trillionnium.direct-operation-outer-ack-inbox-publication-proof.v3";
const ACK_PUBLISHER_PROVENANCE_SCHEMA: &str =
    "trillionnium.direct-operation-outer-ack-publisher-provenance.v4";
const ANDROID_BACKEND_ACK_CONFIRMATION_PROOF_SCHEMA: &str =
    "trillionnium.direct-operation-android-backend-ack-confirmation-proof.v3";
const REPLAY_SYNC_LAUNCH_PROGRESS_SCHEMA: &str =
    "trillionnium.direct-operation-replay-sync-launch-progress.v3";
const REPLAY_SYNC_LAUNCH_RECEIPT_SCHEMA: &str =
    "trillionnium.direct-operation-replay-sync-launch-receipt.v4";
const OUTER_ACK_RETIREMENT_PROOF_SCHEMA: &str =
    "trillionnium.direct-operation-outer-ack-retirement-proof.v3";
const ADAPTER_ACK_PROGRESS_SCHEMA: &str =
    "trillionnium.direct-operation-daemon-adapter-ack-progress.v3";
const MAX_STORE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECORDS: usize = 128;
const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RECORD_DIGEST_DOMAIN: &[u8] = b"trillionnium.direct-operation-daemon-custody-record.v3";
const ACK_INTENT_DIGEST_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-daemon-ack-intent-digest.v3";
const REPLAY_SYNC_LAUNCH_ID_DIGEST_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-replay-sync-launch-id.v3";
const REPLAY_SYNC_LAUNCH_CHALLENGE_DIGEST_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-replay-sync-launch-challenge.v3";
const REPLAY_SYNC_LAUNCH_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-replay-sync-launch-receipt.v4";
const AUTHORIZED_LEAF_SET_DIGEST_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-binding-authorized-leaf-publication-set.v3";
const TERMINAL_EGRESS_DIGEST_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-terminal-egress-cas-snapshot.v1";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BindingCustodyStage {
    BindingPrepared,
    BindingPublished,
    CancelledBeforeTool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationBindingPreparedV3 {
    schema: String,
    binding: DirectOperationBinding,
    binding_sha256: String,
    binding_inbox: DirectOperationBindingInbox,
    binding_inbox_bytes_sha256: String,
    egress_grant_id_sha256: String,
    egress_journal_binding_sha256: String,
    allocation_egress_cas_sha256: String,
}

impl DirectOperationBindingPreparedV3 {
    fn validate(&self) -> Result<()> {
        if self.schema != BINDING_PREPARED_SCHEMA {
            bail!("direct_operation_custody_binding_prepared_schema_denied");
        }
        self.binding
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        self.binding_inbox
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        if self
            .binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?
            != self.binding_sha256
            || self.binding_inbox.schema != BINDING_INBOX_SCHEMA
            || self.binding_inbox.binding != self.binding
            || binding_inbox_bytes_sha256(&self.binding_inbox)? != self.binding_inbox_bytes_sha256
            || !valid_nonzero_sha256(&self.egress_grant_id_sha256)
            || !valid_nonzero_sha256(&self.egress_journal_binding_sha256)
            || !valid_nonzero_sha256(&self.allocation_egress_cas_sha256)
        {
            bail!("direct_operation_custody_binding_prepared_identity_denied");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationBindingLeafPublicationProofV3 {
    schema: String,
    adapter: DirectOperationAdapter,
    authorized_adapter_set_sha256: String,
    binding_sha256: String,
    binding_inbox_bytes_sha256: String,
    parent_directory_identity_sha256: String,
    published_file_identity_sha256: String,
    published_bytes_sha256: String,
    parent_directory_fsync_proof_sha256: String,
}

impl DirectOperationBindingLeafPublicationProofV3 {
    fn validate_for_prepared(&self, prepared: &DirectOperationBindingPreparedV3) -> Result<()> {
        let authorized_adapter_set_sha256 = prepared
            .binding
            .authorized_adapter_set
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        if self.schema != BINDING_LEAF_PUBLICATION_SCHEMA
            || self.authorized_adapter_set_sha256 != authorized_adapter_set_sha256
            || !prepared
                .binding
                .authorized_adapter_set
                .authorizes(self.adapter)
            || self.binding_sha256 != prepared.binding_sha256
            || self.binding_inbox_bytes_sha256 != prepared.binding_inbox_bytes_sha256
            || self.published_bytes_sha256 != prepared.binding_inbox_bytes_sha256
            || !valid_nonzero_sha256(&self.parent_directory_identity_sha256)
            || !valid_nonzero_sha256(&self.published_file_identity_sha256)
            || !valid_nonzero_sha256(&self.parent_directory_fsync_proof_sha256)
        {
            bail!("direct_operation_custody_leaf_publication_proof_denied");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationBindingPublicationProofV3 {
    schema: String,
    authorized_adapter_set_sha256: String,
    binding_sha256: String,
    binding_inbox_bytes_sha256: String,
    leaves: Vec<DirectOperationBindingLeafPublicationProofV3>,
    leaves_sha256: String,
}

impl DirectOperationBindingPublicationProofV3 {
    fn validate_for_prepared(&self, prepared: &DirectOperationBindingPreparedV3) -> Result<()> {
        let authorized = &prepared.binding.authorized_adapter_set;
        authorized
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        let authorized_adapter_set_sha256 = authorized
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        if self.schema != BINDING_PUBLICATION_SCHEMA
            || self.authorized_adapter_set_sha256 != authorized_adapter_set_sha256
            || self.binding_sha256 != prepared.binding_sha256
            || self.binding_inbox_bytes_sha256 != prepared.binding_inbox_bytes_sha256
            || self.leaves.len() != authorized.authorized_adapters.len()
        {
            bail!("direct_operation_custody_authorized_leaf_publication_set_denied");
        }
        let mut parent_directory_identities = BTreeSet::new();
        let mut published_file_identities = BTreeSet::new();
        for (leaf, authorized_adapter) in self.leaves.iter().zip(&authorized.authorized_adapters) {
            if leaf.adapter != *authorized_adapter {
                bail!("direct_operation_custody_authorized_leaf_publication_set_denied");
            }
            leaf.validate_for_prepared(prepared)?;
            if !parent_directory_identities.insert(&leaf.parent_directory_identity_sha256)
                || !published_file_identities.insert(&leaf.published_file_identity_sha256)
            {
                bail!("direct_operation_custody_authorized_leaf_publication_identity_reuse_denied");
            }
        }
        if domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &self.leaves)? != self.leaves_sha256 {
            bail!("direct_operation_custody_leaf_publication_digest_mismatch");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TerminalEgressState {
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationTerminalEgressProofV1 {
    schema: String,
    binding_sha256: String,
    invocation_id: String,
    delivery_provider_attempt_id: String,
    egress_grant_id_sha256: String,
    egress_journal_binding_sha256: String,
    terminal_state: TerminalEgressState,
    final_record_sha256: String,
    predecessor_record_sha256: String,
    runtime_evidence_sha256: String,
    provider_teardown_completion_ack_sha256: String,
    terminal_egress_cas_sha256: String,
}

impl DirectOperationTerminalEgressProofV1 {
    fn expected_terminal_digest(&self) -> Result<String> {
        #[derive(Serialize)]
        struct DigestPreimage<'a> {
            schema: &'a str,
            binding_sha256: &'a str,
            invocation_id: &'a str,
            delivery_provider_attempt_id: &'a str,
            egress_grant_id_sha256: &'a str,
            egress_journal_binding_sha256: &'a str,
            terminal_state: TerminalEgressState,
            final_record_sha256: &'a str,
            predecessor_record_sha256: &'a str,
            runtime_evidence_sha256: &'a str,
            provider_teardown_completion_ack_sha256: &'a str,
        }
        domain_digest(
            TERMINAL_EGRESS_DIGEST_DOMAIN,
            &DigestPreimage {
                schema: &self.schema,
                binding_sha256: &self.binding_sha256,
                invocation_id: &self.invocation_id,
                delivery_provider_attempt_id: &self.delivery_provider_attempt_id,
                egress_grant_id_sha256: &self.egress_grant_id_sha256,
                egress_journal_binding_sha256: &self.egress_journal_binding_sha256,
                terminal_state: self.terminal_state,
                final_record_sha256: &self.final_record_sha256,
                predecessor_record_sha256: &self.predecessor_record_sha256,
                runtime_evidence_sha256: &self.runtime_evidence_sha256,
                provider_teardown_completion_ack_sha256: &self
                    .provider_teardown_completion_ack_sha256,
            },
        )
    }

    fn validate_for_prepared(&self, prepared: &DirectOperationBindingPreparedV3) -> Result<()> {
        if self.schema != TERMINAL_EGRESS_PROOF_SCHEMA
            || self.binding_sha256 != prepared.binding_sha256
            || self.invocation_id != prepared.binding.invocation_id
            || self.delivery_provider_attempt_id
                != prepared.binding.attempt.delivery_provider_attempt_id
            || self.egress_grant_id_sha256 != prepared.egress_grant_id_sha256
            || self.egress_journal_binding_sha256 != prepared.egress_journal_binding_sha256
            || self.terminal_state != TerminalEgressState::Completed
            || !valid_nonzero_sha256(&self.final_record_sha256)
            || !valid_nonzero_sha256(&self.predecessor_record_sha256)
            || !valid_nonzero_sha256(&self.runtime_evidence_sha256)
            || !valid_nonzero_sha256(&self.provider_teardown_completion_ack_sha256)
            || self.expected_terminal_digest()? != self.terminal_egress_cas_sha256
        {
            bail!("direct_operation_custody_terminal_egress_proof_denied");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationDirectUiProofV1 {
    schema: String,
    binding_sha256: String,
    invocation_id: String,
    delivery_provider_attempt_id: String,
    direct_execution_receipt_sha256: String,
    direct_result_semantic_sha256: String,
    ui_replay_completion_proof_sha256: String,
    ui_replay_semantic_sha256: String,
}

impl DirectOperationDirectUiProofV1 {
    fn validate_for_prepared(&self, prepared: &DirectOperationBindingPreparedV3) -> Result<()> {
        if self.schema != DIRECT_UI_PROOF_SCHEMA
            || self.binding_sha256 != prepared.binding_sha256
            || self.invocation_id != prepared.binding.invocation_id
            || self.delivery_provider_attempt_id
                != prepared.binding.attempt.delivery_provider_attempt_id
            || !valid_nonzero_sha256(&self.direct_execution_receipt_sha256)
            || !valid_nonzero_sha256(&self.direct_result_semantic_sha256)
            || !valid_nonzero_sha256(&self.ui_replay_completion_proof_sha256)
            || !valid_nonzero_sha256(&self.ui_replay_semantic_sha256)
        {
            bail!("direct_operation_custody_direct_ui_proof_denied");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum AdapterDispositionCustody {
    AwaitingAuthenticatedDisposition,
    Authenticated {
        terminal_disposition: Box<DirectOperationAdapterTerminalDispositionV1>,
        /// Root-store provenance for the future trusted handoff. This digest
        /// is intentionally not supplied by MCP/provider evidence and is not
        /// part of the public receipt contract.
        authentication_capability_sha256: String,
    },
}

impl AdapterDispositionCustody {
    fn authenticated(&self) -> bool {
        matches!(self, Self::Authenticated { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticatedAdapterDisposition {
    adapter: DirectOperationAdapter,
    disposition: AdapterDispositionCustody,
}

impl AuthenticatedAdapterDisposition {
    fn awaiting(adapter: DirectOperationAdapter) -> Self {
        Self {
            adapter,
            disposition: AdapterDispositionCustody::AwaitingAuthenticatedDisposition,
        }
    }

    fn validate_for_prepared(&self, prepared: &DirectOperationBindingPreparedV3) -> Result<()> {
        match &self.disposition {
            AdapterDispositionCustody::AwaitingAuthenticatedDisposition => Ok(()),
            AdapterDispositionCustody::Authenticated {
                terminal_disposition,
                authentication_capability_sha256,
            } => {
                terminal_disposition
                    .validate_for_binding(&prepared.binding, self.adapter)
                    .map_err(|error| anyhow!(error.to_string()))?;
                if terminal_disposition.adapter != self.adapter
                    || !valid_nonzero_sha256(authentication_capability_sha256)
                {
                    bail!("direct_operation_custody_authenticated_disposition_denied");
                }
                Ok(())
            }
        }
    }
}

/// Capability wrappers intentionally have no production constructor. A future
/// source must authenticate secure journal/egress/UI provenance before adding
/// such a constructor. In particular, MCP or provider evidence is insufficient.
pub(crate) struct VerifiedAdapterDisposition(AuthenticatedAdapterDisposition);

#[cfg(feature = "p0-launch-package-device-conformance")]
impl VerifiedAdapterDisposition {
    pub(crate) fn from_p0_userdebug_authenticated_transport(
        peer: &crate::direct_tool_call_transport::VerifiedP0UserdebugAdapterTransportPeer,
        binding: &DirectOperationBinding,
        acknowledgement: &trillionnium_os_types::direct_operation::DirectOperationToolCallPreparedAckV3,
        commit: &trillionnium_os_types::direct_operation::DirectOperationToolCallCommitReceiptV3,
        disposition: DirectOperationAdapterTerminalDispositionV1,
    ) -> Result<Self> {
        disposition
            .validate_for_binding(binding, DirectOperationAdapter::SystemApi)
            .map_err(|error| anyhow!(error.to_string()))?;
        commit
            .validate_for_acknowledgement(acknowledgement)
            .map_err(|error| anyhow!(error.to_string()))?;
        if disposition.binding_sha256 != commit.binding_sha256
            || disposition.invocation_id != commit.invocation_id
            || disposition.adapter != commit.adapter
            || disposition.adapter != DirectOperationAdapter::SystemApi
        {
            bail!("direct_operation_custody_p0_adapter_disposition_identity_denied");
        }
        let snapshot = disposition
            .ackable_snapshot()
            .map_err(|_| anyhow!("direct_operation_custody_p0_adapter_disposition_not_ackable"))?;
        let [evidence] = snapshot.evidence.as_slice() else {
            bail!("direct_operation_custody_p0_adapter_disposition_cardinality_denied");
        };
        if snapshot.allocation_binding_sha256 != commit.binding_sha256
            || snapshot.journal_epoch != acknowledgement.journal_epoch
            || snapshot.journal_payload_sha256 != acknowledgement.journal_payload_sha256
            || snapshot.first_journal_sequence != acknowledgement.journal_sequence
            || snapshot.last_journal_sequence != acknowledgement.journal_sequence
            || evidence.adapter_effect_ordinal != commit.adapter_effect_ordinal
            || evidence.canonical_request_sha256 != acknowledgement.canonical_request_sha256
            || evidence.backend_request_id_sha256 != acknowledgement.backend_request_id_sha256
        {
            bail!("direct_operation_custody_p0_adapter_disposition_prepared_ack_denied");
        }
        let authentication_capability_sha256 =
            sha256_bytes(&serde_json::to_vec(&serde_json::json!({
                "domain": "trillionnium.p0-userdebug-authenticated-adapter-disposition.v1",
                "peer_identity_sha256": peer.identity_sha256(),
                "tool_call_commit_receipt_sha256": commit.commit_receipt_sha256,
                "terminal_disposition_sha256": disposition
                    .digest_sha256()
                    .map_err(|error| anyhow!(error.to_string()))?,
            }))?);
        Ok(Self(AuthenticatedAdapterDisposition {
            adapter: disposition.adapter,
            disposition: AdapterDispositionCustody::Authenticated {
                terminal_disposition: Box::new(disposition),
                authentication_capability_sha256,
            },
        }))
    }
}

enum VerifiedTerminalEgressProofSource {
    Snapshot(VerifiedDirectTerminalEgressSnapshot),
    #[cfg(test)]
    Fixture(DirectOperationTerminalEgressProofV1),
}

/// A terminal egress proof can enter production custody only through the
/// sealed egress-journal snapshot. Raw digest fixtures remain test-only.
pub(crate) struct VerifiedTerminalEgressProof(VerifiedTerminalEgressProofSource);

impl From<VerifiedDirectTerminalEgressSnapshot> for VerifiedTerminalEgressProof {
    fn from(snapshot: VerifiedDirectTerminalEgressSnapshot) -> Self {
        Self(VerifiedTerminalEgressProofSource::Snapshot(snapshot))
    }
}

impl VerifiedTerminalEgressProof {
    fn materialize_for_prepared(
        self,
        prepared: &DirectOperationBindingPreparedV3,
    ) -> Result<DirectOperationTerminalEgressProofV1> {
        let proof = match self.0 {
            VerifiedTerminalEgressProofSource::Snapshot(snapshot) => {
                snapshot.validate_custody_identity(
                    &prepared.binding,
                    &prepared.egress_grant_id_sha256,
                    &prepared.egress_journal_binding_sha256,
                )?;
                DirectOperationTerminalEgressProofV1 {
                    schema: TERMINAL_EGRESS_PROOF_SCHEMA.to_string(),
                    binding_sha256: prepared.binding_sha256.clone(),
                    invocation_id: prepared.binding.invocation_id.clone(),
                    delivery_provider_attempt_id: prepared
                        .binding
                        .attempt
                        .delivery_provider_attempt_id
                        .clone(),
                    egress_grant_id_sha256: prepared.egress_grant_id_sha256.clone(),
                    egress_journal_binding_sha256: prepared.egress_journal_binding_sha256.clone(),
                    terminal_state: TerminalEgressState::Completed,
                    final_record_sha256: snapshot.final_record_sha256().to_string(),
                    predecessor_record_sha256: snapshot.predecessor_record_sha256().to_string(),
                    runtime_evidence_sha256: snapshot.runtime_evidence_sha256().to_string(),
                    provider_teardown_completion_ack_sha256: snapshot
                        .provider_teardown_completion_ack_sha256()
                        .to_string(),
                    terminal_egress_cas_sha256: snapshot.terminal_egress_cas_sha256().to_string(),
                }
            }
            #[cfg(test)]
            VerifiedTerminalEgressProofSource::Fixture(proof) => proof,
        };
        proof.validate_for_prepared(prepared)?;
        Ok(proof)
    }

    #[cfg(test)]
    fn for_test(proof: DirectOperationTerminalEgressProofV1) -> Self {
        Self(VerifiedTerminalEgressProofSource::Fixture(proof))
    }
}

enum VerifiedDirectUiProofSource {
    Snapshot(VerifiedDirectUiReplaySnapshot),
    #[cfg(test)]
    Fixture(DirectOperationDirectUiProofV1),
}

/// A Direct UI proof can enter production custody only through the sealed
/// ContextMemory snapshot. Raw digests remain constructible solely by unit
/// fixtures and are never a production capability.
pub(crate) struct VerifiedDirectUiProof(VerifiedDirectUiProofSource);

impl From<VerifiedDirectUiReplaySnapshot> for VerifiedDirectUiProof {
    fn from(snapshot: VerifiedDirectUiReplaySnapshot) -> Self {
        Self(VerifiedDirectUiProofSource::Snapshot(snapshot))
    }
}

impl VerifiedDirectUiProof {
    fn materialize_for_prepared(
        self,
        prepared: &DirectOperationBindingPreparedV3,
    ) -> Result<DirectOperationDirectUiProofV1> {
        let proof = match self.0 {
            VerifiedDirectUiProofSource::Snapshot(snapshot) => {
                snapshot.validate_for_direct_binding(&prepared.binding)?;
                DirectOperationDirectUiProofV1 {
                    schema: DIRECT_UI_PROOF_SCHEMA.to_string(),
                    binding_sha256: prepared.binding_sha256.clone(),
                    invocation_id: prepared.binding.invocation_id.clone(),
                    delivery_provider_attempt_id: prepared
                        .binding
                        .attempt
                        .delivery_provider_attempt_id
                        .clone(),
                    direct_execution_receipt_sha256: snapshot
                        .direct_execution_receipt_sha256()
                        .to_string(),
                    direct_result_semantic_sha256: snapshot
                        .exact_plan_ready_semantic_sha256()
                        .to_string(),
                    ui_replay_completion_proof_sha256: snapshot
                        .ui_replay_completion_proof_sha256()
                        .to_string(),
                    ui_replay_semantic_sha256: snapshot.ui_replay_semantic_sha256().to_string(),
                }
            }
            #[cfg(test)]
            VerifiedDirectUiProofSource::Fixture(proof) => proof,
        };
        proof.validate_for_prepared(prepared)?;
        Ok(proof)
    }

    #[cfg(test)]
    fn for_test(proof: DirectOperationDirectUiProofV1) -> Self {
        Self(VerifiedDirectUiProofSource::Fixture(proof))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationAdapterAckIntentV3 {
    schema: String,
    adapter: DirectOperationAdapter,
    inbox: DirectOperationOuterAckInboxV3,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectOperationReplaySyncLaunchProgressV3 {
    schema: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    ack_intent_sha256: String,
    operation_replay_sync_ack_intent_sha256: String,
    outer_ack_publication_custody_sha256: String,
    predecessor_generation: u64,
    predecessor_store_sha256: String,
    launch_id_sha256: String,
    launch_challenge_sha256: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReplaySyncLaunchIdMaterialV3<'a> {
    schema: &'static str,
    adapter: DirectOperationAdapter,
    binding_sha256: &'a str,
    ack_intent_sha256: &'a str,
    operation_replay_sync_ack_intent_sha256: &'a str,
    outer_ack_publication_custody_sha256: &'a str,
    predecessor_generation: u64,
    predecessor_store_sha256: &'a str,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ReplaySyncLaunchChallengeMaterialV3<'a> {
    schema: &'static str,
    launch_id_sha256: &'a str,
    binding_sha256: &'a str,
    operation_replay_sync_ack_intent_sha256: &'a str,
    outer_ack_publication_custody_sha256: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationReplaySyncLaunchReceiptV3 {
    schema: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    launch_id_sha256: String,
    launch_challenge_sha256: String,
    operation_replay_sync_ack_intent_sha256: String,
    authority_evidence: DirectOperationExecutionAuthorityEvidenceV1,
    fsverity_digest_sha256: Option<String>,
    executable_sha256: String,
    executable_file_identity_sha256: String,
    executable_static_aarch64_elf64: bool,
    pid: u32,
    start_time_ticks: u64,
    pidfd_identity_sha256: String,
    cgroup_identity_sha256: String,
    uid: u32,
    gid: u32,
    selinux_domain: String,
    command_frame_sha256: String,
    response_frame_sha256: String,
    confirmation_sha256: String,
    tracer_parent_verified: bool,
    pdeathsig_sigkill_verified: bool,
    exact_process_surface_verified: bool,
}

impl DirectOperationReplaySyncLaunchReceiptV3 {
    fn validate_for_prepared(&self, prepared: &PreparedOperationReplaySyncLaunch) -> Result<()> {
        if self.schema != REPLAY_SYNC_LAUNCH_RECEIPT_SCHEMA
            || self.adapter != prepared.adapter
            || self.binding_sha256 != prepared.binding_sha256
            || self.launch_id_sha256 != prepared.launch_id_sha256
            || self.launch_challenge_sha256 != prepared.launch_challenge_sha256
            || self.operation_replay_sync_ack_intent_sha256
                != prepared.operation_replay_sync_ack_intent_sha256
            || self.authority_evidence.validate().is_err()
            || !self
                .authority_evidence
                .valid_component_integrity(&self.fsverity_digest_sha256)
            || !valid_nonzero_sha256(&self.executable_sha256)
            || !valid_nonzero_sha256(&self.executable_file_identity_sha256)
            || !self.executable_static_aarch64_elf64
            || self.pid == 0
            || self.start_time_ticks == 0
            || !valid_nonzero_sha256(&self.pidfd_identity_sha256)
            || !valid_nonzero_sha256(&self.cgroup_identity_sha256)
            || self.uid == 0
            || self.gid == 0
            || self.selinux_domain.is_empty()
            || !valid_nonzero_sha256(&self.command_frame_sha256)
            || !valid_nonzero_sha256(&self.response_frame_sha256)
            || !valid_nonzero_sha256(&self.confirmation_sha256)
            || !self.tracer_parent_verified
            || !self.pdeathsig_sigkill_verified
            || !self.exact_process_surface_verified
        {
            bail!("direct_operation_custody_replay_sync_launch_receipt_denied");
        }
        Ok(())
    }

    fn digest_sha256(&self) -> Result<String> {
        domain_digest(REPLAY_SYNC_LAUNCH_RECEIPT_DIGEST_DOMAIN, self)
    }

    fn validate_for_launch_progress(
        &self,
        launch: &DirectOperationReplaySyncLaunchProgressV3,
    ) -> Result<()> {
        if self.schema != REPLAY_SYNC_LAUNCH_RECEIPT_SCHEMA
            || self.adapter != launch.adapter
            || self.binding_sha256 != launch.binding_sha256
            || self.launch_id_sha256 != launch.launch_id_sha256
            || self.launch_challenge_sha256 != launch.launch_challenge_sha256
            || self.operation_replay_sync_ack_intent_sha256
                != launch.operation_replay_sync_ack_intent_sha256
            || self.authority_evidence.validate().is_err()
            || !self
                .authority_evidence
                .valid_component_integrity(&self.fsverity_digest_sha256)
            || !valid_nonzero_sha256(&self.executable_sha256)
            || !valid_nonzero_sha256(&self.executable_file_identity_sha256)
            || !self.executable_static_aarch64_elf64
            || self.pid == 0
            || self.start_time_ticks == 0
            || !valid_nonzero_sha256(&self.pidfd_identity_sha256)
            || !valid_nonzero_sha256(&self.cgroup_identity_sha256)
            || self.uid == 0
            || self.gid == 0
            || self.selinux_domain.is_empty()
            || !valid_nonzero_sha256(&self.command_frame_sha256)
            || !valid_nonzero_sha256(&self.response_frame_sha256)
            || !valid_nonzero_sha256(&self.confirmation_sha256)
            || !self.tracer_parent_verified
            || !self.pdeathsig_sigkill_verified
            || !self.exact_process_surface_verified
        {
            bail!("direct_operation_custody_replay_sync_launch_receipt_denied");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "authority_class",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub(crate) enum DirectOperationExecutionAuthorityEvidenceV1 {
    SignedProduct {
        product_descriptor_sha256: String,
        signed_product_measurement_sha256: String,
        avb_partition_digest_sha256: String,
    },
    P0UserdebugConformance {
        build_variant: String,
        product_manifest_sha256: String,
        daemon_executable_sha256: String,
        replay_sync_executable_sha256: String,
    },
}

impl DirectOperationExecutionAuthorityEvidenceV1 {
    fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::SignedProduct {
                product_descriptor_sha256,
                signed_product_measurement_sha256,
                avb_partition_digest_sha256,
            } => {
                valid_nonzero_sha256(product_descriptor_sha256)
                    && valid_nonzero_sha256(signed_product_measurement_sha256)
                    && valid_nonzero_sha256(avb_partition_digest_sha256)
            }
            Self::P0UserdebugConformance {
                build_variant,
                product_manifest_sha256,
                daemon_executable_sha256,
                replay_sync_executable_sha256,
            } => {
                build_variant == "userdebug"
                    && valid_nonzero_sha256(product_manifest_sha256)
                    && valid_nonzero_sha256(daemon_executable_sha256)
                    && valid_nonzero_sha256(replay_sync_executable_sha256)
            }
        };
        if !valid {
            bail!("direct_operation_custody_execution_authority_evidence_denied");
        }
        Ok(())
    }

    fn valid_component_integrity(&self, fsverity_digest_sha256: &Option<String>) -> bool {
        match self {
            Self::SignedProduct { .. } => fsverity_digest_sha256
                .as_deref()
                .is_some_and(valid_nonzero_sha256),
            Self::P0UserdebugConformance { .. } => fsverity_digest_sha256.is_none(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationOuterAckPublisherProvenanceV3 {
    schema: String,
    authority_evidence: DirectOperationExecutionAuthorityEvidenceV1,
    fsverity_root_digest_sha256: Option<String>,
    parent_filesystem_identity_sha256: String,
    parent_selinux_context_sha256: String,
}

impl DirectOperationOuterAckPublisherProvenanceV3 {
    fn validate(&self) -> Result<()> {
        if self.schema != ACK_PUBLISHER_PROVENANCE_SCHEMA
            || self.authority_evidence.validate().is_err()
            || !self
                .authority_evidence
                .valid_component_integrity(&self.fsverity_root_digest_sha256)
            || !valid_nonzero_sha256(&self.parent_filesystem_identity_sha256)
            || !valid_nonzero_sha256(&self.parent_selinux_context_sha256)
        {
            bail!("direct_operation_custody_outer_ack_publisher_provenance_denied");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationOuterAckRetirementProofV3 {
    schema: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    ack_intent_sha256: String,
    launch_id_sha256: String,
    acknowledgement_sha256: String,
    authenticated_ack_chain_sha256: String,
    archived_leaf_name: String,
    archived_bytes_sha256: String,
    publisher_provenance: DirectOperationOuterAckPublisherProvenanceV3,
    retirement_custody_source_sha256: String,
    #[serde(default, skip_serializing_if = "is_false")]
    external_state_reconciled: bool,
}

/// Affine custody snapshot for publishing one exact daemon-authored outer ACK
/// into the fixed root-owned adapter inbox.  Its fields are deliberately
/// private: neither a caller-selected path nor caller-supplied UID/GID can be
/// substituted after the durable ACK intent has been frozen.
#[must_use = "a prepared outer-ACK publication must be published or dropped without authority"]
pub(crate) struct PreparedOuterAckPublication {
    custody_head: DirectOperationCustodyHead,
    provider_id: String,
    agent_id: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    ack_intent_sha256: String,
    inbox: DirectOperationOuterAckInboxV3,
    _store_writer_lease: DirectOperationStoreWriterLease,
}

/// Move-only proof that one exact delivery binding is durably published to
/// every exact Binding-authorized adapter leaf and already has a frozen outer receipt. The
/// allocation binding is retained as a full preimage because a recovery-only
/// delivery attempt may differ from the attempt that allocated the System API
/// journal evidence.
///
/// This source-only P0 type can be minted only by querying an already-open
/// custody store at its exact committed head.  It is not serializable or
/// cloneable and does not publish an ACK or authorize an Android effect.
#[cfg(feature = "p0-launch-package-device-conformance")]
#[must_use = "verified P0 binding publication must remain in daemon custody"]
pub(crate) struct VerifiedP0BindingPublication {
    binding_prepared: DirectOperationBindingPreparedV3,
    binding_publication: DirectOperationBindingPublicationProofV3,
    delivery_binding: DirectOperationBinding,
    allocation_binding: DirectOperationBinding,
    committed_head: DirectOperationCustodyHead,
    binding_publication_sha256: String,
    binding_inbox_bytes_sha256: String,
    outer_receipt: DirectOperationOuterReceiptV3,
    store_parent_identity: FileIdentity,
    store_destination_name: CString,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl VerifiedP0BindingPublication {
    pub(crate) fn delivery_binding(&self) -> &DirectOperationBinding {
        &self.delivery_binding
    }

    pub(crate) fn allocation_binding(&self) -> &DirectOperationBinding {
        &self.allocation_binding
    }

    pub(crate) fn committed_head(&self) -> &DirectOperationCustodyHead {
        &self.committed_head
    }

    pub(crate) fn binding_publication_sha256(&self) -> &str {
        &self.binding_publication_sha256
    }

    pub(crate) fn binding_inbox_bytes_sha256(&self) -> &str {
        &self.binding_inbox_bytes_sha256
    }

    pub(crate) fn outer_receipt(&self) -> &DirectOperationOuterReceiptV3 {
        &self.outer_receipt
    }

    fn validate(&self) -> Result<()> {
        validate_p0_delivery_allocation_bindings(&self.delivery_binding, &self.allocation_binding)?;
        self.binding_prepared.validate()?;
        self.binding_publication
            .validate_for_prepared(&self.binding_prepared)?;
        self.committed_head
            .validate()
            .map_err(|error| anyhow!(error))?;
        if self.binding_prepared.binding != self.delivery_binding
            || self.binding_prepared.binding_inbox_bytes_sha256 != self.binding_inbox_bytes_sha256
            || domain_digest(
                b"trillionnium.p0-binding-publication-proof.v3",
                &self.binding_publication,
            )? != self.binding_publication_sha256
            || self.committed_head.generation == 0
            || !valid_nonzero_sha256(&self.binding_publication_sha256)
            || !valid_nonzero_sha256(&self.binding_inbox_bytes_sha256)
        {
            bail!("direct_operation_custody_p0_publication_identity_denied");
        }
        self.outer_receipt
            .validate_for_binding(&self.delivery_binding)
            .map_err(|error| anyhow!(error.to_string()))?;
        let system = self
            .outer_receipt
            .adapter_terminal_dispositions
            .iter()
            .find(|item| item.adapter == DirectOperationAdapter::SystemApi)
            .context("direct_operation_custody_p0_system_disposition_missing")?;
        system
            .ackable_snapshot()
            .map_err(|error| anyhow!(error.to_string()))?
            .validate_for_allocation_binding(
                &self.allocation_binding,
                DirectOperationAdapter::SystemApi,
            )
            .map_err(|error| anyhow!(error.to_string()))?;
        if self.outer_receipt.adapter_terminal_dispositions.len() != 1
            || self.outer_receipt.adapter_terminal_dispositions[0].adapter
                != DirectOperationAdapter::SystemApi
        {
            bail!("direct_operation_custody_p0_disposition_set_denied");
        }
        Ok(())
    }

    fn validate_for_phase(
        &self,
        custody_head: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> Result<()> {
        self.validate()?;
        let expected_binding_sha256 = self
            .delivery_binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        if adapter != DirectOperationAdapter::SystemApi
            || custody_head != &self.committed_head
            || binding_sha256 != expected_binding_sha256
        {
            bail!("direct_operation_custody_p0_guarded_phase_identity_denied");
        }
        Ok(())
    }
}

/// Affine envelope that keeps the exact, verified P0 publication preimages in
/// daemon custody while an already-existing canonical effect capability crosses
/// its fixed publisher or measured replay helper.  This adds no parallel phase
/// model: `T` is always one of the canonical custody transition types below.
/// The envelope is deliberately neither cloneable nor serializable.
/// It authorizes only the userdebug daemon-custody transition; it cannot
/// construct product external publication, hardware rollback resistance or
/// mutation-CAS authority, and it cannot promote source/helper confirmation
/// into physical-device evidence.
#[cfg(feature = "p0-launch-package-device-conformance")]
#[must_use = "a P0 guarded custody capability must be consumed by its exact next transition"]
pub(crate) struct P0BindingPublicationGuarded<T> {
    publication: VerifiedP0BindingPublication,
    capability: T,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl<T> P0BindingPublicationGuarded<T> {
    fn new(publication: VerifiedP0BindingPublication, capability: T) -> Self {
        Self {
            publication,
            capability,
        }
    }

    fn into_parts(self) -> (VerifiedP0BindingPublication, T) {
        (self.publication, self.capability)
    }

    #[cfg(test)]
    fn capability(&self) -> &T {
        &self.capability
    }
}

/// Affine launch input for one measured operation replay-sync helper.  This
/// value can be derived only after the exact inbox publication proof is itself
/// durable in the daemon custody store.  The launcher consumes it, so ordinary
/// JSON, paths, flags, or model/provider fields cannot mint Android ACK proof.
#[must_use = "a prepared replay-sync launch must remain in measured launcher custody"]
pub(crate) struct PreparedOperationReplaySyncLaunch {
    custody_head: DirectOperationCustodyHead,
    provider_id: String,
    agent_id: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    ack_intent_sha256: String,
    operation_replay_sync_ack_intent_sha256: String,
    launch_id_sha256: String,
    launch_challenge_sha256: String,
    inbox: DirectOperationOuterAckInboxV3,
    outer_ack_inbox_publication: DirectOperationOuterAckInboxPublicationProofV3,
    #[cfg(feature = "p0-launch-package-device-conformance")]
    p0_sealed_authority: Option<DirectOperationP0ReplaySyncSealedAuthorityV1>,
    /// One kernel-held exclusive lock on the stable custody-parent directory.
    /// The descriptor is deliberately carried by value through the measured
    /// launcher, so no second daemon writer can replace the persisted launch
    /// transition or issue a competing helper while this capability is live.
    /// Process death releases it and permits exact persisted-state reconcile.
    _single_flight_lease: DirectOperationStoreWriterLease,
}

#[must_use = "a prepared outer-ACK retirement must remain in fixed publisher custody"]
pub(crate) struct PreparedOuterAckRetirement {
    custody_head: DirectOperationCustodyHead,
    provider_id: String,
    agent_id: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    ack_intent_sha256: String,
    launch_id_sha256: String,
    inbox: DirectOperationOuterAckInboxV3,
    outer_ack_inbox_publication: DirectOperationOuterAckInboxPublicationProofV3,
    android_backend_ack_confirmation: DirectOperationAndroidBackendAckConfirmationProofV3,
    // `Some` for the affine capability crossing the publisher effect.  The
    // internal post-effect reconstruction uses `None` while already holding
    // the caller's exact writer lease.
    _store_writer_lease: Option<DirectOperationStoreWriterLease>,
}

/// Sealed result of a fixed-path publication. It carries the exact custody
/// head captured before filesystem I/O, so callers cannot record the proof
/// against a newer unrelated daemon state.
#[must_use = "a published outer ACK must be reconciled into its exact custody predecessor"]
pub(crate) struct PublishedOuterAckInbox {
    custody_head: DirectOperationCustodyHead,
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    verified: VerifiedOuterAckInboxPublicationProof,
}

/// Sealed exact helper completion tied to the custody head from which the
/// measured launch was derived.
#[must_use = "a replay-sync completion must be reconciled into its exact custody predecessor"]
pub(crate) struct CompletedOperationReplaySyncLaunch {
    custody_head: DirectOperationCustodyHead,
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    verified: VerifiedAndroidBackendAckConfirmationProof,
    /// Keeps the stable cross-process store-writer/single-flight lock live
    /// through the durable Android-confirmation transition, not merely through
    /// helper exit.
    _single_flight_lease: DirectOperationStoreWriterLease,
}

#[must_use = "a retired outer ACK must be committed to its exact custody predecessor"]
pub(crate) struct RetiredOuterAckInbox {
    custody_head: DirectOperationCustodyHead,
    binding_sha256: String,
    adapter: DirectOperationAdapter,
    verified: VerifiedOuterAckRetirementProof,
}

impl DirectOperationAdapterAckIntentV3 {
    fn validate(&self) -> Result<()> {
        self.inbox
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        if self.schema != ACK_INTENT_SCHEMA || self.adapter != self.inbox.acknowledgement.adapter {
            bail!("direct_operation_custody_ack_intent_denied");
        }
        Ok(())
    }

    fn validate_for_receipt(&self, receipt: &DirectOperationOuterReceiptV3) -> Result<()> {
        self.validate()?;
        self.inbox
            .acknowledgement
            .validate_for_outer_receipt(receipt)
            .map_err(|error| anyhow!(error.to_string()))
    }

    fn digest_sha256(&self) -> Result<String> {
        self.validate()?;
        domain_digest(ACK_INTENT_DIGEST_DOMAIN, self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationOuterAckInboxPublicationProofV3 {
    schema: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    ack_intent_sha256: String,
    journal_epoch: String,
    last_journal_sequence: u64,
    acknowledgement_sha256: String,
    ack_chain_step_sha256: String,
    authenticated_ack_chain_sha256: String,
    canonical_inbox_bytes_sha256: String,
    publisher_provenance: DirectOperationOuterAckPublisherProvenanceV3,
    publication_custody_source_sha256: String,
    #[serde(default, skip_serializing_if = "is_false")]
    external_state_reconciled: bool,
}

impl DirectOperationOuterAckInboxPublicationProofV3 {
    fn validate_for_intent(
        &self,
        prepared: &DirectOperationBindingPreparedV3,
        receipt: &DirectOperationOuterReceiptV3,
        intent: &DirectOperationAdapterAckIntentV3,
    ) -> Result<()> {
        intent.validate_for_receipt(receipt)?;
        let acknowledgement = &intent.inbox.acknowledgement;
        let chain_step = &intent.inbox.chain_step;
        let mut canonical_inbox_bytes = serde_json::to_vec(&intent.inbox)?;
        canonical_inbox_bytes.push(b'\n');
        self.publisher_provenance.validate()?;
        if self.schema != ACK_INBOX_PUBLICATION_PROOF_SCHEMA
            || self.adapter != intent.adapter
            || self.binding_sha256 != prepared.binding_sha256
            || self.binding_sha256 != acknowledgement.binding_sha256
            || self.ack_intent_sha256 != intent.digest_sha256()?
            || self.journal_epoch != acknowledgement.journal_evidence_snapshot.journal_epoch
            || self.last_journal_sequence
                != acknowledgement
                    .journal_evidence_snapshot
                    .last_journal_sequence
            || self.acknowledgement_sha256 != intent.inbox.acknowledgement_sha256
            || self.ack_chain_step_sha256 != intent.inbox.chain_step_sha256
            || self.authenticated_ack_chain_sha256 != chain_step.authenticated_ack_chain_sha256
            || self.canonical_inbox_bytes_sha256 != sha256_bytes(&canonical_inbox_bytes)
            || !valid_nonzero_sha256(&self.publication_custody_source_sha256)
        {
            bail!("direct_operation_custody_ack_inbox_publication_proof_denied");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectOperationAndroidBackendAckConfirmationProofV3 {
    schema: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    ack_intent_sha256: String,
    journal_epoch: String,
    last_journal_sequence: u64,
    acknowledgement_sha256: String,
    ack_chain_step_sha256: String,
    authenticated_ack_chain_sha256: String,
    launch_id_sha256: String,
    launch_receipt: DirectOperationReplaySyncLaunchReceiptV3,
    launch_receipt_sha256: String,
    android_confirmation_source_sha256: String,
}

impl DirectOperationAndroidBackendAckConfirmationProofV3 {
    fn validate_for_intent(
        &self,
        prepared: &DirectOperationBindingPreparedV3,
        receipt: &DirectOperationOuterReceiptV3,
        intent: &DirectOperationAdapterAckIntentV3,
    ) -> Result<()> {
        intent.validate_for_receipt(receipt)?;
        let acknowledgement = &intent.inbox.acknowledgement;
        let chain_step = &intent.inbox.chain_step;
        if self.schema != ANDROID_BACKEND_ACK_CONFIRMATION_PROOF_SCHEMA
            || self.adapter != intent.adapter
            || self.binding_sha256 != prepared.binding_sha256
            || self.binding_sha256 != acknowledgement.binding_sha256
            || self.ack_intent_sha256 != intent.digest_sha256()?
            || self.journal_epoch != acknowledgement.journal_evidence_snapshot.journal_epoch
            || self.last_journal_sequence
                != acknowledgement
                    .journal_evidence_snapshot
                    .last_journal_sequence
            || self.acknowledgement_sha256 != intent.inbox.acknowledgement_sha256
            || self.ack_chain_step_sha256 != intent.inbox.chain_step_sha256
            || self.authenticated_ack_chain_sha256 != chain_step.authenticated_ack_chain_sha256
            || !valid_nonzero_sha256(&self.launch_id_sha256)
            || self.launch_receipt.digest_sha256()? != self.launch_receipt_sha256
            || self.android_confirmation_source_sha256 != self.launch_receipt_sha256
            || !valid_nonzero_sha256(&self.android_confirmation_source_sha256)
        {
            bail!("direct_operation_custody_android_ack_confirmation_proof_denied");
        }
        Ok(())
    }
}

/// Sealed source-only capability for proof that one immutable outer-ACK inbox
/// was durably published. There is deliberately no production constructor.
pub(crate) struct VerifiedOuterAckInboxPublicationProof {
    proof: DirectOperationOuterAckInboxPublicationProofV3,
    retained_publication: Option<outer_ack_publisher::RetainedOuterAckPublication>,
}

impl VerifiedOuterAckInboxPublicationProof {
    /// The fixed-path publisher is the sole non-test proof producer.  It
    /// supplies only its kernel/durability custody digest; every semantic field
    /// is copied from the sealed durable intent rather than from publisher
    /// arguments.
    fn from_fixed_publisher(
        prepared: &PreparedOuterAckPublication,
        token: outer_ack_publisher::PublisherProofToken,
    ) -> Result<Self> {
        let (publication_custody_source_sha256, publisher_provenance, retained_publication) =
            token.into_parts();
        let acknowledgement = &prepared.inbox.acknowledgement;
        let proof = DirectOperationOuterAckInboxPublicationProofV3 {
            schema: ACK_INBOX_PUBLICATION_PROOF_SCHEMA.to_string(),
            adapter: prepared.adapter,
            binding_sha256: prepared.binding_sha256.clone(),
            ack_intent_sha256: prepared.ack_intent_sha256.clone(),
            journal_epoch: acknowledgement
                .journal_evidence_snapshot
                .journal_epoch
                .clone(),
            last_journal_sequence: acknowledgement
                .journal_evidence_snapshot
                .last_journal_sequence,
            acknowledgement_sha256: prepared.inbox.acknowledgement_sha256.clone(),
            ack_chain_step_sha256: prepared.inbox.chain_step_sha256.clone(),
            authenticated_ack_chain_sha256: prepared
                .inbox
                .chain_step
                .authenticated_ack_chain_sha256
                .clone(),
            canonical_inbox_bytes_sha256: {
                let mut bytes = serde_json::to_vec(&prepared.inbox)?;
                bytes.push(b'\n');
                sha256_bytes(&bytes)
            },
            publisher_provenance,
            publication_custody_source_sha256,
            external_state_reconciled: false,
        };
        if !valid_nonzero_sha256(&proof.publication_custody_source_sha256) {
            bail!("direct_operation_custody_publisher_source_denied");
        }
        Ok(Self {
            proof,
            retained_publication: Some(retained_publication),
        })
    }

    fn materialize_for_intent(
        &mut self,
        prepared: &DirectOperationBindingPreparedV3,
        receipt: &DirectOperationOuterReceiptV3,
        intent: &DirectOperationAdapterAckIntentV3,
    ) -> Result<DirectOperationOuterAckInboxPublicationProofV3> {
        self.revalidate_retained()?;
        self.proof.validate_for_intent(prepared, receipt, intent)?;
        Ok(self.proof.clone())
    }

    fn revalidate_retained(&mut self) -> Result<()> {
        if let Some(retained) = &mut self.retained_publication {
            retained.revalidate()?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn for_test(proof: DirectOperationOuterAckInboxPublicationProofV3) -> Self {
        Self {
            proof,
            retained_publication: None,
        }
    }
}

/// Sealed source-only capability for the distinct Android backend ACK
/// confirmation. It cannot be built from ordinary paths, flags, JSON, or an
/// outer-ACK publication proof; production intentionally has no constructor.
pub(crate) struct VerifiedAndroidBackendAckConfirmationProof(
    DirectOperationAndroidBackendAckConfirmationProofV3,
);

impl VerifiedAndroidBackendAckConfirmationProof {
    /// The measured operation replay-sync launcher is the sole non-test proof
    /// producer.  Exact helper confirmation is re-bound to the sealed durable
    /// intent here; no raw confirmation JSON can enter custody directly.
    fn from_measured_replay_sync_launcher(
        prepared: &PreparedOperationReplaySyncLaunch,
        token: operation_replay_sync_launcher::ConfirmationProofToken,
    ) -> Result<Self> {
        let launch_receipt = token.into_launch_receipt();
        launch_receipt.validate_for_prepared(prepared)?;
        let launch_receipt_sha256 = launch_receipt.digest_sha256()?;
        let acknowledgement = &prepared.inbox.acknowledgement;
        let proof = DirectOperationAndroidBackendAckConfirmationProofV3 {
            schema: ANDROID_BACKEND_ACK_CONFIRMATION_PROOF_SCHEMA.to_string(),
            adapter: prepared.adapter,
            binding_sha256: prepared.binding_sha256.clone(),
            ack_intent_sha256: prepared.ack_intent_sha256.clone(),
            journal_epoch: acknowledgement
                .journal_evidence_snapshot
                .journal_epoch
                .clone(),
            last_journal_sequence: acknowledgement
                .journal_evidence_snapshot
                .last_journal_sequence,
            acknowledgement_sha256: prepared.inbox.acknowledgement_sha256.clone(),
            ack_chain_step_sha256: prepared.inbox.chain_step_sha256.clone(),
            authenticated_ack_chain_sha256: prepared
                .inbox
                .chain_step
                .authenticated_ack_chain_sha256
                .clone(),
            launch_id_sha256: prepared.launch_id_sha256.clone(),
            launch_receipt,
            launch_receipt_sha256: launch_receipt_sha256.clone(),
            android_confirmation_source_sha256: launch_receipt_sha256,
        };
        if !valid_nonzero_sha256(&proof.android_confirmation_source_sha256) {
            bail!("direct_operation_custody_android_confirmation_source_denied");
        }
        Ok(Self(proof))
    }

    fn materialize_for_intent(
        self,
        prepared: &DirectOperationBindingPreparedV3,
        receipt: &DirectOperationOuterReceiptV3,
        intent: &DirectOperationAdapterAckIntentV3,
    ) -> Result<DirectOperationAndroidBackendAckConfirmationProofV3> {
        self.0.validate_for_intent(prepared, receipt, intent)?;
        Ok(self.0)
    }

    #[cfg(test)]
    fn for_test(proof: DirectOperationAndroidBackendAckConfirmationProofV3) -> Self {
        Self(proof)
    }
}

pub(crate) struct VerifiedOuterAckRetirementProof {
    proof: DirectOperationOuterAckRetirementProofV3,
    retained_retirement: Option<outer_ack_publisher::RetainedOuterAckRetirement>,
}

impl VerifiedOuterAckRetirementProof {
    fn from_fixed_publisher(
        prepared: &PreparedOuterAckRetirement,
        token: outer_ack_publisher::RetirementProofToken,
    ) -> Result<Self> {
        let (
            archived_leaf_name,
            archived_bytes_sha256,
            publisher_provenance,
            retirement_custody_source_sha256,
            retained,
        ) = token.into_parts();
        let proof = DirectOperationOuterAckRetirementProofV3 {
            schema: OUTER_ACK_RETIREMENT_PROOF_SCHEMA.to_string(),
            adapter: prepared.adapter,
            binding_sha256: prepared.binding_sha256.clone(),
            ack_intent_sha256: prepared.ack_intent_sha256.clone(),
            launch_id_sha256: prepared.launch_id_sha256.clone(),
            acknowledgement_sha256: prepared.inbox.acknowledgement_sha256.clone(),
            authenticated_ack_chain_sha256: prepared
                .inbox
                .chain_step
                .authenticated_ack_chain_sha256
                .clone(),
            archived_leaf_name,
            archived_bytes_sha256,
            publisher_provenance,
            retirement_custody_source_sha256,
            external_state_reconciled: false,
        };
        validate_retirement_proof(&proof, prepared)?;
        Ok(Self {
            proof,
            retained_retirement: Some(retained),
        })
    }

    fn materialize(
        &mut self,
        prepared: &PreparedOuterAckRetirement,
    ) -> Result<DirectOperationOuterAckRetirementProofV3> {
        self.revalidate_retained()?;
        validate_retirement_proof(&self.proof, prepared)?;
        Ok(self.proof.clone())
    }

    fn revalidate_retained(&mut self) -> Result<()> {
        if let Some(retained) = &mut self.retained_retirement {
            retained.revalidate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectOperationAdapterAckProgressV3 {
    schema: String,
    adapter: DirectOperationAdapter,
    binding_sha256: String,
    ack_intent_sha256: String,
    outer_ack_inbox_publication: Option<DirectOperationOuterAckInboxPublicationProofV3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    replay_sync_launch: Option<DirectOperationReplaySyncLaunchProgressV3>,
    android_backend_ack_confirmation: Option<DirectOperationAndroidBackendAckConfirmationProofV3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outer_ack_retirement: Option<DirectOperationOuterAckRetirementProofV3>,
    completed: bool,
}

impl DirectOperationAdapterAckProgressV3 {
    fn new(
        prepared: &DirectOperationBindingPreparedV3,
        intent: &DirectOperationAdapterAckIntentV3,
    ) -> Result<Self> {
        let progress = Self {
            schema: ADAPTER_ACK_PROGRESS_SCHEMA.to_string(),
            adapter: intent.adapter,
            binding_sha256: prepared.binding_sha256.clone(),
            ack_intent_sha256: intent.digest_sha256()?,
            outer_ack_inbox_publication: None,
            replay_sync_launch: None,
            android_backend_ack_confirmation: None,
            outer_ack_retirement: None,
            completed: false,
        };
        Ok(progress)
    }

    fn refresh_completed(&mut self) {
        self.completed = self
            .outer_ack_inbox_publication
            .as_ref()
            .is_some_and(|proof| proof.external_state_reconciled)
            && self.replay_sync_launch.is_some()
            && self.android_backend_ack_confirmation.is_some()
            && self
                .outer_ack_retirement
                .as_ref()
                .is_some_and(|proof| proof.external_state_reconciled);
    }

    fn validate_for_intent(
        &self,
        prepared: &DirectOperationBindingPreparedV3,
        receipt: &DirectOperationOuterReceiptV3,
        intent: &DirectOperationAdapterAckIntentV3,
    ) -> Result<()> {
        intent.validate_for_receipt(receipt)?;
        let expected_completed = self
            .outer_ack_inbox_publication
            .as_ref()
            .is_some_and(|proof| proof.external_state_reconciled)
            && self.replay_sync_launch.is_some()
            && self.android_backend_ack_confirmation.is_some()
            && self
                .outer_ack_retirement
                .as_ref()
                .is_some_and(|proof| proof.external_state_reconciled);
        if self.schema != ADAPTER_ACK_PROGRESS_SCHEMA
            || self.adapter != intent.adapter
            || self.binding_sha256 != prepared.binding_sha256
            || self.ack_intent_sha256 != intent.digest_sha256()?
            || (self.outer_ack_inbox_publication.is_none()
                && self.replay_sync_launch.is_none()
                && self.android_backend_ack_confirmation.is_none()
                && self.outer_ack_retirement.is_none())
            || self.completed != expected_completed
        {
            bail!("direct_operation_custody_adapter_ack_progress_denied");
        }
        if self.android_backend_ack_confirmation.is_some()
            && (self
                .outer_ack_inbox_publication
                .as_ref()
                .is_none_or(|proof| !proof.external_state_reconciled)
                || self.replay_sync_launch.is_none())
        {
            bail!("direct_operation_custody_android_ack_before_publication_denied");
        }
        if self.outer_ack_retirement.is_some() && self.android_backend_ack_confirmation.is_none() {
            bail!("direct_operation_custody_retirement_before_android_confirmation_denied");
        }
        if let Some(proof) = &self.outer_ack_inbox_publication {
            proof.validate_for_intent(prepared, receipt, intent)?;
        }
        if let Some(launch) = &self.replay_sync_launch {
            validate_launch_progress(
                launch,
                prepared,
                receipt,
                intent,
                self.outer_ack_inbox_publication
                    .as_ref()
                    .context("direct_operation_custody_launch_without_publication")?,
            )?;
        }
        if let Some(proof) = &self.android_backend_ack_confirmation {
            proof.validate_for_intent(prepared, receipt, intent)?;
            let launch = self
                .replay_sync_launch
                .as_ref()
                .context("direct_operation_custody_confirmation_without_launch")?;
            let publication = self
                .outer_ack_inbox_publication
                .as_ref()
                .context("direct_operation_custody_confirmation_without_publication")?;
            proof.launch_receipt.validate_for_launch_progress(launch)?;
            if proof.launch_id_sha256 != launch.launch_id_sha256 {
                bail!("direct_operation_custody_confirmation_launch_drift");
            }
            if proof.launch_receipt.authority_evidence
                != publication.publisher_provenance.authority_evidence
            {
                bail!("direct_operation_custody_replay_sync_cross_product_proof_denied");
            }
        }
        if let Some(proof) = &self.outer_ack_retirement {
            let launch = self
                .replay_sync_launch
                .as_ref()
                .context("direct_operation_custody_retirement_without_launch")?;
            if proof.schema != OUTER_ACK_RETIREMENT_PROOF_SCHEMA
                || proof.adapter != self.adapter
                || proof.binding_sha256 != self.binding_sha256
                || proof.ack_intent_sha256 != self.ack_intent_sha256
                || proof.launch_id_sha256 != launch.launch_id_sha256
                || proof.acknowledgement_sha256 != intent.inbox.acknowledgement_sha256
                || proof.authenticated_ack_chain_sha256
                    != intent.inbox.chain_step.authenticated_ack_chain_sha256
                || !valid_archived_leaf_name(&proof.archived_leaf_name, &self.ack_intent_sha256)
                || proof.archived_bytes_sha256
                    != self
                        .outer_ack_inbox_publication
                        .as_ref()
                        .context("direct_operation_custody_retirement_without_publication")?
                        .canonical_inbox_bytes_sha256
                || proof.publisher_provenance
                    != self
                        .outer_ack_inbox_publication
                        .as_ref()
                        .context("direct_operation_custody_retirement_without_publication")?
                        .publisher_provenance
                || !valid_nonzero_sha256(&proof.retirement_custody_source_sha256)
            {
                bail!("direct_operation_custody_retirement_proof_denied");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectOperationCustodyRecordV3 {
    schema: String,
    revision: u64,
    predecessor_record_sha256: String,
    stage: BindingCustodyStage,
    prepared: DirectOperationBindingPreparedV3,
    publication: Option<DirectOperationBindingPublicationProofV3>,
    terminal_egress: Option<DirectOperationTerminalEgressProofV1>,
    direct_ui: Option<DirectOperationDirectUiProofV1>,
    adapter_dispositions: Vec<AuthenticatedAdapterDisposition>,
    outer_receipt: Option<DirectOperationOuterReceiptV3>,
    ack_intents: Vec<DirectOperationAdapterAckIntentV3>,
    /// Source-only progress is omitted when empty so the V3 record has one
    /// canonical representation before any ACK transition.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    adapter_ack_progress: Vec<DirectOperationAdapterAckProgressV3>,
}

impl DirectOperationCustodyRecordV3 {
    fn new(prepared: DirectOperationBindingPreparedV3) -> Result<Self> {
        prepared.validate()?;
        let adapter_dispositions = prepared
            .binding
            .authorized_adapter_set
            .authorized_adapters
            .iter()
            .copied()
            .map(AuthenticatedAdapterDisposition::awaiting)
            .collect();
        let record = Self {
            schema: RECORD_SCHEMA.to_string(),
            revision: 1,
            predecessor_record_sha256: ZERO_SHA256.to_string(),
            stage: BindingCustodyStage::BindingPrepared,
            prepared,
            publication: None,
            terminal_egress: None,
            direct_ui: None,
            adapter_dispositions,
            outer_receipt: None,
            ack_intents: Vec::new(),
            adapter_ack_progress: Vec::new(),
        };
        record.validate()?;
        Ok(record)
    }

    fn digest_sha256(&self) -> Result<String> {
        domain_digest(RECORD_DIGEST_DOMAIN, self)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != RECORD_SCHEMA
            || self.revision == 0
            || (self.revision == 1 && self.predecessor_record_sha256 != ZERO_SHA256)
            || (self.revision > 1 && !valid_nonzero_sha256(&self.predecessor_record_sha256))
        {
            bail!("direct_operation_custody_record_header_denied");
        }
        self.prepared.validate()?;
        if self.adapter_dispositions.len()
            != self
                .prepared
                .binding
                .authorized_adapter_set
                .authorized_adapters
                .len()
            || self
                .adapter_dispositions
                .iter()
                .zip(
                    &self
                        .prepared
                        .binding
                        .authorized_adapter_set
                        .authorized_adapters,
                )
                .any(|(disposition, authorized)| disposition.adapter != *authorized)
        {
            bail!("direct_operation_custody_adapter_disposition_set_denied");
        }
        for disposition in &self.adapter_dispositions {
            disposition.validate_for_prepared(&self.prepared)?;
        }
        match self.stage {
            BindingCustodyStage::BindingPrepared => {
                if self.publication.is_some()
                    || self.terminal_egress.is_some()
                    || self.direct_ui.is_some()
                    || self
                        .adapter_dispositions
                        .iter()
                        .any(|item| item.disposition.authenticated())
                    || self.outer_receipt.is_some()
                    || !self.ack_intents.is_empty()
                    || !self.adapter_ack_progress.is_empty()
                {
                    bail!("direct_operation_custody_prepared_stage_overclaim_denied");
                }
            }
            BindingCustodyStage::BindingPublished => {
                self.publication
                    .as_ref()
                    .context("direct_operation_custody_publication_proof_missing")?
                    .validate_for_prepared(&self.prepared)?;
            }
            BindingCustodyStage::CancelledBeforeTool => {
                self.publication
                    .as_ref()
                    .context("direct_operation_custody_cancelled_publication_missing")?
                    .validate_for_prepared(&self.prepared)?;
                if self.terminal_egress.is_some()
                    || self.direct_ui.is_some()
                    || self
                        .adapter_dispositions
                        .iter()
                        .any(|item| item.disposition.authenticated())
                    || self.outer_receipt.is_some()
                    || !self.ack_intents.is_empty()
                    || !self.adapter_ack_progress.is_empty()
                {
                    bail!("direct_operation_custody_cancelled_before_tool_overclaim_denied");
                }
            }
        }
        if let Some(proof) = &self.terminal_egress {
            proof.validate_for_prepared(&self.prepared)?;
        }
        if let Some(proof) = &self.direct_ui {
            proof.validate_for_prepared(&self.prepared)?;
        }

        if let Some(receipt) = &self.outer_receipt {
            if !self
                .adapter_dispositions
                .iter()
                .all(|item| item.disposition.authenticated())
            {
                bail!("direct_operation_custody_receipt_before_dispositions_denied");
            }
            let expected = self.expected_outer_receipt()?;
            if receipt != &expected {
                bail!("direct_operation_custody_frozen_receipt_drift_denied");
            }
        } else if !self.ack_intents.is_empty() || !self.adapter_ack_progress.is_empty() {
            bail!("direct_operation_custody_ack_intent_without_receipt_denied");
        }

        let mut previous_adapter = None;
        for intent in &self.ack_intents {
            if previous_adapter.is_some_and(|previous| previous >= intent.adapter) {
                bail!("direct_operation_custody_ack_intent_order_denied");
            }
            let receipt = self
                .outer_receipt
                .as_ref()
                .context("direct_operation_custody_ack_receipt_missing")?;
            intent.validate_for_receipt(receipt)?;
            let expected = self.expected_ack_intent(intent.adapter)?;
            if intent != &expected {
                bail!("direct_operation_custody_ack_intent_drift_denied");
            }
            previous_adapter = Some(intent.adapter);
        }
        previous_adapter = None;
        for progress in &self.adapter_ack_progress {
            if previous_adapter.is_some_and(|previous| previous >= progress.adapter) {
                bail!("direct_operation_custody_adapter_ack_progress_order_denied");
            }
            let receipt = self
                .outer_receipt
                .as_ref()
                .context("direct_operation_custody_ack_progress_receipt_missing")?;
            let intent = self
                .ack_intents
                .iter()
                .find(|intent| intent.adapter == progress.adapter)
                .context("direct_operation_custody_ack_progress_intent_missing")?;
            progress.validate_for_intent(&self.prepared, receipt, intent)?;
            previous_adapter = Some(progress.adapter);
        }
        Ok(())
    }

    fn expected_outer_receipt(&self) -> Result<DirectOperationOuterReceiptV3> {
        if !self
            .adapter_dispositions
            .iter()
            .all(|item| item.disposition.authenticated())
        {
            bail!("direct_operation_custody_all_adapter_dispositions_required");
        }
        let terminal = self
            .terminal_egress
            .as_ref()
            .context("direct_operation_custody_terminal_egress_missing")?;
        let direct_ui = self
            .direct_ui
            .as_ref()
            .context("direct_operation_custody_direct_ui_missing")?;
        let dispositions = self
            .adapter_dispositions
            .iter()
            .map(|item| match &item.disposition {
                AdapterDispositionCustody::Authenticated {
                    terminal_disposition,
                    ..
                } => Ok((**terminal_disposition).clone()),
                AdapterDispositionCustody::AwaitingAuthenticatedDisposition => {
                    bail!("direct_operation_custody_all_adapter_dispositions_required")
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let mut receipt = DirectOperationOuterReceiptV3 {
            schema: OUTER_RECEIPT_V3_SCHEMA.to_string(),
            binding_sha256: self.prepared.binding_sha256.clone(),
            invocation_id: self.prepared.binding.invocation_id.clone(),
            delivery_provider_attempt_id: self
                .prepared
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            provider_id: self.prepared.binding.stable_seed.provider_id.clone(),
            agent_id: self.prepared.binding.stable_seed.agent_id.clone(),
            direct_execution_receipt_sha256: direct_ui.direct_execution_receipt_sha256.clone(),
            ui_replay_completion_proof_sha256: direct_ui.ui_replay_completion_proof_sha256.clone(),
            ui_replay_semantic_sha256: direct_ui.ui_replay_semantic_sha256.clone(),
            terminal_egress_cas_sha256: terminal.terminal_egress_cas_sha256.clone(),
            runtime_evidence_sha256: terminal.runtime_evidence_sha256.clone(),
            provider_teardown_completion_ack_sha256: terminal
                .provider_teardown_completion_ack_sha256
                .clone(),
            authorized_adapter_set: self.prepared.binding.authorized_adapter_set.clone(),
            adapter_terminal_dispositions: dispositions,
            adapter_terminal_dispositions_sha256: String::new(),
        };
        receipt.adapter_terminal_dispositions_sha256 = receipt
            .adapter_dispositions_digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        receipt
            .validate_for_binding(&self.prepared.binding)
            .map_err(|error| anyhow!(error.to_string()))?;
        Ok(receipt)
    }

    fn expected_ack_intent(
        &self,
        adapter: DirectOperationAdapter,
    ) -> Result<DirectOperationAdapterAckIntentV3> {
        let receipt = self
            .outer_receipt
            .as_ref()
            .context("direct_operation_custody_outer_receipt_missing")?;
        let disposition = self
            .adapter_dispositions
            .iter()
            .find(|item| item.adapter == adapter)
            .context("direct_operation_custody_adapter_disposition_slot_missing")?;
        let snapshot = match &disposition.disposition {
            AdapterDispositionCustody::Authenticated {
                terminal_disposition,
                ..
            } => terminal_disposition
                .ackable_snapshot()
                .map_err(|_| anyhow!("direct_operation_custody_adapter_not_ackable"))?
                .clone(),
            AdapterDispositionCustody::AwaitingAuthenticatedDisposition => {
                bail!("direct_operation_custody_adapter_not_authenticated")
            }
        };
        let mut acknowledgement = DirectOperationOuterAckV3 {
            schema: OUTER_ACK_V3_SCHEMA.to_string(),
            binding_sha256: receipt.binding_sha256.clone(),
            invocation_id: receipt.invocation_id.clone(),
            delivery_provider_attempt_id: receipt.delivery_provider_attempt_id.clone(),
            provider_id: receipt.provider_id.clone(),
            agent_id: receipt.agent_id.clone(),
            adapter,
            authorized_adapter_set_sha256: receipt
                .authorized_adapter_set
                .digest_sha256()
                .map_err(|error| anyhow!(error.to_string()))?,
            outer_receipt_sha256: receipt
                .digest_sha256()
                .map_err(|error| anyhow!(error.to_string()))?,
            journal_evidence_snapshot: snapshot,
            journal_evidence_snapshot_sha256: String::new(),
        };
        acknowledgement.journal_evidence_snapshot_sha256 = acknowledgement
            .journal_evidence_snapshot
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        acknowledgement
            .validate_for_outer_receipt(receipt)
            .map_err(|error| anyhow!(error.to_string()))?;
        let acknowledgement_sha256 = acknowledgement
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let chain_step = DirectOperationOuterAckChainStepV3::derive(
            adapter,
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
        .map_err(|error| anyhow!(error.to_string()))?;
        let chain_step_sha256 = chain_step
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let inbox = DirectOperationOuterAckInboxV3 {
            schema: OUTER_ACK_INBOX_V3_SCHEMA.to_string(),
            acknowledgement,
            acknowledgement_sha256,
            chain_step,
            chain_step_sha256,
        };
        inbox
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        Ok(DirectOperationAdapterAckIntentV3 {
            schema: ACK_INTENT_SCHEMA.to_string(),
            adapter,
            inbox,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectOperationCustodyFileV3 {
    schema: String,
    generation: u64,
    predecessor_store_sha256: String,
    records: Vec<DirectOperationCustodyRecordV3>,
}

impl DirectOperationCustodyFileV3 {
    fn empty() -> Self {
        Self {
            schema: STORE_SCHEMA.to_string(),
            generation: 0,
            predecessor_store_sha256: ZERO_SHA256.to_string(),
            records: Vec::new(),
        }
    }

    fn validate_persisted(&self) -> Result<()> {
        if self.schema != STORE_SCHEMA
            || self.generation == 0
            || (self.generation == 1 && self.predecessor_store_sha256 != ZERO_SHA256)
            || (self.generation > 1 && !valid_nonzero_sha256(&self.predecessor_store_sha256))
            || self.records.is_empty()
            || self.records.len() > MAX_RECORDS
        {
            bail!("direct_operation_custody_file_header_denied");
        }
        let mut previous = None;
        for record in &self.records {
            record.validate()?;
            if previous.is_some_and(|value: &str| value >= record.prepared.binding_sha256.as_str())
            {
                bail!("direct_operation_custody_record_order_or_duplicate_denied");
            }
            previous = Some(record.prepared.binding_sha256.as_str());
        }
        Ok(())
    }
}

struct SecureParent {
    directory: File,
    identity: FileIdentity,
    path: PathBuf,
}

/// One exclusive lock on the retained custody-parent directory inode.  Unlike
/// a same-UID-writable named lock file, the directory inode cannot be bypassed
/// by unlinking and recreating a leaf.  Every store writer and replay launch
/// uses this same kernel lock domain.
struct DirectOperationStoreWriterLease {
    directory: File,
    identity: FileIdentity,
    owner_uid: u32,
    parent_path: PathBuf,
}

impl Drop for DirectOperationStoreWriterLease {
    fn drop(&mut self) {
        // `FD_CLOEXEC` does not prevent an in-flight fork from inheriting this
        // open file description before exec.  Closing only the parent's File
        // would then let that short-lived child extend the flock past the
        // affine capability's lifetime.  Explicit unlock makes lease expiry
        // exact even while such a non-authoritative duplicate still exists.
        unsafe {
            libc::flock(self.directory.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Move-only product admission retaining both the unopened store custody and
/// an exact freshly reconciled external high-water session.  It cannot be
/// reconstructed from a path, head, digest, generation, boolean, or JSON.
#[must_use = "verified custody-store admission must be consumed by open_product"]
pub(crate) struct VerifiedProductDirectOperationCustodyHighWater {
    opened: DirectOperationCustodyStore,
    high_water: VerifiedDirectOperationCustodyHighWater,
    writer_lease: DirectOperationStoreWriterLease,
}

pub(crate) struct DirectOperationCustodyStore {
    parent: SecureParent,
    destination_name: CString,
    file: DirectOperationCustodyFileV3,
    persisted_sha256: Option<String>,
    publication_durability_uncertain: bool,
    active_replay_launches: BTreeSet<String>,
    owner_uid: u32,
    product_high_water_required: bool,
    high_water_permanent_hold: bool,
    high_water: Option<VerifiedDirectOperationCustodyHighWater>,
    #[cfg(test)]
    fail_parent_fsync_after_rename_once: bool,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
#[must_use = "verified pre-dispatch publication must remain in daemon custody"]
pub(crate) struct VerifiedP0PredispatchBindingPublication {
    binding: DirectOperationBinding,
    committed_head: DirectOperationCustodyHead,
    publication_sha256: String,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl VerifiedP0PredispatchBindingPublication {
    pub(crate) fn binding(&self) -> &DirectOperationBinding {
        &self.binding
    }

    pub(crate) fn committed_head(&self) -> &DirectOperationCustodyHead {
        &self.committed_head
    }

    pub(crate) fn publication_sha256(&self) -> &str {
        &self.publication_sha256
    }
}

impl DirectOperationCustodyStore {
    /// Open only the compile-time-fixed root-owned store, reconcile and observe
    /// only the compile-time-fixed independent authority, and return a
    /// move-only admission.  This does not wire main or authorize an effect.
    pub(crate) fn verify_product_high_water()
    -> Result<VerifiedProductDirectOperationCustodyHighWater> {
        transport_contract::require_product_admission_contract()
            .map_err(|error| anyhow!(error.to_string()))?;
        let opened = Self::open_at_path(Path::new(FIXED_PRODUCT_CUSTODY_STORE_PATH), 0)?;
        let writer_lease = acquire_store_writer_lease(&opened.parent, opened.owner_uid)?;
        let opened_head = opened.head();
        opened.verify_named_head_local_under_writer(&opened_head, &writer_lease)?;
        let high_water = VerifiedDirectOperationCustodyHighWater::connect_product(opened.head())?;
        opened.verify_named_head_local_under_writer(&opened_head, &writer_lease)?;
        Ok(VerifiedProductDirectOperationCustodyHighWater {
            opened,
            high_water,
            writer_lease,
        })
    }

    /// The sole product constructor.  The verified fixed-boundary admission is
    /// consumed by value; there are deliberately no constructor arguments.
    pub(crate) fn open_product(
        verified: VerifiedProductDirectOperationCustodyHighWater,
    ) -> Result<Self> {
        transport_contract::require_product_admission_contract()
            .map_err(|error| anyhow!(error.to_string()))?;
        Self::from_verified_product_admission(verified)
    }

    /// Test-only arbitrary-path entry point. Product code has only the fixed,
    /// move-only constructor above; merely compiling it cannot touch a product
    /// path or change a provider lifecycle.
    #[cfg(test)]
    fn open_for_test(path: &Path, owner_uid: u32) -> Result<Self> {
        Self::open_at_path(path, owner_uid)
    }

    #[cfg(test)]
    fn verify_high_water_for_test(
        path: &Path,
        owner_uid: u32,
        authority: &TestDirectOperationCustodyHighWaterAuthority,
    ) -> Result<VerifiedProductDirectOperationCustodyHighWater> {
        let opened = Self::open_at_path(path, owner_uid)?;
        let writer_lease = acquire_store_writer_lease(&opened.parent, opened.owner_uid)?;
        let opened_head = opened.head();
        opened.verify_named_head_local_under_writer(&opened_head, &writer_lease)?;
        let high_water = authority.connect(opened.head())?;
        opened.verify_named_head_local_under_writer(&opened_head, &writer_lease)?;
        Ok(VerifiedProductDirectOperationCustodyHighWater {
            opened,
            high_water,
            writer_lease,
        })
    }

    #[cfg(test)]
    fn open_verified_for_test(
        verified: VerifiedProductDirectOperationCustodyHighWater,
    ) -> Result<Self> {
        Self::from_verified_product_admission(verified)
    }

    fn from_verified_product_admission(
        verified: VerifiedProductDirectOperationCustodyHighWater,
    ) -> Result<Self> {
        let VerifiedProductDirectOperationCustodyHighWater {
            mut opened,
            high_water,
            writer_lease,
        } = verified;
        if opened.product_high_water_required
            || opened.high_water_permanent_hold
            || opened.high_water.is_some()
            || high_water.route() != &product_route()?
            || high_water.committed_head() != &opened.head()
        {
            bail!("direct_operation_custody_verified_high_water_substitution_denied");
        }
        writer_lease.revalidate(&opened.parent, opened.owner_uid)?;
        opened.verify_named_head_local_under_writer(&opened.head(), &writer_lease)?;
        opened.product_high_water_required = true;
        opened.high_water = Some(high_water);
        opened.ensure_live_high_water()?;
        Ok(opened)
    }

    fn open_at_path(path: &Path, owner_uid: u32) -> Result<Self> {
        let (parent, destination_name) = secure_open_parent(path, owner_uid)?;
        let stored = read_named_file(
            &parent.directory,
            &destination_name,
            owner_uid,
            MAX_STORE_BYTES,
        )?;
        let (file, persisted_sha256) = match stored {
            Some(bytes) => {
                let file = decode_canonical_file(&bytes)?;
                // Reopening is the sole recovery boundary for a process that
                // may have lost the result of the prior parent fsync.
                parent
                    .directory
                    .sync_all()
                    .context("direct_operation_custody_reopen_parent_fsync_failed")?;
                (file, Some(sha256_bytes(&bytes)))
            }
            None => (DirectOperationCustodyFileV3::empty(), None),
        };
        Ok(Self {
            parent,
            destination_name,
            file,
            persisted_sha256,
            publication_durability_uncertain: false,
            active_replay_launches: BTreeSet::new(),
            owner_uid,
            product_high_water_required: false,
            high_water_permanent_hold: false,
            high_water: None,
            #[cfg(test)]
            fail_parent_fsync_after_rename_once: false,
        })
    }

    pub(crate) fn head(&self) -> DirectOperationCustodyHead {
        match &self.persisted_sha256 {
            Some(store_sha256) => DirectOperationCustodyHead {
                generation: self.file.generation,
                store_sha256: store_sha256.clone(),
            },
            None => DirectOperationCustodyHead::genesis(),
        }
    }

    pub(crate) fn publication_durability_uncertain(&self) -> bool {
        self.publication_durability_uncertain
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn record_verified_inbox_publication(
        &mut self,
        expected: &DirectOperationCustodyHead,
        seed: DirectOperationInboxCustodySeed,
    ) -> Result<VerifiedP0PredispatchBindingPublication> {
        self.ensure_expected_head(expected)?;
        let binding = seed.binding_inbox.binding.clone();
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let authorized_adapter_set_sha256 = binding
            .authorized_adapter_set
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let prepared = DirectOperationBindingPreparedV3 {
            schema: BINDING_PREPARED_SCHEMA.to_string(),
            binding,
            binding_sha256: binding_sha256.clone(),
            binding_inbox: seed.binding_inbox,
            binding_inbox_bytes_sha256: seed.binding_inbox_bytes_sha256.clone(),
            egress_grant_id_sha256: seed.egress_grant_id_sha256,
            egress_journal_binding_sha256: seed.egress_journal_binding_sha256,
            allocation_egress_cas_sha256: seed.allocation_egress_cas_sha256,
        };
        prepared.validate()?;
        let leaf = DirectOperationBindingLeafPublicationProofV3 {
            schema: BINDING_LEAF_PUBLICATION_SCHEMA.to_string(),
            adapter: DirectOperationAdapter::SystemApi,
            authorized_adapter_set_sha256: authorized_adapter_set_sha256.clone(),
            binding_sha256: binding_sha256.clone(),
            binding_inbox_bytes_sha256: seed.binding_inbox_bytes_sha256.clone(),
            parent_directory_identity_sha256: seed.parent_directory_identity_sha256,
            published_file_identity_sha256: seed.published_file_identity_sha256,
            published_bytes_sha256: seed.binding_inbox_bytes_sha256,
            parent_directory_fsync_proof_sha256: seed.parent_directory_fsync_proof_sha256,
        };
        let leaves = vec![leaf];
        let publication = DirectOperationBindingPublicationProofV3 {
            schema: BINDING_PUBLICATION_SCHEMA.to_string(),
            authorized_adapter_set_sha256,
            binding_sha256: binding_sha256.clone(),
            binding_inbox_bytes_sha256: prepared.binding_inbox_bytes_sha256.clone(),
            leaves_sha256: domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &leaves)?,
            leaves,
        };
        publication.validate_for_prepared(&prepared)?;
        let publication_sha256 = domain_digest(
            b"trillionnium.p0-predispatch-binding-publication.v1",
            &publication,
        )?;
        let prepared_head = self.prepare_binding(expected, prepared)?;
        let committed_head = self.publish_binding(&prepared_head, &binding_sha256, publication)?;
        Ok(VerifiedP0PredispatchBindingPublication {
            binding: self
                .file
                .records
                .iter()
                .find(|record| record.prepared.binding_sha256 == binding_sha256)
                .context("direct_operation_custody_predispatch_binding_missing")?
                .prepared
                .binding
                .clone(),
            committed_head,
            publication_sha256,
        })
    }

    /// Query one exact, already-committed P0 binding publication.  Both full
    /// binding preimages are consumed so the later ACK cannot mistake a
    /// recovery delivery attempt for the attempt that allocated journal
    /// evidence. The exact Binding-authorized P0 System API publication proof
    /// and frozen receipt are read only from this store generation, never from
    /// caller JSON.
    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn verify_p0_binding_publication(
        &self,
        expected: &DirectOperationCustodyHead,
        delivery_binding: DirectOperationBinding,
        allocation_binding: DirectOperationBinding,
    ) -> Result<VerifiedP0BindingPublication> {
        self.ensure_expected_head(expected)?;
        validate_p0_delivery_allocation_bindings(&delivery_binding, &allocation_binding)?;
        let binding_sha256 = delivery_binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let record = self
            .file
            .records
            .iter()
            .find(|record| record.prepared.binding_sha256 == binding_sha256)
            .context("direct_operation_custody_p0_binding_absent")?;
        require_published(record)?;
        if record.prepared.binding != delivery_binding {
            bail!("direct_operation_custody_p0_delivery_preimage_drift");
        }
        let publication = record
            .publication
            .as_ref()
            .context("direct_operation_custody_p0_publication_missing")?;
        publication.validate_for_prepared(&record.prepared)?;
        let outer_receipt = record
            .outer_receipt
            .clone()
            .context("direct_operation_custody_p0_outer_receipt_missing")?;
        let verified = VerifiedP0BindingPublication {
            binding_prepared: record.prepared.clone(),
            binding_publication: publication.clone(),
            delivery_binding,
            allocation_binding,
            committed_head: expected.clone(),
            binding_publication_sha256: domain_digest(
                b"trillionnium.p0-binding-publication-proof.v3",
                publication,
            )?,
            binding_inbox_bytes_sha256: record.prepared.binding_inbox_bytes_sha256.clone(),
            outer_receipt,
            store_parent_identity: self.parent.identity.clone(),
            store_destination_name: self.destination_name.clone(),
        };
        self.validate_current_p0_binding_publication(&verified)?;
        Ok(verified)
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    fn validate_current_p0_binding_publication(
        &self,
        verified: &VerifiedP0BindingPublication,
    ) -> Result<()> {
        self.ensure_expected_head(&verified.committed_head)?;
        verified.validate()?;
        if verified.store_parent_identity != self.parent.identity
            || verified.store_destination_name != self.destination_name
        {
            bail!("direct_operation_custody_p0_guarded_store_identity_drift");
        }
        let binding_sha256 = verified
            .delivery_binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let record = self
            .file
            .records
            .iter()
            .find(|record| record.prepared.binding_sha256 == binding_sha256)
            .context("direct_operation_custody_p0_guarded_binding_absent")?;
        require_published(record)?;
        if record.prepared != verified.binding_prepared
            || record.publication.as_ref() != Some(&verified.binding_publication)
            || record.outer_receipt.as_ref() != Some(&verified.outer_receipt)
        {
            bail!("direct_operation_custody_p0_guarded_store_snapshot_drift");
        }
        Ok(())
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    fn advance_p0_binding_publication(
        &self,
        mut verified: VerifiedP0BindingPublication,
        next_head: DirectOperationCustodyHead,
    ) -> Result<VerifiedP0BindingPublication> {
        if next_head != self.head()
            || next_head.generation < verified.committed_head.generation
            || (next_head.generation == verified.committed_head.generation
                && next_head != verified.committed_head)
        {
            bail!("direct_operation_custody_p0_guarded_head_transition_denied");
        }
        verified.committed_head = next_head;
        self.validate_current_p0_binding_publication(&verified)?;
        Ok(verified)
    }

    pub(crate) fn prepare_binding(
        &mut self,
        expected: &DirectOperationCustodyHead,
        prepared: DirectOperationBindingPreparedV3,
    ) -> Result<DirectOperationCustodyHead> {
        self.ensure_expected_head(expected)?;
        prepared.validate()?;
        if let Some(existing) = self
            .file
            .records
            .iter()
            .find(|record| record.prepared.binding_sha256 == prepared.binding_sha256)
        {
            if existing.prepared == prepared {
                if existing.stage == BindingCustodyStage::CancelledBeforeTool {
                    bail!("direct_operation_custody_cancelled_binding_reuse_denied");
                }
                return Ok(self.head());
            }
            bail!("direct_operation_custody_binding_digest_collision_or_drift");
        }
        let mut candidate = self.file.clone();
        // Cancelled no-dispatch identities are anti-replay tombstones. They
        // must not be pruned without a separately durable monotonic retired-ID
        // accumulator; until that authority exists, exhaustion is a safe
        // liveness HOLD rather than permission to reopen an old binding.
        if candidate.records.len() >= MAX_RECORDS {
            bail!("direct_operation_custody_capacity_exhausted");
        }
        candidate
            .records
            .push(DirectOperationCustodyRecordV3::new(prepared)?);
        candidate.records.sort_by(|left, right| {
            left.prepared
                .binding_sha256
                .cmp(&right.prepared.binding_sha256)
        });
        self.commit_candidate(expected, candidate)
    }

    pub(crate) fn publish_binding(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        publication: DirectOperationBindingPublicationProofV3,
    ) -> Result<DirectOperationCustodyHead> {
        self.transition_record(expected, binding_sha256, |record| {
            publication.validate_for_prepared(&record.prepared)?;
            match &record.publication {
                Some(existing) if existing == &publication => {
                    if record.stage != BindingCustodyStage::BindingPublished {
                        bail!("direct_operation_custody_publication_stage_denied");
                    }
                    Ok(false)
                }
                Some(_) => bail!("direct_operation_custody_publication_proof_drift"),
                None => {
                    if record.stage != BindingCustodyStage::BindingPrepared {
                        bail!("direct_operation_custody_publication_stage_denied");
                    }
                    record.publication = Some(publication);
                    record.stage = BindingCustodyStage::BindingPublished;
                    Ok(true)
                }
            }
        })
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn cancel_published_binding_before_tool(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding: &DirectOperationBinding,
    ) -> Result<DirectOperationCustodyHead> {
        binding
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        self.transition_record(expected, &binding_sha256, |record| {
            if record.prepared.binding != *binding {
                bail!("direct_operation_custody_cancelled_binding_mismatch");
            }
            match record.stage {
                BindingCustodyStage::CancelledBeforeTool => Ok(false),
                BindingCustodyStage::BindingPublished => {
                    if record.terminal_egress.is_some()
                        || record.direct_ui.is_some()
                        || record
                            .adapter_dispositions
                            .iter()
                            .any(|item| item.disposition.authenticated())
                        || record.outer_receipt.is_some()
                        || !record.ack_intents.is_empty()
                        || !record.adapter_ack_progress.is_empty()
                    {
                        bail!("direct_operation_custody_cancel_after_effect_evidence_denied");
                    }
                    record.stage = BindingCustodyStage::CancelledBeforeTool;
                    Ok(true)
                }
                BindingCustodyStage::BindingPrepared => {
                    bail!("direct_operation_custody_cancel_before_publication_denied")
                }
            }
        })
    }

    pub(crate) fn attach_terminal_egress(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        verified: VerifiedTerminalEgressProof,
    ) -> Result<DirectOperationCustodyHead> {
        self.transition_record(expected, binding_sha256, |record| {
            require_published(record)?;
            let proof = verified.materialize_for_prepared(&record.prepared)?;
            match &record.terminal_egress {
                Some(existing) if existing == &proof => Ok(false),
                Some(_) => bail!("direct_operation_custody_terminal_egress_drift"),
                None => {
                    if record.outer_receipt.is_some() {
                        bail!("direct_operation_custody_terminal_after_receipt_denied");
                    }
                    record.terminal_egress = Some(proof);
                    Ok(true)
                }
            }
        })
    }

    pub(crate) fn attach_direct_ui(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        verified: VerifiedDirectUiProof,
    ) -> Result<DirectOperationCustodyHead> {
        self.transition_record(expected, binding_sha256, |record| {
            require_published(record)?;
            let proof = verified.materialize_for_prepared(&record.prepared)?;
            match &record.direct_ui {
                Some(existing) if existing == &proof => Ok(false),
                Some(_) => bail!("direct_operation_custody_direct_ui_drift"),
                None => {
                    if record.outer_receipt.is_some() {
                        bail!("direct_operation_custody_direct_ui_after_receipt_denied");
                    }
                    record.direct_ui = Some(proof);
                    Ok(true)
                }
            }
        })
    }

    pub(crate) fn attach_authenticated_adapter_disposition(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        verified: VerifiedAdapterDisposition,
    ) -> Result<DirectOperationCustodyHead> {
        self.transition_record(expected, binding_sha256, |record| {
            require_published(record)?;
            verified.0.validate_for_prepared(&record.prepared)?;
            let target = record
                .adapter_dispositions
                .iter_mut()
                .find(|item| item.adapter == verified.0.adapter)
                .context("direct_operation_custody_adapter_disposition_slot_missing")?;
            if target == &verified.0 {
                return Ok(false);
            }
            if target.disposition.authenticated() || record.outer_receipt.is_some() {
                bail!("direct_operation_custody_adapter_disposition_drift");
            }
            if !verified.0.disposition.authenticated() {
                bail!("direct_operation_custody_unverified_awaiting_disposition_denied");
            }
            *target = verified.0;
            Ok(true)
        })
    }

    pub(crate) fn freeze_outer_receipt(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
    ) -> Result<DirectOperationCustodyHead> {
        self.transition_record(expected, binding_sha256, |record| {
            require_published(record)?;
            let receipt = record.expected_outer_receipt()?;
            match &record.outer_receipt {
                Some(existing) if existing == &receipt => Ok(false),
                Some(_) => bail!("direct_operation_custody_singleton_receipt_drift"),
                None => {
                    record.outer_receipt = Some(receipt);
                    Ok(true)
                }
            }
        })
    }

    pub(crate) fn prepare_ack_intent(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> Result<DirectOperationCustodyHead> {
        self.transition_record(expected, binding_sha256, |record| {
            require_published(record)?;
            let intent = record.expected_ack_intent(adapter)?;
            if let Some(existing) = record
                .ack_intents
                .iter()
                .find(|existing| existing.adapter == adapter)
            {
                if existing == &intent {
                    return Ok(false);
                }
                bail!("direct_operation_custody_ack_intent_drift");
            }
            record.ack_intents.push(intent);
            record.ack_intents.sort_by_key(|existing| existing.adapter);
            Ok(true)
        })
    }

    /// Snapshot one exact durable ACK intent for the fixed-path root
    /// publisher. This performs no filesystem publication itself and accepts
    /// no path, owner, mode, or endpoint selector beyond the already frozen
    /// adapter slot in this custody record.
    pub(crate) fn prepare_outer_ack_publication(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> Result<PreparedOuterAckPublication> {
        let writer_lease = acquire_store_writer_lease(&self.parent, self.owner_uid)?;
        self.observe_fresh_high_water_under_writer(expected, &writer_lease)?;
        let record = self
            .file
            .records
            .iter()
            .find(|record| record.prepared.binding_sha256 == binding_sha256)
            .context("direct_operation_custody_binding_absent")?;
        require_published(record)?;
        let receipt = record
            .outer_receipt
            .as_ref()
            .context("direct_operation_custody_ack_publication_before_receipt_denied")?;
        let intent = record
            .ack_intents
            .iter()
            .find(|intent| intent.adapter == adapter)
            .context("direct_operation_custody_ack_publication_before_intent_denied")?;
        intent.validate_for_receipt(receipt)?;
        if record
            .adapter_ack_progress
            .iter()
            .find(|progress| progress.adapter == adapter)
            .is_some_and(|progress| progress.completed || progress.outer_ack_retirement.is_some())
        {
            bail!("direct_operation_custody_ack_publication_after_retirement_denied");
        }
        Ok(PreparedOuterAckPublication {
            custody_head: expected.clone(),
            provider_id: record.prepared.binding.stable_seed.provider_id.clone(),
            agent_id: record.prepared.binding.stable_seed.agent_id.clone(),
            adapter,
            binding_sha256: record.prepared.binding_sha256.clone(),
            ack_intent_sha256: intent.digest_sha256()?,
            inbox: intent.inbox.clone(),
            _store_writer_lease: writer_lease,
        })
    }

    /// Consume the verified P0 delivery/allocation publication rather than
    /// accepting a caller-selected binding digest or adapter.  The ordinary
    /// publication capability remains the sole effect input; this affine
    /// envelope only retains the already-verified P0 preimages beside it.
    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn prepare_p0_outer_ack_publication(
        &mut self,
        verified: VerifiedP0BindingPublication,
    ) -> Result<P0BindingPublicationGuarded<PreparedOuterAckPublication>> {
        self.validate_current_p0_binding_publication(&verified)?;
        let expected = verified.committed_head.clone();
        let binding_sha256 = verified
            .delivery_binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let prepared = self.prepare_outer_ack_publication(
            &expected,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
        )?;
        verified.validate_for_phase(
            &prepared.custody_head,
            &prepared.binding_sha256,
            prepared.adapter,
        )?;
        Ok(P0BindingPublicationGuarded::new(verified, prepared))
    }

    /// Derive a measured-helper launch capability only after the publisher's
    /// exact proof has itself been committed. Android confirmation can never
    /// be the first durable ACK-progress fact.
    pub(crate) fn prepare_operation_replay_sync_launch(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> Result<PreparedOperationReplaySyncLaunch> {
        let single_flight_lease = acquire_replay_launch_lease(&self.parent, self.owner_uid)?;
        self.observe_fresh_high_water_under_writer(expected, &single_flight_lease)?;
        let (candidate_launch, needs_commit) = {
            let record = self
                .file
                .records
                .iter()
                .find(|record| record.prepared.binding_sha256 == binding_sha256)
                .context("direct_operation_custody_binding_absent")?;
            require_published(record)?;
            let receipt = record
                .outer_receipt
                .as_ref()
                .context("direct_operation_custody_replay_launch_before_receipt_denied")?;
            let intent = record
                .ack_intents
                .iter()
                .find(|intent| intent.adapter == adapter)
                .context("direct_operation_custody_replay_launch_before_intent_denied")?;
            intent.validate_for_receipt(receipt)?;
            let progress = record
                .adapter_ack_progress
                .iter()
                .find(|progress| progress.adapter == adapter)
                .context("direct_operation_custody_replay_launch_before_publication_denied")?;
            progress.validate_for_intent(&record.prepared, receipt, intent)?;
            let publication = progress
                .outer_ack_inbox_publication
                .as_ref()
                .context("direct_operation_custody_replay_launch_before_publication_denied")?;
            if !publication.external_state_reconciled {
                bail!("direct_operation_custody_replay_launch_publication_reconcile_hold");
            }
            if progress.android_backend_ack_confirmation.is_some()
                || progress.outer_ack_retirement.is_some()
            {
                bail!("direct_operation_custody_replay_launch_after_confirmation_denied");
            }
            match &progress.replay_sync_launch {
                Some(existing) => {
                    validate_launch_progress(
                        existing,
                        &record.prepared,
                        receipt,
                        intent,
                        publication,
                    )?;
                    (existing.clone(), false)
                }
                None => (
                    derive_launch_progress(expected, &record.prepared, intent, publication)?,
                    true,
                ),
            }
        };
        let launch_head = if needs_commit {
            let candidate = candidate_launch.clone();
            self.transition_record_under_writer(
                expected,
                binding_sha256,
                &single_flight_lease,
                |record| {
                    let progress = record
                        .adapter_ack_progress
                        .iter_mut()
                        .find(|progress| progress.adapter == adapter)
                        .context(
                            "direct_operation_custody_replay_launch_before_publication_denied",
                        )?;
                    if progress.replay_sync_launch.is_some()
                        || progress.android_backend_ack_confirmation.is_some()
                        || progress.outer_ack_retirement.is_some()
                    {
                        bail!("direct_operation_custody_replay_launch_single_flight_denied");
                    }
                    progress.replay_sync_launch = Some(candidate);
                    progress.refresh_completed();
                    Ok(true)
                },
            )?
        } else {
            expected.clone()
        };
        if !valid_nonzero_sha256(&candidate_launch.launch_id_sha256) {
            bail!("direct_operation_custody_replay_launch_lease_id_denied");
        }
        if !self
            .active_replay_launches
            .insert(candidate_launch.launch_id_sha256.clone())
        {
            bail!("direct_operation_custody_replay_launch_already_active_hold");
        }
        let record = self
            .file
            .records
            .iter()
            .find(|record| record.prepared.binding_sha256 == binding_sha256)
            .context("direct_operation_custody_binding_absent")?;
        let intent = record
            .ack_intents
            .iter()
            .find(|intent| intent.adapter == adapter)
            .context("direct_operation_custody_replay_launch_before_intent_denied")?;
        let progress = record
            .adapter_ack_progress
            .iter()
            .find(|progress| progress.adapter == adapter)
            .context("direct_operation_custody_replay_launch_before_publication_denied")?;
        let publication = progress
            .outer_ack_inbox_publication
            .clone()
            .context("direct_operation_custody_replay_launch_before_publication_denied")?;
        Ok(PreparedOperationReplaySyncLaunch {
            custody_head: launch_head,
            provider_id: record.prepared.binding.stable_seed.provider_id.clone(),
            agent_id: record.prepared.binding.stable_seed.agent_id.clone(),
            adapter,
            binding_sha256: record.prepared.binding_sha256.clone(),
            ack_intent_sha256: intent.digest_sha256()?,
            operation_replay_sync_ack_intent_sha256: intent
                .inbox
                .operation_replay_sync_ack_intent_sha256()
                .map_err(|error| anyhow!(error.to_string()))?,
            launch_id_sha256: candidate_launch.launch_id_sha256,
            launch_challenge_sha256: candidate_launch.launch_challenge_sha256,
            inbox: intent.inbox.clone(),
            outer_ack_inbox_publication: publication,
            #[cfg(feature = "p0-launch-package-device-conformance")]
            p0_sealed_authority: None,
            _single_flight_lease: single_flight_lease,
        })
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn prepare_p0_operation_replay_sync_launch(
        &mut self,
        verified: VerifiedP0BindingPublication,
    ) -> Result<P0BindingPublicationGuarded<PreparedOperationReplaySyncLaunch>> {
        self.validate_current_p0_binding_publication(&verified)?;
        let expected = verified.committed_head.clone();
        let binding_sha256 = verified
            .delivery_binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let mut prepared = self.prepare_operation_replay_sync_launch(
            &expected,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
        )?;
        let verified =
            self.advance_p0_binding_publication(verified, prepared.custody_head.clone())?;
        verified.validate_for_phase(
            &prepared.custody_head,
            &prepared.binding_sha256,
            prepared.adapter,
        )?;
        prepared._single_flight_lease.revalidate_retained()?;
        self.ensure_live_high_water()?;
        let high_water = self
            .high_water
            .as_mut()
            .context("direct_operation_custody_p0_replay_high_water_missing")?;
        high_water.observe_fresh_exact(&prepared.custody_head)?;
        let high_water_route_sha256 = high_water.route().route_sha256.clone();
        prepared.p0_sealed_authority = Some(
            DirectOperationP0ReplaySyncSealedAuthorityV1::seal(
                verified.delivery_binding.clone(),
                verified.allocation_binding.clone(),
                verified.outer_receipt.clone(),
                prepared.custody_head.clone(),
                verified.binding_publication_sha256.clone(),
                verified.binding_inbox_bytes_sha256.clone(),
                high_water_route_sha256,
                prepared.launch_challenge_sha256.clone(),
                prepared.operation_replay_sync_ack_intent_sha256.clone(),
            )
            .map_err(|error| anyhow!(error.to_string()))?,
        );
        Ok(P0BindingPublicationGuarded::new(verified, prepared))
    }

    pub(crate) fn record_outer_ack_inbox_publication(
        &mut self,
        published: PublishedOuterAckInbox,
    ) -> Result<DirectOperationCustodyHead> {
        self.record_outer_ack_inbox_publication_inner(
            &published.custody_head,
            &published.binding_sha256,
            published.adapter,
            published.verified,
        )
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn record_p0_outer_ack_inbox_publication(
        &mut self,
        guarded: P0BindingPublicationGuarded<PublishedOuterAckInbox>,
    ) -> Result<VerifiedP0BindingPublication> {
        let (verified, published) = guarded.into_parts();
        self.validate_current_p0_binding_publication(&verified)?;
        verified.validate_for_phase(
            &published.custody_head,
            &published.binding_sha256,
            published.adapter,
        )?;
        let next_head = self.record_outer_ack_inbox_publication(published)?;
        self.advance_p0_binding_publication(verified, next_head)
    }

    #[cfg(test)]
    fn record_outer_ack_inbox_publication_for_test(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        verified: VerifiedOuterAckInboxPublicationProof,
    ) -> Result<DirectOperationCustodyHead> {
        self.record_outer_ack_inbox_publication_inner(expected, binding_sha256, adapter, verified)
    }

    fn record_outer_ack_inbox_publication_inner(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        mut verified: VerifiedOuterAckInboxPublicationProof,
    ) -> Result<DirectOperationCustodyHead> {
        let writer = acquire_store_writer_lease(&self.parent, self.owner_uid)?;
        self.verify_named_head_under_writer(expected, &writer)?;
        let mut proof = {
            let record = self
                .file
                .records
                .iter()
                .find(|record| record.prepared.binding_sha256 == binding_sha256)
                .context("direct_operation_custody_binding_absent")?;
            require_published(record)?;
            let receipt = record
                .outer_receipt
                .as_ref()
                .context("direct_operation_custody_ack_publication_before_receipt_denied")?;
            let intent = record
                .ack_intents
                .iter()
                .find(|intent| intent.adapter == adapter)
                .context("direct_operation_custody_ack_publication_before_intent_denied")?;
            verified.materialize_for_intent(&record.prepared, receipt, intent)?
        };
        if proof.adapter != adapter {
            bail!("direct_operation_custody_ack_publication_cross_adapter_denied");
        }
        proof.external_state_reconciled = false;
        let already_reconciled = self
            .file
            .records
            .iter()
            .find(|record| record.prepared.binding_sha256 == binding_sha256)
            .and_then(|record| {
                record
                    .adapter_ack_progress
                    .iter()
                    .find(|progress| progress.adapter == adapter)
            })
            .and_then(|progress| progress.outer_ack_inbox_publication.as_ref())
            .is_some_and(|existing| {
                let mut normalized = existing.clone();
                normalized.external_state_reconciled = false;
                existing.external_state_reconciled && normalized == proof
            });
        let hold_head = if already_reconciled {
            expected.clone()
        } else {
            self.transition_outer_ack_publication_reconcile_under_writer(
                expected,
                binding_sha256,
                adapter,
                &proof,
                false,
                &writer,
            )?
        };
        if let Err(error) = verified.revalidate_retained() {
            if let Err(hold_error) = self.transition_outer_ack_publication_reconcile_under_writer(
                &hold_head,
                binding_sha256,
                adapter,
                &proof,
                false,
                &writer,
            ) {
                self.publication_durability_uncertain = true;
                bail!(
                    "direct_operation_custody_external_publication_hold_commit_unknown: {error:#}; {hold_error:#}"
                );
            }
            return Err(error)
                .context("direct_operation_custody_external_publication_reconcile_hold");
        }
        let reconciled_head = self.transition_outer_ack_publication_reconcile_under_writer(
            &hold_head,
            binding_sha256,
            adapter,
            &proof,
            true,
            &writer,
        )?;
        if let Err(error) = verified.revalidate_retained() {
            match self.transition_outer_ack_publication_reconcile_under_writer(
                &reconciled_head,
                binding_sha256,
                adapter,
                &proof,
                false,
                &writer,
            ) {
                Ok(_) => {
                    return Err(error).context(
                        "direct_operation_custody_external_publication_changed_after_reconcile",
                    );
                }
                Err(hold_error) => {
                    self.publication_durability_uncertain = true;
                    bail!(
                        "direct_operation_custody_external_publication_hold_commit_unknown: {error:#}; {hold_error:#}"
                    );
                }
            }
        }
        Ok(reconciled_head)
    }

    fn transition_outer_ack_publication_reconcile_under_writer(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        proof: &DirectOperationOuterAckInboxPublicationProofV3,
        reconciled: bool,
        writer: &DirectOperationStoreWriterLease,
    ) -> Result<DirectOperationCustodyHead> {
        self.transition_record_under_writer(expected, binding_sha256, writer, |record| {
            require_published(record)?;
            let receipt = record
                .outer_receipt
                .clone()
                .context("direct_operation_custody_ack_publication_before_receipt_denied")?;
            let intent = record
                .ack_intents
                .iter()
                .find(|intent| intent.adapter == adapter)
                .cloned()
                .context("direct_operation_custody_ack_publication_before_intent_denied")?;
            let progress = match record
                .adapter_ack_progress
                .iter_mut()
                .find(|progress| progress.adapter == adapter)
            {
                Some(progress) => progress,
                None if !reconciled => {
                    record
                        .adapter_ack_progress
                        .push(DirectOperationAdapterAckProgressV3::new(
                            &record.prepared,
                            &intent,
                        )?);
                    record
                        .adapter_ack_progress
                        .sort_by_key(|progress| progress.adapter);
                    record
                        .adapter_ack_progress
                        .iter_mut()
                        .find(|progress| progress.adapter == adapter)
                        .expect("inserted ACK progress")
                }
                None => bail!("direct_operation_custody_publication_reconcile_without_hold"),
            };
            if progress.outer_ack_inbox_publication.is_some() {
                progress.validate_for_intent(&record.prepared, &receipt, &intent)?;
            }
            match &mut progress.outer_ack_inbox_publication {
                Some(existing) => {
                    let mut normalized = existing.clone();
                    normalized.external_state_reconciled = false;
                    if normalized != *proof {
                        bail!("direct_operation_custody_ack_publication_proof_drift");
                    }
                    if existing.external_state_reconciled == reconciled {
                        return Ok(false);
                    }
                    existing.external_state_reconciled = reconciled;
                }
                None if !reconciled => {
                    let mut held = proof.clone();
                    held.external_state_reconciled = false;
                    progress.outer_ack_inbox_publication = Some(held);
                }
                None => bail!("direct_operation_custody_publication_reconcile_without_hold"),
            }
            progress.refresh_completed();
            progress.validate_for_intent(&record.prepared, &receipt, &intent)?;
            Ok(true)
        })
    }

    pub(crate) fn record_android_backend_ack_confirmation(
        &mut self,
        completed: CompletedOperationReplaySyncLaunch,
    ) -> Result<DirectOperationCustodyHead> {
        let CompletedOperationReplaySyncLaunch {
            custody_head,
            binding_sha256,
            adapter,
            verified,
            _single_flight_lease,
        } = completed;
        self.record_android_backend_ack_confirmation_inner(
            &custody_head,
            &binding_sha256,
            adapter,
            verified,
            Some(&_single_flight_lease),
        )
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn record_p0_android_backend_ack_confirmation(
        &mut self,
        guarded: P0BindingPublicationGuarded<CompletedOperationReplaySyncLaunch>,
    ) -> Result<VerifiedP0BindingPublication> {
        let (verified, completed) = guarded.into_parts();
        self.validate_current_p0_binding_publication(&verified)?;
        verified.validate_for_phase(
            &completed.custody_head,
            &completed.binding_sha256,
            completed.adapter,
        )?;
        let next_head = self.record_android_backend_ack_confirmation(completed)?;
        self.advance_p0_binding_publication(verified, next_head)
    }

    #[cfg(test)]
    fn record_android_backend_ack_confirmation_for_test(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        verified: VerifiedAndroidBackendAckConfirmationProof,
    ) -> Result<DirectOperationCustodyHead> {
        self.record_android_backend_ack_confirmation_inner(
            expected,
            binding_sha256,
            adapter,
            verified,
            None,
        )
    }

    fn record_android_backend_ack_confirmation_inner(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        verified: VerifiedAndroidBackendAckConfirmationProof,
        writer: Option<&DirectOperationStoreWriterLease>,
    ) -> Result<DirectOperationCustodyHead> {
        let launch_id_sha256 = verified.0.launch_id_sha256.clone();
        let transition = |record: &mut DirectOperationCustodyRecordV3| {
            require_published(record)?;
            let receipt = record
                .outer_receipt
                .clone()
                .context("direct_operation_custody_android_ack_before_receipt_denied")?;
            let intent = record
                .ack_intents
                .iter()
                .find(|intent| intent.adapter == adapter)
                .cloned()
                .context("direct_operation_custody_android_ack_before_intent_denied")?;
            let proof = verified.materialize_for_intent(&record.prepared, &receipt, &intent)?;
            if proof.adapter != adapter {
                bail!("direct_operation_custody_android_ack_cross_adapter_denied");
            }
            if let Some(progress) = record
                .adapter_ack_progress
                .iter_mut()
                .find(|progress| progress.adapter == adapter)
            {
                progress.validate_for_intent(&record.prepared, &receipt, &intent)?;
                if progress.outer_ack_inbox_publication.is_none()
                    || progress.replay_sync_launch.is_none()
                {
                    bail!("direct_operation_custody_android_ack_before_publication_denied");
                }
                match &progress.android_backend_ack_confirmation {
                    Some(existing) if existing == &proof => return Ok(false),
                    Some(_) => {
                        bail!("direct_operation_custody_android_ack_confirmation_drift")
                    }
                    None => progress.android_backend_ack_confirmation = Some(proof),
                }
                progress.refresh_completed();
                progress.validate_for_intent(&record.prepared, &receipt, &intent)?;
                return Ok(true);
            }
            let _ = proof;
            bail!("direct_operation_custody_android_ack_before_publication_denied")
        };
        let head = match writer {
            Some(writer) => {
                self.transition_record_under_writer(expected, binding_sha256, writer, transition)?
            }
            None => self.transition_record(expected, binding_sha256, transition)?,
        };
        if let Some(writer) = writer
            && let Err(error) = writer.revalidate(&self.parent, self.owner_uid)
        {
            self.publication_durability_uncertain = true;
            return Err(error)
                .context("direct_operation_custody_launch_writer_changed_after_confirmation");
        }
        self.active_replay_launches.remove(&launch_id_sha256);
        Ok(head)
    }

    pub(crate) fn prepare_outer_ack_retirement(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
    ) -> Result<PreparedOuterAckRetirement> {
        let writer_lease = acquire_store_writer_lease(&self.parent, self.owner_uid)?;
        self.observe_fresh_high_water_under_writer(expected, &writer_lease)?;
        self.derive_outer_ack_retirement(expected, binding_sha256, adapter, Some(writer_lease))
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn prepare_p0_outer_ack_retirement(
        &mut self,
        verified: VerifiedP0BindingPublication,
    ) -> Result<P0BindingPublicationGuarded<PreparedOuterAckRetirement>> {
        self.validate_current_p0_binding_publication(&verified)?;
        let expected = verified.committed_head.clone();
        let binding_sha256 = verified
            .delivery_binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let prepared = self.prepare_outer_ack_retirement(
            &expected,
            &binding_sha256,
            DirectOperationAdapter::SystemApi,
        )?;
        verified.validate_for_phase(
            &prepared.custody_head,
            &prepared.binding_sha256,
            prepared.adapter,
        )?;
        Ok(P0BindingPublicationGuarded::new(verified, prepared))
    }

    fn derive_outer_ack_retirement(
        &self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        writer_lease: Option<DirectOperationStoreWriterLease>,
    ) -> Result<PreparedOuterAckRetirement> {
        self.ensure_expected_head(expected)?;
        let record = self
            .file
            .records
            .iter()
            .find(|record| record.prepared.binding_sha256 == binding_sha256)
            .context("direct_operation_custody_binding_absent")?;
        require_published(record)?;
        let receipt = record
            .outer_receipt
            .as_ref()
            .context("direct_operation_custody_retirement_before_receipt_denied")?;
        let intent = record
            .ack_intents
            .iter()
            .find(|intent| intent.adapter == adapter)
            .context("direct_operation_custody_retirement_before_intent_denied")?;
        let progress = record
            .adapter_ack_progress
            .iter()
            .find(|progress| progress.adapter == adapter)
            .context("direct_operation_custody_retirement_before_progress_denied")?;
        progress.validate_for_intent(&record.prepared, receipt, intent)?;
        if progress
            .outer_ack_retirement
            .as_ref()
            .is_some_and(|proof| proof.external_state_reconciled)
        {
            bail!("direct_operation_custody_retirement_already_completed");
        }
        let publication = progress
            .outer_ack_inbox_publication
            .clone()
            .context("direct_operation_custody_retirement_before_publication_denied")?;
        if !publication.external_state_reconciled {
            bail!("direct_operation_custody_retirement_publication_reconcile_hold");
        }
        let launch = progress
            .replay_sync_launch
            .as_ref()
            .context("direct_operation_custody_retirement_before_launch_denied")?;
        let confirmation = progress
            .android_backend_ack_confirmation
            .clone()
            .context("direct_operation_custody_retirement_before_android_confirmation_denied")?;
        Ok(PreparedOuterAckRetirement {
            custody_head: expected.clone(),
            provider_id: record.prepared.binding.stable_seed.provider_id.clone(),
            agent_id: record.prepared.binding.stable_seed.agent_id.clone(),
            adapter,
            binding_sha256: binding_sha256.to_string(),
            ack_intent_sha256: intent.digest_sha256()?,
            launch_id_sha256: launch.launch_id_sha256.clone(),
            inbox: intent.inbox.clone(),
            outer_ack_inbox_publication: publication,
            android_backend_ack_confirmation: confirmation,
            _store_writer_lease: writer_lease,
        })
    }

    pub(crate) fn record_outer_ack_retirement(
        &mut self,
        retired: RetiredOuterAckInbox,
    ) -> Result<DirectOperationCustodyHead> {
        let expected = retired.custody_head;
        let binding_sha256 = retired.binding_sha256;
        let adapter = retired.adapter;
        let writer = acquire_store_writer_lease(&self.parent, self.owner_uid)?;
        self.verify_named_head_under_writer(&expected, &writer)?;
        let prepared =
            self.derive_outer_ack_retirement(&expected, &binding_sha256, adapter, None)?;
        let mut verified = retired.verified;
        let mut proof = verified.materialize(&prepared)?;
        proof.external_state_reconciled = false;
        let hold_head = self.transition_outer_ack_retirement_reconcile_under_writer(
            &expected,
            &binding_sha256,
            adapter,
            &proof,
            false,
            &writer,
        )?;
        if let Err(error) = verified.revalidate_retained() {
            return Err(error)
                .context("direct_operation_custody_external_retirement_reconcile_hold");
        }
        let reconciled_head = self.transition_outer_ack_retirement_reconcile_under_writer(
            &hold_head,
            &binding_sha256,
            adapter,
            &proof,
            true,
            &writer,
        )?;
        if let Err(error) = verified.revalidate_retained() {
            match self.transition_outer_ack_retirement_reconcile_under_writer(
                &reconciled_head,
                &binding_sha256,
                adapter,
                &proof,
                false,
                &writer,
            ) {
                Ok(_) => {
                    return Err(error).context(
                        "direct_operation_custody_external_retirement_changed_after_reconcile",
                    );
                }
                Err(hold_error) => {
                    self.publication_durability_uncertain = true;
                    bail!(
                        "direct_operation_custody_external_retirement_hold_commit_unknown: {error:#}; {hold_error:#}"
                    );
                }
            }
        }
        Ok(reconciled_head)
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn record_p0_outer_ack_retirement(
        &mut self,
        guarded: P0BindingPublicationGuarded<RetiredOuterAckInbox>,
    ) -> Result<VerifiedP0BindingPublication> {
        let (verified, retired) = guarded.into_parts();
        self.validate_current_p0_binding_publication(&verified)?;
        verified.validate_for_phase(
            &retired.custody_head,
            &retired.binding_sha256,
            retired.adapter,
        )?;
        let next_head = self.record_outer_ack_retirement(retired)?;
        self.advance_p0_binding_publication(verified, next_head)
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub(crate) fn complete_p0_userdebug_ack_hotpath(
        mut self,
        delivery_binding: DirectOperationBinding,
        allocation_binding: DirectOperationBinding,
        terminal_egress: VerifiedDirectTerminalEgressSnapshot,
        direct_ui: VerifiedDirectUiReplaySnapshot,
    ) -> Result<String> {
        if option_env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT") != Some("userdebug") {
            bail!("direct_operation_custody_p0_hotpath_compiled_variant_denied");
        }
        let binding_sha256 = delivery_binding
            .digest_sha256()
            .map_err(|error| anyhow!(error.to_string()))?;
        let mut head = self.head();
        head = self.attach_terminal_egress(
            &head,
            &binding_sha256,
            VerifiedTerminalEgressProof::from(terminal_egress),
        )?;
        head = self.attach_direct_ui(
            &head,
            &binding_sha256,
            VerifiedDirectUiProof::from(direct_ui),
        )?;
        head = self.freeze_outer_receipt(&head, &binding_sha256)?;
        head =
            self.prepare_ack_intent(&head, &binding_sha256, DirectOperationAdapter::SystemApi)?;
        let verified =
            self.verify_p0_binding_publication(&head, delivery_binding, allocation_binding)?;
        let mut publisher =
            outer_ack_publisher::FixedOuterAckInboxPublisher::from_p0_userdebug_conformance()?;
        let prepared_publication = self.prepare_p0_outer_ack_publication(verified)?;
        let published = publisher.publish_p0(prepared_publication)?;
        let verified = self.record_p0_outer_ack_inbox_publication(published)?;
        let prepared_launch = self.prepare_p0_operation_replay_sync_launch(verified)?;
        let mut launcher = operation_replay_sync_launcher::FixedOperationReplaySyncLauncher::from_p0_userdebug_conformance()?;
        let completed = launcher.launch_p0(prepared_launch)?;
        let verified = self.record_p0_android_backend_ack_confirmation(completed)?;
        let prepared_retirement = self.prepare_p0_outer_ack_retirement(verified)?;
        let retired = publisher.retire_p0(prepared_retirement)?;
        let verified = self.record_p0_outer_ack_retirement(retired)?;
        self.validate_current_p0_binding_publication(&verified)?;
        domain_digest(
            b"trillionnium.p0-userdebug-complete-ack-hotpath.v1",
            verified.committed_head(),
        )
    }

    fn transition_outer_ack_retirement_reconcile_under_writer(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        adapter: DirectOperationAdapter,
        proof: &DirectOperationOuterAckRetirementProofV3,
        reconciled: bool,
        writer: &DirectOperationStoreWriterLease,
    ) -> Result<DirectOperationCustodyHead> {
        self.transition_record_under_writer(expected, binding_sha256, writer, |record| {
            require_published(record)?;
            let receipt = record
                .outer_receipt
                .clone()
                .context("direct_operation_custody_retirement_before_receipt_denied")?;
            let intent = record
                .ack_intents
                .iter()
                .find(|intent| intent.adapter == adapter)
                .cloned()
                .context("direct_operation_custody_retirement_before_intent_denied")?;
            let progress = record
                .adapter_ack_progress
                .iter_mut()
                .find(|progress| progress.adapter == adapter)
                .context("direct_operation_custody_retirement_before_progress_denied")?;
            progress.validate_for_intent(&record.prepared, &receipt, &intent)?;
            match &mut progress.outer_ack_retirement {
                Some(existing) => {
                    let mut normalized = existing.clone();
                    normalized.external_state_reconciled = false;
                    if normalized != *proof {
                        bail!("direct_operation_custody_retirement_proof_drift");
                    }
                    if existing.external_state_reconciled == reconciled {
                        return Ok(false);
                    }
                    existing.external_state_reconciled = reconciled;
                }
                None if !reconciled => {
                    let mut held = proof.clone();
                    held.external_state_reconciled = false;
                    progress.outer_ack_retirement = Some(held);
                }
                None => bail!("direct_operation_custody_retirement_reconcile_without_hold"),
            }
            progress.refresh_completed();
            progress.validate_for_intent(&record.prepared, &receipt, &intent)?;
            Ok(true)
        })
    }

    fn transition_record<F>(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        transition: F,
    ) -> Result<DirectOperationCustodyHead>
    where
        F: FnOnce(&mut DirectOperationCustodyRecordV3) -> Result<bool>,
    {
        let writer = acquire_store_writer_lease(&self.parent, self.owner_uid)?;
        self.transition_record_under_writer(expected, binding_sha256, &writer, transition)
    }

    fn transition_record_under_writer<F>(
        &mut self,
        expected: &DirectOperationCustodyHead,
        binding_sha256: &str,
        writer: &DirectOperationStoreWriterLease,
        transition: F,
    ) -> Result<DirectOperationCustodyHead>
    where
        F: FnOnce(&mut DirectOperationCustodyRecordV3) -> Result<bool>,
    {
        self.verify_named_head_under_writer(expected, writer)?;
        if !valid_nonzero_sha256(binding_sha256) {
            bail!("direct_operation_custody_binding_lookup_denied");
        }
        let mut candidate = self.file.clone();
        let record = candidate
            .records
            .iter_mut()
            .find(|record| record.prepared.binding_sha256 == binding_sha256)
            .context("direct_operation_custody_binding_absent")?;
        let predecessor_record_sha256 = record.digest_sha256()?;
        if !transition(record)? {
            return Ok(self.head());
        }
        record.revision = record
            .revision
            .checked_add(1)
            .context("direct_operation_custody_record_revision_overflow")?;
        record.predecessor_record_sha256 = predecessor_record_sha256;
        record.validate()?;
        self.commit_candidate_under_writer(expected, candidate, writer)
    }

    fn ensure_expected_head(&self, expected: &DirectOperationCustodyHead) -> Result<()> {
        if self.publication_durability_uncertain {
            bail!("direct_operation_custody_fail_stop_commit_unknown");
        }
        self.ensure_live_high_water()?;
        let current = self.head();
        if expected != &current {
            bail!("direct_operation_custody_predecessor_cas_mismatch");
        }
        Ok(())
    }

    fn ensure_live_high_water(&self) -> Result<()> {
        if self.high_water_permanent_hold {
            bail!("direct_operation_custody_external_high_water_permanent_hold");
        }
        if self.product_high_water_required {
            let high_water = self
                .high_water
                .as_ref()
                .context("direct_operation_custody_verified_high_water_capability_missing")?;
            if high_water.route() != &product_route()?
                || high_water.committed_head() != &self.head()
            {
                bail!("direct_operation_custody_live_high_water_drift_hold");
            }
        } else if self.high_water.is_some() {
            bail!("direct_operation_custody_unexpected_high_water_capability");
        }
        Ok(())
    }

    fn observe_fresh_high_water_under_writer(
        &mut self,
        expected: &DirectOperationCustodyHead,
        writer: &DirectOperationStoreWriterLease,
    ) -> Result<()> {
        self.verify_named_head_under_writer(expected, writer)?;
        if self.product_high_water_required {
            let local_head = self.head();
            let observed = self
                .high_water
                .as_mut()
                .context("direct_operation_custody_verified_high_water_capability_missing")?
                .observe_fresh_exact(&local_head);
            if let Err(error) = observed {
                self.high_water_permanent_hold = true;
                return Err(error)
                    .context("direct_operation_custody_fresh_high_water_observe_hold");
            }
        }
        self.verify_named_head_under_writer(expected, writer)
    }

    fn commit_candidate(
        &mut self,
        expected: &DirectOperationCustodyHead,
        candidate: DirectOperationCustodyFileV3,
    ) -> Result<DirectOperationCustodyHead> {
        let writer = acquire_store_writer_lease(&self.parent, self.owner_uid)?;
        self.commit_candidate_under_writer(expected, candidate, &writer)
    }

    fn verify_named_head_under_writer(
        &self,
        expected: &DirectOperationCustodyHead,
        writer: &DirectOperationStoreWriterLease,
    ) -> Result<()> {
        self.ensure_expected_head(expected)?;
        self.verify_named_head_local_under_writer(expected, writer)
    }

    fn verify_named_head_local_under_writer(
        &self,
        expected: &DirectOperationCustodyHead,
        writer: &DirectOperationStoreWriterLease,
    ) -> Result<()> {
        if self.publication_durability_uncertain {
            bail!("direct_operation_custody_fail_stop_commit_unknown");
        }
        if expected != &self.head() {
            bail!("direct_operation_custody_predecessor_cas_mismatch");
        }
        writer.revalidate(&self.parent, self.owner_uid)?;
        let current = read_named_file(
            &self.parent.directory,
            &self.destination_name,
            self.owner_uid,
            MAX_STORE_BYTES,
        )?;
        match (&self.persisted_sha256, current.as_deref()) {
            (None, None) => {}
            (Some(expected_sha256), Some(bytes)) if sha256_bytes(bytes) == *expected_sha256 => {}
            _ => bail!("direct_operation_custody_changed_outside_atomic_writer"),
        }
        Ok(())
    }

    fn commit_candidate_under_writer(
        &mut self,
        expected: &DirectOperationCustodyHead,
        mut candidate: DirectOperationCustodyFileV3,
        writer: &DirectOperationStoreWriterLease,
    ) -> Result<DirectOperationCustodyHead> {
        self.verify_named_head_under_writer(expected, writer)?;

        candidate.generation = self
            .file
            .generation
            .checked_add(1)
            .context("direct_operation_custody_generation_overflow")?;
        candidate.predecessor_store_sha256 = self
            .persisted_sha256
            .clone()
            .unwrap_or_else(|| ZERO_SHA256.to_string());
        candidate.validate_persisted()?;
        let bytes = encode_canonical_file(&candidate)?;
        let new_sha256 = sha256_bytes(&bytes);
        let to_head = DirectOperationCustodyHead::new(candidate.generation, new_sha256.clone())
            .map_err(|error| anyhow!(error))?;

        if !self.product_high_water_required {
            return self.publish_finalized_candidate_under_writer(
                expected, candidate, &bytes, new_sha256, writer,
            );
        }

        let from_head = self.head();
        let authority = self
            .high_water
            .take()
            .context("direct_operation_custody_verified_high_water_capability_missing")?;
        let prepared = match authority.prepare(to_head.clone()) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.high_water_permanent_hold = true;
                return Err(error)
                    .context("direct_operation_custody_high_water_prepare_permanent_hold");
            }
        };

        let published = self.publish_finalized_candidate_under_writer(
            expected, candidate, &bytes, new_sha256, writer,
        );
        let published_head = match published {
            Ok(head) => head,
            Err(local_error) => {
                if self.publication_durability_uncertain {
                    self.high_water_permanent_hold = true;
                    return Err(local_error).context(
                        "direct_operation_custody_local_commit_unknown_high_water_session_hold",
                    );
                }
                match prepared.reconcile_known_local(from_head) {
                    Ok(reconciled) => self.high_water = Some(reconciled),
                    Err(reconcile_error) => {
                        self.high_water_permanent_hold = true;
                        return Err(reconcile_error).context(
                            "direct_operation_custody_known_local_abort_reconcile_permanent_hold",
                        );
                    }
                }
                return Err(local_error)
                    .context("direct_operation_custody_known_local_commit_failure_reconciled");
            }
        };
        if published_head != to_head {
            self.high_water_permanent_hold = true;
            bail!("direct_operation_custody_local_published_head_drift_hold");
        }
        let committed = match prepared.commit(&to_head) {
            Ok(committed) => committed,
            Err(error) => {
                self.high_water_permanent_hold = true;
                return Err(error)
                    .context("direct_operation_custody_high_water_commit_permanent_hold");
            }
        };
        let reconciled = match committed.reconcile(&to_head) {
            Ok(reconciled) => reconciled,
            Err(error) => {
                self.high_water_permanent_hold = true;
                return Err(error)
                    .context("direct_operation_custody_high_water_reconcile_permanent_hold");
            }
        };
        self.high_water = Some(reconciled);
        self.ensure_live_high_water()?;
        Ok(published_head)
    }

    fn publish_finalized_candidate_under_writer(
        &mut self,
        expected: &DirectOperationCustodyHead,
        candidate: DirectOperationCustodyFileV3,
        bytes: &[u8],
        new_sha256: String,
        writer: &DirectOperationStoreWriterLease,
    ) -> Result<DirectOperationCustodyHead> {
        let temporary_name = temporary_name()?;
        let mut temporary =
            openat_create_new(self.parent.directory.as_raw_fd(), &temporary_name, 0o600)?;
        let before_rename = (|| -> Result<()> {
            set_exact_mode(&temporary, 0o600)?;
            temporary.write_all(bytes)?;
            temporary.sync_all()?;
            validate_open_regular(&temporary, self.owner_uid, MAX_STORE_BYTES)?;
            temporary.seek(SeekFrom::Start(0))?;
            let mut readback = Vec::new();
            Read::by_ref(&mut temporary)
                .take(MAX_STORE_BYTES as u64 + 1)
                .read_to_end(&mut readback)?;
            if readback != bytes {
                bail!("direct_operation_custody_temp_readback_mismatch");
            }
            // Recheck the named predecessor immediately before replacement
            // while the stable directory writer lease is still held.
            self.verify_named_head_local_under_writer(expected, writer)?;
            renameat_same_parent(
                self.parent.directory.as_raw_fd(),
                &temporary_name,
                &self.destination_name,
            )?;
            Ok(())
        })();
        if let Err(error) = before_rename {
            let _ = unlinkat_file(self.parent.directory.as_raw_fd(), &temporary_name);
            return Err(error);
        }

        // The namespace now exposes candidate bytes. From this point forward
        // rollback would contradict what a reopening daemon can observe.
        self.file = candidate;
        self.persisted_sha256 = Some(new_sha256.clone());
        #[cfg(test)]
        if std::mem::take(&mut self.fail_parent_fsync_after_rename_once) {
            self.publication_durability_uncertain = true;
            bail!("direct_operation_custody_parent_fsync_commit_unknown_test_fault");
        }
        if let Err(error) = self.parent.directory.sync_all() {
            self.publication_durability_uncertain = true;
            return Err(error).context("direct_operation_custody_parent_fsync_commit_unknown");
        }
        match read_named_file(
            &self.parent.directory,
            &self.destination_name,
            self.owner_uid,
            MAX_STORE_BYTES,
        ) {
            Ok(Some(readback)) if readback == bytes => {}
            Ok(_) => {
                self.publication_durability_uncertain = true;
                bail!("direct_operation_custody_published_readback_mismatch");
            }
            Err(error) => {
                self.publication_durability_uncertain = true;
                return Err(error).context("direct_operation_custody_published_readback_failed");
            }
        }
        if let Err(error) = self.parent.validate(self.owner_uid) {
            self.publication_durability_uncertain = true;
            return Err(error).context("direct_operation_custody_parent_changed_after_publish");
        }
        if let Err(error) = writer.revalidate(&self.parent, self.owner_uid) {
            self.publication_durability_uncertain = true;
            return Err(error).context("direct_operation_custody_writer_changed_after_publish");
        }
        DirectOperationCustodyHead::new(self.file.generation, new_sha256)
            .map_err(|error| anyhow!(error))
    }

    #[cfg(test)]
    fn fail_parent_fsync_after_rename_once_for_test(&mut self) {
        self.fail_parent_fsync_after_rename_once = true;
    }
}

fn derive_launch_progress(
    predecessor: &DirectOperationCustodyHead,
    prepared: &DirectOperationBindingPreparedV3,
    intent: &DirectOperationAdapterAckIntentV3,
    publication: &DirectOperationOuterAckInboxPublicationProofV3,
) -> Result<DirectOperationReplaySyncLaunchProgressV3> {
    intent.validate()?;
    if predecessor.generation == 0
        || !valid_nonzero_sha256(&predecessor.store_sha256)
        || publication.adapter != intent.adapter
        || publication.binding_sha256 != prepared.binding_sha256
        || publication.ack_intent_sha256 != intent.digest_sha256()?
        || !valid_nonzero_sha256(&publication.publication_custody_source_sha256)
    {
        bail!("direct_operation_custody_replay_launch_predecessor_denied");
    }
    let operation_replay_sync_ack_intent_sha256 = intent
        .inbox
        .operation_replay_sync_ack_intent_sha256()
        .map_err(|error| anyhow!(error.to_string()))?;
    let binding_sha256 = prepared.binding_sha256.clone();
    let ack_intent_sha256 = intent.digest_sha256()?;
    let outer_ack_publication_custody_sha256 =
        publication.publication_custody_source_sha256.clone();
    let id_material = ReplaySyncLaunchIdMaterialV3 {
        schema: REPLAY_SYNC_LAUNCH_PROGRESS_SCHEMA,
        adapter: intent.adapter,
        binding_sha256: &binding_sha256,
        ack_intent_sha256: &ack_intent_sha256,
        operation_replay_sync_ack_intent_sha256: &operation_replay_sync_ack_intent_sha256,
        outer_ack_publication_custody_sha256: &outer_ack_publication_custody_sha256,
        predecessor_generation: predecessor.generation,
        predecessor_store_sha256: &predecessor.store_sha256,
    };
    let launch_id_sha256 = domain_digest(REPLAY_SYNC_LAUNCH_ID_DIGEST_DOMAIN, &id_material)?;
    let challenge_material = ReplaySyncLaunchChallengeMaterialV3 {
        schema: REPLAY_SYNC_LAUNCH_PROGRESS_SCHEMA,
        launch_id_sha256: &launch_id_sha256,
        binding_sha256: &binding_sha256,
        operation_replay_sync_ack_intent_sha256: &operation_replay_sync_ack_intent_sha256,
        outer_ack_publication_custody_sha256: &outer_ack_publication_custody_sha256,
    };
    let launch_challenge_sha256 = domain_digest(
        REPLAY_SYNC_LAUNCH_CHALLENGE_DIGEST_DOMAIN,
        &challenge_material,
    )?;
    Ok(DirectOperationReplaySyncLaunchProgressV3 {
        schema: REPLAY_SYNC_LAUNCH_PROGRESS_SCHEMA.to_string(),
        adapter: intent.adapter,
        binding_sha256,
        ack_intent_sha256,
        operation_replay_sync_ack_intent_sha256,
        outer_ack_publication_custody_sha256,
        predecessor_generation: predecessor.generation,
        predecessor_store_sha256: predecessor.store_sha256.clone(),
        launch_id_sha256,
        launch_challenge_sha256,
    })
}

fn validate_launch_progress(
    launch: &DirectOperationReplaySyncLaunchProgressV3,
    prepared: &DirectOperationBindingPreparedV3,
    _receipt: &DirectOperationOuterReceiptV3,
    intent: &DirectOperationAdapterAckIntentV3,
    publication: &DirectOperationOuterAckInboxPublicationProofV3,
) -> Result<()> {
    let operation_replay_sync_ack_intent_sha256 = intent
        .inbox
        .operation_replay_sync_ack_intent_sha256()
        .map_err(|error| anyhow!(error.to_string()))?;
    if launch.schema != REPLAY_SYNC_LAUNCH_PROGRESS_SCHEMA
        || launch.adapter != intent.adapter
        || launch.binding_sha256 != prepared.binding_sha256
        || launch.ack_intent_sha256 != intent.digest_sha256()?
        || launch.operation_replay_sync_ack_intent_sha256 != operation_replay_sync_ack_intent_sha256
        || launch.outer_ack_publication_custody_sha256
            != publication.publication_custody_source_sha256
        || launch.predecessor_generation == 0
        || !valid_nonzero_sha256(&launch.predecessor_store_sha256)
    {
        bail!("direct_operation_custody_replay_launch_progress_denied");
    }
    let id_material = ReplaySyncLaunchIdMaterialV3 {
        schema: REPLAY_SYNC_LAUNCH_PROGRESS_SCHEMA,
        adapter: launch.adapter,
        binding_sha256: &launch.binding_sha256,
        ack_intent_sha256: &launch.ack_intent_sha256,
        operation_replay_sync_ack_intent_sha256: &launch.operation_replay_sync_ack_intent_sha256,
        outer_ack_publication_custody_sha256: &launch.outer_ack_publication_custody_sha256,
        predecessor_generation: launch.predecessor_generation,
        predecessor_store_sha256: &launch.predecessor_store_sha256,
    };
    let expected_id = domain_digest(REPLAY_SYNC_LAUNCH_ID_DIGEST_DOMAIN, &id_material)?;
    let challenge_material = ReplaySyncLaunchChallengeMaterialV3 {
        schema: REPLAY_SYNC_LAUNCH_PROGRESS_SCHEMA,
        launch_id_sha256: &expected_id,
        binding_sha256: &launch.binding_sha256,
        operation_replay_sync_ack_intent_sha256: &launch.operation_replay_sync_ack_intent_sha256,
        outer_ack_publication_custody_sha256: &launch.outer_ack_publication_custody_sha256,
    };
    let expected_challenge = domain_digest(
        REPLAY_SYNC_LAUNCH_CHALLENGE_DIGEST_DOMAIN,
        &challenge_material,
    )?;
    if launch.launch_id_sha256 != expected_id
        || launch.launch_challenge_sha256 != expected_challenge
    {
        bail!("direct_operation_custody_replay_launch_digest_drift");
    }
    Ok(())
}

fn valid_archived_leaf_name(name: &str, ack_intent_sha256: &str) -> bool {
    valid_nonzero_sha256(ack_intent_sha256) && name == format!("acked-{ack_intent_sha256}.json")
}

fn validate_retirement_proof(
    proof: &DirectOperationOuterAckRetirementProofV3,
    prepared: &PreparedOuterAckRetirement,
) -> Result<()> {
    if proof.schema != OUTER_ACK_RETIREMENT_PROOF_SCHEMA
        || proof.adapter != prepared.adapter
        || proof.binding_sha256 != prepared.binding_sha256
        || proof.ack_intent_sha256 != prepared.ack_intent_sha256
        || proof.launch_id_sha256 != prepared.launch_id_sha256
        || proof.acknowledgement_sha256 != prepared.inbox.acknowledgement_sha256
        || proof.authenticated_ack_chain_sha256
            != prepared.inbox.chain_step.authenticated_ack_chain_sha256
        || !valid_archived_leaf_name(&proof.archived_leaf_name, &prepared.ack_intent_sha256)
        || proof.archived_bytes_sha256
            != prepared
                .outer_ack_inbox_publication
                .canonical_inbox_bytes_sha256
        || proof.publisher_provenance != prepared.outer_ack_inbox_publication.publisher_provenance
        || !valid_nonzero_sha256(&proof.retirement_custody_source_sha256)
    {
        bail!("direct_operation_custody_retirement_proof_denied");
    }
    Ok(())
}

fn acquire_replay_launch_lease(
    parent: &SecureParent,
    owner_uid: u32,
) -> Result<DirectOperationStoreWriterLease> {
    acquire_store_writer_lease(parent, owner_uid).map_err(|error| {
        if error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock)
        {
            anyhow!("direct_operation_custody_replay_launch_already_active_hold")
        } else {
            error.context("direct_operation_custody_replay_launch_lease_failed")
        }
    })
}

fn require_published(record: &DirectOperationCustodyRecordV3) -> Result<()> {
    if record.stage != BindingCustodyStage::BindingPublished || record.publication.is_none() {
        bail!("direct_operation_custody_binding_not_published");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FileIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
}

#[allow(clippy::useless_conversion)]
fn normalized_nlink(value: libc::nlink_t) -> u64 {
    u64::from(value)
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            nlink: metadata.nlink(),
        }
    }

    fn from_stat(stat: &libc::stat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: stat.st_mode,
            nlink: normalized_nlink(stat.st_nlink),
        }
    }

    fn same_directory_custody(&self, other: &Self) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.uid == other.uid
            && self.gid == other.gid
            && self.mode == other.mode
    }
}

impl SecureParent {
    fn validate(&self, owner_uid: u32) -> Result<()> {
        let metadata = self.directory.metadata()?;
        let current = FileIdentity::from_metadata(&metadata);
        if current != self.identity
            || !metadata.is_dir()
            || metadata.uid() != owner_uid
            || metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.nlink() == 0
        {
            bail!("direct_operation_custody_parent_identity_changed");
        }
        let path_directory = open_existing_secure_parent_path(&self.path, owner_uid)?;
        if FileIdentity::from_metadata(&path_directory.metadata()?) != self.identity {
            bail!("direct_operation_custody_parent_path_rebound");
        }
        Ok(())
    }
}

impl DirectOperationStoreWriterLease {
    fn revalidate_retained(&self) -> Result<()> {
        let metadata = self.directory.metadata()?;
        let current = FileIdentity::from_metadata(&metadata);
        if current != self.identity
            || !metadata.is_dir()
            || metadata.uid() != self.owner_uid
            || metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.nlink() == 0
        {
            bail!("direct_operation_custody_writer_directory_identity_changed");
        }
        let path_directory = open_existing_secure_parent_path(&self.parent_path, self.owner_uid)?;
        if FileIdentity::from_metadata(&path_directory.metadata()?) != self.identity {
            bail!("direct_operation_custody_writer_directory_path_rebound");
        }
        Ok(())
    }

    fn revalidate(&self, parent: &SecureParent, owner_uid: u32) -> Result<()> {
        parent.validate(owner_uid)?;
        self.revalidate_retained()?;
        if self.identity != parent.identity || self.owner_uid != owner_uid {
            bail!("direct_operation_custody_writer_directory_identity_changed");
        }
        Ok(())
    }
}

fn acquire_store_writer_lease(
    parent: &SecureParent,
    owner_uid: u32,
) -> Result<DirectOperationStoreWriterLease> {
    parent.validate(owner_uid)?;
    // Reopen `.` relative to the retained parent to obtain an independent open
    // file description.  `flock` on that stable directory inode serialises all
    // conforming store writers without relying on a replaceable lock leaf.
    let directory = open_directory(parent.directory.as_raw_fd(), c".")?;
    let identity = FileIdentity::from_metadata(&directory.metadata()?);
    if identity != parent.identity {
        bail!("direct_operation_custody_writer_directory_reopen_drift");
    }
    if unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_writer_directory_lock_unavailable");
    }
    let lease = DirectOperationStoreWriterLease {
        directory,
        identity,
        owner_uid,
        parent_path: parent.path.clone(),
    };
    lease.revalidate(parent, owner_uid)?;
    Ok(lease)
}

fn open_existing_secure_parent_path(path: &Path, owner_uid: u32) -> Result<File> {
    if !path.is_absolute() {
        bail!("direct_operation_custody_parent_path_must_be_absolute");
    }
    let root_name = CString::new("/").expect("literal has no NUL");
    let mut current = open_directory(libc::AT_FDCWD, &root_name)?;
    validate_trusted_ancestor(Path::new("/"), &current.metadata()?, owner_uid)?;
    let mut current_path = PathBuf::from("/");
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(name) => Some(Ok(name.to_owned())),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => Some(Err(anyhow!(
                "direct_operation_custody_parent_component_denied"
            ))),
        })
        .collect::<Result<Vec<_>>>()?;
    if components.is_empty() {
        bail!("direct_operation_custody_root_parent_denied");
    }
    for (index, component) in components.iter().enumerate() {
        let component_name = CString::new(component.as_bytes())
            .context("direct_operation_custody_parent_component_contains_nul")?;
        let next = open_directory(current.as_raw_fd(), &component_name)?;
        current_path.push(component);
        let metadata = next.metadata()?;
        if index + 1 == components.len() {
            if !metadata.is_dir()
                || metadata.uid() != owner_uid
                || metadata.permissions().mode() & 0o7777 != 0o700
                || metadata.nlink() == 0
            {
                bail!("direct_operation_custody_parent_not_owner_private");
            }
        } else {
            validate_trusted_ancestor(&current_path, &metadata, owner_uid)?;
        }
        current = next;
    }
    Ok(current)
}

fn secure_open_parent(path: &Path, owner_uid: u32) -> Result<(SecureParent, CString)> {
    if !path.is_absolute() {
        bail!("direct_operation_custody_path_must_be_absolute");
    }
    let destination = path
        .file_name()
        .context("direct_operation_custody_destination_name_missing")?;
    if destination.as_bytes().is_empty() || destination.as_bytes().contains(&0) {
        bail!("direct_operation_custody_destination_name_denied");
    }
    let destination_name = CString::new(destination.as_bytes())
        .context("direct_operation_custody_destination_name_contains_nul")?;
    let parent_path = path
        .parent()
        .context("direct_operation_custody_parent_missing")?;

    let root_name = CString::new("/").expect("literal has no NUL");
    let mut current = open_directory(libc::AT_FDCWD, &root_name)?;
    let root_metadata = current.metadata()?;
    validate_trusted_ancestor(Path::new("/"), &root_metadata, owner_uid)?;
    let mut current_path = PathBuf::from("/");
    let mut components = Vec::new();
    for component in parent_path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name.to_owned()),
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                bail!("direct_operation_custody_parent_component_denied")
            }
        }
    }
    if components.is_empty() {
        bail!("direct_operation_custody_root_parent_denied");
    }

    for (index, component) in components.iter().enumerate() {
        let component_name = CString::new(component.as_bytes())
            .context("direct_operation_custody_parent_component_contains_nul")?;
        let (next, created) = match open_directory(current.as_raw_fd(), &component_name) {
            Ok(directory) => (directory, false),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
            {
                mkdirat_private(current.as_raw_fd(), &component_name)?;
                (open_directory(current.as_raw_fd(), &component_name)?, true)
            }
            Err(error) => return Err(error),
        };
        if created {
            // A child-directory fsync does not make its name durable in the
            // parent.  Persist every lazily-created ancestry edge before a
            // journal or custody record can be treated as crash durable.
            next.sync_all()?;
            current.sync_all()?;
            let rebound = open_directory(current.as_raw_fd(), &component_name)?;
            if FileIdentity::from_metadata(&rebound.metadata()?)
                != FileIdentity::from_metadata(&next.metadata()?)
            {
                bail!("direct_operation_custody_created_parent_rebound");
            }
        }
        current_path.push(component);
        let metadata = next.metadata()?;
        let final_parent = index + 1 == components.len();
        if final_parent {
            if !metadata.is_dir()
                || metadata.uid() != owner_uid
                || metadata.permissions().mode() & 0o7777 != 0o700
                || metadata.nlink() == 0
            {
                bail!("direct_operation_custody_parent_not_owner_private");
            }
        } else {
            validate_trusted_ancestor(&current_path, &metadata, owner_uid)?;
        }
        current = next;
    }

    let identity = FileIdentity::from_metadata(&current.metadata()?);
    let parent = SecureParent {
        directory: current,
        identity,
        path: parent_path.to_path_buf(),
    };
    parent.validate(owner_uid)?;
    Ok((parent, destination_name))
}

fn validate_trusted_ancestor(
    path: &Path,
    metadata: &std::fs::Metadata,
    owner_uid: u32,
) -> Result<()> {
    let mode = metadata.mode() & 0o7777;
    let trusted_owner = metadata.uid() == 0 || metadata.uid() == owner_uid;
    let sticky_system_root = metadata.uid() == 0
        && mode & libc::S_ISVTX != 0
        && matches!(path.to_str(), Some("/tmp" | "/var/tmp" | "/dev/shm"));
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.nlink() == 0
        || !trusted_owner
        || (mode & 0o022 != 0 && !sticky_system_root)
    {
        bail!(
            "direct_operation_custody_unsafe_ancestor:{}:uid={}:expected_uid={}:mode={:o}:nlink={}:is_dir={}",
            path.display(),
            metadata.uid(),
            owner_uid,
            mode,
            metadata.nlink(),
            metadata.is_dir()
        );
    }
    Ok(())
}

fn open_directory(parent_fd: RawFd, name: &CStr) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_open_directory_failed");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn mkdirat_private(parent_fd: RawFd, name: &CStr) -> Result<()> {
    let result = unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o700) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(error).context("direct_operation_custody_mkdirat_failed");
        }
    }
    Ok(())
}

fn read_named_file(
    parent: &File,
    name: &CStr,
    owner_uid: u32,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("direct_operation_custody_open_file_failed");
    }
    let input = unsafe { File::from_raw_fd(fd) };
    validate_open_regular(&input, owner_uid, max_bytes)?;
    let opened = FileIdentity::from_metadata(&input.metadata()?);
    let mut bytes = Vec::new();
    input.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("direct_operation_custody_file_size_limit_exceeded");
    }
    let (named, named_len) = statat_nofollow(parent.as_raw_fd(), name)?
        .context("direct_operation_custody_file_disappeared_during_read")?;
    if opened != named || named_len != bytes.len() as u64 {
        bail!("direct_operation_custody_file_identity_changed_during_read");
    }
    Ok(Some(bytes))
}

fn statat_nofollow(parent_fd: RawFd, name: &CStr) -> Result<Option<(FileIdentity, u64)>> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::zeroed();
    let result = unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error).context("direct_operation_custody_fstatat_failed");
    }
    let stat = unsafe { stat.assume_init() };
    Ok(Some((FileIdentity::from_stat(&stat), stat.st_size as u64)))
}

fn validate_open_regular(file: &File, owner_uid: u32, max_bytes: usize) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > max_bytes as u64
    {
        bail!("direct_operation_custody_file_not_owner_private_single_link");
    }
    Ok(())
}

fn openat_create_new(parent_fd: RawFd, name: &CStr, mode: libc::mode_t) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_create_temp_failed");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn set_exact_mode(file: &File, mode: u32) -> Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .context("direct_operation_custody_set_mode_failed")
}

fn renameat_same_parent(parent_fd: RawFd, old_name: &CStr, new_name: &CStr) -> Result<()> {
    let result =
        unsafe { libc::renameat(parent_fd, old_name.as_ptr(), parent_fd, new_name.as_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_atomic_rename_failed");
    }
    Ok(())
}

fn unlinkat_file(parent_fd: RawFd, name: &CStr) -> Result<()> {
    let result = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("direct_operation_custody_unlink_temp_failed");
    }
    Ok(())
}

fn temporary_name() -> Result<CString> {
    CString::new(format!(
        ".direct-operation-custody.tmp-{}-{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
    .context("direct_operation_custody_temp_name_contains_nul")
}

fn encode_canonical_file(file: &DirectOperationCustodyFileV3) -> Result<Vec<u8>> {
    file.validate_persisted()?;
    let mut bytes = serde_json::to_vec_pretty(file)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_STORE_BYTES {
        bail!("direct_operation_custody_file_size_limit_exceeded");
    }
    Ok(bytes)
}

fn decode_canonical_file(bytes: &[u8]) -> Result<DirectOperationCustodyFileV3> {
    if bytes.is_empty() || bytes.len() > MAX_STORE_BYTES {
        bail!("direct_operation_custody_file_size_boundary_denied");
    }
    let file: DirectOperationCustodyFileV3 =
        serde_json::from_slice(bytes).context("direct_operation_custody_file_json_denied")?;
    file.validate_persisted()?;
    if encode_canonical_file(&file)? != bytes {
        bail!("direct_operation_custody_file_not_canonical_closed_world_json");
    }
    Ok(file)
}

fn binding_inbox_bytes_sha256(inbox: &DirectOperationBindingInbox) -> Result<String> {
    inbox
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    let mut bytes = serde_json::to_vec(inbox)?;
    bytes.push(b'\n');
    Ok(sha256_bytes(&bytes))
}

fn domain_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String> {
    let encoded = serde_json::to_vec(value)?;
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(&encoded);
    Ok(format!("{:x}", hasher.finalize()))
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value != ZERO_SHA256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(feature = "p0-launch-package-device-conformance")]
fn validate_p0_delivery_allocation_bindings(
    delivery: &DirectOperationBinding,
    allocation: &DirectOperationBinding,
) -> Result<()> {
    delivery
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    allocation
        .validate()
        .map_err(|error| anyhow!(error.to_string()))?;
    if delivery.stable_seed != allocation.stable_seed
        || delivery.invocation_id != allocation.invocation_id
        || delivery.workflow_id_sha256 != allocation.workflow_id_sha256
        || delivery.agent_identity_key_sha256 != allocation.agent_identity_key_sha256
        || delivery.agent_executable_sha256 != allocation.agent_executable_sha256
        || delivery.authorized_adapter_set != allocation.authorized_adapter_set
    {
        bail!("direct_operation_custody_p0_delivery_allocation_lineage_denied");
    }
    delivery
        .authorized_adapter_set
        .validate_p0_system_api()
        .map_err(|error| anyhow!(error.to_string()))?;
    allocation
        .authorized_adapter_set
        .validate_p0_system_api()
        .map_err(|error| anyhow!(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt, symlink};

    use crate::action_workflow::{DirectPlanCustodyCandidate, PlanRecoveryBinding};
    use crate::context_memory::{ContextMemoryService, Subject};
    use serde_json::json;
    use tempfile::TempDir;
    use trillionnium_os_types::direct_operation::{
        ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA, BINDING_SCHEMA,
        DirectOperationAdapterTerminalStateV1, DirectOperationJournalEvidenceSnapshotV1,
        DirectOperationOuterEvidence, DirectOperationOuterOutcome, DirectOperationProviderAttempt,
        DirectOperationReplaySyncAckConfirmationV3, DirectOperationStableSeed,
        JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA, OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA,
        STABLE_SEED_SCHEMA,
    };
    #[cfg(feature = "p0-launch-package-device-conformance")]
    use trillionnium_os_types::direct_operation::{
        DirectOperationP0ReplaySyncAckConfirmationV1, P0_REPLAY_SYNC_ACK_CONFIRMATION_LANE,
        P0_REPLAY_SYNC_ACK_CONFIRMATION_V1_SCHEMA,
    };

    struct PublishedFixture {
        _temporary: TempDir,
        path: PathBuf,
        store: DirectOperationCustodyStore,
        prepared: DirectOperationBindingPreparedV3,
        head: DirectOperationCustodyHead,
    }

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    #[test]
    fn execution_authority_evidence_keeps_product_and_p0_userdebug_non_substitutable() {
        let product = DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
            product_descriptor_sha256: digest("authority-product-descriptor"),
            signed_product_measurement_sha256: digest("authority-signed-product"),
            avb_partition_digest_sha256: digest("authority-avb-partition"),
        };
        let conformance = DirectOperationExecutionAuthorityEvidenceV1::P0UserdebugConformance {
            build_variant: "userdebug".to_string(),
            product_manifest_sha256: digest("authority-product-manifest"),
            daemon_executable_sha256: digest("authority-daemon"),
            replay_sync_executable_sha256: digest("authority-replay-sync"),
        };

        product.validate().unwrap();
        conformance.validate().unwrap();
        assert_ne!(product, conformance);
        assert_ne!(
            serde_json::to_vec(&product).unwrap(),
            serde_json::to_vec(&conformance).unwrap()
        );

        let mut invalid = conformance;
        if let DirectOperationExecutionAuthorityEvidenceV1::P0UserdebugConformance {
            build_variant,
            ..
        } = &mut invalid
        {
            *build_variant = "user".to_string();
        }
        assert!(invalid.validate().is_err());
    }

    fn owner_uid() -> u32 {
        unsafe { libc::geteuid() }
    }

    fn owner_gid() -> u32 {
        unsafe { libc::getegid() }
    }

    fn private_tempdir() -> TempDir {
        let temporary = TempDir::new().unwrap();
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temporary
    }

    struct MockReplayChild {
        executable_sha256: String,
        executable_identity_sha256: String,
        executable_path: String,
        uid: u32,
        gid: u32,
        selinux_domain: String,
        cgroup_path: String,
    }

    struct MockReplayLaunchOps {
        exact: operation_replay_sync_launcher::ExactHelperConfirmation,
        calls: Vec<&'static str>,
        killed: bool,
        product_descriptor_override: Option<String>,
    }

    impl operation_replay_sync_launcher::OperationReplaySyncLaunchOps for MockReplayLaunchOps {
        type Child = MockReplayChild;

        fn verify_daemon_capabilities(
            &mut self,
        ) -> Result<operation_replay_sync_launcher::VerifiedDaemonCapabilityCustody> {
            self.calls.push("capabilities");
            Ok(
                operation_replay_sync_launcher::VerifiedDaemonCapabilityCustody {
                    effective: operation_replay_sync_launcher::RETAINED_AGENTD_CAPABILITY_MASK,
                    permitted: operation_replay_sync_launcher::RETAINED_AGENTD_CAPABILITY_MASK,
                    bounding: 0,
                    inheritable: 0,
                    ambient: 0,
                    securebits: operation_replay_sync_launcher::REQUIRED_AGENTD_SECUREBITS,
                },
            )
        }

        fn measure_fixed_executable(
            &mut self,
            spec: &operation_replay_sync_launcher::OperationReplaySyncLaunchSpec,
        ) -> Result<operation_replay_sync_launcher::MeasuredOperationReplaySyncExecutable> {
            self.calls.push("measure");
            Ok(
                operation_replay_sync_launcher::MeasuredOperationReplaySyncExecutable {
                    fixed_path: spec.executable_path.to_string(),
                    executable_sha256: digest("measured-replay-sync-executable"),
                    executable_file_identity_sha256: digest(
                        "measured-replay-sync-executable-inode",
                    ),
                    same_fd_for_execveat: true,
                    read_only_mount: true,
                    regular_single_link: true,
                    root_owned_nonwritable: true,
                    elf_image: true,
                    static_aarch64_elf64: true,
                    pt_interp_absent: true,
                    pt_dynamic_absent: true,
                    wx_segment_absent: true,
                    executable_stack_absent: true,
                    setid_bits_absent: true,
                    file_capabilities_absent: true,
                    expected_hash_authority_matched: true,
                    fsverity_measurement_matched: matches!(
                        spec.authority_evidence,
                        DirectOperationExecutionAuthorityEvidenceV1::SignedProduct { .. }
                    ),
                    authority_evidence: match &self.product_descriptor_override {
                        Some(product_descriptor_sha256) => match &spec.authority_evidence {
                            DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
                                signed_product_measurement_sha256,
                                avb_partition_digest_sha256,
                                ..
                            } => DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
                                product_descriptor_sha256: product_descriptor_sha256.clone(),
                                signed_product_measurement_sha256:
                                    signed_product_measurement_sha256.clone(),
                                avb_partition_digest_sha256: avb_partition_digest_sha256.clone(),
                            },
                            evidence => evidence.clone(),
                        },
                        None => spec.authority_evidence.clone(),
                    },
                    fsverity_digest_sha256: match spec.authority_evidence {
                        DirectOperationExecutionAuthorityEvidenceV1::SignedProduct { .. } => {
                            Some(digest("mock-fsverity-digest"))
                        }
                        DirectOperationExecutionAuthorityEvidenceV1::P0UserdebugConformance {
                            ..
                        } => None,
                    },
                },
            )
        }

        fn spawn_stopped(
            &mut self,
            spec: &operation_replay_sync_launcher::OperationReplaySyncLaunchSpec,
            executable: &operation_replay_sync_launcher::MeasuredOperationReplaySyncExecutable,
        ) -> Result<Self::Child> {
            self.calls.push("spawn");
            assert_eq!(sha256_bytes(&spec.command_frame), spec.command_frame_sha256);
            Ok(MockReplayChild {
                executable_sha256: executable.executable_sha256.clone(),
                executable_identity_sha256: executable.executable_file_identity_sha256.clone(),
                executable_path: spec.executable_path.to_string(),
                uid: spec.uid,
                gid: spec.gid,
                selinux_domain: spec.selinux_domain.to_string(),
                cgroup_path: spec.unified_cgroup_path.clone(),
            })
        }

        fn verify_post_exec(
            &mut self,
            child: &mut Self::Child,
        ) -> Result<operation_replay_sync_launcher::VerifiedOperationReplaySyncExec> {
            self.calls.push("verify");
            assert_eq!(
                child.executable_identity_sha256,
                digest("measured-replay-sync-executable-inode")
            );
            Ok(
                operation_replay_sync_launcher::VerifiedOperationReplaySyncExec {
                    pid: 4242,
                    start_time_ticks: 31337,
                    pidfd_identity_sha256: digest("mock-replay-sync-pidfd"),
                    cgroup_identity_sha256: digest("mock-replay-sync-cgroup"),
                    pidfd_returned_by_clone3: true,
                    clone_into_fixed_cgroup: true,
                    ptrace_exec_stop_observed: true,
                    start_time_stable_after_exec: true,
                    uid: child.uid,
                    gid: child.gid,
                    selinux_domain: child.selinux_domain.clone(),
                    unified_cgroup_path: child.cgroup_path.clone(),
                    executable_path: child.executable_path.clone(),
                    executable_sha256: child.executable_sha256.clone(),
                    command_fd3_only: true,
                    response_fd4_only: true,
                    other_fds_closed: true,
                    environment_empty: true,
                    arguments_empty: true,
                    pdeathsig_sigkill: true,
                    no_new_privs: true,
                    dumpable_disabled: true,
                    capabilities_empty: true,
                    descendants_forbidden: true,
                    tracer_parent_verified: true,
                },
            )
        }

        fn resume(&mut self, _child: &mut Self::Child) -> Result<()> {
            self.calls.push("resume");
            Ok(())
        }

        fn release_command(&mut self, _child: &mut Self::Child) -> Result<()> {
            self.calls.push("release");
            Ok(())
        }

        fn collect_exact_confirmation(
            &mut self,
            _child: &mut Self::Child,
            _spec: &operation_replay_sync_launcher::OperationReplaySyncLaunchSpec,
        ) -> Result<operation_replay_sync_launcher::ExactHelperConfirmation> {
            self.calls.push("collect");
            Ok(self.exact.clone())
        }

        fn verify_successful_exit_and_reap(&mut self, _child: &mut Self::Child) -> Result<()> {
            self.calls.push("exit");
            Ok(())
        }

        fn kill_and_reap(&mut self, _child: Self::Child) -> Result<()> {
            self.calls.push("kill");
            self.killed = true;
            Ok(())
        }
    }

    fn exact_replay_confirmation(
        prepared: &PreparedOperationReplaySyncLaunch,
    ) -> operation_replay_sync_launcher::ExactHelperConfirmation {
        #[cfg(feature = "p0-launch-package-device-conformance")]
        let confirmation = if let Some(authority) = &prepared.p0_sealed_authority {
            operation_replay_sync_launcher::ReplaySyncAckConfirmation::P0(
                DirectOperationP0ReplaySyncAckConfirmationV1 {
                    schema: P0_REPLAY_SYNC_ACK_CONFIRMATION_V1_SCHEMA.to_string(),
                    lane: P0_REPLAY_SYNC_ACK_CONFIRMATION_LANE.to_string(),
                    ack_intent_sha256: prepared.operation_replay_sync_ack_intent_sha256.clone(),
                    android_ack_echo_sha256: digest("mock-android-ack-echo"),
                    acknowledgement_sha256: prepared.inbox.acknowledgement_sha256.clone(),
                    authenticated_ack_chain_sha256: prepared
                        .inbox
                        .chain_step
                        .authenticated_ack_chain_sha256
                        .clone(),
                    compacted_ack_watermark: prepared
                        .inbox
                        .acknowledgement
                        .journal_evidence_snapshot
                        .last_journal_sequence,
                    post_compaction_journal_sha256: digest("mock-post-compaction-journal"),
                    journal_file_identity_sha256: digest("mock-journal-file-identity"),
                    daemon_custody_committed_head_sha256: authority
                        .committed_custody_head_sha256
                        .clone(),
                    daemon_high_water_observation_sha256: authority
                        .daemon_high_water_observation_sha256
                        .clone(),
                    daemon_binding_publication_identity_sha256: authority
                        .daemon_binding_publication_identity_sha256
                        .clone(),
                    sealed_authority_sha256: authority.sealed_authority_sha256.clone(),
                },
            )
        } else {
            operation_replay_sync_launcher::ReplaySyncAckConfirmation::Product(
                DirectOperationReplaySyncAckConfirmationV3 {
                    schema: OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA.to_string(),
                    ack_intent_sha256: prepared.operation_replay_sync_ack_intent_sha256.clone(),
                    android_ack_echo_sha256: digest("mock-android-ack-echo"),
                    acknowledgement_sha256: prepared.inbox.acknowledgement_sha256.clone(),
                    authenticated_ack_chain_sha256: prepared
                        .inbox
                        .chain_step
                        .authenticated_ack_chain_sha256
                        .clone(),
                    compacted_ack_watermark: prepared
                        .inbox
                        .acknowledgement
                        .journal_evidence_snapshot
                        .last_journal_sequence,
                    post_compaction_journal_sha256: digest("mock-post-compaction-journal"),
                    journal_file_identity_sha256: digest("mock-journal-file-identity"),
                    mutation_cas_committed_head_sha256: digest("mock-mutation-cas-head"),
                },
            )
        };
        #[cfg(not(feature = "p0-launch-package-device-conformance"))]
        let confirmation = operation_replay_sync_launcher::ReplaySyncAckConfirmation::Product(
            DirectOperationReplaySyncAckConfirmationV3 {
                schema: OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA.to_string(),
                ack_intent_sha256: prepared.operation_replay_sync_ack_intent_sha256.clone(),
                android_ack_echo_sha256: digest("mock-android-ack-echo"),
                acknowledgement_sha256: prepared.inbox.acknowledgement_sha256.clone(),
                authenticated_ack_chain_sha256: prepared
                    .inbox
                    .chain_step
                    .authenticated_ack_chain_sha256
                    .clone(),
                compacted_ack_watermark: prepared
                    .inbox
                    .acknowledgement
                    .journal_evidence_snapshot
                    .last_journal_sequence,
                post_compaction_journal_sha256: digest("mock-post-compaction-journal"),
                journal_file_identity_sha256: digest("mock-journal-file-identity"),
                mutation_cas_committed_head_sha256: digest("mock-mutation-cas-head"),
            },
        );
        operation_replay_sync_launcher::ExactHelperConfirmation {
            confirmation,
            response_frame_sha256: digest("mock-exact-response-frame"),
            exact_eof: true,
        }
    }

    fn prepared_fixture() -> DirectOperationBindingPreparedV3 {
        prepared_fixture_index(0)
    }

    fn prepared_fixture_index(index: usize) -> DirectOperationBindingPreparedV3 {
        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: format!("task-direct-custody-{index}"),
            provider_invocation_id_sha256: digest(&format!("provider-invocation-{index}")),
            provider_session_id_sha256: digest(&format!("provider-session-{index}")),
            subject_uid: 5901,
            subject_selinux_domain_sha256: digest("u:r:trillionnium_agent_codex:s0"),
        };
        let invocation_id = stable_seed.invocation_id().unwrap();
        let attempt = DirectOperationProviderAttempt::derive(
            digest("runtime-lifecycle-binding"),
            u64::try_from(index).unwrap() + 1,
            digest(&format!("daemon-attempt-context-{index}")),
        )
        .unwrap();
        let binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed,
            invocation_id,
            workflow_id_sha256: digest(&format!("workflow-{index}")),
            agent_identity_key_sha256: digest("agent-identity-key"),
            agent_executable_sha256: digest("agent-executable"),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt,
        };
        let binding_sha256 = binding.digest_sha256().unwrap();
        let binding_inbox = DirectOperationBindingInbox {
            schema: BINDING_INBOX_SCHEMA.to_string(),
            binding: binding.clone(),
            binding_sha256: binding_sha256.clone(),
        };
        DirectOperationBindingPreparedV3 {
            schema: BINDING_PREPARED_SCHEMA.to_string(),
            binding,
            binding_sha256,
            binding_inbox_bytes_sha256: binding_inbox_bytes_sha256(&binding_inbox).unwrap(),
            binding_inbox,
            egress_grant_id_sha256: digest("egress-grant-id"),
            egress_journal_binding_sha256: digest("egress-journal-binding"),
            allocation_egress_cas_sha256: digest("allocation-egress-cas"),
        }
    }

    fn prepared_from_binding(binding: DirectOperationBinding) -> DirectOperationBindingPreparedV3 {
        let binding_sha256 = binding.digest_sha256().unwrap();
        let binding_inbox = DirectOperationBindingInbox {
            schema: BINDING_INBOX_SCHEMA.to_string(),
            binding: binding.clone(),
            binding_sha256: binding_sha256.clone(),
        };
        DirectOperationBindingPreparedV3 {
            schema: BINDING_PREPARED_SCHEMA.to_string(),
            binding,
            binding_sha256,
            binding_inbox_bytes_sha256: binding_inbox_bytes_sha256(&binding_inbox).unwrap(),
            binding_inbox,
            egress_grant_id_sha256: digest("cross-store-egress-grant"),
            egress_journal_binding_sha256: digest("cross-store-egress-journal-binding"),
            allocation_egress_cas_sha256: digest("cross-store-allocation-egress-cas"),
        }
    }

    fn future_dual_prepared_fixture() -> DirectOperationBindingPreparedV3 {
        let mut binding = prepared_fixture().binding;
        binding.authorized_adapter_set = trillionnium_os_types::direct_operation::
            DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility();
        prepared_from_binding(binding)
    }

    fn leaf(
        prepared: &DirectOperationBindingPreparedV3,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationBindingLeafPublicationProofV3 {
        DirectOperationBindingLeafPublicationProofV3 {
            schema: BINDING_LEAF_PUBLICATION_SCHEMA.to_string(),
            adapter,
            authorized_adapter_set_sha256: prepared
                .binding
                .authorized_adapter_set
                .digest_sha256()
                .unwrap(),
            binding_sha256: prepared.binding_sha256.clone(),
            binding_inbox_bytes_sha256: prepared.binding_inbox_bytes_sha256.clone(),
            parent_directory_identity_sha256: digest(&format!(
                "{}-parent-directory",
                adapter.adapter_id()
            )),
            published_file_identity_sha256: digest(&format!(
                "{}-published-file",
                adapter.adapter_id()
            )),
            published_bytes_sha256: prepared.binding_inbox_bytes_sha256.clone(),
            parent_directory_fsync_proof_sha256: digest(&format!(
                "{}-parent-fsync",
                adapter.adapter_id()
            )),
        }
    }

    fn publication_fixture(
        prepared: &DirectOperationBindingPreparedV3,
    ) -> DirectOperationBindingPublicationProofV3 {
        let leaves = prepared
            .binding
            .authorized_adapter_set
            .authorized_adapters
            .iter()
            .copied()
            .map(|adapter| leaf(prepared, adapter))
            .collect::<Vec<_>>();
        DirectOperationBindingPublicationProofV3 {
            schema: BINDING_PUBLICATION_SCHEMA.to_string(),
            authorized_adapter_set_sha256: prepared
                .binding
                .authorized_adapter_set
                .digest_sha256()
                .unwrap(),
            binding_sha256: prepared.binding_sha256.clone(),
            binding_inbox_bytes_sha256: prepared.binding_inbox_bytes_sha256.clone(),
            leaves_sha256: domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &leaves).unwrap(),
            leaves,
        }
    }

    fn terminal_fixture(
        prepared: &DirectOperationBindingPreparedV3,
    ) -> DirectOperationTerminalEgressProofV1 {
        let mut proof = DirectOperationTerminalEgressProofV1 {
            schema: TERMINAL_EGRESS_PROOF_SCHEMA.to_string(),
            binding_sha256: prepared.binding_sha256.clone(),
            invocation_id: prepared.binding.invocation_id.clone(),
            delivery_provider_attempt_id: prepared
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            egress_grant_id_sha256: prepared.egress_grant_id_sha256.clone(),
            egress_journal_binding_sha256: prepared.egress_journal_binding_sha256.clone(),
            terminal_state: TerminalEgressState::Completed,
            final_record_sha256: digest("terminal-final-record"),
            predecessor_record_sha256: digest("terminal-predecessor-record"),
            runtime_evidence_sha256: digest("terminal-runtime-evidence"),
            provider_teardown_completion_ack_sha256: digest("terminal-completion-ack"),
            terminal_egress_cas_sha256: String::new(),
        };
        proof.terminal_egress_cas_sha256 = proof.expected_terminal_digest().unwrap();
        proof
    }

    fn direct_ui_fixture(
        prepared: &DirectOperationBindingPreparedV3,
    ) -> DirectOperationDirectUiProofV1 {
        DirectOperationDirectUiProofV1 {
            schema: DIRECT_UI_PROOF_SCHEMA.to_string(),
            binding_sha256: prepared.binding_sha256.clone(),
            invocation_id: prepared.binding.invocation_id.clone(),
            delivery_provider_attempt_id: prepared
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            direct_execution_receipt_sha256: digest("direct-execution-receipt"),
            direct_result_semantic_sha256: digest("direct-result-semantic"),
            ui_replay_completion_proof_sha256: digest("ui-replay-completion-proof"),
            ui_replay_semantic_sha256: digest("ui-replay-semantic"),
        }
    }

    fn snapshot_fixture(
        prepared: &DirectOperationBindingPreparedV3,
        adapter: DirectOperationAdapter,
    ) -> DirectOperationJournalEvidenceSnapshotV1 {
        let evidence = vec![DirectOperationOuterEvidence {
            allocating_provider_attempt_id: prepared
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            adapter_effect_ordinal: 0,
            journal_sequence: 1,
            tool: adapter.tool_name().to_string(),
            canonical_request_sha256: digest(&format!(
                "{}-canonical-request",
                adapter.adapter_id()
            )),
            backend_request_id_sha256: digest(&format!("{}-backend-request", adapter.adapter_id())),
            backend_result_sha256: digest(&format!("{}-backend-result", adapter.adapter_id())),
            outcome: DirectOperationOuterOutcome::Success,
            backend_error_code: None,
        }];
        let mut snapshot = DirectOperationJournalEvidenceSnapshotV1 {
            schema: JOURNAL_EVIDENCE_SNAPSHOT_V1_SCHEMA.to_string(),
            allocation_binding_sha256: prepared.binding_sha256.clone(),
            invocation_id: prepared.binding.invocation_id.clone(),
            provider_id: prepared.binding.stable_seed.provider_id.clone(),
            agent_id: prepared.binding.stable_seed.agent_id.clone(),
            allocating_provider_attempt_id: prepared
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            adapter,
            journal_epoch: match adapter {
                DirectOperationAdapter::SystemApi => "11".repeat(16),
                DirectOperationAdapter::Accessibility => "22".repeat(16),
            },
            journal_payload_sha256: digest(&format!("{}-journal", adapter.adapter_id())),
            previous_ack_watermark: 0,
            previous_ack_chain_sha256: ZERO_SHA256.to_string(),
            journal_allocation_count: 1,
            journal_evidence_count: 1,
            first_journal_sequence: 1,
            last_journal_sequence: 1,
            evidence,
            evidence_sha256: String::new(),
        };
        snapshot.evidence_sha256 = snapshot.evidence_digest_sha256().unwrap();
        snapshot.validate().unwrap();
        snapshot
    }

    fn terminal_disposition(
        prepared: &DirectOperationBindingPreparedV3,
        adapter: DirectOperationAdapter,
        state: DirectOperationAdapterTerminalStateV1,
    ) -> DirectOperationAdapterTerminalDispositionV1 {
        let disposition = DirectOperationAdapterTerminalDispositionV1 {
            schema: ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA.to_string(),
            binding_sha256: prepared.binding_sha256.clone(),
            invocation_id: prepared.binding.invocation_id.clone(),
            delivery_provider_attempt_id: prepared
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            provider_id: prepared.binding.stable_seed.provider_id.clone(),
            agent_id: prepared.binding.stable_seed.agent_id.clone(),
            adapter,
            terminal_state: state,
        };
        disposition
            .validate_for_binding(&prepared.binding, adapter)
            .unwrap();
        disposition
    }

    fn ackable(
        prepared: &DirectOperationBindingPreparedV3,
        adapter: DirectOperationAdapter,
    ) -> VerifiedAdapterDisposition {
        verified_disposition(terminal_disposition(
            prepared,
            adapter,
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot: snapshot_fixture(prepared, adapter),
            },
        ))
    }

    fn no_operations(
        prepared: &DirectOperationBindingPreparedV3,
        adapter: DirectOperationAdapter,
    ) -> VerifiedAdapterDisposition {
        verified_disposition(terminal_disposition(
            prepared,
            adapter,
            DirectOperationAdapterTerminalStateV1::NoOperations {
                journal_epoch: "33".repeat(16),
                journal_payload_sha256: digest("no-operations-journal"),
                previous_ack_watermark: 0,
                previous_ack_chain_sha256: ZERO_SHA256.to_string(),
                authenticated_terminal_sha256: digest("authenticated-no-operations"),
            },
        ))
    }

    fn held(
        prepared: &DirectOperationBindingPreparedV3,
        adapter: DirectOperationAdapter,
    ) -> VerifiedAdapterDisposition {
        verified_disposition(terminal_disposition(
            prepared,
            adapter,
            DirectOperationAdapterTerminalStateV1::HeldIndeterminate {
                journal_epoch: "44".repeat(16),
                journal_payload_sha256: digest("held-journal"),
                previous_ack_watermark: 0,
                previous_ack_chain_sha256: ZERO_SHA256.to_string(),
                authenticated_hold_sha256: digest("authenticated-held"),
            },
        ))
    }

    fn verified_disposition(
        disposition: DirectOperationAdapterTerminalDispositionV1,
    ) -> VerifiedAdapterDisposition {
        VerifiedAdapterDisposition(AuthenticatedAdapterDisposition {
            adapter: disposition.adapter,
            disposition: AdapterDispositionCustody::Authenticated {
                authentication_capability_sha256: digest(&format!(
                    "{}-root-authentication-capability",
                    disposition.adapter.adapter_id()
                )),
                terminal_disposition: Box::new(disposition),
            },
        })
    }

    fn published_fixture_for_prepared(
        prepared: DirectOperationBindingPreparedV3,
    ) -> PublishedFixture {
        let temporary = private_tempdir();
        let path = temporary.path().join("private").join("custody.json");
        let mut store = DirectOperationCustodyStore::open_for_test(&path, owner_uid()).unwrap();
        let head = store
            .prepare_binding(&store.head(), prepared.clone())
            .unwrap();
        let predecessor_record_sha256 = store.file.records[0].digest_sha256().unwrap();
        let head = store
            .publish_binding(
                &head,
                &prepared.binding_sha256,
                publication_fixture(&prepared),
            )
            .unwrap();
        assert_eq!(store.file.records[0].revision, 2);
        assert_eq!(
            store.file.records[0].predecessor_record_sha256,
            predecessor_record_sha256
        );
        PublishedFixture {
            _temporary: temporary,
            path,
            store,
            prepared,
            head,
        }
    }

    fn published_fixture() -> PublishedFixture {
        published_fixture_for_prepared(prepared_fixture())
    }

    fn attach_result_proofs(fixture: &mut PublishedFixture) {
        fixture.head = fixture
            .store
            .attach_terminal_egress(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                VerifiedTerminalEgressProof::for_test(terminal_fixture(&fixture.prepared)),
            )
            .unwrap();
        fixture.head = fixture
            .store
            .attach_direct_ui(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                VerifiedDirectUiProof::for_test(direct_ui_fixture(&fixture.prepared)),
            )
            .unwrap();
    }

    fn receipt_ready_fixture_for_prepared(
        prepared: DirectOperationBindingPreparedV3,
        ackable_adapters: &[DirectOperationAdapter],
    ) -> PublishedFixture {
        let mut fixture = published_fixture_for_prepared(prepared);
        attach_result_proofs(&mut fixture);
        let authorized_adapters = fixture
            .prepared
            .binding
            .authorized_adapter_set
            .authorized_adapters
            .clone();
        for adapter in authorized_adapters {
            let disposition = if ackable_adapters.contains(&adapter) {
                ackable(&fixture.prepared, adapter)
            } else {
                held(&fixture.prepared, adapter)
            };
            fixture.head = fixture
                .store
                .attach_authenticated_adapter_disposition(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    disposition,
                )
                .unwrap();
        }
        fixture.head = fixture
            .store
            .freeze_outer_receipt(&fixture.head, &fixture.prepared.binding_sha256)
            .unwrap();
        fixture
    }

    fn receipt_ready_fixture(ackable_adapters: &[DirectOperationAdapter]) -> PublishedFixture {
        receipt_ready_fixture_for_prepared(prepared_fixture(), ackable_adapters)
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    fn p0_recovery_delivery_fixture() -> (PublishedFixture, DirectOperationBindingPreparedV3) {
        let allocation = prepared_fixture();
        let mut delivery_binding = allocation.binding.clone();
        delivery_binding.attempt = DirectOperationProviderAttempt::derive(
            digest("p0-recovery-delivery-runtime-lifecycle"),
            2,
            digest("p0-recovery-delivery-attempt-context"),
        )
        .unwrap();
        let delivery = prepared_from_binding(delivery_binding);

        let temporary = private_tempdir();
        let path = temporary.path().join("p0-private").join("custody.json");
        let mut store = DirectOperationCustodyStore::open_for_test(&path, owner_uid()).unwrap();
        let head = store
            .prepare_binding(&store.head(), delivery.clone())
            .unwrap();
        let head = store
            .publish_binding(
                &head,
                &delivery.binding_sha256,
                publication_fixture(&delivery),
            )
            .unwrap();
        let mut fixture = PublishedFixture {
            _temporary: temporary,
            path,
            store,
            prepared: delivery,
            head,
        };
        attach_result_proofs(&mut fixture);

        let system_api = terminal_disposition(
            &fixture.prepared,
            DirectOperationAdapter::SystemApi,
            DirectOperationAdapterTerminalStateV1::Ackable {
                journal_evidence_snapshot: snapshot_fixture(
                    &allocation,
                    DirectOperationAdapter::SystemApi,
                ),
            },
        );
        fixture.head = fixture
            .store
            .attach_authenticated_adapter_disposition(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                verified_disposition(system_api),
            )
            .unwrap();
        fixture.head = fixture
            .store
            .freeze_outer_receipt(&fixture.head, &fixture.prepared.binding_sha256)
            .unwrap();
        (fixture, allocation)
    }

    fn ack_intent_fixture(adapter: DirectOperationAdapter) -> PublishedFixture {
        assert_eq!(adapter, DirectOperationAdapter::SystemApi);
        let mut fixture = receipt_ready_fixture(&[adapter]);
        fixture.head = fixture
            .store
            .prepare_ack_intent(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        fixture
    }

    fn future_dual_ack_intent_fixture(adapter: DirectOperationAdapter) -> PublishedFixture {
        let mut fixture =
            receipt_ready_fixture_for_prepared(future_dual_prepared_fixture(), &[adapter]);
        fixture.head = fixture
            .store
            .prepare_ack_intent(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        fixture
    }

    fn dual_ack_intent_fixture() -> PublishedFixture {
        let mut fixture = receipt_ready_fixture_for_prepared(
            future_dual_prepared_fixture(),
            &[
                DirectOperationAdapter::SystemApi,
                DirectOperationAdapter::Accessibility,
            ],
        );
        for adapter in [
            DirectOperationAdapter::SystemApi,
            DirectOperationAdapter::Accessibility,
        ] {
            fixture.head = fixture
                .store
                .prepare_ack_intent(&fixture.head, &fixture.prepared.binding_sha256, adapter)
                .unwrap();
        }
        fixture
    }

    fn ack_publication_fixture(
        prepared: &DirectOperationBindingPreparedV3,
        intent: &DirectOperationAdapterAckIntentV3,
    ) -> DirectOperationOuterAckInboxPublicationProofV3 {
        let acknowledgement = &intent.inbox.acknowledgement;
        let mut canonical_inbox_bytes = serde_json::to_vec(&intent.inbox).unwrap();
        canonical_inbox_bytes.push(b'\n');
        DirectOperationOuterAckInboxPublicationProofV3 {
            schema: ACK_INBOX_PUBLICATION_PROOF_SCHEMA.to_string(),
            adapter: intent.adapter,
            binding_sha256: prepared.binding_sha256.clone(),
            ack_intent_sha256: intent.digest_sha256().unwrap(),
            journal_epoch: acknowledgement
                .journal_evidence_snapshot
                .journal_epoch
                .clone(),
            last_journal_sequence: acknowledgement
                .journal_evidence_snapshot
                .last_journal_sequence,
            acknowledgement_sha256: intent.inbox.acknowledgement_sha256.clone(),
            ack_chain_step_sha256: intent.inbox.chain_step_sha256.clone(),
            authenticated_ack_chain_sha256: intent
                .inbox
                .chain_step
                .authenticated_ack_chain_sha256
                .clone(),
            canonical_inbox_bytes_sha256: sha256_bytes(&canonical_inbox_bytes),
            publisher_provenance: DirectOperationOuterAckPublisherProvenanceV3 {
                schema: ACK_PUBLISHER_PROVENANCE_SCHEMA.to_string(),
                authority_evidence: DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
                    product_descriptor_sha256: digest("fixture-publisher-product-descriptor"),
                    signed_product_measurement_sha256: digest("fixture-publisher-signed-product"),
                    avb_partition_digest_sha256: digest("fixture-publisher-avb-partition"),
                },
                fsverity_root_digest_sha256: Some(digest("fixture-publisher-fsverity-root")),
                parent_filesystem_identity_sha256: digest("fixture-publisher-filesystem"),
                parent_selinux_context_sha256: digest("fixture-publisher-selinux"),
            },
            publication_custody_source_sha256: digest(&format!(
                "{}-ack-inbox-publication-custody",
                intent.adapter.adapter_id()
            )),
            external_state_reconciled: false,
        }
    }

    fn android_ack_confirmation_fixture(
        prepared: &DirectOperationBindingPreparedV3,
        intent: &DirectOperationAdapterAckIntentV3,
    ) -> DirectOperationAndroidBackendAckConfirmationProofV3 {
        android_ack_confirmation_fixture_for_launch(
            prepared,
            intent,
            &digest(&format!("{}-test-launch-id", intent.adapter.adapter_id())),
            &digest(&format!(
                "{}-test-launch-challenge",
                intent.adapter.adapter_id()
            )),
        )
    }

    fn android_ack_confirmation_fixture_for_launch(
        prepared: &DirectOperationBindingPreparedV3,
        intent: &DirectOperationAdapterAckIntentV3,
        launch_id_sha256: &str,
        launch_challenge_sha256: &str,
    ) -> DirectOperationAndroidBackendAckConfirmationProofV3 {
        let acknowledgement = &intent.inbox.acknowledgement;
        let launch_receipt = DirectOperationReplaySyncLaunchReceiptV3 {
            schema: REPLAY_SYNC_LAUNCH_RECEIPT_SCHEMA.to_string(),
            adapter: intent.adapter,
            binding_sha256: prepared.binding_sha256.clone(),
            launch_id_sha256: launch_id_sha256.to_string(),
            launch_challenge_sha256: launch_challenge_sha256.to_string(),
            operation_replay_sync_ack_intent_sha256: intent
                .inbox
                .operation_replay_sync_ack_intent_sha256()
                .unwrap(),
            authority_evidence: DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
                product_descriptor_sha256: digest("fixture-publisher-product-descriptor"),
                signed_product_measurement_sha256: digest("fixture-publisher-signed-product"),
                avb_partition_digest_sha256: digest("fixture-publisher-avb-partition"),
            },
            fsverity_digest_sha256: Some(digest("fixture-fsverity")),
            executable_sha256: digest("fixture-executable"),
            executable_file_identity_sha256: digest("fixture-executable-identity"),
            executable_static_aarch64_elf64: true,
            pid: 4242,
            start_time_ticks: 31337,
            pidfd_identity_sha256: digest("fixture-pidfd"),
            cgroup_identity_sha256: digest("fixture-cgroup"),
            uid: 5901,
            gid: 5901,
            selinux_domain: "u:r:trillionnium_system_api_operation_replay_sync:s0".to_string(),
            command_frame_sha256: digest("fixture-command"),
            response_frame_sha256: digest("fixture-response"),
            confirmation_sha256: digest("fixture-confirmation"),
            tracer_parent_verified: true,
            pdeathsig_sigkill_verified: true,
            exact_process_surface_verified: true,
        };
        let launch_receipt_sha256 = launch_receipt.digest_sha256().unwrap();
        DirectOperationAndroidBackendAckConfirmationProofV3 {
            schema: ANDROID_BACKEND_ACK_CONFIRMATION_PROOF_SCHEMA.to_string(),
            adapter: intent.adapter,
            binding_sha256: prepared.binding_sha256.clone(),
            ack_intent_sha256: intent.digest_sha256().unwrap(),
            journal_epoch: acknowledgement
                .journal_evidence_snapshot
                .journal_epoch
                .clone(),
            last_journal_sequence: acknowledgement
                .journal_evidence_snapshot
                .last_journal_sequence,
            acknowledgement_sha256: intent.inbox.acknowledgement_sha256.clone(),
            ack_chain_step_sha256: intent.inbox.chain_step_sha256.clone(),
            authenticated_ack_chain_sha256: intent
                .inbox
                .chain_step
                .authenticated_ack_chain_sha256
                .clone(),
            launch_id_sha256: launch_id_sha256.to_string(),
            launch_receipt,
            launch_receipt_sha256: launch_receipt_sha256.clone(),
            android_confirmation_source_sha256: launch_receipt_sha256,
        }
    }

    fn adapter_ack_progress(
        fixture: &PublishedFixture,
        adapter: DirectOperationAdapter,
    ) -> &DirectOperationAdapterAckProgressV3 {
        fixture.store.file.records[0]
            .adapter_ack_progress
            .iter()
            .find(|progress| progress.adapter == adapter)
            .unwrap()
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_binding_publication_binds_distinct_allocation_and_delivery_preimages() {
        let (mut fixture, allocation) = p0_recovery_delivery_fixture();
        assert_ne!(
            fixture
                .prepared
                .binding
                .attempt
                .delivery_provider_attempt_id,
            allocation.binding.attempt.delivery_provider_attempt_id
        );

        let verified = fixture
            .store
            .verify_p0_binding_publication(
                &fixture.head,
                fixture.prepared.binding.clone(),
                allocation.binding.clone(),
            )
            .unwrap();
        assert_eq!(verified.delivery_binding(), &fixture.prepared.binding);
        assert_eq!(verified.allocation_binding(), &allocation.binding);
        assert_eq!(verified.committed_head(), &fixture.head);
        assert!(valid_nonzero_sha256(verified.binding_publication_sha256()));
        assert_eq!(
            verified.binding_inbox_bytes_sha256(),
            fixture.prepared.binding_inbox_bytes_sha256
        );
        verified
            .outer_receipt()
            .validate_for_binding(verified.delivery_binding())
            .unwrap();
        let system_snapshot = verified
            .outer_receipt()
            .adapter_terminal_dispositions
            .iter()
            .find(|item| item.adapter == DirectOperationAdapter::SystemApi)
            .unwrap()
            .ackable_snapshot()
            .unwrap();
        system_snapshot
            .validate_for_allocation_binding(
                verified.allocation_binding(),
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();

        let mut wrong_allocation = allocation.binding.clone();
        wrong_allocation.attempt = DirectOperationProviderAttempt::derive(
            digest("p0-wrong-allocation-runtime-lifecycle"),
            3,
            digest("p0-wrong-allocation-attempt-context"),
        )
        .unwrap();
        assert!(
            fixture
                .store
                .verify_p0_binding_publication(
                    &fixture.head,
                    fixture.prepared.binding.clone(),
                    wrong_allocation,
                )
                .is_err()
        );

        let publication_proof = fixture.store.file.records[0].publication.clone().unwrap();
        fixture.store.file.records[0]
            .publication
            .as_mut()
            .unwrap()
            .leaves[0]
            .published_bytes_sha256 = digest("tampered-published-bytes");
        assert!(
            fixture
                .store
                .verify_p0_binding_publication(
                    &fixture.head,
                    fixture.prepared.binding.clone(),
                    allocation.binding.clone(),
                )
                .is_err()
        );
        fixture.store.file.records[0].publication = Some(publication_proof);

        let frozen_receipt = fixture.store.file.records[0].outer_receipt.take().unwrap();
        assert!(
            fixture
                .store
                .verify_p0_binding_publication(
                    &fixture.head,
                    fixture.prepared.binding.clone(),
                    allocation.binding.clone(),
                )
                .is_err()
        );
        fixture.store.file.records[0].outer_receipt = Some(frozen_receipt.clone());
        let verified_after_restore = fixture
            .store
            .verify_p0_binding_publication(
                &fixture.head,
                fixture.prepared.binding.clone(),
                allocation.binding,
            )
            .unwrap();
        assert_eq!(verified_after_restore.outer_receipt(), &frozen_receipt);
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_constructor_rejects_the_reserved_future_dual_adapter_profile() {
        let allocation = future_dual_prepared_fixture().binding;
        let mut delivery = allocation.clone();
        delivery.attempt = DirectOperationProviderAttempt::derive(
            digest("future-dual-delivery-runtime-lifecycle"),
            2,
            digest("future-dual-delivery-attempt-context"),
        )
        .unwrap();
        assert!(
            validate_p0_delivery_allocation_bindings(&delivery, &allocation)
                .unwrap_err()
                .to_string()
                .contains("authorized")
        );

        let fixture = receipt_ready_fixture_for_prepared(
            prepared_from_binding(delivery.clone()),
            &[DirectOperationAdapter::SystemApi],
        );
        assert!(
            fixture
                .store
                .verify_p0_binding_publication(&fixture.head, delivery, allocation,)
                .is_err()
        );
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_binding_publication_guard_drives_daemon_sealed_ack_closure_without_product_authority() {
        let (mut fixture, allocation) = p0_recovery_delivery_fixture();
        fixture.head = fixture
            .store
            .prepare_ack_intent(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();
        let verified = fixture
            .store
            .verify_p0_binding_publication(
                &fixture.head,
                fixture.prepared.binding.clone(),
                allocation.binding,
            )
            .unwrap();

        let publication_root = fixture._temporary.path().join("p0-guarded-outer-ack");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root,
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        let p0_userdebug_authority =
            DirectOperationExecutionAuthorityEvidenceV1::P0UserdebugConformance {
                build_variant: "userdebug".to_string(),
                product_manifest_sha256: digest("p0-userdebug-product-manifest"),
                daemon_executable_sha256: digest("p0-userdebug-daemon"),
                replay_sync_executable_sha256: digest("measured-replay-sync-executable"),
            };
        publisher.use_test_authority_evidence(p0_userdebug_authority.clone());

        let prepared_publication = fixture
            .store
            .prepare_p0_outer_ack_publication(verified)
            .unwrap();
        assert_eq!(
            prepared_publication.capability().adapter,
            DirectOperationAdapter::SystemApi
        );
        let published = publisher.publish_p0(prepared_publication).unwrap();
        let verified = fixture
            .store
            .record_p0_outer_ack_inbox_publication(published)
            .unwrap();
        fixture.head = verified.committed_head().clone();

        // The real P0 hotpath enters with the daemon's already-verified
        // high-water session. This test fixture starts from an arbitrary
        // private path, so attach the equivalent test-only session at the
        // exact current head before preparing the measured replay launch.
        let high_water_authority =
            TestDirectOperationCustodyHighWaterAuthority::new(fixture.head.clone());
        fixture.store.product_high_water_required = true;
        fixture.store.high_water =
            Some(high_water_authority.connect(fixture.head.clone()).unwrap());
        fixture.store.ensure_live_high_water().unwrap();

        let prepared_launch = fixture
            .store
            .prepare_p0_operation_replay_sync_launch(verified)
            .unwrap();
        fixture.head = prepared_launch.capability().custody_head.clone();
        let prepared = prepared_launch.capability();
        let product_lane_substitution = operation_replay_sync_launcher::ExactHelperConfirmation {
            confirmation: operation_replay_sync_launcher::ReplaySyncAckConfirmation::Product(
                DirectOperationReplaySyncAckConfirmationV3 {
                    schema: OPERATION_REPLAY_SYNC_ACK_CONFIRMATION_V3_SCHEMA.to_string(),
                    ack_intent_sha256: prepared.operation_replay_sync_ack_intent_sha256.clone(),
                    android_ack_echo_sha256: digest("wrong-product-lane-android-echo"),
                    acknowledgement_sha256: prepared.inbox.acknowledgement_sha256.clone(),
                    authenticated_ack_chain_sha256: prepared
                        .inbox
                        .chain_step
                        .authenticated_ack_chain_sha256
                        .clone(),
                    compacted_ack_watermark: prepared
                        .inbox
                        .acknowledgement
                        .journal_evidence_snapshot
                        .last_journal_sequence,
                    post_compaction_journal_sha256: digest("wrong-product-lane-post-compaction"),
                    journal_file_identity_sha256: digest("wrong-product-lane-journal-identity"),
                    mutation_cas_committed_head_sha256: digest("wrong-product-lane-mutation-cas"),
                },
            ),
            response_frame_sha256: digest("wrong-product-lane-response-frame"),
            exact_eof: true,
        };
        assert!(
            operation_replay_sync_launcher::validate_confirmation(
                prepared,
                &product_lane_substitution,
            )
            .unwrap_err()
            .to_string()
            .contains("confirmation_lane_substitution_denied")
        );
        let exact = exact_replay_confirmation(prepared_launch.capability());
        let mut ops = MockReplayLaunchOps {
            exact,
            calls: Vec::new(),
            killed: false,
            product_descriptor_override: None,
        };
        let completed =
            operation_replay_sync_launcher::launch_p0_with_ops(prepared_launch, &mut ops).unwrap();
        let verified = fixture
            .store
            .record_p0_android_backend_ack_confirmation(completed)
            .unwrap();
        fixture.head = verified.committed_head().clone();

        let prepared_retirement = fixture
            .store
            .prepare_p0_outer_ack_retirement(verified)
            .unwrap();
        let retired = publisher.retire_p0(prepared_retirement).unwrap();
        let verified = fixture
            .store
            .record_p0_outer_ack_retirement(retired)
            .unwrap();
        fixture.head = verified.committed_head().clone();

        fixture
            .store
            .validate_current_p0_binding_publication(&verified)
            .unwrap();
        let progress = adapter_ack_progress(&fixture, DirectOperationAdapter::SystemApi);
        assert!(progress.completed);
        assert_eq!(
            progress
                .outer_ack_inbox_publication
                .as_ref()
                .unwrap()
                .publisher_provenance
                .authority_evidence,
            p0_userdebug_authority
        );
        assert_eq!(
            progress
                .android_backend_ack_confirmation
                .as_ref()
                .unwrap()
                .launch_receipt
                .authority_evidence,
            p0_userdebug_authority
        );
        assert!(progress.android_backend_ack_confirmation.is_some());
        assert!(
            progress
                .outer_ack_retirement
                .as_ref()
                .is_some_and(|proof| proof.external_state_reconciled)
        );
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_binding_publication_guard_rejects_same_bytes_from_another_store() {
        let (mut source, allocation) = p0_recovery_delivery_fixture();
        source.head = source
            .store
            .prepare_ack_intent(
                &source.head,
                &source.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();
        let verified = source
            .store
            .verify_p0_binding_publication(
                &source.head,
                source.prepared.binding.clone(),
                allocation.binding,
            )
            .unwrap();

        let (mut other, _) = p0_recovery_delivery_fixture();
        other.head = other
            .store
            .prepare_ack_intent(
                &other.head,
                &other.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();
        assert_eq!(source.head, other.head, "fixture bytes must be identical");
        let error = other
            .store
            .prepare_p0_outer_ack_publication(verified)
            .err()
            .unwrap();
        assert!(error.to_string().contains("guarded_store_identity_drift"));
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p0_binding_publication_guard_rejects_destination_rebind_and_stale_head() {
        let (mut rebound, allocation) = p0_recovery_delivery_fixture();
        rebound.head = rebound
            .store
            .prepare_ack_intent(
                &rebound.head,
                &rebound.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();
        let verified = rebound
            .store
            .verify_p0_binding_publication(
                &rebound.head,
                rebound.prepared.binding.clone(),
                allocation.binding,
            )
            .unwrap();
        rebound.store.destination_name = CString::new("rebound-custody.json").unwrap();
        let error = rebound
            .store
            .prepare_p0_outer_ack_publication(verified)
            .err()
            .unwrap();
        assert!(error.to_string().contains("guarded_store_identity_drift"));

        let (mut stale, allocation) = p0_recovery_delivery_fixture();
        let verified = stale
            .store
            .verify_p0_binding_publication(
                &stale.head,
                stale.prepared.binding.clone(),
                allocation.binding,
            )
            .unwrap();
        stale.head = stale
            .store
            .prepare_ack_intent(
                &stale.head,
                &stale.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();
        let error = stale
            .store
            .prepare_p0_outer_ack_publication(verified)
            .err()
            .unwrap();
        assert!(error.to_string().contains("predecessor_cas_mismatch"));
    }

    #[test]
    fn sealed_ui_snapshot_cross_store_exact_retry_missing_and_binding_drift() {
        let temporary = private_tempdir();
        let context = ContextMemoryService::open(temporary.path().join("context-state")).unwrap();
        let owner = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let request_id = "custody-cross-store-direct-ui";
        let payload = json!({
            "provider": "openai-codex",
            "workflow_id": "workflow-cross-store-direct-ui",
            "egress_grant_id": format!("egress-{}", "c".repeat(64)),
        });
        let direct_execution_receipt_sha256 = digest("cross-store-direct-receipt");
        let exact_response = json!({
            "execution_mode": "agent_direct",
            "action": "agent_direct_result",
            "summary": "sensitive provider summary",
            "direct_execution_receipt_sha256": direct_execution_receipt_sha256,
        });
        context
            .run_ui_request("plan", request_id, &owner, &payload, || {
                Ok(exact_response.clone())
            })
            .unwrap();
        let request_payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload).unwrap());
        let completion_proof = context
            .ui_request_completion_proof_exact(
                "plan",
                request_id,
                owner.uid,
                &owner.selinux_domain,
                &request_payload_sha256,
            )
            .unwrap()
            .unwrap();
        let workflow_binding = PlanRecoveryBinding {
            method: "plan".to_string(),
            request_id: request_id.to_string(),
            request_payload_sha256,
            subject_uid: owner.uid,
            subject_selinux_domain: owner.selinux_domain.clone(),
            provider_id: "openai-codex".to_string(),
            task_id: "task-cross-store-direct-ui".to_string(),
            plan_id: String::new(),
            action_id: String::new(),
            tool_call_id: String::new(),
            accepted_plan_sha256: String::new(),
            challenge_sha256: String::new(),
            challenge_expires_at_ms: 0,
        };
        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: workflow_binding.provider_id.clone(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: workflow_binding.task_id.clone(),
            provider_invocation_id_sha256: sha256_bytes(request_id.as_bytes()),
            provider_session_id_sha256: digest("cross-store-provider-session"),
            subject_uid: owner.uid,
            subject_selinux_domain_sha256: sha256_bytes(owner.selinux_domain.as_bytes()),
        };
        let direct_binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            invocation_id: stable_seed.invocation_id().unwrap(),
            stable_seed,
            workflow_id_sha256: digest("cross-store-workflow"),
            agent_identity_key_sha256: digest("cross-store-agent-identity"),
            agent_executable_sha256: digest("cross-store-agent-executable"),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                digest("cross-store-runtime-lifecycle"),
                1,
                digest("cross-store-attempt-context"),
            )
            .unwrap(),
        };
        let candidate = DirectPlanCustodyCandidate::for_test(
            direct_binding.clone(),
            workflow_binding,
            digest("cross-store-action-record"),
            exact_response,
            Some(completion_proof.digest_sha256().unwrap()),
        )
        .unwrap();
        let snapshot = context
            .verified_direct_ui_replay_snapshot(&candidate)
            .unwrap();

        let prepared = prepared_from_binding(direct_binding.clone());
        let path = temporary.path().join("custody").join("ui.json");
        let mut store = DirectOperationCustodyStore::open_for_test(&path, owner_uid()).unwrap();
        let head = store
            .prepare_binding(&store.head(), prepared.clone())
            .unwrap();
        let head = store
            .publish_binding(
                &head,
                &prepared.binding_sha256,
                publication_fixture(&prepared),
            )
            .unwrap();
        assert!(
            store
                .freeze_outer_receipt(&head, &prepared.binding_sha256)
                .is_err(),
            "missing UI/terminal/dispositions must not freeze a receipt"
        );
        let attached = store
            .attach_direct_ui(
                &head,
                &prepared.binding_sha256,
                VerifiedDirectUiProof::from(snapshot.clone()),
            )
            .unwrap();
        let exact_retry = store
            .attach_direct_ui(
                &attached,
                &prepared.binding_sha256,
                VerifiedDirectUiProof::from(snapshot.clone()),
            )
            .unwrap();
        assert_eq!(exact_retry, attached);

        let mut different_binding = direct_binding;
        different_binding.stable_seed.task_id = "task-other-binding".to_string();
        different_binding.invocation_id = different_binding.stable_seed.invocation_id().unwrap();
        let different = prepared_from_binding(different_binding);
        let different_path = temporary.path().join("custody-other").join("ui.json");
        let mut different_store =
            DirectOperationCustodyStore::open_for_test(&different_path, owner_uid()).unwrap();
        let different_head = different_store
            .prepare_binding(&different_store.head(), different.clone())
            .unwrap();
        let different_head = different_store
            .publish_binding(
                &different_head,
                &different.binding_sha256,
                publication_fixture(&different),
            )
            .unwrap();
        assert!(
            different_store
                .attach_direct_ui(
                    &different_head,
                    &different.binding_sha256,
                    VerifiedDirectUiProof::from(snapshot),
                )
                .is_err(),
            "sealed snapshot must not cross Direct bindings"
        );
    }

    #[test]
    fn exact_p0_disposition_freezes_one_receipt_and_only_system_api_ack_intent() {
        let mut fixture = published_fixture();
        attach_result_proofs(&mut fixture);
        fixture.head = fixture
            .store
            .attach_authenticated_adapter_disposition(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                ackable(&fixture.prepared, DirectOperationAdapter::SystemApi),
            )
            .unwrap();
        let unauthorized = DirectOperationAdapterTerminalDispositionV1 {
            schema: ADAPTER_TERMINAL_DISPOSITION_V1_SCHEMA.to_string(),
            binding_sha256: fixture.prepared.binding_sha256.clone(),
            invocation_id: fixture.prepared.binding.invocation_id.clone(),
            delivery_provider_attempt_id: fixture
                .prepared
                .binding
                .attempt
                .delivery_provider_attempt_id
                .clone(),
            provider_id: fixture.prepared.binding.stable_seed.provider_id.clone(),
            agent_id: fixture.prepared.binding.stable_seed.agent_id.clone(),
            adapter: DirectOperationAdapter::Accessibility,
            terminal_state: DirectOperationAdapterTerminalStateV1::NoOperations {
                journal_epoch: "33".repeat(16),
                journal_payload_sha256: digest("unauthorized-accessibility-journal"),
                previous_ack_watermark: 0,
                previous_ack_chain_sha256: ZERO_SHA256.to_string(),
                authenticated_terminal_sha256: digest("unauthorized-accessibility-terminal"),
            },
        };
        assert!(
            fixture
                .store
                .attach_authenticated_adapter_disposition(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    verified_disposition(unauthorized),
                )
                .is_err()
        );
        fixture.head = fixture
            .store
            .freeze_outer_receipt(&fixture.head, &fixture.prepared.binding_sha256)
            .unwrap();
        let frozen_head = fixture.head.clone();
        assert_eq!(
            fixture
                .store
                .freeze_outer_receipt(&fixture.head, &fixture.prepared.binding_sha256)
                .unwrap(),
            frozen_head
        );
        fixture.head = fixture
            .store
            .prepare_ack_intent(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();
        let denied = fixture.store.prepare_ack_intent(
            &fixture.head,
            &fixture.prepared.binding_sha256,
            DirectOperationAdapter::Accessibility,
        );
        assert!(denied.is_err());

        let record = &fixture.store.file.records[0];
        let receipt = record.outer_receipt.as_ref().unwrap();
        assert_eq!(receipt.adapter_terminal_dispositions.len(), 1);
        assert_eq!(record.ack_intents.len(), 1);
        record.ack_intents[0].validate_for_receipt(receipt).unwrap();
        assert!(matches!(
            receipt.adapter_terminal_dispositions[0].terminal_state,
            DirectOperationAdapterTerminalStateV1::Ackable { .. }
        ));

        let metadata = fs::metadata(&fixture.path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let parent = fs::metadata(fixture.path.parent().unwrap()).unwrap();
        assert_eq!(parent.permissions().mode() & 0o7777, 0o700);
        let reopened =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        assert_eq!(reopened.head(), fixture.head);
        assert_eq!(reopened.file, fixture.store.file);
    }

    #[test]
    fn ack_publication_then_restart_then_android_completion_is_exact() {
        let adapter = DirectOperationAdapter::SystemApi;
        let mut fixture = ack_intent_fixture(adapter);
        let frozen_intent = fixture.store.file.records[0].ack_intents[0].clone();
        let publication = ack_publication_fixture(&fixture.prepared, &frozen_intent);
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedOuterAckInboxPublicationProof::for_test(publication.clone()),
            )
            .unwrap();
        let publication_head = fixture.head.clone();
        assert_eq!(
            fixture
                .store
                .record_outer_ack_inbox_publication_for_test(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    adapter,
                    VerifiedOuterAckInboxPublicationProof::for_test(publication.clone()),
                )
                .unwrap(),
            publication_head
        );
        let progress = adapter_ack_progress(&fixture, adapter);
        assert!(progress.outer_ack_inbox_publication.is_some());
        assert!(progress.android_backend_ack_confirmation.is_none());
        assert!(!progress.completed);
        assert_eq!(
            fixture.store.file.records[0].ack_intents,
            vec![frozen_intent.clone()]
        );

        fixture.store =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        fixture.head = fixture.store.head();
        let prepared_launch = fixture
            .store
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        fixture.head = prepared_launch.custody_head.clone();
        let android = android_ack_confirmation_fixture_for_launch(
            &fixture.prepared,
            &frozen_intent,
            &prepared_launch.launch_id_sha256,
            &prepared_launch.launch_challenge_sha256,
        );
        drop(prepared_launch);
        let mut cross_product = android.clone();
        cross_product.launch_receipt.authority_evidence =
            DirectOperationExecutionAuthorityEvidenceV1::SignedProduct {
                product_descriptor_sha256: digest("different-signed-product-descriptor"),
                signed_product_measurement_sha256: digest("fixture-publisher-signed-product"),
                avb_partition_digest_sha256: digest("fixture-publisher-avb-partition"),
            };
        cross_product.launch_receipt_sha256 = cross_product.launch_receipt.digest_sha256().unwrap();
        cross_product.android_confirmation_source_sha256 =
            cross_product.launch_receipt_sha256.clone();
        let error = fixture
            .store
            .record_android_backend_ack_confirmation_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedAndroidBackendAckConfirmationProof::for_test(cross_product),
            )
            .unwrap_err();
        assert!(error.to_string().contains("cross_product_proof_denied"));
        assert_eq!(fixture.store.head(), fixture.head);
        fixture.head = fixture
            .store
            .record_android_backend_ack_confirmation_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedAndroidBackendAckConfirmationProof::for_test(android.clone()),
            )
            .unwrap();
        let completed_head = fixture.head.clone();
        assert_eq!(
            fixture
                .store
                .record_android_backend_ack_confirmation_for_test(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    adapter,
                    VerifiedAndroidBackendAckConfirmationProof::for_test(android),
                )
                .unwrap(),
            completed_head
        );
        assert_eq!(
            fixture
                .store
                .record_outer_ack_inbox_publication_for_test(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    adapter,
                    VerifiedOuterAckInboxPublicationProof::for_test(publication),
                )
                .unwrap(),
            completed_head
        );
        let progress = adapter_ack_progress(&fixture, adapter);
        assert!(progress.outer_ack_inbox_publication.is_some());
        assert!(progress.android_backend_ack_confirmation.is_some());
        assert!(!progress.completed);
        assert!(progress.outer_ack_retirement.is_none());
        assert_eq!(
            fixture.store.file.records[0].ack_intents,
            vec![frozen_intent]
        );

        let reopened =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        assert_eq!(reopened.head(), fixture.head);
        assert_eq!(reopened.file, fixture.store.file);
    }

    #[test]
    fn android_confirmation_before_ack_publication_is_rejected_without_state_change() {
        let adapter = DirectOperationAdapter::Accessibility;
        let mut fixture = future_dual_ack_intent_fixture(adapter);
        let frozen_intent = fixture.store.file.records[0].ack_intents[0].clone();
        let android = android_ack_confirmation_fixture(&fixture.prepared, &frozen_intent);
        let error = fixture
            .store
            .record_android_backend_ack_confirmation_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedAndroidBackendAckConfirmationProof::for_test(android),
            )
            .unwrap_err();
        assert!(error.to_string().contains("android_ack_before_publication"));
        assert_eq!(fixture.store.head(), fixture.head);
        assert!(
            fixture.store.file.records[0]
                .adapter_ack_progress
                .is_empty()
        );
        assert_eq!(
            fixture.store.file.records[0].ack_intents,
            vec![frozen_intent]
        );
    }

    #[test]
    fn fixed_publisher_first_empty_directory_reconciles_exact_inode_and_bytes() {
        let adapter = DirectOperationAdapter::SystemApi;
        let mut fixture = ack_intent_fixture(adapter);
        let publication_root = fixture._temporary.path().join("outer-ack-empty");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let prepared = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let mut expected_bytes = serde_json::to_vec(&prepared.inbox).unwrap();
        expected_bytes.push(b'\n');
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root.clone(),
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        let published = publisher.publish(prepared).unwrap();
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication(published)
            .unwrap();

        let named = publication_root.join("pending-outer-ack-v3.json");
        assert_eq!(fs::read(&named).unwrap(), expected_bytes);
        let metadata = fs::metadata(&named).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o440);
        assert_eq!(metadata.uid(), owner_uid());
        assert_eq!(metadata.gid(), owner_gid());
        assert_eq!(metadata.nlink(), 1);

        // Re-opening the exact named inode is idempotent even though the
        // custody head advanced when its proof was first recorded.
        let retry = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let retry = publisher.publish(retry).unwrap();
        assert_eq!(
            fixture
                .store
                .record_outer_ack_inbox_publication(retry)
                .unwrap(),
            fixture.head
        );
    }

    #[test]
    fn fixed_publisher_faults_drift_and_parent_rebind_fail_closed() {
        let adapter = DirectOperationAdapter::SystemApi;
        for fault in [
            outer_ack_publisher::TestPublishFault::PartialWrite,
            outer_ack_publisher::TestPublishFault::FileFsync,
        ] {
            let mut fixture = ack_intent_fixture(adapter);
            let publication_root = fixture
                ._temporary
                .path()
                .join(format!("outer-ack-fault-{fault:?}"));
            fs::DirBuilder::new()
                .mode(0o750)
                .create(&publication_root)
                .unwrap();
            let prepared = fixture
                .store
                .prepare_outer_ack_publication(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    adapter,
                )
                .unwrap();
            let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
                publication_root.clone(),
                owner_uid(),
                owner_gid(),
                0o750,
                owner_uid(),
                owner_gid(),
            );
            publisher.fail_once(fault);
            assert!(publisher.publish(prepared).is_err());
            assert!(!publication_root.join("pending-outer-ack-v3.json").exists());
            assert!(!publisher.publication_durability_uncertain());
        }

        let mut fixture = ack_intent_fixture(adapter);
        let publication_root = fixture._temporary.path().join("outer-ack-exact-race");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let prepared = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let mut expected = serde_json::to_vec(&prepared.inbox).unwrap();
        expected.push(b'\n');
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root.clone(),
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        publisher.fail_once(outer_ack_publisher::TestPublishFault::ExactNoReplaceRace);
        let _retained = publisher.publish(prepared).unwrap();
        assert_eq!(
            fs::read(publication_root.join("pending-outer-ack-v3.json")).unwrap(),
            expected
        );
        assert_eq!(fs::read_dir(&publication_root).unwrap().count(), 1);

        let mut fixture = ack_intent_fixture(adapter);
        let publication_root = fixture._temporary.path().join("outer-ack-drift-race");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let prepared = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root.clone(),
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        publisher.fail_once(outer_ack_publisher::TestPublishFault::DriftNoReplaceRace);
        assert!(publisher.publish(prepared).is_err());
        assert_eq!(
            fs::read(publication_root.join("pending-outer-ack-v3.json")).unwrap(),
            b"racing-drift\n"
        );
        assert_eq!(fs::read_dir(&publication_root).unwrap().count(), 1);

        let mut fixture = ack_intent_fixture(adapter);
        let publication_root = fixture._temporary.path().join("outer-ack-drift");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let named = publication_root.join("pending-outer-ack-v3.json");
        fs::write(&named, b"drift\n").unwrap();
        fs::set_permissions(&named, fs::Permissions::from_mode(0o440)).unwrap();
        let prepared = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root.clone(),
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        assert!(publisher.publish(prepared).is_err());
        assert_eq!(fs::read(&named).unwrap(), b"drift\n");

        let mut fixture = ack_intent_fixture(adapter);
        let publication_root = fixture._temporary.path().join("outer-ack-rebind");
        let displaced = fixture._temporary.path().join("outer-ack-displaced");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let prepared = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root.clone(),
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        let published = publisher.publish(prepared).unwrap();
        fs::rename(&publication_root, &displaced).unwrap();
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        assert!(
            fixture
                .store
                .record_outer_ack_inbox_publication(published)
                .unwrap_err()
                .to_string()
                .contains("parent_path_rebound")
        );
        assert_eq!(fixture.store.head(), fixture.head);
    }

    #[test]
    fn fixed_publisher_parent_fsync_uncertainty_requires_fresh_reconcile() {
        let adapter = DirectOperationAdapter::Accessibility;
        let mut fixture = future_dual_ack_intent_fixture(adapter);
        let publication_root = fixture._temporary.path().join("outer-ack-unknown");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let prepared = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root.clone(),
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        publisher.fail_once(outer_ack_publisher::TestPublishFault::ParentFsync);
        assert!(
            publisher
                .publish(prepared)
                .err()
                .unwrap()
                .to_string()
                .contains("commit_unknown")
        );
        assert!(publisher.publication_durability_uncertain());

        let prepared = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        assert!(
            publisher
                .publish(prepared)
                .err()
                .unwrap()
                .to_string()
                .contains("commit_unknown")
        );

        let prepared = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let mut reopened = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root,
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        let published = reopened.publish(prepared).unwrap();
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication(published)
            .unwrap();
        assert!(
            adapter_ack_progress(&fixture, adapter)
                .outer_ack_inbox_publication
                .is_some()
        );
    }

    #[test]
    fn replay_launch_requires_durable_publication_and_records_only_exact_completion() {
        let adapter = DirectOperationAdapter::SystemApi;
        let mut fixture = ack_intent_fixture(adapter);
        assert!(
            fixture
                .store
                .prepare_operation_replay_sync_launch(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    adapter,
                )
                .err()
                .unwrap()
                .to_string()
                .contains("before_publication")
        );
        let intent = fixture.store.file.records[0].ack_intents[0].clone();
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedOuterAckInboxPublicationProof::for_test(ack_publication_fixture(
                    &fixture.prepared,
                    &intent,
                )),
            )
            .unwrap();
        let prepared = fixture
            .store
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        let exact = exact_replay_confirmation(&prepared);
        let mut ops = MockReplayLaunchOps {
            exact,
            calls: Vec::new(),
            killed: false,
            product_descriptor_override: None,
        };
        let completed =
            operation_replay_sync_launcher::launch_with_ops(prepared, &mut ops).unwrap();
        assert_eq!(
            ops.calls,
            [
                "capabilities",
                "measure",
                "spawn",
                "verify",
                "release",
                "resume",
                "collect",
                "exit"
            ]
        );
        assert!(!ops.killed);
        fixture.head = fixture
            .store
            .record_android_backend_ack_confirmation(completed)
            .unwrap();
        assert!(!adapter_ack_progress(&fixture, adapter).completed);
        assert!(
            adapter_ack_progress(&fixture, adapter)
                .outer_ack_retirement
                .is_none()
        );
        assert!(
            fixture
                .store
                .prepare_operation_replay_sync_launch(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    adapter,
                )
                .err()
                .unwrap()
                .to_string()
                .contains("after_confirmation")
        );
    }

    #[test]
    fn replay_launch_confirmation_drift_kills_and_reaps_without_android_proof() {
        let adapter = DirectOperationAdapter::Accessibility;
        let mut fixture = future_dual_ack_intent_fixture(adapter);
        let intent = fixture.store.file.records[0].ack_intents[0].clone();
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedOuterAckInboxPublicationProof::for_test(ack_publication_fixture(
                    &fixture.prepared,
                    &intent,
                )),
            )
            .unwrap();
        let prepared = fixture
            .store
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        let mut exact = exact_replay_confirmation(&prepared);
        let confirmation = match &mut exact.confirmation {
            operation_replay_sync_launcher::ReplaySyncAckConfirmation::Product(confirmation) => {
                confirmation
            }
            #[cfg(feature = "p0-launch-package-device-conformance")]
            operation_replay_sync_launcher::ReplaySyncAckConfirmation::P0(_) => {
                panic!("test fixture must use the product confirmation lane")
            }
        };
        confirmation.acknowledgement_sha256 = digest("wrong-helper-acknowledgement");
        let mut ops = MockReplayLaunchOps {
            exact,
            calls: Vec::new(),
            killed: false,
            product_descriptor_override: None,
        };
        let error = operation_replay_sync_launcher::launch_with_ops(prepared, &mut ops)
            .err()
            .unwrap();
        assert!(error.to_string().contains("helper_confirmation_denied"));
        assert!(ops.killed);
        assert_eq!(ops.calls.last(), Some(&"kill"));
        let progress = adapter_ack_progress(&fixture, adapter);
        assert!(progress.outer_ack_inbox_publication.is_some());
        assert!(progress.android_backend_ack_confirmation.is_none());
        assert!(!progress.completed);
    }

    #[test]
    fn replay_launch_rejects_cross_product_executable_before_spawn() {
        let adapter = DirectOperationAdapter::Accessibility;
        let mut fixture = future_dual_ack_intent_fixture(adapter);
        let intent = fixture.store.file.records[0].ack_intents[0].clone();
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedOuterAckInboxPublicationProof::for_test(ack_publication_fixture(
                    &fixture.prepared,
                    &intent,
                )),
            )
            .unwrap();
        let prepared = fixture
            .store
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        let exact = exact_replay_confirmation(&prepared);
        let mut ops = MockReplayLaunchOps {
            exact,
            calls: Vec::new(),
            killed: false,
            product_descriptor_override: Some(digest("different-signed-product-descriptor")),
        };
        let error = operation_replay_sync_launcher::launch_with_ops(prepared, &mut ops)
            .err()
            .unwrap();
        assert!(error.to_string().contains("executable_measurement_denied"));
        assert_eq!(ops.calls, ["capabilities", "measure"]);
        assert!(!ops.killed);
        assert!(
            adapter_ack_progress(&fixture, adapter)
                .android_backend_ack_confirmation
                .is_none()
        );
    }

    #[test]
    fn replay_launch_is_kernel_single_flight_and_restart_reconciles_exact_id() {
        let adapter = DirectOperationAdapter::SystemApi;
        let mut fixture = ack_intent_fixture(adapter);
        let intent = fixture.store.file.records[0].ack_intents[0].clone();
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedOuterAckInboxPublicationProof::for_test(ack_publication_fixture(
                    &fixture.prepared,
                    &intent,
                )),
            )
            .unwrap();
        let first = fixture
            .store
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        fixture.head = first.custody_head.clone();
        let launch_id = first.launch_id_sha256.clone();
        let launch_challenge = first.launch_challenge_sha256.clone();

        let mut concurrent =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        let error = concurrent
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .err()
            .unwrap();
        assert!(error.to_string().contains("already_active_hold"));
        drop(first);

        let reconciled = concurrent
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        assert_eq!(reconciled.launch_id_sha256, launch_id);
        assert_eq!(reconciled.launch_challenge_sha256, launch_challenge);
    }

    #[test]
    fn android_confirmation_then_archive_retirement_survives_commit_unknown_and_completes() {
        let adapter = DirectOperationAdapter::SystemApi;
        let mut fixture = ack_intent_fixture(adapter);
        let intent = fixture.store.file.records[0].ack_intents[0].clone();
        let publication_root = fixture._temporary.path().join("outer-ack-retirement");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root.clone(),
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        let publication = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication(publisher.publish(publication).unwrap())
            .unwrap();

        let prepared_launch = fixture
            .store
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        fixture.head = prepared_launch.custody_head.clone();
        let exact = exact_replay_confirmation(&prepared_launch);
        let mut ops = MockReplayLaunchOps {
            exact,
            calls: Vec::new(),
            killed: false,
            product_descriptor_override: None,
        };
        let completed =
            operation_replay_sync_launcher::launch_with_ops(prepared_launch, &mut ops).unwrap();
        let mut concurrent =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        assert!(
            concurrent
                .prepare_operation_replay_sync_launch(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    adapter,
                )
                .err()
                .unwrap()
                .to_string()
                .contains("already_active_hold")
        );
        fixture.head = fixture
            .store
            .record_android_backend_ack_confirmation(completed)
            .unwrap();
        assert!(!adapter_ack_progress(&fixture, adapter).completed);
        assert!(publication_root.join("pending-outer-ack-v3.json").exists());

        let prepared_retirement = fixture
            .store
            .prepare_outer_ack_retirement(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        publisher.fail_once(outer_ack_publisher::TestPublishFault::RetirementParentFsync);
        let error = publisher.retire(prepared_retirement).err().unwrap();
        assert!(error.to_string().contains("parent_fsync_test_fault"));
        assert!(publisher.publication_durability_uncertain());
        assert!(!publication_root.join("pending-outer-ack-v3.json").exists());

        let archived_leaf = format!("acked-{}.json", intent.digest_sha256().unwrap());
        let archived_path = publication_root.join("acked").join(&archived_leaf);
        assert!(archived_path.exists());
        let prepared_retirement = fixture
            .store
            .prepare_outer_ack_retirement(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let mut reopened_publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root.clone(),
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        let retired = reopened_publisher.retire(prepared_retirement).unwrap();
        fixture.store.fail_parent_fsync_after_rename_once_for_test();
        let error = fixture
            .store
            .record_outer_ack_retirement(retired)
            .unwrap_err();
        assert!(error.to_string().contains("commit_unknown_test_fault"));
        fixture.store =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        fixture.head = fixture.store.head();
        let held = adapter_ack_progress(&fixture, adapter);
        assert!(!held.completed);
        assert!(
            held.outer_ack_retirement
                .as_ref()
                .is_some_and(|proof| !proof.external_state_reconciled)
        );

        let prepared_retirement = fixture
            .store
            .prepare_outer_ack_retirement(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        let retired = reopened_publisher.retire(prepared_retirement).unwrap();
        fixture.head = fixture.store.record_outer_ack_retirement(retired).unwrap();
        let progress = adapter_ack_progress(&fixture, adapter);
        assert!(progress.completed);
        assert_eq!(
            progress
                .outer_ack_retirement
                .as_ref()
                .unwrap()
                .archived_leaf_name,
            archived_leaf
        );
        assert_eq!(fs::read(&archived_path).unwrap(), {
            let mut bytes = serde_json::to_vec(&intent.inbox).unwrap();
            bytes.push(b'\n');
            bytes
        });
        assert!(
            fixture
                .store
                .prepare_outer_ack_publication(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    adapter,
                )
                .err()
                .unwrap()
                .to_string()
                .contains("after_retirement")
        );
        let reopened =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        assert_eq!(reopened.head(), fixture.head);
        assert!(reopened.file.records[0].adapter_ack_progress[0].completed);
    }

    #[test]
    fn ack_progress_commit_unknown_recovers_without_losing_intent() {
        let adapter = DirectOperationAdapter::SystemApi;
        let mut fixture = ack_intent_fixture(adapter);
        let frozen_intent = fixture.store.file.records[0].ack_intents[0].clone();
        let publication = ack_publication_fixture(&fixture.prepared, &frozen_intent);
        let android = android_ack_confirmation_fixture(&fixture.prepared, &frozen_intent);
        fixture.store.fail_parent_fsync_after_rename_once_for_test();
        let error = fixture
            .store
            .record_outer_ack_inbox_publication_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedOuterAckInboxPublicationProof::for_test(publication.clone()),
            )
            .unwrap_err();
        assert!(error.to_string().contains("commit_unknown_test_fault"));
        assert!(fixture.store.publication_durability_uncertain());
        assert!(
            fixture
                .store
                .record_android_backend_ack_confirmation_for_test(
                    &fixture.store.head(),
                    &fixture.prepared.binding_sha256,
                    adapter,
                    VerifiedAndroidBackendAckConfirmationProof::for_test(android.clone()),
                )
                .unwrap_err()
                .to_string()
                .contains("fail_stop_commit_unknown")
        );

        fixture.store =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        fixture.head = fixture.store.head();
        let progress = adapter_ack_progress(&fixture, adapter);
        assert!(progress.outer_ack_inbox_publication.is_some());
        assert!(progress.android_backend_ack_confirmation.is_none());
        assert!(!progress.completed);
        assert_eq!(
            fixture.store.file.records[0].ack_intents,
            vec![frozen_intent.clone()]
        );
        // The uncertain first phase is intentionally durable as a persisted
        // HOLD.  A fresh exact external proof must reconcile it before any
        // replay helper launch capability can be issued.
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedOuterAckInboxPublicationProof::for_test(publication),
            )
            .unwrap();
        let prepared_launch = fixture
            .store
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        fixture.head = prepared_launch.custody_head.clone();
        let android = android_ack_confirmation_fixture_for_launch(
            &fixture.prepared,
            &frozen_intent,
            &prepared_launch.launch_id_sha256,
            &prepared_launch.launch_challenge_sha256,
        );
        drop(prepared_launch);
        fixture.head = fixture
            .store
            .record_android_backend_ack_confirmation_for_test(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
                VerifiedAndroidBackendAckConfirmationProof::for_test(android),
            )
            .unwrap();
        assert!(!adapter_ack_progress(&fixture, adapter).completed);
        assert_eq!(
            fixture.store.file.records[0].ack_intents,
            vec![frozen_intent]
        );
    }

    #[test]
    fn ack_progress_rejects_early_cross_adapter_drift_and_persisted_tamper() {
        let adapter = DirectOperationAdapter::SystemApi;
        let mut early = receipt_ready_fixture(&[adapter]);
        let expected_intent = early.store.file.records[0]
            .expected_ack_intent(adapter)
            .unwrap();
        let publication = ack_publication_fixture(&early.prepared, &expected_intent);
        assert!(
            early
                .store
                .record_outer_ack_inbox_publication_for_test(
                    &early.head,
                    &early.prepared.binding_sha256,
                    adapter,
                    VerifiedOuterAckInboxPublicationProof::for_test(publication),
                )
                .unwrap_err()
                .to_string()
                .contains("before_intent")
        );

        let mut dual = dual_ack_intent_fixture();
        let system_intent = dual.store.file.records[0]
            .ack_intents
            .iter()
            .find(|intent| intent.adapter == DirectOperationAdapter::SystemApi)
            .unwrap()
            .clone();
        let system_publication = ack_publication_fixture(&dual.prepared, &system_intent);
        assert!(
            dual.store
                .record_outer_ack_inbox_publication_for_test(
                    &dual.head,
                    &dual.prepared.binding_sha256,
                    DirectOperationAdapter::Accessibility,
                    VerifiedOuterAckInboxPublicationProof::for_test(system_publication.clone()),
                )
                .unwrap_err()
                .to_string()
                .contains("publication_proof_denied")
        );
        dual.head = dual
            .store
            .record_outer_ack_inbox_publication_for_test(
                &dual.head,
                &dual.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
                VerifiedOuterAckInboxPublicationProof::for_test(system_publication.clone()),
            )
            .unwrap();
        let mut publication_drift = system_publication;
        publication_drift.publication_custody_source_sha256 =
            digest("different-publication-custody-source");
        assert!(
            dual.store
                .record_outer_ack_inbox_publication_for_test(
                    &dual.head,
                    &dual.prepared.binding_sha256,
                    DirectOperationAdapter::SystemApi,
                    VerifiedOuterAckInboxPublicationProof::for_test(publication_drift),
                )
                .unwrap_err()
                .to_string()
                .contains("proof_drift")
        );
        let mut android_tamper = android_ack_confirmation_fixture(&dual.prepared, &system_intent);
        android_tamper.acknowledgement_sha256 = digest("wrong-acknowledgement");
        assert!(
            dual.store
                .record_android_backend_ack_confirmation_for_test(
                    &dual.head,
                    &dual.prepared.binding_sha256,
                    DirectOperationAdapter::SystemApi,
                    VerifiedAndroidBackendAckConfirmationProof::for_test(android_tamper),
                )
                .unwrap_err()
                .to_string()
                .contains("confirmation_proof_denied")
        );

        let path = dual.path.clone();
        let owner = owner_uid();
        let mut persisted = serde_json::to_value(&dual.store.file).unwrap();
        persisted["records"][0]["adapter_ack_progress"][0]["outer_ack_inbox_publication"]["journal_epoch"] =
            serde_json::json!("ff".repeat(16));
        let mut bytes = serde_json::to_vec_pretty(&persisted).unwrap();
        bytes.push(b'\n');
        drop(dual.store);
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            DirectOperationCustodyStore::open_for_test(&path, owner)
                .err()
                .unwrap()
                .to_string()
                .contains("publication_proof_denied")
        );
    }

    #[test]
    fn empty_ack_progress_extension_preserves_v3_canonical_bytes_and_stays_unwired() {
        let fixture = ack_intent_fixture(DirectOperationAdapter::SystemApi);
        let bytes = encode_canonical_file(&fixture.store.file).unwrap();
        assert!(
            !bytes
                .windows(b"adapter_ack_progress".len())
                .any(|window| window == b"adapter_ack_progress")
        );
        assert_eq!(decode_canonical_file(&bytes).unwrap(), fixture.store.file);
        let main_source = include_str!("main.rs");
        assert!(!main_source.contains("record_outer_ack_inbox_publication"));
        assert!(!main_source.contains("record_android_backend_ack_confirmation"));
    }

    #[test]
    fn p0_receipt_requires_terminal_ui_and_one_authenticated_system_disposition() {
        let mut fixture = published_fixture();
        assert!(
            fixture
                .store
                .freeze_outer_receipt(&fixture.head, &fixture.prepared.binding_sha256)
                .unwrap_err()
                .to_string()
                .contains("dispositions_required")
        );
        attach_result_proofs(&mut fixture);
        fixture.head = fixture
            .store
            .attach_authenticated_adapter_disposition(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                no_operations(&fixture.prepared, DirectOperationAdapter::SystemApi),
            )
            .unwrap();
        fixture.head = fixture
            .store
            .freeze_outer_receipt(&fixture.head, &fixture.prepared.binding_sha256)
            .unwrap();
        assert_eq!(
            fixture.store.file.records[0]
                .outer_receipt
                .as_ref()
                .unwrap()
                .adapter_terminal_dispositions
                .len(),
            1
        );
        assert!(
            fixture
                .store
                .prepare_ack_intent(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    DirectOperationAdapter::SystemApi,
                )
                .unwrap_err()
                .to_string()
                .contains("not_ackable")
        );
        assert!(
            fixture
                .store
                .prepare_ack_intent(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    DirectOperationAdapter::Accessibility,
                )
                .is_err()
        );
    }

    #[test]
    fn publication_requires_the_exact_binding_authorized_ordered_leaf_set() {
        let temporary = private_tempdir();
        let path = temporary.path().join("private").join("custody.json");
        let prepared = future_dual_prepared_fixture();
        let mut store = DirectOperationCustodyStore::open_for_test(&path, owner_uid()).unwrap();
        let head = store
            .prepare_binding(&store.head(), prepared.clone())
            .unwrap();

        let mut missing = publication_fixture(&prepared);
        missing.leaves.pop();
        missing.leaves_sha256 =
            domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &missing.leaves).unwrap();
        assert!(
            store
                .publish_binding(&head, &prepared.binding_sha256, missing)
                .unwrap_err()
                .to_string()
                .contains("authorized_leaf_publication_set_denied")
        );
        let mut reversed = publication_fixture(&prepared);
        reversed.leaves.reverse();
        reversed.leaves_sha256 =
            domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &reversed.leaves).unwrap();
        assert!(
            store
                .publish_binding(&head, &prepared.binding_sha256, reversed)
                .unwrap_err()
                .to_string()
                .contains("authorized_leaf_publication_set_denied")
        );
        let mut drift = publication_fixture(&prepared);
        drift.leaves[0].published_bytes_sha256 = digest("different-published-bytes");
        drift.leaves_sha256 =
            domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &drift.leaves).unwrap();
        assert!(
            store
                .publish_binding(&head, &prepared.binding_sha256, drift)
                .unwrap_err()
                .to_string()
                .contains("leaf_publication_proof_denied")
        );
        let mut reused_parent = publication_fixture(&prepared);
        reused_parent.leaves[1].parent_directory_identity_sha256 = reused_parent.leaves[0]
            .parent_directory_identity_sha256
            .clone();
        reused_parent.leaves_sha256 =
            domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &reused_parent.leaves).unwrap();
        assert!(
            store
                .publish_binding(&head, &prepared.binding_sha256, reused_parent)
                .unwrap_err()
                .to_string()
                .contains("authorized_leaf_publication_identity_reuse_denied")
        );
        let mut reused_file = publication_fixture(&prepared);
        reused_file.leaves[1].published_file_identity_sha256 =
            reused_file.leaves[0].published_file_identity_sha256.clone();
        reused_file.leaves_sha256 =
            domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &reused_file.leaves).unwrap();
        assert!(
            store
                .publish_binding(&head, &prepared.binding_sha256, reused_file)
                .unwrap_err()
                .to_string()
                .contains("authorized_leaf_publication_identity_reuse_denied")
        );

        let p0 = prepared_fixture();
        let mut extra = publication_fixture(&p0);
        extra
            .leaves
            .push(leaf(&p0, DirectOperationAdapter::Accessibility));
        extra.leaves_sha256 =
            domain_digest(AUTHORIZED_LEAF_SET_DIGEST_DOMAIN, &extra.leaves).unwrap();
        let p0_path = temporary.path().join("p0-private").join("custody.json");
        let mut p0_store =
            DirectOperationCustodyStore::open_for_test(&p0_path, owner_uid()).unwrap();
        let p0_head = p0_store
            .prepare_binding(&p0_store.head(), p0.clone())
            .unwrap();
        assert!(
            p0_store
                .publish_binding(&p0_head, &p0.binding_sha256, extra)
                .unwrap_err()
                .to_string()
                .contains("authorized_leaf_publication_set_denied")
        );
    }

    #[test]
    fn directory_writer_lock_rejects_cross_store_stale_cas() {
        let mut fixture = receipt_ready_fixture_for_prepared(
            future_dual_prepared_fixture(),
            &[
                DirectOperationAdapter::SystemApi,
                DirectOperationAdapter::Accessibility,
            ],
        );
        let mut stale =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        let stale_head = stale.head();
        fixture.head = fixture
            .store
            .prepare_ack_intent(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap();
        let error = stale
            .prepare_ack_intent(
                &stale_head,
                &fixture.prepared.binding_sha256,
                DirectOperationAdapter::Accessibility,
            )
            .unwrap_err();
        assert!(error.to_string().contains("changed_outside_atomic_writer"));
        let reopened =
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid()).unwrap();
        assert_eq!(reopened.head(), fixture.head);
    }

    #[test]
    fn writer_lease_drop_unlocks_an_inherited_open_file_description() {
        let fixture = published_fixture();
        let lease = acquire_store_writer_lease(&fixture.store.parent, owner_uid()).unwrap();
        let inherited_fd = unsafe { libc::dup(lease.directory.as_raw_fd()) };
        assert!(inherited_fd >= 0);
        let inherited = unsafe { File::from_raw_fd(inherited_fd) };

        drop(lease);
        let reacquired = acquire_store_writer_lease(&fixture.store.parent, owner_uid()).unwrap();

        drop(reacquired);
        drop(inherited);
    }

    #[test]
    fn retained_writer_rejects_custody_parent_path_rebind() {
        let mut fixture = receipt_ready_fixture(&[DirectOperationAdapter::SystemApi]);
        let parent = fixture.path.parent().unwrap().to_path_buf();
        let moved = fixture._temporary.path().join("private-original-inode");
        fs::rename(&parent, &moved).unwrap();
        fs::DirBuilder::new().mode(0o700).create(&parent).unwrap();
        let error = fixture
            .store
            .prepare_ack_intent(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                DirectOperationAdapter::SystemApi,
            )
            .unwrap_err();
        assert!(error.to_string().contains("parent_path_rebound"));
        assert!(moved.join("custody.json").exists());
    }

    #[test]
    fn stale_predecessor_cas_and_post_freeze_disposition_drift_are_denied() {
        let mut fixture = published_fixture();
        let stale = DirectOperationCustodyHead::genesis();
        assert!(
            fixture
                .store
                .attach_direct_ui(
                    &stale,
                    &fixture.prepared.binding_sha256,
                    VerifiedDirectUiProof::for_test(direct_ui_fixture(&fixture.prepared))
                )
                .unwrap_err()
                .to_string()
                .contains("predecessor_cas_mismatch")
        );
        attach_result_proofs(&mut fixture);
        fixture.head = fixture
            .store
            .attach_authenticated_adapter_disposition(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                ackable(&fixture.prepared, DirectOperationAdapter::SystemApi),
            )
            .unwrap();
        let exact = ackable(&fixture.prepared, DirectOperationAdapter::SystemApi);
        assert_eq!(
            fixture
                .store
                .attach_authenticated_adapter_disposition(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    exact
                )
                .unwrap(),
            fixture.head
        );
        assert!(
            fixture
                .store
                .attach_authenticated_adapter_disposition(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    no_operations(&fixture.prepared, DirectOperationAdapter::SystemApi)
                )
                .unwrap_err()
                .to_string()
                .contains("disposition_drift")
        );
    }

    #[test]
    fn prepared_and_published_exact_retries_do_not_advance_the_store() {
        let mut fixture = published_fixture();
        let before = fixture.head.clone();
        assert_eq!(
            fixture
                .store
                .prepare_binding(&fixture.head, fixture.prepared.clone())
                .unwrap(),
            before
        );
        assert_eq!(
            fixture
                .store
                .publish_binding(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    publication_fixture(&fixture.prepared),
                )
                .unwrap(),
            before
        );
        assert_eq!(fixture.store.file.records[0].revision, 2);
    }

    #[test]
    fn parent_fsync_commit_unknown_fail_stops_until_reopen() {
        let temporary = private_tempdir();
        let path = temporary.path().join("private").join("custody.json");
        let prepared = prepared_fixture();
        let mut store = DirectOperationCustodyStore::open_for_test(&path, owner_uid()).unwrap();
        store.fail_parent_fsync_after_rename_once_for_test();
        let error = store
            .prepare_binding(&store.head(), prepared.clone())
            .unwrap_err();
        assert!(error.to_string().contains("commit_unknown_test_fault"));
        assert!(store.publication_durability_uncertain());
        assert!(
            store
                .publish_binding(
                    &store.head(),
                    &prepared.binding_sha256,
                    publication_fixture(&prepared)
                )
                .unwrap_err()
                .to_string()
                .contains("fail_stop_commit_unknown")
        );
        let mut reopened = DirectOperationCustodyStore::open_for_test(&path, owner_uid()).unwrap();
        assert!(!reopened.publication_durability_uncertain());
        let head = reopened.head();
        reopened
            .publish_binding(
                &head,
                &prepared.binding_sha256,
                publication_fixture(&prepared),
            )
            .unwrap();
    }

    #[test]
    fn closed_canonical_json_rejects_unknown_and_noncanonical_encodings() {
        let fixture = published_fixture();
        let path = fixture.path.clone();
        let owner = owner_uid();
        let mut unknown = serde_json::to_value(&fixture.store.file).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("untrusted_extra".to_string(), serde_json::json!(true));
        let mut unknown_bytes = serde_json::to_vec_pretty(&unknown).unwrap();
        unknown_bytes.push(b'\n');
        drop(fixture.store);
        fs::write(&path, unknown_bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            DirectOperationCustodyStore::open_for_test(&path, owner)
                .err()
                .unwrap()
                .to_string()
                .contains("file_json_denied")
        );

        let fixture = published_fixture();
        let compact = serde_json::to_vec(&fixture.store.file).unwrap();
        let path = fixture.path.clone();
        drop(fixture.store);
        fs::write(&path, compact).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            DirectOperationCustodyStore::open_for_test(&path, owner)
                .err()
                .unwrap()
                .to_string()
                .contains("not_canonical")
        );
    }

    #[test]
    fn persisted_v3_chain_rejects_every_v1_or_v2_nested_schema_splice() {
        let fixture = ack_intent_fixture(DirectOperationAdapter::SystemApi);
        let current = serde_json::to_value(&fixture.store.file).unwrap();
        let schema_paths = [
            "/schema",
            "/records/0/schema",
            "/records/0/prepared/schema",
            "/records/0/prepared/binding/schema",
            "/records/0/prepared/binding/authorized_adapter_set/schema",
            "/records/0/prepared/binding_inbox/schema",
            "/records/0/publication/schema",
            "/records/0/publication/leaves/0/schema",
            "/records/0/outer_receipt/schema",
            "/records/0/ack_intents/0/schema",
            "/records/0/ack_intents/0/inbox/schema",
            "/records/0/ack_intents/0/inbox/acknowledgement/schema",
            "/records/0/ack_intents/0/inbox/chain_step/schema",
        ];
        for version in 1..=2 {
            for path in schema_paths {
                let mut spliced = current.clone();
                *spliced.pointer_mut(path).unwrap() =
                    serde_json::json!(format!("trillionnium.old-direct-operation.v{version}"));
                let mut bytes = serde_json::to_vec_pretty(&spliced).unwrap();
                bytes.push(b'\n');
                assert!(
                    decode_canonical_file(&bytes).is_err(),
                    "old schema v{version} was accepted at {path}"
                );
            }
        }
    }

    #[test]
    fn byte_record_and_destination_mode_bounds_fail_closed() {
        assert!(
            decode_canonical_file(&vec![b' '; MAX_STORE_BYTES + 1])
                .unwrap_err()
                .to_string()
                .contains("size_boundary")
        );

        let mut oversized = DirectOperationCustodyFileV3 {
            schema: STORE_SCHEMA.to_string(),
            generation: 1,
            predecessor_store_sha256: ZERO_SHA256.to_string(),
            records: (0..=MAX_RECORDS)
                .map(|index| {
                    DirectOperationCustodyRecordV3::new(prepared_fixture_index(index)).unwrap()
                })
                .collect(),
        };
        oversized.records.sort_by(|left, right| {
            left.prepared
                .binding_sha256
                .cmp(&right.prepared.binding_sha256)
        });
        assert!(
            oversized
                .validate_persisted()
                .unwrap_err()
                .to_string()
                .contains("file_header_denied")
        );

        let fixture = published_fixture();
        let path = fixture.path.clone();
        drop(fixture.store);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(
            DirectOperationCustodyStore::open_for_test(&path, owner_uid())
                .err()
                .unwrap()
                .to_string()
                .contains("owner_private_single_link")
        );
    }

    #[test]
    fn nofollow_single_link_and_private_parent_boundaries_are_enforced() {
        let fixture = published_fixture();
        let hardlink = fixture.path.with_file_name("custody-hardlink.json");
        fs::hard_link(&fixture.path, &hardlink).unwrap();
        assert!(
            DirectOperationCustodyStore::open_for_test(&fixture.path, owner_uid())
                .err()
                .unwrap()
                .to_string()
                .contains("single_link")
        );

        let temporary = private_tempdir();
        let private = temporary.path().join("private");
        fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
        let target = private.join("target");
        fs::write(&target, b"not a store").unwrap();
        let symlink_path = private.join("custody.json");
        symlink(&target, &symlink_path).unwrap();
        assert!(DirectOperationCustodyStore::open_for_test(&symlink_path, owner_uid()).is_err());

        let temporary = private_tempdir();
        let unsafe_parent = temporary.path().join("unsafe");
        fs::DirBuilder::new()
            .mode(0o770)
            .create(&unsafe_parent)
            .unwrap();
        assert!(
            DirectOperationCustodyStore::open_for_test(
                &unsafe_parent.join("custody.json"),
                owner_uid()
            )
            .err()
            .unwrap()
            .to_string()
            .contains("parent_not_owner_private")
        );
    }

    fn assert_external_head_exact(
        fixture: &PublishedFixture,
        authority: &TestDirectOperationCustodyHighWaterAuthority,
    ) {
        assert_eq!(authority.committed_head(), fixture.store.head());
        assert_eq!(
            authority.operation_count(
                trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Commit,
            ),
            usize::try_from(fixture.store.head().generation).unwrap()
        );
        fixture.store.ensure_live_high_water().unwrap();
    }

    #[test]
    fn product_high_water_advances_every_binding_receipt_ack_confirmation_and_retirement_transition()
     {
        let temporary = private_tempdir();
        let path = temporary.path().join("private").join("custody.json");
        let authority = TestDirectOperationCustodyHighWaterAuthority::new(
            DirectOperationCustodyHead::genesis(),
        );
        let verified =
            DirectOperationCustodyStore::verify_high_water_for_test(&path, owner_uid(), &authority)
                .unwrap();
        let mut store = DirectOperationCustodyStore::open_verified_for_test(verified).unwrap();
        let prepared = prepared_fixture();

        let head = store
            .prepare_binding(&store.head(), prepared.clone())
            .unwrap();
        let commits_after_binding = authority.operation_count(
            trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Commit,
        );
        assert_eq!(
            store.prepare_binding(&head, prepared.clone()).unwrap(),
            head
        );
        assert_eq!(
            authority.operation_count(
                trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Commit,
            ),
            commits_after_binding
        );
        let head = store
            .publish_binding(
                &head,
                &prepared.binding_sha256,
                publication_fixture(&prepared),
            )
            .unwrap();
        let mut fixture = PublishedFixture {
            _temporary: temporary,
            path,
            store,
            prepared,
            head,
        };
        assert_external_head_exact(&fixture, &authority);

        attach_result_proofs(&mut fixture);
        assert_external_head_exact(&fixture, &authority);
        for adapter in fixture
            .prepared
            .binding
            .authorized_adapter_set
            .authorized_adapters
            .clone()
        {
            let disposition = if adapter == DirectOperationAdapter::SystemApi {
                ackable(&fixture.prepared, adapter)
            } else {
                no_operations(&fixture.prepared, adapter)
            };
            fixture.head = fixture
                .store
                .attach_authenticated_adapter_disposition(
                    &fixture.head,
                    &fixture.prepared.binding_sha256,
                    disposition,
                )
                .unwrap();
            assert_external_head_exact(&fixture, &authority);
        }
        fixture.head = fixture
            .store
            .freeze_outer_receipt(&fixture.head, &fixture.prepared.binding_sha256)
            .unwrap();
        assert_external_head_exact(&fixture, &authority);

        let adapter = DirectOperationAdapter::SystemApi;
        fixture.head = fixture
            .store
            .prepare_ack_intent(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        assert_external_head_exact(&fixture, &authority);
        let intent = fixture.store.file.records[0].ack_intents[0].clone();
        let publication_root = fixture._temporary.path().join("high-water-outer-ack");
        fs::DirBuilder::new()
            .mode(0o750)
            .create(&publication_root)
            .unwrap();
        let mut publisher = outer_ack_publisher::FixedOuterAckInboxPublisher::for_test(
            publication_root,
            owner_uid(),
            owner_gid(),
            0o750,
            owner_uid(),
            owner_gid(),
        );
        let observes_before_publication = authority.operation_count(
            trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Observe,
        );
        let prepared_publication = fixture
            .store
            .prepare_outer_ack_publication(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        assert_eq!(
            authority.operation_count(
                trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Observe,
            ),
            observes_before_publication + 1
        );
        fixture.head = fixture
            .store
            .record_outer_ack_inbox_publication(publisher.publish(prepared_publication).unwrap())
            .unwrap();
        assert_external_head_exact(&fixture, &authority);

        let observes_before_launch = authority.operation_count(
            trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Observe,
        );
        let prepared_launch = fixture
            .store
            .prepare_operation_replay_sync_launch(
                &fixture.head,
                &fixture.prepared.binding_sha256,
                adapter,
            )
            .unwrap();
        assert_eq!(
            authority.operation_count(
                trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Observe,
            ),
            // One fresh effect-boundary Observe plus the mutation protocol's
            // pre-Prepare and post-Commit reconciliation Observes.
            observes_before_launch + 3
        );
        fixture.head = prepared_launch.custody_head.clone();
        let exact = exact_replay_confirmation(&prepared_launch);
        let mut ops = MockReplayLaunchOps {
            exact,
            calls: Vec::new(),
            killed: false,
            product_descriptor_override: None,
        };
        let completed =
            operation_replay_sync_launcher::launch_with_ops(prepared_launch, &mut ops).unwrap();
        fixture.head = fixture
            .store
            .record_android_backend_ack_confirmation(completed)
            .unwrap();
        assert_external_head_exact(&fixture, &authority);

        let observes_before_retirement = authority.operation_count(
            trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Observe,
        );
        let prepared_retirement = fixture
            .store
            .prepare_outer_ack_retirement(&fixture.head, &fixture.prepared.binding_sha256, adapter)
            .unwrap();
        assert_eq!(
            authority.operation_count(
                trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation::Observe,
            ),
            observes_before_retirement + 1
        );
        fixture.head = fixture
            .store
            .record_outer_ack_retirement(publisher.retire(prepared_retirement).unwrap())
            .unwrap();
        assert_external_head_exact(&fixture, &authority);
        assert!(adapter_ack_progress(&fixture, adapter).completed);
        assert_eq!(intent.adapter, adapter);
    }

    #[test]
    fn product_high_water_exact_reopen_and_local_or_external_rollback_fail_closed() {
        let temporary = private_tempdir();
        let path = temporary.path().join("exact").join("custody.json");
        let authority = TestDirectOperationCustodyHighWaterAuthority::new(
            DirectOperationCustodyHead::genesis(),
        );
        let verified =
            DirectOperationCustodyStore::verify_high_water_for_test(&path, owner_uid(), &authority)
                .unwrap();
        let mut store = DirectOperationCustodyStore::open_verified_for_test(verified).unwrap();
        let prepared = prepared_fixture();
        let generation_one = store
            .prepare_binding(&store.head(), prepared.clone())
            .unwrap();
        let generation_one_bytes = fs::read(&path).unwrap();
        let generation_two = store
            .publish_binding(
                &generation_one,
                &prepared.binding_sha256,
                publication_fixture(&prepared),
            )
            .unwrap();
        assert_eq!(authority.committed_head(), generation_two);
        drop(store);

        let exact =
            DirectOperationCustodyStore::verify_high_water_for_test(&path, owner_uid(), &authority)
                .unwrap();
        let exact = DirectOperationCustodyStore::open_verified_for_test(exact).unwrap();
        assert_eq!(exact.head(), generation_two);
        drop(exact);

        fs::write(&path, generation_one_bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(
            DirectOperationCustodyStore::verify_high_water_for_test(
                &path,
                owner_uid(),
                &authority,
            )
            .is_err()
        );
        assert!(authority.is_permanent_hold());

        let other_temporary = private_tempdir();
        let other_path = other_temporary.path().join("external").join("custody.json");
        let mut local =
            DirectOperationCustodyStore::open_for_test(&other_path, owner_uid()).unwrap();
        local
            .prepare_binding(&local.head(), prepared_fixture_index(7))
            .unwrap();
        let external_rollback = TestDirectOperationCustodyHighWaterAuthority::new(
            DirectOperationCustodyHead::genesis(),
        );
        assert!(
            DirectOperationCustodyStore::verify_high_water_for_test(
                &other_path,
                owner_uid(),
                &external_rollback,
            )
            .is_err()
        );
        assert!(external_rollback.is_permanent_hold());
    }

    #[test]
    fn product_high_water_unknown_prepare_or_commit_is_a_permanent_store_hold() {
        use super::high_water::TestAuthorityFault;
        use trillionnium_os_types::direct_operation_custody_high_water::DirectOperationCustodyHighWaterOperation;

        for fault in [
            TestAuthorityFault::OutcomeUnknownBeforeApply(
                DirectOperationCustodyHighWaterOperation::Prepare,
            ),
            TestAuthorityFault::OutcomeUnknownAfterApply(
                DirectOperationCustodyHighWaterOperation::Prepare,
            ),
            TestAuthorityFault::OutcomeUnknownBeforeApply(
                DirectOperationCustodyHighWaterOperation::Commit,
            ),
            TestAuthorityFault::OutcomeUnknownAfterApply(
                DirectOperationCustodyHighWaterOperation::Commit,
            ),
        ] {
            let temporary = private_tempdir();
            let path = temporary.path().join("unknown").join("custody.json");
            let authority = TestDirectOperationCustodyHighWaterAuthority::new(
                DirectOperationCustodyHead::genesis(),
            );
            let verified = DirectOperationCustodyStore::verify_high_water_for_test(
                &path,
                owner_uid(),
                &authority,
            )
            .unwrap();
            let mut store = DirectOperationCustodyStore::open_verified_for_test(verified).unwrap();
            authority.inject_fault(fault);
            assert!(
                store
                    .prepare_binding(&store.head(), prepared_fixture())
                    .is_err()
            );
            assert!(store.high_water_permanent_hold);
            assert!(authority.is_permanent_hold());
            assert!(
                store
                    .prepare_binding(&store.head(), prepared_fixture_index(9))
                    .unwrap_err()
                    .to_string()
                    .contains("permanent_hold")
            );
        }
    }

    #[test]
    fn product_high_water_is_source_only_unwired_and_cannot_call_android_backend() {
        assert_eq!(
            FIXED_PRODUCT_CUSTODY_STORE_PATH,
            "/var/lib/trillionnium/direct-operation-custody/custody-v1.json"
        );
        let main_source = include_str!("main.rs");
        assert!(!main_source.contains("DirectOperationCustodyStore::verify_product_high_water"));
        assert!(!main_source.contains("DirectOperationCustodyStore::open_product"));
        assert!(!main_source.contains("VerifiedProductDirectOperationCustodyHighWater"));
        let source = include_str!("direct_operation_custody.rs");
        assert!(!source.contains(&["AndroidBackend", "::execute"].concat()));
        assert!(!source.contains(&["launch_", "package("].concat()));
    }

    #[test]
    fn product_custody_holds_before_store_or_high_water_without_admission_contract() {
        assert!(!transport_contract::product_admission_contract_is_complete());
        let error = match DirectOperationCustodyStore::verify_product_high_water() {
            Ok(_) => panic!("product custody unexpectedly crossed the admission boundary"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains(transport_contract::PRODUCTION_ADMISSION_HOLD_CODE),
            "unexpected product custody admission error: {error:#}"
        );
    }
}
