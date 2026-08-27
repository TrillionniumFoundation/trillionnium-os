//! Closed data ABI for a future independent Direct operation-journal mutation
//! CAS authority.
//!
//! This namespace is deliberately distinct from the HOLD-only runtime
//! authority observation carrier and from the privilege broker's provider-leaf
//! authority.  It defines canonical data and validation rules only: there is
//! no listener, client, daemon route, backend, product constructor for a
//! sealed authority capability, or effect-authorizing value in this module.

use std::error::Error;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_descriptor_registry;
use crate::direct_operation::DirectOperationAdapter;

pub const PROTOCOL: &str = "trillionnium.direct-operation-runtime-authority-mutation-cas.v1";
pub const SOCKET_NAME: &str = "trillionnium_direct_operation_runtime_authority_mutation_cas";
pub const SOCKET_ADDRESS: &str = "@trillionnium_direct_operation_runtime_authority_mutation_cas";
pub const MAXIMUM_FRAME_BYTES: usize = 128 * 1024;

pub const FIRST_USE_LINEAGE_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-first-use-lineage.v1";
pub const FIRST_USE_ANCHOR_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-first-use-anchor.v1";
pub const FIRST_USE_CANDIDATE_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-first-use-candidate.v1";
pub const FIRST_USE_PREPARED_HEAD_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-first-use-prepared-head.v1";
pub const FIRST_USE_COMMITTED_HEAD_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-first-use-committed-head.v1";
pub const FIRST_USE_COMMITTED_RESULT_BINDING_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-first-use-committed-result-binding.v1";
pub const FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-first-use-immutable-sentinel.v2";
pub const JOURNAL_VERSION_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-journal-version.v1";
pub const COMMITTED_HEAD_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-committed-head.v1";
pub const MUTATION_INTENT_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-mutation-intent.v1";
pub const PREPARED_HEAD_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-prepared-head.v1";
pub const LOCAL_PUBLICATION_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-local-publication.v1";
pub const AUTHORITY_SNAPSHOT_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-snapshot.v1";
pub const LOCAL_OBSERVATION_CONTEXT_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-local-observation-context.v1";
pub const LOCAL_ENTRY_BINDING_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-local-entry-binding.v1";
pub const LOCAL_OBSERVATION_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-local-observation.v1";
pub const PREPARE_REQUEST_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-prepare-request.v1";
pub const PREPARE_RECEIPT_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-prepare-receipt.v1";
pub const COMMIT_REQUEST_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-commit-request.v1";
pub const COMMIT_RECEIPT_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-commit-receipt.v1";
pub const OBSERVE_REQUEST_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-observe-request.v1";
pub const OBSERVE_RESPONSE_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-observe-response.v1";
pub const RECONCILE_REQUEST_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-reconcile-request.v1";
pub const RECONCILE_RESPONSE_V1_SCHEMA: &str =
    "trillionnium.direct-operation-runtime-authority-reconcile-response.v1";

pub const PREPARE_OPERATION: &str = "prepare_operation_journal_mutation";
pub const COMMIT_OPERATION: &str = "commit_operation_journal_mutation";
pub const OBSERVE_OPERATION: &str = "observe_committed_operation_journal_head";
pub const RECONCILE_OPERATION: &str = "reconcile_uncertain_operation_journal_mutation";

pub const NAMED_JOURNAL_ENTRY_DOMAIN: &str =
    "trillionnium.operation-journal.entry.named-journal.v1";
pub const STAGED_CANDIDATE_ENTRY_DOMAIN: &str =
    "trillionnium.operation-journal.entry.staged-candidate.v1";

pub const SOURCE_DATA_ABI_IMPLEMENTED: bool = true;
pub const AUTHORITY_BACKEND_PRODUCT_AVAILABLE: bool = false;
pub const ADAPTER_CLIENT_PRODUCT_WIRED: bool = false;
pub const DAEMON_LISTENER_PRODUCT_WIRED: bool = false;
pub const PREPARE_PRODUCT_AVAILABLE: bool = false;
pub const COMMIT_PRODUCT_AVAILABLE: bool = false;
pub const OBSERVE_PRODUCT_AVAILABLE: bool = false;
pub const RECONCILE_PRODUCT_AVAILABLE: bool = false;
pub const MUTATION_CAS_PRODUCT_AVAILABLE: bool = false;
pub const CONFERS_FIRST_USE_AUTHORITY: bool = false;
pub const CONFERS_REPLAY_AUTHORITY: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

const JOURNAL_EPOCH_HEX_BYTES: usize = 32;

pub type DirectOperationRuntimeAuthorityMutationCasResult<T> =
    Result<T, DirectOperationRuntimeAuthorityMutationCasError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectOperationRuntimeAuthorityMutationCasError(&'static str);

impl DirectOperationRuntimeAuthorityMutationCasError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DirectOperationRuntimeAuthorityMutationCasError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for DirectOperationRuntimeAuthorityMutationCasError {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityFirstUseAnchorV1 {
    pub schema: String,
    pub protocol: String,
    pub authority_identity_sha256: String,
    pub authority_store_instance_sha256: String,
    pub provision_epoch_sha256: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub journal_epoch: String,
    pub state_directory_identity_sha256: String,
    pub genesis_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub immutable_sentinel_schema: String,
    pub immutable_sentinel_embeds_prepared_head: bool,
    pub sentinel_identity_sha256: String,
    pub sentinel_bytes_sha256: String,
    pub first_use_anchor_sha256: String,
}

impl DirectOperationRuntimeAuthorityFirstUseAnchorV1 {
    pub fn validate(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.genesis_journal_version.validate()?;
        if self.schema != FIRST_USE_ANCHOR_V1_SCHEMA
            || self.protocol != PROTOCOL
            || agent_descriptor_registry::from_provider_agent_pair(
                &self.provider_id,
                &self.agent_id,
            )
            .is_none()
            || !valid_journal_epoch(&self.journal_epoch)
            || self.immutable_sentinel_schema != FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA
            || self.immutable_sentinel_embeds_prepared_head
            || ![
                &self.authority_identity_sha256,
                &self.authority_store_instance_sha256,
                &self.provision_epoch_sha256,
                &self.state_directory_identity_sha256,
                &self.sentinel_identity_sha256,
                &self.sentinel_bytes_sha256,
                &self.first_use_anchor_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
            || self.canonical_immutable_sentinel_bytes_sha256()? != self.sentinel_bytes_sha256
            || self.canonical_sha256()? != self.first_use_anchor_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_anchor_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        self.genesis_journal_version.validate()?;
        if self.schema != FIRST_USE_ANCHOR_V1_SCHEMA
            || self.protocol != PROTOCOL
            || agent_descriptor_registry::from_provider_agent_pair(
                &self.provider_id,
                &self.agent_id,
            )
            .is_none()
            || !valid_journal_epoch(&self.journal_epoch)
            || self.immutable_sentinel_schema != FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA
            || self.immutable_sentinel_embeds_prepared_head
            || ![
                &self.authority_identity_sha256,
                &self.authority_store_instance_sha256,
                &self.provision_epoch_sha256,
                &self.state_directory_identity_sha256,
                &self.sentinel_identity_sha256,
                &self.sentinel_bytes_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
            || self.canonical_immutable_sentinel_bytes_sha256()? != self.sentinel_bytes_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_anchor_denied",
            ));
        }
        let mut hasher = domain_hasher(FIRST_USE_ANCHOR_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "authority_identity_sha256",
                self.authority_identity_sha256.as_str(),
            ),
            (
                "authority_store_instance_sha256",
                self.authority_store_instance_sha256.as_str(),
            ),
            (
                "provision_epoch_sha256",
                self.provision_epoch_sha256.as_str(),
            ),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("adapter", self.adapter.adapter_id()),
            ("journal_epoch", self.journal_epoch.as_str()),
            (
                "state_directory_identity_sha256",
                self.state_directory_identity_sha256.as_str(),
            ),
            (
                "genesis_journal_version_sha256",
                self.genesis_journal_version.journal_version_sha256.as_str(),
            ),
            (
                "immutable_sentinel_schema",
                self.immutable_sentinel_schema.as_str(),
            ),
            ("immutable_sentinel_embeds_prepared_head", "false"),
            (
                "sentinel_identity_sha256",
                self.sentinel_identity_sha256.as_str(),
            ),
            ("sentinel_bytes_sha256", self.sentinel_bytes_sha256.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    /// Canonical bytes for the pre-staged immutable sentinel v2. The field set
    /// intentionally has no candidate or prepared-head digest, avoiding a
    /// PREPARED ↔ sentinel construction cycle.
    pub fn canonical_immutable_sentinel_bytes(
        &self,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<Vec<u8>> {
        self.genesis_journal_version.validate()?;
        if self.protocol != PROTOCOL
            || self.immutable_sentinel_schema != FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA
            || self.immutable_sentinel_embeds_prepared_head
            || agent_descriptor_registry::from_provider_agent_pair(
                &self.provider_id,
                &self.agent_id,
            )
            .is_none()
            || !valid_journal_epoch(&self.journal_epoch)
            || ![
                &self.authority_identity_sha256,
                &self.authority_store_instance_sha256,
                &self.provision_epoch_sha256,
                &self.state_directory_identity_sha256,
                &self.genesis_journal_version.journal_version_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_sentinel_denied",
            ));
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.as_bytes());
        bytes.push(0);
        for (name, value) in [
            ("schema", self.immutable_sentinel_schema.as_str()),
            ("protocol", self.protocol.as_str()),
            ("phase", "pre_staged_immutable"),
            ("prepared_head_embedded", "false"),
            (
                "authority_identity_sha256",
                self.authority_identity_sha256.as_str(),
            ),
            (
                "authority_store_instance_sha256",
                self.authority_store_instance_sha256.as_str(),
            ),
            (
                "provision_epoch_sha256",
                self.provision_epoch_sha256.as_str(),
            ),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("adapter", self.adapter.adapter_id()),
            ("journal_epoch", self.journal_epoch.as_str()),
            (
                "state_directory_identity_sha256",
                self.state_directory_identity_sha256.as_str(),
            ),
            (
                "genesis_journal_version_sha256",
                self.genesis_journal_version.journal_version_sha256.as_str(),
            ),
        ] {
            append_framed_bytes(&mut bytes, name.as_bytes(), value.as_bytes())?;
        }
        Ok(bytes)
    }

    pub fn canonical_immutable_sentinel_bytes_sha256(
        &self,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        Ok(lower_hex(&Sha256::digest(
            self.canonical_immutable_sentinel_bytes()?,
        )))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityFirstUseCandidateV1 {
    pub schema: String,
    pub protocol: String,
    pub first_use_anchor_sha256: String,
    pub proposed_genesis_journal_version_sha256: String,
    pub candidate_nonce_sha256: String,
    pub first_use_candidate_sha256: String,
}

impl DirectOperationRuntimeAuthorityFirstUseCandidateV1 {
    fn validate_integrity(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        if self.schema != FIRST_USE_CANDIDATE_V1_SCHEMA
            || self.protocol != PROTOCOL
            || ![
                &self.first_use_anchor_sha256,
                &self.proposed_genesis_journal_version_sha256,
                &self.candidate_nonce_sha256,
                &self.first_use_candidate_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
            || self.canonical_sha256()? != self.first_use_candidate_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_candidate_denied",
            ));
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        anchor: &DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        anchor.validate()?;
        self.validate_integrity()?;
        if self.first_use_anchor_sha256 != anchor.first_use_anchor_sha256
            || self.proposed_genesis_journal_version_sha256
                != anchor.genesis_journal_version.journal_version_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_candidate_anchor_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        if self.schema != FIRST_USE_CANDIDATE_V1_SCHEMA
            || self.protocol != PROTOCOL
            || ![
                &self.first_use_anchor_sha256,
                &self.proposed_genesis_journal_version_sha256,
                &self.candidate_nonce_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_candidate_denied",
            ));
        }
        let mut hasher = domain_hasher(FIRST_USE_CANDIDATE_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "first_use_anchor_sha256",
                self.first_use_anchor_sha256.as_str(),
            ),
            (
                "proposed_genesis_journal_version_sha256",
                self.proposed_genesis_journal_version_sha256.as_str(),
            ),
            (
                "candidate_nonce_sha256",
                self.candidate_nonce_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1 {
    pub schema: String,
    pub protocol: String,
    pub first_use_anchor_sha256: String,
    pub first_use_candidate_sha256: String,
    pub prepared_genesis_journal_version_sha256: String,
    pub prepared_sentinel_identity_sha256: String,
    pub prepared_sentinel_bytes_sha256: String,
    pub prepare_nonce_sha256: String,
    pub first_use_prepared_head_sha256: String,
}

impl DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1 {
    fn validate_integrity(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        if self.schema != FIRST_USE_PREPARED_HEAD_V1_SCHEMA
            || self.protocol != PROTOCOL
            || ![
                &self.first_use_anchor_sha256,
                &self.first_use_candidate_sha256,
                &self.prepared_genesis_journal_version_sha256,
                &self.prepared_sentinel_identity_sha256,
                &self.prepared_sentinel_bytes_sha256,
                &self.prepare_nonce_sha256,
                &self.first_use_prepared_head_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
            || self.canonical_sha256()? != self.first_use_prepared_head_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_prepared_denied",
            ));
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        anchor: &DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        candidate: &DirectOperationRuntimeAuthorityFirstUseCandidateV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        candidate.validate_for(anchor)?;
        self.validate_integrity()?;
        if self.first_use_anchor_sha256 != anchor.first_use_anchor_sha256
            || self.first_use_candidate_sha256 != candidate.first_use_candidate_sha256
            || self.prepared_genesis_journal_version_sha256
                != anchor.genesis_journal_version.journal_version_sha256
            || self.prepared_sentinel_identity_sha256 != anchor.sentinel_identity_sha256
            || self.prepared_sentinel_bytes_sha256 != anchor.sentinel_bytes_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_prepared_chain_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        if self.schema != FIRST_USE_PREPARED_HEAD_V1_SCHEMA
            || self.protocol != PROTOCOL
            || ![
                &self.first_use_anchor_sha256,
                &self.first_use_candidate_sha256,
                &self.prepared_genesis_journal_version_sha256,
                &self.prepared_sentinel_identity_sha256,
                &self.prepared_sentinel_bytes_sha256,
                &self.prepare_nonce_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_prepared_denied",
            ));
        }
        let mut hasher = domain_hasher(FIRST_USE_PREPARED_HEAD_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "first_use_anchor_sha256",
                self.first_use_anchor_sha256.as_str(),
            ),
            (
                "first_use_candidate_sha256",
                self.first_use_candidate_sha256.as_str(),
            ),
            (
                "prepared_genesis_journal_version_sha256",
                self.prepared_genesis_journal_version_sha256.as_str(),
            ),
            (
                "prepared_sentinel_identity_sha256",
                self.prepared_sentinel_identity_sha256.as_str(),
            ),
            (
                "prepared_sentinel_bytes_sha256",
                self.prepared_sentinel_bytes_sha256.as_str(),
            ),
            ("prepare_nonce_sha256", self.prepare_nonce_sha256.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1 {
    pub schema: String,
    pub protocol: String,
    pub first_use_anchor_sha256: String,
    pub first_use_candidate_sha256: String,
    pub first_use_prepared_head_sha256: String,
    pub committed_genesis_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub committed_sentinel_identity_sha256: String,
    pub committed_sentinel_bytes_sha256: String,
    pub durable_commit_evidence_sha256: String,
    pub first_use_committed_head_sha256: String,
}

impl DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1 {
    fn validate_integrity(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.committed_genesis_journal_version.validate()?;
        if self.schema != FIRST_USE_COMMITTED_HEAD_V1_SCHEMA
            || self.protocol != PROTOCOL
            || ![
                &self.first_use_anchor_sha256,
                &self.first_use_candidate_sha256,
                &self.first_use_prepared_head_sha256,
                &self.committed_sentinel_identity_sha256,
                &self.committed_sentinel_bytes_sha256,
                &self.durable_commit_evidence_sha256,
                &self.first_use_committed_head_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
            || self.canonical_sha256()? != self.first_use_committed_head_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_committed_head_denied",
            ));
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        anchor: &DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        candidate: &DirectOperationRuntimeAuthorityFirstUseCandidateV1,
        prepared: &DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        prepared.validate_for(anchor, candidate)?;
        self.validate_integrity()?;
        if self.first_use_anchor_sha256 != anchor.first_use_anchor_sha256
            || self.first_use_candidate_sha256 != candidate.first_use_candidate_sha256
            || self.first_use_prepared_head_sha256 != prepared.first_use_prepared_head_sha256
            || self.committed_genesis_journal_version != anchor.genesis_journal_version
            || self.committed_sentinel_identity_sha256 != anchor.sentinel_identity_sha256
            || self.committed_sentinel_bytes_sha256 != anchor.sentinel_bytes_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_committed_chain_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        self.committed_genesis_journal_version.validate()?;
        if self.schema != FIRST_USE_COMMITTED_HEAD_V1_SCHEMA
            || self.protocol != PROTOCOL
            || ![
                &self.first_use_anchor_sha256,
                &self.first_use_candidate_sha256,
                &self.first_use_prepared_head_sha256,
                &self.committed_sentinel_identity_sha256,
                &self.committed_sentinel_bytes_sha256,
                &self.durable_commit_evidence_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_committed_head_denied",
            ));
        }
        let mut hasher = domain_hasher(FIRST_USE_COMMITTED_HEAD_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "first_use_anchor_sha256",
                self.first_use_anchor_sha256.as_str(),
            ),
            (
                "first_use_candidate_sha256",
                self.first_use_candidate_sha256.as_str(),
            ),
            (
                "first_use_prepared_head_sha256",
                self.first_use_prepared_head_sha256.as_str(),
            ),
            (
                "committed_genesis_journal_version_sha256",
                self.committed_genesis_journal_version
                    .journal_version_sha256
                    .as_str(),
            ),
            (
                "committed_sentinel_identity_sha256",
                self.committed_sentinel_identity_sha256.as_str(),
            ),
            (
                "committed_sentinel_bytes_sha256",
                self.committed_sentinel_bytes_sha256.as_str(),
            ),
            (
                "durable_commit_evidence_sha256",
                self.durable_commit_evidence_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityFirstUseCommittedResultBindingV1 {
    pub schema: String,
    pub protocol: String,
    pub first_use_anchor_sha256: String,
    pub first_use_candidate_sha256: String,
    pub first_use_prepared_head_sha256: String,
    pub first_use_committed_head_sha256: String,
    pub committed_genesis_journal_version_sha256: String,
    pub committed_sentinel_identity_sha256: String,
    pub committed_sentinel_bytes_sha256: String,
    pub durable_commit_evidence_sha256: String,
    pub result_receipt_sha256: String,
    pub first_use_committed_result_binding_sha256: String,
}

impl DirectOperationRuntimeAuthorityFirstUseCommittedResultBindingV1 {
    fn validate_integrity(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        if self.schema != FIRST_USE_COMMITTED_RESULT_BINDING_V1_SCHEMA
            || self.protocol != PROTOCOL
            || ![
                &self.first_use_anchor_sha256,
                &self.first_use_candidate_sha256,
                &self.first_use_prepared_head_sha256,
                &self.first_use_committed_head_sha256,
                &self.committed_genesis_journal_version_sha256,
                &self.committed_sentinel_identity_sha256,
                &self.committed_sentinel_bytes_sha256,
                &self.durable_commit_evidence_sha256,
                &self.result_receipt_sha256,
                &self.first_use_committed_result_binding_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
            || self.canonical_sha256()? != self.first_use_committed_result_binding_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_result_binding_denied",
            ));
        }
        Ok(())
    }

    pub fn validate_for(
        &self,
        anchor: &DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        candidate: &DirectOperationRuntimeAuthorityFirstUseCandidateV1,
        prepared: &DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
        committed: &DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        committed.validate_for(anchor, candidate, prepared)?;
        self.validate_integrity()?;
        if self.first_use_anchor_sha256 != anchor.first_use_anchor_sha256
            || self.first_use_candidate_sha256 != candidate.first_use_candidate_sha256
            || self.first_use_prepared_head_sha256 != prepared.first_use_prepared_head_sha256
            || self.first_use_committed_head_sha256 != committed.first_use_committed_head_sha256
            || self.committed_genesis_journal_version_sha256
                != anchor.genesis_journal_version.journal_version_sha256
            || self.committed_sentinel_identity_sha256 != anchor.sentinel_identity_sha256
            || self.committed_sentinel_bytes_sha256 != anchor.sentinel_bytes_sha256
            || self.durable_commit_evidence_sha256 != committed.durable_commit_evidence_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_result_chain_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        if self.schema != FIRST_USE_COMMITTED_RESULT_BINDING_V1_SCHEMA
            || self.protocol != PROTOCOL
            || ![
                &self.first_use_anchor_sha256,
                &self.first_use_candidate_sha256,
                &self.first_use_prepared_head_sha256,
                &self.first_use_committed_head_sha256,
                &self.committed_genesis_journal_version_sha256,
                &self.committed_sentinel_identity_sha256,
                &self.committed_sentinel_bytes_sha256,
                &self.durable_commit_evidence_sha256,
                &self.result_receipt_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied(
                "direct_operation_mutation_cas_first_use_result_binding_denied",
            ));
        }
        let mut hasher = domain_hasher(FIRST_USE_COMMITTED_RESULT_BINDING_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "first_use_anchor_sha256",
                self.first_use_anchor_sha256.as_str(),
            ),
            (
                "first_use_candidate_sha256",
                self.first_use_candidate_sha256.as_str(),
            ),
            (
                "first_use_prepared_head_sha256",
                self.first_use_prepared_head_sha256.as_str(),
            ),
            (
                "first_use_committed_head_sha256",
                self.first_use_committed_head_sha256.as_str(),
            ),
            (
                "committed_genesis_journal_version_sha256",
                self.committed_genesis_journal_version_sha256.as_str(),
            ),
            (
                "committed_sentinel_identity_sha256",
                self.committed_sentinel_identity_sha256.as_str(),
            ),
            (
                "committed_sentinel_bytes_sha256",
                self.committed_sentinel_bytes_sha256.as_str(),
            ),
            (
                "durable_commit_evidence_sha256",
                self.durable_commit_evidence_sha256.as_str(),
            ),
            ("result_receipt_sha256", self.result_receipt_sha256.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityFirstUseLineageV1 {
    pub schema: String,
    pub protocol: String,
    pub anchor: DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    pub candidate: DirectOperationRuntimeAuthorityFirstUseCandidateV1,
    pub prepared_head: DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1,
    pub committed_head: DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1,
    pub committed_result_binding: DirectOperationRuntimeAuthorityFirstUseCommittedResultBindingV1,
    pub first_use_lineage_sha256: String,
}

impl DirectOperationRuntimeAuthorityFirstUseLineageV1 {
    pub fn validate(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.anchor.validate()?;
        self.candidate.validate_for(&self.anchor)?;
        self.prepared_head
            .validate_for(&self.anchor, &self.candidate)?;
        self.committed_head
            .validate_for(&self.anchor, &self.candidate, &self.prepared_head)?;
        self.committed_result_binding.validate_for(
            &self.anchor,
            &self.candidate,
            &self.prepared_head,
            &self.committed_head,
        )?;
        if self.schema != FIRST_USE_LINEAGE_V1_SCHEMA
            || self.protocol != PROTOCOL
            || !valid_nonzero_sha256(&self.first_use_lineage_sha256)
            || self.canonical_sha256()? != self.first_use_lineage_sha256
        {
            return Err(denied("direct_operation_mutation_cas_lineage_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        self.anchor.validate()?;
        self.candidate.validate_integrity()?;
        self.prepared_head.validate_integrity()?;
        self.committed_head.validate_integrity()?;
        self.committed_result_binding.validate_integrity()?;
        if self.schema != FIRST_USE_LINEAGE_V1_SCHEMA || self.protocol != PROTOCOL {
            return Err(denied("direct_operation_mutation_cas_lineage_denied"));
        }
        let mut hasher = domain_hasher(FIRST_USE_LINEAGE_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "first_use_anchor_sha256",
                self.anchor.first_use_anchor_sha256.as_str(),
            ),
            (
                "first_use_candidate_sha256",
                self.candidate.first_use_candidate_sha256.as_str(),
            ),
            (
                "first_use_prepared_head_sha256",
                self.prepared_head.first_use_prepared_head_sha256.as_str(),
            ),
            (
                "first_use_committed_head_sha256",
                self.committed_head.first_use_committed_head_sha256.as_str(),
            ),
            (
                "first_use_committed_result_binding_sha256",
                self.committed_result_binding
                    .first_use_committed_result_binding_sha256
                    .as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityJournalVersionV1 {
    pub schema: String,
    pub protocol: String,
    pub journal_identity_sha256: String,
    pub journal_bytes_sha256: String,
    pub journal_version_sha256: String,
}

impl DirectOperationRuntimeAuthorityJournalVersionV1 {
    pub fn validate(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        if self.schema != JOURNAL_VERSION_V1_SCHEMA
            || self.protocol != PROTOCOL
            || !valid_nonzero_sha256(&self.journal_identity_sha256)
            || !valid_nonzero_sha256(&self.journal_bytes_sha256)
            || !valid_nonzero_sha256(&self.journal_version_sha256)
            || self.canonical_sha256()? != self.journal_version_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_journal_version_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        if self.schema != JOURNAL_VERSION_V1_SCHEMA
            || self.protocol != PROTOCOL
            || !valid_nonzero_sha256(&self.journal_identity_sha256)
            || !valid_nonzero_sha256(&self.journal_bytes_sha256)
        {
            return Err(denied(
                "direct_operation_mutation_cas_journal_version_denied",
            ));
        }
        let mut hasher = domain_hasher(JOURNAL_VERSION_V1_SCHEMA);
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(
            &mut hasher,
            "journal_identity_sha256",
            &self.journal_identity_sha256,
        )?;
        hash_string(
            &mut hasher,
            "journal_bytes_sha256",
            &self.journal_bytes_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectOperationRuntimeAuthorityHeadAncestryV1 {
    Genesis {
        first_use_committed_result_binding_sha256: String,
    },
    Successor {
        predecessor_committed_head_sha256: String,
        prepared_head_sha256: String,
    },
}

impl DirectOperationRuntimeAuthorityHeadAncestryV1 {
    fn validate(
        &self,
        generation: u64,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        match self {
            Self::Genesis {
                first_use_committed_result_binding_sha256,
            } if generation == 1
                && first_use_committed_result_binding_sha256
                    == &lineage
                        .committed_result_binding
                        .first_use_committed_result_binding_sha256 =>
            {
                Ok(())
            }
            Self::Successor {
                predecessor_committed_head_sha256,
                prepared_head_sha256,
            } if generation > 1
                && valid_nonzero_sha256(predecessor_committed_head_sha256)
                && valid_nonzero_sha256(prepared_head_sha256) =>
            {
                Ok(())
            }
            _ => Err(denied("direct_operation_mutation_cas_head_ancestry_denied")),
        }
    }

    fn hash_into(
        &self,
        hasher: &mut Sha256,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        match self {
            Self::Genesis {
                first_use_committed_result_binding_sha256,
            } => {
                hash_string(hasher, "ancestry_kind", "genesis")?;
                hash_string(
                    hasher,
                    "first_use_committed_result_binding_sha256",
                    first_use_committed_result_binding_sha256,
                )
            }
            Self::Successor {
                predecessor_committed_head_sha256,
                prepared_head_sha256,
            } => {
                hash_string(hasher, "ancestry_kind", "successor")?;
                hash_string(
                    hasher,
                    "predecessor_committed_head_sha256",
                    predecessor_committed_head_sha256,
                )?;
                hash_string(hasher, "prepared_head_sha256", prepared_head_sha256)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityCommittedHeadV1 {
    pub schema: String,
    pub protocol: String,
    pub authority_identity_sha256: String,
    pub authority_store_instance_sha256: String,
    pub first_use_lineage_sha256: String,
    pub provider_id: String,
    pub agent_id: String,
    pub adapter: DirectOperationAdapter,
    pub journal_epoch: String,
    pub state_directory_identity_sha256: String,
    pub mutation_generation: u64,
    pub journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub ancestry: DirectOperationRuntimeAuthorityHeadAncestryV1,
    pub committed_head_sha256: String,
}

impl DirectOperationRuntimeAuthorityCommittedHeadV1 {
    pub fn validate(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        lineage.validate()?;
        self.journal_version.validate()?;
        self.ancestry.validate(self.mutation_generation, lineage)?;
        if self.schema != COMMITTED_HEAD_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.authority_identity_sha256 != lineage.anchor.authority_identity_sha256
            || self.authority_store_instance_sha256
                != lineage.anchor.authority_store_instance_sha256
            || self.first_use_lineage_sha256 != lineage.first_use_lineage_sha256
            || self.provider_id != lineage.anchor.provider_id
            || self.agent_id != lineage.anchor.agent_id
            || self.adapter != lineage.anchor.adapter
            || self.journal_epoch != lineage.anchor.journal_epoch
            || self.state_directory_identity_sha256
                != lineage.anchor.state_directory_identity_sha256
            || self.mutation_generation == 0
            || (self.mutation_generation == 1
                && (self.journal_version.journal_identity_sha256
                    != lineage
                        .anchor
                        .genesis_journal_version
                        .journal_identity_sha256
                    || self.journal_version.journal_bytes_sha256
                        != lineage.anchor.genesis_journal_version.journal_bytes_sha256))
            || !valid_nonzero_sha256(&self.committed_head_sha256)
            || self.canonical_sha256()? != self.committed_head_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_committed_head_denied",
            ));
        }
        Ok(())
    }

    pub fn validate_successor(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        predecessor: &Self,
        prepared: &DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.validate(lineage)?;
        predecessor.validate(lineage)?;
        prepared.validate_for_head(lineage, predecessor)?;
        let expected_generation = predecessor
            .mutation_generation
            .checked_add(1)
            .ok_or_else(|| denied("direct_operation_mutation_cas_generation_denied"))?;
        let expected_ancestry = DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
            predecessor_committed_head_sha256: predecessor.committed_head_sha256.clone(),
            prepared_head_sha256: prepared.prepared_head_sha256.clone(),
        };
        if self.mutation_generation != expected_generation
            || self.journal_version != prepared.proposed_journal_version
            || self.ancestry != expected_ancestry
        {
            return Err(denied("direct_operation_mutation_cas_successor_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        self.journal_version.validate()?;
        if self.schema != COMMITTED_HEAD_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.mutation_generation == 0
            || !valid_journal_epoch(&self.journal_epoch)
            || agent_descriptor_registry::from_provider_agent_pair(
                &self.provider_id,
                &self.agent_id,
            )
            .is_none()
            || ![
                &self.authority_identity_sha256,
                &self.authority_store_instance_sha256,
                &self.first_use_lineage_sha256,
                &self.state_directory_identity_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied(
                "direct_operation_mutation_cas_committed_head_denied",
            ));
        }
        let mut hasher = domain_hasher(COMMITTED_HEAD_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "authority_identity_sha256",
                self.authority_identity_sha256.as_str(),
            ),
            (
                "authority_store_instance_sha256",
                self.authority_store_instance_sha256.as_str(),
            ),
            (
                "first_use_lineage_sha256",
                self.first_use_lineage_sha256.as_str(),
            ),
            ("provider_id", self.provider_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("adapter", self.adapter.adapter_id()),
            ("journal_epoch", self.journal_epoch.as_str()),
            (
                "state_directory_identity_sha256",
                self.state_directory_identity_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u64(&mut hasher, "mutation_generation", self.mutation_generation)?;
        hash_string(
            &mut hasher,
            "journal_version_sha256",
            &self.journal_version.journal_version_sha256,
        )?;
        self.ancestry.hash_into(&mut hasher)?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationRuntimeAuthorityMutationKindV1 {
    BeginEffect,
    PersistPreparedTransportAck,
    RecordClassifiedResult,
    /// ABI-stable V1 CAS mutation-class label. It carries no ACK body and does
    /// not parse or authorize the retired V2 ACK schema; the caller admits
    /// only a V3 ACK before proposing the exact successor journal digest.
    AcknowledgeOuterV2,
}

impl DirectOperationRuntimeAuthorityMutationKindV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BeginEffect => "begin_effect",
            Self::PersistPreparedTransportAck => "persist_prepared_transport_ack",
            Self::RecordClassifiedResult => "record_classified_result",
            Self::AcknowledgeOuterV2 => "acknowledge_outer_v2",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityMutationIntentV1 {
    pub schema: String,
    pub protocol: String,
    pub authority_store_instance_sha256: String,
    pub first_use_lineage_sha256: String,
    pub from_committed_head_sha256: String,
    pub from_mutation_generation: u64,
    pub mutation_kind: DirectOperationRuntimeAuthorityMutationKindV1,
    pub expected_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub observed_current_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub to_mutation_generation: u64,
    pub proposed_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub mutation_nonce_sha256: String,
    pub mutation_intent_sha256: String,
}

impl DirectOperationRuntimeAuthorityMutationIntentV1 {
    pub fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        lineage.validate()?;
        current.validate(lineage)?;
        self.expected_journal_version.validate()?;
        self.observed_current_journal_version.validate()?;
        self.proposed_journal_version.validate()?;
        let expected_next_generation = next_mutation_generation(self.from_mutation_generation)?;
        if self.schema != MUTATION_INTENT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.authority_store_instance_sha256
                != lineage.anchor.authority_store_instance_sha256
            || self.first_use_lineage_sha256 != lineage.first_use_lineage_sha256
            || self.from_committed_head_sha256 != current.committed_head_sha256
            || self.from_mutation_generation != current.mutation_generation
            || self.expected_journal_version != current.journal_version
            || self.observed_current_journal_version != self.expected_journal_version
            || self.to_mutation_generation != expected_next_generation
            || self.proposed_journal_version.journal_identity_sha256
                == self.expected_journal_version.journal_identity_sha256
            || self.proposed_journal_version.journal_bytes_sha256
                == self.expected_journal_version.journal_bytes_sha256
            || !valid_nonzero_sha256(&self.mutation_nonce_sha256)
            || !valid_nonzero_sha256(&self.mutation_intent_sha256)
            || self.canonical_sha256()? != self.mutation_intent_sha256
        {
            return Err(denied("direct_operation_mutation_cas_intent_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        self.expected_journal_version.validate()?;
        self.observed_current_journal_version.validate()?;
        self.proposed_journal_version.validate()?;
        let expected_next_generation = next_mutation_generation(self.from_mutation_generation)?;
        if self.schema != MUTATION_INTENT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.from_mutation_generation == 0
            || self.to_mutation_generation != expected_next_generation
            || ![
                &self.authority_store_instance_sha256,
                &self.first_use_lineage_sha256,
                &self.from_committed_head_sha256,
                &self.mutation_nonce_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied("direct_operation_mutation_cas_intent_denied"));
        }
        let mut hasher = domain_hasher(MUTATION_INTENT_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "authority_store_instance_sha256",
                self.authority_store_instance_sha256.as_str(),
            ),
            (
                "first_use_lineage_sha256",
                self.first_use_lineage_sha256.as_str(),
            ),
            (
                "from_committed_head_sha256",
                self.from_committed_head_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u64(
            &mut hasher,
            "from_mutation_generation",
            self.from_mutation_generation,
        )?;
        hash_string(&mut hasher, "mutation_kind", self.mutation_kind.as_str())?;
        hash_string(
            &mut hasher,
            "expected_journal_version_sha256",
            &self.expected_journal_version.journal_version_sha256,
        )?;
        hash_string(
            &mut hasher,
            "observed_current_journal_version_sha256",
            &self.observed_current_journal_version.journal_version_sha256,
        )?;
        hash_u64(
            &mut hasher,
            "to_mutation_generation",
            self.to_mutation_generation,
        )?;
        hash_string(
            &mut hasher,
            "proposed_journal_version_sha256",
            &self.proposed_journal_version.journal_version_sha256,
        )?;
        hash_string(
            &mut hasher,
            "mutation_nonce_sha256",
            &self.mutation_nonce_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityPreparedHeadV1 {
    pub schema: String,
    pub protocol: String,
    pub authority_identity_sha256: String,
    pub authority_store_instance_sha256: String,
    pub first_use_lineage_sha256: String,
    pub from_committed_head_sha256: String,
    pub from_mutation_generation: u64,
    pub to_mutation_generation: u64,
    pub mutation_intent_sha256: String,
    pub expected_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub proposed_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub prepared_head_sha256: String,
}

impl DirectOperationRuntimeAuthorityPreparedHeadV1 {
    pub fn validate_for_head(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        lineage.validate()?;
        current.validate(lineage)?;
        self.expected_journal_version.validate()?;
        self.proposed_journal_version.validate()?;
        let expected_next_generation = next_mutation_generation(self.from_mutation_generation)?;
        if self.schema != PREPARED_HEAD_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.authority_identity_sha256 != lineage.anchor.authority_identity_sha256
            || self.authority_store_instance_sha256
                != lineage.anchor.authority_store_instance_sha256
            || self.first_use_lineage_sha256 != lineage.first_use_lineage_sha256
            || self.from_committed_head_sha256 != current.committed_head_sha256
            || self.from_mutation_generation != current.mutation_generation
            || self.to_mutation_generation != expected_next_generation
            || self.expected_journal_version != current.journal_version
            || !valid_nonzero_sha256(&self.mutation_intent_sha256)
            || !valid_nonzero_sha256(&self.prepared_head_sha256)
            || self.canonical_sha256()? != self.prepared_head_sha256
        {
            return Err(denied("direct_operation_mutation_cas_prepared_head_denied"));
        }
        Ok(())
    }

    pub fn validate_for_intent(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: &DirectOperationRuntimeAuthorityMutationIntentV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.validate_for_head(lineage, current)?;
        intent.validate_for(lineage, current)?;
        if self.mutation_intent_sha256 != intent.mutation_intent_sha256
            || self.expected_journal_version != intent.expected_journal_version
            || self.proposed_journal_version != intent.proposed_journal_version
            || self.to_mutation_generation != intent.to_mutation_generation
        {
            return Err(denied(
                "direct_operation_mutation_cas_prepared_intent_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        self.expected_journal_version.validate()?;
        self.proposed_journal_version.validate()?;
        let expected_next_generation = next_mutation_generation(self.from_mutation_generation)?;
        if self.schema != PREPARED_HEAD_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.from_mutation_generation == 0
            || self.to_mutation_generation != expected_next_generation
            || ![
                &self.authority_identity_sha256,
                &self.authority_store_instance_sha256,
                &self.first_use_lineage_sha256,
                &self.from_committed_head_sha256,
                &self.mutation_intent_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied("direct_operation_mutation_cas_prepared_head_denied"));
        }
        let mut hasher = domain_hasher(PREPARED_HEAD_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            (
                "authority_identity_sha256",
                self.authority_identity_sha256.as_str(),
            ),
            (
                "authority_store_instance_sha256",
                self.authority_store_instance_sha256.as_str(),
            ),
            (
                "first_use_lineage_sha256",
                self.first_use_lineage_sha256.as_str(),
            ),
            (
                "from_committed_head_sha256",
                self.from_committed_head_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        hash_u64(
            &mut hasher,
            "from_mutation_generation",
            self.from_mutation_generation,
        )?;
        hash_u64(
            &mut hasher,
            "to_mutation_generation",
            self.to_mutation_generation,
        )?;
        hash_string(
            &mut hasher,
            "mutation_intent_sha256",
            &self.mutation_intent_sha256,
        )?;
        hash_string(
            &mut hasher,
            "expected_journal_version_sha256",
            &self.expected_journal_version.journal_version_sha256,
        )?;
        hash_string(
            &mut hasher,
            "proposed_journal_version_sha256",
            &self.proposed_journal_version.journal_version_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityLocalPublicationV1 {
    pub schema: String,
    pub protocol: String,
    pub first_use_lineage_sha256: String,
    pub prepared_head_sha256: String,
    pub mutation_generation: u64,
    pub state_directory_identity_sha256: String,
    pub writer_lock_identity_sha256: String,
    pub named_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub local_publication_sha256: String,
}

impl DirectOperationRuntimeAuthorityLocalPublicationV1 {
    pub fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        prepared: &DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        lineage.validate()?;
        self.named_journal_version.validate()?;
        if self.schema != LOCAL_PUBLICATION_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.first_use_lineage_sha256 != lineage.first_use_lineage_sha256
            || self.prepared_head_sha256 != prepared.prepared_head_sha256
            || self.mutation_generation != prepared.to_mutation_generation
            || self.state_directory_identity_sha256
                != lineage.anchor.state_directory_identity_sha256
            || !valid_nonzero_sha256(&self.writer_lock_identity_sha256)
            || self.named_journal_version != prepared.proposed_journal_version
            || !valid_nonzero_sha256(&self.local_publication_sha256)
            || self.canonical_sha256()? != self.local_publication_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_local_publication_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        self.named_journal_version.validate()?;
        if self.schema != LOCAL_PUBLICATION_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.mutation_generation == 0
            || ![
                &self.first_use_lineage_sha256,
                &self.prepared_head_sha256,
                &self.state_directory_identity_sha256,
                &self.writer_lock_identity_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied(
                "direct_operation_mutation_cas_local_publication_denied",
            ));
        }
        let mut hasher = domain_hasher(LOCAL_PUBLICATION_V1_SCHEMA);
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(
            &mut hasher,
            "first_use_lineage_sha256",
            &self.first_use_lineage_sha256,
        )?;
        hash_string(
            &mut hasher,
            "prepared_head_sha256",
            &self.prepared_head_sha256,
        )?;
        hash_u64(&mut hasher, "mutation_generation", self.mutation_generation)?;
        hash_string(
            &mut hasher,
            "state_directory_identity_sha256",
            &self.state_directory_identity_sha256,
        )?;
        hash_string(
            &mut hasher,
            "writer_lock_identity_sha256",
            &self.writer_lock_identity_sha256,
        )?;
        hash_string(
            &mut hasher,
            "named_journal_version_sha256",
            &self.named_journal_version.journal_version_sha256,
        )?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
// Keep the prepared head inline: this is a closed wire schema, and adding
// implementation-only indirection would needlessly change its public Rust ABI.
#[allow(clippy::large_enum_variant)]
pub enum DirectOperationRuntimeAuthorityPreparedSlotV1 {
    Empty,
    Pending {
        prepared_head: DirectOperationRuntimeAuthorityPreparedHeadV1,
    },
}

impl DirectOperationRuntimeAuthorityPreparedSlotV1 {
    fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        committed: &DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        match self {
            Self::Empty => Ok(()),
            Self::Pending { prepared_head } => prepared_head.validate_for_head(lineage, committed),
        }
    }

    fn hash_into(
        &self,
        hasher: &mut Sha256,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        match self {
            Self::Empty => hash_string(hasher, "prepared_slot_state", "empty"),
            Self::Pending { prepared_head } => {
                hash_string(hasher, "prepared_slot_state", "pending")?;
                hash_string(
                    hasher,
                    "prepared_head_sha256",
                    &prepared_head.prepared_head_sha256,
                )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthoritySnapshotV1 {
    pub schema: String,
    pub protocol: String,
    pub first_use_lineage_sha256: String,
    pub committed_head: DirectOperationRuntimeAuthorityCommittedHeadV1,
    pub prepared_slot: DirectOperationRuntimeAuthorityPreparedSlotV1,
    pub snapshot_sha256: String,
}

impl DirectOperationRuntimeAuthoritySnapshotV1 {
    pub fn validate(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        lineage.validate()?;
        self.committed_head.validate(lineage)?;
        self.prepared_slot
            .validate_for(lineage, &self.committed_head)?;
        if self.schema != AUTHORITY_SNAPSHOT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.first_use_lineage_sha256 != lineage.first_use_lineage_sha256
            || !valid_nonzero_sha256(&self.snapshot_sha256)
            || self.canonical_sha256()? != self.snapshot_sha256
        {
            return Err(denied("direct_operation_mutation_cas_snapshot_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        if self.schema != AUTHORITY_SNAPSHOT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || !valid_nonzero_sha256(&self.first_use_lineage_sha256)
            || !valid_nonzero_sha256(&self.committed_head.committed_head_sha256)
        {
            return Err(denied("direct_operation_mutation_cas_snapshot_denied"));
        }
        let mut hasher = domain_hasher(AUTHORITY_SNAPSHOT_V1_SCHEMA);
        hash_string(&mut hasher, "schema", &self.schema)?;
        hash_string(&mut hasher, "protocol", &self.protocol)?;
        hash_string(
            &mut hasher,
            "first_use_lineage_sha256",
            &self.first_use_lineage_sha256,
        )?;
        hash_string(
            &mut hasher,
            "committed_head_sha256",
            &self.committed_head.committed_head_sha256,
        )?;
        self.prepared_slot.hash_into(&mut hasher)?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityPrepareRequestV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub mutation_transaction_sha256: String,
    pub request_nonce_sha256: String,
    pub current_committed_head: DirectOperationRuntimeAuthorityCommittedHeadV1,
    pub mutation_intent: DirectOperationRuntimeAuthorityMutationIntentV1,
    pub request_sha256: String,
}

impl DirectOperationRuntimeAuthorityPrepareRequestV1 {
    pub fn validate(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.current_committed_head.validate(lineage)?;
        self.mutation_intent
            .validate_for(lineage, &self.current_committed_head)?;
        if self.schema != PREPARE_REQUEST_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != PREPARE_OPERATION
            || self.mutation_transaction_sha256 != self.mutation_intent.mutation_intent_sha256
            || !valid_nonzero_sha256(&self.request_nonce_sha256)
            || !valid_nonzero_sha256(&self.request_sha256)
            || self.canonical_sha256()? != self.request_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_prepare_request_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        message_request_digest(
            PREPARE_REQUEST_V1_SCHEMA,
            PREPARE_OPERATION,
            &self.schema,
            &self.protocol,
            &self.operation,
            (
                "mutation_transaction_sha256",
                &self.mutation_transaction_sha256,
            ),
            &self.request_nonce_sha256,
            &[
                (
                    "current_committed_head_sha256",
                    &self.current_committed_head.committed_head_sha256,
                ),
                (
                    "mutation_intent_sha256",
                    &self.mutation_intent.mutation_intent_sha256,
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityPrepareReceiptV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub request_sha256: String,
    pub prepared_head: DirectOperationRuntimeAuthorityPreparedHeadV1,
    pub receipt_sha256: String,
}

impl DirectOperationRuntimeAuthorityPrepareReceiptV1 {
    pub fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityPrepareRequestV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        request.validate(lineage)?;
        self.prepared_head.validate_for_intent(
            lineage,
            &request.current_committed_head,
            &request.mutation_intent,
        )?;
        if self.schema != PREPARE_RECEIPT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != PREPARE_OPERATION
            || self.request_sha256 != request.request_sha256
            || !valid_nonzero_sha256(&self.receipt_sha256)
            || self.canonical_sha256()? != self.receipt_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_prepare_receipt_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        message_response_digest(
            PREPARE_RECEIPT_V1_SCHEMA,
            PREPARE_OPERATION,
            &self.schema,
            &self.protocol,
            &self.operation,
            &self.request_sha256,
            "prepared_head_sha256",
            &self.prepared_head.prepared_head_sha256,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityCommitRequestV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub mutation_transaction_sha256: String,
    pub request_nonce_sha256: String,
    pub prepare_request_sha256: String,
    pub prepare_receipt_sha256: String,
    pub prepared_head_sha256: String,
    pub local_publication: DirectOperationRuntimeAuthorityLocalPublicationV1,
    pub request_sha256: String,
}

impl DirectOperationRuntimeAuthorityCommitRequestV1 {
    pub fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        prepare: &DirectOperationRuntimeAuthorityPrepareRequestV1,
        receipt: &DirectOperationRuntimeAuthorityPrepareReceiptV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        receipt.validate_for(lineage, prepare)?;
        self.local_publication
            .validate_for(lineage, &receipt.prepared_head)?;
        if self.schema != COMMIT_REQUEST_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != COMMIT_OPERATION
            || self.mutation_transaction_sha256 != prepare.mutation_transaction_sha256
            || self.mutation_transaction_sha256 != prepare.mutation_intent.mutation_intent_sha256
            || !valid_nonzero_sha256(&self.request_nonce_sha256)
            || self.prepare_request_sha256 != prepare.request_sha256
            || self.prepare_receipt_sha256 != receipt.receipt_sha256
            || self.prepared_head_sha256 != receipt.prepared_head.prepared_head_sha256
            || !valid_nonzero_sha256(&self.request_sha256)
            || self.canonical_sha256()? != self.request_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_commit_request_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        message_request_digest(
            COMMIT_REQUEST_V1_SCHEMA,
            COMMIT_OPERATION,
            &self.schema,
            &self.protocol,
            &self.operation,
            (
                "mutation_transaction_sha256",
                &self.mutation_transaction_sha256,
            ),
            &self.request_nonce_sha256,
            &[
                ("prepare_request_sha256", &self.prepare_request_sha256),
                ("prepare_receipt_sha256", &self.prepare_receipt_sha256),
                ("prepared_head_sha256", &self.prepared_head_sha256),
                (
                    "local_publication_sha256",
                    &self.local_publication.local_publication_sha256,
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityCommitReceiptV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub request_sha256: String,
    pub committed_head: DirectOperationRuntimeAuthorityCommittedHeadV1,
    pub receipt_sha256: String,
}

impl DirectOperationRuntimeAuthorityCommitReceiptV1 {
    pub fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        prepare: &DirectOperationRuntimeAuthorityPrepareRequestV1,
        prepare_receipt: &DirectOperationRuntimeAuthorityPrepareReceiptV1,
        request: &DirectOperationRuntimeAuthorityCommitRequestV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        request.validate_for(lineage, prepare, prepare_receipt)?;
        self.committed_head
            .validate_successor(lineage, current, &prepare_receipt.prepared_head)?;
        if self.schema != COMMIT_RECEIPT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != COMMIT_OPERATION
            || self.request_sha256 != request.request_sha256
            || !valid_nonzero_sha256(&self.receipt_sha256)
            || self.canonical_sha256()? != self.receipt_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_commit_receipt_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        message_response_digest(
            COMMIT_RECEIPT_V1_SCHEMA,
            COMMIT_OPERATION,
            &self.schema,
            &self.protocol,
            &self.operation,
            &self.request_sha256,
            "committed_head_sha256",
            &self.committed_head.committed_head_sha256,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityObserveRequestV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub observation_session_sha256: String,
    pub request_nonce_sha256: String,
    pub expected_committed_head_sha256: String,
    pub observed_journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
    pub request_sha256: String,
}

impl DirectOperationRuntimeAuthorityObserveRequestV1 {
    pub fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        expected: &DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        expected.validate(lineage)?;
        self.observed_journal_version.validate()?;
        if self.schema != OBSERVE_REQUEST_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != OBSERVE_OPERATION
            || !valid_nonzero_sha256(&self.observation_session_sha256)
            || !valid_nonzero_sha256(&self.request_nonce_sha256)
            || self.expected_committed_head_sha256 != expected.committed_head_sha256
            || self.observed_journal_version != expected.journal_version
            || !valid_nonzero_sha256(&self.request_sha256)
            || self.canonical_sha256()? != self.request_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_observe_request_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        message_request_digest(
            OBSERVE_REQUEST_V1_SCHEMA,
            OBSERVE_OPERATION,
            &self.schema,
            &self.protocol,
            &self.operation,
            (
                "observation_session_sha256",
                &self.observation_session_sha256,
            ),
            &self.request_nonce_sha256,
            &[
                (
                    "expected_committed_head_sha256",
                    &self.expected_committed_head_sha256,
                ),
                (
                    "observed_journal_version_sha256",
                    &self.observed_journal_version.journal_version_sha256,
                ),
            ],
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityObserveResponseV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub request_sha256: String,
    pub snapshot: DirectOperationRuntimeAuthoritySnapshotV1,
    pub response_sha256: String,
}

impl DirectOperationRuntimeAuthorityObserveResponseV1 {
    pub fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityObserveRequestV1,
        expected: &DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        request.validate_for(lineage, expected)?;
        self.snapshot.validate(lineage)?;
        if self.schema != OBSERVE_RESPONSE_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != OBSERVE_OPERATION
            || self.request_sha256 != request.request_sha256
            || self.snapshot.committed_head != *expected
            || self.snapshot.prepared_slot != DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
            || !valid_nonzero_sha256(&self.response_sha256)
            || self.canonical_sha256()? != self.response_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_observe_response_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        message_response_digest(
            OBSERVE_RESPONSE_V1_SCHEMA,
            OBSERVE_OPERATION,
            &self.schema,
            &self.protocol,
            &self.operation,
            &self.request_sha256,
            "snapshot_sha256",
            &self.snapshot.snapshot_sha256,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationRuntimeAuthorityReconcileCauseV1 {
    PrepareResponseUnknown,
    LocalPublicationUnknown,
    CommitResponseUnknown,
    RestartWithPrepared,
}

impl DirectOperationRuntimeAuthorityReconcileCauseV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::PrepareResponseUnknown => "prepare_response_unknown",
            Self::LocalPublicationUnknown => "local_publication_unknown",
            Self::CommitResponseUnknown => "commit_response_unknown",
            Self::RestartWithPrepared => "restart_with_prepared",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationRuntimeAuthorityLocalEntryRoleV1 {
    NamedJournal,
    StagedCandidate,
}

impl DirectOperationRuntimeAuthorityLocalEntryRoleV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NamedJournal => "named_journal",
            Self::StagedCandidate => "staged_candidate",
        }
    }

    const fn entry_domain(self) -> &'static str {
        match self {
            Self::NamedJournal => NAMED_JOURNAL_ENTRY_DOMAIN,
            Self::StagedCandidate => STAGED_CANDIDATE_ENTRY_DOMAIN,
        }
    }
}

/// Source data only. A future sealed local observer must attest that the
/// observation is truthful; this context and its digests confer no authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityLocalObservationContextV1 {
    pub schema: String,
    pub protocol: String,
    pub role: DirectOperationRuntimeAuthorityLocalEntryRoleV1,
    pub entry_domain: String,
    pub entry_binding_sha256: String,
    pub state_directory_identity_sha256: String,
    pub writer_lock_identity_sha256: String,
    pub first_use_lineage_sha256: String,
    pub mutation_transaction_sha256: String,
    pub request_nonce_sha256: String,
    pub mutation_intent_sha256: String,
    pub expected_committed_head_sha256: String,
    pub expected_journal_version_sha256: String,
    pub proposed_journal_version_sha256: String,
    pub reconcile_cause: DirectOperationRuntimeAuthorityReconcileCauseV1,
    pub context_sha256: String,
}

impl DirectOperationRuntimeAuthorityLocalObservationContextV1 {
    fn validate_integrity(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        if self.schema != LOCAL_OBSERVATION_CONTEXT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.entry_domain != self.role.entry_domain()
            || ![
                &self.entry_binding_sha256,
                &self.state_directory_identity_sha256,
                &self.writer_lock_identity_sha256,
                &self.first_use_lineage_sha256,
                &self.mutation_transaction_sha256,
                &self.request_nonce_sha256,
                &self.mutation_intent_sha256,
                &self.expected_committed_head_sha256,
                &self.expected_journal_version_sha256,
                &self.proposed_journal_version_sha256,
                &self.context_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
            || self.canonical_entry_binding_sha256()? != self.entry_binding_sha256
            || self.canonical_sha256()? != self.context_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_local_observation_context_denied",
            ));
        }
        Ok(())
    }

    fn validate_for(
        &self,
        expected_role: DirectOperationRuntimeAuthorityLocalEntryRoleV1,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.validate_integrity()?;
        if self.role != expected_role
            || self.state_directory_identity_sha256
                != lineage.anchor.state_directory_identity_sha256
            || self.first_use_lineage_sha256 != lineage.first_use_lineage_sha256
            || self.mutation_transaction_sha256 != request.mutation_transaction_sha256
            || self.request_nonce_sha256 != request.request_nonce_sha256
            || self.mutation_intent_sha256 != request.mutation_intent.mutation_intent_sha256
            || self.expected_committed_head_sha256
                != request.expected_committed_head.committed_head_sha256
            || self.expected_journal_version_sha256
                != request
                    .expected_committed_head
                    .journal_version
                    .journal_version_sha256
            || self.proposed_journal_version_sha256
                != request
                    .mutation_intent
                    .proposed_journal_version
                    .journal_version_sha256
            || self.reconcile_cause != request.cause
        {
            return Err(denied(
                "direct_operation_mutation_cas_local_observation_request_denied",
            ));
        }
        Ok(())
    }

    fn same_reconcile_context(&self, other: &Self) -> bool {
        self.schema == other.schema
            && self.protocol == other.protocol
            && self.state_directory_identity_sha256 == other.state_directory_identity_sha256
            && self.writer_lock_identity_sha256 == other.writer_lock_identity_sha256
            && self.first_use_lineage_sha256 == other.first_use_lineage_sha256
            && self.mutation_transaction_sha256 == other.mutation_transaction_sha256
            && self.request_nonce_sha256 == other.request_nonce_sha256
            && self.mutation_intent_sha256 == other.mutation_intent_sha256
            && self.expected_committed_head_sha256 == other.expected_committed_head_sha256
            && self.expected_journal_version_sha256 == other.expected_journal_version_sha256
            && self.proposed_journal_version_sha256 == other.proposed_journal_version_sha256
            && self.reconcile_cause == other.reconcile_cause
    }

    pub fn canonical_entry_binding_sha256(
        &self,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        if self.schema != LOCAL_OBSERVATION_CONTEXT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.entry_domain != self.role.entry_domain()
            || ![
                &self.state_directory_identity_sha256,
                &self.first_use_lineage_sha256,
                &self.mutation_intent_sha256,
                &self.expected_committed_head_sha256,
                &self.expected_journal_version_sha256,
                &self.proposed_journal_version_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
        {
            return Err(denied(
                "direct_operation_mutation_cas_local_entry_binding_denied",
            ));
        }
        let mut hasher = domain_hasher(LOCAL_ENTRY_BINDING_V1_SCHEMA);
        for (name, value) in [
            ("schema", LOCAL_ENTRY_BINDING_V1_SCHEMA),
            ("protocol", self.protocol.as_str()),
            ("role", self.role.as_str()),
            ("entry_domain", self.entry_domain.as_str()),
            (
                "state_directory_identity_sha256",
                self.state_directory_identity_sha256.as_str(),
            ),
            (
                "first_use_lineage_sha256",
                self.first_use_lineage_sha256.as_str(),
            ),
            (
                "mutation_intent_sha256",
                self.mutation_intent_sha256.as_str(),
            ),
            (
                "expected_committed_head_sha256",
                self.expected_committed_head_sha256.as_str(),
            ),
            (
                "expected_journal_version_sha256",
                self.expected_journal_version_sha256.as_str(),
            ),
            (
                "proposed_journal_version_sha256",
                self.proposed_journal_version_sha256.as_str(),
            ),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        if self.schema != LOCAL_OBSERVATION_CONTEXT_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.entry_domain != self.role.entry_domain()
            || ![
                &self.entry_binding_sha256,
                &self.state_directory_identity_sha256,
                &self.writer_lock_identity_sha256,
                &self.first_use_lineage_sha256,
                &self.mutation_transaction_sha256,
                &self.request_nonce_sha256,
                &self.mutation_intent_sha256,
                &self.expected_committed_head_sha256,
                &self.expected_journal_version_sha256,
                &self.proposed_journal_version_sha256,
            ]
            .into_iter()
            .all(|value| valid_nonzero_sha256(value))
            || self.canonical_entry_binding_sha256()? != self.entry_binding_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_local_observation_context_denied",
            ));
        }
        let mut hasher = domain_hasher(LOCAL_OBSERVATION_CONTEXT_V1_SCHEMA);
        for (name, value) in [
            ("schema", self.schema.as_str()),
            ("protocol", self.protocol.as_str()),
            ("role", self.role.as_str()),
            ("entry_domain", self.entry_domain.as_str()),
            ("entry_binding_sha256", self.entry_binding_sha256.as_str()),
            (
                "state_directory_identity_sha256",
                self.state_directory_identity_sha256.as_str(),
            ),
            (
                "writer_lock_identity_sha256",
                self.writer_lock_identity_sha256.as_str(),
            ),
            (
                "first_use_lineage_sha256",
                self.first_use_lineage_sha256.as_str(),
            ),
            (
                "mutation_transaction_sha256",
                self.mutation_transaction_sha256.as_str(),
            ),
            ("request_nonce_sha256", self.request_nonce_sha256.as_str()),
            (
                "mutation_intent_sha256",
                self.mutation_intent_sha256.as_str(),
            ),
            (
                "expected_committed_head_sha256",
                self.expected_committed_head_sha256.as_str(),
            ),
            (
                "expected_journal_version_sha256",
                self.expected_journal_version_sha256.as_str(),
            ),
            (
                "proposed_journal_version_sha256",
                self.proposed_journal_version_sha256.as_str(),
            ),
            ("reconcile_cause", self.reconcile_cause.as_str()),
        ] {
            hash_string(&mut hasher, name, value)?;
        }
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectOperationRuntimeAuthorityLocalObservationV1 {
    Present {
        context: DirectOperationRuntimeAuthorityLocalObservationContextV1,
        journal_version: DirectOperationRuntimeAuthorityJournalVersionV1,
        observation_sha256: String,
    },
    Missing {
        context: DirectOperationRuntimeAuthorityLocalObservationContextV1,
        name_absent: bool,
        observation_sha256: String,
    },
}

impl DirectOperationRuntimeAuthorityLocalObservationV1 {
    fn context(&self) -> &DirectOperationRuntimeAuthorityLocalObservationContextV1 {
        match self {
            Self::Present { context, .. } | Self::Missing { context, .. } => context,
        }
    }

    fn validate_integrity(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.context().validate_integrity()?;
        let observation_sha256 = match self {
            Self::Present {
                journal_version,
                observation_sha256,
                ..
            } => {
                journal_version.validate()?;
                observation_sha256
            }
            Self::Missing {
                name_absent,
                observation_sha256,
                ..
            } if *name_absent => observation_sha256,
            Self::Missing { .. } => {
                return Err(denied("direct_operation_mutation_cas_local_missing_denied"));
            }
        };
        if !valid_nonzero_sha256(observation_sha256)
            || self.canonical_sha256()? != *observation_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_local_observation_denied",
            ));
        }
        Ok(())
    }

    pub fn validate_for_named(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.validate_for_role(
            DirectOperationRuntimeAuthorityLocalEntryRoleV1::NamedJournal,
            lineage,
            request,
        )
    }

    pub fn validate_for_staged(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.validate_for_role(
            DirectOperationRuntimeAuthorityLocalEntryRoleV1::StagedCandidate,
            lineage,
            request,
        )
    }

    fn validate_for_role(
        &self,
        expected_role: DirectOperationRuntimeAuthorityLocalEntryRoleV1,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.context()
            .validate_for(expected_role, lineage, request)?;
        self.validate_integrity()?;
        let expected_version = &request.expected_committed_head.journal_version;
        let proposed_version = &request.mutation_intent.proposed_journal_version;
        match (expected_role, self) {
            (
                DirectOperationRuntimeAuthorityLocalEntryRoleV1::NamedJournal,
                Self::Present {
                    journal_version, ..
                },
            ) if journal_version == expected_version || journal_version == proposed_version => {
                Ok(())
            }
            (
                DirectOperationRuntimeAuthorityLocalEntryRoleV1::StagedCandidate,
                Self::Present {
                    journal_version, ..
                },
            ) if journal_version == proposed_version => Ok(()),
            (_, Self::Missing { name_absent, .. }) if *name_absent => Ok(()),
            _ => Err(denied(
                "direct_operation_mutation_cas_local_observation_version_denied",
            )),
        }
    }

    fn is_validated_missing_for_staged(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> bool {
        self.validate_for_staged(lineage, request).is_ok()
            && matches!(
                self,
                Self::Missing {
                    name_absent: true,
                    ..
                }
            )
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        self.context().validate_integrity()?;
        let mut hasher = domain_hasher(LOCAL_OBSERVATION_V1_SCHEMA);
        hash_string(&mut hasher, "schema", LOCAL_OBSERVATION_V1_SCHEMA)?;
        hash_string(&mut hasher, "protocol", PROTOCOL)?;
        hash_string(
            &mut hasher,
            "context_sha256",
            &self.context().context_sha256,
        )?;
        match self {
            Self::Present {
                journal_version, ..
            } => {
                journal_version.validate()?;
                hash_string(&mut hasher, "state", "present")?;
                hash_string(
                    &mut hasher,
                    "journal_version_sha256",
                    &journal_version.journal_version_sha256,
                )?;
            }
            Self::Missing { name_absent, .. } if *name_absent => {
                hash_string(&mut hasher, "state", "missing")?;
                hash_string(&mut hasher, "name_absent", "true")?;
            }
            Self::Missing { .. } => {
                return Err(denied("direct_operation_mutation_cas_local_missing_denied"));
            }
        }
        Ok(lower_hex(&hasher.finalize()))
    }

    fn hash_into(
        &self,
        hasher: &mut Sha256,
        prefix: &str,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.validate_integrity()?;
        hash_string(
            hasher,
            &format!("{prefix}_role"),
            self.context().role.as_str(),
        )?;
        hash_string(
            hasher,
            &format!("{prefix}_entry_binding_sha256"),
            &self.context().entry_binding_sha256,
        )?;
        let observation_sha256 = match self {
            Self::Present {
                observation_sha256, ..
            }
            | Self::Missing {
                observation_sha256, ..
            } => observation_sha256,
        };
        hash_string(
            hasher,
            &format!("{prefix}_observation_sha256"),
            observation_sha256,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
// Keep the exact prepared head inline so the public Rust and wire shapes
// describe the same closed reconciliation evidence without hidden indirection.
#[allow(clippy::large_enum_variant)]
pub enum DirectOperationRuntimeAuthorityPreparedKnowledgeV1 {
    Unknown,
    Known {
        prepared_head: DirectOperationRuntimeAuthorityPreparedHeadV1,
    },
}

impl DirectOperationRuntimeAuthorityPreparedKnowledgeV1 {
    fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        expected: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: &DirectOperationRuntimeAuthorityMutationIntentV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        match self {
            Self::Unknown => Ok(()),
            Self::Known { prepared_head } => {
                prepared_head.validate_for_intent(lineage, expected, intent)
            }
        }
    }

    fn hash_into(
        &self,
        hasher: &mut Sha256,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        match self {
            Self::Unknown => hash_string(hasher, "prepared_knowledge", "unknown"),
            Self::Known { prepared_head } => {
                if !valid_nonzero_sha256(&prepared_head.prepared_head_sha256)
                    || prepared_head.canonical_sha256()? != prepared_head.prepared_head_sha256
                {
                    return Err(denied(
                        "direct_operation_mutation_cas_prepared_knowledge_denied",
                    ));
                }
                hash_string(hasher, "prepared_knowledge", "known")?;
                hash_string(
                    hasher,
                    "known_prepared_head_sha256",
                    &prepared_head.prepared_head_sha256,
                )
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityReconcileRequestV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub mutation_transaction_sha256: String,
    pub request_nonce_sha256: String,
    pub cause: DirectOperationRuntimeAuthorityReconcileCauseV1,
    pub expected_committed_head: DirectOperationRuntimeAuthorityCommittedHeadV1,
    pub mutation_intent: DirectOperationRuntimeAuthorityMutationIntentV1,
    pub prepared_knowledge: DirectOperationRuntimeAuthorityPreparedKnowledgeV1,
    pub observed_named_journal: DirectOperationRuntimeAuthorityLocalObservationV1,
    pub observed_staged_candidate: DirectOperationRuntimeAuthorityLocalObservationV1,
    pub request_sha256: String,
}

impl DirectOperationRuntimeAuthorityReconcileRequestV1 {
    pub fn validate(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.expected_committed_head.validate(lineage)?;
        self.mutation_intent
            .validate_for(lineage, &self.expected_committed_head)?;
        self.prepared_knowledge.validate_for(
            lineage,
            &self.expected_committed_head,
            &self.mutation_intent,
        )?;
        self.observed_named_journal
            .validate_for_named(lineage, self)?;
        self.observed_staged_candidate
            .validate_for_staged(lineage, self)?;
        if self.schema != RECONCILE_REQUEST_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != RECONCILE_OPERATION
            || !self
                .observed_named_journal
                .context()
                .same_reconcile_context(self.observed_staged_candidate.context())
            || self.mutation_transaction_sha256 != self.mutation_intent.mutation_intent_sha256
            || !valid_nonzero_sha256(&self.request_nonce_sha256)
            || !valid_nonzero_sha256(&self.request_sha256)
            || self.canonical_sha256()? != self.request_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_reconcile_request_denied",
            ));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        validate_message_header(
            RECONCILE_REQUEST_V1_SCHEMA,
            RECONCILE_OPERATION,
            &self.schema,
            &self.protocol,
            &self.operation,
            (
                "mutation_transaction_sha256",
                &self.mutation_transaction_sha256,
            ),
            &self.request_nonce_sha256,
        )?;
        let mut hasher = domain_hasher(RECONCILE_REQUEST_V1_SCHEMA);
        hash_message_header(
            &mut hasher,
            &self.schema,
            &self.protocol,
            &self.operation,
            (
                "mutation_transaction_sha256",
                &self.mutation_transaction_sha256,
            ),
            &self.request_nonce_sha256,
        )?;
        hash_string(&mut hasher, "cause", self.cause.as_str())?;
        hash_string(
            &mut hasher,
            "expected_committed_head_sha256",
            &self.expected_committed_head.committed_head_sha256,
        )?;
        hash_string(
            &mut hasher,
            "mutation_intent_sha256",
            &self.mutation_intent.mutation_intent_sha256,
        )?;
        self.prepared_knowledge.hash_into(&mut hasher)?;
        self.observed_named_journal
            .hash_into(&mut hasher, "observed_named_journal")?;
        self.observed_staged_candidate
            .hash_into(&mut hasher, "observed_staged_candidate")?;
        Ok(lower_hex(&hasher.finalize()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectOperationRuntimeAuthorityReconcileDispositionV1 {
    NoMutation,
    ResumeExactPreparedPublication,
    RetryExactCommit,
    Committed,
}

fn observed_version(
    observation: &DirectOperationRuntimeAuthorityLocalObservationV1,
) -> Option<&DirectOperationRuntimeAuthorityJournalVersionV1> {
    match observation {
        DirectOperationRuntimeAuthorityLocalObservationV1::Present {
            journal_version, ..
        } => Some(journal_version),
        DirectOperationRuntimeAuthorityLocalObservationV1::Missing { .. } => None,
    }
}

fn exact_request_prepared_head(
    lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
    request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    prepared: &DirectOperationRuntimeAuthorityPreparedHeadV1,
) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
    prepared.validate_for_intent(
        lineage,
        &request.expected_committed_head,
        &request.mutation_intent,
    )?;
    if let DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
        prepared_head: known,
    } = &request.prepared_knowledge
        && known != prepared
    {
        return Err(denied(
            "direct_operation_mutation_cas_reconcile_prepared_mismatch_denied",
        ));
    }
    Ok(())
}

fn validate_reconcile_snapshot_for_request(
    lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
    request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    snapshot: &DirectOperationRuntimeAuthoritySnapshotV1,
) -> DirectOperationRuntimeAuthorityMutationCasResult<
    DirectOperationRuntimeAuthorityReconcileDispositionV1,
> {
    snapshot.validate(lineage)?;
    let expected = &request.expected_committed_head;
    let proposed = &request.mutation_intent.proposed_journal_version;
    let named = observed_version(&request.observed_named_journal);
    let staged = observed_version(&request.observed_staged_candidate);

    if snapshot.committed_head == *expected
        && snapshot.prepared_slot == DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
        && request.cause == DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown
        && request.prepared_knowledge == DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown
        && named == Some(&expected.journal_version)
        && staged == Some(proposed)
    {
        return Ok(DirectOperationRuntimeAuthorityReconcileDispositionV1::NoMutation);
    }

    if snapshot.committed_head == *expected
        && let DirectOperationRuntimeAuthorityPreparedSlotV1::Pending { prepared_head } =
            &snapshot.prepared_slot
    {
        exact_request_prepared_head(lineage, request, prepared_head)?;
        let exact_known = matches!(
            &request.prepared_knowledge,
            DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                prepared_head: known,
            } if known == prepared_head
        );
        if named == Some(&expected.journal_version)
            && staged == Some(proposed)
            && ((request.cause
                == DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown
                && request.prepared_knowledge
                    == DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown)
                || (request.cause
                    == DirectOperationRuntimeAuthorityReconcileCauseV1::RestartWithPrepared
                    && exact_known))
        {
            return Ok(
                DirectOperationRuntimeAuthorityReconcileDispositionV1::ResumeExactPreparedPublication,
            );
        }
        if matches!(
            request.cause,
            DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown
                | DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown
        ) && exact_known
            && named == Some(proposed)
            && request
                .observed_staged_candidate
                .is_validated_missing_for_staged(lineage, request)
        {
            return Ok(DirectOperationRuntimeAuthorityReconcileDispositionV1::RetryExactCommit);
        }
    }

    if let DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known { prepared_head } =
        &request.prepared_knowledge
        && snapshot.prepared_slot == DirectOperationRuntimeAuthorityPreparedSlotV1::Empty
        && request.cause == DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown
        && named == Some(proposed)
        && request
            .observed_staged_candidate
            .is_validated_missing_for_staged(lineage, request)
        && snapshot
            .committed_head
            .validate_successor(lineage, expected, prepared_head)
            .is_ok()
    {
        return Ok(DirectOperationRuntimeAuthorityReconcileDispositionV1::Committed);
    }

    Err(denied(
        "direct_operation_mutation_cas_reconcile_truth_table_denied",
    ))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectOperationRuntimeAuthorityReconcileResponseV1 {
    pub schema: String,
    pub protocol: String,
    pub operation: String,
    pub request_sha256: String,
    pub snapshot: DirectOperationRuntimeAuthoritySnapshotV1,
    pub response_sha256: String,
}

impl DirectOperationRuntimeAuthorityReconcileResponseV1 {
    pub fn validate_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
        self.disposition_for(lineage, request).map(|_| ())
    }

    pub fn disposition_for(
        &self,
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
    ) -> DirectOperationRuntimeAuthorityMutationCasResult<
        DirectOperationRuntimeAuthorityReconcileDispositionV1,
    > {
        request.validate(lineage)?;
        self.snapshot.validate(lineage)?;
        if self.schema != RECONCILE_RESPONSE_V1_SCHEMA
            || self.protocol != PROTOCOL
            || self.operation != RECONCILE_OPERATION
            || self.request_sha256 != request.request_sha256
            || !valid_nonzero_sha256(&self.response_sha256)
            || self.canonical_sha256()? != self.response_sha256
        {
            return Err(denied(
                "direct_operation_mutation_cas_reconcile_response_denied",
            ));
        }
        validate_reconcile_snapshot_for_request(lineage, request, &self.snapshot)
    }

    pub fn canonical_sha256(&self) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
        message_response_digest(
            RECONCILE_RESPONSE_V1_SCHEMA,
            RECONCILE_OPERATION,
            &self.schema,
            &self.protocol,
            &self.operation,
            &self.request_sha256,
            "snapshot_sha256",
            &self.snapshot.snapshot_sha256,
        )
    }
}

// The explicit expected/observed header fields are part of the fail-closed
// domain-separation check; grouping them would make field substitution easier.
#[allow(clippy::too_many_arguments)]
fn message_request_digest(
    expected_schema: &'static str,
    expected_operation: &'static str,
    schema: &str,
    protocol: &str,
    operation: &str,
    request_context: (&str, &str),
    request_nonce_sha256: &str,
    payload_fields: &[(&str, &String)],
) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
    validate_message_header(
        expected_schema,
        expected_operation,
        schema,
        protocol,
        operation,
        request_context,
        request_nonce_sha256,
    )?;
    let mut hasher = domain_hasher(expected_schema);
    hash_message_header(
        &mut hasher,
        schema,
        protocol,
        operation,
        request_context,
        request_nonce_sha256,
    )?;
    for (name, value) in payload_fields {
        if !valid_nonzero_sha256(value) {
            return Err(denied(
                "direct_operation_mutation_cas_request_payload_denied",
            ));
        }
        hash_string(&mut hasher, name, value)?;
    }
    Ok(lower_hex(&hasher.finalize()))
}

// Keep every correlation field explicit for the same reason as requests.
#[allow(clippy::too_many_arguments)]
fn message_response_digest(
    expected_schema: &'static str,
    expected_operation: &'static str,
    schema: &str,
    protocol: &str,
    operation: &str,
    request_sha256: &str,
    payload_name: &str,
    payload_sha256: &str,
) -> DirectOperationRuntimeAuthorityMutationCasResult<String> {
    if schema != expected_schema
        || protocol != PROTOCOL
        || operation != expected_operation
        || !valid_nonzero_sha256(request_sha256)
        || !valid_nonzero_sha256(payload_sha256)
    {
        return Err(denied(
            "direct_operation_mutation_cas_response_header_denied",
        ));
    }
    let mut hasher = domain_hasher(expected_schema);
    hash_string(&mut hasher, "schema", schema)?;
    hash_string(&mut hasher, "protocol", protocol)?;
    hash_string(&mut hasher, "operation", operation)?;
    hash_string(&mut hasher, "request_sha256", request_sha256)?;
    hash_string(&mut hasher, payload_name, payload_sha256)?;
    Ok(lower_hex(&hasher.finalize()))
}

fn validate_message_header(
    expected_schema: &'static str,
    expected_operation: &'static str,
    schema: &str,
    protocol: &str,
    operation: &str,
    request_context: (&str, &str),
    request_nonce_sha256: &str,
) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
    if schema != expected_schema
        || protocol != PROTOCOL
        || operation != expected_operation
        || !valid_nonzero_sha256(request_context.1)
        || !valid_nonzero_sha256(request_nonce_sha256)
    {
        return Err(denied(
            "direct_operation_mutation_cas_request_header_denied",
        ));
    }
    Ok(())
}

fn hash_message_header(
    hasher: &mut Sha256,
    schema: &str,
    protocol: &str,
    operation: &str,
    request_context: (&str, &str),
    request_nonce_sha256: &str,
) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
    hash_string(hasher, "schema", schema)?;
    hash_string(hasher, "protocol", protocol)?;
    hash_string(hasher, "operation", operation)?;
    hash_string(hasher, request_context.0, request_context.1)?;
    hash_string(hasher, "request_nonce_sha256", request_nonce_sha256)
}

fn domain_hasher(domain: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher
}

fn hash_string(
    hasher: &mut Sha256,
    name: &str,
    value: &str,
) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
    hash_bytes(hasher, name, value.as_bytes())
}

fn hash_u64(
    hasher: &mut Sha256,
    name: &str,
    value: u64,
) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
    hash_bytes(hasher, name, &value.to_be_bytes())
}

fn hash_bytes(
    hasher: &mut Sha256,
    name: &str,
    value: &[u8],
) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("direct_operation_mutation_cas_digest_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("direct_operation_mutation_cas_digest_denied"))?;
    hasher.update(name_length.to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update(value_length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn append_framed_bytes(
    output: &mut Vec<u8>,
    name: &[u8],
    value: &[u8],
) -> DirectOperationRuntimeAuthorityMutationCasResult<()> {
    let name_length = u32::try_from(name.len())
        .map_err(|_| denied("direct_operation_mutation_cas_digest_denied"))?;
    let value_length = u32::try_from(value.len())
        .map_err(|_| denied("direct_operation_mutation_cas_digest_denied"))?;
    output.extend_from_slice(&name_length.to_be_bytes());
    output.extend_from_slice(name);
    output.extend_from_slice(&value_length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && !value.bytes().all(|byte| byte == b'0')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn next_mutation_generation(current: u64) -> DirectOperationRuntimeAuthorityMutationCasResult<u64> {
    current
        .checked_add(1)
        .ok_or_else(|| denied("direct_operation_mutation_cas_generation_overflow_denied"))
}

const fn denied(code: &'static str) -> DirectOperationRuntimeAuthorityMutationCasError {
    DirectOperationRuntimeAuthorityMutationCasError(code)
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use std::fmt::Debug;

    use serde::Serialize;
    use serde::de::DeserializeOwned;

    use super::*;
    use crate::sha256_bytes;

    fn digest(label: &str) -> String {
        sha256_bytes(label.as_bytes())
    }

    fn immutable_sentinel_fields(
        anchor: &DirectOperationRuntimeAuthorityFirstUseAnchorV1,
    ) -> Vec<(&'static str, &str)> {
        vec![
            ("schema", anchor.immutable_sentinel_schema.as_str()),
            ("protocol", anchor.protocol.as_str()),
            ("phase", "pre_staged_immutable"),
            ("prepared_head_embedded", "false"),
            (
                "authority_identity_sha256",
                anchor.authority_identity_sha256.as_str(),
            ),
            (
                "authority_store_instance_sha256",
                anchor.authority_store_instance_sha256.as_str(),
            ),
            (
                "provision_epoch_sha256",
                anchor.provision_epoch_sha256.as_str(),
            ),
            ("provider_id", anchor.provider_id.as_str()),
            ("agent_id", anchor.agent_id.as_str()),
            ("adapter", anchor.adapter.adapter_id()),
            ("journal_epoch", anchor.journal_epoch.as_str()),
            (
                "state_directory_identity_sha256",
                anchor.state_directory_identity_sha256.as_str(),
            ),
            (
                "genesis_journal_version_sha256",
                anchor
                    .genesis_journal_version
                    .journal_version_sha256
                    .as_str(),
            ),
        ]
    }

    fn independently_frame_immutable_sentinel(fields: &[(&str, &str)]) -> Vec<u8> {
        let mut bytes = FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.as_bytes().to_vec();
        bytes.push(0);
        for (name, value) in fields {
            bytes.extend_from_slice(&u32::try_from(name.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(name.as_bytes());
            bytes.extend_from_slice(&u32::try_from(value.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes
    }

    fn assert_noncanonical_sentinel_rejected(
        mut anchor: DirectOperationRuntimeAuthorityFirstUseAnchorV1,
        noncanonical_bytes: &[u8],
    ) {
        assert_ne!(
            anchor.canonical_immutable_sentinel_bytes().unwrap(),
            noncanonical_bytes
        );
        anchor.sentinel_bytes_sha256 = sha256_bytes(noncanonical_bytes);
        assert!(anchor.validate().is_err());
    }

    fn journal_version(
        identity_label: &str,
        bytes_label: &str,
    ) -> DirectOperationRuntimeAuthorityJournalVersionV1 {
        let mut version = DirectOperationRuntimeAuthorityJournalVersionV1 {
            schema: JOURNAL_VERSION_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            journal_identity_sha256: digest(identity_label),
            journal_bytes_sha256: digest(bytes_label),
            journal_version_sha256: String::new(),
        };
        version.journal_version_sha256 = version.canonical_sha256().unwrap();
        version.validate().unwrap();
        version
    }

    fn lineage() -> DirectOperationRuntimeAuthorityFirstUseLineageV1 {
        let mut anchor = DirectOperationRuntimeAuthorityFirstUseAnchorV1 {
            schema: FIRST_USE_ANCHOR_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            authority_identity_sha256: digest("authority"),
            authority_store_instance_sha256: digest("authority-store"),
            provision_epoch_sha256: digest("provision-epoch"),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            adapter: DirectOperationAdapter::SystemApi,
            journal_epoch: "01".repeat(16),
            state_directory_identity_sha256: digest("state-directory"),
            genesis_journal_version: journal_version(
                "genesis-journal-identity",
                "genesis-journal-bytes",
            ),
            immutable_sentinel_schema: FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.to_string(),
            immutable_sentinel_embeds_prepared_head: false,
            sentinel_identity_sha256: digest("sentinel-identity"),
            sentinel_bytes_sha256: String::new(),
            first_use_anchor_sha256: String::new(),
        };
        anchor.sentinel_bytes_sha256 = anchor.canonical_immutable_sentinel_bytes_sha256().unwrap();
        anchor.first_use_anchor_sha256 = anchor.canonical_sha256().unwrap();
        anchor.validate().unwrap();

        let mut candidate = DirectOperationRuntimeAuthorityFirstUseCandidateV1 {
            schema: FIRST_USE_CANDIDATE_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            proposed_genesis_journal_version_sha256: anchor
                .genesis_journal_version
                .journal_version_sha256
                .clone(),
            candidate_nonce_sha256: digest("first-use-candidate-nonce"),
            first_use_candidate_sha256: String::new(),
        };
        candidate.first_use_candidate_sha256 = candidate.canonical_sha256().unwrap();
        candidate.validate_for(&anchor).unwrap();

        let mut prepared_head = DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1 {
            schema: FIRST_USE_PREPARED_HEAD_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
            prepared_genesis_journal_version_sha256: anchor
                .genesis_journal_version
                .journal_version_sha256
                .clone(),
            prepared_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
            prepared_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
            prepare_nonce_sha256: digest("first-use-prepare-nonce"),
            first_use_prepared_head_sha256: String::new(),
        };
        prepared_head.first_use_prepared_head_sha256 = prepared_head.canonical_sha256().unwrap();
        prepared_head.validate_for(&anchor, &candidate).unwrap();

        let mut committed_head = DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1 {
            schema: FIRST_USE_COMMITTED_HEAD_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
            first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
            first_use_prepared_head_sha256: prepared_head.first_use_prepared_head_sha256.clone(),
            committed_genesis_journal_version: anchor.genesis_journal_version.clone(),
            committed_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
            committed_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
            durable_commit_evidence_sha256: digest("first-use-durable-commit-evidence"),
            first_use_committed_head_sha256: String::new(),
        };
        committed_head.first_use_committed_head_sha256 = committed_head.canonical_sha256().unwrap();
        committed_head
            .validate_for(&anchor, &candidate, &prepared_head)
            .unwrap();

        let mut committed_result_binding =
            DirectOperationRuntimeAuthorityFirstUseCommittedResultBindingV1 {
                schema: FIRST_USE_COMMITTED_RESULT_BINDING_V1_SCHEMA.to_string(),
                protocol: PROTOCOL.to_string(),
                first_use_anchor_sha256: anchor.first_use_anchor_sha256.clone(),
                first_use_candidate_sha256: candidate.first_use_candidate_sha256.clone(),
                first_use_prepared_head_sha256: prepared_head
                    .first_use_prepared_head_sha256
                    .clone(),
                first_use_committed_head_sha256: committed_head
                    .first_use_committed_head_sha256
                    .clone(),
                committed_genesis_journal_version_sha256: anchor
                    .genesis_journal_version
                    .journal_version_sha256
                    .clone(),
                committed_sentinel_identity_sha256: anchor.sentinel_identity_sha256.clone(),
                committed_sentinel_bytes_sha256: anchor.sentinel_bytes_sha256.clone(),
                durable_commit_evidence_sha256: committed_head
                    .durable_commit_evidence_sha256
                    .clone(),
                result_receipt_sha256: digest("first-use-result-receipt"),
                first_use_committed_result_binding_sha256: String::new(),
            };
        committed_result_binding.first_use_committed_result_binding_sha256 =
            committed_result_binding.canonical_sha256().unwrap();
        committed_result_binding
            .validate_for(&anchor, &candidate, &prepared_head, &committed_head)
            .unwrap();

        let mut lineage = DirectOperationRuntimeAuthorityFirstUseLineageV1 {
            schema: FIRST_USE_LINEAGE_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            anchor,
            candidate,
            prepared_head,
            committed_head,
            committed_result_binding,
            first_use_lineage_sha256: String::new(),
        };
        lineage.first_use_lineage_sha256 = lineage.canonical_sha256().unwrap();
        lineage.validate().unwrap();
        lineage
    }

    fn rehash_first_use_descendants(
        lineage: &mut DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) {
        lineage.candidate.first_use_candidate_sha256 =
            lineage.candidate.canonical_sha256().unwrap();
        lineage.prepared_head.first_use_candidate_sha256 =
            lineage.candidate.first_use_candidate_sha256.clone();
        lineage.prepared_head.first_use_prepared_head_sha256 =
            lineage.prepared_head.canonical_sha256().unwrap();
        lineage.committed_head.first_use_candidate_sha256 =
            lineage.candidate.first_use_candidate_sha256.clone();
        lineage.committed_head.first_use_prepared_head_sha256 =
            lineage.prepared_head.first_use_prepared_head_sha256.clone();
        lineage.committed_head.first_use_committed_head_sha256 =
            lineage.committed_head.canonical_sha256().unwrap();
        lineage.committed_result_binding.first_use_candidate_sha256 =
            lineage.candidate.first_use_candidate_sha256.clone();
        lineage
            .committed_result_binding
            .first_use_prepared_head_sha256 =
            lineage.prepared_head.first_use_prepared_head_sha256.clone();
        lineage
            .committed_result_binding
            .first_use_committed_head_sha256 = lineage
            .committed_head
            .first_use_committed_head_sha256
            .clone();
        lineage
            .committed_result_binding
            .committed_genesis_journal_version_sha256 = lineage
            .committed_head
            .committed_genesis_journal_version
            .journal_version_sha256
            .clone();
        lineage
            .committed_result_binding
            .durable_commit_evidence_sha256 = lineage
            .committed_head
            .durable_commit_evidence_sha256
            .clone();
        lineage
            .committed_result_binding
            .first_use_committed_result_binding_sha256 =
            lineage.committed_result_binding.canonical_sha256().unwrap();
        lineage.first_use_lineage_sha256 = lineage.canonical_sha256().unwrap();
    }

    fn genesis(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
    ) -> DirectOperationRuntimeAuthorityCommittedHeadV1 {
        let version = journal_version("genesis-journal-identity", "genesis-journal-bytes");
        assert_eq!(
            version.journal_identity_sha256,
            lineage
                .anchor
                .genesis_journal_version
                .journal_identity_sha256
        );
        assert_eq!(
            version.journal_bytes_sha256,
            lineage.anchor.genesis_journal_version.journal_bytes_sha256
        );
        let mut head = DirectOperationRuntimeAuthorityCommittedHeadV1 {
            schema: COMMITTED_HEAD_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            authority_identity_sha256: lineage.anchor.authority_identity_sha256.clone(),
            authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            provider_id: lineage.anchor.provider_id.clone(),
            agent_id: lineage.anchor.agent_id.clone(),
            adapter: lineage.anchor.adapter,
            journal_epoch: lineage.anchor.journal_epoch.clone(),
            state_directory_identity_sha256: lineage.anchor.state_directory_identity_sha256.clone(),
            mutation_generation: 1,
            journal_version: version,
            ancestry: DirectOperationRuntimeAuthorityHeadAncestryV1::Genesis {
                first_use_committed_result_binding_sha256: lineage
                    .committed_result_binding
                    .first_use_committed_result_binding_sha256
                    .clone(),
            },
            committed_head_sha256: String::new(),
        };
        head.committed_head_sha256 = head.canonical_sha256().unwrap();
        head.validate(lineage).unwrap();
        head
    }

    fn intent(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        kind: DirectOperationRuntimeAuthorityMutationKindV1,
        suffix: &str,
    ) -> DirectOperationRuntimeAuthorityMutationIntentV1 {
        let proposed = journal_version(
            &format!("proposed-journal-identity-{suffix}"),
            &format!("proposed-journal-bytes-{suffix}"),
        );
        let mut intent = DirectOperationRuntimeAuthorityMutationIntentV1 {
            schema: MUTATION_INTENT_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            from_committed_head_sha256: current.committed_head_sha256.clone(),
            from_mutation_generation: current.mutation_generation,
            mutation_kind: kind,
            expected_journal_version: current.journal_version.clone(),
            observed_current_journal_version: current.journal_version.clone(),
            to_mutation_generation: current.mutation_generation + 1,
            proposed_journal_version: proposed,
            mutation_nonce_sha256: digest(&format!("mutation-nonce-{suffix}")),
            mutation_intent_sha256: String::new(),
        };
        intent.mutation_intent_sha256 = intent.canonical_sha256().unwrap();
        intent.validate_for(lineage, current).unwrap();
        intent
    }

    fn prepared(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: &DirectOperationRuntimeAuthorityMutationIntentV1,
    ) -> DirectOperationRuntimeAuthorityPreparedHeadV1 {
        let mut prepared = DirectOperationRuntimeAuthorityPreparedHeadV1 {
            schema: PREPARED_HEAD_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            authority_identity_sha256: lineage.anchor.authority_identity_sha256.clone(),
            authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            from_committed_head_sha256: current.committed_head_sha256.clone(),
            from_mutation_generation: current.mutation_generation,
            to_mutation_generation: intent.to_mutation_generation,
            mutation_intent_sha256: intent.mutation_intent_sha256.clone(),
            expected_journal_version: intent.expected_journal_version.clone(),
            proposed_journal_version: intent.proposed_journal_version.clone(),
            prepared_head_sha256: String::new(),
        };
        prepared.prepared_head_sha256 = prepared.canonical_sha256().unwrap();
        prepared
            .validate_for_intent(lineage, current, intent)
            .unwrap();
        prepared
    }

    fn successor(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        prepared: &DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> DirectOperationRuntimeAuthorityCommittedHeadV1 {
        let mut head = DirectOperationRuntimeAuthorityCommittedHeadV1 {
            schema: COMMITTED_HEAD_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            authority_identity_sha256: lineage.anchor.authority_identity_sha256.clone(),
            authority_store_instance_sha256: lineage.anchor.authority_store_instance_sha256.clone(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            provider_id: lineage.anchor.provider_id.clone(),
            agent_id: lineage.anchor.agent_id.clone(),
            adapter: lineage.anchor.adapter,
            journal_epoch: lineage.anchor.journal_epoch.clone(),
            state_directory_identity_sha256: lineage.anchor.state_directory_identity_sha256.clone(),
            mutation_generation: prepared.to_mutation_generation,
            journal_version: prepared.proposed_journal_version.clone(),
            ancestry: DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
                predecessor_committed_head_sha256: current.committed_head_sha256.clone(),
                prepared_head_sha256: prepared.prepared_head_sha256.clone(),
            },
            committed_head_sha256: String::new(),
        };
        head.committed_head_sha256 = head.canonical_sha256().unwrap();
        head.validate_successor(lineage, current, prepared).unwrap();
        head
    }

    fn local_publication(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        prepared: &DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> DirectOperationRuntimeAuthorityLocalPublicationV1 {
        let mut publication = DirectOperationRuntimeAuthorityLocalPublicationV1 {
            schema: LOCAL_PUBLICATION_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            prepared_head_sha256: prepared.prepared_head_sha256.clone(),
            mutation_generation: prepared.to_mutation_generation,
            state_directory_identity_sha256: lineage.anchor.state_directory_identity_sha256.clone(),
            writer_lock_identity_sha256: digest("writer-lock"),
            named_journal_version: prepared.proposed_journal_version.clone(),
            local_publication_sha256: String::new(),
        };
        publication.local_publication_sha256 = publication.canonical_sha256().unwrap();
        publication.validate_for(lineage, prepared).unwrap();
        publication
    }

    fn prepare_request(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: &DirectOperationRuntimeAuthorityMutationIntentV1,
    ) -> DirectOperationRuntimeAuthorityPrepareRequestV1 {
        let mut request = DirectOperationRuntimeAuthorityPrepareRequestV1 {
            schema: PREPARE_REQUEST_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: PREPARE_OPERATION.to_string(),
            mutation_transaction_sha256: intent.mutation_intent_sha256.clone(),
            request_nonce_sha256: digest("prepare-request-nonce"),
            current_committed_head: current.clone(),
            mutation_intent: intent.clone(),
            request_sha256: String::new(),
        };
        request.request_sha256 = request.canonical_sha256().unwrap();
        request.validate(lineage).unwrap();
        request
    }

    fn prepare_receipt(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityPrepareRequestV1,
        prepared: &DirectOperationRuntimeAuthorityPreparedHeadV1,
    ) -> DirectOperationRuntimeAuthorityPrepareReceiptV1 {
        let mut receipt = DirectOperationRuntimeAuthorityPrepareReceiptV1 {
            schema: PREPARE_RECEIPT_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: PREPARE_OPERATION.to_string(),
            request_sha256: request.request_sha256.clone(),
            prepared_head: prepared.clone(),
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.canonical_sha256().unwrap();
        receipt.validate_for(lineage, request).unwrap();
        receipt
    }

    fn commit_request(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        prepare: &DirectOperationRuntimeAuthorityPrepareRequestV1,
        receipt: &DirectOperationRuntimeAuthorityPrepareReceiptV1,
    ) -> DirectOperationRuntimeAuthorityCommitRequestV1 {
        let mut request = DirectOperationRuntimeAuthorityCommitRequestV1 {
            schema: COMMIT_REQUEST_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: COMMIT_OPERATION.to_string(),
            mutation_transaction_sha256: prepare.mutation_transaction_sha256.clone(),
            request_nonce_sha256: digest("commit-request-nonce"),
            prepare_request_sha256: prepare.request_sha256.clone(),
            prepare_receipt_sha256: receipt.receipt_sha256.clone(),
            prepared_head_sha256: receipt.prepared_head.prepared_head_sha256.clone(),
            local_publication: local_publication(lineage, &receipt.prepared_head),
            request_sha256: String::new(),
        };
        request.request_sha256 = request.canonical_sha256().unwrap();
        request.validate_for(lineage, prepare, receipt).unwrap();
        request
    }

    fn commit_receipt(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        prepare: &DirectOperationRuntimeAuthorityPrepareRequestV1,
        prepare_receipt: &DirectOperationRuntimeAuthorityPrepareReceiptV1,
        request: &DirectOperationRuntimeAuthorityCommitRequestV1,
    ) -> DirectOperationRuntimeAuthorityCommitReceiptV1 {
        let committed = successor(lineage, current, &prepare_receipt.prepared_head);
        let mut receipt = DirectOperationRuntimeAuthorityCommitReceiptV1 {
            schema: COMMIT_RECEIPT_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: COMMIT_OPERATION.to_string(),
            request_sha256: request.request_sha256.clone(),
            committed_head: committed,
            receipt_sha256: String::new(),
        };
        receipt.receipt_sha256 = receipt.canonical_sha256().unwrap();
        receipt
            .validate_for(lineage, current, prepare, prepare_receipt, request)
            .unwrap();
        receipt
    }

    fn snapshot(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        committed: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        prepared_slot: DirectOperationRuntimeAuthorityPreparedSlotV1,
    ) -> DirectOperationRuntimeAuthoritySnapshotV1 {
        let mut snapshot = DirectOperationRuntimeAuthoritySnapshotV1 {
            schema: AUTHORITY_SNAPSHOT_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            committed_head: committed.clone(),
            prepared_slot,
            snapshot_sha256: String::new(),
        };
        snapshot.snapshot_sha256 = snapshot.canonical_sha256().unwrap();
        snapshot.validate(lineage).unwrap();
        snapshot
    }

    fn observe_request(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        expected: &DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> DirectOperationRuntimeAuthorityObserveRequestV1 {
        let mut request = DirectOperationRuntimeAuthorityObserveRequestV1 {
            schema: OBSERVE_REQUEST_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: OBSERVE_OPERATION.to_string(),
            observation_session_sha256: digest("observe-session"),
            request_nonce_sha256: digest("observe-nonce"),
            expected_committed_head_sha256: expected.committed_head_sha256.clone(),
            observed_journal_version: expected.journal_version.clone(),
            request_sha256: String::new(),
        };
        request.request_sha256 = request.canonical_sha256().unwrap();
        request.validate_for(lineage, expected).unwrap();
        request
    }

    fn observe_response(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityObserveRequestV1,
        expected: &DirectOperationRuntimeAuthorityCommittedHeadV1,
    ) -> DirectOperationRuntimeAuthorityObserveResponseV1 {
        let mut response = DirectOperationRuntimeAuthorityObserveResponseV1 {
            schema: OBSERVE_RESPONSE_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: OBSERVE_OPERATION.to_string(),
            request_sha256: request.request_sha256.clone(),
            snapshot: snapshot(
                lineage,
                expected,
                DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
            ),
            response_sha256: String::new(),
        };
        response.response_sha256 = response.canonical_sha256().unwrap();
        response.validate_for(lineage, request, expected).unwrap();
        response
    }

    #[derive(Clone)]
    enum LocalObservationSpec {
        Present(DirectOperationRuntimeAuthorityJournalVersionV1),
        Missing,
    }

    fn local_present(
        version: &DirectOperationRuntimeAuthorityJournalVersionV1,
    ) -> LocalObservationSpec {
        LocalObservationSpec::Present(version.clone())
    }

    fn local_missing() -> LocalObservationSpec {
        LocalObservationSpec::Missing
    }

    #[allow(clippy::too_many_arguments)]
    fn local_observation(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: &DirectOperationRuntimeAuthorityMutationIntentV1,
        cause: DirectOperationRuntimeAuthorityReconcileCauseV1,
        role: DirectOperationRuntimeAuthorityLocalEntryRoleV1,
        mutation_transaction_sha256: &str,
        request_nonce_sha256: &str,
        writer_lock_identity_sha256: &str,
        spec: LocalObservationSpec,
    ) -> DirectOperationRuntimeAuthorityLocalObservationV1 {
        let mut context = DirectOperationRuntimeAuthorityLocalObservationContextV1 {
            schema: LOCAL_OBSERVATION_CONTEXT_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            role,
            entry_domain: role.entry_domain().to_string(),
            entry_binding_sha256: String::new(),
            state_directory_identity_sha256: lineage.anchor.state_directory_identity_sha256.clone(),
            writer_lock_identity_sha256: writer_lock_identity_sha256.to_string(),
            first_use_lineage_sha256: lineage.first_use_lineage_sha256.clone(),
            mutation_transaction_sha256: mutation_transaction_sha256.to_string(),
            request_nonce_sha256: request_nonce_sha256.to_string(),
            mutation_intent_sha256: intent.mutation_intent_sha256.clone(),
            expected_committed_head_sha256: current.committed_head_sha256.clone(),
            expected_journal_version_sha256: current.journal_version.journal_version_sha256.clone(),
            proposed_journal_version_sha256: intent
                .proposed_journal_version
                .journal_version_sha256
                .clone(),
            reconcile_cause: cause,
            context_sha256: String::new(),
        };
        context.entry_binding_sha256 = context.canonical_entry_binding_sha256().unwrap();
        context.context_sha256 = context.canonical_sha256().unwrap();

        let mut observation = match spec {
            LocalObservationSpec::Present(journal_version) => {
                DirectOperationRuntimeAuthorityLocalObservationV1::Present {
                    context,
                    journal_version,
                    observation_sha256: String::new(),
                }
            }
            LocalObservationSpec::Missing => {
                DirectOperationRuntimeAuthorityLocalObservationV1::Missing {
                    context,
                    name_absent: true,
                    observation_sha256: String::new(),
                }
            }
        };
        let observation_sha256 = observation.canonical_sha256().unwrap();
        match &mut observation {
            DirectOperationRuntimeAuthorityLocalObservationV1::Present {
                observation_sha256: stored,
                ..
            }
            | DirectOperationRuntimeAuthorityLocalObservationV1::Missing {
                observation_sha256: stored,
                ..
            } => *stored = observation_sha256,
        }
        observation
    }

    fn local_observation_context_mut(
        observation: &mut DirectOperationRuntimeAuthorityLocalObservationV1,
    ) -> &mut DirectOperationRuntimeAuthorityLocalObservationContextV1 {
        match observation {
            DirectOperationRuntimeAuthorityLocalObservationV1::Present { context, .. }
            | DirectOperationRuntimeAuthorityLocalObservationV1::Missing { context, .. } => context,
        }
    }

    fn rehash_local_observation(
        observation: &mut DirectOperationRuntimeAuthorityLocalObservationV1,
    ) {
        let context = local_observation_context_mut(observation);
        context.entry_binding_sha256 = context.canonical_entry_binding_sha256().unwrap();
        context.context_sha256 = context.canonical_sha256().unwrap();
        let digest = observation.canonical_sha256().unwrap();
        match observation {
            DirectOperationRuntimeAuthorityLocalObservationV1::Present {
                observation_sha256,
                ..
            }
            | DirectOperationRuntimeAuthorityLocalObservationV1::Missing {
                observation_sha256,
                ..
            } => *observation_sha256 = digest,
        }
    }

    fn rehash_reconcile_request(request: &mut DirectOperationRuntimeAuthorityReconcileRequestV1) {
        request.request_sha256 = request.canonical_sha256().unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_request(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: &DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: &DirectOperationRuntimeAuthorityMutationIntentV1,
        cause: DirectOperationRuntimeAuthorityReconcileCauseV1,
        prepared_knowledge: DirectOperationRuntimeAuthorityPreparedKnowledgeV1,
        named: LocalObservationSpec,
        staged: LocalObservationSpec,
        nonce_label: &str,
    ) -> DirectOperationRuntimeAuthorityReconcileRequestV1 {
        let mutation_transaction_sha256 = intent.mutation_intent_sha256.clone();
        let request_nonce_sha256 = digest(nonce_label);
        let writer_lock_identity_sha256 = digest("reconcile-writer-lock");
        let observed_named_journal = local_observation(
            lineage,
            current,
            intent,
            cause,
            DirectOperationRuntimeAuthorityLocalEntryRoleV1::NamedJournal,
            &mutation_transaction_sha256,
            &request_nonce_sha256,
            &writer_lock_identity_sha256,
            named,
        );
        let observed_staged_candidate = local_observation(
            lineage,
            current,
            intent,
            cause,
            DirectOperationRuntimeAuthorityLocalEntryRoleV1::StagedCandidate,
            &mutation_transaction_sha256,
            &request_nonce_sha256,
            &writer_lock_identity_sha256,
            staged,
        );
        let mut request = DirectOperationRuntimeAuthorityReconcileRequestV1 {
            schema: RECONCILE_REQUEST_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: RECONCILE_OPERATION.to_string(),
            mutation_transaction_sha256,
            request_nonce_sha256,
            cause,
            expected_committed_head: current.clone(),
            mutation_intent: intent.clone(),
            prepared_knowledge,
            observed_named_journal,
            observed_staged_candidate,
            request_sha256: String::new(),
        };
        request.request_sha256 = request.canonical_sha256().unwrap();
        request
    }

    fn reconcile_response(
        _lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
        snapshot: DirectOperationRuntimeAuthoritySnapshotV1,
    ) -> DirectOperationRuntimeAuthorityReconcileResponseV1 {
        let mut response = DirectOperationRuntimeAuthorityReconcileResponseV1 {
            schema: RECONCILE_RESPONSE_V1_SCHEMA.to_string(),
            protocol: PROTOCOL.to_string(),
            operation: RECONCILE_OPERATION.to_string(),
            request_sha256: request.request_sha256.clone(),
            snapshot,
            response_sha256: String::new(),
        };
        response.response_sha256 = response.canonical_sha256().unwrap();
        response
    }

    fn canonical_round_trip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + Eq + Debug,
    {
        let bytes = serde_json::to_vec(value).unwrap();
        let decoded: T = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(&decoded, value);
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
    }

    fn assert_closed<T>(value: &T, missing: &str, typed: &str)
    where
        T: Serialize + DeserializeOwned,
    {
        let mut unknown = serde_json::to_value(value).unwrap();
        unknown["broker_authority_sha256"] = serde_json::json!(digest("wrong-domain"));
        assert!(serde_json::from_value::<T>(unknown).is_err());

        let mut missing_value = serde_json::to_value(value).unwrap();
        missing_value.as_object_mut().unwrap().remove(missing);
        assert!(serde_json::from_value::<T>(missing_value).is_err());

        let mut type_drift = serde_json::to_value(value).unwrap();
        type_drift[typed] = serde_json::json!(false);
        assert!(serde_json::from_value::<T>(type_drift).is_err());

        let bytes = serde_json::to_string(value).unwrap();
        let duplicate = format!("{{\"schema\":\"duplicate\",{}", &bytes[1..]);
        assert!(serde_json::from_str::<T>(&duplicate).is_err());
    }

    struct Flow {
        lineage: DirectOperationRuntimeAuthorityFirstUseLineageV1,
        current: DirectOperationRuntimeAuthorityCommittedHeadV1,
        intent: DirectOperationRuntimeAuthorityMutationIntentV1,
        prepared: DirectOperationRuntimeAuthorityPreparedHeadV1,
        prepare_request: DirectOperationRuntimeAuthorityPrepareRequestV1,
        prepare_receipt: DirectOperationRuntimeAuthorityPrepareReceiptV1,
        commit_request: DirectOperationRuntimeAuthorityCommitRequestV1,
        commit_receipt: DirectOperationRuntimeAuthorityCommitReceiptV1,
    }

    fn flow() -> Flow {
        let lineage = lineage();
        let current = genesis(&lineage);
        let intent = intent(
            &lineage,
            &current,
            DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            "begin",
        );
        let prepared = prepared(&lineage, &current, &intent);
        let prepare_request = prepare_request(&lineage, &current, &intent);
        let prepare_receipt = prepare_receipt(&lineage, &prepare_request, &prepared);
        let commit_request = commit_request(&lineage, &prepare_request, &prepare_receipt);
        let commit_receipt = commit_receipt(
            &lineage,
            &current,
            &prepare_request,
            &prepare_receipt,
            &commit_request,
        );
        Flow {
            lineage,
            current,
            intent,
            prepared,
            prepare_request,
            prepare_receipt,
            commit_request,
            commit_receipt,
        }
    }

    #[test]
    fn all_contracts_round_trip_canonically_and_are_closed() {
        let flow = flow();
        let observe_request = observe_request(&flow.lineage, &flow.current);
        let observe_response = observe_response(&flow.lineage, &observe_request, &flow.current);
        let snapshot = snapshot(
            &flow.lineage,
            &flow.current,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                prepared_head: flow.prepared.clone(),
            },
        );
        let reconcile_request = reconcile_request(
            &flow.lineage,
            &flow.current,
            &flow.intent,
            DirectOperationRuntimeAuthorityReconcileCauseV1::RestartWithPrepared,
            DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
                prepared_head: flow.prepared.clone(),
            },
            local_present(&flow.current.journal_version),
            local_present(&flow.intent.proposed_journal_version),
            "canonical-reconcile",
        );
        let reconcile_response = reconcile_response(&flow.lineage, &reconcile_request, snapshot);
        let disposition = reconcile_response
            .disposition_for(&flow.lineage, &reconcile_request)
            .unwrap();
        assert_eq!(
            disposition,
            DirectOperationRuntimeAuthorityReconcileDispositionV1::ResumeExactPreparedPublication
        );

        canonical_round_trip(&flow.lineage);
        canonical_round_trip(&flow.lineage.anchor);
        canonical_round_trip(&flow.lineage.candidate);
        canonical_round_trip(&flow.lineage.prepared_head);
        canonical_round_trip(&flow.lineage.committed_head);
        canonical_round_trip(&flow.lineage.committed_result_binding);
        canonical_round_trip(&flow.current.journal_version);
        canonical_round_trip(&flow.current);
        canonical_round_trip(&flow.intent);
        canonical_round_trip(&flow.prepared);
        canonical_round_trip(&flow.commit_request.local_publication);
        canonical_round_trip(&flow.prepare_request);
        canonical_round_trip(&flow.prepare_receipt);
        canonical_round_trip(&flow.commit_request);
        canonical_round_trip(&flow.commit_receipt);
        canonical_round_trip(&observe_request);
        canonical_round_trip(&observe_response);
        canonical_round_trip(reconcile_request.observed_named_journal.context());
        canonical_round_trip(&reconcile_request.observed_named_journal);
        canonical_round_trip(reconcile_request.observed_staged_candidate.context());
        canonical_round_trip(&reconcile_request.observed_staged_candidate);
        canonical_round_trip(&reconcile_request);
        canonical_round_trip(&reconcile_response);
        canonical_round_trip(&disposition);

        assert_closed::<DirectOperationRuntimeAuthorityFirstUseLineageV1>(
            &flow.lineage,
            "anchor",
            "protocol",
        );
        assert_closed::<DirectOperationRuntimeAuthorityFirstUseAnchorV1>(
            &flow.lineage.anchor,
            "agent_id",
            "protocol",
        );
        assert_closed::<DirectOperationRuntimeAuthorityFirstUseCandidateV1>(
            &flow.lineage.candidate,
            "candidate_nonce_sha256",
            "protocol",
        );
        assert_closed::<DirectOperationRuntimeAuthorityFirstUsePreparedHeadV1>(
            &flow.lineage.prepared_head,
            "prepare_nonce_sha256",
            "protocol",
        );
        assert_closed::<DirectOperationRuntimeAuthorityFirstUseCommittedHeadV1>(
            &flow.lineage.committed_head,
            "durable_commit_evidence_sha256",
            "protocol",
        );
        assert_closed::<DirectOperationRuntimeAuthorityFirstUseCommittedResultBindingV1>(
            &flow.lineage.committed_result_binding,
            "result_receipt_sha256",
            "protocol",
        );
        assert_closed::<DirectOperationRuntimeAuthorityPrepareRequestV1>(
            &flow.prepare_request,
            "mutation_intent",
            "operation",
        );
        assert_closed::<DirectOperationRuntimeAuthorityCommitRequestV1>(
            &flow.commit_request,
            "local_publication",
            "operation",
        );
        assert_closed::<DirectOperationRuntimeAuthorityObserveResponseV1>(
            &observe_response,
            "snapshot",
            "operation",
        );
        assert_closed::<DirectOperationRuntimeAuthorityReconcileRequestV1>(
            &reconcile_request,
            "cause",
            "operation",
        );
        assert_closed::<DirectOperationRuntimeAuthorityLocalObservationContextV1>(
            reconcile_request.observed_named_journal.context(),
            "writer_lock_identity_sha256",
            "role",
        );
        assert_closed::<DirectOperationRuntimeAuthorityLocalObservationV1>(
            &reconcile_request.observed_staged_candidate,
            "context",
            "observation_sha256",
        );
    }

    #[test]
    fn lineage_current_and_nested_digest_drift_fail_closed() {
        let flow = flow();

        let mut uppercase = flow.lineage.clone();
        uppercase.anchor.authority_identity_sha256 = "A".repeat(64);
        assert!(uppercase.canonical_sha256().is_err());
        assert!(uppercase.validate().is_err());

        let mut cross_store = flow.current.clone();
        cross_store.authority_store_instance_sha256 = digest("other-store");
        cross_store.committed_head_sha256 = cross_store.canonical_sha256().unwrap();
        assert!(cross_store.validate(&flow.lineage).is_err());

        let mut observed_drift = flow.intent.clone();
        observed_drift.observed_current_journal_version =
            journal_version("other-current-identity", "other-current-bytes");
        observed_drift.mutation_intent_sha256 = observed_drift.canonical_sha256().unwrap();
        assert!(
            observed_drift
                .validate_for(&flow.lineage, &flow.current)
                .is_err()
        );

        let mut request_drift = flow.prepare_receipt.clone();
        request_drift.request_sha256 = digest("other-request");
        request_drift.receipt_sha256 = request_drift.canonical_sha256().unwrap();
        assert!(
            request_drift
                .validate_for(&flow.lineage, &flow.prepare_request)
                .is_err()
        );

        let mut local_drift = flow.commit_request.local_publication.clone();
        local_drift.named_journal_version =
            journal_version("other-published-identity", "other-published-bytes");
        local_drift.local_publication_sha256 = local_drift.canonical_sha256().unwrap();
        assert!(
            local_drift
                .validate_for(&flow.lineage, &flow.prepared)
                .is_err()
        );
    }

    #[test]
    fn first_use_chain_rejects_structural_drift_after_every_affected_rehash() {
        let original = lineage();

        let mut candidate_anchor_drift = original.clone();
        candidate_anchor_drift.candidate.first_use_anchor_sha256 =
            digest("forged-first-use-anchor");
        rehash_first_use_descendants(&mut candidate_anchor_drift);
        assert!(candidate_anchor_drift.validate().is_err());

        let mut candidate_genesis_drift = original.clone();
        candidate_genesis_drift
            .candidate
            .proposed_genesis_journal_version_sha256 = digest("forged-candidate-genesis");
        rehash_first_use_descendants(&mut candidate_genesis_drift);
        assert!(candidate_genesis_drift.validate().is_err());

        let mut prepared_sentinel_drift = original.clone();
        prepared_sentinel_drift
            .prepared_head
            .prepared_sentinel_bytes_sha256 = digest("forged-prepared-sentinel");
        rehash_first_use_descendants(&mut prepared_sentinel_drift);
        assert!(prepared_sentinel_drift.validate().is_err());

        let mut committed_journal_drift = original.clone();
        committed_journal_drift
            .committed_head
            .committed_genesis_journal_version =
            journal_version("forged-genesis-identity", "forged-genesis-bytes");
        rehash_first_use_descendants(&mut committed_journal_drift);
        assert!(committed_journal_drift.validate().is_err());

        let mut result_sentinel_drift = original;
        result_sentinel_drift
            .committed_result_binding
            .committed_sentinel_identity_sha256 = digest("forged-result-sentinel");
        rehash_first_use_descendants(&mut result_sentinel_drift);
        assert!(result_sentinel_drift.validate().is_err());
    }

    #[test]
    fn first_use_anchor_uses_pre_staged_immutable_sentinel_v2() {
        let mut first_use = lineage();
        let sentinel_before = first_use.anchor.sentinel_bytes_sha256.clone();
        let expected_bytes =
            independently_frame_immutable_sentinel(&immutable_sentinel_fields(&first_use.anchor));
        assert_eq!(
            first_use.anchor.immutable_sentinel_schema,
            FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA
        );
        assert!(!first_use.anchor.immutable_sentinel_embeds_prepared_head);
        assert_eq!(
            first_use
                .anchor
                .canonical_immutable_sentinel_bytes()
                .unwrap(),
            expected_bytes
        );
        assert_eq!(expected_bytes.len(), 965);
        assert_eq!(
            first_use
                .anchor
                .canonical_immutable_sentinel_bytes_sha256()
                .unwrap(),
            sentinel_before
        );
        assert_eq!(sentinel_before, sha256_bytes(&expected_bytes));
        assert_eq!(
            sentinel_before,
            "81cba1e71e924cb7a8cfbeb5506efaeb8dc54d4e57ce5317283e768be39fbefc"
        );

        first_use.prepared_head.prepare_nonce_sha256 = digest("different-prepared-head");
        rehash_first_use_descendants(&mut first_use);
        assert_eq!(first_use.anchor.sentinel_bytes_sha256, sentinel_before);
        first_use.validate().unwrap();

        let mut cyclic = lineage();
        cyclic.anchor.immutable_sentinel_embeds_prepared_head = true;
        assert!(
            cyclic
                .anchor
                .canonical_immutable_sentinel_bytes_sha256()
                .is_err()
        );
        assert!(cyclic.validate().is_err());
    }

    #[test]
    fn immutable_sentinel_rejects_noncanonical_encodings() {
        let anchor = lineage().anchor;

        let json = serde_json::to_vec(&anchor).unwrap();
        assert_noncanonical_sentinel_rejected(anchor.clone(), &json);

        let mut newline = anchor.canonical_immutable_sentinel_bytes().unwrap();
        newline.push(b'\n');
        assert_noncanonical_sentinel_rejected(anchor.clone(), &newline);

        let mut reordered_fields = immutable_sentinel_fields(&anchor);
        reordered_fields.swap(0, 1);
        let reordered = independently_frame_immutable_sentinel(&reordered_fields);
        assert_noncanonical_sentinel_rejected(anchor.clone(), &reordered);

        let mut malformed_length = anchor.canonical_immutable_sentinel_bytes().unwrap();
        let first_name_length_last_byte = FIRST_USE_IMMUTABLE_SENTINEL_V2_SCHEMA.len() + 4;
        malformed_length[first_name_length_last_byte] ^= 1;
        assert_noncanonical_sentinel_rejected(anchor.clone(), &malformed_length);

        let mut trailing = anchor.canonical_immutable_sentinel_bytes().unwrap();
        trailing.push(0);
        assert_noncanonical_sentinel_rejected(anchor.clone(), &trailing);

        let mut protocol_fields = immutable_sentinel_fields(&anchor);
        protocol_fields[1].1 = "trillionnium.direct-operation-runtime-authority-mutation-cas.v0";
        let protocol_drift = independently_frame_immutable_sentinel(&protocol_fields);
        assert_noncanonical_sentinel_rejected(anchor.clone(), &protocol_drift);

        let mut phase_fields = immutable_sentinel_fields(&anchor);
        phase_fields[2].1 = "pre-staged-immutable";
        let phase_drift = independently_frame_immutable_sentinel(&phase_fields);
        assert_noncanonical_sentinel_rejected(anchor, &phase_drift);
    }

    #[test]
    fn immutable_sentinel_rejects_invalid_protocol_and_nested_lineage() {
        let mut protocol_drift = lineage().anchor;
        protocol_drift.protocol =
            "trillionnium.direct-operation-runtime-authority-mutation-cas.v0".to_string();
        assert!(protocol_drift.canonical_immutable_sentinel_bytes().is_err());
        assert!(protocol_drift.validate().is_err());

        let mut nested_protocol_drift = lineage().anchor;
        nested_protocol_drift.genesis_journal_version.protocol =
            "trillionnium.direct-operation-runtime-authority-mutation-cas.v0".to_string();
        assert!(
            nested_protocol_drift
                .canonical_immutable_sentinel_bytes()
                .is_err()
        );
        assert!(nested_protocol_drift.validate().is_err());

        let mut uppercase_digest = lineage().anchor;
        uppercase_digest.authority_identity_sha256 =
            uppercase_digest.authority_identity_sha256.to_uppercase();
        assert!(
            uppercase_digest
                .canonical_immutable_sentinel_bytes()
                .is_err()
        );
        assert!(uppercase_digest.validate().is_err());

        let mut all_zero_digest = lineage().anchor;
        all_zero_digest.authority_identity_sha256 = "0".repeat(64);
        assert!(
            all_zero_digest
                .canonical_immutable_sentinel_bytes()
                .is_err()
        );
        assert!(all_zero_digest.validate().is_err());
    }

    #[test]
    fn generation_is_exactly_plus_one_and_forks_are_rejected() {
        let flow = flow();
        let successor = &flow.commit_receipt.committed_head;

        let mut gap = successor.clone();
        gap.mutation_generation += 1;
        gap.committed_head_sha256 = gap.canonical_sha256().unwrap();
        gap.validate(&flow.lineage).unwrap();
        assert!(
            gap.validate_successor(&flow.lineage, &flow.current, &flow.prepared)
                .is_err()
        );

        let mut fork = successor.clone();
        fork.journal_version = journal_version("fork-identity", "fork-bytes");
        fork.committed_head_sha256 = fork.canonical_sha256().unwrap();
        fork.validate(&flow.lineage).unwrap();
        assert!(
            fork.validate_successor(&flow.lineage, &flow.current, &flow.prepared)
                .is_err()
        );

        let mut stale = flow.intent.clone();
        stale.from_mutation_generation = 2;
        stale.to_mutation_generation = 3;
        stale.mutation_intent_sha256 = stale.canonical_sha256().unwrap();
        assert!(stale.validate_for(&flow.lineage, &flow.current).is_err());

        let mut skipped = flow.intent.clone();
        skipped.to_mutation_generation += 1;
        assert!(skipped.canonical_sha256().is_err());
    }

    #[test]
    fn generation_overflow_is_rejected_across_prepare_and_commit_chain() {
        let flow = flow();
        let mut max_head = flow.current.clone();
        max_head.mutation_generation = u64::MAX;
        max_head.ancestry = DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
            predecessor_committed_head_sha256: digest("max-generation-predecessor"),
            prepared_head_sha256: digest("max-generation-prepared"),
        };
        max_head.committed_head_sha256 = max_head.canonical_sha256().unwrap();
        max_head.validate(&flow.lineage).unwrap();

        let mut overflow_intent = flow.intent.clone();
        overflow_intent.from_committed_head_sha256 = max_head.committed_head_sha256.clone();
        overflow_intent.from_mutation_generation = u64::MAX;
        overflow_intent.to_mutation_generation = 0;
        overflow_intent.expected_journal_version = max_head.journal_version.clone();
        overflow_intent.observed_current_journal_version = max_head.journal_version.clone();
        overflow_intent.mutation_intent_sha256 = digest("forged-overflow-intent");
        assert!(overflow_intent.canonical_sha256().is_err());
        assert!(
            overflow_intent
                .validate_for(&flow.lineage, &max_head)
                .is_err()
        );

        let mut overflow_prepared = flow.prepared.clone();
        overflow_prepared.from_committed_head_sha256 = max_head.committed_head_sha256.clone();
        overflow_prepared.from_mutation_generation = u64::MAX;
        overflow_prepared.to_mutation_generation = 0;
        overflow_prepared.mutation_intent_sha256 = overflow_intent.mutation_intent_sha256.clone();
        overflow_prepared.expected_journal_version = max_head.journal_version.clone();
        overflow_prepared.proposed_journal_version =
            overflow_intent.proposed_journal_version.clone();
        overflow_prepared.prepared_head_sha256 = digest("forged-overflow-prepared");
        assert!(overflow_prepared.canonical_sha256().is_err());
        assert!(
            overflow_prepared
                .validate_for_intent(&flow.lineage, &max_head, &overflow_intent)
                .is_err()
        );

        let mut prepare = flow.prepare_request.clone();
        prepare.current_committed_head = max_head.clone();
        prepare.mutation_intent = overflow_intent;
        prepare.mutation_transaction_sha256 =
            prepare.mutation_intent.mutation_intent_sha256.clone();
        prepare.request_sha256 = prepare.canonical_sha256().unwrap();
        assert!(prepare.validate(&flow.lineage).is_err());

        let mut prepare_receipt = flow.prepare_receipt.clone();
        prepare_receipt.request_sha256 = prepare.request_sha256.clone();
        prepare_receipt.prepared_head = overflow_prepared;
        prepare_receipt.receipt_sha256 = prepare_receipt.canonical_sha256().unwrap();
        assert!(
            prepare_receipt
                .validate_for(&flow.lineage, &prepare)
                .is_err()
        );

        let mut commit = flow.commit_request.clone();
        commit.prepare_request_sha256 = prepare.request_sha256.clone();
        commit.prepare_receipt_sha256 = prepare_receipt.receipt_sha256.clone();
        commit.prepared_head_sha256 = prepare_receipt.prepared_head.prepared_head_sha256.clone();
        commit.mutation_transaction_sha256 = prepare.mutation_transaction_sha256.clone();
        commit.request_sha256 = commit.canonical_sha256().unwrap();
        assert!(
            commit
                .validate_for(&flow.lineage, &prepare, &prepare_receipt)
                .is_err()
        );

        let mut commit_receipt = flow.commit_receipt.clone();
        commit_receipt.request_sha256 = commit.request_sha256.clone();
        commit_receipt.receipt_sha256 = commit_receipt.canonical_sha256().unwrap();
        assert!(
            commit_receipt
                .validate_for(
                    &flow.lineage,
                    &max_head,
                    &prepare,
                    &prepare_receipt,
                    &commit,
                )
                .is_err()
        );
    }

    #[test]
    fn all_four_mutation_kinds_are_closed_distinct_transitions() {
        let lineage = lineage();
        let current = genesis(&lineage);
        let kinds = [
            DirectOperationRuntimeAuthorityMutationKindV1::BeginEffect,
            DirectOperationRuntimeAuthorityMutationKindV1::PersistPreparedTransportAck,
            DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            DirectOperationRuntimeAuthorityMutationKindV1::AcknowledgeOuterV2,
        ];
        let mut digests = std::collections::HashSet::new();
        for (index, kind) in kinds.into_iter().enumerate() {
            let intent = intent(&lineage, &current, kind, &index.to_string());
            assert!(digests.insert(intent.mutation_intent_sha256));
        }
        assert!(
            serde_json::from_str::<DirectOperationRuntimeAuthorityMutationKindV1>(
                "\"model_authored_mutation\""
            )
            .is_err()
        );
    }

    #[test]
    fn phase_types_and_response_correlation_are_not_interchangeable() {
        let flow = flow();
        let prepare_json = serde_json::to_value(&flow.prepare_receipt).unwrap();
        assert!(
            serde_json::from_value::<DirectOperationRuntimeAuthorityCommitReceiptV1>(prepare_json)
                .is_err()
        );

        let observe_request = observe_request(&flow.lineage, &flow.current);
        let observe_response = observe_response(&flow.lineage, &observe_request, &flow.current);
        let reconcile_request = reconcile_request(
            &flow.lineage,
            &flow.current,
            &flow.intent,
            DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown,
            DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown,
            local_present(&flow.current.journal_version),
            local_present(&flow.intent.proposed_journal_version),
            "phase-reconcile",
        );
        let mut phase_drift = DirectOperationRuntimeAuthorityReconcileResponseV1 {
            schema: observe_response.schema,
            protocol: observe_response.protocol,
            operation: observe_response.operation,
            request_sha256: observe_response.request_sha256,
            snapshot: observe_response.snapshot,
            response_sha256: observe_response.response_sha256,
        };
        assert!(
            phase_drift
                .validate_for(&flow.lineage, &reconcile_request)
                .is_err()
        );
        assert!(
            phase_drift
                .disposition_for(&flow.lineage, &reconcile_request)
                .is_err()
        );
        phase_drift.schema = RECONCILE_RESPONSE_V1_SCHEMA.to_string();
        phase_drift.operation = RECONCILE_OPERATION.to_string();
        phase_drift.response_sha256 = phase_drift.canonical_sha256().unwrap();
        assert!(
            phase_drift
                .validate_for(&flow.lineage, &reconcile_request)
                .is_err()
        );
        assert!(
            phase_drift
                .disposition_for(&flow.lineage, &reconcile_request)
                .is_err()
        );
        assert!(
            serde_json::from_str::<DirectOperationRuntimeAuthorityReconcileDispositionV1>(
                "\"continue_effect\""
            )
            .is_err()
        );

        let mut commit_correlation = flow.commit_receipt.clone();
        commit_correlation.request_sha256 = digest("wrong-commit-request");
        commit_correlation.receipt_sha256 = commit_correlation.canonical_sha256().unwrap();
        assert!(
            commit_correlation
                .validate_for(
                    &flow.lineage,
                    &flow.current,
                    &flow.prepare_request,
                    &flow.prepare_receipt,
                    &flow.commit_request,
                )
                .is_err()
        );
    }

    #[test]
    fn local_observations_reject_arbitrary_missing_and_context_drift_after_rehash() {
        let flow = flow();
        let known = DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
            prepared_head: flow.prepared.clone(),
        };
        let request = reconcile_request(
            &flow.lineage,
            &flow.current,
            &flow.intent,
            DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
            known,
            local_present(&flow.intent.proposed_journal_version),
            local_missing(),
            "structured-observation",
        );
        request.validate(&flow.lineage).unwrap();

        let mut arbitrary_missing = request.clone();
        if let DirectOperationRuntimeAuthorityLocalObservationV1::Missing {
            observation_sha256,
            ..
        } = &mut arbitrary_missing.observed_staged_candidate
        {
            *observation_sha256 = digest("anything");
        } else {
            panic!("fixture must carry a staged Missing observation");
        }
        assert!(arbitrary_missing.canonical_sha256().is_err());
        arbitrary_missing.request_sha256 = digest("fully-rehashed-outer-request");
        assert!(arbitrary_missing.validate(&flow.lineage).is_err());

        let mut role_swap = request.clone();
        let named = role_swap.observed_named_journal.clone();
        role_swap.observed_named_journal = role_swap.observed_staged_candidate.clone();
        role_swap.observed_staged_candidate = named;
        rehash_reconcile_request(&mut role_swap);
        assert!(role_swap.validate(&flow.lineage).is_err());

        let mut transaction_drift = request.clone();
        transaction_drift.mutation_transaction_sha256 = digest("other-transaction");
        for observation in [
            &mut transaction_drift.observed_named_journal,
            &mut transaction_drift.observed_staged_candidate,
        ] {
            local_observation_context_mut(observation).mutation_transaction_sha256 =
                transaction_drift.mutation_transaction_sha256.clone();
            rehash_local_observation(observation);
        }
        rehash_reconcile_request(&mut transaction_drift);
        assert!(transaction_drift.validate(&flow.lineage).is_err());

        let mut nonce_drift = request.clone();
        for observation in [
            &mut nonce_drift.observed_named_journal,
            &mut nonce_drift.observed_staged_candidate,
        ] {
            local_observation_context_mut(observation).request_nonce_sha256 =
                digest("other-observation-nonce");
            rehash_local_observation(observation);
        }
        rehash_reconcile_request(&mut nonce_drift);
        assert!(nonce_drift.validate(&flow.lineage).is_err());

        let mut cause_drift = request.clone();
        for observation in [
            &mut cause_drift.observed_named_journal,
            &mut cause_drift.observed_staged_candidate,
        ] {
            local_observation_context_mut(observation).reconcile_cause =
                DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown;
            rehash_local_observation(observation);
        }
        rehash_reconcile_request(&mut cause_drift);
        assert!(cause_drift.validate(&flow.lineage).is_err());

        let mut lock_drift = request.clone();
        local_observation_context_mut(&mut lock_drift.observed_staged_candidate)
            .writer_lock_identity_sha256 = digest("other-writer-lock");
        rehash_local_observation(&mut lock_drift.observed_staged_candidate);
        rehash_reconcile_request(&mut lock_drift);
        assert!(lock_drift.validate(&flow.lineage).is_err());

        let mut version_drift = request.clone();
        local_observation_context_mut(&mut version_drift.observed_staged_candidate)
            .proposed_journal_version_sha256 = digest("other-proposed-version");
        rehash_local_observation(&mut version_drift.observed_staged_candidate);
        rehash_reconcile_request(&mut version_drift);
        assert!(version_drift.validate(&flow.lineage).is_err());

        let mut present_version_drift = request;
        if let DirectOperationRuntimeAuthorityLocalObservationV1::Present {
            journal_version: observed_version,
            ..
        } = &mut present_version_drift.observed_named_journal
        {
            *observed_version = journal_version("unrelated-local-entry", "unrelated-local-bytes");
        } else {
            panic!("fixture must carry a named Present observation");
        }
        rehash_local_observation(&mut present_version_drift.observed_named_journal);
        rehash_reconcile_request(&mut present_version_drift);
        assert!(present_version_drift.validate(&flow.lineage).is_err());

        assert!(
            serde_json::from_str::<DirectOperationRuntimeAuthorityLocalEntryRoleV1>(
                "\"caller_selected_path\""
            )
            .is_err()
        );
    }

    #[test]
    fn durable_transaction_survives_nonce_retry_and_rejects_cross_phase_drift() {
        let flow = flow();

        let mut prepare_retry = flow.prepare_request.clone();
        prepare_retry.request_nonce_sha256 = digest("retry-transport-challenge");
        prepare_retry.request_sha256 = prepare_retry.canonical_sha256().unwrap();
        prepare_retry.validate(&flow.lineage).unwrap();
        assert_eq!(
            prepare_retry.mutation_transaction_sha256,
            flow.intent.mutation_intent_sha256
        );
        assert_ne!(
            prepare_retry.request_sha256,
            flow.prepare_request.request_sha256
        );

        let mut commit_transaction_drift = flow.commit_request.clone();
        commit_transaction_drift.mutation_transaction_sha256 = digest("other-commit-transaction");
        commit_transaction_drift.request_sha256 =
            commit_transaction_drift.canonical_sha256().unwrap();
        assert!(
            commit_transaction_drift
                .validate_for(&flow.lineage, &flow.prepare_request, &flow.prepare_receipt,)
                .is_err()
        );

        let known = DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
            prepared_head: flow.prepared.clone(),
        };
        let first_reconcile = reconcile_request(
            &flow.lineage,
            &flow.current,
            &flow.intent,
            DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
            known.clone(),
            local_present(&flow.intent.proposed_journal_version),
            local_missing(),
            "first-reconcile-transport",
        );
        let retried_reconcile = reconcile_request(
            &flow.lineage,
            &flow.current,
            &flow.intent,
            DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
            known,
            local_present(&flow.intent.proposed_journal_version),
            local_missing(),
            "retried-reconcile-transport",
        );
        first_reconcile.validate(&flow.lineage).unwrap();
        retried_reconcile.validate(&flow.lineage).unwrap();
        assert_eq!(
            first_reconcile.mutation_transaction_sha256,
            retried_reconcile.mutation_transaction_sha256
        );
        assert_ne!(
            first_reconcile.request_nonce_sha256,
            retried_reconcile.request_nonce_sha256
        );

        let observe = observe_request(&flow.lineage, &flow.current);
        let mut observe_retry = observe.clone();
        observe_retry.observation_session_sha256 = digest("new-observation-session");
        observe_retry.request_nonce_sha256 = digest("new-observation-nonce");
        observe_retry.request_sha256 = observe_retry.canonical_sha256().unwrap();
        observe_retry
            .validate_for(&flow.lineage, &flow.current)
            .unwrap();
        assert_ne!(
            observe.observation_session_sha256,
            observe_retry.observation_session_sha256
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReconcileDisposition {
        NoMutation,
        ResumeExactPreparedPublication,
        RetryExactCommit,
        Committed,
        Hold,
    }

    fn classify_reconcile(
        lineage: &DirectOperationRuntimeAuthorityFirstUseLineageV1,
        request: &DirectOperationRuntimeAuthorityReconcileRequestV1,
        response: &DirectOperationRuntimeAuthorityReconcileResponseV1,
    ) -> ReconcileDisposition {
        match response.disposition_for(lineage, request) {
            Err(_) => ReconcileDisposition::Hold,
            Ok(
                DirectOperationRuntimeAuthorityReconcileDispositionV1::NoMutation,
            ) => {
                ReconcileDisposition::NoMutation
            }
            Ok(
                DirectOperationRuntimeAuthorityReconcileDispositionV1::ResumeExactPreparedPublication,
            ) => ReconcileDisposition::ResumeExactPreparedPublication,
            Ok(
                DirectOperationRuntimeAuthorityReconcileDispositionV1::RetryExactCommit,
            ) => ReconcileDisposition::RetryExactCommit,
            Ok(DirectOperationRuntimeAuthorityReconcileDispositionV1::Committed) => {
                ReconcileDisposition::Committed
            }
        }
    }

    #[test]
    fn reconcile_truth_table_is_fail_closed() {
        let flow = flow();
        let c0_empty = snapshot(
            &flow.lineage,
            &flow.current,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        );
        let c0_pending = snapshot(
            &flow.lineage,
            &flow.current,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                prepared_head: flow.prepared.clone(),
            },
        );
        let c1_empty = snapshot(
            &flow.lineage,
            &flow.commit_receipt.committed_head,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        );
        let old = local_present(&flow.current.journal_version);
        let proposed = local_present(&flow.intent.proposed_journal_version);
        let missing = local_missing();
        let other = local_present(&journal_version("third-identity", "third-bytes"));
        let known = DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
            prepared_head: flow.prepared.clone(),
        };

        let cases = [
            (
                DirectOperationRuntimeAuthorityReconcileCauseV1::PrepareResponseUnknown,
                DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown,
                old.clone(),
                proposed.clone(),
                c0_empty,
                ReconcileDisposition::NoMutation,
            ),
            (
                DirectOperationRuntimeAuthorityReconcileCauseV1::RestartWithPrepared,
                known.clone(),
                old.clone(),
                proposed.clone(),
                c0_pending.clone(),
                ReconcileDisposition::ResumeExactPreparedPublication,
            ),
            (
                DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
                known.clone(),
                proposed.clone(),
                missing.clone(),
                c0_pending.clone(),
                ReconcileDisposition::RetryExactCommit,
            ),
            (
                DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
                known.clone(),
                proposed.clone(),
                missing.clone(),
                c0_pending,
                ReconcileDisposition::RetryExactCommit,
            ),
            (
                DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
                known.clone(),
                proposed.clone(),
                missing.clone(),
                c1_empty.clone(),
                ReconcileDisposition::Committed,
            ),
            (
                DirectOperationRuntimeAuthorityReconcileCauseV1::LocalPublicationUnknown,
                known.clone(),
                proposed.clone(),
                missing.clone(),
                snapshot(
                    &flow.lineage,
                    &flow.current,
                    DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
                ),
                ReconcileDisposition::Hold,
            ),
            (
                DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
                known.clone(),
                old.clone(),
                missing.clone(),
                c1_empty,
                ReconcileDisposition::Hold,
            ),
            (
                DirectOperationRuntimeAuthorityReconcileCauseV1::RestartWithPrepared,
                known,
                other,
                missing,
                snapshot(
                    &flow.lineage,
                    &flow.current,
                    DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                        prepared_head: flow.prepared.clone(),
                    },
                ),
                ReconcileDisposition::Hold,
            ),
        ];

        for (index, (cause, knowledge, named, staged, authority, expected)) in
            cases.into_iter().enumerate()
        {
            let request = reconcile_request(
                &flow.lineage,
                &flow.current,
                &flow.intent,
                cause,
                knowledge,
                named,
                staged,
                &format!("truth-table-{index}"),
            );
            let response = reconcile_response(&flow.lineage, &request, authority);
            assert_eq!(
                classify_reconcile(&flow.lineage, &request, &response),
                expected
            );
        }
    }

    #[test]
    fn commit_response_unknown_retries_only_exact_pending_publication() {
        let flow = flow();
        let known = DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
            prepared_head: flow.prepared.clone(),
        };
        let exact_request = reconcile_request(
            &flow.lineage,
            &flow.current,
            &flow.intent,
            DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
            known.clone(),
            local_present(&flow.intent.proposed_journal_version),
            local_missing(),
            "commit-unknown-exact-pending",
        );
        let exact_pending = snapshot(
            &flow.lineage,
            &flow.current,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                prepared_head: flow.prepared.clone(),
            },
        );
        let exact_response =
            reconcile_response(&flow.lineage, &exact_request, exact_pending.clone());
        assert_eq!(
            classify_reconcile(&flow.lineage, &exact_request, &exact_response),
            ReconcileDisposition::RetryExactCommit
        );

        let unknown_prepared_request = reconcile_request(
            &flow.lineage,
            &flow.current,
            &flow.intent,
            DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
            DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Unknown,
            local_present(&flow.intent.proposed_journal_version),
            local_missing(),
            "commit-unknown-prepared-unknown",
        );
        let unknown_prepared_response = reconcile_response(
            &flow.lineage,
            &unknown_prepared_request,
            exact_pending.clone(),
        );
        assert_eq!(
            classify_reconcile(
                &flow.lineage,
                &unknown_prepared_request,
                &unknown_prepared_response,
            ),
            ReconcileDisposition::Hold
        );

        let alternate_intent = intent(
            &flow.lineage,
            &flow.current,
            DirectOperationRuntimeAuthorityMutationKindV1::RecordClassifiedResult,
            "alternate-prepared",
        );
        let alternate_prepared = prepared(&flow.lineage, &flow.current, &alternate_intent);
        let prepared_mismatch = snapshot(
            &flow.lineage,
            &flow.current,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                prepared_head: alternate_prepared.clone(),
            },
        );
        let prepared_mismatch_response =
            reconcile_response(&flow.lineage, &exact_request, prepared_mismatch);
        assert_eq!(
            classify_reconcile(&flow.lineage, &exact_request, &prepared_mismatch_response),
            ReconcileDisposition::Hold
        );

        let stale_snapshot = snapshot(
            &flow.lineage,
            &flow.current,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        );
        let stale_response = reconcile_response(&flow.lineage, &exact_request, stale_snapshot);
        assert_eq!(
            classify_reconcile(&flow.lineage, &exact_request, &stale_response),
            ReconcileDisposition::Hold
        );

        let fork_head = successor(&flow.lineage, &flow.current, &alternate_prepared);
        let fork_snapshot = snapshot(
            &flow.lineage,
            &fork_head,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        );
        let fork_response = reconcile_response(&flow.lineage, &exact_request, fork_snapshot);
        assert_eq!(
            classify_reconcile(&flow.lineage, &exact_request, &fork_response),
            ReconcileDisposition::Hold
        );

        for (index, (named, staged)) in [
            (
                local_present(&flow.current.journal_version),
                local_missing(),
            ),
            (
                local_present(&flow.intent.proposed_journal_version),
                local_present(&flow.intent.proposed_journal_version),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let layout_drift_request = reconcile_request(
                &flow.lineage,
                &flow.current,
                &flow.intent,
                DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
                known.clone(),
                named,
                staged,
                &format!("commit-unknown-layout-drift-{index}"),
            );
            let layout_drift_response =
                reconcile_response(&flow.lineage, &layout_drift_request, exact_pending.clone());
            assert_eq!(
                classify_reconcile(&flow.lineage, &layout_drift_request, &layout_drift_response),
                ReconcileDisposition::Hold
            );
        }
    }

    #[test]
    fn reconcile_rejects_self_consistent_same_lineage_fork_and_later_generation() {
        let flow = flow();
        let known = DirectOperationRuntimeAuthorityPreparedKnowledgeV1::Known {
            prepared_head: flow.prepared.clone(),
        };
        let request = reconcile_request(
            &flow.lineage,
            &flow.current,
            &flow.intent,
            DirectOperationRuntimeAuthorityReconcileCauseV1::CommitResponseUnknown,
            known,
            local_present(&flow.intent.proposed_journal_version),
            local_missing(),
            "same-lineage-fork",
        );

        let mut fork = flow.commit_receipt.committed_head.clone();
        fork.journal_version = journal_version("fork-current-identity", "fork-current-bytes");
        fork.ancestry = DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
            predecessor_committed_head_sha256: flow.current.committed_head_sha256.clone(),
            prepared_head_sha256: digest("other-self-consistent-prepared"),
        };
        fork.committed_head_sha256 = fork.canonical_sha256().unwrap();
        fork.validate(&flow.lineage).unwrap();
        let fork_snapshot = snapshot(
            &flow.lineage,
            &fork,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        );
        let fork_response = reconcile_response(&flow.lineage, &request, fork_snapshot);
        assert!(fork_response.validate_for(&flow.lineage, &request).is_err());

        let mut later = fork;
        later.mutation_generation = 3;
        later.journal_version = journal_version("later-identity", "later-bytes");
        later.ancestry = DirectOperationRuntimeAuthorityHeadAncestryV1::Successor {
            predecessor_committed_head_sha256: later.committed_head_sha256.clone(),
            prepared_head_sha256: digest("later-self-consistent-prepared"),
        };
        later.committed_head_sha256 = later.canonical_sha256().unwrap();
        later.validate(&flow.lineage).unwrap();
        let later_snapshot = snapshot(
            &flow.lineage,
            &later,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Empty,
        );
        let later_response = reconcile_response(&flow.lineage, &request, later_snapshot);
        assert!(
            later_response
                .validate_for(&flow.lineage, &request)
                .is_err()
        );
    }

    #[test]
    fn observe_rejects_pending_fork_or_local_rollback() {
        let flow = flow();
        let request = observe_request(&flow.lineage, &flow.current);

        let mut pending = observe_response(&flow.lineage, &request, &flow.current);
        pending.snapshot = snapshot(
            &flow.lineage,
            &flow.current,
            DirectOperationRuntimeAuthorityPreparedSlotV1::Pending {
                prepared_head: flow.prepared.clone(),
            },
        );
        pending.response_sha256 = pending.canonical_sha256().unwrap();
        assert!(
            pending
                .validate_for(&flow.lineage, &request, &flow.current)
                .is_err()
        );

        let mut local_rollback = request.clone();
        local_rollback.observed_journal_version =
            journal_version("rolled-back-identity", "rolled-back-bytes");
        local_rollback.request_sha256 = local_rollback.canonical_sha256().unwrap();
        assert!(
            local_rollback
                .validate_for(&flow.lineage, &flow.current)
                .is_err()
        );
    }

    #[test]
    fn namespace_and_all_product_authority_flags_remain_closed() {
        assert!(SOURCE_DATA_ABI_IMPLEMENTED);
        assert!(!AUTHORITY_BACKEND_PRODUCT_AVAILABLE);
        assert!(!ADAPTER_CLIENT_PRODUCT_WIRED);
        assert!(!DAEMON_LISTENER_PRODUCT_WIRED);
        assert!(!PREPARE_PRODUCT_AVAILABLE);
        assert!(!COMMIT_PRODUCT_AVAILABLE);
        assert!(!OBSERVE_PRODUCT_AVAILABLE);
        assert!(!RECONCILE_PRODUCT_AVAILABLE);
        assert!(!MUTATION_CAS_PRODUCT_AVAILABLE);
        assert!(!CONFERS_FIRST_USE_AUTHORITY);
        assert!(!CONFERS_REPLAY_AUTHORITY);
        assert!(!CONFERS_EFFECT_AUTHORITY);
        assert_eq!(SOCKET_ADDRESS, format!("@{SOCKET_NAME}"));
        assert_ne!(
            SOCKET_NAME,
            crate::direct_operation_runtime_authority::SOCKET_NAME
        );
        assert_ne!(
            PROTOCOL,
            crate::direct_operation_runtime_authority::PROTOCOL
        );
        assert_ne!(
            SOCKET_NAME,
            crate::direct_operation_tool_call_transport::SOCKET_NAME
        );
        assert_ne!(SOCKET_NAME, "trillionnium_capability_lease_root_route");

        let source = include_str!("direct_operation_runtime_authority_mutation_cas.rs");
        let production_source = source
            .split_once("#[cfg(test)]")
            .expect("test module marker must remain present")
            .0;
        for forbidden in [
            "UnixListener",
            "UnixStream",
            "connect(",
            "bind(",
            "trillionnium_privilege_broker",
            "monotonic_authority_contract",
        ] {
            assert!(!production_source.contains(forbidden));
        }
    }
}
