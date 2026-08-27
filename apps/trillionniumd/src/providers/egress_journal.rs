//! Root-owned durable lifecycle tombstones for Android data-egress grants.
//!
//! Only bounded metadata and cryptographic digests are persisted. Raw context,
//! source identifiers, and complete user intent never enter this journal.

use std::collections::HashSet;
use std::env;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use trillionnium_os_types::agent_principal_registry;
use trillionnium_os_types::direct_operation::DirectOperationBinding;
use trillionnium_os_types::{now_unix_ms, sha256_bytes, sha256_json};
#[cfg(test)]
use trillionnium_tool_runtime::supervised_codex::{
    CODEX_CAPABILITY_AGENT_SELINUX_DOMAIN, CODEX_CAPABILITY_PROVIDER_ID,
    CODEX_DIRECT_CAPABILITY_AGENT_ID,
};
use trillionnium_tool_runtime::supervised_codex::{
    ChildContainmentProofScope, CodexRuntimeEvidence, EgressBrokerOutcome,
    EgressBrokerTerminationReason, ProviderSessionCleanupEvidence, RuntimeLifecycleBinding,
    runtime_evidence_component_sha256,
};

use crate::context_memory::EgressRecoveryBlobRef;
use crate::direct_operation_binding_inbox::{
    DurableProviderAttemptQuery, DurableProviderAttemptRecord, DurableProviderAttemptSource,
    daemon_attempt_context_sha256,
};
const JOURNAL_SCHEMA: &str = "trillionnium.android-egress-lifecycle.v7";
const LEGACY_V6_JOURNAL_SCHEMA: &str = "trillionnium.android-egress-lifecycle.v6";
const LEGACY_V5_JOURNAL_SCHEMA: &str = "trillionnium.android-egress-lifecycle.v5";
const LEGACY_V4_JOURNAL_SCHEMA: &str = "trillionnium.android-egress-lifecycle.v4";
const LEGACY_V3_JOURNAL_SCHEMA: &str = "trillionnium.android-egress-lifecycle.v3";
const LEGACY_V2_JOURNAL_SCHEMA: &str = "trillionnium.android-egress-lifecycle.v2";
const LEGACY_JOURNAL_SCHEMA: &str = "trillionnium.android-egress-lifecycle.v1";
const COMPACTION_SCHEMA: &str = "trillionnium.android-egress-lifecycle-compaction.v1";
const DEFAULT_JOURNAL_PATH: &str = "/var/lib/trillionnium/egress/android-egress-lifecycle-v1.json";
const MAX_RECORDS: usize = 32_768;
const COMPACTION_TRIGGER_RECORDS: usize = MAX_RECORDS - 4_096;
const COMPACTION_TARGET_RECORDS: usize = MAX_RECORDS / 2;
const COMPACTION_TRIGGER_BYTES: usize = MAX_JOURNAL_BYTES - (4 * 1024 * 1024);
const REPLAY_FILTER_BYTES: usize = 1024 * 1024;
const REPLAY_FILTER_HASHES: usize = 7;
const MAX_JOURNAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
const MAX_GRANT_TTL_MS: u64 = 120_000;
const MAX_EGRESS_BYTES: u64 = 4 * 1024 * 1024;
const CURRENT_EGRESS_POLICY_EPOCH: u64 = 1;
const CURRENT_PROVIDER_ABI_EPOCH: u64 = 1;
const DIRECT_PROVIDER_ATTEMPT_SCHEMA: &str = "trillionnium.android-direct-provider-attempt.v1";
const DIRECT_TERMINAL_EGRESS_PROOF_SCHEMA: &str =
    "trillionnium.direct-operation-terminal-egress-cas-proof.v1";
const DIRECT_TERMINAL_EGRESS_DIGEST_DOMAIN: &[u8] =
    b"trillionnium.direct-operation-terminal-egress-cas-snapshot.v1";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum EgressLifecycleState {
    Prepared,
    Consumed,
    RevokePending,
    Completed,
    Revoked,
    RevokedBeforeDispatch,
    Expired,
    InterruptedRestart,
    IndeterminateRestart,
    #[serde(rename = "INVALIDATED_RESTART")]
    LegacyInvalidatedRestart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum EgressRevokeUiOutcome {
    RevokedBeforeDispatch,
    RevokePending,
    Revoked,
    GrantExpired,
}

impl EgressLifecycleState {
    fn is_compactable_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Revoked
                | Self::RevokedBeforeDispatch
                | Self::Expired
                | Self::InterruptedRestart
                | Self::IndeterminateRestart
                | Self::LegacyInvalidatedRestart
        )
    }
}

impl EgressJournalRecord {
    fn is_compactable_terminal(&self) -> bool {
        if !self.state.is_compactable_terminal() {
            return false;
        }
        // A Direct lifecycle is the only durable source for the exact final
        // CAS, predecessor, runtime evidence, and teardown acknowledgement
        // required by the future daemon-owned outer receipt.  Until that
        // receipt has an independently reviewed durable handoff marker, no
        // Direct terminal may enter either normal or headroom compaction.
        // Capacity exhaustion is deliberately fail-closed.
        if self.direct_provider_attempt.is_some() {
            return false;
        }
        // Legacy records are already policy-retired tombstones; current UI
        // replay refuses their epoch before decrypting any historical result.
        if self.record_version < 3 {
            return true;
        }
        if self.prepare_ui_completion_ack_sha256.is_none()
            || self.prepare_ui_completion_proof_sha256.is_none()
        {
            return false;
        }
        // Any current-epoch record that has accepted a revoke request or
        // frozen a revoke UI outcome must retain that exact outcome until the
        // outer UI replay record durably acknowledges it.  This applies even
        // when restart reconstruction or expiry moved the lifecycle into a
        // different terminal state.
        if self.revoke_event.is_some() || self.revoke_ui_outcome.is_some() {
            return self.revoke_ui_completion_ack_sha256.is_some()
                && self.revoke_ui_completion_proof_sha256.is_some();
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressJournalMetadata {
    pub grant_id: String,
    pub provider_id: String,
    pub workflow_id_sha256: String,
    #[serde(default)]
    pub policy_epoch: u64,
    #[serde(default)]
    pub provider_abi_epoch: u64,
    #[serde(default)]
    pub prepare_request_id_sha256: String,
    #[serde(default)]
    pub prepare_request_payload_sha256: String,
    pub peer_uid: u32,
    pub peer_selinux_domain_sha256: String,
    pub subject_user_id: u32,
    #[serde(default)]
    pub boot_id_sha256: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub agent_peer_uid: u32,
    #[serde(default)]
    pub agent_peer_gid: u32,
    #[serde(default)]
    pub agent_selinux_domain_sha256: String,
    #[serde(default)]
    pub agent_executable_sha256: String,
    #[serde(default)]
    pub agent_manifest_sha256: String,
    pub context_id_sha256: String,
    pub context_kind: String,
    pub context_captured_at_ms: u64,
    pub context_expires_at_ms: u64,
    pub context_sha256: String,
    pub source_id_sha256: String,
    pub privacy_class: String,
    pub content_bytes: u64,
    pub intent_sha256: String,
    pub intent_bytes: u64,
    pub allowed_actions_sha256: String,
    pub prompt_contract: String,
    pub prompt_contract_version: u64,
    pub endpoint: String,
    pub upload_byte_limit: u64,
    pub download_byte_limit: u64,
    pub consent_challenge_sha256: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl EgressJournalMetadata {
    pub(crate) fn binding_sha256(&self) -> Result<String> {
        validate_metadata(self, now_unix_ms())?;
        Ok(sha256_json(&serde_json::to_value(self)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressJournalRecord {
    record_version: u32,
    metadata: EgressJournalMetadata,
    binding_sha256: String,
    state: EgressLifecycleState,
    #[serde(default)]
    recovery_envelope_file: String,
    #[serde(default)]
    recovery_envelope_sha256: String,
    #[serde(default)]
    teardown_nonce_sha256: Option<String>,
    #[serde(default)]
    revoke_event: Option<EgressRevokeEvent>,
    #[serde(default)]
    revoke_ui_outcome: Option<EgressRevokeUiOutcome>,
    #[serde(default)]
    completion_ack_sha256: Option<String>,
    #[serde(default)]
    runtime_evidence_sha256: Option<String>,
    #[serde(default)]
    runtime_evidence: Option<CodexRuntimeEvidence>,
    #[serde(default)]
    predispatch_binding: Option<RuntimeLifecycleBinding>,
    #[serde(default)]
    predispatch_binding_sha256: Option<String>,
    #[serde(default)]
    predispatch_task_id_sha256: Option<String>,
    #[serde(default)]
    direct_provider_attempt: Option<DurableDirectProviderAttempt>,
    #[serde(default)]
    prepare_ui_completion_ack_sha256: Option<String>,
    #[serde(default)]
    prepare_ui_completion_proof_sha256: Option<String>,
    #[serde(default)]
    revoke_ui_completion_ack_sha256: Option<String>,
    #[serde(default)]
    revoke_ui_completion_proof_sha256: Option<String>,
    #[serde(default)]
    last_transition_from_sha256: Option<String>,
    prepared_at_ms: u64,
    consumed_at_ms: Option<u64>,
    #[serde(default)]
    completed_at_ms: Option<u64>,
    revoked_at_ms: Option<u64>,
    expired_at_ms: Option<u64>,
    invalidated_restart_at_ms: Option<u64>,
    #[serde(default)]
    interrupted_restart_at_ms: Option<u64>,
    #[serde(default)]
    indeterminate_restart_at_ms: Option<u64>,
    consent_receipt_id: Option<String>,
    updated_at_ms: u64,
}

/// Root-authored attempt allocation bound to one already-frozen provider
/// lifecycle.  This is deliberately not a retry log: a lifecycle record may
/// acquire this subrecord at most once, and no caller can replace it with a
/// later generation.  The enclosing canonical journal-record digest is the
/// durable record commitment consumed by the binding inbox publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableDirectProviderAttempt {
    schema: String,
    provider_id: String,
    agent_id: String,
    task_id_sha256: String,
    runtime_lifecycle_binding_sha256: String,
    attempt_generation: u64,
    allocation_predecessor_record_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressRevokeEvent {
    schema: String,
    request_id: String,
    request_payload_sha256: String,
    requested_at_ms: u64,
    teardown_ack_sha256: Option<String>,
    teardown_ack_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct EgressUiCompletionAck<'a> {
    schema: &'a str,
    method: &'a str,
    request_id: &'a str,
    request_payload_sha256: &'a str,
    completion_proof_sha256: &'a str,
    peer_uid: u32,
    peer_selinux_domain_sha256: String,
    completed_at_ms: u64,
}

pub(crate) struct EgressExpiredRevokeRequest<'a> {
    pub workflow_id: &'a str,
    pub peer_uid: u32,
    pub peer_selinux_domain: &'a str,
    pub request_id: &'a str,
    pub request_payload_sha256: &'a str,
    pub now: u64,
}

pub(crate) struct EgressUiCompletionBinding<'a> {
    pub method: &'a str,
    pub request_id: &'a str,
    pub request_payload_sha256: &'a str,
    pub completion_proof_sha256: &'a str,
    pub peer_uid: u32,
    pub peer_selinux_domain: &'a str,
    pub completed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgressJournalCas {
    pub binding_sha256: String,
    pub state: EgressLifecycleState,
    pub record_sha256: String,
    /// The rename that published this exact record completed, but the parent
    /// directory fsync did not.  The namespace and a same-process reopen see
    /// these bytes, so callers must continue from this CAS rather than roll
    /// back to the pre-transition state.  They must still report an explicit
    /// commit-unknown outcome and keep the journal fail-stopped until reopen.
    pub publication_durability_uncertain: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct EgressTeardownAck {
    pub proof_schema: String,
    pub grant_id: String,
    pub journal_binding_sha256: String,
    pub provider_id: String,
    pub teardown_nonce: String,
    pub child_cleanup_sha256: String,
    pub provider_session_cleanup_sha256: String,
    pub broker_outcome_sha256: String,
    pub runtime_evidence_sha256: String,
    pub termination_reason: String,
    pub acknowledged_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressCompactionCheckpoint {
    schema: String,
    epoch: u64,
    compacted_terminal_records: u64,
    through_issued_at_ms: u64,
    through_updated_at_ms: u64,
    terminal_commitment_sha256: String,
    replay_filter_sha256: String,
    replay_filter_b64: String,
}

impl Default for EgressCompactionCheckpoint {
    fn default() -> Self {
        Self {
            schema: COMPACTION_SCHEMA.to_string(),
            epoch: 0,
            compacted_terminal_records: 0,
            through_issued_at_ms: 0,
            through_updated_at_ms: 0,
            terminal_commitment_sha256: sha256_bytes(&[]),
            replay_filter_sha256: sha256_bytes(&[]),
            replay_filter_b64: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressJournalFile {
    schema: String,
    #[serde(default)]
    compaction: EgressCompactionCheckpoint,
    records: Vec<EgressJournalRecord>,
}

/// Immutable, journal-derived source handed to the inbox publisher after the
/// journal lock is released.  It contains no environment/model material and
/// answers only the exact query frozen during the durable allocation.
#[derive(Debug, Clone)]
pub(crate) struct EgressDurableProviderAttemptSource {
    query: DurableProviderAttemptQuery,
    record: DurableProviderAttemptRecord,
}

/// Sealed, read-only projection of one exact Direct terminal egress record.
///
/// Fields stay private and this type is intentionally not `Deserialize`: only
/// `EgressLifecycleJournal::verified_direct_terminal_snapshot` can mint it
/// from the already validated root-owned journal.  It contains identity and
/// digests only; no runtime evidence, provider output, request, URI, or user
/// text crosses this boundary.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedDirectTerminalEgressSnapshot {
    binding_sha256: String,
    invocation_id: String,
    delivery_provider_attempt_id: String,
    egress_grant_id_sha256: String,
    egress_journal_binding_sha256: String,
    final_record_sha256: String,
    predecessor_record_sha256: String,
    runtime_evidence_sha256: String,
    provider_teardown_completion_ack_sha256: String,
    terminal_egress_cas_sha256: String,
}

#[allow(dead_code)]
impl VerifiedDirectTerminalEgressSnapshot {
    pub(crate) fn validate_for_binding(&self, binding: &DirectOperationBinding) -> Result<()> {
        binding
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        if self.binding_sha256 != binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.attempt.delivery_provider_attempt_id
            || direct_terminal_egress_digest(
                &self.binding_sha256,
                &self.invocation_id,
                &self.delivery_provider_attempt_id,
                &self.egress_grant_id_sha256,
                &self.egress_journal_binding_sha256,
                &self.final_record_sha256,
                &self.predecessor_record_sha256,
                &self.runtime_evidence_sha256,
                &self.provider_teardown_completion_ack_sha256,
            )? != self.terminal_egress_cas_sha256
        {
            bail!("android_egress_journal_direct_terminal_snapshot_binding_denied");
        }
        Ok(())
    }

    pub(crate) fn validate_custody_identity(
        &self,
        binding: &DirectOperationBinding,
        egress_grant_id_sha256: &str,
        egress_journal_binding_sha256: &str,
    ) -> Result<()> {
        self.validate_for_binding(binding)?;
        if self.egress_grant_id_sha256 != egress_grant_id_sha256
            || self.egress_journal_binding_sha256 != egress_journal_binding_sha256
        {
            bail!("android_egress_journal_direct_terminal_snapshot_custody_identity_denied");
        }
        Ok(())
    }

    pub(crate) fn final_record_sha256(&self) -> &str {
        &self.final_record_sha256
    }

    pub(crate) fn predecessor_record_sha256(&self) -> &str {
        &self.predecessor_record_sha256
    }

    pub(crate) fn runtime_evidence_sha256(&self) -> &str {
        &self.runtime_evidence_sha256
    }

    pub(crate) fn provider_teardown_completion_ack_sha256(&self) -> &str {
        &self.provider_teardown_completion_ack_sha256
    }

    pub(crate) fn terminal_egress_cas_sha256(&self) -> &str {
        &self.terminal_egress_cas_sha256
    }
}

impl DurableProviderAttemptSource for EgressDurableProviderAttemptSource {
    fn load_durable_attempt(
        &self,
        query: &DurableProviderAttemptQuery,
    ) -> Result<DurableProviderAttemptRecord> {
        if query != &self.query {
            bail!("android_egress_journal_direct_attempt_query_mismatch");
        }
        Ok(self.record.clone())
    }
}

/// Exact child-evidence contract serialized by journal v4. It is accepted only
/// long enough to validate the closed legacy shape and its frozen commitment;
/// no field is promoted into v5 proof.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyV4ChildContainmentEvidence {
    lifecycle_binding_sha256: String,
    provider_invocation_id_sha256: String,
    provider_session_id_sha256: String,
    child_pid: u32,
    session_id: i32,
    proof_scope: ChildContainmentProofScope,
    observed_process_count: usize,
    process_group_empty: bool,
    observed_tree_empty: bool,
    dedicated_uid: Option<u32>,
    dedicated_uid_preflight_empty: Option<bool>,
    dedicated_uid_empty: Option<bool>,
    pdeathsig_pre_exec_verified: bool,
    no_new_privs_pre_exec_verified: bool,
    independent_session_pre_exec_verified: bool,
    rlimit_core_zero_pre_exec_verified: bool,
    dumpable_zero_pre_exec_verified: bool,
    post_exec_dumpable_verified: bool,
    cleanup_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyV4RuntimeEvidence {
    child_started: bool,
    broker_started: bool,
    provider_session_started: bool,
    child: Option<LegacyV4ChildContainmentEvidence>,
    child_cleanup_sha256: Option<String>,
    egress: Option<EgressBrokerOutcome>,
    broker_outcome_sha256: Option<String>,
    provider_session_cleanup: Option<ProviderSessionCleanupEvidence>,
    provider_session_cleanup_sha256: Option<String>,
    lifecycle_binding: Option<LegacyV6RuntimeLifecycleBinding>,
    lifecycle_binding_sha256: Option<String>,
}

impl LegacyV4RuntimeEvidence {
    fn closed_presence_shape_proven(&self) -> bool {
        self.child_started == self.child.is_some()
            && self.child.is_some() == self.child_cleanup_sha256.is_some()
            && self.broker_started == self.egress.is_some()
            && self.egress.is_some() == self.broker_outcome_sha256.is_some()
            && self.provider_session_started == self.provider_session_cleanup.is_some()
            && self.provider_session_cleanup.is_some()
                == self.provider_session_cleanup_sha256.is_some()
            && self.lifecycle_binding.is_some() == self.lifecycle_binding_sha256.is_some()
    }
}

/// Exact lifecycle/child shape serialized by journal v6 before the final
/// runtime digest became part of the durable lifecycle binding.  These types
/// exist only to authenticate old canonical commitments before retiring them;
/// conversion into current evidence is intentionally impossible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyV6RuntimeLifecycleBinding {
    provider_id: String,
    agent_id: String,
    agent_peer_uid: u32,
    agent_peer_gid: u32,
    agent_selinux_domain_sha256: String,
    agent_executable_sha256: String,
    agent_manifest_sha256: String,
    provider_invocation_id_sha256: String,
    provider_session_id_sha256: String,
    egress_grant_id: String,
    journal_binding_sha256: String,
    capability_token_sha256: String,
    teardown_nonce_sha256: String,
    proxy_instance_credential_sha256: String,
    approved_endpoint: String,
    upload_byte_limit: u64,
    download_byte_limit: u64,
    grant_issued_at_unix_ms: u64,
    grant_expires_at_unix_ms: u64,
}

impl LegacyV6RuntimeLifecycleBinding {
    fn shape_proven(&self) -> bool {
        !self.provider_id.is_empty()
            && !self.agent_id.is_empty()
            && self.agent_peer_uid > 0
            && self.agent_peer_gid > 0
            && !self.egress_grant_id.is_empty()
            && [
                self.agent_selinux_domain_sha256.as_str(),
                self.agent_executable_sha256.as_str(),
                self.agent_manifest_sha256.as_str(),
                self.provider_invocation_id_sha256.as_str(),
                self.provider_session_id_sha256.as_str(),
                self.journal_binding_sha256.as_str(),
                self.capability_token_sha256.as_str(),
                self.teardown_nonce_sha256.as_str(),
                self.proxy_instance_credential_sha256.as_str(),
            ]
            .iter()
            .all(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            && self.approved_endpoint == "chatgpt.com:443"
            && self.upload_byte_limit > 0
            && self.download_byte_limit > 0
            && self.grant_expires_at_unix_ms > self.grant_issued_at_unix_ms
    }

    fn digest_sha256(&self) -> Result<String> {
        if !self.shape_proven() {
            bail!("android_egress_journal_legacy_v6_lifecycle_shape_denied");
        }
        // RuntimeLifecycleBinding::digest_sha256 in journal v6 hashed the
        // typed struct serialization, whose declaration order is part of the
        // commitment. A Value round-trip sorts map keys and is not the old
        // byte contract.
        Ok(sha256_bytes(&serde_json::to_vec(self)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyV6ChildContainmentEvidence {
    lifecycle_binding_sha256: String,
    provider_invocation_id_sha256: String,
    provider_session_id_sha256: String,
    child_pid: u32,
    session_id: i32,
    proof_scope: ChildContainmentProofScope,
    observed_process_count: usize,
    process_group_empty: bool,
    observed_tree_empty: bool,
    dedicated_uid: Option<u32>,
    dedicated_uid_preflight_empty: Option<bool>,
    dedicated_uid_empty: Option<bool>,
    executable_sha256: String,
    executable_device: u64,
    executable_inode: u64,
    exact_executable_fd_verified: bool,
    executable_source_read_only_mount_verified: bool,
    executable_elf_image_verified: bool,
    root_pidfd_custody_verified: bool,
    pidfd_signalling_verified: bool,
    pdeathsig_pre_exec_verified: bool,
    no_new_privs_pre_exec_verified: bool,
    independent_session_pre_exec_verified: bool,
    rlimit_core_zero_pre_exec_verified: bool,
    dumpable_zero_pre_exec_verified: bool,
    inherited_fd_cloexec_pre_exec_verified: bool,
    post_exec_dumpable_verified: bool,
    cleanup_errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyV6RuntimeEvidence {
    child_started: bool,
    broker_started: bool,
    provider_session_started: bool,
    child: Option<LegacyV6ChildContainmentEvidence>,
    child_cleanup_sha256: Option<String>,
    egress: Option<EgressBrokerOutcome>,
    broker_outcome_sha256: Option<String>,
    provider_session_cleanup: Option<ProviderSessionCleanupEvidence>,
    provider_session_cleanup_sha256: Option<String>,
    lifecycle_binding: Option<LegacyV6RuntimeLifecycleBinding>,
    lifecycle_binding_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyV6DirectProviderAttempt {
    schema: String,
    provider_id: String,
    agent_id: String,
    task_id_sha256: String,
    runtime_lifecycle_binding_sha256: String,
    attempt_generation: u64,
    allocation_predecessor_record_sha256: String,
}

impl LegacyV6RuntimeEvidence {
    fn closed_presence_shape_proven(&self) -> bool {
        self.child_started == self.child.is_some()
            && self.child.is_some() == self.child_cleanup_sha256.is_some()
            && self.broker_started == self.egress.is_some()
            && self.egress.is_some() == self.broker_outcome_sha256.is_some()
            && self.provider_session_started == self.provider_session_cleanup.is_some()
            && self.provider_session_cleanup.is_some()
                == self.provider_session_cleanup_sha256.is_some()
            && self.lifecycle_binding.is_some() == self.lifecycle_binding_sha256.is_some()
    }
}

/// Recursive JSON decoder used before schema dispatch. Parsing a legacy file
/// through ordinary `Value` would collapse duplicate members before the v4
/// terminalization code could see them.
struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        UniqueJsonValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            output.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(output)))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if output.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key {key}")));
            }
            let value = map.next_value::<UniqueJsonValue>()?;
            output.insert(key, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(output)))
    }
}

pub(crate) struct EgressLifecycleJournal {
    path: PathBuf,
    owner_uid: u32,
    file: EgressJournalFile,
    persisted_sha256: Option<String>,
    publication_durability_uncertain: bool,
    #[cfg(test)]
    fail_parent_fsync_after_rename_once: bool,
}

fn parse_journal_file(bytes: &[u8], migration_now: u64) -> Result<EgressJournalFile> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let UniqueJsonValue(mut value) = UniqueJsonValue::deserialize(&mut deserializer)
        .context("invalid_android_egress_journal_json")?;
    deserializer
        .end()
        .context("invalid_android_egress_journal_trailing_json")?;
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .context("android_egress_journal_schema_missing")?;
    if schema == LEGACY_V4_JOURNAL_SCHEMA {
        terminalize_legacy_v4_value(&mut value, migration_now)?;
    } else if schema == LEGACY_V6_JOURNAL_SCHEMA {
        terminalize_legacy_v6_value(&mut value, migration_now)?;
    }
    serde_json::from_value(value).context("invalid_android_egress_journal_closed_world_shape")
}

fn legacy_typed_component_commitment_matches<T: Serialize>(
    component: Option<&T>,
    digest: Option<&String>,
    digest_field: &str,
) -> Result<bool> {
    match (component, digest) {
        (None, None) => Ok(true),
        (Some(component), Some(digest)) => {
            validate_digest(digest, digest_field)?;
            Ok(runtime_evidence_component_sha256(component)
                .map_err(|_| anyhow::anyhow!("legacy_v4_component_serialization_failed"))?
                == *digest)
        }
        _ => Ok(false),
    }
}

fn validate_legacy_v4_runtime_value(
    value: &Value,
    expected_digest: &str,
) -> Result<Option<(LegacyV6RuntimeLifecycleBinding, String)>> {
    validate_digest(expected_digest, "legacy_v4_runtime_evidence_sha256")?;
    if sha256_json(value) != expected_digest {
        bail!("android_egress_journal_legacy_v4_runtime_commitment_mismatch");
    }
    let legacy: LegacyV4RuntimeEvidence = serde_json::from_value(value.clone())
        .context("android_egress_journal_legacy_v4_runtime_shape_denied")?;
    if !legacy.closed_presence_shape_proven() {
        bail!("android_egress_journal_legacy_v4_runtime_presence_mismatch");
    }
    for (component, matches) in [
        (
            "child",
            legacy_typed_component_commitment_matches(
                legacy.child.as_ref(),
                legacy.child_cleanup_sha256.as_ref(),
                "legacy_v4_child_cleanup_sha256",
            )?,
        ),
        (
            "egress",
            legacy_typed_component_commitment_matches(
                legacy.egress.as_ref(),
                legacy.broker_outcome_sha256.as_ref(),
                "legacy_v4_broker_outcome_sha256",
            )?,
        ),
        (
            "provider_session_cleanup",
            legacy_typed_component_commitment_matches(
                legacy.provider_session_cleanup.as_ref(),
                legacy.provider_session_cleanup_sha256.as_ref(),
                "legacy_v4_provider_session_cleanup_sha256",
            )?,
        ),
    ] {
        if !matches {
            bail!("android_egress_journal_legacy_v4_component_commitment_mismatch:{component}");
        }
    }
    let lifecycle = if let Some(binding) = &legacy.lifecycle_binding {
        let digest = legacy
            .lifecycle_binding_sha256
            .as_deref()
            .context("android_egress_journal_legacy_v4_lifecycle_digest_missing")?;
        validate_digest(digest, "legacy_v4_lifecycle_binding_sha256")?;
        if binding.digest_sha256()? != digest {
            bail!("android_egress_journal_legacy_v4_lifecycle_commitment_mismatch");
        }
        if let Some(child) = &legacy.child
            && (child.lifecycle_binding_sha256 != digest
                || child.provider_invocation_id_sha256 != binding.provider_invocation_id_sha256
                || child.provider_session_id_sha256 != binding.provider_session_id_sha256)
        {
            bail!("android_egress_journal_legacy_v4_child_lifecycle_mismatch");
        }
        Some((binding.clone(), digest.to_string()))
    } else {
        None
    };
    Ok(lifecycle)
}

fn terminalize_legacy_v4_value(file: &mut Value, migration_now: u64) -> Result<()> {
    let records = file
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .context("android_egress_journal_legacy_v4_records_missing")?;
    for record in records {
        let old_record_sha256 = sha256_json(record);
        let object = record
            .as_object_mut()
            .context("android_egress_journal_legacy_v4_record_not_object")?;
        let runtime = object
            .get("runtime_evidence")
            .context("android_egress_journal_legacy_v4_runtime_field_missing")?;
        let runtime_digest = object
            .get("runtime_evidence_sha256")
            .context("android_egress_journal_legacy_v4_runtime_digest_field_missing")?;
        let legacy_runtime_binding = match (runtime, runtime_digest) {
            (Value::Null, Value::Null) => None,
            (runtime, Value::String(digest)) => {
                Some(validate_legacy_v4_runtime_value(runtime, digest)?)
            }
            _ => bail!("android_egress_journal_legacy_v4_runtime_pair_mismatch"),
        };
        let has_runtime = legacy_runtime_binding.is_some();
        let legacy_binding = match (
            object.get("predispatch_binding"),
            object.get("predispatch_binding_sha256"),
            object.get("predispatch_task_id_sha256"),
        ) {
            (Some(Value::Null), Some(Value::Null), Some(Value::Null)) => None,
            (
                Some(binding),
                Some(Value::String(binding_digest)),
                Some(Value::String(task_digest)),
            ) => {
                validate_digest(task_digest, "legacy_v4_predispatch_task_id_sha256")?;
                Some((
                    validate_legacy_v6_binding_value(binding, binding_digest)?,
                    binding_digest.clone(),
                    task_digest.clone(),
                ))
            }
            _ => bail!("android_egress_journal_legacy_v4_predispatch_pair_mismatch"),
        };
        let direct_attempt = match object.get("direct_provider_attempt") {
            Some(Value::Null) => None,
            Some(value) => Some(value),
            None => None,
        };
        if let Some(runtime_binding) = legacy_runtime_binding.as_ref() {
            let Some((predispatch_binding, predispatch_digest, _)) = legacy_binding.as_ref() else {
                bail!("android_egress_journal_legacy_v4_runtime_without_binding");
            };
            let Some((runtime_binding, runtime_digest)) = runtime_binding.as_ref() else {
                bail!("android_egress_journal_legacy_v4_runtime_lifecycle_missing");
            };
            if runtime_binding != predispatch_binding || runtime_digest != predispatch_digest {
                bail!("android_egress_journal_legacy_v4_runtime_predispatch_mismatch");
            }
        }
        if let Some(attempt) = direct_attempt {
            let Some((binding, binding_digest, task_digest)) = legacy_binding.as_ref() else {
                bail!("android_egress_journal_legacy_v4_attempt_without_binding");
            };
            validate_legacy_v6_direct_attempt_value(attempt, binding, binding_digest, task_digest)?;
        }
        let in_flight = object
            .get("state")
            .and_then(Value::as_str)
            .is_some_and(|state| matches!(state, "PREPARED" | "CONSUMED" | "REVOKE_PENDING"));
        if !in_flight && !has_runtime && legacy_binding.is_none() && direct_attempt.is_none() {
            continue;
        }
        let prepared_at = object
            .get("prepared_at_ms")
            .and_then(Value::as_u64)
            .context("android_egress_journal_legacy_v4_prepared_time_missing")?;
        let updated_at = object
            .get("updated_at_ms")
            .and_then(Value::as_u64)
            .context("android_egress_journal_legacy_v4_updated_time_missing")?;
        let transitioned_at = migration_now.max(prepared_at).max(updated_at);
        object.insert(
            "state".to_string(),
            Value::String("INDETERMINATE_RESTART".to_string()),
        );
        object.insert("runtime_evidence".to_string(), Value::Null);
        object.insert("runtime_evidence_sha256".to_string(), Value::Null);
        object.insert("predispatch_binding".to_string(), Value::Null);
        object.insert("predispatch_binding_sha256".to_string(), Value::Null);
        object.insert("predispatch_task_id_sha256".to_string(), Value::Null);
        object.insert("direct_provider_attempt".to_string(), Value::Null);
        object.insert("completion_ack_sha256".to_string(), Value::Null);
        object.insert("completed_at_ms".to_string(), Value::Null);
        object.insert("revoked_at_ms".to_string(), Value::Null);
        object.insert("expired_at_ms".to_string(), Value::Null);
        object.insert("invalidated_restart_at_ms".to_string(), Value::Null);
        object.insert("interrupted_restart_at_ms".to_string(), Value::Null);
        object.insert(
            "indeterminate_restart_at_ms".to_string(),
            Value::Number(transitioned_at.into()),
        );
        object.insert(
            "last_transition_from_sha256".to_string(),
            Value::String(old_record_sha256),
        );
        object.insert(
            "updated_at_ms".to_string(),
            Value::Number(transitioned_at.into()),
        );
        // A legacy terminal/revoke outcome cannot be replayed as a current
        // proof after its runtime evidence is retired. Keep the request event
        // itself, but remove the UI outcome/ack rather than inventing one.
        object.insert("revoke_ui_outcome".to_string(), Value::Null);
        object.insert("revoke_ui_completion_ack_sha256".to_string(), Value::Null);
        object.insert("revoke_ui_completion_proof_sha256".to_string(), Value::Null);
    }
    Ok(())
}

fn validate_legacy_v6_binding_value(
    value: &Value,
    expected_digest: &str,
) -> Result<LegacyV6RuntimeLifecycleBinding> {
    validate_digest(expected_digest, "legacy_v6_lifecycle_binding_sha256")?;
    let binding: LegacyV6RuntimeLifecycleBinding = serde_json::from_value(value.clone())
        .context("android_egress_journal_legacy_v6_lifecycle_shape_denied")?;
    if serde_json::to_value(&binding)? != *value || binding.digest_sha256()? != expected_digest {
        bail!("android_egress_journal_legacy_v6_lifecycle_commitment_mismatch");
    }
    Ok(binding)
}

fn validate_legacy_v6_runtime_value(
    value: &Value,
    expected_digest: &str,
) -> Result<Option<(LegacyV6RuntimeLifecycleBinding, String)>> {
    validate_digest(expected_digest, "legacy_v6_runtime_evidence_sha256")?;
    if sha256_json(value) != expected_digest {
        bail!("android_egress_journal_legacy_v6_runtime_commitment_mismatch");
    }
    let legacy: LegacyV6RuntimeEvidence = serde_json::from_value(value.clone())
        .context("android_egress_journal_legacy_v6_runtime_shape_denied")?;
    if !legacy.closed_presence_shape_proven() {
        bail!("android_egress_journal_legacy_v6_runtime_presence_mismatch");
    }
    for (component, matches) in [
        (
            "child",
            legacy_typed_component_commitment_matches(
                legacy.child.as_ref(),
                legacy.child_cleanup_sha256.as_ref(),
                "legacy_v6_child_cleanup_sha256",
            )?,
        ),
        (
            "egress",
            legacy_typed_component_commitment_matches(
                legacy.egress.as_ref(),
                legacy.broker_outcome_sha256.as_ref(),
                "legacy_v6_broker_outcome_sha256",
            )?,
        ),
        (
            "provider_session_cleanup",
            legacy_typed_component_commitment_matches(
                legacy.provider_session_cleanup.as_ref(),
                legacy.provider_session_cleanup_sha256.as_ref(),
                "legacy_v6_provider_session_cleanup_sha256",
            )?,
        ),
    ] {
        if !matches {
            bail!("android_egress_journal_legacy_v6_component_commitment_mismatch:{component}");
        }
    }
    let lifecycle = if let Some(binding) = &legacy.lifecycle_binding {
        let digest = legacy
            .lifecycle_binding_sha256
            .as_deref()
            .context("android_egress_journal_legacy_v6_lifecycle_digest_missing")?;
        if binding.digest_sha256()? != digest {
            bail!("android_egress_journal_legacy_v6_lifecycle_commitment_mismatch");
        }
        if let Some(child) = &legacy.child
            && (child.lifecycle_binding_sha256 != digest
                || child.provider_invocation_id_sha256 != binding.provider_invocation_id_sha256
                || child.provider_session_id_sha256 != binding.provider_session_id_sha256)
        {
            bail!("android_egress_journal_legacy_v6_child_lifecycle_mismatch");
        }
        Some((binding.clone(), digest.to_string()))
    } else {
        None
    };
    Ok(lifecycle)
}

fn validate_legacy_v6_direct_attempt_value(
    value: &Value,
    binding: &LegacyV6RuntimeLifecycleBinding,
    binding_digest: &str,
    task_digest: &str,
) -> Result<()> {
    let attempt: LegacyV6DirectProviderAttempt = serde_json::from_value(value.clone())
        .context("android_egress_journal_legacy_v6_direct_attempt_shape_denied")?;
    validate_digest(
        &attempt.task_id_sha256,
        "legacy_v6_direct_attempt_task_id_sha256",
    )?;
    validate_digest(
        &attempt.runtime_lifecycle_binding_sha256,
        "legacy_v6_direct_attempt_lifecycle_binding_sha256",
    )?;
    validate_digest(
        &attempt.allocation_predecessor_record_sha256,
        "legacy_v6_direct_attempt_predecessor_sha256",
    )?;
    if serde_json::to_value(&attempt)? != *value
        || attempt.schema != DIRECT_PROVIDER_ATTEMPT_SCHEMA
        || attempt.provider_id != binding.provider_id
        || attempt.agent_id != binding.agent_id
        || attempt.task_id_sha256 != task_digest
        || attempt.runtime_lifecycle_binding_sha256 != binding_digest
        || attempt.attempt_generation != 1
    {
        bail!("android_egress_journal_legacy_v6_direct_attempt_binding_denied");
    }
    Ok(())
}

fn terminalize_legacy_v6_value(file: &mut Value, migration_now: u64) -> Result<()> {
    let records = file
        .get_mut("records")
        .and_then(Value::as_array_mut)
        .context("android_egress_journal_legacy_v6_records_missing")?;
    for record in records {
        let old_record_sha256 = sha256_json(record);
        let object = record
            .as_object_mut()
            .context("android_egress_journal_legacy_v6_record_not_object")?;
        let record_version = object
            .get("record_version")
            .and_then(Value::as_u64)
            .context("android_egress_journal_legacy_v6_record_version_missing")?;
        if record_version < 3 {
            continue;
        }

        let legacy_binding = match (
            object.get("predispatch_binding"),
            object.get("predispatch_binding_sha256"),
            object.get("predispatch_task_id_sha256"),
        ) {
            (Some(Value::Null), Some(Value::Null), Some(Value::Null)) => None,
            (
                Some(binding),
                Some(Value::String(binding_digest)),
                Some(Value::String(task_digest)),
            ) => {
                validate_digest(task_digest, "legacy_v6_predispatch_task_id_sha256")?;
                Some((
                    validate_legacy_v6_binding_value(binding, binding_digest)?,
                    binding_digest.clone(),
                    task_digest.clone(),
                ))
            }
            _ => bail!("android_egress_journal_legacy_v6_predispatch_pair_mismatch"),
        };
        let legacy_runtime_binding = match (
            object.get("runtime_evidence"),
            object.get("runtime_evidence_sha256"),
        ) {
            (Some(Value::Null), Some(Value::Null)) => None,
            (Some(runtime), Some(Value::String(digest))) => {
                Some(validate_legacy_v6_runtime_value(runtime, digest)?)
            }
            _ => bail!("android_egress_journal_legacy_v6_runtime_pair_mismatch"),
        };
        let has_runtime = legacy_runtime_binding.is_some();
        let direct_attempt = match object.get("direct_provider_attempt") {
            Some(Value::Null) => None,
            Some(value) => Some(value),
            None => bail!("android_egress_journal_legacy_v6_direct_attempt_field_missing"),
        };
        if has_runtime && legacy_binding.is_none() {
            bail!("android_egress_journal_legacy_v6_runtime_without_binding");
        }
        if !has_runtime && legacy_binding.is_none() && direct_attempt.is_none() {
            continue;
        }
        if direct_attempt.is_some() && legacy_binding.is_none() {
            bail!("android_egress_journal_legacy_v6_attempt_without_binding");
        }
        if let Some(runtime_binding) = legacy_runtime_binding.as_ref() {
            let Some((predispatch_binding, predispatch_digest, _)) = legacy_binding.as_ref() else {
                bail!("android_egress_journal_legacy_v6_runtime_without_binding");
            };
            let Some((runtime_binding, runtime_digest)) = runtime_binding.as_ref() else {
                bail!("android_egress_journal_legacy_v6_runtime_lifecycle_missing");
            };
            if runtime_binding != predispatch_binding || runtime_digest != predispatch_digest {
                bail!("android_egress_journal_legacy_v6_runtime_predispatch_mismatch");
            }
        }
        if let (Some(attempt), Some((binding, binding_digest, task_digest))) =
            (direct_attempt, legacy_binding.as_ref())
        {
            validate_legacy_v6_direct_attempt_value(attempt, binding, binding_digest, task_digest)?;
        }

        let prepared_at = object
            .get("prepared_at_ms")
            .and_then(Value::as_u64)
            .context("android_egress_journal_legacy_v6_prepared_time_missing")?;
        let updated_at = object
            .get("updated_at_ms")
            .and_then(Value::as_u64)
            .context("android_egress_journal_legacy_v6_updated_time_missing")?;
        let transitioned_at = migration_now.max(prepared_at).max(updated_at);
        object.insert(
            "state".to_string(),
            Value::String("INDETERMINATE_RESTART".to_string()),
        );
        for field in [
            "runtime_evidence",
            "runtime_evidence_sha256",
            "predispatch_binding",
            "predispatch_binding_sha256",
            "predispatch_task_id_sha256",
            "direct_provider_attempt",
            "completion_ack_sha256",
            "completed_at_ms",
            "revoked_at_ms",
            "expired_at_ms",
            "invalidated_restart_at_ms",
            "interrupted_restart_at_ms",
            "revoke_ui_outcome",
            "revoke_ui_completion_ack_sha256",
            "revoke_ui_completion_proof_sha256",
        ] {
            object.insert(field.to_string(), Value::Null);
        }
        object.insert(
            "indeterminate_restart_at_ms".to_string(),
            Value::Number(transitioned_at.into()),
        );
        object.insert(
            "last_transition_from_sha256".to_string(),
            Value::String(old_record_sha256),
        );
        object.insert(
            "updated_at_ms".to_string(),
            Value::Number(transitioned_at.into()),
        );
    }
    Ok(())
}

impl EgressLifecycleJournal {
    pub(crate) fn open_from_env() -> Result<Self> {
        let owner_uid = unsafe { libc::geteuid() };
        if owner_uid != 0 {
            bail!("android_egress_journal_requires_root");
        }
        let path = env::var_os("TRILLIONNIUM_ANDROID_EGRESS_JOURNAL_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_JOURNAL_PATH));
        Self::open(&path, owner_uid)
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(path: &Path) -> Result<Self> {
        Self::open(path, unsafe { libc::geteuid() })
    }

    fn open(path: &Path, owner_uid: u32) -> Result<Self> {
        if !path.is_absolute() {
            bail!("android_egress_journal_path_not_absolute");
        }
        let parent = path
            .parent()
            .context("android_egress_journal_parent_missing")?;
        ensure_private_parent(parent, owner_uid)?;
        cleanup_owned_journal_temps(parent, owner_uid)?;
        // A predecessor may have published the visible generation and then
        // lost the parent-directory fsync result.  Re-durabilize the current
        // namespace before accepting any visible generation as recoverable.
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("android_egress_journal_parent_redurabilization_failed")?;
        let now = now_unix_ms();
        let (mut file, persisted_sha256) = match read_owner_controlled(path, owner_uid)? {
            Some(bytes) => {
                let file = parse_journal_file(&bytes, now)?;
                if file.schema == JOURNAL_SCHEMA {
                    let mut canonical = serde_json::to_vec_pretty(&file)?;
                    canonical.push(b'\n');
                    if canonical != bytes {
                        bail!("android_egress_journal_not_canonical_closed_world_json");
                    }
                }
                (file, Some(sha256_bytes(&bytes)))
            }
            None => (
                EgressJournalFile {
                    schema: JOURNAL_SCHEMA.to_string(),
                    compaction: EgressCompactionCheckpoint::default(),
                    records: Vec::new(),
                },
                None,
            ),
        };
        let migrated = matches!(
            file.schema.as_str(),
            LEGACY_JOURNAL_SCHEMA
                | LEGACY_V2_JOURNAL_SCHEMA
                | LEGACY_V3_JOURNAL_SCHEMA
                | LEGACY_V4_JOURNAL_SCHEMA
                | LEGACY_V5_JOURNAL_SCHEMA
                | LEGACY_V6_JOURNAL_SCHEMA
        );
        if migrated {
            if file.schema == LEGACY_JOURNAL_SCHEMA {
                file.compaction = EgressCompactionCheckpoint::default();
            }
            file.schema = JOURNAL_SCHEMA.to_string();
        }
        let mut reconstructed = false;
        for record in &mut file.records {
            if migrated && record.record_version < 3 {
                // Legacy records are permanently non-resumable. Rebind the
                // now-closed metadata shape before terminalizing so future
                // v4 reads have one canonical representation.
                record.binding_sha256 = sha256_json(&serde_json::to_value(&record.metadata)?);
            }
            let transitioned_at = now.max(record.prepared_at_ms);
            let previous_sha256 = record_sha256(record)?;
            let target = if migrated && record.record_version < 3 {
                matches!(
                    record.state,
                    EgressLifecycleState::Prepared
                        | EgressLifecycleState::Consumed
                        | EgressLifecycleState::RevokePending
                        | EgressLifecycleState::LegacyInvalidatedRestart
                )
                .then_some(EgressLifecycleState::IndeterminateRestart)
            } else {
                match record.state {
                    EgressLifecycleState::Consumed => {
                        Some(EgressLifecycleState::InterruptedRestart)
                    }
                    EgressLifecycleState::RevokePending
                    | EgressLifecycleState::LegacyInvalidatedRestart => {
                        Some(EgressLifecycleState::IndeterminateRestart)
                    }
                    _ => None,
                }
            };
            if let Some(target) = target {
                record.state = target;
                record.last_transition_from_sha256 = Some(previous_sha256);
                record.updated_at_ms = transitioned_at;
                match target {
                    EgressLifecycleState::InterruptedRestart => {
                        record.interrupted_restart_at_ms = Some(transitioned_at);
                    }
                    EgressLifecycleState::IndeterminateRestart => {
                        record.indeterminate_restart_at_ms = Some(transitioned_at);
                    }
                    _ => unreachable!(),
                }
                reconstructed = true;
            }
        }
        validate_file(&file, now)?;
        let mut journal = Self {
            path: path.to_path_buf(),
            owner_uid,
            file,
            persisted_sha256,
            publication_durability_uncertain: false,
            #[cfg(test)]
            fail_parent_fsync_after_rename_once: false,
        };
        if migrated || reconstructed || journal.persisted_sha256.is_none() {
            journal.flush()?;
        }
        Ok(journal)
    }

    pub(crate) fn record_prepared(
        &mut self,
        metadata: EgressJournalMetadata,
        recovery: &EgressRecoveryBlobRef,
    ) -> Result<EgressJournalCas> {
        self.ensure_mutable()?;
        let now = now_unix_ms();
        validate_metadata(&metadata, now)?;
        validate_recovery_reference(recovery)?;
        let previous = self.file.clone();
        let result = (|| -> Result<EgressJournalCas> {
            self.compact_for_headroom()?;
            if metadata.issued_at_ms <= self.file.compaction.through_issued_at_ms {
                bail!("android_egress_journal_compacted_epoch_replay_denied");
            }
            if self
                .file
                .records
                .iter()
                .any(|record| record.metadata.grant_id == metadata.grant_id)
            {
                bail!("android_egress_journal_duplicate_grant_id");
            }
            if replay_filter_contains(&self.file.compaction, &metadata.grant_id)? {
                bail!("android_egress_journal_compacted_grant_replay_denied");
            }
            if self.file.records.len() >= MAX_RECORDS {
                bail!("android_egress_journal_active_capacity_exhausted");
            }
            let binding_sha256 = metadata.binding_sha256()?;
            self.file.records.push(EgressJournalRecord {
                record_version: 4,
                prepared_at_ms: metadata.issued_at_ms,
                metadata,
                binding_sha256: binding_sha256.clone(),
                state: EgressLifecycleState::Prepared,
                recovery_envelope_file: recovery.file_name.clone(),
                recovery_envelope_sha256: recovery.ciphertext_sha256.clone(),
                teardown_nonce_sha256: None,
                revoke_event: None,
                revoke_ui_outcome: None,
                completion_ack_sha256: None,
                runtime_evidence_sha256: None,
                runtime_evidence: None,
                predispatch_binding: None,
                predispatch_binding_sha256: None,
                predispatch_task_id_sha256: None,
                direct_provider_attempt: None,
                prepare_ui_completion_ack_sha256: None,
                prepare_ui_completion_proof_sha256: None,
                revoke_ui_completion_ack_sha256: None,
                revoke_ui_completion_proof_sha256: None,
                last_transition_from_sha256: None,
                consumed_at_ms: None,
                completed_at_ms: None,
                revoked_at_ms: None,
                expired_at_ms: None,
                invalidated_restart_at_ms: None,
                interrupted_restart_at_ms: None,
                indeterminate_restart_at_ms: None,
                consent_receipt_id: None,
                updated_at_ms: now,
            });
            self.compact_for_headroom()?;
            if let Err(error) = self.flush()
                && !self.publication_durability_uncertain
            {
                return Err(error);
            }
            self.cas_for(
                self.file
                    .records
                    .last()
                    .context("prepared_record_missing")?,
            )
        })();
        if result.is_err() && !self.publication_durability_uncertain {
            self.file = previous;
        }
        result
    }

    pub(crate) fn mark_consumed(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        consent_receipt_id: &str,
        teardown_nonce_sha256: &str,
        now: u64,
    ) -> Result<EgressJournalCas> {
        validate_digest(consent_receipt_id, "consent_receipt_id")?;
        validate_digest(teardown_nonce_sha256, "teardown_nonce_sha256")?;
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::Prepared,
            EgressLifecycleState::Consumed,
            now,
            |record| {
                if record.prepare_ui_completion_ack_sha256.is_none() {
                    bail!("android_egress_journal_consume_before_prepare_ui_completion_ack");
                }
                record.consumed_at_ms = Some(record.updated_at_ms);
                record.consent_receipt_id = Some(consent_receipt_id.to_string());
                record.teardown_nonce_sha256 = Some(teardown_nonce_sha256.to_string());
                Ok(())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn freeze_predispatch_binding(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        binding: &RuntimeLifecycleBinding,
        task_id: &str,
        provider_invocation_id: &str,
        provider_session_id: &str,
        now: u64,
    ) -> Result<EgressJournalCas> {
        validate_grant_id(grant_id)?;
        validate_request_id(provider_invocation_id)?;
        if provider_session_id.is_empty()
            || provider_session_id.len() > 256
            || provider_session_id.chars().any(char::is_control)
        {
            bail!("android_egress_journal_provider_session_id_denied");
        }
        if task_id.is_empty() || task_id.len() > 128 || task_id.chars().any(char::is_control) {
            bail!("android_egress_journal_predispatch_task_id_denied");
        }
        if !binding.shape_proven()
            || binding.egress_grant_id != grant_id
            || binding.provider_invocation_id_sha256
                != sha256_bytes(provider_invocation_id.as_bytes())
            || binding.provider_session_id_sha256 != sha256_bytes(provider_session_id.as_bytes())
        {
            bail!("android_egress_journal_predispatch_runtime_binding_shape_denied");
        }
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let task_id_sha256 = sha256_bytes(task_id.as_bytes());
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::Consumed,
            EgressLifecycleState::Consumed,
            now,
            |record| {
                let teardown_nonce_sha256 = record
                    .teardown_nonce_sha256
                    .as_deref()
                    .context("android_egress_journal_teardown_nonce_missing")?;
                let metadata = &record.metadata;
                if binding.provider_id != metadata.provider_id
                    || binding.agent_id != metadata.agent_id
                    || binding.agent_peer_uid != metadata.agent_peer_uid
                    || binding.agent_peer_gid != metadata.agent_peer_gid
                    || binding.agent_selinux_domain_sha256 != metadata.agent_selinux_domain_sha256
                    || binding.agent_executable_sha256 != metadata.agent_executable_sha256
                    || binding.agent_manifest_sha256 != metadata.agent_manifest_sha256
                    || binding.journal_binding_sha256 != record.binding_sha256
                    || binding.teardown_nonce_sha256 != teardown_nonce_sha256
                    || binding.approved_endpoint != metadata.endpoint
                    || binding.upload_byte_limit != metadata.upload_byte_limit
                    || binding.download_byte_limit != metadata.download_byte_limit
                    || binding.grant_issued_at_unix_ms < metadata.issued_at_ms
                    || binding.grant_expires_at_unix_ms > metadata.expires_at_ms
                    || binding.grant_expires_at_unix_ms <= binding.grant_issued_at_unix_ms
                    || record.runtime_evidence.is_some()
                    || record.runtime_evidence_sha256.is_some()
                {
                    bail!("android_egress_journal_predispatch_runtime_binding_mismatch");
                }
                if let Some(existing) = &record.predispatch_binding {
                    if existing != binding
                        || record.predispatch_binding_sha256.as_deref()
                            != Some(binding_sha256.as_str())
                        || record.predispatch_task_id_sha256.as_deref()
                            != Some(task_id_sha256.as_str())
                    {
                        bail!("android_egress_journal_predispatch_binding_changed");
                    }
                } else {
                    record.predispatch_binding = Some(binding.clone());
                    record.predispatch_binding_sha256 = Some(binding_sha256.clone());
                    record.predispatch_task_id_sha256 = Some(task_id_sha256.clone());
                }
                Ok(())
            },
        )
    }

    /// Allocate the one provider-attempt generation owned by this exact
    /// frozen lifecycle. The generation is exactly one because this milestone
    /// has no retry rollover: uniqueness comes from the exact lifecycle binding
    /// and the allocation's canonical predecessor/successor record CAS. No
    /// timestamp or caller nonce stands in for durability. A second allocation
    /// is always rejected, even when the caller presents the latest CAS.
    pub(crate) fn allocate_direct_provider_attempt(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        binding: &RuntimeLifecycleBinding,
        task_id: &str,
        now: u64,
    ) -> Result<EgressJournalCas> {
        self.ensure_mutable()?;
        validate_grant_id(grant_id)?;
        validate_cas(expected)?;
        if expected.publication_durability_uncertain {
            bail!("android_egress_journal_direct_attempt_uncertain_predecessor_denied");
        }
        if task_id.is_empty() || task_id.len() > 128 || task_id.chars().any(char::is_control) {
            bail!("android_egress_journal_direct_attempt_task_id_denied");
        }
        if !binding.shape_proven() || binding.egress_grant_id != grant_id {
            bail!("android_egress_journal_direct_attempt_runtime_binding_shape_denied");
        }
        let runtime_lifecycle_binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let task_id_sha256 = sha256_bytes(task_id.as_bytes());
        let index = self
            .file
            .records
            .iter()
            .position(|record| record.metadata.grant_id == grant_id)
            .context("android_egress_journal_unknown_grant")?;
        let record = &self.file.records[index];
        if !matches!(record.record_version, 3 | 4)
            || record.binding_sha256 != expected.binding_sha256
            || record.state != EgressLifecycleState::Consumed
            || expected.state != EgressLifecycleState::Consumed
            || record_sha256(record)? != expected.record_sha256
        {
            bail!("android_egress_journal_direct_attempt_compare_and_swap_failed");
        }
        if record.direct_provider_attempt.is_some() {
            bail!("android_egress_journal_direct_attempt_already_allocated");
        }
        if record.predispatch_binding.as_ref() != Some(binding)
            || record.predispatch_binding_sha256.as_deref()
                != Some(runtime_lifecycle_binding_sha256.as_str())
            || record.predispatch_task_id_sha256.as_deref() != Some(task_id_sha256.as_str())
            || record.metadata.provider_id != binding.provider_id
            || record.metadata.agent_id != binding.agent_id
        {
            bail!("android_egress_journal_direct_attempt_frozen_binding_mismatch");
        }
        let attempt_generation = 1;
        let previous_file = self.file.clone();
        let record = &mut self.file.records[index];
        // A v5 PREPARED record may legitimately survive migration and be
        // consumed only after the user completes the pending consent. Promote
        // that exact record to v4 only while durably allocating its first and
        // only direct attempt; migration itself never invents an attempt.
        record.record_version = 4;
        record.updated_at_ms = now.max(record.prepared_at_ms);
        record.last_transition_from_sha256 = Some(expected.record_sha256.clone());
        record.direct_provider_attempt = Some(DurableDirectProviderAttempt {
            schema: DIRECT_PROVIDER_ATTEMPT_SCHEMA.to_string(),
            provider_id: binding.provider_id.clone(),
            agent_id: binding.agent_id.clone(),
            task_id_sha256,
            runtime_lifecycle_binding_sha256,
            attempt_generation,
            allocation_predecessor_record_sha256: expected.record_sha256.clone(),
        });
        if let Err(error) = self.flush()
            && !self.publication_durability_uncertain
        {
            self.file = previous_file;
            return Err(error);
        }
        self.cas_for(&self.file.records[index])
    }

    /// Snapshot the exact just-allocated record for lock-free inbox
    /// publication.  The returned digest is the canonical digest of the whole
    /// updated egress record, not a caller-provided identifier and not a
    /// self-referential field inside the attempt subrecord.
    pub(crate) fn direct_provider_attempt_source(
        &self,
        grant_id: &str,
        expected: &EgressJournalCas,
        binding: &RuntimeLifecycleBinding,
        task_id: &str,
    ) -> Result<EgressDurableProviderAttemptSource> {
        self.ensure_mutable()?;
        validate_grant_id(grant_id)?;
        validate_cas(expected)?;
        if expected.publication_durability_uncertain {
            bail!("android_egress_journal_direct_attempt_source_uncertain_denied");
        }
        let record = self.record(grant_id)?;
        let runtime_lifecycle_binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let task_id_sha256 = sha256_bytes(task_id.as_bytes());
        let attempt = record
            .direct_provider_attempt
            .as_ref()
            .context("android_egress_journal_direct_attempt_missing")?;
        if record.record_version != 4
            || record.binding_sha256 != expected.binding_sha256
            || record.state != EgressLifecycleState::Consumed
            || expected.state != EgressLifecycleState::Consumed
            || record_sha256(record)? != expected.record_sha256
            || record.predispatch_binding.as_ref() != Some(binding)
            || record.predispatch_binding_sha256.as_deref()
                != Some(runtime_lifecycle_binding_sha256.as_str())
            || record.predispatch_task_id_sha256.as_deref() != Some(task_id_sha256.as_str())
            || attempt.provider_id != binding.provider_id
            || attempt.agent_id != binding.agent_id
            || attempt.task_id_sha256 != task_id_sha256
            || attempt.runtime_lifecycle_binding_sha256 != runtime_lifecycle_binding_sha256
            || record.last_transition_from_sha256.as_deref()
                != Some(attempt.allocation_predecessor_record_sha256.as_str())
            || record.runtime_evidence.is_some()
            || record.runtime_evidence_sha256.is_some()
            || record.revoke_event.is_some()
            || record.completion_ack_sha256.is_some()
        {
            bail!("android_egress_journal_direct_attempt_source_binding_mismatch");
        }
        let query = DurableProviderAttemptQuery {
            provider_id: binding.provider_id.clone(),
            agent_id: binding.agent_id.clone(),
            task_id: task_id.to_string(),
            runtime_lifecycle_binding_sha256: runtime_lifecycle_binding_sha256.clone(),
        };
        let durable_record = DurableProviderAttemptRecord::from_durable_journal_record(
            runtime_lifecycle_binding_sha256,
            attempt.attempt_generation,
            expected.record_sha256.clone(),
            sha256_bytes(grant_id.as_bytes()),
            expected.binding_sha256.clone(),
        )?;
        Ok(EgressDurableProviderAttemptSource {
            query,
            record: durable_record,
        })
    }

    /// Derive an inert custody snapshot from the exact durable Direct terminal.
    ///
    /// `allocation_cas` is the successor CAS whose record digest was committed
    /// into the hidden binding's daemon-attempt context. `terminal_cas` is the
    /// exact current Completed CAS. Neither digest is accepted in isolation:
    /// both are checked against the root-owned journal record and the closed
    /// `DirectOperationBinding` before any sealed snapshot is returned.
    #[allow(dead_code)]
    pub(crate) fn verified_direct_terminal_snapshot(
        &self,
        grant_id: &str,
        terminal_cas: &EgressJournalCas,
        allocation_cas: &EgressJournalCas,
        binding: &DirectOperationBinding,
    ) -> Result<VerifiedDirectTerminalEgressSnapshot> {
        self.ensure_mutable()?;
        validate_grant_id(grant_id)?;
        validate_cas(terminal_cas)?;
        validate_cas(allocation_cas)?;
        if terminal_cas.publication_durability_uncertain
            || allocation_cas.publication_durability_uncertain
        {
            bail!("android_egress_journal_direct_terminal_uncertain_cas_denied");
        }
        binding
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        prove_current_persisted_file(self)?;

        let record = self.record(grant_id)?;
        let final_record_sha256 = record_sha256(record)?;
        let attempt = record
            .direct_provider_attempt
            .as_ref()
            .context("android_egress_journal_direct_terminal_attempt_missing")?;
        let runtime_binding = record
            .predispatch_binding
            .as_ref()
            .context("android_egress_journal_direct_terminal_runtime_binding_missing")?;
        let runtime_lifecycle_binding_sha256 = runtime_binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let binding_sha256 = binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let expected_attempt_context_sha256 = daemon_attempt_context_sha256(
            &attempt.provider_id,
            &attempt.agent_id,
            &binding.stable_seed.task_id,
            &runtime_lifecycle_binding_sha256,
            attempt.attempt_generation,
            &allocation_cas.record_sha256,
        )?;
        let predecessor_record_sha256 = record
            .last_transition_from_sha256
            .as_ref()
            .context("android_egress_journal_direct_terminal_predecessor_missing")?;
        let runtime_evidence = record
            .runtime_evidence
            .as_ref()
            .context("android_egress_journal_direct_terminal_runtime_evidence_missing")?;
        let runtime_evidence_sha256 = record
            .runtime_evidence_sha256
            .as_ref()
            .context("android_egress_journal_direct_terminal_runtime_digest_missing")?;
        let completion_ack_sha256 = record
            .completion_ack_sha256
            .as_ref()
            .context("android_egress_journal_direct_terminal_completion_ack_missing")?;

        if record.record_version != 4
            || record.state != EgressLifecycleState::Completed
            || terminal_cas.state != EgressLifecycleState::Completed
            || terminal_cas.binding_sha256 != record.binding_sha256
            || terminal_cas.record_sha256 != final_record_sha256
            || allocation_cas.state != EgressLifecycleState::Consumed
            || allocation_cas.binding_sha256 != record.binding_sha256
            || allocation_cas.record_sha256 == final_record_sha256
            || allocation_cas.record_sha256.as_str() == predecessor_record_sha256.as_str()
            || allocation_cas.record_sha256 == attempt.allocation_predecessor_record_sha256
            || record.revoke_event.is_some()
            || record.revoke_ui_outcome.is_some()
            || record.metadata.grant_id != grant_id
            || record.metadata.provider_id != binding.stable_seed.provider_id
            || record.metadata.agent_id != binding.stable_seed.agent_id
            || record.metadata.peer_uid != binding.stable_seed.subject_uid
            || record.metadata.peer_selinux_domain_sha256
                != binding.stable_seed.subject_selinux_domain_sha256
            || record.metadata.workflow_id_sha256 != binding.workflow_id_sha256
            || record.metadata.agent_executable_sha256 != binding.agent_executable_sha256
            || runtime_binding.agent_executable_sha256 != binding.agent_executable_sha256
            || binding.agent_identity_key_sha256 != binding.agent_executable_sha256
            || record.predispatch_binding_sha256.as_deref()
                != Some(runtime_lifecycle_binding_sha256.as_str())
            || record.predispatch_task_id_sha256.as_deref()
                != Some(sha256_bytes(binding.stable_seed.task_id.as_bytes()).as_str())
            || runtime_binding.provider_id != binding.stable_seed.provider_id
            || runtime_binding.agent_id != binding.stable_seed.agent_id
            || runtime_binding.provider_invocation_id_sha256
                != binding.stable_seed.provider_invocation_id_sha256
            || runtime_binding.provider_session_id_sha256
                != binding.stable_seed.provider_session_id_sha256
            || runtime_binding.egress_grant_id != grant_id
            || runtime_binding.journal_binding_sha256 != record.binding_sha256
            || attempt.provider_id != binding.stable_seed.provider_id
            || attempt.agent_id != binding.stable_seed.agent_id
            || attempt.task_id_sha256 != sha256_bytes(binding.stable_seed.task_id.as_bytes())
            || attempt.runtime_lifecycle_binding_sha256 != runtime_lifecycle_binding_sha256
            || attempt.attempt_generation != binding.attempt.attempt_generation
            || binding.attempt.runtime_lifecycle_binding_sha256 != runtime_lifecycle_binding_sha256
            || binding.attempt.daemon_attempt_context_sha256 != expected_attempt_context_sha256
        {
            bail!("android_egress_journal_direct_terminal_binding_mismatch");
        }
        for (field, digest) in [
            ("direct_binding_sha256", binding_sha256.as_str()),
            (
                "egress_journal_binding_sha256",
                record.binding_sha256.as_str(),
            ),
            (
                "direct_terminal_final_record_sha256",
                final_record_sha256.as_str(),
            ),
            (
                "direct_terminal_predecessor_record_sha256",
                predecessor_record_sha256.as_str(),
            ),
            (
                "direct_terminal_runtime_evidence_sha256",
                runtime_evidence_sha256.as_str(),
            ),
            (
                "direct_terminal_completion_ack_sha256",
                completion_ack_sha256.as_str(),
            ),
        ] {
            validate_digest(digest, field)?;
            if digest.bytes().all(|byte| byte == b'0') {
                bail!("android_egress_journal_direct_terminal_zero_digest_denied:{field}");
            }
        }
        validate_runtime_evidence_against_record(
            record,
            runtime_evidence_sha256,
            runtime_evidence,
        )?;

        let egress_grant_id_sha256 = sha256_bytes(grant_id.as_bytes());
        let terminal_egress_cas_sha256 = direct_terminal_egress_digest(
            &binding_sha256,
            &binding.invocation_id,
            &binding.attempt.delivery_provider_attempt_id,
            &egress_grant_id_sha256,
            &record.binding_sha256,
            &final_record_sha256,
            predecessor_record_sha256,
            runtime_evidence_sha256,
            completion_ack_sha256,
        )?;
        Ok(VerifiedDirectTerminalEgressSnapshot {
            binding_sha256,
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.attempt.delivery_provider_attempt_id.clone(),
            egress_grant_id_sha256,
            egress_journal_binding_sha256: record.binding_sha256.clone(),
            final_record_sha256,
            predecessor_record_sha256: predecessor_record_sha256.clone(),
            runtime_evidence_sha256: runtime_evidence_sha256.clone(),
            provider_teardown_completion_ack_sha256: completion_ack_sha256.clone(),
            terminal_egress_cas_sha256,
        })
    }

    pub(crate) fn mark_revoke_pending(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        request_id: &str,
        request_payload_sha256: &str,
        teardown_nonce_sha256: &str,
        now: u64,
    ) -> Result<EgressJournalCas> {
        validate_request_id(request_id)?;
        validate_digest(request_payload_sha256, "request_payload_sha256")?;
        validate_digest(teardown_nonce_sha256, "teardown_nonce_sha256")?;
        if expected.state != EgressLifecycleState::Consumed {
            bail!("android_egress_journal_revoke_source_state_denied");
        }
        self.transition_cas(
            grant_id,
            expected,
            expected.state,
            EgressLifecycleState::RevokePending,
            now,
            |record| {
                if let Some(existing) = &record.teardown_nonce_sha256 {
                    if existing != teardown_nonce_sha256 {
                        bail!("android_egress_journal_teardown_nonce_binding_mismatch");
                    }
                } else {
                    record.teardown_nonce_sha256 = Some(teardown_nonce_sha256.to_string());
                }
                record.revoke_event = Some(EgressRevokeEvent {
                    schema: "trillionnium.android-egress-revoke-event.v1".to_string(),
                    request_id: request_id.to_string(),
                    request_payload_sha256: request_payload_sha256.to_string(),
                    requested_at_ms: record.updated_at_ms,
                    teardown_ack_sha256: None,
                    teardown_ack_at_ms: None,
                });
                Ok(())
            },
        )
    }

    pub(crate) fn mark_revoked_before_dispatch(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        request_id: &str,
        request_payload_sha256: &str,
        now: u64,
    ) -> Result<EgressJournalCas> {
        validate_request_id(request_id)?;
        validate_digest(request_payload_sha256, "request_payload_sha256")?;
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::Prepared,
            EgressLifecycleState::RevokedBeforeDispatch,
            now,
            |record| {
                if record.consumed_at_ms.is_some()
                    || record.consent_receipt_id.is_some()
                    || record.teardown_nonce_sha256.is_some()
                    || record.runtime_evidence.is_some()
                    || record.runtime_evidence_sha256.is_some()
                {
                    bail!("android_egress_journal_no_dispatch_revocation_proof_denied");
                }
                record.revoke_event = Some(EgressRevokeEvent {
                    schema: "trillionnium.android-egress-revoke-event.v1".to_string(),
                    request_id: request_id.to_string(),
                    request_payload_sha256: request_payload_sha256.to_string(),
                    requested_at_ms: record.updated_at_ms,
                    teardown_ack_sha256: None,
                    teardown_ack_at_ms: None,
                });
                record.revoke_ui_outcome = Some(EgressRevokeUiOutcome::RevokedBeforeDispatch);
                record.revoked_at_ms = Some(record.updated_at_ms);
                Ok(())
            },
        )
    }

    pub(crate) fn freeze_revoke_pending_ui_outcome(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        request_id: &str,
        request_payload_sha256: &str,
        now: u64,
    ) -> Result<EgressJournalCas> {
        validate_request_id(request_id)?;
        validate_digest(request_payload_sha256, "request_payload_sha256")?;
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::RevokePending,
            EgressLifecycleState::RevokePending,
            now,
            |record| {
                let event = record
                    .revoke_event
                    .as_ref()
                    .context("android_egress_journal_revoke_event_missing")?;
                if event.request_id != request_id
                    || event.request_payload_sha256 != request_payload_sha256
                {
                    bail!("android_egress_journal_revoke_request_binding_mismatch");
                }
                match record.revoke_ui_outcome {
                    None | Some(EgressRevokeUiOutcome::RevokePending) => {
                        record.revoke_ui_outcome = Some(EgressRevokeUiOutcome::RevokePending);
                    }
                    _ => bail!("android_egress_journal_revoke_ui_outcome_changed"),
                }
                Ok(())
            },
        )
    }

    pub(crate) fn mark_expired_for_revoke(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        request_id: &str,
        request_payload_sha256: &str,
        now: u64,
    ) -> Result<EgressJournalCas> {
        validate_request_id(request_id)?;
        validate_digest(request_payload_sha256, "request_payload_sha256")?;
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::Prepared,
            EgressLifecycleState::Expired,
            now,
            |record| {
                if record.updated_at_ms < record.metadata.expires_at_ms {
                    bail!("android_egress_journal_premature_expiry_denied");
                }
                record.expired_at_ms = Some(record.updated_at_ms);
                record.revoke_event = Some(EgressRevokeEvent {
                    schema: "trillionnium.android-egress-revoke-event.v1".to_string(),
                    request_id: request_id.to_string(),
                    request_payload_sha256: request_payload_sha256.to_string(),
                    requested_at_ms: record.updated_at_ms,
                    teardown_ack_sha256: None,
                    teardown_ack_at_ms: None,
                });
                record.revoke_ui_outcome = Some(EgressRevokeUiOutcome::GrantExpired);
                Ok(())
            },
        )
    }

    pub(crate) fn freeze_expired_revoke_ui_outcome_for_subject(
        &mut self,
        grant_id: &str,
        request: EgressExpiredRevokeRequest<'_>,
    ) -> Result<EgressJournalCas> {
        let EgressExpiredRevokeRequest {
            workflow_id,
            peer_uid,
            peer_selinux_domain,
            request_id,
            request_payload_sha256,
            now,
        } = request;
        if self.status_for_subject(grant_id, workflow_id, peer_uid, peer_selinux_domain)?
            != EgressLifecycleState::Expired
        {
            bail!("android_egress_journal_expired_revoke_state_mismatch");
        }
        let expected = self.snapshot(grant_id, &self.record(grant_id)?.binding_sha256.clone())?;
        self.transition_cas(
            grant_id,
            &expected,
            EgressLifecycleState::Expired,
            EgressLifecycleState::Expired,
            now,
            |record| {
                if let Some(event) = &record.revoke_event {
                    if event.request_id != request_id
                        || event.request_payload_sha256 != request_payload_sha256
                    {
                        bail!("android_egress_journal_revoke_request_binding_mismatch");
                    }
                } else {
                    record.revoke_event = Some(EgressRevokeEvent {
                        schema: "trillionnium.android-egress-revoke-event.v1".to_string(),
                        request_id: request_id.to_string(),
                        request_payload_sha256: request_payload_sha256.to_string(),
                        requested_at_ms: record.updated_at_ms,
                        teardown_ack_sha256: None,
                        teardown_ack_at_ms: None,
                    });
                }
                record.revoke_ui_outcome = Some(EgressRevokeUiOutcome::GrantExpired);
                Ok(())
            },
        )
    }

    pub(crate) fn mark_runtime_evidence(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        runtime_evidence_sha256: &str,
        runtime_evidence: &CodexRuntimeEvidence,
        now: u64,
    ) -> Result<EgressJournalCas> {
        validate_digest(runtime_evidence_sha256, "runtime_evidence_sha256")?;
        if !matches!(
            expected.state,
            EgressLifecycleState::Consumed | EgressLifecycleState::RevokePending
        ) {
            bail!("android_egress_journal_runtime_evidence_source_state_denied");
        }
        self.transition_cas(
            grant_id,
            expected,
            expected.state,
            expected.state,
            now,
            |record| {
                validate_runtime_evidence_against_record(
                    record,
                    runtime_evidence_sha256,
                    runtime_evidence,
                )?;
                if let Some(existing) = record.runtime_evidence_sha256.as_deref()
                    && existing != runtime_evidence_sha256
                {
                    bail!("android_egress_journal_runtime_evidence_changed");
                }
                record.runtime_evidence_sha256 = Some(runtime_evidence_sha256.to_string());
                record.runtime_evidence = Some(runtime_evidence.clone());
                Ok(())
            },
        )
    }

    pub(crate) fn mark_revoked(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        ack: &EgressTeardownAck,
    ) -> Result<EgressJournalCas> {
        validate_teardown_ack(ack)?;
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::RevokePending,
            EgressLifecycleState::Revoked,
            ack.acknowledged_at_ms,
            |record| {
                validate_teardown_ack_against_record(record, ack)?;
                let event = record
                    .revoke_event
                    .as_mut()
                    .context("android_egress_journal_revoke_event_missing")?;
                event.teardown_ack_sha256 = Some(sha256_json(&serde_json::to_value(ack)?));
                event.teardown_ack_at_ms = Some(ack.acknowledged_at_ms);
                if record.revoke_ui_outcome.is_none() {
                    record.revoke_ui_outcome = Some(EgressRevokeUiOutcome::Revoked);
                }
                record.revoked_at_ms = Some(record.updated_at_ms);
                Ok(())
            },
        )
    }

    pub(crate) fn mark_completed(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        ack: &EgressTeardownAck,
    ) -> Result<EgressJournalCas> {
        validate_teardown_ack(ack)?;
        if ack.termination_reason != "completed" {
            bail!("android_egress_journal_completion_ack_reason_denied");
        }
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::Consumed,
            EgressLifecycleState::Completed,
            ack.acknowledged_at_ms,
            |record| {
                validate_teardown_ack_against_record(record, ack)?;
                record.completed_at_ms = Some(record.updated_at_ms);
                record.completion_ack_sha256 = Some(sha256_json(&serde_json::to_value(ack)?));
                Ok(())
            },
        )
    }

    pub(crate) fn mark_expired(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        now: u64,
    ) -> Result<EgressJournalCas> {
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::Prepared,
            EgressLifecycleState::Expired,
            now,
            |record| {
                if record.updated_at_ms < record.metadata.expires_at_ms {
                    bail!("android_egress_journal_premature_expiry_denied");
                }
                record.expired_at_ms = Some(record.updated_at_ms);
                Ok(())
            },
        )
    }

    pub(crate) fn mark_prepared_indeterminate(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        now: u64,
    ) -> Result<EgressJournalCas> {
        self.transition_cas(
            grant_id,
            expected,
            EgressLifecycleState::Prepared,
            EgressLifecycleState::IndeterminateRestart,
            now,
            |record| {
                record.indeterminate_restart_at_ms = Some(record.updated_at_ms);
                Ok(())
            },
        )
    }

    pub(crate) fn snapshot(
        &self,
        grant_id: &str,
        binding_sha256: &str,
    ) -> Result<EgressJournalCas> {
        validate_grant_id(grant_id)?;
        validate_digest(binding_sha256, "binding_sha256")?;
        let record = self.record(grant_id)?;
        if record.binding_sha256 != binding_sha256 {
            bail!("android_egress_journal_binding_mismatch");
        }
        self.cas_for(record)
    }

    pub(crate) fn prepared_records(
        &self,
    ) -> Result<
        Vec<(
            EgressJournalMetadata,
            EgressJournalCas,
            EgressRecoveryBlobRef,
        )>,
    > {
        self.file
            .records
            .iter()
            .filter(|record| record.state == EgressLifecycleState::Prepared)
            .map(|record| {
                Ok((
                    record.metadata.clone(),
                    self.cas_for(record)?,
                    recovery_reference(record)?,
                ))
            })
            .collect()
    }

    pub(crate) fn retained_recovery_files(&self) -> Result<HashSet<String>> {
        self.file
            .records
            .iter()
            .filter(|record| {
                record.record_version >= 3
                    && (record.state == EgressLifecycleState::Prepared
                        || record.prepare_ui_completion_ack_sha256.is_none())
            })
            .map(|record| Ok(recovery_reference(record)?.file_name))
            .collect()
    }

    pub(crate) fn recovery_must_be_retained(&self, grant_id: &str) -> Result<bool> {
        let record = self.record(grant_id)?;
        Ok(record.record_version >= 3
            && (record.state == EgressLifecycleState::Prepared
                || record.prepare_ui_completion_ack_sha256.is_none()))
    }

    pub(crate) fn prepare_recovery_candidates_for_subject(
        &self,
        workflow_id: &str,
        provider_id: &str,
        peer_uid: u32,
        peer_selinux_domain: &str,
        request_id: &str,
        request_payload_sha256: &str,
    ) -> Result<
        Vec<(
            EgressJournalMetadata,
            EgressJournalCas,
            EgressRecoveryBlobRef,
        )>,
    > {
        validate_request_id(workflow_id)?;
        validate_request_id(request_id)?;
        validate_digest(request_payload_sha256, "prepare_request_payload_sha256")?;
        if agent_principal_registry::from_provider_id(provider_id).is_none() {
            bail!("android_egress_journal_provider_denied");
        }
        self.file
            .records
            .iter()
            .filter(|record| {
                record.record_version >= 3
                    && record.metadata.workflow_id_sha256 == sha256_bytes(workflow_id.as_bytes())
                    && record.metadata.provider_id == provider_id
                    && record.metadata.peer_uid == peer_uid
                    && record.metadata.peer_selinux_domain_sha256
                        == sha256_bytes(peer_selinux_domain.as_bytes())
                    && record.metadata.prepare_request_id_sha256
                        == sha256_bytes(request_id.as_bytes())
                    && record.metadata.prepare_request_payload_sha256 == request_payload_sha256
                    && record.metadata.policy_epoch == CURRENT_EGRESS_POLICY_EPOCH
                    && record.metadata.provider_abi_epoch == CURRENT_PROVIDER_ABI_EPOCH
            })
            .map(|record| {
                Ok((
                    record.metadata.clone(),
                    self.cas_for(record)?,
                    recovery_reference(record)?,
                ))
            })
            .collect()
    }

    pub(crate) fn mark_ui_request_completed_exact(
        &mut self,
        grant_id: &str,
        completion: EgressUiCompletionBinding<'_>,
    ) -> Result<EgressJournalCas> {
        let EgressUiCompletionBinding {
            method,
            request_id,
            request_payload_sha256,
            completion_proof_sha256,
            peer_uid,
            peer_selinux_domain,
            completed_at_ms,
        } = completion;
        validate_grant_id(grant_id)?;
        validate_request_id(request_id)?;
        validate_digest(request_payload_sha256, "ui_request_payload_sha256")?;
        validate_digest(completion_proof_sha256, "ui_completion_proof_sha256")?;
        if !matches!(method, "prepare_egress" | "revoke_egress") {
            bail!("android_egress_journal_ui_completion_method_denied");
        }
        let record = self.record(grant_id)?;
        if record.record_version < 3
            || record.metadata.peer_uid != peer_uid
            || record.metadata.peer_selinux_domain_sha256
                != sha256_bytes(peer_selinux_domain.as_bytes())
            || record.metadata.policy_epoch != CURRENT_EGRESS_POLICY_EPOCH
            || record.metadata.provider_abi_epoch != CURRENT_PROVIDER_ABI_EPOCH
        {
            bail!("android_egress_journal_ui_completion_subject_or_epoch_mismatch");
        }
        if method == "prepare_egress" {
            if record.metadata.prepare_request_id_sha256 != sha256_bytes(request_id.as_bytes())
                || record.metadata.prepare_request_payload_sha256 != request_payload_sha256
            {
                bail!("android_egress_journal_prepare_ui_completion_binding_mismatch");
            }
        } else {
            let event = record
                .revoke_event
                .as_ref()
                .context("android_egress_journal_revoke_event_missing")?;
            if event.request_id != request_id
                || event.request_payload_sha256 != request_payload_sha256
                || record.revoke_ui_outcome.is_none()
            {
                bail!("android_egress_journal_revoke_ui_completion_binding_mismatch");
            }
        }
        let (existing_ack, existing_proof) = if method == "prepare_egress" {
            (
                record.prepare_ui_completion_ack_sha256.as_deref(),
                record.prepare_ui_completion_proof_sha256.as_deref(),
            )
        } else {
            (
                record.revoke_ui_completion_ack_sha256.as_deref(),
                record.revoke_ui_completion_proof_sha256.as_deref(),
            )
        };
        match (existing_ack, existing_proof) {
            (Some(_), Some(existing)) if existing == completion_proof_sha256 => {
                // Identity/payload/epoch/proof were checked above. The first
                // completion time is committed inside the stored ack digest;
                // an exact retry with a later wall clock must be idempotent.
                return self.cas_for(record);
            }
            (Some(_), Some(_)) => {
                bail!("android_egress_journal_ui_completion_proof_changed")
            }
            (None, None) => {}
            _ => bail!("android_egress_journal_ui_completion_ack_proof_shape_mismatch"),
        }
        if completed_at_ms < record.prepared_at_ms
            || completed_at_ms > now_unix_ms().saturating_add(MAX_CLOCK_SKEW_MS)
        {
            bail!("android_egress_journal_ui_completion_time_denied");
        }
        let ack = EgressUiCompletionAck {
            schema: "trillionnium.android-egress-ui-completion.v1",
            method,
            request_id,
            request_payload_sha256,
            completion_proof_sha256,
            peer_uid,
            peer_selinux_domain_sha256: sha256_bytes(peer_selinux_domain.as_bytes()),
            completed_at_ms,
        };
        let ack_sha256 = sha256_json(&serde_json::to_value(&ack)?);
        let expected = self.cas_for(record)?;
        self.transition_cas(
            grant_id,
            &expected,
            expected.state,
            expected.state,
            completed_at_ms,
            |record| {
                if method == "prepare_egress" {
                    record.prepare_ui_completion_ack_sha256 = Some(ack_sha256);
                    record.prepare_ui_completion_proof_sha256 =
                        Some(completion_proof_sha256.to_string());
                } else {
                    record.revoke_ui_completion_ack_sha256 = Some(ack_sha256);
                    record.revoke_ui_completion_proof_sha256 =
                        Some(completion_proof_sha256.to_string());
                }
                Ok(())
            },
        )
    }

    pub(crate) fn revoke_status_exact(
        &self,
        grant_id: &str,
        binding_sha256: &str,
        request_id: &str,
        request_payload_sha256: &str,
    ) -> Result<Option<EgressLifecycleState>> {
        let record = self.record(grant_id)?;
        if record.binding_sha256 != binding_sha256 {
            bail!("android_egress_journal_binding_mismatch");
        }
        let Some(event) = &record.revoke_event else {
            return Ok(None);
        };
        if event.request_id != request_id || event.request_payload_sha256 != request_payload_sha256
        {
            bail!("android_egress_journal_revoke_request_binding_mismatch");
        }
        Ok(Some(record.state))
    }

    pub(crate) fn revoke_outcome_for_subject(
        &self,
        grant_id: &str,
        workflow_id: &str,
        peer_uid: u32,
        peer_selinux_domain: &str,
        request_id: &str,
        request_payload_sha256: &str,
    ) -> Result<Option<EgressRevokeUiOutcome>> {
        self.status_for_subject(grant_id, workflow_id, peer_uid, peer_selinux_domain)?;
        validate_request_id(request_id)?;
        validate_digest(request_payload_sha256, "revoke_request_payload_sha256")?;
        let record = self.record(grant_id)?;
        let Some(event) = &record.revoke_event else {
            return Ok(None);
        };
        if event.request_id != request_id || event.request_payload_sha256 != request_payload_sha256
        {
            bail!("android_egress_journal_revoke_request_binding_mismatch");
        }
        Ok(record.revoke_ui_outcome)
    }

    pub(crate) fn status_for_subject(
        &self,
        grant_id: &str,
        workflow_id: &str,
        peer_uid: u32,
        peer_selinux_domain: &str,
    ) -> Result<EgressLifecycleState> {
        validate_grant_id(grant_id)?;
        validate_request_id(workflow_id)?;
        let record = self.record(grant_id)?;
        if record.metadata.workflow_id_sha256 != sha256_bytes(workflow_id.as_bytes())
            || record.metadata.peer_uid != peer_uid
            || record.metadata.peer_selinux_domain_sha256
                != sha256_bytes(peer_selinux_domain.as_bytes())
            || record.metadata.subject_user_id != peer_uid / 100_000
        {
            bail!("android_egress_journal_status_subject_binding_mismatch");
        }
        Ok(record.state)
    }

    pub(crate) fn runtime_evidence_for_subject(
        &self,
        grant_id: &str,
        workflow_id: &str,
        peer_uid: u32,
        peer_selinux_domain: &str,
    ) -> Result<Option<(CodexRuntimeEvidence, String)>> {
        self.status_for_subject(grant_id, workflow_id, peer_uid, peer_selinux_domain)?;
        let record = self.record(grant_id)?;
        match (&record.runtime_evidence, &record.runtime_evidence_sha256) {
            (None, None) => Ok(None),
            (Some(evidence), Some(digest)) => Ok(Some((evidence.clone(), digest.clone()))),
            _ => bail!("android_egress_journal_runtime_evidence_shape_mismatch"),
        }
    }

    pub(crate) fn provider_id_for_subject(
        &self,
        grant_id: &str,
        workflow_id: &str,
        peer_uid: u32,
        peer_selinux_domain: &str,
    ) -> Result<String> {
        self.status_for_subject(grant_id, workflow_id, peer_uid, peer_selinux_domain)?;
        Ok(self.record(grant_id)?.metadata.provider_id.clone())
    }

    fn transition_cas<F>(
        &mut self,
        grant_id: &str,
        expected: &EgressJournalCas,
        expected_state: EgressLifecycleState,
        target: EgressLifecycleState,
        now: u64,
        mutate: F,
    ) -> Result<EgressJournalCas>
    where
        F: FnOnce(&mut EgressJournalRecord) -> Result<()>,
    {
        self.ensure_mutable()?;
        validate_grant_id(grant_id)?;
        validate_cas(expected)?;
        let index = self
            .file
            .records
            .iter()
            .position(|record| record.metadata.grant_id == grant_id)
            .context("android_egress_journal_unknown_grant")?;
        let record = &self.file.records[index];
        if record.binding_sha256 != expected.binding_sha256 {
            bail!("android_egress_journal_binding_mismatch");
        }
        if record.state != expected_state
            || expected.state != expected_state
            || record_sha256(record)? != expected.record_sha256
        {
            bail!("android_egress_journal_compare_and_swap_failed");
        }
        let previous_file = self.file.clone();
        let record = &mut self.file.records[index];
        record.state = target;
        record.updated_at_ms = now.max(record.prepared_at_ms);
        record.last_transition_from_sha256 = Some(expected.record_sha256.clone());
        if let Err(error) = mutate(record) {
            self.file = previous_file;
            return Err(error);
        }
        if let Err(error) = self.flush()
            && !self.publication_durability_uncertain
        {
            self.file = previous_file;
            return Err(error);
        }
        self.cas_for(&self.file.records[index])
    }

    fn record(&self, grant_id: &str) -> Result<&EgressJournalRecord> {
        self.file
            .records
            .iter()
            .find(|record| record.metadata.grant_id == grant_id)
            .context("android_egress_journal_unknown_grant")
    }

    pub(crate) fn contains_grant(&self, grant_id: &str) -> bool {
        self.file
            .records
            .iter()
            .any(|record| record.metadata.grant_id == grant_id)
    }

    fn cas_for(&self, record: &EgressJournalRecord) -> Result<EgressJournalCas> {
        Ok(EgressJournalCas {
            binding_sha256: record.binding_sha256.clone(),
            state: record.state,
            record_sha256: record_sha256(record)?,
            publication_durability_uncertain: self.publication_durability_uncertain,
        })
    }

    fn compact_for_headroom(&mut self) -> Result<()> {
        self.compact_for_headroom_with_limits(
            COMPACTION_TRIGGER_RECORDS,
            COMPACTION_TRIGGER_BYTES,
            COMPACTION_TARGET_RECORDS,
        )
    }

    fn compact_for_headroom_with_limits(
        &mut self,
        trigger_records: usize,
        trigger_bytes: usize,
        target_records: usize,
    ) -> Result<()> {
        loop {
            let encoded_len = serde_json::to_vec(&self.file)?.len();
            if self.file.records.len() < trigger_records && encoded_len < trigger_bytes {
                break;
            }
            let desired = self
                .file
                .records
                .len()
                .saturating_sub(target_records)
                .max(self.file.records.len() / 4)
                .max(1);
            if self.compact_terminal_prefix(desired)? == 0 {
                break;
            }
        }
        Ok(())
    }

    /// Compact only a terminal prefix whose issuance boundary is strictly
    /// older than every retained record. Captured pre-compaction records can
    /// therefore never be reintroduced with their original signed metadata.
    /// The fixed Bloom checkpoint additionally rejects a compacted grant ID
    /// even if a caller attempts to pair it with newer metadata; false
    /// positives fail closed and can only deny a fresh random mint.
    fn compact_terminal_prefix(&mut self, desired: usize) -> Result<usize> {
        let terminal_prefix = self
            .file
            .records
            .iter()
            .take_while(|record| record.is_compactable_terminal())
            .count();
        let mut remove = desired.min(terminal_prefix);
        if remove == 0 {
            return Ok(0);
        }

        let mut prefix_max = Vec::with_capacity(remove);
        let mut maximum = 0u64;
        for record in self.file.records.iter().take(remove) {
            maximum = maximum.max(record.metadata.issued_at_ms);
            prefix_max.push(maximum);
        }
        let mut suffix_min = vec![u64::MAX; self.file.records.len() + 1];
        for index in (0..self.file.records.len()).rev() {
            suffix_min[index] =
                suffix_min[index + 1].min(self.file.records[index].metadata.issued_at_ms);
        }
        while remove > 0 && prefix_max[remove - 1] >= suffix_min[remove] {
            remove -= 1;
        }
        if remove == 0 {
            return Ok(0);
        }

        let removed = self.file.records.drain(0..remove).collect::<Vec<_>>();
        let mut filter = replay_filter_bytes(&self.file.compaction)?;
        for record in &removed {
            replay_filter_insert(&mut filter, &record.metadata.grant_id);
        }
        let replay_filter_sha256 = sha256_bytes(&filter);
        let batch_commitment = sha256_json(&serde_json::to_value(&removed)?);
        let next_epoch = self
            .file
            .compaction
            .epoch
            .checked_add(1)
            .context("android_egress_journal_compaction_epoch_overflow")?;
        let terminal_commitment_sha256 = sha256_bytes(
            format!(
                "{}\n{}\n{}\n{}\n{}\n",
                self.file.compaction.terminal_commitment_sha256,
                next_epoch,
                removed.len(),
                batch_commitment,
                replay_filter_sha256
            )
            .as_bytes(),
        );
        self.file.compaction.epoch = next_epoch;
        self.file.compaction.compacted_terminal_records = self
            .file
            .compaction
            .compacted_terminal_records
            .checked_add(u64::try_from(removed.len())?)
            .context("android_egress_journal_compacted_count_overflow")?;
        self.file.compaction.through_issued_at_ms = self.file.compaction.through_issued_at_ms.max(
            removed
                .iter()
                .map(|record| record.metadata.issued_at_ms)
                .max()
                .unwrap_or(0),
        );
        self.file.compaction.through_updated_at_ms =
            self.file.compaction.through_updated_at_ms.max(
                removed
                    .iter()
                    .map(|record| record.updated_at_ms)
                    .max()
                    .unwrap_or(0),
            );
        self.file.compaction.terminal_commitment_sha256 = terminal_commitment_sha256;
        self.file.compaction.replay_filter_sha256 = replay_filter_sha256;
        self.file.compaction.replay_filter_b64 = BASE64_STANDARD.encode(filter);
        Ok(remove)
    }

    #[cfg(test)]
    pub(crate) fn compact_terminal_prefix_for_test(&mut self, desired: usize) -> Result<usize> {
        self.ensure_mutable()?;
        let previous = self.file.clone();
        let removed = match self.compact_terminal_prefix(desired) {
            Ok(removed) => removed,
            Err(error) => {
                self.file = previous;
                return Err(error);
            }
        };
        if removed > 0
            && let Err(error) = self.flush()
        {
            if !self.publication_durability_uncertain {
                self.file = previous;
            }
            return Err(error);
        }
        Ok(removed)
    }

    #[cfg(test)]
    pub(crate) fn state_for_test(&self, grant_id: &str) -> Option<EgressLifecycleState> {
        self.file
            .records
            .iter()
            .find(|record| record.metadata.grant_id == grant_id)
            .map(|record| record.state)
    }

    #[cfg(test)]
    pub(crate) fn metadata_for_test(&self, grant_id: &str) -> Option<EgressJournalMetadata> {
        self.file
            .records
            .iter()
            .find(|record| record.metadata.grant_id == grant_id)
            .map(|record| record.metadata.clone())
    }

    pub(crate) fn publication_durability_uncertain(&self) -> bool {
        self.publication_durability_uncertain
    }

    fn ensure_mutable(&self) -> Result<()> {
        if self.publication_durability_uncertain {
            bail!("android_egress_journal_fail_stop_published_durability_uncertain");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fail_parent_fsync_after_rename_once_for_test(&mut self) {
        self.fail_parent_fsync_after_rename_once = true;
    }

    fn flush(&mut self) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("android_egress_journal_parent_missing")?;
        ensure_private_parent(parent, self.owner_uid)?;
        validate_destination(&self.path, self.owner_uid)?;
        match (
            self.persisted_sha256.as_deref(),
            read_owner_controlled(&self.path, self.owner_uid)?,
        ) {
            (Some(expected), Some(bytes)) if sha256_bytes(&bytes) == expected => {}
            (None, None) => {}
            _ => bail!("android_egress_journal_changed_outside_atomic_writer"),
        }
        validate_file(&self.file, now_unix_ms())?;
        let mut bytes = serde_json::to_vec_pretty(&self.file)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_JOURNAL_BYTES {
            bail!("android_egress_journal_size_limit_exceeded");
        }
        let temporary = parent.join(format!(
            ".android-egress-journal.tmp-{}-{}-{}",
            std::process::id(),
            now_unix_ms(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .context("failed_to_create_android_egress_journal_temp")?;
        let publish_before_rename = (|| -> Result<()> {
            output.write_all(&bytes)?;
            output.sync_all()?;
            validate_open_file(&output, self.owner_uid, MAX_JOURNAL_BYTES)?;
            fs::rename(&temporary, &self.path)
                .context("failed_to_atomically_publish_android_egress_journal")?;
            Ok(())
        })();
        if let Err(error) = publish_before_rename {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        // The namespace now points at the new canonical bytes. From this
        // boundary onward an error must never roll the in-memory record back to
        // the old state: a reopen observes the new file even if directory
        // durability could not be proven.
        self.persisted_sha256 = Some(sha256_bytes(&bytes));
        #[cfg(test)]
        if std::mem::take(&mut self.fail_parent_fsync_after_rename_once) {
            self.publication_durability_uncertain = true;
            bail!("android_egress_journal_published_parent_fsync_uncertain_test_fault");
        }
        if let Err(error) = File::open(parent).and_then(|parent| parent.sync_all()) {
            self.publication_durability_uncertain = true;
            return Err(error).context("android_egress_journal_published_parent_fsync_uncertain");
        }
        Ok(())
    }
}

fn replay_filter_bytes(checkpoint: &EgressCompactionCheckpoint) -> Result<Vec<u8>> {
    if checkpoint.replay_filter_b64.is_empty() {
        return Ok(vec![0; REPLAY_FILTER_BYTES]);
    }
    let decoded = BASE64_STANDARD
        .decode(&checkpoint.replay_filter_b64)
        .context("android_egress_journal_replay_filter_invalid_base64")?;
    if decoded.len() != REPLAY_FILTER_BYTES
        || BASE64_STANDARD.encode(&decoded) != checkpoint.replay_filter_b64
    {
        bail!("android_egress_journal_replay_filter_boundary_denied");
    }
    Ok(decoded)
}

fn replay_filter_positions(grant_id: &str) -> Result<[usize; REPLAY_FILTER_HASHES]> {
    validate_grant_id(grant_id)?;
    let bit_count = REPLAY_FILTER_BYTES * 8;
    let mut positions = [0usize; REPLAY_FILTER_HASHES];
    for (index, position) in positions.iter_mut().enumerate() {
        let digest =
            sha256_bytes(format!("egress-replay-filter-v1\n{index}\n{grant_id}").as_bytes());
        let prefix = u64::from_str_radix(&digest[..16], 16)
            .context("android_egress_journal_replay_filter_digest_invalid")?;
        *position = usize::try_from(prefix % u64::try_from(bit_count)?)?;
    }
    Ok(positions)
}

fn replay_filter_insert(filter: &mut [u8], grant_id: &str) {
    // Inputs were validated before compaction; an impossible derivation error
    // leaves all bits set so the checkpoint fails closed instead of dropping a
    // tombstone. The fallible validation path is used for lookups.
    match replay_filter_positions(grant_id) {
        Ok(positions) => {
            for position in positions {
                filter[position / 8] |= 1 << (position % 8);
            }
        }
        Err(_) => filter.fill(u8::MAX),
    }
}

fn replay_filter_contains(checkpoint: &EgressCompactionCheckpoint, grant_id: &str) -> Result<bool> {
    if checkpoint.compacted_terminal_records == 0 {
        return Ok(false);
    }
    let filter = replay_filter_bytes(checkpoint)?;
    Ok(replay_filter_positions(grant_id)?
        .iter()
        .all(|position| filter[position / 8] & (1 << (position % 8)) != 0))
}

fn validate_metadata(metadata: &EgressJournalMetadata, now: u64) -> Result<()> {
    validate_metadata_common(metadata, now)?;
    for (field, digest) in [
        (
            "prepare_request_id_sha256",
            metadata.prepare_request_id_sha256.as_str(),
        ),
        (
            "prepare_request_payload_sha256",
            metadata.prepare_request_payload_sha256.as_str(),
        ),
        ("boot_id_sha256", metadata.boot_id_sha256.as_str()),
        (
            "agent_selinux_domain_sha256",
            metadata.agent_selinux_domain_sha256.as_str(),
        ),
        (
            "agent_executable_sha256",
            metadata.agent_executable_sha256.as_str(),
        ),
        (
            "agent_manifest_sha256",
            metadata.agent_manifest_sha256.as_str(),
        ),
    ] {
        validate_digest(digest, field)?;
    }
    if metadata.policy_epoch != CURRENT_EGRESS_POLICY_EPOCH
        || metadata.provider_abi_epoch != CURRENT_PROVIDER_ABI_EPOCH
        || metadata.agent_id.is_empty()
        || metadata.agent_id.len() > 128
        || metadata.agent_id.chars().any(char::is_control)
        || metadata.agent_peer_uid == 0
        || metadata.agent_peer_gid == 0
    {
        bail!("android_egress_journal_agent_binding_denied");
    }
    Ok(())
}

fn validate_metadata_common(metadata: &EgressJournalMetadata, now: u64) -> Result<()> {
    validate_grant_id(&metadata.grant_id)?;
    if agent_principal_registry::from_provider_id(&metadata.provider_id).is_none() {
        bail!("android_egress_journal_provider_denied");
    }
    for (field, digest) in [
        ("workflow_id_sha256", metadata.workflow_id_sha256.as_str()),
        (
            "peer_selinux_domain_sha256",
            metadata.peer_selinux_domain_sha256.as_str(),
        ),
        ("context_id_sha256", metadata.context_id_sha256.as_str()),
        ("context_sha256", metadata.context_sha256.as_str()),
        ("source_id_sha256", metadata.source_id_sha256.as_str()),
        ("intent_sha256", metadata.intent_sha256.as_str()),
        (
            "allowed_actions_sha256",
            metadata.allowed_actions_sha256.as_str(),
        ),
        (
            "consent_challenge_sha256",
            metadata.consent_challenge_sha256.as_str(),
        ),
    ] {
        validate_digest(digest, field)?;
    }
    if metadata.peer_uid < 10_000
        || metadata.subject_user_id != metadata.peer_uid / 100_000
        || !matches!(
            metadata.context_kind.as_str(),
            "file" | "browser" | "memory"
        )
        || metadata.context_captured_at_ms == 0
        || metadata.context_expires_at_ms <= metadata.context_captured_at_ms
        || metadata.issued_at_ms < metadata.context_captured_at_ms
        || metadata.expires_at_ms > metadata.context_expires_at_ms
        || !matches!(
            metadata.privacy_class.as_str(),
            "public" | "local_private" | "sensitive"
        )
        || metadata.content_bytes > MAX_EGRESS_BYTES
        || metadata.intent_bytes == 0
        || metadata.intent_bytes > 8_192
        || metadata.prompt_contract.is_empty()
        || metadata.prompt_contract.len() > 128
        || metadata.prompt_contract_version == 0
        || metadata.endpoint != "chatgpt.com:443"
        || metadata.upload_byte_limit < metadata.content_bytes
        || metadata.upload_byte_limit > MAX_EGRESS_BYTES
        || metadata.download_byte_limit == 0
        || metadata.download_byte_limit > MAX_EGRESS_BYTES
        || metadata.issued_at_ms == 0
        || metadata.issued_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        || metadata.expires_at_ms <= metadata.issued_at_ms
        || metadata.expires_at_ms - metadata.issued_at_ms > MAX_GRANT_TTL_MS
    {
        bail!("android_egress_journal_metadata_boundary_denied");
    }
    Ok(())
}

fn validate_predispatch_binding_for_record(
    record: &EgressJournalRecord,
) -> Result<Option<&RuntimeLifecycleBinding>> {
    match (
        &record.predispatch_binding,
        &record.predispatch_binding_sha256,
        &record.predispatch_task_id_sha256,
    ) {
        (None, None, None) => Ok(None),
        (Some(binding), Some(binding_sha256), Some(task_id_sha256)) => {
            validate_digest(binding_sha256, "predispatch_binding_sha256")?;
            validate_digest(task_id_sha256, "predispatch_task_id_sha256")?;
            let actual = binding
                .digest_sha256()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let metadata = &record.metadata;
            if !binding.shape_proven()
                || actual != *binding_sha256
                || binding.provider_id != metadata.provider_id
                || binding.agent_id != metadata.agent_id
                || binding.agent_peer_uid != metadata.agent_peer_uid
                || binding.agent_peer_gid != metadata.agent_peer_gid
                || binding.agent_selinux_domain_sha256 != metadata.agent_selinux_domain_sha256
                || binding.agent_executable_sha256 != metadata.agent_executable_sha256
                || binding.agent_manifest_sha256 != metadata.agent_manifest_sha256
                || binding.egress_grant_id != metadata.grant_id
                || binding.journal_binding_sha256 != record.binding_sha256
                || record.teardown_nonce_sha256.as_deref()
                    != Some(binding.teardown_nonce_sha256.as_str())
                || binding.approved_endpoint != metadata.endpoint
                || binding.upload_byte_limit != metadata.upload_byte_limit
                || binding.download_byte_limit != metadata.download_byte_limit
                || binding.grant_issued_at_unix_ms < metadata.issued_at_ms
                || binding.grant_expires_at_unix_ms > metadata.expires_at_ms
            {
                bail!("android_egress_journal_predispatch_binding_record_mismatch");
            }
            Ok(Some(binding))
        }
        _ => bail!("android_egress_journal_predispatch_binding_partial_shape_denied"),
    }
}

fn validate_runtime_evidence_against_record(
    record: &EgressJournalRecord,
    runtime_evidence_sha256: &str,
    runtime_evidence: &CodexRuntimeEvidence,
) -> Result<()> {
    validate_digest(runtime_evidence_sha256, "runtime_evidence_sha256")?;
    let expected = validate_predispatch_binding_for_record(record)?
        .context("android_egress_journal_runtime_evidence_without_predispatch_binding")?;
    let expected_domain = agent_principal_registry::from_provider_agent_pair(
        &record.metadata.provider_id,
        &record.metadata.agent_id,
    )
    .ok_or_else(|| anyhow::anyhow!("android_egress_journal_runtime_provider_identity_denied"))?
    .agent_selinux_domain;
    if record.metadata.agent_selinux_domain_sha256 != sha256_bytes(expected_domain.as_bytes())
        || !runtime_evidence.production_egress_teardown_proven_for(
            &record.metadata.provider_id,
            &record.metadata.agent_id,
            expected_domain,
        )
        || sha256_json(&serde_json::to_value(runtime_evidence)?) != runtime_evidence_sha256
        || runtime_evidence.lifecycle_binding.as_ref() != Some(expected)
        || runtime_evidence.lifecycle_binding_sha256.as_deref()
            != record.predispatch_binding_sha256.as_deref()
    {
        bail!("android_egress_journal_runtime_evidence_record_binding_denied");
    }
    // `production_egress_teardown_proven_for` independently recomputes all three
    // component digests and requires child/broker/session cleanup to carry the
    // same lifecycle, invocation and provider-session identifiers. Recompute
    // once more at this custody boundary so top-level self-consistency cannot
    // substitute components from another grant.
    let expected_child_sha256 = runtime_evidence
        .child
        .as_ref()
        .map(|child| {
            runtime_evidence_component_sha256(child)
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        })
        .transpose()?;
    let broker = runtime_evidence
        .egress
        .as_ref()
        .context("android_egress_journal_broker_evidence_missing")?;
    let session = runtime_evidence
        .provider_session_cleanup
        .as_ref()
        .context("android_egress_journal_provider_session_evidence_missing")?;
    if runtime_evidence.child_cleanup_sha256.as_deref() != expected_child_sha256.as_deref()
        || runtime_evidence.broker_outcome_sha256.as_deref()
            != Some(
                runtime_evidence_component_sha256(broker)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?
                    .as_str(),
            )
        || runtime_evidence.provider_session_cleanup_sha256.as_deref()
            != Some(
                runtime_evidence_component_sha256(session)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?
                    .as_str(),
            )
    {
        bail!("android_egress_journal_runtime_component_digest_mismatch");
    }
    Ok(())
}

fn runtime_component_hashes(evidence: &CodexRuntimeEvidence) -> Result<(String, String, String)> {
    let child = evidence
        .child_cleanup_sha256
        .clone()
        .unwrap_or_else(|| sha256_bytes(b"trillionnium.provider-runtime.no-child-started.v1"));
    let broker = evidence
        .broker_outcome_sha256
        .clone()
        .context("android_egress_journal_broker_component_digest_missing")?;
    let session = evidence
        .provider_session_cleanup_sha256
        .clone()
        .context("android_egress_journal_session_component_digest_missing")?;
    Ok((child, broker, session))
}

fn validate_teardown_ack_against_record(
    record: &EgressJournalRecord,
    ack: &EgressTeardownAck,
) -> Result<()> {
    let evidence = record
        .runtime_evidence
        .as_ref()
        .context("android_egress_journal_teardown_without_runtime_evidence")?;
    let evidence_sha256 = record
        .runtime_evidence_sha256
        .as_deref()
        .context("android_egress_journal_teardown_runtime_digest_missing")?;
    validate_runtime_evidence_against_record(record, evidence_sha256, evidence)?;
    let (child, broker, session) = runtime_component_hashes(evidence)?;
    let teardown_nonce_sha256 = sha256_bytes(ack.teardown_nonce.as_bytes());
    if ack.grant_id != record.metadata.grant_id
        || ack.journal_binding_sha256 != record.binding_sha256
        || ack.provider_id != record.metadata.provider_id
        || ack.runtime_evidence_sha256 != evidence_sha256
        || ack.child_cleanup_sha256 != child
        || ack.broker_outcome_sha256 != broker
        || ack.provider_session_cleanup_sha256 != session
        || record.teardown_nonce_sha256.as_deref() != Some(teardown_nonce_sha256.as_str())
    {
        bail!("android_egress_journal_teardown_ack_binding_mismatch");
    }
    let broker_evidence = evidence
        .egress
        .as_ref()
        .context("android_egress_journal_teardown_broker_evidence_missing")?;
    let session_evidence = evidence
        .provider_session_cleanup
        .as_ref()
        .context("android_egress_journal_teardown_session_evidence_missing")?;
    let reason_matches = match ack.termination_reason.as_str() {
        "completed" => {
            broker_evidence.evidence.termination_reason
                == EgressBrokerTerminationReason::InvocationCompleted
        }
        "caller" => {
            broker_evidence.evidence.termination_reason
                == EgressBrokerTerminationReason::CallerStopped
        }
        "cancelled" => {
            broker_evidence.evidence.termination_reason
                == EgressBrokerTerminationReason::ProviderCancelled
        }
        "timed_out" => {
            broker_evidence.evidence.termination_reason
                == EgressBrokerTerminationReason::ProviderTimedOut
        }
        "failed" => !matches!(
            broker_evidence.evidence.termination_reason,
            EgressBrokerTerminationReason::InvocationCompleted
                | EgressBrokerTerminationReason::CallerStopped
                | EgressBrokerTerminationReason::ProviderCancelled
                | EgressBrokerTerminationReason::ProviderTimedOut
        ),
        _ => false,
    };
    if !reason_matches
        || ack.acknowledged_at_ms < broker_evidence.evidence.ended_at_unix_ms
        || ack.acknowledged_at_ms < session_evidence.cleanup_completed_at_unix_ms
    {
        bail!("android_egress_journal_teardown_ack_reason_or_time_mismatch");
    }
    Ok(())
}

fn validate_file(file: &EgressJournalFile, now: u64) -> Result<()> {
    if file.schema != JOURNAL_SCHEMA {
        bail!("unsupported_android_egress_journal_schema");
    }
    validate_compaction_checkpoint(&file.compaction, now)?;
    if file.records.len() > MAX_RECORDS {
        bail!("android_egress_journal_record_limit_exceeded");
    }
    let mut grant_ids = HashSet::with_capacity(file.records.len());
    for record in &file.records {
        if !matches!(record.record_version, 1..=4)
            || !grant_ids.insert(record.metadata.grant_id.clone())
        {
            bail!("android_egress_journal_record_identity_denied");
        }
        if record.record_version >= 3 {
            validate_metadata(&record.metadata, now)?;
            recovery_reference(record)?;
        } else {
            validate_metadata_common(&record.metadata, now)?;
            if record.record_version == 2 {
                recovery_reference(record)?;
            }
            if (record.record_version == 1
                && (!record.recovery_envelope_file.is_empty()
                    || !record.recovery_envelope_sha256.is_empty()
                    || record.runtime_evidence_sha256.is_some()
                    || record.runtime_evidence.is_some()))
                || !matches!(
                    record.state,
                    EgressLifecycleState::Completed
                        | EgressLifecycleState::Revoked
                        | EgressLifecycleState::RevokedBeforeDispatch
                        | EgressLifecycleState::Expired
                        | EgressLifecycleState::InterruptedRestart
                        | EgressLifecycleState::IndeterminateRestart
                )
            {
                bail!("android_egress_journal_legacy_record_not_terminal");
            }
        }
        if record.metadata.issued_at_ms <= file.compaction.through_issued_at_ms {
            bail!("android_egress_journal_record_crosses_compacted_epoch");
        }
        if record.binding_sha256 != sha256_json(&serde_json::to_value(&record.metadata)?)
            || record.prepared_at_ms != record.metadata.issued_at_ms
            || record.updated_at_ms < record.prepared_at_ms
            || record.updated_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        {
            bail!("android_egress_journal_record_binding_denied");
        }
        if let Some(receipt_id) = &record.consent_receipt_id {
            validate_digest(receipt_id, "consent_receipt_id")?;
        }
        if let Some(digest) = &record.teardown_nonce_sha256 {
            validate_digest(digest, "teardown_nonce_sha256")?;
        }
        if let Some(digest) = &record.last_transition_from_sha256 {
            validate_digest(digest, "last_transition_from_sha256")?;
        }
        if let Some(digest) = &record.completion_ack_sha256 {
            validate_digest(digest, "completion_ack_sha256")?;
        }
        if let Some(digest) = &record.runtime_evidence_sha256 {
            validate_digest(digest, "runtime_evidence_sha256")?;
        }
        match (&record.runtime_evidence, &record.runtime_evidence_sha256) {
            (None, None) => {}
            (Some(evidence), Some(digest)) => {
                if record.record_version >= 3 {
                    validate_runtime_evidence_against_record(record, digest, evidence)?;
                } else {
                    let expected_domain = agent_principal_registry::from_provider_agent_pair(
                        &record.metadata.provider_id,
                        &record.metadata.agent_id,
                    )
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "android_egress_journal_legacy_runtime_provider_identity_denied"
                        )
                    })?
                    .agent_selinux_domain;
                    if record.metadata.agent_selinux_domain_sha256
                        != sha256_bytes(expected_domain.as_bytes())
                        || !evidence.production_egress_teardown_proven_for(
                            &record.metadata.provider_id,
                            &record.metadata.agent_id,
                            expected_domain,
                        )
                        || sha256_json(&serde_json::to_value(evidence)?) != *digest
                    {
                        bail!("android_egress_journal_legacy_runtime_evidence_shape_mismatch");
                    }
                }
            }
            _ => bail!("android_egress_journal_runtime_evidence_shape_mismatch"),
        }
        if record.record_version >= 3 {
            validate_predispatch_binding_for_record(record)?;
        }
        match (&record.direct_provider_attempt, record.record_version) {
            (None, _) => {}
            (Some(_), 1..=3) => {
                bail!("android_egress_journal_legacy_direct_attempt_denied")
            }
            (Some(attempt), 4) => {
                if attempt.schema != DIRECT_PROVIDER_ATTEMPT_SCHEMA
                    || attempt.provider_id != record.metadata.provider_id
                    || attempt.agent_id != record.metadata.agent_id
                    || attempt.attempt_generation != 1
                    || record.predispatch_binding_sha256.as_deref()
                        != Some(attempt.runtime_lifecycle_binding_sha256.as_str())
                    || record.predispatch_task_id_sha256.as_deref()
                        != Some(attempt.task_id_sha256.as_str())
                    || record.predispatch_binding.as_ref().is_none_or(|binding| {
                        binding.provider_id != attempt.provider_id
                            || binding.agent_id != attempt.agent_id
                    })
                    || record.consumed_at_ms.is_none()
                    || record.consent_receipt_id.is_none()
                    || record.teardown_nonce_sha256.is_none()
                {
                    bail!("android_egress_journal_direct_attempt_shape_denied");
                }
                validate_digest(&attempt.task_id_sha256, "direct_attempt_task_id_sha256")?;
                validate_digest(
                    &attempt.runtime_lifecycle_binding_sha256,
                    "direct_attempt_runtime_lifecycle_binding_sha256",
                )?;
                validate_digest(
                    &attempt.allocation_predecessor_record_sha256,
                    "direct_attempt_allocation_predecessor_record_sha256",
                )?;
            }
            (Some(_), _) => bail!("android_egress_journal_direct_attempt_version_denied"),
        }
        if let Some(event) = &record.revoke_event {
            validate_revoke_event(event, now)?;
        }
        for (field, digest) in [
            (
                "prepare_ui_completion_ack_sha256",
                record.prepare_ui_completion_ack_sha256.as_deref(),
            ),
            (
                "revoke_ui_completion_ack_sha256",
                record.revoke_ui_completion_ack_sha256.as_deref(),
            ),
            (
                "prepare_ui_completion_proof_sha256",
                record.prepare_ui_completion_proof_sha256.as_deref(),
            ),
            (
                "revoke_ui_completion_proof_sha256",
                record.revoke_ui_completion_proof_sha256.as_deref(),
            ),
        ] {
            if let Some(digest) = digest {
                validate_digest(digest, field)?;
            }
        }
        for (ack, proof) in [
            (
                record.prepare_ui_completion_ack_sha256.as_deref(),
                record.prepare_ui_completion_proof_sha256.as_deref(),
            ),
            (
                record.revoke_ui_completion_ack_sha256.as_deref(),
                record.revoke_ui_completion_proof_sha256.as_deref(),
            ),
        ] {
            if ack.is_some() != proof.is_some() {
                bail!("android_egress_journal_ui_completion_ack_proof_shape_mismatch");
            }
        }
        if record.record_version < 3
            && (record.prepare_ui_completion_ack_sha256.is_some()
                || record.prepare_ui_completion_proof_sha256.is_some()
                || record.revoke_ui_completion_ack_sha256.is_some()
                || record.revoke_ui_completion_proof_sha256.is_some())
        {
            bail!("android_egress_journal_legacy_ui_completion_ack_denied");
        }
        if (record.revoke_ui_completion_ack_sha256.is_some()
            || record.revoke_ui_completion_proof_sha256.is_some())
            && record.revoke_event.is_none()
        {
            bail!("android_egress_journal_revoke_ui_completion_without_event");
        }
        if record.record_version >= 3 && record.invalidated_restart_at_ms.is_some() {
            bail!("android_egress_journal_legacy_restart_marker_denied");
        }
        let timestamps_match = match record.state {
            EgressLifecycleState::Prepared => {
                record.consumed_at_ms.is_none()
                    && record.completed_at_ms.is_none()
                    && record.revoked_at_ms.is_none()
                    && record.expired_at_ms.is_none()
                    && record.invalidated_restart_at_ms.is_none()
                    && record.interrupted_restart_at_ms.is_none()
                    && record.indeterminate_restart_at_ms.is_none()
                    && record.consent_receipt_id.is_none()
                    && record.teardown_nonce_sha256.is_none()
                    && record.revoke_event.is_none()
                    && record.completion_ack_sha256.is_none()
                    && record.runtime_evidence_sha256.is_none()
                    && record.runtime_evidence.is_none()
            }
            EgressLifecycleState::Consumed => {
                record.consumed_at_ms.is_some()
                    && record.completed_at_ms.is_none()
                    && record.revoked_at_ms.is_none()
                    && record.expired_at_ms.is_none()
                    && record.invalidated_restart_at_ms.is_none()
                    && record.consent_receipt_id.is_some()
                    && record.teardown_nonce_sha256.is_some()
                    && record.revoke_event.is_none()
                    && record.completion_ack_sha256.is_none()
                    && record.interrupted_restart_at_ms.is_none()
                    && record.indeterminate_restart_at_ms.is_none()
            }
            EgressLifecycleState::RevokePending => {
                record.completed_at_ms.is_none()
                    && record.revoked_at_ms.is_none()
                    && record.expired_at_ms.is_none()
                    && record.interrupted_restart_at_ms.is_none()
                    && record.indeterminate_restart_at_ms.is_none()
                    && record.teardown_nonce_sha256.is_some()
                    && record.revoke_event.as_ref().is_some_and(|event| {
                        event.teardown_ack_sha256.is_none() && event.teardown_ack_at_ms.is_none()
                    })
                    && record.completion_ack_sha256.is_none()
                    && (record.consumed_at_ms.is_some() == record.consent_receipt_id.is_some())
            }
            EgressLifecycleState::Completed => {
                record.consumed_at_ms.is_some()
                    && record.completed_at_ms.is_some()
                    && record.revoked_at_ms.is_none()
                    && record.expired_at_ms.is_none()
                    && record.invalidated_restart_at_ms.is_none()
                    && record.consent_receipt_id.is_some()
                    && record.teardown_nonce_sha256.is_some()
                    && record.revoke_event.is_none()
                    && record.completion_ack_sha256.is_some()
                    && (record.record_version == 1
                        || (record.runtime_evidence_sha256.is_some()
                            && record.runtime_evidence.is_some()))
                    && record.interrupted_restart_at_ms.is_none()
                    && record.indeterminate_restart_at_ms.is_none()
            }
            EgressLifecycleState::Revoked => {
                record.completed_at_ms.is_none()
                    && record.revoked_at_ms.is_some()
                    && record.expired_at_ms.is_none()
                    && record.invalidated_restart_at_ms.is_none()
                    && record.interrupted_restart_at_ms.is_none()
                    && record.indeterminate_restart_at_ms.is_none()
                    && record.teardown_nonce_sha256.is_some()
                    && record.revoke_event.as_ref().is_some_and(|event| {
                        event.teardown_ack_sha256.is_some() && event.teardown_ack_at_ms.is_some()
                    })
                    && record.completion_ack_sha256.is_none()
                    && (record.record_version == 1
                        || (record.runtime_evidence_sha256.is_some()
                            && record.runtime_evidence.is_some()))
                    && (record.consumed_at_ms.is_some() == record.consent_receipt_id.is_some())
            }
            EgressLifecycleState::RevokedBeforeDispatch => {
                record.consumed_at_ms.is_none()
                    && record.completed_at_ms.is_none()
                    && record.revoked_at_ms.is_some()
                    && record.expired_at_ms.is_none()
                    && record.invalidated_restart_at_ms.is_none()
                    && record.interrupted_restart_at_ms.is_none()
                    && record.indeterminate_restart_at_ms.is_none()
                    && record.consent_receipt_id.is_none()
                    && record.teardown_nonce_sha256.is_none()
                    && record.revoke_event.as_ref().is_some_and(|event| {
                        event.teardown_ack_sha256.is_none() && event.teardown_ack_at_ms.is_none()
                    })
                    && record.completion_ack_sha256.is_none()
                    && record.runtime_evidence_sha256.is_none()
                    && record.runtime_evidence.is_none()
            }
            EgressLifecycleState::Expired => {
                record.consumed_at_ms.is_none()
                    && record.completed_at_ms.is_none()
                    && record.revoked_at_ms.is_none()
                    && record.expired_at_ms.is_some()
                    && record.invalidated_restart_at_ms.is_none()
                    && record.interrupted_restart_at_ms.is_none()
                    && record.indeterminate_restart_at_ms.is_none()
                    && record.consent_receipt_id.is_none()
                    && record.teardown_nonce_sha256.is_none()
                    && (record.revoke_event.is_none()
                        || (record.revoke_ui_outcome == Some(EgressRevokeUiOutcome::GrantExpired)
                            && record.revoke_event.as_ref().is_some_and(|event| {
                                event.teardown_ack_sha256.is_none()
                                    && event.teardown_ack_at_ms.is_none()
                            })))
                    && record.completion_ack_sha256.is_none()
                    && record.runtime_evidence_sha256.is_none()
                    && record.runtime_evidence.is_none()
            }
            EgressLifecycleState::InterruptedRestart => {
                record.completed_at_ms.is_none()
                    && record.revoked_at_ms.is_none()
                    && record.expired_at_ms.is_none()
                    && record.interrupted_restart_at_ms.is_some()
                    && record.indeterminate_restart_at_ms.is_none()
                    && record.consumed_at_ms.is_some()
                    && record.consent_receipt_id.is_some()
                    && record.teardown_nonce_sha256.is_some()
                    && record.revoke_event.is_none()
                    && record.completion_ack_sha256.is_none()
            }
            EgressLifecycleState::IndeterminateRestart => {
                record.completed_at_ms.is_none()
                    && record.revoked_at_ms.is_none()
                    && record.expired_at_ms.is_none()
                    && record.indeterminate_restart_at_ms.is_some()
                    && record.interrupted_restart_at_ms.is_none()
                    && (record.consumed_at_ms.is_some() == record.consent_receipt_id.is_some())
                    && record.completion_ack_sha256.is_none()
            }
            EgressLifecycleState::LegacyInvalidatedRestart => false,
        };
        let revoke_outcome_shape_matches = match record.revoke_ui_outcome {
            None => {
                record.record_version < 3
                    || !(matches!(
                        record.state,
                        EgressLifecycleState::RevokedBeforeDispatch | EgressLifecycleState::Revoked
                    ) || (record.state == EgressLifecycleState::Expired
                        && record.revoke_event.is_some()))
            }
            Some(EgressRevokeUiOutcome::RevokedBeforeDispatch) => {
                record.state == EgressLifecycleState::RevokedBeforeDispatch
            }
            Some(EgressRevokeUiOutcome::RevokePending) => matches!(
                record.state,
                EgressLifecycleState::RevokePending
                    | EgressLifecycleState::Revoked
                    | EgressLifecycleState::IndeterminateRestart
            ),
            Some(EgressRevokeUiOutcome::Revoked) => record.state == EgressLifecycleState::Revoked,
            Some(EgressRevokeUiOutcome::GrantExpired) => {
                record.state == EgressLifecycleState::Expired
            }
        };
        let transition_shape_matches = if record.record_version < 3 {
            true
        } else if record.state == EgressLifecycleState::Prepared {
            // A newly prepared record has no predecessor. The only legal
            // same-state mutation is the durable outer UI-completion pin, and
            // that CAS must retain its predecessor hash.
            record.last_transition_from_sha256.is_some()
                == record.prepare_ui_completion_ack_sha256.is_some()
        } else {
            record.last_transition_from_sha256.is_some()
        };
        if !timestamps_match || !transition_shape_matches || !revoke_outcome_shape_matches {
            bail!("android_egress_journal_state_timestamp_mismatch");
        }
        if record.record_version == 1
            && record.state == EgressLifecycleState::IndeterminateRestart
            && record.indeterminate_restart_at_ms.is_none()
        {
            bail!("android_egress_journal_legacy_restart_timestamp_missing");
        }
    }
    Ok(())
}

fn validate_compaction_checkpoint(checkpoint: &EgressCompactionCheckpoint, now: u64) -> Result<()> {
    if checkpoint.schema != COMPACTION_SCHEMA {
        bail!("unsupported_android_egress_journal_compaction_schema");
    }
    validate_digest(
        &checkpoint.terminal_commitment_sha256,
        "terminal_commitment_sha256",
    )?;
    validate_digest(&checkpoint.replay_filter_sha256, "replay_filter_sha256")?;
    let empty = checkpoint.epoch == 0
        && checkpoint.compacted_terminal_records == 0
        && checkpoint.through_issued_at_ms == 0
        && checkpoint.through_updated_at_ms == 0
        && checkpoint.terminal_commitment_sha256 == sha256_bytes(&[])
        && checkpoint.replay_filter_sha256 == sha256_bytes(&[])
        && checkpoint.replay_filter_b64.is_empty();
    if empty {
        return Ok(());
    }
    if checkpoint.epoch == 0
        || checkpoint.compacted_terminal_records < checkpoint.epoch
        || checkpoint.through_issued_at_ms == 0
        || checkpoint.through_updated_at_ms < checkpoint.through_issued_at_ms
        || checkpoint.through_updated_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        || checkpoint.replay_filter_b64.is_empty()
    {
        bail!("android_egress_journal_compaction_boundary_denied");
    }
    let filter = replay_filter_bytes(checkpoint)?;
    if filter.iter().all(|byte| *byte == 0)
        || sha256_bytes(&filter) != checkpoint.replay_filter_sha256
    {
        bail!("android_egress_journal_empty_replay_filter_denied");
    }
    Ok(())
}

fn validate_grant_id(value: &str) -> Result<()> {
    if value.len() != "egress-".len() + 64
        || !value.starts_with("egress-")
        || !value["egress-".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("android_egress_journal_grant_id_denied");
    }
    Ok(())
}

fn validate_digest(value: &str, field: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("android_egress_journal_invalid_digest:{field}");
    }
    Ok(())
}

fn validate_request_id(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        bail!("android_egress_journal_request_id_denied");
    }
    Ok(())
}

fn validate_recovery_reference(reference: &EgressRecoveryBlobRef) -> Result<()> {
    let prefix = "egress-recovery-";
    let suffix = ".enc";
    if reference.file_name.len() != prefix.len() + 64 + suffix.len()
        || !reference.file_name.starts_with(prefix)
        || !reference.file_name.ends_with(suffix)
        || !reference.file_name[prefix.len()..reference.file_name.len() - suffix.len()]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("android_egress_journal_recovery_reference_denied");
    }
    validate_digest(&reference.ciphertext_sha256, "recovery_envelope_sha256")
}

fn recovery_reference(record: &EgressJournalRecord) -> Result<EgressRecoveryBlobRef> {
    let reference = EgressRecoveryBlobRef {
        file_name: record.recovery_envelope_file.clone(),
        ciphertext_sha256: record.recovery_envelope_sha256.clone(),
        publication_durability_uncertain: false,
    };
    validate_recovery_reference(&reference)?;
    Ok(reference)
}

fn record_sha256(record: &EgressJournalRecord) -> Result<String> {
    Ok(sha256_json(&serde_json::to_value(record)?))
}

fn prove_current_persisted_file(journal: &EgressLifecycleJournal) -> Result<()> {
    validate_file(&journal.file, now_unix_ms())?;
    let persisted_sha256 = journal
        .persisted_sha256
        .as_deref()
        .context("android_egress_journal_direct_terminal_persisted_digest_missing")?;
    let persisted_bytes = read_owner_controlled(&journal.path, journal.owner_uid)?
        .context("android_egress_journal_direct_terminal_persisted_file_missing")?;
    let mut canonical = serde_json::to_vec_pretty(&journal.file)?;
    canonical.push(b'\n');
    if persisted_bytes != canonical || sha256_bytes(&persisted_bytes) != persisted_sha256 {
        bail!("android_egress_journal_direct_terminal_persisted_file_changed");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn direct_terminal_egress_digest(
    binding_sha256: &str,
    invocation_id: &str,
    delivery_provider_attempt_id: &str,
    egress_grant_id_sha256: &str,
    egress_journal_binding_sha256: &str,
    final_record_sha256: &str,
    predecessor_record_sha256: &str,
    runtime_evidence_sha256: &str,
    provider_teardown_completion_ack_sha256: &str,
) -> Result<String> {
    #[derive(Serialize)]
    struct DigestPreimage<'a> {
        schema: &'a str,
        binding_sha256: &'a str,
        invocation_id: &'a str,
        delivery_provider_attempt_id: &'a str,
        egress_grant_id_sha256: &'a str,
        egress_journal_binding_sha256: &'a str,
        terminal_state: &'a str,
        final_record_sha256: &'a str,
        predecessor_record_sha256: &'a str,
        runtime_evidence_sha256: &'a str,
        provider_teardown_completion_ack_sha256: &'a str,
    }
    for (field, digest) in [
        ("binding_sha256", binding_sha256),
        ("egress_grant_id_sha256", egress_grant_id_sha256),
        (
            "egress_journal_binding_sha256",
            egress_journal_binding_sha256,
        ),
        ("final_record_sha256", final_record_sha256),
        ("predecessor_record_sha256", predecessor_record_sha256),
        ("runtime_evidence_sha256", runtime_evidence_sha256),
        (
            "provider_teardown_completion_ack_sha256",
            provider_teardown_completion_ack_sha256,
        ),
    ] {
        validate_digest(digest, field)?;
    }
    let encoded = serde_json::to_vec(&DigestPreimage {
        schema: DIRECT_TERMINAL_EGRESS_PROOF_SCHEMA,
        binding_sha256,
        invocation_id,
        delivery_provider_attempt_id,
        egress_grant_id_sha256,
        egress_journal_binding_sha256,
        terminal_state: "completed",
        final_record_sha256,
        predecessor_record_sha256,
        runtime_evidence_sha256,
        provider_teardown_completion_ack_sha256,
    })?;
    let mut hasher = Sha256::new();
    hasher.update((DIRECT_TERMINAL_EGRESS_DIGEST_DOMAIN.len() as u64).to_be_bytes());
    hasher.update(DIRECT_TERMINAL_EGRESS_DIGEST_DOMAIN);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_cas(cas: &EgressJournalCas) -> Result<()> {
    validate_digest(&cas.binding_sha256, "cas_binding_sha256")?;
    validate_digest(&cas.record_sha256, "cas_record_sha256")
}

fn validate_teardown_ack(ack: &EgressTeardownAck) -> Result<()> {
    validate_grant_id(&ack.grant_id)?;
    validate_digest(&ack.journal_binding_sha256, "teardown_ack_binding_sha256")?;
    for (field, digest) in [
        ("child_cleanup_sha256", ack.child_cleanup_sha256.as_str()),
        (
            "provider_session_cleanup_sha256",
            ack.provider_session_cleanup_sha256.as_str(),
        ),
        ("broker_outcome_sha256", ack.broker_outcome_sha256.as_str()),
        (
            "runtime_evidence_sha256",
            ack.runtime_evidence_sha256.as_str(),
        ),
    ] {
        validate_digest(digest, field)?;
    }
    if ack.proof_schema != "trillionnium.egress-teardown-proof.v2"
        || ack.provider_id.is_empty()
        || ack.provider_id.len() > 64
        || ack.teardown_nonce.len() != 64
        || !ack
            .teardown_nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || ack.acknowledged_at_ms == 0
        || !matches!(
            ack.termination_reason.as_str(),
            "completed" | "cancelled" | "timed_out" | "failed" | "caller" | "owner"
        )
    {
        bail!("android_egress_journal_teardown_ack_boundary_denied");
    }
    Ok(())
}

fn validate_revoke_event(event: &EgressRevokeEvent, now: u64) -> Result<()> {
    if event.schema != "trillionnium.android-egress-revoke-event.v1" {
        bail!("android_egress_journal_revoke_event_schema_denied");
    }
    validate_request_id(&event.request_id)?;
    validate_digest(
        &event.request_payload_sha256,
        "revoke_request_payload_sha256",
    )?;
    if event.requested_at_ms == 0 || event.requested_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS) {
        bail!("android_egress_journal_revoke_event_time_denied");
    }
    match (&event.teardown_ack_sha256, event.teardown_ack_at_ms) {
        (None, None) => {}
        (Some(digest), Some(at)) => {
            validate_digest(digest, "teardown_ack_sha256")?;
            if at < event.requested_at_ms || at > now.saturating_add(MAX_CLOCK_SKEW_MS) {
                bail!("android_egress_journal_teardown_ack_time_denied");
            }
        }
        _ => bail!("android_egress_journal_teardown_ack_shape_denied"),
    }
    Ok(())
}

fn ensure_private_parent(path: &Path, owner_uid: u32) -> Result<()> {
    if !path.is_absolute() {
        bail!("android_egress_journal_parent_not_absolute");
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::Normal(_) => {
                current.push(component.as_os_str());
            }
            _ => bail!("android_egress_journal_parent_component_denied"),
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .context("failed_to_create_android_egress_journal_parent")?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
                fs::symlink_metadata(&current)?
            }
            Err(error) => {
                return Err(error).context("android_egress_journal_path_component_unavailable");
            }
        };
        validate_trusted_journal_ancestor(&current, &metadata, owner_uid)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        bail!("android_egress_journal_parent_not_owner_private");
    }
    Ok(())
}

fn validate_trusted_journal_ancestor(
    path: &Path,
    metadata: &std::fs::Metadata,
    owner_uid: u32,
) -> Result<()> {
    let mode = metadata.mode() & 0o7777;
    let trusted_owner = metadata.uid() == 0 || metadata.uid() == owner_uid;
    let sticky_system_root = metadata.uid() == 0
        && mode & libc::S_ISVTX != 0
        && matches!(path.to_str(), Some("/tmp" | "/var/tmp" | "/dev/shm"));
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.nlink() == 0
        || !trusted_owner
        || (mode & 0o022 != 0 && !sticky_system_root)
    {
        bail!("android_egress_journal_unsafe_ancestor: {}", path.display());
    }
    Ok(())
}

fn validate_destination(path: &Path, owner_uid: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != owner_uid
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.nlink() != 1 =>
        {
            bail!("android_egress_journal_destination_not_owner_private")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn cleanup_owned_journal_temps(parent: &Path, owner_uid: u32) -> Result<usize> {
    const PREFIX: &str = ".android-egress-journal.tmp-";
    let mut removed = 0usize;
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let file_name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("android_egress_journal_temp_name_not_utf8"))?;
        if !file_name.starts_with(PREFIX) {
            continue;
        }
        let components = file_name[PREFIX.len()..].split('-').collect::<Vec<_>>();
        if components.len() != 3
            || components.iter().any(|component| {
                component.is_empty()
                    || component.len() > 20
                    || !component.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            bail!("android_egress_journal_unknown_temp_lookalike_denied");
        }
        let path = parent.join(&file_name);
        let input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .context("failed_to_open_android_egress_journal_temp")?;
        validate_open_file(&input, owner_uid, MAX_JOURNAL_BYTES)?;
        let opened = input.metadata()?;
        let current = fs::symlink_metadata(&path)?;
        if current.file_type().is_symlink()
            || current.dev() != opened.dev()
            || current.ino() != opened.ino()
            || current.nlink() != 1
        {
            bail!("android_egress_journal_temp_changed_before_cleanup");
        }
        fs::remove_file(&path).context("failed_to_remove_android_egress_journal_temp")?;
        removed = removed.saturating_add(1);
    }
    if removed > 0 {
        File::open(parent)?.sync_all()?;
    }
    Ok(removed)
}

fn read_owner_controlled(path: &Path, owner_uid: u32) -> Result<Option<Vec<u8>>> {
    let input = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(input) => input,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed_to_open_android_egress_journal"),
    };
    validate_open_file(&input, owner_uid, MAX_JOURNAL_BYTES)?;
    let mut bytes = Vec::new();
    input
        .take(MAX_JOURNAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        bail!("android_egress_journal_file_too_large");
    }
    Ok(Some(bytes))
}

fn validate_open_file(file: &File, owner_uid: u32, max_bytes: usize) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > max_bytes as u64
    {
        bail!("android_egress_journal_file_not_owner_private");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        EgressJournalCas, EgressJournalMetadata, EgressLifecycleJournal, EgressLifecycleState,
        EgressTeardownAck, EgressUiCompletionBinding, now_unix_ms,
    };
    use crate::context_memory::EgressRecoveryBlobRef;
    use crate::direct_operation_binding_inbox::{
        DurableProviderAttemptQuery, DurableProviderAttemptSource, daemon_attempt_context_sha256,
    };
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationBinding, DirectOperationProviderAttempt,
        DirectOperationStableSeed, STABLE_SEED_SCHEMA,
    };
    use trillionnium_os_types::{sha256_bytes, sha256_json};
    use trillionnium_tool_runtime::supervised_codex::{
        ChildContainmentEvidence, ChildContainmentProofScope, CodexRuntimeEvidence,
        DIRECT_EXECUTION_PROMPT_CONTRACT, DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION,
        EgressBrokerEvidence, EgressBrokerOutcome, EgressBrokerTerminationReason,
        ProviderSessionCleanupEvidence, RuntimeLifecycleBinding, runtime_evidence_component_sha256,
    };

    fn fixture(_path: &std::path::Path, suffix: char) -> EgressJournalMetadata {
        let now = now_unix_ms();
        EgressJournalMetadata {
            grant_id: format!("egress-{}", suffix.to_string().repeat(64)),
            provider_id: "openai-codex".to_string(),
            workflow_id_sha256: sha256_bytes(b"private-workflow"),
            policy_epoch: super::CURRENT_EGRESS_POLICY_EPOCH,
            provider_abi_epoch: super::CURRENT_PROVIDER_ABI_EPOCH,
            prepare_request_id_sha256: sha256_bytes(b"prepare-request"),
            prepare_request_payload_sha256: sha256_bytes(b"prepare-payload"),
            peer_uid: 10_123,
            peer_selinux_domain_sha256: sha256_bytes(b"u:r:trillionnium_aishell:s0"),
            subject_user_id: 0,
            boot_id_sha256: sha256_bytes(b"boot-id"),
            agent_id: "agent-codex-direct-v1".to_string(),
            agent_peer_uid: 5_901,
            agent_peer_gid: 5_901,
            agent_selinux_domain_sha256: sha256_bytes(b"u:r:trillionnium_codex_agent:s0"),
            agent_executable_sha256: sha256_bytes(b"codex-executable"),
            agent_manifest_sha256: sha256_bytes(b"codex-manifest"),
            context_id_sha256: sha256_bytes(b"context-private"),
            context_kind: "file".to_string(),
            context_captured_at_ms: now.saturating_sub(1),
            context_expires_at_ms: now + 120_000,
            context_sha256: sha256_bytes(b"raw secret context"),
            source_id_sha256: sha256_bytes(b"raw secret source"),
            privacy_class: "local_private".to_string(),
            content_bytes: 18,
            intent_sha256: sha256_bytes(b"raw secret intent"),
            intent_bytes: 17,
            allowed_actions_sha256: sha256_json(&serde_json::json!([])),
            prompt_contract: DIRECT_EXECUTION_PROMPT_CONTRACT.to_string(),
            prompt_contract_version: DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION,
            endpoint: "chatgpt.com:443".to_string(),
            upload_byte_limit: 262_144,
            download_byte_limit: 4 * 1024 * 1024,
            consent_challenge_sha256: sha256_bytes(b"challenge"),
            issued_at_ms: now,
            expires_at_ms: now + 120_000,
        }
    }

    fn private_temp() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        temp
    }

    fn recovery(grant_id: &str) -> EgressRecoveryBlobRef {
        EgressRecoveryBlobRef {
            file_name: format!("egress-recovery-{}.enc", sha256_bytes(grant_id.as_bytes())),
            ciphertext_sha256: sha256_bytes(format!("ciphertext:{grant_id}").as_bytes()),
            publication_durability_uncertain: false,
        }
    }

    fn prepare(
        journal: &mut EgressLifecycleJournal,
        metadata: EgressJournalMetadata,
    ) -> EgressJournalCas {
        let reference = recovery(&metadata.grant_id);
        let grant_id = metadata.grant_id.clone();
        journal.record_prepared(metadata, &reference).unwrap();
        journal
            .mark_ui_request_completed_exact(
                &grant_id,
                EgressUiCompletionBinding {
                    method: "prepare_egress",
                    request_id: "prepare-request",
                    request_payload_sha256: &sha256_bytes(b"prepare-payload"),
                    completion_proof_sha256: &sha256_bytes(b"prepare-ui-completion-proof"),
                    peer_uid: 10_123,
                    peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                    completed_at_ms: now_unix_ms(),
                },
            )
            .unwrap()
    }

    fn teardown_nonce() -> String {
        "1".repeat(64)
    }

    fn runtime_binding(
        journal: &EgressLifecycleJournal,
        grant_id: &str,
        journal_binding_sha256: &str,
    ) -> RuntimeLifecycleBinding {
        let metadata = &journal.record(grant_id).unwrap().metadata;
        RuntimeLifecycleBinding {
            provider_id: metadata.provider_id.clone(),
            agent_id: metadata.agent_id.clone(),
            agent_peer_uid: metadata.agent_peer_uid,
            agent_peer_gid: metadata.agent_peer_gid,
            agent_selinux_domain_sha256: metadata.agent_selinux_domain_sha256.clone(),
            agent_executable_sha256: metadata.agent_executable_sha256.clone(),
            final_runtime_executable_sha256: "f".repeat(64),
            agent_manifest_sha256: metadata.agent_manifest_sha256.clone(),
            provider_invocation_id_sha256: sha256_bytes(b"plan-request"),
            provider_session_id_sha256: sha256_bytes(b"provider-session"),
            egress_grant_id: grant_id.to_string(),
            journal_binding_sha256: journal_binding_sha256.to_string(),
            capability_token_sha256: sha256_bytes(b"signed-capability-token"),
            teardown_nonce_sha256: sha256_bytes(teardown_nonce().as_bytes()),
            proxy_instance_credential_sha256: sha256_bytes(b"proxy-instance-credential"),
            approved_endpoint: metadata.endpoint.clone(),
            upload_byte_limit: metadata.upload_byte_limit,
            download_byte_limit: metadata.download_byte_limit,
            grant_issued_at_unix_ms: metadata.issued_at_ms,
            grant_expires_at_unix_ms: metadata.expires_at_ms,
        }
    }

    fn runtime_evidence(binding: &RuntimeLifecycleBinding) -> CodexRuntimeEvidence {
        let binding_sha256 = binding.digest_sha256().unwrap();
        let child = ChildContainmentEvidence {
            lifecycle_binding_sha256: binding_sha256.clone(),
            provider_invocation_id_sha256: binding.provider_invocation_id_sha256.clone(),
            provider_session_id_sha256: binding.provider_session_id_sha256.clone(),
            child_pid: 42,
            session_id: 42,
            proof_scope: ChildContainmentProofScope::ProductionDedicatedUid,
            observed_process_count: 1,
            process_group_empty: true,
            observed_tree_empty: true,
            dedicated_uid: Some(5_901),
            dedicated_uid_preflight_empty: Some(true),
            dedicated_uid_empty: Some(true),
            executable_sha256: binding.agent_executable_sha256.clone(),
            executable_device: 1,
            executable_inode: 1,
            exact_executable_fd_verified: true,
            executable_source_read_only_mount_verified: true,
            executable_elf_image_verified: true,
            root_pidfd_custody_verified: true,
            pidfd_signalling_verified: true,
            pdeathsig_pre_exec_verified: true,
            no_new_privs_pre_exec_verified: true,
            independent_session_pre_exec_verified: true,
            rlimit_core_zero_pre_exec_verified: true,
            dumpable_zero_pre_exec_verified: true,
            inherited_fd_cloexec_pre_exec_verified: true,
            // Synthetic complete-production fixture: real local-supervisor
            // evidence remains false until an OS-owned post-exec zero probe is
            // implemented.
            post_exec_dumpable_verified: true,
            post_exec_selinux_domain: None,
            post_exec_uid: None,
            post_exec_gid: None,
            post_exec_uid_gid_verified: false,
            post_exec_supplementary_groups_empty_verified: false,
            post_exec_no_new_privs_verified: false,
            post_exec_capabilities_empty_verified: false,
            post_exec_executable_identity_verified: true,
            post_exec_final_runtime_executable_sha256: Some(
                binding.final_runtime_executable_sha256.clone(),
            ),
            post_exec_final_runtime_device: 2,
            post_exec_final_runtime_inode: 3,
            post_exec_final_runtime_source_read_only_mount_verified: true,
            post_exec_final_runtime_elf_image_verified: true,
            post_exec_independent_session_verified: false,
            post_exec_parent_identity_verified: false,
            cleanup_errors: Vec::new(),
        };
        let broker = EgressBrokerOutcome {
            lifecycle_binding_sha256: binding_sha256.clone(),
            provider_invocation_id_sha256: binding.provider_invocation_id_sha256.clone(),
            provider_session_id_sha256: binding.provider_session_id_sha256.clone(),
            proxy_instance_credential_sha256: binding.proxy_instance_credential_sha256.clone(),
            evidence: EgressBrokerEvidence {
                approved_authority: "chatgpt.com:443".to_string(),
                validated_sni: Some("chatgpt.com".to_string()),
                resolved_candidate_ips: vec!["1.1.1.1".to_string()],
                chosen_ip: Some("1.1.1.1".to_string()),
                actual_upload_bytes: 128,
                actual_download_bytes: 256,
                started_at_unix_ms: binding.grant_issued_at_unix_ms + 1,
                ended_at_unix_ms: binding.grant_issued_at_unix_ms + 2,
                termination_reason: EgressBrokerTerminationReason::InvocationCompleted,
                tls_claim_scope: "connect_authority_sni_dns_bytes_ttl_only".to_string(),
            },
            error: None,
        };
        let session = ProviderSessionCleanupEvidence {
            provider_id: binding.provider_id.clone(),
            lifecycle_binding_sha256: binding_sha256.clone(),
            provider_invocation_id_sha256: binding.provider_invocation_id_sha256.clone(),
            provider_session_id_sha256: binding.provider_session_id_sha256.clone(),
            session_artifact_sha256: sha256_bytes(b"fixture-session-artifact"),
            cleanup_attempted: true,
            ownership_restored: true,
            cleanup_complete: true,
            cleanup_started_at_unix_ms: binding.grant_issued_at_unix_ms + 1,
            cleanup_completed_at_unix_ms: binding.grant_issued_at_unix_ms + 2,
            cleanup_errors: Vec::new(),
        };
        let child_sha256 = super::runtime_evidence_component_sha256(&child).unwrap();
        let broker_sha256 = super::runtime_evidence_component_sha256(&broker).unwrap();
        let session_sha256 = super::runtime_evidence_component_sha256(&session).unwrap();
        let evidence = CodexRuntimeEvidence {
            child_started: true,
            broker_started: true,
            provider_session_started: true,
            child: Some(child),
            child_cleanup_sha256: Some(child_sha256),
            egress: Some(broker),
            broker_outcome_sha256: Some(broker_sha256),
            provider_session_cleanup: Some(session),
            provider_session_cleanup_sha256: Some(session_sha256),
            lifecycle_binding: Some(binding.clone()),
            lifecycle_binding_sha256: Some(binding_sha256),
        };
        assert!(
            binding.shape_proven(),
            "fixture lifecycle binding is invalid"
        );
        assert!(
            evidence.containment_proven(),
            "fixture runtime containment is invalid: {evidence:?}"
        );
        assert!(
            evidence.production_egress_teardown_proven_for(
                super::CODEX_CAPABILITY_PROVIDER_ID,
                super::CODEX_DIRECT_CAPABILITY_AGENT_ID,
                super::CODEX_CAPABILITY_AGENT_SELINUX_DOMAIN,
            ),
            "fixture production teardown is invalid: {evidence:?}"
        );
        evidence
    }

    fn consume(
        journal: &mut EgressLifecycleJournal,
        grant_id: &str,
        prepared: &EgressJournalCas,
        receipt_id: &str,
        now: u64,
    ) -> EgressJournalCas {
        let consumed = journal
            .mark_consumed(
                grant_id,
                prepared,
                receipt_id,
                &sha256_bytes(teardown_nonce().as_bytes()),
                now,
            )
            .unwrap();
        let binding = runtime_binding(journal, grant_id, &consumed.binding_sha256);
        let frozen = journal
            .freeze_predispatch_binding(
                grant_id,
                &consumed,
                &binding,
                "fixture-task",
                "plan-request",
                "provider-session",
                now,
            )
            .unwrap();
        let evidence = runtime_evidence(&binding);
        journal
            .mark_runtime_evidence(
                grant_id,
                &frozen,
                &sha256_json(&serde_json::to_value(&evidence).unwrap()),
                &evidence,
                now,
            )
            .unwrap()
    }

    fn consume_and_freeze(
        journal: &mut EgressLifecycleJournal,
        metadata: EgressJournalMetadata,
        task_id: &str,
    ) -> (String, RuntimeLifecycleBinding, EgressJournalCas) {
        let now = now_unix_ms();
        let grant_id = metadata.grant_id.clone();
        let prepared = prepare(journal, metadata);
        let consumed = journal
            .mark_consumed(
                &grant_id,
                &prepared,
                &sha256_bytes(format!("receipt:{grant_id}").as_bytes()),
                &sha256_bytes(teardown_nonce().as_bytes()),
                now,
            )
            .unwrap();
        let binding = runtime_binding(journal, &grant_id, &consumed.binding_sha256);
        let frozen = journal
            .freeze_predispatch_binding(
                &grant_id,
                &consumed,
                &binding,
                task_id,
                "plan-request",
                "provider-session",
                now,
            )
            .unwrap();
        (grant_id, binding, frozen)
    }

    fn teardown_ack(
        journal: &EgressLifecycleJournal,
        grant_id: &str,
        cas: &EgressJournalCas,
        termination_reason: &str,
        now: u64,
    ) -> EgressTeardownAck {
        let record = journal.record(grant_id).unwrap();
        let evidence = record.runtime_evidence.as_ref().unwrap();
        let broker = evidence.egress.as_ref().unwrap();
        let session = evidence.provider_session_cleanup.as_ref().unwrap();
        EgressTeardownAck {
            proof_schema: "trillionnium.egress-teardown-proof.v2".to_string(),
            grant_id: grant_id.to_string(),
            journal_binding_sha256: cas.binding_sha256.clone(),
            provider_id: "openai-codex".to_string(),
            teardown_nonce: teardown_nonce(),
            child_cleanup_sha256: evidence.child_cleanup_sha256.clone().unwrap_or_else(|| {
                sha256_bytes(b"trillionnium.provider-runtime.no-child-started.v1")
            }),
            provider_session_cleanup_sha256: evidence
                .provider_session_cleanup_sha256
                .clone()
                .unwrap(),
            broker_outcome_sha256: evidence.broker_outcome_sha256.clone().unwrap(),
            runtime_evidence_sha256: record.runtime_evidence_sha256.clone().unwrap(),
            termination_reason: termination_reason.to_string(),
            acknowledged_at_ms: now
                .max(broker.evidence.ended_at_unix_ms)
                .max(session.cleanup_completed_at_unix_ms),
        }
    }

    fn placeholder_teardown_ack(
        grant_id: &str,
        cas: &EgressJournalCas,
        termination_reason: &str,
        runtime_evidence_sha256: &str,
        now: u64,
    ) -> EgressTeardownAck {
        EgressTeardownAck {
            proof_schema: "trillionnium.egress-teardown-proof.v2".to_string(),
            grant_id: grant_id.to_string(),
            journal_binding_sha256: cas.binding_sha256.clone(),
            provider_id: "openai-codex".to_string(),
            teardown_nonce: teardown_nonce(),
            child_cleanup_sha256: sha256_bytes(b"placeholder-child"),
            provider_session_cleanup_sha256: sha256_bytes(b"placeholder-session"),
            broker_outcome_sha256: sha256_bytes(b"placeholder-broker"),
            runtime_evidence_sha256: runtime_evidence_sha256.to_string(),
            termination_reason: termination_reason.to_string(),
            acknowledged_at_ms: now,
        }
    }

    fn complete(
        journal: &mut EgressLifecycleJournal,
        grant_id: &str,
        consumed: &EgressJournalCas,
        now: u64,
    ) -> EgressJournalCas {
        journal
            .mark_completed(
                grant_id,
                consumed,
                &teardown_ack(journal, grant_id, consumed, "completed", now),
            )
            .unwrap()
    }

    fn direct_binding(
        journal: &EgressLifecycleJournal,
        grant_id: &str,
        runtime_binding: &RuntimeLifecycleBinding,
        task_id: &str,
        allocation_cas: &EgressJournalCas,
    ) -> DirectOperationBinding {
        let metadata = &journal.record(grant_id).unwrap().metadata;
        let runtime_lifecycle_binding_sha256 = runtime_binding.digest_sha256().unwrap();
        let daemon_attempt_context_sha256 = daemon_attempt_context_sha256(
            &runtime_binding.provider_id,
            &runtime_binding.agent_id,
            task_id,
            &runtime_lifecycle_binding_sha256,
            1,
            &allocation_cas.record_sha256,
        )
        .unwrap();
        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: runtime_binding.provider_id.clone(),
            agent_id: runtime_binding.agent_id.clone(),
            task_id: task_id.to_string(),
            provider_invocation_id_sha256: runtime_binding.provider_invocation_id_sha256.clone(),
            provider_session_id_sha256: runtime_binding.provider_session_id_sha256.clone(),
            subject_uid: metadata.peer_uid,
            subject_selinux_domain_sha256: metadata.peer_selinux_domain_sha256.clone(),
        };
        let invocation_id = stable_seed.invocation_id().unwrap();
        DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed,
            invocation_id,
            workflow_id_sha256: metadata.workflow_id_sha256.clone(),
            agent_identity_key_sha256: runtime_binding.agent_executable_sha256.clone(),
            agent_executable_sha256: runtime_binding.agent_executable_sha256.clone(),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(
                runtime_lifecycle_binding_sha256,
                1,
                daemon_attempt_context_sha256,
            )
            .unwrap(),
        }
    }

    fn completed_direct_terminal(
        journal: &mut EgressLifecycleJournal,
        metadata: EgressJournalMetadata,
        task_id: &str,
    ) -> (
        String,
        DirectOperationBinding,
        EgressJournalCas,
        EgressJournalCas,
    ) {
        let (grant_id, runtime_binding, frozen) = consume_and_freeze(journal, metadata, task_id);
        let allocation_cas = journal
            .allocate_direct_provider_attempt(
                &grant_id,
                &frozen,
                &runtime_binding,
                task_id,
                now_unix_ms(),
            )
            .unwrap();
        let binding = direct_binding(
            journal,
            &grant_id,
            &runtime_binding,
            task_id,
            &allocation_cas,
        );
        let evidence = runtime_evidence(&runtime_binding);
        let evidence_sha256 = sha256_json(&serde_json::to_value(&evidence).unwrap());
        let evidenced = journal
            .mark_runtime_evidence(
                &grant_id,
                &allocation_cas,
                &evidence_sha256,
                &evidence,
                now_unix_ms(),
            )
            .unwrap();
        let terminal_cas = complete(journal, &grant_id, &evidenced, now_unix_ms());
        (grant_id, binding, allocation_cas, terminal_cas)
    }

    fn rewrite_current_file_as_exact_legacy_v6(value: &mut serde_json::Value) -> String {
        value["schema"] = serde_json::json!(super::LEGACY_V6_JOURNAL_SCHEMA);
        let record = value["records"][0].as_object_mut().unwrap();

        let binding_value = record
            .get_mut("predispatch_binding")
            .unwrap()
            .as_object_mut()
            .unwrap();
        assert!(
            binding_value
                .remove("final_runtime_executable_sha256")
                .is_some()
        );
        let legacy_binding: super::LegacyV6RuntimeLifecycleBinding =
            serde_json::from_value(serde_json::Value::Object(binding_value.clone())).unwrap();
        let typed_binding_value = serde_json::to_value(&legacy_binding).unwrap();
        assert_eq!(
            typed_binding_value,
            serde_json::Value::Object(binding_value.clone())
        );
        let binding_digest = legacy_binding.digest_sha256().unwrap();
        record.insert(
            "predispatch_binding".to_string(),
            typed_binding_value.clone(),
        );
        record.insert(
            "predispatch_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );
        let task_digest = record["predispatch_task_id_sha256"]
            .as_str()
            .unwrap()
            .to_string();
        let attempt = record
            .get_mut("direct_provider_attempt")
            .unwrap()
            .as_object_mut()
            .unwrap();
        attempt.insert(
            "runtime_lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );
        let typed_attempt: super::LegacyV6DirectProviderAttempt =
            serde_json::from_value(serde_json::Value::Object(attempt.clone())).unwrap();
        super::validate_legacy_v6_direct_attempt_value(
            &serde_json::to_value(&typed_attempt).unwrap(),
            &legacy_binding,
            &binding_digest,
            &task_digest,
        )
        .unwrap();

        let runtime = record
            .get_mut("runtime_evidence")
            .unwrap()
            .as_object_mut()
            .unwrap();
        let runtime_binding = runtime
            .get_mut("lifecycle_binding")
            .unwrap()
            .as_object_mut()
            .unwrap();
        assert!(
            runtime_binding
                .remove("final_runtime_executable_sha256")
                .is_some()
        );
        assert_eq!(
            serde_json::from_value::<super::LegacyV6RuntimeLifecycleBinding>(
                serde_json::Value::Object(runtime_binding.clone())
            )
            .unwrap(),
            legacy_binding
        );
        runtime.insert(
            "lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );

        let child = runtime.get_mut("child").unwrap().as_object_mut().unwrap();
        child.insert(
            "lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );
        for v7_only in [
            "post_exec_selinux_domain",
            "post_exec_uid",
            "post_exec_gid",
            "post_exec_uid_gid_verified",
            "post_exec_supplementary_groups_empty_verified",
            "post_exec_no_new_privs_verified",
            "post_exec_capabilities_empty_verified",
            "post_exec_executable_identity_verified",
            "post_exec_final_runtime_executable_sha256",
            "post_exec_final_runtime_device",
            "post_exec_final_runtime_inode",
            "post_exec_final_runtime_source_read_only_mount_verified",
            "post_exec_final_runtime_elf_image_verified",
            "post_exec_independent_session_verified",
            "post_exec_parent_identity_verified",
        ] {
            assert!(child.remove(v7_only).is_some(), "missing {v7_only}");
        }
        let typed_child: super::LegacyV6ChildContainmentEvidence =
            serde_json::from_value(serde_json::Value::Object(child.clone())).unwrap();
        let child_value = serde_json::to_value(&typed_child).unwrap();
        assert_eq!(child_value, serde_json::Value::Object(child.clone()));
        runtime.insert("child".to_string(), child_value);
        runtime.insert(
            "child_cleanup_sha256".to_string(),
            serde_json::Value::String(runtime_evidence_component_sha256(&typed_child).unwrap()),
        );

        let broker = runtime.get_mut("egress").unwrap().as_object_mut().unwrap();
        broker.insert(
            "lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );
        let typed_broker: EgressBrokerOutcome =
            serde_json::from_value(serde_json::Value::Object(broker.clone())).unwrap();
        runtime.insert(
            "broker_outcome_sha256".to_string(),
            serde_json::Value::String(runtime_evidence_component_sha256(&typed_broker).unwrap()),
        );

        let session = runtime
            .get_mut("provider_session_cleanup")
            .unwrap()
            .as_object_mut()
            .unwrap();
        session.insert(
            "lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest),
        );
        let typed_session: ProviderSessionCleanupEvidence =
            serde_json::from_value(serde_json::Value::Object(session.clone())).unwrap();
        runtime.insert(
            "provider_session_cleanup_sha256".to_string(),
            serde_json::Value::String(runtime_evidence_component_sha256(&typed_session).unwrap()),
        );

        let legacy_runtime: super::LegacyV6RuntimeEvidence =
            serde_json::from_value(serde_json::Value::Object(runtime.clone())).unwrap();
        assert!(legacy_runtime.closed_presence_shape_proven());
        let typed_runtime_value = serde_json::to_value(&legacy_runtime).unwrap();
        assert_eq!(
            typed_runtime_value,
            serde_json::Value::Object(runtime.clone())
        );
        record.insert("runtime_evidence".to_string(), typed_runtime_value.clone());
        record.insert(
            "runtime_evidence_sha256".to_string(),
            serde_json::Value::String(sha256_json(&typed_runtime_value)),
        );
        sha256_json(&serde_json::Value::Object(record.clone()))
    }

    fn revoke(
        journal: &mut EgressLifecycleJournal,
        grant_id: &str,
        source: &EgressJournalCas,
        now: u64,
    ) -> EgressJournalCas {
        let request_payload_sha256 = sha256_bytes(b"revoke-payload");
        let _terminal = if source.state == EgressLifecycleState::Prepared {
            journal
                .mark_revoked_before_dispatch(
                    grant_id,
                    source,
                    "revoke-request",
                    &request_payload_sha256,
                    now,
                )
                .unwrap()
        } else {
            let pending = journal
                .mark_revoke_pending(
                    grant_id,
                    source,
                    "revoke-request",
                    &request_payload_sha256,
                    &sha256_bytes(teardown_nonce().as_bytes()),
                    now,
                )
                .unwrap();
            journal
                .mark_revoked(
                    grant_id,
                    &pending,
                    &teardown_ack(journal, grant_id, &pending, "completed", now),
                )
                .unwrap()
        };
        journal
            .mark_ui_request_completed_exact(
                grant_id,
                EgressUiCompletionBinding {
                    method: "revoke_egress",
                    request_id: "revoke-request",
                    request_payload_sha256: &request_payload_sha256,
                    completion_proof_sha256: &sha256_bytes(b"revoke-ui-completion-proof"),
                    peer_uid: 10_123,
                    peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                    completed_at_ms: now,
                },
            )
            .unwrap()
    }

    #[test]
    fn prepared_survives_journal_reopen_for_custody_gated_recovery() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let metadata = fixture(&path, 'a');
        let grant_id = metadata.grant_id.clone();
        let binding = {
            let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
            prepare(&mut journal, metadata)
        };
        let mut restarted = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(
            restarted.state_for_test(&grant_id),
            Some(EgressLifecycleState::Prepared)
        );
        assert!(
            restarted
                .mark_consumed(
                    &grant_id,
                    &EgressJournalCas {
                        record_sha256: "f".repeat(64),
                        ..binding.clone()
                    },
                    &"c".repeat(64),
                    &sha256_bytes(teardown_nonce().as_bytes()),
                    now_unix_ms(),
                )
                .unwrap_err()
                .to_string()
                .contains("compare_and_swap_failed")
        );
        drop(restarted);
        let restarted_again = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(
            restarted_again.state_for_test(&grant_id),
            Some(EgressLifecycleState::Prepared)
        );
    }

    #[test]
    fn durable_direct_attempt_is_single_generation_bound_to_exact_frozen_record() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let (grant_id, binding, frozen) =
            consume_and_freeze(&mut journal, fixture(&path, 'd'), "direct-task");

        assert!(
            journal
                .allocate_direct_provider_attempt(
                    &grant_id,
                    &frozen,
                    &binding,
                    "cross-task",
                    now_unix_ms(),
                )
                .unwrap_err()
                .to_string()
                .contains("frozen_binding_mismatch")
        );
        let mut cross_binding = binding.clone();
        cross_binding.capability_token_sha256 = sha256_bytes(b"cross-lifecycle-capability");
        assert!(
            journal
                .allocate_direct_provider_attempt(
                    &grant_id,
                    &frozen,
                    &cross_binding,
                    "direct-task",
                    now_unix_ms(),
                )
                .unwrap_err()
                .to_string()
                .contains("frozen_binding_mismatch")
        );
        let allocated = journal
            .allocate_direct_provider_attempt(
                &grant_id,
                &frozen,
                &binding,
                "direct-task",
                now_unix_ms(),
            )
            .unwrap();
        assert_ne!(allocated.record_sha256, frozen.record_sha256);
        let stored = journal
            .record(&grant_id)
            .unwrap()
            .direct_provider_attempt
            .as_ref()
            .unwrap()
            .clone();
        assert_eq!(stored.attempt_generation, 1);
        assert_eq!(
            stored.allocation_predecessor_record_sha256,
            frozen.record_sha256
        );
        assert_eq!(
            stored.runtime_lifecycle_binding_sha256,
            binding.digest_sha256().unwrap()
        );
        let source = journal
            .direct_provider_attempt_source(&grant_id, &allocated, &binding, "direct-task")
            .unwrap();
        let exact_query = DurableProviderAttemptQuery {
            provider_id: binding.provider_id.clone(),
            agent_id: binding.agent_id.clone(),
            task_id: "direct-task".to_string(),
            runtime_lifecycle_binding_sha256: binding.digest_sha256().unwrap(),
        };
        source.load_durable_attempt(&exact_query).unwrap();
        let mut cross_provider = exact_query.clone();
        cross_provider.provider_id = "unregistered-provider".to_string();
        assert!(source.load_durable_attempt(&cross_provider).is_err());
        assert!(
            journal
                .allocate_direct_provider_attempt(
                    &grant_id,
                    &allocated,
                    &binding,
                    "direct-task",
                    now_unix_ms(),
                )
                .unwrap_err()
                .to_string()
                .contains("already_allocated")
        );
        let evidence = runtime_evidence(&binding);
        let evidenced = journal
            .mark_runtime_evidence(
                &grant_id,
                &allocated,
                &sha256_json(&serde_json::to_value(&evidence).unwrap()),
                &evidence,
                now_unix_ms(),
            )
            .unwrap();
        assert!(
            journal
                .direct_provider_attempt_source(&grant_id, &evidenced, &binding, "direct-task",)
                .is_err()
        );

        drop(journal);
        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(
            reopened.state_for_test(&grant_id),
            Some(EgressLifecycleState::InterruptedRestart)
        );
        let persisted = reopened
            .record(&grant_id)
            .unwrap()
            .direct_provider_attempt
            .as_ref()
            .unwrap();
        assert_eq!(persisted, &stored);
        let reopened_cas = reopened
            .cas_for(reopened.record(&grant_id).unwrap())
            .unwrap();
        assert!(
            reopened
                .direct_provider_attempt_source(&grant_id, &reopened_cas, &binding, "direct-task",)
                .is_err()
        );
    }

    #[test]
    fn distinct_lifecycles_each_have_one_generation_without_cross_record_counter() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        for (suffix, task) in [('e', "task-one"), ('f', "task-two")] {
            let (grant_id, binding, frozen) =
                consume_and_freeze(&mut journal, fixture(&path, suffix), task);
            journal
                .allocate_direct_provider_attempt(&grant_id, &frozen, &binding, task, now_unix_ms())
                .unwrap();
            assert_eq!(
                journal
                    .record(&grant_id)
                    .unwrap()
                    .direct_provider_attempt
                    .as_ref()
                    .unwrap()
                    .attempt_generation,
                1
            );
        }
    }

    #[test]
    fn direct_attempt_commit_unknown_blocks_source_and_reopen_never_dispatches() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let (grant_id, binding, frozen) =
            consume_and_freeze(&mut journal, fixture(&path, '0'), "direct-task");
        journal.fail_parent_fsync_after_rename_once_for_test();
        let uncertain = journal
            .allocate_direct_provider_attempt(
                &grant_id,
                &frozen,
                &binding,
                "direct-task",
                now_unix_ms(),
            )
            .unwrap();
        assert!(uncertain.publication_durability_uncertain);
        assert!(
            journal
                .direct_provider_attempt_source(&grant_id, &uncertain, &binding, "direct-task",)
                .is_err()
        );
        drop(journal);
        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(
            reopened.state_for_test(&grant_id),
            Some(EgressLifecycleState::InterruptedRestart)
        );
        assert!(
            reopened
                .record(&grant_id)
                .unwrap()
                .direct_provider_attempt
                .is_some()
        );
    }

    #[test]
    fn legacy_v5_record_three_migrates_without_inventing_an_attempt() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let grant_id;
        {
            let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
            let metadata = fixture(&path, '1');
            grant_id = metadata.grant_id.clone();
            let prepared = prepare(&mut journal, metadata);
            journal
                .mark_consumed(
                    &grant_id,
                    &prepared,
                    &sha256_bytes(b"legacy-v5-receipt"),
                    &sha256_bytes(teardown_nonce().as_bytes()),
                    now_unix_ms(),
                )
                .unwrap();
        }
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["schema"] = serde_json::json!(super::LEGACY_V5_JOURNAL_SCHEMA);
        let record = value["records"][0].as_object_mut().unwrap();
        record.insert("record_version".to_string(), serde_json::json!(3));
        record.remove("direct_provider_attempt");
        let mut encoded = serde_json::to_vec_pretty(&value).unwrap();
        encoded.push(b'\n');
        fs::write(&path, encoded).unwrap();

        let migrated = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(migrated.file.schema, super::JOURNAL_SCHEMA);
        let record = migrated.record(&grant_id).unwrap();
        assert_eq!(record.record_version, 3);
        assert!(record.direct_provider_attempt.is_none());
        assert_eq!(record.state, EgressLifecycleState::InterruptedRestart);
    }

    #[test]
    fn legacy_v5_prepared_record_promotes_only_during_real_attempt_allocation() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let grant_id;
        {
            let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
            let metadata = fixture(&path, '3');
            grant_id = metadata.grant_id.clone();
            prepare(&mut journal, metadata);
        }
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["schema"] = serde_json::json!(super::LEGACY_V5_JOURNAL_SCHEMA);
        let record = value["records"][0].as_object_mut().unwrap();
        record.insert("record_version".to_string(), serde_json::json!(3));
        record.remove("direct_provider_attempt");
        let mut encoded = serde_json::to_vec_pretty(&value).unwrap();
        encoded.push(b'\n');
        fs::write(&path, encoded).unwrap();

        let mut migrated = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let prepared = migrated
            .cas_for(migrated.record(&grant_id).unwrap())
            .unwrap();
        assert_eq!(migrated.record(&grant_id).unwrap().record_version, 3);
        assert!(
            migrated
                .record(&grant_id)
                .unwrap()
                .direct_provider_attempt
                .is_none()
        );
        let consumed = migrated
            .mark_consumed(
                &grant_id,
                &prepared,
                &sha256_bytes(b"late-v5-consent-receipt"),
                &sha256_bytes(teardown_nonce().as_bytes()),
                now_unix_ms(),
            )
            .unwrap();
        let binding = runtime_binding(&migrated, &grant_id, &consumed.binding_sha256);
        let frozen = migrated
            .freeze_predispatch_binding(
                &grant_id,
                &consumed,
                &binding,
                "late-v5-task",
                "plan-request",
                "provider-session",
                now_unix_ms(),
            )
            .unwrap();
        let allocated = migrated
            .allocate_direct_provider_attempt(
                &grant_id,
                &frozen,
                &binding,
                "late-v5-task",
                now_unix_ms(),
            )
            .unwrap();
        assert!(!allocated.publication_durability_uncertain);
        let record = migrated.record(&grant_id).unwrap();
        assert_eq!(record.record_version, 4);
        assert_eq!(
            record
                .direct_provider_attempt
                .as_ref()
                .unwrap()
                .attempt_generation,
            1
        );
    }

    #[test]
    fn exact_legacy_v6_runtime_reopens_as_nonresumable_v7_tombstone() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let grant_id;
        {
            let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
            (grant_id, _, _, _) =
                completed_direct_terminal(&mut journal, fixture(&path, '4'), "legacy-v6-task");
        }
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let legacy_record_sha256 = rewrite_current_file_as_exact_legacy_v6(&mut value);
        let mut encoded = serde_json::to_vec_pretty(&value).unwrap();
        encoded.push(b'\n');
        fs::write(&path, encoded).unwrap();

        let migrated = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(migrated.file.schema, super::JOURNAL_SCHEMA);
        let record = migrated.record(&grant_id).unwrap();
        assert_eq!(record.state, EgressLifecycleState::IndeterminateRestart);
        assert_eq!(
            record.last_transition_from_sha256.as_deref(),
            Some(legacy_record_sha256.as_str())
        );
        assert!(record.runtime_evidence.is_none());
        assert!(record.runtime_evidence_sha256.is_none());
        assert!(record.predispatch_binding.is_none());
        assert!(record.predispatch_binding_sha256.is_none());
        assert!(record.predispatch_task_id_sha256.is_none());
        assert!(record.direct_provider_attempt.is_none());
        assert!(record.completion_ack_sha256.is_none());
        drop(migrated);

        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let record = reopened.record(&grant_id).unwrap();
        assert_eq!(record.state, EgressLifecycleState::IndeterminateRestart);
        assert_eq!(
            record.last_transition_from_sha256.as_deref(),
            Some(legacy_record_sha256.as_str())
        );
    }

    #[test]
    fn v7_final_runtime_binding_round_trips_canonical_bytes() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let grant_id;
        {
            let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
            (grant_id, _, _, _) =
                completed_direct_terminal(&mut journal, fixture(&path, '5'), "v7-round-trip-task");
        }
        let before = fs::read(&path).unwrap();
        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let record = reopened.record(&grant_id).unwrap();
        let predispatch = record.predispatch_binding.as_ref().unwrap();
        let runtime = record
            .runtime_evidence
            .as_ref()
            .unwrap()
            .lifecycle_binding
            .as_ref()
            .unwrap();
        assert_eq!(predispatch.final_runtime_executable_sha256, "f".repeat(64));
        assert_eq!(runtime, predispatch);
        drop(reopened);
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn tampered_direct_attempt_version_generation_and_consumed_shape_are_denied() {
        let make_value = || {
            let temp = private_temp();
            let path = temp.path().join("egress.json");
            let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
            let (grant_id, binding, frozen) =
                consume_and_freeze(&mut journal, fixture(&path, '2'), "direct-task");
            journal
                .allocate_direct_provider_attempt(
                    &grant_id,
                    &frozen,
                    &binding,
                    "direct-task",
                    now_unix_ms(),
                )
                .unwrap();
            drop(journal);
            let value =
                serde_json::from_slice::<serde_json::Value>(&fs::read(&path).unwrap()).unwrap();
            (temp, path, value)
        };
        let write_and_reject = |path: &std::path::Path, value: &serde_json::Value| {
            let mut encoded = serde_json::to_vec_pretty(value).unwrap();
            encoded.push(b'\n');
            fs::write(path, encoded).unwrap();
            assert!(EgressLifecycleJournal::open_for_test(path).is_err());
        };

        let (_temp, path, mut value) = make_value();
        value["records"][0]["direct_provider_attempt"]["attempt_generation"] = serde_json::json!(2);
        write_and_reject(&path, &value);

        let (_temp, path, mut value) = make_value();
        value["records"][0]["record_version"] = serde_json::json!(3);
        write_and_reject(&path, &value);

        let (_temp, path, mut value) = make_value();
        value["records"][0]["consumed_at_ms"] = serde_json::Value::Null;
        write_and_reject(&path, &value);
    }

    #[test]
    fn direct_terminal_is_never_compacted_and_survives_reopen() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let (grant_id, _, _, _) =
            completed_direct_terminal(&mut journal, fixture(&path, '3'), "direct-task");
        assert_eq!(journal.compact_terminal_prefix_for_test(1).unwrap(), 0);
        assert!(journal.contains_grant(&grant_id));
        assert!(!super::replay_filter_contains(&journal.file.compaction, &grant_id).unwrap());
        drop(journal);

        let mut reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert!(reopened.contains_grant(&grant_id));
        assert_eq!(reopened.compact_terminal_prefix_for_test(1).unwrap(), 0);
        assert!(reopened.contains_grant(&grant_id));
    }

    #[test]
    fn direct_terminal_blocks_headroom_compaction_without_removing_later_records() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let (direct_id, _, _, _) =
            completed_direct_terminal(&mut journal, fixture(&path, '6'), "direct-headroom");

        let ordinary = fixture(&path, '9');
        let ordinary_id = ordinary.grant_id.clone();
        let prepared = prepare(&mut journal, ordinary);
        let consumed = consume(
            &mut journal,
            &ordinary_id,
            &prepared,
            &sha256_bytes(b"ordinary-headroom-receipt"),
            now_unix_ms(),
        );
        complete(&mut journal, &ordinary_id, &consumed, now_unix_ms());
        assert_eq!(journal.file.records.len(), 2);

        journal
            .compact_for_headroom_with_limits(2, usize::MAX, 1)
            .unwrap();
        assert_eq!(journal.file.records.len(), 2);
        assert!(journal.contains_grant(&direct_id));
        assert!(journal.contains_grant(&ordinary_id));
        assert_eq!(journal.file.compaction.compacted_terminal_records, 0);
    }

    #[test]
    fn verified_direct_terminal_snapshot_is_exact_and_restart_stable() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let (grant_id, binding, allocation_cas, terminal_cas) =
            completed_direct_terminal(&mut journal, fixture(&path, '7'), "snapshot-task");
        let snapshot = journal
            .verified_direct_terminal_snapshot(&grant_id, &terminal_cas, &allocation_cas, &binding)
            .unwrap();
        let record = journal.record(&grant_id).unwrap();
        snapshot.validate_for_binding(&binding).unwrap();
        snapshot
            .validate_custody_identity(
                &binding,
                &sha256_bytes(grant_id.as_bytes()),
                &record.binding_sha256,
            )
            .unwrap();
        assert!(
            snapshot
                .validate_custody_identity(
                    &binding,
                    &sha256_bytes(b"cross-grant"),
                    &record.binding_sha256,
                )
                .is_err()
        );
        assert_eq!(snapshot.final_record_sha256(), terminal_cas.record_sha256);
        assert_eq!(
            snapshot.predecessor_record_sha256(),
            record.last_transition_from_sha256.as_deref().unwrap()
        );
        assert_eq!(
            snapshot.runtime_evidence_sha256(),
            record.runtime_evidence_sha256.as_deref().unwrap()
        );
        assert_eq!(
            snapshot.provider_teardown_completion_ack_sha256(),
            record.completion_ack_sha256.as_deref().unwrap()
        );
        assert_ne!(snapshot.terminal_egress_cas_sha256(), "0".repeat(64));
        drop(journal);

        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let reopened_snapshot = reopened
            .verified_direct_terminal_snapshot(&grant_id, &terminal_cas, &allocation_cas, &binding)
            .unwrap();
        assert_eq!(reopened_snapshot, snapshot);
    }

    #[test]
    fn verified_direct_terminal_snapshot_rejects_all_identity_and_cas_drift() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let (grant_id, binding, allocation_cas, terminal_cas) =
            completed_direct_terminal(&mut journal, fixture(&path, '8'), "snapshot-task");

        let mut stale_terminal = terminal_cas.clone();
        stale_terminal.record_sha256 = sha256_bytes(b"stale-terminal");
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &stale_terminal,
                    &allocation_cas,
                    &binding,
                )
                .is_err()
        );
        let mut stale_allocation = allocation_cas.clone();
        stale_allocation.record_sha256 = sha256_bytes(b"stale-allocation");
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &terminal_cas,
                    &stale_allocation,
                    &binding,
                )
                .is_err()
        );
        let mut cross_task = binding.clone();
        cross_task.stable_seed.task_id = "cross-task".to_string();
        cross_task.invocation_id = cross_task.stable_seed.invocation_id().unwrap();
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &terminal_cas,
                    &allocation_cas,
                    &cross_task,
                )
                .is_err()
        );

        for (index, mut identity_drift) in [binding.clone(), binding.clone(), binding.clone()]
            .into_iter()
            .enumerate()
        {
            match index {
                0 => identity_drift.workflow_id_sha256 = sha256_bytes(b"cross-workflow"),
                1 => {
                    identity_drift.agent_identity_key_sha256 = sha256_bytes(b"cross-agent-identity")
                }
                2 => {
                    identity_drift.agent_executable_sha256 = sha256_bytes(b"cross-agent-executable")
                }
                _ => unreachable!(),
            }
            assert!(
                journal
                    .verified_direct_terminal_snapshot(
                        &grant_id,
                        &terminal_cas,
                        &allocation_cas,
                        &identity_drift,
                    )
                    .is_err()
            );
        }
        let mut cross_provider = binding.clone();
        cross_provider.stable_seed.provider_id = "unregistered-provider".to_string();
        cross_provider.stable_seed.agent_id = "unregistered-agent".to_string();
        assert!(cross_provider.stable_seed.invocation_id().is_err());
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &terminal_cas,
                    &allocation_cas,
                    &cross_provider,
                )
                .is_err()
        );
        let mut cross_agent = binding.clone();
        cross_agent.stable_seed.agent_id = "unregistered-agent".to_string();
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &terminal_cas,
                    &allocation_cas,
                    &cross_agent,
                )
                .is_err()
        );

        let mut wrong_runtime = binding.clone();
        wrong_runtime.attempt = DirectOperationProviderAttempt::derive(
            sha256_bytes(b"wrong-runtime"),
            1,
            daemon_attempt_context_sha256(
                &binding.stable_seed.provider_id,
                &binding.stable_seed.agent_id,
                &binding.stable_seed.task_id,
                &sha256_bytes(b"wrong-runtime"),
                1,
                &allocation_cas.record_sha256,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &terminal_cas,
                    &allocation_cas,
                    &wrong_runtime,
                )
                .is_err()
        );

        let mut wrong_generation = binding.clone();
        wrong_generation.attempt = DirectOperationProviderAttempt::derive(
            binding.attempt.runtime_lifecycle_binding_sha256.clone(),
            2,
            daemon_attempt_context_sha256(
                &binding.stable_seed.provider_id,
                &binding.stable_seed.agent_id,
                &binding.stable_seed.task_id,
                &binding.attempt.runtime_lifecycle_binding_sha256,
                2,
                &allocation_cas.record_sha256,
            )
            .unwrap(),
        )
        .unwrap();
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &terminal_cas,
                    &allocation_cas,
                    &wrong_generation,
                )
                .is_err()
        );

        let mut uncertain_terminal = terminal_cas.clone();
        uncertain_terminal.publication_durability_uncertain = true;
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &uncertain_terminal,
                    &allocation_cas,
                    &binding,
                )
                .is_err()
        );

        let original = journal.record(&grant_id).unwrap().clone();
        for mutation in 0..4 {
            let record = journal
                .file
                .records
                .iter_mut()
                .find(|record| record.metadata.grant_id == grant_id)
                .unwrap();
            match mutation {
                0 => record.last_transition_from_sha256 = None,
                1 => record.runtime_evidence_sha256 = None,
                2 => record.completion_ack_sha256 = None,
                3 => {
                    record.revoke_event = Some(super::EgressRevokeEvent {
                        schema: "trillionnium.android-egress-revoke-event.v1".to_string(),
                        request_id: "substituted-revoke".to_string(),
                        request_payload_sha256: sha256_bytes(b"substituted-revoke"),
                        requested_at_ms: record.updated_at_ms,
                        teardown_ack_sha256: None,
                        teardown_ack_at_ms: None,
                    });
                }
                _ => unreachable!(),
            }
            assert!(
                journal
                    .verified_direct_terminal_snapshot(
                        &grant_id,
                        &terminal_cas,
                        &allocation_cas,
                        &binding,
                    )
                    .is_err()
            );
            *journal
                .file
                .records
                .iter_mut()
                .find(|record| record.metadata.grant_id == grant_id)
                .unwrap() = original.clone();
        }

        journal.publication_durability_uncertain = true;
        assert!(
            journal
                .verified_direct_terminal_snapshot(
                    &grant_id,
                    &terminal_cas,
                    &allocation_cas,
                    &binding,
                )
                .is_err()
        );
    }

    #[test]
    fn no_runtime_evidence_cannot_complete_or_revoke_a_consumed_grant() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let now = now_unix_ms();
        let no_runtime = CodexRuntimeEvidence::no_runtime_started();
        assert!(!no_runtime.production_containment_proven());
        assert!(!no_runtime.production_egress_teardown_proven());

        let complete_metadata = fixture(&path, '4');
        let complete_id = complete_metadata.grant_id.clone();
        let prepared = prepare(&mut journal, complete_metadata);
        let consumed = journal
            .mark_consumed(
                &complete_id,
                &prepared,
                &sha256_bytes(b"complete-receipt"),
                &sha256_bytes(teardown_nonce().as_bytes()),
                now,
            )
            .unwrap();
        let no_runtime_sha256 = sha256_json(&serde_json::to_value(&no_runtime).unwrap());
        assert!(
            journal
                .mark_runtime_evidence(
                    &complete_id,
                    &consumed,
                    &no_runtime_sha256,
                    &no_runtime,
                    now,
                )
                .is_err()
        );
        let completion_ack = placeholder_teardown_ack(
            &complete_id,
            &consumed,
            "completed",
            &no_runtime_sha256,
            now,
        );
        assert!(
            journal
                .mark_completed(&complete_id, &consumed, &completion_ack)
                .is_err()
        );
        assert_eq!(
            journal.state_for_test(&complete_id),
            Some(EgressLifecycleState::Consumed)
        );

        let revoke_metadata = fixture(&path, '5');
        let revoke_id = revoke_metadata.grant_id.clone();
        let prepared = prepare(&mut journal, revoke_metadata);
        let consumed = journal
            .mark_consumed(
                &revoke_id,
                &prepared,
                &sha256_bytes(b"revoke-receipt"),
                &sha256_bytes(teardown_nonce().as_bytes()),
                now,
            )
            .unwrap();
        let pending = journal
            .mark_revoke_pending(
                &revoke_id,
                &consumed,
                "revoke-no-runtime",
                &sha256_bytes(b"revoke-no-runtime-payload"),
                &sha256_bytes(teardown_nonce().as_bytes()),
                now,
            )
            .unwrap();
        assert!(
            journal
                .mark_runtime_evidence(&revoke_id, &pending, &no_runtime_sha256, &no_runtime, now,)
                .is_err()
        );
        let revoke_ack =
            placeholder_teardown_ack(&revoke_id, &pending, "caller", &no_runtime_sha256, now);
        assert!(
            journal
                .mark_revoked(&revoke_id, &pending, &revoke_ack)
                .is_err()
        );
        assert_eq!(
            journal.state_for_test(&revoke_id),
            Some(EgressLifecycleState::RevokePending)
        );
    }

    #[test]
    fn runtime_with_unproven_post_exec_dumpability_is_rejected_before_publication() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let now = now_unix_ms();
        let metadata = fixture(&path, 'd');
        let grant_id = metadata.grant_id.clone();
        let prepared = prepare(&mut journal, metadata);
        let consumed = journal
            .mark_consumed(
                &grant_id,
                &prepared,
                &sha256_bytes(b"dumpability-hold-receipt"),
                &sha256_bytes(teardown_nonce().as_bytes()),
                now,
            )
            .unwrap();
        let binding = runtime_binding(&journal, &grant_id, &consumed.binding_sha256);
        let frozen = journal
            .freeze_predispatch_binding(
                &grant_id,
                &consumed,
                &binding,
                "fixture-task",
                "plan-request",
                "provider-session",
                now,
            )
            .unwrap();
        let mut evidence = runtime_evidence(&binding);
        let child = evidence.child.as_mut().unwrap();
        child.post_exec_dumpable_verified = false;
        evidence.child_cleanup_sha256 = Some(runtime_evidence_component_sha256(child).unwrap());
        assert!(evidence.containment_proven());
        assert!(!evidence.production_containment_proven());
        let evidence_sha256 = sha256_json(&serde_json::to_value(&evidence).unwrap());
        let error = journal
            .mark_runtime_evidence(&grant_id, &frozen, &evidence_sha256, &evidence, now)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("runtime_evidence_record_binding_denied"),
            "{error:#}"
        );
        assert_eq!(
            journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Consumed)
        );
        assert!(
            journal
                .record(&grant_id)
                .unwrap()
                .runtime_evidence
                .is_none()
        );
    }

    #[test]
    fn post_rename_parent_fsync_failure_keeps_published_state_in_memory_and_on_reopen() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let metadata = fixture(&path, '6');
        let grant_id = metadata.grant_id.clone();
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let prepared = prepare(&mut journal, metadata);
        let consumed = consume(
            &mut journal,
            &grant_id,
            &prepared,
            &sha256_bytes(b"parent-fsync-receipt"),
            now_unix_ms(),
        );
        journal.fail_parent_fsync_after_rename_once_for_test();
        let completion_ack =
            teardown_ack(&journal, &grant_id, &consumed, "completed", now_unix_ms());
        let published = journal
            .mark_completed(&grant_id, &consumed, &completion_ack)
            .expect("visible published state must remain in memory under commit uncertainty");
        assert!(published.publication_durability_uncertain);
        assert!(journal.publication_durability_uncertain());
        assert_eq!(
            journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Completed)
        );
        assert_eq!(
            journal
                .status_for_subject(
                    &grant_id,
                    "private-workflow",
                    10_123,
                    "u:r:trillionnium_aishell:s0",
                )
                .unwrap(),
            EgressLifecycleState::Completed
        );
        assert!(
            journal
                .mark_expired(&grant_id, &consumed, now_unix_ms())
                .unwrap_err()
                .to_string()
                .contains("fail_stop_published_durability_uncertain")
        );
        drop(journal);
        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(
            reopened.state_for_test(&grant_id),
            Some(EgressLifecycleState::Completed)
        );
    }

    #[test]
    fn lifecycle_states_reconstruct_without_reviving_inflight_work() {
        for (suffix, state, reconstructed_state) in [
            (
                'b',
                EgressLifecycleState::Consumed,
                EgressLifecycleState::InterruptedRestart,
            ),
            (
                'c',
                EgressLifecycleState::RevokedBeforeDispatch,
                EgressLifecycleState::RevokedBeforeDispatch,
            ),
            (
                'd',
                EgressLifecycleState::Expired,
                EgressLifecycleState::Expired,
            ),
            (
                'e',
                EgressLifecycleState::Completed,
                EgressLifecycleState::Completed,
            ),
        ] {
            let temp = private_temp();
            let path = temp.path().join("egress.json");
            let metadata = fixture(&path, suffix);
            let grant_id = metadata.grant_id.clone();
            let expires_at = metadata.expires_at_ms;
            let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
            let prepared = prepare(&mut journal, metadata);
            match state {
                EgressLifecycleState::Consumed => {
                    consume(
                        &mut journal,
                        &grant_id,
                        &prepared,
                        &"c".repeat(64),
                        now_unix_ms(),
                    );
                }
                EgressLifecycleState::Completed => {
                    let consumed = consume(
                        &mut journal,
                        &grant_id,
                        &prepared,
                        &"c".repeat(64),
                        now_unix_ms(),
                    );
                    complete(&mut journal, &grant_id, &consumed, now_unix_ms());
                }
                EgressLifecycleState::RevokedBeforeDispatch => {
                    revoke(&mut journal, &grant_id, &prepared, now_unix_ms());
                }
                EgressLifecycleState::Expired => {
                    journal
                        .mark_expired(&grant_id, &prepared, expires_at)
                        .unwrap();
                }
                _ => unreachable!(),
            }
            drop(journal);
            let reconstructed = EgressLifecycleJournal::open_for_test(&path).unwrap();
            assert_eq!(
                reconstructed.state_for_test(&grant_id),
                Some(reconstructed_state)
            );
        }
    }

    #[test]
    fn compacted_terminal_ids_remain_non_replayable_and_capacity_recovers() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let old = fixture(&path, 'a');
        let old_id = old.grant_id.clone();
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let old_prepared = prepare(&mut journal, old);
        let old_consumed = consume(
            &mut journal,
            &old_id,
            &old_prepared,
            &"c".repeat(64),
            now_unix_ms(),
        );
        complete(&mut journal, &old_id, &old_consumed, now_unix_ms());
        assert_eq!(journal.compact_terminal_prefix_for_test(1).unwrap(), 1);
        assert_eq!(journal.state_for_test(&old_id), None);
        assert!(
            journal
                .mark_consumed(
                    &old_id,
                    &old_prepared,
                    &"c".repeat(64),
                    &sha256_bytes(teardown_nonce().as_bytes()),
                    now_unix_ms(),
                )
                .unwrap_err()
                .to_string()
                .contains("unknown_grant")
        );

        let boundary = journal.file.compaction.through_issued_at_ms;
        let mut substituted_old_id = fixture(&path, 'a');
        substituted_old_id.issued_at_ms = boundary.saturating_add(1);
        substituted_old_id.expires_at_ms = substituted_old_id.issued_at_ms + 120_000;
        substituted_old_id.context_captured_at_ms =
            substituted_old_id.issued_at_ms.saturating_sub(1);
        substituted_old_id.context_expires_at_ms = substituted_old_id.expires_at_ms;
        assert!(
            journal
                .record_prepared(
                    substituted_old_id.clone(),
                    &recovery(&substituted_old_id.grant_id)
                )
                .unwrap_err()
                .to_string()
                .contains("compacted_grant_replay_denied")
        );

        let mut fresh = fixture(&path, 'b');
        fresh.issued_at_ms = boundary.saturating_add(1);
        fresh.expires_at_ms = fresh.issued_at_ms + 120_000;
        fresh.context_captured_at_ms = fresh.issued_at_ms.saturating_sub(1);
        fresh.context_expires_at_ms = fresh.expires_at_ms;
        let fresh_id = fresh.grant_id.clone();
        prepare(&mut journal, fresh);
        assert_eq!(
            journal.state_for_test(&fresh_id),
            Some(EgressLifecycleState::Prepared)
        );
        drop(journal);

        let restarted = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(restarted.state_for_test(&old_id), None);
        assert_eq!(
            restarted.state_for_test(&fresh_id),
            Some(EgressLifecycleState::Prepared)
        );
        assert!(restarted.file.compaction.compacted_terminal_records >= 1);
        assert!(!restarted.file.compaction.replay_filter_b64.is_empty());
    }

    #[test]
    fn compaction_never_removes_revocable_consumed_run_and_reclaims_after_terminalization() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let base = now_unix_ms();
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();

        let mut terminal = fixture(&path, '1');
        terminal.issued_at_ms = base;
        terminal.expires_at_ms = terminal.issued_at_ms + 120_000;
        terminal.context_captured_at_ms = terminal.issued_at_ms.saturating_sub(1);
        terminal.context_expires_at_ms = terminal.expires_at_ms;
        let terminal_id = terminal.grant_id.clone();
        let terminal_prepared = prepare(&mut journal, terminal);
        let terminal_consumed = consume(
            &mut journal,
            &terminal_id,
            &terminal_prepared,
            &"1".repeat(64),
            base,
        );
        complete(&mut journal, &terminal_id, &terminal_consumed, base);

        let mut active = fixture(&path, '2');
        active.issued_at_ms = base + 1;
        active.expires_at_ms = active.issued_at_ms + 120_000;
        active.context_captured_at_ms = active.issued_at_ms.saturating_sub(1);
        active.context_expires_at_ms = active.expires_at_ms;
        let active_id = active.grant_id.clone();
        let active_prepared = prepare(&mut journal, active);
        let active_consumed = consume(
            &mut journal,
            &active_id,
            &active_prepared,
            &"2".repeat(64),
            base,
        );

        let mut trailing_terminal = fixture(&path, '3');
        trailing_terminal.issued_at_ms = base + 2;
        trailing_terminal.expires_at_ms = trailing_terminal.issued_at_ms + 120_000;
        trailing_terminal.context_captured_at_ms = trailing_terminal.issued_at_ms.saturating_sub(1);
        trailing_terminal.context_expires_at_ms = trailing_terminal.expires_at_ms;
        let trailing_id = trailing_terminal.grant_id.clone();
        let trailing_prepared = prepare(&mut journal, trailing_terminal);
        let trailing_consumed = consume(
            &mut journal,
            &trailing_id,
            &trailing_prepared,
            &"3".repeat(64),
            base,
        );
        complete(&mut journal, &trailing_id, &trailing_consumed, base);

        assert_eq!(journal.compact_terminal_prefix_for_test(3).unwrap(), 1);
        assert_eq!(journal.state_for_test(&terminal_id), None);
        assert_eq!(
            journal.state_for_test(&active_id),
            Some(EgressLifecycleState::Consumed)
        );
        assert_eq!(
            journal.state_for_test(&trailing_id),
            Some(EgressLifecycleState::Completed)
        );
        revoke(
            &mut journal,
            &active_id,
            &active_consumed,
            now_unix_ms().max(base.saturating_add(2)),
        );
        assert_eq!(journal.compact_terminal_prefix_for_test(2).unwrap(), 2);
        assert_eq!(journal.state_for_test(&active_id), None);

        let boundary = journal.file.compaction.through_issued_at_ms;
        let mut replay = fixture(&path, '2');
        replay.issued_at_ms = boundary + 1;
        replay.expires_at_ms = replay.issued_at_ms + 120_000;
        replay.context_captured_at_ms = replay.issued_at_ms.saturating_sub(1);
        replay.context_expires_at_ms = replay.expires_at_ms;
        assert!(
            journal
                .record_prepared(replay.clone(), &recovery(&replay.grant_id))
                .unwrap_err()
                .to_string()
                .contains("compacted_grant_replay_denied")
        );
    }

    #[test]
    fn indeterminate_restart_with_revoke_pending_compacts_only_after_exact_ui_ack_and_reopen() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let metadata = fixture(&path, '7');
        let grant_id = metadata.grant_id.clone();
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let prepared = prepare(&mut journal, metadata);
        let consumed = consume(
            &mut journal,
            &grant_id,
            &prepared,
            &sha256_bytes(b"revoke-pending-receipt"),
            now_unix_ms(),
        );
        let request_payload_sha256 = sha256_bytes(b"revoke-pending-payload");
        let pending = journal
            .mark_revoke_pending(
                &grant_id,
                &consumed,
                "revoke-pending-request",
                &request_payload_sha256,
                &sha256_bytes(teardown_nonce().as_bytes()),
                now_unix_ms(),
            )
            .unwrap();
        journal
            .freeze_revoke_pending_ui_outcome(
                &grant_id,
                &pending,
                "revoke-pending-request",
                &request_payload_sha256,
                now_unix_ms(),
            )
            .unwrap();
        assert_eq!(
            journal.record(&grant_id).unwrap().revoke_ui_outcome,
            Some(super::EgressRevokeUiOutcome::RevokePending)
        );

        drop(journal);
        let mut restarted = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(
            restarted.state_for_test(&grant_id),
            Some(EgressLifecycleState::IndeterminateRestart)
        );
        assert_eq!(
            restarted.compact_terminal_prefix_for_test(1).unwrap(),
            0,
            "a frozen revoke response must survive until its outer completion is durable"
        );
        assert!(
            restarted
                .mark_ui_request_completed_exact(
                    &grant_id,
                    EgressUiCompletionBinding {
                        method: "revoke_egress",
                        request_id: "revoke-pending-request",
                        request_payload_sha256: &request_payload_sha256,
                        completion_proof_sha256: "not-a-digest",
                        peer_uid: 10_123,
                        peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                        completed_at_ms: now_unix_ms(),
                    },
                )
                .unwrap_err()
                .to_string()
                .contains("ui_completion_proof_sha256")
        );
        let completion_proof_sha256 = sha256_bytes(b"revoke-pending-ui-completion-proof");
        let acknowledged = restarted
            .mark_ui_request_completed_exact(
                &grant_id,
                EgressUiCompletionBinding {
                    method: "revoke_egress",
                    request_id: "revoke-pending-request",
                    request_payload_sha256: &request_payload_sha256,
                    completion_proof_sha256: &completion_proof_sha256,
                    peer_uid: 10_123,
                    peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                    completed_at_ms: now_unix_ms(),
                },
            )
            .unwrap();
        let exact_retry = restarted
            .mark_ui_request_completed_exact(
                &grant_id,
                EgressUiCompletionBinding {
                    method: "revoke_egress",
                    request_id: "revoke-pending-request",
                    request_payload_sha256: &request_payload_sha256,
                    completion_proof_sha256: &completion_proof_sha256,
                    peer_uid: 10_123,
                    peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                    completed_at_ms: now_unix_ms(),
                },
            )
            .unwrap();
        assert_eq!(exact_retry, acknowledged);
        assert!(
            restarted
                .mark_ui_request_completed_exact(
                    &grant_id,
                    EgressUiCompletionBinding {
                        method: "revoke_egress",
                        request_id: "revoke-pending-request",
                        request_payload_sha256: &request_payload_sha256,
                        completion_proof_sha256: &sha256_bytes(
                            b"substituted-revoke-ui-completion-proof",
                        ),
                        peer_uid: 10_123,
                        peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                        completed_at_ms: now_unix_ms(),
                    },
                )
                .unwrap_err()
                .to_string()
                .contains("ui_completion_proof_changed")
        );
        assert_eq!(restarted.compact_terminal_prefix_for_test(1).unwrap(), 1);
        assert_eq!(restarted.state_for_test(&grant_id), None);
        assert!(super::replay_filter_contains(&restarted.file.compaction, &grant_id).unwrap());

        drop(restarted);
        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(reopened.state_for_test(&grant_id), None);
        assert_eq!(reopened.file.compaction.compacted_terminal_records, 1);
        assert!(super::replay_filter_contains(&reopened.file.compaction, &grant_id).unwrap());
    }

    #[test]
    fn expired_with_grant_expired_compacts_only_after_exact_ui_ack_and_reopen() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let metadata = fixture(&path, '8');
        let grant_id = metadata.grant_id.clone();
        let expires_at_ms = metadata.expires_at_ms;
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let prepared = prepare(&mut journal, metadata);
        let request_payload_sha256 = sha256_bytes(b"expired-revoke-payload");
        journal
            .mark_expired_for_revoke(
                &grant_id,
                &prepared,
                "expired-revoke-request",
                &request_payload_sha256,
                expires_at_ms,
            )
            .unwrap();
        assert_eq!(
            journal.record(&grant_id).unwrap().revoke_ui_outcome,
            Some(super::EgressRevokeUiOutcome::GrantExpired)
        );
        assert_eq!(journal.compact_terminal_prefix_for_test(1).unwrap(), 0);

        drop(journal);
        let mut restarted = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(
            restarted.state_for_test(&grant_id),
            Some(EgressLifecycleState::Expired)
        );
        assert_eq!(restarted.compact_terminal_prefix_for_test(1).unwrap(), 0);
        restarted
            .mark_ui_request_completed_exact(
                &grant_id,
                EgressUiCompletionBinding {
                    method: "revoke_egress",
                    request_id: "expired-revoke-request",
                    request_payload_sha256: &request_payload_sha256,
                    completion_proof_sha256: &sha256_bytes(b"expired-revoke-ui-completion-proof"),
                    peer_uid: 10_123,
                    peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                    completed_at_ms: now_unix_ms().max(expires_at_ms),
                },
            )
            .unwrap();
        assert_eq!(restarted.compact_terminal_prefix_for_test(1).unwrap(), 1);
        assert_eq!(restarted.state_for_test(&grant_id), None);

        drop(restarted);
        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(reopened.state_for_test(&grant_id), None);
        assert_eq!(reopened.file.compaction.compacted_terminal_records, 1);
        assert!(super::replay_filter_contains(&reopened.file.compaction, &grant_id).unwrap());
    }

    #[test]
    fn completed_runs_reclaim_headroom_at_full_production_capacity() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let now = now_unix_ms();
        let first_issued = now.saturating_sub(super::MAX_RECORDS as u64 + 1);
        let receipt_id = sha256_bytes(b"capacity receipt");
        let mut first_compacted_id = String::new();
        let template = fixture(&path, 'a');

        for index in 0..super::MAX_RECORDS {
            let mut metadata = template.clone();
            metadata.grant_id = format!(
                "egress-{}",
                sha256_bytes(format!("completed-capacity-{index}").as_bytes())
            );
            metadata.issued_at_ms = first_issued + index as u64;
            metadata.expires_at_ms = metadata.issued_at_ms + super::MAX_GRANT_TTL_MS;
            metadata.context_captured_at_ms = metadata.issued_at_ms.saturating_sub(1);
            metadata.context_expires_at_ms = metadata.expires_at_ms;
            if index == 0 {
                first_compacted_id = metadata.grant_id.clone();
            }
            let binding_sha256 = metadata.binding_sha256().unwrap();
            journal.file.records.push(super::EgressJournalRecord {
                record_version: 1,
                prepared_at_ms: metadata.issued_at_ms,
                recovery_envelope_file: recovery(&metadata.grant_id).file_name,
                recovery_envelope_sha256: recovery(&metadata.grant_id).ciphertext_sha256,
                teardown_nonce_sha256: Some(sha256_bytes(teardown_nonce().as_bytes())),
                revoke_event: None,
                revoke_ui_outcome: None,
                completion_ack_sha256: Some(sha256_bytes(b"completion-proof")),
                runtime_evidence_sha256: None,
                runtime_evidence: None,
                predispatch_binding: None,
                predispatch_binding_sha256: None,
                predispatch_task_id_sha256: None,
                direct_provider_attempt: None,
                prepare_ui_completion_ack_sha256: None,
                prepare_ui_completion_proof_sha256: None,
                revoke_ui_completion_ack_sha256: None,
                revoke_ui_completion_proof_sha256: None,
                last_transition_from_sha256: Some(sha256_bytes(b"previous-record")),
                metadata,
                binding_sha256,
                state: EgressLifecycleState::Completed,
                consumed_at_ms: Some(now),
                completed_at_ms: Some(now),
                revoked_at_ms: None,
                expired_at_ms: None,
                invalidated_restart_at_ms: None,
                interrupted_restart_at_ms: None,
                indeterminate_restart_at_ms: None,
                consent_receipt_id: Some(receipt_id.clone()),
                updated_at_ms: now,
            });
        }

        assert_eq!(journal.file.records.len(), super::MAX_RECORDS);
        journal.compact_for_headroom().unwrap();
        assert!(journal.file.records.len() <= super::COMPACTION_TARGET_RECORDS);
        assert!(!journal.file.records.is_empty());
        assert_eq!(
            journal.file.compaction.compacted_terminal_records,
            (super::MAX_RECORDS - journal.file.records.len()) as u64
        );
        assert!(
            super::replay_filter_contains(&journal.file.compaction, &first_compacted_id).unwrap()
        );
    }

    #[test]
    fn legacy_v1_file_is_migrated_to_bounded_compaction_schema() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        EgressLifecycleJournal::open_for_test(&path).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["schema"] = serde_json::json!(super::LEGACY_JOURNAL_SCHEMA);
        value.as_object_mut().unwrap().remove("compaction");
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        let migrated = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(migrated.file.schema, super::JOURNAL_SCHEMA);
        assert_eq!(migrated.file.compaction.epoch, 0);
        let durable: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(durable["schema"], super::JOURNAL_SCHEMA);
        assert!(durable.get("compaction").is_some());
    }

    #[test]
    fn legacy_v6_binding_and_child_canonical_bytes_are_frozen() {
        let binding = super::LegacyV6RuntimeLifecycleBinding {
            provider_id: "p".to_string(),
            agent_id: "a".to_string(),
            agent_peer_uid: 1,
            agent_peer_gid: 2,
            agent_selinux_domain_sha256: "1".repeat(64),
            agent_executable_sha256: "2".repeat(64),
            agent_manifest_sha256: "3".repeat(64),
            provider_invocation_id_sha256: "4".repeat(64),
            provider_session_id_sha256: "5".repeat(64),
            egress_grant_id: "g".to_string(),
            journal_binding_sha256: "6".repeat(64),
            capability_token_sha256: "7".repeat(64),
            teardown_nonce_sha256: "8".repeat(64),
            proxy_instance_credential_sha256: "9".repeat(64),
            approved_endpoint: "chatgpt.com:443".to_string(),
            upload_byte_limit: 10,
            download_byte_limit: 11,
            grant_issued_at_unix_ms: 12,
            grant_expires_at_unix_ms: 13,
        };
        let frozen_binding = concat!(
            "{\"provider_id\":\"p\",\"agent_id\":\"a\",\"agent_peer_uid\":1,\"agent_peer_gid\":2,",
            "\"agent_selinux_domain_sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"agent_executable_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
            "\"agent_manifest_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
            "\"provider_invocation_id_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
            "\"provider_session_id_sha256\":\"5555555555555555555555555555555555555555555555555555555555555555\",",
            "\"egress_grant_id\":\"g\",",
            "\"journal_binding_sha256\":\"6666666666666666666666666666666666666666666666666666666666666666\",",
            "\"capability_token_sha256\":\"7777777777777777777777777777777777777777777777777777777777777777\",",
            "\"teardown_nonce_sha256\":\"8888888888888888888888888888888888888888888888888888888888888888\",",
            "\"proxy_instance_credential_sha256\":\"9999999999999999999999999999999999999999999999999999999999999999\",",
            "\"approved_endpoint\":\"chatgpt.com:443\",\"upload_byte_limit\":10,",
            "\"download_byte_limit\":11,\"grant_issued_at_unix_ms\":12,",
            "\"grant_expires_at_unix_ms\":13}"
        );
        assert_eq!(serde_json::to_string(&binding).unwrap(), frozen_binding);
        assert_eq!(
            binding.digest_sha256().unwrap(),
            sha256_bytes(frozen_binding.as_bytes())
        );

        let child = super::LegacyV6ChildContainmentEvidence {
            lifecycle_binding_sha256: "1".repeat(64),
            provider_invocation_id_sha256: "2".repeat(64),
            provider_session_id_sha256: "3".repeat(64),
            child_pid: 4,
            session_id: 4,
            proof_scope: ChildContainmentProofScope::ProductionDedicatedUid,
            observed_process_count: 1,
            process_group_empty: true,
            observed_tree_empty: true,
            dedicated_uid: Some(5),
            dedicated_uid_preflight_empty: Some(true),
            dedicated_uid_empty: Some(true),
            executable_sha256: "4".repeat(64),
            executable_device: 6,
            executable_inode: 7,
            exact_executable_fd_verified: true,
            executable_source_read_only_mount_verified: true,
            executable_elf_image_verified: true,
            root_pidfd_custody_verified: true,
            pidfd_signalling_verified: true,
            pdeathsig_pre_exec_verified: true,
            no_new_privs_pre_exec_verified: true,
            independent_session_pre_exec_verified: true,
            rlimit_core_zero_pre_exec_verified: true,
            dumpable_zero_pre_exec_verified: true,
            inherited_fd_cloexec_pre_exec_verified: true,
            post_exec_dumpable_verified: false,
            cleanup_errors: Vec::new(),
        };
        let frozen_child = concat!(
            "{\"lifecycle_binding_sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"provider_invocation_id_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
            "\"provider_session_id_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
            "\"child_pid\":4,\"session_id\":4,\"proof_scope\":\"production_dedicated_uid\",",
            "\"observed_process_count\":1,\"process_group_empty\":true,\"observed_tree_empty\":true,",
            "\"dedicated_uid\":5,\"dedicated_uid_preflight_empty\":true,\"dedicated_uid_empty\":true,",
            "\"executable_sha256\":\"4444444444444444444444444444444444444444444444444444444444444444\",",
            "\"executable_device\":6,\"executable_inode\":7,\"exact_executable_fd_verified\":true,",
            "\"executable_source_read_only_mount_verified\":true,\"executable_elf_image_verified\":true,",
            "\"root_pidfd_custody_verified\":true,\"pidfd_signalling_verified\":true,",
            "\"pdeathsig_pre_exec_verified\":true,\"no_new_privs_pre_exec_verified\":true,",
            "\"independent_session_pre_exec_verified\":true,\"rlimit_core_zero_pre_exec_verified\":true,",
            "\"dumpable_zero_pre_exec_verified\":true,\"inherited_fd_cloexec_pre_exec_verified\":true,",
            "\"post_exec_dumpable_verified\":false,\"cleanup_errors\":[]}"
        );
        assert_eq!(serde_json::to_string(&child).unwrap(), frozen_child);
        assert_eq!(
            runtime_evidence_component_sha256(&child).unwrap(),
            sha256_bytes(frozen_child.as_bytes())
        );
    }

    #[test]
    fn legacy_v4_typed_component_golden_vectors_are_stable() {
        let child = super::LegacyV4ChildContainmentEvidence {
            lifecycle_binding_sha256: "1".repeat(64),
            provider_invocation_id_sha256: "2".repeat(64),
            provider_session_id_sha256: "3".repeat(64),
            child_pid: 42,
            session_id: 42,
            proof_scope: ChildContainmentProofScope::ProductionDedicatedUid,
            observed_process_count: 2,
            process_group_empty: true,
            observed_tree_empty: true,
            dedicated_uid: Some(5_901),
            dedicated_uid_preflight_empty: Some(true),
            dedicated_uid_empty: Some(true),
            pdeathsig_pre_exec_verified: true,
            no_new_privs_pre_exec_verified: true,
            independent_session_pre_exec_verified: true,
            rlimit_core_zero_pre_exec_verified: true,
            dumpable_zero_pre_exec_verified: true,
            post_exec_dumpable_verified: false,
            cleanup_errors: Vec::new(),
        };
        let broker = EgressBrokerOutcome {
            lifecycle_binding_sha256: "1".repeat(64),
            provider_invocation_id_sha256: "2".repeat(64),
            provider_session_id_sha256: "3".repeat(64),
            proxy_instance_credential_sha256: "4".repeat(64),
            evidence: EgressBrokerEvidence {
                approved_authority: "chatgpt.com:443".to_string(),
                validated_sni: Some("chatgpt.com".to_string()),
                resolved_candidate_ips: vec!["192.0.2.1".to_string()],
                chosen_ip: Some("192.0.2.1".to_string()),
                actual_upload_bytes: 11,
                actual_download_bytes: 22,
                started_at_unix_ms: 100,
                ended_at_unix_ms: 101,
                termination_reason: EgressBrokerTerminationReason::InvocationCompleted,
                tls_claim_scope: "connect_authority_sni_dns_bytes_ttl_only".to_string(),
            },
            error: None,
        };
        let session = ProviderSessionCleanupEvidence {
            provider_id: "openai-codex".to_string(),
            lifecycle_binding_sha256: "1".repeat(64),
            provider_invocation_id_sha256: "2".repeat(64),
            provider_session_id_sha256: "3".repeat(64),
            session_artifact_sha256: "5".repeat(64),
            cleanup_attempted: true,
            ownership_restored: true,
            cleanup_complete: true,
            cleanup_started_at_unix_ms: 102,
            cleanup_completed_at_unix_ms: 103,
            cleanup_errors: Vec::new(),
        };
        let frozen_child_json = concat!(
            "{\"lifecycle_binding_sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",",
            "\"provider_invocation_id_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
            "\"provider_session_id_sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
            "\"child_pid\":42,\"session_id\":42,\"proof_scope\":\"production_dedicated_uid\",",
            "\"observed_process_count\":2,\"process_group_empty\":true,\"observed_tree_empty\":true,",
            "\"dedicated_uid\":5901,\"dedicated_uid_preflight_empty\":true,\"dedicated_uid_empty\":true,",
            "\"pdeathsig_pre_exec_verified\":true,\"no_new_privs_pre_exec_verified\":true,",
            "\"independent_session_pre_exec_verified\":true,\"rlimit_core_zero_pre_exec_verified\":true,",
            "\"dumpable_zero_pre_exec_verified\":true,\"post_exec_dumpable_verified\":false,",
            "\"cleanup_errors\":[]}"
        );
        assert_eq!(serde_json::to_string(&child).unwrap(), frozen_child_json);
        let child_sha256 = runtime_evidence_component_sha256(&child).unwrap();
        let broker_sha256 = runtime_evidence_component_sha256(&broker).unwrap();
        let session_sha256 = runtime_evidence_component_sha256(&session).unwrap();
        assert_eq!(
            child_sha256,
            "88183f3b0b47631498456fd63980db669c81ff07f6fe7a77de152d15e7da2a89"
        );
        assert_eq!(
            broker_sha256,
            "2cf6c58eb3d030a04f45a8aa4f2d14e8494cdfc4187f71c9f82dbca8232c2abd"
        );
        assert_eq!(
            session_sha256,
            "0bf302312f0c504935bec76e11548afb5a8f26ddb612c10c616f27e60f469081"
        );
        let runtime = super::LegacyV4RuntimeEvidence {
            child_started: true,
            broker_started: true,
            provider_session_started: true,
            child: Some(child),
            child_cleanup_sha256: Some(child_sha256),
            egress: Some(broker),
            broker_outcome_sha256: Some(broker_sha256),
            provider_session_cleanup: Some(session),
            provider_session_cleanup_sha256: Some(session_sha256),
            lifecycle_binding: None,
            lifecycle_binding_sha256: None,
        };
        assert_eq!(
            sha256_json(&serde_json::to_value(runtime).unwrap()),
            "73d512993690aabaebda2bfb5e0b4c4b820e47380f60ba074074deec9c0e38ba"
        );
    }

    #[test]
    fn legacy_v4_runtime_record_reopens_as_committed_indeterminate_v5() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let metadata = fixture(&path, 'd');
        let grant_id = metadata.grant_id.clone();
        {
            let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
            let prepared = prepare(&mut journal, metadata);
            let consumed = consume(
                &mut journal,
                &grant_id,
                &prepared,
                &sha256_bytes(b"consent-receipt-v4"),
                now_unix_ms(),
            );
            complete(&mut journal, &grant_id, &consumed, now_unix_ms());
        }

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["schema"] = serde_json::json!(super::LEGACY_V4_JOURNAL_SCHEMA);
        let record = value["records"][0].as_object_mut().unwrap();
        let binding_value = record
            .get_mut("predispatch_binding")
            .unwrap()
            .as_object_mut()
            .unwrap();
        assert!(
            binding_value
                .remove("final_runtime_executable_sha256")
                .is_some()
        );
        let legacy_binding: super::LegacyV6RuntimeLifecycleBinding =
            serde_json::from_value(serde_json::Value::Object(binding_value.clone())).unwrap();
        let binding_digest = legacy_binding.digest_sha256().unwrap();
        record.insert(
            "predispatch_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );
        let runtime = record
            .get_mut("runtime_evidence")
            .unwrap()
            .as_object_mut()
            .unwrap();
        let runtime_binding = runtime
            .get_mut("lifecycle_binding")
            .unwrap()
            .as_object_mut()
            .unwrap();
        assert!(
            runtime_binding
                .remove("final_runtime_executable_sha256")
                .is_some()
        );
        assert_eq!(
            serde_json::from_value::<super::LegacyV6RuntimeLifecycleBinding>(
                serde_json::Value::Object(runtime_binding.clone())
            )
            .unwrap(),
            legacy_binding
        );
        runtime.insert(
            "lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );
        let child = runtime.get_mut("child").unwrap().as_object_mut().unwrap();
        child.insert(
            "lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );
        for post_v4 in [
            "executable_sha256",
            "executable_device",
            "executable_inode",
            "exact_executable_fd_verified",
            "executable_source_read_only_mount_verified",
            "executable_elf_image_verified",
            "root_pidfd_custody_verified",
            "pidfd_signalling_verified",
            "inherited_fd_cloexec_pre_exec_verified",
            "post_exec_selinux_domain",
            "post_exec_uid",
            "post_exec_gid",
            "post_exec_uid_gid_verified",
            "post_exec_supplementary_groups_empty_verified",
            "post_exec_no_new_privs_verified",
            "post_exec_capabilities_empty_verified",
            "post_exec_executable_identity_verified",
            "post_exec_final_runtime_executable_sha256",
            "post_exec_final_runtime_device",
            "post_exec_final_runtime_inode",
            "post_exec_final_runtime_source_read_only_mount_verified",
            "post_exec_final_runtime_elf_image_verified",
            "post_exec_independent_session_verified",
            "post_exec_parent_identity_verified",
        ] {
            assert!(child.remove(post_v4).is_some(), "missing {post_v4}");
        }
        let legacy_child: super::LegacyV4ChildContainmentEvidence =
            serde_json::from_value(runtime.get("child").unwrap().clone()).unwrap();
        let child_digest =
            trillionnium_tool_runtime::supervised_codex::runtime_evidence_component_sha256(
                &legacy_child,
            )
            .unwrap();
        runtime.insert(
            "child_cleanup_sha256".to_string(),
            serde_json::Value::String(child_digest),
        );
        let broker = runtime.get_mut("egress").unwrap().as_object_mut().unwrap();
        broker.insert(
            "lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest.clone()),
        );
        let typed_broker: EgressBrokerOutcome =
            serde_json::from_value(serde_json::Value::Object(broker.clone())).unwrap();
        runtime.insert(
            "broker_outcome_sha256".to_string(),
            serde_json::Value::String(runtime_evidence_component_sha256(&typed_broker).unwrap()),
        );
        let session = runtime
            .get_mut("provider_session_cleanup")
            .unwrap()
            .as_object_mut()
            .unwrap();
        session.insert(
            "lifecycle_binding_sha256".to_string(),
            serde_json::Value::String(binding_digest),
        );
        let typed_session: ProviderSessionCleanupEvidence =
            serde_json::from_value(serde_json::Value::Object(session.clone())).unwrap();
        runtime.insert(
            "provider_session_cleanup_sha256".to_string(),
            serde_json::Value::String(runtime_evidence_component_sha256(&typed_session).unwrap()),
        );
        // Reconstruct the exact historical typed runtime contract before
        // encoding the fixture. This prevents a Value-only self-consistency
        // test from hiding typed component field-order drift.
        let legacy_runtime: super::LegacyV4RuntimeEvidence =
            serde_json::from_value(serde_json::Value::Object(runtime.clone())).unwrap();
        assert!(legacy_runtime.closed_presence_shape_proven());
        let typed_runtime_value = serde_json::to_value(&legacy_runtime).unwrap();
        assert_eq!(
            typed_runtime_value,
            serde_json::Value::Object(runtime.clone())
        );
        let runtime_digest = sha256_json(&typed_runtime_value);
        record.insert("runtime_evidence".to_string(), typed_runtime_value);
        record.insert(
            "runtime_evidence_sha256".to_string(),
            serde_json::Value::String(runtime_digest),
        );
        let legacy_record_sha256 = sha256_json(&serde_json::Value::Object(record.clone()));
        let mut encoded = serde_json::to_vec_pretty(&value).unwrap();
        encoded.push(b'\n');
        fs::write(&path, encoded).unwrap();

        let migrated = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let record = migrated.record(&grant_id).unwrap();
        assert_eq!(migrated.file.schema, super::JOURNAL_SCHEMA);
        assert_eq!(record.state, EgressLifecycleState::IndeterminateRestart);
        assert!(record.indeterminate_restart_at_ms.is_some());
        assert_eq!(
            record.last_transition_from_sha256.as_deref(),
            Some(legacy_record_sha256.as_str())
        );
        assert!(record.runtime_evidence.is_none());
        assert!(record.runtime_evidence_sha256.is_none());
        assert!(record.completion_ack_sha256.is_none());
        drop(migrated);

        let reopened = EgressLifecycleJournal::open_for_test(&path).unwrap();
        assert_eq!(
            reopened.state_for_test(&grant_id),
            Some(EgressLifecycleState::IndeterminateRestart)
        );
    }

    #[test]
    fn wrong_binding_is_rejected_before_any_transition() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let metadata = fixture(&path, 'e');
        let grant_id = metadata.grant_id.clone();
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let binding = prepare(&mut journal, metadata);
        let wrong = EgressJournalCas {
            binding_sha256: "f".repeat(64),
            ..binding.clone()
        };
        assert!(
            journal
                .mark_consumed(
                    &grant_id,
                    &wrong,
                    &"c".repeat(64),
                    &sha256_bytes(teardown_nonce().as_bytes()),
                    now_unix_ms(),
                )
                .is_err()
        );
        assert_eq!(
            journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Prepared)
        );
        journal
            .mark_consumed(
                &grant_id,
                &binding,
                &"c".repeat(64),
                &sha256_bytes(teardown_nonce().as_bytes()),
                now_unix_ms(),
            )
            .unwrap();
    }

    #[test]
    fn corruption_permissions_and_symlinks_fail_closed() {
        let loose_parent = tempfile::tempdir().unwrap();
        fs::set_permissions(loose_parent.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            EgressLifecycleJournal::open_for_test(&loose_parent.path().join("journal.json"))
                .is_err()
        );

        let temp = private_temp();
        let path = temp.path().join("corrupt.json");
        EgressLifecycleJournal::open_for_test(&path).unwrap();
        fs::write(&path, b"{not-json").unwrap();
        assert!(EgressLifecycleJournal::open_for_test(&path).is_err());

        let mode_path = temp.path().join("mode.json");
        EgressLifecycleJournal::open_for_test(&mode_path).unwrap();
        fs::set_permissions(&mode_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(EgressLifecycleJournal::open_for_test(&mode_path).is_err());

        let target = temp.path().join("target.json");
        fs::write(&target, b"{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = temp.path().join("link.json");
        symlink(&target, &link).unwrap();
        assert!(EgressLifecycleJournal::open_for_test(&link).is_err());
    }

    #[test]
    fn writable_journal_ancestor_is_rejected_before_parent_creation() {
        let temp = private_temp();
        let unsafe_ancestor = temp.path().join("unsafe-ancestor");
        fs::create_dir(&unsafe_ancestor).unwrap();
        fs::set_permissions(&unsafe_ancestor, fs::Permissions::from_mode(0o777)).unwrap();
        let private_parent = unsafe_ancestor.join("private-parent");
        let error = EgressLifecycleJournal::open_for_test(&private_parent.join("journal.json"))
            .err()
            .expect("writable ancestor must be rejected")
            .to_string();

        assert!(error.contains("android_egress_journal_unsafe_ancestor"));
        assert!(!private_parent.exists());
    }

    #[test]
    fn runtime_corruption_cannot_be_overwritten_by_a_lifecycle_transition() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let metadata = fixture(&path, '9');
        let grant_id = metadata.grant_id.clone();
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let binding = prepare(&mut journal, metadata);
        fs::write(&path, b"{runtime-corruption").unwrap();
        let denied = journal
            .mark_consumed(
                &grant_id,
                &binding,
                &"c".repeat(64),
                &sha256_bytes(teardown_nonce().as_bytes()),
                now_unix_ms(),
            )
            .expect_err("unexpected journal mutation must fail closed");
        assert!(denied.to_string().contains("changed_outside_atomic_writer"));
        assert_eq!(
            journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Prepared)
        );
    }

    #[test]
    fn journal_never_contains_raw_context_source_or_complete_intent() {
        let temp = private_temp();
        let path = temp.path().join("egress.json");
        let mut journal = EgressLifecycleJournal::open_for_test(&path).unwrap();
        let metadata = fixture(&path, 'f');
        prepare(&mut journal, metadata);
        let encoded = fs::read_to_string(path).unwrap();
        for secret in [
            "raw secret context",
            "raw secret source",
            "raw secret intent",
            "private-workflow",
            "u:r:trillionnium_aishell:s0",
        ] {
            assert!(!encoded.contains(secret));
        }
    }
}
