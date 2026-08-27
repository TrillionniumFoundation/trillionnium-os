//! Encrypted, crash-safe OS-UI plan and action-consent saga journal.
//!
//! Network planning has a uniquely dangerous crash boundary: the provider may
//! have consumed a one-shot egress grant while the outer UI replay is still
//! `in_progress`.  This journal records `provider_pending` before dispatch and
//! an encrypted `provider_ready` result immediately after the provider returns.
//! Startup reconciliation may resume only the deterministic local stages after
//! `provider_ready`; it never repeats provider/network work.  UI replay
//! recovery itself is query-only.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(test)]
use std::sync::{Arc, Barrier};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trillionnium_os_types::agent_principal_registry::{self, CODEX_STABLE_PRINCIPAL as CODEX};
use trillionnium_os_types::direct_agent_host_abi;
use trillionnium_os_types::direct_operation::DirectOperationBinding;
use trillionnium_os_types::{AgentRegistration, now_unix_ms, sha256_bytes, sha256_json};
use trillionnium_tool_runtime::supervised_codex::{
    CODEX_DIRECT_MCP_TOOL_NAMES, CodexDirectToolCallEvidence, DirectBackendEffectClass,
    codex_direct_mcp_identity_is_authorized, codex_direct_mcp_tool_name_is_authorized,
    direct_backend_error_effect_class,
};
use zeroize::Zeroizing;

use crate::codex_adapter::CompletedShellExecAuthorizationV1;
use crate::context_memory::ContextMemoryService;

const JOURNAL_SCHEMA: &str = "trillionnium.action-workflow-journal.v2";
const SECRET_SCHEMA: &str = "trillionnium.action-workflow-secret.v2";
const AAD_SCHEMA: &str = "trillionnium.action-workflow-aad.v2";
const JOURNAL_FILE: &str = "action-workflow-v2.json";
const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_SECRET_BYTES: usize = 768 * 1024;
const MAX_RECORDS: usize = 256;
const MAX_TOMBSTONES: usize = 4_096;
const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
pub(crate) const RETIRED_NON_DIRECT_WORKFLOW_REASON: &str =
    "legacy_provider_execution_retired_by_agent_direct_v1";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlanRecoveryBinding {
    pub method: String,
    pub request_id: String,
    pub request_payload_sha256: String,
    pub subject_uid: u32,
    pub subject_selinux_domain: String,
    pub provider_id: String,
    pub task_id: String,
    pub plan_id: String,
    pub action_id: String,
    pub tool_call_id: String,
    pub accepted_plan_sha256: String,
    pub challenge_sha256: String,
    pub challenge_expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PlanSagaStage {
    ProviderPending,
    ProviderReady,
    PlanPrepared,
    PlanSubmitted,
    ActionDispatched,
    PayloadStaged,
    PlanReady,
    Indeterminate,
}

impl PlanSagaStage {
    fn rank(self) -> u8 {
        match self {
            Self::ProviderPending => 0,
            Self::ProviderReady => 1,
            Self::PlanPrepared => 2,
            Self::PlanSubmitted => 3,
            Self::ActionDispatched => 4,
            Self::PayloadStaged => 5,
            Self::PlanReady => 6,
            Self::Indeterminate => 7,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ActionConsentState {
    Pending,
    Consuming,
    Consumed,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConsumingApprovalBinding {
    pub approve_request_id: String,
    pub approve_payload_sha256: String,
    pub action_consent_receipt_id: String,
    pub started_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableActionConsent {
    state: ActionConsentState,
    challenge: Value,
    consuming: Option<ConsumingApprovalBinding>,
    consumed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowSecret {
    schema: String,
    local_state: Value,
    exact_plan_response: Option<Value>,
    action_consent: Option<DurableActionConsent>,
    indeterminate_reason: Option<String>,
    #[serde(default)]
    plan_ui_completion_proof_sha256: Option<String>,
    #[serde(default)]
    approve_ui_completion_proof_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedWorkflowRecord {
    record_version: u32,
    binding: PlanRecoveryBinding,
    stage: PlanSagaStage,
    ciphertext_b64: String,
    ciphertext_sha256: String,
    created_at_ms: u64,
    updated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkflowTombstone {
    binding: PlanRecoveryBinding,
    disposition: String,
    archived_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionWorkflowFile {
    schema: String,
    records: Vec<EncryptedWorkflowRecord>,
    tombstones: Vec<WorkflowTombstone>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DurableActionConsentView {
    pub state: ActionConsentState,
    pub challenge: Value,
    pub consuming: Option<ConsumingApprovalBinding>,
    pub binding: PlanRecoveryBinding,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DurableWorkflowView {
    pub stage: PlanSagaStage,
    pub binding: PlanRecoveryBinding,
    pub local_state: Value,
    pub exact_plan_response: Option<Value>,
    pub action_consent: Option<DurableActionConsentView>,
    pub indeterminate_reason: Option<String>,
}

pub(crate) struct PlanReadyPublication {
    pub expected_stage: PlanSagaStage,
    pub binding: PlanRecoveryBinding,
    pub local_state: Value,
    pub exact_plan_response: Value,
    pub challenge: Option<Value>,
}

#[derive(Debug)]
pub(crate) enum PlanWorkflowRecovery {
    Absent,
    Ready(Value),
    Resumable,
    Indeterminate(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionWorkflowUiCustodyBinding {
    pub method: String,
    pub request_id: String,
    pub request_payload_sha256: String,
    pub subject_uid: u32,
    pub subject_selinux_domain: String,
    pub completion_proof_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActionWorkflowCustodyCandidate {
    pub plan: ActionWorkflowUiCustodyBinding,
    pub approve: Option<ActionWorkflowUiCustodyBinding>,
    record_request_id: String,
    record_fingerprint_sha256: String,
    compact_after_handoff: bool,
    disposition: String,
}

/// Read-only, sealed projection of one exact Direct `PlanReady` generation.
///
/// Production code can obtain this value only by asking the encrypted journal
/// to validate a structurally valid daemon-internal [`DirectOperationBinding`]
/// against the exact encrypted PlanReady record.  It is not serializable and
/// its fields stay private so a digest supplied by an outer caller cannot be
/// promoted into custody authority.  This type does not acknowledge UI replay,
/// compact the action journal, or dispatch any effect.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Inert until the daemon-only custody coordinator is wired.
pub(crate) struct DirectPlanCustodyCandidate {
    direct_binding: DirectOperationBinding,
    direct_binding_sha256: String,
    workflow_binding: PlanRecoveryBinding,
    record_fingerprint_sha256: String,
    exact_plan_response: Value,
    exact_plan_response_semantic_sha256: String,
    direct_execution_receipt_sha256: String,
    plan_ui_completion_proof_sha256: Option<String>,
}

#[allow(dead_code)] // Getters are the sealed future custody/UI snapshot seam.
impl DirectPlanCustodyCandidate {
    pub(crate) fn direct_binding(&self) -> &DirectOperationBinding {
        &self.direct_binding
    }

    pub(crate) fn direct_binding_sha256(&self) -> &str {
        &self.direct_binding_sha256
    }

    pub(crate) fn workflow_binding(&self) -> &PlanRecoveryBinding {
        &self.workflow_binding
    }

    pub(crate) fn request_id(&self) -> &str {
        &self.workflow_binding.request_id
    }

    pub(crate) fn request_payload_sha256(&self) -> &str {
        &self.workflow_binding.request_payload_sha256
    }

    pub(crate) fn subject_uid(&self) -> u32 {
        self.workflow_binding.subject_uid
    }

    pub(crate) fn subject_selinux_domain(&self) -> &str {
        &self.workflow_binding.subject_selinux_domain
    }

    pub(crate) fn record_fingerprint_sha256(&self) -> &str {
        &self.record_fingerprint_sha256
    }

    /// Exact validated `PlanReady` value.  This crate-private view exists only
    /// so ContextMemory can apply its single existing replay sanitizer; it is
    /// never an external API or a model-visible value.
    pub(crate) fn exact_plan_response(&self) -> &Value {
        &self.exact_plan_response
    }

    pub(crate) fn exact_plan_response_semantic_sha256(&self) -> &str {
        &self.exact_plan_response_semantic_sha256
    }

    pub(crate) fn direct_execution_receipt_sha256(&self) -> &str {
        &self.direct_execution_receipt_sha256
    }

    pub(crate) fn plan_ui_completion_proof_sha256(&self) -> Option<&str> {
        self.plan_ui_completion_proof_sha256.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        direct_binding: DirectOperationBinding,
        workflow_binding: PlanRecoveryBinding,
        record_fingerprint_sha256: String,
        exact_plan_response: Value,
        plan_ui_completion_proof_sha256: Option<String>,
    ) -> Result<Self> {
        direct_binding
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        validate_binding(&workflow_binding)?;
        if !valid_digest(&record_fingerprint_sha256)
            || plan_ui_completion_proof_sha256
                .as_deref()
                .is_some_and(|digest| !valid_digest(digest))
        {
            bail!("direct_plan_custody_test_fixture_digest_denied");
        }
        let direct_binding_sha256 = direct_binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let direct_execution_receipt_sha256 = exact_plan_response
            .get("direct_execution_receipt_sha256")
            .and_then(Value::as_str)
            .filter(|digest| valid_digest(digest))
            .context("direct_plan_custody_test_fixture_receipt_missing")?
            .to_string();
        let exact_plan_response_semantic_sha256 = sha256_json(&exact_plan_response);
        Ok(Self {
            direct_binding,
            direct_binding_sha256,
            workflow_binding,
            record_fingerprint_sha256,
            exact_plan_response,
            exact_plan_response_semantic_sha256,
            direct_execution_receipt_sha256,
            plan_ui_completion_proof_sha256,
        })
    }
}

pub(crate) struct ActionWorkflowJournal {
    path: PathBuf,
    owner_uid: u32,
    file: ActionWorkflowFile,
    persisted_sha256: Option<String>,
    publication_durability_uncertain: bool,
    #[cfg(test)]
    fail_parent_fsync_after_rename_once: bool,
    #[cfg(test)]
    custody_snapshot_barrier: Option<Arc<Barrier>>,
    #[cfg(test)]
    custody_snapshot_barrier_fired: AtomicBool,
}

impl ActionWorkflowJournal {
    pub(crate) fn open(context_memory: &ContextMemoryService) -> Result<Self> {
        let root = context_memory.action_workflow_root()?;
        Self::open_at(context_memory, &root.join(JOURNAL_FILE))
    }

    #[cfg(test)]
    pub(crate) fn open_for_test(
        context_memory: &ContextMemoryService,
        path: &Path,
    ) -> Result<Self> {
        Self::open_at(context_memory, path)
    }

    fn open_at(context_memory: &ContextMemoryService, path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            bail!("action_workflow_journal_path_not_absolute");
        }
        let owner_uid = unsafe { libc::geteuid() };
        let parent = path
            .parent()
            .context("action_workflow_journal_parent_missing")?;
        ensure_private_parent(parent, owner_uid)?;
        cleanup_owned_action_workflow_temps(parent, owner_uid)?;
        // Resolve a predecessor's rename-visible/parent-fsync-unknown state
        // before trusting the current generation for query-only recovery.
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("action_workflow_parent_redurabilization_failed")?;
        let (file, persisted_sha256) = match read_owner_controlled(path, owner_uid)? {
            Some(bytes) => {
                let file: ActionWorkflowFile = serde_json::from_slice(&bytes)
                    .context("invalid_action_workflow_journal_json")?;
                let mut canonical = serde_json::to_vec_pretty(&file)?;
                canonical.push(b'\n');
                if canonical != bytes {
                    bail!("action_workflow_journal_not_canonical_closed_world_json");
                }
                (file, Some(sha256_bytes(&bytes)))
            }
            None => (
                ActionWorkflowFile {
                    schema: JOURNAL_SCHEMA.to_string(),
                    records: Vec::new(),
                    tombstones: Vec::new(),
                },
                None,
            ),
        };
        validate_file(context_memory, &file, now_unix_ms())?;
        let mut journal = Self {
            path: path.to_path_buf(),
            owner_uid,
            file,
            persisted_sha256,
            publication_durability_uncertain: false,
            #[cfg(test)]
            fail_parent_fsync_after_rename_once: false,
            #[cfg(test)]
            custody_snapshot_barrier: None,
            #[cfg(test)]
            custody_snapshot_barrier_fired: AtomicBool::new(false),
        };
        if journal.persisted_sha256.is_none() {
            journal.flush(context_memory)?;
        }
        Ok(journal)
    }

    pub(crate) fn begin_provider_pending(
        &mut self,
        context_memory: &ContextMemoryService,
        binding: PlanRecoveryBinding,
        local_state: Value,
    ) -> Result<()> {
        self.ensure_mutable()?;
        validate_initial_binding(&binding)?;
        if self.request_exists(&binding.request_id) {
            bail!("action_workflow_request_id_binding_conflict");
        }
        if self.file.records.len() >= MAX_RECORDS {
            bail!("action_workflow_active_capacity_reached");
        }
        let now = now_unix_ms();
        let secret = WorkflowSecret {
            schema: SECRET_SCHEMA.to_string(),
            local_state,
            exact_plan_response: None,
            action_consent: None,
            indeterminate_reason: None,
            plan_ui_completion_proof_sha256: None,
            approve_ui_completion_proof_sha256: None,
        };
        let record = encrypt_record(
            context_memory,
            binding,
            PlanSagaStage::ProviderPending,
            &secret,
            now,
            now,
        )?;
        let previous = self.file.clone();
        self.file.records.push(record);
        if let Err(error) = self.flush(context_memory) {
            if !self.publication_durability_uncertain {
                self.file = previous;
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn transition(
        &mut self,
        context_memory: &ContextMemoryService,
        request_id: &str,
        expected_stage: PlanSagaStage,
        binding: PlanRecoveryBinding,
        next_stage: PlanSagaStage,
        local_state: Value,
    ) -> Result<()> {
        if next_stage == PlanSagaStage::Indeterminate
            || next_stage.rank() != expected_stage.rank().saturating_add(1)
        {
            bail!("action_workflow_invalid_stage_transition");
        }
        let index = self.record_index(request_id)?;
        let current = &self.file.records[index];
        validate_transition_binding(&current.binding, &binding)?;
        let candidate = WorkflowSecret {
            schema: SECRET_SCHEMA.to_string(),
            local_state,
            exact_plan_response: None,
            action_consent: None,
            indeterminate_reason: None,
            plan_ui_completion_proof_sha256: None,
            approve_ui_completion_proof_sha256: None,
        };
        if current.stage == next_stage {
            let existing = decrypt_record(context_memory, current)?;
            if current.binding == binding && existing == candidate {
                return Ok(());
            }
            bail!("action_workflow_idempotent_transition_mismatch");
        }
        if current.stage != expected_stage {
            bail!("action_workflow_stage_compare_and_swap_failed");
        }
        let now = now_unix_ms();
        let replacement = encrypt_record(
            context_memory,
            binding,
            next_stage,
            &candidate,
            current.created_at_ms,
            now,
        )?;
        self.replace_record(context_memory, index, replacement)
    }

    pub(crate) fn publish_plan_ready(
        &mut self,
        context_memory: &ContextMemoryService,
        request_id: &str,
        publication: PlanReadyPublication,
    ) -> Result<()> {
        let PlanReadyPublication {
            expected_stage,
            binding,
            local_state,
            exact_plan_response,
            challenge,
        } = publication;
        if !matches!(
            expected_stage,
            PlanSagaStage::ProviderReady | PlanSagaStage::PayloadStaged
        ) {
            bail!("action_workflow_invalid_ready_source_stage");
        }
        let index = self.record_index(request_id)?;
        let current = &self.file.records[index];
        validate_transition_binding(&current.binding, &binding)?;
        let action_consent = challenge.map(|challenge| DurableActionConsent {
            state: ActionConsentState::Pending,
            challenge,
            consuming: None,
            consumed_at_ms: None,
        });
        let candidate = WorkflowSecret {
            schema: SECRET_SCHEMA.to_string(),
            local_state,
            exact_plan_response: Some(exact_plan_response),
            action_consent,
            indeterminate_reason: None,
            plan_ui_completion_proof_sha256: None,
            approve_ui_completion_proof_sha256: None,
        };
        if current.stage == PlanSagaStage::PlanReady {
            let existing = decrypt_record(context_memory, current)?;
            if current.binding == binding && existing == candidate {
                return Ok(());
            }
            bail!("action_workflow_idempotent_ready_mismatch");
        }
        if current.stage != expected_stage {
            bail!("action_workflow_ready_compare_and_swap_failed");
        }
        let now = now_unix_ms();
        let replacement = encrypt_record(
            context_memory,
            binding,
            PlanSagaStage::PlanReady,
            &candidate,
            current.created_at_ms,
            now,
        )?;
        self.replace_record(context_memory, index, replacement)
    }

    pub(crate) fn mark_indeterminate(
        &mut self,
        context_memory: &ContextMemoryService,
        request_id: &str,
        reason: &str,
    ) -> Result<()> {
        if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
            bail!("invalid_action_workflow_indeterminate_reason");
        }
        let index = self.record_index(request_id)?;
        if self.file.records[index].stage == PlanSagaStage::PlanReady {
            bail!("ready_action_workflow_cannot_be_downgraded");
        }
        let current = &self.file.records[index];
        let mut secret = decrypt_record(context_memory, current)?;
        if current.stage == PlanSagaStage::Indeterminate {
            if secret.indeterminate_reason.as_deref() == Some(reason) {
                return Ok(());
            }
            bail!("action_workflow_indeterminate_reason_mismatch");
        }
        secret.local_state = Value::Null;
        secret.exact_plan_response = None;
        secret.action_consent = None;
        secret.indeterminate_reason = Some(reason.to_string());
        let now = now_unix_ms();
        let replacement = encrypt_record(
            context_memory,
            current.binding.clone(),
            PlanSagaStage::Indeterminate,
            &secret,
            current.created_at_ms,
            now,
        )?;
        self.replace_record(context_memory, index, replacement)
    }

    /// Quarantine a pre-direct workflow without replaying or resuming any of
    /// its plan, approval, Authority, or undo surface. Unlike the general
    /// indeterminate transition, this deliberately accepts a historical
    /// PlanReady record, but only after proving that its frozen result is not
    /// AgentDirect. Old journal bytes stay readable while their effect path is
    /// made terminal and non-replayable.
    pub(crate) fn retire_non_direct_workflow(
        &mut self,
        context_memory: &ContextMemoryService,
        request_id: &str,
    ) -> Result<()> {
        let index = self.record_index(request_id)?;
        let current = &self.file.records[index];
        let mut secret = decrypt_record(context_memory, current)?;
        if current.stage == PlanSagaStage::Indeterminate {
            if secret.indeterminate_reason.as_deref() == Some(RETIRED_NON_DIRECT_WORKFLOW_REASON) {
                return Ok(());
            }
            bail!("action_workflow_indeterminate_reason_mismatch");
        }
        let direct = match current.stage {
            PlanSagaStage::ProviderReady | PlanSagaStage::PlanReady => {
                secret
                    .local_state
                    .pointer("/provider_result/execution_mode")
                    .and_then(Value::as_str)
                    == Some("agent_direct")
            }
            PlanSagaStage::PlanPrepared
            | PlanSagaStage::PlanSubmitted
            | PlanSagaStage::ActionDispatched
            | PlanSagaStage::PayloadStaged => false,
            PlanSagaStage::ProviderPending | PlanSagaStage::Indeterminate => {
                bail!("action_workflow_non_direct_retirement_stage_denied")
            }
        };
        if direct {
            bail!("agent_direct_workflow_retirement_denied");
        }
        secret.local_state = Value::Null;
        secret.exact_plan_response = None;
        secret.action_consent = None;
        secret.approve_ui_completion_proof_sha256 = None;
        secret.indeterminate_reason = Some(RETIRED_NON_DIRECT_WORKFLOW_REASON.to_string());
        let now = now_unix_ms();
        let replacement = encrypt_record(
            context_memory,
            current.binding.clone(),
            PlanSagaStage::Indeterminate,
            &secret,
            current.created_at_ms,
            now,
        )?;
        self.replace_record(context_memory, index, replacement)
    }

    pub(crate) fn recover_plan(
        &self,
        context_memory: &ContextMemoryService,
        request_id: &str,
        request_payload_sha256: &str,
        subject_uid: u32,
        subject_selinux_domain: &str,
    ) -> Result<PlanWorkflowRecovery> {
        if let Some(record) = self
            .file
            .records
            .iter()
            .find(|record| record.binding.request_id == request_id)
        {
            validate_recovery_identity(
                &record.binding,
                request_payload_sha256,
                subject_uid,
                subject_selinux_domain,
            )?;
            let secret = decrypt_record(context_memory, record)?;
            return match record.stage {
                PlanSagaStage::PlanReady => {
                    let response = secret
                        .exact_plan_response
                        .context("ready_action_workflow_response_missing")?;
                    if response.get("execution_mode").and_then(Value::as_str)
                        != Some("agent_direct")
                    {
                        Ok(PlanWorkflowRecovery::Indeterminate(
                            RETIRED_NON_DIRECT_WORKFLOW_REASON.to_string(),
                        ))
                    } else {
                        Ok(PlanWorkflowRecovery::Ready(response))
                    }
                }
                PlanSagaStage::Indeterminate | PlanSagaStage::ProviderPending => {
                    Ok(PlanWorkflowRecovery::Indeterminate(
                        secret.indeterminate_reason.unwrap_or_else(|| {
                            "provider_outcome_unknown_no_network_reexecution".to_string()
                        }),
                    ))
                }
                _ => Ok(PlanWorkflowRecovery::Resumable),
            };
        }
        if let Some(tombstone) = self
            .file
            .tombstones
            .iter()
            .find(|item| item.binding.request_id == request_id)
        {
            validate_recovery_identity(
                &tombstone.binding,
                request_payload_sha256,
                subject_uid,
                subject_selinux_domain,
            )?;
            return Ok(PlanWorkflowRecovery::Indeterminate(
                tombstone.disposition.clone(),
            ));
        }
        Ok(PlanWorkflowRecovery::Absent)
    }

    pub(crate) fn restart_candidates(&self) -> Vec<(String, PlanSagaStage)> {
        self.file
            .records
            .iter()
            .filter(|record| {
                matches!(
                    record.stage,
                    PlanSagaStage::ProviderPending
                        | PlanSagaStage::ProviderReady
                        | PlanSagaStage::PlanPrepared
                        | PlanSagaStage::PlanSubmitted
                        | PlanSagaStage::ActionDispatched
                        | PlanSagaStage::PayloadStaged
                        | PlanSagaStage::PlanReady
                )
            })
            .map(|record| (record.binding.request_id.clone(), record.stage))
            .collect()
    }

    pub(crate) fn workflow_for_reconcile(
        &self,
        context_memory: &ContextMemoryService,
        request_id: &str,
    ) -> Result<DurableWorkflowView> {
        let index = self.record_index(request_id)?;
        let record = &self.file.records[index];
        let secret = decrypt_record(context_memory, record)?;
        Ok(workflow_view(record, secret))
    }

    #[cfg(test)]
    pub(crate) fn pending_challenge(
        &mut self,
        context_memory: &ContextMemoryService,
        approval_id: &str,
        now: u64,
    ) -> Result<Value> {
        let index = self.action_record_index(context_memory, approval_id)?;
        let record = &self.file.records[index];
        let mut secret = decrypt_record(context_memory, record)?;
        let action = secret
            .action_consent
            .as_mut()
            .context("action_consent_challenge_missing_or_consumed")?;
        if action.state != ActionConsentState::Pending {
            bail!("action_consent_challenge_missing_or_consumed");
        }
        if record.binding.challenge_expires_at_ms <= now {
            action.state = ActionConsentState::Expired;
            let replacement = encrypt_record(
                context_memory,
                record.binding.clone(),
                record.stage,
                &secret,
                record.created_at_ms,
                now,
            )?;
            self.replace_record(context_memory, index, replacement)?;
            bail!("action_consent_expired");
        }
        Ok(action.challenge.clone())
    }

    #[cfg(test)]
    pub(crate) fn action_view(
        &self,
        context_memory: &ContextMemoryService,
        approval_id: &str,
    ) -> Result<DurableActionConsentView> {
        let index = self.action_record_index(context_memory, approval_id)?;
        let record = &self.file.records[index];
        let secret = decrypt_record(context_memory, record)?;
        let action = secret
            .action_consent
            .context("action_consent_challenge_missing_or_consumed")?;
        Ok(DurableActionConsentView {
            state: action.state,
            challenge: action.challenge,
            consuming: action.consuming,
            binding: record.binding.clone(),
        })
    }

    pub(crate) fn consuming_actions(
        &self,
        context_memory: &ContextMemoryService,
    ) -> Result<Vec<(String, DurableActionConsentView)>> {
        let mut values = Vec::new();
        for record in &self.file.records {
            if record.stage != PlanSagaStage::PlanReady {
                continue;
            }
            let secret = decrypt_record(context_memory, record)?;
            let Some(action) = secret.action_consent else {
                continue;
            };
            if action.state != ActionConsentState::Consuming {
                continue;
            }
            let approval_id = action
                .challenge
                .get("approval_id")
                .and_then(Value::as_str)
                .context("consuming_action_consent_approval_id_missing")?
                .to_string();
            values.push((
                approval_id,
                DurableActionConsentView {
                    state: action.state,
                    challenge: action.challenge,
                    consuming: action.consuming,
                    binding: record.binding.clone(),
                },
            ));
        }
        Ok(values)
    }

    #[cfg(test)]
    pub(crate) fn begin_consuming(
        &mut self,
        context_memory: &ContextMemoryService,
        approval_id: &str,
        binding: ConsumingApprovalBinding,
    ) -> Result<()> {
        validate_consuming(&binding, now_unix_ms())?;
        let index = self.action_record_index(context_memory, approval_id)?;
        let record = &self.file.records[index];
        let mut secret = decrypt_record(context_memory, record)?;
        let action = secret
            .action_consent
            .as_mut()
            .context("action_consent_challenge_missing_or_consumed")?;
        if action.state == ActionConsentState::Consuming
            && action.consuming.as_ref() == Some(&binding)
        {
            return Ok(());
        }
        if action.state != ActionConsentState::Pending
            || record.binding.challenge_expires_at_ms <= binding.started_at_ms
        {
            bail!("action_consent_not_pending_before_consume");
        }
        action.state = ActionConsentState::Consuming;
        action.consuming = Some(binding.clone());
        let replacement = encrypt_record(
            context_memory,
            record.binding.clone(),
            record.stage,
            &secret,
            record.created_at_ms,
            binding.started_at_ms,
        )?;
        self.replace_record(context_memory, index, replacement)
    }

    pub(crate) fn mark_consumed(
        &mut self,
        context_memory: &ContextMemoryService,
        approval_id: &str,
        consuming: &ConsumingApprovalBinding,
        consumed_at_ms: u64,
    ) -> Result<()> {
        let index = self.action_record_index(context_memory, approval_id)?;
        let record = &self.file.records[index];
        let mut secret = decrypt_record(context_memory, record)?;
        let action = secret
            .action_consent
            .as_mut()
            .context("action_consent_challenge_missing_or_consumed")?;
        if action.state == ActionConsentState::Consumed
            && action.consuming.as_ref() == Some(consuming)
        {
            return Ok(());
        }
        if action.state != ActionConsentState::Consuming
            || action.consuming.as_ref() != Some(consuming)
            || consumed_at_ms < consuming.started_at_ms
        {
            bail!("action_consent_consuming_binding_mismatch");
        }
        action.state = ActionConsentState::Consumed;
        action.consumed_at_ms = Some(consumed_at_ms);
        let replacement = encrypt_record(
            context_memory,
            record.binding.clone(),
            record.stage,
            &secret,
            record.created_at_ms,
            consumed_at_ms,
        )?;
        self.replace_record(context_memory, index, replacement)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_ui_completion_proof(
        &mut self,
        context_memory: &ContextMemoryService,
        method: &str,
        request_id: &str,
        subject_uid: u32,
        subject_selinux_domain: &str,
        request_payload_sha256: &str,
        completion_proof_sha256: &str,
    ) -> Result<()> {
        if !valid_digest(completion_proof_sha256) {
            bail!("action_workflow_ui_completion_proof_digest_denied");
        }
        let (index, mut secret) = if method == "plan" {
            let index = self.record_index(request_id)?;
            let record = &self.file.records[index];
            validate_recovery_identity(
                &record.binding,
                request_payload_sha256,
                subject_uid,
                subject_selinux_domain,
            )?;
            if !matches!(
                record.stage,
                PlanSagaStage::PlanReady | PlanSagaStage::Indeterminate
            ) {
                bail!("action_workflow_plan_completion_stage_denied");
            }
            (index, decrypt_record(context_memory, record)?)
        } else if method == "approve" {
            let mut selected = None;
            for (index, record) in self.file.records.iter().enumerate() {
                if record.binding.subject_uid != subject_uid
                    || record.binding.subject_selinux_domain != subject_selinux_domain
                    || record.stage != PlanSagaStage::PlanReady
                {
                    continue;
                }
                let secret = decrypt_record(context_memory, record)?;
                let matches = secret.action_consent.as_ref().is_some_and(|action| {
                    action.state == ActionConsentState::Consumed
                        && action.consuming.as_ref().is_some_and(|consuming| {
                            consuming.approve_request_id == request_id
                                && consuming.approve_payload_sha256 == request_payload_sha256
                        })
                });
                if matches {
                    if selected.is_some() {
                        bail!("action_workflow_approve_completion_binding_ambiguous");
                    }
                    selected = Some((index, secret));
                }
            }
            selected.context("action_workflow_approve_completion_binding_missing")?
        } else {
            bail!("action_workflow_ui_completion_method_denied");
        };
        let slot = if method == "plan" {
            &mut secret.plan_ui_completion_proof_sha256
        } else {
            &mut secret.approve_ui_completion_proof_sha256
        };
        if let Some(existing) = slot.as_deref() {
            if existing != completion_proof_sha256 {
                bail!("action_workflow_ui_completion_proof_substitution_denied");
            }
            return Ok(());
        }
        *slot = Some(completion_proof_sha256.to_string());
        let record = &self.file.records[index];
        let replacement = encrypt_record(
            context_memory,
            record.binding.clone(),
            record.stage,
            &secret,
            record.created_at_ms,
            now_unix_ms(),
        )?;
        self.replace_record(context_memory, index, replacement)
    }

    /// Collect exact UI-custody work while the action journal is locked.
    ///
    /// This method deliberately never enters the UI replay journal. Callers
    /// must release the action lock, verify/acknowledge each returned UI proof,
    /// and only then re-lock and call `compact_custody_candidate_exact`.
    pub(crate) fn custody_candidates(
        &self,
        context_memory: &ContextMemoryService,
    ) -> Result<Vec<ActionWorkflowCustodyCandidate>> {
        #[cfg(test)]
        if let Some(barrier) = self.custody_snapshot_barrier.as_ref()
            && !self
                .custody_snapshot_barrier_fired
                .swap(true, Ordering::SeqCst)
        {
            barrier.wait();
        }
        let mut candidates = Vec::new();
        for record in &self.file.records {
            let secret = decrypt_record(context_memory, record)?;
            // Direct PlanReady is reserved for the pending direct-custody
            // handoff.  The legacy UI-custody reconciler must never
            // acknowledge its replay record or replace its exact encrypted
            // result with a tombstone.  Until that separate handoff exists,
            // retained Direct records intentionally consume bounded capacity
            // and eventually fail closed.
            if record.stage == PlanSagaStage::PlanReady
                && secret
                    .exact_plan_response
                    .as_ref()
                    .and_then(|response| response.get("execution_mode"))
                    .and_then(Value::as_str)
                    == Some("agent_direct")
            {
                continue;
            }
            let Some(plan_proof_sha256) = secret.plan_ui_completion_proof_sha256.clone() else {
                continue;
            };
            let plan = ActionWorkflowUiCustodyBinding {
                method: "plan".to_string(),
                request_id: record.binding.request_id.clone(),
                request_payload_sha256: record.binding.request_payload_sha256.clone(),
                subject_uid: record.binding.subject_uid,
                subject_selinux_domain: record.binding.subject_selinux_domain.clone(),
                completion_proof_sha256: plan_proof_sha256,
            };
            let approve = match secret.action_consent.as_ref() {
                Some(action) if action.state == ActionConsentState::Consumed => {
                    let consuming = action
                        .consuming
                        .as_ref()
                        .context("consumed_action_consent_binding_missing")?;
                    secret
                        .approve_ui_completion_proof_sha256
                        .as_ref()
                        .map(|proof| ActionWorkflowUiCustodyBinding {
                            method: "approve".to_string(),
                            request_id: consuming.approve_request_id.clone(),
                            request_payload_sha256: consuming.approve_payload_sha256.clone(),
                            subject_uid: record.binding.subject_uid,
                            subject_selinux_domain: record.binding.subject_selinux_domain.clone(),
                            completion_proof_sha256: proof.clone(),
                        })
                }
                _ => None,
            };
            let compact_after_handoff = match record.stage {
                PlanSagaStage::Indeterminate => true,
                PlanSagaStage::PlanReady => match secret.action_consent.as_ref() {
                    None => true,
                    Some(action) if action.state == ActionConsentState::Expired => true,
                    Some(action)
                        if action.state == ActionConsentState::Pending
                            && record.binding.challenge_expires_at_ms <= now_unix_ms() =>
                    {
                        true
                    }
                    Some(action) if action.state == ActionConsentState::Consumed => {
                        approve.is_some()
                    }
                    _ => false,
                },
                _ => false,
            };
            let disposition = if record.stage == PlanSagaStage::Indeterminate {
                "plan_outcome_indeterminate_no_network_reexecution"
            } else {
                "completed_outcome_archived_in_ui_replay"
            };
            candidates.push(ActionWorkflowCustodyCandidate {
                plan,
                approve,
                record_request_id: record.binding.request_id.clone(),
                record_fingerprint_sha256: sha256_bytes(&serde_json::to_vec(record)?),
                compact_after_handoff,
                disposition: disposition.to_string(),
            });
        }
        Ok(candidates)
    }

    /// Read and validate the exact Direct `PlanReady` generation selected by
    /// `direct_binding`.  This is a query-only snapshot: it neither writes a
    /// handoff marker nor makes the record compactable.
    #[allow(dead_code)] // Query-only foundation; no production caller yet.
    pub(crate) fn direct_plan_custody_candidate(
        &self,
        context_memory: &ContextMemoryService,
        direct_binding: &DirectOperationBinding,
    ) -> Result<Option<DirectPlanCustodyCandidate>> {
        if self.publication_durability_uncertain {
            bail!("direct_plan_custody_snapshot_durability_uncertain");
        }
        direct_binding
            .validate()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let mut selected = None;
        for record in &self.file.records {
            if sha256_bytes(record.binding.request_id.as_bytes())
                != direct_binding.stable_seed.provider_invocation_id_sha256
            {
                continue;
            }
            if selected.is_some() {
                bail!("direct_plan_custody_request_binding_ambiguous");
            }
            if record.stage != PlanSagaStage::PlanReady {
                bail!("direct_plan_custody_requires_plan_ready");
            }
            let secret = decrypt_record(context_memory, record)?;
            if secret.action_consent.is_some() {
                bail!("direct_plan_custody_action_consent_denied");
            }
            let response = secret
                .exact_plan_response
                .as_ref()
                .context("direct_plan_custody_response_missing")?;
            if response.get("execution_mode").and_then(Value::as_str) != Some("agent_direct") {
                bail!("direct_plan_custody_execution_mode_denied");
            }
            // Reuse the production Direct receipt/evidence validator before
            // adding the snapshot's stricter closed-world and binding checks.
            validate_actionless_ready_response(&record.binding, response, &secret.local_state)?;
            validate_direct_candidate_response_closed(response, &secret.local_state)?;
            validate_direct_binding_for_plan(direct_binding, &record.binding, &secret.local_state)?;
            let direct_execution_receipt_sha256 = response
                .get("direct_execution_receipt_sha256")
                .and_then(Value::as_str)
                .filter(|digest| valid_digest(digest))
                .context("direct_plan_custody_receipt_digest_missing")?
                .to_string();
            let direct_binding_sha256 = direct_binding
                .digest_sha256()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            selected = Some(DirectPlanCustodyCandidate {
                direct_binding: direct_binding.clone(),
                direct_binding_sha256,
                workflow_binding: record.binding.clone(),
                record_fingerprint_sha256: sha256_bytes(&serde_json::to_vec(record)?),
                exact_plan_response: response.clone(),
                exact_plan_response_semantic_sha256: sha256_json(response),
                direct_execution_receipt_sha256,
                plan_ui_completion_proof_sha256: secret.plan_ui_completion_proof_sha256.clone(),
            });
        }
        Ok(selected)
    }

    /// Exact second-phase CAS after all UI handoffs in `candidate` are known
    /// durable. A concurrently changed record is retained for a later pass.
    pub(crate) fn compact_custody_candidate_exact(
        &mut self,
        context_memory: &ContextMemoryService,
        candidate: &ActionWorkflowCustodyCandidate,
    ) -> Result<bool> {
        self.ensure_mutable()?;
        if !candidate.compact_after_handoff {
            return Ok(false);
        }
        let Some(index) = self
            .file
            .records
            .iter()
            .position(|record| record.binding.request_id == candidate.record_request_id)
        else {
            return Ok(false);
        };
        let record = &self.file.records[index];
        if sha256_bytes(&serde_json::to_vec(record)?) != candidate.record_fingerprint_sha256 {
            return Ok(false);
        }
        let secret = decrypt_record(context_memory, record)?;
        if secret.plan_ui_completion_proof_sha256.as_deref()
            != Some(candidate.plan.completion_proof_sha256.as_str())
            || candidate.approve.as_ref().is_some_and(|approve| {
                secret.approve_ui_completion_proof_sha256.as_deref()
                    != Some(approve.completion_proof_sha256.as_str())
            })
        {
            bail!("action_workflow_custody_candidate_proof_changed");
        }
        let previous = self.file.clone();
        let record = self.file.records.remove(index);
        self.push_tombstone(record.binding, &candidate.disposition);
        if let Err(error) = self.flush(context_memory) {
            if !self.publication_durability_uncertain {
                self.file = previous;
            }
            return Err(error);
        }
        Ok(true)
    }

    fn push_tombstone(&mut self, binding: PlanRecoveryBinding, disposition: &str) {
        if self.file.tombstones.len() >= MAX_TOMBSTONES {
            self.file.tombstones.remove(0);
        }
        self.file.tombstones.push(WorkflowTombstone {
            binding,
            disposition: disposition.to_string(),
            archived_at_ms: now_unix_ms(),
        });
    }

    fn request_exists(&self, request_id: &str) -> bool {
        self.file
            .records
            .iter()
            .any(|record| record.binding.request_id == request_id)
            || self
                .file
                .tombstones
                .iter()
                .any(|record| record.binding.request_id == request_id)
    }

    fn record_index(&self, request_id: &str) -> Result<usize> {
        self.file
            .records
            .iter()
            .position(|record| record.binding.request_id == request_id)
            .context("action_workflow_request_missing")
    }

    fn action_record_index(
        &self,
        context_memory: &ContextMemoryService,
        approval_id: &str,
    ) -> Result<usize> {
        for (index, record) in self.file.records.iter().enumerate() {
            if record.stage != PlanSagaStage::PlanReady {
                continue;
            }
            let secret = decrypt_record(context_memory, record)?;
            if secret.action_consent.is_some()
                && !record.binding.action_id.is_empty()
                && secret
                    .action_consent
                    .as_ref()
                    .and_then(|action| action.challenge.get("approval_id"))
                    .and_then(Value::as_str)
                    == Some(approval_id)
            {
                return Ok(index);
            }
        }
        bail!("action_consent_challenge_missing_or_consumed")
    }

    fn replace_record(
        &mut self,
        context_memory: &ContextMemoryService,
        index: usize,
        replacement: EncryptedWorkflowRecord,
    ) -> Result<()> {
        self.ensure_mutable()?;
        let previous = self.file.records[index].clone();
        self.file.records[index] = replacement;
        if let Err(error) = self.flush(context_memory) {
            if !self.publication_durability_uncertain {
                self.file.records[index] = previous;
            }
            return Err(error);
        }
        Ok(())
    }

    fn flush(&mut self, context_memory: &ContextMemoryService) -> Result<()> {
        self.ensure_mutable()?;
        let parent = self
            .path
            .parent()
            .context("action_workflow_journal_parent_missing")?;
        ensure_private_parent(parent, self.owner_uid)?;
        validate_destination(&self.path, self.owner_uid)?;
        match (
            self.persisted_sha256.as_deref(),
            read_owner_controlled(&self.path, self.owner_uid)?,
        ) {
            (Some(expected), Some(bytes)) if sha256_bytes(&bytes) == expected => {}
            (None, None) => {}
            _ => bail!("action_workflow_journal_changed_outside_atomic_writer"),
        }
        validate_file(context_memory, &self.file, now_unix_ms())?;
        let mut bytes = serde_json::to_vec_pretty(&self.file)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_JOURNAL_BYTES {
            bail!("action_workflow_journal_size_limit_exceeded");
        }
        let temporary = parent.join(format!(
            ".action-workflow.tmp-{}-{}-{}",
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
            .context("failed_to_create_action_workflow_temp")?;
        let publish_before_rename = (|| -> Result<()> {
            output.write_all(&bytes)?;
            output.sync_all()?;
            validate_open_file(&output, self.owner_uid, MAX_JOURNAL_BYTES)?;
            Ok(())
        })();
        if let Err(error) = publish_before_rename {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = fs::rename(&temporary, &self.path) {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("failed_to_atomically_publish_action_workflow_journal");
        }

        // The destination now visibly contains the new generation. From this
        // boundary onward memory must never roll back to the predecessor even
        // if parent-directory durability cannot be proven.
        self.persisted_sha256 = Some(sha256_bytes(&bytes));
        match read_owner_controlled(&self.path, self.owner_uid) {
            Ok(Some(published)) if published == bytes => {}
            _ => {
                self.publication_durability_uncertain = true;
                bail!("action_workflow_published_bytes_revalidation_failed");
            }
        }
        #[cfg(test)]
        if std::mem::take(&mut self.fail_parent_fsync_after_rename_once) {
            self.publication_durability_uncertain = true;
            bail!("action_workflow_published_parent_fsync_uncertain");
        }
        if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
            self.publication_durability_uncertain = true;
            return Err(error).context("action_workflow_published_parent_fsync_uncertain");
        }
        Ok(())
    }

    fn ensure_mutable(&self) -> Result<()> {
        if self.publication_durability_uncertain {
            bail!("action_workflow_fail_stop_published_durability_uncertain");
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_parent_fsync_after_rename_once_for_test(&mut self) {
        self.fail_parent_fsync_after_rename_once = true;
    }

    #[cfg(test)]
    fn publication_durability_uncertain_for_test(&self) -> bool {
        self.publication_durability_uncertain
    }

    #[cfg(test)]
    pub(crate) fn set_custody_snapshot_barrier_for_test(&mut self, barrier: Arc<Barrier>) {
        self.custody_snapshot_barrier = Some(barrier);
        self.custody_snapshot_barrier_fired
            .store(false, Ordering::SeqCst);
    }
}

fn cleanup_owned_action_workflow_temps(parent: &Path, owner_uid: u32) -> Result<()> {
    let prefix = ".action-workflow.tmp-";
    let mut removed = false;
    for entry in fs::read_dir(parent).context("failed_to_scan_action_workflow_parent")? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("action_workflow_temp_name_not_utf8"))?;
        if !name.starts_with(prefix) {
            continue;
        }
        let parts = name[prefix.len()..].split('-').collect::<Vec<_>>();
        if parts.len() != 3
            || parts
                .iter()
                .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        {
            bail!("action_workflow_temp_name_shape_denied");
        }
        let path = entry.path();
        let input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .context("failed_to_open_action_workflow_temp")?;
        validate_open_file(&input, owner_uid, MAX_JOURNAL_BYTES)?;
        let opened = input.metadata()?;
        let current = fs::symlink_metadata(&path)?;
        if current.file_type().is_symlink()
            || current.dev() != opened.dev()
            || current.ino() != opened.ino()
            || current.nlink() != 1
        {
            bail!("action_workflow_temp_changed_before_cleanup");
        }
        fs::remove_file(&path).context("failed_to_remove_action_workflow_temp")?;
        removed = true;
    }
    if removed {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn workflow_view(record: &EncryptedWorkflowRecord, secret: WorkflowSecret) -> DurableWorkflowView {
    let action_consent = secret
        .action_consent
        .map(|action| DurableActionConsentView {
            state: action.state,
            challenge: action.challenge,
            consuming: action.consuming,
            binding: record.binding.clone(),
        });
    DurableWorkflowView {
        stage: record.stage,
        binding: record.binding.clone(),
        local_state: secret.local_state,
        exact_plan_response: secret.exact_plan_response,
        action_consent,
        indeterminate_reason: secret.indeterminate_reason,
    }
}

fn encrypt_record(
    context_memory: &ContextMemoryService,
    binding: PlanRecoveryBinding,
    stage: PlanSagaStage,
    secret: &WorkflowSecret,
    created_at_ms: u64,
    updated_at_ms: u64,
) -> Result<EncryptedWorkflowRecord> {
    validate_binding(&binding)?;
    validate_secret(stage, &binding, secret)?;
    let clear = Zeroizing::new(serde_json::to_vec(secret)?);
    if clear.len() > MAX_SECRET_BYTES {
        bail!("action_workflow_secret_too_large");
    }
    let aad = workflow_aad(stage, &binding)?;
    let ciphertext = context_memory.seal_workflow_blob(&aad, clear.as_slice(), MAX_SECRET_BYTES)?;
    Ok(EncryptedWorkflowRecord {
        record_version: 2,
        binding,
        stage,
        ciphertext_b64: BASE64_STANDARD.encode(&ciphertext),
        ciphertext_sha256: sha256_bytes(&ciphertext),
        created_at_ms,
        updated_at_ms,
    })
}

fn decrypt_record(
    context_memory: &ContextMemoryService,
    record: &EncryptedWorkflowRecord,
) -> Result<WorkflowSecret> {
    let ciphertext = BASE64_STANDARD
        .decode(&record.ciphertext_b64)
        .context("invalid_action_workflow_ciphertext_base64")?;
    if sha256_bytes(&ciphertext) != record.ciphertext_sha256 {
        bail!("action_workflow_ciphertext_digest_mismatch");
    }
    let aad = workflow_aad(record.stage, &record.binding)?;
    let clear = context_memory.unseal_workflow_blob(&aad, &ciphertext, MAX_SECRET_BYTES)?;
    let secret: WorkflowSecret = serde_json::from_slice(clear.as_slice())
        .context("invalid_encrypted_action_workflow_secret")?;
    let canonical = serde_json::to_vec(&secret)?;
    if canonical.as_slice() != clear.as_slice() {
        bail!("action_workflow_secret_not_canonical_closed_world_json");
    }
    validate_secret(record.stage, &record.binding, &secret)?;
    Ok(secret)
}

fn workflow_aad(stage: PlanSagaStage, binding: &PlanRecoveryBinding) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "schema": AAD_SCHEMA,
        "record_version": 2,
        "stage": stage,
        "method": binding.method,
        "request_id": binding.request_id,
        "request_payload_sha256": binding.request_payload_sha256,
        "subject_uid": binding.subject_uid,
        "subject_selinux_domain": binding.subject_selinux_domain,
        "provider_id": binding.provider_id,
        "task_id": binding.task_id,
        "plan_id": binding.plan_id,
        "action_id": binding.action_id,
        "tool_call_id": binding.tool_call_id,
        "accepted_plan_sha256": binding.accepted_plan_sha256,
        "challenge_sha256": binding.challenge_sha256,
        "challenge_expires_at_ms": binding.challenge_expires_at_ms,
    }))?)
}

fn validate_file(
    context_memory: &ContextMemoryService,
    file: &ActionWorkflowFile,
    now: u64,
) -> Result<()> {
    if file.schema != JOURNAL_SCHEMA
        || file.records.len() > MAX_RECORDS
        || file.tombstones.len() > MAX_TOMBSTONES
    {
        bail!("invalid_action_workflow_journal_shape");
    }
    let mut request_ids = std::collections::HashSet::new();
    for record in &file.records {
        validate_record(context_memory, record, now)?;
        if !request_ids.insert(record.binding.request_id.as_str()) {
            bail!("duplicate_action_workflow_request_id");
        }
    }
    for tombstone in &file.tombstones {
        validate_binding(&tombstone.binding)?;
        if !request_ids.insert(tombstone.binding.request_id.as_str())
            || !matches!(
                tombstone.disposition.as_str(),
                "plan_outcome_indeterminate_no_network_reexecution"
                    | "completed_outcome_archived_in_ui_replay"
            )
            || tombstone.archived_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        {
            bail!("invalid_action_workflow_tombstone");
        }
    }
    Ok(())
}

fn validate_record(
    context_memory: &ContextMemoryService,
    record: &EncryptedWorkflowRecord,
    now: u64,
) -> Result<()> {
    validate_binding(&record.binding)?;
    if record.record_version != 2
        || !valid_digest(&record.ciphertext_sha256)
        || record.created_at_ms > record.updated_at_ms
        || record.updated_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
        || record.ciphertext_b64.is_empty()
        || record.ciphertext_b64.len() > (MAX_SECRET_BYTES + 256) * 2
    {
        bail!("invalid_action_workflow_record_envelope");
    }
    let _ = decrypt_record(context_memory, record)?;
    Ok(())
}

fn validate_initial_binding(binding: &PlanRecoveryBinding) -> Result<()> {
    validate_binding(binding)?;
    if !binding.plan_id.is_empty()
        || !binding.action_id.is_empty()
        || !binding.tool_call_id.is_empty()
        || !binding.accepted_plan_sha256.is_empty()
        || !binding.challenge_sha256.is_empty()
        || binding.challenge_expires_at_ms != 0
    {
        bail!("provider_pending_binding_contains_future_identity");
    }
    Ok(())
}

fn validate_binding(binding: &PlanRecoveryBinding) -> Result<()> {
    if binding.method != "plan"
        || !valid_id(&binding.request_id)
        || !valid_digest(&binding.request_payload_sha256)
        || binding.subject_uid >= 100_000
        || !valid_domain(&binding.subject_selinux_domain)
        || agent_principal_registry::from_provider_id(&binding.provider_id).is_none()
        || !valid_id(&binding.task_id)
        || (!binding.plan_id.is_empty() && !valid_id(&binding.plan_id))
        || (!binding.action_id.is_empty() && !valid_id(&binding.action_id))
        || (!binding.tool_call_id.is_empty() && !valid_id(&binding.tool_call_id))
        || (!binding.accepted_plan_sha256.is_empty()
            && !valid_digest(&binding.accepted_plan_sha256))
        || (!binding.challenge_sha256.is_empty() && !valid_digest(&binding.challenge_sha256))
        || (binding.challenge_sha256.is_empty() != (binding.challenge_expires_at_ms == 0))
    {
        bail!("invalid_action_workflow_binding");
    }
    Ok(())
}

fn validate_transition_binding(
    previous: &PlanRecoveryBinding,
    next: &PlanRecoveryBinding,
) -> Result<()> {
    validate_binding(next)?;
    if previous.method != next.method
        || previous.request_id != next.request_id
        || previous.request_payload_sha256 != next.request_payload_sha256
        || previous.subject_uid != next.subject_uid
        || previous.subject_selinux_domain != next.subject_selinux_domain
        || previous.provider_id != next.provider_id
        || previous.task_id != next.task_id
        || (!previous.plan_id.is_empty() && previous.plan_id != next.plan_id)
        || (!previous.action_id.is_empty() && previous.action_id != next.action_id)
        || (!previous.tool_call_id.is_empty() && previous.tool_call_id != next.tool_call_id)
        || (!previous.accepted_plan_sha256.is_empty()
            && previous.accepted_plan_sha256 != next.accepted_plan_sha256)
        || (!previous.challenge_sha256.is_empty()
            && (previous.challenge_sha256 != next.challenge_sha256
                || previous.challenge_expires_at_ms != next.challenge_expires_at_ms))
    {
        bail!("action_workflow_immutable_binding_changed");
    }
    Ok(())
}

fn validate_recovery_identity(
    binding: &PlanRecoveryBinding,
    request_payload_sha256: &str,
    subject_uid: u32,
    subject_selinux_domain: &str,
) -> Result<()> {
    if binding.request_payload_sha256 != request_payload_sha256
        || binding.subject_uid != subject_uid
        || binding.subject_selinux_domain != subject_selinux_domain
    {
        bail!("action_workflow_recovery_binding_mismatch");
    }
    Ok(())
}

fn validate_secret(
    stage: PlanSagaStage,
    binding: &PlanRecoveryBinding,
    secret: &WorkflowSecret,
) -> Result<()> {
    if secret.schema != SECRET_SCHEMA {
        bail!("invalid_action_workflow_secret_schema");
    }
    if secret
        .plan_ui_completion_proof_sha256
        .as_deref()
        .is_some_and(|digest| !valid_digest(digest))
        || secret
            .approve_ui_completion_proof_sha256
            .as_deref()
            .is_some_and(|digest| !valid_digest(digest))
        || (secret.approve_ui_completion_proof_sha256.is_some()
            && secret.plan_ui_completion_proof_sha256.is_none())
    {
        bail!("invalid_action_workflow_ui_completion_proof_binding");
    }
    match stage {
        PlanSagaStage::PlanReady => {
            let response = secret
                .exact_plan_response
                .as_ref()
                .context("ready_action_workflow_response_missing")?;
            if secret.indeterminate_reason.is_some()
                || response.get("task_id").and_then(Value::as_str) != Some(binding.task_id.as_str())
                || response.get("provider_id").and_then(Value::as_str)
                    != Some(binding.provider_id.as_str())
                || response.get("plan_id").and_then(Value::as_str) != Some(binding.plan_id.as_str())
            {
                bail!("action_workflow_ready_response_binding_mismatch");
            }
            match &secret.action_consent {
                Some(action) => validate_action_consent(binding, response, action)?,
                None => {
                    if !binding.action_id.is_empty()
                        || !binding.tool_call_id.is_empty()
                        || !binding.accepted_plan_sha256.is_empty()
                        || !binding.challenge_sha256.is_empty()
                    {
                        bail!("action_workflow_read_only_binding_mismatch");
                    }
                    validate_actionless_ready_response(binding, response, &secret.local_state)?;
                }
            }
            if secret.approve_ui_completion_proof_sha256.is_some()
                && !secret
                    .action_consent
                    .as_ref()
                    .is_some_and(|action| action.state == ActionConsentState::Consumed)
            {
                bail!("approve_ui_completion_proof_without_consumed_action");
            }
        }
        PlanSagaStage::Indeterminate => {
            if secret.exact_plan_response.is_some()
                || secret.action_consent.is_some()
                || secret.approve_ui_completion_proof_sha256.is_some()
                || secret.indeterminate_reason.as_deref().is_none_or(|reason| {
                    reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control)
                })
            {
                bail!("invalid_indeterminate_action_workflow_secret");
            }
        }
        PlanSagaStage::ProviderPending | PlanSagaStage::ProviderReady => {
            if secret.exact_plan_response.is_some()
                || secret.action_consent.is_some()
                || secret.indeterminate_reason.is_some()
                || secret.plan_ui_completion_proof_sha256.is_some()
                || secret.approve_ui_completion_proof_sha256.is_some()
                || !binding.plan_id.is_empty()
                || !binding.action_id.is_empty()
                || !binding.tool_call_id.is_empty()
                || !binding.accepted_plan_sha256.is_empty()
                || !binding.challenge_sha256.is_empty()
            {
                bail!("nonterminal_action_workflow_contains_terminal_state");
            }
        }
        PlanSagaStage::PlanPrepared | PlanSagaStage::PlanSubmitted => {
            if secret.exact_plan_response.is_some()
                || secret.action_consent.is_some()
                || secret.indeterminate_reason.is_some()
                || secret.plan_ui_completion_proof_sha256.is_some()
                || secret.approve_ui_completion_proof_sha256.is_some()
                || binding.plan_id.is_empty()
                || binding.action_id.is_empty()
                || !binding.tool_call_id.is_empty()
                || !binding.challenge_sha256.is_empty()
                || (stage == PlanSagaStage::PlanPrepared
                    && !binding.accepted_plan_sha256.is_empty())
                || (stage == PlanSagaStage::PlanSubmitted
                    && !valid_digest(&binding.accepted_plan_sha256))
            {
                bail!("invalid_pre_dispatch_action_workflow_binding");
            }
        }
        PlanSagaStage::ActionDispatched | PlanSagaStage::PayloadStaged => {
            if secret.exact_plan_response.is_some()
                || secret.action_consent.is_some()
                || secret.indeterminate_reason.is_some()
                || secret.plan_ui_completion_proof_sha256.is_some()
                || secret.approve_ui_completion_proof_sha256.is_some()
                || binding.plan_id.is_empty()
                || binding.action_id.is_empty()
                || binding.tool_call_id.is_empty()
                || !valid_digest(&binding.accepted_plan_sha256)
                || !binding.challenge_sha256.is_empty()
            {
                bail!("invalid_post_dispatch_action_workflow_binding");
            }
        }
    }
    Ok(())
}

#[allow(dead_code)] // Used only by the inert Direct custody producer for now.
fn validate_direct_candidate_response_closed(response: &Value, local_state: &Value) -> Result<()> {
    let object = response
        .as_object()
        .context("direct_plan_custody_response_not_object")?;
    if object.len() != direct_agent_host_abi::DIRECT_RESULT_FIELDS.len()
        || object
            .keys()
            .any(|key| !direct_agent_host_abi::DIRECT_RESULT_FIELDS.contains(&key.as_str()))
    {
        bail!("direct_plan_custody_response_not_closed_world");
    }
    let local_result = local_state
        .get("provider_result")
        .and_then(Value::as_object)
        .context("direct_plan_custody_local_result_missing")?;
    if response.get("summary").and_then(Value::as_str)
        != local_result.get("summary").and_then(Value::as_str)
        || response.get("model").and_then(Value::as_str)
            != local_result.get("model").and_then(Value::as_str)
        || response.get("provider").and_then(Value::as_str)
            != local_result.get("runtime_provider").and_then(Value::as_str)
        || response.get("plan_latency_ms").and_then(Value::as_u64)
            != local_result.get("elapsed_ms").and_then(Value::as_u64)
        || response
            .get("egress_grant_consumed")
            .and_then(Value::as_bool)
            != Some(true)
    {
        bail!("direct_plan_custody_response_projection_mismatch");
    }
    Ok(())
}

#[allow(dead_code)] // Used only by the inert Direct custody producer for now.
fn validate_direct_binding_for_plan(
    direct_binding: &DirectOperationBinding,
    workflow_binding: &PlanRecoveryBinding,
    local_state: &Value,
) -> Result<()> {
    direct_binding
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let workflow_id = local_state
        .get("workflow_id")
        .and_then(Value::as_str)
        .context("direct_plan_custody_workflow_id_missing")?;
    let agent_id = local_state
        .pointer("/registration/agent_id")
        .and_then(Value::as_str)
        .context("direct_plan_custody_agent_id_missing")?;
    let runtime_lifecycle_binding_sha256 = local_state
        .get("runtime_lifecycle_binding_sha256")
        .and_then(Value::as_str)
        .context("direct_plan_custody_lifecycle_missing")?;
    let agent_identity_key_sha256 = local_state
        .pointer("/registration/identity_key_sha256")
        .and_then(Value::as_str)
        .context("direct_plan_custody_agent_identity_missing")?;
    let agent_executable_sha256 = local_state
        .pointer("/agent_executable/sha256")
        .and_then(Value::as_str)
        .context("direct_plan_custody_agent_executable_missing")?;
    let authorized_adapter_set = local_state
        .get("authorized_adapter_set")
        .context("direct_plan_custody_authorized_adapter_set_missing")?;
    let expected_provider_session_id_sha256 = sha256_bytes(
        format!("android-ui-{}-{workflow_id}", workflow_binding.subject_uid).as_bytes(),
    );
    let seed = &direct_binding.stable_seed;
    if seed.provider_id != workflow_binding.provider_id
        || seed.agent_id != agent_id
        || seed.task_id != workflow_binding.task_id
        || seed.provider_invocation_id_sha256
            != sha256_bytes(workflow_binding.request_id.as_bytes())
        || seed.provider_session_id_sha256 != expected_provider_session_id_sha256
        || seed.subject_uid != workflow_binding.subject_uid
        || seed.subject_selinux_domain_sha256
            != sha256_bytes(workflow_binding.subject_selinux_domain.as_bytes())
        || direct_binding.workflow_id_sha256 != sha256_bytes(workflow_id.as_bytes())
        || direct_binding.agent_identity_key_sha256 != agent_identity_key_sha256
        || direct_binding.agent_executable_sha256 != agent_executable_sha256
        || serde_json::to_value(&direct_binding.authorized_adapter_set)? != *authorized_adapter_set
        || direct_binding.attempt.runtime_lifecycle_binding_sha256
            != runtime_lifecycle_binding_sha256
    {
        bail!("direct_plan_custody_direct_binding_mismatch");
    }
    Ok(())
}

pub(crate) fn bind_build_local_direct_receipt_commitment(commitment: &mut Value) {
    let object = commitment
        .as_object_mut()
        .expect("direct receipt commitment is an object");
    #[cfg(feature = "p0-launch-package-device-conformance")]
    let build_binding = Value::String(
        crate::builtin_provider_identity::P01_DAEMON_BUILD_BINDING_SHA256.to_string(),
    );
    #[cfg(not(feature = "p0-launch-package-device-conformance"))]
    let build_binding = Value::Null;
    object.insert("p01_daemon_build_binding_sha256".to_string(), build_binding);
}

pub(crate) fn validate_actionless_ready_response(
    binding: &PlanRecoveryBinding,
    response: &Value,
    local_state: &Value,
) -> Result<()> {
    if response.get("execution_mode").and_then(Value::as_str) != Some("agent_direct") {
        if response.get("execution_available").and_then(Value::as_bool) != Some(false) {
            bail!("action_workflow_read_only_binding_mismatch");
        }
        return Ok(());
    }
    let local_result = local_state
        .get("provider_result")
        .and_then(Value::as_object)
        .context("action_workflow_direct_local_result_missing")?;
    let local_registration = local_state
        .get("registration")
        .context("action_workflow_direct_registration_missing")?;
    let local_provider_id = local_state
        .get("provider_id")
        .and_then(Value::as_str)
        .context("action_workflow_direct_provider_missing")?;
    let descriptor = agent_principal_registry::from_provider_id(local_provider_id)
        .ok_or_else(|| anyhow::anyhow!("action_workflow_direct_provider_invalid"))?;
    let expected_agent_id = descriptor.agent_id;
    let typed_registration: AgentRegistration = serde_json::from_value(local_registration.clone())
        .context("action_workflow_direct_registration_shape_invalid")?;
    let local_agent_id = local_registration
        .get("agent_id")
        .and_then(Value::as_str)
        .context("action_workflow_direct_agent_id_missing")?;
    let agent_executable_sha256 = local_state
        .pointer("/agent_executable/sha256")
        .and_then(Value::as_str)
        .context("action_workflow_direct_executable_digest_missing")?;
    let registration_executable_sha256 = local_registration
        .get("identity_key_sha256")
        .and_then(Value::as_str)
        .context("action_workflow_direct_registration_digest_missing")?;
    let agent_manifest_sha256 = local_state
        .get("agent_manifest_sha256")
        .and_then(Value::as_str)
        .context("action_workflow_direct_manifest_digest_missing")?;
    let lifecycle_sha256 = local_state
        .get("runtime_lifecycle_binding_sha256")
        .and_then(Value::as_str)
        .context("action_workflow_direct_lifecycle_digest_missing")?;
    let provider_output_sha256 = local_result
        .get("provider_output_sha256")
        .and_then(Value::as_str)
        .context("action_workflow_direct_output_digest_missing")?;
    let direct_outcome = local_result
        .get("direct_outcome")
        .and_then(Value::as_str)
        .context("action_workflow_direct_outcome_missing")?;
    let direct_refusal_value = local_result
        .get("direct_refusal_reason")
        .context("action_workflow_direct_refusal_field_missing")?;
    let direct_refusal_reason = if direct_refusal_value.is_null() {
        None
    } else {
        Some(
            direct_refusal_value
                .as_str()
                .context("action_workflow_direct_refusal_not_string")?,
        )
    };
    let direct_calls = local_result
        .get("direct_tool_calls")
        .and_then(Value::as_array)
        .context("action_workflow_direct_calls_missing")?;
    if local_provider_id != CODEX.provider_id || direct_calls.len() > 4_096 {
        bail!("action_workflow_codex_direct_evidence_invalid");
    }
    let typed_calls: Vec<CodexDirectToolCallEvidence> =
        serde_json::from_value(Value::Array(direct_calls.clone()))
            .context("action_workflow_codex_direct_call_shape_invalid")?;
    let mut tool_names = Vec::new();
    let mut completed = 0_u64;
    let mut indeterminate = 0_u64;
    for (sequence, call) in typed_calls.iter().enumerate() {
        if call.sequence != sequence
            || call.server != call.tool
            || !codex_direct_mcp_identity_is_authorized(&call.server, &call.tool)
            || !valid_digest(&call.canonical_request_sha256)
            || !valid_digest(&call.backend_request_id_sha256)
            || !valid_digest(&call.backend_result_sha256)
            || !valid_digest(&call.event_payload_sha256)
        {
            bail!("action_workflow_codex_direct_call_binding_invalid");
        }
        match call.outcome.as_str() {
            "success" if call.status == "completed" && call.backend_error_code.is_none() => {
                completed += 1
            }
            "backend_error" if call.status == "failed" && call.backend_error_code.is_some() => {
                let code = call.backend_error_code.as_deref().unwrap();
                match direct_backend_error_effect_class(&call.server, code) {
                    Some(DirectBackendEffectClass::DefinitelyNoEffect) => {}
                    Some(DirectBackendEffectClass::Indeterminate) => {
                        indeterminate += 1;
                    }
                    Some(DirectBackendEffectClass::DefinitiveTerminal) => {
                        bail!("action_workflow_codex_direct_error_class_invalid")
                    }
                    None => bail!("action_workflow_codex_direct_error_unclassified"),
                }
            }
            "terminal_error"
                if call.status == "failed"
                    && call.backend_error_code.is_some()
                    && direct_backend_error_effect_class(
                        &call.server,
                        call.backend_error_code.as_deref().unwrap(),
                    ) == Some(DirectBackendEffectClass::DefinitiveTerminal) =>
            {
                completed += 1;
            }
            "indeterminate"
                if call.status == "failed"
                    && call.backend_error_code.is_some()
                    && direct_backend_error_effect_class(
                        &call.server,
                        call.backend_error_code.as_deref().unwrap(),
                    ) == Some(DirectBackendEffectClass::Indeterminate) =>
            {
                indeterminate += 1;
            }
            _ => bail!("action_workflow_codex_direct_call_outcome_invalid"),
        }
        tool_names.push(call.server.clone());
    }
    let calls = direct_calls.len() as u64;
    let direct_call_evidence = Value::Array(direct_calls.clone());
    tool_names.sort();
    tool_names.dedup();
    let direct_outcome_valid = match direct_outcome {
        "completed" => completed > 0 && indeterminate == 0 && direct_refusal_reason.is_none(),
        "no_action" => completed == 0 && indeterminate == 0 && direct_refusal_reason.is_none(),
        "indeterminate" => indeterminate > 0 && direct_refusal_reason.is_none(),
        "refused" => {
            completed == 0
                && indeterminate == 0
                && direct_refusal_reason.is_some_and(|reason| {
                    !reason.trim().is_empty()
                        && reason.len() <= 4_096
                        && !reason.chars().any(char::is_control)
                })
        }
        _ => false,
    };
    let direct_refusal_sha256 = direct_refusal_reason.map(|reason| sha256_bytes(reason.as_bytes()));
    let direct_evidence_sha256 = sha256_json(&json!({
        "schema": "trillionnium.agent-direct-evidence.v2",
        "tool_calls": direct_calls,
    }));
    let workflow_id = local_state
        .get("workflow_id")
        .and_then(Value::as_str)
        .context("action_workflow_direct_workflow_id_missing")?;
    let runtime_provider = local_result
        .get("runtime_provider")
        .and_then(Value::as_str)
        .context("action_workflow_direct_runtime_provider_missing")?;
    let model = local_result
        .get("model")
        .and_then(Value::as_str)
        .context("action_workflow_direct_model_missing")?;
    let summary = local_result
        .get("summary")
        .and_then(Value::as_str)
        .context("action_workflow_direct_summary_missing")?;
    let shell_exec_authorization = local_state
        .get("shell_exec_authorization")
        .map(|value| {
            serde_json::from_value::<CompletedShellExecAuthorizationV1>(value.clone())
                .context("action_workflow_shell_exec_authorization_shape_invalid")
        })
        .transpose()?;
    if let Some(authorization) = shell_exec_authorization.as_ref() {
        authorization.validate()?;
        validate_direct_binding_for_plan(
            &authorization.registration.binding,
            binding,
            local_state,
        )?;
    } else if typed_calls
        .iter()
        .any(|call| call.server == "trillionnium_shell_exec")
    {
        bail!("action_workflow_shell_exec_authorization_missing");
    }
    let shell_exec_authorization_sha256 = shell_exec_authorization
        .as_ref()
        .map(CompletedShellExecAuthorizationV1::digest_sha256)
        .transpose()?;
    let shell_exec_direct_binding_sha256 = shell_exec_authorization
        .as_ref()
        .map(|authorization| authorization.registration.binding_sha256.clone());
    let mut expected_commitment = json!({
        "schema": direct_agent_host_abi::DIRECT_RECEIPT_SCHEMA,
        "direct_agent_host_abi": direct_agent_host_abi::ABI_SCHEMA,
        "direct_agent_host_abi_sha256": direct_agent_host_abi::CONTRACT_SHA256,
        "direct_result_schema": direct_agent_host_abi::DIRECT_RESULT_SCHEMA,
        "request_id_sha256": sha256_bytes(binding.request_id.as_bytes()),
        "request_payload_sha256": binding.request_payload_sha256,
        "subject_uid": binding.subject_uid,
        "subject_selinux_domain_sha256": sha256_bytes(binding.subject_selinux_domain.as_bytes()),
        "provider_id": binding.provider_id,
        "workflow_id_sha256": sha256_bytes(workflow_id.as_bytes()),
        "task_id": binding.task_id,
        "agent_id": local_agent_id,
        "agent_manifest_sha256": agent_manifest_sha256,
        "agent_executable_sha256": agent_executable_sha256,
        "runtime_lifecycle_binding_sha256": lifecycle_sha256,
        "runtime_provider": runtime_provider,
        "model": model,
        "summary_sha256": sha256_bytes(summary.as_bytes()),
        "provider_output_sha256": provider_output_sha256,
        "direct_evidence_sha256": direct_evidence_sha256,
        "direct_call_evidence": direct_call_evidence,
        "direct_outcome": direct_outcome,
        "direct_refusal_sha256": direct_refusal_sha256,
        "direct_tool_call_events": calls,
        "completed_direct_tool_calls": completed,
        "direct_tool_names": tool_names,
        "shell_exec_authorization_sha256": shell_exec_authorization_sha256,
        "shell_exec_direct_binding_sha256": shell_exec_direct_binding_sha256,
    });
    bind_build_local_direct_receipt_commitment(&mut expected_commitment);
    let receipt_sha256 = sha256_json(&expected_commitment);
    let response_tools = response
        .get("direct_tool_names")
        .and_then(Value::as_array)
        .context("action_workflow_direct_tool_names_missing")?;
    let model_executed_tools_valid = if completed > 0 {
        response
            .get("model_executed_tools")
            .and_then(Value::as_bool)
            == Some(true)
    } else if indeterminate > 0 {
        response
            .get("model_executed_tools")
            .is_some_and(Value::is_null)
    } else {
        response
            .get("model_executed_tools")
            .and_then(Value::as_bool)
            == Some(false)
    };
    if local_state.get("schema").and_then(Value::as_str) != Some("trillionnium.local-plan-saga.v3")
        || local_result.get("execution_mode").and_then(Value::as_str) != Some("agent_direct")
        || !local_result.get("submission").is_some_and(Value::is_null)
        || local_state.get("request_id").and_then(Value::as_str)
            != Some(binding.request_id.as_str())
        || local_state
            .get("request_payload_sha256")
            .and_then(Value::as_str)
            != Some(binding.request_payload_sha256.as_str())
        || local_state.get("peer_uid").and_then(Value::as_u64) != Some(binding.subject_uid as u64)
        || local_state.get("peer_domain").and_then(Value::as_str)
            != Some(binding.subject_selinux_domain.as_str())
        || local_provider_id != binding.provider_id
        || local_state.get("task_id").and_then(Value::as_str) != Some(binding.task_id.as_str())
        || local_agent_id != expected_agent_id
        || !crate::builtin_provider_identity::matches_registration_with_active_launcher(
            descriptor,
            &typed_registration,
            agent_executable_sha256,
        )
        || agent_manifest_sha256 != sha256_json(local_registration)
        || agent_executable_sha256 != registration_executable_sha256
        || !valid_digest(lifecycle_sha256)
        || !valid_digest(provider_output_sha256)
        || !direct_outcome_valid
        || response.get("direct_receipt_commitment") != Some(&expected_commitment)
        || response
            .get("direct_execution_receipt_sha256")
            .and_then(Value::as_str)
            != Some(receipt_sha256.as_str())
        || response
            .get("direct_execution_receipt_id")
            .and_then(Value::as_str)
            != Some(format!("direct-receipt-{receipt_sha256}").as_str())
        || response
            .get("provider_output_sha256")
            .and_then(Value::as_str)
            != Some(provider_output_sha256)
        || response.get("agent_id").and_then(Value::as_str) != Some(local_agent_id)
        || response
            .get("agent_manifest_sha256")
            .and_then(Value::as_str)
            != Some(agent_manifest_sha256)
        || response
            .get("agent_executable_sha256")
            .and_then(Value::as_str)
            != Some(agent_executable_sha256)
        || response
            .get("runtime_lifecycle_binding_sha256")
            .and_then(Value::as_str)
            != Some(lifecycle_sha256)
        || response
            .get("request_payload_sha256")
            .and_then(Value::as_str)
            != Some(binding.request_payload_sha256.as_str())
        || response.get("workflow_id_sha256").and_then(Value::as_str)
            != Some(sha256_bytes(workflow_id.as_bytes()).as_str())
        || response
            .get("direct_evidence_sha256")
            .and_then(Value::as_str)
            != Some(direct_evidence_sha256.as_str())
        || response.get("direct_call_evidence") != expected_commitment.get("direct_call_evidence")
        || response.get("direct_outcome").and_then(Value::as_str) != Some(direct_outcome)
        || response.get("direct_refusal_reason") != Some(direct_refusal_value)
        || response.get("direct_refusal_sha256") != expected_commitment.get("direct_refusal_sha256")
        || response
            .get("direct_agent_host_abi")
            .and_then(Value::as_str)
            != Some(direct_agent_host_abi::ABI_SCHEMA)
        || response
            .get("direct_agent_host_abi_sha256")
            .and_then(Value::as_str)
            != Some(direct_agent_host_abi::CONTRACT_SHA256)
        || response.get("direct_result_schema").and_then(Value::as_str)
            != Some(direct_agent_host_abi::DIRECT_RESULT_SCHEMA)
        || response.get("action").and_then(Value::as_str) != Some("agent_direct_result")
        || response.get("plan_id").and_then(Value::as_str) != Some("")
        || response.get("approval_id").and_then(Value::as_str) != Some("")
        || response.get("requires_approval").and_then(Value::as_bool) != Some(false)
        || response.get("execution_available").and_then(Value::as_bool)
            != Some(matches!(direct_outcome, "completed" | "no_action"))
        || response.get("execution_completed").and_then(Value::as_bool)
            != Some(direct_outcome == "completed")
        || response
            .get("tool_invocation_owned_by_agent")
            .and_then(Value::as_bool)
            != Some(direct_agent_host_abi::TOOL_INVOCATION_OWNED_BY_AGENT)
        || response
            .get("tool_backend_owned_by_os")
            .and_then(Value::as_bool)
            != Some(direct_agent_host_abi::TOOL_BACKEND_OWNED_BY_OS)
        || response
            .get("daemon_is_effect_executor")
            .and_then(Value::as_bool)
            != Some(direct_agent_host_abi::DAEMON_IS_EFFECT_EXECUTOR)
        || response
            .get("contract_confers_effect_authority")
            .and_then(Value::as_bool)
            != Some(direct_agent_host_abi::CONTRACT_CONFERS_EFFECT_AUTHORITY)
        || response
            .get("plan_submitted_for_execution")
            .and_then(Value::as_bool)
            != Some(false)
        || response.get("authority_called").and_then(Value::as_bool) != Some(false)
        || response.get("network_scope").and_then(Value::as_str) != Some("provider_egress_only")
        || response
            .get("direct_tool_call_events")
            .and_then(Value::as_u64)
            != Some(calls)
        || response
            .get("completed_direct_tool_calls")
            .and_then(Value::as_u64)
            != Some(completed)
        || response_tools != expected_commitment["direct_tool_names"].as_array().unwrap()
        || completed > calls
        || (calls == 0 && !response_tools.is_empty())
        || (calls > 0 && response_tools.is_empty())
        || response.get("model_invoked_tools").and_then(Value::as_bool) != Some(calls > 0)
        || !model_executed_tools_valid
        || response_tools.len() > CODEX_DIRECT_MCP_TOOL_NAMES.len()
        || response_tools.iter().any(|tool| {
            !tool
                .as_str()
                .is_some_and(codex_direct_mcp_tool_name_is_authorized)
        })
    {
        bail!("action_workflow_direct_response_contract_mismatch");
    }
    Ok(())
}

fn validate_action_consent(
    binding: &PlanRecoveryBinding,
    response: &Value,
    action: &DurableActionConsent,
) -> Result<()> {
    if binding.plan_id.is_empty()
        || binding.action_id.is_empty()
        || binding.tool_call_id.is_empty()
        || !valid_digest(&binding.accepted_plan_sha256)
        || !valid_digest(&binding.challenge_sha256)
        || binding.challenge_expires_at_ms == 0
        || sha256_bytes(&serde_json::to_vec(&action.challenge)?) != binding.challenge_sha256
        || action.challenge.get("ui_uid").and_then(Value::as_u64)
            != Some(binding.subject_uid as u64)
        || action
            .challenge
            .get("ui_selinux_domain")
            .and_then(Value::as_str)
            != Some(binding.subject_selinux_domain.as_str())
        || action.challenge.get("task_id").and_then(Value::as_str) != Some(binding.task_id.as_str())
        || action.challenge.get("plan_id").and_then(Value::as_str) != Some(binding.plan_id.as_str())
        || action.challenge.get("action_id").and_then(Value::as_str)
            != Some(binding.action_id.as_str())
        || action.challenge.get("tool_call_id").and_then(Value::as_str)
            != Some(binding.tool_call_id.as_str())
        || action
            .challenge
            .get("accepted_plan_sha256")
            .and_then(Value::as_str)
            != Some(binding.accepted_plan_sha256.as_str())
        || action
            .challenge
            .get("expires_at_ms")
            .and_then(Value::as_u64)
            != Some(binding.challenge_expires_at_ms)
        || response.get("action_consent_challenge") != Some(&action.challenge)
        || response.get("approval_id").and_then(Value::as_str)
            != action.challenge.get("approval_id").and_then(Value::as_str)
    {
        bail!("invalid_durable_action_consent_binding");
    }
    match action.state {
        ActionConsentState::Pending | ActionConsentState::Expired => {
            if action.consuming.is_some() || action.consumed_at_ms.is_some() {
                bail!("invalid_pending_action_consent_state");
            }
        }
        ActionConsentState::Consuming => {
            let consuming = action
                .consuming
                .as_ref()
                .context("action_consent_consuming_binding_missing")?;
            validate_consuming(consuming, now_unix_ms())?;
            if action.consumed_at_ms.is_some() {
                bail!("consuming_action_consent_has_terminal_time");
            }
        }
        ActionConsentState::Consumed => {
            let consuming = action
                .consuming
                .as_ref()
                .context("consumed_action_consent_binding_missing")?;
            validate_consuming(consuming, now_unix_ms())?;
            if action
                .consumed_at_ms
                .is_none_or(|value| value < consuming.started_at_ms)
            {
                bail!("consumed_action_consent_time_invalid");
            }
        }
    }
    Ok(())
}

fn validate_consuming(binding: &ConsumingApprovalBinding, now: u64) -> Result<()> {
    if !valid_id(&binding.approve_request_id)
        || !valid_digest(&binding.approve_payload_sha256)
        || !valid_digest(&binding.action_consent_receipt_id)
        || binding.started_at_ms > now.saturating_add(MAX_CLOCK_SKEW_MS)
    {
        bail!("invalid_action_consent_consuming_binding");
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn ensure_private_parent(path: &Path, owner_uid: u32) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path).context("failed_to_create_action_workflow_parent")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != owner_uid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        bail!("action_workflow_parent_not_owner_private");
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        let metadata =
            fs::symlink_metadata(&current).context("action_workflow_path_component_unavailable")?;
        if metadata.file_type().is_symlink() {
            bail!("action_workflow_symlink_component_denied");
        }
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
            bail!("action_workflow_destination_not_owner_private")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_owner_controlled(path: &Path, owner_uid: u32) -> Result<Option<Vec<u8>>> {
    let input = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(input) => input,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed_to_open_action_workflow_journal"),
    };
    validate_open_file(&input, owner_uid, MAX_JOURNAL_BYTES)?;
    let mut bytes = Vec::new();
    input
        .take(MAX_JOURNAL_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_JOURNAL_BYTES {
        bail!("action_workflow_journal_file_too_large");
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
        bail!("action_workflow_journal_file_not_owner_private");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_memory::ContextMemoryService;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationProviderAttempt, DirectOperationStableSeed,
        STABLE_SEED_SCHEMA,
    };

    const DOMAIN: &str = "u:r:trillionnium_aishell:s0";

    fn context(root: &Path) -> ContextMemoryService {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        ContextMemoryService::open(root.join("context-memory")).unwrap()
    }

    fn initial_binding(request_id: &str) -> PlanRecoveryBinding {
        PlanRecoveryBinding {
            method: "plan".to_string(),
            request_id: request_id.to_string(),
            request_payload_sha256: "a".repeat(64),
            subject_uid: 10_123,
            subject_selinux_domain: DOMAIN.to_string(),
            provider_id: "openai-codex".to_string(),
            task_id: format!("task-{request_id}"),
            plan_id: String::new(),
            action_id: String::new(),
            tool_call_id: String::new(),
            accepted_plan_sha256: String::new(),
            challenge_sha256: String::new(),
            challenge_expires_at_ms: 0,
        }
    }

    fn advance_to_payload_staged(
        journal: &mut ActionWorkflowJournal,
        memory: &ContextMemoryService,
        request_id: &str,
    ) -> PlanRecoveryBinding {
        let initial = initial_binding(request_id);
        journal
            .begin_provider_pending(
                memory,
                initial.clone(),
                json!({"secret_url": "https://private.example/path"}),
            )
            .unwrap();
        journal
            .transition(
                memory,
                request_id,
                PlanSagaStage::ProviderPending,
                initial.clone(),
                PlanSagaStage::ProviderReady,
                json!({"provider_output": "private provider output"}),
            )
            .unwrap();
        let mut prepared = initial;
        prepared.plan_id = format!("plan-{request_id}");
        prepared.action_id = format!("action-{request_id}");
        journal
            .transition(
                memory,
                request_id,
                PlanSagaStage::ProviderReady,
                prepared.clone(),
                PlanSagaStage::PlanPrepared,
                json!({"notification_body": "private body"}),
            )
            .unwrap();
        let mut submitted = prepared;
        submitted.accepted_plan_sha256 = "b".repeat(64);
        journal
            .transition(
                memory,
                request_id,
                PlanSagaStage::PlanPrepared,
                submitted.clone(),
                PlanSagaStage::PlanSubmitted,
                json!({"submitted": true}),
            )
            .unwrap();
        let mut dispatched = submitted;
        dispatched.tool_call_id = format!("toolcall-{request_id}");
        journal
            .transition(
                memory,
                request_id,
                PlanSagaStage::PlanSubmitted,
                dispatched.clone(),
                PlanSagaStage::ActionDispatched,
                json!({"dispatched": true}),
            )
            .unwrap();
        journal
            .transition(
                memory,
                request_id,
                PlanSagaStage::ActionDispatched,
                dispatched.clone(),
                PlanSagaStage::PayloadStaged,
                json!({"payload_staged": true}),
            )
            .unwrap();
        dispatched
    }

    fn publish_action_ready(
        journal: &mut ActionWorkflowJournal,
        memory: &ContextMemoryService,
        request_id: &str,
        expires_at_ms: u64,
    ) -> (PlanRecoveryBinding, Value, Value) {
        let mut binding = advance_to_payload_staged(journal, memory, request_id);
        let approval_id = format!("approval-{request_id}");
        let challenge = json!({
            "ui_uid": binding.subject_uid,
            "ui_selinux_domain": binding.subject_selinux_domain,
            "task_id": binding.task_id,
            "plan_id": binding.plan_id,
            "action_id": binding.action_id,
            "tool_call_id": binding.tool_call_id,
            "accepted_plan_sha256": binding.accepted_plan_sha256,
            "approval_id": approval_id,
            "expires_at_ms": expires_at_ms,
            "private_action_payload": "do not persist in plaintext",
        });
        binding.challenge_sha256 = sha256_bytes(&serde_json::to_vec(&challenge).unwrap());
        binding.challenge_expires_at_ms = expires_at_ms;
        let response = json!({
            "task_id": binding.task_id,
            "plan_id": binding.plan_id,
            "provider_id": binding.provider_id,
            "approval_id": approval_id,
            "execution_available": true,
            "action_consent_challenge": challenge,
            "action_consent_challenge_json": serde_json::to_string(&challenge).unwrap(),
        });
        journal
            .publish_plan_ready(
                memory,
                request_id,
                PlanReadyPublication {
                    expected_stage: PlanSagaStage::PayloadStaged,
                    binding: binding.clone(),
                    local_state: json!({"final_local_state": "private"}),
                    exact_plan_response: response.clone(),
                    challenge: Some(challenge.clone()),
                },
            )
            .unwrap();
        (binding, response, challenge)
    }

    fn publish_direct_ready(
        journal: &mut ActionWorkflowJournal,
        memory: &ContextMemoryService,
        request_id: &str,
    ) -> (PlanRecoveryBinding, Value, DirectOperationBinding) {
        let binding = initial_binding(request_id);
        journal
            .begin_provider_pending(
                memory,
                binding.clone(),
                json!({"state": "provider_pending"}),
            )
            .unwrap();
        let workflow_id = format!("workflow-{request_id}");
        let runtime_lifecycle_binding_sha256 = "d".repeat(64);
        let agent_executable_sha256 =
            crate::builtin_provider_identity::active_launcher_identity(&CODEX)
                .map(str::to_string)
                .unwrap_or_else(|| sha256_bytes(b"fixture-independently-measured-active-launcher"));
        let provider_output_sha256 = "c".repeat(64);
        let registration = serde_json::to_value(AgentRegistration {
            api_version: trillionnium_os_types::AGENT_API_VERSION.to_string(),
            agent_id: CODEX.agent_id.to_string(),
            adapter: CODEX.runtime_adapter.to_string(),
            adapter_version: "fixture".to_string(),
            identity_key_sha256: agent_executable_sha256.clone(),
            peer_uid: CODEX.uid,
            peer_gid: CODEX.gid,
            selinux_domain: CODEX.agent_selinux_domain.to_string(),
            network_policy: trillionnium_os_types::AgentNetworkPolicy::PerRequest,
            enabled: true,
            health: trillionnium_os_types::AgentHealth::Ready,
            registered_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        })
        .unwrap();
        let agent_manifest_sha256 = sha256_json(&registration);
        let summary = "private provider summary";
        let runtime_provider = "openai-codex";
        let model = "built-in.codex-cli-test/test-model";
        let direct_evidence_sha256 = sha256_json(&json!({
            "schema": "trillionnium.agent-direct-evidence.v2",
            "tool_calls": [],
        }));
        let mut direct_receipt_commitment = json!({
            "schema": direct_agent_host_abi::DIRECT_RECEIPT_SCHEMA,
            "direct_agent_host_abi": direct_agent_host_abi::ABI_SCHEMA,
            "direct_agent_host_abi_sha256": direct_agent_host_abi::CONTRACT_SHA256,
            "direct_result_schema": direct_agent_host_abi::DIRECT_RESULT_SCHEMA,
            "request_id_sha256": sha256_bytes(request_id.as_bytes()),
            "request_payload_sha256": binding.request_payload_sha256,
            "subject_uid": binding.subject_uid,
            "subject_selinux_domain_sha256": sha256_bytes(binding.subject_selinux_domain.as_bytes()),
            "provider_id": binding.provider_id,
            "workflow_id_sha256": sha256_bytes(workflow_id.as_bytes()),
            "task_id": binding.task_id,
            "agent_id": CODEX.agent_id,
            "agent_manifest_sha256": agent_manifest_sha256,
            "agent_executable_sha256": agent_executable_sha256,
            "runtime_lifecycle_binding_sha256": runtime_lifecycle_binding_sha256,
            "runtime_provider": runtime_provider,
            "model": model,
            "summary_sha256": sha256_bytes(summary.as_bytes()),
            "provider_output_sha256": provider_output_sha256,
            "direct_evidence_sha256": direct_evidence_sha256,
            "direct_call_evidence": [],
            "direct_outcome": "no_action",
            "direct_refusal_sha256": null,
            "direct_tool_call_events": 0,
            "completed_direct_tool_calls": 0,
            "direct_tool_names": [],
            "shell_exec_authorization_sha256": null,
            "shell_exec_direct_binding_sha256": null,
        });
        bind_build_local_direct_receipt_commitment(&mut direct_receipt_commitment);
        let direct_execution_receipt_sha256 = sha256_json(&direct_receipt_commitment);
        let mut response = json!({
            "task_id": binding.task_id,
            "direct_execution_receipt_id": format!("direct-receipt-{direct_execution_receipt_sha256}"),
            "direct_execution_receipt_sha256": direct_execution_receipt_sha256,
            "direct_receipt_commitment": direct_receipt_commitment,
            "plan_id": "",
            "approval_id": "",
            "action": "agent_direct_result",
            "summary": summary,
            "model": model,
            "provider_id": binding.provider_id,
            "provider": runtime_provider,
            "provider_output_sha256": provider_output_sha256,
            "agent_id": CODEX.agent_id,
            "agent_manifest_sha256": agent_manifest_sha256,
            "agent_executable_sha256": agent_executable_sha256,
            "runtime_lifecycle_binding_sha256": runtime_lifecycle_binding_sha256,
            "request_payload_sha256": binding.request_payload_sha256,
            "workflow_id_sha256": sha256_bytes(workflow_id.as_bytes()),
            "direct_evidence_sha256": direct_evidence_sha256,
            "direct_call_evidence": [],
            "direct_outcome": "no_action",
            "direct_refusal_reason": null,
            "direct_refusal_sha256": null,
            "execution_mode": "agent_direct",
            "requires_approval": false,
            "execution_available": true,
            "execution_completed": false,
            "network_scope": "provider_egress_only",
            "model_invoked_tools": false,
            "model_executed_tools": false,
            "direct_tool_call_events": 0,
            "completed_direct_tool_calls": 0,
            "direct_tool_names": [],
            "plan_submitted_for_execution": false,
            "authority_called": false,
            "plan_latency_ms": 7,
            "egress_grant_consumed": true,
        });
        direct_agent_host_abi::bind_direct_result_contract(
            response
                .as_object_mut()
                .expect("direct result fixture construction produces an object"),
        );
        let local_state = json!({
            "schema": "trillionnium.local-plan-saga.v3",
            "request_id": request_id,
            "request_payload_sha256": binding.request_payload_sha256,
            "peer_uid": binding.subject_uid,
            "peer_domain": binding.subject_selinux_domain,
            "provider_id": binding.provider_id,
            "workflow_id": workflow_id,
            "task_id": binding.task_id,
            "registration": registration,
            "agent_executable": {"sha256": agent_executable_sha256},
            "agent_manifest_sha256": agent_manifest_sha256,
            "runtime_lifecycle_binding_sha256": runtime_lifecycle_binding_sha256,
            "authorized_adapter_set": trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            "provider_result": {
                "submission": null,
                "execution_mode": "agent_direct",
                "direct_outcome": "no_action",
                "direct_refusal_reason": null,
                "direct_tool_calls": [],
                "summary": summary,
                "runtime_provider": runtime_provider,
                "model": model,
                "elapsed_ms": 7,
                "provider_output_sha256": provider_output_sha256,
            },
        });
        journal
            .transition(
                memory,
                request_id,
                PlanSagaStage::ProviderPending,
                binding.clone(),
                PlanSagaStage::ProviderReady,
                local_state.clone(),
            )
            .unwrap();
        journal
            .publish_plan_ready(
                memory,
                request_id,
                PlanReadyPublication {
                    expected_stage: PlanSagaStage::ProviderReady,
                    binding: binding.clone(),
                    local_state,
                    exact_plan_response: response.clone(),
                    challenge: None,
                },
            )
            .unwrap();

        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: binding.provider_id.clone(),
            agent_id: CODEX.agent_id.to_string(),
            task_id: binding.task_id.clone(),
            provider_invocation_id_sha256: sha256_bytes(request_id.as_bytes()),
            provider_session_id_sha256: sha256_bytes(
                format!("android-ui-{}-{workflow_id}", binding.subject_uid).as_bytes(),
            ),
            subject_uid: binding.subject_uid,
            subject_selinux_domain_sha256: sha256_bytes(binding.subject_selinux_domain.as_bytes()),
        };
        let invocation_id = stable_seed.invocation_id().unwrap();
        let attempt = DirectOperationProviderAttempt::derive(
            runtime_lifecycle_binding_sha256,
            1,
            "f".repeat(64),
        )
        .unwrap();
        let direct_binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed,
            invocation_id,
            workflow_id_sha256: sha256_bytes(workflow_id.as_bytes()),
            agent_identity_key_sha256: agent_executable_sha256.clone(),
            agent_executable_sha256,
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt,
        };
        (binding, response, direct_binding)
    }

    fn replace_direct_secret_unchecked<F>(
        journal: &mut ActionWorkflowJournal,
        memory: &ContextMemoryService,
        request_id: &str,
        mutate: F,
    ) where
        F: FnOnce(&mut WorkflowSecret),
    {
        let index = journal.record_index(request_id).unwrap();
        let record = journal.file.records[index].clone();
        let mut secret = decrypt_record(memory, &record).unwrap();
        mutate(&mut secret);
        let clear = serde_json::to_vec(&secret).unwrap();
        let aad = workflow_aad(record.stage, &record.binding).unwrap();
        let ciphertext = memory
            .seal_workflow_blob(&aad, &clear, MAX_SECRET_BYTES)
            .unwrap();
        journal.file.records[index].ciphertext_b64 = BASE64_STANDARD.encode(&ciphertext);
        journal.file.records[index].ciphertext_sha256 = sha256_bytes(&ciphertext);
    }

    #[test]
    fn durable_direct_workflow_uses_the_supervised_codex_mcp_identity_set() {
        assert_eq!(
            CODEX_DIRECT_MCP_TOOL_NAMES,
            &["trillionnium_system_api", "trillionnium_shell_exec"]
        );
        assert!(codex_direct_mcp_identity_is_authorized(
            "trillionnium_system_api",
            "trillionnium_system_api"
        ));
        assert!(codex_direct_mcp_identity_is_authorized(
            "trillionnium_shell_exec",
            "trillionnium_shell_exec"
        ));
        assert!(!codex_direct_mcp_identity_is_authorized(
            "trillionnium_accessibility",
            "trillionnium_accessibility"
        ));
        assert!(!codex_direct_mcp_tool_name_is_authorized(
            "trillionnium_adb"
        ));
    }

    #[test]
    fn direct_plan_snapshot_is_exact_retained_and_excluded_from_legacy_custody() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let (workflow_binding, response, direct_binding) =
            publish_direct_ready(&mut journal, &memory, "direct-retained");
        let proof = "1".repeat(64);
        journal
            .record_ui_completion_proof(
                &memory,
                "plan",
                &workflow_binding.request_id,
                workflow_binding.subject_uid,
                &workflow_binding.subject_selinux_domain,
                &workflow_binding.request_payload_sha256,
                &proof,
            )
            .unwrap();

        assert!(journal.custody_candidates(&memory).unwrap().is_empty());
        let candidate = journal
            .direct_plan_custody_candidate(&memory, &direct_binding)
            .unwrap()
            .expect("exact Direct PlanReady must produce a sealed snapshot");
        assert_eq!(candidate.direct_binding(), &direct_binding);
        assert_eq!(
            candidate.direct_binding_sha256(),
            direct_binding.digest_sha256().unwrap()
        );
        assert_eq!(candidate.workflow_binding(), &workflow_binding);
        assert_eq!(candidate.request_id(), workflow_binding.request_id);
        assert_eq!(
            candidate.request_payload_sha256(),
            workflow_binding.request_payload_sha256
        );
        assert_eq!(candidate.subject_uid(), workflow_binding.subject_uid);
        assert_eq!(
            candidate.subject_selinux_domain(),
            workflow_binding.subject_selinux_domain
        );
        assert_eq!(candidate.exact_plan_response(), &response);
        assert_eq!(
            candidate.exact_plan_response_semantic_sha256(),
            sha256_json(&response)
        );
        assert_eq!(
            candidate.direct_execution_receipt_sha256(),
            response["direct_execution_receipt_sha256"]
                .as_str()
                .unwrap()
        );
        assert_eq!(
            candidate.plan_ui_completion_proof_sha256(),
            Some(proof.as_str())
        );
        assert!(valid_digest(candidate.record_fingerprint_sha256()));

        // A legacy/test-only action record retains the old UI-custody
        // behavior and remains the sole generic candidate.
        let (legacy_binding, _, _) = publish_action_ready(
            &mut journal,
            &memory,
            "legacy-custody",
            now_unix_ms() + 60_000,
        );
        journal
            .record_ui_completion_proof(
                &memory,
                "plan",
                &legacy_binding.request_id,
                legacy_binding.subject_uid,
                &legacy_binding.subject_selinux_domain,
                &legacy_binding.request_payload_sha256,
                &"2".repeat(64),
            )
            .unwrap();
        let generic = journal.custody_candidates(&memory).unwrap();
        assert_eq!(generic.len(), 1);
        assert_eq!(generic[0].plan.request_id, "legacy-custody");

        let fingerprint = candidate.record_fingerprint_sha256().to_string();
        drop(journal);
        let mut reopened = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        assert_eq!(reopened.custody_candidates(&memory).unwrap().len(), 1);
        let reopened_candidate = reopened
            .direct_plan_custody_candidate(&memory, &direct_binding)
            .unwrap()
            .unwrap();
        assert_eq!(reopened_candidate.record_fingerprint_sha256(), fingerprint);
        assert_eq!(
            reopened_candidate.exact_plan_response_semantic_sha256(),
            candidate.exact_plan_response_semantic_sha256()
        );

        // Retention is deliberately bounded.  With no direct handoff, a full
        // active set rejects a new workflow instead of deleting Direct data.
        let retained = reopened
            .file
            .records
            .iter()
            .find(|record| record.binding.request_id == "direct-retained")
            .unwrap()
            .clone();
        while reopened.file.records.len() < MAX_RECORDS {
            reopened.file.records.push(retained.clone());
        }
        let error = reopened
            .begin_provider_pending(
                &memory,
                initial_binding("capacity-denied"),
                json!({"must_not_publish": true}),
            )
            .unwrap_err();
        assert!(error.to_string().contains("active_capacity_reached"));
    }

    #[test]
    fn direct_plan_snapshot_rejects_response_and_binding_drift() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let (_workflow_binding, _response, direct_binding) =
            publish_direct_ready(&mut journal, &memory, "direct-drift");
        let index = journal.record_index("direct-drift").unwrap();
        let original = journal.file.records[index].clone();

        replace_direct_secret_unchecked(&mut journal, &memory, "direct-drift", |secret| {
            secret.exact_plan_response.as_mut().unwrap()["unknown_attacker_field"] = json!(true);
        });
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &direct_binding)
                .unwrap_err()
                .to_string()
                .contains("not_closed_world")
        );

        journal.file.records[index] = original.clone();
        replace_direct_secret_unchecked(&mut journal, &memory, "direct-drift", |secret| {
            secret
                .exact_plan_response
                .as_mut()
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove("summary");
        });
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &direct_binding)
                .is_err()
        );

        journal.file.records[index] = original.clone();
        replace_direct_secret_unchecked(&mut journal, &memory, "direct-drift", |secret| {
            secret.exact_plan_response.as_mut().unwrap()["plan_latency_ms"] = json!("7");
        });
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &direct_binding)
                .unwrap_err()
                .to_string()
                .contains("projection_mismatch")
        );

        journal.file.records[index] = original.clone();
        replace_direct_secret_unchecked(&mut journal, &memory, "direct-drift", |secret| {
            secret.exact_plan_response.as_mut().unwrap()["direct_receipt_commitment"]["task_id"] =
                json!("task-substitution");
        });
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &direct_binding)
                .is_err()
        );

        #[cfg(feature = "p0-launch-package-device-conformance")]
        {
            journal.file.records[index] = original.clone();
            replace_direct_secret_unchecked(&mut journal, &memory, "direct-drift", |secret| {
                let response = secret.exact_plan_response.as_mut().unwrap();
                response["direct_receipt_commitment"]["p01_daemon_build_binding_sha256"] =
                    json!("1".repeat(64));
                let commitment_sha256 = sha256_json(&response["direct_receipt_commitment"]);
                response["direct_execution_receipt_sha256"] = json!(commitment_sha256.clone());
                response["direct_execution_receipt_id"] =
                    json!(format!("direct-receipt-{commitment_sha256}"));
            });
            let error = journal
                .direct_plan_custody_candidate(&memory, &direct_binding)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                "action_workflow_direct_response_contract_mismatch"
            );
        }

        journal.file.records[index] = original;
        let mut wrong_provider = direct_binding.clone();
        wrong_provider.stable_seed.provider_id = "unregistered-provider".to_string();
        wrong_provider.stable_seed.agent_id = "unregistered-agent".to_string();
        assert!(wrong_provider.stable_seed.invocation_id().is_err());
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &wrong_provider)
                .is_err()
        );

        let mut wrong_task = direct_binding.clone();
        wrong_task.stable_seed.task_id = "task-substitution".to_string();
        wrong_task.invocation_id = wrong_task.stable_seed.invocation_id().unwrap();
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &wrong_task)
                .is_err()
        );

        let mut wrong_subject = direct_binding.clone();
        wrong_subject.stable_seed.subject_uid += 1;
        wrong_subject.invocation_id = wrong_subject.stable_seed.invocation_id().unwrap();
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &wrong_subject)
                .is_err()
        );

        let mut wrong_session = direct_binding.clone();
        wrong_session.stable_seed.provider_session_id_sha256 = "9".repeat(64);
        wrong_session.invocation_id = wrong_session.stable_seed.invocation_id().unwrap();
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &wrong_session)
                .is_err()
        );

        let mut wrong_lifecycle = direct_binding.clone();
        wrong_lifecycle.attempt =
            DirectOperationProviderAttempt::derive("8".repeat(64), 2, "7".repeat(64)).unwrap();
        assert!(
            journal
                .direct_plan_custody_candidate(&memory, &wrong_lifecycle)
                .is_err()
        );

        // The exact authenticated attempt, including generation and daemon
        // context, is retained byte-for-byte in the sealed candidate.
        let candidate = journal
            .direct_plan_custody_candidate(&memory, &direct_binding)
            .unwrap()
            .unwrap();
        assert_eq!(candidate.direct_binding().attempt, direct_binding.attempt);
    }

    #[test]
    fn provider_pending_reopen_is_fixed_indeterminate_and_never_resumable() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let binding = initial_binding("provider-pending");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        journal
            .begin_provider_pending(&memory, binding.clone(), json!({"network_calls": 1}))
            .unwrap();
        drop(journal);

        let reopened = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        assert_eq!(
            reopened.restart_candidates(),
            vec![(
                "provider-pending".to_string(),
                PlanSagaStage::ProviderPending
            )]
        );
        match reopened
            .recover_plan(&memory, "provider-pending", &"a".repeat(64), 10_123, DOMAIN)
            .unwrap()
        {
            PlanWorkflowRecovery::Indeterminate(reason) => {
                assert_eq!(reason, "provider_outcome_unknown_no_network_reexecution")
            }
            _ => panic!("provider-pending must never be resumed"),
        }
    }

    #[test]
    fn retired_action_ready_response_is_not_replayed_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let (_binding, response, _challenge) = publish_action_ready(
            &mut journal,
            &memory,
            "ready-reopen",
            now_unix_ms() + 60_000,
        );
        drop(journal);

        let at_rest = fs::read_to_string(&path).unwrap();
        assert!(!at_rest.contains("private.example"));
        assert!(!at_rest.contains("private body"));
        assert!(!at_rest.contains("do not persist in plaintext"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut reopened = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        match reopened
            .recover_plan(&memory, "ready-reopen", &"a".repeat(64), 10_123, DOMAIN)
            .unwrap()
        {
            PlanWorkflowRecovery::Indeterminate(reason) => {
                assert_eq!(reason, RETIRED_NON_DIRECT_WORKFLOW_REASON)
            }
            other => panic!("retired action response escaped recovery quarantine: {other:?}"),
        }
        assert_ne!(response.get("execution_mode"), Some(&json!("agent_direct")));
        assert_eq!(
            reopened.restart_candidates(),
            vec![("ready-reopen".to_string(), PlanSagaStage::PlanReady)]
        );
        reopened
            .retire_non_direct_workflow(&memory, "ready-reopen")
            .unwrap();
        assert!(reopened.restart_candidates().is_empty());
        assert!(
            reopened
                .pending_challenge(&memory, "approval-ready-reopen", now_unix_ms())
                .is_err()
        );
        assert!(
            reopened
                .recover_plan(&memory, "ready-reopen", &"c".repeat(64), 10_123, DOMAIN)
                .unwrap_err()
                .to_string()
                .contains("recovery_binding_mismatch")
        );
        drop(reopened);
        let reopened = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        match reopened
            .recover_plan(&memory, "ready-reopen", &"a".repeat(64), 10_123, DOMAIN)
            .unwrap()
        {
            PlanWorkflowRecovery::Indeterminate(reason) => {
                assert_eq!(reason, RETIRED_NON_DIRECT_WORKFLOW_REASON)
            }
            other => panic!("retired action response revived after reopen: {other:?}"),
        }
    }

    #[test]
    fn consuming_and_consumed_bindings_survive_restart_without_pending_reuse() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        publish_action_ready(
            &mut journal,
            &memory,
            "consume-reopen",
            now_unix_ms() + 60_000,
        );
        let consuming = ConsumingApprovalBinding {
            approve_request_id: "approve-consume-reopen".to_string(),
            approve_payload_sha256: "c".repeat(64),
            action_consent_receipt_id: "d".repeat(64),
            started_at_ms: now_unix_ms(),
        };
        journal
            .begin_consuming(&memory, "approval-consume-reopen", consuming.clone())
            .unwrap();
        drop(journal);

        let mut reopened = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let view = reopened
            .action_view(&memory, "approval-consume-reopen")
            .unwrap();
        assert_eq!(view.state, ActionConsentState::Consuming);
        assert_eq!(view.consuming.as_ref(), Some(&consuming));
        assert!(
            reopened
                .begin_consuming(
                    &memory,
                    "approval-consume-reopen",
                    ConsumingApprovalBinding {
                        approve_request_id: "approve-attacker".to_string(),
                        ..consuming.clone()
                    },
                )
                .is_err()
        );
        reopened
            .mark_consumed(
                &memory,
                "approval-consume-reopen",
                &consuming,
                now_unix_ms(),
            )
            .unwrap();
        drop(reopened);
        let reopened = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        assert_eq!(
            reopened
                .action_view(&memory, "approval-consume-reopen")
                .unwrap()
                .state,
            ActionConsentState::Consumed
        );
    }

    #[test]
    fn expired_challenge_is_durable_and_never_consumed() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        publish_action_ready(
            &mut journal,
            &memory,
            "expired",
            now_unix_ms().saturating_sub(1),
        );
        assert!(
            journal
                .pending_challenge(&memory, "approval-expired", now_unix_ms())
                .unwrap_err()
                .to_string()
                .contains("action_consent_expired")
        );
        drop(journal);
        let reopened = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        assert_eq!(
            reopened
                .action_view(&memory, "approval-expired")
                .unwrap()
                .state,
            ActionConsentState::Expired
        );
    }

    #[test]
    fn aad_tamper_duplicate_json_and_tombstone_reuse_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let binding = initial_binding("tombstoned");
        journal.push_tombstone(
            binding.clone(),
            "plan_outcome_indeterminate_no_network_reexecution",
        );
        journal.flush(&memory).unwrap();
        match journal
            .recover_plan(&memory, "tombstoned", &"a".repeat(64), 10_123, DOMAIN)
            .unwrap()
        {
            PlanWorkflowRecovery::Indeterminate(_) => {}
            _ => panic!("tombstone must never permit a fresh provider run"),
        }
        assert!(
            journal
                .begin_provider_pending(&memory, binding, json!({}))
                .unwrap_err()
                .to_string()
                .contains("request_id_binding_conflict")
        );

        let mut encoded = fs::read_to_string(&path).unwrap();
        encoded = encoded.replacen(
            "\"schema\": \"trillionnium.action-workflow-journal.v2\"",
            "\"schema\": \"trillionnium.action-workflow-journal.v2\",\n  \"schema\": \"trillionnium.action-workflow-journal.v2\"",
            1,
        );
        fs::write(&path, encoded).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ActionWorkflowJournal::open_for_test(&memory, &path).is_err());
    }

    #[test]
    fn outer_binding_tamper_cannot_relabel_encrypted_workflow() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        journal
            .begin_provider_pending(
                &memory,
                initial_binding("aad-tamper"),
                json!({"private": "sealed"}),
            )
            .unwrap();
        drop(journal);
        let mut envelope: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["records"][0]["binding"]["task_id"] = json!("task-attacker");
        let mut encoded = serde_json::to_vec_pretty(&envelope).unwrap();
        encoded.push(b'\n');
        fs::write(&path, encoded).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        ActionWorkflowJournal::open_for_test(&memory, &path)
            .err()
            .expect("AAD relabeling must fail closed");
    }

    #[test]
    fn post_rename_parent_fsync_uncertainty_keeps_published_generation_and_fail_stops() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        let mut journal = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        journal.fail_parent_fsync_after_rename_once_for_test();
        let error = journal
            .begin_provider_pending(
                &memory,
                initial_binding("published-uncertain"),
                json!({"private": "sealed"}),
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("published_parent_fsync_uncertain")
        );
        assert!(journal.publication_durability_uncertain_for_test());
        assert_eq!(
            journal.restart_candidates(),
            vec![(
                "published-uncertain".to_string(),
                PlanSagaStage::ProviderPending
            )]
        );
        assert!(
            journal
                .begin_provider_pending(
                    &memory,
                    initial_binding("must-not-enter-memory"),
                    json!({}),
                )
                .unwrap_err()
                .to_string()
                .contains("fail_stop_published_durability_uncertain")
        );
        assert_eq!(journal.restart_candidates().len(), 1);
        drop(journal);

        let reopened = ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        assert_eq!(
            reopened.restart_candidates(),
            vec![(
                "published-uncertain".to_string(),
                PlanSagaStage::ProviderPending
            )]
        );
    }

    #[test]
    fn open_removes_only_strict_owner_private_action_workflow_temps() {
        let temp = tempfile::tempdir().unwrap();
        let memory = context(temp.path());
        let path = temp.path().join("workflow.json");
        ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();

        let owned_temp = temp.path().join(".action-workflow.tmp-123-456-789");
        fs::write(&owned_temp, b"interrupted unpublished generation").unwrap();
        fs::set_permissions(&owned_temp, fs::Permissions::from_mode(0o600)).unwrap();
        ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        assert!(!owned_temp.exists());

        let malformed = temp.path().join(".action-workflow.tmp-malformed");
        fs::write(&malformed, b"not an owned temp name").unwrap();
        fs::set_permissions(&malformed, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ActionWorkflowJournal::open_for_test(&memory, &path).is_err());
        assert!(malformed.exists());
    }
}
