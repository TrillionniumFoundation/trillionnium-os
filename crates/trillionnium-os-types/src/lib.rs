pub mod agent_descriptor_registry;
pub mod agent_direct_permission_model;
pub mod agent_principal_registry;
pub mod capability_lease_activation_gate;
pub mod capability_lease_agent_binding;
pub mod capability_lease_android_evidence;
pub mod capability_lease_root_authenticator;
#[cfg(test)]
mod capability_lease_root_contract_graph;
pub mod capability_lease_root_proof_carrier;
pub mod capability_lease_root_publication;
pub mod capability_lease_root_publisher_launch;
pub mod capability_lease_root_registration;
pub mod capability_lease_root_route_session;
pub mod capability_lease_root_route_socket_custody;
pub mod capability_lease_root_route_transport;
pub mod direct_agent_host_abi;
pub mod direct_effect;
pub mod direct_operation;
pub mod direct_operation_custody_high_water;
pub mod direct_operation_runtime_authority;
pub mod direct_operation_runtime_authority_mutation_cas;
pub mod direct_operation_stdio_proxy;
pub mod direct_operation_tool_call_transport;
#[cfg(feature = "p0-launch-package-device-conformance")]
pub mod p0_launch_package_device_conformance;
pub mod provider_post_exec_containment;
pub mod provider_seccomp_contract;
mod sha256;
pub mod typed_operation_catalog;

pub use sha256::{SHA256_HEX_LEN, is_lower_sha256, is_nonzero_lower_sha256};

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const TOOL_SCHEMA_VERSION: &str = "trillionnium.tool.v1";
pub const AGENT_API_VERSION: &str = "trillionnium.agent-api.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentNetworkPolicy {
    Deny,
    PerRequest,
    Allowlisted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealth {
    Ready,
    Degraded,
    Offline,
    Disabled,
}

/// OS-owned identity for an interchangeable built-in agent runtime.
///
/// Agent credentials and model/provider details stay behind the adapter. The
/// OS authorizes this identity, never an untrusted model string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentRegistration {
    pub api_version: String,
    pub agent_id: String,
    pub adapter: String,
    pub adapter_version: String,
    pub identity_key_sha256: String,
    pub peer_uid: u32,
    /// Primary group authenticated by the kernel for this Agent process.
    /// This is an independent OS-owned identity component; callers must not
    /// infer it from `peer_uid`.
    pub peer_gid: u32,
    pub selinux_domain: String,
    pub network_policy: AgentNetworkPolicy,
    pub enabled: bool,
    pub health: AgentHealth,
    pub registered_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContextPrivacyClass {
    Public,
    LocalPrivate,
    Sensitive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentContextRef {
    pub context_id: String,
    pub source_id: String,
    pub source_kind: String,
    pub captured_at_unix_ms: u64,
    pub freshness_ttl_ms: u64,
    pub privacy_class: ContextPrivacyClass,
    pub content_sha256: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPlannedAction {
    pub action_id: String,
    pub tool_name: String,
    /// OS-authored digest of the complete ToolManifest accepted with this
    /// action. Providers must omit it; the broker fills it before persistence
    /// and requires an exact match again before execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_tool_manifest_sha256: Option<String>,
    /// OS-authored digest of the exact daemon executable that accepted the
    /// plan. This invalidates accepted plans across daemon rebuilds even when
    /// a ToolManifest remains byte-for-byte unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_executor_sha256: Option<String>,
    pub arguments: Value,
    pub arguments_sha256: String,
    pub rationale: String,
    pub requires_approval: bool,
    pub network_scope: String,
    pub undo_contract: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPlanSubmission {
    pub api_version: String,
    pub plan_id: String,
    pub task_id: TaskId,
    pub session_id: String,
    pub agent_id: String,
    pub intent_sha256: String,
    pub provider_output_sha256: String,
    pub contexts: Vec<AgentContextRef>,
    pub actions: Vec<AgentPlannedAction>,
    pub created_at_unix_ms: u64,
}

/// A public Agent API execution request deliberately contains no tool name or
/// arguments. The OS resolves both from the immutable plan it accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentExecutionRequest {
    pub task_id: TaskId,
    pub plan_id: String,
    pub action_id: String,
}

/// OS-authored binding recorded before a planned action enters policy and
/// approval. `tool_call_id` is deterministic for a plan action, making a
/// repeated dispatch fail closed across daemon restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentExecutionBinding {
    pub agent_id: String,
    pub peer_uid: u32,
    pub peer_gid: u32,
    pub peer_selinux_domain: String,
    pub agent_executable_sha256: String,
    pub subject_user_id: u32,
    pub origin_uid: u32,
    pub origin_selinux_domain: String,
    pub session_id: String,
    pub task_id: TaskId,
    pub plan_id: String,
    pub action_id: String,
    pub tool_call_id: ToolCallId,
    pub tool_name: String,
    pub tool_manifest_sha256: String,
    /// Digest of the complete immutable `AgentPlanSubmission` loaded from the
    /// OS audit store. This is deliberately distinct from any provider-level
    /// `plan_sha256` carried inside an action's frozen arguments.
    pub accepted_plan_sha256: String,
    pub arguments_sha256: String,
}

impl AgentExecutionBinding {
    /// Stable approval subject independent of plan/action ids. A CurrentTask
    /// grant may cover another action only for the exact same attested Agent,
    /// Linux peer, Android subject, origin and session.
    pub fn approval_subject_sha256(&self) -> String {
        sha256_json(&serde_json::json!({
            "agent_id": self.agent_id,
            "peer_uid": self.peer_uid,
            "peer_gid": self.peer_gid,
            "peer_selinux_domain": self.peer_selinux_domain,
            "agent_executable_sha256": self.agent_executable_sha256,
            "subject_user_id": self.subject_user_id,
            "origin_uid": self.origin_uid,
            "origin_selinux_domain": self.origin_selinux_domain,
            "session_id": self.session_id,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AgentApiValidation {
    pub valid: bool,
    pub errors: Vec<String>,
}

impl AgentApiValidation {
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn failed(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }
}

pub fn validate_agent_registration(registration: &AgentRegistration) -> AgentApiValidation {
    let mut errors = Vec::new();
    if registration.api_version != AGENT_API_VERSION {
        errors.push("unsupported api_version".to_string());
    }
    if !valid_stable_id(&registration.agent_id, "agent-") {
        errors.push("agent_id must be a stable agent-* identifier".to_string());
    }
    if registration.adapter.trim().is_empty()
        || registration.adapter.trim() != registration.adapter
        || registration.adapter.len() > 128
        || registration.adapter.chars().any(char::is_control)
    {
        errors.push("adapter must be 1..=128 bytes".to_string());
    }
    if registration.adapter_version.trim().is_empty()
        || registration.adapter_version.trim() != registration.adapter_version
        || registration.adapter_version.len() > 64
        || registration.adapter_version.chars().any(char::is_control)
    {
        errors.push("adapter_version must be 1..=64 bytes".to_string());
    }
    if !is_lower_sha256(&registration.identity_key_sha256) {
        errors.push("identity_key_sha256 must be 64 lowercase hex characters".to_string());
    }
    if registration.peer_uid == 0 {
        errors.push("peer_uid must be a dedicated non-root UID".to_string());
    }
    if registration.peer_gid == 0 {
        errors.push("peer_gid must be a dedicated non-root GID".to_string());
    }
    if registration.selinux_domain.trim().is_empty()
        || registration.selinux_domain.trim() != registration.selinux_domain
        || registration.selinux_domain.len() > 128
        || registration.selinux_domain.chars().any(char::is_control)
    {
        errors.push("selinux_domain must be 1..=128 bytes".to_string());
    }
    if registration.updated_at_unix_ms < registration.registered_at_unix_ms {
        errors.push("updated_at_unix_ms must not predate registration".to_string());
    }
    if errors.is_empty() {
        AgentApiValidation::ok()
    } else {
        AgentApiValidation::failed(errors)
    }
}

pub fn validate_agent_plan(plan: &AgentPlanSubmission) -> AgentApiValidation {
    let mut errors = Vec::new();
    if plan.api_version != AGENT_API_VERSION {
        errors.push("unsupported api_version".to_string());
    }
    if !valid_stable_id(&plan.plan_id, "plan-") {
        errors.push("plan_id must be a stable plan-* identifier".to_string());
    }
    if !valid_stable_id(&plan.agent_id, "agent-") {
        errors.push("agent_id must be a stable agent-* identifier".to_string());
    }
    if plan.session_id.trim().is_empty() || plan.session_id.len() > 128 {
        errors.push("session_id must be 1..=128 bytes".to_string());
    }
    if !is_lower_sha256(&plan.intent_sha256) || !is_lower_sha256(&plan.provider_output_sha256) {
        errors.push("intent/provider output digests must be sha256".to_string());
    }
    if plan.actions.is_empty() || plan.actions.len() > 32 {
        errors.push("actions must contain 1..=32 entries".to_string());
    }
    let mut action_ids = std::collections::BTreeSet::new();
    for action in &plan.actions {
        if !action_ids.insert(action.action_id.as_str()) {
            errors.push(format!("duplicate action_id: {}", action.action_id));
        }
        if !valid_stable_id(&action.action_id, "action-") {
            errors.push(format!("invalid action_id: {}", action.action_id));
        }
        if action.tool_name.trim().is_empty() || action.tool_name.len() > 128 {
            errors.push(format!("invalid tool_name for {}", action.action_id));
        }
        if action
            .os_tool_manifest_sha256
            .as_ref()
            .is_some_and(|digest| !is_lower_sha256(digest))
        {
            errors.push(format!(
                "invalid OS tool manifest digest for {}",
                action.action_id
            ));
        }
        if action
            .os_executor_sha256
            .as_ref()
            .is_some_and(|digest| !is_lower_sha256(digest))
        {
            errors.push(format!(
                "invalid OS executor digest for {}",
                action.action_id
            ));
        }
        if !is_lower_sha256(&action.arguments_sha256)
            || action.arguments_sha256 != sha256_json(&action.arguments)
        {
            errors.push(format!(
                "arguments digest mismatch for {}",
                action.action_id
            ));
        }
        if action.undo_contract.trim().is_empty() || action.undo_contract.len() > 256 {
            errors.push(format!("missing undo contract for {}", action.action_id));
        }
        if !matches!(
            action.network_scope.as_str(),
            "none" | "per_request" | "allowlisted"
        ) {
            errors.push(format!("invalid network scope for {}", action.action_id));
        }
    }
    for context in &plan.contexts {
        if context.revoked {
            errors.push(format!("revoked context: {}", context.context_id));
        }
        if !is_lower_sha256(&context.content_sha256) {
            errors.push(format!("invalid context digest: {}", context.context_id));
        }
    }
    if errors.is_empty() {
        AgentApiValidation::ok()
    } else {
        AgentApiValidation::failed(errors)
    }
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn sha256_reader(mut reader: impl Read) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn sha256_json(value: &Value) -> String {
    let encoded = serde_json::to_vec(value).unwrap_or_default();
    sha256_bytes(&encoded)
}

fn valid_stable_id(value: &str, prefix: &str) -> bool {
    value.starts_with(prefix)
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct TaskId(pub String);

impl TaskId {
    pub fn new() -> Self {
        Self(format!("task-{}", Uuid::new_v4()))
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ToolCallId(pub String);

impl ToolCallId {
    pub fn new() -> Self {
        Self(format!("toolcall-{}", Uuid::new_v4()))
    }
}

impl Default for ToolCallId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRequirement {
    None,
    Ask,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLifetime {
    OneCall,
    CurrentTask,
    CurrentSession,
    UntilReboot,
    Persistent,
    NeverAllow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolExecutorKind {
    LocalShim,
    AndroidGateway,
    Native,
    Process,
    SystemdScope,
    Waydroid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolExecutor {
    pub kind: ToolExecutorKind,
    pub command: Vec<String>,
}

/// OS-authored preview semantics for an action backed by this manifest.
///
/// Agent plans must copy these fields exactly. They are deliberately part of
/// the serialized manifest so the execution binding's manifest digest freezes
/// the same approval, network, and undo semantics shown before execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPlanActionContract {
    pub requires_approval: bool,
    pub network_scope: String,
    pub undo_contract: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolManifest {
    pub schema_version: String,
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub output_schema: Value,
    pub capabilities: Vec<String>,
    pub risk: RiskTier,
    pub executor: ToolExecutor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_plan_contract: Option<AgentPlanActionContract>,
}

impl ToolManifest {
    pub fn system_status() -> Self {
        Self {
            schema_version: TOOL_SCHEMA_VERSION.to_string(),
            name: "system.status".to_string(),
            description: "Return non-sensitive OS and daemon status.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "required": ["ok", "daemon", "platform"],
                "properties": {
                    "ok": { "type": "boolean" },
                    "daemon": { "type": "string" },
                    "platform": { "type": "string" }
                },
                "additionalProperties": false
            }),
            capabilities: vec!["system.status".to_string()],
            risk: RiskTier::Low,
            executor: ToolExecutor {
                kind: ToolExecutorKind::LocalShim,
                command: vec![
                    "trillionnium-os-local-shim".to_string(),
                    "system.status".to_string(),
                ],
            },
            agent_plan_contract: Some(AgentPlanActionContract {
                requires_approval: false,
                network_scope: "none".to_string(),
                undo_contract: "none".to_string(),
            }),
        }
    }

    pub fn demo_approval_echo() -> Self {
        Self {
            schema_version: TOOL_SCHEMA_VERSION.to_string(),
            name: "demo.approval_echo".to_string(),
            description: "Safe medium-risk demo tool that echoes a message only after approval."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "required": ["message"],
                "properties": {
                    "message": { "type": "string", "minLength": 1, "maxLength": 4096 }
                },
                "additionalProperties": false
            }),
            output_schema: serde_json::json!({
                "type": "object",
                "required": ["ok", "message", "approved"],
                "properties": {
                    "ok": { "type": "boolean" },
                    "message": { "type": "string" },
                    "approved": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
            capabilities: vec!["demo.approval".to_string()],
            risk: RiskTier::Medium,
            executor: ToolExecutor {
                kind: ToolExecutorKind::LocalShim,
                command: vec![
                    "trillionnium-os-local-shim".to_string(),
                    "demo.approval_echo".to_string(),
                ],
            },
            agent_plan_contract: Some(AgentPlanActionContract {
                requires_approval: true,
                network_scope: "none".to_string(),
                undo_contract: "none".to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolCallInput {
    pub task_id: TaskId,
    pub tool_call_id: ToolCallId,
    pub tool_name: String,
    pub arguments: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_execution_binding: Option<AgentExecutionBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolRunStatus {
    Requested,
    WaitingForApproval,
    ApprovalGrantedAwaitingRetry,
    Running,
    /// ToolStarted was durable, but no durable finish receipt exists after a
    /// daemon restart. Automatic replay is forbidden because the external
    /// side effect may already have happened.
    Indeterminate,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ToolRun {
    pub task_id: TaskId,
    pub tool_call_id: ToolCallId,
    pub tool_name: String,
    pub arguments: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_execution_binding: Option<AgentExecutionBinding>,
    pub status: ToolRunStatus,
    pub requested_at_unix_ms: u64,
    pub started_at_unix_ms: Option<u64>,
    pub finished_at_unix_ms: Option<u64>,
    pub output: Option<Value>,
    pub error: Option<String>,
    pub approval_id: Option<String>,
    pub policy_decision: Option<PolicyDecision>,
}

impl ToolRun {
    pub fn requested(call: ToolCallInput) -> Self {
        Self {
            task_id: call.task_id,
            tool_call_id: call.tool_call_id,
            tool_name: call.tool_name,
            arguments: call.arguments,
            agent_execution_binding: call.agent_execution_binding,
            status: ToolRunStatus::Requested,
            requested_at_unix_ms: now_unix_ms(),
            started_at_unix_ms: None,
            finished_at_unix_ms: None,
            output: None,
            error: None,
            approval_id: None,
            policy_decision: None,
        }
    }

    pub fn call_input(&self) -> ToolCallInput {
        ToolCallInput {
            task_id: self.task_id.clone(),
            tool_call_id: self.tool_call_id.clone(),
            tool_name: self.tool_name.clone(),
            arguments: self.arguments.clone(),
            agent_execution_binding: self.agent_execution_binding.clone(),
        }
    }

    pub fn mark_waiting_for_approval(&mut self, approval_id: impl Into<String>) {
        self.status = ToolRunStatus::WaitingForApproval;
        self.approval_id = Some(approval_id.into());
    }

    pub fn mark_approval_granted_awaiting_retry(&mut self) {
        self.status = ToolRunStatus::ApprovalGrantedAwaitingRetry;
    }

    pub fn mark_running(&mut self) {
        self.status = ToolRunStatus::Running;
        self.started_at_unix_ms = Some(now_unix_ms());
        self.finished_at_unix_ms = None;
        self.output = None;
        self.error = None;
    }

    pub fn mark_succeeded(&mut self, output: Value) {
        self.status = ToolRunStatus::Succeeded;
        self.finished_at_unix_ms = Some(now_unix_ms());
        self.output = Some(output);
        self.error = None;
    }

    pub fn mark_failed(&mut self, error: impl Into<String>) {
        self.status = ToolRunStatus::Failed;
        self.finished_at_unix_ms = Some(now_unix_ms());
        self.output = None;
        self.error = Some(error.into());
    }

    pub fn mark_indeterminate(&mut self, error: impl Into<String>) {
        self.status = ToolRunStatus::Indeterminate;
        self.finished_at_unix_ms = Some(now_unix_ms());
        self.output = None;
        self.error = Some(error.into());
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

impl ValidationResult {
    pub fn ok() -> Self {
        Self {
            valid: true,
            errors: Vec::new(),
        }
    }

    pub fn failed(errors: Vec<String>) -> Self {
        Self {
            valid: false,
            errors,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionKind {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyDecision {
    pub kind: PolicyDecisionKind,
    pub requirement: ApprovalRequirement,
    pub reason: String,
    pub matched_rule_id: Option<String>,
}

impl PolicyDecision {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            kind: PolicyDecisionKind::Allow,
            requirement: ApprovalRequirement::None,
            reason: reason.into(),
            matched_rule_id: None,
        }
    }

    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            kind: PolicyDecisionKind::Ask,
            requirement: ApprovalRequirement::Ask,
            reason: reason.into(),
            matched_rule_id: None,
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            kind: PolicyDecisionKind::Deny,
            requirement: ApprovalRequirement::Deny,
            reason: reason.into(),
            matched_rule_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalGrant {
    pub id: String,
    pub tool_name: String,
    pub tool_call_id: Option<ToolCallId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    pub lifetime: ApprovalLifetime,
    pub created_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    /// Exact complete ToolManifest approved by the user. Legacy positive
    /// grants without this field are pruned and never match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_manifest_sha256: Option<String>,
    /// Exact Agent/peer/user/origin/session subject for Agent-originated calls.
    /// `None` deliberately denotes a non-Agent call, not a wildcard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_subject_sha256: Option<String>,
    /// Exact OS daemon executable that minted the grant. The broker prunes
    /// legacy or cross-upgrade positive grants before policy evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_executor_sha256: Option<String>,
}

impl ApprovalGrant {
    pub fn one_call(tool_name: impl Into<String>, tool_call_id: ToolCallId) -> Self {
        Self {
            id: format!("approval-{}", Uuid::new_v4()),
            tool_name: tool_name.into(),
            tool_call_id: Some(tool_call_id),
            task_id: None,
            lifetime: ApprovalLifetime::OneCall,
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: None,
            boot_id: None,
            tool_manifest_sha256: None,
            agent_subject_sha256: None,
            os_executor_sha256: None,
        }
    }

    pub fn current_task(tool_name: impl Into<String>, task_id: TaskId) -> Self {
        Self {
            id: format!("approval-{}", Uuid::new_v4()),
            tool_name: tool_name.into(),
            tool_call_id: None,
            task_id: Some(task_id),
            lifetime: ApprovalLifetime::CurrentTask,
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: None,
            boot_id: None,
            tool_manifest_sha256: None,
            agent_subject_sha256: None,
            os_executor_sha256: None,
        }
    }

    pub fn current_session(tool_name: impl Into<String>) -> Self {
        Self {
            id: format!("approval-{}", Uuid::new_v4()),
            tool_name: tool_name.into(),
            tool_call_id: None,
            task_id: None,
            lifetime: ApprovalLifetime::CurrentSession,
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: None,
            boot_id: None,
            tool_manifest_sha256: None,
            agent_subject_sha256: None,
            os_executor_sha256: None,
        }
    }

    pub fn until_reboot(tool_name: impl Into<String>, boot_id: impl Into<String>) -> Self {
        Self {
            id: format!("approval-{}", Uuid::new_v4()),
            tool_name: tool_name.into(),
            tool_call_id: None,
            task_id: None,
            lifetime: ApprovalLifetime::UntilReboot,
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: None,
            boot_id: Some(boot_id.into()),
            tool_manifest_sha256: None,
            agent_subject_sha256: None,
            os_executor_sha256: None,
        }
    }

    pub fn persistent(tool_name: impl Into<String>) -> Self {
        Self {
            id: format!("approval-{}", Uuid::new_v4()),
            tool_name: tool_name.into(),
            tool_call_id: None,
            task_id: None,
            lifetime: ApprovalLifetime::Persistent,
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: None,
            boot_id: None,
            tool_manifest_sha256: None,
            agent_subject_sha256: None,
            os_executor_sha256: None,
        }
    }

    pub fn never_allow(tool_name: impl Into<String>) -> Self {
        Self {
            id: format!("approval-{}", Uuid::new_v4()),
            tool_name: tool_name.into(),
            tool_call_id: None,
            task_id: None,
            lifetime: ApprovalLifetime::NeverAllow,
            created_at_unix_ms: now_unix_ms(),
            expires_at_unix_ms: None,
            boot_id: None,
            tool_manifest_sha256: None,
            agent_subject_sha256: None,
            os_executor_sha256: None,
        }
    }

    pub fn with_expires_at(mut self, expires_at_unix_ms: u64) -> Self {
        self.expires_at_unix_ms = Some(expires_at_unix_ms);
        self
    }

    pub fn with_boot_id(mut self, boot_id: impl Into<String>) -> Self {
        self.boot_id = Some(boot_id.into());
        self
    }

    pub fn with_execution_scope(
        mut self,
        tool_manifest_sha256: impl Into<String>,
        agent_subject_sha256: Option<String>,
        os_executor_sha256: impl Into<String>,
    ) -> Self {
        self.tool_manifest_sha256 = Some(tool_manifest_sha256.into());
        self.agent_subject_sha256 = agent_subject_sha256;
        self.os_executor_sha256 = Some(os_executor_sha256.into());
        self
    }

    pub fn is_expired_at(&self, now_unix_ms: u64) -> bool {
        self.expires_at_unix_ms
            .is_some_and(|expires_at| expires_at <= now_unix_ms)
    }

    pub fn scoped(
        tool_name: impl Into<String>,
        tool_call_id: ToolCallId,
        task_id: TaskId,
        lifetime: ApprovalLifetime,
    ) -> Self {
        match lifetime {
            ApprovalLifetime::OneCall => Self::one_call(tool_name, tool_call_id),
            ApprovalLifetime::CurrentTask => Self::current_task(tool_name, task_id),
            ApprovalLifetime::CurrentSession => Self::current_session(tool_name),
            ApprovalLifetime::Persistent => Self::persistent(tool_name),
            ApprovalLifetime::NeverAllow => Self::never_allow(tool_name),
            ApprovalLifetime::UntilReboot => Self {
                id: format!("approval-{}", Uuid::new_v4()),
                tool_name: tool_name.into(),
                tool_call_id: None,
                task_id: None,
                lifetime,
                created_at_unix_ms: now_unix_ms(),
                expires_at_unix_ms: None,
                boot_id: None,
                tool_manifest_sha256: None,
                agent_subject_sha256: None,
                os_executor_sha256: None,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalSubmission {
    pub task_id: TaskId,
    pub tool_call_id: Option<ToolCallId>,
    pub tool_name: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalRequest {
    pub id: String,
    pub task_id: TaskId,
    pub tool_call_id: ToolCallId,
    pub tool_name: String,
    pub reason: String,
    pub status: ApprovalStatus,
    pub created_at_unix_ms: u64,
    pub decided_at_unix_ms: Option<u64>,
    pub decision_reason: Option<String>,
    /// OS-authored complete ToolManifest digest captured when this approval
    /// was requested. It prevents a scoped consent from migrating to a tool
    /// implementation with different declared semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_manifest_sha256: Option<String>,
}

impl ApprovalRequest {
    pub fn summary(&self) -> ApprovalSummary {
        ApprovalSummary {
            id: self.id.clone(),
            task_id: self.task_id.clone(),
            tool_name: self.tool_name.clone(),
            status: self.status.clone(),
            created_at_unix_ms: self.created_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalSummary {
    pub id: String,
    pub task_id: TaskId,
    pub tool_name: String,
    pub status: ApprovalStatus,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    Created,
    Running,
    WaitingForApproval,
    /// At least one tool crossed ToolStarted without a durable finish receipt.
    /// This is terminal and requires explicit forensic/manual resolution.
    Indeterminate,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TaskInput {
    pub title: String,
    pub description: Option<String>,
    pub metadata: Value,
}

impl Default for TaskInput {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: None,
            metadata: Value::Object(Default::default()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TaskSummary {
    pub id: TaskId,
    pub title: String,
    pub status: TaskStatus,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TaskView {
    pub id: TaskId,
    pub title: String,
    pub description: Option<String>,
    pub status: TaskStatus,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub metadata: Value,
}

impl TaskView {
    pub fn summary(&self) -> TaskSummary {
        TaskSummary {
            id: self.id.clone(),
            title: self.title.clone(),
            status: self.status.clone(),
            created_at_unix_ms: self.created_at_unix_ms,
            updated_at_unix_ms: self.updated_at_unix_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    AgentRegistered,
    AgentPlanSubmitted,
    AgentMemorySaved,
    AgentMemoryRevoked,
    AgentMemoryDeleted,
    TaskCreated,
    TaskCancelled,
    ToolRequested,
    PolicyEvaluated,
    ApprovalRequested,
    ApprovalDecided,
    ApprovalGrantRevoked,
    ToolValidated,
    ToolStarted,
    ToolFinished,
    ToolFailed,
    DbusPing,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AuditEvent {
    pub id: String,
    pub kind: AuditEventKind,
    pub task_id: Option<TaskId>,
    pub tool_call_id: Option<ToolCallId>,
    pub summary: String,
    pub payload: Value,
    pub created_at_unix_ms: u64,
}

impl AuditEvent {
    pub fn new(kind: AuditEventKind, summary: impl Into<String>) -> Self {
        Self {
            id: format!("audit-{}", Uuid::new_v4()),
            kind,
            task_id: None,
            tool_call_id: None,
            summary: summary.into(),
            payload: Value::Null,
            created_at_unix_ms: now_unix_ms(),
        }
    }

    pub fn with_task(mut self, task_id: TaskId) -> Self {
        self.task_id = Some(task_id);
        self
    }

    pub fn with_tool_call(mut self, tool_call_id: ToolCallId) -> Self {
        self.tool_call_id = Some(tool_call_id);
        self
    }

    pub fn with_payload(mut self, payload: Value) -> Self {
        self.payload = payload;
        self
    }
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().try_into().unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_agent() -> AgentRegistration {
        AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: "agent-codex-local-v1".to_string(),
            adapter: "codex-cli".to_string(),
            adapter_version: "0.144.1".to_string(),
            identity_key_sha256: "a".repeat(64),
            peer_uid: 1000,
            peer_gid: 1000,
            selinux_domain: "u:r:trillionnium_agent:s0".to_string(),
            network_policy: AgentNetworkPolicy::PerRequest,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        }
    }

    fn sample_plan() -> AgentPlanSubmission {
        let arguments = serde_json::json!({"uri": "content://fixture/1"});
        AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-fixture-1".to_string(),
            task_id: TaskId("task-fixture-1".to_string()),
            session_id: "session-fixture-1".to_string(),
            agent_id: "agent-codex-local-v1".to_string(),
            intent_sha256: "b".repeat(64),
            provider_output_sha256: "c".repeat(64),
            contexts: vec![AgentContextRef {
                context_id: "context-fixture-1".to_string(),
                source_id: "saf:fixture".to_string(),
                source_kind: "selected_file".to_string(),
                captured_at_unix_ms: 1,
                freshness_ttl_ms: 60_000,
                privacy_class: ContextPrivacyClass::LocalPrivate,
                content_sha256: "d".repeat(64),
                revoked: false,
            }],
            actions: vec![AgentPlannedAction {
                action_id: "action-fixture-1".to_string(),
                tool_name: "android.file.read_bounded".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments_sha256: sha256_json(&arguments),
                arguments,
                rationale: "Read the file selected by the user".to_string(),
                requires_approval: true,
                network_scope: "none".to_string(),
                undo_contract: "no external mutation".to_string(),
            }],
            created_at_unix_ms: 1,
        }
    }

    #[test]
    fn agent_api_v1_accepts_bound_registration_and_plan() {
        assert!(validate_agent_registration(&sample_agent()).valid);
        assert!(validate_agent_plan(&sample_plan()).valid);
    }

    #[test]
    fn agent_api_v1_rejects_digest_substitution_and_revoked_context() {
        let mut plan = sample_plan();
        plan.actions[0].arguments = serde_json::json!({"uri": "content://attacker/2"});
        plan.contexts[0].revoked = true;
        let result = validate_agent_plan(&plan);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("digest mismatch"))
        );
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("revoked context"))
        );
    }

    #[test]
    fn agent_plan_rejects_malformed_optional_os_manifest_digest() {
        let mut plan = sample_plan();
        plan.actions[0].os_tool_manifest_sha256 = Some("not-a-sha256".to_string());
        let result = validate_agent_plan(&plan);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("OS tool manifest digest"))
        );

        let mut plan = sample_plan();
        plan.actions[0].os_executor_sha256 = Some("not-a-sha256".to_string());
        let result = validate_agent_plan(&plan);
        assert!(!result.valid);
        assert!(
            result
                .errors
                .iter()
                .any(|error| error.contains("OS executor digest"))
        );
    }

    #[test]
    fn agent_execution_request_rejects_tool_or_argument_substitution_fields() {
        let request = serde_json::json!({
            "task_id": "task-fixture-1",
            "plan_id": "plan-fixture-1",
            "action_id": "action-fixture-1",
            "tool_name": "attacker.tool",
            "arguments": {"target": "attacker-controlled"}
        });
        assert!(serde_json::from_value::<AgentExecutionRequest>(request).is_err());
    }

    #[test]
    fn streaming_sha256_matches_in_memory_digest() {
        let bytes = b"kernel-authenticated agent executable";
        assert_eq!(
            sha256_reader(std::io::Cursor::new(bytes)).unwrap(),
            sha256_bytes(bytes)
        );
    }

    #[test]
    fn system_status_manifest_is_trillionnium_v1_and_low_risk() {
        let manifest = ToolManifest::system_status();

        assert_eq!(manifest.schema_version, TOOL_SCHEMA_VERSION);
        assert_eq!(manifest.name, "system.status");
        assert_eq!(manifest.risk, RiskTier::Low);
        assert_eq!(manifest.capabilities, vec!["system.status"]);
        assert_eq!(manifest.executor.kind, ToolExecutorKind::LocalShim);
    }

    #[test]
    fn demo_approval_echo_manifest_is_medium_risk() {
        let manifest = ToolManifest::demo_approval_echo();

        assert_eq!(manifest.schema_version, TOOL_SCHEMA_VERSION);
        assert_eq!(manifest.name, "demo.approval_echo");
        assert_eq!(manifest.risk, RiskTier::Medium);
        assert_eq!(manifest.capabilities, vec!["demo.approval"]);
        assert_eq!(manifest.executor.kind, ToolExecutorKind::LocalShim);
    }

    #[test]
    fn tool_run_serializes_stable_status_and_output() {
        let call = ToolCallInput {
            task_id: TaskId("task-stable".to_string()),
            tool_call_id: ToolCallId("toolcall-stable".to_string()),
            tool_name: "system.status".to_string(),
            arguments: serde_json::json!({}),
            agent_execution_binding: None,
        };
        let mut run = ToolRun::requested(call);
        run.mark_running();
        run.mark_succeeded(serde_json::json!({"ok": true}));

        let value = serde_json::to_value(&run).expect("tool run should serialize");
        assert_eq!(value["status"], "succeeded");
        assert_eq!(value["tool_call_id"], "toolcall-stable");
        assert_eq!(value["output"]["ok"], true);
        assert!(value["error"].is_null());
    }

    #[test]
    fn checked_in_json_schemas_match_runtime_enum_truth() {
        fn strings(value: &Value) -> std::collections::BTreeSet<String> {
            value
                .as_array()
                .expect("schema enum must be an array")
                .iter()
                .map(|item| {
                    item.as_str()
                        .expect("schema enum values must be strings")
                        .to_string()
                })
                .collect()
        }

        let tool_schema: Value =
            serde_json::from_str(include_str!("../../../schemas/tool-manifest.schema.json"))
                .expect("tool schema must parse");
        let checked_tool_kinds =
            strings(&tool_schema["properties"]["executor"]["properties"]["kind"]["enum"]);
        let runtime_tool_kinds = [
            ToolExecutorKind::LocalShim,
            ToolExecutorKind::AndroidGateway,
            ToolExecutorKind::Native,
            ToolExecutorKind::Process,
            ToolExecutorKind::SystemdScope,
            ToolExecutorKind::Waydroid,
        ]
        .into_iter()
        .map(|kind| {
            serde_json::to_value(kind)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
        assert_eq!(checked_tool_kinds, runtime_tool_kinds);
        let contract_schema = &tool_schema["properties"]["agent_plan_contract"];
        assert_eq!(contract_schema["type"], "object");
        assert_eq!(contract_schema["additionalProperties"], false);
        assert_eq!(
            strings(&contract_schema["required"]),
            ["network_scope", "requires_approval", "undo_contract"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        assert_eq!(
            strings(&contract_schema["properties"]["network_scope"]["enum"]),
            ["allowlisted", "none", "per_request"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        assert_eq!(
            contract_schema["properties"]["undo_contract"]["maxLength"],
            256
        );
        let mut browser_manifest = ToolManifest::demo_approval_echo();
        browser_manifest.name = "android.browser.open_bounded".to_string();
        browser_manifest.executor = ToolExecutor {
            kind: ToolExecutorKind::AndroidGateway,
            command: vec![
                "/dev/socket/trillionnium/ai-authority-v1".to_string(),
                "android.browser.open_bounded".to_string(),
            ],
        };
        browser_manifest.agent_plan_contract = Some(AgentPlanActionContract {
            requires_approval: true,
            network_scope: "per_request".to_string(),
            undo_contract: "no_undo_external_browser_launch".to_string(),
        });
        let serialized_browser = serde_json::to_value(browser_manifest).unwrap();
        let allowed_manifest_fields = tool_schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            serialized_browser
                .as_object()
                .unwrap()
                .keys()
                .all(|key| allowed_manifest_fields.contains(key))
        );
        assert_eq!(
            serialized_browser["agent_plan_contract"]["network_scope"],
            "per_request"
        );

        let audit_schema: Value =
            serde_json::from_str(include_str!("../../../schemas/audit-event.schema.json"))
                .expect("audit schema must parse");
        let checked_audit_kinds = strings(&audit_schema["properties"]["kind"]["enum"]);
        let runtime_audit_kinds = [
            AuditEventKind::AgentRegistered,
            AuditEventKind::AgentPlanSubmitted,
            AuditEventKind::AgentMemorySaved,
            AuditEventKind::AgentMemoryRevoked,
            AuditEventKind::AgentMemoryDeleted,
            AuditEventKind::TaskCreated,
            AuditEventKind::TaskCancelled,
            AuditEventKind::ToolRequested,
            AuditEventKind::PolicyEvaluated,
            AuditEventKind::ApprovalRequested,
            AuditEventKind::ApprovalDecided,
            AuditEventKind::ApprovalGrantRevoked,
            AuditEventKind::ToolValidated,
            AuditEventKind::ToolStarted,
            AuditEventKind::ToolFinished,
            AuditEventKind::ToolFailed,
            AuditEventKind::DbusPing,
        ]
        .into_iter()
        .map(|kind| {
            serde_json::to_value(kind)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
        assert_eq!(checked_audit_kinds, runtime_audit_kinds);
    }
}
