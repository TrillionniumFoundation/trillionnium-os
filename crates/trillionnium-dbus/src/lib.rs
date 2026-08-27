use std::fs;
use std::os::unix::fs::MetadataExt;
#[cfg(any(test, feature = "legacy-plan-execution"))]
use std::sync::RwLock;
use std::sync::{Arc, Mutex, OnceLock};

use serde_json::{Value, json};
#[cfg(any(test, feature = "legacy-plan-execution"))]
use trillionnium_audit_sqlite::AgentPlanSaveOutcome;
use trillionnium_audit_sqlite::AuditStore;
#[cfg(any(test, feature = "legacy-plan-execution"))]
use trillionnium_os_types::ToolCallInput;
use trillionnium_os_types::{
    AGENT_API_VERSION, AgentPlanSubmission, AgentRegistration, ApprovalGrant, ApprovalLifetime,
    ApprovalRequest, AuditEvent, AuditEventKind, TaskInput, TaskStatus, TaskView, ToolRun,
    is_lower_sha256, now_unix_ms, sha256_reader, validate_agent_registration,
};
#[cfg(any(test, feature = "legacy-plan-execution"))]
use trillionnium_os_types::{
    AgentExecutionBinding, AgentExecutionRequest, AgentPlannedAction, ApprovalSubmission,
    PolicyDecision, PolicyDecisionKind, TaskId, ToolCallId, ToolManifest, ToolRunStatus,
    sha256_json, validate_agent_plan,
};
#[cfg(any(test, feature = "legacy-plan-execution"))]
use trillionnium_policy_system::PolicyEngine;
use trillionnium_task_registry::TaskRegistry;
#[cfg(any(test, feature = "legacy-plan-execution"))]
use trillionnium_tool_runtime::ResolvedExecutionPayload;
#[cfg(any(test, feature = "legacy-plan-execution"))]
use trillionnium_tool_runtime::{
    ToolRuntimeError, execute_builtin_tool_with_execution_payload, manifest_by_name,
    validate_manifest, validate_tool_call,
};
static OS_EXECUTOR_SHA256: OnceLock<Result<String, String>> = OnceLock::new();

#[cfg(any(test, feature = "legacy-plan-execution"))]
fn ensure_task_nonterminal(task: &TaskView, operation: &str) -> Result<(), String> {
    if matches!(
        task.status,
        TaskStatus::Indeterminate
            | TaskStatus::Completed
            | TaskStatus::Failed
            | TaskStatus::Cancelled
    ) {
        return Err(format!(
            "{operation} is denied for terminal task {} ({:?})",
            task.id.0, task.status
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "legacy-plan-execution"))]
fn ensure_task_accepts_new_dispatch(task: &TaskView, operation: &str) -> Result<(), String> {
    ensure_task_nonterminal(task, operation)?;
    if task.status != TaskStatus::Created {
        return Err(format!(
            "{operation} is denied while task {} is busy ({:?})",
            task.id.0, task.status
        ));
    }
    Ok(())
}

#[cfg(any(test, feature = "legacy-plan-execution"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FrozenAgentTaskSubject {
    agent_executable_sha256: String,
    subject_user_id: u32,
    origin_uid: u32,
    origin_selinux_domain: String,
}

#[cfg(any(test, feature = "legacy-plan-execution"))]
fn frozen_agent_task_subject(
    task: &TaskView,
    registration: &AgentRegistration,
) -> Result<FrozenAgentTaskSubject, String> {
    if task.metadata.get("agent_id").and_then(Value::as_str) != Some(registration.agent_id.as_str())
        || task.metadata.get("agent_peer_uid").and_then(Value::as_u64)
            != Some(u64::from(registration.peer_uid))
        || task.metadata.get("agent_peer_gid").and_then(Value::as_u64)
            != Some(u64::from(registration.peer_gid))
        || task
            .metadata
            .get("agent_peer_selinux_domain")
            .and_then(Value::as_str)
            != Some(registration.selinux_domain.as_str())
    {
        return Err("OS-owned Agent task subject does not match its provisioned identity".into());
    }
    let agent_executable_sha256 = task
        .metadata
        .get("agent_peer_executable_sha256")
        .and_then(Value::as_str)
        .filter(|digest| is_lower_sha256(digest))
        .ok_or_else(|| "OS-owned Agent executable digest is missing or invalid".to_string())?;
    if agent_executable_sha256 != registration.identity_key_sha256 {
        return Err("OS-owned Agent executable digest does not match its manifest".to_string());
    }
    let origin_uid = task
        .metadata
        .get("origin_uid")
        .or_else(|| task.metadata.get("android_ui_uid"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "OS-owned task origin UID is missing or invalid".to_string())?;
    let origin_selinux_domain = task
        .metadata
        .get("origin_selinux_domain")
        .or_else(|| task.metadata.get("android_ui_domain"))
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 256
                && value.trim() == *value
                && !value.chars().any(char::is_control)
        })
        .ok_or_else(|| "OS-owned task origin SELinux domain is missing or invalid".to_string())?
        .to_string();
    let subject_user_id = task
        .metadata
        .get("subject_user_id")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "OS-owned task subject user id is missing or invalid".to_string())?;
    if origin_uid / 100_000 != subject_user_id {
        return Err("OS-owned task origin UID does not belong to its subject user".to_string());
    }
    Ok(FrozenAgentTaskSubject {
        agent_executable_sha256: agent_executable_sha256.to_string(),
        subject_user_id,
        origin_uid,
        origin_selinux_domain,
    })
}

fn current_os_executor_sha256() -> Result<String, String> {
    OS_EXECUTOR_SHA256
        .get_or_init(|| {
            let mut executable = fs::File::open("/proc/self/exe")
                .map_err(|error| format!("failed to open current OS executor: {error}"))?;
            let before = executable
                .metadata()
                .map_err(|error| format!("failed to stat current OS executor: {error}"))?;
            if !before.is_file() {
                return Err("current OS executor is not a regular file".to_string());
            }
            let digest = sha256_reader(&mut executable)
                .map_err(|error| format!("failed to hash current OS executor: {error}"))?;
            let after = executable
                .metadata()
                .map_err(|error| format!("failed to restat current OS executor: {error}"))?;
            let before_identity = (
                before.dev(),
                before.ino(),
                before.size(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            );
            let after_identity = (
                after.dev(),
                after.ino(),
                after.size(),
                after.mtime(),
                after.mtime_nsec(),
                after.ctime(),
                after.ctime_nsec(),
            );
            if before_identity != after_identity {
                return Err("current OS executor changed while hashing".to_string());
            }
            Ok(digest)
        })
        .clone()
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum SignalEmission {
    TaskUpdated(TaskView),
    ApprovalRequested(ApprovalRequest),
    AuditEventAppended(AuditEvent),
    ToolRequested(ToolRun),
    PolicyEvaluated(AuditEvent),
    ToolStarted(ToolRun),
    ToolFinished(ToolRun),
    ToolFailed(ToolRun),
}

/// OS-owned resolver for encrypted, single-use execution payloads. Durable
/// plans and audit rows contain only an opaque reference and payload digest;
/// raw data exists only in the transient call sent to the Android gateway.
#[cfg(any(test, feature = "legacy-plan-execution"))]
pub trait ExecutionPayloadResolver: Send + Sync {
    fn resolve_and_consume(
        &self,
        call: &ToolCallInput,
    ) -> Result<Option<ResolvedExecutionPayload>, String>;
}

#[cfg(any(test, feature = "legacy-plan-execution"))]
fn current_manifest_for_agent_action(
    action: &AgentPlannedAction,
) -> Result<(ToolManifest, String), String> {
    let manifest = manifest_by_name(&action.tool_name)
        .ok_or_else(|| format!("unknown or unavailable tool: {}", action.tool_name))?;
    let validation = validate_manifest(&manifest).map_err(|error| error.to_string())?;
    if !validation.valid {
        return Err(format!(
            "invalid OS tool manifest for {}: {}",
            action.tool_name,
            validation.errors.join("; ")
        ));
    }
    let contract = manifest.agent_plan_contract.as_ref().ok_or_else(|| {
        format!(
            "OS tool manifest has no Agent plan contract: {}",
            action.tool_name
        )
    })?;
    let mut drift = Vec::new();
    if action.requires_approval != contract.requires_approval {
        drift.push("requires_approval");
    }
    if action.network_scope != contract.network_scope {
        drift.push("network_scope");
    }
    if action.undo_contract != contract.undo_contract {
        drift.push("undo_contract");
    }
    if !drift.is_empty() {
        return Err(format!(
            "agent plan preview semantics do not match OS tool manifest for {}: {}",
            action.tool_name,
            drift.join(", ")
        ));
    }
    let digest = sha256_json(
        &serde_json::to_value(&manifest)
            .map_err(|error| format!("failed to canonicalize OS tool manifest: {error}"))?,
    );
    Ok((manifest, digest))
}

#[cfg(any(test, feature = "legacy-plan-execution"))]
fn frozen_manifest_for_agent_action(action: &AgentPlannedAction) -> Result<ToolManifest, String> {
    let (manifest, current_digest) = current_manifest_for_agent_action(action)?;
    match action.os_tool_manifest_sha256.as_deref() {
        Some(frozen_digest) if frozen_digest == current_digest => {}
        Some(_) => Err(format!(
            "accepted plan OS tool manifest changed before execution: {}",
            action.tool_name
        ))?,
        None => Err(format!(
            "accepted plan predates OS tool manifest freezing and is invalidated: {}",
            action.tool_name
        ))?,
    }
    let current_executor = current_os_executor_sha256()?;
    match action.os_executor_sha256.as_deref() {
        Some(frozen_digest) if frozen_digest == current_executor => Ok(manifest),
        Some(_) => Err(format!(
            "accepted plan OS executor changed before execution: {}",
            action.tool_name
        )),
        None => Err(format!(
            "accepted plan predates OS executor freezing and is invalidated: {}",
            action.tool_name
        )),
    }
}

#[derive(Clone)]
pub struct AgentService {
    registry: Arc<Mutex<TaskRegistry>>,
    audit: Arc<Mutex<AuditStore>>,
    grants: Arc<Mutex<Vec<ApprovalGrant>>>,
    #[cfg(any(test, feature = "legacy-plan-execution"))]
    dispatch_gate: Arc<Mutex<()>>,
    state_transition_gate: Arc<Mutex<()>>,
    #[cfg(any(test, feature = "legacy-plan-execution"))]
    execution_payload_resolver: Arc<RwLock<Option<Arc<dyn ExecutionPayloadResolver>>>>,
}

impl AgentService {
    pub fn new(registry: TaskRegistry, audit: AuditStore) -> Self {
        Self::with_grants(registry, audit, Vec::new())
    }

    fn with_grants(registry: TaskRegistry, audit: AuditStore, grants: Vec<ApprovalGrant>) -> Self {
        Self {
            registry: Arc::new(Mutex::new(registry)),
            audit: Arc::new(Mutex::new(audit)),
            grants: Arc::new(Mutex::new(grants)),
            #[cfg(any(test, feature = "legacy-plan-execution"))]
            dispatch_gate: Arc::new(Mutex::new(())),
            state_transition_gate: Arc::new(Mutex::new(())),
            #[cfg(any(test, feature = "legacy-plan-execution"))]
            execution_payload_resolver: Arc::new(RwLock::new(None)),
        }
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    pub fn set_execution_payload_resolver(
        &self,
        resolver: Arc<dyn ExecutionPayloadResolver>,
    ) -> Result<(), String> {
        let mut slot = self
            .execution_payload_resolver
            .write()
            .map_err(|_| "execution payload resolver lock poisoned".to_string())?;
        *slot = Some(resolver);
        Ok(())
    }

    pub fn from_store(
        audit: AuditStore,
    ) -> Result<Self, trillionnium_audit_sqlite::AuditStoreError> {
        let tasks = audit.load_tasks()?;
        let approvals = audit.load_approvals()?;
        let now = now_unix_ms();
        let boot_id = current_boot_id().ok();
        let current_executor = current_os_executor_sha256().ok();
        let mut grants = Vec::new();
        for grant in audit.load_approval_grants()? {
            let task_is_terminal = grant.task_id.as_ref().is_some_and(|task_id| {
                tasks.iter().any(|task| {
                    task.id == *task_id
                        && matches!(
                            task.status,
                            TaskStatus::Indeterminate
                                | TaskStatus::Completed
                                | TaskStatus::Failed
                                | TaskStatus::Cancelled
                        )
                })
            });
            if task_is_terminal
                || grant.lifetime == ApprovalLifetime::OneCall
                || grant.lifetime == ApprovalLifetime::CurrentSession
                || grant.lifetime == ApprovalLifetime::UntilReboot
                || grant.lifetime == ApprovalLifetime::Persistent
                || (grant.lifetime == ApprovalLifetime::CurrentTask
                    && !grant
                        .tool_manifest_sha256
                        .as_deref()
                        .is_some_and(is_lower_sha256))
                || (grant.lifetime == ApprovalLifetime::CurrentTask
                    && grant.os_executor_sha256.as_deref() != current_executor.as_deref())
                || grant
                    .agent_subject_sha256
                    .as_deref()
                    .is_some_and(|digest| !is_lower_sha256(digest))
                || !grant_matches_current_boot(&grant, boot_id.as_deref())
                || grant.is_expired_at(now)
            {
                audit.delete_approval_grant(&grant.id)?;
            } else {
                grants.push(grant);
            }
        }
        Ok(Self::with_grants(
            TaskRegistry::from_records(tasks, approvals),
            audit,
            grants,
        ))
    }

    /// Startup-only recovery constructor. The caller must already hold the
    /// OS-level singleton service lease (the production daemon binds and
    /// validates its exclusive UDS listener first). Secondary readers/tests
    /// must use `from_store`, which never mutates a live execution lease.
    pub fn from_store_after_exclusive_startup(
        audit: AuditStore,
    ) -> Result<Self, trillionnium_audit_sqlite::AuditStoreError> {
        audit.recover_inflight_as_indeterminate()?;
        Self::from_store(audit)
    }

    pub fn in_memory() -> Result<Self, trillionnium_audit_sqlite::AuditStoreError> {
        Self::from_store(AuditStore::open_memory()?)
    }

    /// Replaces speculative in-memory state with the durable SQLite truth
    /// after a compare-and-swap loses to another service/transition.
    fn reload_runtime_state_from_audit(&self) -> Result<(), String> {
        let (tasks, approvals, mut grants) = {
            let audit = self.lock_audit()?;
            (
                audit.load_tasks().map_err(|error| error.to_string())?,
                audit.load_approvals().map_err(|error| error.to_string())?,
                audit
                    .load_approval_grants()
                    .map_err(|error| error.to_string())?,
            )
        };
        let now = now_unix_ms();
        let boot_id = current_boot_id().ok();
        let current_executor = current_os_executor_sha256().ok();
        grants.retain(|grant| {
            let task_is_terminal = grant.task_id.as_ref().is_some_and(|task_id| {
                tasks.iter().any(|task| {
                    task.id == *task_id
                        && matches!(
                            task.status,
                            TaskStatus::Indeterminate
                                | TaskStatus::Completed
                                | TaskStatus::Failed
                                | TaskStatus::Cancelled
                        )
                })
            });
            !task_is_terminal
                && grant.lifetime != ApprovalLifetime::OneCall
                && grant.lifetime != ApprovalLifetime::CurrentSession
                && grant.lifetime != ApprovalLifetime::UntilReboot
                && grant.lifetime != ApprovalLifetime::Persistent
                && (grant.lifetime != ApprovalLifetime::CurrentTask
                    || (grant
                        .tool_manifest_sha256
                        .as_deref()
                        .is_some_and(is_lower_sha256)
                        && grant.os_executor_sha256.as_deref() == current_executor.as_deref()))
                && grant
                    .agent_subject_sha256
                    .as_deref()
                    .is_none_or(is_lower_sha256)
                && grant_matches_current_boot(grant, boot_id.as_deref())
                && !grant.is_expired_at(now)
        });
        *self.lock_registry()? = TaskRegistry::from_records(tasks, approvals);
        *self.lock_grants()? = grants;
        Ok(())
    }

    pub fn register_agent_local(
        &self,
        registration: AgentRegistration,
    ) -> Result<AgentRegistration, String> {
        self.register_agent_record(
            serde_json::to_string(&registration).map_err(|error| error.to_string())?,
        )
        .map(|(registration, _)| registration)
    }

    /// Install or rotate an identity from an OS-owned, integrity-protected
    /// AgentManifest. This is intentionally not exposed on D-Bus or Agent UDS.
    pub fn provision_agent_local(
        &self,
        registration: AgentRegistration,
    ) -> Result<AgentRegistration, String> {
        self.register_agent_record_with_authority(
            serde_json::to_string(&registration).map_err(|error| error.to_string())?,
            true,
        )
        .map(|(registration, _)| registration)
    }

    pub fn create_task_local(&self, input: TaskInput) -> Result<TaskView, String> {
        self.create_task_record(serde_json::to_string(&input).map_err(|error| error.to_string())?)
            .map(|(task, _)| task)
    }

    pub fn get_agent_local(&self, agent_id: &str) -> Result<Option<AgentRegistration>, String> {
        self.lock_audit()?
            .get_agent_registration(agent_id)
            .map_err(|error| error.to_string())
    }

    pub fn cancel_task_local(&self, task_id: &str) -> Result<TaskView, String> {
        self.cancel_task_record(task_id.to_string())
            .map(|(task, _)| task)
    }

    pub fn get_task_local(&self, task_id: &str) -> Result<Option<TaskView>, String> {
        Ok(self.lock_registry()?.get_task(task_id))
    }

    pub fn get_approval_local(&self, approval_id: &str) -> Result<Option<ApprovalRequest>, String> {
        self.lock_audit()?
            .load_approvals()
            .map_err(|error| error.to_string())
            .map(|values| values.into_iter().find(|value| value.id == approval_id))
    }

    pub fn get_tool_run_local(&self, tool_call_id: &str) -> Result<Option<ToolRun>, String> {
        if tool_call_id.is_empty()
            || tool_call_id.len() > 128
            || tool_call_id.as_bytes().contains(&0)
        {
            return Err("invalid tool_call_id".to_string());
        }
        self.lock_audit()?
            .load_tool_run(tool_call_id)
            .map_err(|error| error.to_string())
    }

    /// Query the durable dispatch created for one immutable planned action.
    ///
    /// This is intentionally local-only. It lets the OS-owned crash reconciler
    /// distinguish "dispatch committed, response lost" from "not dispatched"
    /// without ever submitting the action a second time.
    pub fn get_agent_planned_action_dispatch_local(
        &self,
        plan_id: &str,
        action_id: &str,
    ) -> Result<Option<Value>, String> {
        let Some(plan) = self.get_agent_plan_local(plan_id)? else {
            return Ok(None);
        };
        if !plan
            .actions
            .iter()
            .any(|action| action.action_id == action_id)
        {
            return Err("action is not part of the immutable accepted plan".to_string());
        }
        let mut matches = self
            .list_tool_runs_record(Some(&plan.task_id.0), 1024)?
            .into_iter()
            .filter(|run| {
                run.agent_execution_binding.as_ref().is_some_and(|binding| {
                    binding.plan_id == plan_id
                        && binding.action_id == action_id
                        && binding.task_id == plan.task_id
                        && binding.tool_call_id == run.tool_call_id
                })
            });
        let Some(run) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            return Err("multiple durable dispatches exist for one immutable action".to_string());
        }
        let binding = run
            .agent_execution_binding
            .clone()
            .ok_or_else(|| "durable planned action dispatch omitted binding".to_string())?;
        let approval_id = run
            .approval_id
            .as_deref()
            .ok_or_else(|| "durable planned action dispatch omitted approval".to_string())?;
        let approval = self
            .get_approval_local(approval_id)?
            .ok_or_else(|| "durable planned action approval disappeared".to_string())?;
        if approval.task_id != run.task_id
            || approval.tool_call_id != run.tool_call_id
            || approval.tool_name != run.tool_name
        {
            return Err("durable planned action approval binding mismatch".to_string());
        }
        Ok(Some(json!({
            "execution_binding": binding,
            "approval": approval,
            "tool_run": run,
        })))
    }

    pub fn count_tool_started_local(&self, tool_call_id: &str) -> Result<usize, String> {
        let Some(run) = self.get_tool_run_local(tool_call_id)? else {
            return Ok(0);
        };
        self.lock_audit()?
            .list_events(Some(&run.task_id.0), 1024)
            .map_err(|error| error.to_string())
            .map(|events| {
                events
                    .into_iter()
                    .filter(|event| {
                        event.kind == AuditEventKind::ToolStarted
                            && event
                                .tool_call_id
                                .as_ref()
                                .is_some_and(|id| id.0 == tool_call_id)
                    })
                    .count()
            })
    }

    pub fn find_tool_run_by_receipt_local(
        &self,
        task_id: &str,
        receipt_id: &str,
    ) -> Result<Option<ToolRun>, String> {
        if receipt_id.len() != 64
            || !receipt_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("receipt_id must be 64 lowercase hex characters".to_string());
        }
        self.lock_audit()?
            .find_succeeded_tool_run_by_receipt(task_id, receipt_id)
            .map_err(|error| error.to_string())
    }

    pub fn get_agent_plan_local(
        &self,
        plan_id: &str,
    ) -> Result<Option<AgentPlanSubmission>, String> {
        self.lock_audit()?
            .get_agent_plan(plan_id)
            .map_err(|error| error.to_string())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    pub fn submit_agent_plan_local(
        &self,
        plan: AgentPlanSubmission,
    ) -> Result<AgentPlanSubmission, String> {
        self.submit_agent_plan_record(
            serde_json::to_string(&plan).map_err(|error| error.to_string())?,
        )
        .map(|(plan, _)| plan)
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    pub fn run_tool_local(
        &self,
        task_id: &str,
        tool_name: &str,
        arguments: &Value,
    ) -> Result<Value, String> {
        self.run_tool_record(
            task_id.to_string(),
            tool_name.to_string(),
            serde_json::to_string(arguments).map_err(|error| error.to_string())?,
        )
        .map(|(response, _)| response)
    }

    /// Resolve and dispatch an action from an already accepted immutable plan.
    /// Public Agent API callers never get to resubmit a tool name or arguments
    /// at execution time.
    #[cfg(any(test, feature = "legacy-plan-execution"))]
    pub fn run_agent_planned_action_local(
        &self,
        agent_id: &str,
        peer_uid: u32,
        peer_gid: u32,
        peer_selinux_domain: &str,
        request: AgentExecutionRequest,
    ) -> Result<Value, String> {
        let plan = self
            .get_agent_plan_local(&request.plan_id)?
            .ok_or_else(|| format!("unknown agent plan id: {}", request.plan_id))?;
        if !self
            .lock_audit()?
            .has_exact_agent_plan_submission_receipt(&plan)
            .map_err(|error| error.to_string())?
        {
            return Err(
                "accepted agent plan lacks its exact durable submission receipt".to_string(),
            );
        }
        if plan.agent_id != agent_id
            || plan.task_id != request.task_id
            || plan.api_version != AGENT_API_VERSION
        {
            return Err("agent execution request does not match the accepted plan".to_string());
        }
        let registration = self
            .get_agent_local(agent_id)?
            .ok_or_else(|| format!("unknown agent id: {agent_id}"))?;
        if !registration.enabled
            || registration.peer_uid != peer_uid
            || registration.peer_gid != peer_gid
            || registration.selinux_domain != peer_selinux_domain
        {
            return Err(
                "agent execution identity does not match the OS-owned manifest".to_string(),
            );
        }
        let task = self
            .get_task_local(&request.task_id.0)?
            .ok_or_else(|| format!("unknown task id: {}", request.task_id.0))?;
        ensure_task_nonterminal(&task, "agent action dispatch")?;
        let subject = frozen_agent_task_subject(&task, &registration)?;
        let action = plan
            .actions
            .iter()
            .find(|action| action.action_id == request.action_id)
            .ok_or_else(|| format!("unknown action id in accepted plan: {}", request.action_id))?;
        let action_index = plan
            .actions
            .iter()
            .position(|candidate| candidate.action_id == request.action_id)
            .expect("accepted action was found above");
        let prior_runs = self.list_tool_runs_record(Some(&request.task_id.0), 1024)?;
        for prior_action in &plan.actions[..action_index] {
            let succeeded = prior_runs.iter().any(|candidate| {
                candidate.status == ToolRunStatus::Succeeded
                    && candidate
                        .agent_execution_binding
                        .as_ref()
                        .is_some_and(|binding| {
                            binding.plan_id == plan.plan_id
                                && binding.action_id == prior_action.action_id
                        })
            });
            if !succeeded {
                return Err(format!(
                    "accepted plan action {} cannot run before prior action {} succeeds",
                    request.action_id, prior_action.action_id
                ));
            }
        }
        frozen_manifest_for_agent_action(action)?;
        let tool_manifest_sha256 = action
            .os_tool_manifest_sha256
            .clone()
            .ok_or_else(|| "accepted plan lacks its frozen OS tool manifest digest".to_string())?;
        let accepted_plan_sha256 = sha256_json(
            &serde_json::to_value(&plan)
                .map_err(|error| format!("failed to canonicalize accepted plan: {error}"))?,
        );
        let arguments_sha256 = sha256_json(&action.arguments);
        if action.arguments_sha256 != arguments_sha256 {
            return Err("accepted plan action arguments digest no longer matches".to_string());
        }
        let binding_digest = sha256_json(&json!({
            "agent_id": agent_id,
            "peer_uid": peer_uid,
            "peer_gid": peer_gid,
            "peer_selinux_domain": peer_selinux_domain,
            "agent_executable_sha256": subject.agent_executable_sha256,
            "subject_user_id": subject.subject_user_id,
            "origin_uid": subject.origin_uid,
            "origin_selinux_domain": subject.origin_selinux_domain,
            "session_id": plan.session_id,
            "task_id": request.task_id,
            "plan_id": request.plan_id,
            "action_id": request.action_id,
            "tool_name": action.tool_name,
            "tool_manifest_sha256": tool_manifest_sha256,
            "accepted_plan_sha256": accepted_plan_sha256,
            "arguments_sha256": arguments_sha256,
        }));
        let tool_call_id = ToolCallId(format!("toolcall-agent-{}", &binding_digest[..32]));
        if self.load_tool_run(&tool_call_id.0)?.is_some() {
            return Err("accepted plan action was already dispatched".to_string());
        }
        let binding = AgentExecutionBinding {
            agent_id: agent_id.to_string(),
            peer_uid,
            peer_gid,
            peer_selinux_domain: peer_selinux_domain.to_string(),
            agent_executable_sha256: subject.agent_executable_sha256,
            subject_user_id: subject.subject_user_id,
            origin_uid: subject.origin_uid,
            origin_selinux_domain: subject.origin_selinux_domain,
            session_id: plan.session_id,
            task_id: request.task_id.clone(),
            plan_id: request.plan_id,
            action_id: request.action_id,
            tool_call_id: tool_call_id.clone(),
            tool_name: action.tool_name.clone(),
            tool_manifest_sha256,
            accepted_plan_sha256,
            arguments_sha256,
        };
        let call = ToolCallInput {
            task_id: request.task_id,
            tool_call_id,
            tool_name: action.tool_name.clone(),
            arguments: action.arguments.clone(),
            agent_execution_binding: Some(binding.clone()),
        };
        let (mut response, _) = self.run_tool_call_record(call)?;
        if let Some(object) = response.as_object_mut() {
            object.insert("execution_binding".to_string(), json!(binding));
        }
        Ok(response)
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    pub fn approve_local(&self, approval_id: &str) -> Result<Value, String> {
        let (approval, grant, task, _) =
            self.approve_record(approval_id.to_string(), ApprovalLifetime::OneCall, None)?;
        let (tool_run, _) = self.resume_approved_tool_run(&approval, &grant)?;
        Ok(json!({
            "ok": true,
            "approval": approval,
            "grant": grant,
            "task": task,
            "tool_run": tool_run
        }))
    }

    fn lock_registry(&self) -> Result<std::sync::MutexGuard<'_, TaskRegistry>, String> {
        self.registry
            .lock()
            .map_err(|_| "task registry lock poisoned".to_string())
    }

    fn lock_audit(&self) -> Result<std::sync::MutexGuard<'_, AuditStore>, String> {
        self.audit
            .lock()
            .map_err(|_| "audit store lock poisoned".to_string())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn ensure_tool_run_frozen(&self, run: &ToolRun, manifest: &ToolManifest) -> Result<(), String> {
        let Some(binding) = run.agent_execution_binding.as_ref() else {
            return Ok(());
        };
        let current_manifest = sha256_json(
            &serde_json::to_value(manifest)
                .map_err(|error| format!("failed to canonicalize OS tool manifest: {error}"))?,
        );
        if binding.tool_manifest_sha256 != current_manifest {
            return Err(format!(
                "accepted plan OS tool manifest changed after dispatch: {}",
                run.tool_name
            ));
        }
        let plan = self
            .lock_audit()?
            .get_agent_plan(&binding.plan_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "accepted plan disappeared after dispatch".to_string())?;
        if !self
            .lock_audit()?
            .has_exact_agent_plan_submission_receipt(&plan)
            .map_err(|error| error.to_string())?
        {
            return Err(
                "accepted agent plan lost its exact durable submission receipt".to_string(),
            );
        }
        let accepted_plan_sha256 = sha256_json(
            &serde_json::to_value(&plan)
                .map_err(|error| format!("failed to canonicalize accepted plan: {error}"))?,
        );
        if accepted_plan_sha256 != binding.accepted_plan_sha256 {
            return Err("accepted plan changed after dispatch".to_string());
        }
        let action = plan
            .actions
            .iter()
            .find(|action| action.action_id == binding.action_id)
            .ok_or_else(|| "accepted plan action disappeared after dispatch".to_string())?;
        if action.tool_name != run.tool_name
            || action.os_tool_manifest_sha256.as_deref()
                != Some(binding.tool_manifest_sha256.as_str())
        {
            return Err("accepted plan action binding changed after dispatch".to_string());
        }
        let frozen_executor = action
            .os_executor_sha256
            .as_deref()
            .ok_or_else(|| "accepted plan predates OS executor freezing".to_string())?;
        if frozen_executor != current_os_executor_sha256()? {
            return Err(format!(
                "accepted plan OS executor changed after dispatch: {}",
                run.tool_name
            ));
        }
        Ok(())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn task_status_after_tool_success(&self, run: &ToolRun) -> Result<TaskStatus, String> {
        let Some(binding) = run.agent_execution_binding.as_ref() else {
            // A direct tool call has no immutable action set to aggregate.
            // Therefore one successful call completes the task and revokes
            // task-scoped consent; CurrentTask must never mean "open forever".
            return Ok(TaskStatus::Completed);
        };
        let plan = self
            .lock_audit()?
            .get_agent_plan(&binding.plan_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "accepted plan disappeared after tool success".to_string())?;
        let runs = self.list_tool_runs_record(Some(&run.task_id.0), 1024)?;
        let all_actions_succeeded = plan.actions.iter().all(|action| {
            action.action_id == binding.action_id
                || runs.iter().any(|candidate| {
                    candidate.status == ToolRunStatus::Succeeded
                        && candidate.agent_execution_binding.as_ref().is_some_and(
                            |candidate_binding| {
                                candidate_binding.plan_id == binding.plan_id
                                    && candidate_binding.action_id == action.action_id
                            },
                        )
                })
        });
        Ok(if all_actions_succeeded {
            TaskStatus::Completed
        } else {
            // Running is reserved for the in-flight side-effect interval. An
            // accepted plan with remaining actions is open but cancellable.
            TaskStatus::Created
        })
    }

    fn lock_grants(&self) -> Result<std::sync::MutexGuard<'_, Vec<ApprovalGrant>>, String> {
        self.grants
            .lock()
            .map_err(|_| "approval grant store lock poisoned".to_string())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn remember_atomically_persisted_grant(&self, grant: ApprovalGrant) -> Result<(), String> {
        if matches!(
            grant.lifetime,
            ApprovalLifetime::CurrentSession
                | ApprovalLifetime::UntilReboot
                | ApprovalLifetime::Persistent
        ) {
            return Err("subjectless long-lived positive approval grants are disabled".to_string());
        }
        if grant.lifetime == ApprovalLifetime::OneCall || grant.is_expired_at(now_unix_ms()) {
            return Ok(());
        }
        if grant.lifetime == ApprovalLifetime::CurrentTask
            && (!grant
                .tool_manifest_sha256
                .as_deref()
                .is_some_and(is_lower_sha256)
                || grant.os_executor_sha256.as_deref()
                    != Some(current_os_executor_sha256()?.as_str()))
        {
            return Err(
                "positive approval grant lacks its current frozen execution scope".to_string(),
            );
        }
        let mut grants = self.lock_grants()?;
        grants.retain(|existing| existing.id != grant.id);
        grants.push(grant);
        Ok(())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn prune_expired_grants(&self) -> Result<(), String> {
        let now = now_unix_ms();
        let expired_ids = {
            let mut grants = self.lock_grants()?;
            let expired_ids = grants
                .iter()
                .filter(|grant| grant.is_expired_at(now))
                .map(|grant| grant.id.clone())
                .collect::<Vec<_>>();
            grants.retain(|grant| !grant.is_expired_at(now));
            expired_ids
        };
        for grant_id in expired_ids {
            self.lock_audit()?
                .delete_approval_grant(&grant_id)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn policy_engine_with_grants(&self) -> Result<PolicyEngine, String> {
        self.prune_expired_grants()?;
        let current_executor = current_os_executor_sha256()?;
        let grants = self
            .lock_grants()?
            .iter()
            .filter(|grant| {
                grant.lifetime == ApprovalLifetime::NeverAllow
                    || grant.os_executor_sha256.as_deref() == Some(current_executor.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        let mut engine = PolicyEngine::new();
        for grant in grants {
            engine.add_grant(grant);
        }
        Ok(engine)
    }

    #[cfg(test)]
    fn list_approval_grants_record(&self) -> Result<Vec<ApprovalGrant>, String> {
        self.prune_expired_grants()?;
        Ok(self.lock_grants()?.clone())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn discard_grant_after_failed_resume(
        &self,
        grant_id: &str,
    ) -> Result<Option<AuditEvent>, String> {
        let grant = {
            let mut grants = self.lock_grants()?;
            let Some(index) = grants.iter().position(|grant| grant.id == grant_id) else {
                return Ok(None);
            };
            grants.remove(index)
        };
        self.lock_audit()?
            .delete_approval_grant(&grant.id)
            .map_err(|error| error.to_string())?;
        let mut event = AuditEvent::new(
            AuditEventKind::ApprovalGrantRevoked,
            format!(
                "discarded approval grant after frozen execution failed for {}",
                grant.tool_name
            ),
        )
        .with_payload(json!({ "grant": grant.clone(), "failure_first": true }));
        if let Some(task_id) = grant.task_id {
            event = event.with_task(task_id);
        }
        if let Some(tool_call_id) = grant.tool_call_id {
            event = event.with_tool_call(tool_call_id);
        }
        self.append_audit(event.clone())?;
        Ok(Some(event))
    }

    fn append_audit(&self, event: AuditEvent) -> Result<(), String> {
        self.lock_audit()?
            .append(&event)
            .map_err(|error| error.to_string())
    }

    fn save_task(&self, task: &TaskView) -> Result<(), String> {
        self.lock_audit()?
            .save_task(task)
            .map_err(|error| error.to_string())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn save_approval(&self, approval: &ApprovalRequest) -> Result<(), String> {
        self.lock_audit()?
            .save_approval(approval)
            .map_err(|error| error.to_string())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn save_tool_run(&self, run: &ToolRun) -> Result<(), String> {
        self.lock_audit()?
            .save_tool_run(run)
            .map_err(|error| error.to_string())
    }

    fn register_agent_record(
        &self,
        input_json: String,
    ) -> Result<(AgentRegistration, AuditEvent), String> {
        self.register_agent_record_with_authority(input_json, false)
    }

    fn register_agent_record_with_authority(
        &self,
        input_json: String,
        os_manifest_authority: bool,
    ) -> Result<(AgentRegistration, AuditEvent), String> {
        let mut registration = serde_json::from_str::<AgentRegistration>(&input_json)
            .map_err(|error| format!("invalid AgentRegistration JSON: {error}"))?;
        let validation = validate_agent_registration(&registration);
        if !validation.valid {
            return Err(format!(
                "invalid AgentRegistration: {}",
                validation.errors.join("; ")
            ));
        }
        let now = now_unix_ms();
        let existing = self
            .lock_audit()?
            .get_agent_registration(&registration.agent_id)
            .map_err(|error| error.to_string())?;
        if !os_manifest_authority {
            let existing = existing.as_ref().ok_or_else(|| {
                format!(
                    "agent identity must be OS-provisioned before attestation: {}",
                    registration.agent_id
                )
            })?;
            let mut attested = registration.clone();
            attested.registered_at_unix_ms = existing.registered_at_unix_ms;
            attested.updated_at_unix_ms = existing.updated_at_unix_ms;
            if attested != *existing {
                return Err(format!(
                    "agent attestation does not exactly match the OS-owned manifest: {}",
                    registration.agent_id
                ));
            }
            registration = existing.clone();
        }
        let registrations = self
            .lock_audit()?
            .load_agent_registrations()
            .map_err(|error| error.to_string())?;
        if registrations.iter().any(|bound| {
            bound.agent_id != registration.agent_id
                && bound.enabled
                && bound.peer_uid == registration.peer_uid
                && bound.selinux_domain == registration.selinux_domain
                && bound.identity_key_sha256 == registration.identity_key_sha256
        }) {
            return Err(
                "peer UID/domain/executable security identity is already bound to another agent"
                    .to_string(),
            );
        }
        if os_manifest_authority {
            registration.registered_at_unix_ms = existing
                .as_ref()
                .map(|value| value.registered_at_unix_ms)
                .unwrap_or(now);
            registration.updated_at_unix_ms = now;
            self.lock_audit()?
                .save_agent_registration(&registration)
                .map_err(|error| error.to_string())?;
        }
        let event = AuditEvent::new(
            AuditEventKind::AgentRegistered,
            format!(
                "{} built-in agent {}",
                if os_manifest_authority {
                    "OS-provisioned"
                } else {
                    "attested"
                },
                registration.agent_id
            ),
        )
        .with_payload(json!({
            "api_version": AGENT_API_VERSION,
            "os_manifest_authority": os_manifest_authority,
            "attestation_only": !os_manifest_authority,
            "registration": registration.clone()
        }));
        self.append_audit(event.clone())?;
        Ok((registration, event))
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn submit_agent_plan_record(
        &self,
        input_json: String,
    ) -> Result<(AgentPlanSubmission, AuditEvent), String> {
        let mut plan = serde_json::from_str::<AgentPlanSubmission>(&input_json)
            .map_err(|error| format!("invalid AgentPlanSubmission JSON: {error}"))?;
        let validation = validate_agent_plan(&plan);
        if !validation.valid {
            return Err(format!(
                "invalid AgentPlanSubmission: {}",
                validation.errors.join("; ")
            ));
        }
        let executor_digest = current_os_executor_sha256()?;
        for action in &mut plan.actions {
            if action.os_tool_manifest_sha256.is_some() {
                return Err(format!(
                    "agent plan must not supply OS tool manifest digest: {}",
                    action.action_id
                ));
            }
            if action.os_executor_sha256.is_some() {
                return Err(format!(
                    "agent plan must not supply OS executor digest: {}",
                    action.action_id
                ));
            }
            let (_, digest) = current_manifest_for_agent_action(action)?;
            action.os_tool_manifest_sha256 = Some(digest);
            action.os_executor_sha256 = Some(executor_digest.clone());
        }
        let frozen_validation = validate_agent_plan(&plan);
        if !frozen_validation.valid {
            return Err(format!(
                "invalid OS-frozen AgentPlanSubmission: {}",
                frozen_validation.errors.join("; ")
            ));
        }
        let agent = self
            .lock_audit()?
            .get_agent_registration(&plan.agent_id)
            .map_err(|error| format!("agent registration lookup failed: {error}"))?
            .ok_or_else(|| format!("unregistered agent id: {}", plan.agent_id))?;
        if !agent.enabled || agent.api_version != AGENT_API_VERSION {
            return Err(format!(
                "agent is disabled or incompatible: {}",
                plan.agent_id
            ));
        }
        let task = self
            .lock_registry()?
            .get_task(&plan.task_id.0)
            .ok_or_else(|| format!("unknown task id for plan: {}", plan.task_id.0))?;
        ensure_task_accepts_new_dispatch(&task, "agent plan submission")?;
        frozen_agent_task_subject(&task, &agent)?;
        if let Some(existing) = self
            .lock_audit()?
            .get_agent_plan_for_task(&plan.task_id.0)
            .map_err(|error| format!("immutable agent plan preflight failed: {error}"))?
            && existing.plan_id != plan.plan_id
        {
            return Err(format!(
                "task already has immutable agent plan {}",
                existing.plan_id
            ));
        }
        let event = AuditEvent::new(
            AuditEventKind::AgentPlanSubmitted,
            format!(
                "accepted bounded plan {} from {}",
                plan.plan_id, plan.agent_id
            ),
        )
        .with_task(plan.task_id.clone())
        .with_payload(json!({
            "api_version": AGENT_API_VERSION,
            "plan": plan.clone()
        }));
        match self
            .lock_audit()?
            .persist_agent_plan_submission_atomic(&plan, &event)
            .map_err(|error| format!("immutable agent plan commit failed: {error}"))?
        {
            AgentPlanSaveOutcome::Inserted => {}
            AgentPlanSaveOutcome::AlreadyPresent => {
                return Err(format!(
                    "agent plan id was already submitted: {}",
                    plan.plan_id
                ));
            }
        }
        Ok((plan, event))
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn load_tool_run(&self, tool_call_id: &str) -> Result<Option<ToolRun>, String> {
        self.lock_audit()?
            .load_tool_run(tool_call_id)
            .map_err(|error| error.to_string())
    }

    fn list_tool_runs_record(
        &self,
        task_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<ToolRun>, String> {
        self.lock_audit()?
            .list_tool_runs(task_id, limit)
            .map_err(|error| error.to_string())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn append_audit_signal(
        &self,
        event: AuditEvent,
        emissions: &mut Vec<SignalEmission>,
    ) -> Result<(), String> {
        self.append_audit(event.clone())?;
        emissions.push(SignalEmission::AuditEventAppended(event));
        Ok(())
    }

    fn create_task_record(&self, input_json: String) -> Result<(TaskView, AuditEvent), String> {
        let input = serde_json::from_str::<TaskInput>(&input_json)
            .map_err(|error| format!("invalid TaskInput JSON: {error}"))?;
        let task = {
            let mut registry = self.lock_registry()?;
            registry.create_task(input)
        };
        self.save_task(&task)?;
        let event = AuditEvent::new(
            AuditEventKind::TaskCreated,
            format!("created task {}", task.id.0),
        )
        .with_task(task.id.clone())
        .with_payload(json!({ "task": task.clone() }));
        self.append_audit(event.clone())?;
        Ok((task, event))
    }

    fn cancel_task_record(&self, task_id: String) -> Result<(TaskView, AuditEvent), String> {
        let _transition = self
            .state_transition_gate
            .lock()
            .map_err(|_| "task state transition gate lock poisoned".to_string())?;
        let task = self
            .lock_registry()?
            .cancel_task(&task_id)
            .ok_or_else(|| format!("task cannot be cancelled in its current state: {task_id}"))?;
        let event = AuditEvent::new(
            AuditEventKind::TaskCancelled,
            format!("cancelled task {}", task.id.0),
        )
        .with_task(task.id.clone())
        .with_payload(json!({ "task": task.clone() }));
        let persisted = self
            .lock_audit()?
            .persist_task_cancellation_atomic(
                &task,
                "task cancelled before approval execution",
                &event,
            )
            .map_err(|error| error.to_string())?;
        if !persisted {
            self.reload_runtime_state_from_audit()?;
            return Err("task cancellation lost a race with durable execution".to_string());
        }
        self.lock_grants()?
            .retain(|grant| grant.task_id.as_ref().is_none_or(|id| id.0 != task_id));
        Ok((task, event))
    }

    #[cfg(test)]
    fn request_approval_record(
        &self,
        input_json: String,
    ) -> Result<(ApprovalRequest, TaskView, AuditEvent), String> {
        let submission = serde_json::from_str::<ApprovalSubmission>(&input_json)
            .map_err(|error| format!("invalid ApprovalSubmission JSON: {error}"))?;
        let manifest = manifest_by_name(&submission.tool_name).ok_or_else(|| {
            format!(
                "approval tool manifest is unavailable: {}",
                submission.tool_name
            )
        })?;
        validate_manifest(&manifest).map_err(|error| error.to_string())?;
        let manifest_sha256 = sha256_json(
            &serde_json::to_value(&manifest)
                .map_err(|error| format!("failed to canonicalize OS tool manifest: {error}"))?,
        );
        self.request_approval_transition(submission, manifest_sha256, None)
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn request_approval_transition(
        &self,
        submission: ApprovalSubmission,
        manifest_sha256: String,
        mut tool_run: Option<&mut ToolRun>,
    ) -> Result<(ApprovalRequest, TaskView, AuditEvent), String> {
        let _transition = self
            .state_transition_gate
            .lock()
            .map_err(|_| "approval state transition gate lock poisoned".to_string())?;
        let (request, task, expected_status) = {
            let mut registry = self.lock_registry()?;
            let before = registry
                .get_task(&submission.task_id.0)
                .ok_or_else(|| "unknown task id for approval request".to_string())?;
            ensure_task_accepts_new_dispatch(&before, "approval request")?;
            let expected_status = before.status;
            let request = registry
                .request_approval(submission)
                .ok_or_else(|| "task rejected approval request".to_string())?;
            let request = registry
                .bind_approval_manifest(&request.id, manifest_sha256)
                .ok_or_else(|| {
                    "approval manifest binding was not published atomically".to_string()
                })?;
            let task = registry
                .get_task(&request.task_id.0)
                .ok_or_else(|| "task disappeared after approval request".to_string())?;
            (request, task, expected_status)
        };
        if let Some(run) = tool_run.as_deref_mut() {
            run.mark_waiting_for_approval(request.id.clone());
        }
        let event_payload = tool_run.as_deref().map_or_else(
            || json!({ "approval": request.clone() }),
            |run| json!({ "approval": request.clone(), "tool_run": run.clone() }),
        );
        let event = AuditEvent::new(
            AuditEventKind::ApprovalRequested,
            format!("approval requested for {}", request.tool_name),
        )
        .with_task(request.task_id.clone())
        .with_tool_call(request.tool_call_id.clone())
        .with_payload(event_payload);
        let persisted = self
            .lock_audit()?
            .persist_approval_request_atomic(
                &expected_status,
                &task,
                &request,
                tool_run.as_deref(),
                &event,
            )
            .map_err(|error| error.to_string())?;
        if !persisted {
            self.reload_runtime_state_from_audit()?;
            return Err("approval request lost a race with a durable task transition".to_string());
        }
        Ok((request, task, event))
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn approve_record(
        &self,
        approval_id: String,
        lifetime: ApprovalLifetime,
        expires_at_unix_ms: Option<u64>,
    ) -> Result<(ApprovalRequest, ApprovalGrant, TaskView, AuditEvent), String> {
        ensure_supported_grant_lifetime(&lifetime)?;
        validate_grant_expiry(&lifetime, expires_at_unix_ms)?;
        let _transition = self
            .state_transition_gate
            .lock()
            .map_err(|_| "approval state transition gate lock poisoned".to_string())?;
        let pending = self
            .get_approval_local(&approval_id)?
            .ok_or_else(|| format!("unknown approval id: {approval_id}"))?;
        let manifest_sha256 = pending
            .tool_manifest_sha256
            .clone()
            .filter(|digest| is_lower_sha256(digest))
            .ok_or_else(|| "approval predates ToolManifest consent freezing".to_string())?;
        let agent_subject_sha256 = self
            .load_tool_run(&pending.tool_call_id.0)?
            .filter(|run| run.task_id == pending.task_id && run.tool_name == pending.tool_name)
            .and_then(|run| run.agent_execution_binding)
            .map(|binding| binding.approval_subject_sha256());
        let boot_id = if lifetime == ApprovalLifetime::UntilReboot {
            Some(current_boot_id()?)
        } else {
            None
        };
        let (mut approval, grant, task) = {
            let mut registry = self.lock_registry()?;
            let (approval, grant) = registry
                .approve_with_lifetime(&approval_id, lifetime)
                .ok_or_else(|| format!("unknown or non-pending approval id: {approval_id}"))?;
            let task = registry
                .get_task(&approval.task_id.0)
                .ok_or_else(|| "task disappeared after approval decision".to_string())?;
            (approval, grant, task)
        };
        approval.tool_manifest_sha256 = Some(manifest_sha256.clone());
        let grant = grant.with_execution_scope(
            manifest_sha256,
            agent_subject_sha256,
            current_os_executor_sha256()?,
        );
        let grant = if let Some(expires_at_unix_ms) = expires_at_unix_ms {
            grant.with_expires_at(expires_at_unix_ms)
        } else {
            grant
        };
        let grant = if grant.lifetime == ApprovalLifetime::UntilReboot {
            grant.with_boot_id(boot_id.expect("until-reboot boot id should be pre-read"))
        } else {
            grant
        };
        let event = AuditEvent::new(
            AuditEventKind::ApprovalDecided,
            format!("approved {}", approval.tool_name),
        )
        .with_task(approval.task_id.clone())
        .with_tool_call(approval.tool_call_id.clone())
        .with_payload(json!({
            "approval": approval.clone(),
            "grant": grant.clone()
        }));
        let durable_grant = (grant.lifetime != ApprovalLifetime::OneCall).then_some(&grant);
        let persisted = self
            .lock_audit()?
            .persist_approval_decision_atomic(
                &TaskStatus::WaitingForApproval,
                &trillionnium_os_types::ApprovalStatus::Pending,
                &task,
                &approval,
                durable_grant,
                &event,
            )
            .map_err(|error| error.to_string())?;
        if !persisted {
            self.reload_runtime_state_from_audit()?;
            return Err("approval decision lost a race with durable cancellation".to_string());
        }
        self.remember_atomically_persisted_grant(grant.clone())?;
        Ok((approval, grant, task, event))
    }

    #[cfg(test)]
    fn deny_with_lifetime_record(
        &self,
        approval_id: String,
        reason: String,
        lifetime: Option<ApprovalLifetime>,
        expires_at_unix_ms: Option<u64>,
    ) -> Result<(ApprovalRequest, Option<ApprovalGrant>, TaskView, AuditEvent), String> {
        if let Some(lifetime) = &lifetime {
            ensure_supported_deny_lifetime(lifetime)?;
            validate_grant_expiry(lifetime, expires_at_unix_ms)?;
        } else if expires_at_unix_ms.is_some() {
            return Err("deny expiry requires never_allow scope".to_string());
        }
        let _transition = self
            .state_transition_gate
            .lock()
            .map_err(|_| "approval state transition gate lock poisoned".to_string())?;
        let (approval, task) = {
            let mut registry = self.lock_registry()?;
            let approval = registry
                .deny(&approval_id, reason)
                .ok_or_else(|| format!("unknown or non-pending approval id: {approval_id}"))?;
            let task = registry
                .get_task(&approval.task_id.0)
                .ok_or_else(|| "task disappeared after approval decision".to_string())?;
            (approval, task)
        };
        let grant = lifetime.map(|lifetime| {
            let grant = ApprovalGrant::scoped(
                approval.tool_name.clone(),
                approval.tool_call_id.clone(),
                approval.task_id.clone(),
                lifetime,
            );
            if let Some(expires_at_unix_ms) = expires_at_unix_ms {
                grant.with_expires_at(expires_at_unix_ms)
            } else {
                grant
            }
        });
        let event = AuditEvent::new(
            AuditEventKind::ApprovalDecided,
            format!("denied {}", approval.tool_name),
        )
        .with_task(approval.task_id.clone())
        .with_tool_call(approval.tool_call_id.clone())
        .with_payload(json!({
            "approval": approval.clone(),
            "grant": grant.clone()
        }));
        let persisted = self
            .lock_audit()?
            .persist_approval_decision_atomic(
                &TaskStatus::WaitingForApproval,
                &trillionnium_os_types::ApprovalStatus::Pending,
                &task,
                &approval,
                grant.as_ref(),
                &event,
            )
            .map_err(|error| error.to_string())?;
        if !persisted {
            self.reload_runtime_state_from_audit()?;
            return Err("denial decision lost a race with durable cancellation".to_string());
        }
        if let Some(grant) = &grant {
            self.remember_atomically_persisted_grant(grant.clone())?;
        }
        Ok((approval, grant, task, event))
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn run_tool_record(
        &self,
        task_id: String,
        tool_name: String,
        arguments_json: String,
    ) -> Result<(Value, Vec<SignalEmission>), String> {
        let arguments = serde_json::from_str::<Value>(&arguments_json)
            .map_err(|error| format!("invalid tool arguments JSON: {error}"))?;
        let task_id = TaskId(task_id);
        self.run_tool_call_record(ToolCallInput {
            task_id,
            tool_call_id: ToolCallId::new(),
            tool_name,
            arguments,
            agent_execution_binding: None,
        })
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn run_tool_call_record(
        &self,
        call: ToolCallInput,
    ) -> Result<(Value, Vec<SignalEmission>), String> {
        // Serialize the transition from an open task to either Waiting or an
        // execution claim. This makes two concurrent callers observe the
        // first caller's durable busy state instead of creating two pending
        // approvals for one task.
        let _dispatch = self
            .dispatch_gate
            .lock()
            .map_err(|_| "tool dispatch gate lock poisoned".to_string())?;
        self.reload_runtime_state_from_audit()?;
        let mut emissions = Vec::new();
        let manifest = manifest_by_name(&call.tool_name)
            .ok_or_else(|| format!("unknown or unavailable tool: {}", call.tool_name))?;
        let task = self
            .lock_registry()?
            .get_task(&call.task_id.0)
            .ok_or_else(|| format!("unknown task id: {}", call.task_id.0))?;
        ensure_task_accepts_new_dispatch(&task, "tool dispatch")?;
        let run = ToolRun::requested(call);
        if run.agent_execution_binding.is_some()
            && !self
                .lock_audit()?
                .insert_tool_run_if_absent(&run)
                .map_err(|error| error.to_string())?
        {
            return Err("accepted plan action was already dispatched".to_string());
        }
        self.record_tool_requested(&run, &mut emissions, false)?;
        let response = self.process_requested_tool_run(run, manifest, &mut emissions)?;
        Ok((response, emissions))
    }

    #[cfg(test)]
    fn retry_tool_run_record(
        &self,
        tool_call_id: String,
    ) -> Result<(Value, Vec<SignalEmission>), String> {
        self.reload_runtime_state_from_audit()?;
        let mut emissions = Vec::new();
        let Some(mut run) = self.load_tool_run(&tool_call_id)? else {
            return Err(format!("unknown tool call id: {tool_call_id}"));
        };
        let task = self
            .get_task_local(&run.task_id.0)?
            .ok_or_else(|| "tool retry task disappeared".to_string())?;
        ensure_task_nonterminal(&task, "tool retry")?;
        if !matches!(
            run.status,
            ToolRunStatus::Failed | ToolRunStatus::ApprovalGrantedAwaitingRetry
        ) {
            return Err(format!(
                "tool run {} is {:?}; retry supports only Failed or ApprovalGrantedAwaitingRetry",
                run.tool_call_id.0, run.status
            ));
        }
        let Some(manifest) = manifest_by_name(&run.tool_name) else {
            let error = format!(
                "cannot retry {}; tool manifest {} is unavailable",
                run.tool_call_id.0, run.tool_name
            );
            run.mark_approval_granted_awaiting_retry();
            run.error = Some(error.clone());
            self.save_tool_run(&run)?;
            return Ok((
                tool_response(false, &run, None, None, Some(error)),
                emissions,
            ));
        };
        if let Err(error) = self.ensure_tool_run_frozen(&run, &manifest) {
            run.mark_failed(error.clone());
            self.save_tool_run(&run)?;
            if let Some(task) = self.fail_task(&run.task_id.0)? {
                emissions.push(SignalEmission::TaskUpdated(task));
            }
            let event = AuditEvent::new(AuditEventKind::ToolFailed, error.clone())
                .with_task(run.task_id.clone())
                .with_tool_call(run.tool_call_id.clone())
                .with_payload(json!({ "tool_run": run.clone(), "retry": true }));
            self.append_audit(event.clone())?;
            emissions.push(SignalEmission::ToolFailed(run.clone()));
            emissions.push(SignalEmission::AuditEventAppended(event));
            return Ok((
                tool_response(false, &run, None, None, Some(error)),
                emissions,
            ));
        }

        // Preserve ApprovalGrantedAwaitingRetry and its approval id so the
        // durable claim can prove Waiting task ↔ Approved request lineage.
        run.requested_at_unix_ms = now_unix_ms();
        run.started_at_unix_ms = None;
        run.finished_at_unix_ms = None;
        run.output = None;
        run.error = None;
        run.policy_decision = None;
        self.record_tool_requested(&run, &mut emissions, true)?;
        let response = self.process_requested_tool_run(run, manifest, &mut emissions)?;
        Ok((response, emissions))
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn record_tool_requested(
        &self,
        run: &ToolRun,
        emissions: &mut Vec<SignalEmission>,
        retry: bool,
    ) -> Result<(), String> {
        // Requested is deliberately persisted before its informational event.
        // If event insertion fails or the process stops in that narrow window,
        // this function returns before policy evaluation and before the atomic
        // Running/ToolStarted side-effect claim. Startup never auto-replays a
        // Requested row, and an accepted action's deterministic tool-call id
        // prevents silent redispatch. The possible outcome is therefore a
        // fail-closed row requiring explicit forensic recovery, not execution
        // without a receipt.
        self.save_tool_run(run)?;
        let event = AuditEvent::new(
            AuditEventKind::ToolRequested,
            if retry {
                format!("tool retry requested: {}", run.tool_name)
            } else {
                format!("tool requested: {}", run.tool_name)
            },
        )
        .with_task(run.task_id.clone())
        .with_tool_call(run.tool_call_id.clone())
        .with_payload(json!({
            "tool_run": run.clone(),
            "retry": retry,
            "agent_execution_binding": run.agent_execution_binding
        }));
        self.append_audit(event.clone())?;
        emissions.push(SignalEmission::ToolRequested(run.clone()));
        emissions.push(SignalEmission::AuditEventAppended(event));
        Ok(())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn process_requested_tool_run(
        &self,
        mut run: ToolRun,
        manifest: trillionnium_os_types::ToolManifest,
        emissions: &mut Vec<SignalEmission>,
    ) -> Result<Value, String> {
        let call = run.call_input();
        validate_manifest(&manifest).map_err(|error| error.to_string())?;
        if let Err(error) = self.ensure_tool_run_frozen(&run, &manifest) {
            run.mark_failed(error.clone());
            self.save_tool_run(&run)?;
            if let Some(task) = self.fail_task(&run.task_id.0)? {
                emissions.push(SignalEmission::TaskUpdated(task));
            }
            let event = AuditEvent::new(AuditEventKind::ToolFailed, error.clone())
                .with_task(run.task_id.clone())
                .with_tool_call(run.tool_call_id.clone())
                .with_payload(json!({ "tool_run": run.clone(), "pre_policy": true }));
            self.append_audit(event.clone())?;
            emissions.push(SignalEmission::ToolFailed(run.clone()));
            emissions.push(SignalEmission::AuditEventAppended(event));
            return Ok(tool_response(false, &run, None, None, Some(error)));
        }
        let validation = validate_tool_call(&manifest, &call).map_err(|error| error.to_string())?;
        if !validation.valid {
            let error = format!(
                "tool arguments failed validation: {}",
                validation.errors.join("; ")
            );
            run.mark_failed(error.clone());
            self.save_tool_run(&run)?;
            self.fail_task(&run.task_id.0)?;
            let event = AuditEvent::new(AuditEventKind::ToolFailed, error.clone())
                .with_task(run.task_id.clone())
                .with_tool_call(run.tool_call_id.clone())
                .with_payload(json!({ "tool_run": run.clone(), "validation": validation }));
            self.append_audit(event.clone())?;
            emissions.push(SignalEmission::ToolFailed(run.clone()));
            emissions.push(SignalEmission::AuditEventAppended(event));
            return Ok(tool_response(false, &run, None, None, Some(error)));
        }

        let decision = self.policy_engine_with_grants()?.evaluate(&manifest, &call);
        run.policy_decision = Some(decision.clone());
        self.save_tool_run(&run)?;
        self.record_policy_evaluated(&run, &decision, emissions)?;

        match decision.kind {
            PolicyDecisionKind::Allow => {
                let run = self.execute_allowed_tool_run(run, manifest, emissions)?;
                Ok(tool_response(true, &run, None, run.output.clone(), None))
            }
            PolicyDecisionKind::Ask => {
                let manifest_sha256 =
                    sha256_json(&serde_json::to_value(&manifest).map_err(|error| {
                        format!("failed to canonicalize OS tool manifest: {error}")
                    })?);
                let (approval, task, event) = self.request_approval_transition(
                    ApprovalSubmission {
                        task_id: run.task_id.clone(),
                        tool_call_id: Some(run.tool_call_id.clone()),
                        tool_name: run.tool_name.clone(),
                        reason: decision.reason.clone(),
                    },
                    manifest_sha256,
                    Some(&mut run),
                )?;
                emissions.push(SignalEmission::ApprovalRequested(approval.clone()));
                emissions.push(SignalEmission::TaskUpdated(task));
                emissions.push(SignalEmission::AuditEventAppended(event));
                Ok(tool_response(true, &run, Some(approval), None, None))
            }
            PolicyDecisionKind::Deny => {
                let error = decision.reason.clone();
                run.mark_failed(error.clone());
                self.save_tool_run(&run)?;
                self.fail_task(&run.task_id.0)?;
                let event = AuditEvent::new(
                    AuditEventKind::ToolFailed,
                    format!("tool denied by policy: {}", run.tool_name),
                )
                .with_task(run.task_id.clone())
                .with_tool_call(run.tool_call_id.clone())
                .with_payload(json!({ "tool_run": run.clone(), "decision": decision }));
                self.append_audit(event.clone())?;
                emissions.push(SignalEmission::ToolFailed(run.clone()));
                emissions.push(SignalEmission::AuditEventAppended(event));
                Ok(tool_response(false, &run, None, None, Some(error)))
            }
        }
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn resume_approved_tool_run(
        &self,
        approval: &ApprovalRequest,
        grant: &ApprovalGrant,
    ) -> Result<(Option<ToolRun>, Vec<SignalEmission>), String> {
        let mut emissions = Vec::new();
        let Some(mut run) = self.load_tool_run(&approval.tool_call_id.0)? else {
            return Ok((None, emissions));
        };
        if run.status != ToolRunStatus::WaitingForApproval {
            return Ok((Some(run), emissions));
        }
        let task = self
            .get_task_local(&run.task_id.0)?
            .ok_or_else(|| "approval task disappeared before resume".to_string())?;
        if let Err(error) = ensure_task_nonterminal(&task, "approval resume") {
            run.mark_failed(error.clone());
            self.save_tool_run(&run)?;
            if let Some(event) = self.discard_grant_after_failed_resume(&grant.id)? {
                emissions.push(SignalEmission::AuditEventAppended(event));
            }
            let event = AuditEvent::new(AuditEventKind::ToolFailed, error)
                .with_task(run.task_id.clone())
                .with_tool_call(run.tool_call_id.clone())
                .with_payload(json!({ "tool_run": run.clone(), "terminal_task": true }));
            self.append_audit(event.clone())?;
            emissions.push(SignalEmission::ToolFailed(run.clone()));
            emissions.push(SignalEmission::AuditEventAppended(event));
            return Ok((Some(run), emissions));
        }

        let Some(manifest) = manifest_by_name(&run.tool_name) else {
            run.mark_approval_granted_awaiting_retry();
            run.error = Some("approved, but tool manifest is no longer available".to_string());
            self.save_tool_run(&run)?;
            return Ok((Some(run), emissions));
        };
        let frozen_resume = self.ensure_tool_run_frozen(&run, &manifest).and_then(|()| {
            let current_executor = current_os_executor_sha256()?;
            if grant.os_executor_sha256.as_deref() == Some(current_executor.as_str()) {
                Ok(())
            } else {
                Err("approval grant OS executor changed before resume".to_string())
            }
        });
        if let Err(error) = frozen_resume {
            run.mark_failed(error.clone());
            self.save_tool_run(&run)?;
            if let Some(task) = self.fail_task(&run.task_id.0)? {
                emissions.push(SignalEmission::TaskUpdated(task));
            }
            if let Some(event) = self.discard_grant_after_failed_resume(&grant.id)? {
                emissions.push(SignalEmission::AuditEventAppended(event));
            }
            let event = AuditEvent::new(AuditEventKind::ToolFailed, error)
                .with_task(run.task_id.clone())
                .with_tool_call(run.tool_call_id.clone())
                .with_payload(json!({ "tool_run": run.clone() }));
            self.append_audit(event.clone())?;
            emissions.push(SignalEmission::ToolFailed(run.clone()));
            emissions.push(SignalEmission::AuditEventAppended(event));
            return Ok((Some(run), emissions));
        }
        let call = run.call_input();
        let decision = PolicyEngine::new()
            .with_grant(grant.clone())
            .evaluate(&manifest, &call);
        run.policy_decision = Some(decision.clone());
        self.save_tool_run(&run)?;
        self.record_policy_evaluated(&run, &decision, &mut emissions)?;

        if decision.kind != PolicyDecisionKind::Allow {
            run.mark_approval_granted_awaiting_retry();
            run.error = Some(decision.reason.clone());
            self.save_tool_run(&run)?;
            return Ok((Some(run), emissions));
        }

        let run = self.execute_allowed_tool_run(run, manifest, &mut emissions)?;
        Ok((Some(run), emissions))
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn execute_allowed_tool_run(
        &self,
        mut run: ToolRun,
        manifest: trillionnium_os_types::ToolManifest,
        emissions: &mut Vec<SignalEmission>,
    ) -> Result<ToolRun, String> {
        let task = self
            .get_task_local(&run.task_id.0)?
            .ok_or_else(|| "tool task disappeared before execution".to_string())?;
        ensure_task_nonterminal(&task, "tool execution")?;
        self.ensure_tool_run_frozen(&run, &manifest)?;
        let expected_run_status = run.status.clone();
        let mut claimed_task = task;
        claimed_task.status = TaskStatus::Running;
        claimed_task.updated_at_unix_ms = now_unix_ms();
        run.mark_running();
        let event = AuditEvent::new(
            AuditEventKind::ToolStarted,
            format!("tool started: {}", run.tool_name),
        )
        .with_task(run.task_id.clone())
        .with_tool_call(run.tool_call_id.clone())
        .with_payload(json!({ "tool_run": run.clone() }));
        let claimed = self
            .lock_audit()?
            .persist_tool_execution_claim_atomic(&claimed_task, &run, &expected_run_status, &event)
            .map_err(|error| error.to_string())?;
        if !claimed {
            self.reload_runtime_state_from_audit()?;
            return Err(format!(
                "durable tool execution claim denied for task {}",
                run.task_id.0
            ));
        }
        self.lock_registry()?
            .apply_persisted_task(claimed_task.clone())
            .ok_or_else(|| "durably claimed task disappeared from registry".to_string())?;
        emissions.push(SignalEmission::TaskUpdated(claimed_task));
        emissions.push(SignalEmission::ToolStarted(run.clone()));
        emissions.push(SignalEmission::AuditEventAppended(event));

        let call = run.call_input();
        let execution_payload = self
            .execution_payload_resolver
            .read()
            .map_err(|_| "execution payload resolver lock poisoned".to_string())
            .and_then(|slot| {
                slot.as_ref()
                    .map(|resolver| resolver.resolve_and_consume(&call))
                    .transpose()
                    .map(Option::flatten)
            });
        let execution_payload = match execution_payload {
            Ok(payload) => payload,
            Err(_) => {
                let error = "protected execution payload resolution failed closed".to_string();
                run.mark_failed(error.clone());
                let event = AuditEvent::new(AuditEventKind::ToolFailed, error)
                    .with_task(run.task_id.clone())
                    .with_tool_call(run.tool_call_id.clone())
                    .with_payload(json!({ "tool_run": run.clone() }));
                let task = self.persist_tool_execution_finish(&run, TaskStatus::Failed, &event)?;
                emissions.push(SignalEmission::TaskUpdated(task));
                emissions.push(SignalEmission::ToolFailed(run.clone()));
                emissions.push(SignalEmission::AuditEventAppended(event));
                return Ok(run);
            }
        };
        match execute_builtin_tool_with_execution_payload(
            &manifest,
            &call,
            execution_payload.as_ref(),
        ) {
            Ok(output) => {
                run.mark_succeeded(output.clone());
                let task_status = self.task_status_after_tool_success(&run)?;
                let event = AuditEvent::new(
                    AuditEventKind::ToolFinished,
                    format!("tool finished: {}", run.tool_name),
                )
                .with_task(run.task_id.clone())
                .with_tool_call(run.tool_call_id.clone())
                .with_payload(json!({ "tool_run": run.clone(), "output": output }));
                let task = self.persist_tool_execution_finish(&run, task_status, &event)?;
                emissions.push(SignalEmission::TaskUpdated(task));
                emissions.push(SignalEmission::ToolFinished(run.clone()));
                emissions.push(SignalEmission::AuditEventAppended(event));
            }
            Err(error) => {
                let outcome_indeterminate = matches!(
                    &error,
                    ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(_)
                );
                if outcome_indeterminate {
                    run.mark_indeterminate(error.to_string());
                } else {
                    run.mark_failed(error.to_string());
                }
                let event = AuditEvent::new(
                    AuditEventKind::ToolFailed,
                    if outcome_indeterminate {
                        format!("tool outcome indeterminate: {}", run.tool_name)
                    } else {
                        format!("tool failed: {}", run.tool_name)
                    },
                )
                .with_task(run.task_id.clone())
                .with_tool_call(run.tool_call_id.clone())
                .with_payload(json!({
                    "tool_run": run.clone(),
                    "indeterminate": outcome_indeterminate,
                    "automatic_replay_forbidden": outcome_indeterminate
                }));
                let task = self.persist_tool_execution_finish(
                    &run,
                    if outcome_indeterminate {
                        TaskStatus::Indeterminate
                    } else {
                        TaskStatus::Failed
                    },
                    &event,
                )?;
                emissions.push(SignalEmission::TaskUpdated(task));
                emissions.push(SignalEmission::ToolFailed(run.clone()));
                emissions.push(SignalEmission::AuditEventAppended(event));
            }
        }
        Ok(run)
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn persist_tool_execution_finish(
        &self,
        run: &ToolRun,
        status: TaskStatus,
        event: &AuditEvent,
    ) -> Result<TaskView, String> {
        let mut task = self
            .get_task_local(&run.task_id.0)?
            .ok_or_else(|| "claimed tool task disappeared before durable finish".to_string())?;
        if task.status != TaskStatus::Running {
            return Err(format!(
                "tool finish expected Running task {}, found {:?}",
                task.id.0, task.status
            ));
        }
        task.status = status;
        task.updated_at_unix_ms = now_unix_ms();
        let persisted = self
            .lock_audit()?
            .persist_tool_execution_finish_atomic(&task, run, event)
            .map_err(|error| error.to_string())?;
        if !persisted {
            self.reload_runtime_state_from_audit()?;
            return Err(format!(
                "tool {} crossed the side-effect boundary but its durable finish receipt could not be committed; outcome is indeterminate",
                run.tool_call_id.0
            ));
        }
        self.reload_runtime_state_from_audit()?;
        self.get_task_local(&run.task_id.0)?
            .ok_or_else(|| "durably finished task disappeared after reload".to_string())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn record_policy_evaluated(
        &self,
        run: &ToolRun,
        decision: &PolicyDecision,
        emissions: &mut Vec<SignalEmission>,
    ) -> Result<(), String> {
        let event = AuditEvent::new(
            AuditEventKind::PolicyEvaluated,
            format!(
                "policy evaluated for {}: {:?}",
                run.tool_name, decision.kind
            ),
        )
        .with_task(run.task_id.clone())
        .with_tool_call(run.tool_call_id.clone())
        .with_payload(json!({ "tool_run": run.clone(), "decision": decision.clone() }));
        self.append_audit_signal(event.clone(), emissions)?;
        emissions.push(SignalEmission::PolicyEvaluated(event));
        Ok(())
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn update_task_status(
        &self,
        task_id: &str,
        status: TaskStatus,
    ) -> Result<Option<TaskView>, String> {
        let terminal = matches!(
            status,
            TaskStatus::Indeterminate
                | TaskStatus::Completed
                | TaskStatus::Failed
                | TaskStatus::Cancelled
        );
        let (task, terminated_approvals) = {
            let mut registry = self.lock_registry()?;
            let task = registry.update_task_status(task_id, status);
            let terminated = if terminal && task.is_some() {
                registry.terminate_pending_approvals(
                    task_id,
                    "task entered a terminal state before approval execution",
                )
            } else {
                Vec::new()
            };
            (task, terminated)
        };
        if let Some(task) = &task {
            self.save_task(task)?;
        }
        if terminal && task.is_some() {
            let removed_grants = {
                let mut grants = self.lock_grants()?;
                let mut removed = Vec::new();
                grants.retain(|grant| {
                    if grant.task_id.as_ref().is_some_and(|id| id.0 == task_id) {
                        removed.push(grant.clone());
                        false
                    } else {
                        true
                    }
                });
                removed
            };
            for grant in removed_grants {
                self.lock_audit()?
                    .delete_approval_grant(&grant.id)
                    .map_err(|error| error.to_string())?;
                self.append_audit(
                    AuditEvent::new(
                        AuditEventKind::ApprovalGrantRevoked,
                        format!(
                            "revoked {} grant because task became terminal",
                            grant.tool_name
                        ),
                    )
                    .with_task(TaskId(task_id.to_string()))
                    .with_payload(json!({ "grant": grant, "terminal_task": true })),
                )?;
            }
        }
        for approval in terminated_approvals {
            self.save_approval(&approval)?;
            self.append_audit(
                AuditEvent::new(
                    AuditEventKind::ApprovalDecided,
                    format!(
                        "approval {} denied because its task became terminal",
                        approval.id
                    ),
                )
                .with_task(approval.task_id.clone())
                .with_tool_call(approval.tool_call_id.clone())
                .with_payload(json!({ "approval": approval.clone(), "failure_first": true })),
            )?;
            if let Some(mut run) = self.load_tool_run(&approval.tool_call_id.0)?
                && run.status == ToolRunStatus::WaitingForApproval
            {
                run.mark_failed("task became terminal before approval execution");
                self.save_tool_run(&run)?;
                self.append_audit(
                    AuditEvent::new(
                        AuditEventKind::ToolFailed,
                        format!(
                            "tool {} invalidated because its task became terminal",
                            run.tool_name
                        ),
                    )
                    .with_task(run.task_id.clone())
                    .with_tool_call(run.tool_call_id.clone())
                    .with_payload(json!({
                        "tool_run": run,
                        "terminal_task": true,
                        "failure_first": true
                    })),
                )?;
            }
        }
        Ok(task)
    }

    #[cfg(any(test, feature = "legacy-plan-execution"))]
    fn fail_task(&self, task_id: &str) -> Result<Option<TaskView>, String> {
        self.update_task_status(task_id, TaskStatus::Failed)
    }
}

impl Default for AgentService {
    fn default() -> Self {
        Self::in_memory().expect("in-memory audit store should initialize")
    }
}

#[cfg(any(test, feature = "legacy-plan-execution"))]
fn tool_response(
    ok: bool,
    run: &ToolRun,
    approval: Option<ApprovalRequest>,
    output: Option<Value>,
    error: Option<String>,
) -> Value {
    json!({
        "ok": ok,
        "tool_run": run,
        "approval": approval,
        "output": output,
        "error": error
    })
}

#[cfg(test)]
fn parse_approval_lifetime(value: &str) -> Result<ApprovalLifetime, String> {
    let lifetime = parse_lifetime_value(value)?;
    ensure_supported_grant_lifetime(&lifetime)?;
    Ok(lifetime)
}

#[cfg(test)]
fn parse_deny_lifetime(value: &str) -> Result<ApprovalLifetime, String> {
    let lifetime = parse_lifetime_value(value)?;
    ensure_supported_deny_lifetime(&lifetime)?;
    Ok(lifetime)
}

#[cfg(test)]
fn parse_lifetime_value(value: &str) -> Result<ApprovalLifetime, String> {
    let lifetime = serde_json::from_value::<ApprovalLifetime>(json!(value.trim()))
        .map_err(|_| format!("unsupported approval lifetime: {value}"))?;
    Ok(lifetime)
}

#[cfg(any(test, feature = "legacy-plan-execution"))]
fn ensure_supported_grant_lifetime(lifetime: &ApprovalLifetime) -> Result<(), String> {
    match lifetime {
        ApprovalLifetime::OneCall | ApprovalLifetime::CurrentTask => Ok(()),
        ApprovalLifetime::CurrentSession
        | ApprovalLifetime::UntilReboot
        | ApprovalLifetime::Persistent => Err(format!(
            "approval lifetime {lifetime:?} is disabled until grants bind agent, UID, user, and session"
        )),
        ApprovalLifetime::NeverAllow => Err(format!(
            "approval lifetime {lifetime:?} is not supported by Approve; use DenyScoped with never_allow instead"
        )),
    }
}

#[cfg(test)]
fn ensure_supported_deny_lifetime(lifetime: &ApprovalLifetime) -> Result<(), String> {
    match lifetime {
        ApprovalLifetime::NeverAllow => Ok(()),
        ApprovalLifetime::OneCall
        | ApprovalLifetime::CurrentTask
        | ApprovalLifetime::CurrentSession
        | ApprovalLifetime::UntilReboot
        | ApprovalLifetime::Persistent => Err(format!(
            "deny lifetime {lifetime:?} is not supported; supported: never_allow"
        )),
    }
}

#[cfg(any(test, feature = "legacy-plan-execution"))]
fn validate_grant_expiry(
    lifetime: &ApprovalLifetime,
    expires_at_unix_ms: Option<u64>,
) -> Result<(), String> {
    let Some(expires_at_unix_ms) = expires_at_unix_ms else {
        return Ok(());
    };
    if *lifetime == ApprovalLifetime::OneCall {
        return Err(
            "approval expiry requires current_task, current_session, until_reboot, persistent, or never_allow scope"
                .to_string(),
        );
    }
    let now = now_unix_ms();
    if expires_at_unix_ms <= now {
        return Err("approval expiry must be in the future".to_string());
    }
    Ok(())
}

fn current_boot_id() -> Result<String, String> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("failed to read Linux boot id: {error}"))?
        .trim()
        .to_string();
    if boot_id.is_empty() {
        return Err("Linux boot id was empty".to_string());
    }
    Ok(boot_id)
}

fn grant_matches_current_boot(grant: &ApprovalGrant, current_boot_id: Option<&str>) -> bool {
    if grant.lifetime != ApprovalLifetime::UntilReboot {
        return true;
    }
    grant
        .boot_id
        .as_deref()
        .zip(current_boot_id)
        .is_some_and(|(grant_boot_id, current_boot_id)| grant_boot_id == current_boot_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_registration_requires_os_provisioning_and_attestation_is_read_only() {
        let service = AgentService::in_memory().expect("service should initialize");
        let now = now_unix_ms();
        let manifest = AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: "agent-immutable-test".to_string(),
            adapter: "fixture-adapter".to_string(),
            adapter_version: "1".to_string(),
            identity_key_sha256: "a".repeat(64),
            peer_uid: 22001,
            peer_gid: 22002,
            selinux_domain: "u:r:trillionnium_fixture_agent:s0".to_string(),
            network_policy: trillionnium_os_types::AgentNetworkPolicy::Deny,
            enabled: true,
            health: trillionnium_os_types::AgentHealth::Ready,
            registered_at_unix_ms: now,
            updated_at_unix_ms: now,
        };
        assert!(
            service
                .register_agent_local(manifest.clone())
                .unwrap_err()
                .contains("must be OS-provisioned before attestation")
        );
        let registration = service
            .provision_agent_local(manifest)
            .expect("OS provisioning should succeed");
        assert_eq!(
            service.register_agent_local(registration.clone()).unwrap(),
            registration
        );

        let mut replacement = registration.clone();
        replacement.adapter_version = "agent-chosen-version".to_string();
        assert!(
            service
                .register_agent_local(replacement)
                .unwrap_err()
                .contains("does not exactly match the OS-owned manifest")
        );
        assert_eq!(
            service
                .get_agent_local(&registration.agent_id)
                .unwrap()
                .unwrap(),
            registration
        );

        for replacement in [
            AgentRegistration {
                health: trillionnium_os_types::AgentHealth::Degraded,
                ..registration.clone()
            },
            AgentRegistration {
                enabled: false,
                ..registration.clone()
            },
            AgentRegistration {
                peer_gid: registration.peer_gid + 1,
                ..registration.clone()
            },
        ] {
            assert!(
                service
                    .register_agent_local(replacement)
                    .unwrap_err()
                    .contains("does not exactly match the OS-owned manifest")
            );
        }

        let mut alias = registration.clone();
        alias.agent_id = "agent-immutable-alias".to_string();
        assert!(
            service
                .provision_agent_local(alias)
                .unwrap_err()
                .contains("already bound to another agent")
        );
    }

    #[test]
    fn immutable_plan_without_exact_submission_receipt_is_never_executable() {
        let service = AgentService::in_memory().expect("service should initialize");
        let now = now_unix_ms();
        let agent_id = "agent-plan-without-receipt";
        let peer_uid = 22_101;
        let peer_gid = 22_102;
        let peer_domain = "u:r:trillionnium_receipt_test_agent:s0";
        service
            .provision_agent_local(AgentRegistration {
                api_version: AGENT_API_VERSION.to_string(),
                agent_id: agent_id.to_string(),
                adapter: "fixture-adapter".to_string(),
                adapter_version: "1".to_string(),
                identity_key_sha256: "b".repeat(64),
                peer_uid,
                peer_gid,
                selinux_domain: peer_domain.to_string(),
                network_policy: trillionnium_os_types::AgentNetworkPolicy::Deny,
                enabled: true,
                health: trillionnium_os_types::AgentHealth::Ready,
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
            .unwrap();
        let task = service
            .create_task_local(TaskInput {
                title: "receipt-less plan must stay inert".to_string(),
                description: None,
                metadata: json!({
                    "agent_id": agent_id,
                    "agent_peer_uid": peer_uid,
                    "agent_peer_gid": peer_gid,
                    "agent_peer_selinux_domain": peer_domain,
                    "agent_peer_executable_sha256": "c".repeat(64),
                    "subject_user_id": 10,
                    "origin_uid": 1_022_101u32,
                    "origin_selinux_domain": "u:r:trillionnium_aishell:s0"
                }),
            })
            .unwrap();
        let arguments = json!({});
        let manifest = manifest_by_name("system.status").unwrap();
        let plan = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-without-submission-receipt".to_string(),
            task_id: task.id.clone(),
            session_id: "session-without-submission-receipt".to_string(),
            agent_id: agent_id.to_string(),
            intent_sha256: "d".repeat(64),
            provider_output_sha256: "e".repeat(64),
            contexts: Vec::new(),
            actions: vec![trillionnium_os_types::AgentPlannedAction {
                action_id: "action-without-submission-receipt".to_string(),
                tool_name: "system.status".to_string(),
                os_tool_manifest_sha256: Some(sha256_json(
                    &serde_json::to_value(manifest).unwrap(),
                )),
                os_executor_sha256: Some(current_os_executor_sha256().unwrap()),
                arguments: arguments.clone(),
                arguments_sha256: sha256_json(&arguments),
                rationale: "prove missing receipt is fail closed".to_string(),
                requires_approval: false,
                network_scope: "none".to_string(),
                undo_contract: "none".to_string(),
            }],
            created_at_unix_ms: now,
        };
        assert_eq!(
            service
                .lock_audit()
                .unwrap()
                .insert_agent_plan_if_absent(&plan)
                .unwrap(),
            AgentPlanSaveOutcome::Inserted
        );

        let error = service
            .run_agent_planned_action_local(
                agent_id,
                peer_uid,
                peer_gid,
                peer_domain,
                AgentExecutionRequest {
                    task_id: task.id.clone(),
                    plan_id: plan.plan_id,
                    action_id: plan.actions[0].action_id.clone(),
                },
            )
            .expect_err("a plan-only row must never authorize an action");
        assert!(error.contains("lacks its exact durable submission receipt"));
        assert!(
            service
                .list_tool_runs_record(Some(&task.id.0), 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn planned_action_dispatch_uses_frozen_arguments_and_is_single_use() {
        let service = AgentService::in_memory().expect("service should initialize");
        let now = now_unix_ms();
        let agent_id = "agent-planned-dispatch-test";
        let peer_uid = 22002;
        let peer_domain = "u:r:trillionnium_planned_agent:s0";
        service
            .provision_agent_local(AgentRegistration {
                api_version: AGENT_API_VERSION.to_string(),
                agent_id: agent_id.to_string(),
                adapter: "fixture-adapter".to_string(),
                adapter_version: "1".to_string(),
                identity_key_sha256: "c".repeat(64),
                peer_uid,
                peer_gid: peer_uid,
                selinux_domain: peer_domain.to_string(),
                network_policy: trillionnium_os_types::AgentNetworkPolicy::Deny,
                enabled: true,
                health: trillionnium_os_types::AgentHealth::Ready,
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
            .unwrap();
        let task = service
            .create_task_local(TaskInput {
                title: "planned dispatch".to_string(),
                description: None,
                metadata: json!({
                    "agent_id": agent_id,
                    "agent_peer_uid": peer_uid,
                    "agent_peer_gid": peer_uid,
                    "agent_peer_selinux_domain": peer_domain,
                    "agent_peer_executable_sha256": "c".repeat(64),
                    "subject_user_id": 10,
                    "origin_uid": 1_022_002u32,
                    "origin_selinux_domain": "u:r:trillionnium_aishell:s0"
                }),
            })
            .unwrap();
        let arguments = json!({"message": "frozen by the OS"});
        let plan = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-planned-dispatch-test".to_string(),
            task_id: task.id.clone(),
            session_id: "session-planned-dispatch-test".to_string(),
            agent_id: agent_id.to_string(),
            intent_sha256: "d".repeat(64),
            provider_output_sha256: "e".repeat(64),
            contexts: Vec::new(),
            actions: vec![trillionnium_os_types::AgentPlannedAction {
                action_id: "action-planned-dispatch-test".to_string(),
                tool_name: "demo.approval_echo".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments: arguments.clone(),
                arguments_sha256: sha256_json(&arguments),
                rationale: "test frozen plan".to_string(),
                requires_approval: true,
                network_scope: "none".to_string(),
                undo_contract: "none".to_string(),
            }],
            created_at_unix_ms: now,
        };
        let mut approval_drift = plan.clone();
        approval_drift.actions[0].requires_approval = false;
        let error = service
            .submit_agent_plan_local(approval_drift)
            .expect_err("approval preview drift must be rejected before persistence");
        assert!(error.contains("requires_approval"), "{error}");

        let mut network_drift = plan.clone();
        network_drift.actions[0].network_scope = "per_request".to_string();
        let error = service
            .submit_agent_plan_local(network_drift)
            .expect_err("network preview drift must be rejected before persistence");
        assert!(error.contains("network_scope"), "{error}");

        let mut undo_drift = plan.clone();
        undo_drift.actions[0].undo_contract = "agent_claims_reversible".to_string();
        let error = service
            .submit_agent_plan_local(undo_drift)
            .expect_err("undo preview drift must be rejected before persistence");
        assert!(error.contains("undo_contract"), "{error}");

        let mut provider_asserted_manifest = plan.clone();
        provider_asserted_manifest.actions[0].os_tool_manifest_sha256 = Some("a".repeat(64));
        let error = service
            .submit_agent_plan_local(provider_asserted_manifest)
            .expect_err("provider-supplied OS manifest digest must be rejected");
        assert!(
            error.contains("must not supply OS tool manifest digest"),
            "{error}"
        );
        let mut provider_asserted_executor = plan.clone();
        provider_asserted_executor.actions[0].os_executor_sha256 = Some("a".repeat(64));
        let error = service
            .submit_agent_plan_local(provider_asserted_executor)
            .expect_err("provider-supplied OS executor digest must be rejected");
        assert!(
            error.contains("must not supply OS executor digest"),
            "{error}"
        );

        let accepted_plan = service.submit_agent_plan_local(plan.clone()).unwrap();
        let mut substituted = plan.clone();
        substituted.actions[0].arguments = json!({"message": "substituted"});
        substituted.actions[0].arguments_sha256 = sha256_json(&substituted.actions[0].arguments);
        assert!(
            service
                .submit_agent_plan_local(substituted)
                .unwrap_err()
                .contains("immutable agent plan id")
        );
        let frozen_manifest_sha256 = accepted_plan.actions[0]
            .os_tool_manifest_sha256
            .as_deref()
            .expect("OS must freeze the complete manifest before persistence");
        assert_eq!(
            accepted_plan.actions[0].os_executor_sha256.as_deref(),
            Some(current_os_executor_sha256().unwrap().as_str())
        );
        let request = AgentExecutionRequest {
            task_id: task.id.clone(),
            plan_id: plan.plan_id.clone(),
            action_id: plan.actions[0].action_id.clone(),
        };
        let dispatch = service
            .run_agent_planned_action_local(
                agent_id,
                peer_uid,
                peer_uid,
                peer_domain,
                request.clone(),
            )
            .unwrap();
        assert_eq!(dispatch["tool_run"]["arguments"], arguments);
        assert_eq!(dispatch["execution_binding"]["peer_gid"], peer_uid);
        assert_eq!(
            dispatch["execution_binding"]["arguments_sha256"],
            plan.actions[0].arguments_sha256
        );
        assert_eq!(
            dispatch["execution_binding"]["tool_name"],
            plan.actions[0].tool_name
        );
        assert_eq!(
            dispatch["execution_binding"]["accepted_plan_sha256"],
            sha256_json(&serde_json::to_value(&accepted_plan).unwrap())
        );
        let manifest = manifest_by_name(&plan.actions[0].tool_name).unwrap();
        let expected_manifest_sha256 = sha256_json(&serde_json::to_value(manifest).unwrap());
        assert_eq!(frozen_manifest_sha256, expected_manifest_sha256);
        assert_eq!(
            dispatch["execution_binding"]["tool_manifest_sha256"],
            expected_manifest_sha256
        );
        let mut missing_manifest_freeze = accepted_plan.actions[0].clone();
        missing_manifest_freeze.os_tool_manifest_sha256 = None;
        assert!(
            frozen_manifest_for_agent_action(&missing_manifest_freeze)
                .unwrap_err()
                .contains("predates OS tool manifest freezing")
        );
        let mut changed_manifest_freeze = accepted_plan.actions[0].clone();
        changed_manifest_freeze.os_tool_manifest_sha256 = Some("b".repeat(64));
        assert!(
            frozen_manifest_for_agent_action(&changed_manifest_freeze)
                .unwrap_err()
                .contains("manifest changed before execution")
        );
        let mut missing_executor_freeze = accepted_plan.actions[0].clone();
        missing_executor_freeze.os_executor_sha256 = None;
        assert!(
            frozen_manifest_for_agent_action(&missing_executor_freeze)
                .unwrap_err()
                .contains("predates OS executor freezing")
        );
        let mut changed_executor_freeze = accepted_plan.actions[0].clone();
        changed_executor_freeze.os_executor_sha256 = Some("b".repeat(64));
        assert!(
            frozen_manifest_for_agent_action(&changed_executor_freeze)
                .unwrap_err()
                .contains("OS executor changed before execution")
        );
        assert!(dispatch["approval"].is_object());
        assert!(
            service
                .run_agent_planned_action_local(
                    agent_id,
                    peer_uid,
                    peer_uid,
                    peer_domain,
                    request.clone(),
                )
                .unwrap_err()
                .contains("already dispatched")
        );

        let tool_call_id = dispatch["tool_run"]["tool_call_id"]
            .as_str()
            .expect("dispatched tool call id")
            .to_string();
        let approval_id = dispatch["approval"]["id"]
            .as_str()
            .expect("approval id")
            .to_string();
        let mut drifted_run = service
            .load_tool_run(&tool_call_id)
            .unwrap()
            .expect("waiting run must be durable");
        drifted_run
            .agent_execution_binding
            .as_mut()
            .expect("agent run must retain its execution binding")
            .tool_manifest_sha256 = "b".repeat(64);
        service.save_tool_run(&drifted_run).unwrap();
        let (approval, grant, _, _) = service
            .approve_record(approval_id, ApprovalLifetime::CurrentTask, None)
            .unwrap();
        let (resumed, resume_emissions) = service
            .resume_approved_tool_run(&approval, &grant)
            .expect("manifest drift must be represented as a failed run");
        let resumed = resumed.expect("waiting run must remain inspectable");
        assert_eq!(resumed.status, ToolRunStatus::Failed);
        assert!(
            resumed
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("manifest changed after dispatch")
        );
        assert!(!resume_emissions.iter().any(|emission| matches!(
            emission,
            SignalEmission::ToolStarted(_) | SignalEmission::ToolFinished(_)
        )));
        assert!(service.list_approval_grants_record().unwrap().is_empty());
        let retry_error = service.retry_tool_run_record(tool_call_id).unwrap_err();
        assert!(retry_error.contains("denied for terminal task"));

        let mut terminal_plan = plan;
        terminal_plan.plan_id = "plan-terminal-task-denied".to_string();
        terminal_plan.actions[0].action_id = "action-terminal-task-denied".to_string();
        assert!(
            service
                .submit_agent_plan_local(terminal_plan)
                .unwrap_err()
                .contains("denied for terminal task")
        );
        assert!(
            service
                .run_tool_local(
                    &task.id.0,
                    "demo.approval_echo",
                    &json!({"message": "must not dispatch"}),
                )
                .unwrap_err()
                .contains("denied for terminal task")
        );
        assert!(
            service
                .run_agent_planned_action_local(agent_id, peer_uid, peer_uid, peer_domain, request,)
                .unwrap_err()
                .contains("denied for terminal task")
        );
    }

    #[test]
    fn cross_agent_plan_action_and_identifier_substitution_is_fail_closed() {
        let service = AgentService::in_memory().unwrap();
        let now = now_unix_ms();
        let provision = |agent_id: &str, uid: u32, digest_byte: char, domain: &str| {
            service
                .provision_agent_local(AgentRegistration {
                    api_version: AGENT_API_VERSION.to_string(),
                    agent_id: agent_id.to_string(),
                    adapter: "fixture-adapter".to_string(),
                    adapter_version: "1".to_string(),
                    identity_key_sha256: digest_byte.to_string().repeat(64),
                    peer_uid: uid,
                    peer_gid: uid + 1,
                    selinux_domain: domain.to_string(),
                    network_policy: trillionnium_os_types::AgentNetworkPolicy::Deny,
                    enabled: true,
                    health: trillionnium_os_types::AgentHealth::Ready,
                    registered_at_unix_ms: now,
                    updated_at_unix_ms: now,
                })
                .unwrap()
        };
        let codex = provision(
            "agent-codex-collision-test",
            24_001,
            'a',
            "u:r:trillionnium_codex_agent:s0",
        );
        let second_agent = provision(
            "agent-secondary-collision-test",
            24_101,
            'b',
            "u:r:trillionnium_secondary_agent:s0",
        );
        let make_task = |registration: &AgentRegistration, title: &str| {
            service
                .create_task_local(TaskInput {
                    title: title.to_string(),
                    description: None,
                    metadata: json!({
                        "agent_id": registration.agent_id,
                        "agent_peer_uid": registration.peer_uid,
                        "agent_peer_gid": registration.peer_gid,
                        "agent_peer_selinux_domain": registration.selinux_domain,
                        "agent_peer_executable_sha256": registration.identity_key_sha256,
                        "subject_user_id": 0,
                        "origin_uid": 10_123,
                        "origin_selinux_domain": "u:r:trillionnium_aishell:s0"
                    }),
                })
                .unwrap()
        };
        let codex_task = make_task(&codex, "Codex collision owner");
        let arguments = json!({});
        let plan = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-cross-agent-collision".to_string(),
            task_id: codex_task.id.clone(),
            session_id: "session-cross-agent-collision".to_string(),
            agent_id: codex.agent_id.clone(),
            intent_sha256: "c".repeat(64),
            provider_output_sha256: "d".repeat(64),
            contexts: Vec::new(),
            actions: vec![AgentPlannedAction {
                action_id: "action-cross-agent-collision".to_string(),
                tool_name: "system.status".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments_sha256: sha256_json(&arguments),
                arguments,
                rationale: "cross-agent negative fixture".to_string(),
                requires_approval: false,
                network_scope: "none".to_string(),
                undo_contract: "none".to_string(),
            }],
            created_at_unix_ms: now,
        };
        let accepted = service.submit_agent_plan_local(plan).unwrap();
        let request = AgentExecutionRequest {
            task_id: codex_task.id.clone(),
            plan_id: accepted.plan_id.clone(),
            action_id: accepted.actions[0].action_id.clone(),
        };
        let denied = service
            .run_agent_planned_action_local(
                &second_agent.agent_id,
                second_agent.peer_uid,
                second_agent.peer_gid,
                &second_agent.selinux_domain,
                request.clone(),
            )
            .unwrap_err();
        assert!(
            denied.contains("does not match the accepted plan"),
            "{denied}"
        );
        assert!(
            service
                .list_tool_runs_record(Some(&codex_task.id.0), 10)
                .unwrap()
                .is_empty()
        );

        let second_task = make_task(&second_agent, "Second collision owner");
        let mut colliding = accepted.clone();
        colliding.agent_id = second_agent.agent_id.clone();
        colliding.task_id = second_task.id;
        colliding.session_id = "session-secondary-collision".to_string();
        colliding.actions[0].os_tool_manifest_sha256 = None;
        colliding.actions[0].os_executor_sha256 = None;
        let error = service.submit_agent_plan_local(colliding).unwrap_err();
        assert!(error.contains("immutable agent plan"), "{error}");

        let result = service
            .run_agent_planned_action_local(
                &codex.agent_id,
                codex.peer_uid,
                codex.peer_gid,
                &codex.selinux_domain,
                request,
            )
            .unwrap();
        assert_eq!(result["tool_run"]["status"], "succeeded");
        let stored = service
            .get_agent_plan_local(&accepted.plan_id)
            .unwrap()
            .unwrap();
        assert_eq!(stored.agent_id, codex.agent_id);
        assert_eq!(stored.task_id, codex_task.id);
    }

    #[test]
    fn two_action_plan_completes_only_after_both_actions_and_rejects_plan_extension() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-two-action-finish-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let now = now_unix_ms();
        let agent_id = "agent-two-action-test";
        let peer_uid = 22012;
        let peer_domain = "u:r:trillionnium_two_action_agent:s0";
        service
            .provision_agent_local(AgentRegistration {
                api_version: AGENT_API_VERSION.to_string(),
                agent_id: agent_id.to_string(),
                adapter: "fixture-adapter".to_string(),
                adapter_version: "1".to_string(),
                identity_key_sha256: "c".repeat(64),
                peer_uid,
                peer_gid: peer_uid,
                selinux_domain: peer_domain.to_string(),
                network_policy: trillionnium_os_types::AgentNetworkPolicy::Deny,
                enabled: true,
                health: trillionnium_os_types::AgentHealth::Ready,
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
            .unwrap();
        let task = service
            .create_task_local(TaskInput {
                title: "two action aggregation".to_string(),
                description: None,
                metadata: json!({
                    "agent_id": agent_id,
                    "agent_peer_uid": peer_uid,
                    "agent_peer_gid": peer_uid,
                    "agent_peer_selinux_domain": peer_domain,
                    "agent_peer_executable_sha256": "c".repeat(64),
                    "subject_user_id": 10,
                    "origin_uid": 1_022_012u32,
                    "origin_selinux_domain": "u:r:trillionnium_aishell:s0"
                }),
            })
            .unwrap();
        let manifest = manifest_by_name("demo.approval_echo").unwrap();
        let contract = manifest.agent_plan_contract.unwrap();
        let make_action = |action_id: &str| {
            let arguments = json!({"message": action_id});
            trillionnium_os_types::AgentPlannedAction {
                action_id: action_id.to_string(),
                tool_name: "demo.approval_echo".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments_sha256: sha256_json(&arguments),
                arguments,
                rationale: "two-action aggregation test".to_string(),
                requires_approval: contract.requires_approval,
                network_scope: contract.network_scope.clone(),
                undo_contract: contract.undo_contract.clone(),
            }
        };
        let plan = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-two-action-test".to_string(),
            task_id: task.id.clone(),
            session_id: "session-two-action-test".to_string(),
            agent_id: agent_id.to_string(),
            intent_sha256: "d".repeat(64),
            provider_output_sha256: "e".repeat(64),
            contexts: Vec::new(),
            actions: vec![
                make_action("action-two-first"),
                make_action("action-two-second"),
            ],
            created_at_unix_ms: now,
        };
        service.submit_agent_plan_local(plan.clone()).unwrap();

        let mut pre_execution_extension = plan.clone();
        pre_execution_extension.plan_id = "plan-two-action-pre-execution-extension".to_string();
        pre_execution_extension.actions[0].action_id =
            "action-pre-execution-extension-first".to_string();
        pre_execution_extension.actions[1].action_id =
            "action-pre-execution-extension-second".to_string();
        assert!(
            service
                .submit_agent_plan_local(pre_execution_extension)
                .unwrap_err()
                .contains("already has immutable agent plan")
        );

        let out_of_order = service
            .run_agent_planned_action_local(
                agent_id,
                peer_uid,
                peer_uid,
                peer_domain,
                AgentExecutionRequest {
                    task_id: task.id.clone(),
                    plan_id: plan.plan_id.clone(),
                    action_id: "action-two-second".to_string(),
                },
            )
            .unwrap_err();
        assert!(
            out_of_order.contains("before prior action"),
            "{out_of_order}"
        );

        let first = service
            .run_agent_planned_action_local(
                agent_id,
                peer_uid,
                peer_uid,
                peer_domain,
                AgentExecutionRequest {
                    task_id: task.id.clone(),
                    plan_id: plan.plan_id.clone(),
                    action_id: "action-two-first".to_string(),
                },
            )
            .unwrap();
        assert_eq!(first["tool_run"]["status"], "waiting_for_approval");
        let approval_id = first["approval"]["id"].as_str().unwrap().to_string();
        let (approval, grant, _, _) = service
            .approve_record(approval_id, ApprovalLifetime::CurrentTask, None)
            .unwrap();
        let (first_resumed, _) = service.resume_approved_tool_run(&approval, &grant).unwrap();
        assert_eq!(first_resumed.unwrap().status, ToolRunStatus::Succeeded);
        assert_eq!(
            service.get_task_local(&task.id.0).unwrap().unwrap().status,
            TaskStatus::Created
        );

        let mut extension = plan.clone();
        extension.plan_id = "plan-two-action-extension".to_string();
        extension.actions[0].action_id = "action-extension-first".to_string();
        extension.actions[1].action_id = "action-extension-second".to_string();
        assert!(
            service
                .submit_agent_plan_local(extension)
                .unwrap_err()
                .contains("already has immutable agent plan")
        );

        let second = service
            .run_agent_planned_action_local(
                agent_id,
                peer_uid,
                peer_uid,
                peer_domain,
                AgentExecutionRequest {
                    task_id: task.id.clone(),
                    plan_id: plan.plan_id,
                    action_id: "action-two-second".to_string(),
                },
            )
            .unwrap();
        assert_eq!(second["tool_run"]["status"], "succeeded");
        assert_eq!(
            service.get_task_local(&task.id.0).unwrap().unwrap().status,
            TaskStatus::Completed
        );
        assert!(service.list_approval_grants_record().unwrap().is_empty());
        drop(service);
        let reopened = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        assert_eq!(
            reopened.get_task_local(&task.id.0).unwrap().unwrap().status,
            TaskStatus::Completed
        );
        assert!(reopened.list_approval_grants_record().unwrap().is_empty());
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_different_plans_cannot_bind_the_same_task() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-concurrent-service-plan-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let bootstrap = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let now = now_unix_ms();
        let agent_id = "agent-concurrent-plan-test";
        let peer_uid = 22005;
        let peer_domain = "u:r:trillionnium_concurrent_agent:s0";
        bootstrap
            .provision_agent_local(AgentRegistration {
                api_version: AGENT_API_VERSION.to_string(),
                agent_id: agent_id.to_string(),
                adapter: "fixture-adapter".to_string(),
                adapter_version: "1".to_string(),
                identity_key_sha256: "9".repeat(64),
                peer_uid,
                peer_gid: peer_uid,
                selinux_domain: peer_domain.to_string(),
                network_policy: trillionnium_os_types::AgentNetworkPolicy::Deny,
                enabled: true,
                health: trillionnium_os_types::AgentHealth::Ready,
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
            .unwrap();
        let task = bootstrap
            .create_task_local(TaskInput {
                title: "concurrent frozen plan".to_string(),
                description: None,
                metadata: json!({
                    "agent_id": agent_id,
                    "agent_peer_uid": peer_uid,
                    "agent_peer_gid": peer_uid,
                    "agent_peer_selinux_domain": peer_domain,
                    "agent_peer_executable_sha256": "9".repeat(64),
                    "subject_user_id": 13,
                    "origin_uid": 1_322_005u32,
                    "origin_selinux_domain": "u:r:trillionnium_aishell:s0"
                }),
            })
            .unwrap();
        drop(bootstrap);

        let arguments = json!({"message": "immutable"});
        let first = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-concurrent-service-test".to_string(),
            task_id: task.id,
            session_id: "session-concurrent-service-test".to_string(),
            agent_id: agent_id.to_string(),
            intent_sha256: "6".repeat(64),
            provider_output_sha256: "5".repeat(64),
            contexts: Vec::new(),
            actions: vec![trillionnium_os_types::AgentPlannedAction {
                action_id: "action-concurrent-service-test".to_string(),
                tool_name: "demo.approval_echo".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments: arguments.clone(),
                arguments_sha256: sha256_json(&arguments),
                rationale: "concurrency fixture".to_string(),
                requires_approval: true,
                network_scope: "none".to_string(),
                undo_contract: "none".to_string(),
            }],
            created_at_unix_ms: now,
        };
        let mut second = first.clone();
        second.plan_id = "plan-concurrent-service-second".to_string();
        second.actions[0].action_id = "action-concurrent-service-second".to_string();
        second.provider_output_sha256 = "4".repeat(64);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles = [first, second]
            .into_iter()
            .map(|plan| {
                let service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let result = service.submit_agent_plan_local(plan.clone());
                    (plan, result)
                })
            })
            .collect::<Vec<_>>();

        let mut winner = None;
        let mut rejections = Vec::new();
        for handle in handles {
            let (plan, result) = handle.join().expect("plan submitter should not panic");
            match result {
                Ok(saved) => {
                    assert_eq!(saved.plan_id, plan.plan_id);
                    assert_eq!(saved.provider_output_sha256, plan.provider_output_sha256);
                    assert!(saved.actions[0].os_tool_manifest_sha256.is_some());
                    winner = Some(saved);
                }
                Err(error) => {
                    assert!(!error.to_ascii_lowercase().contains("sqlite"), "{error}");
                    assert!(
                        !error.to_ascii_lowercase().contains("database is locked"),
                        "{error}"
                    );
                    rejections.push(error);
                }
            }
        }
        assert_eq!(rejections.len(), 1);
        let winner = winner.expect("one plan should win the insert race");
        let rejection = &rejections[0];
        assert!(
            rejection.contains(&format!(
                "task already has immutable agent plan {}",
                winner.plan_id
            )) || rejection.contains("audit write contention exhausted for plan"),
            "unexpected bounded immutable-plan rejection: {rejection}"
        );
        let reopened = AuditStore::open(&path).unwrap();
        let stored = reopened
            .get_agent_plan(&winner.plan_id)
            .unwrap()
            .expect("winning plan should remain durable");
        assert_eq!(stored, winner);
        assert!(
            reopened
                .has_exact_agent_plan_submission_receipt(&stored)
                .expect("receipt lookup should succeed")
        );
        let receipts = reopened
            .list_events_page_by_kinds(
                Some(&stored.task_id.0),
                None,
                &[AuditEventKind::AgentPlanSubmitted],
                None,
                None,
                10,
            )
            .expect("receipt page should load");
        assert_eq!(receipts.len(), 1);
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn concurrent_new_dispatches_create_only_one_pending_approval() {
        let service = AgentService::in_memory().unwrap();
        let task = service
            .create_task_local(TaskInput {
                title: "single pending dispatch".to_string(),
                ..TaskInput::default()
            })
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles = ["first", "second"]
            .into_iter()
            .map(|message| {
                let service = service.clone();
                let barrier = Arc::clone(&barrier);
                let task_id = task.id.0.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    service.run_tool_local(
                        &task_id,
                        "demo.approval_echo",
                        &json!({"message": message}),
                    )
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("dispatch thread"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .all(|error| error.contains("busy (WaitingForApproval)"),)
        );
        assert_eq!(
            service
                .lock_registry()
                .unwrap()
                .list_approval_requests()
                .into_iter()
                .filter(|approval| {
                    approval.task_id == task.id
                        && approval.status == trillionnium_os_types::ApprovalStatus::Pending
                })
                .count(),
            1
        );
    }

    #[test]
    fn planned_action_binding_survives_restart_and_approval_execution() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-planned-binding-restart-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let now = now_unix_ms();
        let agent_id = "agent-binding-restart-test";
        let peer_uid = 22003;
        let peer_domain = "u:r:trillionnium_restart_agent:s0";
        service
            .provision_agent_local(AgentRegistration {
                api_version: AGENT_API_VERSION.to_string(),
                agent_id: agent_id.to_string(),
                adapter: "fixture-adapter".to_string(),
                adapter_version: "1".to_string(),
                identity_key_sha256: "f".repeat(64),
                peer_uid,
                peer_gid: peer_uid,
                selinux_domain: peer_domain.to_string(),
                network_policy: trillionnium_os_types::AgentNetworkPolicy::Deny,
                enabled: true,
                health: trillionnium_os_types::AgentHealth::Ready,
                registered_at_unix_ms: now,
                updated_at_unix_ms: now,
            })
            .unwrap();
        let task = service
            .create_task_local(TaskInput {
                title: "binding restart".to_string(),
                description: None,
                metadata: json!({
                    "agent_id": agent_id,
                    "agent_peer_uid": peer_uid,
                    "agent_peer_gid": peer_uid,
                    "agent_peer_selinux_domain": peer_domain,
                    "agent_peer_executable_sha256": "f".repeat(64),
                    "subject_user_id": 11,
                    "origin_uid": 1_122_003u32,
                    "origin_selinux_domain": "u:r:trillionnium_aishell:s0"
                }),
            })
            .unwrap();
        let arguments = json!({"message": "execute only after restart approval"});
        let plan = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: "plan-binding-restart-test".to_string(),
            task_id: task.id.clone(),
            session_id: "session-binding-restart-test".to_string(),
            agent_id: agent_id.to_string(),
            intent_sha256: "1".repeat(64),
            provider_output_sha256: "2".repeat(64),
            contexts: Vec::new(),
            actions: vec![trillionnium_os_types::AgentPlannedAction {
                action_id: "action-binding-restart-test".to_string(),
                tool_name: "demo.approval_echo".to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments: arguments.clone(),
                arguments_sha256: sha256_json(&arguments),
                rationale: "restart fixture".to_string(),
                requires_approval: true,
                network_scope: "none".to_string(),
                undo_contract: "none".to_string(),
            }],
            created_at_unix_ms: now,
        };
        service.submit_agent_plan_local(plan.clone()).unwrap();
        let dispatch = service
            .run_agent_planned_action_local(
                agent_id,
                peer_uid,
                peer_uid,
                peer_domain,
                AgentExecutionRequest {
                    task_id: task.id,
                    plan_id: plan.plan_id.clone(),
                    action_id: plan.actions[0].action_id.clone(),
                },
            )
            .unwrap();
        let approval_id = dispatch["approval"]["id"].as_str().unwrap().to_string();
        drop(service);

        let reloaded = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let reloaded_plan = reloaded
            .get_agent_plan_local(&plan.plan_id)
            .unwrap()
            .expect("the exact manifest-consistent plan must survive restart");
        let reloaded_manifest = manifest_by_name(&reloaded_plan.actions[0].tool_name).unwrap();
        let reloaded_manifest_sha256 =
            sha256_json(&serde_json::to_value(&reloaded_manifest).unwrap());
        assert_eq!(
            reloaded_plan.actions[0].os_tool_manifest_sha256.as_deref(),
            Some(reloaded_manifest_sha256.as_str())
        );
        let contract = reloaded_manifest
            .agent_plan_contract
            .expect("built-in manifest must freeze Agent plan semantics");
        assert_eq!(
            reloaded_plan.actions[0].requires_approval,
            contract.requires_approval
        );
        assert_eq!(
            reloaded_plan.actions[0].network_scope,
            contract.network_scope
        );
        assert_eq!(
            reloaded_plan.actions[0].undo_contract,
            contract.undo_contract
        );
        let approved = reloaded.approve_local(&approval_id).unwrap();
        let binding = &approved["tool_run"]["agent_execution_binding"];
        assert_eq!(binding["plan_id"], plan.plan_id);
        assert_eq!(binding["action_id"], plan.actions[0].action_id);
        assert_eq!(binding["tool_name"], plan.actions[0].tool_name);
        assert_eq!(
            binding["accepted_plan_sha256"],
            sha256_json(&serde_json::to_value(&reloaded_plan).unwrap())
        );
        assert_eq!(binding["subject_user_id"], 11);
        assert_eq!(binding["origin_uid"], 1_122_003u32);
        assert_eq!(approved["tool_run"]["status"], "succeeded");
        assert_eq!(
            approved["tool_run"]["output"]["message"],
            arguments["message"]
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn receipt_lookup_is_task_scoped_and_returns_persisted_binding() {
        let service = AgentService::in_memory().unwrap();
        let task_id = TaskId("task-receipt-binding-test".to_string());
        let tool_call_id = ToolCallId("toolcall-receipt-binding-test".to_string());
        let receipt_id = "a".repeat(64);
        let binding = AgentExecutionBinding {
            agent_id: "agent-receipt-binding-test".to_string(),
            peer_uid: 22004,
            peer_gid: 22005,
            peer_selinux_domain: "u:r:trillionnium_receipt_agent:s0".to_string(),
            agent_executable_sha256: "c".repeat(64),
            subject_user_id: 12,
            origin_uid: 1_222_004,
            origin_selinux_domain: "u:r:trillionnium_aishell:s0".to_string(),
            session_id: "session-receipt-binding-test".to_string(),
            task_id: task_id.clone(),
            plan_id: "plan-receipt-binding-test".to_string(),
            action_id: "action-receipt-binding-test".to_string(),
            tool_call_id: tool_call_id.clone(),
            tool_name: "demo.approval_echo".to_string(),
            tool_manifest_sha256: "d".repeat(64),
            accepted_plan_sha256: "e".repeat(64),
            arguments_sha256: "b".repeat(64),
        };
        let mut run = ToolRun::requested(ToolCallInput {
            task_id: task_id.clone(),
            tool_call_id,
            tool_name: "demo.approval_echo".to_string(),
            arguments: json!({"message": "receipt lookup"}),
            agent_execution_binding: Some(binding.clone()),
        });
        run.mark_succeeded(json!({"receipt_id": receipt_id}));
        service.save_tool_run(&run).unwrap();

        let found = service
            .find_tool_run_by_receipt_local(&task_id.0, &receipt_id)
            .unwrap()
            .expect("receipt-bound run");
        assert_eq!(found.agent_execution_binding, Some(binding));
        assert!(
            service
                .find_tool_run_by_receipt_local("task-other", &receipt_id)
                .unwrap()
                .is_none()
        );
        assert!(
            service
                .find_tool_run_by_receipt_local(&task_id.0, &"c".repeat(64))
                .unwrap()
                .is_none()
        );
        assert!(
            service
                .find_tool_run_by_receipt_local(&task_id.0, &"A".repeat(64))
                .is_err()
        );
    }

    #[test]
    fn scoped_lifetime_parsers_keep_approve_and_deny_paths_separate() {
        assert!(parse_approval_lifetime("persistent").is_err());
        assert!(parse_approval_lifetime("current_session").is_err());
        assert!(parse_approval_lifetime("until_reboot").is_err());
        assert_eq!(
            parse_approval_lifetime("current_task").expect("task scope is subject-bound"),
            ApprovalLifetime::CurrentTask
        );
        assert_eq!(
            parse_deny_lifetime("never_allow").expect("negative never-allow scope"),
            ApprovalLifetime::NeverAllow
        );
        assert!(parse_approval_lifetime("never_allow").is_err());
        assert!(parse_deny_lifetime("persistent").is_err());
    }

    #[test]
    fn task_approval_and_audit_surface_round_trip() {
        let service = AgentService::in_memory().expect("service should initialize");

        let (created, _) = service
            .create_task_record(
                r#"{"title":"M1 task","description":"dbus test","metadata":{"source":"unit"}}"#
                    .to_string(),
            )
            .expect("task should create");
        let task_id = created.id.0.clone();

        assert_eq!(service.lock_registry().unwrap().list_task_views().len(), 1);

        let (requested, _, _) = service
            .request_approval_record(format!(
                r#"{{"task_id":"{task_id}","tool_call_id":null,"tool_name":"demo.approval_echo","reason":"unit approval"}}"#
            ))
            .expect("approval should request");
        let (approved, grant, _, _) = service
            .approve_record(requested.id, ApprovalLifetime::OneCall, None)
            .expect("approval should approve");
        assert_eq!(approved.tool_name, "demo.approval_echo");
        assert_eq!(grant.tool_name, "demo.approval_echo");

        let (cancelled, _) = service
            .cancel_task_record(task_id.clone())
            .expect("task should cancel");
        assert_eq!(
            cancelled.status,
            trillionnium_os_types::TaskStatus::Cancelled
        );

        let events = service
            .lock_audit()
            .unwrap()
            .list_events(Some(&task_id), 50)
            .expect("timeline should load");
        assert_eq!(events.len(), 4);
    }

    #[test]
    fn low_risk_tool_executes_and_audits_lifecycle() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"tool task","metadata":{}}"#.to_string())
            .expect("task should create");

        let (response, emissions) = service
            .run_tool_record(
                task.id.0.clone(),
                "system.status".to_string(),
                "{}".to_string(),
            )
            .expect("tool should run");

        assert_eq!(response["ok"], true);
        assert_eq!(response["tool_run"]["status"], "succeeded");
        assert_eq!(response["output"]["ok"], true);
        assert!(
            emissions
                .iter()
                .any(|emission| matches!(emission, SignalEmission::ToolRequested(_)))
        );
        assert!(
            emissions
                .iter()
                .any(|emission| matches!(emission, SignalEmission::ToolFinished(_)))
        );

        let runs = service
            .list_tool_runs_record(Some(&task.id.0), 10)
            .expect("tool runs should load");
        assert_eq!(runs.len(), 1);

        let timeline = service
            .lock_audit()
            .unwrap()
            .list_events(Some(&task.id.0), 50)
            .expect("timeline should load");
        let kinds = timeline
            .iter()
            .map(|event| serde_json::to_value(&event.kind).unwrap())
            .filter_map(|kind| kind.as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert!(kinds.contains(&"tool_requested".to_string()));
        assert!(kinds.contains(&"policy_evaluated".to_string()));
        assert!(kinds.contains(&"tool_started".to_string()));
        assert!(kinds.contains(&"tool_finished".to_string()));

        let filtered = service
            .lock_audit()
            .unwrap()
            .list_events_page_by_kinds(
                None,
                None,
                &[AuditEventKind::ToolRequested, AuditEventKind::ToolFinished],
                None,
                None,
                50,
            )
            .expect("filtered events should load");
        let filtered_kinds = filtered
            .iter()
            .map(|event| serde_json::to_value(&event.kind).unwrap())
            .filter_map(|kind| kind.as_str().map(str::to_string))
            .collect::<Vec<_>>();
        assert_eq!(filtered_kinds.len(), 2);
        assert!(filtered_kinds.contains(&"tool_requested".to_string()));
        assert!(filtered_kinds.contains(&"tool_finished".to_string()));
    }

    #[test]
    fn terminal_failed_tool_run_cannot_be_retried() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"retry task","metadata":{}}"#.to_string())
            .expect("task should create");

        let (failed, _) = service
            .run_tool_record(
                task.id.0.clone(),
                "demo.approval_echo".to_string(),
                "{}".to_string(),
            )
            .expect("tool failure should still return a response");
        assert_eq!(failed["ok"], false);
        assert_eq!(failed["tool_run"]["status"], "failed");
        let tool_call_id = failed["tool_run"]["tool_call_id"]
            .as_str()
            .expect("tool call id")
            .to_string();

        let error = service.retry_tool_run_record(tool_call_id).unwrap_err();
        assert!(error.contains("denied for terminal task"), "{error}");
    }

    #[test]
    fn retry_rejects_non_retryable_waiting_run() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"retry waiting task","metadata":{}}"#.to_string())
            .expect("task should create");
        let (waiting, _) = service
            .run_tool_record(
                task.id.0,
                "demo.approval_echo".to_string(),
                r#"{"message":"needs approval"}"#.to_string(),
            )
            .expect("tool should request approval");
        let tool_call_id = waiting["tool_run"]["tool_call_id"]
            .as_str()
            .expect("tool call id")
            .to_string();

        let error = service
            .retry_tool_run_record(tool_call_id)
            .expect_err("waiting run should not retry");

        assert!(error.contains("retry supports only Failed or ApprovalGrantedAwaitingRetry"));
    }

    #[test]
    fn approval_granted_awaiting_retry_run_can_be_retried() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"approval retry task","metadata":{}}"#.to_string())
            .expect("task should create");
        let mut run = ToolRun::requested(ToolCallInput {
            task_id: task.id,
            tool_call_id: ToolCallId::new(),
            tool_name: "demo.approval_echo".to_string(),
            arguments: json!({}),
            agent_execution_binding: None,
        });
        run.mark_approval_granted_awaiting_retry();
        let tool_call_id = run.tool_call_id.0.clone();
        service.save_tool_run(&run).expect("tool run should save");

        let (retried, emissions) = service
            .retry_tool_run_record(tool_call_id.clone())
            .expect("approval-granted retryable run should retry");

        assert_eq!(retried["ok"], false);
        assert_eq!(retried["tool_run"]["tool_call_id"], tool_call_id);
        assert_eq!(retried["tool_run"]["status"], "failed");
        assert!(
            emissions
                .iter()
                .any(|emission| matches!(emission, SignalEmission::ToolRequested(_)))
        );
    }

    #[test]
    fn medium_risk_demo_tool_waits_for_approval_then_resumes() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"approval tool task","metadata":{}}"#.to_string())
            .expect("task should create");

        let (response, _) = service
            .run_tool_record(
                task.id.0.clone(),
                "demo.approval_echo".to_string(),
                r#"{"message":"approved hello"}"#.to_string(),
            )
            .expect("tool should request approval");
        assert_eq!(response["ok"], true);
        assert_eq!(response["tool_run"]["status"], "waiting_for_approval");
        let approval_id = response["approval"]["id"]
            .as_str()
            .expect("approval id")
            .to_string();

        let (approval, grant, _, _) = service
            .approve_record(approval_id, ApprovalLifetime::OneCall, None)
            .expect("approval should approve");
        let (resumed, emissions) = service
            .resume_approved_tool_run(&approval, &grant)
            .expect("approval should resume tool");
        let resumed = resumed.expect("pending tool should resume");

        assert_eq!(resumed.status, ToolRunStatus::Succeeded);
        assert_eq!(resumed.output.expect("output")["message"], "approved hello");
        assert!(
            emissions
                .iter()
                .any(|emission| matches!(emission, SignalEmission::ToolFinished(_)))
        );
    }

    #[test]
    fn terminal_task_cancels_pending_approval_and_never_resumes_tool() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"cancel pending tool","metadata":{}}"#.to_string())
            .unwrap();
        let (response, _) = service
            .run_tool_record(
                task.id.0.clone(),
                "demo.approval_echo".to_string(),
                r#"{"message":"must never execute"}"#.to_string(),
            )
            .unwrap();
        let approval_id = response["approval"]["id"].as_str().unwrap().to_string();
        let tool_call_id = response["tool_run"]["tool_call_id"]
            .as_str()
            .unwrap()
            .to_string();

        service.cancel_task_record(task.id.0).unwrap();
        let error = service
            .approve_record(approval_id.clone(), ApprovalLifetime::OneCall, None)
            .unwrap_err();
        assert!(
            error.contains("non-pending") || error.contains("terminal"),
            "unexpected approval denial: {error}"
        );
        let approval = service.get_approval_local(&approval_id).unwrap().unwrap();
        assert_eq!(
            approval.status,
            trillionnium_os_types::ApprovalStatus::Denied
        );
        let run = service.load_tool_run(&tool_call_id).unwrap().unwrap();
        assert_eq!(run.status, ToolRunStatus::Failed);
        assert!(run.output.is_none());
        assert!(
            run.error
                .as_deref()
                .unwrap_or_default()
                .contains("cancelled")
        );
    }

    #[test]
    fn cancel_versus_approve_race_stays_terminal_after_fresh_reopen() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-cancel-approve-race-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let bootstrap = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let task = bootstrap
            .create_task_local(TaskInput {
                title: "durable cancel race".to_string(),
                ..TaskInput::default()
            })
            .unwrap();
        let waiting = bootstrap
            .run_tool_local(
                &task.id.0,
                "demo.approval_echo",
                &json!({"message": "must not resurrect"}),
            )
            .unwrap();
        let approval_id = waiting["approval"]["id"].as_str().unwrap().to_string();
        let tool_call_id = waiting["tool_run"]["tool_call_id"]
            .as_str()
            .unwrap()
            .to_string();
        drop(bootstrap);

        let approve_service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let cancel_service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let approve_handle = {
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                let result = approve_service.approve_record(
                    approval_id,
                    ApprovalLifetime::CurrentTask,
                    None,
                );
                (approve_service, result)
            })
        };
        let cancel_handle = {
            let barrier = Arc::clone(&barrier);
            let task_id = task.id.0.clone();
            std::thread::spawn(move || {
                barrier.wait();
                cancel_service.cancel_task_record(task_id)
            })
        };
        let (approve_service, approve_result) = approve_handle.join().expect("approve thread");
        let cancel_result = cancel_handle.join().expect("cancel thread");
        assert!(
            cancel_result.is_ok(),
            "cancel must eventually win: {cancel_result:?}"
        );
        match approve_result {
            Ok((approval, grant, _, _)) => {
                let (resumed, emissions) = approve_service
                    .resume_approved_tool_run(&approval, &grant)
                    .unwrap();
                assert_eq!(resumed.unwrap().status, ToolRunStatus::Failed);
                assert!(
                    !emissions
                        .iter()
                        .any(|emission| matches!(emission, SignalEmission::ToolStarted(_)))
                );
            }
            Err(error) => {
                assert!(
                    error.contains("durable cancellation") || error.contains("non-pending"),
                    "unexpected approval race error: {error}"
                );
                let retry = approve_service.run_tool_local(
                    &task.id.0,
                    "demo.approval_echo",
                    &json!({"message": "stale loser must not execute"}),
                );
                assert!(retry.unwrap_err().contains("terminal task"));
            }
        }
        drop(approve_service);

        let reopened = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        assert_eq!(
            reopened.get_task_local(&task.id.0).unwrap().unwrap().status,
            TaskStatus::Cancelled
        );
        assert!(
            reopened
                .lock_registry()
                .unwrap()
                .list_approval_requests()
                .iter()
                .all(|approval| {
                    approval.task_id != task.id
                        || approval.status != trillionnium_os_types::ApprovalStatus::Pending
                })
        );
        assert!(reopened.list_approval_grants_record().unwrap().is_empty());
        let run = reopened.load_tool_run(&tool_call_id).unwrap().unwrap();
        assert_eq!(run.status, ToolRunStatus::Failed);
        assert!(
            run.error
                .as_deref()
                .unwrap_or_default()
                .contains("cancelled")
        );
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn durable_execution_claim_and_cancel_cannot_both_win_or_resurrect() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-claim-cancel-race-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let bootstrap = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let task = bootstrap
            .create_task_local(TaskInput {
                title: "durable execution claim versus cancel".to_string(),
                ..TaskInput::default()
            })
            .unwrap();
        let run = ToolRun::requested(ToolCallInput {
            task_id: task.id.clone(),
            tool_call_id: ToolCallId("toolcall-claim-cancel-race".to_string()),
            tool_name: "system.status".to_string(),
            arguments: json!({}),
            agent_execution_binding: None,
        });
        bootstrap.save_tool_run(&run).unwrap();
        drop(bootstrap);

        let execute_service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let cancel_service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let execute_handle = {
            let barrier = Arc::clone(&barrier);
            let run = run.clone();
            std::thread::spawn(move || {
                let mut emissions = Vec::new();
                barrier.wait();
                let result = execute_service.execute_allowed_tool_run(
                    run,
                    manifest_by_name("system.status").unwrap(),
                    &mut emissions,
                );
                (execute_service, result, emissions)
            })
        };
        let cancel_handle = {
            let barrier = Arc::clone(&barrier);
            let task_id = task.id.0.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let result = cancel_service.cancel_task_record(task_id);
                (cancel_service, result)
            })
        };
        let (execute_service, execute_result, execute_emissions) =
            execute_handle.join().expect("execute thread");
        let (cancel_service, cancel_result) = cancel_handle.join().expect("cancel thread");
        assert_ne!(execute_result.is_ok(), cancel_result.is_ok());
        assert_eq!(
            execute_emissions
                .iter()
                .filter(|emission| matches!(emission, SignalEmission::ToolStarted(_)))
                .count(),
            usize::from(execute_result.is_ok())
        );

        let stale_service = if execute_result.is_err() {
            execute_service
        } else {
            cancel_service
        };
        let stale_run = stale_service
            .load_tool_run(&run.tool_call_id.0)
            .unwrap()
            .unwrap();
        let mut stale_emissions = Vec::new();
        let stale_result = stale_service.execute_allowed_tool_run(
            stale_run,
            manifest_by_name("system.status").unwrap(),
            &mut stale_emissions,
        );
        assert!(stale_result.is_err());
        assert!(
            !stale_emissions
                .iter()
                .any(|emission| matches!(emission, SignalEmission::ToolStarted(_)))
        );
        drop(stale_service);

        let reopened = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let final_task = reopened.get_task_local(&task.id.0).unwrap().unwrap();
        let final_run = reopened
            .load_tool_run(&run.tool_call_id.0)
            .unwrap()
            .unwrap();
        assert!(matches!(
            (final_task.status, final_run.status),
            (TaskStatus::Cancelled, ToolRunStatus::Failed)
                | (TaskStatus::Completed, ToolRunStatus::Succeeded)
        ));
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn direct_claim_and_approval_request_busy_transition_have_one_winner() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-claim-approval-race-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let bootstrap = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let task = bootstrap
            .create_task_local(TaskInput {
                title: "claim versus approval busy state".to_string(),
                ..TaskInput::default()
            })
            .unwrap();
        let run = ToolRun::requested(ToolCallInput {
            task_id: task.id.clone(),
            tool_call_id: ToolCallId("toolcall-claim-approval-race".to_string()),
            tool_name: "system.status".to_string(),
            arguments: json!({}),
            agent_execution_binding: None,
        });
        bootstrap.save_tool_run(&run).unwrap();
        drop(bootstrap);

        let execute_service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let approval_service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let execute_handle = {
            let barrier = Arc::clone(&barrier);
            let run = run.clone();
            std::thread::spawn(move || {
                let mut emissions = Vec::new();
                barrier.wait();
                let result = execute_service.execute_allowed_tool_run(
                    run,
                    manifest_by_name("system.status").unwrap(),
                    &mut emissions,
                );
                (result, emissions)
            })
        };
        let approval_handle = {
            let barrier = Arc::clone(&barrier);
            let task_id = task.id.0.clone();
            std::thread::spawn(move || {
                barrier.wait();
                approval_service.request_approval_record(
                    serde_json::to_string(&ApprovalSubmission {
                        task_id: TaskId(task_id),
                        tool_call_id: None,
                        tool_name: "demo.approval_echo".to_string(),
                        reason: "competing durable busy transition".to_string(),
                    })
                    .unwrap(),
                )
            })
        };
        let (execute_result, execute_emissions) = execute_handle.join().expect("execute thread");
        let approval_result = approval_handle.join().expect("approval thread");
        assert_ne!(execute_result.is_ok(), approval_result.is_ok());
        assert_eq!(
            execute_emissions
                .iter()
                .filter(|emission| matches!(emission, SignalEmission::ToolStarted(_)))
                .count(),
            usize::from(execute_result.is_ok())
        );

        let reopened = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let final_task = reopened.get_task_local(&task.id.0).unwrap().unwrap();
        let final_run = reopened
            .load_tool_run(&run.tool_call_id.0)
            .unwrap()
            .unwrap();
        assert!(matches!(
            (final_task.status, final_run.status),
            (TaskStatus::WaitingForApproval, ToolRunStatus::Requested)
                | (TaskStatus::Completed, ToolRunStatus::Succeeded)
        ));
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn two_durable_execution_claims_produce_exactly_one_tool_started_receipt() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-double-claim-race-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let bootstrap = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let task = bootstrap
            .create_task_local(TaskInput {
                title: "single durable execution claim".to_string(),
                ..TaskInput::default()
            })
            .unwrap();
        let run = ToolRun::requested(ToolCallInput {
            task_id: task.id.clone(),
            tool_call_id: ToolCallId("toolcall-double-claim-race".to_string()),
            tool_name: "system.status".to_string(),
            arguments: json!({}),
            agent_execution_binding: None,
        });
        bootstrap.save_tool_run(&run).unwrap();
        drop(bootstrap);

        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles = (0..2)
            .map(|_| {
                let service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
                let barrier = Arc::clone(&barrier);
                let run = run.clone();
                std::thread::spawn(move || {
                    let mut emissions = Vec::new();
                    barrier.wait();
                    let result = service.execute_allowed_tool_run(
                        run,
                        manifest_by_name("system.status").unwrap(),
                        &mut emissions,
                    );
                    (service, result, emissions)
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("claim thread"))
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|(_, result, _)| result.is_ok())
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .flat_map(|(_, _, emissions)| emissions)
                .filter(|emission| matches!(emission, SignalEmission::ToolStarted(_)))
                .count(),
            1
        );
        drop(results);

        let reopened = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        assert_eq!(
            reopened.get_task_local(&task.id.0).unwrap().unwrap().status,
            TaskStatus::Completed
        );
        assert_eq!(
            reopened
                .load_tool_run(&run.tool_call_id.0)
                .unwrap()
                .unwrap()
                .status,
            ToolRunStatus::Succeeded
        );
        let tool_started_count = reopened
            .lock_audit()
            .unwrap()
            .list_events(Some(&task.id.0), 100)
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == AuditEventKind::ToolStarted)
            .count();
        assert_eq!(tool_started_count, 1);
        drop(reopened);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn restart_marks_started_without_finish_as_terminal_indeterminate() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-indeterminate-recovery-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let service = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        let task = service
            .create_task_local(TaskInput {
                title: "crash after ToolStarted".to_string(),
                ..TaskInput::default()
            })
            .unwrap();
        service
            .update_task_status(&task.id.0, TaskStatus::Running)
            .unwrap()
            .unwrap();
        let mut run = ToolRun::requested(ToolCallInput {
            task_id: task.id.clone(),
            tool_call_id: ToolCallId("toolcall-indeterminate-recovery".to_string()),
            tool_name: "system.status".to_string(),
            arguments: json!({}),
            agent_execution_binding: None,
        });
        run.mark_running();
        service.save_tool_run(&run).unwrap();
        service
            .lock_audit()
            .unwrap()
            .save_approval_grant(&ApprovalGrant::current_task(
                "system.status",
                task.id.clone(),
            ))
            .unwrap();
        drop(service);

        let secondary = AgentService::from_store(AuditStore::open(&path).unwrap()).unwrap();
        assert_eq!(
            secondary
                .get_task_local(&task.id.0)
                .unwrap()
                .unwrap()
                .status,
            TaskStatus::Running
        );
        assert_eq!(
            secondary
                .load_tool_run(&run.tool_call_id.0)
                .unwrap()
                .unwrap()
                .status,
            ToolRunStatus::Running
        );
        drop(secondary);

        let recovered =
            AgentService::from_store_after_exclusive_startup(AuditStore::open(&path).unwrap())
                .unwrap();
        assert_eq!(
            recovered
                .get_task_local(&task.id.0)
                .unwrap()
                .unwrap()
                .status,
            TaskStatus::Indeterminate
        );
        let recovered_run = recovered
            .load_tool_run(&run.tool_call_id.0)
            .unwrap()
            .unwrap();
        assert_eq!(recovered_run.status, ToolRunStatus::Indeterminate);
        assert!(
            recovered_run
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("automatic replay is forbidden")
        );
        assert!(recovered.list_approval_grants_record().unwrap().is_empty());
        assert!(
            recovered
                .retry_tool_run_record(run.tool_call_id.0.clone())
                .unwrap_err()
                .contains("terminal task")
        );
        assert!(
            recovered
                .cancel_task_record(task.id.0.clone())
                .unwrap_err()
                .contains("cannot be cancelled")
        );
        let events = recovered
            .lock_audit()
            .unwrap()
            .list_events(Some(&task.id.0), 100)
            .unwrap();
        assert!(events.iter().any(|event| {
            event.kind == AuditEventKind::ToolFailed
                && event.payload["indeterminate"] == true
                && event.payload["automatic_replay_forbidden"] == true
        }));
        drop(recovered);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn direct_current_task_grant_is_revoked_when_the_single_call_completes() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"scoped approval task","metadata":{}}"#.to_string())
            .expect("task should create");

        let (response, _) = service
            .run_tool_record(
                task.id.0.clone(),
                "demo.approval_echo".to_string(),
                r#"{"message":"first"}"#.to_string(),
            )
            .expect("tool should request approval");
        let approval_id = response["approval"]["id"]
            .as_str()
            .expect("approval id")
            .to_string();

        let (approval, grant, _, _) = service
            .approve_record(approval_id, ApprovalLifetime::CurrentTask, None)
            .expect("approval should approve");
        assert_eq!(grant.lifetime, ApprovalLifetime::CurrentTask);
        assert_eq!(grant.task_id.as_ref(), Some(&task.id));
        let (resumed, _) = service
            .resume_approved_tool_run(&approval, &grant)
            .expect("approval should resume tool");
        assert_eq!(
            resumed.expect("resumed run").status,
            ToolRunStatus::Succeeded
        );
        assert_eq!(
            service.get_task_local(&task.id.0).unwrap().unwrap().status,
            TaskStatus::Completed
        );
        assert!(service.list_approval_grants_record().unwrap().is_empty());

        let error = service
            .run_tool_record(
                task.id.0,
                "demo.approval_echo".to_string(),
                r#"{"message":"second"}"#.to_string(),
            )
            .unwrap_err();
        assert!(error.contains("denied for terminal task"), "{error}");
    }

    #[test]
    fn current_session_grant_is_rejected_without_subject_binding() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task_one, _) = service
            .create_task_record(r#"{"title":"session grant task one","metadata":{}}"#.to_string())
            .expect("task one should create");
        let (response, _) = service
            .run_tool_record(
                task_one.id.0,
                "demo.approval_echo".to_string(),
                r#"{"message":"first"}"#.to_string(),
            )
            .expect("tool should request approval");
        let approval_id = response["approval"]["id"].as_str().expect("approval id");
        let error = service
            .approve_record(
                approval_id.to_string(),
                ApprovalLifetime::CurrentSession,
                None,
            )
            .unwrap_err();
        assert!(error.contains("disabled until grants bind agent, UID, user, and session"));
    }

    #[test]
    fn direct_current_task_grant_never_survives_task_completion() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"revoke grant task","metadata":{}}"#.to_string())
            .expect("task should create");

        let (response, _) = service
            .run_tool_record(
                task.id.0.clone(),
                "demo.approval_echo".to_string(),
                r#"{"message":"first"}"#.to_string(),
            )
            .expect("tool should request approval");
        let approval_id = response["approval"]["id"].as_str().expect("approval id");
        let (approval, grant, _, _) = service
            .approve_record(approval_id.to_string(), ApprovalLifetime::CurrentTask, None)
            .expect("approval should approve");
        service
            .resume_approved_tool_run(&approval, &grant)
            .expect("approval should resume tool");
        assert!(
            service
                .list_approval_grants_record()
                .expect("grants")
                .is_empty()
        );
        assert_eq!(
            service.get_task_local(&task.id.0).unwrap().unwrap().status,
            TaskStatus::Completed
        );
    }

    #[test]
    fn completed_direct_task_does_not_reload_current_task_grant() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-dbus-grant-roundtrip-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let audit = AuditStore::open(&path).expect("audit store should open");
        let service = AgentService::from_store(audit).expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"grant reload task","metadata":{}}"#.to_string())
            .expect("task should create");
        let (response, _) = service
            .run_tool_record(
                task.id.0.clone(),
                "demo.approval_echo".to_string(),
                r#"{"message":"first"}"#.to_string(),
            )
            .expect("tool should request approval");
        let approval_id = response["approval"]["id"].as_str().expect("approval id");
        let (approval, grant, _, _) = service
            .approve_record(approval_id.to_string(), ApprovalLifetime::CurrentTask, None)
            .expect("approval should approve");
        service
            .resume_approved_tool_run(&approval, &grant)
            .expect("tool should resume");
        drop(service);

        let audit = AuditStore::open(&path).expect("audit store should reopen");
        let reloaded = AgentService::from_store(audit).expect("service should reload");
        assert!(
            reloaded
                .list_approval_grants_record()
                .expect("grants should load")
                .is_empty()
        );
        assert_eq!(
            reloaded.get_task_local(&task.id.0).unwrap().unwrap().status,
            TaskStatus::Completed
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_current_session_grant_is_pruned_on_service_load() {
        let audit = AuditStore::open_memory().expect("audit store should open");
        let grant = ApprovalGrant::current_session("demo.approval_echo");
        audit
            .save_approval_grant(&grant)
            .expect("legacy grant should save");
        let service = AgentService::from_store(audit).expect("service should load");
        assert!(service.list_approval_grants_record().unwrap().is_empty());
    }

    #[test]
    fn legacy_until_reboot_grant_is_pruned_even_on_same_boot() {
        let audit = AuditStore::open_memory().expect("audit store should open");
        let grant = ApprovalGrant::until_reboot(
            "demo.approval_echo",
            current_boot_id().expect("boot id should be readable on Linux"),
        );
        audit
            .save_approval_grant(&grant)
            .expect("legacy grant should save");
        let service = AgentService::from_store(audit).expect("service should load");
        assert!(service.list_approval_grants_record().unwrap().is_empty());
    }

    #[test]
    fn stale_until_reboot_grant_is_pruned_on_service_load() {
        let audit = AuditStore::open_memory().expect("audit store should open");
        let grant = ApprovalGrant::until_reboot("demo.approval_echo", "not-this-boot");
        audit
            .save_approval_grant(&grant)
            .expect("stale grant should save");

        let service = AgentService::from_store(audit).expect("service should initialize");

        assert!(
            service
                .list_approval_grants_record()
                .expect("grants should list")
                .is_empty()
        );
    }

    #[test]
    fn legacy_persistent_positive_grant_is_pruned_on_service_load() {
        let audit = AuditStore::open_memory().expect("audit store should open");
        let grant = ApprovalGrant::persistent("demo.approval_echo");
        audit
            .save_approval_grant(&grant)
            .expect("legacy grant should save");
        let service = AgentService::from_store(audit).expect("service should load");
        assert!(service.list_approval_grants_record().unwrap().is_empty());
    }

    #[test]
    fn never_allow_grant_denies_matching_tool_after_reload() {
        let path = std::env::temp_dir().join(format!(
            "trillionnium-dbus-never-allow-roundtrip-{}-{}.sqlite",
            std::process::id(),
            now_unix_ms()
        ));
        let audit = AuditStore::open(&path).expect("audit store should open");
        let service = AgentService::from_store(audit).expect("service should initialize");
        let (task_one, _) = service
            .create_task_record(r#"{"title":"never allow task one","metadata":{}}"#.to_string())
            .expect("task one should create");
        let (response, _) = service
            .run_tool_record(
                task_one.id.0,
                "demo.approval_echo".to_string(),
                r#"{"message":"first"}"#.to_string(),
            )
            .expect("tool should request approval");
        let approval_id = response["approval"]["id"].as_str().expect("approval id");
        let (_approval, grant, _task, _event) = service
            .deny_with_lifetime_record(
                approval_id.to_string(),
                "not this tool".to_string(),
                Some(ApprovalLifetime::NeverAllow),
                None,
            )
            .expect("deny should create never-allow grant");
        let grant = grant.expect("grant should exist");
        assert_eq!(grant.lifetime, ApprovalLifetime::NeverAllow);
        drop(service);

        let audit = AuditStore::open(&path).expect("audit store should reopen");
        let reloaded = AgentService::from_store(audit).expect("service should reload");
        assert_eq!(
            reloaded
                .list_approval_grants_record()
                .expect("grants should load")
                .len(),
            1
        );
        let (task_two, _) = reloaded
            .create_task_record(r#"{"title":"never allow task two","metadata":{}}"#.to_string())
            .expect("task two should create");
        let (second_response, _) = reloaded
            .run_tool_record(
                task_two.id.0,
                "demo.approval_echo".to_string(),
                r#"{"message":"second"}"#.to_string(),
            )
            .expect("second tool should be denied by never-allow grant");
        assert_eq!(second_response["ok"], false);
        assert_eq!(second_response["approval"], Value::Null);
        assert_eq!(second_response["tool_run"]["status"], "failed");
        assert!(
            second_response["error"]
                .as_str()
                .unwrap_or_default()
                .contains("never-allow")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn current_task_grant_records_expiry() {
        let service = AgentService::in_memory().expect("service should initialize");
        let (task, _) = service
            .create_task_record(r#"{"title":"grant expiry task","metadata":{}}"#.to_string())
            .expect("task should create");
        let (response, _) = service
            .run_tool_record(
                task.id.0,
                "demo.approval_echo".to_string(),
                r#"{"message":"first"}"#.to_string(),
            )
            .expect("tool should request approval");
        let approval_id = response["approval"]["id"].as_str().expect("approval id");
        let expires_at = now_unix_ms() + 60_000;
        let (_, grant, _, _) = service
            .approve_record(
                approval_id.to_string(),
                ApprovalLifetime::CurrentTask,
                Some(expires_at),
            )
            .expect("approval should approve with expiry");

        assert_eq!(grant.expires_at_unix_ms, Some(expires_at));
        assert_eq!(
            service
                .list_approval_grants_record()
                .expect("grants should list")[0]
                .expires_at_unix_ms,
            Some(expires_at)
        );
    }

    #[test]
    fn expired_persisted_grant_is_pruned_on_service_load() {
        let audit = AuditStore::open_memory().expect("audit store should open");
        let grant = ApprovalGrant::current_task(
            "demo.approval_echo",
            TaskId("task-expired-grant".to_string()),
        )
        .with_expires_at(1);
        audit
            .save_approval_grant(&grant)
            .expect("expired grant should save");

        let service = AgentService::from_store(audit).expect("service should initialize");

        assert!(
            service
                .list_approval_grants_record()
                .expect("grants should list")
                .is_empty()
        );
    }
}
