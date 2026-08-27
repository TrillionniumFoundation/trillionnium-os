use std::path::Path;
use std::time::Duration;

use rusqlite::{
    Connection, OptionalExtension, TransactionBehavior, params, params_from_iter,
    types::Value as SqlValue,
};
use thiserror::Error;
use trillionnium_os_types::{
    AgentExecutionBinding, AgentPlanSubmission, AgentRegistration, ApprovalGrant, ApprovalLifetime,
    ApprovalRequest, ApprovalStatus, AuditEvent, AuditEventKind, TaskId, TaskStatus, TaskView,
    ToolCallId, ToolRun, ToolRunStatus,
};

#[derive(Debug, Error)]
pub enum AuditStoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("immutable agent plan id was resubmitted with different content: {plan_id}")]
    ImmutableAgentPlanConflict { plan_id: String },
    #[error("task already has immutable agent plan {existing_plan_id}: {task_id}")]
    ImmutableTaskPlanConflict {
        task_id: String,
        existing_plan_id: String,
    },
    #[error("agent plan submission receipt does not exactly bind immutable plan {plan_id}")]
    InvalidAgentPlanSubmissionReceipt { plan_id: String },
    #[error("audit write contention exhausted for plan {plan_id} on task {task_id}")]
    AgentPlanContentionExhausted {
        plan_id: String,
        task_id: String,
        #[source]
        source: rusqlite::Error,
    },
}

pub type Result<T> = std::result::Result<T, AuditStoreError>;

// rusqlite installs a five-second busy handler by default.  That is short
// enough for an otherwise valid immutable-plan race to leak a raw SQLITE_BUSY
// error while the winning FULL/WAL commit is delayed by a loaded or slow
// filesystem.  Keep the wait finite, but make the production contract
// explicit and long enough for the losing writer to observe the committed row
// and return the semantic immutable-plan conflict instead.
const SQLITE_WRITE_CONTENTION_TIMEOUT: Duration = Duration::from_secs(30);

fn is_sqlite_contention(error: &rusqlite::Error) -> bool {
    matches!(
        error.sqlite_error_code(),
        Some(rusqlite::ffi::ErrorCode::DatabaseBusy)
            | Some(rusqlite::ffi::ErrorCode::DatabaseLocked)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentPlanSaveOutcome {
    Inserted,
    AlreadyPresent,
}

pub struct AuditStore {
    conn: Connection,
}

impl AuditStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut conn = Connection::open(path)?;
        conn.busy_timeout(SQLITE_WRITE_CONTENTION_TIMEOUT)?;
        // Every `unchecked_transaction` in this store inherits IMMEDIATE.
        // Writers therefore acquire SQLite's reserved write lock at BEGIN,
        // before evaluating any compare-and-swap or immutable-plan relation.
        conn.set_transaction_behavior(TransactionBehavior::Immediate);
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory()?;
        conn.busy_timeout(SQLITE_WRITE_CONTENTION_TIMEOUT)?;
        // Keep tests and production on the same BEGIN IMMEDIATE semantics.
        conn.set_transaction_behavior(TransactionBehavior::Immediate);
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn append(&self, event: &AuditEvent) -> Result<()> {
        append_event_on(&self.conn, event)
    }

    pub fn count_events(&self) -> Result<u64> {
        let count: u64 = self
            .conn
            .query_row("select count(*) from audit_events", [], |row| row.get(0))?;
        Ok(count)
    }

    pub fn latest_summary(&self) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare(
            "select summary from audit_events order by created_at_unix_ms desc, rowid desc limit 1",
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn save_task(&self, task: &TaskView) -> Result<()> {
        save_task_on(&self.conn, task)
    }

    pub fn load_tasks(&self) -> Result<Vec<TaskView>> {
        let mut stmt = self.conn.prepare(
            "select id, title, description, status_json, created_at_unix_ms, updated_at_unix_ms, metadata_json
             from tasks
             order by created_at_unix_ms asc, rowid asc",
        )?;
        let mut rows = stmt.query([])?;
        let mut tasks = Vec::new();
        while let Some(row) = rows.next()? {
            tasks.push(row_to_task(row)?);
        }
        Ok(tasks)
    }

    pub fn save_approval(&self, approval: &ApprovalRequest) -> Result<()> {
        save_approval_on(&self.conn, approval)
    }

    pub fn load_approvals(&self) -> Result<Vec<ApprovalRequest>> {
        let mut stmt = self.conn.prepare(
            "select id, task_id, tool_call_id, tool_name, reason, status_json,
                    created_at_unix_ms, decided_at_unix_ms, decision_reason,
                    tool_manifest_sha256
             from approvals
             order by created_at_unix_ms asc, rowid asc",
        )?;
        let mut rows = stmt.query([])?;
        let mut approvals = Vec::new();
        while let Some(row) = rows.next()? {
            approvals.push(row_to_approval(row)?);
        }
        Ok(approvals)
    }

    pub fn save_approval_grant(&self, grant: &ApprovalGrant) -> Result<()> {
        save_approval_grant_on(&self.conn, grant)
    }

    /// Durably publishes the task busy-state, frozen approval request, and
    /// receipt event as one immediate SQLite transaction. The expected task
    /// status is a compare-and-swap guard against a concurrent cancellation.
    pub fn persist_approval_request_atomic(
        &self,
        expected_task_status: &TaskStatus,
        task: &TaskView,
        approval: &ApprovalRequest,
        tool_run: Option<&ToolRun>,
        event: &AuditEvent,
    ) -> Result<bool> {
        let transaction = self.conn.unchecked_transaction()?;
        if !update_task_if_status(&transaction, task, expected_task_status)? {
            return Ok(false);
        }
        save_approval_on(&transaction, approval)?;
        if let Some(tool_run) = tool_run {
            save_tool_run_on(&transaction, tool_run)?;
        }
        append_event_on(&transaction, event)?;
        transaction.commit()?;
        Ok(true)
    }

    /// Atomically commits an approval/denial decision with the task snapshot,
    /// scoped grant (when durable), and its audit receipt. Both old statuses
    /// are checked so a stale decision can never overwrite cancellation.
    pub fn persist_approval_decision_atomic(
        &self,
        expected_task_status: &TaskStatus,
        expected_approval_status: &ApprovalStatus,
        task: &TaskView,
        approval: &ApprovalRequest,
        grant: Option<&ApprovalGrant>,
        event: &AuditEvent,
    ) -> Result<bool> {
        let transaction = self.conn.unchecked_transaction()?;
        if !update_task_if_status(&transaction, task, expected_task_status)? {
            return Ok(false);
        }
        let changed = transaction.execute(
            "update approvals set
                task_id = ?2,
                tool_call_id = ?3,
                tool_name = ?4,
                reason = ?5,
                status_json = ?6,
                decided_at_unix_ms = ?7,
                decision_reason = ?8,
                tool_manifest_sha256 = ?9
             where id = ?1 and status_json = ?10",
            params![
                &approval.id,
                &approval.task_id.0,
                &approval.tool_call_id.0,
                &approval.tool_name,
                &approval.reason,
                serde_json::to_string(&approval.status)?,
                approval.decided_at_unix_ms,
                approval.decision_reason.as_deref(),
                approval.tool_manifest_sha256.as_deref(),
                serde_json::to_string(expected_approval_status)?,
            ],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        if let Some(grant) = grant {
            save_approval_grant_on(&transaction, grant)?;
        }
        append_event_on(&transaction, event)?;
        transaction.commit()?;
        Ok(true)
    }

    /// Cancellation is a failure-first transaction: the terminal task, all
    /// pending approvals, all not-yet-running tool runs, task grants, and the
    /// cancellation receipt become visible together or not at all.
    pub fn persist_task_cancellation_atomic(
        &self,
        task: &TaskView,
        reason: &str,
        event: &AuditEvent,
    ) -> Result<bool> {
        let transaction = self.conn.unchecked_transaction()?;
        let changed = transaction.execute(
            "update tasks set
                title = ?2,
                description = ?3,
                status_json = ?4,
                updated_at_unix_ms = ?5,
                metadata_json = ?6
             where id = ?1 and status_json in (?7, ?8)",
            params![
                &task.id.0,
                &task.title,
                task.description.as_deref(),
                serde_json::to_string(&task.status)?,
                task.updated_at_unix_ms,
                serde_json::to_string(&task.metadata)?,
                serde_json::to_string(&TaskStatus::Created)?,
                serde_json::to_string(&TaskStatus::WaitingForApproval)?,
            ],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        let now = event.created_at_unix_ms;
        transaction.execute(
            "update approvals set
                status_json = ?2,
                decided_at_unix_ms = ?3,
                decision_reason = ?4
             where task_id = ?1 and status_json = ?5",
            params![
                &task.id.0,
                serde_json::to_string(&ApprovalStatus::Denied)?,
                now,
                reason,
                serde_json::to_string(&ApprovalStatus::Pending)?,
            ],
        )?;
        transaction.execute(
            "update tool_runs set
                status_json = ?2,
                finished_at_unix_ms = ?3,
                output_json = null,
                error = ?4
             where task_id = ?1 and status_json in (?5, ?6, ?7)",
            params![
                &task.id.0,
                serde_json::to_string(&ToolRunStatus::Failed)?,
                now,
                reason,
                serde_json::to_string(&ToolRunStatus::Requested)?,
                serde_json::to_string(&ToolRunStatus::WaitingForApproval)?,
                serde_json::to_string(&ToolRunStatus::ApprovalGrantedAwaitingRetry)?,
            ],
        )?;
        transaction.execute(
            "delete from approval_grants where task_id = ?1",
            params![&task.id.0],
        )?;
        append_event_on(&transaction, event)?;
        transaction.commit()?;
        Ok(true)
    }

    /// Atomically acquires the durable side-effect lease. Both the task and
    /// tool-run rows are compare-and-swapped before ToolStarted is published;
    /// callers must not execute the tool unless this transaction commits.
    pub fn persist_tool_execution_claim_atomic(
        &self,
        task: &TaskView,
        run: &ToolRun,
        expected_run_status: &ToolRunStatus,
        event: &AuditEvent,
    ) -> Result<bool> {
        let expected_task_status = match expected_run_status {
            ToolRunStatus::Requested => TaskStatus::Created,
            ToolRunStatus::WaitingForApproval | ToolRunStatus::ApprovalGrantedAwaitingRetry => {
                TaskStatus::WaitingForApproval
            }
            _ => return Ok(false),
        };
        let transaction = self.conn.unchecked_transaction()?;
        let task_changed = transaction.execute(
            "update tasks set
                title = ?2,
                description = ?3,
                status_json = ?4,
                updated_at_unix_ms = ?5,
                metadata_json = ?6
             where id = ?1 and status_json = ?7",
            params![
                &task.id.0,
                &task.title,
                task.description.as_deref(),
                serde_json::to_string(&task.status)?,
                task.updated_at_unix_ms,
                serde_json::to_string(&task.metadata)?,
                serde_json::to_string(&expected_task_status)?,
            ],
        )?;
        if task_changed != 1 {
            return Ok(false);
        }
        let arguments_json = serde_json::to_string(&run.arguments)?;
        let binding_json = run
            .agent_execution_binding
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let run_changed = transaction.execute(
            "update tool_runs set
                status_json = ?6,
                requested_at_unix_ms = ?7,
                started_at_unix_ms = ?8,
                finished_at_unix_ms = ?9,
                output_json = ?10,
                error = ?11,
                approval_id = ?12,
                policy_decision_json = ?13,
                agent_execution_binding_json = ?14
             where tool_call_id = ?1
               and task_id = ?2
               and tool_name = ?3
               and arguments_json = ?4
               and agent_execution_binding_json is ?5
               and status_json = ?15",
            params![
                &run.tool_call_id.0,
                &run.task_id.0,
                &run.tool_name,
                &arguments_json,
                binding_json.as_deref(),
                serde_json::to_string(&run.status)?,
                run.requested_at_unix_ms,
                run.started_at_unix_ms,
                run.finished_at_unix_ms,
                run.output.as_ref().map(serde_json::to_string).transpose()?,
                run.error.as_deref(),
                run.approval_id.as_deref(),
                run.policy_decision
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                binding_json.as_deref(),
                serde_json::to_string(expected_run_status)?,
            ],
        )?;
        if run_changed != 1 {
            return Ok(false);
        }
        if matches!(
            expected_run_status,
            ToolRunStatus::WaitingForApproval | ToolRunStatus::ApprovalGrantedAwaitingRetry
        ) {
            let Some(approval_id) = run.approval_id.as_deref() else {
                return Ok(false);
            };
            let approved_count: u64 = transaction.query_row(
                "select count(*) from approvals
                 where id = ?1
                   and task_id = ?2
                   and tool_call_id = ?3
                   and tool_name = ?4
                   and status_json = ?5",
                params![
                    approval_id,
                    &run.task_id.0,
                    &run.tool_call_id.0,
                    &run.tool_name,
                    serde_json::to_string(&ApprovalStatus::Approved)?,
                ],
                |row| row.get(0),
            )?;
            if approved_count != 1 {
                return Ok(false);
            }
        }
        append_event_on(&transaction, event)?;
        transaction.commit()?;
        Ok(true)
    }

    /// Atomically publishes the durable outcome for an already claimed tool.
    /// A final run can only replace Running while its task is also Running.
    /// Terminal cleanup and the finish/failure receipt share the transaction.
    pub fn persist_tool_execution_finish_atomic(
        &self,
        task: &TaskView,
        run: &ToolRun,
        event: &AuditEvent,
    ) -> Result<bool> {
        if !matches!(
            run.status,
            ToolRunStatus::Succeeded | ToolRunStatus::Failed | ToolRunStatus::Indeterminate
        ) || !matches!(
            task.status,
            TaskStatus::Created
                | TaskStatus::Completed
                | TaskStatus::Failed
                | TaskStatus::Indeterminate
        ) {
            return Ok(false);
        }
        let transaction = self.conn.unchecked_transaction()?;
        if !update_task_if_status(&transaction, task, &TaskStatus::Running)? {
            return Ok(false);
        }
        let arguments_json = serde_json::to_string(&run.arguments)?;
        let binding_json = run
            .agent_execution_binding
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let run_changed = transaction.execute(
            "update tool_runs set
                status_json = ?6,
                requested_at_unix_ms = ?7,
                started_at_unix_ms = ?8,
                finished_at_unix_ms = ?9,
                output_json = ?10,
                error = ?11,
                approval_id = ?12,
                policy_decision_json = ?13,
                agent_execution_binding_json = ?14
             where tool_call_id = ?1
               and task_id = ?2
               and tool_name = ?3
               and arguments_json = ?4
               and agent_execution_binding_json is ?5
               and status_json = ?15",
            params![
                &run.tool_call_id.0,
                &run.task_id.0,
                &run.tool_name,
                &arguments_json,
                binding_json.as_deref(),
                serde_json::to_string(&run.status)?,
                run.requested_at_unix_ms,
                run.started_at_unix_ms,
                run.finished_at_unix_ms,
                run.output.as_ref().map(serde_json::to_string).transpose()?,
                run.error.as_deref(),
                run.approval_id.as_deref(),
                run.policy_decision
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                binding_json.as_deref(),
                serde_json::to_string(&ToolRunStatus::Running)?,
            ],
        )?;
        if run_changed != 1 {
            return Ok(false);
        }
        if matches!(
            task.status,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Indeterminate
        ) {
            let reason = format!("task entered {:?} after durable tool finish", task.status);
            transaction.execute(
                "update approvals set
                    status_json = ?2,
                    decided_at_unix_ms = ?3,
                    decision_reason = ?4
                 where task_id = ?1 and status_json = ?5",
                params![
                    &task.id.0,
                    serde_json::to_string(&ApprovalStatus::Denied)?,
                    event.created_at_unix_ms,
                    reason,
                    serde_json::to_string(&ApprovalStatus::Pending)?,
                ],
            )?;
            transaction.execute(
                "delete from approval_grants where task_id = ?1",
                params![&task.id.0],
            )?;
        }
        append_event_on(&transaction, event)?;
        transaction.commit()?;
        Ok(true)
    }

    /// On daemon startup, a durable Running/ToolStarted pair without a finish
    /// receipt is explicitly terminal and indeterminate. It must never be
    /// treated as safe to replay automatically.
    pub fn recover_inflight_as_indeterminate(&self) -> Result<u64> {
        let transaction = self.conn.unchecked_transaction()?;
        let mut statement = transaction.prepare(
            "select tool_call_id, task_id, tool_name, arguments_json, status_json,
                    requested_at_unix_ms, started_at_unix_ms, finished_at_unix_ms,
                    output_json, error, approval_id, policy_decision_json,
                    agent_execution_binding_json
             from tool_runs where status_json = ?1
             order by requested_at_unix_ms asc, rowid asc",
        )?;
        let mut rows = statement.query(params![serde_json::to_string(&ToolRunStatus::Running)?])?;
        let mut inflight = Vec::new();
        while let Some(row) = rows.next()? {
            inflight.push(row_to_tool_run(row)?);
        }
        drop(rows);
        drop(statement);

        let now = trillionnium_os_types::now_unix_ms();
        for mut run in inflight.iter().cloned() {
            run.status = ToolRunStatus::Indeterminate;
            run.finished_at_unix_ms = Some(now);
            run.output = None;
            run.error = Some(
                "daemon restarted after durable ToolStarted without a durable finish receipt; external effect may have occurred and automatic replay is forbidden"
                    .to_string(),
            );
            save_tool_run_on(&transaction, &run)?;
            transaction.execute(
                "update tasks set status_json = ?2, updated_at_unix_ms = ?3
                 where id = ?1 and status_json = ?4",
                params![
                    &run.task_id.0,
                    serde_json::to_string(&TaskStatus::Indeterminate)?,
                    now,
                    serde_json::to_string(&TaskStatus::Running)?,
                ],
            )?;
            transaction.execute(
                "update approvals set
                    status_json = ?2,
                    decided_at_unix_ms = ?3,
                    decision_reason = ?4
                 where task_id = ?1 and status_json = ?5",
                params![
                    &run.task_id.0,
                    serde_json::to_string(&ApprovalStatus::Denied)?,
                    now,
                    "task outcome became indeterminate after daemon restart",
                    serde_json::to_string(&ApprovalStatus::Pending)?,
                ],
            )?;
            transaction.execute(
                "delete from approval_grants where task_id = ?1",
                params![&run.task_id.0],
            )?;
            let event = AuditEvent::new(
                AuditEventKind::ToolFailed,
                format!(
                    "tool outcome indeterminate after daemon restart: {}",
                    run.tool_name
                ),
            )
            .with_task(run.task_id.clone())
            .with_tool_call(run.tool_call_id.clone())
            .with_payload(serde_json::json!({
                "tool_run": run,
                "indeterminate": true,
                "automatic_replay_forbidden": true
            }));
            append_event_on(&transaction, &event)?;
        }
        transaction.commit()?;
        Ok(inflight.len().try_into().unwrap_or(u64::MAX))
    }

    pub fn load_approval_grants(&self) -> Result<Vec<ApprovalGrant>> {
        let mut stmt = self.conn.prepare(
            "select id, tool_name, tool_call_id, task_id, lifetime_json,
                    created_at_unix_ms, expires_at_unix_ms, boot_id,
                    tool_manifest_sha256, agent_subject_sha256, os_executor_sha256
             from approval_grants
             order by created_at_unix_ms asc, rowid asc",
        )?;
        let mut rows = stmt.query([])?;
        let mut grants = Vec::new();
        while let Some(row) = rows.next()? {
            grants.push(row_to_approval_grant(row)?);
        }
        Ok(grants)
    }

    pub fn delete_approval_grant(&self, grant_id: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "delete from approval_grants where id = ?1",
            params![grant_id],
        )?;
        Ok(changed > 0)
    }

    pub fn save_tool_run(&self, run: &ToolRun) -> Result<()> {
        save_tool_run_on(&self.conn, run)
    }

    pub fn insert_tool_run_if_absent(&self, run: &ToolRun) -> Result<bool> {
        let changed = self.conn.execute(
            "insert or ignore into tool_runs (
                tool_call_id, task_id, tool_name, arguments_json, status_json,
                requested_at_unix_ms, started_at_unix_ms, finished_at_unix_ms,
                output_json, error, approval_id, policy_decision_json,
                agent_execution_binding_json
            ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                &run.tool_call_id.0,
                &run.task_id.0,
                &run.tool_name,
                serde_json::to_string(&run.arguments)?,
                serde_json::to_string(&run.status)?,
                run.requested_at_unix_ms,
                run.started_at_unix_ms,
                run.finished_at_unix_ms,
                run.output.as_ref().map(serde_json::to_string).transpose()?,
                run.error.as_deref(),
                run.approval_id.as_deref(),
                run.policy_decision
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
                run.agent_execution_binding
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn save_agent_registration(&self, registration: &AgentRegistration) -> Result<()> {
        self.conn.execute(
            "insert into agent_registrations (agent_id, registration_json, updated_at_unix_ms)
             values (?1, ?2, ?3)
             on conflict(agent_id) do update set
                 registration_json = excluded.registration_json,
                 updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                &registration.agent_id,
                serde_json::to_string(registration)?,
                registration.updated_at_unix_ms,
            ],
        )?;
        Ok(())
    }

    pub fn load_agent_registrations(&self) -> Result<Vec<AgentRegistration>> {
        let mut stmt = self.conn.prepare(
            "select registration_json from agent_registrations
             order by agent_id asc",
        )?;
        let mut rows = stmt.query([])?;
        let mut registrations = Vec::new();
        while let Some(row) = rows.next()? {
            let encoded: String = row.get(0)?;
            registrations.push(serde_json::from_str(&encoded)?);
        }
        Ok(registrations)
    }

    pub fn get_agent_registration(&self, agent_id: &str) -> Result<Option<AgentRegistration>> {
        let encoded: Option<String> = self
            .conn
            .query_row(
                "select registration_json from agent_registrations where agent_id = ?1 limit 1",
                params![agent_id],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(Into::into)
    }

    pub fn save_agent_plan(&self, plan: &AgentPlanSubmission) -> Result<()> {
        self.insert_agent_plan_if_absent(plan).map(|_| ())
    }

    pub fn insert_agent_plan_if_absent(
        &self,
        plan: &AgentPlanSubmission,
    ) -> Result<AgentPlanSaveOutcome> {
        let transaction = self.conn.unchecked_transaction()?;
        let outcome = insert_agent_plan_if_absent_on(&transaction, plan)?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Atomically publishes an immutable Agent plan and the exact receipt that
    /// authorizes later plan-to-action execution. The plan is never visible
    /// without its receipt, including when receipt insertion fails or the
    /// process terminates before SQLite commits the immediate transaction.
    pub fn persist_agent_plan_submission_atomic(
        &self,
        plan: &AgentPlanSubmission,
        event: &AuditEvent,
    ) -> Result<AgentPlanSaveOutcome> {
        validate_agent_plan_submission_receipt(plan, event)?;
        let mut last_contention = None;
        for attempt in 0..=1 {
            match self.persist_agent_plan_submission_once(plan, event) {
                Ok(outcome) => return Ok(outcome),
                Err(AuditStoreError::Sqlite(source)) if is_sqlite_contention(&source) => {
                    last_contention = Some(source);
                    match self.reconcile_agent_plan_submission(plan) {
                        Ok(Some(outcome)) => return Ok(outcome),
                        Ok(None) => {}
                        Err(AuditStoreError::Sqlite(source)) if is_sqlite_contention(&source) => {
                            last_contention = Some(source);
                        }
                        Err(error) => return Err(error),
                    }
                    if attempt == 0 {
                        continue;
                    }
                }
                Err(error) => return Err(error),
            }
            break;
        }
        Err(AuditStoreError::AgentPlanContentionExhausted {
            plan_id: plan.plan_id.clone(),
            task_id: plan.task_id.0.clone(),
            source: last_contention.expect("contention source must exist after bounded retry"),
        })
    }

    fn persist_agent_plan_submission_once(
        &self,
        plan: &AgentPlanSubmission,
        event: &AuditEvent,
    ) -> Result<AgentPlanSaveOutcome> {
        let transaction = self.conn.unchecked_transaction()?;
        let outcome = insert_agent_plan_if_absent_on(&transaction, plan)?;
        if outcome == AgentPlanSaveOutcome::Inserted {
            append_event_on(&transaction, event)?;
        }
        transaction.commit()?;
        Ok(outcome)
    }

    fn reconcile_agent_plan_submission(
        &self,
        plan: &AgentPlanSubmission,
    ) -> Result<Option<AgentPlanSaveOutcome>> {
        if let Some(stored) = self.get_agent_plan(&plan.plan_id)? {
            if stored != *plan {
                return Err(AuditStoreError::ImmutableAgentPlanConflict {
                    plan_id: plan.plan_id.clone(),
                });
            }
            self.require_one_exact_agent_plan_submission_receipt(&stored)?;
            return Ok(Some(AgentPlanSaveOutcome::AlreadyPresent));
        }
        if let Some(existing) = self.get_agent_plan_for_task(&plan.task_id.0)? {
            return Err(AuditStoreError::ImmutableTaskPlanConflict {
                task_id: plan.task_id.0.clone(),
                existing_plan_id: existing.plan_id,
            });
        }
        Ok(None)
    }

    fn require_one_exact_agent_plan_submission_receipt(
        &self,
        plan: &AgentPlanSubmission,
    ) -> Result<()> {
        let mut statement = self.conn.prepare(
            "select id, kind, task_id, tool_call_id, summary, payload_json, created_at_unix_ms
             from audit_events
             where kind = ?1 and task_id = ?2
             order by created_at_unix_ms asc, rowid asc",
        )?;
        let mut rows = statement.query(params![
            serde_json::to_string(&AuditEventKind::AgentPlanSubmitted)?,
            &plan.task_id.0,
        ])?;
        let mut exact_receipts = 0usize;
        while let Some(row) = rows.next()? {
            let event = match row_to_event(row) {
                Ok(event) => event,
                Err(AuditStoreError::Json(_)) => {
                    return Err(AuditStoreError::InvalidAgentPlanSubmissionReceipt {
                        plan_id: plan.plan_id.clone(),
                    });
                }
                Err(error) => return Err(error),
            };
            if validate_agent_plan_submission_receipt(plan, &event).is_err() {
                return Err(AuditStoreError::InvalidAgentPlanSubmissionReceipt {
                    plan_id: plan.plan_id.clone(),
                });
            }
            exact_receipts += 1;
        }
        if exact_receipts != 1 {
            return Err(AuditStoreError::InvalidAgentPlanSubmissionReceipt {
                plan_id: plan.plan_id.clone(),
            });
        }
        Ok(())
    }

    /// Returns true only when the audit store contains an exact immutable
    /// `AgentPlanSubmitted` receipt for this plan. This makes legacy or
    /// externally-corrupted plan-only rows non-executable even though they
    /// remain readable for custody/forensics.
    pub fn has_exact_agent_plan_submission_receipt(
        &self,
        plan: &AgentPlanSubmission,
    ) -> Result<bool> {
        match self.require_one_exact_agent_plan_submission_receipt(plan) {
            Ok(()) => Ok(true),
            Err(AuditStoreError::InvalidAgentPlanSubmissionReceipt { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn get_agent_plan(&self, plan_id: &str) -> Result<Option<AgentPlanSubmission>> {
        let encoded: Option<String> = self
            .conn
            .query_row(
                "select plan_json from agent_plans where plan_id = ?1 limit 1",
                params![plan_id],
                |row| row.get(0),
            )
            .optional()?;
        encoded
            .map(|value| serde_json::from_str(&value))
            .transpose()
            .map_err(Into::into)
    }

    pub fn get_agent_plan_for_task(&self, task_id: &str) -> Result<Option<AgentPlanSubmission>> {
        let plan_json = self
            .conn
            .query_row(
                "select plan_json from agent_plans
                 where task_id = ?1
                 order by created_at_unix_ms asc, rowid asc
                 limit 1",
                params![task_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        plan_json
            .map(|value| serde_json::from_str(&value).map_err(AuditStoreError::from))
            .transpose()
    }

    pub fn load_tool_run(&self, tool_call_id: &str) -> Result<Option<ToolRun>> {
        let mut stmt = self.conn.prepare(
            "select tool_call_id, task_id, tool_name, arguments_json, status_json,
                    requested_at_unix_ms, started_at_unix_ms, finished_at_unix_ms,
                    output_json, error, approval_id, policy_decision_json
                    , agent_execution_binding_json
             from tool_runs
             where tool_call_id = ?1
             limit 1",
        )?;
        let mut rows = stmt.query(params![tool_call_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_tool_run(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn find_succeeded_tool_run_by_receipt(
        &self,
        task_id: &str,
        receipt_id: &str,
    ) -> Result<Option<ToolRun>> {
        let mut stmt = self.conn.prepare(
            "select tool_call_id, task_id, tool_name, arguments_json, status_json,
                    requested_at_unix_ms, started_at_unix_ms, finished_at_unix_ms,
                    output_json, error, approval_id, policy_decision_json,
                    agent_execution_binding_json
             from tool_runs
             where task_id = ?1
               and status_json = ?2
               and json_extract(output_json, '$.receipt_id') = ?3
             order by finished_at_unix_ms desc, rowid desc
             limit 1",
        )?;
        let mut rows = stmt.query(params![
            task_id,
            serde_json::to_string(&ToolRunStatus::Succeeded)?,
            receipt_id
        ])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_tool_run(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn list_tool_runs(&self, task_id: Option<&str>, limit: u32) -> Result<Vec<ToolRun>> {
        let limit = limit.clamp(1, 500);
        let limit_i64 = i64::from(limit);
        let mut runs = Vec::new();
        if let Some(task_id) = task_id {
            let mut stmt = self.conn.prepare(
                "select tool_call_id, task_id, tool_name, arguments_json, status_json,
                        requested_at_unix_ms, started_at_unix_ms, finished_at_unix_ms,
                        output_json, error, approval_id, policy_decision_json
                        , agent_execution_binding_json
                 from tool_runs
                 where task_id = ?1
                 order by requested_at_unix_ms asc, rowid asc
                 limit ?2",
            )?;
            let mut rows = stmt.query(params![task_id, limit_i64])?;
            while let Some(row) = rows.next()? {
                runs.push(row_to_tool_run(row)?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "select tool_call_id, task_id, tool_name, arguments_json, status_json,
                        requested_at_unix_ms, started_at_unix_ms, finished_at_unix_ms,
                        output_json, error, approval_id, policy_decision_json
                        , agent_execution_binding_json
                 from tool_runs
                 order by requested_at_unix_ms asc, rowid asc
                 limit ?1",
            )?;
            let mut rows = stmt.query(params![limit_i64])?;
            while let Some(row) = rows.next()? {
                runs.push(row_to_tool_run(row)?);
            }
        }
        Ok(runs)
    }

    pub fn list_events(&self, task_id: Option<&str>, limit: u32) -> Result<Vec<AuditEvent>> {
        let limit = limit.clamp(1, 500);
        let limit_i64 = i64::from(limit);
        let mut events = Vec::new();
        if let Some(task_id) = task_id {
            let mut stmt = self.conn.prepare(
                "select id, kind, task_id, tool_call_id, summary, payload_json, created_at_unix_ms
                 from audit_events
                 where task_id = ?1
                 order by created_at_unix_ms desc, rowid desc
                 limit ?2",
            )?;
            let mut rows = stmt.query(params![task_id, limit_i64])?;
            while let Some(row) = rows.next()? {
                events.push(row_to_event(row)?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "select id, kind, task_id, tool_call_id, summary, payload_json, created_at_unix_ms
                 from audit_events
                 order by created_at_unix_ms desc, rowid desc
                 limit ?1",
            )?;
            let mut rows = stmt.query(params![limit_i64])?;
            while let Some(row) = rows.next()? {
                events.push(row_to_event(row)?);
            }
        }
        events.reverse();
        Ok(events)
    }

    pub fn load_event(&self, event_id: &str) -> Result<Option<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "select id, kind, task_id, tool_call_id, summary, payload_json, created_at_unix_ms
             from audit_events
             where id = ?1
             limit 1",
        )?;
        let mut rows = stmt.query(params![event_id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_event(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn list_events_page(
        &self,
        task_id: Option<&str>,
        tool_call_id: Option<&str>,
        kind: Option<AuditEventKind>,
        before_id: Option<&str>,
        after_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditEvent>> {
        let kinds = kind.into_iter().collect::<Vec<_>>();
        self.list_events_page_by_kinds(task_id, tool_call_id, &kinds, before_id, after_id, limit)
    }

    pub fn list_events_page_by_kinds(
        &self,
        task_id: Option<&str>,
        tool_call_id: Option<&str>,
        kinds: &[AuditEventKind],
        before_id: Option<&str>,
        after_id: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AuditEvent>> {
        let limit = limit.clamp(1, 5000);
        let cursor = match (before_id, after_id) {
            (Some(_), Some(_)) => None,
            (Some(event_id), None) | (None, Some(event_id)) => self.cursor_for_event(event_id)?,
            (None, None) => None,
        };
        if before_id.is_some() || after_id.is_some() {
            let Some(_) = cursor else {
                return Ok(Vec::new());
            };
        }

        let mut where_parts = Vec::<String>::new();
        let mut params = Vec::<SqlValue>::new();
        if let Some(task_id) = task_id {
            where_parts.push("task_id = ?".to_string());
            params.push(SqlValue::Text(task_id.to_string()));
        }
        if let Some(tool_call_id) = tool_call_id {
            where_parts.push("tool_call_id = ?".to_string());
            params.push(SqlValue::Text(tool_call_id.to_string()));
        }
        if !kinds.is_empty() {
            let placeholders = std::iter::repeat_n("?", kinds.len())
                .collect::<Vec<_>>()
                .join(", ");
            where_parts.push(format!("kind in ({placeholders})"));
            for kind in kinds {
                params.push(SqlValue::Text(serde_json::to_string(kind)?));
            }
        }
        if let Some((cursor_created_at, cursor_rowid)) = cursor {
            if before_id.is_some() {
                where_parts.push(
                    "(created_at_unix_ms < ? or (created_at_unix_ms = ? and rowid < ?))"
                        .to_string(),
                );
                params.push(SqlValue::Integer(
                    cursor_created_at.try_into().unwrap_or(i64::MAX),
                ));
                params.push(SqlValue::Integer(
                    cursor_created_at.try_into().unwrap_or(i64::MAX),
                ));
                params.push(SqlValue::Integer(cursor_rowid));
            } else if after_id.is_some() {
                where_parts.push(
                    "(created_at_unix_ms > ? or (created_at_unix_ms = ? and rowid > ?))"
                        .to_string(),
                );
                params.push(SqlValue::Integer(
                    cursor_created_at.try_into().unwrap_or(i64::MAX),
                ));
                params.push(SqlValue::Integer(
                    cursor_created_at.try_into().unwrap_or(i64::MAX),
                ));
                params.push(SqlValue::Integer(cursor_rowid));
            }
        }

        let where_clause = if where_parts.is_empty() {
            String::new()
        } else {
            format!(" where {}", where_parts.join(" and "))
        };
        let order_clause = if after_id.is_some() {
            " order by created_at_unix_ms asc, rowid asc"
        } else {
            " order by created_at_unix_ms desc, rowid desc"
        };
        let sql = format!(
            "select id, kind, task_id, tool_call_id, summary, payload_json, created_at_unix_ms
             from audit_events{where_clause}{order_clause} limit ?"
        );
        params.push(SqlValue::Integer(i64::from(limit)));

        let mut stmt = self.conn.prepare(&sql)?;
        let mut rows = stmt.query(params_from_iter(params))?;
        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            events.push(row_to_event(row)?);
        }
        if after_id.is_none() {
            events.reverse();
        }
        Ok(events)
    }

    fn cursor_for_event(&self, event_id: &str) -> Result<Option<(u64, i64)>> {
        self.conn
            .query_row(
                "select created_at_unix_ms, rowid from audit_events where id = ?1 limit 1",
                params![event_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(Into::into)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            pragma journal_mode = wal;
            create table if not exists audit_events (
                id text primary key,
                kind text not null,
                task_id text,
                tool_call_id text,
                summary text not null,
                payload_json text not null,
                created_at_unix_ms integer not null
            );
            create index if not exists idx_audit_events_task_id on audit_events(task_id);
            create index if not exists idx_audit_events_tool_call_id on audit_events(tool_call_id);
            create index if not exists idx_audit_events_created_at on audit_events(created_at_unix_ms);

            create table if not exists tasks (
                id text primary key,
                title text not null,
                description text,
                status_json text not null,
                created_at_unix_ms integer not null,
                updated_at_unix_ms integer not null,
                metadata_json text not null
            );
            create index if not exists idx_tasks_created_at on tasks(created_at_unix_ms);
            create index if not exists idx_tasks_updated_at on tasks(updated_at_unix_ms);

            create table if not exists approvals (
                id text primary key,
                task_id text not null,
                tool_call_id text not null,
                tool_name text not null,
                reason text not null,
                status_json text not null,
                created_at_unix_ms integer not null,
                decided_at_unix_ms integer,
                decision_reason text,
                tool_manifest_sha256 text
            );
            create index if not exists idx_approvals_task_id on approvals(task_id);
            create index if not exists idx_approvals_status on approvals(status_json);

            create table if not exists approval_grants (
                id text primary key,
                tool_name text not null,
                tool_call_id text,
                task_id text,
                lifetime_json text not null,
                created_at_unix_ms integer not null,
                expires_at_unix_ms integer,
                boot_id text,
                tool_manifest_sha256 text,
                agent_subject_sha256 text,
                os_executor_sha256 text
            );
            create index if not exists idx_approval_grants_tool_name on approval_grants(tool_name);
            create index if not exists idx_approval_grants_task_id on approval_grants(task_id);
            create index if not exists idx_approval_grants_lifetime on approval_grants(lifetime_json);
            create index if not exists idx_approval_grants_expires_at on approval_grants(expires_at_unix_ms);

            create table if not exists tool_runs (
                tool_call_id text primary key,
                task_id text not null,
                tool_name text not null,
                arguments_json text not null,
                status_json text not null,
                requested_at_unix_ms integer not null,
                started_at_unix_ms integer,
                finished_at_unix_ms integer,
                output_json text,
                error text,
                approval_id text,
                policy_decision_json text,
                agent_execution_binding_json text
            );
            create index if not exists idx_tool_runs_task_id on tool_runs(task_id);
            create index if not exists idx_tool_runs_status on tool_runs(status_json);
            create index if not exists idx_tool_runs_requested_at on tool_runs(requested_at_unix_ms);

            create table if not exists agent_registrations (
                agent_id text primary key,
                registration_json text not null,
                updated_at_unix_ms integer not null
            );
            create index if not exists idx_agent_registrations_updated
                on agent_registrations(updated_at_unix_ms);

            create table if not exists agent_plans (
                plan_id text primary key,
                task_id text not null,
                agent_id text not null,
                plan_json text not null,
                created_at_unix_ms integer not null
            );
            create index if not exists idx_agent_plans_task_id on agent_plans(task_id);
            create unique index if not exists idx_agent_plans_one_per_task
                on agent_plans(task_id);
            create index if not exists idx_agent_plans_agent_id on agent_plans(agent_id);
            create index if not exists idx_agent_plans_created on agent_plans(created_at_unix_ms);

            "#,
        )?;
        // Legacy databases may still contain the former agent_memories table.
        // Deliberately neither access nor DROP it here: production Memory has a
        // single owner in ContextMemoryService, while historical rows remain
        // intact for a separately authorized custody/export migration.
        self.ensure_column("approval_grants", "boot_id", "text")?;
        self.ensure_column("approvals", "tool_manifest_sha256", "text")?;
        self.ensure_column("approval_grants", "tool_manifest_sha256", "text")?;
        self.ensure_column("approval_grants", "agent_subject_sha256", "text")?;
        self.ensure_column("approval_grants", "os_executor_sha256", "text")?;
        self.ensure_column("tool_runs", "agent_execution_binding_json", "text")?;
        // Registrations written before peer GID became an explicit identity
        // component were accepted only under the old UID=GID contract. Carry
        // that exact legacy binding forward once so upgraded stores remain
        // readable; all newly supplied AgentManifests must name `peer_gid`.
        self.conn.execute(
            "update agent_registrations
             set registration_json = json_set(
                 registration_json,
                 '$.peer_gid',
                 json_extract(registration_json, '$.peer_uid')
             )
             where json_type(registration_json, '$.peer_gid') is null
               and json_type(registration_json, '$.peer_uid') = 'integer'",
            [],
        )?;
        self.conn.execute(
            "create index if not exists idx_approval_grants_boot_id on approval_grants(boot_id)",
            [],
        )?;
        Ok(())
    }

    fn ensure_column(&self, table: &str, column: &str, definition: &str) -> Result<()> {
        let pragma = format!("pragma table_info({table})");
        let mut stmt = self.conn.prepare(&pragma)?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == column {
                return Ok(());
            }
        }
        self.conn.execute(
            &format!("alter table {table} add column {column} {definition}"),
            [],
        )?;
        Ok(())
    }
}

fn append_event_on(conn: &Connection, event: &AuditEvent) -> Result<()> {
    conn.execute(
        "insert into audit_events (
            id, kind, task_id, tool_call_id, summary, payload_json, created_at_unix_ms
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            &event.id,
            serde_json::to_string(&event.kind)?,
            event.task_id.as_ref().map(|id| id.0.as_str()),
            event.tool_call_id.as_ref().map(|id| id.0.as_str()),
            &event.summary,
            serde_json::to_string(&event.payload)?,
            event.created_at_unix_ms,
        ],
    )?;
    Ok(())
}

fn insert_agent_plan_if_absent_on(
    conn: &Connection,
    plan: &AgentPlanSubmission,
) -> Result<AgentPlanSaveOutcome> {
    let encoded = serde_json::to_string(plan)?;
    let changed = conn.execute(
        "insert into agent_plans
            (plan_id, task_id, agent_id, plan_json, created_at_unix_ms)
         values (?1, ?2, ?3, ?4, ?5)
         on conflict do nothing",
        params![
            &plan.plan_id,
            &plan.task_id.0,
            &plan.agent_id,
            &encoded,
            plan.created_at_unix_ms,
        ],
    )?;
    if changed == 1 {
        return Ok(AgentPlanSaveOutcome::Inserted);
    }

    let by_plan_id = conn
        .query_row(
            "select task_id, agent_id, plan_json, created_at_unix_ms
             from agent_plans where plan_id = ?1 limit 1",
            params![&plan.plan_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((task_id, agent_id, stored_json, created_at_unix_ms)) = by_plan_id else {
        let existing_plan_id = conn.query_row(
            "select plan_id from agent_plans where task_id = ?1 limit 1",
            params![&plan.task_id.0],
            |row| row.get::<_, String>(0),
        )?;
        return Err(AuditStoreError::ImmutableTaskPlanConflict {
            task_id: plan.task_id.0.clone(),
            existing_plan_id,
        });
    };
    let stored = serde_json::from_str::<AgentPlanSubmission>(&stored_json)?;
    if task_id != plan.task_id.0
        || agent_id != plan.agent_id
        || created_at_unix_ms != plan.created_at_unix_ms
        || stored != *plan
    {
        return Err(AuditStoreError::ImmutableAgentPlanConflict {
            plan_id: plan.plan_id.clone(),
        });
    }
    Ok(AgentPlanSaveOutcome::AlreadyPresent)
}

fn validate_agent_plan_submission_receipt(
    plan: &AgentPlanSubmission,
    event: &AuditEvent,
) -> Result<()> {
    let payload = event.payload.as_object();
    let receipt_plan = payload
        .and_then(|payload| payload.get("plan"))
        .cloned()
        .map(serde_json::from_value::<AgentPlanSubmission>)
        .transpose()?;
    if event.kind != AuditEventKind::AgentPlanSubmitted
        || event.task_id.as_ref() != Some(&plan.task_id)
        || event.tool_call_id.is_some()
        || payload.is_none_or(|payload| payload.len() != 2)
        || payload
            .and_then(|payload| payload.get("api_version"))
            .and_then(serde_json::Value::as_str)
            != Some(plan.api_version.as_str())
        || receipt_plan.as_ref() != Some(plan)
    {
        return Err(AuditStoreError::InvalidAgentPlanSubmissionReceipt {
            plan_id: plan.plan_id.clone(),
        });
    }
    Ok(())
}

fn save_task_on(conn: &Connection, task: &TaskView) -> Result<()> {
    conn.execute(
        "insert into tasks (
            id, title, description, status_json, created_at_unix_ms, updated_at_unix_ms, metadata_json
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        on conflict(id) do update set
            title = excluded.title,
            description = excluded.description,
            status_json = excluded.status_json,
            updated_at_unix_ms = excluded.updated_at_unix_ms,
            metadata_json = excluded.metadata_json",
        params![
            &task.id.0,
            &task.title,
            task.description.as_deref(),
            serde_json::to_string(&task.status)?,
            task.created_at_unix_ms,
            task.updated_at_unix_ms,
            serde_json::to_string(&task.metadata)?,
        ],
    )?;
    Ok(())
}

fn update_task_if_status(
    conn: &Connection,
    task: &TaskView,
    expected_status: &TaskStatus,
) -> Result<bool> {
    let changed = conn.execute(
        "update tasks set
            title = ?2,
            description = ?3,
            status_json = ?4,
            updated_at_unix_ms = ?5,
            metadata_json = ?6
         where id = ?1 and status_json = ?7",
        params![
            &task.id.0,
            &task.title,
            task.description.as_deref(),
            serde_json::to_string(&task.status)?,
            task.updated_at_unix_ms,
            serde_json::to_string(&task.metadata)?,
            serde_json::to_string(expected_status)?,
        ],
    )?;
    Ok(changed == 1)
}

fn save_approval_on(conn: &Connection, approval: &ApprovalRequest) -> Result<()> {
    conn.execute(
        "insert into approvals (
            id, task_id, tool_call_id, tool_name, reason, status_json,
            created_at_unix_ms, decided_at_unix_ms, decision_reason,
            tool_manifest_sha256
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        on conflict(id) do update set
            task_id = excluded.task_id,
            tool_call_id = excluded.tool_call_id,
            tool_name = excluded.tool_name,
            reason = excluded.reason,
            status_json = excluded.status_json,
            decided_at_unix_ms = excluded.decided_at_unix_ms,
            decision_reason = excluded.decision_reason,
            tool_manifest_sha256 = excluded.tool_manifest_sha256",
        params![
            &approval.id,
            &approval.task_id.0,
            &approval.tool_call_id.0,
            &approval.tool_name,
            &approval.reason,
            serde_json::to_string(&approval.status)?,
            approval.created_at_unix_ms,
            approval.decided_at_unix_ms,
            approval.decision_reason.as_deref(),
            approval.tool_manifest_sha256.as_deref(),
        ],
    )?;
    Ok(())
}

fn save_approval_grant_on(conn: &Connection, grant: &ApprovalGrant) -> Result<()> {
    conn.execute(
        "insert into approval_grants (
            id, tool_name, tool_call_id, task_id, lifetime_json,
            created_at_unix_ms, expires_at_unix_ms, boot_id,
            tool_manifest_sha256, agent_subject_sha256, os_executor_sha256
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
        on conflict(id) do update set
            tool_name = excluded.tool_name,
            tool_call_id = excluded.tool_call_id,
            task_id = excluded.task_id,
            lifetime_json = excluded.lifetime_json,
            created_at_unix_ms = excluded.created_at_unix_ms,
            expires_at_unix_ms = excluded.expires_at_unix_ms,
            boot_id = excluded.boot_id,
            tool_manifest_sha256 = excluded.tool_manifest_sha256,
            agent_subject_sha256 = excluded.agent_subject_sha256,
            os_executor_sha256 = excluded.os_executor_sha256",
        params![
            &grant.id,
            &grant.tool_name,
            grant.tool_call_id.as_ref().map(|id| id.0.as_str()),
            grant.task_id.as_ref().map(|id| id.0.as_str()),
            serde_json::to_string(&grant.lifetime)?,
            grant.created_at_unix_ms,
            grant.expires_at_unix_ms,
            grant.boot_id.as_deref(),
            grant.tool_manifest_sha256.as_deref(),
            grant.agent_subject_sha256.as_deref(),
            grant.os_executor_sha256.as_deref(),
        ],
    )?;
    Ok(())
}

fn save_tool_run_on(conn: &Connection, run: &ToolRun) -> Result<()> {
    conn.execute(
        "insert into tool_runs (
            tool_call_id, task_id, tool_name, arguments_json, status_json,
            requested_at_unix_ms, started_at_unix_ms, finished_at_unix_ms,
            output_json, error, approval_id, policy_decision_json,
            agent_execution_binding_json
        ) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        on conflict(tool_call_id) do update set
            task_id = excluded.task_id,
            tool_name = excluded.tool_name,
            arguments_json = excluded.arguments_json,
            status_json = excluded.status_json,
            requested_at_unix_ms = excluded.requested_at_unix_ms,
            started_at_unix_ms = excluded.started_at_unix_ms,
            finished_at_unix_ms = excluded.finished_at_unix_ms,
            output_json = excluded.output_json,
            error = excluded.error,
            approval_id = excluded.approval_id,
            policy_decision_json = excluded.policy_decision_json,
            agent_execution_binding_json = excluded.agent_execution_binding_json",
        params![
            &run.tool_call_id.0,
            &run.task_id.0,
            &run.tool_name,
            serde_json::to_string(&run.arguments)?,
            serde_json::to_string(&run.status)?,
            run.requested_at_unix_ms,
            run.started_at_unix_ms,
            run.finished_at_unix_ms,
            run.output.as_ref().map(serde_json::to_string).transpose()?,
            run.error.as_deref(),
            run.approval_id.as_deref(),
            run.policy_decision
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            run.agent_execution_binding
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
        ],
    )?;
    Ok(())
}

fn row_to_event(row: &rusqlite::Row<'_>) -> Result<AuditEvent> {
    let kind_json: String = row.get(1)?;
    let task_id: Option<String> = row.get(2)?;
    let tool_call_id: Option<String> = row.get(3)?;
    let payload_json: String = row.get(5)?;
    Ok(AuditEvent {
        id: row.get(0)?,
        kind: serde_json::from_str::<AuditEventKind>(&kind_json)?,
        task_id: task_id.map(TaskId),
        tool_call_id: tool_call_id.map(ToolCallId),
        summary: row.get(4)?,
        payload: serde_json::from_str(&payload_json)?,
        created_at_unix_ms: row.get(6)?,
    })
}

fn row_to_task(row: &rusqlite::Row<'_>) -> Result<TaskView> {
    let status_json: String = row.get(3)?;
    let metadata_json: String = row.get(6)?;
    Ok(TaskView {
        id: TaskId(row.get(0)?),
        title: row.get(1)?,
        description: row.get(2)?,
        status: serde_json::from_str::<TaskStatus>(&status_json)?,
        created_at_unix_ms: row.get(4)?,
        updated_at_unix_ms: row.get(5)?,
        metadata: serde_json::from_str(&metadata_json)?,
    })
}

fn row_to_approval(row: &rusqlite::Row<'_>) -> Result<ApprovalRequest> {
    let status_json: String = row.get(5)?;
    Ok(ApprovalRequest {
        id: row.get(0)?,
        task_id: TaskId(row.get(1)?),
        tool_call_id: ToolCallId(row.get(2)?),
        tool_name: row.get(3)?,
        reason: row.get(4)?,
        status: serde_json::from_str::<ApprovalStatus>(&status_json)?,
        created_at_unix_ms: row.get(6)?,
        decided_at_unix_ms: row.get(7)?,
        decision_reason: row.get(8)?,
        tool_manifest_sha256: row.get(9)?,
    })
}

fn row_to_approval_grant(row: &rusqlite::Row<'_>) -> Result<ApprovalGrant> {
    let tool_call_id: Option<String> = row.get(2)?;
    let task_id: Option<String> = row.get(3)?;
    let lifetime_json: String = row.get(4)?;
    Ok(ApprovalGrant {
        id: row.get(0)?,
        tool_name: row.get(1)?,
        tool_call_id: tool_call_id.map(ToolCallId),
        task_id: task_id.map(TaskId),
        lifetime: serde_json::from_str::<ApprovalLifetime>(&lifetime_json)?,
        created_at_unix_ms: row.get(5)?,
        expires_at_unix_ms: row.get(6)?,
        boot_id: row.get(7)?,
        tool_manifest_sha256: row.get(8)?,
        agent_subject_sha256: row.get(9)?,
        os_executor_sha256: row.get(10)?,
    })
}

fn row_to_tool_run(row: &rusqlite::Row<'_>) -> Result<ToolRun> {
    let arguments_json: String = row.get(3)?;
    let status_json: String = row.get(4)?;
    let output_json: Option<String> = row.get(8)?;
    let policy_decision_json: Option<String> = row.get(11)?;
    let agent_execution_binding_json: Option<String> = row.get(12)?;
    Ok(ToolRun {
        tool_call_id: ToolCallId(row.get(0)?),
        task_id: TaskId(row.get(1)?),
        tool_name: row.get(2)?,
        arguments: serde_json::from_str(&arguments_json)?,
        agent_execution_binding: agent_execution_binding_json
            .map(|json| serde_json::from_str::<AgentExecutionBinding>(&json))
            .transpose()?,
        status: serde_json::from_str::<ToolRunStatus>(&status_json)?,
        requested_at_unix_ms: row.get(5)?,
        started_at_unix_ms: row.get(6)?,
        finished_at_unix_ms: row.get(7)?,
        output: output_json
            .map(|json| serde_json::from_str(&json))
            .transpose()?,
        error: row.get(9)?,
        approval_id: row.get(10)?,
        policy_decision: policy_decision_json
            .map(|json| serde_json::from_str(&json))
            .transpose()?,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;
    use trillionnium_os_types::{
        AGENT_API_VERSION, AgentHealth, AgentNetworkPolicy, AgentRegistration, ApprovalGrant,
        ApprovalRequest, ApprovalStatus, AuditEvent, AuditEventKind, PolicyDecision, TaskStatus,
        TaskView, ToolCallId, ToolRun,
    };

    use super::*;

    #[test]
    fn write_contention_timeout_is_explicit_and_bounded() {
        let store = AuditStore::open_memory().expect("in-memory store should open");
        let configured_ms: u64 = store
            .conn
            .query_row("pragma busy_timeout", [], |row| row.get(0))
            .expect("busy timeout should be readable");
        assert_eq!(
            configured_ms,
            SQLITE_WRITE_CONTENTION_TIMEOUT.as_millis() as u64
        );
    }

    fn concurrent_plan_fixture(plan_id: &str, provider_output_byte: char) -> AgentPlanSubmission {
        AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: plan_id.to_string(),
            task_id: TaskId("task-concurrent-plan".to_string()),
            session_id: "session-concurrent-plan".to_string(),
            agent_id: "agent-concurrent-plan".to_string(),
            intent_sha256: "a".repeat(64),
            provider_output_sha256: provider_output_byte.to_string().repeat(64),
            contexts: Vec::new(),
            actions: Vec::new(),
            created_at_unix_ms: 42,
        }
    }

    fn plan_submission_event_fixture(plan: &AgentPlanSubmission) -> AuditEvent {
        AuditEvent::new(
            AuditEventKind::AgentPlanSubmitted,
            format!("accepted bounded plan {}", plan.plan_id),
        )
        .with_task(plan.task_id.clone())
        .with_payload(json!({
            "api_version": AGENT_API_VERSION,
            "plan": plan
        }))
    }

    #[test]
    fn concurrent_different_content_never_overwrites_frozen_agent_plan() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "trillionnium-concurrent-plan-{}-{nonce}.sqlite",
            std::process::id()
        ));
        AuditStore::open(&path).expect("schema should initialize");

        let plan_id = "plan-concurrent-conflict";
        let plans = [
            concurrent_plan_fixture(plan_id, 'b'),
            concurrent_plan_fixture(plan_id, 'c'),
        ];
        let barrier = Arc::new(Barrier::new(plans.len()));
        let handles = plans
            .into_iter()
            .map(|plan| {
                let path = path.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let store = AuditStore::open(path).expect("concurrent store should open");
                    let event = plan_submission_event_fixture(&plan);
                    assert!(
                        store
                            .get_agent_plan_for_task(&plan.task_id.0)
                            .expect("preflight plan lookup should succeed")
                            .is_none()
                    );
                    barrier.wait();
                    let result = store.persist_agent_plan_submission_atomic(&plan, &event);
                    (plan, result)
                })
            })
            .collect::<Vec<_>>();

        let mut inserted = None;
        let mut conflicts = 0;
        for handle in handles {
            let (plan, result) = handle.join().expect("plan writer should not panic");
            match result {
                Ok(AgentPlanSaveOutcome::Inserted) => inserted = Some(plan),
                Ok(AgentPlanSaveOutcome::AlreadyPresent) => {
                    panic!("different plan content must not be accepted as identical")
                }
                Err(AuditStoreError::ImmutableAgentPlanConflict {
                    plan_id: conflict_id,
                }) => {
                    assert_eq!(conflict_id, plan_id);
                    conflicts += 1;
                }
                Err(error) => panic!("unexpected concurrent plan error: {error}"),
            }
        }
        let inserted = inserted.expect("one writer must insert the plan");
        assert_eq!(conflicts, 1);

        let reopened = AuditStore::open(&path).expect("store should reopen");
        let stored = reopened
            .get_agent_plan(plan_id)
            .expect("plan lookup should succeed")
            .expect("winning plan should remain stored");
        assert_eq!(stored, inserted);
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
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn committed_winner_is_reconciled_during_bounded_plan_retry() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "trillionnium-plan-reconcile-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let holder = AuditStore::open(&path).expect("holder should open");
        let contender = AuditStore::open(&path).expect("contender should open");
        contender
            .conn
            .busy_timeout(Duration::from_millis(400))
            .expect("test busy timeout should apply");

        let winner = concurrent_plan_fixture("plan-reconcile-winner", 'b');
        let winner_event = plan_submission_event_fixture(&winner);
        let (locked_tx, locked_rx) = mpsc::channel();
        let holder_thread = thread::spawn(move || {
            let transaction = holder
                .conn
                .unchecked_transaction()
                .expect("winner should acquire the immediate write lock");
            assert_eq!(
                insert_agent_plan_if_absent_on(&transaction, &winner)
                    .expect("winner plan should stage"),
                AgentPlanSaveOutcome::Inserted
            );
            append_event_on(&transaction, &winner_event).expect("winner receipt should stage");
            locked_tx.send(()).expect("lock signal should send");
            thread::sleep(Duration::from_millis(500));
            transaction.commit().expect("winner should commit");
        });
        locked_rx.recv().expect("winner should hold the write lock");

        let loser = concurrent_plan_fixture("plan-reconcile-loser", 'c');
        let loser_event = plan_submission_event_fixture(&loser);
        let result = contender.persist_agent_plan_submission_atomic(&loser, &loser_event);
        match result {
            Err(AuditStoreError::ImmutableTaskPlanConflict {
                task_id,
                existing_plan_id,
            }) => {
                assert_eq!(task_id, loser.task_id.0);
                assert_eq!(existing_plan_id, "plan-reconcile-winner");
            }
            other => panic!("expected committed-winner task conflict, got {other:?}"),
        }
        holder_thread.join().expect("winner thread should finish");

        let reopened = AuditStore::open(&path).expect("store should reopen");
        let stored = reopened
            .get_agent_plan_for_task(&loser.task_id.0)
            .expect("task plan lookup should succeed")
            .expect("winner should remain durable");
        assert_eq!(stored.plan_id, "plan-reconcile-winner");
        reopened
            .require_one_exact_agent_plan_submission_receipt(&stored)
            .expect("winner should have exactly one exact receipt");
        assert!(
            reopened
                .get_agent_plan(&loser.plan_id)
                .expect("loser lookup should succeed")
                .is_none()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn bounded_plan_contention_exhaustion_writes_nothing() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "trillionnium-plan-contention-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let holder = AuditStore::open(&path).expect("holder should open");
        let contender = AuditStore::open(&path).expect("contender should open");
        contender
            .conn
            .busy_timeout(Duration::from_millis(10))
            .expect("test busy timeout should apply");
        let transaction = holder
            .conn
            .unchecked_transaction()
            .expect("holder should acquire the immediate write lock");

        let plan = concurrent_plan_fixture("plan-contention-exhausted", 'd');
        let event = plan_submission_event_fixture(&plan);
        let result = contender.persist_agent_plan_submission_atomic(&plan, &event);
        match result {
            Err(AuditStoreError::AgentPlanContentionExhausted {
                plan_id,
                task_id,
                source,
            }) => {
                assert_eq!(plan_id, plan.plan_id);
                assert_eq!(task_id, plan.task_id.0);
                assert!(is_sqlite_contention(&source));
            }
            other => panic!("expected typed contention exhaustion, got {other:?}"),
        }
        transaction.rollback().expect("holder should release lock");
        drop(contender);
        drop(holder);

        let reopened = AuditStore::open(&path).expect("store should reopen");
        assert!(
            reopened
                .get_agent_plan(&plan.plan_id)
                .expect("plan lookup should succeed")
                .is_none()
        );
        let receipts = reopened
            .list_events_page_by_kinds(
                Some(&plan.task_id.0),
                None,
                &[AuditEventKind::AgentPlanSubmitted],
                None,
                None,
                10,
            )
            .expect("receipt page should load");
        assert!(receipts.is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn plan_receipt_failure_rolls_back_plan_before_fresh_reopen() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "trillionnium-plan-receipt-fault-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let store = AuditStore::open(&path).expect("schema should initialize");
        store
            .conn
            .execute_batch(
                r#"
                create trigger fail_agent_plan_receipt
                before insert on audit_events
                when new.kind = '"agent_plan_submitted"'
                begin
                    select raise(abort, 'injected agent plan receipt failure');
                end;
                "#,
            )
            .expect("fault trigger should install");
        let plan = concurrent_plan_fixture("plan-receipt-fault", 'd');
        let event = plan_submission_event_fixture(&plan);

        assert!(
            store
                .persist_agent_plan_submission_atomic(&plan, &event)
                .is_err()
        );
        drop(store);

        let reopened = AuditStore::open(&path).expect("store should reopen after fault");
        assert!(
            reopened
                .get_agent_plan(&plan.plan_id)
                .expect("plan lookup should succeed")
                .is_none(),
            "receipt insertion failure must roll back the immutable plan"
        );
        assert_eq!(reopened.count_events().unwrap(), 0);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn identical_duplicate_plan_never_appends_a_second_submission_receipt() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let plan = concurrent_plan_fixture("plan-identical-duplicate", 'e');
        let first_event = plan_submission_event_fixture(&plan);
        assert_eq!(
            store
                .persist_agent_plan_submission_atomic(&plan, &first_event)
                .unwrap(),
            AgentPlanSaveOutcome::Inserted
        );
        let duplicate_event = plan_submission_event_fixture(&plan);
        assert_eq!(
            store
                .persist_agent_plan_submission_atomic(&plan, &duplicate_event)
                .unwrap(),
            AgentPlanSaveOutcome::AlreadyPresent
        );
        assert_eq!(store.count_events().unwrap(), 1);
        assert!(
            store
                .has_exact_agent_plan_submission_receipt(&plan)
                .unwrap()
        );
        // Direct corruption or an append bug that introduces a second exact
        // receipt must make the plan non-executable. Existence alone is not a
        // sufficient plan-to-action custody proof.
        store.append(&duplicate_event).unwrap();
        assert_eq!(store.count_events().unwrap(), 2);
        assert!(
            !store
                .has_exact_agent_plan_submission_receipt(&plan)
                .unwrap()
        );
    }

    #[test]
    fn agent_plan_submission_receipt_payload_is_closed_world() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let plan = concurrent_plan_fixture("plan-closed-world-receipt", 'f');
        let mut wrong_api = plan_submission_event_fixture(&plan);
        wrong_api.payload["api_version"] = json!("trillionnium.agent-api.v0");
        assert!(
            store
                .persist_agent_plan_submission_atomic(&plan, &wrong_api)
                .is_err()
        );
        assert!(store.get_agent_plan(&plan.plan_id).unwrap().is_none());

        let mut extra_field = plan_submission_event_fixture(&plan);
        extra_field.payload["legacy_plan_alias"] = json!(plan.clone());
        assert!(
            store
                .persist_agent_plan_submission_atomic(&plan, &extra_field)
                .is_err()
        );
        assert!(store.get_agent_plan(&plan.plan_id).unwrap().is_none());

        // A separately appended legacy-shaped event cannot make a raw
        // custody/import row executable: exact receipt lookup applies the
        // same closed-world validation as the atomic writer.
        assert_eq!(
            store.insert_agent_plan_if_absent(&plan).unwrap(),
            AgentPlanSaveOutcome::Inserted
        );
        store.append(&extra_field).unwrap();
        assert!(
            !store
                .has_exact_agent_plan_submission_receipt(&plan)
                .unwrap()
        );
    }

    #[test]
    fn persists_agent_registry_records() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let registration = AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: "agent-codex-test".to_string(),
            adapter: "codex-cli".to_string(),
            adapter_version: "test".to_string(),
            identity_key_sha256: "a".repeat(64),
            peer_uid: 1000,
            peer_gid: 1000,
            selinux_domain: "u:r:trillionnium_agent:s0".to_string(),
            network_policy: AgentNetworkPolicy::PerRequest,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: 10,
            updated_at_unix_ms: 11,
        };

        store
            .save_agent_registration(&registration)
            .expect("agent should persist");

        assert_eq!(
            store
                .get_agent_registration(&registration.agent_id)
                .unwrap(),
            Some(registration.clone())
        );
        assert_eq!(
            store.load_agent_registrations().unwrap(),
            vec![registration]
        );
    }

    #[test]
    fn migrates_legacy_uid_only_agent_identity_to_explicit_equal_gid() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let legacy = json!({
            "api_version": AGENT_API_VERSION,
            "agent_id": "agent-legacy-uid-gid-test",
            "adapter": "fixture-adapter",
            "adapter_version": "1",
            "identity_key_sha256": "a".repeat(64),
            "peer_uid": 23001,
            "selinux_domain": "u:r:trillionnium_fixture_agent:s0",
            "network_policy": "deny",
            "enabled": true,
            "health": "ready",
            "registered_at_unix_ms": 10,
            "updated_at_unix_ms": 11
        });
        store
            .conn
            .execute(
                "insert into agent_registrations
                 (agent_id, registration_json, updated_at_unix_ms)
                 values (?1, ?2, ?3)",
                params![
                    "agent-legacy-uid-gid-test",
                    serde_json::to_string(&legacy).unwrap(),
                    11
                ],
            )
            .unwrap();

        store
            .migrate()
            .expect("legacy identity migration should pass");
        let migrated = store
            .get_agent_registration("agent-legacy-uid-gid-test")
            .unwrap()
            .unwrap();
        assert_eq!(migrated.peer_uid, 23001);
        assert_eq!(migrated.peer_gid, 23001);
    }

    #[test]
    fn legacy_agent_memory_rows_are_preserved_but_fresh_schema_does_not_create_them() {
        let fresh = AuditStore::open_memory().expect("fresh audit store should open");
        let fresh_table_count: u64 = fresh
            .conn
            .query_row(
                "select count(*) from sqlite_master where type = 'table' and name = 'agent_memories'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(fresh_table_count, 0);

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "trillionnium-legacy-agent-memory-{}-{nonce}.sqlite",
            std::process::id()
        ));
        let legacy = Connection::open(&path).expect("legacy database should open");
        legacy
            .execute_batch(
                "create table agent_memories (
                    memory_id text primary key,
                    owner_agent_id text not null,
                    memory_json text not null,
                    revoked_at_unix_ms integer,
                    updated_at_unix_ms integer not null
                );
                insert into agent_memories values (
                    'memory-legacy-custody',
                    'agent-legacy-custody',
                    '{\"legacy\":true}',
                    null,
                    1
                );",
            )
            .expect("legacy custody fixture should initialize");
        drop(legacy);

        let migrated = AuditStore::open(&path).expect("current migration should open legacy db");
        let preserved_rows: u64 = migrated
            .conn
            .query_row("select count(*) from agent_memories", [], |row| row.get(0))
            .unwrap();
        assert_eq!(preserved_rows, 1);
        drop(migrated);
        std::fs::remove_file(path).expect("legacy custody fixture should be removed");
    }

    #[test]
    fn append_and_count_audit_event() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let event = AuditEvent::new(AuditEventKind::DbusPing, "pinged daemon");

        store.append(&event).expect("event should append");

        assert_eq!(store.count_events().expect("count should load"), 1);
        assert_eq!(
            store.latest_summary().expect("summary should load"),
            Some("pinged daemon".to_string())
        );
        assert_eq!(
            store
                .list_events(None, 10)
                .expect("timeline should load")
                .len(),
            1
        );
    }

    #[test]
    fn audit_event_pages_support_before_after_and_filters() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let task_id = TaskId("task-page".to_string());
        let tool_call_id = ToolCallId("toolcall-page".to_string());
        let mut events = Vec::new();
        for index in 0..5_u64 {
            let mut event = AuditEvent::new(
                if index % 2 == 0 {
                    AuditEventKind::ToolRequested
                } else {
                    AuditEventKind::PolicyEvaluated
                },
                format!("event {index}"),
            )
            .with_task(task_id.clone())
            .with_tool_call(tool_call_id.clone());
            event.created_at_unix_ms = 100 + index;
            store.append(&event).expect("event should append");
            events.push(event);
        }

        let latest_two = store
            .list_events_page(None, None, None, None, None, 2)
            .expect("latest page should load");
        assert_eq!(latest_two[0].summary, "event 3");
        assert_eq!(latest_two[1].summary, "event 4");

        let older = store
            .list_events_page(None, None, None, Some(&latest_two[0].id), None, 2)
            .expect("older page should load");
        assert_eq!(older[0].summary, "event 1");
        assert_eq!(older[1].summary, "event 2");

        let newer = store
            .list_events_page(None, None, None, None, Some(&older[1].id), 5)
            .expect("newer page should load");
        assert_eq!(newer[0].summary, "event 3");
        assert_eq!(newer[1].summary, "event 4");

        let filtered = store
            .list_events_page(
                Some(&task_id.0),
                Some(&tool_call_id.0),
                Some(AuditEventKind::ToolRequested),
                None,
                None,
                10,
            )
            .expect("filtered page should load");
        assert_eq!(filtered.len(), 3);
        assert!(
            filtered
                .iter()
                .all(|event| event.kind == AuditEventKind::ToolRequested)
        );

        let multi_kind = store
            .list_events_page_by_kinds(
                Some(&task_id.0),
                Some(&tool_call_id.0),
                &[
                    AuditEventKind::ToolRequested,
                    AuditEventKind::PolicyEvaluated,
                ],
                None,
                None,
                10,
            )
            .expect("multi-kind page should load");
        assert_eq!(multi_kind.len(), 5);
        assert!(multi_kind.iter().any(|event| event.summary == "event 0"));
        assert!(multi_kind.iter().any(|event| event.summary == "event 1"));
    }

    #[test]
    fn persists_task_and_approval_snapshots() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let task = TaskView {
            id: TaskId::new(),
            title: "Persistent task".to_string(),
            description: Some("round trip".to_string()),
            status: TaskStatus::WaitingForApproval,
            created_at_unix_ms: 1,
            updated_at_unix_ms: 2,
            metadata: json!({ "source": "unit" }),
        };
        let approval = ApprovalRequest {
            id: "approval-test".to_string(),
            task_id: task.id.clone(),
            tool_call_id: ToolCallId::new(),
            tool_name: "files.read".to_string(),
            reason: "test".to_string(),
            status: ApprovalStatus::Pending,
            created_at_unix_ms: 3,
            decided_at_unix_ms: None,
            decision_reason: None,
            tool_manifest_sha256: None,
        };

        store.save_task(&task).expect("task should save");
        store
            .save_approval(&approval)
            .expect("approval should save");

        let tasks = store.load_tasks().expect("tasks should load");
        let approvals = store.load_approvals().expect("approvals should load");
        assert_eq!(tasks, vec![task]);
        assert_eq!(approvals, vec![approval]);
    }

    #[test]
    fn persists_approval_grants() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let task_id = TaskId("task-grant".to_string());
        let grant = ApprovalGrant::current_task("demo.approval_echo", task_id.clone())
            .with_expires_at(12345)
            .with_boot_id("boot-test");

        store
            .save_approval_grant(&grant)
            .expect("grant should save");

        let grants = store.load_approval_grants().expect("grants should load");
        assert_eq!(grants, vec![grant.clone()]);
        assert!(
            store
                .delete_approval_grant(&grant.id)
                .expect("grant should delete")
        );
        assert!(
            store
                .load_approval_grants()
                .expect("grants should reload")
                .is_empty()
        );
    }

    #[test]
    fn persists_tool_run_snapshots() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let mut run = ToolRun {
            task_id: TaskId("task-test".to_string()),
            tool_call_id: ToolCallId("toolcall-test".to_string()),
            tool_name: "system.status".to_string(),
            arguments: json!({}),
            agent_execution_binding: Some(AgentExecutionBinding {
                agent_id: "agent-persistence-test".to_string(),
                peer_uid: 24001,
                peer_gid: 24002,
                peer_selinux_domain: "u:r:trillionnium_test_agent:s0".to_string(),
                agent_executable_sha256: "b".repeat(64),
                subject_user_id: 10,
                origin_uid: 1_024_001,
                origin_selinux_domain: "u:r:trillionnium_aishell:s0".to_string(),
                session_id: "session-persistence-test".to_string(),
                task_id: TaskId("task-test".to_string()),
                plan_id: "plan-persistence-test".to_string(),
                action_id: "action-persistence-test".to_string(),
                tool_call_id: ToolCallId("toolcall-test".to_string()),
                tool_name: "system.status".to_string(),
                tool_manifest_sha256: "c".repeat(64),
                accepted_plan_sha256: "d".repeat(64),
                arguments_sha256: "a".repeat(64),
            }),
            status: ToolRunStatus::Requested,
            requested_at_unix_ms: 10,
            started_at_unix_ms: None,
            finished_at_unix_ms: None,
            output: None,
            error: None,
            approval_id: None,
            policy_decision: Some(PolicyDecision::allow("unit")),
        };
        store.save_tool_run(&run).expect("tool run should save");
        assert!(
            !store
                .insert_tool_run_if_absent(&run)
                .expect("duplicate tool run insert should be checked")
        );

        run.mark_succeeded(json!({"ok": true}));
        store.save_tool_run(&run).expect("tool run should update");

        let loaded = store
            .load_tool_run("toolcall-test")
            .expect("tool run should load")
            .expect("tool run should exist");
        assert_eq!(loaded.status, ToolRunStatus::Succeeded);
        assert_eq!(
            loaded
                .agent_execution_binding
                .as_ref()
                .expect("agent execution binding")
                .plan_id,
            "plan-persistence-test"
        );
        assert_eq!(loaded.output.expect("output")["ok"], true);
        assert_eq!(store.list_tool_runs(None, 10).expect("list").len(), 1);
        assert_eq!(
            store
                .list_tool_runs(Some("task-test"), 10)
                .expect("list by task")
                .len(),
            1
        );
    }

    #[test]
    fn ambiguous_post_start_finish_is_atomically_indeterminate_not_failed() {
        let store = AuditStore::open_memory().expect("audit store should open");
        let mut task = TaskView {
            id: TaskId("task-ambiguous-finish".to_string()),
            title: "ambiguous external action".to_string(),
            description: Some("fixture".to_string()),
            status: TaskStatus::Running,
            created_at_unix_ms: 10,
            updated_at_unix_ms: 11,
            metadata: json!({}),
        };
        let mut run = ToolRun {
            task_id: task.id.clone(),
            tool_call_id: ToolCallId("toolcall-ambiguous-finish".to_string()),
            tool_name: "android.notification.post_bounded".to_string(),
            arguments: json!({"payload": {"title": "fixture", "body": "fixture"}}),
            agent_execution_binding: None,
            status: ToolRunStatus::Running,
            requested_at_unix_ms: 10,
            started_at_unix_ms: Some(11),
            finished_at_unix_ms: None,
            output: Some(json!({"must_not": "survive"})),
            error: None,
            approval_id: None,
            policy_decision: Some(PolicyDecision::allow("fixture")),
        };
        store.save_task(&task).unwrap();
        store.save_tool_run(&run).unwrap();

        run.mark_indeterminate("gateway response lost after durable ToolStarted");
        task.status = TaskStatus::Indeterminate;
        task.updated_at_unix_ms = 12;
        let event = AuditEvent::new(
            AuditEventKind::ToolFailed,
            "tool outcome indeterminate: android.notification.post_bounded",
        )
        .with_task(task.id.clone())
        .with_tool_call(run.tool_call_id.clone())
        .with_payload(json!({
            "tool_run": run.clone(),
            "indeterminate": true,
            "automatic_replay_forbidden": true,
        }));
        assert!(
            store
                .persist_tool_execution_finish_atomic(&task, &run, &event)
                .unwrap()
        );

        let durable_task = store
            .load_tasks()
            .unwrap()
            .into_iter()
            .find(|candidate| candidate.id == task.id)
            .unwrap();
        let durable_run = store.load_tool_run(&run.tool_call_id.0).unwrap().unwrap();
        assert_eq!(durable_task.status, TaskStatus::Indeterminate);
        assert_eq!(durable_run.status, ToolRunStatus::Indeterminate);
        assert!(durable_run.output.is_none());
        assert!(
            durable_run
                .error
                .as_deref()
                .unwrap()
                .contains("gateway response lost")
        );
        assert_ne!(durable_task.status, TaskStatus::Failed);
        assert_ne!(durable_run.status, ToolRunStatus::Failed);
    }
}
