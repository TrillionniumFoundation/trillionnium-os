use std::collections::BTreeMap;

use serde_json::json;
use trillionnium_os_types::{
    ApprovalGrant, ApprovalLifetime, ApprovalRequest, ApprovalStatus, ApprovalSubmission,
    ApprovalSummary, TaskId, TaskInput, TaskStatus, TaskSummary, TaskView, now_unix_ms,
};
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct TaskRegistry {
    tasks: BTreeMap<String, TaskView>,
    approvals: BTreeMap<String, ApprovalRequest>,
}

impl TaskRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_records(tasks: Vec<TaskView>, approvals: Vec<ApprovalRequest>) -> Self {
        Self {
            tasks: tasks
                .into_iter()
                .map(|task| (task.id.0.clone(), task))
                .collect(),
            approvals: approvals
                .into_iter()
                .map(|approval| (approval.id.clone(), approval))
                .collect(),
        }
    }

    pub fn create_task(&mut self, input: TaskInput) -> TaskView {
        let now = now_unix_ms();
        let title = if input.title.trim().is_empty() {
            "Untitled task".to_string()
        } else {
            input.title.trim().to_string()
        };
        let task = TaskView {
            id: TaskId::new(),
            title,
            description: input.description,
            status: TaskStatus::Created,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
            metadata: input.metadata,
        };
        self.tasks.insert(task.id.0.clone(), task.clone());
        task
    }

    pub fn list_tasks(&self) -> Vec<TaskSummary> {
        self.tasks
            .values()
            .map(TaskView::summary)
            .collect::<Vec<_>>()
    }

    pub fn list_task_views(&self) -> Vec<TaskView> {
        self.tasks.values().cloned().collect::<Vec<_>>()
    }

    pub fn get_task(&self, task_id: &str) -> Option<TaskView> {
        self.tasks.get(task_id).cloned()
    }

    /// Synchronizes an already committed durable task snapshot into the
    /// process-local cache. Callers must never use this to bypass persistence.
    pub fn apply_persisted_task(&mut self, task: TaskView) -> Option<TaskView> {
        if !self.tasks.contains_key(&task.id.0) {
            return None;
        }
        self.tasks.insert(task.id.0.clone(), task.clone());
        Some(task)
    }

    pub fn update_task_status(&mut self, task_id: &str, status: TaskStatus) -> Option<TaskView> {
        let task = self.tasks.get_mut(task_id)?;
        if matches!(
            task.status,
            TaskStatus::Indeterminate
                | TaskStatus::Completed
                | TaskStatus::Failed
                | TaskStatus::Cancelled
        ) && task.status != status
        {
            return None;
        }
        // Until a cooperative running-tool cancellation protocol exists, a
        // cancel request must not claim success while an external side effect
        // may already be executing.
        if task.status == TaskStatus::Running && status == TaskStatus::Cancelled {
            return None;
        }
        task.status = status;
        task.updated_at_unix_ms = now_unix_ms();
        Some(task.clone())
    }

    /// Atomically claims the task for the single tool execution that is about
    /// to cross the side-effect boundary. `Running` is an execution lease, not
    /// a general "task is open" state: a second executor and cancellation must
    /// race on this same registry lock, and exactly one may win.
    pub fn claim_task_for_execution(&mut self, task_id: &str) -> Option<TaskView> {
        let task = self.tasks.get_mut(task_id)?;
        if matches!(
            task.status,
            TaskStatus::Running
                | TaskStatus::Indeterminate
                | TaskStatus::Completed
                | TaskStatus::Failed
                | TaskStatus::Cancelled
        ) {
            return None;
        }
        task.status = TaskStatus::Running;
        task.updated_at_unix_ms = now_unix_ms();
        Some(task.clone())
    }

    pub fn cancel_task(&mut self, task_id: &str) -> Option<TaskView> {
        let task = self.update_task_status(task_id, TaskStatus::Cancelled)?;
        self.terminate_pending_approvals(task_id, "task cancelled before approval execution");
        Some(task)
    }

    pub fn terminate_pending_approvals(
        &mut self,
        task_id: &str,
        reason: &str,
    ) -> Vec<ApprovalRequest> {
        let now = now_unix_ms();
        let mut terminated = Vec::new();
        for approval in self.approvals.values_mut() {
            if approval.task_id.0 == task_id && approval.status == ApprovalStatus::Pending {
                approval.status = ApprovalStatus::Denied;
                approval.decided_at_unix_ms = Some(now);
                approval.decision_reason = Some(reason.to_string());
                terminated.push(approval.clone());
            }
        }
        terminated
    }

    pub fn request_approval(&mut self, submission: ApprovalSubmission) -> Option<ApprovalRequest> {
        if !self.tasks.get(&submission.task_id.0).is_some_and(|task| {
            !matches!(
                task.status,
                TaskStatus::Indeterminate
                    | TaskStatus::Completed
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
            )
        }) {
            return None;
        }

        let now = now_unix_ms();
        let request = ApprovalRequest {
            id: format!("approval-{}", Uuid::new_v4()),
            task_id: submission.task_id,
            tool_call_id: submission.tool_call_id.unwrap_or_default(),
            tool_name: submission.tool_name,
            reason: submission.reason,
            status: ApprovalStatus::Pending,
            created_at_unix_ms: now,
            decided_at_unix_ms: None,
            decision_reason: None,
            tool_manifest_sha256: None,
        };
        if let Some(task) = self.tasks.get_mut(&request.task_id.0) {
            task.status = TaskStatus::WaitingForApproval;
            task.updated_at_unix_ms = now;
        }
        self.approvals.insert(request.id.clone(), request.clone());
        Some(request)
    }

    pub fn bind_approval_manifest(
        &mut self,
        approval_id: &str,
        tool_manifest_sha256: String,
    ) -> Option<ApprovalRequest> {
        let request = self.approvals.get_mut(approval_id)?;
        if request.status != ApprovalStatus::Pending || request.tool_manifest_sha256.is_some() {
            return None;
        }
        request.tool_manifest_sha256 = Some(tool_manifest_sha256);
        Some(request.clone())
    }

    pub fn approve(&mut self, approval_id: &str) -> Option<(ApprovalRequest, ApprovalGrant)> {
        self.approve_with_lifetime(approval_id, ApprovalLifetime::OneCall)
    }

    pub fn approve_with_lifetime(
        &mut self,
        approval_id: &str,
        lifetime: ApprovalLifetime,
    ) -> Option<(ApprovalRequest, ApprovalGrant)> {
        let request = self.approvals.get_mut(approval_id)?;
        if request.status != ApprovalStatus::Pending {
            return None;
        }
        if !self.tasks.get(&request.task_id.0).is_some_and(|task| {
            !matches!(
                task.status,
                TaskStatus::Indeterminate
                    | TaskStatus::Completed
                    | TaskStatus::Failed
                    | TaskStatus::Cancelled
            )
        }) {
            return None;
        }
        request.status = ApprovalStatus::Approved;
        request.decided_at_unix_ms = Some(now_unix_ms());
        request.decision_reason = Some(format!("approved by OS authority ({lifetime:?})"));

        let grant = ApprovalGrant::scoped(
            request.tool_name.clone(),
            request.tool_call_id.clone(),
            request.task_id.clone(),
            lifetime,
        );
        if let Some(task) = self.tasks.get_mut(&request.task_id.0) {
            // Approval is not execution. Keep the task cancellable until the
            // executor atomically claims it immediately before side effects.
            task.updated_at_unix_ms = now_unix_ms();
            set_last_approval_metadata(task, &request.id, "approved");
        }
        Some((request.clone(), grant))
    }

    pub fn deny(&mut self, approval_id: &str, reason: String) -> Option<ApprovalRequest> {
        let request = self.approvals.get_mut(approval_id)?;
        if request.status != ApprovalStatus::Pending {
            return None;
        }
        request.status = ApprovalStatus::Denied;
        request.decided_at_unix_ms = Some(now_unix_ms());
        request.decision_reason = Some(reason);
        if let Some(task) = self.tasks.get_mut(&request.task_id.0) {
            task.status = TaskStatus::Failed;
            task.updated_at_unix_ms = now_unix_ms();
            set_last_approval_metadata(task, &request.id, "denied");
        }
        Some(request.clone())
    }

    pub fn list_approvals(&self) -> Vec<ApprovalSummary> {
        self.approvals
            .values()
            .map(ApprovalRequest::summary)
            .collect::<Vec<_>>()
    }

    pub fn list_approval_requests(&self) -> Vec<ApprovalRequest> {
        self.approvals.values().cloned().collect::<Vec<_>>()
    }
}

fn set_last_approval_metadata(task: &mut TaskView, approval_id: &str, status: &str) {
    if !task.metadata.is_object() {
        task.metadata = json!({});
    }
    if let Some(metadata) = task.metadata.as_object_mut() {
        metadata.insert(
            "last_approval".to_string(),
            json!({
                "approval_id": approval_id,
                "status": status
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use trillionnium_os_types::{ApprovalStatus, TaskInput};

    use super::*;

    #[test]
    fn creates_and_lists_tasks() {
        let mut registry = TaskRegistry::new();
        let task = registry.create_task(TaskInput {
            title: "Check daemon".into(),
            ..TaskInput::default()
        });

        assert_eq!(registry.list_tasks().len(), 1);
        assert_eq!(
            registry
                .get_task(&task.id.0)
                .expect("task should exist")
                .title,
            "Check daemon"
        );
    }

    #[test]
    fn approval_lifecycle_updates_task_state() {
        let mut registry = TaskRegistry::new();
        let task = registry.create_task(TaskInput {
            title: "Read file".into(),
            ..TaskInput::default()
        });
        let approval = registry
            .request_approval(ApprovalSubmission {
                task_id: task.id.clone(),
                tool_call_id: None,
                tool_name: "files.read".into(),
                reason: "medium risk".into(),
            })
            .expect("approval should be requested");

        assert_eq!(approval.status, ApprovalStatus::Pending);
        assert_eq!(
            registry
                .get_task(&task.id.0)
                .expect("task should exist")
                .status,
            TaskStatus::WaitingForApproval
        );

        let (approved, grant) = registry
            .approve(&approval.id)
            .expect("approval should approve");

        assert_eq!(approved.status, ApprovalStatus::Approved);
        assert_eq!(grant.tool_name, "files.read");
        assert_eq!(grant.lifetime, ApprovalLifetime::OneCall);
        assert_eq!(
            registry
                .get_task(&task.id.0)
                .expect("task should exist")
                .status,
            TaskStatus::WaitingForApproval
        );
    }

    #[test]
    fn execution_claim_and_cancel_are_mutually_exclusive() {
        let mut registry = TaskRegistry::new();
        let task = registry.create_task(TaskInput {
            title: "claim versus cancel".into(),
            ..TaskInput::default()
        });
        let task_id = task.id.0;
        let registry = std::sync::Arc::new(std::sync::Mutex::new(registry));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let claim_handle = {
            let registry = std::sync::Arc::clone(&registry);
            let barrier = std::sync::Arc::clone(&barrier);
            let task_id = task_id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                registry
                    .lock()
                    .expect("registry lock")
                    .claim_task_for_execution(&task_id)
                    .is_some()
            })
        };
        let cancel_handle = {
            let registry = std::sync::Arc::clone(&registry);
            let barrier = std::sync::Arc::clone(&barrier);
            let task_id = task_id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                registry
                    .lock()
                    .expect("registry lock")
                    .cancel_task(&task_id)
                    .is_some()
            })
        };

        let claimed = claim_handle.join().expect("claim thread");
        let cancelled = cancel_handle.join().expect("cancel thread");
        assert_ne!(claimed, cancelled, "exactly one transition must win");
        let final_status = registry
            .lock()
            .expect("registry lock")
            .get_task(&task_id)
            .expect("task")
            .status;
        assert_eq!(
            final_status,
            if claimed {
                TaskStatus::Running
            } else {
                TaskStatus::Cancelled
            }
        );
    }

    #[test]
    fn approval_can_create_current_task_grant() {
        let mut registry = TaskRegistry::new();
        let task = registry.create_task(TaskInput {
            title: "Read multiple files".into(),
            ..TaskInput::default()
        });
        let approval = registry
            .request_approval(ApprovalSubmission {
                task_id: task.id.clone(),
                tool_call_id: None,
                tool_name: "files.read".into(),
                reason: "medium risk".into(),
            })
            .expect("approval should be requested");

        let (_approved, grant) = registry
            .approve_with_lifetime(&approval.id, ApprovalLifetime::CurrentTask)
            .expect("approval should approve");

        assert_eq!(grant.lifetime, ApprovalLifetime::CurrentTask);
        assert_eq!(grant.task_id, Some(task.id));
        assert_eq!(grant.tool_call_id, None);
    }

    #[test]
    fn records_can_round_trip_through_registry() {
        let mut registry = TaskRegistry::new();
        let task = registry.create_task(TaskInput {
            title: "Persistent task".into(),
            ..TaskInput::default()
        });
        let approval = registry
            .request_approval(ApprovalSubmission {
                task_id: task.id.clone(),
                tool_call_id: None,
                tool_name: "files.read".into(),
                reason: "needs approval".into(),
            })
            .expect("approval should be requested");

        let loaded = TaskRegistry::from_records(
            registry.list_task_views(),
            registry.list_approval_requests(),
        );

        assert_eq!(
            loaded.get_task(&task.id.0).expect("task should load").title,
            "Persistent task"
        );
        assert_eq!(loaded.list_approvals()[0].id, approval.id);
    }
}
