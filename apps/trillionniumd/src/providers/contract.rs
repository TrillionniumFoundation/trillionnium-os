//! Provider-neutral adapter contract.
//!
//! `register` returns a descriptor for conformance and health reporting. It
//! does not provision an Agent identity: only the OS-owned AgentManifest
//! loader may mutate the authoritative registration store.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use trillionnium_os_types::AgentPlanSubmission;
use trillionnium_os_types::{AGENT_API_VERSION, AgentNetworkPolicy};
#[cfg(test)]
use trillionnium_tool_runtime::supervised_codex::PlanningRequest;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAdapterExecutionMode {
    AgentDirect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAdapterRegistration {
    pub api_version: String,
    pub agent_id: String,
    pub adapter: String,
    pub adapter_version: String,
    pub network_policy: AgentNetworkPolicy,
    pub execution_mode: AgentAdapterExecutionMode,
}

impl AgentAdapterRegistration {
    pub fn agent_direct(
        agent_id: impl Into<String>,
        adapter: impl Into<String>,
        adapter_version: impl Into<String>,
    ) -> Self {
        Self {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: agent_id.into(),
            adapter: adapter.into(),
            adapter_version: adapter_version.into(),
            network_policy: AgentNetworkPolicy::PerRequest,
            execution_mode: AgentAdapterExecutionMode::AgentDirect,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentAdapterHealth {
    pub ready: bool,
    pub provider: String,
    pub detail: String,
    pub facts: Value,
}

/// A replaceable direct intelligence adapter. Terminal results flow through
/// each adapter's durable direct-result path.
#[allow(dead_code)]
pub trait AgentAdapter: Send + Sync {
    fn register(&self) -> AgentAdapterRegistration;
    fn health(&self) -> AgentAdapterHealth;
    #[cfg(test)]
    fn plan(&self, request: &PlanningRequest, session_id: &str) -> Result<AgentPlanSubmission>;
    fn cancel(&self);
}

/// Serializes direct invocations per adapter while leaving cancellation
/// lock-free with respect to the active subprocess.
#[derive(Default)]
pub(crate) struct AdapterRunState {
    invocation: Mutex<()>,
    active_cancel: Mutex<Option<Arc<AtomicBool>>>,
}

struct ActiveAdapterRun<'a> {
    state: &'a AdapterRunState,
}

impl Drop for ActiveAdapterRun<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.state.active_cancel.lock() {
            active.take();
        }
    }
}

#[allow(dead_code)]
impl AdapterRunState {
    pub(crate) fn run<T>(&self, operation: impl FnOnce(&AtomicBool) -> Result<T>) -> Result<T> {
        self.run_with_cancellation(Arc::new(AtomicBool::new(false)), operation)
    }

    pub(crate) fn run_with_cancellation<T>(
        &self,
        cancelled: Arc<AtomicBool>,
        operation: impl FnOnce(&AtomicBool) -> Result<T>,
    ) -> Result<T> {
        let _invocation = self
            .invocation
            .lock()
            .map_err(|_| anyhow::anyhow!("adapter invocation lock poisoned"))?;
        *self
            .active_cancel
            .lock()
            .map_err(|_| anyhow::anyhow!("adapter cancellation lock poisoned"))? =
            Some(Arc::clone(&cancelled));
        let _active = ActiveAdapterRun { state: self };
        operation(&cancelled)
    }

    pub(crate) fn cancel(&self) {
        if let Ok(active) = self.active_cancel.lock()
            && let Some(cancelled) = active.as_ref()
        {
            cancelled.store(true, Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    #[test]
    fn direct_run_installs_and_clears_one_cancellation_token() {
        let state = AdapterRunState::default();
        let result = state
            .run(|cancelled| {
                assert!(!cancelled.load(Ordering::SeqCst));
                state.cancel();
                assert!(cancelled.load(Ordering::SeqCst));
                Ok("done")
            })
            .unwrap();
        assert_eq!(result, "done");
        assert!(state.active_cancel.lock().unwrap().is_none());
    }

    #[test]
    fn direct_run_preserves_a_cancellation_latched_before_start() {
        let state = AdapterRunState::default();
        let cancelled = Arc::new(AtomicBool::new(true));
        state
            .run_with_cancellation(Arc::clone(&cancelled), |active| {
                assert!(active.load(Ordering::SeqCst));
                Ok(())
            })
            .unwrap();
        assert!(cancelled.load(Ordering::SeqCst));
        assert!(state.active_cancel.lock().unwrap().is_none());
    }

    #[test]
    fn provider_panic_does_not_leave_a_stale_cancellation_token() {
        let state = AdapterRunState::default();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = state.run::<()>(|_| panic!("provider panic fixture"));
        }));
        assert!(panic.is_err());
        assert!(state.active_cancel.lock().unwrap().is_none());
    }
}
