//! Deterministic mechanical control in OBSERVE/SHADOW mode.
//!
//! The controller owns only budgets, leases, epochs and fencing.  It has no
//! semantic request fields and cannot authorize a command, retry an effect or
//! rewrite provider output.  Existing non-expired leases may continue during
//! a controller outage; new effectful admissions are rejected until authority
//! returns.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LEASE_SCHEMA: &str = "trillionnium.owner-open.control-lease.v1";
pub const OBSERVATION_SCHEMA: &str = "trillionnium.owner-open.module-observation.v1";
pub const DECISION_SCHEMA: &str = "trillionnium.owner-open.shadow-decision.v1";
pub const MODULE_INSTANCE_SCHEMA: &str = "trillionnium.owner-open.module-instance.v1";
pub const AUDIT_ENTRY_SCHEMA: &str = "trillionnium.owner-open.decision-audit-entry.v1";
pub const DEFAULT_MAX_MODULE_INSTANCES: usize = 4096;
pub const DEFAULT_MAX_AUDIT_ENTRIES: usize = 4096;
pub const MAX_MODULE_REGISTRY_ENTRIES: usize = 1_048_576;
pub const MAX_AUDIT_ENTRIES: usize = 1_048_576;
pub const MAX_SHADOW_RECOMMENDATIONS: usize = MAX_CONTROLLER_INDEX_ENTRIES;
pub const MAX_SHADOW_OBSERVATION_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SHADOW_DECISION_BYTES: usize = 64 * 1024 * 1024;
pub const SHADOW_POLICY_SCHEMA: &str = "trillionnium.owner-open.shadow-policy.v1";

/// Serializes transitions that must observe one control epoch across the
/// controller, its module registry and its decision audit.  The individual
/// state mutexes remain separate so ordinary reads/writes do not hold a lock
/// across unrelated data structures; callers which touch more than one of
/// them take this gate first.
type EpochGate = Arc<Mutex<()>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    Invalid(String),
    EpochMismatch,
    FencingMismatch,
    LeaseExpired,
    AuthorityUnavailable,
    UnsupportedMode,
    CapacityExceeded,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::EpochMismatch => f.write_str("control epoch is stale"),
            Self::FencingMismatch => f.write_str("fencing token is stale"),
            Self::LeaseExpired => f.write_str("control lease is expired"),
            Self::AuthorityUnavailable => f.write_str("control authority is unavailable"),
            Self::UnsupportedMode => f.write_str("active control modes are not enabled"),
            Self::CapacityExceeded => f.write_str("requested admission exceeds lease budget"),
        }
    }
}

impl std::error::Error for ControlError {}

pub type Result<T> = std::result::Result<T, ControlError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlMode {
    Observe,
    Shadow,
    Advisory,
    ActiveCanary,
    Active,
}

impl ControlMode {
    pub fn is_shadow_safe(self) -> bool {
        matches!(self, Self::Observe | Self::Shadow)
    }
}

/// Versioned, mechanical stability controls for shadow recommendations.
/// These controls shape a shadow projection only; they never authorize an
/// effect or mutate a module's semantic state.  The controller may retain a
/// bounded projection history so hysteresis is deterministic across calls.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowPolicy {
    pub schema: String,
    pub version: String,
    pub health_guard_threshold: f64,
    pub health_recover_threshold: f64,
    pub rollback_unknown_rate_threshold: f64,
    pub max_adjustment: u32,
    pub min_dwell_ms: u64,
    pub cooldown_ms: u64,
}

impl Default for ShadowPolicy {
    fn default() -> Self {
        Self {
            schema: SHADOW_POLICY_SCHEMA.to_string(),
            version: "shadow-policy-v1".to_string(),
            health_guard_threshold: 0.5,
            health_recover_threshold: 0.7,
            rollback_unknown_rate_threshold: 0.5,
            max_adjustment: 1,
            min_dwell_ms: 10,
            cooldown_ms: 10,
        }
    }
}

impl ShadowPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SHADOW_POLICY_SCHEMA
            || self.version.trim().is_empty()
            || self.version.len() > 128
        {
            return Err(ControlError::Invalid(
                "shadow policy schema or version is invalid".into(),
            ));
        }
        for (name, value) in [
            ("health_guard_threshold", self.health_guard_threshold),
            ("health_recover_threshold", self.health_recover_threshold),
            (
                "rollback_unknown_rate_threshold",
                self.rollback_unknown_rate_threshold,
            ),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                return Err(ControlError::Invalid(format!(
                    "shadow policy {name} must be finite and in [0,1]"
                )));
            }
        }
        if self.health_recover_threshold < self.health_guard_threshold {
            return Err(ControlError::Invalid(
                "shadow policy recovery threshold must not be below guard threshold".into(),
            ));
        }
        if self.max_adjustment == 0 {
            return Err(ControlError::Invalid(
                "shadow policy max adjustment must be non-zero".into(),
            ));
        }
        if self.max_adjustment > MAX_RESOURCE_CONCURRENCY {
            return Err(ControlError::Invalid(format!(
                "shadow policy max adjustment exceeds hard bound {MAX_RESOURCE_CONCURRENCY}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModuleInstanceStatus {
    Registered,
    Draining,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInstanceKey {
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
}

impl ModuleInstanceKey {
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("module_id", self.module_id.as_str()),
            ("module_instance_id", self.module_instance_id.as_str()),
            ("partition", self.partition.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(ControlError::Invalid(format!(
                    "module instance {name} is invalid"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInstance {
    pub schema: String,
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
    pub version: String,
    pub control_epoch: u64,
    pub fencing_token: String,
    pub status: ModuleInstanceStatus,
    pub registered_at_ms: u64,
    pub last_seen_at_ms: u64,
}

impl ModuleInstance {
    pub fn key(&self) -> ModuleInstanceKey {
        ModuleInstanceKey {
            module_id: self.module_id.clone(),
            module_instance_id: self.module_instance_id.clone(),
            partition: self.partition.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != MODULE_INSTANCE_SCHEMA {
            return Err(ControlError::Invalid(
                "module instance schema mismatch".into(),
            ));
        }
        self.key().validate()?;
        if self.version.trim().is_empty() || self.version.len() > 256 {
            return Err(ControlError::Invalid(
                "module instance version is invalid".into(),
            ));
        }
        if self.control_epoch == 0
            || self.fencing_token.trim().is_empty()
            || self.fencing_token.len() > 256
        {
            return Err(ControlError::Invalid(
                "module instance epoch or fencing token is invalid".into(),
            ));
        }
        if self.registered_at_ms > self.last_seen_at_ms {
            return Err(ControlError::Invalid(
                "module instance timestamps are not monotonic".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleRegistryLimits {
    pub max_instances: usize,
}

impl Default for ModuleRegistryLimits {
    fn default() -> Self {
        Self {
            max_instances: DEFAULT_MAX_MODULE_INSTANCES,
        }
    }
}

impl ModuleRegistryLimits {
    fn validate(self) -> Result<()> {
        if self.max_instances == 0 || self.max_instances > MAX_MODULE_REGISTRY_ENTRIES {
            return Err(ControlError::Invalid(format!(
                "module registry limit must be between 1 and {MAX_MODULE_REGISTRY_ENTRIES}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ModuleRegistryState {
    current_epoch: u64,
    limits: ModuleRegistryLimits,
    instances: BTreeMap<ModuleInstanceKey, ModuleInstance>,
}

/// Bounded, thread-safe ownership of live module-instance identities.
/// Registration and heartbeats are monotonic and epoch/fencing checked; a
/// stale instance can never overwrite a newer registration.
#[derive(Debug, Clone)]
pub struct ModuleInstanceRegistry {
    inner: Arc<Mutex<ModuleRegistryState>>,
    epoch_gate: EpochGate,
}

impl ModuleInstanceRegistry {
    pub fn new(max_instances: usize) -> Result<Self> {
        Self::new_with_epoch(1, max_instances)
    }

    pub fn new_with_epoch(current_epoch: u64, max_instances: usize) -> Result<Self> {
        Self::new_with_epoch_and_gate(current_epoch, max_instances, Arc::new(Mutex::new(())))
    }

    fn new_with_epoch_and_gate(
        current_epoch: u64,
        max_instances: usize,
        epoch_gate: EpochGate,
    ) -> Result<Self> {
        if current_epoch == 0 {
            return Err(ControlError::Invalid(
                "module registry epoch must be non-zero".into(),
            ));
        }
        let limits = ModuleRegistryLimits { max_instances };
        limits.validate()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(ModuleRegistryState {
                current_epoch,
                limits,
                instances: BTreeMap::new(),
            })),
            epoch_gate,
        })
    }

    pub fn limits(&self) -> ModuleRegistryLimits {
        let Ok(_epoch_guard) = self.epoch_gate.lock() else {
            return ModuleRegistryLimits::default();
        };
        self.inner
            .lock()
            .map(|state| state.limits)
            .unwrap_or_default()
    }

    pub fn current_epoch(&self) -> u64 {
        let Ok(_epoch_guard) = self.epoch_gate.lock() else {
            return 0;
        };
        self.inner
            .lock()
            .map(|state| state.current_epoch)
            .unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        let Ok(_epoch_guard) = self.epoch_gate.lock() else {
            return 0;
        };
        self.inner
            .lock()
            .map(|state| state.instances.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn register(&self, instance: ModuleInstance) -> Result<()> {
        instance.validate()?;
        let key = instance.key();
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("module registry epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        Self::register_locked(&mut state, instance, key)
    }

    fn register_locked(
        state: &mut ModuleRegistryState,
        instance: ModuleInstance,
        key: ModuleInstanceKey,
    ) -> Result<()> {
        if instance.control_epoch != state.current_epoch {
            return Err(ControlError::EpochMismatch);
        }
        if instance.fencing_token != format!("epoch-{}", state.current_epoch) {
            return Err(ControlError::FencingMismatch);
        }
        if let Some(previous) = state.instances.get(&key) {
            if previous == &instance {
                return Ok(());
            }
            return Err(ControlError::Invalid(
                "module instance registration conflicts with an existing identity".into(),
            ));
        }
        if state.instances.len() >= state.limits.max_instances {
            return Err(ControlError::CapacityExceeded);
        }
        state.instances.insert(key, instance);
        Ok(())
    }

    pub fn register_instance(
        &self,
        module_id: &str,
        module_instance_id: &str,
        partition: &str,
        version: &str,
        now_ms: u64,
    ) -> Result<ModuleInstance> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("module registry epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        let epoch = state.current_epoch;
        let instance = ModuleInstance {
            schema: MODULE_INSTANCE_SCHEMA.to_string(),
            module_id: module_id.to_string(),
            module_instance_id: module_instance_id.to_string(),
            partition: partition.to_string(),
            version: version.to_string(),
            control_epoch: epoch,
            fencing_token: format!("epoch-{epoch}"),
            status: ModuleInstanceStatus::Registered,
            registered_at_ms: now_ms,
            last_seen_at_ms: now_ms,
        };
        // Keep the convenience constructor subject to the exact same wire
        // contract as `register(instance)`.  Without this check an empty or
        // overlong identity could enter the authoritative registry simply by
        // using the string-argument API.
        instance.validate()?;
        Self::register_locked(&mut state, instance.clone(), instance.key())?;
        Ok(instance)
    }

    pub fn heartbeat(
        &self,
        key: &ModuleInstanceKey,
        control_epoch: u64,
        fencing_token: &str,
        now_ms: u64,
    ) -> Result<ModuleInstance> {
        key.validate()?;
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("module registry epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        Self::heartbeat_locked(&mut state, key, control_epoch, fencing_token, now_ms)
    }

    fn heartbeat_locked(
        state: &mut ModuleRegistryState,
        key: &ModuleInstanceKey,
        control_epoch: u64,
        fencing_token: &str,
        now_ms: u64,
    ) -> Result<ModuleInstance> {
        if control_epoch != state.current_epoch {
            return Err(ControlError::EpochMismatch);
        }
        if fencing_token != format!("epoch-{}", state.current_epoch) {
            return Err(ControlError::FencingMismatch);
        }
        let instance = state
            .instances
            .get_mut(key)
            .ok_or_else(|| ControlError::Invalid("module instance is not registered".into()))?;
        if instance.control_epoch != control_epoch || instance.fencing_token != fencing_token {
            return Err(ControlError::FencingMismatch);
        }
        if now_ms < instance.last_seen_at_ms {
            return Err(ControlError::Invalid(
                "module heartbeat timestamp regressed".into(),
            ));
        }
        instance.last_seen_at_ms = now_ms;
        if instance.status == ModuleInstanceStatus::Offline {
            instance.status = ModuleInstanceStatus::Registered;
        }
        Ok(instance.clone())
    }

    pub fn set_status(
        &self,
        key: &ModuleInstanceKey,
        control_epoch: u64,
        fencing_token: &str,
        status: ModuleInstanceStatus,
        now_ms: u64,
    ) -> Result<()> {
        key.validate()?;
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("module registry epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        // Heartbeat validation and status transition intentionally share one
        // state lock.  A separate heartbeat call would permit unregister and
        // same-key re-registration between the two operations, allowing a
        // stale caller to mutate the replacement instance.
        let _ = Self::heartbeat_locked(&mut state, key, control_epoch, fencing_token, now_ms)?;
        let instance = state
            .instances
            .get_mut(key)
            .ok_or_else(|| ControlError::Invalid("module instance is not registered".into()))?;
        if instance.control_epoch != control_epoch || instance.fencing_token != fencing_token {
            return Err(ControlError::FencingMismatch);
        }
        instance.status = status;
        Ok(())
    }

    pub fn unregister(
        &self,
        key: &ModuleInstanceKey,
        control_epoch: u64,
        fencing_token: &str,
    ) -> Result<ModuleInstance> {
        key.validate()?;
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("module registry epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        if control_epoch != state.current_epoch {
            return Err(ControlError::EpochMismatch);
        }
        if fencing_token != format!("epoch-{}", state.current_epoch) {
            return Err(ControlError::FencingMismatch);
        }
        let instance = state
            .instances
            .get(key)
            .cloned()
            .ok_or_else(|| ControlError::Invalid("module instance is not registered".into()))?;
        if instance.control_epoch != control_epoch || instance.fencing_token != fencing_token {
            return Err(ControlError::FencingMismatch);
        }
        state.instances.remove(key);
        Ok(instance)
    }

    pub fn get(&self, key: &ModuleInstanceKey) -> Result<Option<ModuleInstance>> {
        key.validate()?;
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("module registry epoch gate poisoned".into()))?;
        let state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        Ok(state.instances.get(key).cloned())
    }

    pub fn snapshot(&self) -> Result<Vec<ModuleInstance>> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("module registry epoch gate poisoned".into()))?;
        let state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        Ok(state.instances.values().cloned().collect())
    }

    pub fn rotate_epoch(&self, next_epoch: u64) -> Result<()> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("module registry epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        Self::rotate_epoch_locked(&mut state, next_epoch)
    }

    fn rotate_epoch_locked(state: &mut ModuleRegistryState, next_epoch: u64) -> Result<()> {
        if next_epoch <= state.current_epoch {
            return Err(ControlError::EpochMismatch);
        }
        state.current_epoch = next_epoch;
        state.instances.clear();
        Ok(())
    }
}

/// Bind a lease to the authoritative module-instance registry.  Epoch and
/// fencing checks on a lease alone are insufficient: a caller could otherwise
/// forge a current-looking identity or continue using a lease after its
/// instance was removed.  Callers choose whether a path is effectful (which
/// requires `Registered`) or read-only cleanup (which may inspect a draining
/// or offline instance while retaining the exact epoch/fence binding).
fn validate_registry_lease_binding(
    registry: &ModuleRegistryState,
    lease: &Lease,
    expected_epoch: u64,
    require_registered: bool,
) -> Result<()> {
    if registry.current_epoch != expected_epoch {
        return Err(ControlError::EpochMismatch);
    }
    let key = ModuleInstanceKey {
        module_id: lease.module_id.clone(),
        module_instance_id: lease.module_instance_id.clone(),
        partition: lease.partition.clone(),
    };
    let instance = registry
        .instances
        .get(&key)
        .ok_or_else(|| ControlError::Invalid("lease module instance is not registered".into()))?;
    if instance.control_epoch != lease.control_epoch {
        return Err(ControlError::EpochMismatch);
    }
    if instance.fencing_token != lease.fencing_token {
        return Err(ControlError::FencingMismatch);
    }
    if require_registered && instance.status != ModuleInstanceStatus::Registered {
        return Err(ControlError::Invalid(
            "module instance is not accepting effectful work".into(),
        ));
    }
    Ok(())
}

fn validate_registry_observation_binding(
    registry: &ModuleRegistryState,
    observation: &ModuleObservation,
    expected_epoch: u64,
    require_registered: bool,
) -> Result<()> {
    if registry.current_epoch != expected_epoch || observation.control_epoch != expected_epoch {
        return Err(ControlError::EpochMismatch);
    }
    let key = ModuleInstanceKey {
        module_id: observation.module_id.clone(),
        module_instance_id: observation.module_instance_id.clone(),
        partition: observation.partition.clone(),
    };
    let instance = registry.instances.get(&key).ok_or_else(|| {
        ControlError::Invalid("observation module instance is not registered".into())
    })?;
    if instance.control_epoch != expected_epoch {
        return Err(ControlError::EpochMismatch);
    }
    if instance.fencing_token != format!("epoch-{expected_epoch}") {
        return Err(ControlError::FencingMismatch);
    }
    if require_registered && instance.status != ModuleInstanceStatus::Registered {
        return Err(ControlError::Invalid(
            "module instance is not accepting observations".into(),
        ));
    }
    Ok(())
}

fn validate_observation_budget(observation: &ModuleObservation, lease: &Lease) -> Result<()> {
    if observation.queue_depth > lease.resource_budget.max_queue
        || observation.active_count > lease.maximum_concurrency
        || observation.cpu_millis > lease.resource_budget.max_cpu_millis
        || observation.memory_bytes > lease.resource_budget.max_memory_bytes
        || observation.io_bytes > lease.resource_budget.max_io_bytes
    {
        return Err(ControlError::CapacityExceeded);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceBudget {
    pub max_concurrency: u32,
    pub max_queue: u32,
    pub max_cpu_millis: u64,
    pub max_memory_bytes: u64,
    pub max_io_bytes: u64,
}

/// Hard ceilings for a single lease's mechanical resource budget.  These are
/// intentionally generous operational limits, not host-capacity claims: a
/// deployment may choose lower values, but a malformed configuration cannot
/// turn a lease into an effectively unbounded admission or accounting scope.
pub const MAX_RESOURCE_CONCURRENCY: u32 = 65_536;
pub const MAX_RESOURCE_QUEUE: u32 = 1_048_576;
pub const MAX_RESOURCE_CPU_MILLIS: u64 = 86_400_000; // 24 hours of CPU time.
pub const MAX_RESOURCE_MEMORY_BYTES: u64 = 1_u64 << 40; // 1 TiB.
pub const MAX_RESOURCE_IO_BYTES: u64 = 1_u64 << 40; // 1 TiB.

impl ResourceBudget {
    pub fn validate(&self) -> Result<()> {
        if self.max_concurrency == 0
            || self.max_queue == 0
            || self.max_cpu_millis == 0
            || self.max_memory_bytes == 0
            || self.max_io_bytes == 0
        {
            return Err(ControlError::Invalid(
                "resource budgets must be finite and non-zero".into(),
            ));
        }
        if self.max_concurrency > MAX_RESOURCE_CONCURRENCY {
            return Err(ControlError::Invalid(format!(
                "resource concurrency exceeds hard bound {MAX_RESOURCE_CONCURRENCY}"
            )));
        }
        if self.max_queue > MAX_RESOURCE_QUEUE {
            return Err(ControlError::Invalid(format!(
                "resource queue exceeds hard bound {MAX_RESOURCE_QUEUE}"
            )));
        }
        if self.max_cpu_millis > MAX_RESOURCE_CPU_MILLIS {
            return Err(ControlError::Invalid(format!(
                "resource CPU budget exceeds hard bound {MAX_RESOURCE_CPU_MILLIS}"
            )));
        }
        if self.max_memory_bytes > MAX_RESOURCE_MEMORY_BYTES {
            return Err(ControlError::Invalid(format!(
                "resource memory budget exceeds hard bound {MAX_RESOURCE_MEMORY_BYTES}"
            )));
        }
        if self.max_io_bytes > MAX_RESOURCE_IO_BYTES {
            return Err(ControlError::Invalid(format!(
                "resource I/O budget exceeds hard bound {MAX_RESOURCE_IO_BYTES}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub schema: String,
    pub control_epoch: u64,
    pub lease_id: String,
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
    pub resource_budget: ResourceBudget,
    pub maximum_concurrency: u32,
    pub priority_class: u16,
    pub fencing_token: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

impl Lease {
    pub fn validate(
        &self,
        now_ms: u64,
        expected_epoch: u64,
        expected_fencing_token: &str,
    ) -> Result<()> {
        if self.schema != LEASE_SCHEMA {
            return Err(ControlError::Invalid("lease schema mismatch".into()));
        }
        for (name, value) in [
            ("lease_id", self.lease_id.as_str()),
            ("module_id", self.module_id.as_str()),
            ("module_instance_id", self.module_instance_id.as_str()),
            ("partition", self.partition.as_str()),
            ("fencing_token", self.fencing_token.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(ControlError::Invalid(format!("lease {name} is invalid")));
            }
        }
        self.resource_budget.validate()?;
        if self.control_epoch != expected_epoch {
            return Err(ControlError::EpochMismatch);
        }
        if self.fencing_token != expected_fencing_token {
            return Err(ControlError::FencingMismatch);
        }
        if now_ms < self.issued_at_ms {
            return Err(ControlError::Invalid(
                "lease is not yet valid at the supplied timestamp".into(),
            ));
        }
        if self.issued_at_ms >= self.expires_at_ms || now_ms >= self.expires_at_ms {
            return Err(ControlError::LeaseExpired);
        }
        if self.maximum_concurrency == 0
            || self.maximum_concurrency > self.resource_budget.max_concurrency
        {
            return Err(ControlError::Invalid(
                "lease concurrency exceeds its resource budget".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleObservation {
    pub schema: String,
    pub control_epoch: u64,
    pub lease_id: String,
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
    pub observed_at_ms: u64,
    pub queue_depth: u32,
    pub active_count: u32,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub io_bytes: u64,
    pub latency_p99_ms: f64,
    pub unknown_rate: f64,
    pub health_score: f64,
}

impl ModuleObservation {
    pub fn validate(&self) -> Result<()> {
        if self.schema != OBSERVATION_SCHEMA {
            return Err(ControlError::Invalid("observation schema mismatch".into()));
        }
        for (name, value) in [
            ("module_id", self.module_id.as_str()),
            ("module_instance_id", self.module_instance_id.as_str()),
            ("partition", self.partition.as_str()),
            ("lease_id", self.lease_id.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(ControlError::Invalid(format!(
                    "observation {name} is invalid"
                )));
            }
        }
        for (name, value) in [
            ("latency_p99_ms", self.latency_p99_ms),
            ("unknown_rate", self.unknown_rate),
            ("health_score", self.health_score),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(ControlError::Invalid(format!(
                    "observation {name} must be finite and nonnegative"
                )));
            }
        }
        if self.unknown_rate > 1.0 || self.health_score > 1.0 {
            return Err(ControlError::Invalid(
                "observation rates/scores must be in [0,1]".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetRecommendation {
    pub module_id: String,
    pub module_instance_id: String,
    pub partition: String,
    pub recommended_concurrency: u32,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowDecision {
    pub schema: String,
    pub control_epoch: u64,
    pub generated_at_ms: u64,
    pub mode: ControlMode,
    pub observations_digest: String,
    pub recommendations: Vec<BudgetRecommendation>,
    pub effectful: bool,
    pub semantic_authority: String,
    pub decision_digest: String,
}

impl ShadowDecision {
    fn compute_digest(&self) -> Result<String> {
        let mut clone = self.clone();
        clone.decision_digest.clear();
        let bytes = serde_json::to_vec(&clone)
            .map_err(|error| ControlError::Invalid(format!("encode shadow decision: {error}")))?;
        if bytes.len() > MAX_SHADOW_DECISION_BYTES {
            return Err(ControlError::CapacityExceeded);
        }
        Ok(hex(&Sha256::digest(bytes)))
    }

    pub fn validate(&self, expected_epoch: u64) -> Result<()> {
        if self.schema != DECISION_SCHEMA {
            return Err(ControlError::Invalid(
                "shadow decision schema mismatch".into(),
            ));
        }
        if self.control_epoch != expected_epoch {
            return Err(ControlError::EpochMismatch);
        }
        if !self.mode.is_shadow_safe() {
            return Err(ControlError::UnsupportedMode);
        }
        if self.effectful || self.semantic_authority != "none" {
            return Err(ControlError::Invalid(
                "shadow decision contains semantic or effectful authority".into(),
            ));
        }
        if !is_digest(&self.observations_digest) || !is_digest(&self.decision_digest) {
            return Err(ControlError::Invalid(
                "shadow decision digests must be 256-bit hexadecimal values".into(),
            ));
        }
        if self.recommendations.len() > MAX_SHADOW_RECOMMENDATIONS {
            return Err(ControlError::CapacityExceeded);
        }
        let mut identities = BTreeSet::new();
        for recommendation in &self.recommendations {
            for (name, value) in [
                ("module_id", recommendation.module_id.as_str()),
                (
                    "module_instance_id",
                    recommendation.module_instance_id.as_str(),
                ),
                ("partition", recommendation.partition.as_str()),
                ("reason_code", recommendation.reason_code.as_str()),
            ] {
                if value.trim().is_empty() || value.len() > 256 {
                    return Err(ControlError::Invalid(format!(
                        "shadow recommendation {name} is invalid"
                    )));
                }
            }
            if recommendation.recommended_concurrency == 0 {
                return Err(ControlError::Invalid(
                    "shadow recommendation concurrency is zero".into(),
                ));
            }
            if !matches!(
                recommendation.reason_code.as_str(),
                "health_guard" | "unknown_guard" | "queue_pressure" | "steady_state"
            ) {
                return Err(ControlError::Invalid(
                    "shadow recommendation reason code is unknown".into(),
                ));
            }
            if !identities.insert((
                recommendation.module_id.as_str(),
                recommendation.module_instance_id.as_str(),
                recommendation.partition.as_str(),
            )) {
                return Err(ControlError::Invalid(
                    "shadow decision contains duplicate recommendations".into(),
                ));
            }
        }
        if self.decision_digest != self.compute_digest()? {
            return Err(ControlError::Invalid(
                "shadow decision digest does not match content".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionAuditKind {
    Decision,
    Rollback,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionAuditEntry {
    pub schema: String,
    pub sequence: u64,
    pub control_epoch: u64,
    pub recorded_at_ms: u64,
    pub kind: DecisionAuditKind,
    pub decision_digest: String,
    pub previous_entry_digest: Option<String>,
    pub target_digest: Option<String>,
    pub entry_digest: String,
}

impl DecisionAuditEntry {
    fn digest(&self) -> Result<String> {
        let mut clone = self.clone();
        clone.entry_digest.clear();
        let bytes = serde_json::to_vec(&clone).map_err(|error| {
            ControlError::Invalid(format!("encode decision audit entry: {error}"))
        })?;
        Ok(hex(&Sha256::digest(bytes)))
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != AUDIT_ENTRY_SCHEMA {
            return Err(ControlError::Invalid(
                "decision audit entry schema mismatch".into(),
            ));
        }
        if self.sequence == 0 || self.control_epoch == 0 {
            return Err(ControlError::Invalid(
                "decision audit sequence or epoch is zero".into(),
            ));
        }
        if !is_digest(&self.decision_digest) || !is_digest(&self.entry_digest) {
            return Err(ControlError::Invalid(
                "decision audit digests must be 256-bit hexadecimal values".into(),
            ));
        }
        if let Some(previous) = &self.previous_entry_digest
            && !is_digest(previous)
        {
            return Err(ControlError::Invalid(
                "decision audit previous digest is malformed".into(),
            ));
        }
        match self.kind {
            DecisionAuditKind::Decision => {
                if self.target_digest.is_some() {
                    return Err(ControlError::Invalid(
                        "decision audit decision cannot carry a rollback target".into(),
                    ));
                }
            }
            DecisionAuditKind::Rollback => {
                let Some(target) = &self.target_digest else {
                    return Err(ControlError::Invalid(
                        "decision audit rollback target is missing".into(),
                    ));
                };
                if !is_digest(target) || target != &self.decision_digest {
                    return Err(ControlError::Invalid(
                        "decision audit rollback target is inconsistent".into(),
                    ));
                }
            }
        }
        if self.entry_digest != self.digest()? {
            return Err(ControlError::Invalid(
                "decision audit entry digest does not match content".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct DecisionAuditState {
    current_epoch: u64,
    max_entries: usize,
    next_sequence: u64,
    entries: VecDeque<DecisionAuditEntry>,
    active_digest: Option<String>,
}

/// A bounded hash-chained audit log for shadow decisions.  Rollback appends a
/// marker and changes the active projection; it never erases history and it
/// never grants semantic or effect authority.
#[derive(Debug, Clone)]
pub struct DecisionAuditLog {
    inner: Arc<Mutex<DecisionAuditState>>,
    epoch_gate: EpochGate,
}

impl DecisionAuditLog {
    pub fn new(max_entries: usize) -> Result<Self> {
        Self::new_with_epoch(1, max_entries)
    }

    pub fn new_with_epoch(current_epoch: u64, max_entries: usize) -> Result<Self> {
        Self::new_with_epoch_and_gate(current_epoch, max_entries, Arc::new(Mutex::new(())))
    }

    fn new_with_epoch_and_gate(
        current_epoch: u64,
        max_entries: usize,
        epoch_gate: EpochGate,
    ) -> Result<Self> {
        if current_epoch == 0 {
            return Err(ControlError::Invalid(
                "decision audit epoch must be non-zero".into(),
            ));
        }
        if max_entries == 0 || max_entries > MAX_AUDIT_ENTRIES {
            return Err(ControlError::Invalid(format!(
                "decision audit capacity must be between 1 and {MAX_AUDIT_ENTRIES}"
            )));
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(DecisionAuditState {
                current_epoch,
                max_entries,
                next_sequence: 0,
                entries: VecDeque::new(),
                active_digest: None,
            })),
            epoch_gate,
        })
    }

    pub fn current_epoch(&self) -> u64 {
        let Ok(_epoch_guard) = self.epoch_gate.lock() else {
            return 0;
        };
        self.inner
            .lock()
            .map(|state| state.current_epoch)
            .unwrap_or(0)
    }

    pub fn max_entries(&self) -> usize {
        let Ok(_epoch_guard) = self.epoch_gate.lock() else {
            return 0;
        };
        self.inner
            .lock()
            .map(|state| state.max_entries)
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        let Ok(_epoch_guard) = self.epoch_gate.lock() else {
            return 0;
        };
        self.inner
            .lock()
            .map(|state| state.entries.len())
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn active_digest(&self) -> Option<String> {
        let Ok(_epoch_guard) = self.epoch_gate.lock() else {
            return None;
        };
        self.inner
            .lock()
            .ok()
            .and_then(|state| state.active_digest.clone())
    }

    pub fn entries(&self) -> Vec<DecisionAuditEntry> {
        let Ok(_epoch_guard) = self.epoch_gate.lock() else {
            return Vec::new();
        };
        self.inner
            .lock()
            .map(|state| state.entries.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn record(
        &self,
        decision: &ShadowDecision,
        recorded_at_ms: u64,
    ) -> Result<DecisionAuditEntry> {
        decision.validate(decision.control_epoch)?;
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit lock poisoned".into()))?;
        Self::record_locked(&mut state, decision, recorded_at_ms)
    }

    fn record_locked(
        state: &mut DecisionAuditState,
        decision: &ShadowDecision,
        recorded_at_ms: u64,
    ) -> Result<DecisionAuditEntry> {
        decision.validate(decision.control_epoch)?;
        if decision.control_epoch != state.current_epoch {
            return Err(ControlError::EpochMismatch);
        }
        if let Some(existing) = state.entries.iter().find(|entry| {
            entry.kind == DecisionAuditKind::Decision
                && entry.decision_digest == decision.decision_digest
        }) {
            // An exact retry of the currently active digest is idempotent.
            // A digest that was superseded (for example by a rollback marker)
            // is rejected instead of being silently accepted: accepting it
            // would make the caller believe it recorded the active decision
            // while the audit projection still names another digest.
            if state.active_digest.as_deref() == Some(decision.decision_digest.as_str()) {
                return Ok(existing.clone());
            }
            return Err(ControlError::Invalid(
                "decision digest is historical and cannot be re-recorded".into(),
            ));
        }
        append_audit_entry(
            state,
            decision.control_epoch,
            recorded_at_ms,
            DecisionAuditKind::Decision,
            decision.decision_digest.clone(),
            None,
        )
    }

    pub fn rollback(
        &self,
        target_digest: &str,
        expected_epoch: u64,
        recorded_at_ms: u64,
    ) -> Result<DecisionAuditEntry> {
        if !is_digest(target_digest) {
            return Err(ControlError::Invalid(
                "rollback target digest is malformed".into(),
            ));
        }
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit lock poisoned".into()))?;
        Self::rollback_locked(&mut state, target_digest, expected_epoch, recorded_at_ms)
    }

    fn rollback_locked(
        state: &mut DecisionAuditState,
        target_digest: &str,
        expected_epoch: u64,
        recorded_at_ms: u64,
    ) -> Result<DecisionAuditEntry> {
        if !is_digest(target_digest) {
            return Err(ControlError::Invalid(
                "rollback target digest is malformed".into(),
            ));
        }
        if expected_epoch != state.current_epoch {
            return Err(ControlError::EpochMismatch);
        }
        let target = state
            .entries
            .iter()
            .find(|entry| {
                entry.kind == DecisionAuditKind::Decision
                    && entry.control_epoch == expected_epoch
                    && entry.decision_digest == target_digest
            })
            .ok_or_else(|| {
                ControlError::Invalid("rollback target is not an audited decision".into())
            })?;
        if state.active_digest.as_deref() == Some(target_digest) {
            return Ok(target.clone());
        }
        append_audit_entry(
            state,
            expected_epoch,
            recorded_at_ms,
            DecisionAuditKind::Rollback,
            target_digest.to_string(),
            Some(target_digest.to_string()),
        )
    }

    pub fn verify(&self) -> Result<()> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit epoch gate poisoned".into()))?;
        let state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit lock poisoned".into()))?;
        let mut expected_sequence = 1_u64;
        let mut previous_digest = None;
        let mut active_digest = None;
        let mut decisions = BTreeSet::new();
        for entry in &state.entries {
            entry.validate()?;
            if entry.sequence != expected_sequence || entry.previous_entry_digest != previous_digest
            {
                return Err(ControlError::Invalid(
                    "decision audit hash chain sequence is broken".into(),
                ));
            }
            match entry.kind {
                DecisionAuditKind::Decision => {
                    decisions.insert((entry.control_epoch, entry.decision_digest.clone()));
                    if entry.control_epoch == state.current_epoch {
                        active_digest = Some(entry.decision_digest.clone());
                    }
                }
                DecisionAuditKind::Rollback => {
                    if !decisions.contains(&(entry.control_epoch, entry.decision_digest.clone())) {
                        return Err(ControlError::Invalid(
                            "decision audit rollback target is not earlier in the chain".into(),
                        ));
                    }
                    if entry.control_epoch == state.current_epoch {
                        active_digest = Some(entry.decision_digest.clone());
                    }
                }
            }
            previous_digest = Some(entry.entry_digest.clone());
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or_else(|| ControlError::Invalid("decision audit sequence exhausted".into()))?;
        }
        if state.active_digest != active_digest {
            return Err(ControlError::Invalid(
                "decision audit active projection does not match its chain".into(),
            ));
        }
        Ok(())
    }

    fn rotate_epoch_locked(state: &mut DecisionAuditState, next_epoch: u64) -> Result<()> {
        if next_epoch <= state.current_epoch {
            return Err(ControlError::EpochMismatch);
        }
        state.current_epoch = next_epoch;
        // A decision from a fenced epoch must never remain the active
        // projection while the new epoch is waiting for its first decision.
        // `verify` treats only entries from `current_epoch` as active, so the
        // historical hash chain remains intact while the active view resets.
        state.active_digest = None;
        Ok(())
    }

    pub fn rotate_epoch(&self, next_epoch: u64) -> Result<()> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit lock poisoned".into()))?;
        Self::rotate_epoch_locked(&mut state, next_epoch)
    }
}

fn append_audit_entry(
    state: &mut DecisionAuditState,
    control_epoch: u64,
    recorded_at_ms: u64,
    kind: DecisionAuditKind,
    decision_digest: String,
    target_digest: Option<String>,
) -> Result<DecisionAuditEntry> {
    if state.entries.len() >= state.max_entries {
        return Err(ControlError::CapacityExceeded);
    }
    let sequence = state
        .next_sequence
        .checked_add(1)
        .ok_or_else(|| ControlError::Invalid("decision audit sequence exhausted".into()))?;
    let mut entry = DecisionAuditEntry {
        schema: AUDIT_ENTRY_SCHEMA.to_string(),
        sequence,
        control_epoch,
        recorded_at_ms,
        kind,
        decision_digest,
        previous_entry_digest: state
            .entries
            .back()
            .map(|previous| previous.entry_digest.clone()),
        target_digest,
        entry_digest: String::new(),
    };
    entry.entry_digest = entry.digest()?;
    entry.validate()?;
    state.next_sequence = sequence;
    state.active_digest = Some(entry.decision_digest.clone());
    state.entries.push_back(entry.clone());
    Ok(entry)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerConfig {
    pub lease_ttl_ms: u64,
    pub max_lease_ttl_ms: u64,
    pub default_budget: ResourceBudget,
}

/// Bounds for the controller's in-memory lease and observation indexes.  The
/// limits are deliberately separate from [`ControllerConfig`] so adding a
/// capacity policy does not silently change the resource budget granted to a
/// module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerLimits {
    pub max_leases: usize,
    pub max_observations: usize,
}

pub const DEFAULT_MAX_LEASES: usize = 4096;
pub const DEFAULT_MAX_OBSERVATIONS: usize = 4096;
/// Hard upper bound for each controller index.  The caller may lower the
/// limits, but cannot turn a serialized/configured limit into an effectively
/// unbounded in-memory allocation.
pub const MAX_CONTROLLER_INDEX_ENTRIES: usize = 1_048_576;
/// A reservation consumes at least one slot, so this also bounds the number
/// of live reservation records.  The cap is independent of configured lease
/// budgets: a malformed or overly large configuration must not turn a burst
/// of callers into an unbounded allocation in the controller.
pub const MAX_ACTIVE_ADMISSION_SLOTS: u64 = MAX_CONTROLLER_INDEX_ENTRIES as u64;

impl Default for ControllerLimits {
    fn default() -> Self {
        Self {
            max_leases: DEFAULT_MAX_LEASES,
            max_observations: DEFAULT_MAX_OBSERVATIONS,
        }
    }
}

impl ControllerLimits {
    fn validate(self) -> Result<()> {
        if self.max_leases == 0
            || self.max_observations == 0
            || self.max_leases > MAX_CONTROLLER_INDEX_ENTRIES
            || self.max_observations > MAX_CONTROLLER_INDEX_ENTRIES
        {
            return Err(ControlError::Invalid(format!(
                "controller index limits must be between 1 and {MAX_CONTROLLER_INDEX_ENTRIES}"
            )));
        }
        Ok(())
    }
}

impl ControllerConfig {
    pub fn validate(&self) -> Result<()> {
        if self.lease_ttl_ms == 0
            || self.max_lease_ttl_ms == 0
            || self.lease_ttl_ms > self.max_lease_ttl_ms
        {
            return Err(ControlError::Invalid(
                "lease TTL configuration is invalid".into(),
            ));
        }
        self.default_budget.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDecision {
    pub allowed: bool,
    pub reason: &'static str,
    pub control_epoch: u64,
    pub fencing_token: String,
}

#[derive(Debug, Clone)]
pub struct Controller {
    inner: Arc<Mutex<ControllerState>>,
    module_registry: ModuleInstanceRegistry,
    decision_audit: DecisionAuditLog,
    epoch_gate: EpochGate,
}

#[derive(Debug)]
struct ControllerState {
    mode: ControlMode,
    control_epoch: u64,
    config: ControllerConfig,
    shadow_policy: ShadowPolicy,
    shadow_recommendations: BTreeMap<(String, String, String), ShadowRecommendationState>,
    next_lease: u64,
    outage: bool,
    limits: ControllerLimits,
    leases: BTreeMap<String, Lease>,
    observations: BTreeMap<(String, String, String), ModuleObservation>,
    next_reservation: u64,
    reserved_slots: u64,
    reservations: BTreeMap<u64, ReservationRecord>,
    lease_reserved_slots: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ShadowRecommendationState {
    recommended_concurrency: u32,
    last_change_ms: u64,
    cooldown_until_ms: u64,
    safety_latched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReservationRecord {
    lease_id: String,
    control_epoch: u64,
    slots: u32,
}

/// A move-only capacity token returned by [`Controller::reserve_admission`].
///
/// The token is safe to move between threads and releases its slots when it
/// is dropped.  A reservation does not grant semantic authority; callers must
/// still pass the original lease and operation-specific checks before doing
/// any effect. Dropping a token after an epoch rotation or lease expiry is a
/// harmless no-op because the controller has already fenced that record.
#[derive(Debug)]
pub struct AdmissionReservation {
    controller: Arc<Mutex<ControllerState>>,
    module_registry: ModuleInstanceRegistry,
    epoch_gate: EpochGate,
    reservation_id: u64,
    lease_id: String,
    control_epoch: u64,
    slots: u32,
    lease: Lease,
    decision: AdmissionDecision,
    released: bool,
}

impl AdmissionReservation {
    pub fn reservation_id(&self) -> u64 {
        self.reservation_id
    }

    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    pub fn control_epoch(&self) -> u64 {
        self.control_epoch
    }

    pub fn slots(&self) -> u32 {
        self.slots
    }

    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    pub fn decision(&self) -> &AdmissionDecision {
        &self.decision
    }

    pub fn is_released(&self) -> bool {
        self.released
    }

    /// Revalidate the reservation immediately before an effect boundary.
    /// This catches lease expiry, outage transitions, epoch rotation and a
    /// controller-side release while the token was in flight.
    pub fn validate(&self, now_ms: u64, new_effect: bool) -> Result<AdmissionDecision> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let state = self
            .controller
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        if self.released
            || !state
                .reservations
                .get(&self.reservation_id)
                .is_some_and(|record| {
                    record.lease_id == self.lease_id
                        && record.control_epoch == self.control_epoch
                        && record.slots == self.slots
                })
        {
            return Err(ControlError::Invalid(
                "admission reservation is no longer active".into(),
            ));
        }
        let decision = state.validate_admission(&self.lease, now_ms, self.slots, new_effect)?;
        let registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        validate_registry_lease_binding(&registry, &self.lease, state.control_epoch, new_effect)?;
        Ok(decision)
    }

    /// Release this token early. It is idempotent; the destructor performs
    /// the same release as a final safety net when callers do not call this
    /// method explicitly.
    pub fn release(&mut self) -> Result<()> {
        if self.released {
            return Ok(());
        }
        let mut state = self
            .controller
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        state.release_reservation(self.reservation_id);
        self.released = true;
        Ok(())
    }
}

impl Drop for AdmissionReservation {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Ok(mut state) = self.controller.lock() {
            state.release_reservation(self.reservation_id);
        }
        self.released = true;
    }
}

impl Controller {
    pub fn new(mode: ControlMode, control_epoch: u64, config: ControllerConfig) -> Result<Self> {
        Self::new_with_limits(mode, control_epoch, config, ControllerLimits::default())
    }

    pub fn new_with_limits(
        mode: ControlMode,
        control_epoch: u64,
        config: ControllerConfig,
        limits: ControllerLimits,
    ) -> Result<Self> {
        Self::new_with_policy(mode, control_epoch, config, limits, ShadowPolicy::default())
    }

    /// Construct a controller with an explicit, versioned shadow stability
    /// policy.  The policy is evaluated only for read-only recommendations;
    /// active control modes remain rejected by construction.
    pub fn new_with_policy(
        mode: ControlMode,
        control_epoch: u64,
        config: ControllerConfig,
        limits: ControllerLimits,
        shadow_policy: ShadowPolicy,
    ) -> Result<Self> {
        if control_epoch == 0 {
            return Err(ControlError::Invalid(
                "control epoch must be non-zero".into(),
            ));
        }
        config.validate()?;
        limits.validate()?;
        shadow_policy.validate()?;
        if !mode.is_shadow_safe() {
            return Err(ControlError::UnsupportedMode);
        }
        let epoch_gate = Arc::new(Mutex::new(()));
        Ok(Self {
            inner: Arc::new(Mutex::new(ControllerState {
                mode,
                control_epoch,
                config,
                shadow_policy,
                shadow_recommendations: BTreeMap::new(),
                next_lease: 0,
                outage: false,
                limits,
                leases: BTreeMap::new(),
                observations: BTreeMap::new(),
                next_reservation: 0,
                reserved_slots: 0,
                reservations: BTreeMap::new(),
                lease_reserved_slots: BTreeMap::new(),
            })),
            module_registry: ModuleInstanceRegistry::new_with_epoch_and_gate(
                control_epoch,
                DEFAULT_MAX_MODULE_INSTANCES,
                Arc::clone(&epoch_gate),
            )?,
            decision_audit: DecisionAuditLog::new_with_epoch_and_gate(
                control_epoch,
                DEFAULT_MAX_AUDIT_ENTRIES,
                Arc::clone(&epoch_gate),
            )?,
            epoch_gate,
        })
    }

    pub fn mode(&self) -> ControlMode {
        self.inner
            .lock()
            .map(|state| state.mode)
            .unwrap_or(ControlMode::Observe)
    }

    pub fn control_epoch(&self) -> u64 {
        self.inner
            .lock()
            .map(|state| state.control_epoch)
            .unwrap_or(0)
    }

    pub fn limits(&self) -> ControllerLimits {
        self.inner
            .lock()
            .map(|state| state.limits)
            .unwrap_or_default()
    }

    pub fn shadow_policy(&self) -> ShadowPolicy {
        self.inner
            .lock()
            .map(|state| state.shadow_policy.clone())
            .unwrap_or_default()
    }

    /// Return the bounded module-instance registry shared by all clones of
    /// this controller.  Registration is mechanical identity bookkeeping and
    /// does not grant semantic or effect authority.
    pub fn module_registry(&self) -> ModuleInstanceRegistry {
        self.module_registry.clone()
    }

    pub fn register_module_instance(
        &self,
        module_id: &str,
        module_instance_id: &str,
        partition: &str,
        version: &str,
        now_ms: u64,
    ) -> Result<ModuleInstance> {
        self.module_registry.register_instance(
            module_id,
            module_instance_id,
            partition,
            version,
            now_ms,
        )
    }

    /// Return the bounded decision audit log shared by controller clones.
    pub fn decision_audit(&self) -> DecisionAuditLog {
        self.decision_audit.clone()
    }

    pub fn record_shadow_decision(
        &self,
        decision: &ShadowDecision,
        recorded_at_ms: u64,
    ) -> Result<DecisionAuditEntry> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        if decision.control_epoch != state.control_epoch {
            return Err(ControlError::EpochMismatch);
        }
        decision.validate(state.control_epoch)?;
        let registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        let expected = state.shadow_decision(decision.generated_at_ms, &registry, false)?;
        if expected != *decision {
            return Err(ControlError::Invalid(
                "shadow decision does not match the controller observation projection".into(),
            ));
        }
        let mut audit = self
            .decision_audit
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit lock poisoned".into()))?;
        DecisionAuditLog::record_locked(&mut audit, decision, recorded_at_ms)
    }

    pub fn shadow_decision_and_record(&self, generated_at_ms: u64) -> Result<ShadowDecision> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        let registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        // `shadow_decision(..., true)` advances the bounded stability history
        // while it computes the projection.  Keep a snapshot until the audit
        // append has committed: publishing a recommendation that has no
        // corresponding audit entry would make the next projection diverge
        // from the durable control record.  The snapshot also covers errors
        // raised part-way through projection (for example, a later malformed
        // observation), not only an audit-capacity rejection.
        let history_before = state.shadow_recommendations.clone();
        let decision = match state.shadow_decision(generated_at_ms, &registry, true) {
            Ok(decision) => decision,
            Err(error) => {
                state.shadow_recommendations = history_before;
                return Err(error);
            }
        };
        let mut audit = match self.decision_audit.inner.lock() {
            Ok(audit) => audit,
            Err(_) => {
                state.shadow_recommendations = history_before;
                return Err(ControlError::Invalid("decision audit lock poisoned".into()));
            }
        };
        if let Err(error) = DecisionAuditLog::record_locked(&mut audit, &decision, generated_at_ms)
        {
            // This includes the fail-closed historical-digest replay path;
            // no projection bookkeeping may survive an audit rejection.
            state.shadow_recommendations = history_before;
            return Err(error);
        }
        Ok(decision)
    }

    pub fn rollback_shadow_decision(
        &self,
        target_digest: &str,
        recorded_at_ms: u64,
    ) -> Result<DecisionAuditEntry> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        let expected_epoch = state.control_epoch;
        let mut audit = self
            .decision_audit
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit lock poisoned".into()))?;
        let result = DecisionAuditLog::rollback_locked(
            &mut audit,
            target_digest,
            expected_epoch,
            recorded_at_ms,
        );
        if result.is_ok() {
            // Audit rollback changes the active decision immediately, while
            // hysteresis state is otherwise independent mutable memory.  A
            // newer recommendation must not continue to constrain the first
            // projection after rollback (dwell, cooldown and safety latches
            // would otherwise make the rollback only an audit-side change).
            // Resetting the bounded history is fail-closed; the next call
            // starts a fresh projection from the current observations.
            state.shadow_recommendations.clear();
        }
        result
    }

    pub fn fencing_token(&self) -> String {
        format!("epoch-{}", self.control_epoch())
    }

    pub fn set_outage(&self, outage: bool) {
        let _ = self.try_set_outage(outage);
    }

    /// Fallible form of [`Self::set_outage`] for callers that need to surface
    /// a poisoned controller state instead of treating it as a best-effort
    /// health signal.
    pub fn try_set_outage(&self, outage: bool) -> Result<()> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        state.outage = outage;
        Ok(())
    }

    pub fn outage(&self) -> bool {
        self.inner.lock().map(|state| state.outage).unwrap_or(true)
    }

    pub fn issue_lease(
        &self,
        module_id: &str,
        module_instance_id: &str,
        partition: &str,
        now_ms: u64,
        requested_ttl_ms: Option<u64>,
    ) -> Result<Lease> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        let registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        let key = ModuleInstanceKey {
            module_id: module_id.to_string(),
            module_instance_id: module_instance_id.to_string(),
            partition: partition.to_string(),
        };
        key.validate()?;
        let instance = registry.instances.get(&key).ok_or_else(|| {
            ControlError::Invalid("cannot issue a lease for an unregistered module instance".into())
        })?;
        if instance.status != ModuleInstanceStatus::Registered {
            return Err(ControlError::Invalid(
                "cannot issue a lease for an offline or draining module instance".into(),
            ));
        }
        if instance.control_epoch != state.control_epoch
            || instance.fencing_token != state.fencing_token()
        {
            return Err(ControlError::FencingMismatch);
        }
        state.issue_lease(
            module_id,
            module_instance_id,
            partition,
            now_ms,
            requested_ttl_ms,
        )
    }

    pub fn observe(&self, observation: ModuleObservation) -> Result<()> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        let registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        state.observe(observation, &registry)
    }

    /// Return a deterministic recommendation and advance the bounded
    /// hysteresis history used by subsequent projections.  This mutates only
    /// controller-local projection bookkeeping: it never mutates a lease,
    /// module semantic state or authorizes an effect.  Use
    /// [`Self::record_shadow_decision`] to audit an independently generated
    /// projection without advancing that history.
    pub fn shadow_decision(&self, generated_at_ms: u64) -> Result<ShadowDecision> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        let registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        state.shadow_decision(generated_at_ms, &registry, true)
    }

    /// Check a local admission against an already-issued lease without
    /// retaining capacity. Use [`Self::reserve_admission`] when the caller is
    /// about to hold work concurrently and needs a releaseable token.
    pub fn admit(
        &self,
        lease: &Lease,
        now_ms: u64,
        requested_slots: u32,
        new_effect: bool,
    ) -> Result<AdmissionDecision> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        let registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        let decision = state.validate_admission(lease, now_ms, requested_slots, new_effect)?;
        validate_registry_lease_binding(&registry, lease, state.control_epoch, new_effect)?;
        Ok(decision)
    }

    /// Atomically validate a lease and reserve its requested concurrency
    /// slots. The returned move-only token releases the reservation on drop.
    /// All checks and the counter update happen under one bounded critical
    /// section, so concurrent callers cannot oversubscribe a lease.
    pub fn reserve_admission(
        &self,
        lease: &Lease,
        now_ms: u64,
        requested_slots: u32,
        new_effect: bool,
    ) -> Result<AdmissionReservation> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        let decision = state.validate_admission(lease, now_ms, requested_slots, new_effect)?;
        let registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        validate_registry_lease_binding(&registry, lease, state.control_epoch, new_effect)?;
        state.prune_expired(now_ms);

        let next = state.next_reservation.checked_add(1).ok_or_else(|| {
            ControlError::Invalid("admission reservation sequence exhausted".into())
        })?;
        let requested = u64::from(requested_slots);
        let next_total = state
            .reserved_slots
            .checked_add(requested)
            .ok_or(ControlError::CapacityExceeded)?;
        if next_total > MAX_ACTIVE_ADMISSION_SLOTS {
            return Err(ControlError::CapacityExceeded);
        }
        let lease_reserved = state
            .lease_reserved_slots
            .get(&lease.lease_id)
            .copied()
            .unwrap_or_default();
        let next_lease_reserved = lease_reserved
            .checked_add(requested)
            .ok_or(ControlError::CapacityExceeded)?;
        if next_lease_reserved > u64::from(lease.maximum_concurrency) {
            return Err(ControlError::CapacityExceeded);
        }

        state.next_reservation = next;
        state.reserved_slots = next_total;
        state
            .lease_reserved_slots
            .insert(lease.lease_id.clone(), next_lease_reserved);
        state.reservations.insert(
            next,
            ReservationRecord {
                lease_id: lease.lease_id.clone(),
                control_epoch: lease.control_epoch,
                slots: requested_slots,
            },
        );
        Ok(AdmissionReservation {
            controller: Arc::clone(&self.inner),
            module_registry: self.module_registry.clone(),
            epoch_gate: Arc::clone(&self.epoch_gate),
            reservation_id: next,
            lease_id: lease.lease_id.clone(),
            control_epoch: lease.control_epoch,
            slots: requested_slots,
            lease: lease.clone(),
            decision,
            released: false,
        })
    }

    /// Alias emphasizing that reservation is a nonblocking bounded attempt.
    pub fn try_reserve_admission(
        &self,
        lease: &Lease,
        now_ms: u64,
        requested_slots: u32,
        new_effect: bool,
    ) -> Result<AdmissionReservation> {
        self.reserve_admission(lease, now_ms, requested_slots, new_effect)
    }

    /// Convenience form for an effectful admission.  Read-only cleanup can
    /// use the explicit `new_effect = false` form above.
    pub fn reserve(
        &self,
        lease: &Lease,
        now_ms: u64,
        requested_slots: u32,
    ) -> Result<AdmissionReservation> {
        self.reserve_admission(lease, now_ms, requested_slots, true)
    }

    pub fn try_reserve(
        &self,
        lease: &Lease,
        now_ms: u64,
        requested_slots: u32,
    ) -> Result<AdmissionReservation> {
        self.reserve(lease, now_ms, requested_slots)
    }

    pub fn reserved_slots(&self, lease: &Lease) -> u32 {
        self.inner
            .lock()
            .ok()
            .and_then(|state| state.lease_reserved_slots.get(&lease.lease_id).copied())
            .unwrap_or_default()
            .min(u64::from(u32::MAX)) as u32
    }

    pub fn reservation_count(&self) -> usize {
        self.inner
            .lock()
            .map(|state| state.reservations.len())
            .unwrap_or(0)
    }

    pub fn total_reserved_slots(&self) -> u64 {
        self.inner
            .lock()
            .map(|state| state.reserved_slots)
            .unwrap_or(MAX_ACTIVE_ADMISSION_SLOTS)
    }

    /// Advance the epoch and fence all prior leases and reservations.
    pub fn rotate_epoch(&self, next_epoch: u64) -> Result<()> {
        let _epoch_guard = self
            .epoch_gate
            .lock()
            .map_err(|_| ControlError::Invalid("controller epoch gate poisoned".into()))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("controller state lock poisoned".into()))?;
        if next_epoch <= state.control_epoch {
            return Err(ControlError::EpochMismatch);
        }
        let mut registry = self
            .module_registry
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("module registry lock poisoned".into()))?;
        let mut audit = self
            .decision_audit
            .inner
            .lock()
            .map_err(|_| ControlError::Invalid("decision audit lock poisoned".into()))?;
        // All three states must still describe one epoch.  The public
        // registry/audit handles share this gate, so a mismatch here means a
        // caller has bypassed the controller's coordinated transition; fail
        // closed instead of silently repairing one side.
        if registry.current_epoch != state.control_epoch
            || audit.current_epoch != state.control_epoch
        {
            return Err(ControlError::Invalid(
                "controller epoch state is inconsistent".into(),
            ));
        }
        state.rotate_epoch(next_epoch)?;
        ModuleInstanceRegistry::rotate_epoch_locked(&mut registry, next_epoch)?;
        DecisionAuditLog::rotate_epoch_locked(&mut audit, next_epoch)?;
        Ok(())
    }

    /*
     * The state-level implementations below are deliberately kept separate
     * from the public lock-taking methods.  This makes lock scope obvious and
     * prevents a future caller from accidentally taking the controller lock
     * across external I/O.
     */
}

impl ControllerState {
    fn fencing_token(&self) -> String {
        format!("epoch-{}", self.control_epoch)
    }

    fn issue_lease(
        &mut self,
        module_id: &str,
        module_instance_id: &str,
        partition: &str,
        now_ms: u64,
        requested_ttl_ms: Option<u64>,
    ) -> Result<Lease> {
        if self.outage {
            return Err(ControlError::AuthorityUnavailable);
        }
        for (name, value) in [
            ("module_id", module_id),
            ("module_instance_id", module_instance_id),
            ("partition", partition),
        ] {
            if value.trim().is_empty() || value.len() > 256 {
                return Err(ControlError::Invalid(format!("{name} is invalid")));
            }
        }
        let ttl = requested_ttl_ms.unwrap_or(self.config.lease_ttl_ms);
        if ttl == 0 || ttl > self.config.max_lease_ttl_ms {
            return Err(ControlError::Invalid(
                "requested lease TTL exceeds bound".into(),
            ));
        }
        self.prune_expired(now_ms);
        if self.leases.len() >= self.limits.max_leases {
            return Err(ControlError::CapacityExceeded);
        }
        self.next_lease = self.next_lease.checked_add(1).ok_or_else(|| {
            ControlError::Invalid("lease sequence exhausted; rotate control epoch".into())
        })?;
        let lease = Lease {
            schema: LEASE_SCHEMA.to_string(),
            control_epoch: self.control_epoch,
            lease_id: format!("lease-{}-{}", self.control_epoch, self.next_lease),
            module_id: module_id.to_string(),
            module_instance_id: module_instance_id.to_string(),
            partition: partition.to_string(),
            resource_budget: self.config.default_budget.clone(),
            maximum_concurrency: self.config.default_budget.max_concurrency,
            priority_class: 0,
            fencing_token: self.fencing_token(),
            issued_at_ms: now_ms,
            expires_at_ms: now_ms
                .checked_add(ttl)
                .ok_or_else(|| ControlError::Invalid("lease expiry overflows timestamp".into()))?,
        };
        lease.validate(now_ms, self.control_epoch, &self.fencing_token())?;
        self.leases.insert(lease.lease_id.clone(), lease.clone());
        Ok(lease)
    }

    fn observe(
        &mut self,
        observation: ModuleObservation,
        registry: &ModuleRegistryState,
    ) -> Result<()> {
        observation.validate()?;
        let lease = self
            .leases
            .get(&observation.lease_id)
            .ok_or_else(|| ControlError::Invalid("observation references unknown lease".into()))?;
        if lease.module_id != observation.module_id
            || lease.module_instance_id != observation.module_instance_id
            || lease.partition != observation.partition
        {
            return Err(ControlError::Invalid(
                "observation identity does not match lease".into(),
            ));
        }
        if observation.control_epoch != self.control_epoch {
            return Err(ControlError::EpochMismatch);
        }
        validate_registry_observation_binding(registry, &observation, self.control_epoch, true)?;
        validate_observation_budget(&observation, lease)?;
        if observation.observed_at_ms < lease.issued_at_ms
            || observation.observed_at_ms >= lease.expires_at_ms
        {
            return Err(ControlError::LeaseExpired);
        }
        let identity = (
            observation.module_id.clone(),
            observation.module_instance_id.clone(),
            observation.partition.clone(),
        );
        if !self.observations.contains_key(&identity)
            && self.observations.len() >= self.limits.max_observations
        {
            return Err(ControlError::CapacityExceeded);
        }
        if let Some(previous) = self.observations.get(&identity) {
            if observation.observed_at_ms < previous.observed_at_ms {
                return Err(ControlError::Invalid(
                    "observation timestamp regressed for module identity".into(),
                ));
            }
            if observation.observed_at_ms == previous.observed_at_ms {
                // Exact retransmission is idempotent.  A conflicting sample
                // at the same timestamp has no deterministic winner and must
                // not let arrival order alter a shadow decision.
                if previous == &observation {
                    return Ok(());
                }
                return Err(ControlError::Invalid(
                    "observation timestamp collision for module identity".into(),
                ));
            }
        }
        self.observations.insert(identity, observation);
        Ok(())
    }

    /// Return a deterministic recommendation. It is a read-only projection;
    /// the bounded policy state only remembers prior projections so repeated
    /// decisions cannot oscillate at request frequency. No recommendation
    /// mutates a lease or authorizes an effect.
    fn shadow_decision(
        &mut self,
        generated_at_ms: u64,
        registry: &ModuleRegistryState,
        update_history: bool,
    ) -> Result<ShadowDecision> {
        let observations = self.observations.values().cloned().collect::<Vec<_>>();
        if observations.len() > MAX_SHADOW_RECOMMENDATIONS {
            return Err(ControlError::CapacityExceeded);
        }
        let observation_bytes = serde_json::to_vec(&observations)
            .map_err(|error| ControlError::Invalid(format!("encode observations: {error}")))?;
        if observation_bytes.len() > MAX_SHADOW_OBSERVATION_BYTES {
            return Err(ControlError::CapacityExceeded);
        }
        let observations_digest = hex(&Sha256::digest(observation_bytes));
        let policy = self.shadow_policy.clone();
        let mut recommendations = Vec::with_capacity(observations.len());
        for observation in observations {
            validate_registry_observation_binding(
                registry,
                &observation,
                self.control_epoch,
                true,
            )?;
            let Some(lease) = self.leases.get(&observation.lease_id) else {
                return Err(ControlError::Invalid(
                    "observation references a lease that is no longer tracked".into(),
                ));
            };
            // A shadow projection is still a time-indexed control artifact.
            // Do not let a future observation or an observation whose lease
            // has expired influence a later decision. Silently filtering
            // either case would make replicas disagree about the digest;
            // failing closed keeps the decision deterministic.
            if generated_at_ms < observation.observed_at_ms {
                return Err(ControlError::Invalid(
                    "shadow decision timestamp precedes an observation".into(),
                ));
            }
            if generated_at_ms >= lease.expires_at_ms {
                return Err(ControlError::LeaseExpired);
            }

            let identity = (
                observation.module_id.clone(),
                observation.module_instance_id.clone(),
                observation.partition.clone(),
            );
            let max_concurrency = lease
                .maximum_concurrency
                .min(lease.resource_budget.max_concurrency)
                .max(1);
            let health_guard = observation.health_score < policy.health_guard_threshold;
            let unknown_guard = observation.unknown_rate > 0.0;
            let rollback_guard = observation.unknown_rate >= policy.rollback_unknown_rate_threshold;
            let recovered = observation.health_score >= policy.health_recover_threshold
                && observation.unknown_rate < policy.rollback_unknown_rate_threshold;
            let raw_recommended = if health_guard || unknown_guard {
                1
            } else if observation.queue_depth > lease.resource_budget.max_queue / 2 {
                max_concurrency
            } else {
                lease
                    .maximum_concurrency
                    .min(lease.resource_budget.max_concurrency.saturating_add(1))
                    .max(1)
            };
            let safety_guard = health_guard || rollback_guard;
            let previous = self.shadow_recommendations.get(&identity).copied();
            let (recommended, safety_latched) = match previous {
                None => (raw_recommended, safety_guard),
                Some(previous) => {
                    let hold_until = previous
                        .last_change_ms
                        .saturating_add(policy.min_dwell_ms)
                        .max(previous.cooldown_until_ms);
                    let time_regressed = generated_at_ms < previous.last_change_ms;
                    // A newly observed hard safety condition is allowed to
                    // clamp immediately; ordinary changes obey dwell/cooldown
                    // and the maximum adjustment rate.
                    if (safety_guard && !previous.safety_latched)
                        || (previous.safety_latched && !recovered)
                    {
                        (1, true)
                    } else if time_regressed || generated_at_ms < hold_until {
                        (previous.recommended_concurrency, previous.safety_latched)
                    } else if raw_recommended > previous.recommended_concurrency {
                        (
                            previous
                                .recommended_concurrency
                                .saturating_add(policy.max_adjustment)
                                .min(raw_recommended),
                            false,
                        )
                    } else {
                        (
                            previous
                                .recommended_concurrency
                                .saturating_sub(policy.max_adjustment)
                                .max(raw_recommended),
                            false,
                        )
                    }
                }
            };
            let recommended = recommended.min(max_concurrency).max(1);
            if update_history {
                let changed = previous.is_none_or(|prior| {
                    prior.recommended_concurrency != recommended
                        || prior.safety_latched != safety_latched
                });
                let last_change_ms = if changed {
                    generated_at_ms
                } else {
                    previous.map_or(generated_at_ms, |prior| prior.last_change_ms)
                };
                self.shadow_recommendations.insert(
                    identity,
                    ShadowRecommendationState {
                        recommended_concurrency: recommended,
                        last_change_ms,
                        cooldown_until_ms: last_change_ms.saturating_add(policy.cooldown_ms),
                        safety_latched,
                    },
                );
            }
            recommendations.push(BudgetRecommendation {
                module_id: observation.module_id,
                module_instance_id: observation.module_instance_id,
                partition: observation.partition,
                recommended_concurrency: recommended,
                reason_code: if health_guard {
                    "health_guard"
                } else if unknown_guard {
                    "unknown_guard"
                } else if observation.queue_depth > lease.resource_budget.max_queue / 2 {
                    "queue_pressure"
                } else {
                    "steady_state"
                }
                .to_string(),
            });
        }
        let mut decision = ShadowDecision {
            schema: DECISION_SCHEMA.to_string(),
            control_epoch: self.control_epoch,
            generated_at_ms,
            mode: self.mode,
            observations_digest,
            recommendations,
            effectful: false,
            semantic_authority: "none".to_string(),
            decision_digest: String::new(),
        };
        decision.decision_digest = decision.compute_digest()?;
        Ok(decision)
    }

    /// Check a local admission against an already-issued lease.  During an
    /// outage, read-only cleanup and work under a non-expired lease continue;
    /// a caller that is about to create a new effect must pass `new_effect`=
    /// true and will be rejected until the controller returns.
    fn validate_admission(
        &self,
        lease: &Lease,
        now_ms: u64,
        requested_slots: u32,
        new_effect: bool,
    ) -> Result<AdmissionDecision> {
        lease.validate(now_ms, self.control_epoch, &self.fencing_token())?;
        // Epoch and fencing values alone are not proof that this exact lease
        // was issued by this controller. A caller could otherwise forge a
        // lease with the current token and bypass the bound budget or module
        // identity. Compare the complete record retained by this controller.
        let issued = self.leases.get(&lease.lease_id).ok_or_else(|| {
            ControlError::Invalid("lease was not issued by this controller".into())
        })?;
        if issued != lease {
            return Err(ControlError::Invalid(
                "lease does not match the controller-issued record".into(),
            ));
        }
        if requested_slots == 0 || requested_slots > lease.maximum_concurrency {
            return Err(ControlError::CapacityExceeded);
        }
        if self.outage && new_effect {
            return Err(ControlError::AuthorityUnavailable);
        }
        Ok(AdmissionDecision {
            allowed: true,
            reason: if self.outage {
                "existing_lease_during_bounded_outage"
            } else if self.mode == ControlMode::Observe {
                "observe_local_admission"
            } else {
                "shadow_local_admission"
            },
            control_epoch: self.control_epoch,
            fencing_token: lease.fencing_token.clone(),
        })
    }

    /// Advance the epoch and fence all prior leases.  This is the only state
    /// mutation that invalidates ownership; it never replays an effect.
    fn rotate_epoch(&mut self, next_epoch: u64) -> Result<()> {
        if next_epoch <= self.control_epoch {
            return Err(ControlError::EpochMismatch);
        }
        self.control_epoch = next_epoch;
        self.next_lease = 0;
        self.leases.clear();
        self.observations.clear();
        self.shadow_recommendations.clear();
        // Keep the reservation sequence monotonic across epochs. Old tokens
        // may still be held by another thread; reusing an id after rotation
        // would let a late destructor release a new-epoch reservation.
        self.reserved_slots = 0;
        self.reservations.clear();
        self.lease_reserved_slots.clear();
        self.outage = false;
        Ok(())
    }

    fn prune_expired(&mut self, now_ms: u64) {
        let expired = self
            .leases
            .iter()
            .filter(|(_, lease)| lease.expires_at_ms <= now_ms)
            .map(|(lease_id, _)| lease_id.clone())
            .collect::<BTreeSet<_>>();
        if expired.is_empty() {
            return;
        }
        for lease_id in &expired {
            self.leases.remove(lease_id);
        }
        let expired_identities = self
            .observations
            .values()
            .filter(|observation| expired.contains(&observation.lease_id))
            .map(|observation| {
                (
                    observation.module_id.clone(),
                    observation.module_instance_id.clone(),
                    observation.partition.clone(),
                )
            })
            .collect::<BTreeSet<_>>();
        self.observations
            .retain(|_, observation| !expired.contains(&observation.lease_id));
        self.shadow_recommendations
            .retain(|identity, _| !expired_identities.contains(identity));
        let expired_reservations = self
            .reservations
            .iter()
            .filter(|(_, reservation)| expired.contains(&reservation.lease_id))
            .map(|(reservation_id, _)| *reservation_id)
            .collect::<Vec<_>>();
        for reservation_id in expired_reservations {
            self.release_reservation(reservation_id);
        }
    }

    fn release_reservation(&mut self, reservation_id: u64) {
        let Some(record) = self.reservations.remove(&reservation_id) else {
            return;
        };
        self.reserved_slots = self.reserved_slots.saturating_sub(u64::from(record.slots));
        let remove_lease_entry =
            if let Some(slots) = self.lease_reserved_slots.get_mut(&record.lease_id) {
                *slots = slots.saturating_sub(u64::from(record.slots));
                *slots == 0
            } else {
                false
            };
        if remove_lease_entry {
            self.lease_reserved_slots.remove(&record.lease_id);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("String formatting cannot fail");
    }
    output
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn config() -> ControllerConfig {
        ControllerConfig {
            lease_ttl_ms: 100,
            max_lease_ttl_ms: 1_000,
            default_budget: ResourceBudget {
                max_concurrency: 8,
                max_queue: 32,
                max_cpu_millis: 10_000,
                max_memory_bytes: 1_000_000,
                max_io_bytes: 1_000_000,
            },
        }
    }

    fn observation(lease: &Lease) -> ModuleObservation {
        ModuleObservation {
            schema: OBSERVATION_SCHEMA.to_string(),
            control_epoch: lease.control_epoch,
            lease_id: lease.lease_id.clone(),
            module_id: lease.module_id.clone(),
            module_instance_id: lease.module_instance_id.clone(),
            partition: lease.partition.clone(),
            observed_at_ms: lease.issued_at_ms + 1,
            queue_depth: 2,
            active_count: 1,
            cpu_millis: 2,
            memory_bytes: 3,
            io_bytes: 4,
            latency_p99_ms: 5.0,
            unknown_rate: 0.0,
            health_score: 1.0,
        }
    }

    /// Test-only convenience: production lease issuance intentionally refuses
    /// identities that have not completed registry registration.  Most tests
    /// exercise the happy path, so keep the registration ceremony in one
    /// helper instead of weakening that production invariant.
    fn issue(
        controller: &Controller,
        module_id: &str,
        module_instance_id: &str,
        partition: &str,
        now_ms: u64,
        ttl_ms: Option<u64>,
    ) -> Lease {
        let key = ModuleInstanceKey {
            module_id: module_id.to_string(),
            module_instance_id: module_instance_id.to_string(),
            partition: partition.to_string(),
        };
        if controller.module_registry().get(&key).unwrap().is_none() {
            controller
                .register_module_instance(module_id, module_instance_id, partition, "v1", now_ms)
                .unwrap();
        }
        controller
            .issue_lease(module_id, module_instance_id, partition, now_ms, ttl_ms)
            .unwrap()
    }

    #[test]
    fn lease_expiry_and_fencing_are_fail_closed() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "broker", "b-1", "p0", 10, None);
        assert!(controller.admit(&lease, 50, 1, true).unwrap().allowed);
        assert_eq!(
            controller.admit(&lease, 110, 1, true).unwrap_err(),
            ControlError::LeaseExpired
        );
        let mut stale = lease.clone();
        stale.fencing_token = "old".into();
        assert_eq!(
            controller.admit(&stale, 50, 1, true).unwrap_err(),
            ControlError::FencingMismatch
        );
        controller.rotate_epoch(2).unwrap();
        assert_eq!(
            controller.admit(&lease, 50, 1, true).unwrap_err(),
            ControlError::EpochMismatch
        );
    }

    #[test]
    fn lease_not_before_boundary_is_fail_closed() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "broker", "b-1", "p0", 100, None);
        assert!(matches!(
            controller.admit(&lease, 99, 1, true),
            Err(ControlError::Invalid(message)) if message.contains("not yet valid")
        ));
        assert!(controller.admit(&lease, 100, 1, true).unwrap().allowed);
    }

    #[test]
    fn admission_requires_the_exact_controller_issued_lease() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "broker", "b-1", "p0", 10, None);

        let mut forged = lease.clone();
        forged.module_id = "other-module".into();
        assert!(matches!(
            controller.admit(&forged, 50, 1, true),
            Err(ControlError::Invalid(message)) if message.contains("controller-issued")
        ));

        let mut unknown = lease.clone();
        unknown.lease_id = "lease-1-forged".into();
        assert!(matches!(
            controller.admit(&unknown, 50, 1, true),
            Err(ControlError::Invalid(message)) if message.contains("not issued")
        ));
    }

    #[test]
    fn shadow_decisions_are_reproducible_and_non_semantic() {
        let first = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&first, "broker", "b-1", "p0", 10, None);
        first.observe(observation(&lease)).unwrap();
        let a = first.shadow_decision(20).unwrap();

        let second = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease2 = issue(&second, "broker", "b-1", "p0", 10, None);
        second.observe(observation(&lease2)).unwrap();
        let b = second.shadow_decision(20).unwrap();
        assert_eq!(a, b);
        a.validate(1).unwrap();
        let encoded = serde_json::to_string(&a).unwrap();
        assert!(!encoded.contains("command"));
        assert!(!encoded.contains("intent"));
        assert!(!encoded.contains("prompt"));
    }

    #[test]
    fn outage_allows_existing_lease_but_stops_new_effects_and_leases() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller
            .register_module_instance("jobs", "j-2", "p0", "v1", 10)
            .unwrap();
        controller.set_outage(true);
        assert!(controller.admit(&lease, 50, 1, false).unwrap().allowed);
        assert_eq!(
            controller.admit(&lease, 50, 1, true).unwrap_err(),
            ControlError::AuthorityUnavailable
        );
        assert_eq!(
            controller
                .issue_lease("jobs", "j-2", "p0", 50, None)
                .unwrap_err(),
            ControlError::AuthorityUnavailable
        );
    }

    #[test]
    fn active_modes_are_not_accidentally_enabled() {
        assert_eq!(
            Controller::new(ControlMode::Active, 1, config()).unwrap_err(),
            ControlError::UnsupportedMode
        );
    }

    #[test]
    fn a_tampered_active_mode_cannot_validate_as_shadow() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "broker", "b-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();
        let mut decision = controller.shadow_decision(20).unwrap();
        decision.mode = ControlMode::Active;
        decision.decision_digest = decision.compute_digest().unwrap();
        assert_eq!(
            decision.validate(1).unwrap_err(),
            ControlError::UnsupportedMode
        );
    }

    #[test]
    fn controller_indexes_are_bounded_and_expired_leases_are_reclaimed() {
        let limits = ControllerLimits {
            max_leases: 1,
            max_observations: 2,
        };
        let controller =
            Controller::new_with_limits(ControlMode::Shadow, 1, config(), limits).unwrap();
        let first = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller
            .register_module_instance("jobs", "j-2", "p0", "v1", 10)
            .unwrap();
        assert_eq!(
            controller.issue_lease("jobs", "j-2", "p0", 20, None),
            Err(ControlError::CapacityExceeded)
        );
        // Capacity is reclaimed only after the lease's expiry is observed;
        // this keeps the index bounded without evicting live ownership.
        let second = issue(&controller, "jobs", "j-2", "p0", 110, None);
        assert_ne!(first.lease_id, second.lease_id);
    }

    #[test]
    fn observation_index_rejects_new_entries_after_its_bound() {
        let limits = ControllerLimits {
            max_leases: 2,
            max_observations: 1,
        };
        let controller =
            Controller::new_with_limits(ControlMode::Shadow, 1, config(), limits).unwrap();
        let first = issue(&controller, "jobs", "j-1", "p0", 10, None);
        let second = issue(&controller, "jobs", "j-2", "p0", 10, None);
        controller.observe(observation(&first)).unwrap();
        assert_eq!(
            controller.observe(observation(&second)),
            Err(ControlError::CapacityExceeded)
        );
    }

    #[test]
    fn controller_limits_reject_unbounded_indexes() {
        let limits = ControllerLimits {
            max_leases: MAX_CONTROLLER_INDEX_ENTRIES + 1,
            max_observations: 1,
        };
        assert!(matches!(
            Controller::new_with_limits(ControlMode::Shadow, 1, config(), limits),
            Err(ControlError::Invalid(message)) if message.contains("between 1")
        ));
    }

    #[test]
    fn observations_are_monotonic_and_conflicting_ties_fail_closed() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        let first = observation(&lease);
        controller.observe(first.clone()).unwrap();
        // Exact retransmission is safe and idempotent.
        controller.observe(first.clone()).unwrap();

        let mut older = first.clone();
        older.observed_at_ms -= 1;
        assert!(matches!(
            controller.observe(older),
            Err(ControlError::Invalid(message)) if message.contains("regressed")
        ));

        let mut same_time_different_value = first;
        same_time_different_value.queue_depth += 1;
        assert!(matches!(
            controller.observe(same_time_different_value),
            Err(ControlError::Invalid(message)) if message.contains("collision")
        ));
    }

    #[test]
    fn registry_status_and_observation_identity_are_bound_to_leases() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        let key = ModuleInstanceKey {
            module_id: lease.module_id.clone(),
            module_instance_id: lease.module_instance_id.clone(),
            partition: lease.partition.clone(),
        };
        controller
            .module_registry()
            .set_status(
                &key,
                1,
                &lease.fencing_token,
                ModuleInstanceStatus::Offline,
                11,
            )
            .unwrap();
        assert!(matches!(
            controller.admit(&lease, 20, 1, true),
            Err(ControlError::Invalid(message)) if message.contains("not accepting")
        ));

        // A lease ID cannot be reused to smuggle telemetry for another
        // registered identity into the controller's observation projection.
        let other = issue(&controller, "jobs", "j-2", "p0", 12, None);
        let mut forged = observation(&lease);
        forged.module_instance_id = other.module_instance_id;
        assert!(matches!(
            controller.observe(forged),
            Err(ControlError::Invalid(message)) if message.contains("identity")
        ));
    }

    #[test]
    fn shadow_decision_fails_closed_if_observation_lease_is_missing() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();
        controller
            .inner
            .lock()
            .unwrap()
            .leases
            .remove(&lease.lease_id);
        assert!(matches!(
            controller.shadow_decision(20),
            Err(ControlError::Invalid(message)) if message.contains("no longer tracked")
        ));
    }

    #[test]
    fn shadow_decision_rejects_future_or_expired_observations() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();
        assert!(matches!(
            controller.shadow_decision(10),
            Err(ControlError::Invalid(message)) if message.contains("precedes")
        ));
        assert_eq!(
            controller.shadow_decision(110).unwrap_err(),
            ControlError::LeaseExpired
        );
    }

    #[test]
    fn concurrent_reservations_are_atomic_and_bounded() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        let callers = 32;
        let barrier = Arc::new(Barrier::new(callers));
        let mut handles = Vec::with_capacity(callers);
        for _ in 0..callers {
            let controller = controller.clone();
            let lease = lease.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                controller.reserve_admission(&lease, 20, 1, true)
            }));
        }
        let reservations = handles
            .into_iter()
            .map(|handle| handle.join().expect("reservation worker panicked"))
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        assert_eq!(reservations.len(), lease.maximum_concurrency as usize);
        assert_eq!(controller.reservation_count(), reservations.len());
        assert_eq!(controller.reserved_slots(&lease), lease.maximum_concurrency);
        assert!(matches!(
            controller.reserve_admission(&lease, 20, 1, true),
            Err(ControlError::CapacityExceeded)
        ));
        drop(reservations);
        assert_eq!(controller.reservation_count(), 0);
        assert_eq!(controller.reserved_slots(&lease), 0);
        assert!(
            controller
                .reserve_admission(&lease, 20, lease.maximum_concurrency, true)
                .is_ok()
        );
    }

    #[test]
    fn multi_slot_reservation_never_partially_commits() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        let mut first = controller.reserve_admission(&lease, 20, 5, true).unwrap();
        assert_eq!(controller.reserved_slots(&lease), 5);
        assert!(matches!(
            controller.reserve_admission(&lease, 20, 4, true),
            Err(ControlError::CapacityExceeded)
        ));
        let second = controller.reserve_admission(&lease, 20, 3, true).unwrap();
        assert_eq!(controller.reserved_slots(&lease), 8);
        assert_eq!(first.validate(20, true).unwrap().control_epoch, 1);
        first.release().unwrap();
        assert_eq!(controller.reserved_slots(&lease), 3);
        drop(second);
        assert_eq!(controller.reserved_slots(&lease), 0);
    }

    #[test]
    fn reservation_revalidation_fences_outage_expiry_and_epoch_changes() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        let reservation = controller.reserve_admission(&lease, 20, 1, true).unwrap();
        controller.set_outage(true);
        assert_eq!(
            reservation.validate(20, true).unwrap_err(),
            ControlError::AuthorityUnavailable
        );
        assert!(reservation.validate(20, false).is_ok());
        assert_eq!(
            reservation.validate(110, false).unwrap_err(),
            ControlError::LeaseExpired
        );
        controller.rotate_epoch(2).unwrap();
        assert_eq!(
            reservation.validate(20, false).unwrap_err(),
            ControlError::Invalid("admission reservation is no longer active".into())
        );
        assert_eq!(controller.reservation_count(), 0);
    }

    #[test]
    fn controller_and_reservation_are_send_sync_and_clones_share_state() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Controller>();
        assert_send_sync::<AdmissionReservation>();

        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let clone = controller.clone();
        let lease = issue(&clone, "jobs", "j-1", "p0", 10, None);
        let reservation = controller.reserve_admission(&lease, 20, 2, true).unwrap();
        assert_eq!(clone.reserved_slots(&lease), 2);
        drop(reservation);
        assert_eq!(controller.reserved_slots(&lease), 0);
    }

    #[test]
    fn stale_reservation_drop_cannot_release_a_new_epoch_token() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let old_lease = issue(&controller, "jobs", "j-old", "p0", 10, None);
        let old_reservation = controller
            .reserve_admission(&old_lease, 20, 1, true)
            .unwrap();
        controller.rotate_epoch(2).unwrap();
        let new_lease = issue(&controller, "jobs", "j-new", "p0", 20, None);
        let new_reservation = controller
            .reserve_admission(&new_lease, 21, 2, true)
            .unwrap();
        assert_ne!(
            old_reservation.reservation_id(),
            new_reservation.reservation_id()
        );
        drop(old_reservation);
        assert_eq!(controller.reservation_count(), 1);
        assert_eq!(controller.reserved_slots(&new_lease), 2);
        drop(new_reservation);
        assert_eq!(controller.total_reserved_slots(), 0);
    }

    #[test]
    fn expiry_prunes_reservations_and_reclaims_capacity() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        let reservation = controller.reserve_admission(&lease, 20, 3, true).unwrap();
        assert_eq!(controller.total_reserved_slots(), 3);
        // Issuing a later lease is the bounded maintenance point that prunes
        // expired ownership and its still-held tokens.
        let replacement = issue(&controller, "jobs", "j-2", "p0", 110, None);
        assert_eq!(controller.reservation_count(), 0);
        assert_eq!(controller.total_reserved_slots(), 0);
        assert!(matches!(
            reservation.validate(110, false),
            Err(ControlError::Invalid(message)) if message.contains("no longer active")
        ));
        assert!(
            controller
                .reserve_admission(&replacement, 111, 8, true)
                .is_ok()
        );
    }

    #[test]
    fn module_registry_is_bounded_and_epoch_fenced() {
        let registry = ModuleInstanceRegistry::new(1).unwrap();
        let first = registry
            .register_instance("broker", "b-1", "p0", "v1", 10)
            .unwrap();
        // Exact retransmission is idempotent, but a second identity cannot
        // silently evict the live owner when the bound is reached.
        registry.register(first.clone()).unwrap();
        assert_eq!(
            registry.register_instance("broker", "b-2", "p0", "v1", 10),
            Err(ControlError::CapacityExceeded)
        );
        let key = first.key();
        let heartbeat = registry.heartbeat(&key, 1, "epoch-1", 11).unwrap();
        assert_eq!(heartbeat.last_seen_at_ms, 11);
        assert!(matches!(
            registry.heartbeat(&key, 1, "epoch-1", 10),
            Err(ControlError::Invalid(message)) if message.contains("regressed")
        ));
        registry.rotate_epoch(2).unwrap();
        assert!(registry.is_empty());
        assert_eq!(
            registry.heartbeat(&key, 1, "epoch-1", 20).unwrap_err(),
            ControlError::EpochMismatch
        );
        let second = registry
            .register_instance("broker", "b-2", "p0", "v2", 20)
            .unwrap();
        assert_eq!(second.control_epoch, 2);
    }

    #[test]
    fn convenience_registration_validates_identity_before_insertion() {
        let registry = ModuleInstanceRegistry::new(2).unwrap();
        assert!(
            registry
                .register_instance("", "b-1", "p0", "v1", 1)
                .is_err()
        );
        assert!(
            registry
                .register_instance("broker", "b-1", "p0", "", 1)
                .is_err()
        );
        assert_eq!(registry.len(), 0);
        assert!(
            registry
                .register_instance("broker", &"x".repeat(257), "p0", "v1", 1)
                .is_err()
        );
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn module_status_transition_updates_heartbeat_atomically() {
        let registry = ModuleInstanceRegistry::new(1).unwrap();
        let instance = registry
            .register_instance("broker", "b-1", "p0", "v1", 10)
            .unwrap();
        let key = instance.key();

        registry
            .set_status(
                &key,
                instance.control_epoch,
                &instance.fencing_token,
                ModuleInstanceStatus::Draining,
                11,
            )
            .unwrap();
        let draining = registry.get(&key).unwrap().unwrap();
        assert_eq!(draining.status, ModuleInstanceStatus::Draining);
        assert_eq!(draining.last_seen_at_ms, 11);

        assert!(matches!(
            registry.set_status(
                &key,
                instance.control_epoch,
                &instance.fencing_token,
                ModuleInstanceStatus::Offline,
                10,
            ),
            Err(ControlError::Invalid(message)) if message.contains("regressed")
        ));
        assert_eq!(registry.get(&key).unwrap().unwrap(), draining);
    }

    #[test]
    fn resource_budget_rejects_unbounded_values() {
        let mut budget = config().default_budget;
        assert!(budget.validate().is_ok());

        budget.max_concurrency = MAX_RESOURCE_CONCURRENCY + 1;
        assert!(matches!(
            budget.validate(),
            Err(ControlError::Invalid(message)) if message.contains("concurrency")
        ));
        budget.max_concurrency = config().default_budget.max_concurrency;

        budget.max_queue = MAX_RESOURCE_QUEUE + 1;
        assert!(matches!(
            budget.validate(),
            Err(ControlError::Invalid(message)) if message.contains("queue")
        ));
        budget.max_queue = config().default_budget.max_queue;

        budget.max_cpu_millis = MAX_RESOURCE_CPU_MILLIS + 1;
        assert!(matches!(
            budget.validate(),
            Err(ControlError::Invalid(message)) if message.contains("CPU")
        ));
        budget.max_cpu_millis = config().default_budget.max_cpu_millis;

        budget.max_memory_bytes = MAX_RESOURCE_MEMORY_BYTES + 1;
        assert!(matches!(
            budget.validate(),
            Err(ControlError::Invalid(message)) if message.contains("memory")
        ));
        budget.max_memory_bytes = config().default_budget.max_memory_bytes;

        budget.max_io_bytes = MAX_RESOURCE_IO_BYTES + 1;
        assert!(matches!(
            budget.validate(),
            Err(ControlError::Invalid(message)) if message.contains("I/O")
        ));

        budget.max_concurrency = MAX_RESOURCE_CONCURRENCY;
        budget.max_queue = MAX_RESOURCE_QUEUE;
        budget.max_cpu_millis = MAX_RESOURCE_CPU_MILLIS;
        budget.max_memory_bytes = MAX_RESOURCE_MEMORY_BYTES;
        budget.max_io_bytes = MAX_RESOURCE_IO_BYTES;
        assert!(budget.validate().is_ok());
    }

    #[test]
    fn epoch_rotation_fences_shared_registry_and_audit_handles() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let registry = controller.module_registry();
        let audit = controller.decision_audit();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();
        let old_decision = controller.shadow_decision_and_record(20).unwrap();

        controller.rotate_epoch(2).unwrap();
        assert_eq!(controller.control_epoch(), 2);
        assert_eq!(registry.current_epoch(), 2);
        assert_eq!(audit.current_epoch(), 2);

        assert_eq!(
            controller.record_shadow_decision(&old_decision, 21),
            Err(ControlError::EpochMismatch)
        );
        assert_eq!(
            audit.record(&old_decision, 21),
            Err(ControlError::EpochMismatch)
        );
        assert!(audit.verify().is_ok());

        let new_lease = issue(&controller, "jobs", "j-2", "p0", 30, None);
        controller.observe(observation(&new_lease)).unwrap();
        let new_decision = controller.shadow_decision_and_record(40).unwrap();
        assert_eq!(new_decision.control_epoch, 2);
        assert!(audit.entries().iter().any(|entry| entry.control_epoch == 2));
        audit.verify().unwrap();
    }

    #[test]
    fn decision_audit_is_hash_chained_and_rolls_back_without_erasing_history() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();
        let first = controller.shadow_decision_and_record(20).unwrap();
        let mut next_observation = observation(&lease);
        next_observation.observed_at_ms = 21;
        next_observation.queue_depth = 20;
        controller.observe(next_observation).unwrap();
        let second = controller.shadow_decision_and_record(30).unwrap();
        assert_ne!(first.decision_digest, second.decision_digest);
        let rollback = controller
            .rollback_shadow_decision(&first.decision_digest, 31)
            .unwrap();
        assert_eq!(rollback.kind, DecisionAuditKind::Rollback);
        assert_eq!(
            controller.decision_audit().active_digest(),
            Some(first.decision_digest.clone())
        );
        assert_eq!(controller.decision_audit().len(), 3);
        controller.decision_audit().verify().unwrap();
        assert!(
            controller
                .decision_audit()
                .entries()
                .iter()
                .any(|entry| entry.kind == DecisionAuditKind::Decision
                    && entry.decision_digest == second.decision_digest)
        );
    }

    #[test]
    fn rollback_resets_stale_shadow_hysteresis_before_next_projection() {
        // Disable time holds so the test isolates the state reset: after a
        // safety clamp and one recovery step, a stale history would only
        // allow the next projection to move by `max_adjustment` instead of
        // starting from the current raw recommendation.
        let policy = ShadowPolicy {
            min_dwell_ms: 0,
            cooldown_ms: 0,
            ..ShadowPolicy::default()
        };
        let controller = Controller::new_with_policy(
            ControlMode::Shadow,
            1,
            config(),
            ControllerLimits::default(),
            policy,
        )
        .unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();

        let first = controller.shadow_decision_and_record(20).unwrap();
        assert_eq!(first.recommendations[0].recommended_concurrency, 8);

        let mut guarded = observation(&lease);
        guarded.observed_at_ms = 21;
        guarded.health_score = 0.1;
        controller.observe(guarded).unwrap();
        let second = controller.shadow_decision_and_record(21).unwrap();
        assert_eq!(second.recommendations[0].recommended_concurrency, 1);

        let mut recovered = observation(&lease);
        recovered.observed_at_ms = 22;
        controller.observe(recovered).unwrap();
        let stepped = controller.shadow_decision(22).unwrap();
        assert_eq!(stepped.recommendations[0].recommended_concurrency, 2);
        assert!(
            !controller
                .inner
                .lock()
                .unwrap()
                .shadow_recommendations
                .is_empty()
        );

        controller
            .rollback_shadow_decision(&first.decision_digest, 23)
            .unwrap();
        assert!(
            controller
                .inner
                .lock()
                .unwrap()
                .shadow_recommendations
                .is_empty()
        );
        assert_eq!(
            controller.decision_audit().active_digest(),
            Some(first.decision_digest.clone())
        );

        // The current observation is healthy (raw recommendation 8).  A
        // stale post-recovery value of 2 would advance only to 3; a reset
        // starts a fresh projection and returns the raw value directly.
        let fresh = controller.shadow_decision(23).unwrap();
        assert_eq!(fresh.recommendations[0].recommended_concurrency, 8);
    }

    #[test]
    fn historical_shadow_digest_replay_is_idempotent_and_non_activating() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        let first = controller.shadow_decision_and_record(20).unwrap();

        let mut guarded = observation(&lease);
        guarded.observed_at_ms = 21;
        guarded.health_score = 0.1;
        controller.observe(guarded).unwrap();
        let second = controller.shadow_decision_and_record(21).unwrap();
        assert_ne!(first.decision_digest, second.decision_digest);

        controller
            .rollback_shadow_decision(&first.decision_digest, 22)
            .unwrap();
        let audit = controller.decision_audit();
        assert_eq!(audit.active_digest(), Some(first.decision_digest.clone()));
        assert_eq!(audit.len(), 3);
        let history_after_rollback = controller
            .inner
            .lock()
            .unwrap()
            .shadow_recommendations
            .clone();

        // Replaying the exact historical decision is rejected rather than
        // silently claiming to record it.  The audit and staged hysteresis
        // state remain unchanged.
        assert!(matches!(
            controller.shadow_decision_and_record(21),
            Err(ControlError::Invalid(message)) if message.contains("historical")
        ));
        assert_eq!(audit.len(), 3);
        assert_eq!(audit.active_digest(), Some(first.decision_digest.clone()));
        assert_eq!(
            controller.inner.lock().unwrap().shadow_recommendations,
            history_after_rollback
        );

        // The standalone audit handle follows the same fail-closed rule.
        assert!(matches!(
            audit.record(&second, 23),
            Err(ControlError::Invalid(message)) if message.contains("historical")
        ));
        assert_eq!(audit.active_digest(), Some(first.decision_digest.clone()));
        assert_eq!(audit.len(), 3);
    }

    #[test]
    fn shadow_decision_and_record_does_not_commit_history_without_audit_entry() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let audit = controller.decision_audit();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();
        controller.shadow_decision_and_record(20).unwrap();

        // Change the projection so the attempted call would advance the
        // recommendation (the first decision is steady-state, this sample
        // trips the health safety guard).  Then simulate a full audit log by
        // lowering its test-only capacity to the current entry count.
        let mut guarded = observation(&lease);
        guarded.observed_at_ms = 21;
        guarded.health_score = 0.1;
        controller.observe(guarded).unwrap();
        {
            let mut state = audit.inner.lock().unwrap();
            state.max_entries = state.entries.len();
        }
        let history_before = controller
            .inner
            .lock()
            .unwrap()
            .shadow_recommendations
            .clone();
        assert_eq!(
            controller.shadow_decision_and_record(40),
            Err(ControlError::CapacityExceeded)
        );
        assert_eq!(
            controller.inner.lock().unwrap().shadow_recommendations,
            history_before
        );
        assert_eq!(audit.len(), 1);

        // Once capacity is restored, retrying the same timestamp must append
        // exactly one decision and then commit the staged safety recommendation.
        {
            let mut state = audit.inner.lock().unwrap();
            state.max_entries = state.entries.len() + 1;
        }
        let retry = controller.shadow_decision_and_record(40).unwrap();
        assert_eq!(retry.recommendations[0].recommended_concurrency, 1);
        assert_eq!(audit.len(), 2);
        assert_eq!(
            controller
                .inner
                .lock()
                .unwrap()
                .shadow_recommendations
                .values()
                .next()
                .unwrap()
                .recommended_concurrency,
            1
        );
    }

    #[test]
    fn recording_recomputes_shadow_projection_and_rotation_clears_active_digest() {
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();
        let decision = controller.shadow_decision(20).unwrap();
        let mut forged = decision.clone();
        forged.recommendations[0].recommended_concurrency = 1;
        forged.decision_digest = forged.compute_digest().unwrap();
        assert!(matches!(
            controller.record_shadow_decision(&forged, 20),
            Err(ControlError::Invalid(message)) if message.contains("projection")
        ));
        controller.record_shadow_decision(&decision, 20).unwrap();
        assert_eq!(
            controller.decision_audit().active_digest(),
            Some(decision.decision_digest)
        );
        controller.rotate_epoch(2).unwrap();
        assert_eq!(controller.decision_audit().active_digest(), None);
        controller.decision_audit().verify().unwrap();
    }

    #[test]
    fn decision_audit_capacity_is_fail_closed_and_exact_retries_are_idempotent() {
        let audit = DecisionAuditLog::new(1).unwrap();
        let controller = Controller::new(ControlMode::Shadow, 1, config()).unwrap();
        let lease = issue(&controller, "jobs", "j-1", "p0", 10, None);
        controller.observe(observation(&lease)).unwrap();
        let decision = controller.shadow_decision(20).unwrap();
        let first = audit.record(&decision, 20).unwrap();
        assert_eq!(audit.record(&decision, 21).unwrap(), first);
        let mut changed = decision.clone();
        changed.generated_at_ms = 21;
        changed.decision_digest = changed.compute_digest().unwrap();
        assert_eq!(
            audit.record(&changed, 21).unwrap_err(),
            ControlError::CapacityExceeded
        );
    }
}
