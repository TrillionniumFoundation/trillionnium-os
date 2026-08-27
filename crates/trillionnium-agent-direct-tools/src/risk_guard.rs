//! Deterministic Agent-owned policy for direct Android OS-control actions.
//!
//! This is a pure policy layer. It is not a broker, backend selector,
//! Authority service, or OS dispatcher. Codex calls this evaluator after
//! selecting a typed backend action.
//!
//! Product policy intentionally has no enabled, authenticated lease-consume
//! path today. Actions that cannot be proven low risk therefore fail closed.
//! Neither risk tiers, leases, policy paths, nor overrides are part of a
//! model-facing request. Candidate leases exist only in this module's unit-test
//! compilation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use trillionnium_os_types::agent_direct_permission_model::{
    self, PermissionAction, PermissionDisposition, PermissionPrincipal, PermissionSurface,
};
use trillionnium_os_types::agent_principal_registry::{
    self, AgentStablePrincipal, CODEX_STABLE_PRINCIPAL,
};
use url::{Host, Url};

use crate::Result;
use crate::accessibility::{
    AccessibilityBatchAction as WireBatchAction, AccessibilityRequest,
    GesturePoint as WireGesturePoint, GlobalAction as WireGlobalAction, MAX_BATCH_ACTIONS,
    MAX_BATCH_GESTURE_DURATION_MS, MAX_GESTURE_DURATION_MS, ScrollDirection as WireScrollDirection,
    SnapshotMode, valid_node_id_shape,
};
use crate::system_api::SystemApiRequest;

pub const EVIDENCE_SCHEMA: &str = "org.trillionnium.agent-risk-guard-evidence.v1";
pub const POLICY_VERSION: &str = "org.trillionnium.agent-risk-guard.v1";
const MAX_ANDROID_USER_ID: u32 = 999;
const MAX_PACKAGE_BYTES: usize = 255;
const MAX_URI_BYTES: usize = 4_096;
const MAX_TEXT_UTF16_CODE_UNITS: usize = 16_384;
const MAX_GESTURE_POINTS: usize = 128;
const MAX_GESTURE_COORDINATE: f32 = 100_000.0;
#[cfg(test)]
const MAX_LEASE_LIFETIME_MS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentIdentity {
    Codex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolIdentity {
    SystemApi,
    Accessibility,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Observe,
    LowNavigation,
    SensitiveEffect,
    CriticalEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredAuthority {
    None,
    OsSessionLease,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    NotRequired,
    IssuerUnavailable,
    Missing,
    NotYetValid,
    Expired,
    LifetimeExceeded,
    Rebooted,
    PolicyMismatch,
    AgentMismatch,
    ToolMismatch,
    ActionMismatch,
    InsufficientTier,
    Valid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    DefaultObserveAllowed,
    DefaultLowNavigationAllowed,
    MalformedTypedActionRejected,
    UnsafeUriRejected,
    TrustedLeaseIssuerUnavailable,
    TrustedLeaseMissing,
    TrustedLeaseNotYetValid,
    TrustedLeaseExpired,
    TrustedLeaseLifetimeExceeded,
    TrustedLeaseRebooted,
    TrustedLeasePolicyMismatch,
    TrustedLeaseAgentMismatch,
    TrustedLeaseToolMismatch,
    TrustedLeaseActionMismatch,
    TrustedLeaseInsufficientTier,
    TrustedLeaseAccepted,
    PermissionModelDenied,
    PermissionModelUnavailable,
}

/// Closed, non-secret evidence suitable for a future per-call receipt.
///
/// `action_binding_sha256` covers every typed action field but stores none of
/// them. In particular, URI, node ID, and `set_text` material never appear in
/// this evidence object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardEvidence {
    pub schema: String,
    pub policy_version: String,
    pub permission_model_sha256: String,
    pub agent: AgentIdentity,
    pub tool: ToolIdentity,
    pub action_kind: String,
    pub action_binding_sha256: String,
    pub risk_tier: RiskTier,
    pub required_authority: RequiredAuthority,
    pub decision: GuardDecision,
    pub reason_code: ReasonCode,
    pub lease_state: LeaseState,
    pub batch_action_count: Option<u16>,
    pub batch_max_risk_tier: Option<RiskTier>,
}

impl GuardEvidence {
    #[must_use]
    pub const fn allowed(&self) -> bool {
        matches!(self.decision, GuardDecision::Allow)
    }
}

/// Typed System API business actions. Protocol and request identity are
/// intentionally absent because they cannot lower risk.
#[derive(Debug, Clone, Copy)]
pub enum SystemAction<'a> {
    LaunchPackage { package: &'a str, user: u32 },
    OpenUri { uri: &'a str, user: u32 },
}

/// Typed Accessibility business actions. Opaque node IDs are not trusted as
/// semantic claims; click, text, and gesture therefore remain sensitive.
#[derive(Debug, Clone, Copy)]
pub enum AccessibilityAction<'a> {
    Snapshot {
        window_id: Option<i32>,
        snapshot_mode: SnapshotMode,
    },
    Click {
        node_id: &'a str,
    },
    SetText {
        node_id: &'a str,
        text: &'a str,
    },
    Scroll {
        node_id: &'a str,
        direction: ScrollDirection,
    },
    GlobalAction {
        action: GlobalAction,
    },
    Gesture {
        points: &'a [GesturePoint],
        duration_ms: u64,
    },
    Batch {
        actions: &'a [BatchAction<'a>],
    },
}

#[derive(Debug, Clone, Copy)]
pub enum BatchAction<'a> {
    Click {
        node_id: &'a str,
    },
    SetText {
        node_id: &'a str,
        text: &'a str,
    },
    Scroll {
        node_id: &'a str,
        direction: ScrollDirection,
    },
    GlobalAction {
        action: GlobalAction,
    },
    Gesture {
        points: &'a [GesturePoint],
        duration_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollDirection {
    Forward,
    Backward,
    Up,
    Down,
    Left,
    Right,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalAction {
    Back,
    Home,
    Recents,
    Notifications,
    QuickSettings,
    PowerDialog,
    LockScreen,
    TakeScreenshot,
}

#[derive(Debug, Clone, Copy)]
pub struct GesturePoint {
    pub x: f32,
    pub y: f32,
    pub at_ms: u64,
}

/// Product construction is deliberately not configurable. There is no env,
/// CLI, feature, policy file, or model field that enables sensitive actions.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProductRiskGuard;

impl ProductRiskGuard {
    #[must_use]
    pub fn assess_system(self, agent: AgentIdentity, action: SystemAction<'_>) -> GuardEvidence {
        evaluate(
            agent,
            classify_system(action),
            LeaseInput::IssuerUnavailable,
        )
    }

    #[must_use]
    pub fn assess_accessibility(
        self,
        agent: AgentIdentity,
        action: AccessibilityAction<'_>,
    ) -> GuardEvidence {
        evaluate(
            agent,
            classify_accessibility(action),
            LeaseInput::IssuerUnavailable,
        )
    }

    /// Assess the exact typed System API wire request. Protocol and request ID
    /// are validated by the adapter and intentionally do not participate in
    /// the business-action risk binding.
    #[must_use]
    pub fn assess_system_request(
        self,
        agent: AgentIdentity,
        request: &SystemApiRequest,
    ) -> GuardEvidence {
        let action = match request {
            SystemApiRequest::LaunchPackage { package, user, .. } => SystemAction::LaunchPackage {
                package,
                user: *user,
            },
            SystemApiRequest::OpenUri { uri, user, .. } => {
                SystemAction::OpenUri { uri, user: *user }
            }
        };
        self.assess_system(agent, action)
    }

    /// Assess the exact typed Accessibility wire request, including every
    /// batch child and the privacy-significant snapshot mode.
    #[must_use]
    pub fn assess_accessibility_request(
        self,
        agent: AgentIdentity,
        request: &AccessibilityRequest,
    ) -> GuardEvidence {
        match request {
            AccessibilityRequest::Snapshot {
                window_id,
                snapshot_mode,
                ..
            } => self.assess_accessibility(
                agent,
                AccessibilityAction::Snapshot {
                    window_id: *window_id,
                    snapshot_mode: *snapshot_mode,
                },
            ),
            AccessibilityRequest::Click { node_id, .. } => {
                self.assess_accessibility(agent, AccessibilityAction::Click { node_id })
            }
            AccessibilityRequest::SetText { node_id, text, .. } => {
                self.assess_accessibility(agent, AccessibilityAction::SetText { node_id, text })
            }
            AccessibilityRequest::Scroll {
                node_id, direction, ..
            } => self.assess_accessibility(
                agent,
                AccessibilityAction::Scroll {
                    node_id,
                    direction: map_scroll_direction(direction),
                },
            ),
            AccessibilityRequest::GlobalAction { global_action, .. } => self.assess_accessibility(
                agent,
                AccessibilityAction::GlobalAction {
                    action: map_global_action(global_action),
                },
            ),
            AccessibilityRequest::Gesture {
                points,
                duration_ms,
                ..
            } => {
                let points = points.iter().map(map_gesture_point).collect::<Vec<_>>();
                self.assess_accessibility(
                    agent,
                    AccessibilityAction::Gesture {
                        points: &points,
                        duration_ms: *duration_ms,
                    },
                )
            }
            AccessibilityRequest::Batch { actions, .. } => {
                let gesture_points = actions
                    .iter()
                    .filter_map(|action| match action {
                        WireBatchAction::Gesture { points, .. } => Some(
                            points
                                .iter()
                                .map(map_gesture_point)
                                .collect::<Vec<GesturePoint>>(),
                        ),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let mut gesture_index = 0_usize;
                let actions = actions
                    .iter()
                    .map(|action| match action {
                        WireBatchAction::Click { node_id } => BatchAction::Click { node_id },
                        WireBatchAction::SetText { node_id, text } => {
                            BatchAction::SetText { node_id, text }
                        }
                        WireBatchAction::Scroll { node_id, direction } => BatchAction::Scroll {
                            node_id,
                            direction: map_scroll_direction(direction),
                        },
                        WireBatchAction::GlobalAction { global_action } => {
                            BatchAction::GlobalAction {
                                action: map_global_action(global_action),
                            }
                        }
                        WireBatchAction::Gesture { duration_ms, .. } => {
                            let points = &gesture_points[gesture_index];
                            gesture_index += 1;
                            BatchAction::Gesture {
                                points,
                                duration_ms: *duration_ms,
                            }
                        }
                    })
                    .collect::<Vec<_>>();
                self.assess_accessibility(agent, AccessibilityAction::Batch { actions: &actions })
            }
        }
    }
}

/// Resolve the only product Agent principal from real/effective process
/// credentials. There is no environment, argument, or model-controlled
/// override. Unit and explicitly feature-gated host development builds use a
/// deterministic Codex identity because production credentials do not exist
/// on the build host; product builds fail closed for every other UID/GID.
pub fn current_agent_identity() -> Result<AgentIdentity> {
    let uid = unsafe { libc::getuid() };
    let effective_uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let effective_gid = unsafe { libc::getegid() };
    if uid == effective_uid
        && gid == effective_gid
        && agent_principal_registry::from_uid_gid(uid, gid)
            == Some(stable_principal(AgentIdentity::Codex))
    {
        return Ok(AgentIdentity::Codex);
    }
    #[cfg(any(test, feature = "dev-overrides"))]
    return Ok(AgentIdentity::Codex);
    #[cfg(not(any(test, feature = "dev-overrides")))]
    Err(crate::DirectToolError::BackendUnavailable(
        "direct risk guard requires a fixed product Agent UID/GID".to_string(),
    ))
}

const fn stable_principal(agent: AgentIdentity) -> &'static AgentStablePrincipal {
    match agent {
        AgentIdentity::Codex => &CODEX_STABLE_PRINCIPAL,
    }
}

fn map_scroll_direction(direction: &WireScrollDirection) -> ScrollDirection {
    match direction {
        WireScrollDirection::Forward => ScrollDirection::Forward,
        WireScrollDirection::Backward => ScrollDirection::Backward,
        WireScrollDirection::Up => ScrollDirection::Up,
        WireScrollDirection::Down => ScrollDirection::Down,
        WireScrollDirection::Left => ScrollDirection::Left,
        WireScrollDirection::Right => ScrollDirection::Right,
    }
}

fn map_global_action(action: &WireGlobalAction) -> GlobalAction {
    match action {
        WireGlobalAction::Back => GlobalAction::Back,
        WireGlobalAction::Home => GlobalAction::Home,
        WireGlobalAction::Recents => GlobalAction::Recents,
        WireGlobalAction::Notifications => GlobalAction::Notifications,
        WireGlobalAction::QuickSettings => GlobalAction::QuickSettings,
        WireGlobalAction::PowerDialog => GlobalAction::PowerDialog,
        WireGlobalAction::LockScreen => GlobalAction::LockScreen,
        WireGlobalAction::TakeScreenshot => GlobalAction::TakeScreenshot,
    }
}

fn map_gesture_point(point: &WireGesturePoint) -> GesturePoint {
    GesturePoint {
        x: point.x,
        y: point.y,
        at_ms: point.at_ms,
    }
}

#[derive(Debug)]
struct ClassifiedAction {
    tool: ToolIdentity,
    kind: &'static str,
    permission_action: PermissionAction,
    binding: String,
    tier: RiskTier,
    hard_denial: Option<ReasonCode>,
    batch_action_count: Option<u16>,
    batch_max_risk_tier: Option<RiskTier>,
}

#[derive(Debug, Clone)]
enum LeaseInput {
    IssuerUnavailable,
    #[cfg(test)]
    Missing,
    #[cfg(test)]
    Candidate {
        now_monotonic_ms: u64,
        boot_generation: String,
        claims: TestLeaseClaims,
    },
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct TestLeaseClaims {
    policy_version: String,
    agent: AgentIdentity,
    tool: ToolIdentity,
    action_binding_sha256: String,
    max_risk_tier: RiskTier,
    boot_generation: String,
    not_before_monotonic_ms: u64,
    expires_monotonic_ms: u64,
}

fn classify_system(action: SystemAction<'_>) -> ClassifiedAction {
    match action {
        SystemAction::LaunchPackage { package, user } => ClassifiedAction {
            tool: ToolIdentity::SystemApi,
            kind: "launch_package",
            permission_action: PermissionAction::LaunchPackage,
            binding: binding_hash(|hash| {
                hash_field(hash, b"launch_package");
                hash_field(hash, package.as_bytes());
                hash_field(hash, &user.to_be_bytes());
            }),
            tier: RiskTier::LowNavigation,
            hard_denial: (!(valid_package(package) && user <= MAX_ANDROID_USER_ID))
                .then_some(ReasonCode::MalformedTypedActionRejected),
            batch_action_count: None,
            batch_max_risk_tier: None,
        },
        SystemAction::OpenUri { uri, user } => ClassifiedAction {
            tool: ToolIdentity::SystemApi,
            kind: "open_uri",
            permission_action: PermissionAction::OpenUri,
            binding: binding_hash(|hash| {
                hash_field(hash, b"open_uri");
                hash_field(hash, uri.as_bytes());
                hash_field(hash, &user.to_be_bytes());
            }),
            tier: RiskTier::CriticalEffect,
            hard_denial: if user > MAX_ANDROID_USER_ID
                || uri.is_empty()
                || uri.len() > MAX_URI_BYTES
            {
                Some(ReasonCode::MalformedTypedActionRejected)
            } else {
                (!uri_has_safe_external_shape(uri)).then_some(ReasonCode::UnsafeUriRejected)
            },
            batch_action_count: None,
            batch_max_risk_tier: None,
        },
    }
}

fn classify_accessibility(action: AccessibilityAction<'_>) -> ClassifiedAction {
    match action {
        AccessibilityAction::Snapshot {
            window_id,
            snapshot_mode,
        } => ClassifiedAction {
            tool: ToolIdentity::Accessibility,
            kind: "snapshot",
            permission_action: match snapshot_mode {
                SnapshotMode::MetadataOnly => PermissionAction::SnapshotMetadataOnly,
                SnapshotMode::FullText => PermissionAction::SnapshotFullText,
            },
            binding: binding_hash(|hash| {
                hash_field(hash, b"snapshot");
                match window_id {
                    Some(window_id) => hash_field(hash, &window_id.to_be_bytes()),
                    None => hash_field(hash, b"all-windows"),
                }
                hash_field(hash, snapshot_mode.as_str().as_bytes());
            }),
            tier: match snapshot_mode {
                SnapshotMode::MetadataOnly => RiskTier::Observe,
                SnapshotMode::FullText => RiskTier::SensitiveEffect,
            },
            hard_denial: window_id
                .is_some_and(|window_id| window_id < 0)
                .then_some(ReasonCode::MalformedTypedActionRejected),
            batch_action_count: None,
            batch_max_risk_tier: None,
        },
        AccessibilityAction::Click { node_id } => {
            classify_node_effect("click", PermissionAction::Click, node_id, None)
        }
        AccessibilityAction::SetText { node_id, text } => {
            classify_node_effect("set_text", PermissionAction::SetText, node_id, Some(text))
        }
        AccessibilityAction::Scroll { node_id, direction } => ClassifiedAction {
            tool: ToolIdentity::Accessibility,
            kind: "scroll",
            permission_action: PermissionAction::Scroll,
            binding: binding_hash(|hash| {
                hash_field(hash, b"scroll");
                hash_field(hash, node_id.as_bytes());
                hash_field(hash, scroll_name(direction));
            }),
            tier: RiskTier::LowNavigation,
            hard_denial: (!valid_node_id_shape(node_id))
                .then_some(ReasonCode::MalformedTypedActionRejected),
            batch_action_count: None,
            batch_max_risk_tier: None,
        },
        AccessibilityAction::GlobalAction { action } => ClassifiedAction {
            tool: ToolIdentity::Accessibility,
            kind: global_action_name(action),
            permission_action: global_action_permission(action),
            binding: binding_hash(|hash| {
                hash_field(hash, b"global_action");
                hash_field(hash, global_action_name(action).as_bytes());
            }),
            tier: global_action_tier(action),
            hard_denial: None,
            batch_action_count: None,
            batch_max_risk_tier: None,
        },
        AccessibilityAction::Gesture {
            points,
            duration_ms,
        } => ClassifiedAction {
            tool: ToolIdentity::Accessibility,
            kind: "gesture",
            permission_action: PermissionAction::Gesture,
            binding: gesture_binding("gesture", points, duration_ms),
            tier: RiskTier::SensitiveEffect,
            hard_denial: (!valid_gesture(points, duration_ms))
                .then_some(ReasonCode::MalformedTypedActionRejected),
            batch_action_count: None,
            batch_max_risk_tier: None,
        },
        AccessibilityAction::Batch { actions } => classify_batch(actions),
    }
}

fn classify_node_effect(
    kind: &'static str,
    permission_action: PermissionAction,
    node_id: &str,
    text: Option<&str>,
) -> ClassifiedAction {
    ClassifiedAction {
        tool: ToolIdentity::Accessibility,
        kind,
        permission_action,
        binding: binding_hash(|hash| {
            hash_field(hash, kind.as_bytes());
            hash_field(hash, node_id.as_bytes());
            if let Some(text) = text {
                hash_field(hash, text.as_bytes());
            }
        }),
        tier: RiskTier::SensitiveEffect,
        hard_denial: (!(valid_node_id_shape(node_id) && text.is_none_or(valid_text)))
            .then_some(ReasonCode::MalformedTypedActionRejected),
        batch_action_count: None,
        batch_max_risk_tier: None,
    }
}

fn classify_batch(actions: &[BatchAction<'_>]) -> ClassifiedAction {
    let mut max_tier = RiskTier::Observe;
    let mut malformed = actions.is_empty() || actions.len() > MAX_BATCH_ACTIONS;
    let mut cumulative_gesture_ms = 0_u64;
    let binding = binding_hash(|hash| {
        hash_field(hash, b"batch");
        hash_field(hash, &usize_to_u64(actions.len()).to_be_bytes());
        for action in actions {
            let classified = classify_batch_action(*action);
            max_tier = max_tier.max(classified.tier);
            malformed |= classified.hard_denial.is_some();
            if let BatchAction::Gesture { duration_ms, .. } = action {
                match cumulative_gesture_ms.checked_add(*duration_ms) {
                    Some(total) => cumulative_gesture_ms = total,
                    None => malformed = true,
                }
            }
            hash_field(hash, classified.kind.as_bytes());
            hash_field(hash, classified.binding.as_bytes());
        }
    });
    malformed |= cumulative_gesture_ms > MAX_BATCH_GESTURE_DURATION_MS;
    ClassifiedAction {
        tool: ToolIdentity::Accessibility,
        kind: "batch",
        permission_action: PermissionAction::Batch,
        binding,
        tier: max_tier,
        hard_denial: malformed.then_some(ReasonCode::MalformedTypedActionRejected),
        batch_action_count: u16::try_from(actions.len()).ok(),
        batch_max_risk_tier: Some(max_tier),
    }
}

fn classify_batch_action(action: BatchAction<'_>) -> ClassifiedAction {
    match action {
        BatchAction::Click { node_id } => {
            classify_node_effect("click", PermissionAction::Click, node_id, None)
        }
        BatchAction::SetText { node_id, text } => {
            classify_node_effect("set_text", PermissionAction::SetText, node_id, Some(text))
        }
        BatchAction::Scroll { node_id, direction } => {
            classify_accessibility(AccessibilityAction::Scroll { node_id, direction })
        }
        BatchAction::GlobalAction { action } => {
            classify_accessibility(AccessibilityAction::GlobalAction { action })
        }
        BatchAction::Gesture {
            points,
            duration_ms,
        } => classify_accessibility(AccessibilityAction::Gesture {
            points,
            duration_ms,
        }),
    }
}

fn evaluate(agent: AgentIdentity, action: ClassifiedAction, lease: LeaseInput) -> GuardEvidence {
    if let Some(reason_code) = action.hard_denial {
        return evidence(
            agent,
            action,
            GuardDecision::Deny,
            RequiredAuthority::None,
            reason_code,
            LeaseState::NotRequired,
        );
    }
    let disposition = preliminary_permission(agent, &action);
    match disposition {
        Ok(PermissionDisposition::PolicyAllowRequiresEffectCustody)
            if action.tier <= RiskTier::LowNavigation =>
        {
            allow_low_risk(agent, action)
        }
        Ok(PermissionDisposition::OsSessionLeaseRequired)
            if action.tier > RiskTier::LowNavigation =>
        {
            evaluate_lease(agent, action, lease)
        }
        Ok(PermissionDisposition::ConditionalEveryBatchMember)
            if action.permission_action == PermissionAction::Batch =>
        {
            if action.tier <= RiskTier::LowNavigation {
                allow_low_risk(agent, action)
            } else {
                evaluate_lease(agent, action, lease)
            }
        }
        Ok(_) => evidence(
            agent,
            action,
            GuardDecision::Deny,
            RequiredAuthority::None,
            ReasonCode::PermissionModelDenied,
            LeaseState::NotRequired,
        ),
        Err(()) => evidence(
            agent,
            action,
            GuardDecision::Deny,
            RequiredAuthority::None,
            ReasonCode::PermissionModelUnavailable,
            LeaseState::NotRequired,
        ),
    }
}

fn preliminary_permission(
    agent: AgentIdentity,
    action: &ClassifiedAction,
) -> std::result::Result<PermissionDisposition, ()> {
    let principal =
        PermissionPrincipal::from_stable_principal(stable_principal(agent)).map_err(|_| ())?;
    let surface = match action.tool {
        ToolIdentity::SystemApi => PermissionSurface::DirectSystemApi,
        ToolIdentity::Accessibility => PermissionSurface::DirectAccessibility,
    };
    agent_direct_permission_model::permission_disposition(
        principal,
        surface,
        action.permission_action,
    )
    .map_err(|_| ())
}

fn allow_low_risk(agent: AgentIdentity, action: ClassifiedAction) -> GuardEvidence {
    let reason = match action.tier {
        RiskTier::Observe => ReasonCode::DefaultObserveAllowed,
        RiskTier::LowNavigation => ReasonCode::DefaultLowNavigationAllowed,
        RiskTier::SensitiveEffect | RiskTier::CriticalEffect => {
            return evidence(
                agent,
                action,
                GuardDecision::Deny,
                RequiredAuthority::None,
                ReasonCode::PermissionModelDenied,
                LeaseState::NotRequired,
            );
        }
    };
    evidence(
        agent,
        action,
        GuardDecision::Allow,
        RequiredAuthority::None,
        reason,
        LeaseState::NotRequired,
    )
}

fn evaluate_lease(
    agent: AgentIdentity,
    action: ClassifiedAction,
    lease: LeaseInput,
) -> GuardEvidence {
    match lease {
        LeaseInput::IssuerUnavailable => evidence(
            agent,
            action,
            GuardDecision::Deny,
            RequiredAuthority::OsSessionLease,
            ReasonCode::TrustedLeaseIssuerUnavailable,
            LeaseState::IssuerUnavailable,
        ),
        #[cfg(test)]
        LeaseInput::Missing => evidence(
            agent,
            action,
            GuardDecision::Deny,
            RequiredAuthority::OsSessionLease,
            ReasonCode::TrustedLeaseMissing,
            LeaseState::Missing,
        ),
        #[cfg(test)]
        LeaseInput::Candidate {
            now_monotonic_ms,
            boot_generation,
            claims,
        } => evaluate_test_lease(agent, action, now_monotonic_ms, &boot_generation, &claims),
    }
}

#[cfg(test)]
fn evaluate_test_lease(
    agent: AgentIdentity,
    action: ClassifiedAction,
    now: u64,
    boot_generation: &str,
    claims: &TestLeaseClaims,
) -> GuardEvidence {
    let denial = if claims.policy_version != POLICY_VERSION {
        Some((
            ReasonCode::TrustedLeasePolicyMismatch,
            LeaseState::PolicyMismatch,
        ))
    } else if claims.agent != agent {
        Some((
            ReasonCode::TrustedLeaseAgentMismatch,
            LeaseState::AgentMismatch,
        ))
    } else if claims.tool != action.tool {
        Some((
            ReasonCode::TrustedLeaseToolMismatch,
            LeaseState::ToolMismatch,
        ))
    } else if claims.action_binding_sha256 != action.binding {
        Some((
            ReasonCode::TrustedLeaseActionMismatch,
            LeaseState::ActionMismatch,
        ))
    } else if claims.boot_generation != boot_generation {
        Some((ReasonCode::TrustedLeaseRebooted, LeaseState::Rebooted))
    } else if claims.not_before_monotonic_ms > now {
        Some((ReasonCode::TrustedLeaseNotYetValid, LeaseState::NotYetValid))
    } else if claims.expires_monotonic_ms < now {
        Some((ReasonCode::TrustedLeaseExpired, LeaseState::Expired))
    } else if claims
        .expires_monotonic_ms
        .checked_sub(claims.not_before_monotonic_ms)
        .is_none_or(|lifetime| lifetime > MAX_LEASE_LIFETIME_MS)
    {
        Some((
            ReasonCode::TrustedLeaseLifetimeExceeded,
            LeaseState::LifetimeExceeded,
        ))
    } else if claims.max_risk_tier < action.tier {
        Some((
            ReasonCode::TrustedLeaseInsufficientTier,
            LeaseState::InsufficientTier,
        ))
    } else {
        None
    };
    if let Some((reason, state)) = denial {
        evidence(
            agent,
            action,
            GuardDecision::Deny,
            RequiredAuthority::OsSessionLease,
            reason,
            state,
        )
    } else {
        evidence(
            agent,
            action,
            GuardDecision::Allow,
            RequiredAuthority::OsSessionLease,
            ReasonCode::TrustedLeaseAccepted,
            LeaseState::Valid,
        )
    }
}

fn evidence(
    agent: AgentIdentity,
    action: ClassifiedAction,
    decision: GuardDecision,
    required_authority: RequiredAuthority,
    reason_code: ReasonCode,
    lease_state: LeaseState,
) -> GuardEvidence {
    GuardEvidence {
        schema: EVIDENCE_SCHEMA.to_string(),
        policy_version: POLICY_VERSION.to_string(),
        permission_model_sha256: agent_direct_permission_model::PERMISSION_MODEL_SHA256.to_string(),
        agent,
        tool: action.tool,
        action_kind: action.kind.to_string(),
        action_binding_sha256: action.binding,
        risk_tier: action.tier,
        required_authority,
        decision,
        reason_code,
        lease_state,
        batch_action_count: action.batch_action_count,
        batch_max_risk_tier: action.batch_max_risk_tier,
    }
}

fn global_action_tier(action: GlobalAction) -> RiskTier {
    match action {
        GlobalAction::Back | GlobalAction::Home => RiskTier::LowNavigation,
        GlobalAction::Recents | GlobalAction::Notifications | GlobalAction::QuickSettings => {
            RiskTier::SensitiveEffect
        }
        GlobalAction::PowerDialog | GlobalAction::LockScreen | GlobalAction::TakeScreenshot => {
            RiskTier::CriticalEffect
        }
    }
}

fn global_action_name(action: GlobalAction) -> &'static str {
    match action {
        GlobalAction::Back => "global_back",
        GlobalAction::Home => "global_home",
        GlobalAction::Recents => "global_recents",
        GlobalAction::Notifications => "global_notifications",
        GlobalAction::QuickSettings => "global_quick_settings",
        GlobalAction::PowerDialog => "global_power_dialog",
        GlobalAction::LockScreen => "global_lock_screen",
        GlobalAction::TakeScreenshot => "global_take_screenshot",
    }
}

fn global_action_permission(action: GlobalAction) -> PermissionAction {
    match action {
        GlobalAction::Back => PermissionAction::GlobalBack,
        GlobalAction::Home => PermissionAction::GlobalHome,
        GlobalAction::Recents => PermissionAction::GlobalRecents,
        GlobalAction::Notifications => PermissionAction::GlobalNotifications,
        GlobalAction::QuickSettings => PermissionAction::GlobalQuickSettings,
        GlobalAction::PowerDialog => PermissionAction::GlobalPowerDialog,
        GlobalAction::LockScreen => PermissionAction::GlobalLockScreen,
        GlobalAction::TakeScreenshot => PermissionAction::GlobalTakeScreenshot,
    }
}

fn scroll_name(direction: ScrollDirection) -> &'static [u8] {
    match direction {
        ScrollDirection::Forward => b"forward",
        ScrollDirection::Backward => b"backward",
        ScrollDirection::Up => b"up",
        ScrollDirection::Down => b"down",
        ScrollDirection::Left => b"left",
        ScrollDirection::Right => b"right",
    }
}

fn gesture_binding(kind: &str, points: &[GesturePoint], duration_ms: u64) -> String {
    binding_hash(|hash| {
        hash_field(hash, kind.as_bytes());
        hash_field(hash, &duration_ms.to_be_bytes());
        hash_field(hash, &usize_to_u64(points.len()).to_be_bytes());
        for point in points {
            hash_field(hash, &point.x.to_bits().to_be_bytes());
            hash_field(hash, &point.y.to_bits().to_be_bytes());
            hash_field(hash, &point.at_ms.to_be_bytes());
        }
    })
}

fn binding_hash(update: impl FnOnce(&mut Sha256)) -> String {
    let mut hash = Sha256::new();
    hash_field(&mut hash, POLICY_VERSION.as_bytes());
    hash_field(
        &mut hash,
        agent_direct_permission_model::PERMISSION_MODEL_SHA256.as_bytes(),
    );
    update(&mut hash);
    format!("{:x}", hash.finalize())
}

fn hash_field(hash: &mut Sha256, value: &[u8]) {
    hash.update(usize_to_u64(value.len()).to_be_bytes());
    hash.update(value);
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn valid_package(package: &str) -> bool {
    !package.is_empty()
        && package.len() <= MAX_PACKAGE_BYTES
        && package.split('.').all(|segment| {
            let mut bytes = segment.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn valid_text(text: &str) -> bool {
    text.encode_utf16().count() <= MAX_TEXT_UTF16_CODE_UNITS
}

fn valid_gesture(points: &[GesturePoint], duration_ms: u64) -> bool {
    if points.is_empty()
        || points.len() > MAX_GESTURE_POINTS
        || duration_ms == 0
        || duration_ms > MAX_GESTURE_DURATION_MS
        || points.first().is_none_or(|point| point.at_ms != 0)
    {
        return false;
    }
    let mut previous = None;
    for point in points {
        if !point.x.is_finite()
            || !point.y.is_finite()
            || point.x < 0.0
            || point.y < 0.0
            || point.x > MAX_GESTURE_COORDINATE
            || point.y > MAX_GESTURE_COORDINATE
            || point.at_ms > duration_ms
            || previous.is_some_and(|previous| point.at_ms <= previous)
        {
            return false;
        }
        previous = Some(point.at_ms);
    }
    true
}

/// This validates only the shape eligible for future lease review. Every URI
/// remains `CriticalEffect`; a syntactically safe shape is never a default
/// authorization. Data-bearing web paths are rejected because the guard has
/// no trusted destination allowlist or semantic context.
fn uri_has_safe_external_shape(raw: &str) -> bool {
    if raw.is_empty()
        || !raw.is_ascii()
        || raw.contains('\\')
        || raw.contains('@')
        || raw
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || contains_encoded_delimiter_or_control(raw)
    {
        return false;
    }
    let Ok(uri) = Url::parse(raw) else {
        return false;
    };
    if !uri.username().is_empty()
        || uri.password().is_some()
        || uri.query().is_some()
        || uri.fragment().is_some()
    {
        return false;
    }
    match uri.scheme() {
        "http" | "https" => {
            if uri.port().is_some() || uri.path() != "/" {
                return false;
            }
            matches!(uri.host(), Some(Host::Domain(domain)) if valid_public_domain_shape(domain))
        }
        "content" => {
            uri.port().is_none()
                && matches!(uri.host(), Some(Host::Domain(authority)) if valid_android_authority_shape(authority))
        }
        "geo" => uri.cannot_be_a_base() && valid_geo_path(uri.path()),
        _ => false,
    }
}

fn contains_encoded_delimiter_or_control(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return true;
            }
            let Some(high) = hex(bytes[index + 1]) else {
                return true;
            };
            let Some(low) = hex(bytes[index + 2]) else {
                return true;
            };
            let decoded = high * 16 + low;
            if decoded <= 0x20
                || decoded == 0x7f
                || matches!(decoded, b'%' | b'\\' | b'/' | b'?' | b'#' | b'@' | b':')
            {
                return true;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_public_domain_shape(domain: &str) -> bool {
    domain.len() <= 253
        && domain.contains('.')
        && !domain.ends_with(".local")
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && !label.starts_with("xn--")
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_android_authority_shape(authority: &str) -> bool {
    authority.len() <= 255
        && authority.contains('.')
        && authority.split('.').all(|label| {
            let mut bytes = label.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn valid_geo_path(path: &str) -> bool {
    let Some((latitude, longitude)) = path.split_once(',') else {
        return false;
    };
    if longitude.contains(',') || latitude.is_empty() || longitude.is_empty() {
        return false;
    }
    let (Ok(latitude), Ok(longitude)) = (latitude.parse::<f64>(), longitude.parse::<f64>()) else {
        return false;
    };
    latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BOOT: &str = "boot-generation-a";

    fn guard() -> ProductRiskGuard {
        ProductRiskGuard
    }

    fn sensitive_click<'a>() -> AccessibilityAction<'a> {
        AccessibilityAction::Click { node_id: "node-1" }
    }

    fn assert_malformed(evidence: &GuardEvidence) {
        assert_eq!(evidence.decision, GuardDecision::Deny, "{evidence:?}");
        assert_eq!(
            evidence.reason_code,
            ReasonCode::MalformedTypedActionRejected,
            "{evidence:?}"
        );
        assert_eq!(evidence.required_authority, RequiredAuthority::None);
        assert_eq!(evidence.lease_state, LeaseState::NotRequired);
    }

    fn candidate_for(
        agent: AgentIdentity,
        evidence: &GuardEvidence,
        max_risk_tier: RiskTier,
    ) -> TestLeaseClaims {
        TestLeaseClaims {
            policy_version: POLICY_VERSION.to_string(),
            agent,
            tool: evidence.tool,
            action_binding_sha256: evidence.action_binding_sha256.clone(),
            max_risk_tier,
            boot_generation: BOOT.to_string(),
            not_before_monotonic_ms: 1_000,
            expires_monotonic_ms: 2_000,
        }
    }

    fn assess_click_with_lease(
        agent: AgentIdentity,
        claims: &TestLeaseClaims,
        now: u64,
        boot: &str,
    ) -> GuardEvidence {
        evaluate(
            agent,
            classify_accessibility(sensitive_click()),
            LeaseInput::Candidate {
                now_monotonic_ms: now,
                boot_generation: boot.to_string(),
                claims: claims.clone(),
            },
        )
    }

    #[test]
    fn product_default_set_is_closed_for_codex() {
        for agent in [AgentIdentity::Codex] {
            for action in [
                AccessibilityAction::Snapshot {
                    window_id: None,
                    snapshot_mode: SnapshotMode::MetadataOnly,
                },
                AccessibilityAction::Scroll {
                    node_id: "node-1",
                    direction: ScrollDirection::Down,
                },
                AccessibilityAction::GlobalAction {
                    action: GlobalAction::Back,
                },
                AccessibilityAction::GlobalAction {
                    action: GlobalAction::Home,
                },
            ] {
                let evidence = guard().assess_accessibility(agent, action);
                assert!(evidence.allowed(), "{evidence:?}");
                assert_eq!(evidence.required_authority, RequiredAuthority::None);
            }
            let launch = guard().assess_system(
                agent,
                SystemAction::LaunchPackage {
                    package: "com.example.app",
                    user: 0,
                },
            );
            assert!(launch.allowed());
            assert_eq!(launch.risk_tier, RiskTier::LowNavigation);
        }
    }

    #[test]
    fn malformed_default_allowed_actions_fail_before_policy_allowance() {
        for package in ["", "com..example", "-bad.example", "com.example/"] {
            let adapter = crate::system_api::SystemApiRequest::LaunchPackage {
                protocol: crate::system_api::PROTOCOL.to_string(),
                request_id: "risk-parity".to_string(),
                package: package.to_string(),
                user: 0,
            };
            assert!(crate::system_api::validate(&adapter).is_err());
            assert_malformed(&guard().assess_system(
                AgentIdentity::Codex,
                SystemAction::LaunchPackage { package, user: 0 },
            ));
        }
        let long_package = "a".repeat(MAX_PACKAGE_BYTES + 1);
        let adapter_long_package = crate::system_api::SystemApiRequest::LaunchPackage {
            protocol: crate::system_api::PROTOCOL.to_string(),
            request_id: "risk-parity".to_string(),
            package: long_package.clone(),
            user: 0,
        };
        assert!(crate::system_api::validate(&adapter_long_package).is_err());
        assert_malformed(&guard().assess_system(
            AgentIdentity::Codex,
            SystemAction::LaunchPackage {
                package: &long_package,
                user: 0,
            },
        ));
        let adapter_invalid_user = crate::system_api::SystemApiRequest::LaunchPackage {
            protocol: crate::system_api::PROTOCOL.to_string(),
            request_id: "risk-parity".to_string(),
            package: "com.example".to_string(),
            user: MAX_ANDROID_USER_ID + 1,
        };
        assert!(crate::system_api::validate(&adapter_invalid_user).is_err());
        assert_malformed(&guard().assess_system(
            AgentIdentity::Codex,
            SystemAction::LaunchPackage {
                package: "com.example",
                user: MAX_ANDROID_USER_ID + 1,
            },
        ));
        assert_malformed(&guard().assess_system(
            AgentIdentity::Codex,
            SystemAction::OpenUri {
                uri: "https://example.com/",
                user: MAX_ANDROID_USER_ID + 1,
            },
        ));

        let invalid_snapshot = crate::accessibility::AccessibilityRequest::Snapshot {
            protocol: crate::accessibility::PROTOCOL.to_string(),
            request_id: "risk-parity".to_string(),
            window_id: Some(-1),
            snapshot_mode: SnapshotMode::MetadataOnly,
        };
        assert!(crate::accessibility::validate(&invalid_snapshot).is_err());
        assert_malformed(&guard().assess_accessibility(
            AgentIdentity::Codex,
            AccessibilityAction::Snapshot {
                window_id: Some(-1),
                snapshot_mode: SnapshotMode::MetadataOnly,
            },
        ));

        let long_node = "n".repeat(crate::accessibility::MAX_NODE_ID_CHARS + 1);
        for node_id in ["", "node with space", "node\nline", &long_node] {
            let adapter = crate::accessibility::AccessibilityRequest::Scroll {
                protocol: crate::accessibility::PROTOCOL.to_string(),
                request_id: "risk-parity".to_string(),
                node_id: node_id.to_string(),
                direction: crate::accessibility::ScrollDirection::Forward,
            };
            assert!(crate::accessibility::validate(&adapter).is_err());
            assert_malformed(&guard().assess_accessibility(
                AgentIdentity::Codex,
                AccessibilityAction::Scroll {
                    node_id,
                    direction: ScrollDirection::Forward,
                },
            ));
        }

        let invalid_child = [BatchAction::Scroll {
            node_id: "bad node",
            direction: ScrollDirection::Down,
        }];
        let adapter_invalid_child = crate::accessibility::AccessibilityRequest::Batch {
            protocol: crate::accessibility::PROTOCOL.to_string(),
            request_id: "risk-parity".to_string(),
            actions: vec![crate::accessibility::AccessibilityBatchAction::Scroll {
                node_id: "bad node".to_string(),
                direction: crate::accessibility::ScrollDirection::Down,
            }],
        };
        assert!(crate::accessibility::validate(&adapter_invalid_child).is_err());
        assert_malformed(&guard().assess_accessibility(
            AgentIdentity::Codex,
            AccessibilityAction::Batch {
                actions: &invalid_child,
            },
        ));

        let valid_system = crate::system_api::SystemApiRequest::LaunchPackage {
            protocol: crate::system_api::PROTOCOL.to_string(),
            request_id: "risk-parity".to_string(),
            package: "com.example_app".to_string(),
            user: MAX_ANDROID_USER_ID,
        };
        assert!(crate::system_api::validate(&valid_system).is_ok());
        assert!(
            guard()
                .assess_system(
                    AgentIdentity::Codex,
                    SystemAction::LaunchPackage {
                        package: "com.example_app",
                        user: MAX_ANDROID_USER_ID,
                    },
                )
                .allowed()
        );
    }

    #[test]
    fn malformed_sensitive_effects_match_adapter_and_lease_cannot_override() {
        let long_text = "x".repeat(MAX_TEXT_UTF16_CODE_UNITS + 1);
        let adapter_text = crate::accessibility::AccessibilityRequest::SetText {
            protocol: crate::accessibility::PROTOCOL.to_string(),
            request_id: "risk-parity".to_string(),
            node_id: "node-1".to_string(),
            text: long_text.clone(),
        };
        assert!(crate::accessibility::validate(&adapter_text).is_err());
        assert_malformed(&guard().assess_accessibility(
            AgentIdentity::Codex,
            AccessibilityAction::SetText {
                node_id: "node-1",
                text: &long_text,
            },
        ));

        let gesture_cases = vec![
            (Vec::new(), 100),
            (
                vec![GesturePoint {
                    x: 1.0,
                    y: 1.0,
                    at_ms: 1,
                }],
                100,
            ),
            (
                vec![
                    GesturePoint {
                        x: 1.0,
                        y: 1.0,
                        at_ms: 0,
                    },
                    GesturePoint {
                        x: 2.0,
                        y: 2.0,
                        at_ms: 0,
                    },
                ],
                100,
            ),
            (
                vec![GesturePoint {
                    x: f32::NAN,
                    y: 1.0,
                    at_ms: 0,
                }],
                100,
            ),
            (
                vec![GesturePoint {
                    x: MAX_GESTURE_COORDINATE + 1.0,
                    y: 1.0,
                    at_ms: 0,
                }],
                100,
            ),
            (
                vec![GesturePoint {
                    x: 1.0,
                    y: 1.0,
                    at_ms: 101,
                }],
                100,
            ),
            (
                vec![GesturePoint {
                    x: 1.0,
                    y: 1.0,
                    at_ms: 0,
                }],
                0,
            ),
            (
                vec![GesturePoint {
                    x: 1.0,
                    y: 1.0,
                    at_ms: 0,
                }],
                MAX_GESTURE_DURATION_MS + 1,
            ),
            (
                vec![
                    GesturePoint {
                        x: 1.0,
                        y: 1.0,
                        at_ms: 0,
                    };
                    MAX_GESTURE_POINTS + 1
                ],
                100,
            ),
        ];
        for (points, duration_ms) in gesture_cases {
            let adapter_points = points
                .iter()
                .map(|point| crate::accessibility::GesturePoint {
                    x: point.x,
                    y: point.y,
                    at_ms: point.at_ms,
                })
                .collect();
            let adapter = crate::accessibility::AccessibilityRequest::Gesture {
                protocol: crate::accessibility::PROTOCOL.to_string(),
                request_id: "risk-parity".to_string(),
                points: adapter_points,
                duration_ms,
            };
            assert!(crate::accessibility::validate(&adapter).is_err());
            assert_malformed(&guard().assess_accessibility(
                AgentIdentity::Codex,
                AccessibilityAction::Gesture {
                    points: &points,
                    duration_ms,
                },
            ));
        }

        let points = [GesturePoint {
            x: 1.0,
            y: 1.0,
            at_ms: 0,
        }];
        let cumulative = [
            BatchAction::Gesture {
                points: &points,
                duration_ms: 40_000,
            },
            BatchAction::Gesture {
                points: &points,
                duration_ms: 40_000,
            },
        ];
        let adapter_cumulative = crate::accessibility::AccessibilityRequest::Batch {
            protocol: crate::accessibility::PROTOCOL.to_string(),
            request_id: "risk-parity".to_string(),
            actions: vec![
                crate::accessibility::AccessibilityBatchAction::Gesture {
                    points: vec![crate::accessibility::GesturePoint {
                        x: 1.0,
                        y: 1.0,
                        at_ms: 0,
                    }],
                    duration_ms: 40_000,
                },
                crate::accessibility::AccessibilityBatchAction::Gesture {
                    points: vec![crate::accessibility::GesturePoint {
                        x: 1.0,
                        y: 1.0,
                        at_ms: 0,
                    }],
                    duration_ms: 40_000,
                },
            ],
        };
        assert!(crate::accessibility::validate(&adapter_cumulative).is_err());
        let malformed = guard().assess_accessibility(
            AgentIdentity::Codex,
            AccessibilityAction::Batch {
                actions: &cumulative,
            },
        );
        assert_malformed(&malformed);

        let claims = candidate_for(AgentIdentity::Codex, &malformed, RiskTier::CriticalEffect);
        let still_malformed = evaluate(
            AgentIdentity::Codex,
            classify_accessibility(AccessibilityAction::Batch {
                actions: &cumulative,
            }),
            LeaseInput::Candidate {
                now_monotonic_ms: 1_500,
                boot_generation: BOOT.to_string(),
                claims,
            },
        );
        assert_malformed(&still_malformed);
    }

    #[test]
    fn set_text_guard_matches_utf16_wire_bound_for_direct_and_batch() {
        fn assert_boundary(text: &str, expected_valid: bool) {
            let direct_request = crate::accessibility::AccessibilityRequest::SetText {
                protocol: crate::accessibility::PROTOCOL.to_string(),
                request_id: "risk-utf16-direct".to_string(),
                node_id: "node-1".to_string(),
                text: text.to_string(),
            };
            let batch_request = crate::accessibility::AccessibilityRequest::Batch {
                protocol: crate::accessibility::PROTOCOL.to_string(),
                request_id: "risk-utf16-batch".to_string(),
                actions: vec![crate::accessibility::AccessibilityBatchAction::SetText {
                    node_id: "node-1".to_string(),
                    text: text.to_string(),
                }],
            };
            assert_eq!(
                crate::accessibility::validate(&direct_request).is_ok(),
                expected_valid
            );
            assert_eq!(
                crate::accessibility::validate(&batch_request).is_ok(),
                expected_valid
            );

            let batch_actions = [BatchAction::SetText {
                node_id: "node-1",
                text,
            }];
            let evidence = [
                guard().assess_accessibility(
                    AgentIdentity::Codex,
                    AccessibilityAction::SetText {
                        node_id: "node-1",
                        text,
                    },
                ),
                guard().assess_accessibility(
                    AgentIdentity::Codex,
                    AccessibilityAction::Batch {
                        actions: &batch_actions,
                    },
                ),
            ];
            for item in evidence {
                if expected_valid {
                    assert_eq!(item.reason_code, ReasonCode::TrustedLeaseIssuerUnavailable);
                    assert_eq!(item.required_authority, RequiredAuthority::OsSessionLease);
                } else {
                    assert_malformed(&item);
                }
            }
        }

        // BMP text consumes one UTF-16 code unit per character; an astral
        // character consumes two, independent of either string's UTF-8 size.
        assert_boundary(&"雪".repeat(MAX_TEXT_UTF16_CODE_UNITS), true);
        assert_boundary(&"雪".repeat(MAX_TEXT_UTF16_CODE_UNITS + 1), false);
        assert_boundary(&"😀".repeat(MAX_TEXT_UTF16_CODE_UNITS / 2), true);
        assert_boundary(&"😀".repeat(MAX_TEXT_UTF16_CODE_UNITS / 2 + 1), false);
    }

    #[test]
    fn opaque_ui_effects_never_claim_safe_semantics() {
        let points = [GesturePoint {
            x: 1.0,
            y: 2.0,
            at_ms: 0,
        }];
        for action in [
            AccessibilityAction::Click {
                node_id: "checkout.pay_now",
            },
            AccessibilityAction::SetText {
                node_id: "password",
                text: "credential-material",
            },
            AccessibilityAction::Gesture {
                points: &points,
                duration_ms: 100,
            },
        ] {
            let evidence = guard().assess_accessibility(AgentIdentity::Codex, action);
            assert_eq!(evidence.decision, GuardDecision::Deny);
            assert_eq!(evidence.risk_tier, RiskTier::SensitiveEffect);
            assert_eq!(
                evidence.reason_code,
                ReasonCode::TrustedLeaseIssuerUnavailable
            );
        }
    }

    #[test]
    fn sensitive_global_actions_are_disabled_without_os_lease_issuer() {
        for action in [
            GlobalAction::Recents,
            GlobalAction::Notifications,
            GlobalAction::QuickSettings,
            GlobalAction::PowerDialog,
            GlobalAction::LockScreen,
            GlobalAction::TakeScreenshot,
        ] {
            let evidence = guard().assess_accessibility(
                AgentIdentity::Codex,
                AccessibilityAction::GlobalAction { action },
            );
            assert_eq!(evidence.decision, GuardDecision::Deny);
            assert_eq!(
                evidence.required_authority,
                RequiredAuthority::OsSessionLease
            );
            assert_eq!(evidence.lease_state, LeaseState::IssuerUnavailable);
        }
    }

    #[test]
    fn batch_takes_maximum_risk_and_cannot_mix_around_guard() {
        let low = [
            BatchAction::Scroll {
                node_id: "node-1",
                direction: ScrollDirection::Forward,
            },
            BatchAction::GlobalAction {
                action: GlobalAction::Home,
            },
        ];
        let low_evidence = guard().assess_accessibility(
            AgentIdentity::Codex,
            AccessibilityAction::Batch { actions: &low },
        );
        assert!(low_evidence.allowed());
        assert_eq!(low_evidence.batch_action_count, Some(2));
        assert_eq!(
            low_evidence.batch_max_risk_tier,
            Some(RiskTier::LowNavigation)
        );

        let mixed = [
            BatchAction::Scroll {
                node_id: "node-1",
                direction: ScrollDirection::Forward,
            },
            BatchAction::SetText {
                node_id: "node-2",
                text: "possible-secret",
            },
            BatchAction::GlobalAction {
                action: GlobalAction::TakeScreenshot,
            },
        ];
        let mixed_evidence = guard().assess_accessibility(
            AgentIdentity::Codex,
            AccessibilityAction::Batch { actions: &mixed },
        );
        assert_eq!(mixed_evidence.decision, GuardDecision::Deny);
        assert_eq!(mixed_evidence.risk_tier, RiskTier::CriticalEffect);
        assert_eq!(
            mixed_evidence.batch_max_risk_tier,
            Some(RiskTier::CriticalEffect)
        );

        for invalid in [
            &[][..],
            &vec![
                BatchAction::GlobalAction {
                    action: GlobalAction::Home,
                };
                MAX_BATCH_ACTIONS + 1
            ][..],
        ] {
            let evidence = guard().assess_accessibility(
                AgentIdentity::Codex,
                AccessibilityAction::Batch { actions: invalid },
            );
            assert_eq!(
                evidence.reason_code,
                ReasonCode::MalformedTypedActionRejected
            );
        }
    }

    #[test]
    fn open_uri_is_external_transfer_and_confused_shapes_are_hard_denied() {
        for agent in [AgentIdentity::Codex] {
            let safe_shape = guard().assess_system(
                agent,
                SystemAction::OpenUri {
                    uri: "https://example.com/",
                    user: 0,
                },
            );
            assert_eq!(safe_shape.decision, GuardDecision::Deny);
            assert_eq!(safe_shape.risk_tier, RiskTier::CriticalEffect);
            assert_eq!(
                safe_shape.reason_code,
                ReasonCode::TrustedLeaseIssuerUnavailable
            );
        }

        for uri in [
            "file:///data/private",
            "intent://example.com/#Intent;scheme=https;end",
            "javascript:alert(1)",
            "https://user:pass@example.com/",
            "https://@example.com/",
            "https://example.com/?secret=value",
            "https://example.com/#secret",
            "https://example.com/private-data",
            "https://example.com/%0asecret",
            "https://example.com/%250asecret",
            "https://example.com/%2fsecret",
            "https://example.com\\@attacker.invalid/",
            "https://exa\u{00a0}mple.com/",
            "https://xn--bcher-kva.example/",
            "https://example.com:8443/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://localhost/",
            "content://authority/path?token=secret",
            "geo:0,0?q=secret",
        ] {
            let evidence =
                guard().assess_system(AgentIdentity::Codex, SystemAction::OpenUri { uri, user: 0 });
            assert_eq!(evidence.decision, GuardDecision::Deny, "{uri}");
            assert_eq!(evidence.reason_code, ReasonCode::UnsafeUriRejected, "{uri}");
            assert_eq!(evidence.required_authority, RequiredAuthority::None);
        }
    }

    #[test]
    fn strict_uri_shape_handles_content_geo_unicode_and_encoding() {
        assert!(uri_has_safe_external_shape("https://example.com/"));
        assert!(uri_has_safe_external_shape(
            "content://com.example.provider/item/1"
        ));
        assert!(uri_has_safe_external_shape("geo:45.0,-73.0"));
        assert!(!uri_has_safe_external_shape("geo:91,0"));
        assert!(!uri_has_safe_external_shape("geo:0,181"));
        assert!(!uri_has_safe_external_shape("https://例子.example/"));
        assert!(!uri_has_safe_external_shape("https://example.com/%GG"));
        assert!(!uri_has_safe_external_shape(
            "https://example.com/%40secret"
        ));
    }

    #[test]
    fn evidence_is_closed_deterministic_and_does_not_expose_inputs() {
        let first = guard().assess_accessibility(
            AgentIdentity::Codex,
            AccessibilityAction::SetText {
                node_id: "node-1",
                text: "RAW-CREDENTIAL",
            },
        );
        let second = guard().assess_accessibility(
            AgentIdentity::Codex,
            AccessibilityAction::SetText {
                node_id: "node-1",
                text: "RAW-CREDENTIAL",
            },
        );
        assert_eq!(first, second);
        let encoded = serde_json::to_string(&first).unwrap();
        assert!(!encoded.contains("RAW-CREDENTIAL"));
        assert!(!encoded.contains("node-1"));
        assert_eq!(
            first.permission_model_sha256,
            agent_direct_permission_model::PERMISSION_MODEL_SHA256
        );
        assert!(encoded.contains(agent_direct_permission_model::PERMISSION_MODEL_SHA256));
        assert_eq!(first.action_binding_sha256.len(), 64);
        let with_unknown = encoded.replace(
            &format!("\"schema\":\"{EVIDENCE_SCHEMA}\""),
            &format!("\"schema\":\"{EVIDENCE_SCHEMA}\",\"override\":true"),
        );
        assert!(serde_json::from_str::<GuardEvidence>(&with_unknown).is_err());
    }

    #[test]
    fn test_only_lease_covers_missing_expiry_binding_and_reboot() {
        let unavailable = guard().assess_accessibility(AgentIdentity::Codex, sensitive_click());
        let missing = evaluate(
            AgentIdentity::Codex,
            classify_accessibility(sensitive_click()),
            LeaseInput::Missing,
        );
        assert_eq!(unavailable.lease_state, LeaseState::IssuerUnavailable);
        assert_eq!(missing.lease_state, LeaseState::Missing);

        let mut claims = candidate_for(
            AgentIdentity::Codex,
            &unavailable,
            RiskTier::SensitiveEffect,
        );
        let valid = assess_click_with_lease(AgentIdentity::Codex, &claims, 1_500, BOOT);
        assert!(valid.allowed());
        assert_eq!(valid.lease_state, LeaseState::Valid);
        assert_eq!(
            assess_click_with_lease(AgentIdentity::Codex, &claims, 999, BOOT).lease_state,
            LeaseState::NotYetValid
        );
        assert_eq!(
            assess_click_with_lease(AgentIdentity::Codex, &claims, 2_001, BOOT).lease_state,
            LeaseState::Expired
        );
        assert_eq!(
            assess_click_with_lease(AgentIdentity::Codex, &claims, 1_500, "new-boot").lease_state,
            LeaseState::Rebooted
        );

        claims.tool = ToolIdentity::SystemApi;
        assert_eq!(
            assess_click_with_lease(AgentIdentity::Codex, &claims, 1_500, BOOT).lease_state,
            LeaseState::ToolMismatch
        );
        claims.tool = ToolIdentity::Accessibility;
        claims.action_binding_sha256 = "0".repeat(64);
        assert_eq!(
            assess_click_with_lease(AgentIdentity::Codex, &claims, 1_500, BOOT).lease_state,
            LeaseState::ActionMismatch
        );
    }

    #[test]
    fn test_only_lease_rejects_policy_tier_and_lifetime_mismatch() {
        let action = AccessibilityAction::GlobalAction {
            action: GlobalAction::TakeScreenshot,
        };
        let denied = guard().assess_accessibility(AgentIdentity::Codex, action);
        let mut claims = candidate_for(AgentIdentity::Codex, &denied, RiskTier::SensitiveEffect);
        let assess = |claims: &TestLeaseClaims| {
            evaluate(
                AgentIdentity::Codex,
                classify_accessibility(action),
                LeaseInput::Candidate {
                    now_monotonic_ms: 1_500,
                    boot_generation: BOOT.to_string(),
                    claims: claims.clone(),
                },
            )
        };
        assert_eq!(assess(&claims).lease_state, LeaseState::InsufficientTier);
        claims.max_risk_tier = RiskTier::CriticalEffect;
        claims.policy_version = "future-policy".to_string();
        assert_eq!(assess(&claims).lease_state, LeaseState::PolicyMismatch);
        claims.policy_version = POLICY_VERSION.to_string();
        claims.expires_monotonic_ms = claims.not_before_monotonic_ms + MAX_LEASE_LIFETIME_MS + 1;
        assert_eq!(assess(&claims).lease_state, LeaseState::LifetimeExceeded);
    }

    #[test]
    fn product_configuration_is_closed() {
        let source = include_str!("risk_guard.rs");
        let manifest = include_str!("../Cargo.toml");
        for forbidden in [
            ["std::env", "::var"].concat(),
            ["risk", "_override"].concat(),
            ["policy", "_path"].concat(),
            ["model", "_lease"].concat(),
        ] {
            assert!(!source.contains(&forbidden), "found {forbidden}");
        }
        assert!(!manifest.lines().any(|line| {
            let line = line.trim();
            line.starts_with("risk-") || line.starts_with("risk_")
        }));
    }

    #[test]
    fn p01_prelauncher_consumers_use_stable_principals_not_measured_descriptors() {
        for (name, source) in [
            ("risk_guard", include_str!("risk_guard.rs")),
            ("trusted_context", include_str!("trusted_context.rs")),
            (
                "device_launch_package_conformance",
                include_str!("device_launch_package_conformance.rs"),
            ),
            (
                "device_launch_package_conformance_replay_sync",
                include_str!("device_launch_package_conformance_replay_sync.rs"),
            ),
            (
                "direct_operation",
                include_str!("../../trillionnium-os-types/src/direct_operation.rs"),
            ),
            (
                "runtime_authority_store_session",
                include_str!("direct_operation_runtime_authority_store_session.rs"),
            ),
            (
                "production_entry_hardening",
                include_str!("production_entry_hardening.rs"),
            ),
            (
                "canonical_operation_contract",
                include_str!("canonical_operation_contract.rs"),
            ),
            (
                "root_publication_transport",
                include_str!("root_publication_transport.rs"),
            ),
            (
                "secure_first_use_journal",
                include_str!("secure_first_use_journal.rs"),
            ),
            (
                "operation_replay_sync",
                include_str!("operation_replay_sync.rs"),
            ),
        ] {
            let production = source
                .split_once("\n#[cfg(test)]\nmod tests")
                .map_or(source, |(production, _)| production);
            assert!(
                source.contains("agent_principal_registry"),
                "{name} lacks the stable principal registry"
            );
            for forbidden in [
                "agent_descriptor_registry",
                "agent_descriptor_registry::CODEX",
                "agent_descriptor_registry::from_provider_agent_pair",
                "PermissionPrincipal::from_descriptor",
                "AgentDescriptor",
                "CODEX.provider_id",
                "CODEX.agent_id",
                "CODEX.replay_namespace",
            ] {
                assert!(
                    !production.contains(forbidden),
                    "{name} still consumes measured descriptor identity through {forbidden}"
                );
            }
        }
    }
}
