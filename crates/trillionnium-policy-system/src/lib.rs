use trillionnium_os_types::{
    ApprovalGrant, ApprovalLifetime, ApprovalRequirement, PolicyDecision, PolicyDecisionKind,
    RiskTier, ToolCallInput, ToolManifest, now_unix_ms,
};

#[derive(Debug, Clone, Default)]
pub struct PolicyEngine {
    grants: Vec<ApprovalGrant>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_grant(mut self, grant: ApprovalGrant) -> Self {
        self.grants.push(grant);
        self
    }

    pub fn add_grant(&mut self, grant: ApprovalGrant) {
        self.grants.push(grant);
    }

    pub fn evaluate(&self, manifest: &ToolManifest, call: &ToolCallInput) -> PolicyDecision {
        if let Some(grant) = self.matching_never_allow_grant(manifest) {
            return PolicyDecision::deny(format!(
                "{} approval grant matched this tool call",
                grant_lifetime_label(&grant.lifetime)
            ));
        }

        if let Some(grant) = self.matching_grant(manifest, call) {
            return PolicyDecision::allow(format!(
                "{} approval grant matched this tool call",
                grant_lifetime_label(&grant.lifetime)
            ));
        }

        match manifest.risk {
            RiskTier::Low => PolicyDecision::allow("low-risk tool allowed by baseline policy"),
            RiskTier::Medium => {
                PolicyDecision::ask("medium-risk tool requires user approval before execution")
            }
            RiskTier::High => PolicyDecision::deny(
                "high-risk tool denied until an explicit narrower policy rule is installed",
            ),
            RiskTier::Critical => PolicyDecision::deny(
                "critical tool denied by default and must be confirmed per call",
            ),
        }
    }

    pub fn grants(&self) -> &[ApprovalGrant] {
        &self.grants
    }

    fn matching_grant(
        &self,
        manifest: &ToolManifest,
        call: &ToolCallInput,
    ) -> Option<&ApprovalGrant> {
        let now = now_unix_ms();
        let manifest_sha256 = serde_json::to_value(manifest)
            .ok()
            .map(|value| trillionnium_os_types::sha256_json(&value));
        let agent_subject_sha256 = call
            .agent_execution_binding
            .as_ref()
            .map(|binding| binding.approval_subject_sha256());
        self.grants.iter().find(|grant| {
            grant.tool_name == manifest.name
                && grant.tool_manifest_sha256 == manifest_sha256
                && grant.agent_subject_sha256 == agent_subject_sha256
                && !grant.is_expired_at(now)
                && match grant.lifetime {
                    ApprovalLifetime::OneCall => {
                        grant.tool_call_id.as_ref() == Some(&call.tool_call_id)
                    }
                    ApprovalLifetime::CurrentTask => grant.task_id.as_ref() == Some(&call.task_id),
                    ApprovalLifetime::CurrentSession
                    | ApprovalLifetime::UntilReboot
                    | ApprovalLifetime::Persistent => false,
                    ApprovalLifetime::NeverAllow => false,
                }
        })
    }

    fn matching_never_allow_grant(&self, manifest: &ToolManifest) -> Option<&ApprovalGrant> {
        let now = now_unix_ms();
        self.grants.iter().find(|grant| {
            grant.tool_name == manifest.name
                && grant.lifetime == ApprovalLifetime::NeverAllow
                && !grant.is_expired_at(now)
        })
    }
}

fn grant_lifetime_label(lifetime: &ApprovalLifetime) -> &'static str {
    match lifetime {
        ApprovalLifetime::OneCall => "one-call",
        ApprovalLifetime::CurrentTask => "current-task",
        ApprovalLifetime::CurrentSession => "current-session",
        ApprovalLifetime::UntilReboot => "until-reboot",
        ApprovalLifetime::Persistent => "persistent",
        ApprovalLifetime::NeverAllow => "never-allow",
    }
}

/// v0.4 target-spec action risk labels.
///
/// These are a compatibility crosswalk for the downloaded v0.4 design document,
/// not a replacement for the current `PolicyEngine` decision path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V04RiskLevel {
    L0ReadOnly,
    L1LowRiskOrganize,
    L2ExternalOutput,
    L3HighRisk,
    L4ForbiddenAutomation,
}

/// v0.4 target-spec data classification labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum V04DataClass {
    D0Public,
    D1PersonalLow,
    D2PersonalMedium,
    D3Sensitive,
    D4HighlySensitive,
}

/// v0.4 target-spec Android automation labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V04AndroidAutomationLevel {
    A0Launch,
    A1ContentHandoff,
    A2NotificationBridge,
    A3UiAutomation,
}

/// v0.4 target-spec policy outcomes.
///
/// Current dogfood policy can express only allow / ask / deny, so this enum is
/// intentionally crossed into the stricter current `RiskTier` and
/// `PolicyDecisionKind` below instead of widening runtime behavior implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V04PolicyDecision {
    Allow,
    RequireLightConfirm,
    RequireExplicitConfirm,
    RequireStrongConfirm,
    RequirePolicyRecheck,
    RequireClarification,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V04PolicyCase {
    pub risk: V04RiskLevel,
    pub max_data_class: V04DataClass,
    pub android_automation: Option<V04AndroidAutomationLevel>,
    pub external_effect: bool,
    pub reversible: bool,
    pub cloud_enhancement: bool,
    pub untrusted_content: bool,
    pub privacy_mode: bool,
    pub low_power_mode: bool,
}

impl V04PolicyCase {
    pub const fn new(risk: V04RiskLevel, max_data_class: V04DataClass) -> Self {
        Self {
            risk,
            max_data_class,
            android_automation: None,
            external_effect: false,
            reversible: true,
            cloud_enhancement: false,
            untrusted_content: false,
            privacy_mode: false,
            low_power_mode: false,
        }
    }

    pub const fn with_android_automation(
        mut self,
        android_automation: V04AndroidAutomationLevel,
    ) -> Self {
        self.android_automation = Some(android_automation);
        self
    }

    pub const fn with_external_effect(mut self) -> Self {
        self.external_effect = true;
        self
    }

    pub const fn with_irreversible_effect(mut self) -> Self {
        self.external_effect = true;
        self.reversible = false;
        self
    }

    pub const fn with_cloud_enhancement(mut self) -> Self {
        self.cloud_enhancement = true;
        self
    }

    pub const fn with_untrusted_content(mut self) -> Self {
        self.untrusted_content = true;
        self
    }

    pub const fn in_privacy_mode(mut self) -> Self {
        self.privacy_mode = true;
        self
    }

    pub const fn in_low_power_mode(mut self) -> Self {
        self.low_power_mode = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V04PolicyCrosswalk {
    pub v04_decision: V04PolicyDecision,
    pub current_risk_floor: RiskTier,
    pub current_decision_kind: PolicyDecisionKind,
    pub current_requirement: ApprovalRequirement,
    pub note: &'static str,
}

/// Crosswalk a v0.4 target-spec case into the current dogfood policy vocabulary.
///
/// This function is deliberately read-only and is not called by `PolicyEngine`.
/// It exists so the v0.4 policy matrix can be regression-tested before the
/// runtime grows first-class L0-L4 / D0-D4 / A0-A3 policy types.
pub fn crosswalk_v04_policy_case(case: V04PolicyCase) -> V04PolicyCrosswalk {
    let (v04_decision, note) = if case.android_automation
        == Some(V04AndroidAutomationLevel::A3UiAutomation)
    {
        (
            V04PolicyDecision::Deny,
            "Android A3 UI automation is denied in MVP and ordinary builds",
        )
    } else if case.risk == V04RiskLevel::L4ForbiddenAutomation {
        (
            V04PolicyDecision::Deny,
            "L4 forbidden automation cannot be executed directly",
        )
    } else if case.max_data_class == V04DataClass::D4HighlySensitive
        && (case.external_effect || case.cloud_enhancement)
    {
        (
            V04PolicyDecision::Deny,
            "D4 data cannot be automatically externalized or sent to cloud enhancement",
        )
    } else if case.privacy_mode
        && case.android_automation == Some(V04AndroidAutomationLevel::A2NotificationBridge)
    {
        (
            V04PolicyDecision::Deny,
            "privacy mode blocks Android notification body processing",
        )
    } else if case.risk == V04RiskLevel::L3HighRisk || !case.reversible {
        (
            V04PolicyDecision::RequireStrongConfirm,
            "L3 or irreversible work needs strong confirmation; current dogfood maps this to deny-by-default",
        )
    } else if case.untrusted_content && case.external_effect {
        (
            V04PolicyDecision::RequirePolicyRecheck,
            "untrusted content cannot directly trigger external effects",
        )
    } else if case.risk == V04RiskLevel::L2ExternalOutput || case.external_effect {
        (
            V04PolicyDecision::RequireExplicitConfirm,
            "external output requires explicit confirmation",
        )
    } else if case.max_data_class == V04DataClass::D3Sensitive && case.cloud_enhancement {
        (
            V04PolicyDecision::RequireExplicitConfirm,
            "D3 cloud enhancement requires explicit data-scope confirmation",
        )
    } else if case.low_power_mode
        && case.android_automation == Some(V04AndroidAutomationLevel::A0Launch)
    {
        (
            V04PolicyDecision::RequireLightConfirm,
            "low-power mode should not cold-start Android compatibility without user intent",
        )
    } else if case.risk == V04RiskLevel::L1LowRiskOrganize {
        if case.reversible {
            (
                V04PolicyDecision::RequireLightConfirm,
                "L1 maps conservatively to ask until light-confirm semantics exist",
            )
        } else {
            (
                V04PolicyDecision::RequireStrongConfirm,
                "irreversible L1-like work is promoted to strong confirmation",
            )
        }
    } else if case.untrusted_content {
        (
            V04PolicyDecision::RequirePolicyRecheck,
            "untrusted content requires a policy recheck boundary before use",
        )
    } else {
        (
            V04PolicyDecision::Allow,
            "L0 low-sensitivity read-only work maps to low-risk allow",
        )
    };

    let current_risk_floor = current_risk_floor_for_v04_decision(v04_decision);
    let current_decision_kind = current_decision_for_risk(&current_risk_floor);
    let current_requirement = approval_requirement_for_decision(&current_decision_kind);

    V04PolicyCrosswalk {
        v04_decision,
        current_risk_floor,
        current_decision_kind,
        current_requirement,
        note,
    }
}

fn current_risk_floor_for_v04_decision(decision: V04PolicyDecision) -> RiskTier {
    match decision {
        V04PolicyDecision::Allow => RiskTier::Low,
        V04PolicyDecision::RequireLightConfirm
        | V04PolicyDecision::RequireExplicitConfirm
        | V04PolicyDecision::RequirePolicyRecheck
        | V04PolicyDecision::RequireClarification => RiskTier::Medium,
        V04PolicyDecision::RequireStrongConfirm => RiskTier::High,
        V04PolicyDecision::Deny => RiskTier::Critical,
    }
}

fn current_decision_for_risk(risk: &RiskTier) -> PolicyDecisionKind {
    match risk {
        RiskTier::Low => PolicyDecisionKind::Allow,
        RiskTier::Medium => PolicyDecisionKind::Ask,
        RiskTier::High | RiskTier::Critical => PolicyDecisionKind::Deny,
    }
}

fn approval_requirement_for_decision(decision: &PolicyDecisionKind) -> ApprovalRequirement {
    match decision {
        PolicyDecisionKind::Allow => ApprovalRequirement::None,
        PolicyDecisionKind::Ask => ApprovalRequirement::Ask,
        PolicyDecisionKind::Deny => ApprovalRequirement::Deny,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use trillionnium_os_types::{PolicyDecisionKind, TaskId, ToolCallId, ToolManifest};

    use super::*;

    fn call_for(manifest: &ToolManifest) -> ToolCallInput {
        ToolCallInput {
            task_id: TaskId::new(),
            tool_call_id: ToolCallId::new(),
            tool_name: manifest.name.clone(),
            arguments: json!({}),
            agent_execution_binding: None,
        }
    }

    fn manifest_sha256(manifest: &ToolManifest) -> String {
        trillionnium_os_types::sha256_json(&serde_json::to_value(manifest).unwrap())
    }

    #[test]
    fn low_risk_system_status_is_allowed() {
        let manifest = ToolManifest::system_status();
        let call = call_for(&manifest);

        let decision = PolicyEngine::new().evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn medium_risk_requires_approval_without_grant() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);

        let decision = PolicyEngine::new().evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn exact_one_call_grant_allows_medium_risk_call() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);
        let grant = ApprovalGrant::one_call(manifest.name.clone(), call.tool_call_id.clone())
            .with_execution_scope(manifest_sha256(&manifest), None, "e".repeat(64));

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
    }

    #[test]
    fn current_task_grant_allows_same_tool_in_same_task() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);
        let grant = ApprovalGrant::current_task(manifest.name.clone(), call.task_id.clone())
            .with_execution_scope(manifest_sha256(&manifest), None, "e".repeat(64));

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Allow);
        assert!(decision.reason.contains("current-task"));
    }

    #[test]
    fn positive_grant_does_not_cross_manifest_or_agent_subject_boundaries() {
        let mut approved_manifest = ToolManifest::system_status();
        approved_manifest.name = "files.read".into();
        approved_manifest.risk = RiskTier::Medium;
        let call = call_for(&approved_manifest);
        let grant =
            ApprovalGrant::current_task(approved_manifest.name.clone(), call.task_id.clone())
                .with_execution_scope(manifest_sha256(&approved_manifest), None, "e".repeat(64));

        let mut changed_manifest = approved_manifest.clone();
        changed_manifest.description = "changed after approval".to_string();
        assert_eq!(
            PolicyEngine::new()
                .with_grant(grant.clone())
                .evaluate(&changed_manifest, &call)
                .kind,
            PolicyDecisionKind::Ask
        );

        let mut agent_scoped = grant;
        agent_scoped.agent_subject_sha256 = Some("a".repeat(64));
        assert_eq!(
            PolicyEngine::new()
                .with_grant(agent_scoped)
                .evaluate(&approved_manifest, &call)
                .kind,
            PolicyDecisionKind::Ask
        );
    }

    #[test]
    fn current_task_grant_does_not_cross_task_boundaries() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);
        let grant = ApprovalGrant::current_task(manifest.name.clone(), TaskId::new());

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn subjectless_current_session_grant_fails_closed() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);
        let grant = ApprovalGrant::current_session(manifest.name.clone());

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn current_session_grant_does_not_cross_tool_boundaries() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.write".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);
        let grant = ApprovalGrant::current_session("files.read");

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn subjectless_until_reboot_grant_fails_closed() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);
        let grant = ApprovalGrant::until_reboot(manifest.name.clone(), "boot-test");

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn subjectless_persistent_grant_fails_closed() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);
        let grant = ApprovalGrant::persistent(manifest.name.clone());

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn never_allow_grant_denies_even_low_risk_tool() {
        let manifest = ToolManifest::system_status();
        let call = call_for(&manifest);
        let grant = ApprovalGrant::never_allow(manifest.name.clone());

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reason.contains("never-allow"));
    }

    #[test]
    fn never_allow_grant_overrides_positive_grant() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);

        let decision = PolicyEngine::new()
            .with_grant(ApprovalGrant::persistent(manifest.name.clone()))
            .with_grant(ApprovalGrant::never_allow(manifest.name.clone()))
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
        assert!(decision.reason.contains("never-allow"));
    }

    #[test]
    fn expired_grant_does_not_allow_tool_call() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "files.read".into();
        manifest.risk = RiskTier::Medium;
        let call = call_for(&manifest);
        let grant = ApprovalGrant::current_task(manifest.name.clone(), call.task_id.clone())
            .with_expires_at(1);

        let decision = PolicyEngine::new()
            .with_grant(grant)
            .evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn critical_tool_stays_denied_without_exact_grant() {
        let mut manifest = ToolManifest::system_status();
        manifest.name = "disk.partition".into();
        manifest.risk = RiskTier::Critical;
        let call = call_for(&manifest);

        let decision = PolicyEngine::new().evaluate(&manifest, &call);

        assert_eq!(decision.kind, PolicyDecisionKind::Deny);
    }

    #[test]
    fn v04_l0_low_sensitivity_read_only_maps_to_current_allow() {
        let crosswalk = crosswalk_v04_policy_case(V04PolicyCase::new(
            V04RiskLevel::L0ReadOnly,
            V04DataClass::D1PersonalLow,
        ));

        assert_eq!(crosswalk.v04_decision, V04PolicyDecision::Allow);
        assert_eq!(crosswalk.current_risk_floor, RiskTier::Low);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Allow);
        assert_eq!(crosswalk.current_requirement, ApprovalRequirement::None);
    }

    #[test]
    fn v04_l1_reversible_work_maps_conservatively_to_current_ask() {
        let crosswalk = crosswalk_v04_policy_case(V04PolicyCase::new(
            V04RiskLevel::L1LowRiskOrganize,
            V04DataClass::D1PersonalLow,
        ));

        assert_eq!(
            crosswalk.v04_decision,
            V04PolicyDecision::RequireLightConfirm
        );
        assert_eq!(crosswalk.current_risk_floor, RiskTier::Medium);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn v04_l2_external_output_maps_to_current_ask() {
        let crosswalk = crosswalk_v04_policy_case(
            V04PolicyCase::new(
                V04RiskLevel::L2ExternalOutput,
                V04DataClass::D2PersonalMedium,
            )
            .with_external_effect(),
        );

        assert_eq!(
            crosswalk.v04_decision,
            V04PolicyDecision::RequireExplicitConfirm
        );
        assert_eq!(crosswalk.current_risk_floor, RiskTier::Medium);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn v04_l3_high_risk_maps_to_current_deny_until_strong_confirm_exists() {
        let crosswalk = crosswalk_v04_policy_case(
            V04PolicyCase::new(V04RiskLevel::L3HighRisk, V04DataClass::D3Sensitive)
                .with_irreversible_effect(),
        );

        assert_eq!(
            crosswalk.v04_decision,
            V04PolicyDecision::RequireStrongConfirm
        );
        assert_eq!(crosswalk.current_risk_floor, RiskTier::High);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Deny);
    }

    #[test]
    fn v04_l4_forbidden_automation_maps_to_current_deny() {
        let crosswalk = crosswalk_v04_policy_case(
            V04PolicyCase::new(
                V04RiskLevel::L4ForbiddenAutomation,
                V04DataClass::D2PersonalMedium,
            )
            .with_external_effect(),
        );

        assert_eq!(crosswalk.v04_decision, V04PolicyDecision::Deny);
        assert_eq!(crosswalk.current_risk_floor, RiskTier::Critical);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Deny);
    }

    #[test]
    fn v04_android_a3_overrides_lower_risk_as_current_deny() {
        let crosswalk = crosswalk_v04_policy_case(
            V04PolicyCase::new(V04RiskLevel::L0ReadOnly, V04DataClass::D1PersonalLow)
                .with_android_automation(V04AndroidAutomationLevel::A3UiAutomation),
        );

        assert_eq!(crosswalk.v04_decision, V04PolicyDecision::Deny);
        assert_eq!(crosswalk.current_risk_floor, RiskTier::Critical);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Deny);
        assert!(crosswalk.note.contains("Android A3"));
    }

    #[test]
    fn v04_d4_external_or_cloud_use_maps_to_current_deny() {
        let external = crosswalk_v04_policy_case(
            V04PolicyCase::new(
                V04RiskLevel::L2ExternalOutput,
                V04DataClass::D4HighlySensitive,
            )
            .with_external_effect(),
        );
        let cloud = crosswalk_v04_policy_case(
            V04PolicyCase::new(V04RiskLevel::L0ReadOnly, V04DataClass::D4HighlySensitive)
                .with_cloud_enhancement(),
        );

        assert_eq!(external.v04_decision, V04PolicyDecision::Deny);
        assert_eq!(external.current_decision_kind, PolicyDecisionKind::Deny);
        assert_eq!(cloud.v04_decision, V04PolicyDecision::Deny);
        assert_eq!(cloud.current_decision_kind, PolicyDecisionKind::Deny);
    }

    #[test]
    fn v04_untrusted_content_external_effect_maps_to_current_ask_recheck() {
        let crosswalk = crosswalk_v04_policy_case(
            V04PolicyCase::new(
                V04RiskLevel::L1LowRiskOrganize,
                V04DataClass::D2PersonalMedium,
            )
            .with_untrusted_content()
            .with_external_effect(),
        );

        assert_eq!(
            crosswalk.v04_decision,
            V04PolicyDecision::RequirePolicyRecheck
        );
        assert_eq!(crosswalk.current_risk_floor, RiskTier::Medium);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Ask);
    }

    #[test]
    fn v04_privacy_mode_denies_android_notification_body_processing() {
        let crosswalk = crosswalk_v04_policy_case(
            V04PolicyCase::new(V04RiskLevel::L0ReadOnly, V04DataClass::D2PersonalMedium)
                .with_android_automation(V04AndroidAutomationLevel::A2NotificationBridge)
                .in_privacy_mode(),
        );

        assert_eq!(crosswalk.v04_decision, V04PolicyDecision::Deny);
        assert_eq!(crosswalk.current_risk_floor, RiskTier::Critical);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Deny);
    }

    #[test]
    fn v04_low_power_android_launch_maps_to_current_ask() {
        let crosswalk = crosswalk_v04_policy_case(
            V04PolicyCase::new(V04RiskLevel::L0ReadOnly, V04DataClass::D1PersonalLow)
                .with_android_automation(V04AndroidAutomationLevel::A0Launch)
                .in_low_power_mode(),
        );

        assert_eq!(
            crosswalk.v04_decision,
            V04PolicyDecision::RequireLightConfirm
        );
        assert_eq!(crosswalk.current_risk_floor, RiskTier::Medium);
        assert_eq!(crosswalk.current_decision_kind, PolicyDecisionKind::Ask);
    }
}
