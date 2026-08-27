//! Closed, non-authorizing v1 permission model for the implemented Codex
//! Direct System API/Accessibility surfaces and typed shell/ADB candidates.
//!
//! The accepted v2 product boundary supersedes this model for direct shell and
//! ADB: both are product capabilities, but remain unimplemented holds here.
//! This module freezes only the currently implemented Codex principal ×
//! surface × action decision table.
//! A policy allow is only a prerequisite for the
//! separately owned product effect-custody chain; it cannot mint an effect
//! capability, select an adapter, or bypass durable replay/outer-ACK gates.

use crate::agent_principal_registry::{self, AgentStablePrincipal};
use crate::{AgentHealth, AgentRegistration};

pub const PERMISSION_MODEL_SCHEMA: &str = "org.trillionnium.agent-direct-permission-model.v1";
pub const PERMISSION_MODEL_SHA256: &str =
    "9399b1375d267e2672d3de28519d9f001e5c50ff83d056dd20fe08383613613d";
pub const PERMISSION_MODEL_STATUS: &str = "superseded_typed_candidate_model_hold";
pub const PERMISSION_MODEL_SUPERSEDED_BY: &str =
    "org.trillionnium.agent-exec-adb-windows-product-boundary.v2";
pub const DIRECT_SHELL_IMPLEMENTATION_STATUS: &str =
    "not_modeled_here_superseded_by_product_boundary_v2";
pub const DIRECT_ADB_IMPLEMENTATION_STATUS: &str = "planned_not_implemented_hold";
pub const DIRECT_AGENT_TOOL_NAMES: &[&str] =
    &["trillionnium_system_api", "trillionnium_accessibility"];

#[must_use]
pub fn direct_agent_tool_name_is_allowed(name: &str) -> bool {
    DIRECT_AGENT_TOOL_NAMES.contains(&name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionSurface {
    DirectSystemApi,
    DirectAccessibility,
    TypedExec,
    TypedAdb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductVariant {
    User,
    Userdebug,
    Eng,
    Recovery,
}

impl ProductVariant {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Userdebug => "userdebug",
            Self::Eng => "eng",
            Self::Recovery => "recovery",
        }
    }
}

impl PermissionSurface {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DirectSystemApi => "direct_system_api",
            Self::DirectAccessibility => "direct_accessibility",
            Self::TypedExec => "typed_exec",
            Self::TypedAdb => "typed_adb",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionAction {
    LaunchPackage,
    OpenUri,
    SnapshotMetadataOnly,
    SnapshotFullText,
    Scroll,
    GlobalBack,
    GlobalHome,
    Click,
    SetText,
    Gesture,
    GlobalRecents,
    GlobalNotifications,
    GlobalQuickSettings,
    GlobalPowerDialog,
    GlobalLockScreen,
    GlobalTakeScreenshot,
    Batch,
    ExecLaunchSettingsV1,
    AdbLaunchSettingsUserV1,
    AdbLaunchSettingsEngineeringRecoveryV1,
}

impl PermissionAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LaunchPackage => "launch_package",
            Self::OpenUri => "open_uri",
            Self::SnapshotMetadataOnly => "snapshot_metadata_only",
            Self::SnapshotFullText => "snapshot_full_text",
            Self::Scroll => "scroll",
            Self::GlobalBack => "global_back",
            Self::GlobalHome => "global_home",
            Self::Click => "click",
            Self::SetText => "set_text",
            Self::Gesture => "gesture",
            Self::GlobalRecents => "global_recents",
            Self::GlobalNotifications => "global_notifications",
            Self::GlobalQuickSettings => "global_quick_settings",
            Self::GlobalPowerDialog => "global_power_dialog",
            Self::GlobalLockScreen => "global_lock_screen",
            Self::GlobalTakeScreenshot => "global_take_screenshot",
            Self::Batch => "batch",
            Self::ExecLaunchSettingsV1 => "exec.launch_package.settings.v1",
            Self::AdbLaunchSettingsUserV1 => "adb.launch_package.settings.user.v1",
            Self::AdbLaunchSettingsEngineeringRecoveryV1 => {
                "adb.launch_package.settings.engineering-recovery.v1"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionDisposition {
    /// Preliminary low-risk policy allow. Product effect custody is still
    /// mandatory and this value is never an effect capability.
    PolicyAllowRequiresEffectCustody,
    /// The action must fail closed until an authenticated, single-use OS
    /// session lease is available and consumed by the product custody chain.
    OsSessionLeaseRequired,
    /// A batch is admissible only after each canonical child independently
    /// resolves to a current allow and the batch bounds pass.
    ConditionalEveryBatchMember,
    /// The exact typed operation may be materialized for source validation,
    /// but the current model deliberately provides no product authority.
    SourceCandidateHold,
    /// The surface/action pairing is not part of the closed permission set.
    Deny,
}

impl PermissionDisposition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAllowRequiresEffectCustody => "policy_allow_requires_effect_custody",
            Self::OsSessionLeaseRequired => "os_session_lease_required",
            Self::ConditionalEveryBatchMember => "conditional_every_batch_member",
            Self::SourceCandidateHold => "source_candidate_hold",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionModelError {
    PermissionModelMeasurementMismatch,
    PrincipalIdentityMismatch,
    PrincipalNotReady,
    ProductEffectAuthorityUnavailable,
}

/// Exact built-in stable principal resolved from the generated OS principal
/// registry. Executable/launcher identity is deliberately not retained here:
/// the daemon/broker custody chain must authenticate that independent dynamic
/// binding before any effect can be admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionPrincipal {
    stable_principal: &'static AgentStablePrincipal,
}

impl PermissionPrincipal {
    pub fn from_registration(
        registration: &AgentRegistration,
    ) -> Result<Self, PermissionModelError> {
        if !registration.enabled || registration.health != AgentHealth::Ready {
            return Err(PermissionModelError::PrincipalNotReady);
        }
        let stable_principal = agent_principal_registry::from_registration_fields(registration)
            .ok_or(PermissionModelError::PrincipalIdentityMismatch)?;
        Ok(Self { stable_principal })
    }

    pub fn from_stable_principal(
        stable_principal: &'static AgentStablePrincipal,
    ) -> Result<Self, PermissionModelError> {
        let canonical = agent_principal_registry::from_provider_agent_pair(
            stable_principal.provider_id,
            stable_principal.agent_id,
        )
        .filter(|canonical| **canonical == *stable_principal)
        .ok_or(PermissionModelError::PrincipalIdentityMismatch)?;
        Ok(Self {
            stable_principal: canonical,
        })
    }

    #[must_use]
    pub const fn stable_principal(self) -> &'static AgentStablePrincipal {
        self.stable_principal
    }
}

#[must_use]
pub fn embedded_permission_model_measurement_is_exact() -> bool {
    crate::sha256_bytes(include_bytes!(
        "../contracts/agent-direct-permission-model-v1.json"
    )) == PERMISSION_MODEL_SHA256
}

/// Resolve one preliminary policy disposition for the exact built-in Codex
/// stable principal. Unknown surface/action pairings return an explicit deny.
pub fn permission_disposition(
    principal: PermissionPrincipal,
    surface: PermissionSurface,
    action: PermissionAction,
) -> Result<PermissionDisposition, PermissionModelError> {
    if !embedded_permission_model_measurement_is_exact() {
        return Err(PermissionModelError::PermissionModelMeasurementMismatch);
    }
    if principal.stable_principal != &agent_principal_registry::CODEX_STABLE_PRINCIPAL {
        return Err(PermissionModelError::PrincipalIdentityMismatch);
    }
    Ok(match (surface, action) {
        (PermissionSurface::DirectSystemApi, PermissionAction::LaunchPackage)
        | (
            PermissionSurface::DirectAccessibility,
            PermissionAction::SnapshotMetadataOnly
            | PermissionAction::Scroll
            | PermissionAction::GlobalBack
            | PermissionAction::GlobalHome,
        ) => PermissionDisposition::PolicyAllowRequiresEffectCustody,
        (PermissionSurface::DirectSystemApi, PermissionAction::OpenUri)
        | (
            PermissionSurface::DirectAccessibility,
            PermissionAction::SnapshotFullText
            | PermissionAction::Click
            | PermissionAction::SetText
            | PermissionAction::Gesture
            | PermissionAction::GlobalRecents
            | PermissionAction::GlobalNotifications
            | PermissionAction::GlobalQuickSettings
            | PermissionAction::GlobalPowerDialog
            | PermissionAction::GlobalLockScreen
            | PermissionAction::GlobalTakeScreenshot,
        ) => PermissionDisposition::OsSessionLeaseRequired,
        (PermissionSurface::DirectAccessibility, PermissionAction::Batch) => {
            PermissionDisposition::ConditionalEveryBatchMember
        }
        (PermissionSurface::TypedExec, PermissionAction::ExecLaunchSettingsV1)
        | (
            PermissionSurface::TypedAdb,
            PermissionAction::AdbLaunchSettingsUserV1
            | PermissionAction::AdbLaunchSettingsEngineeringRecoveryV1,
        ) => PermissionDisposition::SourceCandidateHold,
        _ => PermissionDisposition::Deny,
    })
}

/// Apply the variant partition from the same permission model. Direct tools
/// are identical across variants, while the user ADB descriptor and the
/// engineering/recovery descriptor are deliberately disjoint.
pub fn variant_permission_disposition(
    principal: PermissionPrincipal,
    variant: ProductVariant,
    surface: PermissionSurface,
    action: PermissionAction,
) -> Result<PermissionDisposition, PermissionModelError> {
    let base = permission_disposition(principal, surface, action)?;
    if surface != PermissionSurface::TypedAdb {
        return Ok(base);
    }
    let variant_matches = matches!(
        (variant, action),
        (
            ProductVariant::User,
            PermissionAction::AdbLaunchSettingsUserV1
        ) | (
            ProductVariant::Userdebug | ProductVariant::Eng | ProductVariant::Recovery,
            PermissionAction::AdbLaunchSettingsEngineeringRecoveryV1
        )
    );
    Ok(if variant_matches {
        base
    } else {
        PermissionDisposition::Deny
    })
}

/// This source freeze cannot be promoted into effect authority. A future
/// product constructor must consume independently verified signed/AVB state
/// and the complete durability chain rather than changing this return value.
pub fn require_current_product_effect_authority(
    _principal: PermissionPrincipal,
) -> Result<(), PermissionModelError> {
    Err(PermissionModelError::ProductEffectAuthorityUnavailable)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::*;
    use crate::{AgentNetworkPolicy, AgentRegistration};

    const ALL_RULES: &[(PermissionSurface, PermissionAction, PermissionDisposition)] = &[
        (
            PermissionSurface::DirectSystemApi,
            PermissionAction::LaunchPackage,
            PermissionDisposition::PolicyAllowRequiresEffectCustody,
        ),
        (
            PermissionSurface::DirectSystemApi,
            PermissionAction::OpenUri,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::SnapshotMetadataOnly,
            PermissionDisposition::PolicyAllowRequiresEffectCustody,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::SnapshotFullText,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::Scroll,
            PermissionDisposition::PolicyAllowRequiresEffectCustody,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::GlobalBack,
            PermissionDisposition::PolicyAllowRequiresEffectCustody,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::GlobalHome,
            PermissionDisposition::PolicyAllowRequiresEffectCustody,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::Click,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::SetText,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::Gesture,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::GlobalRecents,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::GlobalNotifications,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::GlobalQuickSettings,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::GlobalPowerDialog,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::GlobalLockScreen,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::GlobalTakeScreenshot,
            PermissionDisposition::OsSessionLeaseRequired,
        ),
        (
            PermissionSurface::DirectAccessibility,
            PermissionAction::Batch,
            PermissionDisposition::ConditionalEveryBatchMember,
        ),
        (
            PermissionSurface::TypedExec,
            PermissionAction::ExecLaunchSettingsV1,
            PermissionDisposition::SourceCandidateHold,
        ),
        (
            PermissionSurface::TypedAdb,
            PermissionAction::AdbLaunchSettingsUserV1,
            PermissionDisposition::SourceCandidateHold,
        ),
        (
            PermissionSurface::TypedAdb,
            PermissionAction::AdbLaunchSettingsEngineeringRecoveryV1,
            PermissionDisposition::SourceCandidateHold,
        ),
    ];

    fn registration(stable_principal: &AgentStablePrincipal) -> AgentRegistration {
        AgentRegistration {
            api_version: crate::AGENT_API_VERSION.to_string(),
            agent_id: stable_principal.agent_id.to_string(),
            adapter: stable_principal.runtime_adapter.to_string(),
            adapter_version: "permission-model-test".to_string(),
            identity_key_sha256: crate::sha256_bytes(b"independent-permission-test-launcher"),
            peer_uid: stable_principal.uid,
            peer_gid: stable_principal.gid,
            selinux_domain: stable_principal.agent_selinux_domain.to_string(),
            network_policy: AgentNetworkPolicy::Deny,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: 1,
            updated_at_unix_ms: 1,
        }
    }

    #[test]
    fn embedded_contract_hash_bindings_and_hold_are_exact() {
        assert!(embedded_permission_model_measurement_is_exact());
        let contract: Value = serde_json::from_slice(include_bytes!(
            "../contracts/agent-direct-permission-model-v1.json"
        ))
        .expect("permission model JSON");
        assert_eq!(contract["schema"], PERMISSION_MODEL_SCHEMA);
        assert_eq!(contract["status"], PERMISSION_MODEL_STATUS);
        assert_eq!(contract["superseded_by"], PERMISSION_MODEL_SUPERSEDED_BY);
        assert_eq!(contract["effect_authority"], false);
        assert_eq!(contract["current_product_effects_enabled"], false);
        assert_eq!(contract["scope"]["current_product_boundary"], false);
        assert_eq!(
            contract["scope"]["direct_shell_status"],
            DIRECT_SHELL_IMPLEMENTATION_STATUS
        );
        assert_eq!(
            contract["scope"]["direct_adb_status"],
            DIRECT_ADB_IMPLEMENTATION_STATUS
        );
        assert_eq!(
            contract["scope"]["direct_shell_and_adb_effect_authority"],
            false
        );
        for variant in ["user", "userdebug", "eng", "recovery"] {
            assert_eq!(
                contract["variant_tool_sets"][variant]["direct_mcp_tools"],
                serde_json::json!(DIRECT_AGENT_TOOL_NAMES)
            );
            assert_eq!(
                contract["variant_tool_sets"][variant].get("raw_adb_agent_tool"),
                None
            );
        }
        assert!(
            contract["variant_tool_sets"]
                .get("engineering_raw_adb")
                .is_none()
        );
        assert_eq!(
            contract["bindings"]["agent_stable_principal_projection_sha256"],
            agent_principal_registry::STABLE_PRINCIPAL_CANONICAL_SHA256
        );
        assert_eq!(
            contract["bindings"]["direct_agent_host_abi_sha256"],
            crate::direct_agent_host_abi::CONTRACT_SHA256
        );
        assert_eq!(
            contract["bindings"]["typed_operation_catalog_sha256"],
            crate::typed_operation_catalog::CATALOG_SHA256
        );
        assert!(
            contract["promotion_gates"]
                .as_object()
                .expect("promotion gates")
                .values()
                .all(|value| value == false)
        );
    }

    #[test]
    fn contract_rows_equal_the_typed_resolver_for_codex() {
        let contract: Value = serde_json::from_slice(include_bytes!(
            "../contracts/agent-direct-permission-model-v1.json"
        ))
        .expect("permission model JSON");
        let rows = contract["permissions"]
            .as_array()
            .expect("permission rows")
            .iter()
            .map(|row| {
                (
                    row["surface"].as_str().expect("surface").to_string(),
                    row["action"].as_str().expect("action").to_string(),
                    row["disposition"]
                        .as_str()
                        .expect("disposition")
                        .to_string(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), ALL_RULES.len());
        let mut unique = BTreeMap::new();
        for (surface, action, disposition) in &rows {
            assert!(
                unique
                    .insert((surface.clone(), action.clone()), disposition.clone())
                    .is_none(),
                "duplicate permission row"
            );
        }
        for stable_principal in [&agent_principal_registry::CODEX_STABLE_PRINCIPAL] {
            let principal = PermissionPrincipal::from_registration(&registration(stable_principal))
                .expect("exact built-in principal");
            for (surface, action, expected) in ALL_RULES {
                assert_eq!(
                    permission_disposition(principal, *surface, *action),
                    Ok(*expected)
                );
                assert_eq!(
                    unique.get(&(surface.as_str().to_string(), action.as_str().to_string())),
                    Some(&expected.as_str().to_string())
                );
            }
            assert_eq!(
                require_current_product_effect_authority(principal),
                Err(PermissionModelError::ProductEffectAuthorityUnavailable)
            );
        }
    }

    #[test]
    fn unsupported_surface_action_pairs_deny() {
        let principal = PermissionPrincipal::from_stable_principal(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
        )
        .expect("canonical stable principal");
        for (surface, action) in [
            (PermissionSurface::DirectSystemApi, PermissionAction::Click),
            (
                PermissionSurface::DirectAccessibility,
                PermissionAction::LaunchPackage,
            ),
            (
                PermissionSurface::TypedExec,
                PermissionAction::AdbLaunchSettingsUserV1,
            ),
            (
                PermissionSurface::TypedAdb,
                PermissionAction::ExecLaunchSettingsV1,
            ),
        ] {
            assert_eq!(
                permission_disposition(principal, surface, action),
                Ok(PermissionDisposition::Deny)
            );
        }
    }

    #[test]
    fn typed_adb_variant_partition_is_enforced_not_documentary() {
        let principal = PermissionPrincipal::from_stable_principal(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
        )
        .expect("canonical stable principal");
        for variant in [
            ProductVariant::Userdebug,
            ProductVariant::Eng,
            ProductVariant::Recovery,
        ] {
            assert_eq!(
                variant_permission_disposition(
                    principal,
                    variant,
                    PermissionSurface::TypedAdb,
                    PermissionAction::AdbLaunchSettingsUserV1,
                ),
                Ok(PermissionDisposition::Deny)
            );
            assert_eq!(
                variant_permission_disposition(
                    principal,
                    variant,
                    PermissionSurface::TypedAdb,
                    PermissionAction::AdbLaunchSettingsEngineeringRecoveryV1,
                ),
                Ok(PermissionDisposition::SourceCandidateHold)
            );
        }
        assert_eq!(
            variant_permission_disposition(
                principal,
                ProductVariant::User,
                PermissionSurface::TypedAdb,
                PermissionAction::AdbLaunchSettingsUserV1,
            ),
            Ok(PermissionDisposition::SourceCandidateHold)
        );
        assert_eq!(
            variant_permission_disposition(
                principal,
                ProductVariant::User,
                PermissionSurface::TypedAdb,
                PermissionAction::AdbLaunchSettingsEngineeringRecoveryV1,
            ),
            Ok(PermissionDisposition::Deny)
        );
    }

    #[test]
    fn executable_identity_rotation_does_not_change_preliminary_disposition() {
        let baseline = registration(&agent_principal_registry::CODEX_STABLE_PRINCIPAL);
        let baseline_principal =
            PermissionPrincipal::from_registration(&baseline).expect("baseline stable principal");
        let mut rotated = baseline.clone();
        rotated.identity_key_sha256 = crate::sha256_bytes(b"rotated-launcher-executable");
        assert_ne!(rotated.identity_key_sha256, baseline.identity_key_sha256);
        let rotated_principal = PermissionPrincipal::from_registration(&rotated)
            .expect("rotated executable retains stable principal");
        assert_eq!(rotated_principal, baseline_principal);
        assert_eq!(
            permission_disposition(
                rotated_principal,
                PermissionSurface::DirectSystemApi,
                PermissionAction::LaunchPackage,
            ),
            permission_disposition(
                baseline_principal,
                PermissionSurface::DirectSystemApi,
                PermissionAction::LaunchPackage,
            )
        );
    }

    #[test]
    fn stable_principal_or_liveness_drift_cannot_enter_the_profile() {
        let baseline = registration(&agent_principal_registry::CODEX_STABLE_PRINCIPAL);
        let mut drifts = Vec::new();

        let mut agent = baseline.clone();
        agent.agent_id = "agent-unknown-v1".to_string();
        drifts.push(agent);

        let mut adapter = baseline.clone();
        adapter.adapter = "unknown-adapter".to_string();
        drifts.push(adapter);

        let mut uid = baseline.clone();
        uid.peer_uid += 1;
        drifts.push(uid);

        let mut gid = baseline.clone();
        gid.peer_gid += 1;
        drifts.push(gid);

        let mut selinux = baseline.clone();
        selinux.selinux_domain = "u:r:untrusted_app:s0".to_string();
        drifts.push(selinux);

        for drifted in &drifts {
            assert_eq!(
                PermissionPrincipal::from_registration(drifted),
                Err(PermissionModelError::PrincipalIdentityMismatch)
            );
        }

        let mut disabled = baseline.clone();
        disabled.enabled = false;
        assert_eq!(
            PermissionPrincipal::from_registration(&disabled),
            Err(PermissionModelError::PrincipalNotReady)
        );
        for health in [
            AgentHealth::Degraded,
            AgentHealth::Offline,
            AgentHealth::Disabled,
        ] {
            let mut not_ready = baseline.clone();
            not_ready.health = health;
            assert_eq!(
                PermissionPrincipal::from_registration(&not_ready),
                Err(PermissionModelError::PrincipalNotReady)
            );
        }
    }
}
