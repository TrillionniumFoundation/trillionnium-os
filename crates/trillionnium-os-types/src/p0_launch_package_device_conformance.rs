//! Opt-in machine contract for the non-product P0 `launch_package` device lane.
//!
//! The descriptor below is caller-visible data, not authority.  It binds one
//! exact source candidate to a generated stable Agent principal, the frozen
//! Direct permission model, Settings/user 0, and complete measured launch
//! policy.  Authentication of the descriptor and observed process is owned by
//! the privilege broker; this crate deliberately exposes no authenticated
//! capability or product-effect token.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::agent_direct_permission_model::{self, PERMISSION_MODEL_SHA256};
use crate::agent_principal_registry::{self, AgentStablePrincipal};
use crate::direct_operation::CODEX_PROVIDER_RUNTIME_CGROUP_PATH;
use crate::provider_post_exec_containment::ProviderRuntimeExecTopologyV1;

pub const BUILD_DESCRIPTOR_SCHEMA: &str =
    "org.trillionnium.p0-launch-package-device-conformance-build.v2";
pub const BUILD_DESCRIPTOR_STATUS: &str = "source_only_unmaterialized_hold";
pub const TARGET_ACTION: &str = "launch_package";
pub const TARGET_PACKAGE: &str = "com.android.settings";
pub const TARGET_ANDROID_USER: u32 = 0;
pub const REQUIRED_FD_POLICY: &str = "stdio_only_no_inherited_control_fds_v1";
pub const REQUIRED_GROUP_POLICY: &str = "no_supplementary_groups_v1";
pub const REQUIRED_CAPABILITY_POLICY: &str = "all_capability_sets_empty_v1";
pub const REQUIRED_DESCENDANT_POLICY: &str =
    "outer_owned_cgroup_zero_survivors_before_durable_ack_v1";

pub const SOURCE_BUILD_DESCRIPTOR_CONTRACT_IMPLEMENTED: bool = true;
pub const SOURCE_ARTIFACT_PINS_MATERIALIZED: bool = false;
pub const PRODUCT_BUILD_AUTHENTICATOR_AVAILABLE: bool = false;
pub const PRODUCT_PROVIDER_LAUNCH_ADMISSION_WIRED: bool = false;
pub const CONFERS_PRODUCT_EFFECT_AUTHORITY: bool = false;

#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum P0ConformanceProductVariant {
    Userdebug,
    Eng,
}

impl P0ConformanceProductVariant {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Userdebug => "userdebug",
            Self::Eng => "eng",
        }
    }
}

/// Canonical descriptor body.  Artifact digests are exact byte identities,
/// but remain unauthenticated until retained by a separately trusted build
/// authority.  No digest may be inferred from a path after launch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct P0LaunchPackageConformanceBuildBodyV2 {
    pub schema: String,
    pub status: String,
    pub provider_id: String,
    pub agent_id: String,
    pub identity_key_sha256: String,
    pub runtime_adapter: String,
    pub uid: u32,
    pub gid: u32,
    pub agent_selinux_domain: String,
    pub product_variant: P0ConformanceProductVariant,
    pub runtime_exec_topology: ProviderRuntimeExecTopologyV1,
    pub permission_model_sha256: String,
    pub direct_tool_names: [String; 2],
    pub action: String,
    pub package: String,
    pub android_user: u32,
    pub agent_manifest_sha256: String,
    pub launcher_executable_sha256: String,
    pub final_runtime_executable_sha256: String,
    pub final_runtime_closure_sha256: String,
    pub system_api_tool_sha256: String,
    pub accessibility_tool_sha256: String,
    pub compiled_selinux_policy_sha256: String,
    pub cgroup_policy_sha256: String,
    pub seccomp_filter_sha256: String,
    pub fd_table_sha256: String,
    pub supplementary_groups_policy_sha256: String,
    pub descendant_policy_sha256: String,
    pub expected_provider_runtime_cgroup_leaf: String,
    pub permitted_fd_numbers: [u32; 3],
    pub supplementary_groups: Vec<u32>,
    pub fd_policy: String,
    pub supplementary_group_policy: String,
    pub capability_policy: String,
    pub descendant_policy: String,
    pub required_no_new_privileges: u32,
    pub required_dumpable: u32,
    pub required_seccomp_mode: u32,
    pub outer_owned_cgroup_supervisor: bool,
    pub zero_survivors_required_before_durable_ack: bool,
    pub local_command_fallback: bool,
    pub product_effect_authority: bool,
}

/// Checksummed, authority-neutral build descriptor.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct P0LaunchPackageConformanceBuildDescriptorV2 {
    body: P0LaunchPackageConformanceBuildBodyV2,
    descriptor_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P0ConformanceContractError(&'static str);

impl P0ConformanceContractError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for P0ConformanceContractError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for P0ConformanceContractError {}

impl P0LaunchPackageConformanceBuildDescriptorV2 {
    /// Materialize authority-neutral candidate data.  This function computes
    /// an integrity checksum; it does not authenticate a build or caller.
    pub fn from_source_body(
        body: P0LaunchPackageConformanceBuildBodyV2,
    ) -> Result<Self, P0ConformanceContractError> {
        validate_body(&body)?;
        let descriptor_sha256 = canonical_body_sha256(&body)?;
        let descriptor = Self {
            body,
            descriptor_sha256,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn validate(&self) -> Result<(), P0ConformanceContractError> {
        validate_body(&self.body)?;
        if !valid_nonzero_sha256(&self.descriptor_sha256)
            || canonical_body_sha256(&self.body)? != self.descriptor_sha256
        {
            return Err(denied("p0_conformance_descriptor_checksum_denied"));
        }
        Ok(())
    }

    #[must_use]
    pub const fn body(&self) -> &P0LaunchPackageConformanceBuildBodyV2 {
        &self.body
    }

    #[must_use]
    pub fn descriptor_sha256(&self) -> &str {
        &self.descriptor_sha256
    }

    pub fn canonical_descriptor_json(&self) -> Result<Vec<u8>, P0ConformanceContractError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| denied("p0_conformance_descriptor_json_denied"))
    }
}

fn validate_body(
    body: &P0LaunchPackageConformanceBuildBodyV2,
) -> Result<(), P0ConformanceContractError> {
    if body.schema != BUILD_DESCRIPTOR_SCHEMA
        || body.status != BUILD_DESCRIPTOR_STATUS
        || body.permission_model_sha256 != PERMISSION_MODEL_SHA256
        || !agent_direct_permission_model::embedded_permission_model_measurement_is_exact()
        || body.direct_tool_names
            != [
                agent_direct_permission_model::DIRECT_AGENT_TOOL_NAMES[0].to_string(),
                agent_direct_permission_model::DIRECT_AGENT_TOOL_NAMES[1].to_string(),
            ]
        || body.action != TARGET_ACTION
        || body.package != TARGET_PACKAGE
        || body.android_user != TARGET_ANDROID_USER
    {
        return Err(denied("p0_conformance_fixed_contract_denied"));
    }

    let principal =
        agent_principal_registry::from_provider_agent_pair(&body.provider_id, &body.agent_id)
            .filter(|principal| principal_matches_body(principal, body))
            .ok_or_else(|| denied("p0_conformance_principal_denied"))?;

    if principal != &agent_principal_registry::CODEX_STABLE_PRINCIPAL {
        return Err(denied("p0_conformance_principal_denied"));
    }
    let expected_leaf = CODEX_PROVIDER_RUNTIME_CGROUP_PATH;
    // Codex enters through a measured launcher which retains
    // outer supervision while a distinct final runtime image is exec'd.  The
    // single-image enum value remains reserved for a future provider contract;
    // it is not a valid topology for either built-in provider.
    if body.runtime_exec_topology != ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime
        || body.launcher_executable_sha256 == body.final_runtime_executable_sha256
    {
        return Err(denied("p0_conformance_codex_topology_denied"));
    }

    if body.expected_provider_runtime_cgroup_leaf != expected_leaf
        || body.permitted_fd_numbers != [0, 1, 2]
        || !body.supplementary_groups.is_empty()
        || body.fd_policy != REQUIRED_FD_POLICY
        || body.supplementary_group_policy != REQUIRED_GROUP_POLICY
        || body.capability_policy != REQUIRED_CAPABILITY_POLICY
        || body.descendant_policy != REQUIRED_DESCENDANT_POLICY
        || body.required_no_new_privileges != 1
        || body.required_dumpable != 0
        || body.required_seccomp_mode != 2
        || !body.outer_owned_cgroup_supervisor
        || !body.zero_survivors_required_before_durable_ack
        || body.local_command_fallback
        || body.product_effect_authority
    {
        return Err(denied("p0_conformance_process_policy_denied"));
    }

    let exact_hashes = [
        body.agent_manifest_sha256.as_str(),
        body.identity_key_sha256.as_str(),
        body.final_runtime_closure_sha256.as_str(),
        body.system_api_tool_sha256.as_str(),
        body.accessibility_tool_sha256.as_str(),
        body.compiled_selinux_policy_sha256.as_str(),
        body.cgroup_policy_sha256.as_str(),
        body.seccomp_filter_sha256.as_str(),
        body.fd_table_sha256.as_str(),
        body.supplementary_groups_policy_sha256.as_str(),
        body.descendant_policy_sha256.as_str(),
    ];
    if body.launcher_executable_sha256 != body.identity_key_sha256
        || !exact_hashes.iter().all(|value| valid_nonzero_sha256(value))
        || !valid_nonzero_sha256(&body.final_runtime_executable_sha256)
        || (body.runtime_exec_topology == ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime
            && exact_hashes.contains(&body.final_runtime_executable_sha256.as_str()))
        || !all_distinct(&exact_hashes)
    {
        return Err(denied("p0_conformance_artifact_identity_denied"));
    }
    Ok(())
}

fn principal_matches_body(
    principal: &&'static AgentStablePrincipal,
    body: &P0LaunchPackageConformanceBuildBodyV2,
) -> bool {
    principal.runtime_adapter == body.runtime_adapter
        && principal.uid == body.uid
        && principal.gid == body.gid
        && principal.agent_selinux_domain == body.agent_selinux_domain
}

fn canonical_body_sha256(
    body: &P0LaunchPackageConformanceBuildBodyV2,
) -> Result<String, P0ConformanceContractError> {
    let canonical =
        serde_json::to_vec(body).map_err(|_| denied("p0_conformance_descriptor_json_denied"))?;
    let mut bytes = b"org.trillionnium.p0-launch-package-device-conformance-build.v2\0".to_vec();
    bytes.extend_from_slice(&canonical);
    Ok(crate::sha256_bytes(&bytes))
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().all(|byte| !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

fn all_distinct(values: &[&str]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

const fn denied(code: &'static str) -> P0ConformanceContractError {
    P0ConformanceContractError(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: u8) -> String {
        crate::sha256_bytes(&[seed])
    }

    fn body(
        principal: &'static AgentStablePrincipal,
        variant: P0ConformanceProductVariant,
    ) -> P0LaunchPackageConformanceBuildBodyV2 {
        // Authority-neutral measured candidate. The authenticated build
        // custody, not the stable principal registry, supplies this digest.
        let active_launcher_identity = digest(12);
        P0LaunchPackageConformanceBuildBodyV2 {
            schema: BUILD_DESCRIPTOR_SCHEMA.to_string(),
            status: BUILD_DESCRIPTOR_STATUS.to_string(),
            provider_id: principal.provider_id.to_string(),
            agent_id: principal.agent_id.to_string(),
            identity_key_sha256: active_launcher_identity.clone(),
            runtime_adapter: principal.runtime_adapter.to_string(),
            uid: principal.uid,
            gid: principal.gid,
            agent_selinux_domain: principal.agent_selinux_domain.to_string(),
            product_variant: variant,
            runtime_exec_topology: ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime,
            permission_model_sha256: PERMISSION_MODEL_SHA256.to_string(),
            direct_tool_names: [
                agent_direct_permission_model::DIRECT_AGENT_TOOL_NAMES[0].to_string(),
                agent_direct_permission_model::DIRECT_AGENT_TOOL_NAMES[1].to_string(),
            ],
            action: TARGET_ACTION.to_string(),
            package: TARGET_PACKAGE.to_string(),
            android_user: TARGET_ANDROID_USER,
            agent_manifest_sha256: digest(1),
            launcher_executable_sha256: active_launcher_identity,
            final_runtime_executable_sha256: digest(2),
            final_runtime_closure_sha256: digest(3),
            system_api_tool_sha256: digest(4),
            accessibility_tool_sha256: digest(5),
            compiled_selinux_policy_sha256: digest(6),
            cgroup_policy_sha256: digest(7),
            seccomp_filter_sha256: digest(8),
            fd_table_sha256: digest(9),
            supplementary_groups_policy_sha256: digest(10),
            descendant_policy_sha256: digest(11),
            expected_provider_runtime_cgroup_leaf: CODEX_PROVIDER_RUNTIME_CGROUP_PATH.to_string(),
            permitted_fd_numbers: [0, 1, 2],
            supplementary_groups: Vec::new(),
            fd_policy: REQUIRED_FD_POLICY.to_string(),
            supplementary_group_policy: REQUIRED_GROUP_POLICY.to_string(),
            capability_policy: REQUIRED_CAPABILITY_POLICY.to_string(),
            descendant_policy: REQUIRED_DESCENDANT_POLICY.to_string(),
            required_no_new_privileges: 1,
            required_dumpable: 0,
            required_seccomp_mode: 2,
            outer_owned_cgroup_supervisor: true,
            zero_survivors_required_before_durable_ack: true,
            local_command_fallback: false,
            product_effect_authority: false,
        }
    }

    #[test]
    fn receipt_active_codex_identity_validates_for_both_variants() {
        for principal in agent_principal_registry::PRODUCT_ALLOWLIST {
            for variant in [
                P0ConformanceProductVariant::Userdebug,
                P0ConformanceProductVariant::Eng,
            ] {
                let descriptor = P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(
                    body(principal, variant),
                )
                .unwrap();
                descriptor.validate().unwrap();
                assert_eq!(descriptor.body().product_variant, variant);
                assert!(valid_nonzero_sha256(descriptor.descriptor_sha256()));
                let decoded: P0LaunchPackageConformanceBuildDescriptorV2 =
                    serde_json::from_slice(&descriptor.canonical_descriptor_json().unwrap())
                        .unwrap();
                assert_eq!(decoded, descriptor);
            }
        }
    }

    #[test]
    fn active_launcher_rotation_does_not_change_the_stable_principal() {
        let mut rotated = body(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
            P0ConformanceProductVariant::Userdebug,
        );
        rotated.identity_key_sha256 = digest(31);
        rotated.launcher_executable_sha256 = rotated.identity_key_sha256.clone();
        let rotated = P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(rotated)
            .expect("independently measured active launcher candidate");
        assert_eq!(
            rotated.body().provider_id,
            agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id
        );
        assert_eq!(
            rotated.body().agent_id,
            agent_principal_registry::CODEX_STABLE_PRINCIPAL.agent_id
        );
    }

    #[test]
    fn every_principal_target_and_policy_drift_fails_closed() {
        type Drift = Box<dyn Fn(&mut P0LaunchPackageConformanceBuildBodyV2)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|v| v.schema.push_str("-drift")),
            Box::new(|v| v.status.push_str("-drift")),
            Box::new(|v| v.provider_id = "unregistered-provider".into()),
            Box::new(|v| v.agent_id = "unregistered-agent".into()),
            Box::new(|v| v.identity_key_sha256 = digest(20)),
            Box::new(|v| v.runtime_adapter.push_str("-drift")),
            Box::new(|v| v.uid += 1),
            Box::new(|v| v.gid += 1),
            Box::new(|v| v.agent_selinux_domain.push_str("-drift")),
            Box::new(|v| v.permission_model_sha256 = digest(21)),
            Box::new(|v| v.direct_tool_names.swap(0, 1)),
            Box::new(|v| v.action = "open_uri".into()),
            Box::new(|v| v.package = "com.example.injected".into()),
            Box::new(|v| v.android_user = 10),
            Box::new(|v| v.expected_provider_runtime_cgroup_leaf.push_str("/nested")),
            Box::new(|v| v.permitted_fd_numbers = [0, 1, 3]),
            Box::new(|v| v.supplementary_groups.push(5901)),
            Box::new(|v| v.fd_policy.push_str("-drift")),
            Box::new(|v| v.supplementary_group_policy.push_str("-drift")),
            Box::new(|v| v.capability_policy.push_str("-drift")),
            Box::new(|v| v.descendant_policy.push_str("-drift")),
            Box::new(|v| v.required_no_new_privileges = 0),
            Box::new(|v| v.required_dumpable = 1),
            Box::new(|v| v.required_seccomp_mode = 0),
            Box::new(|v| v.outer_owned_cgroup_supervisor = false),
            Box::new(|v| v.zero_survivors_required_before_durable_ack = false),
            Box::new(|v| v.local_command_fallback = true),
            Box::new(|v| v.product_effect_authority = true),
        ];
        for drift in drifts {
            let mut candidate = body(
                &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
                P0ConformanceProductVariant::Userdebug,
            );
            drift(&mut candidate);
            assert!(
                P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(candidate).is_err()
            );
        }
    }

    #[test]
    fn every_artifact_hash_and_topology_drift_fails_closed() {
        type Drift = Box<dyn Fn(&mut P0LaunchPackageConformanceBuildBodyV2)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|v| v.agent_manifest_sha256 = "0".repeat(64)),
            Box::new(|v| v.launcher_executable_sha256 = digest(30)),
            Box::new(|v| v.final_runtime_executable_sha256 = "0".repeat(64)),
            Box::new(|v| v.final_runtime_closure_sha256 = v.agent_manifest_sha256.clone()),
            Box::new(|v| v.system_api_tool_sha256 = v.accessibility_tool_sha256.clone()),
            Box::new(|v| v.accessibility_tool_sha256 = "F".repeat(64)),
            Box::new(|v| v.compiled_selinux_policy_sha256 = "short".into()),
            Box::new(|v| v.cgroup_policy_sha256 = v.seccomp_filter_sha256.clone()),
            Box::new(|v| v.seccomp_filter_sha256 = v.fd_table_sha256.clone()),
            Box::new(|v| v.fd_table_sha256 = v.supplementary_groups_policy_sha256.clone()),
            Box::new(|v| v.supplementary_groups_policy_sha256 = v.descendant_policy_sha256.clone()),
            Box::new(|v| v.descendant_policy_sha256 = v.final_runtime_closure_sha256.clone()),
            Box::new(|v| {
                v.runtime_exec_topology = ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage
            }),
        ];
        for drift in drifts {
            let mut candidate = body(
                &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
                P0ConformanceProductVariant::Eng,
            );
            drift(&mut candidate);
            assert!(
                P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(candidate).is_err()
            );
        }
    }

    #[test]
    fn codex_single_image_and_aliased_launcher_final_are_denied() {
        let mut single_image = body(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
            P0ConformanceProductVariant::Userdebug,
        );
        single_image.runtime_exec_topology = ProviderRuntimeExecTopologyV1::SingleFinalRuntimeImage;
        single_image.final_runtime_executable_sha256 =
            single_image.launcher_executable_sha256.clone();
        assert_eq!(
            P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(single_image)
                .unwrap_err()
                .code(),
            "p0_conformance_codex_topology_denied"
        );

        let mut aliased = body(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
            P0ConformanceProductVariant::Eng,
        );
        aliased.final_runtime_executable_sha256 = aliased.launcher_executable_sha256.clone();
        assert_eq!(
            P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(aliased)
                .unwrap_err()
                .code(),
            "p0_conformance_codex_topology_denied"
        );
    }

    #[test]
    fn checksum_unknown_fields_and_non_conformance_variants_are_closed() {
        let mut descriptor = P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(body(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
            P0ConformanceProductVariant::Userdebug,
        ))
        .unwrap();
        descriptor.descriptor_sha256 = digest(40);
        assert!(descriptor.validate().is_err());

        let exact = P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(body(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
            P0ConformanceProductVariant::Userdebug,
        ))
        .unwrap();
        let mut value = serde_json::to_value(exact).unwrap();
        value["injected"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<P0LaunchPackageConformanceBuildDescriptorV2>(value).is_err()
        );

        let mut value = serde_json::to_value(body(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
            P0ConformanceProductVariant::Userdebug,
        ))
        .unwrap();
        value["product_variant"] = serde_json::json!("user");
        assert!(serde_json::from_value::<P0LaunchPackageConformanceBuildBodyV2>(value).is_err());
    }

    #[test]
    fn status_flags_do_not_claim_materialized_or_product_authority() {
        const {
            assert!(SOURCE_BUILD_DESCRIPTOR_CONTRACT_IMPLEMENTED);
            assert!(!SOURCE_ARTIFACT_PINS_MATERIALIZED);
            assert!(!PRODUCT_BUILD_AUTHENTICATOR_AVAILABLE);
            assert!(!PRODUCT_PROVIDER_LAUNCH_ADMISSION_WIRED);
            assert!(!CONFERS_PRODUCT_EFFECT_AUTHORITY);
        }
    }
}
