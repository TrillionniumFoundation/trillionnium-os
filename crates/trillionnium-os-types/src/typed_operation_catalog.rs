//! Closed, non-authorizing source model for the future typed exec/ADB broker.
//!
//! This module deliberately separates request materialization from product
//! authority. It can resolve only the three frozen P0 launch-package candidates
//! and has no constructor that can mint effect authority.  A signed,
//! AVB-bound product catalog, Android backend, policy lease, durable PREPARED
//! record, and replay/outer-ACK pipeline must land before promotion.

use serde_json::Value;

use crate::agent_direct_permission_model::{
    self, PermissionAction, PermissionDisposition, PermissionPrincipal, PermissionSurface,
    ProductVariant,
};
use crate::agent_principal_registry::{self, AgentStablePrincipal};
use crate::{AgentHealth, AgentRegistration};

pub const CATALOG_SCHEMA: &str = "org.trillionnium.agent-typed-operation-catalog.v1";
pub const CATALOG_SHA256: &str = "c4efd224e75bc21ab95753eac4f183732c447e315ac89d4369bc5185a4997453";
pub const CATALOG_STATUS: &str = "frozen_source_candidate_hold";
pub const EXEC_LAUNCH_SETTINGS_V1: &str = "exec.launch_package.settings.v1";
pub const ADB_LAUNCH_SETTINGS_USER_V1: &str = "adb.launch_package.settings.user.v1";
pub const ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY_V1: &str =
    "adb.launch_package.settings.engineering-recovery.v1";

const LAUNCH_SETTINGS_ARGUMENTS: &[&str] = &[
    "activity",
    "start-activity",
    "--user",
    "current",
    "-a",
    "android.intent.action.MAIN",
    "-c",
    "android.intent.category.LAUNCHER",
    "-p",
    "com.android.settings",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedOperationAdapter {
    TypedExec,
    TypedAdb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedExecutionControls {
    pub capabilities: &'static [&'static str],
    pub environment: &'static [(&'static str, &'static str)],
    pub stdin: &'static str,
    pub filesystem_scope: &'static str,
    pub network_scope: &'static str,
    pub deadline_ms: u64,
    pub stdout_limit_bytes: u64,
    pub stderr_limit_bytes: u64,
    pub total_output_limit_bytes: u64,
    pub descendant_process_policy: &'static str,
    pub opaque_fd_passing: bool,
}

pub const EXEC_LAUNCH_SETTINGS_CONTROLS: TypedExecutionControls = TypedExecutionControls {
    capabilities: &[],
    environment: &[
        ("ANDROID_DATA", "/data"),
        ("ANDROID_ROOT", "/system"),
        ("PATH", "/system/bin"),
    ],
    stdin: "closed",
    filesystem_scope: "fixed_android_framework_only",
    network_scope: "none",
    deadline_ms: 15_000,
    stdout_limit_bytes: 65_536,
    stderr_limit_bytes: 65_536,
    total_output_limit_bytes: 65_536,
    descendant_process_policy: "no_background_descendants_kill_cgroup_at_deadline",
    opaque_fd_passing: false,
};

pub const ADB_LAUNCH_SETTINGS_CONTROLS: TypedExecutionControls = TypedExecutionControls {
    capabilities: &[],
    environment: &[],
    stdin: "closed",
    filesystem_scope: "none",
    network_scope: "fixed_local_adbd_only",
    deadline_ms: 15_000,
    stdout_limit_bytes: 65_536,
    stderr_limit_bytes: 65_536,
    total_output_limit_bytes: 65_536,
    descendant_process_policy: "no_background_descendants_kill_cgroup_at_deadline",
    opaque_fd_passing: false,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedExecutionDescriptor {
    Exec {
        executable: &'static str,
        argv0: &'static str,
        argv: &'static [&'static str],
        uid: u32,
        gid: u32,
        selinux_domain: &'static str,
        cgroup_profile: &'static str,
        seccomp_profile: &'static str,
        controls: TypedExecutionControls,
    },
    Adb {
        target: &'static str,
        transport: &'static str,
        service: &'static str,
        service_arguments: &'static [&'static str],
        serial: Option<&'static str>,
        host: Option<&'static str>,
        port: Option<u16>,
        adbd_key_custody: &'static str,
        product_identity: &'static str,
        cgroup_profile: &'static str,
        seccomp_profile: &'static str,
        controls: TypedExecutionControls,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedOperationAdmission {
    pub product_variants: &'static [&'static str],
    pub risk_class: &'static str,
    pub one_shot_lease_required: bool,
    pub user_consent: &'static str,
    pub single_delivery_attempt_required: bool,
    pub direct_system_api_unavailable_proof_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TypedOperationDefinition {
    pub operation_id: &'static str,
    pub adapter: TypedOperationAdapter,
    pub agent_argument_shape: &'static str,
    pub unknown_fields: &'static str,
    pub descriptor: TypedExecutionDescriptor,
    pub admission: TypedOperationAdmission,
}

pub const EXEC_LAUNCH_SETTINGS: TypedOperationDefinition = TypedOperationDefinition {
    operation_id: EXEC_LAUNCH_SETTINGS_V1,
    adapter: TypedOperationAdapter::TypedExec,
    agent_argument_shape: "closed_empty_object",
    unknown_fields: "reject",
    descriptor: TypedExecutionDescriptor::Exec {
        executable: "/system/bin/cmd",
        argv0: "cmd",
        argv: LAUNCH_SETTINGS_ARGUMENTS,
        uid: 2000,
        gid: 2000,
        selinux_domain: "u:r:trillionnium_typed_exec:s0",
        cgroup_profile: "typed-exec-launch-package-v1",
        seccomp_profile: "typed-exec-launch-package-v1",
        controls: EXEC_LAUNCH_SETTINGS_CONTROLS,
    },
    admission: TypedOperationAdmission {
        product_variants: &["user", "userdebug", "eng", "recovery"],
        risk_class: "foreground_app_launch",
        one_shot_lease_required: true,
        user_consent: "os_policy_decides_before_prepared",
        single_delivery_attempt_required: true,
        direct_system_api_unavailable_proof_required: false,
    },
};

pub const ADB_LAUNCH_SETTINGS_USER: TypedOperationDefinition = TypedOperationDefinition {
    operation_id: ADB_LAUNCH_SETTINGS_USER_V1,
    adapter: TypedOperationAdapter::TypedAdb,
    agent_argument_shape: "closed_empty_object",
    unknown_fields: "reject",
    descriptor: TypedExecutionDescriptor::Adb {
        target: "self_device_only",
        transport: "os_owned_local_user_product_adbd",
        service: "abb_exec",
        service_arguments: LAUNCH_SETTINGS_ARGUMENTS,
        serial: None,
        host: None,
        port: None,
        adbd_key_custody: "os_owned_user_product_not_agent_addressable",
        product_identity: "os_selected_local_user_device_avb_identity",
        cgroup_profile: "typed-adb-launch-package-user-v1",
        seccomp_profile: "typed-adb-launch-package-user-v1",
        controls: ADB_LAUNCH_SETTINGS_CONTROLS,
    },
    admission: TypedOperationAdmission {
        product_variants: &["user"],
        risk_class: "foreground_app_launch_product_fallback",
        one_shot_lease_required: true,
        user_consent: "os_policy_decides_before_prepared",
        single_delivery_attempt_required: true,
        direct_system_api_unavailable_proof_required: true,
    },
};

pub const ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY: TypedOperationDefinition =
    TypedOperationDefinition {
        operation_id: ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY_V1,
        adapter: TypedOperationAdapter::TypedAdb,
        agent_argument_shape: "closed_empty_object",
        unknown_fields: "reject",
        descriptor: TypedExecutionDescriptor::Adb {
            target: "self_device_only",
            transport: "os_owned_local_engineering_recovery_adbd",
            service: "abb_exec",
            service_arguments: LAUNCH_SETTINGS_ARGUMENTS,
            serial: None,
            host: None,
            port: None,
            adbd_key_custody: "os_owned_engineering_recovery_not_agent_addressable",
            product_identity: "os_selected_local_engineering_recovery_avb_identity",
            cgroup_profile: "typed-adb-launch-package-engineering-recovery-v1",
            seccomp_profile: "typed-adb-launch-package-engineering-recovery-v1",
            controls: ADB_LAUNCH_SETTINGS_CONTROLS,
        },
        admission: TypedOperationAdmission {
            product_variants: &["userdebug", "eng", "recovery"],
            risk_class: "foreground_app_launch_engineering_recovery",
            one_shot_lease_required: true,
            user_consent: "os_policy_decides_before_prepared",
            single_delivery_attempt_required: true,
            direct_system_api_unavailable_proof_required: true,
        },
    };

pub const SOURCE_CANDIDATES: &[&TypedOperationDefinition] = &[
    &EXEC_LAUNCH_SETTINGS,
    &ADB_LAUNCH_SETTINGS_USER,
    &ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY,
];

/// Exact JSON projection used to prove that the typed Rust model carries every
/// field in the measured machine catalog. This is a source model only; parsing
/// or projecting it cannot grant effect authority.
#[must_use]
pub fn definition_as_json(definition: &TypedOperationDefinition) -> Value {
    let execution_descriptor = match definition.descriptor {
        TypedExecutionDescriptor::Exec {
            executable,
            argv0,
            argv,
            uid,
            gid,
            selinux_domain,
            cgroup_profile,
            seccomp_profile,
            controls,
        } => {
            let mut value = serde_json::json!({
                "executable": executable,
                "argv0": argv0,
                "argv": argv,
                "uid": uid,
                "gid": gid,
                "selinux_domain": selinux_domain,
                "cgroup_profile": cgroup_profile,
                "seccomp_profile": seccomp_profile,
            });
            append_controls(&mut value, controls);
            value
        }
        TypedExecutionDescriptor::Adb {
            target,
            transport,
            service,
            service_arguments,
            serial,
            host,
            port,
            adbd_key_custody,
            product_identity,
            cgroup_profile,
            seccomp_profile,
            controls,
        } => {
            let mut value = serde_json::json!({
                "target": target,
                "transport": transport,
                "service": service,
                "service_arguments": service_arguments,
                "serial": serial,
                "host": host,
                "port": port,
                "adbd_key_custody": adbd_key_custody,
                "product_identity": product_identity,
                "cgroup_profile": cgroup_profile,
                "seccomp_profile": seccomp_profile,
            });
            append_controls(&mut value, controls);
            value
        }
    };
    let mut admission = serde_json::json!({
        "product_variants": definition.admission.product_variants,
        "risk_class": definition.admission.risk_class,
        "one_shot_lease_required": definition.admission.one_shot_lease_required,
        "user_consent": definition.admission.user_consent,
        "single_delivery_attempt_required": definition.admission.single_delivery_attempt_required,
    });
    if definition
        .admission
        .direct_system_api_unavailable_proof_required
    {
        admission
            .as_object_mut()
            .expect("admission projection is an object")
            .insert(
                "direct_system_api_unavailable_proof_required".to_string(),
                Value::Bool(true),
            );
    }
    serde_json::json!({
        "operation_id": definition.operation_id,
        "adapter": match definition.adapter {
            TypedOperationAdapter::TypedExec => "typed_exec",
            TypedOperationAdapter::TypedAdb => "typed_adb",
        },
        "agent_arguments": {
            "shape": definition.agent_argument_shape,
            "unknown_fields": definition.unknown_fields,
        },
        "execution_descriptor": execution_descriptor,
        "admission": admission,
    })
}

fn append_controls(value: &mut Value, controls: TypedExecutionControls) {
    let object = value
        .as_object_mut()
        .expect("execution descriptor projection is an object");
    let environment = controls
        .environment
        .iter()
        .map(|(key, value)| ((*key).to_string(), Value::String((*value).to_string())))
        .collect::<serde_json::Map<_, _>>();
    for (key, value) in [
        (
            "capabilities",
            Value::Array(
                controls
                    .capabilities
                    .iter()
                    .map(|value| Value::String((*value).to_string()))
                    .collect(),
            ),
        ),
        ("environment", Value::Object(environment)),
        ("stdin", Value::String(controls.stdin.to_string())),
        (
            "filesystem_scope",
            Value::String(controls.filesystem_scope.to_string()),
        ),
        (
            "network_scope",
            Value::String(controls.network_scope.to_string()),
        ),
        ("deadline_ms", Value::from(controls.deadline_ms)),
        (
            "stdout_limit_bytes",
            Value::from(controls.stdout_limit_bytes),
        ),
        (
            "stderr_limit_bytes",
            Value::from(controls.stderr_limit_bytes),
        ),
        (
            "total_output_limit_bytes",
            Value::from(controls.total_output_limit_bytes),
        ),
        (
            "descendant_process_policy",
            Value::String(controls.descendant_process_policy.to_string()),
        ),
        ("opaque_fd_passing", Value::Bool(controls.opaque_fd_passing)),
    ] {
        object.insert(key.to_string(), value);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatalogPrincipal {
    stable_principal: &'static AgentStablePrincipal,
}

impl CatalogPrincipal {
    pub fn from_registration(
        registration: &AgentRegistration,
    ) -> Result<Self, TypedOperationCatalogError> {
        if !registration.enabled || registration.health != AgentHealth::Ready {
            return Err(TypedOperationCatalogError::PrincipalNotReady);
        }
        let stable_principal = agent_principal_registry::from_registration_fields(registration)
            .ok_or(TypedOperationCatalogError::PrincipalIdentityMismatch)?;
        Ok(Self { stable_principal })
    }

    pub const fn stable_principal(&self) -> &'static AgentStablePrincipal {
        self.stable_principal
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedTypedOperation {
    pub catalog_sha256: &'static str,
    pub permission_model_sha256: &'static str,
    pub operation: &'static TypedOperationDefinition,
    pub provider_id: &'static str,
    pub agent_id: &'static str,
    pub canonical_arguments_sha256: String,
    pub operation_binding_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypedOperationCatalogError {
    CatalogMeasurementMismatch,
    PrincipalIdentityMismatch,
    PrincipalNotReady,
    UnknownOperation,
    ArgumentsNotClosedEmptyObject,
    PermissionModelDenied,
    ProductCatalogAuthorityUnavailable,
}

pub fn embedded_catalog_measurement_is_exact() -> bool {
    crate::sha256_bytes(include_bytes!(
        "../contracts/agent-typed-operation-catalog-v1.json"
    )) == CATALOG_SHA256
}

/// Resolve a closed source candidate without granting permission to execute it.
pub fn materialize_source_candidate(
    principal: CatalogPrincipal,
    product_variant: ProductVariant,
    operation_id: &str,
    arguments: &Value,
) -> Result<MaterializedTypedOperation, TypedOperationCatalogError> {
    if !embedded_catalog_measurement_is_exact() {
        return Err(TypedOperationCatalogError::CatalogMeasurementMismatch);
    }
    if arguments
        .as_object()
        .is_none_or(|object| !object.is_empty())
    {
        return Err(TypedOperationCatalogError::ArgumentsNotClosedEmptyObject);
    }
    let operation = SOURCE_CANDIDATES
        .iter()
        .copied()
        .find(|candidate| candidate.operation_id == operation_id)
        .ok_or(TypedOperationCatalogError::UnknownOperation)?;
    let (surface, permission_action) = match operation.operation_id {
        EXEC_LAUNCH_SETTINGS_V1 => (
            PermissionSurface::TypedExec,
            PermissionAction::ExecLaunchSettingsV1,
        ),
        ADB_LAUNCH_SETTINGS_USER_V1 => (
            PermissionSurface::TypedAdb,
            PermissionAction::AdbLaunchSettingsUserV1,
        ),
        ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY_V1 => (
            PermissionSurface::TypedAdb,
            PermissionAction::AdbLaunchSettingsEngineeringRecoveryV1,
        ),
        _ => return Err(TypedOperationCatalogError::PermissionModelDenied),
    };
    let permission_principal =
        PermissionPrincipal::from_stable_principal(principal.stable_principal)
            .map_err(|_| TypedOperationCatalogError::PermissionModelDenied)?;
    if agent_direct_permission_model::variant_permission_disposition(
        permission_principal,
        product_variant,
        surface,
        permission_action,
    ) != Ok(PermissionDisposition::SourceCandidateHold)
    {
        return Err(TypedOperationCatalogError::PermissionModelDenied);
    }
    let canonical_arguments_sha256 = crate::sha256_json(arguments);
    let operation_binding_sha256 = crate::sha256_json(&serde_json::json!({
        "agent_id": principal.stable_principal.agent_id,
        "arguments_sha256": canonical_arguments_sha256,
        "catalog_sha256": CATALOG_SHA256,
        "operation_id": operation.operation_id,
        "permission_model_sha256": agent_direct_permission_model::PERMISSION_MODEL_SHA256,
        "product_variant": product_variant.as_str(),
        "provider_id": principal.stable_principal.provider_id,
    }));
    Ok(MaterializedTypedOperation {
        catalog_sha256: CATALOG_SHA256,
        permission_model_sha256: agent_direct_permission_model::PERMISSION_MODEL_SHA256,
        operation,
        provider_id: principal.stable_principal.provider_id,
        agent_id: principal.stable_principal.agent_id,
        canonical_arguments_sha256,
        operation_binding_sha256,
    })
}

/// Product authority is intentionally unavailable until every promotion gate
/// in the embedded catalog is backed by installed and measured product state.
pub fn require_current_product_authority(
    _candidate: &MaterializedTypedOperation,
) -> Result<(), TypedOperationCatalogError> {
    Err(TypedOperationCatalogError::ProductCatalogAuthorityUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentNetworkPolicy, AgentRegistration};

    fn registration(stable_principal: &AgentStablePrincipal) -> AgentRegistration {
        AgentRegistration {
            api_version: crate::AGENT_API_VERSION.to_string(),
            agent_id: stable_principal.agent_id.to_string(),
            adapter: stable_principal.runtime_adapter.to_string(),
            adapter_version: "frozen-test".to_string(),
            identity_key_sha256: crate::sha256_bytes(b"independent-catalog-test-launcher"),
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
    fn embedded_catalog_is_measured_and_non_authorizing() {
        assert!(embedded_catalog_measurement_is_exact());
        let catalog: Value = serde_json::from_slice(include_bytes!(
            "../contracts/agent-typed-operation-catalog-v1.json"
        ))
        .expect("catalog JSON");
        assert_eq!(catalog["schema"], CATALOG_SCHEMA);
        assert_eq!(catalog["revision"], 2);
        assert_eq!(catalog["status"], CATALOG_STATUS);
        assert_eq!(catalog["effect_authority"], false);
        assert!(agent_direct_permission_model::embedded_permission_model_measurement_is_exact());
        assert_eq!(catalog["product_signature"]["status"], "absent_hold");
        assert!(
            catalog["promotion_gates"]
                .as_object()
                .expect("promotion gates")
                .values()
                .all(|value| value == false)
        );
    }

    #[test]
    fn rust_definitions_equal_every_measured_catalog_operation_field() {
        let catalog: Value = serde_json::from_slice(include_bytes!(
            "../contracts/agent-typed-operation-catalog-v1.json"
        ))
        .expect("catalog JSON");
        let operations = catalog["operations"]
            .as_array()
            .expect("catalog operations");
        assert_eq!(operations.len(), SOURCE_CANDIDATES.len());
        for (measured, definition) in operations.iter().zip(SOURCE_CANDIDATES) {
            assert_eq!(measured, &definition_as_json(definition));
        }
    }

    #[test]
    fn codex_principal_resolves_only_the_variant_closed_candidates() {
        for stable_principal in [&agent_principal_registry::CODEX_STABLE_PRINCIPAL] {
            let principal = CatalogPrincipal::from_registration(&registration(stable_principal))
                .expect("registered principal");
            for (variant, admitted) in [
                (
                    ProductVariant::User,
                    [EXEC_LAUNCH_SETTINGS_V1, ADB_LAUNCH_SETTINGS_USER_V1],
                ),
                (
                    ProductVariant::Userdebug,
                    [
                        EXEC_LAUNCH_SETTINGS_V1,
                        ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY_V1,
                    ],
                ),
                (
                    ProductVariant::Eng,
                    [
                        EXEC_LAUNCH_SETTINGS_V1,
                        ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY_V1,
                    ],
                ),
                (
                    ProductVariant::Recovery,
                    [
                        EXEC_LAUNCH_SETTINGS_V1,
                        ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY_V1,
                    ],
                ),
            ] {
                for operation_id in admitted {
                    let candidate = materialize_source_candidate(
                        principal,
                        variant,
                        operation_id,
                        &serde_json::json!({}),
                    )
                    .expect("variant-closed candidate");
                    assert_eq!(candidate.catalog_sha256, CATALOG_SHA256);
                    assert_eq!(
                        candidate.permission_model_sha256,
                        agent_direct_permission_model::PERMISSION_MODEL_SHA256
                    );
                    assert_eq!(candidate.agent_id, stable_principal.agent_id);
                    assert_eq!(candidate.operation.operation_id, operation_id);
                    assert_eq!(
                        candidate.operation_binding_sha256,
                        crate::sha256_json(&serde_json::json!({
                            "agent_id": stable_principal.agent_id,
                            "arguments_sha256": candidate.canonical_arguments_sha256,
                            "catalog_sha256": CATALOG_SHA256,
                            "operation_id": operation_id,
                            "permission_model_sha256":
                                agent_direct_permission_model::PERMISSION_MODEL_SHA256,
                            "product_variant": variant.as_str(),
                            "provider_id": stable_principal.provider_id,
                        }))
                    );
                    assert_eq!(
                        require_current_product_authority(&candidate),
                        Err(TypedOperationCatalogError::ProductCatalogAuthorityUnavailable)
                    );
                }
            }
        }
    }

    #[test]
    fn cross_variant_typed_adb_materialization_is_denied() {
        let principal = CatalogPrincipal::from_registration(&registration(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
        ))
        .expect("registered principal");
        assert_eq!(
            materialize_source_candidate(
                principal,
                ProductVariant::User,
                ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY_V1,
                &serde_json::json!({}),
            ),
            Err(TypedOperationCatalogError::PermissionModelDenied)
        );
        assert_eq!(
            materialize_source_candidate(
                principal,
                ProductVariant::Userdebug,
                ADB_LAUNCH_SETTINGS_USER_V1,
                &serde_json::json!({}),
            ),
            Err(TypedOperationCatalogError::PermissionModelDenied)
        );
    }

    #[test]
    fn caller_cannot_supply_argv_transport_or_identity() {
        let principal = CatalogPrincipal::from_registration(&registration(
            &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
        ))
        .expect("registered principal");
        for arguments in [
            serde_json::json!({"argv": ["sh", "-c", "id"]}),
            serde_json::json!({"serial": "attacker-selected"}),
            serde_json::json!({"uid": 0}),
            serde_json::json!({"package": "attacker.package"}),
            serde_json::json!(null),
            serde_json::json!([]),
        ] {
            assert_eq!(
                materialize_source_candidate(
                    principal,
                    ProductVariant::User,
                    EXEC_LAUNCH_SETTINGS_V1,
                    &arguments,
                ),
                Err(TypedOperationCatalogError::ArgumentsNotClosedEmptyObject)
            );
        }
        assert_eq!(
            materialize_source_candidate(
                principal,
                ProductVariant::User,
                "exec.arbitrary.v1",
                &serde_json::json!({}),
            ),
            Err(TypedOperationCatalogError::UnknownOperation)
        );
    }

    #[test]
    fn principal_binding_ignores_executable_rotation_but_rejects_stable_or_liveness_drift() {
        let baseline = registration(&agent_principal_registry::CODEX_STABLE_PRINCIPAL);
        let baseline_principal =
            CatalogPrincipal::from_registration(&baseline).expect("stable catalog principal");
        let mut rotated = baseline.clone();
        rotated.identity_key_sha256 = crate::sha256_bytes(b"rotated-catalog-launcher");
        assert_ne!(rotated.identity_key_sha256, baseline.identity_key_sha256);
        assert_eq!(
            CatalogPrincipal::from_registration(&rotated),
            Ok(baseline_principal)
        );
        let baseline_candidate = materialize_source_candidate(
            baseline_principal,
            ProductVariant::User,
            EXEC_LAUNCH_SETTINGS_V1,
            &serde_json::json!({}),
        )
        .expect("baseline source candidate");
        let rotated_candidate = materialize_source_candidate(
            CatalogPrincipal::from_registration(&rotated).expect("rotated stable principal"),
            ProductVariant::User,
            EXEC_LAUNCH_SETTINGS_V1,
            &serde_json::json!({}),
        )
        .expect("rotated source candidate");
        assert_eq!(rotated_candidate, baseline_candidate);

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
        for value in &drifts {
            assert_eq!(
                CatalogPrincipal::from_registration(value),
                Err(TypedOperationCatalogError::PrincipalIdentityMismatch)
            );
        }

        let mut value = baseline.clone();
        value.enabled = false;
        assert_eq!(
            CatalogPrincipal::from_registration(&value),
            Err(TypedOperationCatalogError::PrincipalNotReady)
        );
        for health in [
            AgentHealth::Degraded,
            AgentHealth::Offline,
            AgentHealth::Disabled,
        ] {
            let mut value = baseline.clone();
            value.health = health;
            assert_eq!(
                CatalogPrincipal::from_registration(&value),
                Err(TypedOperationCatalogError::PrincipalNotReady)
            );
        }
    }

    #[test]
    fn descriptors_have_no_shell_interpreter_or_agent_selected_target() {
        match EXEC_LAUNCH_SETTINGS.descriptor {
            TypedExecutionDescriptor::Exec {
                executable,
                argv0,
                argv,
                uid,
                ..
            } => {
                assert_eq!(executable, "/system/bin/cmd");
                assert_eq!(argv0, "cmd");
                assert_eq!(uid, 2000);
                assert!(!argv.contains(&"sh"));
                assert!(!argv.windows(2).any(|pair| pair == ["sh", "-c"]));
            }
            _ => panic!("typed exec descriptor drifted"),
        }
        for definition in [
            ADB_LAUNCH_SETTINGS_USER,
            ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY,
        ] {
            match definition.descriptor {
                TypedExecutionDescriptor::Adb {
                    target,
                    service,
                    service_arguments,
                    serial,
                    host,
                    port,
                    ..
                } => {
                    assert_eq!(target, "self_device_only");
                    assert_eq!(service, "abb_exec");
                    assert_eq!((serial, host, port), (None, None, None));
                    assert!(
                        !service_arguments
                            .iter()
                            .any(|token| matches!(*token, "shell" | "sh"))
                    );
                    assert!(
                        !service_arguments
                            .windows(2)
                            .any(|pair| pair == ["sh", "-c"])
                    );
                }
                _ => panic!("typed adb descriptor drifted"),
            }
        }
    }

    #[test]
    fn user_and_engineering_recovery_adb_descriptors_are_disjoint() {
        assert_eq!(
            ADB_LAUNCH_SETTINGS_USER.admission.product_variants,
            &["user"]
        );
        assert_eq!(
            ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY
                .admission
                .product_variants,
            &["userdebug", "eng", "recovery"]
        );
        assert_ne!(
            ADB_LAUNCH_SETTINGS_USER.descriptor,
            ADB_LAUNCH_SETTINGS_ENGINEERING_RECOVERY.descriptor
        );
    }
}
