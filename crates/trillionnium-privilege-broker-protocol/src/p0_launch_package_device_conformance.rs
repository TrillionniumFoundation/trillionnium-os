//! Authority-neutral broker binding for the opt-in P0 device conformance lane.
//!
//! This type is deliberately not a live `Request` variant.  It contains no
//! path, argv, environment, PID, cgroup selector, or command.  Its checksum
//! binds one validated source descriptor to the closed broker provider enum;
//! broker-owned build and held-process authentication remain mandatory.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use trillionnium_os_types::agent_direct_permission_model::PERMISSION_MODEL_SHA256;
use trillionnium_os_types::agent_principal_registry;
use trillionnium_os_types::p0_launch_package_device_conformance::{
    P0ConformanceProductVariant, P0LaunchPackageConformanceBuildDescriptorV2, TARGET_ACTION,
    TARGET_ANDROID_USER, TARGET_PACKAGE,
};

use crate::{Digest, FixedBytes32, Provider};

pub const INTENT_SCHEMA: &str = "org.trillionnium.p0-launch-package-device-conformance-intent.v1";
pub const SOURCE_INTENT_CONTRACT_IMPLEMENTED: bool = true;
pub const LIVE_REQUEST_VARIANT_AVAILABLE: bool = false;
pub const PRODUCT_MUTATION_ROUTE_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct P0LaunchPackageConformanceIntentV1 {
    schema: String,
    provider: Provider,
    product_variant: P0ConformanceProductVariant,
    provider_id_sha256: Digest,
    agent_id_sha256: Digest,
    build_descriptor_sha256: Digest,
    permission_model_sha256: Digest,
    system_api_tool_sha256: Digest,
    accessibility_tool_sha256: Digest,
    target_sha256: Digest,
    intent_sha256: Digest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct P0ConformanceIntentError(&'static str);

impl P0ConformanceIntentError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for P0ConformanceIntentError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for P0ConformanceIntentError {}

impl P0LaunchPackageConformanceIntentV1 {
    /// Bind an authority-neutral intent to exact descriptor data.  The return
    /// value is checksummed data and cannot release a provider or Android
    /// effect by itself.
    pub fn from_source_descriptor(
        provider: Provider,
        descriptor: &P0LaunchPackageConformanceBuildDescriptorV2,
    ) -> Result<Self, P0ConformanceIntentError> {
        descriptor
            .validate()
            .map_err(|_| denied("p0_conformance_build_descriptor_denied"))?;
        let body = descriptor.body();
        let principal = stable_principal(provider);
        if body.provider_id != principal.provider_id || body.agent_id != principal.agent_id {
            return Err(denied("p0_conformance_provider_binding_denied"));
        }
        let mut intent = Self {
            schema: INTENT_SCHEMA.to_string(),
            provider,
            product_variant: body.product_variant,
            provider_id_sha256: digest_utf8(principal.provider_id.as_bytes())?,
            agent_id_sha256: digest_utf8(principal.agent_id.as_bytes())?,
            build_descriptor_sha256: digest_lower_hex(descriptor.descriptor_sha256())?,
            permission_model_sha256: digest_lower_hex(PERMISSION_MODEL_SHA256)?,
            system_api_tool_sha256: digest_lower_hex(&body.system_api_tool_sha256)?,
            accessibility_tool_sha256: digest_lower_hex(&body.accessibility_tool_sha256)?,
            target_sha256: target_sha256()?,
            // Replaced before the value escapes.
            intent_sha256: digest_utf8(b"p0-conformance-intent-placeholder")?,
        };
        intent.intent_sha256 = intent.expected_sha256()?;
        intent.validate()?;
        Ok(intent)
    }

    pub fn validate(&self) -> Result<(), P0ConformanceIntentError> {
        let principal = stable_principal(self.provider);
        if self.schema != INTENT_SCHEMA
            || self.provider_id_sha256 != digest_utf8(principal.provider_id.as_bytes())?
            || self.agent_id_sha256 != digest_utf8(principal.agent_id.as_bytes())?
            || self.permission_model_sha256 != digest_lower_hex(PERMISSION_MODEL_SHA256)?
            || self.system_api_tool_sha256 == self.accessibility_tool_sha256
            || self.target_sha256 != target_sha256()?
            || self.intent_sha256 != self.expected_sha256()?
        {
            return Err(denied("p0_conformance_intent_denied"));
        }
        Ok(())
    }

    #[must_use]
    pub const fn provider(&self) -> Provider {
        self.provider
    }

    #[must_use]
    pub const fn product_variant(&self) -> P0ConformanceProductVariant {
        self.product_variant
    }

    #[must_use]
    pub const fn build_descriptor_sha256(&self) -> Digest {
        self.build_descriptor_sha256
    }

    #[must_use]
    pub const fn system_api_tool_sha256(&self) -> Digest {
        self.system_api_tool_sha256
    }

    #[must_use]
    pub const fn accessibility_tool_sha256(&self) -> Digest {
        self.accessibility_tool_sha256
    }

    #[must_use]
    pub const fn intent_sha256(&self) -> Digest {
        self.intent_sha256
    }

    fn expected_sha256(&self) -> Result<Digest, P0ConformanceIntentError> {
        let mut hasher = Sha256::new();
        hasher.update(b"org.trillionnium.p0-launch-package-device-conformance-intent.v1\0");
        hasher.update([match self.provider {
            Provider::Codex => 1,
        }]);
        hasher.update([match self.product_variant {
            P0ConformanceProductVariant::Userdebug => 1,
            P0ConformanceProductVariant::Eng => 2,
        }]);
        for digest in [
            self.provider_id_sha256,
            self.agent_id_sha256,
            self.build_descriptor_sha256,
            self.permission_model_sha256,
            self.system_api_tool_sha256,
            self.accessibility_tool_sha256,
            self.target_sha256,
        ] {
            hasher.update(digest.value().as_bytes());
        }
        fixed_digest(hasher.finalize().into())
    }
}

fn stable_principal(provider: Provider) -> &'static agent_principal_registry::AgentStablePrincipal {
    match provider {
        Provider::Codex => &agent_principal_registry::CODEX_STABLE_PRINCIPAL,
    }
}

fn target_sha256() -> Result<Digest, P0ConformanceIntentError> {
    let mut hasher = Sha256::new();
    hasher.update(b"org.trillionnium.p0-launch-package-target.v1\0");
    hasher.update(TARGET_ACTION.as_bytes());
    hasher.update([0]);
    hasher.update(TARGET_PACKAGE.as_bytes());
    hasher.update([0]);
    hasher.update(TARGET_ANDROID_USER.to_be_bytes());
    fixed_digest(hasher.finalize().into())
}

fn digest_utf8(value: &[u8]) -> Result<Digest, P0ConformanceIntentError> {
    fixed_digest(Sha256::digest(value).into())
}

fn digest_lower_hex(value: &str) -> Result<Digest, P0ConformanceIntentError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(denied("p0_conformance_digest_denied"));
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    fixed_digest(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, P0ConformanceIntentError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(denied("p0_conformance_digest_denied")),
    }
}

fn fixed_digest(bytes: [u8; 32]) -> Result<Digest, P0ConformanceIntentError> {
    FixedBytes32::new(bytes)
        .map(Digest::new)
        .map_err(|_| denied("p0_conformance_digest_denied"))
}

const fn denied(code: &'static str) -> P0ConformanceIntentError {
    P0ConformanceIntentError(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use trillionnium_os_types::agent_direct_permission_model;
    use trillionnium_os_types::direct_operation::CODEX_PROVIDER_RUNTIME_CGROUP_PATH;
    use trillionnium_os_types::p0_launch_package_device_conformance::{
        BUILD_DESCRIPTOR_SCHEMA, BUILD_DESCRIPTOR_STATUS, P0LaunchPackageConformanceBuildBodyV2,
        REQUIRED_CAPABILITY_POLICY, REQUIRED_DESCENDANT_POLICY, REQUIRED_FD_POLICY,
        REQUIRED_GROUP_POLICY,
    };
    use trillionnium_os_types::provider_post_exec_containment::ProviderRuntimeExecTopologyV1;

    fn sha(seed: u8) -> String {
        let bytes: [u8; 32] = Sha256::digest([seed]).into();
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn descriptor(
        provider: Provider,
        variant: P0ConformanceProductVariant,
    ) -> P0LaunchPackageConformanceBuildDescriptorV2 {
        let principal = stable_principal(provider);
        let active_launcher_identity = sha(12);
        P0LaunchPackageConformanceBuildDescriptorV2::from_source_body(
            P0LaunchPackageConformanceBuildBodyV2 {
                schema: BUILD_DESCRIPTOR_SCHEMA.into(),
                status: BUILD_DESCRIPTOR_STATUS.into(),
                provider_id: principal.provider_id.into(),
                agent_id: principal.agent_id.into(),
                identity_key_sha256: active_launcher_identity.clone(),
                runtime_adapter: principal.runtime_adapter.into(),
                uid: principal.uid,
                gid: principal.gid,
                agent_selinux_domain: principal.agent_selinux_domain.into(),
                product_variant: variant,
                runtime_exec_topology: ProviderRuntimeExecTopologyV1::LauncherThenFinalRuntime,
                permission_model_sha256: PERMISSION_MODEL_SHA256.into(),
                direct_tool_names: [
                    agent_direct_permission_model::DIRECT_AGENT_TOOL_NAMES[0].into(),
                    agent_direct_permission_model::DIRECT_AGENT_TOOL_NAMES[1].into(),
                ],
                action: TARGET_ACTION.into(),
                package: TARGET_PACKAGE.into(),
                android_user: TARGET_ANDROID_USER,
                agent_manifest_sha256: sha(1),
                launcher_executable_sha256: active_launcher_identity,
                final_runtime_executable_sha256: sha(2),
                final_runtime_closure_sha256: sha(3),
                system_api_tool_sha256: sha(4),
                accessibility_tool_sha256: sha(5),
                compiled_selinux_policy_sha256: sha(6),
                cgroup_policy_sha256: sha(7),
                seccomp_filter_sha256: sha(8),
                fd_table_sha256: sha(9),
                supplementary_groups_policy_sha256: sha(10),
                descendant_policy_sha256: sha(11),
                expected_provider_runtime_cgroup_leaf: CODEX_PROVIDER_RUNTIME_CGROUP_PATH.into(),
                permitted_fd_numbers: [0, 1, 2],
                supplementary_groups: vec![],
                fd_policy: REQUIRED_FD_POLICY.into(),
                supplementary_group_policy: REQUIRED_GROUP_POLICY.into(),
                capability_policy: REQUIRED_CAPABILITY_POLICY.into(),
                descendant_policy: REQUIRED_DESCENDANT_POLICY.into(),
                required_no_new_privileges: 1,
                required_dumpable: 0,
                required_seccomp_mode: 2,
                outer_owned_cgroup_supervisor: true,
                zero_survivors_required_before_durable_ack: true,
                local_command_fallback: false,
                product_effect_authority: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn intents_bind_codex_and_variants() {
        for variant in [
            P0ConformanceProductVariant::Userdebug,
            P0ConformanceProductVariant::Eng,
        ] {
            let descriptor = descriptor(Provider::Codex, variant);
            let intent = P0LaunchPackageConformanceIntentV1::from_source_descriptor(
                Provider::Codex,
                &descriptor,
            )
            .unwrap();
            intent.validate().unwrap();
            assert_eq!(intent.product_variant(), variant);
            assert_eq!(
                intent.build_descriptor_sha256(),
                digest_lower_hex(descriptor.descriptor_sha256()).unwrap()
            );
        }
    }

    #[test]
    fn provider_and_every_bound_field_drift_fail_closed() {
        let descriptor = descriptor(Provider::Codex, P0ConformanceProductVariant::Userdebug);
        type Drift = Box<dyn Fn(&mut P0LaunchPackageConformanceIntentV1)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|v| v.schema = "drift".into()),
            Box::new(|v| v.product_variant = P0ConformanceProductVariant::Eng),
            Box::new(|v| v.provider_id_sha256 = digest_utf8(b"drift-provider").unwrap()),
            Box::new(|v| v.agent_id_sha256 = digest_utf8(b"drift-agent").unwrap()),
            Box::new(|v| v.build_descriptor_sha256 = digest_utf8(b"drift-build").unwrap()),
            Box::new(|v| v.permission_model_sha256 = digest_utf8(b"drift-policy").unwrap()),
            Box::new(|v| v.system_api_tool_sha256 = digest_utf8(b"drift-system").unwrap()),
            Box::new(|v| {
                v.accessibility_tool_sha256 = digest_utf8(b"drift-accessibility").unwrap()
            }),
            Box::new(|v| v.target_sha256 = digest_utf8(b"drift-target").unwrap()),
            Box::new(|v| v.intent_sha256 = digest_utf8(b"drift-intent").unwrap()),
        ];
        for drift in drifts {
            let mut intent = P0LaunchPackageConformanceIntentV1::from_source_descriptor(
                Provider::Codex,
                &descriptor,
            )
            .unwrap();
            drift(&mut intent);
            assert!(intent.validate().is_err());
        }
    }

    #[test]
    fn intent_is_not_a_live_request_and_unknown_fields_are_closed() {
        let descriptor = descriptor(Provider::Codex, P0ConformanceProductVariant::Eng);
        let intent = P0LaunchPackageConformanceIntentV1::from_source_descriptor(
            Provider::Codex,
            &descriptor,
        )
        .unwrap();
        let mut value = serde_json::to_value(intent).unwrap();
        value["path"] = serde_json::json!("/data/local/tmp/injected");
        assert!(serde_json::from_value::<P0LaunchPackageConformanceIntentV1>(value).is_err());

        let injected = serde_json::json!({
            "operation": "p0_launch_package_device_conformance",
            "provider": "codex"
        });
        assert!(serde_json::from_value::<crate::Request>(injected).is_err());
    }

    #[test]
    fn status_is_source_only_and_non_authorizing() {
        const {
            assert!(SOURCE_INTENT_CONTRACT_IMPLEMENTED);
            assert!(!LIVE_REQUEST_VARIANT_AVAILABLE);
            assert!(!PRODUCT_MUTATION_ROUTE_AVAILABLE);
            assert!(!CONFERS_EFFECT_AUTHORITY);
        }
    }
}
