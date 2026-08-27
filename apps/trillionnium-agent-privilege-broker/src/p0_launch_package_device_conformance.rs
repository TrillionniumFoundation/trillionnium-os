//! Sealed broker-owned admission contract for the opt-in P0 Settings lane.
//!
//! The feature compiles a type-state seam only.  No concrete build
//! authenticator, kernel launch implementation, socket operation, `main`
//! dispatch, local `Command` fallback, or product authority exists.  Tests use
//! an injected build authenticator; provider custody is the existing affine
//! `BrokerPostExecFullChainCustody`, which retains the exact child, pidfd,
//! cgroup, stdio, policy and reservation handles.

use thiserror::Error;
use trillionnium_os_types::agent_direct_permission_model::PERMISSION_MODEL_SHA256;
use trillionnium_os_types::agent_principal_registry;
use trillionnium_os_types::p0_launch_package_device_conformance::{
    P0ConformanceProductVariant, P0LaunchPackageConformanceBuildDescriptorV2,
};
use trillionnium_os_types::provider_post_exec_containment::{
    P0ConformanceProvisionedRuntimePolicyIdentityV2, ProviderExecEventAuthorityV1,
};
use trillionnium_privilege_broker_protocol::p0_launch_package_device_conformance::P0LaunchPackageConformanceIntentV1;
use trillionnium_privilege_broker_protocol::{Digest, FixedBytes32, Provider};

use crate::provider_launch_custody::{BrokerPostExecFullChainCustody, ProviderLaunchCustodyOps};

pub(crate) const SOURCE_SEALED_BUILD_AUTHENTICATION_TYPESTATE_IMPLEMENTED: bool = true;
pub(crate) const SOURCE_BROKER_OWNED_PROVIDER_ADMISSION_IMPLEMENTED: bool = true;
pub(crate) const CONCRETE_BUILD_AUTHENTICATOR_AVAILABLE: bool = false;
pub(crate) const CONCRETE_PROVIDER_LAUNCHER_AVAILABLE: bool = false;
pub(crate) const LIVE_BROKER_ROUTE_AVAILABLE: bool = false;
pub(crate) const PRODUCT_EFFECT_AUTHORITY_AVAILABLE: bool = false;
pub(crate) const LOCAL_COMMAND_FALLBACK_AVAILABLE: bool = false;

/// Exact build facts that a future root/AVB-owned authenticator must observe.
/// Data supplied by a daemon or provider cannot implement the private trait
/// below and therefore cannot mint authenticated build custody.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct P0ConformanceBuildAuthenticationObservation {
    provider: Provider,
    product_variant: P0ConformanceProductVariant,
    descriptor_sha256: Digest,
    permission_model_sha256: Digest,
    agent_manifest_sha256: Digest,
    launcher_executable_sha256: Digest,
    final_runtime_executable_sha256: Digest,
    final_runtime_closure_sha256: Digest,
    system_api_tool_sha256: Digest,
    accessibility_tool_sha256: Digest,
    compiled_selinux_policy_sha256: Digest,
    cgroup_policy_sha256: Digest,
    seccomp_filter_sha256: Digest,
    fd_table_sha256: Digest,
    supplementary_groups_policy_sha256: Digest,
    descendant_policy_sha256: Digest,
    policy_authority_identity_sha256: Digest,
    policy_store_instance_sha256: Digest,
    system_image_sha256: Digest,
    avb_chain_sha256: Digest,
    boot_id_sha256: Digest,
    provisioning_manifest_sha256: Digest,
    provision_epoch_sha256: Digest,
    fixed_cgroup_inventory_sha256: Digest,
    cgroup_directory_ancestry_sha256: Digest,
    provider_runtime_leaf_binding_sha256: Digest,
    expected_exec_event_authority: ProviderExecEventAuthorityV1,
    permitted_argv_sha256: Digest,
    permitted_environment_sha256: Digest,
    policy_anchor_sha256: Digest,
    signed_descriptor_verified: bool,
    artifact_bytes_verified: bool,
    avb_bound: bool,
    runtime_policy_anchor_authenticated: bool,
    policy_store_rollback_resistant: bool,
    boot_identity_authenticated: bool,
    cgroup_provenance_authenticated: bool,
    exec_authority_authenticated: bool,
    product_variant_bound_to_system_image_and_avb: bool,
    provisioning_manifest_binds_descriptor_and_artifact_pins: bool,
    compiled_selinux_policy_bound_to_system_image: bool,
    system_api_tool_bound_to_system_image: bool,
    accessibility_tool_bound_to_system_image: bool,
    user_product_absence_proven: bool,
    source_only_conformance_build: bool,
    product_effect_authority_disabled: bool,
}

/// Private typed join between a trusted build observation and the complete
/// per-boot runtime policy identity. It is retained with build custody and is
/// never reconstructed from the caller intent or static descriptor.
#[derive(Debug, Eq, PartialEq)]
struct AuthenticatedP0ConformanceRuntimeBuildJoin {
    observation: P0ConformanceBuildAuthenticationObservation,
}

/// Injected authentication seam. There is intentionally no implementation in
/// non-test source and no constructor from a serialized record.
pub(crate) trait P0ConformanceBuildAuthenticationOps {
    type Custody;

    fn authenticate_exact_build(
        &mut self,
        descriptor: &P0LaunchPackageConformanceBuildDescriptorV2,
    ) -> Result<
        (Self::Custody, P0ConformanceBuildAuthenticationObservation),
        P0ConformanceAdmissionError,
    >;
}

#[must_use = "authenticated build custody must remain owned by broker admission"]
pub(crate) struct AuthenticatedP0ConformanceBuild<Custody> {
    descriptor: P0LaunchPackageConformanceBuildDescriptorV2,
    runtime_build_join: AuthenticatedP0ConformanceRuntimeBuildJoin,
    _authority_custody: Custody,
}

/// Opaque affine admission. It retains both build authority custody and the
/// existing complete post-exec held-child custody. It has no release method,
/// process-start method, or Android-effect authority.
#[must_use = "broker-owned P0 admission must remain in its source-only custody chain"]
pub(crate) struct P0ConformanceProviderLaunchAdmission<BuildCustody, LaunchOps>
where
    LaunchOps: ProviderLaunchCustodyOps,
{
    _authenticated_build: AuthenticatedP0ConformanceBuild<BuildCustody>,
    _post_exec_full_chain: BrokerPostExecFullChainCustody<LaunchOps>,
    provider: Provider,
    product_variant: P0ConformanceProductVariant,
    intent_sha256: Digest,
}

impl<BuildCustody, LaunchOps> P0ConformanceProviderLaunchAdmission<BuildCustody, LaunchOps>
where
    LaunchOps: ProviderLaunchCustodyOps,
{
    #[must_use]
    pub(crate) const fn provider(&self) -> Provider {
        self.provider
    }

    #[must_use]
    pub(crate) const fn product_variant(&self) -> P0ConformanceProductVariant {
        self.product_variant
    }

    #[must_use]
    pub(crate) const fn intent_sha256(&self) -> Digest {
        self.intent_sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum P0ConformanceAdmissionError {
    #[error("P0 conformance build descriptor is invalid")]
    BuildDescriptorInvalid,
    #[error("P0 conformance build authentication is unavailable or inconsistent")]
    BuildAuthenticationDenied,
    #[error("P0 conformance intent is invalid or cross-bound")]
    IntentDenied,
    #[error("P0 conformance full post-exec child custody is inconsistent")]
    FullChainCustodyDenied,
    #[error("P0 conformance digest is malformed")]
    DigestDenied,
}

pub(crate) fn authenticate_p0_conformance_build<Ops>(
    descriptor: P0LaunchPackageConformanceBuildDescriptorV2,
    ops: &mut Ops,
) -> Result<AuthenticatedP0ConformanceBuild<Ops::Custody>, P0ConformanceAdmissionError>
where
    Ops: P0ConformanceBuildAuthenticationOps,
{
    descriptor
        .validate()
        .map_err(|_| P0ConformanceAdmissionError::BuildDescriptorInvalid)?;
    let (custody, observation) = ops.authenticate_exact_build(&descriptor)?;
    if !build_observation_matches_descriptor(&observation, &descriptor)? {
        return Err(P0ConformanceAdmissionError::BuildAuthenticationDenied);
    }
    Ok(AuthenticatedP0ConformanceBuild {
        descriptor,
        runtime_build_join: AuthenticatedP0ConformanceRuntimeBuildJoin { observation },
        _authority_custody: custody,
    })
}

pub(crate) fn admit_p0_conformance_held_provider<BuildCustody, LaunchOps>(
    authenticated_build: AuthenticatedP0ConformanceBuild<BuildCustody>,
    intent: &P0LaunchPackageConformanceIntentV1,
    full_chain: BrokerPostExecFullChainCustody<LaunchOps>,
) -> Result<
    P0ConformanceProviderLaunchAdmission<BuildCustody, LaunchOps>,
    P0ConformanceAdmissionError,
>
where
    LaunchOps: ProviderLaunchCustodyOps,
{
    intent
        .validate()
        .map_err(|_| P0ConformanceAdmissionError::IntentDenied)?;
    let descriptor = &authenticated_build.descriptor;
    let body = descriptor.body();
    let provider = provider_for_body(descriptor)?;
    let product_variant = body.product_variant;
    let runtime_policy_matches = full_chain
        .p0_conformance_runtime_policy_identity()
        .is_some_and(|runtime_policy| {
            authenticated_build
                .runtime_build_join
                .matches_retained_policy(descriptor, runtime_policy)
                .unwrap_or(false)
        });
    if intent.provider() != provider
        || intent.product_variant() != body.product_variant
        || intent.build_descriptor_sha256() != digest_lower_hex(descriptor.descriptor_sha256())?
        || intent.system_api_tool_sha256() != digest_lower_hex(&body.system_api_tool_sha256)?
        || intent.accessibility_tool_sha256() != digest_lower_hex(&body.accessibility_tool_sha256)?
        || !runtime_policy_matches
    {
        return Err(P0ConformanceAdmissionError::FullChainCustodyDenied);
    }
    Ok(P0ConformanceProviderLaunchAdmission {
        _authenticated_build: authenticated_build,
        _post_exec_full_chain: full_chain,
        provider,
        product_variant,
        intent_sha256: intent.intent_sha256(),
    })
}

impl AuthenticatedP0ConformanceRuntimeBuildJoin {
    fn matches_retained_policy(
        &self,
        descriptor: &P0LaunchPackageConformanceBuildDescriptorV2,
        policy: P0ConformanceProvisionedRuntimePolicyIdentityV2<'_>,
    ) -> Result<bool, P0ConformanceAdmissionError> {
        let observation = &self.observation;
        let body = descriptor.body();
        Ok(
            build_observation_matches_descriptor(observation, descriptor)?
                && policy.provider_id() == body.provider_id
                && policy.agent_id() == body.agent_id
                && policy.runtime_exec_topology() == body.runtime_exec_topology
                && policy.agent_identity_key_sha256() == body.identity_key_sha256
                && policy.agent_manifest_sha256() == body.agent_manifest_sha256
                && digest_lower_hex(policy.policy_authority_identity_sha256())?
                    == observation.policy_authority_identity_sha256
                && digest_lower_hex(policy.policy_store_instance_sha256())?
                    == observation.policy_store_instance_sha256
                && digest_lower_hex(policy.system_image_sha256())?
                    == observation.system_image_sha256
                && digest_lower_hex(policy.avb_chain_sha256())? == observation.avb_chain_sha256
                && digest_lower_hex(policy.boot_id_sha256())? == observation.boot_id_sha256
                && digest_lower_hex(policy.provisioning_manifest_sha256())?
                    == observation.provisioning_manifest_sha256
                && digest_lower_hex(policy.provision_epoch_sha256())?
                    == observation.provision_epoch_sha256
                && policy.launcher_executable_sha256() == body.launcher_executable_sha256
                && policy.final_runtime_executable_sha256() == body.final_runtime_executable_sha256
                && policy.final_runtime_closure_sha256() == body.final_runtime_closure_sha256
                && policy.expected_uid() == body.uid
                && policy.expected_gid() == body.gid
                && policy.expected_selinux_domain() == body.agent_selinux_domain
                && policy.expected_provider_runtime_cgroup_leaf()
                    == body.expected_provider_runtime_cgroup_leaf
                && digest_lower_hex(policy.fixed_cgroup_inventory_sha256())?
                    == observation.fixed_cgroup_inventory_sha256
                && digest_lower_hex(policy.cgroup_directory_ancestry_sha256())?
                    == observation.cgroup_directory_ancestry_sha256
                && digest_lower_hex(policy.provider_runtime_leaf_binding_sha256())?
                    == observation.provider_runtime_leaf_binding_sha256
                && policy.provider_cgroup_policy_sha256() == body.cgroup_policy_sha256
                && policy.expected_exec_event_authority()
                    == observation.expected_exec_event_authority
                && policy.post_exec_seccomp_filter_sha256() == body.seccomp_filter_sha256
                && digest_lower_hex(policy.permitted_argv_sha256())?
                    == observation.permitted_argv_sha256
                && digest_lower_hex(policy.permitted_environment_sha256())?
                    == observation.permitted_environment_sha256
                && policy.permitted_fd_table_sha256() == body.fd_table_sha256
                && policy.permitted_supplementary_groups_sha256()
                    == body.supplementary_groups_policy_sha256
                && policy.permitted_descendant_closure_sha256() == body.descendant_policy_sha256
                && digest_lower_hex(policy.policy_anchor_sha256())?
                    == observation.policy_anchor_sha256,
        )
    }
}

fn build_observation_matches_descriptor(
    observation: &P0ConformanceBuildAuthenticationObservation,
    descriptor: &P0LaunchPackageConformanceBuildDescriptorV2,
) -> Result<bool, P0ConformanceAdmissionError> {
    let body = descriptor.body();
    let provider = provider_for_body(descriptor)?;
    Ok(observation.provider == provider
        && observation.product_variant == body.product_variant
        && observation.descriptor_sha256 == digest_lower_hex(descriptor.descriptor_sha256())?
        && observation.permission_model_sha256 == digest_lower_hex(PERMISSION_MODEL_SHA256)?
        && observation.agent_manifest_sha256 == digest_lower_hex(&body.agent_manifest_sha256)?
        && observation.launcher_executable_sha256
            == digest_lower_hex(&body.launcher_executable_sha256)?
        && observation.final_runtime_executable_sha256
            == digest_lower_hex(&body.final_runtime_executable_sha256)?
        && observation.final_runtime_closure_sha256
            == digest_lower_hex(&body.final_runtime_closure_sha256)?
        && observation.system_api_tool_sha256 == digest_lower_hex(&body.system_api_tool_sha256)?
        && observation.accessibility_tool_sha256
            == digest_lower_hex(&body.accessibility_tool_sha256)?
        && observation.compiled_selinux_policy_sha256
            == digest_lower_hex(&body.compiled_selinux_policy_sha256)?
        && observation.cgroup_policy_sha256 == digest_lower_hex(&body.cgroup_policy_sha256)?
        && observation.seccomp_filter_sha256 == digest_lower_hex(&body.seccomp_filter_sha256)?
        && observation.fd_table_sha256 == digest_lower_hex(&body.fd_table_sha256)?
        && observation.supplementary_groups_policy_sha256
            == digest_lower_hex(&body.supplementary_groups_policy_sha256)?
        && observation.descendant_policy_sha256
            == digest_lower_hex(&body.descendant_policy_sha256)?
        && all_nonzero_distinct(&[
            observation.policy_authority_identity_sha256,
            observation.policy_store_instance_sha256,
            observation.system_image_sha256,
            observation.avb_chain_sha256,
            observation.boot_id_sha256,
            observation.provisioning_manifest_sha256,
            observation.provision_epoch_sha256,
            observation.fixed_cgroup_inventory_sha256,
            observation.cgroup_directory_ancestry_sha256,
            observation.provider_runtime_leaf_binding_sha256,
            observation.permitted_argv_sha256,
            observation.permitted_environment_sha256,
            observation.policy_anchor_sha256,
        ])
        && observation.signed_descriptor_verified
        && observation.artifact_bytes_verified
        && observation.avb_bound
        && observation.runtime_policy_anchor_authenticated
        && observation.policy_store_rollback_resistant
        && observation.boot_identity_authenticated
        && observation.cgroup_provenance_authenticated
        && observation.exec_authority_authenticated
        && observation.product_variant_bound_to_system_image_and_avb
        && observation.provisioning_manifest_binds_descriptor_and_artifact_pins
        && observation.compiled_selinux_policy_bound_to_system_image
        && observation.system_api_tool_bound_to_system_image
        && observation.accessibility_tool_bound_to_system_image
        && observation.user_product_absence_proven
        && observation.source_only_conformance_build
        && observation.product_effect_authority_disabled)
}

fn provider_for_body(
    descriptor: &P0LaunchPackageConformanceBuildDescriptorV2,
) -> Result<Provider, P0ConformanceAdmissionError> {
    let body = descriptor.body();
    if body.provider_id == agent_principal_registry::CODEX_STABLE_PRINCIPAL.provider_id
        && body.agent_id == agent_principal_registry::CODEX_STABLE_PRINCIPAL.agent_id
    {
        Ok(Provider::Codex)
    } else {
        Err(P0ConformanceAdmissionError::BuildDescriptorInvalid)
    }
}

fn all_nonzero_distinct(values: &[Digest]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}

fn digest_lower_hex(value: &str) -> Result<Digest, P0ConformanceAdmissionError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(P0ConformanceAdmissionError::DigestDenied);
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    FixedBytes32::new(bytes)
        .map(Digest::new)
        .map_err(|_| P0ConformanceAdmissionError::DigestDenied)
}

fn hex_nibble(byte: u8) -> Result<u8, P0ConformanceAdmissionError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(P0ConformanceAdmissionError::DigestDenied),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn digest(seed: u8) -> Digest {
        Digest::new(FixedBytes32::new(Sha256::digest([seed]).into()).unwrap())
    }

    fn build_observation(
        provider: Provider,
        descriptor: &P0LaunchPackageConformanceBuildDescriptorV2,
        policy: P0ConformanceProvisionedRuntimePolicyIdentityV2<'_>,
    ) -> P0ConformanceBuildAuthenticationObservation {
        let body = descriptor.body();
        P0ConformanceBuildAuthenticationObservation {
            provider,
            product_variant: body.product_variant,
            descriptor_sha256: digest_lower_hex(descriptor.descriptor_sha256()).unwrap(),
            permission_model_sha256: digest_lower_hex(PERMISSION_MODEL_SHA256).unwrap(),
            agent_manifest_sha256: digest_lower_hex(&body.agent_manifest_sha256).unwrap(),
            launcher_executable_sha256: digest_lower_hex(&body.launcher_executable_sha256).unwrap(),
            final_runtime_executable_sha256: digest_lower_hex(
                &body.final_runtime_executable_sha256,
            )
            .unwrap(),
            final_runtime_closure_sha256: digest_lower_hex(&body.final_runtime_closure_sha256)
                .unwrap(),
            system_api_tool_sha256: digest_lower_hex(&body.system_api_tool_sha256).unwrap(),
            accessibility_tool_sha256: digest_lower_hex(&body.accessibility_tool_sha256).unwrap(),
            compiled_selinux_policy_sha256: digest_lower_hex(&body.compiled_selinux_policy_sha256)
                .unwrap(),
            cgroup_policy_sha256: digest_lower_hex(&body.cgroup_policy_sha256).unwrap(),
            seccomp_filter_sha256: digest_lower_hex(&body.seccomp_filter_sha256).unwrap(),
            fd_table_sha256: digest_lower_hex(&body.fd_table_sha256).unwrap(),
            supplementary_groups_policy_sha256: digest_lower_hex(
                &body.supplementary_groups_policy_sha256,
            )
            .unwrap(),
            descendant_policy_sha256: digest_lower_hex(&body.descendant_policy_sha256).unwrap(),
            policy_authority_identity_sha256: digest_lower_hex(
                policy.policy_authority_identity_sha256(),
            )
            .unwrap(),
            policy_store_instance_sha256: digest_lower_hex(policy.policy_store_instance_sha256())
                .unwrap(),
            system_image_sha256: digest_lower_hex(policy.system_image_sha256()).unwrap(),
            avb_chain_sha256: digest_lower_hex(policy.avb_chain_sha256()).unwrap(),
            boot_id_sha256: digest_lower_hex(policy.boot_id_sha256()).unwrap(),
            provisioning_manifest_sha256: digest_lower_hex(policy.provisioning_manifest_sha256())
                .unwrap(),
            provision_epoch_sha256: digest_lower_hex(policy.provision_epoch_sha256()).unwrap(),
            fixed_cgroup_inventory_sha256: digest_lower_hex(policy.fixed_cgroup_inventory_sha256())
                .unwrap(),
            cgroup_directory_ancestry_sha256: digest_lower_hex(
                policy.cgroup_directory_ancestry_sha256(),
            )
            .unwrap(),
            provider_runtime_leaf_binding_sha256: digest_lower_hex(
                policy.provider_runtime_leaf_binding_sha256(),
            )
            .unwrap(),
            expected_exec_event_authority: policy.expected_exec_event_authority(),
            permitted_argv_sha256: digest_lower_hex(policy.permitted_argv_sha256()).unwrap(),
            permitted_environment_sha256: digest_lower_hex(policy.permitted_environment_sha256())
                .unwrap(),
            policy_anchor_sha256: digest_lower_hex(policy.policy_anchor_sha256()).unwrap(),
            signed_descriptor_verified: true,
            artifact_bytes_verified: true,
            avb_bound: true,
            runtime_policy_anchor_authenticated: true,
            policy_store_rollback_resistant: true,
            boot_identity_authenticated: true,
            cgroup_provenance_authenticated: true,
            exec_authority_authenticated: true,
            product_variant_bound_to_system_image_and_avb: true,
            provisioning_manifest_binds_descriptor_and_artifact_pins: true,
            compiled_selinux_policy_bound_to_system_image: true,
            system_api_tool_bound_to_system_image: true,
            accessibility_tool_bound_to_system_image: true,
            user_product_absence_proven: true,
            source_only_conformance_build: true,
            product_effect_authority_disabled: true,
        }
    }

    struct TestCustody;

    struct FakeAuthenticator {
        observation: Option<P0ConformanceBuildAuthenticationObservation>,
    }

    impl P0ConformanceBuildAuthenticationOps for FakeAuthenticator {
        type Custody = TestCustody;

        fn authenticate_exact_build(
            &mut self,
            _descriptor: &P0LaunchPackageConformanceBuildDescriptorV2,
        ) -> Result<
            (Self::Custody, P0ConformanceBuildAuthenticationObservation),
            P0ConformanceAdmissionError,
        > {
            Ok((
                TestCustody,
                self.observation
                    .take()
                    .ok_or(P0ConformanceAdmissionError::BuildAuthenticationDenied)?,
            ))
        }
    }

    fn authenticate<LaunchOps: ProviderLaunchCustodyOps>(
        provider: Provider,
        descriptor: P0LaunchPackageConformanceBuildDescriptorV2,
        full_chain: &BrokerPostExecFullChainCustody<LaunchOps>,
    ) -> AuthenticatedP0ConformanceBuild<TestCustody> {
        let policy = full_chain.p0_conformance_runtime_policy_identity().unwrap();
        let observation = build_observation(provider, &descriptor, policy);
        authenticate_p0_conformance_build(
            descriptor,
            &mut FakeAuthenticator {
                observation: Some(observation),
            },
        )
        .unwrap()
    }

    #[test]
    fn codex_engineering_variants_reach_only_sealed_admission_and_drop_once() {
        for variant in [
            P0ConformanceProductVariant::Userdebug,
            P0ConformanceProductVariant::Eng,
        ] {
            let provider = Provider::Codex;
            let (full_chain, descriptor, cleanup) =
                crate::provider_launch_custody::tests::p0_full_chain_descriptor_and_probe_for_test(
                    provider, variant,
                );
            let intent =
                P0LaunchPackageConformanceIntentV1::from_source_descriptor(provider, &descriptor)
                    .unwrap();
            let authenticated_build = authenticate(provider, descriptor, &full_chain);
            let admission =
                admit_p0_conformance_held_provider(authenticated_build, &intent, full_chain)
                    .unwrap();
            assert_eq!(admission.provider(), provider);
            assert_eq!(admission.product_variant(), variant);
            assert_eq!(admission.intent_sha256(), intent.intent_sha256());
            assert_eq!(cleanup.cleanup_calls(), 0);
            assert_eq!(cleanup.release_calls(), 0);
            drop(admission);
            assert_eq!(cleanup.cleanup_calls(), 1);
            assert_eq!(cleanup.release_calls(), 0);
        }
    }

    #[test]
    fn every_build_authentication_fact_drift_is_denied() {
        type Drift = Box<dyn Fn(&mut P0ConformanceBuildAuthenticationObservation)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|v| v.product_variant = P0ConformanceProductVariant::Eng),
            Box::new(|v| v.descriptor_sha256 = digest(20)),
            Box::new(|v| v.permission_model_sha256 = digest(21)),
            Box::new(|v| v.agent_manifest_sha256 = digest(22)),
            Box::new(|v| v.launcher_executable_sha256 = digest(23)),
            Box::new(|v| v.final_runtime_executable_sha256 = digest(24)),
            Box::new(|v| v.final_runtime_closure_sha256 = digest(25)),
            Box::new(|v| v.system_api_tool_sha256 = digest(26)),
            Box::new(|v| v.accessibility_tool_sha256 = digest(27)),
            Box::new(|v| v.compiled_selinux_policy_sha256 = digest(28)),
            Box::new(|v| v.cgroup_policy_sha256 = digest(29)),
            Box::new(|v| v.seccomp_filter_sha256 = digest(30)),
            Box::new(|v| v.fd_table_sha256 = digest(31)),
            Box::new(|v| v.supplementary_groups_policy_sha256 = digest(32)),
            Box::new(|v| v.descendant_policy_sha256 = digest(33)),
            Box::new(|v| v.signed_descriptor_verified = false),
            Box::new(|v| v.artifact_bytes_verified = false),
            Box::new(|v| v.avb_bound = false),
            Box::new(|v| v.runtime_policy_anchor_authenticated = false),
            Box::new(|v| v.policy_store_rollback_resistant = false),
            Box::new(|v| v.boot_identity_authenticated = false),
            Box::new(|v| v.cgroup_provenance_authenticated = false),
            Box::new(|v| v.exec_authority_authenticated = false),
            Box::new(|v| v.product_variant_bound_to_system_image_and_avb = false),
            Box::new(|v| v.provisioning_manifest_binds_descriptor_and_artifact_pins = false),
            Box::new(|v| v.compiled_selinux_policy_bound_to_system_image = false),
            Box::new(|v| v.system_api_tool_bound_to_system_image = false),
            Box::new(|v| v.accessibility_tool_bound_to_system_image = false),
            Box::new(|v| v.user_product_absence_proven = false),
            Box::new(|v| v.source_only_conformance_build = false),
            Box::new(|v| v.product_effect_authority_disabled = false),
        ];
        for (drift_index, drift) in drifts.into_iter().enumerate() {
            let (full_chain, descriptor, cleanup) =
                crate::provider_launch_custody::tests::p0_full_chain_descriptor_and_probe_for_test(
                    Provider::Codex,
                    P0ConformanceProductVariant::Userdebug,
                );
            let policy = full_chain.p0_conformance_runtime_policy_identity().unwrap();
            let mut observation = build_observation(Provider::Codex, &descriptor, policy);
            drift(&mut observation);
            let result = authenticate_p0_conformance_build(
                descriptor,
                &mut FakeAuthenticator {
                    observation: Some(observation),
                },
            );
            assert!(result.is_err(), "build drift {drift_index} was accepted");
            assert_eq!(cleanup.cleanup_calls(), 0);
            drop(full_chain);
            assert_eq!(cleanup.cleanup_calls(), 1);
            assert_eq!(cleanup.release_calls(), 0);
        }
    }

    #[test]
    fn authenticated_runtime_build_join_retains_every_per_boot_observation() {
        type Drift = Box<dyn Fn(&mut P0ConformanceBuildAuthenticationObservation)>;
        let drifts: Vec<Drift> = vec![
            Box::new(|v| v.policy_authority_identity_sha256 = digest(34)),
            Box::new(|v| v.policy_store_instance_sha256 = digest(35)),
            Box::new(|v| v.system_image_sha256 = digest(36)),
            Box::new(|v| v.avb_chain_sha256 = digest(37)),
            Box::new(|v| v.boot_id_sha256 = digest(38)),
            Box::new(|v| v.provisioning_manifest_sha256 = digest(39)),
            Box::new(|v| v.provision_epoch_sha256 = digest(40)),
            Box::new(|v| v.fixed_cgroup_inventory_sha256 = digest(41)),
            Box::new(|v| v.cgroup_directory_ancestry_sha256 = digest(42)),
            Box::new(|v| v.provider_runtime_leaf_binding_sha256 = digest(43)),
            Box::new(|v| {
                v.expected_exec_event_authority =
                    ProviderExecEventAuthorityV1::PrivilegeBrokerSeccompExecNotification;
            }),
            Box::new(|v| v.permitted_argv_sha256 = digest(44)),
            Box::new(|v| v.permitted_environment_sha256 = digest(45)),
            Box::new(|v| v.policy_anchor_sha256 = digest(46)),
        ];
        for (drift_index, drift) in drifts.into_iter().enumerate() {
            let (full_chain, descriptor, cleanup) =
                crate::provider_launch_custody::tests::p0_full_chain_descriptor_and_probe_for_test(
                    Provider::Codex,
                    P0ConformanceProductVariant::Userdebug,
                );
            let policy = full_chain.p0_conformance_runtime_policy_identity().unwrap();
            let mut observation = build_observation(Provider::Codex, &descriptor, policy);
            drift(&mut observation);
            let authenticated_build = authenticate_p0_conformance_build(
                descriptor.clone(),
                &mut FakeAuthenticator {
                    observation: Some(observation),
                },
            )
            .unwrap_or_else(|error| {
                panic!("trusted runtime observation drift {drift_index} was not retained: {error}")
            });
            let intent = P0LaunchPackageConformanceIntentV1::from_source_descriptor(
                Provider::Codex,
                &descriptor,
            )
            .unwrap();
            assert!(
                admit_p0_conformance_held_provider(authenticated_build, &intent, full_chain)
                    .is_err(),
                "retained runtime observation drift {drift_index} cross-spliced"
            );
            assert_eq!(cleanup.cleanup_calls(), 1);
            assert_eq!(cleanup.release_calls(), 0);
        }
    }

    #[test]
    fn independently_valid_build_and_full_chain_cross_splices_fail_closed_once() {
        use crate::provider_launch_custody::tests::P0FullChainPolicyDriftForTest as Drift;

        let drifts = [
            Drift::PolicyAuthority,
            Drift::PolicyStore,
            Drift::SystemImage,
            Drift::AvbChain,
            Drift::BootId,
            Drift::ProvisioningManifest,
            Drift::ProvisionEpoch,
            Drift::FixedCgroupInventory,
            Drift::CgroupDirectoryAncestry,
            Drift::ProviderRuntimeLeafBinding,
            Drift::ProviderCgroupPolicy,
            Drift::ExecEventAuthority,
            Drift::Argv,
            Drift::Environment,
            Drift::CompiledSelinuxAndImage,
            Drift::SystemApiToolAndImage,
            Drift::AccessibilityToolAndImage,
        ];
        for drift in drifts {
            let (build_full_chain, build_descriptor, build_cleanup) =
                crate::provider_launch_custody::tests::p0_full_chain_descriptor_and_probe_for_test(
                    Provider::Codex,
                    P0ConformanceProductVariant::Userdebug,
                );
            let authenticated_build =
                authenticate(Provider::Codex, build_descriptor.clone(), &build_full_chain);
            let intent = P0LaunchPackageConformanceIntentV1::from_source_descriptor(
                Provider::Codex,
                &build_descriptor,
            )
            .unwrap();
            let build_policy_anchor = build_full_chain
                .p0_conformance_runtime_policy_identity()
                .unwrap()
                .policy_anchor_sha256()
                .to_string();
            drop(build_full_chain);
            assert_eq!(build_cleanup.cleanup_calls(), 1);

            let (drifted_full_chain, drifted_descriptor, drifted_cleanup) =
                crate::provider_launch_custody::tests::p0_full_chain_with_policy_drift_for_test(
                    Provider::Codex,
                    P0ConformanceProductVariant::Userdebug,
                    drift,
                );
            // The other side is independently authenticatable and its complete
            // chain was validated before composition; it is not malformed data.
            drop(authenticate(
                Provider::Codex,
                drifted_descriptor.clone(),
                &drifted_full_chain,
            ));
            let drifted_policy_anchor = drifted_full_chain
                .p0_conformance_runtime_policy_identity()
                .unwrap()
                .policy_anchor_sha256()
                .to_string();
            assert_ne!(build_policy_anchor, drifted_policy_anchor);
            match drift {
                Drift::CompiledSelinuxAndImage => assert_ne!(
                    build_descriptor.body().compiled_selinux_policy_sha256,
                    drifted_descriptor.body().compiled_selinux_policy_sha256
                ),
                Drift::SystemApiToolAndImage => assert_ne!(
                    build_descriptor.body().system_api_tool_sha256,
                    drifted_descriptor.body().system_api_tool_sha256
                ),
                Drift::AccessibilityToolAndImage => assert_ne!(
                    build_descriptor.body().accessibility_tool_sha256,
                    drifted_descriptor.body().accessibility_tool_sha256
                ),
                _ => {}
            }
            assert!(
                admit_p0_conformance_held_provider(
                    authenticated_build,
                    &intent,
                    drifted_full_chain,
                )
                .is_err()
            );
            assert_eq!(drifted_cleanup.cleanup_calls(), 1);
            assert_eq!(drifted_cleanup.release_calls(), 0);
        }
    }

    #[test]
    fn userdebug_eng_cross_splices_are_rejected_between_valid_custodies() {
        let (userdebug_chain, userdebug_descriptor, userdebug_cleanup) =
            crate::provider_launch_custody::tests::p0_full_chain_descriptor_and_probe_for_test(
                Provider::Codex,
                P0ConformanceProductVariant::Userdebug,
            );
        let authenticated = authenticate(
            Provider::Codex,
            userdebug_descriptor.clone(),
            &userdebug_chain,
        );
        let intent = P0LaunchPackageConformanceIntentV1::from_source_descriptor(
            Provider::Codex,
            &userdebug_descriptor,
        )
        .unwrap();
        drop(userdebug_chain);
        assert_eq!(userdebug_cleanup.cleanup_calls(), 1);
        let (eng_chain, eng_descriptor, eng_cleanup) =
            crate::provider_launch_custody::tests::p0_full_chain_descriptor_and_probe_for_test(
                Provider::Codex,
                P0ConformanceProductVariant::Eng,
            );
        drop(authenticate(Provider::Codex, eng_descriptor, &eng_chain));
        assert!(admit_p0_conformance_held_provider(authenticated, &intent, eng_chain).is_err());
        assert_eq!(eng_cleanup.cleanup_calls(), 1);
        assert_eq!(eng_cleanup.release_calls(), 0);
    }

    #[test]
    fn feature_has_no_default_product_or_command_reachability() {
        let cargo = include_str!("../Cargo.toml");
        let library = include_str!("lib.rs");
        let main = include_str!("main.rs");
        let protocol =
            include_str!("../../../crates/trillionnium-privilege-broker-protocol/src/lib.rs");
        let source = include_str!("p0_launch_package_device_conformance.rs");
        let production = include_str!("production_effect_wiring.rs");

        assert!(cargo.contains("default = []"));
        assert!(library.contains("#[cfg(feature = \"p0-launch-package-device-conformance\")]"));
        assert!(!main.contains("p0_launch_package_device_conformance"));
        assert!(!main.contains("P0ConformanceProviderLaunchAdmission"));
        let request_enum = protocol
            .split("pub enum Request {")
            .nth(1)
            .and_then(|tail| tail.split("impl Request").next())
            .expect("closed Request enum source");
        assert!(!request_enum.contains("P0LaunchPackage"));
        let process_namespace = ["std", "::process"].concat();
        let command_constructor = ["Command", "::new"].concat();
        assert!(!source.contains(&process_namespace));
        assert!(!source.contains(&command_constructor));
        assert!(source.contains("runtime_build_join: AuthenticatedP0ConformanceRuntimeBuildJoin"));
        assert!(source.contains("matches_retained_policy(descriptor, runtime_policy)"));
        assert!(production.contains("PRODUCT_FIXED_CGROUP_PROVENANCE_AVAILABLE: bool = false"));
        assert!(production.contains("PRODUCT_OUTER_RECEIPT_PUBLISHER_AVAILABLE: bool = false"));
        const {
            assert!(!CONCRETE_BUILD_AUTHENTICATOR_AVAILABLE);
            assert!(!CONCRETE_PROVIDER_LAUNCHER_AVAILABLE);
            assert!(!LIVE_BROKER_ROUTE_AVAILABLE);
            assert!(!PRODUCT_EFFECT_AUTHORITY_AVAILABLE);
            assert!(!LOCAL_COMMAND_FALLBACK_AVAILABLE);
        }
    }
}
