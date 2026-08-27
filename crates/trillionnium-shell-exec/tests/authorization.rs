use trillionnium_os_types::agent_descriptor_registry;
use trillionnium_os_types::direct_effect::{
    DirectEffectExecutionProfileV1, DirectEffectModelArgumentsV1,
};
use trillionnium_os_types::direct_operation::{
    BINDING_SCHEMA, DirectOperationAuthorizedAdapterSetV3, DirectOperationBinding,
    DirectOperationProviderAttempt, DirectOperationStableSeed, STABLE_SEED_SCHEMA,
};
use trillionnium_shell_exec::authorization::{
    ShellExecAuthorizationRegistryV1, ShellExecHostRegistrationV1, ShellExecHostRetirementV1,
    ShellExecRequestAdmissionV1,
};

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn binding() -> DirectOperationBinding {
    let stable_seed = DirectOperationStableSeed {
        schema: STABLE_SEED_SCHEMA.to_string(),
        provider_id: agent_descriptor_registry::CODEX.provider_id.to_string(),
        agent_id: agent_descriptor_registry::CODEX.agent_id.to_string(),
        task_id: "shell-authorization-test".to_string(),
        provider_invocation_id_sha256: digest('1'),
        provider_session_id_sha256: digest('2'),
        subject_uid: 20_000,
        subject_selinux_domain_sha256: digest('3'),
    };
    let invocation_id = stable_seed.invocation_id().unwrap();
    let attempt = DirectOperationProviderAttempt::derive(digest('4'), 1, digest('5')).unwrap();
    let value = DirectOperationBinding {
        schema: BINDING_SCHEMA.to_string(),
        stable_seed,
        invocation_id,
        workflow_id_sha256: digest('6'),
        agent_identity_key_sha256: digest('7'),
        agent_executable_sha256: digest('8'),
        authorized_adapter_set: DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
        attempt,
    };
    value.validate().unwrap();
    value
}

fn arguments(value: &str) -> DirectEffectModelArgumentsV1 {
    DirectEffectModelArgumentsV1 {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            value.to_string(),
        ],
        cwd: None,
        timeout_ms: 5_000,
        stdout_limit_bytes: 1_024,
        stderr_limit_bytes: 1_024,
        total_output_limit_bytes: 2_048,
        requested_profile: DirectEffectExecutionProfileV1::Standard,
    }
}

#[test]
fn registration_is_exactly_replayed_and_token_is_not_debug_visible() {
    let now = 10_000;
    let registration = ShellExecHostRegistrationV1::derive(binding(), now, now + 90_000).unwrap();
    let mut registry = ShellExecAuthorizationRegistryV1::default();
    let first = registry
        .register_with_entropy(registration.clone(), now, [0x41; 32])
        .unwrap();
    let replay = registry
        .register_with_entropy(registration.clone(), now + 1, [0x42; 32])
        .unwrap();
    assert_eq!(replay, first);
    first.validate_for(&registration).unwrap();
    assert!(!format!("{first:?}").contains(first.invocation_token()));
    let wire = serde_json::to_value(&first).unwrap();
    assert!(wire.get("invocation_token").is_none());
    assert!(
        !serde_json::to_string(&wire)
            .unwrap()
            .contains(first.invocation_token())
    );

    let competing = ShellExecHostRegistrationV1::derive(binding(), now, now + 80_000).unwrap();
    assert!(
        registry
            .register_with_entropy(competing, now, [0x43; 32])
            .is_err()
    );
}

#[test]
fn zero_effect_retirement_allows_the_next_registration() {
    let now = 15_000;
    let first_registration =
        ShellExecHostRegistrationV1::derive(binding(), now, now + 60_000).unwrap();
    let retirement = ShellExecHostRetirementV1::derive(&first_registration).unwrap();
    let mut registry = ShellExecAuthorizationRegistryV1::default();
    registry
        .register_with_entropy(first_registration.clone(), now, [0x45; 32])
        .unwrap();
    assert!(!registry.retirement_has_ordinals(&retirement).unwrap());
    let receipt = registry.retire(&retirement, now + 1).unwrap();
    receipt.validate_for(&retirement).unwrap();
    assert!(!registry.retirement_has_ordinals(&retirement).unwrap());
    assert_eq!(registry.retire(&retirement, now + 2).unwrap(), receipt);
    assert!(
        registry
            .register_with_entropy(first_registration, now + 2, [0x47; 32])
            .is_err()
    );
    assert!(
        registry
            .begin_unique_active_request(1, arguments("denied"), now + 2)
            .is_err()
    );

    let second_registration =
        ShellExecHostRegistrationV1::derive(binding(), now + 2, now + 60_002).unwrap();
    registry
        .register_with_entropy(second_registration, now + 2, [0x46; 32])
        .unwrap();
    assert!(matches!(
        registry
            .begin_unique_active_request(1, arguments("next"), now + 3)
            .unwrap(),
        ShellExecRequestAdmissionV1::NeedsWorker(_)
    ));
}

#[test]
fn token_and_ordinal_derive_one_os_request_and_replay_exactly() {
    let now = 20_000;
    let registration = ShellExecHostRegistrationV1::derive(binding(), now, now + 90_000).unwrap();
    let binding_sha256 = registration.binding_sha256.clone();
    let mut registry = ShellExecAuthorizationRegistryV1::default();
    let receipt = registry
        .register_with_entropy(registration, now, [0x51; 32])
        .unwrap();
    let pending = match registry
        .begin_request(receipt.invocation_token(), 1, arguments("literal"), now + 1)
        .unwrap()
    {
        ShellExecRequestAdmissionV1::NeedsWorker(pending) => pending,
        ShellExecRequestAdmissionV1::Existing(_) => panic!("first request unexpectedly existed"),
    };
    let request = registry
        .materialize_request(pending, now + 2, digest('9'), digest('a'), digest('b'))
        .unwrap();
    assert_eq!(request.direct_binding_sha256, binding_sha256);
    assert_eq!(request.adapter_effect_ordinal, 1);
    assert_eq!(request.arguments.argv[2], "literal");
    assert_eq!(request.absolute_deadline_boottime_ms, now + 2 + 5_000);
    request.validate().unwrap();

    let replay = match registry
        .begin_request(
            receipt.invocation_token(),
            1,
            arguments("literal"),
            now + 10,
        )
        .unwrap()
    {
        ShellExecRequestAdmissionV1::Existing(request) => request,
        ShellExecRequestAdmissionV1::NeedsWorker(_) => panic!("materialized request was lost"),
    };
    assert_eq!(replay, request);

    assert!(
        registry
            .begin_request(
                receipt.invocation_token(),
                1,
                arguments("changed"),
                now + 11
            )
            .is_err()
    );
    assert!(
        registry
            .begin_request(receipt.invocation_token(), 3, arguments("skip"), now + 12)
            .is_err()
    );
    assert!(
        registry
            .begin_request("shell-inv:not-a-digest", 2, arguments("next"), now + 12)
            .is_err()
    );
}

#[test]
fn expired_registration_cannot_begin_or_materialize_an_effect() {
    let now = 30_000;
    let registration = ShellExecHostRegistrationV1::derive(binding(), now, now + 1_000).unwrap();
    let mut registry = ShellExecAuthorizationRegistryV1::default();
    let receipt = registry
        .register_with_entropy(registration, now, [0x61; 32])
        .unwrap();
    assert!(
        registry
            .begin_request(
                receipt.invocation_token(),
                1,
                arguments("late"),
                now + 1_000,
            )
            .is_err()
    );
}

#[test]
fn broker_restart_restores_ordinal_high_water_without_rederiving_request() {
    let now = 40_000;
    let registration = ShellExecHostRegistrationV1::derive(binding(), now, now + 90_000).unwrap();
    let mut first = ShellExecAuthorizationRegistryV1::default();
    let receipt = first
        .register_with_entropy(registration.clone(), now, [0x71; 32])
        .unwrap();
    let pending = match first
        .begin_request(
            receipt.invocation_token(),
            1,
            arguments("old-boot"),
            now + 1,
        )
        .unwrap()
    {
        ShellExecRequestAdmissionV1::NeedsWorker(pending) => pending,
        ShellExecRequestAdmissionV1::Existing(_) => panic!("unexpected existing request"),
    };
    let old_request = first
        .materialize_request(pending, now + 2, digest('9'), digest('a'), digest('b'))
        .unwrap();

    let mut restarted = ShellExecAuthorizationRegistryV1::default();
    restarted
        .register_with_entropy(registration.clone(), now + 3, [0x72; 32])
        .unwrap();
    restarted
        .restore_durable_requests(&registration.binding_sha256, &[old_request.clone()])
        .unwrap();
    // Repeated registration/hydration is idempotent.
    restarted
        .restore_durable_requests(&registration.binding_sha256, &[old_request.clone()])
        .unwrap();
    assert!(matches!(
        restarted
            .begin_unique_active_request(1, arguments("old-boot"), now + 4)
            .unwrap(),
        ShellExecRequestAdmissionV1::Existing(request) if request == old_request
    ));
    let error = restarted
        .begin_unique_active_request(2, arguments("next"), now + 5)
        .err()
        .expect("effect ordinal 2 must be rejected for the single-effect P0 profile");
    assert!(error.to_string().contains("adapter_effect_ordinal_invalid"));
}
