use std::process::Command;

use trillionnium_os_types::agent_descriptor_registry;
use trillionnium_os_types::direct_effect::{
    DirectEffectExecutionProfileV1, DirectEffectModelArgumentsV1,
};
use trillionnium_os_types::direct_operation::{
    BINDING_SCHEMA, DirectOperationAuthorizedAdapterSetV3, DirectOperationBinding,
    DirectOperationProviderAttempt, DirectOperationStableSeed, STABLE_SEED_SCHEMA,
};
use trillionnium_shell_exec::INVOCATION_TOKEN_ENV;
use trillionnium_shell_exec::authorization::{
    INVOCATION_TOKEN_PREFIX, ShellExecAuthorizationRegistryV1, ShellExecHostRegistrationV1,
    ShellExecRequestAdmissionV1,
};
use trillionnium_shell_exec::mcp_adapter::ProductTransportBackendV1;

const ADAPTER_ENV_CHILD_MODE: &str = "TRILLIONNIUM_TEST_SHELL_ADAPTER_ENV_CHILD_MODE";

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn binding(task_id: &str, invocation_digest: char) -> DirectOperationBinding {
    let stable_seed = DirectOperationStableSeed {
        schema: STABLE_SEED_SCHEMA.to_string(),
        provider_id: agent_descriptor_registry::CODEX.provider_id.to_string(),
        agent_id: agent_descriptor_registry::CODEX.agent_id.to_string(),
        task_id: task_id.to_string(),
        provider_invocation_id_sha256: digest(invocation_digest),
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

fn arguments(literal: &str) -> DirectEffectModelArgumentsV1 {
    DirectEffectModelArgumentsV1 {
        argv: vec![
            "/usr/bin/printf".to_string(),
            "%s".to_string(),
            literal.to_string(),
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
fn exact_reregistration_replays_only_while_the_broker_registry_survives() {
    let now = 10_000;
    let registration = ShellExecHostRegistrationV1::derive(
        binding("same-binding-restart", '1'),
        now,
        now + 90_000,
    )
    .unwrap();
    let mut live = ShellExecAuthorizationRegistryV1::default();
    let first = live
        .register_with_entropy(registration.clone(), now, [0x41; 32])
        .unwrap();
    let exact_retry = live
        .register_with_entropy(registration.clone(), now + 1, [0x42; 32])
        .unwrap();
    assert_eq!(first, exact_retry);

    // A broker process restart loses the volatile token registry. The exact
    // same unexpired binding/registration can be registered again, but the
    // returned one-time token changes and the old adapter must remain dead.
    let mut restarted = ShellExecAuthorizationRegistryV1::default();
    let replacement = restarted
        .register_with_entropy(registration.clone(), now + 2, [0x42; 32])
        .unwrap();
    assert_ne!(first.invocation_token(), replacement.invocation_token());
    assert!(
        restarted
            .begin_request(first.invocation_token(), 1, arguments("old"), now + 3)
            .is_err()
    );
    assert!(matches!(
        restarted
            .begin_request(
                replacement.invocation_token(),
                1,
                arguments("replacement"),
                now + 3,
            )
            .unwrap(),
        ShellExecRequestAdmissionV1::NeedsWorker(_)
    ));
    assert!(!format!("{replacement:?}").contains(replacement.invocation_token()));
}

#[test]
fn invocation_token_selects_exactly_one_binding_and_cannot_be_cross_spliced() {
    let now = 20_000;
    let first_registration =
        ShellExecHostRegistrationV1::derive(binding("first-invocation", '1'), now, now + 90_000)
            .unwrap();
    let second_registration =
        ShellExecHostRegistrationV1::derive(binding("second-invocation", '9'), now, now + 90_000)
            .unwrap();
    let second_binding_sha256 = second_registration.binding_sha256.clone();
    assert_ne!(first_registration.binding_sha256, second_binding_sha256);

    let mut registry = ShellExecAuthorizationRegistryV1::default();
    let first = registry
        .register_with_entropy(first_registration.clone(), now, [0x51; 32])
        .unwrap();
    assert!(
        registry
            .register_with_entropy(second_registration.clone(), now, [0x52; 32])
            .is_err()
    );
    registry
        .retire_registration(
            &first.registration_sha256,
            &first_registration.binding_sha256,
        )
        .unwrap();
    let second = registry
        .register_with_entropy(second_registration, now + 1, [0x52; 32])
        .unwrap();
    assert!(
        registry
            .begin_request(first.invocation_token(), 1, arguments("stale"), now + 2)
            .is_err()
    );
    let pending = match registry
        .begin_unique_active_request(1, arguments("second-only"), now + 2)
        .unwrap()
    {
        ShellExecRequestAdmissionV1::NeedsWorker(pending) => pending,
        ShellExecRequestAdmissionV1::Existing(_) => panic!("first ordinal unexpectedly existed"),
    };
    let request = registry
        .materialize_request(pending, now + 3, digest('a'), digest('b'), digest('c'))
        .unwrap();
    assert_eq!(request.direct_binding_sha256, second_binding_sha256);
    assert_ne!(first.invocation_token(), second.invocation_token());
}

#[test]
fn adapter_restart_replays_only_the_exact_ordinal_and_cannot_skip_forward() {
    let now = 30_000;
    let registration = ShellExecHostRegistrationV1::derive(
        binding("adapter-restart-ordinal", '5'),
        now,
        now + 90_000,
    )
    .unwrap();
    let mut registry = ShellExecAuthorizationRegistryV1::default();
    registry
        .register_with_entropy(registration, now, [0x61; 32])
        .unwrap();

    let first_arguments = arguments("first");
    let first_pending = match registry
        .begin_unique_active_request(1, first_arguments.clone(), now + 1)
        .unwrap()
    {
        ShellExecRequestAdmissionV1::NeedsWorker(pending) => pending,
        ShellExecRequestAdmissionV1::Existing(_) => panic!("first ordinal unexpectedly existed"),
    };
    let first_request = registry
        .materialize_request(
            first_pending,
            now + 2,
            digest('d'),
            digest('e'),
            digest('f'),
        )
        .unwrap();

    // A fresh adapter process restarts its local counter at one. The broker's
    // surviving registry returns the exact OS-authored request and never
    // creates a second effect for that ordinal.
    match registry
        .begin_unique_active_request(1, first_arguments, now + 3)
        .unwrap()
    {
        ShellExecRequestAdmissionV1::Existing(replayed) => assert_eq!(replayed, first_request),
        ShellExecRequestAdmissionV1::NeedsWorker(_) => {
            panic!("exact ordinal replay unexpectedly requested another worker")
        }
    }
    assert!(
        registry
            .begin_unique_active_request(1, arguments("changed"), now + 4)
            .is_err(),
        "an existing ordinal must not be cross-spliced with different argv"
    );
    assert!(
        registry
            .begin_unique_active_request(3, arguments("skipped"), now + 4)
            .is_err(),
        "a restarted adapter must not amplify effects by skipping an ordinal"
    );
    let error = registry
        .begin_unique_active_request(2, arguments("second"), now + 4)
        .err()
        .expect("the one-effect P0 registration must reject ordinal two");
    assert!(error.to_string().contains("adapter_effect_ordinal_invalid"));
}

#[test]
fn adapter_product_environment_is_tokenless_and_rejects_legacy_secret() {
    if let Some(mode) = std::env::var_os(ADAPTER_ENV_CHILD_MODE) {
        match mode.to_str().unwrap() {
            "tokenless" => {
                assert!(ProductTransportBackendV1::from_process_environment().is_ok());
            }
            "leaked" => {
                let leaked = std::env::var(INVOCATION_TOKEN_ENV).unwrap();
                let error = match ProductTransportBackendV1::from_process_environment() {
                    Ok(_) => panic!("product adapter accepted a legacy invocation secret"),
                    Err(error) => error.to_string(),
                };
                assert!(error.contains("refuses a leaked invocation secret"));
                assert!(!error.contains(&leaked));
            }
            other => panic!("unexpected adapter environment child mode: {other}"),
        }
        return;
    }

    let executable = std::env::current_exe().unwrap();
    let run_child = |mode: &str, leaked_token: Option<&str>| {
        let mut command = Command::new(&executable);
        command
            .arg("--exact")
            .arg("adapter_product_environment_is_tokenless_and_rejects_legacy_secret")
            .arg("--nocapture")
            .env(ADAPTER_ENV_CHILD_MODE, mode);
        if let Some(token) = leaked_token {
            command.env(INVOCATION_TOKEN_ENV, token);
        } else {
            command.env_remove(INVOCATION_TOKEN_ENV);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "adapter environment child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    run_child("tokenless", None);
    let leaked_token = format!("{INVOCATION_TOKEN_PREFIX}{}", "9".repeat(64));
    run_child("leaked", Some(&leaked_token));
}
