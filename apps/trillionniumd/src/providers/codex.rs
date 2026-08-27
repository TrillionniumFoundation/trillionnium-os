//! Supervised Codex implementation of the provider-neutral adapter contract.

use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
#[cfg(test)]
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
#[cfg(test)]
use trillionnium_os_types::AgentPlanSubmission;
use trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL as CODEX_PRINCIPAL;
use trillionnium_os_types::direct_operation::DirectOperationBinding;
use trillionnium_shell_exec::authorization::{
    MAX_INVOCATION_LIFETIME_MS, ShellExecHostRegistrationReceiptV1, ShellExecHostRegistrationV1,
    ShellExecHostRetirementReceiptV1, ShellExecHostRetirementV1,
};
use trillionnium_shell_exec::mcp_adapter::{
    register_product_invocation, retire_product_invocation,
};
#[cfg(test)]
use trillionnium_tool_runtime::supervised_codex::CODEX_DIRECT_SHELL_EXEC_TIMEOUT_SECONDS;
use trillionnium_tool_runtime::supervised_codex::{
    CapabilityIssuer, CodexBackend, CodexCapabilityIdentity, CodexExecutionMode, CodexPlanAttempt,
    DEFAULT_TIMEOUT, PlanningRequest, SupervisedCodexConfig, SupervisedCodexProvider,
};

use crate::provider_contract::{
    AdapterRunState, AgentAdapter, AgentAdapterHealth, AgentAdapterRegistration,
};

pub const CODEX_AGENT_ID: &str = CODEX_PRINCIPAL.agent_id;
pub const CODEX_ADAPTER_NAME: &str = CODEX_PRINCIPAL.runtime_adapter;
pub const CODEX_ADAPTER_VERSION: &str = "0.144.1";
pub const CODEX_PRODUCT_UID: u32 = CODEX_PRINCIPAL.uid;
pub const CODEX_PRODUCT_GID: u32 = CODEX_PRINCIPAL.gid;
const COMPLETED_SHELL_EXEC_AUTHORIZATION_SCHEMA: &str =
    "org.trillionnium.shell-exec.completed-host-authorization.v1";

/// Durable, secret-free proof that the exact Direct-operation binding was
/// registered with the shell broker for this provider turn and was retired
/// again before the turn became ProviderReady.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompletedShellExecAuthorizationV1 {
    pub schema: String,
    pub registration: ShellExecHostRegistrationV1,
    pub registration_receipt: ShellExecHostRegistrationReceiptV1,
    pub retirement: ShellExecHostRetirementV1,
    pub retirement_receipt: ShellExecHostRetirementReceiptV1,
}

impl CompletedShellExecAuthorizationV1 {
    pub(crate) fn from_completed_lifecycle(
        registration: ShellExecHostRegistrationV1,
        registration_receipt: ShellExecHostRegistrationReceiptV1,
        retirement: ShellExecHostRetirementV1,
        retirement_receipt: ShellExecHostRetirementReceiptV1,
    ) -> Result<Self> {
        let value = Self {
            schema: COMPLETED_SHELL_EXEC_AUTHORIZATION_SCHEMA.to_string(),
            registration,
            registration_receipt,
            retirement,
            retirement_receipt,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.registration
            .validate_at(self.registration.issued_boottime_ms)
            .map_err(|error| anyhow!(error.to_string()))
            .context("completed_shell_exec_registration_invalid")?;
        if self.schema != COMPLETED_SHELL_EXEC_AUTHORIZATION_SCHEMA
            || !self.registration_receipt.invocation_token().is_empty()
        {
            anyhow::bail!("completed_shell_exec_authorization_shape_invalid");
        }
        self.registration_receipt
            .validate_for(&self.registration)
            .map_err(|error| anyhow!(error.to_string()))
            .context("completed_shell_exec_registration_receipt_invalid")?;
        let expected_retirement = ShellExecHostRetirementV1::derive(&self.registration)
            .map_err(|error| anyhow!(error.to_string()))
            .context("completed_shell_exec_retirement_derivation_failed")?;
        if self.retirement != expected_retirement {
            anyhow::bail!("completed_shell_exec_retirement_binding_invalid");
        }
        self.retirement_receipt
            .validate_for(&self.retirement)
            .map_err(|error| anyhow!(error.to_string()))
            .context("completed_shell_exec_retirement_receipt_invalid")?;
        if self.retirement_receipt.retired_boottime_ms < self.registration.issued_boottime_ms {
            anyhow::bail!("completed_shell_exec_retirement_precedes_registration");
        }
        Ok(())
    }

    pub(crate) fn digest_sha256(&self) -> Result<String> {
        self.validate()?;
        Ok(trillionnium_os_types::sha256_bytes(&serde_json::to_vec(
            self,
        )?))
    }
}

#[derive(Debug)]
struct ShellAuthorizedValue<T> {
    value: T,
    authorization: CompletedShellExecAuthorizationV1,
}

pub(crate) struct ShellAuthorizedCodexPlanAttempt {
    pub attempt: CodexPlanAttempt,
    pub authorization: CompletedShellExecAuthorizationV1,
}

pub struct CodexAdapter {
    provider: SupervisedCodexProvider,
    run_state: AdapterRunState,
}

trait ShellInvocationControl {
    fn register(
        &self,
        registration: &ShellExecHostRegistrationV1,
    ) -> Result<ShellExecHostRegistrationReceiptV1>;

    fn retire(
        &self,
        retirement: &ShellExecHostRetirementV1,
    ) -> Result<ShellExecHostRetirementReceiptV1>;
}

struct ProductShellInvocationControl;

impl ShellInvocationControl for ProductShellInvocationControl {
    fn register(
        &self,
        registration: &ShellExecHostRegistrationV1,
    ) -> Result<ShellExecHostRegistrationReceiptV1> {
        register_product_invocation(registration)
            .map_err(|error| anyhow!(error.to_string()))
            .context("shell_exec_host_registration_failed_dispatch_denied")
    }

    fn retire(
        &self,
        retirement: &ShellExecHostRetirementV1,
    ) -> Result<ShellExecHostRetirementReceiptV1> {
        retire_product_invocation(retirement)
            .map_err(|error| anyhow!(error.to_string()))
            .context("shell_exec_host_retirement_failed_turn_invalid")
    }
}

struct ShellInvocationLease<'a, C: ShellInvocationControl> {
    control: &'a C,
    retirement: ShellExecHostRetirementV1,
    retirement_attempted: bool,
}

impl<C: ShellInvocationControl> ShellInvocationLease<'_, C> {
    fn retire(mut self) -> Result<ShellExecHostRetirementReceiptV1> {
        let receipt = retire_shell_invocation(self.control, &self.retirement)?;
        // Only a verified broker receipt closes the registration.  If the
        // first retirement attempt failed or its response was ambiguous, keep
        // the guard armed so Drop retries the exact idempotent retirement and
        // fail-stops the daemon if that second proof is also unavailable.
        self.retirement_attempted = true;
        Ok(receipt)
    }
}

impl<C: ShellInvocationControl> Drop for ShellInvocationLease<'_, C> {
    fn drop(&mut self) {
        if !self.retirement_attempted {
            self.retirement_attempted = true;
            if retire_shell_invocation(self.control, &self.retirement).is_err() {
                // An unwind has no Result channel through which revocation
                // failure can be reported. Continuing the daemon would leave
                // a possibly live effect registration, so fail-stop and let
                // the init-owned crash coupling tear down the effect plane.
                fail_stop_shell_invocation_lifecycle();
            }
        }
    }
}

#[cold]
fn fail_stop_shell_invocation_lifecycle() -> ! {
    #[cfg(test)]
    panic!("shell_exec_host_lifecycle_fail_stop");
    #[cfg(not(test))]
    std::process::abort();
}

fn retire_shell_invocation<C: ShellInvocationControl>(
    control: &C,
    retirement: &ShellExecHostRetirementV1,
) -> Result<ShellExecHostRetirementReceiptV1> {
    let receipt = control.retire(retirement)?;
    receipt
        .validate_for(retirement)
        .map_err(|error| anyhow!(error.to_string()))
        .context("shell_exec_host_retirement_receipt_invalid")?;
    Ok(receipt)
}

fn run_with_shell_invocation_lifecycle<C, T>(
    control: &C,
    binding: &DirectOperationBinding,
    issued_boottime_ms: u64,
    operation: impl FnOnce() -> Result<T>,
) -> Result<ShellAuthorizedValue<T>>
where
    C: ShellInvocationControl,
{
    let expires_boottime_ms = issued_boottime_ms
        .checked_add(MAX_INVOCATION_LIFETIME_MS)
        .context("shell_exec_host_registration_lifetime_overflow")?;
    let registration = ShellExecHostRegistrationV1::derive(
        binding.clone(),
        issued_boottime_ms,
        expires_boottime_ms,
    )
    .map_err(|error| anyhow!(error.to_string()))
    .context("shell_exec_host_registration_derivation_failed_dispatch_denied")?;
    let retirement = ShellExecHostRetirementV1::derive(&registration)
        .map_err(|error| anyhow!(error.to_string()))
        .context("shell_exec_host_retirement_derivation_failed_dispatch_denied")?;
    let receipt = match control.register(&registration) {
        Ok(receipt) => receipt,
        Err(registration_error) => {
            return match retire_shell_invocation(control, &retirement) {
                Ok(_) => Err(registration_error),
                // A registration transport failure is ambiguous: the broker
                // may have committed before the response was lost.  Without
                // an exact retirement receipt, continuing this daemon could
                // retain effect authority that no durable provider result can
                // account for.
                Err(_) => fail_stop_shell_invocation_lifecycle(),
            };
        }
    };
    if let Err(error) = receipt.validate_for(&registration) {
        let registration_error = anyhow!(error.to_string())
            .context("shell_exec_host_registration_receipt_invalid_dispatch_denied");
        return match retire_shell_invocation(control, &retirement) {
            Ok(_) => Err(registration_error),
            Err(_) => fail_stop_shell_invocation_lifecycle(),
        };
    }
    // From this point onward every fallible local proof/redaction step is
    // covered by the exact retirement guard.  A successfully registered
    // broker lease must never escape because durable-proof construction
    // failed before the provider ran.
    let lease = ShellInvocationLease {
        control,
        retirement: retirement.clone(),
        retirement_attempted: false,
    };
    let durable_registration_receipt: ShellExecHostRegistrationReceiptV1 =
        serde_json::from_value(serde_json::to_value(&receipt)?)
            .context("shell_exec_host_registration_receipt_redaction_failed")?;
    if !durable_registration_receipt.invocation_token().is_empty() {
        anyhow::bail!("shell_exec_host_registration_receipt_secret_persisted");
    }
    durable_registration_receipt
        .validate_for(&registration)
        .map_err(|error| anyhow!(error.to_string()))
        .context("shell_exec_host_registration_redacted_receipt_invalid")?;
    let operation_result = operation();
    let retirement_result = lease.retire();
    match (operation_result, retirement_result) {
        (Ok(value), Ok(retirement_receipt)) => {
            let authorization = CompletedShellExecAuthorizationV1::from_completed_lifecycle(
                registration,
                durable_registration_receipt,
                retirement,
                retirement_receipt,
            )?;
            Ok(ShellAuthorizedValue {
                value,
                authorization,
            })
        }
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(operation_error), Err(retirement_error)) => Err(anyhow!(
            "provider invocation failed and shell retirement also failed: provider={operation_error:#}; retirement={retirement_error:#}"
        )),
    }
}

fn boottime_ms() -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is valid writable storage for one timespec.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("shell_exec_host_boottime_unavailable_dispatch_denied");
    }
    let seconds = u64::try_from(value.tv_sec)
        .context("shell_exec_host_boottime_seconds_invalid_dispatch_denied")?;
    let nanoseconds = u64::try_from(value.tv_nsec)
        .context("shell_exec_host_boottime_nanoseconds_invalid_dispatch_denied")?;
    let milliseconds = seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(nanoseconds / 1_000_000))
        .context("shell_exec_host_boottime_overflow_dispatch_denied")?;
    if milliseconds == 0 {
        anyhow::bail!("shell_exec_host_boottime_zero_dispatch_denied");
    }
    Ok(milliseconds)
}

impl CodexAdapter {
    #[cfg(test)]
    pub fn new(config: SupervisedCodexConfig, secret: [u8; 32]) -> Self {
        Self {
            provider: SupervisedCodexProvider::new(config, CapabilityIssuer::new(secret)),
            run_state: AdapterRunState::default(),
        }
    }

    pub fn new_bound(
        config: SupervisedCodexConfig,
        secret: [u8; 32],
        capability_identity: CodexCapabilityIdentity,
    ) -> Result<Self> {
        let provider = SupervisedCodexProvider::new_bound(
            config,
            CapabilityIssuer::new(secret),
            capability_identity,
        )?;
        Ok(Self {
            provider,
            run_state: AdapterRunState::default(),
        })
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    pub fn new_p0_launch_package_conformance(
        config: SupervisedCodexConfig,
        secret: [u8; 32],
        capability_identity: CodexCapabilityIdentity,
    ) -> Result<Self> {
        let provider = SupervisedCodexProvider::new_p0_launch_package_conformance(
            config,
            CapabilityIssuer::new(secret),
            capability_identity,
        )?;
        Ok(Self {
            provider,
            run_state: AdapterRunState::default(),
        })
    }

    // The smoke binary includes this provider module independently.
    #[allow(dead_code)]
    pub fn from_env(secret: [u8; 32]) -> Result<Self> {
        let config = config_from_env()?;
        let identity = capability_identity_from_env(&config)?;
        Self::new_bound(config, secret, identity)
    }

    pub fn plan_attempt_with_cancellation(
        &self,
        request: &PlanningRequest,
        direct_binding: &DirectOperationBinding,
        cancelled: Arc<AtomicBool>,
    ) -> Result<ShellAuthorizedCodexPlanAttempt> {
        self.run_state
            .run_with_cancellation(cancelled, |cancelled| {
                // Acquire a fresh lifetime only after this invocation owns the
                // serialized adapter slot. Time spent waiting behind another
                // turn must never consume the next turn's broker lease.
                let issued_boottime_ms = boottime_ms()?;
                let completed = run_with_shell_invocation_lifecycle(
                    &ProductShellInvocationControl,
                    direct_binding,
                    issued_boottime_ms,
                    || {
                        Ok(self.provider.plan_attempt(
                            request,
                            &direct_binding.authorized_adapter_set,
                            cancelled,
                        ))
                    },
                )?;
                Ok(ShellAuthorizedCodexPlanAttempt {
                    attempt: completed.value,
                    authorization: completed.authorization,
                })
            })
    }
}

impl AgentAdapter for CodexAdapter {
    fn register(&self) -> AgentAdapterRegistration {
        AgentAdapterRegistration::agent_direct(
            CODEX_AGENT_ID,
            CODEX_ADAPTER_NAME,
            CODEX_ADAPTER_VERSION,
        )
    }

    fn health(&self) -> AgentAdapterHealth {
        let facts = self.provider.readiness();
        let installed = facts
            .get("installed")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let version_matches = facts
            .get("version_matches")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let authentication_ready = facts
            .get("authentication_ready")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        AgentAdapterHealth {
            ready: installed && version_matches && authentication_ready,
            provider: CODEX_ADAPTER_NAME.to_string(),
            detail: if installed && version_matches && authentication_ready {
                "supervised Codex CLI base identity is ready; effect-facing MCP registration is rechecked per invocation"
                    .to_string()
            } else {
                "Codex executable, version, or dedicated authentication is not ready".to_string()
            },
            facts,
        }
    }

    #[cfg(test)]
    fn plan(&self, _request: &PlanningRequest, _session_id: &str) -> Result<AgentPlanSubmission> {
        anyhow::bail!(
            "Codex AgentAdapter::plan is disabled; use plan_attempt and durable lifecycle acknowledgement"
        )
    }

    fn cancel(&self) {
        self.run_state.cancel();
    }
}

pub fn config_from_env() -> Result<SupervisedCodexConfig> {
    let model = env::var("TRILLIONNIUM_CODEX_MODEL").unwrap_or_else(|_| "gpt-5.6-sol".to_string());
    let executable = env::var_os("TRILLIONNIUM_CODEX_EXECUTABLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("codex"));
    let credential_home = env::var_os("TRILLIONNIUM_CODEX_CREDENTIAL_HOME").map(PathBuf::from);
    Ok(SupervisedCodexConfig {
        executable,
        backend: CodexBackend::OpenAi { model },
        // Binding V3 retains its exact System API adapter set. shell.exec.v1
        // is separately bound to that complete DirectOperationBinding by the
        // host registration lease above; Accessibility and raw ADB stay out.
        execution_mode: CodexExecutionMode::AgentDirectV1,
        // Keep the complete Codex turn strictly inside the 120-second broker
        // registration lifetime, including teardown/revocation margin.
        timeout: DEFAULT_TIMEOUT,
        expected_cli_version: Some(CODEX_ADAPTER_VERSION.to_string()),
        credential_home,
        run_as_uid: Some(CODEX_PRODUCT_UID),
        run_as_gid: Some(CODEX_PRODUCT_GID),
    })
}

fn capability_identity_from_env(config: &SupervisedCodexConfig) -> Result<CodexCapabilityIdentity> {
    let agent_peer_uid = config
        .run_as_uid
        .context("fixed Codex product UID is missing from the bound adapter")?;
    let agent_peer_gid = config
        .run_as_gid
        .context("fixed Codex product GID is missing from the bound adapter")?;
    let agent_executable_sha256 = env::var("TRILLIONNIUM_CODEX_IDENTITY_SHA256")
        .context("TRILLIONNIUM_CODEX_IDENTITY_SHA256 is required for a bound Codex adapter")?;
    let agent_manifest_sha256 = env::var("TRILLIONNIUM_CODEX_MANIFEST_SHA256")
        .context("TRILLIONNIUM_CODEX_MANIFEST_SHA256 is required for a bound Codex adapter")?;
    Ok(CodexCapabilityIdentity {
        agent_peer_uid,
        agent_peer_gid,
        agent_executable_sha256,
        final_runtime_executable_sha256: env!("TRILLIONNIUM_P01_CODEX_RUNTIME_SHA256").to_string(),
        agent_manifest_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::{Cell, RefCell};
    use trillionnium_os_types::agent_descriptor_registry;
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationAuthorizedAdapterSetV3, DirectOperationProviderAttempt,
        DirectOperationStableSeed, STABLE_SEED_SCHEMA,
    };
    use trillionnium_shell_exec::authorization::ShellExecAuthorizationRegistryV1;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn direct_binding(task_id: &str) -> DirectOperationBinding {
        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: agent_descriptor_registry::CODEX.provider_id.to_string(),
            agent_id: agent_descriptor_registry::CODEX.agent_id.to_string(),
            task_id: task_id.to_string(),
            provider_invocation_id_sha256: digest('1'),
            provider_session_id_sha256: digest('2'),
            subject_uid: 20_000,
            subject_selinux_domain_sha256: digest('3'),
        };
        let invocation_id = stable_seed.invocation_id().unwrap();
        let attempt = DirectOperationProviderAttempt::derive(digest('4'), 1, digest('5')).unwrap();
        let binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed,
            invocation_id,
            workflow_id_sha256: digest('6'),
            agent_identity_key_sha256: digest('7'),
            agent_executable_sha256: digest('8'),
            authorized_adapter_set: DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt,
        };
        binding.validate().unwrap();
        binding
    }

    struct FakeShellInvocationControl {
        registry: RefCell<ShellExecAuthorizationRegistryV1>,
        events: RefCell<Vec<&'static str>>,
        fail_registration: Cell<bool>,
        lose_registration_receipt: Cell<bool>,
        invalid_registration_receipt: Cell<bool>,
        fail_retirement: Cell<bool>,
        invalid_retirement_receipt: Cell<bool>,
        retirement_failures_remaining: Cell<u32>,
        invalid_retirement_receipts_remaining: Cell<u32>,
    }

    impl Default for FakeShellInvocationControl {
        fn default() -> Self {
            Self {
                registry: RefCell::new(ShellExecAuthorizationRegistryV1::default()),
                events: RefCell::new(Vec::new()),
                fail_registration: Cell::new(false),
                lose_registration_receipt: Cell::new(false),
                invalid_registration_receipt: Cell::new(false),
                fail_retirement: Cell::new(false),
                invalid_retirement_receipt: Cell::new(false),
                retirement_failures_remaining: Cell::new(0),
                invalid_retirement_receipts_remaining: Cell::new(0),
            }
        }
    }

    impl ShellInvocationControl for FakeShellInvocationControl {
        fn register(
            &self,
            registration: &ShellExecHostRegistrationV1,
        ) -> Result<ShellExecHostRegistrationReceiptV1> {
            self.events.borrow_mut().push("register");
            if self.fail_registration.get() {
                anyhow::bail!("injected registration failure");
            }
            let receipt = self
                .registry
                .borrow_mut()
                .register_with_entropy(
                    registration.clone(),
                    registration.issued_boottime_ms,
                    [0x51; 32],
                )
                .map_err(|error| anyhow!(error.to_string()))?;
            let serialized = serde_json::to_value(&receipt)?;
            assert!(serialized.get("invocation_token").is_none());
            assert!(!format!("{receipt:?}").contains(receipt.invocation_token()));
            let mut receipt: ShellExecHostRegistrationReceiptV1 =
                serde_json::from_value(serialized)?;
            assert!(receipt.invocation_token().is_empty());
            if self.lose_registration_receipt.get() {
                anyhow::bail!("injected registration response loss");
            }
            if self.invalid_registration_receipt.get() {
                receipt.authorization_sha256 = digest('0');
            }
            Ok(receipt)
        }

        fn retire(
            &self,
            retirement: &ShellExecHostRetirementV1,
        ) -> Result<ShellExecHostRetirementReceiptV1> {
            self.events.borrow_mut().push("retire");
            let remaining = self.retirement_failures_remaining.get();
            if remaining > 0 {
                self.retirement_failures_remaining.set(remaining - 1);
                anyhow::bail!("injected retirement failure");
            }
            if self.fail_retirement.get() {
                anyhow::bail!("injected retirement failure");
            }
            let mut receipt = self
                .registry
                .borrow_mut()
                .retire(retirement, 1_000_000)
                .map_err(|error| anyhow!(error.to_string()))?;
            let invalid_remaining = self.invalid_retirement_receipts_remaining.get();
            if invalid_remaining > 0 {
                self.invalid_retirement_receipts_remaining
                    .set(invalid_remaining - 1);
                receipt.retired_boottime_ms = 0;
            } else if self.invalid_retirement_receipt.get() {
                receipt.retired_boottime_ms = 0;
            }
            Ok(receipt)
        }
    }

    #[test]
    fn product_config_uses_the_closed_codex_identity() {
        let config = config_from_env().unwrap();
        assert_eq!(config.run_as_uid, Some(CODEX_PRODUCT_UID));
        assert_eq!(config.run_as_gid, Some(CODEX_PRODUCT_GID));
        assert!(
            config.timeout > Duration::from_secs(CODEX_DIRECT_SHELL_EXEC_TIMEOUT_SECONDS),
            "the provider must outlive one bounded shell MCP request"
        );
        assert!(
            config.timeout.as_millis() < u128::from(MAX_INVOCATION_LIFETIME_MS),
            "the provider must leave time to retire its broker registration"
        );
    }

    #[test]
    fn registration_exposes_explicit_direct_execution_mode() {
        let adapter = CodexAdapter::new(
            SupervisedCodexConfig {
                execution_mode: CodexExecutionMode::AgentDirectV1,
                ..SupervisedCodexConfig::default()
            },
            [1u8; 32],
        );
        let registration = adapter.register();
        assert_eq!(
            registration.execution_mode,
            crate::provider_contract::AgentAdapterExecutionMode::AgentDirect
        );
        assert_eq!(registration.agent_id, CODEX_AGENT_ID);
        assert_eq!(
            registration.network_policy,
            trillionnium_os_types::AgentNetworkPolicy::PerRequest
        );
        assert_eq!(
            json!(registration)
                .get("api_version")
                .and_then(|v| v.as_str()),
            Some(trillionnium_os_types::AGENT_API_VERSION)
        );
    }

    #[test]
    fn shell_registration_wraps_every_provider_outcome_and_redacts_its_secret() {
        let control = FakeShellInvocationControl::default();
        let binding = direct_binding("shell-lifecycle-success");
        let completed = run_with_shell_invocation_lifecycle(&control, &binding, 10_000, || {
            control.events.borrow_mut().push("provider");
            Ok(7_u64)
        })
        .unwrap();
        assert_eq!(completed.value, 7);
        completed.authorization.validate().unwrap();
        assert_eq!(completed.authorization.registration.binding, binding);
        assert!(
            completed
                .authorization
                .registration_receipt
                .invocation_token()
                .is_empty()
        );
        assert_eq!(
            &*control.events.borrow(),
            &["register", "provider", "retire"]
        );

        let control = FakeShellInvocationControl::default();
        let error = run_with_shell_invocation_lifecycle(
            &control,
            &direct_binding("shell-lifecycle-provider-failure"),
            20_000,
            || -> Result<()> {
                control.events.borrow_mut().push("provider");
                anyhow::bail!("injected provider failure")
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected provider failure"));
        assert_eq!(
            &*control.events.borrow(),
            &["register", "provider", "retire"]
        );
    }

    #[test]
    fn shell_registration_and_retirement_require_exact_cleanup_proof() {
        let control = FakeShellInvocationControl::default();
        control.fail_registration.set(true);
        let invoked = Cell::new(false);
        let registration_failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run_with_shell_invocation_lifecycle(
                &control,
                &direct_binding("shell-registration-failure"),
                30_000,
                || {
                    invoked.set(true);
                    Ok(())
                },
            );
        }));
        assert!(registration_failure.is_err());
        assert!(!invoked.get());
        assert_eq!(&*control.events.borrow(), &["register", "retire"]);

        let control = FakeShellInvocationControl::default();
        control.lose_registration_receipt.set(true);
        let invoked = Cell::new(false);
        let error = run_with_shell_invocation_lifecycle(
            &control,
            &direct_binding("shell-registration-response-loss"),
            32_000,
            || {
                invoked.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("registration response loss"));
        assert!(!invoked.get());
        assert_eq!(&*control.events.borrow(), &["register", "retire"]);

        let control = FakeShellInvocationControl::default();
        control.invalid_registration_receipt.set(true);
        let invoked = Cell::new(false);
        let error = run_with_shell_invocation_lifecycle(
            &control,
            &direct_binding("shell-registration-receipt-invalid"),
            35_000,
            || {
                invoked.set(true);
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("receipt_invalid"));
        assert!(!invoked.get());
        assert_eq!(&*control.events.borrow(), &["register", "retire"]);

        let control = FakeShellInvocationControl::default();
        control.retirement_failures_remaining.set(1);
        let error = run_with_shell_invocation_lifecycle(
            &control,
            &direct_binding("shell-retirement-failure"),
            40_000,
            || {
                control.events.borrow_mut().push("provider");
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected retirement failure"));
        assert_eq!(
            &*control.events.borrow(),
            &["register", "provider", "retire", "retire"]
        );

        let control = FakeShellInvocationControl::default();
        control.invalid_retirement_receipts_remaining.set(1);
        let error = run_with_shell_invocation_lifecycle(
            &control,
            &direct_binding("shell-retirement-receipt-invalid"),
            45_000,
            || {
                control.events.borrow_mut().push("provider");
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("retirement_receipt_invalid"));
        assert_eq!(
            &*control.events.borrow(),
            &["register", "provider", "retire", "retire"]
        );
    }

    #[test]
    fn shell_lifecycle_fail_stops_when_exact_cleanup_cannot_be_proven() {
        let control = FakeShellInvocationControl::default();
        control.lose_registration_receipt.set(true);
        control.fail_retirement.set(true);
        let registration_cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run_with_shell_invocation_lifecycle(
                &control,
                &direct_binding("shell-registration-response-loss-cleanup-unprovable"),
                47_000,
                || Ok(()),
            );
        }));
        assert!(registration_cleanup.is_err());
        assert_eq!(&*control.events.borrow(), &["register", "retire"]);

        let control = FakeShellInvocationControl::default();
        control.fail_retirement.set(true);
        let retirement_cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run_with_shell_invocation_lifecycle(
                &control,
                &direct_binding("shell-retirement-cleanup-unprovable"),
                48_000,
                || {
                    control.events.borrow_mut().push("provider");
                    Ok(())
                },
            );
        }));
        assert!(retirement_cleanup.is_err());
        assert_eq!(
            &*control.events.borrow(),
            &["register", "provider", "retire", "retire"]
        );
    }

    #[test]
    fn shell_registration_drop_guard_retires_during_provider_unwind() {
        let control = FakeShellInvocationControl::default();
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<ShellAuthorizedValue<()>> = run_with_shell_invocation_lifecycle(
                &control,
                &direct_binding("shell-lifecycle-unwind"),
                50_000,
                || {
                    control.events.borrow_mut().push("provider");
                    panic!("injected provider panic")
                },
            );
        }));
        assert!(unwind.is_err());
        assert_eq!(
            &*control.events.borrow(),
            &["register", "provider", "retire"]
        );
    }
}
