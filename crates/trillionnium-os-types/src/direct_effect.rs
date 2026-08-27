//! Closed, authority-neutral data contract for future Codex direct shell/ADB effects.
//!
//! This module deliberately contains no listener, process launcher, transport,
//! key, policy issuer, or product constructor. It freezes only model-visible
//! arguments, the OS-owned request envelope, canonical hashes, and the durable
//! state transition rules that a later broker must implement.

use std::error::Error;
use std::fmt;
use std::path::{Component, Path};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_descriptor_registry;

pub const CONTRACT_SCHEMA: &str = "org.trillionnium.direct-effect.contract.v1";
pub const CONTRACT_SHA256: &str =
    "5c4fe8ac528d2da54d7eecb28b7c50107f1bd9971196bdabd6b55e5f483d2266";
pub const REQUEST_SCHEMA: &str = "org.trillionnium.direct-effect.request.v1";
pub const STATE_SCHEMA: &str = "org.trillionnium.direct-effect.state.v1";
pub const TERMINAL_OBSERVATION_SCHEMA: &str =
    "org.trillionnium.direct-effect.terminal-observation.v1";
pub const TERMINAL_RESPONSE_SCHEMA: &str = "org.trillionnium.direct-effect.terminal-response.v1";
pub const BINARY_OUTPUT_ENCODING: &str = "base64_standard_rfc4648";
pub const BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE: &str = "broker_restart_before_dispatch";

pub const MODEL_ARGUMENTS_HASH_DOMAIN: &str = "trillionnium.direct-effect-model-arguments.v1";
pub const EFFECT_ID_HASH_DOMAIN: &str = "trillionnium.direct-effect-id.v1";
pub const REQUEST_HASH_DOMAIN: &str = "trillionnium.direct-effect-request.v1";
pub const STATE_HASH_DOMAIN: &str = "trillionnium.direct-effect-state.v1";
pub const TERMINAL_OBSERVATION_HASH_DOMAIN: &str =
    "trillionnium.direct-effect-terminal-observation.v1";

pub const INVOCATION_ID_PREFIX: &str = "inv:";
pub const PROVIDER_ATTEMPT_ID_PREFIX: &str = "attempt:";
pub const OS_TOOL_CALL_ID_PREFIX: &str = "tool-call:";
pub const EFFECT_ID_PREFIX: &str = "effect:";

pub const MAX_ARGV_COUNT: usize = 256;
pub const MAX_ARGUMENT_BYTES: usize = 16 * 1024;
pub const MAX_ARGV_TOTAL_BYTES: usize = 64 * 1024;
pub const MAX_CWD_RELATIVE_BYTES: usize = 4096;
pub const MAX_TIMEOUT_MS: u64 = 120_000;
pub const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;

pub const SOURCE_PROTOCOL_IMPLEMENTED: bool = true;
pub const PURE_DURABLE_STATE_MACHINE_IMPLEMENTED: bool = true;
pub const PRODUCT_LISTENER_WIRED: bool = true;
pub const PRODUCT_BACKEND_WIRED: bool = true;
pub const PRODUCT_EFFECT_AUTHORITY_AVAILABLE: bool = false;
pub const CONFERS_EFFECT_AUTHORITY: bool = false;

pub type DirectEffectResult<T> = Result<T, DirectEffectError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectEffectError(&'static str);

impl DirectEffectError {
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for DirectEffectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for DirectEffectError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectEffectToolV1 {
    ShellExecV1,
    AdbShellLocalV1,
}

impl DirectEffectToolV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ShellExecV1 => "shell_exec_v1",
            Self::AdbShellLocalV1 => "adb_shell_local_v1",
        }
    }

    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ShellExecV1 => "shell.exec.v1",
            Self::AdbShellLocalV1 => "adb.shell.local.v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectEffectExecutionProfileV1 {
    Standard,
    Elevated,
    DeveloperRecovery,
}

impl DirectEffectExecutionProfileV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Elevated => "elevated",
            Self::DeveloperRecovery => "developer_recovery",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectEffectRiskClassV1 {
    Standard,
    Elevated,
    Destructive,
}

impl DirectEffectRiskClassV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Elevated => "elevated",
            Self::Destructive => "destructive",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectEffectWorkingDirectoryScopeV1 {
    Workspace,
}

impl DirectEffectWorkingDirectoryScopeV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectEffectWorkingDirectoryV1 {
    pub scope: DirectEffectWorkingDirectoryScopeV1,
    pub relative: String,
}

impl DirectEffectWorkingDirectoryV1 {
    pub fn validate(&self) -> DirectEffectResult<()> {
        let bytes = self.relative.as_bytes();
        let path = Path::new(&self.relative);
        if bytes.is_empty()
            || bytes.len() > MAX_CWD_RELATIVE_BYTES
            || bytes.contains(&0)
            || path.is_absolute()
            || self
                .relative
                .split('/')
                .any(|component| component.is_empty() || matches!(component, "." | ".."))
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(denied("direct_effect_cwd_denied"));
        }
        Ok(())
    }
}

/// The complete model-visible argument set. All identity, target, policy,
/// deadline, receipt, and backend fields live exclusively in the OS envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectEffectModelArgumentsV1 {
    pub argv: Vec<String>,
    pub cwd: Option<DirectEffectWorkingDirectoryV1>,
    pub timeout_ms: u64,
    pub stdout_limit_bytes: u64,
    pub stderr_limit_bytes: u64,
    pub total_output_limit_bytes: u64,
    pub requested_profile: DirectEffectExecutionProfileV1,
}

impl DirectEffectModelArgumentsV1 {
    pub fn validate(&self) -> DirectEffectResult<()> {
        if self.argv.is_empty() || self.argv.len() > MAX_ARGV_COUNT || self.argv[0].is_empty() {
            return Err(denied("direct_effect_argv_shape_denied"));
        }
        let mut total = 0_usize;
        for argument in &self.argv {
            if argument.len() > MAX_ARGUMENT_BYTES || argument.as_bytes().contains(&0) {
                return Err(denied("direct_effect_argv_argument_denied"));
            }
            total = total
                .checked_add(argument.len())
                .ok_or_else(|| denied("direct_effect_argv_total_denied"))?;
        }
        if total > MAX_ARGV_TOTAL_BYTES {
            return Err(denied("direct_effect_argv_total_denied"));
        }
        if let Some(cwd) = &self.cwd {
            cwd.validate()?;
        }
        if self.timeout_ms == 0
            || self.timeout_ms > MAX_TIMEOUT_MS
            || self.stdout_limit_bytes == 0
            || self.stdout_limit_bytes > MAX_OUTPUT_BYTES
            || self.stderr_limit_bytes == 0
            || self.stderr_limit_bytes > MAX_OUTPUT_BYTES
            || self.total_output_limit_bytes == 0
            || self.total_output_limit_bytes > MAX_OUTPUT_BYTES
            || self.stdout_limit_bytes > self.total_output_limit_bytes
            || self.stderr_limit_bytes > self.total_output_limit_bytes
        {
            return Err(denied("direct_effect_bounds_denied"));
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectEffectResult<String> {
        self.validate()?;
        let mut hasher = domain_hasher(MODEL_ARGUMENTS_HASH_DOMAIN);
        hash_u64_field(&mut hasher, "argv_count", usize_to_u64(self.argv.len())?);
        for argument in &self.argv {
            hash_string_field(&mut hasher, "argv", argument);
        }
        match &self.cwd {
            Some(cwd) => {
                hash_bytes_field(&mut hasher, "cwd_present", &[1]);
                hash_string_field(&mut hasher, "cwd_scope", cwd.scope.as_str());
                hash_string_field(&mut hasher, "cwd_relative", &cwd.relative);
            }
            None => hash_bytes_field(&mut hasher, "cwd_present", &[0]),
        }
        hash_u64_field(&mut hasher, "timeout_ms", self.timeout_ms);
        hash_u64_field(&mut hasher, "stdout_limit_bytes", self.stdout_limit_bytes);
        hash_u64_field(&mut hasher, "stderr_limit_bytes", self.stderr_limit_bytes);
        hash_u64_field(
            &mut hasher,
            "total_output_limit_bytes",
            self.total_output_limit_bytes,
        );
        hash_string_field(
            &mut hasher,
            "requested_profile",
            self.requested_profile.as_str(),
        );
        Ok(lower_hex(&hasher.finalize()))
    }
}

/// OS-authored request material for one future effect broker admission.
///
/// Constructing or validating this data never grants effect authority. A later
/// broker must independently observe the peer and consume retained OS custody.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectEffectRequestV1 {
    pub schema: String,
    pub contract_sha256: String,
    pub provider_id: String,
    pub agent_id: String,
    pub direct_binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub os_tool_call_id: String,
    pub adapter_effect_ordinal: u64,
    pub effect_id: String,
    pub allocation_record_sha256: String,
    pub kernel_launch_custody_sha256: String,
    pub boot_id_sha256: String,
    pub tool: DirectEffectToolV1,
    pub arguments: DirectEffectModelArgumentsV1,
    pub absolute_deadline_boottime_ms: u64,
    pub effective_profile: DirectEffectExecutionProfileV1,
    pub risk_class: DirectEffectRiskClassV1,
    pub confirmation_lease_receipt_sha256: Option<String>,
    pub policy_sha256: String,
    pub backend_identity_sha256: String,
    pub request_sha256: String,
}

impl DirectEffectRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn derive_os_owned(
        provider_id: String,
        agent_id: String,
        direct_binding_sha256: String,
        invocation_id: String,
        delivery_provider_attempt_id: String,
        os_tool_call_id: String,
        adapter_effect_ordinal: u64,
        allocation_record_sha256: String,
        kernel_launch_custody_sha256: String,
        boot_id_sha256: String,
        tool: DirectEffectToolV1,
        arguments: DirectEffectModelArgumentsV1,
        absolute_deadline_boottime_ms: u64,
        effective_profile: DirectEffectExecutionProfileV1,
        risk_class: DirectEffectRiskClassV1,
        confirmation_lease_receipt_sha256: Option<String>,
        policy_sha256: String,
        backend_identity_sha256: String,
    ) -> DirectEffectResult<Self> {
        let effect_id = derive_effect_id(
            &direct_binding_sha256,
            &invocation_id,
            &delivery_provider_attempt_id,
            &os_tool_call_id,
            adapter_effect_ordinal,
            tool,
        )?;
        let mut request = Self {
            schema: REQUEST_SCHEMA.to_string(),
            contract_sha256: CONTRACT_SHA256.to_string(),
            provider_id,
            agent_id,
            direct_binding_sha256,
            invocation_id,
            delivery_provider_attempt_id,
            os_tool_call_id,
            adapter_effect_ordinal,
            effect_id,
            allocation_record_sha256,
            kernel_launch_custody_sha256,
            boot_id_sha256,
            tool,
            arguments,
            absolute_deadline_boottime_ms,
            effective_profile,
            risk_class,
            confirmation_lease_receipt_sha256,
            policy_sha256,
            backend_identity_sha256,
            request_sha256: String::new(),
        };
        request.request_sha256 = request.expected_request_sha256()?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> DirectEffectResult<()> {
        self.validate_hash_material()?;
        if !crate::is_nonzero_lower_sha256(&self.request_sha256)
            || self.expected_request_sha256()? != self.request_sha256
        {
            return Err(denied("direct_effect_request_hash_denied"));
        }
        Ok(())
    }

    pub fn expected_request_sha256(&self) -> DirectEffectResult<String> {
        self.validate_hash_material()?;
        let model_arguments_sha256 = self.arguments.canonical_sha256()?;
        let mut hasher = domain_hasher(REQUEST_HASH_DOMAIN);
        hash_string_field(&mut hasher, "schema", &self.schema);
        hash_string_field(&mut hasher, "contract_sha256", &self.contract_sha256);
        hash_string_field(&mut hasher, "provider_id", &self.provider_id);
        hash_string_field(&mut hasher, "agent_id", &self.agent_id);
        hash_string_field(
            &mut hasher,
            "direct_binding_sha256",
            &self.direct_binding_sha256,
        );
        hash_string_field(&mut hasher, "invocation_id", &self.invocation_id);
        hash_string_field(
            &mut hasher,
            "delivery_provider_attempt_id",
            &self.delivery_provider_attempt_id,
        );
        hash_string_field(&mut hasher, "os_tool_call_id", &self.os_tool_call_id);
        hash_u64_field(
            &mut hasher,
            "adapter_effect_ordinal",
            self.adapter_effect_ordinal,
        );
        hash_string_field(&mut hasher, "effect_id", &self.effect_id);
        hash_string_field(
            &mut hasher,
            "allocation_record_sha256",
            &self.allocation_record_sha256,
        );
        hash_string_field(
            &mut hasher,
            "kernel_launch_custody_sha256",
            &self.kernel_launch_custody_sha256,
        );
        hash_string_field(&mut hasher, "boot_id_sha256", &self.boot_id_sha256);
        hash_string_field(&mut hasher, "tool", self.tool.as_str());
        hash_string_field(
            &mut hasher,
            "model_arguments_sha256",
            &model_arguments_sha256,
        );
        hash_u64_field(
            &mut hasher,
            "absolute_deadline_boottime_ms",
            self.absolute_deadline_boottime_ms,
        );
        hash_string_field(
            &mut hasher,
            "effective_profile",
            self.effective_profile.as_str(),
        );
        hash_string_field(&mut hasher, "risk_class", self.risk_class.as_str());
        hash_optional_string_field(
            &mut hasher,
            "confirmation_lease_receipt_sha256",
            self.confirmation_lease_receipt_sha256.as_deref(),
        );
        hash_string_field(&mut hasher, "policy_sha256", &self.policy_sha256);
        hash_string_field(
            &mut hasher,
            "backend_identity_sha256",
            &self.backend_identity_sha256,
        );
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_hash_material(&self) -> DirectEffectResult<()> {
        let descriptor = &agent_descriptor_registry::CODEX;
        self.arguments.validate()?;
        if self.schema != REQUEST_SCHEMA
            || self.contract_sha256 != CONTRACT_SHA256
            || self.provider_id != descriptor.provider_id
            || self.agent_id != descriptor.agent_id
            || !crate::is_nonzero_lower_sha256(&self.direct_binding_sha256)
            || !valid_prefixed_sha256(&self.invocation_id, INVOCATION_ID_PREFIX)
            || !valid_prefixed_sha256(
                &self.delivery_provider_attempt_id,
                PROVIDER_ATTEMPT_ID_PREFIX,
            )
            || !valid_prefixed_sha256(&self.os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
            || self.adapter_effect_ordinal == 0
            || !valid_prefixed_sha256(&self.effect_id, EFFECT_ID_PREFIX)
            || self.effect_id
                != derive_effect_id(
                    &self.direct_binding_sha256,
                    &self.invocation_id,
                    &self.delivery_provider_attempt_id,
                    &self.os_tool_call_id,
                    self.adapter_effect_ordinal,
                    self.tool,
                )?
            || !crate::is_nonzero_lower_sha256(&self.allocation_record_sha256)
            || !crate::is_nonzero_lower_sha256(&self.kernel_launch_custody_sha256)
            || !crate::is_nonzero_lower_sha256(&self.boot_id_sha256)
            || self.absolute_deadline_boottime_ms == 0
            || self.effective_profile != self.arguments.requested_profile
            || !crate::is_nonzero_lower_sha256(&self.policy_sha256)
            || !crate::is_nonzero_lower_sha256(&self.backend_identity_sha256)
        {
            return Err(denied("direct_effect_request_material_denied"));
        }
        let lease_required = self.effective_profile != DirectEffectExecutionProfileV1::Standard
            || self.risk_class != DirectEffectRiskClassV1::Standard;
        match (&self.confirmation_lease_receipt_sha256, lease_required) {
            (None, false) => {}
            (Some(value), true) if crate::is_nonzero_lower_sha256(value) => {}
            _ => return Err(denied("direct_effect_confirmation_lease_denied")),
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectEffectTerminalKindV1 {
    Exited,
    Signaled,
    LaunchRejected,
    CancelledBeforeDispatch,
    DeadlineBeforeDispatch,
    PolicyRejectedBeforeDispatch,
}

impl DirectEffectTerminalKindV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exited => "exited",
            Self::Signaled => "signaled",
            Self::LaunchRejected => "launch_rejected",
            Self::CancelledBeforeDispatch => "cancelled_before_dispatch",
            Self::DeadlineBeforeDispatch => "deadline_before_dispatch",
            Self::PolicyRejectedBeforeDispatch => "policy_rejected_before_dispatch",
        }
    }

    #[must_use]
    pub const fn dispatch_occurred(self) -> bool {
        matches!(self, Self::Exited | Self::Signaled | Self::LaunchRejected)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectEffectBinaryOutputV1 {
    pub encoding: String,
    pub bytes: u64,
    pub sha256: String,
    pub data: String,
    pub complete: bool,
}

impl DirectEffectBinaryOutputV1 {
    #[must_use]
    pub fn from_complete_bytes(bytes: &[u8]) -> Self {
        Self {
            encoding: BINARY_OUTPUT_ENCODING.to_string(),
            bytes: u64::try_from(bytes.len()).expect("slice length always fits u64"),
            sha256: crate::sha256_bytes(bytes),
            data: BASE64_STANDARD.encode(bytes),
            complete: true,
        }
    }

    pub fn validate(&self) -> DirectEffectResult<Vec<u8>> {
        if self.encoding != BINARY_OUTPUT_ENCODING || !self.complete {
            return Err(denied("direct_effect_binary_output_shape_denied"));
        }
        let decoded = BASE64_STANDARD
            .decode(self.data.as_bytes())
            .map_err(|_| denied("direct_effect_binary_output_encoding_denied"))?;
        if u64::try_from(decoded.len()).ok() != Some(self.bytes)
            || !crate::is_nonzero_lower_sha256(&self.sha256)
            || crate::sha256_bytes(&decoded) != self.sha256
        {
            return Err(denied("direct_effect_binary_output_binding_denied"));
        }
        Ok(decoded)
    }
}

/// Canonical binary-safe bytes returned by the broker for a definitive result.
///
/// The SHA-256 of [`Self::canonical_bytes`] is stored in the durable terminal
/// observation. Keeping the digest outside this object avoids a self-hash and
/// lets recovery replay these exact serialized bytes without re-derivation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectEffectTerminalResponseV1 {
    pub schema: String,
    pub effect_id: String,
    pub request_sha256: String,
    pub dispatch_occurred: bool,
    pub kind: DirectEffectTerminalKindV1,
    pub exit_code: Option<i32>,
    pub signal: Option<u32>,
    pub backend_error_code: Option<String>,
    pub stdout: DirectEffectBinaryOutputV1,
    pub stderr: DirectEffectBinaryOutputV1,
    pub started_boottime_ms: u64,
    pub finished_boottime_ms: u64,
}

impl DirectEffectTerminalResponseV1 {
    pub fn validate_for_request(&self, request: &DirectEffectRequestV1) -> DirectEffectResult<()> {
        request.validate()?;
        let stdout = self.stdout.validate()?;
        let stderr = self.stderr.validate()?;
        let total = self
            .stdout
            .bytes
            .checked_add(self.stderr.bytes)
            .ok_or_else(|| denied("direct_effect_terminal_output_denied"))?;
        if self.schema != TERMINAL_RESPONSE_SCHEMA
            || self.effect_id != request.effect_id
            || self.request_sha256 != request.request_sha256
            || self.dispatch_occurred != self.kind.dispatch_occurred()
            || self.stdout.bytes > request.arguments.stdout_limit_bytes
            || self.stderr.bytes > request.arguments.stderr_limit_bytes
            || total > request.arguments.total_output_limit_bytes
            || stdout.len() as u64 != self.stdout.bytes
            || stderr.len() as u64 != self.stderr.bytes
        {
            return Err(denied("direct_effect_terminal_response_denied"));
        }
        let observation = DirectEffectTerminalObservationV1 {
            schema: TERMINAL_OBSERVATION_SCHEMA.to_string(),
            kind: self.kind,
            exit_code: self.exit_code,
            signal: self.signal,
            backend_error_code: self.backend_error_code.clone(),
            stdout_bytes: self.stdout.bytes,
            stderr_bytes: self.stderr.bytes,
            stdout_sha256: self.stdout.sha256.clone(),
            stderr_sha256: self.stderr.sha256.clone(),
            started_boottime_ms: self.started_boottime_ms,
            finished_boottime_ms: self.finished_boottime_ms,
            response_sha256: "f".repeat(64),
        };
        observation.validate_for_request(request)?;
        Ok(())
    }

    pub fn canonical_bytes(&self, request: &DirectEffectRequestV1) -> DirectEffectResult<Vec<u8>> {
        self.validate_for_request(request)?;
        serde_json::to_vec(self)
            .map_err(|_| denied("direct_effect_terminal_response_encode_denied"))
    }

    pub fn to_terminal_observation(
        &self,
        request: &DirectEffectRequestV1,
    ) -> DirectEffectResult<DirectEffectTerminalObservationV1> {
        let canonical = self.canonical_bytes(request)?;
        Ok(DirectEffectTerminalObservationV1 {
            schema: TERMINAL_OBSERVATION_SCHEMA.to_string(),
            kind: self.kind,
            exit_code: self.exit_code,
            signal: self.signal,
            backend_error_code: self.backend_error_code.clone(),
            stdout_bytes: self.stdout.bytes,
            stderr_bytes: self.stderr.bytes,
            stdout_sha256: self.stdout.sha256.clone(),
            stderr_sha256: self.stderr.sha256.clone(),
            started_boottime_ms: self.started_boottime_ms,
            finished_boottime_ms: self.finished_boottime_ms,
            response_sha256: crate::sha256_bytes(&canonical),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectEffectTerminalObservationV1 {
    pub schema: String,
    pub kind: DirectEffectTerminalKindV1,
    pub exit_code: Option<i32>,
    pub signal: Option<u32>,
    pub backend_error_code: Option<String>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub started_boottime_ms: u64,
    pub finished_boottime_ms: u64,
    pub response_sha256: String,
}

impl DirectEffectTerminalObservationV1 {
    pub fn validate_for_request(&self, request: &DirectEffectRequestV1) -> DirectEffectResult<()> {
        request.validate()?;
        self.validate_shape()?;
        let total = self
            .stdout_bytes
            .checked_add(self.stderr_bytes)
            .ok_or_else(|| denied("direct_effect_terminal_output_denied"))?;
        if self.stdout_bytes > request.arguments.stdout_limit_bytes
            || self.stderr_bytes > request.arguments.stderr_limit_bytes
            || total > request.arguments.total_output_limit_bytes
        {
            return Err(denied("direct_effect_terminal_output_denied"));
        }
        let is_restart_before_dispatch = self.kind
            == DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch
            && self.backend_error_code.as_deref()
                == Some(BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE);
        match self.kind {
            DirectEffectTerminalKindV1::DeadlineBeforeDispatch
                if self.started_boottime_ms < request.absolute_deadline_boottime_ms =>
            {
                return Err(denied("direct_effect_terminal_deadline_denied"));
            }
            DirectEffectTerminalKindV1::CancelledBeforeDispatch
            | DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch
                if self.started_boottime_ms >= request.absolute_deadline_boottime_ms
                    && !is_restart_before_dispatch =>
            {
                return Err(denied("direct_effect_terminal_deadline_denied"));
            }
            _ => {}
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> DirectEffectResult<String> {
        self.validate_shape()?;
        let mut hasher = domain_hasher(TERMINAL_OBSERVATION_HASH_DOMAIN);
        hash_string_field(&mut hasher, "schema", &self.schema);
        hash_string_field(&mut hasher, "kind", self.kind.as_str());
        hash_optional_i32_field(&mut hasher, "exit_code", self.exit_code);
        hash_optional_u32_field(&mut hasher, "signal", self.signal);
        hash_optional_string_field(
            &mut hasher,
            "backend_error_code",
            self.backend_error_code.as_deref(),
        );
        hash_u64_field(&mut hasher, "stdout_bytes", self.stdout_bytes);
        hash_u64_field(&mut hasher, "stderr_bytes", self.stderr_bytes);
        hash_string_field(&mut hasher, "stdout_sha256", &self.stdout_sha256);
        hash_string_field(&mut hasher, "stderr_sha256", &self.stderr_sha256);
        hash_u64_field(&mut hasher, "started_boottime_ms", self.started_boottime_ms);
        hash_u64_field(
            &mut hasher,
            "finished_boottime_ms",
            self.finished_boottime_ms,
        );
        hash_string_field(&mut hasher, "response_sha256", &self.response_sha256);
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_shape(&self) -> DirectEffectResult<()> {
        let outcome_valid = match self.kind {
            DirectEffectTerminalKindV1::Exited => {
                self.exit_code.is_some()
                    && self.signal.is_none()
                    && self.backend_error_code.is_none()
            }
            DirectEffectTerminalKindV1::Signaled => {
                self.exit_code.is_none()
                    && self.signal.is_some_and(|signal| (1..=64).contains(&signal))
                    && self.backend_error_code.is_none()
            }
            DirectEffectTerminalKindV1::LaunchRejected => {
                self.exit_code.is_none()
                    && self.signal.is_none()
                    && self
                        .backend_error_code
                        .as_deref()
                        .is_some_and(valid_error_code)
                    && self.stdout_bytes == 0
                    && self.stderr_bytes == 0
            }
            DirectEffectTerminalKindV1::CancelledBeforeDispatch
            | DirectEffectTerminalKindV1::DeadlineBeforeDispatch => {
                self.exit_code.is_none()
                    && self.signal.is_none()
                    && self.backend_error_code.is_none()
                    && self.stdout_bytes == 0
                    && self.stderr_bytes == 0
                    && self.finished_boottime_ms == self.started_boottime_ms
            }
            DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch => {
                self.exit_code.is_none()
                    && self.signal.is_none()
                    && self
                        .backend_error_code
                        .as_deref()
                        .is_some_and(valid_error_code)
                    && self.stdout_bytes == 0
                    && self.stderr_bytes == 0
                    && self.finished_boottime_ms == self.started_boottime_ms
            }
        };
        if self.schema != TERMINAL_OBSERVATION_SCHEMA
            || !outcome_valid
            || !crate::is_nonzero_lower_sha256(&self.stdout_sha256)
            || !crate::is_nonzero_lower_sha256(&self.stderr_sha256)
            || self.started_boottime_ms == 0
            || self.finished_boottime_ms < self.started_boottime_ms
            || !crate::is_nonzero_lower_sha256(&self.response_sha256)
        {
            return Err(denied("direct_effect_terminal_observation_denied"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectEffectPhaseV1 {
    NotDispatched,
    Dispatched,
    Terminal,
    Indeterminate,
}

impl DirectEffectPhaseV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotDispatched => "not_dispatched",
            Self::Dispatched => "dispatched",
            Self::Terminal => "terminal",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DirectEffectIndeterminateReasonV1 {
    DeadlineAfterDispatch,
    CancelledAfterDispatch,
    OutputLimitAfterDispatch,
    BrokerRestartAfterDispatch,
    BackendLostAfterDispatch,
}

impl DirectEffectIndeterminateReasonV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeadlineAfterDispatch => "deadline_after_dispatch",
            Self::CancelledAfterDispatch => "cancelled_after_dispatch",
            Self::OutputLimitAfterDispatch => "output_limit_after_dispatch",
            Self::BrokerRestartAfterDispatch => "broker_restart_after_dispatch",
            Self::BackendLostAfterDispatch => "backend_lost_after_dispatch",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectEffectRecoveryActionV1 {
    AwaitAuthenticatedRetryBeforeDispatch,
    PersistIndeterminateWithoutRetry,
    ReplayExactTerminalResponse,
    HoldWithoutRetry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectEffectTransitionV1 {
    MarkDispatched {
        started_boottime_ms: u64,
        dispatch_binding_sha256: String,
    },
    RecordNotDispatchedTerminal {
        observation: DirectEffectTerminalObservationV1,
    },
    RecordTerminal {
        observation: DirectEffectTerminalObservationV1,
    },
    HoldIndeterminate {
        reason: DirectEffectIndeterminateReasonV1,
        observed_boottime_ms: u64,
    },
}

/// Pure durable-state record. Exact response bytes are retained by the future
/// broker and bound here by `response_sha256`; this type never performs I/O.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DirectEffectDurableStateV1 {
    pub schema: String,
    pub effect_id: String,
    pub request_sha256: String,
    pub generation: u64,
    pub phase: DirectEffectPhaseV1,
    pub previous_state_sha256: Option<String>,
    pub dispatch_occurred: bool,
    pub dispatch_started_boottime_ms: Option<u64>,
    pub dispatch_binding_sha256: Option<String>,
    pub terminal_observation: Option<DirectEffectTerminalObservationV1>,
    pub indeterminate_reason: Option<DirectEffectIndeterminateReasonV1>,
    pub indeterminate_observed_boottime_ms: Option<u64>,
    pub state_sha256: String,
}

impl DirectEffectDurableStateV1 {
    pub fn not_dispatched(request: &DirectEffectRequestV1) -> DirectEffectResult<Self> {
        request.validate()?;
        let mut state = Self {
            schema: STATE_SCHEMA.to_string(),
            effect_id: request.effect_id.clone(),
            request_sha256: request.request_sha256.clone(),
            generation: 1,
            phase: DirectEffectPhaseV1::NotDispatched,
            previous_state_sha256: None,
            dispatch_occurred: false,
            dispatch_started_boottime_ms: None,
            dispatch_binding_sha256: None,
            terminal_observation: None,
            indeterminate_reason: None,
            indeterminate_observed_boottime_ms: None,
            state_sha256: String::new(),
        };
        state.state_sha256 = state.expected_state_sha256()?;
        state.validate()?;
        Ok(state)
    }

    pub fn transition(
        &self,
        request: &DirectEffectRequestV1,
        transition: DirectEffectTransitionV1,
    ) -> DirectEffectResult<Self> {
        self.validate()?;
        request.validate()?;
        if self.effect_id != request.effect_id || self.request_sha256 != request.request_sha256 {
            return Err(denied("direct_effect_transition_request_denied"));
        }
        let mut successor = match (self.phase, transition) {
            (
                DirectEffectPhaseV1::NotDispatched,
                DirectEffectTransitionV1::MarkDispatched {
                    started_boottime_ms,
                    dispatch_binding_sha256,
                },
            ) => {
                if started_boottime_ms == 0
                    || started_boottime_ms >= request.absolute_deadline_boottime_ms
                    || !crate::is_nonzero_lower_sha256(&dispatch_binding_sha256)
                {
                    return Err(denied("direct_effect_dispatch_marker_denied"));
                }
                Self {
                    schema: STATE_SCHEMA.to_string(),
                    effect_id: self.effect_id.clone(),
                    request_sha256: self.request_sha256.clone(),
                    generation: 2,
                    phase: DirectEffectPhaseV1::Dispatched,
                    previous_state_sha256: Some(self.state_sha256.clone()),
                    dispatch_occurred: true,
                    dispatch_started_boottime_ms: Some(started_boottime_ms),
                    dispatch_binding_sha256: Some(dispatch_binding_sha256),
                    terminal_observation: None,
                    indeterminate_reason: None,
                    indeterminate_observed_boottime_ms: None,
                    state_sha256: String::new(),
                }
            }
            (
                DirectEffectPhaseV1::NotDispatched,
                DirectEffectTransitionV1::RecordNotDispatchedTerminal { observation },
            ) => {
                observation.validate_for_request(request)?;
                if observation.kind.dispatch_occurred() {
                    return Err(denied("direct_effect_not_dispatched_terminal_denied"));
                }
                Self {
                    schema: STATE_SCHEMA.to_string(),
                    effect_id: self.effect_id.clone(),
                    request_sha256: self.request_sha256.clone(),
                    generation: 2,
                    phase: DirectEffectPhaseV1::Terminal,
                    previous_state_sha256: Some(self.state_sha256.clone()),
                    dispatch_occurred: false,
                    dispatch_started_boottime_ms: None,
                    dispatch_binding_sha256: None,
                    terminal_observation: Some(observation),
                    indeterminate_reason: None,
                    indeterminate_observed_boottime_ms: None,
                    state_sha256: String::new(),
                }
            }
            (
                DirectEffectPhaseV1::Dispatched,
                DirectEffectTransitionV1::RecordTerminal { observation },
            ) => {
                observation.validate_for_request(request)?;
                if !observation.kind.dispatch_occurred()
                    || Some(observation.started_boottime_ms) != self.dispatch_started_boottime_ms
                {
                    return Err(denied("direct_effect_terminal_dispatch_time_denied"));
                }
                Self {
                    schema: STATE_SCHEMA.to_string(),
                    effect_id: self.effect_id.clone(),
                    request_sha256: self.request_sha256.clone(),
                    generation: 3,
                    phase: DirectEffectPhaseV1::Terminal,
                    previous_state_sha256: Some(self.state_sha256.clone()),
                    dispatch_occurred: true,
                    dispatch_started_boottime_ms: self.dispatch_started_boottime_ms,
                    dispatch_binding_sha256: self.dispatch_binding_sha256.clone(),
                    terminal_observation: Some(observation),
                    indeterminate_reason: None,
                    indeterminate_observed_boottime_ms: None,
                    state_sha256: String::new(),
                }
            }
            (
                DirectEffectPhaseV1::Dispatched,
                DirectEffectTransitionV1::HoldIndeterminate {
                    reason,
                    observed_boottime_ms,
                },
            ) => {
                if observed_boottime_ms
                    < self
                        .dispatch_started_boottime_ms
                        .ok_or_else(|| denied("direct_effect_dispatch_marker_denied"))?
                {
                    return Err(denied("direct_effect_indeterminate_time_denied"));
                }
                Self {
                    schema: STATE_SCHEMA.to_string(),
                    effect_id: self.effect_id.clone(),
                    request_sha256: self.request_sha256.clone(),
                    generation: 3,
                    phase: DirectEffectPhaseV1::Indeterminate,
                    previous_state_sha256: Some(self.state_sha256.clone()),
                    dispatch_occurred: true,
                    dispatch_started_boottime_ms: self.dispatch_started_boottime_ms,
                    dispatch_binding_sha256: self.dispatch_binding_sha256.clone(),
                    terminal_observation: None,
                    indeterminate_reason: Some(reason),
                    indeterminate_observed_boottime_ms: Some(observed_boottime_ms),
                    state_sha256: String::new(),
                }
            }
            _ => return Err(denied("direct_effect_transition_denied")),
        };
        successor.state_sha256 = successor.expected_state_sha256()?;
        successor.validate()?;
        self.validate_successor(&successor)?;
        Ok(successor)
    }

    pub fn validate(&self) -> DirectEffectResult<()> {
        self.validate_hash_material()?;
        if !crate::is_nonzero_lower_sha256(&self.state_sha256)
            || self.expected_state_sha256()? != self.state_sha256
        {
            return Err(denied("direct_effect_state_hash_denied"));
        }
        Ok(())
    }

    pub fn validate_successor(&self, successor: &Self) -> DirectEffectResult<()> {
        self.validate()?;
        successor.validate()?;
        let transition_allowed = matches!(
            (self.phase, successor.phase),
            (
                DirectEffectPhaseV1::NotDispatched,
                DirectEffectPhaseV1::Dispatched | DirectEffectPhaseV1::Terminal
            ) | (
                DirectEffectPhaseV1::Dispatched,
                DirectEffectPhaseV1::Terminal | DirectEffectPhaseV1::Indeterminate
            )
        );
        if !transition_allowed
            || successor.effect_id != self.effect_id
            || successor.request_sha256 != self.request_sha256
            || successor.generation != self.generation + 1
            || successor.previous_state_sha256.as_deref() != Some(self.state_sha256.as_str())
            || (self.phase == DirectEffectPhaseV1::Dispatched
                && (successor.dispatch_started_boottime_ms != self.dispatch_started_boottime_ms
                    || successor.dispatch_binding_sha256 != self.dispatch_binding_sha256
                    || !successor.dispatch_occurred))
            || (self.phase == DirectEffectPhaseV1::NotDispatched
                && successor.phase == DirectEffectPhaseV1::Terminal
                && successor.dispatch_occurred)
        {
            return Err(denied("direct_effect_successor_denied"));
        }
        Ok(())
    }

    pub fn recovery_action(&self) -> DirectEffectResult<DirectEffectRecoveryActionV1> {
        self.validate()?;
        Ok(match self.phase {
            DirectEffectPhaseV1::NotDispatched => {
                DirectEffectRecoveryActionV1::AwaitAuthenticatedRetryBeforeDispatch
            }
            DirectEffectPhaseV1::Dispatched => {
                DirectEffectRecoveryActionV1::PersistIndeterminateWithoutRetry
            }
            DirectEffectPhaseV1::Terminal => {
                DirectEffectRecoveryActionV1::ReplayExactTerminalResponse
            }
            DirectEffectPhaseV1::Indeterminate => DirectEffectRecoveryActionV1::HoldWithoutRetry,
        })
    }

    pub fn expected_state_sha256(&self) -> DirectEffectResult<String> {
        self.validate_hash_material()?;
        let mut hasher = domain_hasher(STATE_HASH_DOMAIN);
        hash_string_field(&mut hasher, "schema", &self.schema);
        hash_string_field(&mut hasher, "effect_id", &self.effect_id);
        hash_string_field(&mut hasher, "request_sha256", &self.request_sha256);
        hash_u64_field(&mut hasher, "generation", self.generation);
        hash_string_field(&mut hasher, "phase", self.phase.as_str());
        hash_optional_string_field(
            &mut hasher,
            "previous_state_sha256",
            self.previous_state_sha256.as_deref(),
        );
        hash_bytes_field(
            &mut hasher,
            "dispatch_occurred",
            &[u8::from(self.dispatch_occurred)],
        );
        hash_optional_u64_field(
            &mut hasher,
            "dispatch_started_boottime_ms",
            self.dispatch_started_boottime_ms,
        );
        hash_optional_string_field(
            &mut hasher,
            "dispatch_binding_sha256",
            self.dispatch_binding_sha256.as_deref(),
        );
        let terminal_sha256 = self
            .terminal_observation
            .as_ref()
            .map(DirectEffectTerminalObservationV1::canonical_sha256)
            .transpose()?;
        hash_optional_string_field(
            &mut hasher,
            "terminal_observation_sha256",
            terminal_sha256.as_deref(),
        );
        hash_optional_string_field(
            &mut hasher,
            "indeterminate_reason",
            self.indeterminate_reason.map(|reason| reason.as_str()),
        );
        hash_optional_u64_field(
            &mut hasher,
            "indeterminate_observed_boottime_ms",
            self.indeterminate_observed_boottime_ms,
        );
        Ok(lower_hex(&hasher.finalize()))
    }

    fn validate_hash_material(&self) -> DirectEffectResult<()> {
        if self.schema != STATE_SCHEMA
            || !valid_prefixed_sha256(&self.effect_id, EFFECT_ID_PREFIX)
            || !crate::is_nonzero_lower_sha256(&self.request_sha256)
        {
            return Err(denied("direct_effect_state_material_denied"));
        }
        let valid_phase_shape = match self.phase {
            DirectEffectPhaseV1::NotDispatched => {
                self.generation == 1
                    && !self.dispatch_occurred
                    && self.previous_state_sha256.is_none()
                    && self.dispatch_started_boottime_ms.is_none()
                    && self.dispatch_binding_sha256.is_none()
                    && self.terminal_observation.is_none()
                    && self.indeterminate_reason.is_none()
                    && self.indeterminate_observed_boottime_ms.is_none()
            }
            DirectEffectPhaseV1::Dispatched => {
                self.generation == 2
                    && self.dispatch_occurred
                    && self
                        .previous_state_sha256
                        .as_deref()
                        .is_some_and(crate::is_nonzero_lower_sha256)
                    && self
                        .dispatch_started_boottime_ms
                        .is_some_and(|value| value > 0)
                    && self
                        .dispatch_binding_sha256
                        .as_deref()
                        .is_some_and(crate::is_nonzero_lower_sha256)
                    && self.terminal_observation.is_none()
                    && self.indeterminate_reason.is_none()
                    && self.indeterminate_observed_boottime_ms.is_none()
            }
            DirectEffectPhaseV1::Terminal => {
                matches!(self.generation, 2 | 3)
                    && self
                        .previous_state_sha256
                        .as_deref()
                        .is_some_and(crate::is_nonzero_lower_sha256)
                    && self.terminal_observation.as_ref().is_some_and(|value| {
                        value.validate_shape().is_ok()
                            && value.kind.dispatch_occurred() == self.dispatch_occurred
                            && if self.dispatch_occurred {
                                self.generation == 3
                                    && Some(value.started_boottime_ms)
                                        == self.dispatch_started_boottime_ms
                                    && self
                                        .dispatch_binding_sha256
                                        .as_deref()
                                        .is_some_and(crate::is_nonzero_lower_sha256)
                            } else {
                                self.generation == 2
                                    && self.dispatch_started_boottime_ms.is_none()
                                    && self.dispatch_binding_sha256.is_none()
                            }
                    })
                    && self.indeterminate_reason.is_none()
                    && self.indeterminate_observed_boottime_ms.is_none()
            }
            DirectEffectPhaseV1::Indeterminate => {
                self.generation == 3
                    && self.dispatch_occurred
                    && self
                        .previous_state_sha256
                        .as_deref()
                        .is_some_and(crate::is_nonzero_lower_sha256)
                    && self
                        .dispatch_started_boottime_ms
                        .is_some_and(|value| value > 0)
                    && self
                        .dispatch_binding_sha256
                        .as_deref()
                        .is_some_and(crate::is_nonzero_lower_sha256)
                    && self.terminal_observation.is_none()
                    && self.indeterminate_reason.is_some()
                    && self
                        .indeterminate_observed_boottime_ms
                        .is_some_and(|observed| {
                            self.dispatch_started_boottime_ms
                                .is_some_and(|started| observed >= started)
                        })
            }
        };
        if !valid_phase_shape {
            return Err(denied("direct_effect_state_phase_denied"));
        }
        Ok(())
    }
}

#[must_use]
pub fn embedded_contract_measurement_is_exact() -> bool {
    crate::sha256_bytes(include_bytes!("../contracts/direct-effect-v1.json")) == CONTRACT_SHA256
}

fn derive_effect_id(
    direct_binding_sha256: &str,
    invocation_id: &str,
    delivery_provider_attempt_id: &str,
    os_tool_call_id: &str,
    adapter_effect_ordinal: u64,
    tool: DirectEffectToolV1,
) -> DirectEffectResult<String> {
    if !crate::is_nonzero_lower_sha256(direct_binding_sha256)
        || !valid_prefixed_sha256(invocation_id, INVOCATION_ID_PREFIX)
        || !valid_prefixed_sha256(delivery_provider_attempt_id, PROVIDER_ATTEMPT_ID_PREFIX)
        || !valid_prefixed_sha256(os_tool_call_id, OS_TOOL_CALL_ID_PREFIX)
        || adapter_effect_ordinal == 0
    {
        return Err(denied("direct_effect_id_material_denied"));
    }
    let mut hasher = domain_hasher(EFFECT_ID_HASH_DOMAIN);
    hash_string_field(&mut hasher, "direct_binding_sha256", direct_binding_sha256);
    hash_string_field(&mut hasher, "invocation_id", invocation_id);
    hash_string_field(
        &mut hasher,
        "delivery_provider_attempt_id",
        delivery_provider_attempt_id,
    );
    hash_string_field(&mut hasher, "os_tool_call_id", os_tool_call_id);
    hash_u64_field(
        &mut hasher,
        "adapter_effect_ordinal",
        adapter_effect_ordinal,
    );
    hash_string_field(&mut hasher, "tool", tool.as_str());
    Ok(format!(
        "{EFFECT_ID_PREFIX}{}",
        lower_hex(&hasher.finalize())
    ))
}

fn valid_prefixed_sha256(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(crate::is_nonzero_lower_sha256)
}

fn valid_error_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn denied(code: &'static str) -> DirectEffectError {
    DirectEffectError(code)
}

fn usize_to_u64(value: usize) -> DirectEffectResult<u64> {
    u64::try_from(value).map_err(|_| denied("direct_effect_length_denied"))
}

fn domain_hasher(domain: &str) -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hasher
}

fn hash_string_field(hasher: &mut Sha256, name: &str, value: &str) {
    hash_bytes_field(hasher, name, value.as_bytes());
}

fn hash_u64_field(hasher: &mut Sha256, name: &str, value: u64) {
    hash_bytes_field(hasher, name, &value.to_be_bytes());
}

fn hash_bytes_field(hasher: &mut Sha256, name: &str, value: &[u8]) {
    hasher.update((name.len() as u64).to_be_bytes());
    hasher.update(name.as_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn hash_optional_string_field(hasher: &mut Sha256, name: &str, value: Option<&str>) {
    match value {
        Some(value) => {
            hash_bytes_field(hasher, name, &[1]);
            hash_string_field(hasher, name, value);
        }
        None => hash_bytes_field(hasher, name, &[0]),
    }
}

fn hash_optional_u64_field(hasher: &mut Sha256, name: &str, value: Option<u64>) {
    match value {
        Some(value) => {
            hash_bytes_field(hasher, name, &[1]);
            hash_u64_field(hasher, name, value);
        }
        None => hash_bytes_field(hasher, name, &[0]),
    }
}

fn hash_optional_u32_field(hasher: &mut Sha256, name: &str, value: Option<u32>) {
    match value {
        Some(value) => {
            hash_bytes_field(hasher, name, &[1]);
            hash_bytes_field(hasher, name, &value.to_be_bytes());
        }
        None => hash_bytes_field(hasher, name, &[0]),
    }
}

fn hash_optional_i32_field(hasher: &mut Sha256, name: &str, value: Option<i32>) {
    match value {
        Some(value) => {
            hash_bytes_field(hasher, name, &[1]);
            hash_bytes_field(hasher, name, &value.to_be_bytes());
        }
        None => hash_bytes_field(hasher, name, &[0]),
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn digest(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn arguments() -> DirectEffectModelArgumentsV1 {
        DirectEffectModelArgumentsV1 {
            argv: vec![
                "/usr/bin/printf".to_string(),
                "%s:%s".to_string(),
                String::new(),
                "value".to_string(),
            ],
            cwd: Some(DirectEffectWorkingDirectoryV1 {
                scope: DirectEffectWorkingDirectoryScopeV1::Workspace,
                relative: "project/subdir".to_string(),
            }),
            timeout_ms: 10_000,
            stdout_limit_bytes: 65_536,
            stderr_limit_bytes: 32_768,
            total_output_limit_bytes: 65_536,
            requested_profile: DirectEffectExecutionProfileV1::Standard,
        }
    }

    fn request() -> DirectEffectRequestV1 {
        request_with_policy(
            DirectEffectExecutionProfileV1::Standard,
            DirectEffectRiskClassV1::Standard,
            None,
        )
    }

    fn request_with_policy(
        profile: DirectEffectExecutionProfileV1,
        risk_class: DirectEffectRiskClassV1,
        lease: Option<String>,
    ) -> DirectEffectRequestV1 {
        let mut arguments = arguments();
        arguments.requested_profile = profile;
        DirectEffectRequestV1::derive_os_owned(
            agent_descriptor_registry::CODEX.provider_id.to_string(),
            agent_descriptor_registry::CODEX.agent_id.to_string(),
            digest('1'),
            format!("{INVOCATION_ID_PREFIX}{}", digest('2')),
            format!("{PROVIDER_ATTEMPT_ID_PREFIX}{}", digest('3')),
            format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('4')),
            1,
            digest('5'),
            digest('6'),
            digest('7'),
            DirectEffectToolV1::ShellExecV1,
            arguments,
            50_000,
            profile,
            risk_class,
            lease,
            digest('8'),
            digest('9'),
        )
        .expect("canonical request")
    }

    fn terminal(started: u64) -> DirectEffectTerminalObservationV1 {
        DirectEffectTerminalObservationV1 {
            schema: TERMINAL_OBSERVATION_SCHEMA.to_string(),
            kind: DirectEffectTerminalKindV1::Exited,
            exit_code: Some(0),
            signal: None,
            backend_error_code: None,
            stdout_bytes: 12,
            stderr_bytes: 3,
            stdout_sha256: digest('a'),
            stderr_sha256: digest('b'),
            started_boottime_ms: started,
            finished_boottime_ms: started + 5,
            response_sha256: digest('c'),
        }
    }

    fn terminal_response(
        request: &DirectEffectRequestV1,
        kind: DirectEffectTerminalKindV1,
        stdout: &[u8],
        stderr: &[u8],
        observed_boottime_ms: u64,
    ) -> DirectEffectTerminalResponseV1 {
        let (exit_code, signal, backend_error_code) = match kind {
            DirectEffectTerminalKindV1::Exited => (Some(0), None, None),
            DirectEffectTerminalKindV1::Signaled => (None, Some(9), None),
            DirectEffectTerminalKindV1::LaunchRejected => {
                (None, None, Some("execveat_denied".to_string()))
            }
            DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch => (
                None,
                None,
                Some("standard_profile_policy_denied".to_string()),
            ),
            DirectEffectTerminalKindV1::CancelledBeforeDispatch
            | DirectEffectTerminalKindV1::DeadlineBeforeDispatch => (None, None, None),
        };
        DirectEffectTerminalResponseV1 {
            schema: TERMINAL_RESPONSE_SCHEMA.to_string(),
            effect_id: request.effect_id.clone(),
            request_sha256: request.request_sha256.clone(),
            dispatch_occurred: kind.dispatch_occurred(),
            kind,
            exit_code,
            signal,
            backend_error_code,
            stdout: DirectEffectBinaryOutputV1::from_complete_bytes(stdout),
            stderr: DirectEffectBinaryOutputV1::from_complete_bytes(stderr),
            started_boottime_ms: observed_boottime_ms,
            finished_boottime_ms: if kind.dispatch_occurred() {
                observed_boottime_ms + 5
            } else {
                observed_boottime_ms
            },
        }
    }

    #[test]
    fn embedded_contract_and_source_holds_are_exact() {
        assert!(embedded_contract_measurement_is_exact());
        assert!(SOURCE_PROTOCOL_IMPLEMENTED);
        assert!(PURE_DURABLE_STATE_MACHINE_IMPLEMENTED);
        assert!(PRODUCT_LISTENER_WIRED);
        assert!(PRODUCT_BACKEND_WIRED);
        assert!(!PRODUCT_EFFECT_AUTHORITY_AVAILABLE);
        assert!(!CONFERS_EFFECT_AUTHORITY);
    }

    #[test]
    fn model_arguments_are_closed_and_preserve_empty_nonzero_arguments() {
        let arguments = arguments();
        arguments.validate().unwrap();
        let encoded = serde_json::to_vec(&arguments).unwrap();
        let decoded: DirectEffectModelArgumentsV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.argv[2], "");
        assert_eq!(decoded, arguments);

        for forbidden in [
            "provider_id",
            "agent_id",
            "direct_binding_sha256",
            "invocation_id",
            "delivery_provider_attempt_id",
            "os_tool_call_id",
            "adapter_effect_ordinal",
            "effect_id",
            "absolute_deadline_boottime_ms",
            "effective_profile",
            "risk_class",
            "confirmation_lease_receipt_sha256",
            "policy_sha256",
            "backend_identity_sha256",
            "request_sha256",
            "serial",
            "host",
            "port",
            "build_type",
            "enable_token",
        ] {
            let mut value = serde_json::to_value(&arguments).unwrap();
            value[forbidden] = json!("caller-controlled");
            assert!(serde_json::from_value::<DirectEffectModelArgumentsV1>(value).is_err());
        }
    }

    #[test]
    fn model_argument_bounds_and_paths_fail_closed() {
        let mut value = arguments();
        value.argv.clear();
        assert_eq!(
            value.validate().unwrap_err().code(),
            "direct_effect_argv_shape_denied"
        );

        let mut value = arguments();
        value.argv[0].clear();
        assert!(value.validate().is_err());

        let mut value = arguments();
        value.argv = vec!["x".to_string(); MAX_ARGV_COUNT + 1];
        assert!(value.validate().is_err());

        let mut value = arguments();
        value.argv[1] = "x".repeat(MAX_ARGUMENT_BYTES + 1);
        assert!(value.validate().is_err());

        let mut value = arguments();
        value.argv[1] = "nul\0argument".to_string();
        assert!(value.validate().is_err());

        for relative in ["", ".", "..", "../escape", "/absolute", "a/./b", "a//b"] {
            let mut value = arguments();
            value.cwd.as_mut().unwrap().relative = relative.to_string();
            assert!(value.validate().is_err(), "accepted cwd {relative:?}");
        }

        for mutation in [
            |value: &mut DirectEffectModelArgumentsV1| value.timeout_ms = 0,
            |value: &mut DirectEffectModelArgumentsV1| value.timeout_ms = MAX_TIMEOUT_MS + 1,
            |value: &mut DirectEffectModelArgumentsV1| value.stdout_limit_bytes = 0,
            |value: &mut DirectEffectModelArgumentsV1| {
                value.stderr_limit_bytes = value.total_output_limit_bytes + 1
            },
            |value: &mut DirectEffectModelArgumentsV1| {
                value.total_output_limit_bytes = MAX_OUTPUT_BYTES + 1
            },
        ] {
            let mut value = arguments();
            mutation(&mut value);
            assert!(value.validate().is_err());
        }
    }

    #[test]
    fn request_is_closed_os_bound_and_hash_sensitive() {
        let request = request();
        request.validate().unwrap();
        assert!(request.effect_id.starts_with(EFFECT_ID_PREFIX));
        assert_eq!(
            request.request_sha256,
            request.expected_request_sha256().unwrap()
        );

        let encoded = serde_json::to_vec(&request).unwrap();
        let decoded: DirectEffectRequestV1 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, request);

        for forbidden in ["serial", "host", "port", "enable_token", "unknown"] {
            let mut value = serde_json::to_value(&request).unwrap();
            value[forbidden] = json!("caller-controlled");
            assert!(serde_json::from_value::<DirectEffectRequestV1>(value).is_err());
        }

        let mut drift = request.clone();
        drift.provider_id = "caller-provider".to_string();
        assert!(drift.validate().is_err());
        let mut drift = request.clone();
        drift.agent_id = "caller-agent".to_string();
        assert!(drift.validate().is_err());
        let mut drift = request.clone();
        drift.os_tool_call_id = format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('d'));
        assert!(drift.validate().is_err());
        let mut drift = request.clone();
        drift.arguments.argv.push(String::new());
        assert!(drift.validate().is_err());
        let mut drift = request.clone();
        drift.request_sha256 = digest('e');
        assert!(drift.validate().is_err());
    }

    #[test]
    fn every_os_owned_request_boundary_rejects_unbound_drift() {
        let request = request();
        let mutations = [
            ("schema", json!("org.trillionnium.direct-effect.request.v2")),
            ("contract_sha256", json!(digest('a'))),
            ("provider_id", json!("caller-provider")),
            ("agent_id", json!("caller-agent")),
            ("direct_binding_sha256", json!(digest('a'))),
            (
                "invocation_id",
                json!(format!("{INVOCATION_ID_PREFIX}{}", digest('a'))),
            ),
            (
                "delivery_provider_attempt_id",
                json!(format!("{PROVIDER_ATTEMPT_ID_PREFIX}{}", digest('a'))),
            ),
            (
                "os_tool_call_id",
                json!(format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('a'))),
            ),
            ("adapter_effect_ordinal", json!(2)),
            (
                "effect_id",
                json!(format!("{EFFECT_ID_PREFIX}{}", digest('a'))),
            ),
            ("allocation_record_sha256", json!(digest('a'))),
            ("kernel_launch_custody_sha256", json!(digest('a'))),
            ("boot_id_sha256", json!(digest('a'))),
            ("absolute_deadline_boottime_ms", json!(0)),
            ("effective_profile", json!("elevated")),
            ("risk_class", json!("destructive")),
            ("confirmation_lease_receipt_sha256", json!(digest('a'))),
            ("policy_sha256", json!(digest('a'))),
            ("backend_identity_sha256", json!(digest('a'))),
            ("request_sha256", json!(digest('a'))),
        ];
        for (field, replacement) in mutations {
            let mut raw = serde_json::to_value(&request).unwrap();
            raw[field] = replacement;
            let drift: DirectEffectRequestV1 = serde_json::from_value(raw).unwrap();
            assert!(drift.validate().is_err(), "accepted drift in {field}");
        }

        let mut changed_arguments = serde_json::to_value(&request).unwrap();
        changed_arguments["arguments"]["argv"][1] = json!("changed");
        let changed_arguments: DirectEffectRequestV1 =
            serde_json::from_value(changed_arguments).unwrap();
        assert!(changed_arguments.validate().is_err());

        let mut changed_tool = serde_json::to_value(&request).unwrap();
        changed_tool["tool"] = json!("adb_shell_local_v1");
        let changed_tool: DirectEffectRequestV1 = serde_json::from_value(changed_tool).unwrap();
        assert!(changed_tool.validate().is_err());
    }

    #[test]
    fn profile_risk_and_confirmation_receipt_are_os_coherent() {
        request().validate().unwrap();
        request_with_policy(
            DirectEffectExecutionProfileV1::Elevated,
            DirectEffectRiskClassV1::Elevated,
            Some(digest('d')),
        )
        .validate()
        .unwrap();
        request_with_policy(
            DirectEffectExecutionProfileV1::Standard,
            DirectEffectRiskClassV1::Destructive,
            Some(digest('e')),
        )
        .validate()
        .unwrap();

        let mut standard_with_lease = request();
        standard_with_lease.confirmation_lease_receipt_sha256 = Some(digest('f'));
        assert!(standard_with_lease.expected_request_sha256().is_err());
        assert!(standard_with_lease.validate().is_err());

        let elevated_without_lease = DirectEffectRequestV1::derive_os_owned(
            agent_descriptor_registry::CODEX.provider_id.to_string(),
            agent_descriptor_registry::CODEX.agent_id.to_string(),
            digest('1'),
            format!("{INVOCATION_ID_PREFIX}{}", digest('2')),
            format!("{PROVIDER_ATTEMPT_ID_PREFIX}{}", digest('3')),
            format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest('4')),
            1,
            digest('5'),
            digest('6'),
            digest('7'),
            DirectEffectToolV1::ShellExecV1,
            {
                let mut value = arguments();
                value.requested_profile = DirectEffectExecutionProfileV1::Elevated;
                value
            },
            50_000,
            DirectEffectExecutionProfileV1::Elevated,
            DirectEffectRiskClassV1::Elevated,
            None,
            digest('8'),
            digest('9'),
        );
        assert!(elevated_without_lease.is_err());

        let mut mismatch = request();
        mismatch.effective_profile = DirectEffectExecutionProfileV1::Elevated;
        assert!(mismatch.validate().is_err());
    }

    #[test]
    fn enum_and_nested_schemas_reject_unknown_values_and_fields() {
        let mut value = serde_json::to_value(arguments()).unwrap();
        value["requested_profile"] = json!("unbounded_root");
        assert!(serde_json::from_value::<DirectEffectModelArgumentsV1>(value).is_err());

        let mut value = serde_json::to_value(arguments()).unwrap();
        value["cwd"]["path_from_caller"] = json!("/data");
        assert!(serde_json::from_value::<DirectEffectModelArgumentsV1>(value).is_err());

        let mut value = serde_json::to_value(request()).unwrap();
        value["tool"] = json!("adb_shell_remote_v1");
        assert!(serde_json::from_value::<DirectEffectRequestV1>(value).is_err());
    }

    #[test]
    fn canonical_hashes_preserve_order_and_empty_argument_boundaries() {
        let original = arguments();
        let original_hash = original.canonical_sha256().unwrap();
        let mut reordered = original.clone();
        reordered.argv.swap(1, 3);
        assert_ne!(reordered.canonical_sha256().unwrap(), original_hash);
        let mut removed_empty = original.clone();
        removed_empty.argv.remove(2);
        assert_ne!(removed_empty.canonical_sha256().unwrap(), original_hash);
        let mut changed_tool = request();
        changed_tool.tool = DirectEffectToolV1::AdbShellLocalV1;
        assert!(changed_tool.validate().is_err());
    }

    #[test]
    fn durable_state_machine_has_only_the_reviewed_edges() {
        let request = request();
        let prepared = DirectEffectDurableStateV1::not_dispatched(&request).unwrap();
        assert_eq!(prepared.phase, DirectEffectPhaseV1::NotDispatched);
        assert_eq!(
            prepared.recovery_action().unwrap(),
            DirectEffectRecoveryActionV1::AwaitAuthenticatedRetryBeforeDispatch
        );

        assert!(
            prepared
                .transition(
                    &request,
                    DirectEffectTransitionV1::RecordTerminal {
                        observation: terminal(20_000),
                    },
                )
                .is_err()
        );
        assert!(
            prepared
                .transition(
                    &request,
                    DirectEffectTransitionV1::HoldIndeterminate {
                        reason: DirectEffectIndeterminateReasonV1::BackendLostAfterDispatch,
                        observed_boottime_ms: 20_000,
                    },
                )
                .is_err()
        );

        let dispatched = prepared
            .transition(
                &request,
                DirectEffectTransitionV1::MarkDispatched {
                    started_boottime_ms: 20_000,
                    dispatch_binding_sha256: digest('d'),
                },
            )
            .unwrap();
        assert_eq!(dispatched.phase, DirectEffectPhaseV1::Dispatched);
        assert_eq!(
            dispatched.recovery_action().unwrap(),
            DirectEffectRecoveryActionV1::PersistIndeterminateWithoutRetry
        );
        prepared.validate_successor(&dispatched).unwrap();

        let terminal_state = dispatched
            .transition(
                &request,
                DirectEffectTransitionV1::RecordTerminal {
                    observation: terminal(20_000),
                },
            )
            .unwrap();
        assert_eq!(terminal_state.phase, DirectEffectPhaseV1::Terminal);
        assert_eq!(
            terminal_state.recovery_action().unwrap(),
            DirectEffectRecoveryActionV1::ReplayExactTerminalResponse
        );
        dispatched.validate_successor(&terminal_state).unwrap();
        assert!(
            terminal_state
                .transition(
                    &request,
                    DirectEffectTransitionV1::MarkDispatched {
                        started_boottime_ms: 21_000,
                        dispatch_binding_sha256: digest('e'),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn not_dispatched_cancel_deadline_and_policy_are_terminal_without_backend_contact() {
        let request = request();
        for (kind, observed) in [
            (DirectEffectTerminalKindV1::CancelledBeforeDispatch, 49_999),
            (DirectEffectTerminalKindV1::DeadlineBeforeDispatch, 50_000),
            (
                DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch,
                10_000,
            ),
        ] {
            let initial = DirectEffectDurableStateV1::not_dispatched(&request).unwrap();
            let response = terminal_response(&request, kind, b"", b"", observed);
            let observation = response.to_terminal_observation(&request).unwrap();
            let terminal = initial
                .transition(
                    &request,
                    DirectEffectTransitionV1::RecordNotDispatchedTerminal { observation },
                )
                .unwrap();
            assert_eq!(terminal.phase, DirectEffectPhaseV1::Terminal);
            assert!(!terminal.dispatch_occurred);
            assert!(terminal.dispatch_started_boottime_ms.is_none());
            assert!(terminal.dispatch_binding_sha256.is_none());
            assert_eq!(terminal.generation, 2);
            assert_eq!(
                terminal.recovery_action().unwrap(),
                DirectEffectRecoveryActionV1::ReplayExactTerminalResponse
            );
        }

        let initial = DirectEffectDurableStateV1::not_dispatched(&request).unwrap();
        let late_cancel = terminal_response(
            &request,
            DirectEffectTerminalKindV1::CancelledBeforeDispatch,
            b"",
            b"",
            request.absolute_deadline_boottime_ms,
        );
        assert!(late_cancel.validate_for_request(&request).is_err());
        let early_deadline = terminal_response(
            &request,
            DirectEffectTerminalKindV1::DeadlineBeforeDispatch,
            b"",
            b"",
            request.absolute_deadline_boottime_ms - 1,
        );
        assert!(early_deadline.validate_for_request(&request).is_err());
        let mut late_policy = terminal_response(
            &request,
            DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch,
            b"",
            b"",
            request.absolute_deadline_boottime_ms,
        );
        assert!(late_policy.validate_for_request(&request).is_err());
        late_policy.backend_error_code =
            Some(BROKER_RESTART_BEFORE_DISPATCH_ERROR_CODE.to_string());
        // CLOCK_BOOTTIME values from different boot epochs are not ordered.
        // The restart-specific terminal remains valid even when its new-boot
        // observation is numerically beyond the old request's deadline.
        late_policy.validate_for_request(&request).unwrap();
        assert_eq!(initial.phase.as_str(), "not_dispatched");
    }

    #[test]
    fn terminal_response_preserves_non_utf8_nul_and_exact_response_bytes() {
        let request = request();
        let stdout = [0xff, 0x00, 0xfe, b'\n'];
        let stderr = [0x80, 0x81, 0x00];
        let response = terminal_response(
            &request,
            DirectEffectTerminalKindV1::Exited,
            &stdout,
            &stderr,
            20_000,
        );
        response.validate_for_request(&request).unwrap();
        assert_eq!(response.stdout.validate().unwrap(), stdout);
        assert_eq!(response.stderr.validate().unwrap(), stderr);
        let canonical = response.canonical_bytes(&request).unwrap();
        let observation = response.to_terminal_observation(&request).unwrap();
        assert_eq!(observation.response_sha256, crate::sha256_bytes(&canonical));
        assert_eq!(observation.stdout_sha256, crate::sha256_bytes(&stdout));
        assert_eq!(observation.stderr_sha256, crate::sha256_bytes(&stderr));

        let decoded: DirectEffectTerminalResponseV1 = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(decoded, response);
        assert!(!String::from_utf8(canonical).unwrap().contains('\u{fffd}'));

        let mut tampered = response.clone();
        tampered.stdout.data = BASE64_STANDARD.encode(b"different");
        assert!(tampered.validate_for_request(&request).is_err());
        let mut tampered = response.clone();
        tampered.stdout.complete = false;
        assert!(tampered.validate_for_request(&request).is_err());
    }

    #[test]
    fn binary_terminal_response_enforces_each_and_combined_output_limit() {
        let mut request = request();
        request.arguments.stdout_limit_bytes = 16;
        request.arguments.stderr_limit_bytes = 16;
        request.arguments.total_output_limit_bytes = 16;
        request.request_sha256 = request.expected_request_sha256().unwrap();
        request.validate().unwrap();

        terminal_response(
            &request,
            DirectEffectTerminalKindV1::Exited,
            &[0xff; 8],
            &[0x00; 8],
            20_000,
        )
        .validate_for_request(&request)
        .unwrap();
        assert!(
            terminal_response(
                &request,
                DirectEffectTerminalKindV1::Exited,
                &[0xff; 9],
                &[0x00; 8],
                20_000,
            )
            .validate_for_request(&request)
            .is_err()
        );
        assert!(
            terminal_response(
                &request,
                DirectEffectTerminalKindV1::Exited,
                &[0xff; 17],
                b"",
                20_000,
            )
            .validate_for_request(&request)
            .is_err()
        );
    }

    #[test]
    fn dispatch_recovery_becomes_indeterminate_and_never_retries() {
        let request = request();
        let prepared = DirectEffectDurableStateV1::not_dispatched(&request).unwrap();
        let dispatched = prepared
            .transition(
                &request,
                DirectEffectTransitionV1::MarkDispatched {
                    started_boottime_ms: 20_000,
                    dispatch_binding_sha256: digest('d'),
                },
            )
            .unwrap();
        let indeterminate = dispatched
            .transition(
                &request,
                DirectEffectTransitionV1::HoldIndeterminate {
                    reason: DirectEffectIndeterminateReasonV1::BrokerRestartAfterDispatch,
                    observed_boottime_ms: 20_001,
                },
            )
            .unwrap();
        assert_eq!(indeterminate.phase, DirectEffectPhaseV1::Indeterminate);
        assert_eq!(
            indeterminate.recovery_action().unwrap(),
            DirectEffectRecoveryActionV1::HoldWithoutRetry
        );
        assert!(
            indeterminate
                .transition(
                    &request,
                    DirectEffectTransitionV1::RecordTerminal {
                        observation: terminal(20_000),
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn state_hash_chain_and_terminal_output_bounds_reject_drift() {
        let request = request();
        let prepared = DirectEffectDurableStateV1::not_dispatched(&request).unwrap();
        let dispatched = prepared
            .transition(
                &request,
                DirectEffectTransitionV1::MarkDispatched {
                    started_boottime_ms: 20_000,
                    dispatch_binding_sha256: digest('d'),
                },
            )
            .unwrap();

        let mut oversized = terminal(20_000);
        oversized.stdout_bytes = request.arguments.total_output_limit_bytes;
        oversized.stderr_bytes = 1;
        assert!(
            dispatched
                .transition(
                    &request,
                    DirectEffectTransitionV1::RecordTerminal {
                        observation: oversized,
                    },
                )
                .is_err()
        );

        let mut drift = dispatched.clone();
        drift.previous_state_sha256 = Some(digest('e'));
        assert!(drift.validate().is_err());

        let mut raw = serde_json::to_value(&dispatched).unwrap();
        raw["backend_pid"] = Value::from(42);
        assert!(serde_json::from_value::<DirectEffectDurableStateV1>(raw).is_err());
    }

    #[test]
    fn terminal_outcome_shapes_are_mutually_exclusive() {
        let request = request();
        let exited = terminal(20_000);
        exited.validate_for_request(&request).unwrap();

        let mut signaled = exited.clone();
        signaled.kind = DirectEffectTerminalKindV1::Signaled;
        signaled.exit_code = None;
        signaled.signal = Some(9);
        signaled.validate_for_request(&request).unwrap();
        signaled.exit_code = Some(137);
        assert!(signaled.validate_for_request(&request).is_err());

        let mut rejected = exited;
        rejected.kind = DirectEffectTerminalKindV1::LaunchRejected;
        rejected.exit_code = None;
        rejected.backend_error_code = Some("execveat_denied".to_string());
        assert!(rejected.validate_for_request(&request).is_err());
        rejected.stdout_bytes = 0;
        rejected.stderr_bytes = 0;
        rejected.stdout_sha256 = crate::sha256_bytes(b"");
        rejected.stderr_sha256 = crate::sha256_bytes(b"");
        rejected.validate_for_request(&request).unwrap();
        rejected.backend_error_code = Some("INVALID ERROR".to_string());
        assert!(rejected.validate_for_request(&request).is_err());
    }
}
