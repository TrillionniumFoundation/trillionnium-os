//! Root-Linux MCP adapter and fixed shell-exec broker transport.
//!
//! The MCP surface accepts only model-visible semantic arguments. It never
//! accepts an effect id, principal, deadline, policy digest, backend identity,
//! serial, host, port, or executable field outside exact `argv[0]`. The Android
//! broker remains the sole future author of the complete
//! [`DirectEffectRequestV1`].

use std::io::{BufRead, Write};
use std::mem::{offset_of, size_of, zeroed};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
#[cfg(feature = "host-conformance")]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(feature = "host-conformance")]
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use trillionnium_agent_direct_tools::{DirectToolError, mcp};
use trillionnium_os_types::direct_effect::{
    DirectEffectDurableStateV1, DirectEffectIndeterminateReasonV1, DirectEffectModelArgumentsV1,
    DirectEffectPhaseV1, DirectEffectRequestV1, DirectEffectTerminalKindV1,
    DirectEffectTerminalResponseV1, DirectEffectToolV1, TERMINAL_RESPONSE_SCHEMA,
};

use crate::{
    INVOCATION_TOKEN_ENV, MCP_SERVER_NAME, MCP_TOOL_NAME, SHELL_BROKER_SELINUX_DOMAIN,
    SHELL_BROKER_UID, SHELL_EXEC_FIRST_SLICE_MAX_TIMEOUT_MS, SHELL_EXEC_MAX_RAW_OUTPUT_BYTES,
    SOCKET_ADDRESS, TRANSPORT_PROTOCOL, TRANSPORT_RESPONSE_PACKET_BYTES_CAP,
    authorization::{
        ShellExecHostControlV1, ShellExecHostRegistrationReceiptV1, ShellExecHostRegistrationV1,
        ShellExecHostRetirementReceiptV1, ShellExecHostRetirementV1, invocation_token_sha256,
    },
    validate_first_slice_arguments, validate_first_slice_request,
};

pub const TRANSPORT_REQUEST_SCHEMA: &str = "org.trillionnium.shell-exec.transport-request.v1";
pub const PRODUCT_TRANSPORT_REQUEST_SCHEMA: &str =
    "org.trillionnium.shell-exec.product-transport-request.v1";
pub const TRANSPORT_RESPONSE_SCHEMA: &str = "org.trillionnium.shell-exec.transport-response.v1";
pub const MCP_RESULT_SCHEMA: &str = "org.trillionnium.shell-exec.mcp-result.v1";
pub const MAX_TRANSPORT_REQUEST_BYTES: usize = 128 * 1024;
pub const MAX_TRANSPORT_RESPONSE_BYTES: usize = TRANSPORT_RESPONSE_PACKET_BYTES_CAP;
const TRANSPORT_TIMEOUT_OVERHEAD_MS: u64 = 5_000;
const REQUESTED_SOCKET_BUFFER_BYTES: libc::c_int = 512 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecTransportRequestV1 {
    pub schema: String,
    pub protocol: String,
    pub invocation_token: String,
    pub adapter_effect_ordinal: u64,
    pub semantic_arguments_sha256: String,
    pub arguments: DirectEffectModelArgumentsV1,
}

impl ShellExecTransportRequestV1 {
    pub fn derive_for_invocation(
        arguments: DirectEffectModelArgumentsV1,
        invocation_token: String,
        adapter_effect_ordinal: u64,
    ) -> Result<Self, DirectToolError> {
        validate_first_slice_arguments(&arguments)
            .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
        invocation_token_sha256(&invocation_token)
            .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
        if adapter_effect_ordinal == 0 {
            return Err(DirectToolError::InvalidRequest(
                "shell exec adapter ordinal must be nonzero".to_string(),
            ));
        }
        let semantic_arguments_sha256 = arguments
            .canonical_sha256()
            .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
        Ok(Self {
            schema: TRANSPORT_REQUEST_SCHEMA.to_string(),
            protocol: TRANSPORT_PROTOCOL.to_string(),
            invocation_token,
            adapter_effect_ordinal,
            semantic_arguments_sha256,
            arguments,
        })
    }

    pub fn validate(&self) -> Result<(), DirectToolError> {
        validate_first_slice_arguments(&self.arguments)
            .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
        let expected = self
            .arguments
            .canonical_sha256()
            .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
        if self.schema != TRANSPORT_REQUEST_SCHEMA
            || self.protocol != TRANSPORT_PROTOCOL
            || invocation_token_sha256(&self.invocation_token).is_err()
            || self.adapter_effect_ordinal == 0
            || self.semantic_arguments_sha256 != expected
        {
            return Err(DirectToolError::InvalidRequest(
                "shell exec transport request binding mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecProductTransportRequestV1 {
    pub schema: String,
    pub protocol: String,
    pub adapter_effect_ordinal: u64,
    pub semantic_arguments_sha256: String,
    pub arguments: DirectEffectModelArgumentsV1,
}

impl ShellExecProductTransportRequestV1 {
    pub fn derive(
        arguments: DirectEffectModelArgumentsV1,
        adapter_effect_ordinal: u64,
    ) -> Result<Self, DirectToolError> {
        validate_first_slice_arguments(&arguments)
            .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
        if adapter_effect_ordinal == 0 {
            return Err(DirectToolError::InvalidRequest(
                "shell exec adapter ordinal must be nonzero".to_string(),
            ));
        }
        let semantic_arguments_sha256 = arguments
            .canonical_sha256()
            .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
        Ok(Self {
            schema: PRODUCT_TRANSPORT_REQUEST_SCHEMA.to_string(),
            protocol: TRANSPORT_PROTOCOL.to_string(),
            adapter_effect_ordinal,
            semantic_arguments_sha256,
            arguments,
        })
    }

    pub fn validate(&self) -> Result<(), DirectToolError> {
        let expected = Self::derive(self.arguments.clone(), self.adapter_effect_ordinal)?;
        if self != &expected {
            return Err(DirectToolError::InvalidRequest(
                "shell exec product transport request binding mismatch".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecTransportResponseV1 {
    pub schema: String,
    pub protocol: String,
    pub request: DirectEffectRequestV1,
    pub durable_state: DirectEffectDurableStateV1,
    pub terminal_response: Option<DirectEffectTerminalResponseV1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellExecPeerIdentityV1 {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub selinux_domain: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShellExecPeerRoleV1 {
    AgentHostRegistration,
    ShellAdapterExecute,
}

impl ShellExecPeerIdentityV1 {
    pub fn classify(&self) -> Result<ShellExecPeerRoleV1, DirectToolError> {
        if self.uid == crate::AGENTD_UID
            && self.gid == crate::AGENTD_GID
            && self.selinux_domain == crate::AGENTD_SELINUX_DOMAIN
        {
            Ok(ShellExecPeerRoleV1::AgentHostRegistration)
        } else if self.uid == crate::SHELL_ADAPTER_UID
            && self.gid == crate::SHELL_ADAPTER_GID
            && self.selinux_domain == crate::SHELL_ADAPTER_SELINUX_DOMAIN
        {
            Ok(ShellExecPeerRoleV1::ShellAdapterExecute)
        } else {
            Err(protocol_error(
                "shell transport peer has no public wire role",
            ))
        }
    }

    pub fn require_agentd(&self) -> Result<(), DirectToolError> {
        if self.uid != crate::AGENTD_UID
            || self.gid != crate::AGENTD_GID
            || self.selinux_domain != crate::AGENTD_SELINUX_DOMAIN
        {
            return Err(protocol_error(
                "shell registration peer is not the fixed root Agent Host",
            ));
        }
        Ok(())
    }

    pub fn require_shell_adapter(&self) -> Result<(), DirectToolError> {
        if self.uid != crate::SHELL_ADAPTER_UID
            || self.gid != crate::SHELL_ADAPTER_GID
            || self.selinux_domain != crate::SHELL_ADAPTER_SELINUX_DOMAIN
        {
            return Err(protocol_error(
                "shell execution peer is not the fixed Codex shell adapter",
            ));
        }
        Ok(())
    }
}

impl ShellExecTransportResponseV1 {
    pub fn terminal(
        request: DirectEffectRequestV1,
        durable_state: DirectEffectDurableStateV1,
        exact_terminal_response: &[u8],
    ) -> Result<Self, DirectToolError> {
        let terminal_response: DirectEffectTerminalResponseV1 =
            serde_json::from_slice(exact_terminal_response)
                .map_err(|_| protocol_error("terminal shell response JSON is invalid"))?;
        if terminal_response
            .canonical_bytes(&request)
            .map_err(|error| protocol_error(&error.to_string()))?
            != exact_terminal_response
        {
            return Err(protocol_error(
                "terminal shell response was not the exact canonical durable bytes",
            ));
        }
        let value = Self {
            schema: TRANSPORT_RESPONSE_SCHEMA.to_string(),
            protocol: TRANSPORT_PROTOCOL.to_string(),
            request,
            durable_state,
            terminal_response: Some(terminal_response),
        };
        value.validate(&value.request.arguments)?;
        Ok(value)
    }

    pub fn indeterminate(
        request: DirectEffectRequestV1,
        durable_state: DirectEffectDurableStateV1,
    ) -> Result<Self, DirectToolError> {
        let value = Self {
            schema: TRANSPORT_RESPONSE_SCHEMA.to_string(),
            protocol: TRANSPORT_PROTOCOL.to_string(),
            request,
            durable_state,
            terminal_response: None,
        };
        value.validate(&value.request.arguments)?;
        Ok(value)
    }

    pub fn validate(
        &self,
        expected_arguments: &DirectEffectModelArgumentsV1,
    ) -> Result<(), DirectToolError> {
        if self.schema != TRANSPORT_RESPONSE_SCHEMA || self.protocol != TRANSPORT_PROTOCOL {
            return Err(protocol_error(
                "shell exec transport response header mismatch",
            ));
        }
        validate_first_slice_request(&self.request)
            .map_err(|error| protocol_error(&error.to_string()))?;
        self.durable_state
            .validate()
            .map_err(|error| protocol_error(&error.to_string()))?;
        if self.request.tool != DirectEffectToolV1::ShellExecV1
            || self.request.arguments != *expected_arguments
            || self.durable_state.effect_id != self.request.effect_id
            || self.durable_state.request_sha256 != self.request.request_sha256
        {
            return Err(protocol_error(
                "shell exec transport response request/state binding mismatch",
            ));
        }
        match self.durable_state.phase {
            DirectEffectPhaseV1::Terminal => {
                let terminal = self.terminal_response.as_ref().ok_or_else(|| {
                    protocol_error("terminal shell response omitted exact object")
                })?;
                if self.durable_state.terminal_observation.as_ref()
                    != Some(
                        &terminal
                            .to_terminal_observation(&self.request)
                            .map_err(|error| protocol_error(&error.to_string()))?,
                    )
                {
                    return Err(protocol_error(
                        "terminal shell response bytes/state observation mismatch",
                    ));
                }
            }
            DirectEffectPhaseV1::Indeterminate => {
                if self.terminal_response.is_some()
                    || self.durable_state.indeterminate_reason.is_none()
                {
                    return Err(protocol_error(
                        "indeterminate shell response carried terminal bytes or omitted reason",
                    ));
                }
            }
            DirectEffectPhaseV1::NotDispatched | DirectEffectPhaseV1::Dispatched => {
                return Err(protocol_error(
                    "nonterminal shell state crossed the response boundary",
                ));
            }
        }
        Ok(())
    }

    pub fn into_mcp_result(
        self,
        expected_arguments: &DirectEffectModelArgumentsV1,
    ) -> Result<ShellExecMcpResultV1, DirectToolError> {
        self.validate(expected_arguments)?;
        let effect_id = self.request.effect_id.clone();
        let request_sha256 = self.request.request_sha256.clone();
        let semantic_arguments_sha256 = self
            .request
            .arguments
            .canonical_sha256()
            .map_err(|error| protocol_error(&error.to_string()))?;
        let stdout_limit_bytes = self.request.arguments.stdout_limit_bytes;
        let stderr_limit_bytes = self.request.arguments.stderr_limit_bytes;
        let total_output_limit_bytes = self.request.arguments.total_output_limit_bytes;
        match self.durable_state.phase {
            DirectEffectPhaseV1::Terminal => {
                let terminal_response = self
                    .terminal_response
                    .expect("validated terminal response object");
                let error = terminal_error_code(&terminal_response).map(str::to_string);
                let result = ShellExecMcpResultV1 {
                    schema: MCP_RESULT_SCHEMA.to_string(),
                    protocol: TRANSPORT_PROTOCOL.to_string(),
                    ok: error.is_none(),
                    disposition: ShellExecMcpDispositionV1::Terminal,
                    effect_id,
                    request_sha256,
                    semantic_arguments_sha256,
                    stdout_limit_bytes,
                    stderr_limit_bytes,
                    total_output_limit_bytes,
                    terminal_response: Some(terminal_response),
                    indeterminate_reason: None,
                    error,
                };
                result.validate()?;
                Ok(result)
            }
            DirectEffectPhaseV1::Indeterminate => {
                let result = ShellExecMcpResultV1 {
                    schema: MCP_RESULT_SCHEMA.to_string(),
                    protocol: TRANSPORT_PROTOCOL.to_string(),
                    ok: false,
                    disposition: ShellExecMcpDispositionV1::Indeterminate,
                    effect_id,
                    request_sha256,
                    semantic_arguments_sha256,
                    stdout_limit_bytes,
                    stderr_limit_bytes,
                    total_output_limit_bytes,
                    terminal_response: None,
                    indeterminate_reason: self.durable_state.indeterminate_reason,
                    error: Some("effect_outcome_indeterminate".to_string()),
                };
                result.validate()?;
                Ok(result)
            }
            DirectEffectPhaseV1::NotDispatched | DirectEffectPhaseV1::Dispatched => Err(
                protocol_error("validated shell response became nonterminal"),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellExecMcpDispositionV1 {
    Terminal,
    Indeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellExecMcpResultV1 {
    pub schema: String,
    pub protocol: String,
    pub ok: bool,
    pub disposition: ShellExecMcpDispositionV1,
    pub effect_id: String,
    pub request_sha256: String,
    pub semantic_arguments_sha256: String,
    pub stdout_limit_bytes: u64,
    pub stderr_limit_bytes: u64,
    pub total_output_limit_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_response: Option<DirectEffectTerminalResponseV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indeterminate_reason: Option<DirectEffectIndeterminateReasonV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ShellExecMcpResultV1 {
    pub fn validate(&self) -> Result<(), DirectToolError> {
        let effect_digest = self.effect_id.strip_prefix("effect:");
        if self.schema != MCP_RESULT_SCHEMA
            || self.protocol != TRANSPORT_PROTOCOL
            || !effect_digest.is_some_and(trillionnium_os_types::is_nonzero_lower_sha256)
            || !trillionnium_os_types::is_nonzero_lower_sha256(&self.request_sha256)
            || !trillionnium_os_types::is_nonzero_lower_sha256(&self.semantic_arguments_sha256)
            || self.stdout_limit_bytes == 0
            || self.stderr_limit_bytes == 0
            || self.total_output_limit_bytes == 0
            || self.stdout_limit_bytes > self.total_output_limit_bytes
            || self.stderr_limit_bytes > self.total_output_limit_bytes
            || self.total_output_limit_bytes > SHELL_EXEC_MAX_RAW_OUTPUT_BYTES
        {
            return Err(protocol_error("shell MCP result identity/header mismatch"));
        }
        let shape_valid = match self.disposition {
            ShellExecMcpDispositionV1::Terminal => {
                let Some(terminal) = self.terminal_response.as_ref() else {
                    return Err(protocol_error("terminal shell MCP result omitted response"));
                };
                validate_unbound_terminal_response(terminal)?;
                let expected_error = terminal_error_code(terminal);
                terminal.effect_id == self.effect_id
                    && terminal.request_sha256 == self.request_sha256
                    && terminal.stdout.bytes <= self.stdout_limit_bytes
                    && terminal.stderr.bytes <= self.stderr_limit_bytes
                    && terminal
                        .stdout
                        .bytes
                        .checked_add(terminal.stderr.bytes)
                        .is_some_and(|total| total <= self.total_output_limit_bytes)
                    && self.indeterminate_reason.is_none()
                    && self.ok == expected_error.is_none()
                    && self.error.as_deref() == expected_error
            }
            ShellExecMcpDispositionV1::Indeterminate => {
                !self.ok
                    && self.terminal_response.is_none()
                    && self.indeterminate_reason.is_some()
                    && self.error.as_deref() == Some("effect_outcome_indeterminate")
            }
        };
        if !shape_valid {
            return Err(protocol_error("shell MCP result disposition mismatch"));
        }
        Ok(())
    }
}

fn validate_unbound_terminal_response(
    terminal: &DirectEffectTerminalResponseV1,
) -> Result<(), DirectToolError> {
    terminal
        .stdout
        .validate()
        .map_err(|error| protocol_error(&error.to_string()))?;
    terminal
        .stderr
        .validate()
        .map_err(|error| protocol_error(&error.to_string()))?;
    let total = terminal
        .stdout
        .bytes
        .checked_add(terminal.stderr.bytes)
        .ok_or_else(|| protocol_error("shell MCP output count overflowed"))?;
    let effect_digest = terminal.effect_id.strip_prefix("effect:");
    let identity_valid = effect_digest.is_some_and(trillionnium_os_types::is_nonzero_lower_sha256)
        && trillionnium_os_types::is_nonzero_lower_sha256(&terminal.request_sha256);
    let backend_code_valid = |value: &str| {
        !value.is_empty()
            && value.len() <= 128
            && value.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                }
            })
    };
    let outcome_valid = match terminal.kind {
        DirectEffectTerminalKindV1::Exited => {
            terminal.exit_code.is_some()
                && terminal.signal.is_none()
                && terminal.backend_error_code.is_none()
        }
        DirectEffectTerminalKindV1::Signaled => {
            terminal.exit_code.is_none()
                && terminal
                    .signal
                    .is_some_and(|signal| (1..=64).contains(&signal))
                && terminal.backend_error_code.is_none()
        }
        DirectEffectTerminalKindV1::LaunchRejected => {
            terminal.exit_code.is_none()
                && terminal.signal.is_none()
                && terminal
                    .backend_error_code
                    .as_deref()
                    .is_some_and(backend_code_valid)
                && total == 0
        }
        DirectEffectTerminalKindV1::CancelledBeforeDispatch
        | DirectEffectTerminalKindV1::DeadlineBeforeDispatch => {
            terminal.exit_code.is_none()
                && terminal.signal.is_none()
                && terminal.backend_error_code.is_none()
                && total == 0
                && terminal.finished_boottime_ms == terminal.started_boottime_ms
        }
        DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch => {
            terminal.exit_code.is_none()
                && terminal.signal.is_none()
                && terminal
                    .backend_error_code
                    .as_deref()
                    .is_some_and(backend_code_valid)
                && total == 0
                && terminal.finished_boottime_ms == terminal.started_boottime_ms
        }
    };
    if terminal.schema != TERMINAL_RESPONSE_SCHEMA
        || !identity_valid
        || terminal.dispatch_occurred != terminal.kind.dispatch_occurred()
        || terminal.started_boottime_ms == 0
        || terminal.finished_boottime_ms < terminal.started_boottime_ms
        || total > SHELL_EXEC_MAX_RAW_OUTPUT_BYTES
        || !outcome_valid
    {
        return Err(protocol_error(
            "shell MCP terminal response shape is invalid",
        ));
    }
    Ok(())
}

fn terminal_error_code(response: &DirectEffectTerminalResponseV1) -> Option<&'static str> {
    match response.kind {
        DirectEffectTerminalKindV1::Exited if response.exit_code == Some(0) => None,
        DirectEffectTerminalKindV1::Exited => Some("process_exited_nonzero"),
        DirectEffectTerminalKindV1::Signaled => Some("process_signaled"),
        DirectEffectTerminalKindV1::LaunchRejected => Some("launch_rejected_before_effect"),
        DirectEffectTerminalKindV1::CancelledBeforeDispatch => Some("cancelled_before_dispatch"),
        DirectEffectTerminalKindV1::DeadlineBeforeDispatch => Some("deadline_before_dispatch"),
        DirectEffectTerminalKindV1::PolicyRejectedBeforeDispatch => {
            Some("policy_rejected_before_dispatch")
        }
    }
}

fn protocol_error(message: &str) -> DirectToolError {
    DirectToolError::BackendFailed(message.to_string())
}

pub trait ShellExecMcpBackendV1 {
    fn execute(
        &mut self,
        arguments: &DirectEffectModelArgumentsV1,
    ) -> Result<ShellExecMcpResultV1, DirectToolError>;
}

pub fn mcp_tool() -> mcp::McpTool {
    mcp::McpTool {
        name: MCP_TOOL_NAME,
        description: "Execute one bounded exact-argv command in the measured Trillionnium Root Linux workspace. Inline shell command strings, Android /system execution, ADB, root, elevated, and recovery modes are not part of shell.exec.v1.",
        input_schema: json!({
            "type": "object",
            "required": [
                "argv",
                "cwd",
                "timeout_ms",
                "stdout_limit_bytes",
                "stderr_limit_bytes",
                "total_output_limit_bytes",
                "requested_profile"
            ],
            "properties": {
                "argv": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 256,
                    "items": {"type": "string", "maxLength": 16384}
                },
                "cwd": {
                    "oneOf": [
                        {"type": "null"},
                        {
                            "type": "object",
                            "required": ["scope", "relative"],
                            "properties": {
                                "scope": {"const": "workspace"},
                                "relative": {"type": "string", "minLength": 1, "maxLength": 4096}
                            },
                            "additionalProperties": false
                        }
                    ]
                },
                "timeout_ms": {"type": "integer", "minimum": 1, "maximum": SHELL_EXEC_FIRST_SLICE_MAX_TIMEOUT_MS},
                "stdout_limit_bytes": {"type": "integer", "minimum": 1, "maximum": SHELL_EXEC_MAX_RAW_OUTPUT_BYTES},
                "stderr_limit_bytes": {"type": "integer", "minimum": 1, "maximum": SHELL_EXEC_MAX_RAW_OUTPUT_BYTES},
                "total_output_limit_bytes": {"type": "integer", "minimum": 1, "maximum": SHELL_EXEC_MAX_RAW_OUTPUT_BYTES},
                "requested_profile": {"const": "standard"}
            },
            "additionalProperties": false
        }),
    }
}

pub fn serve_stdio<B: ShellExecMcpBackendV1>(mut backend: B) -> Result<(), DirectToolError> {
    mcp::serve_stdio(MCP_SERVER_NAME, mcp_tool(), move |arguments| {
        execute_mcp_arguments(arguments, &mut backend)
    })
}

pub fn serve<R, W, B>(reader: R, writer: W, mut backend: B) -> Result<(), DirectToolError>
where
    R: BufRead,
    W: Write,
    B: ShellExecMcpBackendV1,
{
    mcp::serve(
        reader,
        writer,
        MCP_SERVER_NAME,
        mcp_tool(),
        move |arguments| execute_mcp_arguments(arguments, &mut backend),
    )
}

fn execute_mcp_arguments<B: ShellExecMcpBackendV1>(
    arguments: Value,
    backend: &mut B,
) -> Result<Value, DirectToolError> {
    let arguments: DirectEffectModelArgumentsV1 = serde_json::from_value(arguments)
        .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
    validate_first_slice_arguments(&arguments)
        .map_err(|error| DirectToolError::InvalidRequest(error.to_string()))?;
    let result = backend.execute(&arguments)?;
    result.validate()?;
    serde_json::to_value(result).map_err(DirectToolError::from)
}

enum TransportEndpointV1 {
    Abstract(&'static str),
    #[cfg(feature = "host-conformance")]
    Path(PathBuf),
}

pub struct ProductTransportBackendV1 {
    endpoint: TransportEndpointV1,
    #[cfg(feature = "host-conformance")]
    invocation_token: Option<String>,
    next_adapter_effect_ordinal: u64,
}

impl ProductTransportBackendV1 {
    #[must_use]
    pub const fn fixed() -> Self {
        Self {
            endpoint: TransportEndpointV1::Abstract(SOCKET_ADDRESS),
            #[cfg(feature = "host-conformance")]
            invocation_token: None,
            next_adapter_effect_ordinal: 1,
        }
    }

    pub fn from_process_environment() -> Result<Self, DirectToolError> {
        if std::env::var_os(INVOCATION_TOKEN_ENV).is_some() {
            return Err(DirectToolError::BackendUnavailable(
                "shell adapter refuses a leaked invocation secret in its process environment"
                    .to_string(),
            ));
        }
        Ok(Self::fixed())
    }

    #[cfg(feature = "host-conformance")]
    #[must_use]
    pub fn for_host_conformance_path(path: &Path) -> Self {
        Self {
            endpoint: TransportEndpointV1::Path(path.to_path_buf()),
            invocation_token: Some(format!(
                "{}{}",
                crate::authorization::INVOCATION_TOKEN_PREFIX,
                "a".repeat(64)
            )),
            next_adapter_effect_ordinal: 1,
        }
    }

    fn connect(&self, timeout: Duration) -> Result<ShellExecSeqpacketV1, DirectToolError> {
        let connection = ShellExecSeqpacketV1::connect(&self.endpoint, timeout)?;
        if matches!(&self.endpoint, TransportEndpointV1::Abstract(_)) {
            connection.require_peer(SHELL_BROKER_UID, SHELL_BROKER_SELINUX_DOMAIN)?;
        }
        Ok(connection)
    }
}

pub fn register_product_invocation(
    registration: &ShellExecHostRegistrationV1,
) -> Result<ShellExecHostRegistrationReceiptV1, DirectToolError> {
    registration
        .validate_at(registration.issued_boottime_ms)
        .map_err(|error| protocol_error(&error.to_string()))?;
    let connection = ShellExecSeqpacketV1::connect(
        &TransportEndpointV1::Abstract(SOCKET_ADDRESS),
        Duration::from_secs(5),
    )?;
    connection.require_peer(SHELL_BROKER_UID, SHELL_BROKER_SELINUX_DOMAIN)?;
    send_canonical_packet(
        connection.descriptor.as_raw_fd(),
        &ShellExecHostControlV1::Register {
            registration: registration.clone(),
        },
        MAX_TRANSPORT_REQUEST_BYTES,
    )?;
    let receipt: ShellExecHostRegistrationReceiptV1 = receive_canonical_packet(
        connection.descriptor.as_raw_fd(),
        MAX_TRANSPORT_RESPONSE_BYTES,
    )?;
    receipt
        .validate_for(registration)
        .map_err(|error| protocol_error(&error.to_string()))?;
    connection.require_peer_close_without_trailing_packet()?;
    Ok(receipt)
}

pub fn retire_product_invocation(
    retirement: &ShellExecHostRetirementV1,
) -> Result<ShellExecHostRetirementReceiptV1, DirectToolError> {
    retirement
        .validate()
        .map_err(|error| protocol_error(&error.to_string()))?;
    let connection = ShellExecSeqpacketV1::connect(
        &TransportEndpointV1::Abstract(SOCKET_ADDRESS),
        Duration::from_secs(5),
    )?;
    connection.require_peer(SHELL_BROKER_UID, SHELL_BROKER_SELINUX_DOMAIN)?;
    send_canonical_packet(
        connection.descriptor.as_raw_fd(),
        &ShellExecHostControlV1::Retire {
            retirement: retirement.clone(),
        },
        MAX_TRANSPORT_REQUEST_BYTES,
    )?;
    let receipt: ShellExecHostRetirementReceiptV1 = receive_canonical_packet(
        connection.descriptor.as_raw_fd(),
        MAX_TRANSPORT_RESPONSE_BYTES,
    )?;
    receipt
        .validate_for(retirement)
        .map_err(|error| protocol_error(&error.to_string()))?;
    connection.require_peer_close_without_trailing_packet()?;
    Ok(receipt)
}

impl ShellExecMcpBackendV1 for ProductTransportBackendV1 {
    fn execute(
        &mut self,
        arguments: &DirectEffectModelArgumentsV1,
    ) -> Result<ShellExecMcpResultV1, DirectToolError> {
        let ordinal = self.next_adapter_effect_ordinal;
        if ordinal == 0 {
            return Err(DirectToolError::BackendUnavailable(
                "shell adapter effect ordinal exhausted".to_string(),
            ));
        }
        let timeout = Duration::from_millis(
            arguments
                .timeout_ms
                .saturating_add(TRANSPORT_TIMEOUT_OVERHEAD_MS),
        );
        let connection = self.connect(timeout).map_err(|error| {
            DirectToolError::BackendUnavailable(format!(
                "fixed shell broker connection failed: {error}"
            ))
        })?;
        match &self.endpoint {
            TransportEndpointV1::Abstract(_) => {
                let request =
                    ShellExecProductTransportRequestV1::derive(arguments.clone(), ordinal)?;
                connection.send_product_request(&request)?;
            }
            #[cfg(feature = "host-conformance")]
            TransportEndpointV1::Path(_) => {
                let invocation_token = self.invocation_token.as_ref().ok_or_else(|| {
                    DirectToolError::BackendUnavailable(
                        "host-conformance invocation token missing".to_string(),
                    )
                })?;
                let request = ShellExecTransportRequestV1::derive_for_invocation(
                    arguments.clone(),
                    invocation_token.clone(),
                    ordinal,
                )?;
                connection.send_request(&request)?;
            }
        }
        let response = connection.receive_response()?;
        connection.require_peer_close_without_trailing_packet()?;
        let result = response.into_mcp_result(arguments)?;
        self.next_adapter_effect_ordinal = ordinal.checked_add(1).ok_or_else(|| {
            DirectToolError::BackendUnavailable(
                "shell adapter effect ordinal exhausted".to_string(),
            )
        })?;
        Ok(result)
    }
}

/// One Linux AF_UNIX SOCK_SEQPACKET connection. Each direction permits exactly
/// one canonical JSON record. The adapter keeps the full-duplex descriptor open
/// while the broker executes. The product broker watches this descriptor and
/// maps peer disconnect to the request cancellation token.
pub struct ShellExecSeqpacketV1 {
    descriptor: OwnedFd,
}

impl ShellExecSeqpacketV1 {
    #[cfg(all(test, feature = "android-product"))]
    pub(crate) fn from_owned_descriptor_for_test(descriptor: OwnedFd) -> Self {
        Self { descriptor }
    }

    fn connect(endpoint: &TransportEndpointV1, timeout: Duration) -> Result<Self, DirectToolError> {
        let descriptor = new_seqpacket_descriptor()?;
        configure_socket(&descriptor, timeout)?;
        let (address, address_length) = socket_address(endpoint)?;
        // SAFETY: address is fully initialized and address_length covers the
        // exact AF_UNIX pathname/abstract address bytes.
        if unsafe {
            libc::connect(
                descriptor.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                address_length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { descriptor })
    }

    pub fn send_request(
        &self,
        request: &ShellExecTransportRequestV1,
    ) -> Result<(), DirectToolError> {
        request.validate()?;
        send_canonical_packet(
            self.descriptor.as_raw_fd(),
            request,
            MAX_TRANSPORT_REQUEST_BYTES,
        )
    }

    pub fn send_product_request(
        &self,
        request: &ShellExecProductTransportRequestV1,
    ) -> Result<(), DirectToolError> {
        request.validate()?;
        send_canonical_packet(
            self.descriptor.as_raw_fd(),
            request,
            MAX_TRANSPORT_REQUEST_BYTES,
        )
    }

    pub fn receive_request(&self) -> Result<ShellExecTransportRequestV1, DirectToolError> {
        let request: ShellExecTransportRequestV1 =
            receive_canonical_packet(self.descriptor.as_raw_fd(), MAX_TRANSPORT_REQUEST_BYTES)?;
        request.validate()?;
        require_no_queued_packet(self.descriptor.as_raw_fd())?;
        Ok(request)
    }

    pub fn receive_host_control(&self) -> Result<ShellExecHostControlV1, DirectToolError> {
        let control =
            receive_canonical_packet(self.descriptor.as_raw_fd(), MAX_TRANSPORT_REQUEST_BYTES)?;
        require_no_queued_packet(self.descriptor.as_raw_fd())?;
        Ok(control)
    }

    pub fn receive_authenticated_execute(
        &self,
    ) -> Result<ShellExecProductTransportRequestV1, DirectToolError> {
        let request: ShellExecProductTransportRequestV1 =
            receive_canonical_packet(self.descriptor.as_raw_fd(), MAX_TRANSPORT_REQUEST_BYTES)?;
        request.validate()?;
        require_no_queued_packet(self.descriptor.as_raw_fd())?;
        Ok(request)
    }

    pub fn send_registration_receipt(
        &self,
        receipt: &ShellExecHostRegistrationReceiptV1,
    ) -> Result<(), DirectToolError> {
        send_canonical_packet(
            self.descriptor.as_raw_fd(),
            receipt,
            MAX_TRANSPORT_RESPONSE_BYTES,
        )
    }

    pub fn send_retirement_receipt(
        &self,
        receipt: &ShellExecHostRetirementReceiptV1,
    ) -> Result<(), DirectToolError> {
        send_canonical_packet(
            self.descriptor.as_raw_fd(),
            receipt,
            MAX_TRANSPORT_RESPONSE_BYTES,
        )
    }

    pub fn peer_identity(&self) -> Result<ShellExecPeerIdentityV1, DirectToolError> {
        observed_peer_identity(self.descriptor.as_raw_fd())
    }

    #[cfg(feature = "android-product")]
    pub(crate) fn duplicate_descriptor(&self) -> Result<OwnedFd, DirectToolError> {
        // SAFETY: F_DUPFD_CLOEXEC returns an independently owned reference to
        // this connected socket without changing the original descriptor.
        let duplicate =
            unsafe { libc::fcntl(self.descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: duplicate is a fresh descriptor uniquely owned here.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    pub fn require_peer(&self, uid: u32, domain: &str) -> Result<(), DirectToolError> {
        let peer = self.peer_identity()?;
        if peer.uid != uid || peer.selinux_domain != domain {
            return Err(protocol_error("shell transport peer identity mismatch"));
        }
        Ok(())
    }

    pub fn send_response(
        &self,
        response: &ShellExecTransportResponseV1,
    ) -> Result<(), DirectToolError> {
        response.validate(&response.request.arguments)?;
        send_canonical_packet(
            self.descriptor.as_raw_fd(),
            response,
            MAX_TRANSPORT_RESPONSE_BYTES,
        )
    }

    pub fn receive_response(&self) -> Result<ShellExecTransportResponseV1, DirectToolError> {
        receive_canonical_packet(self.descriptor.as_raw_fd(), MAX_TRANSPORT_RESPONSE_BYTES)
    }

    pub fn require_peer_close_without_trailing_packet(&self) -> Result<(), DirectToolError> {
        let mut probe = 0_u8;
        let received = retry_recv(
            self.descriptor.as_raw_fd(),
            (&raw mut probe).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_TRUNC,
        )?;
        if received == 0 {
            Ok(())
        } else {
            Err(protocol_error(
                "shell broker sent a trailing packet after its one response",
            ))
        }
    }

    #[cfg(feature = "host-conformance")]
    pub fn send_raw_packet_for_host_conformance(
        &self,
        bytes: &[u8],
    ) -> Result<(), DirectToolError> {
        send_packet(self.descriptor.as_raw_fd(), bytes)
    }
}

pub struct ProductSeqpacketListenerV1 {
    descriptor: OwnedFd,
}

impl ProductSeqpacketListenerV1 {
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.descriptor.as_raw_fd()
    }

    pub fn bind_fixed() -> Result<Self, DirectToolError> {
        let descriptor = new_seqpacket_descriptor()?;
        configure_socket(&descriptor, Duration::from_secs(70))?;
        let endpoint = TransportEndpointV1::Abstract(SOCKET_ADDRESS);
        let (address, address_length) = socket_address(&endpoint)?;
        // SAFETY: address and length describe the fixed abstract socket.
        if unsafe {
            libc::bind(
                descriptor.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                address_length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: descriptor is one bound SOCK_SEQPACKET socket.
        if unsafe { libc::listen(descriptor.as_raw_fd(), 8) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { descriptor })
    }

    pub fn accept_authenticated(
        &self,
    ) -> Result<(ShellExecSeqpacketV1, ShellExecPeerIdentityV1), DirectToolError> {
        let accepted = accept_seqpacket(self.descriptor.as_raw_fd())?;
        configure_socket(&accepted, Duration::from_secs(70))?;
        let connection = ShellExecSeqpacketV1 {
            descriptor: accepted,
        };
        let peer = connection.peer_identity()?;
        Ok((connection, peer))
    }
}

#[cfg(feature = "host-conformance")]
pub struct HostConformanceSeqpacketListenerV1 {
    descriptor: OwnedFd,
}

#[cfg(feature = "host-conformance")]
impl HostConformanceSeqpacketListenerV1 {
    pub fn bind(path: &Path) -> Result<Self, DirectToolError> {
        let descriptor = new_seqpacket_descriptor()?;
        configure_socket(&descriptor, Duration::from_secs(5))?;
        let endpoint = TransportEndpointV1::Path(path.to_path_buf());
        let (address, address_length) = socket_address(&endpoint)?;
        // SAFETY: address and length are initialized as above.
        if unsafe {
            libc::bind(
                descriptor.as_raw_fd(),
                (&raw const address).cast::<libc::sockaddr>(),
                address_length,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: descriptor is one bound SOCK_SEQPACKET socket.
        if unsafe { libc::listen(descriptor.as_raw_fd(), 1) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { descriptor })
    }

    pub fn accept(&self) -> Result<ShellExecSeqpacketV1, DirectToolError> {
        // SAFETY: null address pointers request no peer pathname and accept4
        // returns a new independently owned descriptor.
        let accepted = unsafe {
            libc::accept4(
                self.descriptor.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if accepted < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: accepted is a fresh descriptor owned by this function.
        let descriptor = unsafe { OwnedFd::from_raw_fd(accepted) };
        configure_socket(&descriptor, Duration::from_secs(5))?;
        Ok(ShellExecSeqpacketV1 { descriptor })
    }
}

#[cfg(feature = "host-conformance")]
pub fn host_conformance_seqpacket_pair(
    timeout: Duration,
) -> Result<(ShellExecSeqpacketV1, ShellExecSeqpacketV1), DirectToolError> {
    let mut descriptors = [-1_i32; 2];
    // SAFETY: descriptors points to two writable ints and flags request two
    // close-on-exec AF_UNIX SOCK_SEQPACKET endpoints.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: socketpair returned two distinct fresh descriptors.
    let first = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: ownership of the second descriptor is also unique.
    let second = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    configure_socket(&first, timeout)?;
    configure_socket(&second, timeout)?;
    Ok((
        ShellExecSeqpacketV1 { descriptor: first },
        ShellExecSeqpacketV1 { descriptor: second },
    ))
}

fn new_seqpacket_descriptor() -> Result<OwnedFd, DirectToolError> {
    // SAFETY: constant domain/type/protocol; returned descriptor is immediately
    // transferred into OwnedFd on success.
    let descriptor =
        unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: descriptor is fresh and uniquely owned.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

fn accept_seqpacket(listener: RawFd) -> Result<OwnedFd, DirectToolError> {
    loop {
        // SAFETY: listener is a live AF_UNIX SOCK_SEQPACKET listener. Null
        // address pointers request no pathname and accept4 returns a fresh
        // independently owned descriptor with close-on-exec set atomically.
        let accepted = unsafe {
            libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if accepted >= 0 {
            // SAFETY: accepted is a fresh descriptor uniquely owned here.
            return Ok(unsafe { OwnedFd::from_raw_fd(accepted) });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn observed_peer_identity(descriptor: RawFd) -> Result<ShellExecPeerIdentityV1, DirectToolError> {
    // SAFETY: zero is a valid initial representation for Linux ucred and the
    // full object is populated by a successful getsockopt call below.
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut credentials_length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: credentials is writable for credentials_length bytes and
    // descriptor is a connected AF_UNIX socket.
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut credentials).cast(),
            &mut credentials_length,
        )
    } != 0
        || credentials_length as usize != size_of::<libc::ucred>()
    {
        return Err(DirectToolError::BackendUnavailable(
            "shell transport SO_PEERCRED authentication failed".to_string(),
        ));
    }
    let pid = u32::try_from(credentials.pid).map_err(|_| {
        DirectToolError::BackendUnavailable(
            "shell transport returned an invalid peer pid".to_string(),
        )
    })?;
    if pid == 0 {
        return Err(DirectToolError::BackendUnavailable(
            "shell transport returned an invalid peer pid".to_string(),
        ));
    }

    let mut security_context = [0_u8; 512];
    let mut security_context_length = security_context.len() as libc::socklen_t;
    // SAFETY: security_context is writable for security_context_length bytes
    // and descriptor is a connected AF_UNIX socket.
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            security_context.as_mut_ptr().cast(),
            &mut security_context_length,
        )
    } != 0
    {
        return Err(DirectToolError::BackendUnavailable(
            "shell transport SO_PEERSEC authentication failed".to_string(),
        ));
    }
    let security_context_length = security_context_length as usize;
    if security_context_length == 0 || security_context_length > security_context.len() {
        return Err(DirectToolError::BackendUnavailable(
            "shell transport returned a malformed peer security context".to_string(),
        ));
    }
    let mut security_context = &security_context[..security_context_length];
    while let Some(stripped) = security_context.strip_suffix(&[0]) {
        security_context = stripped;
    }
    if security_context.is_empty() || security_context.contains(&0) {
        return Err(DirectToolError::BackendUnavailable(
            "shell transport returned a malformed peer security context".to_string(),
        ));
    }
    let selinux_domain = std::str::from_utf8(security_context)
        .map_err(|_| {
            DirectToolError::BackendUnavailable(
                "shell transport peer security context is not UTF-8".to_string(),
            )
        })?
        .to_string();
    Ok(ShellExecPeerIdentityV1 {
        pid,
        uid: credentials.uid,
        gid: credentials.gid,
        selinux_domain,
    })
}

fn configure_socket(descriptor: &OwnedFd, timeout: Duration) -> Result<(), DirectToolError> {
    for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        set_socket_option(
            descriptor.as_raw_fd(),
            option,
            &REQUESTED_SOCKET_BUFFER_BYTES,
        )?;
    }
    let seconds = timeout.as_secs().min(i64::MAX as u64);
    let microseconds = timeout.subsec_micros();
    let value = libc::timeval {
        tv_sec: seconds as _,
        tv_usec: microseconds as _,
    };
    for option in [libc::SO_SNDTIMEO, libc::SO_RCVTIMEO] {
        set_socket_option(descriptor.as_raw_fd(), option, &value)?;
    }
    Ok(())
}

fn set_socket_option<T>(descriptor: RawFd, option: i32, value: &T) -> Result<(), DirectToolError> {
    // SAFETY: value points to a fully initialized T for the exact option and
    // the length matches it.
    if unsafe {
        libc::setsockopt(
            descriptor,
            libc::SOL_SOCKET,
            option,
            (std::ptr::from_ref(value)).cast(),
            size_of::<T>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn socket_address(
    endpoint: &TransportEndpointV1,
) -> Result<(libc::sockaddr_un, libc::socklen_t), DirectToolError> {
    // SAFETY: zero is a valid initial representation for sockaddr_un and all
    // fields used below are explicitly populated.
    let mut address: libc::sockaddr_un = unsafe { zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    let path_offset = offset_of!(libc::sockaddr_un, sun_path);
    let encoded: &[u8];
    let abstract_address: bool;
    match endpoint {
        TransportEndpointV1::Abstract(value) => {
            encoded = value
                .strip_prefix('@')
                .filter(|value| !value.is_empty())
                .ok_or_else(|| protocol_error("fixed abstract shell socket is invalid"))?
                .as_bytes();
            abstract_address = true;
        }
        #[cfg(feature = "host-conformance")]
        TransportEndpointV1::Path(value) => {
            encoded = value.as_os_str().as_bytes();
            abstract_address = false;
        }
    }
    if encoded.contains(&0)
        || encoded.is_empty()
        || encoded.len().saturating_add(usize::from(abstract_address)) >= address.sun_path.len()
    {
        return Err(protocol_error(
            "shell socket address is oversized or invalid",
        ));
    }
    let start = usize::from(abstract_address);
    for (destination, source) in address.sun_path[start..].iter_mut().zip(encoded) {
        *destination = *source as libc::c_char;
    }
    // Abstract sockets spend the leading byte on the namespace marker;
    // pathname sockets spend the trailing byte on NUL termination.
    let encoded_length = encoded.len() + 1;
    let address_length = path_offset
        .checked_add(encoded_length)
        .and_then(|value| libc::socklen_t::try_from(value).ok())
        .ok_or_else(|| protocol_error("shell socket address length overflowed"))?;
    Ok((address, address_length))
}

fn send_canonical_packet<T: Serialize>(
    descriptor: RawFd,
    value: &T,
    maximum: usize,
) -> Result<(), DirectToolError> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(protocol_error("shell transport packet exceeded its bound"));
    }
    send_packet(descriptor, &bytes)
}

fn send_packet(descriptor: RawFd, bytes: &[u8]) -> Result<(), DirectToolError> {
    let sent = loop {
        // SAFETY: bytes is a valid buffer for the duration of this call and
        // MSG_NOSIGNAL prevents process-global SIGPIPE delivery.
        let result = unsafe {
            libc::send(
                descriptor,
                bytes.as_ptr().cast(),
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        if result >= 0 {
            break result as usize;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    };
    if sent != bytes.len() {
        return Err(protocol_error(
            "SOCK_SEQPACKET shell transport did not send one complete record",
        ));
    }
    Ok(())
}

fn receive_canonical_packet<T: for<'de> Deserialize<'de> + Serialize>(
    descriptor: RawFd,
    maximum: usize,
) -> Result<T, DirectToolError> {
    let mut probe = 0_u8;
    let length = retry_recv(
        descriptor,
        (&raw mut probe).cast(),
        1,
        libc::MSG_PEEK | libc::MSG_TRUNC,
    )?;
    if length == 0 || length > maximum {
        return Err(protocol_error(
            "shell transport record is empty, truncated, or oversized",
        ));
    }
    let mut bytes = vec![0_u8; length];
    let received = retry_recv(descriptor, bytes.as_mut_ptr().cast(), bytes.len(), 0)?;
    if received != length {
        return Err(protocol_error(
            "SOCK_SEQPACKET shell transport record was truncated",
        ));
    }
    let value: T = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&value)? != bytes {
        return Err(protocol_error(
            "shell transport record is not canonical JSON",
        ));
    }
    Ok(value)
}

fn retry_recv(
    descriptor: RawFd,
    buffer: *mut libc::c_void,
    length: usize,
    flags: i32,
) -> Result<usize, DirectToolError> {
    loop {
        // SAFETY: caller supplies writable storage of at least length bytes for
        // this synchronous receive operation.
        let received = unsafe { libc::recv(descriptor, buffer, length, flags) };
        if received >= 0 {
            return Ok(received as usize);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
}

fn require_no_queued_packet(descriptor: RawFd) -> Result<(), DirectToolError> {
    let mut probe = 0_u8;
    // SAFETY: probe is one writable byte and MSG_DONTWAIT avoids confusing an
    // idle full-duplex cancellation channel with a required peer close.
    let received = unsafe {
        libc::recv(
            descriptor,
            (&raw mut probe).cast(),
            1,
            libc::MSG_PEEK | libc::MSG_TRUNC | libc::MSG_DONTWAIT,
        )
    };
    if received > 0 {
        return Err(protocol_error(
            "shell transport received a trailing request packet",
        ));
    }
    if received == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Ok(())
    } else {
        Err(error.into())
    }
}
