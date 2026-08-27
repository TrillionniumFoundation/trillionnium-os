//! Closed data contract for the standalone typed broker foundation.
//!
//! Values in this module are parseable and measurable, but never authoritative
//! on their own. A future product listener must bind them to kernel-observed
//! peer identity and separately provisioned policy before any backend call.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;
use trillionnium_os_types::agent_descriptor_registry;
use trillionnium_os_types::direct_operation::CODEX_PROVIDER_RUNTIME_CGROUP_PATH;

pub const CATALOG_SCHEMA: &str = "org.trillionnium.typed-exec-adb-broker-conformance-catalog.v1";
pub const CATALOG_SHA256: &str = "31b975f6cb5e7151fcb3810be6e7adfb052f53d81f792ad71f15645acf956987";
pub const CATALOG_STATUS: &str = "standalone_host_runnable_core_userdebug_conformance_only";
pub const REQUEST_SCHEMA: &str = "trillionnium.typed-broker-request.v1";
pub const RESPONSE_SCHEMA: &str = "trillionnium.typed-broker-response.v1";
pub const BINDING_IDENTITY_SCHEMA: &str = "trillionnium.typed-broker-binding-identity.v1";
pub const REQUEST_DIGEST_DOMAIN: &str = "trillionnium.typed-broker-request-digest.v1";
pub const OPERATION_IDENTITY_DOMAIN: &str = "trillionnium.typed-broker-operation-identity.v1";
pub const RESPONSE_DIGEST_DOMAIN: &str = "trillionnium.typed-broker-response-digest.v1";
pub const MAX_REQUEST_WIRE_BYTES: usize = 32 * 1024;
pub const MAX_RESPONSE_WIRE_BYTES: usize = 32 * 1024;

pub const EXEC_INSPECT_BUILD_FINGERPRINT_USERDEBUG_V1: &str =
    "exec.inspect_build_fingerprint.userdebug.v1";
pub const ADB_INSPECT_PACKAGE_SETTINGS_USERDEBUG_V1: &str =
    "adb.inspect_package.settings.userdebug.v1";

const EXEC_FINGERPRINT_ARGV: &[&str] = &["ro.build.fingerprint"];
const ADB_PACKAGE_SETTINGS_ARGUMENTS: &[&str] = &["package", "path", "com.android.settings"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrincipalDescriptor {
    pub provider_id: &'static str,
    pub agent_id: &'static str,
    pub uid: u32,
    pub gid: u32,
    pub selinux_domain: &'static str,
    pub cgroup_leaf: &'static str,
}

pub const CODEX: PrincipalDescriptor = PrincipalDescriptor {
    provider_id: agent_descriptor_registry::CODEX.provider_id,
    agent_id: agent_descriptor_registry::CODEX.agent_id,
    uid: agent_descriptor_registry::CODEX.uid,
    gid: agent_descriptor_registry::CODEX.gid,
    selinux_domain: agent_descriptor_registry::CODEX.agent_selinux_domain,
    cgroup_leaf: CODEX_PROVIDER_RUNTIME_CGROUP_PATH,
};

pub const BUILTIN_PRINCIPALS: &[&PrincipalDescriptor] = &[&CODEX];

#[must_use]
pub fn principal(provider_id: &str, agent_id: &str) -> Option<&'static PrincipalDescriptor> {
    BUILTIN_PRINCIPALS
        .iter()
        .copied()
        .find(|candidate| candidate.provider_id == provider_id && candidate.agent_id == agent_id)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum TypedBrokerOperationV1 {
    #[serde(rename = "exec.inspect_build_fingerprint.userdebug.v1")]
    ExecInspectBuildFingerprintUserdebugV1,
    #[serde(rename = "adb.inspect_package.settings.userdebug.v1")]
    AdbInspectPackageSettingsUserdebugV1,
}

impl TypedBrokerOperationV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecInspectBuildFingerprintUserdebugV1 => {
                EXEC_INSPECT_BUILD_FINGERPRINT_USERDEBUG_V1
            }
            Self::AdbInspectPackageSettingsUserdebugV1 => ADB_INSPECT_PACKAGE_SETTINGS_USERDEBUG_V1,
        }
    }

    #[must_use]
    pub const fn definition(self) -> &'static TypedOperationDefinitionV1 {
        match self {
            Self::ExecInspectBuildFingerprintUserdebugV1 => &EXEC_INSPECT_BUILD_FINGERPRINT,
            Self::AdbInspectPackageSettingsUserdebugV1 => &ADB_INSPECT_PACKAGE_SETTINGS,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypedBrokerAdapterV1 {
    TypedExec,
    TypedAdb,
}

impl TypedBrokerAdapterV1 {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TypedExec => "typed_exec",
            Self::TypedAdb => "typed_adb",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionControlsV1 {
    pub deadline_ms: u64,
    pub stdout_limit_bytes: usize,
    pub stderr_limit_bytes: usize,
    pub total_output_limit_bytes: usize,
    pub filesystem_scope: &'static str,
    pub network_scope: &'static str,
    pub descendant_process_policy: &'static str,
}

pub const EXEC_CONTROLS: ExecutionControlsV1 = ExecutionControlsV1 {
    deadline_ms: 5_000,
    stdout_limit_bytes: 8_192,
    stderr_limit_bytes: 8_192,
    total_output_limit_bytes: 8_192,
    filesystem_scope: "android_property_read_only",
    network_scope: "none",
    descendant_process_policy: "no_descendants_kill_dedicated_cgroup_at_deadline",
};

pub const ADB_CONTROLS: ExecutionControlsV1 = ExecutionControlsV1 {
    deadline_ms: 5_000,
    stdout_limit_bytes: 16_384,
    stderr_limit_bytes: 16_384,
    total_output_limit_bytes: 16_384,
    filesystem_scope: "none",
    network_scope: "fixed_local_adbd_only",
    descendant_process_policy: "no_descendants_kill_dedicated_cgroup_at_deadline",
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionDescriptorV1 {
    Exec {
        executable: &'static str,
        argv0: &'static str,
        argv: &'static [&'static str],
        uid: u32,
        gid: u32,
        selinux_domain: &'static str,
        cgroup_profile: &'static str,
        seccomp_profile: &'static str,
        controls: ExecutionControlsV1,
    },
    Adb {
        target: &'static str,
        transport: &'static str,
        service: &'static str,
        service_arguments: &'static [&'static str],
        adbd_key_custody: &'static str,
        product_identity: &'static str,
        cgroup_profile: &'static str,
        seccomp_profile: &'static str,
        controls: ExecutionControlsV1,
    },
}

impl ExecutionDescriptorV1 {
    #[must_use]
    pub const fn controls(self) -> ExecutionControlsV1 {
        match self {
            Self::Exec { controls, .. } | Self::Adb { controls, .. } => controls,
        }
    }

    #[must_use]
    pub const fn cgroup_profile(self) -> &'static str {
        match self {
            Self::Exec { cgroup_profile, .. } | Self::Adb { cgroup_profile, .. } => cgroup_profile,
        }
    }

    #[must_use]
    pub const fn seccomp_profile(self) -> &'static str {
        match self {
            Self::Exec {
                seccomp_profile, ..
            }
            | Self::Adb {
                seccomp_profile, ..
            } => seccomp_profile,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypedOperationDefinitionV1 {
    pub operation: TypedBrokerOperationV1,
    pub adapter: TypedBrokerAdapterV1,
    pub backend_status: &'static str,
    pub descriptor: ExecutionDescriptorV1,
}

pub const EXEC_INSPECT_BUILD_FINGERPRINT: TypedOperationDefinitionV1 = TypedOperationDefinitionV1 {
    operation: TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1,
    adapter: TypedBrokerAdapterV1::TypedExec,
    backend_status: "standalone_source_fixture_only_not_packaged",
    descriptor: ExecutionDescriptorV1::Exec {
        executable: "/system/bin/getprop",
        argv0: "getprop",
        argv: EXEC_FINGERPRINT_ARGV,
        uid: 2000,
        gid: 2000,
        selinux_domain: "u:r:trillionnium_typed_broker_userdebug:s0",
        cgroup_profile: "typed-exec-inspect-build-fingerprint-userdebug-v1",
        seccomp_profile: "typed-exec-inspect-build-fingerprint-userdebug-v1",
        controls: EXEC_CONTROLS,
    },
};

pub const ADB_INSPECT_PACKAGE_SETTINGS: TypedOperationDefinitionV1 = TypedOperationDefinitionV1 {
    operation: TypedBrokerOperationV1::AdbInspectPackageSettingsUserdebugV1,
    adapter: TypedBrokerAdapterV1::TypedAdb,
    backend_status: "descriptor_and_protocol_only_hold",
    descriptor: ExecutionDescriptorV1::Adb {
        target: "self_device_only",
        transport: "os_owned_local_userdebug_adbd",
        service: "abb_exec",
        service_arguments: ADB_PACKAGE_SETTINGS_ARGUMENTS,
        adbd_key_custody: "absent_hold_not_agent_addressable",
        product_identity: "os_selected_local_userdebug_device_avb_identity",
        cgroup_profile: "typed-adb-inspect-package-settings-userdebug-v1",
        seccomp_profile: "typed-adb-inspect-package-settings-userdebug-v1",
        controls: ADB_CONTROLS,
    },
};

pub const SOURCE_OPERATIONS: &[&TypedOperationDefinitionV1] = &[
    &EXEC_INSPECT_BUILD_FINGERPRINT,
    &ADB_INSPECT_PACKAGE_SETTINGS,
];

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosedEmptyArgumentsV1 {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerBindingIdentityV1 {
    pub schema: String,
    pub provider_id: String,
    pub agent_id: String,
    pub direct_binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub agent_executable_sha256: String,
}

impl BrokerBindingIdentityV1 {
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.schema != BINDING_IDENTITY_SCHEMA {
            return Err(ProtocolError::BindingIdentityInvalid);
        }
        principal(&self.provider_id, &self.agent_id)
            .ok_or(ProtocolError::BindingIdentityInvalid)?;
        if !valid_nonzero_sha256(&self.direct_binding_sha256)
            || !valid_prefixed_sha256(&self.invocation_id, "inv:")
            || !valid_prefixed_sha256(&self.delivery_provider_attempt_id, "attempt:")
            || !valid_nonzero_sha256(&self.agent_executable_sha256)
        {
            return Err(ProtocolError::BindingIdentityInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedBrokerRequestV1 {
    pub schema: String,
    pub catalog_sha256: String,
    pub provider_id: String,
    pub agent_id: String,
    pub direct_binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub operation_ordinal: u64,
    pub operation_identity_sha256: String,
    pub operation_id: TypedBrokerOperationV1,
    pub arguments: ClosedEmptyArgumentsV1,
    pub absolute_deadline_boot_ms: u64,
    pub request_sha256: String,
}

impl TypedBrokerRequestV1 {
    pub fn derive(
        binding: &BrokerBindingIdentityV1,
        operation_ordinal: u64,
        operation_id: TypedBrokerOperationV1,
        absolute_deadline_boot_ms: u64,
    ) -> ProtocolResult<Self> {
        binding.validate()?;
        if operation_ordinal == 0 || absolute_deadline_boot_ms == 0 {
            return Err(ProtocolError::RequestIdentityInvalid);
        }
        let operation_identity_sha256 = operation_identity_sha256(binding, operation_ordinal);
        let mut request = Self {
            schema: REQUEST_SCHEMA.to_string(),
            catalog_sha256: CATALOG_SHA256.to_string(),
            provider_id: binding.provider_id.clone(),
            agent_id: binding.agent_id.clone(),
            direct_binding_sha256: binding.direct_binding_sha256.clone(),
            invocation_id: binding.invocation_id.clone(),
            delivery_provider_attempt_id: binding.delivery_provider_attempt_id.clone(),
            operation_ordinal,
            operation_identity_sha256,
            operation_id,
            arguments: ClosedEmptyArgumentsV1 {},
            absolute_deadline_boot_ms,
            request_sha256: String::new(),
        };
        request.request_sha256 = request.expected_request_sha256()?;
        request.validate_identity_for(binding)?;
        Ok(request)
    }

    pub fn validate_identity_for(&self, binding: &BrokerBindingIdentityV1) -> ProtocolResult<()> {
        binding.validate()?;
        if self.schema != REQUEST_SCHEMA
            || self.catalog_sha256 != CATALOG_SHA256
            || self.provider_id != binding.provider_id
            || self.agent_id != binding.agent_id
            || self.direct_binding_sha256 != binding.direct_binding_sha256
            || self.invocation_id != binding.invocation_id
            || self.delivery_provider_attempt_id != binding.delivery_provider_attempt_id
            || self.operation_ordinal == 0
            || self.absolute_deadline_boot_ms == 0
            || self.operation_identity_sha256
                != operation_identity_sha256(binding, self.operation_ordinal)
            || !valid_nonzero_sha256(&self.request_sha256)
            || self.expected_request_sha256()? != self.request_sha256
        {
            return Err(ProtocolError::RequestIdentityInvalid);
        }
        Ok(())
    }

    /// Fresh delivery validation is intentionally separate from identity
    /// validation so an already committed response remains replayable after
    /// its original execution deadline.
    pub fn validate_first_delivery_for(
        &self,
        binding: &BrokerBindingIdentityV1,
        now_boot_ms: u64,
    ) -> ProtocolResult<()> {
        self.validate_identity_for(binding)?;
        let maximum = self
            .operation_id
            .definition()
            .descriptor
            .controls()
            .deadline_ms;
        let remaining = self
            .absolute_deadline_boot_ms
            .checked_sub(now_boot_ms)
            .ok_or(ProtocolError::DeadlineExpired)?;
        if remaining == 0 {
            return Err(ProtocolError::DeadlineExpired);
        }
        if remaining > maximum {
            return Err(ProtocolError::DeadlineExceedsCatalogBound);
        }
        Ok(())
    }

    pub fn expected_request_sha256(&self) -> ProtocolResult<String> {
        if self.schema != REQUEST_SCHEMA
            || self.catalog_sha256 != CATALOG_SHA256
            || principal(&self.provider_id, &self.agent_id).is_none()
            || !valid_nonzero_sha256(&self.direct_binding_sha256)
            || !valid_prefixed_sha256(&self.invocation_id, "inv:")
            || !valid_prefixed_sha256(&self.delivery_provider_attempt_id, "attempt:")
            || self.operation_ordinal == 0
            || !valid_nonzero_sha256(&self.operation_identity_sha256)
            || self.absolute_deadline_boot_ms == 0
        {
            return Err(ProtocolError::RequestIdentityInvalid);
        }
        Ok(sha256_json(&json!({
            "domain": REQUEST_DIGEST_DOMAIN,
            "schema": self.schema,
            "catalog_sha256": self.catalog_sha256,
            "provider_id": self.provider_id,
            "agent_id": self.agent_id,
            "direct_binding_sha256": self.direct_binding_sha256,
            "invocation_id": self.invocation_id,
            "delivery_provider_attempt_id": self.delivery_provider_attempt_id,
            "operation_ordinal": self.operation_ordinal,
            "operation_identity_sha256": self.operation_identity_sha256,
            "operation_id": self.operation_id,
            "arguments": self.arguments,
            "absolute_deadline_boot_ms": self.absolute_deadline_boot_ms,
        })))
    }

    pub fn canonical_wire_bytes(&self) -> ProtocolResult<Vec<u8>> {
        if !valid_nonzero_sha256(&self.request_sha256)
            || self.expected_request_sha256()? != self.request_sha256
        {
            return Err(ProtocolError::RequestIdentityInvalid);
        }
        let wire = serde_json::to_vec(self).map_err(|_| ProtocolError::CanonicalEncodingFailed)?;
        if wire.len() > MAX_REQUEST_WIRE_BYTES {
            return Err(ProtocolError::RequestTooLarge);
        }
        Ok(wire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypedBrokerOutcomeV1 {
    Completed,
    CommandFailed,
    TimedOutIndeterminate,
    OutputLimitIndeterminate,
    BackendIndeterminate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedBrokerResponseV1 {
    pub schema: String,
    pub catalog_sha256: String,
    pub provider_id: String,
    pub agent_id: String,
    pub direct_binding_sha256: String,
    pub invocation_id: String,
    pub delivery_provider_attempt_id: String,
    pub operation_ordinal: u64,
    pub operation_identity_sha256: String,
    pub operation_id: TypedBrokerOperationV1,
    pub request_sha256: String,
    pub outcome: TypedBrokerOutcomeV1,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub elapsed_ms: u64,
    pub response_sha256: String,
}

impl TypedBrokerResponseV1 {
    pub(crate) fn terminal(
        request: &TypedBrokerRequestV1,
        outcome: TypedBrokerOutcomeV1,
        exit_code: Option<i32>,
        stdout: String,
        stderr: String,
        elapsed_ms: u64,
    ) -> ProtocolResult<Self> {
        let mut response = Self {
            schema: RESPONSE_SCHEMA.to_string(),
            catalog_sha256: CATALOG_SHA256.to_string(),
            provider_id: request.provider_id.clone(),
            agent_id: request.agent_id.clone(),
            direct_binding_sha256: request.direct_binding_sha256.clone(),
            invocation_id: request.invocation_id.clone(),
            delivery_provider_attempt_id: request.delivery_provider_attempt_id.clone(),
            operation_ordinal: request.operation_ordinal,
            operation_identity_sha256: request.operation_identity_sha256.clone(),
            operation_id: request.operation_id,
            request_sha256: request.request_sha256.clone(),
            outcome,
            exit_code,
            stdout_sha256: sha256_bytes(stdout.as_bytes()),
            stderr_sha256: sha256_bytes(stderr.as_bytes()),
            stdout,
            stderr,
            elapsed_ms,
            response_sha256: String::new(),
        };
        response.response_sha256 = response.expected_response_sha256()?;
        response.validate_for(request)?;
        Ok(response)
    }

    pub fn validate_for(&self, request: &TypedBrokerRequestV1) -> ProtocolResult<()> {
        let controls = request.operation_id.definition().descriptor.controls();
        let state_is_valid = match self.outcome {
            TypedBrokerOutcomeV1::Completed => self.exit_code == Some(0),
            TypedBrokerOutcomeV1::CommandFailed => self.exit_code.is_some_and(|code| code != 0),
            TypedBrokerOutcomeV1::TimedOutIndeterminate
            | TypedBrokerOutcomeV1::OutputLimitIndeterminate
            | TypedBrokerOutcomeV1::BackendIndeterminate => self.exit_code.is_none(),
        };
        let stdout_bytes = self.stdout.len();
        let stderr_bytes = self.stderr.len();
        if self.schema != RESPONSE_SCHEMA
            || self.catalog_sha256 != CATALOG_SHA256
            || self.provider_id != request.provider_id
            || self.agent_id != request.agent_id
            || self.direct_binding_sha256 != request.direct_binding_sha256
            || self.invocation_id != request.invocation_id
            || self.delivery_provider_attempt_id != request.delivery_provider_attempt_id
            || self.operation_ordinal != request.operation_ordinal
            || self.operation_identity_sha256 != request.operation_identity_sha256
            || self.operation_id != request.operation_id
            || self.request_sha256 != request.request_sha256
            || !state_is_valid
            || stdout_bytes > controls.stdout_limit_bytes
            || stderr_bytes > controls.stderr_limit_bytes
            || stdout_bytes.saturating_add(stderr_bytes) > controls.total_output_limit_bytes
            || self.stdout_sha256 != sha256_bytes(self.stdout.as_bytes())
            || self.stderr_sha256 != sha256_bytes(self.stderr.as_bytes())
            || !valid_nonzero_sha256(&self.response_sha256)
            || self.expected_response_sha256()? != self.response_sha256
        {
            return Err(ProtocolError::ResponseInvalid);
        }
        let wire = serde_json::to_vec(self).map_err(|_| ProtocolError::CanonicalEncodingFailed)?;
        if wire.len() > MAX_RESPONSE_WIRE_BYTES {
            return Err(ProtocolError::ResponseTooLarge);
        }
        Ok(())
    }

    pub fn expected_response_sha256(&self) -> ProtocolResult<String> {
        if self.schema != RESPONSE_SCHEMA
            || self.catalog_sha256 != CATALOG_SHA256
            || principal(&self.provider_id, &self.agent_id).is_none()
            || !valid_nonzero_sha256(&self.direct_binding_sha256)
            || !valid_prefixed_sha256(&self.invocation_id, "inv:")
            || !valid_prefixed_sha256(&self.delivery_provider_attempt_id, "attempt:")
            || self.operation_ordinal == 0
            || !valid_nonzero_sha256(&self.operation_identity_sha256)
            || !valid_nonzero_sha256(&self.request_sha256)
            || !valid_nonzero_sha256(&self.stdout_sha256)
            || !valid_nonzero_sha256(&self.stderr_sha256)
        {
            return Err(ProtocolError::ResponseInvalid);
        }
        Ok(sha256_json(&json!({
            "domain": RESPONSE_DIGEST_DOMAIN,
            "schema": self.schema,
            "catalog_sha256": self.catalog_sha256,
            "provider_id": self.provider_id,
            "agent_id": self.agent_id,
            "direct_binding_sha256": self.direct_binding_sha256,
            "invocation_id": self.invocation_id,
            "delivery_provider_attempt_id": self.delivery_provider_attempt_id,
            "operation_ordinal": self.operation_ordinal,
            "operation_identity_sha256": self.operation_identity_sha256,
            "operation_id": self.operation_id,
            "request_sha256": self.request_sha256,
            "outcome": self.outcome,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "elapsed_ms": self.elapsed_ms,
        })))
    }

    pub fn canonical_wire_bytes(&self, request: &TypedBrokerRequestV1) -> ProtocolResult<Vec<u8>> {
        self.validate_for(request)?;
        serde_json::to_vec(self).map_err(|_| ProtocolError::CanonicalEncodingFailed)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ProtocolError {
    #[error("binding identity is invalid")]
    BindingIdentityInvalid,
    #[error("typed broker request identity is invalid")]
    RequestIdentityInvalid,
    #[error("request deadline has expired")]
    DeadlineExpired,
    #[error("request deadline exceeds the catalog bound")]
    DeadlineExceedsCatalogBound,
    #[error("typed broker response is invalid")]
    ResponseInvalid,
    #[error("typed broker request exceeds the wire bound")]
    RequestTooLarge,
    #[error("typed broker response exceeds the wire bound")]
    ResponseTooLarge,
    #[error("canonical JSON encoding failed")]
    CanonicalEncodingFailed,
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;

#[must_use]
pub fn embedded_catalog_measurement_is_exact() -> bool {
    sha256_bytes(include_bytes!(
        "../contracts/typed-exec-adb-broker-conformance-v1.json"
    )) == CATALOG_SHA256
}

#[must_use]
pub fn definition_as_json(definition: &TypedOperationDefinitionV1) -> Value {
    let descriptor = match definition.descriptor {
        ExecutionDescriptorV1::Exec {
            executable,
            argv0,
            argv,
            uid,
            gid,
            selinux_domain,
            cgroup_profile,
            seccomp_profile,
            controls,
        } => json!({
            "executable": executable,
            "argv0": argv0,
            "argv": argv,
            "uid": uid,
            "gid": gid,
            "selinux_domain": selinux_domain,
            "cgroup_profile": cgroup_profile,
            "seccomp_profile": seccomp_profile,
            "capabilities": [],
            "environment": {},
            "stdin": "closed",
            "filesystem_scope": controls.filesystem_scope,
            "network_scope": controls.network_scope,
            "deadline_ms": controls.deadline_ms,
            "stdout_limit_bytes": controls.stdout_limit_bytes,
            "stderr_limit_bytes": controls.stderr_limit_bytes,
            "total_output_limit_bytes": controls.total_output_limit_bytes,
            "descendant_process_policy": controls.descendant_process_policy,
            "opaque_fd_passing": false,
        }),
        ExecutionDescriptorV1::Adb {
            target,
            transport,
            service,
            service_arguments,
            adbd_key_custody,
            product_identity,
            cgroup_profile,
            seccomp_profile,
            controls,
        } => json!({
            "target": target,
            "transport": transport,
            "service": service,
            "service_arguments": service_arguments,
            "serial": null,
            "host": null,
            "port": null,
            "adbd_key_custody": adbd_key_custody,
            "product_identity": product_identity,
            "cgroup_profile": cgroup_profile,
            "seccomp_profile": seccomp_profile,
            "capabilities": [],
            "environment": {},
            "stdin": "closed",
            "filesystem_scope": controls.filesystem_scope,
            "network_scope": controls.network_scope,
            "deadline_ms": controls.deadline_ms,
            "stdout_limit_bytes": controls.stdout_limit_bytes,
            "stderr_limit_bytes": controls.stderr_limit_bytes,
            "total_output_limit_bytes": controls.total_output_limit_bytes,
            "descendant_process_policy": controls.descendant_process_policy,
            "opaque_fd_passing": false,
        }),
    };
    json!({
        "operation_id": definition.operation.as_str(),
        "adapter": definition.adapter.as_str(),
        "backend_status": definition.backend_status,
        "agent_arguments": {
            "shape": "closed_empty_object",
            "unknown_fields": "reject",
        },
        "execution_descriptor": descriptor,
        "admission": {
            "product_variants": ["userdebug"],
            "risk_class": "read_only_transport_conformance",
            "userdebug_conformance_only": true,
            "direct_system_api_unavailable_proof_required": true,
            "single_delivery_attempt_required": true,
        },
    })
}

#[must_use]
pub fn operation_identity_sha256(
    binding: &BrokerBindingIdentityV1,
    operation_ordinal: u64,
) -> String {
    sha256_json(&json!({
        "domain": OPERATION_IDENTITY_DOMAIN,
        "provider_id": binding.provider_id,
        "agent_id": binding.agent_id,
        "direct_binding_sha256": binding.direct_binding_sha256,
        "invocation_id": binding.invocation_id,
        "delivery_provider_attempt_id": binding.delivery_provider_attempt_id,
        "operation_ordinal": operation_ordinal,
    }))
}

#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut value = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

#[must_use]
pub fn sha256_json(value: &Value) -> String {
    sha256_bytes(&serde_json::to_vec(value).expect("serde_json::Value serialization cannot fail"))
}

#[must_use]
pub fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value != "0000000000000000000000000000000000000000000000000000000000000000"
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_prefixed_sha256(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(valid_nonzero_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: &str) -> String {
        sha256_bytes(seed.as_bytes())
    }

    fn binding() -> BrokerBindingIdentityV1 {
        BrokerBindingIdentityV1 {
            schema: BINDING_IDENTITY_SCHEMA.to_string(),
            provider_id: CODEX.provider_id.to_string(),
            agent_id: CODEX.agent_id.to_string(),
            direct_binding_sha256: digest("binding"),
            invocation_id: format!("inv:{}", digest("invocation")),
            delivery_provider_attempt_id: format!("attempt:{}", digest("attempt")),
            agent_executable_sha256: digest("agent-executable"),
        }
    }

    #[test]
    fn measured_contract_and_rust_operation_projection_are_exact() {
        assert!(embedded_catalog_measurement_is_exact());
        let contract: Value = serde_json::from_slice(include_bytes!(
            "../contracts/typed-exec-adb-broker-conformance-v1.json"
        ))
        .expect("contract JSON");
        assert_eq!(contract["schema"], CATALOG_SCHEMA);
        assert_eq!(contract["status"], CATALOG_STATUS);
        assert_eq!(contract["product_effect_authority"], false);
        assert_eq!(contract["android_product_graph_member"], false);
        assert_eq!(
            contract["principals"],
            json!([{
                "provider_id": CODEX.provider_id,
                "agent_id": CODEX.agent_id,
                "uid": CODEX.uid,
                "gid": CODEX.gid,
                "selinux_domain": CODEX.selinux_domain,
                "cgroup_leaf": CODEX.cgroup_leaf,
            }])
        );
        let operations = contract["operations"].as_array().expect("operations");
        assert_eq!(operations.len(), SOURCE_OPERATIONS.len());
        for (measured, definition) in operations.iter().zip(SOURCE_OPERATIONS) {
            assert_eq!(measured, &definition_as_json(definition));
        }
        assert!(
            contract["promotion_gates"]
                .as_object()
                .expect("promotion gates")
                .values()
                .all(|gate| gate == false)
        );
    }

    #[test]
    fn request_is_exactly_bound_and_deadline_bounded() {
        let binding = binding();
        let request = TypedBrokerRequestV1::derive(
            &binding,
            1,
            TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1,
            15_000,
        )
        .expect("request");
        request
            .validate_first_delivery_for(&binding, 10_001)
            .expect("bounded deadline");
        assert_eq!(
            request.validate_first_delivery_for(&binding, 9_999),
            Err(ProtocolError::DeadlineExceedsCatalogBound)
        );
        assert_eq!(
            request.validate_first_delivery_for(&binding, 15_000),
            Err(ProtocolError::DeadlineExpired)
        );
        let mut drift = request.clone();
        drift.delivery_provider_attempt_id = format!("attempt:{}", digest("other"));
        assert_eq!(
            drift.validate_identity_for(&binding),
            Err(ProtocolError::RequestIdentityInvalid)
        );
    }

    #[test]
    fn unknown_fields_shell_mutations_and_nonempty_arguments_are_not_parseable() {
        let request = TypedBrokerRequestV1::derive(
            &binding(),
            1,
            TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1,
            15_000,
        )
        .expect("request");
        let mut value = serde_json::to_value(&request).expect("request JSON");
        value["arguments"] = json!({"argv": ["sh", "-c", "id"]});
        assert!(serde_json::from_value::<TypedBrokerRequestV1>(value).is_err());
        for operation in [
            "exec.arbitrary.v1",
            "adb.shell.v1",
            "adb.install.v1",
            "adb.reboot.v1",
            "windows.launch.v1",
        ] {
            let mut value = serde_json::to_value(&request).expect("request JSON");
            value["operation_id"] = Value::String(operation.to_string());
            assert!(serde_json::from_value::<TypedBrokerRequestV1>(value).is_err());
        }
        let mut value = serde_json::to_value(&request).expect("request JSON");
        value["serial"] = Value::String("caller-selected".to_string());
        assert!(serde_json::from_value::<TypedBrokerRequestV1>(value).is_err());
    }

    #[test]
    fn descriptors_have_fixed_non_mutating_vectors_and_no_target_selection() {
        match EXEC_INSPECT_BUILD_FINGERPRINT.descriptor {
            ExecutionDescriptorV1::Exec {
                executable,
                argv0,
                argv,
                controls,
                ..
            } => {
                assert_eq!(executable, "/system/bin/getprop");
                assert_eq!(argv0, "getprop");
                assert_eq!(argv, &["ro.build.fingerprint"]);
                assert_eq!(controls.network_scope, "none");
                assert!(!argv.iter().any(|token| matches!(*token, "sh" | "-c")));
            }
            _ => panic!("exec descriptor drifted"),
        }
        match ADB_INSPECT_PACKAGE_SETTINGS.descriptor {
            ExecutionDescriptorV1::Adb {
                target,
                service,
                service_arguments,
                adbd_key_custody,
                ..
            } => {
                assert_eq!(target, "self_device_only");
                assert_eq!(service, "abb_exec");
                assert_eq!(
                    service_arguments,
                    &["package", "path", "com.android.settings"]
                );
                assert_eq!(adbd_key_custody, "absent_hold_not_agent_addressable");
                assert!(!service_arguments.iter().any(|token| matches!(
                    *token,
                    "shell" | "sh" | "-c" | "push" | "pull" | "install" | "reboot"
                )));
            }
            _ => panic!("ADB descriptor drifted"),
        }
    }

    #[test]
    fn response_state_output_and_digest_are_closed() {
        let request = TypedBrokerRequestV1::derive(
            &binding(),
            1,
            TypedBrokerOperationV1::ExecInspectBuildFingerprintUserdebugV1,
            15_000,
        )
        .expect("request");
        let response = TypedBrokerResponseV1::terminal(
            &request,
            TypedBrokerOutcomeV1::Completed,
            Some(0),
            "trillionnium/fogos/userdebug\n".to_string(),
            String::new(),
            4,
        )
        .expect("response");
        response.validate_for(&request).expect("valid response");
        let mut drift = response.clone();
        drift.stdout.push_str("tamper");
        assert_eq!(
            drift.validate_for(&request),
            Err(ProtocolError::ResponseInvalid)
        );
        assert!(response.canonical_wire_bytes(&request).unwrap().len() < MAX_RESPONSE_WIRE_BYTES);
    }
}
