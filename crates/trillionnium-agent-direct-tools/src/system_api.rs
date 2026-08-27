use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::mcp::McpTool;
use crate::risk_guard::{AgentIdentity, GuardEvidence, ProductRiskGuard};
#[cfg(any(test, feature = "development-compatibility-lane"))]
use crate::semantic_identity::BackendRequestIdentityAuthor;
use crate::{
    DirectToolError, Result, reject_reserved_backend_fields, valid_request_id,
    validate_response_binding,
};

pub const DEFAULT_SOCKET: &str = "@trillionnium_system_api";
pub const PROTOCOL: &str = "org.trillionnium.agent-system-api.v1";
pub const MCP_TOOL_NAME: &str = "trillionnium_system_api";
const MAX_ANDROID_USER_ID: u32 = 999;
const SEMANTIC_PENDING_REQUEST_ID: &str = "os-semantic-pending";

/// Model-facing System API action. Protocol, Android user, and replay identity
/// are intentionally absent and are added only inside the OS adapter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemApiSemanticRequest {
    LaunchPackage { package: String },
    OpenUri { uri: String },
}

impl SystemApiSemanticRequest {
    fn to_backend_request(&self, request_id: String) -> SystemApiRequest {
        match self {
            Self::LaunchPackage { package } => SystemApiRequest::LaunchPackage {
                protocol: PROTOCOL.to_string(),
                request_id,
                package: package.clone(),
                user: 0,
            },
            Self::OpenUri { uri } => SystemApiRequest::OpenUri {
                protocol: PROTOCOL.to_string(),
                request_id,
                uri: uri.clone(),
                user: 0,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemApiRequest {
    LaunchPackage {
        protocol: String,
        request_id: String,
        package: String,
        user: u32,
    },
    OpenUri {
        protocol: String,
        request_id: String,
        uri: String,
        user: u32,
    },
}

impl SystemApiRequest {
    pub fn protocol(&self) -> &str {
        match self {
            Self::LaunchPackage { protocol, .. } | Self::OpenUri { protocol, .. } => protocol,
        }
    }

    pub fn request_id(&self) -> &str {
        match self {
            Self::LaunchPackage { request_id, .. } | Self::OpenUri { request_id, .. } => request_id,
        }
    }
}

/// Return the exact OS semantic-operation digest used by the durable System API
/// journal for one Codex MCP request. The model-facing JSON cannot supply a
/// replay ID, Android user, protocol, or replay namespace; those fields remain
/// fixed by the OS canonical-operation contract.
pub fn canonical_semantic_request_sha256_for_codex(
    semantic: &SystemApiSemanticRequest,
) -> Result<String> {
    validate_semantic(semantic)?;
    let request = semantic.to_backend_request(SEMANTIC_PENDING_REQUEST_ID.to_string());
    let canonical = crate::canonical_operation::system_api_request(AgentIdentity::Codex, &request)?;
    Ok(crate::operation_journal::Sha256Digest::of_bytes(&canonical).to_hex())
}

/// Convert one validated semantic action into the unchanged Android wire ABI.
/// The injected author sees the semantic bytes but no caller-supplied protocol,
/// Android user, or candidate replay ID.
#[cfg(any(test, feature = "development-compatibility-lane"))]
pub fn author_backend_request(
    semantic: &SystemApiSemanticRequest,
    author: &mut impl BackendRequestIdentityAuthor,
) -> Result<SystemApiRequest> {
    validate_semantic(semantic)?;
    let semantic_bytes = serde_json::to_vec(semantic)?;
    let request_id = author.author_backend_request_id("system_api", &semantic_bytes)?;
    let request = semantic.to_backend_request(request_id);
    validate(&request)?;
    Ok(request)
}

#[cfg(any(test, feature = "development-compatibility-lane"))]
pub fn call(path: &Path, request: &SystemApiRequest) -> Result<Value> {
    let agent = crate::risk_guard::current_agent_identity()?;
    call_as(path, request, agent)
}

#[cfg(any(test, feature = "development-compatibility-lane"))]
pub fn call_semantic(
    path: &Path,
    semantic: &SystemApiSemanticRequest,
    author: &mut impl BackendRequestIdentityAuthor,
) -> Result<Value> {
    let request = author_backend_request(semantic, author)?;
    call(path, &request)
}

/// Feature-gated integration entry point after the executable has consumed its
/// fixed hidden launch context. Allowed operations enter the trusted journal
/// before the backend is contacted and release a result only after its exact
/// response digest and closed outcome are durable.
pub fn call_trusted(
    path: &Path,
    request: &SystemApiRequest,
    context: &crate::trusted_context::TrustedAdapterContext,
) -> Result<Value> {
    if context.adapter()
        != trillionnium_os_types::direct_operation::DirectOperationAdapter::SystemApi
    {
        return Err(DirectToolError::InvalidRequest(
            "trusted context adapter does not match System API".to_string(),
        ));
    }
    let agent = crate::risk_guard::current_agent_identity()?;
    if let Some(denial) = trusted_preflight(request, agent)? {
        return Ok(denial);
    }
    context
        .require_product_effect_custody()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    context
        .require_no_pending_outer_ack_v3()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    let journal = context
        .open_operation_journal()
        .map_err(crate::journaled_call::journal_error)?;
    #[cfg(feature = "production-durable-hotpath")]
    {
        let mut journal = journal;
        call_allowed_journaled(path, request, agent, context, &mut journal)
    }
    #[cfg(not(feature = "production-durable-hotpath"))]
    {
        let _ = (path, request, agent, context, journal);
        Err(DirectToolError::BackendUnavailable(
            "production durable tool-call identity is not compiled".to_string(),
        ))
    }
}

/// Trusted semantic entry point. The temporary request identity is used only
/// for validation/risk/canonicalization; [`call_trusted`] replaces it with the
/// durable journal-authored identity before contacting the backend.
pub fn call_semantic_trusted(
    path: &Path,
    semantic: &SystemApiSemanticRequest,
    context: &crate::trusted_context::TrustedAdapterContext,
) -> Result<Value> {
    validate_semantic(semantic)?;
    let request = semantic.to_backend_request(SEMANTIC_PENDING_REQUEST_ID.to_string());
    call_trusted(path, &request, context)
}

/// Non-product P0 vertical-slice entry point.
///
/// It keeps the normal typed semantic/risk/canonical/backend path, but uses a
/// daemon-allocated logical-call identity and the separate durable conformance
/// journal without claiming production kernel custody or mutation-CAS
/// authority. The caller cannot provide a wire request ID, Android user,
/// backend socket, tool-call identity, or effect ordinal.
#[cfg(feature = "device-launch-package-conformance")]
pub(crate) fn call_semantic_device_conformance(
    path: &Path,
    semantic: &SystemApiSemanticRequest,
    context: &crate::trusted_context::TrustedAdapterContext,
    journal: &mut crate::operation_journal::OperationJournal,
) -> Result<Value> {
    if context.adapter()
        != trillionnium_os_types::direct_operation::DirectOperationAdapter::SystemApi
    {
        return Err(DirectToolError::InvalidRequest(
            "device-conformance context adapter does not match System API".to_string(),
        ));
    }
    validate_semantic(semantic)?;
    let request = semantic.to_backend_request(SEMANTIC_PENDING_REQUEST_ID.to_string());
    let agent = crate::risk_guard::current_agent_identity()?;
    if let Some(denial) = trusted_preflight(&request, agent)? {
        return Ok(denial);
    }
    let canonical_request = crate::canonical_operation::system_api_request(agent, &request)?;
    let session = crate::direct_tool_call_transport::prepare_p0_userdebug_effect(
        context,
        journal,
        &canonical_request,
    )?;
    let result = execute_prepared(path, &request, agent, journal, session.prepared.clone());
    crate::direct_tool_call_transport::complete_p0_userdebug_effect(session, context, journal)?;
    result
}

fn trusted_preflight(request: &SystemApiRequest, agent: AgentIdentity) -> Result<Option<Value>> {
    validate(request)?;
    if request_user(request) != 0 {
        return Err(DirectToolError::InvalidRequest(
            "trusted System API calls are bound to Android user 0".to_string(),
        ));
    }
    let guard = ProductRiskGuard.assess_system_request(agent, request);
    Ok((!guard.allowed()).then(|| guard_denial(request, guard)))
}

#[cfg(feature = "production-durable-hotpath")]
fn call_allowed_journaled(
    path: &Path,
    request: &SystemApiRequest,
    agent: AgentIdentity,
    context: &crate::trusted_context::TrustedAdapterContext,
    journal: &mut crate::operation_journal::OperationJournal,
) -> Result<Value> {
    let canonical_request = crate::canonical_operation::system_api_request(agent, request)?;
    let prepared = crate::direct_tool_call_transport::prepare_product_effect(
        context,
        journal,
        &canonical_request,
    )?;
    execute_prepared(path, request, agent, journal, prepared)
}

fn execute_prepared(
    path: &Path,
    request: &SystemApiRequest,
    _agent: AgentIdentity,
    journal: &mut crate::operation_journal::OperationJournal,
    prepared: crate::operation_journal::PreparedOperation,
) -> Result<Value> {
    let backend_request = with_backend_identity(request, prepared.request_id.clone());
    crate::journaled_call::execute(
        path,
        crate::uds::ExpectedBackendPeer::SystemServer,
        &backend_request,
        journal,
        &prepared,
        |response| {
            validate_response_binding(response, PROTOCOL, &prepared.request_id)?;
            reject_reserved_backend_fields(
                response,
                &[
                    "risk_guard",
                    crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD,
                    crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD,
                ],
            )
        },
    )
}

#[cfg(test)]
fn call_journaled(
    path: &Path,
    request: &SystemApiRequest,
    agent: AgentIdentity,
    journal: &mut crate::operation_journal::OperationJournal,
) -> Result<Value> {
    if let Some(denial) = trusted_preflight(request, agent)? {
        return Ok(denial);
    }
    let canonical_request = crate::canonical_operation::system_api_request(agent, request)?;
    let prepared = journal
        .begin_next_effect(&canonical_request)
        .map_err(crate::journaled_call::journal_error)?
        .into_prepared();
    execute_prepared(path, request, agent, journal, prepared)
}

#[cfg(test)]
fn call_journaled_with_identity(
    path: &Path,
    request: &SystemApiRequest,
    agent: AgentIdentity,
    journal: &mut crate::operation_journal::OperationJournal,
    os_tool_call_id: &str,
    adapter_effect_ordinal: u64,
) -> Result<Value> {
    if let Some(denial) = trusted_preflight(request, agent)? {
        return Ok(denial);
    }
    let canonical_request = crate::canonical_operation::system_api_request(agent, request)?;
    let prepared = journal
        .begin_effect_with_identity(os_tool_call_id, adapter_effect_ordinal, &canonical_request)
        .map_err(crate::journaled_call::journal_error)?
        .into_prepared();
    execute_prepared(path, request, agent, journal, prepared)
}

#[cfg(test)]
fn call_journaled_with_allocation_authority(
    path: &Path,
    request: &SystemApiRequest,
    agent: AgentIdentity,
    journal: &mut crate::operation_journal::OperationJournal,
    binding: &trillionnium_os_types::direct_operation::DirectOperationBinding,
    authority: &mut impl crate::trusted_context::ToolCallAllocationAuthority,
) -> Result<Value> {
    if let Some(denial) = trusted_preflight(request, agent)? {
        return Ok(denial);
    }
    let canonical_request = crate::canonical_operation::system_api_request(agent, request)?;
    let binding_sha256 = binding
        .digest_sha256()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    let tool_call = crate::trusted_context::allocate_tool_call_with_authority(
        binding,
        &binding_sha256,
        trillionnium_os_types::direct_operation::DirectOperationAdapter::SystemApi,
        &canonical_request,
        authority,
    )
    .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
    let prepared = journal
        .begin_effect_with_identity(
            &tool_call.os_tool_call_id,
            tool_call.adapter_effect_ordinal,
            &canonical_request,
        )
        .map_err(crate::journaled_call::journal_error)?
        .into_prepared();
    execute_prepared(path, request, agent, journal, prepared)
}

fn with_backend_identity(request: &SystemApiRequest, request_id: String) -> SystemApiRequest {
    match request {
        SystemApiRequest::LaunchPackage { package, user, .. } => SystemApiRequest::LaunchPackage {
            protocol: PROTOCOL.to_string(),
            request_id,
            package: package.clone(),
            user: *user,
        },
        SystemApiRequest::OpenUri { uri, user, .. } => SystemApiRequest::OpenUri {
            protocol: PROTOCOL.to_string(),
            request_id,
            uri: uri.clone(),
            user: *user,
        },
    }
}

fn request_user(request: &SystemApiRequest) -> u32 {
    match request {
        SystemApiRequest::LaunchPackage { user, .. } | SystemApiRequest::OpenUri { user, .. } => {
            *user
        }
    }
}

/// Execute one typed request under an already authenticated Agent identity.
/// Default product binaries currently use [`call`], which derives identity from
/// fixed process credentials. This explicit form keeps the non-journaled
/// compatibility lane directly testable without weakening either boundary.
#[cfg(any(
    test,
    feature = "development-compatibility-lane",
    feature = "device-launch-package-conformance"
))]
pub(crate) fn call_as(
    path: &Path,
    request: &SystemApiRequest,
    agent: AgentIdentity,
) -> Result<Value> {
    validate(request)?;
    let guard = ProductRiskGuard.assess_system_request(agent, request);
    if !guard.allowed() {
        return Ok(guard_denial(request, guard));
    }
    let response = crate::uds::call(path, crate::uds::ExpectedBackendPeer::SystemServer, request)?;
    validate_response_binding(&response, PROTOCOL, request.request_id())?;
    reject_reserved_backend_fields(
        &response,
        &[
            "risk_guard",
            crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD,
            crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD,
        ],
    )?;
    Ok(response)
}

fn guard_denial(request: &SystemApiRequest, evidence: GuardEvidence) -> Value {
    json!({
        "protocol": PROTOCOL,
        "request_id": request.request_id(),
        "ok": false,
        "error": "operation_denied",
        "risk_guard": evidence,
    })
}

pub fn validate(request: &SystemApiRequest) -> Result<()> {
    if request.protocol() != PROTOCOL {
        return Err(DirectToolError::InvalidRequest(format!(
            "system API protocol must be {PROTOCOL}"
        )));
    }
    if !valid_request_id(request.request_id()) {
        return Err(DirectToolError::InvalidRequest(
            "invalid system API request_id".to_string(),
        ));
    }
    let user = match request {
        SystemApiRequest::LaunchPackage { package, user, .. } => {
            if !valid_package(package) {
                return Err(DirectToolError::InvalidRequest(
                    "invalid Android package name".to_string(),
                ));
            }
            *user
        }
        SystemApiRequest::OpenUri { uri, user, .. } => {
            if !valid_uri(uri) {
                return Err(DirectToolError::InvalidRequest(
                    "unsupported or malformed URI".to_string(),
                ));
            }
            *user
        }
    };
    if user > MAX_ANDROID_USER_ID {
        return Err(DirectToolError::InvalidRequest(format!(
            "Android user must be in 0..={MAX_ANDROID_USER_ID}"
        )));
    }
    Ok(())
}

pub fn validate_semantic(request: &SystemApiSemanticRequest) -> Result<()> {
    match request {
        SystemApiSemanticRequest::LaunchPackage { package } if valid_package(package) => Ok(()),
        SystemApiSemanticRequest::OpenUri { uri } if valid_uri(uri) => Ok(()),
        SystemApiSemanticRequest::LaunchPackage { .. } => Err(DirectToolError::InvalidRequest(
            "invalid Android package name".to_string(),
        )),
        SystemApiSemanticRequest::OpenUri { .. } => Err(DirectToolError::InvalidRequest(
            "unsupported or malformed URI".to_string(),
        )),
    }
}

fn valid_package(package: &str) -> bool {
    !package.is_empty()
        && package.len() <= 255
        && package.split('.').all(|segment| {
            let mut bytes = segment.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

fn valid_uri(uri: &str) -> bool {
    !uri.is_empty()
        && uri.len() <= 4096
        && !uri.chars().any(|character| {
            character == '\0' || character.is_control() || character.is_whitespace()
        })
        && ["https://", "http://", "content://", "geo:"]
            .iter()
            .any(|scheme| uri.starts_with(scheme) && uri.len() > scheme.len())
}

pub fn mcp_tool() -> McpTool {
    McpTool {
        name: MCP_TOOL_NAME,
        description: "Request one bounded Trillionnium Android System API action.",
        input_schema: json!({
            "oneOf": [
                {
                    "type": "object",
                    "required": ["action", "package"],
                    "properties": {
                        "action": {"const": "launch_package"},
                        "package": {"type": "string", "minLength": 1, "maxLength": 255}
                    },
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "required": ["action", "uri"],
                    "properties": {
                        "action": {"const": "open_uri"},
                        "uri": {"type": "string", "minLength": 1, "maxLength": 4096}
                    },
                    "additionalProperties": false
                }
            ]
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::io::{BufRead, BufReader, Cursor, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::thread;

    use super::*;
    use trillionnium_os_types::direct_operation::{
        BINDING_SCHEMA, DirectOperationBinding, DirectOperationProviderAttempt,
        DirectOperationStableSeed, DirectOperationToolCallEnvelopeV3,
        DirectOperationUncorrelatedToolCallAllocationRequestV3, OS_TOOL_CALL_ID_PREFIX,
        STABLE_SEED_SCHEMA, TOOL_CALL_ENVELOPE_V3_SCHEMA,
    };

    const JOURNAL_ATTEMPT_ID: &str =
        "attempt:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct FixedAuthor(&'static str);

    impl BackendRequestIdentityAuthor for FixedAuthor {
        fn author_backend_request_id(
            &mut self,
            adapter: &'static str,
            semantic_request: &[u8],
        ) -> Result<String> {
            assert_eq!(adapter, "system_api");
            assert!(
                !semantic_request
                    .windows(8)
                    .any(|bytes| bytes == b"protocol")
            );
            assert!(!semantic_request.windows(4).any(|bytes| bytes == b"user"));
            Ok(self.0.to_string())
        }
    }

    fn journal(path: &Path) -> crate::operation_journal::OperationJournal {
        crate::operation_journal::OperationJournal::open(
            path,
            "codex",
            "system_api",
            "inv-system-live-1",
            JOURNAL_ATTEMPT_ID,
        )
        .unwrap()
    }

    fn launch_package(package: &str, user: u32) -> SystemApiRequest {
        SystemApiRequest::LaunchPackage {
            protocol: PROTOCOL.to_string(),
            request_id: "req-system-1".to_string(),
            package: package.to_string(),
            user,
        }
    }

    fn digest(character: char) -> String {
        character.to_string().repeat(64)
    }

    fn direct_binding() -> DirectOperationBinding {
        let seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: "openai-codex".to_string(),
            agent_id: "agent-codex-direct-v1".to_string(),
            task_id: "task-system-api-per-call".to_string(),
            provider_invocation_id_sha256: digest('1'),
            provider_session_id_sha256: digest('2'),
            subject_uid: 5_901,
            subject_selinux_domain_sha256: digest('3'),
        };
        let binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            invocation_id: seed.invocation_id().unwrap(),
            stable_seed: seed,
            workflow_id_sha256: digest('4'),
            agent_identity_key_sha256: digest('5'),
            agent_executable_sha256: digest('6'),
            authorized_adapter_set: trillionnium_os_types::direct_operation::DirectOperationAuthorizedAdapterSetV3::p0_system_api(),
            attempt: DirectOperationProviderAttempt::derive(digest('7'), 1, digest('8')).unwrap(),
        };
        binding.validate().unwrap();
        binding
    }

    struct SequenceToolCallAuthority {
        identities: VecDeque<(char, u64)>,
    }

    impl SequenceToolCallAuthority {
        fn new(identities: impl IntoIterator<Item = (char, u64)>) -> Self {
            Self {
                identities: identities.into_iter().collect(),
            }
        }
    }

    impl crate::trusted_context::ToolCallAllocationAuthority for SequenceToolCallAuthority {
        fn allocate(
            &mut self,
            request: &DirectOperationUncorrelatedToolCallAllocationRequestV3,
        ) -> crate::trusted_context::TrustedContextResult<DirectOperationToolCallEnvelopeV3>
        {
            let (token_character, ordinal) = self.identities.pop_front().ok_or(
                crate::trusted_context::TrustedContextError::ToolCallAllocationUnavailable,
            )?;
            let mut envelope = DirectOperationToolCallEnvelopeV3 {
                schema: TOOL_CALL_ENVELOPE_V3_SCHEMA.to_string(),
                binding_sha256: request.binding_sha256.clone(),
                invocation_id: request.invocation_id.clone(),
                delivery_provider_attempt_id: request.delivery_provider_attempt_id.clone(),
                provider_id: request.provider_id.clone(),
                agent_id: request.agent_id.clone(),
                adapter: request.adapter,
                os_tool_call_id: format!("{OS_TOOL_CALL_ID_PREFIX}{}", digest(token_character)),
                adapter_effect_ordinal: ordinal,
                canonical_request_sha256: request.canonical_request_sha256.clone(),
                envelope_sha256: String::new(),
            };
            envelope.envelope_sha256 = envelope.digest_sha256().map_err(|error| {
                crate::trusted_context::TrustedContextError::Corrupt(error.to_string())
            })?;
            Ok(envelope)
        }
    }

    struct UnavailableToolCallAuthority;

    impl crate::trusted_context::ToolCallAllocationAuthority for UnavailableToolCallAuthority {
        fn allocate(
            &mut self,
            _request: &DirectOperationUncorrelatedToolCallAllocationRequestV3,
        ) -> crate::trusted_context::TrustedContextResult<DirectOperationToolCallEnvelopeV3>
        {
            Err(crate::trusted_context::TrustedContextError::ToolCallAllocationUnavailable)
        }
    }

    fn call_with_raw_backend_response(response: Vec<u8>) -> Result<Value> {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("system-api-response.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let result = call(&socket, &launch_package("com.example", 0));
        server.join().unwrap();
        result
    }

    #[test]
    fn validates_versioned_direct_framework_requests() {
        assert!(validate(&launch_package("com.example", 0)).is_ok());
        assert!(
            validate(&SystemApiRequest::OpenUri {
                protocol: PROTOCOL.to_string(),
                request_id: "req-system-1".to_string(),
                uri: "file:///data/private".to_string(),
                user: 0,
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_loose_packages_users_and_request_identity() {
        for package in ["", "com..example", "-bad.example", "com.example/"] {
            assert!(
                validate(&launch_package(package, 0)).is_err(),
                "accepted {package}"
            );
        }
        let mut invalid_user = SystemApiRequest::LaunchPackage {
            protocol: PROTOCOL.to_string(),
            request_id: "req-system-1".to_string(),
            package: "com.example".to_string(),
            user: u32::MAX,
        };
        assert!(validate(&invalid_user).is_err());
        if let SystemApiRequest::LaunchPackage { request_id, .. } = &mut invalid_user {
            *request_id = "contains whitespace".to_string();
        }
        assert!(validate(&invalid_user).is_err());
    }

    #[test]
    fn risk_guard_denies_sensitive_uri_before_any_backend_connection() {
        let request = SystemApiRequest::OpenUri {
            protocol: PROTOCOL.to_string(),
            request_id: "req-risk-denied".to_string(),
            uri: "https://example.com/".to_string(),
            user: 0,
        };
        let response = call_as(
            Path::new("/definitely/missing/system-api.sock"),
            &request,
            AgentIdentity::Codex,
        )
        .expect("risk denial is a structured no-effect outcome");
        assert_eq!(response["protocol"], PROTOCOL);
        assert_eq!(response["request_id"], "req-risk-denied");
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"], "operation_denied");
        assert_eq!(response["risk_guard"]["agent"], "codex");
        assert_eq!(response["risk_guard"]["decision"], "deny");
        assert_eq!(response["risk_guard"]["risk_tier"], "critical_effect");
        assert_eq!(
            response["risk_guard"]["reason_code"],
            "trusted_lease_issuer_unavailable"
        );
    }

    #[test]
    fn mcp_schema_is_closed_and_semantic_only() {
        let schema = mcp_tool().input_schema;
        let variants = schema["oneOf"].as_array().unwrap();
        assert_eq!(variants.len(), 2);
        assert!(
            variants
                .iter()
                .all(|variant| variant["additionalProperties"] == Value::Bool(false))
        );
        let schema_text = serde_json::to_string(&schema).unwrap();
        for reserved in ["protocol", "request_id", "\"user\""] {
            assert!(!schema_text.contains(reserved), "leaked {reserved}");
        }
        assert_eq!(
            variants
                .iter()
                .map(|variant| variant["properties"]["action"]["const"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["launch_package", "open_uri"]
        );
    }

    #[test]
    fn semantic_request_cannot_supply_envelope_and_os_authors_wire_identity() {
        let semantic = SystemApiSemanticRequest::LaunchPackage {
            package: "com.example".to_string(),
        };
        let request =
            author_backend_request(&semantic, &mut FixedAuthor("os:semantic-fixed-1")).unwrap();
        assert_eq!(
            request,
            SystemApiRequest::LaunchPackage {
                protocol: PROTOCOL.to_string(),
                request_id: "os:semantic-fixed-1".to_string(),
                package: "com.example".to_string(),
                user: 0,
            }
        );
        for reserved in [
            json!({
                "action": "launch_package",
                "package": "com.example",
                "protocol": PROTOCOL
            }),
            json!({
                "action": "launch_package",
                "package": "com.example",
                "request_id": "model-id"
            }),
            json!({
                "action": "launch_package",
                "package": "com.example",
                "user": 10
            }),
        ] {
            assert!(serde_json::from_value::<SystemApiSemanticRequest>(reserved).is_err());
        }
    }

    #[test]
    fn backend_ok_false_is_a_structured_system_api_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("system-api-failed.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            stream
                .write_all(
                    b"{\"protocol\":\"org.trillionnium.agent-system-api.v1\",\"request_id\":\"req-system-1\",\"ok\":false,\"error\":\"request_id_conflict\",\"retry_with_same_id\":false}\n",
                )
                .unwrap();
        });
        let response = call(&socket, &launch_package("com.example", 0)).unwrap();
        assert_eq!(
            response,
            json!({
                "protocol": PROTOCOL,
                "request_id": "req-system-1",
                "ok": false,
                "error": "request_id_conflict",
                "retry_with_same_id": false
            })
        );
        server.join().unwrap();
    }

    #[test]
    fn trusted_journal_authors_backend_identity_and_exactly_replays_result() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("system-api-journaled.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (identities, received_identities) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let request_id = request["request_id"].as_str().unwrap().to_string();
            identities.send(request_id.clone()).unwrap();
            let mut response = serde_json::to_vec(&json!({
                "protocol": PROTOCOL,
                "request_id": request_id,
                "ok": true
            }))
            .unwrap();
            response.push(b'\n');
            stream.write_all(&response).unwrap();
        });

        let journal_path = directory.path().join("operations.json");
        let mut first_journal = journal(&journal_path);
        let mut request = launch_package("com.example", 0);
        let first =
            call_journaled(&socket, &request, AgentIdentity::Codex, &mut first_journal).unwrap();
        let first_backend_id = received_identities.recv().unwrap();
        server.join().unwrap();
        let first_operation = first_journal
            .recovery_plan()
            .unwrap()
            .unwrap()
            .operations
            .into_iter()
            .next()
            .unwrap();
        drop(first_journal);
        fs::remove_file(&socket).unwrap();

        // Simulate adapter/provider restart after the exact terminal result was
        // durable. The backend is gone: recovery must return the persisted
        // terminal object and must not attempt a second effect or connection.
        let mut journal = journal(&journal_path);
        if let SystemApiRequest::LaunchPackage { request_id, .. } = &mut request {
            *request_id = "different-model-request-id".to_string();
        }
        let second = call_journaled_with_identity(
            &socket,
            &request,
            AgentIdentity::Codex,
            &mut journal,
            &first_operation.os_tool_call_id,
            first_operation.adapter_effect_ordinal,
        )
        .unwrap();

        assert!(first_backend_id.starts_with("op:"));
        assert_ne!(first_backend_id, "req-system-1");
        assert_eq!(first, second);
        assert_eq!(first["request_id"], first_backend_id);
        assert!(received_identities.try_recv().is_err());
        let recovery = journal.recovery_plan().unwrap().unwrap();
        assert_eq!(recovery.operations.len(), 1);
        assert!(matches!(
            recovery.operations[0].state,
            crate::operation_journal::RecoveryOperationState::ResultRecorded {
                outcome: crate::OperationOutcome::Success,
                ..
            }
        ));
    }

    #[test]
    fn two_os_call_tokens_for_same_action_produce_two_distinct_backend_effects() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("system-api-repeated-action.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let mut request_ids = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                let request_id = request["request_id"].as_str().unwrap().to_string();
                request_ids.push(request_id.clone());
                serde_json::to_writer(
                    &mut stream,
                    &json!({
                        "protocol": PROTOCOL,
                        "request_id": request_id,
                        "ok": true
                    }),
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            }
            request_ids
        });

        let journal_path = directory.path().join("operations.json");
        let mut journal = journal(&journal_path);
        let request = launch_package("com.example.repeated", 0);
        let first = call_journaled(&socket, &request, AgentIdentity::Codex, &mut journal).unwrap();
        let second = call_journaled(&socket, &request, AgentIdentity::Codex, &mut journal).unwrap();
        let request_ids = server.join().unwrap();

        assert_eq!(request_ids.len(), 2);
        assert_ne!(request_ids[0], request_ids[1]);
        assert_eq!(first["request_id"], request_ids[0]);
        assert_eq!(second["request_id"], request_ids[1]);
        let recovery = journal.recovery_plan().unwrap().unwrap();
        assert_eq!(recovery.operations.len(), 2);
        assert_ne!(
            recovery.operations[0].os_tool_call_id,
            recovery.operations[1].os_tool_call_id
        );
        assert_eq!(
            recovery.operations[0].canonical_request_sha256,
            recovery.operations[1].canonical_request_sha256
        );
    }

    #[test]
    fn long_lived_mcp_allocates_per_call_and_exact_retry_does_not_reconnect() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("system-api-mcp-per-call.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let mut request_ids = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                let request_id = request["request_id"].as_str().unwrap().to_string();
                request_ids.push(request_id.clone());
                serde_json::to_writer(
                    &mut stream,
                    &json!({
                        "protocol": PROTOCOL,
                        "request_id": request_id,
                        "ok": true
                    }),
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            }
            request_ids
        });

        let binding = direct_binding();
        let journal_path = directory.path().join("mcp-operations.json");
        let mut journal = crate::operation_journal::OperationJournal::open(
            &journal_path,
            &binding.stable_seed.agent_id,
            "system_api",
            &binding.invocation_id,
            &binding.attempt.delivery_provider_attempt_id,
        )
        .unwrap();
        let mut authority = SequenceToolCallAuthority::new([('a', 0), ('b', 1), ('b', 1)]);
        let semantic = json!({
            "action": "launch_package",
            "package": "com.example.mcp.repeated"
        });
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": crate::mcp::PROTOCOL_VERSION}
            }),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": MCP_TOOL_NAME, "arguments": semantic.clone()}
            }),
            json!({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": MCP_TOOL_NAME, "arguments": semantic.clone()}
            }),
            json!({
                "jsonrpc": "2.0", "id": 5, "method": "tools/call",
                "params": {"name": MCP_TOOL_NAME, "arguments": semantic}
            }),
        ]
        .into_iter()
        .map(|value| format!("{}\n", serde_json::to_string(&value).unwrap()))
        .collect::<String>();
        let mut output = Vec::new();
        crate::mcp::serve(
            BufReader::new(Cursor::new(input)),
            &mut output,
            "system-api-per-call-fixture",
            mcp_tool(),
            |arguments| {
                let semantic: SystemApiSemanticRequest = serde_json::from_value(arguments)?;
                validate_semantic(&semantic)?;
                let request = semantic.to_backend_request(SEMANTIC_PENDING_REQUEST_ID.to_string());
                call_journaled_with_allocation_authority(
                    &socket,
                    &request,
                    AgentIdentity::Codex,
                    &mut journal,
                    &binding,
                    &mut authority,
                )
            },
        )
        .unwrap();
        let backend_request_ids = server.join().unwrap();
        assert_eq!(backend_request_ids.len(), 2);
        assert_ne!(backend_request_ids[0], backend_request_ids[1]);

        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 5);
        assert_eq!(
            responses[3]["result"]["structuredContent"],
            responses[4]["result"]["structuredContent"],
            "retrying the same OS token must replay exact terminal bytes"
        );
        assert_eq!(
            responses[2]["result"]["structuredContent"]["request_id"],
            backend_request_ids[0]
        );
        assert_eq!(
            responses[3]["result"]["structuredContent"]["request_id"],
            backend_request_ids[1]
        );
        let recovery = journal.recovery_plan().unwrap().unwrap();
        assert_eq!(recovery.operations.len(), 2);
        assert_ne!(
            recovery.operations[0].os_tool_call_id,
            recovery.operations[1].os_tool_call_id
        );
        assert_eq!(
            recovery.operations[0].canonical_request_sha256,
            recovery.operations[1].canonical_request_sha256
        );
    }

    #[test]
    fn valid_launch_binding_allows_mcp_metadata_but_missing_allocator_never_connects() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let missing_socket = directory.path().join("backend-must-not-be-created.sock");
        let binding = direct_binding();
        let mut journal = crate::operation_journal::OperationJournal::open(
            directory.path().join("unavailable-operations.json"),
            &binding.stable_seed.agent_id,
            "system_api",
            &binding.invocation_id,
            &binding.attempt.delivery_provider_attempt_id,
        )
        .unwrap();
        let input = [
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": crate::mcp::PROTOCOL_VERSION}
            }),
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {
                    "name": MCP_TOOL_NAME,
                    "arguments": {
                        "action": "launch_package",
                        "package": "com.example.must.hold"
                    }
                }
            }),
        ]
        .into_iter()
        .map(|value| format!("{}\n", serde_json::to_string(&value).unwrap()))
        .collect::<String>();
        let mut authority = UnavailableToolCallAuthority;
        let mut output = Vec::new();
        crate::mcp::serve(
            BufReader::new(Cursor::new(input)),
            &mut output,
            "system-api-missing-allocator-fixture",
            mcp_tool(),
            |arguments| {
                let semantic: SystemApiSemanticRequest = serde_json::from_value(arguments)?;
                validate_semantic(&semantic)?;
                let request = semantic.to_backend_request(SEMANTIC_PENDING_REQUEST_ID.to_string());
                call_journaled_with_allocation_authority(
                    &missing_socket,
                    &request,
                    AgentIdentity::Codex,
                    &mut journal,
                    &binding,
                    &mut authority,
                )
            },
        )
        .unwrap();

        assert!(
            !missing_socket.exists(),
            "missing allocation authority must not create or connect a backend socket"
        );
        assert!(journal.recovery_plan().unwrap().is_none());
        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(responses.len(), 3);
        assert_eq!(
            responses[0]["result"]["protocolVersion"],
            crate::mcp::PROTOCOL_VERSION
        );
        assert_eq!(responses[1]["result"]["tools"].as_array().unwrap().len(), 1);
        assert_eq!(responses[2]["result"]["isError"], true);
        assert!(
            responses[2]["result"]["structuredContent"]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("per-logical-call allocation authority is unavailable")
        );
    }

    #[test]
    fn trusted_system_user_is_fixed_before_journal_or_backend_effect() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut journal = journal(&directory.path().join("operations.json"));
        let error = call_journaled(
            Path::new("/backend-must-not-be-contacted.sock"),
            &launch_package("com.example", 10),
            AgentIdentity::Codex,
            &mut journal,
        )
        .unwrap_err();
        assert!(error.to_string().contains("bound to Android user 0"));
        assert!(journal.recovery_plan().unwrap().is_none());
    }

    #[test]
    fn codex_semantic_parser_digest_matches_the_journal_canonical_operation() {
        let semantic: SystemApiSemanticRequest = serde_json::from_value(json!({
            "action": "launch_package",
            "package": "com.android.settings",
        }))
        .unwrap();
        let backend = semantic.to_backend_request(SEMANTIC_PENDING_REQUEST_ID.to_string());
        let canonical =
            crate::canonical_operation::system_api_request(AgentIdentity::Codex, &backend).unwrap();
        assert_eq!(
            canonical_semantic_request_sha256_for_codex(&semantic).unwrap(),
            crate::operation_journal::Sha256Digest::of_bytes(&canonical).to_hex()
        );
    }

    #[test]
    fn fixed_settings_route_binds_to_system_api_test_seam_and_replays_once() {
        // This is deliberately a unit-test-only bridge: the durable fixed
        // route receives the existing typed System API callback, while the
        // backend is a bounded local UDS fixture. No product authority,
        // device socket, or conformance binary is reachable from this test.
        const EPOCH: &str = "0123456789abcdef0123456789abcdef";
        let directory = tempfile::tempdir().unwrap();
        let route_root = directory.path().join("fixed-settings-route");
        fs::create_dir(&route_root).unwrap();
        fs::set_permissions(&route_root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("system-api-settings.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let backend_calls = Arc::new(AtomicUsize::new(0));
        let backend_calls_for_server = Arc::clone(&backend_calls);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            backend_calls_for_server.fetch_add(1, Ordering::SeqCst);
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let request_id = request["request_id"].as_str().unwrap().to_string();
            request_tx.send(request).unwrap();
            serde_json::to_writer(
                &mut stream,
                &json!({
                    "protocol": PROTOCOL,
                    "request_id": request_id,
                    "ok": true,
                    "foreground_package": "com.android.settings",
                }),
            )
            .unwrap();
            stream.write_all(b"\n").unwrap();
        });

        let semantic = crate::fixed_settings_route::fixed_request();
        let first = {
            let mut route =
                crate::fixed_settings_route::FixedSettingsRoute::open(&route_root, EPOCH).unwrap();
            let expected_operation_id = route.operation_id().to_string();
            let outcome = route
                .execute_once(&semantic, |request| call(&socket, request))
                .unwrap();
            assert!(!outcome.replayed);
            assert_eq!(outcome.operation_id, expected_operation_id);
            route.acknowledge().unwrap();
            outcome
        };
        server.join().unwrap();

        let backend_request = request_rx.recv().unwrap();
        assert_eq!(backend_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend_request["protocol"], PROTOCOL);
        assert_eq!(backend_request["action"], "launch_package");
        assert_eq!(backend_request["package"], "com.android.settings");
        assert_eq!(backend_request["user"], 0);
        assert_eq!(
            backend_request["request_id"], first.operation_id,
            "the route, not the model, authors the backend request identity"
        );

        // Remove the fixture endpoint before reopening. A correct durable
        // route must replay its receipt/ACK without even invoking the callback.
        fs::remove_file(&socket).unwrap();
        let callback_calls = std::cell::Cell::new(0);
        let mut reopened =
            crate::fixed_settings_route::FixedSettingsRoute::open(&route_root, EPOCH).unwrap();
        let replay = reopened
            .execute_once(&semantic, |_request| {
                callback_calls.set(callback_calls.get() + 1);
                Err(DirectToolError::BackendFailed(
                    "replay must not contact the backend".to_string(),
                ))
            })
            .unwrap();
        assert!(replay.replayed);
        assert_eq!(replay.operation_id, first.operation_id);
        assert_eq!(replay.response_bytes, first.response_bytes);
        assert_eq!(replay.receipt_sha256, first.receipt_sha256);
        assert_eq!(callback_calls.get(), 0);
        assert_eq!(
            reopened.phase(),
            crate::fixed_settings_route::RoutePhase::Acked
        );
    }

    #[test]
    fn journaled_system_result_separates_raw_replay_and_semantic_evidence_digests() {
        for (label, ok, error, golden_semantic_digest) in [
            (
                "success",
                true,
                None,
                "9b8d295653814c2c4666f6f8d4287d1658766993cbb911fb4996f715f63c17f0",
            ),
            (
                "error",
                false,
                Some("request_id_conflict"),
                "d98dbfaf56bc5b0a67df60c0f94c366c9d2a31a594aacbfde4068ac5acfe3f74",
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let socket = directory.path().join(format!("system-api-{label}.sock"));
            let listener = UnixListener::bind(&socket).unwrap();
            let (digest_tx, digest_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                let request_id = request["request_id"].as_str().unwrap();
                let exact_response = if let Some(error) = error {
                    format!(
                        "{{ \"retry_with_same_id\" : false, \"error\" : \"{error}\", \"ok\" : false, \"request_id\" : \"{request_id}\", \"protocol\" : \"{PROTOCOL}\" }}"
                    )
                    .into_bytes()
                } else {
                    format!(
                        "{{ \"ok\" : {ok}, \"request_id\" : \"{request_id}\", \"protocol\" : \"{PROTOCOL}\" }}"
                    )
                    .into_bytes()
                };
                let response: Value = serde_json::from_slice(&exact_response).unwrap();
                digest_tx
                    .send((
                        crate::operation_journal::Sha256Digest::of_bytes(&exact_response).to_hex(),
                        crate::semantic_result::canonical_semantic_result_sha256(&response)
                            .unwrap(),
                    ))
                    .unwrap();
                stream.write_all(&exact_response).unwrap();
                stream.write_all(b"\n").unwrap();
            });
            let mut journal = journal(&directory.path().join("operations.json"));
            let result = call_journaled(
                &socket,
                &launch_package("com.android.settings", 0),
                AgentIdentity::Codex,
                &mut journal,
            )
            .unwrap();
            server.join().unwrap();
            let (exact_digest, semantic_digest) = digest_rx.recv().unwrap();
            assert_eq!(semantic_digest, golden_semantic_digest);
            assert_eq!(
                result[crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD],
                exact_digest
            );
            assert_eq!(
                result[crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD],
                semantic_digest
            );
            let recovery = journal.recovery_plan().unwrap().unwrap();
            let crate::operation_journal::RecoveryOperationState::ResultRecorded {
                backend_result_sha256,
                ..
            } = &recovery.operations[0].state
            else {
                panic!("journaled backend result did not recover as RESULT_RECORDED");
            };
            assert_eq!(backend_result_sha256.to_hex(), exact_digest);
            let request = launch_package("com.android.settings", 0);
            let canonical =
                crate::canonical_operation::system_api_request(AgentIdentity::Codex, &request)
                    .unwrap();
            let crate::operation_journal::RecoveryDecision::ResultRecorded(evidence) =
                journal.recover_effect(&canonical).unwrap()
            else {
                panic!("terminal backend result did not recover as evidence");
            };
            assert_eq!(evidence.raw_backend_result_sha256.to_hex(), exact_digest);
            assert_eq!(evidence.backend_result_sha256.to_hex(), semantic_digest);
            assert_eq!(
                evidence.to_outer_evidence().unwrap().backend_result_sha256,
                semantic_digest
            );
        }
    }

    #[test]
    fn malformed_or_mismatched_backend_outcome_fails_closed_after_uds() {
        let oversized_error = json!({
            "protocol": PROTOCOL,
            "request_id": "req-system-1",
            "ok": false,
            "error": "x".repeat(crate::MAX_BACKEND_ERROR_CODE_BYTES + 1)
        });
        let mut oversized_error = serde_json::to_vec(&oversized_error).unwrap();
        oversized_error.push(b'\n');
        for response in [
            b"{not-json}\n".to_vec(),
            b"{\"protocol\":\"wrong\",\"request_id\":\"req-system-1\",\"ok\":true}\n".to_vec(),
            b"{\"protocol\":\"org.trillionnium.agent-system-api.v1\",\"request_id\":\"wrong\",\"ok\":true}\n".to_vec(),
            b"{\"protocol\":\"org.trillionnium.agent-system-api.v1\",\"request_id\":\"req-system-1\"}\n".to_vec(),
            b"{\"protocol\":\"org.trillionnium.agent-system-api.v1\",\"request_id\":\"req-system-1\",\"ok\":\"false\",\"error\":\"request_in_flight\"}\n".to_vec(),
            b"{\"protocol\":\"org.trillionnium.agent-system-api.v1\",\"request_id\":\"req-system-1\",\"ok\":false,\"error\":\"contains whitespace\"}\n".to_vec(),
            b"{\"protocol\":\"org.trillionnium.agent-system-api.v1\",\"request_id\":\"req-system-1\",\"ok\":true,\"risk_guard\":{\"decision\":\"allow\"}}\n".to_vec(),
            format!(
                "{{\"protocol\":\"{PROTOCOL}\",\"request_id\":\"req-system-1\",\"ok\":true,\"{}\":\"{}\"}}\n",
                crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD,
                "a".repeat(64),
            )
            .into_bytes(),
            format!(
                "{{\"protocol\":\"{PROTOCOL}\",\"request_id\":\"req-system-1\",\"ok\":true,\"{}\":\"{}\"}}\n",
                crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD,
                "b".repeat(64),
            )
            .into_bytes(),
            oversized_error,
        ] {
            assert!(call_with_raw_backend_response(response).is_err());
        }
    }

    #[test]
    fn serde_rejects_unknown_duplicate_and_trailing_request_material() {
        let valid = format!(
            "{{\"protocol\":\"{PROTOCOL}\",\"request_id\":\"req-1\",\"action\":\"launch_package\",\"package\":\"com.example\",\"user\":0}}"
        );
        assert!(serde_json::from_str::<SystemApiRequest>(&valid).is_ok());
        let retired_explicit_component = format!(
            "{{\"protocol\":\"{PROTOCOL}\",\"request_id\":\"req-1\",\"action\":\"start_activity\",\"component\":\"com.example/.MainActivity\",\"user\":0}}"
        );
        assert!(serde_json::from_str::<SystemApiRequest>(&retired_explicit_component).is_err());
        assert!(
            serde_json::from_str::<SystemApiRequest>(
                &valid.replace("\"user\":0", "\"user\":0,\"unknown\":true")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<SystemApiRequest>(&valid.replace(
                "\"request_id\":\"req-1\"",
                "\"request_id\":\"req-1\",\"request_id\":\"req-2\""
            ))
            .is_err()
        );
        assert!(serde_json::from_str::<SystemApiRequest>(&format!("{valid}{{}}")).is_err());
    }
}
