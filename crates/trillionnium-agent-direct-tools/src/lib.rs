#![cfg_attr(
    all(not(test), not(feature = "production-durable-hotpath")),
    allow(dead_code)
)]
//! The operation-journal mutation CAS client is deliberately crate-private
//! until a real provisioned authority backend and journal integration exist.
//!
//! ```compile_fail
//! use trillionnium_agent_direct_tools::
//!     direct_operation_runtime_authority_mutation_cas_client::
//!     SealedCommittedMutationCasSession;
//! ```
// The empty feature set is an intentionally inert build-check surface, while
// the development compatibility lane deliberately compiles only the
// pre-journal subset. Their remaining private production custody code is
// exercised by tests or the mutually exclusive durable product lane.

pub mod accessibility;
pub mod adb;
pub mod adb_wire;
#[allow(dead_code)]
pub(crate) mod android_operation_replay_ack;
#[allow(dead_code)]
pub(crate) mod android_operation_replay_control;
mod canonical_operation;
#[cfg(feature = "device-launch-package-conformance")]
pub mod device_launch_package_conformance;
#[cfg(feature = "device-launch-package-conformance")]
pub mod device_launch_package_conformance_replay_sync;
/// Source-only sealed mutation-CAS client. Product builds have no constructible
/// backend; the only authority implementation is confined to module tests.
#[allow(dead_code)]
mod direct_operation_runtime_authority_mutation_cas_client;
/// Source-only same-store first-use/genesis authority core. Product builds
/// have an uninhabited backend and no constructor, transport, or listener.
#[allow(dead_code)]
mod direct_operation_runtime_authority_store_session;
/// Source-only fixed carrier for the independent operation runtime authority.
/// The current contract can return only a closed fail-closed HOLD and has no
/// product connector or authority constructor.
#[allow(dead_code)]
mod direct_operation_runtime_authority_transport;
#[cfg(any(
    test,
    feature = "production-durable-hotpath",
    feature = "device-launch-package-conformance"
))]
mod direct_tool_call_transport;
/// Source-only fixed Settings durability/replay seam. The route is deliberately
/// absent from ordinary product builds: it has no rollback anchor, lease
/// issuer, daemon allocator, or Android ACK authority and must not become a
/// production effect path by accidental linkage. It is available only to
/// unit tests and explicitly non-product conformance/development lanes.
#[cfg(any(
    test,
    feature = "development-compatibility-lane",
    feature = "device-launch-package-conformance"
))]
pub mod fixed_settings_route;
mod journaled_call;
mod linux_syscall;
pub mod mcp;
pub mod operation_journal;
pub mod operation_replay_sync;
pub mod post_exec_admission;
#[cfg(any(test, feature = "production-durable-hotpath"))]
pub mod production_entry_hardening;
pub mod risk_guard;
pub mod root_publication_transport;
/// Source-level typestate ceremony with a one-shot journal-open consumer seam;
/// no adapter has a production authority constructor or transport.
#[allow(dead_code)]
pub(crate) mod secure_first_use_journal;
#[cfg(any(test, feature = "development-compatibility-lane"))]
pub mod semantic_identity;
pub mod semantic_result;
pub mod system_api;
pub mod trusted_context;
mod uds;

/// Adapter-authored digest of the exact bounded backend response bytes that
/// were durably recorded before the MCP result was released. Backends are
/// forbidden from supplying this field themselves.
pub const OS_RAW_BACKEND_RESULT_SHA256_FIELD: &str = "trillionnium_os_raw_backend_result_sha256";

/// Adapter-authored, domain-separated digest of the canonical semantic
/// backend result. Backends are forbidden from supplying this field; the
/// adapter inserts it only after typed response validation and raw durability.
pub const OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD: &str =
    "trillionnium_os_canonical_semantic_result_sha256";

#[cfg(all(
    feature = "production-durable-hotpath",
    feature = "dev-overrides",
    not(feature = "development-compatibility-lane")
))]
compile_error!(
    "production-durable-hotpath and dev-overrides are mutually exclusive custody domains"
);

#[cfg(all(
    feature = "production-durable-hotpath",
    feature = "development-compatibility-lane"
))]
compile_error!(
    "production-durable-hotpath and development-compatibility-lane are mutually exclusive effect lanes"
);

#[cfg(all(
    feature = "trusted-context-hotpath",
    not(feature = "production-durable-hotpath"),
    not(test)
))]
compile_error!(
    "trusted-context-hotpath is source-only; product binaries must select production-durable-hotpath"
);

#[cfg(all(
    feature = "device-launch-package-conformance",
    any(
        feature = "production-durable-hotpath",
        feature = "trusted-context-hotpath",
        feature = "development-compatibility-lane",
        feature = "dev-overrides"
    )
))]
compile_error!(
    "device-launch-package-conformance is a separate non-product custody domain and cannot be combined with product, trusted-context, compatibility, or override features"
);

use std::io::{self, Read};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_BACKEND_ERROR_CODE_BYTES: usize = 128;

#[derive(Debug, Error)]
pub enum DirectToolError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("backend failed: {0}")]
    BackendFailed(String),
    #[error("backend timed out: {0}")]
    BackendTimedOut(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, DirectToolError>;

pub fn read_request<T: DeserializeOwned>() -> Result<T> {
    let mut bytes = Vec::new();
    io::stdin()
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(DirectToolError::InvalidRequest(
            "stdin must contain one bounded JSON request".to_string(),
        ));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn write_response<T: Serialize>(response: &T) -> Result<()> {
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, response)?;
    use std::io::Write as _;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

/// Product builds always return `default`. Only an explicitly feature-gated
/// development build can redirect a backend for host integration tests.
pub fn production_endpoint(default: &'static str, development_variable: &str) -> String {
    #[cfg(feature = "dev-overrides")]
    {
        std::env::var(development_variable).unwrap_or_else(|_| default.to_string())
    }
    #[cfg(not(feature = "dev-overrides"))]
    {
        let _ = development_variable;
        default.to_string()
    }
}

pub fn valid_atom(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

pub fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendOutcome {
    Success,
    Error,
}

/// Closed, durable outcome classes shared by the direct-adapter journal and
/// the future outer-receipt bridge. Callers do not select this class directly;
/// [`classify_backend_completion`] derives it from an exact backend response or
/// from the adapter's typed transport/protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    Success,
    BackendError,
    Indeterminate,
}

/// What the adapter actually observed after a PREPARED operation was durable.
///
/// `Response` always re-parses and validates the exact bytes supplied to the
/// journal. Every transport, timeout, framing, JSON, or protocol ambiguity is
/// conservatively indeterminate; there is no caller-authored outcome override.
#[derive(Debug, Clone, Copy)]
pub enum BackendCompletion<'a> {
    Response,
    Failure(&'a DirectToolError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedBackendCompletion {
    pub outcome: OperationOutcome,
    pub backend_error_code: Option<String>,
}

/// Classify a backend completion without ever upgrading uncertainty to a
/// definitive result. In particular, `request_in_flight`, timeouts, transport
/// failures, malformed frames, and protocol ambiguity are all indeterminate.
#[must_use]
pub fn classify_backend_completion(
    exact_backend_result: &[u8],
    completion: BackendCompletion<'_>,
    expected_protocol: &str,
    expected_request_id: &str,
) -> ClassifiedBackendCompletion {
    match completion {
        BackendCompletion::Failure(error) => {
            let backend_error_code = match error {
                DirectToolError::BackendTimedOut(_) => "backend_timeout",
                DirectToolError::Io(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    "backend_timeout"
                }
                DirectToolError::BackendUnavailable(_) | DirectToolError::Io(_) => {
                    "backend_transport_error"
                }
                DirectToolError::InvalidRequest(_)
                | DirectToolError::BackendFailed(_)
                | DirectToolError::Json(_) => "backend_protocol_ambiguous",
            };
            ClassifiedBackendCompletion {
                outcome: OperationOutcome::Indeterminate,
                backend_error_code: Some(backend_error_code.to_string()),
            }
        }
        BackendCompletion::Response => {
            let Ok(response) = serde_json::from_slice::<Value>(exact_backend_result) else {
                return indeterminate_protocol_completion();
            };
            match validate_response_binding(&response, expected_protocol, expected_request_id) {
                Ok(BackendOutcome::Success) => ClassifiedBackendCompletion {
                    outcome: OperationOutcome::Success,
                    backend_error_code: None,
                },
                Ok(BackendOutcome::Error) => {
                    let Some(error) = response.get("error").and_then(Value::as_str) else {
                        return indeterminate_protocol_completion();
                    };
                    ClassifiedBackendCompletion {
                        outcome: if is_indeterminate_backend_error_code(error) {
                            OperationOutcome::Indeterminate
                        } else {
                            OperationOutcome::BackendError
                        },
                        backend_error_code: Some(error.to_string()),
                    }
                }
                Err(_) => indeterminate_protocol_completion(),
            }
        }
    }
}

fn is_indeterminate_backend_error_code(value: &str) -> bool {
    matches!(
        value,
        "request_in_flight"
            | "timeout"
            | "backend_timeout"
            | "transport_error"
            | "backend_transport_error"
            | "protocol_ambiguous"
            | "backend_protocol_ambiguous"
    )
}

fn indeterminate_protocol_completion() -> ClassifiedBackendCompletion {
    ClassifiedBackendCompletion {
        outcome: OperationOutcome::Indeterminate,
        backend_error_code: Some("backend_protocol_ambiguous".to_string()),
    }
}

impl BackendOutcome {
    #[must_use]
    pub const fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }
}

/// Validate the common shape of a backend response without changing it.
///
/// A correctly shaped `ok: false` response is a protocol outcome, not a
/// transport failure. Callers must preserve that object so recovery codes such
/// as `request_id_conflict` and `request_in_flight` reach the Agent intact.
pub fn validate_backend_outcome(response: &Value) -> Result<BackendOutcome> {
    let object = response.as_object().ok_or_else(|| {
        DirectToolError::BackendFailed("backend response must be an object".to_string())
    })?;
    let ok = object.get("ok").and_then(Value::as_bool).ok_or_else(|| {
        DirectToolError::BackendFailed("backend response ok must be a boolean".to_string())
    })?;
    if ok {
        if object.contains_key("error") {
            return Err(DirectToolError::BackendFailed(
                "successful backend response must not contain error".to_string(),
            ));
        }
        return Ok(BackendOutcome::Success);
    }

    let error = object.get("error").and_then(Value::as_str).ok_or_else(|| {
        DirectToolError::BackendFailed(
            "failed backend response error must be a string code".to_string(),
        )
    })?;
    if !valid_backend_error_code(error) {
        return Err(DirectToolError::BackendFailed(format!(
            "backend error code must match [a-z][a-z0-9_]* and be at most {MAX_BACKEND_ERROR_CODE_BYTES} bytes"
        )));
    }
    Ok(BackendOutcome::Error)
}

pub fn valid_backend_error_code(value: &str) -> bool {
    if value.len() > MAX_BACKEND_ERROR_CODE_BYTES {
        return false;
    }
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub fn validate_response_binding(
    response: &Value,
    expected_protocol: &str,
    expected_request_id: &str,
) -> Result<BackendOutcome> {
    let object = response.as_object().ok_or_else(|| {
        DirectToolError::BackendFailed("backend response must be an object".to_string())
    })?;
    if object.get("protocol").and_then(Value::as_str) != Some(expected_protocol)
        || object.get("request_id").and_then(Value::as_str) != Some(expected_request_id)
    {
        return Err(DirectToolError::BackendFailed(
            "backend response protocol/request_id binding mismatch".to_string(),
        ));
    }
    validate_backend_outcome(response)
}

/// Backend payloads cannot author fields reserved for adapter-produced
/// security evidence. This keeps a future consumer from confusing untrusted
/// backend material with a local policy decision.
pub fn reject_reserved_backend_fields(response: &Value, fields: &[&str]) -> Result<()> {
    let object = response.as_object().ok_or_else(|| {
        DirectToolError::BackendFailed("backend response must be an object".to_string())
    })?;
    if let Some(field) = fields.iter().find(|field| object.contains_key(**field)) {
        return Err(DirectToolError::BackendFailed(format!(
            "backend response attempted to author reserved {field} field"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_binding_requires_exact_protocol_and_request_id() {
        let response = serde_json::json!({
            "protocol": "protocol.v1",
            "request_id": "request-1",
            "ok": true
        });
        assert_eq!(
            validate_response_binding(&response, "protocol.v1", "request-1").unwrap(),
            BackendOutcome::Success
        );
        assert!(validate_response_binding(&response, "protocol.v2", "request-1").is_err());
        assert!(validate_response_binding(&response, "protocol.v1", "request-2").is_err());

        let recovery = serde_json::json!({
            "protocol": "protocol.v1",
            "request_id": "request-1",
            "ok": false,
            "error": "request_id_conflict",
            "backend_detail": {"preserved": true}
        });
        assert_eq!(
            validate_response_binding(&recovery, "protocol.v1", "request-1").unwrap(),
            BackendOutcome::Error
        );

        for failed in [
            serde_json::json!({"protocol":"protocol.v1","request_id":"request-1"}),
            serde_json::json!({"protocol":"protocol.v1","request_id":"request-1","ok":"true"}),
            serde_json::json!({"protocol":"protocol.v1","request_id":"request-1","ok":false}),
            serde_json::json!({"protocol":"protocol.v1","request_id":"request-1","ok":false,"error":false}),
            serde_json::json!({"protocol":"protocol.v1","request_id":"request-1","ok":false,"error":"contains whitespace"}),
            serde_json::json!({"protocol":"protocol.v1","request_id":"request-1","ok":false,"error":"UPPERCASE"}),
            serde_json::json!({"protocol":"protocol.v1","request_id":"request-1","ok":true,"error":"contradictory"}),
            serde_json::json!({
                "protocol":"protocol.v1",
                "request_id":"request-1",
                "ok":false,
                "error":"x".repeat(MAX_BACKEND_ERROR_CODE_BYTES + 1)
            }),
        ] {
            assert!(validate_response_binding(&failed, "protocol.v1", "request-1").is_err());
        }
    }

    #[test]
    fn backend_completion_classification_never_upgrades_ambiguity() {
        assert_eq!(
            classify_backend_completion(
                br#"{"protocol":"protocol.v1","request_id":"request-1","ok":true}"#,
                BackendCompletion::Response,
                "protocol.v1",
                "request-1",
            ),
            ClassifiedBackendCompletion {
                outcome: OperationOutcome::Success,
                backend_error_code: None,
            }
        );
        assert_eq!(
            classify_backend_completion(
                br#"{"protocol":"protocol.v1","request_id":"request-1","ok":false,"error":"permission_denied"}"#,
                BackendCompletion::Response,
                "protocol.v1",
                "request-1",
            ),
            ClassifiedBackendCompletion {
                outcome: OperationOutcome::BackendError,
                backend_error_code: Some("permission_denied".to_string()),
            }
        );
        assert_eq!(
            classify_backend_completion(
                br#"{"protocol":"protocol.v1","request_id":"request-1","ok":false,"error":"request_in_flight"}"#,
                BackendCompletion::Response,
                "protocol.v1",
                "request-1",
            ),
            ClassifiedBackendCompletion {
                outcome: OperationOutcome::Indeterminate,
                backend_error_code: Some("request_in_flight".to_string()),
            }
        );
        for code in [
            "timeout",
            "backend_timeout",
            "transport_error",
            "backend_transport_error",
            "protocol_ambiguous",
            "backend_protocol_ambiguous",
        ] {
            let response = serde_json::to_vec(&serde_json::json!({
                "protocol": "protocol.v1",
                "request_id": "request-1",
                "ok": false,
                "error": code,
            }))
            .unwrap();
            assert_eq!(
                classify_backend_completion(
                    &response,
                    BackendCompletion::Response,
                    "protocol.v1",
                    "request-1",
                ),
                ClassifiedBackendCompletion {
                    outcome: OperationOutcome::Indeterminate,
                    backend_error_code: Some(code.to_string()),
                }
            );
        }
        assert_eq!(
            classify_backend_completion(
                b"malformed",
                BackendCompletion::Response,
                "protocol.v1",
                "request-1",
            ),
            ClassifiedBackendCompletion {
                outcome: OperationOutcome::Indeterminate,
                backend_error_code: Some("backend_protocol_ambiguous".to_string()),
            }
        );

        for (error, code) in [
            (
                DirectToolError::BackendTimedOut("deadline".to_string()),
                "backend_timeout",
            ),
            (
                DirectToolError::BackendUnavailable("connect".to_string()),
                "backend_transport_error",
            ),
            (
                DirectToolError::BackendFailed("framing".to_string()),
                "backend_protocol_ambiguous",
            ),
        ] {
            assert_eq!(
                classify_backend_completion(
                    b"opaque-local-detail",
                    BackendCompletion::Failure(&error),
                    "protocol.v1",
                    "request-1",
                ),
                ClassifiedBackendCompletion {
                    outcome: OperationOutcome::Indeterminate,
                    backend_error_code: Some(code.to_string()),
                }
            );
        }
    }
}
