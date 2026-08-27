#![recursion_limit = "256"]

//! Trillionnium OS tool transport and execution boundary.
//!
//! This crate owns the OS-facing adapters used by `trillionniumd`. Product
//! effects flow through measured Direct adapters; the local shim and retired
//! Authority surface remain explicit non-product conformance fixtures.

#[cfg(any(test, feature = "legacy-authority-effects"))]
mod authority_receipt;
#[cfg(feature = "dev-conformance-fault-hook")]
pub mod dev_conformance_fault;
mod strict_json;
pub mod supervised_codex;

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use jsonschema::JSONSchema;
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
#[cfg(any(test, feature = "legacy-authority-effects"))]
use trillionnium_os_types::{AgentExecutionBinding, AgentPlanActionContract, ToolExecutor};
use trillionnium_os_types::{
    RiskTier, TOOL_SCHEMA_VERSION, ToolCallInput, ToolExecutorKind, ToolManifest, ValidationResult,
};

#[cfg(any(test, feature = "legacy-authority-effects"))]
pub use authority_receipt::UndoReceipt;

#[derive(Debug, Error)]
pub enum ToolRuntimeError {
    #[error("unsupported tool schema version: {0}")]
    UnsupportedSchemaVersion(String),
    #[error("invalid JSON schema: {0}")]
    InvalidSchema(String),
    #[error("tool call targets {call_tool} but manifest is for {manifest_tool}")]
    ToolNameMismatch {
        call_tool: String,
        manifest_tool: String,
    },
    #[error("unsupported built-in tool: {0}")]
    UnsupportedTool(String),
    #[error("invalid tool arguments for {tool}: {error}")]
    InvalidArguments { tool: String, error: String },
    #[error("tool output failed schema validation for {tool}: {errors:?}")]
    InvalidOutput { tool: String, errors: Vec<String> },
    #[error("Android Agent Gateway unavailable: {0}")]
    AndroidGatewayUnavailable(String),
    #[error("Android Agent Gateway outcome indeterminate: {0}")]
    AndroidGatewayOutcomeIndeterminate(String),
    #[error("Android Agent Gateway protocol error: {0}")]
    AndroidGatewayProtocol(String),
}

pub type Result<T> = std::result::Result<T, ToolRuntimeError>;

/// OS-side delegation boundary for explicit non-product conformance tools.
///
/// Production Agents use measured Direct adapters and do not obtain authority
/// from this trait or from the local compatibility shim.
pub trait ToolRuntimeAdapter {
    fn adapter_name(&self) -> &'static str;
    fn manifests(&self) -> Vec<ToolManifest>;
    fn execute_tool(&self, manifest: &ToolManifest, call: &ToolCallInput) -> Result<Value>;
}

/// Temporary local compatibility shim for Trillionnium OS smoke tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct LocalShimAdapter;

impl ToolRuntimeAdapter for LocalShimAdapter {
    fn adapter_name(&self) -> &'static str {
        "local-shim"
    }

    fn manifests(&self) -> Vec<ToolManifest> {
        local_shim_manifests()
    }

    fn execute_tool(&self, manifest: &ToolManifest, call: &ToolCallInput) -> Result<Value> {
        execute_local_shim_tool(manifest, call)
    }
}

pub const ANDROID_GATEWAY_PROTOCOL: &str = "trillionnium.android-agent-gateway.v1";
pub const DEFAULT_ANDROID_GATEWAY_SOCKET: &str = "@trillionnium-agent-gateway-v1";
const DEFAULT_ANDROID_AUTHORITY_SELINUX_DOMAIN: &str = "u:r:trillionnium_aiauthority:s0";

/// Fail-closed OS executor transport from the Rust control plane to Android.
///
/// The Android endpoint owns Binder identity checks, SELinux policy, single-use
/// capability consumption, side effects, receipts, and undo. This adapter never
/// falls back to adb, `cmd`, shell properties, or a model-controlled process.
#[derive(Debug, Clone)]
pub struct AndroidGatewayAdapter {
    socket_path: std::path::PathBuf,
    timeout: Duration,
    peer_policy: GatewayPeerPolicy,
}

#[derive(Debug, Clone)]
struct GatewayPeerPolicy {
    expected_uid: Option<u32>,
    expected_selinux_domain: Option<String>,
    /// Boot-frozen receipt key identity. The key metadata parser independently
    /// proves this is the lowercase SHA-256 digest of the returned SPKI before
    /// any mutating request may use it.
    #[cfg(any(test, feature = "legacy-authority-effects"))]
    expected_receipt_key_id: Option<String>,
    allow_uid_discovery: bool,
    #[cfg(test)]
    allow_host_test_uid: bool,
}

impl GatewayPeerPolicy {
    fn deny_all() -> Self {
        Self {
            expected_uid: None,
            expected_selinux_domain: None,
            #[cfg(any(test, feature = "legacy-authority-effects"))]
            expected_receipt_key_id: None,
            allow_uid_discovery: false,
            #[cfg(test)]
            allow_host_test_uid: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GatewayPeerIdentity {
    pid: u32,
    uid: u32,
    gid: u32,
    selinux_domain: String,
}

struct AuthenticatedGatewayResult {
    result: Value,
    peer: GatewayPeerIdentity,
    #[cfg(feature = "dev-conformance-fault-hook")]
    raw_response: String,
}

#[cfg(any(test, feature = "legacy-authority-effects"))]
struct PreparedGatewayCall {
    request_id: String,
    encoded: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(test, feature = "legacy-authority-effects"))]
pub enum DurableUndoRecovery {
    NotFound,
    NotRecoverable,
    Indeterminate,
    Receipt(Box<UndoReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorityBootPeerPin {
    uid: u32,
    selinux_domain: String,
    receipt_key_id: String,
}

type AuthorityBootPeerPinState = Mutex<Option<AuthorityBootPeerPin>>;

/// Kernel-observed peer identity plus key metadata.  The daemon must validate
/// and durably pin `metadata` before committing this boot-local UID.
#[derive(Debug, Clone)]
pub struct AuthorityKeyMetadataObservation {
    pub metadata: Value,
    pub peer_uid: u32,
    pub peer_selinux_domain: String,
}

static AUTHORITY_BOOT_PEER_PIN: OnceLock<AuthorityBootPeerPinState> = OnceLock::new();
fn production_authority_boot_peer_pin_state() -> &'static AuthorityBootPeerPinState {
    AUTHORITY_BOOT_PEER_PIN.get_or_init(|| Mutex::new(None))
}

fn read_authority_boot_peer_pin_from(
    state: &AuthorityBootPeerPinState,
) -> Result<Option<AuthorityBootPeerPin>> {
    state
        .lock()
        .map_err(|_| {
            ToolRuntimeError::AndroidGatewayProtocol(
                "Authority boot peer pin lock poisoned".to_string(),
            )
        })
        .map(|pin| pin.clone())
}

fn authority_boot_peer_pin() -> Result<Option<AuthorityBootPeerPin>> {
    read_authority_boot_peer_pin_from(production_authority_boot_peer_pin_state())
}

fn system_default_gateway_peer_policy_from(
    state: &AuthorityBootPeerPinState,
    configured_uid: Option<u32>,
    configured_selinux_domain: Option<String>,
) -> GatewayPeerPolicy {
    match read_authority_boot_peer_pin_from(state) {
        Ok(Some(pin)) => GatewayPeerPolicy {
            expected_uid: Some(pin.uid),
            expected_selinux_domain: Some(pin.selinux_domain),
            #[cfg(any(test, feature = "legacy-authority-effects"))]
            expected_receipt_key_id: Some(pin.receipt_key_id),
            allow_uid_discovery: false,
            #[cfg(test)]
            allow_host_test_uid: false,
        },
        Ok(None) => GatewayPeerPolicy {
            expected_uid: configured_uid,
            expected_selinux_domain: configured_selinux_domain
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .or_else(|| Some(DEFAULT_ANDROID_AUTHORITY_SELINUX_DOMAIN.to_string())),
            #[cfg(any(test, feature = "legacy-authority-effects"))]
            expected_receipt_key_id: None,
            allow_uid_discovery: false,
            #[cfg(test)]
            allow_host_test_uid: false,
        },
        // A poisoned boot pin cannot be reclassified as "not pinned" or
        // replaced by environment configuration.  An impossible policy keeps
        // every subsequent gateway authentication fail-closed.
        Err(_) => GatewayPeerPolicy::deny_all(),
    }
}

fn commit_authority_boot_peer_pin_to(
    state: &AuthorityBootPeerPinState,
    peer_uid: u32,
    peer_selinux_domain: &str,
    receipt_key_id: &str,
) -> Result<()> {
    if peer_uid < 10_000
        || !security_context_matches(
            DEFAULT_ANDROID_AUTHORITY_SELINUX_DOMAIN,
            peer_selinux_domain,
        )
        || receipt_key_id.len() != 64
        || !receipt_key_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ToolRuntimeError::AndroidGatewayProtocol(
            "invalid Authority boot peer/key pin".to_string(),
        ));
    }
    let candidate = AuthorityBootPeerPin {
        uid: peer_uid,
        selinux_domain: peer_selinux_domain.to_string(),
        receipt_key_id: receipt_key_id.to_string(),
    };
    let mut pin = state.lock().map_err(|_| {
        ToolRuntimeError::AndroidGatewayProtocol(
            "Authority boot peer pin lock poisoned".to_string(),
        )
    })?;
    match pin.as_ref() {
        Some(existing) if existing != &candidate => Err(ToolRuntimeError::AndroidGatewayProtocol(
            "Authority UID/domain/key changed during this daemon boot".to_string(),
        )),
        Some(_) => Ok(()),
        None => {
            *pin = Some(candidate);
            Ok(())
        }
    }
}

/// Commit the UID only after the caller has validated the independently
/// persisted hardware receipt key metadata returned by the same peer.
pub fn commit_android_authority_boot_peer_pin(
    peer_uid: u32,
    peer_selinux_domain: &str,
    receipt_key_id: &str,
) -> Result<()> {
    commit_authority_boot_peer_pin_to(
        production_authority_boot_peer_pin_state(),
        peer_uid,
        peer_selinux_domain,
        receipt_key_id,
    )
}

/// Return the boot-pinned UID only after a key-bound commit succeeded.
pub fn android_authority_boot_peer_uid() -> Result<Option<u32>> {
    authority_boot_peer_pin().map(|pin| pin.map(|pin| pin.uid))
}

/// Decrypted only after OS approval and consumed before the Android gateway
/// call. The raw URL is zeroized when this short-lived value leaves scope.
pub struct ResolvedExecutionPayload {
    pub execution_payload_ref: String,
    pub payload_sha256: String,
    pub payload_shape: String,
    pub url: zeroize::Zeroizing<String>,
}

impl AndroidGatewayAdapter {
    /// Construct an adapter pinned to a same-identity local gateway. This is
    /// useful for host conformance tests and never disables peer checks.
    pub fn new(socket_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            timeout: Duration::from_secs(15),
            peer_policy: GatewayPeerPolicy {
                expected_uid: Some(unsafe { libc::geteuid() }),
                expected_selinux_domain: current_security_context().ok(),
                #[cfg(any(test, feature = "legacy-authority-effects"))]
                expected_receipt_key_id: None,
                allow_uid_discovery: false,
                #[cfg(test)]
                allow_host_test_uid: true,
            },
        }
    }

    pub fn system_default() -> Self {
        let path = std::env::var_os("TRILLIONNIUM_ANDROID_GATEWAY_SOCKET")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| DEFAULT_ANDROID_GATEWAY_SOCKET.into());
        let configured_uid = std::env::var("TRILLIONNIUM_ANDROID_AUTHORITY_UID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok());
        let configured_selinux_domain =
            std::env::var("TRILLIONNIUM_ANDROID_AUTHORITY_SELINUX_DOMAIN").ok();
        let peer_policy = system_default_gateway_peer_policy_from(
            production_authority_boot_peer_pin_state(),
            configured_uid,
            configured_selinux_domain,
        );
        Self {
            socket_path: path,
            timeout: Duration::from_secs(15),
            peer_policy,
        }
    }

    /// Discover only the UID associated with the exact Authority SELinux
    /// domain while fetching key metadata.  This does not pin or authorize the
    /// UID; the daemon must validate the returned hardware key and call
    /// `commit_android_authority_boot_peer_pin` before any other method.
    pub fn discover_authority_key_metadata(
        request_id: &str,
    ) -> Result<AuthorityKeyMetadataObservation> {
        let existing = authority_boot_peer_pin()?;
        let adapter = Self {
            socket_path: std::env::var_os("TRILLIONNIUM_ANDROID_GATEWAY_SOCKET")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| DEFAULT_ANDROID_GATEWAY_SOCKET.into()),
            timeout: Duration::from_secs(15),
            peer_policy: GatewayPeerPolicy {
                expected_uid: existing.as_ref().map(|pin| pin.uid),
                expected_selinux_domain: existing
                    .as_ref()
                    .map(|pin| pin.selinux_domain.clone())
                    .or_else(|| Some(DEFAULT_ANDROID_AUTHORITY_SELINUX_DOMAIN.to_string())),
                #[cfg(any(test, feature = "legacy-authority-effects"))]
                expected_receipt_key_id: existing.as_ref().map(|pin| pin.receipt_key_id.clone()),
                allow_uid_discovery: existing.is_none(),
                #[cfg(test)]
                allow_host_test_uid: false,
            },
        };
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "key_metadata",
            "request_id": request_id,
        });
        let observed = adapter.call_authenticated(request_id, &frame)?;
        Ok(AuthorityKeyMetadataObservation {
            metadata: observed.result,
            peer_uid: observed.peer.uid,
            peer_selinux_domain: observed.peer.selinux_domain,
        })
    }

    fn call_authenticated<T: Serialize>(
        &self,
        request_id: &str,
        frame: &T,
    ) -> Result<AuthenticatedGatewayResult> {
        let encoded = serde_json::to_vec(frame)
            .map_err(|error| ToolRuntimeError::AndroidGatewayProtocol(error.to_string()))?;
        self.call_authenticated_bytes(request_id, &encoded)
    }

    fn call_authenticated_bytes(
        &self,
        request_id: &str,
        encoded: &[u8],
    ) -> Result<AuthenticatedGatewayResult> {
        let mut observed_peer = None;
        self.call_authenticated_bytes_observing_peer(request_id, encoded, &mut observed_peer)
    }

    fn call_authenticated_bytes_observing_peer(
        &self,
        request_id: &str,
        encoded: &[u8],
        observed_peer: &mut Option<GatewayPeerIdentity>,
    ) -> Result<AuthenticatedGatewayResult> {
        if !valid_gateway_identifier(request_id) {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid gateway request identity".to_string(),
            ));
        }
        if encoded.is_empty() || encoded.len() > 262_144 || encoded.contains(&b'\n') {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid pre-serialized gateway request boundary".to_string(),
            ));
        }
        let mut stream = connect_android_gateway(&self.socket_path).map_err(|error| {
            ToolRuntimeError::AndroidGatewayUnavailable(format!(
                "{}: {error}",
                self.socket_path.display()
            ))
        })?;
        let peer = authenticate_gateway_peer(&stream, &self.peer_policy)?;
        *observed_peer = Some(peer.clone());
        stream
            .set_read_timeout(Some(self.timeout))
            .map_err(|error| ToolRuntimeError::AndroidGatewayUnavailable(error.to_string()))?;
        stream
            .set_write_timeout(Some(self.timeout))
            .map_err(|error| ToolRuntimeError::AndroidGatewayUnavailable(error.to_string()))?;
        stream
            .write_all(encoded)
            .and_then(|_| stream.write_all(b"\n"))
            .map_err(|error| {
                ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(format!(
                    "gateway request write may have crossed the dispatch boundary: {error}"
                ))
            })?;
        stream.flush().map_err(|error| {
            ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(format!(
                "gateway request flush may have crossed the dispatch boundary: {error}"
            ))
        })?;
        let mut response = String::new();
        BufReader::new(stream)
            .read_line(&mut response)
            .map_err(|error| {
                ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(format!(
                    "gateway response was lost after request dispatch: {error}"
                ))
            })?;
        if response.is_empty() {
            return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                "gateway closed after request dispatch without a response".to_string(),
            ));
        }
        if response.len() > 512 * 1024 {
            return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                "gateway response exceeded the authenticated boundary after dispatch".to_string(),
            ));
        }
        let value = strict_json::parse(&response, "gateway response").map_err(|error| {
            ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(format!(
                "gateway returned an unverifiable response after dispatch: {error}"
            ))
        })?;
        let object = value.as_object().ok_or_else(|| {
            ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                "gateway response envelope is not an object after dispatch".to_string(),
            )
        })?;
        if value.get("protocol").and_then(Value::as_str) != Some(ANDROID_GATEWAY_PROTOCOL)
            || value.get("request_id").and_then(Value::as_str) != Some(request_id)
        {
            return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                "response identity or protocol mismatch after dispatch".to_string(),
            ));
        }
        if value.get("ok").and_then(Value::as_bool) != Some(true) {
            if object.len() != 4 || !object.contains_key("error") {
                return Err(ToolRuntimeError::AndroidGatewayProtocol(
                    "gateway denial envelope has missing or unknown fields".to_string(),
                ));
            }
            let error = value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("gateway_denied_without_error");
            if error == "execution_outcome_indeterminate" {
                return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                    "Authority durably recorded an indeterminate execution outcome".to_string(),
                ));
            }
            return Err(ToolRuntimeError::AndroidGatewayProtocol(format!(
                "gateway denied request: {error}"
            )));
        }
        if object.len() != 4 || !object.contains_key("result") {
            return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                "gateway success envelope has missing or unknown fields after dispatch".to_string(),
            ));
        }
        let result = value.get("result").cloned().ok_or_else(|| {
            ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                "missing result envelope after dispatch".to_string(),
            )
        })?;
        Ok(AuthenticatedGatewayResult {
            result,
            peer,
            #[cfg(feature = "dev-conformance-fault-hook")]
            raw_response: response,
        })
    }

    /// Retry one byte-identical request only for actions whose replay is owned
    /// by Authority's durable execution journal. A second failure after either
    /// attempt may have crossed the side-effect boundary and is therefore never
    /// downgraded to an ordinary tool failure.
    fn call_durable_authenticated_bytes(
        &self,
        request_id: &str,
        encoded: &[u8],
    ) -> Result<AuthenticatedGatewayResult> {
        let mut first_peer = None;
        let first = match self.call_authenticated_bytes_observing_peer(
            request_id,
            encoded,
            &mut first_peer,
        ) {
            Ok(result) => return Ok(result),
            Err(error @ ToolRuntimeError::AndroidGatewayUnavailable(_))
            | Err(error @ ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(_)) => error,
            Err(error) => return Err(error),
        };
        let mut retry_peer = None;
        match self.call_authenticated_bytes_observing_peer(request_id, encoded, &mut retry_peer) {
            Ok(result) => {
                if first_peer
                    .as_ref()
                    .is_some_and(|first| retry_peer.as_ref() != Some(first))
                {
                    return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                        "byte-identical durable retry reached a different authenticated Authority peer"
                            .to_string(),
                    ));
                }
                Ok(result)
            }
            Err(second) => match (&first, &second) {
                (
                    ToolRuntimeError::AndroidGatewayUnavailable(_),
                    ToolRuntimeError::AndroidGatewayUnavailable(_),
                ) => Err(second),
                _ => Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                    format!(
                        "byte-identical durable request retry did not recover; first={first}; second={second}"
                    ),
                )),
            },
        }
    }

    #[cfg(feature = "dev-conformance-fault-hook")]
    fn call_authenticated_expect_denied_bytes(
        &self,
        request_id: &str,
        encoded: &[u8],
    ) -> Result<(GatewayPeerIdentity, String)> {
        if !valid_gateway_identifier(request_id)
            || encoded.is_empty()
            || encoded.len() > 262_144
            || encoded.contains(&b'\n')
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid mutation-probe request boundary".to_string(),
            ));
        }
        let mut stream = connect_android_gateway(&self.socket_path).map_err(|error| {
            ToolRuntimeError::AndroidGatewayUnavailable(format!(
                "{}: {error}",
                self.socket_path.display()
            ))
        })?;
        let peer = authenticate_gateway_peer(&stream, &self.peer_policy)?;
        stream
            .set_read_timeout(Some(self.timeout))
            .and_then(|_| stream.set_write_timeout(Some(self.timeout)))
            .map_err(|error| ToolRuntimeError::AndroidGatewayUnavailable(error.to_string()))?;
        stream
            .write_all(encoded)
            .and_then(|_| stream.write_all(b"\n"))
            .and_then(|_| stream.flush())
            .map_err(|error| ToolRuntimeError::AndroidGatewayUnavailable(error.to_string()))?;
        let mut response = String::new();
        BufReader::new(stream)
            .read_line(&mut response)
            .map_err(|error| ToolRuntimeError::AndroidGatewayUnavailable(error.to_string()))?;
        if response.is_empty() || response.len() > 512 * 1024 {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "mutation-probe response boundary denied".to_string(),
            ));
        }
        let value = strict_json::parse(&response, "mutation-probe response")?;
        let object = value.as_object().ok_or_else(|| {
            ToolRuntimeError::AndroidGatewayProtocol(
                "mutation-probe response is not an object".to_string(),
            )
        })?;
        if object.len() != 4
            || value.get("protocol").and_then(Value::as_str) != Some(ANDROID_GATEWAY_PROTOCOL)
            || value.get("request_id").and_then(Value::as_str) != Some(request_id)
            || value.get("ok").and_then(Value::as_bool) != Some(false)
            || value.get("error").and_then(Value::as_str) != Some("gateway_request_denied")
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "mutation probe was not explicitly denied by Authority".to_string(),
            ));
        }
        Ok((peer, response))
    }

    fn call<T: Serialize>(&self, request_id: &str, frame: &T) -> Result<Value> {
        self.call_authenticated(request_id, frame)
            .map(|response| response.result)
    }

    #[cfg(any(test, feature = "legacy-authority-effects"))]
    fn prepare_execution_call(
        &self,
        call: &ToolCallInput,
        resolved: Option<&ResolvedExecutionPayload>,
        expected_receipt_key_id: &str,
    ) -> Result<PreparedGatewayCall> {
        let request_id = call
            .arguments
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or_else(|| {
                ToolRuntimeError::AndroidGatewayProtocol(
                    "planned arguments omitted a bounded request_id".to_string(),
                )
            })?;
        let binding = call.agent_execution_binding.as_ref().ok_or_else(|| {
            ToolRuntimeError::AndroidGatewayProtocol(
                "OS execution binding is required for Android gateway dispatch".to_string(),
            )
        })?;
        let arguments_sha256 = trillionnium_os_types::sha256_json(&call.arguments);
        if binding.task_id != call.task_id
            || binding.tool_call_id != call.tool_call_id
            || binding.tool_name != call.tool_name
            || binding.arguments_sha256 != arguments_sha256
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "OS execution binding does not match the frozen tool call".to_string(),
            ));
        }
        let safe_payload = call.arguments.get("payload").and_then(Value::as_object);
        let expected_ref = safe_payload
            .and_then(|value| value.get("execution_payload_ref"))
            .and_then(Value::as_str);
        let expected_sha = safe_payload
            .and_then(|value| value.get("execution_payload_sha256"))
            .and_then(Value::as_str);
        let expected_shape = safe_payload
            .and_then(|value| value.get("execution_payload_shape"))
            .and_then(Value::as_str);
        match (expected_ref, expected_sha, expected_shape, resolved) {
            (Some(reference), Some(sha), Some(shape), Some(resolved))
                if reference == resolved.execution_payload_ref
                    && sha == resolved.payload_sha256
                    && shape == resolved.payload_shape
                    && resolved.payload_sha256
                        == trillionnium_os_types::sha256_json(&json!({
                            "url": resolved.url.as_str(),
                        })) => {}
            (None, None, None, None) if call.tool_name != "android.browser.open_bounded" => {}
            _ => {
                return Err(ToolRuntimeError::AndroidGatewayProtocol(
                    "protected execution payload binding mismatch".to_string(),
                ));
            }
        }

        #[derive(Serialize)]
        struct RawPayload<'a> {
            url: &'a str,
        }
        #[derive(Serialize)]
        struct ExecuteFrame<'a> {
            protocol: &'static str,
            method: &'static str,
            request_id: &'a str,
            expected_receipt_key_id: &'a str,
            tool_name: &'a str,
            arguments: &'a Value,
            execution_binding: &'a AgentExecutionBinding,
            execution_payload_ref: Option<&'a str>,
            execution_payload_sha256: Option<&'a str>,
            execution_payload_shape: Option<&'a str>,
            resolved_execution_payload: Option<RawPayload<'a>>,
        }
        let frame = ExecuteFrame {
            protocol: ANDROID_GATEWAY_PROTOCOL,
            method: "execute",
            request_id,
            expected_receipt_key_id,
            tool_name: &call.tool_name,
            arguments: &call.arguments,
            execution_binding: binding,
            execution_payload_ref: resolved.map(|value| value.execution_payload_ref.as_str()),
            execution_payload_sha256: resolved.map(|value| value.payload_sha256.as_str()),
            execution_payload_shape: resolved.map(|value| value.payload_shape.as_str()),
            resolved_execution_payload: resolved.map(|value| RawPayload {
                url: value.url.as_str(),
            }),
        };
        let encoded = serde_json::to_vec(&frame)
            .map_err(|error| ToolRuntimeError::AndroidGatewayProtocol(error.to_string()))?;
        Ok(PreparedGatewayCall {
            request_id: request_id.to_string(),
            encoded,
        })
    }

    #[cfg(any(test, feature = "legacy-authority-effects"))]
    fn execute_tool_with_execution_payload(
        &self,
        manifest: &ToolManifest,
        call: &ToolCallInput,
        resolved: Option<&ResolvedExecutionPayload>,
    ) -> Result<Value> {
        let validation = validate_tool_call(manifest, call)?;
        if !validation.valid {
            return Err(ToolRuntimeError::InvalidArguments {
                tool: manifest.name.clone(),
                error: validation.errors.join("; "),
            });
        }
        let supported_shape = matches!(
            (manifest.name.as_str(), resolved.is_some()),
            ("android.browser.open_bounded", true) | ("android.notification.post_bounded", false)
        );
        if !supported_shape {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "only a production Android action with its exact payload shape may enter Authority"
                    .to_string(),
            ));
        }
        if manifest.name == "android.notification.post_bounded" {
            validate_notification_call_payload(call)?;
        }
        authority_receipt::validate_call_manifest_binding(manifest, call)?;
        let request_id = call
            .arguments
            .get("request_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ToolRuntimeError::AndroidGatewayProtocol(
                    "planned arguments omitted request_id".to_string(),
                )
            })?;
        let metadata_request_id = format!(
            "keymeta-{}",
            trillionnium_os_types::sha256_bytes(
                format!("{request_id}\n{}", call.tool_call_id.0).as_bytes()
            )
        );
        let metadata_frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "key_metadata",
            "request_id": metadata_request_id,
        });
        let metadata = self.call_authenticated(&metadata_request_id, &metadata_frame)?;
        let authority_key = authority_receipt::validate_key_metadata(&metadata.result)?;
        let expected_receipt_key_id = self
            .peer_policy
            .expected_receipt_key_id
            .as_deref()
            .ok_or_else(|| {
                ToolRuntimeError::AndroidGatewayProtocol(
                    "Authority boot-frozen receipt key is not pinned".to_string(),
                )
            })?;
        if authority_key.key_id() != expected_receipt_key_id {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "Authority receipt key differs from the boot-frozen SPKI digest".to_string(),
            ));
        }

        let prepared = self.prepare_execution_call(call, resolved, expected_receipt_key_id)?;
        let execution =
            self.call_durable_authenticated_bytes(&prepared.request_id, &prepared.encoded)?;
        if metadata.peer != execution.peer {
            return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                "Authority identity changed after execution dispatch".to_string(),
            ));
        }
        let validation = validate_tool_output(manifest, &execution.result).map_err(|error| {
            ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(format!(
                "Authority response could not be schema-validated after execution dispatch: {error}"
            ))
        })?;
        if !validation.valid {
            return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                format!(
                    "Authority response failed schema validation after execution dispatch: {}",
                    validation.errors.join("; ")
                ),
            ));
        }
        authority_receipt::verify_execution_result(
            &execution.result,
            manifest,
            call,
            resolved,
            &authority_key,
            &execution.peer,
        )
        .map_err(|error| {
            ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(format!(
                "Authority receipt verification failed after execution dispatch: {error}"
            ))
        })?;
        Ok(execution.result)
    }

    /// Ask the OS-owned Android Authority to undo a previously receipted
    /// action. The Agent cannot call this directly; the Android-facing Agent
    /// API verifies the approving UI peer and task ownership first.
    #[cfg(any(test, feature = "legacy-authority-effects"))]
    pub fn undo_receipt(
        &self,
        request_id: &str,
        receipt_id: &str,
        original_execution_result: &Value,
        binding: &AgentExecutionBinding,
        payload_sha256: &str,
        frozen_authority_key_pin: &Value,
    ) -> Result<UndoReceipt> {
        if !valid_gateway_identifier(request_id)
            || !is_lower_sha256(receipt_id)
            || !is_lower_sha256(payload_sha256)
            || binding.agent_id.is_empty()
            || binding.session_id.is_empty()
            || binding.plan_id.is_empty()
            || binding.action_id.is_empty()
            || !is_lower_sha256(&binding.arguments_sha256)
            || !is_lower_sha256(&binding.tool_manifest_sha256)
            || !is_lower_sha256(&binding.accepted_plan_sha256)
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid undo request identity".to_string(),
            ));
        }
        let source = authority_receipt::prevalidate_undo_source(
            original_execution_result,
            receipt_id,
            binding,
            payload_sha256,
        )?;
        let metadata_request_id = format!(
            "undo-keymeta-{}",
            trillionnium_os_types::sha256_bytes(
                format!("{request_id}\n{}", source.receipt_id()).as_bytes()
            )
        );
        let metadata_frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "key_metadata",
            "request_id": metadata_request_id,
        });
        let metadata = self.call_authenticated(&metadata_request_id, &metadata_frame)?;
        let authority_key = authority_receipt::validate_key_metadata(&metadata.result)?;
        authority_receipt::validate_key_against_frozen_pin(
            &authority_key,
            frozen_authority_key_pin,
        )?;
        authority_receipt::verify_prepared_undo_source(
            &source,
            binding,
            payload_sha256,
            &authority_key,
            &metadata.peer,
        )?;

        // The durable Authority execution journal is the final replay and
        // crash-recovery authority. The OS UI journal remains a front-line
        // ownership/replay gate, but this process must not invent a volatile
        // HashSet whose state disappears at daemon restart.
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "undo",
            "request_id": request_id,
            "receipt_id": receipt_id,
            "execution_payload_sha256": payload_sha256,
            "execution_binding": binding,
        });
        let encoded = serde_json::to_vec(&frame)
            .map_err(|error| ToolRuntimeError::AndroidGatewayProtocol(error.to_string()))?;
        let undo = self.call_durable_authenticated_bytes(request_id, &encoded)?;
        if metadata.peer != undo.peer {
            return Err(ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(
                "Authority identity changed after undo dispatch".to_string(),
            ));
        }
        let verified = authority_receipt::verify_undo_result(
            &undo.result,
            request_id,
            &source,
            binding,
            payload_sha256,
            &authority_key,
            &undo.peer,
        )
        .map_err(|error| {
            ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(format!(
                "Authority undo receipt verification failed after dispatch: {error}"
            ))
        })?;

        #[cfg(feature = "dev-conformance-fault-hook")]
        {
            let path = dev_conformance_fault::configured_spec_path();
            if let Some(mut claim) = dev_conformance_fault::claim_matching_fault(
                &path,
                &frame,
                &encoded,
                &undo.result,
                undo.raw_response.as_bytes(),
                &undo.peer,
                trillionnium_os_types::now_unix_ms(),
            )? {
                claim.set_failure_stage("undo_agent_id_mutation_frame_prepare_failed");
                let (_mutation_frame, mutation_bytes) =
                    dev_conformance_fault::agent_id_mutation_frame(&claim, &frame)?;
                claim.set_failure_stage("undo_agent_id_mutation_denial_failed");
                let (mutation_peer, mutation_denial) =
                    self.call_authenticated_expect_denied_bytes(request_id, &mutation_bytes)?;
                if mutation_peer != undo.peer {
                    claim.set_failure_stage("undo_agent_id_mutation_peer_mismatch");
                    return Err(ToolRuntimeError::AndroidGatewayProtocol(
                        "Authority identity changed during undo mutation denial probe".to_string(),
                    ));
                }

                claim.set_failure_stage("original_undo_retry_transport_failed");
                let retry = self.call_authenticated_bytes(request_id, &encoded)?;
                claim.set_failure_stage("original_undo_retry_peer_mismatch");
                if retry.peer != undo.peer {
                    return Err(ToolRuntimeError::AndroidGatewayProtocol(
                        "Authority identity changed during exact undo retry".to_string(),
                    ));
                }
                claim.set_failure_stage("original_undo_retry_receipt_verification_failed");
                let retry_verified = authority_receipt::verify_undo_result(
                    &retry.result,
                    request_id,
                    &source,
                    binding,
                    payload_sha256,
                    &authority_key,
                    &retry.peer,
                )?;
                claim.set_failure_stage("original_undo_retry_response_mismatch");
                if retry.raw_response.as_bytes() != undo.raw_response.as_bytes() {
                    return Err(ToolRuntimeError::AndroidGatewayProtocol(
                        "Authority undo retry response was not byte-identical".to_string(),
                    ));
                }
                let retry_response_sha =
                    trillionnium_os_types::sha256_bytes(retry.raw_response.as_bytes());
                let retry_request_sha = claim.spec.request_frame_sha256.clone();
                let mutation_request_sha = trillionnium_os_types::sha256_bytes(&mutation_bytes);
                let mutation_denial_sha =
                    trillionnium_os_types::sha256_bytes(mutation_denial.as_bytes());
                claim.set_failure_stage("completed_undo_audit_write_failed");
                dev_conformance_fault::write_completed_audit(
                    &mut claim,
                    &dev_conformance_fault::CompletedFaultAudit {
                        mutation_request_sha256: &mutation_request_sha,
                        mutation_denial_response_sha256: &mutation_denial_sha,
                        retry_request_sha256: &retry_request_sha,
                        retry_response_sha256: &retry_response_sha,
                        authority_peer_pid: retry.peer.pid,
                        authority_peer_uid: retry.peer.uid,
                        authority_peer_gid: retry.peer.gid,
                        authority_peer_selinux_domain: &retry.peer.selinux_domain,
                        completed_at_ms: trillionnium_os_types::now_unix_ms(),
                    },
                )?;
                return Ok(retry_verified);
            }
        }

        Ok(verified)
    }

    /// Query an already durable Authority undo outcome without dispatching an
    /// undo. This is used only to complete an OS-UI replay record left
    /// `in_progress` by process death after Authority had committed.
    #[cfg(any(test, feature = "legacy-authority-effects"))]
    pub fn recover_undo_receipt(
        &self,
        original_request_id: &str,
        receipt_id: &str,
        original_execution_result: &Value,
        binding: &AgentExecutionBinding,
        payload_sha256: &str,
        frozen_authority_key_pin: &Value,
    ) -> Result<DurableUndoRecovery> {
        if !valid_gateway_identifier(original_request_id)
            || !is_lower_sha256(receipt_id)
            || !is_lower_sha256(payload_sha256)
            || binding.agent_id.is_empty()
            || binding.session_id.is_empty()
            || binding.plan_id.is_empty()
            || binding.action_id.is_empty()
            || !is_lower_sha256(&binding.arguments_sha256)
            || !is_lower_sha256(&binding.tool_manifest_sha256)
            || !is_lower_sha256(&binding.accepted_plan_sha256)
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid durable undo recovery identity".to_string(),
            ));
        }
        let source = authority_receipt::prevalidate_undo_source(
            original_execution_result,
            receipt_id,
            binding,
            payload_sha256,
        )?;
        let metadata_request_id = format!(
            "recover-keymeta-{}",
            trillionnium_os_types::sha256_bytes(
                format!("{original_request_id}\n{}", source.receipt_id()).as_bytes()
            )
        );
        let metadata_frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "key_metadata",
            "request_id": metadata_request_id,
        });
        let metadata = self.call_authenticated(&metadata_request_id, &metadata_frame)?;
        let authority_key = authority_receipt::validate_key_metadata(&metadata.result)?;
        authority_receipt::validate_key_against_frozen_pin(
            &authority_key,
            frozen_authority_key_pin,
        )?;
        authority_receipt::verify_prepared_undo_source(
            &source,
            binding,
            payload_sha256,
            &authority_key,
            &metadata.peer,
        )?;

        let recovery_request_id = format!(
            "recover-{}",
            trillionnium_os_types::sha256_bytes(
                format!(
                    "undo\n{original_request_id}\n{receipt_id}\n{}",
                    binding.tool_call_id.0
                )
                .as_bytes()
            )
        );
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "recover_execution",
            "request_id": recovery_request_id,
            "operation": "undo",
            "original_request_id": original_request_id,
            "receipt_id": receipt_id,
            "execution_payload_sha256": payload_sha256,
            "execution_binding": binding,
        });
        let encoded = serde_json::to_vec(&frame)
            .map_err(|error| ToolRuntimeError::AndroidGatewayProtocol(error.to_string()))?;
        let recovery = self.call_durable_authenticated_bytes(&recovery_request_id, &encoded)?;
        if metadata.peer != recovery.peer {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "Authority identity changed during query-only undo recovery".to_string(),
            ));
        }
        let object = recovery.result.as_object().ok_or_else(|| {
            ToolRuntimeError::AndroidGatewayProtocol(
                "durable undo recovery result is not an object".to_string(),
            )
        })?;
        const RECOVERY_FIELDS: &[&str] = &[
            "operation",
            "original_request_id",
            "recovery_status",
            "execution_state",
            "receipt_publication_state",
            "undo_state",
            "receipt_id",
            "receipt_json",
        ];
        if object.len() != RECOVERY_FIELDS.len()
            || RECOVERY_FIELDS
                .iter()
                .any(|field| !object.contains_key(*field))
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "durable undo recovery result has missing or unknown fields".to_string(),
            ));
        }
        let field = |name: &str| -> Result<&str> {
            object.get(name).and_then(Value::as_str).ok_or_else(|| {
                ToolRuntimeError::AndroidGatewayProtocol(format!(
                    "durable undo recovery field is not a string: {name}"
                ))
            })
        };
        if field("operation")? != "undo" || field("original_request_id")? != original_request_id {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "durable undo recovery identity mismatch".to_string(),
            ));
        }
        let execution_state = field("execution_state")?;
        let publication_state = field("receipt_publication_state")?;
        let undo_state = field("undo_state")?;
        if !matches!(
            execution_state,
            "missing" | "reserved" | "dispatching" | "indeterminate" | "committed" | "aborted"
        ) || !matches!(
            publication_state,
            "none" | "staged" | "published" | "aborted"
        ) || !matches!(undo_state, "none" | "available" | "reserved" | "undone")
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "durable undo recovery journal state is outside the closed contract".to_string(),
            ));
        }
        let recovered_receipt_id = field("receipt_id")?;
        let recovered_receipt_json = field("receipt_json")?;
        match field("recovery_status")? {
            "not_found" => {
                if execution_state != "missing"
                    || publication_state != "none"
                    || undo_state != "none"
                    || !recovered_receipt_id.is_empty()
                    || !recovered_receipt_json.is_empty()
                {
                    return Err(ToolRuntimeError::AndroidGatewayProtocol(
                        "durable undo not-found result is internally inconsistent".to_string(),
                    ));
                }
                Ok(DurableUndoRecovery::NotFound)
            }
            "not_recoverable" => {
                if !recovered_receipt_id.is_empty() || !recovered_receipt_json.is_empty() {
                    return Err(ToolRuntimeError::AndroidGatewayProtocol(
                        "non-recoverable undo result exposed receipt material".to_string(),
                    ));
                }
                Ok(DurableUndoRecovery::NotRecoverable)
            }
            "indeterminate" => {
                if undo_state != "reserved"
                    || !recovered_receipt_id.is_empty()
                    || !recovered_receipt_json.is_empty()
                {
                    return Err(ToolRuntimeError::AndroidGatewayProtocol(
                        "indeterminate undo recovery result is internally inconsistent".to_string(),
                    ));
                }
                Ok(DurableUndoRecovery::Indeterminate)
            }
            "receipt_available" => {
                if execution_state != "committed"
                    || undo_state != "undone"
                    || !is_lower_sha256(recovered_receipt_id)
                    || recovered_receipt_json.is_empty()
                    || recovered_receipt_json.len() > 256 * 1024
                {
                    return Err(ToolRuntimeError::AndroidGatewayProtocol(
                        "available undo recovery receipt has invalid journal state or shape"
                            .to_string(),
                    ));
                }
                let output = json!({
                    "action_ok": true,
                    "receipt_id": recovered_receipt_id,
                    "receipt_json": recovered_receipt_json,
                    "result_text": "",
                    "undo_supported": true,
                });
                let receipt = authority_receipt::verify_undo_result(
                    &output,
                    original_request_id,
                    &source,
                    binding,
                    payload_sha256,
                    &authority_key,
                    &recovery.peer,
                )?;
                Ok(DurableUndoRecovery::Receipt(Box::new(receipt)))
            }
            _ => Err(ToolRuntimeError::AndroidGatewayProtocol(
                "unknown durable undo recovery status".to_string(),
            )),
        }
    }

    /// Fetch the receipt signer identity directly over the authenticated OS
    /// gateway. Callers must pin this metadata independently of a receipt.
    pub fn authority_key_metadata(&self, request_id: &str) -> Result<Value> {
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "key_metadata",
            "request_id": request_id,
        });
        self.call(request_id, &frame)
    }

    /// Consume one Authority-staged context capture over the same root-only,
    /// SO_PEERCRED/SO_PEERSEC-authenticated channel used by Android executors.
    /// The untrusted UI carries only the signed receipt and never receives the
    /// raw content returned by this method.
    pub fn resolve_context_capture(
        &self,
        request_id: &str,
        capture_id: &str,
        capture_receipt_id: &str,
        capture_request_id: &str,
        requesting_uid: u32,
        subject_user_id: u32,
    ) -> Result<Value> {
        if !capture_id.strip_prefix("capture-").is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }) || capture_receipt_id.len() != 64
            || !capture_receipt_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || !valid_gateway_identifier(capture_request_id)
            || requesting_uid < 10_000
            || subject_user_id != requesting_uid / 100_000
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid context capture resolution binding".to_string(),
            ));
        }
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "resolve_context",
            "request_id": request_id,
            "capture_id": capture_id,
            "capture_receipt_id": capture_receipt_id,
            "capture_request_id": capture_request_id,
            "requesting_uid": requesting_uid,
            "subject_user_id": subject_user_id,
        });
        self.call(request_id, &frame)
    }

    /// Query the Authority's durable Context-capture journal without consuming
    /// or resolving a capture. The exact original resolve request, signed
    /// receipt identity, source, content digest and authenticated gateway peer
    /// are all re-bound by Authority before it returns any stored resolution.
    #[allow(clippy::too_many_arguments)]
    pub fn recover_context_capture(
        &self,
        request_id: &str,
        original_request_id: &str,
        capture_id: &str,
        capture_receipt_id: &str,
        capture_request_id: &str,
        requesting_uid: u32,
        subject_user_id: u32,
        source_id: &str,
        content_sha256: &str,
    ) -> Result<Value> {
        validate_context_capture_recovery_binding(
            original_request_id,
            capture_id,
            capture_receipt_id,
            capture_request_id,
            requesting_uid,
            subject_user_id,
            source_id,
            content_sha256,
        )?;
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "recover_context_capture",
            "request_id": request_id,
            "original_request_id": original_request_id,
            "capture_id": capture_id,
            "capture_receipt_id": capture_receipt_id,
            "capture_request_id": capture_request_id,
            "requesting_uid": requesting_uid,
            "subject_user_id": subject_user_id,
            "source_id": source_id,
            "content_sha256": content_sha256,
        });
        self.call_context_capture_journal_frame(request_id, &frame)
    }

    /// Acknowledge that the daemon durably published the exact encrypted
    /// Context identified by an Authority-owned resolution. This operation is
    /// journal-owned and exactly retryable; it never resolves the capture.
    #[allow(clippy::too_many_arguments)]
    pub fn acknowledge_context_capture_imported(
        &self,
        request_id: &str,
        original_request_id: &str,
        capture_id: &str,
        capture_receipt_id: &str,
        capture_request_id: &str,
        requesting_uid: u32,
        subject_user_id: u32,
        source_id: &str,
        content_sha256: &str,
        resolution_sha256: &str,
        context_id: &str,
    ) -> Result<Value> {
        validate_context_capture_recovery_binding(
            original_request_id,
            capture_id,
            capture_receipt_id,
            capture_request_id,
            requesting_uid,
            subject_user_id,
            source_id,
            content_sha256,
        )?;
        if !is_lower_sha256(resolution_sha256)
            || !context_id
                .strip_prefix("context-")
                .is_some_and(is_lower_sha256)
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid context capture imported acknowledgement binding".to_string(),
            ));
        }
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "ack_context_capture_imported",
            "request_id": request_id,
            "original_request_id": original_request_id,
            "capture_id": capture_id,
            "capture_receipt_id": capture_receipt_id,
            "capture_request_id": capture_request_id,
            "requesting_uid": requesting_uid,
            "subject_user_id": subject_user_id,
            "source_id": source_id,
            "content_sha256": content_sha256,
            "resolution_sha256": resolution_sha256,
            "context_id": context_id,
        });
        self.call_context_capture_journal_frame(request_id, &frame)
    }

    /// Freeze a consumed capture as indeterminate when the daemon cannot prove
    /// whether its encrypted Context publication reached durable storage. This
    /// fail-closed transition is exactly retryable and never resolves again.
    #[allow(clippy::too_many_arguments)]
    pub fn mark_context_capture_indeterminate(
        &self,
        request_id: &str,
        original_request_id: &str,
        capture_id: &str,
        capture_receipt_id: &str,
        capture_request_id: &str,
        requesting_uid: u32,
        subject_user_id: u32,
        source_id: &str,
        content_sha256: &str,
        resolution_sha256: &str,
    ) -> Result<Value> {
        validate_context_capture_recovery_binding(
            original_request_id,
            capture_id,
            capture_receipt_id,
            capture_request_id,
            requesting_uid,
            subject_user_id,
            source_id,
            content_sha256,
        )?;
        if !is_lower_sha256(resolution_sha256) {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid indeterminate context capture resolution digest".to_string(),
            ));
        }
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "mark_context_capture_indeterminate",
            "request_id": request_id,
            "original_request_id": original_request_id,
            "capture_id": capture_id,
            "capture_receipt_id": capture_receipt_id,
            "capture_request_id": capture_request_id,
            "requesting_uid": requesting_uid,
            "subject_user_id": subject_user_id,
            "source_id": source_id,
            "content_sha256": content_sha256,
            "resolution_sha256": resolution_sha256,
            "reason_code": "daemon_context_import_publication_uncertain",
        });
        self.call_context_capture_journal_frame(request_id, &frame)
    }

    fn call_context_capture_journal_frame(&self, request_id: &str, frame: &Value) -> Result<Value> {
        if !valid_gateway_identifier(request_id) {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(
                "invalid context capture journal request id".to_string(),
            ));
        }
        let encoded = serde_json::to_vec(frame)
            .map_err(|error| ToolRuntimeError::AndroidGatewayProtocol(error.to_string()))?;
        Ok(self
            .call_durable_authenticated_bytes(request_id, &encoded)?
            .result)
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_context_capture_recovery_binding(
    original_request_id: &str,
    capture_id: &str,
    capture_receipt_id: &str,
    capture_request_id: &str,
    requesting_uid: u32,
    subject_user_id: u32,
    source_id: &str,
    content_sha256: &str,
) -> Result<()> {
    if !valid_gateway_identifier(original_request_id)
        || !capture_id
            .strip_prefix("capture-")
            .is_some_and(is_lower_sha256)
        || !is_lower_sha256(capture_receipt_id)
        || !valid_gateway_identifier(capture_request_id)
        || requesting_uid < 10_000
        || subject_user_id != requesting_uid / 100_000
        || source_id.is_empty()
        || source_id.len() > 512
        || source_id.as_bytes().contains(&0)
        || !is_lower_sha256(content_sha256)
    {
        return Err(ToolRuntimeError::AndroidGatewayProtocol(
            "invalid durable context capture recovery identity".to_string(),
        ));
    }
    Ok(())
}

fn connect_android_gateway(path: &std::path::Path) -> std::io::Result<UnixStream> {
    let rendered = path.to_string_lossy();
    if let Some(name) = rendered.strip_prefix('@') {
        let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        UnixStream::connect_addr(&address)
    } else {
        UnixStream::connect(path)
    }
}

impl Default for AndroidGatewayAdapter {
    fn default() -> Self {
        Self::system_default()
    }
}

impl ToolRuntimeAdapter for AndroidGatewayAdapter {
    fn adapter_name(&self) -> &'static str {
        "android-agent-gateway-v1"
    }

    fn manifests(&self) -> Vec<ToolManifest> {
        executable_android_gateway_manifests()
    }

    fn execute_tool(&self, manifest: &ToolManifest, call: &ToolCallInput) -> Result<Value> {
        #[cfg(any(test, feature = "legacy-authority-effects"))]
        {
            self.execute_tool_with_execution_payload(manifest, call, None)
        }
        #[cfg(not(any(test, feature = "legacy-authority-effects")))]
        {
            let _ = (self, call);
            Err(ToolRuntimeError::UnsupportedTool(manifest.name.clone()))
        }
    }
}

fn valid_gateway_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b':' | b'-'))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(any(test, feature = "legacy-authority-effects"))]
fn validate_notification_call_payload(call: &ToolCallInput) -> Result<()> {
    if call.arguments.get("network_scope").and_then(Value::as_str) != Some("none") {
        return Err(ToolRuntimeError::AndroidGatewayProtocol(
            "bounded notification action must have network_scope=none".to_string(),
        ));
    }
    let payload = call
        .arguments
        .get("payload")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ToolRuntimeError::AndroidGatewayProtocol(
                "bounded notification payload is not an object".to_string(),
            )
        })?;
    if payload.len() != 2 || !payload.contains_key("title") || !payload.contains_key("body") {
        return Err(ToolRuntimeError::AndroidGatewayProtocol(
            "bounded notification payload has missing or unknown fields".to_string(),
        ));
    }
    for (field, minimum, maximum) in [("title", 1_usize, 120_usize), ("body", 1, 1_000)] {
        let value = payload.get(field).and_then(Value::as_str).ok_or_else(|| {
            ToolRuntimeError::AndroidGatewayProtocol(format!(
                "bounded notification {field} is not a string"
            ))
        })?;
        if value.trim().is_empty()
            || !(minimum..=maximum).contains(&value.len())
            || value.chars().any(char::is_control)
        {
            return Err(ToolRuntimeError::AndroidGatewayProtocol(format!(
                "bounded notification {field} violates the UTF-8 byte/control boundary"
            )));
        }
    }
    Ok(())
}

fn current_security_context() -> std::io::Result<String> {
    let value = std::fs::read_to_string("/proc/self/attr/current")?;
    let value = value.trim_matches(|character| character == '\0' || character == '\n');
    if value.is_empty() || value.len() > 256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid current security context",
        ));
    }
    Ok(value.to_string())
}

fn authenticate_gateway_peer(
    stream: &UnixStream,
    policy: &GatewayPeerPolicy,
) -> Result<GatewayPeerIdentity> {
    let expected_domain = policy.expected_selinux_domain.as_deref().ok_or_else(|| {
        ToolRuntimeError::AndroidGatewayProtocol(
            "Authority SELinux peer domain is not configured".to_string(),
        )
    })?;
    let fd = stream.as_raw_fd();
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut credentials_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut credentials_len,
        )
    };
    if status != 0 || credentials_len as usize != std::mem::size_of::<libc::ucred>() {
        return Err(ToolRuntimeError::AndroidGatewayProtocol(
            "SO_PEERCRED verification failed".to_string(),
        ));
    }
    let pid = u32::try_from(credentials.pid).map_err(|_| {
        ToolRuntimeError::AndroidGatewayProtocol("invalid Authority peer pid".to_string())
    })?;
    #[cfg(test)]
    let peer_uid_is_admissible = credentials.uid >= 10_000 || policy.allow_host_test_uid;
    #[cfg(not(test))]
    let peer_uid_is_admissible = credentials.uid >= 10_000;
    if pid == 0
        || !peer_uid_is_admissible
        || match policy.expected_uid {
            Some(expected_uid) => credentials.uid != expected_uid,
            None => !policy.allow_uid_discovery,
        }
    {
        return Err(ToolRuntimeError::AndroidGatewayProtocol(
            "Authority SO_PEERCRED identity mismatch".to_string(),
        ));
    }

    let mut peer_security = [0_u8; 512];
    let mut peer_security_len = peer_security.len() as libc::socklen_t;
    let status = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            peer_security.as_mut_ptr().cast(),
            &mut peer_security_len,
        )
    };
    if status != 0 || peer_security_len == 0 || peer_security_len as usize > peer_security.len() {
        return Err(ToolRuntimeError::AndroidGatewayProtocol(
            "SO_PEERSEC verification failed".to_string(),
        ));
    }
    let peer_security = &peer_security[..peer_security_len as usize];
    let peer_security = peer_security.strip_suffix(&[0]).unwrap_or(peer_security);
    let selinux_domain = std::str::from_utf8(peer_security)
        .map_err(|_| {
            ToolRuntimeError::AndroidGatewayProtocol(
                "Authority SO_PEERSEC identity is not UTF-8".to_string(),
            )
        })?
        .to_string();
    if !security_context_matches(expected_domain, &selinux_domain) {
        return Err(ToolRuntimeError::AndroidGatewayProtocol(
            "Authority SO_PEERSEC domain mismatch".to_string(),
        ));
    }
    Ok(GatewayPeerIdentity {
        pid,
        uid: credentials.uid,
        gid: credentials.gid,
        selinux_domain,
    })
}

fn security_context_matches(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }
    let Some(categories) = actual
        .strip_prefix(expected)
        .and_then(|suffix| suffix.strip_prefix(':'))
    else {
        return false;
    };
    !categories.is_empty()
        && categories.split(',').all(|category| {
            let category = category.strip_prefix('c').unwrap_or("");
            match category.split_once('.') {
                Some((start, end)) => start
                    .parse::<u16>()
                    .ok()
                    .zip(end.parse::<u16>().ok())
                    .is_some_and(|(start, end)| start <= end && end <= 1023),
                None => category
                    .parse::<u16>()
                    .ok()
                    .is_some_and(|category| category <= 1023),
            }
        })
}

pub fn execute_with_adapter<A: ToolRuntimeAdapter + ?Sized>(
    adapter: &A,
    manifest: &ToolManifest,
    call: &ToolCallInput,
) -> Result<Value> {
    adapter.execute_tool(manifest, call)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SystemStatusInput {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SystemStatusOutput {
    pub ok: bool,
    pub daemon: String,
    pub platform: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalEchoInput {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalEchoOutput {
    pub ok: bool,
    pub message: String,
    pub approved: bool,
}

pub fn generated_system_status_manifest() -> ToolManifest {
    let mut manifest = ToolManifest::system_status();
    manifest.input_schema = serde_json::to_value(schema_for!(SystemStatusInput).schema)
        .expect("schema should serialize");
    manifest.output_schema = serde_json::to_value(schema_for!(SystemStatusOutput).schema)
        .expect("schema should serialize");
    manifest
}

pub fn generated_demo_approval_echo_manifest() -> ToolManifest {
    let mut manifest = ToolManifest::demo_approval_echo();
    manifest.input_schema = serde_json::to_value(schema_for!(ApprovalEchoInput).schema)
        .expect("schema should serialize");
    manifest.output_schema = serde_json::to_value(schema_for!(ApprovalEchoOutput).schema)
        .expect("schema should serialize");
    manifest
}

#[cfg(any(test, feature = "legacy-authority-effects"))]
pub fn android_gateway_manifests() -> Vec<ToolManifest> {
    [
        (
            "android.file.read_bounded",
            "Read the exact user-selected Android document.",
        ),
        (
            "android.browser.open_bounded",
            "Open one exact HTTPS URL in the Trillionnium Browser.",
        ),
        (
            "android.notification.post_bounded",
            "Post one exact approval-bound notification owned by Android Authority.",
        ),
        (
            "android.browser.extract_bounded",
            "Return explicitly shared Browser context.",
        ),
        (
            "android.notifications.organize_bounded",
            "Organize user-authorized notification metadata.",
        ),
    ]
    .into_iter()
    .map(|(name, description)| android_gateway_manifest(name, description))
    .collect()
}

/// The Android production runtime has no generic plan/effect catalog. Built-in
/// Agents use their measured direct adapters instead.
#[cfg(not(any(test, feature = "legacy-authority-effects")))]
pub fn android_gateway_manifests() -> Vec<ToolManifest> {
    Vec::new()
}

/// Android actions that currently have a real, independently receipted OS
/// side effect.  File reads, browser extraction, and notification summaries
/// are provenance context acquisition operations; advertising them as
/// executor tools would let an Agent mistake a caller-provided summary for an
/// Android action.  Their schemas remain below as protocol fixtures while the
/// Context Service owns the read-only surface.
#[cfg(any(test, feature = "legacy-authority-effects"))]
pub fn executable_android_gateway_manifests() -> Vec<ToolManifest> {
    android_gateway_manifests()
        .into_iter()
        .filter(|manifest| {
            matches!(
                manifest.name.as_str(),
                "android.browser.open_bounded" | "android.notification.post_bounded"
            )
        })
        .collect()
}

/// Production Android Agents execute through their measured Direct adapters,
/// so the retired generic Authority effect catalog is not linked or exposed.
#[cfg(not(any(test, feature = "legacy-authority-effects")))]
pub fn executable_android_gateway_manifests() -> Vec<ToolManifest> {
    Vec::new()
}

/// The tool catalog exposed to production Agent API peers. Local shims and
/// descriptor-only context operations remain available to explicit developer
/// tests, but are not part of the phone action ABI.
pub fn production_agent_api_manifests() -> Vec<ToolManifest> {
    executable_android_gateway_manifests()
}

pub fn production_agent_tool_allowed(name: &str) -> bool {
    production_agent_api_manifests()
        .iter()
        .any(|manifest| manifest.name == name)
}

#[cfg(any(test, feature = "legacy-authority-effects"))]
fn android_gateway_manifest(name: &str, description: &str) -> ToolManifest {
    let payload_schema = match name {
        "android.browser.open_bounded" => json!({
            "type": "object",
            "required": [
                "execution_payload_ref",
                "execution_payload_sha256",
                "execution_payload_shape"
            ],
            "properties": {
                "execution_payload_ref": {
                    "type": "string",
                    "pattern": "^execution-payload-[0-9a-f]{64}$"
                },
                "execution_payload_sha256": {
                    "type": "string",
                    "pattern": "^[0-9a-f]{64}$"
                },
                "execution_payload_shape": { "const": "exact_https_url.v1" }
            },
            "additionalProperties": false
        }),
        "android.notification.post_bounded" => json!({
            "type": "object",
            "required": ["title", "body"],
            "properties": {
                "title": { "type": "string", "minLength": 1, "maxLength": 120 },
                "body": { "type": "string", "minLength": 1, "maxLength": 1000 }
            },
            "additionalProperties": false
        }),
        _ => json!({ "type": "object" }),
    };
    let network_scope_schema = match name {
        "android.browser.open_bounded" => json!({ "const": "exact_https_url" }),
        "android.notification.post_bounded" => json!({ "const": "none" }),
        _ => json!({ "enum": ["none", "exact_https_url"] }),
    };
    ToolManifest {
        schema_version: TOOL_SCHEMA_VERSION.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        input_schema: json!({
            "type": "object",
            "required": [
                "request_id", "source_id", "context_sha256", "plan_sha256",
                "provider_output_sha256", "approval_nonce", "network_scope", "payload"
            ],
            "properties": {
                "request_id": { "type": "string", "minLength": 1, "maxLength": 128 },
                "source_id": { "type": "string", "minLength": 1, "maxLength": 512 },
                "context_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                "plan_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                "provider_output_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                "approval_nonce": { "type": "string", "minLength": 16, "maxLength": 256 },
                "network_scope": network_scope_schema,
                "payload": payload_schema
            },
            "additionalProperties": false
        }),
        output_schema: json!({
            "type": "object",
            "required": [
                "action_ok", "receipt_id", "receipt_json", "result_text", "undo_supported"
            ],
            "properties": {
                "action_ok": { "type": "boolean" },
                "receipt_id": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                "receipt_json": { "type": "string", "minLength": 2 },
                "result_text": { "type": "string" },
                "undo_supported": { "type": "boolean" }
            },
            "additionalProperties": false
        }),
        capabilities: vec![format!("os.tool.{name}")],
        risk: RiskTier::Medium,
        executor: ToolExecutor {
            kind: ToolExecutorKind::AndroidGateway,
            command: vec![DEFAULT_ANDROID_GATEWAY_SOCKET.to_string(), name.to_string()],
        },
        agent_plan_contract: match name {
            "android.browser.open_bounded" => Some(AgentPlanActionContract {
                requires_approval: true,
                network_scope: "per_request".to_string(),
                undo_contract: "no_undo_external_browser_launch".to_string(),
            }),
            "android.notification.post_bounded" => Some(AgentPlanActionContract {
                requires_approval: true,
                network_scope: "none".to_string(),
                undo_contract: "cancel_exact_owned_notification".to_string(),
            }),
            _ => None,
        },
    }
}

pub fn built_in_manifests() -> Vec<ToolManifest> {
    let mut manifests = local_shim_manifests();
    manifests.extend(executable_android_gateway_manifests());
    manifests
}

pub fn local_shim_manifests() -> Vec<ToolManifest> {
    vec![
        generated_system_status_manifest(),
        generated_demo_approval_echo_manifest(),
    ]
}

pub fn manifest_by_name(tool_name: &str) -> Option<ToolManifest> {
    built_in_manifests()
        .into_iter()
        .find(|manifest| manifest.name == tool_name)
}

pub fn validate_manifest(manifest: &ToolManifest) -> Result<ValidationResult> {
    let mut errors = Vec::new();

    if manifest.schema_version != TOOL_SCHEMA_VERSION {
        return Err(ToolRuntimeError::UnsupportedSchemaVersion(
            manifest.schema_version.clone(),
        ));
    }

    if manifest.name.trim().is_empty() {
        errors.push("tool name must not be empty".to_string());
    }
    if manifest.executor.command.is_empty() {
        errors.push("executor command must not be empty".to_string());
    }
    if let Some(contract) = &manifest.agent_plan_contract {
        if !matches!(
            contract.network_scope.as_str(),
            "none" | "per_request" | "allowlisted"
        ) {
            errors.push("agent plan contract has invalid network scope".to_string());
        }
        if contract.undo_contract.trim().is_empty() || contract.undo_contract.len() > 256 {
            errors.push("agent plan contract has invalid undo contract".to_string());
        }
        if !contract.requires_approval && !matches!(manifest.risk, RiskTier::Low) {
            errors.push("non-low-risk agent plan contract must require approval".to_string());
        }
    }

    compile_schema(&manifest.input_schema)
        .map_err(|error| ToolRuntimeError::InvalidSchema(error.to_string()))?;
    compile_schema(&manifest.output_schema)
        .map_err(|error| ToolRuntimeError::InvalidSchema(error.to_string()))?;

    if errors.is_empty() {
        Ok(ValidationResult::ok())
    } else {
        Ok(ValidationResult::failed(errors))
    }
}

pub fn validate_tool_call(
    manifest: &ToolManifest,
    call: &ToolCallInput,
) -> Result<ValidationResult> {
    if manifest.name != call.tool_name {
        return Err(ToolRuntimeError::ToolNameMismatch {
            call_tool: call.tool_name.clone(),
            manifest_tool: manifest.name.clone(),
        });
    }

    let compiled = compile_schema(&manifest.input_schema)
        .map_err(|error| ToolRuntimeError::InvalidSchema(error.to_string()))?;

    match compiled.validate(&call.arguments) {
        Ok(()) => Ok(ValidationResult::ok()),
        Err(errors) => Ok(ValidationResult::failed(
            errors.map(|error| error.to_string()).collect(),
        )),
    }
}

pub fn run_local_shim_system_status() -> Value {
    json!({
        "ok": true,
        "daemon": "trillionniumd",
        "platform": std::env::consts::OS
    })
}

pub fn run_local_shim_demo_approval_echo(input: ApprovalEchoInput) -> Value {
    json!({
        "ok": true,
        "message": input.message,
        "approved": true
    })
}

pub fn execute_builtin_tool(manifest: &ToolManifest, call: &ToolCallInput) -> Result<Value> {
    execute_builtin_tool_with_execution_payload(manifest, call, None)
}

pub fn execute_builtin_tool_with_execution_payload(
    manifest: &ToolManifest,
    call: &ToolCallInput,
    execution_payload: Option<&ResolvedExecutionPayload>,
) -> Result<Value> {
    match manifest.executor.kind {
        ToolExecutorKind::LocalShim if execution_payload.is_none() => {
            execute_with_adapter(&LocalShimAdapter, manifest, call)
        }
        ToolExecutorKind::AndroidGateway => {
            #[cfg(any(test, feature = "legacy-authority-effects"))]
            {
                let adapter = AndroidGatewayAdapter::system_default();
                adapter.execute_tool_with_execution_payload(manifest, call, execution_payload)
            }
            #[cfg(not(any(test, feature = "legacy-authority-effects")))]
            {
                let _ = execution_payload;
                Err(ToolRuntimeError::UnsupportedTool(manifest.name.clone()))
            }
        }
        _ => Err(ToolRuntimeError::UnsupportedTool(manifest.name.clone())),
    }
}

fn execute_local_shim_tool(manifest: &ToolManifest, call: &ToolCallInput) -> Result<Value> {
    let call_validation = validate_tool_call(manifest, call)?;
    if !call_validation.valid {
        return Err(ToolRuntimeError::InvalidArguments {
            tool: manifest.name.clone(),
            error: call_validation.errors.join("; "),
        });
    }

    let output = match manifest.name.as_str() {
        "system.status" => run_local_shim_system_status(),
        "demo.approval_echo" => {
            let input = serde_json::from_value::<ApprovalEchoInput>(call.arguments.clone())
                .map_err(|error| ToolRuntimeError::InvalidArguments {
                    tool: manifest.name.clone(),
                    error: error.to_string(),
                })?;
            run_local_shim_demo_approval_echo(input)
        }
        other => return Err(ToolRuntimeError::UnsupportedTool(other.to_string())),
    };

    let output_validation = validate_tool_output(manifest, &output)?;
    if !output_validation.valid {
        return Err(ToolRuntimeError::InvalidOutput {
            tool: manifest.name.clone(),
            errors: output_validation.errors,
        });
    }

    Ok(output)
}

pub fn validate_tool_output(manifest: &ToolManifest, output: &Value) -> Result<ValidationResult> {
    let compiled = compile_schema(&manifest.output_schema)
        .map_err(|error| ToolRuntimeError::InvalidSchema(error.to_string()))?;

    match compiled.validate(output) {
        Ok(()) => Ok(ValidationResult::ok()),
        Err(errors) => Ok(ValidationResult::failed(
            errors.map(|error| error.to_string()).collect(),
        )),
    }
}

fn compile_schema(schema: &Value) -> std::result::Result<JSONSchema, String> {
    JSONSchema::compile(schema).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use trillionnium_os_types::{AgentExecutionBinding, TaskId, ToolCallId, sha256_json};

    use super::*;

    #[test]
    fn authority_boot_peer_pin_is_uid_domain_and_key_immutable() {
        let state = Mutex::new(None);
        let domain = "u:r:trillionnium_aiauthority:s0:c1,c2";
        let key_id = "a".repeat(64);
        let expected = AuthorityBootPeerPin {
            uid: 10_123,
            selinux_domain: domain.to_string(),
            receipt_key_id: key_id.clone(),
        };
        commit_authority_boot_peer_pin_to(&state, 10_123, domain, &key_id).unwrap();
        commit_authority_boot_peer_pin_to(&state, 10_123, domain, &key_id).unwrap();
        assert_eq!(
            read_authority_boot_peer_pin_from(&state).unwrap(),
            Some(expected)
        );
        assert!(
            commit_authority_boot_peer_pin_to(&state, 10_124, domain, &key_id)
                .unwrap_err()
                .to_string()
                .contains("changed during this daemon boot")
        );
        assert!(
            commit_authority_boot_peer_pin_to(
                &state,
                10_123,
                "u:r:trillionnium_other:s0",
                &key_id,
            )
            .is_err()
        );
        assert!(
            commit_authority_boot_peer_pin_to(&state, 10_123, domain, &"b".repeat(64))
                .unwrap_err()
                .to_string()
                .contains("changed during this daemon boot")
        );
    }

    #[test]
    fn authority_boot_peer_pin_local_states_are_order_isolated() {
        let domain = "u:r:trillionnium_aiauthority:s0:c1,c2";
        let key_a = "a".repeat(64);
        let key_b = "b".repeat(64);
        let state_a = Mutex::new(None);
        let state_b = Mutex::new(None);

        assert!(commit_authority_boot_peer_pin_to(&state_a, 9_999, domain, &key_a).is_err());
        assert!(
            commit_authority_boot_peer_pin_to(
                &state_a,
                10_123,
                "u:r:trillionnium_other:s0",
                &key_a,
            )
            .is_err()
        );
        assert!(commit_authority_boot_peer_pin_to(&state_a, 10_123, domain, "short").is_err());
        assert_eq!(read_authority_boot_peer_pin_from(&state_a).unwrap(), None);

        commit_authority_boot_peer_pin_to(&state_a, 10_123, domain, &key_a).unwrap();
        commit_authority_boot_peer_pin_to(&state_b, 10_124, domain, &key_b).unwrap();
        commit_authority_boot_peer_pin_to(&state_a, 10_123, domain, &key_a).unwrap();
        commit_authority_boot_peer_pin_to(&state_b, 10_124, domain, &key_b).unwrap();

        assert_eq!(
            read_authority_boot_peer_pin_from(&state_a).unwrap(),
            Some(AuthorityBootPeerPin {
                uid: 10_123,
                selinux_domain: domain.to_string(),
                receipt_key_id: key_a,
            })
        );
        assert_eq!(
            read_authority_boot_peer_pin_from(&state_b).unwrap(),
            Some(AuthorityBootPeerPin {
                uid: 10_124,
                selinux_domain: domain.to_string(),
                receipt_key_id: key_b,
            })
        );
    }

    #[test]
    fn system_default_peer_policy_prefers_boot_pin_over_environment() {
        let state = Mutex::new(None);
        let pinned_domain = "u:r:trillionnium_aiauthority:s0:c1,c2";
        let pinned_key_id = "a".repeat(64);
        commit_authority_boot_peer_pin_to(&state, 10_123, pinned_domain, &pinned_key_id).unwrap();

        let policy = system_default_gateway_peer_policy_from(
            &state,
            Some(20_999),
            Some("u:r:configured_substitution:s0".to_string()),
        );
        assert_eq!(policy.expected_uid, Some(10_123));
        assert_eq!(
            policy.expected_selinux_domain.as_deref(),
            Some(pinned_domain)
        );
        assert_eq!(
            policy.expected_receipt_key_id.as_deref(),
            Some(pinned_key_id.as_str())
        );
        assert!(!policy.allow_uid_discovery);
        assert!(!policy.allow_host_test_uid);
    }

    #[test]
    fn system_default_peer_policy_denies_all_when_boot_pin_lock_is_poisoned() {
        let state = Arc::new(Mutex::new(None));
        let state_to_poison = Arc::clone(&state);
        assert!(
            thread::spawn(move || {
                let _guard = state_to_poison.lock().unwrap();
                panic!("poison local Authority boot pin fixture");
            })
            .join()
            .is_err()
        );
        assert!(state.is_poisoned());

        let policy = system_default_gateway_peer_policy_from(
            &state,
            Some(20_999),
            Some("u:r:configured_substitution:s0".to_string()),
        );
        assert_eq!(policy.expected_uid, None);
        assert_eq!(policy.expected_selinux_domain, None);
        assert_eq!(policy.expected_receipt_key_id, None);
        assert!(!policy.allow_uid_discovery);
        assert!(!policy.allow_host_test_uid);

        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("poisoned-pin-gateway.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let _ = listener.accept().unwrap();
        });
        let adapter = AndroidGatewayAdapter {
            socket_path: socket,
            timeout: Duration::from_secs(2),
            peer_policy: policy,
        };
        let error = adapter
            .authority_key_metadata("poisoned-pin-fixture")
            .expect_err("poisoned production pin state must deny before protocol I/O");
        assert!(
            error
                .to_string()
                .contains("Authority SELinux peer domain is not configured")
        );
        server.join().unwrap();
    }

    #[test]
    fn authority_boot_peer_pin_concurrent_commits_are_atomic_and_isolated() {
        let domain = "u:r:trillionnium_aiauthority:s0:c1,c2";
        let same_state = Arc::new(Mutex::new(None));
        let same_barrier = Arc::new(Barrier::new(8));
        let same_key = "a".repeat(64);
        let mut same_threads = Vec::new();
        for _ in 0..8 {
            let state = Arc::clone(&same_state);
            let barrier = Arc::clone(&same_barrier);
            let key = same_key.clone();
            same_threads.push(thread::spawn(move || {
                barrier.wait();
                commit_authority_boot_peer_pin_to(&state, 10_123, domain, &key)
            }));
        }
        for thread in same_threads {
            thread.join().unwrap().unwrap();
        }
        assert_eq!(
            read_authority_boot_peer_pin_from(&same_state).unwrap(),
            Some(AuthorityBootPeerPin {
                uid: 10_123,
                selinux_domain: domain.to_string(),
                receipt_key_id: same_key,
            })
        );

        let conflicting_state = Arc::new(Mutex::new(None));
        let conflicting_barrier = Arc::new(Barrier::new(12));
        let mut conflicting_threads = Vec::new();
        for index in 0..12 {
            let state = Arc::clone(&conflicting_state);
            let barrier = Arc::clone(&conflicting_barrier);
            let candidate = if index % 2 == 0 {
                (10_123, "a".repeat(64))
            } else {
                (10_124, "b".repeat(64))
            };
            conflicting_threads.push(thread::spawn(move || {
                barrier.wait();
                let result =
                    commit_authority_boot_peer_pin_to(&state, candidate.0, domain, &candidate.1);
                (candidate, result)
            }));
        }
        let results: Vec<_> = conflicting_threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        let winner = read_authority_boot_peer_pin_from(&conflicting_state)
            .unwrap()
            .expect("one complete candidate must win");
        assert!(
            (winner.uid == 10_123 && winner.receipt_key_id == "a".repeat(64))
                || (winner.uid == 10_124 && winner.receipt_key_id == "b".repeat(64))
        );
        assert_eq!(winner.selinux_domain, domain);
        for ((uid, key), result) in results {
            if uid == winner.uid && key == winner.receipt_key_id {
                result.expect("all submissions matching the winner must be idempotent");
            } else {
                assert!(
                    result
                        .expect_err("the losing complete candidate must be rejected")
                        .to_string()
                        .contains("changed during this daemon boot")
                );
            }
        }
    }

    #[test]
    fn generated_manifest_validates() {
        let manifest = generated_system_status_manifest();

        assert!(
            validate_manifest(&manifest)
                .expect("manifest validation should run")
                .valid
        );
    }

    #[test]
    fn built_in_manifests_include_low_and_medium_risk_tools() {
        let manifests = built_in_manifests();

        assert!(
            manifests
                .iter()
                .any(|manifest| manifest.name == "system.status")
        );
        assert!(
            manifests
                .iter()
                .any(|manifest| manifest.name == "demo.approval_echo")
        );
        assert!(manifests.iter().all(|manifest| {
            validate_manifest(manifest)
                .expect("manifest validation should run")
                .valid
        }));
        assert!(
            manifests
                .iter()
                .any(|manifest| manifest.name == "android.browser.open_bounded")
        );
        assert!(!manifests.iter().any(|manifest| {
            matches!(
                manifest.name.as_str(),
                "android.file.read_bounded"
                    | "android.browser.extract_bounded"
                    | "android.notifications.organize_bounded"
            )
        }));
        assert_eq!(android_gateway_manifests().len(), 5);
        assert_eq!(executable_android_gateway_manifests().len(), 2);
        let production = production_agent_api_manifests();
        assert_eq!(production.len(), 2);
        let browser = production
            .iter()
            .find(|manifest| manifest.name == "android.browser.open_bounded")
            .unwrap();
        let contract = browser
            .agent_plan_contract
            .as_ref()
            .expect("production Agent tool must publish immutable preview semantics");
        assert!(contract.requires_approval);
        assert_eq!(contract.network_scope, "per_request");
        assert_eq!(contract.undo_contract, "no_undo_external_browser_launch");
        let serialized = serde_json::to_value(browser).unwrap();
        assert_eq!(
            serialized["agent_plan_contract"]["undo_contract"],
            "no_undo_external_browser_launch"
        );
        let checked_in_schema: Value =
            serde_json::from_str(include_str!("../../../schemas/tool-manifest.schema.json"))
                .unwrap();
        let compiled = JSONSchema::compile(&checked_in_schema).unwrap();
        if let Err(errors) = compiled.validate(&serialized) {
            panic!(
                "production browser manifest drifted from checked-in schema: {}",
                errors
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        let notification = production
            .iter()
            .find(|manifest| manifest.name == "android.notification.post_bounded")
            .unwrap();
        let contract = notification.agent_plan_contract.as_ref().unwrap();
        assert!(contract.requires_approval);
        assert_eq!(contract.network_scope, "none");
        assert_eq!(contract.undo_contract, "cancel_exact_owned_notification");
        let notification_json = serde_json::to_value(notification).unwrap();
        assert_eq!(
            notification_json["input_schema"]["properties"]["payload"]["additionalProperties"],
            false
        );
        assert!(
            android_gateway_manifests()
                .iter()
                .all(|manifest| { manifest.executor.kind == ToolExecutorKind::AndroidGateway })
        );
    }

    fn gateway_call(manifest: &ToolManifest) -> ToolCallInput {
        let task_id = TaskId("task-gateway-test".to_string());
        let tool_call_id = ToolCallId("toolcall-gateway-test".to_string());
        let (payload, network_scope) = match manifest.name.as_str() {
            "android.browser.open_bounded" => (
                json!({
                    "execution_payload_ref": format!("execution-payload-{}", "e".repeat(64)),
                    "execution_payload_sha256": "f".repeat(64),
                    "execution_payload_shape": "exact_https_url.v1"
                }),
                "exact_https_url",
            ),
            "android.notification.post_bounded" => (
                json!({
                    "title": "Approved fixture",
                    "body": "Exact notification body"
                }),
                "none",
            ),
            _ => (json!({"uri": "content://fixture/1"}), "none"),
        };
        let arguments = json!({
            "request_id": "request-gateway-test",
            "source_id": "saf:test",
            "context_sha256": "a".repeat(64),
            "plan_sha256": "b".repeat(64),
            "provider_output_sha256": "c".repeat(64),
            "approval_nonce": "approval-nonce-test-1234",
            "network_scope": network_scope,
            "payload": payload
        });
        let binding = AgentExecutionBinding {
            agent_id: "agent-fixture".to_string(),
            peer_uid: 62010,
            peer_gid: 62011,
            peer_selinux_domain: "u:r:trillionnium_agent:s0".to_string(),
            agent_executable_sha256: "d".repeat(64),
            subject_user_id: 0,
            origin_uid: 10123,
            origin_selinux_domain: "u:r:trillionnium_aishell:s0".to_string(),
            session_id: "session-fixture".to_string(),
            task_id: task_id.clone(),
            plan_id: "plan-fixture".to_string(),
            action_id: "action-fixture".to_string(),
            tool_call_id: tool_call_id.clone(),
            tool_name: manifest.name.clone(),
            tool_manifest_sha256: sha256_json(&serde_json::to_value(manifest).unwrap()),
            accepted_plan_sha256: "9".repeat(64),
            arguments_sha256: sha256_json(&arguments),
        };
        ToolCallInput {
            task_id,
            tool_call_id,
            tool_name: manifest.name.clone(),
            arguments,
            agent_execution_binding: Some(binding),
        }
    }

    #[test]
    fn android_gateway_adapter_rejects_missing_or_mismatched_os_binding() {
        let manifest = android_gateway_manifests().remove(0);
        let temp = tempfile::tempdir().unwrap();
        let mut missing = gateway_call(&manifest);
        missing.agent_execution_binding = None;
        let error = AndroidGatewayAdapter::new(temp.path().join("unused.sock"))
            .execute_tool(&manifest, &missing)
            .expect_err("missing binding must fail before connecting");
        assert!(matches!(error, ToolRuntimeError::AndroidGatewayProtocol(_)));

        let mut mismatched = gateway_call(&manifest);
        mismatched.arguments["payload"]["uri"] = json!("content://fixture/swapped");
        let error = AndroidGatewayAdapter::new(temp.path().join("unused.sock"))
            .execute_tool(&manifest, &mismatched)
            .expect_err("parameter swap must fail before connecting");
        assert!(matches!(error, ToolRuntimeError::AndroidGatewayProtocol(_)));
    }

    #[test]
    fn android_gateway_adapter_fetches_key_metadata_over_independent_channel() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("gateway-key.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request["method"], "key_metadata");
            assert!(request.get("execution_binding").is_none());
            let response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": request["request_id"],
                "ok": true,
                "result": {
                    "schema": "org.trillionnium.ai-authority.receipt-key.v1",
                    "key_id": "e".repeat(64),
                    "key_epoch": 2,
                    "hardware_backed": true
                }
            });
            serde_json::to_writer(&mut stream, &response).unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let output = AndroidGatewayAdapter::new(socket)
            .authority_key_metadata("key-metadata-fixture")
            .expect("authenticated metadata call should pass");
        server.join().unwrap();
        assert_eq!(output["key_id"], "e".repeat(64));
        assert_eq!(output["key_epoch"], 2);
    }

    #[test]
    fn authority_explicit_indeterminate_is_never_downgraded_to_protocol_failure() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("gateway-indeterminate.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            let response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": request["request_id"],
                "ok": false,
                "error": "execution_outcome_indeterminate",
            });
            serde_json::to_writer(&mut stream, &response).unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let error = AndroidGatewayAdapter::new(socket)
            .authority_key_metadata("keymeta-indeterminate-fixture")
            .expect_err("Authority indeterminate outcome must remain terminal and ambiguous");
        server.join().unwrap();
        assert!(matches!(
            error,
            ToolRuntimeError::AndroidGatewayOutcomeIndeterminate(_)
        ));
    }

    #[test]
    fn android_gateway_adapter_resolves_only_exact_context_capture_bindings() {
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("gateway-context.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let capture_id = format!("capture-{}", "a".repeat(64));
        let receipt_id = "b".repeat(64);
        let expected_capture_id = capture_id.clone();
        let expected_receipt_id = receipt_id.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request.as_object().unwrap().len(), 8);
            assert_eq!(request["method"], "resolve_context");
            assert_eq!(request["capture_id"], expected_capture_id);
            assert_eq!(request["capture_receipt_id"], expected_receipt_id);
            assert_eq!(request["capture_request_id"], "capture-request-fixture");
            assert_eq!(request["requesting_uid"], 10_123);
            assert_eq!(request["subject_user_id"], 0);
            assert!(request.get("execution_binding").is_none());
            let response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": request["request_id"],
                "ok": true,
                "result": {
                    "schema": "org.trillionnium.ai-authority.context-resolution.v1",
                    "capture_id": request["capture_id"],
                    "single_use_consumed": true,
                    "content": "private context",
                },
            });
            serde_json::to_writer(&mut stream, &response).unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let output = AndroidGatewayAdapter::new(socket)
            .resolve_context_capture(
                "context-resolve-fixture",
                &capture_id,
                &receipt_id,
                "capture-request-fixture",
                10_123,
                0,
            )
            .expect("exact authenticated context binding should pass");
        server.join().unwrap();
        assert_eq!(output["capture_id"], capture_id);
        assert_eq!(output["single_use_consumed"], true);

        let error = AndroidGatewayAdapter::new(temp.path().join("unused.sock"))
            .resolve_context_capture(
                "context-resolve-invalid",
                "capture-not-a-digest",
                &receipt_id,
                "capture-request-fixture",
                10_123,
                0,
            )
            .expect_err("invalid capture binding must fail before socket I/O");
        assert!(matches!(error, ToolRuntimeError::AndroidGatewayProtocol(_)));
    }

    #[test]
    fn android_gateway_adapter_rejects_non_undoable_receipt_before_gateway_io() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = android_gateway_manifests().remove(0);
        let call = gateway_call(&manifest);
        let binding = call.agent_execution_binding.unwrap();
        let receipt_id = "d".repeat(64);
        let original = json!({
            "action_ok": true,
            "receipt_id": receipt_id,
            "receipt_json": "{}",
            "result_text": "",
            "undo_supported": false,
        });
        let error = AndroidGatewayAdapter::new(temp.path().join("must-not-connect.sock"))
            .undo_receipt(
                "undo-fixture",
                &receipt_id,
                &original,
                &binding,
                &"e".repeat(64),
                &json!({}),
            )
            .expect_err("undo_supported=false must fail before gateway I/O");
        assert!(error.to_string().contains("undo_supported=false"));
    }

    #[test]
    fn android_gateway_adapter_fails_closed_without_socket() {
        let temp = tempfile::tempdir().unwrap();
        let manifest = executable_android_gateway_manifests().remove(0);
        let mut call = gateway_call(&manifest);
        let url = "https://fixture.invalid/bounded";
        let payload_sha256 = sha256_json(&json!({"url": url}));
        call.arguments["network_scope"] = json!("exact_https_url");
        call.arguments["payload"]["execution_payload_sha256"] = json!(payload_sha256.clone());
        call.agent_execution_binding
            .as_mut()
            .unwrap()
            .arguments_sha256 = sha256_json(&call.arguments);
        let resolved = ResolvedExecutionPayload {
            execution_payload_ref: call.arguments["payload"]["execution_payload_ref"]
                .as_str()
                .unwrap()
                .to_string(),
            payload_sha256,
            payload_shape: "exact_https_url.v1".to_string(),
            url: zeroize::Zeroizing::new(url.to_string()),
        };
        let error = AndroidGatewayAdapter::new(temp.path().join("missing.sock"))
            .execute_tool_with_execution_payload(&manifest, &call, Some(&resolved))
            .expect_err("missing gateway must fail closed");
        assert!(matches!(
            error,
            ToolRuntimeError::AndroidGatewayUnavailable(_)
        ));
    }

    #[test]
    fn notification_payload_is_closed_and_utf8_byte_bounded_before_gateway_io() {
        let manifest = executable_android_gateway_manifests()
            .into_iter()
            .find(|manifest| manifest.name == "android.notification.post_bounded")
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("must-not-connect.sock");

        let valid = gateway_call(&manifest);
        let error = AndroidGatewayAdapter::new(&socket)
            .execute_tool(&manifest, &valid)
            .expect_err("valid payload should reach the unavailable gateway");
        assert!(matches!(
            error,
            ToolRuntimeError::AndroidGatewayUnavailable(_)
        ));

        for invalid_payload in [
            json!({"title": "   ", "body": "ok"}),
            json!({"title": "ok", "body": "line\nbreak"}),
            json!({"title": "a".repeat(121), "body": "ok"}),
            json!({"title": "界".repeat(41), "body": "ok"}),
            json!({"title": "ok", "body": "body", "tag": "model-controlled"}),
        ] {
            let mut call = gateway_call(&manifest);
            call.arguments["payload"] = invalid_payload;
            let arguments_sha256 = sha256_json(&call.arguments);
            call.agent_execution_binding
                .as_mut()
                .unwrap()
                .arguments_sha256 = arguments_sha256;
            let error = AndroidGatewayAdapter::new(&socket)
                .execute_tool(&manifest, &call)
                .expect_err("invalid notification payload must fail before gateway I/O");
            assert!(
                matches!(
                    error,
                    ToolRuntimeError::InvalidArguments { .. }
                        | ToolRuntimeError::AndroidGatewayProtocol(_)
                ),
                "unexpected error: {error}"
            );
        }
    }

    #[test]
    fn android_tool_catalog_has_100_positive_and_100_negative_schema_vectors_per_tool() {
        for manifest in android_gateway_manifests() {
            for index in 0..100_u32 {
                let mut positive = gateway_call(&manifest);
                positive.task_id = TaskId(format!("task-schema-{index}"));
                positive.tool_call_id = ToolCallId(format!("toolcall-schema-{index}"));
                positive.arguments["request_id"] = json!(format!("request-schema-{index}"));
                assert!(
                    validate_tool_call(&manifest, &positive)
                        .expect("positive schema vector should validate")
                        .valid,
                    "positive vector {index} failed for {}",
                    manifest.name
                );

                let mut negative = positive;
                negative
                    .arguments
                    .as_object_mut()
                    .unwrap()
                    .remove("approval_nonce");
                assert!(
                    !validate_tool_call(&manifest, &negative)
                        .expect("negative schema vector should validate as rejected")
                        .valid,
                    "negative vector {index} passed for {}",
                    manifest.name
                );
            }
        }
    }

    #[test]
    fn valid_empty_system_status_call_passes_schema() {
        let manifest = generated_system_status_manifest();
        let call = ToolCallInput {
            task_id: TaskId::new(),
            tool_call_id: ToolCallId::new(),
            tool_name: manifest.name.clone(),
            arguments: json!({}),
            agent_execution_binding: None,
        };

        assert!(
            validate_tool_call(&manifest, &call)
                .expect("call validation should run")
                .valid
        );
    }

    #[test]
    fn unknown_argument_is_rejected() {
        let manifest = ToolManifest::system_status();
        let call = ToolCallInput {
            task_id: TaskId::new(),
            tool_call_id: ToolCallId::new(),
            tool_name: manifest.name.clone(),
            arguments: json!({"unexpected": true}),
            agent_execution_binding: None,
        };

        let result = validate_tool_call(&manifest, &call).expect("call validation should run");

        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn executes_system_status_builtin() {
        let manifest = generated_system_status_manifest();
        let call = ToolCallInput {
            task_id: TaskId::new(),
            tool_call_id: ToolCallId::new(),
            tool_name: manifest.name.clone(),
            arguments: json!({}),
            agent_execution_binding: None,
        };

        let output = execute_builtin_tool(&manifest, &call).expect("tool should execute");

        assert_eq!(output["ok"], true);
        assert_eq!(output["daemon"], "trillionniumd");
    }

    #[test]
    fn local_shim_adapter_executes_system_status() {
        let adapter = LocalShimAdapter;
        let manifest = generated_system_status_manifest();
        let call = ToolCallInput {
            task_id: TaskId::new(),
            tool_call_id: ToolCallId::new(),
            tool_name: manifest.name.clone(),
            arguments: json!({}),
            agent_execution_binding: None,
        };

        let output = execute_with_adapter(&adapter, &manifest, &call).expect("shim executes");

        assert_eq!(adapter.adapter_name(), "local-shim");
        assert_eq!(output["ok"], true);
    }

    #[test]
    fn executes_approval_echo_builtin_after_policy_allows() {
        let manifest = generated_demo_approval_echo_manifest();
        let call = ToolCallInput {
            task_id: TaskId::new(),
            tool_call_id: ToolCallId::new(),
            tool_name: manifest.name.clone(),
            arguments: json!({"message":"hello"}),
            agent_execution_binding: None,
        };

        let output = execute_builtin_tool(&manifest, &call).expect("tool should execute");

        assert_eq!(output["ok"], true);
        assert_eq!(output["message"], "hello");
        assert_eq!(output["approved"], true);
    }
}
