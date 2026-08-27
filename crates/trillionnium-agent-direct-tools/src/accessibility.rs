use std::collections::HashSet;
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

pub const DEFAULT_SOCKET: &str = "@trillionnium_accessibility";
pub const PROTOCOL: &str = "org.trillionnium.agent-accessibility.v2";
pub const MCP_TOOL_NAME: &str = "trillionnium_accessibility";
pub const MAX_BATCH_ACTIONS: usize = 128;
pub const MAX_GESTURE_DURATION_MS: u64 = 60_000;
pub const MAX_BATCH_GESTURE_DURATION_MS: u64 = 60_000;
pub const MAX_NODE_ID_CHARS: usize = 512;
pub const NODE_ID_PATTERN: &str = "^[A-Za-z0-9._:/-]+$";
const MAX_TEXT_UTF16_CODE_UNITS: usize = 16_384;
const MAX_GESTURE_COORDINATE: f32 = 100_000.0;
const MAX_SNAPSHOT_TREE_DEPTH: usize = 32;
const MAX_SNAPSHOT_NODES: usize = 1_024;
const MAX_SNAPSHOT_STRING_CHARS: usize = 512;
const SEMANTIC_PENDING_REQUEST_ID: &str = "os-semantic-pending";

/// Model-facing Accessibility action. The backend protocol and replay identity
/// are authored only after this closed semantic object has been validated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessibilitySemanticRequest {
    Snapshot {
        window_id: Option<i32>,
        snapshot_mode: SnapshotMode,
    },
    Click {
        node_id: String,
    },
    SetText {
        node_id: String,
        text: String,
    },
    Scroll {
        node_id: String,
        direction: ScrollDirection,
    },
    GlobalAction {
        global_action: GlobalAction,
    },
    Gesture {
        points: Vec<GesturePoint>,
        duration_ms: u64,
    },
    Batch {
        actions: Vec<AccessibilityBatchAction>,
    },
}

impl AccessibilitySemanticRequest {
    fn to_backend_request(&self, request_id: String) -> AccessibilityRequest {
        match self {
            Self::Snapshot {
                window_id,
                snapshot_mode,
            } => AccessibilityRequest::Snapshot {
                protocol: PROTOCOL.to_string(),
                request_id,
                window_id: *window_id,
                snapshot_mode: *snapshot_mode,
            },
            Self::Click { node_id } => AccessibilityRequest::Click {
                protocol: PROTOCOL.to_string(),
                request_id,
                node_id: node_id.clone(),
            },
            Self::SetText { node_id, text } => AccessibilityRequest::SetText {
                protocol: PROTOCOL.to_string(),
                request_id,
                node_id: node_id.clone(),
                text: text.clone(),
            },
            Self::Scroll { node_id, direction } => AccessibilityRequest::Scroll {
                protocol: PROTOCOL.to_string(),
                request_id,
                node_id: node_id.clone(),
                direction: direction.clone(),
            },
            Self::GlobalAction { global_action } => AccessibilityRequest::GlobalAction {
                protocol: PROTOCOL.to_string(),
                request_id,
                global_action: global_action.clone(),
            },
            Self::Gesture {
                points,
                duration_ms,
            } => AccessibilityRequest::Gesture {
                protocol: PROTOCOL.to_string(),
                request_id,
                points: points.clone(),
                duration_ms: *duration_ms,
            },
            Self::Batch { actions } => AccessibilityRequest::Batch {
                protocol: PROTOCOL.to_string(),
                request_id,
                actions: actions.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessibilityRequest {
    Snapshot {
        protocol: String,
        request_id: String,
        window_id: Option<i32>,
        snapshot_mode: SnapshotMode,
    },
    Click {
        protocol: String,
        request_id: String,
        node_id: String,
    },
    SetText {
        protocol: String,
        request_id: String,
        node_id: String,
        text: String,
    },
    Scroll {
        protocol: String,
        request_id: String,
        node_id: String,
        direction: ScrollDirection,
    },
    GlobalAction {
        protocol: String,
        request_id: String,
        global_action: GlobalAction,
    },
    Gesture {
        protocol: String,
        request_id: String,
        points: Vec<GesturePoint>,
        duration_ms: u64,
    },
    Batch {
        protocol: String,
        request_id: String,
        actions: Vec<AccessibilityBatchAction>,
    },
}

impl AccessibilityRequest {
    pub fn protocol(&self) -> &str {
        match self {
            Self::Snapshot { protocol, .. }
            | Self::Click { protocol, .. }
            | Self::SetText { protocol, .. }
            | Self::Scroll { protocol, .. }
            | Self::GlobalAction { protocol, .. }
            | Self::Gesture { protocol, .. }
            | Self::Batch { protocol, .. } => protocol,
        }
    }

    pub fn request_id(&self) -> &str {
        match self {
            Self::Snapshot { request_id, .. }
            | Self::Click { request_id, .. }
            | Self::SetText { request_id, .. }
            | Self::Scroll { request_id, .. }
            | Self::GlobalAction { request_id, .. }
            | Self::Gesture { request_id, .. }
            | Self::Batch { request_id, .. } => request_id,
        }
    }

    /// Whether this request belongs to the durable Android operation sequence.
    ///
    /// Android deliberately re-samples snapshots and does not write them to its
    /// replay ledger. Allocating an `op:` sequence for a snapshot would
    /// therefore create a permanent hole that a later contiguous ACK could
    /// never cross.
    #[must_use]
    pub const fn requires_durable_operation_sequence(&self) -> bool {
        !matches!(self, Self::Snapshot { .. })
    }
}

/// Convert one validated semantic action into the unchanged Android wire ABI.
#[cfg(any(test, feature = "development-compatibility-lane"))]
pub fn author_backend_request(
    semantic: &AccessibilitySemanticRequest,
    author: &mut impl BackendRequestIdentityAuthor,
) -> Result<AccessibilityRequest> {
    validate_semantic(semantic)?;
    let semantic_bytes = serde_json::to_vec(semantic)?;
    let request_id = author.author_backend_request_id("accessibility", &semantic_bytes)?;
    let request = semantic.to_backend_request(request_id);
    validate(&request)?;
    Ok(request)
}

/// Batch elements deliberately omit `snapshot` and `batch`: a batch is a
/// bounded sequence of effects, never a recursively nested mini-program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessibilityBatchAction {
    Click {
        node_id: String,
    },
    SetText {
        node_id: String,
        text: String,
    },
    Scroll {
        node_id: String,
        direction: ScrollDirection,
    },
    GlobalAction {
        global_action: GlobalAction,
    },
    Gesture {
        points: Vec<GesturePoint>,
        duration_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScrollDirection {
    Forward,
    Backward,
    Up,
    Down,
    Left,
    Right,
}

/// Privacy shape of an Accessibility snapshot. Metadata-only snapshots remain
/// the product's default observable surface; full text is a separate, bound
/// action that the risk guard currently denies without an OS session lease.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotMode {
    MetadataOnly,
    FullText,
}

impl SnapshotMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata_only",
            Self::FullText => "full_text",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GlobalAction {
    Back,
    Home,
    Recents,
    Notifications,
    QuickSettings,
    PowerDialog,
    LockScreen,
    TakeScreenshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GesturePoint {
    pub x: f32,
    pub y: f32,
    pub at_ms: u64,
}

#[cfg(any(test, feature = "development-compatibility-lane"))]
pub fn call(path: &Path, request: &AccessibilityRequest) -> Result<Value> {
    let agent = crate::risk_guard::current_agent_identity()?;
    call_as(path, request, agent)
}

#[cfg(any(test, feature = "development-compatibility-lane"))]
pub fn call_semantic(
    path: &Path,
    semantic: &AccessibilitySemanticRequest,
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
    request: &AccessibilityRequest,
    context: &crate::trusted_context::TrustedAdapterContext,
) -> Result<Value> {
    if context.adapter()
        != trillionnium_os_types::direct_operation::DirectOperationAdapter::Accessibility
    {
        return Err(DirectToolError::InvalidRequest(
            "trusted context adapter does not match Accessibility".to_string(),
        ));
    }
    let agent = crate::risk_guard::current_agent_identity()?;
    if let Some(denial) = trusted_preflight(request, agent)? {
        return Ok(denial);
    }
    if !request.requires_durable_operation_sequence() {
        return Err(DirectToolError::BackendUnavailable(
            "trusted Accessibility snapshot requires a separate OS-authored read-only identity lane"
                .to_string(),
        ));
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

/// Trusted semantic entry point. The durable journal replaces the temporary
/// identity before any backend connection is attempted.
pub fn call_semantic_trusted(
    path: &Path,
    semantic: &AccessibilitySemanticRequest,
    context: &crate::trusted_context::TrustedAdapterContext,
) -> Result<Value> {
    validate_semantic(semantic)?;
    let request = semantic.to_backend_request(SEMANTIC_PENDING_REQUEST_ID.to_string());
    call_trusted(path, &request, context)
}

fn trusted_preflight(
    request: &AccessibilityRequest,
    agent: AgentIdentity,
) -> Result<Option<Value>> {
    validate(request)?;
    let guard = ProductRiskGuard.assess_accessibility_request(agent, request);
    Ok((!guard.allowed()).then(|| guard_denial(request, guard)))
}

#[cfg(feature = "production-durable-hotpath")]
fn call_allowed_journaled(
    path: &Path,
    request: &AccessibilityRequest,
    agent: AgentIdentity,
    context: &crate::trusted_context::TrustedAdapterContext,
    journal: &mut crate::operation_journal::OperationJournal,
) -> Result<Value> {
    let canonical_request = crate::canonical_operation::accessibility_request(agent, request)?;
    let prepared = crate::direct_tool_call_transport::prepare_product_effect(
        context,
        journal,
        &canonical_request,
    )?;
    execute_prepared(path, request, journal, prepared)
}

fn execute_prepared(
    path: &Path,
    request: &AccessibilityRequest,
    journal: &mut crate::operation_journal::OperationJournal,
    prepared: crate::operation_journal::PreparedOperation,
) -> Result<Value> {
    let backend_request = with_backend_identity(request, prepared.request_id.clone());
    crate::journaled_call::execute(
        path,
        crate::uds::ExpectedBackendPeer::AccessibilityService,
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
            )?;
            validate_snapshot_response(response, &backend_request)
        },
    )
}

#[cfg(test)]
fn call_journaled(
    path: &Path,
    request: &AccessibilityRequest,
    agent: AgentIdentity,
    journal: &mut crate::operation_journal::OperationJournal,
) -> Result<Value> {
    if let Some(denial) = trusted_preflight(request, agent)? {
        return Ok(denial);
    }
    let canonical_request = crate::canonical_operation::accessibility_request(agent, request)?;
    let prepared = journal
        .begin_next_effect(&canonical_request)
        .map_err(crate::journaled_call::journal_error)?
        .into_prepared();
    execute_prepared(path, request, journal, prepared)
}

#[cfg(test)]
fn call_journaled_with_identity(
    path: &Path,
    request: &AccessibilityRequest,
    agent: AgentIdentity,
    journal: &mut crate::operation_journal::OperationJournal,
    os_tool_call_id: &str,
    adapter_effect_ordinal: u64,
) -> Result<Value> {
    if let Some(denial) = trusted_preflight(request, agent)? {
        return Ok(denial);
    }
    let canonical_request = crate::canonical_operation::accessibility_request(agent, request)?;
    let prepared = journal
        .begin_effect_with_identity(os_tool_call_id, adapter_effect_ordinal, &canonical_request)
        .map_err(crate::journaled_call::journal_error)?
        .into_prepared();
    execute_prepared(path, request, journal, prepared)
}

fn with_backend_identity(
    request: &AccessibilityRequest,
    request_id: String,
) -> AccessibilityRequest {
    let mut request = request.clone();
    match &mut request {
        AccessibilityRequest::Snapshot {
            protocol,
            request_id: existing,
            ..
        }
        | AccessibilityRequest::Click {
            protocol,
            request_id: existing,
            ..
        }
        | AccessibilityRequest::SetText {
            protocol,
            request_id: existing,
            ..
        }
        | AccessibilityRequest::Scroll {
            protocol,
            request_id: existing,
            ..
        }
        | AccessibilityRequest::GlobalAction {
            protocol,
            request_id: existing,
            ..
        }
        | AccessibilityRequest::Gesture {
            protocol,
            request_id: existing,
            ..
        }
        | AccessibilityRequest::Batch {
            protocol,
            request_id: existing,
            ..
        } => {
            *protocol = PROTOCOL.to_string();
            *existing = request_id;
        }
    }
    request
}

/// Execute one typed request under an already authenticated Agent identity.
/// Default product binaries currently use [`call`], which derives identity from
/// fixed process credentials. This explicit form keeps the non-journaled
/// compatibility lane directly testable without weakening either boundary.
#[cfg(any(test, feature = "development-compatibility-lane"))]
pub(crate) fn call_as(
    path: &Path,
    request: &AccessibilityRequest,
    agent: AgentIdentity,
) -> Result<Value> {
    validate(request)?;
    let guard = ProductRiskGuard.assess_accessibility_request(agent, request);
    if !guard.allowed() {
        return Ok(guard_denial(request, guard));
    }
    let response = crate::uds::call(
        path,
        crate::uds::ExpectedBackendPeer::AccessibilityService,
        request,
    )?;
    validate_response_binding(&response, PROTOCOL, request.request_id())?;
    reject_reserved_backend_fields(
        &response,
        &[
            "risk_guard",
            crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD,
            crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD,
        ],
    )?;
    validate_snapshot_response(&response, request)?;
    Ok(response)
}

fn validate_snapshot_response(response: &Value, request: &AccessibilityRequest) -> Result<()> {
    let AccessibilityRequest::Snapshot {
        snapshot_mode,
        window_id,
        ..
    } = request
    else {
        return Ok(());
    };
    if response.get("action").and_then(Value::as_str) != Some("snapshot")
        || response.get("snapshot_mode").and_then(Value::as_str) != Some(snapshot_mode.as_str())
    {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot response action/snapshot_mode binding mismatch".to_string(),
        ));
    }
    let ok = response.get("ok").and_then(Value::as_bool).ok_or_else(|| {
        DirectToolError::BackendFailed(
            "Accessibility snapshot response ok must be a boolean".to_string(),
        )
    })?;
    let object = response.as_object().expect("validated backend object");
    const COMMON_FIELDS: [&str; 7] = [
        "protocol",
        "request_id",
        "ok",
        "backend",
        "idempotency_capacity_entries_per_peer",
        "idempotency_capacity_reserved_bytes_per_peer",
        "idempotency_reclamation_status",
    ];
    if object.get("backend").and_then(Value::as_str) != Some("accessibility")
        || object
            .get("idempotency_capacity_entries_per_peer")
            .and_then(Value::as_u64)
            != Some(128)
        || object
            .get("idempotency_capacity_reserved_bytes_per_peer")
            .and_then(Value::as_u64)
            != Some(48 * 1024 * 1024)
        || object
            .get("idempotency_reclamation_status")
            .and_then(Value::as_str)
            != Some("inactive_backend_foundation_requires_trusted_adapter_journal_v1")
    {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot backend/capacity foundation binding mismatch".to_string(),
        ));
    }
    if !ok {
        let mut fields = COMMON_FIELDS.to_vec();
        fields.extend(["error", "action", "snapshot_mode"]);
        let has_replay_scope = object.contains_key("replay_scope");
        if has_replay_scope {
            fields.push("replay_scope");
        }
        if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
            return Err(DirectToolError::BackendFailed(
                "Accessibility failed snapshot response fields are not closed".to_string(),
            ));
        }
        if has_replay_scope
            && object.get("replay_scope").and_then(Value::as_str) != Some("read_only_resampled")
        {
            return Err(DirectToolError::BackendFailed(
                "Accessibility snapshot response replay_scope is invalid".to_string(),
            ));
        }
        return Ok(());
    }
    let mut fields = COMMON_FIELDS.to_vec();
    fields.extend([
        "action",
        "snapshot_mode",
        "generation",
        "window_id",
        "truncated",
        "root",
        "replay_scope",
    ]);
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(DirectToolError::BackendFailed(
            "Accessibility successful snapshot response fields are not closed".to_string(),
        ));
    }
    if object
        .get("generation")
        .and_then(Value::as_u64)
        .is_none_or(|generation| generation == 0)
        || object.get("truncated").and_then(Value::as_bool).is_none()
        || object.get("replay_scope").and_then(Value::as_str) != Some("read_only_resampled")
    {
        return Err(DirectToolError::BackendFailed(
            "Accessibility successful snapshot metadata is malformed".to_string(),
        ));
    }
    let response_window_id = object
        .get("window_id")
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .filter(|value| *value >= 0)
        .ok_or_else(|| {
            DirectToolError::BackendFailed(
                "Accessibility snapshot response window_id must be signed 32-bit".to_string(),
            )
        })?;
    if window_id.is_some_and(|expected| expected != response_window_id) {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot response escaped the requested window".to_string(),
        ));
    }
    let root = response.get("root").ok_or_else(|| {
        DirectToolError::BackendFailed(
            "Accessibility successful snapshot response must contain root".to_string(),
        )
    })?;
    let mut nodes = 0_usize;
    let mut node_ids = HashSet::new();
    validate_snapshot_node(
        root,
        *snapshot_mode,
        Some(response_window_id),
        false,
        0,
        &mut nodes,
        &mut node_ids,
    )
}

fn validate_snapshot_node(
    value: &Value,
    snapshot_mode: SnapshotMode,
    expected_window_id: Option<i32>,
    password_ancestor: bool,
    depth: usize,
    nodes: &mut usize,
    node_ids: &mut HashSet<String>,
) -> Result<()> {
    if depth > MAX_SNAPSHOT_TREE_DEPTH || *nodes >= MAX_SNAPSHOT_NODES {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot tree exceeds its structural bound".to_string(),
        ));
    }
    *nodes += 1;
    let object = value.as_object().ok_or_else(|| {
        DirectToolError::BackendFailed("Accessibility snapshot node must be an object".to_string())
    })?;
    const NODE_FIELDS: [&str; 17] = [
        "node_id",
        "window_id",
        "class_name",
        "package",
        "view_id",
        "text",
        "content_description",
        "clickable",
        "editable",
        "scrollable",
        "enabled",
        "focused",
        "selected",
        "password",
        "bounds",
        "actions",
        "children",
    ];
    if object.len() != NODE_FIELDS.len()
        || NODE_FIELDS.iter().any(|field| !object.contains_key(*field))
    {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot node fields are not closed".to_string(),
        ));
    }
    let string = |field: &str| {
        object.get(field).and_then(Value::as_str).ok_or_else(|| {
            DirectToolError::BackendFailed(format!(
                "Accessibility snapshot node {field} must be a string"
            ))
        })
    };
    let node_id = string("node_id")?;
    if !valid_node_id_shape(node_id) || !node_ids.insert(node_id.to_string()) {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot node_id is malformed or duplicated".to_string(),
        ));
    }
    for field in [
        "class_name",
        "package",
        "view_id",
        "text",
        "content_description",
    ] {
        if string(field)?.chars().count() > MAX_SNAPSHOT_STRING_CHARS {
            return Err(DirectToolError::BackendFailed(format!(
                "Accessibility snapshot node {field} exceeds 512 characters"
            )));
        }
    }
    let text = string("text")?;
    let content_description = string("content_description")?;
    let window_id = object
        .get("window_id")
        .and_then(Value::as_i64)
        .filter(|window_id| i32::try_from(*window_id).is_ok())
        .ok_or_else(|| {
            DirectToolError::BackendFailed(
                "Accessibility snapshot node window_id must be a signed 32-bit integer".to_string(),
            )
        })?;
    if expected_window_id.is_some_and(|expected| i64::from(expected) != window_id) {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot node escaped the requested window".to_string(),
        ));
    }
    for field in [
        "clickable",
        "editable",
        "scrollable",
        "enabled",
        "focused",
        "selected",
        "password",
    ] {
        if object.get(field).and_then(Value::as_bool).is_none() {
            return Err(DirectToolError::BackendFailed(format!(
                "Accessibility snapshot node {field} must be a boolean"
            )));
        }
    }
    let password = object["password"].as_bool().expect("validated boolean");
    let redact_subtree = password_ancestor || password;
    if (snapshot_mode == SnapshotMode::MetadataOnly || redact_subtree)
        && (!text.is_empty() || !content_description.is_empty())
    {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot leaked text outside the requested privacy mode".to_string(),
        ));
    }
    let bounds = object["bounds"].as_object().filter(|bounds| {
        bounds.len() == 4
            && ["left", "top", "right", "bottom"].iter().all(|field| {
                bounds
                    .get(*field)
                    .and_then(Value::as_i64)
                    .is_some_and(|value| i32::try_from(value).is_ok())
            })
    });
    let Some(bounds) = bounds else {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot bounds must be a closed signed 32-bit rectangle".to_string(),
        ));
    };
    if bounds["right"].as_i64() < bounds["left"].as_i64()
        || bounds["bottom"].as_i64() < bounds["top"].as_i64()
    {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot bounds are inverted".to_string(),
        ));
    }
    let actions = object["actions"].as_array().ok_or_else(|| {
        DirectToolError::BackendFailed(
            "Accessibility snapshot actions must be an array".to_string(),
        )
    })?;
    if actions.len() > 3
        || actions
            .iter()
            .any(|action| !matches!(action.as_str(), Some("click" | "set_text" | "scroll")))
        || actions
            .iter()
            .enumerate()
            .any(|(index, action)| actions[..index].iter().any(|previous| previous == action))
    {
        return Err(DirectToolError::BackendFailed(
            "Accessibility snapshot actions are not closed and unique".to_string(),
        ));
    }
    let children = object["children"].as_array().ok_or_else(|| {
        DirectToolError::BackendFailed(
            "Accessibility snapshot children must be an array".to_string(),
        )
    })?;
    for child in children {
        validate_snapshot_node(
            child,
            snapshot_mode,
            expected_window_id,
            redact_subtree,
            depth + 1,
            nodes,
            node_ids,
        )?;
    }
    Ok(())
}

fn guard_denial(request: &AccessibilityRequest, evidence: GuardEvidence) -> Value {
    let mut response = json!({
        "protocol": PROTOCOL,
        "request_id": request.request_id(),
        "ok": false,
        "error": "operation_denied",
        "risk_guard": evidence,
    });
    if let AccessibilityRequest::Snapshot { snapshot_mode, .. } = request {
        response["action"] = Value::String("snapshot".to_string());
        response["snapshot_mode"] = Value::String(snapshot_mode.as_str().to_string());
    }
    response
}

pub fn validate(request: &AccessibilityRequest) -> Result<()> {
    if request.protocol() != PROTOCOL {
        return Err(DirectToolError::InvalidRequest(format!(
            "Accessibility protocol must be {PROTOCOL}"
        )));
    }
    if !valid_request_id(request.request_id()) {
        return Err(DirectToolError::InvalidRequest(
            "invalid Accessibility request_id".to_string(),
        ));
    }
    match request {
        AccessibilityRequest::Snapshot { window_id, .. } => {
            if window_id.is_some_and(|window_id| window_id < 0) {
                return Err(DirectToolError::InvalidRequest(
                    "window_id must be non-negative when supplied".to_string(),
                ));
            }
        }
        AccessibilityRequest::Click { node_id, .. }
        | AccessibilityRequest::SetText { node_id, .. }
        | AccessibilityRequest::Scroll { node_id, .. } => validate_node_id(node_id)?,
        AccessibilityRequest::GlobalAction { .. } => {}
        AccessibilityRequest::Gesture {
            points,
            duration_ms,
            ..
        } => validate_gesture(points, *duration_ms)?,
        AccessibilityRequest::Batch { actions, .. } => validate_batch(actions)?,
    }
    if let AccessibilityRequest::SetText { text, .. } = request {
        validate_text(text)?;
    }
    Ok(())
}

pub fn validate_semantic(request: &AccessibilitySemanticRequest) -> Result<()> {
    validate(&request.to_backend_request(SEMANTIC_PENDING_REQUEST_ID.to_string()))
}

fn validate_batch(actions: &[AccessibilityBatchAction]) -> Result<()> {
    if actions.is_empty() || actions.len() > MAX_BATCH_ACTIONS {
        return Err(DirectToolError::InvalidRequest(format!(
            "batch must contain 1..={MAX_BATCH_ACTIONS} actions"
        )));
    }
    let mut cumulative_gesture_ms = 0_u64;
    for action in actions {
        match action {
            AccessibilityBatchAction::Click { node_id }
            | AccessibilityBatchAction::SetText { node_id, .. }
            | AccessibilityBatchAction::Scroll { node_id, .. } => validate_node_id(node_id)?,
            AccessibilityBatchAction::GlobalAction { .. } => {}
            AccessibilityBatchAction::Gesture {
                points,
                duration_ms,
            } => {
                validate_gesture(points, *duration_ms)?;
                cumulative_gesture_ms = cumulative_gesture_ms
                    .checked_add(*duration_ms)
                    .ok_or_else(|| {
                        DirectToolError::InvalidRequest(
                            "batch gesture duration overflow".to_string(),
                        )
                    })?;
            }
        }
        if let AccessibilityBatchAction::SetText { text, .. } = action {
            validate_text(text)?;
        }
    }
    if cumulative_gesture_ms > MAX_BATCH_GESTURE_DURATION_MS {
        return Err(DirectToolError::InvalidRequest(format!(
            "batch gesture duration exceeds {MAX_BATCH_GESTURE_DURATION_MS} ms"
        )));
    }
    Ok(())
}

fn validate_node_id(node_id: &str) -> Result<()> {
    if !valid_node_id_shape(node_id) {
        return Err(DirectToolError::InvalidRequest(
            "invalid accessibility node id".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn valid_node_id_shape(node_id: &str) -> bool {
    !node_id.is_empty()
        && node_id.len() <= MAX_NODE_ID_CHARS
        && node_id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn validate_text(text: &str) -> Result<()> {
    // Android's canonical backend and the Codex procedural validator both
    // bound JavaScript/Java String length, i.e. UTF-16 code units. Counting
    // UTF-8 bytes here would reject ordinary multibyte text that the wire
    // contract accepts; counting Unicode scalars would undercount astral
    // characters relative to the backend.
    if text.encode_utf16().count() > MAX_TEXT_UTF16_CODE_UNITS {
        return Err(DirectToolError::InvalidRequest(
            "text is too large".to_string(),
        ));
    }
    Ok(())
}

fn validate_gesture(points: &[GesturePoint], duration_ms: u64) -> Result<()> {
    if points.is_empty()
        || points.len() > 128
        || duration_ms == 0
        || duration_ms > MAX_GESTURE_DURATION_MS
        || points.first().is_none_or(|point| point.at_ms != 0)
    {
        return Err(DirectToolError::InvalidRequest(
            "invalid gesture shape or duration".to_string(),
        ));
    }
    let mut previous = None;
    for point in points {
        if !point.x.is_finite()
            || !point.y.is_finite()
            || point.x < 0.0
            || point.y < 0.0
            || point.x > MAX_GESTURE_COORDINATE
            || point.y > MAX_GESTURE_COORDINATE
            || point.at_ms > duration_ms
            || previous.is_some_and(|previous| point.at_ms <= previous)
        {
            return Err(DirectToolError::InvalidRequest(
                "gesture points must be finite, bounded, ordered, and within duration".to_string(),
            ));
        }
        previous = Some(point.at_ms);
    }
    Ok(())
}

pub fn mcp_tool() -> McpTool {
    let node_id = json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_NODE_ID_CHARS,
        "pattern": NODE_ID_PATTERN
    });
    let direction = json!({
        "type": "string",
        "enum": ["forward", "backward", "up", "down", "left", "right"]
    });
    let global_action = json!({
        "type": "string",
        "enum": [
            "back", "home", "recents", "notifications", "quick_settings",
            "power_dialog", "lock_screen", "take_screenshot"
        ]
    });
    let snapshot_mode = json!({
        "type": "string",
        "enum": ["metadata_only", "full_text"]
    });
    let points = json!({
        "type": "array",
        "minItems": 1,
        "maxItems": 128,
        "items": {
            "type": "object",
            "required": ["x", "y", "at_ms"],
            "properties": {
                "x": {"type": "number", "minimum": 0, "maximum": MAX_GESTURE_COORDINATE},
                "y": {"type": "number", "minimum": 0, "maximum": MAX_GESTURE_COORDINATE},
                "at_ms": {"type": "integer", "minimum": 0, "maximum": MAX_GESTURE_DURATION_MS}
            },
            "additionalProperties": false
        }
    });
    let batch_action_schema = json!({
        "oneOf": [
            {
                "type": "object",
                "required": ["action", "node_id"],
                "properties": {"action": {"const": "click"}, "node_id": node_id},
                "additionalProperties": false
            },
            {
                "type": "object",
                "required": ["action", "node_id", "text"],
                "properties": {
                    "action": {"const": "set_text"},
                    "node_id": node_id,
                    "text": {"type": "string", "maxLength": 16384}
                },
                "additionalProperties": false
            },
            {
                "type": "object",
                "required": ["action", "node_id", "direction"],
                "properties": {
                    "action": {"const": "scroll"},
                    "node_id": node_id,
                    "direction": direction
                },
                "additionalProperties": false
            },
            {
                "type": "object",
                "required": ["action", "global_action"],
                "properties": {
                    "action": {"const": "global_action"},
                    "global_action": global_action
                },
                "additionalProperties": false
            },
            {
                "type": "object",
                "required": ["action", "points", "duration_ms"],
                "properties": {
                    "action": {"const": "gesture"},
                    "points": points,
                    "duration_ms": {
                        "type": "integer", "minimum": 1,
                        "maximum": MAX_GESTURE_DURATION_MS
                    }
                },
                "additionalProperties": false
            }
        ]
    });
    McpTool {
        name: MCP_TOOL_NAME,
        description: "Request one bounded Trillionnium Accessibility action.",
        input_schema: json!({
            "oneOf": [
                {
                    "type": "object",
                    "required": ["action", "snapshot_mode"],
                    "properties": {
                        "action": {"const": "snapshot"},
                        "window_id": {
                            "type": ["integer", "null"],
                            "minimum": 0,
                            "maximum": i32::MAX
                        },
                        "snapshot_mode": snapshot_mode
                    },
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "required": ["action", "node_id"],
                    "properties": {
                        "action": {"const": "click"}, "node_id": node_id
                    },
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "required": ["action", "node_id", "text"],
                    "properties": {
                        "action": {"const": "set_text"},
                        "node_id": node_id,
                        "text": {"type": "string", "maxLength": 16384}
                    },
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "required": ["action", "node_id", "direction"],
                    "properties": {
                        "action": {"const": "scroll"},
                        "node_id": node_id,
                        "direction": direction
                    },
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "required": ["action", "global_action"],
                    "properties": {
                        "action": {"const": "global_action"},
                        "global_action": global_action
                    },
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "required": ["action", "points", "duration_ms"],
                    "properties": {
                        "action": {"const": "gesture"},
                        "points": points,
                        "duration_ms": {
                            "type": "integer", "minimum": 1,
                            "maximum": MAX_GESTURE_DURATION_MS
                        }
                    },
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "required": ["action", "actions"],
                    "properties": {
                        "action": {"const": "batch"},
                        "actions": {
                            "type": "array", "minItems": 1,
                            "maxItems": MAX_BATCH_ACTIONS,
                            "items": batch_action_schema
                        }
                    },
                    "additionalProperties": false
                }
            ]
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::thread;

    use super::*;

    const JOURNAL_ATTEMPT_ID: &str =
        "attempt:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    struct FixedAuthor(&'static str);

    impl BackendRequestIdentityAuthor for FixedAuthor {
        fn author_backend_request_id(
            &mut self,
            adapter: &'static str,
            semantic_request: &[u8],
        ) -> Result<String> {
            assert_eq!(adapter, "accessibility");
            assert!(
                !semantic_request
                    .windows(8)
                    .any(|bytes| bytes == b"protocol")
            );
            assert!(
                !semantic_request
                    .windows(10)
                    .any(|bytes| bytes == b"request_id")
            );
            Ok(self.0.to_string())
        }
    }

    fn journal(path: &Path) -> crate::operation_journal::OperationJournal {
        crate::operation_journal::OperationJournal::open(
            path,
            "codex",
            "accessibility",
            "inv-accessibility-live-1",
            JOURNAL_ATTEMPT_ID,
        )
        .unwrap()
    }

    fn point(at_ms: u64) -> GesturePoint {
        GesturePoint {
            x: 10.0,
            y: 20.0,
            at_ms,
        }
    }

    fn snapshot() -> AccessibilityRequest {
        AccessibilityRequest::Snapshot {
            protocol: PROTOCOL.to_string(),
            request_id: "req-accessibility-1".to_string(),
            window_id: None,
            snapshot_mode: SnapshotMode::MetadataOnly,
        }
    }

    fn snapshot_node(
        node_id: &str,
        text: &str,
        content_description: &str,
        password: bool,
    ) -> Value {
        json!({
            "node_id": node_id,
            "window_id": 1,
            "class_name": "android.widget.FrameLayout",
            "package": "com.example",
            "view_id": "root",
            "text": text,
            "content_description": content_description,
            "clickable": true,
            "editable": false,
            "scrollable": false,
            "enabled": true,
            "focused": false,
            "selected": false,
            "password": password,
            "bounds": {"left": 0, "top": 0, "right": 100, "bottom": 200},
            "actions": ["click"],
            "children": []
        })
    }

    fn successful_snapshot_response() -> Value {
        json!({
            "protocol": PROTOCOL,
            "request_id": "req-accessibility-1",
            "action": "snapshot",
            "snapshot_mode": "metadata_only",
            "ok": true,
            "backend": "accessibility",
            "idempotency_capacity_entries_per_peer": 128,
            "idempotency_capacity_reserved_bytes_per_peer": 48 * 1024 * 1024,
            "idempotency_reclamation_status":
                "inactive_backend_foundation_requires_trusted_adapter_journal_v1",
            "generation": 1,
            "window_id": 1,
            "truncated": false,
            "root": snapshot_node("node-root", "", "", false),
            "replay_scope": "read_only_resampled",
        })
    }

    fn failed_snapshot_response(error: &str) -> Value {
        json!({
            "protocol": PROTOCOL,
            "request_id": "req-accessibility-1",
            "ok": false,
            "backend": "accessibility",
            "idempotency_capacity_entries_per_peer": 128,
            "idempotency_capacity_reserved_bytes_per_peer": 48 * 1024 * 1024,
            "idempotency_reclamation_status":
                "inactive_backend_foundation_requires_trusted_adapter_journal_v1",
            "error": error,
            "action": "snapshot",
            "snapshot_mode": "metadata_only",
            "replay_scope": "read_only_resampled",
        })
    }

    fn batch(actions: Vec<AccessibilityBatchAction>) -> AccessibilityRequest {
        AccessibilityRequest::Batch {
            protocol: PROTOCOL.to_string(),
            request_id: "req-accessibility-1".to_string(),
            actions,
        }
    }

    fn gesture(points: Vec<GesturePoint>, duration_ms: u64) -> AccessibilityRequest {
        AccessibilityRequest::Gesture {
            protocol: PROTOCOL.to_string(),
            request_id: "req-accessibility-1".to_string(),
            points,
            duration_ms,
        }
    }

    fn call_with_raw_backend_response(response: Vec<u8>) -> Result<Value> {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("accessibility-response.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            stream.write_all(&response).unwrap();
        });
        let result = call_as(&socket, &snapshot(), AgentIdentity::Codex);
        server.join().unwrap();
        result
    }

    #[test]
    fn only_mutations_consume_the_android_operation_sequence() {
        assert!(!snapshot().requires_durable_operation_sequence());

        let effects = [
            AccessibilityRequest::Click {
                protocol: PROTOCOL.to_string(),
                request_id: "req-click".to_string(),
                node_id: "node".to_string(),
            },
            AccessibilityRequest::SetText {
                protocol: PROTOCOL.to_string(),
                request_id: "req-set-text".to_string(),
                node_id: "node".to_string(),
                text: "value".to_string(),
            },
            AccessibilityRequest::Scroll {
                protocol: PROTOCOL.to_string(),
                request_id: "req-scroll".to_string(),
                node_id: "node".to_string(),
                direction: ScrollDirection::Forward,
            },
            AccessibilityRequest::GlobalAction {
                protocol: PROTOCOL.to_string(),
                request_id: "req-global".to_string(),
                global_action: GlobalAction::Back,
            },
            gesture(vec![point(0), point(1)], 1),
            batch(vec![AccessibilityBatchAction::Click {
                node_id: "node".to_string(),
            }]),
        ];

        for request in effects {
            assert!(request.requires_durable_operation_sequence());
        }
    }

    #[test]
    fn supports_typed_bounded_ui_batches() {
        validate(&batch(vec![AccessibilityBatchAction::Click {
            node_id: "n1".to_string(),
        }]))
        .unwrap();
        for node_id in ["bad id", "节点", "bad\\id", ""] {
            assert!(
                validate(&batch(vec![AccessibilityBatchAction::Click {
                    node_id: node_id.to_string(),
                }]))
                .is_err(),
                "accepted out-of-domain node_id {node_id:?}"
            );
        }
        assert!(validate(&batch(vec![])).is_err());
        assert!(
            serde_json::from_value::<AccessibilityRequest>(json!({
                "protocol": PROTOCOL,
                "request_id": "req-accessibility-1",
                "action": "batch",
                "actions": [{"action": "batch", "actions": []}]
            }))
            .is_err()
        );
    }

    #[test]
    fn text_limit_matches_android_utf16_code_units() {
        let assert_boundary = |text: String, expected_valid: bool| {
            let request = AccessibilityRequest::SetText {
                protocol: PROTOCOL.to_string(),
                request_id: "req-text-boundary".to_string(),
                node_id: "node-1".to_string(),
                text: text.clone(),
            };
            let batch_request = batch(vec![AccessibilityBatchAction::SetText {
                node_id: "node-1".to_string(),
                text,
            }]);
            assert_eq!(validate(&request).is_ok(), expected_valid);
            assert_eq!(validate(&batch_request).is_ok(), expected_valid);
        };

        // A BMP character is one UTF-16 code unit even though it occupies
        // three UTF-8 bytes. An astral character occupies two code units.
        assert_boundary("雪".repeat(MAX_TEXT_UTF16_CODE_UNITS), true);
        assert_boundary("雪".repeat(MAX_TEXT_UTF16_CODE_UNITS + 1), false);
        assert_boundary("😀".repeat(MAX_TEXT_UTF16_CODE_UNITS / 2), true);
        assert_boundary("😀".repeat(MAX_TEXT_UTF16_CODE_UNITS / 2 + 1), false);
    }

    #[test]
    fn rejects_bad_gesture_timing_and_cumulative_duration() {
        assert!(validate(&gesture(vec![point(1)], 100)).is_err());
        assert!(validate(&gesture(vec![point(0), point(0)], 100)).is_err());
        assert!(
            validate(&batch(vec![
                AccessibilityBatchAction::Gesture {
                    points: vec![point(0)],
                    duration_ms: 40_000,
                },
                AccessibilityBatchAction::Gesture {
                    points: vec![point(0)],
                    duration_ms: 40_000,
                },
            ]))
            .is_err()
        );
    }

    #[test]
    fn full_text_snapshot_is_denied_before_backend_and_mode_is_risk_bound() {
        let request = AccessibilityRequest::Snapshot {
            protocol: PROTOCOL.to_string(),
            request_id: "req-full-text-denied".to_string(),
            window_id: None,
            snapshot_mode: SnapshotMode::FullText,
        };
        let response = call_as(
            Path::new("/definitely/missing/accessibility.sock"),
            &request,
            AgentIdentity::Codex,
        )
        .expect("risk denial is a structured no-effect outcome");
        assert_eq!(response["protocol"], PROTOCOL);
        assert_eq!(response["request_id"], "req-full-text-denied");
        assert_eq!(response["snapshot_mode"], "full_text");
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"], "operation_denied");
        assert_eq!(response["risk_guard"]["decision"], "deny");
        assert_eq!(response["risk_guard"]["risk_tier"], "sensitive_effect");

        let metadata =
            ProductRiskGuard.assess_accessibility_request(AgentIdentity::Codex, &snapshot());
        assert_eq!(metadata.risk_tier, crate::risk_guard::RiskTier::Observe);
        assert_ne!(
            response["risk_guard"]["action_binding_sha256"],
            metadata.action_binding_sha256
        );
    }

    #[test]
    fn snapshot_backend_must_echo_the_exact_requested_privacy_mode() {
        for response in [
            b"{\"protocol\":\"org.trillionnium.agent-accessibility.v2\",\"request_id\":\"req-accessibility-1\",\"ok\":true,\"nodes\":[]}\n".to_vec(),
            b"{\"protocol\":\"org.trillionnium.agent-accessibility.v2\",\"request_id\":\"req-accessibility-1\",\"action\":\"snapshot\",\"snapshot_mode\":\"full_text\",\"ok\":true,\"root\":{}}\n".to_vec(),
            b"{\"protocol\":\"org.trillionnium.agent-accessibility.v2\",\"request_id\":\"req-accessibility-1\",\"action\":\"snapshot\",\"snapshot_mode\":\"unknown\",\"ok\":true,\"root\":{}}\n".to_vec(),
        ] {
            let error = call_with_raw_backend_response(response).unwrap_err();
            assert!(error
                .to_string()
                .contains("action/snapshot_mode binding mismatch"));
        }
    }

    #[test]
    fn metadata_only_snapshot_rejects_recursive_text_leakage_and_open_nodes() {
        let mut leaked = successful_snapshot_response();
        leaked["root"]["children"] = json!([snapshot_node("node-child", "SECRET", "", false)]);
        let mut bytes = serde_json::to_vec(&leaked).unwrap();
        bytes.push(b'\n');
        let error = call_with_raw_backend_response(bytes).unwrap_err();
        assert!(error.to_string().contains("leaked text"));

        let mut open = successful_snapshot_response();
        open["root"]["unknown"] = json!(true);
        let mut bytes = serde_json::to_vec(&open).unwrap();
        bytes.push(b'\n');
        let error = call_with_raw_backend_response(bytes).unwrap_err();
        assert!(error.to_string().contains("fields are not closed"));

        let mut top_level_leak = successful_snapshot_response();
        top_level_leak["debug_text"] = json!("SECRET");
        let mut bytes = serde_json::to_vec(&top_level_leak).unwrap();
        bytes.push(b'\n');
        let error = call_with_raw_backend_response(bytes).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("successful snapshot response fields are not closed")
        );

        let mut duplicate = successful_snapshot_response();
        duplicate["root"]["children"] = json!([snapshot_node("node-root", "", "", false)]);
        let mut bytes = serde_json::to_vec(&duplicate).unwrap();
        bytes.push(b'\n');
        let error = call_with_raw_backend_response(bytes).unwrap_err();
        assert!(error.to_string().contains("malformed or duplicated"));

        let mut cross_window = successful_snapshot_response();
        cross_window["root"]["children"] = json!([snapshot_node("node-child", "", "", false)]);
        cross_window["root"]["children"][0]["window_id"] = json!(2);
        let mut bytes = serde_json::to_vec(&cross_window).unwrap();
        bytes.push(b'\n');
        let error = call_with_raw_backend_response(bytes).unwrap_err();
        assert!(error.to_string().contains("escaped the requested window"));

        let mut forged_guard = successful_snapshot_response();
        forged_guard["risk_guard"] = json!({"decision": "allow"});
        let mut bytes = serde_json::to_vec(&forged_guard).unwrap();
        bytes.push(b'\n');
        let error = call_with_raw_backend_response(bytes).unwrap_err();
        assert!(error.to_string().contains("reserved risk_guard"));

        for field in [
            crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD,
            crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD,
        ] {
            let mut forged_digest = successful_snapshot_response();
            forged_digest[field] = json!("a".repeat(64));
            let mut bytes = serde_json::to_vec(&forged_digest).unwrap();
            bytes.push(b'\n');
            let error = call_with_raw_backend_response(bytes).unwrap_err();
            assert!(error.to_string().contains(&format!("reserved {field}")));
        }
    }

    #[test]
    fn full_text_validator_redacts_password_subtrees() {
        let mut ordinary = snapshot_node("node-root", "visible", "description", false);
        let mut nodes = 0;
        let mut node_ids = HashSet::new();
        validate_snapshot_node(
            &ordinary,
            SnapshotMode::FullText,
            None,
            false,
            0,
            &mut nodes,
            &mut node_ids,
        )
        .unwrap();

        ordinary["password"] = json!(true);
        ordinary["text"] = json!("");
        ordinary["content_description"] = json!("");
        ordinary["children"] = json!([snapshot_node("node-child", "LEAK", "", false)]);
        let mut nodes = 0;
        let mut node_ids = HashSet::new();
        let error = validate_snapshot_node(
            &ordinary,
            SnapshotMode::FullText,
            None,
            false,
            0,
            &mut nodes,
            &mut node_ids,
        )
        .unwrap_err();
        assert!(error.to_string().contains("leaked text"));
    }

    #[test]
    fn snapshot_string_limit_counts_unicode_scalars_not_utf8_bytes() {
        for (value, expected_valid) in [
            ("雪".repeat(MAX_SNAPSHOT_STRING_CHARS), true),
            ("雪".repeat(MAX_SNAPSHOT_STRING_CHARS + 1), false),
            ("😀".repeat(MAX_SNAPSHOT_STRING_CHARS), true),
            ("😀".repeat(MAX_SNAPSHOT_STRING_CHARS + 1), false),
        ] {
            let mut node = snapshot_node("node-root", "", "", false);
            node["class_name"] = json!(value);
            let mut nodes = 0;
            let mut node_ids = HashSet::new();
            assert_eq!(
                validate_snapshot_node(
                    &node,
                    SnapshotMode::MetadataOnly,
                    None,
                    false,
                    0,
                    &mut nodes,
                    &mut node_ids,
                )
                .is_ok(),
                expected_valid
            );
        }
    }

    #[test]
    fn direct_socket_round_trip_has_no_dispatcher() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("accessibility.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let received: AccessibilityRequest = serde_json::from_str(&line).unwrap();
            assert_eq!(received, snapshot());
            let mut stream = stream;
            serde_json::to_writer(&mut stream, &successful_snapshot_response()).unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let response = call(&socket, &snapshot()).unwrap();
        assert_eq!(response, successful_snapshot_response());
        server.join().unwrap();
        fs::remove_file(socket).ok();
    }

    #[test]
    fn backend_ok_false_is_a_structured_accessibility_outcome() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("accessibility-failed.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            serde_json::to_writer(
                &mut stream,
                &failed_snapshot_response("request_outcome_indeterminate"),
            )
            .unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let response = call(&socket, &snapshot()).unwrap();
        assert_eq!(
            response,
            failed_snapshot_response("request_outcome_indeterminate")
        );
        server.join().unwrap();
    }

    #[test]
    fn trusted_accessibility_result_is_durable_and_exactly_replayable() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("accessibility-journaled.sock");
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
            let mut response = successful_snapshot_response();
            response["request_id"] = Value::String(request_id);
            serde_json::to_writer(&mut stream, &response).unwrap();
            stream.write_all(b"\n").unwrap();
        });

        let journal_path = directory.path().join("operations.json");
        let mut first_journal = journal(&journal_path);
        let mut request = snapshot();
        let first =
            call_journaled(&socket, &request, AgentIdentity::Codex, &mut first_journal).unwrap();
        let first_raw_digest = first[crate::OS_RAW_BACKEND_RESULT_SHA256_FIELD]
            .as_str()
            .unwrap()
            .to_string();
        let first_semantic_digest = first[crate::OS_CANONICAL_SEMANTIC_RESULT_SHA256_FIELD]
            .as_str()
            .unwrap()
            .to_string();
        assert_ne!(first_raw_digest, first_semantic_digest);
        assert_eq!(
            crate::semantic_result::canonical_semantic_result_sha256(&first).unwrap(),
            first_semantic_digest
        );
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

        let mut journal = journal(&journal_path);
        if let AccessibilityRequest::Snapshot { request_id, .. } = &mut request {
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
        assert_ne!(first_backend_id, "req-accessibility-1");
        assert_eq!(first, second);
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
        let canonical =
            crate::canonical_operation::accessibility_request(AgentIdentity::Codex, &request)
                .unwrap();
        let crate::operation_journal::RecoveryDecision::ResultRecorded(evidence) =
            journal.recover_effect(&canonical).unwrap()
        else {
            panic!("terminal Accessibility result did not recover as evidence");
        };
        assert_eq!(
            evidence.raw_backend_result_sha256.to_hex(),
            first_raw_digest
        );
        assert_eq!(
            evidence.backend_result_sha256.to_hex(),
            first_semantic_digest
        );
        assert_eq!(
            evidence.to_outer_evidence().unwrap().backend_result_sha256,
            first_semantic_digest
        );
    }

    #[test]
    fn malformed_snapshot_is_durably_indeterminate_before_error_release() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("accessibility-indeterminate.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            let response = json!({
                "protocol": PROTOCOL,
                "request_id": request["request_id"],
                "ok": true,
                "action": "snapshot",
                "snapshot_mode": "metadata_only"
            });
            serde_json::to_writer(&mut stream, &response).unwrap();
            stream.write_all(b"\n").unwrap();
        });

        let mut journal = journal(&directory.path().join("operations.json"));
        let error =
            call_journaled(&socket, &snapshot(), AgentIdentity::Codex, &mut journal).unwrap_err();
        server.join().unwrap();
        assert!(error.to_string().contains("backend/capacity foundation"));
        let recovery = journal.recovery_plan().unwrap().unwrap();
        assert!(matches!(
            recovery.operations[0].state,
            crate::operation_journal::RecoveryOperationState::ResultRecorded {
                outcome: crate::OperationOutcome::Indeterminate,
                ..
            }
        ));
    }

    #[test]
    fn rejects_more_than_one_backend_response_frame() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("accessibility-extra.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            stream
                .write_all(
                    b"{\"protocol\":\"org.trillionnium.agent-accessibility.v2\",\"request_id\":\"req-accessibility-1\",\"action\":\"snapshot\",\"snapshot_mode\":\"metadata_only\",\"ok\":true}\n{\"ok\":false}\n",
                )
                .unwrap();
        });
        let error = call(&socket, &snapshot()).unwrap_err();
        assert!(error.to_string().contains("more than one"));
        server.join().unwrap();
    }

    #[test]
    fn mcp_batch_schema_has_no_recursive_batch_variant() {
        let schema_text = serde_json::to_string(&mcp_tool().input_schema).unwrap();
        assert_eq!(schema_text.matches("\"const\":\"batch\"").count(), 1);
    }

    #[test]
    fn mcp_snapshot_schema_requires_closed_privacy_mode() {
        let schema = mcp_tool().input_schema;
        let schema_text = serde_json::to_string(&schema).unwrap();
        assert!(!schema_text.contains("protocol"));
        assert!(!schema_text.contains("request_id"));
        let snapshot = schema["oneOf"]
            .as_array()
            .unwrap()
            .iter()
            .find(|variant| variant["properties"]["action"]["const"] == "snapshot")
            .unwrap();
        assert!(
            snapshot["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|field| field == "snapshot_mode")
        );
        assert_eq!(
            snapshot["properties"]["snapshot_mode"]["enum"],
            json!(["metadata_only", "full_text"])
        );
        assert_eq!(
            snapshot["properties"]["window_id"]["maximum"],
            json!(i32::MAX)
        );
        assert_eq!(snapshot["additionalProperties"], false);
    }

    #[test]
    fn semantic_request_cannot_supply_envelope_and_os_authors_wire_identity() {
        let semantic = AccessibilitySemanticRequest::Snapshot {
            window_id: None,
            snapshot_mode: SnapshotMode::MetadataOnly,
        };
        let request =
            author_backend_request(&semantic, &mut FixedAuthor("os:semantic-fixed-2")).unwrap();
        assert_eq!(
            request,
            AccessibilityRequest::Snapshot {
                protocol: PROTOCOL.to_string(),
                request_id: "os:semantic-fixed-2".to_string(),
                window_id: None,
                snapshot_mode: SnapshotMode::MetadataOnly,
            }
        );
        for reserved in [
            json!({
                "action": "snapshot",
                "window_id": null,
                "snapshot_mode": "metadata_only",
                "protocol": PROTOCOL
            }),
            json!({
                "action": "snapshot",
                "window_id": null,
                "snapshot_mode": "metadata_only",
                "request_id": "model-id"
            }),
        ] {
            assert!(serde_json::from_value::<AccessibilitySemanticRequest>(reserved).is_err());
        }
    }

    #[test]
    fn serde_rejects_unknown_duplicate_and_trailing_request_material() {
        let valid = format!(
            "{{\"protocol\":\"{PROTOCOL}\",\"request_id\":\"req-1\",\"action\":\"snapshot\",\"window_id\":null,\"snapshot_mode\":\"metadata_only\"}}"
        );
        assert!(serde_json::from_str::<AccessibilityRequest>(&valid).is_ok());
        assert!(
            serde_json::from_str::<AccessibilityRequest>(
                &valid.replace("\"window_id\":null", "\"window_id\":null,\"unknown\":true")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<AccessibilityRequest>(&valid.replace(
                "\"request_id\":\"req-1\"",
                "\"request_id\":\"req-1\",\"request_id\":\"req-2\""
            ))
            .is_err()
        );
        assert!(serde_json::from_str::<AccessibilityRequest>(&format!("{valid}{{}}")).is_err());
    }
}
