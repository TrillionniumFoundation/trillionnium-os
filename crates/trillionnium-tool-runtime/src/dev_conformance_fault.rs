// SPDX-License-Identifier: MIT

//! Development-conformance-only post-commit response-loss hook.
//!
//! This module is compiled only with `dev-conformance-fault-hook`. Production
//! builds use the crate's empty default feature set, so they contain neither
//! the spec-file path nor any response-drop logic.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use trillionnium_os_types::{AgentExecutionBinding, sha256_bytes, sha256_json};

use crate::{GatewayPeerIdentity, Result, ToolRuntimeError, authority_receipt};

pub const DEFAULT_SPEC_PATH: &str = "/run/trillionnium/dev-conformance/fault-hook.json";
pub const SPEC_SCHEMA: &str = "org.trillionnium.dev-conformance.gateway-response-loss.v1";
pub const AUDIT_SCHEMA: &str = "org.trillionnium.dev-conformance.gateway-response-loss-audit.v1";
pub const BUILD_MARKER: &str = "TRILLIONNIUM_DEVELOPMENT_RESPONSE_LOSS_FAULT_HOOK_V1";
const FAULT_NAME: &str = "drop_verified_post_commit_undo_response_once";
const NOTIFICATION_TOOL: &str = "android.notification.post_bounded";
const NOTIFICATION_ACTION: &str = "notification_post_bounded";
const MAX_SPEC_BYTES: u64 = 128 * 1024;
const MAX_TTL_MS: u64 = 30_000;

static CLAIM_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevConformanceFaultSpec {
    pub schema: String,
    pub fault: String,
    pub run_id: String,
    pub fault_id: String,
    pub postboot_request_sha256: String,
    pub install_session_id: String,
    pub same_abi_run_started_at_unix_ms: u64,
    pub target_method: String,
    pub target_request_id: String,
    pub request_frame_sha256: String,
    pub expected_action: String,
    pub expected_source_receipt_id: Option<String>,
    pub execution_payload_sha256: String,
    pub execution_binding: AgentExecutionBinding,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultProbe {
    pub matched: bool,
    pub reason: &'static str,
    pub actual_receipt_id: Option<String>,
}

#[derive(Debug)]
pub(crate) struct ClaimedFault {
    pub spec: DevConformanceFaultSpec,
    pub consumed_spec_path: PathBuf,
    pub actual_receipt_id: String,
    pub first_response_sha256: String,
    first_peer: GatewayPeerIdentity,
    audit_completed: bool,
    failure_stage: &'static str,
}

impl Drop for ClaimedFault {
    fn drop(&mut self) {
        if !self.audit_completed {
            let _ = write_failure_audit(self, self.failure_stage);
        }
    }
}

impl ClaimedFault {
    pub(crate) fn set_failure_stage(&mut self, stage: &'static str) {
        self.failure_stage = stage;
    }
}

#[derive(Debug)]
pub(crate) struct CompletedFaultAudit<'a> {
    pub mutation_request_sha256: &'a str,
    pub mutation_denial_response_sha256: &'a str,
    pub retry_request_sha256: &'a str,
    pub retry_response_sha256: &'a str,
    pub authority_peer_pid: u32,
    pub authority_peer_uid: u32,
    pub authority_peer_gid: u32,
    pub authority_peer_selinux_domain: &'a str,
    pub completed_at_ms: u64,
}

fn denied(message: impl Into<String>) -> ToolRuntimeError {
    ToolRuntimeError::AndroidGatewayProtocol(format!(
        "dev conformance fault hook denied: {}",
        message.into()
    ))
}

pub(crate) fn configured_spec_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = std::env::var_os("TRILLIONNIUM_DEV_CONFORMANCE_FAULT_SPEC") {
        return PathBuf::from(path);
    }
    #[cfg(not(test))]
    let _ = BUILD_MARKER;
    PathBuf::from(DEFAULT_SPEC_PATH)
}

pub(crate) fn claim_matching_fault(
    path: &Path,
    request_frame: &Value,
    request_bytes: &[u8],
    verified_result: &Value,
    first_raw_response: &[u8],
    first_peer: &GatewayPeerIdentity,
    now_ms: u64,
) -> Result<Option<ClaimedFault>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {}
        Ok(_) => return Err(denied("spec path is not a regular file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(denied(format!("spec lstat failed: {error}"))),
    }
    let first_bytes = read_authorized_spec(path)?;
    let spec = parse_spec(&first_bytes)?;
    let probe = probe_spec(&spec, request_frame, request_bytes, verified_result, now_ms)?;
    if !probe.matched {
        return Ok(None);
    }
    let actual_receipt_id = probe
        .actual_receipt_id
        .ok_or_else(|| denied("matched probe omitted receipt identity"))?;

    let _claim = CLAIM_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| denied("claim lock poisoned"))?;
    let current_bytes = read_authorized_spec(path)?;
    if current_bytes != first_bytes {
        return Err(denied("spec changed during exact-match claim"));
    }
    let parent = path
        .parent()
        .ok_or_else(|| denied("spec has no parent directory"))?;
    let consumed_path = parent.join(format!("fault-hook.consumed.{}.json", spec.fault_id));
    rename_noreplace(path, &consumed_path)?;
    Ok(Some(ClaimedFault {
        spec,
        consumed_spec_path: consumed_path,
        actual_receipt_id,
        first_response_sha256: sha256_bytes(first_raw_response),
        first_peer: first_peer.clone(),
        audit_completed: false,
        failure_stage: "post_claim_unclassified_failure",
    }))
}

/// Pure matcher used by host negative probes. It never mutates or consumes a spec.
pub fn probe_spec(
    spec: &DevConformanceFaultSpec,
    request_frame: &Value,
    request_bytes: &[u8],
    verified_result: &Value,
    now_ms: u64,
) -> Result<FaultProbe> {
    validate_spec(spec)?;
    if now_ms < spec.issued_at_ms || now_ms >= spec.expires_at_ms {
        return Ok(no_match("fault_spec_outside_ttl"));
    }
    if sha256_bytes(request_bytes) != spec.request_frame_sha256 {
        return Ok(no_match("request_frame_sha256_mismatch"));
    }
    let request = request_frame
        .as_object()
        .ok_or_else(|| denied("candidate request is not an object"))?;
    if request.get("protocol").and_then(Value::as_str) != Some(crate::ANDROID_GATEWAY_PROTOCOL)
        || request.get("method").and_then(Value::as_str) != Some(&spec.target_method)
        || request.get("request_id").and_then(Value::as_str) != Some(&spec.target_request_id)
    {
        return Ok(no_match("request_protocol_method_or_id_mismatch"));
    }
    let binding: AgentExecutionBinding = serde_json::from_value(
        request
            .get("execution_binding")
            .cloned()
            .ok_or_else(|| denied("candidate execution binding missing"))?,
    )
    .map_err(|error| denied(format!("candidate execution binding invalid: {error}")))?;
    if binding != spec.execution_binding {
        return Ok(no_match("execution_binding_mismatch"));
    }
    if binding.tool_name != NOTIFICATION_TOOL {
        return Ok(no_match("target_tool_is_not_bounded_notification"));
    }
    let source = spec
        .expected_source_receipt_id
        .as_deref()
        .ok_or_else(|| denied("undo spec omitted source receipt"))?;
    if request.get("receipt_id").and_then(Value::as_str) != Some(source)
        || request
            .get("execution_payload_sha256")
            .and_then(Value::as_str)
            != Some(&spec.execution_payload_sha256)
    {
        return Ok(no_match("undo_source_receipt_or_payload_mismatch"));
    }

    let result = verified_result
        .as_object()
        .ok_or_else(|| denied("verified result is not an object"))?;
    let actual_receipt_id = result
        .get("receipt_id")
        .and_then(Value::as_str)
        .filter(|value| is_lower_sha256(value))
        .ok_or_else(|| denied("verified result receipt identity missing"))?;
    let receipt_text = result
        .get("receipt_json")
        .and_then(Value::as_str)
        .ok_or_else(|| denied("verified result receipt bytes missing"))?;
    let receipt = authority_receipt::parse_strict_json(receipt_text, "fault-hook receipt")?;
    let receipt = receipt
        .as_object()
        .ok_or_else(|| denied("fault-hook receipt is not an object"))?;
    if receipt.get("receipt_id").and_then(Value::as_str) != Some(actual_receipt_id)
        || receipt.get("request_id").and_then(Value::as_str) != Some(&spec.target_request_id)
        || receipt.get("action").and_then(Value::as_str) != Some(&spec.expected_action)
        || !receipt_matches_binding(receipt, &spec.execution_binding)
        || receipt.get("payload_sha256").and_then(Value::as_str)
            != Some(&spec.execution_payload_sha256)
        || receipt
            .get("postboot_request_sha256")
            .and_then(Value::as_str)
            != Some(&spec.postboot_request_sha256)
        || receipt.get("install_session_id").and_then(Value::as_str)
            != Some(&spec.install_session_id)
        || receipt.get("same_abi_run_id").and_then(Value::as_str) != Some(&spec.run_id)
        || receipt
            .get("same_abi_run_started_at_unix_ms")
            .and_then(Value::as_u64)
            != Some(spec.same_abi_run_started_at_unix_ms)
    {
        return Ok(no_match("post_commit_receipt_binding_mismatch"));
    }
    if receipt.get("decision").and_then(Value::as_str) != Some("PASS_BOUNDED_UNDO")
        || receipt.get("undo").and_then(Value::as_bool) != Some(true)
        || receipt.get("previous_receipt_id").and_then(Value::as_str) != Some(source)
    {
        return Ok(no_match("undo_receipt_chain_mismatch"));
    }
    Ok(FaultProbe {
        matched: true,
        reason: "exact_post_commit_match",
        actual_receipt_id: Some(actual_receipt_id.to_string()),
    })
}

pub(crate) fn agent_id_mutation_frame(
    claim: &ClaimedFault,
    request_frame: &Value,
) -> Result<(Value, Vec<u8>)> {
    let mut mutated = request_frame.clone();
    let binding = mutated
        .get_mut("execution_binding")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| denied("mutation candidate execution binding missing"))?;
    binding.insert(
        "agent_id".to_string(),
        Value::String(format!("fault-probe-agent-{}", claim.spec.run_id)),
    );
    let bytes = serde_json::to_vec(&mutated)
        .map_err(|error| denied(format!("mutation frame serialization failed: {error}")))?;
    Ok((mutated, bytes))
}

pub(crate) fn write_completed_audit(
    claim: &mut ClaimedFault,
    completed: &CompletedFaultAudit<'_>,
) -> Result<PathBuf> {
    if !is_lower_sha256(completed.mutation_request_sha256)
        || !is_lower_sha256(completed.mutation_denial_response_sha256)
        || completed.retry_request_sha256 != claim.spec.request_frame_sha256
        || completed.retry_response_sha256 != claim.first_response_sha256
        || completed.authority_peer_pid != claim.first_peer.pid
        || completed.authority_peer_uid != claim.first_peer.uid
        || completed.authority_peer_gid != claim.first_peer.gid
        || completed.authority_peer_selinux_domain != claim.first_peer.selinux_domain
    {
        return Err(denied(
            "completed audit facts do not prove exact request/response/peer replay",
        ));
    }
    let parent = claim
        .consumed_spec_path
        .parent()
        .ok_or_else(|| denied("consumed spec has no parent"))?;
    let path = parent.join(format!(
        "fault-hook.consumed.{}.audit.json",
        claim.spec.fault_id
    ));
    let execution_binding_sha256 = sha256_json(
        &serde_json::to_value(&claim.spec.execution_binding)
            .map_err(|error| denied(format!("audit binding serialization failed: {error}")))?,
    );
    let spec_sha256 = sha256_json(
        &serde_json::to_value(&claim.spec)
            .map_err(|error| denied(format!("audit spec serialization failed: {error}")))?,
    );
    let value = json!({
        "schema": AUDIT_SCHEMA,
        "build_marker": BUILD_MARKER,
        "decision": "PASS_EXACT_UNDO_RESPONSE_LOSS_RECOVERY",
        "run_id": claim.spec.run_id,
        "fault_id": claim.spec.fault_id,
        "fault": claim.spec.fault,
        "postboot_request_sha256": claim.spec.postboot_request_sha256,
        "install_session_id": claim.spec.install_session_id,
        "same_abi_run_started_at_unix_ms": claim.spec.same_abi_run_started_at_unix_ms,
        "target_method": claim.spec.target_method,
        "target_request_id": claim.spec.target_request_id,
        "tool_call_id": claim.spec.execution_binding.tool_call_id.0,
        "expected_action": claim.spec.expected_action,
        "expected_source_receipt_id": claim.spec.expected_source_receipt_id,
        "execution_payload_sha256": claim.spec.execution_payload_sha256,
        "execution_binding_sha256": execution_binding_sha256,
        "fault_spec_sha256": spec_sha256,
        "actual_receipt_id": claim.actual_receipt_id,
        "request_frame_sha256": claim.spec.request_frame_sha256,
        "first_response_sha256": claim.first_response_sha256,
        "mutation_field": "execution_binding.agent_id",
        "mutation_request_sha256": completed.mutation_request_sha256,
        "mutation_denial_response_sha256": completed.mutation_denial_response_sha256,
        "retry_request_sha256": completed.retry_request_sha256,
        "retry_response_sha256": completed.retry_response_sha256,
        "authority_peer_pid": claim.first_peer.pid,
        "authority_peer_uid": claim.first_peer.uid,
        "authority_peer_gid": claim.first_peer.gid,
        "authority_peer_selinux_domain": claim.first_peer.selinux_domain,
        "retry_authority_peer_pid": completed.authority_peer_pid,
        "retry_authority_peer_uid": completed.authority_peer_uid,
        "retry_authority_peer_gid": completed.authority_peer_gid,
        "retry_authority_peer_selinux_domain": completed.authority_peer_selinux_domain,
        "completed_at_ms": completed.completed_at_ms,
        "one_shot_consumed": true,
        "mutation_denied_before_original_retry": true,
        "request_retry_byte_identical": completed.retry_request_sha256
            == claim.spec.request_frame_sha256,
        "response_retry_byte_identical": completed.retry_response_sha256
            == claim.first_response_sha256,
        "authority_replay_response_byte_identical": completed.retry_response_sha256
            == claim.first_response_sha256,
        "external_effect_count_observed_by_hook": Value::Null,
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| denied(format!("audit create-new failed: {error}")))?;
    let mut encoded = serde_json::to_vec_pretty(&value)
        .map_err(|error| denied(format!("audit serialization failed: {error}")))?;
    encoded.push(b'\n');
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|error| denied(format!("audit durable write failed: {error}")))?;
    sync_parent(parent)?;
    claim.audit_completed = true;
    Ok(path)
}

fn write_failure_audit(claim: &ClaimedFault, reason: &str) -> Result<PathBuf> {
    let parent = claim
        .consumed_spec_path
        .parent()
        .ok_or_else(|| denied("consumed spec has no parent"))?;
    let path = parent.join(format!(
        "fault-hook.consumed.{}.failure.json",
        claim.spec.fault_id
    ));
    let execution_binding_sha256 = sha256_json(
        &serde_json::to_value(&claim.spec.execution_binding).map_err(|error| {
            denied(format!(
                "failure audit binding serialization failed: {error}"
            ))
        })?,
    );
    let spec_sha256 =
        sha256_json(&serde_json::to_value(&claim.spec).map_err(|error| {
            denied(format!("failure audit spec serialization failed: {error}"))
        })?);
    let value = json!({
        "schema": AUDIT_SCHEMA,
        "build_marker": BUILD_MARKER,
        "decision": "HOLD_UNDO_RESPONSE_LOSS_RECOVERY_FAILED_CLOSED",
        "run_id": claim.spec.run_id,
        "fault_id": claim.spec.fault_id,
        "fault": claim.spec.fault,
        "postboot_request_sha256": claim.spec.postboot_request_sha256,
        "install_session_id": claim.spec.install_session_id,
        "same_abi_run_started_at_unix_ms": claim.spec.same_abi_run_started_at_unix_ms,
        "target_method": claim.spec.target_method,
        "target_request_id": claim.spec.target_request_id,
        "tool_call_id": claim.spec.execution_binding.tool_call_id.0,
        "expected_action": claim.spec.expected_action,
        "expected_source_receipt_id": claim.spec.expected_source_receipt_id,
        "execution_payload_sha256": claim.spec.execution_payload_sha256,
        "execution_binding_sha256": execution_binding_sha256,
        "fault_spec_sha256": spec_sha256,
        "actual_receipt_id": claim.actual_receipt_id,
        "request_frame_sha256": claim.spec.request_frame_sha256,
        "first_response_sha256": claim.first_response_sha256,
        "authority_peer_pid": claim.first_peer.pid,
        "authority_peer_uid": claim.first_peer.uid,
        "authority_peer_gid": claim.first_peer.gid,
        "authority_peer_selinux_domain": claim.first_peer.selinux_domain,
        "reason": reason,
        "one_shot_consumed": true,
        "automatically_rearmed": false,
    });
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|error| denied(format!("failure audit create-new failed: {error}")))?;
    let mut encoded = serde_json::to_vec_pretty(&value)
        .map_err(|error| denied(format!("failure audit serialization failed: {error}")))?;
    encoded.push(b'\n');
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|error| denied(format!("failure audit durable write failed: {error}")))?;
    sync_parent(parent)?;
    Ok(path)
}

fn validate_spec(spec: &DevConformanceFaultSpec) -> Result<()> {
    if spec.schema != SPEC_SCHEMA
        || spec.fault != FAULT_NAME
        || !is_run_id(&spec.run_id)
        || !is_lower_sha256(&spec.fault_id)
        || spec.fault_id != expected_fault_id(spec)
        || !is_lower_sha256(&spec.postboot_request_sha256)
        || !is_lower_sha256(&spec.install_session_id)
        || spec.same_abi_run_started_at_unix_ms == 0
        || spec.same_abi_run_started_at_unix_ms > spec.issued_at_ms
        || spec.target_method != "undo"
        || !is_identifier(&spec.target_request_id)
        || !is_lower_sha256(&spec.request_frame_sha256)
        || spec.expected_action != NOTIFICATION_ACTION
        || !is_lower_sha256(&spec.execution_payload_sha256)
        || spec.execution_binding.tool_name != NOTIFICATION_TOOL
        || !is_identifier(&spec.execution_binding.tool_call_id.0)
        || !is_lower_sha256(&spec.execution_binding.tool_manifest_sha256)
        || !is_lower_sha256(&spec.execution_binding.accepted_plan_sha256)
        || !is_lower_sha256(&spec.execution_binding.arguments_sha256)
        || spec.issued_at_ms == 0
        || spec.expires_at_ms <= spec.issued_at_ms
        || spec.expires_at_ms - spec.issued_at_ms > MAX_TTL_MS
        || !spec
            .expected_source_receipt_id
            .as_deref()
            .is_some_and(is_lower_sha256)
    {
        return Err(denied("spec closed binding or TTL is invalid"));
    }
    Ok(())
}

/// Deterministic one-shot identity. A single same-ABI run can arm independent
/// two independent undo faults without sharing a consumed/audit filename.
pub fn fault_id_for(
    run_id: &str,
    target_method: &str,
    target_request_id: &str,
    tool_call_id: &str,
) -> String {
    sha256_bytes(
        format!("{run_id}\0{target_method}\0{target_request_id}\0{tool_call_id}").as_bytes(),
    )
}

fn expected_fault_id(spec: &DevConformanceFaultSpec) -> String {
    fault_id_for(
        &spec.run_id,
        &spec.target_method,
        &spec.target_request_id,
        &spec.execution_binding.tool_call_id.0,
    )
}

fn receipt_matches_binding(receipt: &Map<String, Value>, binding: &AgentExecutionBinding) -> bool {
    receipt.get("agent_id").and_then(Value::as_str) == Some(&binding.agent_id)
        && receipt.get("peer_uid").and_then(Value::as_u64) == Some(u64::from(binding.peer_uid))
        && receipt.get("peer_gid").and_then(Value::as_u64) == Some(u64::from(binding.peer_gid))
        && receipt.get("peer_selinux_domain").and_then(Value::as_str)
            == Some(&binding.peer_selinux_domain)
        && receipt
            .get("agent_executable_sha256")
            .and_then(Value::as_str)
            == Some(&binding.agent_executable_sha256)
        && receipt.get("subject_user_id").and_then(Value::as_u64)
            == Some(u64::from(binding.subject_user_id))
        && receipt.get("origin_uid").and_then(Value::as_u64) == Some(u64::from(binding.origin_uid))
        && receipt.get("origin_selinux_domain").and_then(Value::as_str)
            == Some(&binding.origin_selinux_domain)
        && receipt.get("session_id").and_then(Value::as_str) == Some(&binding.session_id)
        && receipt.get("task_id").and_then(Value::as_str) == Some(&binding.task_id.0)
        && receipt.get("plan_id").and_then(Value::as_str) == Some(&binding.plan_id)
        && receipt.get("action_id").and_then(Value::as_str) == Some(&binding.action_id)
        && receipt.get("tool_call_id").and_then(Value::as_str) == Some(&binding.tool_call_id.0)
        && receipt.get("tool_name").and_then(Value::as_str) == Some(&binding.tool_name)
        && receipt.get("tool_manifest_sha256").and_then(Value::as_str)
            == Some(&binding.tool_manifest_sha256)
        && receipt.get("accepted_plan_sha256").and_then(Value::as_str)
            == Some(&binding.accepted_plan_sha256)
        && receipt.get("arguments_sha256").and_then(Value::as_str)
            == Some(&binding.arguments_sha256)
}

fn read_authorized_spec(path: &Path) -> Result<Vec<u8>> {
    let parent = path
        .parent()
        .ok_or_else(|| denied("spec has no parent directory"))?;
    let parent_meta = fs::symlink_metadata(parent)
        .map_err(|error| denied(format!("spec parent metadata failed: {error}")))?;
    let expected_uid = authorized_owner_uid();
    let expected_gid = authorized_owner_gid();
    if !parent_meta.is_dir()
        || parent_meta.uid() != expected_uid
        || parent_meta.gid() != expected_gid
        || parent_meta.mode() & 0o777 != 0o700
    {
        return Err(denied(
            "spec parent must be authorized-owner mode 0700 directory",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| denied(format!("spec nofollow open failed: {error}")))?;
    let metadata_before = file
        .metadata()
        .map_err(|error| denied(format!("spec metadata failed: {error}")))?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| denied(format!("spec lstat after open failed: {error}")))?;
    if !metadata_before.is_file()
        || !path_metadata.file_type().is_file()
        || metadata_before.dev() != path_metadata.dev()
        || metadata_before.ino() != path_metadata.ino()
        || metadata_before.uid() != expected_uid
        || metadata_before.gid() != expected_gid
        || metadata_before.mode() & 0o777 != 0o600
        || metadata_before.nlink() != 1
        || metadata_before.len() == 0
        || metadata_before.len() > MAX_SPEC_BYTES
    {
        return Err(denied(
            "spec must be authorized-owner, regular, single-link, mode 0600, and bounded",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata_before.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| denied(format!("spec read failed: {error}")))?;
    let metadata_after = file
        .metadata()
        .map_err(|error| denied(format!("spec post-read metadata failed: {error}")))?;
    if bytes.len() as u64 != metadata_before.len()
        || !same_file_snapshot(&metadata_before, &metadata_after)
    {
        return Err(denied("spec identity or metadata changed while reading"));
    }
    Ok(bytes)
}

fn parse_spec(bytes: &[u8]) -> Result<DevConformanceFaultSpec> {
    let text = std::str::from_utf8(bytes).map_err(|_| denied("spec is not UTF-8"))?;
    let value = authority_receipt::parse_strict_json(text, "dev conformance fault spec")?;
    serde_json::from_value(value).map_err(|error| {
        denied(format!(
            "spec has missing, unknown, or mistyped fields: {error}"
        ))
    })
}

fn rename_noreplace(from: &Path, to: &Path) -> Result<()> {
    let parent = to
        .parent()
        .ok_or_else(|| denied("consumed path has no parent"))?
        .to_path_buf();
    let from =
        CString::new(from.as_os_str().as_bytes()).map_err(|_| denied("spec path contains NUL"))?;
    let to = CString::new(to.as_os_str().as_bytes())
        .map_err(|_| denied("consumed path contains NUL"))?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the call.
    let status = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status != 0 {
        return Err(denied(format!(
            "atomic one-shot claim failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    sync_parent(&parent)
}

fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|error| denied(format!("spec parent sync failed: {error}")))
}

fn authorized_owner_uid() -> u32 {
    #[cfg(test)]
    {
        // Host tests are the only non-root identity allowed to exercise this module.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(test))]
    {
        0
    }
}

fn authorized_owner_gid() -> u32 {
    #[cfg(test)]
    {
        // Host tests run under the invoking test identity, never an arbitrary peer.
        unsafe { libc::getegid() }
    }
    #[cfg(not(test))]
    {
        0
    }
}

fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mode() == right.mode()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn is_run_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn no_match(reason: &'static str) -> FaultProbe {
    FaultProbe {
        matched: false,
        reason,
        actual_receipt_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use trillionnium_os_types::{TaskId, ToolCallId};

    fn binding() -> AgentExecutionBinding {
        AgentExecutionBinding {
            agent_id: "agent-fixture".to_string(),
            peer_uid: 5901,
            peer_gid: 5901,
            peer_selinux_domain: "u:r:trillionnium_agent:s0".to_string(),
            agent_executable_sha256: "a".repeat(64),
            subject_user_id: 0,
            origin_uid: 10123,
            origin_selinux_domain: "u:r:trillionnium_ai_shell:s0".to_string(),
            session_id: "session-fixture".to_string(),
            task_id: TaskId("task-fixture".to_string()),
            plan_id: "plan-fixture".to_string(),
            action_id: "action-fixture".to_string(),
            tool_call_id: ToolCallId("toolcall-fixture".to_string()),
            tool_name: NOTIFICATION_TOOL.to_string(),
            tool_manifest_sha256: "b".repeat(64),
            accepted_plan_sha256: "c".repeat(64),
            arguments_sha256: String::new(),
        }
    }

    fn fixture() -> (DevConformanceFaultSpec, Value, Vec<u8>, Value) {
        let payload = json!({"title": "Exact", "body": "Body"});
        let arguments = json!({
            "request_id": "action-request-fixture",
            "source_id": "source-fixture",
            "context_sha256": "d".repeat(64),
            "plan_sha256": "e".repeat(64),
            "provider_output_sha256": "f".repeat(64),
            "approval_nonce": "approval-nonce-fixture",
            "network_scope": "none",
            "payload": payload,
        });
        let mut binding = binding();
        binding.arguments_sha256 = sha256_json(&arguments);
        let payload_sha256 = sha256_json(&payload);
        let source_receipt_id = "0".repeat(64);
        let undo_request_id = "undo-request-fixture";
        let frame = json!({
            "protocol": crate::ANDROID_GATEWAY_PROTOCOL,
            "method": "undo",
            "request_id": undo_request_id,
            "receipt_id": source_receipt_id,
            "execution_payload_sha256": payload_sha256,
            "execution_binding": binding,
        });
        let bytes = serde_json::to_vec(&frame).unwrap();
        let receipt_id = "1".repeat(64);
        let receipt = json!({
            "receipt_id": receipt_id,
            "request_id": undo_request_id,
            "decision": "PASS_BOUNDED_UNDO",
            "action": NOTIFICATION_ACTION,
            "undo": true,
            "previous_receipt_id": source_receipt_id,
            "payload_sha256": payload_sha256,
            "agent_id": binding.agent_id,
            "peer_uid": binding.peer_uid,
            "peer_gid": binding.peer_gid,
            "peer_selinux_domain": binding.peer_selinux_domain,
            "agent_executable_sha256": binding.agent_executable_sha256,
            "subject_user_id": binding.subject_user_id,
            "origin_uid": binding.origin_uid,
            "origin_selinux_domain": binding.origin_selinux_domain,
            "session_id": binding.session_id,
            "task_id": binding.task_id.0,
            "plan_id": binding.plan_id,
            "action_id": binding.action_id,
            "tool_call_id": binding.tool_call_id.0,
            "tool_name": binding.tool_name,
            "tool_manifest_sha256": binding.tool_manifest_sha256,
            "accepted_plan_sha256": binding.accepted_plan_sha256,
            "arguments_sha256": binding.arguments_sha256,
            "postboot_request_sha256": "2".repeat(64),
            "install_session_id": "3".repeat(64),
            "same_abi_run_id": "0123456789abcdef0123456789abcdef",
            "same_abi_run_started_at_unix_ms": 500,
        });
        let result = json!({
            "receipt_id": receipt_id,
            "receipt_json": serde_json::to_string(&receipt).unwrap(),
        });
        let run_id = "0123456789abcdef0123456789abcdef";
        let spec = DevConformanceFaultSpec {
            schema: SPEC_SCHEMA.to_string(),
            fault: FAULT_NAME.to_string(),
            run_id: run_id.to_string(),
            fault_id: fault_id_for(run_id, "undo", undo_request_id, &binding.tool_call_id.0),
            postboot_request_sha256: "2".repeat(64),
            install_session_id: "3".repeat(64),
            same_abi_run_started_at_unix_ms: 500,
            target_method: "undo".to_string(),
            target_request_id: undo_request_id.to_string(),
            request_frame_sha256: sha256_bytes(&bytes),
            expected_action: NOTIFICATION_ACTION.to_string(),
            expected_source_receipt_id: Some(source_receipt_id),
            execution_payload_sha256: payload_sha256,
            execution_binding: binding,
            issued_at_ms: 1_000,
            expires_at_ms: 10_000,
        };
        (spec, frame, bytes, result)
    }

    fn peer() -> GatewayPeerIdentity {
        GatewayPeerIdentity {
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            selinux_domain: "host-test".to_string(),
        }
    }

    #[test]
    fn exact_probe_matches_without_consuming() {
        let (spec, frame, bytes, result) = fixture();
        let probe = probe_spec(&spec, &frame, &bytes, &result, 2_000).unwrap();
        assert!(probe.matched);
        assert_eq!(probe.actual_receipt_id, Some("1".repeat(64)));
    }

    #[test]
    fn identity_plan_action_manifest_arguments_and_payload_substitutions_do_not_match() {
        let (spec, frame, _bytes, result) = fixture();
        let cases = [
            ("agent_id", Value::String("agent-swapped".to_string())),
            ("plan_id", Value::String("plan-swapped".to_string())),
            ("action_id", Value::String("action-swapped".to_string())),
            ("tool_manifest_sha256", Value::String("9".repeat(64))),
            ("arguments_sha256", Value::String("8".repeat(64))),
        ];
        for (field, value) in cases {
            let mut changed = frame.clone();
            changed["execution_binding"][field] = value;
            let bytes = serde_json::to_vec(&changed).unwrap();
            let mut matching_frame_digest = spec.clone();
            matching_frame_digest.request_frame_sha256 = sha256_bytes(&bytes);
            let probe =
                probe_spec(&matching_frame_digest, &changed, &bytes, &result, 2_000).unwrap();
            assert!(!probe.matched, "substitution {field} consumed the hook");
        }
        let mut changed = frame.clone();
        changed["execution_payload_sha256"] = Value::String("7".repeat(64));
        let bytes = serde_json::to_vec(&changed).unwrap();
        let mut matching_frame_digest = spec.clone();
        matching_frame_digest.request_frame_sha256 = sha256_bytes(&bytes);
        let probe = probe_spec(&matching_frame_digest, &changed, &bytes, &result, 2_000).unwrap();
        assert!(!probe.matched, "payload substitution consumed the hook");
    }

    #[test]
    fn expired_spec_and_receipt_substitution_do_not_match() {
        let (spec, frame, bytes, mut result) = fixture();
        assert!(
            !probe_spec(&spec, &frame, &bytes, &result, 10_000)
                .unwrap()
                .matched
        );
        result["receipt_id"] = Value::String("2".repeat(64));
        assert!(
            !probe_spec(&spec, &frame, &bytes, &result, 2_000)
                .unwrap()
                .matched
        );
    }

    #[test]
    fn same_abi_run_and_postboot_substitutions_do_not_match() {
        let (spec, frame, bytes, result) = fixture();
        for (field, value) in [
            (
                "same_abi_run_id",
                Value::String("fedcba9876543210fedcba9876543210".to_string()),
            ),
            ("postboot_request_sha256", Value::String("9".repeat(64))),
            ("install_session_id", Value::String("8".repeat(64))),
            ("same_abi_run_started_at_unix_ms", Value::from(501_u64)),
        ] {
            let mut changed = result.clone();
            let receipt_text = changed["receipt_json"].as_str().unwrap();
            let mut receipt: Value = serde_json::from_str(receipt_text).unwrap();
            receipt[field] = value;
            changed["receipt_json"] = Value::String(serde_json::to_string(&receipt).unwrap());
            assert!(
                !probe_spec(&spec, &frame, &bytes, &changed, 2_000)
                    .unwrap()
                    .matched,
                "same-ABI substitution {field} consumed the hook"
            );
        }
    }

    fn write_spec(path: &Path, spec: &DevConformanceFaultSpec) {
        let bytes = serde_json::to_vec(spec).unwrap();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn exact_match_atomically_consumes_once_and_drop_writes_failure_audit() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("fault-hook.json");
        let (spec, frame, bytes, result) = fixture();
        write_spec(&path, &spec);
        let claim = claim_matching_fault(
            &path,
            &frame,
            &bytes,
            &result,
            b"first-response\n",
            &peer(),
            2_000,
        )
        .unwrap()
        .expect("exact spec must be claimed");
        assert!(!path.exists());
        assert!(claim.consumed_spec_path.exists());
        let failure_path = temp.path().join(format!(
            "fault-hook.consumed.{}.failure.json",
            spec.fault_id
        ));
        drop(claim);
        let failure: Value = serde_json::from_slice(&fs::read(failure_path).unwrap()).unwrap();
        assert_eq!(failure["build_marker"], BUILD_MARKER);
        assert_eq!(failure["one_shot_consumed"], true);
        assert_eq!(failure["automatically_rearmed"], false);
    }

    #[test]
    fn substitution_leaves_arm_file_unconsumed() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("fault-hook.json");
        let (spec, mut frame, _bytes, result) = fixture();
        frame["execution_binding"]["agent_id"] = Value::String("agent-swapped".to_string());
        let bytes = serde_json::to_vec(&frame).unwrap();
        write_spec(&path, &spec);
        assert!(
            claim_matching_fault(
                &path,
                &frame,
                &bytes,
                &result,
                b"unused-response\n",
                &peer(),
                2_000,
            )
            .unwrap()
            .is_none()
        );
        assert!(path.exists());
        assert!(temp.path().read_dir().unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("consumed")
        }));
    }

    #[test]
    fn completed_audit_records_only_observed_replay_facts() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("fault-hook.json");
        let (spec, frame, bytes, result) = fixture();
        write_spec(&path, &spec);
        let first_raw = b"byte-identical-response\n";
        let mut claim =
            claim_matching_fault(&path, &frame, &bytes, &result, first_raw, &peer(), 2_000)
                .unwrap()
                .unwrap();
        let request_sha = sha256_bytes(&bytes);
        let response_sha = sha256_bytes(first_raw);
        let observed_peer = peer();
        let audit_path = write_completed_audit(
            &mut claim,
            &CompletedFaultAudit {
                mutation_request_sha256: &"4".repeat(64),
                mutation_denial_response_sha256: &"5".repeat(64),
                retry_request_sha256: &request_sha,
                retry_response_sha256: &response_sha,
                authority_peer_pid: observed_peer.pid,
                authority_peer_uid: observed_peer.uid,
                authority_peer_gid: observed_peer.gid,
                authority_peer_selinux_domain: &observed_peer.selinux_domain,
                completed_at_ms: 2_100,
            },
        )
        .unwrap();
        let audit: Value = serde_json::from_slice(&fs::read(audit_path).unwrap()).unwrap();
        assert_eq!(audit["build_marker"], BUILD_MARKER);
        assert_eq!(audit["authority_replay_response_byte_identical"], true);
        assert!(audit["external_effect_count_observed_by_hook"].is_null());
        assert!(audit.get("side_effect_reexecution_observed").is_none());
        drop(claim);
        assert!(
            !temp
                .path()
                .join(format!(
                    "fault-hook.consumed.{}.failure.json",
                    spec.fault_id
                ))
                .exists()
        );
    }

    #[test]
    fn same_run_distinct_provider_fault_ids_do_not_collide_and_duplicate_is_denied() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = temp.path().join("fault-hook.json");
        let (codex_spec, codex_frame, codex_bytes, codex_result) = fixture();
        write_spec(&path, &codex_spec);
        let codex_claim = claim_matching_fault(
            &path,
            &codex_frame,
            &codex_bytes,
            &codex_result,
            b"codex-response\n",
            &peer(),
            2_000,
        )
        .unwrap()
        .unwrap();

        write_spec(&path, &codex_spec);
        assert!(
            claim_matching_fault(
                &path,
                &codex_frame,
                &codex_bytes,
                &codex_result,
                b"duplicate-response\n",
                &peer(),
                2_000,
            )
            .is_err()
        );
        fs::remove_file(&path).unwrap();

        let mut second_frame = codex_frame.clone();
        second_frame["request_id"] = json!("request-secondary-fixture");
        second_frame["execution_binding"]["agent_id"] = json!("agent-secondary-fixture");
        second_frame["execution_binding"]["tool_call_id"] = json!("toolcall-secondary-fixture");
        let second_bytes = serde_json::to_vec(&second_frame).unwrap();
        let mut second_result = codex_result.clone();
        let mut second_receipt: Value =
            serde_json::from_str(second_result["receipt_json"].as_str().unwrap()).unwrap();
        second_receipt["request_id"] = json!("request-secondary-fixture");
        second_receipt["agent_id"] = json!("agent-secondary-fixture");
        second_receipt["tool_call_id"] = json!("toolcall-secondary-fixture");
        second_result["receipt_json"] = json!(serde_json::to_string(&second_receipt).unwrap());
        let mut second_spec = codex_spec.clone();
        second_spec.target_request_id = "request-secondary-fixture".to_string();
        second_spec.request_frame_sha256 = sha256_bytes(&second_bytes);
        second_spec.execution_binding.agent_id = "agent-secondary-fixture".to_string();
        second_spec.execution_binding.tool_call_id =
            ToolCallId("toolcall-secondary-fixture".to_string());
        second_spec.fault_id = fault_id_for(
            &second_spec.run_id,
            &second_spec.target_method,
            &second_spec.target_request_id,
            &second_spec.execution_binding.tool_call_id.0,
        );
        write_spec(&path, &second_spec);
        let second_claim = claim_matching_fault(
            &path,
            &second_frame,
            &second_bytes,
            &second_result,
            b"secondary-response\n",
            &peer(),
            2_000,
        )
        .unwrap()
        .unwrap();
        assert_ne!(codex_spec.fault_id, second_spec.fault_id);
        assert_ne!(
            codex_claim.consumed_spec_path,
            second_claim.consumed_spec_path
        );
        assert!(codex_claim.consumed_spec_path.exists());
        assert!(second_claim.consumed_spec_path.exists());
        drop(codex_claim);
        drop(second_claim);
    }
}
