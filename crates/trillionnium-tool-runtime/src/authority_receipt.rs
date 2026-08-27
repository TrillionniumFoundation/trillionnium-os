use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use trillionnium_os_types::{AgentExecutionBinding, ToolCallInput, ToolManifest};

use super::{
    ANDROID_GATEWAY_PROTOCOL, GatewayPeerIdentity, ResolvedExecutionPayload, Result,
    ToolRuntimeError,
};

const RECEIPT_SCHEMA: &str = "org.trillionnium.ai-authority.receipt.v2";
const KEY_METADATA_SCHEMA: &str = "org.trillionnium.ai-authority.receipt-key.v1";
const AUTHORITY_PACKAGE: &str = "org.trillionnium.aiauthority";
const SIGNATURE_ALGORITHM: &str = "SHA256withECDSA";
const KEY_EPOCH: u64 = 2;
const KEY_PIN_SCOPE: &str = "package+key_epoch+key_id";
const ROTATION_CONTRACT: &str = "os_authorized_monotonic_epoch_and_pinned_key_id";
const ATTESTATION_CHALLENGE: &[u8] = b"org.trillionnium.ai-authority.receipt-key.v2";
const ATTESTATION_FORMAT: &str = "android-keymint-x509-der-chain";
const KEY_VERIFICATION_CONTRACT: &str = "pin key_id in OS-owned state; reject receipt self-asserted keys; accept rotation only with a higher OS-authorized epoch";
const RECEIPT_IDENTITY_VERIFICATION: &str = "os_pin_key_id_and_validate_keymint_attestation_chain";
const ARGUMENTS_CANONICALIZATION: &str = "serde-json-utf8-lexicographic-v1-no-floats";
const BROWSER_TOOL: &str = "android.browser.open_bounded";
const BROWSER_ACTION: &str = "browser_open_bounded";
const BROWSER_NETWORK_SCOPE: &str = "exact_https_url_once";
const NOTIFICATION_TOOL: &str = "android.notification.post_bounded";
const NOTIFICATION_ACTION: &str = "notification_post_bounded";
const NOTIFICATION_NETWORK_SCOPE: &str = "none";
const BROWSER_DETAIL: &str = "authority_launched_exact_browser_package";
const NOTIFICATION_DETAIL: &str = "authority_posted_exact_owned_notification";
const NOTIFICATION_UNDO_DETAIL: &str = "authority_cancelled_exact_owned_notification";
const CAPABILITY_TTL_MS: u64 = 60_000;

const KEY_METADATA_FIELDS: &[&str] = &[
    "schema",
    "package",
    "signature_algorithm",
    "key_id",
    "key_epoch",
    "pin_scope",
    "public_key_spki",
    "public_key_spki_is_identity_root",
    "security_level",
    "hardware_backed",
    "attestation_challenge_sha256",
    "attestation_challenge_base64",
    "certificate_chain_der",
    "attestation_chain_present",
    "attestation_format",
    "attestation_required_for_new_pin",
    "attestation_application_id_required",
    "rotation_contract",
    "verification_contract",
];

const RECEIPT_FIELDS: &[&str] = &[
    "schema",
    "decision",
    "request_id",
    "agent_id",
    "peer_uid",
    "peer_gid",
    "peer_selinux_domain",
    "agent_executable_sha256",
    "session_id",
    "subject_user_id",
    "origin_uid",
    "origin_selinux_domain",
    "task_id",
    "plan_id",
    "action_id",
    "tool_call_id",
    "tool_manifest_sha256",
    "accepted_plan_sha256",
    "arguments_sha256",
    "arguments_canonicalization",
    "action",
    "tool_name",
    "source_id",
    "context_sha256",
    "params_sha256",
    "payload_sha256",
    "plan_sha256",
    "provider_output_sha256",
    "provider_id",
    "target_generative_model",
    "approval_nonce_sha256",
    "network_scope",
    "caller_uid",
    "user_id",
    "boot_id_sha256",
    "expected_receipt_key_id",
    "issued_at_ms",
    "expires_at_ms",
    "receipt_at_ms",
    "explicit_approval",
    "capability_token_sha256",
    "single_use_capability_consumed",
    "executor_package",
    "executor_uid",
    "hardware_backed_signature",
    "detail",
    "undo",
    "undo_supported",
    "previous_receipt_id",
    "receipt_signature_algorithm",
    "receipt_signing_key_id",
    "receipt_signing_key_epoch",
    "receipt_signing_security_level",
    "receipt_signing_rotation_contract",
    "receipt_signing_key_metadata_protocol",
    "receipt_signing_key_metadata_method",
    "receipt_signing_identity_verification",
    "receipt_signing_public_key_is_identity_root",
    "receipt_signing_public_key_spki",
    "receipt_signing_attestation_challenge_sha256",
    "receipt_signing_attestation_challenge_base64",
    "receipt_signing_certificate_chain_der",
    "receipt_signing_attestation_chain_present",
    "receipt_signature",
    "receipt_id",
];

const SAME_ABI_CONFORMANCE_FIELDS: &[&str] = &[
    "postboot_request_sha256",
    "install_session_id",
    "same_abi_run_id",
    "same_abi_run_started_at_unix_ms",
];

const FROZEN_UNDO_CHAIN_FIELDS: &[&str] = &[
    "agent_id",
    "peer_uid",
    "peer_gid",
    "peer_selinux_domain",
    "agent_executable_sha256",
    "session_id",
    "subject_user_id",
    "origin_uid",
    "origin_selinux_domain",
    "task_id",
    "plan_id",
    "action_id",
    "tool_call_id",
    "tool_manifest_sha256",
    "accepted_plan_sha256",
    "arguments_sha256",
    "arguments_canonicalization",
    "action",
    "tool_name",
    "source_id",
    "context_sha256",
    "params_sha256",
    "payload_sha256",
    "plan_sha256",
    "provider_output_sha256",
    "provider_id",
    "target_generative_model",
    "approval_nonce_sha256",
    "network_scope",
    "caller_uid",
    "user_id",
    "executor_package",
    "executor_uid",
    "expected_receipt_key_id",
    "postboot_request_sha256",
    "install_session_id",
    "same_abi_run_id",
    "same_abi_run_started_at_unix_ms",
];

/// A typed, closed-world Authority receipt accepted specifically as the result
/// of an undo. The wire schema intentionally remains Authority receipt v2: the
/// `undo`, `undo_supported`, and `previous_receipt_id` fields form the signed
/// action/undo chain. Parsing always happens through `parse_strict_json` first,
/// so duplicate keys and floating-point ambiguity are rejected as well as
/// missing or unknown fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoReceipt {
    pub schema: String,
    pub decision: String,
    pub request_id: String,
    pub agent_id: String,
    pub peer_uid: u64,
    pub peer_gid: u64,
    pub peer_selinux_domain: String,
    pub agent_executable_sha256: String,
    pub session_id: String,
    pub subject_user_id: u64,
    pub origin_uid: u64,
    pub origin_selinux_domain: String,
    pub task_id: String,
    pub plan_id: String,
    pub action_id: String,
    pub tool_call_id: String,
    pub tool_manifest_sha256: String,
    pub accepted_plan_sha256: String,
    pub arguments_sha256: String,
    pub arguments_canonicalization: String,
    pub action: String,
    pub tool_name: String,
    pub source_id: String,
    pub context_sha256: String,
    pub params_sha256: String,
    pub payload_sha256: String,
    pub plan_sha256: String,
    pub provider_output_sha256: String,
    pub provider_id: String,
    pub target_generative_model: bool,
    pub approval_nonce_sha256: String,
    pub network_scope: String,
    pub caller_uid: u64,
    pub user_id: u64,
    pub boot_id_sha256: String,
    pub expected_receipt_key_id: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub receipt_at_ms: u64,
    pub explicit_approval: bool,
    pub capability_token_sha256: String,
    pub single_use_capability_consumed: bool,
    pub executor_package: String,
    pub executor_uid: u64,
    pub hardware_backed_signature: bool,
    pub detail: String,
    pub undo: bool,
    pub undo_supported: bool,
    pub previous_receipt_id: String,
    pub receipt_signature_algorithm: String,
    pub receipt_signing_key_id: String,
    pub receipt_signing_key_epoch: u64,
    pub receipt_signing_security_level: String,
    pub receipt_signing_rotation_contract: String,
    pub receipt_signing_key_metadata_protocol: String,
    pub receipt_signing_key_metadata_method: String,
    pub receipt_signing_identity_verification: String,
    pub receipt_signing_public_key_is_identity_root: bool,
    pub receipt_signing_public_key_spki: String,
    pub receipt_signing_attestation_challenge_sha256: String,
    pub receipt_signing_attestation_challenge_base64: String,
    pub receipt_signing_certificate_chain_der: Vec<String>,
    pub receipt_signing_attestation_chain_present: bool,
    pub receipt_signature: String,
    pub receipt_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postboot_request_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_abi_run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_abi_run_started_at_unix_ms: Option<u64>,
    #[serde(skip)]
    verified_receipt_json: String,
}

impl UndoReceipt {
    /// The exact Authority-supplied JSON text whose signature, receipt ID,
    /// frozen action binding, and undo chain were verified before this value
    /// was returned. This is intentionally excluded from serde so forwarding
    /// code cannot accidentally embed the raw receipt inside the receipt.
    pub fn verified_receipt_json(&self) -> &str {
        &self.verified_receipt_json
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptGatewayResult {
    action_ok: bool,
    receipt_id: String,
    receipt_json: String,
    result_text: String,
    undo_supported: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenAuthorityKeyPin {
    schema: String,
    key_id: String,
    key_epoch: u64,
    public_key_spki: String,
    security_level: String,
    hardware_backed: bool,
    attestation_challenge_sha256: String,
    rotation_contract: String,
    pinned_at_ms: u64,
    internal_pin_verified: bool,
    attestation_verified: bool,
    public_release_eligible: bool,
    verification_status: String,
}

pub(super) struct PreparedUndoSource {
    receipt: UndoReceipt,
    value: Value,
}

impl PreparedUndoSource {
    pub(super) fn receipt_id(&self) -> &str {
        &self.receipt.receipt_id
    }
}

pub(super) struct ValidatedAuthorityKey {
    verifying_key: VerifyingKey,
    key_id: String,
    public_key_spki: String,
    security_level: String,
    challenge_sha256: String,
    challenge_base64: String,
    certificate_chain_der: Value,
}

impl ValidatedAuthorityKey {
    pub(super) fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Parse JSON without the duplicate-key and floating-point ambiguity accepted
/// by `serde_json::Value`'s default deserializer.
pub(super) fn parse_strict_json(encoded: &str, boundary: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(encoded);
    let StrictJson(value) = StrictJson::deserialize(&mut deserializer)
        .map_err(|error| denied(format!("{boundary} is not strict canonical JSON: {error}")))?;
    deserializer
        .end()
        .map_err(|error| denied(format!("{boundary} has trailing data: {error}")))?;
    Ok(value)
}

pub(super) fn validate_key_metadata(metadata: &Value) -> Result<ValidatedAuthorityKey> {
    let object = exact_object(metadata, KEY_METADATA_FIELDS, "authority key metadata")?;
    exact_string(object, "schema", KEY_METADATA_SCHEMA)?;
    exact_string(object, "package", AUTHORITY_PACKAGE)?;
    exact_string(object, "signature_algorithm", SIGNATURE_ALGORITHM)?;
    exact_string(object, "pin_scope", KEY_PIN_SCOPE)?;
    exact_bool(object, "public_key_spki_is_identity_root", false)?;
    exact_bool(object, "hardware_backed", true)?;
    exact_bool(object, "attestation_chain_present", true)?;
    exact_bool(object, "attestation_required_for_new_pin", true)?;
    exact_bool(object, "attestation_application_id_required", true)?;
    exact_string(object, "attestation_format", ATTESTATION_FORMAT)?;
    exact_string(object, "rotation_contract", ROTATION_CONTRACT)?;
    exact_string(object, "verification_contract", KEY_VERIFICATION_CONTRACT)?;
    exact_u64(object, "key_epoch", KEY_EPOCH)?;

    let security_level = required_string(object, "security_level")?;
    if !matches!(security_level, "STRONGBOX" | "TRUSTED_ENVIRONMENT") {
        return Err(denied("authority receipt key is not hardware backed"));
    }
    let public_key_spki = required_string(object, "public_key_spki")?;
    let spki_der = decode_canonical_base64(public_key_spki, "authority public key SPKI", 4_096)?;
    let key_id = required_lower_sha256(object, "key_id")?;
    if hex_sha256(&spki_der) != key_id {
        return Err(denied("authority public key SPKI digest mismatch"));
    }
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|_| denied("authority public key is not a P-256 SPKI key"))?;

    let challenge_sha256 = required_lower_sha256(object, "attestation_challenge_sha256")?;
    if challenge_sha256 != hex_sha256(ATTESTATION_CHALLENGE) {
        return Err(denied(
            "authority key attestation challenge digest mismatch",
        ));
    }
    let challenge_base64 = required_string(object, "attestation_challenge_base64")?;
    if decode_canonical_base64(challenge_base64, "attestation challenge", 256)?
        != ATTESTATION_CHALLENGE
    {
        return Err(denied("authority key attestation challenge mismatch"));
    }

    let chain = object
        .get("certificate_chain_der")
        .and_then(Value::as_array)
        .ok_or_else(|| denied("authority certificate chain is missing"))?;
    if !(2..=8).contains(&chain.len()) {
        return Err(denied("authority certificate chain boundary denied"));
    }
    for certificate in chain {
        let certificate = certificate
            .as_str()
            .ok_or_else(|| denied("authority certificate chain entry is not a string"))?;
        if decode_canonical_base64(certificate, "authority certificate", 16_384)?.is_empty() {
            return Err(denied("authority certificate chain entry is empty"));
        }
    }

    Ok(ValidatedAuthorityKey {
        verifying_key,
        key_id: key_id.to_string(),
        public_key_spki: public_key_spki.to_string(),
        security_level: security_level.to_string(),
        challenge_sha256: challenge_sha256.to_string(),
        challenge_base64: challenge_base64.to_string(),
        certificate_chain_der: object["certificate_chain_der"].clone(),
    })
}

pub(super) fn verify_execution_result(
    output: &Value,
    manifest: &ToolManifest,
    call: &ToolCallInput,
    resolved: Option<&ResolvedExecutionPayload>,
    authority_key: &ValidatedAuthorityKey,
    peer: &GatewayPeerIdentity,
) -> Result<()> {
    let output = output
        .as_object()
        .ok_or_else(|| denied("gateway execution result is not an object"))?;
    let receipt_id = required_lower_sha256(output, "receipt_id")?;
    let receipt_json = required_string(output, "receipt_json")?;
    if receipt_json.len() > 256 * 1024 {
        return Err(denied("authority receipt exceeds the protocol boundary"));
    }
    let receipt = parse_strict_json(receipt_json, "authority receipt")?;
    let receipt = exact_receipt_object(&receipt, "authority receipt")?;
    verify_signed_receipt(receipt, receipt_id, authority_key)?;
    verify_execution_binding(receipt, manifest, call, resolved, peer)?;

    let action_ok = required_bool(output, "action_ok")?;
    let decision = required_string(receipt, "decision")?;
    match (action_ok, decision) {
        (true, "PASS_BOUNDED_ACTION") => {
            let detail = match manifest.name.as_str() {
                BROWSER_TOOL => BROWSER_DETAIL,
                NOTIFICATION_TOOL => NOTIFICATION_DETAIL,
                _ => return Err(denied("receipt has no supported action detail mapping")),
            };
            exact_string(receipt, "detail", detail)?;
        }
        (false, "HOLD_ACTION_FAILED") => {}
        _ => return Err(denied("authority action outcome and decision disagree")),
    }
    let undo_supported = required_bool(output, "undo_supported")?;
    if undo_supported != required_bool(receipt, "undo_supported")? {
        return Err(denied(
            "authority undo support disagrees with the signed receipt",
        ));
    }
    let expected_undo_supported = match manifest.name.as_str() {
        BROWSER_TOOL => false,
        NOTIFICATION_TOOL => true,
        _ => return Err(denied("receipt has no supported undo mapping")),
    };
    if undo_supported != expected_undo_supported {
        return Err(denied(
            "authority undo support violates the frozen action contract",
        ));
    }
    if !required_string(output, "result_text")?.is_empty() {
        return Err(denied("unsigned Authority result text is not permitted"));
    }
    if !action_ok {
        return Err(denied("Android Authority reported that the action failed"));
    }
    Ok(())
}

fn verify_signed_receipt(
    receipt: &Map<String, Value>,
    expected_receipt_id: &str,
    authority_key: &ValidatedAuthorityKey,
) -> Result<()> {
    exact_string(receipt, "schema", RECEIPT_SCHEMA)?;
    exact_string(receipt, "receipt_signature_algorithm", SIGNATURE_ALGORITHM)?;
    let encoded_signature = required_string(receipt, "receipt_signature")?;
    let signature_der = decode_canonical_base64(encoded_signature, "receipt signature", 256)?;
    let signature = Signature::from_der(&signature_der)
        .map_err(|_| denied("authority receipt signature is not strict DER ECDSA"))?;
    if signature.normalize_s().is_some() {
        return Err(denied(
            "authority receipt signature uses non-canonical high-S ECDSA",
        ));
    }
    let signed_payload = canonical_receipt(receipt, true)?;
    authority_key
        .verifying_key
        .verify(signed_payload.as_bytes(), &signature)
        .map_err(|_| denied("authority receipt signature verification failed"))?;

    let canonical_id_payload = canonical_receipt(receipt, false)?;
    let canonical_id = hex_sha256(canonical_id_payload.as_bytes());
    if canonical_id != required_lower_sha256(receipt, "receipt_id")?
        || canonical_id != expected_receipt_id
    {
        return Err(denied("authority receipt canonical identity mismatch"));
    }
    verify_receipt_key_binding(receipt, authority_key)
}

/// Perform all non-I/O checks needed before an undo is allowed to contact the
/// Android Authority. In particular, a signed receipt contract that says the
/// action is not undoable is rejected here, before key-metadata or undo socket
/// traffic can occur.
pub(super) fn prevalidate_undo_source(
    output: &Value,
    expected_receipt_id: &str,
    binding: &AgentExecutionBinding,
    payload_sha256: &str,
) -> Result<PreparedUndoSource> {
    if !is_lower_sha256(expected_receipt_id) || !is_lower_sha256(payload_sha256) {
        return Err(denied("undo source identity is not canonical"));
    }
    let result: ReceiptGatewayResult = serde_json::from_value(output.clone())
        .map_err(|error| denied(format!("stored execution result is not strict: {error}")))?;
    if !result.undo_supported {
        return Err(denied(
            "original Authority receipt declares undo_supported=false",
        ));
    }
    if !result.action_ok || !result.result_text.is_empty() {
        return Err(denied("only a successful receipted action may be undone"));
    }
    if result.receipt_id != expected_receipt_id {
        return Err(denied("stored execution receipt identity mismatch"));
    }
    let (receipt, value) = parse_typed_receipt(&result.receipt_json, "undo source receipt")?;
    if !receipt.undo_supported {
        return Err(denied(
            "signed original receipt declares undo_supported=false",
        ));
    }
    let object = exact_receipt_object(&value, "undo source receipt")?;
    verify_original_undo_source_binding(object, expected_receipt_id, binding, payload_sha256)?;
    Ok(PreparedUndoSource { receipt, value })
}

/// Bind freshly fetched Authority key metadata to the OS-owned durable key pin.
/// The metadata channel is authenticated separately from the undo channel; this
/// comparison prevents either response from supplying its own trust root.
pub(super) fn validate_key_against_frozen_pin(
    authority_key: &ValidatedAuthorityKey,
    frozen_pin: &Value,
) -> Result<()> {
    let pin: FrozenAuthorityKeyPin = serde_json::from_value(frozen_pin.clone())
        .map_err(|error| denied(format!("frozen Authority key pin is not strict: {error}")))?;
    if pin.schema != "trillionnium.authority-key-pin.v1"
        || !pin.hardware_backed
        || !pin.internal_pin_verified
        || pin.attestation_verified
        || pin.public_release_eligible
        || pin.pinned_at_ms == 0
        || pin.verification_status != "independent_os_pin_pass_full_keymint_chain_pending"
        || pin.key_epoch != KEY_EPOCH
        || pin.rotation_contract != ROTATION_CONTRACT
        || pin.key_id != authority_key.key_id
        || pin.public_key_spki != authority_key.public_key_spki
        || pin.security_level != authority_key.security_level
        || pin.attestation_challenge_sha256 != authority_key.challenge_sha256
    {
        return Err(denied(
            "fresh Authority key metadata differs from the OS-owned frozen pin",
        ));
    }
    Ok(())
}

pub(super) fn verify_prepared_undo_source(
    source: &PreparedUndoSource,
    binding: &AgentExecutionBinding,
    payload_sha256: &str,
    authority_key: &ValidatedAuthorityKey,
    peer: &GatewayPeerIdentity,
) -> Result<()> {
    let receipt = exact_receipt_object(&source.value, "undo source receipt")?;
    verify_signed_receipt(receipt, source.receipt_id(), authority_key)?;
    verify_original_undo_source_binding(receipt, source.receipt_id(), binding, payload_sha256)?;
    exact_u64(receipt, "executor_uid", u64::from(peer.uid))
}

pub(super) fn verify_undo_result(
    output: &Value,
    request_id: &str,
    source: &PreparedUndoSource,
    binding: &AgentExecutionBinding,
    payload_sha256: &str,
    authority_key: &ValidatedAuthorityKey,
    peer: &GatewayPeerIdentity,
) -> Result<UndoReceipt> {
    let result: ReceiptGatewayResult = serde_json::from_value(output.clone())
        .map_err(|error| denied(format!("undo gateway result is not strict: {error}")))?;
    if !result.undo_supported || !result.result_text.is_empty() {
        return Err(denied("undo result violates the signed result contract"));
    }
    let (mut receipt, value) = parse_typed_receipt(&result.receipt_json, "undo receipt")?;
    let object = exact_receipt_object(&value, "undo receipt")?;
    if result.receipt_id != receipt.receipt_id {
        return Err(denied("undo result and receipt identity disagree"));
    }
    verify_signed_receipt(object, &result.receipt_id, authority_key)?;
    verify_undo_binding(object, request_id, source, binding, payload_sha256, peer)?;
    match (result.action_ok, receipt.decision.as_str()) {
        (true, "PASS_BOUNDED_UNDO") => {
            receipt.verified_receipt_json = result.receipt_json;
            Ok(receipt)
        }
        (false, "HOLD_UNDO_FAILED") => Err(denied("Android Authority reported that undo failed")),
        _ => Err(denied("Authority undo outcome and decision disagree")),
    }
}

fn parse_typed_receipt(encoded: &str, boundary: &str) -> Result<(UndoReceipt, Value)> {
    if encoded.is_empty() || encoded.len() > 256 * 1024 {
        return Err(denied(format!("{boundary} exceeds the protocol boundary")));
    }
    let value = parse_strict_json(encoded, boundary)?;
    exact_receipt_object(&value, boundary)?;
    let receipt = serde_json::from_value::<UndoReceipt>(value.clone())
        .map_err(|error| denied(format!("{boundary} is not typed receipt v2: {error}")))?;
    Ok((receipt, value))
}

fn verify_original_undo_source_binding(
    receipt: &Map<String, Value>,
    expected_receipt_id: &str,
    binding: &AgentExecutionBinding,
    payload_sha256: &str,
) -> Result<()> {
    exact_string(receipt, "schema", RECEIPT_SCHEMA)?;
    exact_string(receipt, "decision", "PASS_BOUNDED_ACTION")?;
    exact_string(receipt, "receipt_id", expected_receipt_id)?;
    exact_binding(receipt, binding)?;
    exact_string(
        receipt,
        "tool_manifest_sha256",
        &binding.tool_manifest_sha256,
    )?;
    exact_string(
        receipt,
        "accepted_plan_sha256",
        &binding.accepted_plan_sha256,
    )?;
    exact_string(
        receipt,
        "arguments_canonicalization",
        ARGUMENTS_CANONICALIZATION,
    )?;
    exact_string(receipt, "params_sha256", &binding.arguments_sha256)?;
    exact_string(receipt, "payload_sha256", payload_sha256)?;
    exact_string(receipt, "tool_name", &binding.tool_name)?;
    if binding.tool_name != NOTIFICATION_TOOL {
        return Err(denied("undo has no supported frozen action mapping"));
    }
    exact_string(receipt, "action", NOTIFICATION_ACTION)?;
    exact_string(receipt, "network_scope", NOTIFICATION_NETWORK_SCOPE)?;
    exact_bool(receipt, "target_generative_model", false)?;
    exact_bool(receipt, "explicit_approval", true)?;
    exact_bool(receipt, "single_use_capability_consumed", true)?;
    exact_bool(receipt, "undo", false)?;
    exact_bool(receipt, "undo_supported", true)?;
    exact_string(receipt, "executor_package", AUTHORITY_PACKAGE)?;
    required_lower_sha256(receipt, "boot_id_sha256")?;
    required_lower_sha256(receipt, "capability_token_sha256")?;
    let previous = required_string(receipt, "previous_receipt_id")?;
    if previous != "genesis" && !is_lower_sha256(previous) {
        return Err(denied("original previous receipt identity is invalid"));
    }
    verify_receipt_time_window(receipt)?;
    exact_string(receipt, "detail", NOTIFICATION_DETAIL)?;
    Ok(())
}

fn verify_undo_binding(
    receipt: &Map<String, Value>,
    request_id: &str,
    source: &PreparedUndoSource,
    binding: &AgentExecutionBinding,
    payload_sha256: &str,
    peer: &GatewayPeerIdentity,
) -> Result<()> {
    if request_id.is_empty() || request_id.len() > 128 {
        return Err(denied("undo request identity is invalid"));
    }
    exact_string(receipt, "schema", RECEIPT_SCHEMA)?;
    exact_string(receipt, "request_id", request_id)?;
    exact_binding(receipt, binding)?;
    exact_string(receipt, "payload_sha256", payload_sha256)?;
    exact_bool(receipt, "target_generative_model", false)?;
    exact_bool(receipt, "explicit_approval", true)?;
    exact_bool(receipt, "single_use_capability_consumed", true)?;
    exact_bool(receipt, "undo", true)?;
    exact_bool(receipt, "undo_supported", true)?;
    exact_string(receipt, "executor_package", AUTHORITY_PACKAGE)?;
    exact_u64(receipt, "executor_uid", u64::from(peer.uid))?;
    exact_string(receipt, "previous_receipt_id", source.receipt_id())?;
    if required_string(receipt, "receipt_id")? == source.receipt_id() {
        return Err(denied("undo receipt replays the original receipt identity"));
    }
    required_lower_sha256(receipt, "boot_id_sha256")?;
    required_lower_sha256(receipt, "capability_token_sha256")?;
    verify_receipt_time_window(receipt)?;
    if binding.tool_name != NOTIFICATION_TOOL {
        return Err(denied("undo receipt has no supported action mapping"));
    }
    exact_string(receipt, "action", NOTIFICATION_ACTION)?;
    exact_string(receipt, "network_scope", NOTIFICATION_NETWORK_SCOPE)?;
    exact_string(receipt, "detail", NOTIFICATION_UNDO_DETAIL)?;
    let original = exact_receipt_object(&source.value, "undo source receipt")?;
    for field in FROZEN_UNDO_CHAIN_FIELDS {
        if receipt.get(*field) != original.get(*field) {
            return Err(denied(format!(
                "undo receipt changed frozen original field {field}"
            )));
        }
    }
    Ok(())
}

fn verify_receipt_time_window(receipt: &Map<String, Value>) -> Result<()> {
    let issued_at = required_u64(receipt, "issued_at_ms")?;
    let expires_at = required_u64(receipt, "expires_at_ms")?;
    let receipt_at = required_u64(receipt, "receipt_at_ms")?;
    if expires_at != issued_at.saturating_add(CAPABILITY_TTL_MS)
        || receipt_at < issued_at
        || receipt_at > expires_at
    {
        return Err(denied("authority receipt time window is invalid"));
    }
    Ok(())
}

fn verify_receipt_key_binding(
    receipt: &Map<String, Value>,
    authority_key: &ValidatedAuthorityKey,
) -> Result<()> {
    exact_string(receipt, "expected_receipt_key_id", &authority_key.key_id)?;
    exact_string(receipt, "receipt_signing_key_id", &authority_key.key_id)?;
    exact_u64(receipt, "receipt_signing_key_epoch", KEY_EPOCH)?;
    exact_string(
        receipt,
        "receipt_signing_public_key_spki",
        &authority_key.public_key_spki,
    )?;
    exact_bool(
        receipt,
        "receipt_signing_public_key_is_identity_root",
        false,
    )?;
    exact_string(
        receipt,
        "receipt_signing_security_level",
        &authority_key.security_level,
    )?;
    exact_string(
        receipt,
        "receipt_signing_attestation_challenge_sha256",
        &authority_key.challenge_sha256,
    )?;
    exact_string(
        receipt,
        "receipt_signing_attestation_challenge_base64",
        &authority_key.challenge_base64,
    )?;
    if receipt.get("receipt_signing_certificate_chain_der")
        != Some(&authority_key.certificate_chain_der)
    {
        return Err(denied(
            "receipt certificate chain differs from authenticated key metadata",
        ));
    }
    exact_bool(receipt, "receipt_signing_attestation_chain_present", true)?;
    exact_bool(receipt, "hardware_backed_signature", true)?;
    exact_string(
        receipt,
        "receipt_signing_rotation_contract",
        ROTATION_CONTRACT,
    )?;
    exact_string(
        receipt,
        "receipt_signing_key_metadata_protocol",
        ANDROID_GATEWAY_PROTOCOL,
    )?;
    exact_string(
        receipt,
        "receipt_signing_key_metadata_method",
        "key_metadata",
    )?;
    exact_string(
        receipt,
        "receipt_signing_identity_verification",
        RECEIPT_IDENTITY_VERIFICATION,
    )?;
    Ok(())
}

fn verify_execution_binding(
    receipt: &Map<String, Value>,
    manifest: &ToolManifest,
    call: &ToolCallInput,
    resolved: Option<&ResolvedExecutionPayload>,
    peer: &GatewayPeerIdentity,
) -> Result<()> {
    let binding = call
        .agent_execution_binding
        .as_ref()
        .ok_or_else(|| denied("OS execution binding is missing during receipt verification"))?;
    validate_call_manifest_binding(manifest, call)?;
    let (action, payload_sha256, call_network_scope, receipt_network_scope, undo_supported) =
        match call.tool_name.as_str() {
            BROWSER_TOOL => {
                let resolved = resolved
                    .ok_or_else(|| denied("resolved browser execution payload is missing"))?;
                let actual_payload_sha256 = trillionnium_os_types::sha256_json(&json!({
                    "url": resolved.url.as_str(),
                }));
                if actual_payload_sha256 != resolved.payload_sha256 {
                    return Err(denied("resolved execution payload digest mismatch"));
                }
                let payload = call
                    .arguments
                    .get("payload")
                    .and_then(Value::as_object)
                    .ok_or_else(|| denied("frozen execution payload descriptor is missing"))?;
                exact_string(
                    payload,
                    "execution_payload_ref",
                    &resolved.execution_payload_ref,
                )?;
                exact_string(
                    payload,
                    "execution_payload_sha256",
                    &resolved.payload_sha256,
                )?;
                exact_string(payload, "execution_payload_shape", &resolved.payload_shape)?;
                (
                    BROWSER_ACTION,
                    resolved.payload_sha256.clone(),
                    "exact_https_url",
                    BROWSER_NETWORK_SCOPE,
                    false,
                )
            }
            NOTIFICATION_TOOL => {
                if resolved.is_some() {
                    return Err(denied(
                        "notification action must not receive a resolved browser payload",
                    ));
                }
                (
                    NOTIFICATION_ACTION,
                    notification_payload_sha256(call)?,
                    NOTIFICATION_NETWORK_SCOPE,
                    NOTIFICATION_NETWORK_SCOPE,
                    true,
                )
            }
            _ => {
                return Err(denied(
                    "receipt verification has no supported action mapping",
                ));
            }
        };
    if argument_string(call, "network_scope")? != call_network_scope {
        return Err(denied("planned network scope violates the action contract"));
    }

    exact_string(receipt, "request_id", argument_string(call, "request_id")?)?;
    exact_binding(receipt, binding)?;
    exact_string(
        receipt,
        "tool_manifest_sha256",
        &binding.tool_manifest_sha256,
    )?;
    exact_string(
        receipt,
        "accepted_plan_sha256",
        &binding.accepted_plan_sha256,
    )?;
    exact_string(
        receipt,
        "arguments_canonicalization",
        ARGUMENTS_CANONICALIZATION,
    )?;
    exact_string(receipt, "action", action)?;
    exact_string(receipt, "tool_name", &call.tool_name)?;
    exact_string(receipt, "source_id", argument_string(call, "source_id")?)?;
    exact_string(
        receipt,
        "context_sha256",
        argument_string(call, "context_sha256")?,
    )?;
    exact_string(receipt, "params_sha256", &binding.arguments_sha256)?;
    exact_string(receipt, "payload_sha256", &payload_sha256)?;
    exact_string(
        receipt,
        "plan_sha256",
        argument_string(call, "plan_sha256")?,
    )?;
    exact_string(
        receipt,
        "provider_output_sha256",
        argument_string(call, "provider_output_sha256")?,
    )?;
    exact_string(
        receipt,
        "provider_id",
        &format!("{}/rootlinux-gateway", binding.agent_id),
    )?;
    exact_bool(receipt, "target_generative_model", false)?;
    exact_string(
        receipt,
        "approval_nonce_sha256",
        &hex_sha256(argument_string(call, "approval_nonce")?.as_bytes()),
    )?;
    exact_string(receipt, "network_scope", receipt_network_scope)?;
    exact_u64(receipt, "caller_uid", 0)?;
    exact_u64(receipt, "user_id", u64::from(binding.subject_user_id))?;
    exact_bool(receipt, "explicit_approval", true)?;
    exact_bool(receipt, "single_use_capability_consumed", true)?;
    exact_string(receipt, "executor_package", AUTHORITY_PACKAGE)?;
    exact_u64(receipt, "executor_uid", u64::from(peer.uid))?;
    exact_bool(receipt, "undo", false)?;
    exact_bool(receipt, "undo_supported", undo_supported)?;

    required_lower_sha256(receipt, "boot_id_sha256")?;
    required_lower_sha256(receipt, "capability_token_sha256")?;
    let previous = required_string(receipt, "previous_receipt_id")?;
    if previous != "genesis" && !is_lower_sha256(previous) {
        return Err(denied("previous receipt identity is invalid"));
    }
    let issued_at = required_u64(receipt, "issued_at_ms")?;
    let expires_at = required_u64(receipt, "expires_at_ms")?;
    let receipt_at = required_u64(receipt, "receipt_at_ms")?;
    if expires_at != issued_at.saturating_add(CAPABILITY_TTL_MS)
        || receipt_at < issued_at
        || receipt_at > expires_at
    {
        return Err(denied("authority receipt time window is invalid"));
    }
    Ok(())
}

fn exact_binding(receipt: &Map<String, Value>, binding: &AgentExecutionBinding) -> Result<()> {
    exact_string(receipt, "agent_id", &binding.agent_id)?;
    exact_u64(receipt, "peer_uid", u64::from(binding.peer_uid))?;
    exact_u64(receipt, "peer_gid", u64::from(binding.peer_gid))?;
    exact_string(receipt, "peer_selinux_domain", &binding.peer_selinux_domain)?;
    exact_string(
        receipt,
        "agent_executable_sha256",
        &binding.agent_executable_sha256,
    )?;
    exact_string(receipt, "session_id", &binding.session_id)?;
    exact_u64(
        receipt,
        "subject_user_id",
        u64::from(binding.subject_user_id),
    )?;
    exact_u64(receipt, "origin_uid", u64::from(binding.origin_uid))?;
    exact_string(
        receipt,
        "origin_selinux_domain",
        &binding.origin_selinux_domain,
    )?;
    exact_string(receipt, "task_id", &binding.task_id.0)?;
    exact_string(receipt, "plan_id", &binding.plan_id)?;
    exact_string(receipt, "action_id", &binding.action_id)?;
    exact_string(receipt, "tool_call_id", &binding.tool_call_id.0)?;
    exact_string(receipt, "tool_name", &binding.tool_name)?;
    exact_string(receipt, "arguments_sha256", &binding.arguments_sha256)?;
    Ok(())
}

/// Freeze the exact parsed manifest before the request can cross into
/// Authority. The digest covers schemas, capabilities, risk, and executor.
pub(super) fn validate_call_manifest_binding(
    manifest: &ToolManifest,
    call: &ToolCallInput,
) -> Result<String> {
    let binding = call
        .agent_execution_binding
        .as_ref()
        .ok_or_else(|| denied("OS execution binding is missing during manifest verification"))?;
    if binding.tool_name != call.tool_name || manifest.name != call.tool_name {
        return Err(denied("tool name differs from the frozen manifest binding"));
    }
    let manifest_value = serde_json::to_value(manifest)
        .map_err(|error| denied(format!("tool manifest serialization failed: {error}")))?;
    let manifest_sha256 = trillionnium_os_types::sha256_json(&manifest_value);
    if !is_lower_sha256(&binding.tool_manifest_sha256)
        || binding.tool_manifest_sha256 != manifest_sha256
    {
        return Err(denied(
            "tool manifest digest differs from the accepted binding",
        ));
    }
    if !is_lower_sha256(&binding.accepted_plan_sha256) {
        return Err(denied("accepted plan digest is not canonical"));
    }
    Ok(manifest_sha256)
}

pub(super) fn canonical_receipt(
    receipt: &Map<String, Value>,
    for_signature: bool,
) -> Result<String> {
    let mut keys = receipt.keys().collect::<Vec<_>>();
    keys.sort_unstable();
    let mut output = String::new();
    for key in keys {
        if key == "receipt_id" || (for_signature && key == "receipt_signature") {
            continue;
        }
        let item = canonical_receipt_item(&receipt[key])?;
        output.push_str(&java_string_len(key).to_string());
        output.push(':');
        output.push_str(key);
        output.push('=');
        output.push_str(&java_string_len(&item).to_string());
        output.push(':');
        output.push_str(&item);
        output.push('\n');
    }
    Ok(output)
}

fn canonical_receipt_item(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Number(value) if value.is_i64() || value.is_u64() => Ok(value.to_string()),
        Value::String(value) => Ok(value.clone()),
        Value::Array(value) if value.iter().all(Value::is_string) => {
            serde_json::to_string(value).map_err(|error| denied(error.to_string()))
        }
        _ => Err(denied("receipt contains a non-canonical value type")),
    }
}

fn java_string_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn exact_receipt_object<'a>(value: &'a Value, boundary: &str) -> Result<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| denied(format!("{boundary} is not an object")))?;
    let present_conformance_fields = SAME_ABI_CONFORMANCE_FIELDS
        .iter()
        .filter(|field| object.contains_key(**field))
        .count();
    if present_conformance_fields != 0
        && present_conformance_fields != SAME_ABI_CONFORMANCE_FIELDS.len()
    {
        return Err(denied(format!(
            "{boundary} has partial same-ABI conformance fields"
        )));
    }
    let has_same_abi_binding = present_conformance_fields == SAME_ABI_CONFORMANCE_FIELDS.len();
    let expected_len = RECEIPT_FIELDS.len()
        + if has_same_abi_binding {
            SAME_ABI_CONFORMANCE_FIELDS.len()
        } else {
            0
        };
    if object.len() != expected_len
        || RECEIPT_FIELDS
            .iter()
            .any(|field| !object.contains_key(*field))
        || object.keys().any(|field| {
            !(RECEIPT_FIELDS.contains(&field.as_str())
                || has_same_abi_binding && SAME_ABI_CONFORMANCE_FIELDS.contains(&field.as_str()))
        })
    {
        return Err(denied(format!("{boundary} has missing or unknown fields")));
    }
    if has_same_abi_binding {
        required_lower_sha256(object, "postboot_request_sha256")?;
        required_lower_sha256(object, "install_session_id")?;
        let run_id = required_string(object, "same_abi_run_id")?;
        if run_id.len() != 32
            || !run_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(denied(format!(
                "{boundary} same-ABI run identity is not canonical"
            )));
        }
        let started_at = required_u64(object, "same_abi_run_started_at_unix_ms")?;
        let issued_at = required_u64(object, "issued_at_ms")?;
        if started_at == 0 || started_at > i64::MAX as u64 || started_at > issued_at {
            return Err(denied(format!("{boundary} same-ABI start time is invalid")));
        }
    }
    Ok(object)
}

fn exact_object<'a>(
    value: &'a Value,
    expected_fields: &[&str],
    boundary: &str,
) -> Result<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .ok_or_else(|| denied(format!("{boundary} is not an object")))?;
    if object.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err(denied(format!("{boundary} has missing or unknown fields")));
    }
    Ok(object)
}

fn argument_string<'a>(call: &'a ToolCallInput, field: &str) -> Result<&'a str> {
    call.arguments
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| denied(format!("frozen argument {field} is missing")))
}

fn notification_payload_sha256(call: &ToolCallInput) -> Result<String> {
    let payload = call
        .arguments
        .get("payload")
        .ok_or_else(|| denied("bounded notification payload is missing"))?;
    let payload_object = exact_object(payload, &["title", "body"], "bounded notification payload")?;
    for (field, minimum, maximum) in [("title", 1_usize, 120_usize), ("body", 1, 1_000)] {
        let value = required_string(payload_object, field)?;
        if value.trim().is_empty()
            || !(minimum..=maximum).contains(&value.len())
            || value.chars().any(char::is_control)
        {
            return Err(denied(format!(
                "bounded notification {field} violates the UTF-8 byte/control boundary"
            )));
        }
    }
    Ok(trillionnium_os_types::sha256_json(payload))
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| denied(format!("{field} is not a string")))
}

fn exact_string(object: &Map<String, Value>, field: &str, expected: &str) -> Result<()> {
    if required_string(object, field)? != expected {
        return Err(denied(format!("{field} does not match its frozen value")));
    }
    Ok(())
}

fn required_bool(object: &Map<String, Value>, field: &str) -> Result<bool> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| denied(format!("{field} is not a boolean")))
}

fn exact_bool(object: &Map<String, Value>, field: &str, expected: bool) -> Result<()> {
    if required_bool(object, field)? != expected {
        return Err(denied(format!("{field} does not match the required value")));
    }
    Ok(())
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| denied(format!("{field} is not an unsigned integer")))
}

fn exact_u64(object: &Map<String, Value>, field: &str, expected: u64) -> Result<()> {
    if required_u64(object, field)? != expected {
        return Err(denied(format!("{field} does not match the required value")));
    }
    Ok(())
}

fn required_lower_sha256<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    let value = required_string(object, field)?;
    if !is_lower_sha256(value) {
        return Err(denied(format!("{field} is not a canonical SHA-256 digest")));
    }
    Ok(value)
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_canonical_base64(encoded: &str, boundary: &str, max_bytes: usize) -> Result<Vec<u8>> {
    if encoded.is_empty() || encoded.len() > max_bytes.saturating_mul(2) {
        return Err(denied(format!("{boundary} exceeds its boundary")));
    }
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .map_err(|_| denied(format!("{boundary} is not canonical base64")))?;
    if decoded.len() > max_bytes || BASE64_STANDARD.encode(&decoded) != encoded {
        return Err(denied(format!("{boundary} is not canonical base64")));
    }
    Ok(decoded)
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn denied(reason: impl Into<String>) -> ToolRuntimeError {
    ToolRuntimeError::AndroidGatewayProtocol(format!(
        "authenticated Authority receipt denied: {}",
        reason.into()
    ))
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_any(StrictJsonVisitor)
            .map(StrictJson)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("strict JSON without duplicate keys or floating-point numbers")
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point numbers are denied"))
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(Value::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJson::deserialize(deserializer).map(|value| value.0)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut output = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJson>()? {
            output.push(value.0);
        }
        Ok(Value::Array(output))
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut output = Map::new();
        let mut fields = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !fields.insert(key.clone()) {
                return Err(de::Error::custom(format!("duplicate key {key}")));
            }
            let value = map.next_value::<StrictJson>()?;
            output.insert(key, value.0);
        }
        Ok(Value::Object(output))
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::pkcs8::EncodePublicKey;
    use serde_json::{Value, json};
    #[cfg(feature = "dev-conformance-fault-hook")]
    use std::fs::{self, OpenOptions};
    use std::io::{BufRead, BufReader, Write};
    #[cfg(feature = "dev-conformance-fault-hook")]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    #[cfg(feature = "dev-conformance-fault-hook")]
    use std::sync::{Mutex, OnceLock};
    use std::thread;
    use std::time::Duration;
    use trillionnium_os_types::{
        AgentExecutionBinding, TaskId, ToolCallId, ToolCallInput, sha256_json,
    };

    use super::*;
    use crate::{
        AndroidGatewayAdapter, DurableUndoRecovery, GatewayPeerPolicy, ResolvedExecutionPayload,
        executable_android_gateway_manifests,
    };

    #[cfg(feature = "dev-conformance-fault-hook")]
    static DEV_FAULT_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn fixture_signing_key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).expect("fixture signing key")
    }

    fn fixture_key_metadata(signing_key: &SigningKey) -> Value {
        let spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("fixture SPKI")
            .as_bytes()
            .to_vec();
        json!({
            "schema": KEY_METADATA_SCHEMA,
            "package": AUTHORITY_PACKAGE,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "key_id": hex_sha256(&spki),
            "key_epoch": KEY_EPOCH,
            "pin_scope": KEY_PIN_SCOPE,
            "public_key_spki": BASE64_STANDARD.encode(&spki),
            "public_key_spki_is_identity_root": false,
            "security_level": "TRUSTED_ENVIRONMENT",
            "hardware_backed": true,
            "attestation_challenge_sha256": hex_sha256(ATTESTATION_CHALLENGE),
            "attestation_challenge_base64": BASE64_STANDARD.encode(ATTESTATION_CHALLENGE),
            "certificate_chain_der": [
                BASE64_STANDARD.encode(b"fixture-leaf-certificate"),
                BASE64_STANDARD.encode(b"fixture-root-certificate")
            ],
            "attestation_chain_present": true,
            "attestation_format": ATTESTATION_FORMAT,
            "attestation_required_for_new_pin": true,
            "attestation_application_id_required": true,
            "rotation_contract": ROTATION_CONTRACT,
            "verification_contract": KEY_VERIFICATION_CONTRACT,
        })
    }

    fn adapter_with_boot_frozen_receipt_key(
        socket: impl Into<std::path::PathBuf>,
        metadata: &Value,
    ) -> AndroidGatewayAdapter {
        let mut adapter = AndroidGatewayAdapter::new(socket);
        adapter.peer_policy.expected_receipt_key_id = Some(
            metadata["key_id"]
                .as_str()
                .expect("fixture key id")
                .to_string(),
        );
        adapter
    }

    fn fixture_call() -> (ToolCallInput, ResolvedExecutionPayload) {
        let manifest = executable_android_gateway_manifests().remove(0);
        let task_id = TaskId("task-receipt-fixture".to_string());
        let tool_call_id = ToolCallId("toolcall-receipt-fixture".to_string());
        let url = "https://example.test/frozen-path";
        let payload_sha256 = sha256_json(&json!({"url": url}));
        let payload_ref = format!("execution-payload-{}", "e".repeat(64));
        let arguments = json!({
            "request_id": "request-receipt-fixture",
            "source_id": "browser:user-selected",
            "context_sha256": "a".repeat(64),
            "plan_sha256": "b".repeat(64),
            "provider_output_sha256": "c".repeat(64),
            "approval_nonce": "approval-nonce-receipt-fixture",
            "network_scope": "exact_https_url",
            "payload": {
                "execution_payload_ref": payload_ref,
                "execution_payload_sha256": payload_sha256,
                "execution_payload_shape": "exact_https_url.v1"
            }
        });
        let binding = AgentExecutionBinding {
            agent_id: "agent-receipt-fixture".to_string(),
            peer_uid: 62010,
            peer_gid: 62011,
            peer_selinux_domain: "u:r:trillionnium_agent:s0".to_string(),
            agent_executable_sha256: "d".repeat(64),
            subject_user_id: 0,
            origin_uid: 10123,
            origin_selinux_domain: "u:r:trillionnium_aishell:s0".to_string(),
            session_id: "session-receipt-fixture".to_string(),
            task_id: task_id.clone(),
            plan_id: "plan-receipt-fixture".to_string(),
            action_id: "action-receipt-fixture".to_string(),
            tool_call_id: tool_call_id.clone(),
            tool_name: manifest.name.clone(),
            tool_manifest_sha256: sha256_json(&serde_json::to_value(&manifest).unwrap()),
            accepted_plan_sha256: "9".repeat(64),
            arguments_sha256: sha256_json(&arguments),
        };
        (
            ToolCallInput {
                task_id,
                tool_call_id,
                tool_name: BROWSER_TOOL.to_string(),
                arguments,
                agent_execution_binding: Some(binding),
            },
            ResolvedExecutionPayload {
                execution_payload_ref: payload_ref,
                payload_sha256,
                payload_shape: "exact_https_url.v1".to_string(),
                url: zeroize::Zeroizing::new(url.to_string()),
            },
        )
    }

    fn fixture_notification_call() -> (ToolCallInput, String) {
        let (mut call, _) = fixture_call();
        let manifest = executable_android_gateway_manifests()
            .into_iter()
            .find(|manifest| manifest.name == NOTIFICATION_TOOL)
            .unwrap();
        call.tool_name = NOTIFICATION_TOOL.to_string();
        call.arguments = json!({
            "request_id": "request-receipt-fixture",
            "source_id": "context:user-approved",
            "context_sha256": "a".repeat(64),
            "plan_sha256": "b".repeat(64),
            "provider_output_sha256": "c".repeat(64),
            "approval_nonce": "approval-nonce-receipt-fixture",
            "network_scope": "none",
            "payload": {
                "title": "Approved fixture",
                "body": "Exact notification body"
            }
        });
        let payload_sha256 = trillionnium_os_types::sha256_json(&call.arguments["payload"]);
        let arguments_sha256 = sha256_json(&call.arguments);
        let binding = call.agent_execution_binding.as_mut().unwrap();
        binding.tool_name = NOTIFICATION_TOOL.to_string();
        binding.tool_manifest_sha256 = sha256_json(&serde_json::to_value(&manifest).unwrap());
        binding.arguments_sha256 = arguments_sha256;
        (call, payload_sha256)
    }

    fn fixture_peer() -> GatewayPeerIdentity {
        GatewayPeerIdentity {
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            selinux_domain: crate::current_security_context().expect("fixture security context"),
        }
    }

    fn fixture_receipt(
        call: &ToolCallInput,
        resolved: &ResolvedExecutionPayload,
        metadata: &Value,
        peer: &GatewayPeerIdentity,
    ) -> Value {
        let binding = call.agent_execution_binding.as_ref().unwrap();
        json!({
            "schema": RECEIPT_SCHEMA,
            "decision": "PASS_BOUNDED_ACTION",
            "request_id": call.arguments["request_id"],
            "agent_id": binding.agent_id,
            "peer_uid": binding.peer_uid,
            "peer_gid": binding.peer_gid,
            "peer_selinux_domain": binding.peer_selinux_domain,
            "agent_executable_sha256": binding.agent_executable_sha256,
            "session_id": binding.session_id,
            "subject_user_id": binding.subject_user_id,
            "origin_uid": binding.origin_uid,
            "origin_selinux_domain": binding.origin_selinux_domain,
            "task_id": binding.task_id.0,
            "plan_id": binding.plan_id,
            "action_id": binding.action_id,
            "tool_call_id": binding.tool_call_id.0,
            "tool_manifest_sha256": binding.tool_manifest_sha256,
            "accepted_plan_sha256": binding.accepted_plan_sha256,
            "arguments_sha256": binding.arguments_sha256,
            "arguments_canonicalization": ARGUMENTS_CANONICALIZATION,
            "action": BROWSER_ACTION,
            "tool_name": BROWSER_TOOL,
            "source_id": call.arguments["source_id"],
            "context_sha256": call.arguments["context_sha256"],
            "params_sha256": binding.arguments_sha256,
            "payload_sha256": resolved.payload_sha256,
            "plan_sha256": call.arguments["plan_sha256"],
            "provider_output_sha256": call.arguments["provider_output_sha256"],
            "provider_id": format!("{}/rootlinux-gateway", binding.agent_id),
            "target_generative_model": false,
            "approval_nonce_sha256": hex_sha256(
                call.arguments["approval_nonce"].as_str().unwrap().as_bytes()
            ),
            "network_scope": BROWSER_NETWORK_SCOPE,
            "caller_uid": 0,
            "user_id": binding.subject_user_id,
            "boot_id_sha256": "1".repeat(64),
            "expected_receipt_key_id": metadata["key_id"],
            "issued_at_ms": 1_000_u64,
            "expires_at_ms": 61_000_u64,
            "receipt_at_ms": 2_000_u64,
            "explicit_approval": true,
            "capability_token_sha256": "2".repeat(64),
            "single_use_capability_consumed": true,
            "executor_package": AUTHORITY_PACKAGE,
            "executor_uid": peer.uid,
            "hardware_backed_signature": true,
            "detail": "authority_launched_exact_browser_package",
            "undo": false,
            "undo_supported": false,
            "previous_receipt_id": "genesis",
            "receipt_signature_algorithm": SIGNATURE_ALGORITHM,
            "receipt_signing_key_id": metadata["key_id"],
            "receipt_signing_key_epoch": metadata["key_epoch"],
            "receipt_signing_security_level": metadata["security_level"],
            "receipt_signing_rotation_contract": metadata["rotation_contract"],
            "receipt_signing_key_metadata_protocol": ANDROID_GATEWAY_PROTOCOL,
            "receipt_signing_key_metadata_method": "key_metadata",
            "receipt_signing_identity_verification": RECEIPT_IDENTITY_VERIFICATION,
            "receipt_signing_public_key_is_identity_root": false,
            "receipt_signing_public_key_spki": metadata["public_key_spki"],
            "receipt_signing_attestation_challenge_sha256":
                metadata["attestation_challenge_sha256"],
            "receipt_signing_attestation_challenge_base64":
                metadata["attestation_challenge_base64"],
            "receipt_signing_certificate_chain_der": metadata["certificate_chain_der"],
            "receipt_signing_attestation_chain_present": true,
        })
    }

    fn fixture_notification_receipt(
        call: &ToolCallInput,
        metadata: &Value,
        peer: &GatewayPeerIdentity,
    ) -> Value {
        let (_, resolved) = fixture_call();
        let mut receipt = fixture_receipt(call, &resolved, metadata, peer);
        receipt["action"] = json!(NOTIFICATION_ACTION);
        receipt["tool_name"] = json!(NOTIFICATION_TOOL);
        receipt["payload_sha256"] = json!(trillionnium_os_types::sha256_json(
            &call.arguments["payload"]
        ));
        receipt["network_scope"] = json!(NOTIFICATION_NETWORK_SCOPE);
        receipt["detail"] = json!(NOTIFICATION_DETAIL);
        receipt["undo_supported"] = json!(true);
        receipt
    }

    fn annotate_same_abi(mut receipt: Value) -> Value {
        receipt["postboot_request_sha256"] = json!("4".repeat(64));
        receipt["install_session_id"] = json!("5".repeat(64));
        receipt["same_abi_run_id"] = json!("6".repeat(32));
        receipt["same_abi_run_started_at_unix_ms"] = json!(500_u64);
        receipt
    }

    fn seal_receipt(mut receipt: Value, signing_key: &SigningKey) -> Value {
        let canonical = canonical_receipt(receipt.as_object().unwrap(), true).unwrap();
        let signature: Signature = signing_key.sign(canonical.as_bytes());
        let signature = signature.normalize_s().unwrap_or(signature);
        receipt["receipt_signature"] = json!(BASE64_STANDARD.encode(signature.to_der().as_bytes()));
        let canonical = canonical_receipt(receipt.as_object().unwrap(), false).unwrap();
        receipt["receipt_id"] = json!(hex_sha256(canonical.as_bytes()));
        receipt
    }

    fn high_s_malleate_receipt(mut receipt: Value) -> Value {
        const P256_ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let encoded = receipt["receipt_signature"].as_str().unwrap();
        let signature = Signature::from_der(&BASE64_STANDARD.decode(encoded).unwrap()).unwrap();
        assert!(signature.normalize_s().is_none());
        let low_s = signature.s().to_bytes();
        let mut high_s = [0u8; 32];
        let mut borrow = 0u16;
        for index in (0..32).rev() {
            let minuend = u16::from(P256_ORDER[index]);
            let subtrahend = u16::from(low_s[index]) + borrow;
            if minuend >= subtrahend {
                high_s[index] = (minuend - subtrahend) as u8;
                borrow = 0;
            } else {
                high_s[index] = (minuend + 256 - subtrahend) as u8;
                borrow = 1;
            }
        }
        assert_eq!(borrow, 0);
        let malleated = Signature::from_scalars(signature.r().to_bytes(), high_s).unwrap();
        assert!(malleated.normalize_s().is_some());
        receipt["receipt_signature"] = json!(BASE64_STANDARD.encode(malleated.to_der().as_bytes()));
        let canonical = canonical_receipt(receipt.as_object().unwrap(), false).unwrap();
        receipt["receipt_id"] = json!(hex_sha256(canonical.as_bytes()));
        receipt
    }

    fn fixture_output(receipt: &Value) -> Value {
        json!({
            "action_ok": true,
            "receipt_id": receipt["receipt_id"],
            "receipt_json": format!("{}\n", serde_json::to_string_pretty(receipt).unwrap()),
            "result_text": "",
            "undo_supported": false,
        })
    }

    fn fixture_undoable_output(receipt: &Value) -> Value {
        json!({
            "action_ok": true,
            "receipt_id": receipt["receipt_id"],
            "receipt_json": serde_json::to_string(receipt).unwrap(),
            "result_text": "",
            "undo_supported": true,
        })
    }

    fn fixture_frozen_pin(metadata: &Value) -> Value {
        json!({
            "schema": "trillionnium.authority-key-pin.v1",
            "key_id": metadata["key_id"],
            "key_epoch": metadata["key_epoch"],
            "public_key_spki": metadata["public_key_spki"],
            "security_level": metadata["security_level"],
            "hardware_backed": true,
            "attestation_challenge_sha256": metadata["attestation_challenge_sha256"],
            "rotation_contract": metadata["rotation_contract"],
            "pinned_at_ms": 1_u64,
            "internal_pin_verified": true,
            "attestation_verified": false,
            "public_release_eligible": false,
            "verification_status": "independent_os_pin_pass_full_keymint_chain_pending",
        })
    }

    fn fixture_undoable_source(
        call: &ToolCallInput,
        metadata: &Value,
        peer: &GatewayPeerIdentity,
        signing_key: &SigningKey,
    ) -> Value {
        seal_receipt(
            fixture_notification_receipt(call, metadata, peer),
            signing_key,
        )
    }

    fn fixture_undo_receipt(source: &Value, request_id: &str, signing_key: &SigningKey) -> Value {
        let mut receipt = source.clone();
        receipt.as_object_mut().unwrap().remove("receipt_signature");
        receipt.as_object_mut().unwrap().remove("receipt_id");
        receipt["decision"] = json!("PASS_BOUNDED_UNDO");
        receipt["request_id"] = json!(request_id);
        receipt["issued_at_ms"] = json!(70_000_u64);
        receipt["expires_at_ms"] = json!(130_000_u64);
        receipt["receipt_at_ms"] = json!(71_000_u64);
        receipt["capability_token_sha256"] = json!("3".repeat(64));
        receipt["detail"] = json!(NOTIFICATION_UNDO_DETAIL);
        receipt["undo"] = json!(true);
        receipt["previous_receipt_id"] = source["receipt_id"].clone();
        seal_receipt(receipt, signing_key)
    }

    fn resign_output(receipt: Value, signing_key: &SigningKey) -> Value {
        let mut receipt = receipt;
        receipt.as_object_mut().unwrap().remove("receipt_signature");
        receipt.as_object_mut().unwrap().remove("receipt_id");
        fixture_output(&seal_receipt(receipt, signing_key))
    }

    fn mutate(value: &mut Value) {
        match value {
            Value::Bool(value) => *value = !*value,
            Value::Number(value) => {
                *value =
                    serde_json::Number::from(value.as_u64().unwrap_or_default().saturating_add(1))
            }
            Value::String(value) => value.push('x'),
            Value::Array(value) => value.push(json!(BASE64_STANDARD.encode(b"substitute"))),
            Value::Null | Value::Object(_) => *value = json!("tampered"),
        }
    }

    fn assert_denied(
        output: &Value,
        call: &ToolCallInput,
        resolved: &ResolvedExecutionPayload,
        key: &ValidatedAuthorityKey,
        peer: &GatewayPeerIdentity,
    ) {
        let manifest = executable_android_gateway_manifests().remove(0);
        assert!(
            verify_execution_result(output, &manifest, call, Some(resolved), key, peer).is_err(),
            "tampered receipt was accepted: {}",
            output["receipt_json"]
        );
    }

    #[test]
    fn valid_p256_authority_receipt_is_accepted() {
        let signing_key = fixture_signing_key(7);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, resolved) = fixture_call();
        let peer = fixture_peer();
        let receipt = seal_receipt(
            fixture_receipt(&call, &resolved, &metadata, &peer),
            &signing_key,
        );
        verify_execution_result(
            &fixture_output(&receipt),
            &executable_android_gateway_manifests().remove(0),
            &call,
            Some(&resolved),
            &authority_key,
            &peer,
        )
        .expect("valid hardware Authority receipt should pass");
    }

    #[test]
    fn mathematically_valid_high_s_authority_receipt_is_rejected() {
        let signing_key = fixture_signing_key(47);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, resolved) = fixture_call();
        let peer = fixture_peer();
        let receipt = high_s_malleate_receipt(seal_receipt(
            fixture_receipt(&call, &resolved, &metadata, &peer),
            &signing_key,
        ));
        let error = verify_execution_result(
            &fixture_output(&receipt),
            &executable_android_gateway_manifests().remove(0),
            &call,
            Some(&resolved),
            &authority_key,
            &peer,
        )
        .expect_err("high-S malleation must fail even when ECDSA verifies mathematically");
        assert!(error.to_string().contains("non-canonical high-S ECDSA"));
    }

    #[test]
    fn valid_notification_action_receipt_is_undoable_and_payload_bound() {
        let signing_key = fixture_signing_key(35);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, payload_sha256) = fixture_notification_call();
        let peer = fixture_peer();
        let receipt = seal_receipt(
            annotate_same_abi(fixture_notification_receipt(&call, &metadata, &peer)),
            &signing_key,
        );
        let manifest = executable_android_gateway_manifests()
            .into_iter()
            .find(|manifest| manifest.name == NOTIFICATION_TOOL)
            .unwrap();
        verify_execution_result(
            &fixture_undoable_output(&receipt),
            &manifest,
            &call,
            None,
            &authority_key,
            &peer,
        )
        .expect("valid bounded notification receipt should pass");
        assert_eq!(receipt["payload_sha256"], payload_sha256);
        assert_eq!(receipt["network_scope"], NOTIFICATION_NETWORK_SCOPE);
        assert_eq!(receipt["undo_supported"], true);
        assert_eq!(receipt["same_abi_run_id"], "6".repeat(32));
    }

    #[test]
    fn same_abi_receipt_fields_are_all_or_none_closed_and_shape_checked() {
        let signing_key = fixture_signing_key(37);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, _) = fixture_notification_call();
        let peer = fixture_peer();
        let manifest = executable_android_gateway_manifests()
            .into_iter()
            .find(|manifest| manifest.name == NOTIFICATION_TOOL)
            .unwrap();
        let base = fixture_notification_receipt(&call, &metadata, &peer);
        let annotated = annotate_same_abi(base.clone());
        let denied_receipt = |receipt: Value| {
            let receipt = seal_receipt(receipt, &signing_key);
            verify_execution_result(
                &fixture_undoable_output(&receipt),
                &manifest,
                &call,
                None,
                &authority_key,
                &peer,
            )
            .is_err()
        };

        for field in SAME_ABI_CONFORMANCE_FIELDS {
            let mut partial = base.clone();
            partial[*field] = annotated[*field].clone();
            assert!(
                denied_receipt(partial),
                "partial field was accepted: {field}"
            );
        }

        for (field, invalid) in [
            ("postboot_request_sha256", json!("A".repeat(64))),
            ("install_session_id", json!("5".repeat(63))),
            ("same_abi_run_id", json!("6".repeat(64))),
            ("same_abi_run_started_at_unix_ms", json!(0_u64)),
            ("same_abi_run_started_at_unix_ms", json!("500")),
        ] {
            let mut malformed = annotated.clone();
            malformed[field] = invalid;
            assert!(
                denied_receipt(malformed),
                "malformed same-ABI field was accepted: {field}"
            );
        }

        let mut unknown = annotated;
        unknown["same_abi_model_extension"] = json!(true);
        assert!(denied_receipt(unknown));
    }

    #[test]
    fn same_abi_undo_receipt_inherits_all_four_signed_fields_exactly() {
        let signing_key = fixture_signing_key(38);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, payload_sha256) = fixture_notification_call();
        let binding = call.agent_execution_binding.as_ref().unwrap();
        let peer = fixture_peer();
        let source_receipt = seal_receipt(
            annotate_same_abi(fixture_notification_receipt(&call, &metadata, &peer)),
            &signing_key,
        );
        let source = prevalidate_undo_source(
            &fixture_undoable_output(&source_receipt),
            source_receipt["receipt_id"].as_str().unwrap(),
            binding,
            &payload_sha256,
        )
        .unwrap();
        verify_prepared_undo_source(&source, binding, &payload_sha256, &authority_key, &peer)
            .unwrap();

        let undo = fixture_undo_receipt(&source_receipt, "undo-same-abi-fixture", &signing_key);
        let verified = verify_undo_result(
            &fixture_undoable_output(&undo),
            "undo-same-abi-fixture",
            &source,
            binding,
            &payload_sha256,
            &authority_key,
            &peer,
        )
        .expect("same-ABI undo chain should preserve its signed binding");
        assert_eq!(verified.postboot_request_sha256, Some("4".repeat(64)));
        assert_eq!(verified.install_session_id, Some("5".repeat(64)));
        assert_eq!(verified.same_abi_run_id, Some("6".repeat(32)));
        assert_eq!(verified.same_abi_run_started_at_unix_ms, Some(500));

        for (field, substitution) in [
            ("postboot_request_sha256", json!("7".repeat(64))),
            ("install_session_id", json!("8".repeat(64))),
            ("same_abi_run_id", json!("9".repeat(32))),
            ("same_abi_run_started_at_unix_ms", json!(501_u64)),
        ] {
            let mut changed = undo.clone();
            changed.as_object_mut().unwrap().remove("receipt_signature");
            changed.as_object_mut().unwrap().remove("receipt_id");
            changed[field] = substitution;
            let changed = seal_receipt(changed, &signing_key);
            assert!(
                verify_undo_result(
                    &fixture_undoable_output(&changed),
                    "undo-same-abi-fixture",
                    &source,
                    binding,
                    &payload_sha256,
                    &authority_key,
                    &peer,
                )
                .is_err(),
                "re-signed same-ABI substitution was accepted: {field}"
            );
        }

        let mut stripped = undo;
        stripped
            .as_object_mut()
            .unwrap()
            .remove("receipt_signature");
        stripped.as_object_mut().unwrap().remove("receipt_id");
        for field in SAME_ABI_CONFORMANCE_FIELDS {
            stripped.as_object_mut().unwrap().remove(*field);
        }
        let stripped = seal_receipt(stripped, &signing_key);
        assert!(
            verify_undo_result(
                &fixture_undoable_output(&stripped),
                "undo-same-abi-fixture",
                &source,
                binding,
                &payload_sha256,
                &authority_key,
                &peer,
            )
            .is_err()
        );
    }

    #[test]
    fn browser_receipt_cannot_claim_undo_even_when_authority_signed() {
        let signing_key = fixture_signing_key(36);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, resolved) = fixture_call();
        let binding = call.agent_execution_binding.as_ref().unwrap();
        let peer = fixture_peer();
        let mut receipt = fixture_receipt(&call, &resolved, &metadata, &peer);
        receipt["undo_supported"] = json!(true);
        let receipt = seal_receipt(receipt, &signing_key);
        let output = fixture_undoable_output(&receipt);
        let browser = executable_android_gateway_manifests()
            .into_iter()
            .find(|manifest| manifest.name == BROWSER_TOOL)
            .unwrap();
        assert!(
            verify_execution_result(
                &output,
                &browser,
                &call,
                Some(&resolved),
                &authority_key,
                &peer,
            )
            .is_err()
        );
        assert!(
            prevalidate_undo_source(
                &output,
                receipt["receipt_id"].as_str().unwrap(),
                binding,
                &resolved.payload_sha256,
            )
            .is_err()
        );
    }

    #[test]
    fn strict_typed_undo_receipt_binds_the_original_signed_action() {
        let signing_key = fixture_signing_key(31);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let frozen_pin = fixture_frozen_pin(&metadata);
        validate_key_against_frozen_pin(&authority_key, &frozen_pin).unwrap();
        let (call, payload_sha256) = fixture_notification_call();
        let binding = call.agent_execution_binding.as_ref().unwrap();
        let peer = fixture_peer();
        let source_receipt = fixture_undoable_source(&call, &metadata, &peer, &signing_key);
        let source_output = fixture_undoable_output(&source_receipt);
        let source = prevalidate_undo_source(
            &source_output,
            source_receipt["receipt_id"].as_str().unwrap(),
            binding,
            &payload_sha256,
        )
        .unwrap();
        verify_prepared_undo_source(&source, binding, &payload_sha256, &authority_key, &peer)
            .unwrap();

        let undo = fixture_undo_receipt(&source_receipt, "undo-strict-fixture", &signing_key);
        let raw_receipt_json = format!("{}\n", serde_json::to_string_pretty(&undo).unwrap());
        let mut undo_output = fixture_undoable_output(&undo);
        undo_output["receipt_json"] = json!(raw_receipt_json.clone());
        let verified = verify_undo_result(
            &undo_output,
            "undo-strict-fixture",
            &source,
            binding,
            &payload_sha256,
            &authority_key,
            &peer,
        )
        .expect("strict signed undo receipt should pass");
        assert!(verified.undo);
        assert!(verified.undo_supported);
        assert_eq!(verified.previous_receipt_id, source.receipt_id());
        assert_eq!(verified.tool_call_id, binding.tool_call_id.0);
        assert_eq!(verified.verified_receipt_json(), raw_receipt_json);
        let serialized = serde_json::to_value(&verified).unwrap();
        assert_eq!(serialized["receipt_id"], undo["receipt_id"]);
        assert!(serialized.get("verified_receipt_json").is_none());
        assert_eq!(serialized.as_object().unwrap().len(), RECEIPT_FIELDS.len());
    }

    #[test]
    fn undo_receipt_rejects_resigned_frozen_field_substitution_and_chain_replay() {
        let signing_key = fixture_signing_key(32);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, payload_sha256) = fixture_notification_call();
        let binding = call.agent_execution_binding.as_ref().unwrap();
        let peer = fixture_peer();
        let source_receipt = fixture_undoable_source(&call, &metadata, &peer, &signing_key);
        let source = prevalidate_undo_source(
            &fixture_undoable_output(&source_receipt),
            source_receipt["receipt_id"].as_str().unwrap(),
            binding,
            &payload_sha256,
        )
        .unwrap();
        let undo = fixture_undo_receipt(&source_receipt, "undo-tamper-fixture", &signing_key);

        for field in FROZEN_UNDO_CHAIN_FIELDS {
            let mut changed = undo.clone();
            let Some(value) = changed.get_mut(*field) else {
                continue;
            };
            mutate(value);
            changed.as_object_mut().unwrap().remove("receipt_signature");
            changed.as_object_mut().unwrap().remove("receipt_id");
            let changed = seal_receipt(changed, &signing_key);
            assert!(
                verify_undo_result(
                    &fixture_undoable_output(&changed),
                    "undo-tamper-fixture",
                    &source,
                    binding,
                    &payload_sha256,
                    &authority_key,
                    &peer,
                )
                .is_err(),
                "re-signed frozen undo field was accepted: {field}"
            );
        }

        let mut replayed = undo;
        replayed
            .as_object_mut()
            .unwrap()
            .remove("receipt_signature");
        replayed.as_object_mut().unwrap().remove("receipt_id");
        replayed["previous_receipt_id"] = json!("f".repeat(64));
        let replayed = seal_receipt(replayed, &signing_key);
        assert!(
            verify_undo_result(
                &fixture_undoable_output(&replayed),
                "undo-tamper-fixture",
                &source,
                binding,
                &payload_sha256,
                &authority_key,
                &peer,
            )
            .is_err()
        );

        let mut extended =
            fixture_undo_receipt(&source_receipt, "undo-tamper-fixture", &signing_key);
        extended
            .as_object_mut()
            .unwrap()
            .remove("receipt_signature");
        extended.as_object_mut().unwrap().remove("receipt_id");
        extended["authority_extension"] = json!("must-not-cross");
        let extended = seal_receipt(extended, &signing_key);
        assert!(
            verify_undo_result(
                &fixture_undoable_output(&extended),
                "undo-tamper-fixture",
                &source,
                binding,
                &payload_sha256,
                &authority_key,
                &peer,
            )
            .is_err()
        );
    }

    #[test]
    fn undo_requires_fresh_metadata_to_match_the_os_frozen_pin() {
        let signing_key = fixture_signing_key(33);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let mut pin = fixture_frozen_pin(&metadata);
        pin["key_id"] = json!("a".repeat(64));
        assert!(validate_key_against_frozen_pin(&authority_key, &pin).is_err());
    }

    #[test]
    fn adapter_delegates_idempotent_undo_replay_to_the_durable_authority_journal() {
        let signing_key = fixture_signing_key(34);
        let metadata = fixture_key_metadata(&signing_key);
        let frozen_pin = fixture_frozen_pin(&metadata);
        let (call, payload_sha256) = fixture_notification_call();
        let binding = call.agent_execution_binding.as_ref().unwrap().clone();
        let peer = fixture_peer();
        let source_receipt = fixture_undoable_source(&call, &metadata, &peer, &signing_key);
        let source_output = fixture_undoable_output(&source_receipt);
        let receipt_id = source_receipt["receipt_id"].as_str().unwrap().to_string();
        let undo_receipt =
            fixture_undo_receipt(&source_receipt, "undo-adapter-fixture", &signing_key);
        let undo_output = fixture_undoable_output(&undo_receipt);

        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("strict-undo.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server_metadata = metadata.clone();
        let expected_receipt_id = receipt_id.clone();
        let expected_payload_sha256 = payload_sha256.clone();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                let (mut metadata_stream, _) = listener.accept().unwrap();
                let mut request_line = String::new();
                BufReader::new(metadata_stream.try_clone().unwrap())
                    .read_line(&mut request_line)
                    .unwrap();
                let request: Value = serde_json::from_str(&request_line).unwrap();
                assert_eq!(request["method"], "key_metadata");
                let response = json!({
                    "protocol": ANDROID_GATEWAY_PROTOCOL,
                    "request_id": request["request_id"],
                    "ok": true,
                    "result": server_metadata,
                });
                serde_json::to_writer(&mut metadata_stream, &response).unwrap();
                metadata_stream.write_all(b"\n").unwrap();

                let (mut undo_stream, _) = listener.accept().unwrap();
                request_line = String::new();
                BufReader::new(undo_stream.try_clone().unwrap())
                    .read_line(&mut request_line)
                    .unwrap();
                let request: Value = serde_json::from_str(&request_line).unwrap();
                assert_eq!(request["method"], "undo");
                assert_eq!(request["receipt_id"], expected_receipt_id);
                assert_eq!(request["execution_payload_sha256"], expected_payload_sha256);
                assert_eq!(
                    request["execution_binding"]["tool_call_id"],
                    "toolcall-receipt-fixture"
                );
                let response = json!({
                    "protocol": ANDROID_GATEWAY_PROTOCOL,
                    "request_id": request["request_id"],
                    "ok": true,
                    "result": undo_output,
                });
                serde_json::to_writer(&mut undo_stream, &response).unwrap();
                undo_stream.write_all(b"\n").unwrap();
            }
        });

        let adapter = AndroidGatewayAdapter::new(socket);
        let verified = adapter
            .undo_receipt(
                "undo-adapter-fixture",
                &receipt_id,
                &source_output,
                &binding,
                &payload_sha256,
                &frozen_pin,
            )
            .expect("independently pinned signed undo should pass");
        assert!(verified.undo);

        let replay = adapter
            .undo_receipt(
                "undo-adapter-fixture",
                &receipt_id,
                &source_output,
                &binding,
                &payload_sha256,
                &frozen_pin,
            )
            .expect("the durable Authority may return the same idempotent undo receipt");
        server.join().unwrap();
        assert_eq!(replay, verified);
    }

    #[test]
    fn query_only_undo_recovery_returns_only_a_verified_durable_receipt() {
        let signing_key = fixture_signing_key(35);
        let metadata = fixture_key_metadata(&signing_key);
        let frozen_pin = fixture_frozen_pin(&metadata);
        let (call, payload_sha256) = fixture_notification_call();
        let binding = call.agent_execution_binding.as_ref().unwrap().clone();
        let peer = fixture_peer();
        let source_receipt = fixture_undoable_source(&call, &metadata, &peer, &signing_key);
        let source_output = fixture_undoable_output(&source_receipt);
        let receipt_id = source_receipt["receipt_id"].as_str().unwrap().to_string();
        let original_request_id = format!("undo-{receipt_id}");
        let undo_receipt =
            fixture_undo_receipt(&source_receipt, &original_request_id, &signing_key);
        let undo_receipt_id = undo_receipt["receipt_id"].as_str().unwrap().to_string();
        let undo_receipt_json = serde_json::to_string(&undo_receipt).unwrap();

        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("query-only-undo-recovery.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server_metadata = metadata.clone();
        let expected_original_request_id = original_request_id.clone();
        let expected_source_receipt_id = receipt_id.clone();
        let expected_payload_sha256 = payload_sha256.clone();
        let server_receipt_id = undo_receipt_id.clone();
        let server_receipt_json = undo_receipt_json.clone();
        let server = thread::spawn(move || {
            let (mut metadata_stream, _) = listener.accept().unwrap();
            let mut request_line = String::new();
            BufReader::new(metadata_stream.try_clone().unwrap())
                .read_line(&mut request_line)
                .unwrap();
            let request: Value = serde_json::from_str(&request_line).unwrap();
            assert_eq!(request["method"], "key_metadata");
            let response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": request["request_id"],
                "ok": true,
                "result": server_metadata,
            });
            serde_json::to_writer(&mut metadata_stream, &response).unwrap();
            metadata_stream.write_all(b"\n").unwrap();

            let (mut recovery_stream, _) = listener.accept().unwrap();
            request_line.clear();
            BufReader::new(recovery_stream.try_clone().unwrap())
                .read_line(&mut request_line)
                .unwrap();
            let request: Value = serde_json::from_str(&request_line).unwrap();
            assert_eq!(request["method"], "recover_execution");
            assert_eq!(request["operation"], "undo");
            assert_eq!(request["original_request_id"], expected_original_request_id);
            assert_eq!(request["receipt_id"], expected_source_receipt_id);
            assert_eq!(request["execution_payload_sha256"], expected_payload_sha256);
            let response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": request["request_id"],
                "ok": true,
                "result": {
                    "operation": "undo",
                    "original_request_id": expected_original_request_id,
                    "recovery_status": "receipt_available",
                    "execution_state": "committed",
                    "receipt_publication_state": "published",
                    "undo_state": "undone",
                    "receipt_id": server_receipt_id,
                    "receipt_json": server_receipt_json,
                },
            });
            serde_json::to_writer(&mut recovery_stream, &response).unwrap();
            recovery_stream.write_all(b"\n").unwrap();
        });

        let recovered = AndroidGatewayAdapter::new(socket)
            .recover_undo_receipt(
                &original_request_id,
                &receipt_id,
                &source_output,
                &binding,
                &payload_sha256,
                &frozen_pin,
            )
            .expect("query-only recovery should verify the stored signed undo receipt");
        server.join().unwrap();
        match recovered {
            DurableUndoRecovery::Receipt(receipt) => {
                assert_eq!(receipt.receipt_id, undo_receipt_id);
                assert_eq!(receipt.verified_receipt_json(), undo_receipt_json);
            }
            other => panic!("unexpected recovery outcome: {other:?}"),
        }
    }

    #[test]
    fn every_signed_receipt_field_rejects_unsigned_tampering() {
        let signing_key = fixture_signing_key(8);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, resolved) = fixture_call();
        let peer = fixture_peer();
        let receipt = seal_receipt(
            fixture_receipt(&call, &resolved, &metadata, &peer),
            &signing_key,
        );
        assert_eq!(receipt.as_object().unwrap().len(), RECEIPT_FIELDS.len());
        for field in RECEIPT_FIELDS {
            let mut changed = receipt.clone();
            mutate(changed.get_mut(*field).unwrap());
            let output = fixture_output(&changed);
            assert_denied(&output, &call, &resolved, &authority_key, &peer);
        }
    }

    #[test]
    fn re_signed_workflow_field_substitution_is_rejected() {
        let signing_key = fixture_signing_key(9);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, resolved) = fixture_call();
        let peer = fixture_peer();
        let receipt = fixture_receipt(&call, &resolved, &metadata, &peer);
        let frozen_fields = [
            "request_id",
            "agent_id",
            "peer_uid",
            "peer_gid",
            "peer_selinux_domain",
            "agent_executable_sha256",
            "session_id",
            "subject_user_id",
            "origin_uid",
            "origin_selinux_domain",
            "task_id",
            "plan_id",
            "action_id",
            "tool_call_id",
            "tool_manifest_sha256",
            "accepted_plan_sha256",
            "arguments_sha256",
            "arguments_canonicalization",
            "action",
            "tool_name",
            "source_id",
            "context_sha256",
            "params_sha256",
            "payload_sha256",
            "plan_sha256",
            "provider_output_sha256",
            "provider_id",
            "target_generative_model",
            "approval_nonce_sha256",
            "network_scope",
            "caller_uid",
            "user_id",
            "expected_receipt_key_id",
            "explicit_approval",
            "single_use_capability_consumed",
            "executor_package",
            "executor_uid",
            "undo",
            "undo_supported",
        ];
        for field in frozen_fields {
            let mut changed = receipt.clone();
            mutate(changed.get_mut(field).unwrap());
            let output = resign_output(changed, &signing_key);
            assert_denied(&output, &call, &resolved, &authority_key, &peer);
        }
    }

    #[test]
    fn unknown_receipt_field_is_rejected_even_when_re_signed() {
        let signing_key = fixture_signing_key(16);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, resolved) = fixture_call();
        let peer = fixture_peer();
        let mut receipt = fixture_receipt(&call, &resolved, &metadata, &peer);
        receipt["model_supplied_extension"] = json!("must-not-cross");
        let output = resign_output(receipt, &signing_key);
        assert_denied(&output, &call, &resolved, &authority_key, &peer);
    }

    #[test]
    fn parsed_tool_manifest_and_binding_are_frozen_exactly() {
        let manifest = executable_android_gateway_manifests().remove(0);
        let (call, _) = fixture_call();
        let expected = call
            .agent_execution_binding
            .as_ref()
            .unwrap()
            .tool_manifest_sha256
            .clone();
        assert_eq!(
            validate_call_manifest_binding(&manifest, &call).unwrap(),
            expected
        );

        let mut changed_manifest = manifest.clone();
        changed_manifest.description.push_str(" substituted");
        assert!(validate_call_manifest_binding(&changed_manifest, &call).is_err());

        let mut changed_tool = call.clone();
        changed_tool
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .tool_name = "android.browser.substituted".to_string();
        assert!(validate_call_manifest_binding(&manifest, &changed_tool).is_err());

        let mut changed_digest = call.clone();
        changed_digest
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .tool_manifest_sha256 = "0".repeat(64);
        assert!(validate_call_manifest_binding(&manifest, &changed_digest).is_err());

        let mut invalid_plan = call;
        invalid_plan
            .agent_execution_binding
            .as_mut()
            .unwrap()
            .accepted_plan_sha256 = "not-a-digest".to_string();
        assert!(validate_call_manifest_binding(&manifest, &invalid_plan).is_err());
    }

    #[test]
    fn every_gateway_result_field_is_bound_to_the_receipt_contract() {
        let signing_key = fixture_signing_key(15);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, resolved) = fixture_call();
        let peer = fixture_peer();
        let receipt = seal_receipt(
            fixture_receipt(&call, &resolved, &metadata, &peer),
            &signing_key,
        );
        let output = fixture_output(&receipt);
        for field in [
            "action_ok",
            "receipt_id",
            "receipt_json",
            "result_text",
            "undo_supported",
        ] {
            let mut changed = output.clone();
            mutate(changed.get_mut(field).unwrap());
            assert_denied(&changed, &call, &resolved, &authority_key, &peer);
        }
    }

    #[test]
    fn every_key_metadata_field_is_fail_closed() {
        let signing_key = fixture_signing_key(10);
        let metadata = fixture_key_metadata(&signing_key);
        assert_eq!(
            metadata.as_object().unwrap().len(),
            KEY_METADATA_FIELDS.len()
        );
        for field in KEY_METADATA_FIELDS {
            let mut changed = metadata.clone();
            if *field == "certificate_chain_der" {
                changed[*field] = json!([BASE64_STANDARD.encode(b"truncated-leaf")]);
            } else {
                mutate(changed.get_mut(*field).unwrap());
            }
            assert!(
                validate_key_metadata(&changed).is_err(),
                "tampered metadata field {field} was accepted"
            );
        }
    }

    #[test]
    fn embedded_key_substitution_is_rejected() {
        let pinned_signing_key = fixture_signing_key(11);
        let substituted_signing_key = fixture_signing_key(12);
        let pinned_metadata = fixture_key_metadata(&pinned_signing_key);
        let substituted_metadata = fixture_key_metadata(&substituted_signing_key);
        let authority_key = validate_key_metadata(&pinned_metadata).unwrap();
        let (call, resolved) = fixture_call();
        let peer = fixture_peer();
        let receipt = seal_receipt(
            fixture_receipt(&call, &resolved, &substituted_metadata, &peer),
            &substituted_signing_key,
        );
        assert_denied(
            &fixture_output(&receipt),
            &call,
            &resolved,
            &authority_key,
            &peer,
        );
    }

    #[test]
    fn signed_failed_action_is_never_returned_as_success() {
        let signing_key = fixture_signing_key(13);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key = validate_key_metadata(&metadata).unwrap();
        let (call, resolved) = fixture_call();
        let peer = fixture_peer();
        let mut receipt = fixture_receipt(&call, &resolved, &metadata, &peer);
        receipt["decision"] = json!("HOLD_ACTION_FAILED");
        receipt["detail"] = json!("execution_failed:ActivityNotFoundException");
        let receipt = seal_receipt(receipt, &signing_key);
        let mut output = fixture_output(&receipt);
        output["action_ok"] = json!(false);
        assert_denied(&output, &call, &resolved, &authority_key, &peer);
    }

    #[test]
    fn peer_uid_and_selinux_mismatch_are_rejected_before_protocol_io() {
        for policy in [
            GatewayPeerPolicy {
                expected_uid: Some(unsafe { libc::geteuid() }.saturating_add(1)),
                expected_selinux_domain: Some(
                    crate::current_security_context().expect("security context"),
                ),
                expected_receipt_key_id: None,
                allow_uid_discovery: false,
                allow_host_test_uid: false,
            },
            GatewayPeerPolicy {
                expected_uid: Some(unsafe { libc::geteuid() }),
                expected_selinux_domain: Some("u:r:substituted_authority:s0".to_string()),
                expected_receipt_key_id: None,
                allow_uid_discovery: false,
                allow_host_test_uid: true,
            },
        ] {
            let temp = tempfile::tempdir().unwrap();
            let socket = temp.path().join("peer-mismatch.sock");
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
                .authority_key_metadata("peer-mismatch-fixture")
                .expect_err("peer mismatch must fail closed");
            assert!(matches!(error, ToolRuntimeError::AndroidGatewayProtocol(_)));
            server.join().unwrap();
        }
    }

    #[test]
    fn adapter_exactly_retries_execute_after_post_commit_response_loss() {
        let signing_key = fixture_signing_key(14);
        let metadata = fixture_key_metadata(&signing_key);
        let (call, resolved) = fixture_call();
        let server_call = call.clone();
        let (_, server_resolved) = fixture_call();
        let peer = fixture_peer();
        let server_peer = peer.clone();

        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("verified-gateway.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server_metadata = metadata.clone();
        let server = thread::spawn(move || {
            let server_key_id = server_metadata["key_id"].clone();
            let (mut metadata_stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(metadata_stream.try_clone().unwrap())
                .read_line(&mut request)
                .unwrap();
            let request: Value = serde_json::from_str(&request).unwrap();
            assert_eq!(request["method"], "key_metadata");
            let response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": request["request_id"],
                "ok": true,
                "result": server_metadata,
            });
            serde_json::to_writer(&mut metadata_stream, &response).unwrap();
            metadata_stream.write_all(b"\n").unwrap();
            drop(metadata_stream);

            let (first_execution_stream, _) = listener.accept().unwrap();
            let mut first_execution_request = String::new();
            BufReader::new(first_execution_stream.try_clone().unwrap())
                .read_line(&mut first_execution_request)
                .unwrap();
            let request: Value = serde_json::from_str(&first_execution_request).unwrap();
            assert_eq!(request["method"], "execute");
            assert_eq!(request["expected_receipt_key_id"], server_key_id);
            assert_eq!(
                request["execution_binding"]["tool_call_id"],
                server_call.tool_call_id.0
            );
            // Model the Authority durably committing the action and losing the
            // first response. The second connection is journal replay, not a
            // second external effect.
            drop(first_execution_stream);

            let (mut retry_stream, _) = listener.accept().unwrap();
            let mut retry_request = String::new();
            BufReader::new(retry_stream.try_clone().unwrap())
                .read_line(&mut retry_request)
                .unwrap();
            assert_eq!(retry_request.as_bytes(), first_execution_request.as_bytes());
            let receipt = seal_receipt(
                fixture_receipt(
                    &server_call,
                    &server_resolved,
                    &fixture_key_metadata(&signing_key),
                    &server_peer,
                ),
                &signing_key,
            );
            let response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": request["request_id"],
                "ok": true,
                "result": fixture_output(&receipt),
            });
            serde_json::to_writer(&mut retry_stream, &response).unwrap();
            retry_stream.write_all(b"\n").unwrap();
            1_u32
        });

        let manifest = executable_android_gateway_manifests().remove(0);
        let output = adapter_with_boot_frozen_receipt_key(socket, &metadata)
            .execute_tool_with_execution_payload(&manifest, &call, Some(&resolved))
            .expect("verified Authority execution should pass");
        assert_eq!(server.join().unwrap(), 1, "external effect was duplicated");
        assert_eq!(output["action_ok"], true);
    }

    #[test]
    fn execute_frame_closes_metadata_to_dispatch_authority_restart_race() {
        let boot_key = fixture_signing_key(53);
        let boot_metadata = fixture_key_metadata(&boot_key);
        let restarted_key = fixture_signing_key(54);
        let restarted_metadata = fixture_key_metadata(&restarted_key);
        let (call, resolved) = fixture_call();

        let temp = tempfile::tempdir().unwrap();
        let socket = temp.path().join("authority-restart-key-race.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server_boot_metadata = boot_metadata.clone();
        let current_key_id = restarted_metadata["key_id"].as_str().unwrap().to_string();
        let server = thread::spawn(move || {
            let (mut metadata_stream, _) = listener.accept().unwrap();
            let mut metadata_request = String::new();
            BufReader::new(metadata_stream.try_clone().unwrap())
                .read_line(&mut metadata_request)
                .unwrap();
            let metadata_request: Value = serde_json::from_str(&metadata_request).unwrap();
            assert_eq!(metadata_request["method"], "key_metadata");
            let metadata_response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": metadata_request["request_id"],
                "ok": true,
                "result": server_boot_metadata,
            });
            serde_json::to_writer(&mut metadata_stream, &metadata_response).unwrap();
            metadata_stream.write_all(b"\n").unwrap();
            drop(metadata_stream);

            // Model a process restart between the read-only metadata connection
            // and the mutating execute connection. Authority B sees the boot-key-A
            // precondition inside the exact durable frame and rejects before state.
            let (mut execution_stream, _) = listener.accept().unwrap();
            let mut execution_request = String::new();
            BufReader::new(execution_stream.try_clone().unwrap())
                .read_line(&mut execution_request)
                .unwrap();
            let execution_request: Value = serde_json::from_str(&execution_request).unwrap();
            assert_eq!(execution_request["method"], "execute");
            let expected_key_id = execution_request["expected_receipt_key_id"]
                .as_str()
                .unwrap()
                .to_string();
            let mut replay_tombstones = 0_u32;
            let mut external_effects = 0_u32;
            if expected_key_id == current_key_id {
                replay_tombstones += 1;
                external_effects += 1;
            }
            let denial = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": execution_request["request_id"],
                "ok": false,
                "error": "gateway_request_denied",
            });
            serde_json::to_writer(&mut execution_stream, &denial).unwrap();
            execution_stream.write_all(b"\n").unwrap();
            (expected_key_id, replay_tombstones, external_effects)
        });

        let manifest = executable_android_gateway_manifests().remove(0);
        let error = adapter_with_boot_frozen_receipt_key(socket, &boot_metadata)
            .execute_tool_with_execution_payload(&manifest, &call, Some(&resolved))
            .expect_err("restarted Authority key must reject the closed execute frame");
        assert!(error.to_string().contains("gateway denied request"));
        let (expected_key_id, replay_tombstones, external_effects) = server.join().unwrap();
        assert_eq!(expected_key_id, boot_metadata["key_id"]);
        assert_eq!(replay_tombstones, 0);
        assert_eq!(external_effects, 0);
    }

    #[test]
    fn ordinary_execute_requires_matching_boot_frozen_key_before_dispatch() {
        let boot_key = fixture_signing_key(51);
        let boot_metadata = fixture_key_metadata(&boot_key);
        let replacement_key = fixture_signing_key(52);
        let replacement_metadata = fixture_key_metadata(&replacement_key);

        for (case, expected_key_id, expected_error) in [
            (
                "missing-pin",
                None,
                "Authority boot-frozen receipt key is not pinned",
            ),
            (
                "key-a-to-key-b",
                Some(boot_metadata["key_id"].as_str().unwrap().to_string()),
                "Authority receipt key differs from the boot-frozen SPKI digest",
            ),
        ] {
            let (call, resolved) = fixture_call();
            let manifest = executable_android_gateway_manifests().remove(0);
            let temp = tempfile::tempdir().unwrap();
            let socket = temp.path().join(format!("{case}.sock"));
            let listener = UnixListener::bind(&socket).unwrap();
            let server_metadata = replacement_metadata.clone();
            let (client_done_tx, client_done_rx) = mpsc::channel();
            let server = thread::spawn(move || {
                let (mut metadata_stream, _) = listener.accept().unwrap();
                let mut request_line = String::new();
                BufReader::new(metadata_stream.try_clone().unwrap())
                    .read_line(&mut request_line)
                    .unwrap();
                let request: Value = serde_json::from_str(&request_line).unwrap();
                assert_eq!(request["method"], "key_metadata");
                let response = json!({
                    "protocol": ANDROID_GATEWAY_PROTOCOL,
                    "request_id": request["request_id"],
                    "ok": true,
                    "result": server_metadata,
                });
                serde_json::to_writer(&mut metadata_stream, &response).unwrap();
                metadata_stream.write_all(b"\n").unwrap();
                drop(metadata_stream);

                listener.set_nonblocking(true).unwrap();
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    if client_done_rx.try_recv().is_ok() {
                        return None;
                    }
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let mut mutating_request = String::new();
                            BufReader::new(stream.try_clone().unwrap())
                                .read_line(&mut mutating_request)
                                .unwrap();
                            let request: Value = serde_json::from_str(&mutating_request).unwrap();
                            let response = json!({
                                "protocol": ANDROID_GATEWAY_PROTOCOL,
                                "request_id": request["request_id"],
                                "ok": false,
                                "error": "gateway_request_denied",
                            });
                            serde_json::to_writer(&mut stream, &response).unwrap();
                            stream.write_all(b"\n").unwrap();
                            return request["method"].as_str().map(str::to_string);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("unexpected listener error: {error}"),
                    }
                    assert!(
                        std::time::Instant::now() < deadline,
                        "client did not finish the metadata-only request"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
            });

            let mut adapter = AndroidGatewayAdapter::new(socket);
            adapter.peer_policy.expected_receipt_key_id = expected_key_id;
            let error = adapter
                .execute_tool_with_execution_payload(&manifest, &call, Some(&resolved))
                .expect_err("missing or changed boot key must reject ordinary execution");
            assert!(
                error.to_string().contains(expected_error),
                "{case}: {error}"
            );
            let _ = client_done_tx.send(());
            assert_eq!(
                server.join().unwrap(),
                None,
                "{case}: execute reached Authority before boot key validation"
            );
        }
    }

    #[cfg(feature = "dev-conformance-fault-hook")]
    #[test]
    fn dev_fault_hook_requires_closed_denial_then_retries_exact_undo_bytes() {
        let _env = DEV_FAULT_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let signing_key = fixture_signing_key(41);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_key_peer = fixture_peer();
        let (call, payload_sha256) = fixture_notification_call();
        let binding = call.agent_execution_binding.as_ref().unwrap().clone();
        let source_receipt = seal_receipt(
            annotate_same_abi(fixture_notification_receipt(
                &call,
                &metadata,
                &authority_key_peer,
            )),
            &signing_key,
        );
        let source_result = fixture_undoable_output(&source_receipt);
        let source_receipt_id = source_receipt["receipt_id"].as_str().unwrap().to_string();
        let request_id = format!("undo-{source_receipt_id}");
        let undo_receipt = fixture_undo_receipt(&source_receipt, &request_id, &signing_key);
        let undo_result = fixture_undoable_output(&undo_receipt);
        let frozen_pin = fixture_frozen_pin(&metadata);
        let frame = json!({
            "protocol": ANDROID_GATEWAY_PROTOCOL,
            "method": "undo",
            "request_id": request_id,
            "receipt_id": source_receipt_id,
            "execution_payload_sha256": payload_sha256,
            "execution_binding": binding,
        });
        let frame_bytes = serde_json::to_vec(&frame).unwrap();

        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = temp.path().join("dev-fault-undo.sock");
        let spec_path = temp.path().join("fault-hook.json");
        let adapter = AndroidGatewayAdapter::new(&socket);
        let now = trillionnium_os_types::now_unix_ms();
        let run_id = "6".repeat(32);
        let spec = crate::dev_conformance_fault::DevConformanceFaultSpec {
            schema: crate::dev_conformance_fault::SPEC_SCHEMA.to_string(),
            fault: "drop_verified_post_commit_undo_response_once".to_string(),
            run_id: run_id.clone(),
            fault_id: crate::dev_conformance_fault::fault_id_for(
                &run_id,
                "undo",
                &request_id,
                &call.tool_call_id.0,
            ),
            postboot_request_sha256: "4".repeat(64),
            install_session_id: "5".repeat(64),
            same_abi_run_started_at_unix_ms: 500,
            target_method: "undo".to_string(),
            target_request_id: request_id.clone(),
            request_frame_sha256: trillionnium_os_types::sha256_bytes(&frame_bytes),
            expected_action: NOTIFICATION_ACTION.to_string(),
            expected_source_receipt_id: Some(source_receipt_id.clone()),
            execution_payload_sha256: payload_sha256.clone(),
            execution_binding: binding.clone(),
            issued_at_ms: now,
            expires_at_ms: now + 30_000,
        };
        let mut spec_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&spec_path)
            .unwrap();
        serde_json::to_writer(&mut spec_file, &spec).unwrap();
        spec_file.sync_all().unwrap();
        // SAFETY: this test serializes all access to the process-global test-only override.
        unsafe { std::env::set_var("TRILLIONNIUM_DEV_CONFORMANCE_FAULT_SPEC", &spec_path) };

        let listener = UnixListener::bind(&socket).unwrap();
        let server_metadata = metadata.clone();
        let success_request_id = request_id.clone();
        let server = thread::spawn(move || {
            let (mut metadata_stream, _) = listener.accept().unwrap();
            let mut metadata_request = String::new();
            BufReader::new(metadata_stream.try_clone().unwrap())
                .read_line(&mut metadata_request)
                .unwrap();
            let metadata_request: Value = serde_json::from_str(&metadata_request).unwrap();
            let metadata_response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": metadata_request["request_id"],
                "ok": true,
                "result": server_metadata,
            });
            serde_json::to_writer(&mut metadata_stream, &metadata_response).unwrap();
            metadata_stream.write_all(b"\n").unwrap();
            drop(metadata_stream);

            let success = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": success_request_id,
                "ok": true,
                "result": undo_result,
            });
            let mut success_bytes = serde_json::to_vec(&success).unwrap();
            success_bytes.push(b'\n');

            let mut requests = Vec::new();
            for stage in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut request)
                    .unwrap();
                requests.push(request.clone());
                if stage == 1 {
                    let denial = json!({
                        "protocol": ANDROID_GATEWAY_PROTOCOL,
                        "request_id": success_request_id,
                        "ok": false,
                        "error": "gateway_request_denied",
                    });
                    serde_json::to_writer(&mut stream, &denial).unwrap();
                    stream.write_all(b"\n").unwrap();
                } else {
                    stream.write_all(&success_bytes).unwrap();
                }
            }
            requests
        });

        let output = adapter
            .undo_receipt(
                &request_id,
                &source_receipt_id,
                &source_result,
                &binding,
                &payload_sha256,
                &frozen_pin,
            )
            .expect("dev undo response-loss hook must recover internally");
        let requests = server.join().unwrap();
        // SAFETY: the serialized test owns the override and removes it before releasing the lock.
        unsafe { std::env::remove_var("TRILLIONNIUM_DEV_CONFORMANCE_FAULT_SPEC") };
        assert_eq!(output.receipt_id, undo_receipt["receipt_id"]);
        assert_eq!(requests[0].as_bytes(), requests[2].as_bytes());
        let original: Value = serde_json::from_str(&requests[0]).unwrap();
        let mutation: Value = serde_json::from_str(&requests[1]).unwrap();
        let mut expected_mutation = original.clone();
        expected_mutation["execution_binding"]["agent_id"] =
            json!(format!("fault-probe-agent-{run_id}"));
        assert_eq!(mutation, expected_mutation);
        let audit_path = temp
            .path()
            .join(format!("fault-hook.consumed.{}.audit.json", spec.fault_id));
        let audit: Value = serde_json::from_slice(&fs::read(audit_path).unwrap()).unwrap();
        assert_eq!(
            audit["build_marker"],
            crate::dev_conformance_fault::BUILD_MARKER
        );
        assert_eq!(audit["mutation_denied_before_original_retry"], true);
        assert_eq!(audit["request_retry_byte_identical"], true);
        assert_eq!(audit["authority_replay_response_byte_identical"], true);
        assert_eq!(audit["decision"], "PASS_EXACT_UNDO_RESPONSE_LOSS_RECOVERY");
        assert!(audit["external_effect_count_observed_by_hook"].is_null());
    }

    #[cfg(feature = "dev-conformance-fault-hook")]
    #[test]
    fn undo_exactly_retries_first_post_commit_eof() {
        let _env = DEV_FAULT_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap();
        let signing_key = fixture_signing_key(42);
        let metadata = fixture_key_metadata(&signing_key);
        let authority_peer = fixture_peer();
        let (call, payload_sha256) = fixture_notification_call();
        let binding = call.agent_execution_binding.as_ref().unwrap().clone();
        let source_receipt = seal_receipt(
            annotate_same_abi(fixture_notification_receipt(
                &call,
                &metadata,
                &authority_peer,
            )),
            &signing_key,
        );
        let source_result = fixture_undoable_output(&source_receipt);
        let source_receipt_id = source_receipt["receipt_id"].as_str().unwrap().to_string();
        let request_id = format!("undo-{source_receipt_id}");
        let undo_receipt = fixture_undo_receipt(&source_receipt, &request_id, &signing_key);
        let undo_result = fixture_undoable_output(&undo_receipt);
        let frozen_pin = fixture_frozen_pin(&metadata);

        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = temp.path().join("dev-fault-no-generic-retry.sock");
        let missing_spec_path = temp.path().join("no-fault-armed.json");
        // SAFETY: this test serializes all access to the process-global test-only override.
        unsafe {
            std::env::set_var(
                "TRILLIONNIUM_DEV_CONFORMANCE_FAULT_SPEC",
                &missing_spec_path,
            )
        };

        let listener = UnixListener::bind(&socket).unwrap();
        let server_metadata = metadata.clone();
        let success_request_id = request_id.clone();
        let server = thread::spawn(move || {
            let (mut metadata_stream, _) = listener.accept().unwrap();
            let mut metadata_request = String::new();
            BufReader::new(metadata_stream.try_clone().unwrap())
                .read_line(&mut metadata_request)
                .unwrap();
            let metadata_request: Value = serde_json::from_str(&metadata_request).unwrap();
            let metadata_response = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": metadata_request["request_id"],
                "ok": true,
                "result": server_metadata,
            });
            serde_json::to_writer(&mut metadata_stream, &metadata_response).unwrap();
            metadata_stream.write_all(b"\n").unwrap();
            drop(metadata_stream);

            let (first_undo_stream, _) = listener.accept().unwrap();
            let mut first_undo_request = String::new();
            BufReader::new(first_undo_stream.try_clone().unwrap())
                .read_line(&mut first_undo_request)
                .unwrap();
            drop(first_undo_stream);

            let (mut retry_stream, _) = listener.accept().unwrap();
            let mut retry_request = String::new();
            BufReader::new(retry_stream.try_clone().unwrap())
                .read_line(&mut retry_request)
                .unwrap();
            let success = json!({
                "protocol": ANDROID_GATEWAY_PROTOCOL,
                "request_id": success_request_id,
                "ok": true,
                "result": undo_result,
            });
            serde_json::to_writer(&mut retry_stream, &success).unwrap();
            retry_stream.write_all(b"\n").unwrap();
            (first_undo_request, retry_request, 1_u32)
        });

        let output = AndroidGatewayAdapter::new(&socket)
            .undo_receipt(
                &request_id,
                &source_receipt_id,
                &source_result,
                &binding,
                &payload_sha256,
                &frozen_pin,
            )
            .expect("the first undo EOF must recover by exact durable replay");
        // SAFETY: the serialized test owns the override and removes it before releasing the lock.
        unsafe { std::env::remove_var("TRILLIONNIUM_DEV_CONFORMANCE_FAULT_SPEC") };
        let (first_undo_request, retry_request, external_effect_count) = server.join().unwrap();
        assert_eq!(output.receipt_id, undo_receipt["receipt_id"]);
        assert_eq!(first_undo_request.as_bytes(), retry_request.as_bytes());
        let undo_request: Value = serde_json::from_str(&first_undo_request).unwrap();
        assert_eq!(undo_request["method"], "undo");
        assert_eq!(undo_request["request_id"], request_id);
        assert_eq!(external_effect_count, 1, "undo side effect was duplicated");
        assert!(!missing_spec_path.exists());
    }

    #[test]
    fn strict_json_rejects_duplicate_receipt_fields() {
        assert!(parse_strict_json("{\"schema\":1,\"schema\":2}", "fixture").is_err());
        assert!(parse_strict_json("{\"receipt_at_ms\":1.5}", "fixture").is_err());
    }
}
