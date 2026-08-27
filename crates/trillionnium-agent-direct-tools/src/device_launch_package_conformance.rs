//! P0-1 non-product `launch_package` device-conformance lane.
//!
//! This module is physically absent unless the dedicated Cargo feature is
//! selected. It never exposes a caller-selected backend, Android user, target
//! package, replay endpoint, epoch, or operation sequence. The only semantic
//! effect it will issue is `launch_package(com.android.settings)` for user 0.
//! It consumes the fixed root-authored invocation inbox, durably journals the
//! exact Android `op:<epoch>:<sequence>:<canonical-sha256>` identity before the
//! backend and releases the exact durable result before any outer ACK is
//! accepted. ACK publication and local compaction are reserved to the
//! endpoint-specific operation replay-sync helper. The legacy `reconcile-ack`
//! CLI now returns HOLD because a tool-domain process is not an Android ACK
//! role. A restart before host persistence replays the retained response
//! without re-effecting the backend.
//!
//! This remains a non-product userdebug-only source candidate: local journal
//! first use and mutation use fsync/rename without claiming the unavailable
//! product external rollback/mutation-CAS authorities.

use serde::Deserialize;
use serde_json::{Value, json};
#[cfg(test)]
use sha2::{Digest as _, Sha256};
use std::path::Path;

use trillionnium_os_types::agent_principal_registry::CODEX_STABLE_PRINCIPAL;
use trillionnium_os_types::direct_operation::DirectOperationAdapter;

use crate::android_operation_replay_control::activate_system_api_for_device_conformance;
use crate::operation_journal::OperationJournal;
use crate::system_api::{self, SystemApiSemanticRequest};
use crate::trusted_context::TrustedAdapterContext;
use crate::{DirectToolError, Result, mcp, read_request, write_response};

pub const EVIDENCE_SCHEMA: &str = "org.trillionnium.p0-1.launch-package-device-conformance.v2";
pub const LANE: &str = "non_product_userdebug_only";
pub const TARGET_PACKAGE: &str = "com.android.settings";
pub const TOOL_NAME: &str = "trillionnium_system_api";
pub const SEMANTIC_ACTION: &str = "launch_package";
pub const ACTIVATION_STATUS: &str = "exact_created_or_restart_reconciled";

const SERVER_NAME: &str = "trillionnium-agent-system-api-p0-1-device-conformance";
const COMPILED_BUILD_VARIANT: Option<&str> =
    option_env!("TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT");
const BUILD_VARIANT_EVIDENCE_BYTES: usize = 96;
const BUILD_VARIANT_EVIDENCE_PREFIX: &str = "org.trillionnium.p01.conformance.compiled-variant.v1=";

// Keep the selected compile-time lane in a dedicated ELF section. A packaging
// verifier can read this exact fixed-width value without executing the helper
// or mistaking the source's accepted `userdebug` branch string for the
// selected artifact identity.
#[used]
#[unsafe(link_section = ".trillionnium.p01.variant")]
#[cfg(p01_conformance_variant = "userdebug")]
static COMPILED_BUILD_VARIANT_EVIDENCE: [u8; BUILD_VARIANT_EVIDENCE_BYTES] =
    build_variant_evidence("userdebug");

#[used]
#[unsafe(link_section = ".trillionnium.p01.variant")]
#[cfg(p01_conformance_variant = "invalid")]
static COMPILED_BUILD_VARIANT_EVIDENCE: [u8; BUILD_VARIANT_EVIDENCE_BYTES] =
    build_variant_evidence("invalid");

const fn build_variant_evidence(selected: &str) -> [u8; BUILD_VARIANT_EVIDENCE_BYTES] {
    let prefix = BUILD_VARIANT_EVIDENCE_PREFIX.as_bytes();
    let selected = selected.as_bytes();
    let mut output = [0_u8; BUILD_VARIANT_EVIDENCE_BYTES];
    let mut index = 0;
    while index < prefix.len() {
        output[index] = prefix[index];
        index += 1;
    }
    let mut selected_index = 0;
    while selected_index < selected.len() {
        output[index + selected_index] = selected[selected_index];
        selected_index += 1;
    }
    output
}

#[must_use]
pub fn compiled_build_variant_evidence() -> &'static [u8; BUILD_VARIANT_EVIDENCE_BYTES] {
    &COMPILED_BUILD_VARIANT_EVIDENCE
}

/// Run the distinct non-product System API binary.
///
/// The build variant is embedded at compile time; runtime environment
/// variables cannot promote this lane. Android packaging must additionally
/// keep this binary in `PRODUCT_PACKAGES_DEBUG` and physically absent from user
/// images before a device run is allowed.
pub fn run_system_api() -> Result<()> {
    let _compiled_artifact_identity = compiled_build_variant_evidence();
    require_compiled_non_product_build_variant(COMPILED_BUILD_VARIANT)?;
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    match arguments.as_slice() {
        [mode] if mode == "semantic" => {
            let mut session = DeviceConformanceEffectSession::open()?;
            let request: SystemApiSemanticRequest = read_request()?;
            write_response(&session.execute(request)?)
        }
        [mode] if mode == "mcp" => {
            let mut session = DeviceConformanceEffectSession::open()?;
            mcp::serve_stdio(SERVER_NAME, mcp_tool(), |arguments| {
                let request = serde_json::from_value(arguments)?;
                session.execute(request)
            })
        }
        [mode] if mode == "reconcile-ack" => write_response(&reconcile_pending_outer_ack()?),
        _ => Err(DirectToolError::InvalidRequest(
            "usage: trillionnium-agent-system-api-device-conformance [semantic|mcp|reconcile-ack]"
                .to_string(),
        )),
    }
}

struct DeviceConformanceEffectSession {
    context: TrustedAdapterContext,
    journal: OperationJournal,
}

impl DeviceConformanceEffectSession {
    fn open() -> Result<Self> {
        let context = TrustedAdapterContext::open_current_device_conformance(
            DirectOperationAdapter::SystemApi,
        )
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?;
        let mut journal = OperationJournal::open_device_conformance(&context)
            .map_err(crate::journaled_call::journal_error)?;
        require_no_pending_outer_ack(&context)?;
        let replay_state = journal
            .device_conformance_replay_state()
            .map_err(crate::journaled_call::journal_error)?;
        let activation = activate_system_api_for_device_conformance(&replay_state, None, &context)?;
        journal
            .install_device_conformance_epoch_authority(activation)
            .map_err(crate::journaled_call::journal_error)?;
        Ok(Self { context, journal })
    }

    fn execute(&mut self, semantic: SystemApiSemanticRequest) -> Result<Value> {
        require_fixed_semantic_request(&semantic)?;
        // A pending ACK proves that the upper host persisted a prior result.
        // It can be consumed only by the explicit non-effect reconcile phase.
        require_no_pending_outer_ack(&self.context)?;
        system_api::call_semantic_device_conformance(
            Path::new(system_api::DEFAULT_SOCKET),
            &semantic,
            &self.context,
            &mut self.journal,
        )
    }
}

/// Reconcile a host-persisted result in a process that cannot execute another
/// model-selected operation. The tool-domain conformance binary is not an
/// Android replay-control ACK role and must never compact the local journal.
/// Phase A requires the dedicated System API operation replay-sync helper;
/// daemon launch/custody wiring is still HOLD, so this legacy CLI mode stops
/// without reading or applying the ACK.
fn reconcile_pending_outer_ack() -> Result<Value> {
    Err(DirectToolError::BackendUnavailable(
        "P0 ACK reconciliation requires trillionnium-system-api-device-conformance-replay-sync; its daemon sealed launch wiring remains unavailable"
            .to_string(),
    ))
}

fn require_no_pending_outer_ack(context: &TrustedAdapterContext) -> Result<()> {
    if context
        .pending_outer_ack_v3_for_device_conformance()
        .map_err(|error| DirectToolError::BackendUnavailable(error.to_string()))?
        .is_some()
    {
        return Err(DirectToolError::BackendUnavailable(
            "P0 pending outer ACK requires trillionnium-system-api-device-conformance-replay-sync; its daemon sealed launch wiring remains unavailable"
                .to_string(),
        ));
    }
    Ok(())
}

fn require_fixed_semantic_request(request: &SystemApiSemanticRequest) -> Result<()> {
    match request {
        SystemApiSemanticRequest::LaunchPackage { package } if package == TARGET_PACKAGE => Ok(()),
        _ => Err(DirectToolError::InvalidRequest(format!(
            "P0-1 device conformance permits only launch_package({TARGET_PACKAGE})"
        ))),
    }
}

fn require_compiled_non_product_build_variant(value: Option<&str>) -> Result<&str> {
    match value {
        Some("userdebug") => Ok("userdebug"),
        _ => Err(DirectToolError::BackendUnavailable(
            "P0-1 device-conformance binary lacks an embedded userdebug-only build identity"
                .to_string(),
        )),
    }
}

#[cfg(test)]
fn lower_hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(ALPHABET[(byte >> 4) as usize] as char);
        encoded.push(ALPHABET[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn mcp_tool() -> mcp::McpTool {
    mcp::McpTool {
        name: TOOL_NAME,
        description: "Non-product P0-1 conformance: open Android Settings through the canonical System API.",
        input_schema: json!({
            "type": "object",
            "required": ["action", "package"],
            "properties": {
                "action": {"const": SEMANTIC_ACTION},
                "package": {"const": TARGET_PACKAGE}
            },
            "additionalProperties": false
        }),
    }
}

/// Strict per-provider receipt accepted by the future host/device collector.
///
/// The durability/ACK flags are accepted only when the device collector has
/// observed the complete conformance chain.  Product availability and P0-3
/// payload claims remain structurally false.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceConformanceEvidence {
    schema: String,
    lane: String,
    status: String,
    provider_id: String,
    provider_version: String,
    agent_id: String,
    build_variant: String,
    build_fingerprint: String,
    target_package: String,
    foreground_package: String,
    semantic_tool: String,
    semantic_action: String,
    activation_status: String,
    operation_sequence: u64,
    backend_ok: bool,
    model_invoked_tool: bool,
    model_completed_tool_call: bool,
    completed_direct_tool_calls: u64,
    system_server_backend_observed: bool,
    durable_result_recorded: bool,
    restart_replay_proven: bool,
    android_replay_ack_proven: bool,
    legacy_bridge_used: bool,
    authority_called: bool,
    provider_adb_used: bool,
    product_available: bool,
    exactly_once_proven: bool,
    outer_ack_proven: bool,
    p0_3_payload_evidence: bool,
    backend_request_id_sha256: String,
    backend_result_sha256: String,
    provider_direct_result_sha256: String,
    foreground_observation_sha256: String,
    journal_evidence_snapshot_sha256: String,
    outer_ack_sha256: String,
    android_ack_chain_sha256: String,
}

/// Parse the legacy self-reported shape, then return HOLD. JSON booleans and
/// non-zero strings are not device evidence and can never promote a provider
/// run. A future root collector must independently bind and recompute the
/// provider, binding, invocation, attempt, journal epoch, boot, device,
/// foreground observation, Android ACK and host-durable receipt.
pub fn validate_evidence(raw: &[u8]) -> Result<()> {
    validate_self_reported_evidence_shape(raw)?;
    Err(DirectToolError::BackendUnavailable(
        "P0 conformance evidence is shape-only self-report; authenticated root artifact collector is unavailable"
            .to_string(),
    ))
}

fn validate_self_reported_evidence_shape(raw: &[u8]) -> Result<()> {
    if raw.is_empty() || raw.len() > crate::MAX_REQUEST_BYTES {
        return Err(invalid_evidence("evidence byte length is invalid"));
    }
    let evidence: DeviceConformanceEvidence = serde_json::from_slice(raw)?;
    let provider_matches = evidence.provider_id == CODEX_STABLE_PRINCIPAL.provider_id
        && evidence.provider_version == "0.144.1"
        && evidence.agent_id == CODEX_STABLE_PRINCIPAL.agent_id;
    let fingerprint_matches = match evidence.build_variant.as_str() {
        "userdebug" => evidence.build_fingerprint.contains(":userdebug/"),
        _ => false,
    };
    if evidence.schema != EVIDENCE_SCHEMA
        || evidence.lane != LANE
        || evidence.status != "pass"
        || !provider_matches
        || !fingerprint_matches
        || evidence.target_package != TARGET_PACKAGE
        || evidence.foreground_package != TARGET_PACKAGE
        || evidence.semantic_tool != TOOL_NAME
        || evidence.semantic_action != SEMANTIC_ACTION
        || evidence.activation_status != ACTIVATION_STATUS
        || evidence.operation_sequence != 1
        || !evidence.backend_ok
        || !evidence.model_invoked_tool
        || !evidence.model_completed_tool_call
        || evidence.completed_direct_tool_calls != 1
        || !evidence.system_server_backend_observed
        || !evidence.durable_result_recorded
        || !evidence.restart_replay_proven
        || !evidence.android_replay_ack_proven
        || evidence.legacy_bridge_used
        || evidence.authority_called
        || evidence.provider_adb_used
        || evidence.product_available
        || !evidence.exactly_once_proven
        || !evidence.outer_ack_proven
        || evidence.p0_3_payload_evidence
    {
        return Err(invalid_evidence(
            "closed evidence identity or proof flags mismatch",
        ));
    }
    for digest in [
        &evidence.backend_request_id_sha256,
        &evidence.backend_result_sha256,
        &evidence.provider_direct_result_sha256,
        &evidence.foreground_observation_sha256,
        &evidence.journal_evidence_snapshot_sha256,
        &evidence.outer_ack_sha256,
        &evidence.android_ack_chain_sha256,
    ] {
        if !valid_nonzero_sha256(digest) {
            return Err(invalid_evidence("evidence digest is invalid"));
        }
    }
    Ok(())
}

fn valid_nonzero_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn invalid_evidence(reason: &str) -> DirectToolError {
    DirectToolError::InvalidRequest(format!("P0-1 conformance evidence rejected: {reason}"))
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::*;
    use crate::risk_guard::AgentIdentity;
    use crate::system_api::SystemApiRequest;

    const EPOCH: &str = "00112233445566778899aabbccddeeff";
    const GOLDEN_CONTRACT: &[u8] =
        include_bytes!("../contracts/device-launch-package-conformance-v2.json");

    fn fixed_operation_id(agent: AgentIdentity) -> String {
        let request = SystemApiRequest::LaunchPackage {
            protocol: system_api::PROTOCOL.to_string(),
            request_id: "pending".to_string(),
            package: TARGET_PACKAGE.to_string(),
            user: 0,
        };
        let canonical = crate::canonical_operation::system_api_request(agent, &request).unwrap();
        format!("op:{EPOCH}:1:{}", lower_hex(&Sha256::digest(canonical)))
    }

    fn valid_evidence(provider: AgentIdentity) -> Value {
        let (provider_id, provider_version, agent_id) = match provider {
            AgentIdentity::Codex => (
                CODEX_STABLE_PRINCIPAL.provider_id,
                "0.144.1",
                CODEX_STABLE_PRINCIPAL.agent_id,
            ),
        };
        json!({
            "schema": EVIDENCE_SCHEMA,
            "lane": LANE,
            "status": "pass",
            "provider_id": provider_id,
            "provider_version": provider_version,
            "agent_id": agent_id,
            "build_variant": "userdebug",
            "build_fingerprint": "trillionnium/fogos/device:16/BP4A/test:userdebug/test-keys",
            "target_package": TARGET_PACKAGE,
            "foreground_package": TARGET_PACKAGE,
            "semantic_tool": TOOL_NAME,
            "semantic_action": SEMANTIC_ACTION,
            "activation_status": ACTIVATION_STATUS,
            "operation_sequence": 1,
            "backend_ok": true,
            "model_invoked_tool": true,
            "model_completed_tool_call": true,
            "completed_direct_tool_calls": 1,
            "system_server_backend_observed": true,
            "durable_result_recorded": true,
            "restart_replay_proven": true,
            "android_replay_ack_proven": true,
            "legacy_bridge_used": false,
            "authority_called": false,
            "provider_adb_used": false,
            "product_available": false,
            "exactly_once_proven": true,
            "outer_ack_proven": true,
            "p0_3_payload_evidence": false,
            "backend_request_id_sha256": "1".repeat(64),
            "backend_result_sha256": "2".repeat(64),
            "provider_direct_result_sha256": "3".repeat(64),
            "foreground_observation_sha256": "4".repeat(64),
            "journal_evidence_snapshot_sha256": "5".repeat(64),
            "outer_ack_sha256": "6".repeat(64),
            "android_ack_chain_sha256": "7".repeat(64)
        })
    }

    #[test]
    fn only_userdebug_compile_identity_is_accepted() {
        assert_eq!(
            require_compiled_non_product_build_variant(Some("userdebug")).unwrap(),
            "userdebug"
        );
        for invalid in [
            None,
            Some(""),
            Some("user"),
            Some("eng"),
            Some("recovery"),
            Some("release"),
            Some("USERDEBUG"),
        ] {
            assert!(require_compiled_non_product_build_variant(invalid).is_err());
        }
    }

    #[test]
    fn artifact_evidence_section_matches_the_selected_compile_identity() {
        let evidence = compiled_build_variant_evidence();
        let end = evidence
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(evidence.len());
        let evidence = std::str::from_utf8(&evidence[..end]).unwrap();
        let expected = match COMPILED_BUILD_VARIANT {
            Some("userdebug") => "userdebug",
            _ => "invalid",
        };
        assert_eq!(
            evidence,
            format!("{BUILD_VARIANT_EVIDENCE_PREFIX}{expected}")
        );
    }

    #[test]
    fn fixed_target_is_the_only_semantic_request() {
        require_fixed_semantic_request(&SystemApiSemanticRequest::LaunchPackage {
            package: TARGET_PACKAGE.to_string(),
        })
        .unwrap();
        assert!(
            require_fixed_semantic_request(&SystemApiSemanticRequest::LaunchPackage {
                package: "com.android.camera".to_string(),
            })
            .is_err()
        );
        assert!(
            require_fixed_semantic_request(&SystemApiSemanticRequest::OpenUri {
                uri: "https://example.com".to_string(),
            })
            .is_err()
        );
    }

    #[test]
    fn effect_delivery_and_ack_reconciliation_are_source_separated() {
        let source = include_str!("device_launch_package_conformance.rs");
        let effect = source
            .split_once("impl DeviceConformanceEffectSession")
            .unwrap()
            .1
            .split_once("fn reconcile_pending_outer_ack()")
            .unwrap()
            .0;
        assert!(effect.contains("call_semantic_device_conformance"));
        assert!(!effect.contains("os_tool_call_id"));
        let retired_fixed_id = ["derive_fixed_", "os_tool_call_id"].concat();
        assert!(!source.contains(&retired_fixed_id));
        let system_api = include_str!("system_api.rs");
        assert!(system_api.contains("prepare_p0_userdebug_effect"));
        assert!(!effect.contains("acknowledge_outer_v3"));
        assert!(!effect.contains("acknowledge_system_api_for_device_conformance"));

        let reconcile = source
            .split_once("fn reconcile_pending_outer_ack()")
            .unwrap()
            .1
            .split_once("fn require_no_pending_outer_ack")
            .unwrap()
            .0;
        assert!(reconcile.contains("trillionnium-system-api-device-conformance-replay-sync"));
        assert!(reconcile.contains("BackendUnavailable"));
        assert!(!reconcile.contains("acknowledge_outer_v3"));
        assert!(!reconcile.contains("acknowledge_system_api_for_device_conformance"));
        assert!(!reconcile.contains("call_semantic_device_conformance"));
        assert!(!reconcile.contains("SystemApiSemanticRequest"));
        let legacy_wait = ["await_root_", "outer_ack"].concat();
        let blocking_sleep = ["std::thread::", "sleep"].concat();
        assert!(!source.contains(&legacy_wait));
        assert!(!source.contains(&blocking_sleep));
    }

    #[test]
    fn operation_ids_match_the_cross_language_canonical_binding() {
        let contract: Value = serde_json::from_slice(GOLDEN_CONTRACT).unwrap();
        assert_eq!(contract["schema"], EVIDENCE_SCHEMA);
        assert_eq!(contract["lane"], LANE);
        assert_eq!(contract["tool"], TOOL_NAME);
        assert_eq!(contract["action"], SEMANTIC_ACTION);
        assert_eq!(contract["package"], TARGET_PACKAGE);
        assert_eq!(contract["android_user"], 0);
        assert_eq!(contract["fixed_epoch_for_golden_only"], EPOCH);
        assert_eq!(
            fixed_operation_id(AgentIdentity::Codex),
            contract["providers"]["codex"]["operation_id"]
        );
        assert_eq!(contract["requires"]["durable_result"], true);
        assert_eq!(contract["requires"]["restart_replay"], true);
        assert_eq!(
            contract["requires"]["result_delivery_before_outer_ack"],
            true
        );
        assert_eq!(contract["requires"]["explicit_ack_reconcile_stage"], true);
        assert_eq!(
            contract["requires"]["effect_mode_consumes_outer_ack"],
            false
        );
        assert_eq!(contract["requires"]["outer_ack_v2"], false);
        assert_eq!(contract["requires"]["outer_ack_v3"], true);
        assert_eq!(contract["requires"]["android_replay_ack"], true);
        assert_eq!(contract["requires"]["fixed_measured_fd_handoff"], true);
        assert_eq!(
            contract["requires"]["independent_root_binding_inbox_crosscheck"],
            true
        );
        assert_eq!(
            contract["requires"]["p0_userdebug_daemon_sealed_ack_closure_source"],
            true
        );
        assert_eq!(
            contract["requires"]["p0_daemon_custody_confirmation_lane"],
            true
        );
        assert_eq!(
            contract["requires"]["durable_local_compaction_readback"],
            true
        );
        assert_eq!(contract["requires"]["daemon_ack_inbox_retirement"], true);
        for held in [
            "product_external_rollback_authority",
            "product_hardware_rollback_anchor",
            "product_mutation_cas_authority",
            "physical_device_closure_evidence",
        ] {
            assert_eq!(contract["requires"][held], false);
        }
        assert_eq!(
            contract["runtime_wiring"]["status"],
            "source_wired_system_api_only_device_evidence_hold"
        );
        assert_eq!(
            contract["runtime_wiring"]["codex_userdebug_system_api_hotpath"],
            true
        );
        assert_eq!(contract["requires"]["product_available"], false);
    }

    #[test]
    fn self_reported_codex_shape_never_becomes_evidence() {
        for provider in [AgentIdentity::Codex] {
            let encoded = serde_json::to_vec(&valid_evidence(provider)).unwrap();
            validate_self_reported_evidence_shape(&encoded).unwrap();
            assert!(matches!(
                validate_evidence(&encoded),
                Err(DirectToolError::BackendUnavailable(_))
            ));
        }
    }

    #[test]
    fn evidence_requires_full_conformance_durability_but_cannot_claim_product() {
        for field in ["product_available", "p0_3_payload_evidence"] {
            let mut evidence = valid_evidence(AgentIdentity::Codex);
            evidence[field] = Value::Bool(true);
            assert!(validate_evidence(&serde_json::to_vec(&evidence).unwrap()).is_err());
        }
        for field in [
            "durable_result_recorded",
            "restart_replay_proven",
            "android_replay_ack_proven",
            "exactly_once_proven",
            "outer_ack_proven",
        ] {
            let mut evidence = valid_evidence(AgentIdentity::Codex);
            evidence[field] = Value::Bool(false);
            assert!(validate_evidence(&serde_json::to_vec(&evidence).unwrap()).is_err());
        }
    }

    #[test]
    fn evidence_rejects_legacy_bypass_broader_target_and_non_userdebug_builds() {
        for (field, value) in [
            ("legacy_bridge_used", Value::Bool(true)),
            ("authority_called", Value::Bool(true)),
            ("provider_adb_used", Value::Bool(true)),
            (
                "target_package",
                Value::String("com.android.camera".to_string()),
            ),
            ("build_variant", Value::String("user".to_string())),
            ("build_variant", Value::String("eng".to_string())),
            ("build_variant", Value::String("recovery".to_string())),
        ] {
            let mut evidence = valid_evidence(AgentIdentity::Codex);
            evidence[field] = value;
            assert!(validate_evidence(&serde_json::to_vec(&evidence).unwrap()).is_err());
        }
    }

    #[test]
    fn evidence_rejects_unknown_duplicate_and_zero_digest_fields() {
        let mut evidence = valid_evidence(AgentIdentity::Codex);
        evidence["unexpected"] = Value::Bool(true);
        assert!(validate_evidence(&serde_json::to_vec(&evidence).unwrap()).is_err());

        let mut evidence = valid_evidence(AgentIdentity::Codex);
        evidence["backend_result_sha256"] = Value::String("0".repeat(64));
        assert!(validate_evidence(&serde_json::to_vec(&evidence).unwrap()).is_err());

        let mut fields = valid_evidence(AgentIdentity::Codex)
            .as_object()
            .cloned()
            .unwrap_or_else(Map::new);
        let provider = fields.remove("provider_id").unwrap();
        let mut raw = serde_json::to_string(&fields).unwrap();
        raw.pop();
        raw.push_str(&format!(
            ",\"provider_id\":{},\"provider_id\":{}}}",
            provider, provider
        ));
        assert!(validate_evidence(raw.as_bytes()).is_err());
    }
}
