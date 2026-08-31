use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::mem::{size_of, zeroed};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, chown};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
use std::time::Instant;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::pkcs8::DecodePublicKey;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use trillionnium_dbus::AgentService;
use trillionnium_os_types::agent_principal_registry::{self, CODEX_STABLE_PRINCIPAL as CODEX};
use trillionnium_os_types::direct_agent_host_abi::{self, DirectOutcome as ProviderDirectOutcome};
#[cfg(any(test, feature = "p0-launch-package-device-conformance"))]
use trillionnium_os_types::direct_operation::DirectOperationOuterOutcome;
use trillionnium_os_types::direct_operation::{
    DirectOperationAdapter, DirectOperationAuthorizedAdapterSetV3,
};
use trillionnium_os_types::{
    AGENT_API_VERSION, AgentHealth, AgentNetworkPolicy, AgentPlanSubmission, AgentRegistration,
    TaskInput, TaskStatus, TaskView, ToolRunStatus, now_unix_ms, sha256_bytes, sha256_json,
};
#[cfg(test)]
use trillionnium_os_types::{
    AgentExecutionBinding, AgentExecutionRequest, ApprovalRequest, ApprovalStatus, ToolRun,
};
use trillionnium_tool_runtime::AndroidGatewayAdapter;
use trillionnium_tool_runtime::supervised_codex::{
    CODEX_DIRECT_EFFECT_RECOVERY_DECISION, CapabilityClaims, CapabilityIssuer,
    CodexDirectToolCallEvidence, CodexPlanAttempt, CodexPlanAttemptLifecycle, CodexPlanningReceipt,
    CodexRuntimeEvidence, DirectBackendEffectClass, EgressBrokerTerminationReason, PlanningRequest,
    PrivacyClass, ProvenanceContext, RuntimeLifecycleBinding,
    codex_direct_mcp_identity_is_authorized, direct_backend_error_effect_class,
    validate_codex_direct_effect_recovery_receipt,
};
use zeroize::{Zeroize, Zeroizing};

use crate::codex_adapter::CompletedShellExecAuthorizationV1;

#[cfg(test)]
use crate::action_workflow::{ActionConsentState, ConsumingApprovalBinding};
use crate::action_workflow::{
    ActionWorkflowJournal, ActionWorkflowUiCustodyBinding, PlanReadyPublication,
    PlanRecoveryBinding, PlanSagaStage, PlanWorkflowRecovery, RETIRED_NON_DIRECT_WORKFLOW_REASON,
};
#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
use crate::context_memory::VerifiedDirectUiReplaySnapshot;
use crate::context_memory::{
    AgentGrantTarget, ContextMemoryService, EgressRecoveryBlobRef, Subject, UiRequestBinding,
    UiRequestRecovery, VerifiedContextCapture, canonical_https_execution_url,
};
#[cfg(test)]
use crate::context_memory::{ExecutionPayloadBinding, ExecutionPayloadDescriptor};
use crate::direct_operation_binding_inbox::{
    DirectOperationBindingInboxPublisher, DirectOperationOsIdentity,
};
#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
use crate::direct_operation_custody::DirectOperationCustodyStore;
#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
use crate::direct_tool_call_allocator::{DirectToolCallAllocator, VerifiedDaemonLogicalDelivery};
#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
use crate::direct_tool_call_transport::{
    FixedDirectToolCallListener, P0UserdebugDirectToolCallCancellation,
};
#[cfg(feature = "p0-launch-package-device-conformance")]
use crate::direct_tool_call_transport::{
    P0UserdebugDirectToolCallSessionOutcome, P0UserdebugDirectToolCallSessionTermination,
};
use crate::egress_journal::{
    EgressExpiredRevokeRequest, EgressJournalCas, EgressJournalMetadata, EgressLifecycleJournal,
    EgressLifecycleState, EgressRevokeUiOutcome, EgressTeardownAck, EgressUiCompletionBinding,
};
const PROTOCOL: &str = direct_agent_host_abi::BUILTIN_ANDROID_PROTOCOL;
const SOCKET_NAME: &str = direct_agent_host_abi::BUILTIN_ANDROID_SOCKET;
const MAX_FRAME: u64 = 262_144;
const CODEX_AGENT_ID: &str = CODEX.agent_id;
const CODEX_AGENT_SELINUX_DOMAIN: &str = CODEX.agent_selinux_domain;
const DEFAULT_CODEX_UID: u32 = CODEX.uid;
const DEFAULT_CODEX_GID: u32 = CODEX.gid;
const MAX_CODEX_AUTH_BYTES: usize = 192 * 1024;
const DEFAULT_AGENT_PRIVATE_ROOT: &str = "/var/lib/trillionnium";
const MAX_IN_FLIGHT_CONNECTIONS: usize = 16;
const MAX_PENDING_EGRESS_GRANTS: usize = 64;
const EGRESS_GRANT_TTL_MS: u64 = 120_000;
// This is only a hard resource ceiling: every actual listener deadline is
// further clamped to the exact root-issued capability expiry below.
#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
const P0_USERDEBUG_TOOL_INVOCATION_MAX_TIMEOUT: Duration = Duration::from_secs(605);
// The P0 System listener has one fixed kernel namespace.  Admission must be
// serialized before any grant consumption, Direct binding publication, or
// listener bind so a concurrent UI turn cannot strand durable custody and
// then collide on that fixed socket.  Busy callers fail before mutation.
#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
static P0_USERDEBUG_DIRECT_TURN_SERIAL: Mutex<()> = Mutex::new(());
const CODEX_PROVIDER_ID: &str = CODEX.provider_id;
const CODEX_EGRESS_ENDPOINT: &str = "chatgpt.com:443";
const EGRESS_CHALLENGE_SCHEMA: &str = "org.trillionnium.ai-authority.egress-consent-challenge.v2";
const EGRESS_POLICY_EPOCH: u64 = 1;
const PROVIDER_ABI_EPOCH: u64 = 1;
const EGRESS_CONSENT_SCHEMA: &str = "org.trillionnium.ai-authority.egress-consent.v2";
const AUTHORITY_RECEIPT_KEY_EPOCH: u64 = 2;
const AUTHORITY_SIGNATURE_ALGORITHM: &str = "SHA256withECDSA";
const AUTHORITY_ROTATION_CONTRACT: &str = "os_authorized_monotonic_epoch_and_pinned_key_id";
const AUTHORITY_IDENTITY_VERIFICATION: &str =
    "os_pin_key_id_and_validate_keymint_attestation_chain";
const AUTHORITY_USERDEBUG_LOCAL_IDENTITY_VERIFICATION: &str =
    "userdebug_signed_image_pin_key_id_and_hardware_security_level_no_attestation";
const AUTHORITY_ATTESTED_KEY_PROFILE: &str = "keymint_attested_v1";
const AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE: &str = "userdebug_local_hardware_v1";
const AUTHORITY_USERDEBUG_LOCAL_PROFILE_ENV: &str = "TRILLIONNIUM_P01_AUTHORITY_KEY_PROFILE";
const AUTHORITY_ATTESTATION_UNAVAILABLE: &str = "unavailable";
const AUTHORITY_ATTESTATION_CHALLENGE: &[u8] = b"org.trillionnium.ai-authority.receipt-key.v2";
const EGRESS_UPLOAD_MAX_BYTES: u64 = 4 * 1024 * 1024;
const EGRESS_DOWNLOAD_MAX_BYTES: u64 = 4 * 1024 * 1024;
const EGRESS_CLOCK_SKEW_MS: u64 = 5_000;
const EGRESS_RECOVERY_SCHEMA: &str = "trillionnium.egress-recovery-envelope.v1";
const EGRESS_RECOVERY_AAD_SCHEMA: &str = "trillionnium.egress-recovery-aad.v1";
const EGRESS_RECOVERY_FORMAT_VERSION: u32 = 1;
#[cfg(test)]
const ACTION_CONSENT_CHALLENGE_SCHEMA: &str =
    "org.trillionnium.ai-authority.action-consent-challenge.v2";
#[cfg(test)]
const ACTION_CONSENT_SCHEMA: &str = "org.trillionnium.ai-authority.action-consent.v2";
#[cfg(test)]
const ACTION_CONSENT_TTL_MS: u64 = 120_000;
const CONTEXT_CAPTURE_SCHEMA: &str = "org.trillionnium.ai-authority.context-capture.v1";
const CONTEXT_RESOLUTION_SCHEMA: &str = "org.trillionnium.ai-authority.context-resolution.v1";
const CONTEXT_CAPTURE_RECOVERY_SCHEMA: &str =
    "org.trillionnium.ai-authority.context-capture-recovery.v4";
const CONTEXT_CAPTURE_TTL_MS: u64 = 120_000;
const MAX_CONTEXT_CAPTURE_BYTES: u64 = 65_536;
const MAX_HTTPS_URL_BYTES: usize = 8 * 1024;
const ANDROID_UID_PER_USER_RANGE: u32 = 100_000;
const ANDROID_USER_ZERO_CUSTODY_ERROR: &str = "android_user_zero_custody_required";
#[cfg(test)]
const BROWSER_TOOL: &str = "android.browser.open_bounded";
#[cfg(test)]
const BROWSER_ACTION: &str = "browser_open_bounded";
#[cfg(test)]
const BROWSER_UNDO_CONTRACT: &str = "no_undo_external_browser_launch";
#[cfg(test)]
const NOTIFICATION_TOOL: &str = "android.notification.post_bounded";
#[cfg(test)]
const NOTIFICATION_ACTION: &str = "notification_post_bounded";
#[cfg(test)]
const NOTIFICATION_UNDO_CONTRACT: &str = "cancel_exact_owned_notification";
#[cfg(test)]
const MAX_NOTIFICATION_TITLE_BYTES: usize = 120;
#[cfg(test)]
const MAX_NOTIFICATION_BODY_BYTES: usize = 1_000;
const AI_SHELL_SIGNER_SHA256: &str =
    "28bbfe4a7b97e74681dc55c2fbb6ccb8d6c74963733f6af6ae74d8c3a6e879fd";

const AUTHORITY_PIN_FIELDS: &[&str] = &[
    "schema",
    "key_id",
    "key_epoch",
    "key_profile",
    "public_key_spki",
    "security_level",
    "hardware_backed",
    "attestation_challenge_sha256",
    "attestation_chain_present",
    "rotation_contract",
    "pinned_at_ms",
    "internal_pin_verified",
    "attestation_verified",
    "public_release_eligible",
    "verification_status",
];

#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
struct P0UserdebugDirectToolCallSessionGuard {
    session: Option<std::thread::JoinHandle<Result<P0UserdebugDirectToolCallSessionTermination>>>,
    cancellation: P0UserdebugDirectToolCallCancellation,
}

#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
impl P0UserdebugDirectToolCallSessionGuard {
    fn finish(mut self) -> Result<P0UserdebugDirectToolCallSessionTermination> {
        // Store both results before propagating either one: even an impossible
        // eventfd signalling failure must not detach the listener thread.
        let cancellation_result = self.cancellation.cancel();
        let session_result = self
            .session
            .take()
            .context("direct_tool_call_listener_p0_session_handle_missing")?
            .join()
            .map_err(|_| anyhow::anyhow!("direct_tool_call_listener_p0_thread_panicked"));
        cancellation_result
            .context("direct_tool_call_listener_p0_cancel_failed_dispatch_denied")?;
        session_result?.context("direct_tool_call_listener_p0_session_failed_dispatch_denied")
    }
}

#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
impl Drop for P0UserdebugDirectToolCallSessionGuard {
    fn drop(&mut self) {
        let _ = self.cancellation.cancel();
        if let Some(session) = self.session.take() {
            let _ = session.join();
        }
    }
}

#[cfg(any(test, feature = "p0-launch-package-device-conformance"))]
struct P0SystemApiListenerEvidence<'a> {
    commit_receipt:
        &'a trillionnium_os_types::direct_operation::DirectOperationToolCallCommitReceiptV3,
    terminal_evidence: &'a trillionnium_os_types::direct_operation::DirectOperationOuterEvidence,
    delivery_binding: &'a trillionnium_os_types::direct_operation::DirectOperationBinding,
    allocation_binding: &'a trillionnium_os_types::direct_operation::DirectOperationBinding,
}

#[cfg(feature = "p0-launch-package-device-conformance")]
impl<'a> From<&'a P0UserdebugDirectToolCallSessionOutcome> for P0SystemApiListenerEvidence<'a> {
    fn from(outcome: &'a P0UserdebugDirectToolCallSessionOutcome) -> Self {
        Self {
            commit_receipt: &outcome.commit_receipt,
            terminal_evidence: &outcome.terminal_evidence,
            delivery_binding: &outcome.delivery_binding,
            allocation_binding: &outcome.allocation_binding,
        }
    }
}

#[cfg(any(test, feature = "p0-launch-package-device-conformance"))]
fn validate_p0_system_api_listener_reconciliation(
    provider_result: &ProviderPlanResult,
    direct_binding: &trillionnium_os_types::direct_operation::DirectOperationBinding,
    listener_outcome: Option<P0SystemApiListenerEvidence<'_>>,
) -> Result<()> {
    let mut system_api_calls = provider_result.direct_tool_calls.iter().filter(|call| {
        call.server == "trillionnium_system_api" || call.tool == "trillionnium_system_api"
    });
    let system_api_call = system_api_calls.next();
    if system_api_calls.next().is_some() {
        bail!("direct_provider_multiple_p0_system_api_calls_denied");
    }
    match (system_api_call, listener_outcome) {
        (None, None) => Ok(()),
        (None, Some(_)) => bail!("p0_system_api_listener_commit_without_provider_evidence"),
        (Some(_), None) => bail!("p0_system_api_provider_evidence_without_listener_commit"),
        (Some(call), Some(listener_outcome)) => {
            let commit = &listener_outcome.commit_receipt;
            let terminal = &listener_outcome.terminal_evidence;
            direct_binding
                .validate()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let binding_sha256 = direct_binding
                .digest_sha256()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let commit_sha256 = commit
                .digest_sha256()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let terminal_outcome_matches = match terminal.outcome {
                DirectOperationOuterOutcome::Success => {
                    call.outcome == "success" && call.backend_error_code.is_none()
                }
                DirectOperationOuterOutcome::BackendError => {
                    call.backend_error_code.as_deref().is_some_and(|code| {
                        match direct_backend_error_effect_class(&call.server, code) {
                            Some(DirectBackendEffectClass::DefinitelyNoEffect) => {
                                call.outcome == "backend_error"
                            }
                            Some(DirectBackendEffectClass::DefinitiveTerminal) => {
                                call.outcome == "terminal_error"
                            }
                            Some(DirectBackendEffectClass::Indeterminate) | None => false,
                        }
                    }) && terminal.backend_error_code == call.backend_error_code
                }
                DirectOperationOuterOutcome::Indeterminate => {
                    call.outcome == "backend_error"
                        && call.backend_error_code.as_deref().is_some_and(|code| {
                            direct_backend_error_effect_class(&call.server, code)
                                == Some(DirectBackendEffectClass::Indeterminate)
                        })
                        && terminal.backend_error_code == call.backend_error_code
                }
            };
            if call.server != "trillionnium_system_api"
                || call.tool != "trillionnium_system_api"
                || commit.commit_receipt_sha256 != commit_sha256
                || commit.binding_sha256 != binding_sha256
                || commit.invocation_id != direct_binding.invocation_id
                || commit.adapter != DirectOperationAdapter::SystemApi
                || !direct_binding
                    .authorized_adapter_set
                    .authorizes(DirectOperationAdapter::SystemApi)
                // The P0 System API allocator has one adapter-local delivery;
                // Codex evidence.sequence is global across System API and
                // shell calls, so it is not this adapter-local ordinal.
                || commit.adapter_effect_ordinal != 0
                || sha256_bytes(commit.os_tool_call_id.as_bytes())
                    != call.backend_request_id_sha256
                || *listener_outcome.delivery_binding != *direct_binding
                || *listener_outcome.allocation_binding != *direct_binding
                || terminal.allocating_provider_attempt_id
                    != direct_binding.attempt.delivery_provider_attempt_id
                || terminal.adapter_effect_ordinal != commit.adapter_effect_ordinal
                || terminal.tool != "trillionnium_system_api"
                || terminal.canonical_request_sha256 != call.canonical_request_sha256
                || terminal.backend_request_id_sha256 != call.backend_request_id_sha256
                || terminal.backend_result_sha256 != call.backend_result_sha256
                || terminal.backend_error_code != call.backend_error_code
                || !terminal_outcome_matches
            {
                bail!("p0_system_api_listener_provider_evidence_mismatch");
            }
            Ok(())
        }
    }
}

const EGRESS_CHALLENGE_FIELDS: &[&str] = &[
    "challenge_schema",
    "challenge_id",
    "egress_grant_id",
    "ui_uid",
    "ui_selinux_domain",
    "subject_user_id",
    "boot_id_sha256",
    "context_id",
    "context_captured_at_ms",
    "context_expires_at_ms",
    "context_sha256",
    "source_kind",
    "source_id_sha256",
    "privacy_class",
    "content_bytes",
    "intent",
    "intent_bytes",
    "intent_sha256",
    "allowed_actions",
    "allowed_actions_sha256",
    "prompt_contract",
    "prompt_contract_version",
    "provider_id",
    "agent_id",
    "agent_peer_uid",
    "agent_peer_gid",
    "agent_selinux_domain",
    "agent_executable_sha256",
    "endpoint",
    "upload_byte_limit",
    "download_byte_limit",
    "issued_at_ms",
    "expires_at_ms",
    "ttl_ms",
    "workflow_id",
    "prepare_request_id",
    "plan_request_id",
    "nonce",
];

const EGRESS_CONSENT_RECEIPT_FIELDS: &[&str] = &[
    "schema",
    "challenge_schema",
    "challenge_id",
    "egress_grant_id",
    "ui_uid",
    "ui_selinux_domain",
    "subject_user_id",
    "boot_id_sha256",
    "context_id",
    "context_captured_at_ms",
    "context_expires_at_ms",
    "context_sha256",
    "source_kind",
    "source_id_sha256",
    "privacy_class",
    "content_bytes",
    "intent",
    "intent_bytes",
    "intent_sha256",
    "allowed_actions",
    "allowed_actions_sha256",
    "prompt_contract",
    "prompt_contract_version",
    "provider_id",
    "agent_id",
    "agent_peer_uid",
    "agent_peer_gid",
    "agent_selinux_domain",
    "agent_executable_sha256",
    "endpoint",
    "upload_byte_limit",
    "download_byte_limit",
    "issued_at_ms",
    "expires_at_ms",
    "ttl_ms",
    "workflow_id",
    "prepare_request_id",
    "plan_request_id",
    "nonce",
    "decision",
    "confirmed_at_ms",
    "receipt_signature_algorithm",
    "receipt_signing_key_id",
    "receipt_signing_key_epoch",
    "receipt_signing_key_profile",
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
    "hardware_backed_signature",
    "receipt_signature",
    "receipt_id",
];

#[cfg(test)]
const ACTION_CONSENT_CHALLENGE_FIELDS: &[&str] = &[
    "challenge_schema",
    "challenge_id",
    "ui_uid",
    "ui_selinux_domain",
    "subject_user_id",
    "boot_id_sha256",
    "workflow_id",
    "approve_request_id",
    "task_id",
    "session_id",
    "plan_id",
    "action_id",
    "approval_id",
    "approval_created_at_ms",
    "tool_call_id",
    "tool_name",
    "agent_id",
    "agent_peer_uid",
    "agent_peer_gid",
    "agent_selinux_domain",
    "agent_executable_sha256",
    "origin_uid",
    "origin_selinux_domain",
    "tool_manifest_sha256",
    "accepted_plan_sha256",
    "arguments_sha256",
    "approval_nonce_sha256",
    "context_sha256",
    "action_payload",
    "execution_payload_sha256",
    "network_scope",
    "issued_at_ms",
    "expires_at_ms",
    "ttl_ms",
];

#[cfg(test)]
const ACTION_CONSENT_RECEIPT_FIELDS: &[&str] = &[
    "challenge_schema",
    "challenge_id",
    "ui_uid",
    "ui_selinux_domain",
    "subject_user_id",
    "boot_id_sha256",
    "workflow_id",
    "approve_request_id",
    "task_id",
    "session_id",
    "plan_id",
    "action_id",
    "approval_id",
    "approval_created_at_ms",
    "tool_call_id",
    "tool_name",
    "agent_id",
    "agent_peer_uid",
    "agent_peer_gid",
    "agent_selinux_domain",
    "agent_executable_sha256",
    "origin_uid",
    "origin_selinux_domain",
    "tool_manifest_sha256",
    "accepted_plan_sha256",
    "arguments_sha256",
    "approval_nonce_sha256",
    "context_sha256",
    "action_payload",
    "execution_payload_sha256",
    "network_scope",
    "issued_at_ms",
    "expires_at_ms",
    "ttl_ms",
    "schema",
    "decision",
    "confirmed_at_ms",
    "receipt_signature_algorithm",
    "receipt_signing_key_id",
    "receipt_signing_key_epoch",
    "receipt_signing_key_profile",
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
    "hardware_backed_signature",
    "receipt_signature",
    "receipt_id",
];

const SAF_CONTEXT_CAPTURE_RECEIPT_FIELDS: &[&str] = &[
    "schema",
    "decision",
    "capture_id",
    "capture_request_id",
    "capture_method",
    "requesting_package",
    "requesting_uid",
    "requesting_signer_sha256",
    "subject_user_id",
    "boot_id_sha256",
    "source_kind",
    "source_id",
    "privacy_class",
    "uri_scheme",
    "provider_package",
    "provider_uid",
    "provider_authority_sha256",
    "document_id_sha256",
    "display_name_sha256",
    "mime_type",
    "declared_size_bytes",
    "last_modified_ms",
    "document_flags",
    "metadata_query_complete",
    "provider_metadata_asserted",
    "content_sha256",
    "content_bytes",
    "captured_at_ms",
    "expires_at_ms",
    "ttl_ms",
    "single_use",
    "raw_content_returned_to_ui",
    "receipt_signature_algorithm",
    "receipt_signing_key_id",
    "receipt_signing_key_epoch",
    "receipt_signing_key_profile",
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
    "hardware_backed_signature",
    "receipt_signature",
    "receipt_id",
];

const BROWSER_CONTEXT_CAPTURE_RECEIPT_FIELDS: &[&str] = &[
    "schema",
    "decision",
    "capture_id",
    "capture_request_id",
    "capture_method",
    "requesting_package",
    "requesting_uid",
    "requesting_signer_sha256",
    "subject_user_id",
    "boot_id_sha256",
    "source_kind",
    "source_id",
    "privacy_class",
    "uri_scheme",
    "url_sha256",
    "url_bytes",
    "url_host_sha256",
    "user_entered_in_authority_ui",
    "explicit_user_confirmation",
    "content_sha256",
    "content_bytes",
    "captured_at_ms",
    "expires_at_ms",
    "ttl_ms",
    "single_use",
    "raw_content_returned_to_ui",
    "receipt_signature_algorithm",
    "receipt_signing_key_id",
    "receipt_signing_key_epoch",
    "receipt_signing_key_profile",
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
    "hardware_backed_signature",
    "receipt_signature",
    "receipt_id",
];

const SAF_CONTEXT_RESOLUTION_FIELDS: &[&str] = &[
    "schema",
    "capture_id",
    "capture_receipt_id",
    "capture_request_id",
    "requesting_uid",
    "subject_user_id",
    "requesting_package",
    "requesting_signer_sha256",
    "boot_id_sha256",
    "capture_method",
    "source_kind",
    "source_id",
    "privacy_class",
    "provider_package",
    "provider_uid",
    "provider_authority_sha256",
    "document_id_sha256",
    "display_name_sha256",
    "mime_type",
    "declared_size_bytes",
    "last_modified_ms",
    "document_flags",
    "metadata_query_complete",
    "provider_metadata_asserted",
    "content_sha256",
    "content_bytes",
    "captured_at_ms",
    "expires_at_ms",
    "single_use_consumed",
    "content",
];

const BROWSER_CONTEXT_RESOLUTION_FIELDS: &[&str] = &[
    "schema",
    "capture_id",
    "capture_receipt_id",
    "capture_request_id",
    "requesting_uid",
    "subject_user_id",
    "requesting_package",
    "requesting_signer_sha256",
    "boot_id_sha256",
    "capture_method",
    "source_kind",
    "source_id",
    "privacy_class",
    "url_sha256",
    "url_bytes",
    "url_host_sha256",
    "user_entered_in_authority_ui",
    "explicit_user_confirmation",
    "content_sha256",
    "content_bytes",
    "captured_at_ms",
    "expires_at_ms",
    "single_use_consumed",
    "content",
];

const CONTEXT_CAPTURE_RECOVERY_FIELDS: &[&str] = &[
    "schema",
    "capture_id",
    "capture_request_id",
    "original_request_id",
    "capture_state",
    "recovery_status",
    "capture_receipt_id",
    "capture_receipt_bytes_sha256",
    "capture_receipt_json_b64",
    "source_id",
    "content_sha256",
    "resolution_sha256",
    "resolution_json_b64",
    "imported_context_id",
    "indeterminate_reason_code",
    "gateway_peer_binding_sha256",
    "capture_expires_at_ms",
    "recovery_expires_at_ms",
];

type EgressGrantStore = Arc<Mutex<EgressGrantState>>;
type ActiveEgressStore = Arc<Mutex<HashMap<String, ActiveEgressRun>>>;
type ActionConsentStore = Arc<Mutex<ActionWorkflowJournal>>;
const ACTIVE_EGRESS_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct EgressGrantState {
    pending: HashMap<String, PendingEgressGrant>,
    journal: EgressLifecycleJournal,
}

impl EgressGrantState {
    fn open_from_env(
        service: &AgentService,
        context_memory: &ContextMemoryService,
    ) -> Result<Self> {
        let mut state = Self {
            pending: HashMap::new(),
            journal: EgressLifecycleJournal::open_from_env()?,
        };
        recover_prepared_egress_grants(&mut state, service, context_memory)?;
        Ok(state)
    }

    #[cfg(test)]
    fn open_for_test(path: &Path) -> Result<Self> {
        Ok(Self {
            pending: HashMap::new(),
            journal: EgressLifecycleJournal::open_for_test(path)?,
        })
    }
}

impl Deref for EgressGrantState {
    type Target = HashMap<String, PendingEgressGrant>;

    fn deref(&self) -> &Self::Target {
        &self.pending
    }
}

impl DerefMut for EgressGrantState {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pending
    }
}

#[derive(Clone)]
struct ActiveEgressCancellation {
    cancelled: Arc<AtomicBool>,
    teardown_nonce: String,
    teardown_ack: Arc<(Mutex<Option<EgressTeardownAck>>, Condvar)>,
    #[cfg(test)]
    cancel_count: Arc<AtomicUsize>,
    #[cfg(test)]
    ack_publish_count: Arc<AtomicUsize>,
    #[cfg(test)]
    wait_entered_barrier: Option<Arc<std::sync::Barrier>>,
    #[cfg(test)]
    after_ack_gate: Option<ActiveEgressAfterAckGate>,
    #[cfg(test)]
    force_teardown_timeout: bool,
}

#[cfg(test)]
#[derive(Clone)]
struct ActiveEgressAfterAckGate {
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

impl ActiveEgressCancellation {
    fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            #[cfg(test)]
            self.cancel_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    #[allow(dead_code)]
    fn publish_verified_teardown_ack(&self, ack: EgressTeardownAck) -> Result<()> {
        if ack.teardown_nonce != self.teardown_nonce {
            bail!("active_egress_teardown_nonce_mismatch");
        }
        let (slot, condition) = &*self.teardown_ack;
        let mut slot = slot
            .lock()
            .map_err(|_| anyhow::anyhow!("active_egress_teardown_lock_poisoned"))?;
        if let Some(existing) = slot.as_ref() {
            if existing != &ack {
                bail!("active_egress_teardown_ack_changed");
            }
            return Ok(());
        }
        *slot = Some(ack);
        #[cfg(test)]
        self.ack_publish_count.fetch_add(1, Ordering::SeqCst);
        condition.notify_all();
        Ok(())
    }

    fn teardown_ack(&self) -> Result<Option<EgressTeardownAck>> {
        self.teardown_ack
            .0
            .lock()
            .map(|slot| slot.clone())
            .map_err(|_| anyhow::anyhow!("active_egress_teardown_lock_poisoned"))
    }

    fn wait_for_teardown(&self, timeout: Duration) -> Result<EgressTeardownAck> {
        #[cfg(test)]
        if let Some(barrier) = self.wait_entered_barrier.as_ref() {
            barrier.wait();
        }
        #[cfg(test)]
        if self.force_teardown_timeout {
            bail!("active_egress_teardown_not_cryptographically_proven");
        }
        let (slot, condition) = &*self.teardown_ack;
        let slot = slot
            .lock()
            .map_err(|_| anyhow::anyhow!("active_egress_teardown_lock_poisoned"))?;
        let (slot, _) = condition
            .wait_timeout_while(slot, timeout, |slot| slot.is_none())
            .map_err(|_| anyhow::anyhow!("active_egress_teardown_wait_poisoned"))?;
        let ack = slot
            .clone()
            .context("active_egress_teardown_not_cryptographically_proven")?;
        drop(slot);
        #[cfg(test)]
        if let Some(gate) = self.after_ack_gate.as_ref() {
            gate.entered.wait();
            gate.release.wait();
        }
        Ok(ack)
    }
}

#[derive(Clone)]
struct ActiveEgressRun {
    workflow_id: String,
    peer_uid: u32,
    peer_domain: String,
    provider_id: String,
    journal_binding_sha256: String,
    journal_cas: EgressJournalCas,
    teardown_nonce: String,
    cancellation: ActiveEgressCancellation,
    durability: ActiveEgressDurability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveEgressDurability {
    Running,
    CompletionPending,
    RevokePending,
    /// A consumed/predispatch/attempt journal rename or the two-inbox
    /// publication crossed a point whose global durability cannot be proven.
    /// This is query-only custody until a clean reopen: no provider, broker or
    /// child may be started from this run in the current process.
    DispatchBlockedCommitUnknown,
}

struct ActiveEgressGuard {
    egress_grants: EgressGrantStore,
    store: ActiveEgressStore,
    grant_id: String,
    cancellation: ActiveEgressCancellation,
    finalized: bool,
}

#[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
struct P0UserdebugAckHotpath {
    session: P0UserdebugDirectToolCallSessionOutcome,
    allocation_egress_cas: EgressJournalCas,
    direct_ui: VerifiedDirectUiReplaySnapshot,
}

impl ActiveEgressGuard {
    fn finish(mut self, outcome: Result<Value>) -> Result<Value> {
        let outcome = if self.cancellation.is_cancelled() {
            Err(anyhow::anyhow!("active_egress_cancelled_fail_closed"))
        } else {
            outcome
        };
        // A provider return is not itself teardown evidence. Completion is
        // durable only when the provider adapter separately published a typed
        // child/session cleanup proof plus a finalized broker outcome.
        let finalized =
            finalize_active_egress_completion(&self.egress_grants, &self.store, &self.grant_id);
        // The provider has returned and any typed runtime proof was already
        // published by the adapter. A journal durability error is not evidence
        // that a live child still exists, so Drop must not synthesize a second
        // cancellation event.
        self.finalized = true;
        let finalized = finalized?;
        if !finalized {
            // Keep CONSUMED/CompletionPending durable and queryable. Returning
            // the provider result does not falsely assert lifecycle terminality.
        }
        outcome
    }

    #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
    fn finish_p0_userdebug(
        mut self,
        outcome: Result<Value>,
        allocation_cas: &EgressJournalCas,
        binding: &trillionnium_os_types::direct_operation::DirectOperationBinding,
    ) -> Result<(
        Value,
        crate::egress_journal::VerifiedDirectTerminalEgressSnapshot,
    )> {
        let outcome = if self.cancellation.is_cancelled() {
            Err(anyhow::anyhow!("active_egress_cancelled_fail_closed"))
        } else {
            outcome
        };
        let finalized = finalize_active_egress_completion_inner(
            &self.egress_grants,
            &self.store,
            &self.grant_id,
            Some((allocation_cas, binding)),
        );
        self.finalized = true;
        let (finalized, snapshot) = finalized?;
        if !finalized {
            bail!("p0_userdebug_terminal_egress_completion_pending_denied");
        }
        let snapshot = snapshot.context("p0_userdebug_terminal_egress_snapshot_missing")?;
        Ok((outcome?, snapshot))
    }
}

impl Drop for ActiveEgressGuard {
    fn drop(&mut self) {
        if !self.finalized {
            // Fail closed without a best-effort terminal journal mutation.
            // The durable CONSUMED record becomes INTERRUPTED_RESTART after a
            // daemon reconstruction and is never automatically re-executed.
            self.cancellation.cancel();
        }
    }
}

struct PendingEgressGrant {
    provider_id: String,
    workflow_id: String,
    prepare_request_id: String,
    prepare_request_payload_sha256: String,
    policy_epoch: u64,
    provider_abi_epoch: u64,
    peer_uid: u32,
    peer_domain: String,
    agent_peer_uid: u32,
    agent_peer_gid: u32,
    agent_id: String,
    agent_selinux_domain: String,
    agent_executable_sha256: String,
    agent_registration: AgentRegistration,
    boot_id_sha256: String,
    context_id: String,
    context_kind: String,
    context_captured_at_ms: u64,
    context_expires_at_ms: u64,
    privacy_class: String,
    source_id: Zeroizing<String>,
    content: Zeroizing<String>,
    intent: Zeroizing<String>,
    content_sha256: String,
    allowed_actions: Vec<String>,
    allowed_actions_sha256: String,
    prompt_contract: String,
    prompt_contract_version: u64,
    journal_binding_sha256: String,
    journal_cas: EgressJournalCas,
    recovery_blob: EgressRecoveryBlobRef,
    issued_at_ms: u64,
    expires_at_ms: u64,
    upload_byte_limit: u64,
    download_byte_limit: u64,
    consent_challenge: Value,
}

#[derive(Clone, PartialEq)]
struct PendingEgressBinding {
    provider_id: String,
    workflow_id: String,
    prepare_request_id_sha256: String,
    prepare_request_payload_sha256: String,
    policy_epoch: u64,
    provider_abi_epoch: u64,
    peer_uid: u32,
    peer_domain: String,
    agent_peer_uid: u32,
    agent_peer_gid: u32,
    agent_id: String,
    agent_selinux_domain: String,
    agent_executable_sha256: String,
    agent_manifest_sha256: String,
    boot_id_sha256: String,
    context_id: String,
    context_kind: String,
    context_captured_at_ms: u64,
    context_expires_at_ms: u64,
    privacy_class: String,
    source_id_sha256: String,
    content_sha256: String,
    actual_content_sha256: String,
    content_bytes: u64,
    intent_sha256: String,
    intent_bytes: u64,
    allowed_actions: Vec<String>,
    allowed_actions_sha256: String,
    prompt_contract: String,
    prompt_contract_version: u64,
    journal_binding_sha256: String,
    upload_byte_limit: u64,
    download_byte_limit: u64,
    issued_at_ms: u64,
    expires_at_ms: u64,
    consent_challenge: Value,
}

struct ValidatedEgressConsent {
    grant_id: String,
    binding: PendingEgressBinding,
    receipt_id: String,
}

impl PendingEgressGrant {
    fn binding(&self) -> PendingEgressBinding {
        PendingEgressBinding {
            provider_id: self.provider_id.clone(),
            workflow_id: self.workflow_id.clone(),
            prepare_request_id_sha256: sha256_bytes(self.prepare_request_id.as_bytes()),
            prepare_request_payload_sha256: self.prepare_request_payload_sha256.clone(),
            policy_epoch: self.policy_epoch,
            provider_abi_epoch: self.provider_abi_epoch,
            peer_uid: self.peer_uid,
            peer_domain: self.peer_domain.clone(),
            agent_peer_uid: self.agent_peer_uid,
            agent_peer_gid: self.agent_peer_gid,
            agent_id: self.agent_id.clone(),
            agent_selinux_domain: self.agent_selinux_domain.clone(),
            agent_executable_sha256: self.agent_executable_sha256.clone(),
            agent_manifest_sha256: sha256_json(
                &serde_json::to_value(&self.agent_registration)
                    .expect("AgentRegistration serialization is infallible"),
            ),
            boot_id_sha256: self.boot_id_sha256.clone(),
            context_id: self.context_id.clone(),
            context_kind: self.context_kind.clone(),
            context_captured_at_ms: self.context_captured_at_ms,
            context_expires_at_ms: self.context_expires_at_ms,
            privacy_class: self.privacy_class.clone(),
            source_id_sha256: sha256_bytes(self.source_id.as_bytes()),
            content_sha256: self.content_sha256.clone(),
            actual_content_sha256: sha256_bytes(self.content.as_bytes()),
            content_bytes: self.content.len() as u64,
            intent_sha256: sha256_bytes(self.intent.as_bytes()),
            intent_bytes: self.intent.len() as u64,
            allowed_actions: self.allowed_actions.clone(),
            allowed_actions_sha256: self.allowed_actions_sha256.clone(),
            prompt_contract: self.prompt_contract.clone(),
            prompt_contract_version: self.prompt_contract_version,
            journal_binding_sha256: self.journal_binding_sha256.clone(),
            upload_byte_limit: self.upload_byte_limit,
            download_byte_limit: self.download_byte_limit,
            issued_at_ms: self.issued_at_ms,
            expires_at_ms: self.expires_at_ms,
            consent_challenge: self.consent_challenge.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct EgressRecoveryBody {
    grant_id: String,
    provider_id: String,
    workflow_id: String,
    #[serde(default)]
    prepare_request_id: String,
    #[serde(default)]
    prepare_request_payload_sha256: String,
    #[serde(default)]
    policy_epoch: u64,
    #[serde(default)]
    provider_abi_epoch: u64,
    peer_uid: u32,
    peer_domain: String,
    subject_user_id: u32,
    boot_id_sha256: String,
    agent_id: String,
    agent_peer_uid: u32,
    agent_peer_gid: u32,
    agent_selinux_domain: String,
    agent_executable_sha256: String,
    agent_registration: AgentRegistration,
    context_id: String,
    context_kind: String,
    context_captured_at_ms: u64,
    context_expires_at_ms: u64,
    privacy_class: String,
    source_id: String,
    content: String,
    intent: String,
    content_sha256: String,
    allowed_actions: Vec<String>,
    allowed_actions_sha256: String,
    prompt_contract: String,
    prompt_contract_version: u64,
    journal_binding_sha256: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    upload_byte_limit: u64,
    download_byte_limit: u64,
    consent_challenge: Value,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressRecoveryEnvelope {
    schema: String,
    format_version: u32,
    body: EgressRecoveryBody,
    payload_sha256: String,
}

#[derive(Serialize)]
struct EgressRecoveryDigestInput<'a> {
    schema: &'a str,
    format_version: u32,
    body: &'a EgressRecoveryBody,
}

#[derive(Serialize)]
struct EgressRecoveryAad<'a> {
    schema: &'a str,
    format_version: u32,
    grant_id: &'a str,
    journal_binding_sha256: &'a str,
    metadata: &'a EgressJournalMetadata,
}

struct SecretPlanningRequest(PlanningRequest);

impl Drop for SecretPlanningRequest {
    fn drop(&mut self) {
        self.0.intent.zeroize();
        for context in &mut self.0.contexts {
            context.content.zeroize();
            context.source_id.zeroize();
        }
    }
}

#[derive(Clone)]
struct ProviderPlanResult {
    submission: Option<AgentPlanSubmission>,
    execution_mode: ProviderExecutionMode,
    direct_outcome: Option<ProviderDirectOutcome>,
    direct_refusal_reason: Option<String>,
    direct_tool_calls: Vec<CodexDirectToolCallEvidence>,
    summary: String,
    runtime_provider: String,
    model: String,
    elapsed_ms: u64,
    provider_output_sha256: String,
}

struct AgentDirectProviderResult {
    direct_outcome: ProviderDirectOutcome,
    direct_refusal_reason: Option<String>,
    direct_tool_calls: Vec<CodexDirectToolCallEvidence>,
    summary: String,
    runtime_provider: String,
    model: String,
    elapsed_ms: u64,
    provider_output_sha256: String,
}

impl From<AgentDirectProviderResult> for ProviderPlanResult {
    fn from(value: AgentDirectProviderResult) -> Self {
        Self {
            submission: None,
            execution_mode: ProviderExecutionMode::AgentDirect,
            direct_outcome: Some(value.direct_outcome),
            direct_refusal_reason: value.direct_refusal_reason,
            direct_tool_calls: value.direct_tool_calls,
            summary: value.summary,
            runtime_provider: value.runtime_provider,
            model: value.model,
            elapsed_ms: value.elapsed_ms,
            provider_output_sha256: value.provider_output_sha256,
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ProviderExecutionMode {
    LegacyPlan,
    AgentDirect,
}

const LEGACY_LOCAL_PLAN_SAGA_SCHEMA: &str = "trillionnium.local-plan-saga.v1";
const RETIRED_MULTI_PROVIDER_LOCAL_PLAN_SAGA_SCHEMA: &str = "trillionnium.local-plan-saga.v2";
const LOCAL_PLAN_SAGA_SCHEMA: &str = "trillionnium.local-plan-saga.v3";
const LEGACY_LOCAL_PLAN_SAGA_INDETERMINATE_REASON: &str =
    "legacy_local_plan_saga_v1_missing_executable_identity";
const RETIRED_MULTI_PROVIDER_LOCAL_PLAN_SAGA_INDETERMINATE_REASON: &str =
    "retired_local_plan_saga_v2_multi_provider_shape";

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ProviderReadySaga {
    schema: String,
    request_id: String,
    request_payload_sha256: String,
    peer_uid: u32,
    peer_domain: String,
    provider_id: String,
    workflow_id: String,
    task_id: String,
    registration: AgentRegistration,
    agent_executable: DurableAgentExecutableIdentity,
    agent_manifest_sha256: String,
    runtime_lifecycle_binding_sha256: String,
    authorized_adapter_set: DirectOperationAuthorizedAdapterSetV3,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shell_exec_authorization: Option<CompletedShellExecAuthorizationV1>,
    context_id: String,
    context_expires_at_ms: u64,
    source_id: String,
    content: String,
    content_sha256: String,
    provider_result: DurableProviderPlanResult,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DurableAgentExecutableIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    sha256: String,
}

impl From<&super::AgentExecutableDispatchIdentity> for DurableAgentExecutableIdentity {
    fn from(value: &super::AgentExecutableDispatchIdentity) -> Self {
        Self {
            dev: value.dev,
            ino: value.ino,
            uid: value.uid,
            gid: value.gid,
            mode: value.mode,
            sha256: value.sha256.clone(),
        }
    }
}

impl DurableAgentExecutableIdentity {
    #[cfg(test)]
    fn dispatch_identity(&self) -> super::AgentExecutableDispatchIdentity {
        super::AgentExecutableDispatchIdentity {
            dev: self.dev,
            ino: self.ino,
            uid: self.uid,
            gid: self.gid,
            mode: self.mode,
            sha256: self.sha256.clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct DurableProviderPlanResult {
    submission: Option<AgentPlanSubmission>,
    execution_mode: ProviderExecutionMode,
    #[serde(default)]
    direct_outcome: Option<ProviderDirectOutcome>,
    #[serde(default)]
    direct_refusal_reason: Option<String>,
    direct_tool_calls: Vec<CodexDirectToolCallEvidence>,
    summary: String,
    runtime_provider: String,
    model: String,
    elapsed_ms: u64,
    provider_output_sha256: String,
}

#[cfg(test)]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct DurableExecutionPayloadDescriptor {
    reference: String,
    payload_sha256: String,
    shape: String,
}

#[cfg(test)]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct PlanPreparedSaga {
    provider: ProviderReadySaga,
    submission: AgentPlanSubmission,
    descriptor: Option<DurableExecutionPayloadDescriptor>,
    execution_payload_expires_at_ms: Option<u64>,
    action_summary: String,
}

#[cfg(test)]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct PlanSubmittedSaga {
    prepared: PlanPreparedSaga,
    plan: AgentPlanSubmission,
}

#[cfg(test)]
#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct ActionDispatchedSaga {
    submitted: PlanSubmittedSaga,
    execution_binding: AgentExecutionBinding,
    approval_id: String,
}

struct VerifiedContextCaptureReceipt {
    capture_id: String,
    receipt_id: String,
    request_id: String,
    requesting_uid: u32,
    subject_user_id: u32,
    boot_id_sha256: String,
    capture_method: String,
    source_kind: String,
    source_id: String,
    privacy_class: String,
    provider_package: String,
    provider_uid: u32,
    provider_authority_sha256: String,
    document_id_sha256: String,
    display_name_sha256: String,
    mime_type: String,
    declared_size_bytes: i64,
    last_modified_ms: u64,
    document_flags: u64,
    url_host_sha256: String,
    content_sha256: String,
    content_bytes: usize,
    captured_at_ms: u64,
    expires_at_ms: u64,
    encoded_receipt: String,
}

#[cfg(test)]
struct ValidatedActionConsent {
    task_id: String,
    approval_id: String,
    expected_challenge: Value,
    receipt_id: String,
    approve_request_id: String,
    approve_payload_sha256: String,
}

struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub fn spawn(service: Arc<AgentService>, context_memory: Arc<ContextMemoryService>) {
    std::thread::spawn(move || {
        let egress_grants = match EgressGrantState::open_from_env(&service, &context_memory) {
            Ok(state) => Arc::new(Mutex::new(state)),
            Err(error) => {
                eprintln!("OS UI egress lifecycle journal failed closed: {error:#}");
                return;
            }
        };
        let active_egress = Arc::new(Mutex::new(HashMap::new()));
        let action_consents = match ActionWorkflowJournal::open(&context_memory) {
            Ok(journal) => Arc::new(Mutex::new(journal)),
            Err(error) => {
                eprintln!("OS UI action workflow journal failed closed: {error:#}");
                return;
            }
        };
        if let Err(error) = reconcile_action_workflows(&service, &action_consents, &context_memory)
        {
            eprintln!("OS UI action workflow reconciliation failed closed: {error:#}");
            return;
        }
        if let Err(error) =
            spawn_egress_expiry_reaper(&egress_grants, &active_egress, &context_memory)
        {
            eprintln!("OS UI egress expiry reaper failed closed: {error:#}");
            return;
        }
        if let Err(error) = serve(
            service,
            egress_grants,
            active_egress,
            action_consents,
            context_memory,
        ) {
            eprintln!("OS UI authority API failed closed: {error:#}");
        }
    });
}

fn spawn_egress_expiry_reaper(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    context_memory: &Arc<ContextMemoryService>,
) -> Result<()> {
    let grants = Arc::downgrade(egress_grants);
    let active = Arc::downgrade(active_egress);
    let context_memory = Arc::downgrade(context_memory);
    std::thread::Builder::new()
        .name("android-egress-expiry".to_string())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let Some(grants) = grants.upgrade() else {
                    return;
                };
                let Some(active) = active.upgrade() else {
                    return;
                };
                let Some(context_memory) = context_memory.upgrade() else {
                    return;
                };
                let result =
                    retry_pending_active_egress_durability(&grants, &active).and_then(|_| {
                        grants
                            .lock()
                            .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))
                            .and_then(|mut state| {
                                expire_pending_egress_grants(
                                    &mut state,
                                    &context_memory,
                                    now_unix_ms(),
                                )
                            })
                    });
                if let Err(error) = result {
                    eprintln!("OS UI egress expiry transition failed closed: {error:#}");
                }
            }
        })?;
    Ok(())
}

fn encode_android_agent_api_response_frame(response: &Value) -> Vec<u8> {
    let mut encoded = serde_json::to_vec(response).unwrap_or_else(|_| {
        br#"{"protocol":"trillionnium.direct-agent-host.uds.v1","request_id":null,"ok":false,"error":"android_agent_api_response_encoding_denied"}"#.to_vec()
    });
    if encoded.len().saturating_add(1) > MAX_FRAME as usize {
        encoded = br#"{"protocol":"trillionnium.direct-agent-host.uds.v1","request_id":null,"ok":false,"error":"android_agent_api_response_too_large"}"#.to_vec();
    }
    debug_assert!(encoded.len().saturating_add(1) <= MAX_FRAME as usize);
    encoded.push(b'\n');
    encoded
}

fn serve(
    service: Arc<AgentService>,
    egress_grants: EgressGrantStore,
    active_egress: ActiveEgressStore,
    action_consents: ActionConsentStore,
    context_memory: Arc<ContextMemoryService>,
) -> Result<()> {
    let listener = bind_abstract(SOCKET_NAME)?;
    let in_flight = Arc::new(AtomicUsize::new(0));
    eprintln!("trillionniumd owns {PROTOCOL} at abstract:{SOCKET_NAME}");
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                if in_flight
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                        (active < MAX_IN_FLIGHT_CONNECTIONS).then_some(active + 1)
                    })
                    .is_err()
                {
                    let _ = serde_json::to_writer(
                        &mut stream,
                        &json!({
                            "protocol": PROTOCOL,
                            "request_id": Value::Null,
                            "ok": false,
                            "error": "android_agent_api_busy",
                        }),
                    );
                    let _ = stream.write_all(b"\n");
                    continue;
                }
                let service = Arc::clone(&service);
                let egress_grants = Arc::clone(&egress_grants);
                let active_egress = Arc::clone(&active_egress);
                let action_consents = Arc::clone(&action_consents);
                let context_memory = Arc::clone(&context_memory);
                let in_flight = Arc::clone(&in_flight);
                std::thread::spawn(move || {
                    let _guard = InFlightGuard(in_flight);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    let response = handle(
                        &service,
                        &egress_grants,
                        &active_egress,
                        &action_consents,
                        &context_memory,
                        &stream,
                    )
                    .unwrap_or_else(|error| {
                        json!({
                            "protocol": PROTOCOL,
                            "request_id": Value::Null,
                            "ok": false,
                            "error": error.to_string(),
                        })
                    });
                    let encoded = encode_android_agent_api_response_frame(&response);
                    let _ = stream.write_all(&encoded);
                    let _ = stream.flush();
                });
            }
            Err(error) => eprintln!("OS UI authority API accept denied: {error}"),
        }
    }
    Ok(())
}

fn handle(
    service: &AgentService,
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
    stream: &UnixStream,
) -> Result<Value> {
    let peer_uid = peer_uid(stream)?;
    let peer_domain = peer_security_context(stream)?;
    // SO_PEERCRED and SO_PEERSEC are the authenticated boundary.  Enforce the
    // current user-0-only Context/Memory custody contract before reading or
    // parsing a caller-controlled frame, so no replay journal, credential,
    // gateway, capture or egress side effect can run for another Android user.
    let subject = authenticated_android_ui_subject(peer_uid, &peer_domain)?;
    let mut line = Zeroizing::new(String::new());
    BufReader::new(stream.try_clone()?)
        .take(MAX_FRAME + 1)
        .read_line(&mut line)?;
    if line.is_empty() || line.len() as u64 > MAX_FRAME {
        bail!("invalid_or_oversized_android_agent_api_frame");
    }
    let mut request = SecretJson(parse_os_ui_request(line.as_bytes())?);
    if request.0.get("protocol").and_then(Value::as_str) != Some(PROTOCOL) {
        bail!("unsupported_android_agent_api_protocol");
    }
    let request_id = required_string(&request.0, "request_id", 128)?;
    let method = required_string(&request.0, "method", 64)?;
    let payload = SecretJson(
        request
            .0
            .get_mut("payload")
            .map(Value::take)
            .unwrap_or_else(|| json!({})),
    );
    let result = match method.as_str() {
        "get_context" => context_memory.run_ui_request_with_preflight_and_recovery(
            UiRequestBinding {
                method: &method,
                request_id: &request_id,
                subject: &subject,
                payload: &payload.0,
            },
            || {
                recover_original_context_capture_outcome(
                    context_memory,
                    &subject,
                    &request_id,
                    peer_uid,
                    &payload.0,
                )
            },
            || {
                prevalidate_context_capture(
                    context_memory,
                    &subject,
                    &request_id,
                    peer_uid,
                    &payload.0,
                )
            },
            |receipt| capture_context_validated(context_memory, &subject, &request_id, receipt),
        ),
        direct_agent_host_abi::BUILTIN_WIRE_METHOD_RUN_DIRECT_TURN => {
            let outcome = context_memory.run_ui_request_with_preflight_and_recovery(
                UiRequestBinding {
                    method: &method,
                    request_id: &request_id,
                    subject: &subject,
                    payload: &payload.0,
                },
                || {
                    let payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload.0)?);
                    let journal = action_consents
                        .lock()
                        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?;
                    match journal.recover_plan(
                        context_memory,
                        &request_id,
                        &payload_sha256,
                        peer_uid,
                        &peer_domain,
                    )? {
                        PlanWorkflowRecovery::Ready(response) => {
                            Ok(UiRequestRecovery::Outcome(Ok(response)))
                        }
                        PlanWorkflowRecovery::Indeterminate(reason) => {
                            Ok(UiRequestRecovery::Outcome(Err(reason)))
                        }
                        PlanWorkflowRecovery::Absent | PlanWorkflowRecovery::Resumable => {
                            Ok(UiRequestRecovery::Unresolved)
                        }
                    }
                },
                || {
                    prevalidate_plan(
                        egress_grants,
                        context_memory,
                        peer_uid,
                        &peer_domain,
                        &request_id,
                        &payload.0,
                    )
                },
                |validated| {
                    plan_validated(
                        service,
                        egress_grants,
                        active_egress,
                        action_consents,
                        context_memory,
                        peer_uid,
                        &peer_domain,
                        &request_id,
                        payload.0.clone(),
                        validated,
                    )
                },
            );
            ack_action_workflow_ui_completion_if_present(
                action_consents,
                context_memory,
                &method,
                &request_id,
                &subject,
                &payload.0,
            )?;
            outcome
        }
        "prepare_egress" => {
            let provider_id = required_string(&payload.0, "provider", 64)?;
            let registration = register_builtin_provider(service, &provider_id)?;
            let outcome = context_memory.run_ui_request_with_preflight_and_recovery(
                UiRequestBinding {
                    method: &method,
                    request_id: &request_id,
                    subject: &subject,
                    payload: &payload.0,
                },
                || {
                    recover_prepare_egress_outcome(
                        egress_grants,
                        context_memory,
                        &subject,
                        &registration,
                        &request_id,
                        &payload.0,
                    )
                },
                || {
                    exact_json_object_fields(
                        &payload.0,
                        &["context_id", "intent", "workflow_id", "provider"],
                        "egress_prepare_payload",
                    )?;
                    if agent_principal_registry::from_provider_id(&provider_id).is_none() {
                        bail!("unsupported_direct_provider");
                    }
                    Ok(registration.clone())
                },
                |validated_registration| {
                    prepare_egress(
                        egress_grants,
                        context_memory,
                        &subject,
                        &validated_registration,
                        &request_id,
                        payload.0.clone(),
                    )
                },
            );
            ack_egress_ui_completion_if_present(
                egress_grants,
                active_egress,
                context_memory,
                &method,
                &request_id,
                &subject,
                &payload.0,
            )?;
            outcome
        }
        "revoke_egress" => {
            let outcome = context_memory.run_ui_request_with_preflight_and_recovery(
                UiRequestBinding {
                    method: &method,
                    request_id: &request_id,
                    subject: &subject,
                    payload: &payload.0,
                },
                || {
                    recover_revoke_egress_outcome(
                        egress_grants,
                        peer_uid,
                        &peer_domain,
                        &request_id,
                        &payload.0,
                    )
                },
                || {
                    exact_json_object_fields(
                        &payload.0,
                        &["egress_grant_id", "workflow_id"],
                        "egress_revoke_payload",
                    )?;
                    Ok(())
                },
                |()| {
                    revoke_egress_with_context(
                        egress_grants,
                        active_egress,
                        Some(context_memory),
                        peer_uid,
                        &peer_domain,
                        &request_id,
                        payload.0.clone(),
                    )
                },
            );
            ack_egress_ui_completion_if_present(
                egress_grants,
                active_egress,
                context_memory,
                &method,
                &request_id,
                &subject,
                &payload.0,
            )?;
            outcome
        }
        "select_memory_context" => context_memory.run_ui_request_with_preflight_and_recovery(
            UiRequestBinding {
                method: &method,
                request_id: &request_id,
                subject: &subject,
                payload: &payload.0,
            },
            || {
                let object = exact_json_object_fields(
                    &payload.0,
                    &[
                        "memory_id",
                        "expected_payload_sha256",
                        "expected_updated_at_ms",
                    ],
                    "memory_context_selection_payload",
                )?;
                let memory_id = map_string(object, "memory_id")?;
                let payload_sha256 = map_lower_sha256(object, "expected_payload_sha256")?;
                let updated_at_ms = map_u64(object, "expected_updated_at_ms")?;
                Ok(
                    match context_memory.recover_memory_context_exact(
                        &subject,
                        &request_id,
                        memory_id,
                        payload_sha256,
                        updated_at_ms,
                    )? {
                        Some(value) => UiRequestRecovery::Outcome(Ok(value)),
                        None => UiRequestRecovery::Unresolved,
                    },
                )
            },
            || {
                exact_json_object_fields(
                    &payload.0,
                    &[
                        "memory_id",
                        "expected_payload_sha256",
                        "expected_updated_at_ms",
                    ],
                    "memory_context_selection_payload",
                )?;
                Ok(())
            },
            |()| {
                select_memory_context_for_request(
                    context_memory,
                    &subject,
                    &request_id,
                    payload.0.clone(),
                )
            },
        ),
        "save_memory" | "delete_memory" | "revoke_context" => context_memory
            .run_ui_request_with_preflight_and_recovery(
                UiRequestBinding {
                    method: &method,
                    request_id: &request_id,
                    subject: &subject,
                    payload: &payload.0,
                },
                || {
                    Ok(
                        match context_memory.query_call_replay_exact(
                            &method,
                            &request_id,
                            &subject,
                            &payload.0,
                        )? {
                            Some(outcome) => UiRequestRecovery::Outcome(outcome),
                            None => UiRequestRecovery::Unresolved,
                        },
                    )
                },
                || Ok(()),
                |()| context_memory.call(&method, &request_id, &subject, payload.0.clone()),
            ),
        _ => context_memory.run_ui_request(&method, &request_id, &subject, &payload.0, || {
            match method.as_str() {
                direct_agent_host_abi::BUILTIN_WIRE_METHOD_HEALTH => {
                    exact_json_object_fields(&payload.0, &[], "health_request")?;
                    Ok(android_ui_health(peer_uid, &peer_domain))
                }
                "provision_codex" => provision_codex(&subject, &payload.0),
                "authority_key_metadata" => {
                    exact_json_object_fields(&payload.0, &[], "authority_key_metadata_request")?;
                    authority_key_metadata(context_memory, &subject, &request_id)
                }
                "list_memory" => {
                    context_memory.call(&method, &request_id, &subject, payload.0.clone())
                }
                "recover_context_capture" => query_only_recover_context_capture(
                    context_memory,
                    &subject,
                    &request_id,
                    peer_uid,
                    &payload.0,
                ),
                "recover_memory_context" => query_only_recover_memory_context(
                    context_memory,
                    &subject,
                    &request_id,
                    &payload.0,
                ),
                "recover_egress_prepare" => query_only_recover_egress_prepare(
                    service,
                    egress_grants,
                    context_memory,
                    &subject,
                    &request_id,
                    &payload.0,
                ),
                "grant_context_to_agent" => issue_agent_data_grant(
                    service,
                    context_memory,
                    &subject,
                    payload.0.clone(),
                    "context",
                ),
                "grant_memory_to_agent" => {
                    bail!("direct_memory_grant_retired_use_select_memory_context")
                }
                "revoke_agent_data_grant" => {
                    exact_json_object_fields(
                        &payload.0,
                        &["grant_id"],
                        "agent_data_grant_revoke_request",
                    )?;
                    let grant_id = required_string(&payload.0, "grant_id", 96)?;
                    context_memory.revoke_agent_data_grant(&subject, &grant_id)
                }
                "egress_status" => {
                    egress_status(egress_grants, peer_uid, &peer_domain, payload.0.clone())
                }
                direct_agent_host_abi::BUILTIN_WIRE_METHOD_CANCEL_TASK => {
                    cancel(service, peer_uid, &request_id, payload.0.clone())
                }
                _ => bail!("unknown_or_ui_forbidden_android_agent_api_method"),
            }
        }),
    };
    Ok(match result {
        Ok(result) => json!({
            "protocol": PROTOCOL,
            "request_id": request_id,
            "ok": true,
            "result": result,
        }),
        Err(error) => json!({
            "protocol": PROTOCOL,
            "request_id": request_id,
            "ok": false,
            "error": error.to_string(),
        }),
    })
}

pub(crate) fn android_ui_health(peer_uid: u32, peer_domain: &str) -> Value {
    let selectable_providers = agent_principal_registry::PRODUCT_ALLOWLIST
        .iter()
        .map(|descriptor| descriptor.provider_id)
        .collect::<Vec<_>>();
    let provider_execution_modes = agent_principal_registry::PRODUCT_ALLOWLIST
        .iter()
        .map(|descriptor| {
            (
                descriptor.provider_id.to_string(),
                Value::String("agent_direct".to_string()),
            )
        })
        .collect::<Map<String, Value>>();
    json!({
        "api_version": AGENT_API_VERSION,
        "protocol": PROTOCOL,
        "direct_agent_host": direct_agent_host_abi::health_contract(),
        "tool_invocation_owned_by_agent": direct_agent_host_abi::TOOL_INVOCATION_OWNED_BY_AGENT,
        "tool_backend_owned_by_os": direct_agent_host_abi::TOOL_BACKEND_OWNED_BY_OS,
        "daemon_is_effect_executor": direct_agent_host_abi::DAEMON_IS_EFFECT_EXECUTOR,
        "contract_confers_effect_authority": direct_agent_host_abi::CONTRACT_CONFERS_EFFECT_AUTHORITY,
        "context_service_owned_by_os": true,
        "memory_service_owned_by_os": true,
        "authority_receipt_key_independently_pinned": true,
        "durable_request_replay_protection": true,
        "agent_data_delegation_mode": "metadata_only",
        "raw_agent_data_delegation_available": false,
        "stable_principal_authority": "agent_principal_registry_v2",
        "active_launcher_compile_time_authority_available":
            crate::builtin_provider_identity::compile_time_launcher_authority_available(),
        "active_launcher_admission": if crate::builtin_provider_identity::compile_time_launcher_authority_available() {
            "compile_time_measured_p01_launcher_required"
        } else {
            "runtime_file_description_measurement_required"
        },
        "codex_process_uid": codex_uid(),
        "codex_process_gid": codex_gid(),
        "selectable_providers": selectable_providers,
        "provider_execution_modes": provider_execution_modes,
        "peer_uid": peer_uid,
        "peer_domain": peer_domain,
    })
}

fn is_aishell_security_context(value: &str) -> bool {
    const BASE: &str = "u:r:trillionnium_aishell:s0";
    value == BASE
        || value
            .strip_prefix("u:r:trillionnium_aishell:s0:")
            .is_some_and(valid_mls_categories)
}

fn ensure_android_user_zero(uid: u32) -> Result<()> {
    if uid / ANDROID_UID_PER_USER_RANGE != 0 {
        bail!(ANDROID_USER_ZERO_CUSTODY_ERROR);
    }
    Ok(())
}

fn authenticated_android_ui_subject(peer_uid: u32, peer_domain: &str) -> Result<Subject> {
    if peer_uid < 10_000 || !is_aishell_security_context(peer_domain) {
        bail!("android_ui_peer_identity_denied");
    }
    ensure_android_user_zero(peer_uid)?;
    Subject::new(peer_uid, peer_domain)
}

fn valid_mls_categories(categories: &str) -> bool {
    fn category(value: &str) -> Option<u16> {
        value
            .strip_prefix('c')?
            .parse::<u16>()
            .ok()
            .filter(|value| *value <= 1023)
    }

    !categories.is_empty()
        && categories
            .split(',')
            .all(|item| match item.split_once('.') {
                Some((start, end)) => category(start)
                    .zip(category(end))
                    .is_some_and(|(start, end)| start <= end),
                None => category(item).is_some(),
            })
}

fn authority_key_metadata(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    request_id: &str,
) -> Result<Value> {
    ensure_android_user_zero(subject.uid)?;
    let gateway_request_id = unique_authority_key_metadata_request_id(request_id)?;
    let observed = AndroidGatewayAdapter::discover_authority_key_metadata(&gateway_request_id)
        .map_err(anyhow::Error::msg)?;
    let pin =
        context_memory.prevalidate_authority_key_metadata_against_frozen_pin(&observed.metadata)?;
    let key_id = pin
        .get("key_id")
        .and_then(Value::as_str)
        .context("authority_key_pin_id_missing")?;
    trillionnium_tool_runtime::commit_android_authority_boot_peer_pin(
        observed.peer_uid,
        &observed.peer_selinux_domain,
        key_id,
    )
    .map_err(anyhow::Error::msg)?;
    Ok(pin)
}

fn unique_authority_key_metadata_request_id(purpose: &str) -> Result<String> {
    let mut nonce = [0u8; 16];
    fill_kernel_random(&mut nonce)?;
    Ok(format!(
        "key-metadata-{}-{}",
        &sha256_bytes(purpose.as_bytes())[..24],
        &sha256_bytes(&nonce)[..32],
    ))
}

#[cfg(test)]
fn capture_context(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    request_id: &str,
    peer_uid: u32,
    payload: Value,
) -> Result<Value> {
    let receipt =
        prevalidate_context_capture(context_memory, subject, request_id, peer_uid, &payload)?;
    capture_context_validated(context_memory, subject, request_id, receipt)
}

fn prevalidate_context_capture(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    request_id: &str,
    peer_uid: u32,
    payload: &Value,
) -> Result<VerifiedContextCaptureReceipt> {
    ensure_android_user_zero(peer_uid)?;
    ensure_android_user_zero(subject.uid)?;
    exact_json_object_fields(
        payload,
        &["capture_id", "capture_receipt"],
        "context_capture_request",
    )?;
    let capture_id = required_string(payload, "capture_id", 80)?;
    if !capture_id
        .strip_prefix("capture-")
        .is_some_and(valid_lower_sha256)
    {
        bail!("context_capture_id_denied");
    }
    let encoded_receipt = required_string(payload, "capture_receipt", 256 * 1024)?;
    let authority_pin = context_memory.authority_key_pin()?;
    let receipt = verify_context_capture_receipt(
        request_id,
        &capture_id,
        peer_uid,
        &encoded_receipt,
        &authority_pin,
        now_unix_ms(),
    )?;
    if receipt.requesting_uid != subject.uid
        || receipt.subject_user_id != subject.uid / 100_000
        || receipt.requesting_uid != peer_uid
    {
        bail!("context_capture_subject_binding_mismatch");
    }
    Ok(receipt)
}

fn capture_context_validated(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    ui_request_id: &str,
    receipt: VerifiedContextCaptureReceipt,
) -> Result<Value> {
    ensure_android_user_zero(subject.uid)?;
    ensure_android_user_zero(receipt.requesting_uid)?;
    if receipt.subject_user_id != 0 {
        bail!(ANDROID_USER_ZERO_CUSTODY_ERROR);
    }
    ensure_context_capture_fresh_at_consume(receipt.expires_at_ms, now_unix_ms())?;
    context_memory.reserve_context_import_capacity(
        subject,
        ui_request_id,
        &receipt.capture_id,
        &receipt.receipt_id,
        &receipt.request_id,
        &receipt.source_id,
        &receipt.source_kind,
        &receipt.content_sha256,
        receipt.expires_at_ms,
    )?;
    let gateway_request_id = format!("context-resolve-{}", receipt.receipt_id);
    let adapter = AndroidGatewayAdapter::system_default();
    let dispatched = adapter.resolve_context_capture(
        &gateway_request_id,
        &receipt.capture_id,
        &receipt.receipt_id,
        &receipt.request_id,
        receipt.requesting_uid,
        receipt.subject_user_id,
    );
    // Authority owns the canonical resolution bytes and digest. Always query
    // its durable journal after resolve so daemon custody never hashes a
    // reserialized JSONObject or mistakes a lost response for no dispatch.
    let (capture_state, resolution_sha256, durable_resolution, imported_context_id) =
        match query_authority_context_capture_recovery(&adapter, &receipt, &gateway_request_id)? {
            AuthorityContextCaptureRecovery::Resolution {
                capture_state,
                resolution_sha256,
                resolution,
                imported_context_id,
            } => (
                capture_state,
                resolution_sha256,
                resolution,
                imported_context_id,
            ),
            AuthorityContextCaptureRecovery::Staged => {
                return Err(dispatched
                    .err()
                    .map(anyhow::Error::msg)
                    .unwrap_or_else(|| anyhow::anyhow!("context_capture_not_durably_consumed")));
            }
            AuthorityContextCaptureRecovery::Indeterminate => {
                bail!("context_capture_outcome_indeterminate_no_reexecution")
            }
        };
    if let Ok(observed) = dispatched
        && observed != durable_resolution
    {
        bail!("context_capture_resolve_and_recovery_semantic_mismatch");
    }
    let mut resolution = SecretJson(durable_resolution);
    let resolution_fields = match receipt.source_kind.as_str() {
        "file" => SAF_CONTEXT_RESOLUTION_FIELDS,
        "browser" => BROWSER_CONTEXT_RESOLUTION_FIELDS,
        _ => bail!("context_resolution_source_variant_denied"),
    };
    let resolved =
        exact_json_object_fields(&resolution.0, resolution_fields, "context_resolution")?;
    exact_map_string(resolved, "schema", CONTEXT_RESOLUTION_SCHEMA)?;
    exact_map_string(resolved, "capture_id", &receipt.capture_id)?;
    exact_map_string(resolved, "capture_receipt_id", &receipt.receipt_id)?;
    exact_map_string(resolved, "capture_request_id", &receipt.request_id)?;
    exact_map_u64(
        resolved,
        "requesting_uid",
        u64::from(receipt.requesting_uid),
    )?;
    exact_map_u64(
        resolved,
        "subject_user_id",
        u64::from(receipt.subject_user_id),
    )?;
    verify_context_resolution_requester_identity(resolved)?;
    exact_map_string(resolved, "boot_id_sha256", &receipt.boot_id_sha256)?;
    exact_map_string(resolved, "capture_method", &receipt.capture_method)?;
    exact_map_string(resolved, "source_kind", &receipt.source_kind)?;
    exact_map_string(resolved, "source_id", &receipt.source_id)?;
    exact_map_string(resolved, "privacy_class", &receipt.privacy_class)?;
    match receipt.source_kind.as_str() {
        "file" => {
            exact_map_string(resolved, "provider_package", &receipt.provider_package)?;
            exact_map_u64(resolved, "provider_uid", u64::from(receipt.provider_uid))?;
            exact_map_string(
                resolved,
                "provider_authority_sha256",
                &receipt.provider_authority_sha256,
            )?;
            exact_map_string(resolved, "document_id_sha256", &receipt.document_id_sha256)?;
            exact_map_string(
                resolved,
                "display_name_sha256",
                &receipt.display_name_sha256,
            )?;
            exact_map_string(resolved, "mime_type", &receipt.mime_type)?;
            exact_map_i64(resolved, "declared_size_bytes", receipt.declared_size_bytes)?;
            exact_map_u64(resolved, "last_modified_ms", receipt.last_modified_ms)?;
            exact_map_u64(resolved, "document_flags", receipt.document_flags)?;
            exact_map_bool(resolved, "metadata_query_complete", true)?;
            exact_map_bool(resolved, "provider_metadata_asserted", true)?;
        }
        "browser" => {
            exact_map_string(resolved, "url_sha256", &receipt.content_sha256)?;
            exact_map_u64(resolved, "url_bytes", u64::try_from(receipt.content_bytes)?)?;
            exact_map_string(resolved, "url_host_sha256", &receipt.url_host_sha256)?;
            exact_map_bool(resolved, "user_entered_in_authority_ui", true)?;
            exact_map_bool(resolved, "explicit_user_confirmation", true)?;
        }
        _ => unreachable!(),
    }
    exact_map_string(resolved, "content_sha256", &receipt.content_sha256)?;
    exact_map_u64(
        resolved,
        "content_bytes",
        u64::try_from(receipt.content_bytes)?,
    )?;
    exact_map_u64(resolved, "captured_at_ms", receipt.captured_at_ms)?;
    exact_map_u64(resolved, "expires_at_ms", receipt.expires_at_ms)?;
    exact_map_bool(resolved, "single_use_consumed", true)?;

    let content_slot = resolution
        .0
        .as_object_mut()
        .and_then(|object| object.get_mut("content"))
        .context("context_resolution_content_missing")?;
    let content = match content_slot {
        Value::String(text) => Zeroizing::new(std::mem::take(text)),
        _ => {
            let _rejected = SecretJson(Value::take(content_slot));
            bail!("context_resolution_content_not_string");
        }
    };
    verify_context_resolution_content(&receipt, &content)?;
    let source_metadata = match receipt.source_kind.as_str() {
        "file" => json!({
            "capture_method": receipt.capture_method,
            "provider_package": receipt.provider_package,
            "provider_uid": receipt.provider_uid,
            "provider_authority_sha256": receipt.provider_authority_sha256,
            "document_id_sha256": receipt.document_id_sha256,
            "display_name_sha256": receipt.display_name_sha256,
            "mime_type": receipt.mime_type,
            "declared_size_bytes": receipt.declared_size_bytes,
            "last_modified_ms": receipt.last_modified_ms,
            "document_flags": receipt.document_flags,
            "metadata_query_complete": true,
            "provider_metadata_asserted": true,
            "raw_content_returned_to_ui": false,
        }),
        "browser" => json!({
            "capture_method": receipt.capture_method,
            "url_host_sha256": receipt.url_host_sha256,
            "user_entered_in_authority_ui": true,
            "explicit_user_confirmation": true,
            "raw_content_returned_to_ui": false,
        }),
        _ => unreachable!(),
    };
    let imported = context_memory.insert_verified_context(
        subject,
        VerifiedContextCapture {
            capture_id: receipt.capture_id.clone(),
            capture_receipt_id: receipt.receipt_id.clone(),
            capture_request_id: receipt.request_id.clone(),
            requesting_uid: receipt.requesting_uid,
            subject_user_id: receipt.subject_user_id,
            boot_id_sha256: receipt.boot_id_sha256.clone(),
            source_id: receipt.source_id.clone(),
            source_kind: receipt.source_kind.clone(),
            captured_at_ms: receipt.captured_at_ms,
            expires_at_ms: receipt.expires_at_ms,
            privacy_class: receipt.privacy_class.clone(),
            content_sha256: receipt.content_sha256.clone(),
            content_bytes: receipt.content_bytes,
            content: content.as_str().to_string(),
            source_metadata,
            origin_request_id: ui_request_id.to_string(),
            resolution_sha256: resolution_sha256.clone(),
        },
    );
    let imported = match imported {
        Ok(value) => value,
        Err(error) => {
            if context_memory.context_journal_publication_is_uncertain() {
                let request_id = format!("context-indeterminate-{}", receipt.receipt_id);
                let _ = adapter.mark_context_capture_indeterminate(
                    &request_id,
                    &gateway_request_id,
                    &receipt.capture_id,
                    &receipt.receipt_id,
                    &receipt.request_id,
                    receipt.requesting_uid,
                    receipt.subject_user_id,
                    &receipt.source_id,
                    &receipt.content_sha256,
                    &resolution_sha256,
                );
            }
            return Err(error);
        }
    };
    let context_id = required_string(&imported, "context_id", 96)?;
    if capture_state == "imported" {
        if imported_context_id != context_id {
            bail!("context_capture_imported_context_id_substitution_denied");
        }
    } else {
        let ack_request_id = format!("context-import-ack-{}", receipt.receipt_id);
        let ack = adapter
            .acknowledge_context_capture_imported(
                &ack_request_id,
                &gateway_request_id,
                &receipt.capture_id,
                &receipt.receipt_id,
                &receipt.request_id,
                receipt.requesting_uid,
                receipt.subject_user_id,
                &receipt.source_id,
                &receipt.content_sha256,
                &resolution_sha256,
                &context_id,
            )
            .map_err(anyhow::Error::msg)?;
        match parse_authority_context_capture_recovery(&ack, &receipt, &gateway_request_id)? {
            AuthorityContextCaptureRecovery::Resolution {
                capture_state,
                resolution_sha256: acknowledged_resolution_sha256,
                imported_context_id,
                ..
            } if capture_state == "imported"
                && acknowledged_resolution_sha256 == resolution_sha256
                && imported_context_id == context_id => {}
            _ => bail!("context_capture_import_ack_state_or_binding_denied"),
        }
    }
    context_memory.acknowledge_context_imported(subject, &context_id, &resolution_sha256)
}

fn ensure_context_capture_fresh_at_consume(expires_at_ms: u64, now_ms: u64) -> Result<()> {
    if expires_at_ms <= now_ms {
        bail!("context_capture_expired_before_gateway_consume");
    }
    Ok(())
}

fn publish_authority_context_resolution(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    ui_request_id: &str,
    receipt: &VerifiedContextCaptureReceipt,
    resolution_sha256: &str,
    resolution: Value,
) -> Result<Value> {
    let mut resolution = SecretJson(resolution);
    let resolution_fields = match receipt.source_kind.as_str() {
        "file" => SAF_CONTEXT_RESOLUTION_FIELDS,
        "browser" => BROWSER_CONTEXT_RESOLUTION_FIELDS,
        _ => bail!("context_resolution_source_variant_denied"),
    };
    let resolved =
        exact_json_object_fields(&resolution.0, resolution_fields, "context_resolution")?;
    exact_map_string(resolved, "schema", CONTEXT_RESOLUTION_SCHEMA)?;
    exact_map_string(resolved, "capture_id", &receipt.capture_id)?;
    exact_map_string(resolved, "capture_receipt_id", &receipt.receipt_id)?;
    exact_map_string(resolved, "capture_request_id", &receipt.request_id)?;
    exact_map_u64(
        resolved,
        "requesting_uid",
        u64::from(receipt.requesting_uid),
    )?;
    exact_map_u64(
        resolved,
        "subject_user_id",
        u64::from(receipt.subject_user_id),
    )?;
    verify_context_resolution_requester_identity(resolved)?;
    exact_map_string(resolved, "boot_id_sha256", &receipt.boot_id_sha256)?;
    exact_map_string(resolved, "capture_method", &receipt.capture_method)?;
    exact_map_string(resolved, "source_kind", &receipt.source_kind)?;
    exact_map_string(resolved, "source_id", &receipt.source_id)?;
    exact_map_string(resolved, "privacy_class", &receipt.privacy_class)?;
    match receipt.source_kind.as_str() {
        "file" => {
            exact_map_string(resolved, "provider_package", &receipt.provider_package)?;
            exact_map_u64(resolved, "provider_uid", u64::from(receipt.provider_uid))?;
            exact_map_string(
                resolved,
                "provider_authority_sha256",
                &receipt.provider_authority_sha256,
            )?;
            exact_map_string(resolved, "document_id_sha256", &receipt.document_id_sha256)?;
            exact_map_string(
                resolved,
                "display_name_sha256",
                &receipt.display_name_sha256,
            )?;
            exact_map_string(resolved, "mime_type", &receipt.mime_type)?;
            exact_map_i64(resolved, "declared_size_bytes", receipt.declared_size_bytes)?;
            exact_map_u64(resolved, "last_modified_ms", receipt.last_modified_ms)?;
            exact_map_u64(resolved, "document_flags", receipt.document_flags)?;
            exact_map_bool(resolved, "metadata_query_complete", true)?;
            exact_map_bool(resolved, "provider_metadata_asserted", true)?;
        }
        "browser" => {
            exact_map_string(resolved, "url_sha256", &receipt.content_sha256)?;
            exact_map_u64(resolved, "url_bytes", u64::try_from(receipt.content_bytes)?)?;
            exact_map_string(resolved, "url_host_sha256", &receipt.url_host_sha256)?;
            exact_map_bool(resolved, "user_entered_in_authority_ui", true)?;
            exact_map_bool(resolved, "explicit_user_confirmation", true)?;
        }
        _ => unreachable!(),
    }
    exact_map_string(resolved, "content_sha256", &receipt.content_sha256)?;
    exact_map_u64(
        resolved,
        "content_bytes",
        u64::try_from(receipt.content_bytes)?,
    )?;
    exact_map_u64(resolved, "captured_at_ms", receipt.captured_at_ms)?;
    exact_map_u64(resolved, "expires_at_ms", receipt.expires_at_ms)?;
    exact_map_bool(resolved, "single_use_consumed", true)?;
    let content_slot = resolution
        .0
        .as_object_mut()
        .and_then(|object| object.get_mut("content"))
        .context("context_resolution_content_missing")?;
    let content = match content_slot {
        Value::String(text) => Zeroizing::new(std::mem::take(text)),
        _ => {
            let _rejected = SecretJson(Value::take(content_slot));
            bail!("context_resolution_content_not_string");
        }
    };
    verify_context_resolution_content(receipt, &content)?;
    let source_metadata = match receipt.source_kind.as_str() {
        "file" => json!({
            "capture_method": receipt.capture_method,
            "provider_package": receipt.provider_package,
            "provider_uid": receipt.provider_uid,
            "provider_authority_sha256": receipt.provider_authority_sha256,
            "document_id_sha256": receipt.document_id_sha256,
            "display_name_sha256": receipt.display_name_sha256,
            "mime_type": receipt.mime_type,
            "declared_size_bytes": receipt.declared_size_bytes,
            "last_modified_ms": receipt.last_modified_ms,
            "document_flags": receipt.document_flags,
            "metadata_query_complete": true,
            "provider_metadata_asserted": true,
            "raw_content_returned_to_ui": false,
            "raw_cleartext_persisted": false,
            "encrypted_context_payload_persisted": true,
        }),
        "browser" => json!({
            "capture_method": receipt.capture_method,
            "url_host_sha256": receipt.url_host_sha256,
            "user_entered_in_authority_ui": true,
            "explicit_user_confirmation": true,
            "raw_content_returned_to_ui": false,
            "raw_cleartext_persisted": false,
            "encrypted_context_payload_persisted": true,
        }),
        _ => unreachable!(),
    };
    context_memory.insert_verified_context(
        subject,
        VerifiedContextCapture {
            capture_id: receipt.capture_id.clone(),
            capture_receipt_id: receipt.receipt_id.clone(),
            capture_request_id: receipt.request_id.clone(),
            requesting_uid: receipt.requesting_uid,
            subject_user_id: receipt.subject_user_id,
            boot_id_sha256: receipt.boot_id_sha256.clone(),
            source_id: receipt.source_id.clone(),
            source_kind: receipt.source_kind.clone(),
            captured_at_ms: receipt.captured_at_ms,
            expires_at_ms: receipt.expires_at_ms,
            privacy_class: receipt.privacy_class.clone(),
            content_sha256: receipt.content_sha256.clone(),
            content_bytes: receipt.content_bytes,
            content: content.as_str().to_string(),
            source_metadata,
            origin_request_id: ui_request_id.to_string(),
            resolution_sha256: resolution_sha256.to_string(),
        },
    )
}

fn acknowledge_authority_context_import(
    adapter: &AndroidGatewayAdapter,
    receipt: &VerifiedContextCaptureReceipt,
    original_resolve_request_id: &str,
    resolution_sha256: &str,
    context_id: &str,
) -> Result<()> {
    let ack_request_id = format!("context-import-ack-{}", receipt.receipt_id);
    let ack = adapter
        .acknowledge_context_capture_imported(
            &ack_request_id,
            original_resolve_request_id,
            &receipt.capture_id,
            &receipt.receipt_id,
            &receipt.request_id,
            receipt.requesting_uid,
            receipt.subject_user_id,
            &receipt.source_id,
            &receipt.content_sha256,
            resolution_sha256,
            context_id,
        )
        .map_err(anyhow::Error::msg)?;
    match parse_authority_context_capture_recovery(&ack, receipt, original_resolve_request_id)? {
        AuthorityContextCaptureRecovery::Resolution {
            capture_state,
            resolution_sha256: acknowledged_resolution_sha256,
            imported_context_id,
            ..
        } if capture_state == "imported"
            && acknowledged_resolution_sha256 == resolution_sha256
            && imported_context_id == context_id =>
        {
            Ok(())
        }
        _ => bail!("context_capture_import_ack_state_or_binding_denied"),
    }
}

fn recover_original_context_capture_outcome(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    original_ui_request_id: &str,
    peer_uid: u32,
    payload: &Value,
) -> Result<UiRequestRecovery> {
    let receipt = prevalidate_context_capture(
        context_memory,
        subject,
        original_ui_request_id,
        peer_uid,
        payload,
    )?;
    let original_resolve_request_id = format!("context-resolve-{}", receipt.receipt_id);
    let adapter = AndroidGatewayAdapter::system_default();
    let recovery =
        query_authority_context_capture_recovery(&adapter, &receipt, &original_resolve_request_id)?;
    let AuthorityContextCaptureRecovery::Resolution {
        capture_state,
        resolution_sha256,
        resolution,
        imported_context_id,
    } = recovery
    else {
        return Ok(match recovery {
            AuthorityContextCaptureRecovery::Staged => UiRequestRecovery::Unresolved,
            AuthorityContextCaptureRecovery::Indeterminate => UiRequestRecovery::Outcome(Err(
                "context_capture_outcome_indeterminate_no_reexecution".to_string(),
            )),
            AuthorityContextCaptureRecovery::Resolution { .. } => unreachable!(),
        });
    };
    let mut local = context_memory.context_import_candidate_exact(
        subject,
        original_ui_request_id,
        &receipt.capture_id,
        &receipt.receipt_id,
        &resolution_sha256,
    )?;
    if local.is_none() {
        let metadata = publish_authority_context_resolution(
            context_memory,
            subject,
            original_ui_request_id,
            &receipt,
            &resolution_sha256,
            resolution,
        )?;
        let context_id = required_string(&metadata, "context_id", 96)?;
        local = Some((context_id, "published_pending_ack".to_string(), metadata));
    }
    let (context_id, local_state, _) = local.context("context_import_candidate_missing")?;
    match capture_state.as_str() {
        "consumed" => acknowledge_authority_context_import(
            &adapter,
            &receipt,
            &original_resolve_request_id,
            &resolution_sha256,
            &context_id,
        )?,
        "imported" if imported_context_id == context_id => {}
        _ => bail!("context_capture_recovery_authority_import_binding_denied"),
    }
    let metadata = if local_state == "imported" {
        context_memory
            .recover_imported_context_exact(
                subject,
                original_ui_request_id,
                &receipt.capture_id,
                &receipt.receipt_id,
                &resolution_sha256,
            )?
            .context("context_capture_recovery_live_import_missing")?
    } else {
        context_memory.acknowledge_context_imported(subject, &context_id, &resolution_sha256)?
    };
    Ok(UiRequestRecovery::Outcome(Ok(metadata)))
}

fn query_only_recover_context_capture(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    recovery_request_id: &str,
    peer_uid: u32,
    payload: &Value,
) -> Result<Value> {
    exact_json_object_fields(
        payload,
        &["original_request_id", "capture_id", "capture_receipt"],
        "context_capture_query_only_recovery_payload",
    )?;
    let original_request_id = required_string(payload, "original_request_id", 128)?;
    if original_request_id == recovery_request_id {
        bail!("context_capture_recovery_request_id_must_be_distinct");
    }
    let original_payload = json!({
        "capture_id": required_string(payload, "capture_id", 80)?,
        "capture_receipt": required_string(payload, "capture_receipt", 256 * 1024)?,
    });
    // This reuses only the already-durable Authority resolution and the exact
    // local import journal. It may finish a pending publication/ack, but it
    // never invokes `resolve_context` and therefore never consumes or
    // re-executes the capture.
    let mut metadata = match recover_original_context_capture_outcome(
        context_memory,
        subject,
        &original_request_id,
        peer_uid,
        &original_payload,
    )? {
        UiRequestRecovery::Outcome(Ok(value)) => value,
        UiRequestRecovery::Outcome(Err(error)) => return Err(anyhow::Error::msg(error)),
        UiRequestRecovery::Unresolved => {
            bail!("context_capture_query_only_recovery_not_available")
        }
    };
    metadata
        .as_object_mut()
        .context("context_capture_recovery_metadata_not_object")?
        .insert(
            "recovery_status".to_string(),
            Value::String("context_available".to_string()),
        );
    metadata
        .as_object_mut()
        .context("context_capture_recovery_metadata_not_object")?
        .insert(
            "original_request_id".to_string(),
            Value::String(original_request_id),
        );
    Ok(metadata)
}

enum AuthorityContextCaptureRecovery {
    Staged,
    Indeterminate,
    Resolution {
        capture_state: String,
        resolution_sha256: String,
        resolution: Value,
        imported_context_id: String,
    },
}

fn query_authority_context_capture_recovery(
    adapter: &AndroidGatewayAdapter,
    receipt: &VerifiedContextCaptureReceipt,
    original_resolve_request_id: &str,
) -> Result<AuthorityContextCaptureRecovery> {
    let request_id = format!(
        "context-recover-{}",
        sha256_bytes(
            format!(
                "{}\n{}\n{}",
                original_resolve_request_id, receipt.capture_id, receipt.receipt_id
            )
            .as_bytes()
        )
    );
    let value = adapter
        .recover_context_capture(
            &request_id,
            original_resolve_request_id,
            &receipt.capture_id,
            &receipt.receipt_id,
            &receipt.request_id,
            receipt.requesting_uid,
            receipt.subject_user_id,
            &receipt.source_id,
            &receipt.content_sha256,
        )
        .map_err(anyhow::Error::msg)?;
    parse_authority_context_capture_recovery(&value, receipt, original_resolve_request_id)
}

fn parse_authority_context_capture_recovery(
    value: &Value,
    receipt: &VerifiedContextCaptureReceipt,
    original_resolve_request_id: &str,
) -> Result<AuthorityContextCaptureRecovery> {
    let object = exact_json_object_fields(
        value,
        CONTEXT_CAPTURE_RECOVERY_FIELDS,
        "context_capture_recovery",
    )?;
    exact_map_string(object, "schema", CONTEXT_CAPTURE_RECOVERY_SCHEMA)?;
    exact_map_string(object, "capture_id", &receipt.capture_id)?;
    exact_map_string(object, "capture_request_id", &receipt.request_id)?;
    exact_map_string(object, "original_request_id", original_resolve_request_id)?;
    exact_map_string(object, "capture_receipt_id", &receipt.receipt_id)?;
    exact_map_string(object, "source_id", &receipt.source_id)?;
    exact_map_string(object, "content_sha256", &receipt.content_sha256)?;
    exact_map_u64(object, "capture_expires_at_ms", receipt.expires_at_ms)?;

    let encoded_receipt_b64 = map_string(object, "capture_receipt_json_b64")?;
    let receipt_bytes_sha256 = map_string(object, "capture_receipt_bytes_sha256")?;
    let state = map_string(object, "capture_state")?;
    let status = map_string(object, "recovery_status")?;
    let resolution_sha256 = map_string(object, "resolution_sha256")?;
    let resolution_b64 = map_string(object, "resolution_json_b64")?;
    let imported_context_id = map_string(object, "imported_context_id")?;
    let indeterminate_reason = map_string(object, "indeterminate_reason_code")?;
    let peer_binding_sha256 = map_string(object, "gateway_peer_binding_sha256")?;
    let recovery_expires_at_ms = map_u64(object, "recovery_expires_at_ms")?;

    if state == "missing" && status == "not_found" {
        bail!("context_capture_recovery_not_found");
    }
    let receipt_bytes = decode_canonical_base64(
        encoded_receipt_b64,
        "context_capture_recovery_receipt",
        256 * 1024,
    )?;
    if receipt_bytes != receipt.encoded_receipt.as_bytes()
        || receipt_bytes_sha256 != sha256_bytes(&receipt_bytes)
    {
        bail!("context_capture_recovery_receipt_bytes_substitution_denied");
    }
    match (state, status) {
        ("staged", "staged") => {
            if !resolution_sha256.is_empty()
                || !resolution_b64.is_empty()
                || !imported_context_id.is_empty()
                || !indeterminate_reason.is_empty()
                || !peer_binding_sha256.is_empty()
                || recovery_expires_at_ms != 0
            {
                bail!("context_capture_staged_recovery_shape_denied");
            }
            Ok(AuthorityContextCaptureRecovery::Staged)
        }
        ("indeterminate", "indeterminate") => {
            if recovery_expires_at_ms <= now_unix_ms()
                || !valid_lower_sha256(resolution_sha256)
                || !resolution_b64.is_empty()
                || !imported_context_id.is_empty()
                || indeterminate_reason != "daemon_context_import_publication_uncertain"
                || !valid_lower_sha256(peer_binding_sha256)
            {
                bail!("context_capture_indeterminate_recovery_shape_denied");
            }
            Ok(AuthorityContextCaptureRecovery::Indeterminate)
        }
        ("consumed" | "imported", "resolution_available") => {
            if recovery_expires_at_ms <= now_unix_ms()
                || !valid_lower_sha256(resolution_sha256)
                || !valid_lower_sha256(peer_binding_sha256)
                || !indeterminate_reason.is_empty()
                || (state == "consumed" && !imported_context_id.is_empty())
                || (state == "imported"
                    && !imported_context_id
                        .strip_prefix("context-")
                        .is_some_and(valid_lower_sha256))
            {
                bail!("context_capture_available_recovery_shape_denied");
            }
            let resolution_bytes = decode_canonical_base64(
                resolution_b64,
                "context_capture_recovery_resolution",
                256 * 1024,
            )?;
            if sha256_bytes(&resolution_bytes) != resolution_sha256 {
                bail!("context_capture_recovery_resolution_digest_mismatch");
            }
            let resolution = parse_strict_json(
                std::str::from_utf8(&resolution_bytes)
                    .context("context_capture_recovery_resolution_not_utf8")?,
                "context_capture_recovery_resolution",
            )?;
            Ok(AuthorityContextCaptureRecovery::Resolution {
                capture_state: state.to_string(),
                resolution_sha256: resolution_sha256.to_string(),
                resolution,
                imported_context_id: imported_context_id.to_string(),
            })
        }
        _ => bail!("context_capture_recovery_state_or_status_denied"),
    }
}

fn verify_context_resolution_content(
    receipt: &VerifiedContextCaptureReceipt,
    content: &str,
) -> Result<()> {
    if content.is_empty()
        || content.len() != receipt.content_bytes
        || content.len() > MAX_CONTEXT_CAPTURE_BYTES as usize
        || content.as_bytes().contains(&0)
        || sha256_bytes(content.as_bytes()) != receipt.content_sha256
    {
        bail!("context_resolution_content_integrity_mismatch");
    }
    if receipt.source_kind == "browser" {
        let canonical = Zeroizing::new(canonical_https_execution_url(content)?);
        let parsed =
            url::Url::parse(content).context("context_resolution_browser_url_parse_denied")?;
        let host = parsed
            .host_str()
            .context("context_resolution_browser_host_missing")?;
        if canonical.as_str() != content || sha256_bytes(host.as_bytes()) != receipt.url_host_sha256
        {
            bail!("context_resolution_browser_url_binding_mismatch");
        }
    }
    Ok(())
}

fn verify_context_resolution_requester_identity(resolved: &Map<String, Value>) -> Result<()> {
    exact_map_string(resolved, "requesting_package", "org.trillionnium.aishell")?;
    exact_map_string(resolved, "requesting_signer_sha256", AI_SHELL_SIGNER_SHA256)?;
    Ok(())
}

fn verify_context_capture_receipt(
    request_id: &str,
    capture_id: &str,
    peer_uid: u32,
    encoded_receipt: &str,
    authority_key_pin: &Value,
    now: u64,
) -> Result<VerifiedContextCaptureReceipt> {
    if encoded_receipt.is_empty() || encoded_receipt.len() > 256 * 1024 {
        bail!("context_capture_receipt_boundary_denied");
    }
    let receipt_value = parse_strict_json(encoded_receipt, "context_capture_receipt")?;
    let untrusted_receipt = receipt_value
        .as_object()
        .context("context_capture_receipt_not_object")?;
    let capture_method = map_string(untrusted_receipt, "capture_method")?;
    let expected_fields = match capture_method {
        "android_saf_forwarded_read_grant" => SAF_CONTEXT_CAPTURE_RECEIPT_FIELDS,
        "android_authority_secure_https_url_entry" => BROWSER_CONTEXT_CAPTURE_RECEIPT_FIELDS,
        _ => bail!("context_capture_method_denied"),
    };
    let receipt =
        exact_json_object_fields(&receipt_value, expected_fields, "context_capture_receipt")?;
    let pin =
        exact_json_object_fields(authority_key_pin, AUTHORITY_PIN_FIELDS, "authority_key_pin")?;

    exact_map_string(receipt, "schema", CONTEXT_CAPTURE_SCHEMA)?;
    exact_map_string(receipt, "decision", "CAPTURED")?;
    exact_map_string(receipt, "capture_id", capture_id)?;
    exact_map_string(receipt, "capture_request_id", request_id)?;
    exact_map_string(receipt, "requesting_package", "org.trillionnium.aishell")?;
    exact_map_u64(receipt, "requesting_uid", u64::from(peer_uid))?;
    exact_map_u64(receipt, "subject_user_id", u64::from(peer_uid / 100_000))?;
    exact_map_string(receipt, "requesting_signer_sha256", AI_SHELL_SIGNER_SHA256)?;
    exact_map_string(receipt, "boot_id_sha256", &current_boot_id_sha256()?)?;
    exact_map_string(receipt, "privacy_class", "local_private")?;
    exact_map_bool(receipt, "single_use", true)?;
    exact_map_bool(receipt, "raw_content_returned_to_ui", false)?;

    exact_map_string(
        receipt,
        "receipt_signature_algorithm",
        AUTHORITY_SIGNATURE_ALGORITHM,
    )?;
    exact_map_string(pin, "schema", "trillionnium.authority-key-pin.v1")?;
    exact_map_bool(pin, "hardware_backed", true)?;
    exact_map_bool(pin, "internal_pin_verified", true)?;
    exact_map_bool(pin, "public_release_eligible", false)?;
    exact_map_string(pin, "rotation_contract", AUTHORITY_ROTATION_CONTRACT)?;
    if !matches!(
        map_string(pin, "security_level")?,
        "STRONGBOX" | "TRUSTED_ENVIRONMENT"
    ) {
        bail!("authority_context_key_not_hardware_backed");
    }
    let pin_epoch = map_u64(pin, "key_epoch")?;
    if pin_epoch != AUTHORITY_RECEIPT_KEY_EPOCH {
        bail!("authority_context_key_epoch_denied");
    }
    let pin_key_id = map_lower_sha256(pin, "key_id")?;
    let pin_spki = map_string(pin, "public_key_spki")?;
    let spki_der = decode_canonical_base64(pin_spki, "authority_context_spki", 4_096)?;
    if hex_sha256(&spki_der) != pin_key_id {
        bail!("authority_context_spki_pin_digest_mismatch");
    }
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|_| anyhow::anyhow!("authority_context_spki_not_p256"))?;
    exact_map_string(receipt, "receipt_signing_key_id", pin_key_id)?;
    exact_map_u64(receipt, "receipt_signing_key_epoch", pin_epoch)?;
    exact_map_string(
        receipt,
        "receipt_signing_security_level",
        map_string(pin, "security_level")?,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_rotation_contract",
        AUTHORITY_ROTATION_CONTRACT,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_key_metadata_protocol",
        trillionnium_tool_runtime::ANDROID_GATEWAY_PROTOCOL,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_key_metadata_method",
        "key_metadata",
    )?;
    exact_map_bool(
        receipt,
        "receipt_signing_public_key_is_identity_root",
        false,
    )?;
    exact_map_string(receipt, "receipt_signing_public_key_spki", pin_spki)?;
    validate_authority_receipt_key_profile(receipt, pin)?;
    let signature_der = decode_canonical_base64(
        map_string(receipt, "receipt_signature")?,
        "context_capture_receipt_signature",
        256,
    )?;
    let signature = Signature::from_der(&signature_der)
        .map_err(|_| anyhow::anyhow!("context_capture_signature_not_strict_der"))?;
    if signature.normalize_s().is_some() {
        bail!("context_capture_signature_noncanonical_high_s");
    }
    verifying_key
        .verify(canonical_receipt(receipt, true)?.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("context_capture_signature_verification_failed"))?;
    let receipt_id = map_lower_sha256(receipt, "receipt_id")?;
    if receipt_id != hex_sha256(canonical_receipt(receipt, false)?.as_bytes()) {
        bail!("context_capture_canonical_receipt_id_mismatch");
    }

    let content_bytes = usize::try_from(map_u64(receipt, "content_bytes")?)?;
    if content_bytes == 0 || content_bytes > MAX_CONTEXT_CAPTURE_BYTES as usize {
        bail!("context_capture_content_boundary_denied");
    }
    let content_sha256 = map_lower_sha256(receipt, "content_sha256")?.to_string();
    let source_id = map_string(receipt, "source_id")?;
    if source_id.is_empty() || source_id.len() > 512 || source_id.chars().any(char::is_control) {
        bail!("context_capture_source_metadata_denied");
    }
    let (
        source_kind,
        provider_package,
        provider_uid,
        provider_authority_sha256,
        document_id_sha256,
        display_name_sha256,
        mime_type,
        declared_size_bytes,
        last_modified_ms,
        document_flags,
        url_host_sha256,
    ) = match capture_method {
        "android_saf_forwarded_read_grant" => {
            exact_map_string(receipt, "source_kind", "file")?;
            exact_map_string(receipt, "uri_scheme", "content")?;
            exact_map_bool(receipt, "metadata_query_complete", true)?;
            exact_map_bool(receipt, "provider_metadata_asserted", true)?;
            let provider_authority = map_lower_sha256(receipt, "provider_authority_sha256")?;
            let document_id = map_lower_sha256(receipt, "document_id_sha256")?;
            let expected_source_id =
                format!("saf-provider:{provider_authority}:document:{document_id}");
            if source_id != expected_source_id {
                bail!("context_capture_source_id_digest_binding_mismatch");
            }
            let provider_package = map_string(receipt, "provider_package")?;
            let mime_type = map_string(receipt, "mime_type")?;
            if provider_package.is_empty()
                || provider_package.len() > 256
                || provider_package.chars().any(char::is_control)
                || mime_type.is_empty()
                || mime_type.len() > 256
                || !(mime_type.starts_with("text/") || mime_type == "application/json")
            {
                bail!("context_capture_source_metadata_denied");
            }
            let provider_uid = u32::try_from(map_u64(receipt, "provider_uid")?)?;
            if provider_uid / 100_000 != peer_uid / 100_000 {
                bail!("context_capture_provider_user_mismatch");
            }
            let declared_size_bytes = map_i64(receipt, "declared_size_bytes")?;
            if declared_size_bytes < -1 {
                bail!("context_capture_declared_size_denied");
            }
            (
                "file".to_string(),
                provider_package.to_string(),
                provider_uid,
                provider_authority.to_string(),
                document_id.to_string(),
                map_lower_sha256(receipt, "display_name_sha256")?.to_string(),
                mime_type.to_string(),
                declared_size_bytes,
                map_u64(receipt, "last_modified_ms")?,
                map_u64(receipt, "document_flags")?,
                String::new(),
            )
        }
        "android_authority_secure_https_url_entry" => {
            exact_map_string(receipt, "source_kind", "browser")?;
            exact_map_string(receipt, "uri_scheme", "https")?;
            exact_map_bool(receipt, "user_entered_in_authority_ui", true)?;
            exact_map_bool(receipt, "explicit_user_confirmation", true)?;
            exact_map_string(receipt, "url_sha256", &content_sha256)?;
            exact_map_u64(receipt, "url_bytes", u64::try_from(content_bytes)?)?;
            let expected_source_id = format!("authority-url:{content_sha256}");
            if source_id != expected_source_id || content_bytes > MAX_HTTPS_URL_BYTES {
                bail!("context_capture_browser_source_binding_denied");
            }
            (
                "browser".to_string(),
                String::new(),
                0,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                -1,
                0,
                0,
                map_lower_sha256(receipt, "url_host_sha256")?.to_string(),
            )
        }
        _ => unreachable!(),
    };
    let captured_at_ms = map_u64(receipt, "captured_at_ms")?;
    let expires_at_ms = map_u64(receipt, "expires_at_ms")?;
    let ttl_ms = map_u64(receipt, "ttl_ms")?;
    if ttl_ms == 0
        || ttl_ms > CONTEXT_CAPTURE_TTL_MS
        || captured_at_ms > now.saturating_add(EGRESS_CLOCK_SKEW_MS)
        || expires_at_ms <= now
        || captured_at_ms.saturating_add(ttl_ms) != expires_at_ms
    {
        bail!("context_capture_ttl_binding_denied");
    }

    Ok(VerifiedContextCaptureReceipt {
        capture_id: capture_id.to_string(),
        receipt_id: receipt_id.to_string(),
        request_id: request_id.to_string(),
        requesting_uid: peer_uid,
        subject_user_id: peer_uid / 100_000,
        boot_id_sha256: map_lower_sha256(receipt, "boot_id_sha256")?.to_string(),
        capture_method: capture_method.to_string(),
        source_kind,
        source_id: source_id.to_string(),
        privacy_class: "local_private".to_string(),
        provider_package,
        provider_uid,
        provider_authority_sha256,
        document_id_sha256,
        display_name_sha256,
        mime_type,
        declared_size_bytes,
        last_modified_ms,
        document_flags,
        url_host_sha256,
        content_sha256,
        content_bytes,
        captured_at_ms,
        expires_at_ms,
        encoded_receipt: encoded_receipt.to_string(),
    })
}

fn issue_agent_data_grant(
    service: &AgentService,
    context_memory: &ContextMemoryService,
    owner: &Subject,
    payload: Value,
    resource_kind: &str,
) -> Result<Value> {
    ensure_android_user_zero(owner.uid)?;
    let resource_field = match resource_kind {
        "context" => "context_id",
        "memory" => "memory_id",
        _ => bail!("unsupported_agent_data_delegation_kind"),
    };
    exact_json_object_fields(
        &payload,
        &[resource_field, "agent_id", "task_id", "ttl_ms"],
        "agent_data_delegation_request",
    )?;
    let agent_id = required_string(&payload, "agent_id", 128)?;
    let task_id = required_string(&payload, "task_id", 128)?;
    // This UI method is an OS-held metadata-only policy.  A client cannot
    // expand it into raw access or egress with self-asserted booleans.  Raw
    // planning data follows the separately signed context/egress ceremonies.
    let raw_allowed = false;
    let egress_scope = "none";
    let egress_endpoint = "none";
    let ttl_ms = payload
        .get("ttl_ms")
        .and_then(Value::as_u64)
        .context("agent_data_delegation_ttl_required")?;
    let subject_user_id = owner.uid / 100_000;
    let registration = service
        .get_agent_local(&agent_id)
        .map_err(anyhow::Error::msg)?
        .context("target agent is not OS-provisioned")?;
    if !registration.enabled
        || registration.health != AgentHealth::Ready
        || registration.api_version != AGENT_API_VERSION
    {
        bail!("target agent is not enabled and ready");
    }
    let task = service
        .get_task_local(&task_id)
        .map_err(anyhow::Error::msg)?
        .context("delegation task does not exist")?;
    if !matches!(
        task.status,
        TaskStatus::Created | TaskStatus::Running | TaskStatus::WaitingForApproval
    ) {
        bail!("delegation task is no longer active");
    }
    if task.metadata.get("agent_id").and_then(Value::as_str) != Some(agent_id.as_str())
        || task.metadata.get("agent_peer_uid").and_then(Value::as_u64)
            != Some(registration.peer_uid as u64)
        || task.metadata.get("agent_peer_gid").and_then(Value::as_u64)
            != Some(registration.peer_gid as u64)
        || task
            .metadata
            .get("agent_peer_selinux_domain")
            .and_then(Value::as_str)
            != Some(registration.selinux_domain.as_str())
        || task
            .metadata
            .get("agent_peer_executable_sha256")
            .and_then(Value::as_str)
            != Some(registration.identity_key_sha256.as_str())
        || task.metadata.get("subject_user_id").and_then(Value::as_u64)
            != Some(subject_user_id as u64)
    {
        bail!("delegation task agent_or_user_binding_mismatch");
    }
    let target = AgentGrantTarget {
        agent_id,
        peer_uid: registration.peer_uid,
        peer_gid: registration.peer_gid,
        selinux_domain: registration.selinux_domain,
        executable_sha256: registration.identity_key_sha256,
        task_id,
        subject_user_id,
    };
    match resource_kind {
        "context" => {
            let context_id = required_string(&payload, "context_id", 96)?;
            context_memory.issue_context_grant(
                owner,
                target,
                &context_id,
                raw_allowed,
                egress_scope,
                egress_endpoint,
                ttl_ms,
            )
        }
        "memory" => {
            let memory_id = required_string(&payload, "memory_id", 96)?;
            context_memory.issue_memory_grant(
                owner,
                target,
                &memory_id,
                raw_allowed,
                egress_scope,
                egress_endpoint,
                ttl_ms,
            )
        }
        _ => unreachable!(),
    }
}

fn provision_codex(subject: &Subject, payload: &Value) -> Result<Value> {
    ensure_android_user_zero(subject.uid)?;
    exact_json_object_fields(payload, &["auth_json"], "codex_credential_request")?;
    let auth_json = Zeroizing::new(required_string(payload, "auth_json", MAX_CODEX_AUTH_BYTES)?);
    let parsed = SecretJson(
        serde_json::from_str(auth_json.as_str()).context("invalid Codex credential JSON")?,
    );
    let auth_mode = parsed
        .0
        .get("auth_mode")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .context("Codex credential is missing auth_mode")?
        .to_string();
    if parsed.0.get("tokens").and_then(Value::as_object).is_none() {
        bail!("Codex credential is missing tokens");
    }
    let canonical = Zeroizing::new(serde_json::to_vec(&parsed.0)?);
    if canonical.is_empty() || canonical.len() > MAX_CODEX_AUTH_BYTES {
        bail!("Codex credential is outside the bounded size contract");
    }
    let home = std::env::var_os("TRILLIONNIUM_CODEX_CREDENTIAL_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/trillionnium/agents/codex/home"));
    install_codex_credential(&home, canonical.as_slice(), codex_uid(), codex_gid())?;
    Ok(json!({
        "credential_sha256": sha256_bytes(canonical.as_slice()),
        "auth_mode": auth_mode,
        "credential_bytes": canonical.len(),
        "isolated_uid": codex_uid(),
        "persisted_mode": "0600",
        "tokens_returned": false,
    }))
}

struct SecretJson(Value);

impl Drop for SecretJson {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::String(text) => text.zeroize(),
                Value::Array(items) => items.iter_mut().for_each(wipe),
                Value::Object(items) => items.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

fn install_codex_credential(
    home: &Path,
    canonical: &[u8],
    isolated_uid: u32,
    isolated_gid: u32,
) -> Result<()> {
    match fs::symlink_metadata(home) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("isolated Codex home is not a real directory")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(home).with_context(|| {
                format!("failed to create isolated Codex home {}", home.display())
            })?;
        }
        Err(error) => return Err(error.into()),
    }
    make_credential_parents_traversable(home, Path::new(DEFAULT_AGENT_PRIVATE_ROOT))?;

    // The supervised Codex child owns a 0700 home. Before an atomic credential
    // replacement, hand only that directory back to the daemon's effective
    // identity. This avoids granting the daemon process broad DAC override or
    // DAC read/search capabilities. The isolated owner is restored on every
    // success and failure path.
    let daemon_uid = unsafe { libc::geteuid() };
    let daemon_gid = unsafe { libc::getegid() };
    chown(home, Some(daemon_uid), Some(daemon_gid))
        .with_context(|| format!("failed to acquire isolated Codex home {}", home.display()))?;
    let restore_owner = || chown(home, Some(isolated_uid), Some(isolated_gid));

    let destination = home.join("auth.json");
    let temporary = home.join(format!(
        ".auth.json.tmp-{}-{}",
        std::process::id(),
        now_unix_ms()
    ));
    let install_result = (|| -> Result<()> {
        fs::set_permissions(home, fs::Permissions::from_mode(0o700))?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        output.write_all(canonical)?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        chown(&temporary, Some(isolated_uid), Some(isolated_gid))?;
        fs::rename(&temporary, &destination)?;
        Ok(())
    })();
    if install_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    let restore_result = restore_owner();
    install_result?;
    restore_result.with_context(|| {
        format!(
            "failed to restore isolated Codex home owner {}",
            home.display()
        )
    })?;
    Ok(())
}

fn make_credential_parents_traversable(home: &Path, private_root: &Path) -> Result<()> {
    let parent = match home.parent() {
        Some(parent) if parent.starts_with(private_root) => parent,
        _ => return Ok(()),
    };
    let relative = parent.strip_prefix(private_root)?;
    let mut path = private_root.to_path_buf();
    for component in std::iter::once(None).chain(relative.components().map(Some)) {
        if let Some(component) = component {
            path.push(component.as_os_str());
        }
        let metadata = fs::symlink_metadata(&path).with_context(|| {
            format!("missing isolated Codex parent directory {}", path.display())
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "isolated Codex parent is not a real directory: {}",
                path.display()
            );
        }
        // The model UID knows the exact credential path. Permit traversal but
        // not directory listing; the final home remains UID-owned mode 0700.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o711)).with_context(|| {
            format!("failed to secure isolated Codex parent {}", path.display())
        })?;
    }
    Ok(())
}

#[cfg(test)]
fn allowed_actions_for_context(context_kind: &str) -> Result<Vec<String>> {
    match context_kind {
        "file" => Ok(vec![NOTIFICATION_ACTION.to_string()]),
        "browser" => Ok(vec![
            BROWSER_ACTION.to_string(),
            NOTIFICATION_ACTION.to_string(),
        ]),
        // Saved Memory may inform planning, but it never carries an exact URL
        // provenance contract. Keep its executable surface local and
        // notification-only for both providers.
        "memory" => Ok(vec![NOTIFICATION_ACTION.to_string()]),
        _ => bail!("unsupported_context_kind"),
    }
}

fn select_memory_context_for_request(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    request_id: &str,
    payload: Value,
) -> Result<Value> {
    ensure_android_user_zero(subject.uid)?;
    exact_json_object_fields(
        &payload,
        &[
            "memory_id",
            "expected_payload_sha256",
            "expected_updated_at_ms",
        ],
        "memory_context_selection_payload",
    )?;
    let memory_id = required_string(&payload, "memory_id", 96)?;
    let expected_payload_sha256 = map_lower_sha256(
        payload
            .as_object()
            .context("memory_context_selection_payload_not_object")?,
        "expected_payload_sha256",
    )?;
    let expected_updated_at_ms = payload
        .get("expected_updated_at_ms")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .context("memory_context_selection_updated_at_denied")?;
    context_memory.materialize_memory_planning_context_for_request(
        subject,
        request_id,
        &memory_id,
        expected_payload_sha256,
        expected_updated_at_ms,
    )
}

#[cfg(test)]
fn select_memory_context(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    payload: Value,
) -> Result<Value> {
    select_memory_context_for_request(
        context_memory,
        subject,
        "test-memory-selection-request",
        payload,
    )
}

fn query_only_recover_memory_context(
    context_memory: &ContextMemoryService,
    subject: &Subject,
    recovery_request_id: &str,
    payload: &Value,
) -> Result<Value> {
    ensure_android_user_zero(subject.uid)?;
    exact_json_object_fields(
        payload,
        &[
            "original_request_id",
            "memory_id",
            "expected_payload_sha256",
            "expected_updated_at_ms",
        ],
        "memory_context_query_only_recovery_payload",
    )?;
    let original_request_id = required_string(payload, "original_request_id", 128)?;
    if original_request_id == recovery_request_id {
        bail!("memory_context_recovery_request_id_must_be_distinct");
    }
    let memory_id = required_string(payload, "memory_id", 96)?;
    let expected_payload_sha256 = map_lower_sha256(
        payload
            .as_object()
            .context("memory_context_recovery_payload_not_object")?,
        "expected_payload_sha256",
    )?;
    let expected_updated_at_ms = payload
        .get("expected_updated_at_ms")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .context("memory_context_recovery_updated_at_denied")?;
    let mut metadata = context_memory
        .recover_memory_context_exact(
            subject,
            &original_request_id,
            &memory_id,
            expected_payload_sha256,
            expected_updated_at_ms,
        )?
        .context("memory_context_query_only_recovery_not_available")?;
    metadata
        .as_object_mut()
        .context("memory_context_recovery_result_not_object")?
        .insert(
            "recovery_status".to_string(),
            Value::String("context_available".to_string()),
        );
    metadata
        .as_object_mut()
        .context("memory_context_recovery_result_not_object")?
        .insert(
            "original_request_id".to_string(),
            Value::String(original_request_id),
        );
    Ok(metadata)
}

#[derive(Clone, Copy)]
#[cfg(test)]
struct BoundedActionContract {
    action: &'static str,
    plan_network_scope: &'static str,
    argument_network_scope: &'static str,
    receipt_network_scope: &'static str,
    undo_contract: &'static str,
    undo_supported: bool,
}

#[cfg(test)]
fn bounded_action_contract(tool_name: &str) -> Result<BoundedActionContract> {
    match tool_name {
        BROWSER_TOOL => Ok(BoundedActionContract {
            action: BROWSER_ACTION,
            plan_network_scope: "per_request",
            argument_network_scope: "exact_https_url",
            receipt_network_scope: "exact_https_url_once",
            undo_contract: BROWSER_UNDO_CONTRACT,
            undo_supported: false,
        }),
        NOTIFICATION_TOOL => Ok(BoundedActionContract {
            action: NOTIFICATION_ACTION,
            plan_network_scope: "none",
            argument_network_scope: "none",
            receipt_network_scope: "none",
            undo_contract: NOTIFICATION_UNDO_CONTRACT,
            undo_supported: true,
        }),
        _ => bail!("unsupported_bounded_android_action"),
    }
}

#[cfg(test)]
fn validate_notification_action_payload(payload: &Value) -> Result<()> {
    let object = payload
        .as_object()
        .context("bounded_notification_payload_not_object")?;
    if object.len() != 2 || !object.contains_key("title") || !object.contains_key("body") {
        bail!("bounded_notification_payload_missing_or_unknown_fields");
    }
    for (field, maximum) in [
        ("title", MAX_NOTIFICATION_TITLE_BYTES),
        ("body", MAX_NOTIFICATION_BODY_BYTES),
    ] {
        let text = object
            .get(field)
            .and_then(Value::as_str)
            .with_context(|| format!("bounded_notification_{field}_not_string"))?;
        if text.trim().is_empty()
            || text.is_empty()
            || text.len() > maximum
            || text.chars().any(char::is_control)
        {
            bail!("bounded_notification_{field}_outside_utf8_byte_contract");
        }
    }
    Ok(())
}

#[cfg(test)]
fn validate_action_payload_binding(
    tool_name: &str,
    action_payload: &Value,
    execution_payload_sha256: &str,
) -> Result<BoundedActionContract> {
    if !valid_lower_sha256(execution_payload_sha256) {
        bail!("action_payload_digest_invalid");
    }
    let contract = bounded_action_contract(tool_name)?;
    match tool_name {
        BROWSER_TOOL => {
            let object = action_payload
                .as_object()
                .context("bounded_browser_action_payload_not_object")?;
            if object.len() != 1 || !object.contains_key("url") {
                bail!("bounded_browser_action_payload_missing_or_unknown_fields");
            }
            let url = object
                .get("url")
                .and_then(Value::as_str)
                .context("bounded_browser_action_url_not_string")?;
            if canonical_https_execution_url(url)? != url {
                bail!("bounded_browser_action_url_not_canonical");
            }
        }
        NOTIFICATION_TOOL => validate_notification_action_payload(action_payload)?,
        _ => unreachable!("bounded_action_contract rejected unsupported tool"),
    }
    if sha256_json(action_payload) != execution_payload_sha256 {
        bail!("action_payload_digest_mismatch");
    }
    Ok(contract)
}

#[cfg(test)]
fn frozen_tool_payload_sha256(tool_name: &str, payload: &Value) -> Result<String> {
    match tool_name {
        BROWSER_TOOL => {
            let payload = exact_json_object_fields(
                payload,
                &[
                    "execution_payload_ref",
                    "execution_payload_sha256",
                    "execution_payload_shape",
                ],
                "frozen_browser_execution_payload",
            )?;
            Ok(map_lower_sha256(payload, "execution_payload_sha256")?.to_string())
        }
        NOTIFICATION_TOOL => {
            validate_notification_action_payload(payload)?;
            Ok(sha256_json(payload))
        }
        _ => bail!("receipt_tool_run_action_not_undoable"),
    }
}

#[cfg(test)]
fn authority_undo_request_id(receipt_id: &str) -> Result<String> {
    if !valid_lower_sha256(receipt_id) {
        bail!("invalid_undo_source_receipt_id");
    }
    Ok(format!("undo-{receipt_id}"))
}

fn prompt_contract_for_provider(provider_id: &str) -> Result<(&'static str, u64)> {
    if provider_id != CODEX_PROVIDER_ID {
        bail!("unsupported_direct_provider");
    }
    Ok((
        trillionnium_tool_runtime::supervised_codex::DIRECT_EXECUTION_PROMPT_CONTRACT,
        trillionnium_tool_runtime::supervised_codex::DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION,
    ))
}

fn validate_pending_egress_material_binding(binding: &PendingEgressBinding) -> Result<()> {
    let challenge = exact_json_object_fields(
        &binding.consent_challenge,
        EGRESS_CHALLENGE_FIELDS,
        "stored_egress_consent_challenge",
    )?;
    exact_map_string(challenge, "challenge_schema", EGRESS_CHALLENGE_SCHEMA)?;
    exact_map_string(challenge, "provider_id", &binding.provider_id)?;
    exact_map_string(challenge, "workflow_id", &binding.workflow_id)?;
    if binding.policy_epoch != EGRESS_POLICY_EPOCH
        || binding.provider_abi_epoch != PROVIDER_ABI_EPOCH
        || !valid_lower_sha256(&binding.prepare_request_id_sha256)
        || !valid_lower_sha256(&binding.prepare_request_payload_sha256)
        || sha256_bytes(map_string(challenge, "prepare_request_id")?.as_bytes())
            != binding.prepare_request_id_sha256
    {
        bail!("egress_prepare_policy_abi_or_request_binding_denied");
    }
    exact_map_u64(challenge, "ui_uid", u64::from(binding.peer_uid))?;
    exact_map_string(challenge, "ui_selinux_domain", &binding.peer_domain)?;
    exact_map_u64(
        challenge,
        "subject_user_id",
        u64::from(binding.peer_uid / ANDROID_UID_PER_USER_RANGE),
    )?;
    exact_map_string(challenge, "boot_id_sha256", &binding.boot_id_sha256)?;
    exact_map_string(challenge, "agent_id", &binding.agent_id)?;
    exact_map_u64(
        challenge,
        "agent_peer_uid",
        u64::from(binding.agent_peer_uid),
    )?;
    exact_map_u64(
        challenge,
        "agent_peer_gid",
        u64::from(binding.agent_peer_gid),
    )?;
    exact_map_string(
        challenge,
        "agent_selinux_domain",
        &binding.agent_selinux_domain,
    )?;
    exact_map_string(
        challenge,
        "agent_executable_sha256",
        &binding.agent_executable_sha256,
    )?;
    if !valid_lower_sha256(&binding.agent_manifest_sha256) {
        bail!("egress_agent_manifest_digest_denied");
    }
    exact_map_string(challenge, "context_id", &binding.context_id)?;
    exact_map_u64(
        challenge,
        "context_captured_at_ms",
        binding.context_captured_at_ms,
    )?;
    exact_map_u64(
        challenge,
        "context_expires_at_ms",
        binding.context_expires_at_ms,
    )?;
    if binding.context_expires_at_ms <= binding.context_captured_at_ms
        || binding.issued_at_ms < binding.context_captured_at_ms
        || binding.expires_at_ms > binding.context_expires_at_ms
    {
        bail!("egress_context_freshness_binding_denied");
    }
    exact_map_string(challenge, "context_sha256", &binding.content_sha256)?;
    exact_map_string(challenge, "source_kind", &binding.context_kind)?;
    exact_map_string(challenge, "source_id_sha256", &binding.source_id_sha256)?;
    exact_map_string(challenge, "privacy_class", &binding.privacy_class)?;
    exact_map_u64(challenge, "content_bytes", binding.content_bytes)?;
    exact_map_u64(challenge, "upload_byte_limit", binding.upload_byte_limit)?;
    exact_map_u64(
        challenge,
        "download_byte_limit",
        binding.download_byte_limit,
    )?;
    exact_map_u64(challenge, "issued_at_ms", binding.issued_at_ms)?;
    exact_map_u64(challenge, "expires_at_ms", binding.expires_at_ms)?;
    if binding.actual_content_sha256 != binding.content_sha256 {
        bail!("egress_grant_content_changed_before_consent");
    }

    let intent = map_string(challenge, "intent")?;
    if intent.trim().is_empty()
        || intent.len() > 8_192
        || intent.len() as u64 != binding.intent_bytes
        || sha256_bytes(intent.as_bytes()) != binding.intent_sha256
    {
        bail!("egress_consent_intent_material_mismatch");
    }
    exact_map_u64(challenge, "intent_bytes", binding.intent_bytes)?;
    exact_map_string(challenge, "intent_sha256", &binding.intent_sha256)?;

    let allowed_actions_value = challenge
        .get("allowed_actions")
        .and_then(Value::as_array)
        .context("allowed_actions_not_array")?;
    let allowed_actions = allowed_actions_value
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .context("allowed_actions_entry_not_string")
        })
        .collect::<Result<Vec<_>>>()?;
    let expected_actions: Vec<String> = Vec::new();
    let allowed_actions_value = Value::Array(allowed_actions_value.clone());
    let actual_allowed_actions_sha256 = sha256_json(&allowed_actions_value);
    if allowed_actions != binding.allowed_actions
        || allowed_actions != expected_actions
        || actual_allowed_actions_sha256 != binding.allowed_actions_sha256
    {
        bail!("egress_consent_allowed_actions_material_mismatch");
    }
    exact_map_string(
        challenge,
        "allowed_actions_sha256",
        &binding.allowed_actions_sha256,
    )?;

    let (expected_prompt_contract, expected_prompt_contract_version) =
        prompt_contract_for_provider(&binding.provider_id)?;
    if binding.prompt_contract != expected_prompt_contract
        || binding.prompt_contract_version != expected_prompt_contract_version
    {
        bail!("egress_consent_prompt_contract_material_mismatch");
    }
    exact_map_string(challenge, "prompt_contract", &binding.prompt_contract)?;
    exact_map_u64(
        challenge,
        "prompt_contract_version",
        binding.prompt_contract_version,
    )?;
    let grant_id = map_string(challenge, "egress_grant_id")?;
    let expected_journal_binding = egress_journal_metadata(grant_id, binding).binding_sha256()?;
    if binding.journal_binding_sha256 != expected_journal_binding {
        bail!("egress_grant_durable_journal_binding_mismatch");
    }
    Ok(())
}

fn egress_journal_metadata(
    grant_id: &str,
    binding: &PendingEgressBinding,
) -> EgressJournalMetadata {
    EgressJournalMetadata {
        grant_id: grant_id.to_string(),
        provider_id: binding.provider_id.clone(),
        workflow_id_sha256: sha256_bytes(binding.workflow_id.as_bytes()),
        policy_epoch: binding.policy_epoch,
        provider_abi_epoch: binding.provider_abi_epoch,
        prepare_request_id_sha256: binding.prepare_request_id_sha256.clone(),
        prepare_request_payload_sha256: binding.prepare_request_payload_sha256.clone(),
        peer_uid: binding.peer_uid,
        peer_selinux_domain_sha256: sha256_bytes(binding.peer_domain.as_bytes()),
        subject_user_id: binding.peer_uid / 100_000,
        boot_id_sha256: binding.boot_id_sha256.clone(),
        agent_id: binding.agent_id.clone(),
        agent_peer_uid: binding.agent_peer_uid,
        agent_peer_gid: binding.agent_peer_gid,
        agent_selinux_domain_sha256: sha256_bytes(binding.agent_selinux_domain.as_bytes()),
        agent_executable_sha256: binding.agent_executable_sha256.clone(),
        agent_manifest_sha256: binding.agent_manifest_sha256.clone(),
        context_id_sha256: sha256_bytes(binding.context_id.as_bytes()),
        context_kind: binding.context_kind.clone(),
        context_captured_at_ms: binding.context_captured_at_ms,
        context_expires_at_ms: binding.context_expires_at_ms,
        context_sha256: binding.content_sha256.clone(),
        source_id_sha256: binding.source_id_sha256.clone(),
        privacy_class: binding.privacy_class.clone(),
        content_bytes: binding.content_bytes,
        intent_sha256: binding.intent_sha256.clone(),
        intent_bytes: binding.intent_bytes,
        allowed_actions_sha256: binding.allowed_actions_sha256.clone(),
        prompt_contract: binding.prompt_contract.clone(),
        prompt_contract_version: binding.prompt_contract_version,
        endpoint: CODEX_EGRESS_ENDPOINT.to_string(),
        upload_byte_limit: binding.upload_byte_limit,
        download_byte_limit: binding.download_byte_limit,
        consent_challenge_sha256: sha256_json(&binding.consent_challenge),
        issued_at_ms: binding.issued_at_ms,
        expires_at_ms: binding.expires_at_ms,
    }
}

fn egress_recovery_body(grant_id: &str, grant: &PendingEgressGrant) -> EgressRecoveryBody {
    EgressRecoveryBody {
        grant_id: grant_id.to_string(),
        provider_id: grant.provider_id.clone(),
        workflow_id: grant.workflow_id.clone(),
        prepare_request_id: grant.prepare_request_id.clone(),
        prepare_request_payload_sha256: grant.prepare_request_payload_sha256.clone(),
        policy_epoch: grant.policy_epoch,
        provider_abi_epoch: grant.provider_abi_epoch,
        peer_uid: grant.peer_uid,
        peer_domain: grant.peer_domain.clone(),
        subject_user_id: grant.peer_uid / ANDROID_UID_PER_USER_RANGE,
        boot_id_sha256: grant.boot_id_sha256.clone(),
        agent_id: grant.agent_id.clone(),
        agent_peer_uid: grant.agent_peer_uid,
        agent_peer_gid: grant.agent_peer_gid,
        agent_selinux_domain: grant.agent_selinux_domain.clone(),
        agent_executable_sha256: grant.agent_executable_sha256.clone(),
        agent_registration: grant.agent_registration.clone(),
        context_id: grant.context_id.clone(),
        context_kind: grant.context_kind.clone(),
        context_captured_at_ms: grant.context_captured_at_ms,
        context_expires_at_ms: grant.context_expires_at_ms,
        privacy_class: grant.privacy_class.clone(),
        source_id: grant.source_id.as_str().to_string(),
        content: grant.content.as_str().to_string(),
        intent: grant.intent.as_str().to_string(),
        content_sha256: grant.content_sha256.clone(),
        allowed_actions: grant.allowed_actions.clone(),
        allowed_actions_sha256: grant.allowed_actions_sha256.clone(),
        prompt_contract: grant.prompt_contract.clone(),
        prompt_contract_version: grant.prompt_contract_version,
        journal_binding_sha256: grant.journal_binding_sha256.clone(),
        issued_at_ms: grant.issued_at_ms,
        expires_at_ms: grant.expires_at_ms,
        upload_byte_limit: grant.upload_byte_limit,
        download_byte_limit: grant.download_byte_limit,
        consent_challenge: grant.consent_challenge.clone(),
    }
}

fn encode_egress_recovery_envelope(body: EgressRecoveryBody) -> Result<Zeroizing<Vec<u8>>> {
    let digest_input = EgressRecoveryDigestInput {
        schema: EGRESS_RECOVERY_SCHEMA,
        format_version: EGRESS_RECOVERY_FORMAT_VERSION,
        body: &body,
    };
    let payload_sha256 = sha256_bytes(&serde_json::to_vec(&digest_input)?);
    let envelope = EgressRecoveryEnvelope {
        schema: EGRESS_RECOVERY_SCHEMA.to_string(),
        format_version: EGRESS_RECOVERY_FORMAT_VERSION,
        body,
        payload_sha256,
    };
    Ok(Zeroizing::new(serde_json::to_vec(&envelope)?))
}

fn decode_egress_recovery_envelope(clear: &[u8]) -> Result<EgressRecoveryBody> {
    let envelope: EgressRecoveryEnvelope =
        serde_json::from_slice(clear).context("invalid_egress_recovery_envelope_json")?;
    if serde_json::to_vec(&envelope)? != clear
        || envelope.schema != EGRESS_RECOVERY_SCHEMA
        || envelope.format_version != EGRESS_RECOVERY_FORMAT_VERSION
    {
        bail!("egress_recovery_envelope_not_canonical_closed_world");
    }
    let expected = sha256_bytes(&serde_json::to_vec(&EgressRecoveryDigestInput {
        schema: EGRESS_RECOVERY_SCHEMA,
        format_version: EGRESS_RECOVERY_FORMAT_VERSION,
        body: &envelope.body,
    })?);
    if envelope.payload_sha256 != expected {
        bail!("egress_recovery_envelope_payload_digest_mismatch");
    }
    Ok(envelope.body)
}

fn egress_recovery_aad(
    metadata: &EgressJournalMetadata,
    journal_binding_sha256: &str,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&EgressRecoveryAad {
        schema: EGRESS_RECOVERY_AAD_SCHEMA,
        format_version: EGRESS_RECOVERY_FORMAT_VERSION,
        grant_id: &metadata.grant_id,
        journal_binding_sha256,
        metadata,
    })?)
}

fn pending_grant_from_recovery(
    body: EgressRecoveryBody,
    cas: EgressJournalCas,
    recovery_blob: EgressRecoveryBlobRef,
) -> PendingEgressGrant {
    PendingEgressGrant {
        provider_id: body.provider_id,
        workflow_id: body.workflow_id,
        prepare_request_id: body.prepare_request_id,
        prepare_request_payload_sha256: body.prepare_request_payload_sha256,
        policy_epoch: body.policy_epoch,
        provider_abi_epoch: body.provider_abi_epoch,
        peer_uid: body.peer_uid,
        peer_domain: body.peer_domain,
        agent_peer_uid: body.agent_peer_uid,
        agent_peer_gid: body.agent_peer_gid,
        agent_id: body.agent_id,
        agent_selinux_domain: body.agent_selinux_domain,
        agent_executable_sha256: body.agent_executable_sha256,
        agent_registration: body.agent_registration,
        boot_id_sha256: body.boot_id_sha256,
        context_id: body.context_id,
        context_kind: body.context_kind,
        context_captured_at_ms: body.context_captured_at_ms,
        context_expires_at_ms: body.context_expires_at_ms,
        privacy_class: body.privacy_class,
        source_id: Zeroizing::new(body.source_id),
        content: Zeroizing::new(body.content),
        intent: Zeroizing::new(body.intent),
        content_sha256: body.content_sha256,
        allowed_actions: body.allowed_actions,
        allowed_actions_sha256: body.allowed_actions_sha256,
        prompt_contract: body.prompt_contract,
        prompt_contract_version: body.prompt_contract_version,
        journal_binding_sha256: body.journal_binding_sha256,
        journal_cas: cas,
        recovery_blob,
        issued_at_ms: body.issued_at_ms,
        expires_at_ms: body.expires_at_ms,
        upload_byte_limit: body.upload_byte_limit,
        download_byte_limit: body.download_byte_limit,
        consent_challenge: body.consent_challenge,
    }
}

fn recover_prepared_egress_grants(
    state: &mut EgressGrantState,
    service: &AgentService,
    context_memory: &ContextMemoryService,
) -> Result<()> {
    let retained = state.journal.retained_recovery_files()?;
    context_memory.prune_egress_recovery_orphans(&retained)?;
    let current_boot = current_boot_id_sha256()?;
    let now = now_unix_ms();
    for (metadata, cas, recovery_blob) in state.journal.prepared_records()? {
        if metadata.expires_at_ms <= now {
            let expired = state.journal.mark_expired(
                &metadata.grant_id,
                &cas,
                now.max(metadata.expires_at_ms),
            )?;
            if expired.publication_durability_uncertain {
                bail!("egress_restart_expiry_commit_unknown_parent_fsync_uncertain");
            }
            if !state
                .journal
                .recovery_must_be_retained(&metadata.grant_id)?
            {
                let _ = context_memory.delete_egress_recovery_blob(&recovery_blob);
            }
            continue;
        }
        if metadata.boot_id_sha256 != current_boot || metadata.subject_user_id != 0 {
            let indeterminate =
                state
                    .journal
                    .mark_prepared_indeterminate(&metadata.grant_id, &cas, now)?;
            if indeterminate.publication_durability_uncertain {
                bail!("egress_restart_indeterminate_commit_unknown_parent_fsync_uncertain");
            }
            if !state
                .journal
                .recovery_must_be_retained(&metadata.grant_id)?
            {
                let _ = context_memory.delete_egress_recovery_blob(&recovery_blob);
            }
            continue;
        }
        let recovered = (|| -> Result<(String, PendingEgressGrant)> {
            // This call re-opens and measures the configured executable before
            // any encrypted grant material is made live. Journal assertions
            // alone are never accepted as a current Agent identity proof.
            let registration = register_builtin_provider(service, &metadata.provider_id)?;
            let aad = egress_recovery_aad(&metadata, &cas.binding_sha256)?;
            let clear = context_memory.read_egress_recovery_blob(&recovery_blob, &aad)?;
            let body = decode_egress_recovery_envelope(clear.as_slice())?;
            if body.grant_id != metadata.grant_id
                || body.subject_user_id != metadata.subject_user_id
                || body.boot_id_sha256 != current_boot
                || body.agent_registration != registration
                || body.agent_id != registration.agent_id
                || body.agent_peer_uid != registration.peer_uid
                || body.agent_peer_gid != registration.peer_gid
                || body.agent_selinux_domain != registration.selinux_domain
                || body.agent_executable_sha256 != registration.identity_key_sha256
                || sha256_json(&serde_json::to_value(&registration)?)
                    != metadata.agent_manifest_sha256
            {
                bail!("egress_recovery_current_agent_manifest_binding_mismatch");
            }
            let grant_id = body.grant_id.clone();
            let grant = pending_grant_from_recovery(body, cas.clone(), recovery_blob.clone());
            let binding = grant.binding();
            validate_pending_egress_material_binding(&binding)?;
            if egress_journal_metadata(&grant_id, &binding) != metadata
                || binding.journal_binding_sha256 != cas.binding_sha256
                || state.pending.contains_key(&grant_id)
            {
                bail!("egress_recovery_journal_material_binding_mismatch");
            }
            Ok((grant_id, grant))
        })();
        match recovered {
            Ok((grant_id, grant)) => {
                state.pending.insert(grant_id, grant);
            }
            Err(_) => {
                // A recovery failure is durable and explicit. It never leaves
                // a PREPARED record that a later restart might accidentally
                // revive after configuration or ciphertext changes.
                let indeterminate =
                    state
                        .journal
                        .mark_prepared_indeterminate(&metadata.grant_id, &cas, now)?;
                if indeterminate.publication_durability_uncertain {
                    bail!("egress_recovery_failure_commit_unknown_parent_fsync_uncertain");
                }
                if !state
                    .journal
                    .recovery_must_be_retained(&metadata.grant_id)?
                {
                    let _ = context_memory.delete_egress_recovery_blob(&recovery_blob);
                }
            }
        }
    }
    let retained = state.journal.retained_recovery_files()?;
    context_memory.prune_egress_recovery_orphans(&retained)?;
    Ok(())
}

fn expire_pending_egress_grants(
    state: &mut EgressGrantState,
    context_memory: &ContextMemoryService,
    now: u64,
) -> Result<()> {
    let expired = state
        .pending
        .iter()
        .filter(|(_, grant)| grant.expires_at_ms <= now)
        .map(|(grant_id, _)| grant_id.clone())
        .collect::<Vec<_>>();
    for grant_id in expired {
        let binding = state
            .pending
            .get(&grant_id)
            .context("expired_egress_grant_disappeared")?
            .binding();
        let (cas, recovery_blob) = {
            let grant = state
                .pending
                .get(&grant_id)
                .context("expired_egress_grant_disappeared")?;
            (grant.journal_cas.clone(), grant.recovery_blob.clone())
        };
        validate_pending_egress_material_binding(&binding)?;
        let expired_cas =
            state
                .journal
                .mark_expired(&grant_id, &cas, now.max(binding.expires_at_ms))?;
        state.pending.remove(&grant_id);
        if expired_cas.publication_durability_uncertain {
            bail!("egress_expiry_commit_unknown_parent_fsync_uncertain");
        }
        if !state.journal.recovery_must_be_retained(&grant_id)? {
            let _ = context_memory.delete_egress_recovery_blob(&recovery_blob);
        }
    }
    Ok(())
}

fn prepare_egress(
    egress_grants: &EgressGrantStore,
    context_memory: &ContextMemoryService,
    subject: &Subject,
    registration: &AgentRegistration,
    request_id: &str,
    payload: Value,
) -> Result<Value> {
    ensure_android_user_zero(subject.uid)?;
    exact_json_object_fields(
        &payload,
        &["context_id", "intent", "workflow_id", "provider"],
        "egress_prepare_payload",
    )?;
    let prepare_request_payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload)?);
    let provider_id = required_string(&payload, "provider", 64)?;
    let descriptor = agent_principal_registry::from_provider_id(&provider_id)
        .ok_or_else(|| anyhow::anyhow!("unsupported_direct_provider"))?;
    if !crate::builtin_provider_identity::matches_stable_registration(descriptor, registration) {
        bail!("egress_agent_manifest_binding_denied");
    }
    let context_id = required_string(&payload, "context_id", 96)?;
    let workflow_id = required_string(&payload, "workflow_id", 128)?;
    let expected_prepare_request_id = format!("{workflow_id}-egress-prepare");
    let plan_request_id = format!("{workflow_id}-plan");
    if request_id != expected_prepare_request_id
        || expected_prepare_request_id.len() > 128
        || plan_request_id.len() > 128
    {
        bail!("egress_request_workflow_binding_mismatch");
    }
    let context = context_memory.resolve_context(subject, &context_id)?;
    let context_kind = context.source_kind.clone();
    match context_kind.as_str() {
        "file" | "browser" | "memory" => {}
        _ => bail!("unsupported_context_kind"),
    }
    let source_id = context.source_id;
    let content = context.content;
    let intent = required_string(&payload, "intent", 8_192)?;
    if intent.trim().is_empty() {
        bail!("egress_intent_blank_denied");
    }
    let intent_bytes = intent.len() as u64;
    let intent_sha256 = sha256_bytes(intent.as_bytes());
    let source_id_sha256 = sha256_bytes(source_id.as_bytes());
    // Direct-v1 tools execute inside the measured Agent turn. Generic plan
    // actions are structurally absent from the production egress contract.
    let allowed_actions: Vec<String> = Vec::new();
    let allowed_actions_value = serde_json::to_value(&allowed_actions)?;
    let allowed_actions_sha256 = sha256_json(&allowed_actions_value);
    let (prompt_contract, prompt_contract_version) = prompt_contract_for_provider(&provider_id)?;
    let now = now_unix_ms();
    let expires_at_ms = now
        .saturating_add(EGRESS_GRANT_TTL_MS)
        .min(context.expires_at_ms);
    let ttl_ms = expires_at_ms.saturating_sub(now);
    if ttl_ms == 0 {
        bail!("egress_context_expired_before_consent");
    }
    let content_sha256 = context.content_sha256;
    let grant_id = format!("egress-{}", random_hex_32()?);
    let challenge_id = format!("egress-challenge-{}", random_hex_32()?);
    let consent_nonce = random_hex_32()?;
    let content_bytes = content.len() as u64;
    let upload_byte_limit = content_bytes
        .saturating_mul(2)
        .saturating_add(64 * 1024)
        .clamp(256 * 1024, EGRESS_UPLOAD_MAX_BYTES);
    let download_byte_limit = EGRESS_DOWNLOAD_MAX_BYTES;
    let boot_id_sha256 = current_boot_id_sha256()?;
    let consent_challenge = json!({
        "challenge_schema": EGRESS_CHALLENGE_SCHEMA,
        "challenge_id": challenge_id,
        "egress_grant_id": grant_id,
        "ui_uid": subject.uid,
        "ui_selinux_domain": subject.selinux_domain,
        "subject_user_id": subject.uid / 100_000,
        "boot_id_sha256": boot_id_sha256,
        "context_id": context_id,
        "context_captured_at_ms": context.captured_at_ms,
        "context_expires_at_ms": context.expires_at_ms,
        "context_sha256": content_sha256,
        "source_kind": context_kind,
        "source_id_sha256": source_id_sha256,
        "privacy_class": context.privacy_class,
        "content_bytes": content_bytes,
        "intent": intent,
        "intent_bytes": intent_bytes,
        "intent_sha256": intent_sha256,
        "allowed_actions": allowed_actions_value,
        "allowed_actions_sha256": allowed_actions_sha256,
        "prompt_contract": prompt_contract,
        "prompt_contract_version": prompt_contract_version,
        "provider_id": provider_id,
        "agent_id": registration.agent_id,
        "agent_peer_uid": registration.peer_uid,
        "agent_peer_gid": registration.peer_gid,
        "agent_selinux_domain": registration.selinux_domain,
        "agent_executable_sha256": registration.identity_key_sha256,
        "endpoint": CODEX_EGRESS_ENDPOINT,
        "upload_byte_limit": upload_byte_limit,
        "download_byte_limit": download_byte_limit,
        "issued_at_ms": now,
        "expires_at_ms": expires_at_ms,
        "ttl_ms": ttl_ms,
        "workflow_id": workflow_id,
        "prepare_request_id": request_id,
        "plan_request_id": plan_request_id,
        "nonce": consent_nonce,
    });
    exact_json_object_fields(
        &consent_challenge,
        EGRESS_CHALLENGE_FIELDS,
        "egress_consent_challenge",
    )?;
    let mut grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    expire_pending_egress_grants(&mut grants, context_memory, now)?;
    if grants.pending.len() >= MAX_PENDING_EGRESS_GRANTS {
        bail!("egress_grant_store_full");
    }
    let mut grant = PendingEgressGrant {
        provider_id: provider_id.clone(),
        workflow_id,
        prepare_request_id: request_id.to_string(),
        prepare_request_payload_sha256,
        policy_epoch: EGRESS_POLICY_EPOCH,
        provider_abi_epoch: PROVIDER_ABI_EPOCH,
        peer_uid: subject.uid,
        peer_domain: subject.selinux_domain.clone(),
        agent_peer_uid: registration.peer_uid,
        agent_peer_gid: registration.peer_gid,
        agent_id: registration.agent_id.clone(),
        agent_selinux_domain: registration.selinux_domain.clone(),
        agent_executable_sha256: registration.identity_key_sha256.clone(),
        agent_registration: registration.clone(),
        boot_id_sha256,
        context_id: context_id.clone(),
        context_kind: context_kind.clone(),
        context_captured_at_ms: context.captured_at_ms,
        context_expires_at_ms: context.expires_at_ms,
        privacy_class: context.privacy_class.clone(),
        source_id: Zeroizing::new(source_id),
        content: Zeroizing::new(content),
        intent: Zeroizing::new(intent),
        content_sha256: content_sha256.clone(),
        allowed_actions: allowed_actions.clone(),
        allowed_actions_sha256: allowed_actions_sha256.clone(),
        prompt_contract: prompt_contract.to_string(),
        prompt_contract_version,
        journal_binding_sha256: String::new(),
        journal_cas: EgressJournalCas {
            binding_sha256: "0".repeat(64),
            state: EgressLifecycleState::Prepared,
            record_sha256: "0".repeat(64),
            publication_durability_uncertain: false,
        },
        recovery_blob: EgressRecoveryBlobRef {
            file_name: format!("egress-recovery-{}.enc", "0".repeat(64)),
            ciphertext_sha256: "0".repeat(64),
            publication_durability_uncertain: false,
        },
        issued_at_ms: now,
        expires_at_ms,
        upload_byte_limit,
        download_byte_limit,
        consent_challenge: consent_challenge.clone(),
    };
    let metadata = egress_journal_metadata(&grant_id, &grant.binding());
    let expected_journal_binding = metadata.binding_sha256()?;
    grant.journal_binding_sha256 = expected_journal_binding.clone();
    validate_pending_egress_material_binding(&grant.binding())?;
    let mut clear = encode_egress_recovery_envelope(egress_recovery_body(&grant_id, &grant))?;
    let aad = egress_recovery_aad(&metadata, &expected_journal_binding)?;
    let recovery_blob =
        context_memory.publish_egress_recovery_blob(&grant_id, &aad, clear.as_slice())?;
    clear.zeroize();
    if recovery_blob.publication_durability_uncertain {
        bail!("egress_recovery_publish_commit_unknown_parent_fsync_uncertain");
    }
    let persisted = match grants.journal.record_prepared(metadata, &recovery_blob) {
        Ok(persisted) => persisted,
        Err(error) => {
            if !grants.journal.publication_durability_uncertain() {
                context_memory
                    .delete_egress_recovery_blob(&recovery_blob)
                    .context("egress_recovery_orphan_cleanup_after_journal_failure")?;
            }
            return Err(error);
        }
    };
    if persisted.binding_sha256 != expected_journal_binding
        || persisted.state != EgressLifecycleState::Prepared
    {
        bail!("egress_durable_journal_binding_changed_during_prepare");
    }
    grant.journal_cas = persisted;
    grant.recovery_blob = recovery_blob;
    grants.pending.insert(grant_id.clone(), grant);
    if grants
        .pending
        .get(&grant_id)
        .is_some_and(|grant| grant.journal_cas.publication_durability_uncertain)
    {
        bail!("egress_prepare_commit_unknown_published_durability_uncertain");
    }
    prepared_egress_response(
        &grant_id,
        grants
            .pending
            .get(&grant_id)
            .context("prepared_egress_grant_missing_before_response")?,
    )
}

fn prepared_egress_response(grant_id: &str, grant: &PendingEgressGrant) -> Result<Value> {
    let binding = grant.binding();
    validate_pending_egress_material_binding(&binding)?;
    let consent_challenge_json = serde_json::to_string(&grant.consent_challenge)?;
    Ok(json!({
        "egress_grant_id": grant_id,
        "context_id": grant.context_id,
        "provider": grant.provider_id,
        "endpoint": CODEX_EGRESS_ENDPOINT,
        "content_bytes": binding.content_bytes,
        "content_sha256": binding.content_sha256,
        "source_kind": grant.context_kind,
        "source_id_sha256": binding.source_id_sha256,
        "intent_bytes": binding.intent_bytes,
        "intent_sha256": binding.intent_sha256,
        "allowed_actions": grant.allowed_actions,
        "allowed_actions_sha256": grant.allowed_actions_sha256,
        "prompt_contract": grant.prompt_contract,
        "prompt_contract_version": grant.prompt_contract_version,
        "privacy_class": grant.privacy_class,
        "context_captured_at_ms": grant.context_captured_at_ms,
        "context_expires_at_ms": grant.context_expires_at_ms,
        "expires_at_ms": grant.expires_at_ms,
        "upload_byte_limit": grant.upload_byte_limit,
        "download_byte_limit": grant.download_byte_limit,
        "consent_challenge": grant.consent_challenge,
        "consent_challenge_json": consent_challenge_json,
        "single_use": true,
        "network_started": false,
    }))
}

fn recover_prepare_egress_outcome(
    egress_grants: &EgressGrantStore,
    context_memory: &ContextMemoryService,
    subject: &Subject,
    registration: &AgentRegistration,
    request_id: &str,
    payload: &Value,
) -> Result<UiRequestRecovery> {
    ensure_android_user_zero(subject.uid)?;
    exact_json_object_fields(
        payload,
        &["context_id", "intent", "workflow_id", "provider"],
        "egress_prepare_payload",
    )?;
    let provider_id = required_string(payload, "provider", 64)?;
    let workflow_id = required_string(payload, "workflow_id", 128)?;
    let descriptor = agent_principal_registry::from_provider_id(&provider_id)
        .ok_or_else(|| anyhow::anyhow!("unsupported_direct_provider"))?;
    if request_id != format!("{workflow_id}-egress-prepare")
        || !crate::builtin_provider_identity::matches_stable_registration(descriptor, registration)
    {
        bail!("egress_prepare_recovery_request_or_provider_binding_mismatch");
    }
    let payload_sha256 = sha256_bytes(&serde_json::to_vec(payload)?);
    let candidates = {
        let grants = egress_grants
            .lock()
            .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
        let pending = grants
            .pending
            .iter()
            .filter(|(_, grant)| {
                grant.workflow_id == workflow_id
                    && grant.provider_id == provider_id
                    && grant.peer_uid == subject.uid
                    && grant.peer_domain == subject.selinux_domain
                    && grant.prepare_request_id == request_id
                    && grant.prepare_request_payload_sha256 == payload_sha256
                    && grant.policy_epoch == EGRESS_POLICY_EPOCH
                    && grant.provider_abi_epoch == PROVIDER_ABI_EPOCH
            })
            .collect::<Vec<_>>();
        if pending.len() > 1 {
            bail!("egress_prepare_recovery_ambiguous_pending_binding");
        }
        if let Some((grant_id, grant)) = pending.first() {
            if grant.agent_registration != *registration {
                return Ok(UiRequestRecovery::Outcome(Err(
                    "egress_prepare_recovery_identity_or_policy_retired_hold".to_string(),
                )));
            }
            return Ok(UiRequestRecovery::Outcome(Ok(prepared_egress_response(
                grant_id, grant,
            )?)));
        }
        grants.journal.prepare_recovery_candidates_for_subject(
            &workflow_id,
            &provider_id,
            subject.uid,
            &subject.selinux_domain,
            request_id,
            &payload_sha256,
        )?
    };
    if candidates.len() > 1 {
        bail!("egress_prepare_recovery_ambiguous_durable_binding");
    }
    let Some((metadata, cas, recovery_blob)) = candidates.into_iter().next() else {
        return Ok(UiRequestRecovery::Unresolved);
    };
    let recovered = (|| -> Result<Value> {
        let aad = egress_recovery_aad(&metadata, &cas.binding_sha256)?;
        let clear = context_memory.read_egress_recovery_blob(&recovery_blob, &aad)?;
        let body = decode_egress_recovery_envelope(clear.as_slice())?;
        if body.prepare_request_id != request_id
            || body.prepare_request_payload_sha256 != payload_sha256
            || body.policy_epoch != EGRESS_POLICY_EPOCH
            || body.provider_abi_epoch != PROVIDER_ABI_EPOCH
            || body.provider_id != provider_id
            || body.workflow_id != workflow_id
            || body.peer_uid != subject.uid
            || body.peer_domain != subject.selinux_domain
            || body.agent_registration != *registration
        {
            bail!("egress_prepare_recovery_sealed_binding_mismatch");
        }
        let grant_id = body.grant_id.clone();
        let grant = pending_grant_from_recovery(body, cas, recovery_blob);
        if egress_journal_metadata(&grant_id, &grant.binding()) != metadata {
            bail!("egress_prepare_recovery_metadata_binding_mismatch");
        }
        prepared_egress_response(&grant_id, &grant)
    })();
    Ok(match recovered {
        Ok(value) => UiRequestRecovery::Outcome(Ok(value)),
        Err(_) => UiRequestRecovery::Outcome(Err(
            "egress_prepare_recovery_identity_or_policy_retired_hold".to_string(),
        )),
    })
}

fn query_only_recover_egress_prepare(
    service: &AgentService,
    egress_grants: &EgressGrantStore,
    context_memory: &ContextMemoryService,
    subject: &Subject,
    recovery_request_id: &str,
    payload: &Value,
) -> Result<Value> {
    ensure_android_user_zero(subject.uid)?;
    exact_json_object_fields(
        payload,
        &[
            "original_request_id",
            "context_id",
            "intent",
            "workflow_id",
            "provider",
        ],
        "egress_prepare_query_only_recovery_payload",
    )?;
    let original_request_id = required_string(payload, "original_request_id", 128)?;
    if original_request_id == recovery_request_id {
        bail!("egress_prepare_recovery_request_id_must_be_distinct");
    }
    let provider_id = required_string(payload, "provider", 64)?;
    let registration = register_builtin_provider(service, &provider_id)?;
    let original_payload = json!({
        "context_id": required_string(payload, "context_id", 96)?,
        "intent": required_string(payload, "intent", 4 * 1024)?,
        "workflow_id": required_string(payload, "workflow_id", 128)?,
        "provider": provider_id,
    });
    let recovery = recover_prepare_egress_outcome(
        egress_grants,
        context_memory,
        subject,
        &registration,
        &original_request_id,
        &original_payload,
    )?;
    let mut result = match recovery {
        UiRequestRecovery::Outcome(Ok(value)) => value,
        UiRequestRecovery::Outcome(Err(error)) => return Err(anyhow::Error::msg(error)),
        UiRequestRecovery::Unresolved => bail!("egress_prepare_query_only_recovery_not_found"),
    };
    let object = result
        .as_object_mut()
        .context("egress_prepare_recovery_result_not_object")?;
    object.insert(
        "recovery_status".to_string(),
        Value::String("grant_available".to_string()),
    );
    object.insert(
        "original_request_id".to_string(),
        Value::String(original_request_id),
    );
    object.insert(
        "workflow_id".to_string(),
        Value::String(
            original_payload
                .get("workflow_id")
                .and_then(Value::as_str)
                .context("egress_prepare_recovery_workflow_id_missing")?
                .to_string(),
        ),
    );
    Ok(result)
}

fn revoke_egress_with_context(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    context_memory: Option<&ContextMemoryService>,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: Value,
) -> Result<Value> {
    ensure_android_user_zero(peer_uid)?;
    exact_json_object_fields(
        &payload,
        &["egress_grant_id", "workflow_id"],
        "egress_revoke_payload",
    )?;
    let grant_id = required_string(&payload, "egress_grant_id", 96)?;
    let workflow_id = required_string(&payload, "workflow_id", 128)?;
    let request_payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload)?);
    let mut grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let now = now_unix_ms();
    if let Some(grant) = grants.pending.get(&grant_id) {
        if grant.peer_uid != peer_uid
            || grant.peer_domain != peer_domain
            || grant.workflow_id != workflow_id
        {
            bail!("egress_grant_identity_binding_mismatch");
        }
        let binding = grant.binding();
        let cas = grant.journal_cas.clone();
        let recovery_blob = grant.recovery_blob.clone();
        validate_pending_egress_material_binding(&binding)?;
        if binding.expires_at_ms <= now {
            if cas.state == EgressLifecycleState::Prepared {
                let expired_cas = grants.journal.mark_expired_for_revoke(
                    &grant_id,
                    &cas,
                    request_id,
                    &request_payload_sha256,
                    now,
                )?;
                let commit_unknown = expired_cas.publication_durability_uncertain;
                grants.pending.remove(&grant_id);
                if !grants.journal.recovery_must_be_retained(&grant_id)?
                    && let Some(context_memory) = context_memory
                {
                    context_memory.delete_egress_recovery_blob(&recovery_blob)?;
                }
                if commit_unknown {
                    bail!("egress_expired_revoke_commit_unknown_parent_fsync_uncertain");
                }
            }
            bail!("egress_grant_expired");
        }
        if cas.state != EgressLifecycleState::Prepared {
            bail!("pending_egress_revoke_state_denied");
        }
        let active = active_egress
            .lock()
            .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
        if active.contains_key(&grant_id) {
            bail!("pending_egress_no_runtime_proof_failed");
        }
        drop(active);
        let revoked_cas = grants.journal.mark_revoked_before_dispatch(
            &grant_id,
            &cas,
            request_id,
            &request_payload_sha256,
            now,
        )?;
        let commit_unknown = revoked_cas.publication_durability_uncertain;
        let mut removed = grants
            .pending
            .remove(&grant_id)
            .context("pending_egress_grant_disappeared_after_no_dispatch_revoke")?;
        removed.journal_cas = revoked_cas;
        drop(removed);
        drop(grants);
        // The sealed prepare result remains custody for exact outer replay
        // until a durable UI-completion acknowledgement releases it.
        let _ = (context_memory, recovery_blob);
        if commit_unknown {
            bail!("egress_revoke_no_dispatch_commit_unknown_published_durability_uncertain");
        }
        return Ok(json!({
            "egress_grant_id": grant_id,
            "revoked": true,
            "lifecycle_state": "REVOKED_BEFORE_DISPATCH",
            "active_run_cancelled": false,
            "network_started": false,
            "teardown_proven": true,
            "no_dispatch_proven": true,
        }));
    }
    if grants.journal.contains_grant(&grant_id)
        && grants
            .journal
            .status_for_subject(&grant_id, &workflow_id, peer_uid, peer_domain)?
            == EgressLifecycleState::Expired
        && grants
            .journal
            .revoke_outcome_for_subject(
                &grant_id,
                &workflow_id,
                peer_uid,
                peer_domain,
                request_id,
                &request_payload_sha256,
            )?
            .is_none()
    {
        let frozen = grants
            .journal
            .freeze_expired_revoke_ui_outcome_for_subject(
                &grant_id,
                EgressExpiredRevokeRequest {
                    workflow_id: &workflow_id,
                    peer_uid,
                    peer_selinux_domain: peer_domain,
                    request_id,
                    request_payload_sha256: &request_payload_sha256,
                    now,
                },
            )?;
        if frozen.publication_durability_uncertain {
            bail!("egress_expired_revoke_commit_unknown_parent_fsync_uncertain");
        }
    }
    if let Some(frozen_outcome) = grants.journal.revoke_outcome_for_subject(
        &grant_id,
        &workflow_id,
        peer_uid,
        peer_domain,
        request_id,
        &request_payload_sha256,
    )? {
        let frozen_provider = grants.journal.provider_id_for_subject(
            &grant_id,
            &workflow_id,
            peer_uid,
            peer_domain,
        )?;
        match frozen_outcome {
            EgressRevokeUiOutcome::RevokedBeforeDispatch => {
                return Ok(json!({
                    "egress_grant_id": grant_id,
                    "revoked": true,
                    "lifecycle_state": "REVOKED_BEFORE_DISPATCH",
                    "active_run_cancelled": false,
                    "network_started": false,
                    "teardown_proven": true,
                    "no_dispatch_proven": true,
                }));
            }
            EgressRevokeUiOutcome::RevokePending => {
                return Ok(json!({
                    "egress_grant_id": grant_id,
                    "provider": frozen_provider,
                    "revoked": false,
                    "lifecycle_state": "REVOKE_PENDING",
                    "active_run_cancelled": true,
                    "network_started": true,
                    "teardown_proven": false,
                }));
            }
            EgressRevokeUiOutcome::Revoked => {
                return Ok(json!({
                    "egress_grant_id": grant_id,
                    "provider": frozen_provider,
                    "revoked": true,
                    "lifecycle_state": "REVOKED",
                    "active_run_cancelled": true,
                    "network_started": true,
                    "teardown_proven": true,
                    "no_dispatch_proven": false,
                }));
            }
            EgressRevokeUiOutcome::GrantExpired => bail!("egress_grant_expired"),
        }
    }
    // Keep the lock order identical to the consent transition in
    // consume_egress_grant so revoke observes either pending or active, never
    // an unprotected gap between them.
    let mut active = active_egress
        .lock()
        .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
    let run = active
        .get_mut(&grant_id)
        .context("unknown_or_consumed_egress_grant")?;
    if run.peer_uid != peer_uid || run.peer_domain != peer_domain || run.workflow_id != workflow_id
    {
        bail!("active_egress_identity_binding_mismatch");
    }
    if run.durability == ActiveEgressDurability::DispatchBlockedCommitUnknown {
        bail!("egress_consume_commit_unknown_query_only_until_restart");
    }
    // Fail before publishing REVOKE_PENDING or signalling the provider when
    // the in-memory runtime proof no longer matches its durable lifecycle
    // record.  A later comparison is too late: it would allow cancellation
    // to become observable from a corrupted active-run binding.
    if run.journal_binding_sha256 != run.journal_cas.binding_sha256 {
        bail!("active_egress_journal_binding_mismatch");
    }
    let cancellation = run.cancellation.clone();
    let provider_id = run.provider_id.clone();
    let journal_binding_sha256 = run.journal_binding_sha256.clone();
    if run.durability == ActiveEgressDurability::Running {
        let revoke_pending_cas = grants.journal.mark_revoke_pending(
            &grant_id,
            &run.journal_cas,
            request_id,
            &request_payload_sha256,
            &sha256_bytes(run.teardown_nonce.as_bytes()),
            now,
        )?;
        let commit_unknown = revoke_pending_cas.publication_durability_uncertain;
        run.journal_cas = revoke_pending_cas;
        run.durability = ActiveEgressDurability::RevokePending;
        // Cancellation becomes observable only after REVOKE_PENDING is
        // durably published.
        cancellation.cancel();
        if commit_unknown {
            drop(active);
            drop(grants);
            bail!("egress_revoke_pending_commit_unknown_published_durability_uncertain");
        }
    } else if run.durability == ActiveEgressDurability::RevokePending {
        if grants.journal.revoke_status_exact(
            &grant_id,
            &journal_binding_sha256,
            request_id,
            &request_payload_sha256,
        )? != Some(EgressLifecycleState::RevokePending)
        {
            bail!("active_egress_revoke_status_mismatch");
        }
    } else {
        bail!("active_egress_completion_already_pending");
    }
    // A cancellation flag is not a teardown acknowledgement. Release the
    // lifecycle locks so the provider thread can finish, stop and join its
    // child/proxy, then wait for ActiveEgressGuard to publish that fact. A
    // timeout returns an error and retains the retryable RevokePending record;
    // it never reports a false successful revoke while egress may still flow.
    drop(active);
    drop(grants);
    let ack = match cancellation.wait_for_teardown(ACTIVE_EGRESS_TEARDOWN_TIMEOUT) {
        Ok(ack) => ack,
        Err(_) => {
            let mut grants = egress_grants
                .lock()
                .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
            let mut active = active_egress
                .lock()
                .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
            let (commit_unknown, selected_outcome) = if let Some(run) = active.get_mut(&grant_id) {
                let frozen_cas = grants.journal.freeze_revoke_pending_ui_outcome(
                    &grant_id,
                    &run.journal_cas,
                    request_id,
                    &request_payload_sha256,
                    now_unix_ms(),
                )?;
                let commit_unknown = frozen_cas.publication_durability_uncertain;
                run.journal_cas = frozen_cas;
                (commit_unknown, EgressRevokeUiOutcome::RevokePending)
            } else {
                // The teardown durability reaper won the race. Its terminal
                // transition froze the same request's first result; return
                // that result rather than inventing an error or PENDING.
                let frozen = grants
                    .journal
                    .revoke_outcome_for_subject(
                        &grant_id,
                        &workflow_id,
                        peer_uid,
                        peer_domain,
                        request_id,
                        &request_payload_sha256,
                    )?
                    .context("active_egress_timeout_race_missing_frozen_revoke_outcome")?;
                (false, frozen)
            };
            drop(active);
            drop(grants);
            if commit_unknown {
                bail!("egress_revoke_pending_outcome_commit_unknown_parent_fsync_uncertain");
            }
            return frozen_revoke_ui_outcome(&grant_id, &provider_id, selected_outcome);
        }
    };
    let mut grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let mut active = active_egress
        .lock()
        .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
    if !active.contains_key(&grant_id) {
        // The durability reaper can win after the acknowledgement wakes this
        // waiter but before these locks are reacquired. It has already frozen
        // the exact first UI outcome, so return that outcome instead of
        // manufacturing a missing-run failure.
        let frozen = grants
            .journal
            .revoke_outcome_for_subject(
                &grant_id,
                &workflow_id,
                peer_uid,
                peer_domain,
                request_id,
                &request_payload_sha256,
            )?
            .context("active_egress_ack_race_missing_frozen_revoke_outcome")?;
        drop(active);
        drop(grants);
        return frozen_revoke_ui_outcome(&grant_id, &provider_id, frozen);
    }
    if let Some(run) = active.get(&grant_id)
        && (run.journal_binding_sha256 != journal_binding_sha256
            || run.durability != ActiveEgressDurability::RevokePending)
    {
        bail!("active_egress_teardown_binding_changed");
    }
    let run = active
        .get_mut(&grant_id)
        .context("active_egress_run_missing_before_teardown_commit")?;
    let revoked_cas = grants
        .journal
        .mark_revoked(&grant_id, &run.journal_cas, &ack)?;
    let commit_unknown = revoked_cas.publication_durability_uncertain;
    run.journal_cas = revoked_cas;
    active.remove(&grant_id);
    if commit_unknown {
        bail!("egress_revoke_terminal_commit_unknown_published_durability_uncertain");
    }
    Ok(json!({
        "egress_grant_id": grant_id,
        "provider": provider_id,
        "revoked": true,
        "lifecycle_state": "REVOKED",
        "active_run_cancelled": true,
        "network_started": true,
        "teardown_proven": true,
    }))
}

fn recover_revoke_egress_outcome(
    egress_grants: &EgressGrantStore,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: &Value,
) -> Result<UiRequestRecovery> {
    ensure_android_user_zero(peer_uid)?;
    exact_json_object_fields(
        payload,
        &["egress_grant_id", "workflow_id"],
        "egress_revoke_payload",
    )?;
    let grant_id = required_string(payload, "egress_grant_id", 96)?;
    let workflow_id = required_string(payload, "workflow_id", 128)?;
    let payload_sha256 = sha256_bytes(&serde_json::to_vec(payload)?);
    let grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let Some(frozen_outcome) = grants.journal.revoke_outcome_for_subject(
        &grant_id,
        &workflow_id,
        peer_uid,
        peer_domain,
        request_id,
        &payload_sha256,
    )?
    else {
        return Ok(UiRequestRecovery::Unresolved);
    };
    let provider_id =
        grants
            .journal
            .provider_id_for_subject(&grant_id, &workflow_id, peer_uid, peer_domain)?;
    let result = frozen_revoke_ui_outcome(&grant_id, &provider_id, frozen_outcome);
    Ok(UiRequestRecovery::Outcome(
        result.map_err(|error| error.to_string()),
    ))
}

fn frozen_revoke_ui_outcome(
    grant_id: &str,
    provider_id: &str,
    frozen_outcome: EgressRevokeUiOutcome,
) -> Result<Value> {
    Ok(match frozen_outcome {
        EgressRevokeUiOutcome::RevokedBeforeDispatch => json!({
            "egress_grant_id": grant_id,
            "revoked": true,
            "lifecycle_state": "REVOKED_BEFORE_DISPATCH",
            "active_run_cancelled": false,
            "network_started": false,
            "teardown_proven": true,
            "no_dispatch_proven": true,
        }),
        EgressRevokeUiOutcome::RevokePending => json!({
            "egress_grant_id": grant_id,
            "provider": provider_id,
            "revoked": false,
            "lifecycle_state": "REVOKE_PENDING",
            "active_run_cancelled": true,
            "network_started": true,
            "teardown_proven": false,
        }),
        EgressRevokeUiOutcome::Revoked => json!({
            "egress_grant_id": grant_id,
            "provider": provider_id,
            "revoked": true,
            "lifecycle_state": "REVOKED",
            "active_run_cancelled": true,
            "network_started": true,
            "teardown_proven": true,
            "no_dispatch_proven": false,
        }),
        EgressRevokeUiOutcome::GrantExpired => {
            bail!("egress_grant_expired");
        }
    })
}

fn ack_egress_ui_completion_if_present(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    context_memory: &ContextMemoryService,
    method: &str,
    request_id: &str,
    subject: &Subject,
    payload: &Value,
) -> Result<()> {
    let payload_sha256 = sha256_bytes(&serde_json::to_vec(payload)?);
    let Some(completion_proof) = context_memory.ui_request_completion_proof_exact(
        method,
        request_id,
        subject.uid,
        &subject.selinux_domain,
        &payload_sha256,
    )?
    else {
        return Ok(());
    };
    let completion_proof_sha256 = completion_proof.digest_sha256()?;
    let mut grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let mut active = active_egress
        .lock()
        .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
    let (grant_id, recovery_blob) = if method == "prepare_egress" {
        exact_json_object_fields(
            payload,
            &["context_id", "intent", "workflow_id", "provider"],
            "egress_prepare_payload",
        )?;
        let workflow_id = required_string(payload, "workflow_id", 128)?;
        let provider_id = required_string(payload, "provider", 64)?;
        let candidates = grants.journal.prepare_recovery_candidates_for_subject(
            &workflow_id,
            &provider_id,
            subject.uid,
            &subject.selinux_domain,
            request_id,
            &payload_sha256,
        )?;
        if candidates.len() > 1 {
            bail!("egress_prepare_ui_completion_ambiguous_durable_binding");
        }
        let Some((metadata, _, recovery_blob)) = candidates.into_iter().next() else {
            // A denied prepare has no
            // lifecycle record. Persist an exact self-terminal custody ack so
            // this denial can age out without pretending a grant owns it.
            drop(active);
            drop(grants);
            return context_memory.acknowledge_ui_replay_custody_handoff(
                &completion_proof,
                subject.uid,
                &subject.selinux_domain,
                "ui_replay_self_terminal",
                request_id,
            );
        };
        (metadata.grant_id, Some(recovery_blob))
    } else if method == "revoke_egress" {
        exact_json_object_fields(
            payload,
            &["egress_grant_id", "workflow_id"],
            "egress_revoke_payload",
        )?;
        let grant_id = required_string(payload, "egress_grant_id", 96)?;
        if !grants.journal.contains_grant(&grant_id) {
            // Unknown-grant denial has no lifecycle record to acknowledge.
            drop(active);
            drop(grants);
            return context_memory.acknowledge_ui_replay_custody_handoff(
                &completion_proof,
                subject.uid,
                &subject.selinux_domain,
                "ui_replay_self_terminal",
                request_id,
            );
        }
        (grant_id, None)
    } else {
        bail!("egress_ui_completion_method_denied");
    };
    let cas = grants.journal.mark_ui_request_completed_exact(
        &grant_id,
        EgressUiCompletionBinding {
            method,
            request_id,
            request_payload_sha256: &payload_sha256,
            completion_proof_sha256: &completion_proof_sha256,
            peer_uid: subject.uid,
            peer_selinux_domain: &subject.selinux_domain,
            completed_at_ms: now_unix_ms(),
        },
    )?;
    if let Some(pending) = grants.pending.get_mut(&grant_id) {
        pending.journal_cas = cas.clone();
    }
    if let Some(run) = active.get_mut(&grant_id) {
        run.journal_cas = cas.clone();
    }
    let commit_unknown = cas.publication_durability_uncertain;
    drop(active);
    drop(grants);
    if commit_unknown {
        bail!("egress_ui_completion_ack_commit_unknown_parent_fsync_uncertain");
    }
    context_memory.acknowledge_ui_replay_custody_handoff(
        &completion_proof,
        subject.uid,
        &subject.selinux_domain,
        "egress_lifecycle_journal",
        &grant_id,
    )?;
    if method == "prepare_egress"
        && cas.state != EgressLifecycleState::Prepared
        && let Some(recovery_blob) = recovery_blob
    {
        // Both the downstream lifecycle ack and the UI custody handoff are
        // durable. Ciphertext deletion is now post-commit orphan cleanup.
        let _ = context_memory.delete_egress_recovery_blob(&recovery_blob);
    }
    Ok(())
}

fn ack_action_workflow_ui_completion_if_present(
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
    method: &str,
    request_id: &str,
    subject: &Subject,
    payload: &Value,
) -> Result<()> {
    if method != direct_agent_host_abi::BUILTIN_WIRE_METHOD_RUN_DIRECT_TURN {
        bail!("action_workflow_ui_completion_method_denied");
    }
    let payload_sha256 = sha256_bytes(&serde_json::to_vec(payload)?);
    let Some(completion_proof) = context_memory.ui_request_completion_proof_exact(
        method,
        request_id,
        subject.uid,
        &subject.selinux_domain,
        &payload_sha256,
    )?
    else {
        return Ok(());
    };
    let proof_sha256 = completion_proof.digest_sha256()?;
    {
        let mut journal = action_consents
            .lock()
            .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?;
        journal.record_ui_completion_proof(
            context_memory,
            method,
            request_id,
            subject.uid,
            &subject.selinux_domain,
            &payload_sha256,
            &proof_sha256,
        )?;
    }
    reconcile_action_workflow_custody(action_consents, context_memory)
}

fn acknowledge_action_workflow_ui_binding(
    context_memory: &ContextMemoryService,
    binding: &ActionWorkflowUiCustodyBinding,
) -> Result<bool> {
    let Some(proof) = context_memory.ui_request_completion_proof_exact(
        &binding.method,
        &binding.request_id,
        binding.subject_uid,
        &binding.subject_selinux_domain,
        &binding.request_payload_sha256,
    )?
    else {
        return Ok(false);
    };
    if proof.digest_sha256()? != binding.completion_proof_sha256 {
        bail!("action_workflow_ui_completion_proof_changed");
    }
    context_memory.acknowledge_ui_replay_custody_handoff(
        &proof,
        binding.subject_uid,
        &binding.subject_selinux_domain,
        "action_workflow_journal",
        &binding.request_id,
    )?;
    Ok(true)
}

/// Three-phase custody reconciliation with one global lock order:
/// action snapshot -> unlocked UI proof/handoff -> exact action CAS.
fn reconcile_action_workflow_custody(
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
) -> Result<()> {
    let candidates = action_consents
        .lock()
        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
        .custody_candidates(context_memory)?;
    for candidate in candidates {
        if !acknowledge_action_workflow_ui_binding(context_memory, &candidate.plan)? {
            continue;
        }
        if let Some(approve) = candidate.approve.as_ref()
            && !acknowledge_action_workflow_ui_binding(context_memory, approve)?
        {
            continue;
        }
        action_consents
            .lock()
            .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
            .compact_custody_candidate_exact(context_memory, &candidate)?;
    }
    Ok(())
}

#[cfg(test)]
fn revoke_egress(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: Value,
) -> Result<Value> {
    revoke_egress_with_context(
        egress_grants,
        active_egress,
        None,
        peer_uid,
        peer_domain,
        request_id,
        payload,
    )
}

fn egress_status(
    egress_grants: &EgressGrantStore,
    peer_uid: u32,
    peer_domain: &str,
    payload: Value,
) -> Result<Value> {
    ensure_android_user_zero(peer_uid)?;
    exact_json_object_fields(
        &payload,
        &["egress_grant_id", "workflow_id"],
        "egress_status_payload",
    )?;
    let grant_id = required_string(&payload, "egress_grant_id", 96)?;
    let workflow_id = required_string(&payload, "workflow_id", 128)?;
    let grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let state =
        grants
            .journal
            .status_for_subject(&grant_id, &workflow_id, peer_uid, peer_domain)?;
    let runtime_evidence = grants.journal.runtime_evidence_for_subject(
        &grant_id,
        &workflow_id,
        peer_uid,
        peer_domain,
    )?;
    let (runtime_evidence, runtime_evidence_sha256) = runtime_evidence
        .map(|(evidence, digest)| (Some(evidence), Some(digest)))
        .unwrap_or((None, None));
    let state_name = match state {
        EgressLifecycleState::Prepared => "PREPARED",
        EgressLifecycleState::Consumed => "CONSUMED",
        EgressLifecycleState::RevokePending => "REVOKE_PENDING",
        EgressLifecycleState::Completed => "COMPLETED",
        EgressLifecycleState::Revoked => "REVOKED",
        EgressLifecycleState::RevokedBeforeDispatch => "REVOKED_BEFORE_DISPATCH",
        EgressLifecycleState::Expired => "EXPIRED",
        EgressLifecycleState::InterruptedRestart => "INTERRUPTED_RESTART",
        EgressLifecycleState::IndeterminateRestart => "INDETERMINATE_RESTART",
        EgressLifecycleState::LegacyInvalidatedRestart => {
            bail!("legacy_egress_lifecycle_state_unreachable")
        }
    };
    Ok(json!({
        "egress_grant_id": grant_id,
        "workflow_id": workflow_id,
        "lifecycle_state": state_name,
        "revoked": matches!(
            state,
            EgressLifecycleState::Revoked | EgressLifecycleState::RevokedBeforeDispatch
        ),
        "terminal": matches!(
            state,
            EgressLifecycleState::Completed
                | EgressLifecycleState::Revoked
                | EgressLifecycleState::RevokedBeforeDispatch
                | EgressLifecycleState::Expired
                | EgressLifecycleState::InterruptedRestart
                | EgressLifecycleState::IndeterminateRestart
        ),
        "automatic_reexecution_permitted": false,
        "query_only": true,
        "runtime_evidence": runtime_evidence,
        "runtime_evidence_sha256": runtime_evidence_sha256,
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderAttemptClass {
    Succeeded,
    Cancelled,
    TimedOut,
    Failed,
}

struct NormalizedDirectProviderAttempt<T> {
    result: Result<T>,
    runtime_evidence: CodexRuntimeEvidence,
    attempt_class: ProviderAttemptClass,
}

fn normalize_codex_direct_attempt(
    attempt: CodexPlanAttempt,
) -> NormalizedDirectProviderAttempt<CodexPlanningReceipt> {
    let attempt_class = match attempt.lifecycle {
        CodexPlanAttemptLifecycle::Succeeded => ProviderAttemptClass::Succeeded,
        CodexPlanAttemptLifecycle::Cancelled => ProviderAttemptClass::Cancelled,
        CodexPlanAttemptLifecycle::TimedOut => ProviderAttemptClass::TimedOut,
        CodexPlanAttemptLifecycle::Failed => ProviderAttemptClass::Failed,
    };
    let result = match (attempt.result, attempt.recovery_receipt) {
        (Ok(receipt), None) => Ok(receipt),
        (Ok(_), Some(_)) => Err(anyhow::anyhow!(
            "codex_success_attempt_must_not_include_recovery_receipt"
        )),
        (Err(error), None) => Err(error.into()),
        (Err(_), Some(receipt)) => validate_codex_direct_effect_recovery_receipt(&receipt)
            .map(|()| receipt)
            .map_err(anyhow::Error::from)
            .context("codex_direct_effect_recovery_receipt_invalid"),
    };
    NormalizedDirectProviderAttempt {
        result,
        runtime_evidence: attempt.runtime_evidence,
        attempt_class,
    }
}

fn persist_provider_runtime_evidence_and_publish_ack(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    grant_id: &str,
    runtime_evidence: &CodexRuntimeEvidence,
    attempt_class: ProviderAttemptClass,
) -> Result<()> {
    let runtime_evidence_value = serde_json::to_value(runtime_evidence)?;
    let runtime_evidence_sha256 = sha256_json(&runtime_evidence_value);
    let child_cleanup_sha256 = runtime_evidence
        .child_cleanup_sha256
        .clone()
        .unwrap_or_else(|| sha256_bytes(b"trillionnium.provider-runtime.no-child-started.v1"));
    let provider_session_cleanup_sha256 = runtime_evidence
        .provider_session_cleanup_sha256
        .clone()
        .context("provider_session_cleanup_digest_missing")?;
    let broker_outcome_sha256 = runtime_evidence
        .broker_outcome_sha256
        .clone()
        .context("broker_outcome_digest_missing")?;
    let mut grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let mut active = active_egress
        .lock()
        .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
    let run = active
        .get_mut(grant_id)
        .context("active_egress_run_missing_for_runtime_evidence")?;
    let runtime_binding = runtime_evidence
        .lifecycle_binding
        .as_ref()
        .context("provider_runtime_lifecycle_binding_missing")?;
    if run.provider_id != runtime_binding.provider_id
        || runtime_binding.egress_grant_id != grant_id
        || runtime_binding.journal_binding_sha256 != run.journal_binding_sha256
        || runtime_binding.teardown_nonce_sha256 != sha256_bytes(run.teardown_nonce.as_bytes())
        || run.journal_cas.binding_sha256 != run.journal_binding_sha256
        || !matches!(
            run.journal_cas.state,
            EgressLifecycleState::Consumed | EgressLifecycleState::RevokePending
        )
    {
        bail!("provider_runtime_evidence_active_binding_mismatch");
    }
    let expected_agent_domain = if runtime_binding.provider_id == CODEX_PROVIDER_ID
        && runtime_binding.agent_id == CODEX_AGENT_ID
    {
        CODEX_AGENT_SELINUX_DOMAIN
    } else {
        bail!("provider_runtime_evidence_identity_denied");
    };
    if !runtime_evidence.production_egress_teardown_proven_for(
        &runtime_binding.provider_id,
        &runtime_binding.agent_id,
        expected_agent_domain,
    ) {
        bail!("provider_production_egress_teardown_unproven");
    }
    let broker_termination = &runtime_evidence
        .egress
        .as_ref()
        .context("provider_runtime_broker_outcome_missing")?
        .evidence
        .termination_reason;
    let termination_reason = match broker_termination {
        EgressBrokerTerminationReason::InvocationCompleted => "completed",
        EgressBrokerTerminationReason::ProviderCancelled => "cancelled",
        EgressBrokerTerminationReason::ProviderTimedOut => "timed_out",
        EgressBrokerTerminationReason::CallerStopped => "caller",
        _ => "failed",
    };
    let result_class_matches = match attempt_class {
        ProviderAttemptClass::Succeeded => termination_reason == "completed",
        ProviderAttemptClass::Cancelled => termination_reason == "cancelled",
        ProviderAttemptClass::TimedOut => termination_reason == "timed_out",
        ProviderAttemptClass::Failed => termination_reason == "failed",
    };
    if !result_class_matches {
        bail!("provider_runtime_result_broker_termination_mismatch");
    }
    let evidence_cas = grants.journal.mark_runtime_evidence(
        grant_id,
        &run.journal_cas,
        &runtime_evidence_sha256,
        runtime_evidence,
        now_unix_ms(),
    )?;
    let commit_unknown = evidence_cas.publication_durability_uncertain;
    run.journal_cas = evidence_cas;
    if commit_unknown {
        // The visible journal contains the evidence, but parent-directory
        // durability is unknown. Keep custody and fail-stop this run; never
        // publish an acknowledgement that could authorize terminalization in
        // the same process from a not-proven-durable evidence record.
        run.durability = ActiveEgressDurability::DispatchBlockedCommitUnknown;
        drop(active);
        drop(grants);
        bail!("egress_runtime_evidence_commit_unknown_parent_fsync_uncertain");
    }
    let cancellation = run.cancellation.clone();
    let ack = EgressTeardownAck {
        proof_schema: "trillionnium.egress-teardown-proof.v2".to_string(),
        grant_id: grant_id.to_string(),
        journal_binding_sha256: run.journal_binding_sha256.clone(),
        provider_id: run.provider_id.clone(),
        teardown_nonce: run.teardown_nonce.clone(),
        child_cleanup_sha256,
        provider_session_cleanup_sha256,
        broker_outcome_sha256,
        runtime_evidence_sha256,
        termination_reason: termination_reason.to_string(),
        acknowledged_at_ms: now_unix_ms(),
    };
    drop(active);
    drop(grants);
    // Publish only after the full canonical sanitized evidence and its digest
    // are durable under the exact lifecycle CAS.
    cancellation.publish_verified_teardown_ack(ack)?;
    Ok(())
}

fn verify_direct_provider_attempt<T>(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    grant_id: &str,
    attempt: NormalizedDirectProviderAttempt<T>,
) -> Result<T> {
    // The provider result remains untouched until the complete sanitized
    // containment/broker evidence is production-valid, durable, and
    // acknowledged under this exact grant/CAS/nonce.
    persist_provider_runtime_evidence_and_publish_ack(
        egress_grants,
        active_egress,
        grant_id,
        &attempt.runtime_evidence,
        attempt.attempt_class,
    )?;
    attempt.result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectCallEffect {
    Success,
    DefinitiveTerminal,
    Indeterminate,
    NoEffect,
}

fn reduce_direct_provider_outcome(
    refusal_reason: Option<&str>,
    effects: impl IntoIterator<Item = DirectCallEffect>,
) -> (ProviderDirectOutcome, Option<String>) {
    let mut completed = false;
    for effect in effects {
        match effect {
            DirectCallEffect::Success | DirectCallEffect::DefinitiveTerminal => completed = true,
            DirectCallEffect::Indeterminate => {
                return (ProviderDirectOutcome::Indeterminate, None);
            }
            DirectCallEffect::NoEffect => {}
        }
    }
    if completed {
        (ProviderDirectOutcome::Completed, None)
    } else if let Some(reason) = refusal_reason {
        (ProviderDirectOutcome::Refused, Some(reason.to_string()))
    } else {
        (ProviderDirectOutcome::NoAction, None)
    }
}

fn codex_direct_call_effect(call: &CodexDirectToolCallEvidence) -> DirectCallEffect {
    if call.backend_error_code.as_deref().is_some_and(|code| {
        direct_backend_error_effect_class(&call.server, code)
            == Some(DirectBackendEffectClass::Indeterminate)
    }) {
        DirectCallEffect::Indeterminate
    } else if call.backend_error_code.as_deref().is_some_and(|code| {
        direct_backend_error_effect_class(&call.server, code)
            == Some(DirectBackendEffectClass::DefinitiveTerminal)
    }) {
        DirectCallEffect::DefinitiveTerminal
    } else if call.outcome == "success" {
        DirectCallEffect::Success
    } else {
        DirectCallEffect::NoEffect
    }
}

fn direct_call_is_completed(call: &CodexDirectToolCallEvidence) -> bool {
    matches!(
        (call.status.as_str(), call.outcome.as_str()),
        ("completed", "success") | ("failed", "terminal_error")
    )
}

fn map_codex_direct_result(receipt: CodexPlanningReceipt) -> Result<ProviderPlanResult> {
    let recovered_direct_effect = receipt.decision == CODEX_DIRECT_EFFECT_RECOVERY_DECISION;
    if recovered_direct_effect {
        validate_codex_direct_effect_recovery_receipt(&receipt)
            .map_err(anyhow::Error::from)
            .context("codex_direct_effect_recovery_receipt_invalid")?;
    }
    let bounded = receipt
        .plan
        .as_ref()
        .context("provider receipt omitted plan")?;
    if !receipt.tool_execution_enabled
        || (!recovered_direct_effect && receipt.decision != "PASS_CODEX_DIRECT_RESULT_VALIDATED")
        || !bounded.actions.is_empty()
    {
        bail!("codex_direct_result_contract_invalid");
    }
    let provider_output_sha256 = sha256_json(&json!({
        "protocol": &receipt.protocol,
        "decision": &receipt.decision,
        "result": bounded,
        "direct_tool_calls": &receipt.direct_tool_calls,
    }));
    let (direct_outcome, direct_refusal_reason) = reduce_direct_provider_outcome(
        bounded.refusal_reason.as_deref(),
        receipt
            .direct_tool_calls
            .iter()
            .map(codex_direct_call_effect),
    );
    let summary = bounded.summary.clone();
    Ok(AgentDirectProviderResult {
        direct_outcome,
        direct_refusal_reason,
        direct_tool_calls: receipt.direct_tool_calls,
        summary,
        runtime_provider: receipt.provider,
        model: format!(
            "built-in.codex-cli-{}/{}",
            super::codex_adapter::CODEX_ADAPTER_VERSION,
            receipt.model
        ),
        elapsed_ms: receipt.elapsed_ms,
        provider_output_sha256,
    }
    .into())
}

fn finalize_active_egress_completion(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    grant_id: &str,
) -> Result<bool> {
    finalize_active_egress_completion_inner(egress_grants, active_egress, grant_id, None)
        .map(|(finalized, _)| finalized)
}

fn finalize_active_egress_completion_inner(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    grant_id: &str,
    direct_snapshot: Option<(
        &EgressJournalCas,
        &trillionnium_os_types::direct_operation::DirectOperationBinding,
    )>,
) -> Result<(
    bool,
    Option<crate::egress_journal::VerifiedDirectTerminalEgressSnapshot>,
)> {
    let mut grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let mut active = active_egress
        .lock()
        .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
    let Some(run) = active.get_mut(grant_id) else {
        // A successful concurrent revoke already durably terminalized and
        // removed this runtime record.
        return Ok((true, None));
    };
    if run.durability == ActiveEgressDurability::RevokePending {
        // Never disguise an explicitly requested revoke as normal completion.
        return Ok((false, None));
    }
    if run.durability == ActiveEgressDurability::DispatchBlockedCommitUnknown {
        return Ok((false, None));
    }
    run.durability = ActiveEgressDurability::CompletionPending;
    let Some(ack) = run.cancellation.teardown_ack()? else {
        return Ok((false, None));
    };
    if ack.termination_reason != "completed" {
        return Ok((false, None));
    }
    let completed_cas = grants
        .journal
        .mark_completed(grant_id, &run.journal_cas, &ack)
        .context("active_egress_completion_durability_pending")?;
    let commit_unknown = completed_cas.publication_durability_uncertain;
    let direct_snapshot = direct_snapshot
        .map(|(allocation_cas, binding)| {
            grants.journal.verified_direct_terminal_snapshot(
                grant_id,
                &completed_cas,
                allocation_cas,
                binding,
            )
        })
        .transpose()?;
    run.journal_cas = completed_cas;
    active.remove(grant_id);
    if commit_unknown {
        bail!("egress_completion_commit_unknown_published_durability_uncertain");
    }
    Ok((true, direct_snapshot))
}

fn retry_pending_active_egress_durability(
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
) -> Result<usize> {
    let mut grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let mut active = active_egress
        .lock()
        .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
    let pending = active
        .iter()
        .filter(|(_, run)| {
            matches!(
                run.durability,
                ActiveEgressDurability::CompletionPending | ActiveEgressDurability::RevokePending
            )
        })
        .map(|(grant_id, run)| (grant_id.clone(), run.durability))
        .collect::<Vec<_>>();
    let mut recovered = 0usize;
    for (grant_id, durability) in pending {
        let Some(run) = active.get_mut(&grant_id) else {
            continue;
        };
        let Some(ack) = run.cancellation.teardown_ack()? else {
            continue;
        };
        if durability == ActiveEgressDurability::CompletionPending
            && ack.termination_reason != "completed"
        {
            continue;
        }
        let result = match durability {
            ActiveEgressDurability::Running
            | ActiveEgressDurability::DispatchBlockedCommitUnknown => unreachable!(),
            ActiveEgressDurability::CompletionPending => {
                grants
                    .journal
                    .mark_completed(&grant_id, &run.journal_cas, &ack)
            }
            ActiveEgressDurability::RevokePending => {
                grants
                    .journal
                    .mark_revoked(&grant_id, &run.journal_cas, &ack)
            }
        };
        run.journal_cas = result.with_context(|| {
            format!(
                "active_egress_{}_durability_retry_pending",
                match durability {
                    ActiveEgressDurability::Running => "running",
                    ActiveEgressDurability::DispatchBlockedCommitUnknown => "dispatch-blocked",
                    ActiveEgressDurability::CompletionPending => "completion",
                    ActiveEgressDurability::RevokePending => "revoke",
                }
            )
        })?;
        active.remove(&grant_id);
        recovered = recovered.saturating_add(1);
    }
    Ok(recovered)
}

fn prevalidate_plan(
    egress_grants: &EgressGrantStore,
    context_memory: &ContextMemoryService,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: &Value,
) -> Result<ValidatedEgressConsent> {
    ensure_android_user_zero(peer_uid)?;
    let authority_key_pin = context_memory.authority_key_pin()?;
    prevalidate_egress_consent(
        egress_grants,
        peer_uid,
        peer_domain,
        request_id,
        payload,
        &authority_key_pin,
        now_unix_ms(),
    )
}

fn enforce_live_agent_direct_result(
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
    request_id: &str,
    execution_mode: ProviderExecutionMode,
) -> Result<()> {
    if execution_mode == ProviderExecutionMode::AgentDirect {
        return Ok(());
    }
    action_consents
        .lock()
        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
        .mark_indeterminate(
            context_memory,
            request_id,
            RETIRED_NON_DIRECT_WORKFLOW_REASON,
        )?;
    bail!(RETIRED_NON_DIRECT_WORKFLOW_REASON)
}

#[cfg(test)]
fn test_direct_binding_publisher()
-> Result<(tempfile::TempDir, DirectOperationBindingInboxPublisher)> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_parent = manifest
        .ancestors()
        .nth(3)
        .context("direct_binding_test_private_parent_missing")?;
    let root = tempfile::Builder::new()
        .prefix(".android-direct-binding-hook-test-")
        .tempdir_in(fixture_parent)?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    let provider = root.path().join("inbox/provider");
    let system_api = provider.join("system-api");
    let accessibility = provider.join("accessibility");
    fs::create_dir_all(&system_api)?;
    fs::create_dir_all(&accessibility)?;
    for directory in [root.path().join("inbox"), provider] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o750))?;
    }
    for directory in [&system_api, &accessibility] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o750))?;
    }
    let publisher = DirectOperationBindingInboxPublisher::for_test(system_api);
    Ok((root, publisher))
}

#[allow(clippy::too_many_arguments)]
fn plan_validated(
    service: &AgentService,
    egress_grants: &EgressGrantStore,
    active_egress: &ActiveEgressStore,
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: Value,
    validated: ValidatedEgressConsent,
) -> Result<Value> {
    ensure_android_user_zero(peer_uid)?;
    ensure_android_user_zero(validated.binding.peer_uid)?;
    let now = now_unix_ms();
    validate_egress_plan_payload_shape(&payload)?;
    let plan_request_payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload)?);
    let requested_provider = required_string(&payload, "provider", 64)?;
    if requested_provider != CODEX_PROVIDER_ID {
        bail!("unsupported_direct_provider");
    }
    #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
    let _p0_userdebug_direct_turn_serial = P0_USERDEBUG_DIRECT_TURN_SERIAL
        .try_lock()
        .map_err(|_| anyhow::anyhow!("p0_userdebug_direct_turn_busy_or_poisoned_no_mutation"))?;
    let mut secret = [0u8; 32];
    fill_kernel_random(&mut secret)?;
    // Freeze and remeasure the OS AgentManifest identity before constructing
    // Codex. The provider capability identity is derived only from
    // this verified registration, never from wrapper-controlled environment.
    let registration = register_builtin_provider(service, &requested_provider)?;
    let agent_executable = measure_builtin_provider_dispatch_identity(&requested_provider)?;
    if agent_executable.sha256 != registration.identity_key_sha256 {
        bail!("built-in Agent dispatch executable does not match its AgentManifest");
    }
    let codex = Arc::new(super::codex_provider(secret, &registration)?);
    let cancellation = ActiveEgressCancellation {
        cancelled: Arc::new(AtomicBool::new(false)),
        teardown_nonce: random_hex_32()?,
        teardown_ack: Arc::new((Mutex::new(None), Condvar::new())),
        #[cfg(test)]
        cancel_count: Arc::new(AtomicUsize::new(0)),
        #[cfg(test)]
        ack_publish_count: Arc::new(AtomicUsize::new(0)),
        #[cfg(test)]
        wait_entered_barrier: None,
        #[cfg(test)]
        after_ack_gate: None,
        #[cfg(test)]
        force_teardown_timeout: false,
    };
    let (egress_grant_id, grant, consent_receipt_id) = consume_validated_egress_grant(
        egress_grants,
        Some(context_memory),
        active_egress,
        &cancellation,
        validated,
    )?;
    let active_guard = ActiveEgressGuard {
        egress_grants: Arc::clone(egress_grants),
        store: Arc::clone(active_egress),
        grant_id: egress_grant_id.clone(),
        cancellation: cancellation.clone(),
        finalized: false,
    };
    #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
    let mut p0_userdebug_ack_hotpath = None;
    let outcome = (|| -> Result<Value> {
        // Revalidate the consented material immediately before constructing the
        // provider request. The same check runs while the grant is still pending,
        // so any mismatch fails without consuming the single-use grant.
        let grant_binding = grant.binding();
        validate_pending_egress_material_binding(&grant_binding)?;
        let PendingEgressGrant {
            provider_id,
            workflow_id,
            context_id,
            context_kind,
            context_captured_at_ms,
            context_expires_at_ms,
            privacy_class,
            source_id,
            content,
            intent,
            content_sha256,
            allowed_actions,
            allowed_actions_sha256,
            prompt_contract,
            prompt_contract_version,
            expires_at_ms,
            upload_byte_limit,
            download_byte_limit,
            ..
        } = grant;
        let direct_os_identity = DirectOperationOsIdentity::from_registered_agent(
            &workflow_id,
            &registration,
            &agent_executable.sha256,
        )?;
        let context_privacy = match privacy_class.as_str() {
            "public" => PrivacyClass::Public,
            "local_private" => PrivacyClass::LocalPrivate,
            "sensitive" => PrivacyClass::Sensitive,
            _ => bail!("unsupported_context_privacy_class"),
        };
        let dispatch_origin = Subject::new(peer_uid, peer_domain)?;
        let task: TaskView = serde_json::from_value(dispatch_builtin_agent_state_change(
            service,
            &registration,
            &agent_executable,
            Some(&dispatch_origin),
            "create_task",
            serde_json::to_value(TaskInput {
                title: format!("Built-in {provider_id} request {workflow_id}"),
                description: Some(
                    "Android UI -> bounded context/egress handoff -> isolated Agent provider"
                        .to_string(),
                ),
                metadata: json!({
                    "android_ui_uid": peer_uid,
                    "android_ui_domain": peer_domain,
                    "android_workflow_id": workflow_id,
                    "context_kind": context_kind,
                    "context_id": context_id,
                    "context_captured_at_ms": context_captured_at_ms,
                    "context_expires_at_ms": context_expires_at_ms,
                    "context_privacy_class": privacy_class.clone(),
                    "source_id_sha256": sha256_bytes(source_id.as_bytes()),
                    "content_sha256": content_sha256,
                    "intent_sha256": sha256_bytes(intent.as_bytes()),
                    "allowed_actions_sha256": allowed_actions_sha256,
                    "prompt_contract": prompt_contract,
                    "prompt_contract_version": prompt_contract_version,
                    "egress_grant_id": egress_grant_id,
                    "egress_provider": provider_id,
                    "egress_endpoint": CODEX_EGRESS_ENDPOINT,
                    "egress_grant_expires_at_ms": expires_at_ms,
                    "egress_consent_receipt_id": consent_receipt_id,
                    "egress_upload_byte_limit": upload_byte_limit,
                    "egress_download_byte_limit": download_byte_limit,
                }),
            })?,
        )?)
        .context("built-in Agent API create_task returned an invalid task")?;
        let workflow_binding = PlanRecoveryBinding {
            method: direct_agent_host_abi::BUILTIN_WIRE_METHOD_RUN_DIRECT_TURN.to_string(),
            request_id: request_id.to_string(),
            request_payload_sha256: plan_request_payload_sha256.clone(),
            subject_uid: peer_uid,
            subject_selinux_domain: peer_domain.to_string(),
            provider_id: provider_id.clone(),
            task_id: task.id.0.clone(),
            plan_id: String::new(),
            action_id: String::new(),
            tool_call_id: String::new(),
            accepted_plan_sha256: String::new(),
            challenge_sha256: String::new(),
            challenge_expires_at_ms: 0,
        };
        action_consents
            .lock()
            .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
            .begin_provider_pending(
                context_memory,
                workflow_binding.clone(),
                json!({
                    "schema": LOCAL_PLAN_SAGA_SCHEMA,
                    "state": "provider_pending",
                    "task_id": task.id.0,
                }),
            )?;
        let capability_expires_at_ms = (now + 180_000).min(expires_at_ms);
        let session_id = format!("android-ui-{peer_uid}-{workflow_id}");
        let claims = CapabilityClaims {
            token_id: format!("cap-{request_id}-{now}"),
            task_id: task.id.0.clone(),
            provider_id: provider_id.clone(),
            agent_id: grant_binding.agent_id.clone(),
            agent_peer_uid: grant_binding.agent_peer_uid,
            agent_peer_gid: grant_binding.agent_peer_gid,
            agent_selinux_domain_sha256: sha256_bytes(
                grant_binding.agent_selinux_domain.as_bytes(),
            ),
            agent_executable_sha256: grant_binding.agent_executable_sha256.clone(),
            agent_manifest_sha256: grant_binding.agent_manifest_sha256.clone(),
            subject_uid: peer_uid,
            subject_selinux_domain_sha256: sha256_bytes(peer_domain.as_bytes()),
            subject_user_id: peer_uid / ANDROID_UID_PER_USER_RANGE,
            boot_id_sha256: grant_binding.boot_id_sha256.clone(),
            workflow_id_sha256: sha256_bytes(workflow_id.as_bytes()),
            provider_invocation_id_sha256: sha256_bytes(request_id.as_bytes()),
            provider_session_id_sha256: sha256_bytes(session_id.as_bytes()),
            context_id_sha256: sha256_bytes(context_id.as_bytes()),
            context_kind: context_kind.clone(),
            context_captured_at_ms,
            context_expires_at_ms,
            context_sha256: content_sha256.clone(),
            source_id_sha256: sha256_bytes(source_id.as_bytes()),
            privacy_class: privacy_class.clone(),
            content_bytes: u64::try_from(content.len())?,
            intent_sha256: sha256_bytes(intent.as_bytes()),
            intent_bytes: u64::try_from(intent.len())?,
            allowed_actions,
            allowed_actions_sha256: allowed_actions_sha256.clone(),
            prompt_contract: prompt_contract.clone(),
            prompt_contract_version,
            egress_grant_id: egress_grant_id.clone(),
            consent_challenge_sha256: sha256_json(&grant_binding.consent_challenge),
            consent_receipt_id: consent_receipt_id.clone(),
            journal_binding_sha256: grant_binding.journal_binding_sha256.clone(),
            teardown_nonce_sha256: sha256_bytes(cancellation.teardown_nonce.as_bytes()),
            issued_at_unix_ms: now,
            expires_at_unix_ms: capability_expires_at_ms,
            network_approved: true,
            egress_endpoint: CODEX_EGRESS_ENDPOINT.to_string(),
            egress_upload_byte_limit: upload_byte_limit,
            egress_download_byte_limit: download_byte_limit,
            egress_expires_at_unix_ms: capability_expires_at_ms,
            nonce: format!("approval-{request_id}-{now}"),
        };
        let request = SecretPlanningRequest(PlanningRequest {
            task_id: task.id.0.clone(),
            intent: intent.as_str().to_string(),
            contexts: vec![ProvenanceContext {
                source_id: source_id.as_str().to_string(),
                source_kind: context_kind.clone(),
                captured_at_unix_ms: context_captured_at_ms,
                freshness_ttl_ms: context_expires_at_ms.saturating_sub(context_captured_at_ms),
                privacy_class: context_privacy,
                content: content.as_str().to_string(),
            }],
            capability: CapabilityIssuer::new(secret).issue(claims)?,
        });
        let runtime_binding = RuntimeLifecycleBinding::from_verified_request(
            &request.0,
            env!("TRILLIONNIUM_P01_CODEX_RUNTIME_SHA256"),
        )
        .map_err(anyhow::Error::msg)?;
        #[cfg(not(test))]
        let direct_binding_publisher = DirectOperationBindingInboxPublisher::product();
        #[cfg(test)]
        let (_test_direct_binding_root, direct_binding_publisher) =
            test_direct_binding_publisher()?;
        let direct_lifecycle_reservation = direct_binding_publisher
            .reserve_verified(&request.0, &runtime_binding)
            .context("direct_operation_lifecycle_reservation_failed_dispatch_denied")?;
        let (attempt_source, allocated_attempt_cas) = {
            let mut grants = egress_grants
                .lock()
                .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
            let mut active = active_egress
                .lock()
                .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
            let run = active
                .get_mut(&egress_grant_id)
                .context("active_egress_run_missing_before_predispatch_binding")?;
            if run.durability != ActiveEgressDurability::Running
                || run.journal_cas.state != EgressLifecycleState::Consumed
            {
                bail!("active_egress_predispatch_state_denied");
            }
            let frozen = grants.journal.freeze_predispatch_binding(
                &egress_grant_id,
                &run.journal_cas,
                &runtime_binding,
                &task.id.0,
                request_id,
                &session_id,
                now_unix_ms(),
            )?;
            run.journal_cas = frozen.clone();
            if frozen.publication_durability_uncertain {
                run.durability = ActiveEgressDurability::DispatchBlockedCommitUnknown;
                bail!("egress_predispatch_binding_commit_unknown_dispatch_denied");
            }
            let allocated = grants.journal.allocate_direct_provider_attempt(
                &egress_grant_id,
                &frozen,
                &runtime_binding,
                &task.id.0,
                now_unix_ms(),
            )?;
            run.journal_cas = allocated.clone();
            if allocated.publication_durability_uncertain {
                run.durability = ActiveEgressDurability::DispatchBlockedCommitUnknown;
                bail!("egress_direct_attempt_commit_unknown_dispatch_denied");
            }
            let source = grants.journal.direct_provider_attempt_source(
                &egress_grant_id,
                &allocated,
                &runtime_binding,
                &task.id.0,
            )?;
            (source, allocated)
        };
        let direct_binding_publication = match direct_binding_publisher.publish_reserved(
            direct_lifecycle_reservation,
            &request.0,
            &runtime_binding,
            &direct_os_identity,
            &attempt_source,
        ) {
            Ok(publication) => publication,
            Err(error) => {
                let mut active = active_egress
                    .lock()
                    .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
                let run = active
                    .get_mut(&egress_grant_id)
                    .context("active_egress_run_missing_after_inbox_publish_failure")?;
                if run.journal_cas.record_sha256 != allocated_attempt_cas.record_sha256 {
                    bail!("active_egress_direct_attempt_cas_changed_during_inbox_publish");
                }
                run.durability = ActiveEgressDurability::DispatchBlockedCommitUnknown;
                return Err(error)
                    .context("direct_operation_binding_inbox_publication_failed_dispatch_denied");
            }
        };
        #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
        let mut direct_binding_publication = direct_binding_publication;
        #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
        let direct_tool_call_session = {
            let verified_high_water = DirectOperationCustodyStore::verify_product_high_water()
                .context("direct_operation_custody_high_water_unavailable_dispatch_denied")?;
            let mut store = DirectOperationCustodyStore::open_product(verified_high_water)
                .context("direct_operation_custody_store_open_failed_dispatch_denied")?;
            let expected = store.head();
            let custody_seed = direct_binding_publication.take_custody_seed()?;
            let publication = store
                .record_verified_inbox_publication(&expected, custody_seed)
                .context("direct_operation_binding_custody_commit_failed_dispatch_denied")?;
            let logical_delivery = VerifiedDaemonLogicalDelivery::from_p0_predispatch_publication(
                publication,
                trillionnium_os_types::direct_operation::DirectOperationAdapter::SystemApi,
            )
            .context("direct_operation_logical_delivery_admission_failed_dispatch_denied")?;
            let verified_allocator = DirectToolCallAllocator::open_p0_userdebug(
                direct_binding_publication.binding.clone(),
                trillionnium_os_types::direct_operation::DirectOperationAdapter::SystemApi,
                logical_delivery,
            )
            .context("direct_tool_call_allocator_p0_open_failed_dispatch_denied")?;
            let (listener, listener_cancellation) =
                FixedDirectToolCallListener::bind_p0_userdebug(store, verified_allocator)
                    .context("direct_tool_call_listener_p0_bind_failed_dispatch_denied")?;
            let authority_remaining_ms = capability_expires_at_ms
                .checked_sub(now_unix_ms())
                .context("direct_tool_call_listener_p0_authority_expired_before_bind")?;
            let invocation_timeout = Duration::from_millis(authority_remaining_ms)
                .min(P0_USERDEBUG_TOOL_INVOCATION_MAX_TIMEOUT);
            let invocation_deadline = Instant::now()
                .checked_add(invocation_timeout)
                .context("direct_tool_call_listener_p0_invocation_deadline_overflow")?;
            if provider_id != CODEX_PROVIDER_ID {
                bail!("p0_userdebug_direct_tool_call_provider_denied");
            }
            let listener_thread_name = "trillionnium-p0-codex-system-api";
            let session = std::thread::Builder::new()
                .name(listener_thread_name.to_string())
                .spawn(move || listener.serve_once_until(invocation_deadline))
                .context("direct_tool_call_listener_p0_thread_spawn_failed_dispatch_denied")?;
            P0UserdebugDirectToolCallSessionGuard {
                session: Some(session),
                cancellation: listener_cancellation,
            }
        };
        // Retain the publication's per-provider lifecycle guard until the
        // supervised provider and its observed adapter descendants terminate.
        // This remains daemon-side foundation: default/product tools do not
        // consume the inbox until kernel-owned cross-crash descendant custody
        // exists. No launch value enters model input, MCP JSON, environment, or
        // argv.
        let _direct_launch_expectation = &direct_binding_publication.launch;
        let _direct_hidden_binding = &direct_binding_publication.binding;
        {
            let active = active_egress
                .lock()
                .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
            let run = active
                .get(&egress_grant_id)
                .context("active_egress_run_missing_after_inbox_publication")?;
            if run.durability != ActiveEgressDurability::Running
                || run.journal_cas.record_sha256 != allocated_attempt_cas.record_sha256
            {
                bail!("active_egress_changed_before_provider_dispatch");
            }
        }
        ensure_active_egress_not_cancelled(service, &cancellation, &task.id.0)?;
        let provider_result =
            (|| -> Result<(ProviderPlanResult, CompletedShellExecAuthorizationV1)> {
                let authorized_attempt = codex.plan_attempt_with_cancellation(
                    &request.0,
                    _direct_hidden_binding,
                    Arc::clone(&cancellation.cancelled),
                )?;
                let receipt = verify_direct_provider_attempt(
                    egress_grants,
                    active_egress,
                    &egress_grant_id,
                    normalize_codex_direct_attempt(authorized_attempt.attempt),
                )?;
                Ok((
                    map_codex_direct_result(receipt)?,
                    authorized_attempt.authorization,
                ))
            })();
        #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
        let direct_tool_call_termination = direct_tool_call_session.finish()?;
        #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
        let direct_tool_call_outcome = match direct_tool_call_termination {
            P0UserdebugDirectToolCallSessionTermination::Completed(outcome) => Some(outcome),
            P0UserdebugDirectToolCallSessionTermination::CancelledBeforeTool(cancelled) => {
                cancelled.commit_no_dispatch()?;
                None
            }
        };
        #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
        let (provider_result, shell_exec_authorization) = match provider_result {
            Ok(value) => value,
            Err(error) if direct_tool_call_outcome.is_none() => {
                return Err(error).context("direct_provider_failed_after_listener_cancelled");
            }
            Err(error) => {
                return Err(error).context("direct_provider_failed_after_p0_system_api_commit");
            }
        };
        #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
        validate_p0_system_api_listener_reconciliation(
            &provider_result,
            _direct_hidden_binding,
            direct_tool_call_outcome
                .as_ref()
                .map(P0SystemApiListenerEvidence::from),
        )?;
        #[cfg(not(all(feature = "p0-launch-package-device-conformance", not(test))))]
        let (provider_result, shell_exec_authorization) = provider_result?;
        let authorized_adapter_set = direct_binding_publication
            .binding
            .authorized_adapter_set
            .clone();
        // Once validated terminal evidence proves a physical/indeterminate
        // effect, cancellation can stop further work but must not erase the
        // phone-facing receipt. No-action/refused paths still honor the latch.
        if !matches!(
            provider_result.direct_outcome,
            Some(ProviderDirectOutcome::Completed | ProviderDirectOutcome::Indeterminate)
        ) {
            ensure_active_egress_not_cancelled(service, &cancellation, &task.id.0)?;
        }
        enforce_live_agent_direct_result(
            action_consents,
            context_memory,
            request_id,
            provider_result.execution_mode,
        )?;
        validate_live_direct_provider_result(
            &provider_result,
            &provider_id,
            &registration,
            &authorized_adapter_set,
            _direct_hidden_binding,
            &shell_exec_authorization,
        )?;
        let provider_ready = ProviderReadySaga {
            schema: LOCAL_PLAN_SAGA_SCHEMA.to_string(),
            request_id: request_id.to_string(),
            request_payload_sha256: plan_request_payload_sha256.clone(),
            peer_uid,
            peer_domain: peer_domain.to_string(),
            provider_id: provider_id.clone(),
            workflow_id: workflow_id.clone(),
            task_id: task.id.0.clone(),
            registration: registration.clone(),
            agent_executable: DurableAgentExecutableIdentity::from(&agent_executable),
            agent_manifest_sha256: grant_binding.agent_manifest_sha256.clone(),
            runtime_lifecycle_binding_sha256: runtime_binding
                .digest_sha256()
                .map_err(anyhow::Error::msg)?,
            authorized_adapter_set: authorized_adapter_set.clone(),
            shell_exec_authorization: Some(shell_exec_authorization),
            context_id: context_id.clone(),
            context_expires_at_ms,
            source_id: source_id.as_str().to_string(),
            content: content.as_str().to_string(),
            content_sha256: content_sha256.clone(),
            provider_result: DurableProviderPlanResult {
                submission: provider_result.submission.clone(),
                execution_mode: provider_result.execution_mode,
                direct_outcome: provider_result.direct_outcome,
                direct_refusal_reason: provider_result.direct_refusal_reason.clone(),
                direct_tool_calls: provider_result.direct_tool_calls.clone(),
                summary: provider_result.summary.clone(),
                runtime_provider: provider_result.runtime_provider.clone(),
                model: provider_result.model.clone(),
                elapsed_ms: provider_result.elapsed_ms,
                provider_output_sha256: provider_result.provider_output_sha256.clone(),
            },
        };
        drop(direct_binding_publication);
        action_consents
            .lock()
            .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
            .transition(
                context_memory,
                request_id,
                PlanSagaStage::ProviderPending,
                workflow_binding.clone(),
                PlanSagaStage::ProviderReady,
                serde_json::to_value(&provider_ready)?,
            )?;
        if provider_result.execution_mode == ProviderExecutionMode::AgentDirect {
            ensure_active_egress_not_cancelled(service, &cancellation, &task.id.0)?;
            let response = direct_provider_response(&provider_ready)?;
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .publish_plan_ready(
                    context_memory,
                    request_id,
                    PlanReadyPublication {
                        expected_stage: PlanSagaStage::ProviderReady,
                        binding: workflow_binding,
                        local_state: serde_json::to_value(&provider_ready)?,
                        exact_plan_response: response.clone(),
                        challenge: None,
                    },
                )?;
            #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
            if let Some(direct_tool_call_outcome) = direct_tool_call_outcome {
                let candidate = action_consents
                    .lock()
                    .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                    .direct_plan_custody_candidate(
                        context_memory,
                        &direct_tool_call_outcome.delivery_binding,
                    )?
                    .context("p0_userdebug_direct_plan_custody_candidate_missing")?;
                let direct_ui = context_memory
                    .verified_direct_ui_replay_snapshot(&candidate)
                    .context("p0_userdebug_direct_ui_snapshot_denied")?;
                p0_userdebug_ack_hotpath = Some(P0UserdebugAckHotpath {
                    session: direct_tool_call_outcome,
                    allocation_egress_cas: allocated_attempt_cas.clone(),
                    direct_ui,
                });
            }
            return Ok(response);
        }
        // The historical plan/approval bridge remains test-only so old journal
        // vectors can be parsed and quarantined. It is not linked into the
        // production daemon and cannot produce an Authority receipt
        // expectation or action-consent challenge.
        #[cfg(test)]
        {
            let mut workflow_binding = workflow_binding;
            let execution_available = provider_result.submission.is_some();
            if !execution_available {
                ensure_active_egress_not_cancelled(service, &cancellation, &task.id.0)?;
                let provider_output_sha256 = provider_result.provider_output_sha256.clone();
                let response = json!({
                    "task_id": task.id.0,
                    "plan_id": "",
                    "read_only_planning_receipt_id": format!("planning-receipt-{provider_output_sha256}"),
                    "approval_id": "",
                    "action": "context_summary_read_only",
                    "summary": provider_result.summary,
                    "model": provider_result.model,
                    "provider_id": provider_id,
                    "provider": provider_result.runtime_provider,
                    "provider_output_sha256": provider_output_sha256,
                    "requires_approval": false,
                    "execution_available": false,
                    "execution_hold_reason": "context_acquisition_already_completed_no_honest_executor_side_effect",
                    "network_scope": "none",
                    "tool_execution_owned_by_os": true,
                    "model_executed_tools": false,
                    "plan_submitted_for_execution": false,
                    "plan_latency_ms": provider_result.elapsed_ms,
                    "egress_grant_consumed": true,
                });
                action_consents
                    .lock()
                    .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                    .publish_plan_ready(
                        context_memory,
                        request_id,
                        PlanReadyPublication {
                            expected_stage: PlanSagaStage::ProviderReady,
                            binding: workflow_binding,
                            local_state: serde_json::to_value(&provider_ready)?,
                            exact_plan_response: response.clone(),
                            challenge: None,
                        },
                    )?;
                return Ok(response);
            }
            let mut submission = provider_result
                .submission
                .context("executable provider result omitted AgentPlan")?;
            if submission.actions.len() != 1 || submission.contexts.len() != 1 {
                bail!("executable_provider_plan_shape_invalid");
            }
            let opaque_source_id = format!("context-ref:{}", sha256_bytes(source_id.as_bytes()));
            let context_ref = submission
                .contexts
                .first_mut()
                .context("provider plan omitted context reference")?;
            context_ref.context_id = context_id.clone();
            context_ref.source_id = opaque_source_id.clone();
            context_ref.content_sha256 = content_sha256.clone();
            let planned_action = submission
                .actions
                .first_mut()
                .context("provider plan omitted action")?;
            let action_contract = bounded_action_contract(&planned_action.tool_name)?;
            if planned_action.network_scope != action_contract.plan_network_scope
                || planned_action.undo_contract != action_contract.undo_contract
            {
                bail!("provider_action_contract_mismatch");
            }
            let action_summary = match planned_action.tool_name.as_str() {
                BROWSER_TOOL => {
                    "The built-in provider proposed the user-selected bounded browser action."
                }
                NOTIFICATION_TOOL => {
                    "The built-in provider proposed one exact Authority-owned bounded notification."
                }
                _ => unreachable!("bounded_action_contract rejected unsupported tool"),
            };
            planned_action.rationale = match planned_action.tool_name.as_str() {
                BROWSER_TOOL => "Provider proposed the user-selected bounded browser action.",
                NOTIFICATION_TOOL => {
                    "Provider proposed one exact Authority-owned bounded notification."
                }
                _ => unreachable!("bounded_action_contract rejected unsupported tool"),
            }
            .to_string();
            planned_action.undo_contract = action_contract.undo_contract.to_string();
            let arguments = planned_action
                .arguments
                .as_object_mut()
                .context("provider action arguments must be an object")?;
            if arguments.get("network_scope").and_then(Value::as_str)
                != Some(action_contract.argument_network_scope)
            {
                bail!("provider_action_argument_network_scope_mismatch");
            }
            arguments.insert("source_id".to_string(), json!(opaque_source_id));
            arguments.insert("context_sha256".to_string(), json!(content_sha256));
            let descriptor = match planned_action.tool_name.as_str() {
                BROWSER_TOOL => {
                    let descriptor = context_memory.describe_execution_payload(content.as_str())?;
                    arguments.insert(
                        "payload".to_string(),
                        json!({
                            "execution_payload_ref": descriptor.reference,
                            "execution_payload_sha256": descriptor.payload_sha256,
                            "execution_payload_shape": descriptor.shape,
                        }),
                    );
                    Some(descriptor)
                }
                NOTIFICATION_TOOL => {
                    validate_notification_action_payload(
                        arguments
                            .get("payload")
                            .context("provider notification action omitted payload")?,
                    )?;
                    None
                }
                _ => unreachable!("bounded_action_contract rejected unsupported tool"),
            };
            planned_action.arguments_sha256 = sha256_json(&planned_action.arguments);
            ensure_active_egress_not_cancelled(service, &cancellation, &task.id.0)?;
            workflow_binding.plan_id = submission.plan_id.clone();
            workflow_binding.action_id = planned_action.action_id.clone();
            let prepared = PlanPreparedSaga {
                provider: provider_ready.clone(),
                submission: submission.clone(),
                descriptor: descriptor
                    .as_ref()
                    .map(|value| DurableExecutionPayloadDescriptor {
                        reference: value.reference.clone(),
                        payload_sha256: value.payload_sha256.clone(),
                        shape: value.shape.clone(),
                    }),
                execution_payload_expires_at_ms: descriptor
                    .as_ref()
                    .map(|_| context_expires_at_ms.min(now.saturating_add(10 * 60 * 1_000))),
                action_summary: action_summary.to_string(),
            };
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .transition(
                    context_memory,
                    request_id,
                    PlanSagaStage::ProviderReady,
                    workflow_binding.clone(),
                    PlanSagaStage::PlanPrepared,
                    serde_json::to_value(&prepared)?,
                )?;
            let plan: AgentPlanSubmission =
                serde_json::from_value(dispatch_builtin_agent_state_change(
                    service,
                    &registration,
                    &agent_executable,
                    None,
                    "submit_plan",
                    serde_json::to_value(submission)?,
                )?)
                .context("built-in Agent API submit_plan returned an invalid plan")?;
            let submitted = PlanSubmittedSaga {
                prepared: prepared.clone(),
                plan: plan.clone(),
            };
            workflow_binding.accepted_plan_sha256 = sha256_json(&serde_json::to_value(&plan)?);
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .transition(
                    context_memory,
                    request_id,
                    PlanSagaStage::PlanPrepared,
                    workflow_binding.clone(),
                    PlanSagaStage::PlanSubmitted,
                    serde_json::to_value(&submitted)?,
                )?;
            let planned_action = plan
                .actions
                .first()
                .context("provider plan omitted action")?;
            let execution_request = AgentExecutionRequest {
                task_id: task.id.clone(),
                plan_id: plan.plan_id.clone(),
                action_id: planned_action.action_id.clone(),
            };
            let dispatch = dispatch_builtin_agent_state_change(
                service,
                &registration,
                &agent_executable,
                None,
                "run_tool",
                serde_json::to_value(execution_request)?,
            )?;
            ensure_active_egress_not_cancelled(service, &cancellation, &task.id.0)?;
            let approval_id = dispatch
                .get("approval")
                .and_then(|value| value.get("id"))
                .and_then(Value::as_str)
                .context("OS policy did not stop at approval")?
                .to_string();
            let execution_binding: AgentExecutionBinding = serde_json::from_value(
                dispatch
                    .get("execution_binding")
                    .cloned()
                    .context("planned action dispatch omitted execution binding")?,
            )
            .context("planned action dispatch returned an invalid execution binding")?;
            workflow_binding.tool_call_id = execution_binding.tool_call_id.0.clone();
            if workflow_binding.accepted_plan_sha256 != execution_binding.accepted_plan_sha256
                || workflow_binding.plan_id != execution_binding.plan_id
                || workflow_binding.action_id != execution_binding.action_id
            {
                bail!("local_plan_saga_dispatch_binding_mismatch");
            }
            let dispatched = ActionDispatchedSaga {
                submitted: submitted.clone(),
                execution_binding: execution_binding.clone(),
                approval_id: approval_id.clone(),
            };
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .transition(
                    context_memory,
                    request_id,
                    PlanSagaStage::PlanSubmitted,
                    workflow_binding.clone(),
                    PlanSagaStage::ActionDispatched,
                    serde_json::to_value(&dispatched)?,
                )?;
            if let Some(descriptor) = descriptor.as_ref() {
                context_memory.stage_execution_payload(
                    descriptor,
                    ExecutionPayloadBinding {
                        owner_uid: execution_binding.origin_uid,
                        owner_selinux_domain: execution_binding.origin_selinux_domain.clone(),
                        subject_user_id: execution_binding.subject_user_id,
                        agent_id: execution_binding.agent_id.clone(),
                        agent_peer_uid: execution_binding.peer_uid,
                        agent_peer_gid: execution_binding.peer_gid,
                        agent_selinux_domain: execution_binding.peer_selinux_domain.clone(),
                        agent_executable_sha256: execution_binding.agent_executable_sha256.clone(),
                        task_id: execution_binding.task_id.0.clone(),
                        session_id: execution_binding.session_id.clone(),
                        plan_id: execution_binding.plan_id.clone(),
                        action_id: execution_binding.action_id.clone(),
                        tool_call_id: execution_binding.tool_call_id.0.clone(),
                        tool_name: execution_binding.tool_name.clone(),
                        tool_manifest_sha256: execution_binding.tool_manifest_sha256.clone(),
                        accepted_plan_sha256: execution_binding.accepted_plan_sha256.clone(),
                        context_sha256: content_sha256.clone(),
                        arguments_sha256: execution_binding.arguments_sha256.clone(),
                        expires_at_ms: prepared
                            .execution_payload_expires_at_ms
                            .context("browser execution payload expiry disappeared")?,
                    },
                    content.as_str(),
                )?;
            }
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .transition(
                    context_memory,
                    request_id,
                    PlanSagaStage::ActionDispatched,
                    workflow_binding.clone(),
                    PlanSagaStage::PayloadStaged,
                    serde_json::to_value(&dispatched)?,
                )?;
            let frozen_arguments = planned_action
                .arguments
                .as_object()
                .context("frozen Android action arguments must be an object")?;
            let authority_request_id = frozen_arguments
                .get("request_id")
                .and_then(Value::as_str)
                .context("frozen Android action omitted request_id")?;
            let source_id = frozen_arguments
                .get("source_id")
                .and_then(Value::as_str)
                .context("frozen Android action omitted source_id")?;
            let frozen_context_sha256 = frozen_arguments
                .get("context_sha256")
                .and_then(Value::as_str)
                .context("frozen Android action omitted context_sha256")?;
            let plan_sha256 = frozen_arguments
                .get("plan_sha256")
                .and_then(Value::as_str)
                .context("frozen Android action omitted plan_sha256")?;
            let frozen_provider_output_sha256 = frozen_arguments
                .get("provider_output_sha256")
                .and_then(Value::as_str)
                .context("frozen Android action omitted provider_output_sha256")?;
            let approval_nonce = frozen_arguments
                .get("approval_nonce")
                .and_then(Value::as_str)
                .context("frozen Android action omitted approval_nonce")?;
            let requested_network_scope = frozen_arguments
                .get("network_scope")
                .and_then(Value::as_str)
                .context("frozen Android action omitted network_scope")?;
            let frozen_payload = frozen_arguments
                .get("payload")
                .context("frozen Android action omitted payload")?;
            let action_contract = bounded_action_contract(&planned_action.tool_name)?;
            let (action_payload, execution_payload_sha256) = match planned_action.tool_name.as_str()
            {
                BROWSER_TOOL => {
                    let descriptor = descriptor
                        .as_ref()
                        .context("browser execution payload descriptor disappeared")?;
                    let payload_sha256 = frozen_payload
                        .get("execution_payload_sha256")
                        .and_then(Value::as_str)
                        .context("frozen browser action omitted execution payload digest")?;
                    if payload_sha256 != descriptor.payload_sha256 {
                        bail!("frozen browser action execution payload digest mismatch");
                    }
                    (json!({"url": content.as_str()}), payload_sha256.to_string())
                }
                NOTIFICATION_TOOL => {
                    if descriptor.is_some() {
                        bail!("notification action unexpectedly staged an execution payload");
                    }
                    validate_notification_action_payload(frozen_payload)?;
                    (frozen_payload.clone(), sha256_json(frozen_payload))
                }
                _ => unreachable!("bounded_action_contract rejected unsupported tool"),
            };
            validate_action_payload_binding(
                &planned_action.tool_name,
                &action_payload,
                &execution_payload_sha256,
            )?;
            if requested_network_scope != action_contract.argument_network_scope
                || frozen_context_sha256 != content_sha256
                || frozen_provider_output_sha256 != plan.provider_output_sha256
                || execution_binding.tool_name != planned_action.tool_name
                || execution_binding.arguments_sha256 != planned_action.arguments_sha256
                || planned_action.network_scope != action_contract.plan_network_scope
                || planned_action.undo_contract != action_contract.undo_contract
            {
                bail!("frozen Android action receipt expectation mismatch");
            }
            let receipt_expectation = json!({
                "schema": "trillionnium.authority-receipt-expectation.v1",
                "request_id": authority_request_id,
                "agent_id": execution_binding.agent_id,
                "peer_uid": execution_binding.peer_uid,
                "peer_gid": execution_binding.peer_gid,
                "peer_selinux_domain": execution_binding.peer_selinux_domain,
                "agent_executable_sha256": execution_binding.agent_executable_sha256,
                "origin_selinux_domain": execution_binding.origin_selinux_domain,
                "session_id": execution_binding.session_id,
                "subject_user_id": execution_binding.subject_user_id,
                "origin_uid": execution_binding.origin_uid,
                "task_id": execution_binding.task_id.0,
                "plan_id": execution_binding.plan_id,
                "action_id": execution_binding.action_id,
                "tool_call_id": execution_binding.tool_call_id.0,
                "arguments_sha256": execution_binding.arguments_sha256,
                "tool_manifest_sha256": execution_binding.tool_manifest_sha256,
                "accepted_plan_sha256": execution_binding.accepted_plan_sha256,
                "arguments_canonicalization": "serde-json-utf8-lexicographic-v1-no-floats",
                "tool_name": planned_action.tool_name,
                "action": action_contract.action,
                "source_id": source_id,
                "context_sha256": frozen_context_sha256,
                "params_sha256": planned_action.arguments_sha256,
                "payload_sha256": execution_payload_sha256,
                "plan_sha256": plan_sha256,
                "provider_output_sha256": frozen_provider_output_sha256,
                "provider_id": format!("{}/rootlinux-gateway", execution_binding.agent_id),
                "target_generative_model": false,
                "approval_nonce_sha256": sha256_bytes(approval_nonce.as_bytes()),
                "network_scope": action_contract.receipt_network_scope,
                "caller_uid": 0,
                "user_id": execution_binding.subject_user_id,
                "explicit_approval": true,
                "single_use_capability_consumed": true,
                "executor_package": "org.trillionnium.aiauthority",
                "undo": false,
                "undo_supported": action_contract.undo_supported,
            });
            let approval = service
                .get_approval_local(&approval_id)
                .map_err(anyhow::Error::msg)?
                .context("OS policy approval disappeared before consent challenge")?;
            let action_consent_challenge = build_action_consent_challenge(
                &execution_binding,
                &approval,
                &workflow_id,
                &sha256_bytes(approval_nonce.as_bytes()),
                frozen_context_sha256,
                &action_payload,
                &execution_payload_sha256,
                now_unix_ms(),
            )?;
            let action_consent_challenge_json = serde_json::to_string(&action_consent_challenge)?;
            ensure_active_egress_not_cancelled(service, &cancellation, &task.id.0)?;
            workflow_binding.challenge_sha256 =
                sha256_bytes(&serde_json::to_vec(&action_consent_challenge)?);
            workflow_binding.challenge_expires_at_ms = action_consent_challenge
                .get("expires_at_ms")
                .and_then(Value::as_u64)
                .context("action_consent_challenge_expiry_missing")?;
            let response = json!({
                "task_id": task.id.0,
                "plan_id": plan.plan_id,
                "approval_id": approval_id,
                "action": action_contract.action,
                "tool_name": planned_action.tool_name,
                "receipt_expectation": receipt_expectation,
                "action_consent_challenge": action_consent_challenge,
                "action_consent_challenge_json": action_consent_challenge_json,
                "summary": action_summary,
                "model": provider_result.model,
                "provider_id": provider_id,
                "provider": provider_result.runtime_provider,
                "provider_output_sha256": plan.provider_output_sha256,
                "requires_approval": true,
                "execution_available": true,
                "network_scope": planned_action.network_scope,
                "tool_execution_owned_by_os": true,
                "model_executed_tools": false,
                "plan_latency_ms": provider_result.elapsed_ms,
                "egress_grant_consumed": true,
            });
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .publish_plan_ready(
                    context_memory,
                    request_id,
                    PlanReadyPublication {
                        expected_stage: PlanSagaStage::PayloadStaged,
                        binding: workflow_binding,
                        local_state: serde_json::to_value(&dispatched)?,
                        exact_plan_response: response.clone(),
                        challenge: Some(action_consent_challenge),
                    },
                )?;
            Ok(response)
        }
        #[cfg(not(test))]
        unreachable!("direct-only provider validation returned a legacy mode")
    })();
    #[cfg(all(feature = "p0-launch-package-device-conformance", not(test)))]
    if let Some(hotpath) = p0_userdebug_ack_hotpath {
        let (response, terminal_egress) = active_guard.finish_p0_userdebug(
            outcome,
            &hotpath.allocation_egress_cas,
            &hotpath.session.delivery_binding,
        )?;
        let ack_hotpath_sha256 = hotpath
            .session
            .custody_store
            .complete_p0_userdebug_ack_hotpath(
                hotpath.session.delivery_binding,
                hotpath.session.allocation_binding,
                terminal_egress,
                hotpath.direct_ui,
            )?;
        if !valid_lower_sha256(&ack_hotpath_sha256) {
            bail!("p0_userdebug_ack_hotpath_receipt_denied");
        }
        return Ok(response);
    }
    active_guard.finish(outcome)
}

#[cfg(test)]
#[allow(dead_code)]
fn prepare_provider_ready_saga(
    context_memory: &ContextMemoryService,
    provider: ProviderReadySaga,
) -> Result<PlanPreparedSaga> {
    if provider.schema != LOCAL_PLAN_SAGA_SCHEMA
        || provider.request_id.is_empty()
        || !valid_lower_sha256(&provider.request_payload_sha256)
        || provider.peer_uid >= ANDROID_UID_PER_USER_RANGE
        || provider.peer_domain.is_empty()
        || agent_principal_registry::from_provider_id(&provider.provider_id).is_none()
        || provider.task_id.is_empty()
        || provider.registration.peer_uid == 0
        || provider.registration.peer_gid == 0
        || provider.content_sha256 != sha256_bytes(provider.content.as_bytes())
        || provider.provider_result.provider_output_sha256.len() != 64
    {
        bail!("invalid_provider_ready_local_saga");
    }
    let mut submission = provider
        .provider_result
        .submission
        .clone()
        .context("read_only_provider_result_has_no_local_action_saga")?;
    if submission.task_id.0 != provider.task_id
        || submission.agent_id != provider.registration.agent_id
        || submission.actions.len() != 1
        || submission.contexts.len() != 1
    {
        bail!("executable_provider_plan_shape_invalid");
    }
    let opaque_source_id = format!(
        "context-ref:{}",
        sha256_bytes(provider.source_id.as_bytes())
    );
    let context_ref = submission
        .contexts
        .first_mut()
        .context("provider plan omitted context reference")?;
    context_ref.context_id = provider.context_id.clone();
    context_ref.source_id = opaque_source_id.clone();
    context_ref.content_sha256 = provider.content_sha256.clone();
    let planned_action = submission
        .actions
        .first_mut()
        .context("provider plan omitted action")?;
    let action_contract = bounded_action_contract(&planned_action.tool_name)?;
    if planned_action.network_scope != action_contract.plan_network_scope
        || planned_action.undo_contract != action_contract.undo_contract
    {
        bail!("provider_action_contract_mismatch");
    }
    let action_summary = match planned_action.tool_name.as_str() {
        BROWSER_TOOL => "The built-in provider proposed the user-selected bounded browser action.",
        NOTIFICATION_TOOL => {
            "The built-in provider proposed one exact Authority-owned bounded notification."
        }
        _ => unreachable!("bounded_action_contract rejected unsupported tool"),
    }
    .to_string();
    planned_action.rationale = match planned_action.tool_name.as_str() {
        BROWSER_TOOL => "Provider proposed the user-selected bounded browser action.",
        NOTIFICATION_TOOL => "Provider proposed one exact Authority-owned bounded notification.",
        _ => unreachable!("bounded_action_contract rejected unsupported tool"),
    }
    .to_string();
    planned_action.undo_contract = action_contract.undo_contract.to_string();
    let arguments = planned_action
        .arguments
        .as_object_mut()
        .context("provider action arguments must be an object")?;
    if arguments.get("network_scope").and_then(Value::as_str)
        != Some(action_contract.argument_network_scope)
    {
        bail!("provider_action_argument_network_scope_mismatch");
    }
    arguments.insert("source_id".to_string(), json!(opaque_source_id));
    arguments.insert("context_sha256".to_string(), json!(provider.content_sha256));
    let descriptor = match planned_action.tool_name.as_str() {
        BROWSER_TOOL => {
            let descriptor = context_memory.describe_execution_payload(&provider.content)?;
            arguments.insert(
                "payload".to_string(),
                json!({
                    "execution_payload_ref": descriptor.reference,
                    "execution_payload_sha256": descriptor.payload_sha256,
                    "execution_payload_shape": descriptor.shape,
                }),
            );
            Some(DurableExecutionPayloadDescriptor {
                reference: descriptor.reference,
                payload_sha256: descriptor.payload_sha256,
                shape: descriptor.shape,
            })
        }
        NOTIFICATION_TOOL => {
            validate_notification_action_payload(
                arguments
                    .get("payload")
                    .context("provider notification action omitted payload")?,
            )?;
            None
        }
        _ => unreachable!("bounded_action_contract rejected unsupported tool"),
    };
    planned_action.arguments_sha256 = sha256_json(&planned_action.arguments);
    let execution_payload_expires_at_ms = descriptor.as_ref().map(|_| {
        provider
            .context_expires_at_ms
            .min(now_unix_ms().saturating_add(10 * 60 * 1_000))
    });
    Ok(PlanPreparedSaga {
        provider,
        submission,
        descriptor,
        execution_payload_expires_at_ms,
        action_summary,
    })
}

struct DirectProviderMaterial<'a> {
    provider_id: &'a str,
    execution_mode: ProviderExecutionMode,
    submission: Option<&'a AgentPlanSubmission>,
    direct_outcome: Option<ProviderDirectOutcome>,
    direct_refusal_reason: Option<&'a str>,
    direct_tool_calls: &'a [CodexDirectToolCallEvidence],
    provider_output_sha256: &'a str,
    registration: &'a AgentRegistration,
}

fn validate_direct_provider_material(material: DirectProviderMaterial<'_>) -> Result<()> {
    let DirectProviderMaterial {
        provider_id,
        execution_mode,
        submission,
        direct_outcome,
        direct_refusal_reason,
        direct_tool_calls,
        provider_output_sha256,
        registration,
    } = material;
    if !valid_lower_sha256(provider_output_sha256) {
        bail!("invalid_direct_provider_output_digest");
    }
    if execution_mode != ProviderExecutionMode::AgentDirect {
        bail!(RETIRED_NON_DIRECT_WORKFLOW_REASON);
    }
    if submission.is_some() {
        bail!("agent_direct_result_must_not_include_legacy_submission");
    }
    let descriptor = agent_principal_registry::from_provider_id(provider_id)
        .ok_or_else(|| anyhow::anyhow!("unsupported_direct_provider"))?;
    if !crate::builtin_provider_identity::matches_stable_registration(descriptor, registration) {
        bail!("direct_provider_registration_identity_mismatch");
    }
    let (completed_calls, indeterminate_calls) = match provider_id {
        CODEX_PROVIDER_ID => {
            if direct_tool_calls.len() > 4_096 {
                bail!("codex_direct_evidence_shape_invalid");
            }
            let mut completed_calls = 0_u64;
            let mut indeterminate_calls = 0_u64;
            for (sequence, call) in direct_tool_calls.iter().enumerate() {
                let identity_valid = matches!(
                    (call.server.as_str(), call.tool.as_str()),
                    ("trillionnium_system_api", "trillionnium_system_api")
                        | ("trillionnium_shell_exec", "trillionnium_shell_exec")
                );
                if !identity_valid
                    || call.sequence != sequence
                    || !valid_lower_sha256(&call.canonical_request_sha256)
                    || !valid_lower_sha256(&call.backend_request_id_sha256)
                    || !valid_lower_sha256(&call.backend_result_sha256)
                    || !valid_lower_sha256(&call.event_payload_sha256)
                {
                    bail!("codex_direct_evidence_binding_invalid");
                }
                match call.outcome.as_str() {
                    "success"
                        if call.status == "completed" && call.backend_error_code.is_none() =>
                    {
                        completed_calls = completed_calls.saturating_add(1);
                    }
                    "backend_error"
                        if call.status == "failed" && call.backend_error_code.is_some() =>
                    {
                        let code = call.backend_error_code.as_deref().unwrap();
                        match direct_backend_error_effect_class(&call.server, code) {
                            Some(DirectBackendEffectClass::DefinitelyNoEffect) => {}
                            Some(DirectBackendEffectClass::Indeterminate) => {
                                indeterminate_calls = indeterminate_calls.saturating_add(1);
                            }
                            Some(DirectBackendEffectClass::DefinitiveTerminal) | None => {
                                bail!("codex_direct_backend_error_unclassified")
                            }
                        }
                    }
                    "terminal_error"
                        if call.status == "failed"
                            && call.backend_error_code.as_deref().is_some_and(|code| {
                                direct_backend_error_effect_class(&call.server, code)
                                    == Some(DirectBackendEffectClass::DefinitiveTerminal)
                            }) =>
                    {
                        completed_calls = completed_calls.saturating_add(1);
                    }
                    "indeterminate"
                        if call.status == "failed"
                            && call.backend_error_code.as_deref().is_some_and(|code| {
                                direct_backend_error_effect_class(&call.server, code)
                                    == Some(DirectBackendEffectClass::Indeterminate)
                            }) =>
                    {
                        indeterminate_calls = indeterminate_calls.saturating_add(1);
                    }
                    _ => bail!("codex_direct_evidence_outcome_invalid"),
                }
            }
            (completed_calls, indeterminate_calls)
        }
        _ => bail!("unsupported_direct_provider"),
    };
    match direct_outcome.context("agent_direct_result_omitted_outcome")? {
        ProviderDirectOutcome::Completed => {
            if completed_calls == 0 || indeterminate_calls != 0 || direct_refusal_reason.is_some() {
                bail!("completed_direct_result_has_no_successful_tool_call");
            }
        }
        ProviderDirectOutcome::NoAction => {
            if completed_calls != 0 || indeterminate_calls != 0 || direct_refusal_reason.is_some() {
                bail!("no_action_direct_result_contains_execution_or_refusal");
            }
        }
        ProviderDirectOutcome::Indeterminate => {
            if indeterminate_calls == 0 || direct_refusal_reason.is_some() {
                bail!("indeterminate_direct_result_has_no_indeterminate_call");
            }
        }
        ProviderDirectOutcome::Refused => {
            let reason = direct_refusal_reason.context("direct_refusal_reason_missing")?;
            if completed_calls != 0
                || indeterminate_calls != 0
                || reason.trim().is_empty()
                || reason.len() > 4_096
                || reason.chars().any(char::is_control)
            {
                bail!("direct_refusal_contract_invalid");
            }
        }
    }
    Ok(())
}

fn validate_live_direct_provider_result(
    result: &ProviderPlanResult,
    provider_id: &str,
    registration: &AgentRegistration,
    authorized_adapter_set: &DirectOperationAuthorizedAdapterSetV3,
    direct_binding: &trillionnium_os_types::direct_operation::DirectOperationBinding,
    shell_exec_authorization: &CompletedShellExecAuthorizationV1,
) -> Result<()> {
    validate_direct_provider_material(DirectProviderMaterial {
        provider_id,
        execution_mode: result.execution_mode,
        submission: result.submission.as_ref(),
        direct_outcome: result.direct_outcome,
        direct_refusal_reason: result.direct_refusal_reason.as_deref(),
        direct_tool_calls: &result.direct_tool_calls,
        provider_output_sha256: &result.provider_output_sha256,
        registration,
    })?;
    validate_completed_shell_exec_authorization_for_binding(
        shell_exec_authorization,
        direct_binding,
    )?;
    validate_direct_provider_authorized_tool_set(
        provider_id,
        &result.direct_tool_calls,
        authorized_adapter_set,
        Some(shell_exec_authorization),
    )
}

fn validate_completed_shell_exec_authorization_for_binding(
    authorization: &CompletedShellExecAuthorizationV1,
    direct_binding: &trillionnium_os_types::direct_operation::DirectOperationBinding,
) -> Result<()> {
    authorization.validate()?;
    direct_binding
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if authorization.registration.binding != *direct_binding
        || authorization.registration.binding_sha256
            != direct_binding
                .digest_sha256()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
    {
        bail!("shell_exec_authorization_not_bound_to_live_direct_operation");
    }
    Ok(())
}

fn validate_completed_shell_exec_authorization_for_provider(
    provider: &ProviderReadySaga,
) -> Result<()> {
    let Some(authorization) = provider.shell_exec_authorization.as_ref() else {
        if provider
            .provider_result
            .direct_tool_calls
            .iter()
            .any(|call| call.server == "trillionnium_shell_exec")
        {
            bail!("shell_exec_evidence_missing_durable_authorization");
        }
        // Historical v3 records before shell authorization was introduced are
        // replayable only when they contain no shell evidence.
        return Ok(());
    };
    authorization.validate()?;
    let binding = &authorization.registration.binding;
    let expected_session_sha256 = sha256_bytes(
        format!("android-ui-{}-{}", provider.peer_uid, provider.workflow_id).as_bytes(),
    );
    if authorization.registration.binding_sha256
        != binding
            .digest_sha256()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
        || binding.stable_seed.provider_id != provider.provider_id
        || binding.stable_seed.agent_id != provider.registration.agent_id
        || binding.stable_seed.task_id != provider.task_id
        || binding.stable_seed.provider_invocation_id_sha256
            != sha256_bytes(provider.request_id.as_bytes())
        || binding.stable_seed.provider_session_id_sha256 != expected_session_sha256
        || binding.stable_seed.subject_uid != provider.peer_uid
        || binding.stable_seed.subject_selinux_domain_sha256
            != sha256_bytes(provider.peer_domain.as_bytes())
        || binding.workflow_id_sha256 != sha256_bytes(provider.workflow_id.as_bytes())
        || binding.agent_identity_key_sha256 != provider.registration.identity_key_sha256
        || binding.agent_executable_sha256 != provider.agent_executable.sha256
        || binding.authorized_adapter_set != provider.authorized_adapter_set
        || binding.attempt.runtime_lifecycle_binding_sha256
            != provider.runtime_lifecycle_binding_sha256
    {
        bail!("shell_exec_authorization_provider_round_binding_invalid");
    }
    Ok(())
}

fn validate_direct_provider_authorized_tool_set(
    provider_id: &str,
    direct_tool_calls: &[CodexDirectToolCallEvidence],
    authorized_adapter_set: &DirectOperationAuthorizedAdapterSetV3,
    shell_exec_authorization: Option<&CompletedShellExecAuthorizationV1>,
) -> Result<()> {
    #[cfg(feature = "p0-launch-package-device-conformance")]
    authorized_adapter_set
        .validate_p0_system_api()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    #[cfg(not(feature = "p0-launch-package-device-conformance"))]
    authorized_adapter_set
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let authorized = |server: &str, tool: &str| {
        if !codex_direct_mcp_identity_is_authorized(server, tool) {
            return false;
        }
        match server {
            "trillionnium_system_api" => {
                authorized_adapter_set.authorizes(DirectOperationAdapter::SystemApi)
            }
            "trillionnium_shell_exec" => shell_exec_authorization.is_some(),
            _ => false,
        }
    };
    let tool_set_matches_binding = match provider_id {
        CODEX_PROVIDER_ID => direct_tool_calls
            .iter()
            .all(|call| authorized(&call.server, &call.tool)),
        _ => false,
    };
    if !tool_set_matches_binding {
        bail!("direct_provider_tool_set_exceeds_root_binding");
    }
    Ok(())
}

fn validate_direct_provider_ready(provider: &ProviderReadySaga) -> Result<()> {
    let result = &provider.provider_result;
    validate_direct_provider_material(DirectProviderMaterial {
        provider_id: &provider.provider_id,
        execution_mode: result.execution_mode,
        submission: result.submission.as_ref(),
        direct_outcome: result.direct_outcome,
        direct_refusal_reason: result.direct_refusal_reason.as_deref(),
        direct_tool_calls: &result.direct_tool_calls,
        provider_output_sha256: &result.provider_output_sha256,
        registration: &provider.registration,
    })?;
    if provider.schema != LOCAL_PLAN_SAGA_SCHEMA
        || provider.request_id.is_empty()
        || !valid_lower_sha256(&provider.request_payload_sha256)
        || provider.workflow_id.is_empty()
        || provider.task_id.is_empty()
        || provider.peer_uid >= ANDROID_UID_PER_USER_RANGE
        || provider.peer_domain.is_empty()
        || !valid_lower_sha256(&provider.agent_manifest_sha256)
        || provider.agent_manifest_sha256
            != sha256_json(&serde_json::to_value(&provider.registration)?)
        || provider.agent_executable.sha256 != provider.registration.identity_key_sha256
        || !valid_lower_sha256(&provider.runtime_lifecycle_binding_sha256)
    {
        bail!("direct_provider_ready_binding_invalid");
    }
    validate_completed_shell_exec_authorization_for_provider(provider)?;
    validate_direct_provider_authorized_tool_set(
        &provider.provider_id,
        &result.direct_tool_calls,
        &provider.authorized_adapter_set,
        provider.shell_exec_authorization.as_ref(),
    )?;
    Ok(())
}

fn direct_provider_response(provider: &ProviderReadySaga) -> Result<Value> {
    let result = &provider.provider_result;
    validate_direct_provider_ready(provider)?;
    let direct_outcome = result
        .direct_outcome
        .context("validated direct result omitted outcome")?;
    let direct_refusal_sha256 = result
        .direct_refusal_reason
        .as_ref()
        .map(|reason| sha256_bytes(reason.as_bytes()));
    let execution_completed = direct_outcome == ProviderDirectOutcome::Completed;
    let execution_available = matches!(
        direct_outcome,
        ProviderDirectOutcome::Completed | ProviderDirectOutcome::NoAction
    );
    let provider_output_sha256 = &result.provider_output_sha256;
    let direct_tool_call_events = result.direct_tool_calls.len() as u64;
    let completed_direct_tool_calls = result
        .direct_tool_calls
        .iter()
        .filter(|call| direct_call_is_completed(call))
        .count() as u64;
    let indeterminate_direct_tool_calls = result
        .direct_tool_calls
        .iter()
        .filter(|call| {
            call.backend_error_code.as_deref().is_some_and(|code| {
                direct_backend_error_effect_class(&call.server, code)
                    == Some(DirectBackendEffectClass::Indeterminate)
            })
        })
        .count() as u64;
    let model_executed_tools = if completed_direct_tool_calls > 0 {
        Value::Bool(true)
    } else if indeterminate_direct_tool_calls > 0 {
        Value::Null
    } else {
        Value::Bool(false)
    };
    let mut direct_tool_names = result
        .direct_tool_calls
        .iter()
        .map(|call| call.server.clone())
        .collect::<Vec<_>>();
    direct_tool_names.sort();
    direct_tool_names.dedup();
    let direct_evidence_sha256 = sha256_json(&json!({
        "schema": "trillionnium.agent-direct-evidence.v2",
        "tool_calls": result.direct_tool_calls,
    }));
    let direct_call_evidence = serde_json::to_value(&result.direct_tool_calls)?;
    let shell_exec_authorization_sha256 = provider
        .shell_exec_authorization
        .as_ref()
        .map(CompletedShellExecAuthorizationV1::digest_sha256)
        .transpose()?;
    let shell_exec_direct_binding_sha256 = provider
        .shell_exec_authorization
        .as_ref()
        .map(|authorization| authorization.registration.binding_sha256.clone());
    let mut direct_receipt_commitment = json!({
        "schema": direct_agent_host_abi::DIRECT_RECEIPT_SCHEMA,
        "direct_agent_host_abi": direct_agent_host_abi::ABI_SCHEMA,
        "direct_agent_host_abi_sha256": direct_agent_host_abi::CONTRACT_SHA256,
        "direct_result_schema": direct_agent_host_abi::DIRECT_RESULT_SCHEMA,
        "request_id_sha256": sha256_bytes(provider.request_id.as_bytes()),
        "request_payload_sha256": provider.request_payload_sha256,
        "subject_uid": provider.peer_uid,
        "subject_selinux_domain_sha256": sha256_bytes(provider.peer_domain.as_bytes()),
        "provider_id": provider.provider_id,
        "workflow_id_sha256": sha256_bytes(provider.workflow_id.as_bytes()),
        "task_id": provider.task_id,
        "agent_id": provider.registration.agent_id,
        "agent_manifest_sha256": provider.agent_manifest_sha256,
        "agent_executable_sha256": provider.agent_executable.sha256,
        "runtime_lifecycle_binding_sha256": provider.runtime_lifecycle_binding_sha256,
        "runtime_provider": result.runtime_provider,
        "model": result.model,
        "summary_sha256": sha256_bytes(result.summary.as_bytes()),
        "provider_output_sha256": provider_output_sha256,
        "direct_evidence_sha256": direct_evidence_sha256,
        "direct_call_evidence": direct_call_evidence,
        "direct_outcome": direct_outcome.as_str(),
        "direct_refusal_sha256": direct_refusal_sha256,
        "direct_tool_call_events": direct_tool_call_events,
        "completed_direct_tool_calls": completed_direct_tool_calls,
        "direct_tool_names": direct_tool_names,
        "shell_exec_authorization_sha256": shell_exec_authorization_sha256,
        "shell_exec_direct_binding_sha256": shell_exec_direct_binding_sha256,
    });
    crate::action_workflow::bind_build_local_direct_receipt_commitment(
        &mut direct_receipt_commitment,
    );
    let direct_receipt_sha256 = sha256_json(&direct_receipt_commitment);
    let mut response = json!({
        "task_id": provider.task_id,
        "direct_execution_receipt_id": format!("direct-receipt-{direct_receipt_sha256}"),
        "direct_execution_receipt_sha256": direct_receipt_sha256,
        "direct_receipt_commitment": direct_receipt_commitment,
        "plan_id": "",
        "approval_id": "",
        "action": "agent_direct_result",
        "summary": result.summary,
        "model": result.model,
        "provider_id": provider.provider_id,
        "provider": result.runtime_provider,
        "provider_output_sha256": provider_output_sha256,
        "agent_id": provider.registration.agent_id,
        "agent_manifest_sha256": provider.agent_manifest_sha256,
        "agent_executable_sha256": provider.agent_executable.sha256,
        "runtime_lifecycle_binding_sha256": provider.runtime_lifecycle_binding_sha256,
        "request_payload_sha256": provider.request_payload_sha256,
        "workflow_id_sha256": sha256_bytes(provider.workflow_id.as_bytes()),
        "direct_evidence_sha256": direct_evidence_sha256,
        "direct_call_evidence": direct_call_evidence,
        "direct_outcome": direct_outcome.as_str(),
        "direct_refusal_reason": result.direct_refusal_reason,
        "direct_refusal_sha256": direct_refusal_sha256,
        "execution_mode": "agent_direct",
        "requires_approval": false,
        "execution_available": execution_available,
        "execution_completed": execution_completed,
        "network_scope": "provider_egress_only",
        "model_invoked_tools": direct_tool_call_events > 0,
        "model_executed_tools": model_executed_tools,
        "direct_tool_call_events": direct_tool_call_events,
        "completed_direct_tool_calls": completed_direct_tool_calls,
        "direct_tool_names": direct_tool_names,
        "plan_submitted_for_execution": false,
        "authority_called": false,
        "plan_latency_ms": result.elapsed_ms,
        "egress_grant_consumed": true,
    });
    direct_agent_host_abi::bind_direct_result_contract(
        response
            .as_object_mut()
            .expect("direct result construction produces an object"),
    );
    Ok(response)
}

#[cfg(test)]
#[allow(dead_code)]
fn read_only_provider_response(provider: &ProviderReadySaga) -> Result<Value> {
    if provider.provider_result.execution_mode != ProviderExecutionMode::LegacyPlan
        || provider.provider_result.submission.is_some()
    {
        bail!("executable_provider_result_is_not_read_only");
    }
    let provider_output_sha256 = &provider.provider_result.provider_output_sha256;
    if !valid_lower_sha256(provider_output_sha256) {
        bail!("invalid_read_only_provider_output_digest");
    }
    Ok(json!({
        "task_id": provider.task_id,
        "plan_id": "",
        "read_only_planning_receipt_id": format!("planning-receipt-{provider_output_sha256}"),
        "approval_id": "",
        "action": "context_summary_read_only",
        "summary": provider.provider_result.summary,
        "model": provider.provider_result.model,
        "provider_id": provider.provider_id,
        "provider": provider.provider_result.runtime_provider,
        "provider_output_sha256": provider_output_sha256,
        "requires_approval": false,
        "execution_available": false,
        "execution_hold_reason": "context_acquisition_already_completed_no_honest_executor_side_effect",
        "network_scope": "none",
        "tool_execution_owned_by_os": true,
        "model_executed_tools": false,
        "plan_submitted_for_execution": false,
        "plan_latency_ms": provider.provider_result.elapsed_ms,
        "egress_grant_consumed": true,
    }))
}

#[cfg(test)]
fn durable_descriptor(value: &DurableExecutionPayloadDescriptor) -> ExecutionPayloadDescriptor {
    ExecutionPayloadDescriptor {
        reference: value.reference.clone(),
        payload_sha256: value.payload_sha256.clone(),
        shape: value.shape.clone(),
    }
}

#[cfg(test)]
fn submit_prepared_saga(
    service: &AgentService,
    prepared: PlanPreparedSaga,
) -> Result<PlanSubmittedSaga> {
    let agent_executable = prepared.provider.agent_executable.dispatch_identity();
    let plan = match service
        .get_agent_plan_local(&prepared.submission.plan_id)
        .map_err(anyhow::Error::msg)?
    {
        Some(existing) => {
            if !accepted_plan_matches_prepared_submission(&existing, &prepared.submission) {
                bail!("durable_plan_submission_binding_mismatch");
            }
            existing
        }
        None => {
            let accepted: AgentPlanSubmission =
                serde_json::from_value(dispatch_builtin_agent_state_change(
                    service,
                    &prepared.provider.registration,
                    &agent_executable,
                    None,
                    "submit_plan",
                    serde_json::to_value(&prepared.submission)?,
                )?)
                .context("recovered built-in Agent API submit_plan returned an invalid plan")?;
            if !accepted_plan_matches_prepared_submission(&accepted, &prepared.submission) {
                bail!("accepted_plan_differs_from_prepared_saga");
            }
            accepted
        }
    };
    Ok(PlanSubmittedSaga { prepared, plan })
}

#[cfg(test)]
fn accepted_plan_matches_prepared_submission(
    accepted: &AgentPlanSubmission,
    prepared: &AgentPlanSubmission,
) -> bool {
    let mut provider_form = accepted.clone();
    for action in &mut provider_form.actions {
        action.os_tool_manifest_sha256 = None;
        action.os_executor_sha256 = None;
    }
    provider_form == *prepared
}

#[cfg(test)]
fn dispatch_submitted_saga(
    service: &AgentService,
    submitted: PlanSubmittedSaga,
) -> Result<ActionDispatchedSaga> {
    let agent_executable = submitted
        .prepared
        .provider
        .agent_executable
        .dispatch_identity();
    let action = submitted
        .plan
        .actions
        .first()
        .context("submitted saga plan omitted action")?;
    let dispatch = match service
        .get_agent_planned_action_dispatch_local(&submitted.plan.plan_id, &action.action_id)
        .map_err(anyhow::Error::msg)?
    {
        Some(existing) => existing,
        None => dispatch_builtin_agent_state_change(
            service,
            &submitted.prepared.provider.registration,
            &agent_executable,
            None,
            "run_tool",
            serde_json::to_value(AgentExecutionRequest {
                task_id: submitted.plan.task_id.clone(),
                plan_id: submitted.plan.plan_id.clone(),
                action_id: action.action_id.clone(),
            })?,
        )?,
    };
    let execution_binding: AgentExecutionBinding = serde_json::from_value(
        dispatch
            .get("execution_binding")
            .cloned()
            .context("planned action dispatch omitted execution binding")?,
    )
    .context("planned action dispatch returned an invalid execution binding")?;
    let approval_id = dispatch
        .get("approval")
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .context("OS policy did not stop at approval")?
        .to_string();
    let accepted_plan_sha256 = sha256_json(&serde_json::to_value(&submitted.plan)?);
    if execution_binding.task_id != submitted.plan.task_id
        || execution_binding.plan_id != submitted.plan.plan_id
        || execution_binding.action_id != action.action_id
        || execution_binding.accepted_plan_sha256 != accepted_plan_sha256
    {
        bail!("recovered_dispatch_frozen_binding_mismatch");
    }
    Ok(ActionDispatchedSaga {
        submitted,
        execution_binding,
        approval_id,
    })
}

#[cfg(test)]
fn stage_dispatched_payload(
    context_memory: &ContextMemoryService,
    dispatched: &ActionDispatchedSaga,
) -> Result<()> {
    let Some(descriptor) = dispatched.submitted.prepared.descriptor.as_ref() else {
        return Ok(());
    };
    let provider = &dispatched.submitted.prepared.provider;
    let binding = &dispatched.execution_binding;
    context_memory.stage_execution_payload(
        &durable_descriptor(descriptor),
        ExecutionPayloadBinding {
            owner_uid: binding.origin_uid,
            owner_selinux_domain: binding.origin_selinux_domain.clone(),
            subject_user_id: binding.subject_user_id,
            agent_id: binding.agent_id.clone(),
            agent_peer_uid: binding.peer_uid,
            agent_peer_gid: binding.peer_gid,
            agent_selinux_domain: binding.peer_selinux_domain.clone(),
            agent_executable_sha256: binding.agent_executable_sha256.clone(),
            task_id: binding.task_id.0.clone(),
            session_id: binding.session_id.clone(),
            plan_id: binding.plan_id.clone(),
            action_id: binding.action_id.clone(),
            tool_call_id: binding.tool_call_id.0.clone(),
            tool_name: binding.tool_name.clone(),
            tool_manifest_sha256: binding.tool_manifest_sha256.clone(),
            accepted_plan_sha256: binding.accepted_plan_sha256.clone(),
            context_sha256: provider.content_sha256.clone(),
            arguments_sha256: binding.arguments_sha256.clone(),
            expires_at_ms: dispatched
                .submitted
                .prepared
                .execution_payload_expires_at_ms
                .context("browser execution payload expiry disappeared")?,
        },
        &provider.content,
    )
}

#[cfg(test)]
fn finalize_dispatched_saga(
    service: &AgentService,
    dispatched: &ActionDispatchedSaga,
) -> Result<(PlanRecoveryBinding, Value, Value)> {
    let provider = &dispatched.submitted.prepared.provider;
    let plan = &dispatched.submitted.plan;
    let planned_action = plan
        .actions
        .first()
        .context("submitted saga plan omitted action")?;
    let execution_binding = &dispatched.execution_binding;
    let frozen_arguments = planned_action
        .arguments
        .as_object()
        .context("frozen Android action arguments must be an object")?;
    let authority_request_id = frozen_arguments
        .get("request_id")
        .and_then(Value::as_str)
        .context("frozen Android action omitted request_id")?;
    let source_id = frozen_arguments
        .get("source_id")
        .and_then(Value::as_str)
        .context("frozen Android action omitted source_id")?;
    let frozen_context_sha256 = frozen_arguments
        .get("context_sha256")
        .and_then(Value::as_str)
        .context("frozen Android action omitted context_sha256")?;
    let plan_sha256 = frozen_arguments
        .get("plan_sha256")
        .and_then(Value::as_str)
        .context("frozen Android action omitted plan_sha256")?;
    let frozen_provider_output_sha256 = frozen_arguments
        .get("provider_output_sha256")
        .and_then(Value::as_str)
        .context("frozen Android action omitted provider_output_sha256")?;
    let approval_nonce = frozen_arguments
        .get("approval_nonce")
        .and_then(Value::as_str)
        .context("frozen Android action omitted approval_nonce")?;
    let requested_network_scope = frozen_arguments
        .get("network_scope")
        .and_then(Value::as_str)
        .context("frozen Android action omitted network_scope")?;
    let frozen_payload = frozen_arguments
        .get("payload")
        .context("frozen Android action omitted payload")?;
    let action_contract = bounded_action_contract(&planned_action.tool_name)?;
    let (action_payload, execution_payload_sha256) = match planned_action.tool_name.as_str() {
        BROWSER_TOOL => {
            let descriptor = dispatched
                .submitted
                .prepared
                .descriptor
                .as_ref()
                .context("browser execution payload descriptor disappeared")?;
            let payload_sha256 = frozen_payload
                .get("execution_payload_sha256")
                .and_then(Value::as_str)
                .context("frozen browser action omitted execution payload digest")?;
            if payload_sha256 != descriptor.payload_sha256 {
                bail!("frozen browser action execution payload digest mismatch");
            }
            (json!({"url": provider.content}), payload_sha256.to_string())
        }
        NOTIFICATION_TOOL => {
            if dispatched.submitted.prepared.descriptor.is_some() {
                bail!("notification action unexpectedly staged an execution payload");
            }
            validate_notification_action_payload(frozen_payload)?;
            (frozen_payload.clone(), sha256_json(frozen_payload))
        }
        _ => unreachable!("bounded_action_contract rejected unsupported tool"),
    };
    validate_action_payload_binding(
        &planned_action.tool_name,
        &action_payload,
        &execution_payload_sha256,
    )?;
    if requested_network_scope != action_contract.argument_network_scope
        || frozen_context_sha256 != provider.content_sha256
        || frozen_provider_output_sha256 != plan.provider_output_sha256
        || execution_binding.tool_name != planned_action.tool_name
        || execution_binding.arguments_sha256 != planned_action.arguments_sha256
        || planned_action.network_scope != action_contract.plan_network_scope
        || planned_action.undo_contract != action_contract.undo_contract
    {
        bail!("frozen Android action receipt expectation mismatch");
    }
    let receipt_expectation = json!({
        "schema": "trillionnium.authority-receipt-expectation.v1",
        "request_id": authority_request_id,
        "agent_id": execution_binding.agent_id,
        "peer_uid": execution_binding.peer_uid,
        "peer_gid": execution_binding.peer_gid,
        "peer_selinux_domain": execution_binding.peer_selinux_domain,
        "agent_executable_sha256": execution_binding.agent_executable_sha256,
        "origin_selinux_domain": execution_binding.origin_selinux_domain,
        "session_id": execution_binding.session_id,
        "subject_user_id": execution_binding.subject_user_id,
        "origin_uid": execution_binding.origin_uid,
        "task_id": execution_binding.task_id.0,
        "plan_id": execution_binding.plan_id,
        "action_id": execution_binding.action_id,
        "tool_call_id": execution_binding.tool_call_id.0,
        "arguments_sha256": execution_binding.arguments_sha256,
        "tool_manifest_sha256": execution_binding.tool_manifest_sha256,
        "accepted_plan_sha256": execution_binding.accepted_plan_sha256,
        "arguments_canonicalization": "serde-json-utf8-lexicographic-v1-no-floats",
        "tool_name": planned_action.tool_name,
        "action": action_contract.action,
        "source_id": source_id,
        "context_sha256": frozen_context_sha256,
        "params_sha256": planned_action.arguments_sha256,
        "payload_sha256": execution_payload_sha256,
        "plan_sha256": plan_sha256,
        "provider_output_sha256": frozen_provider_output_sha256,
        "provider_id": format!("{}/rootlinux-gateway", execution_binding.agent_id),
        "target_generative_model": false,
        "approval_nonce_sha256": sha256_bytes(approval_nonce.as_bytes()),
        "network_scope": action_contract.receipt_network_scope,
        "caller_uid": 0,
        "user_id": execution_binding.subject_user_id,
        "explicit_approval": true,
        "single_use_capability_consumed": true,
        "executor_package": "org.trillionnium.aiauthority",
        "undo": false,
        "undo_supported": action_contract.undo_supported,
    });
    let approval = service
        .get_approval_local(&dispatched.approval_id)
        .map_err(anyhow::Error::msg)?
        .context("OS policy approval disappeared before consent challenge")?;
    let challenge = build_action_consent_challenge(
        execution_binding,
        &approval,
        &provider.workflow_id,
        &sha256_bytes(approval_nonce.as_bytes()),
        frozen_context_sha256,
        &action_payload,
        &execution_payload_sha256,
        now_unix_ms(),
    )?;
    let challenge_json = serde_json::to_string(&challenge)?;
    let challenge_sha256 = sha256_bytes(&serde_json::to_vec(&challenge)?);
    let challenge_expires_at_ms = challenge
        .get("expires_at_ms")
        .and_then(Value::as_u64)
        .context("action_consent_challenge_expiry_missing")?;
    let binding = PlanRecoveryBinding {
        method: "plan".to_string(),
        request_id: provider.request_id.clone(),
        request_payload_sha256: provider.request_payload_sha256.clone(),
        subject_uid: provider.peer_uid,
        subject_selinux_domain: provider.peer_domain.clone(),
        provider_id: provider.provider_id.clone(),
        task_id: provider.task_id.clone(),
        plan_id: plan.plan_id.clone(),
        action_id: execution_binding.action_id.clone(),
        tool_call_id: execution_binding.tool_call_id.0.clone(),
        accepted_plan_sha256: execution_binding.accepted_plan_sha256.clone(),
        challenge_sha256,
        challenge_expires_at_ms,
    };
    let response = json!({
        "task_id": provider.task_id,
        "plan_id": plan.plan_id,
        "approval_id": dispatched.approval_id,
        "action": action_contract.action,
        "tool_name": planned_action.tool_name,
        "receipt_expectation": receipt_expectation,
        "action_consent_challenge": challenge,
        "action_consent_challenge_json": challenge_json,
        "summary": dispatched.submitted.prepared.action_summary,
        "model": provider.provider_result.model,
        "provider_id": provider.provider_id,
        "provider": provider.provider_result.runtime_provider,
        "provider_output_sha256": plan.provider_output_sha256,
        "requires_approval": true,
        "execution_available": true,
        "network_scope": planned_action.network_scope,
        "tool_execution_owned_by_os": true,
        "model_executed_tools": false,
        "plan_latency_ms": provider.provider_result.elapsed_ms,
        "egress_grant_consumed": true,
    });
    Ok((binding, response, challenge))
}

fn provider_workflow_binding(provider: &ProviderReadySaga) -> PlanRecoveryBinding {
    PlanRecoveryBinding {
        method: "plan".to_string(),
        request_id: provider.request_id.clone(),
        request_payload_sha256: provider.request_payload_sha256.clone(),
        subject_uid: provider.peer_uid,
        subject_selinux_domain: provider.peer_domain.clone(),
        provider_id: provider.provider_id.clone(),
        task_id: provider.task_id.clone(),
        plan_id: String::new(),
        action_id: String::new(),
        tool_call_id: String::new(),
        accepted_plan_sha256: String::new(),
        challenge_sha256: String::new(),
        challenge_expires_at_ms: 0,
    }
}

#[cfg(test)]
fn prepared_workflow_binding(prepared: &PlanPreparedSaga) -> Result<PlanRecoveryBinding> {
    let mut binding = provider_workflow_binding(&prepared.provider);
    let action = prepared
        .submission
        .actions
        .first()
        .context("prepared saga omitted action")?;
    binding.plan_id = prepared.submission.plan_id.clone();
    binding.action_id = action.action_id.clone();
    Ok(binding)
}

#[cfg(test)]
fn submitted_workflow_binding(submitted: &PlanSubmittedSaga) -> Result<PlanRecoveryBinding> {
    if !accepted_plan_matches_prepared_submission(&submitted.plan, &submitted.prepared.submission) {
        bail!("submitted_saga_plan_differs_from_prepared_submission");
    }
    let mut binding = prepared_workflow_binding(&submitted.prepared)?;
    binding.accepted_plan_sha256 = sha256_json(&serde_json::to_value(&submitted.plan)?);
    Ok(binding)
}

#[cfg(test)]
fn dispatched_workflow_binding(dispatched: &ActionDispatchedSaga) -> Result<PlanRecoveryBinding> {
    let mut binding = submitted_workflow_binding(&dispatched.submitted)?;
    if binding.plan_id != dispatched.execution_binding.plan_id
        || binding.action_id != dispatched.execution_binding.action_id
        || binding.accepted_plan_sha256 != dispatched.execution_binding.accepted_plan_sha256
    {
        bail!("dispatched_saga_immutable_plan_binding_mismatch");
    }
    binding.tool_call_id = dispatched.execution_binding.tool_call_id.0.clone();
    Ok(binding)
}

fn local_plan_saga_schema(stage: PlanSagaStage, local_state: &Value) -> Option<&str> {
    let pointer = match stage {
        PlanSagaStage::ProviderPending | PlanSagaStage::ProviderReady => "/schema",
        PlanSagaStage::PlanPrepared => "/provider/schema",
        PlanSagaStage::PlanSubmitted => "/prepared/provider/schema",
        PlanSagaStage::ActionDispatched | PlanSagaStage::PayloadStaged => {
            "/submitted/prepared/provider/schema"
        }
        PlanSagaStage::PlanReady | PlanSagaStage::Indeterminate => return None,
    };
    local_state.pointer(pointer).and_then(Value::as_str)
}

fn resumable_saga_is_not_agent_direct(stage: PlanSagaStage, local_state: &Value) -> bool {
    match stage {
        PlanSagaStage::ProviderReady | PlanSagaStage::PlanReady => {
            local_state
                .pointer("/provider_result/execution_mode")
                .and_then(Value::as_str)
                != Some("agent_direct")
        }
        PlanSagaStage::PlanPrepared
        | PlanSagaStage::PlanSubmitted
        | PlanSagaStage::ActionDispatched
        | PlanSagaStage::PayloadStaged => true,
        PlanSagaStage::ProviderPending | PlanSagaStage::Indeterminate => false,
    }
}

fn resume_local_plan_saga(
    _service: &AgentService,
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
    request_id: &str,
) -> Result<()> {
    loop {
        let view = action_consents
            .lock()
            .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
            .workflow_for_reconcile(context_memory, request_id)?;
        let saga_schema = local_plan_saga_schema(view.stage, &view.local_state);
        if matches!(
            saga_schema,
            Some(LEGACY_LOCAL_PLAN_SAGA_SCHEMA)
                | Some(RETIRED_MULTI_PROVIDER_LOCAL_PLAN_SAGA_SCHEMA)
        ) {
            // v1 predates the durable executable dev/inode/owner/mode binding.
            // v2 additionally carried the retired multi-provider result shape.
            // Neither can safely enter the v3 Codex-only dispatcher, and the
            // missing identity must never be synthesized from today's path.
            // Quarantine this one workflow instead of preventing the Authority
            // API from serving and reconciling unrelated v3 work.
            let reason = if saga_schema == Some(LEGACY_LOCAL_PLAN_SAGA_SCHEMA) {
                LEGACY_LOCAL_PLAN_SAGA_INDETERMINATE_REASON
            } else {
                RETIRED_MULTI_PROVIDER_LOCAL_PLAN_SAGA_INDETERMINATE_REASON
            };
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .mark_indeterminate(context_memory, request_id, reason)?;
            return Ok(());
        }
        if resumable_saga_is_not_agent_direct(view.stage, &view.local_state) {
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .retire_non_direct_workflow(context_memory, request_id)?;
            return Ok(());
        }
        match view.stage {
            PlanSagaStage::ProviderPending => {
                bail!("provider_pending_cannot_resume_network");
            }
            PlanSagaStage::ProviderReady => {
                let provider: ProviderReadySaga = serde_json::from_value(view.local_state)
                    .context("invalid_provider_ready_saga_state")?;
                if validate_direct_provider_ready(&provider).is_err() {
                    action_consents
                        .lock()
                        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                        .mark_indeterminate(
                            context_memory,
                            request_id,
                            "invalid_agent_direct_provider_ready_state",
                        )?;
                    return Ok(());
                }
                let response = direct_provider_response(&provider)?;
                action_consents
                    .lock()
                    .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                    .publish_plan_ready(
                        context_memory,
                        request_id,
                        PlanReadyPublication {
                            expected_stage: PlanSagaStage::ProviderReady,
                            binding: provider_workflow_binding(&provider),
                            local_state: serde_json::to_value(&provider)?,
                            exact_plan_response: response,
                            challenge: None,
                        },
                    )?;
            }
            #[cfg(test)]
            PlanSagaStage::PlanPrepared => {
                let prepared: PlanPreparedSaga = serde_json::from_value(view.local_state)
                    .context("invalid_plan_prepared_saga_state")?;
                let submitted = submit_prepared_saga(_service, prepared)?;
                let binding = submitted_workflow_binding(&submitted)?;
                action_consents
                    .lock()
                    .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                    .transition(
                        context_memory,
                        request_id,
                        PlanSagaStage::PlanPrepared,
                        binding,
                        PlanSagaStage::PlanSubmitted,
                        serde_json::to_value(&submitted)?,
                    )?;
            }
            #[cfg(test)]
            PlanSagaStage::PlanSubmitted => {
                let submitted: PlanSubmittedSaga = serde_json::from_value(view.local_state)
                    .context("invalid_plan_submitted_saga_state")?;
                let dispatched = dispatch_submitted_saga(_service, submitted)?;
                let binding = dispatched_workflow_binding(&dispatched)?;
                action_consents
                    .lock()
                    .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                    .transition(
                        context_memory,
                        request_id,
                        PlanSagaStage::PlanSubmitted,
                        binding,
                        PlanSagaStage::ActionDispatched,
                        serde_json::to_value(&dispatched)?,
                    )?;
            }
            #[cfg(test)]
            PlanSagaStage::ActionDispatched => {
                let dispatched: ActionDispatchedSaga = serde_json::from_value(view.local_state)
                    .context("invalid_action_dispatched_saga_state")?;
                stage_dispatched_payload(context_memory, &dispatched)?;
                let binding = dispatched_workflow_binding(&dispatched)?;
                action_consents
                    .lock()
                    .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                    .transition(
                        context_memory,
                        request_id,
                        PlanSagaStage::ActionDispatched,
                        binding,
                        PlanSagaStage::PayloadStaged,
                        serde_json::to_value(&dispatched)?,
                    )?;
            }
            #[cfg(test)]
            PlanSagaStage::PayloadStaged => {
                let dispatched: ActionDispatchedSaga = serde_json::from_value(view.local_state)
                    .context("invalid_payload_staged_saga_state")?;
                let (binding, response, challenge) =
                    finalize_dispatched_saga(_service, &dispatched)?;
                action_consents
                    .lock()
                    .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                    .publish_plan_ready(
                        context_memory,
                        request_id,
                        PlanReadyPublication {
                            expected_stage: PlanSagaStage::PayloadStaged,
                            binding,
                            local_state: serde_json::to_value(&dispatched)?,
                            exact_plan_response: response,
                            challenge: Some(challenge),
                        },
                    )?;
            }
            #[cfg(not(test))]
            PlanSagaStage::PlanPrepared
            | PlanSagaStage::PlanSubmitted
            | PlanSagaStage::ActionDispatched
            | PlanSagaStage::PayloadStaged => {
                action_consents
                    .lock()
                    .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                    .retire_non_direct_workflow(context_memory, request_id)?;
                return Ok(());
            }
            PlanSagaStage::PlanReady | PlanSagaStage::Indeterminate => return Ok(()),
        }
    }
}

fn reconcile_action_workflows(
    service: &AgentService,
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
) -> Result<()> {
    let candidates = action_consents
        .lock()
        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
        .restart_candidates();
    for (request_id, stage) in candidates {
        if stage == PlanSagaStage::ProviderPending {
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .mark_indeterminate(
                    context_memory,
                    &request_id,
                    "provider_outcome_unknown_no_network_reexecution",
                )?;
            continue;
        }
        resume_local_plan_saga(service, action_consents, context_memory, &request_id)?;
    }
    let consuming = action_consents
        .lock()
        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
        .consuming_actions(context_memory)?;
    for (approval_id, view) in consuming {
        let consuming = view
            .consuming
            .context("consuming_action_consent_binding_missing")?;
        let Some(run) = service
            .get_tool_run_local(&view.binding.tool_call_id)
            .map_err(anyhow::Error::msg)?
        else {
            continue;
        };
        if run.approval_id.as_deref() != Some(approval_id.as_str())
            || run.task_id.0 != view.binding.task_id
            || run.tool_call_id.0 != view.binding.tool_call_id
        {
            bail!("consuming_action_restart_tool_run_binding_mismatch");
        }
        if matches!(run.status, ToolRunStatus::Succeeded | ToolRunStatus::Failed) {
            action_consents
                .lock()
                .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
                .mark_consumed(context_memory, &approval_id, &consuming, now_unix_ms())?;
        }
    }
    reconcile_action_workflow_custody(action_consents, context_memory)
}

fn ensure_active_egress_not_cancelled(
    service: &AgentService,
    cancellation: &ActiveEgressCancellation,
    task_id: &str,
) -> Result<()> {
    if cancellation.is_cancelled() {
        let _ = service.cancel_task_local(task_id);
        bail!("active_egress_cancelled_fail_closed");
    }
    Ok(())
}

// Consent verification deliberately receives every independently authenticated
// binding explicitly so no caller can construct a partially trusted context.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn consume_egress_grant(
    egress_grants: &EgressGrantStore,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: &Value,
    authority_key_pin: &Value,
    active_egress: &ActiveEgressStore,
    cancellation: &ActiveEgressCancellation,
    now: u64,
) -> Result<(String, PendingEgressGrant, String)> {
    let validated = prevalidate_egress_consent(
        egress_grants,
        peer_uid,
        peer_domain,
        request_id,
        payload,
        authority_key_pin,
        now,
    )?;
    consume_validated_egress_grant(egress_grants, None, active_egress, cancellation, validated)
}

fn prevalidate_egress_consent(
    egress_grants: &EgressGrantStore,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: &Value,
    authority_key_pin: &Value,
    now: u64,
) -> Result<ValidatedEgressConsent> {
    ensure_android_user_zero(peer_uid)?;
    validate_egress_plan_payload_shape(payload)?;
    let egress_grant_id = required_string(payload, "egress_grant_id", 96)?;
    let workflow_id = required_string(payload, "workflow_id", 128)?;
    let provider_id = required_string(payload, "provider", 64)?;
    let consent_receipt = required_string(payload, "consent_receipt", 256 * 1024)?;
    let binding = {
        let grants = egress_grants
            .lock()
            .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
        grants
            .pending
            .get(&egress_grant_id)
            .context("unknown_or_consumed_egress_grant")?
            .binding()
    };
    validate_pending_egress_material_binding(&binding)?;
    if binding.expires_at_ms <= now {
        bail!("egress_grant_expired");
    }
    if binding.workflow_id != workflow_id
        || binding.peer_uid != peer_uid
        || binding.peer_domain != peer_domain
        || binding.provider_id != provider_id
        || binding
            .consent_challenge
            .get("plan_request_id")
            .and_then(Value::as_str)
            != Some(request_id)
    {
        bail!("egress_grant_identity_binding_mismatch");
    }
    let receipt_id = verify_egress_consent_receipt(
        &binding,
        request_id,
        &consent_receipt,
        authority_key_pin,
        now,
    )?;

    Ok(ValidatedEgressConsent {
        grant_id: egress_grant_id,
        binding,
        receipt_id,
    })
}

fn consume_validated_egress_grant(
    egress_grants: &EgressGrantStore,
    context_memory: Option<&ContextMemoryService>,
    active_egress: &ActiveEgressStore,
    cancellation: &ActiveEgressCancellation,
    validated: ValidatedEgressConsent,
) -> Result<(String, PendingEgressGrant, String)> {
    let ValidatedEgressConsent {
        grant_id: egress_grant_id,
        binding,
        receipt_id,
    } = validated;
    ensure_android_user_zero(binding.peer_uid)?;
    // Re-check the immutable binding while holding the only grant-store lock,
    // then remove exactly once. Signature, field, time, key-pin and replay
    // failures above never consume the grant.
    let mut grants = egress_grants
        .lock()
        .map_err(|_| anyhow::anyhow!("egress_grant_store_poisoned"))?;
    let current = grants
        .pending
        .get(&egress_grant_id)
        .context("unknown_or_consumed_egress_grant")?;
    let current_binding = current.binding();
    validate_pending_egress_material_binding(&current_binding)?;
    if current_binding != binding {
        bail!("egress_grant_changed_or_expired_before_atomic_consume");
    }
    let transition_now = now_unix_ms();
    if current.expires_at_ms <= transition_now {
        let cas = current.journal_cas.clone();
        let recovery_blob = current.recovery_blob.clone();
        grants
            .journal
            .mark_expired(&egress_grant_id, &cas, transition_now)?;
        grants.pending.remove(&egress_grant_id);
        if let Some(context_memory) = context_memory {
            context_memory.delete_egress_recovery_blob(&recovery_blob)?;
        }
        bail!("egress_grant_expired_before_atomic_consume");
    }
    let mut active = active_egress
        .lock()
        .map_err(|_| anyhow::anyhow!("active_egress_store_poisoned"))?;
    if active.contains_key(&egress_grant_id) {
        bail!("egress_grant_already_active");
    }
    let prepared_cas = current.journal_cas.clone();
    // Move the secret-bearing grant into local custody before the durable
    // transition.  On a pre-publication failure it is restored to `pending`;
    // after publication there is no fallible I/O before `active` owns it.
    let grant = grants
        .pending
        .remove(&egress_grant_id)
        .expect("validated pending egress grant must remain present under grant-store lock");
    let consumed_cas = match grants.journal.mark_consumed(
        &egress_grant_id,
        &prepared_cas,
        &receipt_id,
        &sha256_bytes(cancellation.teardown_nonce.as_bytes()),
        transition_now,
    ) {
        Ok(cas) => cas,
        Err(error) => {
            grants.pending.insert(egress_grant_id.clone(), grant);
            return Err(error);
        }
    };
    let dispatch_blocked = consumed_cas.publication_durability_uncertain;
    active.insert(
        egress_grant_id.clone(),
        ActiveEgressRun {
            workflow_id: binding.workflow_id.clone(),
            peer_uid: binding.peer_uid,
            peer_domain: binding.peer_domain.clone(),
            provider_id: binding.provider_id.clone(),
            journal_binding_sha256: binding.journal_binding_sha256.clone(),
            journal_cas: consumed_cas,
            teardown_nonce: cancellation.teardown_nonce.clone(),
            cancellation: cancellation.clone(),
            durability: if dispatch_blocked {
                ActiveEgressDurability::DispatchBlockedCommitUnknown
            } else {
                ActiveEgressDurability::Running
            },
        },
    );
    // Recovery ciphertext cleanup is post-commit orphan collection.  It must
    // never create a CONSUMED state with neither pending nor active custody.
    // A failure leaves a bounded encrypted orphan for startup pruning.
    if let Some(context_memory) = context_memory {
        let _ = context_memory.delete_egress_recovery_blob(&grant.recovery_blob);
    }
    if dispatch_blocked {
        bail!("egress_consume_commit_unknown_dispatch_denied_until_restart");
    }
    Ok((egress_grant_id, grant, receipt_id))
}

fn validate_egress_plan_payload_shape(payload: &Value) -> Result<()> {
    exact_json_object_fields(
        payload,
        &[
            "egress_grant_id",
            "workflow_id",
            "provider",
            "consent_receipt",
        ],
        "egress_plan_payload",
    )?;
    Ok(())
}

fn verify_egress_consent_receipt(
    binding: &PendingEgressBinding,
    request_id: &str,
    encoded_receipt: &str,
    authority_key_pin: &Value,
    now: u64,
) -> Result<String> {
    validate_pending_egress_material_binding(binding)?;
    if encoded_receipt.is_empty() || encoded_receipt.len() > 256 * 1024 {
        bail!("egress_consent_receipt_boundary_denied");
    }
    let receipt_value = parse_strict_json(encoded_receipt, "egress_consent_receipt")?;
    let receipt = exact_json_object_fields(
        &receipt_value,
        EGRESS_CONSENT_RECEIPT_FIELDS,
        "egress_consent_receipt",
    )?;
    let pin =
        exact_json_object_fields(authority_key_pin, AUTHORITY_PIN_FIELDS, "authority_key_pin")?;

    exact_map_string(receipt, "schema", EGRESS_CONSENT_SCHEMA)?;
    exact_map_string(receipt, "decision", "ALLOW_EGRESS")?;
    exact_map_string(
        receipt,
        "receipt_signature_algorithm",
        AUTHORITY_SIGNATURE_ALGORITHM,
    )?;
    exact_map_string(pin, "schema", "trillionnium.authority-key-pin.v1")?;
    exact_map_bool(pin, "hardware_backed", true)?;
    exact_map_bool(pin, "internal_pin_verified", true)?;
    exact_map_bool(pin, "public_release_eligible", false)?;
    exact_map_string(pin, "rotation_contract", AUTHORITY_ROTATION_CONTRACT)?;
    if !matches!(
        map_string(pin, "security_level")?,
        "STRONGBOX" | "TRUSTED_ENVIRONMENT"
    ) {
        bail!("authority_consent_key_not_hardware_backed");
    }
    let pin_epoch = map_u64(pin, "key_epoch")?;
    if pin_epoch != AUTHORITY_RECEIPT_KEY_EPOCH {
        bail!("authority_consent_key_epoch_denied");
    }
    let pin_key_id = map_lower_sha256(pin, "key_id")?;
    let pin_spki = map_string(pin, "public_key_spki")?;
    let spki_der = decode_canonical_base64(pin_spki, "authority_consent_spki", 4_096)?;
    if hex_sha256(&spki_der) != pin_key_id {
        bail!("authority_consent_spki_pin_digest_mismatch");
    }
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|_| anyhow::anyhow!("authority_consent_spki_not_p256"))?;
    exact_map_string(receipt, "receipt_signing_key_id", pin_key_id)?;
    exact_map_u64(receipt, "receipt_signing_key_epoch", pin_epoch)?;
    exact_map_string(
        receipt,
        "receipt_signing_security_level",
        map_string(pin, "security_level")?,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_rotation_contract",
        AUTHORITY_ROTATION_CONTRACT,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_key_metadata_protocol",
        trillionnium_tool_runtime::ANDROID_GATEWAY_PROTOCOL,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_key_metadata_method",
        "key_metadata",
    )?;
    exact_map_bool(
        receipt,
        "receipt_signing_public_key_is_identity_root",
        false,
    )?;
    exact_map_string(receipt, "receipt_signing_public_key_spki", pin_spki)?;
    validate_authority_receipt_key_profile(receipt, pin)?;

    let encoded_signature = map_string(receipt, "receipt_signature")?;
    let signature_der =
        decode_canonical_base64(encoded_signature, "egress_consent_receipt_signature", 256)?;
    let signature = Signature::from_der(&signature_der)
        .map_err(|_| anyhow::anyhow!("egress_consent_signature_not_strict_der"))?;
    if signature.normalize_s().is_some() {
        bail!("egress_consent_signature_noncanonical_high_s");
    }
    let signed_payload = canonical_receipt(receipt, true)?;
    verifying_key
        .verify(signed_payload.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("egress_consent_signature_verification_failed"))?;
    let canonical_id = hex_sha256(canonical_receipt(receipt, false)?.as_bytes());
    if map_lower_sha256(receipt, "receipt_id")? != canonical_id {
        bail!("egress_consent_canonical_receipt_id_mismatch");
    }

    let challenge = exact_json_object_fields(
        &binding.consent_challenge,
        EGRESS_CHALLENGE_FIELDS,
        "stored_egress_consent_challenge",
    )?;
    for field in EGRESS_CHALLENGE_FIELDS {
        if receipt.get(*field) != challenge.get(*field) {
            bail!("egress_consent_challenge_field_mismatch:{field}");
        }
    }
    if map_string(receipt, "plan_request_id")? != request_id
        || map_u64(receipt, "issued_at_ms")? != binding.issued_at_ms
        || map_u64(receipt, "expires_at_ms")? != binding.expires_at_ms
        || map_string(receipt, "boot_id_sha256")? != current_boot_id_sha256()?
    {
        bail!("egress_consent_runtime_binding_mismatch");
    }
    let ttl_ms = map_u64(receipt, "ttl_ms")?;
    if ttl_ms == 0
        || ttl_ms > EGRESS_GRANT_TTL_MS
        || binding.issued_at_ms.saturating_add(ttl_ms) != binding.expires_at_ms
    {
        bail!("egress_consent_ttl_binding_mismatch");
    }
    let confirmed_at_ms = map_u64(receipt, "confirmed_at_ms")?;
    if confirmed_at_ms < binding.issued_at_ms
        || confirmed_at_ms > binding.expires_at_ms
        || confirmed_at_ms > now.saturating_add(EGRESS_CLOCK_SKEW_MS)
        || now >= binding.expires_at_ms
    {
        bail!("egress_consent_time_binding_denied");
    }
    Ok(canonical_id)
}

fn validate_receipt_certificate_chain(receipt: &Map<String, Value>) -> Result<()> {
    let chain = receipt
        .get("receipt_signing_certificate_chain_der")
        .and_then(Value::as_array)
        .context("egress_consent_certificate_chain_missing")?;
    if !(2..=8).contains(&chain.len()) {
        bail!("egress_consent_certificate_chain_boundary_denied");
    }
    for encoded in chain {
        let encoded = encoded
            .as_str()
            .context("egress_consent_certificate_chain_entry_not_string")?;
        if decode_canonical_base64(encoded, "egress_consent_certificate", 16_384)?.is_empty() {
            bail!("egress_consent_certificate_chain_entry_empty");
        }
    }
    Ok(())
}

fn validate_authority_receipt_key_profile(
    receipt: &Map<String, Value>,
    pin: &Map<String, Value>,
) -> Result<()> {
    validate_authority_receipt_key_profile_with_gate(
        receipt,
        pin,
        std::env::var(AUTHORITY_USERDEBUG_LOCAL_PROFILE_ENV).as_deref()
            == Ok(AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE),
    )
}

fn validate_authority_receipt_key_profile_with_gate(
    receipt: &Map<String, Value>,
    pin: &Map<String, Value>,
    allow_userdebug_local_hardware: bool,
) -> Result<()> {
    let key_profile = map_string(pin, "key_profile")?;
    exact_map_string(receipt, "receipt_signing_key_profile", key_profile)?;
    exact_map_bool(receipt, "hardware_backed_signature", true)?;
    match key_profile {
        AUTHORITY_ATTESTED_KEY_PROFILE => {
            exact_map_bool(pin, "attestation_chain_present", true)?;
            let expected_challenge_sha256 = hex_sha256(AUTHORITY_ATTESTATION_CHALLENGE);
            exact_map_string(
                pin,
                "attestation_challenge_sha256",
                &expected_challenge_sha256,
            )?;
            exact_map_string(
                receipt,
                "receipt_signing_identity_verification",
                AUTHORITY_IDENTITY_VERIFICATION,
            )?;
            exact_map_string(
                receipt,
                "receipt_signing_attestation_challenge_sha256",
                &expected_challenge_sha256,
            )?;
            if decode_canonical_base64(
                map_string(receipt, "receipt_signing_attestation_challenge_base64")?,
                "authority_receipt_attestation_challenge",
                256,
            )? != AUTHORITY_ATTESTATION_CHALLENGE
            {
                bail!("authority_receipt_attestation_challenge_mismatch");
            }
            exact_map_bool(receipt, "receipt_signing_attestation_chain_present", true)?;
            validate_receipt_certificate_chain(receipt)?;
        }
        AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE => {
            if !allow_userdebug_local_hardware {
                bail!("authority_userdebug_local_receipt_profile_not_enabled");
            }
            exact_map_bool(pin, "attestation_chain_present", false)?;
            exact_map_string(
                pin,
                "attestation_challenge_sha256",
                AUTHORITY_ATTESTATION_UNAVAILABLE,
            )?;
            exact_map_string(
                receipt,
                "receipt_signing_identity_verification",
                AUTHORITY_USERDEBUG_LOCAL_IDENTITY_VERIFICATION,
            )?;
            exact_map_string(
                receipt,
                "receipt_signing_attestation_challenge_sha256",
                AUTHORITY_ATTESTATION_UNAVAILABLE,
            )?;
            exact_map_string(receipt, "receipt_signing_attestation_challenge_base64", "")?;
            exact_map_bool(receipt, "receipt_signing_attestation_chain_present", false)?;
            let chain = receipt
                .get("receipt_signing_certificate_chain_der")
                .and_then(Value::as_array)
                .context("userdebug_local_receipt_certificate_chain_missing")?;
            if !chain.is_empty() {
                bail!("userdebug_local_receipt_certificate_chain_must_be_empty");
            }
        }
        _ => bail!("authority_receipt_key_profile_denied"),
    }
    Ok(())
}

// Keep every frozen binding input explicit at this authorization boundary.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn build_action_consent_challenge(
    binding: &AgentExecutionBinding,
    approval: &ApprovalRequest,
    workflow_id: &str,
    approval_nonce_sha256: &str,
    context_sha256: &str,
    action_payload: &Value,
    execution_payload_sha256: &str,
    challenge_issued_at_ms: u64,
) -> Result<Value> {
    let action_contract = validate_action_payload_binding(
        &binding.tool_name,
        action_payload,
        execution_payload_sha256,
    )?;
    if approval.status != ApprovalStatus::Pending
        || approval.task_id != binding.task_id
        || approval.tool_call_id != binding.tool_call_id
        || approval.tool_name != binding.tool_name
        || binding.origin_uid / 100_000 != binding.subject_user_id
        || !is_aishell_security_context(&binding.origin_selinux_domain)
        || !valid_lower_sha256(approval_nonce_sha256)
        || !valid_lower_sha256(context_sha256)
        || challenge_issued_at_ms < approval.created_at_unix_ms
    {
        bail!("action_consent_frozen_binding_denied");
    }
    let issued_at_ms = challenge_issued_at_ms;
    let expires_at_ms = issued_at_ms.saturating_add(ACTION_CONSENT_TTL_MS);
    let material = json!({
        "challenge_schema": ACTION_CONSENT_CHALLENGE_SCHEMA,
        "ui_uid": binding.origin_uid,
        "ui_selinux_domain": binding.origin_selinux_domain,
        "subject_user_id": binding.subject_user_id,
        "boot_id_sha256": current_boot_id_sha256()?,
        "workflow_id": workflow_id,
        "approve_request_id": format!("{workflow_id}-approve"),
        "task_id": binding.task_id.0,
        "session_id": binding.session_id,
        "plan_id": binding.plan_id,
        "action_id": binding.action_id,
        "approval_id": approval.id,
        "approval_created_at_ms": approval.created_at_unix_ms,
        "tool_call_id": binding.tool_call_id.0,
        "tool_name": binding.tool_name,
        "agent_id": binding.agent_id,
        "agent_peer_uid": binding.peer_uid,
        "agent_peer_gid": binding.peer_gid,
        "agent_selinux_domain": binding.peer_selinux_domain,
        "agent_executable_sha256": binding.agent_executable_sha256,
        "origin_uid": binding.origin_uid,
        "origin_selinux_domain": binding.origin_selinux_domain,
        "tool_manifest_sha256": binding.tool_manifest_sha256,
        "accepted_plan_sha256": binding.accepted_plan_sha256,
        "arguments_sha256": binding.arguments_sha256,
        "approval_nonce_sha256": approval_nonce_sha256,
        "context_sha256": context_sha256,
        "action_payload": action_payload,
        "execution_payload_sha256": execution_payload_sha256,
        "network_scope": action_contract.receipt_network_scope,
        "issued_at_ms": issued_at_ms,
        "expires_at_ms": expires_at_ms,
        "ttl_ms": ACTION_CONSENT_TTL_MS,
    });
    let challenge_id = format!("action-consent-challenge-{}", sha256_json(&material));
    let mut challenge = material
        .as_object()
        .context("action_consent_material_not_object")?
        .clone();
    challenge.insert("challenge_id".to_string(), json!(challenge_id));
    let challenge = Value::Object(challenge);
    exact_json_object_fields(
        &challenge,
        ACTION_CONSENT_CHALLENGE_FIELDS,
        "action_consent_challenge",
    )?;
    Ok(challenge)
}

#[cfg(test)]
fn verify_action_consent_receipt(
    expected_challenge: &Value,
    request_id: &str,
    encoded_receipt: &str,
    authority_key_pin: &Value,
    now: u64,
) -> Result<String> {
    if encoded_receipt.is_empty() || encoded_receipt.len() > 256 * 1024 {
        bail!("action_consent_receipt_boundary_denied");
    }
    let receipt_value = parse_strict_json(encoded_receipt, "action_consent_receipt")?;
    let receipt = exact_json_object_fields(
        &receipt_value,
        ACTION_CONSENT_RECEIPT_FIELDS,
        "action_consent_receipt",
    )?;
    let challenge = exact_json_object_fields(
        expected_challenge,
        ACTION_CONSENT_CHALLENGE_FIELDS,
        "expected_action_consent_challenge",
    )?;
    let pin =
        exact_json_object_fields(authority_key_pin, AUTHORITY_PIN_FIELDS, "authority_key_pin")?;

    exact_map_string(receipt, "schema", ACTION_CONSENT_SCHEMA)?;
    exact_map_string(receipt, "decision", "ALLOW_ACTION")?;
    exact_map_string(
        receipt,
        "receipt_signature_algorithm",
        AUTHORITY_SIGNATURE_ALGORITHM,
    )?;
    exact_map_string(pin, "schema", "trillionnium.authority-key-pin.v1")?;
    exact_map_bool(pin, "hardware_backed", true)?;
    exact_map_bool(pin, "internal_pin_verified", true)?;
    exact_map_bool(pin, "public_release_eligible", false)?;
    exact_map_string(pin, "rotation_contract", AUTHORITY_ROTATION_CONTRACT)?;
    if !matches!(
        map_string(pin, "security_level")?,
        "STRONGBOX" | "TRUSTED_ENVIRONMENT"
    ) {
        bail!("authority_action_consent_key_not_hardware_backed");
    }
    let pin_epoch = map_u64(pin, "key_epoch")?;
    if pin_epoch != AUTHORITY_RECEIPT_KEY_EPOCH {
        bail!("authority_action_consent_key_epoch_denied");
    }
    let pin_key_id = map_lower_sha256(pin, "key_id")?;
    let pin_spki = map_string(pin, "public_key_spki")?;
    let spki_der = decode_canonical_base64(pin_spki, "authority_action_consent_spki", 4_096)?;
    if hex_sha256(&spki_der) != pin_key_id {
        bail!("authority_action_consent_spki_pin_digest_mismatch");
    }
    let verifying_key = VerifyingKey::from_public_key_der(&spki_der)
        .map_err(|_| anyhow::anyhow!("authority_action_consent_spki_not_p256"))?;
    exact_map_string(receipt, "receipt_signing_key_id", pin_key_id)?;
    exact_map_u64(receipt, "receipt_signing_key_epoch", pin_epoch)?;
    exact_map_string(
        receipt,
        "receipt_signing_security_level",
        map_string(pin, "security_level")?,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_rotation_contract",
        AUTHORITY_ROTATION_CONTRACT,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_key_metadata_protocol",
        trillionnium_tool_runtime::ANDROID_GATEWAY_PROTOCOL,
    )?;
    exact_map_string(
        receipt,
        "receipt_signing_key_metadata_method",
        "key_metadata",
    )?;
    exact_map_bool(
        receipt,
        "receipt_signing_public_key_is_identity_root",
        false,
    )?;
    exact_map_string(receipt, "receipt_signing_public_key_spki", pin_spki)?;
    validate_authority_receipt_key_profile(receipt, pin)?;

    let signature_der = decode_canonical_base64(
        map_string(receipt, "receipt_signature")?,
        "action_consent_receipt_signature",
        256,
    )?;
    let signature = Signature::from_der(&signature_der)
        .map_err(|_| anyhow::anyhow!("action_consent_signature_not_strict_der"))?;
    if signature.normalize_s().is_some() {
        bail!("action_consent_signature_noncanonical_high_s");
    }
    verifying_key
        .verify(canonical_receipt(receipt, true)?.as_bytes(), &signature)
        .map_err(|_| anyhow::anyhow!("action_consent_signature_verification_failed"))?;
    let receipt_id = hex_sha256(canonical_receipt(receipt, false)?.as_bytes());
    if map_lower_sha256(receipt, "receipt_id")? != receipt_id {
        bail!("action_consent_canonical_receipt_id_mismatch");
    }
    for field in ACTION_CONSENT_CHALLENGE_FIELDS {
        if receipt.get(*field) != challenge.get(*field) {
            bail!("action_consent_challenge_field_mismatch:{field}");
        }
    }
    if map_string(receipt, "approve_request_id")? != request_id
        || map_string(receipt, "boot_id_sha256")? != current_boot_id_sha256()?
    {
        bail!("action_consent_runtime_binding_mismatch");
    }
    let issued_at_ms = map_u64(receipt, "issued_at_ms")?;
    let expires_at_ms = map_u64(receipt, "expires_at_ms")?;
    let ttl_ms = map_u64(receipt, "ttl_ms")?;
    let confirmed_at_ms = map_u64(receipt, "confirmed_at_ms")?;
    if ttl_ms != ACTION_CONSENT_TTL_MS
        || issued_at_ms.saturating_add(ttl_ms) != expires_at_ms
        || confirmed_at_ms < issued_at_ms
        || confirmed_at_ms >= expires_at_ms
        || confirmed_at_ms > now.saturating_add(EGRESS_CLOCK_SKEW_MS)
        || now >= expires_at_ms
    {
        bail!("action_consent_time_binding_denied");
    }
    Ok(receipt_id)
}

// Keep every OS-owned lookup/binding input explicit for reviewability.
#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn reconstruct_action_consent_challenge(
    service: &AgentService,
    peer_uid: u32,
    peer_domain: &str,
    workflow_id: &str,
    approval: &ApprovalRequest,
    plan_id: &str,
    action_id: &str,
    action_payload: &Value,
    challenge_issued_at_ms: u64,
) -> Result<Value> {
    if approval.status != ApprovalStatus::Pending {
        bail!("action_approval_not_pending_or_already_consumed");
    }
    let task = service
        .get_task_local(&approval.task_id.0)
        .map_err(anyhow::Error::msg)?
        .context("action_consent_task_missing")?;
    if task.metadata.get("android_ui_uid").and_then(Value::as_u64) != Some(peer_uid as u64)
        || task
            .metadata
            .get("android_ui_domain")
            .and_then(Value::as_str)
            != Some(peer_domain)
        || task
            .metadata
            .get("android_workflow_id")
            .and_then(Value::as_str)
            != Some(workflow_id)
    {
        bail!("action_consent_ui_task_binding_mismatch");
    }
    let plan = service
        .get_agent_plan_local(plan_id)
        .map_err(anyhow::Error::msg)?
        .context("action_consent_plan_missing")?;
    if plan.task_id != task.id || plan.agent_id.is_empty() {
        bail!("action_consent_plan_task_binding_mismatch");
    }
    let action = plan
        .actions
        .iter()
        .find(|action| action.action_id == action_id)
        .context("action_consent_action_missing")?;
    let action_contract = bounded_action_contract(&action.tool_name)?;
    if approval.task_id != task.id
        || approval.tool_name != action.tool_name
        || action.network_scope != action_contract.plan_network_scope
        || action.undo_contract != action_contract.undo_contract
    {
        bail!("action_consent_approval_action_binding_mismatch");
    }
    let agent_uid = task
        .metadata
        .get("agent_peer_uid")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .context("action_consent_agent_uid_missing")?;
    let agent_gid = task
        .metadata
        .get("agent_peer_gid")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .context("action_consent_agent_gid_missing")?;
    let agent_domain = required_metadata_string(&task.metadata, "agent_peer_selinux_domain")?;
    let agent_executable_sha256 =
        required_metadata_lower_sha256(&task.metadata, "agent_peer_executable_sha256")?;
    if required_metadata_string(&task.metadata, "agent_id")? != plan.agent_id {
        bail!("action_consent_agent_plan_binding_mismatch");
    }
    let arguments_sha256 = sha256_json(&action.arguments);
    if action.arguments_sha256 != arguments_sha256 {
        bail!("action_consent_frozen_arguments_digest_mismatch");
    }
    let manifest = trillionnium_tool_runtime::manifest_by_name(&action.tool_name)
        .context("action_consent_tool_manifest_missing")?;
    let tool_manifest_sha256 = sha256_json(&serde_json::to_value(manifest)?);
    let accepted_plan_sha256 = sha256_json(&serde_json::to_value(&plan)?);
    let binding_digest = sha256_json(&json!({
        "agent_id": plan.agent_id,
        "peer_uid": agent_uid,
        "peer_gid": agent_gid,
        "peer_selinux_domain": agent_domain,
        "agent_executable_sha256": agent_executable_sha256,
        "subject_user_id": peer_uid / 100_000,
        "origin_uid": peer_uid,
        "origin_selinux_domain": peer_domain,
        "session_id": plan.session_id,
        "task_id": task.id,
        "plan_id": plan.plan_id,
        "action_id": action.action_id,
        "tool_name": action.tool_name,
        "tool_manifest_sha256": tool_manifest_sha256,
        "accepted_plan_sha256": accepted_plan_sha256,
        "arguments_sha256": arguments_sha256,
    }));
    let expected_tool_call_id = format!("toolcall-agent-{}", &binding_digest[..32]);
    if approval.tool_call_id.0 != expected_tool_call_id {
        bail!("action_consent_tool_call_binding_mismatch");
    }
    let arguments = action
        .arguments
        .as_object()
        .context("action_consent_frozen_arguments_not_object")?;
    let approval_nonce = map_string(arguments, "approval_nonce")?;
    let context_sha256 = map_lower_sha256(arguments, "context_sha256")?;
    if map_string(arguments, "network_scope")? != action_contract.argument_network_scope {
        bail!("action_consent_frozen_network_scope_mismatch");
    }
    let payload = arguments
        .get("payload")
        .context("action_consent_execution_payload_missing")?;
    let execution_payload_sha256 = match action.tool_name.as_str() {
        BROWSER_TOOL => {
            let payload = exact_json_object_fields(
                payload,
                &[
                    "execution_payload_ref",
                    "execution_payload_sha256",
                    "execution_payload_shape",
                ],
                "action_consent_browser_execution_payload",
            )?;
            map_lower_sha256(payload, "execution_payload_sha256")?.to_string()
        }
        NOTIFICATION_TOOL => {
            validate_notification_action_payload(payload)?;
            if payload != action_payload {
                bail!("action_consent_notification_payload_mismatch");
            }
            sha256_json(payload)
        }
        _ => unreachable!("bounded_action_contract rejected unsupported tool"),
    };
    let binding = AgentExecutionBinding {
        agent_id: plan.agent_id.clone(),
        peer_uid: agent_uid,
        peer_gid: agent_gid,
        peer_selinux_domain: agent_domain.to_string(),
        agent_executable_sha256: agent_executable_sha256.to_string(),
        subject_user_id: peer_uid / 100_000,
        origin_uid: peer_uid,
        origin_selinux_domain: peer_domain.to_string(),
        session_id: plan.session_id.clone(),
        task_id: task.id,
        plan_id: plan.plan_id,
        action_id: action.action_id.clone(),
        tool_call_id: approval.tool_call_id.clone(),
        tool_name: action.tool_name.clone(),
        tool_manifest_sha256,
        accepted_plan_sha256,
        arguments_sha256,
    };
    build_action_consent_challenge(
        &binding,
        approval,
        workflow_id,
        &sha256_bytes(approval_nonce.as_bytes()),
        context_sha256,
        action_payload,
        &execution_payload_sha256,
        challenge_issued_at_ms,
    )
}

#[cfg(test)]
fn required_metadata_string<'a>(metadata: &'a Value, field: &str) -> Result<&'a str> {
    metadata
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .with_context(|| format!("action_consent_task_metadata_missing:{field}"))
}

#[cfg(test)]
fn required_metadata_lower_sha256<'a>(metadata: &'a Value, field: &str) -> Result<&'a str> {
    let value = required_metadata_string(metadata, field)?;
    if !valid_lower_sha256(value) {
        bail!("action_consent_task_metadata_digest_denied:{field}");
    }
    Ok(value)
}

#[cfg(test)]
fn approve(
    service: &AgentService,
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: Value,
) -> Result<Value> {
    let validated = prevalidate_action_approval(
        service,
        action_consents,
        context_memory,
        peer_uid,
        peer_domain,
        request_id,
        &payload,
    )?;
    approve_validated(service, action_consents, context_memory, validated)
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn prevalidate_action_approval(
    service: &AgentService,
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
    peer_uid: u32,
    peer_domain: &str,
    request_id: &str,
    payload: &Value,
) -> Result<ValidatedActionConsent> {
    exact_json_object_fields(
        payload,
        &[
            "task_id",
            "workflow_id",
            "approval_id",
            "action_consent_receipt",
        ],
        "action_approve_payload",
    )?;
    let task_id = required_string(payload, "task_id", 128)?;
    let workflow_id = required_string(payload, "workflow_id", 128)?;
    let approval_id = required_string(payload, "approval_id", 128)?;
    let encoded_receipt = required_string(payload, "action_consent_receipt", 256 * 1024)?;
    authorize_task(service, &task_id, &workflow_id, peer_uid)?;
    let approval = service
        .get_approval_local(&approval_id)
        .map_err(anyhow::Error::msg)?
        .context("unknown approval")?;
    if approval.task_id.0 != task_id {
        bail!("approval_task_binding_mismatch");
    }
    let expected_challenge = action_consents
        .lock()
        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
        .pending_challenge(context_memory, &approval_id, now_unix_ms())?;
    let plan_id = required_string(&expected_challenge, "plan_id", 128)?;
    let action_id = required_string(&expected_challenge, "action_id", 128)?;
    let action_payload = expected_challenge
        .get("action_payload")
        .filter(|value| value.is_object())
        .context("action_consent_challenge_action_payload_missing")?;
    let challenge_issued_at_ms = expected_challenge
        .get("issued_at_ms")
        .and_then(Value::as_u64)
        .context("action_consent_challenge_issued_at_missing")?;
    let reconstructed = reconstruct_action_consent_challenge(
        service,
        peer_uid,
        peer_domain,
        &workflow_id,
        &approval,
        &plan_id,
        &action_id,
        action_payload,
        challenge_issued_at_ms,
    )?;
    if reconstructed != expected_challenge {
        bail!("action_consent_stored_frozen_binding_mismatch");
    }
    let authority_key_pin = context_memory.authority_key_pin()?;
    let action_consent_receipt_id = verify_action_consent_receipt(
        &expected_challenge,
        request_id,
        &encoded_receipt,
        &authority_key_pin,
        now_unix_ms(),
    )?;
    Ok(ValidatedActionConsent {
        task_id,
        approval_id,
        expected_challenge,
        receipt_id: action_consent_receipt_id,
        approve_request_id: request_id.to_string(),
        approve_payload_sha256: sha256_bytes(&serde_json::to_vec(payload)?),
    })
}

#[cfg(test)]
fn approve_validated(
    service: &AgentService,
    action_consents: &ActionConsentStore,
    context_memory: &ContextMemoryService,
    validated: ValidatedActionConsent,
) -> Result<Value> {
    let ValidatedActionConsent {
        task_id,
        approval_id,
        expected_challenge,
        receipt_id: action_consent_receipt_id,
        approve_request_id,
        approve_payload_sha256,
    } = validated;
    // This is the first mutation. Forged, unsigned, stale, wrong-binding, or
    // replayed consent failed preflight before a durable UI replay began.
    let mut consents = action_consents
        .lock()
        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?;
    let current = consents.action_view(context_memory, &approval_id)?;
    if current.state != ActionConsentState::Pending || current.challenge != expected_challenge {
        bail!("action_consent_challenge_changed_before_atomic_consume");
    }
    let expires_at_ms = expected_challenge
        .get("expires_at_ms")
        .and_then(Value::as_u64)
        .context("action_consent_expiry_missing_before_atomic_consume")?;
    if expires_at_ms <= now_unix_ms() {
        bail!("action_consent_expired_before_atomic_consume");
    }
    let consuming = ConsumingApprovalBinding {
        approve_request_id,
        approve_payload_sha256,
        action_consent_receipt_id: action_consent_receipt_id.clone(),
        started_at_ms: now_unix_ms(),
    };
    consents.begin_consuming(context_memory, &approval_id, consuming.clone())?;
    drop(consents);
    let approved = service
        .approve_local(&approval_id)
        .map_err(anyhow::Error::msg)?;
    let run: ToolRun = serde_json::from_value(
        approved
            .get("tool_run")
            .cloned()
            .context("approved action omitted tool run")?,
    )
    .context("approved action returned invalid tool run")?;
    let result = action_result_from_succeeded_run(&task_id, &action_consent_receipt_id, &run)?;
    action_consents
        .lock()
        .map_err(|_| anyhow::anyhow!("action_workflow_journal_poisoned"))?
        .mark_consumed(context_memory, &approval_id, &consuming, now_unix_ms())?;
    Ok(result)
}

#[cfg(test)]
fn action_result_from_succeeded_run(
    task_id: &str,
    action_consent_receipt_id: &str,
    run: &ToolRun,
) -> Result<Value> {
    if run.task_id.0 != task_id || run.status != ToolRunStatus::Succeeded {
        bail!("approved_os_tool_failed");
    }
    let output = run
        .output
        .as_ref()
        .context("approved OS tool omitted output")?;
    let receipt_json = output
        .get("receipt_json")
        .and_then(Value::as_str)
        .context("approved OS tool omitted receipt_json")?;
    let receipt = parse_strict_json(receipt_json, "approved_os_tool_receipt")
        .context("approved OS tool returned invalid receipt_json")?;
    let receipt_request_id = required_string(&receipt, "request_id", 128)?;
    let receipt_action = required_string(&receipt, "action", 96)?;
    Ok(json!({
        "task_id": task_id,
        "authority_request_id": receipt_request_id,
        "action": receipt_action,
        "action_ok": output.get("action_ok").and_then(Value::as_bool).unwrap_or(false),
        "receipt_id": output.get("receipt_id"),
        "receipt_json": receipt_json,
        "result_text": output.get("result_text"),
        "undo_supported": output.get("undo_supported"),
        "single_use_consumed": true,
        "explicit_approval": true,
        "action_consent_receipt_id": action_consent_receipt_id,
        "executor": "trillionnium.android-agent-gateway.v1",
    }))
}

fn cancel(
    service: &AgentService,
    peer_uid: u32,
    _request_id: &str,
    payload: Value,
) -> Result<Value> {
    let (task_id, workflow_id) = parse_cancel_request(&payload)?;
    authorize_task(service, &task_id, &workflow_id, peer_uid)?;
    Ok(serde_json::to_value(
        service
            .cancel_task_local(&task_id)
            .map_err(anyhow::Error::msg)?,
    )?)
}

fn authorize_task(
    service: &AgentService,
    task_id: &str,
    workflow_id: &str,
    peer_uid: u32,
) -> Result<()> {
    let task = service
        .get_task_local(task_id)
        .map_err(anyhow::Error::msg)?
        .context("unknown task")?;
    if task.metadata.get("android_ui_uid").and_then(Value::as_u64) != Some(peer_uid as u64)
        || task
            .metadata
            .get("android_workflow_id")
            .and_then(Value::as_str)
            != Some(workflow_id)
    {
        bail!("android_ui_task_ownership_denied");
    }
    Ok(())
}

fn register_builtin_provider(
    service: &AgentService,
    provider_id: &str,
) -> Result<AgentRegistration> {
    if provider_id != CODEX_PROVIDER_ID {
        bail!("unsupported_direct_provider");
    }
    let (agent_id, adapter, uid, gid, selinux_domain, executable_env, identity_env, label) = (
        CODEX_AGENT_ID,
        CODEX.runtime_adapter,
        codex_uid(),
        codex_gid(),
        CODEX_AGENT_SELINUX_DOMAIN,
        "TRILLIONNIUM_CODEX_EXECUTABLE",
        "TRILLIONNIUM_CODEX_IDENTITY_SHA256",
        "Codex",
    );
    let registration = service
        .get_agent_local(agent_id)
        .map_err(anyhow::Error::msg)?
        .with_context(|| format!("{label} AgentManifest is not OS-provisioned"))?;
    validate_builtin_provider_runtime_identity(
        &registration,
        adapter,
        uid,
        gid,
        selinux_domain,
        label,
    )?;
    let executable = std::env::var_os(executable_env)
        .map(PathBuf::from)
        .with_context(|| format!("{label} executable path is not configured"))?;
    if !executable.is_absolute() {
        bail!("{label} executable path must be absolute");
    }
    let actual_identity = measure_executable(&executable, 0)?;
    let principal = agent_principal_registry::from_provider_id(provider_id)
        .ok_or_else(|| anyhow::anyhow!("unsupported_direct_provider"))?;
    if !crate::builtin_provider_identity::matches_registration_with_active_launcher(
        principal,
        &registration,
        &actual_identity,
    ) {
        bail!(
            "{label} active launcher measurement does not match the stable principal and OS AgentManifest"
        );
    }
    if let Ok(expected) = std::env::var(identity_env)
        && expected != actual_identity
    {
        bail!("{label} executable measurement does not match configured expected identity");
    }
    Ok(registration)
}

fn dispatch_builtin_agent_state_change(
    service: &AgentService,
    registration: &AgentRegistration,
    executable: &super::AgentExecutableDispatchIdentity,
    origin: Option<&Subject>,
    method: &str,
    payload: Value,
) -> Result<Value> {
    let origin = origin.map(|subject| super::AgentDispatchOrigin {
        uid: subject.uid,
        selinux_domain: subject.selinux_domain.as_str(),
        subject_user_id: subject.uid / ANDROID_UID_PER_USER_RANGE,
    });
    super::dispatch_agent_state_change(
        service,
        super::AgentDispatchAuthentication::OsSupervisedProvider {
            registration,
            executable,
            origin,
        },
        method,
        payload,
    )
}

fn measure_builtin_provider_dispatch_identity(
    provider_id: &str,
) -> Result<super::AgentExecutableDispatchIdentity> {
    if provider_id != CODEX_PROVIDER_ID {
        bail!("unsupported_direct_provider");
    }
    let (executable_env, label) = ("TRILLIONNIUM_CODEX_EXECUTABLE", "Codex");
    let executable_path = std::env::var_os(executable_env)
        .map(PathBuf::from)
        .with_context(|| format!("{label} executable path is not configured"))?;
    if !executable_path.is_absolute() {
        bail!("{label} executable path must be absolute");
    }
    let executable = measure_dispatch_executable(&executable_path, 0)?;
    Ok(super::AgentExecutableDispatchIdentity::from(&executable))
}

fn validate_builtin_provider_runtime_identity(
    registration: &AgentRegistration,
    adapter: &str,
    uid: u32,
    gid: u32,
    selinux_domain: &str,
    label: &str,
) -> Result<()> {
    let principal =
        crate::builtin_provider_identity::stable_principal_from_registration(registration)
            .ok_or_else(|| anyhow::anyhow!("{label} stable principal binding mismatch"))?;
    if !registration.enabled
        || registration.health != AgentHealth::Ready
        || registration.network_policy != AgentNetworkPolicy::PerRequest
        || principal.runtime_adapter != adapter
        || principal.uid != uid
        || principal.gid != gid
        || principal.agent_selinux_domain != selinux_domain
    {
        bail!("{label} AgentManifest or run identity mismatch");
    }
    Ok(())
}

fn measure_executable(executable: &Path, required_owner_uid: u32) -> Result<String> {
    Ok(measure_dispatch_executable(executable, required_owner_uid)?.sha256)
}

fn measure_dispatch_executable(
    executable: &Path,
    required_owner_uid: u32,
) -> Result<super::OpenedExecutableIdentity> {
    // Open and measure one kernel file description. A path-level metadata
    // check followed by a second open would leave a substitution window.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(executable)
        .with_context(|| format!("failed to open agent executable {}", executable.display()))?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "failed to inspect opened agent executable {}",
            executable.display()
        )
    })?;
    if !metadata.is_file() || metadata.uid() != required_owner_uid || metadata.mode() & 0o022 != 0 {
        bail!("agent executable must be owner-controlled non-writable regular file");
    }
    super::measure_open_executable(file)
}

fn codex_uid() -> u32 {
    DEFAULT_CODEX_UID
}

fn codex_gid() -> u32 {
    DEFAULT_CODEX_GID
}

fn fill_kernel_random(bytes: &mut [u8]) -> Result<()> {
    let mut filled = 0usize;
    while filled < bytes.len() {
        let remaining = &mut bytes[filled..];
        let read = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                remaining.as_mut_ptr(),
                remaining.len(),
                0,
            )
        };
        if read < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("kernel getrandom failed");
        }
        if read == 0 {
            bail!("kernel getrandom returned no bytes");
        }
        filled += usize::try_from(read).context("kernel getrandom returned an invalid length")?;
    }
    Ok(())
}

fn required_string(value: &Value, key: &str, max: usize) -> Result<String> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("{key} is required"))?;
    if text.len() > max || (text.is_empty() && key != "intent") {
        bail!("{key} is outside the bounded input contract");
    }
    Ok(text.to_string())
}

fn exact_json_object_fields<'a>(
    value: &'a Value,
    expected_fields: &[&str],
    boundary: &str,
) -> Result<&'a Map<String, Value>> {
    let object = value
        .as_object()
        .with_context(|| format!("{boundary}_not_object"))?;
    if object.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        bail!("{boundary}_missing_or_unknown_fields");
    }
    Ok(object)
}

fn validate_os_ui_request_shape(value: &Value) -> Result<()> {
    exact_json_object_fields(
        value,
        &["protocol", "request_id", "method", "payload"],
        "os_ui_request",
    )?;
    if !value.get("payload").is_some_and(Value::is_object) {
        bail!("os_ui_request_payload_not_object");
    }
    Ok(())
}

fn parse_os_ui_request(encoded: &[u8]) -> Result<Value> {
    let request = crate::parse_request_json(encoded, "os_ui_request")?;
    validate_os_ui_request_shape(&request)?;
    Ok(request)
}

fn parse_cancel_request(payload: &Value) -> Result<(String, String)> {
    exact_json_object_fields(
        payload,
        &["task_id", "workflow_id"],
        "android_cancel_request",
    )?;
    Ok((
        required_string(payload, "task_id", 128)?,
        required_string(payload, "workflow_id", 128)?,
    ))
}

#[cfg(test)]
fn parse_undo_request(payload: &Value) -> Result<(String, String, String)> {
    exact_json_object_fields(
        payload,
        &["task_id", "workflow_id", "receipt_id"],
        "android_undo_request",
    )?;
    Ok((
        required_string(payload, "task_id", 128)?,
        required_string(payload, "workflow_id", 128)?,
        required_string(payload, "receipt_id", 64)?,
    ))
}

fn map_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("{field}_not_string"))
}

fn exact_map_string(object: &Map<String, Value>, field: &str, expected: &str) -> Result<()> {
    if map_string(object, field)? != expected {
        bail!("{field}_frozen_value_mismatch");
    }
    Ok(())
}

fn map_u64(object: &Map<String, Value>, field: &str) -> Result<u64> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("{field}_not_unsigned_integer"))
}

fn map_i64(object: &Map<String, Value>, field: &str) -> Result<i64> {
    object
        .get(field)
        .and_then(Value::as_i64)
        .with_context(|| format!("{field}_not_i64"))
}

fn exact_map_i64(object: &Map<String, Value>, field: &str, expected: i64) -> Result<()> {
    if map_i64(object, field)? != expected {
        bail!("{field}_binding_mismatch");
    }
    Ok(())
}

fn exact_map_u64(object: &Map<String, Value>, field: &str, expected: u64) -> Result<()> {
    if map_u64(object, field)? != expected {
        bail!("{field}_frozen_value_mismatch");
    }
    Ok(())
}

fn map_bool(object: &Map<String, Value>, field: &str) -> Result<bool> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .with_context(|| format!("{field}_not_boolean"))
}

fn exact_map_bool(object: &Map<String, Value>, field: &str, expected: bool) -> Result<()> {
    if map_bool(object, field)? != expected {
        bail!("{field}_frozen_value_mismatch");
    }
    Ok(())
}

fn map_lower_sha256<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    let value = map_string(object, field)?;
    if !is_lower_hex(value) {
        bail!("{field}_not_canonical_sha256");
    }
    Ok(value)
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn random_hex_32() -> Result<String> {
    let mut random = [0u8; 32];
    fill_kernel_random(&mut random)?;
    Ok(hex_bytes(&random))
}

fn current_boot_id_sha256() -> Result<String> {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("current_boot_id_unavailable")?;
    let boot_id = boot_id.trim();
    if boot_id.len() != 36
        || !boot_id.bytes().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23) && byte == b'-'
                || !matches!(index, 8 | 13 | 18 | 23)
                    && (byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        bail!("current_boot_id_invalid");
    }
    Ok(sha256_bytes(boot_id.as_bytes()))
}

fn decode_canonical_base64(encoded: &str, boundary: &str, max_bytes: usize) -> Result<Vec<u8>> {
    if encoded.is_empty() || encoded.len() > max_bytes.saturating_mul(2) {
        bail!("{boundary}_boundary_denied");
    }
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .with_context(|| format!("{boundary}_invalid_base64"))?;
    if decoded.len() > max_bytes || BASE64_STANDARD.encode(&decoded) != encoded {
        bail!("{boundary}_noncanonical_base64");
    }
    Ok(decoded)
}

fn hex_sha256(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn canonical_receipt(receipt: &Map<String, Value>, for_signature: bool) -> Result<String> {
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
            serde_json::to_string(value).map_err(Into::into)
        }
        Value::Object(value) if value.values().all(Value::is_string) => {
            // serde_json::Map is key-ordered in this build. Action-consent v2
            // therefore signs the same compact, lexicographic object bytes
            // used for execution_payload_sha256.
            serde_json::to_string(value).map_err(Into::into)
        }
        _ => bail!("egress_consent_receipt_noncanonical_value_type"),
    }
}

fn java_string_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn parse_strict_json(encoded: &str, boundary: &str) -> Result<Value> {
    let mut deserializer = serde_json::Deserializer::from_str(encoded);
    let StrictJson(value) = StrictJson::deserialize(&mut deserializer)
        .with_context(|| format!("{boundary}_not_strict_json"))?;
    deserializer
        .end()
        .with_context(|| format!("{boundary}_trailing_data"))?;
    Ok(value)
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

fn bind_abstract(name: &str) -> Result<UnixListener> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() + 1 >= 108 {
        bail!("invalid abstract socket name");
    }
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| {
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (index, byte) in bytes.iter().enumerate() {
            address.sun_path[index + 1] = *byte as libc::c_char;
        }
        let length = (size_of::<libc::sa_family_t>() + 1 + bytes.len()) as libc::socklen_t;
        if unsafe { libc::bind(fd, (&address as *const libc::sockaddr_un).cast(), length) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { libc::listen(fd, 16) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { UnixListener::from_raw_fd(fd) })
    })();
    if result.is_err() {
        unsafe { libc::close(fd) };
    }
    result
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(credentials.uid)
}

fn peer_security_context(stream: &UnixStream) -> Result<String> {
    let mut buffer = [0u8; 256];
    let mut length = buffer.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERSEC,
            buffer.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let length = usize::try_from(length).unwrap_or(0).min(buffer.len());
    Ok(String::from_utf8_lossy(&buffer[..length])
        .trim_end_matches('\0')
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        ACTION_CONSENT_SCHEMA, AUTHORITY_ATTESTATION_CHALLENGE, AUTHORITY_ATTESTATION_UNAVAILABLE,
        AUTHORITY_ATTESTED_KEY_PROFILE, AUTHORITY_IDENTITY_VERIFICATION,
        AUTHORITY_ROTATION_CONTRACT, AUTHORITY_SIGNATURE_ALGORITHM,
        AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE,
        AUTHORITY_USERDEBUG_LOCAL_IDENTITY_VERIFICATION, CONTEXT_CAPTURE_RECOVERY_SCHEMA,
        EGRESS_CONSENT_SCHEMA, approve, build_action_consent_challenge, canonical_receipt,
        capture_context, consume_egress_grant, fill_kernel_random, hex_sha256,
        install_codex_credential, is_aishell_security_context, issue_agent_data_grant,
        make_credential_parents_traversable, measure_executable, prepare_egress, revoke_egress,
        sha256_bytes, sha256_json, validate_authority_receipt_key_profile_with_gate,
        verify_action_consent_receipt, verify_context_capture_receipt,
        verify_context_resolution_content,
    };
    use crate::action_workflow::{ActionWorkflowJournal, PlanRecoveryBinding};
    use crate::context_memory::{ContextMemoryService, Subject};
    use crate::egress_journal::{
        EgressJournalMetadata, EgressLifecycleState, EgressUiCompletionBinding,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use p256::pkcs8::EncodePublicKey;
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use trillionnium_audit_sqlite::AuditStore;
    use trillionnium_dbus::AgentService;
    use trillionnium_os_types::agent_principal_registry::AgentStablePrincipal;
    use trillionnium_os_types::{
        AGENT_API_VERSION, AgentContextRef, AgentExecutionBinding, AgentHealth, AgentNetworkPolicy,
        AgentPlanSubmission, AgentPlannedAction, AgentRegistration, ApprovalRequest,
        ApprovalStatus, ContextPrivacyClass, TaskId, TaskInput, ToolCallId, now_unix_ms,
    };
    use trillionnium_tool_runtime::supervised_codex::{
        BoundedPlan, CODEX_DIRECT_EFFECT_RECOVERY_DECISION, CODEX_DIRECT_EFFECT_RECOVERY_SUMMARY,
        CodexDirectToolCallEvidence, CodexPlanAttempt, CodexPlanAttemptLifecycle,
        CodexPlanningReceipt, CodexProviderError, CodexRuntimeEvidence, EgressBrokerEvidence,
        EgressBrokerOutcome, EgressBrokerTerminationReason, ProviderSessionCleanupEvidence,
        RuntimeLifecycleBinding, runtime_evidence_component_sha256,
    };
    use zeroize::Zeroizing;

    #[test]
    fn context_capture_recovery_schema_matches_authority_v4() {
        assert_eq!(
            CONTEXT_CAPTURE_RECOVERY_SCHEMA,
            "org.trillionnium.ai-authority.context-capture-recovery.v4"
        );
    }

    #[test]
    fn context_resolution_requester_identity_is_strictly_bound() {
        for fields in [
            super::SAF_CONTEXT_RESOLUTION_FIELDS,
            super::BROWSER_CONTEXT_RESOLUTION_FIELDS,
        ] {
            assert!(fields.contains(&"requesting_package"));
            assert!(fields.contains(&"requesting_signer_sha256"));
        }

        let mut resolution = json!({
            "requesting_package": "org.trillionnium.aishell",
            "requesting_signer_sha256": super::AI_SHELL_SIGNER_SHA256,
        });
        super::verify_context_resolution_requester_identity(resolution.as_object().unwrap())
            .unwrap();

        resolution["requesting_package"] = json!("org.trillionnium.substituted");
        assert!(
            super::verify_context_resolution_requester_identity(resolution.as_object().unwrap(),)
                .unwrap_err()
                .to_string()
                .contains("requesting_package_frozen_value_mismatch")
        );

        resolution["requesting_package"] = json!("org.trillionnium.aishell");
        resolution["requesting_signer_sha256"] = json!("f".repeat(64));
        assert!(
            super::verify_context_resolution_requester_identity(resolution.as_object().unwrap(),)
                .unwrap_err()
                .to_string()
                .contains("requesting_signer_sha256_frozen_value_mismatch")
        );
    }

    #[test]
    fn direct_agent_process_identities_are_closed_constants() {
        assert_eq!(super::codex_uid(), super::DEFAULT_CODEX_UID);
        assert_eq!(super::codex_gid(), super::DEFAULT_CODEX_GID);
    }

    #[test]
    fn response_frame_limit_includes_newline_terminator() {
        let max_frame = super::MAX_FRAME as usize;
        let accepted_response = Value::String("x".repeat(max_frame - 3));
        let accepted_body = serde_json::to_vec(&accepted_response).unwrap();
        assert_eq!(accepted_body.len(), max_frame - 1);

        let accepted_frame = super::encode_android_agent_api_response_frame(&accepted_response);
        assert_eq!(accepted_frame.len(), max_frame);
        assert_eq!(accepted_frame.last(), Some(&b'\n'));
        assert_eq!(&accepted_frame[..max_frame - 1], accepted_body.as_slice());

        let oversized_response = Value::String("x".repeat(max_frame - 2));
        let oversized_body = serde_json::to_vec(&oversized_response).unwrap();
        assert_eq!(oversized_body.len(), max_frame);

        let denied_frame = super::encode_android_agent_api_response_frame(&oversized_response);
        assert!(denied_frame.len() <= max_frame);
        assert_eq!(denied_frame.last(), Some(&b'\n'));
        let denied: Value =
            serde_json::from_slice(&denied_frame[..denied_frame.len() - 1]).unwrap();
        assert_eq!(
            denied["error"],
            json!("android_agent_api_response_too_large")
        );
    }

    fn fixture_registration_for(principal: &AgentStablePrincipal) -> AgentRegistration {
        let now = now_unix_ms();
        AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: principal.agent_id.to_string(),
            adapter: principal.runtime_adapter.to_string(),
            adapter_version: "fixture".to_string(),
            identity_key_sha256: crate::builtin_provider_identity::active_launcher_identity(
                principal,
            )
            .map(str::to_string)
            .unwrap_or_else(|| sha256_bytes(b"fixture-independently-measured-active-launcher")),
            peer_uid: principal.uid,
            peer_gid: principal.gid,
            selinux_domain: principal.agent_selinux_domain.to_string(),
            network_policy: AgentNetworkPolicy::PerRequest,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: now,
            updated_at_unix_ms: now,
        }
    }

    fn fixture_registration() -> AgentRegistration {
        fixture_registration_for(&super::CODEX)
    }

    fn bind_fixture_registration(
        registration: &mut AgentRegistration,
        principal: &AgentStablePrincipal,
    ) {
        registration.agent_id = principal.agent_id.to_string();
        registration.adapter = principal.runtime_adapter.to_string();
        registration.identity_key_sha256 =
            crate::builtin_provider_identity::active_launcher_identity(principal)
                .map(str::to_string)
                .unwrap_or_else(|| sha256_bytes(b"fixture-independently-measured-active-launcher"));
        registration.peer_uid = principal.uid;
        registration.peer_gid = principal.gid;
        registration.selinux_domain = principal.agent_selinux_domain.to_string();
    }

    fn fixture_codex_direct_evidence() -> CodexDirectToolCallEvidence {
        CodexDirectToolCallEvidence {
            sequence: 0,
            server: "trillionnium_system_api".to_string(),
            tool: "trillionnium_system_api".to_string(),
            status: "completed".to_string(),
            canonical_request_sha256: sha256_bytes(b"canonical-request"),
            backend_request_id_sha256: sha256_bytes(b"backend-request-id"),
            backend_result_sha256: sha256_bytes(b"backend-result"),
            outcome: "success".to_string(),
            backend_error_code: None,
            event_payload_sha256: sha256_bytes(b"event-payload"),
        }
    }

    fn fixture_codex_direct_receipt(
        direct_tool_calls: Vec<CodexDirectToolCallEvidence>,
        refusal_reason: Option<&str>,
    ) -> CodexPlanningReceipt {
        let now = now_unix_ms();
        CodexPlanningReceipt {
            protocol: "trillionnium.codex-direct-provider.v1".to_string(),
            decision: "PASS_CODEX_DIRECT_RESULT_VALIDATED".to_string(),
            provider: "openai".to_string(),
            backend: "openai".to_string(),
            model: "gpt-fixture".to_string(),
            task_id: "task-direct-mapping".to_string(),
            token_id: "token-direct-mapping".to_string(),
            token_sha256: sha256_bytes(b"token-direct-mapping"),
            started_at_unix_ms: now,
            finished_at_unix_ms: now,
            elapsed_ms: 7,
            context_count: 1,
            context_bytes: 7,
            tainted_context_count: 0,
            network_approved: true,
            external_egress_possible: true,
            tool_execution_enabled: true,
            events: Vec::new(),
            direct_tool_calls,
            plan: Some(BoundedPlan {
                summary: "provider-specific direct summary".to_string(),
                actions: Vec::new(),
                refusal_reason: refusal_reason.map(str::to_string),
            }),
            error: None,
        }
    }

    fn fixture_codex_backend_error(
        tool: &str,
        backend_error_code: &str,
    ) -> CodexDirectToolCallEvidence {
        let mut evidence = fixture_codex_direct_evidence();
        evidence.server = tool.to_string();
        evidence.tool = tool.to_string();
        evidence.status = "failed".to_string();
        evidence.outcome = "backend_error".to_string();
        evidence.backend_error_code = Some(backend_error_code.to_string());
        evidence
    }

    fn fixture_codex_terminal_error(backend_error_code: &str) -> CodexDirectToolCallEvidence {
        let mut evidence =
            fixture_codex_backend_error("trillionnium_shell_exec", backend_error_code);
        evidence.outcome = "terminal_error".to_string();
        evidence
    }

    #[test]
    fn p0_system_api_reconciliation_uses_semantic_not_raw_backend_result_digest() {
        use trillionnium_os_types::direct_operation::{
            DirectOperationAdapter, DirectOperationOuterEvidence, DirectOperationOuterOutcome,
            DirectOperationToolCallCommitReceiptV3, OS_TOOL_CALL_ID_PREFIX,
            TOOL_CALL_COMMIT_RECEIPT_V3_SCHEMA,
        };
        use trillionnium_tool_runtime::supervised_codex::canonical_semantic_result_sha256;

        let service = AgentService::in_memory().unwrap();
        let mut ready = fixture_provider_ready_saga(&service, "semantic-result-reconciliation");
        ready.authorized_adapter_set =
            super::DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility();
        let binding = fixture_completed_shell_exec_authorization(&ready)
            .registration
            .binding;
        binding.validate().unwrap();
        let binding_sha256 = binding.digest_sha256().unwrap();
        let os_tool_call_id = format!("{OS_TOOL_CALL_ID_PREFIX}{}", "c".repeat(64));
        let backend_request_id_sha256 = sha256_bytes(os_tool_call_id.as_bytes());

        let mut commit = DirectOperationToolCallCommitReceiptV3 {
            schema: TOOL_CALL_COMMIT_RECEIPT_V3_SCHEMA.to_string(),
            binding_sha256,
            invocation_id: binding.invocation_id.clone(),
            adapter: DirectOperationAdapter::SystemApi,
            os_tool_call_id,
            adapter_effect_ordinal: 0,
            envelope_sha256: "d".repeat(64),
            prepared_ack_sha256: "e".repeat(64),
            allocator_generation: 1,
            allocation_record_sha256: "f".repeat(64),
            commit_receipt_sha256: String::new(),
        };
        commit.commit_receipt_sha256 = commit.digest_sha256().unwrap();

        for (raw, status, outcome, error, terminal_outcome, golden) in [
            (
                br#"{ "request_id":"wire-success-1", "ok":true, "protocol":"org.trillionnium.agent-system-api.v1" }"#.as_slice(),
                "completed",
                "success",
                None,
                DirectOperationOuterOutcome::Success,
                "9b8d295653814c2c4666f6f8d4287d1658766993cbb911fb4996f715f63c17f0",
            ),
            (
                br#"{ "retry_with_same_id" : false, "error" : "request_id_conflict", "protocol" : "org.trillionnium.agent-system-api.v1", "ok" : false, "request_id" : "wire-error-1" }"#.as_slice(),
                "failed",
                "backend_error",
                Some("request_id_conflict"),
                DirectOperationOuterOutcome::BackendError,
                "d98dbfaf56bc5b0a67df60c0f94c366c9d2a31a594aacbfde4068ac5acfe3f74",
            ),
        ] {
            let backend: Value = serde_json::from_slice(raw).unwrap();
            let semantic_digest = canonical_semantic_result_sha256(&backend).unwrap();
            assert_eq!(semantic_digest, golden);
            let raw_digest = sha256_bytes(raw);
            assert_ne!(raw_digest, semantic_digest);

            let call = CodexDirectToolCallEvidence {
                sequence: 0,
                server: "trillionnium_system_api".to_string(),
                tool: "trillionnium_system_api".to_string(),
                status: status.to_string(),
                canonical_request_sha256: sha256_bytes(b"launch-package-settings"),
                backend_request_id_sha256: backend_request_id_sha256.clone(),
                backend_result_sha256: semantic_digest.clone(),
                outcome: outcome.to_string(),
                backend_error_code: error.map(str::to_string),
                event_payload_sha256: sha256_bytes(raw),
            };
            let provider_result = if outcome == "success" {
                let mut recovery = fixture_codex_direct_receipt(vec![call.clone()], None);
                recovery.decision = CODEX_DIRECT_EFFECT_RECOVERY_DECISION.to_string();
                recovery.plan.as_mut().unwrap().summary =
                    CODEX_DIRECT_EFFECT_RECOVERY_SUMMARY.to_string();
                recovery.error = Some(
                    "provider_output_failed_after_validated_direct_terminal_prefix".to_string(),
                );
                super::map_codex_direct_result(recovery).unwrap()
            } else {
                super::map_codex_direct_result(fixture_codex_direct_receipt(
                    vec![call.clone()],
                    None,
                ))
                .unwrap()
            };
            let terminal = DirectOperationOuterEvidence {
                allocating_provider_attempt_id: binding
                    .attempt
                    .delivery_provider_attempt_id
                    .clone(),
                adapter_effect_ordinal: 0,
                journal_sequence: 1,
                tool: "trillionnium_system_api".to_string(),
                canonical_request_sha256: call.canonical_request_sha256.clone(),
                backend_request_id_sha256: backend_request_id_sha256.clone(),
                backend_result_sha256: semantic_digest,
                outcome: terminal_outcome,
                backend_error_code: error.map(str::to_string),
            };
            super::validate_p0_system_api_listener_reconciliation(
                &provider_result,
                &binding,
                Some(super::P0SystemApiListenerEvidence {
                    commit_receipt: &commit,
                    terminal_evidence: &terminal,
                    delivery_binding: &binding,
                    allocation_binding: &binding,
                }),
            )
            .unwrap();

            let mut raw_domain_terminal = terminal;
            raw_domain_terminal.backend_result_sha256 = raw_digest;
            assert!(
                super::validate_p0_system_api_listener_reconciliation(
                    &provider_result,
                    &binding,
                    Some(super::P0SystemApiListenerEvidence {
                        commit_receipt: &commit,
                        terminal_evidence: &raw_domain_terminal,
                        delivery_binding: &binding,
                        allocation_binding: &binding,
                    }),
                )
                .is_err()
            );
        }
    }

    fn fixture_codex_direct_ready_saga(
        service: &AgentService,
        request_id: &str,
        direct_tool_calls: Vec<CodexDirectToolCallEvidence>,
        refusal_reason: Option<&str>,
    ) -> super::ProviderReadySaga {
        let includes_shell = direct_tool_calls.iter().any(|call| {
            call.server == "trillionnium_shell_exec" || call.tool == "trillionnium_shell_exec"
        });
        let result = super::map_codex_direct_result(fixture_codex_direct_receipt(
            direct_tool_calls,
            refusal_reason,
        ))
        .unwrap();
        let mut provider = fixture_provider_ready_saga(service, request_id);
        provider.provider_result = super::DurableProviderPlanResult {
            submission: result.submission,
            execution_mode: result.execution_mode,
            direct_outcome: result.direct_outcome,
            direct_refusal_reason: result.direct_refusal_reason,
            direct_tool_calls: result.direct_tool_calls,
            summary: result.summary,
            runtime_provider: result.runtime_provider,
            model: result.model,
            elapsed_ms: result.elapsed_ms,
            provider_output_sha256: result.provider_output_sha256,
        };
        if includes_shell {
            provider.shell_exec_authorization =
                Some(fixture_completed_shell_exec_authorization(&provider));
        }
        provider
    }

    fn fixture_completed_shell_exec_authorization(
        provider: &super::ProviderReadySaga,
    ) -> crate::codex_adapter::CompletedShellExecAuthorizationV1 {
        use trillionnium_os_types::direct_operation::{
            BINDING_SCHEMA, DirectOperationBinding, DirectOperationProviderAttempt,
            DirectOperationStableSeed, STABLE_SEED_SCHEMA,
        };
        use trillionnium_shell_exec::authorization::{
            MAX_INVOCATION_LIFETIME_MS, ShellExecAuthorizationRegistryV1,
            ShellExecHostRegistrationReceiptV1, ShellExecHostRegistrationV1,
            ShellExecHostRetirementV1,
        };

        let stable_seed = DirectOperationStableSeed {
            schema: STABLE_SEED_SCHEMA.to_string(),
            provider_id: provider.provider_id.clone(),
            agent_id: provider.registration.agent_id.clone(),
            task_id: provider.task_id.clone(),
            provider_invocation_id_sha256: sha256_bytes(provider.request_id.as_bytes()),
            provider_session_id_sha256: sha256_bytes(
                format!("android-ui-{}-{}", provider.peer_uid, provider.workflow_id).as_bytes(),
            ),
            subject_uid: provider.peer_uid,
            subject_selinux_domain_sha256: sha256_bytes(provider.peer_domain.as_bytes()),
        };
        let invocation_id = stable_seed.invocation_id().unwrap();
        let attempt = DirectOperationProviderAttempt::derive(
            provider.runtime_lifecycle_binding_sha256.clone(),
            1,
            sha256_bytes(format!("fixture-shell-attempt-{}", provider.request_id).as_bytes()),
        )
        .unwrap();
        let binding = DirectOperationBinding {
            schema: BINDING_SCHEMA.to_string(),
            stable_seed,
            invocation_id,
            workflow_id_sha256: sha256_bytes(provider.workflow_id.as_bytes()),
            agent_identity_key_sha256: provider.registration.identity_key_sha256.clone(),
            agent_executable_sha256: provider.agent_executable.sha256.clone(),
            authorized_adapter_set: provider.authorized_adapter_set.clone(),
            attempt,
        };
        binding.validate().unwrap();
        let issued_boottime_ms = 10_000;
        let registration = ShellExecHostRegistrationV1::derive(
            binding,
            issued_boottime_ms,
            issued_boottime_ms + MAX_INVOCATION_LIFETIME_MS,
        )
        .unwrap();
        let mut registry = ShellExecAuthorizationRegistryV1::default();
        let receipt = registry
            .register_with_entropy(registration.clone(), issued_boottime_ms, [0x71; 32])
            .unwrap();
        let receipt: ShellExecHostRegistrationReceiptV1 =
            serde_json::from_value(serde_json::to_value(receipt).unwrap()).unwrap();
        let retirement = ShellExecHostRetirementV1::derive(&registration).unwrap();
        let retirement_receipt = registry.retire(&retirement, 20_000).unwrap();
        crate::codex_adapter::CompletedShellExecAuthorizationV1::from_completed_lifecycle(
            registration,
            receipt,
            retirement,
            retirement_receipt,
        )
        .unwrap()
    }

    fn fixture_provider_ready_saga(
        service: &AgentService,
        request_id: &str,
    ) -> super::ProviderReadySaga {
        fixture_provider_ready_saga_for_principal(service, request_id, &super::CODEX)
    }

    fn fixture_provider_ready_saga_for_principal(
        service: &AgentService,
        request_id: &str,
        descriptor: &AgentStablePrincipal,
    ) -> super::ProviderReadySaga {
        let registration = service
            .provision_agent_local(fixture_registration_for(descriptor))
            .unwrap();
        let task = service
            .create_task_local(TaskInput {
                title: format!("durable local saga {request_id}"),
                description: None,
                metadata: json!({
                    "agent_id": registration.agent_id,
                    "agent_peer_uid": registration.peer_uid,
                    "agent_peer_gid": registration.peer_gid,
                    "agent_peer_selinux_domain": registration.selinux_domain,
                    "agent_peer_executable_sha256": registration.identity_key_sha256,
                    "agent_peer_executable_dev": 71,
                    "agent_peer_executable_ino": 72,
                    "agent_peer_executable_uid": 0,
                    "agent_peer_executable_gid": 0,
                    "agent_peer_executable_mode": 0o555,
                    "agent_api_dispatch_origin": crate::OS_SUPERVISED_AGENT_DISPATCH_ORIGIN,
                    "subject_user_id": 0,
                    "origin_uid": 10_123,
                    "origin_selinux_domain": "u:r:trillionnium_aishell:s0",
                    "android_ui_uid": 10_123,
                    "android_ui_domain": "u:r:trillionnium_aishell:s0",
                    "android_workflow_id": format!("workflow-{request_id}"),
                }),
            })
            .unwrap();
        let now = now_unix_ms();
        let content = "private durable context".to_string();
        let content_sha256 = sha256_bytes(content.as_bytes());
        let provider_output_sha256 = "e".repeat(64);
        let arguments = json!({
            "request_id": format!("authority-{request_id}"),
            "source_id": "provider-source-placeholder",
            "context_sha256": content_sha256,
            "plan_sha256": "f".repeat(64),
            "provider_output_sha256": provider_output_sha256,
            "approval_nonce": format!("approval-nonce-{request_id}-123456"),
            "network_scope": "none",
            "payload": {
                "title": "Durable reminder",
                "body": "Exactly once after restart"
            }
        });
        let submission = AgentPlanSubmission {
            api_version: AGENT_API_VERSION.to_string(),
            plan_id: format!("plan-{request_id}"),
            task_id: task.id.clone(),
            session_id: format!("session-{request_id}"),
            agent_id: registration.agent_id.clone(),
            intent_sha256: "d".repeat(64),
            provider_output_sha256: provider_output_sha256.clone(),
            contexts: vec![AgentContextRef {
                context_id: format!("context-provider-{request_id}"),
                source_id: "provider-source-placeholder".to_string(),
                source_kind: "file".to_string(),
                captured_at_unix_ms: now,
                freshness_ttl_ms: 120_000,
                privacy_class: ContextPrivacyClass::Sensitive,
                content_sha256: content_sha256.clone(),
                revoked: false,
            }],
            actions: vec![AgentPlannedAction {
                action_id: format!("action-{request_id}"),
                tool_name: super::NOTIFICATION_TOOL.to_string(),
                os_tool_manifest_sha256: None,
                os_executor_sha256: None,
                arguments_sha256: sha256_json(&arguments),
                arguments,
                rationale: "provider notification proposal".to_string(),
                requires_approval: true,
                network_scope: "none".to_string(),
                undo_contract: super::NOTIFICATION_UNDO_CONTRACT.to_string(),
            }],
            created_at_unix_ms: now,
        };
        let agent_manifest_sha256 = sha256_json(&serde_json::to_value(&registration).unwrap());
        let agent_executable_sha256 = registration.identity_key_sha256.clone();
        super::ProviderReadySaga {
            schema: super::LOCAL_PLAN_SAGA_SCHEMA.to_string(),
            request_id: request_id.to_string(),
            request_payload_sha256: "a".repeat(64),
            peer_uid: 10_123,
            peer_domain: "u:r:trillionnium_aishell:s0".to_string(),
            provider_id: descriptor.provider_id.to_string(),
            workflow_id: format!("workflow-{request_id}"),
            task_id: task.id.0,
            registration,
            agent_executable: super::DurableAgentExecutableIdentity {
                dev: 71,
                ino: 72,
                uid: 0,
                gid: 0,
                mode: 0o555,
                sha256: agent_executable_sha256,
            },
            agent_manifest_sha256,
            runtime_lifecycle_binding_sha256: "b".repeat(64),
            authorized_adapter_set: {
                #[cfg(feature = "p0-launch-package-device-conformance")]
                {
                    super::DirectOperationAuthorizedAdapterSetV3::p0_system_api()
                }
                #[cfg(not(feature = "p0-launch-package-device-conformance"))]
                {
                    super::DirectOperationAuthorizedAdapterSetV3::future_system_api_and_accessibility()
                }
            },
            shell_exec_authorization: None,
            context_id: format!("context-{request_id}"),
            context_expires_at_ms: now + 120_000,
            source_id: format!("source-{request_id}"),
            content,
            content_sha256,
            provider_result: super::DurableProviderPlanResult {
                submission: Some(submission),
                execution_mode: super::ProviderExecutionMode::LegacyPlan,
                direct_outcome: None,
                direct_refusal_reason: None,
                direct_tool_calls: Vec::new(),
                summary: "durable fixture summary".to_string(),
                runtime_provider: "fixture-provider".to_string(),
                model: "fixture-model".to_string(),
                elapsed_ms: 7,
                provider_output_sha256,
            },
        }
    }

    fn store_provider_ready_saga(
        journal: &mut crate::action_workflow::ActionWorkflowJournal,
        memory: &ContextMemoryService,
        provider: &super::ProviderReadySaga,
    ) {
        let binding = super::provider_workflow_binding(provider);
        journal
            .begin_provider_pending(
                memory,
                binding.clone(),
                json!({"state": "provider_pending"}),
            )
            .unwrap();
        journal
            .transition(
                memory,
                &provider.request_id,
                crate::action_workflow::PlanSagaStage::ProviderPending,
                binding,
                crate::action_workflow::PlanSagaStage::ProviderReady,
                serde_json::to_value(provider).unwrap(),
            )
            .unwrap();
    }

    fn fixture_signing_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    #[test]
    fn builtin_provider_identity_binds_uid_and_gid_independently() {
        let registration = fixture_registration();
        super::validate_builtin_provider_runtime_identity(
            &registration,
            super::CODEX.runtime_adapter,
            super::DEFAULT_CODEX_UID,
            super::DEFAULT_CODEX_GID,
            super::CODEX_AGENT_SELINUX_DOMAIN,
            "Codex",
        )
        .unwrap();

        let error = super::validate_builtin_provider_runtime_identity(
            &registration,
            super::CODEX.runtime_adapter,
            super::DEFAULT_CODEX_UID,
            super::DEFAULT_CODEX_GID + 1,
            super::CODEX_AGENT_SELINUX_DOMAIN,
            "Codex",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("AgentManifest or run identity mismatch"));
    }

    #[test]
    fn disabled_builtin_manifest_retains_stable_principal_but_cannot_register_runtime() {
        let mut registration = fixture_registration();
        registration.enabled = false;
        registration.health = AgentHealth::Disabled;

        assert_eq!(
            crate::builtin_provider_identity::stable_principal_from_registration(&registration),
            Some(&super::CODEX),
        );
        let error = super::validate_builtin_provider_runtime_identity(
            &registration,
            super::CODEX.runtime_adapter,
            super::DEFAULT_CODEX_UID,
            super::DEFAULT_CODEX_GID,
            super::CODEX_AGENT_SELINUX_DOMAIN,
            "Codex",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("AgentManifest or run identity mismatch"));
    }

    #[test]
    fn health_reports_codex_uid_and_gid() {
        let health = super::android_ui_health(10_123, "u:r:trillionnium_aishell:s0");
        assert_eq!(health["codex_process_uid"], super::codex_uid());
        assert_eq!(health["codex_process_gid"], super::codex_gid());
        assert_eq!(
            health["direct_agent_host"],
            super::direct_agent_host_abi::health_contract()
        );
        assert_eq!(health["tool_invocation_owned_by_agent"], true);
        assert_eq!(health["tool_backend_owned_by_os"], true);
        assert_eq!(health["daemon_is_effect_executor"], false);
        assert_eq!(health["contract_confers_effect_authority"], false);
        assert_eq!(
            health["stable_principal_authority"],
            json!("agent_principal_registry_v2")
        );
        #[cfg(not(feature = "p0-launch-package-device-conformance"))]
        {
            assert_eq!(
                health["active_launcher_compile_time_authority_available"],
                json!(false)
            );
            assert_eq!(
                health["active_launcher_admission"],
                json!("runtime_file_description_measurement_required")
            );
        }
        #[cfg(feature = "p0-launch-package-device-conformance")]
        {
            assert_eq!(
                health["active_launcher_compile_time_authority_available"],
                json!(true)
            );
            assert_eq!(
                health["active_launcher_admission"],
                json!("compile_time_measured_p01_launcher_required")
            );
        }
        assert!(health.get("tool_execution_owned_by_os").is_none());
    }

    #[test]
    fn authenticated_android_ui_boundary_is_user_zero_only() {
        let domain = "u:r:trillionnium_aishell:s0";
        let subject = super::authenticated_android_ui_subject(10_123, domain).unwrap();
        assert_eq!(subject.uid, 10_123);
        assert_eq!(subject.selinux_domain, domain);

        for uid in [110_123, 210_123, u32::MAX] {
            let error = super::authenticated_android_ui_subject(uid, domain)
                .unwrap_err()
                .to_string();
            assert_eq!(error, super::ANDROID_USER_ZERO_CUSTODY_ERROR, "uid={uid}");
        }
        assert_eq!(
            super::authenticated_android_ui_subject(9_999, domain)
                .unwrap_err()
                .to_string(),
            "android_ui_peer_identity_denied"
        );
        assert_eq!(
            super::authenticated_android_ui_subject(10_123, "u:r:untrusted_app:s0")
                .unwrap_err()
                .to_string(),
            "android_ui_peer_identity_denied"
        );
    }

    #[test]
    fn nonzero_android_user_is_denied_before_sensitive_dispatch_and_side_effects() {
        let domain = "u:r:trillionnium_aishell:s0";
        let dispatched = AtomicUsize::new(0);
        for operation in ["capture", "gateway", "credential", "grant", "egress"] {
            let result = super::authenticated_android_ui_subject(110_123, domain).map(|_| {
                dispatched.fetch_add(1, Ordering::SeqCst);
            });
            assert_eq!(
                result.unwrap_err().to_string(),
                super::ANDROID_USER_ZERO_CUSTODY_ERROR,
                "operation={operation}"
            );
        }
        assert_eq!(dispatched.load(Ordering::SeqCst), 0);

        let temp = tempfile::tempdir().unwrap();
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let store = fixture_egress_store(&temp.path().join("egress-journal.json"));
        let active = Arc::new(Mutex::new(HashMap::new()));
        let service = AgentService::in_memory().unwrap();
        let user_one = Subject::new(110_123, domain).unwrap();
        let denied = |error: anyhow::Error| {
            assert_eq!(error.to_string(), super::ANDROID_USER_ZERO_CUSTODY_ERROR);
        };

        denied(
            capture_context(
                &contexts,
                &user_one,
                "user-one-capture",
                user_one.uid,
                json!({}),
            )
            .unwrap_err(),
        );
        denied(
            super::authority_key_metadata(&contexts, &user_one, "user-one-gateway").unwrap_err(),
        );
        denied(super::provision_codex(&user_one, &json!({})).unwrap_err());
        denied(
            issue_agent_data_grant(&service, &contexts, &user_one, json!({}), "context")
                .unwrap_err(),
        );
        denied(
            prepare_egress(
                &store,
                &contexts,
                &user_one,
                &fixture_registration(),
                "user-one-egress-prepare",
                json!({}),
            )
            .unwrap_err(),
        );
        denied(
            super::prevalidate_egress_consent(
                &store,
                user_one.uid,
                domain,
                "user-one-plan",
                &json!({}),
                &json!({}),
                now_unix_ms(),
            )
            .err()
            .expect("user one consent prevalidation must fail closed"),
        );
        denied(
            revoke_egress(
                &store,
                &active,
                user_one.uid,
                domain,
                "user-one-revoke",
                json!({}),
            )
            .unwrap_err(),
        );
        assert!(store.lock().unwrap().pending.is_empty());
        assert!(active.lock().unwrap().is_empty());

        let user_zero = Subject::new(10_123, domain).unwrap();
        let downstream = capture_context(
            &contexts,
            &user_zero,
            "user-zero-capture",
            user_zero.uid,
            json!({}),
        )
        .unwrap_err()
        .to_string();
        assert_ne!(downstream, super::ANDROID_USER_ZERO_CUSTODY_ERROR);
        assert!(downstream.contains("context_capture_request_missing_or_unknown_fields"));
    }

    fn fixture_cancellation() -> super::ActiveEgressCancellation {
        super::ActiveEgressCancellation {
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            teardown_nonce: "1".repeat(64),
            teardown_ack: Arc::new((Mutex::new(None), std::sync::Condvar::new())),
            cancel_count: Arc::new(AtomicUsize::new(0)),
            ack_publish_count: Arc::new(AtomicUsize::new(0)),
            wait_entered_barrier: None,
            after_ack_gate: None,
            force_teardown_timeout: false,
        }
    }

    fn fixture_runtime_binding(
        metadata: &EgressJournalMetadata,
        journal_binding_sha256: &str,
        teardown_nonce: &str,
    ) -> RuntimeLifecycleBinding {
        RuntimeLifecycleBinding {
            provider_id: metadata.provider_id.clone(),
            agent_id: metadata.agent_id.clone(),
            agent_peer_uid: metadata.agent_peer_uid,
            agent_peer_gid: metadata.agent_peer_gid,
            agent_selinux_domain_sha256: metadata.agent_selinux_domain_sha256.clone(),
            agent_executable_sha256: metadata.agent_executable_sha256.clone(),
            final_runtime_executable_sha256: env!("TRILLIONNIUM_P01_CODEX_RUNTIME_SHA256")
                .to_string(),
            agent_manifest_sha256: metadata.agent_manifest_sha256.clone(),
            provider_invocation_id_sha256: sha256_bytes(b"fixture-provider-invocation"),
            provider_session_id_sha256: sha256_bytes(b"fixture-provider-session"),
            egress_grant_id: metadata.grant_id.clone(),
            journal_binding_sha256: journal_binding_sha256.to_string(),
            capability_token_sha256: sha256_bytes(b"fixture-capability-token"),
            teardown_nonce_sha256: sha256_bytes(teardown_nonce.as_bytes()),
            proxy_instance_credential_sha256: sha256_bytes(b"fixture-proxy-credential"),
            approved_endpoint: metadata.endpoint.clone(),
            upload_byte_limit: metadata.upload_byte_limit,
            download_byte_limit: metadata.download_byte_limit,
            grant_issued_at_unix_ms: metadata.issued_at_ms,
            grant_expires_at_unix_ms: metadata.expires_at_ms,
        }
    }

    fn fixture_runtime_evidence(
        binding: &RuntimeLifecycleBinding,
        termination_reason: EgressBrokerTerminationReason,
    ) -> CodexRuntimeEvidence {
        let lifecycle_binding_sha256 = binding.digest_sha256().unwrap();
        let broker = EgressBrokerOutcome {
            lifecycle_binding_sha256: lifecycle_binding_sha256.clone(),
            provider_invocation_id_sha256: binding.provider_invocation_id_sha256.clone(),
            provider_session_id_sha256: binding.provider_session_id_sha256.clone(),
            proxy_instance_credential_sha256: binding.proxy_instance_credential_sha256.clone(),
            evidence: EgressBrokerEvidence {
                approved_authority: binding.approved_endpoint.clone(),
                validated_sni: Some("chatgpt.com".to_string()),
                resolved_candidate_ips: vec!["93.184.216.34".to_string()],
                chosen_ip: Some("93.184.216.34".to_string()),
                actual_upload_bytes: 128,
                actual_download_bytes: 256,
                started_at_unix_ms: binding.grant_issued_at_unix_ms + 1,
                ended_at_unix_ms: binding.grant_issued_at_unix_ms + 2,
                termination_reason,
                tls_claim_scope: "connect_authority_sni_dns_bytes_ttl_only".to_string(),
            },
            error: None,
        };
        let session = ProviderSessionCleanupEvidence {
            provider_id: binding.provider_id.clone(),
            lifecycle_binding_sha256: lifecycle_binding_sha256.clone(),
            provider_invocation_id_sha256: binding.provider_invocation_id_sha256.clone(),
            provider_session_id_sha256: binding.provider_session_id_sha256.clone(),
            session_artifact_sha256: sha256_bytes(b"fixture-provider-session-artifact"),
            cleanup_attempted: true,
            ownership_restored: true,
            cleanup_complete: true,
            cleanup_started_at_unix_ms: binding.grant_issued_at_unix_ms + 1,
            cleanup_completed_at_unix_ms: binding.grant_issued_at_unix_ms + 2,
            cleanup_errors: Vec::new(),
        };
        CodexRuntimeEvidence {
            child_started: false,
            broker_started: true,
            provider_session_started: true,
            child: None,
            child_cleanup_sha256: None,
            egress: Some(broker.clone()),
            broker_outcome_sha256: Some(runtime_evidence_component_sha256(&broker).unwrap()),
            provider_session_cleanup: Some(session.clone()),
            provider_session_cleanup_sha256: Some(
                runtime_evidence_component_sha256(&session).unwrap(),
            ),
            lifecycle_binding: Some(binding.clone()),
            lifecycle_binding_sha256: Some(lifecycle_binding_sha256),
        }
    }

    fn fixture_egress_store(path: &std::path::Path) -> super::EgressGrantStore {
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        Arc::new(Mutex::new(
            super::EgressGrantState::open_for_test(path).unwrap(),
        ))
    }

    fn fixture_consumed_journal_binding(
        store: &super::EgressGrantStore,
        grant_id: &str,
        workflow_id: &str,
    ) -> crate::egress_journal::EgressJournalCas {
        let now = now_unix_ms();
        let metadata = EgressJournalMetadata {
            grant_id: grant_id.to_string(),
            provider_id: super::CODEX_PROVIDER_ID.to_string(),
            workflow_id_sha256: sha256_bytes(workflow_id.as_bytes()),
            policy_epoch: super::EGRESS_POLICY_EPOCH,
            provider_abi_epoch: super::PROVIDER_ABI_EPOCH,
            prepare_request_id_sha256: sha256_bytes(b"prepare-request"),
            prepare_request_payload_sha256: sha256_bytes(b"prepare-payload"),
            peer_uid: 10_123,
            peer_selinux_domain_sha256: sha256_bytes(b"u:r:trillionnium_aishell:s0"),
            subject_user_id: 0,
            boot_id_sha256: sha256_bytes(b"boot-id"),
            agent_id: super::CODEX_AGENT_ID.to_string(),
            agent_peer_uid: super::DEFAULT_CODEX_UID,
            agent_peer_gid: super::DEFAULT_CODEX_UID,
            agent_selinux_domain_sha256: sha256_bytes(super::CODEX_AGENT_SELINUX_DOMAIN.as_bytes()),
            agent_executable_sha256: "a".repeat(64),
            agent_manifest_sha256: "b".repeat(64),
            context_id_sha256: sha256_bytes(b"context-active"),
            context_kind: "file".to_string(),
            context_captured_at_ms: now.saturating_sub(1),
            context_expires_at_ms: now + 120_000,
            context_sha256: sha256_bytes(b"content"),
            source_id_sha256: sha256_bytes(b"source"),
            privacy_class: "local_private".to_string(),
            content_bytes: 7,
            intent_sha256: sha256_bytes(b"intent"),
            intent_bytes: 6,
            allowed_actions_sha256: sha256_json(&json!([])),
            prompt_contract:
                trillionnium_tool_runtime::supervised_codex::DIRECT_EXECUTION_PROMPT_CONTRACT
                    .to_string(),
            prompt_contract_version:
                trillionnium_tool_runtime::supervised_codex::DIRECT_EXECUTION_PROMPT_CONTRACT_VERSION,
            endpoint: super::CODEX_EGRESS_ENDPOINT.to_string(),
            upload_byte_limit: 262_144,
            download_byte_limit: 4 * 1024 * 1024,
            consent_challenge_sha256: sha256_bytes(b"challenge"),
            issued_at_ms: now,
            expires_at_ms: now + 120_000,
        };
        let mut state = store.lock().unwrap();
        let recovery = crate::context_memory::EgressRecoveryBlobRef {
            file_name: format!("egress-recovery-{}.enc", sha256_bytes(grant_id.as_bytes())),
            ciphertext_sha256: sha256_bytes(b"fixture-ciphertext"),
            publication_durability_uncertain: false,
        };
        state.journal.record_prepared(metadata, &recovery).unwrap();
        let prepared = state
            .journal
            .mark_ui_request_completed_exact(
                grant_id,
                EgressUiCompletionBinding {
                    method: "prepare_egress",
                    request_id: "prepare-request",
                    request_payload_sha256: &sha256_bytes(b"prepare-payload"),
                    completion_proof_sha256: &sha256_bytes(b"fixture-prepare-completion-proof"),
                    peer_uid: 10_123,
                    peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                    completed_at_ms: now,
                },
            )
            .unwrap();
        let consumed = state
            .journal
            .mark_consumed(
                grant_id,
                &prepared,
                &sha256_bytes(b"active receipt"),
                &sha256_bytes("1".repeat(64).as_bytes()),
                now,
            )
            .unwrap();
        let metadata = state.journal.metadata_for_test(grant_id).unwrap();
        let binding = fixture_runtime_binding(&metadata, &consumed.binding_sha256, &"1".repeat(64));
        state
            .journal
            .freeze_predispatch_binding(
                grant_id,
                &consumed,
                &binding,
                "fixture-task",
                "fixture-provider-invocation",
                "fixture-provider-session",
                now,
            )
            .unwrap()
    }

    fn insert_active_egress_fixture(
        store: &super::EgressGrantStore,
        active: &super::ActiveEgressStore,
        cancellation: &super::ActiveEgressCancellation,
        grant_id: &str,
        workflow_id: &str,
    ) -> String {
        let journal_cas = fixture_consumed_journal_binding(store, grant_id, workflow_id);
        let journal_binding_sha256 = journal_cas.binding_sha256.clone();
        active.lock().unwrap().insert(
            grant_id.to_string(),
            super::ActiveEgressRun {
                workflow_id: workflow_id.to_string(),
                peer_uid: 10_123,
                peer_domain: "u:r:trillionnium_aishell:s0".to_string(),
                provider_id: super::CODEX_PROVIDER_ID.to_string(),
                journal_binding_sha256: journal_binding_sha256.clone(),
                journal_cas,
                teardown_nonce: cancellation.teardown_nonce.clone(),
                cancellation: cancellation.clone(),
                durability: super::ActiveEgressDurability::Running,
            },
        );
        journal_binding_sha256
    }

    fn freeze_test_predispatch_binding(
        store: &super::EgressGrantStore,
        active: &super::ActiveEgressStore,
        grant_id: &str,
    ) -> (RuntimeLifecycleBinding, EgressLifecycleState) {
        let (binding, state) = {
            let mut grants = store.lock().unwrap();
            let mut active_runs = active.lock().unwrap();
            let run = active_runs.get_mut(grant_id).unwrap();
            let metadata = grants.journal.metadata_for_test(grant_id).unwrap();
            let binding = fixture_runtime_binding(
                &metadata,
                &run.journal_binding_sha256,
                &run.teardown_nonce,
            );
            if run.journal_cas.state == EgressLifecycleState::Consumed {
                let frozen = grants
                    .journal
                    .freeze_predispatch_binding(
                        grant_id,
                        &run.journal_cas,
                        &binding,
                        "fixture-task",
                        "fixture-provider-invocation",
                        "fixture-provider-session",
                        now_unix_ms(),
                    )
                    .unwrap();
                run.journal_cas = frozen;
            }
            (binding, run.journal_cas.state)
        };
        assert!(matches!(
            state,
            EgressLifecycleState::Consumed | EgressLifecycleState::RevokePending
        ));
        (binding, state)
    }

    fn publish_test_teardown_ack(
        store: &super::EgressGrantStore,
        cancellation: &super::ActiveEgressCancellation,
        active: &super::ActiveEgressStore,
        grant_id: &str,
        termination_reason: &str,
    ) {
        let (binding, _) = freeze_test_predispatch_binding(store, active, grant_id);
        let broker_reason = match termination_reason {
            "completed" => EgressBrokerTerminationReason::InvocationCompleted,
            // A caller-driven revoke reaches the supervised Codex process as
            // provider cancellation. Mirror that production path instead of
            // relying on the retired provider's unclassified-failure escape.
            "caller" => EgressBrokerTerminationReason::ProviderCancelled,
            "cancelled" => EgressBrokerTerminationReason::ProviderCancelled,
            "timed_out" => EgressBrokerTerminationReason::ProviderTimedOut,
            _ => EgressBrokerTerminationReason::ProviderFailed,
        };
        let attempt_class = match termination_reason {
            "completed" => super::ProviderAttemptClass::Succeeded,
            "cancelled" => super::ProviderAttemptClass::Cancelled,
            "timed_out" => super::ProviderAttemptClass::TimedOut,
            "failed" => super::ProviderAttemptClass::Failed,
            "caller" => super::ProviderAttemptClass::Cancelled,
            _ => super::ProviderAttemptClass::Failed,
        };
        super::persist_provider_runtime_evidence_and_publish_ack(
            store,
            active,
            grant_id,
            &fixture_runtime_evidence(&binding, broker_reason),
            attempt_class,
        )
        .unwrap();
        assert!(cancellation.teardown_ack().unwrap().is_some());
    }

    fn assert_failed_attempt_evidence<T>(
        case: &str,
        broker_reason: EgressBrokerTerminationReason,
        expected_class: super::ProviderAttemptClass,
        expected_termination: &str,
        make_attempt: impl FnOnce(CodexRuntimeEvidence) -> super::NormalizedDirectProviderAttempt<T>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let store = fixture_egress_store(&temp.path().join(format!("{case}-egress.json")));
        let active = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = fixture_cancellation();
        let grant_id = format!("egress-{}", sha256_bytes(case.as_bytes()));
        let workflow_id = format!("workflow-{case}");
        insert_active_egress_fixture(&store, &active, &cancellation, &grant_id, &workflow_id);
        let (binding, _) = freeze_test_predispatch_binding(&store, &active, &grant_id);
        let attempt = make_attempt(fixture_runtime_evidence(&binding, broker_reason));
        assert_eq!(attempt.attempt_class, expected_class);
        let returned = super::verify_direct_provider_attempt(&store, &active, &grant_id, attempt)
            .err()
            .expect("failed provider attempt must return its original failure");
        assert!(!returned.to_string().is_empty());

        let ack = cancellation
            .teardown_ack()
            .unwrap()
            .expect("sanitized failure evidence must publish an exact teardown ack");
        assert_eq!(ack.termination_reason, expected_termination);
        let stored = store
            .lock()
            .unwrap()
            .journal
            .runtime_evidence_for_subject(
                &grant_id,
                &workflow_id,
                10_123,
                "u:r:trillionnium_aishell:s0",
            )
            .unwrap()
            .expect("failure evidence must be durable before the result escapes");
        assert_eq!(stored.1, ack.runtime_evidence_sha256);
    }

    #[test]
    fn normalized_codex_attempt_consumes_only_valid_os_effect_recovery_receipt() {
        let mut recovery =
            fixture_codex_direct_receipt(vec![fixture_codex_direct_evidence()], None);
        recovery.decision = CODEX_DIRECT_EFFECT_RECOVERY_DECISION.to_string();
        recovery.plan.as_mut().unwrap().summary = CODEX_DIRECT_EFFECT_RECOVERY_SUMMARY.to_string();
        recovery.error =
            Some("provider_output_failed_after_validated_direct_terminal_prefix".to_string());
        let normalized = super::normalize_codex_direct_attempt(CodexPlanAttempt {
            result: Err(CodexProviderError::Cancelled),
            recovery_receipt: Some(recovery),
            runtime_evidence: CodexRuntimeEvidence::no_runtime_started(),
            lifecycle: CodexPlanAttemptLifecycle::Cancelled,
        });
        assert_eq!(
            normalized.attempt_class,
            super::ProviderAttemptClass::Cancelled
        );
        assert_eq!(
            normalized.result.unwrap().decision,
            CODEX_DIRECT_EFFECT_RECOVERY_DECISION
        );

        let mut tampered =
            fixture_codex_direct_receipt(vec![fixture_codex_direct_evidence()], None);
        tampered.decision = CODEX_DIRECT_EFFECT_RECOVERY_DECISION.to_string();
        tampered.plan.as_mut().unwrap().summary = "model-owned replacement".to_string();
        tampered.error =
            Some("provider_output_failed_after_validated_direct_terminal_prefix".to_string());
        let normalized = super::normalize_codex_direct_attempt(CodexPlanAttempt {
            result: Err(CodexProviderError::InvalidOutput("bad final".to_string())),
            recovery_receipt: Some(tampered),
            runtime_evidence: CodexRuntimeEvidence::no_runtime_started(),
            lifecycle: CodexPlanAttemptLifecycle::Succeeded,
        });
        assert!(normalized.result.is_err());
    }

    #[test]
    fn normalized_attempt_gate_preserves_cancellation_timeout_and_failure_evidence() {
        for (case, error, broker_reason, expected_class, expected_termination) in [
            (
                "codex-cancelled",
                CodexProviderError::Cancelled,
                EgressBrokerTerminationReason::ProviderCancelled,
                super::ProviderAttemptClass::Cancelled,
                "cancelled",
            ),
            (
                "codex-timeout",
                CodexProviderError::Timeout,
                EgressBrokerTerminationReason::ProviderTimedOut,
                super::ProviderAttemptClass::TimedOut,
                "timed_out",
            ),
            (
                "codex-failed",
                CodexProviderError::Internal("fixture provider failure".to_string()),
                EgressBrokerTerminationReason::ProviderFailed,
                super::ProviderAttemptClass::Failed,
                "failed",
            ),
        ] {
            assert_failed_attempt_evidence(
                case,
                broker_reason,
                expected_class,
                expected_termination,
                |runtime_evidence| {
                    super::normalize_codex_direct_attempt(CodexPlanAttempt {
                        result: Err(error),
                        recovery_receipt: None,
                        runtime_evidence,
                        lifecycle: match expected_class {
                            super::ProviderAttemptClass::Succeeded => {
                                CodexPlanAttemptLifecycle::Succeeded
                            }
                            super::ProviderAttemptClass::Cancelled => {
                                CodexPlanAttemptLifecycle::Cancelled
                            }
                            super::ProviderAttemptClass::TimedOut => {
                                CodexPlanAttemptLifecycle::TimedOut
                            }
                            super::ProviderAttemptClass::Failed => {
                                CodexPlanAttemptLifecycle::Failed
                            }
                        },
                    })
                },
            );
        }
    }

    fn fixture_authority_pin(signing_key: &SigningKey) -> Value {
        let spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        json!({
            "schema": "trillionnium.authority-key-pin.v1",
            "key_id": hex_sha256(&spki),
            "key_epoch": 2,
            "public_key_spki": BASE64_STANDARD.encode(&spki),
            "key_profile": AUTHORITY_ATTESTED_KEY_PROFILE,
            "security_level": "TRUSTED_ENVIRONMENT",
            "hardware_backed": true,
            "attestation_challenge_sha256": hex_sha256(AUTHORITY_ATTESTATION_CHALLENGE),
            "attestation_chain_present": true,
            "rotation_contract": AUTHORITY_ROTATION_CONTRACT,
            "pinned_at_ms": now_unix_ms(),
            "internal_pin_verified": true,
            "attestation_verified": false,
            "public_release_eligible": false,
            "verification_status": "independent_os_pin_pass_full_keymint_chain_pending",
        })
    }

    #[test]
    fn userdebug_local_hardware_receipt_profile_requires_explicit_gate_and_empty_chain() {
        let pin = json!({
            "key_profile": AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE,
            "attestation_chain_present": false,
            "attestation_challenge_sha256": AUTHORITY_ATTESTATION_UNAVAILABLE,
        });
        let receipt = json!({
            "receipt_signing_key_profile": AUTHORITY_USERDEBUG_LOCAL_HARDWARE_KEY_PROFILE,
            "receipt_signing_identity_verification":
                AUTHORITY_USERDEBUG_LOCAL_IDENTITY_VERIFICATION,
            "receipt_signing_attestation_challenge_sha256":
                AUTHORITY_ATTESTATION_UNAVAILABLE,
            "receipt_signing_attestation_challenge_base64": "",
            "receipt_signing_certificate_chain_der": [],
            "receipt_signing_attestation_chain_present": false,
            "hardware_backed_signature": true,
        });
        let pin = pin.as_object().unwrap();
        let receipt = receipt.as_object().unwrap();
        assert!(
            validate_authority_receipt_key_profile_with_gate(receipt, pin, false)
                .unwrap_err()
                .to_string()
                .contains("not_enabled")
        );
        validate_authority_receipt_key_profile_with_gate(receipt, pin, true).unwrap();

        let mut forged = receipt.clone();
        forged.insert(
            "receipt_signing_certificate_chain_der".to_string(),
            json!(["ZmFrZQ=="]),
        );
        assert!(
            validate_authority_receipt_key_profile_with_gate(&forged, pin, true)
                .unwrap_err()
                .to_string()
                .contains("must_be_empty")
        );
    }

    fn fixture_consent_receipt(
        challenge: &Value,
        signing_key: &SigningKey,
        confirmed_at_ms: u64,
    ) -> String {
        fixture_signed_consent_receipt(
            challenge,
            signing_key,
            confirmed_at_ms,
            EGRESS_CONSENT_SCHEMA,
            "ALLOW_EGRESS",
        )
    }

    fn fixture_signed_consent_receipt(
        challenge: &Value,
        signing_key: &SigningKey,
        confirmed_at_ms: u64,
        schema: &str,
        decision: &str,
    ) -> String {
        let mut receipt = challenge.as_object().unwrap().clone();
        let spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        receipt.insert("schema".to_string(), json!(schema));
        receipt.insert("decision".to_string(), json!(decision));
        receipt.insert("confirmed_at_ms".to_string(), json!(confirmed_at_ms));
        receipt.insert(
            "receipt_signature_algorithm".to_string(),
            json!(AUTHORITY_SIGNATURE_ALGORITHM),
        );
        receipt.insert(
            "receipt_signing_key_id".to_string(),
            json!(hex_sha256(&spki)),
        );
        receipt.insert("receipt_signing_key_epoch".to_string(), json!(2));
        receipt.insert(
            "receipt_signing_key_profile".to_string(),
            json!(AUTHORITY_ATTESTED_KEY_PROFILE),
        );
        receipt.insert(
            "receipt_signing_security_level".to_string(),
            json!("TRUSTED_ENVIRONMENT"),
        );
        receipt.insert(
            "receipt_signing_rotation_contract".to_string(),
            json!(AUTHORITY_ROTATION_CONTRACT),
        );
        receipt.insert(
            "receipt_signing_key_metadata_protocol".to_string(),
            json!(trillionnium_tool_runtime::ANDROID_GATEWAY_PROTOCOL),
        );
        receipt.insert(
            "receipt_signing_key_metadata_method".to_string(),
            json!("key_metadata"),
        );
        receipt.insert(
            "receipt_signing_identity_verification".to_string(),
            json!(AUTHORITY_IDENTITY_VERIFICATION),
        );
        receipt.insert(
            "receipt_signing_public_key_is_identity_root".to_string(),
            json!(false),
        );
        receipt.insert(
            "receipt_signing_public_key_spki".to_string(),
            json!(BASE64_STANDARD.encode(&spki)),
        );
        receipt.insert(
            "receipt_signing_attestation_challenge_sha256".to_string(),
            json!(hex_sha256(AUTHORITY_ATTESTATION_CHALLENGE)),
        );
        receipt.insert(
            "receipt_signing_attestation_challenge_base64".to_string(),
            json!(BASE64_STANDARD.encode(AUTHORITY_ATTESTATION_CHALLENGE)),
        );
        receipt.insert(
            "receipt_signing_certificate_chain_der".to_string(),
            json!([
                BASE64_STANDARD.encode(b"fixture-leaf-certificate"),
                BASE64_STANDARD.encode(b"fixture-root-certificate"),
            ]),
        );
        receipt.insert(
            "receipt_signing_attestation_chain_present".to_string(),
            json!(true),
        );
        receipt.insert("hardware_backed_signature".to_string(), json!(true));
        let signed = canonical_receipt(&receipt, true).unwrap();
        let signature: Signature = signing_key.sign(signed.as_bytes());
        let signature = signature.normalize_s().unwrap_or(signature);
        receipt.insert(
            "receipt_signature".to_string(),
            json!(BASE64_STANDARD.encode(signature.to_der().as_bytes())),
        );
        let receipt_id = hex_sha256(canonical_receipt(&receipt, false).unwrap().as_bytes());
        receipt.insert("receipt_id".to_string(), json!(receipt_id));
        serde_json::to_string(&receipt).unwrap()
    }

    fn seal_fixture_context_receipt(
        receipt: &mut serde_json::Map<String, Value>,
        signing_key: &SigningKey,
    ) -> String {
        receipt.remove("receipt_signature");
        receipt.remove("receipt_id");
        let signed = canonical_receipt(receipt, true).unwrap();
        let signature: Signature = signing_key.sign(signed.as_bytes());
        let signature = signature.normalize_s().unwrap_or(signature);
        receipt.insert(
            "receipt_signature".to_string(),
            json!(BASE64_STANDARD.encode(signature.to_der().as_bytes())),
        );
        let receipt_id = hex_sha256(canonical_receipt(receipt, false).unwrap().as_bytes());
        receipt.insert("receipt_id".to_string(), json!(receipt_id));
        serde_json::to_string(receipt).unwrap()
    }

    fn high_s_malleate_receipt_json(receipt_json: &str) -> String {
        const P256_ORDER: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        let mut receipt: Value = serde_json::from_str(receipt_json).unwrap();
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
        serde_json::to_string(&receipt).unwrap()
    }

    fn fixture_context_receipt(
        signing_key: &SigningKey,
        request_id: &str,
        capture_id: &str,
        requesting_uid: u32,
        content: &str,
        captured_at_ms: u64,
    ) -> serde_json::Map<String, Value> {
        let spki = signing_key
            .verifying_key()
            .to_public_key_der()
            .unwrap()
            .as_bytes()
            .to_vec();
        let user_id = requesting_uid / 100_000;
        let provider_uid = user_id * 100_000 + 10_001;
        let mut receipt = json!({
            "schema": super::CONTEXT_CAPTURE_SCHEMA,
            "decision": "CAPTURED",
            "capture_id": capture_id,
            "capture_request_id": request_id,
            "capture_method": "android_saf_forwarded_read_grant",
            "requesting_package": "org.trillionnium.aishell",
            "requesting_uid": requesting_uid,
            "requesting_signer_sha256": super::AI_SHELL_SIGNER_SHA256,
            "subject_user_id": user_id,
            "boot_id_sha256": super::current_boot_id_sha256().unwrap(),
            "source_kind": "file",
            "source_id": format!("saf-provider:{}:document:{}", "b".repeat(64), "c".repeat(64)),
            "privacy_class": "local_private",
            "uri_scheme": "content",
            "provider_package": "com.android.documents",
            "provider_uid": provider_uid,
            "provider_authority_sha256": "b".repeat(64),
            "document_id_sha256": "c".repeat(64),
            "display_name_sha256": "d".repeat(64),
            "mime_type": "text/plain",
            "declared_size_bytes": i64::try_from(content.len()).unwrap(),
            "last_modified_ms": captured_at_ms.saturating_sub(1),
            "document_flags": 0,
            "metadata_query_complete": true,
            "provider_metadata_asserted": true,
            "content_sha256": hex_sha256(content.as_bytes()),
            "content_bytes": content.len(),
            "captured_at_ms": captured_at_ms,
            "expires_at_ms": captured_at_ms + super::CONTEXT_CAPTURE_TTL_MS,
            "ttl_ms": super::CONTEXT_CAPTURE_TTL_MS,
            "single_use": true,
            "raw_content_returned_to_ui": false,
        })
        .as_object()
        .unwrap()
        .clone();
        receipt.extend(
            json!({
            "receipt_signature_algorithm": AUTHORITY_SIGNATURE_ALGORITHM,
            "receipt_signing_key_id": hex_sha256(&spki),
            "receipt_signing_key_epoch": 2,
            "receipt_signing_key_profile": AUTHORITY_ATTESTED_KEY_PROFILE,
            "receipt_signing_security_level": "TRUSTED_ENVIRONMENT",
            "receipt_signing_rotation_contract": AUTHORITY_ROTATION_CONTRACT,
            "receipt_signing_key_metadata_protocol": trillionnium_tool_runtime::ANDROID_GATEWAY_PROTOCOL,
            "receipt_signing_key_metadata_method": "key_metadata",
            "receipt_signing_identity_verification": AUTHORITY_IDENTITY_VERIFICATION,
            "receipt_signing_public_key_is_identity_root": false,
            "receipt_signing_public_key_spki": BASE64_STANDARD.encode(&spki),
            "receipt_signing_attestation_challenge_sha256": hex_sha256(AUTHORITY_ATTESTATION_CHALLENGE),
            "receipt_signing_attestation_challenge_base64": BASE64_STANDARD.encode(AUTHORITY_ATTESTATION_CHALLENGE),
            "receipt_signing_certificate_chain_der": [
                BASE64_STANDARD.encode(b"fixture-leaf-certificate"),
                BASE64_STANDARD.encode(b"fixture-root-certificate"),
            ],
            "receipt_signing_attestation_chain_present": true,
            "hardware_backed_signature": true,
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        seal_fixture_context_receipt(&mut receipt, signing_key);
        receipt
    }

    fn fixture_browser_context_receipt(
        signing_key: &SigningKey,
        request_id: &str,
        capture_id: &str,
        requesting_uid: u32,
        url: &str,
        captured_at_ms: u64,
    ) -> serde_json::Map<String, Value> {
        let mut receipt = fixture_context_receipt(
            signing_key,
            request_id,
            capture_id,
            requesting_uid,
            url,
            captured_at_ms,
        );
        for field in [
            "provider_package",
            "provider_uid",
            "provider_authority_sha256",
            "document_id_sha256",
            "display_name_sha256",
            "mime_type",
            "declared_size_bytes",
            "last_modified_ms",
            "document_flags",
            "metadata_query_complete",
            "provider_metadata_asserted",
        ] {
            receipt.remove(field);
        }
        let url_sha256 = hex_sha256(url.as_bytes());
        receipt.insert(
            "capture_method".to_string(),
            json!("android_authority_secure_https_url_entry"),
        );
        receipt.insert("source_kind".to_string(), json!("browser"));
        receipt.insert(
            "source_id".to_string(),
            json!(format!("authority-url:{url_sha256}")),
        );
        receipt.insert("uri_scheme".to_string(), json!("https"));
        receipt.insert("url_sha256".to_string(), json!(url_sha256));
        receipt.insert("url_bytes".to_string(), json!(url.len()));
        receipt.insert(
            "url_host_sha256".to_string(),
            json!(hex_sha256(b"example.com")),
        );
        receipt.insert("user_entered_in_authority_ui".to_string(), json!(true));
        receipt.insert("explicit_user_confirmation".to_string(), json!(true));
        seal_fixture_context_receipt(&mut receipt, signing_key);
        receipt
    }

    #[test]
    fn signed_receipt_endpoints_use_retry_safe_preflight_replay() {
        let source = include_str!("android_agent_api.rs");
        let branch_marker = |method: &str| match method {
            "plan" => "direct_agent_host_abi::BUILTIN_WIRE_METHOD_RUN_DIRECT_TURN =>".to_string(),
            _ => format!("\"{method}\" =>"),
        };
        let branch = |method: &str, next_method: &str| {
            let start = source
                .find(&branch_marker(method))
                .unwrap_or_else(|| panic!("{method} branch missing"));
            let end = source[start..]
                .find(&branch_marker(next_method))
                .map(|offset| start + offset)
                .unwrap_or(source.len());
            &source[start..end]
        };
        assert!(
            branch("get_context", "plan").contains("run_ui_request_with_preflight_and_recovery("),
            "get_context must persist replay only after signed preflight"
        );
        for (method, next_method, ack) in [
            (
                "plan",
                "prepare_egress",
                "ack_action_workflow_ui_completion_if_present",
            ),
            (
                "prepare_egress",
                "revoke_egress",
                "ack_egress_ui_completion_if_present",
            ),
            (
                "revoke_egress",
                "select_memory_context",
                "ack_egress_ui_completion_if_present",
            ),
        ] {
            let branch = branch(method, next_method);
            let replay = branch
                .find("run_ui_request_with_preflight_and_recovery(")
                .unwrap_or_else(|| panic!("{method} query-only replay missing"));
            let handoff = branch
                .find(ack)
                .unwrap_or_else(|| panic!("{method} typed custody handoff missing"));
            assert!(
                replay < handoff,
                "{method} must finish exact UI pair before downstream proof handoff"
            );
        }
        let handle = source
            .split_once("fn handle(")
            .and_then(|(_, suffix)| suffix.split_once("fn android_ui_health("))
            .map(|(handle, _)| handle)
            .expect("production OS-UI dispatch missing");
        for retired in ["\"approve\" =>", "\"undo\" =>"] {
            assert!(
                !handle.contains(retired),
                "retired effect method remains in production dispatch: {retired}"
            );
        }
        assert!(handle.contains("unknown_or_ui_forbidden_android_agent_api_method"));
        let custody = source
            .find("fn ack_action_workflow_ui_completion_if_present")
            .map(|start| &source[start..])
            .expect("action workflow custody helper missing");
        for marker in [
            "ui_request_completion_proof_exact(",
            "record_ui_completion_proof(",
            "reconcile_action_workflow_custody(",
        ] {
            assert!(
                custody.contains(marker),
                "typed proof binding marker missing: {marker}"
            );
        }
    }

    #[test]
    fn os_ui_request_envelope_is_closed_world_and_requires_object_payload() {
        let valid = json!({
            "protocol": super::PROTOCOL,
            "request_id": "strict-ui-frame",
            "method": "health",
            "payload": {},
        });
        super::validate_os_ui_request_shape(&valid).unwrap();

        let mut extra = valid.clone();
        extra["debug_override"] = json!(true);
        assert!(
            super::validate_os_ui_request_shape(&extra)
                .unwrap_err()
                .to_string()
                .contains("missing_or_unknown_fields")
        );

        let mut scalar_payload = valid;
        scalar_payload["payload"] = json!("{}");
        assert!(
            super::validate_os_ui_request_shape(&scalar_payload)
                .unwrap_err()
                .to_string()
                .contains("payload_not_object")
        );

        let duplicate_request_id = super::parse_os_ui_request(
            br#"{"protocol":"trillionnium.direct-agent-host.uds.v1","request_id":"one","request_id":"two","method":"health","payload":{}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            duplicate_request_id.contains("invalid_or_duplicate_json"),
            "{duplicate_request_id}"
        );
        assert!(
            duplicate_request_id.contains("duplicate key request_id"),
            "{duplicate_request_id}"
        );

        let duplicate_payload_field = super::parse_os_ui_request(
            br#"{"protocol":"trillionnium.direct-agent-host.uds.v1","request_id":"duplicate-payload","method":"cancel","payload":{"task_id":"one","task\u005fid":"two","workflow_id":"workflow"}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(
            duplicate_payload_field.contains("duplicate key task_id"),
            "{duplicate_payload_field}"
        );

        for wrong_type in [
            br#"{"protocol":1,"request_id":"wrong-protocol","method":"health","payload":{}}"#.as_slice(),
            br#"{"protocol":"trillionnium.direct-agent-host.uds.v1","request_id":[],"method":"health","payload":{}}"#.as_slice(),
            br#"{"protocol":"trillionnium.direct-agent-host.uds.v1","request_id":"wrong-method","method":{},"payload":{}}"#.as_slice(),
        ] {
            let parsed = super::parse_os_ui_request(wrong_type).unwrap();
            assert!(
                super::required_string(&parsed, "request_id", 128).is_err()
                    || super::required_string(&parsed, "method", 64).is_err()
                    || parsed.get("protocol").and_then(Value::as_str) != Some(super::PROTOCOL)
            );
        }
    }

    #[test]
    fn android_cancel_and_undo_payloads_are_closed_world_and_typed() {
        assert_eq!(
            super::parse_cancel_request(&json!({
                "task_id": "task-cancel",
                "workflow_id": "workflow-cancel",
            }))
            .unwrap(),
            ("task-cancel".to_string(), "workflow-cancel".to_string())
        );
        assert_eq!(
            super::parse_undo_request(&json!({
                "task_id": "task-undo",
                "workflow_id": "workflow-undo",
                "receipt_id": "receipt-undo",
            }))
            .unwrap(),
            (
                "task-undo".to_string(),
                "workflow-undo".to_string(),
                "receipt-undo".to_string(),
            )
        );

        for denied in [
            json!({"task_id": "task-cancel"}),
            json!({
                "task_id": "task-cancel",
                "workflow_id": "workflow-cancel",
                "force": true,
            }),
            json!({"task_id": 7, "workflow_id": "workflow-cancel"}),
            json!({
                "task_id": {"value": "task-cancel"},
                "workflow_id": "workflow-cancel",
            }),
            json!({
                "task_id": "task-cancel",
                "workflow_id": ["workflow-cancel"],
            }),
        ] {
            assert!(super::parse_cancel_request(&denied).is_err(), "{denied}");
        }

        for denied in [
            json!({
                "task_id": "task-undo",
                "workflow_id": "workflow-undo",
            }),
            json!({
                "task_id": "task-undo",
                "workflow_id": "workflow-undo",
                "receipt_id": "receipt-undo",
                "force": true,
            }),
            json!({
                "task_id": "task-undo",
                "workflow_id": "workflow-undo",
                "receipt_id": false,
            }),
            json!({
                "task_id": "task-undo",
                "workflow_id": "workflow-undo",
                "receipt_id": {"value": "receipt-undo"},
            }),
        ] {
            assert!(super::parse_undo_request(&denied).is_err(), "{denied}");
        }
    }

    #[test]
    fn authority_key_metadata_gateway_ids_are_purpose_bound_and_randomized() {
        let first = super::unique_authority_key_metadata_request_id("approve-key").unwrap();
        let second = super::unique_authority_key_metadata_request_id("approve-key").unwrap();
        let other = super::unique_authority_key_metadata_request_id("context-key").unwrap();
        let purpose = &sha256_bytes(b"approve-key")[..24];
        assert!(first.starts_with(&format!("key-metadata-{purpose}-")));
        assert!(second.starts_with(&format!("key-metadata-{purpose}-")));
        assert_ne!(first, second);
        assert_ne!(first, other);
    }

    #[test]
    fn runtime_authority_metadata_is_read_only_and_boot_pin_checked_last() {
        let source = include_str!("android_agent_api.rs");
        let function = source
            .split_once("fn authority_key_metadata(")
            .unwrap()
            .1
            .split_once("\nfn unique_authority_key_metadata_request_id")
            .unwrap()
            .0;
        let prevalidate = function
            .find("prevalidate_authority_key_metadata_against_frozen_pin")
            .unwrap();
        let boot_commit = function
            .find("commit_android_authority_boot_peer_pin")
            .unwrap();
        assert!(prevalidate < boot_commit);
        assert!(!function.contains("pin_authority_key_metadata"));
    }

    #[test]
    fn retired_action_consent_contract_is_test_only_and_absent_from_live_direct_path() {
        for fields in [
            super::ACTION_CONSENT_CHALLENGE_FIELDS,
            super::ACTION_CONSENT_RECEIPT_FIELDS,
        ] {
            let unique = fields
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>();
            assert_eq!(unique.len(), fields.len());
        }
        let source = include_str!("android_agent_api.rs");
        let live = source
            .split_once("fn plan_validated(")
            .unwrap()
            .1
            .split_once("active_guard.finish(outcome)")
            .unwrap()
            .0;
        let (production_direct, retired_test_only) = live
            .split_once("#[cfg(test)]\n        {")
            .expect("legacy live bridge must have an explicit test-only boundary");
        for retired in [
            "receipt_expectation",
            "action_consent_challenge",
            "\"submit_plan\"",
            "\"run_tool\"",
        ] {
            assert!(
                !production_direct.contains(retired),
                "retired Authority surface escaped into live direct path: {retired}"
            );
        }
        assert!(retired_test_only.contains("receipt_expectation"));
        assert!(retired_test_only.contains("action_consent_challenge"));
        let finalize = source
            .split_once("#[cfg(test)]\nfn finalize_dispatched_saga(")
            .unwrap()
            .1
            .split_once("\nfn provider_workflow_binding(")
            .unwrap()
            .0;
        assert_eq!(finalize.matches("\"action_consent_challenge\":").count(), 1);
    }

    #[test]
    fn durable_attempt_and_authorized_inbox_publication_precede_codex_dispatch() {
        let source = include_str!("android_agent_api.rs");
        let live = source
            .split_once("fn plan_validated(")
            .unwrap()
            .1
            .split_once("active_guard.finish(outcome)")
            .unwrap()
            .0;
        let reserve = live.find(".reserve_verified(").unwrap();
        let allocate = live.find("allocate_direct_provider_attempt(").unwrap();
        let publish = live.find(".publish_reserved(").unwrap();
        let codex_dispatch = live.find(".plan_attempt_with_cancellation(").unwrap();
        let release = live.find("drop(direct_binding_publication);").unwrap();
        assert!(reserve < allocate);
        assert!(allocate < publish);
        assert!(publish < codex_dispatch);
        assert!(codex_dispatch < release);
        let publish_to_dispatch = &live[publish..codex_dispatch];
        assert!(publish_to_dispatch.contains("DispatchBlockedCommitUnknown"));
        assert!(publish_to_dispatch.contains("failed_dispatch_denied"));
    }

    #[test]
    fn p0_fixed_listener_serializes_before_any_direct_turn_mutation() {
        let source = include_str!("android_agent_api.rs");
        let live = source
            .split_once("fn plan_validated(")
            .unwrap()
            .1
            .split_once("active_guard.finish(outcome)")
            .unwrap()
            .0;
        let serial = live.find("P0_USERDEBUG_DIRECT_TURN_SERIAL").unwrap();
        let consume = live.find("consume_validated_egress_grant(").unwrap();
        let reserve = live.find(".reserve_verified(").unwrap();
        let publish = live.find(".publish_reserved(").unwrap();
        let listener = live
            .find("FixedDirectToolCallListener::bind_p0_userdebug")
            .unwrap();
        assert!(serial < consume && consume < reserve && reserve < publish && publish < listener);
        let admission = &live[serial..consume];
        assert!(admission.contains(".try_lock()"));
        assert!(admission.contains("busy_or_poisoned_no_mutation"));
    }

    #[test]
    fn p0_listener_admits_only_codex_and_remains_exactly_system_api() {
        let source = include_str!("android_agent_api.rs");
        let live = source
            .split_once("fn plan_validated(")
            .unwrap()
            .1
            .split_once("active_guard.finish(outcome)")
            .unwrap()
            .0;
        let listener = live
            .split_once("let direct_tool_call_session = {")
            .unwrap()
            .1
            .split_once("// Retain the publication's per-provider lifecycle guard")
            .unwrap()
            .0;
        assert!(listener.contains("provider_id != CODEX_PROVIDER_ID"));
        assert!(listener.contains("\"trillionnium-p0-codex-system-api\""));
        assert_eq!(
            listener
                .matches("DirectOperationAdapter::SystemApi")
                .count(),
            2
        );
        assert!(!listener.contains("DirectOperationAdapter::Accessibility"));
        assert!(live.contains("_direct_hidden_binding,"));
    }

    #[test]
    fn p0_listener_lifecycle_cancels_and_reaps_after_codex_terminates() {
        let source = include_str!("android_agent_api.rs");
        let guard_finish = source
            .split_once("impl P0UserdebugDirectToolCallSessionGuard {")
            .unwrap()
            .1
            .split_once("impl Drop for P0UserdebugDirectToolCallSessionGuard")
            .unwrap()
            .0;
        let cancel = guard_finish.find("self.cancellation.cancel()").unwrap();
        let take = guard_finish.find(".take()").unwrap();
        let join = guard_finish.find(".join()").unwrap();
        assert!(cancel < take && take < join);
        assert!(guard_finish.contains("Store both results before propagating either one"));

        let guard_drop = source
            .split_once("impl Drop for P0UserdebugDirectToolCallSessionGuard")
            .unwrap()
            .1
            .split_once("const EGRESS_CHALLENGE_FIELDS")
            .unwrap()
            .0;
        assert!(guard_drop.contains("self.cancellation.cancel()"));
        assert!(guard_drop.contains("session.join()"));

        let live = source
            .split_once("fn plan_validated(")
            .unwrap()
            .1
            .split_once("active_guard.finish(outcome)")
            .unwrap()
            .0;
        let codex_dispatch = live.find(".plan_attempt_with_cancellation(").unwrap();
        let finish = live
            .find("let direct_tool_call_termination = direct_tool_call_session.finish()?")
            .unwrap();
        assert!(codex_dispatch < finish);
        let termination = &live[finish..];
        assert!(termination.contains("CancelledBeforeTool"));
        assert!(termination.contains("cancelled.commit_no_dispatch()?"));
        assert!(termination.contains("validate_p0_system_api_listener_reconciliation("));
        assert!(termination.contains("direct_provider_failed_after_listener_cancelled"));
        assert!(!termination.contains("direct_provider_completed_without_p0_system_api_tool_call"));
        assert!(!termination.contains("direct_provider_terminated_before_p0_system_api_tool_call"));
    }

    #[test]
    fn context_capture_expiry_is_rechecked_before_gateway_consume() {
        let now = now_unix_ms();
        let error = super::ensure_context_capture_fresh_at_consume(now, now).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("context_capture_expired_before_gateway_consume")
        );
        super::ensure_context_capture_fresh_at_consume(now.saturating_add(1), now).unwrap();
    }

    #[test]
    fn context_capture_receipt_verification_is_failure_first() {
        let signing_key = fixture_signing_key();
        let pin = fixture_authority_pin(&signing_key);
        let request_id = "context-capture-fixture";
        let capture_id = format!("capture-{}", "a".repeat(64));
        let uid = 10_123;
        let now = now_unix_ms();
        let base = fixture_context_receipt(
            &signing_key,
            request_id,
            &capture_id,
            uid,
            "private context",
            now.saturating_sub(100),
        );
        let encoded = serde_json::to_string(&base).unwrap();
        let verified =
            verify_context_capture_receipt(request_id, &capture_id, uid, &encoded, &pin, now)
                .unwrap();
        verify_context_resolution_content(&verified, "private context").unwrap();
        assert!(verify_context_resolution_content(&verified, "private contexu").is_err());
        assert!(verify_context_resolution_content(&verified, "private context\0").is_err());

        let high_s = high_s_malleate_receipt_json(&encoded);
        let high_s_error =
            verify_context_capture_receipt(request_id, &capture_id, uid, &high_s, &pin, now)
                .err()
                .expect("high-S context receipt must be rejected");
        assert!(high_s_error.to_string().contains("noncanonical_high_s"));

        let mut unsigned = base.clone();
        unsigned.remove("receipt_signature");
        assert!(
            verify_context_capture_receipt(
                request_id,
                &capture_id,
                uid,
                &serde_json::to_string(&unsigned).unwrap(),
                &pin,
                now,
            )
            .is_err()
        );

        let mut tampered = base.clone();
        tampered.insert("content_bytes".to_string(), json!(1));
        assert!(
            verify_context_capture_receipt(
                request_id,
                &capture_id,
                uid,
                &serde_json::to_string(&tampered).unwrap(),
                &pin,
                now,
            )
            .is_err()
        );

        assert!(
            verify_context_capture_receipt(request_id, &capture_id, uid + 1, &encoded, &pin, now,)
                .is_err()
        );

        for (field, value) in [
            ("subject_user_id", json!(1)),
            ("boot_id_sha256", json!("e".repeat(64))),
            ("requesting_signer_sha256", json!("f".repeat(64))),
            (
                "source_id",
                json!(format!(
                    "saf-provider:{}:document:{}",
                    "e".repeat(64),
                    "c".repeat(64)
                )),
            ),
        ] {
            let mut changed = base.clone();
            changed.insert(field.to_string(), value);
            let changed = seal_fixture_context_receipt(&mut changed, &signing_key);
            assert!(
                verify_context_capture_receipt(request_id, &capture_id, uid, &changed, &pin, now,)
                    .is_err(),
                "{field} substitution must fail",
            );
        }

        let mut expired = base;
        let captured = now.saturating_sub(super::CONTEXT_CAPTURE_TTL_MS + 1);
        expired.insert("captured_at_ms".to_string(), json!(captured));
        expired.insert(
            "expires_at_ms".to_string(),
            json!(captured + super::CONTEXT_CAPTURE_TTL_MS),
        );
        let expired = seal_fixture_context_receipt(&mut expired, &signing_key);
        assert!(
            verify_context_capture_receipt(request_id, &capture_id, uid, &expired, &pin, now,)
                .is_err()
        );
    }

    #[test]
    fn context_capture_request_rejects_all_legacy_raw_fields_before_gateway_io() {
        let temp = tempfile::tempdir().unwrap();
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        for raw_field in ["source_kind", "source_id", "content", "freshness_ttl_ms"] {
            let mut payload = json!({
                "capture_id": format!("capture-{}", "a".repeat(64)),
                "capture_receipt": "signed-placeholder",
            });
            payload
                .as_object_mut()
                .unwrap()
                .insert(raw_field.to_string(), json!("caller-controlled"));
            let error = capture_context(
                &contexts,
                &subject,
                "context-capture-raw-denied",
                subject.uid,
                payload,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("context_capture_request_missing_or_unknown_fields")
            );
        }
    }

    #[test]
    fn browser_context_receipt_is_a_disjoint_strict_variant() {
        let signing_key = fixture_signing_key();
        let pin = fixture_authority_pin(&signing_key);
        let request_id = "browser-capture-fixture";
        let capture_id = format!("capture-{}", "1".repeat(64));
        let uid = 10_123;
        let now = now_unix_ms();
        let base = fixture_browser_context_receipt(
            &signing_key,
            request_id,
            &capture_id,
            uid,
            "https://example.com/exact",
            now.saturating_sub(100),
        );
        let verified = verify_context_capture_receipt(
            request_id,
            &capture_id,
            uid,
            &serde_json::to_string(&base).unwrap(),
            &pin,
            now,
        )
        .unwrap();
        assert_eq!(verified.source_kind, "browser");
        verify_context_resolution_content(&verified, "https://example.com/exact").unwrap();
        assert!(verify_context_resolution_content(&verified, "https://example.org/exact").is_err());

        let mut ambiguous = base.clone();
        ambiguous.insert("provider_package".to_string(), json!("attacker.example"));
        let ambiguous = seal_fixture_context_receipt(&mut ambiguous, &signing_key);
        assert!(
            verify_context_capture_receipt(request_id, &capture_id, uid, &ambiguous, &pin, now,)
                .is_err()
        );

        let mut wrong_source = base;
        wrong_source.insert(
            "source_id".to_string(),
            json!(format!("authority-url:{}", "e".repeat(64))),
        );
        let wrong_source = seal_fixture_context_receipt(&mut wrong_source, &signing_key);
        assert!(
            verify_context_capture_receipt(request_id, &capture_id, uid, &wrong_source, &pin, now,)
                .is_err()
        );

        let noncanonical = "https://EXAMPLE.com/exact";
        let noncanonical_receipt = fixture_browser_context_receipt(
            &signing_key,
            request_id,
            &capture_id,
            uid,
            noncanonical,
            now.saturating_sub(100),
        );
        let verified_noncanonical = verify_context_capture_receipt(
            request_id,
            &capture_id,
            uid,
            &serde_json::to_string(&noncanonical_receipt).unwrap(),
            &pin,
            now,
        )
        .unwrap();
        assert!(verify_context_resolution_content(&verified_noncanonical, noncanonical).is_err());
    }

    #[test]
    fn codex_credential_install_is_atomic_private_and_replaceable() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("codex-home");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };

        install_codex_credential(&home, br#"{"auth_mode":"first","tokens":{}}"#, uid, gid).unwrap();
        assert_eq!(
            fs::read(home.join("auth.json")).unwrap(),
            b"{\"auth_mode\":\"first\",\"tokens\":{}}\n"
        );
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(home.join("auth.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        install_codex_credential(&home, br#"{"auth_mode":"second","tokens":{}}"#, uid, gid)
            .unwrap();
        assert_eq!(
            fs::read(home.join("auth.json")).unwrap(),
            b"{\"auth_mode\":\"second\",\"tokens\":{}}\n"
        );
        assert!(fs::read_dir(&home).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".auth.json.tmp-")
        }));
    }

    #[test]
    fn capability_secret_uses_kernel_random_without_dev_nodes() {
        let mut secret = [0u8; 32];
        fill_kernel_random(&mut secret).unwrap();
        assert!(secret.iter().any(|byte| *byte != 0));
    }

    #[test]
    fn agent_executable_measurement_rejects_symlink_and_writable_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let executable = temp.path().join("codex");
        fs::write(&executable, b"measured-agent-binary").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert_eq!(
            measure_executable(&executable, uid).unwrap(),
            super::sha256_bytes(b"measured-agent-binary")
        );
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(measure_executable(&executable, uid).is_err());
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let alias = temp.path().join("codex-link");
        std::os::unix::fs::symlink(&executable, &alias).unwrap();
        assert!(measure_executable(&alias, uid).is_err());
    }

    #[test]
    fn aishell_peer_context_requires_exact_type_and_valid_mls_categories() {
        assert!(is_aishell_security_context("u:r:trillionnium_aishell:s0"));
        assert!(is_aishell_security_context(
            "u:r:trillionnium_aishell:s0:c12,c34"
        ));
        assert!(is_aishell_security_context(
            "u:r:trillionnium_aishell:s0:c12.c34,c100"
        ));
        assert!(!is_aishell_security_context("u:r:trillionnium_aishell:s00"));
        assert!(!is_aishell_security_context(
            "u:r:trillionnium_aishell:s0:evil"
        ));
        assert!(!is_aishell_security_context(
            "u:r:trillionnium_aishell:s0:c34.c12"
        ));
        assert!(!is_aishell_security_context(
            "u:r:trillionnium_aishell:s0:c1024"
        ));
        assert!(!is_aishell_security_context(
            "u:r:trillionnium_aishell:s0:c1,,c2"
        ));
    }

    #[test]
    fn codex_private_parents_are_traversable_but_not_listable() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("trillionnium");
        let home = root.join("agents/codex/home");
        fs::create_dir_all(&home).unwrap();
        for path in [
            &root,
            &root.join("agents"),
            &root.join("agents/codex"),
            &home,
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }

        make_credential_parents_traversable(&home, &root).unwrap();

        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o711
        );
        assert_eq!(
            fs::metadata(root.join("agents"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o711
        );
        assert_eq!(
            fs::metadata(root.join("agents/codex"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o711
        );
        assert_eq!(
            fs::metadata(&home).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn egress_requires_os_minted_single_use_grant() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join("egress-journal.json");
        let store = fixture_egress_store(&journal_path);
        let active = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = fixture_cancellation();
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let context = contexts
            .create_test_context(
                &subject,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:documents",
                    "content": "private payload",
                }),
            )
            .unwrap();
        let registration = fixture_registration();
        let prepare_payload = json!({
            "provider": super::CODEX_PROVIDER_ID,
            "context_id": context["context_id"],
            "intent": "summarize",
            "workflow_id": "workflow-1",
        });
        let prepared = prepare_egress(
            &store,
            &contexts,
            &subject,
            &registration,
            "workflow-1-egress-prepare",
            prepare_payload.clone(),
        )
        .unwrap();
        assert_eq!(prepared.get("network_started"), Some(&json!(false)));
        assert_eq!(prepared.get("content_bytes"), Some(&json!(15)));
        assert!(prepared.get("content").is_none());
        let grant_id = prepared
            .get("egress_grant_id")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        {
            let mut state = store.lock().unwrap();
            let prepared_cas = state.pending.get(grant_id).unwrap().journal_cas.clone();
            let acked = state
                .journal
                .mark_ui_request_completed_exact(
                    grant_id,
                    EgressUiCompletionBinding {
                        method: "prepare_egress",
                        request_id: "workflow-1-egress-prepare",
                        request_payload_sha256: &sha256_bytes(
                            &serde_json::to_vec(&prepare_payload).unwrap(),
                        ),
                        completion_proof_sha256: &sha256_bytes(b"fixture-prepare-completion-proof"),
                        peer_uid: 10_123,
                        peer_selinux_domain: "u:r:trillionnium_aishell:s0",
                        completed_at_ms: now_unix_ms(),
                    },
                )
                .unwrap();
            assert_eq!(acked.binding_sha256, prepared_cas.binding_sha256);
            state.pending.get_mut(grant_id).unwrap().journal_cas = acked;
        }
        let challenge = prepared["consent_challenge"].clone();
        assert_eq!(challenge["intent"], json!("summarize"));
        assert_eq!(challenge["intent_bytes"], json!(9));
        assert_eq!(
            challenge["intent_sha256"],
            json!(sha256_bytes(b"summarize"))
        );
        assert_eq!(challenge["source_kind"], json!("file"));
        assert_eq!(challenge["allowed_actions"], json!([]));
        assert_eq!(
            challenge["allowed_actions_sha256"],
            json!(sha256_json(&json!([])))
        );
        let signing_key = fixture_signing_key();
        let pin = fixture_authority_pin(&signing_key);
        let now = super::now_unix_ms();
        let receipt = fixture_consent_receipt(&challenge, &signing_key, now);
        let mismatch = consume_egress_grant(
            &store,
            10_124,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": receipt,
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .err()
        .expect("identity mismatch must be rejected without burning the grant");
        assert!(
            mismatch.to_string().contains("identity_binding_mismatch"),
            "unexpected wrong-peer denial: {mismatch:#}"
        );
        assert_eq!(
            store.lock().unwrap().journal.state_for_test(grant_id),
            Some(EgressLifecycleState::Prepared)
        );

        let high_s_receipt = high_s_malleate_receipt_json(&receipt);
        let high_s = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": high_s_receipt,
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .err()
        .expect("high-S egress consent must fail without consuming the grant");
        assert!(high_s.to_string().contains("noncanonical_high_s"));
        assert_eq!(
            store.lock().unwrap().journal.state_for_test(grant_id),
            Some(EgressLifecycleState::Prepared)
        );

        let unsigned = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": serde_json::to_string(&challenge).unwrap(),
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .err()
        .expect("unsigned receipt must fail without consuming the grant");
        assert!(unsigned.to_string().contains("missing_or_unknown_fields"));
        assert!(store.lock().unwrap().contains_key(grant_id));
        assert_eq!(
            store.lock().unwrap().journal.state_for_test(grant_id),
            Some(EgressLifecycleState::Prepared)
        );

        let mut tampered: Value = serde_json::from_str(&receipt).unwrap();
        tampered["content_bytes"] = json!(999);
        let tamper = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": serde_json::to_string(&tampered).unwrap(),
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .err()
        .expect("tampered receipt must fail without consuming the grant");
        assert!(tamper.to_string().contains("signature_verification_failed"));
        assert!(store.lock().unwrap().contains_key(grant_id));
        assert_eq!(
            store.lock().unwrap().journal.state_for_test(grant_id),
            Some(EgressLifecycleState::Prepared)
        );

        for (field, value) in [
            ("agent_peer_gid", json!(super::DEFAULT_CODEX_UID + 1)),
            ("intent", json!("changed signed intent")),
            ("source_id_sha256", json!("b".repeat(64))),
            ("allowed_actions", json!(["browser_open_bounded"])),
            ("prompt_contract", json!("changed.prompt-contract.v2")),
        ] {
            let mut changed_challenge = challenge.clone();
            changed_challenge[field] = value;
            if field == "intent" {
                changed_challenge["intent_bytes"] = json!(21);
                changed_challenge["intent_sha256"] = json!(sha256_bytes(b"changed signed intent"));
            } else if field == "allowed_actions" {
                changed_challenge["allowed_actions_sha256"] =
                    json!(sha256_json(&json!(["browser_open_bounded"])));
            }
            let changed_receipt = fixture_consent_receipt(&changed_challenge, &signing_key, now);
            let changed = consume_egress_grant(
                &store,
                10_123,
                "u:r:trillionnium_aishell:s0",
                "workflow-1-plan",
                &json!({
                    "egress_grant_id": grant_id,
                    "provider": super::CODEX_PROVIDER_ID,
                    "consent_receipt": changed_receipt,
                    "workflow_id": "workflow-1",
                }),
                &pin,
                &active,
                &cancellation,
                now,
            )
            .err()
            .expect("a differently signed material binding must not consume the grant");
            assert!(
                changed
                    .to_string()
                    .contains("egress_consent_challenge_field_mismatch")
            );
            assert!(store.lock().unwrap().contains_key(grant_id));
        }

        {
            let mut grants = store.lock().unwrap();
            grants.get_mut(grant_id).unwrap().intent =
                Zeroizing::new("changed pending intent".to_string());
        }
        let changed_pending_intent = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": receipt,
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .err()
        .expect("changed pending intent must fail before single-use consumption");
        assert!(
            changed_pending_intent
                .to_string()
                .contains("intent_material_mismatch")
        );
        assert!(store.lock().unwrap().contains_key(grant_id));
        {
            let mut grants = store.lock().unwrap();
            grants.get_mut(grant_id).unwrap().intent = Zeroizing::new("summarize".to_string());
            grants.get_mut(grant_id).unwrap().source_id =
                Zeroizing::new("changed-source".to_string());
        }
        let changed_pending_source = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": receipt,
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .err()
        .expect("changed pending source must fail before single-use consumption");
        assert!(
            changed_pending_source
                .to_string()
                .contains("source_id_sha256")
        );
        assert!(store.lock().unwrap().contains_key(grant_id));
        {
            let mut grants = store.lock().unwrap();
            let grant = grants.get_mut(grant_id).unwrap();
            grant.source_id = Zeroizing::new("saf:documents".to_string());
            grant
                .allowed_actions
                .push("browser_open_bounded".to_string());
        }
        let changed_pending_actions = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": receipt,
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .err()
        .expect("changed pending actions must fail before single-use consumption");
        assert!(
            changed_pending_actions
                .to_string()
                .contains("allowed_actions_material_mismatch")
        );
        assert!(store.lock().unwrap().contains_key(grant_id));
        store
            .lock()
            .unwrap()
            .get_mut(grant_id)
            .unwrap()
            .allowed_actions
            .clear();

        let (_, consumed, receipt_id) = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": receipt,
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .unwrap();
        assert_eq!(consumed.content.as_str(), "private payload");
        assert_eq!(receipt_id.len(), 64);
        assert_eq!(
            store.lock().unwrap().journal.state_for_test(grant_id),
            Some(EgressLifecycleState::Consumed)
        );
        // A real provider freezes this lifecycle binding before dispatch. Do
        // the same before the revoke worker can transition to REVOKE_PENDING;
        // the teardown acknowledgement is intentionally published only after
        // that durable transition.
        freeze_test_predispatch_binding(&store, &active, grant_id);
        let store_for_revoke = Arc::clone(&store);
        let active_for_revoke = Arc::clone(&active);
        let grant_for_revoke = grant_id.to_string();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let revoke_worker = std::thread::spawn(move || {
            result_tx
                .send(revoke_egress(
                    &store_for_revoke,
                    &active_for_revoke,
                    10_123,
                    "u:r:trillionnium_aishell:s0",
                    "workflow-1-revoke",
                    json!({
                        "egress_grant_id": grant_for_revoke,
                        "workflow_id": "workflow-1",
                    }),
                ))
                .unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while !cancellation.is_cancelled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            cancellation.is_cancelled(),
            "revoke did not durably enter REVOKE_PENDING"
        );
        publish_test_teardown_ack(&store, &cancellation, &active, grant_id, "caller");
        let revoked = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("revoke did not finish after teardown acknowledgement")
            .unwrap();
        revoke_worker.join().unwrap();
        assert_eq!(revoked["active_run_cancelled"], json!(true));
        assert!(cancellation.is_cancelled());
        assert_eq!(
            store.lock().unwrap().journal.state_for_test(grant_id),
            Some(EgressLifecycleState::Revoked)
        );
        active.lock().unwrap().remove(grant_id);
        let replay = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": receipt,
                "workflow_id": "workflow-1",
            }),
            &pin,
            &active,
            &cancellation,
            now,
        )
        .err()
        .expect("consumed grant must reject replay");
        assert!(replay.to_string().contains("unknown_or_consumed"));

        let restarted_store = fixture_egress_store(&journal_path);
        let restarted_active = Arc::new(Mutex::new(HashMap::new()));
        let restart = consume_egress_grant(
            &restarted_store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-1-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": receipt,
                "workflow_id": "workflow-1",
            }),
            &pin,
            &restarted_active,
            &fixture_cancellation(),
            now,
        )
        .err()
        .expect("daemon restart must fail closed on an orphaned receipt");
        assert!(restart.to_string().contains("unknown_or_consumed"));
    }

    #[test]
    fn legacy_client_asserted_network_approval_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let store = fixture_egress_store(&temp.path().join("egress-journal.json"));
        let active = Arc::new(Mutex::new(HashMap::new()));
        let signing_key = fixture_signing_key();
        let error = consume_egress_grant(
            &store,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "request-legacy",
            &json!({
                "egress_grant_id": "egress-not-issued",
                "provider": super::CODEX_PROVIDER_ID,
                "user_confirmed": true,
                "network_approved": true,
                "consent_receipt": "unsigned",
                "workflow_id": "workflow-legacy",
            }),
            &fixture_authority_pin(&signing_key),
            &active,
            &fixture_cancellation(),
            super::now_unix_ms(),
        )
        .err()
        .expect("legacy assertion must be rejected");
        assert!(error.to_string().contains("missing_or_unknown_fields"));
    }

    #[test]
    fn daemon_reconstruction_invalidates_prepared_egress_without_revival() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join("egress-journal.json");
        let store = fixture_egress_store(&journal_path);
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let context = contexts
            .create_test_context(
                &subject,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:restart",
                    "content": "restart private payload",
                }),
            )
            .unwrap();
        let prepared = prepare_egress(
            &store,
            &contexts,
            &subject,
            &fixture_registration(),
            "workflow-restart-egress-prepare",
            json!({
                "provider": super::CODEX_PROVIDER_ID,
                "context_id": context["context_id"],
                "intent": "summarize after restart",
                "workflow_id": "workflow-restart",
            }),
        )
        .unwrap();
        let grant_id = prepared["egress_grant_id"].as_str().unwrap().to_string();
        assert_eq!(
            store.lock().unwrap().journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Prepared)
        );
        drop(store);

        let reconstructed = fixture_egress_store(&journal_path);
        assert!(reconstructed.lock().unwrap().pending.is_empty());
        assert_eq!(
            reconstructed
                .lock()
                .unwrap()
                .journal
                .state_for_test(&grant_id),
            Some(EgressLifecycleState::Prepared)
        );
        let denied = consume_egress_grant(
            &reconstructed,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-restart-plan",
            &json!({
                "egress_grant_id": grant_id,
                "provider": super::CODEX_PROVIDER_ID,
                "consent_receipt": "orphaned-after-restart",
                "workflow_id": "workflow-restart",
            }),
            &fixture_authority_pin(&fixture_signing_key()),
            &Arc::new(Mutex::new(HashMap::new())),
            &fixture_cancellation(),
            now_unix_ms(),
        )
        .err()
        .expect("restart-invalidated grant must never be reconstructed in memory");
        assert!(denied.to_string().contains("unknown_or_consumed"));
    }

    #[test]
    fn expiry_reaper_writes_tombstone_before_dropping_pending_material() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join("egress-journal.json");
        let store = fixture_egress_store(&journal_path);
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let context = contexts
            .create_test_context(
                &subject,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:expiry",
                    "content": "expiring private payload",
                }),
            )
            .unwrap();
        let prepared = prepare_egress(
            &store,
            &contexts,
            &subject,
            &fixture_registration(),
            "workflow-expiry-egress-prepare",
            json!({
                "provider": super::CODEX_PROVIDER_ID,
                "context_id": context["context_id"],
                "intent": "expire this grant",
                "workflow_id": "workflow-expiry",
            }),
        )
        .unwrap();
        let grant_id = prepared["egress_grant_id"].as_str().unwrap().to_string();
        let expires_at_ms = prepared["expires_at_ms"].as_u64().unwrap();
        {
            let mut state = store.lock().unwrap();
            super::expire_pending_egress_grants(&mut state, &contexts, expires_at_ms).unwrap();
            assert!(state.pending.is_empty());
            assert_eq!(
                state.journal.state_for_test(&grant_id),
                Some(EgressLifecycleState::Expired)
            );
        }
        drop(store);
        let reconstructed = fixture_egress_store(&journal_path);
        assert_eq!(
            reconstructed
                .lock()
                .unwrap()
                .journal
                .state_for_test(&grant_id),
            Some(EgressLifecycleState::Expired)
        );
    }

    #[test]
    fn active_egress_revoke_is_failure_first_and_identity_bound() {
        let temp = tempfile::tempdir().unwrap();
        let pending = fixture_egress_store(&temp.path().join("egress-journal.json"));
        let active = Arc::new(Mutex::new(HashMap::new()));
        let wait_entered = Arc::new(std::sync::Barrier::new(2));
        let mut cancellation = fixture_cancellation();
        cancellation.wait_entered_barrier = Some(Arc::clone(&wait_entered));
        let grant_id = format!("egress-{}", "b".repeat(64));
        let expected_journal_binding_sha256 = insert_active_egress_fixture(
            &pending,
            &active,
            &cancellation,
            &grant_id,
            "workflow-active",
        );
        let mismatch = revoke_egress(
            &pending,
            &active,
            10_124,
            "u:r:trillionnium_aishell:s0",
            "workflow-active-revoke-wrong-peer",
            json!({
                "egress_grant_id": grant_id,
                "workflow_id": "workflow-active",
            }),
        )
        .expect_err("wrong UI identity must not cancel an active provider");
        assert!(
            mismatch
                .to_string()
                .contains("status_subject_binding_mismatch"),
            "unexpected wrong-peer denial: {mismatch:#}"
        );
        assert!(!cancellation.is_cancelled());
        assert!(active.lock().unwrap().contains_key(&grant_id));
        assert_eq!(
            pending.lock().unwrap().journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Consumed)
        );

        active
            .lock()
            .unwrap()
            .get_mut(&grant_id)
            .unwrap()
            .journal_binding_sha256 = "f".repeat(64);
        let binding_mismatch = revoke_egress(
            &pending,
            &active,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-active-revoke-wrong-binding",
            json!({
                "egress_grant_id": grant_id,
                "workflow_id": "workflow-active",
            }),
        )
        .expect_err("journal binding mismatch must fail before runtime cancellation");
        assert!(binding_mismatch.to_string().contains("binding_mismatch"));
        assert!(!cancellation.is_cancelled());
        assert_eq!(
            active.lock().unwrap().get(&grant_id).unwrap().durability,
            super::ActiveEgressDurability::Running
        );
        active
            .lock()
            .unwrap()
            .get_mut(&grant_id)
            .unwrap()
            .journal_binding_sha256 = expected_journal_binding_sha256;

        let pending_for_revoke = Arc::clone(&pending);
        let active_for_revoke = Arc::clone(&active);
        let grant_for_revoke = grant_id.clone();
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            result_tx
                .send(revoke_egress(
                    &pending_for_revoke,
                    &active_for_revoke,
                    10_123,
                    "u:r:trillionnium_aishell:s0",
                    "workflow-active-revoke",
                    json!({
                        "egress_grant_id": grant_for_revoke,
                        "workflow_id": "workflow-active",
                    }),
                ))
                .unwrap();
        });
        wait_entered.wait();
        publish_test_teardown_ack(&pending, &cancellation, &active, &grant_id, "caller");
        let revoked = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("identity-bound revoke did not finish after exact teardown ack")
            .unwrap();
        worker.join().unwrap();
        assert!(cancellation.is_cancelled());
        assert_eq!(revoked["active_run_cancelled"], json!(true));
        assert_eq!(revoked["network_started"], json!(true));
        assert_eq!(
            pending.lock().unwrap().journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Revoked)
        );
    }

    #[test]
    fn active_egress_revoke_waits_for_provider_and_proxy_teardown() {
        let temp = tempfile::tempdir().unwrap();
        let pending = fixture_egress_store(&temp.path().join("egress-journal.json"));
        let active = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = fixture_cancellation();
        let grant_id = format!("egress-{}", "7".repeat(64));
        let _journal_binding_sha256 = insert_active_egress_fixture(
            &pending,
            &active,
            &cancellation,
            &grant_id,
            "workflow-teardown-ack",
        );

        let pending_for_revoke = Arc::clone(&pending);
        let active_for_revoke = Arc::clone(&active);
        let grant_for_revoke = grant_id.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = revoke_egress(
                &pending_for_revoke,
                &active_for_revoke,
                10_123,
                "u:r:trillionnium_aishell:s0",
                "workflow-teardown-ack-revoke",
                json!({
                    "egress_grant_id": grant_for_revoke,
                    "workflow_id": "workflow-teardown-ack",
                }),
            );
            sender.send(result).unwrap();
        });

        let deadline = Instant::now() + Duration::from_secs(1);
        while !cancellation.is_cancelled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            cancellation.is_cancelled(),
            "revoke returned before durable cancellation: {:?}",
            receiver.try_recv()
        );
        assert!(receiver.try_recv().is_err());
        assert!(active.lock().unwrap().contains_key(&grant_id));

        publish_test_teardown_ack(&pending, &cancellation, &active, &grant_id, "caller");
        let revoked = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("revoke should return after teardown acknowledgement")
            .unwrap();
        worker.join().unwrap();
        assert_eq!(revoked["active_run_cancelled"], json!(true));
        assert!(!active.lock().unwrap().contains_key(&grant_id));
        assert_eq!(
            pending.lock().unwrap().journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Revoked)
        );
    }

    #[test]
    fn active_revoke_write_fault_does_not_cancel_before_durable_pending_and_is_retryable() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join("egress-journal.json");
        let pending = fixture_egress_store(&journal_path);
        let active = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = fixture_cancellation();
        let grant_id = format!("egress-{}", "4".repeat(64));
        insert_active_egress_fixture(
            &pending,
            &active,
            &cancellation,
            &grant_id,
            "workflow-active",
        );
        let durable_before_fault = fs::read(&journal_path).unwrap();
        fs::write(&journal_path, b"{external-journal-write-fault").unwrap();

        let fault = revoke_egress(
            &pending,
            &active,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-active-revoke-write-fault",
            json!({
                "egress_grant_id": grant_id,
                "workflow_id": "workflow-active",
            }),
        )
        .expect_err("durable write fault must not be reported as successful revoke");
        assert!(
            fault.to_string().contains("changed_outside_atomic_writer"),
            "unexpected journal-fault result: {fault:#}"
        );
        assert!(!cancellation.is_cancelled());
        assert_eq!(
            active.lock().unwrap().get(&grant_id).unwrap().durability,
            super::ActiveEgressDurability::Running
        );
        assert_eq!(
            pending.lock().unwrap().journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Consumed)
        );
        fs::write(&journal_path, durable_before_fault).unwrap();
        let pending_for_retry = Arc::clone(&pending);
        let active_for_retry = Arc::clone(&active);
        let grant_for_retry = grant_id.clone();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = revoke_egress(
                &pending_for_retry,
                &active_for_retry,
                10_123,
                "u:r:trillionnium_aishell:s0",
                "workflow-active-revoke-write-fault",
                json!({
                    "egress_grant_id": grant_for_retry,
                    "workflow_id": "workflow-active",
                }),
            );
            sender.send(result).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !cancellation.is_cancelled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(cancellation.is_cancelled());
        assert!(receiver.try_recv().is_err());
        publish_test_teardown_ack(&pending, &cancellation, &active, &grant_id, "caller");
        let recovered = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("revoke retry should finish after exact teardown evidence")
            .unwrap();
        worker.join().unwrap();
        assert_eq!(recovered["revoked"], json!(true));
        assert_eq!(recovered["active_run_cancelled"], json!(true));
        assert!(!active.lock().unwrap().contains_key(&grant_id));
        assert_eq!(
            pending.lock().unwrap().journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Revoked)
        );
        drop(pending);
        assert_eq!(
            fixture_egress_store(&journal_path)
                .lock()
                .unwrap()
                .journal
                .state_for_test(&grant_id),
            Some(EgressLifecycleState::Revoked)
        );
    }

    #[test]
    fn normal_completion_fault_fails_closed_then_reaper_recovers_completed_tombstone() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join("egress-journal.json");
        let pending = fixture_egress_store(&journal_path);
        let active = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = fixture_cancellation();
        let grant_id = format!("egress-{}", "5".repeat(64));
        insert_active_egress_fixture(
            &pending,
            &active,
            &cancellation,
            &grant_id,
            "workflow-active",
        );
        publish_test_teardown_ack(&pending, &cancellation, &active, &grant_id, "completed");
        let durable_before_fault = fs::read(&journal_path).unwrap();
        fs::write(&journal_path, b"{external-completion-write-fault").unwrap();

        let completion = super::ActiveEgressGuard {
            egress_grants: Arc::clone(&pending),
            store: Arc::clone(&active),
            grant_id: grant_id.clone(),
            cancellation: cancellation.clone(),
            finalized: false,
        }
        .finish(Ok(json!({"provider_finished": true})))
        .expect_err("completion must fail closed when its tombstone is not durable");
        assert!(
            completion
                .to_string()
                .contains("completion_durability_pending")
        );
        assert!(!cancellation.is_cancelled());
        assert_eq!(
            active.lock().unwrap().get(&grant_id).unwrap().durability,
            super::ActiveEgressDurability::CompletionPending
        );
        assert_eq!(
            pending.lock().unwrap().journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Consumed)
        );

        fs::write(&journal_path, durable_before_fault).unwrap();
        assert_eq!(
            super::retry_pending_active_egress_durability(&pending, &active).unwrap(),
            1
        );
        assert!(!active.lock().unwrap().contains_key(&grant_id));
        {
            let mut state = pending.lock().unwrap();
            assert_eq!(
                state.journal.state_for_test(&grant_id),
                Some(EgressLifecycleState::Completed)
            );
            assert_eq!(
                state.journal.compact_terminal_prefix_for_test(1).unwrap(),
                1
            );
            assert_eq!(state.journal.state_for_test(&grant_id), None);
        }
        drop(pending);
        assert_eq!(
            fixture_egress_store(&journal_path)
                .lock()
                .unwrap()
                .journal
                .state_for_test(&grant_id),
            None
        );
    }

    #[test]
    fn normal_completion_is_durable_before_active_run_removal() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join("egress-journal.json");
        let pending = fixture_egress_store(&journal_path);
        let active = Arc::new(Mutex::new(HashMap::new()));
        let cancellation = fixture_cancellation();
        let grant_id = format!("egress-{}", "6".repeat(64));
        insert_active_egress_fixture(
            &pending,
            &active,
            &cancellation,
            &grant_id,
            "workflow-active",
        );
        publish_test_teardown_ack(&pending, &cancellation, &active, &grant_id, "completed");
        let outcome = super::ActiveEgressGuard {
            egress_grants: Arc::clone(&pending),
            store: Arc::clone(&active),
            grant_id: grant_id.clone(),
            cancellation: cancellation.clone(),
            finalized: false,
        }
        .finish(Ok(json!({"provider_finished": true})))
        .unwrap();
        assert_eq!(outcome["provider_finished"], json!(true));
        assert!(!cancellation.is_cancelled());
        assert!(!active.lock().unwrap().contains_key(&grant_id));
        assert_eq!(
            pending.lock().unwrap().journal.state_for_test(&grant_id),
            Some(EgressLifecycleState::Completed)
        );
    }

    #[test]
    fn pending_egress_can_be_revoked_before_network_use() {
        let temp = tempfile::tempdir().unwrap();
        let store = fixture_egress_store(&temp.path().join("egress-journal.json"));
        let active = Arc::new(Mutex::new(HashMap::new()));
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let context = contexts
            .create_test_context(
                &subject,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:test-revoke",
                    "content": "mail=2",
                }),
            )
            .unwrap();
        let registration = fixture_registration();
        let prepared = prepare_egress(
            &store,
            &contexts,
            &subject,
            &registration,
            "workflow-revoke-egress-prepare",
            json!({
                "provider": super::CODEX_PROVIDER_ID,
                "context_id": context["context_id"],
                "intent": "organize",
                "workflow_id": "workflow-revoke",
            }),
        )
        .unwrap();
        let grant_id = prepared
            .get("egress_grant_id")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        let revoked = revoke_egress(
            &store,
            &active,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "request-revoke",
            json!({
                "egress_grant_id": grant_id,
                "workflow_id": "workflow-revoke",
            }),
        )
        .unwrap();
        assert_eq!(revoked.get("revoked"), Some(&json!(true)));
        assert!(store.lock().unwrap().is_empty());
        assert_eq!(
            store.lock().unwrap().journal.state_for_test(grant_id),
            Some(EgressLifecycleState::RevokedBeforeDispatch)
        );
    }

    #[test]
    fn action_consent_requires_hardware_signature_and_exact_frozen_binding() {
        let now = now_unix_ms();
        let binding = AgentExecutionBinding {
            agent_id: super::CODEX_AGENT_ID.to_string(),
            peer_uid: super::DEFAULT_CODEX_UID,
            peer_gid: super::DEFAULT_CODEX_UID,
            peer_selinux_domain: super::CODEX_AGENT_SELINUX_DOMAIN.to_string(),
            agent_executable_sha256: "a".repeat(64),
            subject_user_id: 0,
            origin_uid: 10_123,
            origin_selinux_domain: "u:r:trillionnium_aishell:s0".to_string(),
            session_id: "android-ui-10123-workflow-action".to_string(),
            task_id: TaskId("task-action-consent".to_string()),
            plan_id: "plan-action-consent".to_string(),
            action_id: "action-action-consent".to_string(),
            tool_call_id: ToolCallId("toolcall-agent-action-consent".to_string()),
            tool_name: "android.browser.open_bounded".to_string(),
            tool_manifest_sha256: "b".repeat(64),
            accepted_plan_sha256: "c".repeat(64),
            arguments_sha256: "d".repeat(64),
        };
        let approval = ApprovalRequest {
            id: "approval-action-consent".to_string(),
            task_id: binding.task_id.clone(),
            tool_call_id: binding.tool_call_id.clone(),
            tool_name: binding.tool_name.clone(),
            reason: "OS policy requires explicit action consent".to_string(),
            status: ApprovalStatus::Pending,
            created_at_unix_ms: now,
            decided_at_unix_ms: None,
            decision_reason: None,
            tool_manifest_sha256: None,
        };
        let canonical_url = "https://example.test/action";
        let action_payload = json!({"url": canonical_url});
        let execution_payload_sha256 = sha256_json(&action_payload);
        let challenge = build_action_consent_challenge(
            &binding,
            &approval,
            "workflow-action",
            &"e".repeat(64),
            &"f".repeat(64),
            &action_payload,
            &execution_payload_sha256,
            now,
        )
        .unwrap();
        assert_eq!(
            challenge["challenge_schema"],
            json!(super::ACTION_CONSENT_CHALLENGE_SCHEMA)
        );
        assert_eq!(challenge["action_payload"], action_payload);
        let signing_key = fixture_signing_key();
        let pin = fixture_authority_pin(&signing_key);
        let receipt = fixture_signed_consent_receipt(
            &challenge,
            &signing_key,
            now,
            ACTION_CONSENT_SCHEMA,
            "ALLOW_ACTION",
        );
        let receipt_id = verify_action_consent_receipt(
            &challenge,
            "workflow-action-approve",
            &receipt,
            &pin,
            now,
        )
        .unwrap();
        assert_eq!(receipt_id.len(), 64);

        let high_s = high_s_malleate_receipt_json(&receipt);
        let high_s_error = verify_action_consent_receipt(
            &challenge,
            "workflow-action-approve",
            &high_s,
            &pin,
            now,
        )
        .expect_err("high-S action consent must be rejected");
        assert!(high_s_error.to_string().contains("noncanonical_high_s"));

        let unsigned = verify_action_consent_receipt(
            &challenge,
            "workflow-action-approve",
            &serde_json::to_string(&challenge).unwrap(),
            &pin,
            now,
        )
        .unwrap_err();
        assert!(unsigned.to_string().contains("missing_or_unknown_fields"));

        let mut tampered: Value = serde_json::from_str(&receipt).unwrap();
        tampered["task_id"] = json!("task-attacker");
        let tampered = verify_action_consent_receipt(
            &challenge,
            "workflow-action-approve",
            &serde_json::to_string(&tampered).unwrap(),
            &pin,
            now,
        )
        .unwrap_err();
        assert!(
            tampered
                .to_string()
                .contains("signature_verification_failed")
        );

        let mut wrong_challenge = challenge.clone();
        wrong_challenge["plan_id"] = json!("plan-wrong-binding");
        let wrong_receipt = fixture_signed_consent_receipt(
            &wrong_challenge,
            &signing_key,
            now,
            ACTION_CONSENT_SCHEMA,
            "ALLOW_ACTION",
        );
        let wrong_binding = verify_action_consent_receipt(
            &challenge,
            "workflow-action-approve",
            &wrong_receipt,
            &pin,
            now,
        )
        .unwrap_err();
        assert!(
            wrong_binding
                .to_string()
                .contains("challenge_field_mismatch:plan_id")
        );

        let mut wrong_gid_challenge = challenge.clone();
        wrong_gid_challenge["agent_peer_gid"] = json!(super::DEFAULT_CODEX_UID + 1);
        let wrong_gid_receipt = fixture_signed_consent_receipt(
            &wrong_gid_challenge,
            &signing_key,
            now,
            ACTION_CONSENT_SCHEMA,
            "ALLOW_ACTION",
        );
        let wrong_gid = verify_action_consent_receipt(
            &challenge,
            "workflow-action-approve",
            &wrong_gid_receipt,
            &pin,
            now,
        )
        .unwrap_err();
        assert!(
            wrong_gid
                .to_string()
                .contains("challenge_field_mismatch:agent_peer_gid")
        );

        let wrong_key = SigningKey::from_slice(&[8u8; 32]).unwrap();
        let wrong_pin = verify_action_consent_receipt(
            &challenge,
            "workflow-action-approve",
            &receipt,
            &fixture_authority_pin(&wrong_key),
            now,
        )
        .unwrap_err();
        assert!(
            wrong_pin
                .to_string()
                .contains("receipt_signing_key_id_frozen_value_mismatch")
        );

        let mut consumed = approval;
        consumed.status = ApprovalStatus::Approved;
        assert!(
            build_action_consent_challenge(
                &binding,
                &consumed,
                "workflow-action",
                &"e".repeat(64),
                &"f".repeat(64),
                &action_payload,
                &execution_payload_sha256,
                now,
            )
            .unwrap_err()
            .to_string()
            .contains("frozen_binding_denied")
        );
    }

    #[test]
    fn notification_action_consent_v2_binds_exact_closed_payload_and_no_network() {
        let now = now_unix_ms();
        let binding = AgentExecutionBinding {
            agent_id: super::CODEX_AGENT_ID.to_string(),
            peer_uid: super::DEFAULT_CODEX_UID,
            peer_gid: super::DEFAULT_CODEX_UID,
            peer_selinux_domain: super::CODEX_AGENT_SELINUX_DOMAIN.to_string(),
            agent_executable_sha256: "a".repeat(64),
            subject_user_id: 0,
            origin_uid: 10_123,
            origin_selinux_domain: "u:r:trillionnium_aishell:s0".to_string(),
            session_id: "android-ui-10123-workflow-notification".to_string(),
            task_id: TaskId("task-notification-consent".to_string()),
            plan_id: "plan-notification-consent".to_string(),
            action_id: "action-notification-consent".to_string(),
            tool_call_id: ToolCallId("toolcall-agent-notification-consent".to_string()),
            tool_name: super::NOTIFICATION_TOOL.to_string(),
            tool_manifest_sha256: "b".repeat(64),
            accepted_plan_sha256: "c".repeat(64),
            arguments_sha256: "d".repeat(64),
        };
        let approval = ApprovalRequest {
            id: "approval-notification-consent".to_string(),
            task_id: binding.task_id.clone(),
            tool_call_id: binding.tool_call_id.clone(),
            tool_name: binding.tool_name.clone(),
            reason: "OS policy requires explicit action consent".to_string(),
            status: ApprovalStatus::Pending,
            created_at_unix_ms: now,
            decided_at_unix_ms: None,
            decision_reason: None,
            tool_manifest_sha256: None,
        };
        let payload = json!({
            "title": "精确提醒",
            "body": "Only this exact Authority-owned notification."
        });
        let payload_sha256 = sha256_json(&payload);
        let challenge = build_action_consent_challenge(
            &binding,
            &approval,
            "workflow-notification",
            &"e".repeat(64),
            &"f".repeat(64),
            &payload,
            &payload_sha256,
            now,
        )
        .unwrap();
        assert_eq!(challenge["action_payload"], payload);
        assert_eq!(challenge["execution_payload_sha256"], payload_sha256);
        assert_eq!(challenge["network_scope"], "none");
        assert_eq!(challenge["tool_name"], super::NOTIFICATION_TOOL);

        for denied in [
            json!({"title": "ok", "body": "ok", "tag": "attacker"}),
            json!({"title": " \t", "body": "ok"}),
            json!({"title": "bad\nline", "body": "ok"}),
            json!({"title": "ok", "body": "x".repeat(1_001)}),
        ] {
            assert!(
                build_action_consent_challenge(
                    &binding,
                    &approval,
                    "workflow-notification",
                    &"e".repeat(64),
                    &"f".repeat(64),
                    &denied,
                    &sha256_json(&denied),
                    now,
                )
                .is_err(),
                "{denied}"
            );
        }
        assert!(
            build_action_consent_challenge(
                &binding,
                &approval,
                "workflow-notification",
                &"e".repeat(64),
                &"f".repeat(64),
                &payload,
                &"0".repeat(64),
                now,
            )
            .unwrap_err()
            .to_string()
            .contains("digest_mismatch")
        );
    }

    #[test]
    fn memory_context_selection_wrapper_is_user_bound_and_closed_world() {
        let root = tempfile::tempdir().unwrap();
        let memory = ContextMemoryService::open(root.path().join("context-memory")).unwrap();
        let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        for denied in [
            json!({}),
            json!({"memory_id": "memory-", "extra": true}),
            json!({"memory_id": 7}),
        ] {
            assert!(super::select_memory_context(&memory, &subject, denied).is_err());
        }
        let unknown = super::select_memory_context(
            &memory,
            &subject,
            json!({
                "memory_id": format!("memory-{}", "a".repeat(64)),
                "expected_payload_sha256": "b".repeat(64),
                "expected_updated_at_ms": 1,
            }),
        )
        .unwrap_err()
        .to_string();
        assert!(unknown.contains("unknown_or_unavailable_memory_selection"));

        let user_one = Subject::new(110_123, "u:r:trillionnium_aishell:s0").unwrap();
        let denied = super::select_memory_context(
            &memory,
            &user_one,
            json!({
                "memory_id": format!("memory-{}", "a".repeat(64)),
                "expected_payload_sha256": "b".repeat(64),
                "expected_updated_at_ms": 1,
            }),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(denied, super::ANDROID_USER_ZERO_CUSTODY_ERROR);
    }

    #[test]
    fn context_actions_are_fixed_for_file_browser_and_memory() {
        assert_eq!(
            super::allowed_actions_for_context("file").unwrap(),
            vec![super::NOTIFICATION_ACTION.to_string()]
        );
        assert_eq!(
            super::allowed_actions_for_context("memory").unwrap(),
            vec![super::NOTIFICATION_ACTION.to_string()]
        );
        assert_eq!(
            super::allowed_actions_for_context("browser").unwrap(),
            vec![
                super::BROWSER_ACTION.to_string(),
                super::NOTIFICATION_ACTION.to_string(),
            ]
        );
        assert!(super::allowed_actions_for_context("notifications").is_err());

        let browser = super::bounded_action_contract(super::BROWSER_TOOL).unwrap();
        assert_eq!(browser.action, super::BROWSER_ACTION);
        assert_eq!(browser.receipt_network_scope, "exact_https_url_once");
        assert!(!browser.undo_supported);
        let notification = super::bounded_action_contract(super::NOTIFICATION_TOOL).unwrap();
        assert_eq!(notification.action, super::NOTIFICATION_ACTION);
        assert_eq!(notification.plan_network_scope, "none");
        assert_eq!(notification.argument_network_scope, "none");
        assert_eq!(notification.receipt_network_scope, "none");
        assert_eq!(
            notification.undo_contract,
            super::NOTIFICATION_UNDO_CONTRACT
        );
        assert!(notification.undo_supported);

        let notification_payload = json!({"title": "Reminder", "body": "Exact body"});
        assert_eq!(
            super::frozen_tool_payload_sha256(super::NOTIFICATION_TOOL, &notification_payload,)
                .unwrap(),
            sha256_json(&notification_payload)
        );
        let browser_payload_sha256 = "a".repeat(64);
        assert_eq!(
            super::frozen_tool_payload_sha256(
                super::BROWSER_TOOL,
                &json!({
                    "execution_payload_ref": format!("execution-payload-{}", "b".repeat(64)),
                    "execution_payload_sha256": browser_payload_sha256,
                    "execution_payload_shape": "exact_https_url.v1",
                }),
            )
            .unwrap(),
            "a".repeat(64)
        );
    }

    #[test]
    fn memory_context_egress_disables_legacy_actions_for_codex_and_reopens() {
        let temp = tempfile::tempdir().unwrap();
        let journal_path = temp.path().join("memory-egress-journal.json");
        let store = fixture_egress_store(&journal_path);
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let imported = contexts
            .create_test_context(
                &subject,
                json!({
                    "source_kind": "memory_import",
                    "source_id": "import:memory-egress-dual-provider",
                    "content": "same encrypted Memory plaintext",
                }),
            )
            .unwrap();
        let saved = contexts
            .call(
                "save_memory",
                "memory-egress-save",
                &subject,
                json!({
                    "context_id": imported["context_id"],
                    "payload": "same encrypted Memory plaintext",
                    "receipt_id": "",
                    "taint_lineage": "user_imported",
                }),
            )
            .unwrap();
        let memory_context = contexts
            .materialize_memory_planning_context(&subject, saved["memory_id"].as_str().unwrap())
            .unwrap();
        let mut grant_ids = Vec::new();
        let (descriptor, workflow) = (&super::CODEX, "workflow-memory-codex");
        let mut registration = fixture_registration();
        bind_fixture_registration(&mut registration, descriptor);
        let prepared = prepare_egress(
            &store,
            &contexts,
            &subject,
            &registration,
            &format!("{workflow}-egress-prepare"),
            json!({
                "provider": descriptor.provider_id,
                "context_id": memory_context["context_id"],
                "intent": "plan one bounded notification",
                "workflow_id": workflow,
            }),
        )
        .unwrap();
        assert_eq!(prepared["consent_challenge"]["source_kind"], "memory");
        assert_eq!(prepared["consent_challenge"]["allowed_actions"], json!([]));
        grant_ids.push(prepared["egress_grant_id"].as_str().unwrap().to_string());
        drop(store);
        let reopened = fixture_egress_store(&journal_path);
        for grant_id in grant_ids {
            assert_eq!(
                reopened.lock().unwrap().journal.state_for_test(&grant_id),
                Some(EgressLifecycleState::Prepared)
            );
        }
    }

    #[test]
    fn authority_undo_identity_is_derived_only_from_original_receipt() {
        let source_receipt_id = "c".repeat(64);
        let gateway_request_id = super::authority_undo_request_id(&source_receipt_id).unwrap();
        assert_eq!(gateway_request_id, format!("undo-{source_receipt_id}"));
        // Outer OS-UI request IDs are correlation/replay identities only. A
        // changed outer ID cannot mint a different Authority undo identity.
        for _outer_request_id in ["workflow-undo", "workflow-undo-retry-attacker"] {
            assert_eq!(
                super::authority_undo_request_id(&source_receipt_id).unwrap(),
                gateway_request_id
            );
        }
        assert!(super::authority_undo_request_id("not-a-receipt").is_err());
    }

    #[test]
    fn legacy_provider_ready_reopen_is_terminal_without_plan_or_authority_dispatch() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let memory = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let service = AgentService::in_memory().unwrap();
        let provider = fixture_provider_ready_saga(&service, "provider-ready-restart");
        let path = temp.path().join("action-workflow.json");
        let mut journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        store_provider_ready_saga(&mut journal, &memory, &provider);
        drop(journal);

        let journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let store = Arc::new(Mutex::new(journal));
        super::resume_local_plan_saga(&service, &store, &memory, &provider.request_id).unwrap();
        match store
            .lock()
            .unwrap()
            .recover_plan(
                &memory,
                &provider.request_id,
                &provider.request_payload_sha256,
                provider.peer_uid,
                &provider.peer_domain,
            )
            .unwrap()
        {
            crate::action_workflow::PlanWorkflowRecovery::Indeterminate(reason) => {
                assert_eq!(reason, super::RETIRED_NON_DIRECT_WORKFLOW_REASON)
            }
            other => panic!("legacy provider state escaped quarantine: {other:?}"),
        }
        let legacy_plan_id = provider
            .provider_result
            .submission
            .as_ref()
            .unwrap()
            .plan_id
            .clone();
        assert!(
            service
                .get_agent_plan_local(&legacy_plan_id)
                .unwrap()
                .is_none()
        );
        drop(store);

        let reopened =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        match reopened
            .recover_plan(
                &memory,
                &provider.request_id,
                &provider.request_payload_sha256,
                provider.peer_uid,
                &provider.peer_domain,
            )
            .unwrap()
        {
            crate::action_workflow::PlanWorkflowRecovery::Indeterminate(reason) => {
                assert_eq!(reason, super::RETIRED_NON_DIRECT_WORKFLOW_REASON)
            }
            other => panic!("legacy terminal result disappeared after reopen: {other:?}"),
        }
    }

    #[cfg(feature = "p0-launch-package-device-conformance")]
    #[test]
    fn p01_direct_response_receipt_reaches_custody_and_hash_tampering_is_rejected() {
        let service = AgentService::in_memory().unwrap();
        let mut provider = fixture_codex_direct_ready_saga(
            &service,
            "p01-direct-receipt-custody",
            vec![fixture_codex_direct_evidence()],
            None,
        );
        provider.authorized_adapter_set =
            super::DirectOperationAuthorizedAdapterSetV3::p0_system_api();
        let response = super::direct_provider_response(&provider).unwrap();
        assert_eq!(
            response["direct_receipt_commitment"]["p01_daemon_build_binding_sha256"],
            crate::builtin_provider_identity::P01_DAEMON_BUILD_BINDING_SHA256
        );
        let binding = super::provider_workflow_binding(&provider);
        let local_state = serde_json::to_value(&provider).unwrap();
        crate::action_workflow::validate_actionless_ready_response(
            &binding,
            &response,
            &local_state,
        )
        .unwrap();

        let mut tampered = response;
        tampered["direct_receipt_commitment"]["p01_daemon_build_binding_sha256"] =
            json!("1".repeat(64));
        let tampered_sha256 = sha256_json(&tampered["direct_receipt_commitment"]);
        tampered["direct_execution_receipt_sha256"] = json!(tampered_sha256.clone());
        tampered["direct_execution_receipt_id"] =
            json!(format!("direct-receipt-{tampered_sha256}"));
        let error = crate::action_workflow::validate_actionless_ready_response(
            &binding,
            &tampered,
            &local_state,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("action_workflow_direct_response_contract_mismatch")
        );
    }

    #[test]
    fn direct_no_action_indeterminate_and_refusal_are_reported_truthfully() {
        let service = AgentService::in_memory().unwrap();

        let no_action = fixture_codex_direct_ready_saga(
            &service,
            "direct-no-action",
            vec![fixture_codex_backend_error(
                "trillionnium_system_api",
                "request_id_conflict",
            )],
            None,
        );
        let response = super::direct_provider_response(&no_action).unwrap();
        assert_eq!(response["direct_outcome"], "no_action");
        assert_eq!(response["execution_available"], true);
        assert_eq!(response["execution_completed"], false);
        assert_eq!(response["model_executed_tools"], false);
        assert_eq!(response["model_invoked_tools"], true);
        assert_eq!(response["direct_tool_call_events"], 1);
        assert_eq!(response["completed_direct_tool_calls"], 0);
        assert_eq!(
            response["direct_call_evidence"][0]["backend_error_code"],
            "request_id_conflict"
        );

        let indeterminate_code = "effect_outcome_indeterminate";
        let indeterminate = fixture_codex_direct_ready_saga(
            &service,
            "direct-indeterminate",
            vec![fixture_codex_backend_error(
                "trillionnium_system_api",
                indeterminate_code,
            )],
            None,
        );
        let response = super::direct_provider_response(&indeterminate).unwrap();
        assert_eq!(response["direct_outcome"], "indeterminate");
        assert_eq!(response["execution_available"], false);
        assert_eq!(response["execution_completed"], false);
        assert!(response["model_executed_tools"].is_null());

        let mut success = fixture_codex_direct_evidence();
        success.sequence = 0;
        let mut uncertain =
            fixture_codex_backend_error("trillionnium_system_api", indeterminate_code);
        uncertain.sequence = 1;
        let mixed = fixture_codex_direct_ready_saga(
            &service,
            "direct-mixed-indeterminate",
            vec![success, uncertain],
            None,
        );
        let response = super::direct_provider_response(&mixed).unwrap();
        assert_eq!(response["direct_outcome"], "indeterminate");
        assert_eq!(response["completed_direct_tool_calls"], 1);
        assert_eq!(response["model_executed_tools"], true);
        assert_eq!(response["execution_available"], false);

        let refused = fixture_codex_direct_ready_saga(
            &service,
            "direct-refused",
            Vec::new(),
            Some("unsafe request"),
        );
        let response = super::direct_provider_response(&refused).unwrap();
        assert_eq!(response["direct_outcome"], "refused");
        assert_eq!(response["direct_refusal_reason"], "unsafe request");
        assert_eq!(response["execution_available"], false);
        assert_eq!(response["execution_completed"], false);
        assert_eq!(response["model_executed_tools"], false);
        assert_eq!(
            response["direct_receipt_commitment"]["direct_refusal_sha256"],
            sha256_bytes(b"unsafe request")
        );
    }

    #[test]
    fn shell_terminal_error_is_definitively_completed_not_no_effect() {
        let terminal = fixture_codex_terminal_error("process_exited_nonzero");
        assert_eq!(
            super::codex_direct_call_effect(&terminal),
            super::DirectCallEffect::DefinitiveTerminal
        );
        assert!(super::direct_call_is_completed(&terminal));

        let mapped = super::map_codex_direct_result(fixture_codex_direct_receipt(
            vec![terminal.clone()],
            None,
        ))
        .unwrap();
        assert_eq!(
            mapped.direct_outcome,
            Some(super::ProviderDirectOutcome::Completed)
        );

        let service = AgentService::in_memory().unwrap();
        let provider = fixture_codex_direct_ready_saga(
            &service,
            "shell-terminal-error-consumer",
            vec![terminal],
            None,
        );
        super::validate_direct_provider_material(super::DirectProviderMaterial {
            provider_id: &provider.provider_id,
            execution_mode: provider.provider_result.execution_mode,
            submission: provider.provider_result.submission.as_ref(),
            direct_outcome: provider.provider_result.direct_outcome,
            direct_refusal_reason: provider.provider_result.direct_refusal_reason.as_deref(),
            direct_tool_calls: &provider.provider_result.direct_tool_calls,
            provider_output_sha256: &provider.provider_result.provider_output_sha256,
            registration: &provider.registration,
        })
        .unwrap();

        let authorization = provider.shell_exec_authorization.as_ref().unwrap();
        let response = super::direct_provider_response(&provider).unwrap();
        assert_eq!(response["direct_outcome"], "completed");
        assert_eq!(response["completed_direct_tool_calls"], 1);
        assert_eq!(
            response["direct_receipt_commitment"]["shell_exec_authorization_sha256"],
            authorization.digest_sha256().unwrap()
        );
        assert_eq!(
            response["direct_receipt_commitment"]["shell_exec_direct_binding_sha256"],
            authorization.registration.binding_sha256
        );
    }

    #[test]
    fn poisoned_direct_provider_ready_with_legacy_submission_is_quarantined() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let memory = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let service = AgentService::in_memory().unwrap();
        let mut provider = fixture_provider_ready_saga(&service, "poisoned-direct-submission");
        let legacy_plan_id = provider
            .provider_result
            .submission
            .as_ref()
            .unwrap()
            .plan_id
            .clone();
        provider.provider_result.execution_mode = super::ProviderExecutionMode::AgentDirect;
        provider.provider_result.direct_outcome = Some(super::ProviderDirectOutcome::Completed);
        provider.provider_result.direct_refusal_reason = None;
        provider.provider_result.direct_tool_calls = vec![fixture_codex_direct_evidence()];

        let path = temp.path().join("action-workflow.json");
        let mut journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        store_provider_ready_saga(&mut journal, &memory, &provider);
        drop(journal);

        let journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let store = Arc::new(Mutex::new(journal));
        super::resume_local_plan_saga(&service, &store, &memory, &provider.request_id).unwrap();
        match store
            .lock()
            .unwrap()
            .recover_plan(
                &memory,
                &provider.request_id,
                &provider.request_payload_sha256,
                provider.peer_uid,
                &provider.peer_domain,
            )
            .unwrap()
        {
            crate::action_workflow::PlanWorkflowRecovery::Indeterminate(reason) => {
                assert_eq!(reason, "invalid_agent_direct_provider_ready_state")
            }
            other => panic!("poisoned direct state escaped quarantine: {other:?}"),
        }
        assert!(
            service
                .get_agent_plan_local(&legacy_plan_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn malformed_codex_direct_manifest_and_evidence_are_quarantined_on_recovery() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let memory = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let service = AgentService::in_memory().unwrap();
        let path = temp.path().join("action-workflow.json");
        let mut journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let mut providers = Vec::new();

        for (request_id, corruption) in [
            ("direct-bad-manifest", "manifest"),
            ("direct-invalid-call-digest", "digest"),
            ("direct-invalid-call-sequence", "sequence"),
        ] {
            let mut provider = fixture_codex_direct_ready_saga(
                &service,
                request_id,
                vec![fixture_codex_direct_evidence()],
                None,
            );
            match corruption {
                "manifest" => provider.agent_manifest_sha256 = "f".repeat(64),
                "digest" => {
                    provider.provider_result.direct_tool_calls[0].backend_result_sha256 =
                        "not-a-sha256".to_string();
                }
                "sequence" => provider.provider_result.direct_tool_calls[0].sequence = 1,
                _ => unreachable!(),
            }
            store_provider_ready_saga(&mut journal, &memory, &provider);
            providers.push(provider);
        }
        drop(journal);

        let journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let store = Arc::new(Mutex::new(journal));
        super::reconcile_action_workflows(&service, &store, &memory).unwrap();
        for provider in providers {
            match store
                .lock()
                .unwrap()
                .recover_plan(
                    &memory,
                    &provider.request_id,
                    &provider.request_payload_sha256,
                    provider.peer_uid,
                    &provider.peer_domain,
                )
                .unwrap()
            {
                crate::action_workflow::PlanWorkflowRecovery::Indeterminate(reason) => {
                    assert_eq!(reason, "invalid_agent_direct_provider_ready_state")
                }
                other => panic!("malformed direct state escaped quarantine: {other:?}"),
            }
        }
    }

    #[test]
    fn provider_ready_reopen_survives_same_manifest_reprovision_timestamp_change() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let memory = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let audit_path = temp.path().join("audit.sqlite");
        let service = AgentService::from_store_after_exclusive_startup(
            AuditStore::open(&audit_path).unwrap(),
        )
        .unwrap();
        let mut provider = fixture_provider_ready_saga(&service, "provider-ready-reprovision");
        provider.provider_result.submission = None;
        provider.provider_result.execution_mode = super::ProviderExecutionMode::AgentDirect;
        provider.provider_result.direct_outcome = Some(super::ProviderDirectOutcome::NoAction);
        provider.provider_result.direct_refusal_reason = None;
        provider.provider_result.direct_tool_calls.clear();
        super::validate_direct_provider_ready(&provider).unwrap();
        let previous_updated_at = provider.registration.updated_at_unix_ms;
        let path = temp.path().join("action-workflow.json");
        let mut journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        store_provider_ready_saga(&mut journal, &memory, &provider);
        drop(journal);
        drop(service);

        let deadline = Instant::now() + Duration::from_secs(1);
        while now_unix_ms() <= previous_updated_at && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let service = AgentService::from_store_after_exclusive_startup(
            AuditStore::open(&audit_path).unwrap(),
        )
        .unwrap();
        let mut source_manifest = provider.registration.clone();
        source_manifest.registered_at_unix_ms = 0;
        source_manifest.updated_at_unix_ms = 0;
        let reprovisioned = service.provision_agent_local(source_manifest).unwrap();
        assert_eq!(
            reprovisioned.registered_at_unix_ms,
            provider.registration.registered_at_unix_ms
        );
        assert!(reprovisioned.updated_at_unix_ms > previous_updated_at);

        let journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let store = Arc::new(Mutex::new(journal));
        super::reconcile_action_workflows(&service, &store, &memory).unwrap();
        match store
            .lock()
            .unwrap()
            .recover_plan(
                &memory,
                &provider.request_id,
                &provider.request_payload_sha256,
                provider.peer_uid,
                &provider.peer_domain,
            )
            .unwrap()
        {
            crate::action_workflow::PlanWorkflowRecovery::Ready(_) => {}
            other => panic!("same manifest reprovision did not recover: {other:?}"),
        }
    }

    #[test]
    fn legacy_v1_saga_is_quarantined_without_blocking_v2_reconciliation() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let memory = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let service = AgentService::in_memory().unwrap();
        let legacy = fixture_provider_ready_saga(&service, "legacy-v1-provider-ready");
        let current = fixture_codex_direct_ready_saga(
            &service,
            "current-v3-provider-ready",
            vec![fixture_codex_direct_evidence()],
            None,
        );
        let path = temp.path().join("action-workflow.json");
        let mut journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();

        let legacy_binding = super::provider_workflow_binding(&legacy);
        journal
            .begin_provider_pending(
                &memory,
                legacy_binding.clone(),
                json!({
                    "schema": super::LEGACY_LOCAL_PLAN_SAGA_SCHEMA,
                    "state": "provider_pending",
                    "task_id": legacy.task_id,
                }),
            )
            .unwrap();
        let mut legacy_state = serde_json::to_value(&legacy).unwrap();
        legacy_state["schema"] = json!(super::LEGACY_LOCAL_PLAN_SAGA_SCHEMA);
        legacy_state
            .as_object_mut()
            .unwrap()
            .remove("agent_executable");
        journal
            .transition(
                &memory,
                &legacy.request_id,
                crate::action_workflow::PlanSagaStage::ProviderPending,
                legacy_binding,
                crate::action_workflow::PlanSagaStage::ProviderReady,
                legacy_state,
            )
            .unwrap();
        store_provider_ready_saga(&mut journal, &memory, &current);
        drop(journal);

        let journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let store = Arc::new(Mutex::new(journal));
        super::reconcile_action_workflows(&service, &store, &memory).unwrap();

        match store
            .lock()
            .unwrap()
            .recover_plan(
                &memory,
                &legacy.request_id,
                &legacy.request_payload_sha256,
                legacy.peer_uid,
                &legacy.peer_domain,
            )
            .unwrap()
        {
            crate::action_workflow::PlanWorkflowRecovery::Indeterminate(reason) => {
                assert_eq!(reason, super::LEGACY_LOCAL_PLAN_SAGA_INDETERMINATE_REASON)
            }
            other => panic!("legacy v1 saga was not quarantined: {other:?}"),
        }
        match store
            .lock()
            .unwrap()
            .recover_plan(
                &memory,
                &current.request_id,
                &current.request_payload_sha256,
                current.peer_uid,
                &current.peer_domain,
            )
            .unwrap()
        {
            crate::action_workflow::PlanWorkflowRecovery::Ready(_) => {}
            other => panic!("v2 saga was blocked by legacy v1 record: {other:?}"),
        }
    }

    #[test]
    fn legacy_schema_detector_covers_every_resumable_local_stage() {
        let legacy = super::LEGACY_LOCAL_PLAN_SAGA_SCHEMA;
        for (stage, state) in [
            (
                crate::action_workflow::PlanSagaStage::ProviderPending,
                json!({"schema": legacy}),
            ),
            (
                crate::action_workflow::PlanSagaStage::ProviderReady,
                json!({"schema": legacy}),
            ),
            (
                crate::action_workflow::PlanSagaStage::PlanPrepared,
                json!({"provider": {"schema": legacy}}),
            ),
            (
                crate::action_workflow::PlanSagaStage::PlanSubmitted,
                json!({"prepared": {"provider": {"schema": legacy}}}),
            ),
            (
                crate::action_workflow::PlanSagaStage::ActionDispatched,
                json!({"submitted": {"prepared": {"provider": {"schema": legacy}}}}),
            ),
            (
                crate::action_workflow::PlanSagaStage::PayloadStaged,
                json!({"submitted": {"prepared": {"provider": {"schema": legacy}}}}),
            ),
        ] {
            assert_eq!(super::local_plan_saga_schema(stage, &state), Some(legacy));
        }
        assert_eq!(
            super::local_plan_saga_schema(
                crate::action_workflow::PlanSagaStage::ProviderReady,
                &json!({"schema": super::LOCAL_PLAN_SAGA_SCHEMA}),
            ),
            Some(super::LOCAL_PLAN_SAGA_SCHEMA)
        );
    }

    #[test]
    fn provider_pending_reopen_becomes_fixed_indeterminate_without_plan_or_dispatch() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let memory = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let service = AgentService::in_memory().unwrap();
        let provider = fixture_provider_ready_saga(&service, "provider-pending-kill");
        let plan_id = provider
            .provider_result
            .submission
            .as_ref()
            .unwrap()
            .plan_id
            .clone();
        let path = temp.path().join("action-workflow.json");
        let mut journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        journal
            .begin_provider_pending(
                &memory,
                super::provider_workflow_binding(&provider),
                json!({"state": "provider_pending"}),
            )
            .unwrap();
        drop(journal);

        let reopened =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        let reopened = Arc::new(Mutex::new(reopened));
        super::reconcile_action_workflows(&service, &reopened, &memory).unwrap();
        assert!(service.get_agent_plan_local(&plan_id).unwrap().is_none());
        match reopened
            .lock()
            .unwrap()
            .recover_plan(
                &memory,
                &provider.request_id,
                &provider.request_payload_sha256,
                provider.peer_uid,
                &provider.peer_domain,
            )
            .unwrap()
        {
            crate::action_workflow::PlanWorkflowRecovery::Indeterminate(reason) => {
                assert_eq!(reason, "provider_outcome_unknown_no_network_reexecution")
            }
            other => panic!("provider pending was not fixed indeterminate: {other:?}"),
        }
        // A second restart is stable and still cannot submit the stored plan.
        drop(reopened);
        let reopened =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        assert!(reopened.restart_candidates().is_empty());
        assert!(service.get_agent_plan_local(&plan_id).unwrap().is_none());
    }

    #[test]
    fn legacy_boolean_approval_and_delegation_fields_are_rejected() {
        let service = AgentService::in_memory().unwrap();
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let action_consents = Arc::new(Mutex::new(
            crate::action_workflow::ActionWorkflowJournal::open_for_test(
                &contexts,
                &temp.path().join("action-workflow.json"),
            )
            .unwrap(),
        ));
        let approval = approve(
            &service,
            &action_consents,
            &contexts,
            10_123,
            "u:r:trillionnium_aishell:s0",
            "workflow-legacy-approve",
            json!({
                "task_id": "task-legacy",
                "workflow_id": "workflow-legacy",
                "approval_id": "approval-legacy",
                "approved": true,
            }),
        )
        .unwrap_err();
        assert!(approval.to_string().contains("missing_or_unknown_fields"));

        let owner = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let delegation = issue_agent_data_grant(
            &service,
            &contexts,
            &owner,
            json!({
                "context_id": format!("context-{}", "a".repeat(64)),
                "agent_id": "agent-legacy",
                "task_id": "task-legacy",
                "ttl_ms": 120_000,
                "user_confirmed": true,
                "raw_access_confirmed": true,
                "egress_scope_confirmed": true,
            }),
            "context",
        )
        .unwrap_err();
        assert!(delegation.to_string().contains("missing_or_unknown_fields"));

        let credential = super::provision_codex(
            &owner,
            &json!({
                "auth_json": "{}",
                "user_confirmed": true,
            }),
        )
        .unwrap_err();
        assert!(credential.to_string().contains("missing_or_unknown_fields"));
    }

    #[test]
    fn ui_data_grant_requires_existing_agent_owned_same_user_task() {
        let service = AgentService::in_memory().unwrap();
        let now = now_unix_ms();
        let registration = AgentRegistration {
            api_version: AGENT_API_VERSION.to_string(),
            agent_id: "agent-ui-delegation-test".to_string(),
            adapter: "fixture".to_string(),
            adapter_version: "1".to_string(),
            identity_key_sha256: "a".repeat(64),
            peer_uid: 62_010,
            peer_gid: 62_011,
            selinux_domain: "u:r:trillionnium_test_agent:s0".to_string(),
            network_policy: AgentNetworkPolicy::Deny,
            enabled: true,
            health: AgentHealth::Ready,
            registered_at_unix_ms: now,
            updated_at_unix_ms: now,
        };
        service.provision_agent_local(registration.clone()).unwrap();
        let task = service
            .create_task_local(TaskInput {
                title: "delegation wrong user".to_string(),
                description: None,
                metadata: json!({
                    "agent_id": registration.agent_id,
                    "agent_peer_uid": registration.peer_uid,
                    "agent_peer_gid": registration.peer_gid,
                    "agent_peer_selinux_domain": registration.selinux_domain,
                    "agent_peer_executable_sha256": registration.identity_key_sha256,
                    "subject_user_id": 10,
                }),
            })
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let contexts = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let owner = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let context = contexts
            .create_test_context(
                &owner,
                json!({
                    "source_kind": "file",
                    "source_id": "saf:ui-delegation",
                    "content": "private",
                }),
            )
            .unwrap();
        let error = issue_agent_data_grant(
            &service,
            &contexts,
            &owner,
            json!({
                "context_id": context["context_id"],
                "agent_id": "agent-ui-delegation-test",
                "task_id": task.id.0,
                "ttl_ms": 120_000,
            }),
            "context",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("agent_or_user_binding_mismatch"));

        let wrong_gid_task = service
            .create_task_local(TaskInput {
                title: "delegation wrong gid".to_string(),
                description: None,
                metadata: json!({
                    "agent_id": "agent-ui-delegation-test",
                    "agent_peer_uid": registration.peer_uid,
                    "agent_peer_gid": registration.peer_gid + 1,
                    "agent_peer_selinux_domain": registration.selinux_domain,
                    "agent_peer_executable_sha256": registration.identity_key_sha256,
                    "subject_user_id": 0,
                }),
            })
            .unwrap();
        let error = issue_agent_data_grant(
            &service,
            &contexts,
            &owner,
            json!({
                "context_id": context["context_id"],
                "agent_id": "agent-ui-delegation-test",
                "task_id": wrong_gid_task.id.0,
                "ttl_ms": 120_000,
            }),
            "context",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("agent_or_user_binding_mismatch"));
    }

    #[test]
    fn action_ui_custody_reconciliation_has_one_barrier_proven_lock_order() {
        let temp = tempfile::tempdir().unwrap();
        let context =
            Arc::new(ContextMemoryService::open(temp.path().join("context-memory")).unwrap());
        let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
        let request_id = "action-ui-lock-order";
        let payload = json!({ "workflow_id": "workflow-lock-order" });
        let payload_sha256 = sha256_bytes(&serde_json::to_vec(&payload).unwrap());
        let binding = PlanRecoveryBinding {
            method: "plan".to_string(),
            request_id: request_id.to_string(),
            request_payload_sha256: payload_sha256.clone(),
            subject_uid: subject.uid,
            subject_selinux_domain: subject.selinux_domain.clone(),
            provider_id: "openai-codex".to_string(),
            task_id: "task-lock-order".to_string(),
            plan_id: String::new(),
            action_id: String::new(),
            tool_call_id: String::new(),
            accepted_plan_sha256: String::new(),
            challenge_sha256: String::new(),
            challenge_expires_at_ms: 0,
        };
        let action_consents = Arc::new(Mutex::new(ActionWorkflowJournal::open(&context).unwrap()));
        {
            let mut journal = action_consents.lock().unwrap();
            journal
                .begin_provider_pending(&context, binding, json!({ "dispatched": true }))
                .unwrap();
            journal
                .mark_indeterminate(
                    &context,
                    request_id,
                    "provider_outcome_unknown_no_network_reexecution",
                )
                .unwrap();
        }
        assert!(
            context
                .run_ui_request("plan", request_id, &subject, &payload, || {
                    anyhow::bail!("provider_outcome_unknown_no_network_reexecution")
                })
                .is_err()
        );
        let proof = context
            .ui_request_completion_proof_exact(
                "plan",
                request_id,
                subject.uid,
                &subject.selinux_domain,
                &payload_sha256,
            )
            .unwrap()
            .unwrap();
        {
            let mut journal = action_consents.lock().unwrap();
            journal
                .record_ui_completion_proof(
                    &context,
                    "plan",
                    request_id,
                    subject.uid,
                    &subject.selinux_domain,
                    &payload_sha256,
                    &proof.digest_sha256().unwrap(),
                )
                .unwrap();
        }

        // A owns UI then requests action; B owns action during snapshot then
        // requests UI. The shared barrier fixes the dangerous interleaving.
        // Completion proves B released action before entering UI custody.
        let barrier = Arc::new(std::sync::Barrier::new(2));
        action_consents
            .lock()
            .unwrap()
            .set_custody_snapshot_barrier_for_test(Arc::clone(&barrier));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let ui_context = Arc::clone(&context);
        let ui_actions = Arc::clone(&action_consents);
        let ui_barrier = Arc::clone(&barrier);
        let ui_done = done_tx.clone();
        let ui_thread = std::thread::spawn(move || {
            ui_context.hold_ui_replay_lock_for_test(|| {
                ui_barrier.wait();
                drop(ui_actions.lock().unwrap());
            });
            ui_done.send("ui").unwrap();
        });
        let reconcile_context = Arc::clone(&context);
        let reconcile_actions = Arc::clone(&action_consents);
        let reconcile_thread = std::thread::spawn(move || {
            super::reconcile_action_workflow_custody(&reconcile_actions, &reconcile_context)
                .unwrap();
            done_tx.send("reconcile").unwrap();
        });
        let first = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("barrier-proven lock order deadlocked");
        let second = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("barrier-proven lock order did not drain");
        assert_ne!(first, second);
        ui_thread.join().unwrap();
        reconcile_thread.join().unwrap();
        assert!(
            action_consents
                .lock()
                .unwrap()
                .custody_candidates(&context)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn codex_prepare_response_loss_reopens_exactly() {
        for provider_id in [super::CODEX_PROVIDER_ID] {
            let temp = tempfile::tempdir().unwrap();
            let context_root = temp.path().join("context-memory");
            let journal_path = temp.path().join("egress-journal.json");
            let contexts = ContextMemoryService::open(context_root.clone()).unwrap();
            let subject = Subject::new(10_123, "u:r:trillionnium_aishell:s0").unwrap();
            let context = contexts
                .create_test_context(
                    &subject,
                    json!({
                        "source_kind": "file",
                        "source_id": format!("saf:response-loss-{provider_id}"),
                        "content": "provider-neutral private payload",
                    }),
                )
                .unwrap();
            let registration = fixture_registration();
            let suffix = "codex";
            let workflow_id = format!("workflow-response-loss-{suffix}");
            let request_id = format!("{workflow_id}-egress-prepare");
            let payload = json!({
                "provider": provider_id,
                "context_id": context["context_id"],
                "intent": "prepare once and replay after response loss",
                "workflow_id": workflow_id,
            });
            let store = fixture_egress_store(&journal_path);
            let first = prepare_egress(
                &store,
                &contexts,
                &subject,
                &registration,
                &request_id,
                payload.clone(),
            )
            .unwrap();
            drop(store);
            drop(contexts);

            let reopened_contexts = ContextMemoryService::open(context_root).unwrap();
            let reopened = fixture_egress_store(&journal_path);
            for _ in 0..2 {
                let recovered = match super::recover_prepare_egress_outcome(
                    &reopened,
                    &reopened_contexts,
                    &subject,
                    &registration,
                    &request_id,
                    &payload,
                )
                .unwrap()
                {
                    crate::context_memory::UiRequestRecovery::Outcome(Ok(value)) => value,
                    _ => panic!("{suffix} prepare did not replay exactly"),
                };
                assert_eq!(
                    serde_json::to_vec(&recovered).unwrap(),
                    serde_json::to_vec(&first).unwrap()
                );
            }
        }
    }

    #[test]
    fn direct_material_validator_rejects_every_legacy_provider_shape() {
        let service = AgentService::in_memory().unwrap();
        let provider = fixture_provider_ready_saga(&service, "legacy-material-rejected");
        let result = &provider.provider_result;
        let error = super::validate_direct_provider_material(super::DirectProviderMaterial {
            provider_id: &provider.provider_id,
            execution_mode: result.execution_mode,
            submission: result.submission.as_ref(),
            direct_outcome: result.direct_outcome,
            direct_refusal_reason: result.direct_refusal_reason.as_deref(),
            direct_tool_calls: &result.direct_tool_calls,
            provider_output_sha256: &result.provider_output_sha256,
            registration: &provider.registration,
        })
        .unwrap_err();
        assert_eq!(error.to_string(), super::RETIRED_NON_DIRECT_WORKFLOW_REASON);
    }

    #[test]
    fn live_legacy_provider_result_becomes_terminal_without_ready_or_consent_material() {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let memory = ContextMemoryService::open(temp.path().join("context-memory")).unwrap();
        let service = AgentService::in_memory().unwrap();
        let provider = fixture_provider_ready_saga(&service, "live-legacy-terminal");
        let path = temp.path().join("action-workflow.json");
        let mut journal =
            crate::action_workflow::ActionWorkflowJournal::open_for_test(&memory, &path).unwrap();
        journal
            .begin_provider_pending(
                &memory,
                super::provider_workflow_binding(&provider),
                json!({
                    "schema": super::LOCAL_PLAN_SAGA_SCHEMA,
                    "state": "provider_pending",
                    "task_id": provider.task_id,
                }),
            )
            .unwrap();
        let store = Arc::new(Mutex::new(journal));
        let error = super::enforce_live_agent_direct_result(
            &store,
            &memory,
            &provider.request_id,
            super::ProviderExecutionMode::LegacyPlan,
        )
        .unwrap_err();
        assert_eq!(error.to_string(), super::RETIRED_NON_DIRECT_WORKFLOW_REASON);
        let view = store
            .lock()
            .unwrap()
            .workflow_for_reconcile(&memory, &provider.request_id)
            .unwrap();
        assert_eq!(
            view.stage,
            crate::action_workflow::PlanSagaStage::Indeterminate
        );
        assert!(view.local_state.is_null());
        assert!(view.exact_plan_response.is_none());
        assert!(view.action_consent.is_none());
        assert_eq!(
            view.indeterminate_reason.as_deref(),
            Some(super::RETIRED_NON_DIRECT_WORKFLOW_REASON)
        );
        let legacy_plan_id = provider
            .provider_result
            .submission
            .as_ref()
            .unwrap()
            .plan_id
            .clone();
        assert!(
            service
                .get_agent_plan_local(&legacy_plan_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn production_recovery_policy_accepts_only_direct_provider_ready_state() {
        for stage in [
            crate::action_workflow::PlanSagaStage::ProviderReady,
            crate::action_workflow::PlanSagaStage::PlanReady,
        ] {
            assert!(!super::resumable_saga_is_not_agent_direct(
                stage,
                &json!({"provider_result":{"execution_mode":"agent_direct"}}),
            ));
            for state in [
                json!({"provider_result":{"execution_mode":"legacy_plan"}}),
                json!({"provider_result":{}}),
                json!({}),
            ] {
                assert!(super::resumable_saga_is_not_agent_direct(stage, &state));
            }
        }
        for stage in [
            crate::action_workflow::PlanSagaStage::PlanPrepared,
            crate::action_workflow::PlanSagaStage::PlanSubmitted,
            crate::action_workflow::PlanSagaStage::ActionDispatched,
            crate::action_workflow::PlanSagaStage::PayloadStaged,
        ] {
            assert!(super::resumable_saga_is_not_agent_direct(
                stage,
                &json!({"provider":{"provider_result":{"execution_mode":"agent_direct"}}}),
            ));
        }
    }

    #[test]
    fn active_revoke_caller_reaper_and_timeout_barriers_are_single_shot() {
        for winner in ["caller", "reaper", "timeout"] {
            let temp = tempfile::tempdir().unwrap();
            let pending = fixture_egress_store(&temp.path().join("egress-journal.json"));
            let active = Arc::new(Mutex::new(HashMap::new()));
            let wait_entered = Arc::new(std::sync::Barrier::new(2));
            let after_ack_gate = (winner == "reaper").then(|| super::ActiveEgressAfterAckGate {
                entered: Arc::new(std::sync::Barrier::new(2)),
                release: Arc::new(std::sync::Barrier::new(2)),
            });
            let mut cancellation = fixture_cancellation();
            cancellation.wait_entered_barrier = Some(Arc::clone(&wait_entered));
            cancellation.after_ack_gate = after_ack_gate.clone();
            cancellation.force_teardown_timeout = winner == "timeout";
            let grant_id = format!(
                "egress-{}",
                match winner {
                    "caller" => "1".repeat(64),
                    "reaper" => "2".repeat(64),
                    "timeout" => "3".repeat(64),
                    _ => unreachable!(),
                }
            );
            insert_active_egress_fixture(
                &pending,
                &active,
                &cancellation,
                &grant_id,
                "workflow-barrier",
            );
            let pending_for_worker = Arc::clone(&pending);
            let active_for_worker = Arc::clone(&active);
            let grant_for_worker = grant_id.clone();
            let (result_tx, result_rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                result_tx
                    .send(revoke_egress(
                        &pending_for_worker,
                        &active_for_worker,
                        10_123,
                        "u:r:trillionnium_aishell:s0",
                        "workflow-barrier-revoke",
                        json!({
                            "egress_grant_id": grant_for_worker,
                            "workflow_id": "workflow-barrier",
                        }),
                    ))
                    .unwrap();
            });
            // No polling or scheduler timing: this releases only after the
            // caller has durably entered REVOKE_PENDING and reached teardown.
            wait_entered.wait();
            if winner != "timeout" {
                publish_test_teardown_ack(&pending, &cancellation, &active, &grant_id, "caller");
            }
            if let Some(gate) = after_ack_gate.as_ref() {
                gate.entered.wait();
                assert_eq!(
                    super::retry_pending_active_egress_durability(&pending, &active).unwrap(),
                    1
                );
                gate.release.wait();
            }
            let outcome = result_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("barrier-controlled revoke did not finish")
                .unwrap();
            worker.join().unwrap();
            assert_eq!(cancellation.cancel_count.load(Ordering::SeqCst), 1);
            if winner == "timeout" {
                assert_eq!(outcome["lifecycle_state"], json!("REVOKE_PENDING"));
                assert_eq!(outcome["revoked"], json!(false));
                assert_eq!(cancellation.ack_publish_count.load(Ordering::SeqCst), 0);
                assert!(active.lock().unwrap().contains_key(&grant_id));
                publish_test_teardown_ack(&pending, &cancellation, &active, &grant_id, "caller");
                assert_eq!(
                    super::retry_pending_active_egress_durability(&pending, &active).unwrap(),
                    1
                );
            } else {
                assert_eq!(outcome["lifecycle_state"], json!("REVOKED"));
                assert_eq!(outcome["revoked"], json!(true));
            }
            assert_eq!(cancellation.cancel_count.load(Ordering::SeqCst), 1);
            assert_eq!(cancellation.ack_publish_count.load(Ordering::SeqCst), 1);
            assert!(!active.lock().unwrap().contains_key(&grant_id));
            assert_eq!(
                pending.lock().unwrap().journal.state_for_test(&grant_id),
                Some(EgressLifecycleState::Revoked)
            );
        }
    }
}
