#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

locate() {
    local relative=$1
    local direct="$ROOT/$relative"
    if [[ -f "$direct" ]]; then
        printf '%s\n' "$direct"
        return
    fi
    find "$(cd "$(dirname "$0")" && pwd)" -name "$(basename "$relative")" -print -quit
}

CLIENT=$(locate src/org/trillionnium/aishell/BuiltInAgentClient.java)
HOST_ABI=$(locate src/org/trillionnium/aishell/DirectAgentHostAbi.java)
STRICT_FRAME=$(locate src/org/trillionnium/aishell/StrictAgentApiFrame.java)
STRICT_JSON=$(locate src/org/trillionnium/aishell/StrictJson.java)
ACTIVITY=$(locate src/org/trillionnium/aishell/AiShellActivity.java)
PROTOCOL=$(locate src/org/trillionnium/aishell/AiProtocol.java)
CANONICAL_JSON=$(locate src/org/trillionnium/aishell/CanonicalJson.java)
DIRECT_RESULT=$(locate src/org/trillionnium/aishell/DirectAgentResult.java)
DIRECT_DISPLAY=$(locate src/org/trillionnium/aishell/DirectResultDisplay.java)
DIRECT_RECOVERY_POLICY=$(locate src/org/trillionnium/aishell/DirectResultRecoveryPolicy.java)
MANIFEST=$(locate AndroidManifest.xml)
SYSTEM_USER_BOUNDARY=$(locate src/org/trillionnium/aishell/SystemUserBoundary.java)
WORKFLOW_RECOVERY=$(locate src/org/trillionnium/aishell/WorkflowRecoveryState.java)
WORKFLOW_STORE=$(locate src/org/trillionnium/aishell/WorkflowRecoveryStore.java)
WORKFLOW_PROTOCOL=$(locate src/org/trillionnium/aishell/WorkflowStoreProtocol.java)
WORKFLOW_CRYPTO=$(locate src/org/trillionnium/aishell/WorkflowStateCrypto.java)
MEMORY_ADAPTER=$(locate src/org/trillionnium/aishell/MemoryMetadataAdapter.java)
CONTEXT_MEMORY_ABI=$(locate src/org/trillionnium/aishell/ContextMemoryAbi.java)
RECEIPT_STORE=$(locate src/org/trillionnium/aishell/ReceiptCustodyStore.java)
RECEIPT_PROTOCOL=$(locate src/org/trillionnium/aishell/ReceiptStoreProtocol.java)
REQUEST_IDENTITY=$(locate src/org/trillionnium/aishell/RequestIdentity.java)
CAPABILITY_LEASE_RECEIPT=$(locate src/org/trillionnium/aishell/CapabilityLeaseReceipt.java)
CAPABILITY_LEASE_DELIVERY_ACK=$(locate src/org/trillionnium/aishell/CapabilityLeaseSubmissionDeliveryAcknowledger.java)
CAPABILITY_LEASE_GOLDEN=$(locate tests/CapabilityLeaseChallengeV1Golden.java)
BLUEPRINT=$(locate Android.bp)

for source in "$CLIENT" "$HOST_ABI" "$STRICT_FRAME" "$STRICT_JSON" "$ACTIVITY" "$PROTOCOL" \
        "$CANONICAL_JSON" "$DIRECT_RESULT" "$DIRECT_DISPLAY" \
        "$DIRECT_RECOVERY_POLICY" "$MANIFEST" \
        "$SYSTEM_USER_BOUNDARY" "$WORKFLOW_RECOVERY" "$WORKFLOW_STORE" \
        "$WORKFLOW_PROTOCOL" "$WORKFLOW_CRYPTO" "$MEMORY_ADAPTER" \
        "$CONTEXT_MEMORY_ABI" "$RECEIPT_STORE" "$RECEIPT_PROTOCOL" \
        "$REQUEST_IDENTITY" "$CAPABILITY_LEASE_RECEIPT" "$CAPABILITY_LEASE_DELIVERY_ACK" \
        "$CAPABILITY_LEASE_GOLDEN" \
        "$BLUEPRINT"; do
    [[ -f "$source" ]] || { echo "missing static-check input: $source" >&2; exit 1; }
done

require() {
    local pattern=$1
    local file=$2
    rg -q -- "$pattern" "$file" || {
        echo "missing contract marker: $pattern ($file)" >&2
        exit 1
    }
}

deny() {
    local pattern=$1
    shift
    if rg -n -- "$pattern" "$@"; then
        echo "retired or forbidden contract remains: $pattern" >&2
        exit 1
    fi
}

for marker in \
        'd538ef22f6ff1fcc5cf2ff15a158a8227631991bf83c3676ab19a66fce162c11' \
        'org.trillionnium.direct-agent-host.abi.v1' \
        'org.trillionnium.direct-agent-host.direct-result.v1' \
        'trillionnium.agent-direct-receipt.v2' \
        'trillionnium.direct-agent-host.uds.v1' \
        'trillionnium-direct-agent-host-v1' \
        'TOOL_INVOCATION_OWNED_BY_AGENT = true' \
        'TOOL_BACKEND_OWNED_BY_OS = true' \
        'DAEMON_IS_EFFECT_EXECUTOR = false' \
        'CONTRACT_CONFERS_EFFECT_AUTHORITY = false'; do
    require "$marker" "$HOST_ABI"
done
deny 'tool_execution_owned_by_os' "$HOST_ABI" "$DIRECT_RESULT"

for marker in \
        'd3ab8272d63050743e3affc66206d56eeac516192f83871b5490bb872f64f24e' \
        'lease-challenge-95efbcda48ff33c5bfae8d105538c140a571314c8d6800c4a00ef9f601ed1539' \
        'lease-0981b34439ec599752e5210c1306fe916b76d00dc02f7118b2a2e80dc412fb44' \
        'task.open-uri-golden-v1' \
        'org.trillionnium.aishell'; do
    require "$marker" "$CAPABILITY_LEASE_GOLDEN"
done

for marker in 'MAX_FRAME_BYTES = 256 \* 1024' 'CodingErrorAction.REPORT' \
        'StrictJson.parseObject' 'agent_api_response_closed_world_denied' \
        'output.size\(\) >= MAX_FRAME_BYTES - 1'; do
    require "$marker" "$STRICT_FRAME"
done
for marker in 'duplicate_key' 'deny\("float"\)' 'deny\("unpaired_surrogate"\)' \
        'MAX_RECEIPT_BYTES = 256 \* 1024'; do
    require "$marker" "$STRICT_JSON"
done
for marker in 'PER_USER_RANGE = 100_000' 'requireSystemUserUid'; do
    require "$marker" "$SYSTEM_USER_BOUNDARY"
done
require 'SystemUserBoundary.requireSystemUserUid\(android.os.Process.myUid\(\)\)' "$ACTIVITY"
require 'SystemUserBoundary.requireSystemUserUid\(android.os.Process.myUid\(\)\)' "$CLIENT"

for marker in \
        'CODEX_PROVIDER_ID = "openai-codex"' \
        'call\(requestId, "provision_codex"' \
        'payload.put\("consent_receipt", consentReceipt\)' \
        'Bundle plan\(String requestId, String egressGrantId, String provider,' \
        'output.putString\("direct_result_json", CanonicalJson.encode\(result\)\)'; do
    require "$marker" "$CLIENT"
done
deny 'DirectAgentResult.parse\(' "$CLIENT"
deny 'Bundle (approve|undo)\(|"(approve|undo|authority_key_metadata)"' "$CLIENT"
deny 'user_confirmed|raw_access_confirmed|egress_scope_confirmed|payload.put\("approved"' "$CLIENT"
retired_provider_pattern='[Oo][Pp][Ee][Nn][Cc][Ll][Aa][Ww]'
deny "$retired_provider_pattern" "$ACTIVITY" "$CLIENT" "$DIRECT_RESULT" \
    "$WORKFLOW_RECOVERY" "$CAPABILITY_LEASE_RECEIPT"
deny 'Spinner|ArrayAdapter|AdapterView|Direct Agent provider' "$ACTIVITY"
require 'return BuiltInAgentClient.CODEX_PROVIDER_ID.equals\(provider\);' "$ACTIVITY"
require 'if \(!CODEX_PROVIDER_ID.equals\(provider\)\)' "$CLIENT"

for marker in \
        'ActivityOptions\.makeBasic\(\)\.setShareIdentityEnabled\(true\)\.toBundle\(\)' \
        'startActivityForResult\(consent, EGRESS_CONSENT, authorityLaunchOptions\(\)\)' \
        'onEgressConsentResult' \
        'AiProtocol.directAllowedActionsJson' \
        'codex-p0-system-api-shell-exec-prompt.v3' \
        'PROMPT_CONTRACT_VERSION = 3L' \
        '"built-in Codex' \
        '"Connect built-in Codex credential"' \
        '"Send to direct Agent"' \
        'DirectAgentResult.parse\(data.getString\("direct_result_json"' \
        'publishDirectAgentReceipt' \
        'agent_direct_effect_indeterminate_no_retry' \
        'Post-provider Authority action: structurally absent' \
        'recovered_agent_direct_effect_indeterminate_no_retry' \
        'dispatchFrozenEgressRevoke'; do
    require "$marker" "$ACTIVITY"
done
context_authority_launch_count=$(rg -c \
    'startActivityForResult\(broker, CONTEXT_CAPTURE, authorityLaunchOptions\(\)\)' \
    "$ACTIVITY")
if [[ "$context_authority_launch_count" -ne 2 ]]; then
    echo "Authority context launches must share caller identity exactly twice" >&2
    exit 1
fi
require 'setType\("application/json"\)' "$ACTIVITY"
require 'setType\("text/\*"\)' "$ACTIVITY"
require 'startActivityForResult\(intent, requestCode\)' "$ACTIVITY"
require 'startActivityForResult\(intent, OPEN_DOCUMENT\)' "$ACTIVITY"
deny 'startActivityForResult\(broker, CONTEXT_CAPTURE\);|startActivityForResult\(consent, EGRESS_CONSENT\);' \
    "$ACTIVITY"
deny 'ACTION_CONSENT|REQUEST_ACTION_CONSENT|requestCapability|onActionConsentResult|onAuthorityExecuted|onAuthorityUndone|dispatchFrozenApproval|dispatchFrozenUndo|mConfirm|mUndo|mExecutionExpectation|mUndoSourceReceipt' "$ACTIVITY"
deny 'browser_open_bounded|notification_post_bounded|android\.browser\.open_bounded|android\.notification\.post_bounded' \
    "$ACTIVITY" "$CLIENT" "$PROTOCOL" "$WORKFLOW_RECOVERY" "$DIRECT_RESULT"
deny 'agent-codex-cli-v1|plan-only-prompt|bounded-planner-prompt|Plan-only provider' \
    "$ACTIVITY" "$CLIENT" "$WORKFLOW_RECOVERY"

for marker in \
        'CODEX_EVIDENCE_FIELDS' \
        'trillionnium.agent-direct-evidence.v2' \
        'root.put\("tool_calls", evidence\)' \
        'classifyBackendError' \
        'request_id_conflict' \
        'effect_outcome_indeterminate' \
        'trillionnium_shell_exec' \
        'launch_rejected_before_effect' \
        'process_exited_nonzero' \
        'terminal_error' \
        'direct_backend_error_unclassified' \
        'CanonicalJson.sha256\(root\)' \
        'egress_challenge_missing' \
        'nullableString\(value, "direct_refusal_reason", 4_096\)' \
        'Character.CONTROL' \
        'receipt_commitment_hash' \
        'effect_authority_contract' \
        'model_executed_tools'; do
    require "$marker" "$DIRECT_RESULT"
done
deny 'trillionnium_adb' "$DIRECT_RESULT"
deny 'trillionnium_accessibility' "$DIRECT_RESULT"
require 'WorkflowRecoveryState\.requireExactEgressChallengeShape\(challenge\)' "$DIRECT_RESULT"
require 'DirectResultDisplay\.summary\(summary\)\.isEmpty\(\)' "$DIRECT_RESULT"
for marker in 'Character.FORMAT' 'isDirectionalControl' 'MAX_SUMMARY_CODE_POINTS' \
        'MAX_METADATA_CODE_POINTS'; do
    require "$marker" "$DIRECT_DISPLAY"
done
for marker in 'requiresTerminalHold' '"indeterminate"' '"completed"' '"no_action"' \
        '"refused"' 'recovered_direct_outcome_denied'; do
    require "$marker" "$DIRECT_RECOVERY_POLICY"
done
recovered_block=$(sed -n '/private void renderRecoveredDirectResult()/,/private void maybeRecoverPendingOperation()/p' "$ACTIVITY")
parse_line=$(printf '%s\n' "$recovered_block" | grep -n 'requireRecoveredDirectReceiptCustody' | head -1 | cut -d: -f1)
hold_line=$(printf '%s\n' "$recovered_block" | grep -n 'DirectResultRecoveryPolicy.requiresTerminalHold' | head -1 | cut -d: -f1)
render_line=$(printf '%s\n' "$recovered_block" | grep -n 'mPreview.setText' | head -1 | cut -d: -f1)
if [[ -z "$parse_line" || -z "$hold_line" || -z "$render_line" \
        || "$parse_line" -ge "$hold_line" || "$hold_line" -ge "$render_line" ]]; then
    echo "recovered indeterminate result is not held before render/archive enable" >&2
    exit 1
fi
for marker in \
        'ReceiptCustodyStore\.matchingDirectHead\(this, direct\)' \
        '!mLastReceiptId\.equals\(verifiedHead\)' \
        'ReceiptCustodyStore\.requireCurrentHead\(this, mLastReceiptId\)' \
        'recovered_direct_receipt_head_denied' \
        'recovered_direct_receipt_custody_denied'; do
    require "$marker" "$ACTIVITY"
done
memory_complete_block=$(sed -n \
    '/PHASE_MEMORY_SAVE_COMPLETE.equals(mWorkflowPhase)/,/PHASE_MEMORY_DELETE_DISPATCHED.equals/p' \
    "$ACTIVITY")
require 'requireCurrentReceiptHead' <(printf '%s\n' "$memory_complete_block")
deny 'requireRecoveredDirectReceiptCustody' <(printf '%s\n' "$memory_complete_block")
memory_saved_block=$(sed -n '/private void onMemorySaved(/,/private void dispatchFrozenMemoryDelete(/p' "$ACTIVITY")
require 'requireCurrentReceiptHead' <(printf '%s\n' "$memory_saved_block")
deny '\+ "\\n\\n" \+ mSummary|\+ "\\n\\n" \+ direct.summary\(\)' "$ACTIVITY"

require 'directAllowedActionsJson' "$PROTOCOL"
require '\? "\[\]" : null' "$PROTOCOL"
deny 'allowedActionsJson|\[\\"browser_open_bounded\\",\\"notification_post_bounded\\"\]' "$ACTIVITY" "$PROTOCOL"

require 'org.trillionnium.aiauthority.permission.REQUEST_EGRESS_CONSENT' "$MANIFEST"
require 'org.trillionnium.aiauthority.permission.REQUEST_CONTEXT_CAPTURE' "$MANIFEST"
require 'org.trillionnium.capabilitylease.permission.REQUEST_CAPABILITY_LEASE' "$MANIFEST"
require 'android:directBootAware="false"' "$MANIFEST"
deny 'REQUEST_ACTION_CONSENT|android.permission.INTERNET|PACKAGE_USAGE_STATS|BIND_NOTIFICATION_LISTENER_SERVICE|android.intent.action.SEND' "$MANIFEST"

# This is structural receipt preflight only. The future direct adapter remains responsible for
# independently pinned-key signature verification, live typed-action/scope binding, and durable
# single-use consumption; AiShell neither dispatches an effect nor treats self-carried keys as roots.
for marker in \
        'org.trillionnium.capabilitylease.capability-lease-challenge.v1' \
        'org.trillionnium.capabilitylease.capability-lease-receipt.v1' \
        'org.trillionnium.agent-risk-guard.v1' \
        'agent_identity_key_sha256' \
        'action_binding_sha256' \
        'ui_scope_binding_sha256' \
        'not_before_elapsed_realtime_ms' \
        'expires_elapsed_realtime_ms' \
        'risk_class' \
        'max_uses' \
        'receipt_id' \
        'self_asserted_identity' \
        'adapterSignatureVerificationRequired' \
        'pin the' \
        'verify the ECDSA signature' \
        'durably consume'; do
    require "$marker" "$CAPABILITY_LEASE_RECEIPT"
done
deny 'LocalSocket|LocalServerSocket|startActivity|startService|bindService|sendBroadcast|NotificationManager|case "(execute|undo)"' \
    "$CAPABILITY_LEASE_RECEIPT"

# AiShell may acknowledge only an issuer-produced indeterminate submission
# after the Activity result crosses the exact five-field UI boundary. The
# broker, not the model or issuer, owns the release call; recovery is a
# separate issuer-package request and carries no receipt/status claim.
for marker in \
        'extras.size\(\) != 5' \
        'STATUS_INDETERMINATE' \
        'deriveSubmissionStatusTupleSha256' \
        'acknowledgeSubmissionDelivery' \
        'SUBMISSION_STATUS_FIELDS' \
        'STATUS_SUBMITTED' \
        'setPackage\(ISSUER_PACKAGE\)' \
        'binder.isBinderAlive\(\)'; do
    require "$marker" "$CAPABILITY_LEASE_DELIVERY_ACK"
done
for marker in \
        'AgentDescriptor descriptor = AgentDescriptor.CODEX' \
        'descriptor.identityKeySha256\(\).equals\(identityKey\)' \
        'descriptor.identityKeySha256\(\).equals\(executable\)'; do
    require "$marker" "$CAPABILITY_LEASE_RECEIPT"
done
for marker in \
        'private static final AgentDescriptor CODEX = AgentDescriptor.CODEX' \
        'CODEX.identityKeySha256\(\).equals\(agentExecutableSha\)'; do
    require "$marker" "$DIRECT_RESULT"
done
# The capability-lease binder API is an additional UI-only dependency; keep
# the original agent identity library mandatory without requiring a
# single-entry static_libs list.
require 'static_libs: \[' "$BLUEPRINT"
require '"trillionnium-agent-identity-product"' "$BLUEPRINT"
deny '483eb9e97d3ee81bae8656f25749f6cc2c310575898b77e5a364b727a798c8c3' \
    "$CAPABILITY_LEASE_RECEIPT" "$DIRECT_RESULT"

for marker in \
        'workflow-recovery.v5' \
        'PHASE_DIRECT_RESULT = "direct_result_complete"' \
        'direct_result_json' \
        'direct_plan_payload_sha256' \
        'context_captured_at_ms' \
        'EGRESS_CHALLENGE_INTEGER_FIELDS' \
        'EGRESS_CHALLENGE_STRING_FIELDS' \
        'requireExactEgressChallengeShape' \
        'egressChallengeInteger' \
        'raw instanceof String' \
        'challenge.get\("allowed_actions"\) instanceof org.json.JSONArray' \
        'StrictJson.parseObject' \
        'DirectAgentResult.parse' \
        'MAX_STATE_BYTES = 896 \* 1024'; do
    require "$marker" "$WORKFLOW_RECOVERY"
done
require 'WorkflowRecoveryState\.requireExactEgressChallengeShape\(challenge\)' "$ACTIVITY"
deny 'challenge\.(get|opt)(Int|Long)\(' "$ACTIVITY" "$WORKFLOW_RECOVERY"
deny 'workflow-recovery.v3|PHASE_PLAN_READY|PHASE_ACTION_CONSENT|PHASE_APPROVE_DISPATCHED|PHASE_ACTION_COMPLETE|PHASE_UNDO_DISPATCHED|approval_at_ms|agent_plan_id|agent_approval_id|action_consent|execution_expectation|action_previous_receipt_id|undo_source_receipt' "$WORKFLOW_RECOVERY" "$ACTIVITY"
for marker in \
        'edge\("plan_dispatched", "direct_result_complete"\)' \
        'edge\("egress_revoke_dispatched", "direct_result_complete"\)' \
        'edge\("direct_result_complete", "memory_save_dispatched"\)' \
        'requireExplicitArchive'; do
    require "$marker" "$WORKFLOW_PROTOCOL"
done
deny 'plan_ready|action_consent_pending|approve_dispatched|action_complete|undo_dispatched' "$WORKFLOW_PROTOCOL"

for marker in \
        'WorkflowRecoveryStore.beginExplicitWorkflow' \
        'WorkflowRecoveryStore.compareAndSetPhase' \
        'WorkflowRecoveryStore.clearIfOwned' \
        'archiveReceiptCustodyAfterHandoff' \
        'PHASE_MEMORY_SAVE_DISPATCHED' \
        'PHASE_MEMORY_DELETE_DISPATCHED' \
        'IN_FLIGHT_RECOVERY.putIfAbsent' \
        'maybeRecoverPendingOperation'; do
    require "$marker" "$ACTIVITY"
done
for marker in \
        'createDeviceProtectedStorageContext' \
        'AndroidKeyStore' \
        'setUnlockedDeviceRequired\(true\)' \
        'SECURITY_LEVEL_TRUSTED_ENVIRONMENT' \
        'HOLD_NO_REPLAY' \
        'quarantineAndHold' \
        'verifiedWrite' \
        'Os.rename' \
        'Os.fsync' \
        'MessageDigest.isEqual' \
        'O_NOFOLLOW' \
        'expires_elapsed_ms'; do
    require "$marker" "$WORKFLOW_STORE"
done
for marker in 'AES/GCM/NoPadding' 'cipher.updateAAD' 'GCMParameterSpec' 'Arrays.fill'; do
    require "$marker" "$WORKFLOW_CRYPTO"
done

for marker in \
        'ai-shell-receipt-publish-v1.uncertain' \
        'matchingDirectHead' \
        'validateCustodyReceipt' \
        'reconcileTransactionLocked' \
        'ReceiptStoreProtocol.publishDecision' \
        'previous_receipt_id' \
        'receipt_custody_hold'; do
    require "$marker" "$RECEIPT_STORE"
done
for marker in 'requirePublishCas' 'publishDecision' 'afterCrashBarrier'; do
    require "$marker" "$RECEIPT_PROTOCOL"
done

for marker in \
        'Bundle getContext\(String requestId, String captureId, String captureReceipt\)' \
        'Bundle selectMemoryContext\(String requestId, String memoryId, String expectedPayloadSha256' \
        'ContextMemoryAbi.memorySelectionPayload' \
        'ContextMemoryAbi.requireMemorySelectionEcho' \
        'call\(requestId, "select_memory_context", payload\)' \
        'ContextMemoryAbi.requireMemoryDeleteEcho'; do
    require "$marker" "$CLIENT"
done
for marker in 'requireOriginalRequestEcho' 'requireMemoryDeleteEcho' \
        'raw_cleartext_persisted' 'encrypted_context_payload_persisted'; do
    require "$marker" "$CONTEXT_MEMORY_ABI"
done
for marker in 'metadata-only, one bounded page' 'payload_included' 'duplicate_memory_id' \
        'requireUnchanged'; do
    require "$marker" "$MEMORY_ADAPTER"
done
deny 'Use latest|useLatestMemory|include_payload", *true|items_json' "$ACTIVITY" "$CLIENT"

for marker in 'SecureRandom' 'new byte\[16\]' 'req'; do
    require "$marker" "$REQUEST_IDENTITY"
done
require 'mRequestId = RequestIdentity.workflow\(\)' "$ACTIVITY"
deny 'System.currentTimeMillis\(\).*req-|System.currentTimeMillis\(\).*policy-' "$ACTIVITY"

deny 'getMessage\(\)|bounded\(error\)' "$CLIENT" "$ACTIVITY"
deny 'credential_(import|provision)[^\n]*getString\("reason"' "$CLIENT" "$ACTIVITY"

echo "PASS: Direct Agent closure, physical legacy retirement, and durable custody contracts"
