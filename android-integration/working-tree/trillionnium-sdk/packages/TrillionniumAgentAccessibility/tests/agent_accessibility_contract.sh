#!/bin/bash
set -euo pipefail

ROOT="${ANDROID_BUILD_TOP:-$(cd "$(dirname "$0")/../../../.." && pwd)}"
BASE="$ROOT/trillionnium-sdk/packages/TrillionniumAgentAccessibility"
MANIFEST="$BASE/AndroidManifest.xml"
README="$BASE/README.md"
CONFIG="$BASE/res/xml/agent_accessibility_service.xml"
PROTOCOL="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityProtocol.java"
REQUEST_ID="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityRequestId.java"
OPERATION_ID="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityOperationId.java"
REPLAY_POLICY="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityReplayPolicy.java"
ACK_CHAIN="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityReplayAckChain.java"
CONTROL_PROTOCOL="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityReplayControlProtocol.java"
CONTROL_HANDLER="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityReplayControlHandler.java"
JOURNAL="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityReplayJournal.java"
REPLAY_FILE="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityReplayFile.java"
REPLAY="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityReplayLedger.java"
GESTURE_OUTCOME="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityGestureOutcome.java"
SNAPSHOT_REDACTION="$BASE/src/org/trillionnium/agentaccessibility/AccessibilitySnapshotRedaction.java"
SERVICE="$BASE/src/org/trillionnium/agentaccessibility/AgentAccessibilityService.java"
AUTHORIZATION_GATE="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityUserAuthorizationGate.java"
AUTHORIZATION_SESSION="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityAuthorizationSession.java"
DEFERRED_CLOSE="$BASE/src/org/trillionnium/agentaccessibility/AccessibilityDeferredClose.java"
PEER="$BASE/src/org/trillionnium/agentaccessibility/DirectPeerPolicy.java"
DESCRIPTOR="$ROOT/trillionnium-sdk/agentidentity/src/org/trillionnium/agentidentity/AgentDescriptor.java"
DESCRIPTOR_REGISTRY="$ROOT/trillionnium-sdk/agentidentity/src/org/trillionnium/agentidentity/AgentDescriptorRegistry.java"
REPLAY_TEST="$BASE/tests/src/org/trillionnium/agentaccessibility/AccessibilityReplayLedgerTest.java"
ACK_TEST="$BASE/tests/src/org/trillionnium/agentaccessibility/AccessibilityReplayAckTest.java"
CONTROL_TEST="$BASE/tests/src/org/trillionnium/agentaccessibility/AccessibilityReplayControlHandlerTest.java"
PEER_TEST="$BASE/tests/src/org/trillionnium/agentaccessibility/AgentDescriptorEndpointTest.java"
SAFETY_TEST="$BASE/tests/src/org/trillionnium/agentaccessibility/AccessibilitySafetySemanticsTest.java"
SNAPSHOT_TEST="$BASE/tests/src/org/trillionnium/agentaccessibility/AccessibilitySnapshotProtocolTest.java"
AUTHORIZATION_TEST="$BASE/tests/src/org/trillionnium/agentaccessibility/AccessibilityAuthorizationSessionTest.java"
DEFERRED_CLOSE_TEST="$BASE/tests/src/org/trillionnium/agentaccessibility/AccessibilityDeferredCloseTest.java"

if [[ ! -f "$SERVICE" ]]; then
    TEST_DIR=$(cd "$(dirname "$0")" && pwd)
    MANIFEST=$(find "$TEST_DIR" -name AndroidManifest.xml -print -quit)
    README=$(find "$TEST_DIR" -name README.md -print -quit)
    CONFIG=$(find "$TEST_DIR" -name agent_accessibility_service.xml -print -quit)
    PROTOCOL=$(find "$TEST_DIR" -name AccessibilityProtocol.java -print -quit)
    REQUEST_ID=$(find "$TEST_DIR" -name AccessibilityRequestId.java -print -quit)
    OPERATION_ID=$(find "$TEST_DIR" -name AccessibilityOperationId.java -print -quit)
    REPLAY_POLICY=$(find "$TEST_DIR" -name AccessibilityReplayPolicy.java -print -quit)
    ACK_CHAIN=$(find "$TEST_DIR" -name AccessibilityReplayAckChain.java -print -quit)
    CONTROL_PROTOCOL=$(find "$TEST_DIR" -name AccessibilityReplayControlProtocol.java -print -quit)
    CONTROL_HANDLER=$(find "$TEST_DIR" -name AccessibilityReplayControlHandler.java -print -quit)
    JOURNAL=$(find "$TEST_DIR" -name AccessibilityReplayJournal.java -print -quit)
    REPLAY_FILE=$(find "$TEST_DIR" -name AccessibilityReplayFile.java -print -quit)
    REPLAY=$(find "$TEST_DIR" -name AccessibilityReplayLedger.java -print -quit)
    GESTURE_OUTCOME=$(find "$TEST_DIR" -name AccessibilityGestureOutcome.java -print -quit)
    SNAPSHOT_REDACTION=$(find "$TEST_DIR" -name AccessibilitySnapshotRedaction.java -print -quit)
    SERVICE=$(find "$TEST_DIR" -name AgentAccessibilityService.java -print -quit)
    AUTHORIZATION_GATE=$(find "$TEST_DIR" -name AccessibilityUserAuthorizationGate.java -print -quit)
    AUTHORIZATION_SESSION=$(find "$TEST_DIR" -name AccessibilityAuthorizationSession.java -print -quit)
    DEFERRED_CLOSE=$(find "$TEST_DIR" -name AccessibilityDeferredClose.java -print -quit)
    PEER=$(find "$TEST_DIR" -name DirectPeerPolicy.java -print -quit)
    DESCRIPTOR=$(find "$TEST_DIR" -name AgentDescriptor.java -print -quit)
    DESCRIPTOR_REGISTRY=$(find "$TEST_DIR" -name AgentDescriptorRegistry.java -print -quit)
    REPLAY_TEST=$(find "$TEST_DIR" -name AccessibilityReplayLedgerTest.java -print -quit)
    ACK_TEST=$(find "$TEST_DIR" -name AccessibilityReplayAckTest.java -print -quit)
    CONTROL_TEST=$(find "$TEST_DIR" -name AccessibilityReplayControlHandlerTest.java -print -quit)
    PEER_TEST=$(find "$TEST_DIR" -name AgentDescriptorEndpointTest.java -print -quit)
    SAFETY_TEST=$(find "$TEST_DIR" -name AccessibilitySafetySemanticsTest.java -print -quit)
    SNAPSHOT_TEST=$(find "$TEST_DIR" -name AccessibilitySnapshotProtocolTest.java -print -quit)
    AUTHORIZATION_TEST=$(find "$TEST_DIR" -name AccessibilityAuthorizationSessionTest.java -print -quit)
    DEFERRED_CLOSE_TEST=$(find "$TEST_DIR" -name AccessibilityDeferredCloseTest.java -print -quit)
fi

for source in \
    "$MANIFEST" "$README" "$CONFIG" "$PROTOCOL" "$REQUEST_ID" "$OPERATION_ID" \
    "$ACK_CHAIN" "$CONTROL_PROTOCOL" "$CONTROL_HANDLER" "$JOURNAL" "$REPLAY_FILE" \
    "$REPLAY_POLICY" "$REPLAY" "$SERVICE" "$AUTHORIZATION_GATE" "$AUTHORIZATION_SESSION" \
    "$DEFERRED_CLOSE" \
    "$PEER" "$DESCRIPTOR" \
    "$DESCRIPTOR_REGISTRY" \
    "$GESTURE_OUTCOME" "$SNAPSHOT_REDACTION" "$REPLAY_TEST" "$ACK_TEST" "$CONTROL_TEST" "$PEER_TEST" \
    "$SAFETY_TEST" "$SNAPSHOT_TEST" "$AUTHORIZATION_TEST" "$DEFERRED_CLOSE_TEST"; do
    [[ -f "$source" ]] || { echo "missing contract input: $source" >&2; exit 1; }
done

require() {
    local marker=$1
    local source=$2
    grep -Eq "$marker" "$source" || {
        echo "missing Accessibility contract marker '$marker' in $source" >&2
        exit 1
    }
}

for marker in \
    'AccessibilityManager' \
    'isEnabled\(\)' \
    'getEnabledAccessibilityServiceList' \
    'expectedComponent\.equals'; do
    require "$marker" "$AUTHORIZATION_GATE"
done
for marker in \
    'closeAfterTermination' \
    'while \(!worker\.isTerminated\(\)\)' \
    'worker\.awaitTermination' \
    'closeAction\.close\(\)'; do
    require "$marker" "$DEFERRED_CLOSE"
done
for marker in \
    'closeWaitsUntilInterruptedWorkerActuallyTerminates' \
    'shutdownFromWorkerDoesNotSelfJoinBeforeDeferredClose'; do
    require "$marker" "$DEFERRED_CLOSE_TEST"
done
require 'AccessibilityDeferredCloseTest\.java' "$BASE/Android.bp"
for marker in \
    'new ComponentName\(this, AgentAccessibilityService\.class\)' \
    'UserHandle\.myUserId\(\) != UserHandle\.USER_SYSTEM' \
    'mAuthorization\.activateIfAuthorized' \
    'authorizationUsableOrStop\(authorizationGeneration\)' \
    'explicit per-user Accessibility authorization unavailable; held closed'; do
    require "$marker" "$SERVICE"
done
for marker in \
    'interface AuthorizationSource' \
    'activateIfAuthorized' \
    'isCurrentAndAuthorized' \
    'mActiveGeneration = 0' \
    'catch \(RuntimeException unavailable\)'; do
    require "$marker" "$AUTHORIZATION_SESSION"
done
for marker in \
    'disabledSourceNeverActivates' \
    'revokeInvalidatesCurrentGenerationAndReconnectDoesNotReviveOldWork' \
    'authorizationSourceFailureIsClosed'; do
    require "$marker" "$AUTHORIZATION_TEST"
done
authorization_line=$(grep -n 'mAuthorization\.activateIfAuthorized' "$SERVICE" | head -n1 | cut -d: -f1)
backend_start_line=$(grep -n '^[[:space:]]*startDirectBackend(authorizationGeneration);' \
    "$SERVICE" | head -n1 | cut -d: -f1)
[[ -n "$authorization_line" && -n "$backend_start_line" \
        && "$authorization_line" -lt "$backend_start_line" ]] || {
    echo "Accessibility backend must remain closed until the exact component is user-enabled" >&2
    exit 1
}

for dispatch in \
        'node\.performAction' \
        'performGlobalAction' \
        'dispatchGesture'; do
    dispatch_line=$(grep -n "$dispatch" "$SERVICE" | head -n1 | cut -d: -f1)
    prior_recheck=$(head -n "$dispatch_line" "$SERVICE" \
        | grep -n 'authorizationUsableOrStop(authorizationGeneration)' \
        | tail -n1 | cut -d: -f1)
    [[ -n "$dispatch_line" && -n "$prior_recheck" && "$prior_recheck" -lt "$dispatch_line" ]] || {
        echo "Accessibility authorization must be rechecked immediately before $dispatch" >&2
        exit 1
    }
done

for marker in \
    'MAGIC = "TRACSC01"' \
    'VERSION = 1' \
    'OP_ACTIVATE = 1' \
    'OP_ACK = 2' \
    'ACTIVATE_REQUEST_BYTES = 32' \
    'ACK_REQUEST_BYTES = 168' \
    'ACTIVATE_RESPONSE_BYTES = 188' \
    'readSingleRequest' \
    'requireEndOfConnection' \
    'allZero' \
    'isLocalStatePristine'; do
    require "$marker" "$CONTROL_PROTOCOL"
done
for marker in \
    '^final class AccessibilityReplayControlHandler' \
    'enum AuthenticatedRole' \
    'interface BeforeMutationGate' \
    'beforeMutation\.requireCurrent\(\)' \
    'mReplayLedger\.activateEpochFromTrustedAdapter' \
    'mReplayLedger\.acknowledgeCommittedFromTrustedAdapter' \
    'closedReplayError'; do
    require "$marker" "$CONTROL_HANDLER"
done
for marker in \
    'createdExistingAndEpochStateAreExplicitWithoutBootstrapOrRotation' \
    'nullPeerAndWrongEndpointLocalRoleFailBeforeStateMutation' \
    'magicVersionOperationLengthTrailingEpochThroughAndDigestFailClosed' \
    'zeroEpochIsRejectedByEveryControlResponseBoundary' \
    'oneConnectionCarriesExactlyOneFrameAndPayloadHasNoIdentitySelector' \
    'ackUsesExistingLedgerExactRetryStaleAndForkSemantics' \
    'ioAndStoreFailuresExposeOnlyClosedCodesWithoutInternalMessages'; do
    require "$marker" "$CONTROL_TEST"
done
require 'authorizationGateRunsAfterFullFrameAndBeforeLedgerMutation' "$CONTROL_TEST"
for marker in \
    'mWorkerExecutors' \
    'AccessibilityDeferredClose\.closeAfterTermination' \
    'ledger::close' \
    'workers = mWorkerExecutors\.toArray' \
    'handler\.handleSingleFrame' \
    'authorizationUsableOrStop\(authorizationGeneration\)'; do
    require "$marker" "$SERVICE"
done

for marker in \
    'AtomicReference<State>' \
    'compareAndSet\(State\.PENDING, terminal\)' \
    'EFFECT_OUTCOME_INDETERMINATE = "indeterminate"' \
    'gesture_cancelled' \
    'gesture_timeout' \
    'gesture_interrupted'; do
    require "$marker" "$GESTURE_OUTCOME"
done

for marker in \
    'MAX_VISIBLE_CODE_POINTS = 512' \
    'visibleBoundedValue' \
    'Supplier<\? extends CharSequence>' \
    'boundedText\(CharSequence value\)' \
    'Character\.isHighSurrogate' \
    'Character\.isLowSurrogate' \
    'SNAPSHOT_MODE_METADATA_ONLY\.equals\(snapshotMode\)' \
    'SNAPSHOT_MODE_FULL_TEXT\.equals\(snapshotMode\)' \
    'redactsValue\(String snapshotMode, boolean passwordOrPasswordAncestor\)' \
    'return passwordOrPasswordAncestor' \
    'throw new IllegalArgumentException\("invalid snapshot mode"\)'; do
    require "$marker" "$SNAPSHOT_REDACTION"
done

for marker in \
    'PROTOCOL = "org\.trillionnium\.agent-accessibility\.v2"' \
    'SOCKET_NAME = "trillionnium_accessibility"' \
    'MAX_REQUEST_BYTES = 256 \* 1024' \
    'MAX_RESPONSE_BYTES = 1024 \* 1024' \
    'MAX_BATCH_ACTIONS = 128' \
    'MAX_GESTURE_DURATION_MS = 60_000' \
    'MAX_BATCH_GESTURE_DURATION_MS = 60_000' \
    'SNAPSHOT_MODE_METADATA_ONLY = "metadata_only"' \
    'SNAPSHOT_MODE_FULL_TEXT = "full_text"' \
    'MAX_TEXT_CHARS = 16_384' \
    'validateGlobalAction' \
    '"take_screenshot"\.equals\(action\)' \
    'case "snapshot_mode"' \
    'invalid_snapshot_mode' \
    'validateStrictJsonLexemes' \
    'scanStrictJsonString' \
    'scanJsonHexCodeUnit' \
    'Character\.isHighSurrogate' \
    'scanStrictJsonNumber' \
    'non-integer JSON number' \
    'scanStrictJsonLiteral' \
    'requireJsonTokenBoundary' \
    'duplicate_field' \
    'unknown_field' \
    'trailing_json' \
    'nested_batch_denied' \
    'batch_snapshot_denied' \
    'invalid_gesture_timing' \
    'batch_gesture_budget_exceeded' \
    'CANONICAL_IDENTITY_VERSION' \
    'AgentDescriptor peerIdentity' \
    'peerIdentity\.replayNamespace\(\)' \
    'canonicalIdentity' \
    'writeCanonicalAction' \
    'writeCanonicalString\(output, action\.snapshotMode\)' \
    'for \(Action child : action\.actions\)'; do
    require "$marker" "$PROTOCOL"
done
! grep -Eq 'dismiss_notification_shade' "$PROTOCOL" "$SERVICE" "$README" || {
    echo "retired Accessibility global action remains in the backend contract" >&2
    exit 1
}
! grep -Eq 'case "(peer|peer_identity|agent_id|uid|gid|pid|selinux_context)"' \
        "$PROTOCOL" || {
    echo "wire JSON can select or inject Accessibility peer identity" >&2
    exit 1
}

for marker in \
    'READ_ONLY_REPLAY_SCOPE = "read_only_resampled"' \
    'return !"snapshot"\.equals\(actionType\)'; do
    require "$marker" "$REPLAY_POLICY"
done

for marker in \
    'FILE_MAGIC' \
    'RECORD_MAGIC' \
    'TYPE_IN_FLIGHT' \
    'TYPE_COMMITTED' \
    'TYPE_INDETERMINATE' \
    'TYPE_EPOCH_WATERMARK_LEGACY' \
    'TYPE_EPOCH_WATERMARK' \
    'TYPE_COMMITTED_INDETERMINATE' \
    'CRC32' \
    'recordInFlight' \
    'recordCommitted' \
    'recordCommittedIndeterminate' \
    'FILE_VERSION = 2' \
    'RECORD_VERSION = 2' \
    'AgentDescriptor' \
    'repairTornTail' \
    'replay checksum failure' \
    'truncateAndSync' \
    'rewriteAndSync' \
    'acknowledgeThrough' \
    'authenticatedAckSha256' \
    'authenticatedAckChainSha256' \
    'applyAcknowledgedWatermark' \
    'store-level retry completes cleanup and directory durability' \
    'compact\(\)'; do
    require "$marker" "$JOURNAL"
done

for marker in \
    'createDeviceProtectedStorageContext' \
    'getNoBackupFilesDir' \
    'O_NOFOLLOW' \
    'O_CLOEXEC' \
    'S_ISREG' \
    'st_nlink != 1' \
    'FILE_MODE = 0600' \
    'DIRECTORY_MODE = 0700' \
    'Os\.pwrite' \
    'Os\.fsync' \
    'Os\.ftruncate' \
    'TEMP_FILE_NAME = "replay-v1\.log\.new"' \
    'Os\.rename' \
    'rewriteAndSync' \
    'mDescriptor = replacementFd'; do
    require "$marker" "$REPLAY_FILE"
done

for marker in \
    'EPOCH_HEX_CHARS = 32' \
    'DIGEST_HEX_CHARS = 64' \
    'ZERO_EPOCH' \
    'validEpoch\(fields\[1\]\)' \
    'Long\.parseLong' \
    'SHA-256' \
    'matchesCanonicalIdentity'; do
    require "$marker" "$OPERATION_ID"
done

require 'AccessibilityRequestId\.isValid\(parsed\.requestId\)' "$PROTOCOL"
! grep -Eq 'validAtom\(parsed\.requestId' "$PROTOCOL" || {
    echo "request_id must not use the node-id alphabet" >&2
    exit 1
}
for marker in \
    'MAX_CHARS = 128' \
    "character == ':'"; do
    require "$marker" "$REQUEST_ID"
done
! grep -Eq "character == '/'" "$REQUEST_ID" || {
    echo "request_id alphabet must reject slash" >&2
    exit 1
}

for marker in \
    'STATE_IN_FLIGHT' \
    'STATE_COMMITTED' \
    'STATE_INDETERMINATE' \
    'STATE_COMMITTED_INDETERMINATE' \
    'Arrays\.equals' \
    'request_replay_capacity_exhausted' \
    'request_id_conflict' \
    'request_outcome_indeterminate' \
    'request_replay_unavailable' \
    'mJournal\.recordInFlight' \
    'mJournal\.recordCommitted' \
    'mJournal\.recordCommittedIndeterminate' \
    'AgentDescriptor peerIdentity' \
    'peerIdentity\.replayKey\(requestId\)' \
    'owner\.result = result\.clone\(\)' \
    'mLock\.notifyAll\(\)'; do
    require "$marker" "$REPLAY"
done
for marker in \
    'ACK_RECLAMATION_STATUS' \
    'inactive_backend_foundation_requires_trusted_adapter_journal_v1' \
    'activateEpochFromTrustedAdapter' \
    'acknowledgeCommittedFromTrustedAdapter' \
    'already_acknowledged' \
    'operation_ack_not_committed_contiguous' \
    'operation_ack_chain_mismatch' \
    'AccessibilityReplayAckChain\.matches' \
    'operation_epoch_indeterminate' \
    'mEntriesPerPeer' \
    'mReservedBytesPerPeer'; do
    require "$marker" "$REPLAY"
done

for marker in \
    'trillionnium\.direct-operation-outer-ack-chain-step\.v1' \
    'ADAPTER_ID = "accessibility"' \
    'previous_ack_watermark' \
    'acknowledged_through_sequence' \
    'acknowledgement_sha256' \
    'previous_ack_chain_sha256' \
    'MessageDigest\.isEqual'; do
    require "$marker" "$ACK_CHAIN"
done

for marker in \
    'zeroEpochCannotEnterOperationIdsLedgerJournalOrAckChain' \
    'exactAckRetryIsMutationFreeAndEveryBindingDriftFails' \
    'ackChainMustCryptographicallyExtendPreviousWatermark' \
    'journalRejectsForkedChainBeforePublishingWatermark' \
    'committedIndeterminateResponseReplaysButBlocksAckAndEpochAcrossRestart' \
    'concurrentIdenticalAckRetriesConvergeOnOneDurableState' \
    'journalExactRetryRecompactsWithoutRepublishingWatermark' \
    'legacyAckRecordWithoutAuthenticatedBindingFailsRecoveryClosed'; do
    require "$marker" "$ACK_TEST"
done
require 'operation_ack_retry_conflict' "$REPLAY"

for marker in \
    'DirectPeerPolicy\.verify' \
    'AgentDescriptor peerIdentity = DirectPeerPolicy\.verify\(socket\)' \
    'handleOwnedSocket\(' \
    'socket, peerIdentity, authorizationGeneration' \
    'MAX_REPLAY_ENTRIES_PER_PEER = 128' \
    'MAX_REPLAY_RESERVED_BYTES_PER_PEER = 48L \* 1024 \* 1024' \
    'mPublishedGeneration' \
    'mPublishedEpoch' \
    'mUiEpoch' \
    'stale_node' \
    'requestedWindowId' \
    'getWindows\(\)' \
    'NodeRef\.parse' \
    'executeBatch' \
    '!AccessibilityReplayPolicy\.requiresDurableReplay\(request\.action\.type\)' \
    'executeReadOnly\(request, authorizationGeneration\)' \
    'AccessibilityReplayPolicy\.READ_ONLY_REPLAY_SCOPE' \
    'AccessibilityOperationId\.parse\(request\.requestId\)' \
    'operation_epoch_required' \
    'invalid_operation_id' \
    'ledger\.executeClassified' \
    'effectOutcomeIsIndeterminate' \
    '\.indeterminate\(encoded\)' \
    'request\.canonicalIdentity\(\)' \
    'replay_scope", "whole_request' \
    'failed_action_effect", "indeterminate' \
    'AccessibilityGestureOutcome outcome = new AccessibilityGestureOutcome' \
    'OperationResult\.fromGesture' \
    'effect_outcome", result\.effectOutcome' \
    'passwordAncestor \|\| password' \
    'AccessibilitySnapshotRedaction\.visibleBoundedValue' \
    'node::getText' \
    'node::getContentDescription' \
    'passwordAncestor \|\| password\)' \
    'put\(response, "snapshot_mode", snapshotMode\)' \
    'snapshotErrorResponse' \
    'snapshotModeFromResponse' \
    'dispatchGesture' \
    'AccessibilityNodeInfo\.ACTION_SET_TEXT' \
    'performGlobalAction'; do
    require "$marker" "$SERVICE"
done

for marker in \
    'snapshotModeIsRequiredAndClosed' \
    'duplicateUnknownAndUnrelatedSnapshotFieldsFailClosed' \
    'nonStandardJsonSyntaxFailsClosed' \
    'strictJsonNumberLexemesAreClosedAndStandardFormsRemainAccepted' \
    'strictJsonStringsAcceptStandardEscapesAndUnicode' \
    'setTextLimitRemainsExactly16384Utf16CodeUnits' \
    'globalActionVocabularyIsTheExactEightValueClientClosure' \
    'snapshotModeParticipatesInCanonicalIdentity' \
    'metadataModeRedactsSensitiveMarkersAcrossWholeSyntheticTree' \
    'fullTextPreservesOrdinaryValuesAndDoubleRedactsPasswordNodes' \
    'snapshotTextBoundsBmpAndAstralAt512UnicodeScalars' \
    'snapshotTextNeverSplitsOrEmitsAnIsolatedSurrogateAtBoundary' \
    'snapshotRedactionPrecedesEverySensitiveValueRead' \
    'snapshotRemainsForbiddenInsideBatch' \
    'nodeIdBoundIsExactly512AsciiScalars' \
    'SENSITIVE_GRANDCHILD_DESCRIPTION'; do
    require "$marker" "$SNAPSHOT_TEST"
done
! grep -Eq 'activateEpochFromTrustedAdapter|acknowledgeCommittedFromTrustedAdapter|acknowledgeThrough' \
        "$SERVICE" "$PROTOCOL" || {
    echo "inactive Accessibility ACK foundation leaked into the model-facing wire" >&2
    exit 1
}
! grep -Eq 'case "(ack|acknowledge|epoch|sequence|watermark|through_sequence)"' \
        "$SERVICE" "$PROTOCOL" || {
    echo "Accessibility wire exposes inactive ACK control fields" >&2
    exit 1
}
! grep -Eq 'put\(response, "(peer|peer_identity|agent_id|uid|gid|pid|selinux_context)"' \
        "$SERVICE" || {
    echo "Accessibility response exposes peer credentials or namespace" >&2
    exit 1
}

for marker in \
    'passwordSnapshotRedactsTextAndContentDescription' \
    'cancelledGestureIsExplicitlyIndeterminateAndLateCompletionCannotRewriteIt' \
    'timedOutGestureIsExplicitlyIndeterminateAndLateCallbackCannotRewriteIt' \
    'interruptedWaitLinearizesAgainstCallbacksWithoutReturningOrdinaryFailure'; do
    require "$marker" "$SAFETY_TEST"
done


for marker in \
    'wireRequestIdAlphabetMatchesDirectClientAndRejectsSlash' \
    'readOnlySnapshotsNeverConsumeEffectLedgerCapacity' \
    'lostResponseAfterEffectReturnsExactCommitWithoutReexecution' \
    'gestureIndeterminateResponseIsDurablyRetainedAndReplayed' \
    'retryWhileEffectResponseIsPendingFailsClosedThenReplaysCommit' \
    'concurrentSameIdHasExactlyOneCasWinner' \
    'conflictingCanonicalRequestIsRejectedDuringAndAfterExecution' \
    'partialBatchFailureIsOneTerminalWholeRequestResult' \
    'tornFirstInFlightIsIgnoredAndNeverStartsItsEffect' \
    'inFlightAppendAcknowledgementLostNeverStartsOrRetriesEffect' \
    'crashAfterDurableInFlightNeverReexecutesAfterRestart' \
    'tornCommitRecoversAsIndeterminateAndNeverRepeatsEffect' \
    'commitAppendAcknowledgementLostReplaysDurableResult' \
    'truncatedCommittedTailRecoversOnlyItsDurableInFlight' \
    'midFileCorruptionFailsTheWholeJournalClosed' \
    'exhaustedCapacityAndIndeterminateOwnerNeverReexecute'; do
    require "$marker" "$REPLAY_TEST"
done
require 'unnamespacedV1JournalFailsClosedInsteadOfAssigningEntriesToAPeer' "$REPLAY_TEST"

for marker in \
    'ackFsyncThenNewInodeCompactionReclaimsRealCapacity' \
    'crashAfterAckFsyncBeforeRewriteRecoversWatermarkAndCompacts' \
    'tornAckAppendRetainsCommittedReplayInsteadOfReclaiming' \
    'corruptEpochWatermarkFailsWholeJournalClosed' \
    'indeterminateAndGappedSequencesCannotBeAcknowledged' \
    'operationIdFitsWireBoundWithFullDigestAndRejectsTruncation' \
    'assertEquals\(120, maximum\.length\(\)\)'; do
    require "$marker" "$ACK_TEST"
done

for marker in \
    'getPeerCredentials\(\)' \
    'SELinux\.getPeerContext' \
    'AgentDescriptorRegistry\.fromKernelIdentity' \
    'AgentDescriptorRegistry\.Endpoint\.ACCESSIBILITY'; do
    require "$marker" "$PEER"
done

for marker in \
    'CODEX' \
    '"openai-codex"' \
    '"agent-codex-direct-v1"' \
    '"agent-codex-v1"' \
    '5901' \
    'u:r:trillionnium_codex_agent:s0' \
    'org\.trillionnium\.agent-descriptor\.v1' \
    'replayNamespace' \
    'replayKey'; do
    require "$marker" "$DESCRIPTOR"
done
for marker in \
    'PRODUCT_ALLOWLIST' \
    'Collections\.unmodifiableList' \
    'org\.trillionnium\.agent-descriptor-registry\.v1' \
    'u:r:trillionnium_agent_system_api_tool:s0' \
    'u:r:trillionnium_agent_accessibility_tool:s0' \
    'Endpoint endpoint' \
    'fromKernelIdentity' \
    'fromProviderId' \
    'fromAgentId' \
    'fromReplayNamespace' \
    'canonicalBytes' \
    'canonicalSha256' \
    'CANONICAL_SHA256'; do
    require "$marker" "$DESCRIPTOR_REGISTRY"
done
! grep -Eq '(fromJson|JSONObject|JsonReader|registerDescriptor|put\()' \
        "$DESCRIPTOR_REGISTRY" || {
    echo "Agent descriptor registry exposes runtime/model-authored authority" >&2
    exit 1
}

for marker in \
    'exactKernelUidGidAndAccessibilityToolDomainSelectClosedIdentity' \
    'unknownMismatchModelDomainAndWrongAdapterDomainFailClosed' \
    'unknownPeerIsRejectedBeforeLedgerClaimOrEffect' \
    'forgedWireIdentityStringCannotSelectReplayNamespace' \
    'persistentIdentityIsPidIndependentAndDecoderIsClosed'; do
    require "$marker" "$PEER_TEST"
done

require 'android:permission="android\.permission\.BIND_ACCESSIBILITY_SERVICE"' "$MANIFEST"
require 'android:exported="true"' "$MANIFEST"
require 'android:canPerformGestures="true"' "$CONFIG"
require 'android:canRetrieveWindowContent="true"' "$CONFIG"
require 'Installing the package does \*\*not\*\* enable the service' "$README"
require 'user or an explicit' "$README"
require 'SetupWizard policy must authorize' "$README"
require 'whole ordered batch' "$README"
require 'device-protected no-backup directory' "$README"
require 'on-device kill/power-loss campaign' "$README"
require 'complete-length checksum failure' "$README"
require 'including at EOF' "$README"
require 'snapshot.*read-only observation' "$README"
require 'Every `snapshot` request must also carry the closed `snapshot_mode` value' "$README"
require '`metadata_only` or `full_text`' "$README"
require 'mode is part of the canonical request' "$README"
require 'Snapshot remains forbidden inside `batch`' "$README"
require 'same SDK `AgentDescriptorRegistry`' "$README"
require 'immutable OS-compiled product allowlist' "$README"
require '`node_id` values of 1--512 ASCII characters' "$README"
require 'identically 512 UTF-16 code units, Unicode scalar values, and UTF-8' "$README"
require 'bounded at exactly 16,384 UTF-16 code units' "$README"
require '`global_action` vocabulary is the exact closed set' "$README"
require 'strict RFC 8259 JSON' "$README"
require 'isolated UTF-16 surrogate escapes fail closed' "$README"
require 'Integer-valued fields must use' "$README"
require 'read_only_resampled' "$README"
require 'never consumes a durable' "$README"
require 'response echoes `snapshot_mode` at' "$README"
require 'alongside `action: snapshot`' "$README"
require 'successful response carries one recursive `root` object' "$README"
require 'always carries the closed fields `node_id`' "$README"
require 'bounded tree retains node ID' "$README"
require 'every node publishes `text: ""` and' "$README"
require 'never omitted or null' "$README"
require 'bounded to at most 512 Unicode' "$README"
require 'scalar values \(code points\)' "$README"
require 'never splits a UTF-16 surrogate pair' "$README"
require 'response remains valid UTF-8' "$README"
require 'Password nodes and their descendants always publish empty `text` and empty' "$README"
require 'encoder decides this before retrieving' "$README"
require 'cancellation callback, callback timeout, or waiter' "$README"
require 'effect_outcome: indeterminate' "$README"
require 'trillionnium_agent_accessibility_tool' "$README"
require 'authenticated Codex peer' "$README"
require '128 entries and reserves at most 48 MiB for' "$README"
require 'inactive, crash-safe compaction foundation' "$README"
require 'ACK record is appended and fsynced before any result' "$README"
require 'inactive_backend_foundation_requires_trusted_adapter_journal_v1' "$README"
require 'No Accessibility socket request exposes epoch activation or ACK' "$README"
require 'TRA11JNL' "$README"
require 'never silently ignored, migrated, or assigned' "$README"
require 'No UID, GID, PID, context, or persistent peer ID' "$README"

for forbidden in \
    'trillionnium_system_api' \
    'Runtime\.getRuntime' \
    'ProcessBuilder' \
    '/system/bin/' \
    'agentd' \
    'Authority' \
    'Settings\.Secure' \
    'WRITE_SECURE_SETTINGS'; do
    ! grep -Eq "$forbidden" "$SERVICE" "$MANIFEST" || {
        echo "forbidden Accessibility route found: $forbidden" >&2
        exit 1
    }
done

echo "PASS: direct Agent Accessibility v2 contract"
