#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT="${ANDROID_BUILD_TOP:-$(cd "$(dirname "$0")/../.." && pwd)}"
BASE="$ROOT/trillionnium-sdk"
SRC="$BASE/trillionnium/lib/main/java/org/trillionnium/platform/internal"
ROOT_REGISTRATION_CONTRACT="$BASE/contracts/capability-lease-root-registration-v1.json"
ROOT_PUBLICATION_CONTRACT="$BASE/contracts/capability-lease-root-publication-v1.json"
ROOT_PUBLISHER_LAUNCH_CONTRACT="$BASE/contracts/capability-lease-root-publisher-launch-v1.json"
ROOT_AUTHENTICATOR_CONTRACT="$BASE/contracts/capability-lease-root-authenticator-v1.json"
ROOT_PROOF_CARRIER_CONTRACT="$BASE/contracts/capability-lease-root-proof-carrier-v1.json"
ROOT_KERNEL_CUSTODY_CONTRACT="$BASE/contracts/capability-lease-root-kernel-custody-v1.json"
ROOT_SOCKET_RESULT_CUSTODY_CONTRACT="$BASE/contracts/capability-lease-root-socket-result-custody-v1.json"
ROOT_LISTENER_CORRELATION_CONTRACT="$BASE/contracts/capability-lease-root-listener-correlation-v1.json"
ROOT_ROUTE_COORDINATOR_CONTRACT="$BASE/contracts/capability-lease-root-route-coordinator-v1.json"
ROOT_ROUTE_TRANSPORT_CONTRACT="$BASE/contracts/capability-lease-root-route-transport-v1.json"
ROOT_ROUTE_SOCKET_CUSTODY_CONTRACT="$BASE/contracts/capability-lease-root-route-socket-custody-v1.json"
ROOT_ROUTE_SESSION_CONTRACT="$BASE/contracts/capability-lease-root-route-session-v1.json"
BROKER="$SRC/CapabilityLeasePendingBroker.java"
CHALLENGE_ENCODER="$SRC/CapabilityLeaseChallengeEncoderV1.java"
RECEIPT_VERIFIER="$SRC/CapabilityLeaseReceiptVerifierV1.java"
KEYMINT_VERIFIER="$SRC/CapabilityLeasePinnedKeyMintVerifier.java"
LEASE_JSON="$SRC/CapabilityLeaseJson.java"
ECDSA="$SRC/CapabilityLeaseEcdsaP256.java"
COMPACTION_CODEC="$SRC/CapabilityLeaseCompactionWatermarkCodec.java"
RETIREMENT_CODEC="$SRC/CapabilityLeasePendingRetirementCodec.java"
BACKEND_ACK_PUBLISHER="$SRC/CapabilityLeaseBackendAckPublisher.java"
ROOT_PUBLICATION_BINDING="$SRC/CapabilityLeaseRootPublicationBindingV1.java"
ROOT_PUBLICATION_PROTOCOL="$SRC/CapabilityLeaseRootPublicationProtocolV1.java"
ROOT_PUBLICATION_INGRESS="$SRC/CapabilityLeaseRootPublicationIngressV1.java"
ROOT_PUBLICATION_LISTENER="$SRC/CapabilityLeaseRootPublicationSocketListenerV1.java"
ROOT_PUBLICATION_SOCKET_CONSTRUCTOR="$SRC/CapabilityLeaseRootPublicationSocketConstructorV1.java"
ROOT_AUTHENTICATOR="$SRC/CapabilityLeaseMeasuredRootJournalAuthenticatorV1.java"
ROOT_PROOF_CARRIER="$SRC/CapabilityLeaseRootProofCarrierV1.java"
ROOT_PROOF_SOCKET_LISTENER="$SRC/CapabilityLeaseRootProofSocketListenerV1.java"
ROOT_PROOF_PUBLICATION_CORRELATION="$SRC/CapabilityLeaseRootProofPublicationCorrelationV1.java"
ROOT_LISTENER_COORDINATOR="$SRC/CapabilityLeaseRootListenerCoordinatorV1.java"
ROOT_BOUND_LISTENERS="$SRC/CapabilityLeaseRootBoundListenersV1.java"
ROOT_ROUTE_TRANSPORT="$SRC/CapabilityLeaseRootRouteTransportV1.java"
ROOT_ROUTE_ADAPTER="$SRC/CapabilityLeaseRootCoordinatorRouteAdapterV1.java"
ROOT_ROUTE_SOCKET_CONNECTOR="$SRC/CapabilityLeaseRootRouteSocketConnectorV1.java"
ROOT_ROUTE_SESSION_CONSTRUCTOR="$SRC/CapabilityLeaseRootRouteSessionConstructorV1.java"
BACKEND_LEDGER="$SRC/CapabilityLeaseBackendReplayLedger.java"
BACKEND_CODEC="$SRC/CapabilityLeaseBackendReplayRecordCodec.java"
BACKEND_FILE_STORE="$SRC/CapabilityLeaseBackendReplayFileStore.java"
SYSTEM_API_COORDINATOR="$SRC/CapabilityLeaseSystemApiOpenUriCoordinator.java"
TASK_RESOLVER="$SRC/CapabilityLeaseTaskContextResolver.java"
EXECUTION_RESOLVER="$SRC/CapabilityLeaseExecutionTokenResolver.java"
TOKEN_BINDING="$SRC/CapabilityLeaseTokenBindingV1.java"
TOKEN_REGISTRY="$SRC/CapabilityLeaseTokenRegistry.java"
TOKEN_REGISTRY_CODEC="$SRC/CapabilityLeaseTokenRegistryRecordCodec.java"
TOKEN_REGISTRY_FILE_STORE="$SRC/CapabilityLeaseTokenRegistryFileStore.java"
RUNTIME_FACTORY="$SRC/CapabilityLeaseRuntimeFactory.java"
STORE="$SRC/CapabilityLeasePendingStore.java"
FILE_STORE="$SRC/CapabilityLeasePendingFileStore.java"
CODEC="$SRC/CapabilityLeasePendingRecordCodec.java"
POLICY="$SRC/CapabilityLeaseBrokerCallerPolicy.java"
VERIFIER="$SRC/CapabilityLeaseBinderCallerVerifier.java"
CALL_EXECUTOR="$SRC/CapabilityLeaseBrokerCallExecutor.java"
FACADES="$SRC/CapabilityLeaseBrokerServiceFacades.java"
SERVICE="$SRC/CapabilityLeaseBrokerService.java"
PRODUCT_ENROLLMENT="$SRC/CapabilityLeaseBrokerProductEnrollment.java"
UI_BINDER="$SRC/CapabilityLeaseUiBrokerBinder.java"
UI_PROTOCOL="$BASE/capabilityleaseapi/src/org/trillionnium/capabilitylease/CapabilityLeaseUiProtocol.java"
UI_AIDL="$BASE/capabilityleaseapi/src/org/trillionnium/capabilitylease/ICapabilityLeaseUiBroker.aidl"
CONTEXT_CONSTANTS="$BASE/sdk/src/java/trillionnium/app/TrillionniumContextConstants.java"
CURRENT_FEATURE_XML="$BASE/trillionnium/permissions/org.trillionnium.agent.system_api.xml"
CONFIG="$BASE/trillionnium/res/res/values/config.xml"
MANIFEST="$BASE/trillionnium/res/AndroidManifest.xml"
BUILD="$BASE/Android.bp"
SYSTEM_API_SERVICE="$SRC/AgentSystemApiService.java"
OS_FAULT_TEST="$BASE/tests/CapabilityLeaseOsFileStoreFaultMatrixTest.java"
CALL_EXECUTOR_TEST="$BASE/tests/CapabilityLeaseBrokerCallExecutorTest.java"
PENDING_BROKER_TEST="$BASE/tests/CapabilityLeasePendingBrokerTest.java"
OS_FAULT_MANIFEST="$BASE/tests/device/CapabilityLeaseOsFileStoreFaultMatrixAndroidManifest.xml"

if [[ ! -f "$BROKER" ]]; then
    TEST_DIR=$(cd "$(dirname "$0")" && pwd)
    locate() { find "$TEST_DIR" -name "$1" -print -quit; }
    ROOT_REGISTRATION_CONTRACT=$(locate capability-lease-root-registration-v1.json)
    ROOT_PUBLICATION_CONTRACT=$(locate capability-lease-root-publication-v1.json)
    ROOT_PUBLISHER_LAUNCH_CONTRACT=$(locate capability-lease-root-publisher-launch-v1.json)
    ROOT_AUTHENTICATOR_CONTRACT=$(locate capability-lease-root-authenticator-v1.json)
    ROOT_PROOF_CARRIER_CONTRACT=$(locate capability-lease-root-proof-carrier-v1.json)
    ROOT_KERNEL_CUSTODY_CONTRACT=$(locate capability-lease-root-kernel-custody-v1.json)
    ROOT_SOCKET_RESULT_CUSTODY_CONTRACT=$(locate capability-lease-root-socket-result-custody-v1.json)
    ROOT_LISTENER_CORRELATION_CONTRACT=$(locate capability-lease-root-listener-correlation-v1.json)
    ROOT_ROUTE_COORDINATOR_CONTRACT=$(locate capability-lease-root-route-coordinator-v1.json)
    ROOT_ROUTE_TRANSPORT_CONTRACT=$(locate capability-lease-root-route-transport-v1.json)
    ROOT_ROUTE_SOCKET_CUSTODY_CONTRACT=$(locate capability-lease-root-route-socket-custody-v1.json)
    ROOT_ROUTE_SESSION_CONTRACT=$(locate capability-lease-root-route-session-v1.json)
    BROKER=$(locate CapabilityLeasePendingBroker.java)
    CHALLENGE_ENCODER=$(locate CapabilityLeaseChallengeEncoderV1.java)
    RECEIPT_VERIFIER=$(locate CapabilityLeaseReceiptVerifierV1.java)
    KEYMINT_VERIFIER=$(locate CapabilityLeasePinnedKeyMintVerifier.java)
    LEASE_JSON=$(locate CapabilityLeaseJson.java)
    ECDSA=$(locate CapabilityLeaseEcdsaP256.java)
    COMPACTION_CODEC=$(locate CapabilityLeaseCompactionWatermarkCodec.java)
    RETIREMENT_CODEC=$(locate CapabilityLeasePendingRetirementCodec.java)
    BACKEND_ACK_PUBLISHER=$(locate CapabilityLeaseBackendAckPublisher.java)
    ROOT_PUBLICATION_BINDING=$(locate CapabilityLeaseRootPublicationBindingV1.java)
    ROOT_PUBLICATION_PROTOCOL=$(locate CapabilityLeaseRootPublicationProtocolV1.java)
    ROOT_PUBLICATION_INGRESS=$(locate CapabilityLeaseRootPublicationIngressV1.java)
    ROOT_PUBLICATION_LISTENER=$(locate CapabilityLeaseRootPublicationSocketListenerV1.java)
    ROOT_PUBLICATION_SOCKET_CONSTRUCTOR=$(locate CapabilityLeaseRootPublicationSocketConstructorV1.java)
    ROOT_AUTHENTICATOR=$(locate CapabilityLeaseMeasuredRootJournalAuthenticatorV1.java)
    ROOT_PROOF_CARRIER=$(locate CapabilityLeaseRootProofCarrierV1.java)
    ROOT_PROOF_SOCKET_LISTENER=$(locate CapabilityLeaseRootProofSocketListenerV1.java)
    ROOT_PROOF_PUBLICATION_CORRELATION=$(locate CapabilityLeaseRootProofPublicationCorrelationV1.java)
    ROOT_LISTENER_COORDINATOR=$(locate CapabilityLeaseRootListenerCoordinatorV1.java)
    ROOT_BOUND_LISTENERS=$(locate CapabilityLeaseRootBoundListenersV1.java)
    ROOT_ROUTE_TRANSPORT=$(locate CapabilityLeaseRootRouteTransportV1.java)
    ROOT_ROUTE_ADAPTER=$(locate CapabilityLeaseRootCoordinatorRouteAdapterV1.java)
    ROOT_ROUTE_SOCKET_CONNECTOR=$(locate CapabilityLeaseRootRouteSocketConnectorV1.java)
    ROOT_ROUTE_SESSION_CONSTRUCTOR=$(locate CapabilityLeaseRootRouteSessionConstructorV1.java)
    BACKEND_LEDGER=$(locate CapabilityLeaseBackendReplayLedger.java)
    BACKEND_CODEC=$(locate CapabilityLeaseBackendReplayRecordCodec.java)
    BACKEND_FILE_STORE=$(locate CapabilityLeaseBackendReplayFileStore.java)
    SYSTEM_API_COORDINATOR=$(locate CapabilityLeaseSystemApiOpenUriCoordinator.java)
    TASK_RESOLVER=$(locate CapabilityLeaseTaskContextResolver.java)
    EXECUTION_RESOLVER=$(locate CapabilityLeaseExecutionTokenResolver.java)
    TOKEN_BINDING=$(locate CapabilityLeaseTokenBindingV1.java)
    TOKEN_REGISTRY=$(locate CapabilityLeaseTokenRegistry.java)
    TOKEN_REGISTRY_CODEC=$(locate CapabilityLeaseTokenRegistryRecordCodec.java)
    TOKEN_REGISTRY_FILE_STORE=$(locate CapabilityLeaseTokenRegistryFileStore.java)
    RUNTIME_FACTORY=$(locate CapabilityLeaseRuntimeFactory.java)
    STORE=$(locate CapabilityLeasePendingStore.java)
    FILE_STORE=$(locate CapabilityLeasePendingFileStore.java)
    CODEC=$(locate CapabilityLeasePendingRecordCodec.java)
    POLICY=$(locate CapabilityLeaseBrokerCallerPolicy.java)
    VERIFIER=$(locate CapabilityLeaseBinderCallerVerifier.java)
    CALL_EXECUTOR=$(locate CapabilityLeaseBrokerCallExecutor.java)
    FACADES=$(locate CapabilityLeaseBrokerServiceFacades.java)
    SERVICE=$(locate CapabilityLeaseBrokerService.java)
    PRODUCT_ENROLLMENT=$(locate CapabilityLeaseBrokerProductEnrollment.java)
    UI_BINDER=$(locate CapabilityLeaseUiBrokerBinder.java)
    UI_PROTOCOL=$(locate CapabilityLeaseUiProtocol.java)
    UI_AIDL=$(locate ICapabilityLeaseUiBroker.aidl)
    CONTEXT_CONSTANTS=$(locate TrillionniumContextConstants.java)
    CURRENT_FEATURE_XML=$(locate org.trillionnium.agent.system_api.xml)
    CONFIG=$(locate config.xml)
    MANIFEST=$(locate AndroidManifest.xml)
    BUILD=$(locate Android.bp)
    SYSTEM_API_SERVICE=$(locate AgentSystemApiService.java)
    OS_FAULT_TEST=$(locate CapabilityLeaseOsFileStoreFaultMatrixTest.java)
    CALL_EXECUTOR_TEST=$(locate CapabilityLeaseBrokerCallExecutorTest.java)
    PENDING_BROKER_TEST=$(locate CapabilityLeasePendingBrokerTest.java)
    OS_FAULT_MANIFEST=$(locate CapabilityLeaseOsFileStoreFaultMatrixAndroidManifest.xml)
fi

for input in "$ROOT_REGISTRATION_CONTRACT" "$ROOT_PUBLICATION_CONTRACT" \
        "$ROOT_PUBLISHER_LAUNCH_CONTRACT" \
        "$ROOT_AUTHENTICATOR_CONTRACT" \
        "$ROOT_PROOF_CARRIER_CONTRACT" \
        "$ROOT_KERNEL_CUSTODY_CONTRACT" \
        "$ROOT_SOCKET_RESULT_CUSTODY_CONTRACT" \
        "$ROOT_LISTENER_CORRELATION_CONTRACT" \
        "$ROOT_ROUTE_COORDINATOR_CONTRACT" \
        "$ROOT_ROUTE_TRANSPORT_CONTRACT" \
        "$ROOT_ROUTE_SOCKET_CUSTODY_CONTRACT" \
        "$ROOT_ROUTE_SESSION_CONTRACT" \
        "$ROOT_PUBLICATION_BINDING" "$ROOT_PUBLICATION_PROTOCOL" \
        "$ROOT_PUBLICATION_INGRESS" "$ROOT_PUBLICATION_LISTENER" \
        "$ROOT_PUBLICATION_SOCKET_CONSTRUCTOR" \
        "$ROOT_AUTHENTICATOR" \
        "$ROOT_PROOF_CARRIER" \
        "$ROOT_PROOF_SOCKET_LISTENER" \
        "$ROOT_PROOF_PUBLICATION_CORRELATION" \
        "$ROOT_LISTENER_COORDINATOR" \
        "$ROOT_BOUND_LISTENERS" \
        "$ROOT_ROUTE_TRANSPORT" "$ROOT_ROUTE_ADAPTER" \
        "$ROOT_ROUTE_SOCKET_CONNECTOR" \
        "$ROOT_ROUTE_SESSION_CONSTRUCTOR" \
        "$BROKER" "$CHALLENGE_ENCODER" \
        "$RECEIPT_VERIFIER" "$KEYMINT_VERIFIER" \
        "$LEASE_JSON" "$ECDSA" "$COMPACTION_CODEC" "$RETIREMENT_CODEC" \
        "$BACKEND_ACK_PUBLISHER" "$BACKEND_LEDGER" \
        "$BACKEND_CODEC" "$BACKEND_FILE_STORE" "$SYSTEM_API_COORDINATOR" \
        "$TASK_RESOLVER" "$EXECUTION_RESOLVER" "$TOKEN_BINDING" \
        "$TOKEN_REGISTRY" "$TOKEN_REGISTRY_CODEC" "$TOKEN_REGISTRY_FILE_STORE" \
        "$RUNTIME_FACTORY" \
        "$STORE" "$FILE_STORE" "$CODEC" "$POLICY" "$VERIFIER" "$CALL_EXECUTOR" \
        "$FACADES" "$SERVICE" "$PRODUCT_ENROLLMENT" "$UI_BINDER" "$UI_PROTOCOL" "$UI_AIDL" \
        "$CONTEXT_CONSTANTS" "$CURRENT_FEATURE_XML" \
        "$CONFIG" "$MANIFEST" "$BUILD" "$SYSTEM_API_SERVICE" \
        "$OS_FAULT_TEST" "$CALL_EXECUTOR_TEST" "$PENDING_BROKER_TEST" \
        "$OS_FAULT_MANIFEST"; do
    [[ -f "$input" ]] || { echo "missing broker source contract input: $input" >&2; exit 1; }
done

if [[ -d "$SRC" ]]; then
    SOURCE_FILES=("$SRC"/*.java)
else
    mapfile -t SOURCE_FILES < <(find "$(dirname "$BROKER")" -maxdepth 1 -type f \
        -name '*.java' -print)
fi
[[ ${#SOURCE_FILES[@]} -gt 0 ]] || {
    echo "missing production Java inputs for broker source contract" >&2
    exit 1
}

require() {
    local marker=$1
    shift
    rg -q -- "$marker" "$@" || { echo "missing broker marker: $marker" >&2; exit 1; }
}

for marker in \
        'implements CapabilityLeasePendingBroker\.ReceiptValidator' \
        'CapabilityLeaseJson\.parseObject' \
        'CapabilityLeaseEcdsaP256\.isLowS' \
        'canonicalReceipt\(receipt, true\)' \
        'mAttestationVerifier\.verify' \
        'allowedLeafSpkiSha256' \
        'allowedRootSpkiSha256' \
        'issuerPackageSignerSha256' \
        'AgentDescriptor active = request\.creatorPeerIdentity' \
        'active != AgentDescriptor\.CODEX' \
        'active\.identityKeySha256\(\)\.equals' \
        '"agent_identity_key_sha256"' \
        '"agent_executable_sha256"' \
        'capability_lease_trust_disabled'; do
    require "$marker" "$RECEIPT_VERIFIER"
done
for marker in \
        'perUidOutstandingLimitRejectsBeforeUnboundedQueueing' \
        'timedOutRunningCallRetainsUidOccupancyUntilWorkActuallyStops' \
        'uncertainTimeoutCancelsAdmittedQueueAndPermanentlyPoisonsTransport' \
        'fixedWindowRateLimitFailsClosedAndResetsOnlyAfterWindow'; do
    require "$marker" "$CALL_EXECUTOR_TEST"
done
for marker in \
        'startedSubmitTimeoutLateCommitRestartAndOuterAckGateBackend' \
        'ERROR_INDETERMINATE' \
        'State\.INDETERMINATE' \
        'querySubmissionFromIssuer' \
        'authorizeUiAcknowledgeSubmission' \
        'fetchReceiptForBackend' \
        'acknowledgeBackendPrepared'; do
    require "$marker" "$PENDING_BROKER_TEST"
done

for marker in \
        '1\.3\.6\.1\.4\.1\.11129\.2\.1\.17' \
        'verifyChain' 'requireP256' 'parseExtension' \
        'TAG_ATTESTATION_APPLICATION_ID = 709' \
        'TAG_ROOT_OF_TRUST = 704' \
        'KM_ALGORITHM_EC = 3' 'KM_DIGEST_SHA256 = 4' \
        'KM_EC_CURVE_P256 = 1' 'KM_ORIGIN_GENERATED = 0' \
        'allowedRootSpkiSha256'; do
    require "$marker" "$KEYMINT_VERIFIER"
done
require 'Set<String> names' "$LEASE_JSON"
require 'HALF_ORDER' "$ECDSA"

deny() {
    local marker=$1
    shift
    if rg -n -- "$marker" "$@"; then
        echo "forbidden live broker surface: $marker" >&2
        exit 1
    fi
}

for marker in \
        'implements CapabilityLeasePendingBroker\.ChallengeEncoder' \
        'AgentDescriptorRegistry\.fromProviderId' \
        'resolveExact\(request\)' \
        'resolveAiShellForSystemUser' \
        'identityKeySha256\.equals\(binding\.executableSha256\)' \
        'descriptor\.identityKeySha256\(\)\.equals\(binding\.identityKeySha256\)' \
        'workflowId\.matches\("req-\[0-9a-f\]\{32\}"\)' \
        'CHALLENGE_ID_PREFIX \+ sha256\(bindingMaterial\(fields\)\)' \
        'LEASE_ID_DOMAIN' \
        'canonicalObject\(fields\)' \
        'mNonceSource\.nextBytes\(32\)' \
        'UI_PACKAGE = "org\.trillionnium\.aishell"'; do
    require "$marker" "$CHALLENGE_ENCODER"
done
deny 'Binder|IBinder|ServiceManager|publishBinderService|startActivity|startService|sendBroadcast' \
    "$CHALLENGE_ENCODER"

for marker in \
        'mStore\.create\(stored\)' \
        'requireRuntimeIndexAvailable\(runtime\)' \
        'mRetiredHandles\.containsKey\(handle\)' \
        'createOrReplayOpenUri' \
        'mPrepareRequests' \
        'mAuthenticatedTaskBindings' \
        'creatorPeerIdentity' \
        'prepareRequestId' \
        'authenticatedTaskBindingSha256' \
        'prepareCanonicalRequestSha256' \
        'MessageDigest\.isEqual' \
        'mCurrentBootIdSha256 = requireNonzeroDigest' \
        'this\.bootIdSha256 = requireNonzeroDigest' \
        'capability_lease_broker_prepare_binding_conflict' \
        'mStore\.replace\(record\.stored, replacement\)' \
        'State\.DELIVERY_READY' \
        'State\.INDETERMINATE' \
        'querySubmissionFromIssuer' \
        'acknowledgeSubmissionDelivery' \
        'deriveSubmissionOperationIdFromReceiptSha256' \
        'STATUS_INDETERMINATE' \
        'fetchReceiptForBackend' \
        'acknowledgeBackendPrepared' \
        'receiptSha256\.equals' \
        '!stored\.bootIdSha256\.equals\(mCurrentBootIdSha256\)' \
        'loadRetirementTombstones' \
        'restoreRetirementChain' \
        'mRetiredPrepareRequests' \
        'mRetiredTaskBindings' \
        'requireExactRetiredBinding' \
        'retireOneTerminalForCapacity' \
        'mStore\.compactTerminal\(candidate\.stored, replacement\)' \
        'CompactionCommittedException' \
        'RETIREMENT_ACTIVATION_HOLD' \
        'source_only_pending_retirement_capacity_hold_no_authenticated_rollup_v1' \
        'capability_lease_broker_capacity_denied' \
        'MAX_PENDING = 128' \
        'MAX_RETIRED_TOMBSTONES = 8192' \
        'MAX_TTL_MS = 30_000L'; do
    require "$marker" "$BROKER"
done
for marker in 'ReplacementCommittedException' 'CreateCommittedException' \
        'committedIndexFailure' 'mPoisoned = true'; do
    require "$marker" "$BROKER"
done
deny 'compactTerminalRecords|forgetRuntime|mCompactionWatermark\.next' "$BROKER"

for marker in 'TRCLCW01' 'MessageDigest\.isEqual' 'trailing compaction bytes'; do
    require "$marker" "$COMPACTION_CODEC"
done

for marker in \
        'TRCLPT01' 'MessageDigest\.isEqual' 'CodingErrorAction\.REPORT' \
        'stateTag' 'stateFromTag' 'trailing pending retirement bytes' \
        'MAX_TOMBSTONE_BYTES = 16 \* 1024'; do
    require "$marker" "$RETIREMENT_CODEC"
done

for marker in \
        'TRCLPN02' \
        'record\.creatorPeerIdentity\.replayNamespace' \
        'record\.prepareRequestId' \
        'record\.authenticatedTaskBindingSha256' \
        'record\.prepareCanonicalRequestSha256' \
        'descriptorFromReplayNamespace' \
        'MessageDigest\.isEqual' \
        'CodingErrorAction\.REPORT' \
        'stateTag' 'stateFromTag' \
        'trailing pending record bytes' \
        'MAX_RECORD_BYTES = 384 \* 1024'; do
    require "$marker" "$CODEC"
done
deny 'TRCLPN01' "$CODEC"

for marker in \
        'final AgentDescriptor creatorPeerIdentity' \
        'final String prepareRequestId' \
        'final String authenticatedTaskBindingSha256' \
        'final String prepareCanonicalRequestSha256' \
        'this\.bootIdSha256 = requireNonzeroDigest' \
        'creatorPeerIdentity != expected\.creatorPeerIdentity' \
        'constantTimeEquals\(authenticatedTaskBindingSha256' \
        'constantTimeEquals\(prepareCanonicalRequestSha256' \
        'sha256ExactReceipt\(exactReceipt\)' \
        'requireValidReceiptTransitionFrom' \
        'constantTimeTextEquals\(exactReceipt, expected\.exactReceipt\)' \
        'pending receipt binding drift' \
        'final class RetirementTombstone' \
        'loadRetirementTombstones' \
        'every permanent replay tombstone' \
        'requireMatchesRecord' \
        'requireValidSuccessor'; do
    require "$marker" "$STORE"
done

for marker in \
        'O_NOFOLLOW' 'O_EXCL' 'O_CLOEXEC' \
        'DIRECTORY_MODE = 0700' 'FILE_MODE = 0600' \
        'Process\.SYSTEM_UID' 'st_nlink == 1' \
        'SELinux\.getFileContext' 'SELinux\.restorecon' \
        'Os\.fsync' 'Os\.rename' \
        'created && !complete && !unlinkIfSafeTemporary' \
        'trillionnium_capability_lease_data_file'; do
    require "$marker" "$FILE_STORE"
done
for marker in \
        'FAULT_BEFORE_WRITE' 'FAULT_AFTER_WRITE' \
        'FAULT_BEFORE_FILE_FSYNC' 'FAULT_AFTER_FILE_FSYNC' \
        'FAULT_BEFORE_RENAME' 'FAULT_AFTER_RENAME' \
        'FAULT_BEFORE_UNLINK' 'FAULT_AFTER_UNLINK' \
        'FAULT_BEFORE_DIRECTORY_FSYNC' 'FAULT_AFTER_DIRECTORY_FSYNC' \
        'NO_FAULTS, PRODUCTION_SECURITY, true' \
        'Process\.myUid\(\) == Process\.SYSTEM_UID' \
        'fileSecurity\.ownerUid\(\) != Process\.myUid\(\)' \
        'fileSecurity\.ownerGid\(\) != Os\.getgid\(\)' \
        'requireExactTestParent' \
        'SELinux\.getFileContext\(parent\.getPath\(\)\)'; do
    require "$marker" "$FILE_STORE"
done
[[ $(grep -Ec '^    (private )?CapabilityLeasePendingFileStore\(' "$FILE_STORE") -eq 3 ]] || {
    echo "pending store gained a mixed production/test constructor" >&2
    exit 1
}
for marker in \
        'terminal-compaction\.watermark' \
        'FAULT_AFTER_WATERMARK_COMMIT' \
        'FAULT_AFTER_TERMINAL_UNLINK' \
        'FAULT_AFTER_REPLACEMENT_COMMIT' \
        'FAULT_AFTER_CREATE_COMMIT' \
        'CompactionCommittedException' \
        'ReplacementCommittedException' \
        'CreateCommittedException' \
        'mPoisoned = true' \
        'replacement\.requireValidSuccessor' \
        'CapabilityLeaseCompactionWatermarkCodec\.encode' \
        'CapabilityLeaseCompactionWatermarkCodec\.decode' \
        'CapabilityLeasePendingRetirementCodec\.encode' \
        'CapabilityLeasePendingRetirementCodec\.decode' \
        'recoverRetirementState' \
        'tombstone\.fileName\(\) \+ "\.new"' \
        'unlink\(recordPath\)' \
        'fsyncDirectory\(mDirectory, true\)'; do
    require "$marker" "$FILE_STORE"
done
require 'replacement\.requireValidTransitionFrom\(expected\)' "$FILE_STORE"
deny 'Files\.(move|delete)|REPLACE_EXISTING|TRUNCATE_EXISTING|FileOutputStream' "$FILE_STORE"
tombstone_publish_line=$(grep -n 'Os.rename(tombstoneTemporary.getPath(), tombstonePath.getPath())' \
        "$FILE_STORE" | cut -d: -f1)
watermark_publish_line=$(grep -n 'Os.rename(watermarkTemporary.getPath(), watermarkPath.getPath())' \
        "$FILE_STORE" | cut -d: -f1)
terminal_unlink_line=$(grep -n 'unlink(recordPath)' "$FILE_STORE" | head -n1 | cut -d: -f1)
[[ -n "$tombstone_publish_line" && -n "$watermark_publish_line" \
        && -n "$terminal_unlink_line" \
        && "$tombstone_publish_line" -lt "$watermark_publish_line" \
        && "$watermark_publish_line" -lt "$terminal_unlink_line" ]] || {
    echo "pending retirement must publish tombstone, then watermark, then unlink" >&2
    exit 1
}

for marker in \
        'Binder\.getCallingUid' 'Binder\.getCallingPid' \
        'Binder\.clearCallingIdentity' 'Binder\.restoreCallingIdentity' \
        'getPackagesForUid' 'packages\.length != 1' 'getPackageUidAsUser' \
        'GET_SIGNING_CERTIFICATES' 'getApkContentsSigners' \
        'signers\.length != 1' 'SELinux\.getPidContext' \
        'UserHandle\.getUserId' 'Process\.isApplicationUid'; do
    require "$marker" "$VERIFIER"
done

for marker in \
        'enum State \{ PREPARED, CONSUMED \}' \
        'mStore\.createPrepared\(prepared\)' \
        'acknowledger\.acknowledgePrepared' \
        'reconcilePrepared' \
        'record\.handle' \
        'receiptSha256' \
        'MessageDigest\.isEqual' \
        'delivery\.exactReceipt' \
        'final class ExecutorBinding' \
        'executorCanonicalRequestSha256' \
        'terminalResponseSha256' \
        'replayBeforeFetch' \
        'activateVerifiedPublisherEpoch' \
        'inspectForVerifiedPublisher' \
        'acknowledgeVerifiedBackendAck' \
        'CapabilityLeaseBackendAckPublisher\.VerifiedReplaySyncPeer' \
        'CapabilityLeaseBackendAckPublisher\.VerifiedPublisherEpoch' \
        'CapabilityLeaseBackendAckPublisher\.VerifiedBackendAck' \
        'static final class AckInspection' \
        'static final class AckRecord' \
        'requireExactVerifiedCapabilitySnapshot' \
        'trillionnium\.capability-lease-backend-ack-chain-step\.v1' \
        'hashStringField\(digest, "executor_peer"' \
        'hashStringField\(digest, "boot_id_sha256"' \
        'rootJournalGenesisSha256' 'epochProofSha256' \
        'watermarkMapKey' 'mExecutorSequences' \
        'executorSequenceReplayKey' \
        'WATERMARK_ACTIVATION_HOLD' \
        'source_only_backend_boot_watermark_capacity_hold_no_authenticated_rollup_v1' \
        'MAX_WATERMARKS = 128' \
        'capability_lease_backend_epoch_not_activated' \
        'mPoisoned = true' 'requireAvailable\(\)' \
        'capability_lease_backend_ack_blocked_prepared' \
        'validatedPrepared' \
        'catch \(RuntimeException invalid\)' \
        'effect\.execute\(\)' \
        'mStore\.replace\(prepared, consumed\)' \
        'capability_lease_backend_outcome_indeterminate' \
        'capability_lease_backend_binding_conflict'; do
    require "$marker" "$BACKEND_LEDGER"
done
deny 'AgentSystemApiReplayAckChain|AgentSystemApiReplayAckStore' "$BACKEND_LEDGER"
for marker in \
        'source_only_backend_ack_publisher_not_runtime_constructed_v1' \
        'interface RootJournalAuthenticator' \
        'private VerifiedReplaySyncPeer\(' \
        'private VerifiedPublisherEpoch\(' \
        'private VerifiedBackendAck\(' \
        'private VerifiedTaskRegistration\(' \
        'private VerifiedExecutionRegistration\(' \
        'authenticateReplaySyncPeer' \
        'authenticatePublisherEpoch' \
        'authenticateRegistrationRecord' \
        'authenticateContiguousRootAck' \
        'RegistrationRecordProof' 'RegistrationEvidence' \
        'deriveTaskRegistrationBinding' \
        'deriveExecutionRegistrationBinding' \
        'requireExactCapabilitySubset' \
        'actual\.sequence != claimed\.sequence' \
        'actual\.requestId\.equals\(claimed\.requestId\)' \
        'actual\.canonicalRequestSha256' \
        'actual\.terminalResponseSha256' \
        'mCapabilityRecords' \
        'rootAckChainSha256' 'rootProofSha256' \
        'ledger\.inspectForVerifiedPublisher' \
        'ledger\.acknowledgeVerifiedBackendAck'; do
    require "$marker" "$BACKEND_ACK_PUBLISHER"
done
[[ $(grep -Ec '^        private Verified(ReplaySyncPeer|PublisherEpoch|BackendAck)\(' \
        "$BACKEND_ACK_PUBLISHER") -eq 3 ]] || {
    echo "verified replay-sync authority constructors must remain private" >&2
    exit 1
}
deny 'activateEpochFromTrustedExecutor|acknowledgeConsumedThroughFromTrustedExecutor|acknowledgedThroughFrom' \
    "$BACKEND_LEDGER" "$BACKEND_ACK_PUBLISHER"
deny 'CapabilityLeaseBackendAckPublisher|CapabilityLeaseTokenRegistry' \
    "$RUNTIME_FACTORY" "$SYSTEM_API_SERVICE" "$SYSTEM_API_COORDINATOR"
deny 'CapabilityLeaseRootPublication(Ingress|Protocol|Binding|SocketListener|SocketConstructor)V1|CapabilityLeaseMeasuredRootJournalAuthenticatorV1|CapabilityLeaseRootProof(Carrier|SocketListener|PublicationCorrelation)V1|CapabilityLeaseRoot(ListenerCoordinator|BoundListeners|RouteTransport|CoordinatorRouteAdapter|RouteSocketConnector)V1' \
    "$RUNTIME_FACTORY" "$SYSTEM_API_SERVICE" "$SYSTEM_API_COORDINATOR" "$MANIFEST"

for marker in \
        'source_only_no_listener_no_runtime_no_effect_authority_v1' \
        'trillionnium.capability-lease-root-publication.uds.v1' \
        'u:r:trillionnium_agent_system_api_replay_sync:s0' \
        'system_ext/bin/trillionnium-system-api-replay-sync' \
        'LISTENER_AVAILABLE = false' 'RUNTIME_CONSUMER_AVAILABLE = false' \
        'CONFERS_EFFECT_AUTHORITY = false' 'derivePublicationBinding' \
        'deriveAckBinding'; do
    require "$marker" "$ROOT_PUBLICATION_BINDING"
done
for marker in 'org.trillionnium.capabilitylease.root-authenticator.contract.v1' \
        'source_only_no_live_authority_no_product_constructor_v1' \
        'positive_clone3_child_pid' 'ptrace_event_exec_before_resume' \
        '"linux_kernel_backend_available": false' \
        '"broker_route_available": false' \
        '"product_constructor_available": false' \
        '"listener_wired": false' '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_AUTHENTICATOR_CONTRACT"
done
for marker in 'source_only_immutable_snapshot_no_product_constructor_no_effect_authority_v1' \
        'implements' 'RootJournalAuthenticator' 'MeasuredPeerAuthenticationSource' \
        'BrokerCustodySnapshot' 'publisher_start_time_ticks' \
        'publisherEpoch\.matches\("0\{32\}"\)' \
        'fromProofDelivery' \
        'authenticateReplaySyncPeer' 'authenticatePublisherEpoch' \
        'authenticateRegistrationRecord' \
        'authenticateContiguousRootAck' 'return false'; do
    require "$marker" "$ROOT_AUTHENTICATOR"
done
deny 'LocalServerSocket|ServiceManager|Binder|startActivity|sendBroadcast' "$ROOT_AUTHENTICATOR"
for marker in 'org.trillionnium.capabilitylease.root-proof-carrier.contract.v1' \
        'source_only_no_bound_socket_no_runtime_consumer_no_effect_authority_v1' \
        'SO_PEERCRED_pid_uid_gid_plus_SO_PEERSEC_before_and_after_frame' \
        '"broker_publisher_wired": false' '"listener_wired": false' \
        '"confers_ack_authority": false' '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_PROOF_CARRIER_CONTRACT"
done
for marker in 'source_only_no_bound_socket_no_runtime_consumer_no_effect_authority_v1' \
        'trillionnium_capability_lease_root_proof' \
        'KernelPeerSnapshot first = connection\.kernelPeer' \
        'KernelPeerSnapshot second = connection\.kernelPeer' \
        'readSingleFrame' 'epoch\(authentication, "publisher_epoch"\)' \
        '\|\| item\.matches\("0\{32\}"\)' 'deriveDeliveryBinding'; do
    require "$marker" "$ROOT_PROOF_CARRIER"
done
deny 'LocalServerSocket|ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_PROOF_CARRIER"
for marker in 'org.trillionnium.capabilitylease.root-kernel-custody.contract.v1' \
        'source_only_concrete_linux_backend_no_broker_route_no_product_constructor_v1' \
        'clone3_CLONE_PIDFD_SIGCHLD' \
        'single_authenticated_root_proof_delivery_before_resume' \
        '"broker_route_available": false' \
        '"product_constructor_available": false' \
        '"live_proof_socket_available": false' \
        '"confers_ack_authority": false' \
        '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_KERNEL_CUSTODY_CONTRACT"
done
for marker in 'org.trillionnium.capabilitylease.root-socket-result-custody.contract.v1' \
        'source_only_concrete_socket_and_result_custody_no_broker_route_no_product_constructor_v1' \
        'abstract_trillionnium_capability_lease_root_proof' \
        'SO_PEERCRED_and_SO_PEERSEC_before_and_after_exact_frame' \
        'one_canonical_root_publication_ack_matching_every_exact_publication_commitment' \
        'pidfd_observed_normal_exit_zero_then_exact_waitpid_reap' \
        '"broker_route_available": false' \
        '"product_constructor_available": false' \
        '"proof_socket_listener_wired": false' \
        '"token_mutation_available": false' \
        '"confers_ack_authority": false' \
        '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_SOCKET_RESULT_CUSTODY_CONTRACT"
done
for marker in 'source_only_fixed_abstract_listener_no_runtime_factory_no_service_route_v1' \
        '534563d64718520417eb22f22c17a45961e6706c8d498f6720c7e30bd444fcec' \
        'new LocalServerSocket\(CapabilityLeaseRootProofCarrierV1\.SOCKET_NAME\)' \
        'CapabilityLeaseRootProofCarrierV1\.AcceptedConnection acceptOnce' \
        'SELinux\.getPeerContext' 'mAccepted'; do
    require "$marker" "$ROOT_PROOF_SOCKET_LISTENER"
done
deny 'ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_PROOF_SOCKET_LISTENER"
for marker in 'org.trillionnium.capabilitylease.root-listener-correlation.contract.v1' \
        'source_only_single_proof_single_publication_no_broker_route_no_product_constructor_v1' \
        'abstract_trillionnium_capability_lease_root_publication' \
        'single_in_memory_non_persistent_non_replaceable_slot' \
        'same_object_is_listener_peer_authenticator_and_backend_root_journal_authenticator' \
        'terminal_no_retry_no_second_proof_no_second_publication' \
        '"broker_route_available": false' \
        '"product_constructor_available": false' \
        '"publication_socket_listener_wired": false' \
        '"token_mutation_available": false' \
        '"confers_ack_authority": false' \
        '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_LISTENER_CORRELATION_CONTRACT"
done
[[ $(sha256sum "$ROOT_LISTENER_CORRELATION_CONTRACT" | awk '{print $1}') == \
   'd63e931b87db5ff0927620659e9fd4d48e725e6ec8e6a23fd2d6dc773092c65b' ]] || {
    echo "root listener/correlation contract digest drifted" >&2
    exit 1
}
for marker in 'source_only_fixed_abstract_listener_no_runtime_factory_no_service_route_v1' \
        'd63e931b87db5ff0927620659e9fd4d48e725e6ec8e6a23fd2d6dc773092c65b' \
        'new LocalServerSocket\(CapabilityLeaseRootPublicationSocketListenerV1\.SOCKET_NAME\)' \
        'CapabilityLeaseRootPublicationSocketListenerV1\.AcceptedConnection acceptOnce' \
        'SELinux\.getPeerContext' \
        'readStartTimeTicks' \
        'mAccepted'; do
    require "$marker" "$ROOT_PUBLICATION_SOCKET_CONSTRUCTOR"
done
deny 'ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_PUBLICATION_SOCKET_CONSTRUCTOR"
for marker in 'source_only_single_in_memory_proof_single_publication_terminal_typestate_v1' \
        'd63e931b87db5ff0927620659e9fd4d48e725e6ec8e6a23fd2d6dc773092c65b' \
        'implements' 'CorrelatedRootAuthenticationSource' \
        'PENDING_PROOF' 'PUBLICATION_MATCHED' 'PEER_AUTHENTICATED' \
        'EPOCH_AUTHENTICATED' 'TERMINAL' \
        'fromReceivedProof' 'fromProofDelivery' \
        'synchronized String authenticate' \
        'synchronized boolean authenticateReplaySyncPeer' \
        'synchronized boolean authenticatePublisherEpoch' \
        'synchronized boolean authenticateRegistrationRecord' \
        'authenticateContiguousRootAck' 'terminate\(\)'; do
    require "$marker" "$ROOT_PROOF_PUBLICATION_CORRELATION"
done
deny 'LocalServerSocket|ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_PROOF_PUBLICATION_CORRELATION"
for marker in 'org.trillionnium.capabilitylease.root-route-coordinator.contract.v1' \
        'source_only_single_internal_broker_route_dual_listener_terminal_coordinator_v1' \
        'publication_socket_then_proof_socket_before_route_start' \
        'one_proof_then_close_proof_connection_then_one_publication' \
        'same_single_use_object_for_publication_peer_and_backend_root_journal_authentication' \
        '"public_broker_protocol_extended": false' \
        '"broker_main_route_wired": false' \
        '"listener_coordinator_wired": false' \
        '"token_mutation_available": false' \
        '"confers_ack_authority": false' \
        '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_ROUTE_COORDINATOR_CONTRACT"
done
[[ $(sha256sum "$ROOT_ROUTE_COORDINATOR_CONTRACT" | awk '{print $1}') == \
   '260b90d2677b742843abcecd7bf1ed1f5ad949629175bb07318d96eef8f805c4' ]] || {
    echo "root route/coordinator contract digest drifted" >&2
    exit 1
}
for marker in 'source_only_dual_listener_single_internal_route_terminal_coordinator_v1' \
        '260b90d2677b742843abcecd7bf1ed1f5ad949629175bb07318d96eef8f805c4' \
        'implements AutoCloseable' \
        'RouteCompletion routeCompletion = mRoute.startOnce' \
        'proofListener.acceptOnce' 'publicationListener.acceptOnce' \
        'fromReceivedProof' 'mHandlerFactory.create\(correlation\)' \
        'awaitExactCompletion' 'requireExact' 'terminate\(correlation\)' \
        'publicationListener.close' 'proofListener.close' 'route.close'; do
    require "$marker" "$ROOT_LISTENER_COORDINATOR"
done
deny 'LocalServerSocket|ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_LISTENER_COORDINATOR"
for marker in 'source_only_publication_then_proof_bind_no_runtime_factory_no_service_route_v1' \
        'CapabilityLeaseRootPublicationSocketConstructorV1.bindSourceDisabled' \
        'CapabilityLeaseRootProofSocketListenerV1.bindSourceDisabled' \
        'new CapabilityLeaseRootListenerCoordinatorV1'; do
    require "$marker" "$ROOT_BOUND_LISTENERS"
done
deny 'ServiceManager|android\.os\.Binder|IBinder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_BOUND_LISTENERS"
for marker in 'org.trillionnium.capabilitylease.root-route-transport.contract.v1' \
        'source_only_commitment_only_private_route_transport_no_listener_no_product_adapter_v1' \
        'exact_agent_boot_and_registration_commitment_only' \
        'raw_publication_raw_token_task_payload_root_record_or_effect_material' \
        '"public_broker_protocol_extended": false' \
        '"private_listener_available": false' \
        '"private_connector_available": false' \
        '"broker_main_route_wired": false' \
        '"coordinator_route_adapter_wired": false' \
        '"confers_ack_authority": false' \
        '"confers_lease_trust": false' \
        '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_ROUTE_TRANSPORT_CONTRACT"
done
[[ $(sha256sum "$ROOT_ROUTE_TRANSPORT_CONTRACT" | awk '{print $1}') == \
   '176fc01d3a666fe98e2d9209a411a10fae030b69c480c7ef520dc7ca233a68ac' ]] || {
    echo "root route transport contract digest drifted" >&2
    exit 1
}
for marker in 'source_only_commitment_only_private_route_codec_no_socket_no_runtime_v1' \
        '176fc01d3a666fe98e2d9209a411a10fae030b69c480c7ef520dc7ca233a68ac' \
        'PUBLIC_BROKER_PROTOCOL_EXTENDED = false' \
        'PRIVATE_LISTENER_AVAILABLE = false' 'PRIVATE_CONNECTOR_AVAILABLE = false' \
        'exchangeConnectedOnce' 'KernelPeerSnapshot first' 'KernelPeerSnapshot second' \
        'shutdownWrite' 'PendingConnectedExchange' 'System.nanoTime' \
        'remainingTimeoutMillis' 'readExactFrameAndEof' 'decodeResponse'; do
    require "$marker" "$ROOT_ROUTE_TRANSPORT"
done
deny 'LocalSocket|LocalServerSocket|ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_ROUTE_TRANSPORT"
for marker in 'source_only_private_route_adapter_no_connector_no_runtime_factory_v1' \
        'implements CapabilityLeaseRootListenerCoordinatorV1.RootPublisherRoute' \
        'AsyncExchangeStarter' 'PendingExchange' 'awaitExactResponse' \
        'new CapabilityLeaseRootListenerCoordinatorV1.RouteResult' \
        'public synchronized void close' \
        'COORDINATOR_ROUTE_ADAPTER_WIRED = false' \
        'RUNTIME_FACTORY_AVAILABLE = false'; do
    require "$marker" "$ROOT_ROUTE_ADAPTER"
done
deny 'LocalSocket|LocalServerSocket|ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_ROUTE_ADAPTER"
for marker in 'org.trillionnium.capabilitylease.root-route-socket-custody.contract.v1' \
        'source_only_concrete_private_route_listener_connector_no_product_wiring_v1' \
        'one_monotonic_5000ms_deadline_then_accept_one_cloexec_stream' \
        'close_listener_immediately_after_accept_or_any_failure_never_rebind' \
        'create_nonblocking_cloexec_then_one_connect_to_exact_abstract_name_with_monotonic_5000ms_deadline' \
        '"source_listener_implemented": true' \
        '"source_connector_implemented": true' \
        '"listener_product_wired": false' \
        '"connector_product_wired": false' \
        '"broker_main_route_wired": false' \
        '"coordinator_route_adapter_wired": false' \
        '"confers_ack_authority": false' \
        '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_ROUTE_SOCKET_CUSTODY_CONTRACT"
done
[[ $(sha256sum "$ROOT_ROUTE_SOCKET_CUSTODY_CONTRACT" | awk '{print $1}') == \
   '1b275c7956a325f767d037ec0ce578a6dbb078ec42f71ef25a1097b8cf957930' ]] || {
    echo "root route socket custody contract digest drifted" >&2
    exit 1
}
for marker in 'source_only_concrete_private_route_connector_no_runtime_factory_no_product_wiring_v1' \
        '1b275c7956a325f767d037ec0ce578a6dbb078ec42f71ef25a1097b8cf957930' \
        'implements CapabilityLeaseRootCoordinatorRouteAdapterV1.AsyncExchangeStarter' \
        'SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK' \
        'UnixSocketAddress.createAbstract' 'SystemClock.elapsedRealtime' \
        'Os.poll' 'SO_ERROR' 'beginConnectedOnce' \
        'getPeerCredentials' 'SELinux.getPeerContext' 'shutdownOutput' \
        'timeoutMillis <= 0' 'timeoutMillis > CapabilityLeaseRootRouteTransportV1.READ_TIMEOUT_MS' \
        'CONNECTOR_PRODUCT_WIRED = false' \
        'COORDINATOR_ROUTE_ADAPTER_WIRED = false'; do
    require "$marker" "$ROOT_ROUTE_SOCKET_CONNECTOR"
done
deny 'LocalServerSocket|ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_ROUTE_SOCKET_CONNECTOR"
for marker in 'org.trillionnium.capabilitylease.root-route-session.contract.v1' \
        'source_only_private_root_route_session_constructors_no_product_wiring_v1' \
        'system_server_bind_publication_then_proof_then_agentd_bind_private_route_then_system_server_run_once' \
        'close_bound_route_listener_and_clear_session' \
        'close_publication_then_proof_listener_clear_connector_route_and_become_terminal' \
        '"source_agentd_session_constructor_implemented": true' \
        '"source_system_server_session_constructor_implemented": true' \
        '"cross_process_startup_orchestrator_available": false' \
        '"broker_main_route_wired": false' \
        '"system_server_runtime_factory_wired": false' \
        '"product_startup_wired": false' \
        '"confers_ack_authority": false' \
        '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_ROUTE_SESSION_CONTRACT"
done
[[ $(sha256sum "$ROOT_ROUTE_SESSION_CONTRACT" | awk '{print $1}') == \
   'a1352acf879e6c4e4b83956e6998ae540227446634a6f608f087f5a99ce65338' ]] || {
    echo "root route session contract digest drifted" >&2
    exit 1
}
for marker in 'source_only_private_root_route_session_constructor_no_product_wiring_v1' \
        'a1352acf879e6c4e4b83956e6998ae540227446634a6f608f087f5a99ce65338' \
        'new CapabilityLeaseRootRouteSocketConnectorV1' \
        'new CapabilityLeaseRootCoordinatorRouteAdapterV1' \
        'CapabilityLeaseRootBoundListenersV1.bindSourceDisabled' \
        'try \(CapabilityLeaseRootListenerCoordinatorV1 owned = coordinator\)' \
        'coordinator.close' \
        'CROSS_PROCESS_STARTUP_ORCHESTRATOR_AVAILABLE = false' \
        'SYSTEM_SERVER_RUNTIME_FACTORY_WIRED = false' \
        'PRODUCT_STARTUP_WIRED = false'; do
    require "$marker" "$ROOT_ROUTE_SESSION_CONSTRUCTOR"
done
deny 'LocalSocket|LocalServerSocket|ServiceManager|Binder|startActivity|sendBroadcast|CapabilityLeaseTokenRegistry' \
    "$ROOT_ROUTE_SESSION_CONSTRUCTOR"
deny 'CapabilityLeaseRootRouteSessionConstructorV1' \
    "$RUNTIME_FACTORY" "$SYSTEM_API_SERVICE" "$MANIFEST"
for marker in 'decodePublication' 'encodeAck' 'requireExactFields' \
        'frame.length != Integer.BYTES \+ length' \
        'contains_commitments_only_never_raw_token'; do
    if [[ "$marker" == 'contains_commitments_only_never_raw_token' ]]; then
        require "$marker" "$ROOT_PUBLICATION_CONTRACT"
    else
        require "$marker" "$ROOT_PUBLICATION_PROTOCOL"
    fi
done
require 'source_only_injected_root_publication_ingress_no_listener_v1' \
    "$ROOT_PUBLICATION_INGRESS"
require 'ReplaySyncTransportPeerEvidence transportPeer' "$BACKEND_ACK_PUBLISHER"
for marker in 'source_only_listener_seam_not_product_constructed_v1' \
        'trillionnium_capability_lease_root_publication' \
        'CapabilityLeaseRootProofPublicationCorrelationV1' \
        'ingress\.usesAuthenticator\(peerAuthenticationSource\)' \
        'KernelPeerSnapshot first = connection\.kernelPeer' \
        'KernelPeerSnapshot second = connection\.kernelPeer' \
        'descriptorForKernelPeer' 'readSingleFrame' \
        'mPeerAuthenticationSource\.authenticate' 'mIngress\.handle'; do
    require "$marker" "$ROOT_PUBLICATION_LISTENER"
done
for marker in 'source_only_no_product_package_no_live_listener_no_effect_authority_v1' \
        'agentd_to_system_api_replay_sync_only' \
        'SO_PEERCRED_twice_plus_SO_PEERSEC_plus_root_authenticator' \
        'same_fd_consumed_by_execveat_at_empty_path' \
        '"product_package_available": false' '"launcher_wired": false' \
        '"listener_wired": false' '"confers_effect_authority": false'; do
    require "$marker" "$ROOT_PUBLISHER_LAUNCH_CONTRACT"
done

for marker in \
        'CONTRACT_SCHEMA = "org\.trillionnium\.capabilitylease\.root-registration\.contract\.v1"' \
        'TASK_REGISTRATION_SCHEMA = "org\.trillionnium\.capabilitylease\.root-task-registration\.v1"' \
        'SOURCE_STATUS = "source_only_no_transport_no_runtime_no_effect_authority_v1"' \
        'REGISTRATION_BINDING_DOMAIN' 'TASK_CONTEXT_KIND = "TASK_CONTEXT"' \
        'ADAPTER_ID = "system_api"' 'ACTION_ID = "open_uri"' \
        'SUBJECT_USER_ID = 0' 'TRANSPORT_AVAILABLE = false' \
        'RUNTIME_CONSUMER_AVAILABLE = false' 'CONFERS_EFFECT_AUTHORITY = false' \
        'registrationBindingFields' 'registrationPayloadFields'; do
    require "$marker" "$TOKEN_BINDING"
done
require 'CapabilityLeaseTokenBindingV1\.REGISTRATION_BINDING_DOMAIN' \
    "$BACKEND_ACK_PUBLISHER"
require 'CapabilityLeaseTokenBindingV1\.deriveTaskRegistrationBinding' \
    "$BACKEND_ACK_PUBLISHER"
deny 'private static final String REGISTRATION_BINDING_DOMAIN' \
    "$BACKEND_ACK_PUBLISHER"

python3 - "$ROOT_REGISTRATION_CONTRACT" "$TOKEN_BINDING" <<'PY'
import hashlib
import json
import re
import struct
import sys

contract_path, java_path = sys.argv[1:]
raw = open(contract_path, "rb").read()
contract = json.loads(raw)
java = open(java_path, encoding="utf-8").read()

def java_string(name):
    match = re.search(r"\b" + re.escape(name) + r'\s*=\s*"([^"]+)"', java)
    if not match:
        raise SystemExit("missing generated Java constant: " + name)
    return match.group(1)

def java_array(name):
    match = re.search(
        r"\b" + re.escape(name) + r"\s*=\s*\{(.*?)\};", java, re.S)
    if not match:
        raise SystemExit("missing generated Java array: " + name)
    return re.findall(r'"([^"]+)"', match.group(1))

if hashlib.sha256(raw).hexdigest() != java_string("CONTRACT_SHA256"):
    raise SystemExit("root-registration contract hash drift")
if contract["contract_schema"] != java_string("CONTRACT_SCHEMA"):
    raise SystemExit("root-registration contract schema drift")
if contract["task_registration_schema"] != java_string("TASK_REGISTRATION_SCHEMA"):
    raise SystemExit("root-registration payload schema drift")
if contract["source_status"] != java_string("SOURCE_STATUS"):
    raise SystemExit("root-registration source status drift")
if any(contract["authority"].values()):
    raise SystemExit("root-registration contract unexpectedly grants authority")
if contract["encoding"]["binding_fields"] != java_array(
        "REGISTRATION_BINDING_FIELDS"):
    raise SystemExit("root-registration binding-field order drift")
if contract["encoding"]["payload_fields"] != java_array(
        "REGISTRATION_PAYLOAD_FIELDS"):
    raise SystemExit("root-registration payload-field order drift")

fixed = contract["fixed"]
golden = contract["golden"]
opaque_sha256 = hashlib.sha256(
    golden["opaque_task_context_token"].encode("ascii")).hexdigest()
if opaque_sha256 != golden["opaque_token_sha256"]:
    raise SystemExit("root-registration opaque-token golden drift")

values = {
    "domain": fixed["registration_binding_domain"].encode(),
    "kind": fixed["kind"].encode(),
    "peer": golden["replay_namespace"].encode(),
    "boot_id_sha256": golden["boot_id_sha256"].encode(),
    "publisher_epoch": golden["publisher_epoch"].encode(),
    "root_journal_genesis_sha256": golden["root_journal_genesis_sha256"].encode(),
    "epoch_proof_sha256": golden["epoch_proof_sha256"].encode(),
    "publisher_sequence": struct.pack(">q", golden["publisher_sequence"]),
    "adapter": fixed["adapter_id"].encode(),
    "action": fixed["action_id"].encode(),
    "subject_user": struct.pack(">q", fixed["subject_user_id"]),
    "opaque_token_sha256": opaque_sha256.encode(),
    "request_id": golden["prepare_request_id"].encode(),
    "canonical_request_sha256": golden["prepare_canonical_request_sha256"].encode(),
    "workflow_id": golden["workflow_id"].encode(),
    "task_id": golden["task_id"].encode(),
    "authenticated_task_binding_sha256":
        golden["authenticated_task_binding_sha256"].encode(),
    "root_direct_binding_sha256": golden["root_direct_binding_sha256"].encode(),
}
digest = hashlib.sha256()
for name in contract["encoding"]["binding_fields"]:
    encoded_name = name.encode("ascii")
    value = values[name]
    digest.update(struct.pack(">I", len(encoded_name)))
    digest.update(encoded_name)
    digest.update(struct.pack(">I", len(value)))
    digest.update(value)
binding = digest.hexdigest()
if binding != golden["registration_binding_sha256"]:
    raise SystemExit("root-registration golden binding drift")
if binding != java_string("GOLDEN_REGISTRATION_BINDING_SHA256"):
    raise SystemExit("root-registration Java golden binding drift")
if opaque_sha256 != java_string("GOLDEN_OPAQUE_TOKEN_SHA256"):
    raise SystemExit("root-registration Java opaque-token golden drift")
PY
for marker in \
        'source_only_token_registry_activation_hold_no_authenticated_ack_compaction_v1' \
        'VerifiedTaskRegistration verified' \
        'VerifiedExecutionRegistration verified' \
        'journalRegistrationBindingSha256' \
        'rootRecordSha256' 'rootRecordProofSha256' 'journalReplayKey' \
        'consumeTaskOrReplayExact' 'consumeExecutionOrReplayExact' \
        'taskContextResolver' 'executionTokenResolver' \
        'mStore\.replace\(existing, consumed\)' \
        'if \(existing\.state == State\.CONSUMED\) return existing' \
        'rootDirectBindingSha256' 'sameTaskClosure' \
        'task\.state != State\.CONSUMED' \
        'CapabilityLeaseTokenBindingV1\.ADAPTER_ID' \
        'CapabilityLeaseTokenBindingV1\.ACTION_ID' \
        'CapabilityLeaseTokenBindingV1\.SUBJECT_USER_ID' \
        'mPoisoned = true'; do
    require "$marker" "$TOKEN_REGISTRY"
done
for marker in \
        'TRCLTK02' 'MessageDigest\.isEqual' 'CodingErrorAction\.REPORT' \
        'trailing capability token record bytes' 'MAX_RECORD_BYTES = 4 \* 1024'; do
    require "$marker" "$TOKEN_REGISTRY_CODEC"
done
deny 'TRCLTK01' "$TOKEN_REGISTRY_CODEC"
for marker in \
        'openForSystemServer' \
        'device_hold_requires_system_server_uid_and_token_selinux_label_v1' \
        'Process\.myUid\(\) != Process\.SYSTEM_UID' \
        'Os\.getgid\(\) != Process\.SYSTEM_UID' \
        'private CapabilityLeaseTokenRegistryFileStore\(' \
        'DIRECTORY_MODE = 0700' 'FILE_MODE = 0600' \
        'O_NOFOLLOW' 'O_EXCL' 'O_CLOEXEC' \
        'SELinux\.getFileContext' 'SELinux\.restorecon' \
        'Os\.fsync' 'Os\.rename' 'mPoisoned = true' \
        'interface FaultInjector' 'interface FileSecurity' \
        'NO_FAULTS, PRODUCTION_SECURITY, true' \
        'requireExactTestParent' \
        'FAULT_BEFORE_WRITE' 'FAULT_AFTER_WRITE' \
        'FAULT_BEFORE_FILE_FSYNC' 'FAULT_AFTER_FILE_FSYNC' \
        'FAULT_BEFORE_RENAME' 'FAULT_AFTER_RENAME' \
        'FAULT_BEFORE_DIRECTORY_FSYNC' 'FAULT_AFTER_DIRECTORY_FSYNC'; do
    require "$marker" "$TOKEN_REGISTRY_FILE_STORE"
done
deny 'opaqueTaskContextToken|opaqueExecutionToken' \
    "$TOKEN_REGISTRY_CODEC" "$TOKEN_REGISTRY_FILE_STORE"
for marker in \
        'tokenRegistryWriteAndFileFsyncFaultsNeverPublishPartialCreate' \
        'tokenRegistryCreateCommitUnknownPoisonsAndRestartAdoptsIssued' \
        'tokenRegistryReplaceRestartDistinguishesPreAndPostRename' \
        'tokenRegistryFailedCreateCleanupUncertaintyPoisonsUntilRestart' \
        'CapabilityLeaseTokenRegistryFileStore\.FaultInjector' \
        'CapabilityLeaseTokenRegistryFileStore\.FileSecurity'; do
    require "$marker" "$OS_FAULT_TEST"
done
require '^interface CapabilityLeaseExecutionTokenResolver' "$EXECUTION_RESOLVER"
require 'consumeOrReplayExact\(AgentDescriptor authenticatedPeer' "$EXECUTION_RESOLVER"
require 'requireExactCall' "$EXECUTION_RESOLVER"
require '^interface CapabilityLeaseTaskContextResolver' "$TASK_RESOLVER"
require 'consumeOrReplayExact\(AgentDescriptor authenticatedPeer' "$TASK_RESOLVER"
require 'requireExactCall' "$TASK_RESOLVER"
deny 'implements CapabilityLease(TaskContext|ExecutionToken)Resolver' "${SOURCE_FILES[@]}"
deny 'defaultPublisher|self.?signed|SelfSigned|class .*AckPublisher|interface .*AckPublisher' \
    "$BACKEND_LEDGER" "$SYSTEM_API_COORDINATOR"
require '!value\.equals\("0"\.repeat\(32\)\)' "$BACKEND_LEDGER"
require '\|\| !validEpoch\(epoch\)' "$BACKEND_LEDGER"
require '\|\| !validEpoch\(fields\[1\]\)' "$BACKEND_LEDGER"
[[ $(rg -l 'new CapabilityLeaseTokenRegistry\(' "${SOURCE_FILES[@]}" | wc -l) -eq 1 ]] || {
    echo "token registry gained an unguarded product constructor" >&2
    exit 1
}

for marker in \
        'TRCLBR03' 'TRCLBW02' \
        'MessageDigest\.isEqual' \
        'record\.receiptSha256' \
        'record\.executorPeerIdentity\.replayNamespace' \
        'record\.authenticatedTaskBindingSha256' \
        'record\.prepareCanonicalRequestSha256' \
        'record\.terminalResponseSha256' \
        'record\.terminalResponseForEncoding' \
        'watermark\.rootJournalGenesisSha256' \
        'watermark\.epochProofSha256' \
        'encodeWatermark' 'decodeWatermark' \
        'CodingErrorAction\.REPORT' \
        'stateTag' 'stateFromTag' \
        'trailing backend replay bytes' \
        'MAX_TERMINAL_RESPONSE_BYTES \+ 32 \* 1024'; do
    require "$marker" "$BACKEND_CODEC"
done
deny 'TRCLBW01' "$BACKEND_CODEC"

for marker in \
        'trillionnium_capability_lease_backend_replay' \
        'trillionnium_capability_lease_backend_replay_file' \
        'O_NOFOLLOW' 'O_EXCL' 'O_CLOEXEC' \
        'DIRECTORY_MODE = 0700' 'FILE_MODE = 0600' \
        'Process\.SYSTEM_UID' 'st_nlink == 1' \
        'CapabilityLeaseBackendReplayRecordCodec\.decode' \
        'CapabilityLeaseBackendReplayRecordCodec\.encode' \
        'CapabilityLeaseBackendReplayRecordCodec\.encodeWatermark' \
        'CapabilityLeaseBackendReplayRecordCodec\.decodeWatermark' \
        'Os\.fsync' 'Os\.rename' \
        'compactConsumed' 'recoverDurableCompaction' \
        'mPoisoned = true'; do
    require "$marker" "$BACKEND_FILE_STORE"
done
for marker in \
        'FAULT_BEFORE_WRITE' 'FAULT_AFTER_WRITE' \
        'FAULT_BEFORE_FILE_FSYNC' 'FAULT_AFTER_FILE_FSYNC' \
        'FAULT_BEFORE_RENAME' 'FAULT_AFTER_RENAME' \
        'FAULT_BEFORE_UNLINK' 'FAULT_AFTER_UNLINK' \
        'FAULT_BEFORE_DIRECTORY_FSYNC' 'FAULT_AFTER_DIRECTORY_FSYNC' \
        'created && !complete && !unlinkIfSafeTemporary' \
        'NO_FAULTS, PRODUCTION_SECURITY, true' \
        'Process\.myUid\(\) == Process\.SYSTEM_UID' \
        'requireExactTestParent'; do
    require "$marker" "$BACKEND_FILE_STORE"
done
deny 'Files\.(move|delete)|REPLACE_EXISTING|TRUNCATE_EXISTING|FileOutputStream' \
    "$BACKEND_FILE_STORE"

for marker in \
        'final class CapabilityLeaseSystemApiOpenUriCoordinator' \
        'handle\.equals\(delivery\.handle\)' \
        'mLedger\.replayBeforeFetch' \
        'mLedger\.executeOnce' \
        'CapabilityLeaseBackendReplayLedger\.requireValidDelivery' \
        'mBroker\.acknowledgePrepared' \
        'requireCurrent\(delivery\)' \
        'elapsedRealtimeMillis' \
        'bootIdSha256' \
        'createExecutionPreflightProof' \
        'revalidateForExecution' \
        'mDestinationConsumer\.execute\(destination\)' \
        'encodeExecutedResponse' \
        'mLedger\.reconcilePrepared'; do
    require "$marker" "$SYSTEM_API_COORDINATOR"
done
deny 'ExactUriEffect|mEffect|execute\(delivery\.exactHttpsUri\)' \
    "$SYSTEM_API_COORDINATOR"
prefetch_line=$(grep -n 'mLedger\.replayBeforeFetch' "$SYSTEM_API_COORDINATOR" | head -n1 | cut -d: -f1)
fetch_line=$(grep -n 'mBroker\.fetchReceipt' "$SYSTEM_API_COORDINATOR" | tail -n1 | cut -d: -f1)
[[ -n "$prefetch_line" && -n "$fetch_line" && "$prefetch_line" -lt "$fetch_line" ]] || {
    echo "CONSUMED backend replay must be queried before broker receipt fetch" >&2; exit 1;
}
require 'capability_lease_unavailable' "$SYSTEM_API_SERVICE"
require 'CapabilityLeaseSystemApiOpenUriCoordinator' "$SYSTEM_API_SERVICE"
deny 'new Intent\(Intent\.ACTION_VIEW' "$SYSTEM_API_SERVICE"
[[ $(grep -Fc 'SELinux.getPidContext(pid)' "$VERIFIER") -eq 2 ]] || {
    echo "broker caller verifier must re-read the SELinux pid context" >&2; exit 1;
}

for marker in \
        'UI_POLL\(Role\.AI_SHELL\)' \
        'ISSUER_FETCH\(Role\.ISSUER\)' \
        'ISSUER_SUBMIT\(Role\.ISSUER\)' \
        'ISSUER_CANCEL\(Role\.ISSUER\)' \
        'BACKEND_CREATE\(Role\.ACCESSIBILITY\)' \
        'BACKEND_FETCH_RECEIPT\(Role\.ACCESSIBILITY\)' \
        'BACKEND_ACK_PREPARED\(Role\.ACCESSIBILITY\)' \
        'androidUserId != 0' 'packagesForUid != 1'; do
    require "$marker" "$POLICY"
done

for marker in \
        'final class UiFacade' 'final class BackendFacade' \
        'final class LocalSystemApiFacade' \
        'authorizeIssuerFetch' 'authorizeIssuerSubmit' 'authorizeIssuerCancel' \
        'final class AuthorizedCall' 'mConsumed\.compareAndSet\(false, true\)' \
        'mCallerVerifier\.verify' \
        'caller\.role != operation\.requiredRole'; do
    require "$marker" "$FACADES"
done

for marker in \
        'new ThreadPoolExecutor' 'new ArrayBlockingQueue' \
        'DEFAULT_MAX_OUTSTANDING_PER_UID = 2' \
        'DEFAULT_MAX_CALLS_PER_WINDOW = 16' \
        'task\.get\(mTimeoutMillis, TimeUnit\.MILLISECONDS\)' \
        'mExecutor\.remove\(task\)' \
        'mPoisoned' 'ERROR_INDETERMINATE' \
        'state\.outstanding >= mMaxOutstandingPerUid' \
        'state\.callsInWindow >= mMaxCallsPerWindow'; do
    require "$marker" "$CALL_EXECUTOR"
done

for marker in \
        'extends ICapabilityLeaseUiBroker\.Stub' \
        'CapabilityLeaseUiProtocol\.requireTransportSchema' \
        'CapabilityLeaseUiProtocol\.requirePendingHandle' \
        'CapabilityLeaseUiProtocol\.requireReceipt' \
        'CapabilityLeaseUiProtocol\.VIEW_SCHEMA' \
        '!handle\.equals\(view\.handle\)' \
        'mUi\.authorizeIssuerFetch' \
        'mUi\.authorizeIssuerSubmit' \
        'mUi\.authorizeIssuerCancel' \
        'mCalls\.call' \
        'mUi\.fetchForIssuer' \
        'mUi\.submitFromIssuer' \
        'mUi\.cancelFromIssuer'; do
    require "$marker" "$UI_BINDER"
done
deny 'clearCallingIdentity|withCleanCallingIdentity' "$UI_BINDER"
submit_authorize_line=$(grep -n 'mUi\.authorizeIssuerSubmit' "$UI_BINDER" \
        | head -n1 | cut -d: -f1)
receipt_parse_line=$(grep -n 'CapabilityLeaseUiProtocol\.requireReceipt(exactReceipt)' \
        "$UI_BINDER" | head -n1 | cut -d: -f1)
[[ -n "$submit_authorize_line" && -n "$receipt_parse_line" \
        && "$submit_authorize_line" -lt "$receipt_parse_line" ]] || {
    echo "issuer caller must be verified before receipt parsing" >&2
    exit 1
}
for marker in \
        'TRANSPORT_SCHEMA' \
        'VIEW_SCHEMA' \
        'VIEW_FIELDS = 8' \
        'MAX_CHALLENGE_BYTES = 64 \* 1024' \
        'MAX_RECEIPT_BYTES = 256 \* 1024' \
        'value\.length\(\) > maxBytes' \
        'value\.getBytes\(StandardCharsets\.UTF_8\)\.length > maxBytes'; do
    require "$marker" "$UI_PROTOCOL"
done
for marker in \
        'fetchExactChallenge\(String transportSchema, String pendingHandle\)' \
        'String transportSchema, String pendingHandle,' \
        'String submissionOperationId, String exactReceipt' \
        'cancelPending\(String transportSchema, String pendingHandle\)'; do
    require "$marker" "$UI_AIDL"
done
for marker in \
        'CapabilityLeaseBrokerProductEnrollment::load' \
        'TrillionniumContextConstants\.Features\.CAPABILITY_LEASE' \
        'publishBinderService' \
        'CapabilityLeaseBrokerNames\.UI' \
        'enrollment == null' \
        'broker held closed'; do
    require "$marker" "$SERVICE"
done
deny 'TrillionniumContextConstants\.Features\.AGENT_SYSTEM_API' "$SERVICE"
require 'CAPABILITY_LEASE' "$CONTEXT_CONSTANTS"
require 'org\.trillionnium\.agent\.capability_lease' "$CONTEXT_CONSTANTS"
deny 'org\.trillionnium\.agent\.capability_lease' "$CURRENT_FEATURE_XML"
for marker in \
        'CapabilityLeaseTrustConfigLoader\.load' \
        'CapabilityLeaseTrustConfigLoader\.Enabled' \
        'CapabilityLeaseRollbackEpochStateProof\.STATUS'; do
    require "$marker" "$PRODUCT_ENROLLMENT"
done

deny 'publishBinderService|ServiceManager|addService|registerService|onStart\(' \
    "$BROKER" "$CHALLENGE_ENCODER" "$RECEIPT_VERIFIER" "$KEYMINT_VERIFIER" \
    "$BACKEND_LEDGER" "$BACKEND_FILE_STORE" "$SYSTEM_API_COORDINATOR" \
    "$FACADES" "$VERIFIER" "$BACKEND_ACK_PUBLISHER" "$TOKEN_REGISTRY" \
    "$TOKEN_REGISTRY_FILE_STORE"
deny 'Intent\.ACTION_VIEW|startActivity|sendBroadcast' \
    "$BACKEND_ACK_PUBLISHER" "$TOKEN_REGISTRY" "$TOKEN_REGISTRY_FILE_STORE"
require 'org\.trillionnium\.platform\.internal\.CapabilityLeaseBrokerService' "$CONFIG"
deny 'CapabilityLeaseBrokerServiceFacades|CapabilityLeasePendingBroker|capability_lease_(ui|backend)' \
    "$MANIFEST"

for marker in \
        'pendingBrokerCreateOrReplayUsesSameOsBackedHandleAfterObjectReinstantiation' \
        'FAULT_BEFORE_WRITE' 'FAULT_AFTER_FILE_FSYNC' 'FAULT_AFTER_RENAME' \
        'FAULT_AFTER_UNLINK' 'FAULT_AFTER_DIRECTORY_FSYNC' \
        'failedWriteCleanupUncertaintyPoisonsBothLiveStores' \
        'pendingBeforeTombstoneRenameRetainsOldWatermarkAndTerminal' \
        'pendingOrphanTombstoneFaultsRecoverOldTerminalAndWatermark' \
        'pendingCommittedRetirementSurvivesWatermarkUnlinkAndFsyncFaults' \
        'pendingReplaceDirectoryFsyncFaultsPoisonAndRestartUsesReplacement' \
        'backendWatermarkCreateDirectoryFsyncFaultsPoisonAndRestartAdoptsWatermark' \
        'backendReplaceDirectoryFsyncFaultsPoisonAndRestartUsesConsumed' \
        'backendCompactionBeforeRenameRetainsConsumedAndOldWatermark' \
        'backendPreparedIsNeverReclaimedAndOldBootConsumedIsRetained' \
        'Os\.lstat' 'Os\.remove'; do
    require "$marker" "$OS_FAULT_TEST"
done
require 'android:name="androidx\.test\.runner\.AndroidJUnitRunner"' "$OS_FAULT_MANIFEST"
deny 'sharedUserId|uses-permission' "$OS_FAULT_MANIFEST"
[[ $(grep -Fc '"TrillionniumCapabilityLeaseOsFileStoreFaultMatrixTest"' "$BUILD") -eq 1 ]] || {
    echo "device Os fault test must be declared once and never packaged as a requirement" >&2
    exit 1
}
deny 'new CapabilityLease(Pending|BackendReplay)FileStore\([^)]*,[^)]*,[^)]*,[^)]*\)' \
    "${SOURCE_FILES[@]}"

require 'name: "TrillionniumCapabilityLeasePendingBrokerTest"' "$BUILD"
require 'CapabilityLeaseBrokerCallExecutorTest\.java' "$BUILD"
require 'name: "TrillionniumCapabilityLeaseBrokerSourceContractTest"' "$BUILD"
require 'name: "TrillionniumCapabilityLeaseOsFileStoreFaultMatrixTest"' "$BUILD"

echo "PASS: durable capability-lease broker has a fail-closed issuer Binder lifecycle"
