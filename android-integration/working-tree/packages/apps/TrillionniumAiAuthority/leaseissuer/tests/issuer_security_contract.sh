#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
locate() {
    local relative=$1
    local packaged=${2:-$(basename "$relative")}
    local direct="$ROOT/$relative"
    if [[ -f "$direct" ]]; then
        printf '%s\n' "$direct"
        return
    fi
    find "$(cd "$(dirname "$0")" && pwd)" \
        \( -path "*/$relative" -o -name "$packaged" \) -print -quit
}

BLUEPRINT=$(locate Android.bp)
AUTHORITY_MANIFEST=$(locate AndroidManifest.xml)
AUTHORITY_RESOURCES=$(locate res/values/strings.xml)
ISSUER_MANIFEST=$(locate leaseissuer/AndroidManifest.xml \
    TrillionniumCapabilityLeaseIssuer.AndroidManifest.xml)
ISSUER_RESOURCES=$(locate leaseissuer/res/values/strings.xml \
    TrillionniumCapabilityLeaseIssuer.signing-resources.xml)
ACTIVITY=$(locate leaseissuer/src/org/trillionnium/capabilitylease/CapabilityLeaseActivity.java)
CONTRACT=$(locate leaseissuer/src/org/trillionnium/capabilitylease/CapabilityLeaseContract.java)
LEDGER=$(locate leaseissuer/src/org/trillionnium/capabilitylease/CapabilityLeaseIssuanceLedger.java)
DURABLE_FILES=$(locate leaseissuer/src/org/trillionnium/capabilitylease/AndroidDurableFileOps.java)
TRUST=$(locate leaseissuer/src/org/trillionnium/capabilitylease/LeaseIssuerTrust.java)
SIGNER=$(locate leaseissuer/src/org/trillionnium/capabilitylease/ReceiptSigner.java)
CANONICAL=$(locate leaseissuer/src/org/trillionnium/capabilitylease/CanonicalJson.java)
STRICT=$(locate leaseissuer/src/org/trillionnium/capabilitylease/StrictJson.java)
ECDSA=$(locate leaseissuer/src/org/trillionnium/capabilitylease/EcdsaP256.java)
VERIFIER=$(locate leaseissuer/src/org/trillionnium/capabilitylease/ReceiptSignatureVerifier.java)
SYSTEM_USER=$(locate leaseissuer/src/org/trillionnium/capabilitylease/SystemUserBoundary.java)
BROKER_CLIENT=$(locate leaseissuer/src/org/trillionnium/capabilitylease/CapabilityLeaseBrokerClient.java)
BROKER_CLIENTS=$(locate leaseissuer/src/org/trillionnium/capabilitylease/CapabilityLeaseBrokerClients.java)
BROKER_WIRE=$(locate leaseissuer/src/org/trillionnium/capabilitylease/CapabilityLeaseBrokerWire.java)
UI_PROTOCOL="$ROOT/../../../trillionnium-sdk/capabilityleaseapi/src/org/trillionnium/capabilitylease/CapabilityLeaseUiProtocol.java"
if [[ ! -f "$UI_PROTOCOL" ]]; then
    UI_PROTOCOL=$(locate CapabilityLeaseUiProtocol.java CapabilityLeaseUiProtocol.java)
fi
PRESENTATION=$(locate leaseissuer/src/org/trillionnium/capabilitylease/CapabilityLeasePresentation.java)
PENDING_HANDLE=$(locate leaseissuer/src/org/trillionnium/capabilitylease/LeasePendingHandle.java)
CHALLENGE_GOLDEN=$(locate leaseissuer/tests/CapabilityLeaseChallengeV1Golden.java)
ISSUER_SOURCES=("$ACTIVITY" "$CONTRACT" "$LEDGER" "$DURABLE_FILES" "$TRUST" "$SIGNER"
    "$CANONICAL" "$STRICT" "$ECDSA" "$VERIFIER" "$SYSTEM_USER" "$BROKER_CLIENT"
    "$BROKER_CLIENTS" "$BROKER_WIRE" "$UI_PROTOCOL" "$PRESENTATION" "$PENDING_HANDLE")

for source in "$BLUEPRINT" "$AUTHORITY_MANIFEST" "$AUTHORITY_RESOURCES" \
        "$ISSUER_MANIFEST" "$ISSUER_RESOURCES" "$ACTIVITY" "$CONTRACT" "$LEDGER" \
        "$DURABLE_FILES" "$TRUST" "$SIGNER" "$CANONICAL" "$STRICT" "$ECDSA" \
        "$VERIFIER" "$SYSTEM_USER" "$BROKER_CLIENT" "$BROKER_CLIENTS" "$BROKER_WIRE" \
        "$UI_PROTOCOL" \
        "$PRESENTATION" \
        "$PENDING_HANDLE" "$CHALLENGE_GOLDEN"; do
    [[ -f "$source" ]] || { echo "missing issuer security input: $source" >&2; exit 1; }
done

require() {
    local pattern=$1
    shift
    rg -q -- "$pattern" "$@" || {
        echo "missing issuer contract marker: $pattern" >&2
        exit 1
    }
}

deny() {
    local pattern=$1
    shift
    if rg -n -- "$pattern" "$@"; then
        echo "forbidden issuer coupling or effect surface remains: $pattern" >&2
        exit 1
    fi
}

for marker in \
        'd3ab8272d63050743e3affc66206d56eeac516192f83871b5490bb872f64f24e' \
        'lease-challenge-95efbcda48ff33c5bfae8d105538c140a571314c8d6800c4a00ef9f601ed1539' \
        'lease-0981b34439ec599752e5210c1306fe916b76d00dc02f7118b2a2e80dc412fb44' \
        'task.open-uri-golden-v1' \
        'org.trillionnium.aishell'; do
    require "$marker" "$CHALLENGE_GOLDEN"
done

issuer_module=$(sed -n '/name: "TrillionniumCapabilityLeaseIssuer"/,/^}/p' "$BLUEPRINT")
for marker in \
        'manifest: "leaseissuer/AndroidManifest.xml"' \
        'srcs: \["leaseissuer/src/\*\*/\*\.java"\]' \
        'resource_dirs: \["leaseissuer/res"\]' \
        'certificate: "testkey"' \
        '"trillionnium-agent-identity-product"' \
        '"trillionnium-capability-lease-binder-api"' \
        'system_ext_specific: true' \
        'privileged: false'; do
    require "$marker" <(printf '%s\n' "$issuer_module")
done

for marker in \
        'EXTRA_PENDING_HANDLE' \
        'LeasePendingHandle.requireExact' \
        'mBroker.fetchExactChallenge' \
        'mBroker.submitExactReceipt' \
        'mBroker.cancelPending' \
        'requireSameImmutableView' \
        'Exact HTTPS URI \(complete\)' \
        'Authorization: one use only' \
        'CountDownTimer'; do
    require "$marker" "$ACTIVITY" "$BROKER_CLIENT" "$PRESENTATION" "$PENDING_HANDLE"
done
for marker in \
        'ServiceManager\.getService\(CapabilityLeaseBrokerNames\.UI\)' \
        'ICapabilityLeaseUiBroker\.Stub\.asInterface' \
        'binder\.isBinderAlive\(\)' \
        'CapabilityLeaseBrokerWire\.decodePendingView' \
        'mBroker\.submitExactReceipt' \
        'capability_lease_broker_client_unavailable'; do
    require "$marker" "$BROKER_CLIENTS"
done
for marker in \
        'new CapabilityLeaseBrokerClient\.PendingChallenge\(' \
        'CapabilityLeaseUiProtocol\.VIEW_FIELDS' \
        'CapabilityLeaseUiProtocol\.VIEW_SCHEMA\.equals' \
        'capability_lease_broker_response_denied'; do
    require "$marker" "$BROKER_WIRE"
done
for marker in \
        'TRANSPORT_SCHEMA' \
        'VIEW_SCHEMA' \
        'VIEW_FIELDS = 8' \
        'MAX_RECEIPT_BYTES = 256 \* 1024' \
        'value\.length\(\) > maxBytes' \
        'value\.getBytes\(StandardCharsets\.UTF_8\)\.length > maxBytes' \
        'requirePendingHandle' \
        'requireReceiptId'; do
    require "$marker" "$UI_PROTOCOL"
done
deny 'EXTRA_CHALLENGE([[:space:]]|=)|EXTRA_RECEIPT([[:space:]]|=)|capability_lease_challenge_json|capability_lease_receipt_json' \
    "$ACTIVITY" "$BROKER_CLIENT" "$BROKER_CLIENTS" "$BROKER_WIRE" "$UI_PROTOCOL" \
    "$PRESENTATION" \
    "$PENDING_HANDLE"
require 'name: "TrillionniumCapabilityLeaseIssuerPolicyContractSources"' "$BLUEPRINT"

for marker in \
        'package="org.trillionnium.capabilitylease"' \
        'org.trillionnium.capabilitylease.permission.REQUEST_CAPABILITY_LEASE' \
        '@array/capability_lease_request_known_signers' \
        'android:protectionLevel="signature\|knownSigner"' \
        'android:name="\.CapabilityLeaseActivity"' \
        'android:exported="true"' \
        'android:usesCleartextTraffic="false"'; do
    require "$marker" "$ISSUER_MANIFEST"
done
[[ $(grep -Fc 'android:exported="true"' "$ISSUER_MANIFEST") -eq 1 ]] || {
    echo "issuer must export exactly its consent Activity" >&2; exit 1;
}
deny 'sharedUserId|android:process=|<service|<receiver|<provider|android.permission.INTERNET' \
    "$ISSUER_MANIFEST"
deny 'CapabilityLease|REQUEST_CAPABILITY_LEASE|org.trillionnium.capabilitylease' \
    "$AUTHORITY_MANIFEST"

require 'capability_lease_request_known_signers' "$ISSUER_RESOURCES"
deny 'egress_consent_known_signers' "$ISSUER_RESOURCES"
deny 'capability_lease_request_known_signers' "$AUTHORITY_RESOURCES"

for marker in \
        'ISSUER_PACKAGE = "org.trillionnium.capabilitylease"' \
        'UI_PACKAGE = "org.trillionnium.aishell"' \
        'trillionnium-capability-lease-receipt-v1' \
        'org.trillionnium.capabilitylease.receipt-key-trust-config.v1' \
        'os_image_pinned_package_key_epoch_key_id' \
        'org.trillionnium.capabilitylease.receipt-key.v1'; do
    require "$marker" "$TRUST"
done

for marker in \
        'AndroidKeyStore' \
        'LeaseIssuerTrust.RECEIPT_KEY_ALIAS' \
        'PackageManager.FEATURE_STRONGBOX_KEYSTORE' \
        'context\.getPackageManager\(\)\.hasSystemFeature' \
        'setIsStrongBoxBacked' \
        'setAttestationChallenge' \
        'info.getSecurityLevel()' \
        'ReceiptSignatureVerifier.verify' \
        'receipt_signing_trust_config_schema' \
        'receipt_signing_trust_config_source' \
        'requireOwnTrustMetadata'; do
    require "$marker" "$SIGNER"
done

require 'new ReceiptSigner\(getApplicationContext\(\)\)' "$ACTIVITY"

for marker in \
        'org.trillionnium.capabilitylease.capability-lease-challenge.v1' \
        'org.trillionnium.capabilitylease.capability-lease-receipt.v1' \
        'org.trillionnium.agent-risk-guard.v1' \
        'agent_identity_key_sha256' \
        'agent_executable_sha256' \
        'action_binding_sha256' \
        'ui_scope_binding_sha256' \
        'not_before_elapsed_realtime_ms' \
        'expires_elapsed_realtime_ms' \
        'risk_class' \
        'max_uses' \
        'receipt_required' \
        'canonicalReceiptForSignature'; do
    require "$marker" "$CONTRACT"
done

for marker in \
        'private static final AgentDescriptor CODEX = AgentDescriptor.CODEX' \
        'CODEX_PROVIDER_ID = CODEX.providerId\(\)' \
        '!CODEX_PROVIDER_ID\.equals\(provider\)' \
        '!CODEX.identityKeySha256\(\).equals\(identityKey\)' \
        '!CODEX.identityKeySha256\(\).equals\(executable\)' \
        '!CapabilityLeaseContract\.CODEX_PROVIDER_ID\.equals\(providerId\)'; do
    require "$marker" "$CONTRACT" "$BROKER_CLIENT" "$ACTIVITY"
done
deny '483eb9e97d3ee81bae8656f25749f6cc2c310575898b77e5a364b727a798c8c3' \
    "$CONTRACT"

for marker in \
        'capability_lease_issuance_ledger_v1' \
        'issuance-ledger-prepared.v1' \
        'issuance-ledger-issued.v1' \
        'PROCESS_LOCK' \
        'lockPrivateFile' \
        'createNewDurable\(prepared, preparedBytes\)' \
        'receiptFactory.signExactReceipt' \
        'createNewDurable\(issued, issuedBytes\)' \
        'prepared_commit_unknown_denied' \
        'challenge_drift_denied' \
        'capacity_entries_denied' \
        'capacity_bytes_denied'; do
    require "$marker" "$LEDGER"
done

prepare_line=$(rg -n 'createNewDurable\(prepared, preparedBytes\)' "$LEDGER" | cut -d: -f1)
sign_line=$(rg -n 'receiptFactory\.signExactReceipt' "$LEDGER" | cut -d: -f1)
issued_line=$(rg -n 'createNewDurable\(issued, issuedBytes\)' "$LEDGER" | cut -d: -f1)
[[ "$prepare_line" -lt "$sign_line" && "$sign_line" -lt "$issued_line" ]] || {
    echo "issuer ledger must durably PREPARE before sign and durably ISSUE before return" >&2
    exit 1
}

for marker in \
        'O_NOFOLLOW' \
        'O_EXCL' \
        'PRIVATE_FILE_MODE = 0600' \
        'st_uid == android.os.Process.myUid()' \
        'st_nlink == 1' \
        'getFD\(\)\.sync\(\)' \
        'syncDirectory\(file\.getParent\(\)\)' \
        'createNewDurable'; do
    require "$marker" "$DURABLE_FILES"
done

# The append-only ledger has no cleanup path: corruption or ambiguous PREPARED is terminal.
deny 'Files\.delete|\.delete\(|deleteIfExists|Files\.move|Os\.remove|Os\.unlink|'\
'REPLACE_EXISTING|TRUNCATE_EXISTING|Os\.rename' \
    "$LEDGER" "$DURABLE_FILES"

for marker in \
        'setHideOverlayWindows' \
        'setFilterTouchesWhenObscured' \
        'SystemClock.elapsedRealtime' \
        'mReceiptSigner.isHardwareBacked' \
        'mReceiptSigner.hasAttestationChain' \
        'createDeviceProtectedStorageContext' \
        'getNoBackupFilesDir' \
        'mIssuanceLedger.issueOrReplay' \
        'signExactReceiptAfterPrepared' \
        'mReceiptSigner.requireOwnTrustMetadata' \
        'mReceiptSigner.verify' \
        'It authorizes only the exact URI shown below' \
        'does not execute it.'; do
    require "$marker" "$ACTIVITY"
done

# The separate issuer must not reuse AiAuthority's package, caller resource, receipt key, UDS
# metadata protocol, or any dispatch/effect vocabulary.
deny 'org\.trillionnium\.aiauthority|trillionnium-ai-authority-receipt-v2|egress_consent|AgentGatewayServer|trillionnium\.android-agent-gateway|receipt_signing_key_metadata_(protocol|method)' \
    "${ISSUER_SOURCES[@]}" "$ISSUER_MANIFEST" "$ISSUER_RESOURCES"
deny 'LocalSocket|LocalServerSocket|NotificationManager|startActivity\(|startService\(|bindService\(|sendBroadcast\(|case "(execute|undo)"|"(execute|undo)"\.equals' \
    "${ISSUER_SOURCES[@]}"

echo "PASS: independent capability lease issuer durable issuance/key/trust/effect boundary"
