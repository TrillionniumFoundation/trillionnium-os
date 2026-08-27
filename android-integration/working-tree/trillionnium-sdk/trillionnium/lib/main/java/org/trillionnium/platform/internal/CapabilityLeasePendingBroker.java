/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import org.trillionnium.agentidentity.AgentDescriptor;
import org.trillionnium.agentidentity.AgentDescriptorRegistry;
import org.trillionnium.capabilitylease.CapabilityLeaseUiProtocol;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Non-executing pending broker for the first typed capability-lease ceremony. */
final class CapabilityLeasePendingBroker {
    static final String HANDLE_PREFIX = "lease-pending-";
    static final int MAX_PENDING = 128;
    static final int MAX_RETIRED_TOMBSTONES = 8192;
    static final String RETIREMENT_ACTIVATION_HOLD =
            "source_only_pending_retirement_capacity_hold_no_authenticated_rollup_v1";
    static final long MAX_TTL_MS = 30_000L;

    private final Clock mClock;
    private final Entropy mEntropy;
    private final ChallengeEncoder mChallengeEncoder;
    private final ReceiptValidator mReceiptValidator;
    private final CapabilityLeasePendingStore mStore;
    private final String mCurrentBootIdSha256;
    private final Map<String, RuntimeRecord> mRecords = new LinkedHashMap<>();
    private final Map<String, RuntimeRecord> mPrepareRequests = new LinkedHashMap<>();
    private final Map<String, RuntimeRecord> mAuthenticatedTaskBindings = new LinkedHashMap<>();
    private final Map<String, CapabilityLeasePendingStore.RetirementTombstone>
            mRetiredHandles = new LinkedHashMap<>();
    private final Map<String, CapabilityLeasePendingStore.RetirementTombstone>
            mRetiredPrepareRequests = new LinkedHashMap<>();
    private final Map<String, CapabilityLeasePendingStore.RetirementTombstone>
            mRetiredTaskBindings = new LinkedHashMap<>();
    private CapabilityLeasePendingStore.CompactionWatermark mRetirementWatermark;
    private boolean mPoisoned;

    CapabilityLeasePendingBroker(Clock clock, Entropy entropy, ChallengeEncoder challengeEncoder,
            ReceiptValidator receiptValidator, CapabilityLeasePendingStore store,
            String currentBootIdSha256) throws IOException {
        mClock = requireNonNull(clock, "capability_lease_broker_clock_denied");
        mEntropy = requireNonNull(entropy, "capability_lease_broker_entropy_denied");
        mChallengeEncoder = requireNonNull(
                challengeEncoder, "capability_lease_broker_challenge_encoder_denied");
        mReceiptValidator = requireNonNull(
                receiptValidator, "capability_lease_broker_receipt_validator_denied");
        mStore = requireNonNull(store, "capability_lease_broker_store_denied");
        mCurrentBootIdSha256 = requireNonzeroDigest(
                currentBootIdSha256, "capability_lease_broker_boot_denied");
        Map<String, CapabilityLeasePendingStore.Record> loaded = mStore.load();
        CapabilityLeasePendingStore.CompactionWatermark compactionWatermark =
                mStore.loadCompactionWatermark();
        Map<String, CapabilityLeasePendingStore.RetirementTombstone> retired =
                mStore.loadRetirementTombstones();
        if (loaded == null || loaded.size() > MAX_PENDING || compactionWatermark == null
                || retired == null || retired.size() > MAX_RETIRED_TOMBSTONES
                || mStore.isPoisoned()) {
            throw new IOException("invalid durable pending set");
        }
        restoreRetirementChain(retired, compactionWatermark);
        mRetirementWatermark = compactionWatermark;
        for (Map.Entry<String, CapabilityLeasePendingStore.Record> item : loaded.entrySet()) {
            CapabilityLeasePendingStore.Record stored = item.getValue();
            if (stored == null || !item.getKey().equals(stored.handle)) {
                throw new IOException("invalid durable pending identity");
            }
            RuntimeRecord runtime = restore(stored);
            if (!stored.bootIdSha256.equals(mCurrentBootIdSha256)
                    && isLive(stored.state)) {
                CapabilityLeasePendingStore.Record expired = stored.transition(
                        CapabilityLeasePendingStore.State.EXPIRED, null, null, null);
                mStore.replace(stored, expired);
                runtime.stored = expired;
            }
            indexRuntime(runtime);
        }
    }

    synchronized String createOpenUri(PendingOpenUriRequest request) throws Exception {
        return createOrReplayOpenUri(request);
    }

    synchronized PendingView prepareOpenUriForLocalBackend(PendingOpenUriRequest request)
            throws Exception {
        String handle = createOrReplayOpenUri(request);
        RuntimeRecord record = mRecords.get(handle);
        if (record == null) {
            throw denied("capability_lease_broker_prepare_replay_retired");
        }
        return pendingView(record);
    }

    synchronized String createOrReplayOpenUri(PendingOpenUriRequest request) throws Exception {
        requireAvailable();
        requireNonNull(request, "capability_lease_broker_request_denied");
        if (!mCurrentBootIdSha256.equals(request.bootIdSha256)) {
            throw denied("capability_lease_broker_boot_mismatch_denied");
        }
        RuntimeRecord existingRequest = mPrepareRequests.get(request.prepareReplayKey());
        if (existingRequest != null) {
            request.requireExactBinding(existingRequest.stored);
            return existingRequest.stored.handle;
        }
        CapabilityLeasePendingStore.RetirementTombstone retiredRequest =
                mRetiredPrepareRequests.get(request.prepareReplayKey());
        if (retiredRequest != null) {
            requireExactRetiredBinding(request, retiredRequest);
            return retiredRequest.handle;
        }
        RuntimeRecord existingTask =
                mAuthenticatedTaskBindings.get(request.authenticatedTaskReplayKey());
        if (existingTask != null) {
            throw denied("capability_lease_broker_prepare_binding_conflict");
        }
        if (mRetiredTaskBindings.containsKey(request.authenticatedTaskReplayKey())) {
            throw denied("capability_lease_broker_prepare_binding_conflict");
        }
        long nowWallMs = mClock.wallTimeMillis();
        long nowElapsedMs = mClock.elapsedRealtimeMillis();
        requireClock(nowWallMs, nowElapsedMs);
        expireDueRecords(nowElapsedMs);
        if (mRecords.size() >= MAX_PENDING) retireOneTerminalForCapacity();
        if (mRecords.size() >= MAX_PENDING) {
            throw denied("capability_lease_broker_capacity_denied");
        }
        OpenUriLeaseSemanticsV1.Semantics semantics = derive(request);
        long expiresWallMs = checkedAdd(nowWallMs, MAX_TTL_MS);
        long expiresElapsedMs = checkedAdd(nowElapsedMs, MAX_TTL_MS);
        String exactChallenge = mChallengeEncoder.encode(
                request, semantics, nowWallMs, expiresWallMs, nowElapsedMs, expiresElapsedMs);
        requireBoundedText(exactChallenge, 64 * 1024,
                "capability_lease_broker_challenge_denied");
        String handle = newHandle();
        CapabilityLeasePendingStore.Record stored = new CapabilityLeasePendingStore.Record(
                handle, request.creatorPeerIdentity, request.prepareRequestId,
                request.authenticatedTaskBindingSha256,
                request.prepareCanonicalRequestSha256,
                request.workflowId, request.taskId, request.bootIdSha256,
                request.providerId, request.exactHttpsUri, exactChallenge,
                nowWallMs, expiresWallMs, nowElapsedMs, expiresElapsedMs,
                CapabilityLeasePendingStore.State.PENDING, null, null, null);
        RuntimeRecord runtime = new RuntimeRecord(stored, request, semantics);
        // Prove every in-memory identity is free before publishing durable bytes. The store is a
        // callback boundary, so the same checks are repeated when adopting the committed record.
        requireRuntimeIndexAvailable(runtime);
        try {
            mStore.create(stored);
        } catch (CapabilityLeasePendingStore.CreateCommittedException committed) {
            mPoisoned = true;
            committed.requireExact(stored);
            try {
                indexRuntime(runtime);
            } catch (IOException committedIndexFailure) {
                committed.addSuppressed(committedIndexFailure);
            }
            throw committed;
        }
        try {
            indexRuntime(runtime);
        } catch (IOException committedIndexFailure) {
            // Durable create already returned success. Never expose an ordinary create failure or
            // continue with a live view that omitted committed authority.
            mPoisoned = true;
            throw new CapabilityLeasePendingStore.CreateCommittedException(
                    stored, committedIndexFailure);
        }
        return handle;
    }

    synchronized PendingView fetchForIssuer(String handle) throws IOException {
        requireAvailable();
        RuntimeRecord record = requireIssuerVisible(handle);
        return pendingView(record);
    }

    private PendingView pendingView(RuntimeRecord record) {
        return new PendingView(record.stored.handle, record.stored.exactChallenge,
                record.semantics.uri, destinationHost(record.semantics.uri),
                record.semantics.androidUser, record.request.providerId,
                record.stored.expiresAtMs, record.stored.expiresElapsedMs);
    }

    synchronized Submission submitFromIssuer(
            String handle, String submissionOperationId, String exactReceipt)
            throws Exception {
        requireAvailable();
        RuntimeRecord record = requireRecord(handle);
        expireIfNecessary(record, mClock.elapsedRealtimeMillis());
        requireBoundedText(exactReceipt, 256 * 1024,
                "capability_lease_broker_receipt_denied");
        String receiptSha256 = sha256(exactReceipt.getBytes(StandardCharsets.UTF_8));
        String expectedSubmissionOperationId =
                CapabilityLeaseUiProtocol.deriveSubmissionOperationIdFromReceiptSha256(
                        record.stored.handle, receiptSha256);
        if (!constantTimeTextEquals(expectedSubmissionOperationId,
                CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                        submissionOperationId))) {
            throw denied("capability_lease_broker_submission_operation_denied");
        }
        if (record.stored.state != CapabilityLeasePendingStore.State.PENDING) {
            if (hasReceipt(record.stored)
                    && receiptSha256.equals(record.stored.receiptSha256)) {
                return submission(record, expectedSubmissionOperationId);
            }
            throw denied("capability_lease_broker_not_pending");
        }
        String receiptId = mReceiptValidator.validateAndReturnReceiptId(
                record.stored.exactChallenge, exactReceipt, record.request, record.semantics);
        requireDigest(receiptId, "capability_lease_broker_receipt_id_denied");
        // A verified receipt is intentionally not delivery-eligible yet. The caller may lose the
        // synchronous Binder reply after this durable transition, so all broker consumers must
        // observe the same quarantined state until AiShell acknowledges receiving the exact tuple.
        transition(record, record.stored.transition(
                CapabilityLeasePendingStore.State.INDETERMINATE,
                receiptId, receiptSha256, exactReceipt));
        return submission(record, expectedSubmissionOperationId);
    }

    synchronized SubmissionStatus querySubmissionFromIssuer(
            String handle, String submissionOperationId) throws IOException {
        requireAvailable();
        String operationId = CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                submissionOperationId);
        RuntimeRecord record = requireRecord(handle);
        expireIfNecessary(record, mClock.elapsedRealtimeMillis());
        if (hasReceipt(record.stored)) {
            requireExactSubmissionOperation(record.stored, operationId);
        }
        return submissionStatus(record, operationId);
    }

    synchronized SubmissionStatus acknowledgeSubmissionDelivery(
            String handle, String submissionOperationId, String receiptId,
            String statusTupleSha256) throws IOException {
        requireAvailable();
        RuntimeRecord record = requireRecord(handle);
        expireIfNecessary(record, mClock.elapsedRealtimeMillis());
        String operationId = CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                submissionOperationId);
        String exactReceiptId = CapabilityLeaseUiProtocol.requireReceiptId(receiptId);
        String exactTupleSha256 =
                CapabilityLeaseUiProtocol.requireSubmissionStatusTupleSha256(
                        statusTupleSha256);
        requireExactSubmissionOperation(record.stored, operationId);
        if (!constantTimeDigestEquals(exactReceiptId, record.stored.receiptId)) {
            throw denied("capability_lease_broker_submission_delivery_ack_denied");
        }
        String expectedTupleSha256 =
                CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                        record.stored.handle, operationId,
                        CapabilityLeaseUiProtocol.STATUS_INDETERMINATE,
                        record.stored.receiptId);
        if (!constantTimeDigestEquals(exactTupleSha256, expectedTupleSha256)) {
            throw denied("capability_lease_broker_submission_delivery_ack_denied");
        }
        if (record.stored.state == CapabilityLeasePendingStore.State.INDETERMINATE) {
            transition(record, record.stored.transition(
                    CapabilityLeasePendingStore.State.SUBMITTED,
                    record.stored.receiptId, record.stored.receiptSha256,
                    record.stored.exactReceipt));
        } else if (record.stored.state != CapabilityLeasePendingStore.State.SUBMITTED
                && record.stored.state != CapabilityLeasePendingStore.State.DELIVERY_READY
                && record.stored.state != CapabilityLeasePendingStore.State.CONSUMED) {
            throw denied("capability_lease_broker_submission_delivery_ack_denied");
        }
        return submissionStatus(record, operationId);
    }

    synchronized void cancelFromIssuer(String handle) throws IOException {
        requireAvailable();
        RuntimeRecord record = requireRecord(handle);
        expireIfNecessary(record, mClock.elapsedRealtimeMillis());
        if (record.stored.state == CapabilityLeasePendingStore.State.CANCELED) return;
        if (record.stored.state != CapabilityLeasePendingStore.State.PENDING) {
            throw denied("capability_lease_broker_cancel_state_denied");
        }
        transition(record, record.stored.transition(
                CapabilityLeasePendingStore.State.CANCELED, null, null, null));
    }

    synchronized ResultStatus pollForUi(String handle) throws IOException {
        requireAvailable();
        requireHandle(handle);
        CapabilityLeasePendingStore.RetirementTombstone retired = mRetiredHandles.get(handle);
        if (retired != null) {
            return new ResultStatus(retired.terminalState.name().toLowerCase(),
                    retired.receiptId);
        }
        RuntimeRecord record = requireRecord(handle);
        expireIfNecessary(record, mClock.elapsedRealtimeMillis());
        String status;
        switch (record.stored.state) {
            case DELIVERY_READY:
                status = "submitted";
                break;
            default:
                status = record.stored.state.name().toLowerCase();
        }
        return new ResultStatus(status, record.stored.receiptId);
    }

    synchronized ReceiptDelivery fetchReceiptForBackend(String handle) throws IOException {
        requireAvailable();
        RuntimeRecord record = requireRecord(handle);
        expireIfNecessary(record, mClock.elapsedRealtimeMillis());
        if (record.stored.state == CapabilityLeasePendingStore.State.SUBMITTED) {
            transition(record, record.stored.transition(
                    CapabilityLeasePendingStore.State.DELIVERY_READY,
                    record.stored.receiptId, record.stored.receiptSha256,
                    record.stored.exactReceipt));
        }
        if (record.stored.state != CapabilityLeasePendingStore.State.DELIVERY_READY
                || record.stored.exactReceipt == null) {
            throw denied("capability_lease_broker_receipt_not_ready");
        }
        org.json.JSONObject challenge = CapabilityLeaseJson.parseObject(
                record.stored.exactChallenge, "capability_lease_broker_challenge_json_denied");
        String leaseId = requirePrefixedDigest(challenge.optString("lease_id"), "lease-",
                "capability_lease_broker_lease_id_denied");
        return new ReceiptDelivery(record.stored.handle, record.stored.creatorPeerIdentity,
                leaseId, record.stored.receiptId,
                record.stored.receiptSha256,
                requirePrefixedDigest(challenge.optString("operation_id"), "op-",
                        "capability_lease_broker_operation_id_denied"),
                requireDigest(challenge.optString("action_binding_sha256"),
                        "capability_lease_broker_action_binding_denied"),
                record.stored.workflowId, record.stored.taskId,
                record.stored.authenticatedTaskBindingSha256,
                record.stored.prepareCanonicalRequestSha256,
                record.stored.bootIdSha256, record.stored.providerId,
                record.stored.exactHttpsUri, record.stored.expiresAtMs,
                record.stored.expiresElapsedMs, record.stored.exactReceipt);
    }

    synchronized void acknowledgeBackendPrepared(String handle, String receiptId)
            throws IOException {
        requireAvailable();
        requireHandle(handle);
        CapabilityLeasePendingStore.RetirementTombstone retired = mRetiredHandles.get(handle);
        if (retired != null) {
            requireDigest(receiptId, "capability_lease_broker_receipt_id_denied");
            if (retired.terminalState == CapabilityLeasePendingStore.State.CONSUMED
                    && constantTimeDigestEquals(receiptId, retired.receiptId)) {
                return;
            }
            throw denied("capability_lease_broker_backend_ack_denied");
        }
        RuntimeRecord record = requireRecord(handle);
        requireDigest(receiptId, "capability_lease_broker_receipt_id_denied");
        if (record.stored.state == CapabilityLeasePendingStore.State.CONSUMED
                && receiptId.equals(record.stored.receiptId)) {
            return;
        }
        if (record.stored.state != CapabilityLeasePendingStore.State.DELIVERY_READY
                || !receiptId.equals(record.stored.receiptId)) {
            throw denied("capability_lease_broker_backend_ack_denied");
        }
        transition(record, record.stored.transition(CapabilityLeasePendingStore.State.CONSUMED,
                record.stored.receiptId, record.stored.receiptSha256, null));
    }

    synchronized int retainedCountForTest() {
        return mRecords.size();
    }

    synchronized int retiredCountForTest() {
        return mRetiredHandles.size();
    }

    synchronized boolean poisonedForTest() {
        return mPoisoned || mStore.isPoisoned();
    }

    private RuntimeRecord restore(CapabilityLeasePendingStore.Record stored) throws IOException {
        PendingOpenUriRequest request;
        OpenUriLeaseSemanticsV1.Semantics semantics;
        try {
            request = new PendingOpenUriRequest(stored.creatorPeerIdentity,
                    stored.prepareRequestId, stored.authenticatedTaskBindingSha256,
                    stored.prepareCanonicalRequestSha256, stored.workflowId, stored.taskId,
                    stored.bootIdSha256, stored.exactHttpsUri);
            semantics = derive(request);
        } catch (SecurityException invalid) {
            throw new IOException("invalid durable typed draft", invalid);
        }
        return new RuntimeRecord(stored, request, semantics);
    }

    private void restoreRetirementChain(
            Map<String, CapabilityLeasePendingStore.RetirementTombstone> retired,
            CapabilityLeasePendingStore.CompactionWatermark durableWatermark)
            throws IOException {
        List<Map.Entry<String, CapabilityLeasePendingStore.RetirementTombstone>> ordered =
                new ArrayList<>(retired.entrySet());
        ordered.sort(Comparator.comparingLong(item -> item.getValue().epoch));
        CapabilityLeasePendingStore.CompactionWatermark previous =
                CapabilityLeasePendingStore.CompactionWatermark.genesis();
        for (Map.Entry<String, CapabilityLeasePendingStore.RetirementTombstone> item : ordered) {
            CapabilityLeasePendingStore.RetirementTombstone tombstone = item.getValue();
            if (tombstone == null || !tombstone.handle.equals(item.getKey())) {
                throw new IOException("invalid pending retirement identity");
            }
            tombstone.requireValidSuccessor(previous);
            indexRetired(tombstone);
            previous = tombstone.watermark();
        }
        if (!previous.exactState(durableWatermark)) {
            throw new IOException("pending retirement watermark/tombstone mismatch");
        }
    }

    private void indexRuntime(RuntimeRecord runtime) throws IOException {
        requireRuntimeIndexAvailable(runtime);
        mRecords.put(runtime.stored.handle, runtime);
        mPrepareRequests.put(runtime.request.prepareReplayKey(), runtime);
        mAuthenticatedTaskBindings.put(runtime.request.authenticatedTaskReplayKey(), runtime);
    }

    private void requireRuntimeIndexAvailable(RuntimeRecord runtime) throws IOException {
        if (runtime == null || runtime.stored == null || runtime.request == null
                || mRecords.containsKey(runtime.stored.handle)
                || mPrepareRequests.containsKey(runtime.request.prepareReplayKey())
                || mAuthenticatedTaskBindings.containsKey(
                        runtime.request.authenticatedTaskReplayKey())
                || mRetiredHandles.containsKey(runtime.stored.handle)
                || mRetiredPrepareRequests.containsKey(runtime.request.prepareReplayKey())
                || mRetiredTaskBindings.containsKey(
                        runtime.request.authenticatedTaskReplayKey())) {
            throw new IOException("duplicate durable pending prepare identity");
        }
    }

    private void indexRetired(CapabilityLeasePendingStore.RetirementTombstone tombstone)
            throws IOException {
        if (tombstone == null || mRecords.containsKey(tombstone.handle)
                || mRetiredHandles.containsKey(tombstone.handle)
                || mRetiredPrepareRequests.containsKey(tombstone.prepareReplayKey())
                || mRetiredTaskBindings.containsKey(
                        tombstone.authenticatedTaskReplayKey())) {
            throw new IOException("duplicate pending retirement replay identity");
        }
        mRetiredHandles.put(tombstone.handle, tombstone);
        mRetiredPrepareRequests.put(tombstone.prepareReplayKey(), tombstone);
        mRetiredTaskBindings.put(tombstone.authenticatedTaskReplayKey(), tombstone);
    }

    private void retireOneTerminalForCapacity() throws IOException {
        if (mRetiredHandles.size() >= MAX_RETIRED_TOMBSTONES) return;
        RuntimeRecord candidate = null;
        for (RuntimeRecord record : mRecords.values()) {
            if (record != null && !isLive(record.stored.state)) {
                candidate = record;
                break;
            }
        }
        if (candidate == null) return;
        CapabilityLeasePendingStore.CompactionWatermark replacement =
                mRetirementWatermark.next(candidate.stored);
        CapabilityLeasePendingStore.RetirementTombstone tombstone =
                CapabilityLeasePendingStore.RetirementTombstone.from(
                        candidate.stored, replacement);
        try {
            mStore.compactTerminal(candidate.stored, replacement);
        } catch (CapabilityLeasePendingStore.CompactionCommittedException committed) {
            mPoisoned = true;
            committed.requireExact(replacement);
            adoptRetirement(candidate, tombstone, replacement);
            throw committed;
        }
        adoptRetirement(candidate, tombstone, replacement);
    }

    private void adoptRetirement(RuntimeRecord runtime,
            CapabilityLeasePendingStore.RetirementTombstone tombstone,
            CapabilityLeasePendingStore.CompactionWatermark watermark)
            throws IOException {
        if (runtime == null || tombstone == null || watermark == null
                || mRecords.remove(runtime.stored.handle) != runtime
                || mPrepareRequests.remove(runtime.request.prepareReplayKey()) != runtime
                || mAuthenticatedTaskBindings.remove(
                        runtime.request.authenticatedTaskReplayKey()) != runtime) {
            mPoisoned = true;
            throw new IOException("pending retirement in-memory identity drift");
        }
        indexRetired(tombstone);
        mRetirementWatermark = watermark;
    }

    private static void requireExactRetiredBinding(PendingOpenUriRequest request,
            CapabilityLeasePendingStore.RetirementTombstone tombstone) {
        if (request == null || tombstone == null
                || request.creatorPeerIdentity != tombstone.creatorPeerIdentity
                || !request.prepareRequestId.equals(tombstone.prepareRequestId)
                || !constantTimeDigestEquals(request.authenticatedTaskBindingSha256,
                        tombstone.authenticatedTaskBindingSha256)
                || !constantTimeDigestEquals(request.prepareCanonicalRequestSha256,
                        tombstone.prepareCanonicalRequestSha256)
                || !request.workflowId.equals(tombstone.workflowId)
                || !request.taskId.equals(tombstone.taskId)
                || !request.bootIdSha256.equals(tombstone.bootIdSha256)
                || !request.providerId.equals(tombstone.providerId)
                || !request.exactHttpsUri.equals(tombstone.exactHttpsUri)) {
            throw denied("capability_lease_broker_prepare_binding_conflict");
        }
    }

    private RuntimeRecord requireIssuerVisible(String handle) throws IOException {
        RuntimeRecord record = requireRecord(handle);
        expireIfNecessary(record, mClock.elapsedRealtimeMillis());
        if (record.stored.state == CapabilityLeasePendingStore.State.CANCELED
                || record.stored.state == CapabilityLeasePendingStore.State.EXPIRED) {
            throw denied("capability_lease_broker_not_pending");
        }
        return record;
    }

    private RuntimeRecord requireRecord(String handle) {
        requireHandle(handle);
        RuntimeRecord record = mRecords.get(handle);
        if (record == null) throw denied("capability_lease_broker_handle_unknown");
        return record;
    }

    private void expireDueRecords(long nowElapsedMs) throws IOException {
        requireElapsedClock(nowElapsedMs);
        for (RuntimeRecord record : mRecords.values()) expireIfNecessary(record, nowElapsedMs);
    }

    private void expireIfNecessary(RuntimeRecord record, long nowElapsedMs) throws IOException {
        requireElapsedClock(nowElapsedMs);
        if (isLive(record.stored.state)
                && nowElapsedMs >= record.stored.expiresElapsedMs) {
            transition(record, record.stored.transition(
                    CapabilityLeasePendingStore.State.EXPIRED, null, null, null));
        }
    }

    private void transition(RuntimeRecord record, CapabilityLeasePendingStore.Record replacement)
            throws IOException {
        try {
            mStore.replace(record.stored, replacement);
        } catch (CapabilityLeasePendingStore.ReplacementCommittedException committed) {
            mPoisoned = true;
            committed.requireExact(replacement);
            record.stored = replacement;
            throw committed;
        }
        record.stored = replacement;
    }

    private void requireAvailable() throws IOException {
        if (mPoisoned || mStore.isPoisoned()) {
            mPoisoned = true;
            throw new IOException("capability lease broker is poisoned until restart");
        }
    }

    private OpenUriLeaseSemanticsV1.Semantics derive(PendingOpenUriRequest request) {
        try {
            return OpenUriLeaseSemanticsV1.derive(
                    request.taskId, request.bootIdSha256, request.exactHttpsUri);
        } catch (IllegalArgumentException invalidDraft) {
            throw denied("capability_lease_broker_typed_draft_denied");
        }
    }

    private String newHandle() {
        byte[] entropy = mEntropy.nextBytes(32);
        if (entropy == null || entropy.length != 32 || allZero(entropy)) {
            throw denied("capability_lease_broker_entropy_denied");
        }
        String handle = HANDLE_PREFIX + sha256(entropy);
        Arrays.fill(entropy, (byte) 0);
        requireHandle(handle);
        if (mRecords.containsKey(handle) || mRetiredHandles.containsKey(handle)) {
            throw denied("capability_lease_broker_handle_collision");
        }
        return handle;
    }

    private static boolean hasReceipt(CapabilityLeasePendingStore.Record record) {
        return record.receiptId != null && record.receiptSha256 != null;
    }

    private static Submission submission(RuntimeRecord record, String operationId) {
        SubmissionStatus status = submissionStatus(record, operationId);
        if (status.receiptId.isEmpty()) {
            throw denied("capability_lease_broker_submission_denied");
        }
        return new Submission(status.status, status.receiptId,
                status.submissionOperationId, status.statusTupleSha256);
    }

    private static SubmissionStatus submissionStatus(
            RuntimeRecord record, String operationId) {
        if (record == null || record.stored == null) {
            throw denied("capability_lease_broker_submission_status_denied");
        }
        String status;
        switch (record.stored.state) {
            case PENDING:
                status = CapabilityLeaseUiProtocol.STATUS_NOT_STARTED;
                break;
            case INDETERMINATE:
                status = CapabilityLeaseUiProtocol.STATUS_INDETERMINATE;
                break;
            case SUBMITTED:
                status = CapabilityLeaseUiProtocol.STATUS_SUBMITTED;
                break;
            case DELIVERY_READY:
                status = CapabilityLeaseUiProtocol.STATUS_DELIVERY_READY;
                break;
            case CONSUMED:
                status = CapabilityLeaseUiProtocol.STATUS_CONSUMED;
                break;
            case CANCELED:
                status = CapabilityLeaseUiProtocol.STATUS_CANCELED;
                break;
            case EXPIRED:
                status = CapabilityLeaseUiProtocol.STATUS_EXPIRED;
                break;
            default:
                throw denied("capability_lease_broker_submission_status_denied");
        }
        String receiptId = record.stored.receiptId == null ? "" : record.stored.receiptId;
        return new SubmissionStatus(status, operationId, receiptId,
                CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                        record.stored.handle, operationId, status, receiptId));
    }

    private static void requireExactSubmissionOperation(
            CapabilityLeasePendingStore.Record record, String operationId) {
        if (record == null || !hasReceipt(record)
                || !constantTimeTextEquals(operationId,
                        CapabilityLeaseUiProtocol
                                .deriveSubmissionOperationIdFromReceiptSha256(
                                        record.handle, record.receiptSha256))) {
            throw denied("capability_lease_broker_submission_operation_denied");
        }
    }

    private static boolean isLive(CapabilityLeasePendingStore.State state) {
        return state == CapabilityLeasePendingStore.State.PENDING
                || state == CapabilityLeasePendingStore.State.INDETERMINATE
                || state == CapabilityLeasePendingStore.State.SUBMITTED
                || state == CapabilityLeasePendingStore.State.DELIVERY_READY;
    }

    private static String destinationHost(String uri) {
        int start = "https://".length();
        int end = uri.indexOf('/', start);
        if (end <= start) throw denied("capability_lease_broker_uri_denied");
        return uri.substring(start, end);
    }

    private static String requireHandle(String handle) {
        if (handle == null || !handle.matches("lease-pending-[0-9a-f]{64}")) {
            throw denied("capability_lease_broker_handle_denied");
        }
        return handle;
    }

    private static void requireClock(long wallMs, long elapsedMs) {
        if (wallMs <= 0) throw denied("capability_lease_broker_wall_clock_denied");
        requireElapsedClock(elapsedMs);
    }

    private static void requireElapsedClock(long elapsedMs) {
        if (elapsedMs < 0) throw denied("capability_lease_broker_elapsed_clock_denied");
    }

    private static long checkedAdd(long value, long delta) {
        try {
            return Math.addExact(value, delta);
        } catch (ArithmeticException overflow) {
            throw denied("capability_lease_broker_clock_overflow");
        }
    }

    private static String requireDigest(String value, String reason) {
        if (value == null || !value.matches("[0-9a-f]{64}")) throw denied(reason);
        return value;
    }

    private static String requireNonzeroDigest(String value, String reason) {
        String digest = requireDigest(value, reason);
        if (digest.equals("0".repeat(64))) throw denied(reason);
        return digest;
    }

    private static boolean constantTimeDigestEquals(String left, String right) {
        return left != null && right != null && MessageDigest.isEqual(
                left.getBytes(StandardCharsets.US_ASCII),
                right.getBytes(StandardCharsets.US_ASCII));
    }

    private static boolean constantTimeTextEquals(String left, String right) {
        return left != null && right != null && MessageDigest.isEqual(
                left.getBytes(StandardCharsets.UTF_8),
                right.getBytes(StandardCharsets.UTF_8));
    }

    private static String requirePrefixedDigest(String value, String prefix, String reason) {
        if (value == null || !value.matches(java.util.regex.Pattern.quote(prefix)
                + "[0-9a-f]{64}")) {
            throw denied(reason);
        }
        return value;
    }

    private static String requireBoundedText(String value, int maxBytes, String reason) {
        if (value == null || value.isEmpty()
                || value.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
            throw denied(reason);
        }
        return value;
    }

    private static <T> T requireNonNull(T value, String reason) {
        if (value == null) throw denied(reason);
        return value;
    }

    private static boolean allZero(byte[] value) {
        int aggregate = 0;
        for (byte item : value) aggregate |= item;
        return aggregate == 0;
    }

    private static String sha256(byte[] value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
            char[] output = new char[digest.length * 2];
            char[] alphabet = "0123456789abcdef".toCharArray();
            for (int index = 0; index < digest.length; index++) {
                int item = digest[index] & 0xff;
                output[index * 2] = alphabet[item >>> 4];
                output[index * 2 + 1] = alphabet[item & 0x0f];
            }
            return new String(output);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError("SHA-256 unavailable", impossible);
        }
    }

    private static SecurityException denied(String reason) {
        return new SecurityException(reason);
    }

    interface Clock {
        long wallTimeMillis();
        long elapsedRealtimeMillis();
    }

    interface Entropy {
        byte[] nextBytes(int count);
    }

    interface ChallengeEncoder {
        String encode(PendingOpenUriRequest request, OpenUriLeaseSemanticsV1.Semantics semantics,
                long issuedAtMs, long expiresAtMs, long notBeforeElapsedMs,
                long expiresElapsedMs) throws Exception;
    }

    interface ReceiptValidator {
        String validateAndReturnReceiptId(String exactChallenge, String exactReceipt,
                PendingOpenUriRequest request, OpenUriLeaseSemanticsV1.Semantics semantics)
                throws Exception;
    }

    static final class PendingOpenUriRequest {
        final AgentDescriptor creatorPeerIdentity;
        final String prepareRequestId;
        final String authenticatedTaskBindingSha256;
        final String prepareCanonicalRequestSha256;
        final String workflowId;
        final String taskId;
        final String bootIdSha256;
        final String providerId;
        final String exactHttpsUri;

        PendingOpenUriRequest(AgentDescriptor creatorPeerIdentity, String prepareRequestId,
                String authenticatedTaskBindingSha256,
                String prepareCanonicalRequestSha256, String workflowId, String taskId,
                String bootIdSha256, String exactHttpsUri) {
            if (creatorPeerIdentity == null) {
                throw denied("capability_lease_broker_creator_peer_denied");
            }
            this.creatorPeerIdentity = creatorPeerIdentity;
            this.prepareRequestId = requireIdentifier(
                    prepareRequestId, "capability_lease_broker_prepare_request_denied");
            this.authenticatedTaskBindingSha256 = requireNonzeroDigest(
                    authenticatedTaskBindingSha256,
                    "capability_lease_broker_task_binding_denied");
            this.prepareCanonicalRequestSha256 = requireNonzeroDigest(
                    prepareCanonicalRequestSha256,
                    "capability_lease_broker_prepare_digest_denied");
            this.workflowId = requireIdentifier(
                    workflowId, "capability_lease_broker_workflow_denied");
            this.taskId = requireIdentifier(taskId, "capability_lease_broker_task_denied");
            this.bootIdSha256 = requireNonzeroDigest(
                    bootIdSha256, "capability_lease_broker_boot_denied");
            String providerId = creatorPeerIdentity.providerId();
            if (!AgentDescriptorRegistry.isProductProviderId(providerId)) {
                throw denied("capability_lease_broker_provider_denied");
            }
            this.providerId = providerId;
            this.exactHttpsUri = requireBoundedText(
                    exactHttpsUri, 4 * 1024, "capability_lease_broker_uri_denied");
        }

        String prepareReplayKey() {
            return creatorPeerIdentity.replayKey(prepareRequestId);
        }

        String authenticatedTaskReplayKey() {
            return creatorPeerIdentity.replayKey(
                    "task-binding:" + authenticatedTaskBindingSha256);
        }

        void requireExactBinding(CapabilityLeasePendingStore.Record stored) {
            if (stored == null || creatorPeerIdentity != stored.creatorPeerIdentity
                    || !prepareRequestId.equals(stored.prepareRequestId)
                    || !constantTimeDigestEquals(authenticatedTaskBindingSha256,
                            stored.authenticatedTaskBindingSha256)
                    || !constantTimeDigestEquals(prepareCanonicalRequestSha256,
                            stored.prepareCanonicalRequestSha256)
                    || !workflowId.equals(stored.workflowId)
                    || !taskId.equals(stored.taskId)
                    || !bootIdSha256.equals(stored.bootIdSha256)
                    || !providerId.equals(stored.providerId)
                    || !exactHttpsUri.equals(stored.exactHttpsUri)) {
                throw denied("capability_lease_broker_prepare_binding_conflict");
            }
        }

        private static String requireIdentifier(String value, String reason) {
            String item = requireBoundedText(value, 128, reason);
            if (!item.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) throw denied(reason);
            return item;
        }
    }

    static final class PendingView {
        final String handle;
        final String exactChallenge;
        final String exactHttpsUri;
        final String destinationHost;
        final int subjectUserId;
        final String providerId;
        final long expiresAtMs;
        final long expiresElapsedRealtimeMs;

        PendingView(String handle, String exactChallenge, String exactHttpsUri,
                String destinationHost, int subjectUserId, String providerId, long expiresAtMs,
                long expiresElapsedRealtimeMs) {
            this.handle = handle;
            this.exactChallenge = exactChallenge;
            this.exactHttpsUri = exactHttpsUri;
            this.destinationHost = destinationHost;
            this.subjectUserId = subjectUserId;
            this.providerId = providerId;
            this.expiresAtMs = expiresAtMs;
            this.expiresElapsedRealtimeMs = expiresElapsedRealtimeMs;
        }
    }

    static final class Submission {
        final String status;
        final String receiptId;
        final String submissionOperationId;
        final String statusTupleSha256;

        private Submission(String status, String receiptId,
                String submissionOperationId, String statusTupleSha256) {
            this.status = status;
            this.receiptId = receiptId;
            this.submissionOperationId = submissionOperationId;
            this.statusTupleSha256 = statusTupleSha256;
        }
    }

    static final class SubmissionStatus {
        final String status;
        final String submissionOperationId;
        final String receiptId;
        final String statusTupleSha256;

        private SubmissionStatus(String status, String submissionOperationId,
                String receiptId, String statusTupleSha256) {
            this.status = CapabilityLeaseUiProtocol.requireSubmissionStatus(status);
            this.submissionOperationId =
                    CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                            submissionOperationId);
            this.receiptId = receiptId == null ? "" : receiptId;
            this.statusTupleSha256 =
                    CapabilityLeaseUiProtocol.requireSubmissionStatusTupleSha256(
                            statusTupleSha256);
        }
    }

    static final class ResultStatus {
        final String status;
        final String receiptId;

        private ResultStatus(String status, String receiptId) {
            this.status = status;
            this.receiptId = receiptId == null ? "" : receiptId;
        }
    }

    static final class ReceiptDelivery {
        final String handle;
        final AgentDescriptor creatorPeerIdentity;
        final String leaseId;
        final String receiptId;
        final String receiptSha256;
        final String operationId;
        final String actionBindingSha256;
        final String workflowId;
        final String taskId;
        final String authenticatedTaskBindingSha256;
        final String prepareCanonicalRequestSha256;
        final String bootIdSha256;
        final String providerId;
        final String exactHttpsUri;
        final long expiresAtMs;
        final long expiresElapsedMs;
        final String exactReceipt;

        ReceiptDelivery(String handle, AgentDescriptor creatorPeerIdentity,
                String leaseId, String receiptId, String receiptSha256,
                String operationId, String actionBindingSha256, String workflowId, String taskId,
                String authenticatedTaskBindingSha256,
                String prepareCanonicalRequestSha256, String bootIdSha256,
                String providerId, String exactHttpsUri, long expiresAtMs,
                long expiresElapsedMs, String exactReceipt) {
            this.handle = requireHandle(handle);
            if (creatorPeerIdentity == null) {
                throw denied("capability_lease_broker_creator_peer_denied");
            }
            if (!creatorPeerIdentity.providerId().equals(providerId)) {
                throw denied("capability_lease_broker_creator_provider_conflict");
            }
            this.creatorPeerIdentity = creatorPeerIdentity;
            this.leaseId = leaseId;
            this.receiptId = receiptId;
            this.receiptSha256 = receiptSha256;
            this.operationId = operationId;
            this.actionBindingSha256 = actionBindingSha256;
            this.workflowId = workflowId;
            this.taskId = taskId;
            this.authenticatedTaskBindingSha256 = requireNonzeroDigest(
                    authenticatedTaskBindingSha256,
                    "capability_lease_broker_task_binding_denied");
            this.prepareCanonicalRequestSha256 = requireNonzeroDigest(
                    prepareCanonicalRequestSha256,
                    "capability_lease_broker_prepare_binding_denied");
            this.bootIdSha256 = bootIdSha256;
            this.providerId = providerId;
            this.exactHttpsUri = exactHttpsUri;
            this.expiresAtMs = expiresAtMs;
            this.expiresElapsedMs = expiresElapsedMs;
            this.exactReceipt = exactReceipt;
        }
    }

    private static final class RuntimeRecord {
        CapabilityLeasePendingStore.Record stored;
        final PendingOpenUriRequest request;
        final OpenUriLeaseSemanticsV1.Semantics semantics;

        RuntimeRecord(CapabilityLeasePendingStore.Record stored, PendingOpenUriRequest request,
                OpenUriLeaseSemanticsV1.Semantics semantics) {
            this.stored = stored;
            this.request = request;
            this.semantics = semantics;
        }
    }
}
