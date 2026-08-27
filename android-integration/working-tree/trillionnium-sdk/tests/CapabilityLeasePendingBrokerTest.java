/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.Test;
import org.trillionnium.agentidentity.AgentDescriptor;
import org.trillionnium.capabilitylease.CapabilityLeaseUiProtocol;

public final class CapabilityLeasePendingBrokerTest {
    private static final String BOOT = "b".repeat(64);
    private static final String OTHER_BOOT = "d".repeat(64);
    private static final String RECEIPT_ID = "c".repeat(64);
    private static final AtomicInteger NEXT_PREPARE = new AtomicInteger();

    @Test
    public void createIsDurableBeforeOpaqueHandleReturns() throws Exception {
        Fixture fixture = new Fixture();
        String handle = fixture.broker.createOpenUri(request("https://example.com/"));
        CapabilityLeasePendingBroker.PendingView view = fixture.broker.fetchForIssuer(handle);

        assertTrue(handle.matches("lease-pending-[0-9a-f]{64}"));
        assertFalse(handle.contains("example"));
        assertEquals("https://example.com/", view.exactHttpsUri);
        assertEquals("example.com", view.destinationHost);
        assertEquals("openai-codex", view.providerId);
        assertEquals(1, fixture.store.records.size());
        assertEquals(CapabilityLeasePendingStore.State.PENDING,
                fixture.store.records.get(handle).state);

        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        assertEquals("https://example.com/",
                restarted.fetchForIssuer(handle).exactHttpsUri);
    }

    @Test
    public void createOrReplayReturnsExactHandleBeforeAndAfterRestartWithoutNewEntropy()
            throws Exception {
        Fixture fixture = new Fixture();
        CapabilityLeasePendingBroker.PendingOpenUriRequest request =
                request("https://prepare-replay.example.com/");
        String first = fixture.broker.createOrReplayOpenUri(request);
        int entropyAfterCreate = fixture.entropy.counter.get();

        assertEquals(first, fixture.broker.createOrReplayOpenUri(request));
        assertEquals(entropyAfterCreate, fixture.entropy.counter.get());
        assertEquals(1, fixture.store.records.size());

        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        assertEquals(first, restarted.createOrReplayOpenUri(request));
        assertEquals(entropyAfterCreate, fixture.entropy.counter.get());
        assertEquals(1, fixture.store.records.size());
    }

    @Test
    public void prepareRequestAndTaskBindingDriftConflict()
            throws Exception {
        Fixture fixture = new Fixture();
        String uri = "https://prepare-binding.example.com/";
        String taskBinding = digest("one-shot-task-binding");
        CapabilityLeasePendingBroker.PendingOpenUriRequest original = request(
                AgentDescriptor.CODEX, "prepare-stable", taskBinding,
                digest("canonical-original"), uri);
        fixture.broker.createOrReplayOpenUri(original);

        assertSecurityException(() -> fixture.broker.createOrReplayOpenUri(request(
                AgentDescriptor.CODEX, "prepare-stable", taskBinding,
                digest("canonical-drift"), uri)));
        assertSecurityException(() -> fixture.broker.createOrReplayOpenUri(request(
                AgentDescriptor.CODEX, "prepare-drift", taskBinding,
                digest("canonical-drift-id"), uri)));
        assertEquals(1, fixture.store.records.size());
    }

    @Test
    public void receiptDeliveryReplaysUntilBackendPreparedAck() throws Exception {
        Fixture fixture = new Fixture();
        String handle = fixture.broker.createOpenUri(request("https://example.com/"));
        String submissionOperationId = submissionOperationId(handle, "exact-receipt");
        CapabilityLeasePendingBroker.Submission first =
                fixture.broker.submitFromIssuer(
                        handle, submissionOperationId, "exact-receipt");
        CapabilityLeasePendingBroker.Submission retry =
                fixture.broker.submitFromIssuer(
                        handle, submissionOperationId, "exact-receipt");
        assertEquals(RECEIPT_ID, first.receiptId);
        assertEquals(RECEIPT_ID, retry.receiptId);
        assertEquals("indeterminate", first.status);
        assertSecurityException(() -> fixture.broker.fetchReceiptForBackend(handle));
        fixture.broker.acknowledgeSubmissionDelivery(handle, submissionOperationId,
                RECEIPT_ID, first.statusTupleSha256);

        CapabilityLeasePendingBroker.ReceiptDelivery delivery =
                fixture.broker.fetchReceiptForBackend(handle);
        assertEquals("exact-receipt", delivery.exactReceipt);
        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        assertEquals("exact-receipt",
                restarted.fetchReceiptForBackend(handle).exactReceipt);
        restarted.acknowledgeBackendPrepared(handle, RECEIPT_ID);
        restarted.acknowledgeBackendPrepared(handle, RECEIPT_ID);
        assertEquals("consumed", restarted.pollForUi(handle).status);
        assertSecurityException(() -> restarted.fetchReceiptForBackend(handle));
        assertEquals(null, fixture.store.records.get(handle).exactReceipt);
    }

    @Test
    public void startedSubmitTimeoutLateCommitRestartAndOuterAckGateBackend()
            throws Exception {
        CountDownLatch validatorStarted = new CountDownLatch(1);
        CountDownLatch allowLateCommit = new CountDownLatch(1);
        Fixture fixture = new Fixture((challenge, receipt, request, semantics) -> {
            validatorStarted.countDown();
            boolean released = false;
            while (!released) {
                try {
                    allowLateCommit.await();
                    released = true;
                } catch (InterruptedException ignored) {
                    // Model storage/verification past its last safely cancellable boundary.
                }
            }
            return RECEIPT_ID;
        });
        String handle = fixture.broker.createOpenUri(
                request("https://timeout-quarantine.example.com/"));
        String operationId = submissionOperationId(handle, "exact-receipt");
        CapabilityLeaseBrokerCallExecutor calls = new CapabilityLeaseBrokerCallExecutor(
                2, 1, 8, TimeUnit.SECONDS.toNanos(10), 50L, System::nanoTime);
        try {
            try {
                calls.call(10_123, () -> fixture.broker.submitFromIssuer(
                        handle, operationId, "exact-receipt"));
                throw new AssertionError("expected started submit uncertainty");
            } catch (CapabilityLeaseBrokerCallExecutor.CallException expected) {
                assertEquals(CapabilityLeaseBrokerCallExecutor.ERROR_INDETERMINATE,
                        expected.code);
            }
            assertTrue(validatorStarted.await(1, TimeUnit.SECONDS));
            allowLateCommit.countDown();

            // This synchronized read joins the late worker. Its durable result is quarantined,
            // not delivery-eligible, even though the original caller no longer has a reply.
            assertEquals("indeterminate", fixture.broker.pollForUi(handle).status);
            assertEquals(CapabilityLeasePendingStore.State.INDETERMINATE,
                    fixture.store.records.get(handle).state);
        } finally {
            allowLateCommit.countDown();
            calls.close();
        }

        CapabilityLeasePendingBroker firstRestart = fixture.restart(BOOT);
        assertEquals("indeterminate", firstRestart.pollForUi(handle).status);
        assertSecurityException(() -> firstRestart.fetchReceiptForBackend(handle));
        assertSecurityException(() ->
                firstRestart.acknowledgeBackendPrepared(handle, RECEIPT_ID));

        CapabilityLeaseBrokerServiceFacades beforeDelivery = newFacades(firstRestart);
        CapabilityLeaseBrokerServiceFacades.AuthorizedCall queryAuthorization =
                beforeDelivery.ui.authorizeIssuerQuerySubmission();
        CapabilityLeasePendingBroker.SubmissionStatus queried =
                beforeDelivery.ui.querySubmissionFromIssuer(
                        queryAuthorization, handle, operationId);
        assertEquals("indeterminate", queried.status);
        assertEquals(RECEIPT_ID, queried.receiptId);

        // Simulate system_server dying after replying to the issuer but before AiShell receives
        // and confirms the Activity result. Query alone must never release the receipt.
        CapabilityLeasePendingBroker secondRestart = fixture.restart(BOOT);
        assertEquals("indeterminate", secondRestart.pollForUi(handle).status);
        assertSecurityException(() -> secondRestart.fetchReceiptForBackend(handle));

        CapabilityLeaseBrokerServiceFacades afterDelivery = newFacades(secondRestart);
        CapabilityLeaseBrokerServiceFacades.AuthorizedCall deliveryAuthorization =
                afterDelivery.ui.authorizeUiAcknowledgeSubmission();
        CapabilityLeasePendingBroker.SubmissionStatus released =
                afterDelivery.ui.acknowledgeSubmissionDelivery(deliveryAuthorization,
                        handle, operationId, RECEIPT_ID, queried.statusTupleSha256);
        assertEquals("submitted", released.status);
        assertEquals("exact-receipt",
                afterDelivery.localSystemApi.fetchReceipt(handle).exactReceipt);
        afterDelivery.localSystemApi.acknowledgePrepared(handle, RECEIPT_ID);
        assertEquals("consumed", secondRestart.pollForUi(handle).status);
    }

    @Test
    public void expiryCancelAndPriorBootAreDurablyTerminal() throws Exception {
        Fixture fixture = new Fixture();
        String expiring = fixture.broker.createOpenUri(request("https://example.com/"));
        fixture.clock.elapsed += 30_000L;
        assertEquals("expired", fixture.broker.pollForUi(expiring).status);
        assertEquals(CapabilityLeasePendingStore.State.EXPIRED,
                fixture.store.records.get(expiring).state);

        fixture.clock.elapsed += 1L;
        String submitted = fixture.broker.createOpenUri(request("https://openai.com/"));
        fixture.broker.submitFromIssuer(submitted,
                submissionOperationId(submitted, "exact-receipt"), "exact-receipt");
        fixture.clock.elapsed += 30_000L;
        assertEquals("expired", fixture.broker.pollForUi(submitted).status);
        assertEquals(null, fixture.store.records.get(submitted).exactReceipt);

        fixture.clock.elapsed += 1L;
        String canceled = fixture.broker.createOpenUri(request("https://openai.com/"));
        fixture.broker.cancelFromIssuer(canceled);
        fixture.broker.cancelFromIssuer(canceled);
        assertEquals("canceled", fixture.restart(BOOT).pollForUi(canceled).status);

        Fixture priorBoot = new Fixture();
        String pending = priorBoot.broker.createOpenUri(request("https://example.com/"));
        CapabilityLeasePendingBroker afterReboot = priorBoot.restart(OTHER_BOOT);
        assertEquals("expired", afterReboot.pollForUi(pending).status);
        assertSecurityException(() -> afterReboot.fetchForIssuer(pending));
    }

    @Test
    public void storeFailureNeverPublishesOrAdvancesMemory() throws Exception {
        Fixture fixture = new Fixture();
        fixture.store.failNext = true;
        assertIOException(() -> fixture.broker.createOpenUri(request("https://example.com/")));
        assertEquals(0, fixture.broker.retainedCountForTest());

        String handle = fixture.broker.createOpenUri(request("https://example.com/"));
        fixture.store.failNext = true;
        assertIOException(() -> fixture.broker.submitFromIssuer(handle,
                submissionOperationId(handle, "exact-receipt"), "exact-receipt"));
        assertEquals("pending", fixture.broker.pollForUi(handle).status);
    }

    @Test
    public void committedReplacementFailureReconcilesThenPoisonsUntilRestart()
            throws Exception {
        Fixture fixture = new Fixture();
        String handle = fixture.broker.createOpenUri(request("https://replace.example.org/"));
        fixture.store.replaceCommitThenFailNext = true;

        assertIOException(() -> fixture.broker.submitFromIssuer(handle,
                submissionOperationId(handle, "exact-receipt"), "exact-receipt"));
        assertTrue(fixture.broker.poisonedForTest());
        assertEquals(CapabilityLeasePendingStore.State.INDETERMINATE,
                fixture.store.records.get(handle).state);
        assertIOException(() -> fixture.broker.pollForUi(handle));

        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        assertFalse(restarted.poisonedForTest());
        assertEquals("indeterminate", restarted.pollForUi(handle).status);
        assertSecurityException(() -> restarted.fetchReceiptForBackend(handle));
    }

    @Test
    public void committedCreateFailureReconcilesThenPoisonsUntilRestart() throws Exception {
        Fixture fixture = new Fixture();
        fixture.store.createCommitThenFailNext = true;

        assertIOException(() -> fixture.broker.createOpenUri(
                request("https://create-commit.example.org/")));
        assertTrue(fixture.broker.poisonedForTest());
        assertEquals(1, fixture.broker.retainedCountForTest());
        assertEquals(1, fixture.store.records.size());
        String handle = fixture.store.records.keySet().iterator().next();
        assertIOException(() -> fixture.broker.pollForUi(handle));

        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        assertFalse(restarted.poisonedForTest());
        assertEquals("https://create-commit.example.org/",
                restarted.fetchForIssuer(handle).exactHttpsUri);
    }

    @Test
    public void collisionInvalidDraftAndWrongAckFailClosed() throws Exception {
        Fixture collision = new Fixture();
        collision.entropy.fixed = true;
        String handle = collision.broker.createOpenUri(request("https://example.com/"));
        assertSecurityException(
                () -> collision.broker.createOpenUri(request("https://openai.com/")));
        assertSecurityException(
                () -> collision.broker.createOpenUri(request("http://example.com/")));
        assertSecurityException(
                () -> collision.broker.createOpenUri(request("https://localhost/")));
        CapabilityLeasePendingBroker.Submission submitted =
                collision.broker.submitFromIssuer(handle,
                        submissionOperationId(handle, "exact-receipt"), "exact-receipt");
        collision.broker.acknowledgeSubmissionDelivery(handle,
                submitted.submissionOperationId, RECEIPT_ID, submitted.statusTupleSha256);
        collision.broker.fetchReceiptForBackend(handle);
        assertSecurityException(() -> collision.broker.acknowledgeBackendPrepared(
                handle, "e".repeat(64)));
    }

    @Test
    public void retiredEntropyCollisionIsRejectedBeforeStoreWriteAfterRestart()
            throws Exception {
        Fixture fixture = new Fixture();
        fixture.entropy.fixed = true;
        fixture.entropy.fixedValue = 255;
        CapabilityLeasePendingBroker.PendingOpenUriRequest firstRequest = request(
                "https://retired-entropy-first.example.org/");
        String firstHandle = fixture.broker.createOrReplayOpenUri(firstRequest);
        fixture.broker.cancelFromIssuer(firstHandle);
        fixture.entropy.fixed = false;
        for (int index = 1; index < CapabilityLeasePendingBroker.MAX_PENDING; index++) {
            fixture.broker.createOrReplayOpenUri(request(
                    "https://retired-entropy-fill-" + index + ".example.org/"));
        }
        fixture.broker.createOrReplayOpenUri(request(
                "https://retired-entropy-overflow.example.org/"));
        assertEquals(1, fixture.broker.retiredCountForTest());

        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        fixture.entropy.fixed = true;
        fixture.entropy.fixedValue = 255;
        int durableBefore = fixture.store.records.size();
        assertSecurityException(() -> restarted.createOrReplayOpenUri(request(
                "https://retired-entropy-collision.example.org/")));
        assertEquals(durableBefore, fixture.store.records.size());
        assertEquals(firstHandle, fixture.store.retired.keySet().iterator().next());
    }

    @Test
    public void postCreateIndexDriftReturnsTypedCommittedUncertaintyAndPoisons()
            throws Exception {
        Fixture fixture = new Fixture();
        String sharedTaskBinding = digest("post-create-shared-task-binding");
        CapabilityLeasePendingBroker.PendingOpenUriRequest outer = request(
                AgentDescriptor.CODEX, "prepare-post-create-outer", sharedTaskBinding,
                digest("post-create-outer-canonical"),
                "https://post-create-outer.example.org/");
        CapabilityLeasePendingBroker.PendingOpenUriRequest reentrant = request(
                AgentDescriptor.CODEX, "prepare-post-create-reentrant", sharedTaskBinding,
                digest("post-create-reentrant-canonical"),
                "https://post-create-reentrant.example.org/");
        fixture.store.afterCreate = () ->
                fixture.broker.createOrReplayOpenUri(reentrant);

        try {
            fixture.broker.createOrReplayOpenUri(outer);
            throw new AssertionError("expected committed create uncertainty");
        } catch (CapabilityLeasePendingStore.CreateCommittedException expected) {
            assertEquals(CapabilityLeasePendingStore.State.PENDING, expected.record.state);
        }
        assertTrue(fixture.broker.poisonedForTest());
        assertEquals(2, fixture.store.records.size());
        assertIOException(() -> fixture.broker.createOrReplayOpenUri(outer));
    }

    @Test
    public void fullPermanentRetirementHistoryHoldsCapacityWithoutDeletingReplayIdentity()
            throws Exception {
        assertEquals(
                "source_only_pending_retirement_capacity_hold_no_authenticated_rollup_v1",
                CapabilityLeasePendingBroker.RETIREMENT_ACTIVATION_HOLD);
        Fixture fixture = new Fixture();
        CapabilityLeasePendingStore.CompactionWatermark watermark =
                CapabilityLeasePendingStore.CompactionWatermark.genesis();
        for (int index = 1;
                index <= CapabilityLeasePendingBroker.MAX_RETIRED_TOMBSTONES; index++) {
            CapabilityLeasePendingStore.Record record = retiredCapacityRecord(index);
            watermark = watermark.next(record);
            CapabilityLeasePendingStore.RetirementTombstone tombstone =
                    CapabilityLeasePendingStore.RetirementTombstone.from(record, watermark);
            fixture.store.retired.put(tombstone.handle, tombstone);
        }
        fixture.store.watermark = watermark;
        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        assertEquals(CapabilityLeasePendingBroker.MAX_RETIRED_TOMBSTONES,
                restarted.retiredCountForTest());
        for (int index = 0; index < CapabilityLeasePendingBroker.MAX_PENDING; index++) {
            String handle = restarted.createOrReplayOpenUri(request(
                    "https://retirement-wall-live-" + index + ".example.org/"));
            restarted.cancelFromIssuer(handle);
        }
        int compactCalls = fixture.store.compactCalls;
        assertSecurityException(() -> restarted.createOrReplayOpenUri(request(
                "https://retirement-wall-overflow.example.org/")));
        assertEquals(compactCalls, fixture.store.compactCalls);
        assertEquals(CapabilityLeasePendingBroker.MAX_RETIRED_TOMBSTONES,
                fixture.store.retired.size());
        assertEquals(CapabilityLeasePendingBroker.MAX_PENDING,
                fixture.store.records.size());
    }

    @Test
    public void zeroBootDigestIsRejectedAtBrokerAndRequestBoundaries() throws Exception {
        Fixture fixture = new Fixture();
        assertSecurityException(() -> fixture.newBroker("0".repeat(64)));
        assertSecurityException(() -> new CapabilityLeasePendingBroker.PendingOpenUriRequest(
                AgentDescriptor.CODEX, "prepare-zero-boot", digest("zero-boot-binding"),
                digest("zero-boot-canonical"), "workflow-1", "task-1", "0".repeat(64),
                "https://zero-boot.example.org/"));
    }

    @Test
    public void roleFacadesVerifyEveryExternalCallAndKeepSystemApiLocal() throws Exception {
        Fixture fixture = new Fixture();
        List<CapabilityLeaseBrokerCallerPolicy.Operation> verified = new ArrayList<>();
        CapabilityLeaseBrokerServiceFacades facades =
                new CapabilityLeaseBrokerServiceFacades(fixture.broker, operation -> {
                    verified.add(operation);
                    CapabilityLeaseBrokerCallerPolicy.Role role = operation.requiredRole;
                    String packageName;
                    String context;
                    switch (role) {
                        case AI_SHELL:
                            packageName = "org.trillionnium.aishell";
                            context = "u:r:trillionnium_aishell:s0";
                            break;
                        case ISSUER:
                            packageName = "org.trillionnium.capabilitylease";
                            context = "u:r:trillionnium_capability_lease_issuer:s0";
                            break;
                        case ACCESSIBILITY:
                            packageName = "org.trillionnium.agentaccessibility";
                            context = "u:r:trillionnium_agent_accessibility:s0";
                            break;
                        default:
                            throw new AssertionError(role);
                    }
                    CapabilityLeaseBrokerCallerPolicy.CallerPin pin =
                            new CapabilityLeaseBrokerCallerPolicy.CallerPin(
                                    role, packageName, "a".repeat(64), context);
                    return CapabilityLeaseBrokerCallerPolicy.verify(operation, pin,
                            new CapabilityLeaseBrokerCallerPolicy.ObservedCaller(
                                    10_123, 123, 0, true, packageName, 1,
                                    "a".repeat(64), context));
                });

        String external = facades.backend.createOpenUri(request("https://example.com/"));
        facades.ui.poll(external);
        CapabilityLeaseBrokerServiceFacades.AuthorizedCall fetchAuthorization =
                facades.ui.authorizeIssuerFetch();
        facades.ui.fetchForIssuer(fetchAuthorization, external);
        CapabilityLeaseBrokerServiceFacades.AuthorizedCall submitAuthorization =
                facades.ui.authorizeIssuerSubmit();
        String externalOperationId = submissionOperationId(external, "exact-receipt");
        CapabilityLeasePendingBroker.Submission externalSubmission =
                facades.ui.submitFromIssuer(submitAuthorization, external,
                        externalOperationId, "exact-receipt");
        CapabilityLeaseBrokerServiceFacades.AuthorizedCall queryAuthorization =
                facades.ui.authorizeIssuerQuerySubmission();
        facades.ui.querySubmissionFromIssuer(
                queryAuthorization, external, externalOperationId);
        CapabilityLeaseBrokerServiceFacades.AuthorizedCall deliveryAuthorization =
                facades.ui.authorizeUiAcknowledgeSubmission();
        facades.ui.acknowledgeSubmissionDelivery(deliveryAuthorization, external,
                externalOperationId, RECEIPT_ID,
                externalSubmission.statusTupleSha256);
        facades.backend.fetchReceipt(external);
        facades.backend.acknowledgePrepared(external, RECEIPT_ID);
        int verifiedBeforeLocal = verified.size();
        CapabilityLeasePendingBroker.PendingOpenUriRequest localRequest =
                request("https://openai.com/");
        String localHandle = facades.localSystemApi.createOpenUri(localRequest);
        CapabilityLeasePendingBroker.PendingView localPrepared =
                facades.localSystemApi.prepareOpenUri(localRequest);
        assertEquals(localHandle, localPrepared.handle);
        assertEquals(fixture.clock.wall + CapabilityLeasePendingBroker.MAX_TTL_MS,
                localPrepared.expiresAtMs);
        assertEquals(fixture.clock.elapsed + CapabilityLeasePendingBroker.MAX_TTL_MS,
                localPrepared.expiresElapsedRealtimeMs);
        assertEquals(verifiedBeforeLocal, verified.size());
        assertEquals(Arrays.asList(
                CapabilityLeaseBrokerCallerPolicy.Operation.BACKEND_CREATE,
                CapabilityLeaseBrokerCallerPolicy.Operation.UI_POLL,
                CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_FETCH,
                CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_SUBMIT,
                CapabilityLeaseBrokerCallerPolicy.Operation.ISSUER_QUERY_SUBMISSION,
                CapabilityLeaseBrokerCallerPolicy.Operation.UI_ACK_SUBMISSION,
                CapabilityLeaseBrokerCallerPolicy.Operation.BACKEND_FETCH_RECEIPT,
                CapabilityLeaseBrokerCallerPolicy.Operation.BACKEND_ACK_PREPARED), verified);
    }

    @Test
    public void issuerAuthorizationIsOperationBoundAndSingleUse() throws Exception {
        Fixture fixture = new Fixture();
        CapabilityLeaseBrokerServiceFacades facades =
                new CapabilityLeaseBrokerServiceFacades(fixture.broker, operation -> {
                    CapabilityLeaseBrokerCallerPolicy.CallerPin pin =
                            new CapabilityLeaseBrokerCallerPolicy.CallerPin(
                                    operation.requiredRole,
                                    "org.trillionnium.capabilitylease",
                                    "a".repeat(64),
                                    "u:r:trillionnium_capability_lease_issuer:s0");
                    return CapabilityLeaseBrokerCallerPolicy.verify(operation, pin,
                            new CapabilityLeaseBrokerCallerPolicy.ObservedCaller(
                                    10_123, 123, 0, true, pin.packageName, 1,
                                    pin.signerSha256, pin.selinuxContext));
                });
        String handle = fixture.broker.createOpenUri(request("https://example.com/"));
        CapabilityLeaseBrokerServiceFacades.AuthorizedCall fetch =
                facades.ui.authorizeIssuerFetch();
        facades.ui.fetchForIssuer(fetch, handle);
        assertSecurityException(() -> facades.ui.fetchForIssuer(fetch, handle));

        CapabilityLeaseBrokerServiceFacades.AuthorizedCall submit =
                facades.ui.authorizeIssuerSubmit();
        assertSecurityException(() -> facades.ui.cancelFromIssuer(submit, handle));
    }

    @Test
    public void terminalAndExpiredRecordsRemainReplayBoundAcrossRestartWithoutCompaction()
            throws Exception {
        Fixture fixture = new Fixture();
        String taskBinding = digest("terminal-replay-binding");
        CapabilityLeasePendingBroker.PendingOpenUriRequest canceledRequest = request(
                AgentDescriptor.CODEX, "prepare-terminal-stable", taskBinding,
                digest("terminal-canonical"), "https://terminal.example.org/");
        String canceled = fixture.broker.createOrReplayOpenUri(canceledRequest);
        fixture.broker.cancelFromIssuer(canceled);
        CapabilityLeasePendingBroker.PendingOpenUriRequest expiredRequest = request(
                AgentDescriptor.CODEX, "prepare-expired-stable", digest("expired-binding"),
                digest("expired-canonical"), "https://expired.example.org/");
        String expired = fixture.broker.createOrReplayOpenUri(expiredRequest);
        fixture.clock.elapsed += CapabilityLeasePendingBroker.MAX_TTL_MS;
        assertEquals("expired", fixture.broker.pollForUi(expired).status);

        assertEquals(canceled, fixture.broker.createOrReplayOpenUri(canceledRequest));
        assertEquals(expired, fixture.broker.createOrReplayOpenUri(expiredRequest));
        assertEquals(2, fixture.broker.retainedCountForTest());
        assertEquals(0, fixture.store.compactCalls);
        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        assertEquals(canceled, restarted.createOrReplayOpenUri(canceledRequest));
        assertEquals(expired, restarted.createOrReplayOpenUri(expiredRequest));
        assertSecurityException(() -> restarted.createOrReplayOpenUri(request(
                AgentDescriptor.CODEX, "prepare-terminal-drift", taskBinding,
                digest("terminal-canonical-drift"), "https://terminal.example.org/")));
        assertEquals(2, fixture.store.records.size());
        assertEquals(0, fixture.store.compactCalls);
    }

    @Test
    public void fullTerminalCapacityRetiresWithPermanentExactReplayTombstone()
            throws Exception {
        Fixture fixture = new Fixture();
        List<CapabilityLeasePendingBroker.PendingOpenUriRequest> requests = new ArrayList<>();
        List<String> handles = new ArrayList<>();
        for (int index = 0; index < CapabilityLeasePendingBroker.MAX_PENDING; index++) {
            CapabilityLeasePendingBroker.PendingOpenUriRequest candidate = request(
                    AgentDescriptor.CODEX, "prepare-capacity-" + index,
                    digest("capacity-binding-" + index),
                    digest("capacity-canonical-" + index),
                    "https://capacity.example.org/");
            String handle = fixture.broker.createOrReplayOpenUri(candidate);
            fixture.broker.cancelFromIssuer(handle);
            requests.add(candidate);
            handles.add(handle);
        }
        int entropyAtCapacity = fixture.entropy.counter.get();
        CapabilityLeasePendingBroker.PendingOpenUriRequest unseen = request(
                AgentDescriptor.CODEX, "prepare-capacity-overflow",
                digest("capacity-binding-overflow"), digest("capacity-canonical-overflow"),
                "https://capacity.example.org/");

        String unseenHandle = fixture.broker.createOrReplayOpenUri(unseen);
        assertSecurityException(() -> fixture.broker.createOrReplayOpenUri(request(
                AgentDescriptor.CODEX, "prepare-capacity-drift",
                digest("capacity-binding-0"), digest("capacity-canonical-drift"),
                "https://capacity.example.org/")));
        for (int index = 0; index < requests.size(); index++) {
            assertEquals(handles.get(index),
                    fixture.broker.createOrReplayOpenUri(requests.get(index)));
        }
        assertEquals(unseenHandle, fixture.broker.createOrReplayOpenUri(unseen));
        assertEquals(entropyAtCapacity + 1, fixture.entropy.counter.get());
        assertEquals(CapabilityLeasePendingBroker.MAX_PENDING,
                fixture.broker.retainedCountForTest());
        assertEquals(1, fixture.broker.retiredCountForTest());
        assertEquals(1, fixture.store.compactCalls);
        assertEquals(1, fixture.store.retired.size());
        assertEquals(1L, fixture.store.watermark.epoch);
        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        for (int index = 0; index < requests.size(); index++) {
            assertEquals(handles.get(index),
                    restarted.createOrReplayOpenUri(requests.get(index)));
        }
        assertEquals(unseenHandle, restarted.createOrReplayOpenUri(unseen));
        assertSecurityException(() -> restarted.createOrReplayOpenUri(request(
                AgentDescriptor.CODEX, "prepare-capacity-drift-after-restart",
                digest("capacity-binding-0"), digest("capacity-canonical-drift-after-restart"),
                "https://capacity.example.org/")));
        assertEquals(1, restarted.retiredCountForTest());
        assertEquals(1, fixture.store.compactCalls);
    }

    @Test
    public void watermarkWithoutPermanentRetirementTombstoneFailsRestoreClosed()
            throws Exception {
        Fixture fixture = new Fixture();
        String handle = fixture.broker.createOpenUri(request("https://historical.example.org/"));
        fixture.broker.cancelFromIssuer(handle);
        fixture.store.watermark = fixture.store.watermark.next(fixture.store.records.get(handle));
        fixture.store.loaded = false;
        assertIOException(() -> fixture.newBroker(BOOT));
    }

    @Test
    public void committedRetirementFailurePoisonsUntilRestartAndKeepsExactReplay()
            throws Exception {
        Fixture fixture = new Fixture();
        List<CapabilityLeasePendingBroker.PendingOpenUriRequest> requests = new ArrayList<>();
        List<String> handles = new ArrayList<>();
        for (int index = 0; index < CapabilityLeasePendingBroker.MAX_PENDING; index++) {
            CapabilityLeasePendingBroker.PendingOpenUriRequest candidate = request(
                    AgentDescriptor.CODEX, "prepare-retirement-commit-" + index,
                    digest("retirement-commit-binding-" + index),
                    digest("retirement-commit-canonical-" + index),
                    "https://retirement-commit.example.org/");
            String handle = fixture.broker.createOrReplayOpenUri(candidate);
            fixture.broker.cancelFromIssuer(handle);
            requests.add(candidate);
            handles.add(handle);
        }
        fixture.store.compactCommitThenFailNext = true;

        assertIOException(() -> fixture.broker.createOrReplayOpenUri(request(
                AgentDescriptor.CODEX, "prepare-retirement-overflow",
                digest("retirement-overflow-binding"),
                digest("retirement-overflow-canonical"),
                "https://retirement-commit.example.org/")));
        assertTrue(fixture.broker.poisonedForTest());
        assertEquals(1, fixture.broker.retiredCountForTest());
        assertIOException(() -> fixture.broker.createOrReplayOpenUri(requests.get(0)));

        CapabilityLeasePendingBroker restarted = fixture.restart(BOOT);
        assertFalse(restarted.poisonedForTest());
        assertEquals(handles.get(0), restarted.createOrReplayOpenUri(requests.get(0)));
        assertEquals(1, restarted.retiredCountForTest());
        assertEquals(CapabilityLeasePendingBroker.MAX_PENDING - 1,
                restarted.retainedCountForTest());
    }

    @Test
    public void retirementCodecRejectsCorruptionAndTrailingBytes() throws Exception {
        Fixture fixture = new Fixture();
        String handle = fixture.broker.createOpenUri(request(
                "https://retirement-codec.example.org/"));
        fixture.broker.cancelFromIssuer(handle);
        CapabilityLeasePendingStore.Record record = fixture.store.records.get(handle);
        CapabilityLeasePendingStore.CompactionWatermark watermark =
                fixture.store.watermark.next(record);
        CapabilityLeasePendingStore.RetirementTombstone tombstone =
                CapabilityLeasePendingStore.RetirementTombstone.from(record, watermark);
        byte[] encoded = CapabilityLeasePendingRetirementCodec.encode(tombstone);

        CapabilityLeasePendingStore.RetirementTombstone decoded =
                CapabilityLeasePendingRetirementCodec.decode(encoded);
        assertEquals(handle, decoded.handle);
        assertEquals(record.prepareRequestId, decoded.prepareRequestId);
        assertEquals(watermark.rootSha256, decoded.rootSha256);

        byte[] corrupted = encoded.clone();
        corrupted[corrupted.length - 1] ^= 1;
        assertIOException(() -> CapabilityLeasePendingRetirementCodec.decode(corrupted));
        assertIOException(() -> CapabilityLeasePendingRetirementCodec.decode(
                Arrays.copyOf(encoded, encoded.length + 1)));
    }

    private static CapabilityLeasePendingBroker.PendingOpenUriRequest request(String uri) {
        int sequence = NEXT_PREPARE.incrementAndGet();
        String binding = digest("binding:" + sequence + ':' + uri);
        return request(AgentDescriptor.CODEX,
                "prepare-" + binding.substring(0, 32), binding,
                digest("canonical:" + sequence + ':' + uri), uri);
    }

    private static CapabilityLeasePendingBroker.PendingOpenUriRequest request(
            AgentDescriptor peer, String requestId, String taskBinding,
            String canonicalDigest, String uri) {
        return new CapabilityLeasePendingBroker.PendingOpenUriRequest(
                peer, requestId, taskBinding, canonicalDigest,
                "workflow-1", "task-1", BOOT, uri);
    }

    private static String digest(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder encoded = new StringBuilder(64);
            for (byte item : bytes) encoded.append(String.format("%02x", item & 0xff));
            return encoded.toString();
        } catch (Exception impossible) {
            throw new AssertionError(impossible);
        }
    }

    private static String submissionOperationId(String handle, String receipt) {
        return CapabilityLeaseUiProtocol.deriveSubmissionOperationId(handle, receipt);
    }

    private static CapabilityLeaseBrokerServiceFacades newFacades(
            CapabilityLeasePendingBroker broker) {
        return new CapabilityLeaseBrokerServiceFacades(broker, operation -> {
            CapabilityLeaseBrokerCallerPolicy.Role role = operation.requiredRole;
            String packageName;
            String context;
            switch (role) {
                case AI_SHELL:
                    packageName = "org.trillionnium.aishell";
                    context = "u:r:trillionnium_aishell:s0";
                    break;
                case ISSUER:
                    packageName = "org.trillionnium.capabilitylease";
                    context = "u:r:trillionnium_capability_lease_issuer:s0";
                    break;
                case ACCESSIBILITY:
                    packageName = "org.trillionnium.agentaccessibility";
                    context = "u:r:trillionnium_agent_accessibility:s0";
                    break;
                default:
                    throw new AssertionError(role);
            }
            CapabilityLeaseBrokerCallerPolicy.CallerPin pin =
                    new CapabilityLeaseBrokerCallerPolicy.CallerPin(
                            role, packageName, "a".repeat(64), context);
            return CapabilityLeaseBrokerCallerPolicy.verify(operation, pin,
                    new CapabilityLeaseBrokerCallerPolicy.ObservedCaller(
                            10_123, 123, 0, true, packageName, 1,
                            "a".repeat(64), context));
        });
    }

    private static CapabilityLeasePendingStore.Record retiredCapacityRecord(int index) {
        return new CapabilityLeasePendingStore.Record(
                "lease-pending-" + hex(index, 64), AgentDescriptor.CODEX,
                "prepare-retired-capacity-" + index,
                hex(index + 10_000L, 64), hex(index + 20_000L, 64),
                "workflow-retired-capacity", "task-retired-capacity-" + index,
                BOOT, AgentDescriptor.CODEX.providerId(),
                "https://retired-capacity-" + index + ".example.org/",
                "retired-capacity-challenge-" + index,
                1_000_000L, 1_030_000L, 10_000L, 40_000L,
                CapabilityLeasePendingStore.State.CANCELED, null, null, null);
    }

    private static String hex(long value, int width) {
        return String.format("%0" + width + "x", value);
    }

    private static void assertSecurityException(ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
        } catch (SecurityException expected) {
            return;
        }
        throw new AssertionError("expected SecurityException");
    }

    private static void assertIOException(ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
        } catch (IOException expected) {
            return;
        }
        throw new AssertionError("expected IOException");
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private static final class Fixture {
        final TestClock clock = new TestClock();
        final TestEntropy entropy = new TestEntropy();
        final MemoryStore store = new MemoryStore();
        final CapabilityLeasePendingBroker.ReceiptValidator receiptValidator;
        CapabilityLeasePendingBroker broker;

        Fixture() {
            this((challenge, receipt, request, semantics) -> RECEIPT_ID);
        }

        Fixture(CapabilityLeasePendingBroker.ReceiptValidator receiptValidator) {
            this.receiptValidator = receiptValidator;
            try {
                broker = newBroker(BOOT);
            } catch (IOException error) {
                throw new AssertionError(error);
            }
        }

        CapabilityLeasePendingBroker restart(String boot) throws IOException {
            store.loaded = false;
            store.poisoned = false;
            broker = newBroker(boot);
            return broker;
        }

        private CapabilityLeasePendingBroker newBroker(String boot) throws IOException {
            return new CapabilityLeasePendingBroker(
                        clock,
                        entropy,
                        (request, semantics, issuedAt, expiresAt,
                                notBeforeElapsed, expiresElapsed) ->
                                "{\"action_binding_sha256\":\""
                                        + semantics.actionBindingSha256
                                        + "\",\"action_kind\":\"" + semantics.actionKind
                                        + "\",\"lease_id\":\"lease-" + "a".repeat(64)
                                        + "\",\"operation_id\":\"" + semantics.operationId
                                        + "\",\"risk_class\":\"" + semantics.riskClass
                                        + "\",\"summary\":\"Open exact HTTPS URI once\"}",
                        receiptValidator,
                        store,
                        boot);
        }
    }

    private static final class TestClock implements CapabilityLeasePendingBroker.Clock {
        long wall = 1_000_000L;
        long elapsed = 10_000L;

        @Override public long wallTimeMillis() { return wall; }
        @Override public long elapsedRealtimeMillis() { return elapsed; }
    }

    private static final class TestEntropy implements CapabilityLeasePendingBroker.Entropy {
        final AtomicInteger counter = new AtomicInteger(1);
        boolean fixed;
        int fixedValue = 7;

        @Override public byte[] nextBytes(int count) {
            byte[] value = new byte[count];
            Arrays.fill(value, (byte) (fixed ? fixedValue : counter.getAndIncrement()));
            return value;
        }
    }

    private static final class MemoryStore implements CapabilityLeasePendingStore {
        final Map<String, Record> records = new LinkedHashMap<>();
        final Map<String, RetirementTombstone> retired = new LinkedHashMap<>();
        CompactionWatermark watermark = CompactionWatermark.genesis();
        boolean loaded;
        boolean failNext;
        boolean createCommitThenFailNext;
        boolean replaceCommitThenFailNext;
        boolean compactCommitThenFailNext;
        int compactCalls;
        boolean poisoned;
        ThrowingRunnable afterCreate;

        @Override public Map<String, Record> load() throws IOException {
            if (loaded) throw new IOException("duplicate load");
            loaded = true;
            return new LinkedHashMap<>(records);
        }

        @Override public void create(Record record) throws IOException {
            maybeFail();
            if (records.putIfAbsent(record.handle, record) != null) {
                throw new IOException("duplicate");
            }
            if (afterCreate != null) {
                ThrowingRunnable callback = afterCreate;
                afterCreate = null;
                try {
                    callback.run();
                } catch (IOException failure) {
                    throw failure;
                } catch (Exception failure) {
                    throw new IOException("post-create callback failed", failure);
                }
            }
            if (createCommitThenFailNext) {
                createCommitThenFailNext = false;
                poisoned = true;
                throw new CreateCommittedException(
                        record, new IOException("post-create-commit injected"));
            }
        }

        @Override public void replace(Record expected, Record replacement) throws IOException {
            maybeFail();
            if (records.get(expected.handle) != expected) throw new IOException("drift");
            replacement.requireValidTransitionFrom(expected);
            records.put(expected.handle, replacement);
            if (replaceCommitThenFailNext) {
                replaceCommitThenFailNext = false;
                poisoned = true;
                throw new ReplacementCommittedException(
                        replacement, new IOException("post-replacement-commit injected"));
            }
        }

        @Override public CompactionWatermark loadCompactionWatermark() throws IOException {
            if (!loaded) throw new IOException("not loaded");
            return watermark;
        }

        @Override public Map<String, RetirementTombstone> loadRetirementTombstones()
                throws IOException {
            if (!loaded) throw new IOException("not loaded");
            return new LinkedHashMap<>(retired);
        }

        @Override public void compactTerminal(Record expected, CompactionWatermark replacement)
                throws IOException {
            compactCalls++;
            maybeFail();
            if (records.get(expected.handle) != expected) throw new IOException("drift");
            replacement.requireValidSuccessor(watermark, expected);
            RetirementTombstone tombstone = RetirementTombstone.from(expected, replacement);
            if (retired.putIfAbsent(tombstone.handle, tombstone) != null) {
                throw new IOException("duplicate retirement");
            }
            watermark = replacement;
            records.remove(expected.handle);
            if (compactCommitThenFailNext) {
                compactCommitThenFailNext = false;
                poisoned = true;
                throw new CompactionCommittedException(
                        replacement, new IOException("post-compaction-commit injected"));
            }
        }

        @Override public boolean isPoisoned() { return poisoned; }

        private void maybeFail() throws IOException {
            if (failNext) {
                failNext = false;
                throw new IOException("injected");
            }
        }
    }
}
