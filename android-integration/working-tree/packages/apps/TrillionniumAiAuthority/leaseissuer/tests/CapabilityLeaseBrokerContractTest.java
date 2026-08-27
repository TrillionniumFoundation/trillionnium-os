/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.capabilitylease;

import static org.junit.Assert.assertEquals;

import org.json.JSONObject;
import org.junit.Test;

public final class CapabilityLeaseBrokerContractTest {
    private static final String HANDLE = "lease-pending-" + "a".repeat(64);

    @Test
    public void opaqueHandleAndBrokerViewsAreStrict() {
        assertEquals(HANDLE, LeasePendingHandle.requireExact(HANDLE));
        assertSecurityException(() -> LeasePendingHandle.requireExact("lease-pending-example.com"));
        assertSecurityException(() -> LeasePendingHandle.requireExact(
                "lease-pending-" + "A".repeat(64)));

        CapabilityLeaseBrokerClient.PendingChallenge view = view("https://example.com/");
        view.requireSameImmutableView(view("https://example.com/"));
        assertSecurityException(() -> view.requireSameImmutableView(view("https://openai.com/")));
        assertSecurityException(() -> new CapabilityLeaseBrokerClient.PendingChallenge(
                "wrong", "{}", "https://example.com/", "example.com", 0,
                "openai-codex", 1_030_000L, 40_000L));
        assertSecurityException(() -> new CapabilityLeaseBrokerClient.PendingChallenge(
                CapabilityLeaseBrokerClient.PendingChallenge.VIEW_SCHEMA,
                "{}", "https://example.com/", "example.com", 0,
                "retired-provider", 1_030_000L, 40_000L));
    }

    @Test
    public void presentationBindsExactUriProviderUserAndExpiry() throws Exception {
        CapabilityLeaseBrokerClient.PendingChallenge view = view("https://example.com/");
        JSONObject challenge = new JSONObject();
        challenge.put("tool", "system_api");
        challenge.put("action_kind", "open_uri");
        challenge.put("risk_class", "critical_effect");
        challenge.put("subject_user_id", 0);
        challenge.put("provider_id", "openai-codex");
        challenge.put("max_uses", 1);
        challenge.put("expires_at_ms", 1_030_000L);
        challenge.put("expires_elapsed_realtime_ms", 40_000L);
        challenge.put("user_visible_summary",
                "Open exact HTTPS URI once for Android user 0:\nhttps://example.com/");

        CapabilityLeasePresentation presentation =
                CapabilityLeasePresentation.requireExact(challenge, view, 10_000L);
        assertEquals("https://example.com/", presentation.exactUri());
        assertEquals("example.com", presentation.destinationHost());
        assertEquals(30L, presentation.remainingSeconds(10_000L));
        challenge.put("user_visible_summary", "Open something");
        assertSecurityException(
                () -> CapabilityLeasePresentation.requireExact(challenge, view, 10_000L));
    }

    @Test
    public void binderPendingViewRejectsShapeAndNumericDrift() {
        String[] exact = {
                CapabilityLeaseBrokerClient.PendingChallenge.VIEW_SCHEMA,
                "{}", "https://example.com/", "example.com", "0", "openai-codex",
                "1030000", "40000"
        };
        CapabilityLeaseBrokerClient.PendingChallenge decoded =
                CapabilityLeaseBrokerWire.decodePendingView(exact);
        decoded.requireSameImmutableView(view("https://example.com/"));
        assertSecurityException(() -> CapabilityLeaseBrokerWire.decodePendingView(null));
        assertSecurityException(() -> CapabilityLeaseBrokerWire.decodePendingView(
                new String[] {"too", "short"}));
        String[] leadingZero = exact.clone();
        leadingZero[6] = "01030000";
        assertSecurityException(() -> CapabilityLeaseBrokerWire.decodePendingView(leadingZero));
        String[] overflow = exact.clone();
        overflow[7] = "9999999999999999999";
        assertSecurityException(() -> CapabilityLeaseBrokerWire.decodePendingView(overflow));
        String[] wrongSchema = exact.clone();
        wrongSchema[0] = "org.trillionnium.capabilitylease.pending-issuer-view.v0";
        assertSecurityException(() -> CapabilityLeaseBrokerWire.decodePendingView(wrongSchema));
    }

    @Test
    public void binderSubmissionStatusIsExactOperationAndTupleBound() {
        String operationId = CapabilityLeaseUiProtocol.deriveSubmissionOperationId(
                HANDLE, "exact-receipt");
        String receiptId = "b".repeat(64);
        String tupleSha256 = CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                HANDLE, operationId, CapabilityLeaseUiProtocol.STATUS_INDETERMINATE,
                receiptId);
        String[] exact = {
                CapabilityLeaseUiProtocol.SUBMISSION_STATUS_SCHEMA,
                CapabilityLeaseUiProtocol.STATUS_INDETERMINATE,
                operationId,
                receiptId,
                tupleSha256,
        };
        CapabilityLeaseBrokerClient.Submission decoded =
                CapabilityLeaseBrokerWire.decodeSubmissionStatus(
                        HANDLE, operationId, exact);
        assertEquals(CapabilityLeaseUiProtocol.STATUS_INDETERMINATE, decoded.status());
        assertEquals(operationId, decoded.submissionOperationId());
        assertEquals(receiptId, decoded.receiptId());
        assertEquals(tupleSha256, decoded.statusTupleSha256());

        String[] wrongOperation = exact.clone();
        wrongOperation[2] = "lease-submit-" + "c".repeat(64);
        assertSecurityException(() -> CapabilityLeaseBrokerWire.decodeSubmissionStatus(
                HANDLE, operationId, wrongOperation));
        String[] wrongDigest = exact.clone();
        wrongDigest[4] = "d".repeat(64);
        assertSecurityException(() -> CapabilityLeaseBrokerWire.decodeSubmissionStatus(
                HANDLE, operationId, wrongDigest));
        String[] missingReceipt = exact.clone();
        missingReceipt[3] = "";
        assertSecurityException(() -> CapabilityLeaseBrokerWire.decodeSubmissionStatus(
                HANDLE, operationId, missingReceipt));

        String notStartedDigest = CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                HANDLE, operationId, CapabilityLeaseUiProtocol.STATUS_NOT_STARTED, "");
        CapabilityLeaseBrokerClient.Submission notStarted =
                CapabilityLeaseBrokerWire.decodeSubmissionStatus(HANDLE, operationId,
                        new String[] {
                                CapabilityLeaseUiProtocol.SUBMISSION_STATUS_SCHEMA,
                                CapabilityLeaseUiProtocol.STATUS_NOT_STARTED,
                                operationId,
                                "",
                                notStartedDigest,
                        });
        assertEquals(CapabilityLeaseUiProtocol.STATUS_NOT_STARTED, notStarted.status());
        assertEquals("", notStarted.receiptId());
    }

    private static CapabilityLeaseBrokerClient.PendingChallenge view(String uri) {
        String host = uri.substring("https://".length(), uri.length() - 1);
        return new CapabilityLeaseBrokerClient.PendingChallenge(
                CapabilityLeaseBrokerClient.PendingChallenge.VIEW_SCHEMA,
                "{}", uri, host, 0, "openai-codex", 1_030_000L, 40_000L);
    }

    private static void assertSecurityException(ThrowingRunnable runnable) {
        try {
            runnable.run();
        } catch (SecurityException expected) {
            return;
        } catch (Exception unexpected) {
            throw new AssertionError(unexpected);
        }
        throw new AssertionError("expected SecurityException");
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
