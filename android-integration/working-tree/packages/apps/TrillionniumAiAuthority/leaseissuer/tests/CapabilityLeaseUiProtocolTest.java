/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.capabilitylease;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class CapabilityLeaseUiProtocolTest {
    private static final String HANDLE = "lease-pending-" + "a".repeat(64);

    @Test
    public void exactSchemaAndBoundedValuesPass() {
        CapabilityLeaseUiProtocol.requireTransportSchema(
                CapabilityLeaseUiProtocol.TRANSPORT_SCHEMA);
        assertEquals(HANDLE, CapabilityLeaseUiProtocol.requirePendingHandle(HANDLE));
        assertEquals("{}", CapabilityLeaseUiProtocol.requireReceipt("{}"));
        assertEquals("a".repeat(64),
                CapabilityLeaseUiProtocol.requireReceiptId("a".repeat(64)));
    }

    @Test
    public void schemaHandleAndReceiptIdDriftFailClosed() {
        assertDenied(() -> CapabilityLeaseUiProtocol.requireTransportSchema(
                "org.trillionnium.capabilitylease.ui-broker.v0"));
        assertDenied(() -> CapabilityLeaseUiProtocol.requirePendingHandle(
                "lease-pending-" + "A".repeat(64)));
        assertDenied(() -> CapabilityLeaseUiProtocol.requireReceiptId("a".repeat(63)));
        assertDenied(() -> CapabilityLeaseUiProtocol.requireReceiptId("g".repeat(64)));
    }

    @Test
    public void oversizedInputsFailBeforeBrokerUse() {
        assertDenied(() -> CapabilityLeaseUiProtocol.requireReceipt(
                "r".repeat(CapabilityLeaseUiProtocol.MAX_RECEIPT_BYTES + 1)));
        assertDenied(() -> CapabilityLeaseUiProtocol.requireChallenge(
                "c".repeat(CapabilityLeaseUiProtocol.MAX_CHALLENGE_BYTES + 1)));
        assertDenied(() -> CapabilityLeaseUiProtocol.requireUri(
                "u".repeat(CapabilityLeaseUiProtocol.MAX_URI_BYTES + 1)));
    }

    @Test
    public void submissionIdentityAndStatusTupleAreHandleReceiptAndStateBound() {
        String operationId = CapabilityLeaseUiProtocol.deriveSubmissionOperationId(
                HANDLE, "exact-receipt");
        assertEquals(operationId, CapabilityLeaseUiProtocol.deriveSubmissionOperationId(
                HANDLE, "exact-receipt"));
        assertTrue(operationId.matches("lease-submit-[0-9a-f]{64}"));
        assertFalse(operationId.equals(CapabilityLeaseUiProtocol.deriveSubmissionOperationId(
                HANDLE, "different-receipt")));

        String receiptId = "b".repeat(64);
        String indeterminate = CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                HANDLE, operationId, CapabilityLeaseUiProtocol.STATUS_INDETERMINATE,
                receiptId);
        assertEquals(indeterminate,
                CapabilityLeaseUiProtocol.requireSubmissionStatusTupleSha256(indeterminate));
        assertFalse(indeterminate.equals(
                CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                        HANDLE, operationId, CapabilityLeaseUiProtocol.STATUS_SUBMITTED,
                        receiptId)));
        assertDenied(() -> CapabilityLeaseUiProtocol.deriveSubmissionStatusTupleSha256(
                HANDLE, operationId, CapabilityLeaseUiProtocol.STATUS_INDETERMINATE, ""));
        assertDenied(() -> CapabilityLeaseUiProtocol.requireSubmissionStatus("pending-ish"));
        assertDenied(() -> CapabilityLeaseUiProtocol.requireSubmissionOperationId(
                "lease-submit-" + "A".repeat(64)));
    }

    private static void assertDenied(ThrowingRunnable runnable) {
        try {
            runnable.run();
        } catch (SecurityException expected) {
            return;
        }
        throw new AssertionError("expected SecurityException");
    }

    private interface ThrowingRunnable {
        void run();
    }
}
