/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import org.junit.Test;
import org.trillionnium.agentidentity.AgentDescriptor;

public final class CapabilityLeasePendingRecordCodecTest {
    private static final String RECEIPT_SHA256 =
            "6f32860910ca0fb2a20c7fda143666b09dbf8db5238195c90a586fb542ff0cad";
    private static final String OTHER_RECEIPT_SHA256 =
            "8665706e4e0cf51e91bf5374032734894235a4ccd1e6aa482e53f890136c2061";

    @Test
    public void everyStateRoundTripsDeterministically() throws Exception {
        for (CapabilityLeasePendingStore.State state : CapabilityLeasePendingStore.State.values()) {
            CapabilityLeasePendingStore.Record record = record(state);
            byte[] first = CapabilityLeasePendingRecordCodec.encode(record);
            byte[] second = CapabilityLeasePendingRecordCodec.encode(record);
            assertArrayEquals(first, second);
            CapabilityLeasePendingStore.Record decoded =
                    CapabilityLeasePendingRecordCodec.decode(first);
            assertEquals(record.handle, decoded.handle);
            assertEquals(record.creatorPeerIdentity, decoded.creatorPeerIdentity);
            assertEquals(record.prepareRequestId, decoded.prepareRequestId);
            assertEquals(record.authenticatedTaskBindingSha256,
                    decoded.authenticatedTaskBindingSha256);
            assertEquals(record.prepareCanonicalRequestSha256,
                    decoded.prepareCanonicalRequestSha256);
            assertEquals(record.state, decoded.state);
            assertEquals(record.receiptId, decoded.receiptId);
            assertEquals(record.exactReceipt, decoded.exactReceipt);
        }
    }

    @Test
    public void corruptionTruncationTrailingAndUnknownStateFailClosed() throws Exception {
        byte[] encoded = CapabilityLeasePendingRecordCodec.encode(
                record(CapabilityLeasePendingStore.State.PENDING));
        byte[] corrupt = encoded.clone();
        corrupt[20] ^= 1;
        assertIOException(() -> CapabilityLeasePendingRecordCodec.decode(corrupt));
        assertIOException(() -> CapabilityLeasePendingRecordCodec.decode(
                Arrays.copyOf(encoded, encoded.length - 1)));
        assertIOException(() -> CapabilityLeasePendingRecordCodec.decode(
                Arrays.copyOf(encoded, encoded.length + 1)));
    }

    @Test
    public void zeroBootDigestCannotBeConstructedOrRecoveredFromCodec() throws Exception {
        CapabilityLeasePendingStore.Record valid =
                record(CapabilityLeasePendingStore.State.PENDING);
        assertIllegalArgument(() -> new CapabilityLeasePendingStore.Record(
                valid.handle, valid.creatorPeerIdentity, valid.prepareRequestId,
                valid.authenticatedTaskBindingSha256, valid.prepareCanonicalRequestSha256,
                valid.workflowId, valid.taskId, "0".repeat(64), valid.providerId,
                valid.exactHttpsUri, valid.exactChallenge, valid.issuedAtMs, valid.expiresAtMs,
                valid.notBeforeElapsedMs, valid.expiresElapsedMs, valid.state,
                valid.receiptId, valid.receiptSha256, valid.exactReceipt));

        byte[] encoded = CapabilityLeasePendingRecordCodec.encode(valid);
        byte[] boot = "b".repeat(64).getBytes(StandardCharsets.US_ASCII);
        int bootOffset = indexOf(encoded, boot);
        if (bootOffset < 0 || bootOffset + boot.length > encoded.length - 32) {
            throw new AssertionError("encoded boot digest not found");
        }
        Arrays.fill(encoded, bootOffset, bootOffset + boot.length, (byte) '0');
        byte[] checksum = MessageDigest.getInstance("SHA-256").digest(
                Arrays.copyOf(encoded, encoded.length - 32));
        System.arraycopy(checksum, 0, encoded, encoded.length - checksum.length,
                checksum.length);
        assertIOException(() -> CapabilityLeasePendingRecordCodec.decode(encoded));
    }

    @Test
    public void invalidStateShapesCannotBeConstructed() throws Exception {
        assertIllegalArgument(() -> base(CapabilityLeasePendingStore.State.PENDING,
                "c".repeat(64), RECEIPT_SHA256, "receipt"));
        assertIllegalArgument(() -> base(CapabilityLeasePendingStore.State.INDETERMINATE,
                null, null, null));
        assertIllegalArgument(() -> base(CapabilityLeasePendingStore.State.SUBMITTED,
                null, null, null));
        assertIllegalArgument(() -> base(CapabilityLeasePendingStore.State.SUBMITTED,
                "c".repeat(64), "d".repeat(64), "receipt"));
        assertIllegalArgument(() -> base(CapabilityLeasePendingStore.State.CONSUMED,
                "c".repeat(64), RECEIPT_SHA256, "receipt"));
    }

    @Test
    public void immutableDriftAndIllegalTransitionsAreRejected() throws Exception {
        CapabilityLeasePendingStore.Record pending =
                record(CapabilityLeasePendingStore.State.PENDING);
        CapabilityLeasePendingStore.Record indeterminate = pending.transition(
                CapabilityLeasePendingStore.State.INDETERMINATE,
                "c".repeat(64), RECEIPT_SHA256, "receipt");
        indeterminate.requireValidTransitionFrom(pending);
        CapabilityLeasePendingStore.Record submitted = indeterminate.transition(
                CapabilityLeasePendingStore.State.SUBMITTED,
                "c".repeat(64), RECEIPT_SHA256, "receipt");
        submitted.requireValidTransitionFrom(indeterminate);
        assertIOException(() -> pending.transition(CapabilityLeasePendingStore.State.SUBMITTED,
                "c".repeat(64), RECEIPT_SHA256, "receipt")
                .requireValidTransitionFrom(pending));
        assertIOException(() -> pending.transition(CapabilityLeasePendingStore.State.CONSUMED,
                "c".repeat(64), RECEIPT_SHA256, null)
                .requireValidTransitionFrom(pending));
        CapabilityLeasePendingStore.Record drift = new CapabilityLeasePendingStore.Record(
                pending.handle, pending.creatorPeerIdentity, pending.prepareRequestId,
                pending.authenticatedTaskBindingSha256,
                pending.prepareCanonicalRequestSha256,
                pending.workflowId, "task-drift", pending.bootIdSha256,
                pending.providerId, pending.exactHttpsUri, pending.exactChallenge,
                pending.issuedAtMs, pending.expiresAtMs, pending.notBeforeElapsedMs,
                pending.expiresElapsedMs, CapabilityLeasePendingStore.State.CANCELED,
                null, null, null);
        assertIOException(() -> drift.requireValidTransitionFrom(pending));
    }

    @Test
    public void submittedToDeliveryReadyPreservesExactReceiptBinding() throws Exception {
        CapabilityLeasePendingStore.Record pending =
                record(CapabilityLeasePendingStore.State.PENDING);
        CapabilityLeasePendingStore.Record indeterminate = pending.transition(
                CapabilityLeasePendingStore.State.INDETERMINATE,
                "c".repeat(64), RECEIPT_SHA256, "receipt");
        indeterminate.requireValidTransitionFrom(pending);
        CapabilityLeasePendingStore.Record submitted = indeterminate.transition(
                CapabilityLeasePendingStore.State.SUBMITTED,
                "c".repeat(64), RECEIPT_SHA256, "receipt");
        submitted.requireValidTransitionFrom(indeterminate);
        submitted.transition(CapabilityLeasePendingStore.State.DELIVERY_READY,
                "c".repeat(64), RECEIPT_SHA256, "receipt")
                .requireValidTransitionFrom(submitted);

        assertIOException(() -> submitted.transition(
                CapabilityLeasePendingStore.State.DELIVERY_READY,
                "e".repeat(64), RECEIPT_SHA256, "receipt")
                .requireValidTransitionFrom(submitted));
        assertIOException(() -> submitted.transition(
                CapabilityLeasePendingStore.State.DELIVERY_READY,
                "c".repeat(64), OTHER_RECEIPT_SHA256, "other-receipt")
                .requireValidTransitionFrom(submitted));
    }

    @Test
    public void deliveryReadyToConsumedOnlyClearsExactReceiptBody() throws Exception {
        CapabilityLeasePendingStore.Record ready =
                record(CapabilityLeasePendingStore.State.DELIVERY_READY);
        ready.transition(CapabilityLeasePendingStore.State.CONSUMED,
                "c".repeat(64), RECEIPT_SHA256, null)
                .requireValidTransitionFrom(ready);

        assertIOException(() -> ready.transition(CapabilityLeasePendingStore.State.CONSUMED,
                "e".repeat(64), RECEIPT_SHA256, null)
                .requireValidTransitionFrom(ready));
        assertIOException(() -> ready.transition(CapabilityLeasePendingStore.State.CONSUMED,
                "c".repeat(64), "f".repeat(64), null)
                .requireValidTransitionFrom(ready));
    }

    @Test
    public void compactionWatermarkRoundTripsAndChainsExactTerminalBytes() throws Exception {
        CapabilityLeasePendingStore.Record canceled =
                record(CapabilityLeasePendingStore.State.CANCELED);
        CapabilityLeasePendingStore.CompactionWatermark first =
                CapabilityLeasePendingStore.CompactionWatermark.genesis().next(canceled);
        byte[] encoded = CapabilityLeaseCompactionWatermarkCodec.encode(first);
        CapabilityLeasePendingStore.CompactionWatermark decoded =
                CapabilityLeaseCompactionWatermarkCodec.decode(encoded);
        assertEquals(1L, decoded.epoch);
        assertEquals(first.rootSha256, decoded.rootSha256);
        assertEquals(canceled.handle, decoded.lastHandle);
        decoded.requireValidSuccessor(
                CapabilityLeasePendingStore.CompactionWatermark.genesis(), canceled);
    }

    @Test
    public void compactionWatermarkCorruptionAndWrongTerminalFailClosed() throws Exception {
        CapabilityLeasePendingStore.Record canceled =
                record(CapabilityLeasePendingStore.State.CANCELED);
        CapabilityLeasePendingStore.CompactionWatermark first =
                CapabilityLeasePendingStore.CompactionWatermark.genesis().next(canceled);
        byte[] encoded = CapabilityLeaseCompactionWatermarkCodec.encode(first);
        encoded[encoded.length - 1] ^= 1;
        assertIOException(() -> CapabilityLeaseCompactionWatermarkCodec.decode(encoded));
        assertIOException(() -> CapabilityLeasePendingStore.CompactionWatermark.genesis()
                .next(record(CapabilityLeasePendingStore.State.PENDING)));
    }

    private static CapabilityLeasePendingStore.Record record(
            CapabilityLeasePendingStore.State state) {
        switch (state) {
            case INDETERMINATE:
            case SUBMITTED:
            case DELIVERY_READY:
                return base(state, "c".repeat(64), RECEIPT_SHA256, "receipt");
            case CONSUMED:
                return base(state, "c".repeat(64), RECEIPT_SHA256, null);
            default:
                return base(state, null, null, null);
        }
    }

    private static CapabilityLeasePendingStore.Record base(
            CapabilityLeasePendingStore.State state, String receiptId,
            String receiptSha256, String exactReceipt) {
        return new CapabilityLeasePendingStore.Record(
                "lease-pending-" + "a".repeat(64), AgentDescriptor.CODEX,
                "prepare-request-1", "e".repeat(64), "f".repeat(64),
                "workflow-1", "task-1",
                "b".repeat(64), "openai-codex", "https://example.com/", "{}",
                1_000L, 31_000L, 2_000L, 32_000L, state,
                receiptId, receiptSha256, exactReceipt);
    }

    private static void assertIOException(ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
        } catch (IOException expected) {
            return;
        }
        throw new AssertionError("expected IOException");
    }

    private static void assertIllegalArgument(ThrowingRunnable runnable) throws Exception {
        try {
            runnable.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("expected IllegalArgumentException");
    }

    private static int indexOf(byte[] value, byte[] target) {
        outer:
        for (int index = 0; index <= value.length - target.length; index++) {
            for (int offset = 0; offset < target.length; offset++) {
                if (value[index + offset] != target[offset]) continue outer;
            }
            return index;
        }
        return -1;
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
