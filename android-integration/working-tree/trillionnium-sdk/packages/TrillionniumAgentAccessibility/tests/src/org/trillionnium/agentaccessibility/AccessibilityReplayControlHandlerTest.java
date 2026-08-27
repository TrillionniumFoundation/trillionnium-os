/* SPDX-License-Identifier: Apache-2.0 */
package org.trillionnium.agentaccessibility;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;
import org.trillionnium.agentidentity.AgentDescriptor;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

public final class AccessibilityReplayControlHandlerTest {
    private static final String EPOCH = "00112233445566778899aabbccddeeff";
    private static final String OTHER_EPOCH = "ffeeddccbbaa99887766554433221100";
    private static final String ZERO_EPOCH = "00000000000000000000000000000000";
    private static final String ZERO_SHA256 =
            "0000000000000000000000000000000000000000000000000000000000000000";
    private static final String ACK_ONE_SHA256 =
            "1111111111111111111111111111111111111111111111111111111111111111";
    private static final String ACK_TWO_SHA256 =
            "2222222222222222222222222222222222222222222222222222222222222222";
    private static final String FORK_ACK_SHA256 =
            "3333333333333333333333333333333333333333333333333333333333333333";

    @Test
    public void createdExistingAndEpochStateAreExplicitWithoutBootstrapOrRotation()
            throws Exception {
        Harness harness = new Harness();

        AccessibilityReplayControlProtocol.ActivationResponse created = activate(harness, EPOCH);
        assertTrue(created.created);
        assertEquals(EPOCH, created.epoch);
        assertEquals(0, created.acknowledgedThrough);
        assertEquals(1, created.nextSequence);
        assertEquals(0, created.highestRetainedSequence);
        assertFalse(created.operationEpochBlocked);
        assertFalse(created.operationEpochExhausted);
        assertEquals(ZERO_SHA256, created.authenticatedAckSha256);
        assertEquals(ZERO_SHA256, created.authenticatedAckChainSha256);
        assertTrue(created.isLocalStatePristine());

        AccessibilityReplayControlProtocol.ActivationResponse existing = activate(harness, EPOCH);
        assertFalse(existing.created);
        assertTrue(existing.isLocalStatePristine());

        byte[] canonical = bytes("canonical-one");
        String requestId = AccessibilityOperationId.format(EPOCH, 1, canonical);
        assertTrue(
                Arrays.equals(
                        bytes("committed"),
                        harness.ledger.execute(
                                AgentDescriptor.CODEX,
                                requestId,
                                canonical,
                                256,
                                () -> bytes("committed"))));

        AccessibilityReplayControlProtocol.ActivationResponse nonPristine =
                activate(harness, EPOCH);
        assertFalse(nonPristine.created);
        assertEquals(0, nonPristine.acknowledgedThrough);
        assertEquals(2, nonPristine.nextSequence);
        assertEquals(1, nonPristine.highestRetainedSequence);
        assertFalse(nonPristine.isLocalStatePristine());

        assertControlError(
                "operation_epoch_rotation_denied",
                () ->
                        harness.handle(
                                AgentDescriptor.CODEX,
                                AccessibilityReplayControlHandler.AuthenticatedRole.ADAPTER,
                                activateFrame(OTHER_EPOCH)));
    }

    @Test
    public void nullPeerAndWrongEndpointLocalRoleFailBeforeStateMutation() throws Exception {
        Harness harness = new Harness();
        byte[] activation = activateFrame(EPOCH);

        assertControlError(
                AccessibilityReplayControlHandler.ERROR_PEER_DENIED,
                () ->
                        harness.handle(
                                null,
                                AccessibilityReplayControlHandler.AuthenticatedRole.ADAPTER,
                                activation));
        assertControlError(
                AccessibilityReplayControlHandler.ERROR_ROLE_DENIED,
                () ->
                        harness.handle(
                                AgentDescriptor.CODEX,
                                AccessibilityReplayControlHandler.AuthenticatedRole.REPLAY_SYNC,
                                activation));
        assertControlError(
                AccessibilityReplayControlHandler.ERROR_ROLE_DENIED,
                () -> harness.handle(AgentDescriptor.CODEX, null, activation));

        AccessibilityReplayControlProtocol.ActivationResponse created = activate(harness, EPOCH);
        assertTrue(created.created);

        byte[] canonical = bytes("canonical-role");
        String requestId = AccessibilityOperationId.format(EPOCH, 1, canonical);
        harness.ledger.execute(
                AgentDescriptor.CODEX, requestId, canonical, 256, () -> bytes("committed"));
        String chain = AccessibilityReplayAckChain.derive(EPOCH, 0, 1, ACK_ONE_SHA256, ZERO_SHA256);
        byte[] ack = ackFrame(EPOCH, 1, ACK_ONE_SHA256, chain);
        assertControlError(
                AccessibilityReplayControlHandler.ERROR_ROLE_DENIED,
                () ->
                        harness.handle(
                                AgentDescriptor.CODEX,
                                AccessibilityReplayControlHandler.AuthenticatedRole.ADAPTER,
                                ack));
    }

    @Test
    public void magicVersionOperationLengthTrailingEpochThroughAndDigestFailClosed()
            throws Exception {
        Harness harness = new Harness();
        byte[] validActivation = activateFrame(EPOCH);

        byte[] wrongMagic = validActivation.clone();
        wrongMagic[0] ^= 0x20;
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_MAGIC,
                () -> harness.handleAdapter(wrongMagic));

        byte[] wrongVersion = validActivation.clone();
        wrongVersion[8]++;
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_VERSION,
                () -> harness.handleAdapter(wrongVersion));

        byte[] wrongOperation = validActivation.clone();
        wrongOperation[9] = 3;
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_OPERATION,
                () -> harness.handleAdapter(wrongOperation));

        byte[] wrongDeclaredLength = validActivation.clone();
        wrongDeclaredLength[11]--;
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_LENGTH,
                () -> harness.handleAdapter(wrongDeclaredLength));
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_LENGTH,
                () ->
                        harness.handleAdapter(
                                Arrays.copyOf(validActivation, validActivation.length - 1)));

        byte[] trailing = Arrays.copyOf(validActivation, validActivation.length + 1);
        trailing[trailing.length - 1] = 7;
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_TRAILING,
                () -> harness.handleAdapter(trailing));

        byte[] badEpoch = validActivation.clone();
        badEpoch[AccessibilityReplayControlProtocol.HEADER_BYTES] = 'G';
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_EPOCH,
                () -> harness.handleAdapter(badEpoch));
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_EPOCH,
                () -> harness.handleAdapter(activateFrame(ZERO_EPOCH)));
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_EPOCH,
                () -> harness.handleSync(ackFrame(ZERO_EPOCH, 1, ACK_ONE_SHA256, ACK_TWO_SHA256)));

        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_THROUGH,
                () -> harness.handleSync(ackFrame(EPOCH, 0, ACK_ONE_SHA256, ACK_TWO_SHA256)));
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_DIGEST,
                () -> harness.handleSync(ackFrame(EPOCH, 1, ZERO_SHA256, ACK_TWO_SHA256)));
        byte[] uppercaseDigest = ackFrame(EPOCH, 1, ACK_ONE_SHA256, ACK_TWO_SHA256);
        uppercaseDigest[
                        AccessibilityReplayControlProtocol.HEADER_BYTES
                                + AccessibilityOperationId.EPOCH_HEX_CHARS
                                + Long.BYTES] =
                'A';
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_DIGEST,
                () -> harness.handleSync(uppercaseDigest));

        assertTrue(activate(harness, EPOCH).created);
    }

    @Test
    public void zeroEpochIsRejectedByEveryControlResponseBoundary() throws Exception {
        AccessibilityReplayLedger.EpochActivation zeroActivation =
                new AccessibilityReplayLedger.EpochActivation(
                        AccessibilityReplayLedger.EpochActivation.Status.CREATED,
                        ZERO_EPOCH,
                        0,
                        1,
                        0,
                        false,
                        false,
                        ZERO_SHA256,
                        ZERO_SHA256);
        assertThrows(
                IllegalArgumentException.class,
                () -> AccessibilityReplayControlProtocol.encodeActivationResponse(zeroActivation));
        assertThrows(
                IllegalArgumentException.class,
                () ->
                        AccessibilityReplayControlProtocol.encodeAckResponse(
                                ZERO_EPOCH, 1, ACK_ONE_SHA256, ACK_TWO_SHA256));

        AccessibilityReplayLedger.EpochActivation validActivation =
                new AccessibilityReplayLedger.EpochActivation(
                        AccessibilityReplayLedger.EpochActivation.Status.CREATED,
                        EPOCH,
                        0,
                        1,
                        0,
                        false,
                        false,
                        ZERO_SHA256,
                        ZERO_SHA256);
        byte[] activationResponse =
                AccessibilityReplayControlProtocol.encodeActivationResponse(validActivation);
        Arrays.fill(
                activationResponse,
                AccessibilityReplayControlProtocol.HEADER_BYTES + 4,
                AccessibilityReplayControlProtocol.HEADER_BYTES
                        + 4
                        + AccessibilityOperationId.EPOCH_HEX_CHARS,
                (byte) '0');
        AccessibilityReplayControlProtocol.DecodeException activationError =
                assertThrows(
                        AccessibilityReplayControlProtocol.DecodeException.class,
                        () ->
                                AccessibilityReplayControlProtocol.decodeActivationResponse(
                                        activationResponse));
        assertEquals(AccessibilityReplayControlProtocol.ERROR_EPOCH, activationError.code);

        byte[] ackResponse =
                AccessibilityReplayControlProtocol.encodeAckResponse(
                        EPOCH, 1, ACK_ONE_SHA256, ACK_TWO_SHA256);
        Arrays.fill(
                ackResponse,
                AccessibilityReplayControlProtocol.HEADER_BYTES,
                AccessibilityReplayControlProtocol.HEADER_BYTES
                        + AccessibilityOperationId.EPOCH_HEX_CHARS,
                (byte) '0');
        AccessibilityReplayControlProtocol.DecodeException ackError =
                assertThrows(
                        AccessibilityReplayControlProtocol.DecodeException.class,
                        () -> AccessibilityReplayControlProtocol.decodeAckResponse(ackResponse));
        assertEquals(AccessibilityReplayControlProtocol.ERROR_EPOCH, ackError.code);
    }

    @Test
    public void oneConnectionCarriesExactlyOneFrameAndPayloadHasNoIdentitySelector()
            throws Exception {
        Harness harness = new Harness();
        byte[] first = activateFrame(EPOCH);
        byte[] second = activateFrame(EPOCH);
        byte[] twoFrames = new byte[first.length + second.length];
        System.arraycopy(first, 0, twoFrames, 0, first.length);
        System.arraycopy(second, 0, twoFrames, first.length, second.length);
        assertControlError(
                AccessibilityReplayControlProtocol.ERROR_TRAILING,
                () -> harness.handleAdapter(twoFrames));

        assertEquals(
                AccessibilityReplayControlProtocol.HEADER_BYTES
                        + AccessibilityOperationId.EPOCH_HEX_CHARS,
                first.length);
        assertEquals(
                AccessibilityReplayControlProtocol.HEADER_BYTES
                        + AccessibilityOperationId.EPOCH_HEX_CHARS
                        + Long.BYTES
                        + 2 * AccessibilityOperationId.DIGEST_HEX_CHARS,
                ackFrame(EPOCH, 1, ACK_ONE_SHA256, ACK_TWO_SHA256).length);
        assertTrue(activate(harness, EPOCH).created);
    }

    @Test
    public void ackUsesExistingLedgerExactRetryStaleAndForkSemantics() throws Exception {
        Harness harness = new Harness();
        activate(harness, EPOCH);

        byte[] firstCanonical = bytes("canonical-ack-one");
        String firstId = AccessibilityOperationId.format(EPOCH, 1, firstCanonical);
        harness.ledger.execute(
                AgentDescriptor.CODEX, firstId, firstCanonical, 256, () -> bytes("one"));
        String chainOne =
                AccessibilityReplayAckChain.derive(EPOCH, 0, 1, ACK_ONE_SHA256, ZERO_SHA256);
        byte[] ackOne = ackFrame(EPOCH, 1, ACK_ONE_SHA256, chainOne);
        AccessibilityReplayControlProtocol.AckResponse first =
                AccessibilityReplayControlProtocol.decodeAckResponse(harness.handleSync(ackOne));
        assertEquals(EPOCH, first.epoch);
        assertEquals(1, first.throughSequence);
        assertEquals(ACK_ONE_SHA256, first.ackSha256);
        assertEquals(chainOne, first.ackChainSha256);
        harness.handleSync(ackOne);

        byte[] secondCanonical = bytes("canonical-ack-two");
        String secondId = AccessibilityOperationId.format(EPOCH, 2, secondCanonical);
        harness.ledger.execute(
                AgentDescriptor.CODEX, secondId, secondCanonical, 256, () -> bytes("two"));
        assertControlError(
                "operation_ack_chain_mismatch",
                () -> harness.handleSync(ackFrame(EPOCH, 2, ACK_TWO_SHA256, FORK_ACK_SHA256)));

        String chainTwo = AccessibilityReplayAckChain.derive(EPOCH, 1, 2, ACK_TWO_SHA256, chainOne);
        harness.handleSync(ackFrame(EPOCH, 2, ACK_TWO_SHA256, chainTwo));

        String forkChain =
                AccessibilityReplayAckChain.derive(EPOCH, 1, 2, FORK_ACK_SHA256, chainOne);
        assertControlError(
                "operation_ack_retry_conflict",
                () -> harness.handleSync(ackFrame(EPOCH, 2, FORK_ACK_SHA256, forkChain)));
        assertControlError("operation_ack_not_monotonic", () -> harness.handleSync(ackOne));
        assertControlError(
                "operation_epoch_inactive",
                () -> harness.handleSync(ackFrame(OTHER_EPOCH, 2, ACK_TWO_SHA256, chainTwo)));
    }

    @Test
    public void ioAndStoreFailuresExposeOnlyClosedCodesWithoutInternalMessages() throws Exception {
        Harness harness = new Harness();
        InputStream failedInput =
                new InputStream() {
                    @Override
                    public int read() throws IOException {
                        throw new IOException("/secret/control/socket");
                    }
                };
        AccessibilityReplayControlHandler.ControlException ioFailure =
                captureControlError(
                        () ->
                                harness.handler.handleSingleFrame(
                                        AgentDescriptor.CODEX,
                                        AccessibilityReplayControlHandler.AuthenticatedRole.ADAPTER,
                                        failedInput,
                                        () -> {}));
        assertEquals(AccessibilityReplayControlProtocol.ERROR_IO, ioFailure.code);
        assertEquals(ioFailure.code, ioFailure.getMessage());
        assertNull(ioFailure.getCause());

        InputStream failedUncheckedInput = new InputStream() {
            @Override
            public int read() {
                throw new IllegalStateException("/secret/control/runtime");
            }
        };
        AccessibilityReplayControlHandler.ControlException internalFailure =
                captureControlError(
                        () -> harness.handler.handleSingleFrame(
                                AgentDescriptor.CODEX,
                                AccessibilityReplayControlHandler.AuthenticatedRole.ADAPTER,
                                failedUncheckedInput,
                                () -> {}));
        assertEquals(AccessibilityReplayControlHandler.ERROR_INTERNAL, internalFailure.code);
        assertEquals(internalFailure.code, internalFailure.getMessage());
        assertNull(internalFailure.getCause());

        harness.store.failNextAppend = true;
        AccessibilityReplayControlHandler.ControlException storeFailure =
                captureControlError(() -> harness.handleAdapter(activateFrame(EPOCH)));
        assertEquals(AccessibilityReplayLedger.ERROR_LEDGER_UNAVAILABLE, storeFailure.code);
        assertEquals(storeFailure.code, storeFailure.getMessage());
        assertNull(storeFailure.getCause());
    }

    @Test
    public void authorizationGateRunsAfterFullFrameAndBeforeLedgerMutation() throws Exception {
        Harness harness = new Harness();
        AtomicBoolean fullFrameRead = new AtomicBoolean();
        AtomicBoolean gateCalled = new AtomicBoolean();
        InputStream input = new ByteArrayInputStream(activateFrame(EPOCH)) {
            @Override
            public synchronized int read() {
                int value = super.read();
                if (value == -1) fullFrameRead.set(true);
                return value;
            }
        };
        AccessibilityReplayControlHandler.ControlException revoked = captureControlError(
                () -> harness.handler.handleSingleFrame(
                        AgentDescriptor.CODEX,
                        AccessibilityReplayControlHandler.AuthenticatedRole.ADAPTER,
                        input,
                        () -> {
                            assertTrue(fullFrameRead.get());
                            gateCalled.set(true);
                            throw new SecurityException("authorization_revoked");
                        }));
        assertEquals(AccessibilityReplayControlHandler.ERROR_INTERNAL, revoked.code);
        assertTrue(gateCalled.get());

        AccessibilityReplayControlProtocol.ActivationResponse created = activate(harness, EPOCH);
        assertTrue(created.created);
    }

    private static AccessibilityReplayControlProtocol.ActivationResponse activate(
            Harness harness, String epoch) throws Exception {
        return AccessibilityReplayControlProtocol.decodeActivationResponse(
                harness.handleAdapter(activateFrame(epoch)));
    }

    private static byte[] activateFrame(String epoch) {
        return frame(
                AccessibilityReplayControlProtocol.OP_ACTIVATE,
                epoch.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] ackFrame(
            String epoch, long throughSequence, String ackSha256, String ackChainSha256) {
        ByteBuffer payload =
                ByteBuffer.allocate(AccessibilityReplayControlProtocol.ACK_REQUEST_BYTES);
        payload.put(epoch.getBytes(StandardCharsets.US_ASCII));
        payload.putLong(throughSequence);
        payload.put(ackSha256.getBytes(StandardCharsets.US_ASCII));
        payload.put(ackChainSha256.getBytes(StandardCharsets.US_ASCII));
        return frame(AccessibilityReplayControlProtocol.OP_ACK, payload.array());
    }

    private static byte[] frame(int operation, byte[] payload) {
        ByteBuffer frame =
                ByteBuffer.allocate(
                        AccessibilityReplayControlProtocol.HEADER_BYTES + payload.length);
        frame.put(AccessibilityReplayControlProtocol.MAGIC.getBytes(StandardCharsets.US_ASCII));
        frame.put((byte) AccessibilityReplayControlProtocol.VERSION);
        frame.put((byte) operation);
        frame.putShort((short) payload.length);
        frame.put(payload);
        return frame.array();
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    private static void assertControlError(String expected, ControlCall call) throws Exception {
        assertEquals(expected, captureControlError(call).code);
    }

    private static AccessibilityReplayControlHandler.ControlException captureControlError(
            ControlCall call) throws Exception {
        try {
            call.run();
            fail("expected replay control failure");
            throw new AssertionError();
        } catch (AccessibilityReplayControlHandler.ControlException e) {
            return e;
        }
    }

    private interface ControlCall {
        void run() throws Exception;
    }

    private static final class Harness {
        final MemoryStore store = new MemoryStore();
        final AccessibilityReplayLedger ledger =
                new AccessibilityReplayLedger(8, 64 * 1024, 1000, store);
        final AccessibilityReplayControlHandler handler =
                new AccessibilityReplayControlHandler(AgentDescriptor.CODEX, ledger);

        Harness() throws Exception {}

        byte[] handle(
                AgentDescriptor agent,
                AccessibilityReplayControlHandler.AuthenticatedRole role,
                byte[] frame)
                throws Exception {
            return handler.handleSingleFrame(
                    agent, role, new ByteArrayInputStream(frame), () -> {});
        }

        byte[] handleAdapter(byte[] frame) throws Exception {
            return handle(
                    AgentDescriptor.CODEX,
                    AccessibilityReplayControlHandler.AuthenticatedRole.ADAPTER,
                    frame);
        }

        byte[] handleSync(byte[] frame) throws Exception {
            return handle(
                    AgentDescriptor.CODEX,
                    AccessibilityReplayControlHandler.AuthenticatedRole.REPLAY_SYNC,
                    frame);
        }
    }

    private static final class MemoryStore implements AccessibilityReplayJournal.DurableStore {
        private byte[] mBytes = new byte[0];
        boolean failNextAppend;

        @Override
        public synchronized long size() {
            return mBytes.length;
        }

        @Override
        public synchronized void readFully(long offset, byte[] destination) throws IOException {
            if (offset < 0 || offset > mBytes.length - destination.length) {
                throw new IOException("read outside test journal");
            }
            System.arraycopy(mBytes, (int) offset, destination, 0, destination.length);
        }

        @Override
        public synchronized void appendAndSync(byte[] bytes) throws IOException {
            if (failNextAppend) {
                failNextAppend = false;
                throw new IOException("/secret/replay/watermark");
            }
            byte[] next = Arrays.copyOf(mBytes, mBytes.length + bytes.length);
            System.arraycopy(bytes, 0, next, mBytes.length, bytes.length);
            mBytes = next;
        }

        @Override
        public synchronized void truncateAndSync(long length) {
            mBytes = Arrays.copyOf(mBytes, (int) length);
        }

        @Override
        public synchronized void rewriteAndSync(byte[] completeFile) {
            mBytes = completeFile.clone();
        }

        @Override
        public void close() {}
    }
}
