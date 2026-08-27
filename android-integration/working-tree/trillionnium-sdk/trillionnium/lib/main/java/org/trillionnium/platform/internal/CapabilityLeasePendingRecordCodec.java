/*
 * SPDX-License-Identifier: Apache-2.0
 */

package org.trillionnium.platform.internal;

import org.trillionnium.agentidentity.AgentDescriptor;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/** Strict length-framed, checksummed codec for capability-lease pending records. */
final class CapabilityLeasePendingRecordCodec {
    private static final byte[] MAGIC = "TRCLPN02".getBytes(StandardCharsets.US_ASCII);
    private static final int DIGEST_BYTES = 32;
    static final int MAX_RECORD_BYTES = 384 * 1024;

    private CapabilityLeasePendingRecordCodec() {}

    static byte[] encode(CapabilityLeasePendingStore.Record record) throws IOException {
        if (record == null) throw new IOException("missing pending record");
        ByteArrayOutputStream bodyBytes = new ByteArrayOutputStream();
        try (DataOutputStream output = new DataOutputStream(bodyBytes)) {
            output.write(MAGIC);
            writeString(output, record.handle);
            writeString(output, record.creatorPeerIdentity.replayNamespace());
            writeString(output, record.prepareRequestId);
            writeString(output, record.authenticatedTaskBindingSha256);
            writeString(output, record.prepareCanonicalRequestSha256);
            writeString(output, record.workflowId);
            writeString(output, record.taskId);
            writeString(output, record.bootIdSha256);
            writeString(output, record.providerId);
            writeString(output, record.exactHttpsUri);
            writeString(output, record.exactChallenge);
            output.writeLong(record.issuedAtMs);
            output.writeLong(record.expiresAtMs);
            output.writeLong(record.notBeforeElapsedMs);
            output.writeLong(record.expiresElapsedMs);
            output.writeInt(stateTag(record.state));
            writeNullableString(output, record.receiptId);
            writeNullableString(output, record.receiptSha256);
            writeNullableString(output, record.exactReceipt);
        }
        byte[] body = bodyBytes.toByteArray();
        if (body.length + DIGEST_BYTES > MAX_RECORD_BYTES) {
            throw new IOException("pending record too large");
        }
        byte[] encoded = Arrays.copyOf(body, body.length + DIGEST_BYTES);
        System.arraycopy(sha256(body), 0, encoded, body.length, DIGEST_BYTES);
        return encoded;
    }

    static CapabilityLeasePendingStore.Record decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length <= MAGIC.length + DIGEST_BYTES
                || encoded.length > MAX_RECORD_BYTES) {
            throw new IOException("invalid pending record boundary");
        }
        byte[] body = Arrays.copyOf(encoded, encoded.length - DIGEST_BYTES);
        byte[] expectedDigest = Arrays.copyOfRange(
                encoded, encoded.length - DIGEST_BYTES, encoded.length);
        if (!MessageDigest.isEqual(expectedDigest, sha256(body))) {
            throw new IOException("pending record checksum mismatch");
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(body))) {
            byte[] magic = new byte[MAGIC.length];
            input.readFully(magic);
            if (!Arrays.equals(MAGIC, magic)) throw new IOException("pending record magic mismatch");
            String handle = readString(input, 78);
            AgentDescriptor creatorPeerIdentity = descriptorFromReplayNamespace(
                    readString(input, 64));
            String prepareRequestId = readString(input, 128);
            String authenticatedTaskBindingSha256 = readString(input, 64);
            String prepareCanonicalRequestSha256 = readString(input, 64);
            String workflowId = readString(input, 128);
            String taskId = readString(input, 128);
            String bootIdSha256 = readString(input, 64);
            String providerId = readString(input, 64);
            String exactHttpsUri = readString(input, 4 * 1024);
            String exactChallenge = readString(input, 64 * 1024);
            long issuedAtMs = input.readLong();
            long expiresAtMs = input.readLong();
            long notBeforeElapsedMs = input.readLong();
            long expiresElapsedMs = input.readLong();
            CapabilityLeasePendingStore.State state = stateFromTag(input.readInt());
            String receiptId = readNullableString(input, 64);
            String receiptSha256 = readNullableString(input, 64);
            String exactReceipt = readNullableString(input, 256 * 1024);
            if (input.available() != 0) throw new IOException("trailing pending record bytes");
            try {
                return new CapabilityLeasePendingStore.Record(handle, creatorPeerIdentity,
                        prepareRequestId, authenticatedTaskBindingSha256,
                        prepareCanonicalRequestSha256, workflowId, taskId,
                        bootIdSha256, providerId, exactHttpsUri, exactChallenge,
                        issuedAtMs, expiresAtMs, notBeforeElapsedMs, expiresElapsedMs,
                        state, receiptId, receiptSha256, exactReceipt);
            } catch (IllegalArgumentException invalid) {
                throw new IOException("invalid pending record", invalid);
            }
        } catch (EOFException truncated) {
            throw new IOException("truncated pending record", truncated);
        }
    }

    private static void writeNullableString(DataOutputStream output, String value)
            throws IOException {
        if (value == null) {
            output.writeInt(-1);
            return;
        }
        writeString(output, value);
    }

    private static int stateTag(CapabilityLeasePendingStore.State state) throws IOException {
        switch (state) {
            case PENDING: return 1;
            case SUBMITTED: return 2;
            case DELIVERY_READY: return 3;
            case CONSUMED: return 4;
            case CANCELED: return 5;
            case EXPIRED: return 6;
            case INDETERMINATE: return 7;
            default: throw new IOException("invalid pending record state");
        }
    }

    private static CapabilityLeasePendingStore.State stateFromTag(int tag) throws IOException {
        switch (tag) {
            case 1: return CapabilityLeasePendingStore.State.PENDING;
            case 2: return CapabilityLeasePendingStore.State.SUBMITTED;
            case 3: return CapabilityLeasePendingStore.State.DELIVERY_READY;
            case 4: return CapabilityLeasePendingStore.State.CONSUMED;
            case 5: return CapabilityLeasePendingStore.State.CANCELED;
            case 6: return CapabilityLeasePendingStore.State.EXPIRED;
            case 7: return CapabilityLeasePendingStore.State.INDETERMINATE;
            default: throw new IOException("invalid pending record state");
        }
    }

    private static void writeString(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        output.writeInt(encoded.length);
        output.write(encoded);
    }

    private static String readNullableString(DataInputStream input, int maxBytes)
            throws IOException {
        int size = input.readInt();
        if (size == -1) return null;
        return readStringBody(input, size, maxBytes);
    }

    private static String readString(DataInputStream input, int maxBytes) throws IOException {
        return readStringBody(input, input.readInt(), maxBytes);
    }

    private static String readStringBody(DataInputStream input, int size, int maxBytes)
            throws IOException {
        if (size <= 0 || size > maxBytes) throw new IOException("invalid string boundary");
        byte[] value = new byte[size];
        input.readFully(value);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(value)).toString();
        } catch (CharacterCodingException invalid) {
            throw new IOException("invalid UTF-8", invalid);
        }
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException impossible) {
            throw new AssertionError("SHA-256 unavailable", impossible);
        }
    }

    private static AgentDescriptor descriptorFromReplayNamespace(String replayNamespace)
            throws IOException {
        for (AgentDescriptor descriptor : AgentDescriptor.values()) {
            if (descriptor.replayNamespace().equals(replayNamespace)) return descriptor;
        }
        throw new IOException("unknown pending creator peer");
    }
}
