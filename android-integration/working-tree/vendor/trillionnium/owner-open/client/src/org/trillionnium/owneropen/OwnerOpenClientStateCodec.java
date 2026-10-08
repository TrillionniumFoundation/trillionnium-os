package org.trillionnium.owneropen;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumMap;

/** Strict bounded binary schema v1; checksum detects corruption, not malicious same-UID writers. */
public final class OwnerOpenClientStateCodec {
    public static final int MAX_RECORD_BYTES = 512;
    private static final byte[] MAGIC = {'O', 'O', 'C', 'L', 'S', 'T', '0', '1'};
    private static final int VERSION = 1;
    private static final int DIGEST_BYTES = 32;

    public static final class Snapshot {
        public final long revision;
        public final OwnerOpenClientState state;

        public Snapshot(long revision, OwnerOpenClientState state) {
            if (revision < 1 || state == null) {
                throw new IllegalArgumentException("invalid snapshot revision/state");
            }
            this.revision = revision;
            this.state = state;
        }
    }

    public static final class CorruptStateException extends IOException {
        private static final long serialVersionUID = 1L;

        public CorruptStateException(String reason) {
            super(reason);
        }
    }

    private OwnerOpenClientStateCodec() {}

    public static byte[] encode(Snapshot snapshot) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(MAX_RECORD_BYTES);
        DataOutputStream output = new DataOutputStream(buffer);
        output.write(MAGIC);
        output.writeInt(VERSION);
        output.writeLong(snapshot.revision);
        writeAscii(output, snapshot.state.sessionId);
        writeAscii(output, snapshot.state.taskId);
        output.writeByte(snapshot.state.turnId == null ? 0 : 1);
        if (snapshot.state.turnId != null) {
            writeAscii(output, snapshot.state.turnId);
        }
        output.writeByte(snapshot.state.cursors.size());
        for (OwnerOpenClientState.CursorDomain domain : OwnerOpenClientState.CursorDomain.values()) {
            OwnerOpenClientState.Cursor cursor = snapshot.state.cursors.get(domain);
            if (cursor != null) {
                output.writeByte(domain.ordinal());
                writeAscii(output, cursor.producerEpochSha256);
                output.writeLong(cursor.inclusiveCursor);
            }
        }
        output.flush();
        byte[] prefix = buffer.toByteArray();
        output.write(sha256(prefix));
        output.flush();
        byte[] result = buffer.toByteArray();
        if (result.length > MAX_RECORD_BYTES) {
            throw new IOException("state record exceeds bound");
        }
        return result;
    }

    public static Snapshot decode(byte[] encoded) throws IOException {
        if (encoded == null || encoded.length <= MAGIC.length + 4 + 8 + DIGEST_BYTES
                || encoded.length > MAX_RECORD_BYTES) {
            throw new CorruptStateException("invalid record length");
        }
        int payloadLength = encoded.length - DIGEST_BYTES;
        byte[] payload = Arrays.copyOf(encoded, payloadLength);
        if (!MessageDigest.isEqual(sha256(payload),
                Arrays.copyOfRange(encoded, payloadLength, encoded.length))) {
            throw new CorruptStateException("record checksum mismatch");
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(payload))) {
            byte[] magic = new byte[MAGIC.length];
            input.readFully(magic);
            if (!Arrays.equals(magic, MAGIC) || input.readInt() != VERSION) {
                throw new CorruptStateException("unsupported state schema");
            }
            long revision = input.readLong();
            String session = readAscii(input);
            String task = readAscii(input);
            int selected = input.readUnsignedByte();
            if (selected > 1) {
                throw new CorruptStateException("invalid turn presence flag");
            }
            String turn = selected == 1 ? readAscii(input) : null;
            int count = input.readUnsignedByte();
            OwnerOpenClientState.CursorDomain[] domains = OwnerOpenClientState.CursorDomain.values();
            if (count > domains.length) {
                throw new CorruptStateException("too many cursor domains");
            }
            EnumMap<OwnerOpenClientState.CursorDomain, OwnerOpenClientState.Cursor> cursors =
                    new EnumMap<>(OwnerOpenClientState.CursorDomain.class);
            int previousOrdinal = -1;
            for (int index = 0; index < count; index++) {
                int ordinal = input.readUnsignedByte();
                if (ordinal >= domains.length || ordinal <= previousOrdinal) {
                    throw new CorruptStateException("duplicate/unknown/noncanonical cursor domain");
                }
                previousOrdinal = ordinal;
                OwnerOpenClientState.CursorDomain domain = domains[ordinal];
                cursors.put(domain, new OwnerOpenClientState.Cursor(
                        domain, readAscii(input), input.readLong()));
            }
            if (input.available() != 0) {
                throw new CorruptStateException("unknown/trailing state fields");
            }
            return new Snapshot(revision, new OwnerOpenClientState(session, task, turn, cursors));
        } catch (IllegalArgumentException error) {
            throw new CorruptStateException("invalid state field");
        } catch (java.io.EOFException error) {
            throw new CorruptStateException("truncated state field");
        }
    }

    private static void writeAscii(DataOutputStream output, String value) throws IOException {
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        if (encoded.length < 1 || encoded.length > 64) {
            throw new IOException("state string exceeds bound");
        }
        output.writeByte(encoded.length);
        output.write(encoded);
    }

    private static String readAscii(DataInputStream input) throws IOException {
        int length = input.readUnsignedByte();
        if (length < 1 || length > 64 || length > input.available()) {
            throw new CorruptStateException("invalid state string length");
        }
        byte[] encoded = new byte[length];
        input.readFully(encoded);
        for (byte value : encoded) {
            if (value < 0x21 || value > 0x7e) {
                throw new CorruptStateException("noncanonical state string bytes");
            }
        }
        return new String(encoded, StandardCharsets.US_ASCII);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException error) {
            throw new AssertionError("required SHA-256 unavailable", error);
        }
    }
}
