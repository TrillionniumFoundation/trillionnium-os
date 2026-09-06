package org.trillionnium.owneropen;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/** Mechanical JSONL codec for the owner-open R5 wire. */
public final class OwnerOpenFrame {
    public static final int MAX_LINE_BYTES = 1024 * 1024;
    // MAX_LINE_BYTES includes the one-byte LF delimiter on the wire.
    private static final int MAX_PAYLOAD_BYTES = MAX_LINE_BYTES - 1;
    private static final Pattern ID = Pattern.compile("[A-Za-z0-9_.:-]{1,256}");

    private OwnerOpenFrame() {}

    public static String turnStart(
            String sessionId, String taskId, String turnId, String userInput) {
        requireId(sessionId, "sessionId");
        requireId(taskId, "taskId");
        requireId(turnId, "turnId");
        requireText(userInput, "userInput", 256 * 1024);
        return "{\"kind\":\"turn.start\",\"payload\":{"
                + "\"protocol\":\"trillionnium.agent.turn.v1\","
                + "\"protocol_version\":1,"
                + "\"session_id\":" + quote(sessionId) + ","
                + "\"task_id\":" + quote(taskId) + ","
                + "\"turn_id\":" + quote(turnId) + ","
                + "\"user_input\":" + quote(userInput)
                + "}}";
    }

    public static String turnCancel(String sessionId, String turnId) {
        requireId(sessionId, "sessionId");
        requireId(turnId, "turnId");
        return "{\"kind\":\"turn.cancel\",\"payload\":{"
                + "\"session_id\":" + quote(sessionId) + ","
                + "\"turn_id\":" + quote(turnId)
                + "}}";
    }

    public static String turnInspect(
            String sessionId, String taskId, String turnId, long inclusiveCursor, int limit) {
        requireId(sessionId, "sessionId");
        requireId(taskId, "taskId");
        requireId(turnId, "turnId");
        if (inclusiveCursor < 0) {
            throw new IllegalArgumentException("inclusiveCursor must be non-negative");
        }
        if (limit < 1 || limit > 4096) {
            throw new IllegalArgumentException("limit must be in 1..4096");
        }
        return "{\"kind\":\"turn.inspect\",\"payload\":{"
                + "\"session_id\":" + quote(sessionId) + ","
                + "\"task_id\":" + quote(taskId) + ","
                + "\"turn_id\":" + quote(turnId) + ","
                + "\"inclusive_cursor\":" + inclusiveCursor + ","
                + "\"limit\":" + limit
                + "}}";
    }

    public static String brokerRequest(
            String requestId,
            String frame,
            List<String> expectedKinds,
            int timeoutMilliseconds) {
        requireId(requestId, "requestId");
        Objects.requireNonNull(frame, "frame");
        if (frame.isEmpty() || frame.indexOf('\n') >= 0 || frame.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("frame must be one non-empty JSON line");
        }
        if (expectedKinds == null || expectedKinds.isEmpty() || expectedKinds.size() > 64) {
            throw new IllegalArgumentException("expectedKinds must contain 1..64 entries");
        }
        if (timeoutMilliseconds < 1 || timeoutMilliseconds > 300_000) {
            throw new IllegalArgumentException("timeoutMilliseconds must be in 1..300000");
        }
        StringBuilder kinds = new StringBuilder("[");
        for (int index = 0; index < expectedKinds.size(); index++) {
            String kind = expectedKinds.get(index);
            requireText(kind, "expectedKind", 256);
            if (index != 0) {
                kinds.append(',');
            }
            kinds.append(quote(kind));
        }
        kinds.append(']');
        String result = "{\"expected_kinds\":" + kinds
                + ",\"frame\":" + frame
                + ",\"kind\":\"request\",\"request_id\":" + quote(requestId)
                + ",\"timeout_ms\":" + timeoutMilliseconds + "}";
        requireEncodedBound(result);
        return result;
    }

    /**
     * Bind one semantic Host frame to this Android client's transport
     * direction and per-connection sequence.  The broker treats {@code seq}
     * as an immutable contiguous client sequence, so it must be added before
     * the frame is wrapped in a broker request rather than invented by the
     * broker or the native ingress.
     */
    public static String withClientTransportSequence(String frame, long sequence) {
        Objects.requireNonNull(frame, "frame");
        if (sequence < 0 || frame.isEmpty() || frame.indexOf('\n') >= 0
                || frame.indexOf('\r') >= 0 || !frame.startsWith("{\"kind\":")) {
            throw new IllegalArgumentException("frame is not a canonical Host object");
        }
        String result = "{\"direction\":\"client_to_host\",\"seq\":"
                + sequence + "," + frame.substring(1);
        requireEncodedBound(result);
        return result;
    }

    public static boolean hasKind(String line, String kind) {
        requireText(line, "line", MAX_LINE_BYTES);
        requireText(kind, "kind", 256);
        return line.contains("\"kind\":" + quote(kind));
    }

    public static String readLine(InputStream input) throws IOException {
        Objects.requireNonNull(input, "input");
        ByteArrayOutputStream output = new ByteArrayOutputStream(4096);
        // MAX_LINE_BYTES is the complete wire-line bound, including the
        // trailing newline (the native ingress uses the same contract).
        // Keep the delimiter out of the returned JSON string, but reserve
        // one byte for it on every iteration.
        while (true) {
            int current = input.read();
            if (current < 0) {
                if (output.size() == 0) {
                    throw new EOFException("owner-open ingress closed");
                }
                throw new IOException("owner-open frame is not newline terminated");
            }
            if (current == 0) {
                throw new IOException("owner-open frame contains NUL");
            }
            if (current == '\n') {
                if (output.size() == 0) {
                    throw new IOException("owner-open frame is empty");
                }
                return output.toString(StandardCharsets.UTF_8);
            }
            if (output.size() >= MAX_PAYLOAD_BYTES) {
                throw new IOException("owner-open frame exceeds the byte bound");
            }
            output.write(current);
        }
    }

    public static void writeLine(OutputStream output, String line) throws IOException {
        Objects.requireNonNull(output, "output");
        requireText(line, "line", MAX_LINE_BYTES);
        if (line.indexOf('\n') >= 0 || line.indexOf('\r') >= 0) {
            throw new IllegalArgumentException("line contains a newline");
        }
        byte[] raw = line.getBytes(StandardCharsets.UTF_8);
        if (raw.length == 0 || raw.length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("line exceeds the encoded byte bound");
        }
        output.write(raw);
        output.write('\n');
        output.flush();
    }

    public static String quote(String value) {
        requireText(value, "JSON string", MAX_LINE_BYTES);
        StringBuilder result = new StringBuilder(value.length() + 16);
        result.append('"');
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            switch (current) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\b' -> result.append("\\b");
                case '\f' -> result.append("\\f");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (current < 0x20) {
                        result.append(String.format("\\u%04x", (int) current));
                    } else {
                        result.append(current);
                    }
                }
            }
        }
        result.append('"');
        return result.toString();
    }

    private static void requireId(String value, String label) {
        if (value == null || !ID.matcher(value).matches()) {
            throw new IllegalArgumentException(label + " is empty, oversized or malformed");
        }
    }

    private static void requireText(String value, String label, int maximumCharacters) {
        if (value == null || value.length() > maximumCharacters || value.indexOf('\0') >= 0) {
            throw new IllegalArgumentException(label + " is null, oversized or contains NUL");
        }
        for (int index = 0; index < value.length(); index++) {
            char current = value.charAt(index);
            if (Character.isHighSurrogate(current)) {
                if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    throw new IllegalArgumentException(label + " contains an unpaired surrogate");
                }
                index++;
            } else if (Character.isLowSurrogate(current)) {
                throw new IllegalArgumentException(label + " contains an unpaired surrogate");
            }
        }
    }

    private static void requireEncodedBound(String value) {
        // The caller will append one delimiter byte when writing the frame.
        if (value.getBytes(StandardCharsets.UTF_8).length > MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("encoded owner-open frame exceeds the byte bound");
        }
    }
}
