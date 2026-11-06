package org.trillionnium.owneropen;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.ArrayList;
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

    public static String turnInspect(Map<String, Object> turnScope, String requestSha256,
            long inclusiveCursor, int limit) {
        if (inclusiveCursor < 0 || limit < 1 || limit > 4096
                || requestSha256 == null || !requestSha256.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("invalid scoped turn inspection");
        }
        return "{\"kind\":\"turn.inspect\",\"payload\":{" + RecoveryPlan.members(RecoveryPlan.scope(turnScope, false))
                + ",\"request_sha256\":" + quote(requestSha256)
                + ",\"inclusive_cursor\":" + inclusiveCursor + ",\"limit\":" + limit + "}}";
    }

    /** Explicit read-only recovery. Feed decoded Host objects, never substring matches.
     * Unknown scopes and retained-prefix gaps stay unresolved; this never dispatches effects.
     */
    public static final class RecoveryPlan {
        public static final String PROTOCOL = "scoped_cursor_v1";
        private static final String[] TURN_FIELDS = {
            "session_id", "profile_id", "task_id", "turn_id", "turn_stream_id"
        };
        private final Map<String, String> controlScope;
        private final List<RecoveryRange> ranges = new ArrayList<>();
        private final String requestSha256;
        private int pages;
        private RecoveryRange pending;

        public RecoveryPlan(Map<String, Object> gapFrame, Map<String, Object> helloPayload,
                String turnRequestSha256) {
            if (!list(helloPayload.get("resync_protocols")).contains(PROTOCOL)) {
                throw new IllegalArgumentException("Host has not advertised scoped cursor recovery");
            }
            Map<String, Object> gap = object(gapFrame.get("payload"));
            if (!PROTOCOL.equals(gap.get("resync_protocol"))
                    || !Boolean.TRUE.equals(gap.get("cursor_scopes_complete"))) {
                throw new IllegalArgumentException("gap requires explicit reconciliation");
            }
            controlScope = scope(gapFrame, false);
            requestSha256 = turnRequestSha256;
            for (Object value : list(gap.get("required_resumes"))) {
                Map<String, Object> range = object(value);
                String domain = (String) range.get("cursor_domain");
                boolean job = "job_runtime_event".equals(domain)
                        || "job_journal_record".equals(domain);
                if (!job && !"transport_event".equals(domain)) {
                    throw new IllegalArgumentException("unknown cursor domain");
                }
                Map<String, String> selectedScope = scope(object(range.get("cursor_scope")), job);
                long first = number(range.get("first_missing_cursor"));
                long last = number(range.get("last_missing_cursor"));
                long required = number(range.get("required_resume_cursor"));
                if (last < first || last == Long.MAX_VALUE || required != last + 1) {
                    throw new IllegalArgumentException("invalid missing cursor range");
                }
                for (RecoveryRange existing : ranges) {
                    if (domain.equals(existing.domain) && selectedScope.equals(existing.scope)) {
                        throw new IllegalArgumentException("duplicate cursor scope");
                    }
                }
                ranges.add(new RecoveryRange(domain, selectedScope, first, required));
            }
            if (ranges.isEmpty() || ranges.size() > 64) {
                throw new IllegalArgumentException("recovery requires 1..64 cursor scopes");
            }
        }

        public String pendingCursorDomain() {
            return pending == null ? null : pending.domain;
        }

        public boolean isComplete() {
            for (RecoveryRange range : ranges) {
                if (range.cursor < range.required) return false;
            }
            return true;
        }

        public String nextInspection() {
            if (pending != null) throw new IllegalArgumentException("inspection request is already pending");
            for (RecoveryRange range : ranges) {
                if (range.cursor >= range.required) continue;
                pending = range;
                String members = members(range.scope) + ",\"limit\":256";
                if ("transport_event".equals(range.domain)) {
                    if (requestSha256 == null || !requestSha256.matches("[0-9a-f]{64}")) {
                        throw new IllegalArgumentException("turn recovery needs the accepted request digest");
                    }
                    members += ",\"request_sha256\":" + quote(requestSha256)
                            + ",\"inclusive_cursor\":" + range.cursor;
                    return "{\"kind\":\"turn.inspect\",\"payload\":{" + members + "}}";
                }
                members += "job_journal_record".equals(range.domain)
                        ? ",\"inclusive_cursor\":0,\"durable_inclusive_cursor\":" + range.cursor
                        : ",\"inclusive_cursor\":" + range.cursor + ",\"durable_inclusive_cursor\":0";
                return "{\"kind\":\"job.inspect\",\"payload\":{" + members + "}}";
            }
            return null;
        }

        public boolean observeInspection(Map<String, Object> frame) {
            String kind = (String) frame.get("kind");
            if (!"turn.inspect.result".equals(kind) && !"job.inspect.result".equals(kind)) return false;
            Map<String, Object> payload = object(frame.get("payload"));
            for (RecoveryRange range : ranges) {
                if (range != pending) continue;
                boolean job = !"transport_event".equals(range.domain);
                if (!kind.equals(job ? "job.inspect.result" : "turn.inspect.result")
                        || !scope(frame, job).equals(range.scope)) continue;
                if (!"found".equals(payload.get("status"))
                        || !Boolean.FALSE.equals(payload.get("side_effects"))
                        || !Boolean.FALSE.equals(payload.get("automatic_redispatch"))) {
                    throw new IllegalArgumentException("inspection did not return read-only durable observations");
                }
                Map<String, Object> page = payload;
                String startField = "inclusive_cursor", nextField = "next_cursor", recordsField = "frames";
                if ("job_runtime_event".equals(range.domain)) {
                    if (!range.domain.equals(payload.get("runtime_cursor_domain"))) {
                        throw new IllegalArgumentException("runtime cursor domain mismatch");
                    }
                    page = object(payload.get("inspection"));
                    if (!Boolean.FALSE.equals(page.get("resync_required")) || page.get("gap") != null
                            || number(page.get("oldest_available_cursor")) > range.cursor) {
                        throw new IllegalArgumentException("retained runtime prefix is missing; reconcile explicitly");
                    }
                    recordsField = "runtime_events";
                } else if ("job_journal_record".equals(range.domain)) {
                    if (!range.domain.equals(payload.get("durable_cursor_domain"))
                            || !"durable".equals(object(payload.get("inspection")).get("event_log_status"))) {
                        throw new IllegalArgumentException("durable journal is unavailable");
                    }
                    startField = "durable_inclusive_cursor";
                    nextField = "durable_next_cursor";
                    recordsField = "durable_records";
                } else if (!"durable_event_store".equals(payload.get("source"))) {
                    throw new IllegalArgumentException("turn cursor source mismatch");
                }
                long start = number(page.get(startField)), next = number(page.get(nextField));
                List<?> records = list(page.get(recordsField));
                if (start != range.cursor || next <= start || next - start != records.size()) {
                    throw new IllegalArgumentException("inspection omitted a prefix or made no contiguous progress");
                }
                if ("transport_event".equals(range.domain)) {
                    for (int index = 0; index < records.size(); index++) {
                        Object identity = object(records.get(index)).get("event_id");
                        if (!(identity instanceof String) || !((String) identity).endsWith("-event-" + (start + index))) {
                            throw new IllegalArgumentException("turn page event identity does not match its cursor");
                        }
                    }
                }
                if ("job_runtime_event".equals(range.domain)) {
                    for (int index = 0; index < records.size(); index++) {
                        if (number(object(records.get(index)).get("seq")) != start + index) {
                            throw new IllegalArgumentException("runtime page has an ordinal gap");
                        }
                    }
                }
                if ("job_journal_record".equals(range.domain)) {
                    for (int index = 0; index < records.size(); index++) {
                        if (number(object(records.get(index)).get("job_record_seq")) != start + index) {
                            throw new IllegalArgumentException("journal page has an ordinal gap");
                        }
                    }
                }
                if (++pages > 4096) throw new IllegalArgumentException("recovery page budget exhausted");
                range.cursor = next;
                pending = null;
                return true;
            }
            return false;
        }

        public String resume(long controlSequence) {
            if (controlSequence < 0 || pending != null || !isComplete()) {
                throw new IllegalArgumentException("every recovery range must be inspected before resume");
            }
            StringBuilder cursors = new StringBuilder("[");
            for (RecoveryRange range : ranges) {
                if (cursors.length() > 1) cursors.append(',');
                cursors.append("{\"cursor_domain\":").append(quote(range.domain))
                        .append(",\"cursor_scope\":{").append(members(range.scope))
                        .append("},\"resumed_through_cursor\":").append(range.cursor).append('}');
            }
            cursors.append(']');
            return "{\"kind\":\"stream.resume\",\"payload\":{" + members(controlScope)
                    + ",\"control_seq\":" + controlSequence + ",\"resync_protocol\":" + quote(PROTOCOL)
                    + ",\"resumed_cursors\":" + cursors + "}}";
        }

        private static Map<String, String> scope(Map<String, Object> value, boolean job) {
            Map<String, String> result = new LinkedHashMap<>();
            for (String field : TURN_FIELDS) {
                Object selected = value.get(field);
                if (!(selected instanceof String)) throw new IllegalArgumentException("missing recovery scope " + field);
                requireId((String) selected, field);
                result.put(field, (String) selected);
            }
            if (value.get("stream_id") != null && !value.get("stream_id").equals(result.get("turn_stream_id"))) {
                throw new IllegalArgumentException("conflicting recovery stream aliases");
            }
            if (job) {
                Object selected = value.get("job_id");
                if (!(selected instanceof String)) throw new IllegalArgumentException("missing recovery job_id");
                requireId((String) selected, "job_id");
                result.put("job_id", (String) selected);
            } else if (value.get("job_id") != null) {
                throw new IllegalArgumentException("turn cursor scope cannot include job_id");
            }
            return result;
        }

        @SuppressWarnings("unchecked")
        private static Map<String, Object> object(Object value) {
            if (!(value instanceof Map)) throw new IllegalArgumentException("expected recovery object");
            return (Map<String, Object>) value;
        }
        private static List<?> list(Object value) {
            if (!(value instanceof List)) throw new IllegalArgumentException("expected recovery list");
            return (List<?>) value;
        }
        private static long number(Object value) {
            if (!(value instanceof Long) && !(value instanceof Integer)) {
                throw new IllegalArgumentException("cursor must be an integer");
            }
            long result = ((Number) value).longValue();
            if (result < 0) throw new IllegalArgumentException("cursor outside client signed integer range");
            return result;
        }
        private static String members(Map<String, String> scope) {
            StringBuilder output = new StringBuilder();
            for (Map.Entry<String, String> field : scope.entrySet()) {
                if (output.length() > 0) output.append(',');
                output.append(quote(field.getKey())).append(':').append(quote(field.getValue()));
            }
            return output.toString();
        }
        private static final class RecoveryRange {
            final String domain;
            final Map<String, String> scope;
            final long required;
            long cursor;
            RecoveryRange(String domain, Map<String, String> scope, long cursor, long required) {
                this.domain = domain; this.scope = scope; this.cursor = cursor; this.required = required;
            }
        }
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
