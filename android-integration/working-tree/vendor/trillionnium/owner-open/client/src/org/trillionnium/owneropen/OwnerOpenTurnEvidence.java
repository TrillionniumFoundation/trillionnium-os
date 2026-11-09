package org.trillionnium.owneropen;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.nio.charset.StandardCharsets;

/** Bounded mechanical readback parser; acceptance is never an effect outcome or producer epoch. */
public final class OwnerOpenTurnEvidence {
    public final String kind;
    public final String brokerRequestId;
    public final String sessionId;
    public final String taskId;
    public final String turnId;
    public final String requestSha256;
    public final boolean completeReadback;

    private OwnerOpenTurnEvidence(Map<String, Object> envelope, Map<String, Object> frame, String digest, boolean complete) {
        brokerRequestId = text(envelope, "request_id");
        if (!brokerRequestId.equals(text(envelope, "broker_request_id"))) fail("conflicting broker request ID aliases");
        kind = text(frame, "kind");
        sessionId = text(frame, "session_id");
        taskId = text(frame, "task_id");
        turnId = text(frame, "turn_id");
        if (!"owner-open".equals(text(frame, "profile_id"))) fail("unexpected profile");
        String stream = OwnerOpenFrame.turnStreamId(sessionId, taskId, turnId);
        if (!stream.equals(text(frame, "turn_stream_id")) || !stream.equals(text(frame, "stream_id")))
            fail("unexpected turn stream scope");
        if (!"host_to_client".equals(frame.get("direction"))) fail("wrong Host frame direction");
        String brokerDigest = text(envelope, "broker_request_sha256");
        if (!brokerDigest.matches("[0-9a-f]{64}")) fail("invalid broker wire digest");
        long upstream = nonnegative(envelope, "broker_request_upstream_seq");
        if (!brokerRequestId.equals(frame.get("broker_request_id"))
                || !brokerDigest.equals(frame.get("broker_request_sha256"))
                || upstream != nonnegative(frame, "broker_request_upstream_seq"))
            fail("broker/frame correlation conflict");
        Map<String, Object> payload = object(frame.get("payload"));
        for (String key : new String[] {"broker_request_id", "broker_request_sha256", "broker_request_upstream_seq"})
            if (payload.containsKey(key) && !frame.get(key).equals(payload.get(key))) fail("payload correlation conflict");
        if (digest == null || !digest.matches("[0-9a-f]{64}")) fail("invalid request digest");
        requestSha256 = digest;
        completeReadback = complete;
    }

    public boolean matches(OwnerOpenClientState state) {
        return sessionId.equals(state.sessionId) && taskId.equals(state.taskId)
                && turnId.equals(state.turnId) && requestSha256.equals(state.turnRequestSha256);
    }

    /** Parses existing broker result envelopes only, never kind-like text inside model payloads. */
    public static OwnerOpenTurnEvidence parse(String raw) {
        Map<String, Object> envelope = object(new Parser(raw).parse());
        if (!"result".equals(envelope.get("kind"))) return null;
        Map<String, Object> frame = object(envelope.get("frame"));
        String kind = text(frame, "kind");
        if (!"turn.accepted".equals(kind) && !"turn.inspect.result".equals(kind)) return null;
        if (!"org.trillionnium.owner-open.connection-broker-wire.v1".equals(envelope.get("schema"))
                || !Boolean.FALSE.equals(envelope.get("automatic_redispatch"))) fail("invalid broker result");
        Map<String, Object> payload = object(frame.get("payload"));
        if ("turn.accepted".equals(kind)) {
            if (!"turn.start".equals(envelope.get("broker_request_kind"))
                    || !"accepted".equals(payload.get("status"))) fail("invalid acceptance");
            return new OwnerOpenTurnEvidence(envelope, frame, text(payload, "turn_request_sha256"), false);
        }
        if (!"turn.inspect".equals(envelope.get("broker_request_kind"))
                || !Boolean.FALSE.equals(payload.get("side_effects"))
                || !Boolean.FALSE.equals(payload.get("automatic_redispatch"))
                || !"durable_event_store".equals(payload.get("source"))) fail("invalid inspection source");
        OwnerOpenTurnEvidence selected = new OwnerOpenTurnEvidence(envelope, frame, text(payload, "request_sha256"), false);
        if (payload.containsKey("turn_request_sha256")
                && !selected.requestSha256.equals(payload.get("turn_request_sha256")))
            fail("inspection context digest conflict");
        long start = nonnegative(payload, "inclusive_cursor");
        long next = nonnegative(payload, "next_cursor");
        long total = nonnegative(payload, "total_events");
        Object complete = payload.get("complete"), more = payload.get("has_more");
        if (!(complete instanceof Boolean) || !(more instanceof Boolean) || start != 0
                || next > total || !(payload.get("frames") instanceof List<?>)) fail("invalid inspection bounds");
        List<?> frames = (List<?>) payload.get("frames");
        if (frames.size() > 256 || next != frames.size()
                || Boolean.TRUE.equals(more) != (next < total)) fail("unexpected zero-cursor page");
        java.util.Set<String> eventIds = new java.util.HashSet<>();
        String selectedStream = text(frame, "turn_stream_id");
        long priorHostSequence = -1;
        int accepted = 0;
        boolean terminal = false;
        boolean knownTerminal = false;
        for (Object item : frames) {
            if (terminal) fail("inspection events after terminal");
            Map<String, Object> event = object(item);
            String eventId = text(event, "event_id");
            if (eventId.isEmpty() || !eventIds.add(eventId)) fail("duplicate/empty event identity");
            long sequence = nonnegative(event, "host_seq");
            nonnegative(event, "seq");
            if (sequence <= priorHostSequence) fail("non-increasing stored Host sequence");
            priorHostSequence = sequence;
            if (!"host_to_client".equals(event.get("direction"))
                    || !selectedStream.equals(event.get("turn_stream_id"))
                    || !selectedStream.equals(event.get("stream_id"))) fail("stored frame direction/stream conflict");
            Map<String, Object> eventPayload = object(event.get("payload"));
            if (!selected.requestSha256.equals(eventPayload.get("turn_request_sha256")))
                fail("inspection event request digest conflict");
            if (!selected.sessionId.equals(event.get("session_id"))
                    || !selected.taskId.equals(event.get("task_id"))
                    || !selected.turnId.equals(event.get("turn_id"))
                    || !"owner-open".equals(event.get("profile_id"))) fail("mixed inspection scope");
            if ("turn.accepted".equals(event.get("kind"))) {
                if (!"accepted".equals(object(event.get("payload")).get("status"))
                        || !selected.requestSha256.equals(object(event.get("payload")).get("turn_request_sha256")))
                    fail("inspection request digest conflict");
                if (++accepted != 1) fail("duplicate inspection acceptance");
            }
            if ("turn.end".equals(event.get("kind"))) {
                terminal = true;
                String status = text(eventPayload, "status");
                knownTerminal = status.equals("completed") || status.equals("cancelled")
                        || status.equals("provider_failed") || status.equals("provider_panicked")
                        || status.equals("host_failed");
                // Unknown/missing terminal observations never permit replacing the sole identity.
            }
        }
        boolean closedPage = "found".equals(payload.get("status")) && Boolean.TRUE.equals(complete)
                && Boolean.FALSE.equals(more) && total > 0 && next == total && accepted == 1 && terminal && knownTerminal;
        return new OwnerOpenTurnEvidence(envelope, frame, selected.requestSha256, closedPage);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map<?, ?>)) fail("expected JSON object");
        return (Map<String, Object>) value;
    }

    private static String text(Map<String, Object> value, String key) {
        Object found = value.get(key);
        if (!(found instanceof String) || ((String) found).length() > 256) fail("invalid " + key);
        return (String) found;
    }

    private static long nonnegative(Map<String, Object> value, String key) {
        Object found = value.get(key);
        if (!(found instanceof Long) || (Long) found < 0) fail("invalid " + key);
        return (Long) found;
    }

    private static void fail(String message) { throw new IllegalArgumentException(message); }

    // Reject duplicate keys at every level and bounded depth/node count. Other numeric JSON
    // forms remain opaque and cannot satisfy the exact integer cursor fields above.
    private static final class Parser {
        final String raw;
        int offset;
        int nodes;
        Parser(String raw) {
            if (raw == null || raw.length() >= OwnerOpenFrame.MAX_LINE_BYTES
                    || raw.getBytes(StandardCharsets.UTF_8).length >= OwnerOpenFrame.MAX_LINE_BYTES)
                fail("evidence exceeds wire bound");
            this.raw = raw;
        }
        Object parse() {
            Object value = value(0);
            whitespace();
            if (offset != raw.length()) fail("trailing evidence bytes");
            return value;
        }
        Object value(int depth) {
            if (depth > 32 || ++nodes > 65_536) fail("evidence structure exceeds bound");
            whitespace();
            if (offset >= raw.length()) fail("truncated JSON");
            char ch = raw.charAt(offset);
            if (ch == '"') return string();
            if (ch == '{') {
                offset++;
                Map<String, Object> map = new LinkedHashMap<>();
                if (take('}')) return map;
                do {
                    whitespace();
                    if (offset >= raw.length() || raw.charAt(offset) != '"') fail("invalid object key");
                    String key = string();
                    if (map.containsKey(key) || !take(':')) fail("duplicate key or missing colon");
                    map.put(key, value(depth + 1));
                    if (take('}')) return map;
                } while (take(','));
                fail("invalid object delimiter");
            }
            if (ch == '[') {
                offset++;
                List<Object> list = new ArrayList<>();
                if (take(']')) return list;
                do {
                    list.add(value(depth + 1));
                    if (take(']')) return list;
                } while (take(','));
                fail("invalid array delimiter");
            }
            for (String word : new String[] {"true", "false", "null"}) {
                if (raw.startsWith(word, offset)) {
                    offset += word.length();
                    return word.equals("null") ? null : Boolean.valueOf(word);
                }
            }
            int first = offset;
            if (ch == '-') offset++;
            if (offset >= raw.length()) fail("invalid number");
            if (raw.charAt(offset) == '0') offset++;
            else {
                if (raw.charAt(offset) < '1' || raw.charAt(offset) > '9') fail("invalid number");
                digits();
            }
            if (offset < raw.length() && raw.charAt(offset) == '.') {
                offset++; if (!digits()) fail("invalid fraction");
            }
            if (offset < raw.length() && (raw.charAt(offset) == 'e' || raw.charAt(offset) == 'E')) {
                offset++;
                if (offset < raw.length() && (raw.charAt(offset) == '+' || raw.charAt(offset) == '-')) offset++;
                if (!digits()) fail("invalid exponent");
            }
            String number = raw.substring(first, offset);
            if (number.matches("-?(0|[1-9][0-9]*)")) {
                try { return Long.valueOf(number); } catch (NumberFormatException outsideSignedRange) { }
            }
            return new NumberToken(number);
        }
        boolean digits() {
            int first = offset;
            while (offset < raw.length() && raw.charAt(offset) >= '0' && raw.charAt(offset) <= '9') offset++;
            return offset > first;
        }
        String string() {
            offset++;
            StringBuilder text = new StringBuilder();
            while (offset < raw.length()) {
                char ch = raw.charAt(offset++);
                if (ch == '"') {
                    // Reuse actual wire UTF-16 validation, including escaped surrogate pairs.
                    OwnerOpenFrame.quote(text.toString());
                    return text.toString();
                }
                if (ch < 0x20) fail("unescaped control character");
                if (ch == '\\') {
                    if (offset >= raw.length()) fail("truncated escape");
                    ch = raw.charAt(offset++);
                    switch (ch) {
                        case '"': case '\\': case '/': break;
                        case 'b': ch = '\b'; break;
                        case 'f': ch = '\f'; break;
                        case 'n': ch = '\n'; break;
                        case 'r': ch = '\r'; break;
                        case 't': ch = '\t'; break;
                        case 'u':
                            if (offset + 4 > raw.length()) fail("truncated Unicode escape");
                            String hex = raw.substring(offset, offset + 4);
                            if (!hex.matches("[0-9a-fA-F]{4}")) fail("invalid Unicode escape");
                            ch = (char) Integer.parseInt(hex, 16); offset += 4; break;
                        default: fail("invalid escape");
                    }
                }
                text.append(ch);
            }
            fail("unterminated string"); return null;
        }
        boolean take(char expected) {
            whitespace();
            if (offset < raw.length() && raw.charAt(offset) == expected) { offset++; return true; }
            return false;
        }
        void whitespace() {
            while (offset < raw.length() && " \r\n\t".indexOf(raw.charAt(offset)) >= 0) offset++;
        }
    }
    private static final class NumberToken {
        final String value;
        NumberToken(String value) { this.value = value; }
    }
}
