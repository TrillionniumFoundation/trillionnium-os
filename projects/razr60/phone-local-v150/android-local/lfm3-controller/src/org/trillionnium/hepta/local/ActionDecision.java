package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * A single local-model decision. Parsing does not authorize or execute an action.
 * The controller must still validate the exact current observation, package,
 * node, viewport and action preconditions.
 */
public final class ActionDecision {
    private static final int MAX_JSON_UTF8_BYTES = 16384;
    private static final int MAX_TEXT_UTF8_BYTES = 4096;
    private static final Pattern OBSERVATION_ID = Pattern.compile("[0-9a-fA-F]{32}");
    private static final Pattern NODE_ID = Pattern.compile("n[0-9]{1,5}");

    public final String action;
    public final String observationId;
    public final String packageName;
    public final String nodeId;
    public final String nodeLabel;
    public final String text;
    public final String direction;
    public final String status;
    public final String summary;
    public final String reason;
    public final String query;
    public final int x;
    public final int y;
    public final int durationMs;
    public final int offset;

    private ActionDecision(String action, String observationId, String packageName,
                           String nodeId, String nodeLabel, String text, String direction, String status,
                           String summary, String reason, int x, int y, int durationMs, String query, int offset) {
        this.action = action;
        this.observationId = observationId;
        this.packageName = packageName;
        this.nodeId = nodeId;
        this.nodeLabel = nodeLabel;
        this.text = text;
        this.direction = direction;
        this.status = status;
        this.summary = summary;
        this.reason = reason;
        this.x = x;
        this.y = y;
        this.durationMs = durationMs;
        this.query = query;
        this.offset = offset;
    }

    public static final class InvalidActionException extends Exception {
        private static final long serialVersionUID = 1L;

        public InvalidActionException(String message) {
            super(message);
        }
    }

    /** Accepts exactly one flat JSON object; no recovery or substring extraction. */
    public static ActionDecision parse(String raw) throws InvalidActionException {
        return parse(raw, ObservedTargetLabels.ACTION_SCHEMA);
    }

    /** The caller selects an explicit protocol; older or unknown node schemas are not inferred. */
    public static ActionDecision parse(String raw, String schema) throws InvalidActionException {
        require(ObservedTargetLabels.ACTION_SCHEMA.equals(schema), "Unknown action schema");
        require(raw != null && !raw.isEmpty(), "Empty model output");
        require(raw.length() <= MAX_JSON_UTF8_BYTES, "Model output exceeds size bound");
        validateUnicode(raw);
        require(utf8Bytes(raw) <= MAX_JSON_UTF8_BYTES, "Model output exceeds 16384 UTF-8 bytes");
        Map<String, Object> fields = new JsonParser(raw).readObject();
        String action = string(fields, "action");
        String observationId = string(fields, "observation_id");
        require(OBSERVATION_ID.matcher(observationId).matches(), "Invalid observation_id");
        String packageName = string(fields, "package");
        require(validPackageName(packageName), "Invalid package");
        String reason = fields.containsKey("reason") ? string(fields, "reason") : "";
        require(codePoints(reason) <= 256, "reason exceeds 256 characters");

        String nodeId = null;
        String nodeLabel = null;
        String text = null;
        String direction = null;
        String status = null;
        String summary = null;
        int x = -1;
        int y = -1;
        int durationMs = -1;
        String query = null;
        int offset = -1;

        switch (action) {
            case "open":
                requireFields(fields, "package");
                break;
            case "find_app":
                requireFields(fields, "package", "query", "offset");
                query = string(fields, "query");
                require(query.indexOf('\0') < 0, "query contains NUL");
                require(codePoints(query) <= 64, "query exceeds 64 characters");
                offset = integer(fields, "offset", 0, 4095);
                break;
            case "click":
                if (fields.containsKey("node_id")) {
                    requireFields(fields, "package", "node_label", "node_id");
                    nodeLabel = nodeLabel(fields);
                    nodeId = node(fields);
                } else {
                    requireFields(fields, "package", "x", "y");
                    x = integer(fields, "x", 0, 1000);
                    y = integer(fields, "y", 0, 1000);
                }
                break;
            case "type":
                requireFields(fields, "package", "node_label", "node_id", "text");
                nodeLabel = nodeLabel(fields);
                nodeId = node(fields);
                text = string(fields, "text");
                require(text.indexOf('\0') < 0, "text contains NUL");
                require(utf8Bytes(text) <= MAX_TEXT_UTF8_BYTES, "text exceeds 4096 UTF-8 bytes");
                break;
            case "scroll":
                requireFields(fields, "package", "node_label", "node_id", "direction");
                nodeLabel = nodeLabel(fields);
                nodeId = node(fields);
                direction = string(fields, "direction");
                require(oneOf(direction, "forward", "backward", "up", "down", "left", "right"),
                        "Invalid scroll direction");
                break;
            case "back":
            case "home":
                requireFields(fields, "package");
                break;
            case "wait":
                requireFields(fields, "package", "duration_ms");
                durationMs = integer(fields, "duration_ms", 100, 2000);
                break;
            case "done":
                requireFields(fields, "package", "status", "summary");
                status = string(fields, "status");
                require(oneOf(status, "success", "partial", "failure"), "Invalid done status");
                summary = string(fields, "summary");
                require(!summary.isEmpty() && codePoints(summary) <= 1024,
                        "summary must contain 1..1024 characters");
                break;
            default:
                throw new InvalidActionException("Unsupported action");
        }
        return new ActionDecision(action, observationId, packageName, nodeId, nodeLabel, text,
                direction, status, summary, reason, x, y, durationMs, query, offset);
    }

    public static String schemaGuide() {
        return "Return exactly one flat JSON object, with double-quoted keys and strings. "
                + "Every action requires action, observation_id (the exact current 32-hex ID), "
                + "and package (the current verified package; open names its target package). "
                + "reason is optional and at most 256 Unicode characters. "
                + "Allowed actions and additional fields: "
                + "open: no additional fields; "
                + "find_app: query,offset (read-only installed launcher search, not an app launch); "
                + "click: either node_label,node_id or both x,y, never both forms; "
                + "type: node_label,node_id,text; "
                + "scroll: node_label,node_id,direction; "
                + "back: no additional fields; home: no additional fields; "
                + "wait: duration_ms; done: status,summary. "
                + "node_id is n followed by 1..5 ASCII digits. "
                + "node_label must precede node_id and copy its exact supplied label, including empty or duplicate labels. "
                + "The label and ID are a pair from this observation; reason never identifies or changes the target. "
                + "x,y are canonical integers 0..1000 from the current observation. "
                + "duration_ms is a canonical integer 100..2000. "
                + "query has 0..64 Unicode characters, no NUL; empty query browses apps. "
                + "offset is a canonical integer 0..4095; use the returned next_offset to page. "
                + "direction is forward,backward,up,down,left,right. "
                + "status is success,partial,failure; summary has 1..1024 Unicode characters. "
                + "text preserves exact Unicode and escaped newlines, contains no NUL, "
                + "and is at most 4096 UTF-8 bytes. "
                + "No other fields, duplicate keys, nested values, booleans, null, "
                + "floating-point numbers, Markdown, explanations, or trailing content. "
                + "The entire JSON is at most 16384 UTF-8 bytes.";
    }

    private static void requireFields(Map<String, Object> fields, String... required)
            throws InvalidActionException {
        Set<String> allowed = new HashSet<String>(
                Arrays.asList("action", "observation_id", "reason"));
        for (String name : required) {
            require(fields.containsKey(name), "Missing field: " + name);
            allowed.add(name);
        }
        for (String name : fields.keySet()) {
            require(allowed.contains(name), "Field '"+name+"' is not allowed for action '"+fields.get("action")+"'");
        }
    }

    private static String string(Map<String, Object> fields, String name)
            throws InvalidActionException {
        Object value = fields.get(name);
        require(value instanceof String, "Missing or non-string field: " + name);
        return (String) value;
    }

    private static String node(Map<String, Object> fields) throws InvalidActionException {
        String value = string(fields, "node_id");
        require(NODE_ID.matcher(value).matches(), "Invalid node_id");
        return value;
    }

    private static String nodeLabel(Map<String, Object> fields) throws InvalidActionException {
        String label = string(fields, "node_label");
        try { ObservedTargetLabels.requireProjectedLabel(label); }
        catch (IllegalArgumentException error) { throw new InvalidActionException(error.getMessage()); }
        for (String key : fields.keySet()) {
            if ("node_label".equals(key)) return label;
            require(!"node_id".equals(key), "node_label must precede node_id");
        }
        throw new InvalidActionException("Missing node_label");
    }

    private static int integer(Map<String, Object> fields, String name, int minimum, int maximum)
            throws InvalidActionException {
        Object value = fields.get(name);
        require(value instanceof Integer, "Missing or non-integer field: " + name);
        int number = ((Integer) value).intValue();
        require(number >= minimum && number <= maximum, "Out-of-range field: " + name);
        return number;
    }

    private static boolean oneOf(String value, String... allowed) {
        for (String item : allowed) {
            if (item.equals(value)) {
                return true;
            }
        }
        return false;
    }

    private static int codePoints(String value) {
        return value.codePointCount(0, value.length());
    }

    /**
     * Equivalent to [A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+.
     * Iterate segments so a long model string cannot overflow a regex backtracking stack.
     */
    private static boolean validPackageName(String value) {
        // System dialogs legitimately expose package="android". This only parses
        // identity: open still needs a fresh installed launcher catalogue entry.
        if ("android".equals(value)) return true;
        boolean firstInSegment = true;
        boolean sawDot = false;
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (ch == '.') {
                if (firstInSegment) return false;
                firstInSegment = true;
                sawDot = true;
            } else {
                boolean letter = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
                if (firstInSegment) {
                    if (!letter) return false;
                    firstInSegment = false;
                } else if (!letter && !(ch >= '0' && ch <= '9') && ch != '_') {
                    return false;
                }
            }
        }
        return sawDot && !firstInSegment;
    }

    private static int utf8Bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8).length;
    }

    private static void validateUnicode(String value) throws InvalidActionException {
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (Character.isHighSurrogate(ch)) {
                require(i + 1 < value.length() && Character.isLowSurrogate(value.charAt(i + 1)),
                        "Unpaired UTF-16 high surrogate");
                i++;
            } else {
                require(!Character.isLowSurrogate(ch), "Unpaired UTF-16 low surrogate");
            }
        }
    }

    private static void require(boolean condition, String message)
            throws InvalidActionException {
        if (!condition) {
            throw new InvalidActionException(message);
        }
    }

    /** Only JSON strings and canonical integral tokens are admitted as values. */
    private static final class JsonParser {
        private final String source;
        private int position;

        JsonParser(String source) {
            this.source = source;
        }

        Map<String, Object> readObject() throws InvalidActionException {
            Map<String, Object> fields = new LinkedHashMap<String, Object>();
            whitespace();
            expect('{');
            whitespace();
            if (!take('}')) {
                while (true) {
                    require(peek('"'), "Expected double-quoted JSON key");
                    String key = readString();
                    require(!fields.containsKey(key), "Duplicate JSON key");
                    whitespace();
                    expect(':');
                    whitespace();
                    Object value;
                    if (peek('"')) {
                        value = readString();
                    } else {
                        value = readInteger();
                    }
                    fields.put(key, value);
                    whitespace();
                    if (take('}')) {
                        break;
                    }
                    expect(',');
                    whitespace();
                }
            }
            whitespace();
            require(position == source.length(), "Trailing JSON content");
            return fields;
        }

        private String readString() throws InvalidActionException {
            expect('"');
            StringBuilder value = new StringBuilder();
            while (position < source.length()) {
                char ch = source.charAt(position++);
                if (ch == '"') {
                    String decoded = value.toString();
                    validateUnicode(decoded);
                    return decoded;
                }
                require(ch >= 0x20, "Unescaped JSON control character");
                if (ch != '\\') {
                    value.append(ch);
                    continue;
                }
                require(position < source.length(), "Incomplete JSON escape");
                char escaped = source.charAt(position++);
                switch (escaped) {
                    case '"': value.append('"'); break;
                    case '\\': value.append('\\'); break;
                    case '/': value.append('/'); break;
                    case 'b': value.append('\b'); break;
                    case 'f': value.append('\f'); break;
                    case 'n': value.append('\n'); break;
                    case 'r': value.append('\r'); break;
                    case 't': value.append('\t'); break;
                    case 'u':
                        require(source.length() - position >= 4, "Incomplete Unicode escape");
                        int codeUnit = 0;
                        for (int i = 0; i < 4; i++) {
                            char digit = source.charAt(position++);
                            int hex = hexDigit(digit);
                            require(hex >= 0, "Invalid Unicode escape");
                            codeUnit = (codeUnit << 4) | hex;
                        }
                        value.append((char) codeUnit);
                        break;
                    default:
                        throw new InvalidActionException("Invalid JSON escape");
                }
            }
            throw new InvalidActionException("Unterminated JSON string");
        }

        private Integer readInteger() throws InvalidActionException {
            int start = position;
            boolean negative = take('-');
            require(position < source.length(), "Missing integer");
            if (take('0')) {
                require(!negative, "Negative zero is not a canonical action integer");
                require(position == source.length() || !asciiDigit(source.charAt(position)),
                        "Leading zero in integer");
            } else {
                require(position < source.length() && source.charAt(position) >= '1'
                                && source.charAt(position) <= '9',
                        "Only string or canonical integer JSON values are permitted");
                while (position < source.length() && asciiDigit(source.charAt(position))) {
                    position++;
                }
            }
            if (position < source.length()) {
                char next = source.charAt(position);
                require(next == ',' || next == '}' || isWhitespace(next),
                        "Invalid integer token");
            }
            try {
                return Integer.valueOf(source.substring(start, position));
            } catch (NumberFormatException error) {
                throw new InvalidActionException("Integer exceeds 32-bit range");
            }
        }

        private static int hexDigit(char value) {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            if (value >= 'A' && value <= 'F') return value - 'A' + 10;
            return -1;
        }

        private static boolean asciiDigit(char value) {
            return value >= '0' && value <= '9';
        }

        private static boolean isWhitespace(char value) {
            return value == ' ' || value == '\t' || value == '\r' || value == '\n';
        }

        private void whitespace() {
            while (position < source.length() && isWhitespace(source.charAt(position))) {
                position++;
            }
        }

        private boolean peek(char expected) {
            return position < source.length() && source.charAt(position) == expected;
        }

        private boolean take(char expected) {
            if (!peek(expected)) return false;
            position++;
            return true;
        }

        private void expect(char expected) throws InvalidActionException {
            require(take(expected), "Malformed JSON object");
        }
    }
}
