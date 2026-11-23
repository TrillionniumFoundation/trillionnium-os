package org.trillionnium.hepta.background;

/** Closed local tool contracts shared by the ordinary app and background broker.
 * No Android dispatch, authorization, URI, model-supplied component or extras map.
 */
public final class FixedIntentTools {
    public static final String NOTES_CREATE = "notes.create";
    public static final String WEB_SEARCH = "web.search";

    private static final Profile NOTES = new Profile(NOTES_CREATE,
            "com.motorola.stylus", "com.motorola.stylus.note.text.TextNoteActivity",
            "android.intent.action.SEND", "text/plain", "android.intent.extra.TEXT", "draft_opened");
    private static final Profile SEARCH = new Profile(WEB_SEARCH,
            "com.zui.browser", "com.lenovo.browser.BrowserActivity",
            "android.intent.action.WEB_SEARCH", null, "query", "search_opened");

    private FixedIntentTools() { }

    /** Exact identifiers only; unknown actions have no executable profile. */
    public static Profile forAction(String action) {
        if (NOTES_CREATE.equals(action)) return NOTES;
        if (WEB_SEARCH.equals(action)) return SEARCH;
        return null;
    }

    public static boolean isTool(String action) {
        return forAction(action) != null;
    }

    public static final class Profile {
        public final String action;
        public final String packageName;
        public final String className;
        public final String intentAction;
        public final String mimeType;
        public final String extraName;
        /** Requested observation label; a launch acceptance does not prove opened or saved. */
        public final String outcome;
        public final int maxUtf8Bytes = 4096;
        public final int maxCodePoints = 1024;

        private Profile(String action, String packageName, String className,
                        String intentAction, String mimeType, String extraName, String outcome) {
            this.action = action;
            this.packageName = packageName;
            this.className = className;
            this.intentAction = intentAction;
            this.mimeType = mimeType;
            this.extraName = extraName;
            this.outcome = outcome;
        }

        /** Validate without trimming, normalizing or rewriting the caller's text.
         * LF/CR/tab and Unicode text are retained. Errors never echo the payload.
         */
        public void validatePayload(String payload) {
            if (payload == null || payload.isEmpty())
                throw new IllegalArgumentException("FIXED_TOOL_PAYLOAD_REQUIRED");
            if (payload.length() > maxCodePoints * 2)
                throw new IllegalArgumentException("FIXED_TOOL_PAYLOAD_TOO_LONG");
            int scalars = 0;
            int utf8Bytes = 0;
            boolean hasContent = false;
            for (int offset = 0; offset < payload.length();) {
                char first = payload.charAt(offset++);
                int point;
                if (Character.isHighSurrogate(first)) {
                    if (offset == payload.length() || !Character.isLowSurrogate(payload.charAt(offset)))
                        throw new IllegalArgumentException("FIXED_TOOL_PAYLOAD_INVALID_UNICODE");
                    point = Character.toCodePoint(first, payload.charAt(offset++));
                } else {
                    if (Character.isLowSurrogate(first))
                        throw new IllegalArgumentException("FIXED_TOOL_PAYLOAD_INVALID_UNICODE");
                    point = first;
                }
                if (point == 0) throw new IllegalArgumentException("FIXED_TOOL_PAYLOAD_NUL");
                scalars++;
                utf8Bytes += point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
                if (scalars > maxCodePoints || utf8Bytes > maxUtf8Bytes)
                    throw new IllegalArgumentException("FIXED_TOOL_PAYLOAD_TOO_LONG");
                hasContent |= !Character.isWhitespace(point) && !Character.isSpaceChar(point);
            }
            if (!hasContent) throw new IllegalArgumentException("FIXED_TOOL_PAYLOAD_BLANK");
        }
    }
}
