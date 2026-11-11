package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.trillionnium.hepta.background.FixedIntentTools;

/** A small, completely consumed natural note request, not a semantic planner.
 *
 * The body is one exact UTF-16 span of immutable OWNER. This class neither
 * dispatches nor grants tools. A standard supported note request asks for
 * persistence; save/list/reopen is the verification policy, not an invented
 * reminder or a claim that the user literally said "reopen".
 *
 * The older explicit save/list/reopen contract remains owned by its existing
 * parser. Unknown or ambiguous forms must keep their original authorization
 * text, rather than having a model-proposed payload masked out of it.
 */
public final class NotesOwnerIntent {
    public static final String SCHEMA = "hepta.notes-owner-intent.v1";
    /** The current complete list evidence requires body.length() < 95. */
    public static final int MAX_BODY_UTF16 = 94;
    private static final String SPACE = "[ \\t]*";
    private static final String POLITE = "(?:(?:请帮我|帮我|请)" + SPACE + ")?";
    private static final String END = SPACE + "[。.!！]?" + SPACE;
    private static final String PREFIX = "(?:记一下|记录一下|记个笔记|记一条笔记|新建(?:一条|一个)?(?:笔记|备忘录))[：:]";
    private static final String QUOTED_NEW = "(?:新建|创建|写)(?:一条|一个|一则)?(?:笔记|备忘录)"
            + "[，,]?" + SPACE + "(?:正文|内容)(?:为|是)[：:]?" + SPACE;
    private static final String DESTINATION = "(?:记到|记在|写入|保存到)(?:备忘录|笔记)(?:里|中)?";
    private static final Pattern UNQUOTED_PREFIX = full(SPACE + POLITE + PREFIX + "(.+)");
    // Do not consume an apparent polite word from the body: 请假申请记一下
    // must retain 请假申请, rather than silently changing it to 假申请.
    private static final Pattern UNQUOTED_SUFFIX = full(SPACE + "(.+?)[，,]?记一下" + END);
    private static final Pattern UNQUOTED_DESTINATION = full(SPACE + POLITE + "把(.+?)" + DESTINATION + END);
    private static final Pattern AMBIGUOUS_UNQUOTED = Pattern.compile(
            "[，,；;！!？?]|然后|随后|并且|同时|顺便|另外|接着|还要|再帮我|并帮我"
            + "|提醒|闹钟|报警|定时|日历"
            + "|记一下|记录一下|记到(?:备忘录|笔记)|记在(?:备忘录|笔记)"
            + "|(?:^|。)(?:只允许|仅允许|禁止|不得|不允许)");
    private static final Pattern DRAFT_ONLY = Pattern.compile(
            "(?:只|仅|先)(?:新建|打开|写)?(?:一个|一条)?(?:笔记)?草稿"
            + "|(?:新建|打开|写)(?:一个|一条)?(?:笔记)?草稿"
            + "|不要保存|不保存|不必保存|无需保存|只打开(?:笔记)?编辑器");
    private static final char[][] QUOTES = {{'“','”'}, {'‘','’'}, {'"','"'}, {'\'','\''}};

    private NotesOwnerIntent() { }

    public static final class Result {
        public final boolean supported;
        public final String body;
        public final int bodyStartUtf16;
        public final int bodyEndUtf16;
        public final String recognition;
        public final boolean saveAndReopenRequested;
        public final boolean draftOnly;
        public final boolean quotedBody;
        public final String reason;
        public final boolean grantsToolAuthority = false;
        private final String immutableOwner;

        private Result(String owner, boolean ok, String text, int start, int end,
                       String form, boolean draft, boolean quoted, String why) {
            immutableOwner = owner;
            supported = ok;
            body = text;
            bodyStartUtf16 = start;
            bodyEndUtf16 = end;
            recognition = form;
            saveAndReopenRequested = ok;
            draftOnly = draft;
            quotedBody = quoted;
            reason = why;
        }

        /** Only this parser's completely consumed exact OWNER can be masked.
         * Tool clauses outside the body remain byte-for-byte/offset-for-offset.
         * The caller must still run its original tool authorization compiler.
         */
        public String maskedOwnerForAuthority(String owner) {
            if (!supported || immutableOwner == null || !immutableOwner.equals(owner)
                    || !body.equals(owner.substring(bodyStartUtf16, bodyEndUtf16))) {
                throw new IllegalArgumentException("EXACT_SUPPORTED_NOTES_OWNER_REQUIRED");
            }
            char[] chars = owner.toCharArray();
            for (int i = bodyStartUtf16; i < bodyEndUtf16; i++) chars[i] = ' ';
            return new String(chars);
        }
    }

    public static Result parse(String immutableOwner) {
        if (!validOwner(immutableOwner)) return refused(immutableOwner, false, "unsupported_owner_text");
        String owner = immutableOwner;
        for (char[] quote : QUOTES) {
            String body = Pattern.quote(String.valueOf(quote[0])) + "([^"
                    + classEscape(quote[0]) + classEscape(quote[1]) + "\\r\\n]+)"
                    + Pattern.quote(String.valueOf(quote[1]));
            String[] expressions = {
                SPACE + POLITE + PREFIX + SPACE + body + END,
                SPACE + POLITE + QUOTED_NEW + body + END,
                SPACE + POLITE + "把" + body + DESTINATION + END,
                SPACE + body + "[，,]?记一下" + END
            };
            String[] forms = {"quoted_note_prefix.v1", "quoted_new_note.v1",
                    "quoted_note_destination.v1", "quoted_note_suffix.v1"};
            for (int i = 0; i < expressions.length; i++) {
                Matcher match = full(expressions[i]).matcher(owner);
                if (match.matches()) return candidate(owner, match, forms[i], true);
            }
        }
        Pattern[] patterns = {UNQUOTED_PREFIX, UNQUOTED_DESTINATION, UNQUOTED_SUFFIX};
        String[] forms = {"natural_note_prefix.v1", "natural_note_destination.v1", "natural_note_suffix.v1"};
        for (int i = 0; i < patterns.length; i++) {
            Matcher match = patterns[i].matcher(owner);
            if (match.matches()) return candidate(owner, match, forms[i], false);
        }
        return refused(owner, DRAFT_ONLY.matcher(outsideQuotedText(owner)).find(),
                "no_complete_supported_natural_note_request");
    }

    private static Result candidate(String owner, Matcher match, String form, boolean quoted) {
        int start = match.start(1), end = match.end(1);
        String body = owner.substring(start, end); // Never trim/normalize/rewrite the source span.
        if (body.length() > MAX_BODY_UTF16) return refused(owner, false, "body_exceeds_complete_list_limit");
        try {
            FixedIntentTools.forAction("notes.create").validatePayload(body);
        } catch (IllegalArgumentException invalid) {
            return refused(owner, false, "unsupported_literal_body");
        }
        if (!quoted) {
            // Multiple unquoted clauses can also be authority or extra goals.
            // Require explicit quotation for such literal content instead of
            // swallowing it into an allegedly authorized body.
            if (hasQuote(body) || AMBIGUOUS_UNQUOTED.matcher(body).find()
                    || body.indexOf('。') >= 0 && body.indexOf('。') != body.length() - 1
                    || body.endsWith("帮我")) {
                return refused(owner, DRAFT_ONLY.matcher(body).find(), "ambiguous_unquoted_body_or_additional_goal");
            }
            if (DRAFT_ONLY.matcher(body).find()) return refused(owner, true, "explicit_draft_or_no_save_request");
        }
        return new Result(owner, true, body, start, end, form, false, quoted,
                "exact_source_span_with_note_persistence_verification_policy");
    }

    private static Pattern full(String expression) {
        return Pattern.compile("\\A" + expression + "\\z");
    }

    private static String classEscape(char value) {
        return value == '\\' || value == ']' || value == '^' || value == '-'
                ? "\\" + value : String.valueOf(value);
    }

    private static boolean hasQuote(String text) {
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '“' || c == '”' || c == '‘' || c == '’' || c == '"' || c == '\'') return true;
        }
        return false;
    }

    private static String outsideQuotedText(String text) {
        StringBuilder out = new StringBuilder(text);
        char close = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (close == 0) {
                if (c == '“' || c == '‘' || c == '"' || c == '\'') {
                    close = c == '“' ? '”' : c == '‘' ? '’' : c;
                    out.setCharAt(i, ' ');
                }
            } else {
                out.setCharAt(i, ' ');
                if (c == close) close = 0;
            }
        }
        return out.toString();
    }

    private static boolean validOwner(String owner) {
        if (owner == null || owner.isEmpty() || owner.indexOf('\0') >= 0
                || owner.indexOf('\r') >= 0 || owner.indexOf('\n') >= 0
                || owner.contains("<|") || owner.contains("<__image__>")
                || owner.getBytes(StandardCharsets.UTF_8).length > 1600) return false;
        for (int i = 0; i < owner.length(); i++) {
            char c = owner.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= owner.length() || !Character.isLowSurrogate(owner.charAt(++i))) return false;
            } else if (Character.isLowSurrogate(c) || Character.isISOControl(c) && c != '\t') return false;
        }
        return true;
    }

    private static Result refused(String owner, boolean draft, String reason) {
        return new Result(owner, false, null, -1, -1, "unsupported_natural_note_request", draft, false, reason);
    }
}
