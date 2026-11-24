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
    // One explicit Notes app qualifier. It is matched in immutable OWNER;
    // it is never stripped and then reparsed with shifted source offsets.
    private static final String APP_QUALIFIER = "在" + SPACE
            + "(?:备忘录|笔记|(?i:Moto)" + SPACE + "笔记)(?:里|中)" + SPACE;
    private static final String QUOTED_NEW = "(?:新建|创建|写)(?:一条|一个|一则)?(?:笔记|备忘录)"
            + "[，,]?" + SPACE + "(?:正文|内容)(?:为|是)[：:]?" + SPACE;
    private static final String APP_SAVE_PREFIX = SPACE + POLITE
            + "(?:在" + SPACE + "(?i:Moto)" + SPACE + "笔记(?:里|中)" + SPACE + ")?"
            + "(?:新建|创建)并保存(?:一条|一个|一则)?(?:笔记|备忘录)[，,]" + SPACE
            + "(?:正文|内容)(?:为|是)[：:]?" + SPACE;
    private static final String REOPEN_FROM_LIST = SPACE + "[，,]" + SPACE
            + "(?:然后|随后)?从(?:笔记)?列表(?:中)?重新打开(?:并)?核对正文" + END;
    private static final String DESTINATION = "(?:记到|记在|写入|保存到)(?:备忘录|笔记)(?:里|中)?";
    // A colon is required here so the entire remaining source span is one body.
    private static final Pattern UNQUOTED_NEW_BODY = full(SPACE + POLITE
            + "(?:新建|创建|写)(?:一条|一个|一则)?(?:笔记|备忘录)[，,]?" + SPACE
            + "(?:正文|内容)(?:为|是)[：:]" + "(.+)");
    private static final Pattern UNQUOTED_PREFIX = full(SPACE + POLITE + PREFIX + "(.+)");
    private static final Pattern UNQUOTED_APP_PREFIX =
            full(SPACE + POLITE + APP_QUALIFIER + PREFIX + "(.+)");
    // Do not consume an apparent polite word from the body: 请假申请记一下
    // must retain 请假申请, rather than silently changing it to 假申请.
    private static final Pattern UNQUOTED_SUFFIX = full(SPACE + "(.+?)[，,]?记一下" + END);
    private static final Pattern UNQUOTED_DESTINATION = full(SPACE + POLITE + "把(.+?)" + DESTINATION + END);
    private static final Pattern AMBIGUOUS_UNQUOTED = Pattern.compile(
            "[，,；;！!？?]|然后|随后|并且|同时|顺便|另外|接着|还要|再帮我|并帮我"
            + "|提醒|闹钟|报警|定时|日历"
            + "|记一下|记录一下|记到(?:备忘录|笔记)|记在(?:备忘录|笔记)"
            + "|(?:^|。)(?:只允许|仅允许|禁止|不得|不允许)");
    // A complete comma-led note request owns the exact remainder as one body.
    // Commas inside that body are data; additional actions or authority clauses
    // still require explicit quotation instead of being silently masked.
    private static final Pattern UNQUOTED_COMMA_PREFIX =
            full(SPACE + POLITE + "(?:记一下|记录一下)[，,](.+)");
    private static final Pattern AMBIGUOUS_COMMA_BODY = Pattern.compile(
            "[；;！!？?]|然后|随后|并且|同时|顺便|另外|接着|还要|再帮我|并帮我"
            + "|提醒|闹钟|报警|定时|日历"
            + "|记一下|记录一下|记到(?:备忘录|笔记)|记在(?:备忘录|笔记)"
            + "|只允许|仅允许|禁止|不得|不允许"
            + "|删除|清空|擦除|下单|付款|支付|转账|发送|发微信|发邮件|拨打|打电话"
            + "|打开|启动|关闭|退出|点击|返回|回到|滑动|滚动|输入|搜索|查询|查机票"
            + "|创建|新建|添加|截图|截屏"
            + "|\\b(?:then|also|remind|alarm|delete|erase|remove|open|launch|close|click|tap|scroll|swipe|send|call|pay|purchase|order|transfer|checkout)\\b"
            + "|\\bonly[ \\t]+allow\\b|\\bdo[ \\t]+not[ \\t]+save\\b",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern DRAFT_ONLY = Pattern.compile(
            "(?:只|仅|先)(?:新建|打开|写|留|保留)?(?:一个|一条)?(?:笔记)?草稿"
            + "|(?:新建|打开|写)(?:一个|一条)?(?:笔记)?草稿"
            + "|不要保存|不保存|不必保存|无需保存|只打开(?:笔记)?编辑器");
    // This prefix only classifies an explicit new-note request for fail-closed
    // admission. It is not a body recognizer, a tool grant or a completion rule.
    private static final Pattern EXPLICIT_CREATE = Pattern.compile("\\A" + SPACE + POLITE
            + "(?:" + APP_QUALIFIER + ")?(?:(?:新建|创建)(?:并保存)?|写)(?:一条|一个|一则)?(?:笔记|备忘录)"
            + "(?=[ \\t，,：:。.!！]|正文|内容|然后|随后|接着|再|并|$)");
    private static final String EMPTY_DRAFT = "(?:一条|一个)?(?:空白|空)?(?:笔记|备忘录)?草稿";
    private static final String NO_SAVE_TAIL = "(?:[，,]" + SPACE + "(?:不要|不)保存)?";
    // Only a completely consumed, explicitly draft-only request is exempt.
    // A draft phrase in a body or before a second action is not such a request.
    private static final Pattern EXPLICIT_EMPTY_DRAFT = full(SPACE + POLITE
            + "(?:" + APP_QUALIFIER + ")?(?:(?:只|仅)(?:打开|新建|创建)" + EMPTY_DRAFT + NO_SAVE_TAIL
            + "|(?:新建|创建)(?:一条|一个)?(?:笔记|备忘录)[，,]" + SPACE
            + "(?:但)?(?:只|仅)打开" + EMPTY_DRAFT + NO_SAVE_TAIL + ")" + END);
    private static final char[][] QUOTES = {{'“','”'}, {'‘','’'}, {'"','"'}, {'\'','\''}};
    // One bounded literal body followed by the complete requested workflow and
    // limits. The body is not a fixed test message, and no later clause is cut
    // off or treated as an authorized second task.
    private static final Pattern SAVE_REOPEN = full(POLITE
            + "(?:新建|创建)(?:一条|一个)?(?:笔记|备忘录)[，,]正文为(.+?)"
            + " 保存后回到(?:笔记)?列表[，,]再重新打开核对正文[。.]"
            + "只创建本次这条记录[，,]不修改或删除已有记录[，,]不分享[。.]?");

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

        /** Older literal forms mask only their exact body span. The new unquoted
         * comma form must preserve the entire OWNER for every authority rule.
         * This choice is data flow, not a second copy of the authority grammar.
         */
        public boolean masksOwnerBodyForAuthority() {
            return supported && !"natural_new_note_body.v1".equals(recognition)
                    && !"natural_note_comma_prefix.v1".equals(recognition)
                    && !"natural_note_save_list_reopen.v2".equals(recognition)
                    && !"natural_app_note_prefix.v1".equals(recognition)
                    && !"quoted_app_note_prefix.v1".equals(recognition);
        }

        /** Return authority text only for this parser's exact immutable OWNER.
         * A comma-form body remains fully visible to the original compiler.
         */
        public String maskedOwnerForAuthority(String owner) {
            if (!supported || immutableOwner == null || !immutableOwner.equals(owner)
                    || !body.equals(owner.substring(bodyStartUtf16, bodyEndUtf16))) {
                throw new IllegalArgumentException("EXACT_SUPPORTED_NOTES_OWNER_REQUIRED");
            }
            if (!masksOwnerBodyForAuthority()) return owner;
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
                SPACE + body + "[，,]?记一下" + END,
                APP_SAVE_PREFIX + body + REOPEN_FROM_LIST,
                SPACE + POLITE + APP_QUALIFIER + PREFIX + SPACE + body + END
            };
            String[] forms = {"quoted_note_prefix.v1", "quoted_new_note.v1",
                    "quoted_note_destination.v1", "quoted_note_suffix.v1", "quoted_save_reopen_note.v1",
                    "quoted_app_note_prefix.v1"};
            for (int i = 0; i < expressions.length; i++) {
                Matcher match = full(expressions[i]).matcher(owner);
                if (match.matches()) return candidate(owner, match, forms[i], true);
            }
        }
        Matcher appPrefix = UNQUOTED_APP_PREFIX.matcher(owner);
        if (appPrefix.matches()) {
            Result result = candidate(owner, appPrefix, "natural_app_note_prefix.v1", false);
            // Keep all old unquoted-prefix limits. Additional action/authority
            // language is also refused; the entire OWNER remains unmasked.
            if (result.supported && AMBIGUOUS_COMMA_BODY.matcher(result.body).find())
                return refused(owner, false, "ambiguous_unquoted_body_or_additional_goal");
            return result;
        }
        Matcher commaPrefix = UNQUOTED_COMMA_PREFIX.matcher(owner);
        if (commaPrefix.matches()) {
            return candidate(owner, commaPrefix, "natural_note_comma_prefix.v1", false, true);
        }
        Pattern[] patterns = {UNQUOTED_PREFIX, UNQUOTED_DESTINATION, UNQUOTED_SUFFIX};
        String[] forms = {"natural_note_prefix.v1", "natural_note_destination.v1", "natural_note_suffix.v1"};
        for (int i = 0; i < patterns.length; i++) {
            Matcher match = patterns[i].matcher(owner);
            if (match.matches()) return candidate(owner, match, forms[i], false);
        }
        Matcher workflow = SAVE_REOPEN.matcher(owner);
        if (workflow.matches()) {
            Result result = candidate(owner, workflow, "natural_note_save_list_reopen.v2", false);
            // Keep the older short-body validator, and refuse unquoted action
            // language instead of hiding it from the authority compiler. The
            // entire new OWNER remains visible to that unchanged compiler.
            if (result.supported && AMBIGUOUS_COMMA_BODY.matcher(result.body).find())
                return refused(owner, false, "ambiguous_unquoted_body_or_additional_goal");
            return result;
        }
        Matcher newBody = UNQUOTED_NEW_BODY.matcher(owner);
        if (newBody.matches()) {
            // The complete OWNER remains visible to the existing authority compiler.
            return candidate(owner, newBody, "natural_new_note_body.v1", false, true);
        }
        return refused(owner, DRAFT_ONLY.matcher(outsideQuotedText(owner)).find(),
                "no_complete_supported_natural_note_request");
    }

    static boolean explicitCreateRequest(String immutableOwner) {
        return immutableOwner != null && EXPLICIT_CREATE.matcher(immutableOwner).find();
    }

    static boolean explicitEmptyDraftRequest(String immutableOwner) {
        return validOwner(immutableOwner) && EXPLICIT_EMPTY_DRAFT.matcher(immutableOwner).matches();
    }

    private static Result candidate(String owner, Matcher match, String form, boolean quoted) {
        return candidate(owner, match, form, quoted, false);
    }

    private static Result candidate(String owner, Matcher match, String form, boolean quoted,
                                    boolean commaPrefix) {
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
            Pattern ambiguity = commaPrefix ? AMBIGUOUS_COMMA_BODY : AMBIGUOUS_UNQUOTED;
            if (hasQuote(body) || ambiguity.matcher(body).find()
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
