import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import org.trillionnium.hepta.background.FixedIntentTools;

/** Pure production contract tests; no Android lifecycle or app behavior is simulated. */
public final class FixedIntentToolsHostTest {
    private static int passed;
    private interface Check { void run() throws Exception; }
    private static void test(Check check) throws Exception { check.run(); passed++; }
    private static void need(boolean condition) { if (!condition) throw new AssertionError(); }
    private static void refused(FixedIntentTools.Profile profile, String payload, String code) {
        try { profile.validatePayload(payload); }
        catch (IllegalArgumentException expected) {
            need(code.equals(expected.getMessage()));
            return;
        }
        throw new AssertionError("invalid payload was accepted");
    }
    private static String repeat(String value, int count) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < count; i++) builder.append(value);
        return builder.toString();
    }
    public static void main(String[] args) throws Exception {
        final FixedIntentTools.Profile notes = FixedIntentTools.forAction("notes.create");
        final FixedIntentTools.Profile search = FixedIntentTools.forAction("web.search");
        test(() -> {
            need(notes != null && search != null && notes != search);
            need(FixedIntentTools.isTool(FixedIntentTools.NOTES_CREATE));
            need(FixedIntentTools.isTool(FixedIntentTools.WEB_SEARCH));
            for (String bad : new String[]{null, "", "notes", "notes.create ", " notes.create",
                    "Notes.Create", "notes.create\0", "web.search.extra", "intent", "open", "done"})
                need(FixedIntentTools.forAction(bad) == null && !FixedIntentTools.isTool(bad));
        });
        test(() -> {
            // These exact components/actions came from the real device resolver evidence.
            need("com.motorola.stylus".equals(notes.packageName));
            need("com.motorola.stylus.note.text.TextNoteActivity".equals(notes.className));
            need("android.intent.action.SEND".equals(notes.intentAction));
            need("text/plain".equals(notes.mimeType));
            need("android.intent.extra.TEXT".equals(notes.extraName));
            need("draft_opened".equals(notes.outcome));
        });
        test(() -> {
            // Browser package and activity intentionally have different prefixes on this phone.
            need("com.zui.browser".equals(search.packageName));
            need("com.lenovo.browser.BrowserActivity".equals(search.className));
            need("android.intent.action.WEB_SEARCH".equals(search.intentAction));
            need(search.mimeType == null && "query".equals(search.extraName));
            need("search_opened".equals(search.outcome));
        });
        test(() -> {
            need(Modifier.isFinal(FixedIntentTools.Profile.class.getModifiers()));
            need(FixedIntentTools.Profile.class.getConstructors().length == 0);
            for (Constructor<?> constructor : FixedIntentTools.Profile.class.getDeclaredConstructors()) {
                // Java8 target may add a package-private synthetic enclosing-class bridge.
                need(!Modifier.isPublic(constructor.getModifiers()) && !Modifier.isProtected(constructor.getModifiers()));
                if (!constructor.isSynthetic()) need(Modifier.isPrivate(constructor.getModifiers()));
            }
            for (Field field : FixedIntentTools.Profile.class.getFields())
                need(Modifier.isFinal(field.getModifiers()));
        });
        for (final FixedIntentTools.Profile profile : new FixedIntentTools.Profile[]{notes, search}) {
            test(() -> {
                need(profile.maxCodePoints == 1024 && profile.maxUtf8Bytes == 4096);
                profile.validatePayload("  明天下午记录事项\n第二行\t保留制表符\r\n第三行 😀  ");
                profile.validatePayload("机票 上海 北京 2026-11-20");
                profile.validatePayload("字面文本 ; $(id) <tag> https://example.invalid/ — 不成为组件或URI字段");
            });
            test(() -> {
                refused(profile, null, "FIXED_TOOL_PAYLOAD_REQUIRED");
                refused(profile, "", "FIXED_TOOL_PAYLOAD_REQUIRED");
                refused(profile, " \r\n\t\u00a0\u2003\u3000", "FIXED_TOOL_PAYLOAD_BLANK");
                refused(profile, "有内容\0尾部", "FIXED_TOOL_PAYLOAD_NUL");
            });
            test(() -> {
                for (String invalid : new String[]{"\ud800", "\udc00", "a\ud800b", "\ud800\ud800", "\udc00\ud800"})
                    refused(profile, invalid, "FIXED_TOOL_PAYLOAD_INVALID_UNICODE");
                profile.validatePayload("\ud83d\ude00");
            });
            test(() -> {
                for (String scalar : new String[]{"a", "é", "中", "\ud83d\ude00"}) {
                    String edge = repeat(scalar, 1024);
                    need(edge.codePointCount(0, edge.length()) == 1024);
                    need(edge.getBytes(StandardCharsets.UTF_8).length <= 4096);
                    profile.validatePayload(edge);
                    refused(profile, edge + scalar, "FIXED_TOOL_PAYLOAD_TOO_LONG");
                }
                need(repeat("\ud83d\ude00", 1024).getBytes(StandardCharsets.UTF_8).length == 4096);
            });
        }
        System.out.println("{\"schema\":\"hepta.fixed-intent-tools-host.v1\",\"all_pass\":true,\"passed\":" + passed
                + ",\"failed\":0,\"android_or_phone_tested\":false,\"app_open_or_save_claimed\":false}");
    }
}
