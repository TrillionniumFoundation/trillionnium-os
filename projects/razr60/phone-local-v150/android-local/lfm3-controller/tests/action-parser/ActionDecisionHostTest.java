import java.nio.charset.StandardCharsets;
import java.util.Random;
import org.trillionnium.hepta.local.ActionDecision;
import org.trillionnium.hepta.local.ActionDecision.InvalidActionException;

/** Pure JDK tests: no Android API, device, network, shell action or external model. */
public final class ActionDecisionHostTest {
    private static final String OBS = "0123456789abcdef0123456789abcdef";
    private static final String PKG = "com.android.settings";
    private static int accepted, rejected, assertions;

    public static void main(String[] args) throws Exception {
        acceptedActions();
        numericBoundaries();
        unicodeAndLengths();
        forbiddenSyntax();
        exactFields();
        malformedInputs();
        discoveryActions();
        check(ActionDecision.schemaGuide().contains("observation_id"), "Guide binding");
        check(ActionDecision.schemaGuide().contains("4096"), "Guide text limit");
        System.out.println("{\"schema\":\"hepta.action-decision-host-tests.v1\","
                + "\"all_pass\":true,\"accepted_cases\":" + accepted
                + ",\"rejected_cases\":" + rejected + ",\"assertions\":" + assertions
                + ",\"java_release\":8,\"android_or_phone_tested\":false"
                + ",\"external_model_used\":false}");
    }

    private static void discoveryActions() throws Exception {
        ActionDecision found = accept("find explicit package", base("find_app", "\"query\":\"com.example.target\",\"offset\":0"));
        equal(found.query, "com.example.target", "Exact query retained");
        check(found.offset == 0, "First discovery offset");
        unused(found, true, true, true, true, true, true, true, true);
        check(ActionDecision.parse(base("back", "")).query == null, "Other actions have no discovery query");
        check(ActionDecision.parse(base("back", "")).offset == -1, "Other actions have no discovery offset");
        accept("browse empty query", base("find_app", "\"query\":\"\",\"offset\":6"));
        accept("query Unicode limit", base("find_app", "\"query\":" + quote(repeat("😀", 64)) + ",\"offset\":4095"));
        reject("query too long", base("find_app", "\"query\":" + quote(repeat("😀", 65)) + ",\"offset\":0"));
        reject("query NUL", base("find_app", "\"query\":\"x\\u0000y\",\"offset\":0"));
        reject("query wrong type", base("find_app", "\"query\":1,\"offset\":0"));
        reject("query missing", base("find_app", "\"offset\":0"));
        reject("offset missing", base("find_app", "\"query\":\"calc\""));
        for (String value : new String[] {"-1", "-0", "4096", "00", "01", "6.0", "1e2", "\"6\"", "true", "null"})
            reject("invalid discovery offset " + value, base("find_app", "\"query\":\"calc\",\"offset\":" + value));
        for (String extra : new String[] {"\"node_id\":\"n1\"", "\"text\":\"launch\"", "\"x\":0", "\"page\":0", "\"intent\":\"evil\""})
            reject("find_app extra field", base("find_app", "\"query\":\"calc\",\"offset\":0," + extra));
        reject("open cannot carry search", base("open", "\"query\":\"calc\",\"offset\":0"));
    }

    private static void acceptedActions() throws Exception {
        ActionDecision d = accept("open", base("open", "\"reason\":\"打开设置，检查页面\""));
        equal(d.action, "open", "Open action");
        equal(d.observationId, OBS, "Exact observation");
        equal(d.packageName, PKG, "Exact package");
        equal(d.reason, "打开设置，检查页面", "Chinese reason");
        unused(d, true, true, true, true, true, true, true, true);
        d = accept("click node", base("click", "\"node_id\":\"n12\",\"reason\":\"点击已观察按钮\""));
        equal(d.nodeId, "n12", "Click node");
        unused(d, false, true, true, true, true, true, true, true);
        d = accept("click coordinates", base("click", "\"x\":0,\"y\":1000,\"reason\":\"点击截图中的按钮\""));
        check(d.nodeId == null && d.x == 0 && d.y == 1000, "Coordinate variant");
        unused(d, true, true, true, true, true, false, false, true);
        String text = "中文输入\n第二行😀\t保留\t引号\"和反斜杠\\";
        d = accept("type", base("type", "\"node_id\":\"n1\",\"text\":" + quote(text)
                + ",\"reason\":\"按要求输入中文\""));
        equal(d.text, text, "Exact Unicode, newline and escapes");
        equal(d.nodeId, "n1", "Type node");
        unused(d, false, false, true, true, true, true, true, true);
        for (String direction : new String[] {"forward", "backward", "up", "down", "left", "right"}) {
            d = accept("scroll", base("scroll", "\"node_id\":\"n99999\",\"direction\":"
                    + quote(direction) + ",\"reason\":\"滚动当前列表\""));
            equal(d.direction, direction, "Scroll direction");
            unused(d, false, true, false, true, true, true, true, true);
        }
        for (String action : new String[] {"back", "home"}) {
            d = accept(action, base(action, "\"reason\":\"返回已请求页面\""));
            equal(d.action, action, "Navigation action");
            unused(d, true, true, true, true, true, true, true, true);
        }
        d = accept("wait", base("wait", "\"duration_ms\":100,\"reason\":\"等待页面稳定\""));
        check(d.durationMs == 100, "Wait duration");
        unused(d, true, true, true, true, true, true, true, false);
        for (String status : new String[] {"success", "partial", "failure"}) {
            d = accept("done", base("done", "\"status\":" + quote(status)
                    + ",\"summary\":\"已记录真实结果，中文😀\",\"reason\":\"任务结束\""));
            equal(d.status, status, "Done status");
            equal(d.summary, "已记录真实结果，中文😀", "Chinese summary");
            unused(d, true, true, true, false, false, true, true, true);
        }
        d = accept("default reason", base("back", ""));
        equal(d.reason, "", "Reason defaults to empty");
        accept("JSON whitespace", " \t\r\n" + base("home", "") + "\n\t ");
        accept("uppercase hex", base("back", "").replace(OBS, OBS.toUpperCase(java.util.Locale.ROOT)));
        accept("node lower boundary", base("click", "\"node_id\":\"n0\""));
        accept("node leading zero", base("click", "\"node_id\":\"n00001\""));
        accept("package underscore", base("open", "").replace(PKG, "com.example_App.app2"));
        accept("Android system dialog back", base("back", "").replace(PKG, "android"));
        accept("Android system dialog done", base("done", "\"status\":\"success\",\"summary\":\"当前系统窗口已满足目标\"").replace(PKG, "android"));
        for(String invalid : new String[]{"Android", "android.", ".android", "android..settings", "android/Settings"})
            reject("system package exact exception",base("back", "").replace(PKG, invalid));
        accept("many package segments within total bound", base("open", "").replace(PKG, repeat("ab.", 3000) + "last"));
        reject("long invalid package suffix", base("open", "").replace(PKG, repeat("ab.", 3000) + "last-"));
        d = accept("escaped slash", base("type", "\"node_id\":\"n1\",\"text\":\"a\\/b\""));
        equal(d.text, "a/b", "JSON slash escape");
    }

    private static void numericBoundaries() throws Exception {
        accept("coordinate middle", base("click", "\"x\":500,\"y\":1"));
        accept("wait upper boundary", base("wait", "\"duration_ms\":2000"));
        for (String token : new String[] {
                "-1", "-0", "1001", "2147483647", "2147483648", "-2147483649",
                "999999999999999999999999999999", "00", "01", "-01", "+1",
                "1.0", "0.0", "1e2", "1E+2", ".5", "0x10", "NaN", "Infinity",
                "-Infinity", "true", "false", "null", "\"0\"", "[]", "{}", "１", ""
        }) reject("invalid x " + token, base("click", "\"x\":" + token + ",\"y\":0"));
        for (String token : new String[] {"-1", "-0", "99", "2001", "0100", "100.0", "1e3", "\"100\"", "null"})
            reject("invalid duration " + token, base("wait", "\"duration_ms\":" + token));
    }

    private static void unicodeAndLengths() throws Exception {
        ActionDecision d = accept("escaped surrogate pair", base("type",
                "\"node_id\":\"n1\",\"text\":\"\\u4e2d\\u6587\\uD83D\\uDE00\\n\""));
        equal(d.text, "中文😀\n", "Decoded surrogate pair");
        d = accept("standard escapes", base("type",
                "\"node_id\":\"n1\",\"text\":\"\\b\\f\\r\\t\\n\\\"\\\\\\/\""));
        equal(d.text, "\b\f\r\t\n\"\\/", "All standard escapes");
        d = accept("empty replacement", base("type", "\"node_id\":\"n1\",\"text\":\"\""));
        equal(d.text, "", "Empty exact replacement");
        String text4096 = repeat("汉", 1365) + "a";
        check(text4096.getBytes(StandardCharsets.UTF_8).length == 4096, "Known multibyte bound");
        accept("text exact byte bound", base("type", "\"node_id\":\"n1\",\"text\":" + quote(text4096)));
        reject("text over byte bound", base("type", "\"node_id\":\"n1\",\"text\":" + quote(text4096 + "b")));
        accept("emoji exact byte bound", base("type", "\"node_id\":\"n1\",\"text\":" + quote(repeat("😀", 1024))));
        reject("emoji over byte bound", base("type", "\"node_id\":\"n1\",\"text\":" + quote(repeat("😀", 1025))));
        accept("reason 256 characters", base("back", "\"reason\":" + quote(repeat("😀", 256))));
        reject("reason 257 characters", base("back", "\"reason\":" + quote(repeat("😀", 257))));
        accept("summary 1024 characters", base("done", "\"status\":\"success\",\"summary\":" + quote(repeat("😀", 1024))));
        reject("summary 1025 characters", base("done", "\"status\":\"success\",\"summary\":" + quote(repeat("😀", 1025))));
        reject("empty summary", base("done", "\"status\":\"success\",\"summary\":\"\""));
        reject("NUL text", base("type", "\"node_id\":\"n1\",\"text\":\"x\\u0000y\""));
        for (String bad : new String[] {
                "\\uD800", "\\uDC00", "\\uD800x", "\\uD800\\uD800", "\\uDC00\\uD800",
                "\\uD800\\u0041", "\\u12", "\\uZZZZ", "\\u１２３４", "\\x41", "\\v", "\\'", "\\U00000041"
        }) reject("invalid string escape", base("type", "\"node_id\":\"n1\",\"text\":\"" + bad + "\""));
        reject("raw high surrogate", base("type", "\"node_id\":\"n1\",\"text\":\"" + (char) 0xD800 + "\""));
        reject("raw low surrogate", base("type", "\"node_id\":\"n1\",\"text\":\"" + (char) 0xDC00 + "\""));
        reject("raw newline", base("type", "\"node_id\":\"n1\",\"text\":\"a\nb\""));
        reject("raw tab", base("type", "\"node_id\":\"n1\",\"text\":\"a\tb\""));
        reject("raw NUL", base("type", "\"node_id\":\"n1\",\"text\":\"a" + (char) 0 + "b\""));
        String raw = base("back", "");
        int padding = 16384 - raw.getBytes(StandardCharsets.UTF_8).length;
        accept("total exact byte bound", raw + repeat(" ", padding));
        reject("total bound plus one", raw + repeat(" ", padding + 1));
        reject("total multibyte bound", base("back", "\"reason\":" + quote(repeat("汉", 5500))));
    }

    private static void forbiddenSyntax() throws Exception {
        String good = base("back", "");
        for (String raw : new String[] {
                "", " ", "\t\r\n", "{}", "[]", "null", "true", "false", "NaN",
                "'action'", "{'action':'back'}",
                "\u0060\u0060\u0060json\n" + good + "\n\u0060\u0060\u0060",
                good + good, good + "x", "explanation " + good, good + "\u00a0", "\uFEFF" + good,
                good.substring(0, good.length() - 1) + ",}",
                good.replace("\"action\":", "action:"), good.replace("\"action\":", "\"action\"="),
                good.replace(",\"observation_id\"", " \"observation_id\""),
                good.replace("\"back\"", "[\"back\"]"), good.replace("\"back\"", "{\"name\":\"back\"}"),
                good.replace("\"back\"", "null"), good.replace("\"back\"", "true"),
                good.replace("\"back\"", "0"), good.replace("\"back\"", "\"back")
        }) reject("forbidden JSON syntax", raw);
        reject("null Java input", null);
        reject("duplicate global", add(good, "\"action\":\"back\""));
        reject("duplicate decoded key", add(good, "\"\\u0061ction\":\"back\""));
        reject("duplicate optional", base("back", "\"reason\":\"a\",\"reason\":\"b\""));
        reject("nested field", base("back", "\"extra\":{\"x\":1}"));
        reject("array field", base("back", "\"extra\":[1]"));
        for (int end = 0; end < good.length(); end++)
            reject("truncated prefix " + end, good.substring(0, end));
    }

    private static void exactFields() throws Exception {
        String[] actions = {"open", "click", "type", "scroll", "back", "home", "wait", "done", "find_app"};
        String[] extras = {"", "\"node_id\":\"n1\"", "\"node_id\":\"n1\",\"text\":\"中文\"",
                "\"node_id\":\"n1\",\"direction\":\"down\"", "", "", "\"duration_ms\":100",
                "\"status\":\"success\",\"summary\":\"完成\"", "\"query\":\"calc\",\"offset\":0"};
        for (int i = 0; i < actions.length; i++) {
            String raw = base(actions[i], extras[i]);
            reject("unknown field " + actions[i], add(raw, "\"shell\":\"id\""));
            reject("missing observation " + actions[i], raw.replace(",\"observation_id\":\"" + OBS + "\"", ""));
            reject("missing package " + actions[i], raw.replace(",\"package\":\"" + PKG + "\"", ""));
            reject("non-string reason " + actions[i], add(raw, "\"reason\":1"));
            reject("duplicate package " + actions[i], add(raw, "\"package\":\"" + PKG + "\""));
        }
        for (String action : new String[] {"", "Open", "shell", "network", "tap", "terminate"})
            reject("unknown action", base(action, ""));
        for (String observation : new String[] {"", repeat("a", 31), repeat("a", 33), repeat("g", 32), OBS + "\n"})
            reject("invalid observation", base("back", "").replace(quote(OBS), quote(observation)));
        for (String pkg : new String[] {"", "settings", ".com.example", "com..example", "com.example.",
                "com.1example", "com._example", "com.example-app", "com.example/App", "中文.应用", "com.example\n"})
            reject("invalid package", base("open", "").replace(quote(PKG), quote(pkg)));
        for (String node : new String[] {"", "n", "N1", "n123456", "n-1", "n1.0", "n１", "n1 "})
            reject("invalid node", base("click", "\"node_id\":" + quote(node)));
        reject("click mixes variants", base("click", "\"node_id\":\"n1\",\"x\":0,\"y\":0"));
        reject("click no target", base("click", ""));
        reject("click missing x", base("click", "\"y\":0"));
        reject("click missing y", base("click", "\"x\":0"));
        reject("type missing node", base("type", "\"text\":\"中文\""));
        reject("type missing text", base("type", "\"node_id\":\"n1\""));
        reject("type non-string", base("type", "\"node_id\":\"n1\",\"text\":0"));
        reject("scroll missing direction", base("scroll", "\"node_id\":\"n1\""));
        reject("scroll invalid direction", base("scroll", "\"node_id\":\"n1\",\"direction\":\"diagonal\""));
        reject("wait missing duration", base("wait", ""));
        reject("done missing summary", base("done", "\"status\":\"success\""));
        reject("done missing status", base("done", "\"summary\":\"完成\""));
        reject("done invalid status", base("done", "\"status\":\"unknown\",\"summary\":\"完成\""));
        reject("done extra text", base("done", "\"status\":\"success\",\"summary\":\"完成\",\"text\":\"extra\""));
        reject("back extra node", base("back", "\"node_id\":\"n1\""));
        reject("home extra duration", base("home", "\"duration_ms\":100"));
        reject("open extra coordinates", base("open", "\"x\":0,\"y\":0"));
        try{
            ActionDecision.parse(base("open", "\"node_id\":\"n11\""));
            throw new AssertionError("open node_id must be rejected");
        }catch(InvalidActionException expected){
            check(expected.getMessage().contains("node_id")&&expected.getMessage().contains("open"),"specific field/action repair feedback");
        }
    }

    private static void malformedInputs() throws Exception {
        Random random = new Random(9017779L);
        String alphabet = "{}[],:\"\\0123456789+-eENatulf \r\n\t中文😀";
        for (int i = 0; i < 256; i++) {
            StringBuilder value = new StringBuilder();
            int length = random.nextInt(120);
            for (int j = 0; j < length; j++) value.append(alphabet.charAt(random.nextInt(alphabet.length())));
            reject("deterministic malformed " + i, value.toString());
        }
    }

    private static ActionDecision accept(String name, String raw) throws Exception {
        try {
            ActionDecision result = ActionDecision.parse(raw);
            accepted++;
            return result;
        } catch (InvalidActionException error) {
            throw new AssertionError("Valid case rejected: " + name + ": " + error.getMessage(), error);
        }
    }

    private static void reject(String name, String raw) throws Exception {
        try {
            ActionDecision.parse(raw);
        } catch (InvalidActionException expected) {
            rejected++;
            return;
        }
        throw new AssertionError("Invalid case accepted: " + name);
    }

    private static void unused(ActionDecision d, boolean node, boolean text, boolean direction,
                               boolean status, boolean summary, boolean x, boolean y, boolean duration) {
        if (node) check(d.nodeId == null, "Unused node null");
        if (text) check(d.text == null, "Unused text null");
        if (direction) check(d.direction == null, "Unused direction null");
        if (status) check(d.status == null, "Unused status null");
        if (summary) check(d.summary == null, "Unused summary null");
        if (x) check(d.x == -1, "Unused x -1");
        if (y) check(d.y == -1, "Unused y -1");
        if (duration) check(d.durationMs == -1, "Unused duration -1");
    }

    private static void equal(Object actual, Object expected, String message) {
        check(expected == null ? actual == null : expected.equals(actual), message);
    }

    private static void check(boolean condition, String message) {
        assertions++;
        if (!condition) throw new AssertionError(message);
    }

    private static String base(String action, String extra) {
        return "{\"action\":" + quote(action) + ",\"observation_id\":\"" + OBS
                + "\",\"package\":\"" + PKG + "\"" + (extra.isEmpty() ? "" : "," + extra) + "}";
    }

    private static String add(String raw, String extra) {
        return raw.substring(0, raw.length() - 1) + "," + extra + "}";
    }

    private static String repeat(String value, int times) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < times; i++) result.append(value);
        return result.toString();
    }

    private static String quote(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': result.append("\\\""); break;
                case '\\': result.append("\\\\"); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                case '\b': result.append("\\b"); break;
                case '\f': result.append("\\f"); break;
                default: result.append(c);
            }
        }
        return result.append('"').toString();
    }
}
