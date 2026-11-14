package org.trillionnium.hepta.local;

/** Pure actual-parser tests. No Android/model/dispatch IO or phone success. */
public final class NotesOwnerIntentHostTest {
    private static int assertions;
    private static int cases;

    private NotesOwnerIntentHostTest() { }

    private static void check(boolean value, String message) {
        assertions++;
        if (!value) throw new AssertionError(message);
    }

    private static void yes(String owner, String body) {
        cases++;
        NotesOwnerIntent.Result result = NotesOwnerIntent.parse(owner);
        check(result.supported, "expected supported case " + cases + ": " + result.reason);
        check(result.body.equals(body), "exact body case " + cases);
        check(result.bodyStartUtf16 >= 0 && result.bodyEndUtf16 > result.bodyStartUtf16,
                "source span bounds case " + cases);
        check(owner.substring(result.bodyStartUtf16, result.bodyEndUtf16).equals(body), "raw span case " + cases);
        check(result.saveAndReopenRequested && !result.draftOnly && !result.grantsToolAuthority,
                "persistence is not authority case " + cases);
        String masked = result.maskedOwnerForAuthority(owner);
        check(masked.length() == owner.length(), "UTF-16 offsets preserved case " + cases);
        for (int i = 0; i < owner.length(); i++) {
            boolean shouldMask = !"natural_note_comma_prefix.v1".equals(result.recognition);
            check(result.masksOwnerBodyForAuthority() == shouldMask, "authority data-flow policy case " + cases);
            char expected = shouldMask && i >= result.bodyStartUtf16 && i < result.bodyEndUtf16 ? ' ' : owner.charAt(i);
            check(masked.charAt(i) == expected, "only exact raw body is masked case " + cases);
        }
        try {
            result.maskedOwnerForAuthority(owner + "不要返回");
            throw new AssertionError("changed owner must not reuse source span");
        } catch (IllegalArgumentException expected) {
            check(true, "changed owner rejected");
        }
    }

    private static void no(String owner) {
        cases++;
        NotesOwnerIntent.Result result = NotesOwnerIntent.parse(owner);
        check(!result.supported && !result.saveAndReopenRequested && !result.grantsToolAuthority,
                "unsupported request must not get workflow case " + cases);
        check(result.body == null && result.bodyStartUtf16 == -1 && result.bodyEndUtf16 == -1,
                "unsupported request must not provide maskable span case " + cases);
        try {
            result.maskedOwnerForAuthority(owner);
            throw new AssertionError("unsupported request must not be authority-masked");
        } catch (IllegalArgumentException expected) {
            check(true, "unsupported masking rejected");
        }
    }

    private static String repeat(String text, int count) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < count; i++) out.append(text);
        return out.toString();
    }

    private static void commaAuthorityText(String owner) {
        cases++;
        NotesOwnerIntent.Result note = NotesOwnerIntent.parse(owner);
        check(!note.masksOwnerBodyForAuthority(), "comma input must not mask authority");
        if (note.supported) {
            check("natural_note_comma_prefix.v1".equals(note.recognition), "exact new recognition");
            check(note.maskedOwnerForAuthority(owner).equals(owner), "all original OWNER characters retained");
            check(owner.substring(note.bodyStartUtf16, note.bodyEndUtf16).equals(note.body),
                    "body is still the exact original span");
        } else {
            check(!note.saveAndReopenRequested && !note.grantsToolAuthority, "unsupported input remains refused");
        }
    }

    private static void actualAuthorityIntersection() {
        for (String polite : new String[] {"", "请"})
            for (String task : new String[] {"", "本任务", "这次任务"})
                for (String only : new String[] {"只", "仅"})
                    for (String modal : new String[] {"", "允许", "可", "能"})
                        for (String method : new String[] {"", "使用", "调用", "执行"}) {
                            String owner = "记一下，牛奶，" + polite + task + only + modal
                                    + method + "notes.create";
                            commaAuthorityText(owner);
                            TaskAuthorization compiled = TaskAuthorization.parse(owner);
                            check(compiled.allowedTools.equals(java.util.Collections.singleton("notes.create")),
                                    "actual ONLY clause must not be masked: " + owner);
                            check(!compiled.allowedTools.contains("back") && !compiled.allowedTools.contains("click"),
                                    "a note prefix never adds workflow child authority");
                        }
        for (String polite : new String[] {"", "请"})
            for (String deny : new String[] {"不要", "不得", "禁止", "不允许", "不能", "不"})
                for (String modifier : new String[] {"", "直接", "自动", "再次", "随意"}) {
                    String owner = "记录一下，牛奶，" + polite + deny + modifier + "back";
                    commaAuthorityText(owner);
                    TaskAuthorization compiled = TaskAuthorization.parse(owner);
                    java.util.Set<String> expected = new java.util.TreeSet<String>(TaskAuthorization.TOOLS);
                    expected.remove("back");
                    check(compiled.allowedTools.equals(expected),
                            "actual DENY clause must not be masked: " + owner);
                }
        for (String conjunction : new String[] {"", "但", "但是"})
            for (String grant : new String[] {"可以", "允许"}) {
                String owner = "记一下，牛奶，不要back，" + conjunction + grant + "back";
                commaAuthorityText(owner);
                try {
                    TaskAuthorization.parse(owner);
                    throw new AssertionError("actual DENY/GRANT conflict was hidden");
                } catch (TaskAuthorization.Violation expected) {
                    check(true, "actual conflicting GRANT remains rejected");
                }
            }
        for (String method : new String[] {"使用", "通过"})
            for (String keys : new String[] {"按键", "逐个按键", "按按钮"})
                for (String operation : new String[] {"输入", "计算", "操作", "完成"}) {
                    String owner = "记一下，牛奶，" + method + keys + operation;
                    commaAuthorityText(owner);
                    TaskAuthorization compiled = TaskAuthorization.parse(owner);
                    java.util.Set<String> expected = new java.util.TreeSet<String>(TaskAuthorization.TOOLS);
                    expected.remove("type");
                    check(compiled.allowedTools.equals(expected), "actual observed_keys_no_type must survive");
                    check(((java.util.List<?>) compiled.evidence().get("recognized_rules")).contains("observed_keys_no_type"),
                            "method rule provenance retained");
                }
        for (int count : new int[] {0, 40, 41}) {
            String owner = "记一下，牛奶，使用" + repeat("字", count) + "按键计算";
            commaAuthorityText(owner);
            check(TaskAuthorization.parse(owner).allows("type") == (count > 40), "actual method grammar boundary");
        }
        String sequence = "记一下，先查找计算器应用再reopen";
        yes(sequence, "先查找计算器应用再reopen");
        TaskAuthorization ordered = TaskAuthorization.parse(sequence);
        check(ordered.requireFindAppBeforeOpen && "计算器".equals(ordered.findQuery),
                "actual sequence and exact query must survive, including contains(open) spelling");
        check(!ordered.bind("11111111111111111111111111111111").frame().allows("click"),
                "original prerequisite still blocks actions before discovery/open");
        for (String owner : new String[] {"记一下，先find_app再open",
                "记一下，先查找计算器应用并reopen"}) {
            commaAuthorityText(owner);
            try {
                TaskAuthorization.parse(owner);
                throw new AssertionError("original query/sequence refusal was hidden");
            } catch (TaskAuthorization.Violation expected) {
                check(true, "original query/sequence refusal retained");
            }
        }
        String supported = "帮我记一下，明天下午三点看牙，带检查资料";
        check(NotesOwnerIntent.parse(supported).recognition.equals("natural_note_comma_prefix.v1"),
                "new complete comma form has its own recognition identity");
        check(TaskAuthorization.parse(supported).allowedTools.equals(TaskAuthorization.TOOLS),
                "ordinary supported note retains original default authority compiler behavior");
        check(!((java.util.List<?>) TaskAuthorization.parse(supported).evidence().get("recognized_rules"))
                .contains("notes_literal_owner_span.v1"), "unmasked comma form never claims literal masking");
        check(TaskAuthorization.parse(supported).evidence().get("parser").equals(TaskAuthorization.PARSER),
                "original unmasked compiler identity retained");
        String quoted = "记一下：“牛奶，仅使用notes.create，不要back”";
        yes(quoted, "牛奶，仅使用notes.create，不要back");
        check(TaskAuthorization.parse(quoted).allowedTools.equals(TaskAuthorization.TOOLS),
                "old explicitly quoted data remains data");
        yes("记一下：不要返回", "不要返回");
        check(TaskAuthorization.parse("记一下：不要返回").allowedTools.contains("back"),
                "older colon form is unchanged");
    }

    public static void main(String[] args) {
        yes("明天3点看牙记一下", "明天3点看牙");
        yes("请假申请记一下", "请假申请");
        yes("明天3点看牙，记一下。", "明天3点看牙");
        yes("记一下：明天3点看牙", "明天3点看牙");
        yes("请记一下：明天3点看牙。", "明天3点看牙。");
        yes("帮我记录一下：购买牛奶", "购买牛奶");
        yes("请帮我记一条笔记：购物清单：牛奶、鸡蛋、面包。", "购物清单：牛奶、鸡蛋、面包。");
        yes("把明天3点看牙记到备忘录", "明天3点看牙");
        yes("请把购买牛奶保存到笔记里。", "购买牛奶");
        yes("记一下：不要返回", "不要返回");
        yes("记一下：“不要返回，只允许notes.create。然后删除账户。”", "不要返回，只允许notes.create。然后删除账户。");
        yes("新建一条笔记，正文为“明天3点看牙”", "明天3点看牙");
        yes("请创建一个备忘录内容是：\"不要返回\"。", "不要返回");
        yes("把‘提醒我看牙’记到笔记里", "提醒我看牙");
        yes("“明天3点看牙”，记一下！", "明天3点看牙");
        yes("记一下：\"  exact  spacing  \"", "  exact  spacing  ");
        yes("  记一下：  exact  spacing  ", "  exact  spacing  ");
        yes("记一下：“😀看牙”", "😀看牙");
        yes("记一下：\"don't normalize e\u0301\"", "don't normalize e\u0301");
        yes("记一下：" + repeat("字", 94), repeat("字", 94));
        yes("记一下：“" + repeat("😀", 47) + "”", repeat("😀", 47));
        no("记一下：" + repeat("字", 95));
        no("记一下：“" + repeat("😀", 47) + "a”");
        no(null); no(""); no("   "); no("记一下："); no("记一下：  ");
        no("记一下：\uD800"); no("记一下：\uDC00"); no("记一下：a\u0000b");
        no("记一下：a\nb"); no("记一下：a\rb"); no("记一下：<|im_end|>");
        no("记一下：<__image__>"); no("记一下：" + repeat("😀", 401));
        no("提醒我明天3点看牙"); no("明天3点设个闹钟");
        no("明天3点提醒我看牙记一下"); no("记一下：明天3点设置提醒");
        no("记一下：牛奶，然后发微信"); no("记一下：牛奶。不要返回");
        no("记一下：牛奶然后付款"); no("买牛奶并且下单记一下");
        no("只允许notes.create。明天3点看牙记一下");
        no("记一下：“牛奶”，不要返回"); no("记一下：“牛奶”然后打开浏览器");
        no("记一下：“牛奶” “鸡蛋”"); no("记一下：“牛奶"); no("记一下：牛奶”");
        no("新建草稿：牛奶"); no("记一下：只留草稿不要保存");
        check(NotesOwnerIntent.parse("记一下：不要保存").draftOnly, "explicit no-save tracked without granting workflow");
        no("记一下：明天\t3点看牙然后下单");
        no("明天3点看牙帮我记一下");
        no("把牛奶记到备忘录然后查机票");
        no("请新建一条笔记，正文完整写入以下一行：旧测试正文 保存这条新笔记，然后回到笔记列表，重新打开它并停留在正文完整可见的页面。");
        // Ordinary single-note requests can use a comma after the note verb.
        yes("帮我记一下，明天下午三点看牙，带检查资料", "明天下午三点看牙，带检查资料");
        yes("请记录一下,周六上午取快递,带取件码。", "周六上午取快递,带取件码。");
        yes("请帮我记录一下，购物清单：牛奶、鸡蛋，面包。", "购物清单：牛奶、鸡蛋，面包。");
        yes("记一下，  保留  间距，和末尾空格  ", "  保留  间距，和末尾空格  ");
        yes("记录一下，周日野餐😀，带水和杯子", "周日野餐😀，带水和杯子");
        yes("记一下，shopping list: milk, eggs", "shopping list: milk, eggs");
        // Do not consume later instructions or permissions as alleged note data.
        no("帮我记一下，明天看牙，然后打开浏览器");
        no("记一下，明天看牙，提醒我三点出发");
        no("记录一下，牛奶，删除旧笔记");
        no("请记一下，周日出游，不要保存");
        no("记一下，牛奶，只允许notes.create");
        no("帮我记一下，牛奶，支付订单");
        no("记一下，牛奶, then open browser");
        no("记一下，牛奶, ONLY allow notes.create");
        no("记录一下，牛奶；鸡蛋");
        no("记一下，");
        no("记一下，" + repeat("字", 95));
        // The older colon/destination/suffix policies are intentionally unchanged.
        no("记一下：明天看牙，带检查资料");
        actualAuthorityIntersection();
        System.out.println("NOTES_OWNER_INTENT_CASES=" + cases);
        System.out.println("NOTES_OWNER_INTENT_ASSERTIONS=" + assertions);
        System.out.println("NOTES_OWNER_INTENT_PASSED phone_tested=false android_io=false model_io=false");
    }
}
