package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;

/** Actual pure OWNER, saved-target resolver and permission consumers.
 * Profile inventory, runtime ids and decisions below are explicit host values,
 * not evidence of an installed app, a live observation or dispatched input.
 */
public final class ReadOnlyFlightOwnerHostTest {
    private static final String OWNER = "在携程查询2026年11月27日北京到上海的单程机票，1名成人，读取真实航班和票价。只查询，不预订、不提交订单、不支付。";
    private static final String COMMA = OWNER.replace("不预订、不提交订单、不支付", "不预订，不提交订单，不支付");
    private static final String SHORT = "在携程查询2026年11月27日北京到上海单程机票，1名成人";
    private static final String OLD_REPORT = "在携程查询2026年11月27日北京到上海的单程机票，1名成人，读取航班列表中可见的航班时间、航司和价格。只查询，不预订、不支付。";
    private static final String PKG = NativeAppGoal.CTRIP_PACKAGE;
    private static final String HEX32 = String.join("", Collections.nCopies(32, "a"));
    private static final String HEX64 = String.join("", Collections.nCopies(64, "b"));
    private static final List<String> names = new ArrayList<String>();
    private static int assertions;
    private interface Work { void run() throws Exception; }
    private static void check(boolean value, String why) {
        assertions++; if (!value) throw new AssertionError(why);
    }
    private static void test(String name, Work work) throws Exception {
        check(!names.contains(name), "unique case"); work.run(); names.add(name);
    }
    private static void refused(Work work) throws Exception {
        boolean refused = false;
        try { work.run(); } catch (IllegalArgumentException | IllegalStateException expected) { refused = true; }
        check(refused, "actual refusal required");
    }
    private static void reject(String name, String owner) throws Exception {
        test(name, () -> check(NativeAppGoal.parse(owner, PKG) == null, "unsupported whole OWNER rejected"));
    }
    private static NativeAppGoal goal(String owner) {
        NativeAppGoal g = NativeAppGoal.parse(owner, PKG);
        check(g != null, "complete OWNER recognized"); g.requireBinding(owner, PKG); return g;
    }
    private static BackgroundAutoTargetPreferences.Snapshot saved() {
        ProfileTarget p = new ProfileTarget(new ProfileIdentity(10, 1010, 0, ProfileIdentity.MANAGED),
                1010367, PKG, PKG + "/SyntheticActivity", 7,
                Collections.singletonMap("base", HEX64), Collections.singleton(HEX64));
        BackgroundAutoTargetPreferences.Entry e = BackgroundAutoTargetPreferences.captureProfile(p);
        return new BackgroundAutoTargetPreferences.Snapshot(true, Collections.singletonList(e));
    }
    private static BackgroundAutoTargetResolver.Resolution resolve(String owner) {
        return BackgroundAutoTargetResolver.resolve(owner, saved(), TaskAuthorization.parse(owner));
    }
    private static TaskAuthorization bound(String owner) {
        TaskAuthorization original = TaskAuthorization.parse(owner);
        BackgroundAutoTargetResolver.Resolution r = BackgroundAutoTargetResolver.resolve(owner, saved(), original);
        BackgroundAutoTargetResolver.StartSelection start = r.confirm(r.choose(null), HEX32,
                String.join("", Collections.nCopies(32, "c")), HEX64);
        final BackgroundTaskTarget target = BackgroundTaskTarget.resolveAutomaticSelection(owner, start);
        check(target.nativeGoal == start.nativeGoal && target.automaticStart == start,
                "same actual frozen goal and saved selection");
        BackgroundTaskTarget.SelectionBinding selection = () -> target;
        TaskAuthorization effective = original.forExecutionSelection(selection);
        effective.requireExecutionSelection(selection); effective.requireOwner(owner);
        return effective;
    }
    private static ActionDecision decision(String action) throws Exception {
        return ActionDecision.parse(new JSONObject().put("action", action).put("observation_id", HEX32)
                .put("package", PKG).put("node_id", "n1").put("node_label", "查 询")
                .put("reason", "host permission boundary").toString(), ActionDecision.IME_ACTION_SCHEMA);
    }
    private static String hash(String text) throws Exception {
        byte[] raw = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (byte b : raw) out.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
        return out.toString();
    }
    private static void baseline() throws Exception {
        test("baseline_actual_long_owner_is_unrecognized", () -> check(NativeAppGoal.parse(OWNER, PKG) == null, "actual original rejection"));
        test("baseline_actual_auto_resolution_has_no_match", () -> {
            BackgroundAutoTargetResolver.Resolution r = resolve(OWNER);
            check(r.matches.isEmpty(), "original auto mismatch"); refused(() -> r.choose(null));
        });
        test("baseline_enumeration_clause_does_not_remove_submit", () ->
                check(TaskAuthorization.parse(OWNER).allows("submit"), "unknown first business verb leaves original generic mask unchanged"));
        test("baseline_comma_clause_does_remove_submit", () -> {
            TaskAuthorization a = TaskAuthorization.parse(COMMA);
            check(!a.allows("submit") && a.allows("click"), "independent submit deny remains original behavior");
        });
        test("baseline_existing_short_and_report_forms_unchanged", () -> {
            check(NativeAppGoal.parse(SHORT, PKG) != null && NativeAppGoal.parse(OLD_REPORT, PKG) != null, "old recognized forms");
            check(NativeAppGoal.parse(SHORT, PKG).toolCeiling.contains("submit")
                    && NativeAppGoal.parse(OLD_REPORT, PKG).toolCeiling.contains("submit"), "old purpose ceiling");
        });
    }
    private static void candidate() throws Exception {
        test("actual_long_owner_literal_facts_and_utf16_spans", () -> {
            NativeAppGoal g = goal(OWNER);
            check("complete_literal_native_flight_read_only_no_order.v1".equals(g.recognition), "specific complete form");
            check(LocalDate.of(2026, 11, 27).equals(g.departureDate), "literal date");
            check("北京".equals(g.fromCity) && "上海".equals(g.toCity), "literal route");
            check(g.adults == 1 && g.children == 0 && g.infants == 0, "original single-adult boundary");
            check("2026年11月27日".equals(OWNER.substring(g.dateStartUtf16, g.dateEndUtf16)), "date span");
            check("北京".equals(OWNER.substring(g.fromStartUtf16, g.fromEndUtf16))
                    && "上海".equals(OWNER.substring(g.toStartUtf16, g.toEndUtf16)), "city spans");
            check(OWNER.equals(g.immutableOwner) && hash(OWNER).equals(g.ownerSha256), "no text rewritten or tail removed");
        });
        test("new_form_same_requested_facts_as_short_owner", () -> {
            NativeAppGoal a = goal(OWNER), b = goal(SHORT);
            check(a.departureDate.equals(b.departureDate) && a.fromCity.equals(b.fromCity)
                    && a.toCity.equals(b.toCity) && a.adults == b.adults && a.children == b.children
                    && a.infants == b.infants, "same requested facts");
            check(!a.ownerSha256.equals(b.ownerSha256) && !a.contractSha256.equals(b.contractSha256), "different complete owners remain distinct");
        });
        test("actual_saved_auto_resolution_selects_same_ctrip_instance", () -> {
            BackgroundAutoTargetResolver.Resolution r = resolve(OWNER);
            check(r.matches.size() == 1 && PKG.equals(r.choose(null).packageName()), "actual saved resolver matches once");
            check("profile:10:1010:ctrip.android.view".equals(r.choose(null).instanceKey), "exact saved host instance");
            refused(() -> r.choose("profile:11:1011:ctrip.android.view"));
        });
        test("actual_enumeration_permission_is_narrowed_only_at_selection", () -> {
            TaskAuthorization original = TaskAuthorization.parse(OWNER), effective = bound(OWNER);
            check(original.allows("submit"), "original parser unchanged, not claimed to parse business enumeration");
            check(!effective.allows("submit") && effective.allows("click"), "new purpose intersection only narrows");
            check(original.allowedTools.containsAll(effective.allowedTools), "no grant");
            effective.bind(HEX32).frame().requireDecision(decision("click"));
            refused(() -> effective.bind(HEX32).frame().requireDecision(decision("submit")));
        });
        test("comma_separated_original_submit_deny_remains_denied", () -> {
            TaskAuthorization original = TaskAuthorization.parse(COMMA), effective = bound(COMMA);
            check(!original.allows("submit") && original.allows("click"), "original independent-clause deny");
            check(!effective.allows("submit") && effective.allows("click"), "intersection cannot restore submit");
            effective.bind(HEX32).frame().requireDecision(decision("click"));
            refused(() -> effective.bind(HEX32).frame().requireDecision(decision("submit")));
        });
        test("mixed_punctuation_keeps_original_permission_refusal", () -> {
            String originalRefusal = OWNER.replace("不预订、不提交订单", "不预订，不提交订单");
            check(NativeAppGoal.parse(originalRefusal, PKG) != null, "complete grammar alone is not authorization");
            refused(() -> TaskAuthorization.parse(originalRefusal));
            refused(() -> bound(originalRefusal));
            String otherMixed = OWNER.replace("不提交订单、不支付", "不提交订单，不支付");
            check(TaskAuthorization.parse(otherMixed).allows("submit"), "other original punctuation case remains distinct");
            check(!bound(otherMixed).allows("submit"), "new purpose still only narrows");
        });
        test("new_purpose_ceiling_is_exact_and_immutable", () -> {
            NativeAppGoal g = goal(OWNER);
            Set<String> expected = new TreeSet<String>(Arrays.asList("open", "click", "type", "scroll", "back", "wait", "done"));
            check(g.toolCeiling.equals(expected), "only generic submit removed from previous query ceiling");
            boolean immutable = false;
            try { g.toolCeiling.add("submit"); } catch (UnsupportedOperationException expectedError) { immutable = true; }
            check(immutable, "cannot mutate purpose");
        });
        test("old_short_report_and_product_ceilings_are_unchanged", () -> {
            check(goal(SHORT).toolCeiling.contains("submit") && goal(OLD_REPORT).toolCeiling.contains("submit"), "both old flight forms unchanged");
            check(bound(SHORT).allows("submit") && bound(OLD_REPORT).allows("submit"), "old selected permission unchanged");
            NativeAppGoal product = NativeAppGoal.parse("在小米商城搜索小米路由器AX3000T，读取实际商品页面显示的当前售价并说明商品型号。只查询，不购买、不提交订单、不支付。", NativeAppGoal.XIAOMI_PACKAGE);
            check(product != null && product.toolCeiling.contains("submit"), "old product form not modified");
        });
        test("iso_ascii_field_spaces_keep_full_owner_and_spans", () -> {
            String text = OWNER.replace("查询2026年11月27日北京到上海的单程机票，1名成人",
                    "查询 2028-02-29 从 广州 到 深圳 的 单程 航班, 一 位 成人");
            NativeAppGoal g = goal(text);
            check(LocalDate.of(2028, 2, 29).equals(g.departureDate) && "广州".equals(g.fromCity)
                    && "深圳".equals(g.toCity), "same bounded date/city parser, no fixed test route");
            check("2028-02-29".equals(text.substring(g.dateStartUtf16, g.dateEndUtf16)), "ISO span excludes field spaces");
            check(text.equals(g.immutableOwner), "spaces retained");
        });
        test("supplementary_han_city_keeps_utf16_offsets", () -> {
            String text = OWNER.replace("北京", "\uD840\uDC00京");
            NativeAppGoal g = goal(text);
            check("\uD840\uDC00京".equals(g.fromCity) && g.fromEndUtf16 - g.fromStartUtf16 == 3, "UTF16 rather than codepoint offset");
            check("上海".equals(text.substring(g.toStartUtf16, g.toEndUtf16)), "later span remains exact");
        });
        test("complete_owner_binding_cannot_drop_restrictions", () -> {
            NativeAppGoal g = goal(OWNER);
            refused(() -> g.requireBinding(SHORT, PKG));
            refused(() -> g.requireBinding(COMMA, PKG));
            refused(() -> g.requireBinding(OWNER, NativeAppGoal.CSAIR_PACKAGE));
        });
        test("recognition_never_claims_provider_execution_or_completion", () -> {
            Map<String, Object> e = goal(OWNER).evidence();
            for (String key : new String[]{"provider_support_claimed", "installed_identity_verified",
                    "grants_tool_authority", "query_executed", "business_verified", "owner_rewritten"})
                check(Boolean.FALSE.equals(e.get(key)), "unclaimed " + key);
            check(Integer.valueOf(OWNER.length()).equals(e.get("owner_end_utf16")), "full string consumed");
        });
        test("explicit_original_click_deny_is_not_stripped_or_overridden", () -> {
            String text = OWNER + "不要click。";
            check(NativeAppGoal.parse(text, PKG) == null, "extra clause not stripped to a recognized goal");
            TaskAuthorization a = TaskAuthorization.parse(text);
            check(!a.allows("click"), "original deny retained");
            refused(() -> a.bind(HEX32).frame().requireDecision(decision("click")));
        });
        reject("extra_booking_action_refused", OWNER + "然后预订。");
        reject("extra_payment_action_refused", OWNER + "然后支付。");
        reject("extra_order_action_refused", OWNER + "提交订单。");
        reject("second_app_goal_refused", OWNER + "再去小米商城查询价格。");
        reject("unknown_report_suffix_refused", OWNER + "并总结优惠券。");
        reject("unknown_report_phrase_refused", OWNER.replace("真实航班和票价", "真实航班和优惠"));
        reject("missing_report_phrase_refused", OWNER.replace("，读取真实航班和票价", ""));
        reject("missing_no_order_clause_refused", OWNER.replace("、不提交订单", ""));
        reject("positive_order_clause_refused", OWNER.replace("不提交订单", "提交订单"));
        reject("positive_booking_clause_refused", OWNER.replace("不预订", "预订"));
        reject("positive_payment_clause_refused", OWNER.replace("不支付", "支付"));
        reject("conditional_order_exception_refused", OWNER.replace("不提交订单", "不提交订单除非很便宜"));
        reject("double_negation_refused", OWNER.replace("不提交订单", "不是不提交订单"));
        reject("reordered_limits_refused", OWNER.replace("不预订、不提交订单", "不提交订单、不预订"));
        reject("missing_year_refused", OWNER.replace("2026年", ""));
        reject("relative_date_refused", OWNER.replace("2026年11月27日", "明天"));
        reject("invalid_calendar_date_refused", OWNER.replace("2026年11月27日", "2027年2月29日"));
        reject("zero_year_refused", OWNER.replace("2026年", "0000年"));
        reject("two_adults_refused", OWNER.replace("1名成人", "2名成人"));
        reject("additional_child_refused", OWNER.replace("1名成人", "1名成人、1名儿童"));
        reject("return_trip_refused", OWNER.replace("单程", "往返"));
        reject("same_city_refused", OWNER.replace("上海", "北京"));
        reject("alternative_route_refused", OWNER.replace("北京", "北京或天津"));
        reject("multiple_route_refused", OWNER.replace("上海", "上海到广州"));
        reject("city_action_payload_refused", OWNER.replace("上海", "上海然后支付"));
        reject("leading_space_not_trimmed", " " + OWNER);
        reject("trailing_space_not_trimmed", OWNER + " ");
        reject("newline_not_normalized", OWNER.replace("。只查询", "。\n只查询"));
        reject("unpaired_surrogate_refused", OWNER + "\uD800");
        reject("extra_tool_clause_not_stripped", OWNER + "只允许click、done。");
        test("new_form_not_added_to_foreign_native_or_web_packages", () -> {
            for (String pkg : new String[]{NativeAppGoal.CSAIR_PACKAGE, NativeAppGoal.XIAOMI_PACKAGE, "org.trillionnium.hepta.webhelper"})
                check(NativeAppGoal.parse(OWNER, pkg) == null, "wrong package");
            check(NativeAppGoal.parse(OWNER.replace("携程", "南航"), NativeAppGoal.CSAIR_PACKAGE) == null, "only requested Ctrip extension");
            check(NativeAppGoal.parse(OWNER, null) == null, "no implicit package");
        });
        test("unknown_complete_owner_does_not_resolve_saved_target", () -> {
            BackgroundAutoTargetResolver.Resolution r = resolve(OWNER + "然后预订。");
            check(r.matches.isEmpty(), "no partial full-string match");
            refused(() -> r.choose(null));
        });
    }
    public static void main(String[] args) throws Exception {
        boolean old = args.length == 1 && "--baseline".equals(args[0]);
        if (old) baseline(); else { check(args.length == 0, "closed invocation"); candidate(); }
        System.out.println(new JSONObject().put("schema", "hepta.ctrip-readonly-owner-cases.v1")
                .put("all_pass", true).put("baseline", old).put("case_names", new JSONArray(names))
                .put("cases", names.size()).put("assertions", assertions)
                .put("phone_operations", 0).put("android_runtime", false).put("business_verified", false)
                .put("profile_identity_is_host_fixture", true).put("action_dispatched", false).toString());
    }
}
