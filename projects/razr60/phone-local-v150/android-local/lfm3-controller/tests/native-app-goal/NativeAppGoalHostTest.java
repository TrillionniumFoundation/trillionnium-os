package org.trillionnium.hepta.local;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

public final class NativeAppGoalHostTest {
    private static int assertions;
    private static final List<String> names = new ArrayList<String>();
    private static final String FLIGHT = "查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final String PRODUCT = "查一下小米AX3000T的价格";
    private NativeAppGoalHostTest() {}
    private static void check(boolean value, String message) {
        assertions++; if (!value) throw new AssertionError(message);
    }
    private static NativeAppGoal goal(String owner, String pkg) {
        NativeAppGoal value = NativeAppGoal.parse(owner, pkg);
        check(value != null, "recognized complete goal"); return value;
    }
    private static void named(String name, Runnable test) {
        check(!names.contains(name), "unique test name");
        test.run(); names.add(name);
    }
    private static void reject(String name, String owner, String pkg) {
        named(name, () -> check(NativeAppGoal.parse(owner, pkg) == null, name));
    }
    private static void throwsBinding(NativeAppGoal goal, String owner, String pkg) {
        boolean thrown = false;
        try { goal.requireBinding(owner, pkg); } catch (IllegalArgumentException expected) { thrown = true; }
        check(thrown, "foreign binding refused");
    }
    public static void main(String[] args) {
        named("generic_flight_is_bound_to_explicit_ctrip", () -> {
            NativeAppGoal g = goal(FLIGHT, NativeAppGoal.CTRIP_PACKAGE);
            check(NativeAppGoal.FLIGHT_RESULTS.equals(g.kind), "flight kind");
            check("北京".equals(g.fromCity) && "上海".equals(g.toCity), "exact cities");
            check(LocalDate.of(2026,11,17).equals(g.departureDate), "literal full date");
            check(g.adults==1 && g.children==0 && g.infants==0, "exact passengers");
            check(FLIGHT.equals(g.immutableOwner) && g.ownerSha256.matches("[a-f0-9]{64}"), "literal owner");
            check("2026年11月17日".equals(FLIGHT.substring(g.dateStartUtf16,g.dateEndUtf16)), "date source span");
            check("北京".equals(FLIGHT.substring(g.fromStartUtf16,g.fromEndUtf16)), "from source span");
            check("上海".equals(FLIGHT.substring(g.toStartUtf16,g.toEndUtf16)), "to source span");
            check(g.productModel == null && g.modelStartUtf16 == -1, "no product facts");
            g.requireBinding(FLIGHT, NativeAppGoal.CTRIP_PACKAGE);
        });
        named("same_owner_different_explicit_package_different_contract", () -> {
            NativeAppGoal a=goal(FLIGHT,NativeAppGoal.CTRIP_PACKAGE), b=goal(FLIGHT,NativeAppGoal.CSAIR_PACKAGE);
            check(a.ownerSha256.equals(b.ownerSha256), "same owner");
            check(!a.contractSha256.equals(b.contractSha256), "package included in contract identity");
        });
        named("explicit_ctrip_app_matches_selection", () -> {
            NativeAppGoal g=goal("请帮我在携程旅行App里查询2026-11-17从北京到上海的单程航班,一位成人。",NativeAppGoal.CTRIP_PACKAGE);
            check("2026-11-17".equals(g.immutableOwner.substring(g.dateStartUtf16,g.dateEndUtf16)), "ISO source span");
            check("北京".equals(g.fromCity) && "上海".equals(g.toCity), "no prefix inference");
        });
        named("explicit_csair_app_matches_selection", () -> goal("用南航app查查2026年11月17日北京到上海的单程机票，1名成人",NativeAppGoal.CSAIR_PACKAGE));
        named("leap_day_valid", () -> goal("查一下2028年2月29日北京到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE));
        named("task_date_is_separate_required_fact", () -> {
            NativeAppGoal g=goal(FLIGHT,NativeAppGoal.CTRIP_PACKAGE);
            check(g.departureNotBefore(LocalDate.of(2026,11,13)), "future");
            check(g.departureNotBefore(LocalDate.of(2026,11,17)), "same day");
            check(!g.departureNotBefore(LocalDate.of(2026,11,18)) && !g.departureNotBefore(null), "past or unknown refused");
        });
        named("product_model_and_span_exact", () -> {
            NativeAppGoal g=goal(PRODUCT,NativeAppGoal.XIAOMI_PACKAGE);
            check(NativeAppGoal.PRODUCT_PRICE.equals(g.kind), "product kind");
            check("AX3000T".equals(g.productModel), "model fact");
            check("AX3000T".equals(PRODUCT.substring(g.modelStartUtf16,g.modelEndUtf16)), "model source span");
            check(g.fromCity==null && g.toCity==null && g.departureDate==null && g.adults==-1, "no flight inference");
        });
        named("product_native_app_literal", () -> goal("请帮我在小米商城App中查询路由器AX3000T的价格。",NativeAppGoal.XIAOMI_PACKAGE));
        named("product_brand_case_preserves_owner", () -> {
            String owner="查看Xiaomi 路由器 ax3000t售价？";
            NativeAppGoal g=goal(owner,NativeAppGoal.XIAOMI_PACKAGE);
            check(owner.equals(g.immutableOwner), "no text rewrite");
            check("ax3000t".equals(owner.substring(g.modelStartUtf16,g.modelEndUtf16)), "original source case");
        });
        named("tool_ceiling_is_immutable_and_not_a_web_tool", () -> {
            NativeAppGoal g=goal(FLIGHT,NativeAppGoal.CTRIP_PACKAGE);
            check(g.toolCeiling.equals(new HashSet<String>(Arrays.asList("open","click","type","submit","scroll","back","wait","done"))),"exact ceiling");
            check(!g.toolCeiling.contains("web.search") && !g.toolCeiling.contains("notes.create") && !g.toolCeiling.contains("home"),"no unrelated tool");
            boolean thrown=false;try{g.toolCeiling.add("web.search");}catch(UnsupportedOperationException expected){thrown=true;}check(thrown,"immutable");
        });
        named("recognition_evidence_never_claims_provider_or_completion", () -> {
            NativeAppGoal g=goal(PRODUCT,NativeAppGoal.XIAOMI_PACKAGE);Map<String,Object> e=g.evidence();
            for(String key:new String[]{"provider_support_claimed","installed_identity_verified","grants_tool_authority","query_executed","business_verified","owner_rewritten"})
                check(Boolean.FALSE.equals(e.get(key)),key);
            check(NativeAppGoal.XIAOMI_PACKAGE.equals(e.get("package_name")),"explicit package");
            boolean thrown=false;try{e.put("business_verified",true);}catch(UnsupportedOperationException expected){thrown=true;}check(thrown,"immutable evidence");
        });
        named("binding_rejects_rewritten_owner_and_foreign_package", () -> {
            NativeAppGoal g=goal(FLIGHT,NativeAppGoal.CTRIP_PACKAGE);
            throwsBinding(g,FLIGHT+"。",NativeAppGoal.CTRIP_PACKAGE);
            throwsBinding(g,FLIGHT,NativeAppGoal.CSAIR_PACKAGE);
            throwsBinding(g,null,NativeAppGoal.CTRIP_PACKAGE);
        });
        reject("no_implicit_package",FLIGHT,null);
        reject("unknown_package",FLIGHT,"example.native");
        reject("helper_never_native",FLIGHT,"org.trillionnium.hepta.webhelper");
        reject("browser_never_native",FLIGHT,"com.zui.browser");
        reject("explicit_app_mismatch","在携程查询2026年11月17日北京到上海的单程机票，1名成人",NativeAppGoal.CSAIR_PACKAGE);
        reject("explicit_website_not_rewritten","查一下南航官网2026年11月17日北京到上海的单程机票，1名成人",NativeAppGoal.CSAIR_PACKAGE);
        reject("date_year_missing","查一下11月17日北京到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("relative_date_not_inferred","查一下明天北京到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("invalid_date","查一下2026年2月29日北京到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("year_zero","查一下0000年11月17日北京到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("passengers_missing","查一下2026年11月17日北京到上海的单程机票",NativeAppGoal.CTRIP_PACKAGE);
        reject("additional_passengers","查一下2026年11月17日北京到上海的单程机票，2名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("child_count_not_ignored",FLIGHT+"，1名儿童",NativeAppGoal.CTRIP_PACKAGE);
        reject("return_trip_not_inferred","查一下2026年11月17日北京到上海的往返机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("same_city","查一下2026年11月17日北京到北京的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("multiple_city_alternative","查一下2026年11月17日北京或天津到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("multiple_city_conjunction","查一下2026年11月17日北京和天津到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("city_action_payload","查一下2026年11月17日北京到上海然后支付的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
        reject("extra_purchase_goal",FLIGHT+"并帮我预订",NativeAppGoal.CTRIP_PACKAGE);
        reject("extra_tool_clause_not_silently_removed",FLIGHT+"。只允许click、done。",NativeAppGoal.CTRIP_PACKAGE);
        reject("leading_space_not_trimmed"," "+FLIGHT,NativeAppGoal.CTRIP_PACKAGE);
        reject("trailing_space_not_trimmed",FLIGHT+" ",NativeAppGoal.CTRIP_PACKAGE);
        reject("newline_not_removed",FLIGHT+"\n",NativeAppGoal.CTRIP_PACKAGE);
        reject("nul_not_removed",FLIGHT+"\0",NativeAppGoal.CTRIP_PACKAGE);
        reject("unpaired_surrogate",FLIGHT+"\ud800",NativeAppGoal.CTRIP_PACKAGE);
        reject("prompt_delimiter",FLIGHT+"<|assistant|>",NativeAppGoal.CTRIP_PACKAGE);
        reject("product_wrong_app",PRODUCT,NativeAppGoal.CTRIP_PACKAGE);
        reject("flight_wrong_app",FLIGHT,NativeAppGoal.XIAOMI_PACKAGE);
        reject("different_model_not_substituted","查一下小米AX3000的价格",NativeAppGoal.XIAOMI_PACKAGE);
        reject("ambiguous_product_variant","查一下小米AX3000T双只装的价格",NativeAppGoal.XIAOMI_PACKAGE);
        reject("product_website_not_rewritten","查一下小米AX3000T官网价格",NativeAppGoal.XIAOMI_PACKAGE);
        reject("product_purchase_not_price","帮我购买小米AX3000T",NativeAppGoal.XIAOMI_PACKAGE);
        reject("product_multi_goal",PRODUCT+"并下单",NativeAppGoal.XIAOMI_PACKAGE);
        reject("empty_owner","",NativeAppGoal.CTRIP_PACKAGE);
        reject("null_owner",null,NativeAppGoal.CTRIP_PACKAGE);
        StringBuilder json=new StringBuilder("{\"schema\":\"hepta.native-app-goal-host.v1\",\"all_pass\":true,\"cases\":")
                .append(names.size()).append(",\"assertions\":").append(assertions).append(",\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)json.append(',');json.append('"').append(names.get(i)).append('"');}
        System.out.println(json.append("]}").toString());
    }
}
