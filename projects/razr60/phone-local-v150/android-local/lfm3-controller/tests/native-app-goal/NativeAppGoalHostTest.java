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
    private static void readOnlyReportCases() {
        final String product = "在小米商城搜索小米路由器AX3000T，读取实际商品页面显示的当前售价并说明商品型号。只查询，不购买、不提交订单、不支付。";
        final String flight = "在携程查询2026年11月25日北京到上海的单程机票，1名成人，读取航班列表中可见的航班时间、航司和价格。只查询，不预订、不支付。";
        named("complete_product_read_only_report", () -> {
            NativeAppGoal g=goal(product,NativeAppGoal.XIAOMI_PACKAGE);
            check("complete_literal_native_product_read_only_report.v2".equals(g.recognition),"new form identity");
            check(NativeAppGoal.PRODUCT_PRICE.equals(g.kind)&&"AX3000T".equals(g.productModel),"original qualified model");
            check("AX3000T".equals(product.substring(g.modelStartUtf16,g.modelEndUtf16)),"actual model span");
            check(product.equals(g.immutableOwner)&&g.immutableOwner.endsWith("不支付。"),"complete limits retained");
            g.requireBinding(product,NativeAppGoal.XIAOMI_PACKAGE);
            throwsBinding(g,product.substring(0,product.indexOf("只查询")),NativeAppGoal.XIAOMI_PACKAGE);
            check(g.toolCeiling.equals(goal(PRODUCT,NativeAppGoal.XIAOMI_PACKAGE).toolCeiling),"unchanged query tool ceiling");
        });
        named("product_report_keeps_literal_case_and_price_word", () -> {
            String owner=product.replace("搜索小米路由器AX3000T","查询Xiaomi 路由器 ax3000t").replace("当前售价","当前价格");
            NativeAppGoal g=goal(owner,NativeAppGoal.XIAOMI_PACKAGE);
            check("ax3000t".equals(owner.substring(g.modelStartUtf16,g.modelEndUtf16)),"literal source case");
            check(!g.ownerSha256.equals(goal(product,NativeAppGoal.XIAOMI_PACKAGE).ownerSha256),"owner not normalized");
        });
        named("complete_flight_read_only_report", () -> {
            NativeAppGoal g=goal(flight,NativeAppGoal.CTRIP_PACKAGE);
            check("complete_literal_native_flight_read_only_report.v2".equals(g.recognition),"report form identity");
            check(LocalDate.of(2026,11,25).equals(g.departureDate)&&"北京".equals(g.fromCity)&&"上海".equals(g.toCity),"literal flight fields");
            check(g.adults==1&&g.children==0&&g.infants==0,"no added passengers");
            check("2026年11月25日".equals(flight.substring(g.dateStartUtf16,g.dateEndUtf16)),"literal date span");
            check("北京".equals(flight.substring(g.fromStartUtf16,g.fromEndUtf16))&&"上海".equals(flight.substring(g.toStartUtf16,g.toEndUtf16)),"city spans");
            check(flight.equals(g.immutableOwner),"report and no-booking limits belong to same immutable owner");
            for(String key:new String[]{"provider_support_claimed","query_executed","business_verified","grants_tool_authority"})
                check(Boolean.FALSE.equals(g.evidence().get(key)),"recognition never proves "+key);
        });
        named("flight_report_uses_general_literal_date_and_cities", () -> {
            String owner=flight.replace("2026年11月25日北京到上海","2028年2月29日广州到深圳");
            NativeAppGoal g=goal(owner,NativeAppGoal.CTRIP_PACKAGE);
            check(LocalDate.of(2028,2,29).equals(g.departureDate)&&"广州".equals(g.fromCity)&&"深圳".equals(g.toCity),"no test-date or route substitution");
            check(!g.contractSha256.equals(goal(flight,NativeAppGoal.CTRIP_PACKAGE).contractSha256),"distinct complete contract");
        });
        named("flight_report_iso_ascii_field_spacing", () -> {
            String owner=flight.replace("查询2026年11月25日北京到上海的单程机票，1名成人", "查询 2027-04-03 从 广州 到 深圳 的 单程 航班, 一 位 成人");
            NativeAppGoal g=goal(owner,NativeAppGoal.CTRIP_PACKAGE);
            check("2027-04-03".equals(owner.substring(g.dateStartUtf16,g.dateEndUtf16)),"ISO boundary span");
            check("广州".equals(g.fromCity)&&"深圳".equals(g.toCity),"ASCII spaces stay outside city spans");
        });
        named("flight_report_explicit_app_not_substituted", () -> {
            String owner=flight.replace("携程","南航");
            NativeAppGoal g=goal(owner,NativeAppGoal.CSAIR_PACKAGE);
            check(NativeAppGoal.CSAIR_PACKAGE.equals(g.packageName),"same complete purpose remains selected-app specific");
        });
        reject("report_unknown_product_model_not_substituted",product.replace("AX3000T","AX3000"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_variant_not_dropped",product.replace("AX3000T","AX3000T双只装"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_wrong_selected_app",product,NativeAppGoal.CTRIP_PACKAGE);
        reject("report_product_website_not_native",product.replace("小米商城","小米官网"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_unknown_suffix",product+"并总结优惠券。",NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_order_after_query",product+"查询完下单。",NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_payment_after_query",product+"然后支付。",NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_positive_purchase_limit",product.replace("不购买","购买"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_positive_order_limit",product.replace("不提交订单","提交订单"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_positive_payment_limit",product.replace("不支付","支付"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_conditional_purchase",product.replace("不支付。","不支付，除非价格合适就购买。"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_double_negation",product.replace("不购买","不是不购买"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_second_app",product+"再去携程查机票。",NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_injected_action_before_limits",product.replace("只查询","先下单，再只查询"),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_missing_model_reading",product.replace("并说明商品型号",""),NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_product_trailing_space_not_trimmed",product+" ",NativeAppGoal.XIAOMI_PACKAGE);
        reject("report_flight_named_app_mismatch",flight,NativeAppGoal.CSAIR_PACKAGE);
        reject("report_flight_invalid_date",flight.replace("2026年11月25日","2027年2月29日"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_missing_year",flight.replace("2026年",""),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_relative_date",flight.replace("2026年11月25日","明天"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_two_adults",flight.replace("1名成人","2名成人"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_extra_child",flight.replace("1名成人","1名成人、1名儿童"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_return_trip",flight.replace("单程","往返"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_alternative_route",flight.replace("北京到上海","北京或天津到上海"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_action_in_city",flight.replace("北京到上海","北京到上海然后支付"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_booking_after_query",flight+"查询完预订。",NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_payment_exception",flight.replace("不支付。","不支付，但可支付低价票。"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_positive_booking",flight.replace("不预订","预订"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_unknown_report_field",flight.replace("航司和价格","航司、库存和价格"),NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_second_app",flight+"再打开小米商城。",NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_tool_clause_not_removed",flight+"只允许click、done。",NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_leading_space_not_trimmed"," "+flight,NativeAppGoal.CTRIP_PACKAGE);
        reject("report_flight_newline_not_normalized",flight.replace("只查询","\n只查询"),NativeAppGoal.CTRIP_PACKAGE);
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
        readOnlyReportCases();
        StringBuilder json=new StringBuilder("{\"schema\":\"hepta.native-app-goal-host.v1\",\"all_pass\":true,\"cases\":")
                .append(names.size()).append(",\"assertions\":").append(assertions).append(",\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)json.append(',');json.append('"').append(names.get(i)).append('"');}
        System.out.println(json.append("]}").toString());
    }
}
