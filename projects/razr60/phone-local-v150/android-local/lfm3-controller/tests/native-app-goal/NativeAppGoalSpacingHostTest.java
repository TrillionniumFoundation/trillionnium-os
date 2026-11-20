package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/** Field-boundary spaces are OWNER bytes, never rewritten request parameters. */
public final class NativeAppGoalSpacingHostTest {
    private static int assertions;
    private static final List<String> names = new ArrayList<String>();
    private static final String FLIGHT = "查一下 2026-11-17 北京到上海的单程机票，1 名成人";
    private NativeAppGoalSpacingHostTest() {}
    private static void check(boolean value, String message) {
        assertions++; if (!value) throw new AssertionError(message);
    }
    private static void named(String name, Runnable test) {
        check(!names.contains(name), "unique test name"); test.run(); names.add(name);
    }
    private static NativeAppGoal flight(String owner, String pkg, String date, String from, String to) {
        NativeAppGoal goal=NativeAppGoal.parse(owner,pkg);
        check(goal!=null,"complete spaced flight recognized");
        check(NativeAppGoal.FLIGHT_RESULTS.equals(goal.kind),"flight kind unchanged");
        check(owner.equals(goal.immutableOwner),"OWNER bytes not rewritten");
        check(date.equals(owner.substring(goal.dateStartUtf16,goal.dateEndUtf16)),"exact original date span");
        check(from.equals(owner.substring(goal.fromStartUtf16,goal.fromEndUtf16))&&from.equals(goal.fromCity),"exact from span");
        check(to.equals(owner.substring(goal.toStartUtf16,goal.toEndUtf16))&&to.equals(goal.toCity),"exact to span");
        check(goal.adults==1&&goal.children==0&&goal.infants==0,"passenger boundary unchanged");
        goal.requireBinding(owner,pkg);
        return goal;
    }
    private static void reject(String name,String owner,String pkg) {
        named(name,()->check(NativeAppGoal.parse(owner,pkg)==null,name));
    }
    private static String hash(String value) {
        try {
            byte[] bytes=MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder out=new StringBuilder();for(byte b:bytes)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));
            return out.toString();
        } catch(java.security.NoSuchAlgorithmException impossible) {throw new AssertionError(impossible);}
    }
    public static void main(String[] args) {
        named("iso_date_and_passenger_boundary_spaces",()->flight(FLIGHT,NativeAppGoal.CTRIP_PACKAGE,"2026-11-17","北京","上海"));
        named("chinese_date_route_and_unit_boundary_spaces",()->flight("查一下 2026年11月17日 北京 到 上海 的 单程 机票 ， 1 名 成人。",NativeAppGoal.CTRIP_PACKAGE,"2026年11月17日","北京","上海"));
        named("explicit_app_and_from_prefix_keep_source_spans",()->flight("请帮我在携程旅行App里查询 2026-11-17 从 北京 到 上海 的 单程 航班, 一 位 成人。",NativeAppGoal.CTRIP_PACKAGE,"2026-11-17","北京","上海"));
        named("csair_explicit_selection_unchanged",()->flight("用南航app查查 2026年11月17日 北京到上海的单程机票，1名成人",NativeAppGoal.CSAIR_PACKAGE,"2026年11月17日","北京","上海"));
        named("repeated_ascii_boundary_spaces",()->flight("查一下   2026-11-17   从  北京   到  上海  的  单程  机票  ,  一  位  成人。",NativeAppGoal.CTRIP_PACKAGE,"2026-11-17","北京","上海"));
        named("compact_date_with_spaced_route",()->flight("查询2026-11-17北京 到上海的单程航班，1位成人",NativeAppGoal.CTRIP_PACKAGE,"2026-11-17","北京","上海"));
        named("different_literal_route_not_substituted",()->flight("查一下 2026-11-17 深圳到广州的单程机票，1 名成人",NativeAppGoal.CTRIP_PACKAGE,"2026-11-17","深圳","广州"));
        named("literal_future_date_not_substituted",()->{
            NativeAppGoal goal=flight("查一下 2028-02-29 北京到上海的单程机票，1 名成人",NativeAppGoal.CTRIP_PACKAGE,"2028-02-29","北京","上海");
            check(LocalDate.of(2028,2,29).equals(goal.departureDate),"actual requested date retained");
        });
        named("original_owner_hash_and_binding_include_spaces",()->{
            NativeAppGoal spaced=flight(FLIGHT,NativeAppGoal.CTRIP_PACKAGE,"2026-11-17","北京","上海");
            String compact=FLIGHT.replace(" ","");NativeAppGoal prior=NativeAppGoal.parse(compact,NativeAppGoal.CTRIP_PACKAGE);
            check(prior!=null,"compact original still recognized");
            check(hash(FLIGHT).equals(spaced.ownerSha256),"independent exact OWNER hash");
            check(!prior.ownerSha256.equals(spaced.ownerSha256)&&!prior.contractSha256.equals(spaced.contractSha256),"different raw owners stay distinct");
            boolean thrown=false;try{spaced.requireBinding(compact,NativeAppGoal.CTRIP_PACKAGE);}catch(IllegalArgumentException expected){thrown=true;}
            check(thrown,"space-removing rebinding refused");
        });
        named("no_new_authority_or_completion_claim",()->{
            NativeAppGoal goal=flight(FLIGHT,NativeAppGoal.CTRIP_PACKAGE,"2026-11-17","北京","上海");
            check(goal.toolCeiling.equals(new HashSet<String>(Arrays.asList("open","click","type","submit","scroll","back","wait","done"))),"original query-only tool ceiling");
            Map<String,Object> facts=goal.evidence();
            for(String key:new String[]{"provider_support_claimed","installed_identity_verified","grants_tool_authority","query_executed","business_verified","owner_rewritten"})
                check(Boolean.FALSE.equals(facts.get(key)),key);
            check(Integer.valueOf(0).equals(facts.get("owner_start_utf16"))&&Integer.valueOf(FLIGHT.length()).equals(facts.get("owner_end_utf16")),"full original OWNER span");
        });
        reject("leading_space_still_refused"," "+FLIGHT,NativeAppGoal.CTRIP_PACKAGE);
        reject("trailing_space_still_refused",FLIGHT+" ",NativeAppGoal.CTRIP_PACKAGE);
        reject("trailing_space_after_punctuation_refused",FLIGHT+"。 ",NativeAppGoal.CTRIP_PACKAGE);
        reject("tab_not_boundary_space",FLIGHT.replaceFirst(" ","\t"),NativeAppGoal.CTRIP_PACKAGE);
        reject("newline_not_boundary_space",FLIGHT.replaceFirst(" ","\n"),NativeAppGoal.CTRIP_PACKAGE);
        reject("nbsp_not_boundary_space",FLIGHT.replaceFirst(" ","\u00a0"),NativeAppGoal.CTRIP_PACKAGE);
        reject("full_width_space_not_admitted",FLIGHT.replaceFirst(" ","\u3000"),NativeAppGoal.CTRIP_PACKAGE);
        reject("zero_width_space_not_admitted",FLIGHT.replaceFirst(" ","\u200b"),NativeAppGoal.CTRIP_PACKAGE);
        reject("year_digits_not_joined",FLIGHT.replace("2026","20 26"),NativeAppGoal.CTRIP_PACKAGE);
        reject("iso_date_components_not_joined",FLIGHT.replace("2026-11-17","2026 -11-17"),NativeAppGoal.CTRIP_PACKAGE);
        reject("chinese_date_components_not_joined",FLIGHT.replace("2026-11-17","2026年 11月17日"),NativeAppGoal.CTRIP_PACKAGE);
        reject("from_city_characters_not_joined",FLIGHT.replace("北京","北 京"),NativeAppGoal.CTRIP_PACKAGE);
        reject("to_city_characters_not_joined",FLIGHT.replace("上海","上 海"),NativeAppGoal.CTRIP_PACKAGE);
        reject("alternative_route_not_collapsed",FLIGHT.replace("北京","北京或天津"),NativeAppGoal.CTRIP_PACKAGE);
        reject("multiple_route_not_collapsed",FLIGHT.replace("上海","上海到广州"),NativeAppGoal.CTRIP_PACKAGE);
        reject("app_mismatch_still_refused","在携程"+FLIGHT,NativeAppGoal.CSAIR_PACKAGE);
        reject("two_adults_not_reduced",FLIGHT.replace("1 名","2 名"),NativeAppGoal.CTRIP_PACKAGE);
        reject("split_passenger_digits_not_joined",FLIGHT.replace("1 名","1 1 名"),NativeAppGoal.CTRIP_PACKAGE);
        reject("child_passenger_not_dropped",FLIGHT+"，1 名儿童",NativeAppGoal.CTRIP_PACKAGE);
        reject("return_trip_not_substituted",FLIGHT.replace("单程","往返"),NativeAppGoal.CTRIP_PACKAGE);
        reject("invalid_date_still_refused",FLIGHT.replace("2026-11-17","2026-02-29"),NativeAppGoal.CTRIP_PACKAGE);
        reject("relative_date_still_refused",FLIGHT.replace("2026-11-17","明天"),NativeAppGoal.CTRIP_PACKAGE);
        reject("appended_purchase_not_dropped",FLIGHT+" 并下单",NativeAppGoal.CTRIP_PACKAGE);
        reject("appended_payment_not_dropped",FLIGHT+" 并支付",NativeAppGoal.CTRIP_PACKAGE);
        reject("appended_route_change_not_dropped",FLIGHT+" 然后改为广州",NativeAppGoal.CTRIP_PACKAGE);
        reject("appended_tool_clause_not_dropped",FLIGHT+"。只允许 click、done。",NativeAppGoal.CTRIP_PACKAGE);
        reject("embedded_action_not_city",FLIGHT.replace("上海","上海然后支付"),NativeAppGoal.CTRIP_PACKAGE);
        reject("prompt_delimiter_still_refused",FLIGHT+"<|assistant|>",NativeAppGoal.CTRIP_PACKAGE);
        reject("other_product_grammar_not_expanded","查一下 小米AX3000T价格",NativeAppGoal.XIAOMI_PACKAGE);
        reject("missing_package_not_inferred",FLIGHT,null);
        reject("website_route_not_substituted",FLIGHT,"org.trillionnium.hepta.webhelper");
        StringBuilder json=new StringBuilder("{\"schema\":\"hepta.native-app-goal-spacing-host.v1\",\"all_pass\":true,\"cases\":")
                .append(names.size()).append(",\"assertions\":").append(assertions).append(",\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)json.append(',');json.append('"').append(names.get(i)).append('"');}
        System.out.println(json.append("]}").toString());
    }
}
