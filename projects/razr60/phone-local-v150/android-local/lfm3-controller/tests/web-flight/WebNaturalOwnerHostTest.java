package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.local.web.WebShoppingGoal;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Actual old compiler in an isolated loader; original OWNER is never synthesized for authority. */
public final class WebNaturalOwnerHostTest {
    private static int assertions;
    private static final List<String> passed=new ArrayList<String>();
    private interface Run {void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Run action)throws Exception{action.run();passed.add(name);}
    private static String hash(String text)throws Exception{
        StringBuilder out=new StringBuilder();
        for(byte b:MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)))
            out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
    private static Map<String,Object> outcome(Method parse,String owner)throws Exception{
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        try{Object actual=parse.invoke(null,owner);out.put("evidence",actual.getClass().getMethod("evidence").invoke(actual));}
        catch(InvocationTargetException rejected){
            Throwable actual=rejected.getCause();out.put("error_class",actual.getClass().getName());out.put("error",actual.getMessage());
        }
        return out;
    }
    private static void immutable(Run action)throws Exception{
        boolean rejected=false;try{action.run();}catch(UnsupportedOperationException expected){rejected=true;}
        check(rejected,"mutable purpose contract");
    }
    private static String legacy(int y,int m,int d,String from,String to,boolean open){
        return "网页查询测试：在南航官方网站查询"+y+"年"+m+"月"+d+"日"+from+"到"+to
                +"的单程航班，1名成人。"+(open?WebFlightGoal.BACKGROUND_TAIL:WebFlightGoal.TAIL);
    }
    public static void main(String[] args)throws Exception{
        check(args.length==2,"actual baseline classes and new result required");
        Path baseline=Paths.get(args[0]),output=Paths.get(args[1]);check(Files.isDirectory(baseline)&&!Files.exists(output),"real baseline/new output");
        try(URLClassLoader old=new URLClassLoader(new URL[]{baseline.toUri().toURL()},null)){
            Class<?> priorAuthorization=Class.forName("org.trillionnium.hepta.local.TaskAuthorization",true,old);
            Class<?> priorGoal=Class.forName("org.trillionnium.hepta.local.web.WebFlightGoal",true,old);
            Method oldParse=priorAuthorization.getMethod("parse",String.class);
            Method newParse=TaskAuthorization.class.getMethod("parse",String.class);
            Method oldGoalParse=priorGoal.getMethod("parse",String.class);
            check(priorAuthorization!=TaskAuthorization.class&&priorGoal!=WebFlightGoal.class,"isolated actual old implementation");
            String[] natural={
                "查一下2026年11月17日北京到上海的单程机票，1名成人",
                "请查一下2026年11月17日从北京到上海的单程机票，1位成人。",
                "帮我查询2026-11-17北京到上海单程航班,一名成人",
                "请帮我查查南航官网2026年11月17日北京到上海的单程航班，1名成人",
                "查询中国南方航空官方网站上的2026年11月17日北京到上海的单程机票，1名成人"
            };
            // The fifth phrase is intentionally outside the fixed optional single suffix grammar.
            for(int i=0;i<4;i++){
                final String owner=natural[i];test("natural_flight_exact_"+i,()->{
                    WebFlightGoal goal=WebFlightGoal.parse(owner);
                    check(goal!=null&&goal.naturalReadOnlyIntent,"recognized complete original flight");
                    check(owner.equals(goal.immutableOwner)&&hash(owner).equals(goal.ownerSha256),"unchanged exact OWNER/hash");
                    check(LocalDate.of(2026,11,17).equals(goal.departureDate)
                            &&"北京".equals(goal.fromCity)&&"上海".equals(goal.toCity),"explicit actual route/date");
                    check(owner.substring(goal.fromStartUtf16,goal.fromEndUtf16).equals("北京")
                            &&owner.substring(goal.toStartUtf16,goal.toEndUtf16).equals("上海"),"exact UTF16 city spans");
                    String date=owner.substring(goal.dateStartUtf16,goal.dateEndUtf16);
                    check(date.equals("2026年11月17日")||date.equals("2026-11-17"),"exact original date span");
                    check(goal.allowsInitialOfficialPage()&&!goal.ownerContainsOpen,"intent is not fabricated open token");
                    check(goal.departureNotBefore(LocalDate.of(2026,11,17))
                            &&!goal.departureNotBefore(LocalDate.of(2026,11,18)),"real task date boundary");
                    check(Boolean.FALSE.equals(goal.evidence().get("grants_tool_authority"))
                            &&Boolean.FALSE.equals(goal.evidence().get("query_executed"))
                            &&Boolean.FALSE.equals(goal.evidence().get("owner_rewritten")),"purpose not action proof");
                    TaskAuthorization auth=TaskAuthorization.parse(owner);
                    @SuppressWarnings("unchecked") Map<String,Object> prior=(Map<String,Object>)outcome(oldParse,owner).get("evidence");
                    check(prior!=null,"real original compiler accepted natural text");
                    @SuppressWarnings("unchecked") List<String> priorTools=(List<String>)prior.get("allowed_tools");
                    Set<String> intersection=new TreeSet<String>(priorTools);intersection.retainAll(goal.toolCeiling());
                    check(auth.allowedTools.equals(intersection)&&auth.allowedTools.size()==8,"old actual allowed set intersected with purpose only");
                    check(!auth.allows("find_app")&&!auth.allows("home")&&!auth.allows("notes.create")&&!auth.allows("web.search"),"no generic tool escape");
                    check(auth.instructionSha256.equals(hash(owner))&&auth.immutableOwner().equals(owner),"authority keeps full owner");
                    Map<String,Object> evidence=auth.evidence();
                    check(evidence.get("parser").equals(TaskAuthorization.PARSER+"+natural-flight-ceiling.v1")
                            &&evidence.get("recognized_rules").equals(Collections.singletonList(TaskAuthorization.NATURAL_FLIGHT_RULE)),
                            "truthful natural authority provenance");
                    check(Boolean.FALSE.equals(evidence.get("arbitrary_semantic_constraints_verified")),"no arbitrary semantic claim");
                    immutable(()->goal.toolCeiling().clear());
                });
            }
            String[] unsupported={
                natural[4],"查一下11月17日北京到上海的单程机票，1名成人",
                "查一下2026年11月17日北京到上海的机票，1名成人",
                "查一下2026年11月17日北京到上海的单程机票，2名成人",
                "查一下2026年11月17日北京到上海的单程机票，1名儿童",
                "查一下2026年11月17日北京到北京的单程机票，1名成人",
                "查一下2026年2月29日北京到上海的单程机票，1名成人",
                "查一下2026年13月17日北京到上海的单程机票，1名成人",
                "查一下2026-1-17北京到上海的单程机票，1名成人",
                "查一下2026年11月17日北京到上海的单程机票，1名成人，然后付款",
                "查一下2026年11月17日北京到上海的单程机票，1名成人，不要输入",
                "查一下2026年11月17日北京到上海的单程机票，1名成人，只允许click",
                "查一下2026年11月17日北京到上海的单程机票，1名成人，先find_app再open",
                "查一下2026年11月17日北京以及广州到上海的单程机票，1名成人",
                " 查一下2026年11月17日北京到上海的单程机票，1名成人",
                "查一下2026年11月17日北京到上海的单程机票，1名成人\n"
            };
            for(int i=0;i<unsupported.length;i++){
                final String owner=unsupported[i];test("unsupported_flight_raw_compiler_"+i,()->{
                    check(WebFlightGoal.parse(owner)==null,"unsupported goal rejected exactly");
                    check(outcome(oldParse,owner).equals(outcome(newParse,owner)),"all original restrictions/errors preserved for unsupported syntax");
                });
            }
            test("leap_day_is_explicit",()->check(WebFlightGoal.parse("查一下2028年2月29日北京到上海的单程机票，1名成人")!=null,"real leap day"));
            test("natural_city_method_clause_keeps_real_deny",()->{
                String owner="查一下2026年11月17日使用按键计算到上海的单程机票，1名成人";
                WebFlightGoal goal=WebFlightGoal.parse(owner);check(goal!=null,"bounded Han data is not a second authority parser");
                TaskAuthorization auth=TaskAuthorization.parse(owner);
                @SuppressWarnings("unchecked") Map<String,Object> prior=(Map<String,Object>)outcome(oldParse,owner).get("evidence");
                @SuppressWarnings("unchecked") List<String> priorTools=(List<String>)prior.get("allowed_tools");
                Set<String> allowed=new TreeSet<String>(priorTools);allowed.retainAll(goal.toolCeiling());
                check(auth.allowedTools.equals(allowed)&&!auth.allows("type"),"actual observed_keys_no_type is never erased by purpose");
                @SuppressWarnings("unchecked") List<String> rules=(List<String>)auth.evidence().get("recognized_rules");
                check(rules.contains("observed_keys_no_type")&&rules.contains(TaskAuthorization.NATURAL_FLIGHT_RULE),"both real rule sources retained");
            });
            for(boolean open:new boolean[]{false,true})for(String route:new String[]{"北京,上海","广州,深圳","乌鲁木齐,哈尔滨"}){
                String[] cities=route.split(",");final String owner=legacy(2026,11,17,cities[0],cities[1],open);
                test("unchanged_legacy_flight_"+open+"_"+route,()->{
                    Object prior=oldGoalParse.invoke(null,owner);WebFlightGoal goal=WebFlightGoal.parse(owner);
                    check(prior!=null&&goal!=null&&!goal.naturalReadOnlyIntent,"real old and new exact legacy parser");
                    check(priorGoal.getMethod("evidence").invoke(prior).equals(goal.evidence()),"entire old contract/evidence unchanged");
                    check(priorGoal.getField("contractSha256").get(prior).equals(goal.contractSha256),"old exact contract hash");
                    check(outcome(oldParse,owner).equals(outcome(newParse,owner)),"entire old authority unchanged");
                });
            }
            String[] oldOwners={
                "帮我记一下，明天下午三点看牙，带检查资料","记一下，牛奶，使用按键计算","记一下，牛奶，通过按按钮操作",
                "记一下，先查找计算器应用再reopen","记一下，先find_app再open",
                "记一下，牛奶，只允许click","记一下，牛奶，不要输入","记一下，牛奶，可以输入",
                "记一下：‘牛奶，带检查资料’","先查找计算器应用再打开，只允许find_app、open、wait、done",
                "先查找‘计算器’应用再打开","不要输入，允许输入","只允许click，但是可以输入","不要不输入",
                "使用按键计算","只允许click、back、wait、done","打开设置然后查看网络","记一下：牛奶，咖啡"
            };
            for(int i=0;i<oldOwners.length;i++){
                final String owner=oldOwners[i];test("raw_owner_backward_equivalence_"+i,()->
                    check(outcome(oldParse,owner).equals(outcome(newParse,owner)),"old full compiler/evidence/error unchanged"));
            }
            String[] products={"查一下小米AX3000T的官网售价","帮我查询小米官网AX3000T价格",WebShoppingGoal.LEGACY_EXPLICIT_OWNER};
            for(int i=0;i<products.length;i++){
                final String owner=products[i];test("shopping_pure_original_owner_"+i,()->{
                    WebShoppingGoal goal=WebShoppingGoal.parse(owner);check(goal!=null,"actual pure shopping goal");
                    check(goal.owner.equals(owner)&&goal.ownerSha256.equals(hash(owner)),"original product owner");
                    check(owner.substring(goal.productStartUtf16,goal.productEndUtf16).equalsIgnoreCase("AX3000T"),"actual product UTF16 span");
                    check(!goal.naturalReadOnlyIntent||!goal.specificationsRequested&&!goal.singleUnitRequested,"price-only intent not expanded");
                    TaskAuthorization auth=TaskAuthorization.parse(owner);
                    @SuppressWarnings("unchecked") Map<String,Object> prior=(Map<String,Object>)outcome(oldParse,owner).get("evidence");
                    check(prior!=null,"original compiler accepted product owner");
                    @SuppressWarnings("unchecked") List<String> priorTools=(List<String>)prior.get("allowed_tools");
                    Set<String> tools=new TreeSet<String>(priorTools);tools.retainAll(goal.toolCeiling());
                    check(auth.allowedTools.equals(tools)&&auth.allowedTools.size()==6,"actual product intersection");
                    check(!auth.allows("type")&&!auth.allows("submit"),"read-only product ceiling");
                    String rule=goal.naturalReadOnlyIntent?TaskAuthorization.NATURAL_SHOPPING_RULE:TaskAuthorization.EXPLICIT_SHOPPING_RULE;
                    check(((List<?>)auth.evidence().get("recognized_rules")).contains(rule),"actual product provenance");
                    String canonical=WebEvidenceBinding.canonical(new JSONObject(goal.contract()));
                    check(canonical.equals(goal.canonicalContract())&&hash(canonical).equals(goal.contractSha256),"canonical equals actual shared implementation");
                    immutable(()->goal.contract().put("model_term","other"));
                    immutable(()->((List<?>)goal.contract().get("tool_ceiling")).clear());
                    immutable(()->goal.toolCeiling().clear());
                    check(Boolean.FALSE.equals(goal.evidence().get("grants_tool_authority")),"goal never grants authority");
                });
            }
            test("canonical_full_utf16_and_integer_semantics",()->{
                Map<String,Object> nested=new LinkedHashMap<String,Object>();nested.put("空",null);nested.put("整数",Long.valueOf(7));
                Map<String,Object> value=new LinkedHashMap<String,Object>();
                value.put("\uD83D\uDE00",Arrays.asList("汉字","\n\t\b\f\r\"\\",Boolean.FALSE,Long.valueOf(9007199254740991L)));
                value.put("\uE000",nested);value.put("ASCII",Boolean.TRUE);
                JSONObject jsonValue=new JSONObject(value);
                check(!jsonValue.getJSONObject("\uE000").has("空"),"pinned host Map constructor omits Java null");
                jsonValue.getJSONObject("\uE000").put("空",JSONObject.NULL);
                check(jsonValue.getJSONObject("\uE000").has("空")&&jsonValue.getJSONObject("\uE000").isNull("空"),
                        "JSON comparison retains the original null-valued key");
                check(WebShoppingGoal.contractHash(value).equals(hash(WebEvidenceBinding.canonical(jsonValue))),
                        "no second JSON canonical encoding");
            });
            JSONObject result=new JSONObject().put("schema","hepta.v54-natural-owner-host.v1").put("all_pass",true)
                    .put("cases",passed.size()).put("assertions",assertions).put("case_names",new JSONArray(passed))
                    .put("baseline_is_actual_compiled_v53_source",true).put("original_owner_preserved",true)
                    .put("original_authority_is_intersected_not_expanded",true).put("phone_commands_executed",0)
                    .put("android_runtime",false).put("business_verified",false);
            Files.write(output,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
            System.out.println("WebNaturalOwnerHostTest cases="+passed.size()+" assertions="+assertions);
        }
    }
}
