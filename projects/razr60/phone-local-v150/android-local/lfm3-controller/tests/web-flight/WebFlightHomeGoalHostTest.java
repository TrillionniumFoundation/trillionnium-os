package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/**
 * Host-only regression for stage-specific flight next_goal text.
 * Original home DOM and original prompt are byte-pinned. Their task/receipt,
 * native nodes, selections and action outcomes are synthetic unit envelopes.
 * This does not execute a model, Binder, native input, website query or phone task.
 * The unchanged query40 factories are loaded from the reviewed existing gate.
 */
public final class WebFlightHomeGoalHostTest {
    private static final String OWNER="查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final String TASK="11111111111111111111111111111111";
    private static final String LABEL="机票预订按钮，点按两次即可激活";
    private static final String HOME_GOAL="选择实际『机票预订』入口，再观察公开查询表单。";
    private static final String WAIT_GOAL="当前页面没有已验证的只读控件；等待加载或报告未完成。";
    private static final String GENERIC_GOAL="先选择并读回出发城市与到达城市，再选择完整年月日；不能直接提交查询。";
    private static int assertions;
    private static final JSONArray stages=new JSONArray(), checks=new JSONArray();
    private static JSONObject binding, calendar, home;
    private static List<PhoneObservation.Node> calendarRows;
    private static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    private static Object call(Class<?> type,String method,Class<?>[] types,Object...args)throws Exception{
        Method m=type.getDeclaredMethod(method,types);m.setAccessible(true);
        try{return m.invoke(null,args);}catch(InvocationTargetException e){
            if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;
        }
    }
    private static Object q(String method,Class<?>[] types,Object...args)throws Exception{
        return call(WebFlightQueryHostTest.class,method,types,args);
    }
    private static Object factory(String method,Class<?>[] types,Object...args)throws Exception{
        return call(WebTaskCompositionHostTest.class,method,types,args);
    }
    private static Object field(Object object,String name)throws Exception{
        Field f=object.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(object);
    }
    private static void set(String name,Object value)throws Exception{
        Field f=WebFlightQueryHostTest.class.getDeclaredField(name);f.setAccessible(true);f.set(null,value);
    }
    private static String original(String path,String expected)throws Exception{
        byte[] bytes=Files.readAllBytes(Paths.get(path));
        check(WebEvidenceJson.sha(bytes).equals(expected),"original fixture hash: "+expected);
        return new String(bytes,StandardCharsets.UTF_8);
    }
    private static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    @SuppressWarnings("unchecked")
    private static void initialize(String raw,String xml)throws Exception{
        calendar=new JSONObject(new JSONObject(raw).getJSONObject("capture").getString("dom_raw_utf8"))
                .put("schema","hepta.fixed-top-document-dom.v3");
        List<PhoneObservation.Node> rows=(List<PhoneObservation.Node>)call(WebCalendarNativeHostTest.class,"ax",
                new Class<?>[]{String.class},xml);
        calendarRows=new ArrayList<PhoneObservation.Node>();
        for(PhoneObservation.Node row:rows){
            String id=(String)q("nativeId",new Class<?>[]{String.class},row.id);
            calendarRows.add((PhoneObservation.Node)call(WebCalendarNativeHostTest.class,"replace",
                    new Class<?>[]{PhoneObservation.Node.class,String.class,String.class,boolean.class,Rect.class,String.class},
                    row,row.nativeTreePath,row.nativeParentClass,row.enabled,row.bounds,id));
        }
        binding=(JSONObject)factory("binding",new Class<?>[]{String.class},OWNER);
        set("calendar",calendar);set("calendarRows",calendarRows);set("binding",binding);
    }
    private static PhoneObservation.Node button(String id,String text)throws Exception{
        return (PhoneObservation.Node)q("ax",new Class<?>[]{String.class,String.class,String.class,String.class,
                Rect.class,boolean.class,boolean.class,String.class,String.class},
                id,"",text,"android.widget.Button",new Rect(216,1099,612,1372),true,true,
                "0/2/0/7/1/0","android.view.View");
    }
    private static WebFlightDomain observed(JSONObject dom,long time,List<PhoneObservation.Node> rows)throws Exception{
        return (WebFlightDomain)q("observed",new Class<?>[]{JSONObject.class,JSONObject.class,long.class,long.class,List.class},
                binding,copy(dom),time,7L,rows);
    }
    private static WebFlightDomain form(long time,String dep,String arr,String day,String week)throws Exception{
        return (WebFlightDomain)q("formDomain",new Class<?>[]{long.class,String.class,String.class,String.class,String.class},
                time,dep,arr,day,week);
    }
    @SuppressWarnings("unchecked")
    private static WebFlightDomain picker(boolean dep)throws Exception{
        return observed((JSONObject)q("picker",new Class<?>[]{boolean.class},dep),1000,
                (List<PhoneObservation.Node>)q("pickerRows",new Class<?>[]{boolean.class},dep));
    }
    private static ActionDecision click(WebFlightDomain d,String id)throws Exception{
        return (ActionDecision)q("click",new Class<?>[]{WebFlightDomain.class,String.class},d,id);
    }
    private static String run(int n)throws Exception{return (String)q("run",new Class<?>[]{int.class},n);}
    private static WebFlightDomain snapshot(String name,WebFlightDomain original,WebFlightProgress p)throws Exception{
        WebFlightDomain current=original.withProgress(p);
        JSONObject item=new JSONObject().put("name",name).put("original_phase",original.phase)
                .put("original_next_goal",original.evidence().get("next_goal"))
                .put("current",new JSONObject(current.evidence()))
                .put("tool_mask",new JSONArray(new TreeSet<String>(current.toolMask(null))))
                .put("click_ids",new JSONArray(new TreeSet<String>(current.clickIds)))
                .put("edit_values",new JSONObject(current.editValues))
                .put("page_key",current.pageKey).put("query_dispatched",current.queryDispatched())
                .put("result_ready",current.resultReady());
        stages.put(item);return current;
    }
    private static void desired(String name,boolean yes){checks.put(new JSONObject().put("name",name).put("pass",yes));}
    public static void main(String[] args)throws Exception{
        check(args.length==5,"calendar DOM, same-case AX, original home capture, original prompt, new report");
        String calRaw=original(args[0],"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa");
        String calAx=original(args[1],"59d753e32edd620eb2e1fb0947c898df89eb7bf8dbc63dc4138a1636272b82ec");
        String homeRaw=original(args[2],"73e20002f8f2cea161084681f558504d8afb58d09e8e2812ce8ff22a96b7a6c5");
        String promptRaw=original(args[3],"85d6d118b66375f368c3fbcb26ea66aed6f1b58a8f2083e2f6bb22d51f472b14");
        home=new JSONObject(new JSONObject(homeRaw).getJSONObject("capture").getString("dom_raw_utf8"));
        check(home.getJSONArray("nodes").length()==166,"actual home DOM membership");
        check(promptRaw.startsWith("UNTRUSTED_DATA\n")&&promptRaw.indexOf("\nOWNER\n")>0,"saved prompt framing");
        JSONObject prompt=new JSONObject(promptRaw.substring("UNTRUSTED_DATA\n".length(),promptRaw.indexOf("\nOWNER\n")));
        JSONObject official=prompt.getJSONObject("completion").getJSONObject("official_page");
        check("official_home".equals(official.getString("phase"))&&GENERIC_GOAL.equals(official.getString("next_goal")),
                "actual saved home prompt contains the pre-fix form instruction");
        check(official.getJSONArray("allowed_click_ids").length()==1
                &&"n38".equals(official.getJSONArray("allowed_click_ids").getString(0))
                &&"open_public_booking_form".equals(official.getJSONArray("current_controls").getJSONObject(0).getString("purpose")),
                "actual saved prompt had a booking capability");
        check(LABEL.equals(prompt.getJSONObject("screen").getJSONArray("nodes").getJSONArray(0).getString(1)),
                "actual saved native label is retained for this host fixture");
        initialize(calRaw,calAx);
        List<PhoneObservation.Node> homeRows=Collections.singletonList(button("n38",LABEL));
        WebFlightDomain initial=observed(home,1000,homeRows);
        check("official_home".equals(initial.phase)&&initial.clickIds.equals(Collections.singleton("n38")),
                "actual production parsing recognizes the actual homepage and exact label");
        check(HOME_GOAL.equals(initial.evidence().get("next_goal")),"original build has the correct homepage instruction");
        WebFlightDomain current=snapshot("homepage_booking",initial,WebFlightProgress.begin(initial));
        check(current.clickIds.equals(initial.clickIds)&&current.toolMask(null).equals(initial.toolMask(null)),
                "wording change does not mint or remove the existing click");
        check(!current.queryDispatched()&&!current.resultReady()&&current.editValues.isEmpty(),"no query/result/edit authority");
        desired("homepage_booking_retains_observed_entry_goal",HOME_GOAL.equals(current.evidence().get("next_goal")));

        WebFlightDomain absent=observed(home,1000,Collections.<PhoneObservation.Node>emptyList());
        check("official_home".equals(absent.phase)&&absent.clickIds.isEmpty()&&WAIT_GOAL.equals(absent.evidence().get("next_goal")),
                "missing native capability already yields original wait goal");
        current=snapshot("homepage_without_verified_entry",absent,WebFlightProgress.begin(absent));
        check(current.clickIds.isEmpty()&&!current.toolMask(null).contains("click"),"missing capability cannot become a click");
        desired("homepage_without_entry_retains_wait_goal",WAIT_GOAL.equals(current.evidence().get("next_goal")));

        WebFlightDomain duplicate=observed(home,1000,Arrays.asList(button("n38",LABEL),button("n39",LABEL)));
        check(duplicate.clickIds.isEmpty(),"native duplicate remains ambiguous");
        current=snapshot("homepage_duplicate_entry",duplicate,WebFlightProgress.begin(duplicate));
        check(current.clickIds.isEmpty(),"progress cannot authorize duplicate entry");
        desired("homepage_duplicate_retains_wait_goal",WAIT_GOAL.equals(current.evidence().get("next_goal")));

        JSONObject req=(JSONObject)factory("request",new Class<?>[]{long.class},7L);
        JSONObject callback=(JSONObject)factory("callback",new Class<?>[]{JSONObject.class,JSONObject.class},binding,req);
        WebEvidenceReceipt unavailable=WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,req.toString(),binding,
                callback.toString(),null,10484,1000,1500);
        WebTaskPurpose purpose=WebTaskPurpose.requireBinding(binding);
        PhoneObservation empty=(PhoneObservation)q("frame",new Class<?>[]{long.class,List.class},
                1000L,Collections.<PhoneObservation.Node>emptyList());
        WebFlightDomain wait=WebFlightDomain.waiting(TASK,purpose.flight,purpose.authorization.bind(TASK),empty,
                unavailable,WebEvidenceBinding.sha256(binding));
        current=snapshot("capture_pending",wait,WebFlightProgress.begin(wait));
        check("official_page_capture_pending".equals(current.phase)&&current.clickIds.isEmpty()
                &&!current.toolMask(null).contains("click"),"metadata unavailable still cannot act");

        WebFlightDomain unconfirmed=form(1000,null,null,"11月13日","周五");
        current=snapshot("form_unconfirmed",unconfirmed,WebFlightProgress.begin(unconfirmed));
        check(GENERIC_GOAL.equals(current.evidence().get("next_goal"))
                &&!current.clickIds.contains("n1003"),"form still selects and confirms cities before query");
        WebFlightDomain dep=picker(true);
        current=snapshot("city_picker",dep,WebFlightProgress.begin(dep));
        check(current.clickIds.equals(Collections.singleton("n1004")),"city picker exact target retained");
        WebFlightProgress pending=WebFlightProgress.begin(dep).outcome(dep,click(dep,"city"),run(1),
                true,true,false,false,1012,1015);
        current=snapshot("selection_readback_pending",dep,pending);
        check("official_selection_readback_pending".equals(current.phase)&&current.clickIds.isEmpty()
                &&current.evidence().get("next_goal").toString().startsWith("上次城市或日期点击"),
                "selection pending priority preserved");
        WebFlightDomain laterHome=observed(home,1120,homeRows);
        current=snapshot("homepage_while_selection_pending",laterHome,pending);
        check("official_selection_readback_pending".equals(current.phase)&&current.clickIds.isEmpty()
                &&current.evidence().get("next_goal").toString().startsWith("上次城市或日期点击"),
                "homepage cannot override pending priority");

        WebFlightDomain cal=observed(calendar,1080,calendarRows);
        current=snapshot("calendar_before_city_confirmation",cal,WebFlightProgress.begin(cal));
        check(current.clickIds.isEmpty(),"calendar remains withheld before city confirmations");
        Object cities=q("cities",new Class<?>[]{});
        WebFlightProgress cityProgress=(WebFlightProgress)field(cities,"progress");
        current=snapshot("calendar_with_confirmed_cities",cal,cityProgress);
        check(current.clickIds.size()==1,"date capability remains exactly one after confirmations");
        current=snapshot("homepage_after_confirmed_cities",laterHome,cityProgress);
        check(HOME_GOAL.equals(current.evidence().get("next_goal")),"already-confirmed route keeps original home goal");

        Object ready=q("ready",new Class<?>[]{});
        WebFlightDomain readyForm=(WebFlightDomain)field(ready,"current");
        WebFlightProgress readyProgress=(WebFlightProgress)field(ready,"progress");
        current=snapshot("query_ready",readyForm,readyProgress);
        check("official_query_ready".equals(current.phase)&&current.clickIds.equals(Collections.singleton("n1003"))
                &&current.evidence().get("next_goal").toString().startsWith("出发城市、到达城市、完整日期"),
                "ready priority preserves one query capability");
        ActionDecision query=click(readyForm,"queryBtn");
        WebFlightProgress reserved=readyProgress.reserveQuery(readyForm,query,run(6));
        current=snapshot("query_attempt_unconfirmed",readyForm,reserved);
        check("official_query_attempt_unconfirmed".equals(current.phase)&&current.clickIds.isEmpty()
                &&current.evidence().get("next_goal").toString().startsWith("查询尝试已经记录"),
                "reservation consumes one-shot capability");
        current=snapshot("homepage_after_query_attempt",laterHome,reserved);
        check("official_query_attempt_unconfirmed".equals(current.phase)&&current.clickIds.isEmpty()
                &&current.evidence().get("next_goal").toString().startsWith("查询尝试已经记录"),
                "homepage cannot override a reserved query");
        WebFlightProgress dispatched=reserved.outcome(readyForm,query,run(6),true,true,false,true,1112,1115);
        WebFlightDomain after=form(1120,"北京","上海","11月17日","周二");
        dispatched=dispatched.observed(after);
        current=snapshot("query_result_pending",after,dispatched);
        check("official_query_result_pending".equals(current.phase)&&current.queryDispatched()
                &&current.clickIds.isEmpty()&&!current.resultReady(),"actual result evidence remains mandatory");
        current=snapshot("homepage_after_query_dispatch",laterHome,dispatched);
        check("official_query_result_pending".equals(current.phase)&&current.clickIds.isEmpty()&&!current.resultReady()
                &&current.evidence().get("next_goal").toString().startsWith("查询尝试已经记录"),
                "homepage cannot re-enable a consumed query");

        boolean passed=true;for(int i=0;i<checks.length();i++)passed&=checks.getJSONObject(i).getBoolean("pass");
        JSONObject report=new JSONObject().put("schema","hepta.flight-home-goal-host.v1")
                .put("all_pass",passed).put("assertions",assertions).put("stages_count",stages.length())
                .put("desired_home_checks",checks).put("stages",stages)
                .put("original_home_capture_sha256",WebEvidenceJson.sha(homeRaw))
                .put("original_prompt_sha256",WebEvidenceJson.sha(promptRaw))
                .put("calendar_original_sha256",WebEvidenceJson.sha(calRaw))
                .put("calendar_ax_original_sha256",WebEvidenceJson.sha(calAx))
                .put("task_receipt_native_and_model_outcomes_synthetic",true)
                .put("actual_model_executed",false).put("phone_actions",0)
                .put("actual_query_executed",false).put("business_verified",false);
        Files.write(Paths.get(args[4]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("home checks="+checks.length()+" stages="+stages.length()+" assertions="+assertions+" all_pass="+passed);
        if(!passed)System.exit(2);
    }
}
