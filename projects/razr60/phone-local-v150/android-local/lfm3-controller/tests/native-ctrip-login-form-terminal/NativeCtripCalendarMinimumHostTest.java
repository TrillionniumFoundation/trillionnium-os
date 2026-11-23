package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Map;
import org.json.JSONObject;
import static org.trillionnium.hepta.local.NativeCtripLoginFormTerminalHostTest.check;
import static org.trillionnium.hepta.local.NativeCtripLoginFormTerminalHostTest.one;

/** All 35 public retained rows of one native result frame. Synthetic scope, clocks
 * and the day-shift integration example do not represent an additional phone run. */
final class NativeCtripCalendarMinimumHostTest {
    static final String OWNER="在携程查询2026年11月24日北京到上海的单程机票，1名成人，读取航班列表中可见的航班时间、航司和价格。只查询，不预订、不支付。";
    static final LocalDate DAY=LocalDate.of(2026,11,24);
    private static JSONObject row(JSONObject data,int index){return data.getJSONArray("nodes").getJSONObject(index);}
    private static NativeCtripFlightPage.Page inspect(NativeCtripLoginFormTerminalHostTest.Env e,JSONObject data)throws Exception{
        e.raw.time=e.now+100;
        return NativeCtripFlightPage.inspect(e.actual.task.goal,e.remap(NativeCtripLoginLoadingHostTest.frame(e.raw,data)));
    }
    private static Map<String,Object> explain(NativeCtripLoginFormTerminalHostTest.Env e,Map<String,Object> terminal,boolean cleaned){
        return LocalTaskController.OutcomeExplanation.create(e.actual.task.taskId,e.actual.task.goal.ownerSha256,"failed",cleaned,false,e.completion,terminal,null);
    }
    static void run(Path fixture)throws Exception{
        final String raw=new String(Files.readAllBytes(fixture),StandardCharsets.UTF_8);
        one("40c65_exact_date_and_calendar_minimum_from_original_35_rows",()->{
            try(NativeCtripLoginFormTerminalHostTest.Env e=new NativeCtripLoginFormTerminalHostTest.Env(OWNER)){
                JSONObject data=new JSONObject(raw);
                check(data.getJSONArray("nodes").length()==35&&"c2ee7619ef4a844b7e8fed00c0c22bf58484833e87f40e07adb5de38f5abe496".equals(data.getString("observation_source_sha256")),"original full projected frame identity");
                NativeCtripFlightPage.Page page=inspect(e,data);
                check(NativeCtripFlightPage.RESULTS.equals(page.phase)&&page.quotes.isEmpty(),"actual result shell contains no flight card");
                Map<String,Object> m=page.calendarMinimum(e.actual.task.goal,DAY);
                check(m!=null,"typed same-day fare exists");
                JSONObject evidence=new JSONObject(m);
                check(evidence.getString("date").equals("2026-11-24")&&evidence.getString("from").equals("北京")&&evidence.getString("to").equals("上海"),"exact header and date");
                check(evidence.getJSONObject("date_cell").getString("node_id").equals("n7")&&evidence.getJSONObject("day_label").getString("node_id").equals("n20"),"actual parent and date row");
                check(evidence.getJSONObject("day_price").getString("node_id").equals("n21")&&evidence.getJSONObject("day_price").getString("raw").equals("¥330 "),"exact current price and raw whitespace");
                check(row(data,24).getString("text").equals("¥330 ")&&!evidence.getBoolean("flight_card_verified"),"equal adjacent-day price cannot become the source");
                check(page.calendarMinimum(e.actual.task.goal,DAY.plusDays(1))==null,"wrong full query date");
                NativeAppGoal another=NativeAppGoal.parse("查一下2026年11月24日北京到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE);
                check(page.calendarMinimum(another,DAY)==null,"foreign owner cannot reuse same-day amount");
            }
        });
        one("40c65_reject_wrong_calendar_day_amount_role_and_currency",()->{
            try(NativeCtripLoginFormTerminalHostTest.Env e=new NativeCtripLoginFormTerminalHostTest.Env(OWNER)){
                String[][] mutations={{"20","text","11-25"},{"21","text",""},{"21","text","$330"},{"21","text","¥330起"},{"21","text","¥-330"},
                    {"21","view_id","后一天最低价"},{"21","description","后一天最低价"},{"21","class_name","android.widget.EditText"},
                    {"31","text","上海"},{"33","text","北京"},{"15","description","头部信息:上海到北京"}};
                for(String[] change:mutations){JSONObject data=new JSONObject(raw);row(data,Integer.parseInt(change[0])).put(change[1],change[2]);
                    check(inspect(e,data).calendarMinimum(e.actual.task.goal,DAY)==null,"refuse mutation "+java.util.Arrays.toString(change));}
                JSONObject detached=new JSONObject(raw);row(detached,21).getJSONObject("native_tree_position").put("path","0/0/0/2/4");
                check(inspect(e,detached).calendarMinimum(e.actual.task.goal,DAY)==null,"reject cross-day price ancestry");
                JSONObject incomplete=new JSONObject(raw);incomplete.getJSONObject("collection").put("pending_nodes_at_stop",1);
                check(inspect(e,incomplete).calendarMinimum(e.actual.task.goal,DAY)==null,"reject incomplete native collection");
                JSONObject truncated=new JSONObject(raw);truncated.put("nodes_truncated",true);
                NativeCtripLoginFormTerminalHostTest.reject(()->inspect(e,truncated),"truncated original frame has no bound completion hash");
            }
        });
        one("40c65_partial_is_shown_only_following_bound_query_login_return_and_cleanup",()->{
            // The existing real form-history host fixture is November 17. Shift only
            // strip labels to that date to exercise the whole production terminal chain.
            String owner="查一下2026年11月17日北京到上海的单程机票，1名成人";
            try(NativeCtripLoginFormTerminalHostTest.Env e=new NativeCtripLoginFormTerminalHostTest.Env(owner)){
                TaskCompletionGate gate=new TaskCompletionGate(e.actual.task.taskId,owner,e.actual.authority,e.actual.env.session.selection);
                gate.bindNativeSession(e.actual.task);
                e.xml("form17.xml");e.issue("inspect_departure_year");e.xml("calendar14.xml");e.issue("return_from_calendar");
                e.xml("form17.xml");e.issue("query_observed_form");
                JSONObject shifted=new JSONObject(raw);int[] positions={17,20,23,26,29};String[] dates={"16","11-17","18","19","20"};
                for(int i=0;i<positions.length;i++)row(shifted,positions[i]).put("text",dates[i]);
                e.raw.time=e.now+100;e.accept(e.remap(NativeCtripLoginLoadingHostTest.frame(e.raw,shifted)));
                check(!e.actual.task.domain().resultReady,"calendar alone grants no full-flight result");
                e.login();e.issue(NativeCtripFlightPage.LOGIN_EXIT);e.typed(false);e.incompleteOnly();
                gate.observed(e.completion);e.actual.task.retire();
                TaskCompletionGate.Check result=gate.terminalNativeCheck(e.actual.task,e.completion,e.actual.gate.frame(),e.step,null,false,
                        true,true,true,true,false,true,true,Integer.valueOf(0),true,e.actual.task.taskId,
                        "11111111111111111111111111111111",NativeAppEvidence.hash("synthetic terminal worker receipt"));
                check(!result.verified,"entire flight goal remains unverified");
                Map<String,Object> explanation=explain(e,result.evidence,true);
                check("native_ctrip_calendar_minimum_before_login".equals(explanation.get("code")),"bound original fare survives login return and cleanup");
                String message=(String)explanation.get("message");
                check(message.contains("2026-11-17 北京到上海")&&message.contains("低价日历显示 ¥330")&&message.contains("未取得具体航班、航司或时刻")&&message.contains("同一工作资料"),"precise and limited owner presentation");
                check(Boolean.FALSE.equals(explanation.get("business_verified"))&&Boolean.FALSE.equals(explanation.get("grants_tool_authority")),"informational only");
                check(explain(e,result.evidence,false).isEmpty(),"unknown cleanup suppresses presentation");
                for(String field:new String[]{"displayed_amount","date","currency_symbol","owner_sha256","observation_id"}){
                    JSONObject damaged=new JSONObject(result.evidence);
                    damaged.getJSONObject("native_app_session").getJSONObject("current_domain").getJSONObject("provider").getJSONObject("historical_calendar_minimum").put(field,"displayed_amount".equals(field)?"123":"wrong");
                    check(explain(e,damaged.toMap(),true).isEmpty(),"reject mutated terminal history "+field);
                }
            }
        });
    }
}
