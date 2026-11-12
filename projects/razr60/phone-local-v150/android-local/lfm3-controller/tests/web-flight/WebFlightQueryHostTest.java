package org.trillionnium.hepta.local;

import android.graphics.Rect;
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/**
 * Production progression/provider/receipt classes. The calendar and AX are
 * exact manual originals. City/form selections and all model/native outcomes
 * are explicitly synthetic unit inputs, not a successful phone query.
 */
public final class WebFlightQueryHostTest {
    private static final String OWNER="查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final String TASK="11111111111111111111111111111111";
    private static final String PACKAGE=WebEvidenceProtocol.HELPER_PACKAGE;
    private static final String GENERATION="22345678-1234-1234-1234-123456789012";
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private static JSONObject binding,calendar;
    private static List<PhoneObservation.Node> calendarRows;
    private interface Work{void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Work body)throws Exception{body.run();names.add(name);}
    private static void rejects(Work body)throws Exception{
        boolean rejected=false;
        try{body.run();}catch(IllegalArgumentException|IllegalStateException|org.json.JSONException expected){rejected=true;}
        check(rejected,"production boundary must reject");
    }
    private static Object helper(Class<?> type,String name,Class<?>[] types,Object...args)throws Exception{
        Method m=type.getDeclaredMethod(name,types);m.setAccessible(true);
        try{return m.invoke(null,args);}catch(InvocationTargetException e){
            if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;
        }
    }
    private static Object fixture(String name,Class<?>[] types,Object...args)throws Exception{
        return helper(WebTaskCompositionHostTest.class,name,types,args);
    }
    private static String run(int n){return String.format(java.util.Locale.ROOT,"%032x",n);}
    private static JSONObject copy(JSONObject raw)throws Exception{return new JSONObject(raw.toString());}
    private static JSONObject node(String path,String tag,String id,String text)throws Exception{
        return new JSONObject().put("path",path).put("parent_path","0".equals(path)?JSONObject.NULL:path.substring(0,path.lastIndexOf('/')))
                .put("tag",tag).put("id",id).put("text",text).put("role","").put("name","").put("aria_label","")
                .put("visible_in_viewport",true).put("disabled",false).put("aria_disabled",JSONObject.NULL);
    }
    private static JSONObject document(JSONArray nodes,String suffix)throws Exception{
        JSONObject dom=(JSONObject)fixture("oldFixture",new Class<?>[]{String.class},"dom");
        return dom.put("href","https://m.csair.com/booking_new/"+suffix).put("origin","https://m.csair.com")
                .put("ready_state","complete").put("truncated",false).put("truncation_reasons",new JSONArray())
                .put("nodes",nodes).put("visited",nodes.length());
    }
    /** Actual reviewed tag/id/ancestry contract; values below are synthetic. */
    private static JSONObject form(String dep,String arr,String day,String week,int adults,boolean disabled)throws Exception{
        JSONArray n=new JSONArray().put(node("0","html","","")).put(node("0/0","body","",""))
                .put(node("0/0/0","div","flightQuery","")).put(node("0/0/0/0","div","queryBox",""))
                .put(node("0/0/0/0/0","div","tabControl",""))
                .put(node("0/0/0/0/0/0","li","single","单程"))
                .put(node("0/0/0/0/1","div","tabContent",""))
                .put(node("0/0/0/0/1/0","div","single",""))
                .put(node("0/0/0/0/1/0/0","div","depport","出发城市"))
                .put(node("0/0/0/0/1/0/1","div","arrport","到达城市"))
                .put(node("0/0/0/0/1/0/2","div","depDate","出发日期"))
                .put(node("0/0/0/0/1/0/2/0","span","",day))
                .put(node("0/0/0/0/1/0/2/1","span","",week))
                .put(node("0/0/0/0/1/0/3","div","arrDate","").put("visible_in_viewport",false))
                .put(node("0/0/0/0/1/1","button","queryBtn","查询").put("disabled",disabled))
                .put(node("0/0/0/0/1/2","div","psgBox",""))
                .put(node("0/0/0/0/1/2/0","div","","成人"))
                .put(node("0/0/0/0/1/2/0/0","span","",Integer.toString(adults)))
                .put(node("0/0/0/0/1/2/1","div","","儿童"))
                .put(node("0/0/0/0/1/2/1/0","span","","0"))
                .put(node("0/0/0/0/1/2/2","div","","婴儿"))
                .put(node("0/0/0/0/1/2/2/0","span","","0"))
                .put(node("0/0/0/0/1/3","div","multistage","").put("visible_in_viewport",false));
        if(dep!=null)n.put(node("0/0/0/0/1/0/0/0","span","",dep));
        if(arr!=null)n.put(node("0/0/0/0/1/0/1/0","span","",arr));
        return document(n,"");
    }
    private static JSONObject picker(boolean departure)throws Exception{
        JSONArray n=new JSONArray().put(node("0","html","","")).put(node("0/0","body","",""))
                .put(node("0/0/0","div","flightQuery","")).put(node("0/0/0/0","div","queryBox",""))
                .put(node("0/0/0/0/0","div","",""))
                .put(node("0/0/0/0/0/0","div","",""))
                .put(node("0/0/0/0/0/0/0","div","",departure?"选择出发地":"选择目的地"))
                .put(node("0/0/0/0/0/1","div","",""))
                .put(node("0/0/0/0/0/1/0","div","",""))
                .put(node("0/0/0/0/0/1/0/0","div","","热门城市"))
                .put(node("0/0/0/0/0/1/0/1","ul","",""))
                .put(node("0/0/0/0/0/1/0/1/0","li","",departure?"北京":"上海"));
        return document(n,"");
    }
    /** IDs are synthetic native action IDs; original DOM IDs and XML metadata are unchanged. */
    private static String nativeId(String label){
        if(label.matches("n[0-9]{1,5}"))return label;
        if(label.matches("xml[0-9]{1,4}"))return "n"+(2000+Integer.parseInt(label.substring(3)));
        String[] names={"depport","arrport","depDate","queryBtn","city","picker-title","duplicate",
                "depport-value-0","arrport-value-0","depDate-value-0","depDate-value-1"};
        for(int i=0;i<names.length;i++)if(names[i].equals(label))return "n"+(1000+i);
        throw new IllegalArgumentException("unmapped synthetic native node ID: "+label);
    }
    private static PhoneObservation.Node ax(String id,String view,String text,String type,Rect bounds,boolean click,
                                             boolean enabled,String path,String parent)throws Exception{
        return new PhoneObservation.Node(nativeId(id),PACKAGE,type,view,text,"",bounds,click,false,false,enabled,false,false,
                ObservedChildText.notApplicable(),ObservedScrollActions.observed(Collections.<String>emptyList()),
                ObservedImeEnter.UNKNOWN,null,false,WebEvidenceJson.sha("synthetic native "+id+" "+text+" "+path),path,parent);
    }
    private static void field(List<PhoneObservation.Node> rows,String id,String label,String path,int y,String...values)throws Exception{
        Rect box=new Rect(200,y,900,y+120);
        rows.add(ax(id,id,label,"android.view.View",box,true,true,path,"android.view.View"));
        for(int i=0;i<values.length;i++)if(values[i]!=null)
            rows.add(ax(id+"-value-"+i,"",values[i],"android.widget.TextView",new Rect(210,y+25,850,y+100),
                    false,true,path+"/"+i,"android.view.View"));
    }
    private static List<PhoneObservation.Node> formRows(String dep,String arr,String day,String week)throws Exception{
        List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        field(rows,"depport","出发城市","0/1/0",600,dep);
        field(rows,"arrport","到达城市","0/1/1",800,arr);
        field(rows,"depDate","出发日期","0/1/2",1000,day,week);
        rows.add(ax("queryBtn","queryBtn","查询","android.widget.Button",new Rect(200,1400,900,1500),
                true,true,"0/1/3","android.view.View"));return rows;
    }
    private static List<PhoneObservation.Node> pickerRows(boolean departure)throws Exception{
        return Arrays.asList(ax("picker-title","",departure?"选择出发地":"选择目的地","android.widget.TextView",
                new Rect(200,500,900,560),false,true,"0/1/0","android.view.View"),
                ax("city","",departure?"北京":"上海","android.view.View",new Rect(200,700,400,800),
                        true,true,"0/1/1","android.view.View"));
    }
    private static PhoneObservation frame(long t,List<PhoneObservation.Node> rows)throws Exception{
        String obs=run((int)t);
        return new PhoneObservation(obs,PACKAGE,t+5,1224,2992,0,19,new Rect(0,0,1224,2992),null,
                WebEvidenceJson.sha("synthetic tree "+obs),WebEvidenceJson.sha("synthetic screen "+obs),
                new ObservationState(WebEvidenceJson.sha("synthetic app tree "+obs),ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"android.widget.FrameLayout",1,7,
                        new int[]{0,0,1224,2992},"synthetic flight lease"),false,rows,GENERATION,PACKAGE,Collections.singletonList(PACKAGE));
    }
    private static WebFlightDomain observed(JSONObject b,JSONObject dom,long t,long epoch,List<PhoneObservation.Node> rows)throws Exception{
        JSONObject raw=(JSONObject)fixture("rawCapture",new Class<?>[]{JSONObject.class,JSONObject.class,long.class,long.class},b,dom,epoch,t);
        WebEvidenceReceipt receipt=(WebEvidenceReceipt)fixture("receipt",new Class<?>[]{JSONObject.class,JSONObject.class},b,raw);
        WebTaskPurpose p=WebTaskPurpose.requireBinding(b);
        return WebTaskDomain.observed(TASK,p,p.authorization.bind(TASK),frame(t,rows),receipt,b).flight;
    }
    private static WebFlightDomain formDomain(long t,String dep,String arr,String day,String week)throws Exception{
        return observed(binding,form(dep,arr,day,week,1,false),t,7,formRows(dep,arr,day,week));
    }
    private static ActionDecision click(WebFlightDomain before,String node)throws Exception{
        return ActionDecision.parse("{\"action\":\"click\",\"observation_id\":"+JSONObject.quote(before.observationId)
                +",\"package\":"+JSONObject.quote(PACKAGE)+",\"node_label\":\"synthetic observed unit label\",\"node_id\":"
                +JSONObject.quote(nativeId(node))+"}");
    }
    private static final class Chain{
        WebFlightProgress progress;WebFlightDomain current,dateSource;String dateId;
    }
    private static Chain cities()throws Exception{
        Chain c=new Chain();WebFlightDomain dep=observed(binding,picker(true),1000,7,pickerRows(true));
        c.progress=WebFlightProgress.begin(dep);dep=dep.withProgress(c.progress);
        check(dep.clickIds.contains(nativeId("city")),"synthetic real-class departure capability");
        c.progress=c.progress.outcome(dep,click(dep,"city"),run(1),true,true,false,false,1012,1015);
        WebFlightDomain after=formDomain(1020,"北京",null,"11月13日","周五");
        c.progress=c.progress.observed(after);c.current=after.withProgress(c.progress);
        check(c.progress.selectionConfirmed("departure",after),"actual class confirms city only after form/native readback");
        c.progress=c.progress.outcome(c.current,click(c.current,"arrport"),run(2),true,true,false,false,1032,1035);
        WebFlightDomain arr=observed(binding,picker(false),1040,7,pickerRows(false)).withProgress(c.progress);
        c.progress=c.progress.outcome(arr,click(arr,"city"),run(3),true,true,false,false,1052,1055);
        after=formDomain(1060,"北京","上海","11月13日","周五");
        c.progress=c.progress.observed(after);c.current=after.withProgress(c.progress);
        check(c.progress.hasConfirmedCities()&&!c.progress.queryReady(after),"two cities still need a real full-date selection");
        return c;
    }
    private static Chain datePending()throws Exception{
        Chain c=cities();c.progress=c.progress.outcome(c.current,click(c.current,"depDate"),run(4),true,true,false,false,1072,1075);
        c.dateSource=observed(binding,copy(calendar),1080,7,calendarRows).withProgress(c.progress);
        check(c.dateSource.clickIds.size()==1,"actual calendar's one native date capability");
        c.dateId=c.dateSource.clickIds.iterator().next();
        c.progress=c.progress.outcome(c.dateSource,click(c.dateSource,c.dateId),run(5),true,true,false,false,1092,1095);
        return c;
    }
    private static Chain ready()throws Exception{
        Chain c=datePending();WebFlightDomain after=formDomain(1100,"北京","上海","11月17日","周二");
        c.progress=c.progress.observed(after);c.current=after.withProgress(c.progress);
        check(c.progress.queryReady(after)&&c.current.clickIds.equals(Collections.singleton(nativeId("queryBtn"))),
                "only query becomes a capability after all actual-class confirmations");
        return c;
    }
    private static String read(String path,String sha)throws Exception{
        byte[] raw=Files.readAllBytes(Paths.get(path));check(WebEvidenceJson.sha(raw).equals(sha),"exact manual original SHA");
        return new String(raw,StandardCharsets.UTF_8);
    }
    public static void main(String[] argv)throws Exception{
        check(argv.length==3,"stable original calendar, same-case AX, create-only report");
        String calendarRaw=read(argv[0],"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa");
        String axRaw=read(argv[1],"59d753e32edd620eb2e1fb0947c898df89eb7bf8dbc63dc4138a1636272b82ec");
        calendar=new JSONObject(new JSONObject(calendarRaw).getJSONObject("capture").getString("dom_raw_utf8"))
                .put("schema","hepta.fixed-top-document-dom.v3");
        @SuppressWarnings("unchecked") List<PhoneObservation.Node> rows=(List<PhoneObservation.Node>)helper(
                WebCalendarNativeHostTest.class,"ax",new Class<?>[]{String.class},axRaw);
        calendarRows=new ArrayList<PhoneObservation.Node>();
        for(PhoneObservation.Node row:rows)calendarRows.add((PhoneObservation.Node)helper(WebCalendarNativeHostTest.class,
                "replace",new Class<?>[]{PhoneObservation.Node.class,String.class,String.class,boolean.class,Rect.class,String.class},
                row,row.nativeTreePath,row.nativeParentClass,row.enabled,row.bounds,nativeId(row.id)));
        binding=(JSONObject)fixture("binding",new Class<?>[]{String.class},OWNER);
        test("literal_city_data_is_not_a_verified_route",()->{
            CsairFlightForm f=CsairFlightForm.read(form("北京","上海","11月17日","周二",1,false));
            check("北京".equals(f.departureCityLiteral)&&"上海".equals(f.arrivalCityLiteral),"actual literal values retained");
            check(f.evidence().get("selected_departure_city")==null&&Boolean.FALSE.equals(f.evidence().get("query_ready_verified")),
                    "pure form never grants route or query authority");
        });
        test("matching_form_without_model_actions_cannot_query",()->{
            WebFlightDomain f=formDomain(1000,"北京","上海","11月17日","周二");
            WebFlightProgress p=WebFlightProgress.begin(f);
            check(!p.queryReady(f)&&!f.withProgress(p).clickIds.contains(nativeId("queryBtn")),"no synthetic OWNER fill");
        });
        test("real_class_selection_chain_enables_exact_query_once",()->{Chain c=ready();
            check("official_query_ready".equals(c.current.phase)&&!c.current.queryDispatched(),"query not dispatched merely by readiness");});
        test("accepted_picker_click_waits_for_native_form_readback",()->{
            WebFlightDomain f=observed(binding,picker(true),1000,7,pickerRows(true));
            WebFlightProgress p=WebFlightProgress.begin(f).outcome(f,click(f,"city"),run(1),true,true,false,false,1012,1015);
            check(p.selectionPending()&&f.withProgress(p).clickIds.isEmpty(),"no replay of still-visible picker target");
        });
        test("false_city_outcome_never_confirms",()->{
            WebFlightDomain f=observed(binding,picker(true),1000,7,pickerRows(true));
            WebFlightProgress p=WebFlightProgress.begin(f).outcome(f,click(f,"city"),run(1),false,false,false,false,1012,1015);
            p=p.observed(formDomain(1020,"北京",null,"11月13日","周五"));check(!p.hasConfirmedCities(),"no invented action success");
        });
        test("stale_city_outcome_never_confirms",()->{
            WebFlightDomain f=observed(binding,picker(true),1000,7,pickerRows(true));
            WebFlightProgress p=WebFlightProgress.begin(f).outcome(f,click(f,"city"),run(1),true,true,true,false,1012,1015);
            check(!p.selectionPending(),"stale action has no valid pending selection");
        });
        test("date_before_two_city_confirmations_withheld",()->{
            WebFlightDomain d=observed(binding,copy(calendar),1000,7,calendarRows);
            check(d.withProgress(WebFlightProgress.begin(d)).clickIds.isEmpty(),"cannot use year selection before route");
        });
        test("wrong_after_city_literal_stays_pending",()->{
            WebFlightDomain f=observed(binding,picker(true),1000,7,pickerRows(true));
            WebFlightProgress p=WebFlightProgress.begin(f).outcome(f,click(f,"city"),run(1),true,true,false,false,1012,1015);
            p=p.observed(formDomain(1020,"广州",null,"11月13日","周五"));check(p.selectionPending(),"wrong actual city not overwritten");
        });
        test("dom_city_without_same_native_value_stays_pending",()->{
            WebFlightDomain f=observed(binding,picker(true),1000,7,pickerRows(true));
            WebFlightProgress p=WebFlightProgress.begin(f).outcome(f,click(f,"city"),run(1),true,true,false,false,1012,1015);
            WebFlightDomain after=observed(binding,form("北京",null,"11月13日","周五",1,false),1020,7,
                    formRows(null,null,"11月13日","周五"));
            p=p.observed(after);check(p.selectionPending()&&!after.nativeValueMatches("departure"),"DOM is not native readback");
        });
        test("foreign_native_city_descendant_rejected",()->{
            WebFlightDomain after=observed(binding,form("北京","上海","11月17日","周二",1,false),1100,7,
                    formRows("广州","上海","11月17日","周二"));
            check(!after.nativeValueMatches("departure"),"current native literal differs");
        });
        test("two_cities_without_full_calendar_date_cannot_query",()->{
            Chain c=cities();rejects(()->c.progress.reserveQuery(c.current,click(c.current,"queryBtn"),run(6)));});
        test("wrong_after_month_day_stays_pending",()->{
            Chain c=datePending();c.progress=c.progress.observed(formDomain(1100,"北京","上海","11月18日","周三"));
            check(c.progress.selectionPending(),"date changed after actual click");});
        test("wrong_after_weekday_stays_pending",()->{
            Chain c=datePending();c.progress=c.progress.observed(formDomain(1100,"北京","上海","11月17日","周五"));
            check(c.progress.selectionPending(),"weekday inconsistent with actual chosen full date");});
        test("date_before_dispatch_end_cannot_confirm",()->{
            Chain c=datePending();c.progress=c.progress.observed(formDomain(1090,"北京","上海","11月17日","周二"));
            check(c.progress.selectionPending(),"monotonic selection readback order");});
        test("later_route_change_invalidates_current_query",()->{
            Chain c=ready();WebFlightDomain f=formDomain(1120,"广州","上海","11月17日","周二");
            c.progress=c.progress.observed(f);check(!c.progress.queryReady(f)&&!f.withProgress(c.progress).clickIds.contains(nativeId("queryBtn")),"no old city proof reuse");});
        test("later_date_change_invalidates_year_confirmation",()->{
            Chain c=ready();WebFlightDomain f=formDomain(1120,"北京","上海","11月18日","周三");
            c.progress=c.progress.observed(f);check(!c.progress.selectionConfirmed("date",f),"old year proof cannot follow a new displayed day");});
        test("native_field_disappears_query_withheld",()->{
            Chain c=ready();WebFlightDomain f=observed(binding,form("北京","上海","11月17日","周二",1,false),1120,7,
                    formRows(null,"上海","11月17日","周二"));
            check(!c.progress.queryReady(f),"missing native city stays unverified");});
        test("two_adults_are_not_one_adult_query",()->{
            Chain c=ready();WebFlightDomain f=observed(binding,form("北京","上海","11月17日","周二",2,false),1120,7,
                    formRows("北京","上海","11月17日","周二"));check(!c.progress.queryReady(f),"actual passengers retained");});
        test("disabled_dom_query_cannot_mint_target",()->{
            Chain c=ready();WebFlightDomain f=observed(binding,form("北京","上海","11月17日","周二",1,true),1120,7,
                    formRows("北京","上海","11月17日","周二"));check(!c.progress.queryReady(f),"disabled query");});
        test("duplicate_native_query_even_disabled_refuses",()->{
            Chain c=ready();List<PhoneObservation.Node> n=formRows("北京","上海","11月17日","周二");
            n.add(ax("duplicate","queryBtn","查询","android.widget.Button",new Rect(200,1600,900,1700),true,false,"0/2","android.view.View"));
            WebFlightDomain f=observed(binding,form("北京","上海","11月17日","周二",1,false),1120,7,n);
            check(!c.progress.queryReady(f),"uniqueness counted before state");});
        test("another_binding_cannot_import_selection_chain",()->{
            Chain c=ready();JSONObject b=(JSONObject)fixture("binding",new Class<?>[]{String.class},OWNER.replace("17日","18日"));
            WebFlightDomain f=observed(b,form("北京","上海","11月17日","周二",1,false),1120,7,
                    formRows("北京","上海","11月17日","周二"));rejects(()->c.progress.observed(f));});
        test("navigation_epoch_regression_cannot_import_progress",()->{
            Chain c=ready();WebFlightDomain f=observed(binding,form("北京","上海","11月17日","周二",1,false),1120,6,
                    formRows("北京","上海","11月17日","周二"));rejects(()->c.progress.observed(f));});
        test("query_reservation_is_not_a_dispatch",()->{
            Chain c=ready();WebFlightProgress p=c.progress.reserveQuery(c.current,click(c.current,"queryBtn"),run(6));
            check(p.queryAttempted()&&!p.queryDispatched()&&c.current.withProgress(p).clickIds.isEmpty(),"reserved unknown attempt cannot be repeated");});
        test("second_query_reservation_refused",()->{
            Chain c=ready();WebFlightProgress p=c.progress.reserveQuery(c.current,click(c.current,"queryBtn"),run(6));
            rejects(()->p.reserveQuery(c.current,click(c.current,"queryBtn"),run(7)));});
        test("actual_query_outcome_and_after_capture_remain_not_results",()->{
            Chain c=ready();ActionDecision a=click(c.current,"queryBtn");
            WebFlightProgress p=c.progress.reserveQuery(c.current,a,run(6)).outcome(c.current,a,run(6),true,true,false,true,1112,1115);
            WebFlightDomain after=formDomain(1120,"北京","上海","11月17日","周二");
            p=p.observed(after);WebFlightDomain current=after.withProgress(p);
            check(p.queryDispatched()&&current.clickIds.isEmpty()&&"official_query_result_pending".equals(current.phase),"query sent once");
            check(Boolean.FALSE.equals(current.evidence().get("result_ready_for_completion_gate")),"no fabricated server result");
            rejects(()->current.requireCurrent(ActionDecision.parse(new JSONObject().put("action","done")
                    .put("observation_id",current.observationId).put("package",PACKAGE).put("status","success")
                    .put("summary","synthetic claim").toString())));
        });
        test("false_query_outcome_consumes_attempt",()->{
            Chain c=ready();ActionDecision a=click(c.current,"queryBtn");
            WebFlightProgress p=c.progress.reserveQuery(c.current,a,run(6)).outcome(c.current,a,run(6),false,false,false,true,1112,1115);
            check(p.queryAttempted()&&!p.queryDispatched()&&c.current.withProgress(p).clickIds.isEmpty(),"false native return is never retry");});
        test("accepted_query_without_platform_entry_refused",()->{
            Chain c=ready();ActionDecision a=click(c.current,"queryBtn");WebFlightProgress p=c.progress.reserveQuery(c.current,a,run(6));
            rejects(()->p.outcome(c.current,a,run(6),true,true,false,false,1112,1115));});
        test("query_outcome_before_capture_refused",()->{
            Chain c=ready();ActionDecision a=click(c.current,"queryBtn");WebFlightProgress p=c.progress.reserveQuery(c.current,a,run(6));
            rejects(()->p.outcome(c.current,a,run(6),true,true,false,true,1105,1115));});
        test("query_outcome_wrong_model_run_refused",()->{
            Chain c=ready();ActionDecision a=click(c.current,"queryBtn");WebFlightProgress p=c.progress.reserveQuery(c.current,a,run(6));
            rejects(()->p.outcome(c.current,a,run(7),true,true,false,true,1112,1115));});
        test("query_outcome_twice_refused",()->{
            Chain c=ready();ActionDecision a=click(c.current,"queryBtn");
            WebFlightProgress p=c.progress.reserveQuery(c.current,a,run(6)).outcome(c.current,a,run(6),true,true,false,true,1112,1115);
            rejects(()->p.outcome(c.current,a,run(6),true,true,false,true,1112,1115));});
        test("unknown_booking_body_is_read_only_pending",()->{
            JSONObject d=document(new JSONArray().put(node("0","html","","")).put(node("0/0","div","root","")),"");
            check(WebFlightDomain.bookingBodyPending(d),"empty readyState-complete body is not ready");});
        test("city_airport_combination_not_silently_normalized",()->{
            rejects(()->CsairFlightForm.read(form("北京 PEK","上海","11月17日","周二",1,false)));});
        for(int scenario=0;scenario<8;scenario++){
            final int selected=scenario;
            test("actual_session_dispatch_methods_"+scenario,()->{
                Chain c=ready();
                java.lang.reflect.Constructor<WebTaskDomain> constructor=WebTaskDomain.class.getDeclaredConstructor(WebFlightDomain.class);
                constructor.setAccessible(true);WebTaskDomain d=constructor.newInstance(c.current);
                check(WebFlightDispatchProjection.verify(d,c.progress,click(c.current,"queryBtn"),run(6),selected),
                        "actual requireDispatch/hook/outcome boundary");
            });
        }
        check(new String(Files.readAllBytes(Paths.get(argv[0])),StandardCharsets.UTF_8).equals(calendarRaw)
                &&new String(Files.readAllBytes(Paths.get(argv[1])),StandardCharsets.UTF_8).equals(axRaw),"actual fixtures unchanged");
        JSONObject result=new JSONObject().put("schema","hepta.v54-flight-query-host-checks.v1")
                .put("all_pass",true).put("cases",names.size()).put("assertions",assertions).put("case_names",new JSONArray(names))
                .put("calendar_original_sha256",WebEvidenceJson.sha(calendarRaw))
                .put("calendar_ax_original_sha256",WebEvidenceJson.sha(axRaw))
                .put("form_and_city_values_synthetic",true).put("model_and_action_outcomes_synthetic",true).put("native_action_ids_synthetic",true)
                .put("actual_query_executed",false).put("actual_results_verified",false).put("phone_actions",0)
                .put("business_verified",false);
        Files.write(Paths.get(argv[2]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("WebFlightQueryHostTest cases="+names.size()+" assertions="+assertions);
    }
}
