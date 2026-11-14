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
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/** Composition regression against real Progress/Domain/CompletionGate classes.
 * A synthetic typed Page is injected deliberately: this does not test a DOM
 * results provider, actual flight rows, Android dispatch, or real cleanup. */
public final class WebFlightResultCompositionHostTest {
    private static final String TASK="11111111111111111111111111111111";
    private static final String OWNER="查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final List<String> names=new ArrayList<String>();
    private static JSONObject binding;
    private static WebTaskPurpose purpose;
    private static int assertions;
    private interface Work{void run()throws Exception;}
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void test(String name,Work work)throws Exception{work.run();names.add(name);}
    private static void rejects(Work work)throws Exception{
        boolean refused=false;try{work.run();}catch(IllegalArgumentException|IllegalStateException expected){refused=true;}
        check(refused,"production composition must refuse");
    }
    private static boolean plainEvidence(Object value){
        if(value==null||value instanceof String||value instanceof Boolean||value instanceof Number)return true;
        if(value instanceof Map){for(Object item:((Map<?,?>)value).values())if(!plainEvidence(item))return false;return true;}
        if(value instanceof List){for(Object item:(List<?>)value)if(!plainEvidence(item))return false;return true;}
        return false;
    }
    private static Object call(Class<?> type,String name,Class<?>[] types,Object...args)throws Exception{
        Method m=type.getDeclaredMethod(name,types);m.setAccessible(true);
        try{return m.invoke(null,args);}catch(InvocationTargetException e){
            if(e.getCause() instanceof Exception)throw (Exception)e.getCause();throw e;
        }
    }
    private static Object query(String name,Class<?>[] types,Object...args)throws Exception{
        return call(WebFlightQueryHostTest.class,name,types,args);
    }
    private static Object factory(String name,Class<?>[] types,Object...args)throws Exception{
        return call(WebTaskCompositionHostTest.class,name,types,args);
    }
    private static void queryField(String name,Object value)throws Exception{
        Field f=WebFlightQueryHostTest.class.getDeclaredField(name);f.setAccessible(true);f.set(null,value);
    }
    private static Object chainField(Object chain,String name)throws Exception{
        Field f=chain.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(chain);
    }
    private static String id(int value){return String.format(java.util.Locale.ROOT,"%032x",value);}
    private static void initialize(String domPath,String axPath)throws Exception{
        String raw=(String)query("read",new Class<?>[]{String.class,String.class},domPath,
                "f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa");
        String ax=(String)query("read",new Class<?>[]{String.class,String.class},axPath,
                "59d753e32edd620eb2e1fb0947c898df89eb7bf8dbc63dc4138a1636272b82ec");
        JSONObject calendar=new JSONObject(new JSONObject(raw).getJSONObject("capture").getString("dom_raw_utf8"))
                .put("schema","hepta.fixed-top-document-dom.v3");
        @SuppressWarnings("unchecked") List<PhoneObservation.Node> original=(List<PhoneObservation.Node>)call(
                WebCalendarNativeHostTest.class,"ax",new Class<?>[]{String.class},ax);
        List<PhoneObservation.Node> rows=new ArrayList<PhoneObservation.Node>();
        for(PhoneObservation.Node row:original)rows.add((PhoneObservation.Node)call(WebCalendarNativeHostTest.class,"replace",
                new Class<?>[]{PhoneObservation.Node.class,String.class,String.class,boolean.class,Rect.class,String.class},
                row,row.nativeTreePath,row.nativeParentClass,row.enabled,row.bounds,
                query("nativeId",new Class<?>[]{String.class},row.id)));
        binding=(JSONObject)factory("binding",new Class<?>[]{String.class},OWNER);purpose=WebTaskPurpose.requireBinding(binding);
        queryField("calendar",calendar);queryField("calendarRows",rows);queryField("binding",binding);
    }
    private static final class Sample {
        final PhoneObservation frame;final WebTaskDomain domain;
        Sample(PhoneObservation frame,WebTaskDomain domain){this.frame=frame;this.domain=domain;}
    }
    private static Sample sample(long time,long epoch,boolean changed)throws Exception{
        JSONObject dom=(JSONObject)query("form",new Class<?>[]{String.class,String.class,String.class,String.class,int.class,boolean.class},
                "北京","上海","11月17日","周二",1,false);
        // Synthetic unrelated text changes the raw document only. It is not a
        // proposed real result selector and cannot activate any result provider.
        if(changed)dom.getJSONArray("nodes").put(query("node",new Class<?>[]{String.class,String.class,String.class,String.class},
                "0/0/1","span","","synthetic carrier fixture; no result DOM provider"));
        @SuppressWarnings("unchecked") List<PhoneObservation.Node> rows=(List<PhoneObservation.Node>)query("formRows",
                new Class<?>[]{String.class,String.class,String.class,String.class},"北京","上海","11月17日","周二");
        PhoneObservation frame=(PhoneObservation)query("frame",new Class<?>[]{long.class,List.class},time,rows);
        JSONObject raw=(JSONObject)factory("rawCapture",new Class<?>[]{JSONObject.class,JSONObject.class,long.class,long.class},binding,dom,epoch,time);
        WebEvidenceReceipt receipt=(WebEvidenceReceipt)factory("receipt",new Class<?>[]{JSONObject.class,JSONObject.class},binding,raw);
        return new Sample(frame,WebTaskDomain.observed(TASK,purpose,purpose.authorization.bind(TASK),frame,receipt,binding));
    }
    private static final class Fixture {
        WebFlightProgress progress;final WebFlightDomain source;final ActionDecision action;
        Fixture(boolean outcome,boolean accepted,boolean dispatched,boolean stale,boolean entered)throws Exception{
            Object chain=query("ready",new Class<?>[0]);source=(WebFlightDomain)chainField(chain,"current");
            action=(ActionDecision)query("click",new Class<?>[]{WebFlightDomain.class,String.class},source,"queryBtn");
            progress=((WebFlightProgress)chainField(chain,"progress")).reserveQuery(source,action,id(6));
            if(outcome)progress=progress.outcome(source,action,id(6),accepted,dispatched,stale,entered,1112,1115);
        }
        WebTaskDomain current(Sample sample)throws Exception{
            progress=progress.observed(sample.domain.flight);return sample.domain.withFlightProgress(progress);
        }
    }
    private static Fixture dispatched()throws Exception{return new Fixture(true,true,true,false,true);}
    private static WebFlightResult.Page syntheticPage(WebFlightDomain domain){
        Map<String,Object> proof=new LinkedHashMap<String,Object>();proof.put("synthetic_typed_carrier_injection",true);
        proof.put("actual_dom_native_result_parser_executed",false);
        WebFlightResult.Row row=new WebFlightResult.Row("0/0/1","CZ1234","合成出发机场","合成到达机场","2026-11-17","10:00",
                "2026-11-17","12:00","488","CNY","not_stated_on_current_page",null,"not_stated_on_current_page",null,proof);
        return new WebFlightResult.Page(domain.resultFrame(),"synthetic-host-carrier.v1",WebFlightResult.FLIGHTS,
                "北京","上海","2026-11-17",Collections.singletonList(row),null,proof);
    }
    private static ActionDecision done(WebTaskDomain domain)throws Exception{
        return ActionDecision.parse(new JSONObject().put("action","done").put("status","success")
                .put("observation_id",domain.observationId).put("package",domain.flight==null?"":
                        org.trillionnium.hepta.webprotocol.WebEvidenceProtocol.HELPER_PACKAGE).put("summary","synthetic model completion claim").toString());
    }
    private static NotesCompletionEvidence.Frame completion(PhoneObservation frame){
        List<NotesCompletionEvidence.Node> nodes=new ArrayList<NotesCompletionEvidence.Node>();
        for(PhoneObservation.Node n:frame.nodes)nodes.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label(),n.viewId,n.inputTextSha256,
                new int[]{n.bounds.left,n.bounds.top,n.bounds.right,n.bounds.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,n.childText,n.observedAppTreeSignature));
        return new NotesCompletionEvidence.Frame(frame.id,frame.packageName,frame.windowId,frame.windowMetadata.displayId,
                frame.backgroundGeneration,frame.windowMetadata.type,true,frame.nodesTruncated,nodes);
    }
    private static TaskCompletionGate gate(WebTaskDomain domain,PhoneObservation frame){
        TaskCompletionGate gate=new TaskCompletionGate(TASK,OWNER,purpose.authorization);
        gate.observed(completion(frame));gate.bindWebDomain(domain);return gate;
    }
    private static final class Closed {
        final Fixture fixture;final Sample sample;final WebTaskDomain domain;final TaskCompletionGate gate;final Object lease=new Object();
        Closed()throws Exception{
            fixture=dispatched();sample=sample(1200,8,true);WebTaskDomain pending=fixture.current(sample);
            domain=pending.withFlightResult(syntheticPage(pending.flight));gate=gate(domain,sample.frame);
            check(gate.successClaim(7,id(7),completion(sample.frame),true).verified,"typed provider injection passes preclose host gate");
            TaskCompletionGate.WebCloseAttempt attempt=gate.beginWebClose(lease,domain,TASK,domain.flight.bindingSha,"normal");
            check(attempt!=null,"original live domain snapshot consumed once");
            fixture.progress.retire();gate.clearWebDomain();
            check(gate.webCloseKnown(attempt,lease,TASK,domain.flight.bindingSha,"closed",domain.instance,domain.epoch,
                    domain.displayId,domain.windowId,WebEvidenceJson.sha("synthetic close callback")),"exact typed-close identity retained");
            check(!domain.resultReady(),"live result retired after snapshot");
        }
        TaskCompletionGate.Check terminal(int change)throws Exception{
            return gate.terminalWebCheck(lease,completion(sample.frame),purpose.authorization.bind(TASK).frame(),
                    7,change==6?id(8):id(7),true,change!=1,true,true,true,change==2,
                    true,change!=3,change==4?Integer.valueOf(1):Integer.valueOf(0),change!=5,
                    TASK,id(9),WebEvidenceJson.sha("synthetic native receipt"));
        }
    }
    public static void main(String[] args)throws Exception{
        check(args.length==3,"original calendar, AX and new report required");initialize(args[0],args[1]);
        test("ordinary_observed_postquery_page_still_has_no_result_provider",()->{
            Fixture f=dispatched();Sample sample=sample(1200,8,true);WebTaskDomain pending=f.current(sample);
            check(pending.queryDispatched()&&!pending.resultReady(),"actual query dispatch is insufficient");
            rejects(()->pending.requireCurrent(done(pending)));rejects(()->pending.resultRecord());
            check(!gate(pending,sample.frame).successClaim(7,id(7),completion(sample.frame),true).verified,"model text cannot complete missing provider");
        });
        test("reserved_unknown_rejected_and_stale_outcomes_refuse_carrier_attachment",()->{
            Fixture[] fixtures={new Fixture(false,false,false,false,false),new Fixture(true,false,false,false,false),
                    new Fixture(true,true,false,false,true),new Fixture(true,true,true,true,true)};
            for(Fixture f:fixtures){WebTaskDomain pending=f.current(sample(1200,8,true));rejects(()->pending.withFlightResult(syntheticPage(pending.flight)));}
        });
        test("result_carrier_requires_progress_and_changed_postquery_document",()->{
            Sample raw=sample(1200,8,true);rejects(()->raw.domain.withFlightResult(syntheticPage(raw.domain.flight)));
            Fixture f=dispatched();WebTaskDomain unchanged=f.current(sample(1200,8,false));
            rejects(()->unchanged.withFlightResult(syntheticPage(unchanged.flight)));
        });
        test("typed_result_wires_complete_prompt_and_done_without_click_authority",()->{
            Fixture f=dispatched();Sample sample=sample(1200,8,true);WebTaskDomain pending=f.current(sample);
            WebTaskDomain current=pending.withFlightResult(syntheticPage(pending.flight));current.requireCurrent(done(current));
            check(current.resultReady()&&"official_flight_results".equals(current.phase),"typed current result is available");
            check(current.clickIds.isEmpty()&&current.editValues.isEmpty()&&current.noNodeActions(Collections.singletonMap("home",1)).isEmpty(),"no action grant from rows");
            check(current.toolMask(new HashSet<String>(Arrays.asList("click","type","home","back","wait","done"))).equals(
                    new HashSet<String>(Arrays.asList("wait","done"))),"only non-effect choices remain");
            check(Boolean.FALSE.equals(current.evidence().get("server_query_completed"))&&Boolean.FALSE.equals(current.evidence().get("server_response_payload_verified")),"display result does not claim server payload proof");
            check(current.promptEvidence().containsKey("current_flight_result")&&Boolean.TRUE.equals(current.promptEvidence().get("current_result_ready")),"bounded flight summary wired");
            check(plainEvidence(current.evidence()),"flight evidence contains no mutable parser containers or JSON null sentinel");
            @SuppressWarnings("unchecked") Map<String,Object> geometry=(Map<String,Object>)current.evidence().get("native_geometry");
            boolean immutable=false;try{geometry.put("source_geometry",null);}catch(UnsupportedOperationException expected){immutable=true;}
            check(immutable&&geometry.get("source_geometry") instanceof Map,"native geometry evidence is retained and independently immutable");
            rejects(()->current.withFlightResult(syntheticPage(current.flight)));
        });
        test("a_new_observation_never_implicitly_carries_the_old_result",()->{
            Fixture f=dispatched();WebTaskDomain first=f.current(sample(1200,8,true));first=first.withFlightResult(syntheticPage(first.flight));
            WebTaskDomain next=f.current(sample(1300,9,true));check(!next.resultReady(),"fresh capture needs a fresh provider proof");
            check(!first.resultReady(),"new navigation actively retires old domain completion authority");
            WebFlightResult.Page old=syntheticPage(first.flight);rejects(()->next.withFlightResult(old));
        });
        test("fresh_typed_result_recheck_has_stable_semantic_key",()->{
            Fixture f=dispatched();Sample sample=sample(1200,8,true);WebTaskDomain first=f.current(sample);
            first=first.withFlightResult(syntheticPage(first.flight));
            // Same native observation and document with a fresh helper receipt
            // is the beforeModelAction shape; clocks are data, not page semantics.
            JSONObject dom=(JSONObject)query("form",new Class<?>[]{String.class,String.class,String.class,String.class,int.class,boolean.class},"北京","上海","11月17日","周二",1,false);
            dom.getJSONArray("nodes").put(query("node",new Class<?>[]{String.class,String.class,String.class,String.class},"0/0/1","span","","synthetic carrier fixture; no result DOM provider"));
            JSONObject raw=(JSONObject)factory("rawCapture",new Class<?>[]{JSONObject.class,JSONObject.class,long.class,long.class},binding,dom,8L,1210L);
            // The retained factory synthesizes a new scale callback at t-1 for
            // every capture. A changed scale history must remain a rejection;
            // this particular derived recapture instead retains the original
            // callback history while advancing only sample/capture clocks.
            long originalScaleChange=new JSONObject(first.evidence()).getJSONObject("native_geometry")
                    .getJSONObject("source_geometry").getJSONArray("samples").getJSONObject(0)
                    .getJSONObject("native").getLong("scale_changed_elapsed_ms");
            org.json.JSONArray samples=raw.getJSONObject("capture").getJSONObject("capture_geometry").getJSONArray("samples");
            for(int i=0;i<samples.length();i++)samples.getJSONObject(i).getJSONObject("native").put("scale_changed_elapsed_ms",originalScaleChange);
            WebEvidenceReceipt receipt=(WebEvidenceReceipt)factory("receipt",new Class<?>[]{JSONObject.class,JSONObject.class},binding,raw);
            WebTaskDomain rechecked=WebTaskDomain.observed(TASK,purpose,purpose.authorization.bind(TASK),sample.frame,receipt,binding);
            rechecked=rechecked.withFlightProgress(f.progress.observed(rechecked.flight));
            check(!first.resultReady(),"fresh capture alone suspends the old domain until exact provider recheck");
            check(!gate(first,sample.frame).successClaim(7,id(7),completion(sample.frame),true).verified,
                    "generic completion gate cannot use the suspended result while provider proof is missing");
            rechecked=rechecked.withFlightResult(syntheticPage(rechecked.flight));
            check(first.resultReady()&&rechecked.resultReady(),"matching current provider result restores the verified semantic recheck");
            if(!first.pageKey.equals(rechecked.pageKey))Files.write(Paths.get(args[2]+".semantic-diff.json"),
                    (new JSONObject().put("initial",first.evidence()).put("fresh",rechecked.evidence()).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
            check(first.pageKey.equals(rechecked.pageKey),"fresh capture can re-prove exactly the same reported fields");
        });
        test("completion_requires_current_frame_and_stable_final_native_observation",()->{
            Fixture f=dispatched();Sample sample=sample(1200,8,true);WebTaskDomain current=f.current(sample);
            current=current.withFlightResult(syntheticPage(current.flight));TaskCompletionGate gate=gate(current,sample.frame);
            check(!gate.successClaim(7,id(7),completion(sample.frame),false).verified,"unstable native final frame refused");
            check(!gate.successClaim(7,id(7),completion(sample(1300,8,true).frame),true).verified,"other observation refused");
        });
        test("flight_completion_summary_comes_from_typed_rows_not_model_or_mi",()->{
            Fixture f=dispatched();Sample sample=sample(1200,8,true);WebTaskDomain current=f.current(sample);
            current=current.withFlightResult(syntheticPage(current.flight));TaskCompletionGate gate=gate(current,sample.frame);
            check(gate.successClaim(7,id(7),completion(sample.frame),true).verified,"current typed row gate");
            String summary=gate.completionSummary();check(summary.contains("CZ1234")&&summary.contains("488")&&summary.contains("2026-11-17")
                    &&summary.contains("合成出发机场")&&summary.contains("当前页面未注明")&&!summary.contains("小米"),"actual typed fields form the summary");
        });
        test("retirement_prevents_new_claim_and_late_result_attachment",()->{
            Fixture f=dispatched();Sample sample=sample(1200,8,true);WebTaskDomain pending=f.current(sample);
            WebTaskDomain ready=pending.withFlightResult(syntheticPage(pending.flight));TaskCompletionGate gate=gate(ready,sample.frame);f.progress.retire();
            check(!ready.resultReady()&&!gate.successClaim(7,id(7),completion(sample.frame),true).verified,"retired lifetime cannot complete");
            rejects(()->pending.withFlightResult(syntheticPage(pending.flight)));rejects(()->ready.requireCurrent(done(ready)));
        });
        test("typed_close_preserves_only_private_snapshot_and_terminal_is_one_shot",()->{
            Closed closed=new Closed();TaskCompletionGate.Check check=closed.terminal(0);
            check(check.verified,"correct synthetic typed-close and native cleanup flags complete");
            check(!closed.terminal(0).verified,"terminal cannot be replayed");
        });
        for(int i=1;i<=6;i++){
            final int changed=i;test("terminal_required_fact_"+i+"_cannot_be_replaced_by_result_rows",()->{
                Closed closed=new Closed();check(!closed.terminal(changed).verified,"cleanup cancellation worker exit receipt and run remain mandatory");
            });
        }
        test("close_without_prior_success_snapshot_cannot_complete",()->{
            Fixture f=dispatched();Sample sample=sample(1200,8,true);WebTaskDomain d=f.current(sample);
            d=d.withFlightResult(syntheticPage(d.flight));TaskCompletionGate gate=gate(d,sample.frame);
            check(gate.beginWebClose(new Object(),d,TASK,d.flight.bindingSha,"normal")==null,"provider result alone is not a close candidate");
        });
        JSONObject report=new JSONObject().put("schema","hepta.flight-result-composition-host.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("names",names)
                .put("provider_carrier_injected_synthetically",true).put("actual_results_dom_parser_executed",false)
                .put("model_native_query_and_cleanup_synthetic",true).put("actual_results_verified",false).put("phone_actions",0);
        Files.write(Paths.get(args[2]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
        System.out.println("PASS flight result composition: "+names.size()+" cases / "+assertions+" assertions; synthetic carriers only");
    }
}
