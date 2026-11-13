package org.trillionnium.hepta.local;

import android.graphics.Rect;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebDomStability;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/** Real extracted Session predicates/outcome and real receipt/parser classes with synthetic
 * model outcomes, page data and clock/IO. No phone or business completion is claimed. */
public final class WebCityObservationRetryHostTest {
    private static final String OWNER="查一下2026年11月17日北京到上海的单程机票，1名成人";
    private static final String RUN="00000000000000000000000000000001";
    private static final List<String> names=new ArrayList<String>();private static int assertions;
    private interface Case {void run()throws Exception;}
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void test(String name,Case run)throws Exception{run.run();names.add(name);}
    private static Object call(Class<?> owner,Object target,String name,Class<?>[] types,Object...args)throws Exception{
        Method m=owner.getDeclaredMethod(name,types);m.setAccessible(true);
        try{return m.invoke(target,args);}catch(InvocationTargetException e){if(e.getCause() instanceof Exception)throw (Exception)e.getCause();if(e.getCause() instanceof Error)throw (Error)e.getCause();throw e;}
    }
    private static Object query(String name,Class<?>[] types,Object...args)throws Exception{return call(WebFlightQueryHostTest.class,null,name,types,args);}
    private static Object composition(String name,Class<?>[] types,Object...args)throws Exception{return call(WebTaskCompositionHostTest.class,null,name,types,args);}
    private static void set(Object target,String name,Object value)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);f.set(target,value);}
    private static Object get(Object target,String name)throws Exception{Field f=target.getClass().getDeclaredField(name);f.setAccessible(true);return f.get(target);}
    private static final class Fixture {
        final JSONObject binding;final WebTaskPurpose purpose;final WebTaskDomain before;final ActionDecision action;
        final boolean departure;final WebCityObservationRetryProjection harness;final Object token;
        WebEvidenceReceipt first,last;PhoneObservation frame;WebDomStability.Result bracket;
        @SuppressWarnings("unchecked") Fixture(boolean departure)throws Exception{
            this.departure=departure;binding=(JSONObject)composition("binding",new Class<?>[]{String.class},OWNER);
            Field b=WebFlightQueryHostTest.class.getDeclaredField("binding");b.setAccessible(true);b.set(null,binding);
            purpose=WebTaskPurpose.fromOwner(OWNER);
            JSONObject form=(JSONObject)query("form",new Class<?>[]{String.class,String.class,String.class,String.class,int.class,boolean.class},"北京",null,"11月17日","周二",1,false);
            List<PhoneObservation.Node> nodes=(List<PhoneObservation.Node>)query("formRows",new Class<?>[]{String.class,String.class,String.class,String.class},"北京",null,"11月17日","周二");
            PhoneObservation observed=(PhoneObservation)query("frame",new Class<?>[]{long.class,List.class},1000L,nodes);
            WebEvidenceReceipt receipt=receipt(form,7,1000);
            before=WebTaskDomain.observed(binding.getString("task_id"),purpose,purpose.authorization.bind(binding.getString("task_id")),observed,receipt,binding);
            action=(ActionDecision)query("click",new Class<?>[]{WebFlightDomain.class,String.class},before.flight,departure?"depport":"arrport");
            harness=new WebCityObservationRetryProjection(before.flight,purpose);
            token=harness.token(before.flight,action,RUN,true,true,false,1012,1015);
            bracket(departure,8,1100,1200);
        }
        private WebEvidenceReceipt receipt(JSONObject dom,long epoch,long time)throws Exception{
            JSONObject raw=(JSONObject)composition("rawCapture",new Class<?>[]{JSONObject.class,JSONObject.class,long.class,long.class},binding,dom,epoch,time);
            // The retained factory uses one 1000..1500 RPC. This new test's
            // six-second budget needs a separate valid RPC around each capture;
            // the same synthetic background lease already expires at 10000.
            JSONObject request=new JSONObject(raw.getString("request_json_utf8")).put("deadline_elapsed_ms",time+1000);
            String requestRaw=request.toString();raw.put("request_json_utf8",requestRaw).put("request_sha256",WebEvidenceJson.sha(requestRaw));
            byte[] bytes=(raw.toString()+"\n").getBytes(StandardCharsets.UTF_8);
            JSONObject callback=(JSONObject)composition("callback",new Class<?>[]{JSONObject.class,JSONObject.class},binding,request);
            callback.put("status","captured").put("navigation_epoch",epoch).put("raw_length",bytes.length).put("raw_sha256",WebEvidenceJson.sha(bytes));
            return WebEvidenceReceipt.verify(WebEvidenceProtocol.CAPTURE,requestRaw,binding,callback.toString(),bytes,10484,time,time+20);
        }
        @SuppressWarnings("unchecked") void bracket(boolean pickerDeparture,long epoch,long firstAt,long lastAt)throws Exception{
            JSONObject dom=(JSONObject)query("picker",new Class<?>[]{boolean.class},pickerDeparture);
            first=receipt(dom,epoch,firstAt);last=receipt(dom,epoch,lastAt);
            List<PhoneObservation.Node> nodes=(List<PhoneObservation.Node>)query("pickerRows",new Class<?>[]{boolean.class},pickerDeparture);
            PhoneObservation old=(PhoneObservation)query("frame",new Class<?>[]{long.class,List.class},firstAt+50,nodes);
            PhoneObservation.CollectionStats counts=new PhoneObservation.CollectionStats(1536,512,32768,nodes.size(),nodes.size(),100,0,0,0,0,10);
            frame=new PhoneObservation(old.id,old.packageName,old.capturedElapsedMillis,old.width,old.height,old.rotation,old.windowId,
                    new Rect(old.windowBounds),null,old.screenshotSha256,old.treeSha256,old.state,old.windowMetadata,false,old.nodes,
                    old.backgroundGeneration,old.backgroundBootstrapPackage,old.backgroundAllowedPackages,counts);
            bracket=WebDomStability.evaluate(first.domRaw(),last.beforeDomRaw(),purpose.sitePolicyId);
        }
        boolean retry(boolean stable,long now,long deadline)throws Exception{
            harness.now(now);return harness.retry(first,last,frame,stable,bracket,token,deadline);
        }
    }
    private static Object actualOutcome(Fixture f,boolean accepted,boolean dispatched,boolean stale,String run)throws Exception{
        Class<?> type=Class.forName("org.trillionnium.hepta.local.WebFlightDispatchProjection");Constructor<?> c=type.getDeclaredConstructor();c.setAccessible(true);Object p=c.newInstance();
        set(p,"domain",f.before);set(p,"dispatchSource",f.before);set(p,"purpose",f.purpose);set(p,"taskId",f.before.taskId);
        set(p,"dispatchSourceRun",RUN);set(p,"dispatchSourceAction","click\n"+f.action.nodeId);set(p,"dispatchCheckedAt",1011L);
        set(p,"flightProgress",WebFlightProgress.begin(f.before.flight));
        Class<?> outcome=Class.forName("org.trillionnium.hepta.local.WebFlightDispatchProjection$HeptaAccessibilityService$ActionOutcome");
        Constructor<?> factory=outcome.getDeclaredConstructor(boolean.class,boolean.class,boolean.class);factory.setAccessible(true);
        call(type,p,"modelActionOutcome",new Class<?>[]{ActionDecision.class,String.class,outcome,long.class,long.class},f.action,run,factory.newInstance(accepted,dispatched,stale),1012L,1015L);
        check(get(p,"dispatchSource")==null,"actual outcome retires dispatch source");return get(p,"cityObservationRetry");
    }
    public static void main(String[] args)throws Exception{
        check(args.length==1,"one new output path required");Path out=Paths.get(args[0]);check(!Files.exists(out),"create-only output");
        test("actual_arrival_outcome_creates_readonly_source",()->{Fixture f=new Fixture(false);check(actualOutcome(f,true,true,false,RUN)!=null,"actual accepted arrival outcome stores source");check(f.retry(false,1300,10000),"complete corresponding arrival picker permits one read-only retry");});
        test("actual_departure_outcome_creates_readonly_source",()->{Fixture f=new Fixture(true);check(actualOutcome(f,true,true,false,RUN)!=null,"actual accepted departure outcome stores source");check(f.retry(false,1300,10000),"symmetric departure predicate");});
        test("false_outcome_creates_no_source",()->check(actualOutcome(new Fixture(false),false,false,false,RUN)==null,"no rejected native outcome authority"));
        test("undispatched_outcome_creates_no_source",()->check(actualOutcome(new Fixture(false),true,false,false,RUN)==null,"no planned-only authority"));
        test("stale_outcome_creates_no_source",()->check(actualOutcome(new Fixture(false),true,true,true,RUN)==null,"stale result grants no retry"));
        test("foreign_model_run_outcome_rejected",()->{boolean refused=false;try{actualOutcome(new Fixture(false),true,true,false,"00000000000000000000000000000002");}catch(IllegalArgumentException expected){refused=true;}check(refused,"late/foreign run rejected by actual outcome body");});
        test("credential_is_consumed_once_by_observe_entry",()->{Fixture f=new Fixture(false);f.harness.store(f.token);check(f.harness.consume()==f.token&&f.harness.consume()==null,"actual observe entry consumes one source");});
        test("new_action_retires_unconsumed_source",()->{Fixture f=new Fixture(false);f.harness.store(f.token);f.harness.newAction();check(f.harness.consume()==null,"actual new-action entry clears old source");});
        test("stable_frame_uses_no_extra_retry",()->{Fixture f=new Fixture(false);check(!f.retry(true,1300,10000)&&f.harness.retries()==0,"stable original predicate needs no retry");});
        test("wrong_picker_kind_not_retried",()->{Fixture f=new Fixture(false);f.bracket(true,8,1100,1200);check(!f.retry(false,1300,10000),"arrival token does not authorize departure picker retry");});
        test("navigation_epoch_rollback_not_retried",()->{Fixture f=new Fixture(false);f.bracket(false,6,1100,1200);check(!f.retry(false,1300,10000),"no earlier epoch after action");});
        test("capture_before_actual_dispatch_end_not_retried",()->{Fixture f=new Fixture(false);f.bracket(false,8,1000,1200);check(!f.retry(false,1300,10000),"old capture cannot use later outcome");});
        test("foreign_task_context_not_retried",()->{Fixture f=new Fixture(false);f.harness.foreignTask();check(!f.retry(false,1300,10000),"same captured task required");});
        test("foreign_owner_context_not_retried",()->{Fixture f=new Fixture(false);f.harness.foreignOwner();check(!f.retry(false,1300,10000),"same original owner/contract required");});
        test("foreign_background_generation_not_retried",()->{Fixture f=new Fixture(false);f.harness.foreignGeneration();check(!f.retry(false,1300,10000),"same background lease required");});
        test("missing_complete_ax_counters_not_retried",()->{Fixture f=new Fixture(false);f.frame=(PhoneObservation)query("frame",new Class<?>[]{long.class,List.class},1150L,f.frame.nodes);check(!f.retry(false,1300,10000),"missing complete AX traversal remains unqualified");});
        test("one_phase_maximum_two_complete_reobservations",()->{Fixture f=new Fixture(false);check(f.retry(false,1300,10000),"first retry");f.bracket(false,8,1300,1400);check(f.retry(false,1500,10000),"second retry");f.bracket(false,8,1500,1600);check(!f.retry(false,1700,10000)&&f.harness.retries()==2&&f.harness.records()==2,"third refused with no extra dispatch or budget reset");});
        test("six_second_budget_not_extended",()->{Fixture f=new Fixture(false);check(f.retry(false,1300,10000),"initial retry starts original budget");f.bracket(false,8,6900,7000);check(!f.retry(false,7050,10000)&&f.harness.retries()==1,"original 250ms reserve enforces six-second limit");});
        test("original_task_deadline_is_upper_bound",()->{Fixture f=new Fixture(false);check(!f.retry(false,1300,1450)&&f.harness.retries()==0,"no retry beyond existing task deadline");});
        test("wrong_kind_cannot_inherit_loading_key_continuation",()->{Fixture f=new Fixture(false);check(f.retry(false,1300,10000),"first arrival retry");f.bracket(true,8,1300,1400);check(!f.retry(false,1500,10000)&&f.harness.retries()==1,"same key alone never bypasses per-retry picker proof");});
        test("changed_dom_cannot_inherit_loading_key_continuation",()->{Fixture f=new Fixture(false);check(f.retry(false,1300,10000),"first retry");f.bracket(false,8,1300,1400);f.bracket=null;check(!f.retry(false,1500,10000)&&f.harness.retries()==1,"missing exact four-DOM bracket remains refusal");});
        test("query_attempt_cannot_use_city_retry",()->{Fixture f=new Fixture(false);f.harness.queryEntered();check(!f.retry(false,1300,10000)&&f.harness.retries()==0,"no retry of actual query");});
        test("cancelled_task_cannot_enter_retry",()->{Fixture f=new Fixture(false);f.harness.cancel();boolean refused=false;try{f.retry(false,1300,10000);}catch(IllegalArgumentException expected){refused=true;}check(refused&&f.harness.retries()==0,"cancel checked before retry count and sleep");});
        test("retired_session_cannot_enter_retry",()->{Fixture f=new Fixture(false);f.harness.retire();boolean refused=false;try{f.retry(false,1300,10000);}catch(IllegalArgumentException expected){refused=true;}check(refused&&f.harness.retries()==0,"retired session grants no late retry");});
        JSONObject result=new JSONObject().put("schema","hepta.city-observation-retry-synthetic.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",new org.json.JSONArray(names))
                .put("actual_production_method_extraction",true).put("synthetic_model_outcomes_pages_clocks_io",true)
                .put("full_android_session_compiled",false).put("original_query_main_rerun_here",false)
                .put("action_replays",0).put("query_replays",0).put("phone_operations",0).put("business_verified",false);
        Files.write(out,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);System.out.println(result.toString());
    }
}
