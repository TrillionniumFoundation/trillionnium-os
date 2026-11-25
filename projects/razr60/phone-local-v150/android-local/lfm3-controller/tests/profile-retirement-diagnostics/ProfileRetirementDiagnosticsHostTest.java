package org.trillionnium.hepta.background;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONArray;
import org.json.JSONObject;

/** Synthetic platform only. Compare original calls/results, not diagnostic timing values. */
public final class ProfileRetirementDiagnosticsHostTest {
    private static boolean baseline;
    private static int assertions;
    private static final JSONArray functional=new JSONArray(),cases=new JSONArray();
    private interface Work {void run()throws Exception;}
    private static void yes(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void pass(String name,Work work)throws Exception{work.run();cases.put(name);}
    private static final class Platform implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake f=new ProfileBrokerHostTest.Fake();
        final List<String> events=new ArrayList<String>();
        boolean tracing,deleteFalse,keepRoot,throwPreHistory,throwLoopHistory,readersReleased;
        int nowCalls,historyCalls,clearHistoryAt,slowHistoryAt;
        CountDownLatch removeEntered,releaseRemove;
        void event(String what){if(tracing)events.add(what);}
        public ProfileTarget recheck(boolean ready)throws Exception{event("identity:"+ready);return f.recheck(ready);}
        public void guard()throws Exception{event("guard");f.guard();}
        public long now(){if(tracing)nowCalls++;return f.now();}
        public Object newCookie(){return f.newCookie();}
        public ProfileTaskPolicy.Snapshot snapshot()throws Exception{event("global");return f.snapshot();}
        public ProfileTaskPolicy.Recents recents()throws Exception{
            event("history");
            if(tracing){
                historyCalls++;
                if(slowHistoryAt==historyCalls)Thread.sleep(50); // Explicit host-only latency fixture.
                if(throwPreHistory&&historyCalls==1)throw new IOException("TEST_PRE_HISTORY_FAILED");
                if(throwLoopHistory&&historyCalls==2)throw new IOException("TEST_LOOP_HISTORY_FAILED");
                if(clearHistoryAt>0&&historyCalls>=clearHistoryAt)f.recentsApp=false;
            }
            return f.recents();
        }
        public List<BackgroundOwnedSingleTask.Task> roots(){event("roots");return f.roots();}
        public List<BackgroundOwnedSingleTask.Task> children(Object token){event("children");return f.children(token);}
        public void createRoot(Object cookie){event("create_root");f.createRoot(cookie);}
        public void bindRoot(Object token,Object cookie){event("bind_root");f.bindRoot(token,cookie);}
        public void removeLeaf(Object token)throws Exception{
            event("remove_leaf");
            if(removeEntered!=null){removeEntered.countDown();
                if(!releaseRemove.await(2,TimeUnit.SECONDS))throw new IOException("TEST_RELEASE_TIMEOUT");}
            f.removeLeaf(token);
        }
        public boolean deleteRoot(Object token)throws Exception{
            event("delete_root");
            if(deleteFalse){f.mutations.add("delete_root");return false;}
            if(keepRoot){f.mutations.add("delete_root");return true;}
            return f.deleteRoot(token);
        }
        public void pause(){event("pause");f.pause();}
        ProfileOwnedTask active()throws Exception{
            ProfileOwnedTask p=new ProfileOwnedTask(this,ProfileBrokerHostTest.target(10,1010367),
                    ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7);
            p.prepare();p.beforeDispatch();f.launch();p.accepted(0);yes(p.observe(),"new owned leaf not active");
            return p;
        }
        void begin(){tracing=true;events.clear();nowCalls=0;historyCalls=0;}
    }
    @SuppressWarnings("unchecked")
    private static Map<String,Object> audit(ProfileOwnedTask p)throws Exception{
        try{
            Method method=ProfileOwnedTask.class.getMethod("retirementDiagnostics");
            yes(!baseline,"baseline unexpectedly exposes new diagnostic API");
            return (Map<String,Object>)method.invoke(p);
        }catch(NoSuchMethodException absent){yes(baseline,"candidate lacks diagnostic API");return null;}
    }
    private static Map<?,?> item(Map<String,Object> a,String key){Object v=a.get(key);return v instanceof Map?(Map<?,?>)v:null;}
    private static long number(Object value){return ((Number)value).longValue();}
    private static void checkAudit(ProfileOwnedTask task,boolean successful,String failure)throws Exception{
        Map<String,Object> a=audit(task);if(baseline)return;
        yes("hepta.profile-retirement-diagnostics.v1".equals(a.get("schema")),"trace schema changed");
        yes(Boolean.TRUE.equals(a.get("finished")),"retire completion not captured");
        yes(Boolean.valueOf(successful).equals(a.get("returned")),"original outcome not preserved");
        yes("java.lang.System.nanoTime".equals(a.get("duration_clock")),"deadline clock used for durations");
        yes(Long.valueOf(2400).equals(a.get("task_reads_deadline_elapsed_ms")),"original deadline not retained");
        yes(number(a.get("duration_us"))>=0,"negative duration");
        for(String key:new String[]{"diagnostics_grant_authority","provides_cleanup_proof","allows_input_or_model_resumption"})
            yes(Boolean.FALSE.equals(a.get(key)),"audit grants authority");
        List<?> calls=(List<?>)a.get("calls");
        yes(number(a.get("record_limit"))==24&&calls.size()<=24,"unbounded prefix");
        yes(number(a.get("calls_dropped"))==number(a.get("calls_started"))-calls.size(),"lost truncation count");
        long ordinal=0;
        for(Object value:calls){
            Map<?,?> call=(Map<?,?>)value;
            yes(number(call.get("ordinal"))==++ordinal,"call ordinal discontinuity");
            yes(Boolean.TRUE.equals(call.get("entered")),"invented non-entered call");
            yes(Boolean.TRUE.equals(call.get("finished")),"completed retire left incomplete call");
            yes(number(call.get("start_offset_us"))>=0&&number(call.get("duration_us"))>=0,"negative timing");
            if(!"DELETE_ROOT".equals(call.get("phase")))yes(call.get("api_accepted")==null,"void/read API assigned acceptance");
        }
        yes(new JSONObject(a).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8).length<=8192,
                "diagnostic exceeds fixed host wire budget");
        yes(!task.cleanupEvidence().containsKey("profile_retirement_diagnostics")
                &&!task.cleanupEvidence().containsKey("retirement_diagnostics"),"diagnostic inserted into authority proof");
        if(failure!=null)yes(!task.cleanupKnown(),"audit converted refusal into release");
    }
    private static String finish(String name,Platform f,ProfileOwnedTask p,String expected,boolean success)throws Exception{
        f.begin();String error=null;
        try{p.retire(2400);}catch(Exception refused){error=refused.getMessage();}
        yes(java.util.Objects.equals(error,expected),name+" wrong refusal: "+error);
        yes(p.cleanupKnown()==success,name+" changed cleanup result");
        Map<String,Object> evidence=p.evidence(),cleanup=p.cleanupEvidence();
        functional.put(new JSONObject().put("case",name).put("error",error==null?JSONObject.NULL:error)
                .put("cleanup_known",p.cleanupKnown()).put("elapsed_clock",f.f.now)
                .put("elapsed_clock_reads",f.nowCalls).put("history_reads",f.historyCalls)
                .put("calls",new JSONArray(f.events)).put("mutations",new JSONArray(f.f.mutations))
                .put("root_removed",evidence.get("root_removal_requested"))
                .put("leaf_removed",evidence.get("leaf_removal_requested"))
                .put("live_absent",cleanup.get("live_tasks_absent")).put("recents_absent",cleanup.get("recents_tasks_absent"))
                .put("identity_unknown",cleanup.get("identity_unknown")).put("foreign_tasks",cleanup.get("foreign_tasks_present")));
        checkAudit(p,expected==null,error);return error;
    }
    public static void main(String[] args)throws Exception{
        baseline=args.length>0&&"baseline".equals(args[0]);
        pass("normal_original_calls_and_deadline_clock",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();
            finish("normal",f,p,null,true);
            yes(f.f.mutations.equals(Arrays.asList("create","bind","remove_leaf","delete_root")),"mutation sequence changed");
            if(!baseline){
                Map<String,Object>a=audit(p);
                yes(Boolean.TRUE.equals(item(a,"remove_leaf").get("returned")),"leaf call return missing");
                yes(item(a,"remove_leaf").get("api_accepted")==null,"void removal mislabelled accepted");
                yes(Boolean.TRUE.equals(item(a,"delete_root").get("api_accepted")),"root Boolean missing");
                yes(number(item(a,"remove_leaf").get("ordinal"))<number(item(a,"delete_root").get("ordinal")),"effects reordered");
            }
        });
        pass("before_first_root_no_mutation",()->{
            Platform f=new Platform();ProfileOwnedTask p=new ProfileOwnedTask(f,ProfileBrokerHostTest.target(10,1010367),
                    ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7);
            finish("unprepared",f,p,null,true);yes(f.f.mutations.isEmpty(),"unprepared task mutated");
            if(!baseline)yes(item(audit(p),"remove_leaf")==null&&item(audit(p),"delete_root")==null,"invented mutation calls");
        });
        pass("pre_leaf_history_failure_is_distinct",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.throwPreHistory=true;
            finish("pre_history",f,p,"TEST_PRE_HISTORY_FAILED",false);
            if(!baseline){
                Map<String,Object>a=audit(p);
                yes("PRE_LEAF_HISTORY".equals(item(a,"last_call").get("phase")),"pre history mislabeled");
                yes(Boolean.FALSE.equals(item(a,"last_call").get("returned"))&&item(a,"remove_leaf")==null,"failed history advanced effect");
            }
        });
        pass("post_leaf_history_failure_is_distinct",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.throwLoopHistory=true;
            finish("loop_history",f,p,"TEST_LOOP_HISTORY_FAILED",false);
            if(!baseline){
                Map<String,Object>a=audit(p);
                yes("LOOP_HISTORY".equals(item(a,"last_call").get("phase")),"loop history mislabeled");
                yes(Boolean.TRUE.equals(item(a,"remove_leaf").get("returned"))&&item(a,"delete_root")==null,"mutations conflated");
            }
        });
        pass("remove_throw_preserves_exception_and_no_root_delete",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.f.removeThrows=true;
            finish("remove_throw",f,p,"REMOVE_FAILED",false);
            if(!baseline){
                Map<String,Object>a=audit(p);
                yes(Boolean.FALSE.equals(item(a,"remove_leaf").get("returned"))&&item(a,"delete_root")==null,"failed effect misreported");
            }
        });
        pass("delete_false_is_not_release",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.deleteFalse=true;
            finish("delete_false",f,p,"PROFILE_ROOT_DELETE_NOT_ACCEPTED",false);
            if(!baseline){
                Map<?,?>call=item(audit(p),"delete_root");
                yes(Boolean.TRUE.equals(call.get("returned"))&&Boolean.FALSE.equals(call.get("api_accepted")),"Boolean false conflated with throw");
            }
        });
        pass("delete_throw_is_not_false_return",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.f.deleteThrows=true;
            finish("delete_throw",f,p,"DELETE_FAILED",false);
            if(!baseline){
                Map<?,?>call=item(audit(p),"delete_root");
                yes(Boolean.FALSE.equals(call.get("returned"))&&call.get("api_accepted")==null,"throw became false acceptance");
            }
        });
        pass("recents_linger_preserves_original_1400ms_stop",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.f.keepRecents=true;
            finish("lingering_recents",f,p,"PROFILE_LEAF_RETIRE_NOT_CONFIRMED",false);
            yes(f.f.now==2400,"original expiry changed");
            if(!baseline)yes(item(audit(p),"delete_root")==null,"history absence fabricated root delete");
        });
        pass("accepted_root_delete_does_not_prove_absence",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.keepRoot=true;
            finish("lingering_root",f,p,"PROFILE_RETIRE_ABSENCE_UNCONFIRMED",false);
            yes(f.f.now==2400,"original final absence expiry changed");
            if(!baseline)yes(Boolean.TRUE.equals(item(audit(p),"delete_root").get("api_accepted")),"accepted call lost");
        });
        pass("bounded_prefix_keeps_late_root_mutation",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.f.keepRecents=true;f.clearHistoryAt=12;f.slowHistoryAt=12;
            finish("late_delete",f,p,null,true);
            if(!baseline){
                Map<String,Object>a=audit(p);
                yes(number(a.get("calls_dropped"))>0,"saturation not exercised");
                yes(number(item(a,"delete_root").get("ordinal"))>24,"late root not beyond prefix");
                yes(Boolean.TRUE.equals(item(a,"delete_root").get("api_accepted")),"late mutation lost");
                yes(number(item(a,"last_call").get("ordinal"))==number(a.get("calls_started")),"last call lost");
                Map<?,?>slow=item(a,"slowest_completed_call");
                yes(slow!=null&&"LOOP_HISTORY".equals(slow.get("phase"))&&number(slow.get("ordinal"))>24,
                        "slow completed history after prefix overflow was lost");
                yes(number(slow.get("duration_us"))>=40000,"host-only slow call fixture not exercised");
                yes(number(slow.get("ordinal"))<number(item(a,"last_call").get("ordinal")),"only last call was retained");
            }
        });
        pass("changed_owner_still_stops_before_mutation",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.f.actual=ProfileBrokerHostTest.target(11,1010367);
            finish("owner_changed",f,p,"PROFILE_INSTALLATION_IDENTITY_CHANGED",false);
            yes(f.f.mutations.equals(Arrays.asList("create","bind")),"foreign identity mutated");
        });
        if(!baseline)pass("watchdog_can_read_inflight_without_retire_monitor",()->{
            Platform f=new Platform();ProfileOwnedTask p=f.active();f.removeEntered=new CountDownLatch(1);f.releaseRemove=new CountDownLatch(1);
            AtomicReference<Throwable> failure=new AtomicReference<Throwable>();
            AtomicReference<Map<String,Object>> observed=new AtomicReference<Map<String,Object>>();
            CountDownLatch readDone=new CountDownLatch(1);
            Thread retire=new Thread(()->{try{p.retire(2400);}catch(Throwable t){failure.set(t);}},"retirement-fixture");
            Thread reader=new Thread(()->{try{observed.set(audit(p));}catch(Throwable t){failure.set(t);}finally{readDone.countDown();}},"audit-reader");
            retire.start();
            try{
                yes(f.removeEntered.await(1,TimeUnit.SECONDS),"fixture did not enter held platform call");
                reader.start();yes(readDone.await(1,TimeUnit.SECONDS),"audit blocked on task retire monitor");
                Map<String,Object>a=observed.get();yes(a!=null&&Boolean.FALSE.equals(a.get("finished")),"inflight trace missing");
                Map<?,?>call=item(a,"remove_leaf");
                yes(call!=null&&Boolean.TRUE.equals(call.get("entered"))&&Boolean.FALSE.equals(call.get("finished"))
                        &&Boolean.FALSE.equals(call.get("returned"))&&call.get("duration_us")==null,"inflight call presented as returned");
            }finally{f.releaseRemove.countDown();retire.join(2000);reader.join(2000);}
            yes(!retire.isAlive()&&!reader.isAlive()&&failure.get()==null&&p.cleanupKnown(),"fixture failed to drain");
            Map<String,Object>a=audit(p);
            try{a.clear();throw new AssertionError("mutable trace");}catch(UnsupportedOperationException expected){assertions++;}
            try{((List<?>)a.get("calls")).clear();throw new AssertionError("mutable calls");}catch(UnsupportedOperationException expected){assertions++;}
            try{item(a,"remove_leaf").clear();throw new AssertionError("mutable call");}catch(UnsupportedOperationException expected){assertions++;}
        });
        System.out.println(new JSONObject().put("passed",true).put("mode",baseline?"baseline":"candidate")
                .put("cases",cases).put("assertions",assertions).put("functional",functional)
                .put("android_runtime",false).put("phone_operations",0).put("latency_measurement_on_phone",false));
    }
}
