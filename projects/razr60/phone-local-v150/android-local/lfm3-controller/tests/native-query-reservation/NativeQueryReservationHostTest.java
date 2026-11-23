package org.trillionnium.hepta.local;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import org.json.JSONObject;

/** Actual Session/year parser, action lifetime and verbatim Controller projection.
 * Model callbacks, installed verifier, frame metadata and journal are host endpoints. */
public final class NativeQueryReservationHostTest {
    interface Work {void run()throws Exception;}
    interface Change {void apply(Map<String,Object> value);}
    static void yes(boolean value,String why){IntegrationChecks.yes(value,why);}
    static void one(String name,Work work)throws Exception{IntegrationChecks.one(name,()->work.run());}
    static void rejects(Work work,String why)throws Exception{IntegrationChecks.rejects(()->work.run(),why);}
    static String sha(String value){return NativeAppEvidence.hash(value);}
    static String id(String value){return sha(value).substring(0,32);}
    static Map<?,?> progress(NativeAppSession s){return (Map<?,?>)s.evidence().get("progress");}
    static List<?> dates(NativeAppSession s){return (List<?>)progress(s).get("explicit_query_attempt_dates");}
    static JSONObject serviceJson(Map<?,?> values)throws Exception{
        JSONObject out=new JSONObject();
        for(Map.Entry<?,?> e:values.entrySet()){
            Object value=e.getValue();if(value instanceof Map<?,?>)value=serviceJson((Map<?,?>)value);
            out.put((String)e.getKey(),value==null?JSONObject.NULL:value);
        }
        return out;
    }
    static final class Fixture {
        final NativeAppProviderHostTest.Harness h;final NativeAppSession session;
        final List<Map<String,Object>> records=new ArrayList<Map<String,Object>>();
        boolean failOutcome;
        Fixture(String name)throws Exception{
            h=new NativeAppProviderHostTest.Harness("query-reservation:"+name);
            session=new NativeAppSession(h.task,h.owner,h.selected,h.session.installed,h.session.selectionSha,h.session.generation,h.session.displayId,
                    ()->{if(!h.installedCurrent)throw new IllegalStateException("host installed identity replaced");},
                    (leaf,value)->{if(failOutcome&&leaf.startsWith("native-app-outcome-"))throw new java.io.IOException("host durable outcome failure");
                        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("leaf",leaf);row.put("value",NativeAppEvidence.immutableMap(value));records.add(row);});
        }
        void observe(String name)throws Exception{h.frame=h.frame(name);session.observed(h.frame);}
        ActionDecision action(String purpose)throws Exception{
            String node=null;for(Map.Entry<String,String> e:session.domain().purposes.entrySet())if(purpose.equals(e.getValue()))node=e.getKey();
            if(node==null)throw new IllegalStateException("actual purpose absent: "+purpose);
            JSONObject o=new JSONObject().put("action","back".equals(node)?"back":"click").put("package",h.frame.packageName).put("observation_id",h.frame.observationId);
            if(!"back".equals(node))o.put("node_id",node).put("node_label",h.frame.byId.get(node).label);
            return ActionDecision.parse(o.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        ActionDecision begin(String purpose)throws Exception{
            ActionDecision a=action(purpose);h.step++;h.lastRun=id(h.task+":model:"+h.step);h.time+=10;
            h.owner.check(a,h.lastRun);session.beforeModelAction(h.step,a,h.lastRun,h.time);return a;
        }
        void transition(String purpose,String next)throws Exception{
            ActionDecision a=begin(purpose);
            session.modelActionOutcome(a,h.lastRun,true,true,false,sha("host-durable:"+h.lastRun),++h.time);observe(next);
        }
        void year()throws Exception{observe("form14.xml");transition("inspect_departure_year","calendar14.xml");transition("return_from_calendar","form14.xml");}
        NativeAppSession.ActionGuard guard(ActionDecision a)throws Exception{return session.actionGuard(a,h.lastRun,h.frame.observationId,h.time,h.time+8000);}
        Map<String,Object> execution(NativeAppSession.ActionGuard guard,String mode)throws Exception{
            final long[] clock={h.time};
            ActionExecutionState state=new ActionExecutionState(id(h.lastRun+":operation"),h.task,h.lastRun,h.frame.observationId,h.auth.sha256,
                    h.frame.windowId,h.frame.displayId,h.frame.generation,h.time,guard.deadline,()->clock[0]);
            state.phase("worker_started");clock[0]++;
            if(mode.startsWith("entered")||mode.equals("accepted"))state.enterEffect(false,true);
            if(mode.equals("entered-return-false"))state.effectReturned(Boolean.FALSE);
            if(mode.equals("accepted"))state.effectReturned(Boolean.TRUE);
            if(mode.equals("stop"))state.retire("cancelled");
            if(mode.equals("lease"))state.retire("lease_retired");
            clock[0]++;state.drained();clock[0]++;
            if(mode.equals("expired"))clock[0]=guard.deadline;
            state.publish(mode.equals("stop"),!mode.equals("lease"));h.time=clock[0]+1;
            Map<String,Object> raw=state.evidence();raw.put("native_action_guard",guard.evidence());
            return NativeQueryControllerBridge.project(serviceJson(raw));
        }
        void outcome(ActionDecision a,boolean accepted,boolean dispatched,boolean stale,Map<String,Object> execution)throws Exception{
            // Runs the same behavioral regression on the old production API too.
            try{
                Method method=NativeAppSession.class.getDeclaredMethod("modelActionOutcome",ActionDecision.class,String.class,
                        boolean.class,boolean.class,boolean.class,String.class,long.class,Map.class);
                try{method.invoke(session,a,h.lastRun,accepted,dispatched,stale,sha("host-durable:"+h.lastRun),h.time,execution);}
                catch(InvocationTargetException error){Throwable cause=error.getCause();if(cause instanceof Exception)throw (Exception)cause;
                    if(cause instanceof Error)throw (Error)cause;throw error;}
            }catch(NoSuchMethodException legacy){
                session.modelActionOutcome(a,h.lastRun,accepted,dispatched,stale,sha("host-durable:"+h.lastRun),h.time);
            }
        }
        boolean queryAvailable(){return session.domain().purposes.containsValue("query_observed_form");}
    }
    static void retained(Fixture f,ActionDecision a,Map<String,Object> execution)throws Exception{
        f.outcome(a,false,false,true,execution);f.observe("form14.xml");
        yes(dates(f.session).equals(Collections.singletonList("2026-11-14")),"ambiguous or unbound effect keeps reservation");
        yes(!f.queryAvailable(),"same-date query unavailable without proof");yes(progress(f.session).get("last_query_date")==null,"no invented result");
    }
    static void rejectedProof(String name,Change change)throws Exception{
        one(name,()->{Fixture f=new Fixture(name);f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            Map<String,Object> x=f.execution(g,"none");change.apply(x);retained(f,a,x);});
    }
    static void positive()throws Exception{
        one("proved_drained_pre_effect_stale_releases_reservation",()->{
            Fixture f=new Fixture("positive");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            String oldRun=f.h.lastRun;NativeAppEvidence.Frame oldFrame=f.h.frame;
            Map<String,Object> x=f.execution(g,"none");f.outcome(a,false,false,true,x);
            yes(dates(f.session).isEmpty(),"pre-effect stale query reservation must be released");
            yes(progress(f.session).get("last_query_date")==null&&progress(f.session).get("pending")==null,"release creates no result or dispatched transition");
            yes(((Integer)progress(f.session).get("actual_model_actions")).intValue()==3,"model action budget stays consumed");
            rejects(()->g.requireOpen(a,oldRun,f.h.time),"old private guard stays closed");
            rejects(()->f.session.observed(oldFrame),"old observation cannot be replayed");
            rejects(()->f.session.beforeModelAction(4,a,id("same-frame-new-model"),f.h.time),"new model alone cannot reuse stale observation");
            f.observe("form14.xml");yes(f.queryAvailable(),"new observed form can invite a new query");
            rejects(()->f.session.beforeModelAction(4,f.action("query_observed_form"),oldRun,f.h.time),"old model run stays consumed");
            ActionDecision next=f.begin("query_observed_form");NativeAppSession.ActionGuard ng=f.guard(next);
            yes(next!=a&&!next.observationId.equals(a.observationId)&&!f.h.lastRun.equals(oldRun),"new frame and new model action required");
            yes(dates(f.session).equals(Collections.singletonList("2026-11-14"))&&ng!=g,"new single reservation and guard");
            ng.claim(next,f.h.lastRun,f.h.time);Map<String,Object> entered=f.execution(ng,"accepted");f.outcome(next,true,true,false,entered);
            yes(dates(f.session).size()==1&&progress(f.session).get("last_query_date")==null,"accepted effect stays consumed and awaits next page");
            f.observe("result14.xml");yes("2026-11-14".equals(progress(f.session).get("last_query_date")),"actual result page proves that query only");
            yes(!f.session.domain().resultReady,"non-owner14 result cannot complete owner17");
            boolean receipt=false;for(Map<String,Object> row:f.records){Map<?,?> value=(Map<?,?>)row.get("value"),attempt=(Map<?,?>)value.get("attempt");
                if(attempt!=null&&oldRun.equals(attempt.get("model_run_id"))&&attempt.get("actual_action_receipt") instanceof Map<?,?>)
                    receipt=Boolean.TRUE.equals(((Map<?,?>)attempt.get("actual_action_receipt")).get("query_reservation_released"));}
            yes(receipt,"durable outcome records the proven release");
        });
    }
    static void projectionGuardCases()throws Exception{
        String[] labels={"explicit_null","text","boolean","array","number"};
        Object[] malformed={JSONObject.NULL,"untrusted",Boolean.FALSE,new org.json.JSONArray(),Integer.valueOf(1)};
        for(int i=0;i<labels.length;i++){
            final String label=labels[i];final Object value=malformed[i];
            one("present_nonobject_guard_rejects_projection_"+label,()->{
                Fixture f=new Fixture("bad-json-guard:"+label);f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
                JSONObject raw=serviceJson(f.execution(g,"none"));raw.put("native_action_guard",value);
                Map<String,Object> projected=NativeQueryControllerBridge.project(raw);
                yes(projected==null,"present non-object native guard must reject complete projection");
                retained(f,a,projected);
            });
        }
        one("absent_guard_projection_remains_distinct_from_present_null",()->{
            Fixture f=new Fixture("absent-json-guard");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            JSONObject raw=serviceJson(f.execution(g,"none"));raw.remove("native_action_guard");
            Map<String,Object> projected=NativeQueryControllerBridge.project(raw);
            yes(projected!=null&&!projected.containsKey("native_action_guard"),"actual unguarded service actions retain lifecycle facts without inventing a guard");
            retained(f,a,projected);
        });
    }
    public static void main(String[] args)throws Exception{
        Path source=Paths.get(args[0]);NativeAppProviderHostTest.fixtures=source.resolve("tests/native-app-provider/fixtures");
        if(args.length>2&&args[2].equals("previous-projection")){projectionGuardCases();throw new AssertionError("previous Controller unexpectedly passed guard projection regression");}
        positive();
        if(args.length>2&&args[2].equals("legacy"))throw new AssertionError("previous production unexpectedly passed reservation regression");
        projectionGuardCases();
        one("synthetic_no_effect_receipt_round_trip_preserves_explicit_nulls",()->{
            Fixture f=new Fixture("synthetic-round-trip");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            Map<String,Object> generated=f.execution(g,"none");
            JSONObject json=new JSONObject(serviceJson(generated).toString());
            yes(json.has("api_accepted")&&json.isNull("api_accepted")&&json.has("retirement_reason")&&json.isNull("retirement_reason"),
                    "synthetic JSON retains explicit unknown API and unretired state");
            Map<String,Object> projected=NativeQueryControllerBridge.project(json);
            yes(Boolean.FALSE.equals(projected.get("effect_entered"))&&Boolean.FALSE.equals(projected.get("effect_returned"))
                    &&Boolean.TRUE.equals(projected.get("worker_drained")),"real lifetime machine generated a drained unentered host action");
            f.outcome(a,false,false,true,projected);yes(dates(f.session).isEmpty(),"same host Attempt facts release only its reservation");
            yes(progress(f.session).get("last_query_date")==null,"synthetic host proof creates no business result");
        });
        one("session_retirement_cannot_release_reserved_query",()->{
            Fixture f=new Fixture("retired-session");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            Map<String,Object> x=f.execution(g,"none");f.session.retire();
            rejects(()->f.outcome(a,false,false,true,x),"retired task cannot apply a late outcome");
            yes(dates(f.session).size()==1,"task retirement preserves ambiguous reservation history");
        });
        one("nonstale_failure_does_not_refund_query",()->{
            Fixture f=new Fixture("not-stale");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            f.outcome(a,false,false,false,f.execution(g,"none"));yes(dates(f.session).size()==1,"only definite pre-effect stale rejection releases");
            rejects(()->f.session.domain(),"ordinary action failure stays terminal");
        });
        one("legacy_boolean_only_outcome_never_refunds",()->{
            Fixture f=new Fixture("legacy-api");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            f.h.time++;f.session.modelActionOutcome(a,f.h.lastRun,false,false,true,sha("legacy-durable"),f.h.time);f.observe("form14.xml");
            yes(!f.queryAvailable()&&dates(f.session).size()==1,"booleans cannot prove drained no-effect");rejects(()->g.requireOpen(a,f.h.lastRun,f.h.time),"legacy guard closes");
        });
        one("absent_execution_keeps_reservation",()->{Fixture f=new Fixture("no-execution");f.year();ActionDecision a=f.begin("query_observed_form");f.guard(a);f.h.time++;retained(f,a,null);});
        one("no_private_guard_keeps_reservation",()->{Fixture f=new Fixture("no-guard");f.year();ActionDecision a=f.begin("query_observed_form");f.h.time++;retained(f,a,new LinkedHashMap<String,Object>());});
        one("already_claimed_guard_keeps_reservation",()->{
            Fixture f=new Fixture("claimed");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);g.claim(a,f.h.lastRun,f.h.time);retained(f,a,f.execution(g,"none"));
        });
        for(String mode:Arrays.asList("entered-unknown","entered-return-false","stop","lease","expired")){
            final String m=mode;one("no_refund_"+m,()->{Fixture f=new Fixture(m);f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);retained(f,a,f.execution(g,m));});
        }
        for(String key:Arrays.asList("task_id","model_run_id","observation_id","authorization_sha256","background_generation")){
            final String k=key;rejectedProof("foreign_execution_"+k,x->x.put(k,"foreign"));
        }
        for(String key:Arrays.asList("window_id","display_id")){final String k=key;rejectedProof("foreign_execution_"+k,x->x.put(k,999));}
        rejectedProof("malformed_operation_id",x->x.put("operation_id","not-an-operation"));
        rejectedProof("wrong_execution_schema",x->x.put("schema","untrusted-model"));
        rejectedProof("missing_worker_drain",x->x.remove("worker_drained"));
        rejectedProof("worker_not_drained",x->x.put("worker_drained",false));
        rejectedProof("effect_entry_true",x->x.put("effect_entered",true));
        rejectedProof("effect_return_true",x->x.put("effect_returned",true));
        rejectedProof("api_accepted_true",x->x.put("api_accepted",true));
        rejectedProof("api_rejected_not_proven_unentered",x->x.put("api_accepted",false));
        rejectedProof("api_acceptance_missing_is_unknown",x->x.remove("api_accepted"));
        rejectedProof("retirement_reason_missing_is_unknown",x->x.remove("retirement_reason"));
        rejectedProof("callback_not_published",x->x.put("callback_published",false));
        rejectedProof("callback_authority_not_current",x->x.put("callback_authority_current",false));
        rejectedProof("automatic_redispatch_never_accepted",x->x.put("automatic_redispatch",true));
        rejectedProof("queue_before_attempt",x->x.put("queued_elapsed_ms",0L));
        rejectedProof("drain_before_queue",x->x.put("worker_drained_elapsed_ms",0L));
        rejectedProof("drain_after_outcome",x->x.put("worker_drained_elapsed_ms",Long.MAX_VALUE));
        rejectedProof("clock_float_is_not_integer_evidence",x->x.put("queued_elapsed_ms",1.5));
        for(String key:Arrays.asList("purpose","model_run_id","action_sha256","query_history_sha256")){
            final String k=key;rejectedProof("foreign_private_guard_"+k,x->{
                Map<String,Object> guard=new LinkedHashMap<String,Object>();Map<?,?> raw=(Map<?,?>)x.get("native_action_guard");
                for(Map.Entry<?,?> e:raw.entrySet())guard.put((String)e.getKey(),e.getValue());guard.put(k,"foreign");x.put("native_action_guard",guard);
            });
        }
        rejectedProof("missing_guard_receipt",x->x.remove("native_action_guard"));
        one("outcome_journal_failure_keeps_query_consumed",()->{
            Fixture f=new Fixture("journal");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            Map<String,Object> x=f.execution(g,"none");f.failOutcome=true;
            IntegrationChecks.ioRejects(()->f.outcome(a,false,false,true,x),"durable outcome failure propagates");
            yes(dates(f.session).size()==1,"no release before durable receipt");rejects(()->g.requireOpen(a,f.h.lastRun,f.h.time),"failure closes old guard");
            rejects(()->f.session.observed(f.h.frame("form14.xml")),"uncommitted outcome cannot admit later frame");
        });
        one("released_query_requires_frame_after_physical_drain",()->{
            Fixture f=new Fixture("old-capture");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            NativeAppEvidence.Frame oldCapture=f.h.frame("form14.xml");Map<String,Object> x=f.execution(g,"none");f.outcome(a,false,false,true,x);
            rejects(()->f.session.observed(oldCapture),"new ID with old capture time is insufficient");
        });
        one("projection_uses_fixed_service_fields_only",()->{
            Fixture f=new Fixture("projection");f.year();ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);
            JSONObject json=serviceJson(f.execution(g,"none")).put("model_text","pretend dispatched")
                    .put("freshness_diagnostic",new JSONObject().put("untrusted_payload",new org.json.JSONArray().put("query")));
            Map<String,Object> projected=NativeQueryControllerBridge.project(json);
            yes(!projected.containsKey("model_text")&&!projected.containsKey("freshness_diagnostic"),"untrusted payload cannot create quiescence proof");
            f.outcome(a,false,false,true,projected);yes(dates(f.session).isEmpty(),"actual fixed lifetime facts survive projection");
        });
        one("safe_release_never_resets_total_action_budget",()->{
            Fixture f=new Fixture("bounded");f.year();
            for(int i=0;i<18;i++){ActionDecision a=f.begin("query_observed_form");NativeAppSession.ActionGuard g=f.guard(a);f.outcome(a,false,false,true,f.execution(g,"none"));f.observe("form14.xml");}
            yes(((Integer)progress(f.session).get("actual_model_actions")).intValue()==20,"stale model calls count toward existing maximum");
            rejects(()->f.begin("query_observed_form"),"no unbounded model retry");
        });
        IntegrationChecks.finish(Paths.get(args[1]),"hepta.native-query-reservation-host.v1",
                "Actual Session, action state machine, original year XML and verbatim Controller projection; host model/installed/frame/journal endpoints. No Android, phone, model or business pass.");
    }
}
