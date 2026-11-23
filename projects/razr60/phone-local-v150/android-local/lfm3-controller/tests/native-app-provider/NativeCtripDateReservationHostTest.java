package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Actual ebb383 form/calendar/result/undispatched step-5 receipt and SMS graph.
 * Profile proofs, model callbacks and later fresh post-return observations are
 * explicit host fixtures. The post-return graph is a synthetic fresh copy of
 * the original 11/20 result: no phone return or 11/25 success is asserted. */
final class NativeCtripDateReservationHostTest {
    static final String OWNER="查一下2026年11月25日北京到上海的单程机票，1名成人";
    static final String TASK="d17485e67e774d5a9d4106f962d24bdf",GENERATION="fec71428-bdda-479f-840f-71e029457d7f";
    static final String ACTUAL_RUN="656becdea78e40ed87ee2ba02d42e2b7",PURPOSE="navigate_departure_date:2026-11-24";
    static final String FORM="step-02-before.json",CALENDAR="step-02-after.json",RETURNED_FORM="step-03-after.json",RESULT="step-04-after.json";
    static Path fixtures;static int assertions;
    static final List<String> names=new ArrayList<String>();
    interface Test {void run()throws Exception;}
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static void reject(Test t,String why)throws Exception{assertions++;try{t.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}throw new AssertionError(why);}
    static void one(String name,Test t)throws Exception{t.run();names.add(name);}
    static String hash(String s){return NativeAppEvidence.hash(s);}
    static String id(String s){return hash(s).substring(0,32);}
    static JSONObject raw(String leaf)throws Exception{return new JSONObject(new String(Files.readAllBytes(fixtures.resolve("ctrip-date-reservation-r18").resolve(leaf)),StandardCharsets.UTF_8));}
    static JSONObject actualAction()throws Exception{return raw("step-05-action.json");}
    static JSONObject actualExecution()throws Exception{return actualAction().getJSONObject("action_execution");}
    static JSONObject sms()throws Exception{return new JSONObject(new String(Files.readAllBytes(fixtures.resolve("ctrip-sms-login-r18.json")),StandardCharsets.UTF_8));}
    static final class Binding implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target;
        Binding(ProfileTarget p){target=BackgroundTaskTarget.resolveExplicitSelection(OWNER,ProfileTarget.CTRIP,Collections.singleton(ProfileTarget.CTRIP),p);}
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    static final class Harness {
        final String name;
        final ProfileTarget profile=new ProfileTarget(new ProfileIdentity(10,10,0,"android.os.usertype.profile.MANAGED"),1010367,ProfileTarget.CTRIP,
                ProfileTarget.CTRIP+"/ctrip.business.splash.CtripSplashActivity",1779,Collections.singletonMap("base",NativeCtripFlightPage.BASE_APK_SHA256),
                Collections.singleton("8155dc0644fed517e8ef6bef9718c363d0eb3eb2c22c06455044d88268bdcf0a"));
        final Binding selection=new Binding(profile);
        final TaskAuthorization auth=TaskAuthorization.parse(OWNER).forExecutionSelection(selection);
        final TaskAuthorization.Gate owner=auth.bind(TASK);
        final String wire=hash("synthetic-date-fixture-selection:"+selection.target.targetSha256);
        final NativeAppProviderHostTest.Harness parser;
        final NativeAppSession session;
        final TaskCompletionGate gate;
        final Map<String,Map<String,Object>> records=new LinkedHashMap<String,Map<String,Object>>();
        NativeAppEvidence.Frame frame;NotesCompletionEvidence.Frame completion;ActionDecision proposed;
        String run;long time,started;int step,cloneId;boolean installedCurrent=true,failOutcome;
        Harness(String name)throws Exception{
            this.name=name;parser=new NativeAppProviderHostTest.Harness("date-parser:"+name);
            session=new NativeAppSession(TASK,owner,selection,new NativeAppEvidence.Installed(profile),wire,GENERATION,261,
                    ()->{if(!installedCurrent)throw new IllegalStateException("synthetic installation changed");},(leaf,value)->{
                        if(failOutcome&&leaf.startsWith("native-app-outcome-"))throw new java.io.IOException("synthetic journal failure");
                        records.put(leaf,NativeAppEvidence.immutableMap(value));
                    });
            gate=new TaskCompletionGate(TASK,OWNER,auth,selection);gate.bindNativeSession(session);
        }
        NativeAppEvidence.Frame copy(JSONObject r)throws Exception{
            NativeAppEvidence.Frame parsed=NativeCtripLoginLoadingHostTest.frame(parser,r);
            String obs=r.getString("observation_id");long at=r.getLong("captured_elapsed_ms");int window=r.getInt("window_id");
            List<NotesCompletionEvidence.Node> retained=new ArrayList<NotesCompletionEvidence.Node>();
            for(NativeAppEvidence.Node n:parsed.nodes)retained.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label,n.viewId,null,new int[]{n.left,n.top,n.right,n.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,ObservedChildText.notApplicable(),n.signature));
            completion=new NotesCompletionEvidence.Frame(obs,ProfileTarget.CTRIP,window,261,GENERATION,parsed.windowType,true,parsed.nodesTruncated,retained);
            WindowOwnership w=new WindowOwnership(profile,GENERATION,261,window,1000015,1532,"64ae7a3a-fecb-477e-a53c-875466efa88c",
                    "12345678-1234-4234-8234-123456789abb",10,10,1010367,at-1,at+1000);
            return new NativeAppEvidence.Frame(TASK,auth.instructionSha256,selection.target.targetSha256,auth.sha256,wire,obs,ProfileTarget.CTRIP,GENERATION,
                    r.getString("app_tree_sha256"),r.getString("observation_state_sha256"),r.getString("screen_sha256"),hash("synthetic-bound-record:"+r.toString()),TaskCompletionGate.webFrameSha(completion),
                    261,window,parsed.rotation,parsed.width,parsed.height,parsed.left,parsed.top,parsed.right,parsed.bottom,at,parsed.nodesTruncated,parsed.collectionComplete,parsed.nodes,parsed.windowType,true,w);
        }
        void observe(JSONObject r)throws Exception{NativeAppEvidence.Frame f=copy(r);session.observed(f);frame=f;time=f.capturedElapsedMs;gate.observed(completion);}
        void observe(String leaf)throws Exception{observe(raw(leaf));}
        JSONObject freshResult(long at)throws Exception{JSONObject r=raw(RESULT);r.put("observation_id",id("synthetic-post-return:"+name+":"+ ++cloneId)).put("captured_elapsed_ms",at);return r;}
        JSONObject freshSms(long at)throws Exception{JSONObject r=sms();r.put("observation_id",id("synthetic-repeat-sms:"+name+":"+ ++cloneId)).put("captured_elapsed_ms",at);return r;}
        ActionDecision action(String purpose)throws Exception{
            String node=null;for(Map.Entry<String,String> e:session.domain().purposes.entrySet())if(purpose.equals(e.getValue()))node=e.getKey();
            if(node==null)throw new AssertionError("missing current purpose "+purpose+": "+session.domain().purposes);
            JSONObject a=new JSONObject().put("action","back".equals(node)?"back":"click").put("package",ProfileTarget.CTRIP).put("observation_id",frame.observationId);
            if(!"back".equals(node))a.put("node_id",node).put("node_label",frame.byId.get(node).label);
            return ActionDecision.parse(a.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        void begin(String purpose,long at,String modelRun)throws Exception{
            proposed=action(purpose);run=modelRun;started=at;owner.check(proposed,run);session.beforeModelAction(++step,proposed,run,started);time=at;
        }
        void outcome(boolean accepted,boolean dispatched,boolean stale,JSONObject execution,long finished)throws Exception{
            session.modelActionOutcome(proposed,run,accepted,dispatched,stale,hash("synthetic-outcome-record:"+name+":"+step),finished,execution==null?null:execution.toMap());time=finished;
        }
        void perform(String purpose,String next)throws Exception{JSONObject r=raw(next);long at=r.getLong("captured_elapsed_ms")-100;begin(purpose,at,id(name+":synthetic-model:"+step));outcome(true,true,false,null,at+1);observe(r);}
        void prime()throws Exception{observe(FORM);perform("inspect_departure_year",CALENDAR);perform("return_from_calendar",RETURNED_FORM);perform("query_observed_form",RESULT);}
        void beginActualDate()throws Exception{step=4;begin(PURPOSE,525246529L,ACTUAL_RUN);}
        JSONObject receipt(){return new JSONObject(records.get(String.format(java.util.Locale.ROOT,"native-app-outcome-%02d.json",progress().getInt("actual_model_actions")))).getJSONObject("attempt").getJSONObject("actual_action_receipt");}
        JSONObject progress(){return new JSONObject(session.evidence()).getJSONObject("progress");}
        void finishActual(JSONObject x)throws Exception{outcome(false,false,true,x,525247316L);}
        JSONObject matchingExecution()throws Exception{
            JSONObject x=actualExecution();x.put("task_id",TASK).put("model_run_id",run).put("observation_id",frame.observationId).put("authorization_sha256",auth.sha256)
                    .put("window_id",frame.windowId).put("display_id",261).put("background_generation",GENERATION).put("queued_elapsed_ms",started+1).put("deadline_elapsed_ms",started+8000).put("worker_drained_elapsed_ms",started+2);
            return x;
        }
        void returnFromSms()throws Exception{
            observe(sms());check(session.domain().resourceClickIds.equals(Collections.singleton("n0")),"one existing SMS return after query");
            begin(NativeCtripFlightPage.LOGIN_EXIT,time+10,id(name+":synthetic-sms-return"));outcome(true,true,false,null,time+1);observe(freshResult(time+100));
        }
    }
    static Harness atProposal(String name)throws Exception{Harness h=new Harness(name);h.prime();h.beginActualDate();return h;}
    static void notReleased(JSONObject x)throws Exception{Harness h=atProposal("negative:"+names.size()+":"+assertions);h.finishActual(x);check(!h.receipt().optBoolean("date_reservation_released"),"unproved receipt must not release date");h.returnFromSms();check(h.session.domain().purposes.containsValue("navigate_departure_date:2026-11-23")&&!h.session.domain().purposes.containsValue(PURPOSE),"consumed 24 remains unavailable; no unproved retry");}

    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);NativeAppProviderHostTest.fixtures=fixtures;NativeCtripLoginLoadingHostTest.fixtures=fixtures;Path output=Paths.get(args[1]);
        one("actual_stale_24_then_sms_return_reoffers_24_only_after_fresh_observation",()->{
            Harness h=atProposal("actual");JSONObject x=actualExecution();check(h.auth.sha256.equals(x.getString("authorization_sha256"))&&h.frame.observationId.equals(x.getString("observation_id"))&&h.frame.windowId==1351,"exact archived task/model/window/authorization receipt binding");
            h.finishActual(x);check(h.receipt().optBoolean("date_reservation_released"),"regression: proved-unentered actual 11/24 proposal must release its reservation");
            h.returnFromSms();check(h.session.domain().purposes.equals(Collections.singletonMap("n10",PURPOSE)),"same original 11/20 result again permits observed 11/24 instead of consuming it as a click");
            check("2026-11-20".equals(h.progress().getString("last_query_date"))&&!h.session.domain().resultReady&&!h.gate.verified(h.completion),"release and SMS return do not prove 11/25 query");
        });
        one("date_release_proof_is_navigation_only_durable_and_keeps_budget",()->{
            Harness h=atProposal("proof");h.finishActual(actualExecution());JSONObject r=h.receipt(),p=r.getJSONObject("date_reservation_release");
            check(p.getString("schema").equals("hepta.native-date-reservation-release.v1")&&p.getString("date").equals("2026-11-24"),"typed exact-date release proof");
            check(p.getBoolean("worker_drained")&&!p.getBoolean("effect_entered")&&p.getBoolean("fresh_observation_and_new_model_decision_required")&&!p.getBoolean("automatic_redispatch")&&!p.getBoolean("business_verified"),"no action or business authority from release");
            check(!r.getBoolean("query_reservation_released")&&!r.getBoolean("login_exit_reservation_released")&&h.progress().getInt("actual_model_actions")==4&&h.progress().getJSONArray("explicit_query_attempt_dates").length()==1,"only date reservation changed; action/query budgets retained");
        });
        one("released_date_refuses_same_observation_old_capture_and_old_model_run",()->{
            Harness h=atProposal("fresh");NativeAppEvidence.Frame old=h.frame;ActionDecision a=h.proposed;h.finishActual(actualExecution());
            reject(()->h.session.beforeModelAction(6,a,id("same-frame-model"),h.time+1),"fresh observation barrier");reject(()->h.session.observed(old),"same old observation");
            JSONObject oldTime=h.freshResult(old.capturedElapsedMs);reject(()->h.observe(oldTime),"new ID with predating capture cannot refresh authority");
            h.observe(h.freshResult(h.time+100));ActionDecision b=h.action(PURPOSE);reject(()->h.session.beforeModelAction(6,b,ACTUAL_RUN,h.time+1),"old accepted model run remains consumed");
        });
        one("missing_or_legacy_boolean_receipt_never_releases_date",()->{notReleased(null);});
        one("effect_entry_return_api_acceptance_or_undrained_receipt_never_releases",()->{
            for(String key:new String[]{"effect_entered","effect_returned","api_accepted","automatic_redispatch","retired"}){JSONObject x=actualExecution();x.put(key,true);notReleased(x);}
            for(String key:new String[]{"worker_drained","callback_published","callback_authority_current"}){JSONObject x=actualExecution();x.put(key,false);notReleased(x);}
            JSONObject x=actualExecution();x.put("retirement_reason","synthetic cancelled");notReleased(x);
        });
        one("foreign_task_model_observation_authorization_window_display_generation_never_releases",()->{
            for(String key:new String[]{"task_id","model_run_id","observation_id","authorization_sha256","background_generation","operation_id"}){JSONObject x=actualExecution();x.put(key,"foreign");notReleased(x);}
            for(String key:new String[]{"window_id","display_id"}){JSONObject x=actualExecution();x.put(key,999);notReleased(x);}
            for(String key:new String[]{"schema","execution_kind"}){JSONObject x=actualExecution();x.put(key,"unknown");notReleased(x);}
        });
        one("receipt_clock_proof_and_guardless_date_proposal_are_required",()->{
            JSONObject x=actualExecution();x.put("queued_elapsed_ms",525246528L);notReleased(x);
            x=actualExecution();x.put("deadline_elapsed_ms",525247239L);notReleased(x);
            x=actualExecution();x.put("deadline_elapsed_ms",525255240L);notReleased(x);
            x=actualExecution();x.put("worker_drained_elapsed_ms",525247238L);notReleased(x);
            x=actualExecution();x.put("worker_drained_elapsed_ms",525247317L);notReleased(x);
            x=actualExecution();x.put("native_action_guard",new JSONObject());notReleased(x);
        });
        one("accepted_dispatched_or_nonstale_outcome_never_releases_date",()->{
            for(int kind=0;kind<3;kind++){Harness h=atProposal("status:"+kind);h.outcome(kind==0,kind==1,kind!=2,actualExecution(),525247316L);check(!h.receipt().optBoolean("date_reservation_released"),"non-exact outcome is not releasable");
                if(kind==0){h.returnFromSms();check(!h.session.domain().purposes.containsValue(PURPOSE),"accepted flag cannot release the undispatched date");}
                else reject(()->h.session.domain(),"rejected/dispatched receipt invalidates session");}
            Harness h=atProposal("dispatched");h.outcome(true,true,false,actualExecution(),525247316L);check(!h.receipt().optBoolean("date_reservation_released"),"dispatched proposal stays consumed");h.observe(h.freshResult(h.time+100));check(h.session.domain().clickIds.isEmpty()&&!h.progress().isNull("pending"),"wrong-date post-effect result cannot cause retry");
        });
        one("wrong_action_identity_and_unknown_outcome_keep_original_inflight",()->{
            Harness h=atProposal("unknown");ActionDecision copied=h.action(PURPOSE);
            reject(()->h.session.modelActionOutcome(copied,ACTUAL_RUN,false,false,true,hash("synthetic-receipt"),525247316L,actualExecution().toMap()),"equal-looking action is not original proposal");
            reject(()->h.observe(h.freshResult(525247400L)),"no new observation while outcome unknown");reject(()->h.session.beforeModelAction(6,h.proposed,id("unknown-retry"),525247500L),"no second in-flight proposal");
        });
        one("journal_failure_cannot_release_or_authorize_a_retry",()->{
            Harness h=atProposal("journal");h.failOutcome=true;boolean failed=false;try{h.finishActual(actualExecution());}catch(java.io.IOException expected){failed=true;}check(failed,"actual durable write failure injected");
            check(!h.records.containsKey("native-app-outcome-04.json"),"no durable release record");reject(()->h.observe(h.freshResult(525247500L)),"failed durable receipt leaves original attempt in flight");
        });
        one("date_release_does_not_release_one_shot_sms_return",()->{
            Harness h=atProposal("sms-once");h.finishActual(actualExecution());h.observe(sms());h.begin(NativeCtripFlightPage.LOGIN_EXIT,h.time+10,id("synthetic-stale-sms-model"));JSONObject x=h.matchingExecution();h.outcome(false,false,true,x,h.started+3);
            check(!h.receipt().optBoolean("date_reservation_released")&&h.progress().getBoolean("flight_login_exit_attempted"),"date-only release cannot reopen login budget");h.observe(h.freshSms(h.time+100));check(h.session.domain().clickIds.isEmpty()&&!h.session.domain().backAllowed,"same login has no second return or system Back");
        });
        one("fresh_date_retry_still_rechecks_installed_app_and_exact_node",()->{
            Harness h=atProposal("installed");h.finishActual(actualExecution());h.observe(h.freshResult(h.time+100));ActionDecision a=h.action(PURPOSE);h.installedCurrent=false;reject(()->h.session.beforeModelAction(6,a,id("changed-installation"),h.time+10),"installation still current before another proposal");
        });
        one("released_pre_effect_attempts_still_exhaust_original_twenty_action_budget",()->{
            Harness h=new Harness("budget");h.prime();
            for(int i=0;i<17;i++){h.begin(PURPOSE,h.time+10,id("synthetic-bounded-date-attempt:"+i));JSONObject x=h.matchingExecution();h.outcome(false,false,true,x,h.started+3);check(h.receipt().optBoolean("date_reservation_released"),"strong unentered receipt releases date, not action ordinal");h.observe(h.freshResult(h.time+100));}
            check(h.progress().getInt("actual_model_actions")==20,"original action maximum preserved");reject(()->h.begin(PURPOSE,h.time+10,id("twenty-first-date")),"no unbounded stale retries");
        });
        Map<String,Object> out=NativeAppEvidence.map();out.put("schema","hepta.native-ctrip-date-reservation-host.v1");out.put("all_pass",true);out.put("cases",names.size());out.put("assertions",assertions);out.put("case_names",names);
        out.put("phone_operations",0);out.put("android_runtime",false);out.put("model_executed",false);out.put("business_verified",false);out.put("actual_source_bytes_modified",false);out.put("post_sms_return_observation_actual",false);
        out.put("actual_stale_receipt_sha256","ee3bc20c2f8fd6df90fb3bdc699e1dd128b73319b78bd9e9206c7b48f6962864");out.put("boundary","Actual unmodified pre-action date chain, 35-node result, 19-node SMS graph and exact stale receipt flags/identities. Host profile proofs/model callbacks and post-return fresh observations are synthetic; production Session validation executed.");
        Files.write(output,(new JSONObject(out).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println("ctrip date reservation "+names.size()+" cases / "+assertions+" assertions");
    }
}
