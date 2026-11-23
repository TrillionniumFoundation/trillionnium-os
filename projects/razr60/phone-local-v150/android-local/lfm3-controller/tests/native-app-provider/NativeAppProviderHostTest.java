package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDate;
import java.util.*;
import org.json.*;

/** Real production parsers/session/TCG; saved root-exploration XML is original.
 * Frame/NodeRef, task/lease/model/dispatch/installed/cleanup facts are explicit
 * host doubles. This is not Android execution or a model business result. */
final class NativeAppProviderHostTest {
    static final String OWNER="查一下2026年11月17日北京到上海的单程机票，1名成人";
    static final String GENERATION="12345678-1234-4234-8234-123456789abc";
    static Path fixtures;static int checks;static final List<String> names=new ArrayList<String>();
    interface Test {void run()throws Exception;}
    static void check(boolean v,String why){checks++;if(!v)throw new AssertionError(why);}
    static void reject(Test t,String why)throws Exception{checks++;try{t.run();}catch(IllegalArgumentException|IllegalStateException expected){return;}throw new AssertionError(why);}
    static void one(String name,Test t)throws Exception{if(names.contains(name))throw new AssertionError("duplicate case");t.run();names.add(name);}
    static String sha(String s){return NativeAppEvidence.hash(s);}static String id(String s){return sha(s).substring(0,32);}
    static NativeAppGoal goal(){return NativeAppGoal.parse(OWNER,NativeAppGoal.CTRIP_PACKAGE);}
    static class Binding implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target=BackgroundTaskTarget.resolveExplicitSelection(OWNER,NativeAppGoal.CTRIP_PACKAGE,Collections.singleton(NativeAppGoal.CTRIP_PACKAGE));
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    static final class Harness {
        final String task;final Binding selected=new Binding();final TaskAuthorization auth;
        final TaskAuthorization.Gate owner;final TaskCompletionGate gate;final NativeAppSession session;
        final List<Map<String,Object>> records=new ArrayList<Map<String,Object>>();
        NativeAppEvidence.Frame frame;NotesCompletionEvidence.Frame completion;int observation,step;long time=1000;String lastRun;
        boolean installedCurrent=true;
        Harness(String name)throws Exception{
            task=id("synthetic-task:"+name);auth=TaskAuthorization.parse(OWNER).forExecutionSelection(selected);owner=auth.bind(task);
            gate=new TaskCompletionGate(task,OWNER,auth,selected);
            session=new NativeAppSession(task,owner,selected,
                    new NativeAppEvidence.Installed(NativeAppGoal.CTRIP_PACKAGE,10367,1779,Collections.singletonMap("base",NativeCtripFlightPage.BASE_APK_SHA256)),
                    sha("synthetic-selection-wire:"+selected.target.targetSha256),GENERATION,7,
                    new NativeAppSession.InstalledVerifier(){public void verify(){if(!installedCurrent)throw new IllegalStateException("synthetic installed identity changed");}},
                    new NativeAppSession.Journal(){public void write(String leaf,Map<String,Object> value){
                        Map<String,Object> v=NativeAppEvidence.map();v.put("leaf",leaf);v.put("value",NativeAppEvidence.immutableMap(value));records.add(v);
                    }});
            gate.bindNativeSession(session);
        }
        NativeAppEvidence.Frame frame(String fixture)throws Exception{
            NativeXmlFixture.Snapshot raw=NativeXmlFixture.read(fixtures.resolve(fixture));observation++;time+=10;
            String obs=id(task+":synthetic-observation:"+observation);List<NotesCompletionEvidence.Node> retained=new ArrayList<NotesCompletionEvidence.Node>();
            for(NativeAppEvidence.Node n:raw.nodes)retained.add(new NotesCompletionEvidence.Node(n.id,n.packageName,n.text,n.label,n.viewId,null,
                    new int[]{n.left,n.top,n.right,n.bottom},n.editable,n.clickable,n.scrollable,n.enabled,n.password,ObservedChildText.notApplicable(),n.signature));
            completion=new NotesCompletionEvidence.Frame(obs,NativeAppGoal.CTRIP_PACKAGE,70,7,GENERATION,1,true,false,retained);
            return new NativeAppEvidence.Frame(task,goal().ownerSha256,selected.target.targetSha256,auth.sha256,
                    sha("synthetic-selection-wire:"+selected.target.targetSha256),obs,NativeAppGoal.CTRIP_PACKAGE,GENERATION,
                    raw.sourceSha256,raw.sourceSha256,sha("synthetic-screenshot:"+observation),sha("synthetic-phone-record:"+observation+":"+raw.sourceSha256),
                    TaskCompletionGate.webFrameSha(completion),7,70,0,1224,2992,0,0,1224,2992,time,false,true,raw.nodes,1,true);
        }
        void observe(String fixture)throws Exception{frame=frame(fixture);session.observed(frame);gate.observed(completion);}
        String target(String purpose){for(Map.Entry<String,String> e:session.domain().purposes.entrySet())if(e.getValue().equals(purpose)||e.getValue().startsWith(purpose))return e.getKey();return null;}
        ActionDecision action(String purpose)throws Exception{
            String node=target(purpose);check(node!=null,"actual current purpose missing: "+purpose+" "+session.domain().evidence());
            JSONObject o=new JSONObject().put("action","back".equals(node)?"back":"click").put("package",NativeAppGoal.CTRIP_PACKAGE).put("observation_id",frame.observationId);
            if(!"back".equals(node))o.put("node_id",node).put("node_label",frame.byId.get(node).label);
            return ActionDecision.parse(o.toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        void perform(String purpose,String next)throws Exception{ActionDecision a=action(purpose);issue(a,true,true,false);observe(next);}
        void issue(ActionDecision a,boolean accepted,boolean dispatched,boolean stale)throws Exception{
            step++;lastRun=id(task+":synthetic-model-success-callback:"+step);time+=10;
            owner.check(a,lastRun);session.beforeModelAction(step,a,lastRun,time);
            session.modelActionOutcome(a,lastRun,accepted,dispatched,stale,sha("synthetic-durable-step-action:"+step),++time);
        }
        void year()throws Exception{observe("form14.xml");check(target("query_observed_form")==null,"year cannot come from OWNER or relative date alone");
            perform("inspect_departure_year","calendar14.xml");perform("return_from_calendar","form14.xml");check(target("query_observed_form")!=null,"actual month-title roundtrip permits observed form query");}
        void ready()throws Exception{
            year();perform("query_observed_form","result14.xml");
            check(!gate.verified(completion),"14 does not complete 17");
            String p=null;for(String value:session.domain().purposes.values())if(value.startsWith("navigate_departure_date:"))p=value;
            check(p!=null,"real date cell toward goal");
            if(p.endsWith("2026-11-16")){perform(p,"result16.xml");check(!gate.verified(completion),"16 does not complete 17");p="navigate_departure_date:2026-11-17";}
            perform(p,"result17.xml");check(!gate.verified(completion),"date strip alone cannot complete without target query form");
            perform("verify_form_after_result_date","form17.xml");perform("query_observed_form","result17.xml");
            check(gate.verified(completion)&&session.domain().resultReady,"target form/query and same native cards become candidate");
        }
        void claim()throws Exception{JSONObject o=new JSONObject().put("action","done").put("package",NativeAppGoal.CTRIP_PACKAGE)
                .put("observation_id",frame.observationId).put("status","success").put("summary","Synthetic host claim; not a phone result");
            issue(ActionDecision.parse(o.toString(),ActionDecision.IME_ACTION_SCHEMA),true,false,false);observe("result17-second.xml");
            check(gate.successClaim(step,lastRun,completion,true).verified,"same actual final graph accepted as typed candidate");}
        Map<String,Object> terminal(Integer exit,boolean cleanup,boolean background,boolean scope,boolean installed,boolean cancelled,
                boolean started,boolean exited,boolean valid,String workerTask,String workerGeneration,String receipt,String claimRun)throws Exception{
            session.retire();return gate.terminalNativeCheck(session,completion,owner.frame(),step,claimRun,true,cleanup,background,scope,installed,cancelled,
                    started,exited,exit,valid,workerTask,workerGeneration,receipt).evidence;
        }
        Map<String,Object> normal()throws Exception{return terminal(0,true,true,true,true,false,true,true,true,task,id("synthetic-worker"),sha("synthetic-normal0-parent-receipt"),lastRun);}
    }
    static NativeAppEvidence.Frame altered(NativeAppEvidence.Frame f,String owner,String target,String generation,boolean complete,boolean truncated){
        return new NativeAppEvidence.Frame(f.taskId,owner,target,f.authorizationSha,f.selectionSha,f.observationId,f.packageName,generation,
                f.treeSha,f.stateSha,f.screenshotSha,f.sourceRecordSha,f.completionFrameSha,f.displayId,f.windowId,f.rotation,f.width,f.height,
                f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,truncated,complete,f.nodes,f.windowType,f.metadataObserved);
    }
    static Harness completed(String name)throws Exception{Harness h=new Harness(name);h.ready();h.claim();return h;}
    static boolean passed(Map<String,Object> result){return Boolean.TRUE.equals(result.get("completion_verified"));}
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);Path out=Paths.get(args[1]);
        one("actual_complete_flight_cards_keep_conditions_and_reject_promotional_or_clipped_cards",()->{
            Harness h=new Harness("cards");NativeAppEvidence.Frame f=h.frame("result17.xml");NativeCtripFlightPage.Page p=NativeCtripFlightPage.inspect(goal(),f);
            check(p.quotes.size()==2,"two admitted complete economy cards");check("MF8561".equals(p.quotes.get(0).flightNumber)&&"450".equals(p.quotes.get(0).amountDecimal),"same-card MF450");
            check("CA1883".equals(p.quotes.get(1).flightNumber)&&"500".equals(p.quotes.get(1).amountDecimal),"same-card CA500");
            check(p.quotes.get(0).displayTags.toString().contains("共享"),"same wrapper sibling shared condition preserved");
            check(p.rejectedCards.size()==4,"three restricted/incomplete cabin cards and clipped last card rejected");
            check(Boolean.FALSE.equals(p.quotes.get(0).modelView().get("availability_or_checkout_price_verified")),"quote never means checkout");
        });
        one("actual_overlay_vetoes_visible_underlying_flight_cards",()->{Harness h=new Harness("overlay");NativeCtripFlightPage.Page p=NativeCtripFlightPage.inspect(goal(),h.frame("overlay14.xml"));check(NativeCtripFlightPage.OVERLAY.equals(p.phase)&&p.quotes.isEmpty(),"overlay not background result");});
        one("actual_date16_uses_literal_month_day_not_todays_role_or_false_selected",()->{Harness h=new Harness("date16");NativeCtripFlightPage.Page p=NativeCtripFlightPage.inspect(goal(),h.frame("result16.xml"));check(LocalDate.of(2026,11,16).equals(p.displayedMonthDay(LocalDate.of(2026,11,14))),"literal full month/day wins");});
        one("actual_empty_calendar_has_headers_but_never_day_targets",()->{Harness h=new Harness("calendar");h.observe("calendar14.xml");check(h.session.domain().clickIds.isEmpty()&&h.session.domain().backAllowed,"only Back, no canvas/day coordinates");});
        one("owner_year_or_initial_form17_never_bypasses_actual_calendar_year_chain",()->{Harness h=new Harness("year");h.observe("form17.xml");check(h.target("query_observed_form")==null&&h.target("inspect_departure_year")!=null,"year proof must be acquired this task");});
        one("cached_goal_results_without_actual_task_query_never_complete",()->{Harness h=new Harness("cached");h.observe("result17.xml");check(!h.gate.verified(h.completion)&&h.session.domain().backAllowed,"cache has no query provenance");});
        one("actual_calendar_query_date_navigation_form_requery_final_chain",()->{Harness h=completed("normal");check(passed(h.normal()),"full synthetic boundary-qualified normal0 terminal");check(!passed(h.normal()),"one terminal consumption only");});
        for(final int exit:new int[]{70,124,143})one("terminal_exit_"+exit+"_never_substitutes_normal0",()->{Harness h=completed("exit"+exit);check(!passed(h.terminal(exit,true,true,true,true,false,true,true,true,h.task,id("worker"),sha("receipt"),h.lastRun)),"nonzero exit refused");});
        one("actual_query_after_year_read_does_not_imply_native_runtime_or_completion",()->{Harness h=new Harness("queryonly");h.year();h.perform("query_observed_form","result14.xml");check(!h.gate.verified(h.completion),"exploratory query not result completion");check(!passed(h.normal()),"no done candidate");});
        one("late_cancel_revokes_existing_native_success_candidate",()->{Harness h=completed("cancel");check(!passed(h.terminal(0,true,true,true,true,true,true,true,true,h.task,id("worker"),sha("receipt"),h.lastRun)),"late stop wins");});
        one("unknown_cleanup_revokes_native_success",()->{Harness h=completed("cleanup");check(!passed(h.terminal(0,false,true,true,true,false,true,true,true,h.task,id("worker"),sha("receipt"),h.lastRun)),"cleanup gate retained");});
        one("unreleased_virtual_display_revokes_native_success",()->{Harness h=completed("vd");check(!passed(h.terminal(0,true,false,true,true,false,true,true,true,h.task,id("worker"),sha("receipt"),h.lastRun)),"VD gate retained");});
        one("unrechecked_scope_revokes_native_success",()->{Harness h=completed("scope");check(!passed(h.terminal(0,true,true,false,true,false,true,true,true,h.task,id("worker"),sha("receipt"),h.lastRun)),"scope gate retained");});
        one("unrechecked_installed_app_revokes_native_success",()->{Harness h=completed("apk");check(!passed(h.terminal(0,true,true,true,false,false,true,true,true,h.task,id("worker"),sha("receipt"),h.lastRun)),"APK gate retained");});
        one("missing_parent_receipt_revokes_native_success",()->{Harness h=completed("receipt");check(!passed(h.terminal(0,true,true,true,true,false,true,true,false,h.task,id("worker"),sha("receipt"),h.lastRun)),"receipt gate retained");});
        one("foreign_worker_task_revokes_native_success",()->{Harness h=completed("foreignworker");check(!passed(h.terminal(0,true,true,true,true,false,true,true,true,id("foreign"),id("worker"),sha("receipt"),h.lastRun)),"same task required");});
        one("malformed_worker_generation_revokes_native_success",()->{Harness h=completed("workergen");check(!passed(h.terminal(0,true,true,true,true,false,true,true,true,h.task,GENERATION,sha("receipt"),h.lastRun)),"native worker32 is distinct from background UUID");});
        one("different_accepted_model_run_revokes_native_success",()->{Harness h=completed("run");check(!passed(h.terminal(0,true,true,true,true,false,true,true,true,h.task,id("worker"),sha("receipt"),id("foreign-model-run"))),"accepted actual done run required");});
        one("different_accepted_model_step_revokes_native_success",()->{Harness h=completed("step");h.step++;check(!passed(h.normal()),"exact accepted done step required");});
        one("different_final_observation_revokes_native_success",()->{Harness h=completed("finalframe");h.frame("result17-second.xml");check(!passed(h.normal()),"same content in another observation cannot replace accepted final frame");});
        one("no_physical_parent_exit_revokes_native_success",()->{Harness h=completed("parent");check(!passed(h.terminal(0,true,true,true,true,false,true,false,true,h.task,id("worker"),sha("receipt"),h.lastRun)),"physical wait proof required");});
        one("no_worker_started_revokes_native_success",()->{Harness h=completed("notstarted");check(!passed(h.terminal(0,true,true,true,true,false,false,true,true,h.task,id("worker"),sha("receipt"),h.lastRun)),"real task worker required");});
        one("background_uuid_is_preserved_and_worker32_is_rejected",()->{Harness h=new Harness("uuid");NativeAppEvidence.Frame f=h.frame("form14.xml");check(GENERATION.equals(f.generation),"original UUID bytes retained");reject(()->altered(f,f.ownerSha,f.targetSha,id("worker"),true,false),"worker ID cannot masquerade as lease UUID");});
        one("foreign_frame_owner_is_rejected_before_query_progress",()->{Harness h=new Harness("foreignowner");NativeAppEvidence.Frame f=h.frame("form14.xml");reject(()->h.session.observed(altered(f,sha("foreign owner"),f.targetSha,f.generation,true,false)),"foreign owner refused");});
        one("equal_looking_replaced_target_hash_is_rejected",()->{Harness h=new Harness("target");NativeAppEvidence.Frame f=h.frame("form14.xml");reject(()->h.session.observed(altered(f,f.ownerSha,sha("other target"),f.generation,true,false)),"target binding refused");});
        one("different_background_generation_is_rejected",()->{Harness h=new Harness("generation");NativeAppEvidence.Frame f=h.frame("form14.xml");reject(()->h.session.observed(altered(f,f.ownerSha,f.targetSha,"12345678-1234-4234-8234-123456789abd",true,false)),"lease replacement refused");});
        one("incomplete_collection_cannot_grant_any_native_click",()->{Harness h=new Harness("truncated");NativeAppEvidence.Frame f=h.frame("form14.xml");h.session.observed(altered(f,f.ownerSha,f.targetSha,f.generation,false,true));check(h.session.domain().clickIds.isEmpty()&&!h.session.domain().resultReady,"truncated remains unknown");});
        one("replayed_old_observation_cannot_replace_current_native_frame",()->{Harness h=new Harness("replay");h.observe("form14.xml");NativeAppEvidence.Frame old=h.frame;h.observe("form14.xml");reject(()->h.session.observed(old),"old ID/source is not current");});
        one("installed_identity_changed_before_observation_is_rejected",()->{Harness h=new Harness("changedapk");h.installedCurrent=false;reject(()->h.observe("form14.xml"),"actual verifier rechecked");});
        one("stale_undispatched_query_never_advances_query_proof",()->{Harness h=new Harness("stalequery");h.year();ActionDecision a=h.action("query_observed_form");h.issue(a,false,false,true);h.observe("result17.xml");check(!h.gate.verified(h.completion),"stale query no actual query");});
        one("rejected_dispatched_action_never_advances_query_proof",()->{Harness h=new Harness("rejectedquery");h.year();ActionDecision a=h.action("query_observed_form");h.issue(a,false,true,false);reject(()->h.observe("result17.xml"),"rejected effect invalidates query task");});
        one("pending_transition_has_its_actual_dispatch_relative_bound",()->{Harness h=new Harness("deadline");h.year();ActionDecision a=h.action("query_observed_form");h.issue(a,true,true,false);h.time+=15001;h.observe("result14.xml");reject(()->h.session.domain(),"expired transition cannot authorize later actions");});
        one("final_whole_tree_change_does_not_become_native_success",()->{Harness h=new Harness("unstablefinal");h.ready();JSONObject o=new JSONObject().put("action","done").put("package",NativeAppGoal.CTRIP_PACKAGE).put("observation_id",h.frame.observationId).put("status","success").put("summary","host only");h.issue(ActionDecision.parse(o.toString(),ActionDecision.IME_ACTION_SCHEMA),true,false,false);h.observe("result17-second.xml");check(!h.gate.successClaim(h.step,h.lastRun,h.completion,false).verified,"whole scene stability is not relaxed");});
        one("final_overlay_revokes_existing_result_readiness",()->{Harness h=new Harness("finaloverlay");h.ready();h.observe("overlay14.xml");check(!h.gate.verified(h.completion)&&h.session.domain().clickIds.isEmpty(),"underlying previous cards cannot complete");});
        one("unadmitted_native_click_cannot_escape_query_domain",()->{Harness h=new Harness("unadmitted");h.observe("form14.xml");NativeAppEvidence.Node n=null;for(NativeAppEvidence.Node v:h.frame.nodes)if(v.clickable&&!h.session.domain().clickIds.contains(v.id)&&!v.label.isEmpty()){n=v;break;}check(n!=null,"actual nonadmitted control fixture");JSONObject o=new JSONObject().put("action","click").put("package",NativeAppGoal.CTRIP_PACKAGE).put("observation_id",h.frame.observationId).put("node_id",n.id).put("node_label",n.label);checks++;try{h.session.domain().requireCurrent(ActionDecision.parse(o.toString(),ActionDecision.IME_ACTION_SCHEMA));throw new AssertionError("unadmitted control passed");}catch(ActionDecision.InvalidActionException expected){/* actual domain rejects */}});
        one("same_model_run_cannot_authorize_a_second_native_action",()->{Harness h=new Harness("duprun");h.observe("form14.xml");ActionDecision a=h.action("inspect_departure_year");h.issue(a,true,true,false);h.observe("calendar14.xml");ActionDecision b=h.action("return_from_calendar");reject(()->h.session.beforeModelAction(h.step+1,b,h.lastRun,h.time+10),"same run replay refused");});
        one("quote_evidence_maps_are_deeply_immutable",()->{Harness h=new Harness("immutable");NativeCtripFlightPage.Page p=NativeCtripFlightPage.inspect(goal(),h.frame("result17.xml"));Object fields=p.quotes.get(0).evidence().get("fields");checks++;try{((Map<?,?>)fields).clear();throw new AssertionError("mutable quoted fields");}catch(UnsupportedOperationException expected){}});
        JSONObject result=new JSONObject().put("schema","hepta.native-app-provider-host.v1").put("all_pass",true).put("cases",names.size()).put("assertions",checks).put("case_names",new JSONArray(names))
                .put("phone_operations",0).put("android_runtime",false).put("model_executed",false).put("business_verified",false)
                .put("fixture_boundary","Original root-exploration XML; exact production child-label collector; synthetic Frame/NodeRef/Window/Selection-wire/installed/model-action/SDK/cleanup boundaries");
        Files.write(out,(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println(result.toString());
    }
}
