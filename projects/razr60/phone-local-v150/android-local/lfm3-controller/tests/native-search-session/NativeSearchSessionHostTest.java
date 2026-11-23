package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import org.json.JSONObject;
import org.trillionnium.hepta.background.WindowOwnership;

/** Full actual Session/Offer/Attempt and provider classes over synthetic Android
 * transport, clocks and complete census inputs. No Android producer, permission,
 * node effect, model inference or phone business success is established here. */
public final class NativeSearchSessionHostTest {
    static final long START=1000000L;
    static final String OBS="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",RUN="dddddddddddddddddddddddddddddddd";
    static final String H=NativeAppEvidence.hash("explicit synthetic consumer evidence");
    static final List<String> caseNames=new ArrayList<String>();
    static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    static int assertions;
    static Path grammarOutput,planningContractOutput;
    interface Work {void run()throws Exception;}
    static void check(boolean yes,String why){assertions++;if(!yes)throw new AssertionError(why);}
    static void denied(Work action)throws Exception{
        boolean refused=false;
        try{action.run();}
        catch(IllegalArgumentException|IllegalStateException|IOException|ActionDecision.InvalidActionException expected){
            refused=true;check(expected.getMessage()!=null&&!expected.getMessage().isEmpty(),"explicit refusal detail");
        }
        check(refused,"actual production consumer must refuse");
    }
    static void one(String name,Work action){
        if(caseNames.contains(name))throw new AssertionError("duplicate case");
        LocalSocket.reset();SystemClock.now=START;caseNames.add(name);
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{action.run();row.put("passed",true);}
        catch(Throwable failure){row.put("passed",false);row.put("failure",failure.toString());
            java.io.StringWriter text=new java.io.StringWriter();failure.printStackTrace(new java.io.PrintWriter(text));row.put("stack",text.toString());}
        results.add(row);
    }
    static String id(){return UUID.randomUUID().toString().replace("-","");}

    /** Reuses the original actual BackgroundSession constructor and its explicit
     * host socket/display ports. No private Offer/Attempt constructor is called. */
    static final class Fixture implements AutoCloseable {
        final NativeProfileIdentityHostTest.Env env;
        final TaskAuthorization authority;
        final TaskAuthorization.Gate gate;
        final NativeAppSession nativeTask;
        final Object controller;
        final NativeSearchSession search;
        final List<String> journalNames=new ArrayList<String>();
        final List<Map<String,Object>> journal=new ArrayList<Map<String,Object>>();
        final String token=UUID.randomUUID().toString();
        boolean verifierFails,journalFails;
        int verifies,syntheticEffects;
        Fixture()throws Exception{this(NativeProfileIdentityHostTest.OWNER,new Object(),H);}
        Fixture(String owner)throws Exception{this(owner,new Object(),H);}
        Fixture(String owner,Object controller,String selectionSha)throws Exception{
            this.controller=controller;
            env=new NativeProfileIdentityHostTest.Env(NativeProfileIdentityHostTest.xiaomi(),owner);env.active();
            authority=TaskAuthorization.parse(owner).forExecutionSelection(env.session.selection);
            gate=authority.bind(NativeProfileIdentityHostTest.TASK);
            nativeTask=new NativeAppSession(NativeProfileIdentityHostTest.TASK,gate,env.session.selection,
                    new NativeAppEvidence.Installed(env.target),selectionSha,env.session.generation,env.session.displayId(),
                    ()->{verifies++;if(verifierFails)throw new IOException("synthetic installed identity changed");},
                    (name,value)->{if(journalFails)throw new IOException("synthetic journal failure");journalNames.add(name);
                        journal.add(NativeAppEvidence.immutableMap(value));});
            search=new NativeSearchSession(controller,nativeTask,env.session,START,START+60000);
        }
        WindowOwnership window(long at){
            return new WindowOwnership(env.target,env.session.generation,env.session.displayId(),96,1234,1200,
                    token,UUID.randomUUID().toString(),env.target.profile.userId,env.target.profile.serial,
                    env.target.fullUid,at-1,at+1000);
        }
        Map<String,Object> windowFacts(long at){
            Map<String,Object> row=new LinkedHashMap<String,Object>();
            row.put("window_id",96);row.put("display_id",env.session.displayId());row.put("type",1);row.put("layer",1);
            row.put("bounds",Arrays.asList(0,0,1224,2992));row.put("focused",true);row.put("active",true);
            Map<String,Object> reported=new LinkedHashMap<String,Object>();reported.put("display_id",env.session.displayId());
            reported.put("target_window_id",96);reported.put("target_layer",1);reported.put("windows",Collections.singletonList(row));
            reported.put("other_window_roots_traversed",false);reported.put("unreported_windows_excluded",false);
            String metadata=ObservedWindowMetadata.observed(new int[]{0,0,1224,2992},"android.widget.FrameLayout",
                    1,env.session.displayId(),new int[]{0,0,1224,2992},"synthetic host Xiaomi window").bindFreshness("");
            Map<String,Object> w=new LinkedHashMap<String,Object>();w.put("metadata",metadata);w.put("package",NativeAppGoal.XIAOMI_PACKAGE);
            w.put("window_id",96);w.put("display_id",env.session.displayId());w.put("rotation",0);w.put("left",0);w.put("top",0);
            w.put("right",1224);w.put("bottom",2992);w.put("width",1224);w.put("height",2992);
            Map<String,Object> facts=new LinkedHashMap<String,Object>();facts.put("window",w);facts.put("reported_windows",reported);
            facts.put("profile_window",window(at).evidence());facts.put("ime_visibility","hidden");return facts;
        }
        NativeActionSnapshotCheckHostTest.Fixture census(long at){
            NativeActionSnapshotCheckHostTest.Fixture f=NativeActionSnapshotCheckHostTest.xiaomi();
            Map<String,Object> facts=windowFacts(at);
            f.env.putAll(search.binding());f.env.putAll(NativeAppEvidence.profileActionIdentity(window(at)));
            f.env.put("origin_observation_id",OBS);f.env.put("captured_elapsed_ms",at);
            f.env.put("display_id",env.session.displayId());
            f.env.put("window_metadata_sha256",NativeActionSnapshotCheck.hash((String)map(facts.get("window")).get("metadata")));
            f.env.put("reported_windows_sha256",NativeAppEvidence.fingerprint(facts.get("reported_windows")));
            return f;
        }
        NativeSearchSession.Offer offer()throws Exception{
            PlanningParts p=buildPlanning(this);SystemClock.now=START+600;return search.offer(p.published,SystemClock.now);
        }
        NativeSearchDecision decision(NativeSearchSession.Offer offer)throws Exception{return decision(offer,offer.planning.id,offer.planning.role.roleId);}
        NativeSearchDecision decision(NativeSearchSession.Offer offer,String obs,String role)throws Exception{
            return NativeSearchDecision.parse("{\"reason\":\"synthetic model intent\",\"action\":\"native.open_search\",\"observation_id\":\""
                    +obs+"\",\"package\":\""+offer.planning.packageName+"\",\"role_id\":\""+role+"\"}");
        }
        NativeSearchSession.Attempt reserve(NativeSearchSession.Offer offer)throws Exception{
            SystemClock.now=START+700;return offer.reserve(decision(offer),RUN,SystemClock.now,SystemClock.now+8000);
        }
        void revalidate(NativeSearchSession.Attempt attempt){
            SystemClock.now=attempt.startedElapsed+250;
            attempt.revalidate(census(attempt.startedElapsed+100).snapshot(),census(attempt.startedElapsed+200).snapshot(),SystemClock.now);
        }
        HeptaAccessibilityService.ActionOutcome outcome(NativeSearchSession.Attempt attempt,boolean current,boolean returned){
            SystemClock.now=attempt.startedElapsed+300;
            ActionExecutionState state=new ActionExecutionState(id(),search.taskId,attempt.modelRunId,attempt.offer.planning.id,
                    authority.sha256,96,env.session.displayId(),env.session.generation,attempt.startedElapsed,attempt.deadlineElapsed,()->SystemClock.now);
            state.enterEffect(false,true);syntheticEffects++;
            if(returned)state.effectReturned(Boolean.TRUE);
            state.drained();boolean allowed=state.publish(false,current);
            return new HeptaAccessibilityService.ActionOutcome(allowed,returned,false,"explicit synthetic host effect lifecycle")
                    .withAuthorization(new JSONObject().put("callback_lease_current",current).put("callback_cancelled",false))
                    .withActionExecution(new JSONObject(state.evidence()));
        }
        NativeSearchSession.Attempt acceptedNavigation()throws Exception{
            NativeSearchSession.Offer offer=offer();NativeSearchSession.Attempt attempt=reserve(offer);revalidate(attempt);
            SystemClock.now=attempt.startedElapsed+290;attempt.claim(SystemClock.now);
            HeptaAccessibilityService.ActionOutcome result=outcome(attempt,true,true);
            search.acceptOutcome(attempt,result,NativeAppEvidence.hash(result.actionExecution.toString()),SystemClock.now);
            return attempt;
        }
        NativeAppEvidence.Node node(String id,String path,String cls,String parent,String text,String label,
                int left,int top,int right,int bottom,boolean click,boolean editable){
            return new NativeAppEvidence.Node(id,NativeAppGoal.XIAOMI_PACKAGE,cls,"",text,"",path,parent,H,label,
                    left,top,right,bottom,true,false,click,editable,false,Boolean.FALSE,Boolean.FALSE,Boolean.FALSE,Collections.<String>emptySet());
        }
        NativeAppEvidence.Frame inputFrame(long at,boolean complete){
            List<NativeAppEvidence.Node> rows=new ArrayList<NativeAppEvidence.Node>();
            rows.add(node("n1","0/1","android.widget.EditText","android.widget.FrameLayout","","",160,100,1000,200,true,true));
            rows.add(node("n2","0/0","android.view.ViewGroup","android.widget.FrameLayout","","搜索",20,110,150,190,true,false));
            rows.add(node("n3","0/0/0","android.widget.TextView","android.view.ViewGroup","搜索","搜索",30,120,140,180,false,false));
            rows.add(node("n4","0/4","android.view.ViewGroup","android.widget.FrameLayout","","搜索",1020,110,1200,190,true,false));
            rows.add(node("n5","0/4/0","android.widget.TextView","android.view.ViewGroup","搜索","搜索",1030,120,1190,180,false,false));
            return new NativeAppEvidence.Frame(search.taskId,nativeTask.goal.ownerSha256,nativeTask.target.targetSha256,authority.sha256,
                    nativeTask.selectionSha,id(),NativeAppGoal.XIAOMI_PACKAGE,env.session.generation,H,H,H,H,H,
                    env.session.displayId(),96,0,1224,2992,0,0,1224,2992,at,false,complete,rows,1,true,window(at));
        }
        public void close()throws IOException{search.retire();env.close();}
    }
    @SuppressWarnings("unchecked") static Map<String,Object> map(Object value){return (Map<String,Object>)value;}
    static final class PlanningParts {
        final NativeSearchPlanning core,published;final byte[] bytes;
        final NativeSearchPlanning.Timing timing;final NativeSearchPlanning.CaptureContext context;
        final NativeActionSnapshotCheck.Snapshot first,second;
        PlanningParts(NativeSearchPlanning core,NativeSearchPlanning published,byte[] bytes,NativeSearchPlanning.Timing timing,
                NativeSearchPlanning.CaptureContext context,NativeActionSnapshotCheck.Snapshot first,NativeActionSnapshotCheck.Snapshot second){
            this.core=core;this.published=published;this.bytes=bytes;this.timing=timing;this.context=context;this.first=first;this.second=second;
        }
    }
    /** Synthetic complete census/time/window sources, passed through every
     * production encode/readback/hash/publication validator. Reusable by pure
     * serialization probes; no private permission-bearing constructor is used. */
    static PlanningParts buildPlanning(Fixture f)throws Exception{
        NativeActionSnapshotCheck.Snapshot a=f.census(START+100).snapshot(),b=f.census(START+400).snapshot();
        NativeSearchPlanning.Timing timing=new NativeSearchPlanning.Timing(START,START+12000,
                START+50,START+150,START+100,START+350,START+450,START+400,START+460);
        NativeSearchPlanning.EventMark z=new NativeSearchPlanning.EventMark(0,0,0,0);
        NativeSearchPlanning.CaptureContext context=new NativeSearchPlanning.CaptureContext(f.windowFacts(START+100),f.windowFacts(START+400),z,z,z,z,z);
        byte[] encoded=NativeSearchPlanning.encode(OBS,a,b,f.search.binding(),timing,context);
        Path file=f.env.directory.resolve("synthetic-planning-"+id()+".json");
        Files.write(file,encoded,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
        byte[] actual=Files.readAllBytes(file);
        NativeSearchPlanning core=NativeSearchPlanning.fromSealedBytes(actual,HeptaAccessibilityService.sha(encoded),f.search.binding(),START+500);
        NativeSearchPlanning.WindowCheck check=new NativeSearchPlanning.WindowCheck(f.windowFacts(START+550),START+510,START+550,z,z);
        NativeSearchPlanning published=core.published(START+600,z,check);
        return new PlanningParts(core,published,actual,timing,context,a,b);
    }

    static void cases()throws Exception{
        one("actual_background_native_session_offer_chain",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();
            check(o.session==f.search&&f.search.nativeTask==f.nativeTask&&f.nativeTask.selection==f.env.session.selection,"same actual objects");
            check(o.planning.publication!=null&&Boolean.FALSE.equals(o.planning.evidence().get("generic_action_authority")),"published planning-only receipt");
            check(!f.search.navigationEffectRecorded()&&f.syntheticEffects==0,"planning is not an effect");
            Map<String,Object> contract=NativeSearchPlanningContractHostTest.verify(o.planning,planningContractOutput);
            check(Boolean.TRUE.equals(contract.get("all_pass")),"actual published planning contract probes");
        }});
        one("real_offer_emits_separate_grammar_and_actual_parsers",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();Map<String,Object> g=NativeSearchGrammarHostTest.verify(o,f.gate.frame(),grammarOutput);
            check(Boolean.TRUE.equals(g.get("all_pass")),"real Offer grammar checks completed");
        }});
        one("owner_click_deny_cannot_be_bypassed_by_derived_search_intent",()->{
            String owner=NativeProfileIdentityHostTest.OWNER+"；禁止点击";
            try(NativeProfileIdentityHostTest.Env env=new NativeProfileIdentityHostTest.Env(NativeProfileIdentityHostTest.xiaomi(),owner)){
                env.active();TaskAuthorization.Gate gate=TaskAuthorization.parse(owner).forExecutionSelection(env.session.selection).bind(NativeProfileIdentityHostTest.TASK);
                check(!gate.frame().allows("click"),"actual OWNER deny is present in the Gate");
                check(env.session.selection.executionTarget().nativeGoal==null,
                        "actual parser retains the complete deny suffix and refuses a qualified native goal");
                denied(()->new NativeAppSession(NativeProfileIdentityHostTest.TASK,gate,env.session.selection,
                        new NativeAppEvidence.Installed(env.target),H,env.session.generation,env.session.displayId(),()->{},(name,value)->{}));
                denied(()->gate.requireNativeSearchIntent(env.session.selection,env.session.selection.executionTarget().nativeGoal));
            }
        });
        one("same_authorization_value_different_actual_gate_is_rejected",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();TaskAuthorization.Gate other=f.authority.bind(f.search.taskId);
            check(other!=f.gate&&other.authorization==f.gate.authorization,"same authority object, distinct Gate");
            check(NativeSearchPlanning.equal(other.frame().evidence(),f.gate.frame().evidence()),"same public frame evidence");
            denied(()->DecisionGrammar.createNativeSearchAuthorized(o,other.frame()));
        }});
        one("same_value_different_selection_cannot_bind_background",()->{try(Fixture f=new Fixture()){
            BackgroundSession.Selection selection=new BackgroundSession.Selection(f.env.session.selection.taskTarget);
            TaskAuthorization.Gate gate=TaskAuthorization.parse(NativeProfileIdentityHostTest.OWNER).forExecutionSelection(selection).bind(f.search.taskId);
            NativeAppSession other=new NativeAppSession(f.search.taskId,gate,selection,new NativeAppEvidence.Installed(f.env.target),
                    H,f.env.session.generation,f.env.session.displayId(),()->{},(name,value)->{});
            check(selection!=f.env.session.selection&&selection.taskTarget==f.env.session.selection.taskTarget,"same target value, distinct selection");
            denied(()->new NativeSearchSession(new Object(),other,f.env.session,START,START+60000));
        }});
        one("second_session_and_controller_cannot_replace_bound_session",()->{try(Fixture f=new Fixture()){
            denied(()->new NativeSearchSession(new Object(),f.nativeTask,f.env.session,START,START+60000));
            f.search.requireLive(START);check(f.search.controller==f.controller,"original controller holder retained");
        }});
        one("foreign_actual_offer_cannot_move_to_another_session",()->{try(Fixture a=new Fixture();Fixture b=new Fixture()){
            NativeSearchSession.Offer x=a.offer(),y=b.offer();denied(()->a.search.requireOffer(y));denied(()->b.search.requireOffer(x));
        }});
        one("foreign_planning_binding_cannot_mint_an_offer",()->{try(Fixture a=new Fixture();Fixture b=new Fixture()){
            PlanningParts other=buildPlanning(b);denied(()->a.search.offer(other.published,START+600));
        }});
        one("unpublished_planning_never_enters_offer",()->{try(Fixture f=new Fixture()){
            PlanningParts p=buildPlanning(f);denied(()->f.search.offer(p.core,START+600));
        }});
        one("aged_planning_never_refreshes_offer_clock",()->{try(Fixture f=new Fixture()){
            PlanningParts p=buildPlanning(f);denied(()->f.search.offer(p.published,START+2401));
        }});
        one("one_offer_only_per_actual_session",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();denied(()->f.search.offer(o.planning,START+600));
        }});
        one("retired_gate_rejects_existing_offer_grammar",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();f.gate.retire();denied(()->o.grammar());
        }});
        one("retired_session_rejects_existing_offer_grammar",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();f.search.retire();denied(()->o.grammar());
        }});
        one("expired_session_rejects_new_reservation",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();denied(()->o.reserve(f.decision(o),RUN,START+60000,START+61000));
        }});
        one("wrong_observation_or_role_intent_is_rejected",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();denied(()->o.reserve(f.decision(o,id(),o.planning.role.roleId),RUN,START+700,START+8700));
            denied(()->o.reserve(f.decision(o,o.planning.id,H),RUN,START+700,START+8700));
            check(f.syntheticEffects==0,"no identity repair or effect");
        }});
        one("action_deadline_cannot_exceed_original_eight_seconds",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();denied(()->o.reserve(f.decision(o),RUN,START+700,START+8701));
        }});
        one("reservation_consumes_offer_before_any_effect",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();NativeSearchSession.Attempt a=f.reserve(o);
            denied(()->o.grammar());denied(()->o.reserve(f.decision(o),id(),START+701,START+8701));
            check(Boolean.FALSE.equals(a.evidence().get("claimed"))&&f.syntheticEffects==0,"reserved without effect");
            check(f.journalNames.contains("native-search-navigation-attempt.json"),"actual native reservation journal");
        }});
        one("journal_failure_does_not_restore_offer_or_retry",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Offer o=f.offer();f.journalFails=true;denied(()->f.reserve(o));f.journalFails=false;
            denied(()->o.grammar());denied(()->o.reserve(f.decision(o),id(),START+701,START+8701));check(f.syntheticEffects==0,"no retry after persistence failure");
        }});
        one("claim_without_current_complete_cd_is_rejected",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());denied(()->a.claim(START+800));
            check(Boolean.FALSE.equals(a.evidence().get("claimed")),"no pure planning-to-effect shortcut");
        }});
        one("actual_installed_verifier_is_rechecked",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());int before=f.verifies;a.verifyInstalled();check(f.verifies==before+1,"actual verifier call");
            f.verifierFails=true;denied(()->a.verifyInstalled());check(f.syntheticEffects==0,"changed installation did not dispatch");
        }});
        one("current_cd_is_bound_to_original_offer_and_identity",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());NativeActionSnapshotCheckHostTest.Fixture c=f.census(START+800),d=f.census(START+900);
            d.env.put("origin_observation_id",id());denied(()->a.revalidate(c.snapshot(),d.snapshot(),START+950));
        }});
        one("current_cd_cannot_precede_attempt",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());denied(()->a.revalidate(f.census(START+650).snapshot(),f.census(START+900).snapshot(),START+950));
        }});
        one("changed_current_search_role_is_rejected",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());NativeActionSnapshotCheckHostTest.Fixture c=f.census(START+800),d=f.census(START+900);
            d.nodes.get(d.target).put("enabled",false);denied(()->a.revalidate(c.snapshot(),d.snapshot(),START+950));
        }});
        one("current_complete_cd_allows_one_claim_only",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());f.revalidate(a);a.claim(START+980);
            check(Boolean.TRUE.equals(a.evidence().get("claimed")),"claim recorded");denied(()->a.claim(START+981));
            check(f.syntheticEffects==0,"claim is not proof of an Android effect");
        }});
        one("second_revalidation_cannot_replace_original_cd",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());f.revalidate(a);
            denied(()->a.revalidate(f.census(START+960).snapshot(),f.census(START+970).snapshot(),START+980));
        }});
        one("closed_or_retired_attempt_never_becomes_live_again",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());f.revalidate(a);a.close();denied(()->a.claim(START+980));denied(()->a.requireLive(START+981));
        }});
        one("late_attempt_cannot_claim_or_extend_deadline",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());f.revalidate(a);denied(()->a.claim(a.deadlineElapsed));check(a.deadlineElapsed==START+8700,"original deadline retained");
        }});
        one("unclaimed_outcome_cannot_create_navigation_proof",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());f.revalidate(a);HeptaAccessibilityService.ActionOutcome o=f.outcome(a,true,true);
            denied(()->f.search.acceptOutcome(a,o,H,SystemClock.now));check(!f.search.navigationEffectRecorded(),"missing claim refused");
        }});
        one("retired_callback_and_missing_effect_return_are_rejected",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());f.revalidate(a);a.claim(START+980);
            denied(()->f.search.acceptOutcome(a,f.outcome(a,false,true),H,SystemClock.now));
            denied(()->f.search.acceptOutcome(a,f.outcome(a,true,false),H,SystemClock.now));
            check(!f.search.navigationEffectRecorded(),"uncertain effect never authorized handoff");
        }});
        one("effect_receipt_requires_current_same_run_identity",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.reserve(f.offer());f.revalidate(a);a.claim(START+980);
            HeptaAccessibilityService.ActionOutcome o=f.outcome(a,true,true);
            JSONObject changed=new JSONObject(o.actionExecution.toString()).put("model_run_id",id());
            denied(()->f.search.acceptOutcome(a,o.withActionExecution(changed),H,SystemClock.now));
            check(!f.search.navigationEffectRecorded(),"foreign run refused");
        }});
        one("accepted_effect_still_requires_new_provider_observation",()->{try(Fixture f=new Fixture()){
            NativeSearchSession.Attempt a=f.acceptedNavigation();
            check(f.search.navigationEffectRecorded(),"actual consumer recorded synthetic effect");
            denied(()->f.nativeTask.requireModelPlanning());denied(()->f.search.navigationObserved(null));
            check(f.journalNames.contains("native-search-navigation-effect.json"),"effect journal written");
            check(Boolean.TRUE.equals(a.evidence().get("claimed")),"consumed claim preserved");
        }});
        one("provider_frame_before_effect_cannot_close_navigation",()->{try(Fixture f=new Fixture()){
            f.acceptedNavigation();denied(()->f.nativeTask.observed(f.inputFrame(START+999,true)));
            denied(()->f.nativeTask.requireModelPlanning());
        }});
        one("incomplete_provider_frame_cannot_close_navigation",()->{try(Fixture f=new Fixture()){
            f.acceptedNavigation();denied(()->f.nativeTask.observed(f.inputFrame(START+1100,false)));
            denied(()->f.nativeTask.requireModelPlanning());
        }});
        one("fresh_actual_provider_contract_handoff_is_navigation_only",()->{try(Fixture f=new Fixture()){
            f.acceptedNavigation();NativeAppEvidence.Frame frame=f.inputFrame(START+1100,true);
            NativeXiaomiProductPage.Page page=NativeXiaomiProductPage.inspect(f.nativeTask.goal,frame);
            check("search_input".equals(page.phase)&&page.quote==null&&page.missing.isEmpty(),"actual provider parses the synthetic complete input");
            f.nativeTask.observed(frame);f.search.navigationObserved(frame);f.nativeTask.requireModelPlanning();
            check(f.nativeTask.domain().frame.sameSource(frame),"same actual Frame entered native provider");
            check(f.journalNames.contains("native-search-navigation-observed.json"),"fresh contract handoff journal");
            denied(()->f.search.navigationObserved(frame));
            check(page.quote==null&&page.clickIds.isEmpty()&&page.editValues.size()==1,"navigation did not prove query, price, order or success");
        }});
    }
    public static void main(String[] args)throws Exception{
        Path result=Paths.get(args[0]);NativeProfileIdentityHostTest.workspace=Paths.get(args[1]);
        Files.createDirectories(NativeProfileIdentityHostTest.workspace);grammarOutput=Paths.get(args[2]);planningContractOutput=result.resolveSibling("PLANNING-CONTRACT.json");
        cases();boolean pass=true;for(Map<String,Object> row:results)if(!Boolean.TRUE.equals(row.get("passed")))pass=false;
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("schema","hepta.native-search-session-host.v1");
        report.put("all_pass",pass);report.put("cases",caseNames.size());report.put("assertions",assertions);
        report.put("case_names",caseNames);report.put("results",results);
        report.put("boundary","Actual Session/Offer/Attempt/Gate/provider classes; explicit synthetic census, time, Android IO and effect result inputs. No private Offer constructor, permission-acceptance stub, Android producer, model or phone effect.");
        report.put("phone_tested",false);report.put("controller_identity_service_guard_tested",false);
        report.put("android_effect_tested",false);report.put("business_verified",false);
        Files.write(result,(new JSONObject(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
        System.out.println("native search Session cases="+caseNames.size()+" assertions="+assertions+" all_pass="+pass);
        if(!pass)throw new AssertionError("actual Session consumer cases failed; read CASES.json");
    }
}
