package org.trillionnium.hepta.local;

import android.os.SystemClock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Retained 5b8 failed-read shapes plus actual Session/provider transitions.
 * Binding/time/Android transport are explicit host ports, never phone authority. */
public final class NativeSearchModalHostTest {
    private static final long START=NativeSearchSessionHostTest.START;
    private static final String H=NativeSearchSessionHostTest.H;
    private static JSONObject recorded;
    private static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    private static int assertions;
    interface Test {void run()throws Exception;}
    static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static void denied(Test body)throws Exception{boolean refused=false;try{body.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){refused=true;}check(refused,"actual policy must reject");}
    static void one(String name,Test body){Map<String,Object> r=new LinkedHashMap<String,Object>();r.put("name",name);
        try{body.run();r.put("passed",true);}catch(Throwable error){r.put("passed",false);r.put("failure",error.toString());
            java.io.StringWriter trace=new java.io.StringWriter();error.printStackTrace(new java.io.PrintWriter(trace));r.put("stack",trace.toString());}cases.add(r);}
    static JSONObject copy(JSONObject in){return new JSONObject(in.toString());}
    static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject raw){
        List<NativeActionSnapshotCheck.Node> nodes=new ArrayList<NativeActionSnapshotCheck.Node>();
        JSONArray rows=raw.getJSONArray("nodes");for(int i=0;i<rows.length();i++)nodes.add(new NativeActionSnapshotCheck.Node(rows.getJSONObject(i).toMap()));
        return new NativeActionSnapshotCheck.Snapshot(raw.getJSONObject("envelope").toMap(),nodes);
    }
    static Map<String,Object> hint(JSONObject a,JSONObject b){return NativeSearchRole.imageModalReadCandidate(snapshot(a),snapshot(b));}
    static NativeAppEvidence.Frame modalFrame(NativeSearchSessionHostTest.Fixture f,long at,String label){
        JSONArray rows=recorded.getJSONObject("second").getJSONArray("nodes");List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();
        for(int i=1;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);JSONArray b=n.getJSONArray("bounds");
            nodes.add(new NativeAppEvidence.Node("n"+(i-1),n.getString("package"),n.getString("class"),n.getString("view_id"),
                    n.getString("text"),n.getString("description"),n.getString("path"),n.getString("parent_class"),n.getString("ref_signature_sha256"),
                    label==null?n.getString("label"):label,b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),true,false,true,false,false,
                    Boolean.FALSE,Boolean.FALSE,Boolean.FALSE,Collections.<String>emptySet()));
        }
        return new NativeAppEvidence.Frame(f.search.taskId,f.nativeTask.goal.ownerSha256,f.nativeTask.target.targetSha256,f.authority.sha256,
                f.nativeTask.selectionSha,NativeSearchSessionHostTest.id(),NativeAppGoal.XIAOMI_PACKAGE,f.env.session.generation,H,H,H,H,H,
                f.env.session.displayId(),96,0,1224,2992,186,694,1038,2298,at,false,true,nodes,1,true,f.window(at));
    }
    static ActionDecision back(NativeSearchSessionHostTest.Fixture f,NativeAppEvidence.Frame frame,String run,boolean accepted,boolean dispatched,boolean stale)throws Exception{
        ActionDecision a=ActionDecision.parse(new JSONObject().put("action","back").put("package",frame.packageName)
                .put("observation_id",frame.observationId).toString(),ActionDecision.IME_ACTION_SCHEMA);
        f.gate.check(a,run);f.nativeTask.beforeModelAction(1,a,run,START+300);
        f.nativeTask.modelActionOutcome(a,run,accepted,dispatched,stale,H,START+400);SystemClock.now=START+450;return a;
    }
    static NativeSearchPlanning home(NativeSearchSessionHostTest.Fixture f,long at)throws Exception{
        NativeSearchPlanning.EventMark z=new NativeSearchPlanning.EventMark(0,0,0,0);
        NativeActionSnapshotCheck.Snapshot a=f.census(at+100).snapshot(),b=f.census(at+400).snapshot();
        NativeSearchPlanning.Timing timing=new NativeSearchPlanning.Timing(at,at+12000,at+50,at+150,at+100,at+350,at+450,at+400,at+460);
        NativeSearchPlanning.CaptureContext context=new NativeSearchPlanning.CaptureContext(f.windowFacts(at+100),f.windowFacts(at+400),z,z,z,z,z);
        byte[] bytes=NativeSearchPlanning.encode(NativeSearchSessionHostTest.OBS,a,b,f.search.binding(),timing,context);
        NativeSearchPlanning core=NativeSearchPlanning.fromSealedBytes(bytes,HeptaAccessibilityService.sha(bytes),f.search.binding(),at+500);
        return core.published(at+600,z,new NativeSearchPlanning.WindowCheck(f.windowFacts(at+550),at+510,at+550,z,z));
    }
    static void cases()throws Exception{
        one("retained_5b8_pair_routes_only_to_new_observation",()->{
            check(recorded.getString("source_receipt_sha256").equals("bb560a1b65b5406b4cd6ee297df2af24ff1c87b81773f66c68208f071e758311"),"original failure retained");
            JSONObject a=recorded.getJSONObject("first"),b=recorded.getJSONObject("second");
            check(a.getJSONArray("nodes").length()==3&&b.getJSONArray("nodes").length()==3,"full actual pair");
            Map<String,Object> h=hint(a,b);check(Boolean.FALSE.equals(h.get("grants_action_authority")),"no Back authority from hint");
            check(Boolean.FALSE.equals(h.get("close_button_identified"))&&Boolean.FALSE.equals(h.get("image_content_classified")),"image semantics unknown");
            denied(()->NativeSearchRole.compareForPlanning(snapshot(a),snapshot(b)));
        });
        one("routing_rejects_labels_resources_and_changed_geometry",()->{
            for(String key:new String[]{"text","description","label","view_id"}){
                JSONObject a=copy(recorded.getJSONObject("first")),b=copy(recorded.getJSONObject("second"));
                a.getJSONArray("nodes").getJSONObject(1).put(key,"同意");b.getJSONArray("nodes").getJSONObject(1).put(key,"同意");denied(()->hint(a,b));
            }
            JSONObject a=copy(recorded.getJSONObject("first")),b=copy(recorded.getJSONObject("second"));
            b.getJSONArray("nodes").getJSONObject(2).getJSONArray("bounds").put(0,555);denied(()->hint(a,b));
        });
        one("routing_rejects_ownership_window_and_incomplete_changes",()->{
            for(String key:new String[]{"profile_full_uid","window_id","display_id"}){
                JSONObject a=copy(recorded.getJSONObject("first")),b=copy(recorded.getJSONObject("second"));
                b.getJSONObject("envelope").put(key,b.getJSONObject("envelope").getInt(key)+1);denied(()->hint(a,b));
            }
            JSONObject a=copy(recorded.getJSONObject("first")),b=copy(recorded.getJSONObject("second"));b.getJSONObject("envelope").put("pending",1);denied(()->hint(a,b));
        });
        one("routing_rejects_extra_capabilities",()->{
            for(String key:new String[]{"editable","scrollable","password","selected","checkable","checked"}){
                JSONObject a=copy(recorded.getJSONObject("first")),b=copy(recorded.getJSONObject("second"));
                a.getJSONArray("nodes").getJSONObject(1).put(key,true);b.getJSONArray("nodes").getJSONObject(1).put(key,true);denied(()->hint(a,b));
            }
        });
        one("ordinary_modal_requires_explicit_initial_handoff",()->{try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            denied(()->f.nativeTask.observed(modalFrame(f,START+100,null)));
        }});
        one("fresh_existing_provider_exposes_only_once_back",()->{try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            f.search.beginImageModalPrelude(START);f.nativeTask.observed(modalFrame(f,START+100,null));NativeAppDomain d=f.nativeTask.domain();
            check(d.phase.equals(NativeXiaomiProductPage.IMAGE_MODAL)&&d.backAllowed,"existing provider Back domain");
            check(d.clickIds.isEmpty()&&d.editValues.isEmpty()&&!d.resultReady,"no image click/query/result");
            denied(()->f.search.beginImageModalPrelude(START+101));denied(()->f.search.offer(home(f,START),START+600));
            denied(()->f.search.requireBeforeFirstPlanning(START+101));
        }});
        one("fresh_ordinary_provider_must_still_match_modal",()->{try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            f.search.beginImageModalPrelude(START);denied(()->f.nativeTask.observed(modalFrame(f,START+100,"同意")));
        }});
        one("accepted_back_requires_new_full_home_pair_before_offer",()->{try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            f.search.beginImageModalPrelude(START);NativeAppEvidence.Frame frame=modalFrame(f,START+100,null);f.nativeTask.observed(frame);
            String run=NativeSearchSessionHostTest.id();ActionDecision a=back(f,frame,run,true,true,false);
            check(f.search.imageModalBackReady(a,run,START+450),"actual durable Back outcome");long deadline=f.search.chainDeadlineElapsed;
            f.search.prepareImageModalHomePlanning(a,run,START+450);
            check(!f.search.allowsImageModalObservation()&&f.search.imageModalHomePlanning(),"old modal frame no longer executable");
            check(f.search.initialPlanningDeadline()==START+400+15000&&f.search.chainDeadlineElapsed==deadline,"original clocks retained");
            denied(()->f.search.offer(home(f,START),START+600));
            NativeSearchPlanning plan=home(f,START+1000);SystemClock.now=START+1600;NativeSearchSession.Offer offer=f.search.offer(plan,SystemClock.now);
            check(f.journalNames.contains("native-search-image-modal-home.json"),"durable full home navigation evidence");
            check(!f.search.navigationEffectRecorded(),"Back/home are not search effect or query proof");
            denied(()->f.nativeTask.domain());
            NativeSearchSession.Attempt attempt=offer.reserve(f.decision(offer),NativeSearchSessionHostTest.id(),START+1700,START+9700);
            check(!Boolean.TRUE.equals(attempt.evidence().get("claimed")),"new model search intent still unclaimed");
            Map<String,Object> progress=NativeSearchSessionHostTest.map(f.nativeTask.evidence().get("progress"));
            check(((Number)progress.get("actual_model_actions")).intValue()==2,"Back ordinal retained before distinct search model");
            check(Boolean.FALSE.equals(progress.get("product_query_observed")),"business predicate unchanged");
        }});
        one("stale_unentered_back_never_opens_home_planning",()->{try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            f.search.beginImageModalPrelude(START);NativeAppEvidence.Frame frame=modalFrame(f,START+100,null);f.nativeTask.observed(frame);
            String run=NativeSearchSessionHostTest.id();ActionDecision a=back(f,frame,run,false,false,true);
            check(!f.search.imageModalBackReady(a,run,START+450),"no effect means no navigation continuation");
            denied(()->f.search.prepareImageModalHomePlanning(a,run,START+450));
            f.nativeTask.observed(modalFrame(f,START+500,null));check(!f.nativeTask.domain().backAllowed,"one Back budget remains spent");
        }});
        one("different_run_and_late_back_cannot_resume",()->{try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            f.search.beginImageModalPrelude(START);NativeAppEvidence.Frame frame=modalFrame(f,START+100,null);f.nativeTask.observed(frame);
            String run=NativeSearchSessionHostTest.id();ActionDecision a=back(f,frame,run,true,true,false);
            denied(()->f.search.prepareImageModalHomePlanning(a,NativeSearchSessionHostTest.id(),START+450));
            denied(()->f.search.prepareImageModalHomePlanning(a,run,START+15400));
        }});
        one("home_proof_journal_failure_cannot_offer_search",()->{try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            f.search.beginImageModalPrelude(START);NativeAppEvidence.Frame frame=modalFrame(f,START+100,null);f.nativeTask.observed(frame);
            String run=NativeSearchSessionHostTest.id();ActionDecision a=back(f,frame,run,true,true,false);f.search.prepareImageModalHomePlanning(a,run,START+450);
            f.journalFails=true;denied(()->f.search.offer(home(f,START+1000),START+1600));check(!f.search.navigationEffectRecorded(),"no action after receipt failure");
        }});
        one("ordinary_home_cannot_replace_typed_return_proof",()->{try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            f.search.beginImageModalPrelude(START);NativeAppEvidence.Frame frame=modalFrame(f,START+100,null);f.nativeTask.observed(frame);
            String run=NativeSearchSessionHostTest.id();ActionDecision a=back(f,frame,run,true,true,false);f.search.prepareImageModalHomePlanning(a,run,START+450);
            denied(()->f.nativeTask.observed(f.inputFrame(START+500,true)));
        }});
    }
    public static void main(String[] args)throws Exception{
        recorded=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        NativeProfileIdentityHostTest.workspace=Paths.get(args[2]);Files.createDirectories(NativeProfileIdentityHostTest.workspace);cases();
        boolean pass=true;for(Map<String,Object> r:cases)pass&=Boolean.TRUE.equals(r.get("passed"));
        JSONObject report=new JSONObject().put("schema","hepta.native-search-image-modal-host.v1").put("all_pass",pass)
                .put("cases",cases.size()).put("assertions",assertions).put("results",cases).put("phone_operations",0)
                .put("model_inference_tested",false).put("business_verified",false)
                .put("boundary","Actual retained 5b8 raw census; complete production provider/Session. Explicit host identity, time, model-decision and Android transport ports.");
        Files.write(Paths.get(args[1]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());
        if(!pass)throw new AssertionError("image-modal policy cases failed");
    }
}
