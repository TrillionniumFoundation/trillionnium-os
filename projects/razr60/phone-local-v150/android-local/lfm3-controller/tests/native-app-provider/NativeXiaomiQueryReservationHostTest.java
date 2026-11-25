package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileIdentity;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Actual e7ef24 sealed AX nodes and no-effect rejection. The original files are
 * read-only; the action fixture is a labelled projection omitting unrelated encoded\n * hardware display identifiers. Session selection/auth binding, journal and new model decisions are
 * explicit host doubles; no Android dispatch, pixel capture, or business result
 * is performed. Exact actual AX envelopes are validated before host rebinding. */
public final class NativeXiaomiQueryReservationHostTest {
    private static final String OWNER="在小米商城查询AX3000T价格";
    private static final NativeAppGoal GOAL=NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE);
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private static Path root;
    private static JSONObject before,after,binding;
    private static final Map<String,byte[]> originals=new TreeMap<String,byte[]>();
    private interface Work {void run()throws Exception;}
    private interface Change {void apply(JSONObject frame)throws Exception;}
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void one(String name,Work work){
        if(names.contains(name))throw new IllegalArgumentException("duplicate case");names.add(name);
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{work.run();row.put("passed",true);}catch(Throwable failure){row.put("passed",false);row.put("failure",failure.toString());}
        results.add(row);
    }
    private static String hash(String s){return NativeAppEvidence.hash(s);}
    private static String hash(byte[] raw){return hash(new String(raw,StandardCharsets.UTF_8));}
    private static JSONObject copy(JSONObject j){return new JSONObject(j.toString());}
    private static Object plain(Object v){
        if(v==JSONObject.NULL)return null;
        if(v instanceof JSONObject){Map<String,Object> out=new TreeMap<String,Object>();JSONObject o=(JSONObject)v;
            for(String k:o.keySet())out.put(k,plain(o.get(k)));return out;}
        if(v instanceof JSONArray){List<Object> out=new ArrayList<Object>();JSONArray a=(JSONArray)v;
            for(int i=0;i<a.length();i++)out.add(plain(a.get(i)));return out;}
        return v;
    }
    @SuppressWarnings("unchecked")
    private static Map<String,Object> map(JSONObject value){return (Map<String,Object>)plain(value);}
    private static JSONObject at(JSONObject r,String path){
        JSONArray nodes=r.getJSONArray("nodes");for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);if(path.equals(n.getJSONObject("native_tree_position").getString("path")))return n;
        }throw new IllegalArgumentException("fixture native path absent: "+path);
    }
    private static void remove(JSONObject r,String path){
        JSONArray nodes=r.getJSONArray("nodes");for(int i=0;i<nodes.length();i++){
            if(path.equals(nodes.getJSONObject(i).getJSONObject("native_tree_position").getString("path"))){
                nodes.remove(i);r.getJSONObject("collection").put("retained_nodes",nodes.length());return;}
        }throw new IllegalArgumentException("fixture native path absent");
    }
    private static void move(JSONObject r,String old,String replacement){
        JSONArray nodes=r.getJSONArray("nodes");for(int i=0;i<nodes.length();i++){
            JSONObject pos=nodes.getJSONObject(i).getJSONObject("native_tree_position");String p=pos.getString("path");
            if(p.equals(old)||p.startsWith(old+"/"))pos.put("path",replacement+p.substring(old.length()));
        }
    }
    private static void add(JSONObject r,JSONObject node){
        r.getJSONArray("nodes").put(node);r.getJSONObject("collection").put("retained_nodes",r.getJSONArray("nodes").length());
    }
    private static ProfileTarget target(){
        JSONObject t=binding.getJSONObject("profile_target"),p=t.getJSONObject("profile");
        ProfileIdentity profile=new ProfileIdentity(p.getInt("user_id"),p.getLong("user_serial"),p.getInt("parent_user_id"),p.getString("user_type"));
        Map<String,String> apks=new TreeMap<String,String>();JSONObject a=t.getJSONObject("apk_hashes");
        for(String k:a.keySet())apks.put(k,a.getString(k));
        TreeSet<String> signers=new TreeSet<String>();JSONArray ss=t.getJSONArray("signer_sha256");
        for(int i=0;i<ss.length();i++)signers.add(ss.getString(i));
        ProfileTarget actual=new ProfileTarget(profile,t.getInt("full_uid"),t.getString("package"),t.getString("component"),t.getLong("version_code"),apks,signers);
        check(actual.sha256.equals(t.getString("target_identity_sha256")),"actual installed profile target source");
        return actual;
    }
    private static NativeAppEvidence.Frame frame(JSONObject r){
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();JSONArray rows=r.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i),pos=n.getJSONObject("native_tree_position"),sel=n.getJSONObject("native_selection_state");
            JSONArray b=n.getJSONArray("bounds");String text=n.optString("text",""),desc=n.optString("description","");
            // The ordinary projection uses original text, then description, then
            // the already observed child label; no word is invented for input.
            String label=ObservedTargetLabels.project(!text.isEmpty()?text:!desc.isEmpty()?desc:n.optString("child_text",""));
            Boolean selected=sel.optBoolean("observed")?Boolean.valueOf(sel.getBoolean("selected")):null;
            TreeSet<String> directions=new TreeSet<String>();JSONArray ds=n.optJSONArray("scroll_directions");
            if(ds!=null)for(int k=0;k<ds.length();k++)directions.add(ds.getString(k));
            nodes.add(new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),
                text,desc,pos.getString("path"),pos.getString("parent_class"),n.getString("node_app_tree_sha256"),label,
                b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),n.optBoolean("enabled",true),n.optBoolean("password"),
                n.optBoolean("clickable"),n.optBoolean("editable"),n.optBoolean("scrollable"),selected,
                selected==null?null:Boolean.valueOf(sel.getBoolean("checkable")),selected==null?null:Boolean.valueOf(sel.getBoolean("checked")),directions));
        }
        JSONObject meta=r.getJSONObject("capture");byte[] captureRaw=originals.get(meta.getString("receipt_file"));
        check(captureRaw!=null&&captureRaw.length==meta.getInt("receipt_bytes")
                &&hash(captureRaw).equals(meta.getString("receipt_sha256")),"exact sealed capture source");
        JSONObject receipt=new JSONObject(new String(captureRaw,StandardCharsets.UTF_8));
        ObservationCaptureEvidence capture="native_ax_empty_search_input_history".equals(meta.getString("kind"))
                ?ObservationCaptureEvidence.fromSealedNativeAxInputHistory(map(receipt),captureRaw,hash(captureRaw))
                :ObservationCaptureEvidence.fromSealedNativeAx(map(receipt),captureRaw,hash(captureRaw));
        JSONObject b=receipt.getJSONObject("binding"),o=b.getJSONObject("profile_window");
        ProfileTarget t=target();
        WindowOwnership ownership=new WindowOwnership(t,o.getString("generation"),o.getInt("display_id"),o.getInt("window_id"),
                o.getInt("task_id"),o.getInt("parent_task_id"),o.getString("task_token_id"),o.getString("proof_id"),
                o.getInt("user_id"),o.getLong("user_serial"),o.getInt("full_uid"),o.getLong("observed_elapsed_ms"),o.getLong("expires_elapsed_ms"));
        check(ownership.sha256.equals(o.getString("proof_sha256")),"actual original window ownership hash");
        JSONObject window=r.getJSONObject("window"),collection=r.getJSONObject("collection"),background=r.getJSONObject("background_session");
        JSONArray bounds=window.getJSONArray("bounds");boolean complete=collection.getInt("retained_nodes")==nodes.size()
                &&collection.getInt("pending_nodes_at_stop")==0&&collection.getLong("child_slots_omitted_by_traversal_limit")==0
                &&collection.getInt("nodes_omitted_by_node_limit")==0&&collection.getInt("nodes_omitted_by_text_limit")==0;
        check(GOAL.ownerSha256.equals(b.getString("owner_sha256"))&&binding.getString("task_id").equals(b.getString("task_id")),"immutable actual owner/task");
        String sourceHash=r.toString().equals(before.toString())?hash(originals.get("step-03-before.json"))
                :r.toString().equals(after.toString())?hash(originals.get("step-04-before.json"))
                :hash("explicit-host-mutant-record:"+r.toString());
        return new NativeAppEvidence.Frame(b.getString("task_id"),b.getString("owner_sha256"),b.getString("execution_target_sha256"),
                b.getString("task_authorization_sha256"),b.getString("actual_selection_sha256"),r.getString("observation_id"),
                r.getString("package"),background.getString("generation"),r.getString("app_tree_sha256"),r.getString("observation_state_sha256"),
                null,sourceHash,hash("explicit-host-completion-only"),window.getInt("display_id"),r.getInt("window_id"),r.getInt("rotation"),
                r.getInt("screen_width"),r.getInt("screen_height"),bounds.getInt(0),bounds.getInt(1),bounds.getInt(2),bounds.getInt(3),
                r.getLong("captured_elapsed_ms"),r.getBoolean("nodes_truncated"),complete,nodes,window.getInt("type"),
                "observed".equals(window.getString("metadata_status")),ownership,capture);
    }

    private static JSONObject originalAction,originalOutcome;
    private interface Edit {void apply(Map<String,Object> execution);}
    private static void rejects(Work work,String why)throws Exception{
        assertions++;try{work.run();}catch(IllegalArgumentException|IllegalStateException|ActionDecision.InvalidActionException expected){return;}
        throw new AssertionError(why);
    }
    private static final class Selection implements BackgroundTaskTarget.SelectionBinding {
        final BackgroundTaskTarget target;
        Selection(ProfileTarget profile){target=BackgroundTaskTarget.resolveExplicitSelection(OWNER,NativeAppGoal.XIAOMI_PACKAGE,
                Collections.singleton(NativeAppGoal.XIAOMI_PACKAGE),profile);}
        public BackgroundTaskTarget executionTarget(){return target;}
    }
    private static final class Fixture {
        final ProfileTarget profile=target();final Selection selection=new Selection(profile);
        final TaskAuthorization auth=TaskAuthorization.parse(OWNER).forExecutionSelection(selection);
        final String task=binding.getString("task_id"),generation=before.getJSONObject("background_session").getString("generation");
        final String selectionSha=hash("explicit-host-selection:"+selection.target.targetSha256);
        final TaskAuthorization.Gate owner=auth.bind(task);
        final Map<String,Map<String,Object>> records=new LinkedHashMap<String,Map<String,Object>>();
        final NativeAppSession session;final int display=before.getJSONObject("window").getInt("display_id");
        NativeAppEvidence.Frame current;ActionDecision proposed;String run;
        boolean failOutcome,installedCurrent=true;
        final long started=originalOutcome.getJSONObject("attempt").getLong("dispatch_started_elapsed_ms");
        final long finished=originalOutcome.getJSONObject("attempt").getLong("dispatch_finished_elapsed_ms");
        Fixture()throws Exception {
            session=new NativeAppSession(task,owner,selection,new NativeAppEvidence.Installed(profile),selectionSha,generation,display,
                ()->{if(!installedCurrent)throw new IllegalStateException("explicit host installation mismatch");},
                (leaf,value)->{if(failOutcome&&leaf.startsWith("native-app-outcome-"))throw new java.io.IOException("explicit host journal failure");
                    records.put(leaf,NativeAppEvidence.immutableMap(value));});
            observe(before);
        }
        NativeAppEvidence.Frame rebound(JSONObject raw){
            NativeAppEvidence.Frame f=frame(raw); // Validates exact original sealed AX receipt and profile proof.
            // A detached host context is necessary because its explicit Selection is not the
            // phone's private automatic Start object. Only these labelled host bindings change.
            return new NativeAppEvidence.Frame(task,auth.instructionSha256,selection.target.targetSha256,auth.sha256,selectionSha,
                f.observationId,f.packageName,f.generation,f.treeSha,f.stateSha,hash("explicit-host-pixel-placeholder:"+f.observationId),
                hash("explicit-host-context:"+auth.sha256+":"+f.sourceRecordSha),hash("explicit-host-completion:"+f.observationId),
                f.displayId,f.windowId,f.rotation,f.width,f.height,f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,
                f.nodesTruncated,f.collectionComplete,f.nodes,f.windowType,f.metadataObserved,f.profileWindow);
        }
        void observe(JSONObject raw)throws Exception{NativeAppEvidence.Frame f=rebound(raw);session.observed(f);current=f;}
        void begin()throws Exception {
            proposed=ActionDecision.parse(originalAction.getJSONObject("action").toString(),ActionDecision.IME_ACTION_SCHEMA);
            run=originalAction.getString("model_run_id");owner.check(proposed,run);
            session.beforeModelAction(3,proposed,run,started);
        }
        Map<String,Object> execution(){
            Map<String,Object> x=map(copy(originalAction.getJSONObject("action_execution")));
            // Same original timeline, IDs, effect/drain and callback facts; only the explicit host auth binding differs.
            x.put("authorization_sha256",auth.sha256);return x;
        }
        void outcome(Map<String,Object> x,long at)throws Exception {
            session.modelActionOutcome(proposed,run,false,false,true,hash(originals.get("step-03-action-derived.json")),at,x);
        }
        void outcome(Map<String,Object> x)throws Exception{outcome(x,finished);}
        Map<?,?> receipt(){Map<?,?> a=(Map<?,?>)records.get("native-app-outcome-01.json").get("attempt");return (Map<?,?>)a.get("actual_action_receipt");}
        boolean available(){return session.domain().purposes.containsValue("submit_product_query");}
        ActionDecision newDecision(String observation)throws Exception {
            return ActionDecision.parse(new JSONObject().put("action","click").put("observation_id",observation)
                .put("package",NativeAppGoal.XIAOMI_PACKAGE).put("node_id","n2").put("node_label","搜索").toString(),ActionDecision.IME_ACTION_SCHEMA);
        }
        void noResult(){check(!session.domain().resultReady&&session.resultRecord()==null,"reservation release is not a product result");}
        void projectionAgrees(){Map<?,?> view=(Map<?,?>)session.domain().promptEvidence().get("provider");
            check(new TreeSet<Object>((List<?>)view.get("click_node_ids")).equals(new TreeSet<Object>(session.domain().clickIds)),
                "provider targets must equal the actual domain");
            check(view.get("edit_values").equals(session.domain().editValues)&&view.get("purposes").equals(session.domain().purposes),
                "provider edit and purpose projections must equal the actual domain");
        }
    }
    private static void retained(String name,Edit edit){
        one(name,()->{Fixture f=new Fixture();f.begin();Map<String,Object> x=f.execution();edit.apply(x);f.outcome(x);
            check(!Boolean.TRUE.equals(f.receipt().get("product_query_reservation_released")),"uncertain or foreign receipt must retain the reservation");
            f.observe(after);check(!f.available(),"no current query target after unproved release");f.projectionAgrees();f.noResult();});
    }
    private static void cases()throws Exception {
        one("actual_e7ef24_unentered_stale_remains_historical_failure",()->{
            check(!originalAction.getBoolean("accepted")&&!originalAction.getBoolean("dispatched")&&originalAction.getBoolean("stale"),
                "actual step3 remains refused");
            JSONObject source=originalAction.getJSONObject("fixture_source");
            check(source.getBoolean("private_original_unchanged")&&source.getBoolean("consumed_action_and_execution_values_unchanged")
                &&source.getString("original_sha256").equals(originalOutcome.getJSONObject("attempt").getJSONObject("actual_action_receipt").getString("step_action_record_sha256")),
                "derived action preserves the recorded private original identity and exact consumed fields");
            check(!originalAction.has("background_session")&&!originalAction.has("task_authorization")&&!originalAction.has("qualification_scope")
                &&!source.getBoolean("background_session_published"),"unrelated encoded display and runtime metadata are not published");
            JSONObject x=originalAction.getJSONObject("action_execution"),d=x.getJSONObject("freshness_diagnostic");
            check(!x.getBoolean("effect_entered")&&!x.getBoolean("effect_returned")&&x.getBoolean("worker_drained"),
                "actual worker drained without any business effect");
            check("whole_graph_stale_rejected".equals(d.getString("guard_result"))&&!d.getBoolean("guard_changed")
                &&!d.getBoolean("app_tree_equal")&&d.getBoolean("selected_stamp_equal"),"unchanged target did not bypass changing whole graph");
            check(!originalOutcome.getJSONObject("attempt").getJSONObject("actual_action_receipt").getBoolean("query_reservation_released"),
                "original failed receipt is never rewritten");
            check(frame(before).sourceRecordSha.equals(hash(originals.get("step-03-before.json")))
                &&frame(after).sourceRecordSha.equals(hash(originals.get("step-04-before.json"))),"both actual sealed frame originals remain byte bound");
        });
        one("actual_unentered_stale_releases_only_query_reservation_after_durable_outcome",()->{
            Fixture f=new Fixture();f.begin();f.outcome(f.execution());
            check(Boolean.TRUE.equals(f.receipt().get("product_query_reservation_released")),"actual unentered Xiaomi query reservation must be released");
            Map<?,?> proof=(Map<?,?>)f.receipt().get("product_query_reservation_release");
            check(proof!=null&&Boolean.FALSE.equals(proof.get("automatic_redispatch"))&&Boolean.FALSE.equals(proof.get("business_verified")),
                "release supplies neither redispatch nor completion");
            check(((Number)((Map<?,?>)f.session.evidence().get("progress")).get("actual_model_actions")).intValue()==1,"model action budget remains consumed");
            f.noResult();
        });
        one("fresh_actual_frame_restores_search_target_and_requires_new_model_decision",()->{
            Fixture f=new Fixture();NativeAppEvidence.Frame old=f.current;f.begin();f.outcome(f.execution());
            rejects(()->f.session.observed(old),"old observation cannot be reused");
            rejects(()->f.session.beforeModelAction(4,f.proposed,hash("new-run-old-frame").substring(0,32),f.finished+1),"new run cannot reuse old frame");
            f.observe(after);check(f.available()&&f.session.domain().clickIds.equals(Collections.singleton("n2")),
                "actual new complete search_submit frame exposes only current normal search");
            f.projectionAgrees();f.noResult();
            ActionDecision next=f.newDecision(f.current.observationId);String nextRun=hash("explicit-host-new-model-run").substring(0,32);
            f.owner.check(next,nextRun);f.session.beforeModelAction(4,next,nextRun,f.current.capturedElapsedMs+1);
            check(next!=f.proposed&&!next.observationId.equals(f.proposed.observationId),"new action and fresh frame required");
            check(((Number)((Map<?,?>)f.session.evidence().get("progress")).get("actual_model_actions")).intValue()==2,"new model action spends another budget slot");
        });
        one("old_model_run_remains_consumed_after_fresh_frame",()->{
            Fixture f=new Fixture();f.begin();f.outcome(f.execution());f.observe(after);
            rejects(()->f.session.beforeModelAction(4,f.newDecision(f.current.observationId),f.run,f.current.capturedElapsedMs+1),"old model run cannot be replayed");
        });
        one("boolean_only_outcome_cannot_release_xiaomi_query",()->{
            Fixture f=new Fixture();f.begin();f.session.modelActionOutcome(f.proposed,f.run,false,false,true,
                hash(originals.get("step-03-action-derived.json")),f.finished);
            f.observe(after);check(!f.available(),"legacy booleans do not prove no effect");f.projectionAgrees();
        });
        one("expired_action_cannot_release_xiaomi_query",()->{
            Fixture f=new Fixture();f.begin();Map<String,Object> x=f.execution();
            f.outcome(x,((Number)x.get("deadline_elapsed_ms")).longValue());
            check(!Boolean.TRUE.equals(f.receipt().get("product_query_reservation_released")),"original action deadline is not extended");
            f.observe(after);check(!f.available(),"late outcome keeps the reservation");f.projectionAgrees();
        });
        one("outcome_journal_failure_keeps_inflight_barrier",()->{
            Fixture f=new Fixture();f.begin();f.failOutcome=true;boolean failed=false;
            try{f.outcome(f.execution());}catch(java.io.IOException expected){failed=true;}
            check(failed&&!f.records.containsKey("native-app-outcome-01.json"),"no release before durable journal");
            rejects(()->f.observe(after),"uncommitted outcome cannot advance frame");
        });
        one("fresh_frame_installation_mismatch_is_still_refused",()->{
            Fixture f=new Fixture();f.begin();f.outcome(f.execution());f.installedCurrent=false;
            rejects(()->f.observe(after),"release cannot bypass current installed identity");
        });
        one("session_retirement_still_stops_new_observation",()->{
            Fixture f=new Fixture();f.begin();f.outcome(f.execution());f.session.retire();
            rejects(()->f.observe(after),"Stop cannot be revived by reservation release");
        });
        for(String key:Arrays.asList("task_id","model_run_id","observation_id","authorization_sha256","background_generation")){
            final String field=key;retained("foreign_"+field+"_cannot_release",x->x.put(field,hash("foreign:"+field)));
        }
        for(String key:Arrays.asList("display_id","window_id")){
            final String field=key;retained("foreign_"+field+"_cannot_release",x->x.put(field,999));
        }
        retained("main_display_cannot_release",x->x.put("display_id",0));
        retained("cover_display_cannot_release",x->x.put("display_id",1));
        retained("entered_effect_cannot_release",x->x.put("effect_entered",true));
        retained("returned_effect_cannot_release",x->x.put("effect_returned",true));
        retained("accepted_api_cannot_release",x->x.put("api_accepted",true));
        retained("missing_api_state_cannot_release",x->x.remove("api_accepted"));
        retained("undrained_worker_cannot_release",x->x.put("worker_drained",false));
        retained("unpublished_callback_cannot_release",x->x.put("callback_published",false));
        retained("retired_authority_cannot_release",x->x.put("callback_authority_current",false));
        retained("retired_action_cannot_release",x->x.put("retired",true));
        retained("automatic_redispatch_cannot_release",x->x.put("automatic_redispatch",true));
        retained("foreign_guard_cannot_release",x->x.put("native_action_guard",Collections.singletonMap("state",0)));
        retained("invalid_operation_id_cannot_release",x->x.put("operation_id","invalid"));
        retained("too_long_original_deadline_cannot_release",x->x.put("deadline_elapsed_ms",((Number)x.get("queued_elapsed_ms")).longValue()+8001));
        retained("drain_after_outcome_cannot_release",x->x.put("worker_drained_elapsed_ms",
            originalOutcome.getJSONObject("attempt").getLong("dispatch_finished_elapsed_ms")+1));
    }
    public static void main(String[] args)throws Exception{
        root=Paths.get(args[0]);JSONObject provenance=new JSONObject(new String(Files.readAllBytes(root.resolve("PROVENANCE.json")),StandardCharsets.UTF_8));
        for(Object entry:provenance.getJSONArray("files")){
            JSONObject r=(JSONObject)entry;byte[] raw=Files.readAllBytes(root.resolve(r.getString("path")));
            if(raw.length!=r.getLong("bytes")||!hash(raw).equals(r.getString("sha256")))throw new IllegalArgumentException("original fixture bytes differ");
            originals.put(r.getString("path"),raw);
        }
        before=new JSONObject(new String(originals.get("step-03-before.json"),StandardCharsets.UTF_8));
        after=new JSONObject(new String(originals.get("step-04-before.json"),StandardCharsets.UTF_8));
        binding=new JSONObject(new String(originals.get("native-app-binding.json"),StandardCharsets.UTF_8));
        originalAction=new JSONObject(new String(originals.get("step-03-action-derived.json"),StandardCharsets.UTF_8));
        originalOutcome=new JSONObject(new String(originals.get("native-app-outcome-03.json"),StandardCharsets.UTF_8));
        cases();boolean passed=true;for(Map<String,Object> result:results)passed&=Boolean.TRUE.equals(result.get("passed"));
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("schema","hepta.native-xiaomi-query-reservation-host.v1");
        report.put("all_pass",passed);report.put("cases",results.size());report.put("case_names",names);report.put("assertions",assertions);report.put("results",results);
        report.put("actual_fixture_sha256_bound",true);report.put("original_failed_receipt_unchanged",true);
        report.put("host_selection_authorization_binding_synthetic",true);report.put("original_node_and_execution_facts_preserved",true);
        report.put("phone_operations",0);report.put("android_dispatch",false);report.put("business_verified",false);
        Files.write(Paths.get(args[1]),new JSONObject(report).toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(new JSONObject(report).toString());
        if(!passed)System.exit(1);
    }
}
