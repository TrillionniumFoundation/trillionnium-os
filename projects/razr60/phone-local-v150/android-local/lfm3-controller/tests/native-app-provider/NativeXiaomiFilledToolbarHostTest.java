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

/** Original bounded AX records and actual sealed capture bytes. These host tests
 * reconstruct detached facts, never Android node references or dispatch authority.
 * Mutants are labelled host values; their data are never written to originals. */
public final class NativeXiaomiFilledToolbarHostTest {
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
        String sourceHash=r.toString().equals(before.toString())?hash(originals.get("step-04-before.json"))
                :r.toString().equals(after.toString())?hash(originals.get("step-04-after.json"))
                :hash("explicit-host-mutant-record:"+r.toString());
        return new NativeAppEvidence.Frame(b.getString("task_id"),b.getString("owner_sha256"),b.getString("execution_target_sha256"),
                b.getString("task_authorization_sha256"),b.getString("actual_selection_sha256"),r.getString("observation_id"),
                r.getString("package"),background.getString("generation"),r.getString("app_tree_sha256"),r.getString("observation_state_sha256"),
                null,sourceHash,hash("explicit-host-completion-only"),window.getInt("display_id"),r.getInt("window_id"),r.getInt("rotation"),
                r.getInt("screen_width"),r.getInt("screen_height"),bounds.getInt(0),bounds.getInt(1),bounds.getInt(2),bounds.getInt(3),
                r.getLong("captured_elapsed_ms"),r.getBoolean("nodes_truncated"),complete,nodes,window.getInt("type"),
                "observed".equals(window.getString("metadata_status")),ownership,capture);
    }
    private static NativeXiaomiProductPage.Page inspect(JSONObject r){return NativeXiaomiProductPage.inspect(GOAL,frame(r));}
    private static void unavailable(JSONObject r){
        try{NativeXiaomiProductPage.Page p=inspect(r);
            check(p.editValues.isEmpty()&&p.clickIds.isEmpty()&&p.quote==null,"mutant must grant no candidate action or quote");
        }catch(IllegalArgumentException expected){check(expected.getMessage()!=null,"explicit malformed/mismatched frame refusal");}
    }
    private static void mutation(String name,Change change){one(name,()->{JSONObject r=copy(after);change.apply(r);unavailable(r);});}
    private static void submitOnly(NativeXiaomiProductPage.Page p){
        check("search_submit".equals(p.phase),"real filled toolbar must reach search_submit");
        check(p.clickIds.equals(Collections.singleton("n2"))&&p.editValues.isEmpty(),"only actual normal search n2");
        check(p.purposes.equals(Collections.singletonMap("n2","submit_product_query"))&&p.quote==null,"no toggle, Back, suggestion or quote");
        check(Boolean.FALSE.equals(p.evidence().get("dispatch_authority"))
                &&Boolean.FALSE.equals(p.evidence().get("query_dispatched"))&&Boolean.FALSE.equals(p.evidence().get("task_completion_authority")),
                "candidate classification never creates dispatch/query/completion");
    }
    private static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject s){
        List<NativeActionSnapshotCheck.Node> ns=new ArrayList<NativeActionSnapshotCheck.Node>();JSONArray a=s.getJSONArray("nodes");
        for(int i=0;i<a.length();i++)ns.add(new NativeActionSnapshotCheck.Node(map(a.getJSONObject(i))));
        return new NativeActionSnapshotCheck.Snapshot(map(s.getJSONObject("envelope")),ns);
    }
    private static void cases()throws Exception{
        one("actual_empty_frame_and_sealed_history_still_offer_only_exact_query",()->{
            NativeAppEvidence.Frame f=frame(before);
            check(f.sourceRecordSha.equals(hash(originals.get("step-04-before.json"))),"exact original empty observation bytes bound");
            NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,f);
            check("search_input".equals(p.phase)&&p.editValues.equals(Collections.singletonMap("n1","AX3000T"))
                    &&p.clickIds.isEmpty()&&p.quote==null,"original empty page unchanged");
        });
        one("actual_filled_frame_and_sealed_AX_offer_only_normal_search_n2",()->{
            NativeAppEvidence.Frame f=frame(after);
            check(f.sourceRecordSha.equals(hash(originals.get("step-04-after.json"))),"exact original filled observation bytes bound");
            submitOnly(NativeXiaomiProductPage.inspect(GOAL,f));
        });
        one("actual_filled_controls_preserve_literal_sources_and_exclude_mode_back_and_card",()->{
            NativeAppEvidence.Frame f=frame(after);NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,f);submitOnly(p);
            check("0/2".equals(f.byId.get("n2").path)&&"0/2/0".equals(at(after,"0/2/0").getJSONObject("native_tree_position").getString("path"))
                    &&"搜索".equals(at(after,"0/2/0").getString("text")),"actual normal button + direct literal TextView");
            check("AX3000T".equals(f.byId.get("n1").text)&&"0/0".equals(f.byId.get("n0").path),"typed query and mode toggle preserved");
            check(!p.clickIds.contains(at(after,"0/3").getString("id"))&&!p.clickIds.contains(at(after,"0/4").getString("id")),"blank Back and current card not offered");
            check(p.evidence().toString().contains("direct_root_framelayout_filled"),"distinct filled shape recorded");
        });
        one("actual_first_input_rejection_keeps_complete_census_guard",()->{
            JSONObject action=new JSONObject(new String(originals.get("step-03-action.json"),StandardCharsets.UTF_8));
            JSONObject execution=action.getJSONObject("action_execution"),c=execution.getJSONObject("native_action_rejection_census");
            check(!action.getBoolean("accepted")&&!action.getBoolean("dispatched")&&action.getBoolean("stale")
                    &&!execution.getBoolean("effect_entered")&&!execution.getBoolean("effect_returned"),"actual no-effect refusal unchanged");
            boolean refused=false;
            try{NativeXiaomiSearchInputObservation.compare(snapshot(c.getJSONObject("before")),snapshot(c.getJSONObject("fresh")));}
            catch(IllegalArgumentException expected){refused="input window/display/IME/owner/installation/profile differs".equals(expected.getMessage());}
            check(refused,"the original changing census is still refused by actual production guard");
        });
        for(String text:Arrays.asList("","ax3000t","AX3000T ","AX3000","其他商品")){
            final String q=text;mutation("filled_slot_rejects_nonexact_query_"+(text.isEmpty()?"empty":hash(text).substring(0,8)),r->at(r,"0/1").put("text",q));
        }
        mutation("filled_and_old_normal_slots_together_are_ambiguous",r->{
            JSONObject button=copy(at(r,"0/2")).put("id","n900"),label=copy(at(r,"0/2/0")).put("id","n901");
            button.getJSONObject("native_tree_position").put("path","0/4");label.getJSONObject("native_tree_position").put("path","0/4/0");
            remove(r,"0/4");add(r,button);add(r,label);
        });
        mutation("mode_and_normal_geometry_cannot_be_swapped",r->{
            JSONArray a=copy(at(r,"0/0")).getJSONArray("bounds"),b=copy(at(r,"0/2")).getJSONArray("bounds");
            at(r,"0/0").put("bounds",b);at(r,"0/2").put("bounds",a);
        });
        mutation("blank_back_slot_is_never_normal_search_fallback",r->{move(r,"0/3","0/99");move(r,"0/2","0/3");});
        mutation("right_control_with_nonliteral_label_is_refused",r->at(r,"0/2/0").put("text","AI搜索"));
        mutation("missing_normal_TextView_does_not_use_derived_label",r->remove(r,"0/2/0"));
        mutation("normal_label_wrong_child_slot_is_refused",r->move(r,"0/2/0","0/2/1"));
        mutation("normal_label_outside_real_parent_is_refused",r->at(r,"0/2/0").getJSONArray("bounds").put(0,80));
        mutation("normal_search_below_toolbar_is_refused",r->{
            at(r,"0/2").put("bounds",new JSONArray(Arrays.asList(958,500,1142,600)));
            at(r,"0/2/0").put("bounds",new JSONArray(Arrays.asList(999,510,1101,580)));
        });
        mutation("normal_search_not_covering_query_edge_is_refused",r->{
            at(r,"0/2").getJSONArray("bounds").put(2,1070);at(r,"0/2/0").getJSONArray("bounds").put(2,1060);
        });
        mutation("normal_search_disabled_is_refused",r->at(r,"0/2").put("enabled",false));
        mutation("normal_search_nonclickable_is_refused",r->at(r,"0/2").put("clickable",false));
        mutation("normal_search_scroll_capability_is_refused",r->at(r,"0/2").put("scroll_directions",new JSONArray().put("down")));
        mutation("normal_search_unknown_selection_is_refused",r->at(r,"0/2").getJSONObject("native_selection_state").put("observed",false));
        mutation("mode_toggle_selected_is_refused",r->at(r,"0/0").getJSONObject("native_selection_state").put("selected",true));
        mutation("normal_literal_label_interactive_is_refused",r->at(r,"0/2/0").put("clickable",true));
        mutation("foreign_package_cannot_borrow_actual_toolbar",r->at(r,"0/2").put("package","foreign.app"));
        mutation("foreign_parent_cannot_borrow_actual_toolbar",r->at(r,"0/2").getJSONObject("native_tree_position").put("parent_class","android.widget.LinearLayout"));
        mutation("second_editable_field_is_refused",r->{
            JSONObject n=copy(at(r,"0/1")).put("id","n902");n.getJSONObject("native_tree_position").put("path","0/99");add(r,n);
        });
        mutation("incomplete_collection_is_refused",r->r.getJSONObject("collection").put("pending_nodes_at_stop",1));
        mutation("truncated_collection_is_refused",r->r.put("nodes_truncated",true));
        mutation("unknown_window_metadata_is_refused",r->r.getJSONObject("window").put("metadata_status","unknown"));
        mutation("nonapplication_window_is_refused",r->r.getJSONObject("window").put("type",2));
        mutation("main_display_cannot_replace_actual_profile_display",r->r.getJSONObject("window").put("display_id",0));
        mutation("cover_display_cannot_replace_actual_profile_display",r->r.getJSONObject("window").put("display_id",1));
        mutation("different_window_cannot_reuse_original_AX_capture",r->r.put("window_id",2440));
        mutation("different_generation_cannot_reuse_original_AX_capture",r->r.getJSONObject("background_session").put("generation","00000000-0000-4000-8000-000000000001"));
        one("different_immutable_owner_cannot_reuse_actual_frame",()->{
            boolean refused=false;try{NativeXiaomiProductPage.inspect(NativeAppGoal.parse("请在小米商城查询AX3000T价格",NativeAppGoal.XIAOMI_PACKAGE),frame(after));}
            catch(IllegalArgumentException expected){refused=true;}check(refused,"immutable owner remains exact");
        });
    }
    public static void main(String[] args)throws Exception{
        root=Paths.get(args[0]);Path out=Paths.get(args[1]);
        JSONObject provenance=new JSONObject(new String(Files.readAllBytes(root.resolve("PROVENANCE.json")),StandardCharsets.UTF_8));
        JSONArray files=provenance.getJSONArray("files");
        for(int i=0;i<files.length();i++){
            JSONObject row=files.getJSONObject(i);String name=row.getString("path");byte[] raw=Files.readAllBytes(root.resolve(name));
            check(raw.length==row.getInt("bytes")&&hash(raw).equals(row.getString("sha256"))&&row.getBoolean("original_bytes_preserved"),"exact unchanged original fixture");
            if(originals.put(name,raw)!=null)throw new IllegalArgumentException("duplicate original fixture");
        }
        before=new JSONObject(new String(originals.get("step-04-before.json"),StandardCharsets.UTF_8));
        after=new JSONObject(new String(originals.get("step-04-after.json"),StandardCharsets.UTF_8));
        binding=new JSONObject(new String(originals.get("native-app-binding.json"),StandardCharsets.UTF_8));
        cases();boolean passed=true;for(Map<String,Object> row:results)passed&=Boolean.TRUE.equals(row.get("passed"));
        for(Map.Entry<String,byte[]> row:originals.entrySet())check(Arrays.equals(row.getValue(),Files.readAllBytes(root.resolve(row.getKey()))),"original fixture still unchanged");
        JSONObject report=new JSONObject().put("schema","hepta.native-xiaomi-filled-toolbar-host.v1").put("all_pass",passed)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",names).put("results",results)
                .put("actual_observed_node_values_preserved",true).put("actual_typed_AX_receipts_revalidated",true)
                .put("actual_owner_profile_and_capture_bindings_reconstructed",true).put("completion_hash_host_only",true)
                .put("negative_mutations_are_explicit_host_values",true).put("original_fixture_bytes_unchanged",true)
                .put("phone_operations",0).put("android_runtime",false).put("model_executed",false)
                .put("platform_dispatch_executed",false).put("business_verified",false).put("query_execution_verified",false);
        Files.write(out,(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(new JSONObject().put("all_pass",passed).put("cases",names.size()).put("assertions",assertions));
        if(!passed)throw new AssertionError("filled toolbar actual-frame regression failed");
    }
}
