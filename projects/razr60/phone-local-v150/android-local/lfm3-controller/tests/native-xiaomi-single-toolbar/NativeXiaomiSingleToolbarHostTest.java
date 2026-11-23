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
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** The positive source is the complete archived native AX receipt and its 58
 * published nodes, not a hand-written toolbar. Its original profile and capture
 * values remain historical data. No current Android authority is reconstructed.
 * Negative mutations and the conditional query-readback case use the legacy
 * pure Frame port with an explicitly synthetic pixel hash; they are not new
 * native receipts, screenshots, model executions, inputs or completion proofs. */
public final class NativeXiaomiSingleToolbarHostTest {
    private static final String[] KEYS={"owner","frame","native_ax"};
    private static final String[] HASHES={
        "b517dba7b04680d8934f185c9f7a5466d24837bace01114b2ef8df09eeed6c09",
        "be47773986e53bd1f63cc676305cc6c123de43faca90cf39a5a1d3774275091f",
        "100c6206ec8d06345a0daa0f0e7b25bfdb1090540f39a0c1811c383058fdbccf"};
    private static final int[] SIZES={9323,100079,234378};
    private static final String[] ANCHORS={"0/0","0/1","0/2","0/1/0","0/1/1","0/1/2","0/1/2/0"};
    private static final List<String> names=new ArrayList<String>();
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private static JSONObject original,ax,binding;
    private static byte[] originalAx;
    private static NativeAppGoal goal;
    private static int assertions;
    private interface Work {void run()throws Exception;}
    private interface Change {void apply(JSONObject r)throws Exception;}
    private static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void one(String name,Work work){
        if(names.contains(name))throw new IllegalArgumentException("duplicate case");names.add(name);
        Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{work.run();row.put("passed",true);}catch(Throwable failure){row.put("passed",false);row.put("failure",failure.toString());}
        results.add(row);
    }
    private static String hash(String value){return NativeAppEvidence.hash(value);}
    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    private static JSONObject at(JSONObject r,String path){
        JSONArray nodes=r.getJSONArray("nodes");for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);if(path.equals(n.getJSONObject("native_tree_position").getString("path")))return n;
        }throw new IllegalArgumentException("fixture native path absent");
    }
    private static void remove(JSONObject r,String path){
        JSONArray nodes=r.getJSONArray("nodes");for(int i=0;i<nodes.length();i++){
            if(path.equals(nodes.getJSONObject(i).getJSONObject("native_tree_position").getString("path"))){
                nodes.remove(i);r.getJSONObject("collection").put("retained_nodes",nodes.length());return;
            }
        }throw new IllegalArgumentException("fixture native path absent");
    }
    private static void extra(JSONObject r,JSONObject node){
        r.getJSONArray("nodes").put(node);r.getJSONObject("collection").put("retained_nodes",r.getJSONArray("nodes").length());
    }
    private static WindowOwnership profile(JSONObject r){
        JSONObject bg=r.getJSONObject("background_session"),w=bg.getJSONObject("actual_profile_window");
        ProfileTarget t=ProfileTarget.fromWire(bg.getString("profile_target_wire"));
        WindowOwnership p=new WindowOwnership(t,w.getString("generation"),w.getInt("display_id"),w.getInt("window_id"),
                w.getInt("task_id"),w.getInt("parent_task_id"),w.getString("task_token_id"),w.getString("proof_id"),
                w.getInt("user_id"),w.getLong("user_serial"),w.getInt("full_uid"),w.getLong("observed_elapsed_ms"),w.getLong("expires_elapsed_ms"));
        assertions++;NativeAppEvidence.need(t.sha256.equals(bg.getString("profile_target_sha256"))&&p.sha256.equals(w.getString("proof_sha256")),
                "unchanged historical profile values, not a fresh ownership proof");
        return p;
    }
    private static NativeAppEvidence.Frame frame(JSONObject r,boolean actual){
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();JSONArray rows=r.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i),pos=n.getJSONObject("native_tree_position"),sel=n.getJSONObject("native_selection_state");
            JSONArray b=n.getJSONArray("bounds");String text=n.optString("text",""),desc=n.optString("description","");
            String label=ObservedTargetLabels.project(!text.isEmpty()?text:!desc.isEmpty()?desc:n.optString("child_text",""));
            Boolean selected=sel.optBoolean("observed")?Boolean.valueOf(sel.getBoolean("selected")):null;
            TreeSet<String> directions=new TreeSet<String>();JSONArray ds=n.optJSONArray("scroll_directions");
            if(ds!=null)for(int k=0;k<ds.length();k++)directions.add(ds.getString(k));
            nodes.add(new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),
                text,desc,pos.getString("path"),pos.getString("parent_class"),n.optString("node_app_tree_sha256",""),label,
                b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),n.optBoolean("enabled",true),n.optBoolean("password"),
                n.optBoolean("clickable"),n.optBoolean("editable"),n.optBoolean("scrollable"),selected,
                selected==null?null:Boolean.valueOf(sel.getBoolean("checkable")),selected==null?null:Boolean.valueOf(sel.getBoolean("checked")),directions));
        }
        JSONObject window=r.getJSONObject("window"),collection=r.getJSONObject("collection"),bg=r.getJSONObject("background_session");
        JSONArray b=window.getJSONArray("bounds");boolean complete=collection.getInt("retained_nodes")==nodes.size()
                &&collection.getInt("pending_nodes_at_stop")==0&&collection.getLong("child_slots_omitted_by_traversal_limit")==0
                &&collection.getInt("nodes_omitted_by_node_limit")==0&&collection.getInt("nodes_omitted_by_text_limit")==0;
        ObservationCaptureEvidence capture=actual?ObservationCaptureEvidence.fromSealedNativeAx(ax.toMap(),originalAx,HASHES[2]):null;
        return new NativeAppEvidence.Frame(binding.getString("task_id"),binding.getString("owner_sha256"),binding.getString("execution_target_sha256"),
                binding.getString("task_authorization_sha256"),binding.getString("actual_selection_sha256"),r.getString("observation_id"),r.getString("package"),bg.getString("generation"),
                r.getString("app_tree_sha256"),r.getString("observation_state_sha256"),actual?null:hash("explicit host mutant Frame pixel-port value"),
                actual?HASHES[1]:hash("explicit host mutant:"+r.toString()),hash("explicit host completion-port value"),
                window.getInt("display_id"),r.getInt("window_id"),r.getInt("rotation"),r.getInt("screen_width"),r.getInt("screen_height"),
                b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),r.getLong("captured_elapsed_ms"),r.getBoolean("nodes_truncated"),complete,
                nodes,window.getInt("type"),"observed".equals(window.getString("metadata_status")),profile(r),capture);
    }
    private static NativeXiaomiProductPage.Page inspect(JSONObject r){return NativeXiaomiProductPage.inspect(goal,frame(r,false));}
    private static void inputOnly(NativeXiaomiProductPage.Page p,String id){
        check("search_input".equals(p.phase)&&p.missing.isEmpty(),"new complete shape recognized");
        String literal=goal.immutableOwner.substring(goal.modelStartUtf16,goal.modelEndUtf16);
        check(p.editValues.equals(Collections.singletonMap(id,literal)),"only exact immutable owner substring");
        check(p.purposes.equals(Collections.singletonMap(id,"set_product_query")),"real enabled query field only");
        check(p.clickIds.isEmpty()&&p.quote==null,"no navigation, submit, recommendation or result authority");
    }
    private static void unavailable(JSONObject r){
        try{NativeXiaomiProductPage.Page p=inspect(r);check(p.clickIds.isEmpty()&&p.editValues.isEmpty()&&p.quote==null,"changed closed shape must grant no action or quote");}
        catch(IllegalArgumentException rejected){check(rejected.getMessage()!=null,"actual Frame or provider rejection");}
    }
    private static void mutation(Change change)throws Exception{JSONObject r=copy(original);change.apply(r);unavailable(r);}
    private static void cases()throws Exception{
        one("complete_archived_179_node_pair_and_58_node_frame_grant_only_actual_query_field",()->{
            check(ax.getJSONObject("first").getJSONArray("nodes").length()==179&&ax.getJSONObject("second").getJSONArray("nodes").length()==179,"full original censuses");
            check(original.getJSONArray("nodes").length()==58,"full original published population");
            NativeAppEvidence.Frame f=frame(original,true);inputOnly(NativeXiaomiProductPage.inspect(goal,f),"n5");
            check(f.capture.nativeText()&&f.screenshotSha==null&&f.profileWindow.fullUid==1010485,"actual historic AX/profile fields retained, no synthetic screenshot");
        });
        one("disabled_root_field_toolbar_parent_blank_control_and_label_never_get_authority",()->{
            NativeAppEvidence.Frame f=frame(original,true);NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(goal,f);inputOnly(p,"n5");
            check("0/2".equals(f.byId.get("n2").path)&&!f.byId.get("n2").enabled&&f.byId.get("n2").editable,"real disabled sibling, not row-index path");
            for(String id:Arrays.asList("n0","n1","n2","n4","n6","n17"))check(!p.clickIds.contains(id)&&!p.editValues.containsKey(id),"excluded control has no input authority");
        });
        one("node_ids_and_array_order_are_not_position_selectors",()->{
            JSONObject r=copy(original);JSONArray old=r.getJSONArray("nodes"),reverse=new JSONArray();String field=null;
            for(int i=old.length()-1;i>=0;i--){JSONObject n=old.getJSONObject(i);String id="n"+(100+i);n.put("id",id);reverse.put(n);
                if("0/1/1".equals(n.getJSONObject("native_tree_position").getString("path")))field=id;}
            r.put("nodes",reverse);inputOnly(inspect(r),field);
        });
        one("host_conditional_new_exact_query_readback_offers_only_single_normal_button",()->{
            JSONObject r=copy(original);at(r,"0/1/1").put("text","AX3000T");
            r.put("observation_id","22222222222222222222222222222222").put("captured_elapsed_ms",r.getLong("captured_elapsed_ms")+1);
            NativeXiaomiProductPage.Page p=inspect(r);
            check("search_submit".equals(p.phase)&&p.clickIds.equals(Collections.singleton("n6"))&&p.editValues.isEmpty(),"exact current query text required for the real normal button");
            check(p.purposes.equals(Collections.singletonMap("n6","submit_product_query"))&&p.quote==null,"no suggestion, parent, disabled field or quote fallback");
        });
        one("wrong_case_suffix_or_hint_text_never_counts_as_query_readback",()->{
            for(String text:Arrays.asList("","ax3000t","AX3000T ","数字系列手机电池换新","其他商品")){
                JSONObject r=copy(original);at(r,"0/1/1").put("text",text);inputOnly(inspect(r),"n5");
            }
        });
        one("dynamic_hint_is_only_observed_text_and_cannot_replace_owner_query",()->{
            for(String hint:Arrays.asList("AX3000T","请查询其他商品")){
                JSONObject r=copy(original);at(r,"0/1/0").put("text",hint);at(r,"0/1").put("child_text",hint);inputOnly(inspect(r),"n5");
            }
        });
        one("every_observed_anchor_is_required",()->{for(String path:ANCHORS)mutation(r->remove(r,path));});
        one("real_literal_search_label_cannot_be_replaced_by_parent_derived_text",()->{
            mutation(r->at(r,"0/1/2/0").remove("text"));mutation(r->at(r,"0/1/2/0").put("text","AI搜索"));
            mutation(r->at(r,"0/1/2").put("child_text","AI搜索"));
        });
        one("an_extra_search_label_is_ambiguous_even_if_disabled_or_offscreen",()->{
            for(int kind=0;kind<3;kind++){final int variant=kind;mutation(r->{JSONObject n=copy(at(r,"0/1/2/0")).put("id","n99");
                n.getJSONObject("native_tree_position").put("path","0/8/0");
                if(variant==1)n.put("enabled",false);if(variant==2)n.put("bounds",new JSONArray(Arrays.asList(1300,10,1400,40)));extra(r,n);});}
        });
        one("additional_retained_toolbar_descendant_is_not_ignored",()->{
            mutation(r->{JSONObject n=copy(at(r,"0/1/0")).put("id","n99").put("text","额外控件");n.getJSONObject("native_tree_position").put("path","0/1/3");extra(r,n);});
        });
        one("additional_editable_field_never_borrows_the_disabled_sibling_exception",()->{
            for(boolean enabled:Arrays.asList(Boolean.FALSE,Boolean.TRUE))mutation(r->{JSONObject n=copy(at(r,"0/2")).put("id","n99").put("enabled",enabled);
                n.getJSONObject("native_tree_position").put("path","0/8");extra(r,n);});
        });
        one("disabled_sibling_is_required_disabled_empty_editable_and_direct",()->{
            mutation(r->at(r,"0/2").put("enabled",true));mutation(r->at(r,"0/2").put("text","AX3000T"));
            mutation(r->at(r,"0/2").put("editable",false));mutation(r->at(r,"0/2").put("clickable",false));
            mutation(r->at(r,"0/2").put("bounds",new JSONArray(Arrays.asList(0,130,0,201))));
        });
        one("all_native_anchor_paths_and_parent_classes_are_exact",()->{
            for(String path:ANCHORS){mutation(r->at(r,path).getJSONObject("native_tree_position").put("path","0/9/8"));
                mutation(r->at(r,path).getJSONObject("native_tree_position").put("parent_class","android.widget.LinearLayout"));}
        });
        one("toolbar_cannot_be_transplanted_under_another_native_parent",()->{
            mutation(r->{JSONArray ns=r.getJSONArray("nodes");for(int i=0;i<ns.length();i++){
                JSONObject pos=ns.getJSONObject(i).getJSONObject("native_tree_position");String p=pos.getString("path");
                if(p.equals("0/1")||p.startsWith("0/1/"))pos.put("path","0/7"+p.substring(3));}});
        });
        one("all_anchor_classes_resources_and_descriptions_are_bound",()->{
            for(String path:ANCHORS){mutation(r->at(r,path).put("class_name","android.widget.Button"));
                mutation(r->at(r,path).put("view_id","other:id/control"));mutation(r->at(r,path).put("description","搜索"));}
        });
        one("enabled_clickable_editable_password_and_scroll_flags_are_not_promoted",()->{
            for(String path:ANCHORS){
                if(!"0/2".equals(path))mutation(r->at(r,path).put("enabled",false));
                mutation(r->at(r,path).put("clickable",!at(r,path).optBoolean("clickable")));
                mutation(r->at(r,path).put("editable",!at(r,path).optBoolean("editable")));
                mutation(r->at(r,path).put("password",true));mutation(r->at(r,path).put("scrollable",true));
            }
        });
        one("every_selection_tuple_must_be_observed_and_neutral",()->{
            for(String path:ANCHORS){mutation(r->at(r,path).getJSONObject("native_selection_state").put("observed",false));
                for(String flag:Arrays.asList("selected","checkable","checked"))mutation(r->at(r,path).getJSONObject("native_selection_state").put(flag,true));}
        });
        one("all_anchor_scroll_actions_and_direct_signatures_are_required",()->{
            for(String path:ANCHORS){mutation(r->at(r,path).put("scroll_directions",new JSONArray().put("down")));
                mutation(r->at(r,path).remove("node_app_tree_sha256"));}
        });
        one("no_anchor_can_escape_the_actual_window_or_have_empty_bounds",()->{
            for(String path:ANCHORS){mutation(r->at(r,path).put("bounds",new JSONArray(Arrays.asList(-1,130,50,201))));
                mutation(r->at(r,path).put("bounds",new JSONArray(Arrays.asList(1,130,1,201))));}
        });
        one("toolbar_field_hint_button_and_real_label_geometry_remain_constrained",()->{
            mutation(r->at(r,"0/1/1").getJSONArray("bounds").put(0,125));
            mutation(r->at(r,"0/1/0").getJSONArray("bounds").put(0,166));
            mutation(r->at(r,"0/1/0").getJSONArray("bounds").put(2,980));
            mutation(r->at(r,"0/1/2").getJSONArray("bounds").put(2,990));
            mutation(r->at(r,"0/1/2/0").getJSONArray("bounds").put(0,990));
            mutation(r->at(r,"0/1/2/0").getJSONArray("bounds").put(2,1180));
            mutation(r->at(r,"0/0").getJSONArray("bounds").put(2,127));
            mutation(r->at(r,"0/2").getJSONArray("bounds").put(2,60));
        });
        one("foreign_packages_and_nonfullscreen_or_nonapplication_windows_are_denied",()->{
            mutation(r->at(r,"0/1/1").put("package","other.app"));mutation(r->r.put("package","other.app"));
            mutation(r->r.getJSONObject("window").put("type",2));mutation(r->r.getJSONObject("window").put("metadata_status","unknown"));
            mutation(r->r.getJSONObject("window").getJSONArray("bounds").put(1,1));mutation(r->r.getJSONObject("window").put("display_id",0));
        });
        one("incomplete_or_truncated_collection_never_grants_new_toolbar",()->{
            mutation(r->r.put("nodes_truncated",true));
            for(String field:Arrays.asList("pending_nodes_at_stop","child_slots_omitted_by_traversal_limit","nodes_omitted_by_node_limit","nodes_omitted_by_text_limit"))
                mutation(r->r.getJSONObject("collection").put(field,1));
        });
        one("immutable_goal_owner_cannot_be_replaced_by_same_shape",()->{
            boolean rejected=false;try{NativeXiaomiProductPage.inspect(NativeAppGoal.parse("请在小米商城查询AX3000T价格",NativeAppGoal.XIAOMI_PACKAGE),frame(original,true));}
            catch(IllegalArgumentException expected){rejected=true;}check(rejected,"exact historical owner hash retained");
        });
        one("profile_user_uid_window_generation_and_expiry_are_not_relaxed",()->{
            for(String field:Arrays.asList("user_id","full_uid","window_id"))mutation(r->{JSONObject p=r.getJSONObject("background_session").getJSONObject("actual_profile_window");p.put(field,p.getInt(field)+1);});
            mutation(r->r.getJSONObject("background_session").put("generation","11111111-1111-1111-1111-111111111111"));
            mutation(r->r.put("captured_elapsed_ms",r.getJSONObject("background_session").getJSONObject("actual_profile_window").getLong("expires_elapsed_ms")));
        });
        one("complete_native_ax_original_bytes_and_binding_are_checked",()->{
            boolean rejected=false;try{ObservationCaptureEvidence.fromSealedNativeAx(ax.toMap(),originalAx,hash("other receipt"));}
            catch(IllegalArgumentException expected){rejected=true;}check(rejected,"actual complete byte digest required");
            JSONObject bad=copy(ax);bad.getJSONObject("second").put("pending",1);rejected=false;
            try{ObservationCaptureEvidence.fromSealedNativeAx(bad.toMap(),originalAx,HASHES[2]);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"partial census cannot masquerade as original complete pair");
        });
        one("page_evidence_is_immutable_and_keeps_all_authority_flags_false",()->{
            NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(goal,frame(original,true));Map<String,Object> e=p.evidence();
            for(String key:Arrays.asList("dispatch_authority","query_dispatched","task_completion_authority","order_submitted","installed_identity_verified_here"))check(Boolean.FALSE.equals(e.get(key)),"provider facts are not authority");
            boolean rejected=false;try{p.editValues.put("n2","AX3000T");}catch(UnsupportedOperationException expected){rejected=true;}check(rejected,"edit facts immutable");
            rejected=false;try{e.put("task_completion_authority",true);}catch(UnsupportedOperationException expected){rejected=true;}check(rejected,"record immutable");
        });
    }
    public static void main(String[] args)throws Exception{
        JSONObject refs=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8)).getJSONObject("files");
        byte[][] raws=new byte[3][];
        for(int i=0;i<KEYS.length;i++){JSONObject ref=refs.getJSONObject(KEYS[i]);raws[i]=Files.readAllBytes(Paths.get(ref.getString("path")));
            check(raws[i].length==SIZES[i]&&ObservationCaptureEvidence.hash(raws[i]).equals(HASHES[i])
                    &&ref.getLong("bytes")==SIZES[i]&&HASHES[i].equals(ref.getString("sha256")),"exact full external source bytes");}
        JSONObject owner=new JSONObject(new String(raws[0],StandardCharsets.UTF_8));
        goal=NativeAppGoal.parse(owner.getString("instruction"),NativeAppGoal.XIAOMI_PACKAGE);
        original=new JSONObject(new String(raws[1],StandardCharsets.UTF_8));originalAx=raws[2];ax=new JSONObject(new String(originalAx,StandardCharsets.UTF_8));binding=ax.getJSONObject("binding");
        check(goal.ownerSha256.equals(binding.getString("owner_sha256"))&&goal.ownerSha256.equals(owner.getString("instruction_utf8_sha256")),"actual immutable owner is read from original, never screen text");
        cases();boolean pass=true;for(Map<String,Object> row:results)pass&=Boolean.TRUE.equals(row.get("passed"));
        JSONObject result=new JSONObject().put("schema","hepta.native-xiaomi-single-toolbar-host.v1").put("all_pass",pass)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",names).put("results",results)
                .put("fixture_sha256",new JSONArray(Arrays.asList(HASHES))).put("source_bytes_modified",false)
                .put("actual_complete_historical_ax_receipt_validated",true).put("positive_node_values_and_profile_facts_preserved",true)
                .put("completion_binding_is_explicit_host_port",true).put("mutants_are_explicit_host_frames_not_android_proofs",true)
                .put("current_android_ownership_qualified",false).put("android_runtime",false).put("phone_operations",0)
                .put("model_executed",false).put("platform_dispatch_executed",false).put("business_verified",false);
        Files.write(Paths.get(args[1]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("SINGLE_TOOLBAR cases="+names.size()+" assertions="+assertions+" all_pass="+pass);
        if(!pass)throw new AssertionError("single toolbar regression failed; full case results preserved");
    }
}
