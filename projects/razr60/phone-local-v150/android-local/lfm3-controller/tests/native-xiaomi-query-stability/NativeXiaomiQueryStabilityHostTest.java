package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;

/** Exact original populated search tree plus the first complete successor
 * recording with the same app-tree digest as the rejected worker's fresh tree.
 * These are two recorded trees, not a replay of the original Android worker.
 * All mutations and comparison Intent values are explicitly host-only. */
public final class NativeXiaomiQueryStabilityHostTest {
    private static JSONObject fixture;
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private interface Work {void run()throws Exception;}
    private interface Change {void run(JSONObject value)throws Exception;}
    private NativeXiaomiQueryStabilityHostTest(){}
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    static JSONObject endpoint(String side){return copy(fixture.getJSONObject(side));}
    static JSONObject node(JSONObject value,String path){
        JSONArray nodes=value.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);if(path.equals(n.getString("path")))return n;}
        throw new AssertionError("missing recorded node "+path);
    }
    static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject value){
        List<NativeActionSnapshotCheck.Node> rows=new ArrayList<NativeActionSnapshotCheck.Node>();
        JSONArray nodes=value.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++)rows.add(new NativeActionSnapshotCheck.Node(nodes.getJSONObject(i).toMap()));
        return new NativeActionSnapshotCheck.Snapshot(value.getJSONObject("envelope").toMap(),rows);
    }
    static NativeActionSnapshotCheck.Intent intent(JSONObject original,String path,String literal){
        Map<String,Object> identity=new TreeMap<String,Object>(),env=original.getJSONObject("envelope").toMap();
        for(String k:NativeActionSnapshotCheck.PROFILE_AUTHORITY)identity.put(k,env.get(k));
        JSONObject action=fixture.getJSONObject("original_action"),selected=node(original,path);
        return new NativeActionSnapshotCheck.Intent(NativeActionSnapshotCheck.SUBMIT_QUERY,NativeActionSnapshotCheck.XIAOMI,path,
                selected.getString("label"),selected.getString("ref_signature_sha256"),action.getString("model_run_id"),action.getString("node_id"),
                NativeActionSnapshotCheck.hash("explicit host Intent, no Android capability"),null,identity,
                action.getLong("queued_elapsed_ms"),action.getLong("deadline_elapsed_ms"),literal);
    }
    static Map<String,Object> compare(JSONObject a,JSONObject b){
        return NativeActionSnapshotCheck.compare(intent(a,"0/2","AX3000T"),snapshot(a),snapshot(b),
                b.getJSONObject("envelope").getLong("captured_elapsed_ms")+1);
    }
    static void noAuthority(Map<String,Object> proof){
        for(String k:Arrays.asList("grants_dispatch","grants_action_authority","query_dispatched","business_completion_verified",
                "business_verified","published_pair_is_current_tree_claimed","query_history_proved_by_comparator","provider_frame_constructed","session_observed_called"))
            check(Boolean.FALSE.equals(proof.get(k)),"no authority or completion claim: "+k);
        check(Boolean.TRUE.equals(proof.get("full_census_compared")),"complete original/fresh census");
        check(Boolean.TRUE.equals(proof.get("live_node_chain_window_and_one_effect_recheck_required")),"live reference, windows and one claim still mandatory");
    }
    static void denied(Work work)throws Exception{
        boolean refused=false;try{work.run();}catch(IllegalArgumentException|IllegalStateException expected){refused=true;}
        check(refused,"actual production predicate must refuse");
    }
    static void one(String name,Work work){
        Map<String,Object> row=new TreeMap<String,Object>();row.put("name",name);
        try{work.run();row.put("passed",true);}catch(Throwable failure){row.put("passed",false);row.put("failure",failure.toString());}
        results.add(row);
    }
    static void negative(String name,Change change){
        one(name,()->{JSONObject a=endpoint("before"),b=endpoint("after");change.run(b);denied(()->compare(a,b));});
    }
    static void both(String name,Change change){
        one(name,()->{JSONObject a=endpoint("before"),b=endpoint("after");change.run(a);change.run(b);denied(()->compare(a,b));});
    }
    static void cases(){
        one("recorded_successor_digest_matches_step03_fresh_diagnostic_without_claiming_same_worker",()->{
            JSONObject p=fixture.getJSONObject("provenance");
            check(p.getString("after_app_tree_sha256").equals(p.getString("step03_recorded_fresh_app_tree_sha256")),"exact fresh graph digest");
            check(p.getBoolean("after_is_first_complete_successor_observation")&&!p.getBoolean("after_is_original_worker_census"),"separate recorded census provenance");
            check(!p.getBoolean("node_fields_rewritten")&&!p.getBoolean("same_worker_android_action_replayed"),"raw node values retained, no action replay");
            check(endpoint("before").getJSONArray("nodes").length()==186&&endpoint("after").getJSONArray("nodes").length()==186,"both complete raw populations");
        });
        one("real_rotating_hotwords_preserve_exact_AX3000T_toolbar_and_pass_narrow_candidate",()->{
            Map<String,Object> proof=compare(endpoint("before"),endpoint("after"));noAuthority(proof);
            check("submit_product_query".equals(proof.get("purpose"))&&"0/2".equals(proof.get("target_path")),"actual model button purpose");
            check("AX3000T".equals(proof.get("query_literal"))&&Boolean.FALSE.equals(proof.get("empty_query")),"immutable filled query remains exact");
            check(((List<?>)proof.get("changed_paths")).size()==20,"every actual changed native node accounted");
            for(Object path:(List<?>)proof.get("changed_paths"))check(((String)path).startsWith("0/6/"),"only recorded recommendation branch");
        });
        one("unchanged_complete_tree_still_requires_original_private_guard_and_final_check",()->{
            JSONObject a=endpoint("before"),b=endpoint("before");
            b.getJSONObject("envelope").put("captured_elapsed_ms",endpoint("after").getJSONObject("envelope").getLong("captured_elapsed_ms"));
            Map<String,Object> proof=compare(a,b);noAuthority(proof);check(((List<?>)proof.get("changed_paths")).isEmpty(),"equal-tree candidate remains explicit");
        });
        one("filled_query_does_not_broaden_empty_input_observation_publication",()->{
            denied(()->NativeXiaomiSearchInputObservation.compare(snapshot(endpoint("before")),snapshot(endpoint("after"))));
        });
        one("pure_submit_requires_explicit_original_supported_literal",()->{
            denied(()->intent(endpoint("before"),"0/2",null));denied(()->intent(endpoint("before"),"0/2","AX3000"));
        });
        one("mode_toggle_is_not_normal_search_even_with_same_search_label",()->{
            JSONObject a=endpoint("before"),b=endpoint("after");
            denied(()->NativeActionSnapshotCheck.compare(intent(a,"0/0","AX3000T"),snapshot(a),snapshot(b),
                    b.getJSONObject("envelope").getLong("captured_elapsed_ms")+1));
        });
        negative("changed_query_text_refused",b->node(b,"0/1").put("text","AX3000"));
        both("wrong_query_on_both_sides_cannot_be_self_consistent_authority",b->{
            node(b,"0/1").put("text","AX3000").put("label","AX3000").put("input_sha256",ObservedImeEnter.completeTextHash("AX3000"));});
        negative("changed_query_full_input_hash_refused",b->node(b,"0/1").put("input_sha256",NativeActionSnapshotCheck.hash("wrong")));
        negative("query_focus_changed_refused",b->node(b,"0/1").put("focused",true));
        negative("query_disabled_refused",b->node(b,"0/1").put("enabled",false));
        negative("query_hidden_refused",b->node(b,"0/1").put("visible",false));
        negative("selected_button_same_path_moved_refused",b->node(b,"0/2").put("bounds",new JSONArray(Arrays.asList(959,333,1143,421))));
        negative("selected_button_reference_changed_refused",b->node(b,"0/2").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("new reference")));
        negative("selected_button_label_changed_refused",b->node(b,"0/2").put("label","立即购买"));
        negative("selected_button_click_capability_removed_refused",b->node(b,"0/2").put("action_click",false));
        negative("literal_search_label_child_changed_refused",b->node(b,"0/2/0").put("text","购买"));
        negative("actual_root_ancestor_geometry_changed_refused",b->{
            node(b,"0").put("bounds",new JSONArray(Arrays.asList(1,0,1224,2992)));
            b.getJSONObject("envelope").put("root_bounds",new JSONArray(Arrays.asList(1,0,1224,2992)));});
        negative("actual_parent_class_changed_refused",b->node(b,"0/2").put("parent_class","android.widget.LinearLayout"));
        negative("static_lower_suggestion_panel_is_not_variable",b->node(b,"0/4/0").put("text","其他商品"));
        negative("static_recommendation_heading_is_not_variable",b->node(b,"0/6/0").put("text","订单"));
        negative("recommendation_capability_change_refused",b->node(b,"0/6/2").put("clickable",false));
        negative("recommendation_editable_injection_refused",b->node(b,"0/6/2/0").put("editable",true));
        negative("recommendation_description_change_refused",b->node(b,"0/6/2").put("description","new semantics"));
        negative("unbound_recommendation_signature_refused",b->node(b,"0/6/2").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("fabricated")));
        negative("recommendation_can_never_move_over_query_or_button",b->node(b,"0/6/2").put("bounds",new JSONArray(Arrays.asList(958,333,1142,421))));
        negative("hidden_reversed_coordinates_cannot_escape_fixed_enclosure",b->node(b,"0/6/11/0").put("bounds",new JSONArray(Arrays.asList(95,986,352,100))));
        negative("whole_recommendation_enclosure_moved_refused",b->node(b,"0/6").put("bounds",new JSONArray(Arrays.asList(0,449,1224,2992))));
        negative("extra_search_label_cannot_change_provider_ambiguity",b->node(b,"0/6/2/0").put("text","搜索"));
        negative("missing_full_child_slot_refused",b->b.getJSONArray("nodes").remove(b.getJSONArray("nodes").length()-1));
        negative("truncated_census_refused",b->b.getJSONObject("envelope").put("node_omissions",1));
        negative("noncomplete_census_refused",b->b.getJSONObject("envelope").put("full_native_complete",false));
        negative("IME_visible_refused",b->b.getJSONObject("envelope").put("ime_visibility","shown"));
        negative("reported_windows_incomplete_refused",b->b.getJSONObject("envelope").put("reported_windows_complete",false));
        negative("new_reported_overlay_refused",b->b.getJSONObject("envelope").put("reported_windows_sha256",NativeActionSnapshotCheck.hash("extra overlay")));
        negative("window_metadata_changed_refused",b->b.getJSONObject("envelope").put("window_metadata_sha256",NativeActionSnapshotCheck.hash("metadata moved")));
        negative("cross_virtual_display_refused",b->b.getJSONObject("envelope").put("display_id",605));
        negative("cross_window_even_with_same_nodes_refused",b->{
            b.getJSONObject("envelope").put("window_id",2497);
            JSONArray rows=b.getJSONArray("nodes");for(int i=0;i<rows.length();i++)rows.getJSONObject(i).put("window_id",2497);});
        negative("cross_profile_user_refused",b->b.getJSONObject("envelope").put("profile_user_id",11).put("profile_full_uid",1110485).put("profile_user_serial",11));
        negative("changed_profile_uid_refused",b->b.getJSONObject("envelope").put("profile_full_uid",1010486));
        for(String key:Arrays.asList("profile_target_sha256","profile_task_token_id","profile_task_id","profile_parent_task_id",
                "installed_set_sha256","authorization_sha256","goal_sha256","background_generation","origin_observation_id")){
            final String k=key;
            negative("changed_binding_"+k+"_refused",b->{
                Object value=k.equals("profile_task_id")?Integer.valueOf(1000084):k.equals("profile_parent_task_id")?Integer.valueOf(1957):
                        k.equals("profile_task_token_id")||k.equals("background_generation")?"ce4531f7-4a3e-456a-bff3-fbed6421625b":
                        k.equals("origin_observation_id")?"92c4b25021fe4385b28eed28d9f583a3":NativeActionSnapshotCheck.hash("changed:"+k);
                b.getJSONObject("envelope").put(k,value);});
        }
        one("original_action_deadline_never_extended",()->{
            JSONObject a=endpoint("before"),b=endpoint("after");
            denied(()->NativeActionSnapshotCheck.compare(intent(a,"0/2","AX3000T"),snapshot(a),snapshot(b),
                    fixture.getJSONObject("original_action").getLong("deadline_elapsed_ms")));
        });
        one("old_observation_age_not_renewed",()->{
            JSONObject a=endpoint("before"),b=endpoint("after");
            a.getJSONObject("envelope").put("captured_elapsed_ms",b.getJSONObject("envelope").getLong("captured_elapsed_ms")-90001);
            denied(()->compare(a,b));
        });
    }
    public static void main(String[] args)throws Exception{
        fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        cases();boolean pass=true;List<String> names=new ArrayList<String>();
        for(Map<String,Object> r:results){pass&=Boolean.TRUE.equals(r.get("passed"));names.add((String)r.get("name"));}
        JSONObject out=new JSONObject().put("schema","hepta.native-xiaomi-query-stability-host.v1").put("all_pass",pass)
                .put("cases",results.size()).put("assertions",assertions).put("case_names",names).put("results",results)
                .put("original_worker_fresh_census_available",false).put("recorded_successor_matches_original_fresh_digest",true)
                .put("android_execution",false).put("model_execution",false).put("business_completion_verified",false);
        Files.write(Paths.get(args[1]),(out.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        if(!pass)throw new AssertionError("filled query regression failed; complete cases retained");
    }
}
