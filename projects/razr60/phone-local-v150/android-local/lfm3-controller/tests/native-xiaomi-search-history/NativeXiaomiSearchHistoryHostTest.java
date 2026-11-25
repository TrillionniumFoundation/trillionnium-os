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

/** Original full f5fb before/fresh pairs. Counterfactuals are explicitly host-only;
 * no Android object, device permission, model execution or business success. */
public final class NativeXiaomiSearchHistoryHostTest {
    private static JSONObject fixture;
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private interface Work {void run()throws Exception;}
    private interface Change {void run(JSONObject value)throws Exception;}
    private NativeXiaomiSearchHistoryHostTest(){}
    static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    static JSONObject row(int step){return fixture.getJSONArray("pairs").getJSONObject(step-2);}
    static JSONObject endpoint(int step,String side){return copy(row(step).getJSONObject(side));}
    static JSONObject node(JSONObject value,String path){
        JSONArray nodes=value.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);if(path.equals(n.getString("path")))return n;}
        throw new AssertionError("missing fixture node "+path);
    }
    static void removeNode(JSONObject value,String path){
        JSONArray rows=value.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path"))){rows.remove(i);return;}
        throw new AssertionError("missing removal target");
    }
    static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject value){
        List<NativeActionSnapshotCheck.Node> rows=new ArrayList<NativeActionSnapshotCheck.Node>();
        JSONArray nodes=value.getJSONArray("nodes");
        for(int i=0;i<nodes.length();i++)rows.add(new NativeActionSnapshotCheck.Node(nodes.getJSONObject(i).toMap()));
        return new NativeActionSnapshotCheck.Snapshot(value.getJSONObject("envelope").toMap(),rows);
    }
    static Map<String,Object> compare(JSONObject a,JSONObject b){
        return NativeXiaomiSearchInputObservation.compare(snapshot(a),snapshot(b));
    }
    static NativeActionSnapshotCheck.Intent intent(int step,JSONObject original,String path,String reference){
        Map<String,Object> identity=new TreeMap<String,Object>(),env=original.getJSONObject("envelope").toMap();
        for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY)identity.put(key,env.get(key));
        JSONObject r=row(step),guard=r.getJSONObject("guard"),target=node(original,path);
        return new NativeActionSnapshotCheck.Intent(NativeActionSnapshotCheck.SET_QUERY,NativeActionSnapshotCheck.XIAOMI,path,
                target.getString("label"),reference,guard.getString("model_run_id"),r.getString("original_node_id"),
                r.getString("original_action_sha256"),null,identity,
                guard.getLong("issued_elapsed_ms"),guard.getLong("deadline_elapsed_ms"));
    }
    static Map<String,Object> actionCompare(int step,JSONObject a,JSONObject b,long now){
        return NativeActionSnapshotCheck.compare(intent(step,a,"0/1",node(a,"0/1").getString("ref_signature_sha256")),snapshot(a),snapshot(b),now);
    }
    static void noAuthority(Map<String,Object> proof){
        for(String key:Arrays.asList("grants_action_authority","query_dispatched","business_completion_verified","published_pair_is_current_tree_claimed","literal_goal_revalidated_by_session"))
            check(Boolean.FALSE.equals(proof.get(key)),"no fabricated authority: "+key);
        check(Boolean.TRUE.equals(proof.get("full_census_compared")),"full census required");
        check(Boolean.TRUE.equals(proof.get("fresh_action_validation_required")),"actual final action checks still required");
    }
    static String denied(Work work)throws Exception{
        try{work.run();}catch(IllegalArgumentException|IllegalStateException expected){assertions++;return expected.getMessage();}
        throw new AssertionError("actual predicate must refuse");
    }
    static void one(String name,String kind,Work work){
        Map<String,Object> r=new TreeMap<String,Object>();r.put("name",name);r.put("input_kind",kind);
        try{work.run();r.put("passed",true);}catch(Throwable failure){
            r.put("passed",false);r.put("error",failure.toString());
            java.io.StringWriter trace=new java.io.StringWriter();failure.printStackTrace(new java.io.PrintWriter(trace));r.put("trace",trace.toString());
        }results.add(r);
    }
    static void negative(String name,Change change){
        one(name,"synthetic_negative_from_exact_recorded_pair",()->{
            JSONObject a=endpoint(2,"before"),b=endpoint(2,"fresh");change.run(b);denied(()->compare(a,b));
        });
    }
    static void both(String name,Change change){
        one(name,"synthetic_negative_on_both_recorded_endpoints",()->{
            JSONObject a=endpoint(2,"before"),b=endpoint(2,"fresh");change.run(a);change.run(b);denied(()->compare(a,b));
        });
    }
    static void baseline(){
        for(int n=2;n<=4;n++){final int step=n;one("baseline_actual_step_0"+step+"_rejects_historical_prefix","original_complete_before_and_fresh",()->{
            String reason=denied(()->compare(endpoint(step,"before"),endpoint(step,"fresh")));
            check("actual recommendation section heading".equals(reason),"exact original failure reproduced: "+reason);
        });}
    }
    static void candidate(){
        final String original=fixture.toString();
        one("original_six_complete_censuses_and_zero_effect_failures_preserved","original_complete_before_and_fresh",()->{
            for(int step=2;step<=4;step++){
                JSONObject r=row(step);
                check(r.getBoolean("complete_two_censuses")&&!r.getBoolean("nodes_truncated"),"complete original censuses");
                check(!r.getBoolean("effect_entered")&&!r.getBoolean("effect_returned")&&!r.getBoolean("dispatched")&&r.getBoolean("worker_drained"),"historical zero effect remains a failure");
                for(String side:Arrays.asList("before","fresh")){
                    JSONObject e=endpoint(step,side);
                    check(e.getJSONArray("nodes").length()==183,"complete 183-node census, not retained subset");
                    check(snapshot(e).sha.equals(e.getString("snapshot_sha256")),"exact original full snapshot digest");
                    check(node(e,"0/1").getString("text").isEmpty(),"query is actually empty");
                }
            }
        });
        for(int n=2;n<=4;n++){final int step=n;
            one("recorded_step_0"+step+"_complete_pair_accepted","original_complete_before_and_fresh",()->{
                Map<String,Object> proof=compare(endpoint(step,"before"),endpoint(step,"fresh"));noAuthority(proof);
                check(((List<?>)proof.get("changed_paths")).size()==(step==4?21:20),"all actual changing paths accounted");
                check("0/6/14".equals(proof.get("variable_carousel_path")),"actual carousel follows exactly ten recommendation chips");
            });
            one("recorded_step_0"+step+"_original_action_values_accepted_without_dispatch_authority","original_recorded_value_comparison_not_android_replay",()->{
                Map<String,Object> proof=actionCompare(step,endpoint(step,"before"),endpoint(step,"fresh"),row(step).getLong("compared_elapsed_ms"));
                noAuthority(proof);
                check(Boolean.FALSE.equals(proof.get("grants_dispatch"))&&Boolean.TRUE.equals(proof.get("live_node_chain_window_and_one_effect_recheck_required")),"private guard, live object, final census and one effect remain necessary");
                check("0/1".equals(proof.get("target_path"))&&"set_product_query".equals(proof.get("purpose")),"only original input purpose");
            });
        }
        one("equal_tree_keeps_final_live_check_requirement","explicit_same_tree_counterfactual",()->{
            JSONObject a=endpoint(2,"before"),b=endpoint(2,"before");
            b.getJSONObject("envelope").put("captured_elapsed_ms",row(2).getLong("compared_elapsed_ms")-1);
            Map<String,Object> proof=actionCompare(2,a,b,row(2).getLong("compared_elapsed_ms"));noAuthority(proof);
            check(((List<?>)proof.get("changed_paths")).isEmpty(),"exact equal-tree case");
            check(Boolean.TRUE.equals(proof.get("live_node_chain_window_and_one_effect_recheck_required")),"no equal-tree bypass");
        });
        one("prefix_never_becomes_variable_or_a_click_target","original_complete_before_and_fresh",()->{
            Map<String,Object> proof=compare(endpoint(2,"before"),endpoint(2,"fresh"));
            for(String path:Arrays.asList("0/6/0","0/6/1","0/6/1/0","0/6/2","0/6/3"))
                check(!((List<?>)proof.get("variable_chip_paths")).contains(path)&&node(endpoint(2,"before"),path).toMap().equals(node(endpoint(2,"fresh"),path).toMap()),"entire prefix static: "+path);
        });
        negative("history_heading_text_changed_refused",b->{node(b,"0/6/0").put("text","其他历史");});
        negative("history_heading_label_changed_refused",b->{node(b,"0/6/0").put("label","其他历史");});
        negative("history_item_label_changed_refused",b->{node(b,"0/6/1").put("label","其他商品");});
        negative("history_item_own_text_added_refused",b->{node(b,"0/6/1").put("text","AX3000T");});
        negative("history_child_text_changed_refused",b->{node(b,"0/6/1/0").put("text","AX3000");});
        negative("history_child_label_changed_refused",b->{node(b,"0/6/1/0").put("label","AX3000");});
        negative("history_heading_click_capability_added_refused",b->{node(b,"0/6/0").put("clickable",true).put("action_click",true);});
        negative("history_item_click_capability_removed_refused",b->{node(b,"0/6/1").put("action_click",false);});
        negative("history_item_disabled_refused",b->{node(b,"0/6/1").put("enabled",false);});
        negative("history_item_hidden_refused",b->{node(b,"0/6/1").put("visible",false);});
        negative("history_item_editable_refused",b->{node(b,"0/6/1").put("editable",true);});
        negative("history_item_selected_refused",b->{node(b,"0/6/1").put("selected",true);});
        negative("history_child_focused_refused",b->{node(b,"0/6/1/0").put("focused",true);});
        negative("history_item_description_added_refused",b->{node(b,"0/6/1").put("description","other semantics");});
        negative("history_item_view_id_changed_refused",b->{node(b,"0/6/1").put("view_id","other");});
        negative("history_heading_reference_changed_refused",b->{node(b,"0/6/0").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("changed reference"));});
        negative("history_item_reference_changed_refused",b->{node(b,"0/6/1").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("changed reference"));});
        negative("history_child_reference_changed_refused",b->{node(b,"0/6/1/0").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("changed reference"));});
        negative("history_item_over_query_toolbar_refused",b->{node(b,"0/6/1").put("bounds",new JSONArray(Arrays.asList(54,130,320,334)));});
        negative("history_child_outside_item_refused",b->{node(b,"0/6/1/0").put("bounds",new JSONArray(Arrays.asList(53,630,279,684)));});
        negative("history_title_overlaps_item_refused",b->{node(b,"0/6/0").put("bounds",new JSONArray(Arrays.asList(54,518,234,650)));});
        negative("history_item_overlaps_recommendation_title_refused",b->{node(b,"0/6/1").put("bounds",new JSONArray(Arrays.asList(54,613,320,800)));});
        negative("recommendation_title_is_still_protected_refused",b->{node(b,"0/6/2").put("text","其他推荐");});
        negative("refresh_control_is_still_protected_refused",b->{node(b,"0/6/3").put("selected",true);});
        negative("history_child_missing_refused",b->{removeNode(b,"0/6/1/0");});
        negative("duplicate_history_node_refused",b->{b.getJSONArray("nodes").put(copy(node(b,"0/6/0")));});
        negative("second_history_item_instead_of_recommendation_title_refused",b->{node(b,"0/6/2").put("text","搜索历史").put("label","搜索历史");});
        negative("query_text_altered_refused",b->{node(b,"0/1").put("text","AX3000T");});
        negative("query_reference_altered_refused",b->{node(b,"0/1").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("changed query"));});
        negative("query_disabled_refused",b->{node(b,"0/1").put("enabled",false);});
        negative("query_focused_refused",b->{node(b,"0/1").put("focused",true);});
        negative("normal_search_button_altered_refused",b->{node(b,"0/4").put("action_click",false);});
        negative("recommendation_gains_editability_refused",b->{node(b,"0/6/4/0").put("editable",true);});
        negative("recommendation_capability_altered_refused",b->{node(b,"0/6/4").put("clickable",false);});
        negative("recommendation_leaves_enclosure_refused",b->{node(b,"0/6/4").put("bounds",new JSONArray(Arrays.asList(54,129,226,963)));});
        negative("later_fixed_carousel_changed_refused",b->{node(b,"0/6/15").put("selected",true);});
        negative("offscreen_fixed_branch_changed_refused",b->{node(b,"0/6/16/49").put("description","unclassified");});
        negative("membership_omission_refused",b->{b.getJSONArray("nodes").remove(b.getJSONArray("nodes").length()-1);});
        negative("truncated_census_refused",b->{b.getJSONObject("envelope").put("node_omissions",1);});
        negative("incomplete_census_refused",b->{b.getJSONObject("envelope").put("full_native_complete",false);});
        negative("unknown_ime_refused",b->{b.getJSONObject("envelope").put("ime_visibility","unknown");});
        negative("incomplete_window_report_refused",b->{b.getJSONObject("envelope").put("reported_windows_complete",false);});
        negative("window_metadata_changed_refused",b->{b.getJSONObject("envelope").put("window_metadata_sha256",NativeActionSnapshotCheck.hash("changed window"));});
        negative("additional_reported_window_refused",b->{b.getJSONObject("envelope").put("reported_windows_sha256",NativeActionSnapshotCheck.hash("extra window"));});
        negative("cross_display_refused",b->{b.getJSONObject("envelope").put("display_id",642);});
        negative("cross_owner_refused",b->{b.getJSONObject("envelope").put("owner_sha256",NativeActionSnapshotCheck.hash("other owner"));});
        negative("cross_profile_refused",b->{b.getJSONObject("envelope").put("profile_user_id",11).put("profile_user_serial",11L).put("profile_full_uid",1110485);});
        negative("cross_installed_set_refused",b->{b.getJSONObject("envelope").put("installed_set_sha256",NativeActionSnapshotCheck.hash("other install"));});
        negative("cross_authorization_refused",b->{b.getJSONObject("envelope").put("authorization_sha256",NativeActionSnapshotCheck.hash("other authorization"));});
        negative("cross_goal_refused",b->{b.getJSONObject("envelope").put("goal_sha256",NativeActionSnapshotCheck.hash("other goal"));});
        both("unsupported_history_literal_on_both_sides_refused",b->{node(b,"0/6/1").put("label","AX6000");node(b,"0/6/1/0").put("text","AX6000").put("label","AX6000");});
        both("wrong_history_title_on_both_sides_refused",b->{node(b,"0/6/0").put("text","收藏历史").put("label","收藏历史");});
        both("history_input_capability_on_both_sides_refused",b->{node(b,"0/6/1").put("editable",true);});
        both("history_overlap_on_both_sides_refused",b->{node(b,"0/6/1").put("bounds",new JSONArray(Arrays.asList(54,613,320,800)));});
        both("extra_search_label_on_both_sides_refused",b->{node(b,"0/6/4/0").put("text","搜索").put("label","搜索");});
        one("one_side_loses_history_prefix","synthetic_topology_negative",()->{
            JSONObject a=endpoint(2,"before"),b=endpoint(2,"fresh");JSONArray rows=b.getJSONArray("nodes");
            for(int i=rows.length()-1;i>=0;i--){JSONObject n=rows.getJSONObject(i);String path=n.getString("path");
                if(path.equals("0/6/0")||path.equals("0/6/1")||path.startsWith("0/6/1/")){rows.remove(i);continue;}
                if(path.startsWith("0/6/")){String tail=path.substring(4);int slash=tail.indexOf('/');int index=Integer.parseInt(slash<0?tail:tail.substring(0,slash));
                    n.put("path","0/6/"+(index-2)+(slash<0?"":tail.substring(slash)));}
            }
            node(b,"0/6").put("children",15);b.getJSONObject("envelope").put("visited",rows.length());denied(()->compare(a,b));
        });
        one("old_observation_age_not_renewed","synthetic_clock_negative",()->{
            JSONObject a=endpoint(2,"before"),b=endpoint(2,"fresh");
            a.getJSONObject("envelope").put("captured_elapsed_ms",b.getJSONObject("envelope").getLong("captured_elapsed_ms")-90001);
            denied(()->compare(a,b));
        });
        one("original_action_deadline_not_extended","synthetic_clock_negative",()->{
            denied(()->actionCompare(2,endpoint(2,"before"),endpoint(2,"fresh"),row(2).getJSONObject("guard").getLong("deadline_elapsed_ms")));
        });
        one("history_item_never_selected_for_set_query","synthetic_wrong_target_negative",()->{
            JSONObject a=endpoint(2,"before"),b=endpoint(2,"fresh");
            denied(()->NativeActionSnapshotCheck.compare(intent(2,a,"0/6/1",node(a,"0/6/1").getString("ref_signature_sha256")),snapshot(a),snapshot(b),row(2).getLong("compared_elapsed_ms")));
        });
        one("different_original_query_reference_refused","synthetic_original_reference_negative",()->{
            JSONObject a=endpoint(2,"before"),b=endpoint(2,"fresh");
            denied(()->NativeActionSnapshotCheck.compare(intent(2,a,"0/1",NativeActionSnapshotCheck.hash("other original")),snapshot(a),snapshot(b),row(2).getLong("compared_elapsed_ms")));
        });
        one("recorded_json_not_mutated","source_preservation",()->check(original.equals(fixture.toString()),"all original input values remain unchanged"));
    }
    public static void main(String[] args)throws Exception{
        fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        if(args.length!=3||!(args[2].equals("baseline")||args[2].equals("candidate")))throw new IllegalArgumentException("exact host variant required");
        if(args[2].equals("baseline"))baseline();else candidate();
        boolean pass=true;List<String> names=new ArrayList<String>();for(Map<String,Object> r:results){pass&=Boolean.TRUE.equals(r.get("passed"));names.add((String)r.get("name"));}
        JSONObject out=new JSONObject().put("schema","hepta.xiaomi-search-history-pure-cases.v1").put("mode",args[2]).put("all_pass",pass)
                .put("cases",results.size()).put("assertions",assertions).put("case_names",names).put("results",results)
                .put("original_worker_fresh_censuses_available",true).put("original_node_values_rewritten",false)
                .put("android_execution",false).put("model_executed",false).put("business_completion_verified",false);
        Files.write(Paths.get(args[1]),(out.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        if(!pass)throw new AssertionError("search-history regression failed; full cases retained");
    }
}
