package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import org.json.JSONArray;
import org.json.JSONObject;

/** Complete saved node values; synthetic envelope identities confer no live authority. */
public final class NativeSearchBannerCoverageHostTest {
    private static final String FIXTURE_SHA="23a0cc749073ca9ac1385b24b60c40a4aa98a8398b90062a3363716a614f9860";
    private static final String BANNER="0/0/1/0/0",LEFT=BANNER+"/3",RIGHT=BANNER+"/4",TARGET="0/0/3";
    private static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private static JSONObject fixture;
    interface Check {void run()throws Exception;}
    interface Mutation {void apply(JSONObject graph)throws Exception;}
    private static void yes(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void one(String name,Check check){
        int before=assertions;Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{check.run();row.put("passed",true);}catch(Exception|AssertionError error){row.put("passed",false);row.put("error",error.getClass().getName()+": "+error.getMessage());}
        row.put("assertions",assertions-before);cases.add(row);
    }
    private static JSONObject copy(String name)throws Exception{return new JSONObject(fixture.getJSONObject("graphs").getJSONObject(name).toString());}
    private static JSONObject node(JSONObject graph,String path)throws Exception{
        JSONArray rows=graph.getJSONArray("nodes");JSONObject found=null;
        for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path"))){
            yes(found==null,"unique complete path");found=rows.getJSONObject(i);
        }
        if(found==null)throw new AssertionError("absent fixture path: "+path);return found;
    }
    private static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject graph)throws Exception{return NativeSearchPlanning.readSnapshot(NativeSearchPlanning.map(graph));}
    private static String hash(String value){return QualificationScope.hash(value.getBytes(StandardCharsets.UTF_8));}
    private static String field(String value){return value.length()+":"+value;}
    // Independently reproduce the ordinary empty-child leaf reference after a
    // synthetic geometry change, so gap/overlap tests cannot pass on a stale hash.
    private static String emptyReference(JSONObject n)throws Exception{
        JSONArray b=n.getJSONArray("bounds");
        String rect="Rect("+b.getInt(0)+", "+b.getInt(1)+" - "+b.getInt(2)+", "+b.getInt(3)+")";
        String base=hash(n.getString("package")+"\u0001"+n.getInt("window_id")+"\u0001"+n.getString("class")+"\u0001"+
            n.getString("view_id")+"\u0001"+rect+"\u0001"+n.getString("text")+"\u0001"+n.getString("description")+"\u0001"+
            n.getBoolean("enabled")+"|"+n.getBoolean("clickable")+"|"+n.getBoolean("editable")+"|"+n.getBoolean("scrollable"));
        String child=hash(field(ObservedChildText.SOURCE)+field("empty")+field("")+field("false")+field(base)+field("true"));
        String tree=hash(field(base)+field(child));
        return hash(tree+"\nscroll_actions="+n.getString("scroll_actions")+"\nime_enter="+n.getString("ime_enter")+
                    "|focused="+n.getBoolean("focused")+"|full_input=null");
    }
    private static void refresh(JSONObject n)throws Exception{
        if(n.getBoolean("visible"))n.put("ref_signature_sha256",emptyReference(n));
    }
    private static void geometry(JSONObject graph,String path,int l,int t,int r,int b)throws Exception{
        JSONObject n=node(graph,path);n.put("bounds",new JSONArray(Arrays.asList(l,t,r,b)));refresh(n);
    }
    private static void reject(JSONObject first,JSONObject second)throws Exception{
        for(boolean planning:new boolean[]{true,false}){
            boolean refused=false;
            try{
                NativeActionSnapshotCheck.Snapshot a=snapshot(first),b=snapshot(second);
                if(planning)NativeSearchRole.compareForPlanning(a,b);else NativeSearchRole.compareForExecution(a,b);
            }catch(IllegalArgumentException expected){refused=true;}
            yes(refused,"actual "+(planning?"planning":"execution")+" role must refuse mutated complete pair");
        }
    }
    private static void rejectD(String name,Mutation change){one(name,()->{JSONObject d=copy("D");change.apply(d);reject(copy("C"),d);});}
    private static void proof(NativeSearchRole role){
        yes(role.fullPageSwap&&!role.fullTreeEqual,"exact full coverage transition classified");
        yes(role.enclosures.isEmpty(),"banner does not masquerade as a disjoint viewport");
        yes(role.changedPaths.size()==12,"all nine banner and three validated hint differences retained");
        yes(TARGET.equals(role.targetPath),"original observed search target retained");
        Map<String,Object> p=role.evidence();
        yes(Boolean.FALSE.equals(p.get("grants_dispatch")),"pure role grants no input");
        yes(Boolean.FALSE.equals(p.get("generic_action_authority")),"no generic authority");
        yes(Boolean.FALSE.equals(p.get("query_or_price_verified")),"no business result");
        Object raw=p.get("changed_path_classification");yes(raw instanceof Map,"complete classification");
        Map<?,?> classified=(Map<?,?>)raw;
        for(String path:role.changedPaths)yes((path.startsWith(BANNER+"/")?"same_full_blank_banner_coverage":"validated_search_hint").equals(classified.get(path)),"each difference has its exact allowed classification");
    }
    public static void main(String[] args)throws Exception{
        Path input=Paths.get(args[0]),output=Paths.get(args[1]);byte[] raw=Files.readAllBytes(input);
        yes(FIXTURE_SHA.equals(QualificationScope.hash(raw)),"exact derived fixture bytes");
        fixture=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        one("real_complete_75_75_censuses_and_2580ms_interval",()->{
            NativeActionSnapshotCheck.Snapshot c=snapshot(copy("C")),d=snapshot(copy("D"));
            yes(c.nodes.size()==75&&d.nodes.size()==75,"no retained subset");
            JSONObject p=fixture.getJSONObject("provenance");
            yes(p.getBoolean("raw_nodes_preserved_as_values")&&p.getBoolean("authority_identity_fields_are_synthetic"),"actual nodes with explicit synthetic authority");
            yes(!p.getBoolean("phone_or_effect_proof"),"no phone proof");
            yes(p.getInt("original_census_interval_ms")==2580,"original interval preserved");
            yes("33333333333333333333333333333333".equals(c.env.get("task_id")),"synthetic task identity");
            yes(c.node(LEFT).bounds.equals(Arrays.asList(0,0,1224,931)),"original full page");
            yes(d.node(LEFT).bounds.equals(Arrays.asList(0,0,4,931))&&d.node(RIGHT).bounds.equals(Arrays.asList(4,0,1224,931)),"actual 4 plus 1220 pixel coverage");
            yes(c.node(BANNER).v.equals(d.node(BANNER).v),"container unchanged");
        });
        one("real_CD_full_to_seamless_partition_passes_actual_planning",()->proof(NativeSearchRole.compareForPlanning(snapshot(copy("C")),snapshot(copy("D")))));
        one("real_CD_full_to_seamless_partition_passes_actual_execution_role",()->proof(NativeSearchRole.compareForExecution(snapshot(copy("C")),snapshot(copy("D")))));
        one("reverse_partition_to_full_has_same_role",()->{
            NativeSearchRole cd=NativeSearchRole.compareForExecution(snapshot(copy("C")),snapshot(copy("D")));
            NativeSearchRole dc=NativeSearchRole.compareForExecution(snapshot(copy("D")),snapshot(copy("C")));
            proof(dc);yes(cd.roleId.equals(dc.roleId),"same semantic target and authority");
        });
        one("strict_generic_compare_still_refuses_banner_motion",()->{
            boolean refused=false;try{NativeSearchRole.compare(snapshot(copy("C")),snapshot(copy("D")));}catch(IllegalArgumentException expected){refused=true;}
            yes(refused,"exception remains restricted to typed search planning/execution");
        });
        one("equal_pair_keeps_old_full_tree_equal_semantics",()->{
            NativeActionSnapshotCheck.Snapshot c=snapshot(copy("C"));NativeSearchRole role=NativeSearchRole.compareForExecution(c,c);
            yes(role.fullTreeEqual&&!role.fullPageSwap&&role.changedPaths.isEmpty(),"unchanged page not reclassified");
        });
        one("recomputed_geometry_hash_matches_actual_reference",()->{
            for(String key:new String[]{"C","D"})for(String path:new String[]{LEFT,RIGHT}){
                JSONObject n=node(copy(key),path);if(n.getBoolean("visible"))yes(emptyReference(n).equals(n.getString("ref_signature_sha256")),"real ordinary reference algorithm matched");
            }
        });
        one("different_exact_partition_needs_no_special_pixel_width",()->{
            JSONObject d=copy("D");geometry(d,LEFT,0,0,600,931);geometry(d,RIGHT,600,0,1224,931);
            proof(NativeSearchRole.compareForExecution(snapshot(copy("C")),snapshot(d)));
        });
        one("old_single_full_page_swap_remains_accepted",()->{
            JSONObject d=copy("D"),left=node(d,LEFT);
            left.put("visible",false).put("label",JSONObject.NULL).put("ref_signature_sha256",JSONObject.NULL).put("bounds",new JSONArray(Arrays.asList(0,0,0,931)));
            geometry(d,RIGHT,0,0,1224,931);proof(NativeSearchRole.compareForExecution(snapshot(copy("C")),snapshot(d)));
        });
        rejectD("one_pixel_gap_with_fresh_references_rejected",g->geometry(g,RIGHT,5,0,1224,931));
        rejectD("one_pixel_overlap_with_fresh_references_rejected",g->geometry(g,RIGHT,3,0,1224,931));
        rejectD("full_page_plus_edge_overlap_rejected",g->geometry(g,RIGHT,0,0,1224,931));
        rejectD("equal_bounding_box_and_total_width_do_not_allow_gap_overlap",g->{
            geometry(g,LEFT,0,0,600,931);geometry(g,RIGHT,601,0,1224,931);
            JSONObject extra=node(g,BANNER+"/5");extra.put("visible",true).put("label","");
            geometry(g,BANNER+"/5",0,0,1,931);
        });
        rejectD("top_gap_with_fresh_reference_rejected",g->geometry(g,RIGHT,4,1,1224,931));
        rejectD("bottom_gap_with_fresh_reference_rejected",g->geometry(g,RIGHT,4,0,1224,930));
        rejectD("right_overflow_with_fresh_reference_rejected",g->geometry(g,RIGHT,4,0,1225,931));
        rejectD("left_overflow_with_fresh_reference_rejected",g->geometry(g,LEFT,-1,0,4,931));
        rejectD("zero_width_visible_leaf_rejected",g->geometry(g,LEFT,0,0,0,931));
        rejectD("hidden_positive_interior_leaf_not_omitted_from_coverage",g->geometry(g,BANNER+"/0",100,0,200,931));
        rejectD("incorrect_reference_even_with_exact_geometry_rejected",g->node(g,RIGHT).put("ref_signature_sha256",hash("stale reference")));
        rejectD("new_click_capability_with_fresh_reference_rejected",g->{JSONObject n=node(g,RIGHT);n.put("clickable",false).put("action_click",false);refresh(n);});
        rejectD("new_scroll_capability_with_fresh_reference_rejected",g->{JSONObject n=node(g,RIGHT);n.put("scrollable",true);refresh(n);});
        rejectD("new_editable_capability_with_fresh_reference_rejected",g->{JSONObject n=node(g,RIGHT);n.put("editable",true);refresh(n);});
        rejectD("new_focus_state_with_fresh_reference_rejected",g->{JSONObject n=node(g,RIGHT);n.put("focused",true);refresh(n);});
        rejectD("new_input_hash_rejected",g->node(g,RIGHT).put("input_sha256",hash("new input")));
        rejectD("new_scroll_actions_with_fresh_reference_rejected",g->{JSONObject n=node(g,RIGHT);n.put("scroll_actions","hepta.observed-scroll-actions.v1|observed|forward");refresh(n);});
        rejectD("nonblank_visible_page_with_fresh_reference_rejected",g->{JSONObject n=node(g,RIGHT);n.put("text","new");refresh(n);});
        rejectD("banner_container_change_rejected",g->node(g,BANNER).put("selected",true));
        rejectD("banner_holder_change_rejected",g->node(g,"0/0/1/0").put("selected",true));
        rejectD("nonbanner_search_icon_change_rejected",g->node(g,"0/0/4").put("selected",true));
        rejectD("search_target_geometry_change_rejected",g->node(g,TARGET).put("bounds",new JSONArray(Arrays.asList(155,287,1000,375))));
        rejectD("unvalidated_hint_reference_change_rejected",g->node(g,TARGET+"/0/0").put("ref_signature_sha256",hash("invalid hint")));
        rejectD("foreign_window_rejected",g->node(g,RIGHT).put("window_id",0));
        rejectD("census_omission_rejected",g->g.getJSONObject("envelope").put("child_omissions",1));
        rejectD("owner_change_rejected",g->g.getJSONObject("envelope").put("owner_sha256",hash("different owner")));
        rejectD("missing_banner_child_rejected",g->{
            JSONArray rows=g.getJSONArray("nodes");for(int i=0;i<rows.length();i++)if((BANNER+"/8").equals(rows.getJSONObject(i).getString("path"))){rows.remove(i);break;}
            g.getJSONObject("envelope").put("visited",rows.length());
        });
        one("hidden_only_geometry_does_not_expand_visible_transition_exception",()->{
            JSONObject c=copy("C"),changed=copy("C");geometry(changed,BANNER+"/0",0,0,-2449,931);reject(c,changed);
        });
        one("fixture_and_snapshots_are_not_mutated_by_pure_comparison",()->{
            yes(Arrays.equals(raw,Files.readAllBytes(input)),"fixture bytes unchanged");
            NativeActionSnapshotCheck.Snapshot d=snapshot(copy("D"));
            yes(NativeSearchPlanning.equal(NativeSearchPlanning.snapshot(d),NativeSearchPlanning.map(copy("D"))),"all nodes and envelope retained");
        });
        boolean all=true;for(Map<String,Object> row:cases)all&=Boolean.TRUE.equals(row.get("passed"));
        Map<String,Object> result=new LinkedHashMap<String,Object>();
        result.put("schema","hepta.xiaomi-banner-coverage-host.v1");result.put("all_pass",all);
        result.put("cases",cases.size());result.put("assertions",assertions);result.put("case_results",cases);
        result.put("fixture_sha256",FIXTURE_SHA);result.put("fixture_authority_is_synthetic",true);
        result.put("actual_android_or_model_executed",false);result.put("input_dispatched",false);result.put("business_verified",false);
        byte[] encoded=(NativeSearchPlanning.json(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8);
        Files.write(output,encoded);System.out.write(encoded);if(!all)throw new AssertionError("one or more banner coverage cases failed");
    }
}
