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
import org.json.JSONArray;
import org.json.JSONObject;

/** Complete saved phone node values with explicitly synthetic envelope authority.
 * This pure Role gate creates no Session, model, Android reference or input. */
public final class NativeSearchCarouselEdgeHostTest {
    private static final String FIXTURE_SHA="4b04b63db139330fdec649d434aa0010d55aabb359c10f501c8fbdeb2c3126d0";
    private static final String REGION="0/0/1/1/0",EMPTY=REGION+"/3",IMAGE=EMPTY+"/0";
    private static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    private static int assertions;
    private static JSONObject fixture;
    private static NativeActionSnapshotCheck.Snapshot a,b,c,d;
    interface Check {void run()throws Exception;}
    interface Mutation {void apply(JSONObject value)throws Exception;}
    private static void yes(boolean value,String detail){assertions++;if(!value)throw new AssertionError(detail);}
    private static void one(String name,Check check)throws Exception{
        int before=assertions;Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{check.run();row.put("passed",true);}catch(Exception|AssertionError e){row.put("passed",false);row.put("error",e.getClass().getName()+": "+e.getMessage());}
        row.put("assertions",assertions-before);cases.add(row);
    }
    private static JSONObject copy(String graph)throws Exception{return new JSONObject(fixture.getJSONObject("graphs").getJSONObject(graph).toString());}
    private static JSONObject node(JSONObject graph,String path)throws Exception{
        JSONArray nodes=graph.getJSONArray("nodes");JSONObject found=null;
        for(int i=0;i<nodes.length();i++)if(path.equals(nodes.getJSONObject(i).getString("path"))){yes(found==null,"unique fixture path");found=nodes.getJSONObject(i);}
        if(found==null)throw new AssertionError("fixture path absent: "+path);return found;
    }
    private static void bounds(JSONObject node,int left,int top,int right,int bottom)throws Exception{node.put("bounds",new JSONArray(Arrays.asList(left,top,right,bottom)));}
    private static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject value)throws Exception{return NativeSearchPlanning.readSnapshot(NativeSearchPlanning.map(value));}
    private static void reject(JSONObject first,JSONObject second)throws Exception{
        boolean rejected=false;try{NativeSearchRole.compare(snapshot(first),snapshot(second));}catch(IllegalArgumentException expected){rejected=true;}
        yes(rejected,"complete actual Role comparison must refuse this mutated pair");
    }
    private static void rejectD(String name,Mutation change)throws Exception{one(name,()->{JSONObject changed=copy("D");change.apply(changed);reject(copy("C"),changed);});}
    private static void rejectBoth(String name,Mutation change)throws Exception{one(name,()->{JSONObject first=copy("C"),second=copy("D");change.apply(first);change.apply(second);reject(first,second);});}
    private static void pureProof(NativeSearchRole role){
        yes(role.enclosures.equals(Collections.singletonList(REGION)),"only the fixed actual RecyclerView bounds the changes");
        yes(role.changedPaths.size()==8&&!role.fullTreeEqual,"all eight changed rows retained");
        Map<String,Object> proof=role.evidence();yes(Boolean.FALSE.equals(proof.get("grants_dispatch")),"pure role cannot grant input");
        yes(Boolean.FALSE.equals(proof.get("generic_action_authority")),"no generic action authority");
        yes(Boolean.FALSE.equals(proof.get("query_or_price_verified")),"no business completion");
    }
    public static void main(String[] args)throws Exception{
        Path input=Paths.get(args[0]),output=Paths.get(args[1]);byte[] raw=Files.readAllBytes(input);
        if(!QualificationScope.hash(raw).equals(FIXTURE_SHA))throw new AssertionError("exact derived fixture bytes");
        fixture=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        a=snapshot(copy("A"));b=snapshot(copy("B"));c=snapshot(copy("C"));d=snapshot(copy("D"));
        one("derived_fixture_preserves_complete_83_83_84_84_censuses",()->{
            yes(a.nodes.size()==83&&b.nodes.size()==83&&c.nodes.size()==84&&d.nodes.size()==84,"original complete node counts");
            JSONObject p=fixture.getJSONObject("provenance");yes(p.getBoolean("raw_nodes_preserved_as_values"),"node values are derived unchanged");
            yes(p.getBoolean("authority_identity_fields_are_synthetic")&&p.getBoolean("clock_is_translated_preserving_intervals"),"identity and clocks explicitly adapted");
            yes(!p.getBoolean("phone_or_effect_proof"),"fixture is not current phone authority");
            yes("11111111111111111111111111111111".equals(c.env.get("task_id")),"synthetic task identifier");
        });
        one("actual_edge_empty_parent_and_bounded_visible_child_are_retained",()->{
            yes(Boolean.FALSE.equals(d.node(EMPTY).v.get("visible")),"original hidden flag");
            yes(d.node(EMPTY).bounds.equals(Arrays.asList(1228,1033,1224,1368)),"original inverted edge bounds");
            yes(Boolean.TRUE.equals(d.node(IMAGE).v.get("visible"))&&d.node(IMAGE).bounds.equals(Arrays.asList(1036,1033,1224,1368)),"original visible descendant geometry");
            yes(c.node(REGION).v.equals(d.node(REGION).v),"actual viewport is exactly fixed");
        });
        one("saved_planning_AB_still_classifies_the_same_disjoint_carousel",()->pureProof(NativeSearchRole.compare(a,b)));
        one("saved_current_CD_accepts_complete_bounded_edge_footprints_only",()->{
            NativeSearchRole role=NativeSearchRole.compare(c,d);pureProof(role);
            yes(NativeSearchRole.compare(a,b).roleId.equals(role.roleId),"same authenticated search role across independent pairs");
            yes("0/0/3".equals(role.targetPath),"search target stays exact");
            yes(d.node(EMPTY).bounds.equals(Arrays.asList(1228,1033,1224,1368)),"no clipping or repaired input");
        });
        one("synthetic_left_edge_empty_parent_uses_same_fixed_viewport",()->{
            JSONObject changed=copy("D");bounds(node(changed,EMPTY),0,1033,-4,1368);
            NativeSearchRole role=NativeSearchRole.compare(c,snapshot(changed));pureProof(role);
            yes(node(changed,EMPTY).getJSONArray("bounds").getInt(2)==-4,"negative raw coordinate retained");
        });
        one("synthetic_right_edge_zero_parent_keeps_visible_child_bounded",()->{
            JSONObject changed=copy("D");bounds(node(changed,EMPTY),1224,1033,1224,1368);pureProof(NativeSearchRole.compare(c,snapshot(changed)));
        });
        rejectD("interior_zero_hidden_parent_remains_rejected",g->bounds(node(g,EMPTY),10,1033,10,1368));
        rejectD("interior_inverted_hidden_parent_remains_rejected",g->bounds(node(g,EMPTY),100,1033,10,1368));
        rejectD("empty_parent_not_anchored_at_actual_right_edge_rejected",g->bounds(node(g,EMPTY),1228,1033,1223,1368));
        rejectD("empty_parent_wholly_outside_actual_right_edge_rejected",g->bounds(node(g,EMPTY),1230,1033,1230,1368));
        rejectD("vertical_zero_parent_is_outside_horizontal_exception",g->bounds(node(g,EMPTY),100,1033,200,1033));
        rejectD("vertical_inverted_parent_is_outside_horizontal_exception",g->bounds(node(g,EMPTY),100,1400,200,1368));
        rejectD("empty_parent_top_outside_viewport_rejected",g->bounds(node(g,EMPTY),1228,1032,1224,1368));
        rejectD("empty_parent_bottom_outside_viewport_rejected",g->bounds(node(g,EMPTY),1228,1033,1224,1369));
        rejectD("visible_inverted_parent_is_never_treated_hidden",g->node(g,EMPTY).put("visible",true));
        rejectD("visible_descendant_zero_area_rejected",g->bounds(node(g,IMAGE),1100,1033,1100,1368));
        rejectD("visible_descendant_horizontal_overflow_rejected",g->bounds(node(g,IMAGE),1036,1033,1225,1368));
        rejectD("visible_descendant_vertical_overflow_rejected",g->bounds(node(g,IMAGE),1036,1033,1224,1369));
        rejectD("positive_hidden_descendant_overflow_rejected",g->{node(g,IMAGE).put("visible",false);bounds(node(g,IMAGE),1036,1033,1225,1368);});
        rejectBoth("different_resource_is_not_authenticated_carousel",g->node(g,REGION).put("view_id","com.xiaomi.shop:id/other_view"));
        rejectBoth("different_class_is_not_authenticated_carousel",g->{node(g,REGION).put("class","android.widget.LinearLayout");for(int i=0;i<4;i++)node(g,REGION+"/"+i).put("parent_class","android.widget.LinearLayout");});
        rejectBoth("clickable_viewport_cannot_use_empty_edge_exception",g->{node(g,REGION).put("clickable",true);node(g,REGION).put("action_click",true);});
        rejectBoth("disabled_viewport_cannot_use_empty_edge_exception",g->node(g,REGION).put("enabled",false));
        rejectBoth("nonscrollable_viewport_cannot_use_empty_edge_exception",g->node(g,REGION).put("scrollable",false));
        rejectBoth("editable_viewport_cannot_use_empty_edge_exception",g->node(g,REGION).put("editable",true));
        rejectBoth("password_viewport_cannot_use_empty_edge_exception",g->node(g,REGION).put("password",true));
        rejectD("changed_viewport_is_not_fixed_enclosure",g->bounds(node(g,REGION),1,1033,1224,1368));
        rejectD("changed_real_viewport_ancestor_still_rejected",g->node(g,"0/0/1/1").put("selected",true));
        rejectD("changed_search_target_still_rejected",g->bounds(node(g,"0/0/3"),155,287,1000,375));
        rejectD("changed_search_icon_still_rejected",g->node(g,"0/0/4").put("selected",true));
        rejectD("new_editable_role_in_carousel_still_rejected",g->node(g,IMAGE).put("editable",true));
        rejectD("missing_complete_child_slot_still_rejected",g->{JSONArray n=g.getJSONArray("nodes");for(int i=0;i<n.length();i++)if(IMAGE.equals(n.getJSONObject(i).getString("path"))){n.remove(i);break;}g.getJSONObject("envelope").put("visited",n.length());});
        rejectD("foreign_descendant_window_still_rejected",g->node(g,IMAGE).put("window_id",0));
        rejectD("unknown_census_gap_still_rejected",g->g.getJSONObject("envelope").put("child_omissions",1));
        rejectD("different_owner_still_rejected",g->g.getJSONObject("envelope").put("owner_sha256",QualificationScope.hash("synthetic different owner".getBytes(StandardCharsets.UTF_8))));
        rejectBoth("viewport_intersecting_search_and_navigation_still_rejected",g->bounds(node(g,REGION),0,200,1224,2992));
        one("pure_comparison_does_not_mutate_any_fixture_node_or_authority",()->{
            yes(Arrays.equals(raw,Files.readAllBytes(input)),"fixture file unchanged");
            yes(NativeSearchPlanning.equal(NativeSearchPlanning.snapshot(d),NativeSearchPlanning.map(copy("D"))),"entire immutable snapshot remains original derived values");
            yes(NativeSearchRole.compare(c,c).fullTreeEqual,"equal complete pair uses unchanged old semantics");
        });
        boolean all=true;for(Map<String,Object> row:cases)all&=Boolean.TRUE.equals(row.get("passed"));
        Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("schema","hepta.xiaomi-carousel-edge-host.v1");result.put("all_pass",all);
        result.put("cases",cases.size());result.put("assertions",assertions);result.put("case_results",cases);result.put("fixture_sha256",FIXTURE_SHA);
        result.put("fixture_authority_is_synthetic",true);result.put("actual_android_or_model_executed",false);result.put("input_dispatched",false);result.put("business_verified",false);
        byte[] encoded=(NativeSearchPlanning.json(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8);Files.write(output,encoded);System.out.write(encoded);
        if(!all)throw new AssertionError("one or more carousel edge cases failed");
    }
}
