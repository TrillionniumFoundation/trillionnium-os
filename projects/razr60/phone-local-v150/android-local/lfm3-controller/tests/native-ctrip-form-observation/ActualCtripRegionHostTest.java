
package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.local.NativeActionSnapshotCheck.*;
public final class ActualCtripRegionHostTest {
    static int assertions;static final List<String> cases=new ArrayList<String>();
    static JSONObject originalA,originalZ;
    interface Body{void run()throws Exception;}
    interface Change{void run(JSONObject a,JSONObject z)throws Exception;}
    static void need(boolean x,String s){assertions++;if(!x)throw new AssertionError(s);}
    static void test(String name,Body body)throws Exception{body.run();cases.add(name);System.out.println("PASS "+name);}
    static JSONObject copy(JSONObject x){return new JSONObject(x.toString());}
    static JSONObject node(JSONObject raw,String path){JSONArray ns=raw.getJSONArray("nodes");for(int i=0;i<ns.length();i++){JSONObject n=ns.getJSONObject(i);if(path.equals(n.getString("path")))return n;}throw new IllegalArgumentException(path);}
    static Snapshot snap(JSONObject raw){List<Node> nodes=new ArrayList<Node>();JSONArray n=raw.getJSONArray("nodes");for(int i=0;i<n.length();i++)nodes.add(new Node(n.getJSONObject(i).toMap()));return new Snapshot(raw.getJSONObject("envelope").toMap(),nodes);}
    static Map<String,Object> observe(JSONObject a,JSONObject z){return NativeCtripFormObservation.compare(snap(a),snap(z));}
    static Map<String,Object> action(JSONObject a,JSONObject z,String purpose,String path){
        Snapshot old=snap(a),fresh=snap(z);Node target=old.node(path);Map<String,Object> binding=new TreeMap<String,Object>();
        for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY)binding.put(key,old.env.get(key));
        long start=((Number)old.env.get("captured_elapsed_ms")).longValue()+1,now=((Number)fresh.env.get("captured_elapsed_ms")).longValue()+1;
        Intent in=new Intent(purpose,NativeActionSnapshotCheck.CTRIP,path,target.label,(String)target.v.get("ref_signature_sha256"),
            "11111111111111111111111111111111","n1",NativeActionSnapshotCheck.hash("host synthetic action"),
            NativeActionSnapshotCheck.hash("host synthetic existing query history"),binding,start,start+8000);
        return NativeActionSnapshotCheck.compare(in,old,fresh,now);
    }
    static void refuse(Body body)throws Exception{boolean rejected=false;try{body.run();}catch(IllegalArgumentException expected){rejected=true;need(expected.getMessage()!=null,"reason");}need(rejected,"must refuse");}
    static void negative(String name,Change change)throws Exception{test(name,()->{JSONObject a=copy(originalA),z=copy(originalZ);change.run(a,z);refuse(()->observe(a,z));refuse(()->action(a,z,NativeActionSnapshotCheck.YEAR,"0/0/2/5"));});}
    static void both(JSONObject a,JSONObject z,String p,String key,Object value){node(a,p).put(key,value);node(z,p).put(key,value);}
    public static void main(String[] args)throws Exception{
        Path input=Paths.get(args[0]),out=Paths.get(args[1]);
        boolean originalRows=Files.isDirectory(input);
        if(originalRows){
            originalA=new JSONObject(new String(Files.readAllBytes(input.resolve("before.json")),StandardCharsets.UTF_8));
            originalZ=new JSONObject(new String(Files.readAllBytes(input.resolve("after.json")),StandardCharsets.UTF_8));
        }else{
            JSONObject fixture=new JSONObject(new String(Files.readAllBytes(input),StandardCharsets.UTF_8));
            originalA=new JSONObject().put("envelope",fixture.getJSONObject("before_envelope")).put("nodes",fixture.getJSONArray("before"));
            originalZ=new JSONObject().put("envelope",fixture.getJSONObject("after_envelope")).put("nodes",fixture.getJSONArray("after"));
        }
        Map<String,Object> actual=observe(originalA,originalZ);
        test("actual_complete_276_pair_21_changes_classified",()->{
            need(((Number)actual.get("before_visited_nodes")).intValue()==276,"all before nodes");
            need(((Number)actual.get("after_visited_nodes")).intValue()==276,"all after nodes");
            need(((List<?>)actual.get("changed_paths")).size()==21,"21 actual differences");
            need(actual.containsKey("ctrip_form_action_region"),"narrow actual region proof");
            need(Boolean.FALSE.equals(actual.get("grants_action_authority")),"read only");
        });
        test("actual_fresh_date_action_same_scope",()->need(action(originalA,originalZ,NativeActionSnapshotCheck.YEAR,"0/0/2/5").containsKey("ctrip_form_action_region"),"shared date classifier"));
        test("actual_fresh_query_action_same_scope",()->need(action(originalA,originalZ,NativeActionSnapshotCheck.QUERY,"0/0/2/13").containsKey("ctrip_form_action_region"),"shared query classifier"));
        test("no_blanket_banner_overlay_claim",()->{
            Map<?,?> p=(Map<?,?>)actual.get("ctrip_form_action_region");
            need(Boolean.TRUE.equals(p.get("overlap_with_trip_tabs_admitted")),"actual overlapping tabs acknowledged");
            need(Boolean.FALSE.equals(p.get("alpha_or_z_order_assumed")),"no alpha inference");
            need(Boolean.FALSE.equals(p.get("parent_clipping_assumed")),"no clipping inference");
            need(Boolean.FALSE.equals(p.get("whole_screen_pixels_stable")),"no full-screen equality");
            need(((Map<?,?>)p.get("form_purpose_target_paths")).size()==2,"only date/query proof targets");
        });
        negative("banner_moves_into_date_body",(a,z)->both(a,z,"0/0/0","bounds",new JSONArray(Arrays.asList(0,0,1224,900))));
        negative("raw_image_escapes_parent_into_target",(a,z)->both(a,z,"0/0/0/1/0","bounds",new JSONArray(Arrays.asList(3,0,1224,950))));
        negative("visible_sibling_overlay_hits_date",(a,z)->{both(a,z,"0/6","visible",true);both(a,z,"0/6","bounds",new JSONArray(Arrays.asList(79,793,415,937)));});
        negative("visible_sibling_overlay_hits_query",(a,z)->{both(a,z,"0/6","visible",true);both(a,z,"0/6","bounds",new JSONArray(Arrays.asList(79,1131,1145,1263)));});
        negative("banner_unknown_scroll_capability",(a,z)->both(a,z,"0/0/0","scroll_actions","hepta.observed-scroll-actions.v1|unknown"));
        negative("banner_tap_capability",(a,z)->{both(a,z,"0/0/0/1/0","clickable",true);both(a,z,"0/0/0/1/0","action_click",true);});
        negative("banner_focused_input",(a,z)->both(a,z,"0/0/0/1/0","focused",true));
        negative("banner_editable",(a,z)->both(a,z,"0/0/0/1/0","editable",true));
        negative("banner_unknown_ime",(a,z)->both(a,z,"0/0/0/1/0","ime_enter","unknown"));
        negative("banner_unknown_input_hash",(a,z)->both(a,z,"0/0/0/1/0","input_sha256",NativeActionSnapshotCheck.hash("input")));
        negative("banner_vertical_motion",(a,z)->node(z,"0/0/0/1/0").put("bounds",new JSONArray(Arrays.asList(3,1,1224,587))));
        negative("banner_unknown_image_identity",(a,z)->both(a,z,"0/0/0/1/0","description","其他素材"));
        negative("banner_unknown_view_class",(a,z)->both(a,z,"0/0/0/1/0","class","app.CustomCanvas"));
        negative("banner_unknown_alpha_metadata",(a,z)->both(a,z,"0/0/0/1/0","alpha",0.2));
        negative("form_date_semantics_changed",(a,z)->node(z,"0/0/2/5").put("text","11月27日后天"));
        negative("form_city_changed",(a,z)->node(z,"0/0/2/1").put("text","南京"));
        negative("form_tab_selection_changed",(a,z)->node(z,"0/0/2/0/1").put("selected",true));
        negative("form_other_control_changes",(a,z)->node(z,"0/0/2/12").put("enabled",false));
        negative("owner_replaced",(a,z)->z.getJSONObject("envelope").put("owner_sha256",NativeActionSnapshotCheck.hash("foreign")));
        negative("installation_replaced",(a,z)->z.getJSONObject("envelope").put("installed_set_sha256",NativeActionSnapshotCheck.hash("foreign")));
        negative("ime_popup",(a,z)->z.getJSONObject("envelope").put("ime_visibility","visible"));
        negative("complete_node_omission",(a,z)->z.getJSONObject("envelope").put("node_omissions",1));
        test("trip_tab_not_a_form_purpose_target",()->refuse(()->action(originalA,originalZ,NativeActionSnapshotCheck.YEAR,"0/0/2/0/1")));
        test("city_not_a_form_purpose_target",()->refuse(()->action(originalA,originalZ,NativeActionSnapshotCheck.QUERY,"0/0/2/1")));
        test("date_not_query_target",()->refuse(()->action(originalA,originalZ,NativeActionSnapshotCheck.QUERY,"0/0/2/5")));
        test("query_not_year_target",()->refuse(()->action(originalA,originalZ,NativeActionSnapshotCheck.YEAR,"0/0/2/13")));
        test("original_12_second_pair_bound",()->{JSONObject z=copy(originalZ);z.getJSONObject("envelope").put("captured_elapsed_ms",originalA.getJSONObject("envelope").getLong("captured_elapsed_ms")+12001);refuse(()->observe(originalA,z));});
        test("compact_proof_keeps_full_artifact_digest",()->{
            int bytes=new JSONObject(actual).toString().getBytes(StandardCharsets.UTF_8).length;
            Map<String,Object> compact=NativeCtripFormObservation.captureSummary(actual,"11111111111111111111111111111111-form-history.json",bytes,NativeActionSnapshotCheck.hash("synthetic file bytes"),"pre_encoding");
            int compactBytes=new JSONObject(compact).toString().getBytes(StandardCharsets.UTF_8).length;
            need(!compact.containsKey("literal_form_facts")&&compact.containsKey("literal_form_facts_sha256"),"full facts not duplicated in bounded capture");
            need(compact.containsKey("complete_comparison_artifact"),"immutable full artifact reference");
            System.out.println("ACTUAL_PROOF_BYTES "+bytes+" COMPACT_BYTES "+compactBytes+" DOUBLE_PLUS_METADATA "+(2*compactBytes+2500));
        });
        JSONObject result=new JSONObject().put("all_pass",true).put("cases",cases.size()).put("assertions",assertions).put("case_names",cases)
            .put("raw_census_nodes_preserved",originalRows).put("actual_geometry_with_host_identity",!originalRows).put("synthetic_host_envelope_adaptation",true).put("phone_operations",0).put("grants_device_authority",false)
            .put("actual_pair_comparison",new JSONObject(actual));
        Files.write(out,result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS "+cases.size()+" cases / "+assertions+" assertions");
    }
}
