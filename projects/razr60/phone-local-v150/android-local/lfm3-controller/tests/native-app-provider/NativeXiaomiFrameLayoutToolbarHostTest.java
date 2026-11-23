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

/** Exact archived complete App records. Observed node values, positions, bounds,
 * signatures, collection and window fields are retained. Task authorization and
 * completion bindings around the pure Frame are explicit host values; no Android
 * traversal, live NodeRef, model, dispatch or business success is claimed. */
public final class NativeXiaomiFrameLayoutToolbarHostTest {
    private static final String OWNER="在小米商城查询AX3000T价格";
    private static final NativeAppGoal GOAL=NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE);
    private static final String[] FILES={"step-03-before.json","step-04-before.json","step-05-before.json"};
    private static final String[] HASHES={"1f2bf304f716adf64c19757688cc8b4590204992cf2cb36c6770c2801d17930c",
        "5d8b88f9f319f90af473a4ea9b2e8645a716b7f253c99539765c6d39c152c5fc",
        "9a0a0181927f0f9d2ed625b65fd2039e7cff1c2fb770b39d512810f3dc4a7107"};
    private static final int[] SIZES={14991,93716,111897},COUNTS={7,56,67};
    private static final List<JSONObject> originals=new ArrayList<JSONObject>();
    private static final List<String> names=new ArrayList<String>();
    private static final List<Map<String,Object>> results=new ArrayList<Map<String,Object>>();
    private static int assertions;
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
    private static JSONObject copy(JSONObject j){return new JSONObject(j.toString());}
    private static JSONObject at(JSONObject r,String path){
        JSONArray nodes=r.getJSONArray("nodes");for(int i=0;i<nodes.length();i++){
            JSONObject n=nodes.getJSONObject(i);if(path.equals(n.getJSONObject("native_tree_position").getString("path")))return n;
        }throw new IllegalArgumentException("fixture native path absent: "+path);
    }
    private static void remove(JSONObject r,String path){
        JSONArray nodes=r.getJSONArray("nodes");for(int i=0;i<nodes.length();i++)if(path.equals(nodes.getJSONObject(i).getJSONObject("native_tree_position").getString("path"))){
            nodes.remove(i);r.getJSONObject("collection").put("retained_nodes",nodes.length());return;
        }throw new IllegalArgumentException("fixture native path absent");
    }
    private static void move(JSONObject r,String old,String replacement){
        JSONArray nodes=r.getJSONArray("nodes");for(int i=0;i<nodes.length();i++){
            JSONObject pos=nodes.getJSONObject(i).getJSONObject("native_tree_position");String p=pos.getString("path");
            if(p.equals(old)||p.startsWith(old+"/"))pos.put("path",replacement+p.substring(old.length()));
        }
    }
    private static NativeAppEvidence.Frame frame(JSONObject r,String originalHash){
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
        JSONObject window=r.getJSONObject("window"),collection=r.getJSONObject("collection"),background=r.getJSONObject("background_session");
        JSONArray bounds=window.getJSONArray("bounds");boolean complete=collection.getInt("retained_nodes")==nodes.size()
            &&collection.getInt("pending_nodes_at_stop")==0&&collection.getLong("child_slots_omitted_by_traversal_limit")==0
            &&collection.getInt("nodes_omitted_by_node_limit")==0&&collection.getInt("nodes_omitted_by_text_limit")==0;
        return new NativeAppEvidence.Frame("11111111111111111111111111111111",GOAL.ownerSha256,hash("explicit-host-target"),hash("explicit-host-auth"),
            hash("explicit-host-selection"),r.getString("observation_id"),r.getString("package"),background.getString("generation"),
            r.getString("app_tree_sha256"),r.getString("observation_state_sha256"),r.getString("screen_sha256"),originalHash,
            hash("explicit-host-completion:"+originalHash),window.getInt("display_id"),r.getInt("window_id"),r.getInt("rotation"),
            r.getInt("screen_width"),r.getInt("screen_height"),bounds.getInt(0),bounds.getInt(1),bounds.getInt(2),bounds.getInt(3),
            r.getLong("captured_elapsed_ms"),r.getBoolean("nodes_truncated"),complete,nodes,window.getInt("type"),"observed".equals(window.getString("metadata_status")));
    }
    private static NativeXiaomiProductPage.Page inspect(JSONObject r){return NativeXiaomiProductPage.inspect(GOAL,frame(r,hash("explicit-mutant-record:"+r.toString())));}
    private static void inputOnly(NativeXiaomiProductPage.Page p){
        check("search_input".equals(p.phase),"complete actual toolbar must be recognized");
        check(p.editValues.equals(Collections.singletonMap("n1","AX3000T")),"only immutable owner literal may be offered to the real EditText");
        check(p.clickIds.isEmpty()&&p.quote==null,"recognition does not click or claim a price");
        check(p.purposes.equals(Collections.singletonMap("n1","set_product_query")),"original input target is preserved");
    }
    private static void unavailable(JSONObject r){
        try{NativeXiaomiProductPage.Page p=inspect(r);check(p.editValues.isEmpty()&&p.clickIds.isEmpty()&&p.quote==null,"mutated toolbar must grant no action or quote");}
        catch(IllegalArgumentException rejected){check(rejected.getMessage()!=null,"malformed Frame refused explicitly");}
    }
    private static void mutation(String name,Change change){one(name,()->{JSONObject r=copy(originals.get(0));change.apply(r);unavailable(r);});}
    private static void cases()throws Exception{
        for(int i=0;i<FILES.length;i++){final int index=i;one("actual_complete_"+COUNTS[i]+"_node_frame_grants_only_original_query_field",()->{
            JSONObject r=originals.get(index);check(r.getJSONArray("nodes").length()==COUNTS[index],"original complete population");
            inputOnly(NativeXiaomiProductPage.inspect(GOAL,frame(r,HASHES[index])));
        });}
        one("original_empty_input_label_and_real_two_TextView_sources_are_preserved",()->{
            NativeAppEvidence.Frame f=frame(originals.get(0),HASHES[0]);NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,f);inputOnly(p);
            check(f.byId.get("n1").label.isEmpty()&&f.byId.get("n1").text.isEmpty(),"no input label or text fabricated");
            check("0/0/0".equals(f.byId.get("n5").path)&&"0/4/0".equals(f.byId.get("n6").path)
                &&"搜索".equals(f.byId.get("n5").text)&&"搜索".equals(f.byId.get("n6").text),"real independent native label nodes");
            check(p.evidence().toString().contains("observed_frame_layout_direct_children.v1"),"new closed shape recorded");
        });
        one("synthetic_exact_owner_readback_offers_only_right_normal_search",()->{
            JSONObject r=copy(originals.get(0));at(r,"0/1").put("text","AX3000T");NativeXiaomiProductPage.Page p=inspect(r);
            check("search_submit".equals(p.phase)&&p.clickIds.equals(Collections.singleton("n3"))&&p.editValues.isEmpty(),"right observed normal button only");
            check(p.purposes.equals(Collections.singletonMap("n3","submit_product_query"))&&p.quote==null,"no mode-toggle, blank Back, suggestion or quote authority");
        });
        one("different_or_case_changed_existing_query_is_replaced_only_by_owner_literal",()->{
            for(String text:Arrays.asList("ax3000t","其他商品")){JSONObject r=copy(originals.get(0));at(r,"0/1").put("text",text);inputOnly(inspect(r));}
        });
        mutation("field_parent_class_must_be_the_observed_FrameLayout",r->at(r,"0/1").getJSONObject("native_tree_position").put("parent_class","android.widget.LinearLayout"));
        mutation("field_slot_is_exact_and_does_not_use_other_editable_positions",r->move(r,"0/1","0/3"));
        mutation("same_looking_toolbar_at_another_parent_path_is_not_admitted",r->{move(r,"0","0/9");});
        for(String flag:Arrays.asList("clickable","editable","enabled","scrollable","password")){
            final String key=flag;mutation("query_field_"+key+"_capability_is_bound",r->at(r,"0/1").put(key,"scrollable".equals(key)||"password".equals(key)));
        }
        mutation("query_field_class_is_exact",r->at(r,"0/1").put("class_name","android.widget.TextView"));
        mutation("query_field_resource_is_not_inferred_from_another_control",r->at(r,"0/1").put("view_id","foreign:id/input"));
        mutation("multiple_editable_query_fields_are_refused",r->{JSONObject extra=copy(at(r,"0/1")).put("id","n99");
            extra.getJSONObject("native_tree_position").put("path","0/8");r.getJSONArray("nodes").put(extra);r.getJSONObject("collection").put("retained_nodes",8);});
        for(String path:Arrays.asList("0/0","0/4")){
            final String p=path;mutation("missing_"+p.replace('/','_')+"_button_is_not_reconstructed",r->remove(r,p));
            mutation("missing_"+p.replace('/','_')+"_real_label_does_not_use_derived_text",r->remove(r,p+"/0"));
            mutation("nonclickable_"+p.replace('/','_')+"_button_is_not_promoted",r->at(r,p).put("clickable",false));
            mutation("foreign_parent_of_"+p.replace('/','_')+"_button_is_refused",r->at(r,p).getJSONObject("native_tree_position").put("parent_class","android.view.ViewGroup"));
            mutation("interactive_"+p.replace('/','_')+"_TextView_label_is_refused",r->at(r,p+"/0").put("clickable",true));
            mutation("nonliteral_"+p.replace('/','_')+"_label_is_refused",r->at(r,p+"/0").put("text","AI搜索"));
        }
        mutation("normal_button_slot_cannot_fall_back_to_legacy_index",r->move(r,"0/4","0/3"));
        mutation("normal_label_must_be_the_observed_direct_child_zero",r->move(r,"0/4/0","0/4/1"));
        mutation("normal_label_must_be_within_its_real_clickable_parent",r->at(r,"0/4/0").getJSONArray("bounds").put(0,80));
        mutation("normal_and_mode_toggle_geometry_cannot_be_swapped",r->at(r,"0/4").put("bounds",new JSONArray(Arrays.asList(81,328,367,421))));
        mutation("normal_button_must_cover_the_observed_input_right_edge",r->{at(r,"0/4").getJSONArray("bounds").put(2,1070);at(r,"0/4/0").getJSONArray("bounds").put(2,1060);});
        mutation("toolbar_buttons_must_share_the_observed_vertical_row",r->{at(r,"0/4").put("bounds",new JSONArray(Arrays.asList(958,500,1142,600)));
            at(r,"0/4/0").put("bounds",new JSONArray(Arrays.asList(999,510,1101,580)));});
        for(String path:Arrays.asList("0/1","0/0","0/4","0/0/0","0/4/0")){
            final String p=path;mutation("unknown_selection_"+p.replace('/','_')+"_is_refused",r->at(r,p).getJSONObject("native_selection_state").put("observed",false));
            mutation("checked_or_selected_"+p.replace('/','_')+"_is_refused",r->at(r,p).getJSONObject("native_selection_state").put("checked",true));
            mutation("scroll_action_"+p.replace('/','_')+"_is_refused",r->at(r,p).put("scroll_directions",new JSONArray().put("down")));
        }
        mutation("extra_same_toolbar_search_label_is_ambiguous",r->{JSONObject n=copy(at(r,"0/4/0")).put("id","n99");
            n.getJSONObject("native_tree_position").put("path","0/4/1");r.getJSONArray("nodes").put(n);r.getJSONObject("collection").put("retained_nodes",8);});
        mutation("foreign_node_package_cannot_borrow_toolbar",r->at(r,"0/2").put("package","foreign.app"));
        mutation("truncated_frame_grants_no_toolbar_action",r->r.put("nodes_truncated",true));
        mutation("incomplete_collection_grants_no_toolbar_action",r->r.getJSONObject("collection").put("pending_nodes_at_stop",1));
        mutation("unobserved_window_metadata_grants_no_toolbar_action",r->r.getJSONObject("window").put("metadata_status","unknown"));
        mutation("nonapplication_window_grants_no_toolbar_action",r->r.getJSONObject("window").put("type",2));
        mutation("main_display_is_never_a_native_background_frame",r->r.getJSONObject("window").put("display_id",0));
        one("a_different_immutable_owner_cannot_reuse_the_same_frame",()->{
            NativeAppEvidence.Frame f=frame(originals.get(0),HASHES[0]);boolean rejected=false;
            try{NativeXiaomiProductPage.inspect(NativeAppGoal.parse("请在小米商城查询AX3000T价格",NativeAppGoal.XIAOMI_PACKAGE),f);}
            catch(IllegalArgumentException expected){rejected=true;}check(rejected,"same observed shape cannot replace immutable owner");
        });
    }
    public static void main(String[] args)throws Exception{
        Path root=Paths.get(args[0]),out=Paths.get(args[1]);
        for(int i=0;i<FILES.length;i++){byte[] raw=Files.readAllBytes(root.resolve(FILES[i]));
            check(raw.length==SIZES[i]&&hash(new String(raw,StandardCharsets.UTF_8)).equals(HASHES[i]),"exact unchanged archived fixture bytes");
            originals.add(new JSONObject(new String(raw,StandardCharsets.UTF_8)));
        }
        cases();boolean pass=true;for(Map<String,Object> row:results)pass&=Boolean.TRUE.equals(row.get("passed"));
        JSONObject record=new JSONObject().put("schema","hepta.native-xiaomi-frame-layout-toolbar-host.v1").put("all_pass",pass)
            .put("cases",names.size()).put("assertions",assertions).put("case_names",names).put("results",results)
            .put("fixture_sha256",new JSONArray(Arrays.asList(HASHES))).put("source_bytes_modified",false)
            .put("actual_observed_node_values_preserved",true).put("task_authorization_and_completion_bindings_synthetic",true)
            .put("mutations_are_explicit_host_values",true).put("android_runtime",false).put("model_executed",false)
            .put("platform_dispatch_executed",false).put("phone_operations",0).put("business_verified",false);
        Files.write(out,(record.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(record);
        if(!pass)throw new AssertionError("actual toolbar regression failed");
    }
}
