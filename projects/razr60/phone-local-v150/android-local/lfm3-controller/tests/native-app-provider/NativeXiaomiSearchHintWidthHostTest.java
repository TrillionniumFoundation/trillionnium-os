package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;

/** Archived actual complete censuses, not Android observation or dispatch.
 * Mutant fixtures recompute references from their own actual synthetic bounds;
 * the three original fixture bytes are never rewritten or normalized. */
public final class NativeXiaomiSearchHintWidthHostTest {
    private static final String ENTRY="0/0/3",HINT=ENTRY+"/0",TERM=HINT+"/0",ICON="0/0/4";
    private static final List<String> NAMES=new ArrayList<String>();
    private static final List<Map<String,Object>> RESULTS=new ArrayList<Map<String,Object>>();
    private static final List<JSONObject> ORIGINALS=new ArrayList<JSONObject>();
    private static int assertions;
    private interface Work {void run() throws Exception;}
    private interface Change {void apply(JSONObject census);}
    private NativeXiaomiSearchHintWidthHostTest(){}
    private static void require(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void test(String name,Work work){
        NAMES.add(name);Map<String,Object> row=new LinkedHashMap<String,Object>();row.put("name",name);
        try{work.run();row.put("passed",true);}catch(Throwable failure){row.put("passed",false);row.put("failure",failure.toString());}
        RESULTS.add(row);
    }
    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    private static JSONObject census(JSONObject action){return action.getJSONObject("action_execution").getJSONObject("native_action_rejection_census");}
    private static JSONObject fresh(JSONObject action){return census(action).getJSONObject("fresh");}
    private static JSONObject node(JSONObject snap,String path){
        JSONArray rows=snap.getJSONArray("nodes");
        for(int i=0;i<rows.length();i++){JSONObject n=rows.getJSONObject(i);if(path.equals(n.getString("path")))return n;}
        throw new IllegalArgumentException("missing synthetic fixture path: "+path);
    }
    private static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject value){
        List<NativeActionSnapshotCheck.Node> rows=new ArrayList<NativeActionSnapshotCheck.Node>();
        JSONArray nodes=value.getJSONArray("nodes");for(int i=0;i<nodes.length();i++)rows.add(new NativeActionSnapshotCheck.Node(nodes.getJSONObject(i).toMap()));
        return new NativeActionSnapshotCheck.Snapshot(value.getJSONObject("envelope").toMap(),rows);
    }
    private static NativeActionSnapshotCheck.Intent intent(JSONObject action,String purpose,String path){
        JSONObject c=census(action),before=c.getJSONObject("before"),n=node(before,path);
        Map<String,Object> envelope=before.getJSONObject("envelope").toMap(),identity=new TreeMap<String,Object>();
        for(String key:NativeActionSnapshotCheck.IDENTITY)identity.put(key,envelope.get(key));
        JSONObject guard=action.getJSONObject("action_execution").getJSONObject("native_action_guard");
        return new NativeActionSnapshotCheck.Intent(purpose,before.getJSONObject("envelope").getString("package"),path,
                n.getString("label"),n.getString("ref_signature_sha256"),c.getString("model_run_id"),
                c.getString("original_node_id"),c.getString("original_action_sha256"),null,identity,
                guard.getLong("issued_elapsed_ms"),guard.getLong("deadline_elapsed_ms"));
    }
    private static Map<String,Object> compare(JSONObject action){return compare(action,NativeActionSnapshotCheck.SEARCH_ICON,ICON,0L);}
    private static Map<String,Object> compare(JSONObject action,String purpose,String path,long overrideNow){
        JSONObject c=census(action);return NativeActionSnapshotCheck.compare(intent(action,purpose,path),
                snapshot(c.getJSONObject("before")),snapshot(c.getJSONObject("fresh")),
                overrideNow==0L?c.getLong("compared_elapsed_ms"):overrideNow);
    }
    private static void rejected(JSONObject action,String purpose,String path,long now){
        try{compare(action,purpose,path,now);throw new AssertionError("changed protected facts were accepted");}
        catch(IllegalArgumentException expected){require(expected.getMessage()!=null&&!expected.getMessage().isEmpty(),"specific refusal missing");}
    }
    private static void rejected(Change change){
        JSONObject action=copy(ORIGINALS.get(0));change.apply(fresh(action));
        rejected(action,NativeActionSnapshotCheck.SEARCH_ICON,ICON,0L);
    }
    private static void bound(JSONObject n,int edge,int value){n.getJSONArray("bounds").put(edge,value);}
    private static boolean intersects(List<Integer> a,List<Integer> b){return a.get(0)<b.get(2)&&b.get(0)<a.get(2)&&a.get(1)<b.get(3)&&b.get(1)<a.get(3);}
    private static boolean flag(NativeActionSnapshotCheck.Node n,String name){return Boolean.TRUE.equals(n.v.get(name));}
    private static String base(NativeActionSnapshotCheck.Node n){
        String rect="Rect("+n.bounds.get(0)+", "+n.bounds.get(1)+" - "+n.bounds.get(2)+", "+n.bounds.get(3)+")";
        return NativeActionSnapshotCheck.hash(n.pkg+"\u0001"+n.v.get("window_id")+"\u0001"+n.cls+"\u0001"+n.view+"\u0001"+rect+"\u0001"
                +n.text+"\u0001"+n.desc+"\u0001"+flag(n,"enabled")+"|"+flag(n,"clickable")+"|"+flag(n,"editable")+"|"+flag(n,"scrollable"));
    }
    /** The production child collector is used only to construct internally
     * consistent negative fixtures. It neither refreshes nor authorizes a node. */
    private static void references(JSONObject value){
        final NativeActionSnapshotCheck.Snapshot snap=snapshot(value);
        for(String path:Arrays.asList(ENTRY,HINT,TERM)){
            final NativeActionSnapshotCheck.Node root=snap.node(path);
            ObservedChildText.Result child=ObservedChildText.collect(root,new ObservedChildText.Reader<NativeActionSnapshotCheck.Node>(){
                public ObservedChildText.Metadata metadata(NativeActionSnapshotCheck.Node n){
                    boolean click=flag(n,"clickable"),action=flag(n,"action_click"),input=flag(n,"editable");
                    return new ObservedChildText.Metadata(n.visible(),root.pkg.equals(n.pkg)&&root.v.get("window_id").equals(n.v.get("window_id"))
                            &&intersects(root.bounds,n.bounds),click,action,input,flag(n,"password"),click||action||input||flag(n,"scrollable")||flag(n,"checkable"));
                }
                public String text(NativeActionSnapshotCheck.Node n){return n.text;}
                public String description(NativeActionSnapshotCheck.Node n){return n.desc;}
                public String identity(NativeActionSnapshotCheck.Node n){return base(n);}
                public String viewId(NativeActionSnapshotCheck.Node n){return n.view;}
                public int childCount(NativeActionSnapshotCheck.Node n){return n.children;}
                public NativeActionSnapshotCheck.Node child(NativeActionSnapshotCheck.Node n,int i){return snap.node(n.path+"/"+i);}
                public void release(NativeActionSnapshotCheck.Node n){/* immutable test value */}
            });
            JSONObject actual=node(value,path);
            actual.put("label",ObservedTargetLabels.project(!root.text.isEmpty()?root.text:!root.desc.isEmpty()?root.desc:child.text));
            actual.put("ref_signature_sha256",NativeActionSnapshotCheck.hash(child.bind(base(root))+"\nscroll_actions="+root.v.get("scroll_actions")
                    +"\nime_enter="+root.v.get("ime_enter")+"|focused="+flag(root,"focused")+"|full_input="+root.v.get("input_sha256")));
        }
    }
    private static void geometry(String name,final String path,final int edge,final int delta){
        test(name,()->rejected(s->{JSONObject n=node(s,path);bound(n,edge,n.getJSONArray("bounds").getInt(edge)+delta);references(s);}));
    }
    private static void runCases(){
        for(int index=0;index<3;index++){
            final int n=index;
            test("actual_step_0"+(index+1)+"_hint_width_pair_preserves_same_search_icon",()->{
                JSONObject action=copy(ORIGINALS.get(n)),c=census(action);
                String unchanged=action.toString();
                require(!action.getBoolean("accepted")&&!action.getBoolean("dispatched")&&action.getBoolean("stale"),"actual original stale outcome");
                require(!action.getJSONObject("action_execution").getBoolean("effect_entered"),"no original effect entry");
                require(c.getBoolean("complete_two_censuses")&&!c.getBoolean("nodes_truncated")&&!c.getBoolean("grants_dispatch"),"full original census boundaries");
                require(snapshot(c.getJSONObject("before")).sha.equals(c.getJSONObject("before").getString("snapshot_sha256")),"original before census hash");
                require(snapshot(c.getJSONObject("fresh")).sha.equals(c.getJSONObject("fresh").getString("snapshot_sha256")),"original fresh census hash");
                require(snapshot(c.getJSONObject("before")).nodes.size()==77&&snapshot(c.getJSONObject("fresh")).nodes.size()==77,"actual 77-node census");
                require(node(c.getJSONObject("before"),ICON).similar(node(c.getJSONObject("fresh"),ICON)),"exact original target 27 fields");
                Map<String,Object> result=compare(action);
                require(Boolean.FALSE.equals(result.get("grants_dispatch"))&&Boolean.FALSE.equals(result.get("business_verified")),"comparison has no effect or business authority");
                require(Boolean.FALSE.equals(result.get("provider_frame_constructed"))&&Boolean.FALSE.equals(result.get("session_observed_called")),"no constructed app observation");
                require(Boolean.TRUE.equals(result.get("live_node_chain_window_and_one_effect_recheck_required")),"live guard still required");
                require(result.get("changed_paths").equals(Arrays.asList(ENTRY,HINT,TERM)),"only three actual changing hint paths");
                require(unchanged.equals(action.toString()),"original complete facts and bounds unchanged");
            });
        }
        test("fixture_reference_reconstruction_matches_original_actual_bytes",()->{
            for(JSONObject original:ORIGINALS)for(String which:Arrays.asList("before","fresh")){
                JSONObject data=copy(census(original).getJSONObject(which));String before=data.toString();references(data);
                require(before.equals(data.toString()),"reference builder must reproduce actual unmodified hints");
            }
        });
        test("literal_change_without_width_change_keeps_existing_icon_behavior",()->{
            JSONObject action=copy(ORIGINALS.get(0)),c=census(action);JSONArray old=node(c.getJSONObject("before"),TERM).getJSONArray("bounds");
            node(fresh(action),TERM).put("bounds",new JSONArray(old.toString()));references(fresh(action));
            require(Boolean.FALSE.equals(compare(action).get("grants_dispatch")),"old literal-only path remains a comparator");
        });
        test("same_literal_right_edge_resize_remains_contained_and_noninteractive",()->{
            JSONObject action=copy(ORIGINALS.get(0)),before=census(action).getJSONObject("before");
            node(fresh(action),TERM).put("text",node(before,TERM).getString("text"));
            node(fresh(action),HINT).put("description",node(before,HINT).getString("description"));references(fresh(action));
            require(Boolean.FALSE.equals(compare(action).get("grants_dispatch")),"contained decoration width only");
        });
        geometry("term_left_edge_change_is_refused_with_valid_recomputed_references",TERM,0,1);
        geometry("term_top_edge_change_is_refused_with_valid_recomputed_references",TERM,1,1);
        geometry("term_bottom_edge_change_is_refused_with_valid_recomputed_references",TERM,3,-1);
        test("term_right_edge_outside_hint_is_refused",()->rejected(s->{bound(node(s,TERM),2,node(s,HINT).getJSONArray("bounds").getInt(2)+1);references(s);}));
        test("zero_width_term_is_refused",()->rejected(s->{bound(node(s,TERM),2,node(s,TERM).getJSONArray("bounds").getInt(0));references(s);}));
        test("inverted_width_term_is_refused",()->rejected(s->{bound(node(s,TERM),2,node(s,TERM).getJSONArray("bounds").getInt(0)-1);references(s);}));
        geometry("fixed_hint_right_edge_change_is_refused",HINT,2,-1);
        geometry("fixed_entry_right_edge_change_is_refused",ENTRY,2,-1);
        geometry("search_icon_bounds_change_is_refused",ICON,2,-1);
        test("search_icon_overlapping_entry_is_refused",()->rejected(s->{bound(node(s,ICON),0,node(s,ENTRY).getJSONArray("bounds").getInt(2)-1);}));
        test("actual_root_bounds_change_is_refused",()->rejected(s->{bound(node(s,"0"),0,1);s.getJSONObject("envelope").getJSONArray("root_bounds").put(0,1);}));
        test("actual_parent_facts_change_is_refused",()->rejected(s->{node(s,"0/0").put("focused",true);}));
        for(String property:Arrays.asList("clickable","action_click","editable","scrollable","focused","password","selected","checkable","checked")){
            final String key=property;
            test("term_"+property+"_capability_is_refused",()->rejected(s->{node(s,TERM).put(key,true);references(s);}));
        }
        test("disabled_term_is_refused",()->rejected(s->{node(s,TERM).put("enabled",false);references(s);}));
        test("hidden_term_is_refused",()->rejected(s->{node(s,TERM).put("visible",false);references(s);}));
        test("hint_click_capability_is_refused",()->rejected(s->{node(s,HINT).put("clickable",true);node(s,HINT).put("action_click",true);references(s);}));
        test("term_input_binding_change_is_refused",()->rejected(s->{node(s,TERM).put("input_sha256",NativeActionSnapshotCheck.hash("unexpected input"));references(s);}));
        test("term_scroll_action_metadata_change_is_refused",()->rejected(s->{node(s,TERM).put("scroll_actions","hepta.observed-scroll-actions.v1|observed|forward");references(s);}));
        test("term_ime_action_metadata_change_is_refused",()->rejected(s->{node(s,TERM).put("ime_enter","hepta.observed-ime-enter.v1|true|true|6");references(s);}));
        test("term_class_or_resource_change_is_refused",()->{
            rejected(s->{node(s,TERM).put("class","android.widget.Button");references(s);});
            rejected(s->{node(s,TERM).put("view_id","com.xiaomi.shop:id/other");references(s);});
        });
        test("hint_description_must_match_same_actual_term",()->rejected(s->{node(s,HINT).put("description","搜索unrelated");references(s);}));
        test("forged_full_reference_or_projected_label_is_refused",()->{
            rejected(s->node(s,TERM).put("ref_signature_sha256",NativeActionSnapshotCheck.hash("forged reference")));
            rejected(s->node(s,ENTRY).put("label","invented title"));
        });
        test("purchase_or_results_role_change_is_refused",()->{
            rejected(s->{node(s,TERM).put("text","加入购物车");node(s,HINT).put("description","搜索加入购物车");references(s);});
            rejected(s->{node(s,TERM).put("text","综合");node(s,HINT).put("description","搜索综合");references(s);});
        });
        test("SEARCH_whole_entry_purpose_keeps_exact_original_target",()->{
            rejected(copy(ORIGINALS.get(0)),NativeActionSnapshotCheck.SEARCH,ENTRY,0L);
        });
        test("duplicate_search_icon_role_is_refused",()->rejected(s->{node(s,TERM).put("view_id","com.xiaomi.shop.plugin.homepage:id/searchIcon");references(s);}));
        test("foreign_node_package_or_window_is_refused",()->{
            rejected(s->node(s,TERM).put("package","foreign.app"));
            rejected(s->node(s,TERM).put("window_id",1364));
        });
        test("multiwindow_metadata_or_unknown_window_census_is_refused",()->{
            rejected(s->s.getJSONObject("envelope").put("reported_windows_sha256",NativeActionSnapshotCheck.hash("new modal window")));
            rejected(s->s.getJSONObject("envelope").put("reported_windows_complete",false));
            rejected(s->s.getJSONObject("envelope").put("window_metadata_sha256",NativeActionSnapshotCheck.hash("different window")));
        });
        test("display_or_rotation_or_IME_change_is_refused",()->{
            rejected(s->s.getJSONObject("envelope").put("display_id",266));
            rejected(s->s.getJSONObject("envelope").put("rotation",1));
            rejected(s->s.getJSONObject("envelope").put("ime_visibility","visible"));
        });
        test("task_owner_authorization_installation_and_generation_remain_exact",()->{
            for(String key:Arrays.asList("task_id","owner_sha256","authorization_sha256","selection_sha256","installed_set_sha256","goal_sha256","target_sha256")){
                final String field=key;rejected(s->s.getJSONObject("envelope").put(field,"task_id".equals(field)?"11111111111111111111111111111111":NativeActionSnapshotCheck.hash("changed "+field)));
            }
            rejected(s->s.getJSONObject("envelope").put("background_generation","11111111-1111-1111-1111-111111111111"));
        });
        test("missing_child_or_incomplete_census_is_refused",()->{
            rejected(s->s.getJSONObject("envelope").put("node_omissions",1));
            rejected(s->s.getJSONObject("envelope").put("full_native_complete",false));
            rejected(s->{JSONArray nodes=s.getJSONArray("nodes");for(int i=0;i<nodes.length();i++)if(TERM.equals(nodes.getJSONObject(i).getString("path"))){nodes.remove(i);break;}s.getJSONObject("envelope").put("visited",nodes.length());});
        });
        test("original_action_deadline_and_observation_age_are_not_extended",()->{
            JSONObject action=copy(ORIGINALS.get(0));long end=action.getJSONObject("action_execution").getJSONObject("native_action_guard").getLong("deadline_elapsed_ms");
            rejected(action,NativeActionSnapshotCheck.SEARCH_ICON,ICON,end);
            rejected(s->s.getJSONObject("envelope").put("captured_elapsed_ms",527000000));
        });
    }
    public static void main(String[] args)throws Exception{
        Path fixture=Paths.get(args[0]),out=Paths.get(args[1]);
        for(int n=1;n<=3;n++)ORIGINALS.add(new JSONObject(new String(Files.readAllBytes(fixture.resolve(String.format(java.util.Locale.ROOT,"step-%02d-action.json",n))),StandardCharsets.UTF_8)));
        runCases();boolean passed=true;for(Map<String,Object> result:RESULTS)passed&=Boolean.TRUE.equals(result.get("passed"));
        Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("schema","hepta.native-xiaomi-search-hint-width-host.v1");
        result.put("all_pass",passed);result.put("cases",RESULTS.size());result.put("assertions",assertions);result.put("case_names",NAMES);result.put("results",RESULTS);
        result.put("actual_census_pairs",3);result.put("actual_source_bytes_modified",false);result.put("negative_fixtures_synthetic",true);
        result.put("phone_operations",0);result.put("android_runtime",false);result.put("model_executed",false);result.put("business_verified",false);
        result.put("comparison_grants_dispatch",false);result.put("actual_live_rechecks_required",true);
        Files.write(out,(new JSONObject(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("Xiaomi hint width: "+RESULTS.size()+" cases / "+assertions+" assertions, all_pass="+passed);
        if(!passed)throw new AssertionError("see actual pair and negative-case results: "+out);
    }
}
