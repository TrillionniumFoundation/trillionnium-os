package org.trillionnium.hepta.local;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.NativeActionSnapshotCheck.Intent;
import org.trillionnium.hepta.local.NativeActionSnapshotCheck.Node;
import org.trillionnium.hepta.local.NativeActionSnapshotCheck.Snapshot;

/** Actual immutable records plus explicitly derived complete-census host cases.
 * The failed actions' complete fresh censuses were not archived. No case claims
 * to replay those missing values or to grant a live Android action. */
public final class NativeCtripCaptionHostTest {
    private static final String[] OBS={
        "4438ee67817a433aa8e1d88b1f48c994",
        "6afece2af5ce4717b68731456beeb64c",
        "a999b83d176145d9894501221f4b9c80"};
    private static final String[] REFUSAL={
        "0/0/0/1/1","0/0/0/0/1","0/0/0/1/1"};
    private static final String INSTALLED="e46e6fe28b25b74f5b305d5d0437d4d7018d341da848c9acd1cb0aae63be7cd1";
    private static final String VISIBLE="0/0/0/1/1",HIDDEN="0/0/0/0/1",DATE="0/0/2/5",QUERY="0/0/2/13";
    private static final String CP="ctrip.android.view:id/";
    private static int assertions;
    private static final List<String> cases=new ArrayList<String>();
    private interface Body { void run()throws Exception; }
    private interface Change { void run(JSONObject a,JSONObject z)throws Exception; }
    private static final class Record {
        final int step;final JSONObject ax,action;
        Record(int step,JSONObject ax,JSONObject action){this.step=step;this.ax=ax;this.action=action;}
    }
    private static void need(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(String name,Body body)throws Exception{
        need(!cases.contains(name),"unique case name");body.run();cases.add(name);System.out.println("PASS "+name);
    }
    private static JSONObject copy(JSONObject raw){return new JSONObject(raw.toString());}
    private static JSONObject load(Path path)throws Exception{return new JSONObject(new String(Files.readAllBytes(path),StandardCharsets.UTF_8));}
    private static JSONObject node(JSONObject census,String path){
        JSONArray values=census.getJSONArray("nodes");
        for(int i=0;i<values.length();i++){JSONObject n=values.getJSONObject(i);if(path.equals(n.getString("path")))return n;}
        throw new IllegalArgumentException("missing actual node "+path);
    }
    private static boolean visible(JSONObject node){
        JSONArray r=node.getJSONArray("bounds");return node.getBoolean("visible")&&r.getInt(2)>r.getInt(0)&&r.getInt(3)>r.getInt(1);
    }
    /** Fixture transformation using the exact public NodeRef value format.
     * Only a clearly derived host census is changed, never the input records. */
    private static void caption(JSONObject census,String path,String text){
        JSONObject n=node(census,path);n.put("text",text);
        if(!visible(n)){n.put("label",JSONObject.NULL);n.put("ref_signature_sha256",JSONObject.NULL);return;}
        n.put("label",text);JSONArray r=n.getJSONArray("bounds");
        String rectangle="Rect("+r.getInt(0)+", "+r.getInt(1)+" - "+r.getInt(2)+", "+r.getInt(3)+")";
        String sep="\u0001";
        String base=NativeActionSnapshotCheck.hash(n.getString("package")+sep+n.getInt("window_id")+sep
            +n.getString("class")+sep+n.getString("view_id")+sep+rectangle+sep+n.getString("text")+sep
            +n.getString("description")+sep+n.getBoolean("enabled")+"|"+n.getBoolean("clickable")+"|"
            +n.getBoolean("editable")+"|"+n.getBoolean("scrollable"));
        String full=ObservedChildText.notApplicable().bind(base)+"\nscroll_actions="+n.getString("scroll_actions")
            +"\nime_enter="+n.getString("ime_enter")+"|focused="+n.getBoolean("focused")+"|full_input="
            +(n.isNull("input_sha256")?"null":n.getString("input_sha256"));
        n.put("ref_signature_sha256",NativeActionSnapshotCheck.hash(full));
    }
    private static Snapshot snapshot(Record record,JSONObject census){
        try{
            Method adapter=NativeCtripFormObservation.class.getDeclaredMethod("axSnapshot",Map.class,Map.class,String.class);
            adapter.setAccessible(true);
            return (Snapshot)adapter.invoke(null,census.toMap(),record.ax.getJSONObject("binding").toMap(),INSTALLED);
        }catch(InvocationTargetException failure){
            Throwable cause=failure.getCause();if(cause instanceof IllegalArgumentException)throw(IllegalArgumentException)cause;
            throw new IllegalStateException("production AX adapter failed",cause);
        }catch(ReflectiveOperationException failure){throw new IllegalStateException(failure);}
    }
    private static Map<String,Object> observe(Record record,JSONObject a,JSONObject z){
        return NativeCtripFormObservation.compareAxCensuses(a.toMap(),z.toMap(),record.ax.getJSONObject("binding").toMap(),INSTALLED);
    }
    private static Map<String,Object> action(Record record,JSONObject a,JSONObject z,String purpose){
        Snapshot old=snapshot(record,a),fresh=snapshot(record,z);
        String path=NativeActionSnapshotCheck.YEAR.equals(purpose)?DATE:QUERY;Node target=old.node(path);
        Map<String,Object> binding=new TreeMap<String,Object>();
        for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY)binding.put(key,old.env.get(key));
        long start=((Number)old.env.get("captured_elapsed_ms")).longValue()+1;
        long now=((Number)fresh.env.get("captured_elapsed_ms")).longValue()+1;
        Intent intent=new Intent(purpose,NativeActionSnapshotCheck.CTRIP,path,target.label,
            (String)target.v.get("ref_signature_sha256"),"11111111111111111111111111111111","n33",
            NativeActionSnapshotCheck.hash("explicit host comparator probe"),
            NativeActionSnapshotCheck.QUERY.equals(purpose)?NativeActionSnapshotCheck.hash("explicit synthetic query-history binding"):null,
            binding,start,start+8000);
        return NativeActionSnapshotCheck.compare(intent,old,fresh,now);
    }
    private static void refuse(Body body)throws Exception{
        boolean rejected=false;
        try{body.run();}catch(IllegalArgumentException expected){rejected=true;need(expected.getMessage()!=null&&!expected.getMessage().isEmpty(),"retained refusal reason");}
        need(rejected,"changed or incomplete scope must refuse");
    }
    private static JSONObject[] pair(Record record){
        JSONObject a=copy(record.ax.getJSONObject("first")),z=copy(record.ax.getJSONObject("second"));
        caption(a,VISIBLE,"活动");caption(z,VISIBLE,"广告");return new JSONObject[]{a,z};
    }
    private static void assertCandidate(Record record,JSONObject a,JSONObject z){
        Map<String,Object> history=observe(record,a,z);
        need(Boolean.FALSE.equals(history.get("grants_action_authority")),"history supplies no action authority");
        need(Boolean.FALSE.equals(history.get("business_completion_verified")),"history is not a business result");
        need(Boolean.FALSE.equals(history.get("published_pair_is_current_tree_claimed")),"no current-tree claim");
        for(String purpose:Arrays.asList(NativeActionSnapshotCheck.YEAR,NativeActionSnapshotCheck.QUERY)){
            Map<String,Object> proof=action(record,a,z,purpose);
            need(Boolean.FALSE.equals(proof.get("grants_dispatch")),"comparison cannot dispatch");
            need(Boolean.FALSE.equals(proof.get("query_history_proved_by_comparator")),"no query history manufactured");
            need(Boolean.FALSE.equals(proof.get("business_verified")),"no business success manufactured");
            need(Boolean.TRUE.equals(proof.get("live_node_chain_window_and_one_effect_recheck_required")),"final live checks required");
            need(Collections.singletonList("0/0/2").equals(proof.get("protected_subtrees")),"whole form protected");
            Object rawRegion=proof.get("ctrip_form_action_region");
            need(rawRegion instanceof Map,"exact passive banner region must be proved");
            Map<?,?> region=(Map<?,?>)rawRegion;
            need(Arrays.asList("活动","广告").equals(region.get("banner_caption_literals")),"only the two recorded literals");
            need(Boolean.TRUE.equals(region.get("caption_change_requires_actual_reference")),"changed caption has actual reference");
            need(Boolean.FALSE.equals(region.get("parent_clipping_assumed")),"no manufactured clipped rectangle");
            need(Boolean.FALSE.equals(region.get("alpha_or_z_order_assumed")),"no inferred alpha or draw ordering");
        }
    }
    private static void negative(String name,Record record,Change change)throws Exception{
        test(name,()->{JSONObject[] p=pair(record);change.run(p[0],p[1]);
            refuse(()->observe(record,p[0],p[1]));
            refuse(()->action(record,p[0],p[1],NativeActionSnapshotCheck.YEAR));
            refuse(()->action(record,p[0],p[1],NativeActionSnapshotCheck.QUERY));
        });
    }
    private static void both(JSONObject a,JSONObject z,String path,String key,Object value){
        node(a,path).put(key,value);node(z,path).put(key,value);
    }
    private static void child(JSONObject census){
        JSONObject label=node(census,VISIBLE);label.put("children",1);
        JSONObject extra=copy(label);extra.put("path",VISIBLE+"/0");extra.put("parent_class","android.widget.TextView");
        extra.put("children",0);extra.put("view_id","");extra.put("text","");extra.put("label",JSONObject.NULL);
        extra.put("ref_signature_sha256",JSONObject.NULL);extra.put("visible",false);
        census.getJSONArray("nodes").put(extra);census.put("visited",census.getJSONArray("nodes").length());
    }
    /** Explicit complete-census combinations. All changed references are first
     * accepted by the production reference checker; a stale hash cannot satisfy
     * any of these negative cases. These are host variants, not missing device D. */
    private static final List<Map<String,Object>> combinationEvidence=new ArrayList<Map<String,Object>>();
    private static void checkCombinationReferences(Record r,JSONObject a,JSONObject z,String... paths){
        for(JSONObject census:Arrays.asList(a,z)){
            Snapshot snap=snapshot(r,census);
            for(String path:paths){
                NativeActionSnapshotCheck.requireSearchInputReference(snap,snap.node(path));
                need(true,"actual complete reference validates before the comparison");
            }
        }
    }
    private static void moveCaption(JSONObject census,String path,int dx,boolean shown,String text){
        JSONObject value=node(census,path);JSONArray b=value.getJSONArray("bounds");
        b.put(0,b.getInt(0)+dx);b.put(2,b.getInt(2)+dx);value.put("visible",shown);
        caption(census,path,text);
    }
    private static String exactRefusal(Body body,String message,
            NativeActionSnapshotCheck.CurrentnessReason reason)throws Exception{
        try{body.run();}
        catch(IllegalArgumentException rejected){
            need(rejected.getMessage()!=null&&rejected.getMessage().equals(message),
                    "exact actual comparison boundary: "+rejected.getMessage());
            if(reason!=null){
                need(rejected instanceof NativeActionSnapshotCheck.CurrentnessChanged,"typed currentness refusal");
                need(((NativeActionSnapshotCheck.CurrentnessChanged)rejected).reason==reason,"exact currentness category");
            }
            return rejected.getClass().getName()+": "+rejected.getMessage();
        }
        throw new AssertionError("expected comparison refusal at "+message);
    }
    private static void combinationRow(String name,Record r,JSONObject a,JSONObject z,List<String> refusals){
        Map<String,Object> row=new TreeMap<String,Object>();row.put("name",name);
        row.put("before_complete_snapshot_sha256",snapshot(r,a).sha);
        row.put("after_complete_snapshot_sha256",snapshot(r,z).sha);
        row.put("references_validated_by_actual_production",true);row.put("refusals",refusals);
        row.put("synthetic_complete_census_variant",true);row.put("platform_dispatch_executed",false);
        combinationEvidence.add(row);
    }
    private static List<String> unclassifiedCombination(Record r,JSONObject a,JSONObject z)throws Exception{
        Snapshot first=snapshot(r,a),second=snapshot(r,z);
        need(NativeActionSnapshotCheck.ctripFormRegions(first,second,Collections.singleton("0/0/2")).roots.isEmpty(),
                "actual banner-region producer refused this otherwise complete pair");
        List<String> reasons=new ArrayList<String>();
        reasons.add(exactRefusal(()->observe(r,a,z),"unclassified complete census change: "+VISIBLE,null));
        for(String purpose:Arrays.asList(NativeActionSnapshotCheck.YEAR,NativeActionSnapshotCheck.QUERY))
            reasons.add(exactRefusal(()->action(r,a,z,purpose),"change outside proved disjoint branch: "+VISIBLE,
                    NativeActionSnapshotCheck.CurrentnessReason.UNCLASSIFIED_TREE_CHANGE));
        return reasons;
    }
    private static void combinationCases(Record r)throws Exception{
        test("combined_caption_and_horizontal_motion_with_current_references",()->{
            JSONObject[] p=pair(r);moveCaption(p[1],VISIBLE,100,true,"广告");
            checkCombinationReferences(r,p[0],p[1],VISIBLE);assertCandidate(r,p[0],p[1]);
            need(node(p[0],VISIBLE).getJSONArray("bounds").getInt(0)+100
                    ==node(p[1],VISIBLE).getJSONArray("bounds").getInt(0),"actual horizontal displacement");
            combinationRow("horizontal",r,p[0],p[1],Collections.<String>emptyList());
        });
        test("combined_caption_motion_hidden_to_visible_with_current_references",()->{
            JSONObject[] p=pair(r);moveCaption(p[0],VISIBLE,0,false,"活动");moveCaption(p[1],VISIBLE,100,true,"广告");
            checkCombinationReferences(r,p[0],p[1],VISIBLE);assertCandidate(r,p[0],p[1]);
            need(node(p[0],VISIBLE).isNull("label")&&node(p[0],VISIBLE).isNull("ref_signature_sha256")
                    &&!node(p[1],VISIBLE).isNull("ref_signature_sha256"),"hidden has no projection; visible has actual new reference");
            combinationRow("hidden_to_visible",r,p[0],p[1],Collections.<String>emptyList());
        });
        test("combined_caption_motion_visible_to_hidden_with_current_references",()->{
            JSONObject[] p=pair(r);moveCaption(p[1],VISIBLE,100,false,"广告");
            checkCombinationReferences(r,p[0],p[1],VISIBLE);assertCandidate(r,p[0],p[1]);
            need(!node(p[0],VISIBLE).isNull("ref_signature_sha256")
                    &&node(p[1],VISIBLE).isNull("label")&&node(p[1],VISIBLE).isNull("ref_signature_sha256"),"hidden successor cannot keep a stale visible reference");
            combinationRow("visible_to_hidden",r,p[0],p[1],Collections.<String>emptyList());
        });
        for(final String hit:Arrays.asList(DATE,QUERY)){
            final String name=DATE.equals(hit)?"date":"query";
            test("combined_caption_valid_reference_overlaps_"+name+"_refused",()->{
                JSONObject[] p=pair(r);
                for(JSONObject census:Arrays.asList(p[0],p[1])){
                    JSONArray exact=new JSONArray(node(census,hit).getJSONArray("bounds").toString());
                    node(census,VISIBLE).put("bounds",exact);
                    caption(census,VISIBLE,node(census,VISIBLE).getString("text"));
                    need(node(census,VISIBLE).getJSONArray("bounds").toList().equals(node(census,hit).getJSONArray("bounds").toList()),
                            "raw caption rectangle overlaps the actual protected hit rectangle");
                }
                checkCombinationReferences(r,p[0],p[1],VISIBLE);
                combinationRow("overlap_"+name,r,p[0],p[1],unclassifiedCombination(r,p[0],p[1]));
            });
        }
        test("combined_caption_valid_reference_with_click_capability_refused",()->{
            JSONObject[] p=pair(r);
            for(JSONObject census:Arrays.asList(p[0],p[1])){
                node(census,VISIBLE).put("clickable",true).put("action_click",true);
                caption(census,VISIBLE,node(census,VISIBLE).getString("text"));
            }
            checkCombinationReferences(r,p[0],p[1],VISIBLE);
            Method passive=NativeActionSnapshotCheck.class.getDeclaredMethod("passiveBannerFlags",Node.class,boolean.class);
            passive.setAccessible(true);
            for(JSONObject census:Arrays.asList(p[0],p[1]))
                need(Boolean.FALSE.equals(passive.invoke(null,snapshot(r,census).node(VISIBLE),false)),
                        "actual passive capability predicate rejects the well-referenced node");
            combinationRow("click_capability",r,p[0],p[1],unclassifiedCombination(r,p[0],p[1]));
        });
        test("caption_literal_on_protected_non_target_branch_refused",()->{
            final String path="0/0/2/14";JSONObject[] p=pair(r);
            need(node(p[0],path).getInt("children")==0&&node(p[1],path).getInt("children")==0,"actual full-graph leaf outside banner");
            caption(p[0],path,"活动");caption(p[1],path,"广告");
            checkCombinationReferences(r,p[0],p[1],VISIBLE,path);
            List<String> reasons=new ArrayList<String>();
            reasons.add(exactRefusal(()->observe(r,p[0],p[1]),"complete protected form subtree changed: "+path,null));
            for(String purpose:Arrays.asList(NativeActionSnapshotCheck.YEAR,NativeActionSnapshotCheck.QUERY))
                reasons.add(exactRefusal(()->action(r,p[0],p[1],purpose),"complete protected subtree changed: "+path,
                        NativeActionSnapshotCheck.CurrentnessReason.PROTECTED_SUBTREE_CHANGED));
            combinationRow("protected_non_target_branch",r,p[0],p[1],reasons);
        });
    }
    public static void main(String[] args)throws Exception{
        Path root=Paths.get(args[0]),output=Paths.get(args[1]);boolean baseline="baseline".equals(args[2]);
        List<Record> records=new ArrayList<Record>();
        for(int i=0;i<OBS.length;i++){
            Record r=new Record(i+2,load(root.resolve(OBS[i]+"-native-ax.json")),load(root.resolve(String.format("step-%02d-action.json",i+2))));
            records.add(r);final String rejectionPath=REFUSAL[i];
            test("recorded_step_"+r.step+"_refusal_facts",()->{
                JSONObject x=r.action,e=x.getJSONObject("action_execution"),d=e.getJSONObject("freshness_diagnostic");
                need(("stale:原生目的复核失败：stale:change outside proved disjoint branch: "+rejectionPath).equals(x.getString("detail")),"exact recorded refusal");
                need(!x.getBoolean("accepted")&&!x.getBoolean("dispatched")&&x.getBoolean("stale"),"no recorded dispatch");
                need(x.getBoolean("model_issued")&&"click".equals(x.getJSONObject("action").getString("action")),"actual model click");
                need("n33".equals(x.getJSONObject("action").getString("node_id")),"actual date target");
                need(!e.getBoolean("effect_entered")&&!e.getBoolean("effect_returned")&&e.getBoolean("worker_drained"),"failed before effect and drained");
                need(e.getInt("display_id")==768&&e.getInt("window_id")==3091,"actual owned background display/window");
                need(e.getLong("worker_drained_elapsed_ms")<e.getLong("deadline_elapsed_ms"),"not an action deadline expiry");
                need(d.getBoolean("window_metadata_equal")&&d.getBoolean("selected_stamp_equal"),"actual selected target and window retained");
                need(DATE.equals(d.getString("selected_original_path")),"actual date path");
                need("inspect_departure_year".equals(e.getJSONObject("native_action_guard").getString("purpose")),"year inspection only");
                need(!e.has("native_action_rejection_census"),"complete failed fresh census was not archived");
                need("hepta.native-ax-form-history.v1".equals(r.ax.getString("schema")),"complete actual planning history");
                need(r.ax.getBoolean("historical_form_planning_only")&&!r.ax.getBoolean("grants_action_authority"),"history grants nothing");
            });
            test("recorded_complete_ax_pair_step_"+r.step,()->{
                JSONObject a=r.ax.getJSONObject("first"),z=r.ax.getJSONObject("second");
                Map<String,Object> proof=observe(r,a,z);
                need(((Number)proof.get("before_visited_nodes")).intValue()==a.getJSONArray("nodes").length(),"all actual first nodes");
                need(((Number)proof.get("after_visited_nodes")).intValue()==z.getJSONArray("nodes").length(),"all actual second nodes");
                need(Boolean.FALSE.equals(proof.get("grants_action_authority")),"actual history remains read only");
                need("11月28日明天".equals(node(a,DATE).getString("text")),"actual date is not requested Nov27");
            });
            if(baseline){
                test("baseline_rejects_derived_visible_caption_step_"+r.step,()->{
                    JSONObject[] p=pair(r);refuse(()->observe(r,p[0],p[1]));
                    refuse(()->action(r,p[0],p[1],NativeActionSnapshotCheck.YEAR));
                });
            }else{
                test("derived_visible_caption_step_"+r.step,()->{JSONObject[] p=pair(r);assertCandidate(r,p[0],p[1]);});
                test("derived_hidden_caption_step_"+r.step,()->{
                    JSONObject a=copy(r.ax.getJSONObject("first")),z=copy(r.ax.getJSONObject("second"));
                    caption(a,HIDDEN,"活动");caption(z,HIDDEN,"广告");assertCandidate(r,a,z);
                });
                test("derived_reverse_caption_step_"+r.step,()->{JSONObject[] p=pair(r);
                    caption(p[0],VISIBLE,"广告");caption(p[1],VISIBLE,"活动");assertCandidate(r,p[0],p[1]);});
                test("derived_mixed_three_pages_step_"+r.step,()->{
                    JSONObject a=copy(r.ax.getJSONObject("first")),z=copy(r.ax.getJSONObject("second"));
                    for(int page=0;page<3;page++){String path="0/0/0/"+page+"/1";
                        caption(a,path,page%2==0?"活动":"广告");caption(z,path,page%2==0?"广告":"活动");}
                    assertCandidate(r,a,z);
                });
                test("derived_all_ad_captions_step_"+r.step,()->{
                    JSONObject a=copy(r.ax.getJSONObject("first")),z=copy(r.ax.getJSONObject("second"));
                    for(int page=0;page<3;page++){String path="0/0/0/"+page+"/1";caption(a,path,"广告");caption(z,path,"广告");}
                    assertCandidate(r,a,z);
                });
            }
        }
        if(!baseline){
            final Record r=records.get(0);
            negative("unknown_caption_text",r,(a,z)->caption(z,VISIBLE,"促销"));
            negative("unknown_caption_before",r,(a,z)->caption(a,VISIBLE,"任意文本"));
            negative("unknown_caption_class",r,(a,z)->both(a,z,VISIBLE,"class","android.widget.Button"));
            negative("unknown_caption_resource",r,(a,z)->both(a,z,VISIBLE,"view_id",CP+"other_label"));
            negative("caption_unknown_description",r,(a,z)->both(a,z,VISIBLE,"description","new control"));
            negative("caption_with_complete_child",r,(a,z)->{child(a);child(z);});
            for(final String flag:Arrays.asList("clickable","action_click","editable","scrollable","focused","password","selected","checkable","checked"))
                negative("caption_capability_"+flag,r,(a,z)->both(a,z,VISIBLE,flag,true));
            negative("caption_disabled",r,(a,z)->both(a,z,VISIBLE,"enabled",false));
            negative("caption_unknown_scroll_metadata",r,(a,z)->both(a,z,VISIBLE,"scroll_actions","hepta.observed-scroll-actions.v1|unknown"));
            negative("caption_unknown_ime_metadata",r,(a,z)->both(a,z,VISIBLE,"ime_enter","unknown"));
            negative("caption_input_body_hash",r,(a,z)->both(a,z,VISIBLE,"input_sha256",NativeActionSnapshotCheck.hash("input")));
            negative("caption_projected_label_disagrees",r,(a,z)->node(z,VISIBLE).put("label","活动"));
            negative("caption_reference_disagrees",r,(a,z)->node(z,VISIBLE).put("ref_signature_sha256",NativeActionSnapshotCheck.hash("foreign reference")));
            negative("hidden_caption_label_present",r,(a,z)->{caption(a,HIDDEN,"活动");caption(z,HIDDEN,"广告");node(z,HIDDEN).put("label","广告");});
            negative("hidden_caption_reference_present",r,(a,z)->{caption(a,HIDDEN,"活动");caption(z,HIDDEN,"广告");node(z,HIDDEN).put("ref_signature_sha256",NativeActionSnapshotCheck.hash("hidden"));});
            negative("caption_new_unknown_field",r,(a,z)->node(z,VISIBLE).put("alpha",0.5));
            negative("caption_vertical_motion",r,(a,z)->{JSONArray b=node(z,VISIBLE).getJSONArray("bounds");b.put(1,b.getInt(1)+1);});
            negative("banner_overlaps_form_body",r,(a,z)->both(a,z,"0/0/0","bounds",new JSONArray(Arrays.asList(0,0,1224,950))));
            negative("raw_image_overlaps_date_hit",r,(a,z)->both(a,z,"0/0/0/1/0","bounds",new JSONArray(Arrays.asList(3,0,1224,950))));
            negative("visible_sibling_overlaps_date_hit",r,(a,z)->{both(a,z,"0/6","visible",true);both(a,z,"0/6","bounds",new JSONArray(Arrays.asList(79,793,415,937)));});
            negative("form_date_changed",r,(a,z)->node(z,DATE).put("text","11月27日今天"));
            negative("form_city_changed",r,(a,z)->node(z,"0/0/2/1").put("text","南京"));
            negative("form_unselected_control_changed",r,(a,z)->node(z,"0/0/2/12").put("enabled",false));
            negative("target_reference_changed",r,(a,z)->node(z,DATE).put("ref_signature_sha256",NativeActionSnapshotCheck.hash("changed target")));
            negative("actual_form_ancestor_changed",r,(a,z)->node(z,"0/0").put("enabled",false));
            negative("owner_changed",r,(a,z)->z.getJSONObject("identity").put("owner_sha256",NativeActionSnapshotCheck.hash("other owner")));
            negative("profile_leaf_changed",r,(a,z)->z.getJSONObject("profile_owner").put("profile_task_id",1000117));
            negative("ime_visible",r,(a,z)->z.put("ime_visibility","visible"));
            negative("complete_census_has_omission",r,(a,z)->z.put("node_budget_omissions",1));
            test("original_eight_second_action_deadline",()->{
                JSONObject[] p=pair(r);p[1].put("census_captured_elapsed_ms",p[0].getLong("census_captured_elapsed_ms")+8000);
                refuse(()->action(r,p[0],p[1],NativeActionSnapshotCheck.YEAR));
                refuse(()->action(r,p[0],p[1],NativeActionSnapshotCheck.QUERY));
            });
            test("original_twelve_second_history_bound",()->{
                JSONObject[] p=pair(r);p[1].put("census_captured_elapsed_ms",p[0].getLong("census_captured_elapsed_ms")+12001);
                refuse(()->observe(r,p[0],p[1]));
            });
        }
        if(!baseline)combinationCases(records.get(0));
        JSONObject result=new JSONObject().put("schema","hepta.ctrip-caption-cases.v1").put("all_pass",true)
            .put("mode",baseline?"baseline":"candidate").put("cases",cases.size()).put("assertions",assertions).put("case_names",cases)
            .put("recorded_action_fact_cases",3).put("recorded_complete_ax_pair_cases",3)
            .put("missing_failed_fresh_censuses_replayed",false).put("derived_variants_are_synthetic",true)
            .put("synthetic_action_intents",true).put("phone_operations",0).put("platform_dispatch_executed",false)
            .put("business_completion_verified",false).put("grants_device_authority",false)
            .put("combination_evidence",combinationEvidence);
        Files.write(output,result.toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS "+cases.size()+" cases / "+assertions+" assertions");
    }
}
