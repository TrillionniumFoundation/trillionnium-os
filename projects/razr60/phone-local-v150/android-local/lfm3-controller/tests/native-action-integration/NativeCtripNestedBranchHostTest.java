package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import static org.trillionnium.hepta.local.NativeActionSnapshotCheckHostTest.*;

/** Complete synthetic census counterexamples, evaluated by the actual comparator.
 * No screenshot, Android NodeRef, Session authority or business result is created. */
public final class NativeCtripNestedBranchHostTest {
    private static final String HEADER="0/0/0", OUTER=HEADER+"/0", REGION=OUTER+"/0", LEAF=REGION+"/0";
    private static int checks;
    private static final List<String> names=new ArrayList<String>();
    private interface Case { void run()throws Exception; }
    private static void require(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void run(String name,Case body)throws Exception{require(!names.contains(name),"unique test name");body.run();names.add(name);System.out.println("PASS "+name);}
    private static void refuse(Case body)throws Exception{
        boolean refused=false;try{body.run();}catch(IllegalArgumentException expected){refused=true;require(expected.getMessage()!=null&&!expected.getMessage().isEmpty(),"explicit refusal retained");}
        require(refused,"changed or incomplete protected context must be refused");
    }
    private static boolean descendant(String path,String root){return path.equals(root)||path.startsWith(root+"/");}
    private static void passiveMetadata(Fixture f,String root){
        for(Map.Entry<String,Map<String,Object>> entry:f.nodes.entrySet())if(descendant(entry.getKey(),root)){
            entry.getValue().put("scroll_actions",ObservedScrollActions.observed(Collections.<String>emptyList()).fingerprintInput());
            entry.getValue().put("ime_enter",ObservedImeEnter.ABSENT.fingerprintInput());
        }
    }
    private static Fixture nested(String purpose){
        Fixture f=form(purpose);
        f.nodes.get(HEADER).put("class","androidx.viewpager.widget.ViewPager");
        f.nodes.get(HEADER).put("bounds",rect(0,0,1224,587));f.nodes.get(HEADER).put("scrollable",true);
        f.add(OUTER,"android.widget.FrameLayout","","","",rect(0,0,1224,587));
        f.add(REGION,"android.widget.FrameLayout","","","",rect(20,40,1200,440));
        f.add(LEAF,"android.widget.TextView","","促销A","",rect(60,80,500,160));
        f.add(REGION+"/1","android.widget.ImageView","","","",rect(60,180,500,400));
        f.add(OUTER+"/1","android.widget.FrameLayout","","","",rect(0,450,1224,587));
        passiveMetadata(f,HEADER);f.nodes.get(HEADER).put("scroll_actions",ObservedScrollActions.observed(Arrays.asList("left","right")).fingerprintInput());
        f.link();return f;
    }
    private static NativeActionSnapshotCheck.Intent boundIntent(Fixture fixture){
        NativeActionSnapshotCheck.Intent original=fixture.intent();
        Map<String,Object> identity=new TreeMap<String,Object>(original.identity);
        if(fixture.env.containsKey("profile_target_sha256"))
            for(String key:NativeActionSnapshotCheck.PROFILE_IDENTITY)identity.put(key,fixture.env.get(key));
        return new NativeActionSnapshotCheck.Intent(original.purpose,original.pkg,original.path,original.label,
                original.refSha256,original.run,original.node,original.actionSha,original.historySha,identity,original.started,original.deadline);
    }
    private static Map<String,Object> comparePair(Fixture a,Fixture z){
        return NativeActionSnapshotCheck.compare(boundIntent(a),a.snapshot(),z.snapshot(),400L);
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> accepted(Fixture a,Fixture z,String... changed){
        Map<String,Object> proof=comparePair(a,z);
        require(Boolean.FALSE.equals(proof.get("grants_dispatch")),"comparison grants no effect");
        require(Boolean.FALSE.equals(proof.get("query_history_proved_by_comparator")),"history is not invented");
        require(Boolean.FALSE.equals(proof.get("provider_frame_constructed")),"no frame projection");
        require(Boolean.FALSE.equals(proof.get("session_observed_called")),"Session observation is not forged");
        require(Boolean.FALSE.equals(proof.get("business_verified")),"no business success claim");
        require(Boolean.FALSE.equals(proof.get("fully_unoccluded_claimed")),"geometry is not an occlusion oracle");
        require(Boolean.TRUE.equals(proof.get("live_node_chain_window_and_one_effect_recheck_required")),"final live checks remain mandatory");
        require(Boolean.FALSE.equals(proof.get("changed_paths_truncated")),"complete difference union retained");
        require(new TreeSet<String>((List<String>)proof.get("changed_paths")).equals(new TreeSet<String>(Arrays.asList(changed))),"exact independently expected changed paths");
        List<String> anchors=(List<String>)proof.get("variable_branch_anchors");
        for(String p:anchors)for(String q:anchors)if(!p.equals(q))require(!descendant(p,q),"no nested anchor overlap");
        for(String p:changed){int count=0;for(String root:anchors)if(descendant(p,root))count++;require(count==1,"each changed path classified exactly once");}
        require(((List<String>)proof.get("protected_subtrees")).contains("0/0/2"),"whole form stays protected");
        return proof;
    }
    private static void moveHeader(Fixture f,String to){
        Map<String,Map<String,Object>> moved=new TreeMap<String,Map<String,Object>>();
        for(String p:new ArrayList<String>(f.nodes.keySet()))if(descendant(p,HEADER)){
            Map<String,Object> row=f.nodes.remove(p);String next=to+p.substring(HEADER.length());row.put("path",next);moved.put(next,row);
        }
        Map<String,Object> displaced=f.nodes.remove(to);displaced.put("path",HEADER);f.nodes.put(HEADER,displaced);f.nodes.putAll(moved);f.link();
    }
    private static void addProfile(Fixture f){
        f.env.put("profile_target_sha256",H);f.env.put("profile_user_id",10);f.env.put("profile_user_serial",7L);
        f.env.put("profile_full_uid",1012345);f.env.put("profile_task_id",500);f.env.put("profile_parent_task_id",499);
        f.env.put("profile_task_token_id",UUID);
    }
    private static void writeResult(String path,String schema,boolean baseline)throws Exception{
        org.json.JSONObject out=new org.json.JSONObject();out.put("schema",schema);out.put("all_pass",true);out.put("cases",names.size());out.put("assertions",checks);out.put("case_names",names);
        out.put("complete_synthetic_censuses",true);out.put("actual_comparator",true);out.put("baseline_control",baseline);
        out.put("android_execution",false);out.put("screenshot_admission_changed",false);out.put("platform_dispatch_executed",false);out.put("business_completion_verified",false);
        String text=out.toString(2)+"\n";Files.write(Paths.get(path),text.getBytes(StandardCharsets.UTF_8));System.out.print(text);
    }
    public static void main(String[] args)throws Exception{
        if(args.length==2&&"baseline-control".equals(args[0])){
            run("baseline_rejects_disjoint_nested_text_under_overlapping_header",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"促销B");refuse(()->comparePair(a,z));});
            writeResult(args[1],"hepta.ctrip-nested-disjoint-baseline-control.v1",true);return;
        }
        for(String purpose:Arrays.asList(NativeActionSnapshotCheck.YEAR,NativeActionSnapshotCheck.QUERY)){
            final String p=purpose;
            run("nested_passive_text_"+p,()->{Fixture a=nested(p),z=fresh(a);changedText(z,LEAF,"促销B");Map<String,Object> proof=accepted(a,z,LEAF);require(((List<?>)proof.get("variable_branch_anchors")).contains(REGION),"fixed region selected");});
        }
        run("nested_passive_geometry_within_fixed_region",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.nodes.get(LEAF).put("bounds",rect(80,80,520,160));accepted(a,z,LEAF);});
        run("nested_added_descendant_complete_union",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.add(REGION+"/2","android.widget.TextView","","新提示","",rect(520,80,900,160));passiveMetadata(z,REGION);z.link();accepted(a,z,REGION,REGION+"/2");});
        run("nested_removed_descendant_complete_union",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.nodes.remove(REGION+"/1");z.link();accepted(a,z,REGION,REGION+"/1");});
        run("nested_no_numeric_path_allowlist",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);moveHeader(a,"0/0/5");Fixture z=fresh(a);String p="0/0/5/0/0/0";changedText(z,p,"新内容");accepted(a,z,p);});
        run("nested_segmented_paths_ten_and_one_distinct",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);for(int i=2;i<11;i++)a.add(OUTER+"/"+i,"android.widget.TextView","","old","",rect(50,50,400,100));passiveMetadata(a,OUTER);a.link();Fixture z=fresh(a);changedText(z,OUTER+"/10","new");accepted(a,z,OUTER+"/10");});
        run("nested_many_changed_paths_not_dropped",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);for(int i=2;i<14;i++)a.add(REGION+"/"+i,"android.widget.TextView","","old","",rect(60,80,500,160));passiveMetadata(a,REGION);a.link();Fixture z=fresh(a);String[] paths=new String[14];for(int i=0;i<14;i++){paths[i]=REGION+"/"+i;changedText(z,paths[i],"new"+i);}accepted(a,z,paths);});
        run("nested_profile_identity_preserved",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);addProfile(a);Fixture z=fresh(a);changedText(z,LEAF,"new");accepted(a,z,LEAF);});
        for(String field:Arrays.asList("bounds","text","description","label","ref_signature_sha256","view_id","class","scroll_actions","ime_enter")){
            final String key=field;
            run("reject_intermediate_ancestor_changed_"+key,()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");Object value=key.equals("bounds")?rect(0,0,1223,587):key.equals("ref_signature_sha256")?repeat('c',64):"changed";z.nodes.get(OUTER).put(key,value);if(key.equals("class"))z.link();refuse(()->comparePair(a,z));});
        }
        run("reject_intermediate_child_count_change",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.add(OUTER+"/2","android.widget.TextView","","additional","",rect(50,50,400,100));passiveMetadata(z,OUTER);z.link();refuse(()->comparePair(a,z));});
        for(String flag:Arrays.asList("editable","password","focused","selected","checkable","checked")){
            final String key=flag;
            run("reject_intermediate_state_"+key,()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);a.nodes.get(OUTER).put(key,true);Fixture z=fresh(a);changedText(z,LEAF,"new");refuse(()->comparePair(a,z));});
        }
        for(String flag:Arrays.asList("clickable","action_click","editable","scrollable","focused","password","selected","checkable","checked"))for(String at:Arrays.asList(REGION,LEAF)){
            final String key=flag,path=at;
            run("reject_nested_capability_"+key+"_"+(path.equals(REGION)?"root":"child"),()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);a.nodes.get(path).put(key,true);Fixture z=fresh(a);changedText(z,LEAF,"new");refuse(()->comparePair(a,z));});
        }
        for(String value:Arrays.asList(ObservedScrollActions.UNKNOWN.fingerprintInput(),ObservedScrollActions.observed(Arrays.asList("right")).fingerprintInput(),"none")){
            final String v=value;
            run("reject_nested_scroll_metadata_"+names.size(),()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);a.nodes.get(LEAF).put("scroll_actions",v);Fixture z=fresh(a);changedText(z,LEAF,"new");refuse(()->comparePair(a,z));});
        }
        for(String value:Arrays.asList(ObservedImeEnter.UNKNOWN.fingerprintInput(),ObservedImeEnter.present("搜索").fingerprintInput(),"none")){
            final String v=value;
            run("reject_nested_ime_metadata_"+names.size(),()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);a.nodes.get(LEAF).put("ime_enter",v);Fixture z=fresh(a);changedText(z,LEAF,"new");refuse(()->comparePair(a,z));});
        }
        run("reject_nested_nonnull_input_hash",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);a.nodes.get(LEAF).put("input_sha256",H);Fixture z=fresh(a);changedText(z,LEAF,"new");refuse(()->comparePair(a,z));});
        run("reject_region_moved_even_while_disjoint",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.nodes.get(REGION).put("bounds",rect(21,40,1200,440));changedText(z,LEAF,"new");refuse(()->comparePair(a,z));});
        run("reject_descendant_outside_fixed_region",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.nodes.get(LEAF).put("bounds",rect(5,80,500,160));refuse(()->comparePair(a,z));});
        run("reject_descendant_into_whole_form_before_query_target",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.nodes.get(LEAF).put("bounds",rect(60,480,500,550));refuse(()->comparePair(a,z));});
        run("reject_unclassified_overlapping_sibling_change",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");changedText(z,OUTER+"/1","unsafe change");refuse(()->comparePair(a,z));});
        run("reject_added_modal_covering_form",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.add(REGION+"/2","android.widget.FrameLayout","","确认","",rect(0,497,1224,1433));passiveMetadata(z,REGION);z.link();refuse(()->comparePair(a,z));});
        run("reject_disjoint_interactive_sibling_under_stable_pager",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);a.add(OUTER+"/2","android.widget.TextView","","interactive","",rect(50,50,400,100));passiveMetadata(a,OUTER);a.click(OUTER+"/2");a.link();Fixture z=fresh(a);changedText(z,LEAF,"new");changedText(z,OUTER+"/2","changed interaction");refuse(()->comparePair(a,z));});
        run("reject_overlapping_interactive_sibling_under_stable_pager",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);a.click(OUTER+"/1");Fixture z=fresh(a);changedText(z,LEAF,"new");changedText(z,OUTER+"/1","changed interaction");refuse(()->comparePair(a,z));});
        run("reject_known_horizontal_ancestor_actions_changed",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.nodes.get(HEADER).put("scroll_actions",ObservedScrollActions.observed(Arrays.asList("right")).fingerprintInput());refuse(()->comparePair(a,z));});
        run("reject_hidden_new_input_descendant",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.add(REGION+"/2","android.widget.EditText","","hidden input","",rect(60,80,500,160));passiveMetadata(z,REGION);z.nodes.get(REGION+"/2").put("editable",true);z.nodes.get(REGION+"/2").put("visible",false);z.link();refuse(()->comparePair(a,z));});
        run("reject_deleted_region_not_reclassified_as_children",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.nodes.remove(LEAF);z.nodes.remove(REGION+"/1");z.nodes.remove(REGION);refuse(()->comparePair(a,z));});
        for(String path:Arrays.asList("0/0/2/1","0/0/2/4","0/0/2/5","0/0/2/9","0/0/2/10","0/0/2/11","0/0/2/8/0","0/0/2/13")){
            final String p=path;run("reject_protected_form_change_"+p.replace('/','_'),()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");changedText(z,p,"changed protected value");refuse(()->comparePair(a,z));});
        }
        run("reject_protected_target_geometry",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.nodes.get(a.target).put("bounds",rect(80,1095,501,1135));refuse(()->comparePair(a,z));});
        run("reject_protected_target_reference",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.nodes.get(a.target).put("ref_signature_sha256",repeat('c',64));refuse(()->comparePair(a,z));});
        for(String field:Arrays.asList("window_metadata_sha256","reported_windows_sha256","selection_sha256")){
            final String key=field;run("reject_envelope_change_"+key,()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.env.put(key,repeat('c',64));refuse(()->comparePair(a,z));});
        }
        for(String field:Arrays.asList("full_native_complete","reported_windows_complete")){
            final String key=field;run("reject_incomplete_"+key,()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.env.put(key,false);refuse(()->comparePair(a,z));});
        }
        for(String field:Arrays.asList("pending","node_omissions","text_omissions","child_omissions")){
            final String key=field;run("reject_omitted_"+key,()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.env.put(key,1);refuse(()->comparePair(a,z));});
        }
        for(String state:Arrays.asList("visible","unknown")){
            final String value=state;run("reject_IME_"+value,()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.env.put("ime_visibility",value);refuse(()->comparePair(a,z));});
        }
        run("reject_foreign_node_window",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.nodes.get(LEAF).put("window_id",97);refuse(()->comparePair(a,z));});
        run("reject_foreign_node_package",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.nodes.get(LEAF).put("package","other.app");refuse(()->comparePair(a,z));});
        run("reject_missing_child_census",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);z.nodes.remove(REGION+"/1");z.env.put("visited",z.nodes.size());refuse(()->comparePair(a,z));});
        run("reject_unknown_node_field",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.nodes.get(LEAF).put("unobserved",false);refuse(()->comparePair(a,z));});
        run("reject_profile_task_replaced",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY);addProfile(a);Fixture z=fresh(a);changedText(z,LEAF,"new");z.env.put("profile_task_id",501);refuse(()->comparePair(a,z));});
        run("reject_original_capture_expired_with_action_budget_left",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");z.env.put("captured_elapsed_ms",90500L);NativeActionSnapshotCheck.Intent old=a.intent();NativeActionSnapshotCheck.Intent in=new NativeActionSnapshotCheck.Intent(old.purpose,old.pkg,old.path,old.label,old.refSha256,old.run,old.node,old.actionSha,old.historySha,old.identity,90300L,95000L);refuse(()->NativeActionSnapshotCheck.compare(in,a.snapshot(),z.snapshot(),91000L));});
        run("reject_original_action_deadline",()->{Fixture a=nested(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,LEAF,"new");refuse(()->NativeActionSnapshotCheck.compare(a.intent(),a.snapshot(),z.snapshot(),8000L));});
        run("reject_open_flight_form_scope_expansion",()->{Fixture a=home();a.nodes.get("0/1").put("bounds",rect(0,300,1224,2500));passiveMetadata(a,"0/1");Fixture z=fresh(a);changedText(z,"0/1/0","new");refuse(()->comparePair(a,z));});
        run("reject_xiaomi_search_scope_expansion",()->{Fixture a=xiaomi();a.nodes.get("0/2").put("bounds",rect(0,350,1224,2750));passiveMetadata(a,"0/2");Fixture z=fresh(a);changedText(z,"0/2/0","new");refuse(()->comparePair(a,z));});
        writeResult(args[0],"hepta.ctrip-nested-disjoint-host.v1",false);
    }
}
