package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import static org.trillionnium.hepta.local.NativeActionSnapshotCheckHostTest.*;

/** Complete synthetic census cases, using the unchanged action-test data builder.
 * None of these rows is represented as a phone capture or an Action Intent.
 */
public final class FormPairHostTest {
    private static int checks;
    private static final List<String> names=new ArrayList<String>();
    private interface Body {void run()throws Exception;}
    private static void require(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static void run(String name,Body body)throws Exception{
        require(!names.contains(name),"unique case");body.run();names.add(name);System.out.println("PASS "+name);
    }
    private static void refuse(Body body)throws Exception{
        boolean rejected=false;try{body.run();}catch(IllegalArgumentException expected){
            rejected=true;require(expected.getMessage()!=null&&!expected.getMessage().isEmpty(),"specific refusal");
        }require(rejected,"unsafe or incomplete pair must refuse");
    }
    static Fixture managedForm(){
        Fixture f=form(NativeActionSnapshotCheck.QUERY);
        f.env.put("profile_target_sha256",H);f.env.put("profile_user_id",10);f.env.put("profile_user_serial",7L);
        f.env.put("profile_full_uid",1012345);f.env.put("profile_task_id",500);f.env.put("profile_parent_task_id",499);
        f.env.put("profile_task_token_id",UUID);
        knownMetadata(f);return f;
    }
    static void knownMetadata(Fixture f){
        for(Map<String,Object> row:f.nodes.values()){
            row.put("scroll_actions",ObservedScrollActions.observed(Collections.<String>emptyList()).fingerprintInput());
            row.put("ime_enter",ObservedImeEnter.ABSENT.fingerprintInput());
        }
    }
    static Fixture changedForm(Fixture before){
        Fixture after=fresh(before);changedText(after,"0/0/7/0","合成推荐变化B");return after;
    }
    private static Map<String,Object> pair(Fixture a,Fixture z){return NativeCtripFormObservation.compare(a.snapshot(),z.snapshot());}
    @SuppressWarnings("unchecked") private static Map<String,Object> accepted(Fixture a,Fixture z,String... expected){
        Map<String,Object> out=pair(a,z);
        require("hepta.ctrip-native-form-observation-pair.v1".equals(out.get("schema")),"explicit scoped evidence");
        require(Boolean.TRUE.equals(out.get("full_census_compared")),"complete census required");
        require(Boolean.FALSE.equals(out.get("changed_paths_truncated")),"no diagnostic truncation");
        require(Boolean.FALSE.equals(out.get("grants_action_authority")),"read only");
        require(Boolean.FALSE.equals(out.get("query_history_proved")),"no invented query chain");
        require(Boolean.FALSE.equals(out.get("business_completion_verified")),"no business success");
        require(Boolean.FALSE.equals(out.get("same_instant_pixels_and_ax_claimed")),"no pixel simultaneity");
        require(Boolean.FALSE.equals(out.get("published_pair_is_current_tree_claimed")),"no current tree assertion");
        require(Boolean.TRUE.equals(out.get("fresh_action_validation_required")),"last selected node checks retained");
        require(((List<String>)out.get("protected_subtrees")).equals(Collections.singletonList("0/0/2")),"whole form subtree");
        require(new TreeSet<String>((List<String>)out.get("changed_paths")).equals(new TreeSet<String>(Arrays.asList(expected))),"all independently expected changes");
        for(String p:expected){int count=0;for(String anchor:(List<String>)out.get("variable_branch_anchors"))
            if(p.equals(anchor)||p.startsWith(anchor+"/"))count++;require(count==1,"every difference classified once");}
        boolean immutable=false;try{out.put("grants_action_authority",true);}catch(UnsupportedOperationException expectedException){immutable=true;}
        require(immutable,"comparison frozen");return out;
    }
    private static Fixture nested(){
        Fixture f=managedForm();
        Map<String,Object> header=f.nodes.get("0/0/0");
        header.put("class","androidx.viewpager.widget.ViewPager");header.put("bounds",rect(0,0,1224,587));
        header.put("scrollable",true);
        f.add("0/0/0/0","android.widget.FrameLayout","","","",rect(0,0,1224,587));
        f.add("0/0/0/0/0","android.widget.FrameLayout","","","",rect(20,40,1200,440));
        f.add("0/0/0/0/0/0","android.widget.TextView","","合成提示A","",rect(60,80,500,160));
        f.link();knownMetadata(f);header.put("scroll_actions",ObservedScrollActions.observed(Arrays.asList("left","right")).fingerprintInput());
        return f;
    }
    private static Object mutation(String key,Object value){
        if(value instanceof Boolean)return !((Boolean)value);
        if(value instanceof Integer)return ((Integer)value)+1;
        if(value instanceof Long)return ((Long)value)+1L;
        if(value instanceof List)return rect(80,1095,501,1135);
        if(key.equals("ref_signature_sha256")||key.endsWith("sha256"))return repeat('c',64);
        if(value==null)return H;
        return "changed";
    }
    public static void main(String[] args)throws Exception{
        run("same_complete_form_read_only",()->{Fixture a=managedForm();accepted(a,fresh(a));});
        run("disjoint_lower_recommendation_text",()->{Fixture a=managedForm();accepted(a,changedForm(a),"0/0/7/0");});
        run("disjoint_geometry_animation",()->{Fixture a=managedForm(),z=fresh(a);z.nodes.get("0/0/7/0").put("bounds",rect(55,2450,705,2550));accepted(a,z,"0/0/7/0");});
        run("all_forty_changes_are_classified_not_compact_diagnostic",()->{
            Fixture a=managedForm();for(int i=1;i<40;i++)a.add("0/0/7/"+i,"android.widget.TextView","","old"+i,"",rect(50,2450,700,2550));
            a.link();knownMetadata(a);Fixture z=fresh(a);String[] changed=new String[40];
            for(int i=0;i<40;i++){changed[i]="0/0/7/"+i;changedText(z,changed[i],"new"+i);}accepted(a,z,changed);
        });
        run("complete_added_branch_child_and_parent_count",()->{
            Fixture a=managedForm(),z=fresh(a);z.add("0/0/7/1","android.widget.TextView","","新合成内容","",rect(50,2600,700,2700));
            z.link();knownMetadata(z);accepted(a,z,"0/0/7","0/0/7/1");
        });
        run("complete_removed_branch_child_and_parent_count",()->{
            Fixture a=managedForm();a.add("0/0/7/1","android.widget.TextView","","旧合成内容","",rect(50,2600,700,2700));
            a.link();knownMetadata(a);Fixture z=fresh(a);z.nodes.remove("0/0/7/1");z.link();accepted(a,z,"0/0/7","0/0/7/1");
        });
        run("horizontal_actions_only_in_disjoint_horizontal_view",()->{
            Fixture a=managedForm();Map<String,Object> n=a.nodes.get("0/0/7");n.put("class","android.widget.HorizontalScrollView");
            n.put("scrollable",true);n.put("scroll_actions",ObservedScrollActions.observed(Arrays.asList("left","right")).fingerprintInput());a.link();
            Fixture z=fresh(a);z.nodes.get("0/0/7").put("scroll_actions",ObservedScrollActions.observed(Arrays.asList("right")).fingerprintInput());
            accepted(a,z,"0/0/7");
        });
        run("passive_nested_region_under_unchanged_overlapping_pager",()->{
            Fixture a=nested(),z=fresh(a);changedText(z,"0/0/0/0/0/0","合成提示B");accepted(a,z,"0/0/0/0/0/0");
        });
        run("no_numeric_anchor_path_allowlist",()->{
            Fixture a=managedForm();Map<String,Object> sibling=a.nodes.remove("0/0/6"),anchor=a.nodes.remove("0/0/7"),child=a.nodes.remove("0/0/7/0");
            sibling.put("path","0/0/7");anchor.put("path","0/0/6");child.put("path","0/0/6/0");
            a.nodes.put("0/0/7",sibling);a.nodes.put("0/0/6",anchor);a.nodes.put("0/0/6/0",child);a.link();
            Fixture z=fresh(a);changedText(z,"0/0/6/0","合成新内容");accepted(a,z,"0/0/6/0");
        });
        for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY){final String k=key;
            run("refuse_identity_change_"+k,()->{Fixture a=managedForm(),z=changedForm(a);Object v=z.env.get(k);
                if(k.equals("background_generation")||k.equals("profile_task_token_id"))z.env.put(k,"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
                else if(k.equals("task_id")||k.equals("origin_observation_id"))z.env.put(k,repeat('c',32));
                else z.env.put(k,mutation(k,v));refuse(()->pair(a,z));
            });
        }
        for(String key:Arrays.asList("display_id","window_id","rotation","width","height","root_bounds","window_metadata_sha256","reported_windows_sha256")){final String k=key;
            run("refuse_environment_change_"+k,()->{Fixture a=managedForm(),z=changedForm(a);z.env.put(k,mutation(k,z.env.get(k)));refuse(()->pair(a,z));});
        }
        for(String key:Arrays.asList("pending","node_omissions","text_omissions","child_omissions")){final String k=key;
            run("refuse_incomplete_"+k,()->{Fixture a=managedForm(),z=changedForm(a);z.env.put(k,1);refuse(()->pair(a,z));});
        }
        for(String key:Arrays.asList("full_native_complete","reported_windows_complete")){final String k=key;
            run("refuse_partial_"+k,()->{Fixture a=managedForm(),z=changedForm(a);z.env.put(k,false);refuse(()->pair(a,z));});
        }
        for(String ime:Arrays.asList("visible","unknown")){final String v=ime;
            run("refuse_ime_"+v,()->{Fixture a=managedForm(),z=changedForm(a);z.env.put("ime_visibility",v);refuse(()->pair(a,z));});
        }
        run("refuse_personal_profile",()->{Fixture a=managedForm(),z=changedForm(a);for(String k:NativeActionSnapshotCheck.PROFILE_IDENTITY){a.env.remove(k);z.env.remove(k);}refuse(()->pair(a,z));});
        run("refuse_non_ctrip_package",()->{Fixture a=managedForm(),z=changedForm(a);for(Fixture f:Arrays.asList(a,z)){f.env.put("package","com.synthetic.other");for(Map<String,Object> n:f.nodes.values())n.put("package","com.synthetic.other");}refuse(()->pair(a,z));});
        run("refuse_clock_reversed",()->{Fixture a=managedForm(),z=changedForm(a);z.env.put("captured_elapsed_ms",99L);refuse(()->pair(a,z));});
        run("refuse_pair_over_original_observation_bound",()->{Fixture a=managedForm(),z=changedForm(a);z.env.put("captured_elapsed_ms",12101L);refuse(()->pair(a,z));});
        for(String path:Arrays.asList("0/0/2/1","0/0/2/4","0/0/2/5","0/0/2/9","0/0/2/10","0/0/2/11")){final String p=path;
            run("refuse_route_date_passengers_"+p.replace('/','_'),()->{Fixture a=managedForm(),z=changedForm(a);changedText(z,p,"changed");refuse(()->pair(a,z));});
        }
        for(String path:Arrays.asList("0/0/2/0/0","0/0/2/0/1","0/0/2/0/2","0/0/2/8/0")){final String p=path;
            run("refuse_trip_cabin_selection_"+p.replace('/','_'),()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get(p).put("selected",!((Boolean)z.nodes.get(p).get("selected")));refuse(()->pair(a,z));});
        }
        for(String key:Arrays.asList("bounds","view_id","text","description","label","ref_signature_sha256","visible","enabled","clickable","editable","scrollable","focused","password","selected","checkable","checked","scroll_actions","ime_enter","input_sha256","action_click")){final String k=key;
            run("refuse_query_control_"+k,()->{Fixture a=managedForm(),z=changedForm(a);Map<String,Object> n=z.nodes.get("0/0/2/13");n.put(k,mutation(k,n.get(k)));refuse(()->pair(a,z));});
        }
        run("refuse_unlabelled_protected_form_child_change",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/2/12").put("description","changed unselected sibling");refuse(()->pair(a,z));});
        run("refuse_protected_date_reference",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/2/5").put("ref_signature_sha256",repeat('d',64));refuse(()->pair(a,z));});
        run("refuse_protected_ancestor",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0").put("description","changed context");refuse(()->pair(a,z));});
        run("refuse_global_duplicate_date_role",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put("view_id",NativeActionSnapshotCheck.CP+"tv_depart_date");refuse(()->pair(a,z));});
        run("refuse_hidden_duplicate_query_role",()->{Fixture a=managedForm(),z=changedForm(a);Map<String,Object> n=z.nodes.get("0/0/7/0");n.put("view_id",NativeActionSnapshotCheck.CP+"bt_submit_inquire");n.put("visible",false);refuse(()->pair(a,z));});
        for(String role:Arrays.asList("列表页头部重新搜索","单程TripSwitcherCity","单程TripSwitcherDate")){final String value=role;
            run("refuse_research_overlay_"+names.size(),()->{Fixture a=managedForm(),z=changedForm(a);Map<String,Object> n=z.nodes.get("0/0/7/0");n.put("view_id",value);n.put("description",value);refuse(()->pair(a,z));});
        }
        run("refuse_modal_overlapping_form",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put("bounds",rect(0,497,1224,1433));refuse(()->pair(a,z));});
        run("refuse_anchor_moves_despite_remaining_disjoint",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7").put("bounds",rect(40,2417,762,2992));refuse(()->pair(a,z));});
        run("refuse_child_outside_anchor",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put("bounds",rect(20,2450,700,2550));refuse(()->pair(a,z));});
        run("refuse_unclassified_change_above_form",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/1").put("bounds",rect(0,36,1224,65));refuse(()->pair(a,z));});
        run("refuse_last_of_forty_changes_outside_regions",()->{Fixture a=managedForm();for(int i=1;i<40;i++)a.add("0/0/7/"+i,"android.widget.TextView","","old","",rect(50,2450,700,2550));a.link();knownMetadata(a);Fixture z=fresh(a);for(int i=0;i<40;i++)changedText(z,"0/0/7/"+i,"new");z.nodes.get("0/0/7/39").put("bounds",rect(79,1131,1145,1263));refuse(()->pair(a,z));});
        for(String key:Arrays.asList("editable","password","focused","selected","checkable","checked")){final String k=key;
            run("refuse_variable_capability_"+k,()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put(k,true);refuse(()->pair(a,z));});
        }
        for(String key:Arrays.asList("scroll_actions","ime_enter")){final String k=key;
            run("refuse_unknown_variable_metadata_"+k,()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put(k,"unknown");refuse(()->pair(a,z));});
        }
        run("refuse_variable_input_hash",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put("input_sha256",H);refuse(()->pair(a,z));});
        run("refuse_vertical_scroll_capability",()->{Fixture a=managedForm(),z=changedForm(a);Map<String,Object> n=z.nodes.get("0/0/7");n.put("class","android.widget.ScrollView");n.put("scrollable",true);n.put("scroll_actions",ObservedScrollActions.observed(Arrays.asList("forward")).fingerprintInput());z.link();refuse(()->pair(a,z));});
        run("refuse_nested_interactive_leaf",()->{Fixture a=nested(),z=fresh(a);z.click("0/0/0/0/0/0");refuse(()->pair(a,z));});
        run("refuse_nested_intermediate_change",()->{Fixture a=nested(),z=fresh(a);changedText(z,"0/0/0/0/0/0","new");z.nodes.get("0/0/0/0").put("description","changed");refuse(()->pair(a,z));});
        run("refuse_visited_count_mismatch",()->{Fixture a=managedForm(),z=changedForm(a);z.env.put("visited",z.nodes.size()-1);refuse(()->pair(a,z));});
        run("refuse_extra_child_not_in_parent_count",()->{Fixture a=managedForm(),z=changedForm(a);z.add("0/0/7/1","android.widget.TextView","","unlinked","",rect(50,2600,700,2700));z.env.put("visited",z.nodes.size());refuse(()->pair(a,z));});
        run("refuse_declared_missing_child",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7").put("children",2);refuse(()->pair(a,z));});
        run("refuse_missing_raw_field",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").remove("selected");refuse(()->pair(a,z));});
        run("refuse_extra_unclassified_raw_field",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put("unknown_field",true);refuse(()->pair(a,z));});
        run("refuse_missing_complete_child_slot",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.remove("0/0/2/12");z.env.put("visited",z.nodes.size());refuse(()->pair(a,z));});
        run("refuse_foreign_node_package",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put("package","com.synthetic.foreign");refuse(()->pair(a,z));});
        run("refuse_foreign_node_window",()->{Fixture a=managedForm(),z=changedForm(a);z.nodes.get("0/0/7/0").put("window_id",97);refuse(()->pair(a,z));});
        org.json.JSONObject out=new org.json.JSONObject();out.put("schema","hepta.ctrip-form-observation-pure-host.v1");
        out.put("all_pass",true);out.put("cases",names.size());out.put("assertions",checks);out.put("case_names",names);
        out.put("complete_synthetic_censuses",true);out.put("actual_comparator",true);out.put("android_execution",false);
        out.put("model_executed",false);out.put("business_completion_verified",false);out.put("action_comparator_modified",false);
        Files.write(Paths.get(args[0]),(out.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("RESULT "+names.size()+" cases "+checks+" assertions");
    }
}
