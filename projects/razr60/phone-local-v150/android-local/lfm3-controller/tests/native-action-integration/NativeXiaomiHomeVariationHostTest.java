package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import org.json.JSONObject;

/** Exact recorded census replay plus explicit host currentness mutations. */
final class NativeXiaomiHomeVariationHostTest {
    static final String FIXTURE_SHA="78cdcf07d09bc136ce4091dad115b015aa263cc6ea7c840e06bdf5a7f3b2442d";
    static final String TARGET="0/0/3",BANNER="0/0/1/0/0",SWITCHER="0/0/3",OLD_ICON="0/0/4";
    private NativeXiaomiHomeVariationHostTest(){}
    interface Change {void apply(Fixture value)throws Exception;}
    static final class Fixture {
        final Map<String,Object> root,census,guard;final Map<String,Object> before,fresh;
        Fixture(Map<String,Object> value){root=copyMap(value);census=map(root.get("census"));guard=map(root.get("guard"));before=map(census.get("before"));fresh=map(census.get("fresh"));}
        Map<String,Object> env(boolean newer){return map((newer?fresh:before).get("envelope"));}
        List<Object> rows(boolean newer){return list((newer?fresh:before).get("nodes"));}
        Map<String,Object> node(boolean newer,String path){for(Object row:rows(newer)){Map<String,Object> node=map(row);if(path.equals(node.get("path")))return node;}throw new AssertionError("recorded node missing: "+path);}
        NativeActionSnapshotCheck.Snapshot snapshot(boolean newer){List<NativeActionSnapshotCheck.Node> nodes=new ArrayList<NativeActionSnapshotCheck.Node>();
            for(Object row:rows(newer))nodes.add(new NativeActionSnapshotCheck.Node(map(row)));return new NativeActionSnapshotCheck.Snapshot(env(newer),nodes);}
        NativeActionSnapshotCheck.Intent intent(){Map<String,Object> identity=new TreeMap<String,Object>();for(String key:NativeActionSnapshotCheck.IDENTITY)identity.put(key,env(false).get(key));
            return new NativeActionSnapshotCheck.Intent((String)census.get("purpose"),(String)env(false).get("package"),(String)census.get("target_path"),
                    (String)node(false,(String)census.get("target_path")).get("label"),(String)node(false,(String)census.get("target_path")).get("ref_signature_sha256"),(String)census.get("model_run_id"),
                    (String)census.get("original_node_id"),(String)census.get("original_action_sha256"),(String)guard.get("query_history_sha256"),identity,
                    number(guard.get("issued_elapsed_ms")),number(guard.get("deadline_elapsed_ms")));}
        Map<String,Object> compare(){return NativeActionSnapshotCheck.compare(intent(),snapshot(false),snapshot(true),number(census.get("compared_elapsed_ms")));}
        void replaceFreshBranch(String path){List<Object> replacement=new ArrayList<Object>();
            for(Object row:rows(true)){Map<String,Object> n=map(row);String p=(String)n.get("path");if(!p.equals(path)&&!p.startsWith(path+"/"))replacement.add(row);}
            for(Object row:rows(false)){Map<String,Object> n=map(row);String p=(String)n.get("path");if(p.equals(path)||p.startsWith(path+"/"))replacement.add(copyMap(n));}
            fresh.put("nodes",replacement);
        }
        /** Host-only rebind, never relabel the retained phone click as n16. */
        Fixture entryTarget(boolean preserveChangedHint){
            census.put("target_path",TARGET);census.put("original_node_id","n16");
            String run=NativeActionSnapshotCheck.hash("HOST_QUERY_ENTRY_RUN").substring(0,32);
            String action=NativeActionSnapshotCheck.hash("HOST_QUERY_ENTRY_ACTION");
            census.put("model_run_id",run);census.put("original_action_sha256",action);
            guard.put("model_run_id",run);guard.put("action_sha256",action);
            root.put("host_synthetic_query_entry_intent",true);root.put("phone_entry_click_claimed",false);
            if(!preserveChangedHint)replaceFreshBranch(SWITCHER);return this;
        }
        NativeActionSnapshotCheckHostTest.Fixture bridge(boolean newer){
            NativeActionSnapshotCheckHostTest.Fixture out=new NativeActionSnapshotCheckHostTest.Fixture(NativeActionSnapshotCheck.SEARCH,NativeActionSnapshotCheck.XIAOMI);
            out.nodes.clear();for(Object row:rows(newer)){Map<String,Object> n=copyMap(map(row));out.nodes.put((String)n.get("path"),n);}
            out.target=TARGET;out.label=(String)node(newer,TARGET).get("label");out.link();return out;
        }
    }
    static long number(Object value){return ((Number)value).longValue();}
    @SuppressWarnings("unchecked") static Map<String,Object> map(Object value){return (Map<String,Object>)value;}
    @SuppressWarnings("unchecked") static List<Object> list(Object value){return (List<Object>)value;}
    static Object copy(Object value){if(value instanceof Map<?,?>){Map<String,Object> out=new TreeMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())out.put((String)e.getKey(),copy(e.getValue()));return out;}
        if(value instanceof List<?>){List<Object> out=new ArrayList<Object>();for(Object item:(List<?>)value)out.add(copy(item));return out;}return value;}
    static Map<String,Object> copyMap(Map<String,Object> value){return map(copy(value));}
    static void yes(boolean value,String why){IntegrationChecks.yes(value,why);}
    static Fixture stableEntry(Map<String,Object> raw){return new Fixture(raw).entryTarget(false);}
    static void negative(final Map<String,Object> raw,String name,final Change change)throws Exception{
        IntegrationChecks.one("recorded_xiaomi_home_rejects_"+name,()->{Fixture f=stableEntry(raw);yes(Boolean.FALSE.equals(f.compare().get("grants_dispatch")),"unmutated host entry control passes");change.apply(f);IntegrationChecks.rejects(()->f.compare(),"complete changed predicate must refuse "+name);});
    }
    static NativeActionBridgeHost.Fixture bridge(Map<String,Object> raw,String label)throws Exception{
        Fixture data=TARGET.equals(map(raw.get("census")).get("target_path"))?new Fixture(raw):stableEntry(raw);NativeActionBridgeHost.Fixture f=new NativeActionBridgeHost().new Fixture(NativeActionSnapshotCheck.SEARCH_ICON,"recorded-home:"+label,data.bridge(false));
        f.fresh=data.bridge(true);return f;
    }
    static void run(Path source)throws Exception{
        NativeActionBridgeHost.sourceRoot=source;NativeAppProviderHostTest.fixtures=source.resolve("tests/native-app-provider/fixtures");
        byte[] bytes=Files.readAllBytes(source.resolve("tests/native-action-integration/fixtures/r17-xiaomi-open-search-rejection.json"));
        final Map<String,Object> raw=new JSONObject(new String(bytes,StandardCharsets.UTF_8)).toMap();
        IntegrationChecks.one("recorded_xiaomi_icon_and_changing_entry_intents_refused",()->{
            yes(FIXTURE_SHA.equals(NativeActionBridgeHost.sha(bytes)),"exact full recorded 82+82-node fixture pin");
            Fixture f=new Fixture(raw);yes(f.rows(false).size()==82&&f.rows(true).size()==82,"complete before/fresh census retained");
            yes(Boolean.TRUE.equals(f.census.get("complete_two_censuses"))&&Boolean.FALSE.equals(f.census.get("nodes_truncated")),"actual rejection diagnostic was complete");
            yes(f.snapshot(false).sha.equals(f.before.get("snapshot_sha256"))&&f.snapshot(true).sha.equals(f.fresh.get("snapshot_sha256")),"exact recorded snapshot fingerprints reproduced");
            IntegrationChecks.rejects(()->f.compare(),"recorded n17 icon intent cannot open the query editor");
            yes(f.node(false,TARGET).get("bounds").equals(f.node(true,TARGET).get("bounds"))
                    &&f.node(false,TARGET).get("view_id").equals(f.node(true,TARGET).get("view_id")),"same observed entry geometry/resource");
            yes(!f.node(false,TARGET).get("label").equals(f.node(true,TARGET).get("label")),"recorded hint changed while target geometry stayed fixed");
            f.entryTarget(true);IntegrationChecks.rejects(()->f.compare(),"changed hint cannot be exempted once it is the action target");
            Fixture stable=stableEntry(raw);Map<String,Object> proof=stable.compare();Map<String,Object> variants=map(proof.get("xiaomi_search_home_variations"));
            yes(variants.size()==1&&variants.containsKey(BANNER)&&!variants.containsKey(SWITCHER),"only banner is variable in explicit host stable-entry fixture");
            yes(list(proof.get("changed_paths")).size()==9,"all nine remaining original banner changes accounted for");
            yes(Boolean.FALSE.equals(proof.get("grants_dispatch"))&&Boolean.FALSE.equals(proof.get("fully_unoccluded_claimed")),"host rebind claims no phone action or complete visual visibility");
        });
        for(final String unchanged:Arrays.asList(BANNER,SWITCHER))IntegrationChecks.one("host_query_entry_exact_hint_and_banner_"+unchanged.replace('/','_'),()->{
            Fixture f=stableEntry(raw);f.replaceFreshBranch(unchanged);yes(Boolean.FALSE.equals(f.compare().get("grants_dispatch")),"independent decoration proof stays non-authoritative");
        });
        IntegrationChecks.one("recorded_changed_entry_and_old_default_action_remain_refused",()->{
            Fixture data=new Fixture(raw).entryTarget(true);
            IntegrationChecks.rejects(()->data.compare(),"legacy changed target hint remains stale");
            NativeActionBridgeHost.Fixture f=bridge(data.root,"changed-entry-hint");
            ActionDecision oldEntry=f.click(f.ids.get(TARGET));
            IntegrationChecks.rejects(()->f.session.domain().requireCurrent(oldEntry),"actual new default does not admit old entry action");
            f.noEffect("old switcher proposal dispatches no action");
        });
        negative(raw,"second_visible_banner_page",f->{Map<String,Object> n=f.node(true,BANNER+"/5");n.put("visible",true);n.put("bounds",f.node(true,BANNER).get("bounds"));n.put("label","");n.put("ref_signature_sha256",f.node(true,BANNER+"/6").get("ref_signature_sha256"));});
        negative(raw,"changed_visible_banner_coverage",f->f.node(true,BANNER+"/6").put("bounds",NativeActionSnapshotCheckHostTest.rect(1,0,1224,931)));
        negative(raw,"new_banner_leaf_signature",f->f.node(true,BANNER+"/6").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("different-visible-leaf")));
        negative(raw,"banner_leaf_replaced_class",f->f.node(true,BANNER+"/6").put("class","android.widget.ImageView"));
        negative(raw,"banner_leaf_new_business_text",f->f.node(true,BANNER+"/6").put("text","立即购买"));
        negative(raw,"banner_container_geometry",f->f.node(true,BANNER).put("bounds",NativeActionSnapshotCheckHostTest.rect(0,0,1224,932)));
        negative(raw,"banner_container_identity",f->f.node(true,BANNER).put("view_id","different:banner"));
        negative(raw,"banner_parent_identity",f->f.node(true,"0/0/1/0").put("view_id","different:holder"));
        negative(raw,"extra_banner_slot",f->{Map<String,Object> n=copyMap(f.node(true,BANNER+"/8"));n.put("path",BANNER+"/9");f.rows(true).add(n);f.node(true,BANNER).put("children",10);f.env(true).put("visited",83);});
        negative(raw,"removed_banner_slot",f->{f.rows(true).remove(f.node(true,BANNER+"/8"));f.node(true,BANNER).put("children",8);f.env(true).put("visited",81);});
        negative(raw,"hint_overlaps_search_icon",f->f.node(true,SWITCHER).put("bounds",NativeActionSnapshotCheckHostTest.rect(156,287,1001,375)));
        negative(raw,"hint_child_escapes_container",f->f.node(true,SWITCHER+"/0/0").put("bounds",NativeActionSnapshotCheckHostTest.rect(156,301,1100,360)));
        negative(raw,"hint_selected_state",f->f.node(true,SWITCHER+"/0").put("selected",true));
        negative(raw,"hint_editable_state",f->f.node(true,SWITCHER+"/0/0").put("editable",true));
        negative(raw,"hint_replaced_identity",f->f.node(true,SWITCHER+"/0/0").put("view_id","different:text"));
        negative(raw,"hint_becomes_business_role",f->f.node(true,SWITCHER+"/0/0").put("text","Xiaomi路由器AX3000T"));
        negative(raw,"unrelated_feed_field",f->f.node(true,"0/0/1/3/0/0").put("text","其他内容"));
        negative(raw,"unrelated_login_field",f->f.node(true,"0/0/6").put("description","changed login control"));
        negative(raw,"target_signature",f->f.node(true,TARGET).put("ref_signature_sha256",NativeActionSnapshotCheck.hash("new-target")));
        negative(raw,"target_geometry",f->f.node(true,TARGET).put("bounds",NativeActionSnapshotCheckHostTest.rect(1001,290,1156,372)));
        negative(raw,"actual_ancestor_state",f->f.node(true,"0/0").put("scrollable",false));
        negative(raw,"new_overlapping_overlay",f->{Map<String,Object> n=copyMap(f.node(true,BANNER+"/6"));n.put("path","0/15");n.put("parent_class","android.widget.FrameLayout");n.put("bounds",f.node(true,TARGET).get("bounds"));f.rows(true).add(n);f.node(true,"0").put("children",16);f.env(true).put("visited",83);});
        negative(raw,"window_metadata",f->f.env(true).put("window_metadata_sha256",NativeActionSnapshotCheck.hash("new-window")));
        negative(raw,"display_identity",f->f.env(true).put("display_id",31));
        negative(raw,"incomplete_census",f->f.env(true).put("full_native_complete",false));
        negative(raw,"omitted_child_slot",f->f.env(true).put("child_omissions",1));
        negative(raw,"duplicate_census_path",f->{f.rows(true).add(copyMap(f.node(true,BANNER+"/6")));f.env(true).put("visited",83);});
        negative(raw,"foreign_action_purpose",f->f.census.put("purpose",NativeActionSnapshotCheck.QUERY));
        IntegrationChecks.one("recorded_xiaomi_variation_reaches_actual_final_live_chain_once",()->{
            NativeActionBridgeHost.Fixture f=bridge(raw,"dispatch");yes(f.dispatch()&&f.effects()==1,"actual extracted compare and final live chain accept one explicit host icon click");
            yes(f.service.events.contains("full_census"),"actual Service performs fresh census before effect");
        });
        IntegrationChecks.one("recorded_xiaomi_live_ancestor_change_after_fresh_census_refuses",()->{
            NativeActionBridgeHost.Fixture f=bridge(raw,"live-ancestor");NativeActionBridgeHost.NodeData parent=f.data.get("0/0");
            parent.beforeRefresh=()->parent.values.put("bounds",NativeActionSnapshotCheckHostTest.rect(0,1,1224,2992));
            IntegrationChecks.rejects(()->f.dispatch(),"final original ancestor refresh remains exact");f.noEffect("late ancestor change never enters effect");
        });
        IntegrationChecks.one("recorded_xiaomi_live_child_reference_replacement_refuses",()->{
            NativeActionBridgeHost.Fixture f=bridge(raw,"live-reference");NativeActionBridgeHost.NodeData parent=f.data.get("0/0"),target=f.data.get(f.raw.target);
            parent.beforeRefresh=()->{NativeActionBridgeHost.NodeData replacement=new NativeActionBridgeHost.NodeData(target.values);replacement.parent=parent;parent.children.set(Integer.parseInt(f.raw.target.substring(f.raw.target.lastIndexOf('/')+1)),replacement);};
            IntegrationChecks.rejects(()->f.dispatch(),"same fields cannot replace the original retained child object");f.noEffect("late actual reference replacement never enters effect");
        });
        runR18Transition(source);
    }
    static final String R18_FIXTURE_SHA="b27ecaed3a4dd0419fbc49809887b2e6b77cd0a80be17b006d0d8cab72c41d4a";
    static void clip(Fixture f,String path,int left,int top,int right,int bottom){
        Map<String,Object> n=f.node(true,path);
        n.put("bounds",NativeActionSnapshotCheckHostTest.rect(left,top,right,bottom));n.put("visible",true);n.put("label","");
        n.put("ref_signature_sha256",NativeActionBridgeHost.actualBlankLeafReferenceSha(n));
    }
    static void hide(Fixture f,String path){
        Map<String,Object> n=f.node(true,path);n.put("visible",false);n.put("label",null);n.put("ref_signature_sha256",null);
        n.put("bounds",NativeActionSnapshotCheckHostTest.rect(1224,0,1224,931));
    }
    static void runR18Transition(Path source)throws Exception{
        byte[] bytes=Files.readAllBytes(source.resolve("tests/native-action-integration/fixtures/r18-xiaomi-open-search-rejection.json"));
        final Map<String,Object> raw=new JSONObject(new String(bytes,StandardCharsets.UTF_8)).toMap();
        IntegrationChecks.one("recorded_r18_phone_icon_and_changed_entry_refused_then_host_stable_entry",()->{
            yes(R18_FIXTURE_SHA.equals(NativeActionBridgeHost.sha(bytes)),"exact new retained fixture bytes");
            Fixture f=new Fixture(raw);
            yes("b8e1fd019f31eadd60dc163b2bfb4d55d5869919dc29f6ab2895c5e7b00842ed".equals(f.root.get("source_action_sha256")),"original rejected phone action pin retained");
            yes("6b57916cdd44cd18579f10b6f59ef1d053b4d61c".equals(f.root.get("source_commit")),"retained R18 identity, not a fresh host phone run");
            yes(f.rows(false).size()==82&&f.rows(true).size()==82,"all 82+82 original nodes retained");
            yes(f.snapshot(false).sha.equals(f.before.get("snapshot_sha256"))&&f.snapshot(true).sha.equals(f.fresh.get("snapshot_sha256")),"both original complete snapshot fingerprints reproduced");
            yes(f.node(false,BANNER+"/3").get("bounds").equals(NativeActionSnapshotCheckHostTest.rect(0,0,1224,931))
                    &&f.node(true,BANNER+"/6").get("bounds").equals(NativeActionSnapshotCheckHostTest.rect(0,0,18,931))
                    &&f.node(true,BANNER+"/7").get("bounds").equals(NativeActionSnapshotCheckHostTest.rect(18,0,1224,931)),"exact recorded full page and two clips");
            IntegrationChecks.rejects(()->f.compare(),"recorded n17 phone intent remains excluded from query-entry authority");
            f.entryTarget(true);IntegrationChecks.rejects(()->f.compare(),"recorded changed target hint remains protected");
            Fixture stable=stableEntry(raw);Map<String,Object> proof=stable.compare();Map<String,Object> variants=map(proof.get("xiaomi_search_home_variations"));
            yes(variants.size()==1&&"same_complete_horizontal_blank_leaf_coverage".equals(variants.get(BANNER))
                    &&!variants.containsKey(SWITCHER),"only exact banner coverage classified for host stable-entry intent");
            yes(list(proof.get("changed_paths")).size()==9,"all nine banner changes accounted for after explicit host hint stabilization");
            yes(Boolean.FALSE.equals(proof.get("grants_dispatch"))&&Boolean.FALSE.equals(proof.get("fully_unoccluded_claimed")),"coverage does not confer an action or pixel Z-order proof");
        });
        IntegrationChecks.one("recorded_r18_blank_leaf_refs_match_actual_service_producer",()->{
            Fixture f=new Fixture(raw);
            for(String path:Arrays.asList(BANNER+"/3",BANNER+"/6",BANNER+"/7")){
                Map<String,Object> n=f.node(!path.endsWith("/3"),path);
                yes(n.get("ref_signature_sha256").equals(NativeActionBridgeHost.actualBlankLeafReferenceSha(n)),"actual extracted NodeRef plus real empty-child binding reproduces recorded ref "+path);
            }
        });
        negative(raw,"r18_zero_visible_clips",f->{hide(f,BANNER+"/6");hide(f,BANNER+"/7");});
        negative(raw,"r18_visible_zero_width",f->clip(f,BANNER+"/6",0,0,0,931));
        negative(raw,"r18_visible_reverse_width",f->clip(f,BANNER+"/6",18,0,0,931));
        negative(raw,"r18_horizontal_gap_with_valid_refs",f->clip(f,BANNER+"/6",0,0,17,931));
        negative(raw,"r18_horizontal_overlap_with_valid_refs",f->clip(f,BANNER+"/6",0,0,19,931));
        negative(raw,"r18_equal_total_area_gap_and_overlap_with_valid_refs",f->{
            clip(f,BANNER+"/6",0,0,500,931);clip(f,BANNER+"/7",600,0,1100,931);clip(f,BANNER+"/8",1000,0,1224,931);
            yes(500+500+224==1224,"deliberate hole and overlap cancel in total area; bounding box also stays full");
        });
        negative(raw,"r18_different_top_with_valid_ref",f->clip(f,BANNER+"/6",0,1,18,931));
        negative(raw,"r18_different_bottom_with_valid_ref",f->clip(f,BANNER+"/6",0,0,18,930));
        negative(raw,"r18_clip_crosses_anchor_left_with_valid_ref",f->clip(f,BANNER+"/6",-1,0,18,931));
        negative(raw,"r18_clip_crosses_anchor_right_with_valid_ref",f->clip(f,BANNER+"/7",18,0,1225,931));
        negative(raw,"r18_hidden_slot_has_label",f->f.node(true,BANNER+"/5").put("label",""));
        negative(raw,"r18_hidden_slot_has_ref",f->f.node(true,BANNER+"/5").put("ref_signature_sha256",f.node(true,BANNER+"/6").get("ref_signature_sha256")));
        negative(raw,"r18_hidden_positive_area_inside_anchor",f->f.node(true,BANNER+"/5").put("bounds",NativeActionSnapshotCheckHostTest.rect(20,0,30,931)));
        for(final String flag:Arrays.asList("clickable","action_click","enabled"))
            negative(raw,"r18_leaf_loses_"+flag,f->f.node(true,BANNER+"/6").put(flag,false));
        for(final String flag:Arrays.asList("editable","password","scrollable","focused","selected","checkable","checked"))
            negative(raw,"r18_leaf_acquires_"+flag,f->f.node(true,BANNER+"/6").put(flag,true));
        negative(raw,"r18_leaf_new_text",f->f.node(true,BANNER+"/6").put("text","立即购买"));
        negative(raw,"r18_leaf_new_description",f->f.node(true,BANNER+"/6").put("description","付款"));
        negative(raw,"r18_leaf_new_view_identity",f->f.node(true,BANNER+"/6").put("view_id","different:banner-leaf"));
        negative(raw,"r18_leaf_new_class",f->f.node(true,BANNER+"/6").put("class","android.widget.ImageView"));
        negative(raw,"r18_leaf_wrong_actual_parent",f->f.node(true,BANNER+"/6").put("parent_class","android.widget.FrameLayout"));
        negative(raw,"r18_leaf_missing_child",f->f.node(true,BANNER+"/6").put("children",1));
        negative(raw,"r18_leaf_unknown_scroll",f->f.node(true,BANNER+"/6").put("scroll_actions",ObservedScrollActions.UNKNOWN.fingerprintInput()));
        negative(raw,"r18_leaf_unknown_ime",f->f.node(true,BANNER+"/6").put("ime_enter",ObservedImeEnter.UNKNOWN.fingerprintInput()));
        negative(raw,"r18_leaf_unexplained_input",f->f.node(true,BANNER+"/6").put("input_sha256",NativeActionSnapshotCheck.hash("not-a-blank-leaf")));
        negative(raw,"r18_leaf_unexplained_ref",f->f.node(true,BANNER+"/6").put("ref_signature_sha256",NativeActionSnapshotCheck.hash("forged-clipped-ref")));
        negative(raw,"r18_leaf_missing_ref",f->f.node(true,BANNER+"/6").put("ref_signature_sha256",null));
        IntegrationChecks.one("recorded_r18_unsafe_coverage_is_typed_stale_not_a_permit",()->{
            Fixture data=stableEntry(raw);clip(data,BANNER+"/6",0,0,17,931);
            try{data.compare();throw new AssertionError("gap acquired compatibility");}
            catch(NativeActionSnapshotCheck.CurrentnessChanged refusal){
                yes(refusal.reason==NativeActionSnapshotCheck.CurrentnessReason.PROTECTED_SUBTREE_CHANGED,"comparator supplies explicit bound scene-currentness type");
            }
            NativeActionBridgeHost.Fixture f=bridge(data.root,"typed-gap");
            yes("stale".equals(NativeActionBridgeHost.actualComparisonDisposition(f)),"actual extracted Service converts only typed scene refusal");
            yes(NativeActionBridgeHost.recordedRejectionPresent(f),"original complete refusal diagnostic remains present");
            f.noEffect("stale classification itself never enters an effect or supplies a retry seal");
        });
        IntegrationChecks.one("recorded_r18_plain_predicate_error_stays_hard_refusal",()->{
            Fixture data=stableEntry(raw);data.node(true,"0/0/1/3/0/0").put("text","Xiaomi路由器AX3000T");
            try{data.compare();throw new AssertionError("changed business role acquired compatibility");}
            catch(NativeActionSnapshotCheck.CurrentnessChanged wrong){throw new AssertionError("ordinary semantic error broadened into typed currentness",wrong);}
            catch(IllegalArgumentException expected){yes(true,"ordinary semantic predicate remains its original error type");}
            NativeActionBridgeHost.Fixture f=bridge(data.root,"hard-role");
            yes("hard_refusal".equals(NativeActionBridgeHost.actualComparisonDisposition(f)),"actual Service preserves ordinary IllegalArgumentException");
            f.noEffect("hard refusal does not dispatch");
        });
        IntegrationChecks.one("recorded_r18_transition_reaches_original_search_ax_target_only",()->{
            NativeActionBridgeHost.Fixture f=bridge(raw,"two-clip-target");
            yes(f.dispatch()&&f.effects()==1,"actual compare/final census/live chain accepts one synthetic directed AX click");
            yes(f.data.get(f.raw.target).effects==1&&OLD_ICON.equals(f.raw.target),"effect belongs to actual default icon NodeRef");
            yes(f.data.get(TARGET).effects==0,"legacy switcher receives no effect");
            boolean untouched=true;for(Map.Entry<String,NativeActionBridgeHost.NodeData> e:f.data.entrySet())
                if(!f.raw.target.equals(e.getKey())&&e.getValue().effects!=0)untouched=false;
            yes(untouched,"no banner clip or other node receives the effect");
            yes(f.service.events.contains("full_census"),"fresh full census still executes before original target action");
        });
    }
    public static void main(String[] args)throws Exception{
        run(java.nio.file.Paths.get(args[0]));
        IntegrationChecks.finish(java.nio.file.Paths.get(args[1]),"hepta.recorded-xiaomi-home-variation-host.v1",
                "Complete recorded census replay and actual extracted Service currentness checks with synthetic Android endpoints; no phone, model or business completion pass.");
    }
}
