package org.trillionnium.hepta.local;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import org.json.JSONObject;

/** Exact recorded census replay plus explicit host currentness mutations. */
final class NativeXiaomiHomeVariationHostTest {
    static final String FIXTURE_SHA="78cdcf07d09bc136ce4091dad115b015aa263cc6ea7c840e06bdf5a7f3b2442d";
    static final String TARGET="0/0/4",BANNER="0/0/1/0/0",SWITCHER="0/0/3";
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
                    (String)node(false,TARGET).get("label"),(String)node(false,TARGET).get("ref_signature_sha256"),(String)census.get("model_run_id"),
                    (String)census.get("original_node_id"),(String)census.get("original_action_sha256"),(String)guard.get("query_history_sha256"),identity,
                    number(guard.get("issued_elapsed_ms")),number(guard.get("deadline_elapsed_ms")));}
        Map<String,Object> compare(){return NativeActionSnapshotCheck.compare(intent(),snapshot(false),snapshot(true),number(census.get("compared_elapsed_ms")));}
        void replaceFreshBranch(String path){List<Object> replacement=new ArrayList<Object>();
            for(Object row:rows(true)){Map<String,Object> n=map(row);String p=(String)n.get("path");if(!p.equals(path)&&!p.startsWith(path+"/"))replacement.add(row);}
            for(Object row:rows(false)){Map<String,Object> n=map(row);String p=(String)n.get("path");if(p.equals(path)||p.startsWith(path+"/"))replacement.add(copyMap(n));}
            fresh.put("nodes",replacement);
        }
        NativeActionSnapshotCheckHostTest.Fixture bridge(boolean newer){
            NativeActionSnapshotCheckHostTest.Fixture out=new NativeActionSnapshotCheckHostTest.Fixture(NativeActionSnapshotCheck.SEARCH,NativeActionSnapshotCheck.XIAOMI);
            out.nodes.clear();for(Object row:rows(newer)){Map<String,Object> n=copyMap(map(row));out.nodes.put((String)n.get("path"),n);}
            out.target=TARGET;out.label="搜索";out.link();return out;
        }
    }
    static long number(Object value){return ((Number)value).longValue();}
    @SuppressWarnings("unchecked") static Map<String,Object> map(Object value){return (Map<String,Object>)value;}
    @SuppressWarnings("unchecked") static List<Object> list(Object value){return (List<Object>)value;}
    static Object copy(Object value){if(value instanceof Map<?,?>){Map<String,Object> out=new TreeMap<String,Object>();for(Map.Entry<?,?> e:((Map<?,?>)value).entrySet())out.put((String)e.getKey(),copy(e.getValue()));return out;}
        if(value instanceof List<?>){List<Object> out=new ArrayList<Object>();for(Object item:(List<?>)value)out.add(copy(item));return out;}return value;}
    static Map<String,Object> copyMap(Map<String,Object> value){return map(copy(value));}
    static void yes(boolean value,String why){IntegrationChecks.yes(value,why);}
    static void negative(final Map<String,Object> raw,String name,final Change change)throws Exception{
        IntegrationChecks.one("recorded_xiaomi_home_rejects_"+name,()->{Fixture f=new Fixture(raw);change.apply(f);IntegrationChecks.rejects(()->f.compare(),"complete changed predicate must refuse "+name);});
    }
    static NativeActionBridgeHost.Fixture bridge(Map<String,Object> raw,String label)throws Exception{
        Fixture data=new Fixture(raw);NativeActionBridgeHost.Fixture f=new NativeActionBridgeHost().new Fixture(NativeActionSnapshotCheck.SEARCH,"recorded-home:"+label,data.bridge(false));
        f.fresh=data.bridge(true);return f;
    }
    static void run(Path source)throws Exception{
        NativeActionBridgeHost.sourceRoot=source;NativeAppProviderHostTest.fixtures=source.resolve("tests/native-app-provider/fixtures");
        byte[] bytes=Files.readAllBytes(source.resolve("tests/native-action-integration/fixtures/r17-xiaomi-open-search-rejection.json"));
        final Map<String,Object> raw=new JSONObject(new String(bytes,StandardCharsets.UTF_8)).toMap();
        IntegrationChecks.one("recorded_xiaomi_full_census_rotating_banner_and_hint",()->{
            yes(FIXTURE_SHA.equals(NativeActionBridgeHost.sha(bytes)),"exact full recorded 82+82-node fixture pin");
            Fixture f=new Fixture(raw);yes(f.rows(false).size()==82&&f.rows(true).size()==82,"complete before/fresh census retained");
            yes(Boolean.TRUE.equals(f.census.get("complete_two_censuses"))&&Boolean.FALSE.equals(f.census.get("nodes_truncated")),"actual rejection diagnostic was complete");
            yes(f.snapshot(false).sha.equals(f.before.get("snapshot_sha256"))&&f.snapshot(true).sha.equals(f.fresh.get("snapshot_sha256")),"exact recorded snapshot fingerprints reproduced");
            Map<String,Object> proof=f.compare();Map<String,Object> variants=map(proof.get("xiaomi_search_home_variations"));
            yes(variants.size()==2&&variants.containsKey(BANNER)&&variants.containsKey(SWITCHER),"only the two observed branches classified");
            yes(list(proof.get("changed_paths")).size()==12,"all twelve actual census changes accounted for");
            yes(Boolean.FALSE.equals(proof.get("grants_dispatch"))&&Boolean.FALSE.equals(proof.get("fully_unoccluded_claimed")),"coverage equivalence claims no dispatch or complete visual visibility");
        });
        for(final String unchanged:Arrays.asList(BANNER,SWITCHER))IntegrationChecks.one("recorded_xiaomi_one_decoration_changes_"+unchanged.replace('/','_'),()->{
            Fixture f=new Fixture(raw);f.replaceFreshBranch(unchanged);yes(Boolean.FALSE.equals(f.compare().get("grants_dispatch")),"independent decoration proof stays non-authoritative");
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
            NativeActionBridgeHost.Fixture f=bridge(raw,"dispatch");yes(f.dispatch()&&f.effects()==1,"actual extracted compare and final live chain accept one synthetic click");
            yes(f.service.events.contains("full_census"),"actual Service performs fresh census before effect");
        });
        IntegrationChecks.one("recorded_xiaomi_live_ancestor_change_after_fresh_census_refuses",()->{
            NativeActionBridgeHost.Fixture f=bridge(raw,"live-ancestor");NativeActionBridgeHost.NodeData parent=f.data.get("0/0");
            parent.beforeRefresh=()->parent.values.put("bounds",NativeActionSnapshotCheckHostTest.rect(0,1,1224,2992));
            IntegrationChecks.rejects(()->f.dispatch(),"final original ancestor refresh remains exact");f.noEffect("late ancestor change never enters effect");
        });
        IntegrationChecks.one("recorded_xiaomi_live_child_reference_replacement_refuses",()->{
            NativeActionBridgeHost.Fixture f=bridge(raw,"live-reference");NativeActionBridgeHost.NodeData parent=f.data.get("0/0"),target=f.data.get(TARGET);
            parent.beforeRefresh=()->{NativeActionBridgeHost.NodeData replacement=new NativeActionBridgeHost.NodeData(target.values);replacement.parent=parent;parent.children.set(4,replacement);};
            IntegrationChecks.rejects(()->f.dispatch(),"same fields cannot replace the original retained child object");f.noEffect("late actual reference replacement never enters effect");
        });
    }
    public static void main(String[] args)throws Exception{
        run(java.nio.file.Paths.get(args[0]));
        IntegrationChecks.finish(java.nio.file.Paths.get(args[1]),"hepta.recorded-xiaomi-home-variation-host.v1",
                "Complete recorded census replay and actual extracted Service currentness checks with synthetic Android endpoints; no phone, model or business completion pass.");
    }
}
