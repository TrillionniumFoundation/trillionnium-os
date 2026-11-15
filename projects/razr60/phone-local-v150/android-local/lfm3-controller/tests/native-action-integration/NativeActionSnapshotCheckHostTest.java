package org.trillionnium.hepta.local;

import java.util.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;

/** Synthetic complete-tree contract fixtures. No Android/provider/dispatch pass. */
public final class NativeActionSnapshotCheckHostTest {
    static final String H=repeat('a',64), ID=repeat('b',32), UUID="11111111-2222-3333-4444-555555555555";
    static int assertions;static final List<String> cases=new ArrayList<String>();
    interface Check {void check()throws Exception;}
    static void yes(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static void test(String name,Check body)throws Exception{body.check();cases.add(name);}
    static void rejected(Check body,String fragment)throws Exception{boolean refused=false;try{body.check();}catch(IllegalArgumentException e){refused=true;yes(e.getMessage().contains(fragment),"wrong refusal: "+e.getMessage()+" wanted "+fragment);}yes(refused,"must reject");}
    static String repeat(char ch,int n){char[] chars=new char[n];Arrays.fill(chars,ch);return new String(chars);}
    static String fullRefSha(String syntheticBaseHash){
        String appTree=ObservedChildText.notApplicable().bind(syntheticBaseHash);
        String full=ObservedImeEnter.UNKNOWN.bindFreshness(
                ObservedScrollActions.observed(Collections.<String>emptyList()).bindFreshness(appTree),false,null);
        return NativeActionSnapshotCheck.hash(full);
    }
    static List<Integer> rect(int a,int b,int c,int d){return Arrays.asList(a,b,c,d);}
    static final class Fixture {
        Map<String,Object> env=new TreeMap<String,Object>();Map<String,Map<String,Object>> nodes=new TreeMap<String,Map<String,Object>>();
        String purpose,pkg,target,label;
        Fixture(String purpose,String pkg){this.purpose=purpose;this.pkg=pkg;
            for(String key:NativeActionSnapshotCheck.IDENTITY)env.put(key,key.endsWith("sha256")?H:ID);
            env.put("background_generation",UUID);env.put("package",pkg);env.put("display_id",15);env.put("window_id",96);env.put("rotation",0);
            env.put("width",1224);env.put("height",2992);env.put("root_bounds",rect(0,0,1224,2992));env.put("window_metadata_sha256",H);env.put("reported_windows_sha256",H);
            env.put("reported_windows_complete",true);env.put("ime_visibility","hidden");env.put("captured_elapsed_ms",100L);env.put("full_native_complete",true);
            for(String key:Arrays.asList("pending","node_omissions","text_omissions","child_omissions"))env.put(key,0);
        }
        void add(String path,String cls,String view,String text,String desc,List<Integer> bounds){
            Map<String,Object> n=new TreeMap<String,Object>();n.put("path",path);n.put("parent_class","");n.put("package",pkg);n.put("window_id",96);n.put("class",cls);n.put("view_id",view);n.put("text",text);n.put("description",desc);
            n.put("label",!text.isEmpty()?text:desc);n.put("ref_signature_sha256",fullRefSha(NativeActionSnapshotCheck.hash("synthetic-node-base:"+path)));n.put("bounds",bounds);n.put("children",0);
            for(String key:Arrays.asList("clickable","editable","scrollable","focused","password","selected","checkable","checked","action_click"))n.put(key,false);
            n.put("visible",true);n.put("enabled",true);n.put("scroll_actions","none");n.put("ime_enter","none");n.put("input_sha256",null);nodes.put(path,n);
        }
        void link(){for(Map<String,Object> n:nodes.values()){String p=(String)n.get("path");int at=p.lastIndexOf('/');if(at>0){Map<String,Object> parent=nodes.get(p.substring(0,at));n.put("parent_class",parent.get("class"));}
                int count=0;while(nodes.containsKey(p+"/"+count))count++;n.put("children",count);}env.put("visited",nodes.size());}
        void click(String p){nodes.get(p).put("clickable",true);nodes.get(p).put("action_click",true);}
        Fixture copy(){Fixture f=new Fixture(purpose,pkg);f.env=new TreeMap<String,Object>(env);for(Map.Entry<String,Map<String,Object>> e:nodes.entrySet())f.nodes.put(e.getKey(),new TreeMap<String,Object>(e.getValue()));f.target=target;f.label=label;return f;}
        NativeActionSnapshotCheck.Snapshot snapshot(){List<NativeActionSnapshotCheck.Node> list=new ArrayList<NativeActionSnapshotCheck.Node>();for(Map<String,Object> n:nodes.values())list.add(new NativeActionSnapshotCheck.Node(n));return new NativeActionSnapshotCheck.Snapshot(env,list);}
        NativeActionSnapshotCheck.Intent intent(){Map<String,Object> identity=new TreeMap<String,Object>();for(String k:NativeActionSnapshotCheck.IDENTITY)identity.put(k,env.get(k));
            return new NativeActionSnapshotCheck.Intent(purpose,pkg,target,label,(String)nodes.get(target).get("ref_signature_sha256"),ID,"n33",H,NativeActionSnapshotCheck.QUERY.equals(purpose)?NativeActionSnapshotCheck.hash("SYNTHETIC-test-history-not-device-proof"):null,identity,200L,8000L);}
    }
    static Fixture form(String purpose){Fixture f=new Fixture(purpose,NativeActionSnapshotCheck.CTRIP);
        f.add("0","android.widget.FrameLayout","","","",rect(0,0,1224,2992));f.add("0/0","android.widget.LinearLayout","","","",rect(0,0,1224,2992));
        for(int i=0;i<8;i++)f.add("0/0/"+i,"android.widget.LinearLayout","","","",i==2?rect(1,497,1223,1433):i==7?rect(39,2417,762,2992):rect(0,i*35,1224,i*35+30));
        for(int i=0;i<14;i++)f.add("0/0/2/"+i,"android.widget.TextView","","","",rect(79,510+i*45,500,550+i*45));
        String[] names={"tv_depart_city","tv_arrival_city","tv_depart_date","tv_adult_count","tv_child_count","tv_baby_count","bt_submit_inquire"};
        String[] texts={"北京","上海","11月17日周二","1成人","0儿童","0婴儿","查 询"};int[] indices={1,4,5,9,10,11,13};
        for(int i=0;i<names.length;i++){Map<String,Object> n=f.nodes.get("0/0/2/"+indices[i]);n.put("view_id",NativeActionSnapshotCheck.CP+names[i]);n.put("text",texts[i]);n.put("label",texts[i]);}
        f.nodes.get("0/0/2/0").put("class","android.widget.LinearLayout");f.nodes.get("0/0/2/0").put("bounds",rect(79,510,1000,560));
        for(int i=0;i<3;i++){String p="0/0/2/0/"+i;f.add(p,"android.widget.LinearLayout","","",new String[]{"单程","往返","多程"}[i],rect(79+250*i,510,300+250*i,560));f.nodes.get(p).put("selected",i==0);}
        f.nodes.get("0/0/2/8").put("class","android.widget.LinearLayout");f.nodes.get("0/0/2/8").put("bounds",rect(79,870,1000,920));
        f.add("0/0/2/8/0","android.widget.LinearLayout","","","经济舱",rect(79,870,500,920));f.nodes.get("0/0/2/8/0").put("selected",true);
        f.click("0/0/2/5");f.click("0/0/2/13");f.add("0/0/7/0","android.widget.TextView","","21w人围观","",rect(50,2450,700,2550));
        f.target=NativeActionSnapshotCheck.QUERY.equals(purpose)?"0/0/2/13":"0/0/2/5";f.label=(String)f.nodes.get(f.target).get("label");f.link();return f;
    }
    static Fixture home(){Fixture f=new Fixture(NativeActionSnapshotCheck.OPEN,NativeActionSnapshotCheck.CTRIP);
        f.add("0","android.widget.FrameLayout","","","",rect(0,0,1224,2992));f.add("0/0","androidx.viewpager.widget.ViewPager","","","",rect(20,430,1200,625));f.nodes.get("0/0").put("scrollable",true);
        for(int i=0;i<5;i++){String p="0/0/"+i;f.add(p,"android.view.ViewGroup",NativeActionSnapshotCheck.CP+NativeActionSnapshotCheck.TILE_IDS[i],"","",rect(30+230*i,430,240+230*i,625));f.click(p);}
        f.add("0/1","android.widget.LinearLayout","","","",rect(0,900,1224,2500));f.add("0/1/0","android.widget.TextView","","旅行推荐A","",rect(0,1000,1224,1100));
        f.target="0/0/1";f.label="";f.link();return f;
    }
    static Fixture xiaomi(){Fixture f=new Fixture(NativeActionSnapshotCheck.SEARCH,NativeActionSnapshotCheck.XIAOMI);
        f.add("0","android.widget.FrameLayout","","","",rect(0,0,1224,2992));f.add("0/0","android.widget.LinearLayout","","","",rect(0,0,1224,400));
        f.add("0/0/0","android.widget.ImageView","com.xiaomi.shop.plugin.homepage:id/searchIcon","","搜索",rect(1000,100,1200,300));f.click("0/0/0");
        f.add("0/1","android.widget.LinearLayout","","","",rect(0,2800,1224,2992));f.add("0/1/0","android.widget.TextView","com.xiaomi.shop.plugin.homepage:id/main_view_nav_bar_text","首页","",rect(0,2800,200,2992));f.nodes.get("0/1/0").put("selected",true);
        f.add("0/2","android.widget.LinearLayout","","","",rect(0,400,1224,2700));f.add("0/2/0","android.widget.TextView","","推荐A","",rect(0,600,1224,800));
        f.target="0/0/0";f.label="搜索";f.link();return f;
    }
    static Fixture fresh(Fixture f){Fixture x=f.copy();x.env.put("captured_elapsed_ms",300L);return x;}
    static Map<String,Object> compare(Fixture old,Fixture fresh){return NativeActionSnapshotCheck.compare(old.intent(),old.snapshot(),fresh.snapshot(),400L);}
    static void changedText(Fixture f,String path,String text){f.nodes.get(path).put("text",text);f.nodes.get(path).put("label",text);f.nodes.get(path).put("ref_signature_sha256",fullRefSha(NativeActionSnapshotCheck.hash(text)));}
    static void pass(Fixture old,Fixture fresh){Map<String,Object> proof=compare(old,fresh);yes(Boolean.FALSE.equals(proof.get("grants_dispatch")),"pure predicate only");yes(Boolean.FALSE.equals(proof.get("query_history_proved_by_comparator")),"history not fabricated");yes(Boolean.FALSE.equals(proof.get("changed_paths_truncated")),"all differences retained");}
    public static void main(String[] args)throws Exception{
        test("ctrip_home_unrelated_text",()->{Fixture a=home(),z=fresh(a);changedText(z,"0/1/0","旅行推荐B");pass(a,z);});
        test("ctrip_form_date_unrelated_text",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);changedText(z,"0/0/7/0","22w人围观");pass(a,z);});
        test("ctrip_query_same_form_predicate_only",()->{Fixture a=form(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,"0/0/7/0","23w人围观");pass(a,z);});
        test("xiaomi_home_unrelated_feed",()->{Fixture a=xiaomi(),z=fresh(a);changedText(z,"0/2/0","推荐B");pass(a,z);});
        test("complete_added_neutral_descendant",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);z.add("0/0/7/1","android.widget.TextView","","实时推荐","",rect(50,2600,700,2700));z.link();pass(a,z);});
        test("complete_removed_neutral_descendant",()->{Fixture a=home(),z=fresh(a);z.nodes.remove("0/1/0");z.link();pass(a,z);});
        test("all_changed_paths_retained_beyond_eight",()->{Fixture a=home();for(int i=1;i<12;i++)a.add("0/1/"+i,"android.widget.TextView","","old"+i,"",rect(0,1100+i*50,1200,1140+i*50));a.link();Fixture z=fresh(a);for(int i=0;i<12;i++)changedText(z,"0/1/"+i,"new"+i);Map<String,Object> p=compare(a,z);yes(((List<?>)p.get("changed_paths")).size()==12,"must retain every diff");});
        test("same_source_no_changes",()->{Fixture a=home();pass(a,fresh(a));});
        for(String key:NativeActionSnapshotCheck.IDENTITY){final String k=key;test("reject_identity_"+k,()->{Fixture a=home(),z=fresh(a);z.env.put(k,k.equals("background_generation")?"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee":k.endsWith("sha256")?repeat('c',64):repeat('c',32));rejected(()->compare(a,z),"binding changed");});}
        for(String key:Arrays.asList("window_metadata_sha256","reported_windows_sha256","display_id","window_id","rotation","width","height")){final String k=key;test("reject_window_"+k,()->{Fixture a=home(),z=fresh(a);z.env.put(k,k.endsWith("sha256")?repeat('d',64):((Integer)z.env.get(k))+1);rejected(()->compare(a,z),k.equals("window_id")?"foreign node/window":"window/display");});}
        test("reject_ime_visible",()->{Fixture a=home(),z=fresh(a);z.env.put("ime_visibility","visible");rejected(()->compare(a,z),"known hidden IME");});
        test("reject_ime_unknown",()->{Fixture a=home(),z=fresh(a);z.env.put("ime_visibility","unknown");rejected(()->compare(a,z),"known hidden IME");});
        test("reject_reported_window_census_incomplete",()->{Fixture a=home(),z=fresh(a);z.env.put("reported_windows_complete",false);rejected(()->compare(a,z),"complete census");});
        test("reject_retained_only_snapshot",()->{Fixture a=home(),z=fresh(a);z.env.put("full_native_complete",false);rejected(()->compare(a,z),"complete census");});
        for(String key:Arrays.asList("pending","node_omissions","text_omissions","child_omissions")){final String k=key;test("reject_omission_"+k,()->{Fixture a=home(),z=fresh(a);z.env.put(k,1);rejected(()->compare(a,z),"collection omitted");});}
        test("reject_actual_parent_missing",()->{Fixture a=home(),z=fresh(a);z.nodes.remove("0/0");z.env.put("visited",z.nodes.size());rejected(()->compare(a,z),"missing child slot");});
        test("reject_wrong_parent_class",()->{Fixture a=home(),z=fresh(a);z.nodes.get(z.target).put("parent_class","android.webkit.WebView");rejected(()->compare(a,z),"complete real parent");});
        test("reject_duplicate_path",()->{Fixture a=home();List<NativeActionSnapshotCheck.Node> n=new ArrayList<NativeActionSnapshotCheck.Node>();for(Map<String,Object> row:a.nodes.values())n.add(new NativeActionSnapshotCheck.Node(row));n.add(n.get(0));a.env.put("visited",n.size());rejected(()->new NativeActionSnapshotCheck.Snapshot(a.env,n),"duplicate path");});
        test("reject_selection_metadata_unknown",()->{Fixture a=home(),z=fresh(a);z.nodes.get(z.target).put("selected",null);rejected(()->compare(a,z),"actual boolean");});
        test("reject_selected_target_change",()->{Fixture a=home(),z=fresh(a);z.nodes.get(z.target).put("selected",true);rejected(()->compare(a,z),"target facts");});
        test("reject_target_ref_changed_despite_same_label",()->{Fixture a=home(),z=fresh(a);z.nodes.get(z.target).put("ref_signature_sha256",repeat('f',64));rejected(()->compare(a,z),"target facts");});
        test("reject_target_label_changed",()->{Fixture a=home(),z=fresh(a);z.nodes.get(z.target).put("label","机票");rejected(()->compare(a,z),"target facts");});
        test("reject_target_geometry_changed",()->{Fixture a=home(),z=fresh(a);z.nodes.get(z.target).put("bounds",rect(270,430,480,625));rejected(()->compare(a,z),"target facts");});
        test("reject_ancestor_text_changed",()->{Fixture a=home(),z=fresh(a);z.nodes.get("0").put("description","new-root-context");rejected(()->compare(a,z),"actual ancestor");});
        test("reject_ancestor_child_count_change",()->{Fixture a=home(),z=fresh(a);z.add("0/2","android.view.View","","","",rect(0,2700,1224,2800));z.link();rejected(()->compare(a,z),"actual ancestor");});
        test("reject_sibling_tile_role_changed",()->{Fixture a=home(),z=fresh(a);z.nodes.get("0/0/2").put("view_id",NativeActionSnapshotCheck.CP+"different");rejected(()->compare(a,z),"unique resource");});
        test("reject_route_changed",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);changedText(z,"0/0/2/1","南京");rejected(()->compare(a,z),"route/passengers");});
        test("reject_passengers_changed",()->{Fixture a=form(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,"0/0/2/9","2成人");rejected(()->compare(a,z),"route/passengers");});
        test("reject_date_changed_on_query",()->{Fixture a=form(NativeActionSnapshotCheck.QUERY),z=fresh(a);changedText(z,"0/0/2/5","11月18日周三");rejected(()->compare(a,z),"fresh purpose semantics");});
        test("reject_round_trip_selected",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);z.nodes.get("0/0/2/0/1").put("selected",true);rejected(()->compare(a,z),"single-trip");});
        test("reject_economy_unselected",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);z.nodes.get("0/0/2/8/0").put("selected",false);rejected(()->compare(a,z),"economy choice");});
        test("reject_missing_query_history_binding",()->{Fixture a=form(NativeActionSnapshotCheck.QUERY);NativeActionSnapshotCheck.Intent in=a.intent();rejected(()->new NativeActionSnapshotCheck.Intent(in.purpose,in.pkg,in.path,in.label,in.refSha256,in.run,in.node,in.actionSha,null,in.identity,in.started,in.deadline),"history binding");});
        test("reject_empty_query_history_binding",()->{Fixture a=form(NativeActionSnapshotCheck.QUERY);NativeActionSnapshotCheck.Intent in=a.intent();rejected(()->new NativeActionSnapshotCheck.Intent(in.purpose,in.pkg,in.path,in.label,in.refSha256,in.run,in.node,in.actionSha,NativeActionSnapshotCheck.hash(""),in.identity,in.started,in.deadline),"history binding");});
        test("reject_same_target_new_competing_form_role",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);z.add("0/0/7/1","android.widget.TextView",NativeActionSnapshotCheck.CP+"tv_depart_date","11月17日周二","",rect(50,2600,700,2700));z.link();rejected(()->compare(a,z),"unique resource");});
        test("reject_overlay_role_outside_target_rectangle",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);z.add("0/0/7/1","android.view.View","单程TripSwitcherCity","","单程TripSwitcherCity",rect(50,2600,700,2700));z.link();rejected(()->compare(a,z),"overlay veto");});
        test("reject_provider_role_even_if_invisible",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);Map<String,Object> n=z.nodes.get("0/0/7/0");n.put("view_id",NativeActionSnapshotCheck.CP+"tv_depart_date");n.put("visible",false);rejected(()->compare(a,z),"global Provider roles");});
        test("reject_changed_node_covering_target",()->{Fixture a=form(NativeActionSnapshotCheck.YEAR),z=fresh(a);z.nodes.get("0/0/7/0").put("bounds",rect(0,700,1224,1000));rejected(()->compare(a,z),"outside proved disjoint");});
        test("reject_changed_branch_anchor_geometry",()->{Fixture a=home(),z=fresh(a);z.nodes.get("0/1").put("bounds",rect(0,400,1224,2500));rejected(()->compare(a,z),"outside proved disjoint");});
        test("reject_branch_anchor_removed",()->{Fixture a=home(),z=fresh(a);z.nodes.remove("0/1");z.nodes.remove("0/1/0");z.link();rejected(()->compare(a,z),"actual ancestor");});
        test("reject_variable_branch_input",()->{Fixture a=home(),z=fresh(a);z.nodes.get("0/1/0").put("editable",true);rejected(()->compare(a,z),"outside proved disjoint");});
        test("reject_variable_branch_selected",()->{Fixture a=home(),z=fresh(a);z.nodes.get("0/1/0").put("selected",true);rejected(()->compare(a,z),"outside proved disjoint");});
        test("reject_protected_subtree_addition",()->{Fixture a=home(),z=fresh(a);z.add("0/0/1/0","android.widget.TextView","","new child","",rect(270,440,470,500));z.link();rejected(()->compare(a,z),"target facts");});
        test("reject_xiaomi_duplicate_search",()->{Fixture a=xiaomi(),z=fresh(a);z.nodes.get("0/2/0").put("view_id","com.xiaomi.shop.plugin.homepage:id/searchIcon");rejected(()->compare(a,z),"unique resource");});
        test("reject_xiaomi_home_unselected",()->{Fixture a=xiaomi(),z=fresh(a);z.nodes.get("0/1/0").put("selected",false);rejected(()->compare(a,z),"selected home/search");});
        test("reject_xiaomi_input_phase",()->{Fixture a=xiaomi(),z=fresh(a);z.nodes.get("0/2/0").put("editable",true);rejected(()->compare(a,z),"fresh home only");});
        test("reject_foreign_descendant",()->{Fixture a=home(),z=fresh(a);z.nodes.get("0/1/0").put("package","foreign.app");rejected(()->compare(a,z),"foreign node/window");});
        test("reject_unknown_future_field",()->{Fixture a=home(),z=fresh(a);z.nodes.get("0/1/0").put("unknown",true);rejected(()->compare(a,z),"exact node");});
        test("reject_deadline_at_boundary",()->{Fixture a=home(),z=fresh(a);rejected(()->NativeActionSnapshotCheck.compare(a.intent(),a.snapshot(),z.snapshot(),8000L),"age/deadline");});
        test("reject_reversed_fresh_clock",()->{Fixture a=home(),z=fresh(a);z.env.put("captured_elapsed_ms",199L);rejected(()->compare(a,z),"age/deadline");});
        test("reject_extended_deadline",()->{Fixture a=home();NativeActionSnapshotCheck.Intent in=a.intent();rejected(()->new NativeActionSnapshotCheck.Intent(in.purpose,in.pkg,in.path,in.label,in.refSha256,in.run,in.node,in.actionSha,in.historySha,in.identity,200,8201),"original action deadline");});
        for(String purpose:Arrays.asList("set_product_query","submit_product_query","submit_exact_suggestion","open_exact_product","back","done","buy","pay")){final String p=purpose;test("reject_unadmitted_"+p,()->{Fixture a=home();NativeActionSnapshotCheck.Intent in=a.intent();rejected(()->new NativeActionSnapshotCheck.Intent(p,in.pkg,in.path,in.label,in.refSha256,in.run,in.node,in.actionSha,in.historySha,in.identity,in.started,in.deadline),"unsupported purpose");});}
        test("immutable_snapshot_values",()->{Fixture a=home();NativeActionSnapshotCheck.Snapshot first=a.snapshot();a.nodes.get("0/0/1").put("description","external mutation");yes("".equals(first.node("0/0/1").desc),"defensive immutable copy");});
        StringBuilder out=new StringBuilder("{\"schema\":\"hepta.native-action-snapshot-candidate-host.v1\",\"cases\":"+cases.size()+",\"assertions\":"+assertions+",\"all_pass\":true,\"fixtures\":\"synthetic_complete_native_trees\",\"android_or_dispatch_executed\":false,\"names\":[");
        for(int i=0;i<cases.size();i++){if(i>0)out.append(',');out.append('"').append(cases.get(i)).append('"');}out.append("]}\n");Files.write(Paths.get(args[0]),out.toString().getBytes(StandardCharsets.UTF_8));System.out.print(out);
    }
}
