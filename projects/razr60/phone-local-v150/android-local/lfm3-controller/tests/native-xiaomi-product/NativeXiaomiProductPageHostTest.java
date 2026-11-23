package org.trillionnium.hepta.local;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;

/** Public manual UI hierarchy fixtures inside explicitly synthetic Frame bindings.
 * Two irrelevant offscreen delivery-location text values are explicitly redacted;
 * action/quote source fields and all hierarchy/geometry remain the observed values.
 * No Android, model, accessibility IPC, installed identity or dispatch is executed. */
public final class NativeXiaomiProductPageHostTest {
    private static final String OWNER="在小米商城查询AX3000T价格";
    private static final String TITLE="Xiaomi路由器AX3000T";
    private static final NativeAppGoal GOAL=NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE);
    private static final List<String> names=new ArrayList<String>();
    private static int checks,serial;
    private static Path fixtures;
    interface Body {void run()throws Exception;}
    private static void check(boolean yes,String why){checks++;if(!yes)throw new AssertionError(why);}
    private static void test(String name,Body body)throws Exception{body.run();names.add(name);}
    private static String hash(String text){return NativeAppEvidence.hash(text);}
    private static String id(){return String.format(java.util.Locale.ROOT,"%032x",++serial);}
    private static NativeAppEvidence.Frame load(String name)throws Exception{
        NativeXmlFixture.Snapshot fixture=NativeXmlFixture.read(fixtures.resolve(name+".xml"));
        String fixtureHash=fixture.sourceSha256;int[] b=fixture.rootBounds;
        return new NativeAppEvidence.Frame("11111111111111111111111111111111",GOAL.ownerSha256,hash("host-target"),hash("host-auth"),hash("host-selection"),id(),
                NativeAppGoal.XIAOMI_PACKAGE,"12345678-1234-1234-1234-123456789abc",hash("host-tree-"+fixtureHash),hash("host-state-"+fixtureHash),
                hash("host-screen-not-loaded-"+fixtureHash),fixtureHash,hash("host-completion-"+fixtureHash),31,7,0,1224,2992,
                b[0],b[1],b[2],b[3],1000+serial,false,true,fixture.nodes,1,true);
    }
    private static NativeAppEvidence.Frame frame(NativeAppEvidence.Frame f,List<NativeAppEvidence.Node> nodes,boolean truncated,boolean complete,int windowType,boolean metadata){
        return new NativeAppEvidence.Frame(f.taskId,f.ownerSha,f.targetSha,f.authorizationSha,f.selectionSha,id(),f.packageName,f.generation,
                f.treeSha,f.stateSha,f.screenshotSha,f.sourceRecordSha,f.completionFrameSha,f.displayId,f.windowId,f.rotation,f.width,f.height,
                f.left,f.top,f.right,f.bottom,f.capturedElapsedMs,truncated,complete,nodes,windowType,metadata);
    }
    private static NativeAppEvidence.Node edit(NativeAppEvidence.Node n,String text,String desc,String path,String pkg,Boolean click,Boolean enabled,int[] b){
        String t=text==null?n.text:text,d=desc==null?n.description:desc,p=path==null?n.path:path,k=pkg==null?n.packageName:pkg;
        if(b==null)b=new int[]{n.left,n.top,n.right,n.bottom};
        return new NativeAppEvidence.Node(n.id,k,n.className,n.viewId,t,d,p,n.parentClass,hash("HOST_MUTATION\n"+n.signature+"\n"+t+"\n"+d+"\n"+p),n.label,
                b[0],b[1],b[2],b[3],enabled==null?n.enabled:enabled.booleanValue(),n.password,click==null?n.clickable:click.booleanValue(),
                n.editable,n.scrollable,n.selected,n.checkable,n.checked,n.scrollDirections);
    }
    private static NativeAppEvidence.Node text(NativeAppEvidence.Frame f,String value){
        NativeAppEvidence.Node found=null;for(NativeAppEvidence.Node n:f.nodes)if(value.equals(n.text)){if(found!=null)throw new IllegalArgumentException("fixture text is not unique: "+value);found=n;}
        if(found==null)throw new IllegalArgumentException("fixture text missing: "+value);return found;
    }
    private static NativeAppEvidence.Node sameModelParentText(NativeAppEvidence.Frame f,String value){
        NativeAppEvidence.Node model=text(f,TITLE),found=null;String parent=model.path.substring(0,model.path.lastIndexOf('/'));
        for(NativeAppEvidence.Node n:f.nodes)if(value.equals(n.text)&&n.path.substring(0,n.path.lastIndexOf('/')).equals(parent)){
            if(found!=null)throw new IllegalArgumentException("same-card fixture text is ambiguous: "+value);found=n;
        }
        if(found==null)throw new IllegalArgumentException("same-card fixture text missing: "+value);return found;
    }
    private static NativeAppEvidence.Node desc(NativeAppEvidence.Frame f,String value){
        for(NativeAppEvidence.Node n:f.nodes)if(value.equals(n.description))return n;throw new IllegalArgumentException("fixture description missing");
    }
    private static NativeAppEvidence.Frame replace(NativeAppEvidence.Frame f,NativeAppEvidence.Node before,NativeAppEvidence.Node after){
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(f.nodes);if(!nodes.remove(before))throw new IllegalArgumentException("old node missing");if(after!=null)nodes.add(after);
        return frame(f,nodes,false,true,1,true);
    }
    private static NativeAppEvidence.Node resource(NativeAppEvidence.Frame f,String suffix){
        NativeAppEvidence.Node result=null;for(NativeAppEvidence.Node n:f.nodes)if(n.viewId.endsWith(":id/"+suffix)){
            if(result!=null)throw new AssertionError("duplicate fixture resource "+suffix);result=n;}
        if(result==null)throw new AssertionError("fixture resource missing "+suffix);return result;
    }
    private static NativeAppEvidence.Node path(NativeAppEvidence.Frame f,String value){
        for(NativeAppEvidence.Node n:f.nodes)if(value.equals(n.path))return n;throw new AssertionError("fixture path missing");
    }
    /** Explicit synthetic node mutation, never an Android reference. */
    private static NativeAppEvidence.Node alter(NativeAppEvidence.Node n,String key,Object value){
        return new NativeAppEvidence.Node("id".equals(key)?(String)value:n.id,n.packageName,
                "class".equals(key)?(String)value:n.className,"view".equals(key)?(String)value:n.viewId,
                "text".equals(key)?(String)value:n.text,"description".equals(key)?(String)value:n.description,
                "path".equals(key)?(String)value:n.path,"parent".equals(key)?(String)value:n.parentClass,
                hash("HOST_ENTRY_MUTATION\n"+n.signature+"\n"+key+"\n"+value),"label".equals(key)?(String)value:n.label,
                n.left,n.top,n.right,n.bottom,"enabled".equals(key)?((Boolean)value).booleanValue():n.enabled,
                n.password,"clickable".equals(key)?((Boolean)value).booleanValue():n.clickable,
                "editable".equals(key)?((Boolean)value).booleanValue():n.editable,
                "scrollable".equals(key)?((Boolean)value).booleanValue():n.scrollable,
                "selected".equals(key)?(Boolean)value:n.selected,"selected".equals(key)&&value==null?null:"checkable".equals(key)?(Boolean)value:n.checkable,
                "selected".equals(key)&&value==null?null:n.checked,n.scrollDirections);
    }
    private static void changedEntryRejected(String name,String relative,String key,Object value)throws Exception{
        test(name,()->{NativeAppEvidence.Frame f=load("home");NativeAppEvidence.Node entry=resource(f,"switcher"),n=path(f,entry.path+relative);
            unavailable(replace(f,n,alter(n,key,value)),name);});
    }
    private static NativeXiaomiProductPage.Page inspect(NativeAppEvidence.Frame f){return NativeXiaomiProductPage.inspect(GOAL,f);}
    private static void noQuote(NativeAppEvidence.Frame f,String why){check(inspect(f).quote==null,why);}
    private static void unavailable(NativeAppEvidence.Frame f,String why){
        NativeXiaomiProductPage.Page p=inspect(f);check(p.quote==null&&p.clickIds.isEmpty()&&p.editValues.isEmpty(),why);
    }
    private static void readonlyQuote(NativeXiaomiProductPage.Quote q,String kind){
        check(q!=null&&kind.equals(q.kind),"observed quote kind");
        check("159".equals(q.amountDecimal)&&"199".equals(q.comparisonAmountDecimal)&&"CNY".equals(q.currency),"actual displayed price/secondary amount");
        check(TITLE.equals(q.modelRaw),"same exact product title");
        check(Boolean.FALSE.equals(q.evidence().get("order_submitted"))&&Boolean.FALSE.equals(q.evidence().get("task_complete")),"pure quote has no order/completion");
        check(Boolean.FALSE.equals(q.evidence().get("promotions_deducted_from_amount"))&&Boolean.FALSE.equals(q.evidence().get("lowest_price_verified")),"no discount/lowest-price inference");
    }
    /** Explicit synthetic Frame/NodeRef bindings for the five toolbar nodes
     * retained in task a535abf2. The separate raw-JSON replay checks all three
     * original 56/64/67-node records; this does not fill their unsaved census. */
    private static NativeAppEvidence.Node rootNode(String nodeId,String cls,String text,String path,String parent,
            String label,boolean click,boolean editable,int left,int top,int right,int bottom){
        return new NativeAppEvidence.Node(nodeId,NativeAppGoal.XIAOMI_PACKAGE,cls,"",text,"",path,parent,
                hash("HOST_DIRECT_ROOT_TOOLBAR\n"+nodeId+"\n"+text+"\n"+path),label,left,top,right,bottom,
                true,false,click,editable,false,Boolean.FALSE,Boolean.FALSE,Boolean.FALSE,Collections.<String>emptySet());
    }
    private static NativeAppEvidence.Frame directRootFrame(String query)throws Exception{
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();
        nodes.add(rootNode("n0","android.view.ViewGroup","","0/0","android.widget.FrameLayout","搜索",true,false,81,328,367,421));
        nodes.add(rootNode("n1","android.widget.EditText",query,"0/1","android.widget.FrameLayout",query,true,true,162,130,1074,334));
        nodes.add(rootNode("n2","android.widget.TextView","Type-C快充数据线","0/2","android.widget.FrameLayout","Type-C快充数据线",false,false,162,152,1108,237));
        nodes.add(rootNode("n3","android.view.ViewGroup","","0/4","android.widget.FrameLayout","搜索",true,false,958,333,1142,421));
        nodes.add(rootNode("n4","android.view.ViewGroup","","0/5","android.widget.FrameLayout","",true,false,68,154,150,236));
        nodes.add(rootNode("n6","android.widget.TextView","搜索","0/0/0","android.view.ViewGroup","搜索",false,false,167,347,257,401));
        nodes.add(rootNode("n7","android.widget.TextView","搜索","0/4/0","android.view.ViewGroup","搜索",false,false,999,347,1101,408));
        nodes.add(rootNode("n9","android.view.ViewGroup","","0/6/1","android.widget.ScrollView","xiaomi路由器ax3000t",true,false,54,613,573,701));
        nodes.add(rootNode("n25","android.widget.TextView","xiaomi路由器ax3000t","0/6/1/0","android.view.ViewGroup","xiaomi路由器ax3000t",false,false,95,630,532,684));
        return frame(load("search-entry"),nodes,false,true,1,true);
    }
    private static void rootChangedRejected(String nodeId,String key,Object value)throws Exception{
        NativeAppEvidence.Frame f=directRootFrame("");NativeAppEvidence.Node n=f.byId.get(nodeId);
        unavailable(replace(f,n,alter(n,key,value)),"direct-root rejected "+nodeId+" "+key+" "+value);
    }
    private static void directRootCases()throws Exception{
        test("direct_root_toolbar_edits_only_literal_owner_query",()->{
            NativeAppEvidence.Frame f=directRootFrame("");NativeXiaomiProductPage.Page p=inspect(f);
            check("search_input".equals(p.phase)&&p.missing.isEmpty()&&p.clickIds.isEmpty(),"exact root toolbar is an input, not a result");
            check(p.editValues.equals(Collections.singletonMap("n1","AX3000T"))&&"set_product_query".equals(p.purposes.get("n1")),"only immutable owner literal in actual field");
            check(p.quote==null&&!p.purposes.containsKey("n0")&&!p.purposes.containsKey("n4")&&!p.purposes.containsKey("n9"),"no mode, blank back, history, or quote authority");
        });
        test("direct_root_verified_query_offers_only_right_normal_search",()->{
            NativeXiaomiProductPage.Page p=inspect(directRootFrame("AX3000T"));
            check("search_submit".equals(p.phase)&&p.editValues.isEmpty()&&p.clickIds.equals(Collections.singleton("n3")),"only right ordinary button after actual text match");
            check(p.purposes.equals(Collections.singletonMap("n3","submit_product_query"))&&p.quote==null,"no same-text history or query result proof");
            check(Boolean.FALSE.equals(p.evidence().get("dispatch_authority"))&&Boolean.FALSE.equals(p.evidence().get("query_dispatched"))&&Boolean.FALSE.equals(p.evidence().get("task_completion_authority")),"pure parser supplies no dispatch or completion");
        });
        test("direct_root_wrong_existing_text_is_replaced_with_owner_span",()->{
            NativeXiaomiProductPage.Page p=inspect(directRootFrame("REDMI Note 17"));
            check(p.editValues.equals(Collections.singletonMap("n1","AX3000T"))&&p.clickIds.isEmpty(),"placeholder or other query never becomes requested model");
        });
        test("direct_root_requires_unique_editable_field",()->{
            NativeAppEvidence.Frame f=directRootFrame("");List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(f.nodes);
            nodes.add(rootNode("n8","android.widget.EditText","","0/7","android.widget.FrameLayout","",true,true,100,500,1100,600));
            unavailable(frame(f,nodes,false,true,1,true),"second actual editable field");
        });
        test("direct_root_field_cannot_borrow_unknown_parent_or_nested_path",()->{
            rootChangedRejected("n1","parent","android.widget.LinearLayout");
            rootChangedRejected("n1","path","0/9/1");rootChangedRejected("n1","path","0/3");
        });
        test("direct_root_does_not_mix_legacy_button_or_label_indices",()->{
            rootChangedRejected("n3","path","0/3");rootChangedRejected("n6","path","0/0/2");rootChangedRejected("n7","path","0/4/1");
        });
        test("direct_root_requires_both_controls_and_both_literal_labels",()->{
            for(String nodeId:new String[]{"n0","n3","n6","n7"}){
                NativeAppEvidence.Frame f=directRootFrame("");unavailable(replace(f,f.byId.get(nodeId),null),"missing toolbar node "+nodeId);
            }
        });
        test("direct_root_duplicate_native_path_is_rejected_by_frame",()->{
            NativeAppEvidence.Frame f=directRootFrame("");List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(f.nodes);
            nodes.add(alter(f.byId.get("n3"),"id","n30"));boolean rejected=false;
            try{frame(f,nodes,false,true,1,true);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"no duplicate native path carrier can enter parser");
        });
        test("direct_root_disabled_field_control_or_label_is_unavailable",()->{
            for(String nodeId:new String[]{"n0","n1","n3","n6","n7"})rootChangedRejected(nodeId,"enabled",Boolean.FALSE);
        });
        test("direct_root_selection_tuple_must_be_observed_and_neutral",()->{
            for(String nodeId:new String[]{"n0","n1","n3","n6","n7"}){
                rootChangedRejected(nodeId,"selected",null);rootChangedRejected(nodeId,"selected",Boolean.TRUE);
                rootChangedRejected(nodeId,"checkable",Boolean.TRUE);
            }
        });
        test("direct_root_labels_cannot_be_interactive_or_editable",()->{
            for(String nodeId:new String[]{"n6","n7"}){
                rootChangedRejected(nodeId,"clickable",Boolean.TRUE);rootChangedRejected(nodeId,"editable",Boolean.TRUE);
                rootChangedRejected(nodeId,"scrollable",Boolean.TRUE);
            }
        });
        test("direct_root_field_and_controls_require_current_click_capability",()->{
            for(String nodeId:new String[]{"n0","n1","n3"})rootChangedRejected(nodeId,"clickable",Boolean.FALSE);
            rootChangedRejected("n1","editable",Boolean.FALSE);rootChangedRejected("n3","scrollable",Boolean.TRUE);
        });
        test("direct_root_foreign_node_package_is_rejected",()->{
            NativeAppEvidence.Frame f=directRootFrame("");NativeAppEvidence.Node n=f.byId.get("n3");
            unavailable(replace(f,n,edit(n,null,null,null,"foreign.app",null,null,null)),"foreign button even with same text and path");
        });
        test("direct_root_control_parent_and_label_class_are_bound",()->{
            rootChangedRejected("n0","parent","android.view.ViewGroup");rootChangedRejected("n3","parent","android.view.ViewGroup");
            rootChangedRejected("n6","parent","android.widget.FrameLayout");rootChangedRejected("n7","class","android.view.View");
        });
        test("direct_root_swapped_controls_do_not_offer_mode_toggle",()->{
            NativeAppEvidence.Frame f=directRootFrame("");NativeAppEvidence.Node n=f.byId.get("n3");
            unavailable(replace(f,n,edit(n,null,null,null,null,null,null,new int[]{81,328,367,421})),"right search moved onto left mode");
        });
        test("direct_root_label_must_remain_inside_its_real_control",()->{
            NativeAppEvidence.Frame f=directRootFrame("");NativeAppEvidence.Node n=f.byId.get("n7");
            unavailable(replace(f,n,edit(n,null,null,null,null,null,null,new int[]{950,347,1101,408})),"label outside exact right control");
        });
        test("direct_root_text_and_resource_variant_are_exact",()->{
            rootChangedRejected("n7","text","AI 搜索");rootChangedRejected("n3","description","搜索");
            rootChangedRejected("n3","label","登录");rootChangedRejected("n1","view","com.xiaomi.shop:id/unknown_field");
        });
        test("direct_root_incomplete_or_unobserved_window_is_unavailable",()->{
            NativeAppEvidence.Frame f=directRootFrame("");unavailable(frame(f,f.nodes,true,true,1,true),"truncated");
            unavailable(frame(f,f.nodes,false,false,1,true),"incomplete");unavailable(frame(f,f.nodes,false,true,2,true),"wrong window type");
            unavailable(frame(f,f.nodes,false,true,1,false),"unobserved metadata");
        });
        test("direct_root_same_text_history_never_becomes_suggestion",()->{
            NativeAppEvidence.Frame f=directRootFrame("AX3000T");List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(f.nodes);
            nodes.add(rootNode("n29","android.widget.TextView","xiaomi路由器ax3000t","0/6/2","android.widget.ScrollView","xiaomi路由器ax3000t",false,false,100,750,800,820));
            NativeXiaomiProductPage.Page p=inspect(frame(f,nodes,false,true,1,true));
            check("search_submit".equals(p.phase)&&p.clickIds.equals(Collections.singleton("n3"))&&p.quote==null,"history loading and duplicate text do not alter normal query target");
        });
        test("direct_root_repeated_observation_has_no_query_or_completion_claim",()->{
            NativeAppEvidence.Frame f=directRootFrame("");NativeXiaomiProductPage.Page a=inspect(f),b=inspect(f);
            check(a.editValues.equals(b.editValues)&&a.quote==null&&b.quote==null&&a.clickIds.isEmpty()&&b.clickIds.isEmpty(),"no parser-state promotion or automatic query");
        });
    }

    private static void cases()throws Exception{
        test("actual_home_selects_observed_query_entry_not_adjacent_icon",()->{
            NativeAppEvidence.Frame f=load("home");NativeXiaomiProductPage.Page p=inspect(f);
            check("home_search".equals(p.phase)&&p.clickIds.size()==1&&p.editValues.isEmpty(),"actual homepage route");
            NativeAppEvidence.Node n=f.byId.get(p.clickIds.iterator().next());
            check(n.clickable&&"com.xiaomi.shop.plugin.homepage:id/switcher".equals(n.viewId)&&"open_search".equals(p.purposes.get(n.id)),"actual search-entry transition NodeRef carrier");
        });
        test("query_entry_preserves_original_derived_label_and_no_query_claim",()->{
            NativeAppEvidence.Frame f=load("home");NativeXiaomiProductPage.Page p=inspect(f);NativeAppEvidence.Node entry=resource(f,"switcher"),icon=resource(f,"searchIcon");
            check(p.clickIds.contains(entry.id)&&!p.clickIds.contains(icon.id),"adjacent icon stays observed, not granted open_search");
            check("搜索洗衣机 · 洗衣机".equals(entry.label),"fixture original hint label, never replaced with 搜索 or AX3000T");
            check(p.quote==null&&p.editValues.isEmpty()&&!Boolean.TRUE.equals(p.evidence().get("query_dispatched")),"entry navigation is not a product query or result");
        });
        test("query_entry_requires_switcher",()->{NativeAppEvidence.Frame f=load("home");unavailable(replace(f,resource(f,"switcher"),null),"icon is not substitute entry");});
        test("query_entry_requires_adjacent_icon_context",()->{NativeAppEvidence.Frame f=load("home");unavailable(replace(f,resource(f,"searchIcon"),null),"missing observed sibling");});
        test("query_entry_rejects_duplicate_resource",()->{NativeAppEvidence.Frame f=load("home");NativeAppEvidence.Node n=resource(f,"switcher");
            NativeAppEvidence.Node extra=alter(alter(n,"id","n999"),"path",n.path+"/1");List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(f.nodes);nodes.add(extra);
            unavailable(frame(f,nodes,false,true,1,true),"duplicate entry resource never first-match");});
        test("query_entry_rejects_missing_hint",()->{NativeAppEvidence.Frame f=load("home");unavailable(replace(f,path(f,resource(f,"switcher").path+"/0"),null),"complete actual hint path");});
        test("query_entry_rejects_missing_term",()->{NativeAppEvidence.Frame f=load("home");unavailable(replace(f,path(f,resource(f,"switcher").path+"/0/0"),null),"complete actual term path");});
        test("query_entry_rejects_extra_descendant",()->{NativeAppEvidence.Frame f=load("home");NativeAppEvidence.Node entry=resource(f,"switcher"),n=path(f,entry.path+"/0/0");
            NativeAppEvidence.Node extra=alter(alter(n,"id","n999"),"path",entry.path+"/1");List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(f.nodes);nodes.add(extra);
            unavailable(frame(f,nodes,false,true,1,true),"extra descendant cannot supply derived authority");});
        changedEntryRejected("query_entry_rejects_wrong_class","","class","android.widget.ImageView");
        changedEntryRejected("query_entry_rejects_wrong_parent","","parent","android.widget.FrameLayout");
        changedEntryRejected("query_entry_rejects_forged_original_label","","label","AX3000T");
        changedEntryRejected("query_entry_rejects_unclickable_entry","","clickable",Boolean.FALSE);
        changedEntryRejected("query_entry_rejects_editable_entry","","editable",Boolean.TRUE);
        changedEntryRejected("query_entry_rejects_selected_entry","","selected",Boolean.TRUE);
        changedEntryRejected("query_entry_rejects_unknown_selection","","selected",null);
        changedEntryRejected("query_entry_rejects_checkable_entry","","checkable",Boolean.TRUE);
        changedEntryRejected("query_entry_rejects_wrong_hint_class","/0","class","android.widget.TextView");
        changedEntryRejected("query_entry_rejects_unrelated_hint","/0","description","登录");
        changedEntryRejected("query_entry_rejects_clickable_hint","/0","clickable",Boolean.TRUE);
        changedEntryRejected("query_entry_rejects_wrong_term_resource","/0/0","view","com.xiaomi.shop:id/login");
        changedEntryRejected("query_entry_rejects_hint_term_mismatch","/0/0","text","冰箱");
        changedEntryRejected("query_entry_rejects_clickable_term","/0/0","clickable",Boolean.TRUE);
        test("query_entry_rejects_term_outside_actual_parent",()->{NativeAppEvidence.Frame f=load("home");NativeAppEvidence.Node entry=resource(f,"switcher"),term=path(f,entry.path+"/0/0");
            unavailable(replace(f,term,edit(term,null,null,null,null,null,null,new int[]{entry.left,entry.top,entry.right+1,entry.bottom})),"term outside entry");});
        test("actual_search_entry_types_only_literal_owner_span",()->{
            NativeAppEvidence.Frame f=load("search-entry");NativeXiaomiProductPage.Page p=inspect(f);
            check("search_input".equals(p.phase)&&p.clickIds.isEmpty()&&p.editValues.size()==1,"no AI or search click before exact text");
            String nid=p.editValues.keySet().iterator().next();
            check(f.byId.get(nid).editable&&"AX3000T".equals(p.editValues.get(nid))&&"set_product_query".equals(p.purposes.get(nid)),"exact OWNER model span");
        });
        test("actual_focused_search_uses_same_input_contract",()->{
            NativeXiaomiProductPage.Page p=inspect(load("search-focus"));
            check("search_input".equals(p.phase)&&p.editValues.size()==1&&p.clickIds.isEmpty(),"focus cannot change query or select cloud mode");
        });
        test("actual_suggestion_uses_clickable_row_not_text_or_AI",()->{
            NativeAppEvidence.Frame f=load("suggestions");NativeXiaomiProductPage.Page p=inspect(f);
            check("search_suggestion".equals(p.phase)&&p.clickIds.size()==1,"actual suggestion branch");
            NativeAppEvidence.Node n=f.byId.get(p.clickIds.iterator().next());
            check(n.clickable&&n.left==54&&n.top==654&&n.right==1170&&n.bottom==801,"exact observed full suggestion row");
            check("submit_exact_suggestion".equals(p.purposes.get(n.id)),"only exact suggestion purpose");
        });
        test("actual_history_overlap_uses_normal_button_not_first_same_text",()->{
            NativeAppEvidence.Frame f=load("search-history-overlap");NativeXiaomiProductPage.Page p=inspect(f);
            check("search_submit".equals(p.phase)&&p.clickIds.size()==1,"same text overlay/history has safe normal-search fallback");
            NativeAppEvidence.Node n=f.byId.get(p.clickIds.iterator().next());
            check(n.left==958&&n.top==333&&n.right==1142&&n.bottom==421&&n.clickable,"right normal button, never left mode toggle");
            check("submit_product_query".equals(p.purposes.get(n.id)),"ordinary product query purpose");
        });
        test("actual_search_card_reads_only_its_price_and_real_click_ancestor",()->{
            NativeAppEvidence.Frame f=load("results");NativeXiaomiProductPage.Page p=inspect(f);readonlyQuote(p.quote,"search_card");
            check("secondary_display_amount".equals(p.quote.comparisonKind),"search XML does not prove strike semantics");
            check(p.clickIds.size()==1&&p.editValues.isEmpty(),"one exact product-card target");
            NativeAppEvidence.Node card=f.byId.get(p.clickIds.iterator().next());
            check(card.clickable&&card.left==34&&card.top==1003&&card.right==1190&&card.bottom==1501,"actual clickable card");
            check(!p.clickIds.contains(text(f,TITLE).id),"nonclickable title is never invented as a click target");
        });
        test("actual_detail_description_is_159_not_merged_text_1590",()->{
            NativeAppEvidence.Frame f=load("detail");NativeXiaomiProductPage.Page p=inspect(f);readonlyQuote(p.quote,"detail_display");
            check("explicit_strikethrough_label".equals(p.quote.comparisonKind),"description explicitly labels comparison");
            check(p.clickIds.isEmpty()&&p.editValues.isEmpty(),"purchase/cart controls not exposed");
            check(text(f,"￥1590￥199")!=null&&"159".equals(p.quote.amountDecimal),"actual merged rich text retained but not parsed as price");
            check(Boolean.FALSE.equals(p.quote.evidence().get("selected_sku_verified"))&&Boolean.FALSE.equals(p.quote.evidence().get("delivery_address_verified")),"offscreen SKU/address not verified");
            boolean condition=false;for(Map<String,Object> c:p.quote.conditions)if("分期最高减10元".equals(c.get("raw")))condition=true;
            check(condition,"actual installment condition retained without subtraction");
        });
        test("actual_second_read_has_equal_value_but_distinct_frame_binding",()->{
            NativeXiaomiProductPage.Quote a=inspect(load("detail")).quote,b=inspect(load("detail-readonly")).quote;
            check(a!=null&&b!=null&&a.semanticFingerprint.equals(b.semanticFingerprint),"actual equal XML values");
            check(!a.fingerprint.equals(b.fingerprint)&&!a.frame.observationId.equals(b.frame.observationId),"source capability is never reused across observations");
        });
        test("actual_unlabelled_promotion_does_not_invent_a_click",()->unavailable(load("home-promotion"),"unlabelled image popup cannot borrow homepage search"));
        test("complete_window_metadata_is_required",()->{
            NativeAppEvidence.Frame f=load("detail");unavailable(frame(f,f.nodes,false,true,-1,false),"unknown window metadata");
            unavailable(frame(f,f.nodes,false,true,2,true),"wrong window type");
        });
        test("truncated_or_incomplete_capture_is_not_a_quote_or_target",()->{
            NativeAppEvidence.Frame f=load("results");unavailable(frame(f,f.nodes,true,true,1,true),"truncated capture");
            unavailable(frame(f,f.nodes,false,false,1,true),"unknown collection completeness");
        });
        test("foreign_package_node_blocks_all_page_outputs",()->{
            NativeAppEvidence.Frame f=load("detail");NativeAppEvidence.Node n=text(f,TITLE);
            unavailable(replace(f,n,edit(n,null,null,null,"foreign.app",null,null,null)),"mixed package provenance");
        });
        test("wrong_immutable_owner_and_package_are_rejected",()->{
            NativeAppEvidence.Frame f=load("detail");boolean rejected=false;
            try{NativeXiaomiProductPage.inspect(NativeAppGoal.parse("请在小米商城查询AX3000T价格",NativeAppGoal.XIAOMI_PACKAGE),f);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"different immutable OWNER hash rejected");
            rejected=false;try{NativeXiaomiProductPage.inspect(NativeAppGoal.parse("查一下2099年11月17日北京到上海的单程机票，1名成人",NativeAppGoal.CTRIP_PACKAGE),f);}catch(IllegalArgumentException expected){rejected=true;}
            check(rejected,"flight/foreign package cannot use product provider");
        });
        test("missing_detail_description_cannot_fallback_to_1590_rich_text",()->{
            NativeAppEvidence.Frame f=load("detail");NativeAppEvidence.Node n=desc(f,"159元划线价199元");
            noQuote(replace(f,n,edit(n,null,"",null,null,null,null,null)),"no description proof");
        });
        test("partial_or_conditional_price_description_is_not_silently_parsed",()->{
            NativeAppEvidence.Frame f=load("detail");NativeAppEvidence.Node n=desc(f,"159元划线价199元");
            noQuote(replace(f,n,edit(n,null,"159元起划线价199元",null,null,null,null,null)),"conditional amount shape differs");
            noQuote(replace(f,n,edit(n,null,"159元",null,null,null,null,null)),"partial original renderer evidence");
        });
        test("different_router_model_does_not_borrow_AX3000T_price",()->{
            NativeAppEvidence.Frame f=load("detail");NativeAppEvidence.Node n=text(f,TITLE);
            noQuote(replace(f,n,edit(n,"Xiaomi路由器 AX3000E",null,null,null,null,null,null)),"other model rejected");
        });
        test("duplicate_visible_exact_product_titles_are_ambiguous",()->{
            NativeAppEvidence.Frame f=load("detail");NativeAppEvidence.Node n=text(f,"更多优惠");
            noQuote(replace(f,n,edit(n,TITLE,null,null,null,null,null,null)),"second visible product identity");
        });
        test("detail_price_and_title_must_share_the_actual_product_block",()->{
            NativeAppEvidence.Frame f=load("detail");NativeAppEvidence.Node n=desc(f,"159元划线价199元");
            noQuote(replace(f,n,edit(n,null,null,"0/99/1/0/0",null,null,null,null)),"foreign structural price block");
        });
        test("offscreen_or_disabled_price_cannot_complete_visible_quote",()->{
            NativeAppEvidence.Frame f=load("detail");NativeAppEvidence.Node n=desc(f,"159元划线价199元");
            noQuote(replace(f,n,edit(n,null,null,null,null,null,null,new int[]{n.left,f.bottom+1,n.right,f.bottom+50})),"offscreen price");
            noQuote(replace(f,n,edit(n,null,null,null,null,null,Boolean.FALSE,null)),"disabled price");
        });
        test("search_amount_from_other_card_is_not_joined",()->{
            NativeAppEvidence.Frame f=load("results");NativeAppEvidence.Node n=text(f,"159");
            noQuote(replace(f,n,edit(n,null,null,"0/99/0/12",null,null,null,null)),"amount outside exact card");
        });
        test("search_currency_is_required_in_same_adjacent_row",()->{
            NativeAppEvidence.Frame f=load("results");NativeAppEvidence.Node n=sameModelParentText(f,"￥");
            noQuote(replace(f,n,null),"missing same-card currency");
            noQuote(replace(f,n,edit(n,null,null,null,null,null,null,new int[]{n.left,n.top-200,n.right,n.bottom-200})),"unrelated currency geometry");
        });
        test("ambiguous_bare_amount_inside_card_is_rejected",()->{
            NativeAppEvidence.Frame f=load("results");NativeAppEvidence.Node n=sameModelParentText(f,"3000M级");
            noQuote(replace(f,n,edit(n,"149",null,null,null,null,null,null)),"more than one same-card bare price");
        });
        test("nonclickable_card_does_not_turn_title_into_click_target",()->{
            NativeAppEvidence.Frame f=load("results");NativeXiaomiProductPage.Page p=inspect(f);
            NativeAppEvidence.Node card=f.byId.get(p.clickIds.iterator().next());
            unavailable(replace(f,card,edit(card,null,null,null,null,Boolean.FALSE,null,null)),"no invented title action");
        });
        test("search_price_sibling_order_is_bound_not_global_number_match",()->{
            NativeAppEvidence.Frame f=load("results");NativeAppEvidence.Node n=text(f,"159");
            noQuote(replace(f,n,edit(n,null,null,n.path+"/0",null,null,null,null)),"amount changed native parent path");
        });
        test("missing_left_mode_control_refuses_unproved_right_search_semantics",()->{
            NativeAppEvidence.Frame f=load("search-entry");NativeAppEvidence.Node left=null;
            for(NativeAppEvidence.Node n:f.nodes)if("搜索".equals(n.text)&&n.left<300)left=n;
            if(left==null)throw new IllegalArgumentException("actual mode label missing");
            unavailable(replace(f,left,null),"cannot identify normal search by only one generic label");
        });
        test("swapped_search_button_geometry_cannot_select_cloud_toggle",()->{
            NativeAppEvidence.Frame f=load("suggestions");NativeAppEvidence.Node normal=f.byId.get("n28");
            check(normal!=null&&normal.left==958,"pinned fixture normal button");
            unavailable(replace(f,normal,edit(normal,null,null,null,null,null,null,new int[]{81,328,367,421})),"right-button identity cannot move to cloud toggle geometry");
        });
        test("foreign_suggestion_branch_falls_back_to_verified_normal_search",()->{
            NativeAppEvidence.Frame f=load("suggestions");NativeAppEvidence.Node n=text(f,"xiaomi路由器ax3000t");
            NativeAppEvidence.Frame altered=replace(f,n,edit(n,null,null,"0/99/0",null,null,null,null));
            NativeXiaomiProductPage.Page p=inspect(altered);
            check("search_submit".equals(p.phase)&&p.clickIds.size()==1,"no arbitrary same-text suggestion click");
            check("submit_product_query".equals(p.purposes.get(p.clickIds.iterator().next())),"ordinary verified query fallback");
        });
        test("wrong_existing_query_is_replaced_only_with_owner_literal",()->{
            NativeAppEvidence.Frame f=load("suggestions");NativeAppEvidence.Node n=text(f,"AX3000T");
            NativeXiaomiProductPage.Page p=inspect(replace(f,n,edit(n,"别的商品",null,null,null,null,null,null)));
            check("search_input".equals(p.phase)&&p.clickIds.isEmpty()&&"AX3000T".equals(p.editValues.get(n.id)),"no stale suggestion before actual owner query");
        });
        test("unknown_selected_home_flag_does_not_grant_home_search",()->{
            NativeAppEvidence.Frame f=load("home");NativeAppEvidence.Node n=text(f,"首页");
            NativeAppEvidence.Node unknown=new NativeAppEvidence.Node(n.id,n.packageName,n.className,n.viewId,n.text,n.description,n.path,n.parentClass,n.signature,n.label,
                    n.left,n.top,n.right,n.bottom,n.enabled,n.password,n.clickable,n.editable,n.scrollable,null,null,null,n.scrollDirections);
            unavailable(replace(f,n,unknown),"unknown home selection tuple");
        });
        test("quote_and_page_audits_are_deeply_immutable",()->{
            NativeXiaomiProductPage.Page p=inspect(load("detail"));boolean rejected=false;
            try{p.evidence().put("order_submitted",Boolean.TRUE);}catch(UnsupportedOperationException expected){rejected=true;}check(rejected,"page audit immutable");
            rejected=false;try{p.quote.evidence().put("amount_decimal","1");}catch(UnsupportedOperationException expected){rejected=true;}check(rejected,"quote audit immutable");
            rejected=false;try{p.quote.conditions.get(0).put("raw","free");}catch(UnsupportedOperationException expected){rejected=true;}check(rejected,"nested condition immutable");
        });
        test("actual_reset_home_matches_the_official_fresh_start",()->{
            NativeAppEvidence.Frame f=load("home-reset");NativeXiaomiProductPage.Page p=inspect(f);
            check("home_search".equals(p.phase)&&p.clickIds.size()==1&&p.quote==null,"actual reset is homepage, not cached result");
            NativeAppEvidence.Node n=f.byId.get(p.clickIds.iterator().next());
            check(n.clickable&&"com.xiaomi.shop.plugin.homepage:id/switcher".equals(n.viewId)
                    &&"open_search".equals(p.purposes.get(n.id)),"same real homepage query-entry resource");
        });
        test("real_old_child_collector_preserves_bound_prefix_and_legacy_blocker",()->{
            NativeXmlFixture.Snapshot fixture=NativeXmlFixture.read(fixtures.resolve("results.xml"));
            Map<String,Object> child=fixture.childLabels.get("n85");
            check(child!=null&&Boolean.TRUE.equals(child.get("truncated"))&&"derived".equals(child.get("status")),"original bounded collector truncates actual rich product card");
            check(!"".equals(child.get("original_projected_label"))&&"".equals(child.get("native_observation_r4_effective_label")),"r4 adapter suppresses the original prefix; no title label is invented");
            check(fixture.nodes.get(85).label.equals(child.get("original_projected_label"))&&!fixture.nodes.get(85).label.isEmpty(),"current r5 retains the exact original projected prefix");
            check(!TITLE.equals(fixture.nodes.get(85).label)&&fixture.nodes.get(85).label.endsWith("…"),"no title substitution or expansion beyond original projection");
            check(fixture.nodes.get(85).label.equals(child.get("native_observation_r5_effective_label")),"current adapter rule is explicit and separate from legacy r4 refusal");
            NativeXmlFixture.Snapshot simple=NativeXmlFixture.read(fixtures.resolve("suggestions.xml"));
            check("xiaomi路由器ax3000t".equals(simple.nodes.get(43).label)&&!Boolean.TRUE.equals(simple.childLabels.get("n43").get("truncated")),"actual suggestion uses original complete derived label");
        });
        test("empty_native_page_has_no_business_or_action_fallback",()->{
            NativeAppEvidence.Frame f=load("detail");unavailable(frame(f,Collections.<NativeAppEvidence.Node>emptyList(),false,true,1,true),"empty observed page");
        });
        directRootCases();
    }
    private static String json(boolean pass){
        StringBuilder out=new StringBuilder("{\"schema\":\"hepta.native-xiaomi-product-host.v1\",\"all_pass\":");
        out.append(pass).append(",\"cases\":").append(names.size()).append(",\"assertions\":").append(checks).append(",\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)out.append(',');out.append('"').append(names.get(i)).append('"');}
        return out.append("],\"fixture_values_actual\":false,\"public_fixtures_have_explicit_private_value_redactions\":true,\"quote_and_action_source_values_match_original\":true,\"frame_bindings_node_signatures_collection_and_window_metadata_synthetic\":true,\"direct_root_toolbar_shape_and_negative_mutations_synthetic\":true,\"model_inference\":false,\"android_runtime\":false,\"phone_operations\":0,\"query_executed\":false,\"business_verified\":false}\n").toString();
    }
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);Path out=Paths.get(args[1]);boolean pass=false;
        try{cases();pass=true;}finally{Files.write(out,json(pass).getBytes(StandardCharsets.UTF_8));System.out.print(json(pass));}
    }
}
