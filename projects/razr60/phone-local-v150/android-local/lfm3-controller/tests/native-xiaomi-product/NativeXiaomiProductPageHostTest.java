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
    private static void cases()throws Exception{
        test("actual_home_selects_resource_bound_search_icon",()->{
            NativeAppEvidence.Frame f=load("home");NativeXiaomiProductPage.Page p=inspect(f);
            check("home_search".equals(p.phase)&&p.clickIds.size()==1&&p.editValues.isEmpty(),"actual homepage route");
            NativeAppEvidence.Node n=f.byId.get(p.clickIds.iterator().next());
            check(n.clickable&&"com.xiaomi.shop.plugin.homepage:id/searchIcon".equals(n.viewId)&&"open_search".equals(p.purposes.get(n.id)),"real icon NodeRef carrier");
        });
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
            check(n.clickable&&"com.xiaomi.shop.plugin.homepage:id/searchIcon".equals(n.viewId)
                    &&"open_search".equals(p.purposes.get(n.id)),"same real homepage search resource");
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
    }
    private static String json(boolean pass){
        StringBuilder out=new StringBuilder("{\"schema\":\"hepta.native-xiaomi-product-host.v1\",\"all_pass\":");
        out.append(pass).append(",\"cases\":").append(names.size()).append(",\"assertions\":").append(checks).append(",\"case_names\":[");
        for(int i=0;i<names.size();i++){if(i>0)out.append(',');out.append('"').append(names.get(i)).append('"');}
        return out.append("],\"fixture_values_actual\":false,\"public_fixtures_have_explicit_private_value_redactions\":true,\"quote_and_action_source_values_match_original\":true,\"frame_bindings_node_signatures_collection_and_window_metadata_synthetic\":true,\"model_inference\":false,\"android_runtime\":false,\"phone_operations\":0,\"query_executed\":false,\"business_verified\":false}\n").toString();
    }
    public static void main(String[] args)throws Exception{
        fixtures=Paths.get(args[0]);Path out=Paths.get(args[1]);boolean pass=false;
        try{cases();pass=true;}finally{Files.write(out,json(pass).getBytes(StandardCharsets.UTF_8));System.out.print(json(pass));}
    }
}
