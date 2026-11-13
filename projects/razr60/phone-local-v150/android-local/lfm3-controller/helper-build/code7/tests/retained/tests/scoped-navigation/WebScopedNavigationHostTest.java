package org.trillionnium.hepta.webhelper;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.TaskAuthorization;
import org.trillionnium.hepta.webprotocol.*;

/**
 * Focused tests of the real wire4 comparison/ARM/permit classes.
 * All CSS/hit/native-geometry and completed-navigation records below are explicit
 * synthetic fixtures. They are not collected from a WebView or business result.
 * The two outside rectangle values reproduce only the observed change shape;
 * adding synthetic styles/hits never upgrades the historical DOM-v3 sample.
 */
public final class WebScopedNavigationHostTest {
    interface Checked {void run()throws Exception;}
    static int cases,assertions;
    static final ArrayList<String> names=new ArrayList<String>();
    static final String ROOT="0/0/0/0",ANCHOR=ROOT+"/0",MODEL=ANCHOR+"/0",PRICES=ANCHOR+"/1";
    static final String CURRENT=PRICES+"/0",DEL=PRICES+"/1",COMPARISON=DEL+"/0",OUTSIDE="0/1";
    static final String URL="https://www.mi.com/shop/buy?product_id=1230803766&cfrom=search";
    static final String INSTANCE="12345678-1234-1234-1234-123456789abc";
    static void need(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    static void run(String name,Checked test)throws Exception{test.run();cases++;names.add(name);}
    static void rejects(Checked test)throws Exception{
        boolean rejected=false;try{test.run();}catch(Exception expected){rejected=true;}need(rejected,"expected rejection");
    }
    static String rep(char value,int n){char[] a=new char[n];Arrays.fill(a,value);return new String(a);}
    static JSONObject copy(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    static JSONArray rect(double a,double b,double c,double d){return new JSONArray(new double[]{a,b,c,d});}
    static JSONObject node(String path,String tag,String label,JSONArray r)throws Exception{
        int cut=path.lastIndexOf('/');
        JSONObject out=new JSONObject().put("path",path).put("parent_path",cut<0?JSONObject.NULL:path.substring(0,cut))
                .put("tag",tag).put("text",label).put("rect_css_pixels",r);
        for(String key:new String[]{"id","name","role","aria_label","aria_hidden","aria_modal","aria_selected",
                "aria_checked","aria_pressed","item_type","item_prop"})out.put(key,"");
        for(String key:new String[]{"disabled","hidden_attr","inert_attr","item_scope","iframe_contents_read"})out.put(key,false);
        for(String key:new String[]{"href_raw","href_resolved","link_target","value","aria_disabled"})out.put(key,JSONObject.NULL);
        out.put("visible_in_viewport",true);return out;
    }
    static JSONObject find(JSONObject dom,String path)throws Exception{
        JSONArray rows=dom.getJSONArray("nodes");for(int i=0;i<rows.length();i++)
            if(path.equals(rows.getJSONObject(i).getString("path")))return rows.getJSONObject(i);
        throw new IllegalArgumentException("fixture path missing "+path);
    }
    static JSONObject style(JSONObject dom,String path)throws Exception{
        JSONArray rows=dom.getJSONObject("action_region_observations").getJSONArray("style_contexts");
        for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path")))return rows.getJSONObject(i);
        throw new IllegalArgumentException("fixture style missing "+path);
    }
    static JSONObject pseudo()throws Exception{
        return new JSONObject().put("content","none").put("display","inline").put("position","static")
                .put("visibility","visible").put("opacity","1").put("transform","none").put("pointer_events","auto");
    }
    static JSONObject css(String path,int children)throws Exception{
        JSONObject out=new JSONObject().put("path",path).put("position","static").put("display","block")
                .put("visibility","visible").put("opacity","1").put("overflow_x","visible").put("overflow_y","visible")
                .put("overflow_clip_margin","0px").put("transform_style","flat").put("zoom","1")
                .put("content_visibility","visible").put("will_change","auto").put("pointer_events","auto")
                .put("isolation","auto").put("mix_blend_mode","normal").put("element_child_count",children)
                .put("accessible_shadow_root_present",false).put("closed_shadow_contents_inspected",false)
                .put("pseudo_before",pseudo()).put("pseudo_after",pseudo());
        for(String key:new String[]{"transform","translate","rotate","scale","perspective","filter","backdrop_filter",
                "clip_path","mask_image","contain"})out.put(key,"none");return out;
    }
    static JSONObject dom()throws Exception{
        JSONArray rows=new JSONArray()
                .put(node("0","html","",rect(0,0,1280,900)))
                .put(node("0/0","body","",rect(0,0,1280,900)))
                .put(node(OUTSIDE,"div","",rect(900,80.83193969726562,1100,99.16807556152344)))
                .put(node("0/0/0","main","",rect(0,100,1280,900)))
                .put(node(ROOT,"div","",rect(100,200,400,600)))
                .put(node(ANCHOR,"a","",rect(100,200,400,600))
                    .put("href_raw","//www.mi.com/shop/buy?product_id=1230803766&cfrom=search")
                    .put("href_resolved",URL).put("link_target","_blank"))
                .put(node(MODEL,"h2","Xiaomi路由器AX3000T 白色",rect(120,450,380,480)))
                .put(node(PRICES,"p","",rect(120,500,380,540)))
                .put(node(CURRENT,"span","159元",rect(120,500,180,530)))
                .put(node(DEL,"del","",rect(200,500,260,530)))
                .put(node(COMPARISON,"span"," 199元",rect(200,500,260,530)));
        JSONObject candidate=new JSONObject().put("root_path",ROOT).put("anchor_path",ANCHOR).put("model_path",MODEL)
                .put("current_price_path",CURRENT).put("comparison_price_path",COMPARISON)
                .put("model_label","Xiaomi路由器AX3000T 白色").put("observed_variant","白色")
                .put("href_raw","//www.mi.com/shop/buy?product_id=1230803766&cfrom=search")
                .put("href_resolved",URL).put("link_target","_blank").put("current_price_raw","159元")
                .put("comparison_price_raw"," 199元").put("price_context","search_card_only").put("detail_price_verified",false);
        JSONArray styles=new JSONArray(),hits=new JSONArray();
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);String path=n.getString("path");if(path.equals(OUTSIDE))continue;
            int children=0;for(int j=0;j<rows.length();j++)if(path.equals(rows.getJSONObject(j).opt("parent_path")))children++;
            styles.put(css(path,children));
        }
        double[][] ratios={{.5,.5},{.2,.2},{.8,.2},{.2,.8},{.8,.8}};
        for(String path:new String[]{ANCHOR,MODEL,CURRENT,COMPARISON}){
            JSONObject n=null;for(int i=0;i<rows.length();i++)if(path.equals(rows.getJSONObject(i).getString("path")))n=rows.getJSONObject(i);
            JSONArray r=n.getJSONArray("rect_css_pixels"),points=new JSONArray();
            for(double[] ratio:ratios)points.put(new JSONObject()
                    .put("x",r.getDouble(0)+(r.getDouble(2)-r.getDouble(0))*ratio[0])
                    .put("y",r.getDouble(1)+(r.getDouble(3)-r.getDouble(1))*ratio[1])
                    .put("top_path",path).put("stack_complete",true).put("stack_paths",new JSONArray().put(path).put(ROOT)));
            hits.put(new JSONObject().put("dom_path",path).put("rect_css_pixels",new JSONArray(r.toString())).put("points",points));
        }
        JSONObject observations=new JSONObject().put("schema",WebMiActionRegion.OBS_SCHEMA).put("site_policy_id",WebMiActionRegion.POLICY)
                .put("selection",WebMiActionRegion.SELECTION).put("status","observed").put("candidate_count",1)
                .put("complete",true).put("coordinates_used_for_input",false).put("closed_shadow_contents_inspected",false)
                .put("pixel_visibility_claimed",false).put("candidate",candidate).put("foreign_overlap_paths",new JSONArray())
                .put("visible_modal_paths",new JSONArray()).put("special_paint_in_region_paths",new JSONArray())
                .put("style_contexts",styles).put("hit_tests",hits)
                .put("top_layer",new JSONObject().put("selector_api_available",true).put("modal_paths",new JSONArray())
                    .put("popover_paths",new JSONArray()).put("fullscreen_present",false).put("fullscreen_path",JSONObject.NULL)
                    .put("closed_shadow_contents_inspected",false));
        return new JSONObject().put("schema",WebDomStability.DOM_SCHEMA).put("href",WebSitePolicy.INITIAL_URL)
                .put("origin",WebSitePolicy.ORIGIN).put("ready_state","complete").put("truncated",false)
                .put("truncation_reasons",new JSONArray()).put("visited",rows.length()).put("nodes",rows)
                .put("viewport_css_pixels",new JSONArray(new int[]{1280,900})).put("action_region_observations",observations)
                .put("clipping_context_observations",new JSONObject().put("schema","hepta.raw-clip-context-observations.v1")
                    .put("fully_clipped_inferred",false).put("closed_shadow_contents_inspected",false).put("grants_action_authority",false)
                    .put("complete",true).put("style_contexts",new JSONArray().put(css(OUTSIDE,0))));
    }
    static JSONObject changedOutside(JSONObject before)throws Exception{
        JSONObject after=copy(before);find(after,OUTSIDE).put("rect_css_pixels",rect(900,82.87367248535156,1100,97.12633800506592));return after;
    }
    static WebDomStability.Result evaluate(JSONObject a,JSONObject b)throws Exception{return WebDomStability.evaluate(a.toString(),b.toString(),WebMiActionRegion.POLICY);}
    static JSONObject identity(String pkg,int uid,int version)throws Exception{
        return new JSONObject().put("package",pkg).put("uid",uid).put("version_code",version)
                .put("apk_hashes",new JSONObject().put("base",rep('1',64))).put("apk_set_sha256",rep('2',64))
                .put("signer_sha256",WebEvidenceProtocol.SIGNER_SHA256);
    }
    static JSONObject binding()throws Exception{
        String owner="查一下小米AX3000T的官网售价";WebTaskPurpose p=WebTaskPurpose.fromOwner(owner);
        return WebEvidenceBinding.fromAttach(new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.ATTACH))
                .put("request_nonce",rep('c',64)).put("task_id",rep('a',32)).put("controller_session_nonce",rep('b',64))
                .put("deadline_elapsed_ms",3000L).put("owner",owner).put("owner_sha256",p.ownerSha256)
                .put("contract_sha256",p.contractSha256).put("authorization",new JSONObject(WebEvidenceBinding.canonical(new JSONObject(TaskAuthorization.parse(owner).evidence()))))
                .put("background",new JSONObject().put("generation","00000000-0000-4000-8000-000000000001")
                    .put("display_id",15).put("display_name","hepta-bg-00000000-0000-4000-8000-000000000001")
                    .put("boot_count",7).put("created_elapsed_ms",1000L).put("expires_elapsed_ms",10000L)
                    .put("selected_packages",new JSONArray().put(WebEvidenceProtocol.HELPER_PACKAGE)))
                .put("controller_identity",identity(WebEvidenceProtocol.CONTROLLER_PACKAGE,10100,55))
                .put("helper_identity",identity(WebEvidenceProtocol.HELPER_PACKAGE,10123,6)));
    }
    static JSONObject capture(JSONObject binding,JSONObject a,JSONObject b,long epoch,String url,long started,long ended)throws Exception{
        WebDomStability.Result stable=evaluate(a,b);
        return new JSONObject().put("schema",WebObservedNavigation.CAPTURE_SCHEMA).put("binding",binding)
                .put("business_verified",false).put("truncated",false).put("helper_package",WebEvidenceProtocol.HELPER_PACKAGE)
                .put("display_id",15).put("actual_window_id",7).put("webview_instance",INSTANCE).put("navigation_epoch",epoch)
                .put("challenge",rep(epoch==2?'d':'e',64)).put("current_native_url",url).put("committed_main_frame_url",url)
                .put("before_dom_raw_utf8",a.toString()).put("dom_raw_utf8",b.toString())
                .put("before_dom_sha256",stable.beforeRawSha256).put("dom_sha256",stable.afterRawSha256)
                .put("dom_stability",stable.evidence()).put("dom_stability_sha256",WebDomCanonical.sha256(stable.evidence()))
                .put("started_elapsed_ms",started).put("ended_elapsed_ms",ended)
                .put("capture_geometry",new JSONObject().put("schema","hepta.webview-geometry-bracket.v2")
                    .put("samples",new JSONArray().put(new JSONObject()).put(new JSONObject()).put(new JSONObject()).put(new JSONObject()))
                    .put("native_samples_equal",true).put("ui_thread_bracket",true)
                    .put("dom_comparison_scope",stable.comparisonScope).put("dom_equal_across_visual_callback",stable.rawEqual));
    }
    static JSONObject request(JSONObject source)throws Exception{
        JSONObject b=source.getJSONObject("binding");
        return new JSONObject().put("schema",WebEvidenceProtocol.requestSchema(WebEvidenceProtocol.ARM_OBSERVED_LINK))
                .put("task_id",b.get("task_id")).put("controller_session_nonce",b.get("controller_session_nonce"))
                .put("request_nonce",rep('f',64)).put("deadline_elapsed_ms",3000L).put("expected_webview_instance",INSTANCE)
                .put("expected_navigation_epoch",2).put("source_capture_challenge",source.get("challenge"))
                .put("source_dom_sha256",source.get("dom_sha256")).put("source_stability_sha256",source.get("dom_stability_sha256"))
                .put("anchor_dom_path",ANCHOR).put("model_run_id",rep('9',32));
    }
    static void current(ObservedLinkPermit p,long now,JSONObject b)throws Exception{
        p.requireCurrent(now,INSTANCE,2,7,15,WebSitePolicy.INITIAL_URL,WebEvidenceBinding.sha256(b),b.getString("storage_profile_name"));
    }
    static JSONObject assignment(JSONObject b)throws Exception{
        return new JSONObject().put("profile_assignment_api","WebViewCompat.setProfile")
                .put("profile_assigned_before_other_interactions",true).put("actual_profile_name",b.getString("storage_profile_name"))
                .put("profile_assigned_elapsed_ms",1220L).put("reused_same_lease_profile",true)
                .put("network_loads_blocked",true).put("javascript_enabled",false).put("visible_in_layout",false);
    }
    static JSONObject complete(ObservedLinkPermit p,JSONObject b)throws Exception{
        current(p,1200,b);p.beginPopup(1210,false,true);p.auxiliaryCreated(assignment(b));p.acceptUrl(1230,URL,"GET",true);
        p.auxiliaryDestroyed(1240);p.beginMainLoad(1250);p.mainLoadReturned(1260);return p.evidence();
    }
    static JSONObject destination(JSONObject b)throws Exception{
        JSONObject d=dom();d.put("href",URL);
        return capture(b,d,d,3,URL,1300,1350);
    }
    public static void main(String[] args)throws Exception{
        need(args.length==1,"result path");
        run("canonical_numeric_and_unicode_contract",()->{
            need(WebDomCanonical.same(new BigDecimal("1.00"),Integer.valueOf(1)),"equivalent browser numbers");
            need(WebDomCanonical.canonical(-0.0).equals("0"),"negative zero");
            need(WebDomCanonical.same(new JSONObject().put("b",1).put("a","中😀"),new JSONObject().put("a","中😀").put("b",1L)),"sorted Unicode keys");
            rejects(()->WebDomCanonical.canonical(Double.NaN));rejects(()->WebDomCanonical.canonical(Double.POSITIVE_INFINITY));
            rejects(()->WebDomCanonical.canonical("\uD800"));rejects(()->WebDomCanonical.canonical(9007199254740992d));
            rejects(()->WebEvidenceBinding.canonical(1.5));rejects(()->Jsons.parse("{\"n\":1.5}",100));
        });
        run("canonical_completed_output_budget",()->{
            JSONArray a=new JSONArray();for(int i=0;i<6;i++)a.put(rep('x',800000));rejects(()->WebDomCanonical.canonical(a));
        });
        final JSONObject first=dom(),second=changedOutside(first),b=binding();
        final JSONObject source=capture(b,first,second,2,WebSitePolicy.INITIAL_URL,1000,1050),req=request(source);
        final JSONObject arm=WebObservedNavigation.arm(req,b,source,1100);
        run("explicit_scoped_complete_pair_and_target",()->{
            WebDomStability.Result r=evaluate(first,second);
            need(!r.rawEqual&&WebDomStability.REGION_SCOPE.equals(r.comparisonScope),"scoped, not raw equality");
            need(!r.beforeRawSha256.equals(r.afterRawSha256)&&r.region!=null,"both distinct original hashes");
            need(r.evidence().getJSONArray("all_json_differences").length()==2,"complete two-coordinate diff");
            need(r.permitsActionTargetPath(ANCHOR)&&!r.permitsActionTargetPath(ROOT)&&!r.permitsActionTargetPath("0/999"),"one real anchor only");
            need(!r.evidence().getBoolean("whole_page_pixel_visibility_verified")&&!r.evidence().getBoolean("outside_visibility_inferred"),"no pixel/clip assertion");
            need("159".equals(r.region.currentAmountDecimal)&&"199".equals(r.region.comparisonAmountDecimal),"two distinct search-price semantics");
            need(WebDomStability.verify(first.toString(),second.toString(),WebMiActionRegion.POLICY,r.evidence()).region!=null,"independent replay");
        });
        run("equal_complete_raw_and_other_policy_membership",()->{
            WebDomStability.Result r=evaluate(first,first);need(r.rawEqual&&r.region!=null,"full raw equality still independently selects card");
            WebDomStability.Result f=WebDomStability.evaluate(first.toString(),first.toString(),"csair_public_flight_v1");
            need(f.permitsActionTargetPath(ROOT)&&!f.permitsActionTargetPath("0/999"),"full equality only real paths");
            need(f.evidence().getJSONArray("eligible_action_dom_paths").length()==first.getJSONArray("nodes").length(),"API and record agree");
            rejects(()->WebDomStability.evaluate(first.toString(),second.toString(),"csair_public_flight_v1"));
        });
        run("old_observer_and_incomplete_membership_rejected",()->{
            JSONObject old=copy(first).put("schema","hepta.fixed-top-document-dom.v3");rejects(()->evaluate(old,old));
            JSONObject cut=copy(first).put("truncated",true);rejects(()->evaluate(cut,cut));
            JSONObject duplicate=copy(second);duplicate.getJSONArray("nodes").put(copy(find(duplicate,MODEL)));rejects(()->evaluate(first,duplicate));
            JSONObject missing=copy(second);find(missing,MODEL).put("parent_path","0/999");rejects(()->evaluate(first,missing));
        });
        run("serialization_only_mismatch_and_forged_proof_rejected",()->{
            rejects(()->WebDomStability.evaluate(first.toString(),first.toString(2),WebMiActionRegion.POLICY));
            JSONObject claim=evaluate(first,second).evidence().put("raw_dom_equal",true);
            rejects(()->WebDomStability.verify(first.toString(),second.toString(),WebMiActionRegion.POLICY,claim));
        });
        run("card_and_ancestor_changes_rejected",()->{
            for(String path:new String[]{ROOT,ANCHOR,MODEL,CURRENT,COMPARISON,"0/0"}){
                JSONObject x=copy(second);find(x,path).put("text","changed");rejects(()->evaluate(first,x));
            }
            JSONObject href=copy(second);find(href,ANCHOR).put("href_resolved",URL+"&order=1");rejects(()->evaluate(first,href));
        });
        run("outside_semantics_overlap_and_new_membership_rejected",()->{
            JSONObject text=copy(second);find(text,OUTSIDE).put("text","changed");rejects(()->evaluate(first,text));
            JSONObject overlap=copy(second);find(overlap,OUTSIDE).put("rect_css_pixels",rect(100,210,200,240));rejects(()->evaluate(first,overlap));
            JSONObject x=copy(second);x.getJSONArray("nodes").put(node("0/2","div","",rect(900,700,1000,800))).put(node("0/3","div","",rect(900,710,1000,820)));
            x.put("visited",x.getJSONArray("nodes").length());rejects(()->evaluate(first,x));
        });
        run("all_ancestor_visibility_styles_required",()->{
            for(String[] change:new String[][]{{"opacity","0"},{"display","none"},{"visibility","hidden"},{"content_visibility","hidden"},
                    {"filter","opacity(0)"},{"mask_image","url(fake)"},{"backdrop_filter","blur(2px)"},{"clip_path","inset(0 0 100%)"}}){
                JSONObject x=copy(first);style(x,"0/0").put(change[0],change[1]);rejects(()->WebMiActionRegion.read(x));
            }
            JSONObject missing=copy(first);missing.getJSONObject("action_region_observations").getJSONArray("style_contexts").remove(0);
            rejects(()->WebMiActionRegion.read(missing));
        });
        run("observed_modal_toplayer_and_pseudo_overlay_rejected",()->{
            JSONObject modal=copy(first);find(modal,OUTSIDE).put("role","dialog");rejects(()->WebMiActionRegion.read(modal));
            JSONObject top=copy(first);top.getJSONObject("action_region_observations").getJSONObject("top_layer").put("fullscreen_present",true);
            rejects(()->WebMiActionRegion.read(top));
            JSONObject pseudo=copy(first);style(pseudo,ROOT).getJSONObject("pseudo_before").put("content","\"x\"").put("position","fixed");
            rejects(()->WebMiActionRegion.read(pseudo));
            JSONObject shadow=copy(first);style(shadow,ROOT).put("accessible_shadow_root_present",true);rejects(()->WebMiActionRegion.read(shadow));
        });
        run("hit_retarget_missing_and_coordinate_forgery_rejected",()->{
            for(String key:new String[]{"top_path","x","stack_complete"}){
                JSONObject x=copy(first),point=x.getJSONObject("action_region_observations").getJSONArray("hit_tests").getJSONObject(0).getJSONArray("points").getJSONObject(0);
                point.put(key,key.equals("top_path")?OUTSIDE:key.equals("x")?999:false);rejects(()->WebMiActionRegion.read(x));
            }
            JSONObject x=copy(first);x.getJSONObject("action_region_observations").getJSONArray("hit_tests").remove(3);
            rejects(()->WebMiActionRegion.read(x));
        });
        run("auxiliary_clip_css_diff_retained_without_visibility_inference",()->{
            JSONObject x=copy(second);x.getJSONObject("clipping_context_observations").getJSONArray("style_contexts").getJSONObject(0).put("overflow_y","hidden");
            WebDomStability.Result r=evaluate(first,x);need(r.evidence().getJSONArray("all_json_differences").length()==3,"all auxiliary diff retained");
            need(!r.evidence().getBoolean("outside_visibility_inferred"),"no inferred invisible subtree");
        });
        run("detail_full_raw_cannot_acquire_search_action",()->{
            JSONObject d=dom().put("href",URL);WebDomStability.Result r=evaluate(d,d);
            need(r.rawEqual&&r.region==null&&!r.permitsActionTargetPath(ANCHOR),"detail grants no click");
        });
        run("arm_replays_actual_compiler_binding_and_fresh_pair",()->{
            need(WebObservedNavigation.verifyArm(req,b,source,arm).getBoolean("one_shot"),"exact replay");
            need(arm.getLong("expires_elapsed_ms")==2600&&arm.getString("observed_href_resolved").equals(URL),"bounded derived href");
            need(!arm.getBoolean("native_click_observed")&&!arm.getBoolean("navigation_dispatched")&&!arm.getBoolean("business_verified"),"ARM not outcome");
        });
        run("arm_identity_path_hash_and_authority_tamper_rejected",()->{
            for(String[] change:new String[][]{{"task_id",rep('0',32)},{"source_capture_challenge",rep('0',64)},
                    {"source_dom_sha256",rep('0',64)},{"source_stability_sha256",rep('0',64)},{"anchor_dom_path",ROOT}}){
                JSONObject q=copy(req).put(change[0],change[1]);rejects(()->WebObservedNavigation.arm(q,b,source,1100));
            }
            JSONObject q=copy(req).put("url",URL);rejects(()->WebObservedNavigation.arm(q,b,source,1100));
            JSONObject claim=copy(arm).put("business_verified",true);rejects(()->WebObservedNavigation.verifyArm(req,b,source,claim));
        });
        run("arm_deadline_age_and_numeric_type_rejected",()->{
            rejects(()->WebObservedNavigation.arm(req,b,source,1049));rejects(()->WebObservedNavigation.arm(req,b,source,3551));
            JSONObject q=copy(req).put("deadline_elapsed_ms",1100L);rejects(()->WebObservedNavigation.arm(q,b,source,1100));
            JSONObject f=copy(req).put("expected_navigation_epoch",2.0);rejects(()->WebObservedNavigation.arm(f,b,source,1100));
            JSONObject near=copy(req).put("deadline_elapsed_ms",6000L);JSONObject limited=WebObservedNavigation.arm(near,b,source,3500);
            need(limited.getLong("expires_elapsed_ms")==3550,"source absolute freshness caps ARM");
        });
        run("partial_record_shape_retained_but_not_navigation_success",()->{
            ObservedLinkPermit p=new ObservedLinkPermit(arm);JSONObject nav=p.evidence();WebObservedNavigation.requireNavigationRecordShape(nav);
            need(nav.isNull("popup_observed_url")&&!nav.getBoolean("same_lease_main_load_returned"),"partial preserved");
            rejects(()->WebObservedNavigation.verifyNavigation(arm,nav,destination(b),1200,1215));
            JSONObject extra=copy(nav).put("trusted",true);rejects(()->WebObservedNavigation.requireNavigationRecordShape(extra));
            JSONObject bad=copy(nav).put("popup_is_dialog","false");rejects(()->WebObservedNavigation.requireNavigationRecordShape(bad));
        });
        run("permit_single_popup_and_source_binding",()->{
            ObservedLinkPermit p=new ObservedLinkPermit(arm);current(p,1200,b);p.beginPopup(1210,false,true);
            rejects(()->p.beginPopup(1211,false,true));
            ObservedLinkPermit q=new ObservedLinkPermit(arm);
            rejects(()->q.requireCurrent(1200,INSTANCE,3,7,15,WebSitePolicy.INITIAL_URL,WebEvidenceBinding.sha256(b),b.getString("storage_profile_name")));
            rejects(()->q.requireCurrent(1200,INSTANCE,2,8,15,WebSitePolicy.INITIAL_URL,WebEvidenceBinding.sha256(b),b.getString("storage_profile_name")));
            rejects(()->current(q,2600,b));
        });
        run("failed_gesture_and_wrong_url_attempts_are_consumed",()->{
            ObservedLinkPermit p=new ObservedLinkPermit(arm);rejects(()->p.beginPopup(1210,false,false));rejects(()->p.beginPopup(1211,false,true));
            ObservedLinkPermit q=new ObservedLinkPermit(arm);q.beginPopup(1210,false,true);q.auxiliaryCreated(assignment(b));
            rejects(()->q.acceptUrl(1230,URL+"&cart=1","GET",true));rejects(()->q.acceptUrl(1231,URL,"GET",true));
            need(q.evidence().getBoolean("popup_url_observed"),"wrong actual URL retained");
        });
        run("wrong_method_and_missing_auxiliary_retirement_rejected",()->{
            ObservedLinkPermit p=new ObservedLinkPermit(arm);p.beginPopup(1210,false,true);p.auxiliaryCreated(assignment(b));
            rejects(()->p.acceptUrl(1230,URL,"POST",true));
            ObservedLinkPermit q=new ObservedLinkPermit(arm);q.beginPopup(1210,false,true);q.auxiliaryCreated(assignment(b));q.acceptUrl(1230,URL,"GET",true);
            rejects(()->q.beginMainLoad(1231));q.auxiliaryDestroyed(1240);rejects(()->q.beginMainLoad(1250));
        });
        run("actual_typed_navigation_chain_fixture_and_no_native_outcome_claim",()->{
            JSONObject nav=complete(new ObservedLinkPermit(arm),b),destination=destination(b);
            JSONObject verdict=WebObservedNavigation.verifyNavigation(arm,nav,destination,1200,1215);
            need(verdict.getBoolean("helper_navigation_chain_verified")&&!verdict.getBoolean("native_action_outcome_verified_by_this_method")
                    &&!verdict.getBoolean("detail_price_verified")&&!verdict.getBoolean("business_verified"),"only scoped helper chain");
            need(nav.getJSONObject("same_profile_assignment").getString("actual_profile_name").equals(b.getString("storage_profile_name")),"same isolated profile");
        });
        run("navigation_partial_cancelled_wrong_timing_and_context_refused",()->{
            JSONObject nav=complete(new ObservedLinkPermit(arm),b),dest=destination(b);
            JSONObject cancelled=copy(nav).put("cancelled",true).put("cancelled_elapsed_ms",1261L).put("cancellation_reason","synthetic");
            WebObservedNavigation.requireNavigationRecordShape(cancelled);
            rejects(()->WebObservedNavigation.verifyNavigation(arm,cancelled,dest,1200,1215));
            rejects(()->WebObservedNavigation.verifyNavigation(arm,nav,dest,1211,1215));
            rejects(()->WebObservedNavigation.verifyNavigation(arm,nav,dest,1200,2601));
            JSONObject wrong=copy(dest).put("actual_window_id",8);rejects(()->WebObservedNavigation.verifyNavigation(arm,nav,wrong,1200,1215));
            JSONObject wrongURL=copy(nav).put("popup_observed_url",URL+"&pay=1");rejects(()->WebObservedNavigation.verifyNavigation(arm,wrongURL,dest,1200,1215));
            JSONObject visible=copy(nav).put("new_visible_window_created",true);rejects(()->WebObservedNavigation.requireNavigationRecordShape(visible));
        });
        run("cancelled_permit_cannot_be_reused",()->{
            ObservedLinkPermit p=new ObservedLinkPermit(arm);p.cancel("synthetic source changed",1200);rejects(()->current(p,1201,b));
            rejects(()->p.beginPopup(1201,false,true));WebObservedNavigation.requireNavigationRecordShape(p.evidence());
        });
        JSONObject out=new JSONObject().put("schema","hepta.wire4-scoped-navigation-host-result.v1").put("all_pass",true)
                .put("cases",cases).put("assertions",assertions).put("case_names",new JSONArray(names))
                .put("actual_production_shared_and_permit_classes",true).put("synthetic_css_hit_geometry_navigation_fixtures",true)
                .put("historical_dom_v3_upgraded",false).put("android_callbacks_executed",false).put("javascript_executed",false)
                .put("phone_tested",false).put("actual_mi_detail_seen",false).put("business_verified",false);
        Files.write(Paths.get(args[0]),(out.toString()+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(out.toString());
    }
}
